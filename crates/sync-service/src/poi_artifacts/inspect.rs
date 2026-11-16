//! Loading and inspecting durable POI corpora.

use std::time::Instant;

use alloy::primitives::FixedBytes;
use local_db::{
    DbStore, POI_CORPUS_JOURNAL_SOFT_DELTA_COUNT, POI_CORPUS_JOURNAL_SOFT_PAYLOAD_BYTES,
    PoiCorpusJournalCorruptionToken, PoiCorpusJournalHeadRecord, PoiCorpusJournalInspection,
    StoredRecord,
};
use poi::cache::{PoiCache, PoiCacheError, PoiCacheIdentity, PoiCacheJournalDelta};
use poi::poi::BlockedShield;
use tracing::{debug, warn};

use crate::poi_limits::{
    POI_BLOCKED_SHIELD_LIMIT, POI_RPC_EVENT_LIMIT, POI_RPC_LEAF_LIMIT, decode_bounded_vec,
};

use super::validation::{
    normalize_legacy_artifact_metadata, validate_anchored_corpus, validate_materialized_corpus,
    validate_persisted_record,
};
use super::{ExpectedPoiCorpusBase, PersistedPoiArtifactCache, PoiArtifactError};

pub(crate) fn load_persisted_cache_for_publisher(
    db: &DbStore,
    identity: &PoiCacheIdentity,
    publisher_pubkey: FixedBytes<32>,
) -> Result<Option<PersistedPoiArtifactCache>, PoiArtifactError> {
    load_persisted_cache_with_publisher(db, identity, Some(publisher_pubkey))
}

pub(crate) fn load_persisted_cache_candidate_for_publisher(
    db: &DbStore,
    identity: &PoiCacheIdentity,
    publisher_pubkey: FixedBytes<32>,
    mut installed_cache: Option<PoiCache>,
    installed_head: Option<&PoiCorpusJournalHeadRecord>,
) -> Result<(Option<PersistedPoiArtifactCache>, ExpectedPoiCorpusBase), PoiArtifactError> {
    if let (Some(cache), Some(installed_head)) = (installed_cache.as_ref(), installed_head)
        && let StoredRecord::Valid(current_head) = db.inspect_poi_corpus_journal_head(
            identity.chain_type,
            identity.chain_id,
            &identity.txid_version,
            &identity.list_key,
        )?
        && current_head == *installed_head
    {
        let cache_generation = db.poi_artifact_cache_generation()?;
        let mut record = current_head.corpus.clone();
        normalize_legacy_artifact_metadata(&mut record);
        if cache.identity() == identity
            && record.cache_generation == cache_generation
            && current_head.event_cursor == cache.progress().next_event_index
            && current_head.leaf_cursor == cache.progress().next_leaf_index
            && validate_anchored_corpus(&record, cache, Some(publisher_pubkey)).is_ok()
        {
            let persisted = PersistedPoiArtifactCache {
                record,
                cache: installed_cache
                    .take()
                    .expect("validated installed cache remains available"),
                cache_generation,
                compaction_recommended: current_head.delta_count
                    >= POI_CORPUS_JOURNAL_SOFT_DELTA_COUNT
                    || current_head.delta_payload_bytes >= POI_CORPUS_JOURNAL_SOFT_PAYLOAD_BYTES,
                journal_head: Some(current_head),
            };
            let expected = persisted.expected_base();
            return Ok((Some(persisted), expected));
        }
    }
    match inspect_persisted_cache_with_publisher(db, identity, Some(publisher_pubkey))? {
        PersistedPoiCorpusInspection::Missing => Ok((None, ExpectedPoiCorpusBase::NoValidCorpus)),
        PersistedPoiCorpusInspection::Valid(persisted) => {
            let expected = persisted.expected_base();
            Ok((Some(*persisted), expected))
        }
        PersistedPoiCorpusInspection::Corrupt {
            replacement_token,
            error,
        } => {
            warn!(?error, "observed corrupt durable PPOI corpus journal");
            Ok((None, ExpectedPoiCorpusBase::Corrupt { replacement_token }))
        }
    }
}

pub(super) fn load_persisted_cache_with_publisher(
    db: &DbStore,
    identity: &PoiCacheIdentity,
    publisher_pubkey: Option<FixedBytes<32>>,
) -> Result<Option<PersistedPoiArtifactCache>, PoiArtifactError> {
    match inspect_persisted_cache_with_publisher(db, identity, publisher_pubkey)? {
        PersistedPoiCorpusInspection::Missing => Ok(None),
        PersistedPoiCorpusInspection::Valid(persisted) => Ok(Some(*persisted)),
        PersistedPoiCorpusInspection::Corrupt { error, .. } => Err(error),
    }
}

pub(super) enum PersistedPoiCorpusInspection {
    Missing,
    Valid(Box<PersistedPoiArtifactCache>),
    Corrupt {
        replacement_token: PoiCorpusJournalCorruptionToken,
        error: PoiArtifactError,
    },
}

pub(super) fn inspect_persisted_cache_with_publisher(
    db: &DbStore,
    identity: &PoiCacheIdentity,
    publisher_pubkey: Option<FixedBytes<32>>,
) -> Result<PersistedPoiCorpusInspection, PoiArtifactError> {
    let load_started = Instant::now();
    let cache_generation = db.poi_artifact_cache_generation()?;
    let (bundle, replacement_token) = match db.inspect_poi_corpus_journal_detailed(
        identity.chain_type,
        identity.chain_id,
        &identity.txid_version,
        &identity.list_key,
    )? {
        PoiCorpusJournalInspection::Missing => return Ok(PersistedPoiCorpusInspection::Missing),
        PoiCorpusJournalInspection::Corrupt {
            key,
            replacement_token,
        } => {
            return Ok(PersistedPoiCorpusInspection::Corrupt {
                replacement_token,
                error: local_db::DbError::InvalidPpoiCorpusJournalRecord {
                    kind: "bundle",
                    key,
                }
                .into(),
            });
        }
        PoiCorpusJournalInspection::Valid {
            bundle,
            replacement_token,
        } => (*bundle, replacement_token),
    };
    let persisted = (|| -> Result<PersistedPoiArtifactCache, PoiArtifactError> {
        let mut base = bundle.base;
        normalize_legacy_artifact_metadata(&mut base);
        if base.cache_generation != cache_generation {
            return Err(PoiArtifactError::PersistedArtifactMetadata {
                reason: "corpus generation does not match the durable generation",
            });
        }
        let cache = validate_persisted_record(&base, identity, publisher_pubkey)?;
        let Some(mut head) = bundle.head else {
            debug!(
                chain_id = identity.chain_id,
                base_bytes = base.cache_payload.len(),
                elapsed_ms = load_started.elapsed().as_millis(),
                "loaded implicit PPOI corpus base"
            );
            return Ok(PersistedPoiArtifactCache {
                record: base,
                cache,
                cache_generation,
                journal_head: None,
                compaction_recommended: false,
            });
        };
        if head.corpus.cache_generation != cache_generation {
            return Err(PoiArtifactError::PersistedArtifactMetadata {
                reason: "journal head generation does not match the durable generation",
            });
        }
        let mut current_tip_root = base.current_tip_root;
        let delta_count = bundle.deltas.len();
        let delta_payload_bytes = bundle
            .deltas
            .iter()
            .map(|delta| delta.payload.len())
            .sum::<usize>();
        let replay_started = Instant::now();
        let mut replay = cache.into_journal_replay();
        for stored_delta in bundle.deltas {
            let delta = PoiCacheJournalDelta::from_bytes_bounded(
                &stored_delta.payload,
                POI_RPC_EVENT_LIMIT,
                POI_RPC_LEAF_LIMIT,
            )?;
            if delta.identity != *identity
                || delta.event_start_cursor != stored_delta.event_start_cursor
                || delta.event_end_cursor != stored_delta.event_end_cursor
                || delta.leaf_start_cursor != stored_delta.leaf_start_cursor
                || delta.leaf_end_cursor != stored_delta.leaf_end_cursor
                || stored_delta.start_tip_root != current_tip_root
            {
                return Err(PoiArtifactError::PersistedArtifactMetadata {
                    reason: "journal delta metadata does not match its replay payload",
                });
            }
            let tip_index = delta
                .event_end_cursor
                .checked_sub(1)
                .ok_or(PoiArtifactError::EmptyPersistedCorpus)?;
            current_tip_root = replay.apply_delta(&delta)?;
            if current_tip_root != stored_delta.end_tip_root {
                return Err(PoiArtifactError::PersistedRootMismatch { tip_index });
            }
        }
        let mut cache = replay.finish();
        let replay_elapsed = replay_started.elapsed();
        if let Some(blocked) = bundle.blocked {
            let blocked_shields: Vec<BlockedShield> =
                decode_bounded_vec(&blocked.payload, POI_BLOCKED_SHIELD_LIMIT)
                    .map_err(PoiCacheError::from)?;
            cache.replace_blocked_shields(&blocked_shields)?;
        }
        normalize_legacy_artifact_metadata(&mut head.corpus);
        if cache.progress().next_event_index != head.event_cursor
            || cache.progress().next_leaf_index != head.leaf_cursor
            || current_tip_root != head.corpus.current_tip_root
        {
            return Err(PoiArtifactError::PersistedArtifactMetadata {
                reason: "replayed journal does not match its committed head",
            });
        }
        validate_materialized_corpus(&head.corpus, &cache, publisher_pubkey)?;
        debug!(
            chain_id = identity.chain_id,
            journal_revision = head.revision,
            base_bytes = base.cache_payload.len(),
            delta_count,
            delta_payload_bytes,
            replay_elapsed_ms = replay_elapsed.as_millis(),
            elapsed_ms = load_started.elapsed().as_millis(),
            "loaded and replayed PPOI corpus journal"
        );
        Ok(PersistedPoiArtifactCache {
            record: head.corpus.clone(),
            cache,
            cache_generation,
            compaction_recommended: head.delta_count >= POI_CORPUS_JOURNAL_SOFT_DELTA_COUNT
                || head.delta_payload_bytes >= POI_CORPUS_JOURNAL_SOFT_PAYLOAD_BYTES,
            journal_head: Some(head),
        })
    })();
    Ok(match persisted {
        Ok(persisted) => PersistedPoiCorpusInspection::Valid(Box::new(persisted)),
        Err(error) => PersistedPoiCorpusInspection::Corrupt {
            replacement_token,
            error,
        },
    })
}
