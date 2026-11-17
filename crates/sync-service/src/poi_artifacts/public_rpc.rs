//! Persisting public-range corpora and merging list-signed provenance.

use std::time::{Duration, Instant};

use alloy::primitives::FixedBytes;
use local_db::{
    DbStore, POI_CORPUS_JOURNAL_MAX_BLOCKED_PAYLOAD_BYTES, PoiArtifactCacheRecord,
    PoiCacheRecordSource, PoiCorpusBlockedSnapshotRecord, PoiCorpusJournalCommitCondition,
    PoiCorpusJournalCommitOutcome, PoiCorpusJournalDeltaRecord, PoiCorpusJournalHeadRecord,
    PoiCorpusValidationRecord,
};
use poi::cache::{PoiCache, PoiCacheError, PoiCacheJournalDelta};
use poi::poi::BlockedShield;
use tracing::debug;

use crate::poi_limits::{POI_BLOCKED_SHIELD_LIMIT, POI_RPC_EVENT_LIMIT, POI_RPC_LEAF_LIMIT};

use super::validation::{
    normalize_legacy_artifact_metadata, validate_anchored_corpus, validate_materialized_corpus,
};
use super::{
    ExpectedPoiCorpusBase, PendingPublicRpcCommit, PersistedPoiArtifactCache, PoiArtifactError,
    PublicRpcPersistResult, cache_current_tip, empty_descriptor_record,
    ensure_current_cache_generation,
};

const fn expected_base_current_root(expected: ExpectedPoiCorpusBase) -> Option<FixedBytes<32>> {
    match expected {
        ExpectedPoiCorpusBase::NoValidCorpus | ExpectedPoiCorpusBase::Corrupt { .. } => None,
        ExpectedPoiCorpusBase::ImplicitBase {
            current_tip_root, ..
        }
        | ExpectedPoiCorpusBase::JournalHead {
            current_tip_root, ..
        } => Some(current_tip_root),
    }
}

pub(super) fn merge_public_rpc_provenance(
    candidate: &mut PoiArtifactCacheRecord,
    existing: PoiArtifactCacheRecord,
) {
    candidate.legacy_observed_manifest_sequence = candidate
        .legacy_observed_manifest_sequence
        .max(existing.legacy_observed_manifest_sequence);
    if candidate.artifact_tip_index.is_none() {
        candidate.artifact_tip_index = existing.artifact_tip_index;
        candidate.artifact_tip_root = existing.artifact_tip_root;
        candidate.base_descriptor = existing.base_descriptor;
        candidate.applied_delta_descriptors = existing.applied_delta_descriptors;
        candidate.blocked_shields_descriptor = existing.blocked_shields_descriptor;
    }
    if matches!(
        &candidate.validation,
        PoiCorpusValidationRecord::ListSignedRanges { .. }
    ) {
        candidate.validation =
            extend_validation_with_list_ranges(existing.validation, &candidate.validation);
    }
}

fn validate_public_rpc_starting_head(
    expected_base: ExpectedPoiCorpusBase,
    starting_record: Option<&PoiArtifactCacheRecord>,
    starting_head: Option<&PoiCorpusJournalHeadRecord>,
) -> Result<bool, PoiArtifactError> {
    let ExpectedPoiCorpusBase::JournalHead { .. } = expected_base else {
        if starting_head.is_some() {
            return Err(PoiArtifactError::PersistedArtifactMetadata {
                reason: "non-journal public RPC base has an explicit starting head",
            });
        }
        return Ok(false);
    };
    let starting_head = starting_head.ok_or(PoiArtifactError::PersistedArtifactMetadata {
        reason: "journal public RPC append lost its exact starting head",
    })?;
    if ExpectedPoiCorpusBase::from_journal_head(starting_head) != expected_base {
        return Err(PoiArtifactError::PersistedArtifactMetadata {
            reason: "journal public RPC starting head does not match its expected base",
        });
    }
    let mut anchored_record = starting_head.corpus.clone();
    normalize_legacy_artifact_metadata(&mut anchored_record);
    if starting_record != Some(&anchored_record) {
        return Err(PoiArtifactError::PersistedArtifactMetadata {
            reason: "journal public RPC starting metadata does not match its exact head",
        });
    }
    Ok(true)
}

pub(super) fn persist_public_rpc_cache_with_publisher(
    db: &DbStore,
    cache: PoiCache,
    cache_generation: u64,
    range_start_index: u64,
    publisher_pubkey: Option<FixedBytes<32>>,
    expected_base: ExpectedPoiCorpusBase,
    starting_record: Option<&PoiArtifactCacheRecord>,
    starting_head: Option<&PoiCorpusJournalHeadRecord>,
    delta: &PoiCacheJournalDelta,
    blocked_shields: Option<Vec<BlockedShield>>,
) -> Result<PublicRpcPersistResult, PoiArtifactError> {
    let anchored_append =
        validate_public_rpc_starting_head(expected_base, starting_record, starting_head)?;
    let mut record = public_rpc_corpus_record(&cache, cache_generation, range_start_index)?;
    if !public_rpc_delta_fits(delta, &cache, blocked_shields.as_deref()) {
        return Err(PoiArtifactError::PersistedArtifactMetadata {
            reason: "public RPC journal delta does not match its candidate",
        });
    }
    if let Some(existing) = starting_record {
        if !starting_record_continues(existing, &record, delta, expected_base) {
            return Ok(PublicRpcPersistResult::Stale);
        }
        merge_public_rpc_provenance(&mut record, existing.clone());
    } else if !expected_base.replaces_corpus() {
        return Err(PoiArtifactError::PersistedArtifactMetadata {
            reason: "public RPC journal append lost its starting metadata",
        });
    }
    let validation_started = Instant::now();
    if anchored_append {
        validate_anchored_corpus(&record, &cache, publisher_pubkey)?;
    } else {
        validate_materialized_corpus(&record, &cache, publisher_pubkey)?;
    }
    let validation_elapsed = validation_started.elapsed();
    ensure_current_cache_generation(db, cache_generation)?;
    let current_tip_index = record.current_tip_index;
    let (outcome, preparation_elapsed, transaction_elapsed) = PublicRpcJournalWrite {
        db,
        cache: &cache,
        delta,
        blocked_shields: blocked_shields.as_deref(),
        expected_base,
    }
    .commit(record)?;
    if let PoiCorpusJournalCommitOutcome::Applied(commit) = &outcome {
        debug!(
            chain_id = cache.identity().chain_id,
            current_tip_index,
            prior_revision = ?expected_base.journal_revision(),
            journal_revision = commit.head.revision,
            delta_events = delta.events.len(),
            delta_leaves = delta.leaves.len(),
            delta_bytes = commit.delta.as_ref().map_or(0, |delta| delta.payload.len()),
            blocked_bytes = commit
                .blocked
                .as_ref()
                .map_or(0, |blocked| blocked.payload.len()),
            anchored_validation = anchored_append,
            preparation_elapsed_ms = preparation_elapsed.as_millis(),
            validation_elapsed_ms = validation_elapsed.as_millis(),
            transaction_elapsed_ms = transaction_elapsed.as_millis(),
            "PPOI corpus journal append complete"
        );
    }
    public_rpc_persist_result(outcome, cache, blocked_shields, cache_generation)
}

/// The `ListSignedRanges` corpus record for a public-range candidate, serving
/// the cache's current tip.
fn public_rpc_corpus_record(
    cache: &PoiCache,
    cache_generation: u64,
    range_start_index: u64,
) -> Result<PoiArtifactCacheRecord, PoiArtifactError> {
    let identity = cache.identity().clone();
    let (current_tip_index, current_tip_root) = cache_current_tip(cache)?;
    Ok(PoiArtifactCacheRecord {
        chain_type: identity.chain_type,
        chain_id: identity.chain_id,
        txid_version: identity.txid_version.clone(),
        list_key: identity.list_key,
        cache_generation,
        source: PoiCacheRecordSource::PublicRpc,
        validation: PoiCorpusValidationRecord::ListSignedRanges {
            list_key: identity.list_key,
            from_index: range_start_index,
        },
        legacy_observed_manifest_sequence: 0,
        base_descriptor: empty_descriptor_record(),
        applied_delta_descriptors: Vec::new(),
        blocked_shields_descriptor: empty_descriptor_record(),
        artifact_tip_index: None,
        artifact_tip_root: None,
        current_tip_index,
        current_tip_root,
        cache_payload: Vec::new(),
        legacy_last_successful_rpc_sync_at_ms: None,
        updated_at: 0,
    })
}

/// Whether the journal delta covers exactly the candidate's new events and
/// leaves, within the public RPC page and blocked-shield limits.
fn public_rpc_delta_fits(
    delta: &PoiCacheJournalDelta,
    cache: &PoiCache,
    blocked_shields: Option<&[BlockedShield]>,
) -> bool {
    delta.identity == *cache.identity()
        && delta.event_end_cursor == cache.progress().next_event_index
        && delta.leaf_end_cursor == cache.progress().next_leaf_index
        && delta.events.len() <= POI_RPC_EVENT_LIMIT
        && delta.leaves.len() <= POI_RPC_LEAF_LIMIT
        && delta
            .event_end_cursor
            .saturating_sub(delta.event_start_cursor)
            <= POI_RPC_EVENT_LIMIT as u64
        && delta
            .leaf_end_cursor
            .saturating_sub(delta.leaf_start_cursor)
            <= POI_RPC_LEAF_LIMIT as u64
        && blocked_shields.is_none_or(|blocked| blocked.len() <= POI_BLOCKED_SHIELD_LIMIT)
}

/// Whether the stored starting record is the journal state the delta extends:
/// not ahead of the candidate, ending right before the delta, and at the
/// expected base's tip root.
fn starting_record_continues(
    existing: &PoiArtifactCacheRecord,
    record: &PoiArtifactCacheRecord,
    delta: &PoiCacheJournalDelta,
    expected_base: ExpectedPoiCorpusBase,
) -> bool {
    existing.current_tip_index <= record.current_tip_index
        && existing.current_tip_index.saturating_add(1) == delta.event_start_cursor
        && Some(existing.current_tip_root) == expected_base_current_root(expected_base)
}

/// The journal write for one validated public-range corpus record.
struct PublicRpcJournalWrite<'a> {
    db: &'a DbStore,
    cache: &'a PoiCache,
    delta: &'a PoiCacheJournalDelta,
    blocked_shields: Option<&'a [BlockedShield]>,
    expected_base: ExpectedPoiCorpusBase,
}

impl PublicRpcJournalWrite<'_> {
    /// Writes `record` as a new base when the expected base holds no valid
    /// corpus, otherwise appends it to the journal. Returns the outcome with
    /// the preparation and transaction times.
    fn commit(
        &self,
        record: PoiArtifactCacheRecord,
    ) -> Result<(PoiCorpusJournalCommitOutcome, Duration, Duration), PoiArtifactError> {
        let preparation_started = Instant::now();
        let condition = PoiCorpusJournalCommitCondition {
            expected_generation: record.cache_generation,
            expected_publisher: None,
            expected_manifest_hash: None,
            expected_state: self.expected_base.into_db_state(),
        };
        if self.expected_base.replaces_corpus() {
            self.rebase(record, condition, preparation_started)
        } else {
            self.append(record, condition, preparation_started)
        }
    }

    fn rebase(
        &self,
        mut base: PoiArtifactCacheRecord,
        condition: PoiCorpusJournalCommitCondition,
        preparation_started: Instant,
    ) -> Result<(PoiCorpusJournalCommitOutcome, Duration, Duration), PoiArtifactError> {
        base.cache_payload = self.cache.to_bytes()?;
        let preparation_elapsed = preparation_started.elapsed();
        let transaction_started = Instant::now();
        let outcome = self.db.rebase_poi_corpus_journal_if_current(
            base,
            self.cache.progress().next_event_index,
            self.cache.progress().next_leaf_index,
            condition,
        )?;
        Ok((outcome, preparation_elapsed, transaction_started.elapsed()))
    }

    fn append(
        &self,
        record: PoiArtifactCacheRecord,
        condition: PoiCorpusJournalCommitCondition,
        preparation_started: Instant,
    ) -> Result<(PoiCorpusJournalCommitOutcome, Duration, Duration), PoiArtifactError> {
        let stored_delta = self.journal_delta_record(&record)?;
        let blocked = self.blocked_snapshot_record(&record)?;
        let head = PoiCorpusJournalHeadRecord {
            format_version: 0,
            revision: 0,
            base_revision: 0,
            base_payload_hash: FixedBytes::ZERO,
            event_cursor: self.cache.progress().next_event_index,
            leaf_cursor: self.cache.progress().next_leaf_index,
            blocked_revision: None,
            blocked_payload_hash: None,
            delta_count: 0,
            delta_payload_bytes: 0,
            corpus: record,
        };
        let preparation_elapsed = preparation_started.elapsed();
        let transaction_started = Instant::now();
        let outcome =
            self.db
                .append_poi_corpus_journal_if_current(head, stored_delta, blocked, condition)?;
        Ok((outcome, preparation_elapsed, transaction_started.elapsed()))
    }

    /// The stored delta record for a non-empty delta, from the expected base's
    /// tip root to the corpus record's.
    fn journal_delta_record(
        &self,
        corpus: &PoiArtifactCacheRecord,
    ) -> Result<Option<PoiCorpusJournalDeltaRecord>, PoiArtifactError> {
        let delta = self.delta;
        (!delta.is_empty())
            .then(|| {
                Ok::<_, PoiArtifactError>(PoiCorpusJournalDeltaRecord {
                    format_version: 0,
                    chain_type: corpus.chain_type,
                    chain_id: corpus.chain_id,
                    txid_version: corpus.txid_version.clone(),
                    list_key: corpus.list_key,
                    cache_generation: corpus.cache_generation,
                    revision: 0,
                    previous_revision: 0,
                    base_revision: 0,
                    event_start_cursor: delta.event_start_cursor,
                    event_end_cursor: delta.event_end_cursor,
                    leaf_start_cursor: delta.leaf_start_cursor,
                    leaf_end_cursor: delta.leaf_end_cursor,
                    start_tip_root: expected_base_current_root(self.expected_base).ok_or(
                        PoiArtifactError::PersistedArtifactMetadata {
                            reason: "journal append has no expected starting root",
                        },
                    )?,
                    end_tip_root: corpus.current_tip_root,
                    payload: delta.to_bytes()?,
                    updated_at: 0,
                })
            })
            .transpose()
    }

    /// The blocked-shields snapshot record, when the candidate carries one.
    fn blocked_snapshot_record(
        &self,
        corpus: &PoiArtifactCacheRecord,
    ) -> Result<Option<PoiCorpusBlockedSnapshotRecord>, PoiArtifactError> {
        self.blocked_shields
            .map(|blocked_shields| {
                Ok::<_, PoiArtifactError>(PoiCorpusBlockedSnapshotRecord {
                    format_version: 0,
                    chain_type: corpus.chain_type,
                    chain_id: corpus.chain_id,
                    txid_version: corpus.txid_version.clone(),
                    list_key: corpus.list_key,
                    cache_generation: corpus.cache_generation,
                    revision: 0,
                    payload_hash: FixedBytes::ZERO,
                    payload: encode_blocked_shields_snapshot(blocked_shields)?,
                    updated_at: 0,
                })
            })
            .transpose()
    }
}

/// Maps a public-range journal commit outcome to the persist result, handing
/// the candidate back when the journal needs compaction first.
fn public_rpc_persist_result(
    outcome: PoiCorpusJournalCommitOutcome,
    cache: PoiCache,
    blocked_shields: Option<Vec<BlockedShield>>,
    cache_generation: u64,
) -> Result<PublicRpcPersistResult, PoiArtifactError> {
    match outcome {
        PoiCorpusJournalCommitOutcome::Applied(commit) => Ok(PublicRpcPersistResult::Applied(
            Box::new(PersistedPoiArtifactCache {
                record: commit.head.corpus.clone(),
                cache,
                cache_generation,
                journal_head: Some(commit.head.clone()),
                compaction_recommended: commit.compaction_recommended,
            }),
        )),
        PoiCorpusJournalCommitOutcome::CorpusConflict => Ok(PublicRpcPersistResult::Stale),
        PoiCorpusJournalCommitOutcome::CompactionRequired => Ok(
            PublicRpcPersistResult::CompactionRequired(Box::new(PendingPublicRpcCommit {
                cache,
                blocked_shields,
            })),
        ),
        PoiCorpusJournalCommitOutcome::GenerationConflict { actual } => {
            Err(PoiArtifactError::StalePublicCacheGeneration {
                expected: actual,
                actual: cache_generation,
            })
        }
        PoiCorpusJournalCommitOutcome::PublisherSequenceConflict { .. }
        | PoiCorpusJournalCommitOutcome::PublisherManifestConflict { .. } => {
            Ok(PublicRpcPersistResult::Stale)
        }
    }
}

fn encode_blocked_shields_snapshot(
    blocked_shields: &[BlockedShield],
) -> Result<Vec<u8>, PoiArtifactError> {
    let payload = rmp_serde::to_vec_named(blocked_shields).map_err(PoiCacheError::from)?;
    let payload_bytes = u64::try_from(payload.len()).unwrap_or(u64::MAX);
    if payload_bytes > POI_CORPUS_JOURNAL_MAX_BLOCKED_PAYLOAD_BYTES {
        return Err(PoiArtifactError::Persistence {
            reason: format!(
                "public RPC blocked snapshot has {payload_bytes} bytes, maximum is {POI_CORPUS_JOURNAL_MAX_BLOCKED_PAYLOAD_BYTES}"
            ),
        });
    }
    Ok(payload)
}

pub(super) const fn list_signed_range(
    validation: &PoiCorpusValidationRecord,
) -> Option<(FixedBytes<32>, u64)> {
    match validation {
        PoiCorpusValidationRecord::ListSignedRanges {
            list_key,
            from_index,
        } => Some((*list_key, *from_index)),
        PoiCorpusValidationRecord::PublisherAndListSigned {
            list_key,
            list_signed_from_index,
            ..
        }
        | PoiCorpusValidationRecord::PublisherV4AndListSigned {
            list_key,
            list_signed_from_index,
            ..
        } => Some((*list_key, *list_signed_from_index)),
        PoiCorpusValidationRecord::PublisherAttested { .. }
        | PoiCorpusValidationRecord::PublisherAttestedV4 { .. }
        | PoiCorpusValidationRecord::Legacy => None,
    }
}

pub(super) fn extend_validation_with_list_ranges(
    existing: PoiCorpusValidationRecord,
    candidate: &PoiCorpusValidationRecord,
) -> PoiCorpusValidationRecord {
    let PoiCorpusValidationRecord::ListSignedRanges {
        list_key,
        from_index,
    } = candidate
    else {
        return existing;
    };
    match existing {
        PoiCorpusValidationRecord::PublisherAttested {
            publisher_pubkey,
            manifest_sequence,
            manifest_root,
            artifact_tip_index,
        } => PoiCorpusValidationRecord::PublisherAndListSigned {
            publisher_pubkey,
            manifest_sequence,
            manifest_root,
            artifact_tip_index,
            list_key: *list_key,
            list_signed_from_index: (*from_index).max(artifact_tip_index.saturating_add(1)),
        },
        PoiCorpusValidationRecord::PublisherAndListSigned {
            publisher_pubkey,
            manifest_sequence,
            manifest_root,
            artifact_tip_index,
            list_key,
            list_signed_from_index,
        } => PoiCorpusValidationRecord::PublisherAndListSigned {
            publisher_pubkey,
            manifest_sequence,
            manifest_root,
            artifact_tip_index,
            list_key,
            list_signed_from_index: list_signed_from_index.min(*from_index),
        },
        PoiCorpusValidationRecord::PublisherAttestedV4 {
            publisher_pubkey,
            manifest_sequence,
            manifest_body_hash,
            manifest_root,
            artifact_tip_index,
            format_version,
            checkpoint_catalog,
        } => PoiCorpusValidationRecord::PublisherV4AndListSigned {
            publisher_pubkey,
            manifest_sequence,
            manifest_body_hash,
            manifest_root,
            artifact_tip_index,
            format_version,
            checkpoint_catalog,
            list_key: *list_key,
            list_signed_from_index: (*from_index).max(artifact_tip_index.saturating_add(1)),
        },
        PoiCorpusValidationRecord::PublisherV4AndListSigned {
            publisher_pubkey,
            manifest_sequence,
            manifest_body_hash,
            manifest_root,
            artifact_tip_index,
            format_version,
            checkpoint_catalog,
            list_key,
            list_signed_from_index,
        } => PoiCorpusValidationRecord::PublisherV4AndListSigned {
            publisher_pubkey,
            manifest_sequence,
            manifest_body_hash,
            manifest_root,
            artifact_tip_index,
            format_version,
            checkpoint_catalog,
            list_key,
            list_signed_from_index: list_signed_from_index.min(*from_index),
        },
        PoiCorpusValidationRecord::ListSignedRanges {
            list_key,
            from_index: existing_from_index,
        } => PoiCorpusValidationRecord::ListSignedRanges {
            list_key,
            from_index: existing_from_index.min(*from_index),
        },
        PoiCorpusValidationRecord::Legacy => PoiCorpusValidationRecord::Legacy,
    }
}
