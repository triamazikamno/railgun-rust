//! Persisting verified artifact corpora as monotonic journal rebases.

use std::time::{Duration, Instant};

use alloy::primitives::FixedBytes;
use broadcaster_core::tree::normalize_tree_position;
use local_db::{
    DbStore, ExpectedPoiCorpusJournalState, PoiArtifactCacheRecord, PoiCacheRecordSource,
    PoiCorpusJournalCommitCondition, PoiCorpusJournalCommitOutcome,
    PoiCorpusJournalCorruptionToken, PoiCorpusJournalHeadRecord, PoiCorpusValidationRecord,
    PoiV4CatalogIdentityRecord, StoredRecord,
};
use poi::artifacts::v4::{ManifestEntry, PublicationId};
use poi::cache::{PoiCache, PoiCacheIdentity};
use sha2::{Digest, Sha256};
use tracing::{debug, warn};

use super::candidate::VerifiedCorpusCandidate;
use super::inspect::{PersistedPoiCorpusInspection, inspect_persisted_cache_with_publisher};
use super::public_rpc::{
    extend_validation_with_list_ranges, list_signed_range, merge_public_rpc_provenance,
};
use super::validation::{validate_materialized_corpus, validate_materialized_corpus_payload};
use super::{
    ExpectedPoiCorpusBase, PersistCorpusResult, PersistedPoiArtifactCache, PoiArtifactError,
    cache_current_tip, descriptor_record, empty_descriptor_record, ensure_current_cache_generation,
};

struct PreparedPoiCorpus {
    record: PoiArtifactCacheRecord,
    cache: PoiCache,
    serialization_elapsed: Duration,
}

impl PreparedPoiCorpus {
    fn new(mut record: PoiArtifactCacheRecord, cache: PoiCache) -> Result<Self, PoiArtifactError> {
        let serialization_started = Instant::now();
        record.cache_payload = cache.to_bytes()?;
        Ok(Self {
            record,
            cache,
            serialization_elapsed: serialization_started.elapsed(),
        })
    }
}

pub(crate) fn persist_prepared_corpus(
    db: &DbStore,
    candidate: VerifiedCorpusCandidate,
) -> Result<PersistCorpusResult, PoiArtifactError> {
    let VerifiedCorpusCandidate {
        cache,
        entry,
        publication,
        db_root,
        cache_generation,
        expected_base,
        preserve_ahead_events,
        starting_record,
        starting_head,
    } = candidate;
    ensure_current_cache_generation(db, cache_generation)?;
    if db.root_dir() != db_root.as_path() {
        return Err(PoiArtifactError::PersistedIdentityMismatch);
    }
    let identity = cache.identity().clone();
    if !entry_scope_matches(&identity, &entry) {
        return Err(PoiArtifactError::PersistedIdentityMismatch);
    }
    let evidence = ArtifactCorpusEvidence::new(&entry, &publication, cache_generation, &cache)?;
    if !evidence.served_by(&cache, preserve_ahead_events) {
        return Err(PoiArtifactError::PersistedArtifactRootMismatch {
            tip_index: evidence.artifact_tip_index,
        });
    }
    let record = if preserve_ahead_events {
        evidence.ahead_refresh_record(starting_record)?
    } else {
        evidence.v4_record(&identity)?
    };
    CorpusRebase {
        db,
        publisher_pubkey: Some(publication.publisher_pubkey),
        expected_base,
        starting_head: starting_head.as_ref(),
        expected_generation: cache_generation,
        expected_publisher: Some((publication.publisher_pubkey, publication.sequence)),
        expected_manifest_hash: Some(publication.manifest_body_hash),
    }
    .persist_monotonic(PreparedPoiCorpus::new(record, cache)?)
}

/// Whether the manifest entry covers the same corpus identity as the cache.
fn entry_scope_matches(identity: &PoiCacheIdentity, entry: &ManifestEntry) -> bool {
    identity.chain_type == entry.scope.chain_type
        && identity.chain_id == entry.scope.chain_id
        && identity.txid_version == entry.scope.txid_version
        && identity.list_key == entry.scope.list_key
}

/// A verified manifest entry's claims about a candidate corpus, and the tip
/// the candidate cache serves.
struct ArtifactCorpusEvidence<'a> {
    entry: &'a ManifestEntry,
    publication: &'a PublicationId,
    cache_generation: u64,
    artifact_tip_index: u64,
    manifest_root: FixedBytes<32>,
    current_tip_index: u64,
    current_tip_root: FixedBytes<32>,
}

impl<'a> ArtifactCorpusEvidence<'a> {
    fn new(
        entry: &'a ManifestEntry,
        publication: &'a PublicationId,
        cache_generation: u64,
        cache: &PoiCache,
    ) -> Result<Self, PoiArtifactError> {
        let artifact_tip_index = entry
            .current_tip_index
            .ok_or(PoiArtifactError::EmptyPersistedCorpus)?;
        let manifest_root = entry
            .current_root
            .ok_or(PoiArtifactError::EmptyPersistedCorpus)?;
        let (current_tip_index, current_tip_root) = cache_current_tip(cache)?;
        Ok(Self {
            entry,
            publication,
            cache_generation,
            artifact_tip_index,
            manifest_root,
            current_tip_index,
            current_tip_root,
        })
    }

    /// Whether the cache serves the artifact tip: exactly at its current tip,
    /// or, for an ahead refresh, as a historical root below it.
    fn served_by(&self, cache: &PoiCache, preserve_ahead_events: bool) -> bool {
        if preserve_ahead_events {
            self.current_tip_index > self.artifact_tip_index
                && cache.root_at_global_index(self.artifact_tip_index) == Some(self.manifest_root)
        } else {
            self.current_tip_index == self.artifact_tip_index
                && self.current_tip_root == self.manifest_root
        }
    }

    /// The starting record refreshed for a blocked-only manifest update that
    /// keeps the durable events ahead of the artifact tip.
    fn ahead_refresh_record(
        &self,
        starting_record: Option<PoiArtifactCacheRecord>,
    ) -> Result<PoiArtifactCacheRecord, PoiArtifactError> {
        let mut record = starting_record.ok_or(PoiArtifactError::PersistedArtifactMetadata {
            reason: "ahead blocked-only refresh lost its starting provenance",
        })?;
        let boundary_unchanged = record.current_tip_index == self.current_tip_index
            && record.current_tip_root == self.current_tip_root
            && record.cache_generation == self.cache_generation;
        if !boundary_unchanged {
            return Err(PoiArtifactError::PersistedArtifactMetadata {
                reason: "ahead blocked-only refresh changed its durable event boundary",
            });
        }
        record.legacy_observed_manifest_sequence = record
            .legacy_observed_manifest_sequence
            .max(self.publication.sequence);
        record.blocked_shields_descriptor = descriptor_record(&self.entry.blocked_shields.artifact);
        record.updated_at = 0;
        Ok(record)
    }

    /// The `PublisherAttestedV4` corpus record for a cache that ends at the
    /// artifact tip.
    fn v4_record(
        &self,
        identity: &PoiCacheIdentity,
    ) -> Result<PoiArtifactCacheRecord, PoiArtifactError> {
        let publication = self.publication;
        let catalog_descriptor = &self.entry.checkpoint_catalog;
        let descriptor_bytes =
            serde_json::to_vec(catalog_descriptor).map_err(PoiArtifactError::Json)?;
        let catalog_descriptor_hash: [u8; 32] = Sha256::digest(descriptor_bytes).into();
        let validation = PoiCorpusValidationRecord::PublisherAttestedV4 {
            publisher_pubkey: publication.publisher_pubkey,
            manifest_sequence: publication.sequence,
            manifest_body_hash: Some(publication.manifest_body_hash),
            manifest_root: self.manifest_root,
            artifact_tip_index: self.artifact_tip_index,
            format_version: poi::artifacts::v4::FORMAT_VERSION,
            checkpoint_catalog: PoiV4CatalogIdentityRecord {
                cid: catalog_descriptor.artifact.cid.clone(),
                sha256: catalog_descriptor.artifact.sha256,
                byte_size: catalog_descriptor.artifact.byte_size,
                descriptor_hash: FixedBytes::from(catalog_descriptor_hash),
            },
        };
        Ok(PoiArtifactCacheRecord {
            chain_type: identity.chain_type,
            chain_id: identity.chain_id,
            txid_version: identity.txid_version.clone(),
            list_key: identity.list_key,
            cache_generation: self.cache_generation,
            source: PoiCacheRecordSource::IndexedArtifacts,
            validation,
            legacy_observed_manifest_sequence: publication.sequence,
            base_descriptor: empty_descriptor_record(),
            applied_delta_descriptors: Vec::new(),
            blocked_shields_descriptor: descriptor_record(&self.entry.blocked_shields.artifact),
            artifact_tip_index: Some(self.artifact_tip_index),
            artifact_tip_root: Some(self.manifest_root),
            current_tip_index: self.current_tip_index,
            current_tip_root: self.current_tip_root,
            cache_payload: Vec::new(),
            legacy_last_successful_rpc_sync_at_ms: None,
            updated_at: 0,
        })
    }
}

/// The durable journal state a corpus base rebase must find, and what its commit checks.
struct CorpusRebase<'a> {
    db: &'a DbStore,
    publisher_pubkey: Option<FixedBytes<32>>,
    expected_base: ExpectedPoiCorpusBase,
    starting_head: Option<&'a PoiCorpusJournalHeadRecord>,
    expected_generation: u64,
    expected_publisher: Option<(FixedBytes<32>, u64)>,
    expected_manifest_hash: Option<FixedBytes<32>>,
}

/// The durable corpus a rebase replaces and the journal state its commit expects.
struct RebaseBase {
    existing: Option<PersistedPoiArtifactCache>,
    state: ExpectedPoiCorpusJournalState,
}

impl CorpusRebase<'_> {
    /// Rebases the durable journal onto `prepared` when the durable corpus is
    /// still the expected base and the candidate does not move backward.
    fn persist_monotonic(
        &self,
        prepared: PreparedPoiCorpus,
    ) -> Result<PersistCorpusResult, PoiArtifactError> {
        let PreparedPoiCorpus {
            record: mut candidate,
            cache: candidate_cache,
            serialization_elapsed,
        } = prepared;
        let candidate_identity = matching_cache_identity(&candidate, &candidate_cache)?;
        let prepared_validation_started = Instant::now();
        validate_materialized_corpus_payload(&candidate, &candidate_cache)?;
        let prepared_validation_elapsed = prepared_validation_started.elapsed();
        let existing_validation_started = Instant::now();
        let Some(RebaseBase { existing, state }) =
            self.inspect_base(&candidate, &candidate_identity, &candidate_cache)?
        else {
            return Ok(PersistCorpusResult::Stale);
        };
        if let Some(existing) = existing {
            let Some(continued) = continue_from_existing(candidate, &candidate_cache, existing)?
            else {
                return Ok(PersistCorpusResult::Stale);
            };
            candidate = continued;
        }
        let existing_validation_elapsed = existing_validation_started.elapsed();
        let final_validation_started = Instant::now();
        validate_materialized_corpus(&candidate, &candidate_cache, self.publisher_pubkey)?;
        let final_validation_elapsed = final_validation_started.elapsed();
        let source = candidate.source;
        let chain_id = candidate.chain_id;
        let current_tip_index = candidate.current_tip_index;
        let payload_bytes = candidate.cache_payload.len();
        let transaction_started = Instant::now();
        let outcome = self.db.rebase_poi_corpus_journal_if_current(
            candidate,
            candidate_cache.progress().next_event_index,
            candidate_cache.progress().next_leaf_index,
            PoiCorpusJournalCommitCondition {
                expected_generation: self.expected_generation,
                expected_publisher: self.expected_publisher,
                expected_manifest_hash: self.expected_manifest_hash,
                expected_state: state,
            },
        )?;
        let transaction_elapsed = transaction_started.elapsed();
        let (journal_revision, retired_delta_count, retired_delta_payload_bytes) =
            applied_rebase_stats(&outcome);
        debug!(
            ?source,
            chain_id,
            current_tip_index,
            payload_bytes,
            ?journal_revision,
            ?retired_delta_count,
            ?retired_delta_payload_bytes,
            serialization_elapsed_ms = serialization_elapsed.as_millis(),
            prepared_validation_elapsed_ms = prepared_validation_elapsed.as_millis(),
            existing_validation_elapsed_ms = existing_validation_elapsed.as_millis(),
            final_validation_elapsed_ms = final_validation_elapsed.as_millis(),
            transaction_elapsed_ms = transaction_elapsed.as_millis(),
            "PPOI corpus base rebase stages complete"
        );
        self.commit_result(outcome, candidate_cache)
    }

    /// The durable corpus the rebase replaces, or `None` when it is no longer
    /// the expected base. A corrupt journal is replaced only when it is safe to.
    fn inspect_base(
        &self,
        candidate: &PoiArtifactCacheRecord,
        identity: &PoiCacheIdentity,
        cache: &PoiCache,
    ) -> Result<Option<RebaseBase>, PoiArtifactError> {
        let base = match inspect_persisted_cache_with_publisher(
            self.db,
            identity,
            self.publisher_pubkey,
        )? {
            PersistedPoiCorpusInspection::Missing => {
                if self.expected_base != ExpectedPoiCorpusBase::NoValidCorpus {
                    return Ok(None);
                }
                RebaseBase {
                    existing: None,
                    state: ExpectedPoiCorpusJournalState::NoValidBase,
                }
            }
            PersistedPoiCorpusInspection::Valid(existing) => {
                let observed = existing.expected_base();
                if observed != self.expected_base {
                    return Ok(None);
                }
                RebaseBase {
                    existing: Some(*existing),
                    state: observed.into_db_state(),
                }
            }
            PersistedPoiCorpusInspection::Corrupt {
                replacement_token,
                error,
            } => {
                if !self.corrupt_journal_repairable(replacement_token, identity, cache)? {
                    return Ok(None);
                }
                warn!(?error, key = %candidate.key(), "replacing corrupt durable PPOI corpus journal");
                RebaseBase {
                    existing: None,
                    state: ExpectedPoiCorpusJournalState::Corrupt { replacement_token },
                }
            }
        };
        Ok(Some(base))
    }

    fn corrupt_journal_repairable(
        &self,
        replacement_token: PoiCorpusJournalCorruptionToken,
        identity: &PoiCacheIdentity,
        cache: &PoiCache,
    ) -> Result<bool, PoiArtifactError> {
        match self.expected_base {
            ExpectedPoiCorpusBase::Corrupt {
                replacement_token: expected_token,
            } => Ok(self.starting_head.is_none() && expected_token == replacement_token),
            _ => artifact_candidate_can_repair_corrupt_journal(
                self.db,
                identity,
                cache,
                self.expected_base,
                self.starting_head,
                self.expected_generation,
            ),
        }
    }

    /// Maps the rebase commit outcome to the persist result.
    fn commit_result(
        &self,
        outcome: PoiCorpusJournalCommitOutcome,
        cache: PoiCache,
    ) -> Result<PersistCorpusResult, PoiArtifactError> {
        match outcome {
            PoiCorpusJournalCommitOutcome::Applied(commit) => Ok(PersistCorpusResult::Applied(
                Box::new(PersistedPoiArtifactCache {
                    record: commit.head.corpus.clone(),
                    cache,
                    cache_generation: self.expected_generation,
                    journal_head: Some(commit.head.clone()),
                    compaction_recommended: false,
                }),
            )),
            PoiCorpusJournalCommitOutcome::CorpusConflict => Ok(PersistCorpusResult::Stale),
            PoiCorpusJournalCommitOutcome::GenerationConflict { actual } => {
                Err(PoiArtifactError::StalePublicCacheGeneration {
                    expected: actual,
                    actual: self.expected_generation,
                })
            }
            PoiCorpusJournalCommitOutcome::PublisherSequenceConflict { actual } => {
                if actual.is_some_and(|sequence| {
                    self.expected_publisher
                        .is_some_and(|(_, expected)| sequence > expected)
                }) {
                    Ok(PersistCorpusResult::Stale)
                } else {
                    Err(PoiArtifactError::UnobservedManifestSequence {
                        candidate: self.expected_publisher.map_or(0, |(_, sequence)| sequence),
                    })
                }
            }
            PoiCorpusJournalCommitOutcome::PublisherManifestConflict { .. } => {
                Ok(PersistCorpusResult::Stale)
            }
            PoiCorpusJournalCommitOutcome::CompactionRequired => {
                Err(PoiArtifactError::Persistence {
                    reason: "base rebase unexpectedly requires compaction".to_string(),
                })
            }
        }
    }
}

/// The identity the candidate record names, when its cache has that identity.
fn matching_cache_identity(
    candidate: &PoiArtifactCacheRecord,
    cache: &PoiCache,
) -> Result<PoiCacheIdentity, PoiArtifactError> {
    let identity = PoiCacheIdentity::new(
        candidate.chain_type,
        candidate.chain_id,
        candidate.txid_version.clone(),
        candidate.list_key,
    );
    if cache.identity() != &identity {
        return Err(PoiArtifactError::PersistedIdentityMismatch);
    }
    Ok(identity)
}

/// The journal revision and retired delta count and bytes of an applied rebase.
fn applied_rebase_stats(
    outcome: &PoiCorpusJournalCommitOutcome,
) -> (Option<u64>, Option<u32>, Option<u64>) {
    match outcome {
        PoiCorpusJournalCommitOutcome::Applied(commit) => (
            Some(commit.head.revision),
            Some(commit.retired_delta_count),
            Some(commit.retired_delta_payload_bytes),
        ),
        _ => (None, None, None),
    }
}

/// The candidate continued from the existing durable corpus: its events must
/// extend the existing ones, and it inherits the existing public-range
/// provenance. `None` when the existing corpus is ahead of the candidate.
fn continue_from_existing(
    mut candidate: PoiArtifactCacheRecord,
    candidate_cache: &PoiCache,
    existing: PersistedPoiArtifactCache,
) -> Result<Option<PoiArtifactCacheRecord>, PoiArtifactError> {
    if existing.record.current_tip_index > candidate.current_tip_index {
        return Ok(None);
    }
    validate_candidate_event_prefix(
        &existing.cache,
        candidate_cache,
        existing.record.current_tip_index,
        existing.record.current_tip_root,
        candidate.current_tip_index,
    )?;
    if matches!(candidate.source, PoiCacheRecordSource::PublicRpc) {
        merge_public_rpc_provenance(&mut candidate, existing.record);
    } else if let Some((list_key, from_index)) = list_signed_range(&existing.record.validation) {
        candidate.validation = extend_validation_with_list_ranges(
            candidate.validation,
            &PoiCorpusValidationRecord::ListSignedRanges {
                list_key,
                from_index,
            },
        );
        candidate.source = PoiCacheRecordSource::PublicRpc;
    }
    Ok(Some(candidate))
}

fn artifact_candidate_can_repair_corrupt_journal(
    db: &DbStore,
    identity: &PoiCacheIdentity,
    candidate: &PoiCache,
    expected_base: ExpectedPoiCorpusBase,
    starting_head: Option<&PoiCorpusJournalHeadRecord>,
    expected_generation: u64,
) -> Result<bool, PoiArtifactError> {
    let Some(starting_head) = starting_head else {
        return Ok(false);
    };
    let expected_starting_base = ExpectedPoiCorpusBase::JournalHead {
        revision: starting_head.revision,
        base_revision: starting_head.base_revision,
        base_payload_hash: starting_head.base_payload_hash,
        event_cursor: starting_head.event_cursor,
        leaf_cursor: starting_head.leaf_cursor,
        current_tip_root: starting_head.corpus.current_tip_root,
    };
    if expected_base != expected_starting_base
        || starting_head.corpus.chain_type != identity.chain_type
        || starting_head.corpus.chain_id != identity.chain_id
        || starting_head.corpus.txid_version != identity.txid_version
        || starting_head.corpus.list_key != identity.list_key
        || starting_head.corpus.cache_generation != expected_generation
        || candidate.identity() != identity
        || candidate.progress().next_event_index < starting_head.event_cursor
        || candidate.progress().next_leaf_index < starting_head.leaf_cursor
    {
        return Ok(false);
    }
    let Some(starting_tip_index) = starting_head.event_cursor.checked_sub(1) else {
        return Ok(false);
    };
    if candidate.root_at_global_index(starting_tip_index)
        != Some(starting_head.corpus.current_tip_root)
    {
        return Ok(false);
    }
    Ok(matches!(
        db.inspect_poi_corpus_journal_head(
            identity.chain_type,
            identity.chain_id,
            &identity.txid_version,
            &identity.list_key,
        )?,
        StoredRecord::Valid(current_head) if current_head == *starting_head
    ))
}

fn validate_candidate_event_prefix(
    existing_cache: &PoiCache,
    candidate_cache: &PoiCache,
    durable_tip_index: u64,
    durable_tip_root: FixedBytes<32>,
    candidate_tip_index: u64,
) -> Result<(), PoiArtifactError> {
    let (tip_tree, _) = normalize_tree_position(0, durable_tip_index);
    let existing_roots = existing_cache.current_roots_readonly();
    let candidate_roots = candidate_cache.current_roots_readonly();
    if let Some(tree_number) = existing_roots
        .range(..tip_tree)
        .zip(candidate_roots.range(..tip_tree))
        .find_map(
            |((tree_number, existing), (candidate_tree_number, candidate))| {
                (tree_number != candidate_tree_number || existing != candidate)
                    .then_some(*tree_number)
            },
        )
        .or_else(|| {
            (existing_roots.range(..tip_tree).count() != candidate_roots.range(..tip_tree).count())
                .then_some(tip_tree.saturating_sub(1))
        })
    {
        return Err(PoiArtifactError::CorpusPrefixRootConflict {
            tip_index: durable_tip_index,
            tree_number,
        });
    }
    if candidate_cache.root_at_global_index(durable_tip_index) != Some(durable_tip_root) {
        if candidate_tip_index == durable_tip_index {
            return Err(PoiArtifactError::CorpusTipRootConflict {
                tip_index: durable_tip_index,
            });
        }
        return Err(PoiArtifactError::CorpusPrefixRootConflict {
            tip_index: durable_tip_index,
            tree_number: tip_tree,
        });
    }
    Ok(())
}
