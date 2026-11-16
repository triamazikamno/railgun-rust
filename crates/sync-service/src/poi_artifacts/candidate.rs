//! Corpus candidates built from verified manifest entries and their starting state.

use std::path::PathBuf;

use alloy::hex;
use alloy::primitives::FixedBytes;
use local_db::{DbStore, PoiArtifactCacheRecord, PoiCorpusJournalHeadRecord};
use poi::artifacts::v4::{EventArtifactDescriptor, ManifestEntry, PublicationId, Scope};
use poi::cache::{PoiCache, PoiCacheIdentity};
use thiserror::Error;
use tracing::warn;

use super::inspect::{PersistedPoiCorpusInspection, inspect_persisted_cache_with_publisher};
use super::manifest::ObservedManifest;
use super::{
    ExpectedPoiCorpusBase, PersistedPoiArtifactCache, PoiArtifactError, SemanticVerifiedChunk,
    VerifiedBlockedShields, VerifiedCatalog,
};

pub(super) enum CandidateBlockedState {
    Pending,
    Verified,
}

#[derive(Clone)]
pub(super) struct CanonicalBoundaries {
    pub(super) checkpoint_descriptors: Vec<EventArtifactDescriptor>,
    pub(super) current_tail: Option<EventArtifactDescriptor>,
}

#[derive(Debug, Error)]
pub enum CandidateError {
    #[error("POI corpus candidate evidence belongs to another publication or manifest entry")]
    IdentityMismatch,
    #[error("POI corpus candidate expected range start {expected}, got {actual}")]
    RangeMismatch { expected: u64, actual: u64 },
    #[error("POI corpus candidate replay failed: {reason}")]
    Replay { reason: String },
    #[error("POI corpus candidate has no root at event index {event_index}")]
    MissingRoot { event_index: u64 },
    #[error("POI corpus candidate replay root mismatch: expected {expected}, got {actual}")]
    RootMismatch { expected: String, actual: String },
    #[error("POI corpus candidate event range overflows")]
    RangeOverflow,
    #[error("POI corpus candidate cannot finish an empty corpus")]
    EmptyCorpus,
    #[error("POI corpus candidate is incomplete: expected {expected} events, got {actual}")]
    Incomplete { expected: u64, actual: u64 },
    #[error("POI corpus candidate has no verified blocked-shields artifact")]
    MissingBlockedShields,
}

pub struct CorpusCandidate {
    pub(super) cache: PoiCache,
    pub(super) entry: ManifestEntry,
    publication: PublicationId,
    db_root: PathBuf,
    cache_generation: u64,
    expected_base: ExpectedPoiCorpusBase,
    pub(super) canonical_boundaries: CanonicalBoundaries,
    pub(super) blocked_state: CandidateBlockedState,
    preserve_ahead_events: bool,
    pub(super) starting_record: Option<PoiArtifactCacheRecord>,
    starting_head: Option<PoiCorpusJournalHeadRecord>,
}

impl CorpusCandidate {
    #[must_use]
    pub const fn scope(&self) -> &Scope {
        &self.entry.scope
    }

    #[must_use]
    pub const fn next_event_index(&self) -> u64 {
        self.cache.progress().next_event_index
    }

    #[must_use]
    pub fn current_root(&self) -> Option<FixedBytes<32>> {
        self.next_event_index()
            .checked_sub(1)
            .and_then(|event_index| self.cache.root_at_global_index(event_index))
    }

    #[must_use]
    pub fn root_at(&self, event_index: u64) -> Option<FixedBytes<32>> {
        self.cache.root_at_global_index(event_index)
    }

    pub(super) fn expected_descriptor_start_root(
        &self,
        range_start: u64,
    ) -> Result<Option<FixedBytes<32>>, CandidateError> {
        if range_start == 0 {
            return Ok(None);
        }
        let event_index = range_start - 1;
        self.cache
            .root_at_global_index(event_index)
            .map(Some)
            .ok_or(CandidateError::MissingRoot { event_index })
    }

    pub(super) fn validate_canonical_boundaries(&self) -> Result<(), CandidateError> {
        for descriptor in self
            .canonical_boundaries
            .checkpoint_descriptors
            .iter()
            .chain(self.canonical_boundaries.current_tail.iter())
        {
            let expected_start_root =
                self.expected_descriptor_start_root(descriptor.range.start_index)?;
            if descriptor.start_root != expected_start_root {
                return Err(CandidateError::RootMismatch {
                    expected: expected_start_root.map_or_else(
                        || "genesis".to_string(),
                        |root| hex::encode_prefixed(root.as_slice()),
                    ),
                    actual: descriptor.start_root.map_or_else(
                        || "genesis".to_string(),
                        |root| hex::encode_prefixed(root.as_slice()),
                    ),
                });
            }
            let actual_end_root = self
                .cache
                .root_at_global_index(descriptor.range.end_index)
                .ok_or(CandidateError::MissingRoot {
                    event_index: descriptor.range.end_index,
                })?;
            if actual_end_root != descriptor.end_root {
                return Err(CandidateError::RootMismatch {
                    expected: hex::encode_prefixed(descriptor.end_root.as_slice()),
                    actual: hex::encode_prefixed(actual_end_root.as_slice()),
                });
            }
        }
        Ok(())
    }

    pub fn restart_from_genesis(&mut self) {
        self.cache = PoiCache::new(PoiCacheIdentity::new(
            self.entry.scope.chain_type,
            self.entry.scope.chain_id,
            self.entry.scope.txid_version.clone(),
            self.entry.scope.list_key,
        ));
        self.blocked_state = CandidateBlockedState::Pending;
        self.preserve_ahead_events = false;
        self.starting_record = None;
        self.starting_head = None;
    }

    pub(crate) const fn preserve_ahead_events(&mut self) {
        self.preserve_ahead_events = true;
    }

    pub fn replay_chunk(mut self, chunk: &SemanticVerifiedChunk) -> Result<Self, CandidateError> {
        if chunk.publication() != self.publication || chunk.entry() != &self.entry {
            return Err(CandidateError::IdentityMismatch);
        }
        let artifact = chunk.artifact();
        let next_event_index = self.next_event_index();
        if artifact.range.start_index > next_event_index {
            return Err(CandidateError::RangeMismatch {
                expected: next_event_index,
                actual: artifact.range.start_index,
            });
        }
        let suffix_offset = next_event_index.saturating_sub(artifact.range.start_index);
        let suffix_offset =
            usize::try_from(suffix_offset).map_err(|_| CandidateError::RangeOverflow)?;
        if suffix_offset > artifact.events.len() {
            return Err(CandidateError::RangeMismatch {
                expected: next_event_index,
                actual: artifact.range.end_index,
            });
        }
        let expected_start_root =
            self.expected_descriptor_start_root(artifact.range.start_index)?;
        if artifact.start_root != expected_start_root {
            return Err(CandidateError::RootMismatch {
                expected: expected_start_root.map_or_else(
                    || "genesis".to_string(),
                    |root| hex::encode_prefixed(root.as_slice()),
                ),
                actual: artifact.start_root.map_or_else(
                    || "genesis".to_string(),
                    |root| hex::encode_prefixed(root.as_slice()),
                ),
            });
        }
        for event in &artifact.events[..suffix_offset] {
            let expected = FixedBytes::from(event.blinded_commitment);
            if self.cache.commitment_at_global_index(event.event_index) != Some(expected) {
                return Err(CandidateError::Replay {
                    reason: format!(
                        "artifact overlap conflicts with durable event {}",
                        event.event_index
                    ),
                });
            }
        }
        if suffix_offset == artifact.events.len() {
            if self.cache.root_at_global_index(artifact.range.end_index) != Some(artifact.end_root)
            {
                return Err(CandidateError::RootMismatch {
                    expected: hex::encode_prefixed(artifact.end_root.as_slice()),
                    actual: "durable overlap root mismatch".to_string(),
                });
            }
            return Ok(self);
        }
        self.cache
            .apply_verified_artifact_events(&artifact.events[suffix_offset..])
            .map_err(|error| CandidateError::Replay {
                reason: error.to_string(),
            })?;
        let replayed_root = self
            .cache
            .root_at_global_index(artifact.range.end_index)
            .ok_or(CandidateError::MissingRoot {
                event_index: artifact.range.end_index,
            })?;
        if replayed_root != artifact.end_root {
            return Err(CandidateError::RootMismatch {
                expected: hex::encode_prefixed(artifact.end_root.as_slice()),
                actual: hex::encode_prefixed(replayed_root.as_slice()),
            });
        }
        Ok(self)
    }

    pub fn install_blocked_shields(
        mut self,
        blocked: &VerifiedBlockedShields,
    ) -> Result<Self, CandidateError> {
        if blocked.publication() != self.publication || blocked.entry() != &self.entry {
            return Err(CandidateError::IdentityMismatch);
        }
        self.cache
            .replace_blocked_shields(blocked.records())
            .map_err(|error| CandidateError::Replay {
                reason: error.to_string(),
            })?;
        self.blocked_state = CandidateBlockedState::Verified;
        Ok(self)
    }

    pub fn finish(mut self) -> Result<VerifiedCorpusCandidate, CandidateError> {
        let tip_index = self
            .entry
            .current_tip_index
            .ok_or(CandidateError::EmptyCorpus)?;
        let expected_root = self.entry.current_root.ok_or(CandidateError::EmptyCorpus)?;
        let expected_event_count = if self.preserve_ahead_events {
            self.next_event_index()
        } else {
            self.entry.event_count
        };
        if self.cache.progress().next_event_index != expected_event_count
            || self.cache.progress().next_leaf_index != expected_event_count
            || (!self.preserve_ahead_events && self.next_event_index() != self.entry.event_count)
            || (self.preserve_ahead_events && self.next_event_index() <= self.entry.event_count)
        {
            return Err(CandidateError::Incomplete {
                expected: expected_event_count,
                actual: self.next_event_index(),
            });
        }
        if self.cache.root_at_global_index(tip_index) != Some(expected_root) {
            return Err(CandidateError::RootMismatch {
                expected: hex::encode_prefixed(expected_root.as_slice()),
                actual: self.cache.root_at_global_index(tip_index).map_or_else(
                    || "missing".to_string(),
                    |root| hex::encode_prefixed(root.as_slice()),
                ),
            });
        }
        let current_tip_index = self
            .next_event_index()
            .checked_sub(1)
            .ok_or(CandidateError::EmptyCorpus)?;
        self.cache
            .root_at_global_index(current_tip_index)
            .ok_or(CandidateError::MissingRoot {
                event_index: current_tip_index,
            })?;
        self.validate_canonical_boundaries()?;
        if !matches!(self.blocked_state, CandidateBlockedState::Verified) {
            return Err(CandidateError::MissingBlockedShields);
        }
        self.cache.accept_current_roots();
        Ok(VerifiedCorpusCandidate {
            cache: self.cache,
            entry: self.entry,
            publication: self.publication,
            db_root: self.db_root,
            cache_generation: self.cache_generation,
            expected_base: self.expected_base,
            preserve_ahead_events: self.preserve_ahead_events,
            starting_record: self.starting_record,
            starting_head: self.starting_head,
        })
    }
}

pub struct VerifiedCorpusCandidate {
    pub(super) cache: PoiCache,
    pub(super) entry: ManifestEntry,
    pub(super) publication: PublicationId,
    pub(super) db_root: PathBuf,
    pub(super) cache_generation: u64,
    pub(super) expected_base: ExpectedPoiCorpusBase,
    pub(super) preserve_ahead_events: bool,
    pub(super) starting_record: Option<PoiArtifactCacheRecord>,
    pub(super) starting_head: Option<PoiCorpusJournalHeadRecord>,
}

impl VerifiedCorpusCandidate {
    #[cfg(test)]
    pub(crate) const fn cache(&self) -> &PoiCache {
        &self.cache
    }

    pub(crate) const fn manifest_sequence(&self) -> u64 {
        self.publication.sequence
    }
}

pub(crate) fn prepare_candidate(
    db: &DbStore,
    observed: &ObservedManifest,
    catalog: &VerifiedCatalog,
) -> Result<CorpusCandidate, PoiArtifactError> {
    if catalog.publication() != observed.publication_id
        || observed.entry(&catalog.entry().scope)? != catalog.entry()
    {
        return Err(PoiArtifactError::PersistedIdentityMismatch);
    }
    let scope = &catalog.entry().scope;
    let identity = PoiCacheIdentity::new(
        scope.chain_type,
        scope.chain_id,
        scope.txid_version.clone(),
        scope.list_key,
    );
    let publisher_pubkey = observed.manifest.publisher_pubkey;
    let (persisted, expected_base) =
        match inspect_persisted_cache_with_publisher(db, &identity, Some(publisher_pubkey))? {
            PersistedPoiCorpusInspection::Missing => (None, ExpectedPoiCorpusBase::NoValidCorpus),
            PersistedPoiCorpusInspection::Valid(persisted) => {
                let expected = persisted.expected_base();
                (Some(*persisted), expected)
            }
            PersistedPoiCorpusInspection::Corrupt {
                replacement_token,
                error,
            } => {
                warn!(?error, "replacing corrupt durable PPOI corpus journal");
                (None, ExpectedPoiCorpusBase::Corrupt { replacement_token })
            }
        };
    prepare_candidate_from_starting(db, observed, catalog, persisted, expected_base)
}

pub(crate) fn prepare_candidate_from_starting(
    db: &DbStore,
    observed: &ObservedManifest,
    catalog: &VerifiedCatalog,
    persisted: Option<PersistedPoiArtifactCache>,
    expected_base: ExpectedPoiCorpusBase,
) -> Result<CorpusCandidate, PoiArtifactError> {
    if catalog.publication() != observed.publication_id
        || observed.entry(&catalog.entry().scope)? != catalog.entry()
    {
        return Err(PoiArtifactError::PersistedIdentityMismatch);
    }
    if persisted
        .as_ref()
        .is_some_and(|persisted| persisted.expected_base() != expected_base)
        || (persisted.is_none()
            && !matches!(
                expected_base,
                ExpectedPoiCorpusBase::NoValidCorpus | ExpectedPoiCorpusBase::Corrupt { .. }
            ))
    {
        return Err(PoiArtifactError::PersistedArtifactMetadata {
            reason: "prepared starting corpus does not match its observed durable state",
        });
    }
    let scope = &catalog.entry().scope;
    let identity = PoiCacheIdentity::new(
        scope.chain_type,
        scope.chain_id,
        scope.txid_version.clone(),
        scope.list_key,
    );
    let publisher_pubkey = observed.manifest.publisher_pubkey;
    let cache_generation = persisted.as_ref().map_or_else(
        || {
            db.poi_artifact_cache_generation()
                .map_err(PoiArtifactError::from)
        },
        |persisted| Ok(persisted.cache_generation),
    )?;
    let starting_state =
        persisted.and_then(|persisted| persisted.into_starting_state(scope, publisher_pubkey));
    let (cache, starting_record, starting_head) = starting_state.map_or_else(
        || (PoiCache::new(identity), None, None),
        |starting| {
            (
                starting.cache,
                Some(starting.record),
                starting.starting_head,
            )
        },
    );
    Ok(CorpusCandidate {
        cache,
        entry: catalog.entry().clone(),
        publication: observed.publication_id,
        db_root: db.root_dir().to_path_buf(),
        cache_generation,
        expected_base,
        canonical_boundaries: CanonicalBoundaries {
            checkpoint_descriptors: catalog.chunks().to_vec(),
            current_tail: catalog.entry().current_tail.clone(),
        },
        blocked_state: CandidateBlockedState::Pending,
        preserve_ahead_events: false,
        starting_record,
        starting_head,
    })
}

pub(crate) fn prepare_candidate_from_starting_for_generation(
    db: &DbStore,
    observed: &ObservedManifest,
    catalog: &VerifiedCatalog,
    persisted: Option<PersistedPoiArtifactCache>,
    expected_base: ExpectedPoiCorpusBase,
    expected_generation: u64,
) -> Result<CorpusCandidate, PoiArtifactError> {
    let candidate =
        prepare_candidate_from_starting(db, observed, catalog, persisted, expected_base)?;
    if candidate.cache_generation != expected_generation {
        return Err(PoiArtifactError::StalePublicCacheGeneration {
            expected: expected_generation,
            actual: candidate.cache_generation,
        });
    }
    Ok(candidate)
}
