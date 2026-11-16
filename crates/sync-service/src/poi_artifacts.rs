use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use alloy::hex;
use alloy::primitives::{FixedBytes, keccak256};
use broadcaster_core::tree::normalize_tree_position;
use local_db::{
    DbStore, ExpectedPoiCorpusJournalState, POI_CORPUS_JOURNAL_MAX_BLOCKED_PAYLOAD_BYTES,
    POI_CORPUS_JOURNAL_SOFT_DELTA_COUNT, POI_CORPUS_JOURNAL_SOFT_PAYLOAD_BYTES,
    PoiArtifactCacheRecord, PoiArtifactDescriptorRecord, PoiCacheRecordSource,
    PoiCorpusBlockedSnapshotRecord, PoiCorpusJournalCommitCondition, PoiCorpusJournalCommitOutcome,
    PoiCorpusJournalCorruptionToken, PoiCorpusJournalDeltaRecord, PoiCorpusJournalHeadRecord,
    PoiCorpusJournalInspection, PoiCorpusRpcHealthRecord, PoiCorpusValidationRecord,
    PoiPublisherManifestObservation, PoiPublisherManifestWatermarkRecord,
    PoiV4CatalogIdentityRecord, StoredRecord,
};
use poi::artifacts::v4::{
    Error as ArtifactFormatError, EventArtifactDescriptor, Manifest, ManifestEntry, PublicationId,
    Scope,
};
use poi::artifacts::{ArtifactDescriptor, ManifestError};
use poi::cache::{PoiCache, PoiCacheError, PoiCacheIdentity, PoiCacheJournalDelta};
use poi::poi::BlockedShield;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{debug, warn};

use crate::poi_limits::{
    POI_BLOCKED_SHIELD_LIMIT, POI_RPC_EVENT_LIMIT, POI_RPC_LEAF_LIMIT, decode_bounded_vec,
};
use crate::trustless_artifacts::TrustlessArtifactError;
use crate::types::{PoiArtifactCacheGraphProgress, PoiArtifactCachePhase, PoiArtifactSourceConfig};
use trustless_artifacts::GatewayPool;

mod v4_cache;
mod v4_ingest;

pub(crate) use v4_cache::POI_V4_RAW_CHUNK_BLOB_KIND;
pub use v4_cache::{
    CurrentChunk, FetchedArtifact, RawChunkRetainOutcome, SemanticVerifiedChunk,
    TransportVerifiedChunk, VerifiedBlockedShields, VerifiedCatalog,
};
pub(crate) use v4_cache::{
    RawChunkCache, RawChunkCacheError, RawChunkCacheResetFailure, reset_raw_chunk_cache,
};
pub(crate) use v4_ingest::PreparedIngestion;

static POI_ARTIFACT_PUBLICATION_FENCE: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

fn lock_poi_artifact_publication() -> MutexGuard<'static, ()> {
    POI_ARTIFACT_PUBLICATION_FENCE
        .lock()
        .expect("POI artifact publication fence poisoned")
}

#[derive(Clone, Copy)]
pub(crate) struct PoiArtifactProgressEvent {
    pub(crate) phase: PoiArtifactCachePhase,
    pub(crate) current_event_index: Option<u64>,
    pub(crate) target_event_index: Option<u64>,
    pub(crate) graph: PoiArtifactCacheGraphProgress,
}

type PoiArtifactProgressObserver = Arc<dyn Fn(PoiArtifactProgressEvent) + Send + Sync>;

pub(crate) struct PoiArtifactIngestor {
    config: PoiArtifactSourceConfig,
    client: reqwest::Client,
    gateway_pool: GatewayPool,
    progress_observer: Option<PoiArtifactProgressObserver>,
}

impl PoiArtifactIngestor {
    pub(crate) fn new(config: PoiArtifactSourceConfig, client: reqwest::Client) -> Self {
        let gateway_pool = config.gateway_pool.clone().unwrap_or_default();
        Self {
            config,
            client,
            gateway_pool,
            progress_observer: None,
        }
    }

    pub(crate) fn fetcher(&self) -> crate::trustless_artifacts::TrustlessArtifactFetcher<'_> {
        crate::trustless_artifacts::TrustlessArtifactFetcher::new_poi_with_pool(
            &self.client,
            &self.config.gateway_urls,
            self.gateway_pool.clone(),
        )
    }

    pub(crate) fn with_progress_observer(
        mut self,
        observer: impl Fn(PoiArtifactProgressEvent) + Send + Sync + 'static,
    ) -> Self {
        self.progress_observer = Some(Arc::new(observer));
        self
    }

    fn report_progress(
        &self,
        phase: PoiArtifactCachePhase,
        current_event_index: Option<u64>,
        target_event_index: Option<u64>,
        graph: PoiArtifactCacheGraphProgress,
    ) {
        if let Some(observer) = self.progress_observer.as_ref() {
            observer(PoiArtifactProgressEvent {
                phase,
                current_event_index,
                target_event_index,
                graph,
            });
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExpectedPoiCorpusBase {
    NoValidCorpus,
    Corrupt {
        replacement_token: PoiCorpusJournalCorruptionToken,
    },
    ImplicitBase {
        payload_hash: FixedBytes<32>,
        event_cursor: u64,
        leaf_cursor: u64,
        current_tip_root: FixedBytes<32>,
    },
    JournalHead {
        revision: u64,
        base_revision: u64,
        base_payload_hash: FixedBytes<32>,
        event_cursor: u64,
        leaf_cursor: u64,
        current_tip_root: FixedBytes<32>,
    },
}

impl ExpectedPoiCorpusBase {
    pub(crate) const fn from_journal_head(head: &PoiCorpusJournalHeadRecord) -> Self {
        Self::JournalHead {
            revision: head.revision,
            base_revision: head.base_revision,
            base_payload_hash: head.base_payload_hash,
            event_cursor: head.event_cursor,
            leaf_cursor: head.leaf_cursor,
            current_tip_root: head.corpus.current_tip_root,
        }
    }

    const fn journal_revision(self) -> Option<u64> {
        match self {
            Self::NoValidCorpus | Self::ImplicitBase { .. } => Some(0),
            Self::JournalHead { revision, .. } => Some(revision),
            Self::Corrupt { .. } => None,
        }
    }

    const fn into_db_state(self) -> ExpectedPoiCorpusJournalState {
        match self {
            Self::NoValidCorpus => ExpectedPoiCorpusJournalState::NoValidBase,
            Self::Corrupt { replacement_token } => {
                ExpectedPoiCorpusJournalState::Corrupt { replacement_token }
            }
            Self::ImplicitBase {
                payload_hash,
                event_cursor,
                leaf_cursor,
                current_tip_root,
            } => ExpectedPoiCorpusJournalState::ImplicitBase {
                base_payload_hash: payload_hash,
                event_cursor,
                leaf_cursor,
                current_tip_root,
            },
            Self::JournalHead {
                revision,
                base_revision,
                base_payload_hash,
                event_cursor,
                leaf_cursor,
                current_tip_root,
            } => ExpectedPoiCorpusJournalState::Head {
                revision,
                base_revision,
                base_payload_hash,
                event_cursor,
                leaf_cursor,
                current_tip_root,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorpusCommitOutcome {
    Applied,
    Stale,
}

#[derive(Clone)]
pub struct ObservedManifest {
    manifest: Manifest,
    publication_id: PublicationId,
    /// Configured index of the gateway that served the manifest bytes, used as
    /// the first choice for its checkpoint catalogs. Transport metadata only;
    /// it is not persisted.
    serving_gateway_index: Option<usize>,
}

impl ObservedManifest {
    #[must_use]
    pub const fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    #[must_use]
    pub const fn publication_id(&self) -> PublicationId {
        self.publication_id
    }

    pub(crate) const fn serving_gateway_index(&self) -> Option<usize> {
        self.serving_gateway_index
    }

    pub(crate) const fn set_serving_gateway_index(&mut self, gateway_index: usize) {
        self.serving_gateway_index = Some(gateway_index);
    }

    fn entry(&self, scope: &Scope) -> Result<&ManifestEntry, PoiArtifactError> {
        self.manifest
            .entries
            .iter()
            .find(|entry| entry.scope == *scope)
            .ok_or_else(|| PoiArtifactError::MissingManifestEntry {
                chain_id: scope.chain_id,
                list_key: hex::encode_prefixed(scope.list_key.as_slice()),
                txid_version: scope.txid_version.clone(),
            })
    }
}

pub(crate) fn observe_manifest_with_clock<F>(
    db: &DbStore,
    trusted_publisher_pubkey: FixedBytes<32>,
    manifest: Manifest,
    max_age: Option<Duration>,
    acceptance_time: &F,
) -> Result<ObservedManifest, PoiArtifactError>
where
    F: Fn() -> SystemTime + ?Sized,
{
    manifest.verify_trusted_signature_envelope(&trusted_publisher_pubkey.0)?;
    let publication_id = manifest.publication_id_envelope()?;
    let _publication_fence = lock_poi_artifact_publication();
    let previous = publisher_manifest_watermark(db, trusted_publisher_pubkey)?;
    let exact_replay = validate_manifest_order(&publication_id, previous.as_ref())?;
    if !exact_replay {
        // Keep this sample inside the observation fences and adjacent to freshness and persistence.
        validate_manifest_freshness(&manifest, max_age, acceptance_time())?;
    }
    match db.observe_poi_v4_publisher_manifest(
        trusted_publisher_pubkey,
        publication_id.sequence,
        publication_id.manifest_body_hash,
    )? {
        PoiPublisherManifestObservation::Accepted { .. } => {}
        PoiPublisherManifestObservation::Rollback { record } => {
            return Err(PoiArtifactError::ManifestSequenceRollback {
                previous: record.accepted_sequence,
                received: manifest.sequence,
            });
        }
        PoiPublisherManifestObservation::Equivocation { .. } => {
            return Err(PoiArtifactError::ManifestSequenceEquivocation {
                sequence: manifest.sequence,
            });
        }
    }
    manifest.validate()?;
    Ok(ObservedManifest {
        manifest,
        publication_id,
        serving_gateway_index: None,
    })
}

/// Returns the durable publisher manifest sequence, including a migrated
/// hashless floor, for use as the IPNS resolution sequence floor.
pub(crate) fn publisher_manifest_sequence(
    db: &DbStore,
    publisher_pubkey: FixedBytes<32>,
) -> Result<Option<u64>, PoiArtifactError> {
    let _publication_fence = lock_poi_artifact_publication();
    Ok(publisher_manifest_watermark(db, publisher_pubkey)?.map(|record| record.accepted_sequence))
}

pub(crate) struct PersistedPoiArtifactCache {
    pub(crate) record: PoiArtifactCacheRecord,
    pub(crate) cache: PoiCache,
    pub(crate) cache_generation: u64,
    pub(crate) journal_head: Option<PoiCorpusJournalHeadRecord>,
    pub(crate) compaction_recommended: bool,
}

impl std::fmt::Debug for PersistedPoiArtifactCache {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PersistedPoiArtifactCache")
            .field("identity", self.cache.identity())
            .field("cache_generation", &self.cache_generation)
            .field("source", &self.record.source)
            .field("current_tip_index", &self.record.current_tip_index)
            .field(
                "journal_revision",
                &self.journal_head.as_ref().map(|head| head.revision),
            )
            .field("compaction_recommended", &self.compaction_recommended)
            .finish_non_exhaustive()
    }
}

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

#[derive(Debug)]
pub(crate) enum PersistCorpusResult {
    Applied(Box<PersistedPoiArtifactCache>),
    Stale,
}

pub(crate) enum PublicRpcPersistResult {
    Applied(Box<PersistedPoiArtifactCache>),
    Stale,
    CompactionRequired(Box<PendingPublicRpcCommit>),
}

pub(crate) struct PendingPublicRpcCommit {
    pub(crate) cache: PoiCache,
    pub(crate) blocked_shields: Option<Vec<BlockedShield>>,
}

pub(crate) enum PoiCorpusCompactionResult {
    Applied(Box<PersistedPoiArtifactCache>),
    Stale,
}

impl PersistCorpusResult {
    pub(crate) const fn outcome(&self) -> CorpusCommitOutcome {
        match self {
            Self::Applied(_) => CorpusCommitOutcome::Applied,
            Self::Stale => CorpusCommitOutcome::Stale,
        }
    }
}

pub(crate) struct CorpusStartingState {
    cache: PoiCache,
    record: PoiArtifactCacheRecord,
    starting_head: Option<PoiCorpusJournalHeadRecord>,
}

enum CandidateBlockedState {
    Pending,
    Verified,
}

#[derive(Clone)]
struct CanonicalBoundaries {
    checkpoint_descriptors: Vec<EventArtifactDescriptor>,
    current_tail: Option<EventArtifactDescriptor>,
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
    cache: PoiCache,
    entry: ManifestEntry,
    publication: PublicationId,
    db_root: PathBuf,
    cache_generation: u64,
    expected_base: ExpectedPoiCorpusBase,
    canonical_boundaries: CanonicalBoundaries,
    blocked_state: CandidateBlockedState,
    preserve_ahead_events: bool,
    starting_record: Option<PoiArtifactCacheRecord>,
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

    fn expected_descriptor_start_root(
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

    fn validate_canonical_boundaries(&self) -> Result<(), CandidateError> {
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
    cache: PoiCache,
    entry: ManifestEntry,
    publication: PublicationId,
    db_root: PathBuf,
    cache_generation: u64,
    expected_base: ExpectedPoiCorpusBase,
    preserve_ahead_events: bool,
    starting_record: Option<PoiArtifactCacheRecord>,
    starting_head: Option<PoiCorpusJournalHeadRecord>,
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

impl PersistedPoiArtifactCache {
    pub(crate) fn expected_base(&self) -> ExpectedPoiCorpusBase {
        self.journal_head.as_ref().map_or_else(
            || ExpectedPoiCorpusBase::ImplicitBase {
                payload_hash: keccak256(&self.record.cache_payload),
                event_cursor: self.cache.progress().next_event_index,
                leaf_cursor: self.cache.progress().next_leaf_index,
                current_tip_root: self.record.current_tip_root,
            },
            ExpectedPoiCorpusBase::from_journal_head,
        )
    }

    pub(crate) fn metadata_only(&self) -> PoiArtifactCacheRecord {
        self.record.metadata_only()
    }

    pub(crate) fn into_starting_state(
        self,
        scope: &Scope,
        expected_publisher_pubkey: FixedBytes<32>,
    ) -> Option<CorpusStartingState> {
        let identity = self.cache.identity();
        if identity.chain_type != scope.chain_type
            || identity.chain_id != scope.chain_id
            || identity.txid_version != scope.txid_version
            || identity.list_key != scope.list_key
        {
            return None;
        }
        let publisher_pubkey = match &self.record.validation {
            PoiCorpusValidationRecord::PublisherAttested {
                publisher_pubkey, ..
            }
            | PoiCorpusValidationRecord::PublisherAndListSigned {
                publisher_pubkey, ..
            }
            | PoiCorpusValidationRecord::PublisherAttestedV4 {
                publisher_pubkey, ..
            }
            | PoiCorpusValidationRecord::PublisherV4AndListSigned {
                publisher_pubkey, ..
            } => *publisher_pubkey,
            PoiCorpusValidationRecord::Legacy
            | PoiCorpusValidationRecord::ListSignedRanges { .. } => return None,
        };
        if publisher_pubkey != expected_publisher_pubkey {
            return None;
        }
        Some(CorpusStartingState {
            cache: self.cache,
            record: self.record,
            starting_head: self.journal_head,
        })
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

pub(crate) struct PoiCorpusStore<'a> {
    db: &'a DbStore,
    generation: u64,
    publisher_pubkey: FixedBytes<32>,
}

impl<'a> PoiCorpusStore<'a> {
    pub(crate) const fn new(
        db: &'a DbStore,
        generation: u64,
        publisher_pubkey: FixedBytes<32>,
    ) -> Self {
        Self {
            db,
            generation,
            publisher_pubkey,
        }
    }

    pub(crate) fn load(
        &self,
        identity: &PoiCacheIdentity,
    ) -> Result<Option<PersistedPoiArtifactCache>, PoiArtifactError> {
        load_persisted_cache_for_publisher(self.db, identity, self.publisher_pubkey)
    }

    pub(crate) fn commit_public_rpc(
        &self,
        cache: PoiCache,
        range_start_index: u64,
        expected_base: ExpectedPoiCorpusBase,
        starting_record: Option<&PoiArtifactCacheRecord>,
        starting_head: Option<&PoiCorpusJournalHeadRecord>,
        delta: &PoiCacheJournalDelta,
        blocked_shields: Option<Vec<BlockedShield>>,
    ) -> Result<PublicRpcPersistResult, PoiArtifactError> {
        persist_public_rpc_cache_with_publisher(
            self.db,
            cache,
            self.generation,
            range_start_index,
            Some(self.publisher_pubkey),
            expected_base,
            starting_record,
            starting_head,
            delta,
            blocked_shields,
        )
    }

    pub(crate) fn compact(
        &self,
        identity: &PoiCacheIdentity,
        expected_base: ExpectedPoiCorpusBase,
    ) -> Result<PoiCorpusCompactionResult, PoiArtifactError> {
        let semantic_validation_started = Instant::now();
        let Some(persisted) = self.load(identity)? else {
            return Ok(PoiCorpusCompactionResult::Stale);
        };
        let semantic_validation_elapsed = semantic_validation_started.elapsed();
        if persisted.expected_base() != expected_base {
            return Ok(PoiCorpusCompactionResult::Stale);
        }
        let serialization_started = Instant::now();
        let mut base = persisted.metadata_only();
        base.cache_payload = persisted.cache.to_bytes()?;
        let event_cursor = persisted.cache.progress().next_event_index;
        let leaf_cursor = persisted.cache.progress().next_leaf_index;
        let cache = persisted.cache;
        let serialization_elapsed = serialization_started.elapsed();
        let transaction_started = Instant::now();
        let outcome = self.db.rebase_poi_corpus_journal_if_current(
            base,
            event_cursor,
            leaf_cursor,
            PoiCorpusJournalCommitCondition {
                expected_generation: self.generation,
                expected_publisher: None,
                expected_manifest_hash: None,
                expected_state: expected_base.into_db_state(),
            },
        )?;
        let transaction_elapsed = transaction_started.elapsed();
        match outcome {
            PoiCorpusJournalCommitOutcome::Applied(commit) => {
                debug!(
                    chain_id = identity.chain_id,
                    journal_revision = commit.head.revision,
                    retired_delta_count = commit.retired_delta_count,
                    retired_delta_payload_bytes = commit.retired_delta_payload_bytes,
                    semantic_validation_elapsed_ms = semantic_validation_elapsed.as_millis(),
                    serialization_elapsed_ms = serialization_elapsed.as_millis(),
                    transaction_elapsed_ms = transaction_elapsed.as_millis(),
                    "PPOI corpus journal compaction complete"
                );
                Ok(PoiCorpusCompactionResult::Applied(Box::new(
                    PersistedPoiArtifactCache {
                        record: commit.head.corpus.clone(),
                        cache,
                        cache_generation: self.generation,
                        journal_head: Some(commit.head.clone()),
                        compaction_recommended: false,
                    },
                )))
            }
            PoiCorpusJournalCommitOutcome::CorpusConflict
            | PoiCorpusJournalCommitOutcome::PublisherSequenceConflict { .. }
            | PoiCorpusJournalCommitOutcome::PublisherManifestConflict { .. } => {
                Ok(PoiCorpusCompactionResult::Stale)
            }
            PoiCorpusJournalCommitOutcome::GenerationConflict { actual } => {
                Err(PoiArtifactError::StalePublicCacheGeneration {
                    expected: actual,
                    actual: self.generation,
                })
            }
            PoiCorpusJournalCommitOutcome::CompactionRequired => {
                Err(PoiArtifactError::Persistence {
                    reason: "POI corpus journal compaction was rejected".to_string(),
                })
            }
        }
    }
}

pub(crate) fn load_poi_rpc_health(
    db: &DbStore,
    identity: &PoiCacheIdentity,
    generation: u64,
    legacy_last_successful_rpc_sync_at_ms: Option<u64>,
) -> Result<Option<u64>, PoiArtifactError> {
    let current_generation = db.poi_artifact_cache_generation()?;
    if current_generation != generation {
        return Err(PoiArtifactError::StalePublicCacheGeneration {
            expected: current_generation,
            actual: generation,
        });
    }
    match db.inspect_poi_corpus_rpc_health(
        identity.chain_type,
        identity.chain_id,
        &identity.txid_version,
        &identity.list_key,
    )? {
        StoredRecord::Valid(health) if health.cache_generation == generation => {
            Ok(health.last_successful_rpc_sync_at_ms)
        }
        StoredRecord::Valid(_) => Ok(None),
        StoredRecord::Corrupt { key } => {
            warn!(%key, "ignoring corrupt advisory PPOI RPC health");
            Ok(None)
        }
        StoredRecord::Missing => {
            if legacy_last_successful_rpc_sync_at_ms.is_some() {
                db.put_poi_corpus_rpc_health(&PoiCorpusRpcHealthRecord {
                    chain_type: identity.chain_type,
                    chain_id: identity.chain_id,
                    txid_version: identity.txid_version.clone(),
                    list_key: identity.list_key,
                    cache_generation: generation,
                    last_successful_rpc_sync_at_ms: legacy_last_successful_rpc_sync_at_ms,
                    updated_at: 0,
                })?;
            }
            Ok(legacy_last_successful_rpc_sync_at_ms)
        }
    }
}

pub(crate) fn record_poi_rpc_success(
    db: &DbStore,
    identity: &PoiCacheIdentity,
    generation: u64,
) -> Result<(), PoiArtifactError> {
    let current_generation = db.poi_artifact_cache_generation()?;
    if current_generation != generation {
        return Err(PoiArtifactError::StalePublicCacheGeneration {
            expected: current_generation,
            actual: generation,
        });
    }
    db.put_poi_corpus_rpc_health(&PoiCorpusRpcHealthRecord {
        chain_type: identity.chain_type,
        chain_id: identity.chain_id,
        txid_version: identity.txid_version.clone(),
        list_key: identity.list_key,
        cache_generation: generation,
        last_successful_rpc_sync_at_ms: Some(unix_time_ms()),
        updated_at: 0,
    })?;
    Ok(())
}

fn publisher_manifest_watermark(
    db: &DbStore,
    publisher_pubkey: FixedBytes<32>,
) -> Result<Option<PoiPublisherManifestWatermarkRecord>, PoiArtifactError> {
    match db.inspect_poi_publisher_manifest_watermark(&publisher_pubkey)? {
        StoredRecord::Valid(record) => return Ok(Some(record)),
        StoredRecord::Corrupt { key } => {
            return Err(local_db::DbError::InvalidPpoiSidecarRecord {
                kind: "publisher manifest watermark",
                key,
            }
            .into());
        }
        StoredRecord::Missing => {}
    }

    let mut accepted_sequence = None;
    let scan = db.scan_poi_artifact_caches()?;
    if !scan.invalid_keys.is_empty() {
        return Err(PoiArtifactError::AmbiguousPublisherWatermarkMigration {
            invalid_records: scan.invalid_keys.len(),
        });
    }
    for mut record in scan.records {
        normalize_legacy_artifact_metadata(&mut record);
        let identity = PoiCacheIdentity::new(
            record.chain_type,
            record.chain_id,
            record.txid_version.clone(),
            record.list_key,
        );
        if validate_persisted_record(&record, &identity, Some(publisher_pubkey)).is_ok()
            && let Some(sequence) = publisher_sequence_for_record(&record, publisher_pubkey)
        {
            let sequence = sequence.max(record.legacy_observed_manifest_sequence);
            accepted_sequence =
                Some(accepted_sequence.map_or(sequence, |accepted: u64| accepted.max(sequence)));
        }
    }
    let accepted_sequence = accepted_sequence.filter(|sequence| *sequence > 0);
    if let Some(sequence) = accepted_sequence {
        let (record, _) =
            db.advance_poi_publisher_manifest_watermark(publisher_pubkey, sequence)?;
        return Ok(Some(record));
    }
    Ok(None)
}

fn publisher_sequence_for_record(
    record: &PoiArtifactCacheRecord,
    expected_publisher_pubkey: FixedBytes<32>,
) -> Option<u64> {
    match &record.validation {
        PoiCorpusValidationRecord::PublisherAttested {
            publisher_pubkey,
            manifest_sequence,
            ..
        }
        | PoiCorpusValidationRecord::PublisherAndListSigned {
            publisher_pubkey,
            manifest_sequence,
            ..
        }
        | PoiCorpusValidationRecord::PublisherAttestedV4 {
            publisher_pubkey,
            manifest_sequence,
            ..
        }
        | PoiCorpusValidationRecord::PublisherV4AndListSigned {
            publisher_pubkey,
            manifest_sequence,
            ..
        } if *publisher_pubkey == expected_publisher_pubkey => Some(*manifest_sequence),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PoiArtifactCacheReset {
    pub(crate) removed: u64,
    pub(crate) generation: u64,
}

#[derive(Debug, Error)]
pub(crate) enum PoiArtifactError {
    #[error("POI artifact source has no gateway URLs configured")]
    NoGateways,
    #[error("POI artifact ingestion requires an IPNS manifest source")]
    RequiresIpnsSource,
    #[error("POI artifact ingestion was cancelled")]
    Cancelled,
    #[error("POI corpus persistence wrapper rejected the operation: {reason}")]
    Persistence { reason: String },
    #[error("POI corpus journal remains above its hard bound after one compaction retry")]
    JournalHardLimitExceeded,
    #[error("POI artifact refresh plan has no authenticated route from event {start_index}")]
    NoReplayRoute { start_index: u64 },
    #[error("POI artifact refresh plan arithmetic overflow")]
    PlanOverflow,
    #[error("POI artifact fetch window exceeds the aggregate encoded byte limit")]
    InflightByteLimit,
    #[error("POI artifact manifest JSON decode failed")]
    Json(#[source] serde_json::Error),
    #[error("POI artifact manifest verification failed")]
    Manifest(#[from] ManifestError),
    #[error("POI artifact verification failed")]
    Format(#[from] ArtifactFormatError),
    #[error("POI artifact checkpoint chunk cache failed")]
    RawChunk(#[from] RawChunkCacheError),
    #[error("POI corpus candidate verification failed")]
    Candidate(#[from] CandidateError),
    #[error("POI artifact trustless retrieval failed")]
    Trustless(#[from] TrustlessArtifactError),
    #[error("POI artifact cache replay failed")]
    Cache(#[from] PoiCacheError),
    #[error("POI artifact cache persistence failed")]
    Db(#[from] local_db::DbError),
    #[error("manifest sequence rollback: previous={previous}, received={received}")]
    ManifestSequenceRollback { previous: u64, received: u64 },
    #[error("publisher equivocated at manifest sequence {sequence}")]
    ManifestSequenceEquivocation { sequence: u64 },
    #[error("artifact candidate uses manifest sequence {candidate} before durable observation")]
    UnobservedManifestSequence { candidate: u64 },
    #[error(
        "publisher watermark migration is ambiguous because {invalid_records} legacy PPOI corpus records are corrupt"
    )]
    AmbiguousPublisherWatermarkMigration { invalid_records: usize },
    #[error("manifest is stale: age={age:?}, max={max:?}")]
    ManifestStale { age: Duration, max: Duration },
    #[error("manifest issued_at_ms is in the future")]
    ManifestIssuedInFuture,
    #[error(
        "manifest does not contain POI v4 entry for chain_id={chain_id} list_key={list_key} txid_version={txid_version}"
    )]
    MissingManifestEntry {
        chain_id: u64,
        list_key: String,
        txid_version: String,
    },
    #[error("stale POI artifact cache refresh: expected generation {expected}, actual {actual}")]
    StalePublicCacheGeneration { expected: u64, actual: u64 },
    #[error("POI corpus root missing for tree {tree_number}")]
    MissingCacheRoot { tree_number: u32 },
    #[error("POI corpus candidate conflicts with the durable root at tip {tip_index}")]
    CorpusTipRootConflict { tip_index: u64 },
    #[error("persisted POI corpus is empty")]
    EmptyPersistedCorpus,
    #[error(
        "persisted POI corpus cursor mismatch: next event {next_event_index}, next leaf {next_leaf_index}"
    )]
    PersistedCursorMismatch {
        next_event_index: u64,
        next_leaf_index: u64,
    },
    #[error("persisted POI corpus tip mismatch: metadata {metadata}, payload {payload}")]
    PersistedTipMismatch { metadata: u64, payload: u64 },
    #[error("persisted POI corpus record identity does not match its payload")]
    PersistedIdentityMismatch,
    #[error("persisted POI corpus root is missing for tree {tree_number}")]
    MissingPersistedRoot { tree_number: u32 },
    #[error("persisted POI corpus root does not match its payload at tip {tip_index}")]
    PersistedRootMismatch { tip_index: u64 },
    #[error("persisted POI corpus payload does not retain validated current roots")]
    PersistedRootsNotValidated,
    #[error("persisted POI corpus artifact metadata is inconsistent: {reason}")]
    PersistedArtifactMetadata { reason: &'static str },
    #[error("persisted POI corpus artifact root does not match its payload at tip {tip_index}")]
    PersistedArtifactRootMismatch { tip_index: u64 },
    #[error("persisted POI corpus validation provenance is inconsistent: {reason}")]
    PersistedValidationProvenance { reason: &'static str },
    #[error(
        "POI corpus candidate conflicts with durable event history through tip {tip_index} in tree {tree_number}"
    )]
    CorpusPrefixRootConflict { tip_index: u64, tree_number: u32 },
}

const fn normalize_legacy_artifact_metadata(record: &mut PoiArtifactCacheRecord) {
    if record.artifact_tip_index.is_none()
        && matches!(record.source, PoiCacheRecordSource::IndexedArtifacts)
    {
        record.artifact_tip_index = Some(record.current_tip_index);
        record.artifact_tip_root = Some(record.current_tip_root);
    }
}

fn validate_materialized_corpus_payload(
    record: &PoiArtifactCacheRecord,
    cache: &PoiCache,
) -> Result<(), PoiArtifactError> {
    let roots = cache.current_roots_readonly();
    if cache.validated_roots() != Some(&roots) {
        return Err(PoiArtifactError::PersistedRootsNotValidated);
    }
    validate_corpus_payload_with_roots(record, cache, &roots)
}

fn validate_anchored_corpus_payload(
    record: &PoiArtifactCacheRecord,
    cache: &PoiCache,
) -> Result<(), PoiArtifactError> {
    let roots = cache
        .validated_roots()
        .ok_or(PoiArtifactError::PersistedRootsNotValidated)?;
    validate_corpus_payload_metadata_with_roots(record, cache, roots)?;
    Ok(())
}

fn validate_corpus_payload_with_roots(
    record: &PoiArtifactCacheRecord,
    cache: &PoiCache,
    roots: &BTreeMap<u32, FixedBytes<32>>,
) -> Result<(), PoiArtifactError> {
    if let Some((index, root)) = validate_corpus_payload_metadata_with_roots(record, cache, roots)?
        && cache.root_at_global_index(index) != Some(root)
    {
        return Err(PoiArtifactError::PersistedArtifactRootMismatch { tip_index: index });
    }
    Ok(())
}

fn validate_corpus_payload_metadata_with_roots(
    record: &PoiArtifactCacheRecord,
    cache: &PoiCache,
    roots: &BTreeMap<u32, FixedBytes<32>>,
) -> Result<Option<(u64, FixedBytes<32>)>, PoiArtifactError> {
    let next_event_index = cache.progress().next_event_index;
    let next_leaf_index = cache.progress().next_leaf_index;
    if next_event_index == 0 {
        return Err(PoiArtifactError::EmptyPersistedCorpus);
    }
    if next_event_index != next_leaf_index {
        return Err(PoiArtifactError::PersistedCursorMismatch {
            next_event_index,
            next_leaf_index,
        });
    }
    let payload_tip_index = next_event_index - 1;
    if record.current_tip_index != payload_tip_index {
        return Err(PoiArtifactError::PersistedTipMismatch {
            metadata: record.current_tip_index,
            payload: payload_tip_index,
        });
    }
    let (tree_number, _) = normalize_tree_position(0, payload_tip_index);
    let payload_tip_root = roots
        .get(&tree_number)
        .ok_or(PoiArtifactError::MissingPersistedRoot { tree_number })?;
    if record.current_tip_root != *payload_tip_root {
        return Err(PoiArtifactError::PersistedRootMismatch {
            tip_index: payload_tip_index,
        });
    }
    match (record.artifact_tip_index, record.artifact_tip_root) {
        (Some(index), Some(root)) if index <= payload_tip_index => Ok(Some((index, root))),
        (None, None) => Ok(None),
        (Some(_), Some(_)) => Err(PoiArtifactError::PersistedArtifactMetadata {
            reason: "artifact tip exceeds serving tip",
        }),
        _ => Err(PoiArtifactError::PersistedArtifactMetadata {
            reason: "artifact tip index and root must be present together",
        }),
    }
}

fn validate_materialized_corpus(
    record: &PoiArtifactCacheRecord,
    cache: &PoiCache,
    expected_publisher_pubkey: Option<FixedBytes<32>>,
) -> Result<(), PoiArtifactError> {
    validate_materialized_corpus_payload(record, cache)?;
    validate_corpus_provenance(record, cache, expected_publisher_pubkey)
}

fn validate_anchored_corpus(
    record: &PoiArtifactCacheRecord,
    cache: &PoiCache,
    expected_publisher_pubkey: Option<FixedBytes<32>>,
) -> Result<(), PoiArtifactError> {
    validate_anchored_corpus_payload(record, cache)?;
    validate_corpus_provenance(record, cache, expected_publisher_pubkey)
}

fn validate_corpus_provenance(
    record: &PoiArtifactCacheRecord,
    cache: &PoiCache,
    expected_publisher_pubkey: Option<FixedBytes<32>>,
) -> Result<(), PoiArtifactError> {
    let next_event_index = cache.progress().next_event_index;
    let payload_tip_index = next_event_index.saturating_sub(1);

    match &record.validation {
        PoiCorpusValidationRecord::Legacy => {
            if expected_publisher_pubkey.is_some()
                && matches!(record.source, PoiCacheRecordSource::IndexedArtifacts)
            {
                return Err(PoiArtifactError::PersistedValidationProvenance {
                    reason: "legacy artifact evidence does not identify the configured publisher",
                });
            }
        }
        PoiCorpusValidationRecord::PublisherAttested {
            publisher_pubkey,
            manifest_root,
            artifact_tip_index,
            ..
        } => {
            if expected_publisher_pubkey.is_some_and(|expected| expected != *publisher_pubkey)
                || !matches!(record.source, PoiCacheRecordSource::IndexedArtifacts)
                || record.artifact_tip_index != Some(*artifact_tip_index)
                || record.artifact_tip_root != Some(*manifest_root)
                || *artifact_tip_index != payload_tip_index
            {
                return Err(PoiArtifactError::PersistedValidationProvenance {
                    reason: "publisher-attested evidence does not match the serving artifact tip",
                });
            }
        }
        PoiCorpusValidationRecord::ListSignedRanges {
            list_key,
            from_index,
        } => {
            if !matches!(record.source, PoiCacheRecordSource::PublicRpc)
                || list_key != &record.list_key
                || record.artifact_tip_index.is_some()
                || *from_index > next_event_index
            {
                return Err(PoiArtifactError::PersistedValidationProvenance {
                    reason: "list-signed evidence does not match the public range corpus",
                });
            }
        }
        PoiCorpusValidationRecord::PublisherAndListSigned {
            publisher_pubkey,
            manifest_root,
            artifact_tip_index,
            list_key,
            list_signed_from_index,
            ..
        } => {
            if expected_publisher_pubkey.is_some_and(|expected| expected != *publisher_pubkey)
                || !matches!(record.source, PoiCacheRecordSource::PublicRpc)
                || list_key != &record.list_key
                || record.artifact_tip_index != Some(*artifact_tip_index)
                || record.artifact_tip_root != Some(*manifest_root)
                || *artifact_tip_index >= next_event_index
                || *list_signed_from_index != artifact_tip_index.saturating_add(1)
                || *list_signed_from_index > next_event_index
            {
                return Err(PoiArtifactError::PersistedValidationProvenance {
                    reason: "mixed publisher/list evidence does not match corpus boundaries",
                });
            }
        }
        PoiCorpusValidationRecord::PublisherAttestedV4 {
            publisher_pubkey,
            manifest_body_hash,
            manifest_root,
            artifact_tip_index,
            format_version,
            checkpoint_catalog,
            ..
        } => {
            if expected_publisher_pubkey.is_some_and(|expected| expected != *publisher_pubkey)
                || !matches!(record.source, PoiCacheRecordSource::IndexedArtifacts)
                || record.artifact_tip_index != Some(*artifact_tip_index)
                || record.artifact_tip_root != Some(*manifest_root)
                || *artifact_tip_index != payload_tip_index
                || *format_version != poi::artifacts::v4::FORMAT_VERSION
                || manifest_body_hash.is_none()
                || checkpoint_catalog.cid.is_empty()
                || checkpoint_catalog.byte_size == 0
                || checkpoint_catalog.descriptor_hash == FixedBytes::ZERO
            {
                return Err(PoiArtifactError::PersistedValidationProvenance {
                    reason: "v4 publisher evidence does not match the serving corpus",
                });
            }
        }
        PoiCorpusValidationRecord::PublisherV4AndListSigned {
            publisher_pubkey,
            manifest_body_hash,
            manifest_root,
            artifact_tip_index,
            format_version,
            checkpoint_catalog,
            list_key,
            list_signed_from_index,
            ..
        } => {
            if expected_publisher_pubkey.is_some_and(|expected| expected != *publisher_pubkey)
                || !matches!(record.source, PoiCacheRecordSource::PublicRpc)
                || record.artifact_tip_index != Some(*artifact_tip_index)
                || record.artifact_tip_root != Some(*manifest_root)
                || *artifact_tip_index >= next_event_index
                || *format_version != poi::artifacts::v4::FORMAT_VERSION
                || manifest_body_hash.is_none()
                || checkpoint_catalog.cid.is_empty()
                || checkpoint_catalog.byte_size == 0
                || checkpoint_catalog.descriptor_hash == FixedBytes::ZERO
                || list_key != &record.list_key
                || *list_signed_from_index != artifact_tip_index.saturating_add(1)
                || *list_signed_from_index > next_event_index
            {
                return Err(PoiArtifactError::PersistedValidationProvenance {
                    reason: "mixed v4 publisher/list evidence does not match corpus boundaries",
                });
            }
        }
    }
    Ok(())
}

fn validate_persisted_record(
    record: &PoiArtifactCacheRecord,
    expected_identity: &PoiCacheIdentity,
    expected_publisher_pubkey: Option<FixedBytes<32>>,
) -> Result<PoiCache, PoiArtifactError> {
    if record.chain_type != expected_identity.chain_type
        || record.chain_id != expected_identity.chain_id
        || record.txid_version != expected_identity.txid_version
        || record.list_key != expected_identity.list_key
    {
        return Err(PoiArtifactError::PersistedIdentityMismatch);
    }
    let cache = PoiCache::from_bytes(&record.cache_payload, expected_identity)?;
    validate_materialized_corpus(record, &cache, expected_publisher_pubkey)?;
    Ok(cache)
}

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

fn load_persisted_cache_with_publisher(
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

enum PersistedPoiCorpusInspection {
    Missing,
    Valid(Box<PersistedPoiArtifactCache>),
    Corrupt {
        replacement_token: PoiCorpusJournalCorruptionToken,
        error: PoiArtifactError,
    },
}

fn inspect_persisted_cache_with_publisher(
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
    let current_generation = db.poi_artifact_cache_generation()?;
    if cache_generation != current_generation {
        return Err(PoiArtifactError::StalePublicCacheGeneration {
            expected: current_generation,
            actual: cache_generation,
        });
    }
    if db.root_dir() != db_root.as_path() {
        return Err(PoiArtifactError::PersistedIdentityMismatch);
    }
    let identity = cache.identity().clone();
    if identity.chain_type != entry.scope.chain_type
        || identity.chain_id != entry.scope.chain_id
        || identity.txid_version != entry.scope.txid_version
        || identity.list_key != entry.scope.list_key
    {
        return Err(PoiArtifactError::PersistedIdentityMismatch);
    }
    let artifact_tip_index = entry
        .current_tip_index
        .ok_or(PoiArtifactError::EmptyPersistedCorpus)?;
    let manifest_root = entry
        .current_root
        .ok_or(PoiArtifactError::EmptyPersistedCorpus)?;
    let current_tip_index = cache.progress().next_event_index.saturating_sub(1);
    let (tree_number, _) = normalize_tree_position(0, current_tip_index);
    let current_tip_root = *cache
        .validated_roots()
        .ok_or(PoiArtifactError::PersistedRootsNotValidated)?
        .get(&tree_number)
        .ok_or(PoiArtifactError::MissingCacheRoot { tree_number })?;
    let valid_tip = if preserve_ahead_events {
        current_tip_index > artifact_tip_index
            && cache.root_at_global_index(artifact_tip_index) == Some(manifest_root)
    } else {
        current_tip_index == artifact_tip_index && current_tip_root == manifest_root
    };
    if !valid_tip {
        return Err(PoiArtifactError::PersistedArtifactRootMismatch {
            tip_index: artifact_tip_index,
        });
    }
    let record = if preserve_ahead_events {
        let mut record = starting_record.ok_or(PoiArtifactError::PersistedArtifactMetadata {
            reason: "ahead blocked-only refresh lost its starting provenance",
        })?;
        if record.current_tip_index != current_tip_index
            || record.current_tip_root != current_tip_root
            || record.cache_generation != cache_generation
        {
            return Err(PoiArtifactError::PersistedArtifactMetadata {
                reason: "ahead blocked-only refresh changed its durable event boundary",
            });
        }
        record.legacy_observed_manifest_sequence = record
            .legacy_observed_manifest_sequence
            .max(publication.sequence);
        record.blocked_shields_descriptor = descriptor_record(&entry.blocked_shields.artifact);
        record.updated_at = 0;
        record
    } else {
        let catalog_descriptor = &entry.checkpoint_catalog;
        let descriptor_bytes =
            serde_json::to_vec(catalog_descriptor).map_err(PoiArtifactError::Json)?;
        let catalog_descriptor_hash: [u8; 32] = Sha256::digest(descriptor_bytes).into();
        let validation = PoiCorpusValidationRecord::PublisherAttestedV4 {
            publisher_pubkey: publication.publisher_pubkey,
            manifest_sequence: publication.sequence,
            manifest_body_hash: Some(publication.manifest_body_hash),
            manifest_root,
            artifact_tip_index,
            format_version: poi::artifacts::v4::FORMAT_VERSION,
            checkpoint_catalog: PoiV4CatalogIdentityRecord {
                cid: catalog_descriptor.artifact.cid.clone(),
                sha256: catalog_descriptor.artifact.sha256,
                byte_size: catalog_descriptor.artifact.byte_size,
                descriptor_hash: FixedBytes::from(catalog_descriptor_hash),
            },
        };
        PoiArtifactCacheRecord {
            chain_type: identity.chain_type,
            chain_id: identity.chain_id,
            txid_version: identity.txid_version.clone(),
            list_key: identity.list_key,
            cache_generation,
            source: PoiCacheRecordSource::IndexedArtifacts,
            validation,
            legacy_observed_manifest_sequence: publication.sequence,
            base_descriptor: empty_descriptor_record(),
            applied_delta_descriptors: Vec::new(),
            blocked_shields_descriptor: descriptor_record(&entry.blocked_shields.artifact),
            artifact_tip_index: Some(artifact_tip_index),
            artifact_tip_root: Some(manifest_root),
            current_tip_index,
            current_tip_root,
            cache_payload: Vec::new(),
            legacy_last_successful_rpc_sync_at_ms: None,
            updated_at: 0,
        }
    };
    persist_corpus_record_monotonic(
        db,
        PreparedPoiCorpus::new(record, cache)?,
        Some(publication.publisher_pubkey),
        expected_base,
        starting_head.as_ref(),
        cache_generation,
        Some((publication.publisher_pubkey, publication.sequence)),
        Some(publication.manifest_body_hash),
    )
}

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

fn merge_public_rpc_provenance(
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

fn persist_public_rpc_cache_with_publisher(
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
    let identity = cache.identity().clone();
    let current_tip_index = cache.progress().next_event_index.saturating_sub(1);
    let (tree_number, _) = normalize_tree_position(0, current_tip_index);
    let current_tip_root = *cache
        .validated_roots()
        .ok_or(PoiArtifactError::PersistedRootsNotValidated)?
        .get(&tree_number)
        .ok_or(PoiArtifactError::MissingCacheRoot { tree_number })?;
    if delta.identity != identity
        || delta.event_end_cursor != cache.progress().next_event_index
        || delta.leaf_end_cursor != cache.progress().next_leaf_index
        || delta.events.len() > POI_RPC_EVENT_LIMIT
        || delta.leaves.len() > POI_RPC_LEAF_LIMIT
        || delta
            .event_end_cursor
            .saturating_sub(delta.event_start_cursor)
            > POI_RPC_EVENT_LIMIT as u64
        || delta
            .leaf_end_cursor
            .saturating_sub(delta.leaf_start_cursor)
            > POI_RPC_LEAF_LIMIT as u64
        || blocked_shields
            .as_ref()
            .is_some_and(|blocked| blocked.len() > POI_BLOCKED_SHIELD_LIMIT)
    {
        return Err(PoiArtifactError::PersistedArtifactMetadata {
            reason: "public RPC journal delta does not match its candidate",
        });
    }
    let mut record = PoiArtifactCacheRecord {
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
    };
    if let Some(existing) = starting_record {
        if existing.current_tip_index > record.current_tip_index
            || existing.current_tip_index.saturating_add(1) != delta.event_start_cursor
            || Some(existing.current_tip_root) != expected_base_current_root(expected_base)
        {
            return Ok(PublicRpcPersistResult::Stale);
        }
        merge_public_rpc_provenance(&mut record, existing.clone());
    } else if !matches!(
        expected_base,
        ExpectedPoiCorpusBase::NoValidCorpus | ExpectedPoiCorpusBase::Corrupt { .. }
    ) {
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
    let delta_event_count = delta.events.len();
    let delta_leaf_count = delta.leaves.len();
    let current_generation = db.poi_artifact_cache_generation()?;
    if cache_generation != current_generation {
        return Err(PoiArtifactError::StalePublicCacheGeneration {
            expected: current_generation,
            actual: cache_generation,
        });
    }
    let preparation_started = Instant::now();
    let commit_expected_state = expected_base.into_db_state();
    let (outcome, preparation_elapsed, transaction_elapsed) = if matches!(
        expected_base,
        ExpectedPoiCorpusBase::NoValidCorpus | ExpectedPoiCorpusBase::Corrupt { .. }
    ) {
        let mut base = record;
        base.cache_payload = cache.to_bytes()?;
        let preparation_elapsed = preparation_started.elapsed();
        let transaction_started = Instant::now();
        let outcome = db.rebase_poi_corpus_journal_if_current(
            base,
            cache.progress().next_event_index,
            cache.progress().next_leaf_index,
            PoiCorpusJournalCommitCondition {
                expected_generation: cache_generation,
                expected_publisher: None,
                expected_manifest_hash: None,
                expected_state: commit_expected_state,
            },
        )?;
        (outcome, preparation_elapsed, transaction_started.elapsed())
    } else {
        let stored_delta = (!delta.is_empty()).then(|| {
            Ok::<_, PoiArtifactError>(PoiCorpusJournalDeltaRecord {
                format_version: 0,
                chain_type: identity.chain_type,
                chain_id: identity.chain_id,
                txid_version: identity.txid_version.clone(),
                list_key: identity.list_key,
                cache_generation,
                revision: 0,
                previous_revision: 0,
                base_revision: 0,
                event_start_cursor: delta.event_start_cursor,
                event_end_cursor: delta.event_end_cursor,
                leaf_start_cursor: delta.leaf_start_cursor,
                leaf_end_cursor: delta.leaf_end_cursor,
                start_tip_root: expected_base_current_root(expected_base).ok_or(
                    PoiArtifactError::PersistedArtifactMetadata {
                        reason: "journal append has no expected starting root",
                    },
                )?,
                end_tip_root: current_tip_root,
                payload: delta.to_bytes()?,
                updated_at: 0,
            })
        });
        let stored_delta = stored_delta.transpose()?;
        let blocked = blocked_shields
            .as_deref()
            .map(|blocked_shields| {
                Ok::<_, PoiArtifactError>(PoiCorpusBlockedSnapshotRecord {
                    format_version: 0,
                    chain_type: identity.chain_type,
                    chain_id: identity.chain_id,
                    txid_version: identity.txid_version.clone(),
                    list_key: identity.list_key,
                    cache_generation,
                    revision: 0,
                    payload_hash: FixedBytes::ZERO,
                    payload: encode_blocked_shields_snapshot(blocked_shields)?,
                    updated_at: 0,
                })
            })
            .transpose()?;
        let head = PoiCorpusJournalHeadRecord {
            format_version: 0,
            revision: 0,
            base_revision: 0,
            base_payload_hash: FixedBytes::ZERO,
            event_cursor: cache.progress().next_event_index,
            leaf_cursor: cache.progress().next_leaf_index,
            blocked_revision: None,
            blocked_payload_hash: None,
            delta_count: 0,
            delta_payload_bytes: 0,
            corpus: record,
        };
        let preparation_elapsed = preparation_started.elapsed();
        let transaction_started = Instant::now();
        let outcome = db.append_poi_corpus_journal_if_current(
            head,
            stored_delta,
            blocked,
            PoiCorpusJournalCommitCondition {
                expected_generation: cache_generation,
                expected_publisher: None,
                expected_manifest_hash: None,
                expected_state: commit_expected_state,
            },
        )?;
        (outcome, preparation_elapsed, transaction_started.elapsed())
    };
    match outcome {
        PoiCorpusJournalCommitOutcome::Applied(commit) => {
            debug!(
                chain_id = identity.chain_id,
                current_tip_index,
                prior_revision = ?expected_base.journal_revision(),
                journal_revision = commit.head.revision,
                delta_events = delta_event_count,
                delta_leaves = delta_leaf_count,
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
            Ok(PublicRpcPersistResult::Applied(Box::new(
                PersistedPoiArtifactCache {
                    record: commit.head.corpus.clone(),
                    cache,
                    cache_generation,
                    journal_head: Some(commit.head.clone()),
                    compaction_recommended: commit.compaction_recommended,
                },
            )))
        }
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

fn persist_corpus_record_monotonic(
    db: &DbStore,
    prepared: PreparedPoiCorpus,
    publisher_pubkey: Option<FixedBytes<32>>,
    expected_base: ExpectedPoiCorpusBase,
    starting_head: Option<&PoiCorpusJournalHeadRecord>,
    expected_generation: u64,
    expected_publisher: Option<(FixedBytes<32>, u64)>,
    expected_manifest_hash: Option<FixedBytes<32>>,
) -> Result<PersistCorpusResult, PoiArtifactError> {
    let PreparedPoiCorpus {
        record: mut candidate,
        cache: candidate_cache,
        serialization_elapsed,
    } = prepared;
    let candidate_identity = PoiCacheIdentity::new(
        candidate.chain_type,
        candidate.chain_id,
        candidate.txid_version.clone(),
        candidate.list_key,
    );
    if candidate_cache.identity() != &candidate_identity {
        return Err(PoiArtifactError::PersistedIdentityMismatch);
    }
    let prepared_validation_started = Instant::now();
    validate_materialized_corpus_payload(&candidate, &candidate_cache)?;
    let prepared_validation_elapsed = prepared_validation_started.elapsed();
    let existing_validation_started = Instant::now();
    let (existing, commit_expected_state) = match inspect_persisted_cache_with_publisher(
        db,
        &candidate_identity,
        publisher_pubkey,
    )? {
        PersistedPoiCorpusInspection::Missing => {
            if expected_base != ExpectedPoiCorpusBase::NoValidCorpus {
                return Ok(PersistCorpusResult::Stale);
            }
            (None, ExpectedPoiCorpusJournalState::NoValidBase)
        }
        PersistedPoiCorpusInspection::Valid(existing) => {
            let observed = existing.expected_base();
            if observed != expected_base {
                return Ok(PersistCorpusResult::Stale);
            }
            (Some(*existing), observed.into_db_state())
        }
        PersistedPoiCorpusInspection::Corrupt {
            replacement_token,
            error,
        } => {
            let can_repair = match expected_base {
                ExpectedPoiCorpusBase::Corrupt {
                    replacement_token: expected_token,
                } => starting_head.is_none() && expected_token == replacement_token,
                _ => artifact_candidate_can_repair_corrupt_journal(
                    db,
                    &candidate_identity,
                    &candidate_cache,
                    expected_base,
                    starting_head,
                    expected_generation,
                )?,
            };
            if !can_repair {
                return Ok(PersistCorpusResult::Stale);
            }
            warn!(?error, key = %candidate.key(), "replacing corrupt durable PPOI corpus journal");
            (
                None,
                ExpectedPoiCorpusJournalState::Corrupt { replacement_token },
            )
        }
    };
    if let Some(existing) = existing {
        if existing.record.current_tip_index > candidate.current_tip_index {
            return Ok(PersistCorpusResult::Stale);
        }
        validate_candidate_event_prefix(
            &existing.cache,
            &candidate_cache,
            existing.record.current_tip_index,
            existing.record.current_tip_root,
            candidate.current_tip_index,
        )?;
        if matches!(candidate.source, PoiCacheRecordSource::PublicRpc) {
            merge_public_rpc_provenance(&mut candidate, existing.record);
        } else if let Some((list_key, from_index)) = list_signed_range(&existing.record.validation)
        {
            candidate.validation = extend_validation_with_list_ranges(
                candidate.validation,
                &PoiCorpusValidationRecord::ListSignedRanges {
                    list_key,
                    from_index,
                },
            );
            candidate.source = PoiCacheRecordSource::PublicRpc;
        }
    }
    let existing_validation_elapsed = existing_validation_started.elapsed();
    let final_validation_started = Instant::now();
    validate_materialized_corpus(&candidate, &candidate_cache, publisher_pubkey)?;
    let final_validation_elapsed = final_validation_started.elapsed();
    let source = candidate.source;
    let chain_id = candidate.chain_id;
    let current_tip_index = candidate.current_tip_index;
    let payload_bytes = candidate.cache_payload.len();
    let transaction_started = Instant::now();
    let outcome = db.rebase_poi_corpus_journal_if_current(
        candidate,
        candidate_cache.progress().next_event_index,
        candidate_cache.progress().next_leaf_index,
        PoiCorpusJournalCommitCondition {
            expected_generation,
            expected_publisher,
            expected_manifest_hash,
            expected_state: commit_expected_state,
        },
    )?;
    let transaction_elapsed = transaction_started.elapsed();
    let (journal_revision, retired_delta_count, retired_delta_payload_bytes) = match &outcome {
        PoiCorpusJournalCommitOutcome::Applied(commit) => (
            Some(commit.head.revision),
            Some(commit.retired_delta_count),
            Some(commit.retired_delta_payload_bytes),
        ),
        _ => (None, None, None),
    };
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
    match outcome {
        PoiCorpusJournalCommitOutcome::Applied(commit) => Ok(PersistCorpusResult::Applied(
            Box::new(PersistedPoiArtifactCache {
                record: commit.head.corpus.clone(),
                cache: candidate_cache,
                cache_generation: expected_generation,
                journal_head: Some(commit.head.clone()),
                compaction_recommended: false,
            }),
        )),
        PoiCorpusJournalCommitOutcome::CorpusConflict => Ok(PersistCorpusResult::Stale),
        PoiCorpusJournalCommitOutcome::GenerationConflict { actual } => {
            Err(PoiArtifactError::StalePublicCacheGeneration {
                expected: actual,
                actual: expected_generation,
            })
        }
        PoiCorpusJournalCommitOutcome::PublisherSequenceConflict { actual } => {
            if actual.is_some_and(|sequence| {
                expected_publisher.is_some_and(|(_, expected)| sequence > expected)
            }) {
                Ok(PersistCorpusResult::Stale)
            } else {
                Err(PoiArtifactError::UnobservedManifestSequence {
                    candidate: expected_publisher.map_or(0, |(_, sequence)| sequence),
                })
            }
        }
        PoiCorpusJournalCommitOutcome::PublisherManifestConflict { .. } => {
            Ok(PersistCorpusResult::Stale)
        }
        PoiCorpusJournalCommitOutcome::CompactionRequired => Err(PoiArtifactError::Persistence {
            reason: "base rebase unexpectedly requires compaction".to_string(),
        }),
    }
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

const fn list_signed_range(
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

fn extend_validation_with_list_ranges(
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

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

const fn empty_descriptor_record() -> PoiArtifactDescriptorRecord {
    PoiArtifactDescriptorRecord {
        cid: String::new(),
        sha256: String::new(),
        byte_size: 0,
    }
}

fn validate_manifest_order(
    publication: &PublicationId,
    previous: Option<&PoiPublisherManifestWatermarkRecord>,
) -> Result<bool, PoiArtifactError> {
    let Some(previous) = previous else {
        return Ok(false);
    };
    if publication.sequence < previous.accepted_sequence {
        return Err(PoiArtifactError::ManifestSequenceRollback {
            previous: previous.accepted_sequence,
            received: publication.sequence,
        });
    }
    if publication.sequence != previous.accepted_sequence {
        return Ok(false);
    }
    match previous.accepted_manifest_hash {
        Some(hash) if hash == publication.manifest_body_hash => Ok(true),
        Some(_) => Err(PoiArtifactError::ManifestSequenceEquivocation {
            sequence: publication.sequence,
        }),
        None => Ok(false),
    }
}

fn validate_manifest_freshness(
    manifest: &Manifest,
    max_age: Option<Duration>,
    now: SystemTime,
) -> Result<(), PoiArtifactError> {
    let issued_at = UNIX_EPOCH + Duration::from_millis(manifest.issued_at_ms);
    let age = now
        .duration_since(issued_at)
        .map_err(|_| PoiArtifactError::ManifestIssuedInFuture)?;
    if let Some(max_age) = max_age
        && age > max_age
    {
        return Err(PoiArtifactError::ManifestStale { age, max: max_age });
    }
    Ok(())
}

fn descriptor_record(descriptor: &ArtifactDescriptor) -> PoiArtifactDescriptorRecord {
    PoiArtifactDescriptorRecord {
        cid: descriptor.cid.clone(),
        sha256: hex::encode_prefixed(descriptor.sha256.as_slice()),
        byte_size: descriptor.byte_size,
    }
}

pub(crate) fn clear_poi_artifact_cache_for_reset(
    db: &DbStore,
) -> Result<PoiArtifactCacheReset, local_db::DbError> {
    let (removed, generation) = db.clear_poi_artifact_cache_with_generation()?;
    Ok(PoiArtifactCacheReset {
        removed,
        generation,
    })
}

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod tests;
