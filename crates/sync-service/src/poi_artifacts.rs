use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use alloy::hex;
use alloy::primitives::{FixedBytes, keccak256};
use broadcaster_core::tree::normalize_tree_position;
use local_db::{
    DbStore, ExpectedPoiCorpusJournalState, PoiArtifactCacheRecord, PoiArtifactDescriptorRecord,
    PoiCorpusJournalCommitCondition, PoiCorpusJournalCommitOutcome,
    PoiCorpusJournalCorruptionToken, PoiCorpusJournalHeadRecord, PoiCorpusRpcHealthRecord,
    PoiCorpusValidationRecord, StoredRecord,
};
#[cfg(test)]
use poi::artifacts::v4::Manifest;
use poi::artifacts::v4::{Error as ArtifactFormatError, Scope};
use poi::artifacts::{ArtifactDescriptor, ManifestError};
use poi::cache::{PoiCache, PoiCacheError, PoiCacheIdentity, PoiCacheJournalDelta};
use poi::poi::BlockedShield;
use thiserror::Error;
use tracing::{debug, warn};

use crate::trustless_artifacts::TrustlessArtifactError;
use crate::types::{PoiArtifactCacheGraphProgress, PoiArtifactCachePhase, PoiArtifactSourceConfig};
#[cfg(test)]
use local_db::POI_CORPUS_JOURNAL_MAX_BLOCKED_PAYLOAD_BYTES;
#[cfg(test)]
use local_db::PoiCacheRecordSource;
#[cfg(test)]
use local_db::PoiCorpusJournalDeltaRecord;
#[cfg(test)]
use local_db::PoiV4CatalogIdentityRecord;
#[cfg(test)]
use poi::artifacts::v4::ManifestEntry;
#[cfg(test)]
use std::collections::BTreeMap;
use trustless_artifacts::GatewayPool;

mod candidate;
mod inspect;
mod manifest;
mod persist;
mod public_rpc;
mod v4_cache;
mod v4_ingest;
mod validation;

#[cfg(test)]
use candidate::{CandidateBlockedState, prepare_candidate_from_starting};
pub use candidate::{CandidateError, CorpusCandidate, VerifiedCorpusCandidate};
pub(crate) use candidate::{prepare_candidate, prepare_candidate_from_starting_for_generation};
#[cfg(test)]
use inspect::{
    PersistedPoiCorpusInspection, inspect_persisted_cache_with_publisher,
    load_persisted_cache_with_publisher,
};
pub(crate) use inspect::{
    load_persisted_cache_candidate_for_publisher, load_persisted_cache_for_publisher,
};
pub use manifest::ObservedManifest;
use manifest::lock_poi_artifact_publication;
#[cfg(test)]
use manifest::publisher_manifest_watermark;
pub(crate) use manifest::{observe_manifest_with_clock, publisher_manifest_sequence};
pub(crate) use persist::persist_prepared_corpus;
use public_rpc::persist_public_rpc_cache_with_publisher;
#[cfg(test)]
use validation::{
    validate_corpus_provenance, validate_materialized_corpus_payload, validate_persisted_record,
};

pub(crate) use v4_cache::POI_V4_RAW_CHUNK_BLOB_KIND;
pub use v4_cache::{
    CurrentChunk, FetchedArtifact, RawChunkRetainOutcome, SemanticVerifiedChunk,
    TransportVerifiedChunk, VerifiedBlockedShields, VerifiedCatalog,
};
pub(crate) use v4_cache::{
    RawChunkCache, RawChunkCacheError, RawChunkCacheResetFailure, reset_raw_chunk_cache,
};
pub(crate) use v4_ingest::PreparedIngestion;

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

    /// Whether a commit against this base writes a fresh corpus instead of
    /// extending a valid one.
    const fn replaces_corpus(self) -> bool {
        matches!(self, Self::NoValidCorpus | Self::Corrupt { .. })
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
    ensure_current_cache_generation(db, generation)?;
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
    ensure_current_cache_generation(db, generation)?;
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

/// The cache's current tip index and its validated root.
fn cache_current_tip(cache: &PoiCache) -> Result<(u64, FixedBytes<32>), PoiArtifactError> {
    let current_tip_index = cache.progress().next_event_index.saturating_sub(1);
    let (tree_number, _) = normalize_tree_position(0, current_tip_index);
    let current_tip_root = *cache
        .validated_roots()
        .ok_or(PoiArtifactError::PersistedRootsNotValidated)?
        .get(&tree_number)
        .ok_or(PoiArtifactError::MissingCacheRoot { tree_number })?;
    Ok((current_tip_index, current_tip_root))
}

/// Rejects work prepared for a public cache generation that a reset has since replaced.
fn ensure_current_cache_generation(db: &DbStore, generation: u64) -> Result<(), PoiArtifactError> {
    let current_generation = db.poi_artifact_cache_generation()?;
    if current_generation != generation {
        return Err(PoiArtifactError::StalePublicCacheGeneration {
            expected: current_generation,
            actual: generation,
        });
    }
    Ok(())
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
