use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::hex;
use alloy::primitives::{FixedBytes, keccak256};
use broadcaster_core::tree::normalize_tree_position;
use local_db::{
    DbStore, PoiArtifactCacheCommitCondition, PoiArtifactCacheCommitOutcome,
    PoiArtifactCacheRecord, PoiArtifactDescriptorRecord, PoiCacheRecordSource,
    PoiCorpusRpcHealthRecord, PoiCorpusValidationRecord, PoiPublisherManifestObservation,
    PoiPublisherManifestWatermarkRecord, PoiV4CatalogIdentityRecord, StoredRecord,
};
use poi::artifacts::v4::{
    Error as ArtifactFormatError, EventArtifactDescriptor, Manifest, ManifestEntry, PublicationId,
    Scope,
};
use poi::artifacts::{ArtifactDescriptor, ManifestError};
use poi::cache::{PoiCache, PoiCacheError, PoiCacheIdentity, PoiCacheRootValidation};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock};
use tracing::warn;

use crate::trustless_artifacts::TrustlessArtifactError;
use crate::types::{PoiArtifactCacheGraphProgress, PoiArtifactCachePhase, PoiArtifactSourceConfig};

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

static POI_ARTIFACT_CACHE_SYNC_STATE: LazyLock<Mutex<PoiArtifactCacheSyncState>> =
    LazyLock::new(|| Mutex::new(PoiArtifactCacheSyncState::default()));

#[derive(Default)]
struct PoiArtifactCacheSyncState {
    authorities: BTreeMap<PathBuf, Arc<PoiCorpusAuthority>>,
}

#[derive(Debug)]
pub(crate) struct PoiCorpusAuthority {
    generation: Arc<AtomicU64>,
    access: Arc<RwLock<()>>,
    revision_access: Arc<RwLock<()>>,
}

impl PoiCorpusAuthority {
    pub(crate) fn new(generation: u64) -> Self {
        Self {
            generation: Arc::new(AtomicU64::new(generation)),
            access: Arc::new(RwLock::new(())),
            revision_access: Arc::new(RwLock::new(())),
        }
    }

    pub(crate) async fn read_access(&self) -> OwnedRwLockReadGuard<()> {
        Arc::clone(&self.access).read_owned().await
    }

    async fn reset_access(&self) -> OwnedRwLockWriteGuard<()> {
        Arc::clone(&self.access).write_owned().await
    }

    pub(crate) async fn revision_read_access(&self) -> OwnedRwLockReadGuard<()> {
        Arc::clone(&self.revision_access).read_owned().await
    }

    pub(crate) async fn revision_write_access(&self) -> OwnedRwLockWriteGuard<()> {
        Arc::clone(&self.revision_access).write_owned().await
    }

    pub(crate) fn generation(&self) -> &AtomicU64 {
        self.generation.as_ref()
    }

    pub(crate) fn generation_cell(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.generation)
    }
}

impl PoiArtifactCacheSyncState {
    fn lock() -> MutexGuard<'static, Self> {
        POI_ARTIFACT_CACHE_SYNC_STATE
            .lock()
            .expect("POI artifact cache sync state lock poisoned")
    }

    fn authority(&mut self, db: &DbStore) -> Result<Arc<PoiCorpusAuthority>, local_db::DbError> {
        if let Some(authority) = self.authorities.get(db.root_dir()) {
            return Ok(Arc::clone(authority));
        }
        let authority = Arc::new(PoiCorpusAuthority::new(db.poi_artifact_cache_generation()?));
        self.authorities
            .insert(db.root_dir().to_path_buf(), Arc::clone(&authority));
        Ok(authority)
    }

    fn generation_cell(&mut self, db: &DbStore) -> Result<Arc<AtomicU64>, local_db::DbError> {
        Ok(self.authority(db)?.generation_cell())
    }

    fn publish_generation(&mut self, db: &DbStore, generation: u64) {
        let authority = self
            .authorities
            .entry(db.root_dir().to_path_buf())
            .or_insert_with(|| Arc::new(PoiCorpusAuthority::new(generation)));
        authority.generation.store(generation, Ordering::Release);
    }
}

pub(crate) fn with_poi_artifact_cache_generation<R>(
    generation: &AtomicU64,
    operation: impl FnOnce(u64) -> R,
) -> R {
    let _sync_guard = PoiArtifactCacheSyncState::lock();
    operation(generation.load(Ordering::Acquire))
}

pub(crate) fn poi_artifact_cache_generation_cell(
    db: &DbStore,
) -> Result<Arc<AtomicU64>, local_db::DbError> {
    Ok(PoiArtifactCacheSyncState::lock()
        .authority(db)?
        .generation_cell())
}

pub(crate) fn poi_corpus_authority(
    db: &DbStore,
) -> Result<Arc<PoiCorpusAuthority>, local_db::DbError> {
    PoiArtifactCacheSyncState::lock().authority(db)
}

fn lock_poi_artifact_cache_sync() -> MutexGuard<'static, PoiArtifactCacheSyncState> {
    POI_ARTIFACT_CACHE_SYNC_STATE
        .lock()
        .expect("POI artifact cache sync state lock poisoned")
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
    progress_observer: Option<PoiArtifactProgressObserver>,
}

impl PoiArtifactIngestor {
    pub(crate) const fn new(config: PoiArtifactSourceConfig, client: reqwest::Client) -> Self {
        Self {
            config,
            client,
            progress_observer: None,
        }
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
    PayloadHash(FixedBytes<32>),
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
    let _sync_state = lock_poi_artifact_cache_sync();
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
    })
}

#[derive(Clone)]
pub(crate) struct PersistedPoiArtifactCache {
    pub(crate) record: PoiArtifactCacheRecord,
    pub(crate) cache: PoiCache,
    pub(crate) cache_generation: u64,
}

#[derive(Clone)]
pub(crate) struct CorpusStartingState {
    cache: PoiCache,
    record: PoiArtifactCacheRecord,
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
}

impl VerifiedCorpusCandidate {
    pub(crate) const fn cache(&self) -> &PoiCache {
        &self.cache
    }

    pub(crate) const fn manifest_sequence(&self) -> u64 {
        self.publication.sequence
    }

    pub(crate) const fn cache_generation(&self) -> u64 {
        self.cache_generation
    }

    pub(crate) const fn publisher_pubkey(&self) -> FixedBytes<32> {
        self.publication.publisher_pubkey
    }
}

impl PersistedPoiArtifactCache {
    pub(crate) fn starting_state(
        &self,
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
            cache: self.cache.clone(),
            record: self.record.clone(),
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
    let unbound_v4 = db
        .get_poi_artifact_cache(
            identity.chain_type,
            identity.chain_id,
            &identity.txid_version,
            &identity.list_key,
        )?
        .is_some_and(|record| {
            matches!(
                record.validation,
                PoiCorpusValidationRecord::PublisherAttestedV4 {
                    manifest_body_hash: None,
                    ..
                } | PoiCorpusValidationRecord::PublisherV4AndListSigned {
                    manifest_body_hash: None,
                    ..
                }
            )
        });
    let persisted = if unbound_v4 {
        None
    } else {
        load_persisted_cache_for_publisher(db, &identity, publisher_pubkey)?
    };
    let cache_generation = persisted.as_ref().map_or_else(
        || {
            poi_artifact_cache_generation_cell(db)
                .map(|generation| generation.load(Ordering::Acquire))
                .map_err(PoiArtifactError::from)
        },
        |persisted| Ok(persisted.cache_generation),
    )?;
    let expected_base = expected_corpus_base(persisted.as_ref());
    let starting_state = persisted
        .as_ref()
        .and_then(|persisted| persisted.starting_state(scope, publisher_pubkey));
    let (cache, starting_record) = starting_state.map_or_else(
        || (PoiCache::new(identity), None),
        |starting| (starting.cache, Some(starting.record)),
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
    })
}

fn expected_corpus_base(persisted: Option<&PersistedPoiArtifactCache>) -> ExpectedPoiCorpusBase {
    persisted.map_or(ExpectedPoiCorpusBase::NoValidCorpus, |persisted| {
        ExpectedPoiCorpusBase::PayloadHash(keccak256(&persisted.record.cache_payload))
    })
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
        cache: &PoiCache,
        range_start_index: u64,
        expected_base: ExpectedPoiCorpusBase,
    ) -> Result<Option<PersistedPoiArtifactCache>, PoiArtifactError> {
        let outcome = persist_public_rpc_cache_with_publisher(
            self.db,
            cache,
            self.generation,
            range_start_index,
            Some(self.publisher_pubkey),
            expected_base,
        )?;
        let persisted = self.load(cache.identity())?;
        if outcome == CorpusCommitOutcome::Applied && persisted.is_none() {
            return Err(PoiArtifactError::MissingCommittedCorpus);
        }
        Ok(persisted)
    }
}

pub(crate) fn load_poi_rpc_health(
    db: &DbStore,
    identity: &PoiCacheIdentity,
    generation: u64,
    legacy_last_successful_rpc_sync_at_ms: Option<u64>,
) -> Result<Option<u64>, PoiArtifactError> {
    let mut sync_state = lock_poi_artifact_cache_sync();
    let current_generation = sync_state.generation_cell(db)?.load(Ordering::Acquire);
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
    let mut sync_state = lock_poi_artifact_cache_sync();
    let current_generation = sync_state.generation_cell(db)?.load(Ordering::Acquire);
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
    #[error("POI corpus commit completed without a readable durable corpus")]
    MissingCommittedCorpus,
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

fn validate_persisted_corpus_payload(
    record: &PoiArtifactCacheRecord,
    cache: &PoiCache,
) -> Result<(), PoiArtifactError> {
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
    let roots = cache.clone().current_roots();
    let (tree_number, _) = normalize_tree_position(0, payload_tip_index);
    let payload_tip_root = roots
        .get(&tree_number)
        .ok_or(PoiArtifactError::MissingPersistedRoot { tree_number })?;
    if record.current_tip_root != *payload_tip_root {
        return Err(PoiArtifactError::PersistedRootMismatch {
            tip_index: payload_tip_index,
        });
    }
    if !matches!(
        &cache.progress().root_validation,
        PoiCacheRootValidation::Validated { roots: validated } if validated == &roots
    ) {
        return Err(PoiArtifactError::PersistedRootsNotValidated);
    }

    match (record.artifact_tip_index, record.artifact_tip_root) {
        (Some(index), Some(root)) if index <= payload_tip_index => {
            if cache.root_at_global_index(index) != Some(root) {
                return Err(PoiArtifactError::PersistedArtifactRootMismatch { tip_index: index });
            }
        }
        (None, None) => {}
        (Some(_), Some(_)) => {
            return Err(PoiArtifactError::PersistedArtifactMetadata {
                reason: "artifact tip exceeds serving tip",
            });
        }
        _ => {
            return Err(PoiArtifactError::PersistedArtifactMetadata {
                reason: "artifact tip index and root must be present together",
            });
        }
    }

    Ok(())
}

fn validate_persisted_corpus(
    record: &PoiArtifactCacheRecord,
    cache: &PoiCache,
    expected_publisher_pubkey: Option<FixedBytes<32>>,
) -> Result<(), PoiArtifactError> {
    validate_persisted_corpus_payload(record, cache)?;
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
    validate_persisted_corpus(record, &cache, expected_publisher_pubkey)?;
    Ok(cache)
}

pub(crate) fn load_persisted_cache_for_publisher(
    db: &DbStore,
    identity: &PoiCacheIdentity,
    publisher_pubkey: FixedBytes<32>,
) -> Result<Option<PersistedPoiArtifactCache>, PoiArtifactError> {
    load_persisted_cache_with_publisher(db, identity, Some(publisher_pubkey))
}

fn load_persisted_cache_with_publisher(
    db: &DbStore,
    identity: &PoiCacheIdentity,
    publisher_pubkey: Option<FixedBytes<32>>,
) -> Result<Option<PersistedPoiArtifactCache>, PoiArtifactError> {
    let mut sync_state = lock_poi_artifact_cache_sync();
    let cache_generation = sync_state.generation_cell(db)?.load(Ordering::Acquire);
    let Some(mut record) = db.get_poi_artifact_cache(
        identity.chain_type,
        identity.chain_id,
        &identity.txid_version,
        &identity.list_key,
    )?
    else {
        return Ok(None);
    };
    normalize_legacy_artifact_metadata(&mut record);
    if record.cache_generation != cache_generation {
        return Err(PoiArtifactError::PersistedArtifactMetadata {
            reason: "corpus generation does not match the durable generation",
        });
    }
    let cache = validate_persisted_record(&record, identity, publisher_pubkey)?;
    Ok(Some(PersistedPoiArtifactCache {
        record,
        cache,
        cache_generation,
    }))
}

pub(crate) fn persist_prepared_corpus(
    db: &DbStore,
    candidate: VerifiedCorpusCandidate,
) -> Result<CorpusCommitOutcome, PoiArtifactError> {
    let VerifiedCorpusCandidate {
        cache,
        entry,
        publication,
        db_root,
        cache_generation,
        expected_base,
        preserve_ahead_events,
        starting_record,
    } = candidate;
    let current_generation = poi_artifact_cache_generation_cell(db)?.load(Ordering::Acquire);
    if cache_generation != current_generation {
        return Err(PoiArtifactError::StalePublicCacheGeneration {
            expected: current_generation,
            actual: cache_generation,
        });
    }
    if db.root_dir() != db_root.as_path() {
        return Err(PoiArtifactError::PersistedIdentityMismatch);
    }
    let identity = cache.identity();
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
        .clone()
        .current_roots()
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
    let cache_payload = cache.to_bytes()?;
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
        record.cache_payload = cache_payload;
        record.updated_at = unix_time_ms();
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
            cache_payload,
            legacy_last_successful_rpc_sync_at_ms: None,
            updated_at: unix_time_ms(),
        }
    };
    persist_corpus_record_monotonic(
        db,
        record,
        Some(publication.publisher_pubkey),
        expected_base,
        cache_generation,
        Some((publication.publisher_pubkey, publication.sequence)),
        Some(publication.manifest_body_hash),
    )
}

fn persist_public_rpc_cache_with_publisher(
    db: &DbStore,
    cache: &PoiCache,
    cache_generation: u64,
    range_start_index: u64,
    publisher_pubkey: Option<FixedBytes<32>>,
    expected_base: ExpectedPoiCorpusBase,
) -> Result<CorpusCommitOutcome, PoiArtifactError> {
    let identity = cache.identity();
    let current_tip_index = cache.progress().next_event_index.saturating_sub(1);
    let (tree_number, _) = normalize_tree_position(0, current_tip_index);
    let current_tip_root = *cache
        .clone()
        .current_roots()
        .get(&tree_number)
        .ok_or(PoiArtifactError::MissingCacheRoot { tree_number })?;
    let record = PoiArtifactCacheRecord {
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
        cache_payload: cache.to_bytes()?,
        legacy_last_successful_rpc_sync_at_ms: None,
        updated_at: unix_time_ms(),
    };
    let mut sync_state = lock_poi_artifact_cache_sync();
    let current_generation = sync_state.generation_cell(db)?.load(Ordering::Acquire);
    if cache_generation != current_generation {
        return Err(PoiArtifactError::StalePublicCacheGeneration {
            expected: current_generation,
            actual: cache_generation,
        });
    }
    persist_corpus_record_monotonic(
        db,
        record,
        publisher_pubkey,
        expected_base,
        cache_generation,
        None,
        None,
    )
}

fn persist_corpus_record_monotonic(
    db: &DbStore,
    mut candidate: PoiArtifactCacheRecord,
    publisher_pubkey: Option<FixedBytes<32>>,
    expected_base: ExpectedPoiCorpusBase,
    expected_generation: u64,
    expected_publisher: Option<(FixedBytes<32>, u64)>,
    expected_manifest_hash: Option<FixedBytes<32>>,
) -> Result<CorpusCommitOutcome, PoiArtifactError> {
    let candidate_identity = PoiCacheIdentity::new(
        candidate.chain_type,
        candidate.chain_id,
        candidate.txid_version.clone(),
        candidate.list_key,
    );
    let candidate_cache = PoiCache::from_bytes(&candidate.cache_payload, &candidate_identity)?;
    validate_persisted_corpus_payload(&candidate, &candidate_cache)?;
    let existing = db.inspect_poi_artifact_cache(
        candidate.chain_type,
        candidate.chain_id,
        &candidate.txid_version,
        &candidate.list_key,
    )?;
    let expected_stored_payload_hash = match &existing {
        StoredRecord::Valid(record) => Some(keccak256(&record.cache_payload)),
        StoredRecord::Missing | StoredRecord::Corrupt { .. } => None,
    };
    let existing = match existing {
        StoredRecord::Missing => None,
        StoredRecord::Corrupt { key } => {
            warn!(%key, "replacing corrupt durable PPOI corpus");
            None
        }
        StoredRecord::Valid(mut existing) => {
            normalize_legacy_artifact_metadata(&mut existing);
            let identity = PoiCacheIdentity::new(
                existing.chain_type,
                existing.chain_id,
                existing.txid_version.clone(),
                existing.list_key,
            );
            match validate_persisted_record(&existing, &identity, publisher_pubkey) {
                Ok(existing_cache) => Some((existing, existing_cache)),
                Err(error) => {
                    warn!(?error, key = %existing.key(), "replacing semantically corrupt durable PPOI corpus");
                    None
                }
            }
        }
    };
    let observed_base = existing
        .as_ref()
        .map_or(ExpectedPoiCorpusBase::NoValidCorpus, |(record, _)| {
            ExpectedPoiCorpusBase::PayloadHash(keccak256(&record.cache_payload))
        });
    if observed_base != expected_base {
        return Ok(CorpusCommitOutcome::Stale);
    }
    if let Some((existing, mut existing_cache)) = existing {
        if existing.current_tip_index > candidate.current_tip_index {
            return Ok(CorpusCommitOutcome::Stale);
        }
        validate_candidate_event_prefix(
            &mut existing_cache,
            &candidate_cache,
            existing.current_tip_index,
            existing.current_tip_root,
            candidate.current_tip_index,
        )?;
        if matches!(candidate.source, PoiCacheRecordSource::PublicRpc) {
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
        } else if let Some((list_key, from_index)) = list_signed_range(&existing.validation) {
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
    validate_persisted_corpus(&candidate, &candidate_cache, publisher_pubkey)?;
    match db.commit_poi_artifact_cache_if_current(
        &candidate,
        PoiArtifactCacheCommitCondition {
            expected_generation,
            expected_publisher,
            expected_manifest_hash,
            expected_payload_hash: expected_stored_payload_hash,
        },
    )? {
        PoiArtifactCacheCommitOutcome::Applied => Ok(CorpusCommitOutcome::Applied),
        PoiArtifactCacheCommitOutcome::CorpusConflict => Ok(CorpusCommitOutcome::Stale),
        PoiArtifactCacheCommitOutcome::GenerationConflict { actual } => {
            Err(PoiArtifactError::StalePublicCacheGeneration {
                expected: actual,
                actual: expected_generation,
            })
        }
        PoiArtifactCacheCommitOutcome::PublisherSequenceConflict { actual } => {
            if actual.is_some_and(|sequence| {
                expected_publisher.is_some_and(|(_, expected)| sequence > expected)
            }) {
                Ok(CorpusCommitOutcome::Stale)
            } else {
                Err(PoiArtifactError::UnobservedManifestSequence {
                    candidate: expected_publisher.map_or(0, |(_, sequence)| sequence),
                })
            }
        }
        PoiArtifactCacheCommitOutcome::PublisherManifestConflict { .. } => {
            Ok(CorpusCommitOutcome::Stale)
        }
    }
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
    existing_cache: &mut PoiCache,
    candidate_cache: &PoiCache,
    durable_tip_index: u64,
    durable_tip_root: FixedBytes<32>,
    candidate_tip_index: u64,
) -> Result<(), PoiArtifactError> {
    let (tip_tree, _) = normalize_tree_position(0, durable_tip_index);
    let existing_roots = existing_cache.current_roots();
    let mut candidate_cache = candidate_cache.clone();
    let candidate_roots = candidate_cache.current_roots();
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

pub(crate) async fn clear_poi_artifact_cache_for_reset(
    db: &DbStore,
) -> Result<PoiArtifactCacheReset, local_db::DbError> {
    let authority = poi_corpus_authority(db)?;
    let _revision_access = authority.revision_write_access().await;
    let _reset_access = authority.reset_access().await;
    let mut sync_state = lock_poi_artifact_cache_sync();
    let (removed, generation) = db.clear_poi_artifact_cache_with_generation()?;
    sync_state.publish_generation(db, generation);
    Ok(PoiArtifactCacheReset {
        removed,
        generation,
    })
}

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod tests {
    use super::test_support::{
        load_persisted_cache, observe_manifest, persist_public_rpc_cache,
        poi_v4_manifest_envelope_signing_message,
    };
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    use ed25519_dalek::{Signer, SigningKey};
    use local_db::DbConfig;
    use poi::artifacts::v4::{
        ArtifactEncoding, BLOCKED_SHIELDS_ARTIFACT_MAX_BYTES, BlockedShieldsDescriptor,
        CheckpointCatalogDescriptor, Compression, FORMAT_VERSION,
    };
    use poi::artifacts::{ManifestEntry as LegacyManifestEntry, SnapshotEvent};
    use poi::poi::PoiEventType;

    #[test]
    fn v4_manifest_watermark_is_durable_before_entry_or_candidate_work() {
        let root_dir = temp_db_root("v4-watermark-before-entry");
        fs::create_dir_all(&root_dir).expect("create temp DB root");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp DB");
        let signing_key = SigningKey::from_bytes(&[0x91; 32]);
        let publisher = FixedBytes::from(signing_key.verifying_key().to_bytes());
        let mut manifest = Manifest::new(1_700_000_000_000, 9, publisher, Vec::new());
        manifest.sign_manifest(&signing_key).expect("sign manifest");

        let observed = observe_manifest(&db, publisher, manifest, None, SystemTime::now())
            .expect("observe authenticated manifest");
        let missing_scope = Scope::new(FixedBytes::from([0x92; 32]), 0, 1, "V2_PoseidonMerkle");
        assert!(matches!(
            observed.entry(&missing_scope),
            Err(PoiArtifactError::MissingManifestEntry { .. })
        ));
        assert_eq!(
            db.get_poi_publisher_manifest_watermark(&publisher)
                .expect("read publisher watermark")
                .expect("watermark persisted")
                .accepted_sequence,
            9
        );

        let mut older = Manifest::new(1_700_000_000_001, 8, publisher, Vec::new());
        older
            .sign_manifest(&signing_key)
            .expect("sign older manifest");
        assert!(matches!(
            observe_manifest(&db, publisher, older, None, SystemTime::now()),
            Err(PoiArtifactError::ManifestSequenceRollback {
                previous: 9,
                received: 8,
            })
        ));

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp DB root");
    }

    #[test]
    fn v4_equal_sequence_equivocation_is_rejected_after_reopen() {
        let root_dir = temp_db_root("v4-equal-sequence-equivocation");
        fs::create_dir_all(&root_dir).expect("create temp DB root");
        let signing_key = SigningKey::from_bytes(&[0x93; 32]);
        let publisher = FixedBytes::from(signing_key.verifying_key().to_bytes());
        let mut first = Manifest::new(1_700_000_000_000, 11, publisher, Vec::new());
        first
            .sign_manifest(&signing_key)
            .expect("sign first manifest");
        {
            let db = DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp DB");
            observe_manifest(&db, publisher, first.clone(), None, SystemTime::now())
                .expect("observe first publication");
            observe_manifest(&db, publisher, first, None, SystemTime::now())
                .expect("same publication is idempotent");
        }
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("reopen temp DB");
        let mut equivocation = Manifest::new(1_700_000_000_001, 11, publisher, Vec::new());
        equivocation
            .sign_manifest(&signing_key)
            .expect("sign equivocation");
        assert!(matches!(
            observe_manifest(&db, publisher, equivocation, None, SystemTime::now()),
            Err(PoiArtifactError::ManifestSequenceEquivocation { sequence: 11 })
        ));

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp DB root");
    }

    #[test]
    fn oversized_v4_blocked_descriptor_advances_watermark_before_graph_rejection() {
        let root_dir = temp_db_root("v4-oversized-blocked-descriptor");
        fs::create_dir_all(&root_dir).expect("create temp DB root");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp DB");
        let signing_key = SigningKey::from_bytes(&[0x94; 32]);
        let publisher = FixedBytes::from(signing_key.verifying_key().to_bytes());
        let scope = Scope::new(FixedBytes::from([0x95; 32]), 0, 1, "V2_PoseidonMerkle");
        let entry = ManifestEntry {
            scope: scope.clone(),
            event_count: 0,
            current_tip_index: None,
            current_root: None,
            checkpoint_catalog: CheckpointCatalogDescriptor {
                artifact: ArtifactDescriptor {
                    cid: "bafy-catalog".to_string(),
                    sha256: FixedBytes::from([0x96; 32]),
                    byte_size: 1,
                },
                format_version: FORMAT_VERSION,
                scope: scope.clone(),
                range: None,
                row_count: 0,
                chunk_count: 0,
                encoding: ArtifactEncoding::CanonicalJson,
                compression: Compression::Identity,
                checkpoint_root: None,
            },
            current_tail: None,
            retained_bridges: Vec::new(),
            blocked_shields: BlockedShieldsDescriptor {
                artifact: ArtifactDescriptor {
                    cid: "bafy-blocked".to_string(),
                    sha256: FixedBytes::from([0x97; 32]),
                    byte_size: BLOCKED_SHIELDS_ARTIFACT_MAX_BYTES + 1,
                },
                format_version: FORMAT_VERSION,
                scope,
                row_count: 0,
                encoding: ArtifactEncoding::CanonicalJson,
                compression: Compression::Identity,
            },
        };
        let mut manifest = Manifest::new(1_700_000_000_000, 12, publisher, vec![entry]);
        manifest.publisher_signature = Some(FixedBytes::from(
            signing_key
                .sign(&poi_v4_manifest_envelope_signing_message(&manifest))
                .to_bytes(),
        ));

        assert!(matches!(
            observe_manifest(&db, publisher, manifest, None, SystemTime::now()),
            Err(PoiArtifactError::Format(
                ArtifactFormatError::BlockedShieldsArtifactByteLimitExceeded { .. }
            ))
        ));
        assert_eq!(
            db.get_poi_publisher_manifest_watermark(&publisher)
                .expect("read publisher watermark")
                .expect("oversized graph watermark persisted")
                .accepted_sequence,
            12
        );

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp DB root");
    }

    #[test]
    fn v4_manifest_freshness_applies_to_each_higher_sequence() {
        let root_dir = temp_db_root("v4-sequence-freshness");
        fs::create_dir_all(&root_dir).expect("create temp DB root");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp DB");
        let signing_key = SigningKey::from_bytes(&[0x98; 32]);
        let publisher = FixedBytes::from(signing_key.verifying_key().to_bytes());
        let max_age = Duration::from_secs(1);
        let first_now = UNIX_EPOCH + Duration::from_secs(10);

        let stale_first = signed_empty_v4_manifest(&signing_key, 7_000, 9);
        assert!(matches!(
            observe_manifest(&db, publisher, stale_first, Some(max_age), first_now,),
            Err(PoiArtifactError::ManifestStale { .. })
        ));
        assert!(
            db.get_poi_publisher_manifest_watermark(&publisher)
                .expect("read absent stale-first watermark")
                .is_none()
        );

        let sequence_ten = signed_empty_v4_manifest(&signing_key, 9_500, 10);
        observe_manifest(
            &db,
            publisher,
            sequence_ten.clone(),
            Some(max_age),
            first_now,
        )
        .expect("fresh initial publication");
        let retained_ten = db
            .get_poi_publisher_manifest_watermark(&publisher)
            .expect("read sequence ten watermark")
            .expect("sequence ten watermark");

        let later = UNIX_EPOCH + Duration::from_secs(12);
        observe_manifest(&db, publisher, sequence_ten.clone(), Some(max_age), later)
            .expect("aged exact replay remains accepted");
        assert_eq!(
            db.get_poi_publisher_manifest_watermark(&publisher)
                .expect("read replay watermark")
                .expect("replay watermark"),
            retained_ten
        );

        let equal_equivocation = signed_empty_v4_manifest(&signing_key, 7_001, 10);
        assert!(matches!(
            observe_manifest(&db, publisher, equal_equivocation, Some(max_age), later,),
            Err(PoiArtifactError::ManifestSequenceEquivocation { sequence: 10 })
        ));

        let stale_higher = signed_empty_v4_manifest(&signing_key, 7_002, 11);
        assert!(matches!(
            observe_manifest(&db, publisher, stale_higher, Some(max_age), later,),
            Err(PoiArtifactError::ManifestStale { .. })
        ));
        assert_eq!(
            db.get_poi_publisher_manifest_watermark(&publisher)
                .expect("read watermark after stale higher sequence")
                .expect("retained sequence ten"),
            retained_ten
        );

        let fresh_higher = signed_empty_v4_manifest(&signing_key, 11_500, 11);
        observe_manifest(&db, publisher, fresh_higher, Some(max_age), later)
            .expect("fresh higher sequence advances");
        let retained_eleven = db
            .get_poi_publisher_manifest_watermark(&publisher)
            .expect("read sequence eleven watermark")
            .expect("sequence eleven watermark");
        assert_eq!(retained_eleven.accepted_sequence, 11);

        let future_higher = signed_empty_v4_manifest(&signing_key, 13_000, 12);
        assert!(matches!(
            observe_manifest(&db, publisher, future_higher, Some(max_age), later,),
            Err(PoiArtifactError::ManifestIssuedInFuture)
        ));
        assert_eq!(
            db.get_poi_publisher_manifest_watermark(&publisher)
                .expect("read watermark after future higher sequence")
                .expect("retained sequence eleven"),
            retained_eleven
        );

        assert!(matches!(
            observe_manifest(&db, publisher, sequence_ten, Some(max_age), later,),
            Err(PoiArtifactError::ManifestSequenceRollback {
                previous: 11,
                received: 10,
            })
        ));

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp DB root");
    }

    #[test]
    fn hashless_equal_sequence_requires_freshness_before_v4_binding() {
        let root_dir = temp_db_root("v4-hashless-floor-freshness");
        fs::create_dir_all(&root_dir).expect("create temp DB root");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp DB");
        let signing_key = SigningKey::from_bytes(&[0x9a; 32]);
        let publisher = FixedBytes::from(signing_key.verifying_key().to_bytes());
        db.advance_poi_publisher_manifest_watermark(publisher, 10)
            .expect("seed hashless migrated floor");
        let max_age = Duration::from_secs(1);
        let now = UNIX_EPOCH + Duration::from_secs(10);

        let stale = signed_empty_v4_manifest(&signing_key, 7_000, 10);
        assert!(matches!(
            observe_manifest(&db, publisher, stale, Some(max_age), now),
            Err(PoiArtifactError::ManifestStale { .. })
        ));
        assert_eq!(
            db.get_poi_publisher_manifest_watermark(&publisher)
                .expect("read floor after stale observation")
                .expect("hashless floor")
                .accepted_manifest_hash,
            None
        );

        let future = signed_empty_v4_manifest(&signing_key, 11_000, 10);
        assert!(matches!(
            observe_manifest(&db, publisher, future, Some(max_age), now),
            Err(PoiArtifactError::ManifestIssuedInFuture)
        ));
        assert_eq!(
            db.get_poi_publisher_manifest_watermark(&publisher)
                .expect("read floor after future observation")
                .expect("hashless floor")
                .accepted_manifest_hash,
            None
        );

        let fresh = signed_empty_v4_manifest(&signing_key, 9_500, 10);
        let expected_hash = fresh
            .publication_id_envelope()
            .expect("fresh publication identity")
            .manifest_body_hash;
        observe_manifest(&db, publisher, fresh, Some(max_age), now)
            .expect("fresh equal sequence binds migrated floor");
        assert_eq!(
            db.get_poi_publisher_manifest_watermark(&publisher)
                .expect("read bound floor")
                .expect("bound floor")
                .accepted_manifest_hash,
            Some(expected_hash)
        );

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp DB root");
    }

    #[test]
    fn v4_future_time_is_rejected_without_max_age_before_watermark_binding() {
        let root_dir = temp_db_root("v4-future-without-max-age");
        fs::create_dir_all(&root_dir).expect("create temp DB root");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp DB");
        let signing_key = SigningKey::from_bytes(&[0x9b; 32]);
        let publisher = FixedBytes::from(signing_key.verifying_key().to_bytes());
        let now = UNIX_EPOCH + Duration::from_secs(10);

        let future = signed_empty_v4_manifest(&signing_key, 11_000, 1);
        assert!(matches!(
            observe_manifest(&db, publisher, future, None, now),
            Err(PoiArtifactError::ManifestIssuedInFuture)
        ));
        assert!(
            db.get_poi_publisher_manifest_watermark(&publisher)
                .expect("read absent future watermark")
                .is_none()
        );

        let old = signed_empty_v4_manifest(&signing_key, 1_000, 1);
        observe_manifest(&db, publisher, old, None, now)
            .expect("old manifest is accepted when max age is disabled");

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp DB root");
    }

    #[test]
    fn hashless_equal_sequence_future_without_max_age_does_not_bind_hash() {
        let root_dir = temp_db_root("v4-hashless-future-without-max-age");
        fs::create_dir_all(&root_dir).expect("create temp DB root");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp DB");
        let signing_key = SigningKey::from_bytes(&[0x9c; 32]);
        let publisher = FixedBytes::from(signing_key.verifying_key().to_bytes());
        db.advance_poi_publisher_manifest_watermark(publisher, 10)
            .expect("seed hashless floor");
        let now = UNIX_EPOCH + Duration::from_secs(10);

        let future = signed_empty_v4_manifest(&signing_key, 11_000, 10);
        assert!(matches!(
            observe_manifest(&db, publisher, future, None, now),
            Err(PoiArtifactError::ManifestIssuedInFuture)
        ));
        assert_eq!(
            db.get_poi_publisher_manifest_watermark(&publisher)
                .expect("read future-rejected floor")
                .expect("hashless floor")
                .accepted_manifest_hash,
            None
        );

        let nonfuture = signed_empty_v4_manifest(&signing_key, 9_000, 10);
        let expected_hash = nonfuture
            .publication_id_envelope()
            .expect("nonfuture publication identity")
            .manifest_body_hash;
        observe_manifest(&db, publisher, nonfuture, None, now)
            .expect("nonfuture equal sequence binds hashless floor");
        assert_eq!(
            db.get_poi_publisher_manifest_watermark(&publisher)
                .expect("read bound floor")
                .expect("bound floor")
                .accepted_manifest_hash,
            Some(expected_hash)
        );

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp DB root");
    }

    fn signed_empty_v4_manifest(
        signing_key: &SigningKey,
        issued_at_ms: u64,
        sequence: u64,
    ) -> Manifest {
        let publisher = FixedBytes::from(signing_key.verifying_key().to_bytes());
        let mut manifest = Manifest::new(issued_at_ms, sequence, publisher, Vec::new());
        manifest
            .sign_manifest(signing_key)
            .expect("sign empty manifest");
        manifest
    }

    #[test]
    fn legacy_materialized_corpus_is_only_a_v4_start_for_exact_identity() {
        let identity = test_identity();
        let cache = test_cache(&identity, &[0x31]);
        let root = test_cache_root(&cache);
        let entry = test_entry(&identity, 0, root.0);
        let publisher = FixedBytes::from([0x61; 32]);
        let mut persisted = persisted_cache(&identity, cache, 0, root, &entry);
        persisted.record.validation = PoiCorpusValidationRecord::PublisherAttested {
            publisher_pubkey: publisher,
            manifest_sequence: 4,
            manifest_root: root,
            artifact_tip_index: 0,
        };
        let scope = Scope::new(
            identity.list_key,
            identity.chain_type,
            identity.chain_id,
            identity.txid_version.clone(),
        );

        let starting = persisted
            .starting_state(&scope, publisher)
            .expect("exact legacy corpus is reusable");
        assert_eq!(starting.cache.progress().next_event_index, 1);
        assert_eq!(starting.cache.root_at_global_index(0), Some(root));
        assert_eq!(starting.cache.identity(), &identity);

        let mut wrong_txid = scope.clone();
        wrong_txid.txid_version.push_str("-other");
        assert!(persisted.starting_state(&wrong_txid, publisher).is_none());
        let mut wrong_list = scope.clone();
        wrong_list.list_key = FixedBytes::from([0xff; 32]);
        assert!(persisted.starting_state(&wrong_list, publisher).is_none());
        assert!(
            persisted
                .starting_state(&scope, FixedBytes::from([0x62; 32]))
                .is_none()
        );
    }

    #[test]
    fn public_rpc_cache_persistence_does_not_own_publisher_watermark() {
        let root_dir = temp_db_root("rpc-cache-sequence-watermark");
        fs::create_dir_all(&root_dir).expect("create temp DB root");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp DB");
        let identity = test_identity();
        let mut cache = PoiCache::new(identity.clone());
        cache
            .apply_verified_artifact_events(&[SnapshotEvent {
                event_index: 0,
                blinded_commitment: [0x41_u8; 32],
                signature: [0_u8; 64],
                event_type: PoiEventType::Transact,
            }])
            .expect("apply test event");
        cache.accept_current_roots();
        let generation = poi_artifact_cache_generation_cell(&db)
            .expect("cache generation")
            .load(Ordering::Acquire);
        let publisher_pubkey = FixedBytes::from([0x40; 32]);
        db.advance_poi_publisher_manifest_watermark(publisher_pubkey, 7)
            .expect("seed publisher watermark");

        PoiCorpusStore::new(&db, generation, publisher_pubkey)
            .commit_public_rpc(&cache, 0, ExpectedPoiCorpusBase::NoValidCorpus)
            .expect("persist public RPC cache");
        let persisted = load_persisted_cache_for_publisher(&db, &identity, publisher_pubkey)
            .expect("load public RPC cache")
            .expect("public RPC cache record");

        assert_eq!(persisted.record.source, PoiCacheRecordSource::PublicRpc);
        assert_eq!(persisted.record.legacy_observed_manifest_sequence, 0);
        assert_eq!(
            publisher_manifest_watermark(&db, publisher_pubkey)
                .expect("load publisher watermark")
                .map(|record| record.accepted_sequence),
            Some(7)
        );
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp DB root");
    }

    #[test]
    fn rpc_only_corpus_cannot_recover_publisher_watermark() {
        let root_dir = temp_db_root("rpc-cache-no-publisher-watermark");
        fs::create_dir_all(&root_dir).expect("create temp DB root");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp DB");
        let identity = test_identity();
        let cache = test_cache(&identity, &[0x42]);
        let generation = poi_artifact_cache_generation_cell(&db)
            .expect("cache generation")
            .load(Ordering::Acquire);
        persist_public_rpc_cache(
            &db,
            &cache,
            generation,
            0,
            ExpectedPoiCorpusBase::NoValidCorpus,
        )
        .expect("persist RPC-only corpus");
        let mut record = db
            .get_poi_artifact_cache(
                identity.chain_type,
                identity.chain_id,
                &identity.txid_version,
                &identity.list_key,
            )
            .expect("load RPC-only corpus")
            .expect("RPC-only corpus");
        record.legacy_observed_manifest_sequence = 99;
        db.put_poi_artifact_cache(&record)
            .expect("persist legacy observational sequence");

        assert_eq!(
            publisher_manifest_watermark(&db, FixedBytes::from([0x41; 32]))
                .expect("derive publisher watermark"),
            None
        );

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp DB root");
    }

    #[test]
    fn malformed_persisted_tip_is_rejected_and_does_not_block_valid_replacement() {
        let root_dir = temp_db_root("malformed-persisted-tip");
        fs::create_dir_all(&root_dir).expect("create temp DB root");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp DB");
        let identity = test_identity();
        let cache = test_cache(&identity, &[0x31]);
        let root = test_cache_root(&cache);
        let entry = test_entry(&identity, 0, root.0);
        let mut malformed = persisted_cache(&identity, cache.clone(), 0, root, &entry).record;
        malformed.current_tip_index = 50;
        db.put_poi_artifact_cache(&malformed)
            .expect("persist malformed corpus");

        assert!(matches!(
            load_persisted_cache(&db, &identity),
            Err(PoiArtifactError::PersistedTipMismatch {
                metadata: 50,
                payload: 0,
            })
        ));

        let generation = poi_artifact_cache_generation_cell(&db)
            .expect("cache generation")
            .load(Ordering::Acquire);
        assert_eq!(
            persist_public_rpc_cache(
                &db,
                &cache,
                generation,
                0,
                ExpectedPoiCorpusBase::NoValidCorpus,
            )
            .expect("replace malformed corpus"),
            CorpusCommitOutcome::Applied
        );
        let recovered = load_persisted_cache(&db, &identity)
            .expect("load replacement corpus")
            .expect("replacement corpus");
        assert_eq!(recovered.record.current_tip_index, 0);
        assert_eq!(recovered.record.current_tip_root, root);

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp DB root");
    }

    #[test]
    fn persisted_root_and_validation_provenance_must_match_payload() {
        let root_dir = temp_db_root("malformed-persisted-root");
        fs::create_dir_all(&root_dir).expect("create temp DB root");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp DB");
        let identity = test_identity();
        let cache = test_cache(&identity, &[0x32]);
        let root = test_cache_root(&cache);
        let entry = test_entry(&identity, 0, root.0);
        let mut malformed = persisted_cache(&identity, cache.clone(), 0, root, &entry).record;
        malformed.current_tip_root = FixedBytes::from([0xff; 32]);
        db.put_poi_artifact_cache(&malformed)
            .expect("persist mismatched root");
        assert!(matches!(
            load_persisted_cache(&db, &identity),
            Err(PoiArtifactError::PersistedRootMismatch { tip_index: 0 })
        ));

        let generation = poi_artifact_cache_generation_cell(&db)
            .expect("cache generation")
            .load(Ordering::Acquire);
        persist_public_rpc_cache(
            &db,
            &cache,
            generation,
            0,
            ExpectedPoiCorpusBase::NoValidCorpus,
        )
        .expect("replace root-mismatched corpus");
        let mut malformed = db
            .get_poi_artifact_cache(
                identity.chain_type,
                identity.chain_id,
                &identity.txid_version,
                &identity.list_key,
            )
            .expect("load public corpus")
            .expect("public corpus");
        malformed.validation = PoiCorpusValidationRecord::ListSignedRanges {
            list_key: FixedBytes::from([0xee; 32]),
            from_index: 0,
        };
        db.put_poi_artifact_cache(&malformed)
            .expect("persist mismatched provenance");
        assert!(matches!(
            load_persisted_cache(&db, &identity),
            Err(PoiArtifactError::PersistedValidationProvenance { .. })
        ));

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp DB root");
    }

    #[test]
    fn persisted_record_identity_must_match_payload_identity() {
        let identity = test_identity();
        let cache = test_cache(&identity, &[0x3a]);
        let root = test_cache_root(&cache);
        let entry = test_entry(&identity, 0, root.0);
        let mut record = persisted_cache(&identity, cache, 0, root, &entry).record;
        record.chain_id = 137;

        assert!(matches!(
            validate_persisted_record(&record, &identity, None),
            Err(PoiArtifactError::PersistedIdentityMismatch)
        ));
    }

    #[tokio::test]
    async fn stale_generation_rpc_health_cannot_overwrite_current_health() {
        let root_dir = temp_db_root("generation-fenced-rpc-health");
        fs::create_dir_all(&root_dir).expect("create temp DB root");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp DB");
        let identity = test_identity();
        let reset = clear_poi_artifact_cache_for_reset(&db)
            .await
            .expect("advance generation");
        db.put_poi_corpus_rpc_health(&PoiCorpusRpcHealthRecord {
            chain_type: identity.chain_type,
            chain_id: identity.chain_id,
            txid_version: identity.txid_version.clone(),
            list_key: identity.list_key,
            cache_generation: reset.generation,
            last_successful_rpc_sync_at_ms: Some(777),
            updated_at: 0,
        })
        .expect("persist current-generation health");

        assert!(matches!(
            record_poi_rpc_success(&db, &identity, 0),
            Err(PoiArtifactError::StalePublicCacheGeneration {
                expected: 1,
                actual: 0,
            })
        ));
        let retained = db
            .get_poi_corpus_rpc_health(
                identity.chain_type,
                identity.chain_id,
                &identity.txid_version,
                &identity.list_key,
            )
            .expect("load retained health")
            .expect("retained health");
        assert_eq!(retained.cache_generation, reset.generation);
        assert_eq!(retained.last_successful_rpc_sync_at_ms, Some(777));

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp DB root");
    }

    #[test]
    fn expected_absent_public_rpc_candidate_loses_first_writer_race() {
        let root_dir = temp_db_root("rpc-expected-absent-first-writer");
        fs::create_dir_all(&root_dir).expect("create temp DB root");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp DB");
        let identity = test_identity();
        let first = test_cache(&identity, &[0x61]);
        let stale = test_cache(&identity, &[0x62]);
        let generation = poi_artifact_cache_generation_cell(&db)
            .expect("cache generation")
            .load(Ordering::Acquire);

        assert_eq!(
            persist_public_rpc_cache(
                &db,
                &first,
                generation,
                0,
                ExpectedPoiCorpusBase::NoValidCorpus,
            )
            .expect("persist first writer"),
            CorpusCommitOutcome::Applied
        );
        assert_eq!(
            persist_public_rpc_cache(
                &db,
                &stale,
                generation,
                0,
                ExpectedPoiCorpusBase::NoValidCorpus,
            )
            .expect("reject stale first-run candidate"),
            CorpusCommitOutcome::Stale
        );

        let retained = load_persisted_cache(&db, &identity)
            .expect("load retained corpus")
            .expect("first writer remains durable");
        assert_eq!(
            retained.cache.to_bytes().expect("encode retained corpus"),
            first.to_bytes().expect("encode first corpus")
        );

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp DB root");
    }

    fn test_identity() -> PoiCacheIdentity {
        PoiCacheIdentity::new(0, 1, "V2_PoseidonMerkle", FixedBytes::from([0x11; 32]))
    }

    fn temp_db_root(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!("sync-service-poi-artifacts-{name}-{unique}"))
    }

    fn test_entry(
        identity: &PoiCacheIdentity,
        current_tip_index: u64,
        current_tip_merkleroot: [u8; 32],
    ) -> LegacyManifestEntry {
        LegacyManifestEntry {
            list_key: identity.list_key,
            chain_id: identity.chain_id,
            base: descriptor("base"),
            deltas: vec![descriptor("delta")],
            retained_deltas: Vec::new(),
            blocked_shields: descriptor("blocked"),
            current_tip_index,
            current_tip_merkleroot: FixedBytes::from(current_tip_merkleroot),
        }
    }

    fn descriptor(cid: &str) -> ArtifactDescriptor {
        ArtifactDescriptor {
            cid: cid.to_string(),
            sha256: FixedBytes::ZERO,
            byte_size: 0,
        }
    }

    fn test_cache(identity: &PoiCacheIdentity, commitment_bytes: &[u8]) -> PoiCache {
        let events = commitment_bytes
            .iter()
            .enumerate()
            .map(|(index, byte)| SnapshotEvent {
                event_index: index as u64,
                blinded_commitment: [*byte; 32],
                signature: [0_u8; 64],
                event_type: PoiEventType::Transact,
            })
            .collect::<Vec<_>>();
        let mut cache = PoiCache::new(identity.clone());
        cache
            .apply_verified_artifact_events(&events)
            .expect("apply test artifact events");
        cache.accept_current_roots();
        cache
    }

    fn test_cache_root(cache: &PoiCache) -> FixedBytes<32> {
        *cache
            .clone()
            .current_roots()
            .get(&0)
            .expect("test cache root")
    }

    fn persisted_cache(
        identity: &PoiCacheIdentity,
        cache: PoiCache,
        current_tip_index: u64,
        current_tip_root: FixedBytes<32>,
        entry: &LegacyManifestEntry,
    ) -> PersistedPoiArtifactCache {
        PersistedPoiArtifactCache {
            record: PoiArtifactCacheRecord {
                chain_type: identity.chain_type,
                chain_id: identity.chain_id,
                txid_version: identity.txid_version.clone(),
                list_key: identity.list_key,
                cache_generation: 0,
                source: PoiCacheRecordSource::IndexedArtifacts,
                validation: PoiCorpusValidationRecord::Legacy,
                legacy_observed_manifest_sequence: 4,
                base_descriptor: descriptor_record(&descriptor("old-base")),
                applied_delta_descriptors: Vec::new(),
                blocked_shields_descriptor: descriptor_record(&entry.blocked_shields),
                artifact_tip_index: Some(current_tip_index),
                artifact_tip_root: Some(current_tip_root),
                current_tip_index,
                current_tip_root,
                cache_payload: cache.to_bytes().expect("cache bytes"),
                legacy_last_successful_rpc_sync_at_ms: None,
                updated_at: 0,
            },
            cache,
            cache_generation: 0,
        }
    }
}
