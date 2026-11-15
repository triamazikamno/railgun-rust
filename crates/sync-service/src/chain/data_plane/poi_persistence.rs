//! POI artifact persistence behind the data plane's commit fence.

use crate::poi_artifacts::{
    CorpusCandidate, CorpusCommitOutcome, CurrentChunk, ExpectedPoiCorpusBase, FetchedArtifact,
    ObservedManifest, PersistCorpusResult, PersistedPoiArtifactCache, PoiArtifactError,
    PoiCorpusCompactionResult, PoiCorpusStore, PublicRpcPersistResult, RawChunkCache,
    RawChunkRetainOutcome, SemanticVerifiedChunk, TransportVerifiedChunk, VerifiedBlockedShields,
    VerifiedCatalog, VerifiedCorpusCandidate, observe_manifest_with_clock, persist_prepared_corpus,
    prepare_candidate, prepare_candidate_from_starting_for_generation, publisher_manifest_sequence,
};
use crate::poi_cache::PoiCacheRetryHandle;
use crate::runtime_admission::DbRuntimeLease;
use crate::types::PoiArtifactCacheAttemptId;
use alloy::primitives::FixedBytes;
use local_db::{DbStore, PoiArtifactCacheRecord, PoiCorpusJournalHeadRecord};
use poi::artifacts::v4::{Manifest, Scope};
use poi::cache::{PoiCache, PoiCacheIdentity, PoiCacheJournalDelta};
use poi::poi::BlockedShield;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio_util::sync::CancellationToken;

use super::{Mutex, PublicDataPlaneError};

pub struct PoiArtifactCacheRetry {
    pub(super) chain_id: u64,
    pub(super) retry: PoiCacheRetryHandle,
}

#[derive(Clone)]
pub struct PoiArtifactPersistenceHandle {
    db: Arc<DbStore>,
    commit_fence: Arc<Mutex<()>>,
    runtime_lease: Option<DbRuntimeLease>,
}

impl PoiArtifactPersistenceHandle {
    pub(crate) const fn new(db: Arc<DbStore>, commit_fence: Arc<Mutex<()>>) -> Self {
        Self {
            db,
            commit_fence,
            runtime_lease: None,
        }
    }

    #[must_use]
    pub(crate) fn with_runtime_lease(mut self, runtime_lease: DbRuntimeLease) -> Self {
        self.runtime_lease = Some(runtime_lease);
        self
    }

    pub async fn observe_manifest(
        &self,
        trusted_publisher_pubkey: FixedBytes<32>,
        manifest: Manifest,
        max_age: Option<Duration>,
    ) -> Result<ObservedManifest, PublicDataPlaneError> {
        self.observe_manifest_with_clock(
            trusted_publisher_pubkey,
            manifest,
            max_age,
            &SystemTime::now,
        )
        .await
    }

    pub(crate) async fn observe_manifest_with_clock<F>(
        &self,
        trusted_publisher_pubkey: FixedBytes<32>,
        manifest: Manifest,
        max_age: Option<Duration>,
        acceptance_time: &F,
    ) -> Result<ObservedManifest, PublicDataPlaneError>
    where
        F: Fn() -> SystemTime + Sync + ?Sized,
    {
        let _commit_guard = self.commit_fence.lock().await;
        observe_manifest_with_clock(
            self.db.as_ref(),
            trusted_publisher_pubkey,
            manifest,
            max_age,
            acceptance_time,
        )
        .map_err(poi_artifact_persistence_error)
    }

    /// Reads the durable publisher manifest sequence, the floor below which an
    /// IPNS record cannot close manifest resolution early.
    pub(crate) async fn publisher_manifest_sequence(
        &self,
        trusted_publisher_pubkey: FixedBytes<32>,
    ) -> Result<Option<u64>, PublicDataPlaneError> {
        let _commit_guard = self.commit_fence.lock().await;
        publisher_manifest_sequence(self.db.as_ref(), trusted_publisher_pubkey)
            .map_err(poi_artifact_persistence_error)
    }

    pub async fn begin_candidate(
        &self,
        observed: &ObservedManifest,
        catalog: &VerifiedCatalog,
    ) -> Result<CorpusCandidate, PublicDataPlaneError> {
        let observed = observed.clone();
        let catalog = catalog.clone();
        self.run_blocking_commit(None, "artifact candidate preparation", move |db| {
            prepare_candidate(db, &observed, &catalog)
        })
        .await?
        .ok_or_else(|| {
            poi_artifact_persistence_error("uncancelled candidate preparation returned no result")
        })
    }

    pub(crate) async fn begin_candidate_from_starting(
        &self,
        observed: &ObservedManifest,
        catalog: &VerifiedCatalog,
        persisted: Option<PersistedPoiArtifactCache>,
        expected_base: ExpectedPoiCorpusBase,
        expected_generation: u64,
    ) -> Result<CorpusCandidate, PublicDataPlaneError> {
        let _commit_guard = self.commit_fence.lock().await;
        prepare_candidate_from_starting_for_generation(
            self.db.as_ref(),
            observed,
            catalog,
            persisted,
            expected_base,
            expected_generation,
        )
        .map_err(poi_artifact_persistence_error)
    }

    pub fn verify_checkpoint_catalog(
        &self,
        observed: &ObservedManifest,
        scope: &Scope,
        fetched: FetchedArtifact,
    ) -> Result<VerifiedCatalog, PublicDataPlaneError> {
        observed
            .verify_checkpoint_catalog(scope, fetched)
            .map_err(poi_artifact_persistence_error)
    }

    pub fn current_graph_chunk(
        &self,
        observed: &ObservedManifest,
        scope: &Scope,
        catalog: Option<&VerifiedCatalog>,
        descriptor: &poi::artifacts::v4::EventArtifactDescriptor,
    ) -> Result<CurrentChunk, PublicDataPlaneError> {
        let admission = RawChunkCache::new(self.db.as_ref()).admission(observed.publication_id());
        observed
            .current_graph_chunk(scope, catalog, descriptor, admission)
            .map_err(poi_artifact_persistence_error)
    }

    pub fn verify_fetched_chunk(
        &self,
        current: CurrentChunk,
        fetched: FetchedArtifact,
    ) -> Result<TransportVerifiedChunk, PublicDataPlaneError> {
        current
            .verify_fetched(fetched)
            .map_err(poi_artifact_persistence_error)
    }

    pub fn verify_event_signatures(
        &self,
        chunk: TransportVerifiedChunk,
    ) -> Result<SemanticVerifiedChunk, PublicDataPlaneError> {
        chunk
            .verify_event_signatures()
            .map_err(poi_artifact_persistence_error)
    }

    pub fn verify_blocked_shields(
        &self,
        observed: &ObservedManifest,
        scope: &Scope,
        fetched: FetchedArtifact,
    ) -> Result<VerifiedBlockedShields, PublicDataPlaneError> {
        observed
            .verify_blocked_shields(scope, fetched)
            .map_err(poi_artifact_persistence_error)
    }

    pub async fn cached_chunk(
        &self,
        current: &CurrentChunk,
    ) -> Result<Option<SemanticVerifiedChunk>, PublicDataPlaneError> {
        let _commit_guard = self.commit_fence.lock().await;
        RawChunkCache::new(self.db.as_ref())
            .get(current)
            .await
            .map_err(poi_artifact_persistence_error)
    }

    pub async fn retain_chunk(
        &self,
        chunk: &SemanticVerifiedChunk,
    ) -> Result<RawChunkRetainOutcome, PublicDataPlaneError> {
        let _commit_guard = self.commit_fence.lock().await;
        RawChunkCache::new(self.db.as_ref())
            .retain(chunk)
            .await
            .map_err(poi_artifact_persistence_error)
    }

    pub async fn commit_candidate(
        &self,
        candidate: VerifiedCorpusCandidate,
    ) -> Result<CorpusCommitOutcome, PublicDataPlaneError> {
        let result = self
            .run_blocking_commit(None, "artifact candidate", move |db| {
                persist_prepared_corpus(db, candidate)
            })
            .await?
            .ok_or_else(|| {
                poi_artifact_persistence_error("uncancelled blocking commit returned no result")
            })?;
        Ok(result.outcome())
    }

    pub(crate) async fn retain_chunk_for_attempt(
        &self,
        chunk: &SemanticVerifiedChunk,
        cancel: &CancellationToken,
    ) -> Result<Option<RawChunkRetainOutcome>, PublicDataPlaneError> {
        let _commit_guard = self.commit_fence.lock().await;
        RawChunkCache::new(self.db.as_ref())
            .retain_with_fence(chunk, || !cancel.is_cancelled())
            .await
            .map_err(poi_artifact_persistence_error)
    }

    pub(crate) async fn commit_candidate_for_attempt(
        &self,
        candidate: VerifiedCorpusCandidate,
        cancel: &CancellationToken,
    ) -> Result<Option<PersistedPoiArtifactCache>, PublicDataPlaneError> {
        Ok(self
            .run_blocking_commit(Some(cancel), "artifact candidate", move |db| {
                commit_artifact_after_admission(db, candidate)
            })
            .await?
            .flatten())
    }

    pub(crate) async fn commit_public_rpc_for_attempt(
        &self,
        cache: PoiCache,
        cache_generation: u64,
        publisher_pubkey: FixedBytes<32>,
        range_start_index: u64,
        expected_base: ExpectedPoiCorpusBase,
        starting_record: Option<PoiArtifactCacheRecord>,
        starting_head: Option<PoiCorpusJournalHeadRecord>,
        delta: PoiCacheJournalDelta,
        blocked_shields: Option<Vec<BlockedShield>>,
        cancel: &CancellationToken,
    ) -> Result<Option<PersistedPoiArtifactCache>, PublicDataPlaneError> {
        let post_compaction_cancel = cancel.clone();
        Ok(self
            .run_blocking_commit(Some(cancel), "public RPC candidate", move |db| {
                commit_public_rpc_after_admission(
                    db,
                    cache,
                    cache_generation,
                    publisher_pubkey,
                    range_start_index,
                    expected_base,
                    starting_record.as_ref(),
                    starting_head.as_ref(),
                    &delta,
                    blocked_shields,
                    || post_compaction_cancel.is_cancelled(),
                )
            })
            .await?
            .flatten())
    }

    pub(crate) async fn compact_poi_corpus_for_attempt(
        &self,
        identity: PoiCacheIdentity,
        cache_generation: u64,
        publisher_pubkey: FixedBytes<32>,
        expected_base: ExpectedPoiCorpusBase,
        cancel: &CancellationToken,
    ) -> Result<Option<PoiCorpusCompactionResult>, PublicDataPlaneError> {
        self.run_blocking_commit(Some(cancel), "journal compaction", move |db| {
            PoiCorpusStore::new(db, cache_generation, publisher_pubkey)
                .compact(&identity, expected_base)
        })
        .await
    }

    pub(super) async fn run_blocking_commit<T, F>(
        &self,
        cancel: Option<&CancellationToken>,
        operation_name: &'static str,
        operation: F,
    ) -> Result<Option<T>, PublicDataPlaneError>
    where
        T: Send + 'static,
        F: FnOnce(&DbStore) -> Result<T, PoiArtifactError> + Send + 'static,
    {
        let admission_started = Instant::now();
        let commit_guard = if let Some(cancel) = cancel {
            tokio::select! {
                biased;
                () = cancel.cancelled() => return Ok(None),
                guard = Arc::clone(&self.commit_fence).lock_owned() => guard,
            }
        } else {
            Arc::clone(&self.commit_fence).lock_owned().await
        };
        let admission_elapsed = admission_started.elapsed();
        if cancel.is_some_and(CancellationToken::is_cancelled) {
            return Ok(None);
        }

        let db = Arc::clone(&self.db);
        let runtime_lease = self.runtime_lease.clone();
        let blocking_submitted = Instant::now();
        let (result, blocking_start_elapsed, execution_elapsed) =
            tokio::task::spawn_blocking(move || {
                let blocking_start_elapsed = blocking_submitted.elapsed();
                let execution_started = Instant::now();
                let result = operation(db.as_ref());
                drop(runtime_lease);
                drop(commit_guard);
                (result, blocking_start_elapsed, execution_started.elapsed())
            })
            .await
            .map_err(|error| {
                poi_artifact_persistence_error(format!(
                    "{operation_name} blocking task failed: {error}"
                ))
            })?;
        tracing::debug!(
            operation = operation_name,
            admission_elapsed_ms = admission_elapsed.as_millis(),
            blocking_start_elapsed_ms = blocking_start_elapsed.as_millis(),
            execution_elapsed_ms = execution_elapsed.as_millis(),
            "PPOI persistence blocking operation complete"
        );
        result.map(Some).map_err(poi_artifact_persistence_error)
    }
}

pub(crate) fn commit_artifact_after_admission(
    db: &DbStore,
    candidate: VerifiedCorpusCandidate,
) -> Result<Option<PersistedPoiArtifactCache>, PoiArtifactError> {
    Ok(match persist_prepared_corpus(db, candidate)? {
        PersistCorpusResult::Applied(persisted) => Some(*persisted),
        PersistCorpusResult::Stale => None,
    })
}

pub(super) fn commit_public_rpc_after_admission(
    db: &DbStore,
    cache: PoiCache,
    cache_generation: u64,
    publisher_pubkey: FixedBytes<32>,
    range_start_index: u64,
    expected_base: ExpectedPoiCorpusBase,
    starting_record: Option<&PoiArtifactCacheRecord>,
    starting_head: Option<&PoiCorpusJournalHeadRecord>,
    delta: &PoiCacheJournalDelta,
    blocked_shields: Option<Vec<BlockedShield>>,
    cancelled_after_compaction: impl FnOnce() -> bool,
) -> Result<Option<PersistedPoiArtifactCache>, PoiArtifactError> {
    let identity = cache.identity().clone();
    let store = PoiCorpusStore::new(db, cache_generation, publisher_pubkey);
    let initial = store.commit_public_rpc(
        cache,
        range_start_index,
        expected_base,
        starting_record,
        starting_head,
        delta,
        blocked_shields,
    )?;
    let persisted = match initial {
        PublicRpcPersistResult::Applied(persisted) => Some(*persisted),
        PublicRpcPersistResult::Stale => None,
        PublicRpcPersistResult::CompactionRequired(pending) => {
            if !matches!(expected_base, ExpectedPoiCorpusBase::JournalHead { .. }) {
                return Err(PoiArtifactError::JournalHardLimitExceeded);
            }
            let compacted = match store.compact(&identity, expected_base)? {
                PoiCorpusCompactionResult::Applied(compacted) => *compacted,
                PoiCorpusCompactionResult::Stale => {
                    return Ok(None);
                }
            };
            if cancelled_after_compaction() {
                return Ok(None);
            }
            let retry_expected_base = compacted.expected_base();
            let retry_starting_record = Some(compacted.metadata_only());
            let retry_starting_head = compacted.journal_head;
            match store.commit_public_rpc(
                pending.cache,
                range_start_index,
                retry_expected_base,
                retry_starting_record.as_ref(),
                retry_starting_head.as_ref(),
                delta,
                pending.blocked_shields,
            )? {
                PublicRpcPersistResult::Applied(persisted) => Some(*persisted),
                PublicRpcPersistResult::Stale => None,
                PublicRpcPersistResult::CompactionRequired(_) => {
                    return Err(PoiArtifactError::JournalHardLimitExceeded);
                }
            }
        }
    };
    Ok(persisted)
}

fn poi_artifact_persistence_error(error: impl std::fmt::Display) -> PublicDataPlaneError {
    PublicDataPlaneError::PoiArtifactPersistence {
        reason: error.to_string(),
    }
}

impl PoiArtifactCacheRetry {
    #[must_use]
    pub const fn attempt_id(&self) -> PoiArtifactCacheAttemptId {
        self.retry.attempt_id()
    }

    pub async fn wait(self) -> Result<(), PublicDataPlaneError> {
        self.retry
            .wait()
            .await
            .map_err(|reason| PublicDataPlaneError::PoiCorpusRefresh {
                chain_id: self.chain_id,
                reason: reason.to_string(),
            })
    }
}
