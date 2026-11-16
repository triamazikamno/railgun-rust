use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use alloy::primitives::FixedBytes;
use local_db::{DbStore, PoiCorpusJournalHeadRecord};
use poi::SensitiveUrl;
use poi::poi::{DEFAULT_WALLET_POI_RPC_URL, default_active_poi_list_keys};
use tokio::sync::{Mutex, OwnedRwLockWriteGuard, RwLock, mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::chain::PoiArtifactPersistenceHandle;
use crate::poi_artifacts::PersistedPoiArtifactCache;
use crate::types::{
    LocalPoiCaches, PoiArtifactCacheAttemptId, PoiArtifactCacheProgress, PoiArtifactSourceConfig,
};

mod candidates;
mod compaction;
mod coordinator;
mod install;
mod progress;
mod schedule;
mod source_health;

#[cfg(test)]
use candidates::{
    PoiCacheCandidateJob, PreparedPoiCacheBatch, PreparedPoiCacheCandidate,
    PreparedPoiCachePersistence, PreparedPublicRpcPersistence, poi_cache_error_diagnostic,
    produce_chain_poi_cache_candidates, public_rpc_candidate_cache,
};
#[cfg(test)]
use compaction::{
    PoiCorpusCompactionLane, PoiCorpusCompactionRequest, cancel_poi_corpus_compaction_lane,
    enqueue_poi_corpus_compactions, run_background_poi_corpus_compaction,
    start_next_poi_corpus_compaction, wait_for_active_poi_corpus_compaction,
};
use coordinator::spawn_chain_poi_cache_coordinator;
#[cfg(test)]
use coordinator::{
    ActivePoiCacheAttempt, cancel_active_attempt, drop_completed_attempt,
    publish_active_attempt_progress, replacement_poi_cache_scope,
};
#[cfg(test)]
use install::{
    StagedPoiCacheCandidate, apply_staged_poi_cache_batch, finish_chain_poi_cache_attempt,
    install_cache_if_not_behind, stage_poi_cache_candidate, validate_artifact_manifest_sequences,
};
#[cfg(test)]
use progress::{
    chain_poi_cache_list_progress, new_poi_artifact_cache_progress,
    publish_chain_poi_cache_ready_and_acknowledge_initialization, single_list_event_index,
};
#[cfg(test)]
use schedule::{
    POI_CACHE_BLOCKED_ACTIVE_INTERVAL, POI_CACHE_BLOCKED_IDLE_INTERVAL,
    POI_CACHE_EVENT_ACTIVE_INTERVAL, POI_CACHE_EVENT_IDLE_INTERVAL,
    POI_CACHE_FAILURE_RETRY_INTERVAL, PoiCacheMaintenanceSchedule, apply_poi_cache_demand_update,
    effective_poi_cache_scope,
};
use schedule::{PoiCacheDemand, PoiCacheSyncScope, poi_cache_demand};
#[cfg(test)]
use source_health::{
    PoiListSourceOutcome, PoiRpcAttemptOutcome, PoiSourceHealth, record_list_source_outcomes,
    source_health_for_lists,
};

const EVM_CHAIN_TYPE: u8 = 0;
const POI_CACHE_COMMAND_CAPACITY: usize = 16;
const POI_CORPUS_WRITE_FENCE_SLOW_AFTER: Duration = Duration::from_secs(3);

struct ChainPoiCacheCoordinator {
    db: Arc<DbStore>,
    http_client: Option<reqwest::Client>,
    poi_rpc_url: SensitiveUrl,
    artifact_config: PoiArtifactSourceConfig,
    cache_generation: u64,
    chain_id: u64,
    local_caches: LocalPoiCaches,
    active_list_keys: Vec<FixedBytes<32>>,
    preloaded_caches: BTreeMap<FixedBytes<32>, PersistedPoiArtifactCache>,
    installed_head_anchors: StdMutex<BTreeMap<FixedBytes<32>, PoiCorpusJournalHeadRecord>>,
    command_rx: mpsc::Receiver<ChainPoiCacheCommand>,
    job_tx: mpsc::UnboundedSender<ChainPoiCacheJobEvent>,
    job_rx: mpsc::UnboundedReceiver<ChainPoiCacheJobEvent>,
    progress_tx: watch::Sender<BTreeMap<u64, PoiArtifactCacheProgress>>,
    cancel: CancellationToken,
    runtime: Arc<PoiCacheServiceRuntime>,
    poi_artifact_persistence: PoiArtifactPersistenceHandle,
}

struct PoiCacheServiceRuntime {
    next_attempt_id: AtomicU64,
    publication_fence: StdMutex<PoiCachePublicationState>,
    public_cache_reset_gate: Arc<RwLock<()>>,
}

#[derive(Default)]
struct PoiCachePublicationState {
    shutdown: bool,
}

impl PoiCacheServiceRuntime {
    fn new() -> Self {
        Self {
            next_attempt_id: AtomicU64::new(1),
            publication_fence: StdMutex::new(PoiCachePublicationState::default()),
            public_cache_reset_gate: Arc::new(RwLock::new(())),
        }
    }

    fn next_attempt_id(&self) -> PoiArtifactCacheAttemptId {
        PoiArtifactCacheAttemptId::new(self.next_attempt_id.fetch_add(1, Ordering::Relaxed))
    }
}

#[derive(Clone)]
struct ChainPoiCacheHandle {
    command_tx: mpsc::Sender<ChainPoiCacheCommand>,
    initialized_rx: watch::Receiver<bool>,
    stopped_rx: watch::Receiver<bool>,
}

enum ChainPoiCacheCommand {
    UpdateDemand {
        actor_id: u64,
        demand: PoiCacheDemand,
    },
    Retry {
        scope: PoiCacheSyncScope,
        admission: oneshot::Sender<Result<PoiCacheRetryHandle, PoiCacheServiceError>>,
    },
    QuiesceForPublicCacheReset {
        lease: CancellationToken,
        response: oneshot::Sender<()>,
    },
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PoiCacheServiceError {
    #[error("POI cache coordinator stopped")]
    CoordinatorStopped,
    #[error("POI cache service owns chain {expected}, requested chain {actual}")]
    ChainMismatch { expected: u64, actual: u64 },
    #[error("POI corpus or public cache reset is in progress")]
    CorpusResetInProgress,
    #[error("POI cache attempt {attempt_id} was superseded")]
    AttemptSuperseded {
        attempt_id: PoiArtifactCacheAttemptId,
    },
    #[error("POI cache attempt {attempt_id} became stale after reset")]
    StaleAttempt {
        attempt_id: PoiArtifactCacheAttemptId,
    },
    #[error("POI cache attempt {attempt_id} was cancelled during shutdown")]
    Shutdown {
        attempt_id: PoiArtifactCacheAttemptId,
    },
    #[error("POI cache refresh failed: {reason}")]
    Refresh { reason: String },
    #[error(transparent)]
    Db(#[from] local_db::DbError),
}

pub(crate) struct PoiCacheService {
    db: Arc<DbStore>,
    chain_id: u64,
    cache_generation: u64,
    artifact_config: PoiArtifactSourceConfig,
    http_client: Option<reqwest::Client>,
    poi_rpc_url: SensitiveUrl,
    active_list_keys: Vec<FixedBytes<32>>,
    coordinator: Mutex<Option<ChainPoiCacheHandle>>,
    local_caches: LocalPoiCaches,
    progress_tx: watch::Sender<BTreeMap<u64, PoiArtifactCacheProgress>>,
    cancel: CancellationToken,
    runtime: Arc<PoiCacheServiceRuntime>,
    poi_artifact_persistence: PoiArtifactPersistenceHandle,
}

pub(crate) struct PoiPublicCacheResetLease {
    admission: Option<OwnedRwLockWriteGuard<()>>,
    release: CancellationToken,
}

impl Drop for PoiPublicCacheResetLease {
    fn drop(&mut self) {
        drop(self.admission.take());
        self.release.cancel();
    }
}

impl PoiCacheService {
    pub(crate) fn new_with_persistence(
        db: Arc<DbStore>,
        chain_id: u64,
        artifact_config: PoiArtifactSourceConfig,
        http_client: Option<reqwest::Client>,
        poi_artifact_persistence: PoiArtifactPersistenceHandle,
    ) -> Result<Self, local_db::DbError> {
        let (progress_tx, _) = watch::channel(BTreeMap::new());
        let cache_generation = db.poi_artifact_cache_generation()?;
        Ok(Self {
            db,
            chain_id,
            cache_generation,
            artifact_config,
            http_client,
            poi_rpc_url: default_poi_rpc_url(),
            active_list_keys: default_active_poi_list_keys(),
            coordinator: Mutex::new(None),
            local_caches: LocalPoiCaches::new(),
            progress_tx,
            cancel: CancellationToken::new(),
            runtime: Arc::new(PoiCacheServiceRuntime::new()),
            poi_artifact_persistence,
        })
    }

    #[must_use]
    pub(crate) fn with_poi_rpc_url(mut self, poi_rpc_url: impl Into<SensitiveUrl>) -> Self {
        self.poi_rpc_url = poi_rpc_url.into();
        self
    }

    #[must_use]
    pub(crate) fn progress_rx(&self) -> watch::Receiver<BTreeMap<u64, PoiArtifactCacheProgress>> {
        self.progress_tx.subscribe()
    }

    pub(crate) async fn start_chain(
        &self,
        chain_id: u64,
    ) -> Result<LocalPoiCaches, PoiCacheServiceError> {
        self.ensure_chain_id(chain_id)?;
        match self.local_caches(chain_id).await {
            Ok(Some(local_caches)) => return Ok(local_caches),
            Ok(None) | Err(PoiCacheServiceError::CoordinatorStopped) => {}
            Err(error) => return Err(error),
        }
        let _public_cache_reset_admission = self.runtime.public_cache_reset_gate.read().await;
        loop {
            let (handle, created) = {
                let mut coordinator = self.coordinator.lock().await;
                if let Some(existing) = coordinator.as_ref().cloned() {
                    (existing, false)
                } else {
                    if self.cancel.is_cancelled() {
                        return Err(PoiCacheServiceError::CoordinatorStopped);
                    }
                    let active_list_keys = self.active_list_keys.clone();
                    let (command_tx, command_rx) = mpsc::channel(POI_CACHE_COMMAND_CAPACITY);
                    let (job_tx, job_rx) = mpsc::unbounded_channel();
                    let (initialized_tx, initialized_rx) = watch::channel(false);
                    let (stopped_tx, stopped_rx) = watch::channel(false);
                    let handle = ChainPoiCacheHandle {
                        command_tx,
                        initialized_rx,
                        stopped_rx,
                    };
                    *coordinator = Some(handle.clone());
                    spawn_chain_poi_cache_coordinator(
                        ChainPoiCacheCoordinator {
                            db: Arc::clone(&self.db),
                            http_client: self.http_client.clone(),
                            poi_rpc_url: self.poi_rpc_url.clone(),
                            artifact_config: self.artifact_config.clone(),
                            cache_generation: self.cache_generation,
                            chain_id,
                            local_caches: self.local_caches.clone(),
                            active_list_keys,
                            preloaded_caches: BTreeMap::new(),
                            installed_head_anchors: StdMutex::new(BTreeMap::new()),
                            command_rx,
                            job_tx,
                            job_rx,
                            progress_tx: self.progress_tx.clone(),
                            cancel: self.cancel.child_token(),
                            runtime: Arc::clone(&self.runtime),
                            poi_artifact_persistence: self.poi_artifact_persistence.clone(),
                        },
                        initialized_tx,
                        stopped_tx,
                    );
                    (handle, true)
                }
            };
            match wait_for_chain_poi_cache_initialization(handle.initialized_rx.clone()).await {
                Ok(()) if created || !handle.command_tx.is_closed() => {
                    return Ok(self.local_caches.clone());
                }
                Ok(()) => {
                    self.remove_chain_handle(&handle).await;
                }
                Err(err) => {
                    self.remove_chain_handle(&handle).await;
                    if created {
                        return Err(err);
                    }
                }
            }
        }
    }

    pub(crate) async fn retry_chain(
        &self,
        chain_id: u64,
    ) -> Result<PoiCacheRetryHandle, PoiCacheServiceError> {
        self.retry_chain_with_scope(chain_id, PoiCacheSyncScope::FULL)
            .await
    }

    pub(crate) async fn retry_chain_events(
        &self,
        chain_id: u64,
    ) -> Result<PoiCacheRetryHandle, PoiCacheServiceError> {
        self.retry_chain_with_scope(chain_id, PoiCacheSyncScope::EVENTS)
            .await
    }

    async fn retry_chain_with_scope(
        &self,
        chain_id: u64,
        scope: PoiCacheSyncScope,
    ) -> Result<PoiCacheRetryHandle, PoiCacheServiceError> {
        self.ensure_chain_id(chain_id)?;
        match self.local_caches(chain_id).await {
            Ok(Some(_)) => {}
            Ok(None) | Err(PoiCacheServiceError::CoordinatorStopped) => {
                self.start_chain(chain_id).await?;
            }
            Err(error) => return Err(error),
        }
        let public_cache_reset_admission = self.runtime.public_cache_reset_gate.read().await;
        let handle = self
            .coordinator
            .lock()
            .await
            .as_ref()
            .cloned()
            .ok_or(PoiCacheServiceError::CoordinatorStopped)?;
        let (admission, admitted) = oneshot::channel();
        if handle
            .command_tx
            .send(ChainPoiCacheCommand::Retry { scope, admission })
            .await
            .is_err()
        {
            self.remove_chain_handle(&handle).await;
            return Err(PoiCacheServiceError::CoordinatorStopped);
        }
        drop(public_cache_reset_admission);
        if let Ok(result) = admitted.await {
            result
        } else {
            self.remove_chain_handle(&handle).await;
            Err(PoiCacheServiceError::CoordinatorStopped)
        }
    }

    pub(crate) async fn update_wallet_demand(
        &self,
        actor_id: u64,
        observation: &crate::types::WalletObservation,
    ) {
        let demand = poi_cache_demand(observation, &self.active_list_keys);
        let handle = self.coordinator.lock().await.as_ref().cloned();
        let Some(handle) = handle else {
            return;
        };
        let _ = handle
            .command_tx
            .send(ChainPoiCacheCommand::UpdateDemand { actor_id, demand })
            .await;
    }

    pub(crate) async fn clear_wallet_demand(&self, actor_id: u64) {
        let handle = self.coordinator.lock().await.as_ref().cloned();
        let Some(handle) = handle else {
            return;
        };
        let _ = handle
            .command_tx
            .send(ChainPoiCacheCommand::UpdateDemand {
                actor_id,
                demand: PoiCacheDemand::default(),
            })
            .await;
    }

    pub(crate) async fn local_caches(
        &self,
        chain_id: u64,
    ) -> Result<Option<LocalPoiCaches>, PoiCacheServiceError> {
        self.ensure_chain_id(chain_id)?;
        let handle = {
            let coordinator = self.coordinator.lock().await;
            let Some(handle) = coordinator.as_ref().cloned() else {
                return Ok(None);
            };
            handle
        };
        if wait_for_chain_poi_cache_initialization(handle.initialized_rx.clone())
            .await
            .is_err()
            || handle.command_tx.is_closed()
        {
            self.remove_chain_handle(&handle).await;
            return Err(PoiCacheServiceError::CoordinatorStopped);
        }
        Ok(Some(self.local_caches.clone()))
    }

    async fn remove_chain_handle(&self, expected: &ChainPoiCacheHandle) {
        let mut coordinator = self.coordinator.lock().await;
        let remove = coordinator
            .as_ref()
            .is_some_and(|current| current.command_tx.same_channel(&expected.command_tx));
        if remove {
            coordinator.take();
        }
    }

    const fn ensure_chain_id(&self, chain_id: u64) -> Result<(), PoiCacheServiceError> {
        if chain_id == self.chain_id {
            Ok(())
        } else {
            Err(PoiCacheServiceError::ChainMismatch {
                expected: self.chain_id,
                actual: chain_id,
            })
        }
    }

    pub(crate) async fn quiesce_for_public_cache_reset(&self) -> PoiPublicCacheResetLease {
        let admission = Arc::clone(&self.runtime.public_cache_reset_gate)
            .write_owned()
            .await;
        let lease = PoiPublicCacheResetLease {
            admission: Some(admission),
            release: CancellationToken::new(),
        };
        let release = lease.release.clone();
        let handle = self.coordinator.lock().await.as_ref().cloned();
        if let Some(handle) = handle {
            let (response, quiesced) = oneshot::channel();
            let response = handle
                .command_tx
                .send(ChainPoiCacheCommand::QuiesceForPublicCacheReset {
                    lease: release,
                    response,
                })
                .await
                .map(|()| quiesced);
            let quiesced = match response {
                Ok(response) => response.await.is_ok(),
                Err(_) => false,
            };
            if !quiesced {
                self.remove_chain_handle(&handle).await;
            }
        }
        lease
    }

    pub(crate) async fn shutdown(&self) {
        self.begin_shutdown();
        let stopped = self
            .coordinator
            .lock()
            .await
            .as_ref()
            .map(|handle| handle.stopped_rx.clone());
        if let Some(mut receiver) = stopped {
            while !*receiver.borrow() {
                if receiver.changed().await.is_err() {
                    break;
                }
            }
        }
    }

    pub(crate) fn begin_shutdown(&self) {
        let mut publication = self
            .runtime
            .publication_fence
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        publication.shutdown = true;
        self.cancel.cancel();
    }
}

pub(crate) struct PoiCacheRetryHandle {
    attempt_id: PoiArtifactCacheAttemptId,
    completion: oneshot::Receiver<Result<(), PoiCacheServiceError>>,
}

impl PoiCacheRetryHandle {
    pub(crate) const fn attempt_id(&self) -> PoiArtifactCacheAttemptId {
        self.attempt_id
    }

    pub(crate) async fn wait(self) -> Result<(), PoiCacheServiceError> {
        self.completion
            .await
            .unwrap_or(Err(PoiCacheServiceError::CoordinatorStopped))
    }
}

async fn wait_for_chain_poi_cache_initialization(
    mut initialized_rx: watch::Receiver<bool>,
) -> Result<(), PoiCacheServiceError> {
    while !*initialized_rx.borrow() {
        if initialized_rx.changed().await.is_err() {
            return Err(PoiCacheServiceError::CoordinatorStopped);
        }
    }
    Ok(())
}

fn default_poi_rpc_url() -> SensitiveUrl {
    reqwest::Url::parse(DEFAULT_WALLET_POI_RPC_URL)
        .expect("default POI RPC URL is valid")
        .into()
}

impl Drop for PoiCacheService {
    fn drop(&mut self) {
        self.begin_shutdown();
    }
}

struct ChainPoiCacheJobEvent {
    progress: PoiArtifactCacheProgress,
}

/// Acquires the chain POI corpus write fence, warning when readers held it unusually long.
async fn acquire_corpus_write_fence(task: &ChainPoiCacheCoordinator) -> OwnedRwLockWriteGuard<()> {
    let started = Instant::now();
    let revision_fence = task.local_caches.revision_write_fence().await;
    let waited = started.elapsed();
    if waited >= POI_CORPUS_WRITE_FENCE_SLOW_AFTER {
        warn!(
            chain_id = task.chain_id,
            wait_ms = waited.as_millis(),
            "POI corpus write fence acquisition was slow"
        );
    }
    revision_fence
}

#[cfg(test)]
impl PoiCacheService {
    pub(crate) fn new(
        db: Arc<DbStore>,
        artifact_config: PoiArtifactSourceConfig,
        http_client: Option<reqwest::Client>,
    ) -> Result<Self, local_db::DbError> {
        let poi_artifact_persistence = PoiArtifactPersistenceHandle::new(
            Arc::clone(&db),
            Arc::new(tokio::sync::Mutex::new(())),
        );
        Self::new_with_persistence(
            db,
            1,
            artifact_config,
            http_client,
            poi_artifact_persistence,
        )
    }

    fn with_active_list_keys(mut self, active_list_keys: Vec<FixedBytes<32>>) -> Self {
        self.active_list_keys = active_list_keys;
        self
    }
}

#[cfg(test)]
mod tests;
