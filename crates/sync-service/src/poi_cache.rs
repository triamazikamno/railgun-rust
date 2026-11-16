use std::collections::BTreeMap;
use std::ops::ControlFlow;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use alloy::hex;
use alloy::primitives::FixedBytes;
use broadcaster_core::transact::DEFAULT_TXID_VERSION;
use futures::FutureExt;
use futures::future::BoxFuture;
use local_db::{DbStore, PoiArtifactCacheRecord, PoiCorpusJournalHeadRecord};
use poi::SensitiveUrl;
use poi::cache::{
    POI_EVENTS_PAGE_SIZE, POI_MERKLETREE_LEAVES_PAGE_SIZE, PoiCache, PoiCacheError,
    PoiCacheIdentity, PoiCacheJournalDelta, PoiCacheSyncOutcome,
};
use poi::poi::{
    BlockedShield, DEFAULT_WALLET_POI_RPC_URL, PoiRpcClient, default_active_poi_list_keys,
};
use railgun_wallet::UtxoCommitmentKind;
use tokio::sync::{Mutex, OwnedRwLockWriteGuard, RwLock, mpsc, oneshot, watch};
use tokio::time::Instant as TokioInstant;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, info, warn};

use crate::chain::PoiArtifactPersistenceHandle;
use crate::poi_artifacts::{
    ExpectedPoiCorpusBase, ObservedManifest, PersistedPoiArtifactCache, PoiArtifactError,
    PoiArtifactIngestor, PoiCorpusCompactionResult, PreparedIngestion,
    load_persisted_cache_candidate_for_publisher, load_persisted_cache_for_publisher,
    load_poi_rpc_health, record_poi_rpc_success,
};
use crate::types::{
    LocalPoiCaches, PoiArtifactCacheAttemptId, PoiArtifactCacheGraphProgress,
    PoiArtifactCacheListProgress, PoiArtifactCachePhase, PoiArtifactCacheProgress,
    PoiArtifactSourceConfig, WalletObservation, WalletReadiness,
};
use crate::wallet::wallet_poi_status_client;

const EVM_CHAIN_TYPE: u8 = 0;
const POI_CACHE_EVENT_ACTIVE_INTERVAL: Duration = Duration::from_secs(15);
const POI_CACHE_EVENT_IDLE_INTERVAL: Duration = Duration::from_mins(5);
const POI_CACHE_BLOCKED_ACTIVE_INTERVAL: Duration = Duration::from_mins(1);
const POI_CACHE_BLOCKED_IDLE_INTERVAL: Duration = Duration::from_mins(30);
const POI_CACHE_FAILURE_RETRY_INTERVAL: Duration = Duration::from_mins(1);
const POI_ARTIFACT_RPC_FAILURE_THRESHOLD: u32 = 3;
const POI_ARTIFACT_RPC_STALE_AFTER: Duration = Duration::from_mins(5);
const POI_CACHE_COMMAND_CAPACITY: usize = 16;
const POI_CORPUS_WRITE_FENCE_SLOW_AFTER: Duration = Duration::from_secs(3);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PoiCacheDemand {
    events: bool,
    blocked_shields: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PoiCacheSyncScope {
    events: bool,
    blocked_shields: bool,
}

impl PoiCacheSyncScope {
    const FULL: Self = Self {
        events: true,
        blocked_shields: true,
    };

    const EVENTS: Self = Self {
        events: true,
        blocked_shields: false,
    };

    const BLOCKED_SHIELDS: Self = Self {
        events: false,
        blocked_shields: true,
    };

    const fn union(self, other: Self) -> Self {
        Self {
            events: self.events || other.events,
            blocked_shields: self.blocked_shields || other.blocked_shields,
        }
    }
}

#[derive(Clone, Copy)]
struct PoiCacheMaintenanceSchedule {
    demand_actor_id: Option<u64>,
    demand: PoiCacheDemand,
    event_deadline: TokioInstant,
    blocked_shields_deadline: TokioInstant,
    event_last_success: Option<TokioInstant>,
    blocked_shields_last_success: Option<TokioInstant>,
}

impl PoiCacheMaintenanceSchedule {
    fn new(now: TokioInstant) -> Self {
        Self {
            demand_actor_id: None,
            demand: PoiCacheDemand::default(),
            event_deadline: now,
            blocked_shields_deadline: now,
            event_last_success: None,
            blocked_shields_last_success: None,
        }
    }

    fn update_demand(&mut self, demand: PoiCacheDemand, now: TokioInstant) {
        if !self.demand.events && demand.events {
            self.event_deadline = now;
        } else if self.demand.events && !demand.events {
            self.event_deadline = self
                .event_last_success
                .map_or(now, |last| last + POI_CACHE_EVENT_IDLE_INTERVAL);
        }
        if !self.demand.blocked_shields && demand.blocked_shields {
            self.blocked_shields_deadline = now;
        } else if self.demand.blocked_shields && !demand.blocked_shields {
            self.blocked_shields_deadline = self
                .blocked_shields_last_success
                .map_or(now, |last| last + POI_CACHE_BLOCKED_IDLE_INTERVAL);
        }
        self.demand = demand;
    }

    fn due_scope(&self, now: TokioInstant) -> Option<PoiCacheSyncScope> {
        let events = now >= self.event_deadline;
        let blocked_shields = now >= self.blocked_shields_deadline;
        let scope = match (events, blocked_shields) {
            (true, true) => PoiCacheSyncScope::FULL,
            (true, false) => PoiCacheSyncScope::EVENTS,
            (false, true) => PoiCacheSyncScope::BLOCKED_SHIELDS,
            (false, false) => return None,
        };
        Some(scope)
    }

    fn next_deadline(&self) -> TokioInstant {
        self.event_deadline.min(self.blocked_shields_deadline)
    }

    fn record_success(&mut self, scope: PoiCacheSyncScope, completed_at: TokioInstant) {
        if scope.events {
            self.event_last_success = Some(completed_at);
            self.event_deadline = completed_at
                + if self.demand.events {
                    POI_CACHE_EVENT_ACTIVE_INTERVAL
                } else {
                    POI_CACHE_EVENT_IDLE_INTERVAL
                };
        }
        if scope.blocked_shields {
            self.blocked_shields_last_success = Some(completed_at);
            self.blocked_shields_deadline = completed_at
                + if self.demand.blocked_shields {
                    POI_CACHE_BLOCKED_ACTIVE_INTERVAL
                } else {
                    POI_CACHE_BLOCKED_IDLE_INTERVAL
                };
        }
    }

    fn record_failure(&mut self, scope: PoiCacheSyncScope, now: TokioInstant) {
        if scope.events {
            self.event_deadline = now + POI_CACHE_FAILURE_RETRY_INTERVAL;
        }
        if scope.blocked_shields {
            self.blocked_shields_deadline = now + POI_CACHE_FAILURE_RETRY_INTERVAL;
        }
    }
}

fn apply_poi_cache_demand_update(
    schedule: &mut PoiCacheMaintenanceSchedule,
    actor_id: u64,
    demand: PoiCacheDemand,
    now: TokioInstant,
) -> bool {
    if schedule
        .demand_actor_id
        .is_some_and(|current| actor_id < current)
    {
        return false;
    }
    schedule.demand_actor_id = Some(actor_id);
    schedule.update_demand(demand, now);
    true
}

fn effective_poi_cache_scope(
    scope: PoiCacheSyncScope,
    baseline: &BTreeMap<FixedBytes<32>, PoiCache>,
    active_list_keys: &[FixedBytes<32>],
) -> PoiCacheSyncScope {
    if scope.events
        && active_list_keys.iter().any(|list_key| {
            baseline
                .get(list_key)
                .is_none_or(|cache| !cache.progress().blocked_shields_synced)
        })
    {
        PoiCacheSyncScope::FULL
    } else {
        scope
    }
}

fn replacement_poi_cache_scope(
    requested: PoiCacheSyncScope,
    active: Option<&ActivePoiCacheAttempt>,
) -> PoiCacheSyncScope {
    requested.union(active.map_or(
        PoiCacheSyncScope {
            events: false,
            blocked_shields: false,
        },
        |attempt| attempt.scope,
    ))
}

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

#[allow(clippy::too_many_arguments)]
const fn new_poi_artifact_cache_progress(
    attempt_id: PoiArtifactCacheAttemptId,
    generation: u64,
    chain_id: u64,
    phase: PoiArtifactCachePhase,
    completed_lists: usize,
    total_lists: usize,
    current_list_key: Option<FixedBytes<32>>,
    current_event_index: Option<u64>,
    target_event_index: Option<u64>,
    list_progress: Vec<PoiArtifactCacheListProgress>,
    graph: PoiArtifactCacheGraphProgress,
    ready_for_wallet_checks: bool,
    last_error: Option<String>,
) -> PoiArtifactCacheProgress {
    PoiArtifactCacheProgress {
        attempt_id,
        generation,
        chain_id,
        phase,
        completed_lists,
        total_lists,
        current_list_key,
        current_event_index,
        target_event_index,
        list_progress,
        graph,
        ready_for_wallet_checks,
        last_error,
    }
}

fn send_poi_artifact_cache_progress(
    progress_tx: &watch::Sender<BTreeMap<u64, PoiArtifactCacheProgress>>,
    progress: PoiArtifactCacheProgress,
) {
    progress_tx.send_modify(|chains| {
        if chains.get(&progress.chain_id).is_some_and(|current| {
            current.attempt_id > progress.attempt_id
                || (current.attempt_id == progress.attempt_id
                    && current.generation != progress.generation)
        }) {
            return;
        }
        chains.insert(progress.chain_id, progress);
    });
}

fn send_poi_artifact_cache_progress_for_generation(
    progress_tx: &watch::Sender<BTreeMap<u64, PoiArtifactCacheProgress>>,
    generation: u64,
    progress: PoiArtifactCacheProgress,
) -> Result<(), PoiCacheServiceError> {
    if progress.generation != generation {
        return Err(PoiCacheServiceError::Refresh {
            reason: format!(
                "POI cache progress generation {} does not match service generation {generation}",
                progress.generation
            ),
        });
    }
    send_poi_artifact_cache_progress(progress_tx, progress);
    Ok(())
}

fn poi_cache_list_progress_for_keys(
    active_list_keys: &[FixedBytes<32>],
) -> Vec<PoiArtifactCacheListProgress> {
    active_list_keys
        .iter()
        .map(|list_key| PoiArtifactCacheListProgress {
            list_key: *list_key,
            current_event_index: None,
            target_event_index: None,
            ready_for_wallet_checks: false,
        })
        .collect()
}

const fn single_list_event_index(
    list_progress: &[PoiArtifactCacheListProgress],
) -> (Option<u64>, Option<u64>) {
    if let [progress] = list_progress {
        (progress.current_event_index, progress.target_event_index)
    } else {
        (None, None)
    }
}

fn list_progress_with_active_event(
    active_list_keys: &[FixedBytes<32>],
    baseline: &[PoiArtifactCacheListProgress],
    active_list_key: FixedBytes<32>,
    current_event_index: Option<u64>,
    target_event_index: Option<u64>,
) -> Vec<PoiArtifactCacheListProgress> {
    active_list_keys
        .iter()
        .map(|list_key| {
            let mut progress = baseline
                .iter()
                .find(|progress| progress.list_key == *list_key)
                .cloned()
                .unwrap_or(PoiArtifactCacheListProgress {
                    list_key: *list_key,
                    current_event_index: None,
                    target_event_index: None,
                    ready_for_wallet_checks: false,
                });
            if *list_key == active_list_key {
                progress.current_event_index = current_event_index;
                progress.target_event_index = target_event_index;
            }
            progress
        })
        .collect()
}

async fn emit_chain_poi_cache_ready_progress(
    progress_tx: &watch::Sender<BTreeMap<u64, PoiArtifactCacheProgress>>,
    chain_id: u64,
    local_caches: &LocalPoiCaches,
    active_list_keys: &[FixedBytes<32>],
    attempt_id: PoiArtifactCacheAttemptId,
    generation: u64,
    runtime: &PoiCacheServiceRuntime,
    cancel: &CancellationToken,
    initialized_tx: Option<&watch::Sender<bool>>,
) -> Result<(), PoiCacheServiceError> {
    let ready =
        chain_poi_caches_available_for_lists(chain_id, local_caches, active_list_keys).await;
    let completed = installed_chain_poi_cache_count(chain_id, local_caches, active_list_keys).await;
    let list_progress =
        chain_poi_cache_list_progress(chain_id, local_caches, active_list_keys).await;
    let (current_event_index, target_event_index) = single_list_event_index(&list_progress);
    let publication = runtime
        .publication_fence
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if publication.shutdown || cancel.is_cancelled() {
        return Err(PoiCacheServiceError::Shutdown { attempt_id });
    }
    send_poi_artifact_cache_progress_for_generation(
        progress_tx,
        generation,
        new_poi_artifact_cache_progress(
            attempt_id,
            generation,
            chain_id,
            PoiArtifactCachePhase::Ready,
            completed,
            active_list_keys.len(),
            None,
            current_event_index,
            target_event_index,
            list_progress,
            PoiArtifactCacheGraphProgress::default(),
            ready,
            None,
        ),
    )?;
    if let Some(initialized_tx) = initialized_tx {
        let _ = initialized_tx.send(true);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn publish_chain_poi_cache_ready_and_acknowledge_initialization(
    progress_tx: &watch::Sender<BTreeMap<u64, PoiArtifactCacheProgress>>,
    chain_id: u64,
    local_caches: &LocalPoiCaches,
    active_list_keys: &[FixedBytes<32>],
    attempt_id: PoiArtifactCacheAttemptId,
    generation: u64,
    runtime: &PoiCacheServiceRuntime,
    cancel: &CancellationToken,
    initialized_tx: watch::Sender<bool>,
) -> Result<(), PoiCacheServiceError> {
    emit_chain_poi_cache_ready_progress(
        progress_tx,
        chain_id,
        local_caches,
        active_list_keys,
        attempt_id,
        generation,
        runtime,
        cancel,
        Some(&initialized_tx),
    )
    .await?;
    Ok(())
}

impl Drop for PoiCacheService {
    fn drop(&mut self) {
        self.begin_shutdown();
    }
}

struct ActivePoiCacheAttempt {
    id: PoiArtifactCacheAttemptId,
    generation: u64,
    scope: PoiCacheSyncScope,
    cancel: CancellationToken,
    job: BoxFuture<'static, PreparedPoiCacheBatch>,
    retry_completion: Option<oneshot::Sender<Result<(), PoiCacheServiceError>>>,
}

struct PoiSourceHealth {
    consecutive_rpc_failures: u32,
    rpc_stale_at: Option<Instant>,
    observed_since: Instant,
    artifact_acceleration_needed: bool,
    force_rpc_probe: bool,
}

impl PoiSourceHealth {
    fn new(rpc_stale_at: Option<Instant>) -> Self {
        Self {
            consecutive_rpc_failures: 0,
            rpc_stale_at,
            observed_since: Instant::now(),
            artifact_acceleration_needed: false,
            force_rpc_probe: false,
        }
    }

    fn artifact_eligible(&self) -> bool {
        self.consecutive_rpc_failures >= POI_ARTIFACT_RPC_FAILURE_THRESHOLD
            || self.artifact_acceleration_needed
            || self.rpc_stale_at.map_or_else(
                || self.observed_since.elapsed() >= POI_ARTIFACT_RPC_STALE_AFTER,
                |stale_at| Instant::now() >= stale_at,
            )
    }

    fn rpc_recently_healthy(&self) -> bool {
        self.rpc_stale_at
            .is_some_and(|stale_at| Instant::now() < stale_at)
    }

    fn attempt_plan(&self, corpus_ready: bool) -> PoiListAttemptPlan {
        if !corpus_ready && !self.force_rpc_probe && !self.rpc_recently_healthy() {
            return PoiListAttemptPlan {
                use_artifact: true,
                artifact_after_rpc_failure: false,
            };
        }
        let force_rpc_probe = self.force_rpc_probe;
        PoiListAttemptPlan {
            use_artifact: !force_rpc_probe && self.artifact_eligible(),
            artifact_after_rpc_failure: !force_rpc_probe
                && self.consecutive_rpc_failures.saturating_add(1)
                    >= POI_ARTIFACT_RPC_FAILURE_THRESHOLD,
        }
    }

    fn record(&mut self, outcome: &PoiListSourceOutcome) {
        if let Some(rpc) = outcome.rpc {
            self.force_rpc_probe = false;
            match rpc {
                PoiRpcAttemptOutcome::Succeeded { backlog_large } => {
                    self.artifact_acceleration_needed = backlog_large;
                    self.consecutive_rpc_failures = 0;
                    let now = Instant::now();
                    self.rpc_stale_at = now.checked_add(POI_ARTIFACT_RPC_STALE_AFTER).or(Some(now));
                }
                PoiRpcAttemptOutcome::Failed => {
                    self.artifact_acceleration_needed = false;
                    self.consecutive_rpc_failures = self.consecutive_rpc_failures.saturating_add(1);
                }
            }
        }
        if outcome.artifact_succeeded {
            self.artifact_acceleration_needed = false;
            self.force_rpc_probe = true;
        }
    }
}

#[derive(Clone, Copy)]
struct PoiListAttemptPlan {
    use_artifact: bool,
    artifact_after_rpc_failure: bool,
}

#[derive(Clone, Copy)]
enum PoiRpcAttemptOutcome {
    Succeeded { backlog_large: bool },
    Failed,
}

struct PoiRpcSyncResult {
    outcome: PoiCacheSyncOutcome,
    candidate: Option<PoiRpcCandidate>,
}

struct PoiRpcCandidate {
    cache: PoiCache,
    delta: PoiCacheJournalDelta,
    blocked_shields: Option<Vec<BlockedShield>>,
}

#[derive(Clone, Copy)]
struct PoiListSourceOutcome {
    list_key: FixedBytes<32>,
    rpc: Option<PoiRpcAttemptOutcome>,
    artifact_succeeded: bool,
}

enum PreparedPoiCachePersistence {
    Artifact {
        prepared: Box<PreparedIngestion>,
    },
    PublicRpc {
        prepared: Box<PreparedPublicRpcPersistence>,
    },
}

struct PreparedPublicRpcPersistence {
    range_start_index: u64,
    expected_base: ExpectedPoiCorpusBase,
    starting_record: Option<PoiArtifactCacheRecord>,
    starting_head: Option<PoiCorpusJournalHeadRecord>,
    delta: PoiCacheJournalDelta,
    blocked_shields: Option<Vec<BlockedShield>>,
}

impl PreparedPoiCachePersistence {
    const fn artifact_manifest_sequence(&self) -> Option<u64> {
        match self {
            Self::Artifact { prepared } => Some(prepared.candidate.manifest_sequence()),
            Self::PublicRpc { .. } => None,
        }
    }
}

struct PreparedPoiCacheCandidate {
    list_key: FixedBytes<32>,
    cache: Option<PoiCache>,
    persistence: PreparedPoiCachePersistence,
}

struct PreparedPoiCacheBatch {
    candidates: Vec<PreparedPoiCacheCandidate>,
    source_outcomes: Vec<PoiListSourceOutcome>,
    actual_scope: PoiCacheSyncScope,
    result: Result<(), String>,
}

struct FinishedPoiCacheAttempt {
    result: Result<(), PoiCacheServiceError>,
    compactions: Vec<PoiCorpusCompactionRequest>,
}

#[derive(Default)]
struct PoiCorpusCompactionLane {
    pending: BTreeMap<FixedBytes<32>, PoiCorpusCompactionRequest>,
    active: Option<ActivePoiCorpusCompaction>,
}

struct ActivePoiCorpusCompaction {
    cancel: CancellationToken,
    job: BoxFuture<'static, PoiCorpusCompactionCompletion>,
}

struct PoiCorpusCompactionCompletion {
    list_key: FixedBytes<32>,
    expected_base: ExpectedPoiCorpusBase,
    result: Result<Option<PoiCorpusCompactionResult>, String>,
}

struct ChainPoiCacheJobEvent {
    progress: PoiArtifactCacheProgress,
}

fn spawn_chain_poi_cache_coordinator(
    task: ChainPoiCacheCoordinator,
    initialized_tx: watch::Sender<bool>,
    stopped_tx: watch::Sender<bool>,
) {
    let chain_id = task.chain_id;
    tokio::spawn(
        async move {
            run_chain_poi_cache_coordinator(task, initialized_tx).await;
            let _ = stopped_tx.send(true);
        }
        .instrument(tracing::info_span!("poi_artifact_cache", chain_id)),
    );
}

async fn run_chain_poi_cache_coordinator(
    mut task: ChainPoiCacheCoordinator,
    initialized_tx: watch::Sender<bool>,
) {
    let chain_id = task.chain_id;
    let generation = task.cache_generation;
    let startup_attempt_id = task.runtime.next_attempt_id();
    if !publish_persisted_cache_loading(&task, startup_attempt_id) {
        return;
    }
    preload_persisted_chain_poi_caches(&mut task, startup_attempt_id).await;
    if publish_chain_poi_cache_ready_and_acknowledge_initialization(
        &task.progress_tx,
        chain_id,
        &task.local_caches,
        &task.active_list_keys,
        startup_attempt_id,
        generation,
        task.runtime.as_ref(),
        &task.cancel,
        initialized_tx,
    )
    .await
    .is_err()
    {
        return;
    }
    let health = source_health_for_lists(
        task.db.as_ref(),
        chain_id,
        generation,
        &task.active_list_keys,
        &task.preloaded_caches,
    );
    let mut coordinator = ChainPoiCacheCoordinatorLoop {
        generation,
        health,
        active: None,
        public_cache_reset: None,
        compaction_lane: PoiCorpusCompactionLane::default(),
        maintenance: PoiCacheMaintenanceSchedule::new(TokioInstant::now()),
        task,
    };
    info!(
        chain_id,
        list_count = coordinator.task.active_list_keys.len(),
        "starting chain-owned POI cache coordinator"
    );
    coordinator.start_full_sync().await;
    coordinator.run().await;
    info!(chain_id, "chain-owned POI cache coordinator stopped");
}

/// Publishes the startup `LoadingPersisted` progress under the publication
/// fence; false once shutdown has begun or the coordinator is cancelled.
fn publish_persisted_cache_loading(
    task: &ChainPoiCacheCoordinator,
    attempt_id: PoiArtifactCacheAttemptId,
) -> bool {
    let publication = task
        .runtime
        .publication_fence
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if publication.shutdown || task.cancel.is_cancelled() {
        return false;
    }
    let _ = send_poi_artifact_cache_progress_for_generation(
        &task.progress_tx,
        task.cache_generation,
        new_poi_artifact_cache_progress(
            attempt_id,
            task.cache_generation,
            task.chain_id,
            PoiArtifactCachePhase::LoadingPersisted,
            0,
            task.active_list_keys.len(),
            None,
            None,
            None,
            poi_cache_list_progress_for_keys(&task.active_list_keys),
            PoiArtifactCacheGraphProgress::default(),
            false,
            None,
        ),
    );
    true
}

/// Loads the persisted caches into the coordinator and installs their journal
/// heads as the installed head anchors.
async fn preload_persisted_chain_poi_caches(
    task: &mut ChainPoiCacheCoordinator,
    startup_attempt_id: PoiArtifactCacheAttemptId,
) {
    let preload_started = Instant::now();
    let loaded = load_persisted_chain_poi_caches(
        task.db.as_ref(),
        task.chain_id,
        &task.active_list_keys,
        task.artifact_config.trusted_publisher_pubkey,
    );
    task.preloaded_caches =
        apply_loaded_persisted_chain_poi_caches(task, loaded, preload_started, startup_attempt_id)
            .await;
    let mut anchors = task
        .installed_head_anchors
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *anchors = task
        .preloaded_caches
        .iter()
        .filter_map(|(list_key, persisted)| {
            persisted.journal_head.clone().map(|head| (*list_key, head))
        })
        .collect();
}

/// A running chain POI cache coordinator and the state its loop carries between turns.
struct ChainPoiCacheCoordinatorLoop {
    generation: u64,
    health: BTreeMap<FixedBytes<32>, PoiSourceHealth>,
    active: Option<ActivePoiCacheAttempt>,
    public_cache_reset: Option<CancellationToken>,
    compaction_lane: PoiCorpusCompactionLane,
    maintenance: PoiCacheMaintenanceSchedule,
    // Declared last so that the loop state, including any compaction job, drops first.
    task: ChainPoiCacheCoordinator,
}

impl ChainPoiCacheCoordinatorLoop {
    /// Serves commands, attempt and compaction completions, maintenance and
    /// reset releases until cancelled or the command channel closes.
    async fn run(&mut self) {
        loop {
            tokio::select! {
                biased;
                () = self.task.cancel.cancelled() => {
                    cancel_active_attempt(&mut self.active, |attempt_id| {
                        PoiCacheServiceError::Shutdown { attempt_id }
                    });
                    cancel_poi_corpus_compaction_lane(&mut self.compaction_lane);
                    break;
                }
                command = self.task.command_rx.recv() => {
                    let Some(command) = command else {
                        cancel_active_attempt(&mut self.active, |attempt_id| {
                            PoiCacheServiceError::Shutdown { attempt_id }
                        });
                        break;
                    };
                    self.handle_command(command).await;
                }
                event = self.task.job_rx.recv() => {
                    let Some(event) = event else { continue };
                    publish_active_attempt_progress(&self.task, self.active.as_ref(), event);
                }
                completion = wait_for_active_attempt(&mut self.active) => {
                    self.finish_active_attempt(completion).await;
                }
                completion = wait_for_active_poi_corpus_compaction(&mut self.compaction_lane) => {
                    self.compaction_lane.active.take();
                    finish_background_poi_corpus_compaction(&self.task, self.generation, completion)
                        .await;
                    start_next_poi_corpus_compaction(
                        &self.task,
                        &mut self.compaction_lane,
                        self.generation,
                    );
                }
                () = tokio::time::sleep_until(self.maintenance.next_deadline()),
                    if self.active.is_none() && self.public_cache_reset.is_none() => {
                    self.start_due_maintenance().await;
                }
                () = wait_for_public_cache_reset_release(&mut self.public_cache_reset),
                    if self.active.is_none() => {
                    self.public_cache_reset = None;
                    self.start_full_sync().await;
                }
            }
        }
    }

    async fn start_attempt(
        &mut self,
        scope: PoiCacheSyncScope,
        retry_completion: Option<oneshot::Sender<Result<(), PoiCacheServiceError>>>,
    ) -> Result<PoiArtifactCacheAttemptId, PoiCacheServiceError> {
        start_chain_poi_cache_attempt(
            &mut self.task,
            &mut self.active,
            self.generation,
            &self.health,
            scope,
            retry_completion,
        )
        .await
    }

    /// Starts a full sync, recording a failure to start it.
    async fn start_full_sync(&mut self) {
        if self
            .start_attempt(PoiCacheSyncScope::FULL, None)
            .await
            .is_err()
        {
            self.maintenance
                .record_failure(PoiCacheSyncScope::FULL, TokioInstant::now());
        }
    }

    /// Starts the maintenance attempt that is due, recording a failure to start it.
    async fn start_due_maintenance(&mut self) {
        let now = TokioInstant::now();
        if let Some(scope) = self.maintenance.due_scope(now)
            && self.start_attempt(scope, None).await.is_err()
        {
            self.maintenance.record_failure(scope, now);
        }
    }

    async fn handle_command(&mut self, command: ChainPoiCacheCommand) {
        match command {
            ChainPoiCacheCommand::UpdateDemand { actor_id, demand } => {
                let _ = apply_poi_cache_demand_update(
                    &mut self.maintenance,
                    actor_id,
                    demand,
                    TokioInstant::now(),
                );
            }
            ChainPoiCacheCommand::Retry { scope, admission } => {
                self.admit_retry(scope, admission).await;
            }
            ChainPoiCacheCommand::QuiesceForPublicCacheReset { lease, response } => {
                self.public_cache_reset = Some(lease);
                cancel_active_attempt(&mut self.active, |attempt_id| {
                    PoiCacheServiceError::StaleAttempt { attempt_id }
                });
                cancel_poi_corpus_compaction_lane(&mut self.compaction_lane);
                let _ = response.send(());
            }
        }
    }

    /// Replaces the active attempt with a retry over `scope` and answers its admission.
    async fn admit_retry(
        &mut self,
        scope: PoiCacheSyncScope,
        admission: oneshot::Sender<Result<PoiCacheRetryHandle, PoiCacheServiceError>>,
    ) {
        clear_released_public_cache_reset(&mut self.public_cache_reset);
        if self.public_cache_reset.is_some()
            || self
                .task
                .runtime
                .public_cache_reset_gate
                .try_read()
                .is_err()
        {
            let _ = admission.send(Err(PoiCacheServiceError::CorpusResetInProgress));
            return;
        }
        let replacement_scope = replacement_poi_cache_scope(scope, self.active.as_ref());
        cancel_active_attempt(&mut self.active, |attempt_id| {
            PoiCacheServiceError::AttemptSuperseded { attempt_id }
        });
        let (completion, completed) = oneshot::channel();
        match self
            .start_attempt(replacement_scope, Some(completion))
            .await
        {
            Ok(attempt_id) => {
                let publication = self
                    .task
                    .runtime
                    .publication_fence
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if publication.shutdown || self.task.cancel.is_cancelled() {
                    drop(publication);
                    cancel_active_attempt(&mut self.active, |attempt_id| {
                        PoiCacheServiceError::Shutdown { attempt_id }
                    });
                    let _ = admission.send(Err(PoiCacheServiceError::Shutdown { attempt_id }));
                } else {
                    let _ = admission.send(Ok(PoiCacheRetryHandle {
                        attempt_id,
                        completion: completed,
                    }));
                }
            }
            Err(error) => {
                self.maintenance
                    .record_failure(replacement_scope, TokioInstant::now());
                let _ = admission.send(Err(error));
            }
        }
    }

    /// Installs the completed attempt's batch, records its source health and
    /// maintenance outcome, answers its retry, and queues its compactions.
    async fn finish_active_attempt(&mut self, completion: PreparedPoiCacheBatch) {
        let finished = self
            .active
            .take()
            .expect("completed POI cache attempt is active");
        let attempt_id = finished.id;
        let attempt_generation = finished.generation;
        let attempt_scope = finished.scope;
        let actual_scope = completion.actual_scope;
        let source_outcomes = completion.source_outcomes.clone();
        let FinishedPoiCacheAttempt {
            result: attempt_result,
            compactions,
        } = finish_chain_poi_cache_attempt(&self.task, attempt_id, attempt_generation, completion)
            .await;
        if !matches!(&attempt_result, Err(PoiCacheServiceError::Shutdown { .. })) {
            record_list_source_outcomes(&mut self.health, &source_outcomes);
        }
        if attempt_result.is_ok() {
            self.maintenance
                .record_success(actual_scope, TokioInstant::now());
        } else {
            self.maintenance
                .record_failure(attempt_scope, TokioInstant::now());
        }
        if let Some(response) = drop_completed_attempt(finished) {
            let publication = self
                .task
                .runtime
                .publication_fence
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let attempt_result = if publication.shutdown || self.task.cancel.is_cancelled() {
                Err(PoiCacheServiceError::Shutdown { attempt_id })
            } else {
                attempt_result
            };
            let _ = response.send(attempt_result);
        }
        enqueue_poi_corpus_compactions(&mut self.compaction_lane, compactions);
        start_next_poi_corpus_compaction(&self.task, &mut self.compaction_lane, self.generation);
    }
}

fn clear_released_public_cache_reset(reset: &mut Option<CancellationToken>) {
    if reset.as_ref().is_some_and(CancellationToken::is_cancelled) {
        *reset = None;
    }
}

async fn wait_for_public_cache_reset_release(reset: &mut Option<CancellationToken>) {
    match reset {
        Some(reset) => reset.cancelled().await,
        None => std::future::pending().await,
    }
}

fn publish_active_attempt_progress(
    task: &ChainPoiCacheCoordinator,
    active: Option<&ActivePoiCacheAttempt>,
    event: ChainPoiCacheJobEvent,
) {
    let progress = event.progress;
    let attempt_id = progress.attempt_id;
    let generation = progress.generation;
    if !active.is_some_and(|attempt| attempt.id == attempt_id && attempt.generation == generation) {
        return;
    }
    let publication = task
        .runtime
        .publication_fence
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !publication.shutdown && !task.cancel.is_cancelled() {
        let _ = send_poi_artifact_cache_progress_for_generation(
            &task.progress_tx,
            generation,
            progress,
        );
    }
}

fn publish_current_attempt_phase(
    task: &ChainPoiCacheCoordinator,
    attempt_id: PoiArtifactCacheAttemptId,
    generation: u64,
    phase: PoiArtifactCachePhase,
) {
    let publication = task
        .runtime
        .publication_fence
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if publication.shutdown || task.cancel.is_cancelled() {
        return;
    }
    let Some(mut progress) = task.progress_tx.borrow().get(&task.chain_id).cloned() else {
        return;
    };
    if progress.attempt_id != attempt_id || progress.generation != generation {
        return;
    }
    progress.phase = phase;
    let _ =
        send_poi_artifact_cache_progress_for_generation(&task.progress_tx, generation, progress);
}

fn cancel_active_attempt(
    active: &mut Option<ActivePoiCacheAttempt>,
    error: impl FnOnce(PoiArtifactCacheAttemptId) -> PoiCacheServiceError,
) {
    let Some(attempt) = active.take() else {
        return;
    };
    let ActivePoiCacheAttempt {
        id,
        generation: _,
        scope: _,
        cancel,
        job,
        retry_completion,
    } = attempt;
    cancel.cancel();
    drop(job);
    if let Some(response) = retry_completion {
        let _ = response.send(Err(error(id)));
    }
}

fn drop_completed_attempt(
    mut attempt: ActivePoiCacheAttempt,
) -> Option<oneshot::Sender<Result<(), PoiCacheServiceError>>> {
    let retry_completion = attempt.retry_completion.take();
    attempt.cancel.cancel();
    drop(attempt);
    retry_completion
}

async fn wait_for_active_attempt(
    active: &mut Option<ActivePoiCacheAttempt>,
) -> PreparedPoiCacheBatch {
    match active {
        Some(attempt) => (&mut attempt.job).await,
        None => std::future::pending().await,
    }
}

async fn start_chain_poi_cache_attempt(
    task: &mut ChainPoiCacheCoordinator,
    active: &mut Option<ActivePoiCacheAttempt>,
    generation: u64,
    health: &BTreeMap<FixedBytes<32>, PoiSourceHealth>,
    scope: PoiCacheSyncScope,
    retry_completion: Option<oneshot::Sender<Result<(), PoiCacheServiceError>>>,
) -> Result<PoiArtifactCacheAttemptId, PoiCacheServiceError> {
    let Ok(_public_cache_reset_admission) = task.runtime.public_cache_reset_gate.try_read() else {
        return Err(PoiCacheServiceError::CorpusResetInProgress);
    };
    let attempt_id = task.runtime.next_attempt_id();
    let baseline = task.local_caches.read().await.clone();
    let scope = effective_poi_cache_scope(scope, &baseline, &task.active_list_keys);
    let ready = cache_map_available_for_lists(task.chain_id, &baseline, &task.active_list_keys);
    let completed = task
        .active_list_keys
        .iter()
        .filter(|list_key| cache_map_available_for_list(task.chain_id, &baseline, **list_key))
        .count();
    let source_plans = task
        .active_list_keys
        .iter()
        .map(|list_key| {
            let corpus_ready = cache_map_available_for_list(task.chain_id, &baseline, *list_key);
            let plan = health.get(list_key).map_or_else(
                || PoiSourceHealth::new(None).attempt_plan(corpus_ready),
                |health| health.attempt_plan(corpus_ready),
            );
            let plan = if scope.events {
                plan
            } else {
                PoiListAttemptPlan {
                    use_artifact: false,
                    artifact_after_rpc_failure: false,
                }
            };
            (*list_key, plan)
        })
        .collect::<BTreeMap<_, _>>();
    let use_artifact = scope.events && source_plans.values().any(|plan| plan.use_artifact);
    let baseline_list_progress =
        cache_map_list_progress(task.chain_id, &baseline, &task.active_list_keys);
    let (current_event_index, target_event_index) =
        single_list_event_index(&baseline_list_progress);
    let start_progress = new_poi_artifact_cache_progress(
        attempt_id,
        generation,
        task.chain_id,
        if use_artifact {
            PoiArtifactCachePhase::ResolvingManifest
        } else {
            PoiArtifactCachePhase::LiveTailing
        },
        completed,
        task.active_list_keys.len(),
        None,
        current_event_index,
        target_event_index,
        baseline_list_progress,
        PoiArtifactCacheGraphProgress::default(),
        ready,
        None,
    );

    let attempt_cancel = task.cancel.child_token();
    let job = PoiCacheCandidateJob {
        db: Arc::clone(&task.db),
        http_client: task.http_client.clone(),
        poi_rpc_url: task.poi_rpc_url.clone(),
        artifact_config: task.artifact_config.clone(),
        chain_id: task.chain_id,
        active_list_keys: task.active_list_keys.clone(),
        baseline,
        installed_head_anchors: task
            .installed_head_anchors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone(),
        preloaded_caches: std::mem::take(&mut task.preloaded_caches),
        attempt_id,
        generation,
        ready,
        source_plans,
        scope,
        event_tx: task.job_tx.clone(),
        cancel: attempt_cancel.clone(),
        poi_artifact_persistence: task.poi_artifact_persistence.clone(),
    };
    let job = produce_chain_poi_cache_candidates(job)
        .instrument(tracing::info_span!(
            "poi_cache_candidate",
            %attempt_id,
            generation
        ))
        .boxed();
    *active = Some(ActivePoiCacheAttempt {
        id: attempt_id,
        generation,
        scope,
        cancel: attempt_cancel,
        job,
        retry_completion,
    });
    let publication = task
        .runtime
        .publication_fence
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if publication.shutdown || task.cancel.is_cancelled() {
        drop(publication);
        cancel_active_attempt(active, |attempt_id| PoiCacheServiceError::Shutdown {
            attempt_id,
        });
        return Err(PoiCacheServiceError::Shutdown { attempt_id });
    }
    if let Err(error) = send_poi_artifact_cache_progress_for_generation(
        &task.progress_tx,
        generation,
        start_progress,
    ) {
        drop(publication);
        cancel_active_attempt(active, |attempt_id| PoiCacheServiceError::StaleAttempt {
            attempt_id,
        });
        return Err(error);
    }
    drop(publication);
    Ok(attempt_id)
}

struct PoiCacheCandidateJob {
    db: Arc<DbStore>,
    http_client: Option<reqwest::Client>,
    poi_rpc_url: SensitiveUrl,
    artifact_config: PoiArtifactSourceConfig,
    chain_id: u64,
    active_list_keys: Vec<FixedBytes<32>>,
    baseline: BTreeMap<FixedBytes<32>, PoiCache>,
    installed_head_anchors: BTreeMap<FixedBytes<32>, PoiCorpusJournalHeadRecord>,
    preloaded_caches: BTreeMap<FixedBytes<32>, PersistedPoiArtifactCache>,
    attempt_id: PoiArtifactCacheAttemptId,
    generation: u64,
    ready: bool,
    source_plans: BTreeMap<FixedBytes<32>, PoiListAttemptPlan>,
    scope: PoiCacheSyncScope,
    event_tx: mpsc::UnboundedSender<ChainPoiCacheJobEvent>,
    cancel: CancellationToken,
    poi_artifact_persistence: PoiArtifactPersistenceHandle,
}

impl PoiCacheCandidateJob {
    /// Takes the list's installed and preloaded caches out of the job and
    /// returns its persisted cache with the corpus base it expects, loading
    /// the stored candidate when none was preloaded.
    fn take_persisted_cache(
        &mut self,
        list_key: FixedBytes<32>,
        identity: &PoiCacheIdentity,
    ) -> Result<(Option<PersistedPoiArtifactCache>, ExpectedPoiCorpusBase), PoiArtifactError> {
        let installed_cache = self.baseline.remove(&list_key);
        match self.preloaded_caches.remove(&list_key) {
            Some(persisted) => {
                let expected = persisted.expected_base();
                Ok((Some(persisted), expected))
            }
            None => load_persisted_cache_candidate_for_publisher(
                self.db.as_ref(),
                identity,
                self.artifact_config.trusted_publisher_pubkey,
                installed_cache,
                self.installed_head_anchors.get(&list_key),
            ),
        }
    }
}

async fn produce_chain_poi_cache_candidates(job: PoiCacheCandidateJob) -> PreparedPoiCacheBatch {
    let mut producer = PoiCacheCandidateProducer::new(job);
    let list_keys = producer.job.active_list_keys.clone();
    for (list_index, list_key) in list_keys.into_iter().enumerate() {
        let Some((plan, artifact, public_range)) = producer.list_start(list_index, list_key) else {
            continue;
        };
        let step = if producer.job.scope.events && plan.use_artifact {
            producer.artifact_first(artifact, public_range).await
        } else {
            producer.range_first(plan, artifact, public_range).await
        };
        if step.is_break() {
            break;
        }
    }
    producer.finish()
}

/// One list's artifact candidate inputs, with the list's position in the attempt.
struct ArtifactCandidateRequest {
    list_index: usize,
    list_key: FixedBytes<32>,
    identity: PoiCacheIdentity,
    persisted: Option<PersistedPoiArtifactCache>,
    expected_base: ExpectedPoiCorpusBase,
}

/// The cache one list's public-range catch-up starts from, and what its
/// candidate persists against.
struct PublicRangeStart {
    cache: PoiCache,
    range_start_index: u64,
    expected_base: ExpectedPoiCorpusBase,
    starting_record: Option<PoiArtifactCacheRecord>,
    starting_head: Option<PoiCorpusJournalHeadRecord>,
}

/// A candidate job in progress: its clients and the batch built so far.
struct PoiCacheCandidateProducer {
    job: PoiCacheCandidateJob,
    client: reqwest::Client,
    rpc_client: PoiRpcClient,
    candidates: Vec<PreparedPoiCacheCandidate>,
    source_outcomes: Vec<PoiListSourceOutcome>,
    errors: Vec<String>,
    observed_manifest: Option<ObservedManifest>,
    actual_scope: PoiCacheSyncScope,
}

impl PoiCacheCandidateProducer {
    fn new(job: PoiCacheCandidateJob) -> Self {
        let client = job.http_client.clone().unwrap_or_default();
        let rpc_client = wallet_poi_status_client(&job.poi_rpc_url, job.http_client.as_ref());
        Self {
            client,
            rpc_client,
            candidates: Vec::with_capacity(job.active_list_keys.len()),
            source_outcomes: Vec::with_capacity(job.active_list_keys.len()),
            errors: Vec::new(),
            observed_manifest: None,
            actual_scope: job.scope,
            job,
        }
    }

    /// The list's source plan and starting points, taking its installed and
    /// preloaded caches out of the job. `None`, with the error recorded, when
    /// its persisted cache fails to load.
    fn list_start(
        &mut self,
        list_index: usize,
        list_key: FixedBytes<32>,
    ) -> Option<(
        PoiListAttemptPlan,
        ArtifactCandidateRequest,
        PublicRangeStart,
    )> {
        let plan = self
            .job
            .source_plans
            .get(&list_key)
            .copied()
            .expect("active POI list has a source plan");
        let identity = PoiCacheIdentity::new(
            EVM_CHAIN_TYPE,
            self.job.chain_id,
            DEFAULT_TXID_VERSION,
            list_key,
        );
        let (persisted, expected_base) = match self.job.take_persisted_cache(list_key, &identity) {
            Ok(persisted) => persisted,
            Err(err) => {
                self.errors.push(err.to_string());
                return None;
            }
        };
        let starting_record = persisted
            .as_ref()
            .map(PersistedPoiArtifactCache::metadata_only);
        let starting_head = persisted
            .as_ref()
            .and_then(|persisted| persisted.journal_head.clone());
        let (artifact_starting, baseline_cache) =
            if plan.use_artifact || plan.artifact_after_rpc_failure {
                let baseline_cache = persisted.as_ref().map_or_else(
                    || PoiCache::new(identity.clone()),
                    |persisted| persisted.cache.clone(),
                );
                (persisted, baseline_cache)
            } else {
                (
                    None,
                    persisted.map_or_else(
                        || PoiCache::new(identity.clone()),
                        |persisted| persisted.cache,
                    ),
                )
            };
        let public_range = PublicRangeStart {
            range_start_index: baseline_cache.progress().next_event_index,
            cache: baseline_cache,
            expected_base,
            starting_record,
            starting_head,
        };
        let artifact = ArtifactCandidateRequest {
            list_index,
            list_key,
            identity,
            persisted: artifact_starting,
            expected_base,
        };
        Some((plan, artifact, public_range))
    }

    /// Prepares the list from the artifact, falling back to the public range
    /// when the artifact fails for a reason other than cancellation.
    async fn artifact_first(
        &mut self,
        artifact: ArtifactCandidateRequest,
        public_range: PublicRangeStart,
    ) -> ControlFlow<()> {
        let list_key = artifact.list_key;
        match Box::pin(prepare_artifact_candidate(
            &self.job,
            &self.client,
            artifact,
            &mut self.observed_manifest,
        ))
        .await
        {
            Ok(candidate) => self.record_artifact(list_key, candidate, None),
            Err(artifact_error) if self.artifact_cancelled(&artifact_error) => {
                self.errors.push(artifact_error.to_string());
                return ControlFlow::Break(());
            }
            Err(artifact_error) => {
                warn!(chain_id = self.job.chain_id, list_key = %hex::encode(list_key), %artifact_error, "artifact candidate failed; trying public range fallback");
                if let Err(rpc_error) = self.catch_up_public_range(list_key, public_range).await {
                    let rpc_error = poi_cache_error_diagnostic(&rpc_error);
                    self.record_sources_failed(
                        list_key,
                        format!(
                            "artifact refresh failed: {artifact_error}; public range catch-up failed: {rpc_error}"
                        ),
                    );
                }
            }
        }
        ControlFlow::Continue(())
    }

    /// Catches the list up over the public range, falling back to the
    /// artifact when the range fails and the plan allows it.
    async fn range_first(
        &mut self,
        plan: PoiListAttemptPlan,
        artifact: ArtifactCandidateRequest,
        public_range: PublicRangeStart,
    ) -> ControlFlow<()> {
        let list_key = artifact.list_key;
        emit_candidate_progress(
            &self.job,
            artifact.list_index,
            list_key,
            PoiArtifactCachePhase::LiveTailing,
            public_range
                .cache
                .progress()
                .next_event_index
                .checked_sub(1),
            None,
        );
        let Err(rpc_error) = self.catch_up_public_range(list_key, public_range).await else {
            return ControlFlow::Continue(());
        };
        let rpc_error = poi_cache_error_diagnostic(&rpc_error);
        if !plan.artifact_after_rpc_failure {
            self.record_sources_failed(
                list_key,
                format!("public range catch-up failed: {rpc_error}"),
            );
            return ControlFlow::Continue(());
        }
        match Box::pin(prepare_artifact_candidate(
            &self.job,
            &self.client,
            artifact,
            &mut self.observed_manifest,
        ))
        .await
        {
            Ok(candidate) => {
                self.record_artifact(list_key, candidate, Some(PoiRpcAttemptOutcome::Failed));
            }
            Err(artifact_error) if self.artifact_cancelled(&artifact_error) => {
                self.errors.push(artifact_error.to_string());
                return ControlFlow::Break(());
            }
            Err(artifact_error) => self.record_sources_failed(
                list_key,
                format!(
                    "public range catch-up failed: {rpc_error}; artifact refresh failed: {artifact_error}"
                ),
            ),
        }
        ControlFlow::Continue(())
    }

    /// Runs the list's public-range catch-up and records its success; a
    /// failure is returned unrecorded.
    async fn catch_up_public_range(
        &mut self,
        list_key: FixedBytes<32>,
        start: PublicRangeStart,
    ) -> Result<(), PoiCacheError> {
        let result =
            public_rpc_candidate_cache(&self.rpc_client, start.cache, self.job.scope).await?;
        self.source_outcomes.push(PoiListSourceOutcome {
            list_key,
            rpc: Some(PoiRpcAttemptOutcome::Succeeded {
                backlog_large: result.outcome.event_page_budget_exhausted,
            }),
            artifact_succeeded: false,
        });
        if let Some(candidate) = result.candidate {
            self.candidates.push(PreparedPoiCacheCandidate {
                list_key,
                cache: Some(candidate.cache),
                persistence: PreparedPoiCachePersistence::PublicRpc {
                    prepared: Box::new(PreparedPublicRpcPersistence {
                        range_start_index: start.range_start_index,
                        expected_base: start.expected_base,
                        starting_record: start.starting_record,
                        starting_head: start.starting_head,
                        delta: candidate.delta,
                        blocked_shields: candidate.blocked_shields,
                    }),
                },
            });
        }
        Ok(())
    }

    /// Records an artifact success after `rpc`, the public-range outcome that preceded it.
    fn record_artifact(
        &mut self,
        list_key: FixedBytes<32>,
        candidate: Option<PreparedPoiCacheCandidate>,
        rpc: Option<PoiRpcAttemptOutcome>,
    ) {
        self.actual_scope = self.actual_scope.union(PoiCacheSyncScope::FULL);
        if let Some(candidate) = candidate {
            self.candidates.push(candidate);
        }
        self.source_outcomes.push(PoiListSourceOutcome {
            list_key,
            rpc,
            artifact_succeeded: true,
        });
    }

    /// Records that every source tried for the list failed.
    fn record_sources_failed(&mut self, list_key: FixedBytes<32>, error: String) {
        self.source_outcomes.push(PoiListSourceOutcome {
            list_key,
            rpc: Some(PoiRpcAttemptOutcome::Failed),
            artifact_succeeded: false,
        });
        self.errors.push(error);
    }

    fn artifact_cancelled(&self, error: &PoiArtifactError) -> bool {
        matches!(error, PoiArtifactError::Cancelled) || self.job.cancel.is_cancelled()
    }

    fn finish(self) -> PreparedPoiCacheBatch {
        let result = if self.errors.is_empty() {
            Ok(())
        } else {
            Err(self.errors.join("; "))
        };
        PreparedPoiCacheBatch {
            candidates: self.candidates,
            source_outcomes: self.source_outcomes,
            actual_scope: self.actual_scope,
            result,
        }
    }
}

async fn prepare_artifact_candidate(
    job: &PoiCacheCandidateJob,
    client: &reqwest::Client,
    request: ArtifactCandidateRequest,
    observed_manifest: &mut Option<ObservedManifest>,
) -> Result<Option<PreparedPoiCacheCandidate>, PoiArtifactError> {
    let ingestor = PoiArtifactIngestor::new(job.artifact_config.clone(), client.clone())
        .with_progress_observer({
            let event_tx = job.event_tx.clone();
            let active_list_keys = job.active_list_keys.clone();
            let baseline = cache_map_list_progress(job.chain_id, &job.baseline, &active_list_keys);
            let attempt_id = job.attempt_id;
            let generation = job.generation;
            let chain_id = job.chain_id;
            let ready = job.ready;
            move |event| {
                let list_progress = list_progress_with_active_event(
                    &active_list_keys,
                    &baseline,
                    request.list_key,
                    event.current_event_index,
                    event.target_event_index,
                );
                let _ = event_tx.send(ChainPoiCacheJobEvent {
                    progress: new_poi_artifact_cache_progress(
                        attempt_id,
                        generation,
                        chain_id,
                        event.phase,
                        request.list_index,
                        active_list_keys.len(),
                        Some(request.list_key),
                        event.current_event_index,
                        event.target_event_index,
                        list_progress,
                        event.graph,
                        ready,
                        None,
                    ),
                });
            }
        });
    if observed_manifest.is_none() {
        *observed_manifest = Some(
            ingestor
                .fetch_observed_manifest(&job.poi_artifact_persistence, &job.cancel)
                .await?,
        );
    }
    let prepared = ingestor
        .prepare_cache_with_observed_manifest(
            &job.poi_artifact_persistence,
            request.identity,
            observed_manifest
                .as_ref()
                .expect("observed manifest initialized"),
            request.persisted,
            request.expected_base,
            job.generation,
            &job.cancel,
        )
        .await?;
    Ok(prepared.map(|prepared| PreparedPoiCacheCandidate {
        list_key: request.list_key,
        cache: None,
        persistence: PreparedPoiCachePersistence::Artifact {
            prepared: Box::new(prepared),
        },
    }))
}

fn emit_candidate_progress(
    job: &PoiCacheCandidateJob,
    list_index: usize,
    list_key: FixedBytes<32>,
    phase: PoiArtifactCachePhase,
    current_event_index: Option<u64>,
    target_event_index: Option<u64>,
) {
    let baseline = cache_map_list_progress(job.chain_id, &job.baseline, &job.active_list_keys);
    let list_progress = list_progress_with_active_event(
        &job.active_list_keys,
        &baseline,
        list_key,
        current_event_index,
        target_event_index,
    );
    let _ = job.event_tx.send(ChainPoiCacheJobEvent {
        progress: new_poi_artifact_cache_progress(
            job.attempt_id,
            job.generation,
            job.chain_id,
            phase,
            list_index,
            job.active_list_keys.len(),
            Some(list_key),
            current_event_index,
            target_event_index,
            list_progress,
            PoiArtifactCacheGraphProgress::default(),
            job.ready,
            None,
        ),
    });
}

async fn finish_chain_poi_cache_attempt(
    task: &ChainPoiCacheCoordinator,
    attempt_id: PoiArtifactCacheAttemptId,
    generation: u64,
    batch: PreparedPoiCacheBatch,
) -> FinishedPoiCacheAttempt {
    let PreparedPoiCacheBatch {
        candidates,
        source_outcomes,
        result: network_result,
        ..
    } = batch;
    let mut commit_result = validate_artifact_manifest_sequences(
        candidates
            .iter()
            .filter_map(|candidate| candidate.persistence.artifact_manifest_sequence()),
    );
    let candidates_valid = commit_result.is_ok();
    if candidates_valid && !candidates.is_empty() {
        publish_current_attempt_phase(
            task,
            attempt_id,
            generation,
            PoiArtifactCachePhase::Persisting,
        );
    }
    if candidates_valid {
        for outcome in &source_outcomes {
            if task.cancel.is_cancelled() {
                return FinishedPoiCacheAttempt {
                    result: Err(PoiCacheServiceError::Shutdown { attempt_id }),
                    compactions: Vec::new(),
                };
            }
            if !matches!(outcome.rpc, Some(PoiRpcAttemptOutcome::Succeeded { .. })) {
                continue;
            }
            let identity = PoiCacheIdentity::new(
                EVM_CHAIN_TYPE,
                task.chain_id,
                DEFAULT_TXID_VERSION,
                outcome.list_key,
            );
            if let Err(error) = record_poi_rpc_success(task.db.as_ref(), &identity, generation) {
                commit_result = Err(PoiCacheServiceError::Refresh {
                    reason: error.to_string(),
                });
                break;
            }
        }
    }
    let mut staged = Vec::new();
    if candidates_valid {
        for candidate in candidates {
            if task.cancel.is_cancelled() {
                return FinishedPoiCacheAttempt {
                    result: Err(PoiCacheServiceError::Shutdown { attempt_id }),
                    compactions: Vec::new(),
                };
            }
            match stage_poi_cache_candidate(task, attempt_id, generation, candidate).await {
                Ok(Some(candidate)) => staged.push(candidate),
                Ok(None) => {}
                Err(error) => {
                    commit_result = Err(error);
                    break;
                }
            }
        }
    }
    let result = commit_result
        .and_then(|()| network_result.map_err(|reason| PoiCacheServiceError::Refresh { reason }));
    let compactions =
        match apply_staged_poi_cache_batch(task, attempt_id, generation, staged, &result).await {
            Ok(compactions) => compactions,
            Err(error) => {
                return FinishedPoiCacheAttempt {
                    result: Err(error),
                    compactions: Vec::new(),
                };
            }
        };
    FinishedPoiCacheAttempt {
        result,
        compactions,
    }
}

fn enqueue_poi_corpus_compactions(
    lane: &mut PoiCorpusCompactionLane,
    compactions: Vec<PoiCorpusCompactionRequest>,
) {
    for compaction in compactions {
        lane.pending
            .insert(compaction.identity.list_key, compaction);
    }
}

fn start_next_poi_corpus_compaction(
    task: &ChainPoiCacheCoordinator,
    lane: &mut PoiCorpusCompactionLane,
    generation: u64,
) {
    if lane.active.is_some() || task.cancel.is_cancelled() {
        return;
    }
    let Some((_, compaction)) = lane.pending.pop_first() else {
        return;
    };
    let list_key = compaction.identity.list_key;
    let expected_base = compaction.expected_base;
    let persistence = task.poi_artifact_persistence.clone();
    let publisher_pubkey = task.artifact_config.trusted_publisher_pubkey;
    let cancel = task.cancel.child_token();
    let job_cancel = cancel.clone();
    let job = async move {
        let result = persistence
            .compact_poi_corpus_for_attempt(
                compaction.identity,
                generation,
                publisher_pubkey,
                expected_base,
                &job_cancel,
            )
            .await
            .map_err(|error| error.to_string());
        PoiCorpusCompactionCompletion {
            list_key,
            expected_base,
            result,
        }
    }
    .boxed();
    lane.active = Some(ActivePoiCorpusCompaction { cancel, job });
}

async fn wait_for_active_poi_corpus_compaction(
    lane: &mut PoiCorpusCompactionLane,
) -> PoiCorpusCompactionCompletion {
    match lane.active.as_mut() {
        Some(active) => (&mut active.job).await,
        None => std::future::pending().await,
    }
}

fn cancel_poi_corpus_compaction_lane(lane: &mut PoiCorpusCompactionLane) {
    lane.pending.clear();
    if let Some(active) = lane.active.take() {
        active.cancel.cancel();
        drop(active.job);
    }
}

async fn finish_background_poi_corpus_compaction(
    task: &ChainPoiCacheCoordinator,
    generation: u64,
    completion: PoiCorpusCompactionCompletion,
) {
    match completion.result {
        Ok(Some(result)) => {
            reconcile_background_compaction_anchor(
                task,
                generation,
                completion.list_key,
                completion.expected_base,
                &result,
            )
            .await;
        }
        Ok(None) => {}
        Err(error) => {
            warn!(%error, "PPOI corpus journal compaction deferred after failure");
        }
    }
}

#[cfg(test)]
async fn run_background_poi_corpus_compaction(
    task: &ChainPoiCacheCoordinator,
    generation: u64,
    compaction: PoiCorpusCompactionRequest,
) -> bool {
    let mut lane = PoiCorpusCompactionLane::default();
    enqueue_poi_corpus_compactions(&mut lane, vec![compaction]);
    start_next_poi_corpus_compaction(task, &mut lane, generation);
    if lane.active.is_none() {
        return false;
    }
    let completion = wait_for_active_poi_corpus_compaction(&mut lane).await;
    lane.active.take();
    finish_background_poi_corpus_compaction(task, generation, completion).await;
    !task.cancel.is_cancelled()
}

async fn reconcile_background_compaction_anchor(
    task: &ChainPoiCacheCoordinator,
    generation: u64,
    list_key: FixedBytes<32>,
    expected_base: ExpectedPoiCorpusBase,
    result: &PoiCorpusCompactionResult,
) -> bool {
    let PoiCorpusCompactionResult::Applied(persisted) = result else {
        return false;
    };
    let Some(compacted_head) = persisted.journal_head.as_ref() else {
        return false;
    };
    if persisted.cache_generation != generation || persisted.cache.identity().list_key != list_key {
        return false;
    }

    let _revision_fence = acquire_corpus_write_fence(task).await;
    let publication = task
        .runtime
        .publication_fence
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if publication.shutdown || task.cancel.is_cancelled() {
        return false;
    }
    let mut anchors = task
        .installed_head_anchors
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(installed) = anchors.get_mut(&list_key) else {
        return false;
    };
    if ExpectedPoiCorpusBase::from_journal_head(installed) != expected_base {
        return false;
    }
    *installed = compacted_head.clone();
    drop(publication);
    true
}

fn validate_artifact_manifest_sequences(
    sequences: impl Iterator<Item = u64>,
) -> Result<(), PoiCacheServiceError> {
    let sequence_range = sequences.fold(None, |range, sequence| {
        Some(
            range.map_or((sequence, sequence), |(min, max): (u64, u64)| {
                (min.min(sequence), max.max(sequence))
            }),
        )
    });
    match sequence_range {
        Some((min, max)) if min != max => Err(PoiCacheServiceError::Refresh {
            reason: format!(
                "artifact candidates used inconsistent global manifest sequences {min} and {max}"
            ),
        }),
        _ => Ok(()),
    }
}

async fn stage_poi_cache_candidate(
    task: &ChainPoiCacheCoordinator,
    attempt_id: PoiArtifactCacheAttemptId,
    generation: u64,
    candidate: PreparedPoiCacheCandidate,
) -> Result<Option<StagedPoiCacheCandidate>, PoiCacheServiceError> {
    let PreparedPoiCacheCandidate {
        list_key,
        cache,
        persistence,
    } = candidate;
    let persisted = match persistence {
        PreparedPoiCachePersistence::Artifact { prepared } => {
            let PreparedIngestion { candidate } = *prepared;
            let Some(persisted) = task
                .poi_artifact_persistence
                .commit_candidate_for_attempt(candidate, &task.cancel)
                .await
                .map_err(|err| PoiCacheServiceError::Refresh {
                    reason: err.to_string(),
                })?
            else {
                return Ok(None);
            };
            persisted
        }
        PreparedPoiCachePersistence::PublicRpc { prepared } => {
            let PreparedPublicRpcPersistence {
                range_start_index,
                expected_base,
                starting_record,
                starting_head,
                delta,
                blocked_shields,
            } = *prepared;
            let Some(persisted) = task
                .poi_artifact_persistence
                .commit_public_rpc_for_attempt(
                    cache.expect("public RPC candidate has a cache"),
                    generation,
                    task.artifact_config.trusted_publisher_pubkey,
                    range_start_index,
                    expected_base,
                    starting_record,
                    starting_head,
                    delta,
                    blocked_shields,
                    &task.cancel,
                )
                .await
                .map_err(|err| PoiCacheServiceError::Refresh {
                    reason: err.to_string(),
                })?
            else {
                return Ok(None);
            };
            persisted
        }
    };
    if task.cancel.is_cancelled() {
        return Err(PoiCacheServiceError::Shutdown { attempt_id });
    }
    let compaction = persisted
        .compaction_recommended
        .then(|| PoiCorpusCompactionRequest {
            identity: persisted.cache.identity().clone(),
            expected_base: persisted.expected_base(),
        });
    Ok(Some(StagedPoiCacheCandidate {
        list_key,
        cache: persisted.cache,
        journal_head: persisted.journal_head,
        compaction,
    }))
}

struct PoiCorpusCompactionRequest {
    identity: PoiCacheIdentity,
    expected_base: ExpectedPoiCorpusBase,
}

struct StagedPoiCacheCandidate {
    list_key: FixedBytes<32>,
    cache: PoiCache,
    journal_head: Option<PoiCorpusJournalHeadRecord>,
    compaction: Option<PoiCorpusCompactionRequest>,
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

async fn apply_staged_poi_cache_batch(
    task: &ChainPoiCacheCoordinator,
    attempt_id: PoiArtifactCacheAttemptId,
    generation: u64,
    staged: Vec<StagedPoiCacheCandidate>,
    result: &Result<(), PoiCacheServiceError>,
) -> Result<Vec<PoiCorpusCompactionRequest>, PoiCacheServiceError> {
    let _revision_fence = acquire_corpus_write_fence(task).await;
    let mut caches = task.local_caches.write().await;
    let publication = task
        .runtime
        .publication_fence
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if publication.shutdown || task.cancel.is_cancelled() {
        return Err(PoiCacheServiceError::Shutdown { attempt_id });
    }
    let mut installed_head_anchors = task
        .installed_head_anchors
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut installed_any = false;
    let mut blocked_shields_changed = false;
    let mut compactions = Vec::new();
    for candidate in staged {
        let changed = caches.get(&candidate.list_key).is_none_or(|current| {
            current.progress() != candidate.cache.progress()
                || !current.blocked_shields_match(&candidate.cache)
        });
        if let Some(compaction) = candidate.compaction {
            compactions.push(compaction);
        }
        if !changed {
            if let Some(head) = candidate.journal_head {
                installed_head_anchors.insert(candidate.list_key, head);
            }
            continue;
        }
        let blocked_changed = caches
            .get(&candidate.list_key)
            .is_none_or(|current| !current.blocked_shields_match(&candidate.cache));
        if install_cache_if_not_behind(&mut caches, candidate.list_key, candidate.cache) {
            if let Some(head) = candidate.journal_head {
                installed_head_anchors.insert(candidate.list_key, head);
            }
            installed_any = true;
            blocked_shields_changed |= blocked_changed;
        }
    }
    if installed_any {
        task.local_caches
            .publish_committed_revision(blocked_shields_changed);
    }
    let graph_progress = task
        .progress_tx
        .borrow()
        .get(&task.chain_id)
        .filter(|progress| progress.attempt_id == attempt_id && progress.generation == generation)
        .map_or_else(PoiArtifactCacheGraphProgress::default, |progress| {
            progress.graph
        });
    let progress = completion_progress_from_caches(
        attempt_id,
        generation,
        task.chain_id,
        &caches,
        &task.active_list_keys,
        graph_progress,
        result.as_ref().err().map(ToString::to_string),
    );
    send_poi_artifact_cache_progress(&task.progress_tx, progress);
    drop(publication);
    Ok(compactions)
}

fn completion_progress_from_caches(
    attempt_id: PoiArtifactCacheAttemptId,
    generation: u64,
    chain_id: u64,
    caches: &BTreeMap<FixedBytes<32>, PoiCache>,
    active_list_keys: &[FixedBytes<32>],
    graph: PoiArtifactCacheGraphProgress,
    last_error: Option<String>,
) -> PoiArtifactCacheProgress {
    let ready = cache_map_available_for_lists(chain_id, caches, active_list_keys);
    let completed = active_list_keys
        .iter()
        .filter(|list_key| cache_map_available_for_list(chain_id, caches, **list_key))
        .count();
    let list_progress = cache_map_list_progress(chain_id, caches, active_list_keys);
    let (current_event_index, target_event_index) = single_list_event_index(&list_progress);
    new_poi_artifact_cache_progress(
        attempt_id,
        generation,
        chain_id,
        if last_error.is_some() {
            PoiArtifactCachePhase::Failed
        } else {
            PoiArtifactCachePhase::Ready
        },
        completed,
        active_list_keys.len(),
        None,
        current_event_index,
        target_event_index,
        list_progress,
        graph,
        ready,
        last_error,
    )
}

fn poi_cache_error_diagnostic(error: &PoiCacheError) -> String {
    let PoiCacheError::Rpc(error) = error else {
        return error.to_string();
    };
    if let Some(code) = error.json_rpc_code() {
        return format!("POI cache RPC JSON-RPC error {code}");
    }
    if let Some(status) = error.status() {
        return format!("POI cache RPC HTTP {status}");
    }
    if let Some(phase) = error.transport_phase() {
        return format!("POI cache RPC failed during {phase}");
    }
    "POI cache RPC failed".to_string()
}

fn source_health_for_lists(
    db: &DbStore,
    chain_id: u64,
    generation: u64,
    active_list_keys: &[FixedBytes<32>],
    preloaded: &BTreeMap<FixedBytes<32>, PersistedPoiArtifactCache>,
) -> BTreeMap<FixedBytes<32>, PoiSourceHealth> {
    active_list_keys
        .iter()
        .map(|list_key| {
            let identity =
                PoiCacheIdentity::new(EVM_CHAIN_TYPE, chain_id, DEFAULT_TXID_VERSION, *list_key);
            let legacy_timestamp = preloaded
                .get(list_key)
                .and_then(|persisted| persisted.record.legacy_last_successful_rpc_sync_at_ms);
            let timestamp = match load_poi_rpc_health(db, &identity, generation, legacy_timestamp) {
                Ok(timestamp) => timestamp,
                Err(err) => {
                    warn!(
                        ?err,
                        chain_id,
                        list_key = %hex::encode(list_key),
                        "failed to load advisory PPOI RPC health"
                    );
                    None
                }
            };
            let rpc_stale_at = persisted_rpc_stale_at(timestamp);
            (*list_key, PoiSourceHealth::new(rpc_stale_at))
        })
        .collect()
}

fn persisted_rpc_stale_at(timestamp_ms: Option<u64>) -> Option<Instant> {
    let timestamp_ms = timestamp_ms?;
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())?;
    let age = Duration::from_millis(now_ms.saturating_sub(timestamp_ms));
    let remaining = POI_ARTIFACT_RPC_STALE_AFTER.saturating_sub(age);
    let now = Instant::now();
    now.checked_add(remaining).or(Some(now))
}

fn record_list_source_outcomes(
    health: &mut BTreeMap<FixedBytes<32>, PoiSourceHealth>,
    outcomes: &[PoiListSourceOutcome],
) {
    for outcome in outcomes {
        health
            .entry(outcome.list_key)
            .or_insert_with(|| PoiSourceHealth::new(None))
            .record(outcome);
    }
}

fn poi_cache_demand(
    observation: &WalletObservation,
    active_list_keys: &[FixedBytes<32>],
) -> PoiCacheDemand {
    let (WalletReadiness::Syncing | WalletReadiness::Ready) = observation.readiness() else {
        return PoiCacheDemand::default();
    };
    let Some(snapshot) = observation.view().current_snapshot() else {
        return PoiCacheDemand::default();
    };
    let mut demand = PoiCacheDemand::default();
    for wallet_utxo in snapshot
        .utxos
        .iter()
        .chain(snapshot.pending_overlay.new_utxos.iter())
        .filter(|wallet_utxo| !wallet_utxo.is_spent())
    {
        let unresolved = active_list_keys.iter().any(|list_key| {
            wallet_utxo
                .utxo
                .poi
                .statuses
                .get(list_key)
                .is_none_or(|status| status.is_recoverable())
        });
        if unresolved {
            demand.events = true;
            demand.blocked_shields |=
                wallet_utxo.utxo.poi.commitment_kind == UtxoCommitmentKind::Shield;
        }
    }
    let workflow = observation.ppoi_workflow_status();
    demand.events |= workflow.awaiting_validation > 0 || workflow.awaiting_poi_data > 0;
    demand
}

fn cache_map_available_for_list(
    chain_id: u64,
    caches: &BTreeMap<FixedBytes<32>, PoiCache>,
    list_key: FixedBytes<32>,
) -> bool {
    caches.get(&list_key).is_some_and(|cache| {
        cache.identity().chain_type == EVM_CHAIN_TYPE
            && cache.identity().chain_id == chain_id
            && cache.identity().txid_version == DEFAULT_TXID_VERSION
            && cache.progress().next_event_index > 0
    })
}

fn cache_map_available_for_lists(
    chain_id: u64,
    caches: &BTreeMap<FixedBytes<32>, PoiCache>,
    active_list_keys: &[FixedBytes<32>],
) -> bool {
    active_list_keys
        .iter()
        .all(|list_key| cache_map_available_for_list(chain_id, caches, *list_key))
}

fn cache_map_list_progress(
    chain_id: u64,
    caches: &BTreeMap<FixedBytes<32>, PoiCache>,
    active_list_keys: &[FixedBytes<32>],
) -> Vec<PoiArtifactCacheListProgress> {
    active_list_keys
        .iter()
        .map(|list_key| {
            let event_index = caches.get(list_key).and_then(|cache| {
                (cache.identity().chain_type == EVM_CHAIN_TYPE
                    && cache.identity().chain_id == chain_id
                    && cache.identity().txid_version == DEFAULT_TXID_VERSION)
                    .then(|| cache.progress().next_event_index.checked_sub(1))
                    .flatten()
            });
            PoiArtifactCacheListProgress {
                list_key: *list_key,
                current_event_index: event_index,
                target_event_index: event_index,
                ready_for_wallet_checks: event_index.is_some(),
            }
        })
        .collect()
}

fn install_cache_if_not_behind(
    caches: &mut BTreeMap<FixedBytes<32>, PoiCache>,
    list_key: FixedBytes<32>,
    cache: PoiCache,
) -> bool {
    if caches.get(&list_key).is_some_and(|current| {
        current.progress().next_event_index > cache.progress().next_event_index
    }) {
        return false;
    }
    caches.insert(list_key, cache);
    true
}

fn load_persisted_chain_poi_caches(
    db: &DbStore,
    chain_id: u64,
    active_list_keys: &[FixedBytes<32>],
    publisher_pubkey: FixedBytes<32>,
) -> BTreeMap<FixedBytes<32>, PersistedPoiArtifactCache> {
    let mut loaded = BTreeMap::new();
    for list_key in active_list_keys {
        let identity =
            PoiCacheIdentity::new(EVM_CHAIN_TYPE, chain_id, DEFAULT_TXID_VERSION, *list_key);
        match load_persisted_cache_for_publisher(db, &identity, publisher_pubkey) {
            Ok(Some(persisted)) => {
                loaded.insert(*list_key, persisted);
            }
            Ok(None) => {}
            Err(err) => warn!(
                ?err,
                chain_id,
                list_key = %hex::encode(list_key),
                "failed to load persisted artifact POI cache"
            ),
        }
    }

    loaded
}

async fn apply_loaded_persisted_chain_poi_caches(
    task: &ChainPoiCacheCoordinator,
    mut loaded: BTreeMap<FixedBytes<32>, PersistedPoiArtifactCache>,
    started: Instant,
    attempt_id: PoiArtifactCacheAttemptId,
) -> BTreeMap<FixedBytes<32>, PersistedPoiArtifactCache> {
    let loaded_count = loaded.len();
    if loaded_count == 0 {
        return loaded;
    }
    let _revision_fence = acquire_corpus_write_fence(task).await;
    let lock_started = Instant::now();
    let mut caches = task.local_caches.write().await;
    let lock_wait_elapsed_ms = lock_started.elapsed().as_millis();
    let publication = task
        .runtime
        .publication_fence
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if publication.shutdown || task.cancel.is_cancelled() {
        return BTreeMap::new();
    }
    loaded.retain(|list_key, persisted| {
        if task.cache_generation != persisted.cache_generation {
            return false;
        }
        caches.insert(*list_key, persisted.cache.clone());
        true
    });
    let installed_count = loaded.len();
    if installed_count > 0 {
        task.local_caches.publish_committed_revision(true);
    }
    info!(
        chain_id = task.chain_id,
        %attempt_id,
        loaded_count,
        installed_count,
        lock_wait_elapsed_ms,
        elapsed_ms = started.elapsed().as_millis(),
        "installed persisted chain-scoped artifact POI cache"
    );
    loaded
}

async fn chain_poi_caches_available_for_lists(
    chain_id: u64,
    local_caches: &LocalPoiCaches,
    active_list_keys: &[FixedBytes<32>],
) -> bool {
    if active_list_keys.is_empty() {
        return true;
    }
    let caches = local_caches.read().await;
    active_list_keys.iter().all(|list_key| {
        caches.get(list_key).is_some_and(|cache| {
            cache.identity().chain_type == EVM_CHAIN_TYPE
                && cache.identity().chain_id == chain_id
                && cache.identity().txid_version == DEFAULT_TXID_VERSION
                && cache.progress().next_event_index > 0
        })
    })
}

async fn installed_chain_poi_cache_count(
    chain_id: u64,
    local_caches: &LocalPoiCaches,
    active_list_keys: &[FixedBytes<32>],
) -> usize {
    let caches = local_caches.read().await;
    active_list_keys
        .iter()
        .filter(|list_key| {
            caches.get(*list_key).is_some_and(|cache| {
                cache.identity().chain_type == EVM_CHAIN_TYPE
                    && cache.identity().chain_id == chain_id
                    && cache.identity().txid_version == DEFAULT_TXID_VERSION
                    && cache.progress().next_event_index > 0
            })
        })
        .count()
}

async fn chain_poi_cache_list_progress(
    chain_id: u64,
    local_caches: &LocalPoiCaches,
    active_list_keys: &[FixedBytes<32>],
) -> Vec<PoiArtifactCacheListProgress> {
    let caches = local_caches.read().await;
    active_list_keys
        .iter()
        .map(|list_key| {
            let event_index = caches.get(list_key).and_then(|cache| {
                if cache.identity().chain_type == EVM_CHAIN_TYPE
                    && cache.identity().chain_id == chain_id
                    && cache.identity().txid_version == DEFAULT_TXID_VERSION
                {
                    cache.progress().next_event_index.checked_sub(1)
                } else {
                    None
                }
            });
            PoiArtifactCacheListProgress {
                list_key: *list_key,
                current_event_index: event_index,
                target_event_index: event_index,
                ready_for_wallet_checks: event_index.is_some(),
            }
        })
        .collect()
}

async fn public_rpc_candidate_cache(
    client: &PoiRpcClient,
    cache: PoiCache,
    scope: PoiCacheSyncScope,
) -> Result<PoiRpcSyncResult, PoiCacheError> {
    let (mut cache, result) = match scope {
        PoiCacheSyncScope {
            events: true,
            blocked_shields: true,
        } => {
            cache
                .sync_bounded_with_journal(
                    client,
                    POI_EVENTS_PAGE_SIZE,
                    POI_MERKLETREE_LEAVES_PAGE_SIZE,
                    crate::poi_limits::POI_RPC_EVENT_PAGE_LIMIT,
                )
                .await?
        }
        PoiCacheSyncScope {
            events: true,
            blocked_shields: false,
        } => {
            cache
                .sync_events_bounded_with_journal(
                    client,
                    POI_EVENTS_PAGE_SIZE,
                    POI_MERKLETREE_LEAVES_PAGE_SIZE,
                    crate::poi_limits::POI_RPC_EVENT_PAGE_LIMIT,
                )
                .await?
        }
        PoiCacheSyncScope {
            events: false,
            blocked_shields: true,
        } => cache.sync_blocked_shields_with_journal(client).await?,
        PoiCacheSyncScope {
            events: false,
            blocked_shields: false,
        } => unreachable!("empty POI cache synchronization scope"),
    };
    if cache.progress().next_event_index == 0 {
        return Ok(PoiRpcSyncResult {
            outcome: result.outcome,
            candidate: None,
        });
    }
    if cache.progress().next_event_index > 0
        && cache.validated_roots().is_none()
        && !cache.validate_roots(client).await?
    {
        return Err(PoiCacheError::InvalidRoots);
    }
    let candidate = result.outcome.changed.then_some(PoiRpcCandidate {
        cache,
        delta: result.delta,
        blocked_shields: result.blocked_shields,
    });
    Ok(PoiRpcSyncResult {
        outcome: result.outcome,
        candidate,
    })
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
