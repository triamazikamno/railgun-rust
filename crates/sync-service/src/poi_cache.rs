use std::collections::BTreeMap;
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
    {
        let publication = task
            .runtime
            .publication_fence
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if publication.shutdown || task.cancel.is_cancelled() {
            return;
        }
        let _ = send_poi_artifact_cache_progress_for_generation(
            &task.progress_tx,
            generation,
            new_poi_artifact_cache_progress(
                startup_attempt_id,
                generation,
                chain_id,
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
    }
    let preload_started = Instant::now();
    let loaded = load_persisted_chain_poi_caches(
        task.db.as_ref(),
        chain_id,
        &task.active_list_keys,
        task.artifact_config.trusted_publisher_pubkey,
    );
    task.preloaded_caches =
        apply_loaded_persisted_chain_poi_caches(&task, loaded, preload_started, startup_attempt_id)
            .await;
    {
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
    let mut health = source_health_for_lists(
        task.db.as_ref(),
        chain_id,
        generation,
        &task.active_list_keys,
        &task.preloaded_caches,
    );
    let mut active = None;
    let mut public_cache_reset = None;
    let mut compaction_lane = PoiCorpusCompactionLane::default();
    let mut maintenance = PoiCacheMaintenanceSchedule::new(TokioInstant::now());
    info!(
        chain_id,
        list_count = task.active_list_keys.len(),
        "starting chain-owned POI cache coordinator"
    );
    if start_chain_poi_cache_attempt(
        &mut task,
        &mut active,
        generation,
        &health,
        PoiCacheSyncScope::FULL,
        None,
    )
    .await
    .is_err()
    {
        maintenance.record_failure(PoiCacheSyncScope::FULL, TokioInstant::now());
    }

    loop {
        tokio::select! {
            biased;
            () = task.cancel.cancelled() => {
                cancel_active_attempt(&mut active, |attempt_id| {
                    PoiCacheServiceError::Shutdown { attempt_id }
                });
                cancel_poi_corpus_compaction_lane(&mut compaction_lane);
                break;
            }
            command = task.command_rx.recv() => {
                let Some(command) = command else {
                    cancel_active_attempt(&mut active, |attempt_id| {
                        PoiCacheServiceError::Shutdown { attempt_id }
                    });
                    break;
                };
                match command {
                    ChainPoiCacheCommand::UpdateDemand { actor_id, demand } => {
                        let _ = apply_poi_cache_demand_update(
                            &mut maintenance,
                            actor_id,
                            demand,
                            TokioInstant::now(),
                        );
                    }
                    ChainPoiCacheCommand::Retry { scope, admission } => {
                        clear_released_public_cache_reset(&mut public_cache_reset);
                        if public_cache_reset.is_some()
                            || task.runtime.public_cache_reset_gate.try_read().is_err()
                        {
                            let _ = admission.send(Err(PoiCacheServiceError::CorpusResetInProgress));
                            continue;
                        }
                        let replacement_scope = replacement_poi_cache_scope(scope, active.as_ref());
                        cancel_active_attempt(&mut active, |attempt_id| {
                            PoiCacheServiceError::AttemptSuperseded { attempt_id }
                        });
                        let (completion, completed) = oneshot::channel();
                        match start_chain_poi_cache_attempt(
                            &mut task,
                            &mut active,
                            generation,
                            &health,
                            replacement_scope,
                            Some(completion),
                        )
                        .await {
                            Ok(attempt_id) => {
                                let publication = task
                                    .runtime
                                    .publication_fence
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                                if publication.shutdown || task.cancel.is_cancelled() {
                                    drop(publication);
                                    cancel_active_attempt(&mut active, |attempt_id| {
                                        PoiCacheServiceError::Shutdown { attempt_id }
                                    });
                                    let _ = admission.send(Err(PoiCacheServiceError::Shutdown {
                                        attempt_id,
                                    }));
                                } else {
                                    let _ = admission.send(Ok(PoiCacheRetryHandle {
                                        attempt_id,
                                        completion: completed,
                                    }));
                                }
                            }
                            Err(error) => {
                                maintenance.record_failure(
                                    replacement_scope,
                                    TokioInstant::now(),
                                );
                                let _ = admission.send(Err(error));
                            }
                        }
                    }
                    ChainPoiCacheCommand::QuiesceForPublicCacheReset { lease, response } => {
                        public_cache_reset = Some(lease);
                        cancel_active_attempt(&mut active, |attempt_id| {
                            PoiCacheServiceError::StaleAttempt { attempt_id }
                        });
                        cancel_poi_corpus_compaction_lane(&mut compaction_lane);
                        let _ = response.send(());
                    }
                }
            }
            event = task.job_rx.recv() => {
                let Some(event) = event else { continue };
                publish_active_attempt_progress(&task, active.as_ref(), event);
            }
            completion = wait_for_active_attempt(&mut active) => {
                let finished = active.take().expect("completed POI cache attempt is active");
                let attempt_id = finished.id;
                let attempt_generation = finished.generation;
                let attempt_scope = finished.scope;
                let actual_scope = completion.actual_scope;
                let source_outcomes = completion.source_outcomes.clone();
                let finished_attempt = finish_chain_poi_cache_attempt(
                    &task,
                    attempt_id,
                    attempt_generation,
                    completion,
                )
                .await;
                let FinishedPoiCacheAttempt {
                    result: attempt_result,
                    compactions,
                } = finished_attempt;
                if !matches!(
                    &attempt_result,
                    Err(PoiCacheServiceError::Shutdown { .. })
                ) {
                    record_list_source_outcomes(&mut health, &source_outcomes);
                }
                if attempt_result.is_ok() {
                    maintenance.record_success(actual_scope, TokioInstant::now());
                } else {
                    maintenance.record_failure(attempt_scope, TokioInstant::now());
                }
                let retry_completion = drop_completed_attempt(finished);
                if let Some(response) = retry_completion {
                    let publication = task
                        .runtime
                        .publication_fence
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let attempt_result = if publication.shutdown || task.cancel.is_cancelled() {
                        Err(PoiCacheServiceError::Shutdown { attempt_id })
                    } else {
                        attempt_result
                    };
                    let _ = response.send(attempt_result);
                }
                enqueue_poi_corpus_compactions(&mut compaction_lane, compactions);
                start_next_poi_corpus_compaction(&task, &mut compaction_lane, generation);
            }
            completion = wait_for_active_poi_corpus_compaction(&mut compaction_lane) => {
                compaction_lane.active.take();
                finish_background_poi_corpus_compaction(&task, generation, completion).await;
                start_next_poi_corpus_compaction(&task, &mut compaction_lane, generation);
            }
            () = tokio::time::sleep_until(maintenance.next_deadline()), if active.is_none()
                && public_cache_reset.is_none() => {
                let now = TokioInstant::now();
                if let Some(scope) = maintenance.due_scope(now)
                    && start_chain_poi_cache_attempt(
                        &mut task,
                        &mut active,
                        generation,
                        &health,
                        scope,
                        None,
                    )
                    .await
                    .is_err()
                {
                    maintenance.record_failure(scope, now);
                }
            }
            () = wait_for_public_cache_reset_release(&mut public_cache_reset),
                if active.is_none() => {
                public_cache_reset = None;
                if start_chain_poi_cache_attempt(
                    &mut task,
                    &mut active,
                    generation,
                    &health,
                    PoiCacheSyncScope::FULL,
                    None,
                )
                .await
                .is_err()
                {
                    maintenance.record_failure(PoiCacheSyncScope::FULL, TokioInstant::now());
                }
            }
        }
    }
    info!(chain_id, "chain-owned POI cache coordinator stopped");
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

async fn produce_chain_poi_cache_candidates(
    mut job: PoiCacheCandidateJob,
) -> PreparedPoiCacheBatch {
    let client = job.http_client.clone().unwrap_or_default();
    let rpc_client = wallet_poi_status_client(&job.poi_rpc_url, job.http_client.as_ref());
    let mut candidates = Vec::with_capacity(job.active_list_keys.len());
    let mut source_outcomes = Vec::with_capacity(job.active_list_keys.len());
    let mut errors = Vec::new();
    let mut observed_manifest = None;
    let mut actual_scope = job.scope;
    for (list_index, list_key) in job.active_list_keys.iter().copied().enumerate() {
        let plan = job
            .source_plans
            .get(&list_key)
            .copied()
            .expect("active POI list has a source plan");
        let identity =
            PoiCacheIdentity::new(EVM_CHAIN_TYPE, job.chain_id, DEFAULT_TXID_VERSION, list_key);
        let installed_cache = job.baseline.remove(&list_key);
        let (persisted, expected_base) = match job.preloaded_caches.remove(&list_key) {
            Some(persisted) => {
                let expected = persisted.expected_base();
                (Some(persisted), expected)
            }
            None => match load_persisted_cache_candidate_for_publisher(
                job.db.as_ref(),
                &identity,
                job.artifact_config.trusted_publisher_pubkey,
                installed_cache,
                job.installed_head_anchors.get(&list_key),
            ) {
                Ok(observed) => observed,
                Err(err) => {
                    errors.push(err.to_string());
                    continue;
                }
            },
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
        let range_start_index = baseline_cache.progress().next_event_index;

        if job.scope.events && plan.use_artifact {
            match Box::pin(prepare_artifact_candidate(
                &job,
                &client,
                list_index,
                list_key,
                identity,
                artifact_starting,
                expected_base,
                &mut observed_manifest,
            ))
            .await
            {
                Ok(candidate) => {
                    actual_scope = actual_scope.union(PoiCacheSyncScope::FULL);
                    if let Some(candidate) = candidate {
                        candidates.push(candidate);
                    }
                    source_outcomes.push(PoiListSourceOutcome {
                        list_key,
                        rpc: None,
                        artifact_succeeded: true,
                    });
                }
                Err(artifact_error)
                    if matches!(&artifact_error, PoiArtifactError::Cancelled)
                        || job.cancel.is_cancelled() =>
                {
                    errors.push(artifact_error.to_string());
                    break;
                }
                Err(artifact_error) => {
                    warn!(chain_id = job.chain_id, list_key = %hex::encode(list_key), %artifact_error, "artifact candidate failed; trying public range fallback");
                    match public_rpc_candidate_cache(&rpc_client, baseline_cache, job.scope).await {
                        Ok(result) => {
                            source_outcomes.push(PoiListSourceOutcome {
                                list_key,
                                rpc: Some(PoiRpcAttemptOutcome::Succeeded {
                                    backlog_large: result.outcome.event_page_budget_exhausted,
                                }),
                                artifact_succeeded: false,
                            });
                            if let Some(candidate) = result.candidate {
                                candidates.push(PreparedPoiCacheCandidate {
                                    list_key,
                                    cache: Some(candidate.cache),
                                    persistence: PreparedPoiCachePersistence::PublicRpc {
                                        prepared: Box::new(PreparedPublicRpcPersistence {
                                            range_start_index,
                                            expected_base,
                                            starting_record: starting_record.clone(),
                                            starting_head: starting_head.clone(),
                                            delta: candidate.delta,
                                            blocked_shields: candidate.blocked_shields,
                                        }),
                                    },
                                });
                            }
                        }
                        Err(rpc_error) => {
                            source_outcomes.push(PoiListSourceOutcome {
                                list_key,
                                rpc: Some(PoiRpcAttemptOutcome::Failed),
                                artifact_succeeded: false,
                            });
                            let rpc_error = poi_cache_error_diagnostic(&rpc_error);
                            errors.push(format!(
                                "artifact refresh failed: {artifact_error}; public range catch-up failed: {rpc_error}"
                            ));
                        }
                    }
                }
            }
        } else {
            emit_candidate_progress(
                &job,
                list_index,
                list_key,
                PoiArtifactCachePhase::LiveTailing,
                baseline_cache.progress().next_event_index.checked_sub(1),
                None,
            );
            match public_rpc_candidate_cache(&rpc_client, baseline_cache, job.scope).await {
                Ok(result) => {
                    source_outcomes.push(PoiListSourceOutcome {
                        list_key,
                        rpc: Some(PoiRpcAttemptOutcome::Succeeded {
                            backlog_large: result.outcome.event_page_budget_exhausted,
                        }),
                        artifact_succeeded: false,
                    });
                    if let Some(candidate) = result.candidate {
                        candidates.push(PreparedPoiCacheCandidate {
                            list_key,
                            cache: Some(candidate.cache),
                            persistence: PreparedPoiCachePersistence::PublicRpc {
                                prepared: Box::new(PreparedPublicRpcPersistence {
                                    range_start_index,
                                    expected_base,
                                    starting_record: starting_record.clone(),
                                    starting_head: starting_head.clone(),
                                    delta: candidate.delta,
                                    blocked_shields: candidate.blocked_shields,
                                }),
                            },
                        });
                    }
                }
                Err(rpc_error) if plan.artifact_after_rpc_failure => {
                    match Box::pin(prepare_artifact_candidate(
                        &job,
                        &client,
                        list_index,
                        list_key,
                        identity,
                        artifact_starting,
                        expected_base,
                        &mut observed_manifest,
                    ))
                    .await
                    {
                        Ok(candidate) => {
                            actual_scope = actual_scope.union(PoiCacheSyncScope::FULL);
                            if let Some(candidate) = candidate {
                                candidates.push(candidate);
                            }
                            source_outcomes.push(PoiListSourceOutcome {
                                list_key,
                                rpc: Some(PoiRpcAttemptOutcome::Failed),
                                artifact_succeeded: true,
                            });
                        }
                        Err(artifact_error)
                            if matches!(&artifact_error, PoiArtifactError::Cancelled)
                                || job.cancel.is_cancelled() =>
                        {
                            errors.push(artifact_error.to_string());
                            break;
                        }
                        Err(artifact_error) => {
                            source_outcomes.push(PoiListSourceOutcome {
                                list_key,
                                rpc: Some(PoiRpcAttemptOutcome::Failed),
                                artifact_succeeded: false,
                            });
                            let rpc_error = poi_cache_error_diagnostic(&rpc_error);
                            errors.push(format!(
                                "public range catch-up failed: {rpc_error}; artifact refresh failed: {artifact_error}"
                            ));
                        }
                    }
                }
                Err(rpc_error) => {
                    source_outcomes.push(PoiListSourceOutcome {
                        list_key,
                        rpc: Some(PoiRpcAttemptOutcome::Failed),
                        artifact_succeeded: false,
                    });
                    errors.push(format!(
                        "public range catch-up failed: {}",
                        poi_cache_error_diagnostic(&rpc_error)
                    ));
                }
            }
        }
    }
    let result = if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    };
    PreparedPoiCacheBatch {
        candidates,
        source_outcomes,
        actual_scope,
        result,
    }
}

async fn prepare_artifact_candidate(
    job: &PoiCacheCandidateJob,
    client: &reqwest::Client,
    list_index: usize,
    list_key: FixedBytes<32>,
    identity: PoiCacheIdentity,
    persisted: Option<PersistedPoiArtifactCache>,
    expected_base: ExpectedPoiCorpusBase,
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
                    list_key,
                    event.current_event_index,
                    event.target_event_index,
                );
                let _ = event_tx.send(ChainPoiCacheJobEvent {
                    progress: new_poi_artifact_cache_progress(
                        attempt_id,
                        generation,
                        chain_id,
                        event.phase,
                        list_index,
                        active_list_keys.len(),
                        Some(list_key),
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
            identity,
            observed_manifest
                .as_ref()
                .expect("observed manifest initialized"),
            persisted,
            expected_base,
            job.generation,
            &job.cancel,
        )
        .await?;
    Ok(prepared.map(|prepared| PreparedPoiCacheCandidate {
        list_key,
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

    let _revision_fence = task.local_caches.revision_write_fence().await;
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

async fn apply_staged_poi_cache_batch(
    task: &ChainPoiCacheCoordinator,
    attempt_id: PoiArtifactCacheAttemptId,
    generation: u64,
    staged: Vec<StagedPoiCacheCandidate>,
    result: &Result<(), PoiCacheServiceError>,
) -> Result<Vec<PoiCorpusCompactionRequest>, PoiCacheServiceError> {
    let _revision_fence = task.local_caches.revision_write_fence().await;
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
    let _revision_fence = task.local_caches.revision_write_fence().await;
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
mod tests {
    use super::{
        ActivePoiCacheAttempt, ChainPoiCacheCommand, ChainPoiCacheCoordinator, EVM_CHAIN_TYPE,
        POI_CACHE_BLOCKED_ACTIVE_INTERVAL, POI_CACHE_BLOCKED_IDLE_INTERVAL,
        POI_CACHE_EVENT_ACTIVE_INTERVAL, POI_CACHE_EVENT_IDLE_INTERVAL,
        POI_CACHE_FAILURE_RETRY_INTERVAL, PersistedPoiArtifactCache, PoiCacheCandidateJob,
        PoiCacheDemand, PoiCacheMaintenanceSchedule, PoiCacheService, PoiCacheServiceError,
        PoiCacheServiceRuntime, PoiCacheSyncScope, PoiCorpusCompactionLane,
        PoiCorpusCompactionRequest, PoiListSourceOutcome, PoiRpcAttemptOutcome, PoiSourceHealth,
        PreparedPoiCacheBatch, PreparedPoiCacheCandidate, PreparedPoiCachePersistence,
        PreparedPublicRpcPersistence, StagedPoiCacheCandidate, apply_poi_cache_demand_update,
        apply_staged_poi_cache_batch, cancel_active_attempt, cancel_poi_corpus_compaction_lane,
        chain_poi_cache_list_progress, drop_completed_attempt, effective_poi_cache_scope,
        enqueue_poi_corpus_compactions, finish_chain_poi_cache_attempt,
        install_cache_if_not_behind, new_poi_artifact_cache_progress, poi_cache_demand,
        poi_cache_error_diagnostic, produce_chain_poi_cache_candidates, public_rpc_candidate_cache,
        publish_active_attempt_progress,
        publish_chain_poi_cache_ready_and_acknowledge_initialization, record_list_source_outcomes,
        replacement_poi_cache_scope, run_background_poi_corpus_compaction, single_list_event_index,
        source_health_for_lists, stage_poi_cache_candidate, start_next_poi_corpus_compaction,
        validate_artifact_manifest_sequences, wait_for_active_poi_corpus_compaction,
    };
    use crate::chain::PoiArtifactPersistenceHandle;
    use crate::poi_artifacts::test_support::{load_persisted_cache, persist_public_rpc_cache};
    use crate::poi_artifacts::{
        ExpectedPoiCorpusBase, clear_poi_artifact_cache_for_reset,
        load_persisted_cache_candidate_for_publisher, record_poi_rpc_success,
    };
    use crate::types::PoiCorpusRevision;
    use crate::types::{
        LocalPoiCaches, PoiArtifactCacheAttemptId, PoiArtifactCacheFailureKind,
        PoiArtifactCacheGraphProgress, PoiArtifactCachePhase, PoiArtifactCacheProgress,
        PoiArtifactManifestSource, PoiArtifactSourceConfig, WalletCurrentSnapshot,
        WalletObservation, WalletPendingOverlay, WalletPpoiWorkflowStatus, WalletReadiness,
        WalletViewState,
    };
    use crate::wallet::test_support::{LivePoiTailError, live_tail_candidate_cache};
    use alloy::primitives::{FixedBytes, U256};
    use broadcaster_core::transact::DEFAULT_TXID_VERSION;
    use ed25519_dalek::{Signer, SigningKey};
    use local_db::{
        DbConfig, DbStore, POI_CORPUS_JOURNAL_SOFT_DELTA_COUNT, PoiArtifactCacheRecord,
        PoiArtifactDescriptorRecord, PoiCacheRecordSource, PoiCorpusJournalHeadRecord,
        PoiCorpusValidationRecord,
    };
    use poi::artifacts::SnapshotEvent;
    use poi::artifacts::verify::canonical_poi_event_message;
    use poi::cache::{PoiCache, PoiCacheError, PoiCacheIdentity, PoiCacheJournalDelta};
    use poi::error::PoiRpcError;
    use poi::poi::{
        BlockedShield, PoiEventType, PoiRpcClient, PoiSyncedListEvent, SignedPoiEvent,
        default_active_poi_list_key,
    };
    use railgun_wallet::{Note, PoiStatus, Utxo, UtxoCommitmentKind, UtxoSource, WalletUtxo};
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::mpsc::{self, Receiver};
    use std::sync::{Arc, Mutex as StdMutex};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    use tokio::sync::watch;
    use tokio::time::Instant as TokioInstant;
    use tokio_util::sync::CancellationToken;
    use url::Url;

    static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

    const fn attempt_id(value: u64) -> PoiArtifactCacheAttemptId {
        PoiArtifactCacheAttemptId::new(value)
    }

    fn test_persistence(db: &Arc<DbStore>) -> PoiArtifactPersistenceHandle {
        PoiArtifactPersistenceHandle::new(Arc::clone(db), Arc::new(tokio::sync::Mutex::new(())))
    }

    #[test]
    fn v4_candidate_batch_requires_one_global_manifest_sequence() {
        validate_artifact_manifest_sequences([10, 10].into_iter())
            .expect("matching manifest sequences");
        assert!(matches!(
            validate_artifact_manifest_sequences([9, 10].into_iter()),
            Err(PoiCacheServiceError::Refresh { .. })
        ));
    }

    #[test]
    fn maintenance_schedule_uses_demand_intervals_and_last_success() {
        let now = TokioInstant::now();
        let mut schedule = PoiCacheMaintenanceSchedule::new(now);
        assert_eq!(schedule.due_scope(now), Some(PoiCacheSyncScope::FULL));
        assert_eq!(
            PoiCacheSyncScope::EVENTS.union(PoiCacheSyncScope::BLOCKED_SHIELDS),
            PoiCacheSyncScope::FULL
        );

        schedule.record_success(PoiCacheSyncScope::FULL, now);
        schedule.update_demand(
            PoiCacheDemand {
                events: true,
                blocked_shields: true,
            },
            now + Duration::from_secs(1),
        );
        assert_eq!(
            schedule.due_scope(now + Duration::from_secs(1)),
            Some(PoiCacheSyncScope::FULL)
        );

        let active_success = now + Duration::from_secs(2);
        schedule.record_success(PoiCacheSyncScope::FULL, active_success);
        assert_eq!(
            schedule.event_deadline,
            active_success + POI_CACHE_EVENT_ACTIVE_INTERVAL
        );
        assert_eq!(
            schedule.blocked_shields_deadline,
            active_success + POI_CACHE_BLOCKED_ACTIVE_INTERVAL
        );

        schedule.update_demand(PoiCacheDemand::default(), now + Duration::from_secs(3));
        assert_eq!(
            schedule.event_deadline,
            active_success + POI_CACHE_EVENT_IDLE_INTERVAL
        );
        assert_eq!(
            schedule.blocked_shields_deadline,
            active_success + POI_CACHE_BLOCKED_IDLE_INTERVAL
        );

        let failed_at = active_success + Duration::from_secs(4);
        schedule.record_failure(PoiCacheSyncScope::BLOCKED_SHIELDS, failed_at);
        assert_eq!(
            schedule.blocked_shields_deadline,
            failed_at + POI_CACHE_FAILURE_RETRY_INTERVAL
        );
    }

    #[test]
    fn demand_activation_is_immediate_and_identity_fenced() {
        let now = TokioInstant::now();
        let mut schedule = PoiCacheMaintenanceSchedule::new(now);
        schedule.record_success(PoiCacheSyncScope::FULL, now);
        assert!(apply_poi_cache_demand_update(
            &mut schedule,
            2,
            PoiCacheDemand {
                events: true,
                blocked_shields: false,
            },
            now + Duration::from_secs(1),
        ));
        assert_eq!(
            schedule.due_scope(now + Duration::from_secs(1)),
            Some(PoiCacheSyncScope::EVENTS)
        );
        assert!(!apply_poi_cache_demand_update(
            &mut schedule,
            1,
            PoiCacheDemand::default(),
            now + Duration::from_secs(2),
        ));
        assert!(schedule.demand.events);
    }

    #[test]
    fn event_scope_requires_initialized_blocked_shield_snapshots() {
        let list_key = FixedBytes::from([0x12; 32]);
        let mut initialized = cache_with_events(
            PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key),
            &[snapshot_event(0, FixedBytes::from([0x34; 32]))],
        );
        initialized
            .apply_blocked_shields(&[])
            .expect("mark blocked snapshot initialized");

        assert_eq!(
            effective_poi_cache_scope(
                PoiCacheSyncScope::EVENTS,
                &BTreeMap::from([(list_key, initialized)]),
                &[list_key],
            ),
            PoiCacheSyncScope::EVENTS
        );

        let missing = cache_with_events(
            PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key),
            &[snapshot_event(0, FixedBytes::from([0x34; 32]))],
        );
        assert_eq!(
            effective_poi_cache_scope(
                PoiCacheSyncScope::EVENTS,
                &BTreeMap::from([(list_key, missing)]),
                &[list_key],
            ),
            PoiCacheSyncScope::FULL
        );
        assert_eq!(
            effective_poi_cache_scope(PoiCacheSyncScope::EVENTS, &BTreeMap::new(), &[list_key],),
            PoiCacheSyncScope::FULL
        );
        assert_eq!(
            effective_poi_cache_scope(
                PoiCacheSyncScope::BLOCKED_SHIELDS,
                &BTreeMap::new(),
                &[list_key],
            ),
            PoiCacheSyncScope::BLOCKED_SHIELDS
        );
    }

    #[test]
    fn event_retry_replaces_active_full_scope_without_dropping_blocked_work() {
        let active = ActivePoiCacheAttempt {
            id: attempt_id(1),
            generation: 0,
            scope: PoiCacheSyncScope::FULL,
            cancel: CancellationToken::new(),
            job: Box::pin(std::future::pending()),
            retry_completion: None,
        };

        assert_eq!(
            replacement_poi_cache_scope(PoiCacheSyncScope::EVENTS, Some(&active)),
            PoiCacheSyncScope::FULL
        );
        assert_eq!(
            replacement_poi_cache_scope(PoiCacheSyncScope::EVENTS, None),
            PoiCacheSyncScope::EVENTS
        );
    }

    #[test]
    fn demand_derivation_uses_unspent_current_and_pending_utxos() {
        let list_key = FixedBytes::from([0x11; 32]);
        let mut transact = demand_utxo(1, UtxoCommitmentKind::Transact);
        transact
            .utxo
            .poi
            .statuses
            .insert(list_key, PoiStatus::Missing);
        let mut shield = demand_utxo(2, UtxoCommitmentKind::Shield);
        shield
            .utxo
            .poi
            .statuses
            .insert(list_key, PoiStatus::Unknown);
        let mut spent = demand_utxo(3, UtxoCommitmentKind::Shield);
        spent.spent = Some(UtxoSource {
            tx_hash: FixedBytes::from([0x33; 32]),
            block_number: 3,
            block_timestamp: 3,
        });
        let pending = demand_utxo(4, UtxoCommitmentKind::Transact);

        let demand = poi_cache_demand(
            &demand_observation(
                vec![transact, shield, spent],
                WalletPendingOverlay {
                    new_utxos: vec![pending],
                    ..WalletPendingOverlay::default()
                },
                WalletPpoiWorkflowStatus::default(),
            ),
            &[list_key],
        );
        assert_eq!(
            demand,
            PoiCacheDemand {
                events: true,
                blocked_shields: true,
            }
        );

        let workflow = poi_cache_demand(
            &demand_observation(
                Vec::new(),
                WalletPendingOverlay::default(),
                WalletPpoiWorkflowStatus {
                    awaiting_poi_data: 1,
                    awaiting_validation: 1,
                    ..WalletPpoiWorkflowStatus::default()
                },
            ),
            &[list_key],
        );
        assert_eq!(
            workflow,
            PoiCacheDemand {
                events: true,
                blocked_shields: false,
            }
        );

        let reset = WalletObservation::new(
            WalletViewState::ResetPending {
                intent_id: 1,
                from_block: 2,
                reset_generation: 3,
            },
            WalletReadiness::Syncing,
        );
        assert_eq!(
            poi_cache_demand(&reset, &[list_key]),
            PoiCacheDemand::default()
        );
    }

    #[test]
    fn artifact_success_forces_rpc_probe_and_rpc_success_recovers_health() {
        let list_key = FixedBytes::from([0x91; 32]);
        let mut health = PoiSourceHealth::new(Some(Instant::now()));
        health.consecutive_rpc_failures = 3;
        assert!(health.artifact_eligible());
        assert!(health.attempt_plan(true).use_artifact);

        health.record(&PoiListSourceOutcome {
            list_key,
            rpc: None,
            artifact_succeeded: true,
        });

        let forced_probe = health.attempt_plan(true);
        assert!(!forced_probe.use_artifact);
        assert!(!forced_probe.artifact_after_rpc_failure);

        health.record(&PoiListSourceOutcome {
            list_key,
            rpc: Some(PoiRpcAttemptOutcome::Succeeded {
                backlog_large: false,
            }),
            artifact_succeeded: false,
        });

        assert_eq!(health.consecutive_rpc_failures, 0);
        assert!(health.rpc_stale_at.is_some());
        assert!(!health.force_rpc_probe);
        assert!(!health.attempt_plan(true).use_artifact);
    }

    #[test]
    fn mixed_list_source_health_reaches_artifact_eligibility_independently() {
        let healthy_key = FixedBytes::from([0x92; 32]);
        let failing_key = FixedBytes::from([0x93; 32]);
        let mut health = BTreeMap::from([
            (healthy_key, PoiSourceHealth::new(None)),
            (failing_key, PoiSourceHealth::new(None)),
        ]);

        record_list_source_outcomes(
            &mut health,
            &[
                PoiListSourceOutcome {
                    list_key: healthy_key,
                    rpc: Some(PoiRpcAttemptOutcome::Succeeded {
                        backlog_large: true,
                    }),
                    artifact_succeeded: false,
                },
                PoiListSourceOutcome {
                    list_key: failing_key,
                    rpc: Some(PoiRpcAttemptOutcome::Failed),
                    artifact_succeeded: false,
                },
            ],
        );
        assert!(health[&healthy_key].artifact_acceleration_needed);
        assert!(!health[&failing_key].artifact_acceleration_needed);
        assert_eq!(health[&failing_key].consecutive_rpc_failures, 1);

        for _ in 0..2 {
            record_list_source_outcomes(
                &mut health,
                &[
                    PoiListSourceOutcome {
                        list_key: healthy_key,
                        rpc: Some(PoiRpcAttemptOutcome::Succeeded {
                            backlog_large: false,
                        }),
                        artifact_succeeded: false,
                    },
                    PoiListSourceOutcome {
                        list_key: failing_key,
                        rpc: Some(PoiRpcAttemptOutcome::Failed),
                        artifact_succeeded: false,
                    },
                ],
            );
        }

        assert_eq!(health[&healthy_key].consecutive_rpc_failures, 0);
        assert!(health[&healthy_key].rpc_stale_at.is_some());
        assert!(!health[&healthy_key].attempt_plan(true).use_artifact);
        assert_eq!(health[&failing_key].consecutive_rpc_failures, 3);
        assert!(health[&failing_key].rpc_stale_at.is_none());
        assert!(health[&failing_key].attempt_plan(true).use_artifact);
    }

    #[tokio::test]
    async fn empty_rpc_source_success_persists_health_without_creating_corpus() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let list_key = default_active_poi_list_key();
        let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
        let mock = spawn_poi_rpc_sequence(vec![serde_json::json!([]), serde_json::json!([])]);
        let result = public_rpc_candidate_cache(
            &PoiRpcClient::new(mock.url.clone()),
            PoiCache::new(identity.clone()),
            PoiCacheSyncScope::FULL,
        )
        .await
        .expect("empty public RPC synchronization succeeds");
        assert!(result.candidate.is_none());
        assert!(!result.outcome.changed);
        let event_request = mock
            .requests
            .recv_timeout(Duration::from_secs(2))
            .expect("empty event request");
        let blocked_request = mock
            .requests
            .recv_timeout(Duration::from_secs(2))
            .expect("empty blocked-shields request");
        assert_eq!(event_request["method"], "ppoi_poi_events");
        assert_eq!(blocked_request["method"], "ppoi_blocked_shields");
        assert!(mock.requests.try_recv().is_err());

        let generation = db
            .poi_artifact_cache_generation()
            .expect("cache generation");
        let local_caches = LocalPoiCaches::new();
        let (_command_tx, command_rx) = tokio::sync::mpsc::channel(1);
        let (job_tx, job_rx) = tokio::sync::mpsc::unbounded_channel();
        let (progress_tx, _) = tokio::sync::watch::channel(BTreeMap::new());
        let coordinator = ChainPoiCacheCoordinator {
            db: Arc::clone(&db),
            http_client: None,
            poi_rpc_url: mock.url.into(),
            artifact_config: artifact_config(),
            cache_generation: generation,
            chain_id: 1,
            local_caches: local_caches.clone(),
            active_list_keys: vec![list_key],
            preloaded_caches: BTreeMap::new(),
            installed_head_anchors: StdMutex::new(BTreeMap::new()),
            command_rx,
            job_tx,
            job_rx,
            progress_tx,
            cancel: tokio_util::sync::CancellationToken::new(),
            runtime: Arc::new(PoiCacheServiceRuntime::new()),
            poi_artifact_persistence: test_persistence(&db),
        };
        finish_chain_poi_cache_attempt(
            &coordinator,
            attempt_id(1),
            generation,
            PreparedPoiCacheBatch {
                candidates: Vec::new(),
                source_outcomes: vec![PoiListSourceOutcome {
                    list_key,
                    rpc: Some(PoiRpcAttemptOutcome::Succeeded {
                        backlog_large: result.outcome.event_page_budget_exhausted,
                    }),
                    artifact_succeeded: false,
                }],
                actual_scope: PoiCacheSyncScope::FULL,
                result: Ok(()),
            },
        )
        .await
        .result
        .expect("persist empty RPC source health");

        assert!(local_caches.read().await.is_empty());
        assert!(
            db.get_poi_artifact_cache(
                identity.chain_type,
                identity.chain_id,
                &identity.txid_version,
                &identity.list_key,
            )
            .expect("load absent empty corpus")
            .is_none()
        );
        let health = db
            .get_poi_corpus_rpc_health(
                identity.chain_type,
                identity.chain_id,
                &identity.txid_version,
                &identity.list_key,
            )
            .expect("load empty RPC health")
            .expect("empty RPC health");
        assert_eq!(health.cache_generation, generation);
        assert!(health.last_successful_rpc_sync_at_ms.is_some());

        drop(coordinator);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn public_rpc_candidate_reuses_validated_roots_but_revalidates_pending_roots() {
        let list_key = default_active_poi_list_key();
        let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
        let unchanged = spawn_poi_rpc_sequence(vec![serde_json::json!([])]);
        let unchanged_result = public_rpc_candidate_cache(
            &PoiRpcClient::new(unchanged.url.clone()),
            cache_with_events(
                identity.clone(),
                &[snapshot_event(0, FixedBytes::from([0x55; 32]))],
            ),
            PoiCacheSyncScope::EVENTS,
        )
        .await
        .expect("unchanged validated roots");
        assert!(unchanged_result.candidate.is_none());
        assert_eq!(
            unchanged
                .requests
                .recv_timeout(Duration::from_secs(2))
                .expect("event request")["method"],
            "ppoi_poi_events"
        );
        assert!(unchanged.requests.try_recv().is_err());

        let mut pending =
            cache_with_events(identity, &[snapshot_event(0, FixedBytes::from([0x55; 32]))]);
        pending
            .apply_verified_artifact_events(&[snapshot_event(1, FixedBytes::from([0x66; 32]))])
            .expect("mutate event corpus");
        let retry = spawn_poi_rpc_sequence(vec![serde_json::json!([]), serde_json::json!(true)]);
        public_rpc_candidate_cache(
            &PoiRpcClient::new(retry.url.clone()),
            pending,
            PoiCacheSyncScope::EVENTS,
        )
        .await
        .expect("pending roots revalidated");
        let methods = [
            retry
                .requests
                .recv_timeout(Duration::from_secs(2))
                .expect("pending event request"),
            retry
                .requests
                .recv_timeout(Duration::from_secs(2))
                .expect("root validation request"),
        ];
        assert_eq!(methods[0]["method"], "ppoi_poi_events");
        assert_eq!(methods[1]["method"], "ppoi_validate_poi_merkleroots");
    }

    #[tokio::test]
    async fn blocked_only_candidate_keeps_empty_event_delta_for_persistence() {
        let list_key = default_active_poi_list_key();
        let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
        let mock = spawn_poi_rpc_sequence(vec![serde_json::json!([])]);
        let result = public_rpc_candidate_cache(
            &PoiRpcClient::new(mock.url.clone()),
            cache_with_events(identity, &[snapshot_event(0, FixedBytes::from([0x77; 32]))]),
            PoiCacheSyncScope::BLOCKED_SHIELDS,
        )
        .await
        .expect("blocked-only candidate");

        let candidate = result
            .candidate
            .expect("changed blocked snapshot candidate");
        assert!(candidate.delta.is_empty());
        assert_eq!(candidate.blocked_shields, Some(Vec::new()));
        assert_eq!(
            mock.requests
                .recv_timeout(Duration::from_secs(2))
                .expect("blocked-shields request")["method"],
            "ppoi_blocked_shields"
        );
    }

    #[tokio::test]
    async fn durable_base_read_error_skips_network_candidate_work() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let list_key = default_active_poi_list_key();
        let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
        let generation = db
            .poi_artifact_cache_generation()
            .expect("cache generation");
        let persisted =
            persisted_public_rpc_journal_with_delta_count(db.as_ref(), &identity, generation, 0);
        let installed_cache = persisted.cache.clone();
        let installed_head = persisted.journal_head.expect("installed journal head");
        db.put_app_settings_record("poi_artifact_cache_generation", b"invalid-generation")
            .expect("corrupt generation setting");
        let rpc = spawn_stalled_http_server();
        let (event_tx, _event_rx) = tokio::sync::mpsc::unbounded_channel();

        let batch = produce_chain_poi_cache_candidates(PoiCacheCandidateJob {
            db: Arc::clone(&db),
            http_client: None,
            poi_rpc_url: rpc.url.clone().into(),
            artifact_config: artifact_config(),
            chain_id: 1,
            active_list_keys: vec![list_key],
            baseline: BTreeMap::from([(list_key, installed_cache.clone())]),
            installed_head_anchors: BTreeMap::from([(list_key, installed_head)]),
            preloaded_caches: BTreeMap::new(),
            attempt_id: attempt_id(1),
            generation,
            ready: true,
            source_plans: BTreeMap::from([(
                list_key,
                PoiSourceHealth::new(None).attempt_plan(true),
            )]),
            scope: PoiCacheSyncScope::FULL,
            event_tx,
            cancel: CancellationToken::new(),
            poi_artifact_persistence: test_persistence(&db),
        })
        .await;

        assert!(batch.result.is_err());
        assert!(batch.candidates.is_empty());
        assert!(batch.source_outcomes.is_empty());
        assert!(rpc.accepted.try_recv().is_err());
        assert_eq!(installed_cache.progress().next_event_index, 1);

        drop(rpc);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn health_only_restart_probes_rpc_before_artifact() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp db");
        let list_key = default_active_poi_list_key();
        let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
        let generation = db
            .poi_artifact_cache_generation()
            .expect("cache generation");
        record_poi_rpc_success(&db, &identity, generation).expect("persist empty RPC health");
        assert!(
            db.get_poi_artifact_cache(
                identity.chain_type,
                identity.chain_id,
                &identity.txid_version,
                &identity.list_key,
            )
            .expect("load absent corpus")
            .is_none()
        );
        drop(db);

        let reopened = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("reopen temp db"),
        );
        let health = source_health_for_lists(
            reopened.as_ref(),
            1,
            generation,
            &[list_key],
            &BTreeMap::new(),
        );
        assert!(!health[&list_key].attempt_plan(false).use_artifact);

        let rpc = spawn_poi_rpc_sequence(vec![serde_json::json!([]), serde_json::json!([])]);
        let artifact = spawn_stalled_http_server();
        let service = PoiCacheService::new(
            Arc::clone(&reopened),
            artifact_config_with_url(artifact.url.clone()),
            None,
        )
        .expect("initialize POI cache service")
        .with_poi_rpc_url(rpc.url.clone())
        .with_active_list_keys(vec![list_key]);
        service.start_chain(1).await.expect("start chain");

        let event_request = rpc
            .requests
            .recv_timeout(Duration::from_secs(2))
            .expect("recently healthy public RPC receives the first request");
        assert_eq!(event_request["method"], "ppoi_poi_events");
        assert!(
            artifact.accepted.try_recv().is_err(),
            "artifact source must not be contacted before recently healthy RPC"
        );
        let blocked_request = rpc
            .requests
            .recv_timeout(Duration::from_secs(2))
            .expect("empty blocked-shields request");
        assert_eq!(blocked_request["method"], "ppoi_blocked_shields");

        service.shutdown().await;
        drop(service);
        drop(artifact);
        drop(reopened);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn empty_rpc_success_persists_health_without_rewriting_corpus() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let list_key = default_active_poi_list_key();
        let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
        let cache = cache_with_events(
            identity.clone(),
            &[snapshot_event(0, FixedBytes::from([0x94; 32]))],
        );
        let generation = db
            .poi_artifact_cache_generation()
            .expect("cache generation");
        persist_public_rpc_cache(
            &db,
            &cache,
            generation,
            0,
            ExpectedPoiCorpusBase::NoValidCorpus,
        )
        .expect("persist initial public corpus");
        let mut stale_record = db
            .get_poi_artifact_cache(
                identity.chain_type,
                identity.chain_id,
                &identity.txid_version,
                &identity.list_key,
            )
            .expect("load initial corpus")
            .expect("initial corpus");
        stale_record.legacy_last_successful_rpc_sync_at_ms = Some(1);
        db.put_poi_artifact_cache(&stale_record)
            .expect("store stale embedded health");
        let corpus_before = db
            .get_poi_artifact_cache(
                identity.chain_type,
                identity.chain_id,
                &identity.txid_version,
                &identity.list_key,
            )
            .expect("load corpus before health update")
            .expect("corpus before health update");

        let local_caches = LocalPoiCaches::new_for_test(BTreeMap::from([(list_key, cache)]));
        let (_command_tx, command_rx) = tokio::sync::mpsc::channel(1);
        let (job_tx, job_rx) = tokio::sync::mpsc::unbounded_channel();
        let (progress_tx, _) = tokio::sync::watch::channel(BTreeMap::new());
        let coordinator = ChainPoiCacheCoordinator {
            db: Arc::clone(&db),
            http_client: None,
            poi_rpc_url: Url::parse("http://127.0.0.1:1")
                .expect("POI RPC URL")
                .into(),
            artifact_config: artifact_config(),
            cache_generation: generation,
            chain_id: 1,
            local_caches,
            active_list_keys: vec![list_key],
            preloaded_caches: BTreeMap::new(),
            installed_head_anchors: StdMutex::new(BTreeMap::new()),
            command_rx,
            job_tx,
            job_rx,
            progress_tx,
            cancel: tokio_util::sync::CancellationToken::new(),
            runtime: Arc::new(PoiCacheServiceRuntime::new()),
            poi_artifact_persistence: test_persistence(&db),
        };
        finish_chain_poi_cache_attempt(
            &coordinator,
            attempt_id(1),
            generation,
            PreparedPoiCacheBatch {
                candidates: Vec::new(),
                source_outcomes: vec![PoiListSourceOutcome {
                    list_key,
                    rpc: Some(PoiRpcAttemptOutcome::Succeeded {
                        backlog_large: false,
                    }),
                    artifact_succeeded: false,
                }],
                actual_scope: PoiCacheSyncScope::FULL,
                result: Ok(()),
            },
        )
        .await
        .result
        .expect("commit empty RPC health update");
        let corpus_after = db
            .get_poi_artifact_cache(
                identity.chain_type,
                identity.chain_id,
                &identity.txid_version,
                &identity.list_key,
            )
            .expect("load corpus after health update")
            .expect("corpus after health update");
        assert_eq!(corpus_after, corpus_before);

        drop(coordinator);
        drop(db);
        let reopened = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("reopen db");
        let persisted = load_persisted_cache(&reopened, &identity)
            .expect("load corpus after restart")
            .expect("persisted corpus after restart");
        let health = source_health_for_lists(
            &reopened,
            1,
            generation,
            &[list_key],
            &BTreeMap::from([(list_key, persisted)]),
        );
        assert!(health[&list_key].rpc_stale_at.is_some());
        assert!(!health[&list_key].attempt_plan(true).use_artifact);

        drop(reopened);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    struct MockPoiRpc {
        url: Url,
        requests: Receiver<serde_json::Value>,
    }

    struct StalledHttpServer {
        url: Url,
        accepted: Receiver<()>,
        release: Arc<AtomicBool>,
    }

    impl Drop for StalledHttpServer {
        fn drop(&mut self) {
            self.release.store(true, Ordering::Release);
        }
    }

    fn temp_db_root() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let counter = TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "railgun-poi-cache-service-test-{}-{nanos}-{counter}",
            std::process::id()
        ))
    }

    fn artifact_config() -> PoiArtifactSourceConfig {
        PoiArtifactSourceConfig {
            trusted_publisher_pubkey: FixedBytes::from([0x22; 32]),
            manifest_source: PoiArtifactManifestSource::Url(
                Url::parse("http://127.0.0.1:1/manifest")
                    .expect("manifest URL")
                    .into(),
            ),
            gateway_urls: vec![
                Url::parse("http://127.0.0.1:1")
                    .expect("gateway URL")
                    .into(),
            ],
            max_manifest_age: None,
        }
    }

    fn artifact_config_with_url(url: Url) -> PoiArtifactSourceConfig {
        PoiArtifactSourceConfig {
            trusted_publisher_pubkey: FixedBytes::from([0x22; 32]),
            manifest_source: PoiArtifactManifestSource::Url(url.clone().into()),
            gateway_urls: vec![url.into()],
            max_manifest_age: None,
        }
    }

    fn snapshot_event(index: u64, blinded_commitment: FixedBytes<32>) -> SnapshotEvent {
        SnapshotEvent {
            event_index: index,
            blinded_commitment: *blinded_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }
    }

    fn cache_with_events(identity: PoiCacheIdentity, events: &[SnapshotEvent]) -> PoiCache {
        let mut cache = PoiCache::new(identity);
        cache
            .apply_verified_artifact_events(events)
            .expect("apply cache events");
        cache.accept_current_roots();
        cache
    }

    fn demand_utxo(position: u64, kind: UtxoCommitmentKind) -> WalletUtxo {
        WalletUtxo::new(Utxo::new(
            Note {
                token_hash: U256::from(1),
                value: U256::from(10),
                random: [0; 16],
                npk: U256::from(2),
            },
            0,
            position,
            UtxoSource {
                tx_hash: FixedBytes::from([position as u8; 32]),
                block_number: position,
                block_timestamp: position,
            },
            kind,
        ))
    }

    fn demand_observation(
        utxos: Vec<WalletUtxo>,
        overlay: WalletPendingOverlay,
        workflow: WalletPpoiWorkflowStatus,
    ) -> WalletObservation {
        WalletObservation::with_ppoi_workflow_status(
            WalletViewState::Current(WalletCurrentSnapshot::new(0, 0, 0, utxos, overlay)),
            WalletReadiness::Ready,
            workflow,
        )
    }

    fn persisted_public_rpc_journal_with_delta_count(
        db: &DbStore,
        identity: &PoiCacheIdentity,
        generation: u64,
        delta_count: u32,
    ) -> PersistedPoiArtifactCache {
        let mut cache = PoiCache::new(identity.clone());
        for event_index in 0..=u64::from(delta_count) {
            let mut commitment = [0_u8; 32];
            commitment[24..].copy_from_slice(&event_index.to_be_bytes());
            cache
                .apply_verified_artifact_events(&[snapshot_event(
                    event_index,
                    FixedBytes::from(commitment),
                )])
                .expect("append test journal event");
            cache.accept_current_roots();
            let expected_base = if event_index == 0 {
                ExpectedPoiCorpusBase::NoValidCorpus
            } else {
                load_persisted_cache(db, identity)
                    .expect("load prior test journal state")
                    .expect("prior test journal state")
                    .expected_base()
            };
            persist_public_rpc_cache(db, &cache, generation, event_index, expected_base)
                .expect("persist test journal revision");
        }
        load_persisted_cache(db, identity)
            .expect("load completed test journal")
            .expect("completed test journal")
    }

    fn compaction_test_coordinator(
        db: &Arc<DbStore>,
        local_caches: LocalPoiCaches,
        list_key: FixedBytes<32>,
        anchor: PoiCorpusJournalHeadRecord,
    ) -> (
        ChainPoiCacheCoordinator,
        watch::Receiver<BTreeMap<u64, PoiArtifactCacheProgress>>,
        Arc<tokio::sync::Mutex<()>>,
    ) {
        let (_command_tx, command_rx) = tokio::sync::mpsc::channel(1);
        let (job_tx, job_rx) = tokio::sync::mpsc::unbounded_channel();
        let (progress_tx, progress_rx) = tokio::sync::watch::channel(BTreeMap::new());
        let commit_fence = Arc::new(tokio::sync::Mutex::new(()));
        (
            ChainPoiCacheCoordinator {
                db: Arc::clone(db),
                http_client: None,
                poi_rpc_url: Url::parse("http://127.0.0.1:1")
                    .expect("POI RPC URL")
                    .into(),
                artifact_config: artifact_config(),
                cache_generation: db
                    .poi_artifact_cache_generation()
                    .expect("cache generation"),
                chain_id: 1,
                local_caches,
                active_list_keys: vec![list_key],
                preloaded_caches: BTreeMap::new(),
                installed_head_anchors: StdMutex::new(BTreeMap::from([(list_key, anchor)])),
                command_rx,
                job_tx,
                job_rx,
                progress_tx,
                cancel: CancellationToken::new(),
                runtime: Arc::new(PoiCacheServiceRuntime::new()),
                poi_artifact_persistence: PoiArtifactPersistenceHandle::new(
                    Arc::clone(db),
                    Arc::clone(&commit_fence),
                ),
            },
            progress_rx,
            commit_fence,
        )
    }

    fn public_rpc_candidate_for_test(
        list_key: FixedBytes<32>,
        cache: PoiCache,
        range_start_index: u64,
        expected_base: ExpectedPoiCorpusBase,
        starting_record: Option<PoiArtifactCacheRecord>,
        starting_head: Option<PoiCorpusJournalHeadRecord>,
    ) -> PreparedPoiCacheCandidate {
        let event_end_cursor = cache.progress().next_event_index;
        let mut events = Vec::new();
        let mut leaves = Vec::new();
        for event_index in range_start_index..event_end_cursor {
            let blinded_commitment = cache
                .commitment_at_global_index(event_index)
                .expect("test journal delta commitment");
            events.push(poi::cache::PoiCacheJournalEvent {
                event_index,
                blinded_commitment,
            });
            leaves.push(blinded_commitment);
        }
        let delta = PoiCacheJournalDelta {
            version: poi::cache::POI_CACHE_JOURNAL_DELTA_VERSION,
            identity: cache.identity().clone(),
            event_start_cursor: range_start_index,
            event_end_cursor,
            leaf_start_cursor: range_start_index,
            leaf_end_cursor: cache.progress().next_leaf_index,
            events,
            leaves,
        };
        PreparedPoiCacheCandidate {
            list_key,
            cache: Some(cache),
            persistence: PreparedPoiCachePersistence::PublicRpc {
                prepared: Box::new(PreparedPublicRpcPersistence {
                    range_start_index,
                    expected_base,
                    starting_record,
                    starting_head,
                    delta,
                    blocked_shields: None,
                }),
            },
        }
    }

    #[tokio::test]
    async fn chain_poi_cache_list_progress_reports_each_active_list() {
        let first_key = default_active_poi_list_key();
        let second_key = FixedBytes::from([7_u8; 32]);
        let first_identity =
            PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, first_key);
        let second_identity =
            PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, second_key);
        let first_cache = cache_with_events(
            first_identity,
            &[snapshot_event(0, FixedBytes::from([1_u8; 32]))],
        );
        let second_cache = cache_with_events(
            second_identity,
            &[
                snapshot_event(0, FixedBytes::from([2_u8; 32])),
                snapshot_event(1, FixedBytes::from([3_u8; 32])),
            ],
        );
        let local_caches = LocalPoiCaches::new_for_test(BTreeMap::from([
            (first_key, first_cache),
            (second_key, second_cache),
        ]));
        let active_list_keys = vec![first_key, second_key];

        let list_progress =
            chain_poi_cache_list_progress(1, &local_caches, &active_list_keys).await;

        assert_eq!(list_progress.len(), 2);
        assert_eq!(list_progress[0].list_key, first_key);
        assert_eq!(list_progress[0].current_event_index, Some(0));
        assert_eq!(list_progress[0].target_event_index, Some(0));
        assert!(list_progress[0].ready_for_wallet_checks);
        assert_eq!(list_progress[1].list_key, second_key);
        assert_eq!(list_progress[1].current_event_index, Some(1));
        assert_eq!(list_progress[1].target_event_index, Some(1));
        assert!(list_progress[1].ready_for_wallet_checks);
        assert_eq!(single_list_event_index(&list_progress), (None, None));
    }

    fn persist_cache(db: &DbStore, cache: &PoiCache) {
        let identity = cache.identity();
        let cache_generation = db
            .poi_artifact_cache_generation()
            .expect("load cache generation");
        let current_tip_index = cache.progress().next_event_index.saturating_sub(1);
        let current_tip_root = *cache
            .clone()
            .current_roots()
            .get(&0)
            .expect("cache has current tree root");
        db.put_poi_artifact_cache(&PoiArtifactCacheRecord {
            chain_type: identity.chain_type,
            chain_id: identity.chain_id,
            txid_version: identity.txid_version.clone(),
            list_key: identity.list_key,
            cache_generation,
            source: PoiCacheRecordSource::IndexedArtifacts,
            validation: PoiCorpusValidationRecord::PublisherAttested {
                publisher_pubkey: FixedBytes::from([0x22; 32]),
                manifest_sequence: 1,
                manifest_root: current_tip_root,
                artifact_tip_index: current_tip_index,
            },
            legacy_observed_manifest_sequence: 1,
            base_descriptor: test_descriptor_record("base"),
            applied_delta_descriptors: Vec::new(),
            blocked_shields_descriptor: test_descriptor_record("blocked"),
            artifact_tip_index: Some(current_tip_index),
            artifact_tip_root: Some(current_tip_root),
            current_tip_index,
            current_tip_root,
            cache_payload: cache.to_bytes().expect("cache bytes"),
            legacy_last_successful_rpc_sync_at_ms: None,
            updated_at: 0,
        })
        .expect("persist POI artifact cache");
    }

    fn test_descriptor_record(cid: &str) -> PoiArtifactDescriptorRecord {
        PoiArtifactDescriptorRecord {
            cid: cid.to_string(),
            sha256: "0x00".to_string(),
            byte_size: 0,
        }
    }

    async fn wait_for_progress(
        rx: &mut tokio::sync::watch::Receiver<BTreeMap<u64, PoiArtifactCacheProgress>>,
        chain_id: u64,
        predicate: impl Fn(&PoiArtifactCacheProgress) -> bool,
    ) -> PoiArtifactCacheProgress {
        for _ in 0..20 {
            if let Some(progress) = rx.borrow().get(&chain_id)
                && predicate(progress)
            {
                return progress.clone();
            }
            tokio::time::timeout(Duration::from_secs(15), rx.changed())
                .await
                .expect("progress update timeout")
                .expect("progress channel open");
        }
        panic!("expected progress update for chain {chain_id}");
    }

    fn spawn_poi_rpc_sequence(results: Vec<serde_json::Value>) -> MockPoiRpc {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock POI RPC");
        let url = Url::parse(&format!(
            "http://{}",
            listener.local_addr().expect("local addr")
        ))
        .expect("mock POI RPC URL");
        let (tx, requests) = mpsc::channel();
        std::thread::spawn(move || {
            for result in results {
                let (mut stream, _) = listener.accept().expect("accept request");
                let mut bytes = Vec::new();
                let mut buf = [0_u8; 1024];
                let (body_start, content_length) = loop {
                    let read = stream.read(&mut buf).expect("read request");
                    assert!(read > 0, "mock POI RPC closed before request body");
                    bytes.extend_from_slice(&buf[..read]);
                    if let Some(lengths) = http_body_bounds(&bytes) {
                        break lengths;
                    }
                };
                let body = &bytes[body_start..body_start + content_length];
                let request: serde_json::Value =
                    serde_json::from_slice(body).expect("request JSON");
                tx.send(request.clone()).expect("record request");
                let response = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": request["id"].clone(),
                    "result": result,
                })
                .to_string();
                let headers = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    response.len()
                );
                stream.write_all(headers.as_bytes()).expect("write headers");
                stream.write_all(response.as_bytes()).expect("write body");
            }
        });
        MockPoiRpc { url, requests }
    }

    fn spawn_stalled_http_server() -> StalledHttpServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stalled HTTP server");
        listener
            .set_nonblocking(true)
            .expect("set stalled HTTP listener nonblocking");
        let url = Url::parse(&format!(
            "http://{}",
            listener.local_addr().expect("stalled HTTP local addr")
        ))
        .expect("stalled HTTP URL");
        let (accepted_tx, accepted) = mpsc::channel();
        let release = Arc::new(AtomicBool::new(false));
        let thread_release = Arc::clone(&release);
        std::thread::spawn(move || {
            let mut streams = Vec::new();
            while !thread_release.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        streams.push(stream);
                        let _ = accepted_tx.send(());
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        StalledHttpServer {
            url,
            accepted,
            release,
        }
    }

    fn http_body_bounds(bytes: &[u8]) -> Option<(usize, usize)> {
        let body_start = bytes.windows(4).position(|window| window == b"\r\n\r\n")? + 4;
        let headers = std::str::from_utf8(&bytes[..body_start]).ok()?;
        let content_length = headers.lines().find_map(|line| {
            line.strip_prefix("content-length:")
                .or_else(|| line.strip_prefix("Content-Length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
        })?;
        (bytes.len() >= body_start + content_length).then_some((body_start, content_length))
    }

    #[tokio::test]
    async fn concurrent_start_reuses_local_cache_and_coordinator() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let service = Arc::new(
            PoiCacheService::new(db, artifact_config(), None)
                .expect("initialize POI cache generation"),
        );

        let (first, second) = tokio::join!(service.start_chain(1), service.start_chain(1));
        let first = first.expect("first chain start");
        let second = second.expect("concurrent chain start");
        assert!(first.ptr_eq(&second));
        assert!(first.ptr_eq(&service.local_caches));
        assert!(service.coordinator.lock().await.is_some());
        assert_eq!(service.progress_rx().borrow().len(), 1);
        service.shutdown().await;
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn started_chain_reuses_local_cache_during_public_cache_reset() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let service = PoiCacheService::new(db, artifact_config(), None)
            .expect("initialize POI cache service");
        let first = service.start_chain(1).await.expect("start chain");
        let first_command = service
            .coordinator
            .lock()
            .await
            .as_ref()
            .expect("started coordinator")
            .command_tx
            .clone();
        let reset = service.quiesce_for_public_cache_reset().await;

        let reused = tokio::time::timeout(Duration::from_millis(100), service.start_chain(1))
            .await
            .expect("started chain reuse must not wait for public cache reset")
            .expect("reuse started chain");

        assert!(first.ptr_eq(&reused));
        let current_command = service
            .coordinator
            .lock()
            .await
            .as_ref()
            .expect("reused coordinator")
            .command_tx
            .clone();
        assert!(first_command.same_channel(&current_command));

        drop(reset);
        service.shutdown().await;
        drop(service);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn initialization_waiters_release_coordinator_slot_mutex() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let service = Arc::new(
            PoiCacheService::new(db, artifact_config(), None)
                .expect("initialize POI cache service"),
        );

        let (command_tx, _command_rx) = tokio::sync::mpsc::channel(1);
        let (initialized_tx, initialized_rx) = tokio::sync::watch::channel(false);
        let (_stopped_tx, stopped_rx) = tokio::sync::watch::channel(false);
        *service.coordinator.lock().await = Some(super::ChainPoiCacheHandle {
            command_tx,
            initialized_rx,
            stopped_rx,
        });
        let caches = tokio::spawn({
            let service = Arc::clone(&service);
            async move { service.local_caches(1).await }
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while initialized_tx.receiver_count() < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("local cache waiter subscribed to initialization");
        let slot = tokio::time::timeout(Duration::from_millis(100), service.coordinator.lock())
            .await
            .expect("local cache waiter releases coordinator mutex");
        drop(slot);
        initialized_tx.send(true).expect("complete initialization");
        assert!(
            caches
                .await
                .expect("local cache task")
                .expect("local cache lookup")
                .is_some()
        );
        service.coordinator.lock().await.take();

        let (command_tx, _command_rx) = tokio::sync::mpsc::channel(1);
        let (initialized_tx, initialized_rx) = tokio::sync::watch::channel(false);
        let (_stopped_tx, stopped_rx) = tokio::sync::watch::channel(false);
        *service.coordinator.lock().await = Some(super::ChainPoiCacheHandle {
            command_tx,
            initialized_rx,
            stopped_rx,
        });
        let start = tokio::spawn({
            let service = Arc::clone(&service);
            async move { service.start_chain(1).await }
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while initialized_tx.receiver_count() < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("chain start waiter subscribed to initialization");
        let slot = tokio::time::timeout(Duration::from_millis(100), service.coordinator.lock())
            .await
            .expect("chain start waiter releases coordinator mutex");
        drop(slot);
        initialized_tx.send(true).expect("complete chain start");
        start
            .await
            .expect("chain start task")
            .expect("shared chain start");
        service.coordinator.lock().await.take();

        service.shutdown().await;
        drop(service);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn poi_cache_service_rejects_mismatched_chain() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let service = PoiCacheService::new(db, artifact_config(), None)
            .expect("initialize POI cache service");

        assert!(matches!(
            service.start_chain(137).await,
            Err(PoiCacheServiceError::ChainMismatch {
                expected: 1,
                actual: 137,
            })
        ));
        assert!(service.coordinator.lock().await.is_none());

        service.shutdown().await;
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn queued_public_cache_resets_quiesce_without_deadlock() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let service = Arc::new(
            PoiCacheService::new(db, artifact_config(), None)
                .expect("initialize POI cache service"),
        );
        service.start_chain(1).await.expect("start fixed chain");
        let first_attempt = service
            .progress_tx
            .borrow()
            .get(&1)
            .expect("initial cache attempt")
            .attempt_id;

        let first = service.quiesce_for_public_cache_reset().await;
        let queued_service = Arc::clone(&service);
        let queued_polled = Arc::new(AtomicBool::new(false));
        let queued = tokio::spawn({
            let queued_polled = Arc::clone(&queued_polled);
            async move {
                queued_polled.store(true, Ordering::Release);
                queued_service.quiesce_for_public_cache_reset().await
            }
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !queued_polled.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("queued reset reaches admission");
        assert!(!queued.is_finished());
        drop(first);

        let second = tokio::time::timeout(Duration::from_secs(1), queued)
            .await
            .expect("queued reset quiesces")
            .expect("queued reset task completes");
        drop(second);
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if service
                    .progress_tx
                    .borrow()
                    .get(&1)
                    .is_some_and(|progress| progress.attempt_id != first_attempt)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("reset release starts a new attempt");
        service.shutdown().await;
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn closed_initialization_removes_dead_chain_handle() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let service = PoiCacheService::new(Arc::clone(&db), artifact_config(), None)
            .expect("initialize POI cache service");
        let (command_tx, command_rx) = tokio::sync::mpsc::channel(1);
        drop(command_rx);
        let (initialized_tx, initialized_rx) = tokio::sync::watch::channel(false);
        drop(initialized_tx);
        let (stopped_tx, stopped_rx) = tokio::sync::watch::channel(false);
        drop(stopped_tx);
        *service.coordinator.lock().await = Some(super::ChainPoiCacheHandle {
            command_tx,
            initialized_rx,
            stopped_rx,
        });

        assert!(matches!(
            service.local_caches(1).await,
            Err(PoiCacheServiceError::CoordinatorStopped)
        ));
        assert!(service.coordinator.lock().await.is_none());
        let restarted = service
            .start_chain(1)
            .await
            .expect("restart after dead initialization");
        assert!(restarted.ptr_eq(&service.local_caches));

        service.shutdown().await;
        drop(service);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn shutdown_fenced_ready_failure_cannot_acknowledge_initialization() {
        let local_caches = LocalPoiCaches::new_for_test(BTreeMap::new());
        let runtime = PoiCacheServiceRuntime::new();
        runtime
            .publication_fence
            .lock()
            .expect("publication fence")
            .shutdown = true;
        let cancel = tokio_util::sync::CancellationToken::new();
        let (progress_tx, progress_rx) = tokio::sync::watch::channel(BTreeMap::new());
        let (initialized_tx, mut initialized_rx) = tokio::sync::watch::channel(false);

        let result = publish_chain_poi_cache_ready_and_acknowledge_initialization(
            &progress_tx,
            1,
            &local_caches,
            &[],
            attempt_id(1),
            0,
            &runtime,
            &cancel,
            initialized_tx,
        )
        .await;

        assert!(matches!(result, Err(PoiCacheServiceError::Shutdown { .. })));
        assert!(!*initialized_rx.borrow());
        assert!(initialized_rx.changed().await.is_err());
        assert!(progress_rx.borrow().is_empty());
    }

    #[tokio::test]
    async fn retry_response_closure_removes_dead_chain_handle() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let service = PoiCacheService::new(Arc::clone(&db), artifact_config(), None)
            .expect("initialize POI cache service");
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(1);
        let (initialized_tx, initialized_rx) = tokio::sync::watch::channel(true);
        let (stopped_tx, stopped_rx) = tokio::sync::watch::channel(false);
        let coordinator = tokio::spawn(async move {
            let Some(ChainPoiCacheCommand::Retry { scope, admission }) = command_rx.recv().await
            else {
                panic!("expected retry command");
            };
            assert_eq!(scope, PoiCacheSyncScope::FULL);
            drop(admission);
            drop(initialized_tx);
            drop(stopped_tx);
        });
        *service.coordinator.lock().await = Some(super::ChainPoiCacheHandle {
            command_tx,
            initialized_rx,
            stopped_rx,
        });

        assert!(matches!(
            service.retry_chain(1).await,
            Err(PoiCacheServiceError::CoordinatorStopped)
        ));
        assert!(service.coordinator.lock().await.is_none());
        coordinator.await.expect("coordinator task");

        service.shutdown().await;
        drop(service);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn retry_scope_wrappers_route_full_and_event_commands() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let service = PoiCacheService::new(Arc::clone(&db), artifact_config(), None)
            .expect("initialize POI cache service");
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(2);
        let (initialized_tx, initialized_rx) = tokio::sync::watch::channel(true);
        let (stopped_tx, stopped_rx) = tokio::sync::watch::channel(false);
        let coordinator = tokio::spawn(async move {
            for expected_scope in [PoiCacheSyncScope::FULL, PoiCacheSyncScope::EVENTS] {
                let Some(ChainPoiCacheCommand::Retry { scope, admission }) =
                    command_rx.recv().await
                else {
                    panic!("expected retry command");
                };
                assert_eq!(scope, expected_scope);
                assert!(
                    admission
                        .send(Err(PoiCacheServiceError::Refresh {
                            reason: "test scope routing".to_string(),
                        }))
                        .is_ok()
                );
            }
            drop(initialized_tx);
            drop(stopped_tx);
        });
        *service.coordinator.lock().await = Some(super::ChainPoiCacheHandle {
            command_tx,
            initialized_rx,
            stopped_rx,
        });

        assert!(matches!(
            service.retry_chain(1).await,
            Err(PoiCacheServiceError::Refresh { .. })
        ));
        assert!(matches!(
            service.retry_chain_events(1).await,
            Err(PoiCacheServiceError::Refresh { .. })
        ));
        coordinator.await.expect("coordinator task");

        service.shutdown().await;
        drop(service);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn start_chain_reports_persisted_cache_ready() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let list_key = default_active_poi_list_key();
        let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
        let cache = cache_with_events(identity, &[snapshot_event(0, FixedBytes::from([9_u8; 32]))]);
        persist_cache(db.as_ref(), &cache);
        let service = PoiCacheService::new(Arc::clone(&db), artifact_config(), None)
            .expect("initialize POI cache generation");

        service.start_chain(1).await.expect("start chain");

        let progress = service
            .progress_rx()
            .borrow()
            .get(&1)
            .cloned()
            .expect("progress");
        assert_eq!(progress.total_lists, 1);
        assert_eq!(progress.current_event_index, Some(0));
        assert_eq!(progress.list_progress.len(), 1);
        assert_eq!(progress.list_progress[0].list_key, list_key);
        assert_eq!(progress.list_progress[0].current_event_index, Some(0));
        assert!(progress.ready_for_wallet_checks);
        service.shutdown().await;
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn failed_rebuild_with_previous_cache_reports_nonblocking_error() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let list_key = default_active_poi_list_key();
        let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
        let cache = cache_with_events(identity, &[snapshot_event(0, FixedBytes::from([9_u8; 32]))]);
        persist_cache(db.as_ref(), &cache);
        let service = Arc::new(
            PoiCacheService::new(db, artifact_config(), None)
                .expect("initialize POI cache generation")
                .with_poi_rpc_url(Url::parse("http://127.0.0.1:1").expect("test POI RPC URL")),
        );
        let mut progress_rx = service.progress_rx();
        let starter = Arc::clone(&service);
        let start = tokio::spawn(async move {
            starter.start_chain(1).await.expect("start chain");
        });

        let progress =
            wait_for_progress(&mut progress_rx, 1, PoiArtifactCacheProgress::is_error).await;

        assert_eq!(progress.phase, PoiArtifactCachePhase::Failed);
        assert!(progress.ready_for_wallet_checks);
        assert_eq!(
            progress.failure_kind(),
            Some(PoiArtifactCacheFailureKind::RefreshDegraded)
        );
        assert_eq!(progress.completed_lists, 1);
        assert_eq!(progress.current_event_index, Some(0));
        assert_eq!(progress.target_event_index, Some(0));
        assert_eq!(progress.list_progress.len(), 1);
        assert_eq!(progress.list_progress[0].list_key, list_key);
        assert_eq!(progress.list_progress[0].current_event_index, Some(0));
        assert!(progress.last_error.is_some());
        start.await.expect("start chain task");
        service.shutdown().await;
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn failed_rebuild_without_previous_cache_reports_blocking_error() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let service = Arc::new(
            PoiCacheService::new(db, artifact_config(), None)
                .expect("initialize POI cache generation")
                .with_poi_rpc_url(Url::parse("http://127.0.0.1:1").expect("test POI RPC URL")),
        );
        let mut progress_rx = service.progress_rx();
        let starter = Arc::clone(&service);
        let start = tokio::spawn(async move {
            starter.start_chain(1).await.expect("start chain");
        });

        let progress =
            wait_for_progress(&mut progress_rx, 1, PoiArtifactCacheProgress::is_error).await;

        assert_eq!(progress.phase, PoiArtifactCachePhase::Failed);
        assert!(!progress.ready_for_wallet_checks);
        assert_eq!(
            progress.failure_kind(),
            Some(PoiArtifactCacheFailureKind::ServingCorpusUnavailable)
        );
        assert_eq!(progress.completed_lists, 0);
        assert!(progress.last_error.is_some());
        start.await.expect("start chain task");
        service.shutdown().await;
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn v4_warm_refresh_and_cold_startup_keep_readiness_independent_from_phase() {
        let warm_attempt_id = attempt_id(41);
        let warm = new_poi_artifact_cache_progress(
            warm_attempt_id,
            9,
            1,
            PoiArtifactCachePhase::ResolvingManifest,
            1,
            1,
            None,
            Some(7),
            Some(7),
            Vec::new(),
            PoiArtifactCacheGraphProgress::default(),
            true,
            None,
        );
        let cold = new_poi_artifact_cache_progress(
            attempt_id(42),
            10,
            1,
            PoiArtifactCachePhase::DownloadingChunks,
            0,
            1,
            None,
            None,
            Some(7),
            Vec::new(),
            PoiArtifactCacheGraphProgress {
                total_chunks: 2,
                total_authenticated_encoded_bytes: Some(1024),
                replay_start_event_index: Some(0),
                replay_end_event_index: Some(7),
                total_replay_event_count: 8,
                ..PoiArtifactCacheGraphProgress::default()
            },
            false,
            None,
        );

        assert!(warm.is_active());
        assert!(warm.ready_for_wallet_checks);
        assert_eq!(warm.attempt_id, warm_attempt_id);
        assert_eq!(warm.generation, 9);
        assert!(cold.is_active());
        assert!(!cold.ready_for_wallet_checks);
        assert!(!cold.is_ready());
    }

    #[test]
    fn shared_failure_diagnostic_redacts_rpc_message_and_response_data() {
        let error = PoiCacheError::Rpc(PoiRpcError::JsonRpc {
            code: -32_000,
            message: "raw-response-message-sentinel".to_string(),
            data: Some(serde_json::json!({
                "url": "https://user-sentinel:password-sentinel@host.invalid/path?token=sentinel"
            })),
        });

        let diagnostic = poi_cache_error_diagnostic(&error);

        assert_eq!(diagnostic, "POI cache RPC JSON-RPC error -32000");
        for sentinel in [
            "raw-response-message-sentinel",
            "user-sentinel",
            "password-sentinel",
            "token=sentinel",
        ] {
            assert!(!diagnostic.contains(sentinel), "leaked {sentinel}");
        }
    }

    #[test]
    fn persisted_rpc_health_older_than_freshness_window_is_immediately_stale() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp db");
        let list_key = default_active_poi_list_key();
        let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
        let cache = cache_with_events(
            identity.clone(),
            &[snapshot_event(0, FixedBytes::from([0x95; 32]))],
        );
        let generation = db
            .poi_artifact_cache_generation()
            .expect("cache generation");
        persist_public_rpc_cache(
            &db,
            &cache,
            generation,
            0,
            ExpectedPoiCorpusBase::NoValidCorpus,
        )
        .expect("persist public corpus");
        db.put_poi_corpus_rpc_health(&local_db::PoiCorpusRpcHealthRecord {
            chain_type: identity.chain_type,
            chain_id: identity.chain_id,
            txid_version: identity.txid_version.clone(),
            list_key,
            cache_generation: generation,
            last_successful_rpc_sync_at_ms: Some(0),
            updated_at: 0,
        })
        .expect("persist stale RPC health");

        let persisted = load_persisted_cache(&db, &identity)
            .expect("load corpus")
            .expect("persisted corpus");
        let health = source_health_for_lists(
            &db,
            1,
            generation,
            &[list_key],
            &BTreeMap::from([(list_key, persisted)]),
        );
        assert!(health[&list_key].attempt_plan(true).use_artifact);

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn artifact_candidate_install_does_not_roll_back_advanced_cache() {
        let list_key = FixedBytes::from([0x11; 32]);
        let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
        let artifact_commitment = FixedBytes::from([0x22; 32]);
        let live_tail_commitment = FixedBytes::from([0x33; 32]);
        let current_cache = cache_with_events(
            identity.clone(),
            &[
                snapshot_event(0, artifact_commitment),
                snapshot_event(1, live_tail_commitment),
            ],
        );
        let artifact_candidate =
            cache_with_events(identity, &[snapshot_event(0, artifact_commitment)]);
        let mut caches = BTreeMap::from([(list_key, current_cache)]);

        let installed = install_cache_if_not_behind(&mut caches, list_key, artifact_candidate);

        let current = caches.get(&list_key).expect("current cache");
        assert!(!installed);
        assert_eq!(current.progress().next_event_index, 2);
        assert!(current.position(&live_tail_commitment).is_some());
    }

    #[tokio::test]
    async fn blocked_only_staged_install_preserves_events_and_publishes_blocked_revision() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let list_key = default_active_poi_list_key();
        let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
        let event_commitment = FixedBytes::from([0x2a; 32]);
        let current = cache_with_events(identity, &[snapshot_event(0, event_commitment)]);
        let mut replacement = current.clone();
        replacement
            .replace_blocked_shields(&[BlockedShield {
                commitment_hash: alloy::hex::encode_prefixed([0x2b; 32]),
                blinded_commitment: alloy::hex::encode_prefixed([0x2c; 32]),
                block_reason: Some("replacement".to_string()),
                signature: alloy::hex::encode_prefixed([0x2d; 64]),
            }])
            .expect("replace blocked shields");
        let local_caches = LocalPoiCaches::new_for_test(BTreeMap::from([(list_key, current)]));
        let mut revision_rx = local_caches.committed_revision_rx();
        assert_eq!(
            *revision_rx.borrow(),
            PoiCorpusRevision {
                revision: 1,
                blocked_shields_revision: 1,
            }
        );
        let (_command_tx, command_rx) = tokio::sync::mpsc::channel(1);
        let (job_tx, job_rx) = tokio::sync::mpsc::unbounded_channel();
        let (progress_tx, _) = tokio::sync::watch::channel(BTreeMap::new());
        let coordinator = ChainPoiCacheCoordinator {
            db: Arc::clone(&db),
            http_client: None,
            poi_rpc_url: Url::parse("http://127.0.0.1:1")
                .expect("POI RPC URL")
                .into(),
            artifact_config: artifact_config(),
            cache_generation: db
                .poi_artifact_cache_generation()
                .expect("cache generation"),
            chain_id: 1,
            local_caches: local_caches.clone(),
            active_list_keys: vec![list_key],
            preloaded_caches: BTreeMap::new(),
            installed_head_anchors: StdMutex::new(BTreeMap::new()),
            command_rx,
            job_tx,
            job_rx,
            progress_tx,
            cancel: CancellationToken::new(),
            runtime: Arc::new(PoiCacheServiceRuntime::new()),
            poi_artifact_persistence: test_persistence(&db),
        };

        let compactions = apply_staged_poi_cache_batch(
            &coordinator,
            attempt_id(61),
            db.poi_artifact_cache_generation()
                .expect("cache generation"),
            vec![StagedPoiCacheCandidate {
                list_key,
                cache: replacement,
                journal_head: None,
                compaction: None,
            }],
            &Ok(()),
        )
        .await
        .expect("publish blocked-only replacement");
        assert!(compactions.is_empty());

        revision_rx.changed().await.expect("blocked revision");
        assert_eq!(
            *revision_rx.borrow_and_update(),
            PoiCorpusRevision {
                revision: 2,
                blocked_shields_revision: 2,
            }
        );
        let installed = local_caches.read().await[&list_key].clone();
        assert_eq!(installed.progress().next_event_index, 1);
        assert_eq!(
            installed.commitment_at_global_index(0),
            Some(event_commitment)
        );
        assert_eq!(
            installed.status(&FixedBytes::from([0x2c; 32])),
            PoiStatus::ShieldBlocked
        );

        drop(coordinator);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn artifact_failure_recovers_corpus_through_public_ranges_without_wallet_commitments() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let signing_key = SigningKey::from_bytes(&[0x45; 32]);
        let list_key = FixedBytes::from(signing_key.verifying_key().to_bytes());
        let commitment = FixedBytes::from([0x35_u8; 32]);
        let mut signed_poi_event = SignedPoiEvent {
            index: 0,
            blinded_commitment: commitment,
            signature: String::new(),
            event_type: PoiEventType::Transact,
        };
        signed_poi_event.signature = alloy::hex::encode(
            signing_key
                .sign(&canonical_poi_event_message(&signed_poi_event))
                .to_bytes(),
        );
        let event = PoiSyncedListEvent {
            signed_poi_event,
            validated_merkleroot: "0x00".to_string(),
        };
        let mock = spawn_poi_rpc_sequence(vec![
            serde_json::to_value(vec![event]).expect("events JSON"),
            serde_json::to_value(vec![U256::from_be_bytes(commitment.0)]).expect("leaves JSON"),
            serde_json::json!([]),
            serde_json::json!(true),
        ]);
        let service = PoiCacheService::new(Arc::clone(&db), artifact_config(), None)
            .expect("initialize POI cache service")
            .with_poi_rpc_url(mock.url.clone())
            .with_active_list_keys(vec![list_key]);
        let mut progress_rx = service.progress_rx();
        let local_caches = service.start_chain(1).await.expect("start chain");
        wait_for_progress(&mut progress_rx, 1, PoiArtifactCacheProgress::is_ready).await;

        let cache = local_caches
            .read()
            .await
            .get(&list_key)
            .cloned()
            .expect("public range corpus installed");
        assert_eq!(cache.status(&commitment), PoiStatus::Valid);
        assert!(cache.position(&commitment).is_some());
        let persisted = load_persisted_cache(db.as_ref(), cache.identity())
            .expect("load persisted range corpus")
            .expect("persisted range corpus");
        assert_eq!(persisted.record.source, PoiCacheRecordSource::PublicRpc);
        assert!(
            progress_rx
                .borrow()
                .get(&1)
                .is_some_and(PoiArtifactCacheProgress::is_ready)
        );
        let methods = (0..4)
            .map(|_| {
                let request = mock
                    .requests
                    .recv_timeout(Duration::from_secs(2))
                    .expect("public corpus request");
                assert!(!request.to_string().contains("blindedCommitments"));
                request["method"]
                    .as_str()
                    .expect("request method")
                    .to_string()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            methods,
            vec![
                "ppoi_poi_events",
                "ppoi_poi_merkletree_leaves",
                "ppoi_blocked_shields",
                "ppoi_validate_poi_merkleroots",
            ]
        );

        service.shutdown().await;
        drop(service);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn soft_compaction_updates_only_durable_head_anchor() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let list_key = default_active_poi_list_key();
        let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
        let generation = db
            .poi_artifact_cache_generation()
            .expect("cache generation");
        let persisted = persisted_public_rpc_journal_with_delta_count(
            db.as_ref(),
            &identity,
            generation,
            POI_CORPUS_JOURNAL_SOFT_DELTA_COUNT,
        );
        assert!(persisted.compaction_recommended);
        let old_head = persisted
            .journal_head
            .clone()
            .expect("journal head before soft compaction");
        let expected_base = persisted.expected_base();
        let runtime_before = persisted.cache.clone();
        let runtime_bytes = runtime_before.to_bytes().expect("encode runtime cache");
        let local_caches = LocalPoiCaches::new();
        local_caches.write().await.insert(list_key, runtime_before);
        let revision_rx = local_caches.committed_revision_rx();
        let (coordinator, progress_rx, _commit_fence) =
            compaction_test_coordinator(&db, local_caches.clone(), list_key, old_head.clone());

        assert!(
            run_background_poi_corpus_compaction(
                &coordinator,
                generation,
                PoiCorpusCompactionRequest {
                    identity: identity.clone(),
                    expected_base,
                },
            )
            .await
        );

        let durable = load_persisted_cache(&db, &identity)
            .expect("load compacted corpus")
            .expect("compacted corpus");
        let compacted_head = durable
            .journal_head
            .clone()
            .expect("compacted journal head");
        assert!(compacted_head.revision > old_head.revision);
        assert_eq!(compacted_head.base_revision, compacted_head.revision);
        assert_eq!(compacted_head.delta_count, 0);
        assert_eq!(
            coordinator
                .installed_head_anchors
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&list_key),
            Some(&compacted_head)
        );
        assert_eq!(
            local_caches
                .read()
                .await
                .get(&list_key)
                .expect("runtime cache after compaction")
                .to_bytes()
                .expect("encode runtime cache after compaction"),
            runtime_bytes
        );
        assert!(!revision_rx.has_changed().expect("revision stream"));
        assert!(!progress_rx.has_changed().expect("progress stream"));

        let mut corrupt_base = db
            .get_poi_artifact_cache(
                identity.chain_type,
                identity.chain_id,
                &identity.txid_version,
                &identity.list_key,
            )
            .expect("load compacted base")
            .expect("compacted base");
        corrupt_base.cache_payload = vec![0xc1];
        db.put_poi_artifact_cache(&corrupt_base)
            .expect("corrupt compacted historical base");
        assert!(load_persisted_cache(&db, &identity).is_err());
        let installed_cache = local_caches
            .read()
            .await
            .get(&list_key)
            .cloned()
            .expect("installed cache for anchored selection");
        let (selected, selected_base) = load_persisted_cache_candidate_for_publisher(
            &db,
            &identity,
            coordinator.artifact_config.trusted_publisher_pubkey,
            Some(installed_cache),
            Some(&compacted_head),
        )
        .expect("select exact compacted installed anchor");
        assert!(selected.is_some());
        assert_eq!(
            selected_base,
            ExpectedPoiCorpusBase::from_journal_head(&compacted_head)
        );

        drop(coordinator);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn stalled_compaction_lane_does_not_block_quiesce_command() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let list_key = default_active_poi_list_key();
        let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
        let generation = db
            .poi_artifact_cache_generation()
            .expect("cache generation");
        let persisted =
            persisted_public_rpc_journal_with_delta_count(db.as_ref(), &identity, generation, 1);
        let expected_base = persisted.expected_base();
        let anchor = persisted.journal_head.expect("journal head");
        let local_caches = LocalPoiCaches::new();
        local_caches.write().await.insert(list_key, persisted.cache);
        let (coordinator, _progress_rx, commit_fence) =
            compaction_test_coordinator(&db, local_caches, list_key, anchor);
        let commit_guard = commit_fence.lock_owned().await;
        let mut lane = PoiCorpusCompactionLane::default();
        enqueue_poi_corpus_compactions(
            &mut lane,
            vec![PoiCorpusCompactionRequest {
                identity,
                expected_base,
            }],
        );
        start_next_poi_corpus_compaction(&coordinator, &mut lane, generation);
        assert!(lane.active.is_some());

        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(1);
        let (response, quiesced) = tokio::sync::oneshot::channel();
        command_tx
            .send(ChainPoiCacheCommand::QuiesceForPublicCacheReset {
                lease: CancellationToken::new(),
                response,
            })
            .await
            .expect("queue quiesce command");
        let command = tokio::time::timeout(Duration::from_millis(100), async {
            tokio::select! {
                biased;
                command = command_rx.recv() => command,
                _ = wait_for_active_poi_corpus_compaction(&mut lane) => {
                    panic!("held commit fence unexpectedly completed compaction")
                }
            }
        })
        .await
        .expect("quiesce remains responsive during compaction")
        .expect("queued quiesce command");
        let ChainPoiCacheCommand::QuiesceForPublicCacheReset { response, .. } = command else {
            panic!("unexpected retry command");
        };
        cancel_poi_corpus_compaction_lane(&mut lane);
        response.send(()).expect("acknowledge quiescence");
        quiesced.await.expect("receive quiescence acknowledgement");
        assert!(lane.active.is_none());
        assert!(lane.pending.is_empty());

        drop(commit_guard);
        coordinator.cancel.cancel();
        drop(coordinator);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn background_compaction_stale_cancel_and_generation_mismatch_preserve_anchor() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let list_key = default_active_poi_list_key();
        let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
        let generation = db
            .poi_artifact_cache_generation()
            .expect("cache generation");
        let persisted =
            persisted_public_rpc_journal_with_delta_count(db.as_ref(), &identity, generation, 1);
        let original_head = persisted
            .journal_head
            .clone()
            .expect("journal head before rejected compactions");
        let expected_base = persisted.expected_base();
        let local_caches = LocalPoiCaches::new();
        local_caches.write().await.insert(list_key, persisted.cache);
        let revision_rx = local_caches.committed_revision_rx();
        let (coordinator, progress_rx, _commit_fence) =
            compaction_test_coordinator(&db, local_caches, list_key, original_head.clone());

        assert!(
            run_background_poi_corpus_compaction(
                &coordinator,
                generation,
                PoiCorpusCompactionRequest {
                    identity: identity.clone(),
                    expected_base: ExpectedPoiCorpusBase::NoValidCorpus,
                },
            )
            .await
        );
        assert!(
            run_background_poi_corpus_compaction(
                &coordinator,
                generation.saturating_add(1),
                PoiCorpusCompactionRequest {
                    identity: identity.clone(),
                    expected_base,
                },
            )
            .await
        );
        coordinator.cancel.cancel();
        assert!(
            !run_background_poi_corpus_compaction(
                &coordinator,
                generation,
                PoiCorpusCompactionRequest {
                    identity: identity.clone(),
                    expected_base,
                },
            )
            .await
        );

        assert_eq!(
            coordinator
                .installed_head_anchors
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&list_key),
            Some(&original_head)
        );
        assert_eq!(
            load_persisted_cache(&db, &identity)
                .expect("load unchanged durable corpus")
                .expect("unchanged durable corpus")
                .journal_head
                .as_ref(),
            Some(&original_head)
        );
        assert!(!revision_rx.has_changed().expect("revision stream"));
        assert!(!progress_rx.has_changed().expect("progress stream"));

        drop(coordinator);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn reset_before_durable_stage_rejects_old_generation_candidate() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let list_key = default_active_poi_list_key();
        let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
        let candidate_cache = cache_with_events(
            identity.clone(),
            &[snapshot_event(0, FixedBytes::from([0x73; 32]))],
        );
        let generation = db
            .poi_artifact_cache_generation()
            .expect("cache generation");
        let local_caches = LocalPoiCaches::new();
        let revision_rx = local_caches.committed_revision_rx();
        let (_command_tx, command_rx) = tokio::sync::mpsc::channel(1);
        let (job_tx, job_rx) = tokio::sync::mpsc::unbounded_channel();
        let (progress_tx, _) = tokio::sync::watch::channel(BTreeMap::new());
        let coordinator = ChainPoiCacheCoordinator {
            db: Arc::clone(&db),
            http_client: None,
            poi_rpc_url: Url::parse("http://127.0.0.1:1")
                .expect("POI RPC URL")
                .into(),
            artifact_config: artifact_config(),
            cache_generation: generation,
            chain_id: 1,
            local_caches: local_caches.clone(),
            active_list_keys: vec![list_key],
            preloaded_caches: BTreeMap::new(),
            installed_head_anchors: StdMutex::new(BTreeMap::new()),
            command_rx,
            job_tx,
            job_rx,
            progress_tx,
            cancel: tokio_util::sync::CancellationToken::new(),
            runtime: Arc::new(PoiCacheServiceRuntime::new()),
            poi_artifact_persistence: test_persistence(&db),
        };
        let reset = clear_poi_artifact_cache_for_reset(&db).expect("reset before durable stage");
        assert!(reset.generation > generation);
        let result = stage_poi_cache_candidate(
            &coordinator,
            attempt_id(9),
            generation,
            public_rpc_candidate_for_test(
                list_key,
                candidate_cache,
                0,
                ExpectedPoiCorpusBase::NoValidCorpus,
                None,
                None,
            ),
        )
        .await;

        assert!(matches!(result, Err(PoiCacheServiceError::Refresh { .. })));
        assert!(local_caches.read().await.is_empty());
        assert!(!revision_rx.has_changed().expect("revision stream"));
        assert!(coordinator.progress_tx.borrow().is_empty());
        assert!(
            db.get_poi_artifact_cache(
                identity.chain_type,
                identity.chain_id,
                &identity.txid_version,
                &identity.list_key,
            )
            .expect("read reset corpus")
            .is_none()
        );

        drop(coordinator);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn final_public_rpc_candidate_cancelled_at_commit_fence_returns_shutdown() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let list_key = default_active_poi_list_key();
        let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
        let generation = db
            .poi_artifact_cache_generation()
            .expect("cache generation");
        let local_caches = LocalPoiCaches::new();
        let revision_rx = local_caches.committed_revision_rx();
        let attempt_id = attempt_id(13);
        let initial_progress = new_poi_artifact_cache_progress(
            attempt_id,
            generation,
            1,
            PoiArtifactCachePhase::Validating,
            0,
            1,
            Some(list_key),
            None,
            Some(0),
            Vec::new(),
            PoiArtifactCacheGraphProgress::default(),
            false,
            None,
        );
        let (_command_tx, command_rx) = tokio::sync::mpsc::channel(1);
        let (job_tx, job_rx) = tokio::sync::mpsc::unbounded_channel();
        let (progress_tx, progress_rx) =
            tokio::sync::watch::channel(BTreeMap::from([(1, initial_progress)]));
        let commit_fence = Arc::new(tokio::sync::Mutex::new(()));
        let commit_guard = Arc::clone(&commit_fence).lock_owned().await;
        let coordinator = ChainPoiCacheCoordinator {
            db: Arc::clone(&db),
            http_client: None,
            poi_rpc_url: Url::parse("http://127.0.0.1:1")
                .expect("POI RPC URL")
                .into(),
            artifact_config: artifact_config(),
            cache_generation: generation,
            chain_id: 1,
            local_caches: local_caches.clone(),
            active_list_keys: vec![list_key],
            preloaded_caches: BTreeMap::new(),
            installed_head_anchors: StdMutex::new(BTreeMap::new()),
            command_rx,
            job_tx,
            job_rx,
            progress_tx,
            cancel: CancellationToken::new(),
            runtime: Arc::new(PoiCacheServiceRuntime::new()),
            poi_artifact_persistence: PoiArtifactPersistenceHandle::new(
                Arc::clone(&db),
                commit_fence,
            ),
        };
        let mut finish = Box::pin(finish_chain_poi_cache_attempt(
            &coordinator,
            attempt_id,
            generation,
            PreparedPoiCacheBatch {
                candidates: vec![public_rpc_candidate_for_test(
                    list_key,
                    cache_with_events(
                        identity.clone(),
                        &[snapshot_event(0, FixedBytes::from([0x77; 32]))],
                    ),
                    0,
                    ExpectedPoiCorpusBase::NoValidCorpus,
                    None,
                    None,
                )],
                source_outcomes: Vec::new(),
                actual_scope: PoiCacheSyncScope::FULL,
                result: Ok(()),
            },
        ));
        assert!(
            futures::poll!(&mut finish).is_pending(),
            "public RPC candidate must wait for the held commit fence"
        );
        assert_eq!(
            progress_rx.borrow().get(&1).map(|progress| progress.phase),
            Some(PoiArtifactCachePhase::Persisting)
        );

        coordinator.cancel.cancel();
        let finished = tokio::time::timeout(Duration::from_secs(2), finish.as_mut())
            .await
            .expect("cancelled final candidate returned promptly");

        assert!(matches!(
            finished.result,
            Err(PoiCacheServiceError::Shutdown { attempt_id: id }) if id == attempt_id
        ));
        assert!(local_caches.read().await.is_empty());
        assert!(!revision_rx.has_changed().expect("revision stream"));
        assert_eq!(
            progress_rx.borrow().get(&1).map(|progress| progress.phase),
            Some(PoiArtifactCachePhase::Persisting)
        );
        assert!(
            db.get_poi_artifact_cache(
                identity.chain_type,
                identity.chain_id,
                &identity.txid_version,
                &identity.list_key,
            )
            .expect("read corpus after pre-admission cancellation")
            .is_none()
        );

        drop(finish);
        drop(commit_guard);
        drop(coordinator);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn partial_batch_install_publishes_committed_revision() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let list_key = default_active_poi_list_key();
        let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
        let generation = db
            .poi_artifact_cache_generation()
            .expect("cache generation");
        let local_caches = LocalPoiCaches::new();
        let mut revision_rx = local_caches.committed_revision_rx();
        let (_command_tx, command_rx) = tokio::sync::mpsc::channel(1);
        let (job_tx, job_rx) = tokio::sync::mpsc::unbounded_channel();
        let (progress_tx, _) = tokio::sync::watch::channel(BTreeMap::new());
        let coordinator = ChainPoiCacheCoordinator {
            db: Arc::clone(&db),
            http_client: None,
            poi_rpc_url: Url::parse("http://127.0.0.1:1")
                .expect("POI RPC URL")
                .into(),
            artifact_config: artifact_config(),
            cache_generation: generation,
            chain_id: 1,
            local_caches: local_caches.clone(),
            active_list_keys: vec![list_key, FixedBytes::from([0x91; 32])],
            preloaded_caches: BTreeMap::new(),
            installed_head_anchors: StdMutex::new(BTreeMap::new()),
            command_rx,
            job_tx,
            job_rx,
            progress_tx,
            cancel: tokio_util::sync::CancellationToken::new(),
            runtime: Arc::new(PoiCacheServiceRuntime::new()),
            poi_artifact_persistence: test_persistence(&db),
        };

        let result = finish_chain_poi_cache_attempt(
            &coordinator,
            attempt_id(1),
            generation,
            PreparedPoiCacheBatch {
                candidates: vec![public_rpc_candidate_for_test(
                    list_key,
                    cache_with_events(
                        identity.clone(),
                        &[snapshot_event(0, FixedBytes::from([0x92; 32]))],
                    ),
                    0,
                    ExpectedPoiCorpusBase::NoValidCorpus,
                    None,
                    None,
                )],
                source_outcomes: Vec::new(),
                actual_scope: PoiCacheSyncScope::FULL,
                result: Err("second list failed".to_string()),
            },
        )
        .await;

        assert!(matches!(
            result.result,
            Err(PoiCacheServiceError::Refresh { .. })
        ));
        revision_rx
            .changed()
            .await
            .expect("partial batch committed revision");
        assert_eq!(
            *revision_rx.borrow_and_update(),
            PoiCorpusRevision {
                revision: 1,
                blocked_shields_revision: 1,
            }
        );
        assert!(local_caches.read().await.contains_key(&list_key));
        assert!(
            db.get_poi_artifact_cache(
                identity.chain_type,
                identity.chain_id,
                &identity.txid_version,
                &identity.list_key,
            )
            .expect("read partial batch corpus")
            .is_some()
        );

        drop(coordinator);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn cancelled_apply_after_durable_stage_keeps_corpus_without_runtime_publication() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let list_key = default_active_poi_list_key();
        let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
        let candidate_cache = cache_with_events(
            identity.clone(),
            &[snapshot_event(0, FixedBytes::from([0x74; 32]))],
        );
        let second_list_key = FixedBytes::from([0x75; 32]);
        let second_identity =
            PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, second_list_key);
        let generation = db
            .poi_artifact_cache_generation()
            .expect("cache generation");
        let local_caches = LocalPoiCaches::new();
        let revision_rx = local_caches.committed_revision_rx();
        let (_command_tx, command_rx) = tokio::sync::mpsc::channel(1);
        let (job_tx, job_rx) = tokio::sync::mpsc::unbounded_channel();
        let (progress_tx, progress_rx) = tokio::sync::watch::channel(BTreeMap::new());
        let coordinator = ChainPoiCacheCoordinator {
            db: Arc::clone(&db),
            http_client: None,
            poi_rpc_url: Url::parse("http://127.0.0.1:1")
                .expect("POI RPC URL")
                .into(),
            artifact_config: artifact_config(),
            cache_generation: generation,
            chain_id: 1,
            local_caches: local_caches.clone(),
            active_list_keys: vec![list_key, second_list_key],
            preloaded_caches: BTreeMap::new(),
            installed_head_anchors: StdMutex::new(BTreeMap::new()),
            command_rx,
            job_tx,
            job_rx,
            progress_tx,
            cancel: tokio_util::sync::CancellationToken::new(),
            runtime: Arc::new(PoiCacheServiceRuntime::new()),
            poi_artifact_persistence: test_persistence(&db),
        };
        let candidates = vec![
            public_rpc_candidate_for_test(
                list_key,
                candidate_cache,
                0,
                ExpectedPoiCorpusBase::NoValidCorpus,
                None,
                None,
            ),
            public_rpc_candidate_for_test(
                second_list_key,
                cache_with_events(
                    second_identity.clone(),
                    &[snapshot_event(0, FixedBytes::from([0x76; 32]))],
                ),
                0,
                ExpectedPoiCorpusBase::NoValidCorpus,
                None,
                None,
            ),
        ];
        assert!(!coordinator.cancel.is_cancelled());
        let mut staged = Vec::new();
        for candidate in candidates {
            if let Some(candidate) =
                stage_poi_cache_candidate(&coordinator, attempt_id(12), generation, candidate)
                    .await
                    .expect("stage durable POI cache candidate")
            {
                staged.push(candidate);
            }
        }
        assert_eq!(staged.len(), 2);
        assert!(
            db.get_poi_artifact_cache(
                identity.chain_type,
                identity.chain_id,
                &identity.txid_version,
                &identity.list_key,
            )
            .expect("read first corpus after durable stage")
            .is_some()
        );
        assert!(
            db.get_poi_artifact_cache(
                second_identity.chain_type,
                second_identity.chain_id,
                &second_identity.txid_version,
                &second_identity.list_key,
            )
            .expect("read second corpus after durable stage")
            .is_some()
        );

        coordinator.cancel.cancel();
        let result =
            apply_staged_poi_cache_batch(&coordinator, attempt_id(12), generation, staged, &Ok(()))
                .await;

        assert!(matches!(
            result,
            Err(PoiCacheServiceError::Shutdown { attempt_id: id }) if id == attempt_id(12)
        ));
        assert!(local_caches.read().await.is_empty());
        assert!(!revision_rx.has_changed().expect("revision stream"));
        assert!(progress_rx.borrow().is_empty());
        assert!(
            db.get_poi_artifact_cache(
                identity.chain_type,
                identity.chain_id,
                &identity.txid_version,
                &identity.list_key,
            )
            .expect("read first corpus after shutdown")
            .is_some()
        );
        assert!(
            db.get_poi_artifact_cache(
                second_identity.chain_type,
                second_identity.chain_id,
                &second_identity.txid_version,
                &second_identity.list_key,
            )
            .expect("read second corpus after shutdown")
            .is_some()
        );

        drop(coordinator);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn cancelling_active_attempt_drops_candidate_future_before_returning() {
        struct PendingCandidate {
            dropped: Arc<AtomicBool>,
        }

        impl std::future::Future for PendingCandidate {
            type Output = PreparedPoiCacheBatch;

            fn poll(
                self: std::pin::Pin<&mut Self>,
                _context: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Self::Output> {
                std::task::Poll::Pending
            }
        }

        impl Drop for PendingCandidate {
            fn drop(&mut self) {
                self.dropped.store(true, Ordering::Release);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let mut active = Some(ActivePoiCacheAttempt {
            id: attempt_id(44),
            generation: 0,
            scope: PoiCacheSyncScope::FULL,
            cancel: CancellationToken::new(),
            job: Box::pin(PendingCandidate {
                dropped: Arc::clone(&dropped),
            }),
            retry_completion: None,
        });

        cancel_active_attempt(&mut active, |attempt_id| PoiCacheServiceError::Shutdown {
            attempt_id,
        });

        assert!(dropped.load(Ordering::Acquire));
        assert!(active.is_none());
    }

    #[tokio::test]
    async fn stale_attempt_progress_cannot_overwrite_replacement() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let local_caches = LocalPoiCaches::new();
        let (_command_tx, command_rx) = tokio::sync::mpsc::channel(1);
        let (job_tx, job_rx) = tokio::sync::mpsc::unbounded_channel();
        let replacement_id = attempt_id(2);
        let replacement_progress = new_poi_artifact_cache_progress(
            replacement_id,
            0,
            1,
            PoiArtifactCachePhase::LiveTailing,
            0,
            1,
            None,
            None,
            None,
            Vec::new(),
            PoiArtifactCacheGraphProgress::default(),
            false,
            None,
        );
        let (progress_tx, progress_rx) =
            tokio::sync::watch::channel(BTreeMap::from([(1, replacement_progress)]));
        let coordinator = ChainPoiCacheCoordinator {
            db: Arc::clone(&db),
            http_client: None,
            poi_rpc_url: Url::parse("http://127.0.0.1:1")
                .expect("POI RPC URL")
                .into(),
            artifact_config: artifact_config(),
            cache_generation: 0,
            chain_id: 1,
            local_caches,
            active_list_keys: vec![default_active_poi_list_key()],
            preloaded_caches: BTreeMap::new(),
            installed_head_anchors: StdMutex::new(BTreeMap::new()),
            command_rx,
            job_tx,
            job_rx,
            progress_tx,
            cancel: tokio_util::sync::CancellationToken::new(),
            runtime: Arc::new(PoiCacheServiceRuntime::new()),
            poi_artifact_persistence: test_persistence(&db),
        };
        let active = ActivePoiCacheAttempt {
            id: replacement_id,
            generation: 0,
            scope: PoiCacheSyncScope::FULL,
            cancel: CancellationToken::new(),
            job: Box::pin(std::future::pending()),
            retry_completion: None,
        };
        publish_active_attempt_progress(
            &coordinator,
            Some(&active),
            super::ChainPoiCacheJobEvent {
                progress: new_poi_artifact_cache_progress(
                    attempt_id(1),
                    0,
                    1,
                    PoiArtifactCachePhase::Failed,
                    0,
                    1,
                    None,
                    None,
                    None,
                    Vec::new(),
                    PoiArtifactCacheGraphProgress::default(),
                    false,
                    Some("stale".to_string()),
                ),
            },
        );

        assert_eq!(progress_rx.borrow()[&1].attempt_id, replacement_id);
        assert_eq!(progress_rx.borrow()[&1].generation, 0);
        assert_eq!(
            progress_rx.borrow()[&1].phase,
            PoiArtifactCachePhase::LiveTailing
        );
        drop(active);
        drop(coordinator);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn stale_completion_drops_candidate_before_retry_response() {
        struct ReadyCandidate {
            dropped: Arc<AtomicBool>,
        }

        impl std::future::Future for ReadyCandidate {
            type Output = PreparedPoiCacheBatch;

            fn poll(
                self: std::pin::Pin<&mut Self>,
                _context: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Self::Output> {
                std::task::Poll::Ready(PreparedPoiCacheBatch {
                    candidates: Vec::new(),
                    source_outcomes: Vec::new(),
                    actual_scope: PoiCacheSyncScope::FULL,
                    result: Ok(()),
                })
            }
        }

        impl Drop for ReadyCandidate {
            fn drop(&mut self) {
                self.dropped.store(true, Ordering::Release);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let (response, result) = tokio::sync::oneshot::channel();
        let response = drop_completed_attempt(ActivePoiCacheAttempt {
            id: attempt_id(45),
            generation: 0,
            scope: PoiCacheSyncScope::FULL,
            cancel: CancellationToken::new(),
            job: Box::pin(ReadyCandidate {
                dropped: Arc::clone(&dropped),
            }),
            retry_completion: Some(response),
        })
        .expect("retry response");

        assert!(dropped.load(Ordering::Acquire));
        let _ = response.send(Err(PoiCacheServiceError::StaleAttempt {
            attempt_id: attempt_id(45),
        }));
        assert!(matches!(
            result.await.expect("stale response"),
            Err(PoiCacheServiceError::StaleAttempt { attempt_id: id }) if id == attempt_id(45)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stalled_attempt_is_cancelled_on_shutdown() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let stalled = spawn_stalled_http_server();
        let service = Arc::new(
            PoiCacheService::new(
                Arc::clone(&db),
                artifact_config_with_url(stalled.url.clone()),
                None,
            )
            .expect("initialize POI cache service")
            .with_poi_rpc_url(stalled.url.clone()),
        );
        service.start_chain(1).await.expect("start chain");
        stalled
            .accepted
            .recv_timeout(Duration::from_secs(2))
            .expect("background attempt reached network");
        let retry = service.retry_chain(1).await.expect("admit retry");
        let retry = tokio::spawn(retry.wait());
        stalled
            .accepted
            .recv_timeout(Duration::from_secs(2))
            .expect("retry attempt reached network");

        service.shutdown().await;
        let retry_result = tokio::time::timeout(Duration::from_secs(1), retry)
            .await
            .expect("shutdown cancelled retry promptly")
            .expect("retry task");
        assert!(matches!(
            retry_result,
            Err(PoiCacheServiceError::Shutdown { .. })
        ));

        drop(service);
        drop(stalled);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn admitted_retries_have_distinct_correlated_attempt_ids() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let list_key = default_active_poi_list_key();
        let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
        let mut initialized =
            cache_with_events(identity, &[snapshot_event(0, FixedBytes::from([0x45; 32]))]);
        initialized
            .apply_blocked_shields(&[])
            .expect("mark blocked snapshot initialized");
        persist_cache(&db, &initialized);
        let stalled = spawn_stalled_http_server();
        let service = Arc::new(
            PoiCacheService::new(
                Arc::clone(&db),
                artifact_config_with_url(stalled.url.clone()),
                None,
            )
            .expect("initialize POI cache service")
            .with_poi_rpc_url(stalled.url.clone()),
        );
        service.start_chain(1).await.expect("start chain");
        stalled
            .accepted
            .recv_timeout(Duration::from_secs(10))
            .expect("startup attempt reached network");

        let first = service.retry_chain(1).await.expect("admit first retry");
        let first_id = first.attempt_id();
        assert_eq!(service.progress_rx().borrow()[&1].attempt_id, first_id);
        let first_wait = tokio::spawn(first.wait());
        stalled
            .accepted
            .recv_timeout(Duration::from_secs(10))
            .expect("first retry reached network");

        let second = service
            .retry_chain_events(1)
            .await
            .expect("admit event-only retry");
        let second_id = second.attempt_id();
        assert!(second_id > first_id);
        assert_eq!(service.progress_rx().borrow()[&1].attempt_id, second_id);
        assert!(matches!(
            first_wait.await.expect("first retry wait"),
            Err(PoiCacheServiceError::AttemptSuperseded { attempt_id })
                if attempt_id == first_id
        ));

        service.shutdown().await;
        assert!(matches!(
            second.wait().await,
            Err(PoiCacheServiceError::Shutdown { attempt_id }) if attempt_id == second_id
        ));
        drop(service);
        drop(stalled);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn admitted_retry_id_matches_terminal_progress() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let service = PoiCacheService::new(Arc::clone(&db), artifact_config(), None)
            .expect("initialize POI cache service")
            .with_poi_rpc_url(Url::parse("http://127.0.0.1:1").expect("POI RPC URL"));
        service.start_chain(1).await.expect("start chain");
        let mut progress_rx = service.progress_rx();

        let retry = service.retry_chain(1).await.expect("admit retry");
        let retry_id = retry.attempt_id();
        assert_eq!(progress_rx.borrow()[&1].attempt_id, retry_id);
        assert!(matches!(
            retry.wait().await,
            Err(PoiCacheServiceError::Refresh { .. })
        ));
        let terminal = wait_for_progress(&mut progress_rx, 1, |progress| {
            progress.attempt_id == retry_id && progress.is_error()
        })
        .await;
        assert_eq!(terminal.attempt_id, retry_id);

        service.shutdown().await;
        drop(service);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn coordinator_replacement_does_not_reuse_service_attempt_ids() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let service = PoiCacheService::new(Arc::clone(&db), artifact_config(), None)
            .expect("initialize POI cache service")
            .with_poi_rpc_url(Url::parse("http://127.0.0.1:1").expect("POI RPC URL"));
        service
            .start_chain(1)
            .await
            .expect("start first coordinator");
        let first_id = service.progress_rx().borrow()[&1].attempt_id;
        let mut stopped = service
            .coordinator
            .lock()
            .await
            .take()
            .expect("first coordinator")
            .stopped_rx;
        while !*stopped.borrow() {
            stopped.changed().await.expect("first coordinator stops");
        }

        service
            .start_chain(1)
            .await
            .expect("start replacement coordinator");
        let second_id = service.progress_rx().borrow()[&1].attempt_id;
        assert!(second_id > first_id);

        service.shutdown().await;
        drop(service);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ready_progress_is_preserved_until_retry_attempt_starts() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let list_key = default_active_poi_list_key();
        let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
        persist_cache(
            &db,
            &cache_with_events(identity, &[snapshot_event(0, FixedBytes::from([0x45; 32]))]),
        );
        let stalled = spawn_stalled_http_server();
        let service = Arc::new(
            PoiCacheService::new(
                Arc::clone(&db),
                artifact_config_with_url(stalled.url.clone()),
                None,
            )
            .expect("initialize POI cache service")
            .with_poi_rpc_url(stalled.url.clone()),
        );
        let local_caches = service.start_chain(1).await.expect("start chain");
        stalled
            .accepted
            .recv_timeout(Duration::from_secs(2))
            .expect("background public RPC attempt reached network");
        let cache_guard = local_caches.write().await;
        let retry_service = Arc::clone(&service);
        let retry = tokio::spawn(async move { retry_service.retry_chain(1).await });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let progress = service
            .progress_rx()
            .borrow()
            .get(&1)
            .cloned()
            .expect("chain progress");
        assert!(
            progress.ready_for_wallet_checks,
            "a queued retry must not clear readiness while the old corpus remains usable"
        );

        drop(cache_guard);
        service.shutdown().await;
        let _ = tokio::time::timeout(Duration::from_secs(1), retry)
            .await
            .expect("retry released after shutdown");
        drop(service);
        drop(stalled);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn failed_live_tail_candidate_does_not_mutate_artifact_cache() {
        let list_key = FixedBytes::from([7_u8; 32]);
        let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
        let artifact_commitment = FixedBytes::from([0x22; 32]);
        let tailed_commitment = FixedBytes::from([0x33; 32]);
        let cache = cache_with_events(identity, &[snapshot_event(0, artifact_commitment)]);
        let original_next_event_index = cache.progress().next_event_index;
        let leaves = vec![U256::from_be_bytes(tailed_commitment.0)];
        let mock = spawn_poi_rpc_sequence(vec![
            serde_json::to_value(leaves).expect("leaves JSON"),
            serde_json::json!(false),
        ]);
        let client = PoiRpcClient::new(mock.url.clone());

        let err = live_tail_candidate_cache(&client, &cache)
            .await
            .expect_err("root validation rejection should reject candidate cache");

        assert!(matches!(err, LivePoiTailError::RootRejected));
        assert_eq!(cache.progress().next_event_index, original_next_event_index);
        assert!(cache.position(&tailed_commitment).is_none());
        let request = mock
            .requests
            .recv_timeout(Duration::from_secs(2))
            .expect("remote leaf request");
        assert_eq!(request["method"], "ppoi_poi_merkletree_leaves");
        let request = mock
            .requests
            .recv_timeout(Duration::from_secs(2))
            .expect("remote root validation request");
        assert_eq!(request["method"], "ppoi_validate_poi_merkleroots");
    }
}
