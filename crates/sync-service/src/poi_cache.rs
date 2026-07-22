use std::collections::{BTreeMap, HashMap, hash_map::Entry};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use alloy::hex;
use alloy::primitives::FixedBytes;
use broadcaster_core::transact::DEFAULT_TXID_VERSION;
use futures::FutureExt;
use futures::future::{BoxFuture, join_all};
use local_db::DbStore;
use poi::SensitiveUrl;
use poi::cache::{
    POI_EVENTS_PAGE_SIZE, POI_MERKLETREE_LEAVES_PAGE_SIZE, PoiCache, PoiCacheError,
    PoiCacheIdentity, PoiCacheSyncOutcome,
};
use poi::poi::{DEFAULT_WALLET_POI_RPC_URL, PoiRpcClient, default_active_poi_list_keys};
use tokio::sync::{OwnedRwLockWriteGuard, RwLock, mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, info, warn};

use crate::chain::PoiArtifactPersistenceHandle;
use crate::poi_artifacts::{
    ExpectedPoiCorpusBase, ObservedManifest, PersistedPoiArtifactCache, PoiArtifactError,
    PoiArtifactIngestor, PoiCorpusAuthority, PoiCorpusStore, PreparedIngestion,
    load_persisted_cache_for_publisher, load_poi_rpc_health, poi_corpus_authority,
    record_poi_rpc_success, with_poi_artifact_cache_generation,
};
use crate::types::{
    LocalPoiCaches, PoiArtifactCacheAttemptId, PoiArtifactCacheGraphProgress,
    PoiArtifactCacheListProgress, PoiArtifactCachePhase, PoiArtifactCacheProgress,
    PoiArtifactSourceConfig,
};
use crate::wallet::wallet_poi_status_client;

const EVM_CHAIN_TYPE: u8 = 0;
const POI_CACHE_MAINTENANCE_INTERVAL: Duration = Duration::from_mins(1);
const POI_ARTIFACT_RPC_FAILURE_THRESHOLD: u32 = 3;
const POI_ARTIFACT_RPC_STALE_AFTER: Duration = Duration::from_mins(5);
const POI_CACHE_COMMAND_CAPACITY: usize = 16;
const POI_RPC_RANGE_PAGE_BUDGET: usize = 8;

struct ChainPoiCacheCoordinator {
    db: Arc<DbStore>,
    http_client: Option<reqwest::Client>,
    poi_rpc_url: SensitiveUrl,
    artifact_config: PoiArtifactSourceConfig,
    chain_id: u64,
    local_caches: LocalPoiCaches,
    active_list_keys: Vec<FixedBytes<32>>,
    preloaded_caches: BTreeMap<FixedBytes<32>, PersistedPoiArtifactCache>,
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
    local_caches: LocalPoiCaches,
    command_tx: mpsc::Sender<ChainPoiCacheCommand>,
    initialized_rx: watch::Receiver<bool>,
    stopped_rx: watch::Receiver<bool>,
}

enum ChainPoiCacheCommand {
    Retry {
        admission: oneshot::Sender<Result<PoiCacheRetryHandle, PoiCacheServiceError>>,
    },
    Reset {
        generation: u64,
        response: oneshot::Sender<Result<(), PoiCacheServiceError>>,
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
    #[error("stale POI cache generation: expected {expected}, actual {actual}")]
    StaleGeneration { expected: u64, actual: u64 },
    #[error("POI cache refresh failed: {reason}")]
    Refresh { reason: String },
    #[error(transparent)]
    Db(#[from] local_db::DbError),
}

pub(crate) struct PoiCacheService {
    db: Arc<DbStore>,
    artifact_config: PoiArtifactSourceConfig,
    http_client: Option<reqwest::Client>,
    poi_rpc_url: SensitiveUrl,
    active_list_keys: Vec<FixedBytes<32>>,
    chains: RwLock<HashMap<u64, ChainPoiCacheHandle>>,
    chain_caches: RwLock<HashMap<u64, LocalPoiCaches>>,
    progress_tx: watch::Sender<BTreeMap<u64, PoiArtifactCacheProgress>>,
    cancel: CancellationToken,
    cache_authority: Arc<PoiCorpusAuthority>,
    runtime: Arc<PoiCacheServiceRuntime>,
    poi_artifact_persistence: PoiArtifactPersistenceHandle,
}

pub(crate) struct PoiPublicCacheResetLease {
    admission: Option<OwnedRwLockWriteGuard<()>>,
    release: CancellationToken,
}

impl Drop for PoiPublicCacheResetLease {
    fn drop(&mut self) {
        self.release.cancel();
        drop(self.admission.take());
    }
}

impl PoiCacheService {
    pub(crate) fn new_with_persistence(
        db: Arc<DbStore>,
        artifact_config: PoiArtifactSourceConfig,
        http_client: Option<reqwest::Client>,
        poi_artifact_persistence: PoiArtifactPersistenceHandle,
    ) -> Result<Self, local_db::DbError> {
        let (progress_tx, _) = watch::channel(BTreeMap::new());
        let cache_authority = poi_corpus_authority(&db)?;
        Ok(Self {
            db,
            artifact_config,
            http_client,
            poi_rpc_url: default_poi_rpc_url(),
            active_list_keys: default_active_poi_list_keys(),
            chains: RwLock::new(HashMap::new()),
            chain_caches: RwLock::new(HashMap::new()),
            progress_tx,
            cancel: CancellationToken::new(),
            cache_authority,
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
        if let Some(existing) = self.local_caches(chain_id).await? {
            return Ok(existing);
        }
        let _public_cache_reset_admission = self.runtime.public_cache_reset_gate.read().await;

        let local_caches = {
            let mut chain_caches = self.chain_caches.write().await;
            chain_caches
                .entry(chain_id)
                .or_insert_with(|| LocalPoiCaches::new(Arc::clone(&self.cache_authority)))
                .clone()
        };
        let active_list_keys = self.active_list_keys.clone();
        let (command_tx, command_rx) = mpsc::channel(POI_CACHE_COMMAND_CAPACITY);
        let (job_tx, job_rx) = mpsc::unbounded_channel();
        let (initialized_tx, initialized_rx) = watch::channel(false);
        let (stopped_tx, stopped_rx) = watch::channel(false);
        let handle = ChainPoiCacheHandle {
            local_caches: local_caches.clone(),
            command_tx,
            initialized_rx: initialized_rx.clone(),
            stopped_rx,
        };
        let new_handle = handle.clone();
        let concurrent_existing = {
            let mut chains = self.chains.write().await;
            if self.cancel.is_cancelled() {
                return Err(PoiCacheServiceError::CoordinatorStopped);
            }
            match chains.entry(chain_id) {
                Entry::Occupied(entry) => Some(entry.get().clone()),
                Entry::Vacant(entry) => {
                    entry.insert(handle);
                    None
                }
            }
        };
        if let Some(existing) = concurrent_existing {
            if let Err(err) =
                wait_for_chain_poi_cache_initialization(existing.initialized_rx.clone()).await
            {
                self.remove_chain_handle(chain_id, &existing).await;
                return Err(err);
            }
            return Ok(existing.local_caches);
        }

        spawn_chain_poi_cache_coordinator(
            ChainPoiCacheCoordinator {
                db: Arc::clone(&self.db),
                http_client: self.http_client.clone(),
                poi_rpc_url: self.poi_rpc_url.clone(),
                artifact_config: self.artifact_config.clone(),
                chain_id,
                local_caches: local_caches.clone(),
                active_list_keys,
                preloaded_caches: BTreeMap::new(),
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
        if let Err(err) = wait_for_chain_poi_cache_initialization(initialized_rx).await {
            self.remove_chain_handle(chain_id, &new_handle).await;
            return Err(err);
        }
        Ok(local_caches)
    }

    pub(crate) async fn retry_chain(
        &self,
        chain_id: u64,
    ) -> Result<PoiCacheRetryHandle, PoiCacheServiceError> {
        if self.local_caches(chain_id).await?.is_none() {
            self.start_chain(chain_id).await?;
        }
        let public_cache_reset_admission = self.runtime.public_cache_reset_gate.read().await;
        let handle = self
            .chains
            .read()
            .await
            .get(&chain_id)
            .cloned()
            .ok_or(PoiCacheServiceError::CoordinatorStopped)?;
        let (admission, admitted) = oneshot::channel();
        if handle
            .command_tx
            .send(ChainPoiCacheCommand::Retry { admission })
            .await
            .is_err()
        {
            self.remove_chain_handle(chain_id, &handle).await;
            return Err(PoiCacheServiceError::CoordinatorStopped);
        }
        drop(public_cache_reset_admission);
        if let Ok(result) = admitted.await {
            result
        } else {
            self.remove_chain_handle(chain_id, &handle).await;
            Err(PoiCacheServiceError::CoordinatorStopped)
        }
    }

    pub(crate) async fn local_caches(
        &self,
        chain_id: u64,
    ) -> Result<Option<LocalPoiCaches>, PoiCacheServiceError> {
        let Some(handle) = self.chains.read().await.get(&chain_id).cloned() else {
            return Ok(None);
        };
        if wait_for_chain_poi_cache_initialization(handle.initialized_rx.clone())
            .await
            .is_err()
            || handle.command_tx.is_closed()
        {
            self.remove_chain_handle(chain_id, &handle).await;
            return Err(PoiCacheServiceError::CoordinatorStopped);
        }
        if handle.local_caches.installed_generation() != handle.local_caches.current_generation() {
            self.reset_chain_handle_to_latest(chain_id, &handle).await?;
        }
        Ok(Some(handle.local_caches))
    }

    async fn reset_chain_handle_to_latest(
        &self,
        chain_id: u64,
        handle: &ChainPoiCacheHandle,
    ) -> Result<(), PoiCacheServiceError> {
        loop {
            let generation = handle.local_caches.current_generation();
            let (response, result) = oneshot::channel();
            if handle
                .command_tx
                .send(ChainPoiCacheCommand::Reset {
                    generation,
                    response,
                })
                .await
                .is_err()
            {
                self.remove_chain_handle(chain_id, handle).await;
                return Err(PoiCacheServiceError::CoordinatorStopped);
            }
            match result.await {
                Ok(Ok(())) if handle.local_caches.current_generation() == generation => {
                    return Ok(());
                }
                Ok(Ok(()) | Err(PoiCacheServiceError::StaleGeneration { .. })) => {}
                Ok(Err(err)) => return Err(err),
                Err(_) => {
                    self.remove_chain_handle(chain_id, handle).await;
                    return Err(PoiCacheServiceError::CoordinatorStopped);
                }
            }
        }
    }

    async fn remove_chain_handle(&self, chain_id: u64, expected: &ChainPoiCacheHandle) {
        let mut chains = self.chains.write().await;
        let remove = chains
            .get(&chain_id)
            .is_some_and(|current| current.command_tx.same_channel(&expected.command_tx));
        if remove {
            chains.remove(&chain_id);
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
        let chains = self
            .chains
            .read()
            .await
            .iter()
            .map(|(chain_id, handle)| (*chain_id, handle.clone()))
            .collect::<Vec<_>>();
        let responses = join_all(chains.into_iter().map(|(chain_id, handle)| {
            let release = release.clone();
            async move {
                let (response, quiesced) = oneshot::channel();
                let sent = handle
                    .command_tx
                    .send(ChainPoiCacheCommand::QuiesceForPublicCacheReset {
                        lease: release,
                        response,
                    })
                    .await;
                (chain_id, handle, sent.map(|()| quiesced))
            }
        }))
        .await;
        for (chain_id, handle, response) in responses {
            let quiesced = match response {
                Ok(response) => response.await.is_ok(),
                Err(_) => false,
            };
            if !quiesced {
                self.remove_chain_handle(chain_id, &handle).await;
            }
        }
        lease
    }

    pub(crate) async fn shutdown(&self) {
        self.begin_shutdown();
        let mut stopped = self
            .chains
            .read()
            .await
            .values()
            .map(|handle| handle.stopped_rx.clone())
            .collect::<Vec<_>>();
        for receiver in &mut stopped {
            while !*receiver.borrow() {
                if receiver.changed().await.is_err() {
                    break;
                }
            }
        }
    }

    fn begin_shutdown(&self) {
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
    local_caches: &LocalPoiCaches,
    generation: u64,
    progress: PoiArtifactCacheProgress,
) -> Result<(), PoiCacheServiceError> {
    if progress.generation != generation {
        return Err(PoiCacheServiceError::StaleGeneration {
            expected: generation,
            actual: progress.generation,
        });
    }
    with_poi_artifact_cache_generation(local_caches.shared_generation(), |current_generation| {
        if current_generation != generation {
            return Err(PoiCacheServiceError::StaleGeneration {
                expected: generation,
                actual: current_generation,
            });
        }
        send_poi_artifact_cache_progress(progress_tx, progress);
        Ok(())
    })
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
        local_caches,
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
    candidate: Option<PoiCache>,
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
        range_start_index: u64,
        expected_base: ExpectedPoiCorpusBase,
    },
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
    result: Result<(), String>,
}

struct FinishedPoiCacheAttempt {
    result: Result<(), PoiCacheServiceError>,
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
    let mut generation = task.local_caches.current_generation();
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
            &task.local_caches,
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
    synchronize_chain_cache_generation(
        chain_id,
        &task.local_caches,
        Some(&mut task.preloaded_caches),
    )
    .await;
    generation = task.local_caches.current_generation();
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
    let mut maintenance = tokio::time::interval_at(
        tokio::time::Instant::now() + POI_CACHE_MAINTENANCE_INTERVAL,
        POI_CACHE_MAINTENANCE_INTERVAL,
    );
    maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    info!(
        chain_id,
        list_count = task.active_list_keys.len(),
        "starting chain-owned POI cache coordinator"
    );
    let _ = start_chain_poi_cache_attempt(&mut task, &mut active, generation, &health, None).await;

    loop {
        tokio::select! {
            biased;
            () = task.cancel.cancelled() => {
                cancel_active_attempt(&mut active, |attempt_id| {
                    PoiCacheServiceError::Shutdown { attempt_id }
                });
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
                    ChainPoiCacheCommand::Retry { admission } => {
                        clear_released_public_cache_reset(&mut public_cache_reset);
                        if public_cache_reset.is_some()
                            || task.runtime.public_cache_reset_gate.try_read().is_err()
                        {
                            let _ = admission.send(Err(PoiCacheServiceError::CorpusResetInProgress));
                            continue;
                        }
                        cancel_active_attempt(&mut active, |attempt_id| {
                            PoiCacheServiceError::AttemptSuperseded { attempt_id }
                        });
                        generation = task.local_caches.current_generation();
                        let (completion, completed) = oneshot::channel();
                        match start_chain_poi_cache_attempt(
                            &mut task,
                            &mut active,
                            generation,
                            &health,
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
                                let _ = admission.send(Err(error));
                            }
                        }
                    }
                    ChainPoiCacheCommand::Reset { generation: reset_generation, response } => {
                        let current_generation = task.local_caches.current_generation();
                        if current_generation != reset_generation {
                            let _ = response.send(Err(PoiCacheServiceError::StaleGeneration {
                                expected: reset_generation,
                                actual: current_generation,
                            }));
                            continue;
                        }
                        cancel_active_attempt(&mut active, |attempt_id| {
                            PoiCacheServiceError::StaleAttempt { attempt_id }
                        });
                        generation = reset_generation;
                        task.preloaded_caches.clear();
                        let reset_result = reset_chain_runtime(
                            &task,
                            reset_generation,
                            task.runtime.next_attempt_id(),
                        )
                        .await;
                        if reset_result.is_ok() {
                            health = source_health_for_lists(
                                task.db.as_ref(),
                                chain_id,
                                generation,
                                &task.active_list_keys,
                                &task.preloaded_caches,
                            );
                            clear_released_public_cache_reset(&mut public_cache_reset);
                            if public_cache_reset.is_none() {
                                let _ = start_chain_poi_cache_attempt(
                                    &mut task,
                                    &mut active,
                                    generation,
                                    &health,
                                    None,
                                )
                                .await;
                            }
                        }
                        let _ = response.send(reset_result);
                    }
                    ChainPoiCacheCommand::QuiesceForPublicCacheReset { lease, response } => {
                        public_cache_reset = Some(lease);
                        cancel_active_attempt(&mut active, |attempt_id| {
                            PoiCacheServiceError::StaleAttempt { attempt_id }
                        });
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
                let current_generation = task.local_caches.current_generation();
                if current_generation != attempt_generation {
                    let retry_completion = drop_completed_attempt(finished);
                    task.preloaded_caches.clear();
                    let _ = recover_chain_after_stale_attempt(
                        &mut task,
                        &mut active,
                        &mut health,
                        retry_completion,
                        PoiCacheServiceError::StaleAttempt { attempt_id },
                    )
                    .await;
                    continue;
                }
                let source_outcomes = completion.source_outcomes.clone();
                let finished_attempt = finish_chain_poi_cache_attempt(
                    &task,
                    attempt_id,
                    attempt_generation,
                    completion,
                )
                .await;
                let FinishedPoiCacheAttempt { result: attempt_result } = finished_attempt;
                if !matches!(
                    &attempt_result,
                    Err(PoiCacheServiceError::Shutdown { .. }
                        | PoiCacheServiceError::StaleGeneration { .. })
                ) {
                    record_list_source_outcomes(&mut health, &source_outcomes);
                }
                let restart_after_stale = matches!(
                    &attempt_result,
                    Err(PoiCacheServiceError::StaleGeneration { .. })
                );
                let retry_completion = drop_completed_attempt(finished);
                if restart_after_stale {
                    task.preloaded_caches.clear();
                    let Err(stale_error) = attempt_result else {
                        unreachable!("stale recovery requires a stale-generation error");
                    };
                    let _ = recover_chain_after_stale_attempt(
                        &mut task,
                        &mut active,
                        &mut health,
                        retry_completion,
                        stale_error,
                    )
                    .await;
                } else if let Some(response) = retry_completion {
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
            }
            _ = maintenance.tick(), if active.is_none()
                && public_cache_reset.is_none() => {
                generation = task.local_caches.current_generation();
                let _ = start_chain_poi_cache_attempt(
                    &mut task,
                    &mut active,
                    generation,
                    &health,
                    None,
                )
                .await;
            }
            () = wait_for_public_cache_reset_release(&mut public_cache_reset),
                if active.is_none() => {
                let public_cache_reset_gate = Arc::clone(&task.runtime.public_cache_reset_gate);
                let _public_cache_reset_admission = public_cache_reset_gate.read().await;
                public_cache_reset = None;
                generation = task.local_caches.current_generation();
                let _ = start_chain_poi_cache_attempt(
                    &mut task,
                    &mut active,
                    generation,
                    &health,
                    None,
                )
                .await;
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
            &task.local_caches,
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
    let _ = send_poi_artifact_cache_progress_for_generation(
        &task.progress_tx,
        &task.local_caches,
        generation,
        progress,
    );
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

async fn reset_chain_runtime(
    task: &ChainPoiCacheCoordinator,
    generation: u64,
    attempt_id: PoiArtifactCacheAttemptId,
) -> Result<(), PoiCacheServiceError> {
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
    let actual = task.local_caches.current_generation();
    if actual != generation {
        return Err(PoiCacheServiceError::StaleGeneration {
            expected: generation,
            actual,
        });
    }
    caches.clear();
    task.local_caches.mark_installed_generation(generation);
    task.local_caches.publish_committed_revision(true);
    send_poi_artifact_cache_progress_for_generation(
        &task.progress_tx,
        &task.local_caches,
        generation,
        new_poi_artifact_cache_progress(
            attempt_id,
            generation,
            task.chain_id,
            PoiArtifactCachePhase::Resetting,
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
    )?;
    drop(publication);
    Ok(())
}

async fn reset_chain_runtime_to_latest(
    task: &ChainPoiCacheCoordinator,
) -> Result<u64, PoiCacheServiceError> {
    loop {
        let generation = task.local_caches.current_generation();
        match reset_chain_runtime(task, generation, task.runtime.next_attempt_id()).await {
            Ok(()) => return Ok(generation),
            Err(PoiCacheServiceError::StaleGeneration { .. }) => {}
            Err(err) => return Err(err),
        }
    }
}

async fn recover_chain_after_stale_attempt(
    task: &mut ChainPoiCacheCoordinator,
    active: &mut Option<ActivePoiCacheAttempt>,
    health: &mut BTreeMap<FixedBytes<32>, PoiSourceHealth>,
    mut retry_completion: Option<oneshot::Sender<Result<(), PoiCacheServiceError>>>,
    stale_error: PoiCacheServiceError,
) -> u64 {
    let mut stale_error = Some(stale_error);
    loop {
        let generation = match reset_chain_runtime_to_latest(task).await {
            Ok(generation) => generation,
            Err(err) => {
                if let Some(response) = retry_completion.take() {
                    let _ = response.send(Err(err));
                }
                return task.local_caches.current_generation();
            }
        };
        *health = source_health_for_lists(
            task.db.as_ref(),
            task.chain_id,
            generation,
            &task.active_list_keys,
            &task.preloaded_caches,
        );
        let _ = start_chain_poi_cache_attempt(task, active, generation, health, None).await;
        let admitted = with_poi_artifact_cache_generation(
            task.local_caches.shared_generation(),
            |current_generation| {
                if current_generation != generation {
                    return false;
                }
                if let Some(response) = retry_completion.take() {
                    let _ = response.send(Err(stale_error
                        .take()
                        .expect("stale recovery response has one error")));
                }
                true
            },
        );
        if admitted {
            return generation;
        }
        cancel_active_attempt(active, |attempt_id| PoiCacheServiceError::StaleAttempt {
            attempt_id,
        });
    }
}

async fn start_chain_poi_cache_attempt(
    task: &mut ChainPoiCacheCoordinator,
    active: &mut Option<ActivePoiCacheAttempt>,
    generation: u64,
    health: &BTreeMap<FixedBytes<32>, PoiSourceHealth>,
    retry_completion: Option<oneshot::Sender<Result<(), PoiCacheServiceError>>>,
) -> Result<PoiArtifactCacheAttemptId, PoiCacheServiceError> {
    let Ok(_public_cache_reset_admission) = task.runtime.public_cache_reset_gate.try_read() else {
        return Err(PoiCacheServiceError::CorpusResetInProgress);
    };
    let attempt_id = task.runtime.next_attempt_id();
    let baseline = task.local_caches.read().await.clone();
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
            (*list_key, plan)
        })
        .collect::<BTreeMap<_, _>>();
    let use_artifact = source_plans.values().any(|plan| plan.use_artifact);
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
        preloaded_caches: std::mem::take(&mut task.preloaded_caches),
        attempt_id,
        generation,
        ready,
        source_plans,
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
        &task.local_caches,
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
    preloaded_caches: BTreeMap<FixedBytes<32>, PersistedPoiArtifactCache>,
    attempt_id: PoiArtifactCacheAttemptId,
    generation: u64,
    ready: bool,
    source_plans: BTreeMap<FixedBytes<32>, PoiListAttemptPlan>,
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
    for (list_index, list_key) in job.active_list_keys.iter().copied().enumerate() {
        let plan = job
            .source_plans
            .get(&list_key)
            .copied()
            .expect("active POI list has a source plan");
        let identity =
            PoiCacheIdentity::new(EVM_CHAIN_TYPE, job.chain_id, DEFAULT_TXID_VERSION, list_key);
        let persisted = match job.preloaded_caches.remove(&list_key) {
            Some(persisted) => Some(persisted),
            None => match load_persisted_cache_for_publisher(
                job.db.as_ref(),
                &identity,
                job.artifact_config.trusted_publisher_pubkey,
            ) {
                Ok(persisted) => persisted,
                Err(err) => {
                    errors.push(err.to_string());
                    None
                }
            },
        };
        let expected_base =
            persisted
                .as_ref()
                .map_or(ExpectedPoiCorpusBase::NoValidCorpus, |persisted| {
                    ExpectedPoiCorpusBase::PayloadHash(alloy::primitives::keccak256(
                        &persisted.record.cache_payload,
                    ))
                });
        let baseline_cache = newest_cache(
            job.baseline.get(&list_key).cloned(),
            persisted.as_ref().map(|persisted| persisted.cache.clone()),
        )
        .unwrap_or_else(|| PoiCache::new(identity.clone()));
        let range_start_index = baseline_cache.progress().next_event_index;

        if plan.use_artifact {
            match prepare_artifact_candidate(
                &job,
                &client,
                list_index,
                list_key,
                identity,
                &mut observed_manifest,
            )
            .await
            {
                Ok(candidate) => {
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
                    match public_rpc_candidate_cache(&rpc_client, baseline_cache).await {
                        Ok(result) => {
                            source_outcomes.push(PoiListSourceOutcome {
                                list_key,
                                rpc: Some(PoiRpcAttemptOutcome::Succeeded {
                                    backlog_large: result.outcome.event_page_budget_exhausted,
                                }),
                                artifact_succeeded: false,
                            });
                            if let Some(cache) = result.candidate {
                                candidates.push(PreparedPoiCacheCandidate {
                                    list_key,
                                    cache: Some(cache),
                                    persistence: PreparedPoiCachePersistence::PublicRpc {
                                        range_start_index,
                                        expected_base,
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
            match public_rpc_candidate_cache(&rpc_client, baseline_cache).await {
                Ok(result) => {
                    source_outcomes.push(PoiListSourceOutcome {
                        list_key,
                        rpc: Some(PoiRpcAttemptOutcome::Succeeded {
                            backlog_large: result.outcome.event_page_budget_exhausted,
                        }),
                        artifact_succeeded: false,
                    });
                    if let Some(cache) = result.candidate {
                        candidates.push(PreparedPoiCacheCandidate {
                            list_key,
                            cache: Some(cache),
                            persistence: PreparedPoiCachePersistence::PublicRpc {
                                range_start_index,
                                expected_base,
                            },
                        });
                    }
                }
                Err(rpc_error) if plan.artifact_after_rpc_failure => {
                    match prepare_artifact_candidate(
                        &job,
                        &client,
                        list_index,
                        list_key,
                        identity,
                        &mut observed_manifest,
                    )
                    .await
                    {
                        Ok(candidate) => {
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
        result,
    }
}

async fn prepare_artifact_candidate(
    job: &PoiCacheCandidateJob,
    client: &reqwest::Client,
    list_index: usize,
    list_key: FixedBytes<32>,
    identity: PoiCacheIdentity,
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
    if let Err(error) =
        apply_staged_poi_cache_batch(task, attempt_id, generation, staged, &result).await
    {
        return FinishedPoiCacheAttempt { result: Err(error) };
    }
    FinishedPoiCacheAttempt { result }
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
    let actual_generation = task.local_caches.current_generation();
    if actual_generation != generation {
        return Err(PoiCacheServiceError::StaleGeneration {
            expected: generation,
            actual: actual_generation,
        });
    }
    let store = PoiCorpusStore::new(
        task.db.as_ref(),
        generation,
        task.artifact_config.trusted_publisher_pubkey,
    );
    let PreparedPoiCacheCandidate {
        list_key,
        cache,
        persistence,
    } = candidate;
    let persisted = match persistence {
        PreparedPoiCachePersistence::Artifact { prepared } => {
            let PreparedIngestion { candidate } = *prepared;
            let Some(commit) = (tokio::select! {
                biased;
                () = task.cancel.cancelled() => {
                    return Err(PoiCacheServiceError::Shutdown { attempt_id });
                }
                result = task
                    .poi_artifact_persistence
                    .commit_candidate_for_attempt(candidate, &task.cancel) => {
                    result.map_err(|err| PoiCacheServiceError::Refresh {
                        reason: err.to_string(),
                    })?
                }
            }) else {
                return Ok(None);
            };
            commit.persisted
        }
        PreparedPoiCachePersistence::PublicRpc {
            range_start_index,
            expected_base,
        } => store
            .commit_public_rpc(
                cache.as_ref().expect("public RPC candidate has a cache"),
                range_start_index,
                expected_base,
            )
            .map_err(|err| PoiCacheServiceError::Refresh {
                reason: err.to_string(),
            })?,
    };
    if task.cancel.is_cancelled() {
        return Err(PoiCacheServiceError::Shutdown { attempt_id });
    }
    let actual_generation = task.local_caches.current_generation();
    if actual_generation != generation {
        return Err(PoiCacheServiceError::StaleGeneration {
            expected: generation,
            actual: actual_generation,
        });
    }
    let Some(persisted) = persisted else {
        return Ok(None);
    };
    Ok(Some(StagedPoiCacheCandidate {
        list_key,
        cache: persisted.cache,
        payload: persisted.record.cache_payload,
    }))
}

struct StagedPoiCacheCandidate {
    list_key: FixedBytes<32>,
    cache: PoiCache,
    payload: Vec<u8>,
}

async fn apply_staged_poi_cache_batch(
    task: &ChainPoiCacheCoordinator,
    attempt_id: PoiArtifactCacheAttemptId,
    generation: u64,
    staged: Vec<StagedPoiCacheCandidate>,
    result: &Result<(), PoiCacheServiceError>,
) -> Result<(), PoiCacheServiceError> {
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
    let actual_generation = task.local_caches.current_generation();
    if actual_generation != generation {
        return Err(PoiCacheServiceError::StaleGeneration {
            expected: generation,
            actual: actual_generation,
        });
    }

    let mut next_caches = caches.clone();
    if task.local_caches.installed_generation() != generation {
        next_caches.clear();
    }
    let mut installed_any = false;
    let mut blocked_shields_changed = false;
    for candidate in staged {
        let changed = next_caches.get(&candidate.list_key).is_none_or(|current| {
            !current
                .to_bytes()
                .is_ok_and(|payload| payload.as_slice() == candidate.payload.as_slice())
        });
        if !changed {
            continue;
        }
        let blocked_changed = next_caches
            .get(&candidate.list_key)
            .is_none_or(|current| !current.blocked_shields_match(&candidate.cache));
        if install_cache_if_not_behind(&mut next_caches, candidate.list_key, candidate.cache) {
            installed_any = true;
            blocked_shields_changed |= blocked_changed;
        }
    }
    if task.local_caches.installed_generation() != generation {
        task.local_caches.mark_installed_generation(generation);
    }
    *caches = next_caches;
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
    Ok(())
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

fn newest_cache(first: Option<PoiCache>, second: Option<PoiCache>) -> Option<PoiCache> {
    match (first, second) {
        (Some(first), Some(second)) => {
            if first.progress().next_event_index >= second.progress().next_event_index {
                Some(first)
            } else {
                Some(second)
            }
        }
        (Some(cache), None) | (None, Some(cache)) => Some(cache),
        (None, None) => None,
    }
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

async fn synchronize_chain_cache_generation(
    chain_id: u64,
    local_caches: &LocalPoiCaches,
    preloaded_caches: Option<&mut BTreeMap<FixedBytes<32>, PersistedPoiArtifactCache>>,
) -> bool {
    let (installed_is_stale, preloaded_is_stale) = with_poi_artifact_cache_generation(
        local_caches.shared_generation(),
        |current_generation| {
            let installed_is_stale = local_caches.installed_generation() != current_generation;
            let preloaded_is_stale = preloaded_caches.as_ref().is_some_and(|preloaded| {
                preloaded
                    .values()
                    .any(|persisted| persisted.cache_generation != current_generation)
            });
            (installed_is_stale, preloaded_is_stale)
        },
    );
    if !installed_is_stale && !preloaded_is_stale {
        return false;
    }

    let generation_changed = local_caches.synchronize_generation().await;
    let mut preloaded_caches = preloaded_caches;
    let (removed_preloaded, current_generation) = with_poi_artifact_cache_generation(
        local_caches.shared_generation(),
        |current_generation| {
            let removed_preloaded = preloaded_caches.as_mut().map_or(0, |preloaded| {
                let previous_len = preloaded.len();
                preloaded.retain(|_, persisted| persisted.cache_generation == current_generation);
                previous_len.saturating_sub(preloaded.len())
            });
            (removed_preloaded, current_generation)
        },
    );
    if generation_changed || removed_preloaded > 0 {
        debug!(
            chain_id,
            current_generation,
            removed_preloaded,
            "synchronized chain-scoped POI caches to shared generation"
        );
    }
    generation_changed || removed_preloaded > 0
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
    with_poi_artifact_cache_generation(
        task.local_caches.shared_generation(),
        |current_generation| {
            if task.local_caches.installed_generation() != current_generation {
                caches.clear();
                task.local_caches
                    .mark_installed_generation(current_generation);
            }
            loaded.retain(|list_key, persisted| {
                if current_generation != persisted.cache_generation {
                    return false;
                }
                caches.insert(*list_key, persisted.cache.clone());
                true
            });
        },
    );
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
    with_poi_artifact_cache_generation(local_caches.shared_generation(), |current_generation| {
        local_caches.installed_generation() == current_generation
            && active_list_keys.iter().all(|list_key| {
                caches.get(list_key).is_some_and(|cache| {
                    cache.identity().chain_type == EVM_CHAIN_TYPE
                        && cache.identity().chain_id == chain_id
                        && cache.identity().txid_version == DEFAULT_TXID_VERSION
                        && cache.progress().next_event_index > 0
                })
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
    mut cache: PoiCache,
) -> Result<PoiRpcSyncResult, PoiCacheError> {
    let outcome = cache
        .sync_bounded(
            client,
            POI_EVENTS_PAGE_SIZE,
            POI_MERKLETREE_LEAVES_PAGE_SIZE,
            POI_RPC_RANGE_PAGE_BUDGET,
        )
        .await?;
    if cache.progress().next_event_index == 0 {
        return Ok(PoiRpcSyncResult {
            outcome,
            candidate: None,
        });
    }
    if !cache.validate_roots(client).await? {
        return Err(PoiCacheError::InvalidRoots);
    }
    let candidate = outcome.changed.then_some(cache);
    Ok(PoiRpcSyncResult { outcome, candidate })
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
        Self::new_with_persistence(db, artifact_config, http_client, poi_artifact_persistence)
    }

    fn with_active_list_keys(mut self, active_list_keys: Vec<FixedBytes<32>>) -> Self {
        self.active_list_keys = active_list_keys;
        self
    }

    pub(crate) async fn reset_poi_artifact_cache(&self) -> Result<u64, PoiCacheServiceError> {
        self.db
            .ensure_blob_kind_purge_supported(crate::poi_artifacts::POI_V4_RAW_CHUNK_BLOB_KIND)
            .map_err(|error| PoiCacheServiceError::Refresh {
                reason: error.to_string(),
            })?;
        let reset = crate::poi_artifacts::clear_poi_artifact_cache_for_reset(&self.db).await?;
        crate::poi_artifacts::reset_raw_chunk_cache(&self.db)
            .await
            .map_err(|error| PoiCacheServiceError::Refresh {
                reason: error.to_string(),
            })?;
        debug!(
            generation = reset.generation,
            "POI artifact cache generation published after durable reset"
        );
        self.synchronize_after_persisted_reset(reset.generation)
            .await?;
        info!(
            persisted_records = reset.removed,
            generation = reset.generation,
            "reset local artifact POI cache"
        );
        Ok(reset.removed)
    }

    pub(crate) async fn synchronize_after_persisted_reset(
        &self,
        generation: u64,
    ) -> Result<(), PoiCacheServiceError> {
        let chains: Vec<_> = self
            .chains
            .read()
            .await
            .iter()
            .map(|(chain_id, handle)| (*chain_id, handle.clone()))
            .collect();
        let chain_count = chains.len();
        let mut responses = Vec::with_capacity(chain_count);
        let mut first_error = None;
        let sends = join_all(chains.into_iter().map(|(chain_id, handle)| async move {
            let (response, result) = oneshot::channel();
            let send_result = handle
                .command_tx
                .send(ChainPoiCacheCommand::Reset {
                    generation,
                    response,
                })
                .await;
            (chain_id, handle, send_result.map(|()| result))
        }))
        .await;
        for (chain_id, handle, send_result) in sends {
            if let Ok(response) = send_result {
                responses.push((chain_id, handle, response));
            } else {
                self.remove_chain_handle(chain_id, &handle).await;
                if first_error.is_none() {
                    first_error = Some(PoiCacheServiceError::CoordinatorStopped);
                }
            }
        }
        let responses =
            join_all(
                responses
                    .into_iter()
                    .map(|(chain_id, handle, response)| async move {
                        (chain_id, handle, response.await)
                    }),
            )
            .await;
        for (chain_id, handle, result) in responses {
            if let Ok(result) = result {
                if let Err(err) = result
                    && first_error.is_none()
                {
                    first_error = Some(err);
                }
            } else {
                self.remove_chain_handle(chain_id, &handle).await;
                if first_error.is_none() {
                    first_error = Some(PoiCacheServiceError::CoordinatorStopped);
                }
            }
        }

        if let Some(err) = first_error {
            return Err(err);
        }

        debug!(
            generation,
            chain_count, "synchronized POI cache coordinators after reset"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ActivePoiCacheAttempt, ChainPoiCacheCommand, ChainPoiCacheCoordinator, EVM_CHAIN_TYPE,
        PersistedPoiArtifactCache, PoiCacheService, PoiCacheServiceError, PoiCacheServiceRuntime,
        PoiListSourceOutcome, PoiRpcAttemptOutcome, PoiSourceHealth, PreparedPoiCacheBatch,
        PreparedPoiCacheCandidate, PreparedPoiCachePersistence, StagedPoiCacheCandidate,
        apply_staged_poi_cache_batch, cancel_active_attempt, chain_poi_cache_list_progress,
        chain_poi_caches_available_for_lists, completion_progress_from_caches,
        drop_completed_attempt, emit_chain_poi_cache_ready_progress,
        finish_chain_poi_cache_attempt, install_cache_if_not_behind,
        new_poi_artifact_cache_progress, poi_cache_error_diagnostic, public_rpc_candidate_cache,
        publish_active_attempt_progress,
        publish_chain_poi_cache_ready_and_acknowledge_initialization, record_list_source_outcomes,
        recover_chain_after_stale_attempt, send_poi_artifact_cache_progress_for_generation,
        single_list_event_index, source_health_for_lists, stage_poi_cache_candidate,
        validate_artifact_manifest_sequences, with_poi_artifact_cache_generation,
    };
    use crate::chain::PoiArtifactPersistenceHandle;
    use crate::poi_artifacts::test_support::{load_persisted_cache, persist_public_rpc_cache};
    use crate::poi_artifacts::{
        ExpectedPoiCorpusBase, clear_poi_artifact_cache_for_reset,
        poi_artifact_cache_generation_cell, poi_corpus_authority, record_poi_rpc_success,
    };
    use crate::types::PoiCorpusRevision;
    use crate::types::{
        LocalPoiCaches, PoiArtifactCacheAttemptId, PoiArtifactCacheFailureKind,
        PoiArtifactCacheGraphProgress, PoiArtifactCachePhase, PoiArtifactCacheProgress,
        PoiArtifactManifestSource, PoiArtifactSourceConfig,
    };
    use crate::wallet::test_support::{LivePoiTailError, live_tail_candidate_cache};
    use crate::wallet::{LocalPoiMerkleProofSource, LocalPoiStatusReader, PoiStatusReader};
    use alloy::primitives::{FixedBytes, U256};
    use broadcaster_core::transact::DEFAULT_TXID_VERSION;
    use ed25519_dalek::{Signer, SigningKey};
    use local_db::{
        DbConfig, DbStore, PoiArtifactCacheRecord, PoiArtifactDescriptorRecord,
        PoiCacheRecordSource, PoiCorpusValidationRecord,
    };
    use poi::artifacts::SnapshotEvent;
    use poi::artifacts::verify::canonical_poi_event_message;
    use poi::cache::{PoiCache, PoiCacheError, PoiCacheIdentity};
    use poi::error::PoiRpcError;
    use poi::poi::{
        BlindedCommitmentData, BlockedShield, PoiEventType, PoiRpcClient, PoiSyncedListEvent,
        SignedPoiEvent, default_active_poi_list_key,
    };
    use railgun_wallet::PoiStatus;
    use railgun_wallet::tx::PoiMerkleProofSource;
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::mpsc::{self, Receiver};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    use tokio::sync::watch;
    use tokio_util::sync::CancellationToken;
    use tracing::{debug, info};
    use url::Url;

    static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

    const fn attempt_id(value: u64) -> PoiArtifactCacheAttemptId {
        PoiArtifactCacheAttemptId::new(value)
    }

    fn test_persistence(db: &Arc<DbStore>) -> PoiArtifactPersistenceHandle {
        PoiArtifactPersistenceHandle::new(Arc::clone(db), Arc::new(tokio::sync::Mutex::new(())))
    }

    async fn commit_poi_cache_candidate(
        task: &ChainPoiCacheCoordinator,
        attempt_id: PoiArtifactCacheAttemptId,
        generation: u64,
        candidate: PreparedPoiCacheCandidate,
    ) -> Result<(), PoiCacheServiceError> {
        let staged = stage_poi_cache_candidate(task, attempt_id, generation, candidate)
            .await?
            .into_iter()
            .collect();
        apply_staged_poi_cache_batch(task, attempt_id, generation, staged, &Ok(())).await
    }

    async fn emit_chain_poi_cache_completion_progress(
        progress_tx: &watch::Sender<BTreeMap<u64, PoiArtifactCacheProgress>>,
        chain_id: u64,
        local_caches: &LocalPoiCaches,
        active_list_keys: &[FixedBytes<32>],
        attempt_id: PoiArtifactCacheAttemptId,
        generation: u64,
        last_error: Option<String>,
    ) -> Result<(), PoiCacheServiceError> {
        let caches = local_caches.read().await;
        let progress = completion_progress_from_caches(
            attempt_id,
            generation,
            chain_id,
            &caches,
            active_list_keys,
            PoiArtifactCacheGraphProgress::default(),
            last_error,
        );
        drop(caches);
        send_poi_artifact_cache_progress_for_generation(
            progress_tx,
            local_caches,
            generation,
            progress,
        )
    }

    async fn install_generated_cache_if_current(
        local_caches: &LocalPoiCaches,
        list_key: FixedBytes<32>,
        cache: PoiCache,
        candidate_generation: u64,
    ) -> bool {
        let _revision_fence = local_caches.revision_write_fence().await;
        let mut caches = local_caches.write().await;
        let installed = with_poi_artifact_cache_generation(
            local_caches.shared_generation(),
            |current_generation| {
                if current_generation != candidate_generation {
                    return false;
                }
                if local_caches.installed_generation() != candidate_generation {
                    caches.clear();
                    local_caches.mark_installed_generation(candidate_generation);
                }
                install_cache_if_not_behind(&mut caches, list_key, cache)
            },
        );
        if installed {
            local_caches.publish_committed_revision(true);
        }
        installed
    }

    async fn install_loaded_persisted_chain_poi_caches(
        chain_id: u64,
        local_caches: &LocalPoiCaches,
        mut loaded: BTreeMap<FixedBytes<32>, PersistedPoiArtifactCache>,
        started: Instant,
    ) -> BTreeMap<FixedBytes<32>, PersistedPoiArtifactCache> {
        let loaded_count = loaded.len();
        if loaded_count > 0 {
            let _revision_fence = local_caches.revision_write_fence().await;
            let lock_started = Instant::now();
            let mut caches = local_caches.write().await;
            let lock_wait_elapsed_ms = lock_started.elapsed().as_millis();
            with_poi_artifact_cache_generation(
                local_caches.shared_generation(),
                |current_generation| {
                    if local_caches.installed_generation() != current_generation {
                        caches.clear();
                        local_caches.mark_installed_generation(current_generation);
                    }
                    loaded.retain(|list_key, persisted| {
                        if current_generation != persisted.cache_generation {
                            return false;
                        }
                        caches.insert(*list_key, persisted.cache.clone());
                        true
                    });
                },
            );
            let installed_count = loaded.len();
            if installed_count > 0 {
                local_caches.publish_committed_revision(true);
            }
            if installed_count != loaded_count {
                debug!(
                    chain_id,
                    loaded_count,
                    installed_count,
                    "discarded stale persisted chain-scoped artifact POI caches"
                );
            }
            info!(
                chain_id,
                loaded_count,
                installed_count,
                lock_wait_elapsed_ms,
                elapsed_ms = started.elapsed().as_millis(),
                "installed persisted chain-scoped artifact POI cache"
            );
        }
        loaded
    }

    async fn install_tailed_poi_cache_if_current(
        local_caches: &LocalPoiCaches,
        list_key: FixedBytes<32>,
        cache: PoiCache,
        expected_next_event_index: u64,
        candidate_generation: u64,
    ) -> bool {
        let mut caches = local_caches.write().await;
        with_poi_artifact_cache_generation(local_caches.shared_generation(), |current_generation| {
            if current_generation != candidate_generation
                || local_caches.installed_generation() != candidate_generation
            {
                return false;
            }
            let Some(current) = caches.get(&list_key) else {
                return false;
            };
            if current.progress().next_event_index != expected_next_event_index {
                return false;
            }
            caches.insert(list_key, cache);
            true
        })
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

        let generation_cell = poi_artifact_cache_generation_cell(&db).expect("cache generation");
        let generation = generation_cell.load(Ordering::Acquire);
        let local_caches =
            LocalPoiCaches::new(poi_corpus_authority(&db).expect("corpus authority"));
        let (_command_tx, command_rx) = tokio::sync::mpsc::channel(1);
        let (job_tx, job_rx) = tokio::sync::mpsc::unbounded_channel();
        let (progress_tx, _) = tokio::sync::watch::channel(BTreeMap::new());
        let coordinator = ChainPoiCacheCoordinator {
            db: Arc::clone(&db),
            http_client: None,
            poi_rpc_url: mock.url.into(),
            artifact_config: artifact_config(),
            chain_id: 1,
            local_caches: local_caches.clone(),
            active_list_keys: vec![list_key],
            preloaded_caches: BTreeMap::new(),
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
        let generation = poi_artifact_cache_generation_cell(&db)
            .expect("cache generation")
            .load(Ordering::Acquire);
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
            chain_id: 1,
            local_caches,
            active_list_keys: vec![list_key],
            preloaded_caches: BTreeMap::new(),
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
    async fn poi_cache_service_reuses_chain_cache_handle() {
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
        let other_chain = service.start_chain(137).await.expect("other chain start");

        assert!(first.ptr_eq(&second));
        assert!(!first.ptr_eq(&other_chain));
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
        let dead_caches = LocalPoiCaches::new(Arc::clone(&service.cache_authority));
        service
            .chain_caches
            .write()
            .await
            .insert(1, dead_caches.clone());
        let (command_tx, command_rx) = tokio::sync::mpsc::channel(1);
        drop(command_rx);
        let (initialized_tx, initialized_rx) = tokio::sync::watch::channel(false);
        drop(initialized_tx);
        let (stopped_tx, stopped_rx) = tokio::sync::watch::channel(false);
        drop(stopped_tx);
        service.chains.write().await.insert(
            1,
            super::ChainPoiCacheHandle {
                local_caches: dead_caches.clone(),
                command_tx,
                initialized_rx,
                stopped_rx,
            },
        );

        assert!(matches!(
            service.local_caches(1).await,
            Err(PoiCacheServiceError::CoordinatorStopped)
        ));
        assert!(!service.chains.read().await.contains_key(&1));
        let restarted = service
            .start_chain(1)
            .await
            .expect("restart after dead initialization");
        assert!(restarted.ptr_eq(&dead_caches));

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
            local_caches.current_generation(),
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
            let Some(ChainPoiCacheCommand::Retry { admission }) = command_rx.recv().await else {
                panic!("expected retry command");
            };
            drop(admission);
            drop(initialized_tx);
            drop(stopped_tx);
        });
        service.chains.write().await.insert(
            1,
            super::ChainPoiCacheHandle {
                local_caches: LocalPoiCaches::new(Arc::clone(&service.cache_authority)),
                command_tx,
                initialized_rx,
                stopped_rx,
            },
        );

        assert!(matches!(
            service.retry_chain(1).await,
            Err(PoiCacheServiceError::CoordinatorStopped)
        ));
        assert!(!service.chains.read().await.contains_key(&1));
        coordinator.await.expect("coordinator task");

        drop(service);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn cache_lookup_retries_reset_at_latest_generation() {
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
        let local_caches = LocalPoiCaches::new(Arc::clone(&service.cache_authority));
        let first_reset = clear_poi_artifact_cache_for_reset(&db)
            .await
            .expect("first shared reset");
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(2);
        let (initialized_tx, initialized_rx) = tokio::sync::watch::channel(true);
        let (stopped_tx, stopped_rx) = tokio::sync::watch::channel(false);
        let task_db = Arc::clone(&db);
        let task_caches = local_caches.clone();
        let coordinator = tokio::spawn(async move {
            let Some(ChainPoiCacheCommand::Reset {
                generation,
                response,
            }) = command_rx.recv().await
            else {
                panic!("expected first reset command");
            };
            assert_eq!(generation, first_reset.generation);
            let second_reset = clear_poi_artifact_cache_for_reset(&task_db)
                .await
                .expect("second shared reset");
            let _ = response.send(Err(PoiCacheServiceError::StaleGeneration {
                expected: generation,
                actual: second_reset.generation,
            }));
            let Some(ChainPoiCacheCommand::Reset {
                generation,
                response,
            }) = command_rx.recv().await
            else {
                panic!("expected latest reset command");
            };
            assert_eq!(generation, second_reset.generation);
            task_caches.synchronize_generation().await;
            let _ = response.send(Ok(()));
            drop(initialized_tx);
            drop(stopped_tx);
            second_reset.generation
        });
        service.chains.write().await.insert(
            1,
            super::ChainPoiCacheHandle {
                local_caches: local_caches.clone(),
                command_tx,
                initialized_rx,
                stopped_rx,
            },
        );

        let returned = service
            .local_caches(1)
            .await
            .expect("latest-generation reset succeeds")
            .expect("chain cache");
        let latest_generation = coordinator.await.expect("coordinator task");
        assert!(returned.ptr_eq(&local_caches));
        assert_eq!(returned.current_generation(), latest_generation);
        assert_eq!(returned.installed_generation(), latest_generation);

        drop(service);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reset_drains_live_chain_when_another_coordinator_is_closed() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let service = Arc::new(
            PoiCacheService::new(Arc::clone(&db), artifact_config(), None)
                .expect("initialize POI cache service"),
        );
        let (closed_command_tx, closed_command_rx) = tokio::sync::mpsc::channel(1);
        drop(closed_command_rx);
        let (_closed_initialized_tx, closed_initialized_rx) = tokio::sync::watch::channel(true);
        let (_closed_stopped_tx, closed_stopped_rx) = tokio::sync::watch::channel(false);
        let (live_command_tx, mut live_command_rx) = tokio::sync::mpsc::channel(1);
        let (_live_initialized_tx, live_initialized_rx) = tokio::sync::watch::channel(true);
        let (_live_stopped_tx, live_stopped_rx) = tokio::sync::watch::channel(false);
        let (received_tx, received_rx) = tokio::sync::oneshot::channel();
        let release = Arc::new(tokio::sync::Notify::new());
        let live_release = Arc::clone(&release);
        let live = tokio::spawn(async move {
            let Some(ChainPoiCacheCommand::Reset { response, .. }) = live_command_rx.recv().await
            else {
                panic!("live coordinator did not receive reset");
            };
            let _ = received_tx.send(());
            live_release.notified().await;
            let _ = response.send(Ok(()));
        });
        let authority = Arc::clone(&service.cache_authority);
        let mut chains = service.chains.write().await;
        chains.insert(
            1,
            super::ChainPoiCacheHandle {
                local_caches: LocalPoiCaches::new(Arc::clone(&authority)),
                command_tx: closed_command_tx,
                initialized_rx: closed_initialized_rx,
                stopped_rx: closed_stopped_rx,
            },
        );
        chains.insert(
            2,
            super::ChainPoiCacheHandle {
                local_caches: LocalPoiCaches::new(authority),
                command_tx: live_command_tx,
                initialized_rx: live_initialized_rx,
                stopped_rx: live_stopped_rx,
            },
        );
        drop(chains);

        let reset_service = Arc::clone(&service);
        let reset = tokio::spawn(async move { reset_service.reset_poi_artifact_cache().await });
        tokio::time::timeout(Duration::from_secs(1), received_rx)
            .await
            .expect("reset reached live coordinator")
            .expect("live reset receipt");
        assert!(
            !reset.is_finished(),
            "reset must await the live coordinator after another send fails"
        );
        release.notify_one();
        let result = reset.await.expect("reset task");
        assert!(matches!(
            result,
            Err(PoiCacheServiceError::CoordinatorStopped)
        ));
        live.await.expect("live coordinator task");

        drop(service);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reset_fanout_reaches_healthy_chain_before_backpressure_clears() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let service = Arc::new(
            PoiCacheService::new(Arc::clone(&db), artifact_config(), None)
                .expect("initialize POI cache service"),
        );
        let (full_command_tx, mut full_command_rx) = tokio::sync::mpsc::channel(1);
        let (queued_response, _queued_result) = tokio::sync::oneshot::channel();
        full_command_tx
            .send(ChainPoiCacheCommand::Retry {
                admission: queued_response,
            })
            .await
            .expect("fill command channel");
        let (healthy_command_tx, mut healthy_command_rx) = tokio::sync::mpsc::channel(1);
        let (healthy_received_tx, healthy_received_rx) = tokio::sync::oneshot::channel();
        let full_release = Arc::new(tokio::sync::Notify::new());
        let task_release = Arc::clone(&full_release);
        let full = tokio::spawn(async move {
            task_release.notified().await;
            let Some(ChainPoiCacheCommand::Retry { admission }) = full_command_rx.recv().await
            else {
                panic!("expected queued retry");
            };
            let _ = admission.send(Err(PoiCacheServiceError::AttemptSuperseded {
                attempt_id: attempt_id(1),
            }));
            let Some(ChainPoiCacheCommand::Reset { response, .. }) = full_command_rx.recv().await
            else {
                panic!("expected reset after backpressure clears");
            };
            let _ = response.send(Ok(()));
        });
        let healthy = tokio::spawn(async move {
            let Some(ChainPoiCacheCommand::Reset { response, .. }) =
                healthy_command_rx.recv().await
            else {
                panic!("healthy coordinator did not receive reset");
            };
            let _ = healthy_received_tx.send(());
            let _ = response.send(Ok(()));
        });
        let authority = Arc::clone(&service.cache_authority);
        let (_full_initialized_tx, full_initialized_rx) = tokio::sync::watch::channel(true);
        let (_full_stopped_tx, full_stopped_rx) = tokio::sync::watch::channel(false);
        let (_healthy_initialized_tx, healthy_initialized_rx) = tokio::sync::watch::channel(true);
        let (_healthy_stopped_tx, healthy_stopped_rx) = tokio::sync::watch::channel(false);
        let mut chains = service.chains.write().await;
        chains.insert(
            1,
            super::ChainPoiCacheHandle {
                local_caches: LocalPoiCaches::new(Arc::clone(&authority)),
                command_tx: full_command_tx,
                initialized_rx: full_initialized_rx,
                stopped_rx: full_stopped_rx,
            },
        );
        chains.insert(
            2,
            super::ChainPoiCacheHandle {
                local_caches: LocalPoiCaches::new(authority),
                command_tx: healthy_command_tx,
                initialized_rx: healthy_initialized_rx,
                stopped_rx: healthy_stopped_rx,
            },
        );
        drop(chains);

        let reset_service = Arc::clone(&service);
        let reset = tokio::spawn(async move { reset_service.reset_poi_artifact_cache().await });
        tokio::time::timeout(Duration::from_secs(1), healthy_received_rx)
            .await
            .expect("healthy coordinator received concurrent fanout")
            .expect("healthy reset receipt");
        assert!(
            !reset.is_finished(),
            "reset must still wait for the backpressured coordinator"
        );
        full_release.notify_one();
        reset
            .await
            .expect("reset task")
            .expect("all reset responses succeed");
        full.await.expect("backpressured coordinator task");
        healthy.await.expect("healthy coordinator task");

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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reset_racing_chain_initialization_never_republishes_old_readiness() {
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
            db.as_ref(),
            &cache_with_events(identity, &[snapshot_event(0, FixedBytes::from([0x97; 32]))]),
        );
        let service = Arc::new(
            PoiCacheService::new(Arc::clone(&db), artifact_config(), None)
                .expect("initialize POI cache service")
                .with_poi_rpc_url(
                    Url::parse("http://127.0.0.1:1").expect("unavailable POI RPC URL"),
                ),
        );

        let (local_caches, reset_result) =
            tokio::join!(service.start_chain(1), service.reset_poi_artifact_cache());
        let local_caches = local_caches.expect("start chain while reset races");
        reset_result.expect("reset racing initialization");

        assert!(local_caches.read().await.is_empty());
        let progress = service
            .progress_rx()
            .borrow()
            .get(&1)
            .cloned()
            .expect("post-reset progress");
        assert!(!progress.ready_for_wallet_checks);

        service.shutdown().await;
        drop(service);
        drop(db);
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
        let payload = replacement.to_bytes().expect("encode replacement");
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
            chain_id: 1,
            local_caches: local_caches.clone(),
            active_list_keys: vec![list_key],
            preloaded_caches: BTreeMap::new(),
            command_rx,
            job_tx,
            job_rx,
            progress_tx,
            cancel: CancellationToken::new(),
            runtime: Arc::new(PoiCacheServiceRuntime::new()),
            poi_artifact_persistence: test_persistence(&db),
        };

        apply_staged_poi_cache_batch(
            &coordinator,
            attempt_id(61),
            local_caches.current_generation(),
            vec![StagedPoiCacheCandidate {
                list_key,
                cache: replacement,
                payload,
            }],
            &Ok(()),
        )
        .await
        .expect("publish blocked-only replacement");

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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reset_waits_for_admitted_refresh_then_clears_it() {
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
        let candidate = cache_with_events(
            identity,
            &[snapshot_event(0, FixedBytes::from([0x31_u8; 32]))],
        );
        let local_caches =
            LocalPoiCaches::new(poi_corpus_authority(&db).expect("corpus authority"));
        let mut revision_rx = local_caches.committed_revision_rx();
        let local_guard = local_caches.write().await;
        let install = tokio::spawn({
            let local_caches = local_caches.clone();
            async move {
                install_generated_cache_if_current(&local_caches, list_key, candidate, 0).await
            }
        });
        tokio::task::yield_now().await;
        assert!(
            !install.is_finished(),
            "old refresh must wait for cache lock"
        );

        let mut reset_task = {
            let db = Arc::clone(&db);
            tokio::spawn(async move { clear_poi_artifact_cache_for_reset(&db).await })
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut reset_task)
                .await
                .is_err(),
            "reset completed while an admitted refresh was waiting for the cache"
        );
        drop(local_guard);

        assert!(install.await.expect("refresh install task"));
        revision_rx
            .changed()
            .await
            .expect("generated install revision");
        assert_eq!(
            *revision_rx.borrow_and_update(),
            PoiCorpusRevision {
                revision: 1,
                blocked_shields_revision: 1,
            }
        );
        let reset = reset_task
            .await
            .expect("reset task")
            .expect("bump cache generation");
        assert!(local_caches.read().await.is_empty());
        let service = PoiCacheService::new(Arc::clone(&db), artifact_config(), None)
            .expect("initialize service from persistent generation");
        assert_eq!(
            service
                .cache_authority
                .generation_cell()
                .load(Ordering::Acquire),
            reset.generation
        );
        service.shutdown().await;
        drop(service);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reset_waits_for_admitted_preload_then_clears_it() {
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
        let persisted = cache_with_events(
            identity.clone(),
            &[snapshot_event(0, FixedBytes::from([0x41_u8; 32]))],
        );
        persist_cache(&db, &persisted);
        let persisted = load_persisted_cache(&db, &identity)
            .expect("load persisted cache candidate")
            .expect("persisted cache candidate");
        let preloaded = BTreeMap::from([(list_key, persisted)]);
        let local_caches =
            LocalPoiCaches::new(poi_corpus_authority(&db).expect("corpus authority"));
        let local_guard = local_caches.write().await;
        let preload = tokio::spawn({
            let local_caches = local_caches.clone();
            async move {
                install_loaded_persisted_chain_poi_caches(
                    1,
                    &local_caches,
                    preloaded,
                    Instant::now(),
                )
                .await
            }
        });
        tokio::task::yield_now().await;
        assert!(!preload.is_finished(), "preload must wait for cache lock");

        let mut reset_task = {
            let db = Arc::clone(&db);
            tokio::spawn(async move { clear_poi_artifact_cache_for_reset(&db).await })
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut reset_task)
                .await
                .is_err(),
            "reset completed while an admitted preload was waiting for the cache"
        );
        drop(local_guard);

        let _ = preload.await.expect("preload task");
        reset_task
            .await
            .expect("reset task")
            .expect("reset persisted cache");
        assert!(local_caches.read().await.is_empty());
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn services_for_one_db_share_generation_and_resynchronize_stale_caches() {
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
        let old_commitment = FixedBytes::from([0x51_u8; 32]);
        let old_cache = cache_with_events(identity.clone(), &[snapshot_event(0, old_commitment)]);
        persist_cache(&db, &old_cache);

        let unavailable_rpc = Url::parse("http://127.0.0.1:1").expect("unavailable RPC URL");
        let reset_service = Arc::new(
            PoiCacheService::new(Arc::clone(&db), artifact_config(), None)
                .expect("initialize reset service")
                .with_poi_rpc_url(unavailable_rpc.clone()),
        );
        let serving_service = PoiCacheService::new(Arc::clone(&db), artifact_config(), None)
            .expect("initialize serving service")
            .with_poi_rpc_url(unavailable_rpc);
        let reset_generation = reset_service.cache_authority.generation_cell();
        let serving_generation = serving_service.cache_authority.generation_cell();
        assert!(Arc::ptr_eq(&reset_generation, &serving_generation));

        let local_caches = serving_service
            .start_chain(1)
            .await
            .expect("start serving chain");
        assert!(local_caches.read().await.contains_key(&list_key));
        let status_reader = LocalPoiStatusReader::new(local_caches.clone());
        let proof_source = LocalPoiMerkleProofSource::new(local_caches.clone());
        let old_statuses = status_reader
            .pois_per_list(
                DEFAULT_TXID_VERSION,
                EVM_CHAIN_TYPE,
                1,
                &[list_key],
                &[BlindedCommitmentData::transact(old_commitment)],
            )
            .await
            .expect("read old-generation status before reset");
        assert_eq!(
            old_statuses
                .get(&old_commitment)
                .and_then(|per_list| per_list.get(&list_key)),
            Some(&PoiStatus::Valid)
        );
        proof_source
            .poi_merkle_proofs(
                DEFAULT_TXID_VERSION,
                EVM_CHAIN_TYPE,
                1,
                &list_key,
                &[old_commitment],
            )
            .await
            .expect("read old-generation proof before reset");
        let old_generation = serving_generation.load(Ordering::Acquire);
        let old_refresh = cache_with_events(
            identity.clone(),
            &[
                snapshot_event(0, FixedBytes::from([0x51_u8; 32])),
                snapshot_event(1, FixedBytes::from([0x52_u8; 32])),
            ],
        );

        let held_read = local_caches.read().await;
        let mut reset_task = {
            let reset_service = Arc::clone(&reset_service);
            tokio::spawn(async move { reset_service.reset_poi_artifact_cache().await })
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut reset_task)
                .await
                .is_err(),
            "reset completed while a pre-reset corpus read was still active"
        );
        assert!(held_read.contains_key(&list_key));
        drop(held_read);
        reset_task
            .await
            .expect("reset task")
            .expect("reset shared POI cache");
        let current_generation = reset_generation.load(Ordering::Acquire);
        assert_eq!(current_generation, old_generation + 1);
        assert_eq!(
            serving_generation.load(Ordering::Acquire),
            current_generation
        );

        let stale_statuses = status_reader
            .pois_per_list(
                DEFAULT_TXID_VERSION,
                EVM_CHAIN_TYPE,
                1,
                &[list_key],
                &[BlindedCommitmentData::transact(old_commitment)],
            )
            .await
            .expect("old reader fences status after cross-service reset");
        assert_eq!(
            stale_statuses
                .get(&old_commitment)
                .and_then(|per_list| per_list.get(&list_key)),
            Some(&PoiStatus::Unknown)
        );
        proof_source
            .poi_merkle_proofs(
                DEFAULT_TXID_VERSION,
                EVM_CHAIN_TYPE,
                1,
                &list_key,
                &[old_commitment],
            )
            .await
            .expect_err("old reader must not return a stale proof after cross-service reset");
        assert!(
            local_caches.read().await.is_empty(),
            "direct readers must fence the old-generation corpus without service re-entry"
        );
        assert_eq!(local_caches.installed_generation(), current_generation);

        let exposed = serving_service
            .start_chain(1)
            .await
            .expect("start serving chain");
        assert!(local_caches.ptr_eq(&exposed));
        assert!(
            exposed.read().await.is_empty(),
            "the second service must clear its old-generation corpus before exposing it"
        );
        assert!(
            !install_generated_cache_if_current(
                &local_caches,
                list_key,
                old_refresh,
                old_generation,
            )
            .await,
            "an old-generation refresh must be rejected by the shared fence"
        );

        let preloaded_cache = cache_with_events(
            identity.clone(),
            &[snapshot_event(0, FixedBytes::from([0x61_u8; 32]))],
        );
        persist_cache(&db, &preloaded_cache);
        let persisted = load_persisted_cache(&db, &identity)
            .expect("load current-generation persisted cache")
            .expect("current-generation persisted cache");
        assert_eq!(persisted.cache_generation, current_generation);
        let active_list_keys = vec![list_key];
        let installed_preloads = install_loaded_persisted_chain_poi_caches(
            1,
            &local_caches,
            BTreeMap::from([(list_key, persisted)]),
            Instant::now(),
        )
        .await;
        assert_eq!(installed_preloads.len(), 1);
        let current_commitment = FixedBytes::from([0x61_u8; 32]);
        let current_statuses = status_reader
            .pois_per_list(
                DEFAULT_TXID_VERSION,
                EVM_CHAIN_TYPE,
                1,
                &[list_key],
                &[BlindedCommitmentData::transact(current_commitment)],
            )
            .await
            .expect("old reader sees current-generation status after install");
        assert_eq!(
            current_statuses
                .get(&current_commitment)
                .and_then(|per_list| per_list.get(&list_key)),
            Some(&PoiStatus::Valid)
        );
        proof_source
            .poi_merkle_proofs(
                DEFAULT_TXID_VERSION,
                EVM_CHAIN_TYPE,
                1,
                &list_key,
                &[current_commitment],
            )
            .await
            .expect("old reader sees current-generation proof after install");
        assert!(
            chain_poi_caches_available_for_lists(1, &local_caches, &active_list_keys).await,
            "a current-generation install must restore cache readiness"
        );

        let refreshed_cache = cache_with_events(
            identity.clone(),
            &[
                snapshot_event(0, FixedBytes::from([0x61_u8; 32])),
                snapshot_event(1, FixedBytes::from([0x62_u8; 32])),
            ],
        );
        assert!(
            install_generated_cache_if_current(
                &local_caches,
                list_key,
                refreshed_cache,
                current_generation,
            )
            .await
        );

        let live_tailed_cache = cache_with_events(
            identity,
            &[
                snapshot_event(0, FixedBytes::from([0x61_u8; 32])),
                snapshot_event(1, FixedBytes::from([0x62_u8; 32])),
                snapshot_event(2, FixedBytes::from([0x63_u8; 32])),
            ],
        );
        assert!(
            install_tailed_poi_cache_if_current(
                &local_caches,
                list_key,
                live_tailed_cache,
                2,
                current_generation,
            )
            .await
        );
        assert_eq!(
            local_caches
                .read()
                .await
                .get(&list_key)
                .expect("live-tailed cache")
                .progress()
                .next_event_index,
            3
        );
        assert!(chain_poi_caches_available_for_lists(1, &local_caches, &active_list_keys).await);
        let (progress_tx, progress_rx) = tokio::sync::watch::channel(BTreeMap::new());
        emit_chain_poi_cache_ready_progress(
            &progress_tx,
            1,
            &local_caches,
            &active_list_keys,
            attempt_id(1),
            current_generation,
            serving_service.runtime.as_ref(),
            &serving_service.cancel,
            None,
        )
        .await
        .expect("publish current-generation readiness");
        assert!(
            progress_rx
                .borrow()
                .get(&1)
                .expect("serving progress")
                .ready_for_wallet_checks
        );

        serving_service.shutdown().await;
        reset_service.shutdown().await;
        drop(serving_service);
        drop(reset_service);
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
    async fn stale_coordinator_commit_reloads_winning_durable_corpus() {
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
        let first = FixedBytes::from([0x41; 32]);
        let old_cache = cache_with_events(identity.clone(), &[snapshot_event(0, first)]);
        let generation = poi_artifact_cache_generation_cell(&db)
            .expect("cache generation")
            .load(Ordering::Acquire);
        assert_eq!(
            persist_public_rpc_cache(
                &db,
                &old_cache,
                generation,
                0,
                ExpectedPoiCorpusBase::NoValidCorpus,
            )
            .expect("persist old durable corpus"),
            crate::poi_artifacts::CorpusCommitOutcome::Applied
        );
        let expected_old_base = ExpectedPoiCorpusBase::PayloadHash(alloy::primitives::keccak256(
            old_cache.to_bytes().expect("encode old corpus"),
        ));
        let rejected_candidate = cache_with_events(
            identity.clone(),
            &[
                snapshot_event(0, first),
                snapshot_event(1, FixedBytes::from([0x42; 32])),
            ],
        );
        let winning_cache = cache_with_events(
            identity.clone(),
            &[
                snapshot_event(0, first),
                snapshot_event(1, FixedBytes::from([0x43; 32])),
            ],
        );
        let authority = poi_corpus_authority(&db).expect("corpus authority");
        let local_a = LocalPoiCaches::new(Arc::clone(&authority));
        local_a.write().await.insert(list_key, old_cache.clone());
        let local_b = LocalPoiCaches::new(authority);
        local_b.write().await.insert(list_key, old_cache);
        let mut revision_a = local_a.committed_revision_rx();
        let coordinator = |local_caches: LocalPoiCaches| {
            let (_command_tx, command_rx) = tokio::sync::mpsc::channel(1);
            let (job_tx, job_rx) = tokio::sync::mpsc::unbounded_channel();
            let (progress_tx, _) = tokio::sync::watch::channel(BTreeMap::new());
            ChainPoiCacheCoordinator {
                db: Arc::clone(&db),
                http_client: None,
                poi_rpc_url: Url::parse("http://127.0.0.1:1")
                    .expect("POI RPC URL")
                    .into(),
                artifact_config: artifact_config(),
                chain_id: 1,
                local_caches,
                active_list_keys: vec![list_key],
                preloaded_caches: BTreeMap::new(),
                command_rx,
                job_tx,
                job_rx,
                progress_tx,
                cancel: tokio_util::sync::CancellationToken::new(),
                runtime: Arc::new(PoiCacheServiceRuntime::new()),
                poi_artifact_persistence: test_persistence(&db),
            }
        };

        let coordinator_b = coordinator(local_b);
        commit_poi_cache_candidate(
            &coordinator_b,
            attempt_id(1),
            generation,
            PreparedPoiCacheCandidate {
                list_key,
                cache: Some(winning_cache.clone()),
                persistence: PreparedPoiCachePersistence::PublicRpc {
                    range_start_index: 1,
                    expected_base: expected_old_base,
                },
            },
        )
        .await
        .expect("coordinator B commits winning corpus");
        drop(coordinator_b);
        assert!(
            !revision_a
                .has_changed()
                .expect("coordinator A revision state")
        );

        let coordinator_a = coordinator(local_a.clone());
        commit_poi_cache_candidate(
            &coordinator_a,
            attempt_id(2),
            generation,
            PreparedPoiCacheCandidate {
                list_key,
                cache: Some(rejected_candidate.clone()),
                persistence: PreparedPoiCachePersistence::PublicRpc {
                    range_start_index: 1,
                    expected_base: expected_old_base,
                },
            },
        )
        .await
        .expect("coordinator A reloads after stale commit");

        revision_a
            .changed()
            .await
            .expect("reloaded corpus revision");
        assert_eq!(
            *revision_a.borrow_and_update(),
            PoiCorpusRevision {
                revision: 1,
                blocked_shields_revision: 0,
            }
        );
        let reloaded = local_a
            .read()
            .await
            .get(&list_key)
            .cloned()
            .expect("coordinator A reloaded corpus");
        assert_eq!(
            reloaded.to_bytes().expect("encode reloaded corpus"),
            winning_cache.to_bytes().expect("encode winning corpus")
        );
        assert_ne!(
            reloaded.to_bytes().expect("encode reloaded corpus"),
            rejected_candidate
                .to_bytes()
                .expect("encode rejected candidate")
        );
        let durable = load_persisted_cache(&db, &identity)
            .expect("load durable corpus")
            .expect("winning durable corpus");
        assert_eq!(
            durable.cache.to_bytes().expect("encode durable corpus"),
            winning_cache.to_bytes().expect("encode winning corpus")
        );

        drop(coordinator_a);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn reset_waits_for_admitted_commit_then_removes_persistence() {
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
        let generation = poi_artifact_cache_generation_cell(&db)
            .expect("cache generation")
            .load(Ordering::Acquire);
        let local_caches =
            LocalPoiCaches::new(poi_corpus_authority(&db).expect("corpus authority"));
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
            chain_id: 1,
            local_caches: local_caches.clone(),
            active_list_keys: vec![list_key],
            preloaded_caches: BTreeMap::new(),
            command_rx,
            job_tx,
            job_rx,
            progress_tx,
            cancel: tokio_util::sync::CancellationToken::new(),
            runtime: Arc::new(PoiCacheServiceRuntime::new()),
            poi_artifact_persistence: test_persistence(&db),
        };
        let local_guard = local_caches.write().await;
        let mut commit = Box::pin(commit_poi_cache_candidate(
            &coordinator,
            attempt_id(9),
            generation,
            PreparedPoiCacheCandidate {
                list_key,
                cache: Some(candidate_cache),
                persistence: PreparedPoiCachePersistence::PublicRpc {
                    range_start_index: 0,
                    expected_base: ExpectedPoiCorpusBase::NoValidCorpus,
                },
            },
        ));
        assert!(
            futures::poll!(&mut commit).is_pending(),
            "commit should wait for the held cache guard"
        );
        let mut reset_task = {
            let db = Arc::clone(&db);
            tokio::spawn(async move { clear_poi_artifact_cache_for_reset(&db).await })
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut reset_task)
                .await
                .is_err(),
            "reset completed while an admitted commit was still active"
        );
        drop(local_guard);

        commit.as_mut().await.expect("commit before reset");
        revision_rx
            .changed()
            .await
            .expect("candidate commit revision");
        assert_eq!(
            *revision_rx.borrow_and_update(),
            PoiCorpusRevision {
                revision: 1,
                blocked_shields_revision: 1,
            }
        );
        drop(commit);
        reset_task
            .await
            .expect("reset task")
            .expect("reset after commit");
        assert!(local_caches.read().await.is_empty());
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
        let generation = poi_artifact_cache_generation_cell(&db)
            .expect("cache generation")
            .load(Ordering::Acquire);
        let local_caches =
            LocalPoiCaches::new(poi_corpus_authority(&db).expect("corpus authority"));
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
            chain_id: 1,
            local_caches: local_caches.clone(),
            active_list_keys: vec![list_key, FixedBytes::from([0x91; 32])],
            preloaded_caches: BTreeMap::new(),
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
                candidates: vec![PreparedPoiCacheCandidate {
                    list_key,
                    cache: Some(cache_with_events(
                        identity.clone(),
                        &[snapshot_event(0, FixedBytes::from([0x92; 32]))],
                    )),
                    persistence: PreparedPoiCachePersistence::PublicRpc {
                        range_start_index: 0,
                        expected_base: ExpectedPoiCorpusBase::NoValidCorpus,
                    },
                }],
                source_outcomes: Vec::new(),
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
        let generation = poi_artifact_cache_generation_cell(&db)
            .expect("cache generation")
            .load(Ordering::Acquire);
        let local_caches =
            LocalPoiCaches::new(poi_corpus_authority(&db).expect("corpus authority"));
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
            chain_id: 1,
            local_caches: local_caches.clone(),
            active_list_keys: vec![list_key, second_list_key],
            preloaded_caches: BTreeMap::new(),
            command_rx,
            job_tx,
            job_rx,
            progress_tx,
            cancel: tokio_util::sync::CancellationToken::new(),
            runtime: Arc::new(PoiCacheServiceRuntime::new()),
            poi_artifact_persistence: test_persistence(&db),
        };
        let candidates = vec![
            PreparedPoiCacheCandidate {
                list_key,
                cache: Some(candidate_cache),
                persistence: PreparedPoiCachePersistence::PublicRpc {
                    range_start_index: 0,
                    expected_base: ExpectedPoiCorpusBase::NoValidCorpus,
                },
            },
            PreparedPoiCacheCandidate {
                list_key: second_list_key,
                cache: Some(cache_with_events(
                    second_identity.clone(),
                    &[snapshot_event(0, FixedBytes::from([0x76; 32]))],
                )),
                persistence: PreparedPoiCachePersistence::PublicRpc {
                    range_start_index: 0,
                    expected_base: ExpectedPoiCorpusBase::NoValidCorpus,
                },
            },
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stale_reset_command_preserves_current_generation_attempt() {
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
        let retry_attempt_id = retry.attempt_id();
        let retry = tokio::spawn(retry.wait());
        stalled
            .accepted
            .recv_timeout(Duration::from_secs(2))
            .expect("retry attempt reached network");
        let progress_before = service
            .progress_rx()
            .borrow()
            .get(&1)
            .cloned()
            .expect("active attempt progress");
        assert_eq!(progress_before.attempt_id, retry_attempt_id);
        let command_tx = service
            .chains
            .read()
            .await
            .get(&1)
            .expect("chain coordinator")
            .command_tx
            .clone();
        let current_generation = service
            .cache_authority
            .generation_cell()
            .load(Ordering::Acquire);
        let stale_generation = current_generation.saturating_add(1);
        let (response, result) = tokio::sync::oneshot::channel();
        command_tx
            .send(ChainPoiCacheCommand::Reset {
                generation: stale_generation,
                response,
            })
            .await
            .expect("send stale reset command");

        assert!(matches!(
            result.await.expect("stale reset response"),
            Err(PoiCacheServiceError::StaleGeneration {
                expected,
                actual,
            }) if expected == stale_generation && actual == current_generation
        ));
        tokio::task::yield_now().await;
        assert!(
            !retry.is_finished(),
            "stale reset must not cancel the current-generation retry"
        );
        let progress_after = service
            .progress_rx()
            .borrow()
            .get(&1)
            .cloned()
            .expect("progress after stale reset");
        assert_eq!(progress_after.phase, progress_before.phase);
        assert_eq!(
            progress_after.ready_for_wallet_checks,
            progress_before.ready_for_wallet_checks
        );

        service.shutdown().await;
        let retry_result = tokio::time::timeout(Duration::from_secs(1), retry)
            .await
            .expect("shutdown cancelled preserved retry")
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
    async fn retry_result_is_stale_after_reset() {
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

        service
            .reset_poi_artifact_cache()
            .await
            .expect("reset POI cache");
        let retry_result = tokio::time::timeout(Duration::from_secs(1), retry)
            .await
            .expect("retry cancelled promptly")
            .expect("retry task");
        assert!(
            matches!(
                retry_result,
                Err(PoiCacheServiceError::StaleAttempt { .. }
                    | PoiCacheServiceError::StaleGeneration { .. })
            ),
            "reset must make the superseded retry result stale"
        );
        stalled
            .accepted
            .recv_timeout(Duration::from_secs(2))
            .expect("reset started a fresh attempt");

        service.shutdown().await;
        drop(service);
        drop(stalled);
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
        let local_caches =
            LocalPoiCaches::new(poi_corpus_authority(&db).expect("corpus authority"));
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
            chain_id: 1,
            local_caches,
            active_list_keys: vec![default_active_poi_list_key()],
            preloaded_caches: BTreeMap::new(),
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

    #[tokio::test]
    async fn reset_after_commit_suppresses_old_generation_completion_progress() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp db");
        let generation_cell = poi_artifact_cache_generation_cell(&db).expect("cache generation");
        let generation = generation_cell.load(Ordering::Acquire);
        let list_key = default_active_poi_list_key();
        let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
        let local_caches =
            LocalPoiCaches::new(poi_corpus_authority(&db).expect("corpus authority"));
        local_caches.write().await.insert(
            list_key,
            cache_with_events(identity, &[snapshot_event(0, FixedBytes::from([0x96; 32]))]),
        );
        let (progress_tx, progress_rx) = tokio::sync::watch::channel(BTreeMap::new());

        let reset = clear_poi_artifact_cache_for_reset(&db)
            .await
            .expect("reset after candidate commit");
        assert!(reset.generation > generation);
        let result = emit_chain_poi_cache_completion_progress(
            &progress_tx,
            1,
            &local_caches,
            &[list_key],
            attempt_id(1),
            generation,
            None,
        )
        .await;

        assert!(matches!(
            result,
            Err(PoiCacheServiceError::StaleGeneration {
                expected,
                actual,
            }) if expected == generation && actual == reset.generation
        ));
        assert!(progress_rx.borrow().is_empty());
        assert!(local_caches.read().await.is_empty());

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn automatic_stale_recovery_retries_latest_generation() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create temp db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open temp db"),
        );
        let local_caches =
            LocalPoiCaches::new(poi_corpus_authority(&db).expect("corpus authority"));
        let local_guard = local_caches.write().await;
        let (_command_tx, command_rx) = tokio::sync::mpsc::channel(1);
        let (job_tx, job_rx) = tokio::sync::mpsc::unbounded_channel();
        let (progress_tx, _) = tokio::sync::watch::channel(BTreeMap::new());
        let mut coordinator = ChainPoiCacheCoordinator {
            db: Arc::clone(&db),
            http_client: None,
            poi_rpc_url: Url::parse("http://127.0.0.1:1")
                .expect("POI RPC URL")
                .into(),
            artifact_config: artifact_config(),
            chain_id: 1,
            local_caches: local_caches.clone(),
            active_list_keys: vec![default_active_poi_list_key()],
            preloaded_caches: BTreeMap::new(),
            command_rx,
            job_tx,
            job_rx,
            progress_tx,
            cancel: tokio_util::sync::CancellationToken::new(),
            runtime: Arc::new(PoiCacheServiceRuntime::new()),
            poi_artifact_persistence: test_persistence(&db),
        };
        let mut active = None;
        let mut health = BTreeMap::new();
        let (response, result) = tokio::sync::oneshot::channel();
        drop(local_guard);
        let reset = clear_poi_artifact_cache_for_reset(&db)
            .await
            .expect("advance generation before automatic recovery");
        let recovered_generation = recover_chain_after_stale_attempt(
            &mut coordinator,
            &mut active,
            &mut health,
            Some(response),
            PoiCacheServiceError::StaleGeneration {
                expected: 0,
                actual: 1,
            },
        )
        .await;
        assert_eq!(recovered_generation, reset.generation);
        assert_eq!(local_caches.installed_generation(), reset.generation);
        assert_eq!(
            active.as_ref().map(|attempt| attempt.generation),
            Some(reset.generation)
        );
        assert!(matches!(
            result.await.expect("stale retry response"),
            Err(PoiCacheServiceError::StaleGeneration { .. })
        ));

        drop(active);
        drop(coordinator);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
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

        let second = service.retry_chain(1).await.expect("admit second retry");
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
            .chains
            .write()
            .await
            .remove(&1)
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
