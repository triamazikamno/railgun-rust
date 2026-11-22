use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::SystemTime;

use alloy::primitives::Address;
use futures::future::join_all;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use local_db::DbStore;

use crate::amount_statistics::AmountStatisticsStatus;
use crate::chain::{
    ChainError, ChainHandle, ChainPublicSyncCacheReset, ChainService, PreparedChainService,
    PublicDataPlaneError,
};
use crate::poi_submission::{PoiSubmissionScheduler, PoiSubmissionSchedulerConfig};
use crate::public_cache::{
    PersistedPublicSyncCacheResetError, PersistedPublicSyncCacheResetReport,
    reset_persisted_public_sync_caches,
};
use crate::runtime_admission::{DbRuntimeLease, DbRuntimeOwnerKind};
use crate::types::{ChainConfig, ChainKey, GlobalPoiPolicy, WalletConfig};
use crate::wallet::WalletHandle;
use trustless_artifacts::GatewayPool;

#[derive(Debug, thiserror::Error)]
pub enum SyncManagerError {
    #[error("database is already owned by an active runtime operation: {path}")]
    DatabaseAlreadyOwned { path: PathBuf },
    #[error("sync manager is shut down")]
    Shutdown,
    #[error("chain start was cancelled by chain removal")]
    ChainStartRemoved,
    #[error("chain start was cancelled by public cache reset")]
    ChainStartReset,
    #[error(
        "indexed POI coordinator conflict for chain {chain_id}: existing contract {existing_contract}, requested contract {requested_contract}"
    )]
    PoiCoordinatorConflict {
        chain_id: u64,
        existing_contract: Address,
        requested_contract: Address,
    },
    #[error("chain not found")]
    ChainNotFound,
    #[error("wallet not found")]
    WalletNotFound,
    #[error("chain error: {0}")]
    Chain(#[from] ChainError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainPublicSyncCacheResetResult {
    pub chain: ChainKey,
    pub result: Result<ChainPublicSyncCacheReset, PublicDataPlaneError>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicSyncCachesResetReport {
    pub chains: Vec<ChainPublicSyncCacheResetResult>,
    pub persisted: Result<PersistedPublicSyncCacheResetReport, PersistedPublicSyncCacheResetError>,
    pub total_removed_entries: u64,
}

impl Default for PublicSyncCachesResetReport {
    fn default() -> Self {
        Self {
            chains: Vec::new(),
            persisted: Ok(PersistedPublicSyncCacheResetReport::default()),
            total_removed_entries: 0,
        }
    }
}

impl PublicSyncCachesResetReport {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.chains.is_empty()
            && self
                .persisted
                .as_ref()
                .is_ok_and(|persisted| persisted.total_removed_entries() == 0)
    }

    #[must_use]
    pub fn failed_chain_count(&self) -> usize {
        self.chains
            .iter()
            .filter(|chain| chain.result.is_err())
            .count()
    }
}

pub struct SyncManager {
    db: Arc<DbStore>,
    poi_policy: GlobalPoiPolicy,
    gateway_pool: StdMutex<Option<GatewayPool>>,
    /// Shared by every chain so admission spacing spans all of them.
    poi_submission_scheduler: Arc<PoiSubmissionScheduler>,
    state: Arc<StdMutex<SyncManagerState>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SyncManagerLifecycle {
    Running,
    Stopping,
    Stopped,
}

struct SyncManagerState {
    lifecycle: SyncManagerLifecycle,
    lease: Option<DbRuntimeLease>,
    chains: HashMap<ChainKey, Arc<ChainService>>,
    pending_starts: HashMap<ChainKey, PendingChainStart>,
    removals: HashMap<ChainKey, watch::Sender<bool>>,
    reset: Option<watch::Sender<bool>>,
    shutdown: Option<watch::Sender<bool>>,
    next_start_id: u64,
}

struct PendingChainStart {
    id: u64,
    cancel: CancellationToken,
    cancellation: Option<PendingStartCancellation>,
    done: watch::Sender<bool>,
}

#[derive(Clone, Copy)]
enum PendingStartCancellation {
    Shutdown,
    Removed,
    PublicCacheReset,
}

enum AddChainAdmission {
    Existing(Arc<ChainService>),
    Wait(watch::Receiver<bool>),
    Start {
        guard: PendingStartGuard,
        cancel: CancellationToken,
        lease: DbRuntimeLease,
    },
}

enum RemoveChainAdmission {
    WaitForReset(watch::Receiver<bool>),
    WaitForRemoval(watch::Receiver<bool>),
    Start {
        done: watch::Receiver<bool>,
        pending: Option<watch::Receiver<bool>>,
    },
}

struct PendingStartGuard {
    state: Arc<StdMutex<SyncManagerState>>,
    key: ChainKey,
    id: u64,
    finished: bool,
}

impl PendingStartGuard {
    fn finish_locked(&mut self, state: &mut SyncManagerState) {
        if state
            .pending_starts
            .get(&self.key)
            .is_some_and(|pending| pending.id == self.id)
            && let Some(pending) = state.pending_starts.remove(&self.key)
        {
            let _ = pending.done.send(true);
        }
        self.finished = true;
    }

    fn cancellation(&self) -> PendingStartCancellation {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state
            .pending_starts
            .get(&self.key)
            .filter(|pending| pending.id == self.id)
            .and_then(|pending| pending.cancellation)
            .unwrap_or(PendingStartCancellation::Shutdown)
    }
}

impl Drop for PendingStartGuard {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let state = Arc::clone(&self.state);
        let mut state = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.finish_locked(&mut state);
    }
}

struct ResetGuard {
    state: Arc<StdMutex<SyncManagerState>>,
}

impl Drop for ResetGuard {
    fn drop(&mut self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(done) = state.reset.take() {
            let _ = done.send(true);
        }
    }
}

impl SyncManager {
    pub fn new(db: Arc<DbStore>, poi_policy: GlobalPoiPolicy) -> Result<Self, SyncManagerError> {
        let lease = DbRuntimeLease::acquire(db.as_ref(), DbRuntimeOwnerKind::SyncManager)
            .map_err(|error| SyncManagerError::DatabaseAlreadyOwned { path: error.path })?;
        Ok(Self {
            db,
            poi_policy,
            gateway_pool: StdMutex::new(None),
            poi_submission_scheduler: PoiSubmissionScheduler::new(
                PoiSubmissionSchedulerConfig::default(),
                rand::make_rng(),
            ),
            state: Arc::new(StdMutex::new(SyncManagerState {
                lifecycle: SyncManagerLifecycle::Running,
                lease: Some(lease),
                chains: HashMap::new(),
                pending_starts: HashMap::new(),
                removals: HashMap::new(),
                reset: None,
                shutdown: None,
                next_start_id: 1,
            })),
        })
    }

    pub fn set_gateway_pool(&self, gateway_pool: GatewayPool) {
        *self
            .gateway_pool
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(gateway_pool);
    }

    pub async fn add_chain(&self, cfg: ChainConfig) -> Result<Arc<ChainService>, SyncManagerError> {
        self.add_chain_inner(cfg, None).await
    }

    pub async fn add_chain_with_rpc_http_client(
        &self,
        cfg: ChainConfig,
        rpc_http_client: reqwest::Client,
    ) -> Result<Arc<ChainService>, SyncManagerError> {
        self.add_chain_inner(cfg, Some(rpc_http_client)).await
    }

    async fn add_chain_inner(
        &self,
        cfg: ChainConfig,
        rpc_http_client: Option<reqwest::Client>,
    ) -> Result<Arc<ChainService>, SyncManagerError> {
        let key = ChainKey {
            chain_id: cfg.deployment.chain_id,
            contract: cfg.deployment.contract,
        };
        loop {
            let admission = {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if state.lifecycle != SyncManagerLifecycle::Running {
                    return Err(SyncManagerError::Shutdown);
                }
                if let Some(removal) = state.removals.iter().find_map(|(removing, done)| {
                    (removing == &key
                        || (self.poi_policy.is_indexed_artifacts()
                            && removing.chain_id == key.chain_id))
                        .then(|| done.subscribe())
                }) {
                    AddChainAdmission::Wait(removal)
                } else if let Some(existing) = state.chains.get(&key) {
                    AddChainAdmission::Existing(Arc::clone(existing))
                } else if let Some(reset) = state.reset.as_ref() {
                    AddChainAdmission::Wait(reset.subscribe())
                } else if let Some(pending) = state.pending_starts.get(&key) {
                    AddChainAdmission::Wait(pending.done.subscribe())
                } else if self.poi_policy.is_indexed_artifacts()
                    && let Some(existing) = state
                        .chains
                        .keys()
                        .chain(state.pending_starts.keys())
                        .find(|existing| existing.chain_id == key.chain_id)
                        .copied()
                {
                    return Err(SyncManagerError::PoiCoordinatorConflict {
                        chain_id: key.chain_id,
                        existing_contract: existing.contract,
                        requested_contract: key.contract,
                    });
                } else {
                    let id = state.next_start_id;
                    state.next_start_id = state.next_start_id.saturating_add(1);
                    let cancel = CancellationToken::new();
                    let (done, _) = watch::channel(false);
                    state.pending_starts.insert(
                        key,
                        PendingChainStart {
                            id,
                            cancel: cancel.clone(),
                            cancellation: None,
                            done,
                        },
                    );
                    AddChainAdmission::Start {
                        guard: PendingStartGuard {
                            state: Arc::clone(&self.state),
                            key,
                            id,
                            finished: false,
                        },
                        cancel,
                        lease: match state.lease.as_ref() {
                            Some(lease) => lease.clone(),
                            None => return Err(SyncManagerError::Shutdown),
                        },
                    }
                }
            };

            match admission {
                AddChainAdmission::Existing(service) => return Ok(service),
                AddChainAdmission::Wait(mut done) => {
                    wait_for_completion(&mut done).await;
                }
                AddChainAdmission::Start {
                    mut guard,
                    cancel,
                    lease,
                } => {
                    let prepare = ChainService::prepare(
                        Arc::clone(&self.db),
                        cfg.clone(),
                        self.poi_policy.clone().with_optional_gateway_pool(
                            self.gateway_pool
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .clone(),
                        ),
                        lease,
                        rpc_http_client.clone(),
                        Arc::clone(&self.poi_submission_scheduler),
                    );
                    tokio::pin!(prepare);
                    let prepared = tokio::select! {
                        biased;
                        () = cancel.cancelled() => {
                            return Err(start_cancellation_error(guard.cancellation()));
                        }
                        result = &mut prepare => result?,
                    };
                    return self.publish_prepared_chain(key, prepared, &mut guard);
                }
            }
        }
    }

    pub async fn remove_chain(&self, key: &ChainKey) {
        loop {
            let admission = {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if state.lifecycle != SyncManagerLifecycle::Running {
                    return;
                }
                if let Some(reset) = state.reset.as_ref() {
                    RemoveChainAdmission::WaitForReset(reset.subscribe())
                } else if let Some(removal) = state.removals.get(key) {
                    RemoveChainAdmission::WaitForRemoval(removal.subscribe())
                } else {
                    let (done, done_rx) = watch::channel(false);
                    state.removals.insert(*key, done);
                    if let Some(pending) = state.pending_starts.get_mut(key) {
                        pending.cancellation = Some(PendingStartCancellation::Removed);
                        pending.cancel.cancel();
                    }
                    RemoveChainAdmission::Start {
                        done: done_rx,
                        pending: state
                            .pending_starts
                            .get(key)
                            .map(|pending| pending.done.subscribe()),
                    }
                }
            };
            match admission {
                RemoveChainAdmission::WaitForReset(mut done) => {
                    wait_for_completion(&mut done).await;
                }
                RemoveChainAdmission::WaitForRemoval(mut done) => {
                    wait_for_completion(&mut done).await;
                    return;
                }
                RemoveChainAdmission::Start { mut done, pending } => {
                    tokio::spawn(run_chain_removal(Arc::clone(&self.state), *key, pending));
                    wait_for_completion(&mut done).await;
                    return;
                }
            }
        }
    }

    pub async fn shutdown(&self) {
        let mut done = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match state.lifecycle {
                SyncManagerLifecycle::Stopped => return,
                SyncManagerLifecycle::Stopping => {
                    let Some(shutdown) = state.shutdown.as_ref() else {
                        return;
                    };
                    shutdown.subscribe()
                }
                SyncManagerLifecycle::Running => {
                    state.lifecycle = SyncManagerLifecycle::Stopping;
                    for pending in state.pending_starts.values_mut() {
                        pending.cancellation = Some(PendingStartCancellation::Shutdown);
                        pending.cancel.cancel();
                    }
                    for service in state.chains.values() {
                        service.begin_shutdown();
                    }
                    let reset = state.reset.as_ref().map(watch::Sender::subscribe);
                    let (shutdown, done) = watch::channel(false);
                    state.shutdown = Some(shutdown);
                    tokio::spawn(run_manager_shutdown(Arc::clone(&self.state), reset));
                    done
                }
            }
        };
        wait_for_completion(&mut done).await;
    }

    pub async fn add_wallet(&self, cfg: WalletConfig) -> Result<WalletHandle, SyncManagerError> {
        let chain = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .chains
            .get(&cfg.chain)
            .cloned()
            .ok_or(SyncManagerError::ChainNotFound)?;
        Ok(chain.register_wallet(cfg).await?)
    }

    pub async fn replace_wallet(
        &self,
        cfg: WalletConfig,
    ) -> Result<WalletHandle, SyncManagerError> {
        let chain = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .chains
            .get(&cfg.chain)
            .cloned()
            .ok_or(SyncManagerError::ChainNotFound)?;
        Ok(chain.replace_wallet(cfg).await?)
    }

    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)]
    pub async fn chain_handle(&self, chain: &ChainKey) -> Option<ChainHandle> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .chains
            .get(chain)
            .map(|service| service.handle())
    }

    /// The running chain's amount-statistics status at `now`, or `None` when the chain is not
    /// running. Makes no request.
    #[must_use]
    pub fn amount_statistics_status(
        &self,
        chain: &ChainKey,
        now: SystemTime,
    ) -> Option<AmountStatisticsStatus> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .chains
            .get(chain)
            .map(|service| service.amount_statistics_status(now))
    }

    pub async fn wallet_handle(&self, chain: &ChainKey, cache_key: &str) -> Option<WalletHandle> {
        let chain = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .chains
            .get(chain)
            .cloned()?;
        chain.wallet_handle(cache_key).await
    }

    pub async fn remove_wallet_session(
        &self,
        handle: &WalletHandle,
    ) -> Result<(), SyncManagerError> {
        let chain = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .chains
            .get(handle.chain_key())
            .cloned()
            .ok_or(SyncManagerError::ChainNotFound)?;
        chain.unregister_wallet(handle).await;
        Ok(())
    }

    pub async fn remove_all_wallets(&self) {
        let chains = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .chains
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for chain in chains {
            chain.unregister_all_wallets().await;
        }
    }

    pub async fn reset_public_sync_caches(
        &self,
    ) -> Result<PublicSyncCachesResetReport, SyncManagerError> {
        loop {
            let existing = {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if state.lifecycle != SyncManagerLifecycle::Running {
                    return Err(SyncManagerError::Shutdown);
                }
                if let Some(reset) = state.reset.as_ref() {
                    Some(reset.subscribe())
                } else if let Some(removal) = state.removals.values().next() {
                    Some(removal.subscribe())
                } else {
                    let (done, _) = watch::channel(false);
                    state.reset = Some(done);
                    for pending in state.pending_starts.values_mut() {
                        pending.cancellation = Some(PendingStartCancellation::PublicCacheReset);
                        pending.cancel.cancel();
                    }
                    None
                }
            };
            let Some(mut existing) = existing else {
                break;
            };
            wait_for_completion(&mut existing).await;
        }
        let _reset = ResetGuard {
            state: Arc::clone(&self.state),
        };
        let mut pending = {
            let state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state
                .pending_starts
                .values()
                .map(|pending| pending.done.subscribe())
                .collect::<Vec<_>>()
        };
        wait_for_all(&mut pending).await;
        let mut services = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .chains
            .iter()
            .map(|(chain, service)| (*chain, Arc::clone(service)))
            .collect::<Vec<_>>();
        services.sort_by(|(left, _), (right, _)| {
            left.chain_id
                .cmp(&right.chain_id)
                .then_with(|| left.contract.as_slice().cmp(right.contract.as_slice()))
        });
        let permits = join_all(services.into_iter().map(|(chain, service)| async move {
            (
                chain,
                service
                    .public_data_plane()
                    .acquire_public_cache_reset_permit()
                    .await,
            )
        }))
        .await;
        let persisted = match reset_persisted_public_sync_caches(&self.db).await {
            Ok(reset) => reset,
            Err(error) => {
                let chain_error = PublicDataPlaneError::PublicCacheReset {
                    reason: error.to_string(),
                };
                let total_removed_entries = error.partial_report.total_removed_entries();
                return Ok(PublicSyncCachesResetReport {
                    chains: permits
                        .into_iter()
                        .map(|(chain, _permit)| ChainPublicSyncCacheResetResult {
                            chain,
                            result: Err(chain_error.clone()),
                        })
                        .collect(),
                    persisted: Err(error),
                    total_removed_entries,
                });
            }
        };
        let chains = join_all(permits.into_iter().map(|(chain, permit)| async move {
            ChainPublicSyncCacheResetResult {
                chain,
                result: permit.apply().await,
            }
        }))
        .await;
        let total_removed_entries = chains
            .iter()
            .filter_map(|chain| chain.result.as_ref().ok())
            .fold(persisted.total_removed_entries(), |total, reset| {
                total.saturating_add(reset.total_removed_entries())
            });
        Ok(PublicSyncCachesResetReport {
            chains,
            persisted: Ok(persisted),
            total_removed_entries,
        })
    }

    pub async fn reset_wallet(
        &self,
        cache_key: &str,
        from_block: Option<u64>,
    ) -> Result<(), SyncManagerError> {
        let services = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .chains
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for service in &services {
            match service.reset_wallet(cache_key, from_block).await {
                Ok(()) => return Ok(()),
                Err(ChainError::WalletNotFound) => {}
                Err(err) => return Err(SyncManagerError::Chain(err)),
            }
        }
        Err(SyncManagerError::WalletNotFound)
    }

    fn publish_prepared_chain(
        &self,
        key: ChainKey,
        prepared: PreparedChainService,
        guard: &mut PendingStartGuard,
    ) -> Result<Arc<ChainService>, SyncManagerError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let cancellation = state
            .pending_starts
            .get(&key)
            .filter(|pending| pending.id == guard.id)
            .and_then(|pending| pending.cancellation);
        if let Some(cancellation) = cancellation {
            return Err(start_cancellation_error(cancellation));
        }
        if state.lifecycle != SyncManagerLifecycle::Running {
            return Err(SyncManagerError::Shutdown);
        }
        if state.reset.is_some() {
            return Err(SyncManagerError::ChainStartReset);
        }
        if state.removals.contains_key(&key) {
            return Err(SyncManagerError::ChainStartRemoved);
        }
        let service = prepared.activate();
        state.chains.insert(key, Arc::clone(&service));
        guard.finish_locked(&mut state);
        Ok(service)
    }
}

impl Drop for SyncManager {
    fn drop(&mut self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.lifecycle != SyncManagerLifecycle::Running {
            return;
        }
        state.lifecycle = SyncManagerLifecycle::Stopping;
        for pending in state.pending_starts.values_mut() {
            pending.cancellation = Some(PendingStartCancellation::Shutdown);
            pending.cancel.cancel();
        }
        for service in state.chains.values() {
            service.begin_shutdown();
        }
    }
}

const fn start_cancellation_error(cancellation: PendingStartCancellation) -> SyncManagerError {
    match cancellation {
        PendingStartCancellation::Shutdown => SyncManagerError::Shutdown,
        PendingStartCancellation::Removed => SyncManagerError::ChainStartRemoved,
        PendingStartCancellation::PublicCacheReset => SyncManagerError::ChainStartReset,
    }
}

async fn wait_for_completion(done: &mut watch::Receiver<bool>) {
    if !*done.borrow() {
        let _ = done.changed().await;
    }
}

async fn wait_for_all(waiters: &mut [watch::Receiver<bool>]) {
    for waiter in waiters {
        wait_for_completion(waiter).await;
    }
}

async fn run_chain_removal(
    state: Arc<StdMutex<SyncManagerState>>,
    key: ChainKey,
    mut pending: Option<watch::Receiver<bool>>,
) {
    if let Some(pending) = pending.as_mut() {
        wait_for_completion(pending).await;
    }
    let service = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .chains
        .remove(&key);
    if let Some(service) = service {
        service.shutdown().await;
    }
    let mut state = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(done) = state.removals.remove(&key) {
        let _ = done.send(true);
    }
}

async fn run_manager_shutdown(
    state: Arc<StdMutex<SyncManagerState>>,
    mut reset: Option<watch::Receiver<bool>>,
) {
    if let Some(reset) = reset.as_mut() {
        wait_for_completion(reset).await;
    }
    let (mut pending, mut removals) = {
        let state = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (
            state
                .pending_starts
                .values()
                .map(|pending| pending.done.subscribe())
                .collect::<Vec<_>>(),
            state
                .removals
                .values()
                .map(watch::Sender::subscribe)
                .collect::<Vec<_>>(),
        )
    };
    wait_for_all(&mut pending).await;
    wait_for_all(&mut removals).await;
    let services = {
        let mut state = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state
            .chains
            .drain()
            .map(|(_, service)| service)
            .collect::<Vec<_>>()
    };
    for service in services {
        service.shutdown().await;
    }
    let mut state = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    state.lease.take();
    state.lifecycle = SyncManagerLifecycle::Stopped;
    if let Some(done) = state.shutdown.take() {
        let _ = done.send(true);
    }
}

#[cfg(test)]
impl SyncManager {
    pub(crate) fn insert_chain_for_test(&self, key: ChainKey, service: Arc<ChainService>) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .chains
            .insert(key, service);
    }

    fn chain_count_for_test(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .chains
            .len()
    }
}

#[cfg(test)]
mod tests;
