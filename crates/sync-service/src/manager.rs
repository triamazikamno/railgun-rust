use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};

use alloy::primitives::Address;
use futures::future::join_all;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use local_db::DbStore;

use crate::chain::{
    ChainError, ChainHandle, ChainPublicSyncCacheReset, ChainService, PreparedChainService,
    PublicDataPlaneError,
};
use crate::public_cache::{
    PersistedPublicSyncCacheResetError, PersistedPublicSyncCacheResetReport,
    reset_persisted_public_sync_caches,
};
use crate::runtime_admission::{DbRuntimeLease, DbRuntimeOwnerKind};
use crate::types::{ChainConfig, ChainKey, GlobalPoiPolicy, WalletConfig};
use crate::wallet::WalletHandle;

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

    pub async fn add_chain(&self, cfg: ChainConfig) -> Result<Arc<ChainService>, SyncManagerError> {
        let key = ChainKey {
            chain_id: cfg.chain_id,
            contract: cfg.contract,
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
                        self.poi_policy.clone(),
                        lease,
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

    #[allow(clippy::unused_async)]
    pub async fn chain_handle(&self, chain: &ChainKey) -> Option<ChainHandle> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .chains
            .get(chain)
            .map(|service| service.handle())
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
mod tests {
    use std::fs;
    use std::net::TcpListener;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use alloy::primitives::Address;
    use broadcaster_core::query_rpc_pool::QueryRpcPool;
    use local_db::DbConfig;
    use url::Url;

    use super::*;
    use crate::types::{PoiArtifactManifestSource, PoiArtifactSourceConfig, PoiProxyFallback};

    struct StalledRpc {
        url: Url,
        accepted: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<()>>,
        release: Arc<AtomicBool>,
    }

    impl StalledRpc {
        async fn wait_for_request(&self) {
            tokio::time::timeout(Duration::from_secs(2), self.accepted.lock().await.recv())
                .await
                .expect("stalled RPC request timeout")
                .expect("stalled RPC request");
        }
    }

    impl Drop for StalledRpc {
        fn drop(&mut self) {
            self.release.store(true, Ordering::Release);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn manager_ownership_is_exclusive_and_released_by_shutdown() {
        let (db, root) = test_db("manager-ownership");
        let first = Arc::new(
            SyncManager::new(Arc::clone(&db), proxy_policy()).expect("acquire first manager"),
        );

        assert!(matches!(
            SyncManager::new(Arc::clone(&db), proxy_policy()),
            Err(SyncManagerError::DatabaseAlreadyOwned { .. })
        ));

        first.shutdown().await;
        let replacement = SyncManager::new(Arc::clone(&db), proxy_policy())
            .expect("replace manager after orderly shutdown");
        assert!(matches!(
            first.reset_public_sync_caches().await,
            Err(SyncManagerError::Shutdown)
        ));
        replacement.shutdown().await;

        drop(replacement);
        drop(first);
        drop(db);
        fs::remove_dir_all(root).expect("remove manager ownership db");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropped_manager_keeps_runtime_admission_until_chain_runtime_stops() {
        let (db, root) = test_db("dropped-manager-runtime-ownership");
        let manager =
            SyncManager::new(Arc::clone(&db), proxy_policy()).expect("acquire manager ownership");
        let service = manager
            .add_chain(chain_config(1, Address::from([0x21; 20])))
            .await
            .expect("start guarded chain runtime");

        drop(manager);

        assert!(service.shutdown_started());
        assert!(matches!(
            SyncManager::new(Arc::clone(&db), proxy_policy()),
            Err(SyncManagerError::DatabaseAlreadyOwned { .. })
        ));

        service.shutdown().await;
        drop(service);
        let replacement = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match SyncManager::new(Arc::clone(&db), proxy_policy()) {
                    Ok(manager) => break manager,
                    Err(SyncManagerError::DatabaseAlreadyOwned { .. }) => {
                        tokio::task::yield_now().await;
                    }
                    Err(error) => panic!("unexpected replacement-manager error: {error}"),
                }
            }
        })
        .await
        .expect("chain runtime releases admission after cancellation");
        replacement.shutdown().await;

        drop(replacement);
        drop(db);
        fs::remove_dir_all(root).expect("remove dropped manager ownership db");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_manager_acquisition_has_one_winner() {
        let (db, root) = test_db("concurrent-manager-ownership");
        let barrier = Arc::new(Barrier::new(2));
        let acquire = |db: Arc<DbStore>, barrier: Arc<Barrier>| {
            tokio::task::spawn_blocking(move || {
                barrier.wait();
                SyncManager::new(db, proxy_policy())
            })
        };
        let (first, second) = tokio::join!(
            acquire(Arc::clone(&db), Arc::clone(&barrier)),
            acquire(Arc::clone(&db), barrier),
        );
        let first = first.expect("first acquisition task");
        let second = second.expect("second acquisition task");
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        assert!(
            first
                .as_ref()
                .err()
                .or_else(|| second.as_ref().err())
                .is_some_and(|error| matches!(
                    error,
                    SyncManagerError::DatabaseAlreadyOwned { .. }
                ))
        );
        let winner = first
            .ok()
            .or_else(|| second.ok())
            .expect("one manager wins");
        winner.shutdown().await;

        drop(winner);
        drop(db);
        fs::remove_dir_all(root).expect("remove concurrent manager ownership db");
    }

    #[tokio::test]
    async fn concurrent_exact_chain_admission_returns_one_service() {
        let (db, root) = test_db("concurrent-chain-admission");
        let manager =
            SyncManager::new(Arc::clone(&db), proxy_policy()).expect("acquire manager ownership");
        let cfg = chain_config(1, Address::from([0x11; 20]));

        let (first, second) = tokio::join!(
            manager.add_chain(cfg.clone()),
            manager.add_chain(cfg.clone()),
        );
        let first = first.expect("first exact chain admission");
        let second = second.expect("second exact chain admission");
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(manager.chain_count_for_test(), 1);

        manager.shutdown().await;
        drop(first);
        drop(second);
        drop(manager);
        drop(db);
        fs::remove_dir_all(root).expect("remove concurrent chain admission db");
    }

    #[tokio::test]
    async fn existing_chain_admission_does_not_wait_for_public_cache_reset() {
        let (db, root) = test_db("existing-chain-during-reset");
        let manager =
            SyncManager::new(Arc::clone(&db), proxy_policy()).expect("acquire manager ownership");
        let cfg = chain_config(1, Address::from([0x19; 20]));
        let first = manager
            .add_chain(cfg.clone())
            .await
            .expect("start existing chain");
        {
            let mut state = manager
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let (reset, _) = watch::channel(false);
            state.reset = Some(reset);
        }

        let reused = tokio::time::timeout(Duration::from_millis(100), manager.add_chain(cfg))
            .await
            .expect("existing chain admission must not wait for public cache reset")
            .expect("reuse existing chain");

        assert!(Arc::ptr_eq(&first, &reused));
        let reset = manager
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .reset
            .take()
            .expect("held public cache reset admission");
        let _ = reset.send(true);
        manager.shutdown().await;

        drop(first);
        drop(reused);
        drop(manager);
        drop(db);
        fs::remove_dir_all(root).expect("remove existing-chain reset db");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_cancels_stalled_chain_preparation() {
        let (db, root) = test_db("shutdown-stalled-chain");
        let manager = Arc::new(
            SyncManager::new(Arc::clone(&db), proxy_policy()).expect("acquire manager ownership"),
        );
        let stalled = stalled_rpc();
        let cfg = chain_config_with_rpc(1, Address::from([0x12; 20]), stalled.url.clone());
        let start = tokio::spawn({
            let manager = Arc::clone(&manager);
            async move { manager.add_chain(cfg).await }
        });
        stalled.wait_for_request().await;

        tokio::time::timeout(Duration::from_secs(2), manager.shutdown())
            .await
            .expect("shutdown must not wait for stalled RPC");
        assert!(matches!(
            start.await.expect("chain start task"),
            Err(SyncManagerError::Shutdown)
        ));
        assert_eq!(manager.chain_count_for_test(), 0);

        drop(stalled);
        drop(manager);
        drop(db);
        fs::remove_dir_all(root).expect("remove stalled shutdown db");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_removal_keeps_admission_until_owned_cleanup_finishes() {
        let (db, root) = test_db("cancelled-removal-admission");
        let manager = Arc::new(
            SyncManager::new(Arc::clone(&db), proxy_policy()).expect("acquire manager ownership"),
        );
        let contract = Address::from([0x18; 20]);
        let key = ChainKey {
            chain_id: 1,
            contract,
        };
        let pending_done = {
            let mut state = manager
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let (done, done_rx) = watch::channel(false);
            state.pending_starts.insert(
                key,
                PendingChainStart {
                    id: 1,
                    cancel: CancellationToken::new(),
                    cancellation: None,
                    done,
                },
            );
            done_rx
        };
        let removal = tokio::spawn({
            let manager = Arc::clone(&manager);
            async move { manager.remove_chain(&key).await }
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if manager
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .removals
                    .contains_key(&key)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("removal admission installed");
        removal.abort();
        let _ = removal.await;

        let replacement = tokio::spawn({
            let manager = Arc::clone(&manager);
            async move { manager.add_chain(chain_config(1, contract)).await }
        });
        tokio::task::yield_now().await;
        assert!(!replacement.is_finished());
        let pending = manager
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending_starts
            .remove(&key)
            .expect("pending start remains until cleanup");
        let _ = pending.done.send(true);
        drop(pending_done);
        let service = tokio::time::timeout(Duration::from_secs(2), replacement)
            .await
            .expect("replacement admitted after owned cleanup")
            .expect("replacement task")
            .expect("replacement chain");
        manager.shutdown().await;

        drop(service);
        drop(manager);
        drop(db);
        fs::remove_dir_all(root).expect("remove cancelled removal db");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_cleanup_survives_initiating_future_cancellation() {
        let (db, root) = test_db("cancelled-shutdown-cleanup");
        let manager = Arc::new(
            SyncManager::new(Arc::clone(&db), proxy_policy()).expect("acquire manager ownership"),
        );
        {
            let mut state = manager
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let (reset, _) = watch::channel(false);
            state.reset = Some(reset);
        }
        let first = tokio::spawn({
            let manager = Arc::clone(&manager);
            async move { manager.shutdown().await }
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if manager
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .lifecycle
                    == SyncManagerLifecycle::Stopping
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("manager enters stopping state");
        let second = tokio::spawn({
            let manager = Arc::clone(&manager);
            async move { manager.shutdown().await }
        });
        tokio::task::yield_now().await;
        assert!(!second.is_finished());
        first.abort();
        let _ = first.await;

        let reset = manager
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .reset
            .take()
            .expect("active reset admission");
        let _ = reset.send(true);
        tokio::time::timeout(Duration::from_secs(2), second)
            .await
            .expect("owned shutdown cleanup completes")
            .expect("second shutdown waiter");
        let replacement = SyncManager::new(Arc::clone(&db), proxy_policy())
            .expect("shutdown task releases runtime ownership");
        replacement.shutdown().await;

        drop(replacement);
        drop(manager);
        drop(db);
        fs::remove_dir_all(root).expect("remove cancelled shutdown db");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn removal_cancels_stalled_start_and_allows_replacement() {
        let (db, root) = test_db("remove-stalled-chain");
        let manager = Arc::new(
            SyncManager::new(Arc::clone(&db), proxy_policy()).expect("acquire manager ownership"),
        );
        let stalled = stalled_rpc();
        let contract = Address::from([0x13; 20]);
        let cfg = chain_config_with_rpc(1, contract, stalled.url.clone());
        let key = ChainKey {
            chain_id: cfg.chain_id,
            contract,
        };
        let start = tokio::spawn({
            let manager = Arc::clone(&manager);
            async move { manager.add_chain(cfg).await }
        });
        stalled.wait_for_request().await;

        tokio::time::timeout(Duration::from_secs(2), manager.remove_chain(&key))
            .await
            .expect("removal must cancel stalled start");
        assert!(matches!(
            start.await.expect("chain start task"),
            Err(SyncManagerError::ChainStartRemoved)
        ));
        manager
            .add_chain(chain_config(1, contract))
            .await
            .expect("replacement after cancelled removal");
        manager.shutdown().await;

        drop(stalled);
        drop(manager);
        drop(db);
        fs::remove_dir_all(root).expect("remove stalled removal db");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn public_cache_reset_cancels_stalled_start_and_releases_admission() {
        let (db, root) = test_db("reset-stalled-chain");
        let manager = Arc::new(
            SyncManager::new(Arc::clone(&db), proxy_policy()).expect("acquire manager ownership"),
        );
        let stalled = stalled_rpc();
        let contract = Address::from([0x14; 20]);
        let cfg = chain_config_with_rpc(1, contract, stalled.url.clone());
        let start = tokio::spawn({
            let manager = Arc::clone(&manager);
            async move { manager.add_chain(cfg).await }
        });
        stalled.wait_for_request().await;

        tokio::time::timeout(Duration::from_secs(2), manager.reset_public_sync_caches())
            .await
            .expect("reset must cancel stalled start")
            .expect("reset public caches");
        assert!(matches!(
            start.await.expect("chain start task"),
            Err(SyncManagerError::ChainStartReset)
        ));
        manager
            .add_chain(chain_config(1, contract))
            .await
            .expect("replacement after reset admission");
        manager.shutdown().await;

        drop(stalled);
        drop(manager);
        drop(db);
        fs::remove_dir_all(root).expect("remove stalled reset db");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropped_chain_start_future_releases_pending_admission() {
        let (db, root) = test_db("dropped-stalled-chain");
        let manager = Arc::new(
            SyncManager::new(Arc::clone(&db), proxy_policy()).expect("acquire manager ownership"),
        );
        let stalled = stalled_rpc();
        let contract = Address::from([0x15; 20]);
        let start = tokio::spawn({
            let manager = Arc::clone(&manager);
            let cfg = chain_config_with_rpc(1, contract, stalled.url.clone());
            async move { manager.add_chain(cfg).await }
        });
        stalled.wait_for_request().await;
        start.abort();
        let Err(join_error) = start.await else {
            panic!("aborted chain start completed");
        };
        assert!(join_error.is_cancelled());

        manager
            .add_chain(chain_config(1, contract))
            .await
            .expect("replacement after dropped start future");
        manager.shutdown().await;

        drop(stalled);
        drop(manager);
        drop(db);
        fs::remove_dir_all(root).expect("remove dropped start db");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn indexed_conflict_includes_pending_chain_start() {
        let (db, root) = test_db("pending-indexed-conflict");
        let manager = Arc::new(
            SyncManager::new(Arc::clone(&db), indexed_policy()).expect("acquire manager ownership"),
        );
        let stalled = stalled_rpc();
        let first_contract = Address::from([0x16; 20]);
        let first = tokio::spawn({
            let manager = Arc::clone(&manager);
            let cfg = chain_config_with_rpc(1, first_contract, stalled.url.clone());
            async move { manager.add_chain(cfg).await }
        });
        stalled.wait_for_request().await;
        let second_contract = Address::from([0x17; 20]);

        assert!(matches!(
            manager.add_chain(chain_config(1, second_contract)).await,
            Err(SyncManagerError::PoiCoordinatorConflict {
                chain_id: 1,
                existing_contract,
                requested_contract,
            }) if existing_contract == first_contract && requested_contract == second_contract
        ));
        manager.shutdown().await;
        assert!(matches!(
            first.await.expect("pending indexed start"),
            Err(SyncManagerError::Shutdown)
        ));

        drop(stalled);
        drop(manager);
        drop(db);
        fs::remove_dir_all(root).expect("remove pending indexed conflict db");
    }

    #[tokio::test]
    async fn indexed_policy_owns_chain_id_while_proxy_preserves_contract_scoping() {
        let (indexed_db, indexed_root) = test_db("indexed-chain-ownership");
        let indexed = SyncManager::new(Arc::clone(&indexed_db), indexed_policy())
            .expect("acquire indexed manager");
        indexed
            .add_chain(chain_config(1, Address::from([0x21; 20])))
            .await
            .expect("add indexed chain");
        assert!(matches!(
            indexed
                .add_chain(chain_config(1, Address::from([0x22; 20])))
                .await,
            Err(SyncManagerError::PoiCoordinatorConflict {
                chain_id: 1,
                existing_contract,
                requested_contract,
            }) if existing_contract == Address::from([0x21; 20])
                && requested_contract == Address::from([0x22; 20])
        ));
        indexed
            .add_chain(chain_config(2, Address::from([0x23; 20])))
            .await
            .expect("add distinct indexed chain");
        indexed.shutdown().await;

        let (proxy_db, proxy_root) = test_db("proxy-contract-scoping");
        let proxy =
            SyncManager::new(Arc::clone(&proxy_db), proxy_policy()).expect("acquire proxy manager");
        proxy
            .add_chain(chain_config(1, Address::from([0x31; 20])))
            .await
            .expect("add first proxy contract");
        proxy
            .add_chain(chain_config(1, Address::from([0x32; 20])))
            .await
            .expect("add second proxy contract");
        assert_eq!(proxy.chain_count_for_test(), 2);
        proxy.shutdown().await;

        drop(indexed);
        drop(indexed_db);
        fs::remove_dir_all(indexed_root).expect("remove indexed ownership db");
        drop(proxy);
        drop(proxy_db);
        fs::remove_dir_all(proxy_root).expect("remove proxy contract db");
    }

    #[tokio::test]
    async fn shutdown_is_terminal_idempotent_and_allows_chain_replacement_before_it() {
        let (db, root) = test_db("manager-shutdown");
        let manager =
            SyncManager::new(Arc::clone(&db), proxy_policy()).expect("acquire manager ownership");
        let contract = Address::from([0x41; 20]);
        let cfg = chain_config(1, contract);
        let first = manager
            .add_chain(cfg.clone())
            .await
            .expect("add initial chain");
        manager
            .remove_chain(&ChainKey {
                chain_id: cfg.chain_id,
                contract: cfg.contract,
            })
            .await;
        let replacement = manager
            .add_chain(chain_config(1, contract))
            .await
            .expect("re-add chain after complete removal");
        assert!(!Arc::ptr_eq(&first, &replacement));

        manager.shutdown().await;
        manager.shutdown().await;
        assert!(matches!(
            manager.add_chain(chain_config(1, contract)).await,
            Err(SyncManagerError::Shutdown)
        ));

        drop(first);
        drop(replacement);
        drop(manager);
        drop(db);
        fs::remove_dir_all(root).expect("remove manager shutdown db");
    }

    fn proxy_policy() -> GlobalPoiPolicy {
        GlobalPoiPolicy::PoiProxy {
            rpc_url: Url::parse("http://127.0.0.1:1").expect("proxy URL").into(),
        }
    }

    fn indexed_policy() -> GlobalPoiPolicy {
        GlobalPoiPolicy::IndexedArtifacts {
            artifact_source: PoiArtifactSourceConfig {
                trusted_publisher_pubkey: [0x42; 32].into(),
                manifest_source: PoiArtifactManifestSource::Url(
                    Url::parse("http://127.0.0.1:1/manifest.json")
                        .expect("manifest URL")
                        .into(),
                ),
                gateway_urls: Vec::new(),
                max_manifest_age: None,
            },
            rpc_url: Url::parse("http://127.0.0.1:1")
                .expect("POI RPC URL")
                .into(),
            wallet_read_fallback: PoiProxyFallback::Disabled,
        }
    }

    fn chain_config(chain_id: u64, contract: Address) -> ChainConfig {
        ChainConfig {
            chain_id,
            contract,
            rpcs: Arc::new(QueryRpcPool::new(
                vec![Url::parse("http://127.0.0.1:1").expect("RPC URL")],
                Duration::from_millis(1),
            )),
            archive_rpc_url: None,
            archive_until_block: 0,
            deployment_block: 0,
            v2_start_block: 0,
            legacy_shield_block: 0,
            block_range: 100,
            indexed_wallet_block_range: 100,
            block_time: Duration::from_secs(12),
            poll_interval: Duration::from_mins(1),
            finality_depth: 0,
            quick_sync_endpoint: None,
            indexed_artifact_source: None,
            anchor_interval: 1000,
            anchor_retention: 5,
            http_client: None,
            progress_tx: None,
        }
    }

    fn chain_config_with_rpc(chain_id: u64, contract: Address, rpc_url: Url) -> ChainConfig {
        let mut cfg = chain_config(chain_id, contract);
        cfg.rpcs = Arc::new(QueryRpcPool::new(vec![rpc_url], Duration::from_millis(1)));
        cfg
    }

    fn stalled_rpc() -> StalledRpc {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stalled RPC server");
        listener
            .set_nonblocking(true)
            .expect("set stalled RPC listener nonblocking");
        let url = Url::parse(&format!(
            "http://{}",
            listener.local_addr().expect("stalled RPC local addr")
        ))
        .expect("stalled RPC URL");
        let (accepted_tx, accepted) = tokio::sync::mpsc::unbounded_channel();
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
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        StalledRpc {
            url,
            accepted: tokio::sync::Mutex::new(accepted),
            release,
        }
    }

    fn test_db(name: &str) -> (Arc<DbStore>, PathBuf) {
        let root = temp_db_root(name);
        fs::create_dir_all(&root).expect("create test db root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root.clone(),
            })
            .expect("open test db"),
        );
        (db, root)
    }

    fn temp_db_root(name: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("sync-manager-{name}-{unique}-{counter}"))
    }
}
