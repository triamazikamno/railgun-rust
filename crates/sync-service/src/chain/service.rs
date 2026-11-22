use super::poi_submitter::{ChainPoiSubmitterDriver, ChainPoiSubmitterHandle};
use super::workers::read_head_bounded;
use super::{
    Arc, AtomicBool, AtomicU64, BackfillEvent, BackfillRequest, CancellationToken, ChainConfig,
    ChainError, ChainHandle, ChainPublicDataPlane, ChainService, DbStore, GlobalPoiPolicy,
    IndexedWalletArtifactPageOutcome, IndexedWalletArtifactSession,
    IndexedWalletCatchUpSourceOrder, IndexedWalletPage, IndexedWalletPageKind, Instant, JoinHandle,
    MerkleForestDbExt, Mutex, Ordering, Provider, ProviderHandle, PublicDataPlaneDiagnosticKind,
    PublicDataPlaneHandle, PublicScanRange, PublicScanReadScope, PublicScanSource, QueryRpcPool,
    QuickSyncClient, RwLock, SyncProgressSender, WalletBackfillFinishResult,
    WalletBackfillRejectReason, WalletBackfillResetResult, WalletBackfillStartResult, WalletConfig,
    WalletHandle, WalletIndexedCatchUpSource, WalletObservation, WalletReadiness,
    WalletReadinessError, WalletResetReplayPlan, WalletScanApply, WalletStartupSyncError,
    broadcast, debug, info, mpsc, oneshot, send_wallet_startup_events, spawn_backfill_loop,
    spawn_head_poller, spawn_live_log_loop, spawn_pending_tip_loop, spawn_txid_public_cache_loop,
    spawn_wallet_lag_fallback_loop, wait_or_cancel, wallet_backfill_from_block,
    wallet_remote_target_before_cached_suffix, wallet_sync_target, warn, watch,
};
use crate::amount_statistics::{AmountStatisticsStatus, ChainAmountStatistics};
use crate::poi_submission::{PoiSubmissionRouting, PoiSubmissionScheduler};
use crate::runtime_admission::DbRuntimeLease;

mod indexed_sources;
use indexed_sources::SquidIndexedWalletReadSession;

mod rpc_backfill;
use rpc_backfill::RpcTargetPolicy;

mod wallet_registration;

mod startup_sync;
pub(super) use startup_sync::WalletShortStartupPlan;

mod public_scan;
use public_scan::CachedPublicScanApplyOutcome;

mod catch_up_race;
#[cfg(test)]
pub(super) use catch_up_race::SquidWalletCandidateOutcome;

mod indexed_catch_up;
#[cfg(test)]
pub(super) use indexed_catch_up::IndexedWalletCatchUpOutcome;
pub(super) use indexed_catch_up::WalletIndexedTailFallbackResult;

pub(in crate::chain) async fn send_wallet_reset(
    cache_key: &str,
    sender: &mpsc::Sender<BackfillEvent>,
    handle: &WalletHandle,
    intent_id: u64,
    from_block: u64,
    replay_plan: WalletResetReplayPlan,
    committed_to: u64,
) -> WalletBackfillResetResult {
    let (response, result_rx) = oneshot::channel();
    if let Err(err) = sender
        .send(BackfillEvent::Reset {
            token: handle.mint_reset_token(intent_id),
            from_block,
            replay_plan,
            response,
        })
        .await
    {
        warn!(
            ?err,
            cache_key, from_block, "failed to send wallet reset command"
        );
        return WalletBackfillResetResult::Rejected {
            committed_to,
            reason: WalletBackfillRejectReason::Shutdown,
        };
    }
    match result_rx.await {
        Ok(result) => result,
        Err(err) => {
            warn!(?err, cache_key, from_block, "wallet reset response dropped");
            WalletBackfillResetResult::Rejected {
                committed_to,
                reason: WalletBackfillRejectReason::Shutdown,
            }
        }
    }
}

pub(crate) struct PreparedChainService {
    service: Arc<ChainService>,
    rpcs: Arc<QueryRpcPool>,
    archive_provider: Option<alloy_provider::DynProvider>,
    forest_last_rx: watch::Receiver<u64>,
    safe_head_rx: watch::Receiver<u64>,
    snapshot_path: std::path::PathBuf,
    backfill_rx: mpsc::Receiver<BackfillRequest>,
    poi_submitter: ChainPoiSubmitterDriver,
    cancel: CancellationToken,
}

impl PreparedChainService {
    pub(crate) fn activate(self) -> Arc<ChainService> {
        let Self {
            service,
            rpcs,
            archive_provider,
            forest_last_rx,
            safe_head_rx,
            snapshot_path,
            backfill_rx,
            poi_submitter,
            cancel,
        } = self;
        *service
            .poi_submitter_task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(poi_submitter.spawn(cancel.clone()));
        spawn_head_poller(Arc::clone(&service), Arc::clone(&rpcs));
        let live_log_task = spawn_live_log_loop(
            Arc::clone(&service),
            Arc::clone(&rpcs),
            archive_provider.clone(),
            forest_last_rx,
            safe_head_rx.clone(),
            snapshot_path,
            cancel.clone(),
        );
        *service
            .live_log_task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(live_log_task);
        spawn_pending_tip_loop(
            Arc::clone(&service),
            Arc::clone(&rpcs),
            archive_provider.clone(),
            service.head_tx.subscribe(),
            safe_head_rx.clone(),
            cancel.clone(),
        );
        spawn_wallet_lag_fallback_loop(Arc::clone(&service), safe_head_rx.clone(), cancel.clone());
        // Starts with the chain, not with a wallet, and shares no state with wallet sync.
        service.amount_statistics.spawn_refresh(
            Arc::clone(&service.db),
            service.chain.http_client.clone(),
            cancel.clone(),
            service.public_data_plane.runtime_lease(),
        );
        spawn_backfill_loop(
            Arc::clone(&service),
            backfill_rx,
            rpcs,
            archive_provider,
            safe_head_rx,
            cancel,
        );
        service
    }
}

fn wallet_has_persistence_failure(handle: &WalletHandle) -> bool {
    matches!(
        handle.readiness(),
        WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
    )
}

/// The wallet a startup or catch-up step syncs and the channel its sync events go to.
#[derive(Clone, Copy)]
pub(in crate::chain) struct WalletSyncContext<'a> {
    pub(in crate::chain) cfg: &'a WalletConfig,
    pub(in crate::chain) start_block: u64,
    pub(in crate::chain) handle: &'a WalletHandle,
    pub(in crate::chain) backfill_sender: &'a mpsc::Sender<BackfillEvent>,
}

impl ChainService {
    pub(super) const fn chain_id(&self) -> u64 {
        self.chain.deployment.chain_id
    }

    pub(super) fn next_wallet_reset_intent(&self) -> u64 {
        self.wallet_reset_intent_next.fetch_add(1, Ordering::AcqRel)
    }

    fn observe_wallet_reset_intent_floor(&self, highest_accepted_reset_intent: u64) {
        let floor_next = highest_accepted_reset_intent.saturating_add(1);
        let mut current = self.wallet_reset_intent_next.load(Ordering::Acquire);
        while current < floor_next {
            match self.wallet_reset_intent_next.compare_exchange(
                current,
                floor_next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }

    pub(super) fn begin_public_scan_read(&self) -> PublicScanReadScope {
        self.public_data_plane.begin_public_scan_read()
    }

    #[must_use]
    pub fn public_data_plane(self: &Arc<Self>) -> PublicDataPlaneHandle {
        PublicDataPlaneHandle::new(Arc::clone(self))
    }

    pub(super) const fn rpc_scan_source_for_range(&self, from_block: u64) -> PublicScanSource {
        if self.chain.sync.archive_until_block > 0
            && from_block <= self.chain.sync.archive_until_block
        {
            PublicScanSource::ArchiveRpc
        } else {
            PublicScanSource::Rpc
        }
    }

    pub(crate) async fn prepare(
        db: Arc<DbStore>,
        chain: ChainConfig,
        poi_policy: GlobalPoiPolicy,
        runtime_lease: DbRuntimeLease,
        rpc_http_client: Option<reqwest::Client>,
        poi_submission_scheduler: Arc<PoiSubmissionScheduler>,
    ) -> Result<PreparedChainService, ChainError> {
        warn_if_archive_rpc_missing(&chain);
        let archive_provider = chain
            .build_archive_provider(rpc_http_client.as_ref())
            .await?;

        let rpcs = chain.rpcs.clone();
        let (rpc, initial_head, initial_safe_head) =
            fetch_initial_head(&chain, rpcs.as_ref()).await?;

        let (forest, last_processed, snapshot_path, last_anchor) = db
            .load_or_initialize_forest(
                &chain,
                initial_safe_head,
                Some(&rpc),
                archive_provider.as_ref(),
            )
            .await?;

        let (head_tx, _head_rx) = watch::channel(initial_head);
        let (safe_head_tx, safe_head_rx) = watch::channel(initial_safe_head);
        let (forest_last_tx, forest_last_rx) = watch::channel(last_processed);
        let (live_log_tx, _live_log_rx) = broadcast::channel(64);
        let (backfill_tx, backfill_rx) = mpsc::channel(128);
        let cancel = CancellationToken::new();
        let public_data_plane =
            new_chain_public_data_plane(&db, &chain, &poi_policy, runtime_lease)?;
        let (poi_submitter, poi_submitter_driver) = new_chain_poi_submitter(
            &chain,
            &poi_policy,
            &public_data_plane,
            poi_submission_scheduler,
        );
        let amount_statistics = ChainAmountStatistics::for_chain(&chain);
        let service = Arc::new(Self {
            chain,
            poi_policy,
            db,
            forest,
            head_tx,
            safe_head_tx,
            forest_last_tx,
            live_log_tx,
            backfill_tx,
            archive_provider: archive_provider.clone(),
            wallet: RwLock::new(None),
            wallet_registration_gate: Mutex::new(()),
            cancel: cancel.clone(),
            live_log_task: std::sync::Mutex::new(None),
            poi_submitter,
            poi_submitter_task: std::sync::Mutex::new(None),
            anchor_last: AtomicU64::new(last_anchor),
            txid_public_cache_started: AtomicBool::new(false),
            txid_public_cache_task: std::sync::Mutex::new(None),
            amount_statistics,
            wallet_actor_next: AtomicU64::new(1),
            wallet_reset_intent_next: AtomicU64::new(1),
            public_data_plane,
        });

        service.public_data_plane.bind_scan_service(&service);

        Ok(PreparedChainService {
            service,
            rpcs,
            archive_provider,
            forest_last_rx,
            safe_head_rx,
            snapshot_path,
            backfill_rx,
            poi_submitter: poi_submitter_driver,
            cancel,
        })
    }

    #[must_use]
    pub fn handle(&self) -> ChainHandle {
        ChainHandle {
            forest: self.forest.clone(),
            head_rx: self.head_tx.subscribe(),
            safe_head_rx: self.safe_head_tx.subscribe(),
            forest_last_rx: self.forest_last_tx.subscribe(),
            live_log_rx: self.live_log_tx.subscribe(),
        }
    }

    /// Whether this chain's amount statistics can be used at `now`, or why not. Reads the
    /// held snapshot only and never makes a request.
    #[must_use]
    pub fn amount_statistics_status(&self, now: std::time::SystemTime) -> AmountStatisticsStatus {
        self.amount_statistics.status(now)
    }

    pub async fn wallet_handle(&self, cache_key: &str) -> Option<WalletHandle> {
        self.wallet
            .read()
            .await
            .as_ref()
            .filter(|registration| registration.cfg.cache_key.as_str() == cache_key)
            .filter(|registration| !Self::wallet_registration_is_terminal(registration))
            .map(|registration| registration.handle.clone())
    }

    pub(super) fn spawn_txid_public_cache_loop_once(self: &Arc<Self>) {
        if self.txid_public_cache_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let mut task = self
            .txid_public_cache_task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Shutdown cancels before it takes the handle under this lock, so no
        // loop starts after shutdown has awaited it.
        if self.cancel.is_cancelled() {
            return;
        }
        *task = spawn_txid_public_cache_loop(Arc::clone(self), self.cancel.clone());
    }

    fn spawn_txid_public_cache_loop_when_ready(
        self: &Arc<Self>,
        observation_rx: watch::Receiver<WalletObservation>,
        cancel: CancellationToken,
    ) {
        let service = Arc::clone(self);
        tokio::spawn(async move {
            if wait_for_wallet_ready(observation_rx, cancel).await {
                service.spawn_txid_public_cache_loop_once();
            }
        });
    }

    pub async fn reset_wallet(
        &self,
        cache_key: &str,
        from_block: Option<u64>,
    ) -> Result<(), ChainError> {
        let _registration_guard = self.wallet_registration_gate.lock().await;
        let (handle, backfill_sender, start_block, sync_to_block) = {
            let wallet = self.wallet.read().await;
            let registration = wallet
                .as_ref()
                .filter(|registration| registration.cfg.cache_key.as_str() == cache_key)
                .ok_or(ChainError::WalletNotFound)?;
            (
                registration.handle.clone(),
                registration.backfill_sender.clone(),
                registration.start_block,
                registration.sync_to_block,
            )
        };

        let reset_from = from_block.unwrap_or(start_block);
        let safe_head = *self.safe_head_tx.borrow();
        let sync_target = wallet_sync_target(safe_head, sync_to_block);
        let reset_intent_id = self.next_wallet_reset_intent();
        let replay_plan =
            WalletResetReplayPlan::new(start_block, sync_target, sync_to_block.is_none());
        let reset_result = send_wallet_reset(
            cache_key,
            &backfill_sender,
            &handle,
            reset_intent_id,
            reset_from,
            replay_plan,
            handle.last_scanned_raw(),
        )
        .await;
        if reset_result.reset_generation().is_none() {
            warn!(?reset_result, cache_key = %cache_key, from_block = reset_from, "wallet reset rejected");
            return Err(ChainError::WalletResetRejected(reset_result));
        }
        if reset_result.committed() {
            info!(cache_key = %cache_key, from_block = reset_from, "wallet reset rewind committed; actor owns replay admission");
        } else {
            info!(cache_key = %cache_key, from_block = reset_from, "wallet reset accepted and pending actor-owned replay");
        }
        Ok(())
    }

    pub async fn shutdown(&self) {
        self.begin_shutdown();
        let _registration_guard = self.wallet_registration_gate.lock().await;
        let registration = self.wallet.write().await.take();
        if let Some(registration) = registration {
            let cache_key = registration.cfg.cache_key.clone();
            Self::begin_wallet_shutdown(&registration);
            if let Err(err) = self
                .finish_wallet_retirement(cache_key.as_str(), registration)
                .await
            {
                warn!(?err, cache_key = %cache_key, "wallet shutdown cleanup failed");
            }
        }
        // The submitter exits on cancel alone, aborting its sends and corpus
        // refresh, so awaiting it first cannot wait on the data-plane
        // shutdown, and no refresh it started overlaps that shutdown.
        if join_shutdown_task(&self.poi_submitter_task).await.is_some() {
            warn!(
                chain_id = self.chain.deployment.chain_id,
                "chain PPOI submitter failed during shutdown"
            );
        }
        // The loop drops an in-flight sync on cancel, and its service clone
        // keeps the data plane, and with it the runtime lease, alive.
        if join_shutdown_task(&self.txid_public_cache_task)
            .await
            .is_some()
        {
            warn!(
                chain_id = self.chain.deployment.chain_id,
                "TXID public cache loop failed during shutdown"
            );
        }
        // Joined before the data plane releases the runtime lease, since the loop writes to the
        // public cache.
        if join_shutdown_task(self.amount_statistics.task())
            .await
            .is_some()
        {
            warn!(
                chain_id = self.chain.deployment.chain_id,
                "amount statistics refresh failed during shutdown"
            );
        }
        self.public_data_plane.shutdown().await;
        await_live_log_task_shutdown(&self.live_log_task, self.chain.deployment.chain_id).await;
    }

    pub(crate) fn begin_shutdown(&self) {
        self.cancel.cancel();
        self.public_data_plane.begin_shutdown();
    }

    #[cfg(test)]
    pub(crate) fn shutdown_started(&self) -> bool {
        self.cancel.is_cancelled()
    }

    /// Delivers a backfill event to the registered wallet actor.
    #[cfg(test)]
    pub(crate) async fn send_wallet_backfill_event_for_test(&self, event: BackfillEvent) {
        let sender = self
            .wallet
            .read()
            .await
            .as_ref()
            .map(|registration| registration.backfill_sender.clone())
            .expect("registered wallet");
        sender
            .send(event)
            .await
            .expect("deliver wallet backfill test event");
    }
}

pub(super) async fn await_live_log_task_shutdown(
    live_log_task: &std::sync::Mutex<Option<JoinHandle<()>>>,
    chain_id: u64,
) {
    if let Some(err) = join_shutdown_task(live_log_task).await {
        warn!(?err, chain_id, "live log worker failed during shutdown");
    }
}

/// Takes the task out of its slot and awaits it; returns its failure unless it was cancelled.
/// The slot's lock is released before the await.
async fn join_shutdown_task(
    slot: &std::sync::Mutex<Option<JoinHandle<()>>>,
) -> Option<tokio::task::JoinError> {
    let task = slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()?;
    task.await.err().filter(|err| !err.is_cancelled())
}

fn warn_if_archive_rpc_missing(chain: &ChainConfig) {
    if chain.sync.archive_until_block == 0 || chain.archive_rpc_url.is_some() {
        return;
    }
    if chain.deployment.deployment_block <= chain.sync.archive_until_block {
        warn!(
            chain_id = chain.deployment.chain_id,
            archive_until_block = chain.sync.archive_until_block,
            "archive RPC URL not configured; using regular RPC providers for archive-range fallback"
        );
    }
}

/// The chain's public data plane, with a POI cache service when POIs come from indexed
/// artifacts.
fn new_chain_public_data_plane(
    db: &Arc<DbStore>,
    chain: &ChainConfig,
    poi_policy: &GlobalPoiPolicy,
    runtime_lease: DbRuntimeLease,
) -> Result<ChainPublicDataPlane, ChainError> {
    let public_data_plane = ChainPublicDataPlane::new(Arc::clone(db), Arc::new(AtomicU64::new(0)))
        .with_runtime_lease(runtime_lease);
    let GlobalPoiPolicy::IndexedArtifacts {
        artifact_source,
        rpc_url,
        ..
    } = poi_policy
    else {
        return Ok(public_data_plane);
    };
    let poi_artifact_persistence = public_data_plane.poi_artifact_persistence();
    let poi_cache_service = crate::poi_cache::PoiCacheService::new_with_persistence(
        Arc::clone(db),
        chain.deployment.chain_id,
        artifact_source.clone(),
        Some(chain.http_client.clone()),
        poi_artifact_persistence,
    )?
    .with_poi_rpc_url(rpc_url.clone());
    Ok(public_data_plane.with_poi_cache_service(Arc::new(poi_cache_service)))
}

/// The chain's PPOI submitter, routed per transaction when the chain has submission routes.
fn new_chain_poi_submitter(
    chain: &ChainConfig,
    poi_policy: &GlobalPoiPolicy,
    public_data_plane: &ChainPublicDataPlane,
    poi_submission_scheduler: Arc<PoiSubmissionScheduler>,
) -> (ChainPoiSubmitterHandle, ChainPoiSubmitterDriver) {
    let poi_submission_routing = chain.poi_submission_routes.clone().map(|provider| {
        PoiSubmissionRouting::new(
            poi_submission_scheduler,
            provider,
            poi_policy.rpc_url().clone(),
        )
    });
    ChainPoiSubmitterDriver::for_chain(
        chain.deployment.chain_id,
        poi_policy,
        &chain.http_client,
        public_data_plane,
        poi_submission_routing,
    )
}

pub(super) async fn wait_for_wallet_ready(
    mut observation_rx: watch::Receiver<WalletObservation>,
    cancel: CancellationToken,
) -> bool {
    loop {
        match observation_rx.borrow().readiness() {
            WalletReadiness::Ready => return !cancel.is_cancelled(),
            WalletReadiness::Shutdown => return false,
            WalletReadiness::Syncing | WalletReadiness::Failed(_) => {}
        }
        tokio::select! {
            () = cancel.cancelled() => return false,
            changed = observation_rx.changed() => {
                if changed.is_err() {
                    return false;
                }
            },
        }
    }
}

pub(super) async fn wait_for_startup_sync_target(
    mut safe_head_rx: watch::Receiver<u64>,
    sync_to_block: Option<u64>,
    current_target: u64,
    cancel: &CancellationToken,
) -> Option<u64> {
    if current_target > 0 || sync_to_block.is_some() {
        return Some(current_target);
    }
    loop {
        let safe_head = *safe_head_rx.borrow();
        if safe_head > 0 {
            return Some(wallet_sync_target(safe_head, sync_to_block));
        }
        tokio::select! {
            () = cancel.cancelled() => return None,
            changed = safe_head_rx.changed() => {
                if changed.is_err() {
                    return None;
                }
            },
        }
    }
}

/// The provider that answered with the initial head, the head and the safe head. With no
/// answer, a random provider and zero heads, so the chain starts without a safe head.
async fn fetch_initial_head(
    chain: &ChainConfig,
    rpcs: &QueryRpcPool,
) -> Result<(ProviderHandle, u64, u64), ChainError> {
    let fallback_rpc = rpcs
        .random_provider()
        .ok_or_else(|| ChainError::NoHealthyRpc)?;
    let Some((rpc, head)) = read_head_bounded(rpcs).await else {
        warn!(
            chain_id = chain.deployment.chain_id,
            "no rpc provider returned the initial block number; starting without a safe head"
        );
        return Ok((fallback_rpc, 0, 0));
    };
    let safe_head = head
        .saturating_sub(chain.finality_depth)
        .max(chain.deployment.deployment_block);
    Ok((rpc, head, safe_head))
}
