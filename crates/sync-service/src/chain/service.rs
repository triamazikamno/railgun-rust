use super::logs::INDEXED_SQUID_STEP_DEADLINE;
use super::poi_submitter::ChainPoiSubmitterDriver;
use super::workers::{read_head_bounded, untried_provider};
use super::{
    Arc, AtomicBool, AtomicU64, BackfillEvent, BackfillRequest, CancellationToken, ChainConfig,
    ChainError, ChainHandle, ChainPublicDataPlane, ChainService, DbStore, GlobalPoiPolicy,
    IndexedWalletArtifactPageOutcome, IndexedWalletArtifactSession,
    IndexedWalletCatchUpSourceOrder, IndexedWalletPage, IndexedWalletPageKind, Instant, JoinHandle,
    LogBatch, MerkleForestDbExt, Mutex, Ordering, Provider, ProviderHandle,
    PublicDataPlaneDiagnosticKind, PublicDataPlaneHandle, PublicScanRange, PublicScanReadScope,
    PublicScanSource, QueryRpcPool, QuickSyncClient, RwLock, SyncProgressSender,
    WalletBackfillFinishResult, WalletBackfillRejectReason, WalletBackfillResetResult,
    WalletBackfillStartResult, WalletConfig, WalletHandle, WalletIndexedCatchUpSource,
    WalletObservation, WalletPoiRuntime, WalletReadiness, WalletReadinessError, WalletRegistration,
    WalletResetReplayPlan, WalletScanApply, WalletStartupSyncError, WalletWorkerServices,
    broadcast, debug, info, mpsc, oneshot, send_wallet_startup_events, sort_logs,
    spawn_backfill_loop, spawn_head_poller, spawn_live_log_loop, spawn_pending_tip_loop,
    spawn_txid_public_cache_loop, spawn_wallet_lag_fallback_loop, squid_tail_target_after_artifact,
    wait_or_cancel, wallet_backfill_from_block, wallet_cache_store,
    wallet_finish_result_removes_cursor, wallet_finish_retry_request,
    wallet_remote_target_before_cached_suffix, wallet_sync_target, warn, watch,
};
use crate::poi_submission::{PoiSubmissionRouting, PoiSubmissionScheduler};
use crate::runtime_admission::DbRuntimeLease;
use std::collections::BTreeSet;

mod startup_sync;
pub(super) use startup_sync::WalletShortStartupPlan;

mod public_scan;
use public_scan::CachedPublicScanApplyOutcome;

mod indexed_catch_up;
pub(super) use indexed_catch_up::WalletIndexedTailFallbackResult;
#[cfg(test)]
pub(super) use indexed_catch_up::{IndexedWalletCatchUpOutcome, SquidWalletCandidateOutcome};

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

struct WalletRpcBackfillEvents {
    acquisition_applies: Vec<WalletScanApply>,
    delivery_applies: Vec<WalletScanApply>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RpcTargetPolicy {
    RequireRequestedTarget,
    AllowFinalizedPrefix,
}

fn wallet_has_persistence_failure(handle: &WalletHandle) -> bool {
    matches!(
        handle.readiness(),
        WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
    )
}

struct SquidIndexedWalletReadSession {
    client: QuickSyncClient,
    indexed_height: u64,
    read_scope: PublicScanReadScope,
}

impl SquidIndexedWalletReadSession {
    const fn client(&self) -> &QuickSyncClient {
        &self.client
    }

    const fn indexed_height(&self) -> u64 {
        self.indexed_height
    }

    const fn read_scope(&self) -> PublicScanReadScope {
        self.read_scope
    }
}

/// Distinct providers one wallet RPC backfill read tries above the archive
/// boundary before it reports failure.
const WALLET_RPC_READ_MAX_PROVIDERS: usize = 3;

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
        if chain.sync.archive_until_block > 0
            && chain.archive_rpc_url.is_none()
            && chain.deployment.deployment_block <= chain.sync.archive_until_block
        {
            warn!(
                chain_id = chain.deployment.chain_id,
                archive_until_block = chain.sync.archive_until_block,
                "archive RPC URL not configured; using regular RPC providers for archive-range fallback"
            );
        }
        let archive_provider = chain
            .build_archive_provider(rpc_http_client.as_ref())
            .await?;

        let rpcs = chain.rpcs.clone();
        let fallback_rpc = rpcs
            .random_provider()
            .ok_or_else(|| ChainError::NoHealthyRpc)?;
        let (rpc, initial_head, initial_safe_head) = fetch_initial_head(&chain, rpcs.as_ref())
            .await
            .unwrap_or((fallback_rpc, 0, 0));

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
        let mut public_data_plane =
            ChainPublicDataPlane::new(Arc::clone(&db), Arc::new(AtomicU64::new(0)))
                .with_runtime_lease(runtime_lease);
        if let GlobalPoiPolicy::IndexedArtifacts {
            artifact_source,
            rpc_url,
            ..
        } = &poi_policy
        {
            let poi_artifact_persistence = public_data_plane.poi_artifact_persistence();
            let poi_cache_service = crate::poi_cache::PoiCacheService::new_with_persistence(
                Arc::clone(&db),
                chain.deployment.chain_id,
                artifact_source.clone(),
                Some(chain.http_client.clone()),
                poi_artifact_persistence,
            )?
            .with_poi_rpc_url(rpc_url.clone());
            public_data_plane =
                public_data_plane.with_poi_cache_service(Arc::new(poi_cache_service));
        }
        let poi_submission_routing = chain.poi_submission_routes.clone().map(|provider| {
            PoiSubmissionRouting::new(
                poi_submission_scheduler,
                provider,
                poi_policy.rpc_url().clone(),
            )
        });
        let (poi_submitter, poi_submitter_driver) = ChainPoiSubmitterDriver::for_chain(
            chain.deployment.chain_id,
            &poi_policy,
            &chain.http_client,
            &public_data_plane,
            poi_submission_routing,
        );
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

    pub async fn wallet_handle(&self, cache_key: &str) -> Option<WalletHandle> {
        self.wallet
            .read()
            .await
            .as_ref()
            .filter(|registration| registration.cfg.cache_key.as_str() == cache_key)
            .filter(|registration| !Self::wallet_registration_is_terminal(registration))
            .map(|registration| registration.handle.clone())
    }

    fn wallet_registration_is_terminal(registration: &WalletRegistration) -> bool {
        !registration.handle.is_current_actor()
            || !registration.handle.lifecycle().allows_durable_commits()
            || matches!(registration.handle.readiness(), WalletReadiness::Shutdown)
            || registration.worker.is_finished()
    }

    fn spawn_wallet_terminal_reaper(self: &Arc<Self>, handle: WalletHandle) {
        let service = Arc::downgrade(self);
        let public_data_plane = self.public_data_plane.clone();
        let actor_id = handle.actor_id();
        let mut observation_rx = handle.subscribe_observation();
        tokio::spawn(async move {
            loop {
                let observation = observation_rx.borrow_and_update().clone();
                public_data_plane
                    .update_poi_cache_demand(actor_id, &observation)
                    .await;
                if observation.readiness() == &WalletReadiness::Shutdown {
                    break;
                }
                if observation_rx.changed().await.is_err() {
                    break;
                }
            }
            public_data_plane.clear_poi_cache_demand(actor_id).await;
            if let Some(service) = service.upgrade() {
                service.reap_terminal_wallet_registration(&handle).await;
            }
        });
    }

    async fn reap_terminal_wallet_registration(&self, handle: &WalletHandle) {
        let cache_key = handle.cache_key.as_str();
        let _registration_guard = self.wallet_registration_gate.lock().await;
        let registration = {
            let mut wallet = self.wallet.write().await;
            let is_exact_terminal = wallet.as_ref().is_some_and(|registration| {
                registration.handle.same_actor_as(handle)
                    && Self::wallet_registration_is_terminal(registration)
            });
            is_exact_terminal.then(|| wallet.take()).flatten()
        };
        let Some(registration) = registration else {
            return;
        };
        Self::begin_wallet_shutdown(&registration);
        if let Err(err) = self.finish_wallet_retirement(cache_key, registration).await {
            warn!(?err, cache_key = %cache_key, "terminal wallet cleanup failed");
            self.begin_shutdown();
        }
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

    /// Registers or returns the active wallet actor for the configured cache key.
    ///
    /// # Panics
    ///
    /// Panics if the internal prepared-worker activation invariant is violated.
    pub async fn register_wallet(
        self: &Arc<Self>,
        cfg: WalletConfig,
    ) -> Result<WalletHandle, ChainError> {
        let _registration_guard = self.wallet_registration_gate.lock().await;
        self.register_wallet_locked(cfg).await
    }

    /// Retires the current wallet, if any, before installing the successor.
    pub async fn replace_wallet(
        self: &Arc<Self>,
        cfg: WalletConfig,
    ) -> Result<WalletHandle, ChainError> {
        let service = Arc::clone(self);
        tokio::spawn(async move { service.replace_wallet_owned(cfg).await })
            .await
            .map_err(|_| ChainError::WalletReplacementTaskFailed)?
    }

    async fn replace_wallet_owned(
        self: &Arc<Self>,
        cfg: WalletConfig,
    ) -> Result<WalletHandle, ChainError> {
        let _registration_guard = self.wallet_registration_gate.lock().await;
        if self.cancel.is_cancelled() {
            return Err(ChainError::Shutdown);
        }
        let registration = self.wallet.write().await.take();
        if let Some(registration) = registration {
            let cache_key = registration.cfg.cache_key.clone();
            Self::begin_wallet_retirement(&registration);
            self.finish_wallet_retirement(cache_key.as_str(), registration)
                .await?;
        }
        self.register_wallet_locked(cfg).await
    }

    async fn register_wallet_locked(
        self: &Arc<Self>,
        cfg: WalletConfig,
    ) -> Result<WalletHandle, ChainError> {
        let cache_key = cfg.cache_key.clone();
        if self.cancel.is_cancelled() {
            return Err(ChainError::Shutdown);
        }
        let terminal_registration = {
            let mut wallet = self.wallet.write().await;
            if let Some(existing) = wallet
                .as_ref()
                .filter(|existing| !Self::wallet_registration_is_terminal(existing))
            {
                if existing.cfg.cache_key != cache_key {
                    return Err(ChainError::WalletAlreadyRegistered);
                }
                if existing.handle.readiness().is_ready() {
                    self.spawn_txid_public_cache_loop_once();
                }
                return Ok(existing.handle.clone());
            }
            wallet.take()
        };
        if let Some(registration) = terminal_registration {
            let retired_cache_key = registration.cfg.cache_key.clone();
            Self::begin_wallet_shutdown(&registration);
            self.finish_wallet_retirement(retired_cache_key.as_str(), registration)
                .await?;
        }

        let mut cfg = cfg;
        let start_block = cfg
            .start_block
            .unwrap_or(self.chain.deployment.deployment_block);
        cfg.start_block = Some(start_block);

        let mut last_scanned = start_block.saturating_sub(1);
        let cache_store = wallet_cache_store(&self.db, &cfg);
        if let Ok(Some(meta)) = cache_store.get_wallet_meta(&cfg.cache_key) {
            last_scanned = meta.last_scanned_block;
        }
        match cache_store.get_wallet_sync_actor_state(cfg.chain.chain_id, &cfg.cache_key) {
            Ok(Some(state)) => {
                self.observe_wallet_reset_intent_floor(state.highest_accepted_reset_intent);
            }
            Ok(None) => {}
            Err(err) => {
                warn!(?err, cache_key = %cfg.cache_key, "failed to restore wallet reset intent floor");
                return Err(err.into());
            }
        }

        let safe_head = *self.safe_head_tx.borrow();
        let sync_target = wallet_sync_target(safe_head, cfg.sync_to_block);
        info!(
            cache_key = %cfg.cache_key,
            chain_id = cfg.chain.chain_id,
            start_block,
            last_scanned,
            safe_head,
            sync_to_block = ?cfg.sync_to_block,
            sync_target,
            indexed_wallet_catch_up = cfg.use_indexed_wallet_catch_up,
            indexed_artifact_source = self.chain.sync.indexed_artifact_source.is_some(),
            "registering wallet sync"
        );

        let initial_utxos = match cache_store.load_wallet_utxos(&cfg.cache_key) {
            Ok(cached) => cached,
            Err(err) => {
                warn!(?err, cache_key = %cfg.cache_key, "failed to load wallet cache");
                Vec::new()
            }
        };
        if last_scanned < start_block {
            last_scanned = start_block.saturating_sub(1);
        }

        let actor_id = self.wallet_actor_next.fetch_add(1, Ordering::AcqRel);
        let cancel = self.cancel.child_token();
        let live_rx = self.live_log_tx.subscribe();
        let (backfill_sender, backfill_rx) = mpsc::channel(128);
        let mut prepared: crate::wallet::PreparedWalletWorker =
            crate::wallet::prepare_wallet_worker(
                WalletWorkerServices {
                    db: self.db.clone(),
                    http_client: Some(self.chain.http_client.clone()),
                    indexed_artifact_source: self.chain.sync.indexed_artifact_source.clone(),
                    poi_runtime: WalletPoiRuntime::from_policy(
                        &self.poi_policy,
                        Some(&self.chain.http_client),
                    ),
                    forest: self.forest.clone(),
                    backfill_tx: self.backfill_tx.clone(),
                    backfill_sender: backfill_sender.clone(),
                    public_data_plane: self.public_data_plane.clone(),
                    poi_submitter: self.poi_submitter.clone(),
                },
                cfg.clone(),
                actor_id,
                live_rx,
                backfill_rx,
                cancel.clone(),
                initial_utxos,
                last_scanned,
            )
            .await?;

        let worker = prepared.take_worker();
        if self.cancel.is_cancelled() {
            cancel.cancel();
            drop(prepared);
            let _ = worker.await;
            return Err(ChainError::Shutdown);
        }
        let handle = prepared.handle().clone();
        let restored_pending_reset = prepared.has_restored_pending_reset();
        let registration = WalletRegistration {
            handle: handle.clone(),
            cfg: cfg.clone(),
            cancel: cancel.clone(),
            worker,
            observation: prepared.observation_publisher(),
            backfill_sender: backfill_sender.clone(),
            start_block,
            sync_to_block: cfg.sync_to_block,
        };
        {
            let mut wallet = self.wallet.write().await;
            if self.cancel.is_cancelled() {
                drop(wallet);
                cancel.cancel();
                drop(prepared);
                let registration = registration;
                if let Err(err) = self
                    .finish_wallet_retirement(cache_key.as_str(), registration)
                    .await
                {
                    warn!(?err, cache_key = %cache_key, "wallet shutdown cleanup failed");
                }
                return Err(ChainError::Shutdown);
            }
            *wallet = Some(registration);
        }
        let activation_result = prepared.activate();
        if let Err(err) = activation_result {
            let registration = {
                let mut wallet = self.wallet.write().await;
                wallet.take()
            };
            if let Some(registration) = registration {
                let cache_key = registration.cfg.cache_key.clone();
                Self::begin_wallet_retirement(&registration);
                if let Err(cleanup_err) = self
                    .finish_wallet_retirement(cache_key.as_str(), registration)
                    .await
                {
                    warn!(
                        ?cleanup_err,
                        cache_key = %cache_key,
                        "wallet activation cleanup failed"
                    );
                }
            }
            return Err(err);
        }

        self.spawn_wallet_terminal_reaper(handle.clone());
        self.spawn_txid_public_cache_loop_when_ready(
            handle.subscribe_observation(),
            cancel.clone(),
        );

        let service = Arc::clone(self);
        let catch_up_cfg = cfg.clone();
        let catch_up_handle = handle.clone();
        let catch_up_cancel = cancel;
        let catch_up_restored_pending_reset = restored_pending_reset;
        tokio::spawn(async move {
            if catch_up_restored_pending_reset
                && !wait_for_wallet_ready(
                    catch_up_handle.subscribe_observation(),
                    catch_up_cancel.clone(),
                )
                .await
            {
                return;
            }
            let startup_target = if catch_up_restored_pending_reset {
                wallet_sync_target(*service.safe_head_tx.borrow(), catch_up_cfg.sync_to_block)
            } else {
                sync_target
            };
            let Some(sync_target) = wait_for_startup_sync_target(
                service.safe_head_tx.subscribe(),
                catch_up_cfg.sync_to_block,
                startup_target,
                &catch_up_cancel,
            )
            .await
            else {
                return;
            };

            // Only schedule from one public view snapshot (cursor + generation).
            let Some(startup) = catch_up_handle
                .wait_schedulable_progress(&catch_up_cancel)
                .await
            else {
                return;
            };
            let startup_target_lease = if sync_target > startup.last_scanned {
                match catch_up_handle
                    .reserve_sync_target(
                        &catch_up_cfg.cache_key,
                        &backfill_sender,
                        startup,
                        sync_target,
                    )
                    .await
                {
                    Ok(lease) => Some(lease),
                    Err(reason) => {
                        debug!(
                            ?reason,
                            cache_key = %catch_up_cfg.cache_key,
                            sync_target,
                            "wallet startup target reservation rejected"
                        );
                        return;
                    }
                }
            } else {
                None
            };
            let short_startup_plan = WalletShortStartupPlan::new(
                start_block,
                startup.last_scanned,
                sync_target,
                service.chain.sync.block_range,
            );
            let short_window_is_cached = if let Some(plan) = short_startup_plan {
                service
                    .public_data_plane
                    .cached_wallet_scan_suffix(
                        plan.acquisition.from_block,
                        plan.acquisition.to_block,
                    )
                    .await
                    .is_some()
            } else {
                true
            };
            let cached_outcome = if short_window_is_cached {
                service
                    .apply_cached_public_scan_coverage(
                        &catch_up_cfg,
                        start_block,
                        startup.last_scanned,
                        sync_target,
                        &catch_up_handle,
                        &backfill_sender,
                        startup,
                    )
                    .await
            } else {
                CachedPublicScanApplyOutcome {
                    checkpoint: startup.last_scanned,
                    finished: false,
                }
            };
            if cached_outcome.finished {
                return;
            }
            if wallet_has_persistence_failure(&catch_up_handle) {
                let Some(progress) = catch_up_handle.revalidate_schedulable_progress(startup)
                else {
                    return;
                };
                service
                    .enqueue_wallet_backfill(
                        &catch_up_cfg,
                        start_block,
                        cached_outcome.checkpoint,
                        sync_target,
                        catch_up_cfg.sync_to_block.is_none(),
                        &catch_up_handle,
                        progress,
                        backfill_sender,
                        false,
                        short_startup_plan,
                    )
                    .await;
                return;
            }
            let Some(startup) = catch_up_handle.revalidate_schedulable_progress(startup) else {
                return;
            };
            if service
                .short_wallet_startup_sync(
                    &catch_up_cfg,
                    start_block,
                    startup,
                    sync_target,
                    short_startup_plan,
                    backfill_sender.clone(),
                    &catch_up_handle,
                    &catch_up_cancel,
                )
                .await
            {
                return;
            }
            if wallet_has_persistence_failure(&catch_up_handle) {
                let Some(progress) = catch_up_handle.revalidate_schedulable_progress(startup)
                else {
                    return;
                };
                service
                    .enqueue_wallet_backfill(
                        &catch_up_cfg,
                        start_block,
                        progress.last_scanned,
                        sync_target,
                        catch_up_cfg.sync_to_block.is_none(),
                        &catch_up_handle,
                        progress,
                        backfill_sender,
                        false,
                        short_startup_plan,
                    )
                    .await;
                return;
            }

            let Some(checkpoint_progress) = catch_up_handle
                .wait_schedulable_progress(&catch_up_cancel)
                .await
            else {
                return;
            };
            let Some(progress) = startup.revalidate(Some(checkpoint_progress)) else {
                debug!(
                    cache_key = %catch_up_cfg.cache_key,
                    startup_reset_generation = startup.reset_generation,
                    current_reset_generation = checkpoint_progress.reset_generation,
                    "wallet startup sync superseded by reset"
                );
                return;
            };
            let mut checkpoint = progress.last_scanned;
            let mut cached_suffix = service
                .public_data_plane
                .cached_wallet_scan_suffix(
                    wallet_backfill_from_block(checkpoint, start_block),
                    sync_target,
                )
                .await;
            let cached_suffix_from = cached_suffix
                .as_ref()
                .and_then(|applies| applies.first())
                .map(|apply| apply.from_block);
            let historical_target =
                wallet_remote_target_before_cached_suffix(sync_target, cached_suffix_from);
            if let Some(cached_suffix_from) = cached_suffix_from {
                debug!(
                    cache_key = %catch_up_cfg.cache_key,
                    checkpoint,
                    historical_target,
                    cached_suffix_from,
                    sync_target,
                    "historical wallet catch-up capped before cached public suffix"
                );
            }
            if let Some(plan) = short_startup_plan
                && catch_up_cfg.use_indexed_wallet_catch_up
            {
                match service
                    .wallet_startup_artifact_candidate(&catch_up_cfg, plan, &catch_up_cancel)
                    .await
                {
                    Ok(Some(candidate)) => {
                        let acquisition_apply_count = candidate.acquisition_applies.len();
                        if let Some(progress) = service
                            .commit_and_deliver_short_startup_candidate(
                                &catch_up_cfg,
                                startup,
                                sync_target,
                                plan,
                                candidate,
                                &backfill_sender,
                                &catch_up_handle,
                                &catch_up_cancel,
                            )
                            .await
                        {
                            debug!(
                                cache_key = %catch_up_cfg.cache_key,
                                acquisition_apply_count,
                                "wallet startup artifact acquisition delivered"
                            );
                            if catch_up_cfg.sync_to_block.is_none() {
                                service
                                    .enqueue_wallet_backfill(
                                        &catch_up_cfg,
                                        start_block,
                                        sync_target,
                                        sync_target,
                                        true,
                                        &catch_up_handle,
                                        progress,
                                        backfill_sender,
                                        true,
                                        None,
                                    )
                                    .await;
                            }
                            return;
                        }
                    }
                    Ok(None) => {}
                    Err(err) => {
                        debug!(err = %err.without_url(), cache_key = %catch_up_cfg.cache_key, "wallet startup artifact fallback failed");
                    }
                }
            }
            if short_startup_plan.is_none() && catch_up_cfg.use_indexed_wallet_catch_up {
                checkpoint = service
                    .indexed_wallet_catch_up(
                        &catch_up_cfg,
                        start_block,
                        checkpoint,
                        historical_target,
                        &catch_up_handle,
                        &catch_up_cancel,
                        IndexedWalletCatchUpSourceOrder::ArtifactsFirst,
                        false,
                        (&backfill_sender, progress),
                    )
                    .await;
            } else if short_startup_plan.is_none() {
                debug!(cache_key = %catch_up_cfg.cache_key, "indexed wallet catch-up disabled");
            }
            if catch_up_cancel.is_cancelled() {
                return;
            }
            // Superseded if view generation advanced or reset-pending (no public progress).
            let Some(mut progress) = catch_up_handle.revalidate_schedulable_progress(startup)
            else {
                debug!(
                    cache_key = %catch_up_cfg.cache_key,
                    startup_reset_generation = startup.reset_generation,
                    current_reset_generation = ?catch_up_handle
                        .view_state()
                        .reset_generation(),
                    "wallet startup sync superseded by reset"
                );
                return;
            };
            if short_startup_plan.is_none()
                && checkpoint < sync_target
                && let Some(suffix) = cached_suffix.take()
                && suffix.first().is_some_and(|apply| {
                    apply.from_block == wallet_backfill_from_block(checkpoint, start_block)
                })
            {
                let suffix_applies = suffix.len();
                let suffix_restaged = service.restage_captured_public_scan_applies(&suffix).await;
                if suffix_restaged
                    && send_wallet_startup_events(
                        &catch_up_cfg.cache_key,
                        suffix,
                        Some(sync_target),
                        progress,
                        &backfill_sender,
                        &catch_up_handle,
                    )
                    .await
                {
                    debug!(
                        cache_key = %catch_up_cfg.cache_key,
                        checkpoint,
                        sync_target,
                        suffix_applies,
                        "captured public scan suffix delivered after historical catch-up"
                    );
                    if catch_up_cfg.sync_to_block.is_none()
                        && let Some(progress) =
                            catch_up_handle.revalidate_schedulable_progress(startup)
                    {
                        service
                            .enqueue_wallet_backfill(
                                &catch_up_cfg,
                                start_block,
                                sync_target,
                                sync_target,
                                true,
                                &catch_up_handle,
                                progress,
                                backfill_sender,
                                true,
                                None,
                            )
                            .await;
                    }
                    return;
                }
                let Some(refreshed_progress) =
                    catch_up_handle.revalidate_schedulable_progress(startup)
                else {
                    return;
                };
                checkpoint = refreshed_progress.last_scanned;
                progress = refreshed_progress;
                debug!(
                    cache_key = %catch_up_cfg.cache_key,
                    checkpoint,
                    sync_target,
                    "captured public scan suffix was rejected; continuing with normal backfill"
                );
            }
            service
                .enqueue_wallet_backfill(
                    &catch_up_cfg,
                    start_block,
                    checkpoint,
                    sync_target,
                    catch_up_cfg.sync_to_block.is_none(),
                    &catch_up_handle,
                    progress,
                    backfill_sender,
                    !wallet_has_persistence_failure(&catch_up_handle),
                    short_startup_plan,
                )
                .await;
            drop(startup_target_lease);
        });

        Ok(handle)
    }

    async fn enqueue_wallet_backfill(
        &self,
        cfg: &WalletConfig,
        start_block: u64,
        mut last_scanned: u64,
        sync_target: u64,
        follow_safe_head: bool,
        handle: &WalletHandle,
        progress: crate::types::WalletSchedulableProgress,
        backfill_sender: mpsc::Sender<BackfillEvent>,
        try_cached_coverage: bool,
        short_startup_plan: Option<WalletShortStartupPlan>,
    ) {
        if sync_target > 0 && try_cached_coverage && short_startup_plan.is_none() {
            let cached_outcome = self
                .apply_cached_public_scan_coverage(
                    cfg,
                    start_block,
                    last_scanned,
                    sync_target,
                    handle,
                    &backfill_sender,
                    progress,
                )
                .await;
            last_scanned = cached_outcome.checkpoint;
            if cached_outcome.finished {
                return;
            }
        }
        let from_block = wallet_backfill_from_block(last_scanned, start_block);

        // When safe_head has not been set yet (still 0) we cannot tell whether
        // the wallet is caught up, so we always enqueue a backfill request and
        // let the backfill loop wait for safe_head to become available.
        let needs_backfill = follow_safe_head || sync_target == 0 || from_block <= sync_target;

        if needs_backfill {
            let target_result = handle
                .start_backfill(&cfg.cache_key, &backfill_sender, progress, sync_target)
                .await;
            debug!(?target_result, cache_key = %cfg.cache_key, "wallet target update result");
            let driver = match target_result {
                WalletBackfillStartResult::Accepted { grant, .. } => grant.activate(),
                WalletBackfillStartResult::Rejected { .. } => return,
            };
            let request = if let Some(plan) = short_startup_plan
                && from_block <= plan.acquisition.to_block
            {
                // Acquire only blocks after the cursor before delivery; the
                // loop warms the window's leading part once it delivered.
                BackfillRequest::add_with_acquisition(
                    cfg.cache_key.clone(),
                    from_block,
                    sync_target,
                    follow_safe_head,
                    from_block,
                    (from_block, plan.acquisition.to_block),
                    driver,
                )
                .with_startup_warm_range(
                    plan.acquisition_prefix_before_delivery()
                        .map(|range| (range.from_block, range.to_block)),
                )
            } else {
                BackfillRequest::add(
                    cfg.cache_key.clone(),
                    from_block,
                    sync_target,
                    follow_safe_head,
                    from_block,
                    driver,
                )
            };
            if let Err(err) = self.backfill_tx.try_send(request) {
                warn!(
                    ?err,
                    cache_key = %cfg.cache_key,
                    "backfill loop unavailable after target update"
                );
                if let BackfillRequest::Add { driver, .. } = err.into_inner() {
                    driver
                        .fail(&cfg.cache_key, WalletReadinessError::BackfillUnavailable)
                        .await;
                }
            }
        } else {
            let start_result = handle
                .start_backfill(&cfg.cache_key, &backfill_sender, progress, sync_target)
                .await;
            let result = match start_result {
                WalletBackfillStartResult::Accepted { grant, .. } => {
                    let driver = grant.activate();
                    let result = driver.finish(&cfg.cache_key, sync_target).await;
                    if wallet_finish_result_removes_cursor(&result) {
                        driver.retire(&cfg.cache_key).await;
                    } else {
                        let request = wallet_finish_retry_request(
                            cfg.cache_key.to_string(),
                            sync_target,
                            false,
                            from_block,
                            &result,
                            driver,
                        );
                        if let Err(err) = self.backfill_tx.try_send(request) {
                            warn!(?err, cache_key = %cfg.cache_key, sync_target, "failed to enqueue fixed-target finish retry");
                            if let BackfillRequest::Add { driver, .. } = err.into_inner() {
                                driver
                                    .fail(&cfg.cache_key, WalletReadinessError::BackfillUnavailable)
                                    .await;
                            }
                        }
                    }
                    result
                }
                WalletBackfillStartResult::Rejected {
                    committed_to,
                    reason,
                } => WalletBackfillFinishResult::Rejected {
                    committed_to,
                    reason,
                },
            };
            debug!(?result, cache_key = %cfg.cache_key, "wallet finish result");
        }
    }

    async fn fetch_wallet_rpc_backfill_events(
        &self,
        fetch_from_block: u64,
        deliver_from_block: u64,
        to_block: u64,
        target_policy: RpcTargetPolicy,
        cancel: &CancellationToken,
        read_scope: PublicScanReadScope,
    ) -> Result<WalletRpcBackfillEvents, WalletStartupSyncError> {
        if fetch_from_block > to_block {
            return Ok(WalletRpcBackfillEvents {
                acquisition_applies: Vec::new(),
                delivery_applies: Vec::new(),
            });
        }
        // Reads at or below the archive boundary go to the archive endpoint
        // whichever regular provider is chosen, so another regular provider
        // would repeat the same failing request.
        let archive_until_block = self.chain.sync.archive_until_block;
        let max_providers = if archive_until_block > 0 && fetch_from_block <= archive_until_block {
            1
        } else {
            WALLET_RPC_READ_MAX_PROVIDERS
        };
        let mut rpc = self
            .chain
            .rpcs
            .random_provider()
            .ok_or(ChainError::NoHealthyRpc)?;
        let mut tried = BTreeSet::new();
        let started = Instant::now();
        let batch = loop {
            tried.insert(rpc.index);
            let err = match self
                .fetch_wallet_rpc_log_batch(
                    &rpc,
                    fetch_from_block,
                    deliver_from_block,
                    to_block,
                    target_policy,
                    cancel,
                    read_scope,
                )
                .await
            {
                Ok(batch) => break batch,
                Err(err) => err,
            };
            let next = if matches!(err, WalletStartupSyncError::Cancelled)
                || tried.len() >= max_providers
            {
                None
            } else {
                untried_provider(&self.chain.rpcs, &tried)
            };
            let Some(next) = next else {
                return Err(err);
            };
            debug!(
                rpc_index = rpc.index,
                next_rpc_index = next.index,
                fetch_from_block,
                to_block,
                err = %err.without_url(),
                "wallet RPC read failed; trying another provider"
            );
            rpc = next;
        };
        let Some(batch) = batch else {
            return Ok(WalletRpcBackfillEvents {
                acquisition_applies: Vec::new(),
                delivery_applies: Vec::new(),
            });
        };
        let to_block = batch.to_block;
        let batch = Arc::new(batch);
        debug!(
            fetch_from_block,
            deliver_from_block,
            to_block,
            elapsed_ms = started.elapsed().as_millis(),
            "hedged wallet RPC backfill candidate complete"
        );
        let source = self.rpc_scan_source_for_range(fetch_from_block);
        let fetched_apply =
            WalletScanApply::rows_from_log_batch(fetch_from_block, to_block, &batch, source)
                .map_err(ChainError::from)?;
        let delivery_applies = if deliver_from_block > to_block {
            Vec::new()
        } else {
            vec![
                WalletScanApply::rows_from_log_batch(deliver_from_block, to_block, &batch, source)
                    .map_err(ChainError::from)?,
            ]
        };
        Ok(WalletRpcBackfillEvents {
            acquisition_applies: vec![fetched_apply],
            delivery_applies,
        })
    }

    /// Reads `fetch_from_block..=to_block` from `rpc` for a wallet RPC
    /// backfill read, as far as the provider's finalized head proves it.
    /// Returns `None` when a prefix read has no proven coverage.
    async fn fetch_wallet_rpc_log_batch(
        &self,
        rpc: &ProviderHandle,
        fetch_from_block: u64,
        deliver_from_block: u64,
        to_block: u64,
        target_policy: RpcTargetPolicy,
        cancel: &CancellationToken,
        read_scope: PublicScanReadScope,
    ) -> Result<Option<LogBatch>, WalletStartupSyncError> {
        let provider_head = match wait_or_cancel(cancel, rpc.provider.get_block_number()).await? {
            Ok(provider_head) => provider_head,
            Err(err) => {
                let err = ChainError::from(err);
                if err.should_mark_rpc_unhealthy() {
                    self.chain.rpcs.mark_bad_provider(rpc);
                }
                return Err(err.into());
            }
        };
        let proven_to_block = provider_head.saturating_sub(self.chain.finality_depth);
        if target_policy == RpcTargetPolicy::RequireRequestedTarget && proven_to_block < to_block {
            debug!(
                fetch_from_block,
                deliver_from_block,
                requested_to_block = to_block,
                provider_head,
                proven_to_block,
                finality_depth = self.chain.finality_depth,
                "RPC wallet startup source does not cover the required target"
            );
            return Err(WalletStartupSyncError::IncompleteRpcCoverage {
                requested_to: to_block,
                proven_to: proven_to_block,
            });
        }
        if fetch_from_block > proven_to_block {
            debug!(
                fetch_from_block,
                deliver_from_block,
                requested_to_block = to_block,
                provider_head,
                proven_to_block,
                finality_depth = self.chain.finality_depth,
                "RPC wallet scan source has no proven coverage for requested range"
            );
            return Ok(None);
        }
        let to_block = to_block.min(proven_to_block);
        let fetch_logs_started = Instant::now();
        let mut logs = match wait_or_cancel(
            cancel,
            self.chain.fetch_logs_for_range(
                rpc,
                self.archive_provider.as_ref(),
                fetch_from_block,
                to_block,
                cancel,
            ),
        )
        .await?
        {
            Ok(logs) => logs,
            Err(err) => {
                if err.should_mark_rpc_unhealthy() {
                    self.chain.rpcs.mark_bad_provider(rpc);
                }
                return Err(err.into());
            }
        };
        debug!(
            fetch_from_block,
            deliver_from_block,
            to_block,
            num_logs = logs.len(),
            elapsed_ms = fetch_logs_started.elapsed().as_millis(),
            "fetched hedged wallet RPC logs"
        );
        sort_logs(&mut logs);

        let timestamps_started = Instant::now();
        let block_timestamps = match wait_or_cancel(
            cancel,
            self.chain.fetch_log_block_timestamps(
                &rpc.provider,
                self.archive_provider.as_ref(),
                &logs,
            ),
        )
        .await?
        {
            Ok(block_timestamps) => block_timestamps,
            Err(err) => {
                if err.should_mark_rpc_unhealthy() {
                    self.chain.rpcs.mark_bad_provider(rpc);
                }
                return Err(err.into());
            }
        };
        debug!(
            fetch_from_block,
            deliver_from_block,
            to_block,
            num_logs = logs.len(),
            elapsed_ms = timestamps_started.elapsed().as_millis(),
            "fetched hedged wallet RPC log block timestamps"
        );

        if let Some(archive_endpoint) = self
            .chain
            .archive_boundary_crossed_by(fetch_from_block, to_block)
        {
            let archive_hash = wait_or_cancel(
                cancel,
                self.chain.fetch_block_hash(
                    &rpc.provider,
                    self.archive_provider.as_ref(),
                    archive_endpoint,
                ),
            )
            .await??;
            if archive_hash.is_none() {
                return Err(WalletStartupSyncError::UnprovenRpcEndpoint {
                    block_number: archive_endpoint,
                });
            }
        }

        let block_hash_started = Instant::now();
        let to_block_hash = match wait_or_cancel(
            cancel,
            self.chain
                .fetch_block_hash(&rpc.provider, self.archive_provider.as_ref(), to_block),
        )
        .await?
        {
            Ok(hash) => {
                if hash.is_none() {
                    return Err(WalletStartupSyncError::UnprovenRpcEndpoint {
                        block_number: to_block,
                    });
                }
                hash
            }
            Err(err) => return Err(err.into()),
        };
        debug!(
            to_block,
            elapsed_ms = block_hash_started.elapsed().as_millis(),
            "fetched hedged wallet RPC block hash"
        );

        Ok(Some(LogBatch {
            from_block: fetch_from_block,
            to_block,
            logs,
            block_timestamps,
            to_block_hash,
            read_scope,
        }))
    }

    async fn probe_squid_indexed_wallet_source(
        &self,
        cfg: &WalletConfig,
    ) -> Option<SquidIndexedWalletReadSession> {
        self.probe_squid_indexed_wallet_source_for_label(&cfg.cache_key)
            .await
    }

    async fn probe_squid_indexed_wallet_source_for_label(
        &self,
        cache_key: &str,
    ) -> Option<SquidIndexedWalletReadSession> {
        let Some(endpoint) = self.chain.sync.quick_sync_endpoint.clone() else {
            debug!(cache_key = %cache_key, "no indexed endpoint configured; using RPC wallet backfill");
            return None;
        };
        let client = QuickSyncClient::with_http_client(endpoint, self.chain.http_client.clone());
        let read_scope = self.begin_public_scan_read();
        let probe_started = Instant::now();
        let probe = match client.probe_indexed_wallet_support().await {
            Ok(probe) => probe,
            Err(err) => {
                warn!(
                    err = %WalletStartupSyncError::from(err).without_url(),
                    cache_key = %cache_key,
                    "indexed wallet probe failed; using RPC backfill"
                );
                return None;
            }
        };
        debug!(
            cache_key = %cache_key,
            elapsed_ms = probe_started.elapsed().as_millis(),
            "indexed wallet probe complete"
        );
        Some(SquidIndexedWalletReadSession {
            client,
            indexed_height: probe.height,
            read_scope,
        })
    }

    async fn probe_squid_tail_after_artifact(
        &self,
        cfg: &WalletConfig,
        from_block: u64,
        artifact_target: u64,
        safe_head: u64,
    ) -> Option<(SquidIndexedWalletReadSession, u64)> {
        if artifact_target >= safe_head {
            return None;
        }
        let started = Instant::now();
        let tail_blocks = safe_head - artifact_target;
        // A one-page tail goes to RPC backfill without waiting on Squid.
        if self
            .chain
            .should_skip_indexed_forest_catch_up(artifact_target + 1, safe_head)
        {
            debug!(
                cache_key = %cfg.cache_key,
                artifact_target,
                safe_head,
                tail_blocks,
                elapsed_ms = started.elapsed().as_millis(),
                "Squid step skipped for one-page tail"
            );
            return None;
        }
        let Ok(session) = tokio::time::timeout(
            INDEXED_SQUID_STEP_DEADLINE,
            self.probe_squid_indexed_wallet_source(cfg),
        )
        .await
        else {
            debug!(
                cache_key = %cfg.cache_key,
                artifact_target,
                safe_head,
                tail_blocks,
                elapsed_ms = started.elapsed().as_millis(),
                "Squid step deadline passed"
            );
            return None;
        };
        let session = session?;
        let target = squid_tail_target_after_artifact(
            from_block,
            artifact_target,
            safe_head,
            session.indexed_height(),
        )?;
        Some((session, target))
    }

    async fn prepare_indexed_wallet_artifact_session(
        &self,
        cfg: &WalletConfig,
        from_block: u64,
        safe_head: u64,
        progress_tx: Option<&SyncProgressSender>,
    ) -> Option<IndexedWalletArtifactSession> {
        self.prepare_indexed_wallet_artifact_session_for_label(
            &cfg.cache_key,
            from_block,
            safe_head,
            progress_tx,
        )
        .await
    }

    async fn prepare_indexed_wallet_artifact_session_for_label(
        &self,
        cache_key: &str,
        from_block: u64,
        safe_head: u64,
        progress_tx: Option<&SyncProgressSender>,
    ) -> Option<IndexedWalletArtifactSession> {
        self.chain.sync.indexed_artifact_source.as_ref()?;
        let read_scope = self.begin_public_scan_read();
        let range = PublicScanRange::new(from_block, safe_head);
        self.public_data_plane
            .record_source_decision(
                PublicDataPlaneDiagnosticKind::ArtifactProgress,
                PublicScanSource::IndexedArtifacts,
                range,
                read_scope,
                "wallet-scan artifact preparation started",
            )
            .await;
        let artifact_session_started = Instant::now();
        match IndexedWalletArtifactSession::prepare(
            &self.chain,
            from_block,
            safe_head,
            read_scope,
            &self.public_data_plane,
            progress_tx,
        )
        .await
        {
            Ok(Some(session)) => {
                self.public_data_plane
                    .record_source_decision(
                        PublicDataPlaneDiagnosticKind::ArtifactProgress,
                        PublicScanSource::IndexedArtifacts,
                        range,
                        read_scope,
                        format!(
                            "wallet-scan artifact preparation complete: {} chunks",
                            session.chunk_count()
                        ),
                    )
                    .await;
                debug!(
                    cache_key = %cache_key,
                    from_block,
                    safe_head,
                    latest_indexed_block = session.latest_indexed_block(),
                    catalog_count = session.catalog_count(),
                    chunk_count = session.chunk_count(),
                    elapsed_ms = artifact_session_started.elapsed().as_millis(),
                    "indexed wallet artifact session prepared"
                );
                Some(session)
            }
            Ok(None) => {
                self.public_data_plane
                    .record_source_decision(
                        PublicDataPlaneDiagnosticKind::ArtifactProgress,
                        PublicScanSource::IndexedArtifacts,
                        range,
                        read_scope,
                        "wallet-scan artifact preparation unavailable",
                    )
                    .await;
                self.public_data_plane
                    .record_source_decision(
                        PublicDataPlaneDiagnosticKind::SourceFallback,
                        PublicScanSource::IndexedArtifacts,
                        range,
                        read_scope,
                        "wallet-scan artifact preparation unavailable; falling back",
                    )
                    .await;
                debug!(
                    cache_key = %cache_key,
                    from_block,
                    safe_head,
                    elapsed_ms = artifact_session_started.elapsed().as_millis(),
                    "indexed wallet artifact session unavailable"
                );
                None
            }
            Err(err) => {
                self.public_data_plane
                    .record_source_decision(
                        PublicDataPlaneDiagnosticKind::ArtifactProgress,
                        PublicScanSource::IndexedArtifacts,
                        range,
                        read_scope,
                        "wallet-scan artifact preparation failed",
                    )
                    .await;
                self.public_data_plane
                    .record_source_decision(
                        PublicDataPlaneDiagnosticKind::SourceFallback,
                        PublicScanSource::IndexedArtifacts,
                        range,
                        read_scope,
                        "wallet-scan artifact preparation failed; falling back",
                    )
                    .await;
                warn!(
                    err = %WalletStartupSyncError::from(err).without_url(),
                    cache_key = %cache_key,
                    from_block,
                    safe_head,
                    elapsed_ms = artifact_session_started.elapsed().as_millis(),
                    "indexed wallet artifact session failed; falling back to configured indexed sources"
                );
                None
            }
        }
    }

    pub async fn unregister_wallet(&self, handle: &WalletHandle) {
        let cache_key = handle.cache_key.as_str();
        let _registration_guard = self.wallet_registration_gate.lock().await;
        let registration = {
            let mut wallet = self.wallet.write().await;
            let is_current = wallet.as_ref().is_some_and(|registration| {
                registration.cfg.cache_key.as_str() == cache_key
                    && registration.handle.same_actor_as(handle)
            });
            is_current.then(|| wallet.take()).flatten()
        };
        let Some(registration) = registration else {
            return;
        };
        Self::begin_wallet_retirement(&registration);
        if let Err(err) = self.finish_wallet_retirement(cache_key, registration).await {
            warn!(?err, cache_key = %cache_key, "wallet retirement cleanup failed");
        }
    }

    fn begin_wallet_retirement(registration: &WalletRegistration) {
        registration
            .handle
            .retire_actor_with_publisher(&registration.observation);
        registration.cancel.cancel();
    }

    fn begin_wallet_shutdown(registration: &WalletRegistration) {
        registration
            .handle
            .retire_actor_for_shutdown(&registration.observation);
        registration.cancel.cancel();
    }

    async fn finish_wallet_retirement(
        &self,
        cache_key: &str,
        registration: WalletRegistration,
    ) -> Result<(), ChainError> {
        let chain_id = self.chain.deployment.chain_id;
        let actor_id = registration.handle.actor_id();
        let (response_tx, response_rx) = oneshot::channel();
        let backfill_started = Instant::now();
        let backfill_result = match self
            .backfill_tx
            .send(BackfillRequest::Remove {
                cache_key: cache_key.to_string(),
                actor_id: registration.handle.actor_id(),
                response: response_tx,
            })
            .await
        {
            Ok(()) => response_rx
                .await
                .map_err(|_| ChainError::WalletBackfillRetirementFailed),
            Err(_) => Err(ChainError::WalletBackfillRetirementFailed),
        };
        debug!(
            chain_id,
            actor_id,
            elapsed_ms = backfill_started.elapsed().as_millis(),
            acknowledged = backfill_result.is_ok(),
            "wallet backfill retirement acknowledgement"
        );
        let worker_started = Instant::now();
        let worker_result = registration
            .worker
            .await
            .map_err(|_| ChainError::WalletWorkerRetirementFailed);
        debug!(
            chain_id,
            actor_id,
            elapsed_ms = worker_started.elapsed().as_millis(),
            joined = worker_result.is_ok(),
            "wallet worker retirement join"
        );
        match (backfill_result, worker_result) {
            (Err(backfill_err), _) => Err(backfill_err),
            (Ok(()), Err(worker_err)) => Err(worker_err),
            (Ok(()), Ok(())) => Ok(()),
        }
    }

    pub async fn unregister_all_wallets(&self) {
        let _registration_guard = self.wallet_registration_gate.lock().await;
        let registration = self.wallet.write().await.take();
        if let Some(registration) = registration {
            let cache_key = registration.cfg.cache_key.clone();
            Self::begin_wallet_retirement(&registration);
            if let Err(err) = self
                .finish_wallet_retirement(cache_key.as_str(), registration)
                .await
            {
                warn!(?err, cache_key = %cache_key, "wallet cleanup failed");
            }
        }
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
        let poi_submitter_task = self
            .poi_submitter_task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(task) = poi_submitter_task
            && let Err(err) = task.await
            && !err.is_cancelled()
        {
            warn!(
                chain_id = self.chain.deployment.chain_id,
                "chain PPOI submitter failed during shutdown"
            );
        }
        // The loop drops an in-flight sync on cancel, and its service clone
        // keeps the data plane, and with it the runtime lease, alive.
        let txid_public_cache_task = self
            .txid_public_cache_task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(task) = txid_public_cache_task
            && let Err(err) = task.await
            && !err.is_cancelled()
        {
            warn!(
                chain_id = self.chain.deployment.chain_id,
                "TXID public cache loop failed during shutdown"
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
    let live_log_task = live_log_task
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    if let Some(task) = live_log_task
        && let Err(err) = task.await
        && !err.is_cancelled()
    {
        warn!(?err, chain_id, "live log worker failed during shutdown");
    }
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

async fn fetch_initial_head(
    chain: &ChainConfig,
    rpcs: &QueryRpcPool,
) -> Option<(ProviderHandle, u64, u64)> {
    let Some((rpc, head)) = read_head_bounded(rpcs).await else {
        warn!(
            chain_id = chain.deployment.chain_id,
            "no rpc provider returned the initial block number; starting without a safe head"
        );
        return None;
    };
    let safe_head = head
        .saturating_sub(chain.finality_depth)
        .max(chain.deployment.deployment_block);
    Some((rpc, head, safe_head))
}
