use crate::chain::{
    WalletPoiRuntime, WalletRegistration, WalletWorkerServices, wallet_cache_store,
    wallet_finish_result_removes_cursor, wallet_finish_retry_request,
};

use super::{
    Arc, BackfillRequest, CachedPublicScanApplyOutcome, ChainError, ChainService,
    IndexedWalletCatchUpSourceOrder, Instant, Ordering, WalletBackfillFinishResult,
    WalletBackfillStartResult, WalletConfig, WalletHandle, WalletReadiness, WalletReadinessError,
    WalletShortStartupPlan, WalletSyncContext, debug, info, mpsc, oneshot,
    send_wallet_startup_events, wait_for_startup_sync_target, wait_for_wallet_ready,
    wallet_backfill_from_block, wallet_has_persistence_failure,
    wallet_remote_target_before_cached_suffix, wallet_sync_target, warn,
};

impl ChainService {
    pub(super) fn wallet_registration_is_terminal(registration: &WalletRegistration) -> bool {
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
            let ctx = WalletSyncContext {
                cfg: &catch_up_cfg,
                start_block,
                handle: &catch_up_handle,
                backfill_sender: &backfill_sender,
            };
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
                        ctx,
                        startup.last_scanned,
                        sync_target,
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
                        ctx,
                        cached_outcome.checkpoint,
                        sync_target,
                        catch_up_cfg.sync_to_block.is_none(),
                        progress,
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
                    ctx,
                    startup,
                    sync_target,
                    short_startup_plan,
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
                        ctx,
                        progress.last_scanned,
                        sync_target,
                        catch_up_cfg.sync_to_block.is_none(),
                        progress,
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
                                ctx,
                                startup,
                                sync_target,
                                plan,
                                candidate,
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
                                        ctx,
                                        sync_target,
                                        sync_target,
                                        true,
                                        progress,
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
                        ctx,
                        checkpoint,
                        historical_target,
                        &catch_up_cancel,
                        IndexedWalletCatchUpSourceOrder::ArtifactsFirst,
                        false,
                        progress,
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
                                ctx,
                                sync_target,
                                sync_target,
                                true,
                                progress,
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
                    ctx,
                    checkpoint,
                    sync_target,
                    catch_up_cfg.sync_to_block.is_none(),
                    progress,
                    !wallet_has_persistence_failure(&catch_up_handle),
                    short_startup_plan,
                )
                .await;
            drop(startup_target_lease);
        });

        Ok(handle)
    }

    pub(super) async fn enqueue_wallet_backfill(
        &self,
        ctx: WalletSyncContext<'_>,
        mut last_scanned: u64,
        sync_target: u64,
        follow_safe_head: bool,
        progress: crate::types::WalletSchedulableProgress,
        try_cached_coverage: bool,
        short_startup_plan: Option<WalletShortStartupPlan>,
    ) {
        let WalletSyncContext {
            cfg,
            start_block,
            handle,
            backfill_sender,
        } = ctx;
        if sync_target > 0 && try_cached_coverage && short_startup_plan.is_none() {
            let cached_outcome = self
                .apply_cached_public_scan_coverage(ctx, last_scanned, sync_target, progress)
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
                .start_backfill(&cfg.cache_key, backfill_sender, progress, sync_target)
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
                .start_backfill(&cfg.cache_key, backfill_sender, progress, sync_target)
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

    pub(super) fn begin_wallet_shutdown(registration: &WalletRegistration) {
        registration
            .handle
            .retire_actor_for_shutdown(&registration.observation);
        registration.cancel.cancel();
    }

    pub(super) async fn finish_wallet_retirement(
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
}
