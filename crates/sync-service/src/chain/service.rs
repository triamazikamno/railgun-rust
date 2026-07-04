use super::*;

pub(super) async fn send_wallet_scan_apply(
    cache_key: &str,
    sender: &mpsc::Sender<BackfillEvent>,
    apply: WalletScanApply,
    reset_generation: u64,
) -> WalletBackfillApplyResult {
    let requested_to = apply.to_block;
    let (response, result_rx) = oneshot::channel();
    if let Err(err) = sender
        .send(BackfillEvent::Apply {
            apply,
            reset_generation,
            response,
        })
        .await
    {
        warn!(?err, cache_key, "failed to send wallet scan batch");
        return WalletBackfillApplyResult::Rejected {
            committed_to: requested_to.saturating_sub(1),
            reason: WalletBackfillRejectReason::Shutdown,
        };
    }
    match result_rx.await {
        Ok(result) => result,
        Err(err) => {
            warn!(?err, cache_key, "wallet scan batch response dropped");
            WalletBackfillApplyResult::Rejected {
                committed_to: requested_to.saturating_sub(1),
                reason: WalletBackfillRejectReason::Shutdown,
            }
        }
    }
}

pub(super) async fn send_wallet_target(
    cache_key: &str,
    sender: &mpsc::Sender<BackfillEvent>,
    target_block: u64,
    reset_generation: u64,
) -> WalletBackfillFinishResult {
    let (response, result_rx) = oneshot::channel();
    if let Err(err) = sender
        .send(BackfillEvent::Target {
            target_block,
            reset_generation,
            response,
        })
        .await
    {
        warn!(
            ?err,
            cache_key, target_block, "failed to send wallet target update"
        );
        return WalletBackfillFinishResult::Rejected {
            committed_to: target_block.saturating_sub(1),
            reason: WalletBackfillRejectReason::Shutdown,
        };
    }
    match result_rx.await {
        Ok(result) => result,
        Err(err) => {
            warn!(
                ?err,
                cache_key, target_block, "wallet target response dropped"
            );
            WalletBackfillFinishResult::Rejected {
                committed_to: target_block.saturating_sub(1),
                reason: WalletBackfillRejectReason::Shutdown,
            }
        }
    }
}

pub(in crate::chain) async fn send_wallet_reset(
    cache_key: &str,
    sender: &mpsc::Sender<BackfillEvent>,
    intent_id: u64,
    from_block: u64,
    committed_to: u64,
) -> WalletBackfillResetResult {
    let (response, result_rx) = oneshot::channel();
    if let Err(err) = sender
        .send(BackfillEvent::Reset {
            intent_id,
            from_block,
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

impl ChainService {
    pub(super) fn next_wallet_reset_intent(&self) -> u64 {
        self.wallet_reset_intent_next.fetch_add(1, Ordering::AcqRel)
    }

    pub(super) fn current_public_data_epoch(&self) -> PublicDataPlaneEpoch {
        PublicDataPlaneEpoch::new(self.public_data_epoch.load(Ordering::Acquire))
    }

    pub async fn start(db: Arc<DbStore>, chain: ChainConfig) -> Result<Arc<Self>, ChainError> {
        if chain.archive_until_block > 0
            && chain.archive_rpc_url.is_none()
            && chain.deployment_block <= chain.archive_until_block
        {
            warn!(
                chain_id = chain.chain_id,
                archive_until_block = chain.archive_until_block,
                "archive RPC URL not configured; using regular RPC providers for archive-range fallback"
            );
        }
        let archive_provider = match chain.archive_rpc_url.as_ref() {
            Some(url) => Some(
                build_provider_with_http_client(url, chain.http_client.as_ref())
                    .await
                    .map_err(ChainError::ProviderBuild)?,
            ),
            None => None,
        };

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
                Some(&rpc.provider),
                archive_provider.as_ref(),
            )
            .await?;

        let (head_tx, _head_rx) = watch::channel(initial_head);
        let (safe_head_tx, safe_head_rx) = watch::channel(initial_safe_head);
        let (forest_last_tx, forest_last_rx) = watch::channel(last_processed);
        let (live_log_tx, _live_log_rx) = broadcast::channel(64);
        let (backfill_tx, backfill_rx) = mpsc::channel(128);
        let cancel = CancellationToken::new();
        let service = Arc::new(Self {
            chain,
            db,
            forest,
            head_tx,
            safe_head_tx,
            forest_last_tx,
            live_log_tx,
            backfill_tx,
            archive_provider: archive_provider.clone(),
            wallets: RwLock::new(HashMap::new()),
            cancel: cancel.clone(),
            live_log_task: Mutex::new(None),
            anchor_last: AtomicU64::new(last_anchor),
            txid_public_cache_started: AtomicBool::new(false),
            wallet_actor_next: AtomicU64::new(1),
            wallet_reset_intent_next: AtomicU64::new(1),
            public_data_epoch: Arc::new(AtomicU64::new(0)),
        });

        spawn_head_poller(service.clone(), rpcs.clone());
        let live_log_task = spawn_live_log_loop(
            service.clone(),
            rpcs.clone(),
            archive_provider.clone(),
            forest_last_rx,
            safe_head_rx.clone(),
            snapshot_path,
            cancel.clone(),
        );
        *service.live_log_task.lock().await = Some(live_log_task);
        spawn_pending_tip_loop(
            service.clone(),
            rpcs.clone(),
            archive_provider.clone(),
            service.head_tx.subscribe(),
            safe_head_rx.clone(),
            cancel.clone(),
        );
        spawn_wallet_lag_fallback_loop(service.clone(), safe_head_rx.clone(), cancel.clone());
        spawn_backfill_loop(
            service.clone(),
            backfill_rx,
            rpcs,
            archive_provider,
            safe_head_rx,
            cancel,
        );

        Ok(service)
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
        self.wallets
            .read()
            .await
            .get(cache_key)
            .map(|registration| registration.handle.clone())
    }

    fn spawn_txid_public_cache_loop_once(self: &Arc<Self>) {
        if self.txid_public_cache_started.swap(true, Ordering::AcqRel) {
            return;
        }
        spawn_txid_public_cache_loop(Arc::clone(self), self.cancel.clone());
    }

    fn spawn_txid_public_cache_loop_when_ready(
        self: &Arc<Self>,
        readiness_rx: watch::Receiver<WalletReadiness>,
        cancel: CancellationToken,
    ) {
        let service = Arc::clone(self);
        tokio::spawn(async move {
            if wait_for_wallet_ready(readiness_rx, cancel).await {
                service.spawn_txid_public_cache_loop_once();
            }
        });
    }

    pub async fn reset_wallet(
        &self,
        cache_key: &str,
        from_block: Option<u64>,
    ) -> Result<(), ChainError> {
        let (handle, backfill_sender, start_block, sync_to_block, progress_tx) = {
            let wallets = self.wallets.read().await;
            let registration = wallets.get(cache_key).ok_or(ChainError::WalletNotFound)?;
            (
                registration.handle.clone(),
                registration.backfill_sender.clone(),
                registration.start_block,
                registration.sync_to_block,
                registration
                    .cfg
                    .progress_tx
                    .clone()
                    .or_else(|| self.chain.progress_tx.clone()),
            )
        };

        let reset_from = from_block.unwrap_or(start_block);
        let safe_head = *self.safe_head_tx.borrow();
        let sync_target = wallet_sync_target(safe_head, sync_to_block);
        let reset_intent_id = self.next_wallet_reset_intent();
        let reset_result = send_wallet_reset(
            cache_key,
            &backfill_sender,
            reset_intent_id,
            reset_from,
            handle.last_scanned(),
        )
        .await;
        let Some(reset_generation) = reset_result.reset_generation() else {
            warn!(?reset_result, cache_key = %cache_key, from_block = reset_from, "wallet reset rejected");
            return Err(ChainError::WalletResetRejected(reset_result));
        };

        self.backfill_tx
            .send(BackfillRequest::Add {
                cache_key: cache_key.to_string(),
                from_block: reset_from,
                to_block: sync_target,
                follow_safe_head: sync_to_block.is_none(),
                progress_start_block: reset_from,
                reset_generation,
                progress_tx,
                sender: backfill_sender,
            })
            .await?;

        info!(cache_key = %cache_key, from_block = reset_from, "wallet reset requested");
        Ok(())
    }

    pub(super) async fn try_indexed_wallet_tail_catch_up(
        &self,
        cache_key: &str,
        from_block: u64,
        target_block: u64,
        sender: &mpsc::Sender<BackfillEvent>,
    ) -> Option<(u64, u64)> {
        if from_block > target_block {
            return None;
        }
        let (cfg, start_block, handle, cancel) = {
            let wallets = self.wallets.read().await;
            let registration = wallets.get(cache_key)?;
            if !registration.cfg.use_indexed_wallet_catch_up {
                debug!(cache_key = %cache_key, "indexed wallet tail fallback disabled");
                return None;
            }
            (
                registration.cfg.clone(),
                registration.start_block,
                registration.handle.clone(),
                registration.cancel.clone(),
            )
        };
        let reset_generation = handle.reset_generation();
        let last_scanned = from_block.saturating_sub(1);
        let started = Instant::now();
        let checkpoint = self
            .indexed_wallet_catch_up(
                &cfg,
                start_block,
                last_scanned,
                target_block,
                &handle,
                &cancel,
                IndexedWalletCatchUpSourceOrder::SquidFirst,
                true,
                (sender, reset_generation),
            )
            .await;
        if checkpoint < from_block {
            debug!(
                cache_key = %cache_key,
                from_block,
                target_block,
                checkpoint,
                elapsed_ms = started.elapsed().as_millis(),
                "indexed wallet tail fallback did not advance"
            );
            return None;
        }
        info!(
            cache_key = %cache_key,
            from_block,
            target_block,
            checkpoint,
            elapsed_ms = started.elapsed().as_millis(),
            "indexed wallet tail fallback complete"
        );
        Some((checkpoint, reset_generation))
    }

    pub async fn register_wallet(self: &Arc<Self>, cfg: WalletConfig) -> WalletHandle {
        let cache_key = cfg.cache_key.clone();
        if let Some(existing) = self.wallets.read().await.get(&cache_key) {
            if existing.handle.readiness().is_ready() {
                self.spawn_txid_public_cache_loop_once();
            }
            return existing.handle.clone();
        }

        let mut cfg = cfg;
        let start_block = cfg.start_block.unwrap_or(self.chain.deployment_block);
        cfg.start_block = Some(start_block);

        let mut last_scanned = start_block.saturating_sub(1);
        let cache_store = wallet_cache_store(&self.db, &cfg);
        if let Ok(Some(meta)) = cache_store.get_wallet_meta(&cfg.cache_key) {
            last_scanned = meta.last_scanned_block;
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
            indexed_artifact_source = self.chain.indexed_artifact_source.is_some(),
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

        let (handle, cancel, backfill_sender) = {
            let mut wallets = self.wallets.write().await;
            if let Some(existing) = wallets.get(&cache_key) {
                if existing.handle.readiness().is_ready() {
                    self.spawn_txid_public_cache_loop_once();
                }
                return existing.handle.clone();
            }

            let actor_id = self.wallet_actor_next.fetch_add(1, Ordering::AcqRel);
            let cancel = self.cancel.child_token();
            let live_rx = self.live_log_tx.subscribe();
            let (backfill_sender, backfill_rx) = mpsc::channel(128);
            let handle = spawn_wallet_worker(
                WalletWorkerServices {
                    db: self.db.clone(),
                    rpcs: self.chain.rpcs.clone(),
                    http_client: self.chain.http_client.clone(),
                    indexed_artifact_source: self.chain.indexed_artifact_source.clone(),
                    forest: self.forest.clone(),
                    backfill_tx: self.backfill_tx.clone(),
                    backfill_sender: backfill_sender.clone(),
                    public_data_epoch: self.public_data_epoch.clone(),
                },
                cfg.clone(),
                actor_id,
                live_rx,
                backfill_rx,
                cancel.clone(),
                initial_utxos,
                last_scanned,
            );

            wallets.insert(
                cache_key.clone(),
                WalletRegistration {
                    handle: handle.clone(),
                    cfg: cfg.clone(),
                    cancel: cancel.clone(),
                    backfill_sender: backfill_sender.clone(),
                    start_block,
                    sync_to_block: cfg.sync_to_block,
                },
            );
            (handle, cancel, backfill_sender)
        };

        self.spawn_txid_public_cache_loop_when_ready(handle.readiness_rx.clone(), cancel.clone());

        let service = Arc::clone(self);
        let catch_up_cfg = cfg.clone();
        let catch_up_handle = handle.clone();
        let catch_up_cancel = cancel;
        tokio::spawn(async move {
            let startup_reset_generation = catch_up_handle.reset_generation();
            let Some(sync_target) = wait_for_startup_sync_target(
                service.safe_head_tx.subscribe(),
                catch_up_cfg.sync_to_block,
                sync_target,
                &catch_up_cancel,
            )
            .await
            else {
                return;
            };

            if service
                .hedged_wallet_startup_sync(
                    &catch_up_cfg,
                    start_block,
                    last_scanned,
                    sync_target,
                    startup_reset_generation,
                    backfill_sender.clone(),
                    &catch_up_cancel,
                )
                .await
            {
                return;
            }

            let mut checkpoint = last_scanned;
            if catch_up_cfg.use_indexed_wallet_catch_up {
                checkpoint = service
                    .indexed_wallet_catch_up(
                        &catch_up_cfg,
                        start_block,
                        checkpoint,
                        sync_target,
                        &catch_up_handle,
                        &catch_up_cancel,
                        IndexedWalletCatchUpSourceOrder::ArtifactsFirst,
                        false,
                        (&backfill_sender, startup_reset_generation),
                    )
                    .await;
            } else {
                debug!(cache_key = %catch_up_cfg.cache_key, "indexed wallet catch-up disabled");
            }
            if catch_up_cancel.is_cancelled() {
                return;
            }
            if catch_up_handle.reset_generation() != startup_reset_generation {
                debug!(
                    cache_key = %catch_up_cfg.cache_key,
                    startup_reset_generation,
                    current_reset_generation = catch_up_handle.reset_generation(),
                    "wallet startup sync superseded by reset"
                );
                return;
            }
            service
                .enqueue_wallet_backfill(
                    &catch_up_cfg,
                    start_block,
                    checkpoint,
                    sync_target,
                    catch_up_cfg.sync_to_block.is_none(),
                    startup_reset_generation,
                    backfill_sender,
                )
                .await;
        });

        handle
    }

    async fn enqueue_wallet_backfill(
        &self,
        cfg: &WalletConfig,
        start_block: u64,
        last_scanned: u64,
        sync_target: u64,
        follow_safe_head: bool,
        reset_generation: u64,
        backfill_sender: mpsc::Sender<BackfillEvent>,
    ) {
        let from_block = wallet_backfill_from_block(last_scanned, start_block);

        // When safe_head has not been set yet (still 0) we cannot tell whether
        // the wallet is caught up, so we always enqueue a backfill request and
        // let the backfill loop wait for safe_head to become available.
        let needs_backfill = follow_safe_head || sync_target == 0 || from_block <= sync_target;

        if needs_backfill {
            let target_result = send_wallet_target(
                &cfg.cache_key,
                &backfill_sender,
                sync_target,
                reset_generation,
            )
            .await;
            debug!(?target_result, cache_key = %cfg.cache_key, "wallet target update result");
            let progress_tx = cfg
                .progress_tx
                .clone()
                .or_else(|| self.chain.progress_tx.clone());
            if self
                .backfill_tx
                .send(BackfillRequest::Add {
                    cache_key: cfg.cache_key.clone(),
                    from_block,
                    to_block: sync_target,
                    follow_safe_head,
                    progress_start_block: from_block,
                    reset_generation,
                    progress_tx,
                    sender: backfill_sender.clone(),
                })
                .await
                .is_err()
            {
                warn!(
                    cache_key = %cfg.cache_key,
                    "backfill loop unavailable after target update"
                );
                let result = send_wallet_target(
                    &cfg.cache_key,
                    &backfill_sender,
                    sync_target,
                    reset_generation,
                )
                .await;
                debug!(?result, cache_key = %cfg.cache_key, "wallet finish fallback result");
            }
        } else {
            let result = send_wallet_target(
                &cfg.cache_key,
                &backfill_sender,
                sync_target,
                reset_generation,
            )
            .await;
            debug!(?result, cache_key = %cfg.cache_key, "wallet finish result");
        }
    }

    async fn hedged_wallet_startup_sync(
        self: &Arc<Self>,
        cfg: &WalletConfig,
        start_block: u64,
        last_scanned: u64,
        sync_target: u64,
        reset_generation: u64,
        backfill_sender: mpsc::Sender<BackfillEvent>,
        cancel: &CancellationToken,
    ) -> bool {
        if !cfg.use_indexed_wallet_catch_up
            || self.chain.quick_sync_endpoint.is_none()
            || !should_hedge_wallet_startup(
                last_scanned,
                start_block,
                sync_target,
                self.chain.block_range,
                self.chain.indexed_artifact_source.is_some(),
            )
        {
            return false;
        }

        let started = Instant::now();
        info!(
            cache_key = %cfg.cache_key,
            start_block,
            last_scanned,
            sync_target,
            block_range = self.chain.block_range,
            "wallet startup hedge started"
        );

        let hedge_cancel = cancel.child_token();
        let (result_tx, mut result_rx) = mpsc::channel(2);

        let rpc_service = Arc::clone(self);
        let rpc_cfg = cfg.clone();
        let rpc_cancel = hedge_cancel.child_token();
        let rpc_result_tx = result_tx.clone();
        let rpc_handle = tokio::spawn(async move {
            let result = rpc_service
                .wallet_startup_rpc_candidate(
                    &rpc_cfg,
                    start_block,
                    last_scanned,
                    sync_target,
                    rpc_cancel,
                )
                .await;
            let _ = rpc_result_tx
                .send((WalletStartupSyncStrategy::Rpc, result))
                .await;
        });

        let indexed_service = Arc::clone(self);
        let indexed_cfg = cfg.clone();
        let indexed_cancel = hedge_cancel.child_token();
        let indexed_result_tx = result_tx.clone();
        let indexed_handle = tokio::spawn(async move {
            let result = indexed_service
                .wallet_startup_indexed_candidate(
                    &indexed_cfg,
                    start_block,
                    last_scanned,
                    sync_target,
                    indexed_cancel,
                )
                .await;
            let _ = indexed_result_tx
                .send((WalletStartupSyncStrategy::Indexed, result))
                .await;
        });
        drop(result_tx);

        let mut failures = 0_u8;
        while let Some((strategy, result)) = result_rx.recv().await {
            match result {
                Ok(candidate) => {
                    hedge_cancel.cancel();
                    rpc_handle.abort();
                    indexed_handle.abort();
                    let follow_safe_head = cfg.sync_to_block.is_none();
                    let winner = candidate.strategy;
                    let candidate_elapsed_ms = candidate.elapsed_ms;
                    let sent = send_wallet_startup_events(
                        &cfg.cache_key,
                        candidate.applies,
                        Some(sync_target),
                        reset_generation,
                        &backfill_sender,
                    )
                    .await;
                    if sent && follow_safe_head {
                        self.enqueue_wallet_backfill(
                            cfg,
                            start_block,
                            sync_target,
                            sync_target,
                            true,
                            reset_generation,
                            backfill_sender.clone(),
                        )
                        .await;
                    }
                    info!(
                        cache_key = %cfg.cache_key,
                        winner = winner.as_str(),
                        reported_by = strategy.as_str(),
                        candidate_elapsed_ms,
                        follow_safe_head,
                        elapsed_ms = started.elapsed().as_millis(),
                        cancelled_loser = true,
                        sent,
                        "wallet startup hedge complete"
                    );
                    return sent;
                }
                Err(err) => {
                    failures = failures.saturating_add(1);
                    debug!(
                        err = %err,
                        cache_key = %cfg.cache_key,
                        strategy = strategy.as_str(),
                        failures,
                        "wallet startup hedge candidate failed"
                    );
                    if failures >= 2 {
                        break;
                    }
                }
            }
        }

        hedge_cancel.cancel();
        rpc_handle.abort();
        indexed_handle.abort();
        warn!(
            cache_key = %cfg.cache_key,
            elapsed_ms = started.elapsed().as_millis(),
            "wallet startup hedge failed; falling back to indexed-then-rpc startup sync"
        );
        false
    }

    async fn wallet_startup_rpc_candidate(
        self: Arc<Self>,
        cfg: &WalletConfig,
        start_block: u64,
        last_scanned: u64,
        sync_target: u64,
        cancel: CancellationToken,
    ) -> Result<WalletStartupSyncCandidate, WalletStartupSyncError> {
        let started = Instant::now();
        let from_block = wallet_backfill_from_block(last_scanned, start_block);
        let events = self
            .fetch_wallet_rpc_backfill_events(from_block, sync_target, &cancel)
            .await?;
        debug!(
            cache_key = %cfg.cache_key,
            from_block,
            sync_target,
            events = events.len(),
            elapsed_ms = started.elapsed().as_millis(),
            "wallet startup RPC candidate complete"
        );
        Ok(WalletStartupSyncCandidate {
            strategy: WalletStartupSyncStrategy::Rpc,
            applies: events,
            elapsed_ms: started.elapsed().as_millis(),
        })
    }

    async fn wallet_startup_indexed_candidate(
        self: Arc<Self>,
        cfg: &WalletConfig,
        start_block: u64,
        last_scanned: u64,
        sync_target: u64,
        cancel: CancellationToken,
    ) -> Result<WalletStartupSyncCandidate, WalletStartupSyncError> {
        let started = Instant::now();
        let endpoint = self
            .chain
            .quick_sync_endpoint
            .clone()
            .ok_or(WalletStartupSyncError::Cancelled)?;
        let client = match self.chain.http_client.clone() {
            Some(http_client) => QuickSyncClient::with_http_client(endpoint, http_client),
            None => QuickSyncClient::new(endpoint),
        };
        let probe_started = Instant::now();
        let probe = wait_or_cancel(&cancel, client.probe_indexed_wallet_support()).await??;
        debug!(
            cache_key = %cfg.cache_key,
            elapsed_ms = probe_started.elapsed().as_millis(),
            "indexed wallet hedge probe complete"
        );

        let target = probe.height.min(sync_target);
        let mut from_block = wallet_backfill_from_block(last_scanned, start_block);
        let progress_start = from_block;
        let progress_tx = cfg
            .progress_tx
            .clone()
            .or_else(|| self.chain.progress_tx.clone());
        let mut checkpoint = last_scanned;
        let mut events = Vec::new();
        info!(
            cache_key = %cfg.cache_key,
            indexed_height = probe.height,
            sync_target,
            from_block,
            target,
            indexed_block_range = self.chain.indexed_wallet_block_range,
            "indexed wallet hedge target"
        );

        if from_block <= target {
            send_sync_progress(
                progress_tx.as_ref(),
                SyncProgressUpdate::new(
                    SyncProgressStage::IndexingUtxos,
                    progress_start,
                    progress_start,
                    target,
                ),
            );
        }

        while from_block <= target {
            if cancel.is_cancelled() {
                return Err(WalletStartupSyncError::Cancelled);
            }
            let page_started = Instant::now();
            let page_kind =
                IndexedWalletPageKind::for_from_block(from_block, self.chain.v2_start_block);
            let to_block = page_kind.to_block(
                from_block,
                target,
                self.chain.v2_start_block,
                self.chain.indexed_wallet_block_range,
            );
            let fetch_started = Instant::now();
            let page = wait_or_cancel(
                &cancel,
                IndexedWalletPage::fetch(&client, page_kind, from_block, to_block),
            )
            .await??;
            let fetch_elapsed_ms = fetch_started.elapsed().as_millis();
            let parse_started = Instant::now();
            let row_count = page.transact_commitments.len()
                + page.shield_commitments.len()
                + page.legacy_encrypted_commitments.len()
                + page.legacy_generated_commitments.len()
                + page.nullifiers.len();
            let transact_rows = page.transact_rows;
            let shield_rows = page.shield_rows;
            let legacy_encrypted_rows = page.legacy_encrypted_rows;
            let legacy_generated_rows = page.legacy_generated_rows;
            let nullifier_rows = page.nullifier_rows;
            let parse_elapsed_ms = parse_started.elapsed().as_millis();
            checkpoint = page.checkpoint_block;
            events.push(WalletScanApply::indexed_rows(
                from_block,
                checkpoint,
                page.into_scan_rows(WalletIndexedCatchUpSource::Squid),
                self.current_public_data_epoch(),
                WalletIndexedCatchUpSource::Squid,
            ));
            debug!(
                cache_key = %cfg.cache_key,
                page_kind = page_kind.as_str(),
                from_block,
                to_block,
                checkpoint,
                transact_rows,
                shield_rows,
                legacy_encrypted_rows,
                legacy_generated_rows,
                nullifier_rows,
                row_count,
                fetch_elapsed_ms,
                parse_elapsed_ms,
                elapsed_ms = page_started.elapsed().as_millis(),
                "indexed wallet hedge page complete"
            );
            send_sync_progress(
                progress_tx.as_ref(),
                SyncProgressUpdate::new(
                    SyncProgressStage::IndexingUtxos,
                    progress_start,
                    checkpoint,
                    target,
                ),
            );
            from_block = checkpoint.saturating_add(1);
        }

        if checkpoint < sync_target {
            let tail_from = wallet_backfill_from_block(checkpoint, start_block);
            let mut tail_events = self
                .fetch_wallet_rpc_backfill_events(tail_from, sync_target, &cancel)
                .await?;
            events.append(&mut tail_events);
        }

        Ok(WalletStartupSyncCandidate {
            strategy: WalletStartupSyncStrategy::Indexed,
            applies: events,
            elapsed_ms: started.elapsed().as_millis(),
        })
    }

    async fn fetch_wallet_rpc_backfill_events(
        &self,
        from_block: u64,
        to_block: u64,
        cancel: &CancellationToken,
    ) -> Result<Vec<WalletScanApply>, WalletStartupSyncError> {
        if from_block > to_block {
            return Ok(Vec::new());
        }
        let rpc = self
            .chain
            .rpcs
            .random_provider()
            .ok_or(ChainError::NoHealthyRpc)?;
        let started = Instant::now();
        let fetch_logs_started = Instant::now();
        let mut logs = match wait_or_cancel(
            cancel,
            self.chain.fetch_logs_for_range(
                &rpc.provider,
                self.archive_provider.as_ref(),
                from_block,
                to_block,
            ),
        )
        .await?
        {
            Ok(logs) => logs,
            Err(err) => {
                if err.should_mark_rpc_unhealthy() {
                    self.chain.rpcs.mark_bad_provider(&rpc);
                }
                return Err(err.into());
            }
        };
        debug!(
            from_block,
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
                    self.chain.rpcs.mark_bad_provider(&rpc);
                }
                return Err(err.into());
            }
        };
        debug!(
            from_block,
            to_block,
            num_logs = logs.len(),
            elapsed_ms = timestamps_started.elapsed().as_millis(),
            "fetched hedged wallet RPC log block timestamps"
        );

        let block_hash_started = Instant::now();
        let to_block_hash = match wait_or_cancel(
            cancel,
            self.chain
                .fetch_block_hash(&rpc.provider, self.archive_provider.as_ref(), to_block),
        )
        .await?
        {
            Ok(hash) => hash,
            Err(err) => {
                warn!(
                    ?err,
                    to_block, "failed to fetch hedged wallet RPC block hash"
                );
                None
            }
        };
        debug!(
            to_block,
            elapsed_ms = block_hash_started.elapsed().as_millis(),
            "fetched hedged wallet RPC block hash"
        );

        let batch = Arc::new(LogBatch {
            from_block,
            to_block,
            logs,
            block_timestamps,
            to_block_hash,
        });
        debug!(
            from_block,
            to_block,
            elapsed_ms = started.elapsed().as_millis(),
            "hedged wallet RPC backfill candidate complete"
        );
        Ok(vec![WalletScanApply::logs(
            from_block,
            to_block,
            batch,
            self.current_public_data_epoch(),
        )])
    }

    async fn probe_squid_indexed_wallet_source(
        &self,
        cfg: &WalletConfig,
    ) -> Option<(QuickSyncClient, u64)> {
        let Some(endpoint) = self.chain.quick_sync_endpoint.clone() else {
            debug!(cache_key = %cfg.cache_key, "no indexed endpoint configured; using RPC wallet backfill");
            return None;
        };
        let client = match self.chain.http_client.clone() {
            Some(http_client) => QuickSyncClient::with_http_client(endpoint, http_client),
            None => QuickSyncClient::new(endpoint),
        };
        let probe_started = Instant::now();
        let probe = match client.probe_indexed_wallet_support().await {
            Ok(probe) => probe,
            Err(err) => {
                warn!(
                    ?err,
                    cache_key = %cfg.cache_key,
                    "indexed wallet probe failed; using RPC backfill"
                );
                return None;
            }
        };
        debug!(
            cache_key = %cfg.cache_key,
            elapsed_ms = probe_started.elapsed().as_millis(),
            "indexed wallet probe complete"
        );
        Some((client, probe.height))
    }

    async fn probe_squid_tail_after_artifact(
        &self,
        cfg: &WalletConfig,
        from_block: u64,
        artifact_target: u64,
        safe_head: u64,
    ) -> Option<(QuickSyncClient, u64, u64)> {
        if artifact_target >= safe_head {
            return None;
        }
        let (client, height) = self.probe_squid_indexed_wallet_source(cfg).await?;
        let target =
            squid_tail_target_after_artifact(from_block, artifact_target, safe_head, height)?;
        Some((client, height, target))
    }

    async fn prepare_indexed_wallet_artifact_session(
        &self,
        cfg: &WalletConfig,
        from_block: u64,
        safe_head: u64,
        progress_tx: Option<&SyncProgressSender>,
    ) -> Option<IndexedWalletArtifactSession> {
        if self.chain.indexed_artifact_source.is_none() {
            return None;
        }
        let artifact_session_started = Instant::now();
        match IndexedWalletArtifactSession::prepare(&self.chain, from_block, safe_head, progress_tx)
            .await
        {
            Ok(Some(session)) => {
                debug!(
                    cache_key = %cfg.cache_key,
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
                debug!(
                    cache_key = %cfg.cache_key,
                    from_block,
                    safe_head,
                    elapsed_ms = artifact_session_started.elapsed().as_millis(),
                    "indexed wallet artifact session unavailable"
                );
                None
            }
            Err(err) => {
                warn!(
                    ?err,
                    cache_key = %cfg.cache_key,
                    from_block,
                    safe_head,
                    elapsed_ms = artifact_session_started.elapsed().as_millis(),
                    "indexed wallet artifact session failed; falling back to configured indexed sources"
                );
                None
            }
        }
    }

    pub async fn unregister_wallet(&self, cache_key: &str) {
        let registration = {
            let mut wallets = self.wallets.write().await;
            let Some(registration) = wallets.get(cache_key) else {
                return;
            };
            registration.cancel.cancel();
            registration.handle.retire_actor().await;
            wallets.remove(cache_key)
        };
        if registration.is_some() {
            if self
                .backfill_tx
                .send(BackfillRequest::Remove {
                    cache_key: cache_key.to_string(),
                })
                .await
                .is_err()
            {
                warn!(cache_key = %cache_key, "failed to remove backfill cursor");
            }
        }
    }

    pub async fn shutdown(&self) {
        self.cancel.cancel();
        await_live_log_task_shutdown(&self.live_log_task, self.chain.chain_id).await;
    }

    pub(super) async fn indexed_wallet_catch_up(
        &self,
        cfg: &WalletConfig,
        start_block: u64,
        last_scanned: u64,
        safe_head: u64,
        handle: &WalletHandle,
        cancel: &CancellationToken,
        source_order: IndexedWalletCatchUpSourceOrder,
        expose_status: bool,
        queued_sender: (&mpsc::Sender<BackfillEvent>, u64),
    ) -> u64 {
        if safe_head == 0 {
            debug!(cache_key = %cfg.cache_key, "safe head unavailable; skipping indexed wallet catch-up");
            return last_scanned;
        }
        let from_block = last_scanned.saturating_add(1).max(start_block);
        let progress_tx = cfg
            .progress_tx
            .clone()
            .or_else(|| self.chain.progress_tx.clone());
        let Some(status_guard) = WalletIndexedCatchUpStatusGuard::claim(handle, expose_status)
        else {
            debug!(cache_key = %cfg.cache_key, "indexed wallet catch-up already active");
            return last_scanned;
        };
        let mut artifact_session =
            if source_order == IndexedWalletCatchUpSourceOrder::ArtifactsFirst {
                self.prepare_indexed_wallet_artifact_session(
                    cfg,
                    from_block,
                    safe_head,
                    progress_tx.as_ref(),
                )
                .await
            } else {
                None
            };
        let catch_up_started = Instant::now();
        let mut squid_client = None;
        let (mut indexed_source, mut indexed_height, mut target, mut using_artifact) =
            if source_order == IndexedWalletCatchUpSourceOrder::SquidFirst {
                if let Some((client, height)) = self.probe_squid_indexed_wallet_source(cfg).await {
                    let target = height.min(safe_head);
                    if from_block <= target {
                        squid_client = Some(client);
                        (WalletIndexedCatchUpSource::Squid, height, target, false)
                    } else {
                        status_guard.set(
                            WalletIndexedCatchUpSource::IndexedArtifacts,
                            from_block,
                            safe_head,
                        );
                        artifact_session = self
                            .prepare_indexed_wallet_artifact_session(
                                cfg,
                                from_block,
                                safe_head,
                                progress_tx.as_ref(),
                            )
                            .await;
                        let Some(session) = artifact_session.as_ref() else {
                            return last_scanned;
                        };
                        (
                            WalletIndexedCatchUpSource::IndexedArtifacts,
                            session.latest_indexed_block(),
                            session.probe().catch_up_target(safe_head),
                            true,
                        )
                    }
                } else {
                    status_guard.set(
                        WalletIndexedCatchUpSource::IndexedArtifacts,
                        from_block,
                        safe_head,
                    );
                    artifact_session = self
                        .prepare_indexed_wallet_artifact_session(
                            cfg,
                            from_block,
                            safe_head,
                            progress_tx.as_ref(),
                        )
                        .await;
                    let Some(session) = artifact_session.as_ref() else {
                        return last_scanned;
                    };
                    (
                        WalletIndexedCatchUpSource::IndexedArtifacts,
                        session.latest_indexed_block(),
                        session.probe().catch_up_target(safe_head),
                        true,
                    )
                }
            } else if let Some(session) = artifact_session.as_ref() {
                (
                    WalletIndexedCatchUpSource::IndexedArtifacts,
                    session.latest_indexed_block(),
                    session.probe().catch_up_target(safe_head),
                    true,
                )
            } else {
                let Some((client, height)) = self.probe_squid_indexed_wallet_source(cfg).await
                else {
                    return last_scanned;
                };
                squid_client = Some(client);
                (
                    WalletIndexedCatchUpSource::Squid,
                    height,
                    height.min(safe_head),
                    false,
                )
            };
        let mut from_block = from_block;
        let progress_start = from_block;
        status_guard.set(indexed_source, from_block, target);
        info!(
            cache_key = %cfg.cache_key,
            indexed_source = indexed_source.as_str(),
            indexed_height,
            safe_head,
            from_block,
            target,
            indexed_block_range = self.chain.indexed_wallet_block_range,
            "indexed wallet catch-up target"
        );
        if from_block > target {
            let squid_tail = if using_artifact {
                self.probe_squid_tail_after_artifact(cfg, from_block, target, safe_head)
                    .await
            } else {
                None
            };
            if let Some((client, height, squid_target)) = squid_tail {
                let artifact_target = target;
                squid_client = Some(client);
                artifact_session = None;
                using_artifact = false;
                indexed_source = WalletIndexedCatchUpSource::Squid;
                indexed_height = height;
                target = squid_target;
                status_guard.set(indexed_source, from_block, target);
                info!(
                    cache_key = %cfg.cache_key,
                    indexed_source = indexed_source.as_str(),
                    indexed_height,
                    safe_head,
                    from_block,
                    artifact_target,
                    target,
                    indexed_block_range = self.chain.indexed_wallet_block_range,
                    "indexed wallet artifact tail target"
                );
            } else {
                debug!(
                    cache_key = %cfg.cache_key,
                    elapsed_ms = catch_up_started.elapsed().as_millis(),
                    "indexed wallet catch-up skipped; cache already at target"
                );
                return last_scanned;
            }
        }
        send_sync_progress(
            progress_tx.as_ref(),
            SyncProgressUpdate::new(
                SyncProgressStage::IndexingUtxos,
                progress_start,
                progress_start,
                target,
            ),
        );

        let mut checkpoint = last_scanned;
        loop {
            if from_block > target {
                let squid_tail = if using_artifact {
                    self.probe_squid_tail_after_artifact(cfg, from_block, target, safe_head)
                        .await
                } else {
                    None
                };
                let Some((client, height, squid_target)) = squid_tail else {
                    break;
                };
                let artifact_target = target;
                squid_client = Some(client);
                artifact_session = None;
                using_artifact = false;
                indexed_source = WalletIndexedCatchUpSource::Squid;
                indexed_height = height;
                target = squid_target;
                status_guard.set(indexed_source, from_block, target);
                info!(
                    cache_key = %cfg.cache_key,
                    indexed_source = indexed_source.as_str(),
                    indexed_height,
                    safe_head,
                    from_block,
                    artifact_target,
                    target,
                    indexed_block_range = self.chain.indexed_wallet_block_range,
                    "indexed wallet artifact tail target"
                );
                send_sync_progress(
                    progress_tx.as_ref(),
                    SyncProgressUpdate::new(
                        SyncProgressStage::IndexingUtxos,
                        progress_start,
                        from_block,
                        target,
                    ),
                );
                continue;
            }
            if cancel.is_cancelled() {
                return checkpoint;
            }
            let page_started = Instant::now();
            let page_kind =
                IndexedWalletPageKind::for_from_block(from_block, self.chain.v2_start_block);
            let to_block = page_kind.to_block(
                from_block,
                target,
                self.chain.v2_start_block,
                self.chain.indexed_wallet_block_range,
            );
            let fetch_started = Instant::now();
            let page_result = if using_artifact {
                match artifact_session
                    .as_ref()
                    .expect("artifact session is configured for artifact catch-up")
                    .page_for_block_range(from_block, to_block)
                {
                    Ok(outcome) => Ok(outcome),
                    Err(err) => Err(err),
                }
            } else {
                IndexedWalletPage::fetch(
                    squid_client
                        .as_ref()
                        .expect("squid client is configured for squid catch-up"),
                    page_kind,
                    from_block,
                    to_block,
                )
                .await
                .map(IndexedWalletArtifactPageOutcome::Page)
            };
            let page = match page_result {
                Ok(IndexedWalletArtifactPageOutcome::Page(page)) => page,
                Ok(IndexedWalletArtifactPageOutcome::Exhausted { checkpoint_block }) => {
                    checkpoint = checkpoint.max(checkpoint_block);
                    from_block = checkpoint.saturating_add(1);
                    target = checkpoint;
                    debug!(
                        cache_key = %cfg.cache_key,
                        checkpoint,
                        from_block,
                        safe_head,
                        elapsed_ms = page_started.elapsed().as_millis(),
                        "indexed wallet artifact source exhausted at checkpoint"
                    );
                    continue;
                }
                Err(err) => {
                    if artifact_failure_can_fallback_to_squid(
                        using_artifact,
                        checkpoint,
                        last_scanned,
                    ) {
                        warn!(
                            ?err,
                            cache_key = %cfg.cache_key,
                            fallback_from = checkpoint,
                            "indexed wallet artifact page failed before checkpoint; falling back to Squid"
                        );
                        let Some((client, height)) =
                            self.probe_squid_indexed_wallet_source(cfg).await
                        else {
                            return checkpoint;
                        };
                        squid_client = Some(client);
                        artifact_session = None;
                        using_artifact = false;
                        indexed_source = WalletIndexedCatchUpSource::Squid;
                        indexed_height = height;
                        target = height.min(safe_head);
                        status_guard.set(indexed_source, from_block, target);
                        info!(
                            cache_key = %cfg.cache_key,
                            indexed_source = indexed_source.as_str(),
                            indexed_height,
                            safe_head,
                            from_block,
                            target,
                            indexed_block_range = self.chain.indexed_wallet_block_range,
                            "indexed wallet fallback target"
                        );
                        if from_block > target {
                            debug!(
                                cache_key = %cfg.cache_key,
                                indexed_source = indexed_source.as_str(),
                                indexed_height,
                                target,
                                elapsed_ms = catch_up_started.elapsed().as_millis(),
                                "indexed wallet fallback skipped; cache already at target"
                            );
                            return checkpoint;
                        }
                        send_sync_progress(
                            progress_tx.as_ref(),
                            SyncProgressUpdate::new(
                                SyncProgressStage::IndexingUtxos,
                                progress_start,
                                from_block,
                                target,
                            ),
                        );
                        continue;
                    }
                    if !using_artifact
                        && source_order == IndexedWalletCatchUpSourceOrder::SquidFirst
                        && checkpoint == last_scanned
                    {
                        warn!(
                            ?err,
                            cache_key = %cfg.cache_key,
                            fallback_from = checkpoint,
                            "indexed wallet Squid page failed before checkpoint; falling back to artifacts"
                        );
                        status_guard.set(
                            WalletIndexedCatchUpSource::IndexedArtifacts,
                            from_block,
                            safe_head,
                        );
                        artifact_session = self
                            .prepare_indexed_wallet_artifact_session(
                                cfg,
                                from_block,
                                safe_head,
                                progress_tx.as_ref(),
                            )
                            .await;
                        let Some(session) = artifact_session.as_ref() else {
                            return checkpoint;
                        };
                        using_artifact = true;
                        indexed_source = WalletIndexedCatchUpSource::IndexedArtifacts;
                        indexed_height = session.latest_indexed_block();
                        target = session.probe().catch_up_target(safe_head);
                        status_guard.set(indexed_source, from_block, target);
                        info!(
                            cache_key = %cfg.cache_key,
                            indexed_source = indexed_source.as_str(),
                            indexed_height,
                            safe_head,
                            from_block,
                            target,
                            indexed_block_range = self.chain.indexed_wallet_block_range,
                            "indexed wallet fallback target"
                        );
                        if from_block > target {
                            debug!(
                                cache_key = %cfg.cache_key,
                                indexed_source = indexed_source.as_str(),
                                indexed_height,
                                target,
                                elapsed_ms = catch_up_started.elapsed().as_millis(),
                                "indexed wallet fallback skipped; cache already at target"
                            );
                            return checkpoint;
                        }
                        send_sync_progress(
                            progress_tx.as_ref(),
                            SyncProgressUpdate::new(
                                SyncProgressStage::IndexingUtxos,
                                progress_start,
                                from_block,
                                target,
                            ),
                        );
                        continue;
                    }
                    warn!(
                        ?err,
                        cache_key = %cfg.cache_key,
                        indexed_source = indexed_source.as_str(),
                        fallback_from = checkpoint,
                        "indexed wallet catch-up page failed; using RPC backfill"
                    );
                    return checkpoint;
                }
            };
            let fetch_elapsed_ms = fetch_started.elapsed().as_millis();
            if cancel.is_cancelled() {
                return checkpoint;
            }
            let parse_started = Instant::now();
            let row_count = page.transact_commitments.len()
                + page.shield_commitments.len()
                + page.legacy_encrypted_commitments.len()
                + page.legacy_generated_commitments.len()
                + page.nullifiers.len();
            let transact_rows = page.transact_rows;
            let shield_rows = page.shield_rows;
            let legacy_encrypted_rows = page.legacy_encrypted_rows;
            let legacy_generated_rows = page.legacy_generated_rows;
            let nullifier_rows = page.nullifier_rows;
            let parse_elapsed_ms = parse_started.elapsed().as_millis();
            let page_checkpoint = page.checkpoint_block;
            let (sender, reset_generation) = queued_sender;
            let apply_result = send_wallet_scan_apply(
                &cfg.cache_key,
                sender,
                WalletScanApply::indexed_rows(
                    from_block,
                    page_checkpoint,
                    page.into_scan_rows(indexed_source),
                    self.current_public_data_epoch(),
                    indexed_source,
                ),
                reset_generation,
            )
            .await;
            let Some(committed_checkpoint) = apply_result.accepted_committed_to() else {
                warn!(
                    ?apply_result,
                    cache_key = %cfg.cache_key,
                    from_block,
                    to_block = page_checkpoint,
                    "indexed wallet delta was not committed; using RPC backfill from committed cursor"
                );
                return checkpoint;
            };
            checkpoint = committed_checkpoint;
            debug!(
                cache_key = %cfg.cache_key,
                indexed_source = indexed_source.as_str(),
                page_kind = page_kind.as_str(),
                from_block,
                to_block,
                checkpoint,
                reset_generation,
                transact_rows,
                shield_rows,
                legacy_encrypted_rows,
                legacy_generated_rows,
                nullifier_rows,
                row_count,
                fetch_elapsed_ms,
                parse_elapsed_ms,
                elapsed_ms = page_started.elapsed().as_millis(),
                "indexed wallet catch-up page committed"
            );
            from_block = checkpoint.saturating_add(1);
            if from_block <= target {
                status_guard.set(indexed_source, from_block, target);
            }
            send_sync_progress(
                progress_tx.as_ref(),
                SyncProgressUpdate::new(
                    SyncProgressStage::IndexingUtxos,
                    progress_start,
                    checkpoint,
                    target,
                ),
            );
        }
        info!(
            cache_key = %cfg.cache_key,
            checkpoint,
            target,
            elapsed_ms = catch_up_started.elapsed().as_millis(),
            "indexed wallet catch-up complete"
        );
        send_sync_progress(
            progress_tx.as_ref(),
            SyncProgressUpdate::new(
                SyncProgressStage::IndexingUtxos,
                progress_start,
                target,
                target,
            ),
        );
        checkpoint
    }
}

pub(super) async fn await_live_log_task_shutdown(
    live_log_task: &Mutex<Option<JoinHandle<()>>>,
    chain_id: u64,
) {
    let live_log_task = live_log_task.lock().await.take();
    if let Some(task) = live_log_task
        && let Err(err) = task.await
        && !err.is_cancelled()
    {
        warn!(?err, chain_id, "live log worker failed during shutdown");
    }
}

pub(super) async fn wait_for_wallet_ready(
    mut readiness_rx: watch::Receiver<WalletReadiness>,
    cancel: CancellationToken,
) -> bool {
    loop {
        match &*readiness_rx.borrow() {
            WalletReadiness::Ready => return !cancel.is_cancelled(),
            WalletReadiness::Failed(_) | WalletReadiness::Shutdown => return false,
            WalletReadiness::Syncing => {}
        }
        tokio::select! {
            _ = cancel.cancelled() => return false,
            changed = readiness_rx.changed() => {
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
            _ = cancel.cancelled() => return None,
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
    let attempts = rpcs.len().max(3);
    for attempt in 0..attempts {
        let Some(rpc) = rpcs.random_provider() else {
            warn!(
                attempt,
                "no healthy rpc providers available for initial block number"
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
            continue;
        };
        match rpc.provider.get_block_number().await {
            Ok(head) => {
                let safe_head = head
                    .saturating_sub(chain.finality_depth)
                    .max(chain.deployment_block);
                return Some((rpc, head, safe_head));
            }
            Err(err) => {
                warn!(
                    ?err,
                    attempt,
                    rpc = rpc.url.as_str(),
                    "failed to fetch initial block number, retrying..."
                );
                rpcs.mark_bad_provider(&rpc);
                if attempt + 1 < attempts {
                    let backoff_power = match attempt {
                        0 => 0,
                        1 => 1,
                        _ => 2,
                    };
                    tokio::time::sleep(Duration::from_millis(500 * 2u64.pow(backoff_power))).await;
                }
            }
        }
    }
    None
}
