use super::*;

const INDEXED_TAIL_FALLBACK_MIN_STALL: Duration = Duration::from_secs(15);
const INDEXED_TAIL_FALLBACK_COOLDOWN: Duration = Duration::from_secs(60);

pub(super) fn spawn_head_poller(service: Arc<ChainService>, rpcs: Arc<QueryRpcPool>) {
    let cancel = service.cancel.clone();
    let chain_id = service.chain.chain_id;
    tokio::spawn(
        async move {
            loop {
                // Poll first, then sleep.  This ensures the very first poll
                // happens immediately instead of after a full poll_interval
                // delay, which is critical for fast safe_head availability.
                let Some(rpc) = rpcs.random_provider() else {
                    warn!("no healthy rpc providers available");
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = tokio::time::sleep(service.chain.poll_interval) => { continue; }
                    }
                };
                match rpc.provider.get_block_number().await {
                    Ok(head) => {
                        let safe_head = head
                            .saturating_sub(service.chain.finality_depth)
                            .max(service.chain.deployment_block);
                        if service.head_tx.receiver_count() > 0 {
                            let _ = service.head_tx.send(head);
                        }
                        if let Err(err) = service.safe_head_tx.send(safe_head) {
                            debug!(?err, safe_head, "failed to send safe head update");
                        }
                    }
                    Err(err) => {
                        warn!(?err, "failed to fetch latest block");
                        rpcs.mark_bad_provider(&rpc);
                    }
                }
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = tokio::time::sleep(service.chain.poll_interval) => {}
                }
            }
        }
        .instrument(tracing::info_span!("sync_head", chain_id)),
    );
}

pub(super) fn spawn_pending_tip_loop(
    service: Arc<ChainService>,
    rpcs: Arc<QueryRpcPool>,
    archive_provider: Option<DynProvider>,
    mut head_rx: watch::Receiver<u64>,
    mut safe_head_rx: watch::Receiver<u64>,
    cancel: CancellationToken,
) {
    let chain_id = service.chain.chain_id;
    tokio::spawn(
        async move {
            loop {
                let safe_head = *safe_head_rx.borrow();
                let head = *head_rx.borrow();
                refresh_pending_tip_overlays(
                    &service,
                    &rpcs,
                    archive_provider.as_ref(),
                    safe_head,
                    head,
                )
                .await;

                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = head_rx.changed() => {},
                    _ = safe_head_rx.changed() => {},
                    _ = tokio::time::sleep(service.chain.poll_interval) => {},
                }
            }
        }
        .instrument(tracing::info_span!("pending_tip", chain_id)),
    );
}

pub(super) async fn refresh_pending_tip_overlays(
    service: &Arc<ChainService>,
    rpcs: &Arc<QueryRpcPool>,
    archive_provider: Option<&DynProvider>,
    safe_head: u64,
    head: u64,
) {
    let registrations = {
        let wallets = service.wallets.read().await;
        wallets
            .iter()
            .map(|(cache_key, registration)| {
                let handle = registration.handle.clone();
                let from_block = pending_tip_from_block(
                    safe_head,
                    handle.last_scanned(),
                    service.chain.block_range,
                );
                let target_block = registration
                    .sync_to_block
                    .map_or(head, |limit| limit.min(head));
                PendingTipWalletRegistration {
                    cache_key: cache_key.clone(),
                    cfg: registration.cfg.clone(),
                    handle,
                    from_block,
                    target_block,
                }
            })
            .collect::<Vec<_>>()
    };
    if registrations.is_empty() {
        return;
    }

    let Some(fetch_to_block) = registrations
        .iter()
        .filter(|registration| registration.target_block >= registration.from_block)
        .map(|registration| registration.target_block)
        .max()
    else {
        clear_pending_tip_overlays(registrations).await;
        return;
    };

    let Some(rpc) = rpcs.random_provider() else {
        warn!(
            safe_head,
            head, "no healthy rpc providers available for pending wallet tip"
        );
        return;
    };

    let provider_head = match rpc.provider.get_block_number().await {
        Ok(provider_head) => provider_head,
        Err(err) => {
            warn!(
                ?err,
                rpc = rpc.url.as_str(),
                "failed to fetch pending wallet tip provider head"
            );
            rpcs.mark_bad_provider(&rpc);
            return;
        }
    };
    if !pending_tip_provider_covers_target(provider_head, fetch_to_block) {
        debug!(
            rpc = rpc.url.as_str(),
            provider_head,
            fetch_to_block,
            "pending wallet tip provider is behind; preserving existing overlay"
        );
        return;
    }

    let from_block = registrations
        .iter()
        .filter(|registration| registration.target_block >= registration.from_block)
        .map(|registration| registration.from_block)
        .min()
        .unwrap_or(fetch_to_block);
    let mut logs = match service
        .chain
        .fetch_logs_for_range(&rpc.provider, archive_provider, from_block, fetch_to_block)
        .await
    {
        Ok(logs) => logs,
        Err(err) => {
            warn!(
                ?err,
                from_block,
                to_block = fetch_to_block,
                "failed to fetch pending wallet tip logs"
            );
            if err.should_mark_rpc_unhealthy() && !err.is_block_range_beyond_current_head() {
                rpcs.mark_bad_provider(&rpc);
            }
            return;
        }
    };
    sort_logs(&mut logs);

    let block_timestamps = match service
        .chain
        .fetch_log_block_timestamps(&rpc.provider, archive_provider, &logs)
        .await
    {
        Ok(block_timestamps) => block_timestamps,
        Err(err) => {
            warn!(
                ?err,
                from_block,
                to_block = fetch_to_block,
                "failed to fetch pending wallet tip timestamps"
            );
            if err.should_mark_rpc_unhealthy() {
                rpcs.mark_bad_provider(&rpc);
            }
            return;
        }
    };

    for registration in registrations {
        if registration.target_block < registration.from_block {
            registration
                .handle
                .set_chain_pending_overlay(WalletPendingOverlay::default())
                .await;
            continue;
        }

        let wallet_logs = logs
            .iter()
            .filter(|log| {
                log.block_number.is_some_and(|block| {
                    block >= registration.from_block && block <= registration.target_block
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        let delta = if wallet_logs.is_empty() {
            WalletLogDelta {
                utxos: Vec::new(),
                nullifiers: Vec::new(),
                commitment_observations: Vec::new(),
            }
        } else {
            match parse_wallet_delta_from_logs(
                &wallet_logs,
                &block_timestamps,
                &registration.cfg.scan_keys,
            ) {
                Ok(delta) => delta,
                Err(err) => {
                    warn!(?err, cache_key = %registration.cache_key, from_block = registration.from_block, to_block = registration.target_block, "failed to parse pending wallet tip logs");
                    continue;
                }
            }
        };

        let confirmed = registration.handle.utxos.read().await;
        let overlay = pending_overlay_from_delta(&registration.cfg, &confirmed, delta);
        drop(confirmed);
        registration.handle.set_chain_pending_overlay(overlay).await;
    }
}

pub(super) async fn clear_pending_tip_overlays(registrations: Vec<PendingTipWalletRegistration>) {
    for registration in registrations {
        registration
            .handle
            .set_chain_pending_overlay(WalletPendingOverlay::default())
            .await;
    }
}

struct WalletLagFallbackCandidate {
    cache_key: String,
    from_block: u64,
    target_block: u64,
    lag_blocks: u64,
    sender: mpsc::Sender<BackfillEvent>,
}

pub(super) fn spawn_wallet_lag_fallback_loop(
    service: Arc<ChainService>,
    mut safe_head_rx: watch::Receiver<u64>,
    cancel: CancellationToken,
) {
    let chain_id = service.chain.chain_id;
    tokio::spawn(
        async move {
            let mut states: HashMap<String, WalletTailFallbackState> = HashMap::new();
            loop {
                let safe_head = *safe_head_rx.borrow();
                if safe_head > 0 {
                    let now = Instant::now();
                    let candidates =
                        wallet_lag_fallback_candidates(&service, &mut states, safe_head, now).await;

                    for candidate in candidates {
                        info!(
                            cache_key = %candidate.cache_key,
                            from_block = candidate.from_block,
                            target_block = candidate.target_block,
                            lag_blocks = candidate.lag_blocks,
                            stalled_secs = INDEXED_TAIL_FALLBACK_MIN_STALL.as_secs(),
                            "indexed wallet ready-tail fallback triggered"
                        );
                        let Some((checkpoint, reset_generation)) = service
                            .try_indexed_wallet_tail_catch_up(
                                &candidate.cache_key,
                                candidate.from_block,
                                candidate.target_block,
                                &candidate.sender,
                            )
                            .await
                        else {
                            debug!(
                                cache_key = %candidate.cache_key,
                                from_block = candidate.from_block,
                                target_block = candidate.target_block,
                                "indexed wallet ready-tail fallback unavailable"
                            );
                            continue;
                        };
                        if checkpoint < candidate.from_block {
                            continue;
                        }
                        if let Err(err) = candidate
                            .sender
                            .send(BackfillEvent::DoneAtGeneration {
                                last_block: checkpoint,
                                reset_generation,
                            })
                            .await
                        {
                            debug!(
                                ?err,
                                cache_key = %candidate.cache_key,
                                "failed to send ready-tail indexed wallet done"
                            );
                        }
                    }
                }

                tokio::select! {
                    _ = cancel.cancelled() => break,
                    changed = safe_head_rx.changed() => {
                        if changed.is_err() {
                            break;
                        }
                    }
                    _ = tokio::time::sleep(service.chain.poll_interval) => {}
                }
            }
        }
        .instrument(tracing::info_span!("wallet_lag_fallback", chain_id)),
    );
}

async fn wallet_lag_fallback_candidates(
    service: &Arc<ChainService>,
    states: &mut HashMap<String, WalletTailFallbackState>,
    safe_head: u64,
    now: Instant,
) -> Vec<WalletLagFallbackCandidate> {
    let wallets = service.wallets.read().await;
    states.retain(|cache_key, _| wallets.contains_key(cache_key));

    wallets
        .iter()
        .filter_map(|(cache_key, registration)| {
            if !registration.cfg.use_indexed_wallet_catch_up
                || !*registration.handle.ready_rx.borrow()
                || registration.handle.indexed_catch_up_rx.borrow().is_some()
            {
                return None;
            }

            let last_scanned = registration.handle.last_scanned();
            let target_block = wallet_sync_target(safe_head, registration.sync_to_block);
            let from_block = wallet_backfill_from_block(last_scanned, registration.start_block);
            let state = states
                .entry(cache_key.clone())
                .or_insert_with(|| WalletTailFallbackState::new(last_scanned, now));
            state.update_last_scanned(last_scanned, now);

            if !state.should_try_indexed_tail_fallback(
                service.chain.chain_id,
                from_block,
                target_block,
                now,
                INDEXED_TAIL_FALLBACK_MIN_STALL,
                INDEXED_TAIL_FALLBACK_COOLDOWN,
            ) {
                return None;
            }
            let lag_blocks = wallet_backfill_lag_blocks(from_block, target_block);
            state.mark_indexed_tail_attempt(now);
            Some(WalletLagFallbackCandidate {
                cache_key: cache_key.clone(),
                from_block,
                target_block,
                lag_blocks,
                sender: registration.backfill_sender.clone(),
            })
        })
        .collect()
}

pub(super) fn pending_tip_from_block(
    safe_head: u64,
    wallet_last_scanned: u64,
    sticky_block_range: u64,
) -> u64 {
    if wallet_last_scanned < safe_head
        && safe_head.saturating_sub(wallet_last_scanned) <= sticky_block_range
    {
        wallet_last_scanned.saturating_add(1)
    } else {
        safe_head.saturating_add(1)
    }
}

pub(super) const fn pending_tip_provider_covers_target(
    provider_head: u64,
    target_block: u64,
) -> bool {
    provider_head >= target_block
}

pub(super) fn spawn_txid_public_cache_loop(service: Arc<ChainService>, cancel: CancellationToken) {
    let endpoint = service.chain.quick_sync_endpoint.clone();
    let indexed_artifact_source = service.chain.indexed_artifact_source.clone();
    if endpoint.is_none() && indexed_artifact_source.is_none() {
        return;
    }
    let chain_id = service.chain.chain_id;
    let railgun_contract = service.chain.contract.to_string();
    let http_client = service.chain.http_client.clone();
    let db = service.db.clone();
    tokio::spawn(
        async move {
            loop {
                let key = TxidPublicCacheKey {
                    chain_type: EVM_CHAIN_TYPE,
                    chain_id,
                    txid_version: DEFAULT_TXID_VERSION,
                };
                let cache = TxidPublicCache::new(&db, key);
                if let Err(err) = cache
                    .sync_to_indexed_tip(
                        endpoint.as_ref(),
                        http_client.as_ref(),
                        &railgun_contract,
                        indexed_artifact_source.as_ref(),
                    )
                    .await
                {
                    warn!(?err, chain_id, "TXID public cache background sync failed");
                }
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = tokio::time::sleep(TXID_PUBLIC_CACHE_SYNC_INTERVAL) => {}
                }
            }
        }
        .instrument(tracing::info_span!("txid_public_cache", chain_id)),
    );
}

pub(super) fn spawn_live_log_loop(
    service: Arc<ChainService>,
    rpcs: Arc<QueryRpcPool>,
    archive_provider: Option<DynProvider>,
    mut forest_last_rx: watch::Receiver<u64>,
    mut safe_head_rx: watch::Receiver<u64>,
    snapshot_path: PathBuf,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(
        async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = safe_head_rx.changed() => {},
                    _ = forest_last_rx.changed() => {},
                }

                let safe_head = *safe_head_rx.borrow();
                if safe_head == 0 && service.chain.deployment_block > 0 {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = tokio::time::sleep(service.chain.poll_interval) => {}
                    }
                    continue;
                }
                let last_processed = *forest_last_rx.borrow();
                if last_processed >= safe_head {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = tokio::time::sleep(service.chain.poll_interval) => {}
                    }
                    continue;
                }
                let Some(rpc) = rpcs.random_provider() else {
                    warn!("no healthy rpc providers available");
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = tokio::time::sleep(service.chain.poll_interval) => {}
                    }
                    continue;
                };
                let reorg_check = tokio::select! {
                    _ = cancel.cancelled() => break,
                    result = service.check_forest_reorg(
                        &rpc.provider,
                        archive_provider.as_ref(),
                        rpc.url.as_str(),
                        &snapshot_path,
                        safe_head,
                        last_processed,
                    ) => result,
                };
                if let Err(err) = reorg_check {
                    debug!(?err, rpc = rpc.url.as_str(), "reorg check failed");
                }
                if cancel.is_cancelled() {
                    break;
                }
                let last_processed = *forest_last_rx.borrow();
                if last_processed >= safe_head {
                    continue;
                }

                let from_block = last_processed.saturating_add(1);
                let to_block = min(from_block + service.chain.block_range - 1, safe_head);
                let logs_result = tokio::select! {
                    _ = cancel.cancelled() => break,
                    result = service.chain.fetch_logs_for_range(
                        &rpc.provider,
                        archive_provider.as_ref(),
                        from_block,
                        to_block,
                    ) => result,
                };
                match logs_result {
                    Ok(mut logs) => {
                        sort_logs(&mut logs);
                        let block_timestamps = if service.live_log_tx.receiver_count() > 0 {
                            match tokio::select! {
                                _ = cancel.cancelled() => break,
                                result = service.chain.fetch_log_block_timestamps(
                                    &rpc.provider,
                                    archive_provider.as_ref(),
                                    &logs,
                                ) => result,
                            } {
                                Ok(block_timestamps) => block_timestamps,
                                Err(err) => {
                                    warn!(?err, "failed to fetch log block timestamps");
                                    if err.should_mark_rpc_unhealthy() {
                                        rpcs.mark_bad_provider(&rpc);
                                    }
                                    continue;
                                }
                            }
                        } else {
                            HashMap::new()
                        };
                        let to_block_hash = match tokio::select! {
                            _ = cancel.cancelled() => break,
                            result = service.chain.fetch_confirmed_block_hash(
                                &rpc.provider,
                                archive_provider.as_ref(),
                                to_block,
                            ) => result,
                        } {
                            Ok(hash) => hash,
                            Err(err) => {
                                warn!(?err, to_block, "failed to fetch confirmed block hash");
                                None
                            }
                        };
                        if cancel.is_cancelled() {
                            break;
                        }
                        let batch = Arc::new(LogBatch {
                            from_block,
                            to_block,
                            logs,
                            block_timestamps,
                            to_block_hash,
                        });

                        let batch_hash = batch.to_block_hash;
                        if cancel.is_cancelled() {
                            break;
                        }
                        if let Err(err) = service.apply_forest_updates(&batch).await {
                            warn!(?err, "failed to apply forest updates");
                        } else {
                            if cancel.is_cancelled() {
                                break;
                            }
                            let log_count = batch.logs.len();
                            if service.live_log_tx.send(batch).is_err() {
                                debug!(
                                    from_block,
                                    to_block, log_count, "failed to broadcast live log batch"
                                );
                            }
                            if let Err(err) = service.forest_last_tx.send(to_block) {
                                debug!(?err, to_block, "failed to send forest progress update");
                            }
                            if cancel.is_cancelled() {
                                break;
                            }
                            if let Err(err) = service
                                .persist_forest_snapshot(&snapshot_path, to_block, batch_hash)
                                .await
                            {
                                warn!(?err, "failed to persist forest snapshot");
                            }
                        }
                    }
                    Err(err) => {
                        if err.is_rpc_throttled() {
                            warn!(
                                rpc = rpc.url.as_str(),
                                "rpc is throttled, will retry with another..."
                            );
                        } else {
                            warn!(
                                ?err,
                                rpc = rpc.url.as_str(),
                                "failed to fetch logs, retrying..."
                            );
                        }
                        if err.should_mark_rpc_unhealthy() {
                            rpcs.mark_bad_provider(&rpc);
                        }
                    }
                }
            }
        }
        .instrument(tracing::info_span!("sync_live")),
    )
}

pub(super) fn spawn_backfill_loop(
    service: Arc<ChainService>,
    mut backfill_rx: mpsc::Receiver<BackfillRequest>,
    rpcs: Arc<QueryRpcPool>,
    archive_provider: Option<DynProvider>,
    mut safe_head_rx: watch::Receiver<u64>,
    cancel: CancellationToken,
) {
    let task = async move {
        let mut cursors: HashMap<String, WalletBackfill> = HashMap::new();
        loop {
            drain_pending_backfill_requests(&mut backfill_rx, &mut cursors);

            if cursors.is_empty() {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    Some(request) = backfill_rx.recv() => {
                        apply_backfill_request(&mut cursors, request, Instant::now());
                    }
                    _ = safe_head_rx.changed() => {},
                }
                // Re-enter the loop immediately so that pending requests in
                // backfill_rx are picked up without an unnecessary poll_interval
                // delay.
                continue;
            }

            let safe_head = *safe_head_rx.borrow();
            for cursor in cursors.values_mut() {
                cursor.refresh_target(safe_head);
                cursor.send_progress(cursor.from_block);
            }

            let done_keys: Vec<_> = cursors
                .iter()
                .filter(|(_, cursor)| {
                    cursor.target_block > 0 && cursor.from_block > cursor.target_block
                })
                .map(|(key, _)| key.clone())
                .collect();
            for key in done_keys {
                if let Some(cursor) = cursors.remove(&key)
                    && let Err(err) = cursor
                        .sender
                        .send(BackfillEvent::DoneAtGeneration {
                            last_block: cursor.target_block,
                            reset_generation: cursor.reset_generation,
                        })
                        .await
                {
                    debug!(?err, cache_key = %key, "failed to send backfill done");
                }
            }

            let now = Instant::now();
            let indexed_tail_attempts: Vec<_> = cursors
                .iter_mut()
                .filter_map(|(key, cursor)| {
                    if cursor.should_try_indexed_tail_fallback(
                        service.chain.chain_id,
                        now,
                        INDEXED_TAIL_FALLBACK_MIN_STALL,
                        INDEXED_TAIL_FALLBACK_COOLDOWN,
                    ) {
                        let lag_blocks =
                            wallet_backfill_lag_blocks(cursor.from_block, cursor.target_block);
                        cursor.mark_indexed_tail_attempt(now);
                        Some((
                            key.clone(),
                            cursor.from_block,
                            cursor.target_block,
                            lag_blocks,
                            cursor.sender.clone(),
                        ))
                    } else {
                        None
                    }
                })
                .collect();
            for (key, from_block, target_block, lag_blocks, sender) in indexed_tail_attempts {
                info!(
                    cache_key = %key,
                    from_block,
                    target_block,
                    lag_blocks,
                    stalled_secs = INDEXED_TAIL_FALLBACK_MIN_STALL.as_secs(),
                    "indexed wallet tail fallback triggered"
                );
                let Some((checkpoint, reset_generation)) = service
                    .try_indexed_wallet_tail_catch_up(&key, from_block, target_block, &sender)
                    .await
                else {
                    debug!(
                        cache_key = %key,
                        from_block,
                        target_block,
                        "indexed wallet tail fallback unavailable"
                    );
                    continue;
                };
                let latest_safe_head = *safe_head_rx.borrow();
                let mut completed_last_block = None;
                if let Some(cursor) = cursors.get_mut(&key)
                    && checkpoint >= cursor.from_block
                {
                    cursor.send_progress(checkpoint);
                    cursor.mark_progress(checkpoint.saturating_add(1), Instant::now());
                    cursor.refresh_target(latest_safe_head);
                    if cursor.from_block > cursor.target_block {
                        completed_last_block = Some(cursor.target_block);
                    }
                }
                if let Some(last_block) = completed_last_block
                    && let Some(cursor) = cursors.remove(&key)
                    && let Err(err) = cursor
                        .sender
                        .send(BackfillEvent::DoneAtGeneration {
                            last_block,
                            reset_generation,
                        })
                        .await
                {
                    debug!(?err, cache_key = %key, "failed to send backfill done");
                }
            }

            let min_from = cursors.values().map(|cursor| cursor.from_block).min();
            debug!(block=?min_from, "scanning wallet events");
            let Some(from_block) = min_from else {
                continue;
            };
            let Some(target_block) = cursors
                .values()
                .filter(|cursor| cursor.from_block == from_block)
                .map(|cursor| cursor.target_block)
                .filter(|target_block| *target_block > 0)
                .min()
            else {
                if safe_head == 0 {
                    // safe_head not yet available — the head poller hasn't
                    // successfully fetched a block number yet.  Wait for it
                    // instead of prematurely marking wallets as done.
                    debug!("safe_head is 0, waiting for head poller before backfill");
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = safe_head_rx.changed() => { continue; }
                    }
                }
                continue;
            };
            let Some(rpc) = rpcs.random_provider() else {
                warn!("no healthy rpc providers available");
                tokio::time::sleep(service.chain.poll_interval).await;
                continue;
            };
            let to_block = min(from_block + service.chain.block_range - 1, target_block);
            let fetch_logs_started = Instant::now();
            match service
                .chain
                .fetch_logs_for_range(
                    &rpc.provider,
                    archive_provider.as_ref(),
                    from_block,
                    to_block,
                )
                .await
            {
                Ok(mut logs) => {
                    debug!(
                        from_block,
                        to_block,
                        num_logs = logs.len(),
                        elapsed_ms = fetch_logs_started.elapsed().as_millis(),
                        "fetched backfill logs"
                    );
                    sort_logs(&mut logs);
                    let timestamps_started = Instant::now();
                    let block_timestamps = match service
                        .chain
                        .fetch_log_block_timestamps(&rpc.provider, archive_provider.as_ref(), &logs)
                        .await
                    {
                        Ok(block_timestamps) => block_timestamps,
                        Err(err) => {
                            warn!(?err, "failed to fetch backfill log block timestamps");
                            if err.should_mark_rpc_unhealthy() {
                                rpcs.mark_bad_provider(&rpc);
                            } else {
                                tokio::time::sleep(service.chain.poll_interval).await;
                            }
                            continue;
                        }
                    };
                    debug!(
                        from_block,
                        to_block,
                        num_logs = logs.len(),
                        elapsed_ms = timestamps_started.elapsed().as_millis(),
                        "fetched backfill log block timestamps"
                    );
                    let block_hash_started = Instant::now();
                    let to_block_hash = service
                        .chain
                        .fetch_block_hash(&rpc.provider, archive_provider.as_ref(), to_block)
                        .await
                        .unwrap_or_else(|err| {
                            warn!(?err, to_block, "failed to fetch backfill block hash");
                            None
                        });
                    debug!(
                        to_block,
                        elapsed_ms = block_hash_started.elapsed().as_millis(),
                        "fetched backfill block hash"
                    );
                    let batch = Arc::new(LogBatch {
                        from_block,
                        to_block,
                        logs,
                        block_timestamps,
                        to_block_hash,
                    });

                    let keys: Vec<String> = cursors.keys().cloned().collect();
                    let latest_safe_head = *safe_head_rx.borrow();
                    for key in keys {
                        if let Some(cursor) = cursors.get_mut(&key)
                            && cursor.from_block <= to_block
                        {
                            if let Err(err) = cursor
                                .sender
                                .send(BackfillEvent::LogsAtGeneration {
                                    batch: batch.clone(),
                                    reset_generation: cursor.reset_generation,
                                })
                                .await
                            {
                                debug!(
                                    ?err,
                                    cache_key = %key,
                                    "failed to send backfill logs"
                                );
                            }
                            cursor.send_progress(to_block);
                            cursor.mark_progress(to_block.saturating_add(1), Instant::now());
                            cursor.refresh_target(latest_safe_head);
                            if cursor.from_block > cursor.target_block {
                                if let Err(err) = cursor
                                    .sender
                                    .send(BackfillEvent::DoneAtGeneration {
                                        last_block: cursor.target_block,
                                        reset_generation: cursor.reset_generation,
                                    })
                                    .await
                                {
                                    debug!(
                                        ?err,
                                        cache_key = %key,
                                        "failed to send backfill done"
                                    );
                                }
                                cursors.remove(&key);
                            }
                        }
                    }
                }
                Err(err) => {
                    warn!(
                        ?err,
                        rpc = rpc.url.as_str(),
                        "failed to fetch backfill logs"
                    );
                    if err.should_mark_rpc_unhealthy() {
                        rpcs.mark_bad_provider(&rpc);
                    } else {
                        tokio::time::sleep(service.chain.poll_interval).await;
                    }
                }
            }
        }
    };
    tokio::spawn(task.instrument(tracing::info_span!("sync_backfill")));
}

pub(super) fn drain_pending_backfill_requests(
    backfill_rx: &mut mpsc::Receiver<BackfillRequest>,
    cursors: &mut HashMap<String, WalletBackfill>,
) {
    while let Ok(request) = backfill_rx.try_recv() {
        apply_backfill_request(cursors, request, Instant::now());
    }
}

fn apply_backfill_request(
    cursors: &mut HashMap<String, WalletBackfill>,
    request: BackfillRequest,
    now: Instant,
) {
    match request {
        BackfillRequest::Add {
            cache_key,
            from_block,
            to_block,
            follow_safe_head,
            progress_start_block,
            reset_generation,
            progress_tx,
            sender,
        } => {
            cursors.insert(
                cache_key,
                WalletBackfill::new(
                    from_block,
                    to_block,
                    follow_safe_head,
                    progress_start_block,
                    reset_generation,
                    progress_tx,
                    sender,
                    now,
                ),
            );
        }
        BackfillRequest::Reset {
            cache_key,
            from_block,
            reset_generation,
        } => {
            if let Some(cursor) = cursors.get_mut(&cache_key) {
                cursor.mark_progress(from_block, now);
                cursor.progress_start_block = from_block;
                cursor.reset_generation = reset_generation;
                cursor.last_indexed_tail_attempt_at = None;
            }
        }
        BackfillRequest::Remove { cache_key } => {
            cursors.remove(&cache_key);
        }
    }
}
