//! The pending-tip loop, which keeps wallet overlays for blocks above the safe head.

use crate::chain::{PendingTipWalletRegistration, WalletScanInputRows};

use super::{
    Arc, CancellationToken, ChainError, ChainService, DynProvider, Instrument, Provider,
    PublicScanSource, QueryRpcPool, WalletScanRows, WalletScanRowsPayload, debug, sort_logs, warn,
    watch,
};

pub(in crate::chain) fn spawn_pending_tip_loop(
    service: Arc<ChainService>,
    rpcs: Arc<QueryRpcPool>,
    archive_provider: Option<DynProvider>,
    head_rx: watch::Receiver<u64>,
    mut safe_head_rx: watch::Receiver<u64>,
    cancel: CancellationToken,
) {
    let chain_id = service.chain.deployment.chain_id;
    tokio::spawn(
        async move {
            loop {
                let safe_head = *safe_head_rx.borrow_and_update();
                let head = *head_rx.borrow();
                refresh_pending_tip_overlays(
                    &service,
                    &rpcs,
                    archive_provider.as_ref(),
                    safe_head,
                    head,
                    &cancel,
                )
                .await;

                tokio::select! {
                    () = cancel.cancelled() => break,
                    // The poller sends the head before the safe head on every poll, so the safe head alone wakes this loop.
                    _ = safe_head_rx.changed() => {},
                    () = tokio::time::sleep(service.chain.sync.poll_interval) => {},
                }
            }
        }
        .instrument(tracing::info_span!("pending_tip", chain_id)),
    );
}

pub(in crate::chain) async fn refresh_pending_tip_overlays(
    service: &Arc<ChainService>,
    rpcs: &Arc<QueryRpcPool>,
    archive_provider: Option<&DynProvider>,
    safe_head: u64,
    head: u64,
    cancel: &CancellationToken,
) {
    let registration = {
        let wallet = service.wallet.read().await;
        wallet.as_ref().and_then(|registration| {
            let cache_key = &registration.cfg.cache_key;
            let handle = registration.handle.clone();
            // One view snapshot: cursor + generation (never authority gen alone).
            let progress = handle.schedulable_progress()?;
            let from_block = pending_tip_from_block(
                safe_head,
                progress.last_scanned,
                service.chain.sync.block_range,
            );
            let target_block = registration
                .sync_to_block
                .map_or(head, |limit| limit.min(head));
            Some(PendingTipWalletRegistration {
                cache_key: cache_key.as_str().to_string(),
                handle,
                reset_generation: progress.reset_generation,
                last_scanned: progress.last_scanned,
                from_block,
                target_block,
            })
        })
    };
    let Some(registration) = registration else {
        return;
    };

    if registration.target_block < registration.from_block {
        clear_pending_tip_overlays(Some(registration)).await;
        return;
    }
    let fetch_to_block = registration.target_block;

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
                err = %ChainError::from(err).without_url(),
                rpc_index = rpc.index,
                "failed to fetch pending wallet tip provider head"
            );
            rpcs.mark_bad_provider(&rpc);
            return;
        }
    };
    if !pending_tip_provider_covers_target(provider_head, fetch_to_block) {
        debug!(
            rpc_index = rpc.index,
            provider_head,
            fetch_to_block,
            "pending wallet tip provider is behind; preserving existing overlay"
        );
        return;
    }

    let from_block = registration.from_block;
    let mut logs = match service
        .chain
        .fetch_logs_for_range(&rpc, archive_provider, from_block, fetch_to_block, cancel)
        .await
    {
        Ok(logs) => logs,
        Err(err) => {
            let mark_unhealthy =
                err.should_mark_rpc_unhealthy() && !err.is_block_range_beyond_current_head();
            warn!(
                err = %err.without_url(),
                rpc_index = rpc.index,
                from_block,
                to_block = fetch_to_block,
                "failed to fetch pending wallet tip logs"
            );
            if mark_unhealthy {
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
            let mark_unhealthy = err.should_mark_rpc_unhealthy();
            warn!(
                err = %err.without_url(),
                rpc_index = rpc.index,
                from_block,
                to_block = fetch_to_block,
                "failed to fetch pending wallet tip timestamps"
            );
            if mark_unhealthy {
                rpcs.mark_bad_provider(&rpc);
            }
            return;
        }
    };

    let wallet_logs = logs
        .iter()
        .filter(|log| {
            log.block_number.is_some_and(|block| {
                block >= registration.from_block && block <= registration.target_block
            })
        })
        .cloned()
        .collect::<Vec<_>>();
    let rows = match WalletScanInputRows::from_logs(&wallet_logs, &block_timestamps) {
        Ok(rows) => rows,
        Err(err) => {
            warn!(?err, cache_key = %registration.cache_key, from_block = registration.from_block, to_block = registration.target_block, "failed to normalize pending wallet tip logs");
            return;
        }
    };
    let rows = WalletScanRows::new(
        registration.from_block,
        registration.target_block,
        PublicScanSource::Rpc,
        None,
        WalletScanRowsPayload::Rows(Box::new(rows)),
    );
    if !registration
        .handle
        .request_pending_overlay_rows(
            rows,
            registration.reset_generation,
            registration.last_scanned,
        )
        .await
    {
        debug!(cache_key = %registration.cache_key, "failed to send pending overlay update request");
    }
}

pub(in crate::chain) async fn clear_pending_tip_overlays(
    registration: Option<PendingTipWalletRegistration>,
) {
    if let Some(registration) = registration
        && !registration
            .handle
            .request_pending_overlay_clear(registration.reset_generation, registration.last_scanned)
            .await
    {
        debug!(cache_key = %registration.cache_key, "failed to send pending overlay clear request");
    }
}

pub(in crate::chain) const fn pending_tip_from_block(
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

pub(in crate::chain) const fn pending_tip_provider_covers_target(
    provider_head: u64,
    target_block: u64,
) -> bool {
    provider_head >= target_block
}
