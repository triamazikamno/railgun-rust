//! The wallet lag fallback loop, which hands a lagging wallet to the indexed tail fallback.

use crate::chain::{
    BackfillEvent, WalletBackfillStartResult, WalletHandle, WalletIndexedTailFallbackResult,
    WalletReadinessError, WalletTailFallbackState, wallet_backfill_from_block, wallet_sync_target,
};

use super::{
    Arc, BackfillRequest, CancellationToken, ChainService, INDEXED_TAIL_FALLBACK_COOLDOWN,
    INDEXED_TAIL_FALLBACK_MIN_STALL, Instant, Instrument, await_wallet_cancellation, debug, info,
    mpsc, wallet_backfill_lag_blocks, wallet_finish_result_removes_cursor,
    wallet_finish_retry_request, warn, watch,
};

struct WalletLagFallbackCandidate {
    cache_key: String,
    /// Full public progress ticket that justified this range.
    progress: crate::types::WalletSchedulableProgress,
    start_block: u64,
    target_block: u64,
    lag_blocks: u64,
    follow_safe_head: bool,
    sender: mpsc::Sender<BackfillEvent>,
    handle: WalletHandle,
    cancel: CancellationToken,
}

pub(in crate::chain) fn spawn_wallet_lag_fallback_loop(
    service: Arc<ChainService>,
    mut safe_head_rx: watch::Receiver<u64>,
    cancel: CancellationToken,
) {
    let chain_id = service.chain.deployment.chain_id;
    tokio::spawn(
        async move {
            let mut state: Option<(String, u64, WalletTailFallbackState)> = None;
            loop {
                let safe_head = *safe_head_rx.borrow();
                if safe_head > 0 {
                    let now = Instant::now();
                    if let Some(candidate) =
                        wallet_lag_fallback_candidate(&service, &mut state, safe_head, now).await
                    {
                        // Revalidate the full ticket; never re-read generation alone.
                        let Some(progress) = candidate
                            .handle
                            .revalidate_schedulable_progress(candidate.progress)
                        else {
                            continue;
                        };
                        let from_block = wallet_backfill_from_block(
                            progress.last_scanned,
                            candidate.start_block,
                        );
                        info!(
                            cache_key = %candidate.cache_key,
                            from_block,
                            target_block = candidate.target_block,
                            lag_blocks = candidate.lag_blocks,
                            stalled_secs = INDEXED_TAIL_FALLBACK_MIN_STALL.as_secs(),
                            "indexed wallet ready-tail fallback triggered"
                        );
                        let Some(target_result) = await_wallet_cancellation(
                            &candidate.cancel,
                            candidate.handle.start_backfill(
                                &candidate.cache_key,
                                &candidate.sender,
                                progress,
                                candidate.target_block,
                            ),
                        )
                        .await
                        else {
                            continue;
                        };
                        let driver = match target_result {
                            WalletBackfillStartResult::Accepted { grant, .. } => grant.activate(),
                            WalletBackfillStartResult::Rejected { .. } => continue,
                        };
                        let tail_result = service
                            .try_indexed_wallet_tail_catch_up(
                                &candidate.cache_key,
                                from_block,
                                candidate.target_block,
                                progress,
                                &candidate.sender,
                                &candidate.cancel,
                            )
                            .await;
                        if candidate.cancel.is_cancelled() {
                            driver.retire(&candidate.cache_key).await;
                            continue;
                        }
                        let checkpoint = match tail_result {
                            WalletIndexedTailFallbackResult::Completed(checkpoint) => {
                                checkpoint
                            }
                            WalletIndexedTailFallbackResult::Cancelled => {
                                driver.retire(&candidate.cache_key).await;
                                continue;
                            }
                            WalletIndexedTailFallbackResult::Unavailable => {
                                debug!(
                                    cache_key = %candidate.cache_key,
                                    from_block,
                                    target_block = candidate.target_block,
                                    "indexed wallet ready-tail fallback unavailable"
                                );
                                let request = BackfillRequest::add(
                                    candidate.cache_key.clone(),
                                    from_block,
                                    candidate.target_block,
                                    candidate.follow_safe_head,
                                    from_block,
                                    driver,
                                );
                                if let Err(err) = service.backfill_tx.try_send(request) {
                                    warn!(
                                        ?err,
                                        cache_key = %candidate.cache_key,
                                        from_block,
                                        target_block = candidate.target_block,
                                        "failed to enqueue ready-tail fallback backfill"
                                    );
                                    if let BackfillRequest::Add { driver, .. } = err.into_inner() {
                                        driver
                                            .fail(
                                                &candidate.cache_key,
                                                WalletReadinessError::BackfillUnavailable,
                                            )
                                            .await;
                                    }
                                }
                                continue;
                            }
                        };
                        if checkpoint < from_block {
                            let request = BackfillRequest::add(
                                candidate.cache_key.clone(),
                                from_block,
                                candidate.target_block,
                                candidate.follow_safe_head,
                                from_block,
                                driver,
                            );
                            if let Err(err) = service.backfill_tx.try_send(request) {
                                warn!(
                                    ?err,
                                    cache_key = %candidate.cache_key,
                                    from_block,
                                    target_block = candidate.target_block,
                                    "failed to enqueue ready-tail no-progress backfill"
                                );
                                if let BackfillRequest::Add { driver, .. } = err.into_inner() {
                                    driver
                                        .fail(
                                            &candidate.cache_key,
                                            WalletReadinessError::BackfillUnavailable,
                                        )
                                        .await;
                                }
                            }
                            continue;
                        }
                        if checkpoint >= candidate.target_block {
                            let result = driver
                                .finish(&candidate.cache_key, candidate.target_block)
                                .await;
                            debug!(?result, cache_key = %candidate.cache_key, "ready-tail indexed wallet finish result");
                            if wallet_finish_result_removes_cursor(&result) {
                                driver.retire(&candidate.cache_key).await;
                            } else {
                                let retry_from = result.committed_to().saturating_add(1);
                                let request = wallet_finish_retry_request(
                                    candidate.cache_key.clone(),
                                    candidate.target_block,
                                    candidate.follow_safe_head,
                                    from_block,
                                    &result,
                                    driver,
                                );
                                if let Err(err) = service.backfill_tx.try_send(request) {
                                    warn!(
                                        ?err,
                                        cache_key = %candidate.cache_key,
                                        retry_from,
                                        target_block = candidate.target_block,
                                        "failed to enqueue ready-tail finish retry"
                                    );
                                    if let BackfillRequest::Add { driver, .. } = err.into_inner() {
                                        driver
                                            .fail(
                                                &candidate.cache_key,
                                                WalletReadinessError::BackfillUnavailable,
                                            )
                                            .await;
                                    }
                                }
                            }
                        } else {
                            let request = BackfillRequest::add(
                                candidate.cache_key.clone(),
                                checkpoint.saturating_add(1),
                                candidate.target_block,
                                candidate.follow_safe_head,
                                from_block,
                                driver,
                            );
                            if let Err(err) = service.backfill_tx.try_send(request) {

                                warn!(
                                    ?err,
                                    cache_key = %candidate.cache_key,
                                    checkpoint,
                                    target_block = candidate.target_block,
                                    "failed to enqueue ready-tail remainder backfill"
                                );
                                if let BackfillRequest::Add { driver, .. } = err.into_inner() {
                                    driver
                                        .fail(
                                            &candidate.cache_key,
                                            WalletReadinessError::BackfillUnavailable,
                                        )
                                        .await;
                                }
                            } else {
                                debug!(
                                    cache_key = %candidate.cache_key,
                                    checkpoint,
                                    target_block = candidate.target_block,
                                    "ready-tail indexed fallback enqueued remainder backfill"
                                );
                            }
                        }
                    }
                }

                tokio::select! {
                    () = cancel.cancelled() => break,
                    changed = safe_head_rx.changed() => {
                        if changed.is_err() {
                            break;
                        }
                    }
                    () = tokio::time::sleep(service.chain.sync.poll_interval) => {}
                }
            }
        }
        .instrument(tracing::info_span!("wallet_lag_fallback", chain_id)),
    );
}

async fn wallet_lag_fallback_candidate(
    service: &Arc<ChainService>,
    state: &mut Option<(String, u64, WalletTailFallbackState)>,
    safe_head: u64,
    now: Instant,
) -> Option<WalletLagFallbackCandidate> {
    let wallet = service.wallet.read().await;
    let Some(registration) = wallet.as_ref() else {
        *state = None;
        return None;
    };
    let cache_key = registration.cfg.cache_key.as_str();
    let actor_id = registration.handle.actor_id();
    if state
        .as_ref()
        .is_none_or(|(key, state_actor_id, _)| key != cache_key || *state_actor_id != actor_id)
    {
        *state = Some((
            cache_key.to_string(),
            actor_id,
            WalletTailFallbackState::new(registration.handle.last_scanned_raw(), now),
        ));
    }
    let (_, _, fallback_state) = state.as_mut().expect("fallback state installed");
    if !registration.cfg.use_indexed_wallet_catch_up
        || !registration.handle.readiness().is_ready()
        || registration.handle.indexed_catch_up_rx.borrow().is_some()
    {
        return None;
    }

    let progress = registration.handle.schedulable_progress()?;
    let last_scanned = progress.last_scanned;
    let target_block = wallet_sync_target(safe_head, registration.sync_to_block);
    let from_block = wallet_backfill_from_block(last_scanned, registration.start_block);
    fallback_state.update_last_scanned(last_scanned, now);

    if !fallback_state.should_try_indexed_tail_fallback(
        service.chain.block_time,
        from_block,
        target_block,
        now,
        INDEXED_TAIL_FALLBACK_MIN_STALL,
        INDEXED_TAIL_FALLBACK_COOLDOWN,
    ) {
        return None;
    }
    let lag_blocks = wallet_backfill_lag_blocks(from_block, target_block);
    fallback_state.mark_indexed_tail_attempt(now);
    Some(WalletLagFallbackCandidate {
        cache_key: cache_key.to_string(),
        progress,
        start_block: registration.start_block,
        target_block,
        lag_blocks,
        follow_safe_head: registration.sync_to_block.is_none(),
        sender: registration.backfill_sender.clone(),
        handle: registration.handle.clone(),
        cancel: registration.cancel.clone(),
    })
}

#[cfg(test)]
pub(in crate::chain) async fn wallet_lag_fallback_state_for_test(
    service: &Arc<ChainService>,
    state: &mut Option<(String, u64, WalletTailFallbackState)>,
    safe_head: u64,
    now: Instant,
) -> Option<(u64, bool)> {
    let _ = wallet_lag_fallback_candidate(service, state, safe_head, now).await;
    state.as_ref().map(|(_, actor_id, fallback_state)| {
        (
            *actor_id,
            fallback_state.indexed_tail_attempt_recorded_for_test(),
        )
    })
}
