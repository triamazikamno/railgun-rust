//! The wallet backfill loop, which runs queued RPC backfill and cached scan acquisitions.

use crate::chain::{
    PublicDataPlaneDiagnosticKind, PublicScanRange, WalletBackfill, WalletBackfillApplyResult,
    WalletBackfillDriver, WalletBackfillFinishResult, WalletBackfillRejectReason,
    WalletIndexedTailFallbackResult, WalletScanAcquisitionCandidate, WalletScanAcquisitionOutcome,
};

use super::{
    Arc, BackfillRequest, CancellationToken, ChainService, DynProvider,
    INDEXED_TAIL_FALLBACK_COOLDOWN, INDEXED_TAIL_FALLBACK_MIN_STALL, Instant, Instrument, LogBatch,
    PublicScanSource, QueryRpcPool, WalletScanApply, WalletScanRows, WalletScanRowsPayload,
    await_wallet_cancellation, debug, info, min, mpsc, sort_logs, wallet_backfill_lag_blocks, warn,
    watch,
};

/// Remaining RPC backfill pages above which the indexed tail fallback is
/// retried even while backfill keeps advancing.
const INDEXED_TAIL_FALLBACK_RPC_PAGES: u64 = 50;

pub(in crate::chain) struct WalletBackfillSlot {
    pub(in crate::chain) cache_key: String,
    pub(in crate::chain) cursor: WalletBackfill,
}

pub(in crate::chain) const fn wallet_finish_result_removes_cursor(
    result: &WalletBackfillFinishResult,
) -> bool {
    matches!(
        result,
        WalletBackfillFinishResult::Ready { .. }
            | WalletBackfillFinishResult::Rejected {
                reason: WalletBackfillRejectReason::StaleGeneration { .. }
                    | WalletBackfillRejectReason::Shutdown,
                ..
            }
    )
}

pub(in crate::chain) fn wallet_finish_retry_request(
    cache_key: String,
    target_block: u64,
    follow_safe_head: bool,
    progress_start_block: u64,
    result: &WalletBackfillFinishResult,
    driver: WalletBackfillDriver,
) -> BackfillRequest {
    BackfillRequest::add(
        cache_key,
        result.committed_to().saturating_add(1),
        target_block,
        follow_safe_head,
        progress_start_block,
        driver,
    )
}

pub(in crate::chain) fn spawn_backfill_loop(
    service: Arc<ChainService>,
    mut backfill_rx: mpsc::Receiver<BackfillRequest>,
    rpcs: Arc<QueryRpcPool>,
    archive_provider: Option<DynProvider>,
    mut safe_head_rx: watch::Receiver<u64>,
    cancel: CancellationToken,
) {
    let task = async move {
        let mut cursor: Option<WalletBackfillSlot> = None;
        loop {
            if cancel.is_cancelled() {
                break;
            }
            drain_pending_backfill_requests_for_service(&service, &mut backfill_rx, &mut cursor)
                .await;
            if retire_cancelled_backfill_cursor(&mut cursor).await {
                continue;
            }

            if cursor.is_none() {
                tokio::select! {
                    () = cancel.cancelled() => break,
                    Some(request) = backfill_rx.recv() => {
                        let active_actor = current_backfill_actor(&service).await;
                        apply_backfill_request(
                            &mut cursor,
                            request,
                            Instant::now(),
                            active_actor.as_ref().map(|(key, id)| (key.as_str(), *id)),
                        )
                        .await;
                    }
                    _ = safe_head_rx.changed() => {},
                }
                // Re-enter the loop immediately so that pending requests in
                // backfill_rx are picked up without an unnecessary poll_interval
                // delay.
                continue;
            }

            let safe_head = *safe_head_rx.borrow();
            cursor
                .as_mut()
                .expect("cursor installed")
                .cursor
                .refresh_target(safe_head);
            reconcile_retained_acquisition(&service, &mut cursor).await;
            complete_cached_acquisition_without_delivery(&service, &mut cursor).await;

            let now = Instant::now();
            if !cursor
                .as_ref()
                .expect("cursor installed")
                .cursor
                .is_runnable(now)
            {
                let retry_at = cursor
                    .as_ref()
                    .and_then(|slot| slot.cursor.persistence_retry_at())
                    .expect("deferred wallet cursor has retry deadline");
                let actor_cancel = cursor
                    .as_ref()
                    .expect("cursor installed")
                    .cursor
                    .driver
                    .cancellation_token();
                tokio::select! {
                    () = cancel.cancelled() => break,
                    () = actor_cancel.cancelled() => {
                        let _ = retire_cancelled_backfill_cursor(&mut cursor).await;
                    }
                    request = backfill_rx.recv() => {
                        let Some(request) = request else { break };
                        let active_actor = current_backfill_actor(&service).await;
                        apply_backfill_request(
                            &mut cursor,
                            request,
                            Instant::now(),
                            active_actor.as_ref().map(|(key, id)| (key.as_str(), *id)),
                        )
                        .await;
                    }
                    changed = safe_head_rx.changed() => {
                        if changed.is_err() { break; }
                    }
                    () = tokio::time::sleep(retry_at.saturating_duration_since(Instant::now())) => {}
                }
                continue;
            }

            if !reconcile_retained_acquisition(&service, &mut cursor).await {
                continue;
            }
            if cursor
                .as_ref()
                .is_some_and(|slot| slot.cursor.is_runnable(now) && slot.cursor.can_finish())
            {
                // The cursor delivered its target, so the startup window's
                // leading blocks can now be warmed without delaying the wallet.
                if let Some((from_block, to_block)) = cursor
                    .as_mut()
                    .and_then(|slot| slot.cursor.take_startup_warm_range())
                {
                    service
                        .start_public_scan_window_warm(PublicScanRange::new(from_block, to_block))
                        .await;
                }
                let slot = cursor.as_ref().expect("cursor installed");
                let key = slot.cache_key.clone();
                let cancellation = slot.cursor.driver.cancellation_token();
                let Some(result) = await_wallet_cancellation(
                    &cancellation,
                    slot.cursor.driver.finish(&key, slot.cursor.target_block),
                )
                .await
                else {
                    let _ = retire_cancelled_backfill_cursor(&mut cursor).await;
                    continue;
                };
                let remove_cursor = wallet_finish_result_removes_cursor(&result);
                let committed_to = result.committed_to();
                let persistence_failed = matches!(
                    &result,
                    WalletBackfillFinishResult::Rejected {
                        reason: WalletBackfillRejectReason::PersistenceFailed,
                        ..
                    }
                );
                debug!(?result, cache_key = %key, remove_cursor, "wallet backfill finish result");
                if remove_cursor {
                    if let Some(slot) = cursor.take() {
                        slot.cursor.driver.retire(&key).await;
                    }
                } else if let Some(slot) = cursor.as_mut() {
                    slot.cursor.retry_after_rejected_finish(committed_to);
                    if persistence_failed {
                        slot.cursor.defer_persistence_retry(
                            Instant::now(),
                            service.chain.sync.poll_interval,
                        );
                    }
                }
            }

            let now = Instant::now();
            let indexed_tail_attempt = cursor.as_mut().and_then(|slot| {
                let cursor = &mut slot.cursor;
                if !cursor.is_runnable(now)
                    || !cursor.should_try_indexed_tail_fallback(
                        service.chain.block_time,
                        INDEXED_TAIL_FALLBACK_RPC_PAGES
                            .saturating_mul(service.chain.sync.block_range),
                        now,
                        INDEXED_TAIL_FALLBACK_MIN_STALL,
                        INDEXED_TAIL_FALLBACK_COOLDOWN,
                    )
                {
                    return None;
                }
                let attempt = (
                    slot.cache_key.clone(),
                    cursor.from_block,
                    cursor.target_block,
                    wallet_backfill_lag_blocks(cursor.from_block, cursor.target_block),
                    now.duration_since(cursor.last_advanced_at),
                    cursor.driver.sender().clone(),
                    crate::types::WalletSchedulableProgress {
                        last_scanned: cursor.from_block.saturating_sub(1),
                        reset_generation: cursor.driver.token().reset_generation(),
                    },
                );
                cursor.mark_indexed_tail_attempt(now);
                Some(attempt)
            });
            let indexed_tail_attempt = match indexed_tail_attempt {
                Some(attempt) => {
                    // Short-lived read; the service call below takes the same lock.
                    let enabled = {
                        let wallet = service.wallet.read().await;
                        wallet.as_ref().is_some_and(|registration| {
                            registration.cfg.cache_key.as_str() == attempt.0.as_str()
                                && registration.cfg.use_indexed_wallet_catch_up
                        })
                    };
                    enabled.then_some(attempt)
                }
                None => None,
            };
            if let Some((key, from_block, target_block, lag_blocks, idle, sender, progress)) =
                indexed_tail_attempt
            {
                info!(
                    cache_key = %key,
                    from_block,
                    target_block,
                    lag_blocks,
                    idle_secs = idle.as_secs(),
                    "indexed wallet tail fallback triggered"
                );
                let cancellation = cursor
                    .as_ref()
                    .expect("cursor exists during indexed tail fallback")
                    .cursor
                    .driver
                    .cancellation_token();
                let tail_result = service
                    .try_indexed_wallet_tail_catch_up(
                        &key,
                        from_block,
                        target_block,
                        progress,
                        &sender,
                        &cancellation,
                    )
                    .await;
                if let Some(slot) = cursor.as_mut() {
                    slot.cursor.mark_indexed_tail_attempt(Instant::now());
                }
                let checkpoint = match tail_result {
                    WalletIndexedTailFallbackResult::Completed(checkpoint) => checkpoint,
                    WalletIndexedTailFallbackResult::Cancelled => {
                        let _ = retire_cancelled_backfill_cursor(&mut cursor).await;
                        continue;
                    }
                    WalletIndexedTailFallbackResult::Unavailable => {
                        debug!(
                            cache_key = %key,
                            from_block,
                            target_block,
                            "indexed wallet tail fallback unavailable"
                        );
                        continue;
                    }
                };
                let latest_safe_head = *safe_head_rx.borrow();
                if let Some(slot) = cursor.as_mut()
                    && checkpoint >= slot.cursor.from_block
                {
                    slot.cursor
                        .mark_progress(checkpoint.saturating_add(1), Instant::now());
                    slot.cursor.refresh_target(latest_safe_head);
                }
            }

            let latest_safe_head = *safe_head_rx.borrow();
            if apply_cached_backfill_row(&service, &mut cursor, latest_safe_head).await {
                continue;
            }

            let now = Instant::now();
            let Some(slot) = cursor.as_ref().filter(|slot| slot.cursor.is_runnable(now)) else {
                continue;
            };
            let from_block = wallet_backfill_fetch_from_block(&service, &slot.cursor).await;
            let target_block = slot.cursor.fetch_target_block();
            debug!(block = from_block, "scanning wallet events");
            if target_block == 0 {
                if safe_head == 0 {
                    // safe_head not yet available — the head poller hasn't
                    // successfully fetched a block number yet.  Wait for it
                    // instead of prematurely marking wallets as done.
                    debug!("safe_head is 0, waiting for head poller before backfill");
                    let actor_cancel = slot.cursor.driver.cancellation_token();
                    tokio::select! {
                        () = cancel.cancelled() => break,
                        () = actor_cancel.cancelled() => {
                            let _ = retire_cancelled_backfill_cursor(&mut cursor).await;
                        }
                        request = backfill_rx.recv() => {
                            let Some(request) = request else { break };
                            let active_actor = current_backfill_actor(&service).await;
                            apply_backfill_request(
                                &mut cursor,
                                request,
                                Instant::now(),
                                active_actor.as_ref().map(|(key, id)| (key.as_str(), *id)),
                            )
                            .await;
                        }
                        changed = safe_head_rx.changed() => {
                            if changed.is_err() { break; }
                        }
                    }
                }
                continue;
            }
            let requested_to_block = min(
                from_block + service.chain.sync.block_range - 1,
                target_block,
            );
            let cached_suffix_from = service
                .public_data_plane
                .cached_wallet_scan_suffix(from_block, target_block)
                .await
                .and_then(|applies| applies.first().map(|apply| apply.from_block));
            let to_block = cached_suffix_from.map_or(requested_to_block, |suffix_from| {
                if suffix_from > from_block {
                    requested_to_block.min(suffix_from - 1)
                } else {
                    requested_to_block
                }
            });
            let cancellation = cursor
                .as_ref()
                .expect("cursor installed before remote backfill")
                .cursor
                .driver
                .cancellation_token();
            let Some(rpc) = rpcs.random_provider() else {
                warn!("no healthy rpc providers available");
                let _ = await_wallet_cancellation(
                    &cancellation,
                    tokio::time::sleep(service.chain.sync.poll_interval),
                )
                .await;
                continue;
            };
            let read_scope = service.begin_public_scan_read();
            let fetch_logs_started = Instant::now();
            let Some(logs_result) = await_wallet_cancellation(
                &cancellation,
                service.chain.fetch_logs_for_range(
                    &rpc,
                    archive_provider.as_ref(),
                    from_block,
                    to_block,
                    &cancellation,
                ),
            )
            .await
            else {
                let _ = retire_cancelled_backfill_cursor(&mut cursor).await;
                continue;
            };
            match logs_result {
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
                    let Some(timestamps_result) = await_wallet_cancellation(
                        &cancellation,
                        service.chain.fetch_log_block_timestamps(
                            &rpc.provider,
                            archive_provider.as_ref(),
                            &logs,
                        ),
                    )
                    .await
                    else {
                        let _ = retire_cancelled_backfill_cursor(&mut cursor).await;
                        continue;
                    };
                    let block_timestamps = match timestamps_result {
                        Ok(block_timestamps) => block_timestamps,
                        Err(err) => {
                            let mark_unhealthy = err.should_mark_rpc_unhealthy();
                            warn!(
                                err = %err.without_url(),
                                rpc_index = rpc.index,
                                "failed to fetch backfill log block timestamps"
                            );
                            if mark_unhealthy {
                                rpcs.mark_bad_provider(&rpc);
                            } else {
                                let _ = await_wallet_cancellation(
                                    &cancellation,
                                    tokio::time::sleep(service.chain.sync.poll_interval),
                                )
                                .await;
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
                    if let Some(archive_endpoint) = service
                        .chain
                        .archive_boundary_crossed_by(from_block, to_block)
                    {
                        let Some(boundary_hash_result) = await_wallet_cancellation(
                            &cancellation,
                            service.chain.fetch_block_hash(
                                &rpc.provider,
                                archive_provider.as_ref(),
                                archive_endpoint,
                            ),
                        )
                        .await
                        else {
                            let _ = retire_cancelled_backfill_cursor(&mut cursor).await;
                            continue;
                        };
                        match boundary_hash_result {
                            Ok(Some(_)) => {}
                            Ok(None) => {
                                warn!(
                                    rpc_index = rpc.index,
                                    archive_endpoint,
                                    "backfill RPC range does not prove its archive boundary"
                                );
                                rpcs.mark_bad_provider(&rpc);
                                continue;
                            }
                            Err(err) => {
                                let mark_unhealthy = err.should_mark_rpc_unhealthy();
                                warn!(
                                    err = %err.without_url(),
                                    rpc_index = rpc.index,
                                    archive_endpoint,
                                    "failed to fetch backfill RPC archive-boundary hash"
                                );
                                if mark_unhealthy {
                                    rpcs.mark_bad_provider(&rpc);
                                } else {
                                    let _ = await_wallet_cancellation(
                                        &cancellation,
                                        tokio::time::sleep(service.chain.sync.poll_interval),
                                    )
                                    .await;
                                }
                                continue;
                            }
                        }
                    }
                    let block_hash_started = Instant::now();
                    let Some(to_block_hash_result) = await_wallet_cancellation(
                        &cancellation,
                        service.chain.fetch_block_hash(
                            &rpc.provider,
                            archive_provider.as_ref(),
                            to_block,
                        ),
                    )
                    .await
                    else {
                        let _ = retire_cancelled_backfill_cursor(&mut cursor).await;
                        continue;
                    };
                    let to_block_hash = match to_block_hash_result {
                        Ok(Some(hash)) => Some(hash),
                        Ok(None) => {
                            warn!(
                                rpc_index = rpc.index,
                                to_block, "backfill RPC does not cover requested endpoint"
                            );
                            rpcs.mark_bad_provider(&rpc);
                            continue;
                        }
                        Err(err) => {
                            let mark_unhealthy = err.should_mark_rpc_unhealthy();
                            warn!(
                                err = %err.without_url(),
                                rpc_index = rpc.index,
                                to_block,
                                "failed to fetch backfill block hash"
                            );
                            if mark_unhealthy {
                                rpcs.mark_bad_provider(&rpc);
                            } else {
                                let _ = await_wallet_cancellation(
                                    &cancellation,
                                    tokio::time::sleep(service.chain.sync.poll_interval),
                                )
                                .await;
                            }
                            continue;
                        }
                    };
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
                        read_scope,
                    });

                    let batch_source = service.rpc_scan_source_for_range(from_block);
                    let normalized_apply = match WalletScanApply::rows_from_log_batch(
                        from_block,
                        to_block,
                        &batch,
                        batch_source,
                    ) {
                        Ok(apply) => Some(apply),
                        Err(err) => {
                            warn!(
                                ?err,
                                from_block,
                                to_block,
                                "failed to normalize public backfill rows for reuse"
                            );
                            abandon_intersecting_acquisition(
                                &mut cursor,
                                PublicScanRange::new(from_block, to_block),
                            );
                            None
                        }
                    };
                    if let Some(apply) = normalized_apply.as_ref() {
                        let candidate = if let Some(range) = cursor
                            .as_ref()
                            .and_then(|slot| slot.cursor.acquisition_range())
                            .filter(|range| {
                                PublicScanRange::new(from_block, to_block)
                                    .intersects(PublicScanRange::new(range.0, range.1))
                            }) {
                            wallet_scan_acquisition_candidate(&service, range, apply)
                                .await
                                .map(|applies| WalletScanAcquisitionCandidate {
                                    range: PublicScanRange::new(range.0, range.1),
                                    applies,
                                })
                        } else {
                            None
                        };
                        let candidate_range = candidate.as_ref().map(|candidate| candidate.range);
                        match service
                            .public_data_plane
                            .record_public_scan_apply_with_acquisition(apply, candidate.as_ref())
                            .await
                        {
                            Ok((_, outcome)) => {
                                if let Some(range) = candidate_range
                                    && let Some(outcome) = outcome
                                {
                                    match outcome {
                                        WalletScanAcquisitionOutcome::Retained => {
                                            finish_matching_acquisition(
                                                &mut cursor,
                                                (range.from_block, range.to_block),
                                            );
                                        }
                                        WalletScanAcquisitionOutcome::NonRetainable(error) => {
                                            warn!(
                                                ?range,
                                                ?error,
                                                "abandoning non-retainable wallet scan warm acquisition"
                                            );
                                            abandon_matching_acquisition(
                                                &mut cursor,
                                                (range.from_block, range.to_block),
                                            );
                                        }
                                        WalletScanAcquisitionOutcome::Rejected(error) => {
                                            debug!(
                                                ?error,
                                                ?range,
                                                "wallet scan acquisition remains pending"
                                            );
                                        }
                                    }
                                }
                            }
                            Err(err) => {
                                debug!(?err, "public scan apply publication remains pending");
                            }
                        }
                    }
                    complete_cached_acquisition_without_delivery(&service, &mut cursor).await;

                    let latest_safe_head = *safe_head_rx.borrow();
                    let key = cursor.as_ref().map(|slot| slot.cache_key.clone());
                    if let Some(key) = key {
                        let Some((apply_from_block, apply_to_block)) =
                            cursor.as_ref().and_then(|slot| {
                                let cursor = &slot.cursor;
                                if !cursor.is_runnable(Instant::now())
                                    || cursor.target_block == 0
                                    || cursor.from_block > cursor.target_block
                                {
                                    return None;
                                }
                                let apply_to_block = min(to_block, cursor.target_block);
                                (cursor.from_block <= apply_to_block)
                                    .then_some((cursor.from_block, apply_to_block))
                            })
                        else {
                            continue;
                        };
                        let source = service.rpc_scan_source_for_range(apply_from_block);
                        let apply = match WalletScanApply::rows_from_log_batch(
                            apply_from_block,
                            apply_to_block,
                            &batch,
                            source,
                        ) {
                            Ok(apply) => apply,
                            Err(err) => {
                                warn!(?err, cache_key = %key, from_block = apply_from_block, to_block = apply_to_block, "failed to normalize backfill logs");
                                continue;
                            }
                        };
                        service
                            .public_data_plane
                            .record_source_decision(
                                PublicDataPlaneDiagnosticKind::SourceSelected,
                                source,
                                PublicScanRange::new(apply_from_block, apply_to_block),
                                read_scope,
                                "RPC wallet backfill source selected",
                            )
                            .await;
                        let Some(apply_result) = await_wallet_cancellation(
                            &cancellation,
                            cursor
                                .as_ref()
                                .expect("wallet cursor exists while applying")
                                .cursor
                                .driver
                                .apply(&key, apply),
                        )
                        .await
                        else {
                            let _ = retire_cancelled_backfill_cursor(&mut cursor).await;
                            continue;
                        };
                        let mut remove_cursor = false;
                        if let Some(slot) = cursor.as_mut() {
                            let cursor = &mut slot.cursor;
                            if let Some(committed_to) = apply_result.accepted_committed_to() {
                                match apply_result {
                                    WalletBackfillApplyResult::Committed { .. } => cursor
                                        .mark_progress(
                                            committed_to.saturating_add(1),
                                            Instant::now(),
                                        ),
                                    WalletBackfillApplyResult::AlreadyCovered { .. } => cursor
                                        .mark_already_covered(
                                            committed_to.saturating_add(1),
                                            Instant::now(),
                                        ),
                                    WalletBackfillApplyResult::Rejected { .. } => unreachable!(),
                                }
                                cursor.refresh_target(latest_safe_head);
                            } else {
                                warn!(?apply_result, cache_key = %key, "wallet backfill logs rejected");
                                match apply_result {
                                    WalletBackfillApplyResult::Rejected {
                                        reason:
                                            WalletBackfillRejectReason::NonContiguous {
                                                expected_from,
                                                ..
                                            },
                                        ..
                                    } => {
                                        cursor.mark_progress(expected_from, Instant::now());
                                    }
                                    WalletBackfillApplyResult::Rejected {
                                        committed_to,
                                        reason: WalletBackfillRejectReason::PersistenceFailed,
                                    } => {
                                        cursor.retry_after_rejected_apply(committed_to);
                                        cursor.defer_persistence_retry(
                                            Instant::now(),
                                            service.chain.sync.poll_interval,
                                        );
                                    }
                                    WalletBackfillApplyResult::Rejected {
                                        reason:
                                            WalletBackfillRejectReason::StaleGeneration { .. }
                                            | WalletBackfillRejectReason::Shutdown,
                                        ..
                                    } => {
                                        remove_cursor = true;
                                    }
                                    WalletBackfillApplyResult::Rejected {
                                        reason:
                                            WalletBackfillRejectReason::StaleDataPlaneEpoch { .. },
                                        ..
                                    } => {
                                        cursor.restore_retained_acquisition();
                                    }
                                    WalletBackfillApplyResult::Rejected { .. }
                                    | WalletBackfillApplyResult::Committed { .. }
                                    | WalletBackfillApplyResult::AlreadyCovered { .. } => {}
                                }
                            }
                        }
                        if remove_cursor && let Some(slot) = cursor.take() {
                            slot.cursor.driver.retire(&key).await;
                        }
                    }
                }
                Err(err) => {
                    let mark_unhealthy = err.should_mark_rpc_unhealthy();
                    warn!(
                        err = %err.without_url(),
                        rpc_index = rpc.index,
                        from_block,
                        to_block,
                        "failed to fetch backfill logs"
                    );
                    if mark_unhealthy {
                        rpcs.mark_bad_provider(&rpc);
                    } else {
                        let _ = await_wallet_cancellation(
                            &cancellation,
                            tokio::time::sleep(service.chain.sync.poll_interval),
                        )
                        .await;
                    }
                }
            }
        }
        retire_backfill_loop_state(&mut cursor, &mut backfill_rx).await;
    };
    tokio::spawn(task.instrument(tracing::info_span!("sync_backfill")));
}

async fn retire_cancelled_backfill_cursor(cursor: &mut Option<WalletBackfillSlot>) -> bool {
    let cancelled = cursor
        .as_ref()
        .is_some_and(|slot| slot.cursor.driver.cancellation_token().is_cancelled());
    if !cancelled {
        return false;
    }
    if let Some(slot) = cursor.take() {
        slot.cursor.driver.retire(&slot.cache_key).await;
    }
    true
}

async fn retire_backfill_loop_state(
    cursor: &mut Option<WalletBackfillSlot>,
    backfill_rx: &mut mpsc::Receiver<BackfillRequest>,
) {
    if let Some(slot) = cursor.take() {
        slot.cursor.driver.retire(&slot.cache_key).await;
    }
    while let Ok(request) = backfill_rx.try_recv() {
        match request {
            BackfillRequest::Add {
                driver, cache_key, ..
            } => {
                driver.retire(&cache_key).await;
            }
            BackfillRequest::Remove { response, .. } => {
                let _ = response.send(());
            }
        }
    }
}

async fn apply_cached_backfill_row(
    service: &ChainService,
    cursor: &mut Option<WalletBackfillSlot>,
    safe_head: u64,
) -> bool {
    let Some(slot) = cursor.as_ref() else {
        return false;
    };
    let key = slot.cache_key.clone();
    let from_block = slot.cursor.from_block;
    let target_block = slot.cursor.target_block;
    let acquisition_range = slot.cursor.acquisition_range();
    if !slot.cursor.is_runnable(Instant::now()) || target_block == 0 || from_block > target_block {
        return false;
    }
    {
        if let Some(range) = acquisition_range
            && !cached_acquisition_is_complete(service, range).await
        {
            return false;
        }
        let Some(apply) = service
            .public_data_plane
            .cached_wallet_scan_apply(from_block, target_block)
            .await
        else {
            return false;
        };
        let apply_to = apply.to_block;
        let read_scope = apply.read_scope;
        service
            .public_data_plane
            .record_source_decision(
                PublicDataPlaneDiagnosticKind::SourceSelected,
                PublicScanSource::CachedCoverage,
                PublicScanRange::new(from_block, apply_to),
                read_scope,
                "cached public scan data selected by backfill loop",
            )
            .await;
        let apply_result = cursor
            .as_ref()
            .expect("cursor exists")
            .cursor
            .driver
            .apply(&key, apply)
            .await;
        let mut remove_cursor = false;
        if let Some(slot) = cursor.as_mut() {
            let cursor = &mut slot.cursor;
            if let Some(committed_to) = apply_result.accepted_committed_to() {
                match apply_result {
                    WalletBackfillApplyResult::Committed { .. } => {
                        cursor.mark_progress(committed_to.saturating_add(1), Instant::now());
                    }
                    WalletBackfillApplyResult::AlreadyCovered { .. } => {
                        cursor.mark_already_covered(committed_to.saturating_add(1), Instant::now());
                    }
                    WalletBackfillApplyResult::Rejected { .. } => unreachable!(),
                }
                cursor.refresh_target(safe_head);
            } else {
                warn!(?apply_result, cache_key = %key, "cached wallet backfill rows rejected");
                match apply_result {
                    WalletBackfillApplyResult::Rejected {
                        reason: WalletBackfillRejectReason::NonContiguous { expected_from, .. },
                        ..
                    } => cursor.mark_progress(expected_from, Instant::now()),
                    WalletBackfillApplyResult::Rejected {
                        committed_to,
                        reason: WalletBackfillRejectReason::PersistenceFailed,
                    } => {
                        cursor.retry_after_rejected_apply(committed_to);
                        cursor.defer_persistence_retry(
                            Instant::now(),
                            service.chain.sync.poll_interval,
                        );
                    }
                    WalletBackfillApplyResult::Rejected {
                        reason:
                            WalletBackfillRejectReason::StaleGeneration { .. }
                            | WalletBackfillRejectReason::Shutdown,
                        ..
                    } => remove_cursor = true,
                    WalletBackfillApplyResult::Rejected {
                        reason: WalletBackfillRejectReason::StaleDataPlaneEpoch { .. },
                        ..
                    } => {
                        cursor.restore_retained_acquisition();
                    }
                    WalletBackfillApplyResult::Rejected { .. }
                    | WalletBackfillApplyResult::Committed { .. }
                    | WalletBackfillApplyResult::AlreadyCovered { .. } => {}
                }
            }
        }
        if remove_cursor && let Some(slot) = cursor.take() {
            slot.cursor.driver.retire(&key).await;
        }
    }
    true
}

async fn cached_acquisition_is_complete(
    service: &ChainService,
    (from_block, to_block): (u64, u64),
) -> bool {
    service
        .public_data_plane
        .cached_wallet_scan_suffix(from_block, to_block)
        .await
        .is_some_and(|applies| {
            applies
                .first()
                .is_some_and(|apply| apply.from_block == from_block)
        })
}

async fn wallet_backfill_fetch_from_block(service: &ChainService, cursor: &WalletBackfill) -> u64 {
    let Some((acquisition_from, _)) = cursor.acquisition_range() else {
        return cursor.from_block;
    };
    let Some(prefix_to) = cursor.from_block.checked_sub(1) else {
        return acquisition_from;
    };
    if acquisition_from > prefix_to {
        return acquisition_from;
    }
    if service
        .public_data_plane
        .cached_wallet_scan_exact(acquisition_from, prefix_to)
        .await
        .is_some()
    {
        cursor.from_block
    } else {
        acquisition_from
    }
}

async fn complete_cached_acquisition_without_delivery(
    service: &ChainService,
    cursor: &mut Option<WalletBackfillSlot>,
) {
    let Some(range) = cursor
        .as_ref()
        .and_then(|slot| slot.cursor.acquisition_range())
    else {
        return;
    };
    if cached_acquisition_is_complete(service, range).await
        && let Some(slot) = cursor.as_mut()
        && slot.cursor.acquisition_range() == Some(range)
    {
        slot.cursor.finish_retained_acquisition();
    }
}

pub(in crate::chain) async fn reconcile_retained_acquisition(
    service: &ChainService,
    cursor: &mut Option<WalletBackfillSlot>,
) -> bool {
    let Some((range, should_reconcile)) = cursor.as_ref().map(|slot| {
        (
            slot.cursor.retained_acquisition_range(),
            slot.cursor.acquisition_range().is_none(),
        )
    }) else {
        return false;
    };
    let Some(range) = range.filter(|_| should_reconcile) else {
        return true;
    };
    let exact = service
        .public_data_plane
        .cached_wallet_scan_exact(range.0, range.1)
        .await;
    if exact.is_none()
        && let Some(slot) = cursor.as_mut()
        && slot.cursor.acquisition_range().is_none()
        && slot.cursor.retained_acquisition_range() == Some(range)
    {
        if slot.cursor.restore_retained_acquisition() {
            return false;
        }
        slot.cursor.abandon_acquisition();
    }
    true
}

fn finish_matching_acquisition(cursor: &mut Option<WalletBackfillSlot>, range: (u64, u64)) {
    if let Some(slot) = cursor.as_mut()
        && slot.cursor.acquisition_range() == Some(range)
    {
        slot.cursor.finish_retained_acquisition();
    }
}

fn abandon_matching_acquisition(cursor: &mut Option<WalletBackfillSlot>, range: (u64, u64)) {
    if let Some(slot) = cursor.as_mut()
        && slot.cursor.acquisition_range() == Some(range)
    {
        slot.cursor.abandon_acquisition();
    }
}

pub(in crate::chain) fn abandon_intersecting_acquisition(
    cursor: &mut Option<WalletBackfillSlot>,
    fetched_range: PublicScanRange,
) {
    if let Some(range) = cursor
        .as_ref()
        .and_then(|slot| slot.cursor.acquisition_range())
        && fetched_range.intersects(PublicScanRange::new(range.0, range.1))
    {
        warn!(
            acquisition_from = range.0,
            acquisition_to = range.1,
            "abandoning warm wallet scan acquisition after normalization failure"
        );
        abandon_matching_acquisition(cursor, range);
    }
}

async fn wallet_scan_acquisition_candidate(
    service: &ChainService,
    (from_block, to_block): (u64, u64),
    fresh_apply: &WalletScanApply,
) -> Option<Vec<WalletScanApply>> {
    let fresh_range = PublicScanRange::new(fresh_apply.from_block, fresh_apply.to_block);
    let acquisition = PublicScanRange::new(from_block, to_block);
    let overlap_from = from_block.max(fresh_apply.from_block);
    let overlap_to = to_block.min(fresh_apply.to_block);
    let mut applies = Vec::new();
    if overlap_from > overlap_to || !fresh_range.intersects(acquisition) {
        return None;
    }
    if overlap_from > from_block {
        applies.extend(
            service
                .public_data_plane
                .cached_wallet_scan_exact(from_block, overlap_from - 1)
                .await?,
        );
    }
    let mut overlap = fresh_apply.clone();
    if overlap_from != overlap.from_block || overlap_to != overlap.to_block {
        let payload = match &overlap.rows.payload {
            WalletScanRowsPayload::Rows(rows) => {
                let mut rows = rows.as_ref().clone();
                rows.retain_block_range(overlap_from, overlap_to);
                WalletScanRowsPayload::Rows(Box::new(rows))
            }
            WalletScanRowsPayload::EmptyCoverage => WalletScanRowsPayload::EmptyCoverage,
            #[cfg(test)]
            WalletScanRowsPayload::IndexedDeltaForTest { .. } => return None,
        };
        overlap = WalletScanApply::new(
            overlap_from,
            overlap_to,
            WalletScanRows::new(
                overlap_from,
                overlap_to,
                overlap.rows.source,
                if overlap_to == fresh_apply.to_block {
                    overlap.rows.to_block_hash
                } else {
                    None
                },
                payload,
            ),
            overlap.read_scope,
        );
    }
    applies.push(overlap);
    if overlap_to < to_block {
        applies.extend(
            service
                .public_data_plane
                .cached_wallet_scan_exact(overlap_to + 1, to_block)
                .await?,
        );
    }
    Some(applies)
}

#[cfg(test)]
pub(in crate::chain) async fn drain_pending_backfill_requests(
    backfill_rx: &mut mpsc::Receiver<BackfillRequest>,
    cursor: &mut Option<WalletBackfillSlot>,
    active_actor: Option<(&str, u64)>,
) {
    while let Ok(request) = backfill_rx.try_recv() {
        apply_backfill_request(cursor, request, Instant::now(), active_actor).await;
    }
}

async fn drain_pending_backfill_requests_for_service(
    service: &ChainService,
    backfill_rx: &mut mpsc::Receiver<BackfillRequest>,
    cursor: &mut Option<WalletBackfillSlot>,
) {
    while let Ok(request) = backfill_rx.try_recv() {
        let active_actor = current_backfill_actor(service).await;
        apply_backfill_request(
            cursor,
            request,
            Instant::now(),
            active_actor.as_ref().map(|(key, id)| (key.as_str(), *id)),
        )
        .await;
    }
}

async fn current_backfill_actor(service: &ChainService) -> Option<(String, u64)> {
    let wallet = service.wallet.read().await;
    wallet.as_ref().map(|registration| {
        (
            registration.cfg.cache_key.as_str().to_string(),
            registration.handle.actor_id(),
        )
    })
}

async fn apply_backfill_request(
    cursor: &mut Option<WalletBackfillSlot>,
    request: BackfillRequest,
    now: Instant,
    active_actor: Option<(&str, u64)>,
) {
    match request {
        BackfillRequest::Add {
            cache_key,
            from_block,
            to_block,
            follow_safe_head,
            progress_start_block,
            acquisition_range,
            startup_warm_range,
            driver,
        } => {
            let incoming_token = driver.token();
            let valid_actor = active_actor.is_some_and(|(active_cache_key, active_actor_id)| {
                active_cache_key == cache_key && active_actor_id == incoming_token.actor_id()
            });
            if !valid_actor {
                driver.retire(&cache_key).await;
                return;
            }
            if let Some(previous) = cursor.as_ref()
                && previous.cache_key != cache_key
            {
                debug!(
                    cache_key = %cache_key,
                    active_cache_key = %previous.cache_key,
                    "stale wallet backfill request ignored for occupied actor slot"
                );
                driver.retire(&cache_key).await;
                return;
            }
            if let Some(previous) = cursor.as_ref()
                && previous.cache_key == cache_key
                && previous.cursor.driver.token() != incoming_token
                && !driver.supersedes(&previous.cursor.driver)
            {
                debug!(
                    cache_key = %cache_key,
                    incoming_token = ?incoming_token,
                    active_token = ?previous.cursor.driver.token(),
                    "stale wallet backfill request ignored"
                );
                driver.retire(&cache_key).await;
                return;
            }

            let previous = cursor.replace(WalletBackfillSlot {
                cache_key: cache_key.clone(),
                cursor: WalletBackfill::new(
                    from_block,
                    to_block,
                    follow_safe_head,
                    progress_start_block,
                    acquisition_range,
                    driver,
                    now,
                )
                .with_startup_warm_range(startup_warm_range),
            });
            if let Some(previous) = previous {
                previous.cursor.driver.retire(&previous.cache_key).await;
            }
        }
        BackfillRequest::Remove {
            cache_key,
            actor_id,
            response,
        } => {
            let is_current = cursor.as_ref().is_some_and(|slot| {
                slot.cache_key == cache_key && slot.cursor.driver.token().actor_id() == actor_id
            });
            if is_current && let Some(previous) = cursor.take() {
                previous.cursor.driver.retire(&cache_key).await;
            }
            let _ = response.send(());
        }
    }
}
