//! Startup-sync block-range helpers and startup event delivery.

use super::{
    BackfillEvent, CancellationToken, Future, WalletBackfillApplyResult,
    WalletBackfillFinishResult, WalletBackfillStartResult, WalletHandle, WalletScanApply,
    WalletStartupSyncError, debug, mpsc,
};

pub(in crate::chain) const fn artifact_failure_can_fallback_to_squid(
    using_artifact: bool,
    checkpoint: u64,
    last_scanned: u64,
) -> bool {
    using_artifact && checkpoint == last_scanned
}

pub(in crate::chain) fn wallet_backfill_from_block(last_scanned: u64, start_block: u64) -> u64 {
    last_scanned.saturating_add(1).max(start_block)
}

pub(in crate::chain) fn wallet_startup_warm_from_block(
    start_block: u64,
    sync_target: u64,
    block_range: u64,
) -> u64 {
    sync_target
        .saturating_sub(block_range.saturating_sub(1))
        .max(start_block)
}

pub(in crate::chain) fn wallet_remote_target_before_cached_suffix(
    sync_target: u64,
    cached_suffix_from: Option<u64>,
) -> u64 {
    cached_suffix_from.map_or(sync_target, |from_block| from_block.saturating_sub(1))
}

pub(in crate::chain) fn wallet_reorg_backfill_from_block(
    reset_from_block: u64,
    start_block: u64,
) -> u64 {
    reset_from_block.max(start_block)
}

pub(in crate::chain) fn wallet_sync_target(safe_head: u64, sync_to_block: Option<u64>) -> u64 {
    match sync_to_block {
        Some(sync_to_block) if safe_head == 0 => sync_to_block,
        Some(sync_to_block) => sync_to_block.min(safe_head),
        None => safe_head,
    }
}

pub(in crate::chain) const fn squid_tail_target_after_artifact(
    from_block: u64,
    artifact_target: u64,
    safe_head: u64,
    squid_height: u64,
) -> Option<u64> {
    if artifact_target >= safe_head {
        return None;
    }
    let target = if squid_height < safe_head {
        squid_height
    } else {
        safe_head
    };
    if from_block <= target {
        Some(target)
    } else {
        None
    }
}

pub(in crate::chain) fn wallet_startup_hedge_block_count(
    last_scanned: u64,
    start_block: u64,
    sync_target: u64,
) -> Option<u64> {
    if sync_target == 0 {
        return None;
    }
    let from_block = wallet_backfill_from_block(last_scanned, start_block);
    if from_block > sync_target {
        return None;
    }
    Some(sync_target.saturating_sub(from_block).saturating_add(1))
}

pub(in crate::chain) fn should_hedge_wallet_startup(
    last_scanned: u64,
    start_block: u64,
    sync_target: u64,
    block_range: u64,
) -> bool {
    block_range > 0
        && wallet_startup_hedge_block_count(last_scanned, start_block, sync_target)
            .is_some_and(|block_count| block_count <= block_range)
}

pub(in crate::chain) async fn wait_or_cancel<T>(
    cancel: &CancellationToken,
    future: impl Future<Output = T>,
) -> Result<T, WalletStartupSyncError> {
    tokio::select! {
        result = future => Ok(result),
        () = cancel.cancelled() => Err(WalletStartupSyncError::Cancelled),
    }
}

pub(in crate::chain) async fn send_wallet_startup_events(
    cache_key: &str,
    applies: Vec<WalletScanApply>,
    done_block: Option<u64>,
    progress: crate::types::WalletSchedulableProgress,
    sender: &mpsc::Sender<BackfillEvent>,
    handle: &WalletHandle,
) -> bool {
    let target_block =
        done_block.unwrap_or_else(|| applies.last().map_or(0, |apply| apply.to_block));
    let mut driver = if target_block > 0 {
        match handle
            .start_backfill(cache_key, sender, progress, target_block)
            .await
        {
            WalletBackfillStartResult::Accepted { grant, .. } => Some(grant.activate()),
            WalletBackfillStartResult::Rejected { .. } => return false,
        }
    } else {
        None
    };
    for apply in applies {
        let result = if let Some(driver) = driver.as_ref() {
            driver.apply(cache_key, apply).await
        } else {
            let target_block = apply.to_block;
            match handle
                .start_backfill(cache_key, sender, progress, target_block)
                .await
            {
                WalletBackfillStartResult::Accepted { grant, .. } => {
                    let driver = grant.activate();
                    let result = driver.apply(cache_key, apply).await;
                    driver.retire(cache_key).await;
                    result
                }
                WalletBackfillStartResult::Rejected {
                    committed_to,
                    reason,
                } => WalletBackfillApplyResult::Rejected {
                    committed_to,
                    reason,
                },
            }
        };
        match result {
            WalletBackfillApplyResult::Committed { .. }
            | WalletBackfillApplyResult::AlreadyCovered { .. } => {}
            WalletBackfillApplyResult::Rejected { reason, .. } => {
                debug!(?reason, cache_key, "wallet startup scan batch rejected");
                if let Some(driver) = driver.take() {
                    driver.retire(cache_key).await;
                }
                return false;
            }
        }
    }
    if let Some(last_block) = done_block
        && !matches!(
            driver
                .as_ref()
                .expect("startup done block has an active driver")
                .finish(cache_key, last_block)
                .await,
            WalletBackfillFinishResult::Ready { .. }
        )
    {
        debug!(cache_key, last_block, "wallet startup finish rejected");
        if let Some(driver) = driver.take() {
            driver.retire(cache_key).await;
        }
        return false;
    }
    if done_block.is_none()
        && target_block > 0
        && let Some(driver) = driver.take()
    {
        driver.retire(cache_key).await;
    }
    true
}
