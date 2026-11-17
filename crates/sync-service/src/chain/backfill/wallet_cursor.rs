//! A wallet's RPC backfill cursor and its indexed tail fallback timing.

#[allow(clippy::wildcard_imports)]
use super::*;
pub(in crate::chain) struct WalletBackfill {
    pub(in crate::chain) from_block: u64,
    pub(in crate::chain) target_block: u64,
    pub(in crate::chain) follow_safe_head: bool,
    pub(in crate::chain) progress_start_block: u64,
    acquisition_range: Option<(u64, u64)>,
    retained_acquisition_range: Option<(u64, u64)>,
    retained_acquisition_restoration_used: bool,
    startup_warm_range: Option<(u64, u64)>,
    pub(in crate::chain) driver: WalletBackfillDriver,
    pub(in crate::chain) last_advanced_at: Instant,
    pub(in crate::chain) last_indexed_tail_attempt_at: Option<Instant>,
    started_at: Instant,
    run_state: WalletBackfillRunState,
}

#[derive(Clone, Copy)]
enum WalletBackfillRunState {
    Runnable,
    PersistenceBackoff { attempt: u32, retry_at: Instant },
}

const PERSISTENCE_RETRY_MIN_DELAY: Duration = Duration::from_secs(1);
const PERSISTENCE_RETRY_MAX_DELAY: Duration = Duration::from_secs(30);

pub(in crate::chain) struct WalletTailFallbackState {
    last_scanned: u64,
    last_advanced_at: Instant,
    last_indexed_tail_attempt_at: Option<Instant>,
}

impl WalletTailFallbackState {
    pub(in crate::chain) const fn new(last_scanned: u64, now: Instant) -> Self {
        Self {
            last_scanned,
            last_advanced_at: now,
            last_indexed_tail_attempt_at: None,
        }
    }

    pub(in crate::chain) const fn update_last_scanned(&mut self, last_scanned: u64, now: Instant) {
        if last_scanned != self.last_scanned {
            self.last_scanned = last_scanned;
            self.last_advanced_at = now;
        }
    }

    pub(in crate::chain) const fn mark_indexed_tail_attempt(&mut self, now: Instant) {
        self.last_indexed_tail_attempt_at = Some(now);
    }

    #[cfg(test)]
    pub(in crate::chain) const fn indexed_tail_attempt_recorded_for_test(&self) -> bool {
        self.last_indexed_tail_attempt_at.is_some()
    }

    pub(in crate::chain) fn should_try_indexed_tail_fallback(
        &self,
        block_time: Duration,
        from_block: u64,
        target_block: u64,
        now: Instant,
        min_stall: Duration,
        cooldown: Duration,
    ) -> bool {
        if from_block > target_block {
            return false;
        }
        let lag_blocks = wallet_backfill_lag_blocks(from_block, target_block);
        if lag_blocks <= wallet_tail_fallback_lag_threshold_blocks(block_time) {
            return false;
        }
        if now.duration_since(self.last_advanced_at) < min_stall {
            return false;
        }
        self.last_indexed_tail_attempt_at
            .is_none_or(|attempted_at| now.duration_since(attempted_at) >= cooldown)
    }
}

impl WalletBackfill {
    pub(in crate::chain) const fn new(
        from_block: u64,
        target_block: u64,
        follow_safe_head: bool,
        progress_start_block: u64,
        acquisition_range: Option<(u64, u64)>,
        driver: WalletBackfillDriver,
        now: Instant,
    ) -> Self {
        Self {
            from_block,
            target_block,
            follow_safe_head,
            progress_start_block,
            acquisition_range,
            retained_acquisition_range: None,
            retained_acquisition_restoration_used: false,
            startup_warm_range: None,
            driver,
            last_advanced_at: now,
            last_indexed_tail_attempt_at: None,
            started_at: now,
            run_state: WalletBackfillRunState::Runnable,
        }
    }

    pub(in crate::chain) fn refresh_target(&mut self, safe_head: u64) {
        if safe_head == 0 {
            return;
        }
        if self.follow_safe_head {
            self.target_block = self.target_block.max(safe_head);
        } else if self.target_block == 0 {
            self.target_block = safe_head;
        }
    }

    pub(in crate::chain) const fn acquisition_range(&self) -> Option<(u64, u64)> {
        self.acquisition_range
    }

    #[must_use]
    pub(in crate::chain) const fn with_startup_warm_range(
        mut self,
        startup_warm_range: Option<(u64, u64)>,
    ) -> Self {
        self.startup_warm_range = startup_warm_range;
        self
    }

    /// Hands out the startup warm range once, when the cursor is about to
    /// finish after delivering its target.
    pub(in crate::chain) const fn take_startup_warm_range(&mut self) -> Option<(u64, u64)> {
        self.startup_warm_range.take()
    }

    pub(in crate::chain) const fn retained_acquisition_range(&self) -> Option<(u64, u64)> {
        self.retained_acquisition_range
    }

    pub(in crate::chain) const fn fetch_target_block(&self) -> u64 {
        match self.acquisition_range {
            Some((_, to_block)) => to_block,
            None => self.target_block,
        }
    }

    pub(in crate::chain) fn finish_retained_acquisition(&mut self) {
        let range = self.acquisition_range;
        if range != self.retained_acquisition_range || range.is_none() {
            self.retained_acquisition_restoration_used = false;
        }
        self.retained_acquisition_range = range;
        self.acquisition_range = None;
    }

    pub(in crate::chain) const fn abandon_acquisition(&mut self) {
        self.acquisition_range = None;
        self.retained_acquisition_range = None;
        self.retained_acquisition_restoration_used = false;
    }

    pub(in crate::chain) fn restore_retained_acquisition(&mut self) -> bool {
        if let Some(range) = self.retained_acquisition_range {
            if self.acquisition_range == Some(range) {
                return true;
            }
            if self.retained_acquisition_restoration_used {
                return false;
            }
            self.acquisition_range = Some(range);
            self.retained_acquisition_restoration_used = true;
            self.last_advanced_at = Instant::now();
            return true;
        }
        false
    }

    pub(in crate::chain) const fn can_finish(&self) -> bool {
        self.acquisition_range.is_none()
            && self.target_block > 0
            && self.from_block > self.target_block
    }

    pub(in crate::chain) const fn mark_progress(&mut self, from_block: u64, now: Instant) {
        self.from_block = from_block;
        self.last_advanced_at = now;
        self.run_state = WalletBackfillRunState::Runnable;
    }

    pub(in crate::chain) const fn mark_already_covered(&mut self, from_block: u64, now: Instant) {
        self.mark_progress(from_block, now);
    }

    pub(in crate::chain) fn retry_after_rejected_apply(&mut self, committed_to: u64) {
        let retry_from = self.from_block.min(committed_to.saturating_add(1));
        self.from_block = retry_from;
    }

    pub(in crate::chain) fn retry_after_rejected_finish(&mut self, committed_to: u64) {
        let replay_from = self
            .progress_start_block
            .min(committed_to.saturating_add(1));
        self.from_block = if self.target_block == 0 {
            replay_from
        } else {
            replay_from.min(self.target_block)
        };
        self.last_indexed_tail_attempt_at = None;
    }

    pub(in crate::chain) fn is_runnable(&self, now: Instant) -> bool {
        match self.run_state {
            WalletBackfillRunState::Runnable => true,
            WalletBackfillRunState::PersistenceBackoff { retry_at, .. } => now >= retry_at,
        }
    }

    pub(in crate::chain) const fn persistence_retry_at(&self) -> Option<Instant> {
        match self.run_state {
            WalletBackfillRunState::Runnable => None,
            WalletBackfillRunState::PersistenceBackoff { retry_at, .. } => Some(retry_at),
        }
    }

    pub(in crate::chain) fn defer_persistence_retry(
        &mut self,
        now: Instant,
        poll_interval: Duration,
    ) {
        let attempt = match self.run_state {
            WalletBackfillRunState::Runnable => 0,
            WalletBackfillRunState::PersistenceBackoff { attempt, .. } => attempt.saturating_add(1),
        };
        let base_delay = poll_interval.max(PERSISTENCE_RETRY_MIN_DELAY);
        let max_delay = PERSISTENCE_RETRY_MAX_DELAY.max(base_delay);
        let multiplier = 1_u32.checked_shl(attempt.min(16)).unwrap_or(u32::MAX);
        let delay = base_delay.saturating_mul(multiplier).min(max_delay);
        let retry_at = now.checked_add(delay).unwrap_or(now);
        self.run_state = WalletBackfillRunState::PersistenceBackoff { attempt, retry_at };
    }

    /// Moves the cursor on after the wallet answered an apply: an accepted result advances it
    /// and refreshes the target to `safe_head`; a rejection rebases, backs off or restores the
    /// retained acquisition. Returns whether the cursor must be removed.
    pub(in crate::chain) fn record_apply_result(
        &mut self,
        result: &WalletBackfillApplyResult,
        safe_head: u64,
        poll_interval: Duration,
    ) -> bool {
        if let Some(committed_to) = result.accepted_committed_to() {
            match result {
                WalletBackfillApplyResult::Committed { .. } => {
                    self.mark_progress(committed_to.saturating_add(1), Instant::now());
                }
                WalletBackfillApplyResult::AlreadyCovered { .. } => {
                    self.mark_already_covered(committed_to.saturating_add(1), Instant::now());
                }
                WalletBackfillApplyResult::Rejected { .. } => unreachable!(),
            }
            self.refresh_target(safe_head);
            return false;
        }
        match *result {
            WalletBackfillApplyResult::Rejected {
                reason: WalletBackfillRejectReason::NonContiguous { expected_from, .. },
                ..
            } => self.mark_progress(expected_from, Instant::now()),
            WalletBackfillApplyResult::Rejected {
                committed_to,
                reason: WalletBackfillRejectReason::PersistenceFailed,
            } => {
                self.retry_after_rejected_apply(committed_to);
                self.defer_persistence_retry(Instant::now(), poll_interval);
            }
            WalletBackfillApplyResult::Rejected {
                reason:
                    WalletBackfillRejectReason::StaleGeneration { .. }
                    | WalletBackfillRejectReason::Shutdown,
                ..
            } => return true,
            WalletBackfillApplyResult::Rejected {
                reason: WalletBackfillRejectReason::StaleDataPlaneEpoch { .. },
                ..
            } => {
                self.restore_retained_acquisition();
            }
            WalletBackfillApplyResult::Rejected { .. }
            | WalletBackfillApplyResult::Committed { .. }
            | WalletBackfillApplyResult::AlreadyCovered { .. } => {}
        }
        false
    }

    pub(in crate::chain) const fn mark_indexed_tail_attempt(&mut self, now: Instant) {
        self.last_indexed_tail_attempt_at = Some(now);
    }

    /// Fires when RPC backfill has stalled, or when it is still advancing but
    /// more than `rpc_crawl_lag_blocks` behind its target and `cooldown` has
    /// passed since the backfill started or since the last indexed attempt.
    pub(in crate::chain) fn should_try_indexed_tail_fallback(
        &self,
        block_time: Duration,
        rpc_crawl_lag_blocks: u64,
        now: Instant,
        min_stall: Duration,
        cooldown: Duration,
    ) -> bool {
        if self.acquisition_range.is_some() {
            return false;
        }
        if self.target_block == 0 || self.from_block > self.target_block {
            return false;
        }
        let lag_blocks = wallet_backfill_lag_blocks(self.from_block, self.target_block);
        if lag_blocks <= wallet_tail_fallback_lag_threshold_blocks(block_time) {
            return false;
        }
        if now.duration_since(self.last_advanced_at) >= min_stall {
            return self
                .last_indexed_tail_attempt_at
                .is_none_or(|attempted_at| now.duration_since(attempted_at) >= cooldown);
        }
        if lag_blocks <= rpc_crawl_lag_blocks {
            return false;
        }
        let cooldown_from = self
            .last_indexed_tail_attempt_at
            .map_or(self.started_at, |attempted_at| {
                attempted_at.max(self.started_at)
            });
        now.duration_since(cooldown_from) >= cooldown
    }
}

pub(in crate::chain) const fn wallet_backfill_lag_blocks(
    from_block: u64,
    target_block: u64,
) -> u64 {
    if from_block > target_block {
        0
    } else {
        target_block.saturating_sub(from_block).saturating_add(1)
    }
}

pub(in crate::chain) fn wallet_tail_fallback_stale_timeout(block_time: Duration) -> Duration {
    block_time.saturating_mul(10).max(Duration::from_secs(45))
}

pub(in crate::chain) fn wallet_tail_fallback_lag_threshold_blocks(block_time: Duration) -> u64 {
    let threshold =
        wallet_tail_fallback_stale_timeout(block_time).as_nanos() / block_time.as_nanos().max(1);
    u64::try_from(threshold).unwrap_or(u64::MAX).max(2)
}
