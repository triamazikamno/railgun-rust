use super::logs::{
    FOREST_RPC_REQUEST_BUDGET, LogPage, LogRequestBudget, ParallelLogStats, ProviderLogStats,
    log_filter_count_for_range,
};
use super::service::send_wallet_reset;
use super::{
    BlockNumberOrTag, CancellationToken, ChainConfig, ChainError, ChainService, DbStore,
    DynProvider, FixedBytes, ForestMetaCheck, ForestReorgDecision, HashMap, HashSet, Instant, Log,
    LogRangeFetch, LogSpanEndpoint, MerkleForest, MerkleForestDbExt, MerkleForestSnapshot,
    Ordering, Path, PersistError, Provider, ProviderHandle, SNAPSHOT_VERSION, SharedLogBatch,
    WalletBackfillApplyResult, WalletBackfillDriver, WalletBackfillRejectReason,
    WalletResetReplayPlan, anchor_file_name, build_provider_with_http_client, debug,
    fetch_logs_for_range_with_provider, info, parse_anchor_block, wallet_reorg_backfill_from_block,
    wallet_sync_target, warn,
};
use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

pub(super) struct WalletBackfill {
    pub(super) from_block: u64,
    pub(super) target_block: u64,
    pub(super) follow_safe_head: bool,
    pub(super) progress_start_block: u64,
    acquisition_range: Option<(u64, u64)>,
    retained_acquisition_range: Option<(u64, u64)>,
    retained_acquisition_restoration_used: bool,
    startup_warm_range: Option<(u64, u64)>,
    pub(super) driver: WalletBackfillDriver,
    pub(super) last_advanced_at: Instant,
    pub(super) last_indexed_tail_attempt_at: Option<Instant>,
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

pub(super) struct WalletTailFallbackState {
    last_scanned: u64,
    last_advanced_at: Instant,
    last_indexed_tail_attempt_at: Option<Instant>,
}

impl WalletTailFallbackState {
    pub(super) const fn new(last_scanned: u64, now: Instant) -> Self {
        Self {
            last_scanned,
            last_advanced_at: now,
            last_indexed_tail_attempt_at: None,
        }
    }

    pub(super) const fn update_last_scanned(&mut self, last_scanned: u64, now: Instant) {
        if last_scanned != self.last_scanned {
            self.last_scanned = last_scanned;
            self.last_advanced_at = now;
        }
    }

    pub(super) const fn mark_indexed_tail_attempt(&mut self, now: Instant) {
        self.last_indexed_tail_attempt_at = Some(now);
    }

    #[cfg(test)]
    pub(super) const fn indexed_tail_attempt_recorded_for_test(&self) -> bool {
        self.last_indexed_tail_attempt_at.is_some()
    }

    pub(super) fn should_try_indexed_tail_fallback(
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
    pub(super) const fn new(
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

    pub(super) fn refresh_target(&mut self, safe_head: u64) {
        if safe_head == 0 {
            return;
        }
        if self.follow_safe_head {
            self.target_block = self.target_block.max(safe_head);
        } else if self.target_block == 0 {
            self.target_block = safe_head;
        }
    }

    pub(super) const fn acquisition_range(&self) -> Option<(u64, u64)> {
        self.acquisition_range
    }

    #[must_use]
    pub(super) const fn with_startup_warm_range(
        mut self,
        startup_warm_range: Option<(u64, u64)>,
    ) -> Self {
        self.startup_warm_range = startup_warm_range;
        self
    }

    /// Hands out the startup warm range once, when the cursor is about to
    /// finish after delivering its target.
    pub(super) const fn take_startup_warm_range(&mut self) -> Option<(u64, u64)> {
        self.startup_warm_range.take()
    }

    pub(super) const fn retained_acquisition_range(&self) -> Option<(u64, u64)> {
        self.retained_acquisition_range
    }

    pub(super) const fn fetch_target_block(&self) -> u64 {
        match self.acquisition_range {
            Some((_, to_block)) => to_block,
            None => self.target_block,
        }
    }

    pub(super) fn finish_retained_acquisition(&mut self) {
        let range = self.acquisition_range;
        if range != self.retained_acquisition_range || range.is_none() {
            self.retained_acquisition_restoration_used = false;
        }
        self.retained_acquisition_range = range;
        self.acquisition_range = None;
    }

    pub(super) const fn abandon_acquisition(&mut self) {
        self.acquisition_range = None;
        self.retained_acquisition_range = None;
        self.retained_acquisition_restoration_used = false;
    }

    pub(super) fn restore_retained_acquisition(&mut self) -> bool {
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

    pub(super) const fn can_finish(&self) -> bool {
        self.acquisition_range.is_none()
            && self.target_block > 0
            && self.from_block > self.target_block
    }

    pub(super) const fn mark_progress(&mut self, from_block: u64, now: Instant) {
        self.from_block = from_block;
        self.last_advanced_at = now;
        self.run_state = WalletBackfillRunState::Runnable;
    }

    pub(super) const fn mark_already_covered(&mut self, from_block: u64, now: Instant) {
        self.mark_progress(from_block, now);
    }

    pub(super) fn retry_after_rejected_apply(&mut self, committed_to: u64) {
        let retry_from = self.from_block.min(committed_to.saturating_add(1));
        self.from_block = retry_from;
    }

    pub(super) fn retry_after_rejected_finish(&mut self, committed_to: u64) {
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

    pub(super) fn is_runnable(&self, now: Instant) -> bool {
        match self.run_state {
            WalletBackfillRunState::Runnable => true,
            WalletBackfillRunState::PersistenceBackoff { retry_at, .. } => now >= retry_at,
        }
    }

    pub(super) const fn persistence_retry_at(&self) -> Option<Instant> {
        match self.run_state {
            WalletBackfillRunState::Runnable => None,
            WalletBackfillRunState::PersistenceBackoff { retry_at, .. } => Some(retry_at),
        }
    }

    pub(super) fn defer_persistence_retry(&mut self, now: Instant, poll_interval: Duration) {
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
    pub(super) fn record_apply_result(
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

    pub(super) const fn mark_indexed_tail_attempt(&mut self, now: Instant) {
        self.last_indexed_tail_attempt_at = Some(now);
    }

    /// Fires when RPC backfill has stalled, or when it is still advancing but
    /// more than `rpc_crawl_lag_blocks` behind its target and `cooldown` has
    /// passed since the backfill started or since the last indexed attempt.
    pub(super) fn should_try_indexed_tail_fallback(
        &self,
        block_time: Duration,
        rpc_crawl_lag_blocks: u64,
        now: Instant,
        min_stall: Duration,
        cooldown: Duration,
    ) -> bool {
        if self.acquisition_range.is_some()
            || self.target_block == 0
            || self.from_block > self.target_block
        {
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

pub(super) const fn wallet_backfill_lag_blocks(from_block: u64, target_block: u64) -> u64 {
    if from_block > target_block {
        0
    } else {
        target_block.saturating_sub(from_block).saturating_add(1)
    }
}

pub(super) fn wallet_tail_fallback_stale_timeout(block_time: Duration) -> Duration {
    block_time.saturating_mul(10).max(Duration::from_secs(45))
}

pub(super) fn wallet_tail_fallback_lag_threshold_blocks(block_time: Duration) -> u64 {
    let threshold =
        wallet_tail_fallback_stale_timeout(block_time).as_nanos() / block_time.as_nanos().max(1);
    u64::try_from(threshold).unwrap_or(u64::MAX).max(2)
}

/// The live forest's lag behind the safe head, from
/// [`ChainConfig::live_forest_lag`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ForestLag {
    pub(super) estimated_requests: u64,
    pub(super) far_behind: bool,
}

/// Why the published live forest block changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LiveForestProgressCause {
    RpcApply,
    IndexedInstall,
    StallInstall,
    ReorgReset,
}

impl LiveForestProgressCause {
    const fn as_str(self) -> &'static str {
        match self {
            Self::RpcApply => "rpc_apply",
            Self::IndexedInstall => "indexed_install",
            Self::StallInstall => "stall_install",
            Self::ReorgReset => "reorg_reset",
        }
    }
}

impl ChainService {
    /// Publishes `forest_block` on `forest_last_tx`, the only way the live
    /// forest block is published, with a "live forest progress" record. The
    /// record measures the lag from the new block to the current safe head.
    pub(super) fn publish_forest_progress(
        &self,
        forest_block: u64,
        cause: LiveForestProgressCause,
    ) {
        let safe_head = *self.safe_head_tx.borrow();
        let lag = self.chain.live_forest_lag(forest_block, safe_head);
        debug!(
            chain_id = self.chain.deployment.chain_id,
            forest_block,
            cause = cause.as_str(),
            safe_head,
            estimated_requests = lag.estimated_requests,
            far_behind = lag.far_behind,
            "live forest progress"
        );
        if let Err(err) = self.forest_last_tx.send(forest_block) {
            debug!(?err, forest_block, "failed to send forest progress update");
        }
    }

    pub(super) async fn apply_forest_updates(
        &self,
        batch: &SharedLogBatch,
    ) -> Result<(), ChainError> {
        let mut forest = self.forest.write().await;
        forest.apply_commitment_updates_from_logs(&batch.logs)?;
        forest.compute_roots();
        Ok(())
    }
    pub(super) async fn reset_forest_state(
        &self,
        snapshot_path: &Path,
        last_processed: u64,
    ) -> Result<u64, ChainError> {
        let mut forest = self.forest.write().await;
        let mut reset_block = self.chain.deployment.deployment_block.saturating_sub(1);

        if let Ok(Some((anchor_path, anchor_block))) = self.db.find_latest_anchor(&self.chain) {
            match MerkleForestSnapshot::load(
                &anchor_path,
                self.chain.deployment.chain_id,
                self.chain.deployment.contract,
            ) {
                Ok(Some(snapshot)) => {
                    *forest = snapshot.forest;
                    reset_block = snapshot.last_processed_block;
                    MerkleForestSnapshot::write(
                        snapshot_path,
                        self.chain.deployment.chain_id,
                        self.chain.deployment.contract,
                        reset_block,
                        &forest,
                    )?;
                    self.anchor_last.store(anchor_block, Ordering::Relaxed);
                    info!(
                        from = last_processed,
                        to = reset_block,
                        anchor = %anchor_path.display(),
                        "forest reset to anchor"
                    );
                }
                Ok(None) => {
                    *forest = MerkleForest::new();
                    self.anchor_last.store(0, Ordering::Relaxed);
                }
                Err(err) => {
                    warn!(?err, path = %anchor_path.display(), "failed to load anchor snapshot");
                    *forest = MerkleForest::new();
                    self.anchor_last.store(0, Ordering::Relaxed);
                }
            }
        } else {
            *forest = MerkleForest::new();
            self.anchor_last.store(0, Ordering::Relaxed);
        }

        MerkleForestSnapshot::write(
            snapshot_path,
            self.chain.deployment.chain_id,
            self.chain.deployment.contract,
            reset_block,
            &forest,
        )?;

        self.db.update_merkle_forest_meta(
            self.chain.deployment.chain_id,
            &self.chain.deployment.contract.to_string(),
            snapshot_path,
            reset_block,
            SNAPSHOT_VERSION,
            [0u8; 32],
        )?;
        self.publish_forest_progress(reset_block, LiveForestProgressCause::ReorgReset);
        self.public_data_plane
            .invalidate_public_scan_coverage_from(reset_block.saturating_add(1))
            .await;
        info!(
            from = last_processed,
            to = reset_block,
            "forest state reset"
        );
        Ok(reset_block)
    }

    pub(super) async fn reset_wallets(&self, safe_head: u64, reset_from_block: u64) {
        let _registration_guard = self.wallet_registration_gate.lock().await;
        let registration = {
            let wallet = self.wallet.read().await;
            wallet.as_ref().map(|registration| {
                (
                    registration.cfg.cache_key.clone(),
                    registration.backfill_sender.clone(),
                    registration.handle.clone(),
                    registration.start_block,
                    registration.sync_to_block,
                    registration.handle.last_scanned_raw(),
                )
            })
        };
        let Some((cache_key, backfill_sender, handle, start_block, sync_to_block, last_scanned)) =
            registration
        else {
            return;
        };
        let cache_key = cache_key.as_str();
        let from_block = wallet_reorg_backfill_from_block(reset_from_block, start_block);
        let sync_target = wallet_sync_target(safe_head, sync_to_block);
        let replay_plan =
            WalletResetReplayPlan::new(start_block, sync_target, sync_to_block.is_none());
        let reset_result = send_wallet_reset(
            cache_key,
            &backfill_sender,
            &handle,
            self.next_wallet_reset_intent(),
            from_block,
            replay_plan,
            last_scanned,
        )
        .await;
        if reset_result.reset_generation().is_none() {
            debug!(?reset_result, cache_key = %cache_key, "skipping rejected wallet reset");
            return;
        }
        debug!(?reset_result, cache_key = %cache_key, "wallet reorg reset accepted for actor-owned replay");
    }

    /// Checks the forest metadata block against `provider`, and on a confirmed
    /// reorg resets the forest and wallets.
    ///
    /// Returns the check's outcome. `Unchecked` also covers a forest below
    /// deployment and missing metadata. `Unconfirmed` means no confirmed hash
    /// was read, so a reorg can be neither ruled out nor detected. `Mismatch`
    /// means the forest and wallet reset already ran; a failed forest reset
    /// returns its error instead.
    pub(super) async fn check_forest_reorg(
        &self,
        provider: &DynProvider,
        archive_provider: Option<&DynProvider>,
        rpc_index: usize,
        snapshot_path: &Path,
        safe_head: u64,
        last_processed: u64,
    ) -> Result<ForestMetaCheck, ChainError> {
        if last_processed < self.chain.deployment.deployment_block {
            return Ok(ForestMetaCheck::Unchecked);
        }
        let meta = self.db.get_merkle_forest_meta(
            self.chain.deployment.chain_id,
            &self.chain.deployment.contract.to_string(),
        )?;
        let Some(meta) = meta else {
            return Ok(ForestMetaCheck::Unchecked);
        };

        let check = self
            .chain
            .check_forest_meta(
                provider,
                archive_provider,
                meta.last_block,
                meta.hash,
                last_processed,
            )
            .await?;
        match check {
            ForestMetaCheck::Unchecked | ForestMetaCheck::Match => {}
            ForestMetaCheck::StaleMeta => {
                warn!(
                    chain_id = self.chain.deployment.chain_id,
                    contract = %self.chain.deployment.contract,
                    rpc_index,
                    safe_head,
                    last_processed,
                    meta_last_block = meta.last_block,
                    stored_hash = %FixedBytes::<32>::from(meta.hash),
                    "skipping reorg check because forest metadata block does not match progress"
                );
            }
            ForestMetaCheck::Unconfirmed => {
                debug!(
                    chain_id = self.chain.deployment.chain_id,
                    contract = %self.chain.deployment.contract,
                    rpc_index,
                    safe_head,
                    last_processed,
                    meta_last_block = meta.last_block,
                    "skipping reorg check without a confirmed block hash"
                );
            }
            ForestMetaCheck::Mismatch { current_hash } => {
                warn!(
                    chain_id = self.chain.deployment.chain_id,
                    contract = %self.chain.deployment.contract,
                    rpc_index,
                    safe_head,
                    last_processed,
                    meta_last_block = meta.last_block,
                    stored_hash = %FixedBytes::<32>::from(meta.hash),
                    current_hash = %FixedBytes::<32>::from(current_hash),
                    "detected confirmed reorg, rewinding forest and wallet caches"
                );
                let reset_block = self
                    .reset_forest_state(snapshot_path, last_processed)
                    .await?;
                self.reset_wallets(safe_head, reset_block.saturating_add(1))
                    .await;
            }
        }
        Ok(check)
    }

    pub(super) async fn persist_forest_snapshot(
        &self,
        snapshot_path: &Path,
        last_block: u64,
        block_hash: Option<[u8; 32]>,
    ) -> Result<(), ChainError> {
        let forest = self.forest.read().await;
        MerkleForestSnapshot::write(
            snapshot_path,
            self.chain.deployment.chain_id,
            self.chain.deployment.contract,
            last_block,
            &forest,
        )?;

        self.db.update_merkle_forest_meta(
            self.chain.deployment.chain_id,
            &self.chain.deployment.contract.to_string(),
            snapshot_path,
            last_block,
            SNAPSHOT_VERSION,
            block_hash.unwrap_or([0u8; 32]),
        )?;

        self.maybe_write_anchor_snapshot(snapshot_path, last_block, &forest)?;

        Ok(())
    }

    pub(super) fn maybe_write_anchor_snapshot(
        &self,
        snapshot_path: &Path,
        last_block: u64,
        forest: &MerkleForest,
    ) -> Result<(), PersistError> {
        let interval = self.chain.sync.anchor_interval;
        if interval == 0 {
            return Ok(());
        }
        let last_anchor = self.anchor_last.load(Ordering::Relaxed);
        if last_block < last_anchor.saturating_add(interval) {
            return Ok(());
        }
        let anchor_dir = self.db.anchor_dir();
        std::fs::create_dir_all(&anchor_dir)?;
        let file_name = anchor_file_name(
            self.chain.deployment.chain_id,
            self.chain.deployment.contract,
            last_block,
        );
        let relative = DbStore::relative_blob_path("merkle_forest/anchors", &file_name);
        let path = self.db.resolve_path(&relative);
        MerkleForestSnapshot::write(
            &path,
            self.chain.deployment.chain_id,
            self.chain.deployment.contract,
            last_block,
            forest,
        )?;
        self.anchor_last.store(last_block, Ordering::Relaxed);
        if path.as_path() != snapshot_path {
            debug!(path = %path.display(), block = last_block, "wrote anchor snapshot");
        }
        if let Err(err) = self.prune_anchor_snapshots(snapshot_path) {
            warn!(?err, "failed to prune anchor snapshots");
        }
        Ok(())
    }

    pub(super) fn prune_anchor_snapshots(&self, snapshot_path: &Path) -> Result<(), PersistError> {
        let retention = self.chain.sync.anchor_retention;
        if retention == 0 {
            return Ok(());
        }
        let anchor_dir = self.db.anchor_dir();
        if !anchor_dir.exists() {
            return Ok(());
        }
        let mut anchors = Vec::with_capacity(retention + 8);
        for entry in std::fs::read_dir(&anchor_dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if let Some(block) = parse_anchor_block(
                self.chain.deployment.chain_id,
                self.chain.deployment.contract,
                name,
            ) {
                anchors.push((entry.path(), block));
            }
        }
        if anchors.len() <= retention {
            return Ok(());
        }
        anchors.sort_by_key(|(_, block)| *block);
        let mut keep = HashSet::new();
        for (path, _) in anchors.iter().rev().take(retention) {
            keep.insert(path.clone());
        }
        if snapshot_path.starts_with(&anchor_dir) {
            keep.insert(snapshot_path.to_path_buf());
        }
        for (path, block) in anchors {
            if keep.contains(&path) {
                continue;
            }
            match std::fs::remove_file(&path) {
                Ok(()) => {
                    debug!(path = %path.display(), block, "pruned anchor snapshot");
                }
                Err(err) => {
                    warn!(?err, path = %path.display(), block, "failed to prune anchor snapshot");
                }
            }
        }
        Ok(())
    }
}

impl ChainConfig {
    pub(super) const fn archive_boundary_crossed_by(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Option<u64> {
        if self.sync.archive_until_block > 0
            && from_block <= self.sync.archive_until_block
            && to_block > self.sync.archive_until_block
        {
            Some(self.sync.archive_until_block)
        } else {
            None
        }
    }

    /// Builds the configured archive provider over `archive_rpc_http_client`,
    /// else `fallback_client`, else `http_client`.
    pub(super) async fn build_archive_provider(
        &self,
        fallback_client: Option<&reqwest::Client>,
    ) -> Result<Option<DynProvider>, ChainError> {
        let Some(url) = self.archive_rpc_url.as_ref() else {
            return Ok(None);
        };
        let client = self
            .archive_rpc_http_client
            .as_ref()
            .or(fallback_client)
            .unwrap_or(&self.http_client);
        build_provider_with_http_client(url, Some(client))
            .await
            .map(Some)
            .map_err(ChainError::ProviderBuild)
    }

    /// Returns the archive provider that serves reads at or below
    /// `archive_until_block`, or `None` when no archive endpoint is configured
    /// and the regular provider serves them. A configured archive endpoint the
    /// pool has not admitted fails the read without contacting any endpoint.
    fn admitted_archive_provider<'a>(
        &self,
        archive_provider: Option<&'a DynProvider>,
    ) -> Result<Option<&'a DynProvider>, ChainError> {
        match archive_provider {
            Some(_) if !self.rpcs.archive_admitted() => Err(ChainError::ArchiveRpcUnverified),
            archive_provider => Ok(archive_provider),
        }
    }

    /// Checks the forest metadata `(meta_last_block, stored_hash)` against the
    /// hash of `last_processed`. Reads the hash only when the forest is past
    /// deployment and the metadata records a hash for `last_processed`. One
    /// read returning the stored hash is a match; a different hash must be
    /// confirmed by the next read before it counts as a mismatch.
    /// Shared by the reorg check and the startup catch-up gate.
    pub(super) async fn check_forest_meta(
        &self,
        provider: &DynProvider,
        archive_provider: Option<&DynProvider>,
        meta_last_block: u64,
        stored_hash: [u8; 32],
        last_processed: u64,
    ) -> Result<ForestMetaCheck, ChainError> {
        if last_processed < self.deployment.deployment_block || stored_hash == [0u8; 32] {
            return Ok(ForestMetaCheck::Unchecked);
        }
        if meta_last_block != last_processed {
            return Ok(ForestMetaCheck::StaleMeta);
        }
        let current_hash = match self
            .fetch_block_hash(provider, archive_provider, last_processed)
            .await?
        {
            Some(first_hash) if first_hash == stored_hash => return Ok(ForestMetaCheck::Match),
            Some(first_hash) => {
                self.confirm_block_hash(provider, archive_provider, last_processed, first_hash)
                    .await?
            }
            None => None,
        };
        let decision = ForestReorgDecision::from_confirmed_hash(
            last_processed,
            meta_last_block,
            stored_hash,
            current_hash,
        );
        Ok(match decision {
            ForestReorgDecision::Skip => ForestMetaCheck::Unconfirmed,
            ForestReorgDecision::Match => ForestMetaCheck::Match,
            ForestReorgDecision::Mismatch => ForestMetaCheck::Mismatch {
                current_hash: current_hash.expect("mismatch requires confirmed hash"),
            },
        })
    }

    pub(super) async fn fetch_confirmed_block_hash(
        &self,
        provider: &DynProvider,
        archive_provider: Option<&DynProvider>,
        block_number: u64,
    ) -> Result<Option<[u8; 32]>, ChainError> {
        let Some(first_hash) = self
            .fetch_block_hash(provider, archive_provider, block_number)
            .await?
        else {
            return Ok(None);
        };
        self.confirm_block_hash(provider, archive_provider, block_number, first_hash)
            .await
    }

    /// Makes a second read of `block_number` and returns `first_hash` only
    /// when it agrees.
    async fn confirm_block_hash(
        &self,
        provider: &DynProvider,
        archive_provider: Option<&DynProvider>,
        block_number: u64,
        first_hash: [u8; 32],
    ) -> Result<Option<[u8; 32]>, ChainError> {
        let Some(second_hash) = self
            .fetch_block_hash(provider, archive_provider, block_number)
            .await?
        else {
            debug!(
                block_number,
                "block hash confirmation read returned no block"
            );
            return Ok(None);
        };

        if second_hash != first_hash {
            debug!(
                block_number,
                first_hash = %FixedBytes::<32>::from(first_hash),
                second_hash = %FixedBytes::<32>::from(second_hash),
                "block hash changed between confirmation reads"
            );
            return Ok(None);
        }

        Ok(Some(first_hash))
    }

    pub(super) async fn fetch_block_hash(
        &self,
        provider: &DynProvider,
        archive_provider: Option<&DynProvider>,
        block_number: u64,
    ) -> Result<Option<[u8; 32]>, ChainError> {
        let provider =
            if self.sync.archive_until_block > 0 && block_number <= self.sync.archive_until_block {
                self.admitted_archive_provider(archive_provider)?
                    .unwrap_or(provider)
            } else {
                provider
            };
        let block = provider
            .get_block_by_number(BlockNumberOrTag::Number(block_number))
            .await?;
        Ok(block.map(|block| block.header.hash.0))
    }

    pub(super) async fn fetch_block_timestamp(
        &self,
        provider: &DynProvider,
        archive_provider: Option<&DynProvider>,
        block_number: u64,
    ) -> Result<Option<u64>, ChainError> {
        let provider =
            if self.sync.archive_until_block > 0 && block_number <= self.sync.archive_until_block {
                self.admitted_archive_provider(archive_provider)?
                    .unwrap_or(provider)
            } else {
                provider
            };
        let block = provider
            .get_block_by_number(BlockNumberOrTag::Number(block_number))
            .await?;
        Ok(block.map(|block| block.header.timestamp))
    }

    /// Maps each log block to its timestamp, preferring nonzero timestamps supplied
    /// with the logs and requesting headers only for blocks without one.
    pub(super) async fn fetch_log_block_timestamps(
        &self,
        provider: &DynProvider,
        archive_provider: Option<&DynProvider>,
        logs: &[Log],
    ) -> Result<HashMap<u64, u64>, ChainError> {
        let started = Instant::now();
        let mut timestamps = HashMap::new();
        for log in logs {
            // A zero log timestamp is missing metadata, not the note's creation time.
            if let (Some(block_number), Some(timestamp)) = (log.block_number, log.block_timestamp)
                && timestamp != 0
            {
                timestamps.entry(block_number).or_insert(timestamp);
            }
        }
        let blocks_from_logs = timestamps.len();

        let mut missing_blocks = logs
            .iter()
            .filter_map(|log| log.block_number)
            .filter(|block_number| !timestamps.contains_key(block_number))
            .collect::<Vec<_>>();
        missing_blocks.sort_unstable();
        missing_blocks.dedup();
        let headers_requested = missing_blocks.len();

        for block_number in missing_blocks {
            if let Some(timestamp) = self
                .fetch_block_timestamp(provider, archive_provider, block_number)
                .await?
            {
                timestamps.insert(block_number, timestamp);
            }
        }
        debug!(
            logs = logs.len(),
            blocks_from_logs,
            headers_requested,
            elapsed_ms = started.elapsed().as_millis(),
            "log block timestamp coverage"
        );
        Ok(timestamps)
    }

    /// Fetches the logical range `from_block..=to_block` from `rpc`, and from
    /// the archive provider for blocks at or below `archive_until_block`.
    ///
    /// Physical `eth_getLogs` requests adapt to each endpoint's range limits;
    /// the returned log set is that of the whole logical range.
    pub(super) async fn fetch_logs_for_range(
        &self,
        rpc: &ProviderHandle,
        archive_provider: Option<&DynProvider>,
        from_block: u64,
        to_block: u64,
        cancel: &CancellationToken,
    ) -> Result<Vec<Log>, ChainError> {
        let started = Instant::now();
        let mut fetch = LogRangeFetch {
            spans: self.rpcs.as_ref(),
            max_span: self.sync.block_range,
            cancel,
            logical_from: from_block,
            logical_to: to_block,
            get_logs_requests: 0,
            budget: None,
        };
        let result = self
            .fetch_logs_for_logical_range(&mut fetch, rpc, archive_provider)
            .await;
        debug!(
            from_block,
            to_block,
            rpc_index = rpc.index,
            get_logs_requests = fetch.get_logs_requests,
            logs = result.as_ref().map_or(0, Vec::len),
            ok = result.is_ok(),
            elapsed_ms = started.elapsed().as_millis(),
            "logical log range fetch finished"
        );
        result
    }

    async fn fetch_logs_for_logical_range(
        &self,
        fetch: &mut LogRangeFetch<'_>,
        rpc: &ProviderHandle,
        archive_provider: Option<&DynProvider>,
    ) -> Result<Vec<Log>, ChainError> {
        let (from_block, to_block) = (fetch.logical_from, fetch.logical_to);
        let rpc_endpoint = LogSpanEndpoint::Provider(rpc.index);
        let mut logs = Vec::new();
        let archive_until_block = self.sync.archive_until_block;

        if archive_until_block > 0 && from_block <= archive_until_block {
            let archive_end = to_block.min(archive_until_block);
            let (archive_provider, archive_endpoint) = self
                .admitted_archive_provider(archive_provider)?
                .map_or((&rpc.provider, rpc_endpoint), |provider| {
                    (provider, LogSpanEndpoint::Archive)
                });
            let archive_logs = fetch_logs_for_range_with_provider(
                fetch,
                archive_provider,
                archive_endpoint,
                self.deployment.contract,
                from_block,
                archive_end,
                self.deployment.v2_start_block,
                self.deployment.legacy_shield_block,
            )
            .await?;
            logs.extend(archive_logs);
        }

        if to_block > archive_until_block {
            let standard_start = if archive_until_block > 0 {
                from_block.max(archive_until_block + 1)
            } else {
                from_block
            };
            let standard_logs = fetch_logs_for_range_with_provider(
                fetch,
                &rpc.provider,
                rpc_endpoint,
                self.deployment.contract,
                standard_start,
                to_block,
                self.deployment.v2_start_block,
                self.deployment.legacy_shield_block,
            )
            .await?;
            logs.extend(standard_logs);
        }

        Ok(logs)
    }

    /// Estimates the physical `eth_getLogs` requests needed for
    /// `from_block..=to_block` without issuing any request: one request per
    /// span and filter, using the widest span learned for any available
    /// provider, capped at `block_range`.
    pub(super) fn estimate_log_requests(&self, from_block: u64, to_block: u64) -> u64 {
        if from_block > to_block {
            return 0;
        }
        let span = self
            .rpcs
            .available_providers()
            .iter()
            .map(|rpc| {
                self.rpcs
                    .log_span(LogSpanEndpoint::Provider(rpc.index), self.sync.block_range)
            })
            .max()
            .unwrap_or_else(|| self.sync.block_range.max(1));
        let filters = log_filter_count_for_range(
            from_block,
            to_block,
            self.deployment.v2_start_block,
            self.deployment.legacy_shield_block,
        );
        ((to_block - from_block) / span + 1).saturating_mul(filters)
    }

    /// Measures the live forest's lag from `forest_block` to `safe_head` in
    /// estimated `eth_getLogs` requests. The lag is far behind when the
    /// estimate exceeds the forest RPC request budget.
    pub(super) fn live_forest_lag(&self, forest_block: u64, safe_head: u64) -> ForestLag {
        let estimated_requests =
            self.estimate_log_requests(forest_block.saturating_add(1), safe_head);
        ForestLag {
            estimated_requests,
            far_behind: estimated_requests > FOREST_RPC_REQUEST_BUDGET,
        }
    }

    /// Fetches `from_block..=to_block` as consecutive pages of `block_range`
    /// blocks from up to `parallelism` providers at a time, passing each page
    /// to `deliver` in block order.
    ///
    /// Each available provider is tried at most once. It reads its head first
    /// and fetches pages only when the head, less the finality depth, covers
    /// `to_block`, one page at a time. A provider whose head lags, whose head
    /// read fails, or that fails a page stops, and the next untried available
    /// provider takes its place. A failed page goes back to the queue and the
    /// endpoint failure rules apply to its provider. At most `2 * parallelism`
    /// pages are fetched ahead of the next page to deliver.
    ///
    /// Physical requests are reserved on the caller's `budget`, and the
    /// returned `get_logs_requests` is its issued count afterwards. The
    /// acquisition fails with `NoHealthyRpc` once pages remain but no provider
    /// is running and none is left to try, once `budget` is exhausted, or when
    /// `cancel` fires. The range must lie above `archive_until_block`.
    pub(super) async fn fetch_logs_in_parallel(
        &self,
        from_block: u64,
        to_block: u64,
        parallelism: usize,
        budget: &LogRequestBudget,
        cancel: &CancellationToken,
        mut deliver: impl FnMut(LogPage) -> Result<(), ChainError>,
    ) -> (Result<(), ChainError>, ParallelLogStats) {
        let started = Instant::now();
        let mut stats = ParallelLogStats::default();
        let result = self
            .run_parallel_log_fetch(
                from_block,
                to_block,
                parallelism,
                budget,
                cancel,
                &mut deliver,
                &mut stats,
            )
            .await;
        stats.get_logs_requests = budget.issued();
        stats.elapsed = started.elapsed();
        let outcome = match &result {
            Ok(()) => "complete",
            Err(ChainError::LogFetchCancelled) => "cancelled",
            Err(ChainError::LogRequestBudgetExceeded(_)) => "over_budget",
            Err(ChainError::NoHealthyRpc) => "no_provider",
            Err(_) => "failed",
        };
        // Per provider index: fetched pages / physical requests.
        let providers = stats
            .providers
            .iter()
            .map(|provider| {
                format!(
                    "{}:{}/{}",
                    provider.rpc_index, provider.pages, provider.get_logs_requests
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        debug!(
            from_block,
            to_block,
            pages = stats.pages,
            delivered_pages = stats.delivered_pages,
            eligible_providers = stats.eligible_providers,
            get_logs_requests = stats.get_logs_requests,
            request_budget = budget.limit(),
            retries = stats.retries,
            providers = %providers,
            outcome,
            elapsed_ms = stats.elapsed.as_millis(),
            "parallel log range fetch finished"
        );
        (result, stats)
    }

    async fn run_parallel_log_fetch<F>(
        &self,
        from_block: u64,
        to_block: u64,
        parallelism: usize,
        budget: &LogRequestBudget,
        cancel: &CancellationToken,
        deliver: &mut F,
        stats: &mut ParallelLogStats,
    ) -> Result<(), ChainError>
    where
        F: FnMut(LogPage) -> Result<(), ChainError>,
    {
        let archive_until_block = self.sync.archive_until_block;
        if archive_until_block > 0 && from_block <= archive_until_block {
            return Err(ChainError::ArchiveRpcRequired(archive_until_block));
        }
        if from_block > to_block {
            return Ok(());
        }
        let page_span = self.sync.block_range.max(1);
        let page_bounds = |page: u64| {
            let start = from_block + page * page_span;
            (start, start.saturating_add(page_span - 1).min(to_block))
        };
        stats.pages = (to_block - from_block) / page_span + 1;
        let parallelism = parallelism.max(1);
        let window = u64::try_from(parallelism)
            .unwrap_or(u64::MAX)
            .saturating_mul(2);

        let mut tasks = FuturesUnordered::new();
        // Provider indexes that were given a slot; none is tried twice.
        let mut tried = BTreeSet::new();
        let mut idle = Vec::new();
        let mut failed_pages = BTreeSet::new();
        let mut next_page = 0;
        let mut completed = BTreeMap::new();

        loop {
            while let Some(logs) = completed.remove(&stats.delivered_pages) {
                let (_, to_block) = page_bounds(stats.delivered_pages);
                deliver(LogPage { to_block, logs })?;
                stats.delivered_pages += 1;
            }
            if stats.delivered_pages == stats.pages {
                return Ok(());
            }
            if cancel.is_cancelled() {
                return Err(ChainError::LogFetchCancelled);
            }
            // Fill free slots, including those of stopped providers, with
            // untried providers.
            while tasks.len() + idle.len() < parallelism {
                let Some(rpc) = self
                    .rpcs
                    .available_providers()
                    .into_iter()
                    .find(|rpc| !tried.contains(&rpc.index))
                else {
                    break;
                };
                tried.insert(rpc.index);
                stats.providers.push(ProviderLogStats {
                    rpc_index: rpc.index,
                    pages: 0,
                    get_logs_requests: 0,
                });
                tasks.push(self.run_log_pager_task(rpc, LogPagerTask::Head, budget, cancel));
            }
            while let Some(rpc) = idle.pop() {
                let page = if let Some(page) = failed_pages.pop_first() {
                    page
                } else if next_page < stats.pages
                    && next_page < stats.delivered_pages.saturating_add(window)
                {
                    next_page += 1;
                    next_page - 1
                } else {
                    idle.push(rpc);
                    break;
                };
                let (from_block, to_block) = page_bounds(page);
                let task = LogPagerTask::Page {
                    page,
                    from_block,
                    to_block,
                };
                tasks.push(self.run_log_pager_task(rpc, task, budget, cancel));
            }

            let Some((rpc, outcome)) = tasks.next().await else {
                return Err(ChainError::NoHealthyRpc);
            };
            let (err, failed_page) = match outcome {
                LogPagerOutcome::Head(Ok(head)) => {
                    if head.saturating_sub(self.finality_depth) >= to_block {
                        stats.eligible_providers += 1;
                        idle.push(rpc);
                    } else {
                        debug!(
                            rpc_index = rpc.index,
                            head,
                            to_block,
                            "log provider head does not cover the parallel fetch range"
                        );
                    }
                    continue;
                }
                LogPagerOutcome::Head(Err(err)) => (err, None),
                LogPagerOutcome::Page {
                    page,
                    get_logs_requests,
                    result,
                } => {
                    let provider = stats
                        .providers
                        .iter_mut()
                        .find(|provider| provider.rpc_index == rpc.index);
                    if let Some(provider) = provider {
                        provider.get_logs_requests += get_logs_requests;
                        provider.pages += u64::from(result.is_ok());
                    }
                    match result {
                        Ok(logs) => {
                            completed.insert(page, logs);
                            idle.push(rpc);
                            continue;
                        }
                        Err(err) => (err, Some(page)),
                    }
                }
            };
            if matches!(
                err,
                ChainError::LogFetchCancelled | ChainError::LogRequestBudgetExceeded(_)
            ) {
                return Err(err);
            }
            let marked_bad = err.should_mark_rpc_unhealthy();
            if marked_bad {
                self.rpcs.mark_bad_provider(&rpc);
            }
            if let Some(page) = failed_page {
                failed_pages.insert(page);
                stats.retries += 1;
            }
            debug!(
                rpc_index = rpc.index,
                page = ?failed_page,
                marked_bad,
                err = %err.without_url(),
                "parallel log fetch provider failed; its page returns to the queue"
            );
        }
    }

    /// Runs one step of a parallel log fetch on `rpc` and hands the provider
    /// back with the outcome.
    async fn run_log_pager_task(
        &self,
        rpc: ProviderHandle,
        task: LogPagerTask,
        budget: &LogRequestBudget,
        cancel: &CancellationToken,
    ) -> (ProviderHandle, LogPagerOutcome) {
        let outcome = match task {
            LogPagerTask::Head => LogPagerOutcome::Head(tokio::select! {
                biased;
                () = cancel.cancelled() => Err(ChainError::LogFetchCancelled),
                head = rpc.provider.get_block_number() => head.map_err(ChainError::from),
            }),
            LogPagerTask::Page {
                page,
                from_block,
                to_block,
            } => {
                let mut fetch = LogRangeFetch {
                    spans: self.rpcs.as_ref(),
                    max_span: self.sync.block_range,
                    cancel,
                    logical_from: from_block,
                    logical_to: to_block,
                    get_logs_requests: 0,
                    budget: Some(budget),
                };
                let result = self
                    .fetch_logs_for_logical_range(&mut fetch, &rpc, None)
                    .await;
                LogPagerOutcome::Page {
                    page,
                    get_logs_requests: fetch.get_logs_requests,
                    result,
                }
            }
        };
        (rpc, outcome)
    }
}

/// One step a provider takes in a parallel log fetch.
#[derive(Clone, Copy)]
enum LogPagerTask {
    /// Read the head once, before any page.
    Head,
    Page {
        page: u64,
        from_block: u64,
        to_block: u64,
    },
}

enum LogPagerOutcome {
    Head(Result<u64, ChainError>),
    Page {
        page: u64,
        get_logs_requests: u64,
        result: Result<Vec<Log>, ChainError>,
    },
}

#[cfg(test)]
mod tests;
