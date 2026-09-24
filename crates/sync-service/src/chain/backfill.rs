use super::logs::{
    LogPage, LogRequestBudget, ParallelLogStats, ProviderLogStats, log_filter_count_for_range,
};
use super::service::send_wallet_reset;
use super::{
    BlockNumberOrTag, CancellationToken, ChainConfig, ChainError, ChainService, DbStore,
    DynProvider, FixedBytes, ForestMetaCheck, ForestReorgDecision, HashMap, HashSet, Instant, Log,
    LogRangeFetch, LogSpanEndpoint, MerkleForest, MerkleForestDbExt, MerkleForestSnapshot,
    Ordering, Path, PersistError, Provider, ProviderHandle, SNAPSHOT_VERSION, SharedLogBatch,
    WalletBackfillDriver, WalletResetReplayPlan, anchor_file_name, debug,
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

impl ChainService {
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
        if let Err(err) = self.forest_last_tx.send(reset_block) {
            debug!(?err, reset_block, "failed to send forest reset update");
        }
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

    pub(super) async fn check_forest_reorg(
        &self,
        provider: &DynProvider,
        archive_provider: Option<&DynProvider>,
        rpc_index: usize,
        snapshot_path: &Path,
        safe_head: u64,
        last_processed: u64,
    ) -> Result<(), ChainError> {
        if last_processed < self.chain.deployment.deployment_block {
            return Ok(());
        }
        let meta = self.db.get_merkle_forest_meta(
            self.chain.deployment.chain_id,
            &self.chain.deployment.contract.to_string(),
        )?;
        let Some(meta) = meta else {
            return Ok(());
        };

        match self
            .chain
            .check_forest_meta(
                provider,
                archive_provider,
                meta.last_block,
                meta.hash,
                last_processed,
            )
            .await?
        {
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
        Ok(())
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
    /// confirmed hash of `last_processed`. Reads the hash only when the forest
    /// is past deployment and the metadata records a hash for `last_processed`.
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
        let current_hash = self
            .fetch_confirmed_block_hash(provider, archive_provider, last_processed)
            .await?;
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

    /// Maps each log block to its timestamp, preferring timestamps supplied
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
            if let (Some(block_number), Some(timestamp)) = (log.block_number, log.block_timestamp) {
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
mod tests {
    use super::*;

    use super::super::{Address, Arc, QueryRpcPool};
    use broadcaster_core::query_rpc_pool::RpcAdmission;

    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    use super::super::logs::{FOREST_RPC_PARALLELISM, FOREST_RPC_REQUEST_BUDGET, sort_logs};
    use serde_json::json;
    use url::Url;

    struct MockJsonRpc {
        url: Url,
        requests: Arc<AtomicUsize>,
    }

    #[tokio::test]
    async fn archive_range_log_fetch_uses_regular_rpc_when_archive_provider_missing() {
        let mock = spawn_json_rpc_server(1);
        let mut chain = chain_config(mock.url.clone());
        chain.deployment.deployment_block = 100;
        chain.sync.archive_until_block = 150;
        chain.deployment.v2_start_block = 200;
        chain.deployment.legacy_shield_block = 250;

        let rpc = chain.rpcs.random_provider().expect("rpc provider");

        let logs = chain
            .fetch_logs_for_range(&rpc, None, 100, 120, &CancellationToken::new())
            .await
            .expect("regular RPC should be used for archive range");

        assert!(logs.is_empty());
        assert_eq!(mock.requests.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn archive_range_reads_wait_for_archive_admission_without_fallback() {
        let regular = spawn_json_rpc_server(1);
        let archive_mock = spawn_json_rpc_server(3);
        let mut chain = chain_config(regular.url.clone());
        chain.rpcs = Arc::new(
            QueryRpcPool::new(vec![regular.url.clone()], Duration::from_secs(1))
                .with_pending_archive(),
        );
        chain.deployment.deployment_block = 100;
        chain.sync.archive_until_block = 150;
        chain.deployment.v2_start_block = 200;
        chain.deployment.legacy_shield_block = 250;

        let rpc = chain.rpcs.random_provider().expect("rpc provider");
        let archive = broadcaster_core::provider::build_provider(&archive_mock.url)
            .await
            .expect("archive provider");
        let cancel = CancellationToken::new();

        let logs = chain
            .fetch_logs_for_range(&rpc, Some(&archive), 100, 120, &cancel)
            .await;
        assert!(
            matches!(logs, Err(ChainError::ArchiveRpcUnverified)),
            "{logs:?}"
        );
        let hash = chain
            .fetch_block_hash(&rpc.provider, Some(&archive), 120)
            .await;
        assert!(
            matches!(hash, Err(ChainError::ArchiveRpcUnverified)),
            "{hash:?}"
        );
        let timestamp = chain
            .fetch_block_timestamp(&rpc.provider, Some(&archive), 120)
            .await;
        assert!(
            matches!(timestamp, Err(ChainError::ArchiveRpcUnverified)),
            "{timestamp:?}"
        );
        assert_eq!(archive_mock.requests.load(Ordering::SeqCst), 0);
        assert_eq!(regular.requests.load(Ordering::SeqCst), 0);

        chain.rpcs.set_archive_admission(RpcAdmission::Admitted);
        let logs = chain
            .fetch_logs_for_range(&rpc, Some(&archive), 100, 120, &cancel)
            .await
            .expect("admitted archive serves archive-range logs");
        assert!(logs.is_empty());
        let hash = chain
            .fetch_block_hash(&rpc.provider, Some(&archive), 120)
            .await
            .expect("admitted archive serves archive-range block hash");
        assert_eq!(hash, None);
        let timestamp = chain
            .fetch_block_timestamp(&rpc.provider, Some(&archive), 120)
            .await
            .expect("admitted archive serves archive-range block timestamp");
        assert_eq!(timestamp, None);
        assert_eq!(archive_mock.requests.load(Ordering::SeqCst), 3);
        assert_eq!(regular.requests.load(Ordering::SeqCst), 0);
    }

    fn chain_config(rpc_url: Url) -> ChainConfig {
        ChainConfig {
            deployment: broadcaster_core::deployment::RailgunDeployment {
                chain_id: 1,
                contract: Address::ZERO,
                deployment_block: 1,
                v2_start_block: 1,
                legacy_shield_block: 1,
                relay_adapt_contract: Address::ZERO,
                relay_adapt_7702_contract: Address::ZERO,
            },
            sync: crate::RailgunSyncOptions {
                archive_until_block: 0,
                block_range: 100,
                indexed_wallet_block_range: 100,
                poll_interval: Duration::from_secs(1),
                quick_sync_endpoint: None,
                indexed_artifact_source: None,
                anchor_interval: 100,
                anchor_retention: 2,
            },
            rpcs: Arc::new(QueryRpcPool::new(vec![rpc_url], Duration::from_secs(1))),
            archive_rpc_url: None,
            block_time: Duration::from_secs(12),
            finality_depth: 1,
            http_client: reqwest::Client::new(),
            progress_tx: None,
        }
    }

    fn spawn_json_rpc_server(expected_requests: usize) -> MockJsonRpc {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock RPC");
        let url = Url::parse(&format!(
            "http://{}",
            listener.local_addr().expect("local addr")
        ))
        .expect("mock RPC URL");
        let requests = Arc::new(AtomicUsize::new(0));
        let server_requests = Arc::clone(&requests);
        thread::spawn(move || {
            for stream in listener.incoming().take(expected_requests) {
                let mut stream = stream.expect("accept mock RPC request");
                let mut buffer = [0_u8; 8192];
                let read = stream.read(&mut buffer).expect("read mock RPC request");
                assert!(read > 0, "mock RPC connection closed before request");
                server_requests.fetch_add(1, Ordering::SeqCst);

                let request = String::from_utf8_lossy(&buffer[..read]);
                let body_start = request.find("\r\n\r\n").map_or(read, |index| index + 4);
                let request_body = &request[body_start..];
                let parsed = serde_json::from_str::<serde_json::Value>(request_body).ok();
                let id = parsed
                    .as_ref()
                    .and_then(|value| value.get("id").cloned())
                    .unwrap_or_else(|| json!(1));
                let method = parsed
                    .as_ref()
                    .and_then(|value| value.get("method"))
                    .and_then(serde_json::Value::as_str);
                // An unknown block reads as `null`; every other call gets no logs.
                let result = if method == Some("eth_getBlockByNumber") {
                    serde_json::Value::Null
                } else {
                    json!([])
                };
                let body = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": result,
                })
                .to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body,
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("write mock RPC response");
            }
        });

        MockJsonRpc { url, requests }
    }

    #[test]
    fn log_request_estimate_uses_widest_learned_span_without_requests() {
        let servers = [
            spawn_rpc_handler(log_rpc_handler(2000, Vec::new(), |_, _| None)),
            spawn_rpc_handler(log_rpc_handler(2000, Vec::new(), |_, _| None)),
        ];
        let mut chain = pool_chain_config(servers.iter().map(|server| server.url.clone()));

        assert_eq!(
            chain.estimate_log_requests(1001, 1400),
            4,
            "unlimited providers use block_range"
        );
        chain.rpcs.narrow_log_span(LogSpanEndpoint::Provider(0), 25);
        assert_eq!(
            chain.estimate_log_requests(1001, 1400),
            4,
            "the wider provider's span counts"
        );
        chain.rpcs.narrow_log_span(LogSpanEndpoint::Provider(1), 25);
        assert_eq!(chain.estimate_log_requests(1001, 1400), 16);

        // Legacy commitments, transact, legacy shield, modern shield and
        // nullifiers each need their own filter.
        chain.deployment.v2_start_block = 1100;
        chain.deployment.legacy_shield_block = 1200;
        let estimate = chain.estimate_log_requests(1001, 1400);
        assert_eq!(estimate, 16 * 5);
        assert!(estimate > FOREST_RPC_REQUEST_BUDGET);
        for server in &servers {
            assert!(server.bodies().is_empty(), "estimation issues no request");
        }
    }

    #[tokio::test]
    async fn parallel_log_fetch_matches_one_provider_in_order_and_skips_lagging_provider() {
        let log_blocks = vec![1001, 1050, 1100, 1101, 1234, 1333, 1480, 1555, 1600];
        let serving = (0..3)
            .map(|_| {
                spawn_rpc_handler(delayed(
                    "eth_getLogs",
                    Duration::from_millis(25),
                    log_rpc_handler(2000, log_blocks.clone(), |_, _| None),
                ))
            })
            .collect::<Vec<_>>();
        // Head 1600 less finality depth 1 does not cover block 1600.
        let lagging = spawn_rpc_handler(log_rpc_handler(1600, log_blocks.clone(), |_, _| None));
        let chain = pool_chain_config(
            serving
                .iter()
                .chain([&lagging])
                .map(|server| server.url.clone()),
        );

        let mut pages = Vec::new();
        let (result, stats) = chain
            .fetch_logs_in_parallel(
                1001,
                1600,
                FOREST_RPC_PARALLELISM,
                &LogRequestBudget::new(FOREST_RPC_REQUEST_BUDGET),
                &CancellationToken::new(),
                |page| {
                    pages.push(page);
                    Ok(())
                },
            )
            .await;
        result.expect("parallel fetch succeeds");

        assert_eq!(
            pages.iter().map(|page| page.to_block).collect::<Vec<_>>(),
            (0..6).map(|page| 1100 + page * 100).collect::<Vec<_>>(),
            "pages arrive contiguous and in block order"
        );
        assert!(
            serving
                .iter()
                .filter(|server| server.count("eth_getLogs") > 0)
                .count()
                > 1,
            "pages are spread across providers"
        );
        assert_eq!(lagging.count("eth_blockNumber"), 1);
        assert_eq!(
            lagging.count("eth_getLogs"),
            0,
            "lagging provider fetches no page"
        );
        assert_eq!(stats.eligible_providers, 3);

        // With one slot, the lagging provider listed first hands its slot to
        // the next provider.
        let lagging_first = pool_chain_config(
            std::iter::once(&lagging)
                .chain(&serving)
                .map(|server| server.url.clone()),
        );
        let mut lagging_first_pages = 0;
        let (result, _) = lagging_first
            .fetch_logs_in_parallel(
                1001,
                1600,
                1,
                &LogRequestBudget::new(FOREST_RPC_REQUEST_BUDGET),
                &CancellationToken::new(),
                |_| {
                    lagging_first_pages += 1;
                    Ok(())
                },
            )
            .await;
        result.expect("a later provider fetches every page");
        assert_eq!(lagging_first_pages, 6);
        assert_eq!(lagging.count("eth_blockNumber"), 2);
        assert_eq!(
            lagging.count("eth_getLogs"),
            0,
            "lagging provider fetches no page"
        );

        let parallel_logs = pages
            .into_iter()
            .flat_map(|page| {
                let mut logs = page.logs;
                sort_logs(&mut logs);
                logs
            })
            .collect::<Vec<_>>();
        let single = pool_chain_config([serving[0].url.clone()]);
        let rpc = single.rpcs.random_provider().expect("rpc provider");
        let mut single_logs = single
            .fetch_logs_for_range(&rpc, None, 1001, 1600, &CancellationToken::new())
            .await
            .expect("single-provider fetch succeeds");
        sort_logs(&mut single_logs);
        assert_eq!(single_logs.len(), log_blocks.len());
        assert_eq!(parallel_logs, single_logs);
    }

    #[tokio::test]
    async fn failed_log_page_is_retried_elsewhere_and_diagnostics_hide_endpoints() {
        let events = CapturedEvents::default();
        let _guard = events.capture();
        let log_blocks = vec![1010, 1150, 1290];
        let refused_port = TcpListener::bind("127.0.0.1:0")
            .expect("bind refused port")
            .local_addr()
            .expect("local addr")
            .port();
        let failing = spawn_rpc_handler(log_rpc_handler(2000, log_blocks.clone(), |_, _| {
            Some(json!({ "code": -32000, "message": "header not found" }))
        }));
        // The slow head lets the failing provider take the first page.
        let working = spawn_rpc_handler(delayed(
            "eth_blockNumber",
            Duration::from_millis(200),
            log_rpc_handler(2000, log_blocks.clone(), |_, _| None),
        ));
        let chain = pool_chain_config([
            credential_url(refused_port),
            failing.url.clone(),
            working.url.clone(),
        ]);

        let mut pages = Vec::new();
        let (result, stats) = chain
            .fetch_logs_in_parallel(
                1001,
                1300,
                FOREST_RPC_PARALLELISM,
                &LogRequestBudget::new(FOREST_RPC_REQUEST_BUDGET),
                &CancellationToken::new(),
                |page| {
                    pages.push((page.to_block, page.logs.len()));
                    Ok(())
                },
            )
            .await;
        result.expect("working provider fetches every page");

        assert_eq!(pages, vec![(1100, 1), (1200, 1), (1300, 1)]);
        assert_eq!(failing.count("eth_getLogs"), 1);
        assert_eq!(stats.retries, 1, "the failed page is retried");
        assert_eq!(
            stats
                .providers
                .iter()
                .map(|provider| (provider.rpc_index, provider.pages))
                .collect::<Vec<_>>(),
            vec![(0, 0), (1, 0), (2, 3)]
        );
        assert_eq!(
            chain
                .rpcs
                .available_providers()
                .iter()
                .map(|rpc| rpc.index)
                .collect::<Vec<_>>(),
            vec![2],
            "failing providers cool down"
        );

        let finished = events.find("parallel log range fetch finished");
        assert_eq!(
            finished.get("outcome").map(String::as_str),
            Some("complete")
        );
        assert_eq!(finished.get("retries").map(String::as_str), Some("1"));
        assert!(finished.contains_key("providers"));
        events.find("parallel log fetch provider failed; its page returns to the queue");
        for event in events.events() {
            for value in event.values() {
                assert!(
                    ["secret", "user", "apikey", "127.0.0.1"]
                        .iter()
                        .all(|needle| !value.contains(needle)),
                    "log value {value:?} exposes an endpoint"
                );
            }
        }

        let only_failing = pool_chain_config([failing.url.clone()]);
        let mut delivered = 0;
        let (result, _) = only_failing
            .fetch_logs_in_parallel(
                1001,
                1300,
                FOREST_RPC_PARALLELISM,
                &LogRequestBudget::new(FOREST_RPC_REQUEST_BUDGET),
                &CancellationToken::new(),
                |_| {
                    delivered += 1;
                    Ok(())
                },
            )
            .await;
        assert!(
            matches!(result, Err(ChainError::NoHealthyRpc)),
            "{result:?}"
        );
        assert_eq!(delivered, 0);
    }

    #[tokio::test]
    async fn parallel_log_fetch_stops_when_narrowing_exceeds_request_budget() {
        let server = spawn_rpc_handler(log_rpc_handler(2000, Vec::new(), |from, to| {
            (to - from + 1 > 25).then(|| {
                json!({ "code": -32000, "message": "log query range must not exceed 25 blocks" })
            })
        }));
        let chain = pool_chain_config([server.url.clone()]);
        assert_eq!(chain.estimate_log_requests(1001, 1200), 2);

        let budget = LogRequestBudget::new(4);
        let (result, stats) =
            chain
                .fetch_logs_in_parallel(1001, 1200, 4, &budget, &CancellationToken::new(), |_| {
                    Ok(())
                })
                .await;

        assert!(
            matches!(result, Err(ChainError::LogRequestBudgetExceeded(4))),
            "{result:?}"
        );
        assert_eq!(server.count("eth_getLogs"), 4);
        assert_eq!(stats.get_logs_requests, 4);
        assert_eq!(
            chain.rpcs.available_providers().len(),
            1,
            "exceeding the budget is not a provider failure"
        );
    }

    #[tokio::test]
    async fn cancelled_parallel_log_fetch_issues_no_further_requests() {
        let (started_tx, mut started) = tokio::sync::mpsc::unbounded_channel();
        let (release_first, first_gate) = std::sync::mpsc::channel::<()>();
        let (release_second, second_gate) = std::sync::mpsc::channel::<()>();
        let servers = [
            spawn_rpc_handler(gated_get_logs(started_tx.clone(), first_gate)),
            spawn_rpc_handler(gated_get_logs(started_tx, second_gate)),
        ];
        let chain = pool_chain_config(servers.iter().map(|server| server.url.clone()));
        let cancel = CancellationToken::new();
        let budget = LogRequestBudget::new(FOREST_RPC_REQUEST_BUDGET);

        let fetch = chain.fetch_logs_in_parallel(
            1001,
            1600,
            FOREST_RPC_PARALLELISM,
            &budget,
            &cancel,
            |_| Ok(()),
        );
        let cancel_once_both_fetch = async {
            for _ in 0..2 {
                started.recv().await.expect("page request started");
            }
            cancel.cancel();
        };
        let ((result, _), ()) = tokio::join!(fetch, cancel_once_both_fetch);
        assert!(
            matches!(result, Err(ChainError::LogFetchCancelled)),
            "{result:?}"
        );

        // Released servers answer anything queued behind the held requests.
        drop((release_first, release_second));
        tokio::time::sleep(Duration::from_millis(100)).await;
        for server in &servers {
            assert_eq!(server.count("eth_blockNumber"), 1);
            assert_eq!(
                server.count("eth_getLogs"),
                1,
                "no request after cancellation"
            );
        }
        assert_eq!(
            chain.rpcs.available_providers().len(),
            2,
            "cancellation marks no provider bad"
        );
    }

    fn pool_chain_config(urls: impl IntoIterator<Item = Url>) -> ChainConfig {
        let urls = urls.into_iter().collect::<Vec<_>>();
        let mut chain = chain_config(urls[0].clone());
        chain.rpcs = Arc::new(QueryRpcPool::new(urls, Duration::from_mins(1)));
        chain
    }

    fn credential_url(port: u16) -> Url {
        Url::parse(&format!(
            "http://user:secret@127.0.0.1:{port}/?apikey=secret"
        ))
        .expect("mock RPC URL")
    }

    struct HandlerRpc {
        url: Url,
        bodies: Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    }

    impl HandlerRpc {
        fn bodies(&self) -> Vec<serde_json::Value> {
            self.bodies.lock().expect("request bodies lock").clone()
        }

        fn count(&self, method: &str) -> usize {
            self.bodies()
                .iter()
                .filter(|body| body["method"] == method)
                .count()
        }
    }

    /// Serves every request, one connection at a time, with `handler`, which
    /// maps the request body to the response's `result` or `error` member.
    /// The URL carries credentials in its userinfo and query.
    fn spawn_rpc_handler(
        handler: impl Fn(&serde_json::Value) -> serde_json::Value + Send + 'static,
    ) -> HandlerRpc {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock RPC");
        let url = credential_url(listener.local_addr().expect("local addr").port());
        let bodies = Arc::new(std::sync::Mutex::new(Vec::new()));
        let server_bodies = Arc::clone(&bodies);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let Some(body) = read_json_rpc_body(&mut stream) else {
                    continue;
                };
                server_bodies
                    .lock()
                    .expect("request bodies lock")
                    .push(body.clone());
                let mut response = handler(&body);
                response["jsonrpc"] = json!("2.0");
                response["id"] = body["id"].clone();
                let response = response.to_string();
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                    response.len(),
                );
            }
        });
        HandlerRpc { url, bodies }
    }

    fn read_json_rpc_body(stream: &mut std::net::TcpStream) -> Option<serde_json::Value> {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            let read = stream.read(&mut buffer).ok().filter(|read| *read > 0)?;
            request.extend_from_slice(&buffer[..read]);
            let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n")
            else {
                continue;
            };
            let body_start = header_end + 4;
            let content_length = String::from_utf8_lossy(&request[..header_end])
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())?
                })
                .unwrap_or(0);
            if request.len() >= body_start + content_length {
                return serde_json::from_slice(&request[body_start..body_start + content_length])
                    .ok();
            }
        }
    }

    fn hex_quantity(value: &serde_json::Value) -> u64 {
        let hex = value.as_str().expect("hex quantity");
        u64::from_str_radix(hex.trim_start_matches("0x"), 16).expect("hex quantity")
    }

    /// Answers `eth_blockNumber` with `head`, and `eth_getLogs` with one log
    /// per listed block in the requested range unless `reject` returns an
    /// error for that range.
    fn log_rpc_handler(
        head: u64,
        log_blocks: Vec<u64>,
        reject: impl Fn(u64, u64) -> Option<serde_json::Value> + Send + 'static,
    ) -> impl Fn(&serde_json::Value) -> serde_json::Value + Send + 'static {
        move |request: &serde_json::Value| match request["method"].as_str() {
            Some("eth_blockNumber") => json!({ "result": format!("{head:#x}") }),
            Some("eth_getLogs") => {
                let from_block = hex_quantity(&request["params"][0]["fromBlock"]);
                let to_block = hex_quantity(&request["params"][0]["toBlock"]);
                reject(from_block, to_block).map_or_else(
                    || {
                        let logs = log_blocks
                            .iter()
                            .filter(|block| (from_block..=to_block).contains(block))
                            .map(|block| {
                                json!({
                                    "address": format!("{:#x}", Address::ZERO),
                                    "topics": [],
                                    "data": "0x",
                                    "blockHash": format!("{:#x}", FixedBytes::<32>::from([0x11; 32])),
                                    "blockNumber": format!("{block:#x}"),
                                    "transactionHash": format!("{:#x}", FixedBytes::<32>::from([0x33; 32])),
                                    "transactionIndex": "0x0",
                                    "logIndex": "0x0",
                                    "removed": false,
                                })
                            })
                            .collect::<Vec<_>>();
                        json!({ "result": logs })
                    },
                    |error| json!({ "error": error }),
                )
            }
            _ => json!({ "error": { "code": -32601, "message": "method not found" } }),
        }
    }

    /// Delays every `method` request by `delay` before `serve` answers it.
    fn delayed(
        method: &'static str,
        delay: Duration,
        serve: impl Fn(&serde_json::Value) -> serde_json::Value + Send + 'static,
    ) -> impl Fn(&serde_json::Value) -> serde_json::Value + Send + 'static {
        move |request: &serde_json::Value| {
            if request["method"] == method {
                thread::sleep(delay);
            }
            serve(request)
        }
    }

    /// Reports each `eth_getLogs` request on `started` and holds it until
    /// `release` yields or disconnects.
    fn gated_get_logs(
        started: tokio::sync::mpsc::UnboundedSender<()>,
        release: std::sync::mpsc::Receiver<()>,
    ) -> impl Fn(&serde_json::Value) -> serde_json::Value + Send + 'static {
        let serve = log_rpc_handler(2000, Vec::new(), |_, _| None);
        move |request: &serde_json::Value| {
            if request["method"] == "eth_getLogs" {
                let _ = started.send(());
                let _ = release.recv();
            }
            serve(request)
        }
    }

    /// Records `sync_service` tracing events as field-name to value maps.
    #[derive(Clone, Default)]
    struct CapturedEvents(Arc<std::sync::Mutex<Vec<BTreeMap<String, String>>>>);

    impl CapturedEvents {
        fn capture(&self) -> CaptureGuard {
            // With one registered dispatcher, tracing-core resolves a callsite
            // first hit on another test thread against that thread's empty
            // default and caches it as disabled. A second live dispatcher keeps
            // interest computed across every registered dispatcher.
            let registered = tracing::Dispatch::new(CaptureSubscriber(self.clone()));
            CaptureGuard {
                _default: tracing::subscriber::set_default(CaptureSubscriber(self.clone())),
                _registered: registered,
            }
        }

        fn events(&self) -> Vec<BTreeMap<String, String>> {
            self.0.lock().expect("captured events lock").clone()
        }

        fn find(&self, message: &str) -> BTreeMap<String, String> {
            self.events()
                .into_iter()
                .find(|event| event.get("message").is_some_and(|value| value == message))
                .unwrap_or_else(|| panic!("missing {message:?} event"))
        }
    }

    struct CaptureGuard {
        _default: tracing::subscriber::DefaultGuard,
        _registered: tracing::Dispatch,
    }

    struct CaptureSubscriber(CapturedEvents);

    struct CapturedFields<'a>(&'a mut BTreeMap<String, String>);

    impl tracing::field::Visit for CapturedFields<'_> {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0.insert(field.name().to_owned(), value.to_owned());
        }

        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.insert(field.name().to_owned(), format!("{value:?}"));
        }
    }

    impl tracing::Subscriber for CaptureSubscriber {
        fn register_callsite(
            &self,
            _metadata: &'static tracing::Metadata<'static>,
        ) -> tracing::subscriber::Interest {
            tracing::subscriber::Interest::sometimes()
        }

        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            metadata.target().starts_with("sync_service")
        }

        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            let mut fields = BTreeMap::new();
            event.record(&mut CapturedFields(&mut fields));
            self.0.0.lock().expect("captured events lock").push(fields);
        }

        fn enter(&self, _span: &tracing::span::Id) {}

        fn exit(&self, _span: &tracing::span::Id) {}
    }
}
