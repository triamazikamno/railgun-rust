//! Live forest progress, reorg resets and snapshot persistence.

#[allow(clippy::wildcard_imports)]
use super::*;
use std::path::PathBuf;
/// Why the published live forest block changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::chain) enum LiveForestProgressCause {
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
    pub(in crate::chain) fn publish_forest_progress(
        &self,
        forest_block: u64,
        cause: LiveForestProgressCause,
    ) {
        let safe_head = *self.safe_head_tx.borrow();
        let lag = self.chain.live_forest_lag(forest_block, safe_head);
        debug!(target: LOG_TARGET,
            chain_id = self.chain.deployment.chain_id,
            forest_block,
            cause = cause.as_str(),
            safe_head,
            estimated_requests = lag.estimated_requests,
            far_behind = lag.far_behind,
            "live forest progress"
        );
        if let Err(err) = self.forest_last_tx.send(forest_block) {
            debug!(target: LOG_TARGET, ?err, forest_block, "failed to send forest progress update");
        }
    }

    pub(in crate::chain) async fn apply_forest_updates(
        &self,
        batch: &SharedLogBatch,
    ) -> Result<(), ChainError> {
        let mut forest = self.forest.write().await;
        forest.apply_commitment_updates_from_logs(&batch.logs)?;
        forest.compute_roots();
        Ok(())
    }
    pub(in crate::chain) async fn reset_forest_state(
        &self,
        snapshot_path: &Path,
        last_processed: u64,
    ) -> Result<u64, ChainError> {
        let mut forest = self.forest.write().await;
        let reset_block =
            self.restore_forest_from_latest_anchor(&mut forest, snapshot_path, last_processed)?;

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
        info!(target: LOG_TARGET,
            from = last_processed,
            to = reset_block,
            "forest state reset"
        );
        Ok(reset_block)
    }

    /// Restores `forest` from the newest anchor snapshot, writing it to `snapshot_path`
    /// before recording the anchor, and returns its last processed block. When there is no
    /// anchor, or the newest one fails to load, empties the forest and returns the block
    /// before deployment; older anchors are not tried.
    fn restore_forest_from_latest_anchor(
        &self,
        forest: &mut MerkleForest,
        snapshot_path: &Path,
        last_processed: u64,
    ) -> Result<u64, ChainError> {
        let before_deployment = self.chain.deployment.deployment_block.saturating_sub(1);
        let Ok(Some((anchor_path, anchor_block))) = self.db.find_latest_anchor(&self.chain) else {
            *forest = MerkleForest::new();
            self.anchor_last.store(0, Ordering::Relaxed);
            return Ok(before_deployment);
        };
        match MerkleForestSnapshot::load(
            &anchor_path,
            self.chain.deployment.chain_id,
            self.chain.deployment.contract,
        ) {
            Ok(Some(snapshot)) => {
                *forest = snapshot.forest;
                let reset_block = snapshot.last_processed_block;
                MerkleForestSnapshot::write(
                    snapshot_path,
                    self.chain.deployment.chain_id,
                    self.chain.deployment.contract,
                    reset_block,
                    forest,
                )?;
                self.anchor_last.store(anchor_block, Ordering::Relaxed);
                info!(target: LOG_TARGET,
                    from = last_processed,
                    to = reset_block,
                    anchor = %anchor_path.display(),
                    "forest reset to anchor"
                );
                Ok(reset_block)
            }
            Ok(None) => {
                *forest = MerkleForest::new();
                self.anchor_last.store(0, Ordering::Relaxed);
                Ok(before_deployment)
            }
            Err(err) => {
                warn!(target: LOG_TARGET, ?err, path = %anchor_path.display(), "failed to load anchor snapshot");
                *forest = MerkleForest::new();
                self.anchor_last.store(0, Ordering::Relaxed);
                Ok(before_deployment)
            }
        }
    }

    pub(in crate::chain) async fn reset_wallets(&self, safe_head: u64, reset_from_block: u64) {
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
            debug!(target: LOG_TARGET, ?reset_result, cache_key = %cache_key, "skipping rejected wallet reset");
            return;
        }
        debug!(target: LOG_TARGET, ?reset_result, cache_key = %cache_key, "wallet reorg reset accepted for actor-owned replay");
    }

    /// Checks the forest metadata block against `provider`, and on a confirmed
    /// reorg resets the forest and wallets.
    ///
    /// Returns the check's outcome. `Unchecked` also covers a forest below
    /// deployment and missing metadata. `Unconfirmed` means no confirmed hash
    /// was read, so a reorg can be neither ruled out nor detected. `Mismatch`
    /// means the forest and wallet reset already ran; a failed forest reset
    /// returns its error instead.
    pub(in crate::chain) async fn check_forest_reorg(
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
                warn!(target: LOG_TARGET,
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
                debug!(target: LOG_TARGET,
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
                warn!(target: LOG_TARGET,
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

    pub(in crate::chain) async fn persist_forest_snapshot(
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

    pub(in crate::chain) fn maybe_write_anchor_snapshot(
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
            debug!(target: LOG_TARGET, path = %path.display(), block = last_block, "wrote anchor snapshot");
        }
        if let Err(err) = self.prune_anchor_snapshots(snapshot_path) {
            warn!(target: LOG_TARGET, ?err, "failed to prune anchor snapshots");
        }
        Ok(())
    }

    /// This chain's anchor snapshots in `anchor_dir`, each with its block. Names that aren't
    /// UTF-8 or aren't this chain's anchors are skipped.
    fn anchor_snapshots(
        &self,
        anchor_dir: &Path,
        capacity: usize,
    ) -> Result<Vec<(PathBuf, u64)>, PersistError> {
        let mut anchors = Vec::with_capacity(capacity);
        for entry in std::fs::read_dir(anchor_dir)? {
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
        Ok(anchors)
    }

    pub(in crate::chain) fn prune_anchor_snapshots(
        &self,
        snapshot_path: &Path,
    ) -> Result<(), PersistError> {
        let retention = self.chain.sync.anchor_retention;
        if retention == 0 {
            return Ok(());
        }
        let anchor_dir = self.db.anchor_dir();
        if !anchor_dir.exists() {
            return Ok(());
        }
        let mut anchors = self.anchor_snapshots(&anchor_dir, retention + 8)?;
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
            if !keep.contains(&path) {
                remove_anchor_snapshot(&path, block);
            }
        }
        Ok(())
    }
}

fn remove_anchor_snapshot(path: &Path, block: u64) {
    match std::fs::remove_file(path) {
        Ok(()) => {
            debug!(target: LOG_TARGET, path = %path.display(), block, "pruned anchor snapshot");
        }
        Err(err) => {
            warn!(target: LOG_TARGET, ?err, path = %path.display(), block, "failed to prune anchor snapshot");
        }
    }
}
