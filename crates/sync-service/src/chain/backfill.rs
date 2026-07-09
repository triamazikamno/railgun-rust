use super::service::send_wallet_reset;
use super::*;

pub(super) struct WalletBackfill {
    pub(super) from_block: u64,
    pub(super) target_block: u64,
    pub(super) follow_safe_head: bool,
    pub(super) progress_start_block: u64,
    pub(super) lease: WalletBackfillLease,
    pub(super) last_advanced_at: Instant,
    pub(super) last_indexed_tail_attempt_at: Option<Instant>,
}

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

    pub(super) fn update_last_scanned(&mut self, last_scanned: u64, now: Instant) {
        if last_scanned != self.last_scanned {
            self.last_scanned = last_scanned;
            self.last_advanced_at = now;
        }
    }

    pub(super) fn mark_indexed_tail_attempt(&mut self, now: Instant) {
        self.last_indexed_tail_attempt_at = Some(now);
    }

    pub(super) fn should_try_indexed_tail_fallback(
        &self,
        chain_id: u64,
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
        if lag_blocks <= wallet_tail_fallback_lag_threshold_blocks(chain_id) {
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
    pub(super) fn new(
        from_block: u64,
        target_block: u64,
        follow_safe_head: bool,
        progress_start_block: u64,
        lease: WalletBackfillLease,
        now: Instant,
    ) -> Self {
        Self {
            from_block,
            target_block,
            follow_safe_head,
            progress_start_block,
            lease,
            last_advanced_at: now,
            last_indexed_tail_attempt_at: None,
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

    pub(super) fn mark_progress(&mut self, from_block: u64, now: Instant) {
        self.from_block = from_block;
        self.last_advanced_at = now;
    }

    pub(super) fn retry_after_rejected_apply(&mut self, committed_to: u64, now: Instant) {
        let retry_from = self.from_block.min(committed_to.saturating_add(1));
        self.mark_progress(retry_from, now);
    }

    pub(super) fn retry_after_rejected_finish(&mut self, committed_to: u64, now: Instant) {
        let replay_from = self
            .progress_start_block
            .min(committed_to.saturating_add(1));
        self.from_block = if self.target_block == 0 {
            replay_from
        } else {
            replay_from.min(self.target_block)
        };
        self.last_advanced_at = now;
        self.last_indexed_tail_attempt_at = None;
    }

    pub(super) fn mark_indexed_tail_attempt(&mut self, now: Instant) {
        self.last_indexed_tail_attempt_at = Some(now);
    }

    pub(super) fn should_try_indexed_tail_fallback(
        &self,
        chain_id: u64,
        now: Instant,
        min_stall: Duration,
        cooldown: Duration,
    ) -> bool {
        if self.target_block == 0 || self.from_block > self.target_block {
            return false;
        }
        let lag_blocks = wallet_backfill_lag_blocks(self.from_block, self.target_block);
        if lag_blocks <= wallet_tail_fallback_lag_threshold_blocks(chain_id) {
            return false;
        }
        if now.duration_since(self.last_advanced_at) < min_stall {
            return false;
        }
        self.last_indexed_tail_attempt_at
            .is_none_or(|attempted_at| now.duration_since(attempted_at) >= cooldown)
    }
}

pub(super) const fn wallet_backfill_lag_blocks(from_block: u64, target_block: u64) -> u64 {
    if from_block > target_block {
        0
    } else {
        target_block.saturating_sub(from_block).saturating_add(1)
    }
}

pub(super) const fn wallet_tail_fallback_block_time_secs(chain_id: u64) -> u64 {
    match chain_id {
        1 => 12,
        56 => 3,
        137 => 2,
        42161 => 1,
        _ => 12,
    }
}

pub(super) const fn wallet_tail_fallback_stale_timeout_secs(chain_id: u64) -> u64 {
    let timeout = wallet_tail_fallback_block_time_secs(chain_id) * 10;
    if timeout < 45 { 45 } else { timeout }
}

pub(super) const fn wallet_tail_fallback_lag_threshold_blocks(chain_id: u64) -> u64 {
    let block_time = wallet_tail_fallback_block_time_secs(chain_id);
    let threshold = wallet_tail_fallback_stale_timeout_secs(chain_id) / block_time;
    if threshold < 2 { 2 } else { threshold }
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
        let mut reset_block = self.chain.deployment_block.saturating_sub(1);

        if let Ok(Some((anchor_path, anchor_block))) = self.db.find_latest_anchor(&self.chain) {
            match MerkleForestSnapshot::load(&anchor_path, self.chain.chain_id, self.chain.contract)
            {
                Ok(Some(snapshot)) => {
                    *forest = snapshot.forest;
                    reset_block = snapshot.last_processed_block;
                    MerkleForestSnapshot::write(
                        snapshot_path,
                        self.chain.chain_id,
                        self.chain.contract,
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
            self.chain.chain_id,
            self.chain.contract,
            reset_block,
            &forest,
        )?;

        self.db.update_merkle_forest_meta(
            self.chain.chain_id,
            &self.chain.contract.to_string(),
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
        let wallets = self.wallets.read().await;
        for (cache_key, registration) in wallets.iter() {
            let from_block =
                wallet_reorg_backfill_from_block(reset_from_block, registration.start_block);
            let sync_target = wallet_sync_target(safe_head, registration.sync_to_block);
            let replay_plan = WalletResetReplayPlan::new(
                registration.start_block,
                sync_target,
                registration.sync_to_block.is_none(),
            );
            let reset_result = send_wallet_reset(
                cache_key,
                &registration.backfill_sender,
                &registration.handle,
                self.next_wallet_reset_intent(),
                from_block,
                replay_plan,
                registration.handle.last_scanned_raw(),
            )
            .await;
            if reset_result.reset_generation().is_none() {
                debug!(?reset_result, cache_key = %cache_key, "skipping rejected wallet reset");
                continue;
            };
            if !reset_result.committed() {
                debug!(?reset_result, cache_key = %cache_key, "wallet reorg reset accepted and pending durable replay");
                continue;
            }
            let Some(progress) = registration.handle.schedulable_progress() else {
                debug!(cache_key = %cache_key, "wallet reorg reset committed but view not yet schedulable");
                continue;
            };
            let replay_from =
                wallet_backfill_from_block(reset_result.committed_to(), registration.start_block);
            let target_result = registration
                .handle
                .start_backfill(
                    cache_key,
                    &registration.backfill_sender,
                    progress,
                    sync_target,
                )
                .await;
            debug!(?target_result, cache_key = %cache_key, "wallet reorg target update result");
            let lease = match target_result {
                WalletBackfillFinishResult::Ready { .. } => continue,
                WalletBackfillFinishResult::Accepted { lease, .. } => lease,
                WalletBackfillFinishResult::Rejected { .. } => continue,
            };
            if let Err(err) = self.backfill_tx.try_send(BackfillRequest::add(
                cache_key.clone(),
                replay_from,
                sync_target,
                registration.sync_to_block.is_none(),
                replay_from,
                lease.clone(),
            )) {
                warn!(?err, cache_key = %cache_key, "failed to enqueue wallet backfill");
                lease
                    .fail(cache_key, WalletReadinessError::BackfillUnavailable)
                    .await;
            }
        }
    }

    pub(super) async fn check_forest_reorg(
        &self,
        provider: &DynProvider,
        archive_provider: Option<&DynProvider>,
        rpc_url: &str,
        snapshot_path: &Path,
        safe_head: u64,
        last_processed: u64,
    ) -> Result<(), ChainError> {
        if last_processed < self.chain.deployment_block {
            return Ok(());
        }
        let meta = self
            .db
            .get_merkle_forest_meta(self.chain.chain_id, &self.chain.contract.to_string())?;
        let Some(meta) = meta else {
            return Ok(());
        };
        if meta.hash == [0u8; 32] {
            return Ok(());
        }

        if meta.last_block != last_processed {
            warn!(
                chain_id = self.chain.chain_id,
                contract = %self.chain.contract,
                rpc = rpc_url,
                safe_head,
                last_processed,
                meta_last_block = meta.last_block,
                stored_hash = %FixedBytes::<32>::from(meta.hash),
                "skipping reorg check because forest metadata block does not match progress"
            );
            return Ok(());
        }

        let current_hash = self
            .chain
            .fetch_confirmed_block_hash(provider, archive_provider, last_processed)
            .await?;
        match ForestReorgDecision::from_confirmed_hash(
            last_processed,
            meta.last_block,
            meta.hash,
            current_hash,
        ) {
            ForestReorgDecision::Skip => {
                debug!(
                    chain_id = self.chain.chain_id,
                    contract = %self.chain.contract,
                    rpc = rpc_url,
                    safe_head,
                    last_processed,
                    meta_last_block = meta.last_block,
                    "skipping reorg check without a confirmed block hash"
                );
            }
            ForestReorgDecision::Match => {}
            ForestReorgDecision::Mismatch => {
                let current_hash = current_hash.expect("mismatch requires confirmed hash");
                warn!(
                    chain_id = self.chain.chain_id,
                    contract = %self.chain.contract,
                    rpc = rpc_url,
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
            self.chain.chain_id,
            self.chain.contract,
            last_block,
            &forest,
        )?;

        self.db.update_merkle_forest_meta(
            self.chain.chain_id,
            &self.chain.contract.to_string(),
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
        let interval = self.chain.anchor_interval;
        if interval == 0 {
            return Ok(());
        }
        let last_anchor = self.anchor_last.load(Ordering::Relaxed);
        if last_block < last_anchor.saturating_add(interval) {
            return Ok(());
        }
        let anchor_dir = self.db.anchor_dir();
        std::fs::create_dir_all(&anchor_dir)?;
        let file_name = anchor_file_name(self.chain.chain_id, self.chain.contract, last_block);
        let relative = DbStore::relative_blob_path("merkle_forest/anchors", &file_name);
        let path = self.db.resolve_path(&relative);
        MerkleForestSnapshot::write(
            &path,
            self.chain.chain_id,
            self.chain.contract,
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
        let retention = self.chain.anchor_retention;
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
            if let Some(block) = parse_anchor_block(self.chain.chain_id, self.chain.contract, name)
            {
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
        let provider = if self.archive_until_block > 0 && block_number <= self.archive_until_block {
            archive_provider.unwrap_or(provider)
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
        let provider = if self.archive_until_block > 0 && block_number <= self.archive_until_block {
            archive_provider.unwrap_or(provider)
        } else {
            provider
        };
        let block = provider
            .get_block_by_number(BlockNumberOrTag::Number(block_number))
            .await?;
        Ok(block.map(|block| block.header.timestamp))
    }

    pub(super) async fn fetch_log_block_timestamps(
        &self,
        provider: &DynProvider,
        archive_provider: Option<&DynProvider>,
        logs: &[Log],
    ) -> Result<HashMap<u64, u64>, ChainError> {
        let mut block_numbers = logs
            .iter()
            .filter_map(|log| log.block_number)
            .collect::<Vec<_>>();
        block_numbers.sort_unstable();
        block_numbers.dedup();

        let mut timestamps = HashMap::with_capacity(block_numbers.len());
        for block_number in block_numbers {
            if let Some(timestamp) = self
                .fetch_block_timestamp(provider, archive_provider, block_number)
                .await?
            {
                timestamps.insert(block_number, timestamp);
            }
        }
        Ok(timestamps)
    }

    pub(super) async fn fetch_logs_for_range(
        &self,
        provider: &DynProvider,
        archive_provider: Option<&DynProvider>,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<Log>, ChainError> {
        let mut logs = Vec::new();
        let archive_until_block = self.archive_until_block;

        if archive_until_block > 0 && from_block <= archive_until_block {
            let archive_end = to_block.min(archive_until_block);
            let archive_provider = archive_provider.unwrap_or(provider);
            let archive_logs = fetch_logs_for_range_with_provider(
                archive_provider,
                self.contract,
                from_block,
                archive_end,
                self.v2_start_block,
                self.legacy_shield_block,
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
                provider,
                self.contract,
                standard_start,
                to_block,
                self.v2_start_block,
                self.legacy_shield_block,
            )
            .await?;
            logs.extend(standard_logs);
        }

        Ok(logs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    use serde_json::json;
    use url::Url;

    struct MockJsonRpc {
        url: Url,
        requests: Arc<AtomicUsize>,
    }

    #[tokio::test]
    async fn archive_range_log_fetch_uses_regular_rpc_when_archive_provider_missing() {
        let mock = spawn_json_rpc_server(1);
        let provider = build_provider_with_http_client(&mock.url, None)
            .await
            .expect("provider");
        let mut chain = chain_config(mock.url.clone());
        chain.deployment_block = 100;
        chain.archive_until_block = 150;
        chain.v2_start_block = 200;
        chain.legacy_shield_block = 250;

        let logs = chain
            .fetch_logs_for_range(&provider, None, 100, 120)
            .await
            .expect("regular RPC should be used for archive range");

        assert!(logs.is_empty());
        assert_eq!(mock.requests.load(Ordering::SeqCst), 1);
    }

    fn chain_config(rpc_url: Url) -> ChainConfig {
        ChainConfig {
            chain_id: 1,
            contract: Address::ZERO,
            rpcs: Arc::new(QueryRpcPool::new(vec![rpc_url], Duration::from_secs(1))),
            archive_rpc_url: None,
            archive_until_block: 0,
            deployment_block: 1,
            v2_start_block: 1,
            legacy_shield_block: 1,
            block_range: 100,
            indexed_wallet_block_range: 100,
            poll_interval: Duration::from_secs(1),
            finality_depth: 1,
            quick_sync_endpoint: None,
            indexed_artifact_source: None,
            anchor_interval: 100,
            anchor_retention: 2,
            http_client: None,
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
                let id = serde_json::from_str::<serde_json::Value>(request_body)
                    .ok()
                    .and_then(|value| value.get("id").cloned())
                    .unwrap_or_else(|| json!(1));
                let body = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": [],
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
}
