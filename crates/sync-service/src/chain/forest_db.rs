use std::borrow::Cow;

use super::logs::{
    FOREST_RPC_PARALLELISM, FOREST_RPC_REQUEST_BUDGET, INDEXED_SQUID_STEP_DEADLINE,
    LogRequestBudget,
};
use super::merkle_artifacts::MerkleArtifactCatchUp;
use super::{
    Arc, CancellationToken, ChainConfig, ChainError, DEFAULT_PAGE_SIZE, DbStore, Duration,
    DynProvider, FixedBytes, ForestMetaCheck, Instant, MerkleForest, MerkleForestSnapshot, Path,
    PathBuf, PersistError, ProviderHandle, QuickSyncClient, QuickSyncConfig, RwLock,
    SNAPSHOT_VERSION, SyncError, SyncProgressSender, SyncProgressStage, SyncProgressUnit,
    SyncProgressUpdate, async_trait, debug, info, parse_anchor_block,
    run_merkle_artifact_catch_up_into, run_quick_sync_into_with_progress, send_sync_progress,
    sort_logs, warn, watch,
};

#[async_trait]
pub(super) trait MerkleForestDbExt {
    async fn load_or_initialize_forest(
        &self,
        chain: &ChainConfig,
        safe_head: u64,
        rpc: Option<&ProviderHandle>,
        archive_provider: Option<&DynProvider>,
    ) -> Result<(Arc<RwLock<MerkleForest>>, u64, PathBuf, u64), ChainError>;
    fn anchor_dir(&self) -> PathBuf;
    fn find_latest_anchor(&self, chain: &ChainConfig)
    -> Result<Option<(PathBuf, u64)>, ChainError>;
}

#[async_trait]
impl MerkleForestDbExt for DbStore {
    async fn load_or_initialize_forest(
        &self,
        chain: &ChainConfig,
        safe_head: u64,
        rpc: Option<&ProviderHandle>,
        archive_provider: Option<&DynProvider>,
    ) -> Result<(Arc<RwLock<MerkleForest>>, u64, PathBuf, u64), ChainError> {
        let mut forest = MerkleForest::new();
        let mut last_processed = chain.deployment.deployment_block.saturating_sub(1);
        let file_name = format!(
            "forest-{}-{}.msgpack",
            chain.deployment.chain_id, chain.deployment.contract
        );
        self.ensure_blob_dir("merkle_forest")?;
        let relative = Self::relative_blob_path("merkle_forest", &file_name);
        let mut snapshot_path = self.resolve_path(&relative);
        let mut last_anchor = 0;
        let mut loaded_meta = None;

        if let Ok(Some(meta)) = self.get_merkle_forest_meta(
            chain.deployment.chain_id,
            &chain.deployment.contract.to_string(),
        ) {
            loaded_meta = Some((meta.last_block, meta.hash));
            let path = self.resolve_path(&meta.relative_path);
            match MerkleForestSnapshot::load(
                &path,
                chain.deployment.chain_id,
                chain.deployment.contract,
            ) {
                Ok(Some(snapshot)) => {
                    forest = snapshot.forest;
                    last_processed = snapshot.last_processed_block;
                    snapshot_path = path;
                }
                Ok(None) => {}
                Err(err) => {
                    warn!(?err, path = %path.display(), "failed to load merkle forest snapshot");
                }
            }
        }

        if let Ok(Some((anchor_path, anchor_block))) = self.find_latest_anchor(chain) {
            last_anchor = anchor_block;
            if last_processed < anchor_block {
                match MerkleForestSnapshot::load(
                    &anchor_path,
                    chain.deployment.chain_id,
                    chain.deployment.contract,
                ) {
                    Ok(Some(snapshot)) => {
                        forest = snapshot.forest;
                        last_processed = snapshot.last_processed_block;
                        snapshot_path = anchor_path;
                    }
                    Ok(None) => {}
                    Err(err) => {
                        warn!(?err, path = %anchor_path.display(), "failed to load anchor snapshot");
                    }
                }
            }
        }

        let from_block = last_processed
            .saturating_add(1)
            .max(chain.deployment.deployment_block);
        let progress = ForestProgressReporter::new(chain.progress_tx.as_ref());
        if chain.should_skip_indexed_forest_catch_up(from_block, safe_head) {
            debug!(
                chain_id = chain.deployment.chain_id,
                from_block,
                safe_head,
                block_range = chain.sync.block_range,
                tail_blocks = forest_tail_blocks(from_block, safe_head),
                artifact_source_skipped = chain.sync.indexed_artifact_source.is_some(),
                squid_skipped = chain.sync.quick_sync_endpoint.is_some(),
                "skipping indexed merkle forest catch-up for small tail"
            );
        } else if loaded_forest_reorged(chain, rpc, archive_provider, loaded_meta, last_processed)
            .await
        {
            // Left to the live reorg check, which rewinds the forest before
            // anything builds on it.
        } else if let Some(winner) = race_forest_candidates(
            chain,
            &forest,
            last_processed,
            from_block,
            safe_head,
            rpc,
            archive_provider,
            &progress,
        )
        .await
        {
            match persist_forest_candidate(self, chain, &snapshot_path, &winner) {
                Ok(()) => {
                    winner.publish_completion(chain.deployment.chain_id, &progress);
                    last_processed = winner.target;
                    forest = winner.forest;
                }
                Err(err) => {
                    warn!(
                        err = %err.without_url(),
                        source = winner.source.as_str(),
                        target = winner.target,
                        fallback_from = last_processed,
                        "merkle forest catch-up persistence failed; keeping the loaded forest"
                    );
                }
            }
        }

        Ok((
            Arc::new(RwLock::new(forest)),
            last_processed,
            snapshot_path,
            last_anchor,
        ))
    }

    fn anchor_dir(&self) -> PathBuf {
        self.blob_dir().join("merkle_forest").join("anchors")
    }

    fn find_latest_anchor(
        &self,
        chain: &ChainConfig,
    ) -> Result<Option<(PathBuf, u64)>, ChainError> {
        let dir = self.anchor_dir();
        if !dir.exists() {
            return Ok(None);
        }
        let mut latest: Option<(PathBuf, u64)> = None;
        for entry in std::fs::read_dir(&dir).map_err(PersistError::Io)? {
            let entry = entry.map_err(PersistError::Io)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if let Some(block) =
                parse_anchor_block(chain.deployment.chain_id, chain.deployment.contract, name)
            {
                let path = entry.path();
                match &latest {
                    Some((_, latest_block)) if *latest_block >= block => {}
                    _ => latest = Some((path, block)),
                }
            }
        }
        Ok(latest)
    }
}

/// Returns whether the block hash `loaded_meta` records for `last_processed`
/// is no longer canonical. Catching up would build on the orphaned block and
/// persist over the metadata that shows it, so the caller skips catch-up.
/// Without a provider, or when the check is skipped or fails, catch-up runs.
async fn loaded_forest_reorged(
    chain: &ChainConfig,
    rpc: Option<&ProviderHandle>,
    archive_provider: Option<&DynProvider>,
    loaded_meta: Option<(u64, [u8; 32])>,
    last_processed: u64,
) -> bool {
    let (Some(rpc), Some((meta_last_block, stored_hash))) = (rpc, loaded_meta) else {
        return false;
    };
    match chain
        .check_forest_meta(
            &rpc.provider,
            archive_provider,
            meta_last_block,
            stored_hash,
            last_processed,
        )
        .await
    {
        Ok(ForestMetaCheck::Mismatch { current_hash }) => {
            warn!(
                chain_id = chain.deployment.chain_id,
                block = last_processed,
                stored_hash = %FixedBytes::<32>::from(stored_hash),
                current_hash = %FixedBytes::<32>::from(current_hash),
                "loaded merkle forest block reorged; skipping forest catch-up"
            );
            true
        }
        Ok(_) => false,
        Err(err) => {
            debug!(
                err = %err.without_url(),
                chain_id = chain.deployment.chain_id,
                rpc_index = rpc.index,
                block = last_processed,
                "loaded merkle forest reorg check failed; running forest catch-up"
            );
            false
        }
    }
}

/// Where a startup or stall-fallback forest candidate came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ForestCandidateSource {
    IndexedArtifacts,
    Squid,
    Rpc,
}

impl ForestCandidateSource {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::IndexedArtifacts => "indexed_artifacts",
            Self::Squid => "squid",
            Self::Rpc => "rpc",
        }
    }
}

/// A forest caught up on its own copy of the current forest. Nothing is
/// persisted or installed until a caller chooses it.
pub(super) struct ForestCandidate {
    pub(super) forest: MerkleForest,
    pub(super) target: u64,
    /// Hash of `target`, as an RPC provider returned it. A source whose
    /// target no provider confirms yields no candidate.
    pub(super) target_hash: [u8; 32],
    pub(super) source: ForestCandidateSource,
    /// First block the candidate caught up from.
    from_block: u64,
    /// Commitments applied, when the source counts them.
    commitments: Option<usize>,
    /// Progress update that reports the candidate complete.
    completion: SyncProgressUpdate,
}

impl ForestCandidate {
    /// Publishes completion progress, as is, and logs the catch-up as
    /// complete. Call only once the candidate is persisted.
    pub(super) fn publish_completion(&self, chain_id: u64, progress: &ForestProgressReporter<'_>) {
        progress.publish_final(self.completion);
        let (from_block, target, commitments) = (self.from_block, self.target, self.commitments);
        match self.source {
            ForestCandidateSource::IndexedArtifacts => info!(
                chain_id,
                from_block, target, commitments, "artifact-backed merkle forest catch-up complete"
            ),
            ForestCandidateSource::Squid => info!(
                chain_id,
                from_block, target, commitments, "indexed forest catch-up complete"
            ),
            ForestCandidateSource::Rpc => info!(
                chain_id,
                from_block, target, "RPC merkle forest catch-up complete"
            ),
        }
    }
}

/// Publishes forest catch-up progress from racing candidates without moving
/// it backwards: block progress below the furthest published block is dropped,
/// and artifact preparation progress shows only until block progress starts.
/// The final completion describes the installed winner and is sent as is.
pub(super) struct ForestProgressReporter<'a> {
    progress_tx: Option<&'a SyncProgressSender>,
    furthest_block: std::sync::Mutex<Option<u64>>,
}

impl<'a> ForestProgressReporter<'a> {
    pub(super) const fn new(progress_tx: Option<&'a SyncProgressSender>) -> Self {
        Self {
            progress_tx,
            furthest_block: std::sync::Mutex::new(None),
        }
    }

    fn publish(&self, update: SyncProgressUpdate) {
        if self.progress_tx.is_none() {
            return;
        }
        let mut furthest_block = self
            .furthest_block
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if matches!(
            update.unit,
            SyncProgressUnit::Block | SyncProgressUnit::CommitmentTail
        ) {
            if furthest_block.is_some_and(|block| update.current_block < block) {
                return;
            }
            *furthest_block = Some(update.current_block);
        } else if furthest_block.is_some() {
            return;
        }
        drop(furthest_block);
        send_sync_progress(self.progress_tx, update);
    }

    /// Publishes the winner's completion without the race filter.
    fn publish_final(&self, update: SyncProgressUpdate) {
        send_sync_progress(self.progress_tx, update);
    }

    /// Publishes the latest update on `relay`, if it has not been published.
    fn relay(&self, relay: &mut watch::Receiver<Option<SyncProgressUpdate>>) {
        if !relay.has_changed().unwrap_or(false) {
            return;
        }
        if let Some(update) = *relay.borrow_and_update() {
            self.publish(update);
        }
    }
}

/// Races indexed catch-up against the RPC candidate, when the tail from
/// `from_block` to `safe_head` qualifies for it, and returns the first
/// candidate that completes with a target. A candidate that yields nothing
/// doesn't end the race. The loser is dropped and the RPC token cancelled, so
/// it issues no further requests. Nothing is persisted here.
async fn race_forest_candidates(
    chain: &ChainConfig,
    forest: &MerkleForest,
    last_processed: u64,
    from_block: u64,
    safe_head: u64,
    rpc: Option<&ProviderHandle>,
    archive_provider: Option<&DynProvider>,
    progress: &ForestProgressReporter<'_>,
) -> Option<ForestCandidate> {
    let started = Instant::now();
    let chain_id = chain.deployment.chain_id;
    let tail_blocks = if from_block <= safe_head {
        safe_head - from_block + 1
    } else {
        0
    };
    let archive_until_block = chain.sync.archive_until_block;
    let estimated_rpc_requests = chain.estimate_log_requests(from_block, safe_head);
    let rpc_eligible = tail_blocks > chain.sync.block_range
        && (archive_until_block == 0 || from_block > archive_until_block)
        && estimated_rpc_requests <= FOREST_RPC_REQUEST_BUDGET;
    debug!(
        chain_id,
        from_block,
        safe_head,
        tail_blocks,
        candidates = if rpc_eligible {
            "indexed,rpc"
        } else {
            "indexed"
        },
        estimated_rpc_requests,
        rpc_request_budget = FOREST_RPC_REQUEST_BUDGET,
        archive_until_block,
        "merkle forest catch-up race started"
    );
    let cancel = CancellationToken::new();
    let budget = LogRequestBudget::new(FOREST_RPC_REQUEST_BUDGET);
    let winner = {
        let indexed = indexed_forest_candidate(
            chain,
            forest,
            last_processed,
            from_block,
            safe_head,
            rpc,
            archive_provider,
            progress,
        );
        let rpc_candidate = async {
            if rpc_eligible {
                rpc_forest_candidate(
                    chain,
                    forest,
                    from_block,
                    safe_head,
                    archive_provider,
                    &budget,
                    &cancel,
                    progress,
                )
                .await
            } else {
                None
            }
        };
        tokio::pin!(indexed, rpc_candidate);
        let mut indexed_running = true;
        let mut rpc_running = rpc_eligible;
        let winner = loop {
            tokio::select! {
                candidate = &mut indexed, if indexed_running => {
                    indexed_running = false;
                    log_forest_candidate_end(chain_id, "indexed", candidate.as_ref(), None, started);
                    if candidate.is_some() {
                        break candidate;
                    }
                }
                candidate = &mut rpc_candidate, if rpc_running => {
                    rpc_running = false;
                    log_forest_candidate_end(
                        chain_id,
                        "rpc",
                        candidate.as_ref(),
                        Some(&budget),
                        started,
                    );
                    if candidate.is_some() {
                        break candidate;
                    }
                }
                else => break None,
            }
        };
        cancel.cancel();
        for (candidate, running, candidate_budget) in [
            ("indexed", indexed_running, None),
            ("rpc", rpc_running, Some(&budget)),
        ] {
            if running {
                debug!(
                    chain_id,
                    candidate,
                    outcome = "cancelled",
                    get_logs_requests = candidate_budget.map(LogRequestBudget::issued),
                    elapsed_ms = started.elapsed().as_millis(),
                    "merkle forest catch-up candidate finished"
                );
            }
        }
        winner
    };
    if let Some(winner) = &winner {
        info!(
            chain_id,
            source = winner.source.as_str(),
            target = winner.target,
            elapsed_ms = started.elapsed().as_millis(),
            "merkle forest catch-up race won"
        );
    } else {
        debug!(
            chain_id,
            elapsed_ms = started.elapsed().as_millis(),
            "merkle forest catch-up race produced no forest; keeping the loaded forest"
        );
    }
    winner
}

fn log_forest_candidate_end(
    chain_id: u64,
    candidate: &'static str,
    result: Option<&ForestCandidate>,
    budget: Option<&LogRequestBudget>,
    started: Instant,
) {
    debug!(
        chain_id,
        candidate,
        source = result.map(|result| result.source.as_str()),
        outcome = if result.is_some() {
            "confirmed"
        } else {
            "no_result"
        },
        target = result.map(|result| result.target),
        get_logs_requests = budget.map(LogRequestBudget::issued),
        elapsed_ms = started.elapsed().as_millis(),
        "merkle forest catch-up candidate finished"
    );
}

/// Time artifact catch-up runs alone before Squid catch-up from the loaded
/// forest starts next to it.
pub(super) const FOREST_SQUID_HEDGE_DELAY: Duration = Duration::from_secs(15);

/// Runs indexed catch-up on copies of `forest`: indexed artifacts, then Squid
/// on top of the artifact result, or Squid alone. When artifacts yield nothing
/// or are still running after [`FOREST_SQUID_HEDGE_DELAY`], Squid catch-up
/// from `forest` starts next to them, and the first confirmed result wins.
/// Yields the furthest confirmed step.
pub(super) async fn indexed_forest_candidate(
    chain: &ChainConfig,
    forest: &MerkleForest,
    last_processed: u64,
    from_block: u64,
    safe_head: u64,
    rpc: Option<&ProviderHandle>,
    archive_provider: Option<&DynProvider>,
    progress: &ForestProgressReporter<'_>,
) -> Option<ForestCandidate> {
    let started = Instant::now();
    let squid_from_loaded = squid_forest_candidate(
        chain,
        Cow::Borrowed(forest),
        last_processed,
        from_block,
        safe_head,
        rpc,
        archive_provider,
        false,
        progress,
    );
    if chain.sync.indexed_artifact_source.is_none() || from_block > safe_head {
        return squid_from_loaded.await;
    }
    let artifact = artifact_forest_candidate(
        chain,
        forest,
        from_block,
        safe_head,
        rpc,
        archive_provider,
        progress,
    );
    if chain.sync.quick_sync_endpoint.is_none() {
        return artifact.await;
    }
    let artifact = {
        let hedge_delay = tokio::time::sleep(FOREST_SQUID_HEDGE_DELAY);
        tokio::pin!(artifact, squid_from_loaded, hedge_delay);
        let mut artifact_running = true;
        let mut squid_started = false;
        let mut squid_running = true;
        loop {
            tokio::select! {
                candidate = &mut artifact, if artifact_running => {
                    artifact_running = false;
                    if candidate.is_some() {
                        break candidate;
                    }
                    if !squid_started {
                        squid_started = true;
                        log_forest_hedge_started(
                            chain,
                            from_block,
                            safe_head,
                            "artifact_no_result",
                            started,
                        );
                    }
                }
                () = &mut hedge_delay, if !squid_started => {
                    squid_started = true;
                    log_forest_hedge_started(chain, from_block, safe_head, "hedge_delay", started);
                }
                candidate = &mut squid_from_loaded, if squid_started && squid_running => {
                    squid_running = false;
                    if candidate.is_some() {
                        return candidate;
                    }
                }
                else => break None,
            }
        }
        // A Squid hedge still running is dropped here.
    }?;
    let tail_from = artifact
        .target
        .saturating_add(1)
        .max(chain.deployment.deployment_block);
    let tail_blocks = forest_tail_blocks(tail_from, safe_head);
    if chain.should_skip_indexed_forest_catch_up(tail_from, safe_head) {
        debug!(
            chain_id = chain.deployment.chain_id,
            artifact_target = artifact.target,
            safe_head,
            tail_blocks,
            elapsed_ms = started.elapsed().as_millis(),
            "Squid step skipped for one-page tail"
        );
        return Some(artifact);
    }
    let step_started = Instant::now();
    let squid = tokio::time::timeout(
        INDEXED_SQUID_STEP_DEADLINE,
        squid_forest_candidate(
            chain,
            Cow::Borrowed(&artifact.forest),
            artifact.target,
            tail_from,
            safe_head,
            rpc,
            archive_provider,
            true,
            progress,
        ),
    )
    .await;
    match squid {
        Ok(Some(squid)) => Some(squid),
        Ok(None) => Some(artifact),
        Err(_) => {
            debug!(
                chain_id = chain.deployment.chain_id,
                artifact_target = artifact.target,
                safe_head,
                tail_blocks,
                elapsed_ms = step_started.elapsed().as_millis(),
                "Squid step deadline passed"
            );
            Some(artifact)
        }
    }
}

fn log_forest_hedge_started(
    chain: &ChainConfig,
    from_block: u64,
    safe_head: u64,
    trigger: &'static str,
    started: Instant,
) {
    debug!(
        chain_id = chain.deployment.chain_id,
        from_block,
        safe_head,
        tail_blocks = forest_tail_blocks(from_block, safe_head),
        trigger,
        elapsed_ms = started.elapsed().as_millis(),
        "artifact forest hedge started"
    );
}

/// Blocks from `from_block` through `safe_head`; zero for an empty tail.
const fn forest_tail_blocks(from_block: u64, safe_head: u64) -> u64 {
    if from_block <= safe_head {
        safe_head - from_block + 1
    } else {
        0
    }
}

/// Catches a copy of `forest` up from indexed artifacts, starting at
/// `from_block`, and confirms the artifact target's block hash on an available
/// provider, preferring `rpc`.
///
/// Yields no candidate when artifacts are unavailable or fail, when no provider
/// confirms the target, or when the provider hash disagrees with the artifact
/// hash; failures are logged.
async fn artifact_forest_candidate(
    chain: &ChainConfig,
    forest: &MerkleForest,
    from_block: u64,
    safe_head: u64,
    rpc: Option<&ProviderHandle>,
    archive_provider: Option<&DynProvider>,
    progress: &ForestProgressReporter<'_>,
) -> Option<ForestCandidate> {
    let started = Instant::now();
    let mut candidate = forest.clone();
    progress.publish(SyncProgressUpdate::artifact_preparation(
        SyncProgressStage::SynchronizingCommitments,
        0,
        100,
    ));
    let catch_up = match run_artifact_catch_up_with_progress(
        &mut candidate,
        chain,
        from_block,
        safe_head,
        progress,
    )
    .await
    {
        Ok(Some(catch_up)) => catch_up,
        Ok(None) => {
            debug!(
                chain_id = chain.deployment.chain_id,
                from_block,
                safe_head,
                elapsed_ms = started.elapsed().as_millis(),
                "merkle artifact catch-up unavailable"
            );
            return None;
        }
        Err(err) => {
            warn!(
                err = %sync_error_without_url(err),
                chain_id = chain.deployment.chain_id,
                from_block,
                safe_head,
                elapsed_ms = started.elapsed().as_millis(),
                "merkle artifact catch-up failed; falling back to configured indexed sources"
            );
            return None;
        }
    };
    let target = catch_up.target_block;
    let provider_block_hash = confirm_indexed_forest_target(
        chain,
        rpc,
        archive_provider,
        ForestCandidateSource::IndexedArtifacts,
        target,
    )
    .await?;
    if provider_block_hash != catch_up.target_block_hash {
        warn!(
            chain_id = chain.deployment.chain_id,
            target,
            artifact_block_hash = %FixedBytes::<32>::from(catch_up.target_block_hash),
            provider_block_hash = %FixedBytes::<32>::from(provider_block_hash),
            "artifact-backed merkle forest target hash mismatch; falling back to configured indexed sources"
        );
        return None;
    }
    debug!(
        chain_id = chain.deployment.chain_id,
        from_block,
        target,
        commitments = catch_up.progress.commitments,
        elapsed_ms = started.elapsed().as_millis(),
        "artifact-backed merkle forest candidate computed"
    );
    Some(ForestCandidate {
        forest: candidate,
        target,
        target_hash: provider_block_hash,
        source: ForestCandidateSource::IndexedArtifacts,
        from_block,
        commitments: Some(catch_up.progress.commitments),
        completion: SyncProgressUpdate::artifact_applied(
            SyncProgressStage::SynchronizingCommitments,
        ),
    })
}

/// Runs artifact catch-up into `forest`, relaying its preparation progress
/// through `progress`.
async fn run_artifact_catch_up_with_progress(
    forest: &mut MerkleForest,
    chain: &ChainConfig,
    from_block: u64,
    to_block: u64,
    progress: &ForestProgressReporter<'_>,
) -> Result<Option<MerkleArtifactCatchUp>, SyncError> {
    if progress.progress_tx.is_none() {
        return run_merkle_artifact_catch_up_into(forest, chain, from_block, to_block, None).await;
    }
    let (relay_tx, mut relay_rx) = watch::channel(None);
    let catch_up =
        run_merkle_artifact_catch_up_into(forest, chain, from_block, to_block, Some(&relay_tx));
    tokio::pin!(catch_up);
    let result = loop {
        tokio::select! {
            result = &mut catch_up => break result,
            // `changed()` has already marked the update seen, so publish it
            // directly rather than through the `has_changed` gate.
            Ok(()) = relay_rx.changed() => {
                let update = *relay_rx.borrow_and_update();
                if let Some(update) = update {
                    progress.publish(update);
                }
            }
        }
    };
    progress.relay(&mut relay_rx);
    result
}

/// Catches a copy of `forest` up over `from_block..=safe_head` from parallel
/// RPC log pages, then confirms the `safe_head` block hash on a provider that
/// fetched a page. Returns the candidate, if confirmed; failures are logged.
/// Requests are reserved on `budget`.
async fn rpc_forest_candidate(
    chain: &ChainConfig,
    forest: &MerkleForest,
    from_block: u64,
    safe_head: u64,
    archive_provider: Option<&DynProvider>,
    budget: &LogRequestBudget,
    cancel: &CancellationToken,
    progress: &ForestProgressReporter<'_>,
) -> Option<ForestCandidate> {
    let mut candidate = forest.clone();
    let (result, stats) = chain
        .fetch_logs_in_parallel(
            from_block,
            safe_head,
            FOREST_RPC_PARALLELISM,
            budget,
            cancel,
            |mut page| {
                sort_logs(&mut page.logs);
                candidate.apply_commitment_updates_from_logs(&page.logs)?;
                progress.publish(commitment_sync_progress_update(
                    false,
                    from_block,
                    page.to_block,
                    safe_head,
                ));
                Ok(())
            },
        )
        .await;
    if let Err(err) = result {
        debug!(
            err = %err.without_url(),
            from_block,
            safe_head,
            get_logs_requests = stats.get_logs_requests,
            "RPC merkle forest catch-up failed"
        );
        return None;
    }
    // Roots are computed once for the whole tail rather than per page; the
    // forest is the same either way.
    candidate.compute_roots();
    let providers = chain.rpcs.available_providers();
    let Some(rpc) = stats
        .providers
        .iter()
        .filter(|provider| provider.pages > 0)
        .find_map(|provider| providers.iter().find(|rpc| rpc.index == provider.rpc_index))
        .or_else(|| providers.first())
    else {
        debug!(
            safe_head,
            "no provider available to confirm the RPC merkle forest target"
        );
        return None;
    };
    match chain
        .fetch_confirmed_block_hash(&rpc.provider, archive_provider, safe_head)
        .await
    {
        Ok(Some(target_hash)) => Some(ForestCandidate {
            forest: candidate,
            target: safe_head,
            target_hash,
            source: ForestCandidateSource::Rpc,
            from_block,
            commitments: None,
            completion: commitment_sync_progress_update(false, from_block, safe_head, safe_head),
        }),
        Ok(None) => {
            debug!(
                rpc_index = rpc.index,
                safe_head, "RPC merkle forest target block hash unconfirmed"
            );
            None
        }
        Err(err) => {
            debug!(
                err = %err.without_url(),
                rpc_index = rpc.index,
                safe_head,
                "failed to fetch confirmed RPC merkle forest target block hash"
            );
            None
        }
    }
}

/// Catches `forest`, copied if borrowed, up from the configured Squid endpoint
/// to the lesser of the Squid indexed height and `safe_head`, starting at
/// `from_block`, and confirms the target's block hash on an available
/// provider, preferring `rpc`.
///
/// Yields no candidate when Squid is not configured, is not ahead of
/// `last_processed`, or fails, or when no provider confirms the target;
/// failures are logged.
pub(super) async fn squid_forest_candidate(
    chain: &ChainConfig,
    forest: Cow<'_, MerkleForest>,
    last_processed: u64,
    from_block: u64,
    safe_head: u64,
    rpc: Option<&ProviderHandle>,
    archive_provider: Option<&DynProvider>,
    artifact_catch_up_applied: bool,
    progress: &ForestProgressReporter<'_>,
) -> Option<ForestCandidate> {
    let endpoint = chain.sync.quick_sync_endpoint.clone()?;
    let client = QuickSyncClient::with_http_client(endpoint.clone(), chain.http_client.clone());
    let indexed_height = match client.fetch_squid_height().await {
        Ok(indexed_height) => indexed_height,
        Err(err) => {
            warn!(
                err = %sync_error_without_url(err),
                "indexed forest status query failed; falling back to RPC"
            );
            return None;
        }
    };
    let target = indexed_height.min(safe_head);
    info!(
        chain_id = chain.deployment.chain_id,
        indexed_height,
        safe_head,
        current_block = last_processed,
        target,
        "indexed forest catch-up target"
    );
    if target <= last_processed || from_block > target {
        return None;
    }
    let mut candidate = forest.into_owned();
    let config = QuickSyncConfig {
        endpoint,
        start_block: from_block,
        end_block: Some(target),
        page_size: DEFAULT_PAGE_SIZE,
        http_client: Some(chain.http_client.clone()),
    };
    progress.publish(commitment_sync_progress_update(
        artifact_catch_up_applied,
        from_block,
        from_block,
        target,
    ));
    let sync_progress =
        match run_quick_sync_into_with_progress(&mut candidate, config, |page_progress| {
            progress.publish(commitment_sync_progress_update(
                artifact_catch_up_applied,
                page_progress.start_block,
                page_progress.latest_block,
                target,
            ));
        })
        .await
        {
            Ok(sync_progress) => sync_progress,
            Err(err) => {
                warn!(
                    err = %sync_error_without_url(err),
                    fallback_from = last_processed,
                    "indexed forest catch-up failed; falling back to RPC"
                );
                return None;
            }
        };
    let target_hash = confirm_indexed_forest_target(
        chain,
        rpc,
        archive_provider,
        ForestCandidateSource::Squid,
        target,
    )
    .await?;
    debug!(
        chain_id = chain.deployment.chain_id,
        from_block,
        target,
        commitments = sync_progress.commitments,
        "indexed forest candidate computed"
    );
    Some(ForestCandidate {
        forest: candidate,
        target,
        target_hash,
        source: ForestCandidateSource::Squid,
        from_block,
        commitments: Some(sync_progress.commitments),
        completion: commitment_sync_progress_update(
            artifact_catch_up_applied,
            from_block,
            target,
            target,
        ),
    })
}

/// Reads the confirmed block hash of an indexed candidate's `target` from an
/// available provider, preferring `rpc` while the pool still offers it. The
/// provider is chosen at the read, since a long catch-up can outlast the
/// provider it started with. Yields `None`, logged, when no provider is
/// available or the read fails or returns no block.
async fn confirm_indexed_forest_target(
    chain: &ChainConfig,
    rpc: Option<&ProviderHandle>,
    archive_provider: Option<&DynProvider>,
    source: ForestCandidateSource,
    target: u64,
) -> Option<[u8; 32]> {
    let providers = chain.rpcs.available_providers();
    let Some(rpc) = rpc
        .filter(|rpc| providers.iter().any(|provider| provider.index == rpc.index))
        .or_else(|| providers.first())
    else {
        debug!(
            chain_id = chain.deployment.chain_id,
            source = source.as_str(),
            target,
            "no provider available to confirm the indexed merkle forest target"
        );
        return None;
    };
    match chain
        .fetch_confirmed_block_hash(&rpc.provider, archive_provider, target)
        .await
    {
        Ok(Some(target_hash)) => Some(target_hash),
        Ok(None) => {
            debug!(
                chain_id = chain.deployment.chain_id,
                source = source.as_str(),
                rpc_index = rpc.index,
                target,
                "indexed merkle forest target block hash unconfirmed"
            );
            None
        }
        Err(err) => {
            warn!(
                err = %err.without_url(),
                chain_id = chain.deployment.chain_id,
                source = source.as_str(),
                rpc_index = rpc.index,
                target,
                "failed to fetch confirmed indexed merkle forest target block hash"
            );
            None
        }
    }
}

/// Writes `candidate` as the forest snapshot at `snapshot_path`, with its
/// target block and hash as the forest metadata.
pub(super) fn persist_forest_candidate(
    db: &DbStore,
    chain: &ChainConfig,
    snapshot_path: &Path,
    candidate: &ForestCandidate,
) -> Result<(), ChainError> {
    persist_indexed_forest_snapshot(
        db,
        chain,
        snapshot_path,
        candidate.target,
        candidate.target_hash,
        &candidate.forest,
    )
}

fn persist_indexed_forest_snapshot(
    db: &DbStore,
    chain: &ChainConfig,
    snapshot_path: &Path,
    last_block: u64,
    block_hash: [u8; 32],
    forest: &MerkleForest,
) -> Result<(), ChainError> {
    MerkleForestSnapshot::write(
        snapshot_path,
        chain.deployment.chain_id,
        chain.deployment.contract,
        last_block,
        forest,
    )?;
    db.update_merkle_forest_meta(
        chain.deployment.chain_id,
        &chain.deployment.contract.to_string(),
        snapshot_path,
        last_block,
        SNAPSHOT_VERSION,
        block_hash,
    )?;
    Ok(())
}

/// Returns `err` with any reqwest request URL removed, for logging.
fn sync_error_without_url(err: SyncError) -> SyncError {
    match err {
        SyncError::Request(err) => SyncError::Request(err.without_url()),
        other => other,
    }
}

const fn commitment_sync_progress_update(
    is_tail: bool,
    start_block: u64,
    current_block: u64,
    target_block: u64,
) -> SyncProgressUpdate {
    if is_tail {
        SyncProgressUpdate::commitment_tail(start_block, current_block, target_block)
    } else {
        SyncProgressUpdate::new(
            SyncProgressStage::SynchronizingCommitments,
            start_block,
            current_block,
            target_block,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::{Address, Duration, QueryRpcPool};
    use crate::{IndexedArtifactManifestSource, IndexedArtifactSourceConfig};
    use alloy::primitives::U256;
    use local_db::DbConfig;
    use merkletree::tree::MerkleTreeUpdate;
    use url::Url;

    #[tokio::test]
    async fn persist_indexed_forest_snapshot_writes_reorg_metadata() {
        let root_dir = temp_db_root("persist-indexed-forest-snapshot");
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        db.ensure_blob_dir("merkle_forest")
            .expect("create merkle forest blob dir");
        let mut chain = chain_config();
        // A caller-supplied deployment must retain its scan start and cache identity.
        chain.deployment.chain_id = 999_999;
        chain.deployment.contract = Address::from([0x42; 20]);
        chain.deployment.deployment_block = 100;
        let (_, last_processed, _, _) = db
            .load_or_initialize_forest(&chain, 0, None, None)
            .await
            .expect("initialize custom deployment");
        assert_eq!(last_processed, 99);
        let relative = DbStore::relative_blob_path(
            "merkle_forest",
            &format!(
                "forest-{}-{}.msgpack",
                chain.deployment.chain_id, chain.deployment.contract
            ),
        );
        let snapshot_path = db.resolve_path(&relative);
        let mut forest = MerkleForest::new();
        forest
            .insert_leaf(MerkleTreeUpdate {
                tree_number: 0,
                tree_position: 0,
                hash: U256::from(1),
            })
            .expect("insert leaf");
        forest.compute_roots();
        let block_hash = [0x44; 32];

        persist_indexed_forest_snapshot(&db, &chain, &snapshot_path, 123, block_hash, &forest)
            .expect("persist snapshot");

        let meta = db
            .get_merkle_forest_meta(
                chain.deployment.chain_id,
                &chain.deployment.contract.to_string(),
            )
            .expect("read forest meta")
            .expect("forest meta present");
        assert_eq!(meta.last_block, 123);
        assert_eq!(meta.hash, block_hash);
        let snapshot = MerkleForestSnapshot::load(
            &snapshot_path,
            chain.deployment.chain_id,
            chain.deployment.contract,
        )
        .expect("load snapshot")
        .expect("snapshot present");
        assert_eq!(snapshot.last_processed_block, 123);

        drop(db);
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("reopen db");
        let (_, last_processed, _, _) = db
            .load_or_initialize_forest(&chain, 123, None, None)
            .await
            .expect("restore custom deployment");
        assert_eq!(last_processed, 123);
        assert!(
            db.get_merkle_forest_meta(1, &chain.deployment.contract.to_string())
                .expect("read different chain")
                .is_none()
        );
        assert!(
            db.get_merkle_forest_meta(chain.deployment.chain_id, &Address::ZERO.to_string())
                .expect("read different contract")
                .is_none()
        );
        drop(db);
        std::fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn skips_indexed_forest_catch_up_for_small_tail_with_or_without_sources() {
        let mut chain = chain_config();
        chain.sync.block_range = 100;

        assert!(chain.should_skip_indexed_forest_catch_up(101, 200));
        assert!(chain.should_skip_indexed_forest_catch_up(200, 200));
        // An empty tail, including a start without a safe head.
        assert!(chain.should_skip_indexed_forest_catch_up(201, 200));
        assert!(chain.should_skip_indexed_forest_catch_up(1, 0));

        chain.sync.indexed_artifact_source = Some(indexed_artifact_source());
        chain.sync.quick_sync_endpoint = Some(Url::parse("https://squid.example").expect("url"));
        assert!(chain.should_skip_indexed_forest_catch_up(101, 200));
    }

    #[test]
    fn uses_indexed_forest_catch_up_for_large_tail() {
        let mut chain = chain_config();
        chain.sync.indexed_artifact_source = Some(indexed_artifact_source());
        chain.sync.block_range = 100;

        assert!(!chain.should_skip_indexed_forest_catch_up(100, 200));
    }

    fn chain_config() -> ChainConfig {
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
                anchor_interval: 0,
                anchor_retention: 0,
            },
            rpcs: Arc::new(QueryRpcPool::new(
                vec![Url::parse("http://127.0.0.1:8545").expect("rpc url")],
                Duration::from_secs(1),
            )),
            archive_rpc_url: None,
            block_time: Duration::from_secs(12),
            finality_depth: 0,
            http_client: reqwest::Client::new(),
            progress_tx: None,
        }
    }

    fn indexed_artifact_source() -> IndexedArtifactSourceConfig {
        IndexedArtifactSourceConfig {
            trusted_publisher_pubkey: FixedBytes::from([0x22; 32]),
            manifest_source: IndexedArtifactManifestSource::Url(
                Url::parse("https://artifact.example/manifest.json").expect("url"),
            ),
            gateway_urls: vec![Url::parse("https://gateway.example").expect("url")],
            gateway_pool: None,
            manifest_reuse: crate::IndexedArtifactManifestReuse::default(),
            max_manifest_age: None,
            concurrency: 6,
            max_in_flight_bytes: 64 * 1024 * 1024,
        }
    }

    fn temp_db_root(name: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("sync-service-{name}-{unique}"));
        std::fs::create_dir_all(&dir).expect("create temp db dir");
        dir
    }
}
