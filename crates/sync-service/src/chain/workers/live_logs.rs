//! The live log loop and its indexed merkle forest fallbacks.

use std::ops::ControlFlow;

use crate::chain::{
    ChainConfig, ForestCandidate, ForestLag, ForestMetaCheck, ForestProgressReporter, HashMap,
    LiveForestProgressCause, Path, PathBuf, indexed_forest_candidate, persist_forest_candidate,
    squid_forest_candidate, wallet_tail_fallback_stale_timeout,
};

use super::{
    Arc, CancellationToken, ChainService, Duration, DynProvider, INDEXED_TAIL_FALLBACK_COOLDOWN,
    Instrument, JoinHandle, LogBatch, ProviderHandle, QueryRpcPool, WalletScanApply,
    WalletScanRowsPayload, debug, min, sort_logs, warn, watch,
};

/// State the live log task works with across loop iterations.
struct LiveLogLoop {
    service: Arc<ChainService>,
    rpcs: Arc<QueryRpcPool>,
    archive_provider: Option<DynProvider>,
    forest_last_rx: watch::Receiver<u64>,
    safe_head_rx: watch::Receiver<u64>,
    snapshot_path: PathBuf,
    cancel: CancellationToken,
    sources: IndexedForestSources,
    stall: ForestStallTracker,
    /// At most one far-behind attempt runs. Its slot is cleared when its
    /// result is taken, so a finished handle is never polled again.
    attempt: Option<FarBehindAttempt>,
    /// A finished attempt's candidate, installed only after a conclusive
    /// reorg check: one that confirms the stored forest block hash or
    /// finds none to compare.
    pending: Option<ForestCandidate>,
}

/// What a live log stage asks the loop to do instead of going on to the next stage.
enum LiveStep {
    /// Start the next iteration.
    NextIteration,
    /// Stop the loop; `run` then aborts the far-behind attempt.
    Stop,
}

pub(in crate::chain) fn spawn_live_log_loop(
    service: Arc<ChainService>,
    rpcs: Arc<QueryRpcPool>,
    archive_provider: Option<DynProvider>,
    forest_last_rx: watch::Receiver<u64>,
    safe_head_rx: watch::Receiver<u64>,
    snapshot_path: PathBuf,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    let sources = IndexedForestSources::of(&service.chain);
    let stall =
        ForestStallTracker::new(wallet_tail_fallback_stale_timeout(service.chain.block_time));
    let live_loop = LiveLogLoop {
        service,
        rpcs,
        archive_provider,
        forest_last_rx,
        safe_head_rx,
        snapshot_path,
        cancel,
        sources,
        stall,
        attempt: None,
        pending: None,
    };
    tokio::spawn(live_loop.run().instrument(tracing::info_span!("sync_live")))
}

impl LiveLogLoop {
    async fn run(mut self) {
        loop {
            if matches!(
                self.run_iteration().await,
                ControlFlow::Break(LiveStep::Stop)
            ) {
                break;
            }
        }
        // Every exit leaves through here: the attempt is aborted and its
        // task dropped before the loop's own task completes.
        abort_far_behind_attempt(&mut self.attempt).await;
    }

    /// Runs one pass of the live log stages; `Break` says what the loop does next.
    async fn run_iteration(&mut self) -> ControlFlow<LiveStep> {
        let chain_id = self.service.chain.deployment.chain_id;
        self.wait_for_wake().await?;

        let safe_head = *self.safe_head_rx.borrow();
        if safe_head == 0 && self.service.chain.deployment.deployment_block > 0 {
            return self.sleep_poll_interval().await;
        }
        let last_processed = *self.forest_last_rx.borrow();
        let now = tokio::time::Instant::now();
        self.stall.observe(
            last_processed,
            safe_head,
            self.service
                .chain
                .live_forest_lag(last_processed, safe_head),
            now,
        );
        if last_processed >= safe_head {
            if let Some(candidate) = self.pending.take() {
                log_far_behind_result(
                    chain_id,
                    last_processed,
                    candidate.target,
                    "forest_at_safe_head",
                );
            }
            return self.sleep_poll_interval().await;
        }
        // The reorg check runs before any indexed attempt starts. A
        // far-behind install or a stall fallback needs a conclusive
        // check: one that confirms the stored forest block hash or
        // finds none to compare. An attempt may still start after an
        // inconclusive check, and a later rewind aborts it and
        // discards its result.
        let rpc = self.rpcs.random_provider();
        let reorg_check_conclusive = self
            .check_forest_reorg_before_attempts(rpc.as_ref(), safe_head, last_processed)
            .await?;
        self.install_pending_candidate(reorg_check_conclusive, last_processed)
            .await?;
        let last_processed = *self.forest_last_rx.borrow();
        if last_processed >= safe_head {
            return ControlFlow::Break(LiveStep::NextIteration);
        }
        if self.attempt.is_none() {
            self.run_due_indexed_trigger(
                now,
                rpc.as_ref(),
                reorg_check_conclusive,
                last_processed,
                safe_head,
            )
            .await?;
        }
        let Some(rpc) = rpc else {
            warn!("no healthy rpc providers available");
            return self.sleep_poll_interval().await;
        };

        let batch = self
            .fetch_live_batch(&rpc, last_processed, safe_head)
            .await?;
        self.apply_live_batch(batch).await
    }

    /// Waits until something wakes the loop and takes a finished far-behind attempt's candidate.
    async fn wait_for_wake(&mut self) -> ControlFlow<LiveStep> {
        let chain_id = self.service.chain.deployment.chain_id;
        let forest_block = *self.forest_last_rx.borrow();
        let safe_head = *self.safe_head_rx.borrow();
        self.stall.observe(
            forest_block,
            safe_head,
            self.service.chain.live_forest_lag(forest_block, safe_head),
            tokio::time::Instant::now(),
        );
        // A running attempt wakes the loop when it finishes, and no
        // other attempt starts before then.
        let attempt_deadline = if self.attempt.is_none() {
            self.stall.deadline(self.sources)
        } else {
            None
        };
        let finished = tokio::select! {
            biased;
            () = self.cancel.cancelled() => return ControlFlow::Break(LiveStep::Stop),
            result = far_behind_attempt_finished(&mut self.attempt) => {
                self.attempt.take().map(|finished| (finished, result))
            }
            _ = self.safe_head_rx.changed() => None,
            _ = self.forest_last_rx.changed() => None,
            () = sleep_until_stall_deadline(attempt_deadline) => None,
        };
        if let Some((finished, result)) = finished {
            let (candidate, finished_at) = far_behind_attempt_result(chain_id, &finished, result);
            self.stall.finish_far_behind_attempt(finished_at);
            if let Some(candidate) = candidate
                && let Some(old) = self.pending.replace(candidate)
            {
                log_far_behind_result(
                    chain_id,
                    *self.forest_last_rx.borrow(),
                    old.target,
                    "superseded",
                );
            }
        }
        ControlFlow::Continue(())
    }

    /// Waits one poll interval unless the loop is cancelled first.
    async fn sleep_poll_interval(&self) -> ControlFlow<LiveStep> {
        tokio::select! {
            () = self.cancel.cancelled() => ControlFlow::Break(LiveStep::Stop),
            () = tokio::time::sleep(self.service.chain.sync.poll_interval) => {
                ControlFlow::Break(LiveStep::NextIteration)
            }
        }
    }

    /// Runs the reorg check; `Continue` carries whether it was conclusive.
    async fn check_forest_reorg_before_attempts(
        &mut self,
        rpc: Option<&ProviderHandle>,
        safe_head: u64,
        last_processed: u64,
    ) -> ControlFlow<LiveStep, bool> {
        let chain_id = self.service.chain.deployment.chain_id;
        let Some(rpc) = rpc else {
            return ControlFlow::Continue(false);
        };
        let reorg_check = tokio::select! {
            () = self.cancel.cancelled() => return ControlFlow::Break(LiveStep::Stop),
            result = self.service.check_forest_reorg(
                &rpc.provider,
                self.archive_provider.as_ref(),
                rpc.index,
                &self.snapshot_path,
                safe_head,
                last_processed,
            ) => result,
        };
        let conclusive = match reorg_check {
            Ok(
                ForestMetaCheck::Match | ForestMetaCheck::Unchecked | ForestMetaCheck::StaleMeta,
            ) => true,
            Ok(ForestMetaCheck::Mismatch { .. }) => {
                // The rewind invalidates whatever an attempt built on.
                if abort_far_behind_attempt(&mut self.attempt).await {
                    self.stall
                        .finish_far_behind_attempt(tokio::time::Instant::now());
                    debug!(
                        chain_id,
                        forest_block = last_processed,
                        cooldown_ms = INDEXED_TAIL_FALLBACK_COOLDOWN.as_millis(),
                        "far-behind live forest catch-up aborted by a reorg rewind"
                    );
                }
                if let Some(candidate) = self.pending.take() {
                    log_far_behind_result(
                        chain_id,
                        last_processed,
                        candidate.target,
                        "reorg_reset",
                    );
                }
                true
            }
            // `check_forest_reorg` already logs the missing hash.
            Ok(ForestMetaCheck::Unconfirmed) => false,
            Err(err) => {
                debug!(
                    err = %err.without_url(),
                    rpc_index = rpc.index,
                    "reorg check failed"
                );
                false
            }
        };
        if self.cancel.is_cancelled() {
            return ControlFlow::Break(LiveStep::Stop);
        }
        ControlFlow::Continue(conclusive)
    }

    /// Installs the pending far-behind candidate after a conclusive reorg check.
    async fn install_pending_candidate(
        &mut self,
        reorg_check_conclusive: bool,
        last_processed: u64,
    ) -> ControlFlow<LiveStep> {
        let chain_id = self.service.chain.deployment.chain_id;
        if reorg_check_conclusive && let Some(candidate) = self.pending.take() {
            let target = candidate.target;
            let progress = ForestProgressReporter::new(self.service.chain.progress_tx.as_ref());
            let outcome = install_live_forest_candidate(
                &self.service,
                &self.snapshot_path,
                candidate,
                &progress,
                LiveForestProgressCause::IndexedInstall,
            )
            .await;
            log_far_behind_result(chain_id, last_processed, target, outcome.as_str());
            if outcome == LiveForestInstall::Installed {
                return ControlFlow::Break(LiveStep::NextIteration);
            }
        }
        ControlFlow::Continue(())
    }

    /// Starts a far-behind attempt or runs the Squid stall fallback when one is due.
    async fn run_due_indexed_trigger(
        &mut self,
        now: tokio::time::Instant,
        rpc: Option<&ProviderHandle>,
        reorg_check_conclusive: bool,
        last_processed: u64,
        safe_head: u64,
    ) -> ControlFlow<LiveStep> {
        match self.stall.due(now, self.sources, rpc.is_some()) {
            Some(IndexedForestTrigger::FarBehind) => {
                // Live RPC paging below continues while it runs.
                self.attempt = Some(
                    spawn_far_behind_attempt(
                        &self.service,
                        rpc,
                        self.archive_provider.as_ref(),
                        last_processed,
                        safe_head,
                    )
                    .await,
                );
            }
            Some(IndexedForestTrigger::Stall) if !reorg_check_conclusive => {
                // Retry after another stall period; live RPC
                // paging below continues meanwhile.
                self.stall.defer_next_attempt(tokio::time::Instant::now());
                debug!(
                    forest_block = last_processed,
                    safe_head,
                    "live merkle forest stall fallback deferred after an inconclusive reorg check"
                );
            }
            Some(IndexedForestTrigger::Stall) => {
                let stalled_ms = self.stall.stalled_for(now).as_millis();
                let installed = tokio::select! {
                    () = self.cancel.cancelled() => return ControlFlow::Break(LiveStep::Stop),
                    installed = run_live_squid_forest_fallback(
                        &self.service,
                        rpc,
                        self.archive_provider.as_ref(),
                        &self.snapshot_path,
                        last_processed,
                        safe_head,
                    ) => installed,
                };
                let outcome = if installed.is_some() {
                    "applied"
                } else {
                    self.stall.defer_next_attempt(tokio::time::Instant::now());
                    "not_applied"
                };
                debug!(
                    stalled_ms,
                    forest_block = last_processed,
                    safe_head,
                    target = ?installed,
                    outcome,
                    "live merkle forest stall fallback to Squid finished"
                );
                return ControlFlow::Break(LiveStep::NextIteration);
            }
            None => {}
        }
        ControlFlow::Continue(())
    }

    /// Fetches the next live RPC log batch and checks the block hashes that bound it.
    async fn fetch_live_batch(
        &self,
        rpc: &ProviderHandle,
        last_processed: u64,
        safe_head: u64,
    ) -> ControlFlow<LiveStep, Arc<LogBatch>> {
        let from_block = last_processed.saturating_add(1);
        let to_block = min(
            from_block + self.service.chain.sync.block_range - 1,
            safe_head,
        );
        let read_scope = self.service.begin_public_scan_read();
        let logs_result = tokio::select! {
            () = self.cancel.cancelled() => return ControlFlow::Break(LiveStep::Stop),
            result = self.service.chain.fetch_logs_for_range(
                rpc,
                self.archive_provider.as_ref(),
                from_block,
                to_block,
                &self.cancel,
            ) => result,
        };
        let mut logs = match logs_result {
            Ok(logs) => logs,
            Err(err) => {
                let mark_unhealthy = err.should_mark_rpc_unhealthy();
                if err.is_rpc_throttled() {
                    warn!(
                        rpc_index = rpc.index,
                        "rpc is throttled, will retry with another..."
                    );
                } else {
                    warn!(
                        err = %err.without_url(),
                        rpc_index = rpc.index,
                        "failed to fetch logs, retrying..."
                    );
                }
                if mark_unhealthy {
                    self.rpcs.mark_bad_provider(rpc);
                }
                return ControlFlow::Break(LiveStep::NextIteration);
            }
        };
        sort_logs(&mut logs);
        let block_timestamps = if logs.is_empty() {
            HashMap::new()
        } else {
            match tokio::select! {
                () = self.cancel.cancelled() => return ControlFlow::Break(LiveStep::Stop),
                result = self.service.chain.fetch_log_block_timestamps(
                    &rpc.provider,
                    self.archive_provider.as_ref(),
                    &logs,
                ) => result,
            } {
                Ok(block_timestamps) => block_timestamps,
                Err(err) => {
                    let mark_unhealthy = err.should_mark_rpc_unhealthy();
                    warn!(
                        err = %err.without_url(),
                        rpc_index = rpc.index,
                        "failed to fetch log block timestamps"
                    );
                    if mark_unhealthy {
                        self.rpcs.mark_bad_provider(rpc);
                    }
                    return ControlFlow::Break(LiveStep::NextIteration);
                }
            }
        };
        if let Some(archive_endpoint) = self
            .service
            .chain
            .archive_boundary_crossed_by(from_block, to_block)
        {
            match tokio::select! {
                () = self.cancel.cancelled() => return ControlFlow::Break(LiveStep::Stop),
                result = self.service.chain.fetch_block_hash(
                    &rpc.provider,
                    self.archive_provider.as_ref(),
                    archive_endpoint,
                ) => result,
            } {
                Ok(Some(_)) => {}
                Ok(None) => {
                    warn!(
                        rpc_index = rpc.index,
                        archive_endpoint, "live RPC range does not prove its archive boundary"
                    );
                    self.rpcs.mark_bad_provider(rpc);
                    return ControlFlow::Break(LiveStep::NextIteration);
                }
                Err(err) => {
                    let mark_unhealthy = err.should_mark_rpc_unhealthy();
                    warn!(
                        err = %err.without_url(),
                        rpc_index = rpc.index,
                        archive_endpoint,
                        "failed to fetch live RPC archive-boundary hash"
                    );
                    if mark_unhealthy {
                        self.rpcs.mark_bad_provider(rpc);
                    }
                    return ControlFlow::Break(LiveStep::NextIteration);
                }
            }
        }
        // One read suffices: `to_block` is already `finality_depth`
        // deep, and the next iteration's reorg check confirms it.
        let to_block_hash = match tokio::select! {
            () = self.cancel.cancelled() => return ControlFlow::Break(LiveStep::Stop),
            result = self.service.chain.fetch_block_hash(
                &rpc.provider,
                self.archive_provider.as_ref(),
                to_block,
            ) => result,
        } {
            Ok(Some(hash)) => Some(hash),
            Ok(None) => {
                warn!(
                    rpc_index = rpc.index,
                    to_block, "live RPC range does not prove its endpoint"
                );
                self.rpcs.mark_bad_provider(rpc);
                return ControlFlow::Break(LiveStep::NextIteration);
            }
            Err(err) => {
                let mark_unhealthy = err.should_mark_rpc_unhealthy();
                warn!(
                    err = %err.without_url(),
                    rpc_index = rpc.index,
                    to_block,
                    "failed to fetch live RPC endpoint hash"
                );
                if mark_unhealthy {
                    self.rpcs.mark_bad_provider(rpc);
                }
                return ControlFlow::Break(LiveStep::NextIteration);
            }
        };
        if self.cancel.is_cancelled() {
            return ControlFlow::Break(LiveStep::Stop);
        }
        let batch = Arc::new(LogBatch {
            from_block,
            to_block,
            logs,
            block_timestamps,
            to_block_hash,
            read_scope,
        });
        ControlFlow::Continue(batch)
    }

    /// Applies a batch to the forest and public scan, broadcasts it and persists the snapshot.
    async fn apply_live_batch(&self, batch: Arc<LogBatch>) -> ControlFlow<LiveStep> {
        let from_block = batch.from_block;
        let to_block = batch.to_block;
        let batch_hash = batch.to_block_hash;
        if self.cancel.is_cancelled() {
            return ControlFlow::Break(LiveStep::Stop);
        }
        if let Err(err) = self.service.apply_forest_updates(&batch).await {
            warn!(?err, "failed to apply forest updates");
            return ControlFlow::Continue(());
        }
        if self.cancel.is_cancelled() {
            return ControlFlow::Break(LiveStep::Stop);
        }
        let log_count = batch.logs.len();
        match WalletScanApply::rows_from_log_batch(
            from_block,
            to_block,
            &batch,
            self.service.rpc_scan_source_for_range(from_block),
        ) {
            Ok(apply) => {
                self.service.record_public_scan_apply(&apply).await;
                if let WalletScanRowsPayload::Rows(rows) = &apply.rows.payload {
                    self.service.poi_submitter.observe(rows).await;
                }
            }
            Err(err) => {
                warn!(
                    ?err,
                    from_block, to_block, "failed to normalize recent public live rows"
                );
            }
        }
        if self.service.live_log_tx.send(batch).is_err() {
            debug!(
                from_block,
                to_block, log_count, "failed to broadcast live log batch"
            );
        }
        self.service
            .publish_forest_progress(to_block, LiveForestProgressCause::RpcApply);
        if self.cancel.is_cancelled() {
            return ControlFlow::Break(LiveStep::Stop);
        }
        if let Err(err) = self
            .service
            .persist_forest_snapshot(&self.snapshot_path, to_block, batch_hash)
            .await
        {
            warn!(?err, "failed to persist forest snapshot");
        }
        ControlFlow::Continue(())
    }
}

/// Indexed sources the live forest loop can catch up from.
#[derive(Debug, Clone, Copy)]
pub(in crate::chain) struct IndexedForestSources {
    pub(in crate::chain) artifacts: bool,
    pub(in crate::chain) squid: bool,
}

impl IndexedForestSources {
    pub(in crate::chain) const fn of(chain: &ChainConfig) -> Self {
        Self {
            artifacts: chain.sync.indexed_artifact_source.is_some(),
            squid: chain.sync.quick_sync_endpoint.is_some(),
        }
    }
}

/// What made an indexed live forest attempt due.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::chain) enum IndexedForestTrigger {
    /// The forest's lag exceeds the RPC request budget.
    FarBehind,
    /// The forest has not advanced for the stall period.
    Stall,
}

/// Tracks how long the live forest has lagged the safe head without advancing,
/// whether that lag is far behind, and when the next indexed attempt may
/// start.
pub(in crate::chain) struct ForestStallTracker {
    stall_period: Duration,
    forest_block: u64,
    far_behind: bool,
    lagging_since: Option<tokio::time::Instant>,
    next_attempt_not_before: Option<tokio::time::Instant>,
}

impl ForestStallTracker {
    pub(in crate::chain) const fn new(stall_period: Duration) -> Self {
        Self {
            stall_period,
            forest_block: 0,
            far_behind: false,
            lagging_since: None,
            next_attempt_not_before: None,
        }
    }

    /// Restarts the stall period when the forest advances or starts lagging,
    /// and clears it while the forest has reached the safe head. `lag` is the
    /// current estimate for the lag from `forest_block` to `safe_head`.
    pub(in crate::chain) const fn observe(
        &mut self,
        forest_block: u64,
        safe_head: u64,
        lag: ForestLag,
        now: tokio::time::Instant,
    ) {
        if forest_block >= safe_head {
            self.lagging_since = None;
        } else if forest_block > self.forest_block || self.lagging_since.is_none() {
            self.lagging_since = Some(now);
        }
        self.forest_block = forest_block;
        self.far_behind = lag.far_behind;
    }

    /// Whether the far-behind trigger applies: the forest is far behind and
    /// artifacts or Squid are configured.
    const fn far_behind_applies(&self, sources: IndexedForestSources) -> bool {
        self.far_behind && (sources.artifacts || sources.squid)
    }

    /// When the next attempt becomes due, if the forest is lagging and a
    /// trigger's sources are configured: at once while the forest is far
    /// behind, otherwise after the stall period when Squid is configured.
    /// Either waits for the previous attempt's deferral.
    pub(in crate::chain) fn deadline(
        &self,
        sources: IndexedForestSources,
    ) -> Option<tokio::time::Instant> {
        let lagging_since = self.lagging_since?;
        let due_from = if self.far_behind_applies(sources) {
            lagging_since
        } else if sources.squid {
            lagging_since + self.stall_period
        } else {
            return None;
        };
        Some(
            self.next_attempt_not_before
                .map_or(due_from, |not_before| due_from.max(not_before)),
        )
    }

    /// The trigger of the attempt due at `now`, if any. No attempt is due
    /// while no RPC provider is available to confirm its target.
    pub(in crate::chain) fn due(
        &self,
        now: tokio::time::Instant,
        sources: IndexedForestSources,
        provider_available: bool,
    ) -> Option<IndexedForestTrigger> {
        if !provider_available || self.deadline(sources).is_none_or(|deadline| deadline > now) {
            return None;
        }
        Some(if self.far_behind_applies(sources) {
            IndexedForestTrigger::FarBehind
        } else {
            IndexedForestTrigger::Stall
        })
    }

    fn stalled_for(&self, now: tokio::time::Instant) -> Duration {
        self.lagging_since
            .map_or(Duration::ZERO, |since| now.saturating_duration_since(since))
    }

    /// Holds off the next attempt for one stall period after a failed or
    /// unproductive stall attempt.
    fn defer_next_attempt(&mut self, now: tokio::time::Instant) {
        self.next_attempt_not_before = Some(now + self.stall_period);
    }

    /// Holds off the next attempt for [`INDEXED_TAIL_FALLBACK_COOLDOWN`] from
    /// when a far-behind attempt finished, whatever its outcome.
    pub(in crate::chain) fn finish_far_behind_attempt(
        &mut self,
        finished_at: tokio::time::Instant,
    ) {
        self.next_attempt_not_before = Some(finished_at + INDEXED_TAIL_FALLBACK_COOLDOWN);
    }
}

async fn sleep_until_stall_deadline(deadline: Option<tokio::time::Instant>) {
    if let Some(deadline) = deadline {
        tokio::time::sleep_until(deadline).await;
    } else {
        std::future::pending::<()>().await;
    }
}

/// A far-behind attempt's candidate and the time its task finished.
type FarBehindOutput = (Option<ForestCandidate>, tokio::time::Instant);

/// A far-behind indexed attempt running as a compute-only task.
struct FarBehindAttempt {
    task: AbortOnDropHandle<FarBehindOutput>,
    forest_block: u64,
    started: tokio::time::Instant,
}

/// Aborts its task when dropped. The live loop aborts and awaits its attempt
/// on every exit, so this only covers a panic that unwinds the loop.
struct AbortOnDropHandle<T>(JoinHandle<T>);

impl<T> Drop for AbortOnDropHandle<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Starts a far-behind indexed attempt on a copy of the live forest. The task
/// only computes a candidate: it publishes no progress, persists nothing and
/// never touches the live forest. The live loop installs its result.
async fn spawn_far_behind_attempt(
    service: &Arc<ChainService>,
    rpc: Option<&ProviderHandle>,
    archive_provider: Option<&DynProvider>,
    forest_block: u64,
    safe_head: u64,
) -> FarBehindAttempt {
    let chain = &service.chain;
    let from_block = forest_block
        .saturating_add(1)
        .max(chain.deployment.deployment_block);
    debug!(
        chain_id = chain.deployment.chain_id,
        forest_block,
        safe_head,
        lag_blocks = safe_head.saturating_sub(forest_block),
        estimated_requests = chain
            .live_forest_lag(forest_block, safe_head)
            .estimated_requests,
        from_block,
        cooldown_ms = INDEXED_TAIL_FALLBACK_COOLDOWN.as_millis(),
        "far-behind live forest catch-up triggered"
    );
    let base = service.forest.read().await.clone();
    let task = tokio::spawn(
        {
            let service = Arc::clone(service);
            let rpc = rpc.cloned();
            let archive_provider = archive_provider.cloned();
            async move {
                let progress = ForestProgressReporter::new(None);
                let candidate = indexed_forest_candidate(
                    &service.chain,
                    &base,
                    forest_block,
                    from_block,
                    safe_head,
                    rpc.as_ref(),
                    archive_provider.as_ref(),
                    &progress,
                )
                .await;
                (candidate, tokio::time::Instant::now())
            }
        }
        .in_current_span(),
    );
    FarBehindAttempt {
        task: AbortOnDropHandle(task),
        forest_block,
        started: tokio::time::Instant::now(),
    }
}

/// Waits for the in-flight far-behind attempt to finish, or forever when
/// there is none.
async fn far_behind_attempt_finished(
    attempt: &mut Option<FarBehindAttempt>,
) -> Result<FarBehindOutput, tokio::task::JoinError> {
    match attempt {
        Some(attempt) => (&mut attempt.task.0).await,
        None => std::future::pending().await,
    }
}

/// Logs a finished far-behind attempt and returns its candidate and the time
/// it finished, from which the cooldown runs.
fn far_behind_attempt_result(
    chain_id: u64,
    attempt: &FarBehindAttempt,
    result: Result<FarBehindOutput, tokio::task::JoinError>,
) -> FarBehindOutput {
    let (candidate, finished_at, outcome) = match result {
        Ok((Some(candidate), finished_at)) => (Some(candidate), finished_at, "confirmed"),
        Ok((None, finished_at)) => (None, finished_at, "no_result"),
        Err(err) => {
            warn!(
                chain_id,
                is_panic = err.is_panic(),
                "far-behind live forest catch-up task failed"
            );
            (None, tokio::time::Instant::now(), "failed")
        }
    };
    debug!(
        chain_id,
        forest_block = attempt.forest_block,
        target = candidate.as_ref().map(|candidate| candidate.target),
        outcome,
        elapsed_ms = finished_at
            .saturating_duration_since(attempt.started)
            .as_millis(),
        cooldown_ms = INDEXED_TAIL_FALLBACK_COOLDOWN.as_millis(),
        "far-behind live forest catch-up finished"
    );
    (candidate, finished_at)
}

fn log_far_behind_result(chain_id: u64, forest_block: u64, target: u64, outcome: &str) {
    debug!(
        chain_id,
        forest_block, target, outcome, "far-behind live forest catch-up result"
    );
}

/// Aborts the in-flight far-behind attempt, if any, and waits until its task
/// has dropped its copy of the forest and its service handle. Returns whether
/// an attempt was in flight.
async fn abort_far_behind_attempt(attempt: &mut Option<FarBehindAttempt>) -> bool {
    let Some(mut attempt) = attempt.take() else {
        return false;
    };
    attempt.task.0.abort();
    // A result that finished before the abort is discarded too.
    let _ = (&mut attempt.task.0).await;
    true
}

/// How [`install_live_forest_candidate`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiveForestInstall {
    Installed,
    ForestAtTarget,
    PersistFailed,
}

impl LiveForestInstall {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Installed => "installed",
            Self::ForestAtTarget => "forest_at_target",
            Self::PersistFailed => "persist_failed",
        }
    }
}

/// Installs an indexed `candidate` as the live forest. It is dropped when the
/// live forest already reached its target; otherwise it is persisted, swapped
/// in under the write lock, and written as an anchor snapshot, then the
/// forest block is published, and completion progress. Last, when the PPOI
/// submitter holds pending entries, the leaves the install added past the
/// replaced forest are reported to it, after the lock is released.
///
/// Runs inside the live loop, the only forest writer, so the forest block
/// read first stays current until the swap.
async fn install_live_forest_candidate(
    service: &ChainService,
    snapshot_path: &Path,
    mut candidate: ForestCandidate,
    progress: &ForestProgressReporter<'_>,
    cause: LiveForestProgressCause,
) -> LiveForestInstall {
    let target = candidate.target;
    let forest_block = *service.forest_last_tx.borrow();
    if forest_block >= target {
        return LiveForestInstall::ForestAtTarget;
    }
    if let Err(err) =
        persist_forest_candidate(&service.db, &service.chain, snapshot_path, &candidate)
    {
        warn!(
            err = %err.without_url(),
            source = candidate.source.as_str(),
            fallback_from = forest_block,
            target,
            "indexed forest catch-up persistence failed; falling back to RPC"
        );
        return LiveForestInstall::PersistFailed;
    }
    let mut forest = service.forest.write().await;
    // The replaced forest drops with `candidate`, after the lock is released.
    std::mem::swap(&mut *forest, &mut candidate.forest);
    // Diffed against the replaced forest, not the candidate's own base.
    let added_leaves = if service.poi_submitter.pending_count() > 0 {
        forest.leaves_beyond(&candidate.forest).collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    if let Err(err) = service.maybe_write_anchor_snapshot(snapshot_path, target, &forest) {
        warn!(?err, target, "failed to write anchor snapshot");
    }
    drop(forest);
    service.publish_forest_progress(target, cause);
    candidate.publish_completion(service.chain.deployment.chain_id, progress);
    drop(candidate);
    if !added_leaves.is_empty() {
        service
            .poi_submitter
            .observe_forest_leaves(added_leaves)
            .await;
    }
    LiveForestInstall::Installed
}

/// Runs Squid forest catch-up for a stalled live forest and installs the
/// result as the live forest, returning the new forest block.
///
/// Runs inside the live loop, so the live loop stays the only forest writer.
async fn run_live_squid_forest_fallback(
    service: &ChainService,
    rpc: Option<&ProviderHandle>,
    archive_provider: Option<&DynProvider>,
    snapshot_path: &Path,
    forest_block: u64,
    safe_head: u64,
) -> Option<u64> {
    let base = service.forest.read().await.clone();
    let progress = ForestProgressReporter::new(service.chain.progress_tx.as_ref());
    let candidate = squid_forest_candidate(
        &service.chain,
        std::borrow::Cow::Owned(base),
        forest_block,
        forest_block.saturating_add(1),
        safe_head,
        rpc,
        archive_provider,
        false,
        &progress,
    )
    .await?;
    let target = candidate.target;
    let installed = install_live_forest_candidate(
        service,
        snapshot_path,
        candidate,
        &progress,
        LiveForestProgressCause::StallInstall,
    )
    .await;
    (installed == LiveForestInstall::Installed).then_some(target)
}
