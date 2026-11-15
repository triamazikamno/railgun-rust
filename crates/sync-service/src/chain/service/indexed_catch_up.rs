use std::collections::VecDeque;

use crate::chain::{
    SyncError, WalletIndexedCatchUpStatusGuard, artifact_failure_can_fallback_to_squid,
    await_wallet_cancellation,
};

use super::{
    BackfillEvent, CancellationToken, ChainService, IndexedWalletArtifactPageOutcome,
    IndexedWalletArtifactSession, IndexedWalletCatchUpSourceOrder, IndexedWalletPage,
    IndexedWalletPageKind, Instant, PublicDataPlaneDiagnosticKind, PublicScanRange,
    PublicScanReadScope, SquidIndexedWalletReadSession, SyncProgressSender,
    WalletBackfillStartResult, WalletConfig, WalletIndexedCatchUpSource, WalletScanApply,
    WalletStartupSyncError, WalletSyncContext, debug, info, mpsc, wallet_has_persistence_failure,
    warn,
};

/// Most rows the Squid wallet candidate holds while it races artifact
/// preparation. Long gaps past this bound are left to the artifact source.
const WALLET_SQUID_RACE_ROW_BUDGET: usize = 20_000;

/// Squid wallet pages fetched through `target` and held without committing.
pub(in crate::chain) struct SquidWalletCandidate {
    session: SquidIndexedWalletReadSession,
    pub(in crate::chain) target: u64,
    /// Pages in block order, each with its first block.
    pub(in crate::chain) pages: VecDeque<(u64, IndexedWalletPage)>,
    pub(in crate::chain) rows: usize,
}

pub(in crate::chain) enum SquidWalletCandidateOutcome {
    Ready(SquidWalletCandidate),
    /// Squid is indexed below the wallet's next block.
    NoResult,
    Failed {
        target: Option<u64>,
        rows: usize,
    },
    OverBudget {
        target: u64,
        rows: usize,
    },
}

impl SquidWalletCandidateOutcome {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::Ready(_) => "ready",
            Self::NoResult => "no_result",
            Self::Failed { .. } => "failed",
            Self::OverBudget { .. } => "over_budget",
        }
    }

    const fn target(&self) -> Option<u64> {
        match self {
            Self::Ready(candidate) => Some(candidate.target),
            Self::NoResult => None,
            Self::Failed { target, .. } => *target,
            Self::OverBudget { target, .. } => Some(*target),
        }
    }

    const fn rows(&self) -> usize {
        match self {
            Self::Ready(candidate) => candidate.rows,
            Self::NoResult => 0,
            Self::Failed { rows, .. } | Self::OverBudget { rows, .. } => *rows,
        }
    }
}

enum WalletCatchUpRaceWinner {
    Artifacts(IndexedWalletArtifactSession),
    Squid(SquidWalletCandidate),
    /// Artifacts yielded no session and Squid didn't fail, so catch-up takes
    /// the existing path after an artifact failure.
    ArtifactsUnavailable,
    /// Both candidates failed.
    None,
}

/// Takes the held Squid page that starts at `from_block`. Held pages that no
/// longer match the commit cursor are dropped and fetched again.
fn take_held_squid_page(
    pages: &mut VecDeque<(u64, IndexedWalletPage)>,
    from_block: u64,
) -> Option<IndexedWalletPage> {
    if pages
        .front()
        .is_some_and(|(page_from, _)| *page_from == from_block)
    {
        return pages.pop_front().map(|(_, page)| page);
    }
    pages.clear();
    None
}

/// The indexed source a wallet catch-up reads pages from.
enum IndexedCatchUpSession {
    Artifacts(IndexedWalletArtifactSession),
    /// Pages held from the startup race are used before Squid is asked again.
    Squid {
        session: SquidIndexedWalletReadSession,
        held_pages: VecDeque<(u64, IndexedWalletPage)>,
    },
}

impl IndexedCatchUpSession {
    const fn squid(session: SquidIndexedWalletReadSession) -> Self {
        Self::Squid {
            session,
            held_pages: VecDeque::new(),
        }
    }

    const fn is_artifacts(&self) -> bool {
        matches!(self, Self::Artifacts(_))
    }

    const fn source(&self) -> WalletIndexedCatchUpSource {
        match self {
            Self::Artifacts(_) => WalletIndexedCatchUpSource::IndexedArtifacts,
            Self::Squid { .. } => WalletIndexedCatchUpSource::Squid,
        }
    }

    const fn indexed_height(&self) -> u64 {
        match self {
            Self::Artifacts(session) => session.latest_indexed_block(),
            Self::Squid { session, .. } => session.indexed_height(),
        }
    }

    const fn read_scope(&self) -> PublicScanReadScope {
        match self {
            Self::Artifacts(session) => session.read_scope(),
            Self::Squid { session, .. } => session.read_scope(),
        }
    }

    /// Reads the page for `from_block..=to_block` from artifacts, a held Squid page or a Squid
    /// fetch. Only the fetch can be cancelled; `None` means `cancel` fired during it.
    async fn read_page(
        &mut self,
        page_kind: IndexedWalletPageKind,
        from_block: u64,
        to_block: u64,
        cancel: &CancellationToken,
    ) -> Option<Result<IndexedWalletArtifactPageOutcome, SyncError>> {
        match self {
            Self::Artifacts(session) => Some(session.page_for_block_range(from_block, to_block)),
            Self::Squid {
                session,
                held_pages,
            } => {
                if let Some(page) = take_held_squid_page(held_pages, from_block) {
                    return Some(Ok(IndexedWalletArtifactPageOutcome::Page(page)));
                }
                let page = await_wallet_cancellation(
                    cancel,
                    IndexedWalletPage::fetch(session.client(), page_kind, from_block, to_block),
                )
                .await?;
                Some(page.map(IndexedWalletArtifactPageOutcome::Page))
            }
        }
    }
}

/// Inputs that stay fixed for one indexed catch-up call.
#[derive(Clone, Copy)]
struct IndexedCatchUpScope<'a> {
    cfg: &'a WalletConfig,
    cancel: &'a CancellationToken,
    source_order: IndexedWalletCatchUpSourceOrder,
    safe_head: u64,
    /// The cursor after cached coverage, which early exits report and fallbacks compare against.
    last_scanned: u64,
    artifact_progress_tx: Option<&'a SyncProgressSender>,
}

/// The source an indexed catch-up starts reading from.
struct SelectedIndexedCatchUpSource {
    session: IndexedCatchUpSession,
    target: u64,
    /// Taken after the initial artifact preparation or race, before any further probing.
    started: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::chain) enum WalletIndexedTailFallbackResult {
    Completed(u64),
    Unavailable,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::chain) enum IndexedWalletCatchUpOutcome {
    Completed(u64),
    Unavailable(u64),
    Cancelled(u64),
}

impl ChainService {
    pub(in crate::chain) async fn try_indexed_wallet_tail_catch_up(
        &self,
        cache_key: &str,
        from_block: u64,
        target_block: u64,
        progress: crate::types::WalletSchedulableProgress,
        sender: &mpsc::Sender<BackfillEvent>,
        actor_cancel: &CancellationToken,
    ) -> WalletIndexedTailFallbackResult {
        if from_block > target_block {
            return WalletIndexedTailFallbackResult::Unavailable;
        }
        let (cfg, start_block, handle, cancel) = {
            let wallet = self.wallet.read().await;
            let registration = wallet
                .as_ref()
                .filter(|registration| registration.cfg.cache_key.as_str() == cache_key);
            let Some(registration) = registration else {
                return WalletIndexedTailFallbackResult::Unavailable;
            };
            if !registration.cfg.use_indexed_wallet_catch_up {
                debug!(cache_key = %cache_key, "indexed wallet tail fallback disabled");
                return WalletIndexedTailFallbackResult::Unavailable;
            }
            (
                registration.cfg.clone(),
                registration.start_block,
                registration.handle.clone(),
                actor_cancel.clone(),
            )
        };
        // Ticket must still match current view generation before using the range.
        let Some(progress) = handle.revalidate_schedulable_progress(progress) else {
            return WalletIndexedTailFallbackResult::Unavailable;
        };
        let last_scanned = from_block.saturating_sub(1);
        let started = Instant::now();
        let outcome = self
            .indexed_wallet_catch_up_outcome(
                WalletSyncContext {
                    cfg: &cfg,
                    start_block,
                    handle: &handle,
                    backfill_sender: sender,
                },
                last_scanned,
                target_block,
                &cancel,
                IndexedWalletCatchUpSourceOrder::SquidFirst,
                true,
                progress,
            )
            .await;
        if cancel.is_cancelled() {
            return WalletIndexedTailFallbackResult::Cancelled;
        }
        let checkpoint = match outcome {
            IndexedWalletCatchUpOutcome::Completed(checkpoint)
            | IndexedWalletCatchUpOutcome::Unavailable(checkpoint) => checkpoint,
            IndexedWalletCatchUpOutcome::Cancelled(_) => {
                return WalletIndexedTailFallbackResult::Cancelled;
            }
        };
        if checkpoint < from_block {
            debug!(
                cache_key = %cache_key,
                from_block,
                target_block,
                checkpoint,
                elapsed_ms = started.elapsed().as_millis(),
                "indexed wallet tail fallback did not advance"
            );
            return WalletIndexedTailFallbackResult::Unavailable;
        }
        info!(
            cache_key = %cache_key,
            from_block,
            target_block,
            checkpoint,
            elapsed_ms = started.elapsed().as_millis(),
            "indexed wallet tail fallback complete"
        );
        WalletIndexedTailFallbackResult::Completed(checkpoint)
    }

    /// Fetches Squid wallet pages from `from_block` through the lesser of the
    /// Squid indexed height and `safe_head`, and holds them without committing.
    /// Stops without a result once it holds more than `row_budget` rows.
    pub(in crate::chain) async fn squid_wallet_candidate(
        &self,
        cfg: &WalletConfig,
        from_block: u64,
        safe_head: u64,
        row_budget: usize,
    ) -> SquidWalletCandidateOutcome {
        let Some(session) = self.probe_squid_indexed_wallet_source(cfg).await else {
            return SquidWalletCandidateOutcome::Failed {
                target: None,
                rows: 0,
            };
        };
        let target = session.indexed_height().min(safe_head);
        if target < from_block {
            return SquidWalletCandidateOutcome::NoResult;
        }
        let v2_start_block = self.chain.deployment.v2_start_block;
        let mut pages = VecDeque::new();
        let mut rows = 0_usize;
        let mut page_from = from_block;
        while page_from <= target {
            let page_kind = IndexedWalletPageKind::for_from_block(page_from, v2_start_block);
            let to_block = page_kind.to_block(
                page_from,
                target,
                v2_start_block,
                self.chain.sync.indexed_wallet_block_range,
            );
            let page =
                match IndexedWalletPage::fetch(session.client(), page_kind, page_from, to_block)
                    .await
                {
                    Ok(page) => page,
                    Err(err) => {
                        debug!(
                            err = %WalletStartupSyncError::from(err).without_url(),
                            cache_key = %cfg.cache_key,
                            from_block = page_from,
                            to_block,
                            "Squid wallet race page failed"
                        );
                        return SquidWalletCandidateOutcome::Failed {
                            target: Some(target),
                            rows,
                        };
                    }
                };
            rows = rows.saturating_add(page.row_count());
            if rows > row_budget {
                return SquidWalletCandidateOutcome::OverBudget { target, rows };
            }
            let next_from = page.checkpoint_block.saturating_add(1);
            pages.push_back((page_from, page));
            page_from = next_from;
        }
        SquidWalletCandidateOutcome::Ready(SquidWalletCandidate {
            session,
            target,
            pages,
            rows,
        })
    }

    /// Races Squid wallet pages against artifact preparation for startup
    /// catch-up and returns the first candidate that completes. A candidate
    /// that yields nothing doesn't end the race. The loser is dropped, so it
    /// issues no further requests. Nothing is committed here.
    async fn race_indexed_wallet_catch_up_sources(
        &self,
        cfg: &WalletConfig,
        from_block: u64,
        safe_head: u64,
        progress_tx: Option<&SyncProgressSender>,
    ) -> WalletCatchUpRaceWinner {
        let started = Instant::now();
        debug!(
            cache_key = %cfg.cache_key,
            from_block,
            safe_head,
            gap_blocks = safe_head.saturating_sub(from_block).saturating_add(1),
            candidates = "indexed_artifacts,squid",
            squid_row_budget = WALLET_SQUID_RACE_ROW_BUDGET,
            "wallet catch-up race started"
        );
        let winner = {
            let artifacts = self.prepare_indexed_wallet_artifact_session(
                cfg,
                from_block,
                safe_head,
                progress_tx,
            );
            let squid = self.squid_wallet_candidate(
                cfg,
                from_block,
                safe_head,
                WALLET_SQUID_RACE_ROW_BUDGET,
            );
            tokio::pin!(artifacts, squid);
            let mut artifacts_running = true;
            let mut squid_running = true;
            let mut squid_failed = false;
            let winner = loop {
                // Artifacts stay the preferred source when both finish together.
                tokio::select! {
                    biased;
                    session = &mut artifacts, if artifacts_running => {
                        artifacts_running = false;
                        debug!(
                            cache_key = %cfg.cache_key,
                            source = WalletIndexedCatchUpSource::IndexedArtifacts.as_str(),
                            outcome = if session.is_some() { "ready" } else { "no_result" },
                            target = session.as_ref().map(IndexedWalletArtifactSession::target_block),
                            elapsed_ms = started.elapsed().as_millis(),
                            "wallet catch-up race candidate finished"
                        );
                        if let Some(session) = session {
                            break WalletCatchUpRaceWinner::Artifacts(session);
                        }
                    }
                    outcome = &mut squid, if squid_running => {
                        squid_running = false;
                        debug!(
                            cache_key = %cfg.cache_key,
                            source = WalletIndexedCatchUpSource::Squid.as_str(),
                            outcome = outcome.as_str(),
                            target = outcome.target(),
                            squid_rows = outcome.rows(),
                            elapsed_ms = started.elapsed().as_millis(),
                            "wallet catch-up race candidate finished"
                        );
                        match outcome {
                            SquidWalletCandidateOutcome::Ready(candidate) => {
                                break WalletCatchUpRaceWinner::Squid(candidate);
                            }
                            SquidWalletCandidateOutcome::Failed { .. } => {
                                squid_failed = true;
                            }
                            SquidWalletCandidateOutcome::NoResult
                            | SquidWalletCandidateOutcome::OverBudget { .. } => {}
                        }
                    }
                    else => break if squid_failed {
                        WalletCatchUpRaceWinner::None
                    } else {
                        WalletCatchUpRaceWinner::ArtifactsUnavailable
                    },
                }
            };
            for (source, running) in [
                (
                    WalletIndexedCatchUpSource::IndexedArtifacts,
                    artifacts_running,
                ),
                (WalletIndexedCatchUpSource::Squid, squid_running),
            ] {
                if running {
                    debug!(
                        cache_key = %cfg.cache_key,
                        source = source.as_str(),
                        outcome = "cancelled",
                        elapsed_ms = started.elapsed().as_millis(),
                        "wallet catch-up race candidate finished"
                    );
                }
            }
            winner
        };
        let won = match &winner {
            WalletCatchUpRaceWinner::Artifacts(session) => Some((
                WalletIndexedCatchUpSource::IndexedArtifacts,
                session.target_block(),
            )),
            WalletCatchUpRaceWinner::Squid(candidate) => {
                Some((WalletIndexedCatchUpSource::Squid, candidate.target))
            }
            WalletCatchUpRaceWinner::ArtifactsUnavailable | WalletCatchUpRaceWinner::None => None,
        };
        if let Some((source, target)) = won {
            info!(
                cache_key = %cfg.cache_key,
                source = source.as_str(),
                target,
                elapsed_ms = started.elapsed().as_millis(),
                "wallet catch-up race won"
            );
        } else {
            debug!(
                cache_key = %cfg.cache_key,
                squid_failed = matches!(winner, WalletCatchUpRaceWinner::None),
                elapsed_ms = started.elapsed().as_millis(),
                "wallet catch-up race produced no source"
            );
        }
        winner
    }

    pub(in crate::chain) async fn indexed_wallet_catch_up(
        &self,
        ctx: WalletSyncContext<'_>,
        last_scanned: u64,
        safe_head: u64,
        cancel: &CancellationToken,
        source_order: IndexedWalletCatchUpSourceOrder,
        expose_status: bool,
        progress: crate::types::WalletSchedulableProgress,
    ) -> u64 {
        match self
            .indexed_wallet_catch_up_outcome(
                ctx,
                last_scanned,
                safe_head,
                cancel,
                source_order,
                expose_status,
                progress,
            )
            .await
        {
            IndexedWalletCatchUpOutcome::Completed(checkpoint)
            | IndexedWalletCatchUpOutcome::Unavailable(checkpoint)
            | IndexedWalletCatchUpOutcome::Cancelled(checkpoint) => checkpoint,
        }
    }

    pub(in crate::chain) async fn indexed_wallet_catch_up_outcome(
        &self,
        ctx: WalletSyncContext<'_>,
        last_scanned: u64,
        safe_head: u64,
        cancel: &CancellationToken,
        source_order: IndexedWalletCatchUpSourceOrder,
        expose_status: bool,
        progress: crate::types::WalletSchedulableProgress,
    ) -> IndexedWalletCatchUpOutcome {
        let WalletSyncContext {
            cfg,
            start_block,
            handle,
            backfill_sender: sender,
        } = ctx;
        if safe_head == 0 {
            debug!(cache_key = %cfg.cache_key, "safe head unavailable; skipping indexed wallet catch-up");
            return IndexedWalletCatchUpOutcome::Unavailable(last_scanned);
        }
        let mut last_scanned = last_scanned;
        let initial_last_scanned = last_scanned;
        let mut from_block = last_scanned.saturating_add(1).max(start_block);
        let Some(status_guard) =
            WalletIndexedCatchUpStatusGuard::claim(handle, expose_status).await
        else {
            debug!(cache_key = %cfg.cache_key, "indexed wallet catch-up already active");
            return IndexedWalletCatchUpOutcome::Unavailable(last_scanned);
        };
        let cached_outcome = self
            .apply_cached_public_scan_coverage(ctx, last_scanned, safe_head, progress)
            .await;
        if cached_outcome.checkpoint > last_scanned {
            last_scanned = cached_outcome.checkpoint;
            from_block = last_scanned.saturating_add(1).max(start_block);
            if cached_outcome.finished || from_block > safe_head {
                return IndexedWalletCatchUpOutcome::Completed(last_scanned);
            }
        }
        if wallet_has_persistence_failure(handle) {
            return IndexedWalletCatchUpOutcome::Unavailable(last_scanned);
        }
        let artifact_progress_tx = if last_scanned == initial_last_scanned {
            cfg.progress_tx.as_ref()
        } else {
            None
        };
        let scope = IndexedCatchUpScope {
            cfg,
            cancel,
            source_order,
            safe_head,
            last_scanned,
            artifact_progress_tx,
        };
        let SelectedIndexedCatchUpSource {
            session: mut active,
            mut target,
            started: catch_up_started,
        } = match self
            .select_indexed_catch_up_source(scope, &status_guard, from_block)
            .await
        {
            Ok(selected) => selected,
            Err(outcome) => return outcome,
        };
        if from_block > target {
            let squid_tail = if active.is_artifacts() {
                let Some(squid_tail) = await_wallet_cancellation(
                    cancel,
                    self.probe_squid_tail_after_artifact(cfg, from_block, target, safe_head),
                )
                .await
                else {
                    return IndexedWalletCatchUpOutcome::Cancelled(last_scanned);
                };
                squid_tail
            } else {
                None
            };
            if let Some((session, squid_target)) = squid_tail {
                let artifact_target = target;
                active = IndexedCatchUpSession::squid(session);
                target = squid_target;
                self.record_indexed_source_fallback(
                    &status_guard,
                    &active,
                    PublicScanRange::new(from_block, target),
                    "artifact source exhausted before Squid tail",
                )
                .await;
                info!(
                    cache_key = %cfg.cache_key,
                    indexed_source = active.source().as_str(),
                    indexed_height = active.indexed_height(),
                    safe_head,
                    from_block,
                    artifact_target,
                    target,
                    indexed_block_range = self.chain.sync.indexed_wallet_block_range,
                    "indexed wallet artifact tail target"
                );
            } else {
                debug!(
                    cache_key = %cfg.cache_key,
                    elapsed_ms = catch_up_started.elapsed().as_millis(),
                    "indexed wallet catch-up skipped; cache already at target"
                );
                return IndexedWalletCatchUpOutcome::Completed(last_scanned);
            }
        }
        let mut checkpoint = last_scanned;
        let Some(target_result) = await_wallet_cancellation(
            cancel,
            handle.start_backfill(&cfg.cache_key, sender, progress, target),
        )
        .await
        else {
            return IndexedWalletCatchUpOutcome::Cancelled(checkpoint);
        };
        let driver = match target_result {
            WalletBackfillStartResult::Accepted { grant, .. } => grant.activate(),
            WalletBackfillStartResult::Rejected { .. } => {
                return IndexedWalletCatchUpOutcome::Unavailable(checkpoint);
            }
        };
        loop {
            if from_block > target {
                let squid_tail = if active.is_artifacts() {
                    let Some(squid_tail) = await_wallet_cancellation(
                        cancel,
                        self.probe_squid_tail_after_artifact(cfg, from_block, target, safe_head),
                    )
                    .await
                    else {
                        driver.retire(&cfg.cache_key).await;
                        return IndexedWalletCatchUpOutcome::Cancelled(checkpoint);
                    };
                    squid_tail
                } else {
                    None
                };
                let Some((session, squid_target)) = squid_tail else {
                    break;
                };
                let artifact_target = target;
                active = IndexedCatchUpSession::squid(session);
                target = squid_target;
                self.record_indexed_source_fallback(
                    &status_guard,
                    &active,
                    PublicScanRange::new(from_block, target),
                    "artifact source exhausted before Squid tail",
                )
                .await;
                info!(
                    cache_key = %cfg.cache_key,
                    indexed_source = active.source().as_str(),
                    indexed_height = active.indexed_height(),
                    safe_head,
                    from_block,
                    artifact_target,
                    target,
                    indexed_block_range = self.chain.sync.indexed_wallet_block_range,
                    "indexed wallet artifact tail target"
                );
                continue;
            }
            if cancel.is_cancelled() {
                driver.retire(&cfg.cache_key).await;
                return IndexedWalletCatchUpOutcome::Cancelled(checkpoint);
            }
            let page_started = Instant::now();
            let page_kind = IndexedWalletPageKind::for_from_block(
                from_block,
                self.chain.deployment.v2_start_block,
            );
            let to_block = page_kind.to_block(
                from_block,
                target,
                self.chain.deployment.v2_start_block,
                self.chain.sync.indexed_wallet_block_range,
            );
            let fetch_started = Instant::now();
            let read_scope = active.read_scope();
            let Some(page_result) = active
                .read_page(page_kind, from_block, to_block, cancel)
                .await
            else {
                driver.retire(&cfg.cache_key).await;
                return IndexedWalletCatchUpOutcome::Cancelled(checkpoint);
            };
            let page = match page_result {
                Ok(IndexedWalletArtifactPageOutcome::Page(page)) => page,
                Ok(IndexedWalletArtifactPageOutcome::Exhausted { checkpoint_block }) => {
                    checkpoint = checkpoint.max(checkpoint_block);
                    from_block = checkpoint.saturating_add(1);
                    target = checkpoint;
                    debug!(
                        cache_key = %cfg.cache_key,
                        checkpoint,
                        from_block,
                        safe_head,
                        elapsed_ms = page_started.elapsed().as_millis(),
                        "indexed wallet artifact source exhausted at checkpoint"
                    );
                    continue;
                }
                Err(err) => {
                    let err = WalletStartupSyncError::from(err).without_url();
                    if artifact_failure_can_fallback_to_squid(
                        active.is_artifacts(),
                        checkpoint,
                        last_scanned,
                    ) {
                        warn!(
                            err = %err,
                            cache_key = %cfg.cache_key,
                            fallback_from = checkpoint,
                            "indexed wallet artifact page failed before checkpoint; falling back to Squid"
                        );
                        let Some(squid_probe) = await_wallet_cancellation(
                            cancel,
                            self.probe_squid_indexed_wallet_source(cfg),
                        )
                        .await
                        else {
                            driver.retire(&cfg.cache_key).await;
                            return IndexedWalletCatchUpOutcome::Cancelled(checkpoint);
                        };
                        let Some(session) = squid_probe else {
                            driver.retire(&cfg.cache_key).await;
                            return IndexedWalletCatchUpOutcome::Unavailable(checkpoint);
                        };
                        active = IndexedCatchUpSession::squid(session);
                        target = active.indexed_height().min(safe_head);
                        self.record_indexed_source_fallback(
                            &status_guard,
                            &active,
                            PublicScanRange::new(from_block, target),
                            "artifact page failed before checkpoint",
                        )
                        .await;
                        info!(
                            cache_key = %cfg.cache_key,
                            indexed_source = active.source().as_str(),
                            indexed_height = active.indexed_height(),
                            safe_head,
                            from_block,
                            target,
                            indexed_block_range = self.chain.sync.indexed_wallet_block_range,
                            "indexed wallet fallback target"
                        );
                        if from_block > target {
                            debug!(
                                cache_key = %cfg.cache_key,
                                indexed_source = active.source().as_str(),
                                indexed_height = active.indexed_height(),
                                target,
                                elapsed_ms = catch_up_started.elapsed().as_millis(),
                                "indexed wallet fallback skipped; cache already at target"
                            );
                            driver.retire(&cfg.cache_key).await;
                            return IndexedWalletCatchUpOutcome::Completed(checkpoint);
                        }
                        continue;
                    }
                    if !active.is_artifacts()
                        && source_order == IndexedWalletCatchUpSourceOrder::SquidFirst
                        && checkpoint == last_scanned
                    {
                        warn!(
                            err = %err,
                            cache_key = %cfg.cache_key,
                            fallback_from = checkpoint,
                            "indexed wallet Squid page failed before checkpoint; falling back to artifacts"
                        );
                        status_guard.set(
                            WalletIndexedCatchUpSource::IndexedArtifacts,
                            from_block,
                            safe_head,
                        );
                        let Some(prepared) = await_wallet_cancellation(
                            cancel,
                            self.prepare_indexed_wallet_artifact_session(
                                cfg,
                                from_block,
                                safe_head,
                                artifact_progress_tx,
                            ),
                        )
                        .await
                        else {
                            driver.retire(&cfg.cache_key).await;
                            return IndexedWalletCatchUpOutcome::Cancelled(checkpoint);
                        };
                        let Some(session) = prepared else {
                            driver.retire(&cfg.cache_key).await;
                            return IndexedWalletCatchUpOutcome::Unavailable(checkpoint);
                        };
                        target = session.target_block();
                        active = IndexedCatchUpSession::Artifacts(session);
                        self.record_indexed_source_fallback(
                            &status_guard,
                            &active,
                            PublicScanRange::new(from_block, target),
                            "Squid page failed before checkpoint",
                        )
                        .await;
                        info!(
                            cache_key = %cfg.cache_key,
                            indexed_source = active.source().as_str(),
                            indexed_height = active.indexed_height(),
                            safe_head,
                            from_block,
                            target,
                            indexed_block_range = self.chain.sync.indexed_wallet_block_range,
                            "indexed wallet fallback target"
                        );
                        if from_block > target {
                            debug!(
                                cache_key = %cfg.cache_key,
                                indexed_source = active.source().as_str(),
                                indexed_height = active.indexed_height(),
                                target,
                                elapsed_ms = catch_up_started.elapsed().as_millis(),
                                "indexed wallet fallback skipped; cache already at target"
                            );
                            driver.retire(&cfg.cache_key).await;
                            return IndexedWalletCatchUpOutcome::Completed(checkpoint);
                        }
                        continue;
                    }
                    warn!(
                        err = %err,
                        cache_key = %cfg.cache_key,
                        indexed_source = active.source().as_str(),
                        fallback_from = checkpoint,
                        "indexed wallet catch-up page failed; using RPC backfill"
                    );
                    self.record_public_scan_fallback(
                        self.rpc_scan_source_for_range(from_block),
                        PublicScanRange::new(from_block, safe_head),
                        self.begin_public_scan_read(),
                        "indexed wallet catch-up page failed; falling back to RPC",
                    )
                    .await;
                    driver.retire(&cfg.cache_key).await;
                    return if cancel.is_cancelled() {
                        IndexedWalletCatchUpOutcome::Cancelled(checkpoint)
                    } else {
                        IndexedWalletCatchUpOutcome::Unavailable(checkpoint)
                    };
                }
            };
            let fetch_elapsed_ms = fetch_started.elapsed().as_millis();
            if cancel.is_cancelled() {
                driver.retire(&cfg.cache_key).await;
                return IndexedWalletCatchUpOutcome::Cancelled(checkpoint);
            }
            let parse_started = Instant::now();
            let row_count = page.transact_commitments.len()
                + page.shield_commitments.len()
                + page.legacy_encrypted_commitments.len()
                + page.legacy_generated_commitments.len()
                + page.nullifiers.len();
            let transact_rows = page.transact_rows;
            let shield_rows = page.shield_rows;
            let legacy_encrypted_rows = page.legacy_encrypted_rows;
            let legacy_generated_rows = page.legacy_generated_rows;
            let nullifier_rows = page.nullifier_rows;
            let parse_elapsed_ms = parse_started.elapsed().as_millis();
            let page_checkpoint = page.checkpoint_block;
            let apply = WalletScanApply::indexed_rows(
                from_block,
                page_checkpoint,
                page.into_scan_rows(),
                read_scope,
                active.source(),
            );
            if let Err(err) = self.record_public_scan_apply_result(&apply).await {
                debug!(
                    ?err,
                    cache_key = %cfg.cache_key,
                    from_block,
                    to_block = page_checkpoint,
                    "indexed wallet page rejected before wallet apply"
                );
                driver.retire(&cfg.cache_key).await;
                return IndexedWalletCatchUpOutcome::Unavailable(checkpoint);
            }
            let Some(apply_result) =
                await_wallet_cancellation(cancel, driver.apply(&cfg.cache_key, apply)).await
            else {
                driver.retire(&cfg.cache_key).await;
                return IndexedWalletCatchUpOutcome::Cancelled(checkpoint);
            };
            let Some(committed_checkpoint) = apply_result.accepted_committed_to() else {
                warn!(
                    ?apply_result,
                    cache_key = %cfg.cache_key,
                    from_block,
                    to_block = page_checkpoint,
                    "indexed wallet delta was not committed; using RPC backfill from committed cursor"
                );
                driver.retire(&cfg.cache_key).await;
                return if cancel.is_cancelled() {
                    IndexedWalletCatchUpOutcome::Cancelled(checkpoint)
                } else {
                    IndexedWalletCatchUpOutcome::Unavailable(checkpoint)
                };
            };
            checkpoint = committed_checkpoint;
            debug!(
                cache_key = %cfg.cache_key,
                indexed_source = active.source().as_str(),
                page_kind = page_kind.as_str(),
                from_block,
                to_block,
                checkpoint,
                reset_generation = progress.reset_generation,
                transact_rows,
                shield_rows,
                legacy_encrypted_rows,
                legacy_generated_rows,
                nullifier_rows,
                row_count,
                fetch_elapsed_ms,
                parse_elapsed_ms,
                elapsed_ms = page_started.elapsed().as_millis(),
                "indexed wallet catch-up page committed"
            );
            from_block = checkpoint.saturating_add(1);
            if from_block <= target {
                status_guard.set(active.source(), from_block, target);
            }
        }
        info!(
            cache_key = %cfg.cache_key,
            checkpoint,
            target,
            elapsed_ms = catch_up_started.elapsed().as_millis(),
            "indexed wallet catch-up complete"
        );
        driver.retire(&cfg.cache_key).await;
        IndexedWalletCatchUpOutcome::Completed(checkpoint)
    }

    /// Picks the source a catch-up from `from_block` reads first: the artifact/Squid race or
    /// the source `source_order` prefers, then the other source when that one can't serve.
    /// Records the selection, or an RPC fallback when neither source can serve, which ends
    /// the catch-up with the returned outcome.
    async fn select_indexed_catch_up_source(
        &self,
        scope: IndexedCatchUpScope<'_>,
        status_guard: &WalletIndexedCatchUpStatusGuard<'_>,
        from_block: u64,
    ) -> Result<SelectedIndexedCatchUpSource, IndexedWalletCatchUpOutcome> {
        let IndexedCatchUpScope {
            cfg,
            cancel,
            source_order,
            safe_head,
            last_scanned,
            artifact_progress_tx,
        } = scope;
        let squid_race_eligible = source_order == IndexedWalletCatchUpSourceOrder::ArtifactsFirst
            && from_block <= safe_head
            && self.chain.sync.indexed_artifact_source.is_some()
            && self.chain.sync.quick_sync_endpoint.is_some();
        let mut squid_race_winner = None;
        let artifact_session = if squid_race_eligible {
            let Some(winner) = await_wallet_cancellation(
                cancel,
                self.race_indexed_wallet_catch_up_sources(
                    cfg,
                    from_block,
                    safe_head,
                    artifact_progress_tx,
                ),
            )
            .await
            else {
                return Err(IndexedWalletCatchUpOutcome::Cancelled(last_scanned));
            };
            match winner {
                WalletCatchUpRaceWinner::Artifacts(session) => Some(session),
                WalletCatchUpRaceWinner::Squid(candidate) => {
                    squid_race_winner = Some(candidate);
                    None
                }
                // The existing post-artifact-failure path decides, as today.
                WalletCatchUpRaceWinner::ArtifactsUnavailable => None,
                WalletCatchUpRaceWinner::None => {
                    self.record_public_scan_fallback(
                        self.rpc_scan_source_for_range(from_block),
                        PublicScanRange::new(from_block, safe_head),
                        self.begin_public_scan_read(),
                        "indexed wallet sources unavailable; falling back to RPC",
                    )
                    .await;
                    return Err(IndexedWalletCatchUpOutcome::Unavailable(last_scanned));
                }
            }
        } else if source_order == IndexedWalletCatchUpSourceOrder::ArtifactsFirst {
            let Some(session) = await_wallet_cancellation(
                cancel,
                self.prepare_indexed_wallet_artifact_session(
                    cfg,
                    from_block,
                    safe_head,
                    artifact_progress_tx,
                ),
            )
            .await
            else {
                return Err(IndexedWalletCatchUpOutcome::Cancelled(last_scanned));
            };
            session
        } else {
            None
        };
        let catch_up_started = Instant::now();
        let (active, target) = if source_order == IndexedWalletCatchUpSourceOrder::SquidFirst {
            let Some(squid_probe) =
                await_wallet_cancellation(cancel, self.probe_squid_indexed_wallet_source(cfg))
                    .await
            else {
                return Err(IndexedWalletCatchUpOutcome::Cancelled(last_scanned));
            };
            if let Some(session) = squid_probe {
                let height = session.indexed_height();
                let target = height.min(safe_head);
                if from_block <= target {
                    (IndexedCatchUpSession::squid(session), target)
                } else {
                    self.prepare_artifacts_after_squid(
                        scope,
                        status_guard,
                        from_block,
                        "indexed wallet artifacts unavailable after Squid tail gap; falling back to RPC",
                    )
                    .await?
                }
            } else {
                self.prepare_artifacts_after_squid(
                    scope,
                    status_guard,
                    from_block,
                    "indexed wallet sources unavailable; falling back to RPC",
                )
                .await?
            }
        } else if let Some(session) = artifact_session {
            let target = session.target_block();
            (IndexedCatchUpSession::Artifacts(session), target)
        } else if let Some(candidate) = squid_race_winner {
            (
                IndexedCatchUpSession::Squid {
                    session: candidate.session,
                    held_pages: candidate.pages,
                },
                candidate.target,
            )
        } else {
            let Some(squid_probe) =
                await_wallet_cancellation(cancel, self.probe_squid_indexed_wallet_source(cfg))
                    .await
            else {
                return Err(IndexedWalletCatchUpOutcome::Cancelled(last_scanned));
            };
            let Some(session) = squid_probe else {
                self.record_public_scan_fallback(
                    self.rpc_scan_source_for_range(from_block),
                    PublicScanRange::new(from_block, safe_head),
                    self.begin_public_scan_read(),
                    "Squid unavailable for indexed wallet catch-up; falling back to RPC",
                )
                .await;
                return Err(IndexedWalletCatchUpOutcome::Unavailable(last_scanned));
            };
            let height = session.indexed_height();
            (IndexedCatchUpSession::squid(session), height.min(safe_head))
        };
        status_guard.set(active.source(), from_block, target);
        self.public_data_plane
            .record_source_decision(
                PublicDataPlaneDiagnosticKind::SourceSelected,
                active.source().into(),
                PublicScanRange::new(from_block, target),
                active.read_scope(),
                "indexed wallet catch-up source selected",
            )
            .await;
        info!(
            cache_key = %cfg.cache_key,
            indexed_source = active.source().as_str(),
            indexed_height = active.indexed_height(),
            catch_up_ceiling = safe_head,
            from_block,
            target,
            indexed_block_range = self.chain.sync.indexed_wallet_block_range,
            "indexed wallet catch-up target"
        );
        Ok(SelectedIndexedCatchUpSource {
            session: active,
            target,
            started: catch_up_started,
        })
    }

    /// Prepares artifacts when Squid can't serve the catch-up start. Records an RPC fallback
    /// with `fallback_reason` and ends the catch-up when no artifact session is available.
    async fn prepare_artifacts_after_squid(
        &self,
        scope: IndexedCatchUpScope<'_>,
        status_guard: &WalletIndexedCatchUpStatusGuard<'_>,
        from_block: u64,
        fallback_reason: &'static str,
    ) -> Result<(IndexedCatchUpSession, u64), IndexedWalletCatchUpOutcome> {
        status_guard.set(
            WalletIndexedCatchUpSource::IndexedArtifacts,
            from_block,
            scope.safe_head,
        );
        let Some(prepared) = await_wallet_cancellation(
            scope.cancel,
            self.prepare_indexed_wallet_artifact_session(
                scope.cfg,
                from_block,
                scope.safe_head,
                scope.artifact_progress_tx,
            ),
        )
        .await
        else {
            return Err(IndexedWalletCatchUpOutcome::Cancelled(scope.last_scanned));
        };
        let Some(session) = prepared else {
            self.record_public_scan_fallback(
                self.rpc_scan_source_for_range(from_block),
                PublicScanRange::new(from_block, scope.safe_head),
                self.begin_public_scan_read(),
                fallback_reason,
            )
            .await;
            return Err(IndexedWalletCatchUpOutcome::Unavailable(scope.last_scanned));
        };
        let target = session.target_block();
        Ok((IndexedCatchUpSession::Artifacts(session), target))
    }

    /// Publishes `active` as the catch-up source for `range` and records the switch to it as a
    /// source fallback with `reason`.
    async fn record_indexed_source_fallback(
        &self,
        status_guard: &WalletIndexedCatchUpStatusGuard<'_>,
        active: &IndexedCatchUpSession,
        range: PublicScanRange,
        reason: &'static str,
    ) {
        status_guard.set(active.source(), range.from_block, range.to_block);
        self.public_data_plane
            .record_source_decision(
                PublicDataPlaneDiagnosticKind::SourceFallback,
                active.source().into(),
                range,
                active.read_scope(),
                reason,
            )
            .await;
    }
}
