//! The startup race between Squid wallet pages and indexed artifact preparation.

use std::collections::VecDeque;

use super::{
    ChainService, IndexedWalletArtifactSession, IndexedWalletPage, IndexedWalletPageKind, Instant,
    SquidIndexedWalletReadSession, SyncProgressSender, WalletConfig, WalletIndexedCatchUpSource,
    WalletStartupSyncError, debug, info,
};

/// Most rows the Squid wallet candidate holds while it races artifact
/// preparation. Long gaps past this bound are left to the artifact source.
const WALLET_SQUID_RACE_ROW_BUDGET: usize = 20_000;

/// Squid wallet pages fetched through `target` and held without committing.
pub(in crate::chain) struct SquidWalletCandidate {
    pub(super) session: SquidIndexedWalletReadSession,
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

pub(super) enum WalletCatchUpRaceWinner {
    Artifacts(IndexedWalletArtifactSession),
    Squid(SquidWalletCandidate),
    /// Artifacts yielded no session and Squid didn't fail, so catch-up takes
    /// the existing path after an artifact failure.
    ArtifactsUnavailable,
    /// Both candidates failed.
    None,
}

impl ChainService {
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
    pub(super) async fn race_indexed_wallet_catch_up_sources(
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
}
