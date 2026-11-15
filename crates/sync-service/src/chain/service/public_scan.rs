use crate::chain::{
    PublicCoverageAnswer, PublicDataPlaneEpoch, PublicDataPlaneError, PublicScanRowsAnswer,
};

use super::{
    Arc, BackfillEvent, CancellationToken, ChainConfig, ChainError, ChainService,
    IndexedWalletArtifactPageOutcome, IndexedWalletArtifactSession, IndexedWalletPage,
    IndexedWalletPageKind, Instant, PublicDataPlaneDiagnosticKind, PublicScanRange,
    PublicScanReadScope, PublicScanSource, RpcTargetPolicy, WalletBackfillFinishResult,
    WalletBackfillStartResult, WalletConfig, WalletHandle, WalletIndexedCatchUpSource,
    WalletScanApply, WalletStartupSyncError, debug, mpsc, wallet_backfill_from_block, warn,
};

#[derive(Debug, Clone, Copy)]
struct PublicScanPagePlan {
    source_range: PublicScanRange,
}

#[derive(Debug, Clone, Copy)]
pub(in crate::chain) struct CachedPublicScanApplyOutcome {
    pub(in crate::chain) checkpoint: u64,
    pub(in crate::chain) finished: bool,
}

impl PublicScanPagePlan {
    fn new(range: PublicScanRange, chain: &ChainConfig) -> Self {
        let rpc_to =
            Self::bounded_to_block(range.from_block, range.to_block, chain.sync.block_range);
        let indexed_page_kind = IndexedWalletPageKind::for_from_block(
            range.from_block,
            chain.deployment.v2_start_block,
        );
        let indexed_to = indexed_page_kind.to_block(
            range.from_block,
            range.to_block,
            chain.deployment.v2_start_block,
            chain.sync.indexed_wallet_block_range.max(1),
        );
        Self {
            source_range: PublicScanRange::new(range.from_block, rpc_to.min(indexed_to)),
        }
    }

    fn bounded_to_block(from_block: u64, target_block: u64, max_blocks: u64) -> u64 {
        let max_blocks = max_blocks.max(1);
        from_block
            .saturating_add(max_blocks.saturating_sub(1))
            .min(target_block)
    }
}

impl ChainService {
    pub async fn public_scan_coverage(
        &self,
        range: PublicScanRange,
    ) -> Result<PublicCoverageAnswer, ChainError> {
        if !range.is_valid() {
            return Err(PublicDataPlaneError::InvalidRange {
                from_block: range.from_block,
                to_block: range.to_block,
            }
            .into());
        }
        let cached = self
            .public_data_plane
            .cached_public_scan_coverage(range)
            .await;
        match &cached {
            PublicCoverageAnswer::ReplayableEmpty {
                range: covered_range,
                source,
                epoch,
            }
            | PublicCoverageAnswer::CoveredWithRows {
                range: covered_range,
                source,
                epoch,
            } => {
                self.public_data_plane
                    .record_source_decision(
                        PublicDataPlaneDiagnosticKind::SourceSelected,
                        *source,
                        *covered_range,
                        PublicScanReadScope::new(*epoch),
                        "cached public coverage selected",
                    )
                    .await;
                return Ok(cached);
            }
            PublicCoverageAnswer::Missing { .. } => {}
        }

        match self.public_scan_rows(range).await? {
            PublicScanRowsAnswer::Rows(rows) => {
                if rows.row_count() > 0 {
                    Ok(PublicCoverageAnswer::CoveredWithRows {
                        range: rows.range,
                        source: rows.source,
                        epoch: rows.epoch,
                    })
                } else {
                    Ok(PublicCoverageAnswer::ReplayableEmpty {
                        range: rows.range,
                        source: rows.source,
                        epoch: rows.epoch,
                    })
                }
            }
            PublicScanRowsAnswer::CompleteCoverage {
                range,
                source,
                row_count,
                epoch,
            } => {
                if row_count > 0 {
                    Ok(PublicCoverageAnswer::CoveredWithRows {
                        range,
                        source,
                        epoch,
                    })
                } else {
                    Ok(PublicCoverageAnswer::ReplayableEmpty {
                        range,
                        source,
                        epoch,
                    })
                }
            }
            PublicScanRowsAnswer::Missing { range, epoch } => {
                Ok(PublicCoverageAnswer::Missing { range, epoch })
            }
        }
    }

    pub async fn public_scan_rows(
        &self,
        range: PublicScanRange,
    ) -> Result<PublicScanRowsAnswer, ChainError> {
        if !range.is_valid() {
            return Err(PublicDataPlaneError::InvalidRange {
                from_block: range.from_block,
                to_block: range.to_block,
            }
            .into());
        }
        let plan = PublicScanPagePlan::new(range, &self.chain);
        let source_range = plan.source_range;
        if let Some(apply) = self
            .public_data_plane
            .cached_wallet_scan_apply(source_range.from_block, source_range.to_block)
            .await
        {
            let read_scope = apply.read_scope;
            let selected_range = PublicScanRange::new(apply.from_block, apply.to_block);
            self.public_data_plane
                .record_source_decision(
                    PublicDataPlaneDiagnosticKind::SourceSelected,
                    PublicScanSource::CachedCoverage,
                    selected_range,
                    read_scope,
                    "cached public scan data selected",
                )
                .await;
            return self.public_scan_answer_from_apply(apply).await;
        }

        let mut artifact_fallback_reason = None;
        if let Some(session) = self
            .prepare_indexed_wallet_artifact_session_for_label(
                "public_scan_rows",
                source_range.from_block,
                source_range.to_block,
                None,
            )
            .await
        {
            let target = session.target_block();
            if source_range.from_block <= target {
                let read_scope = session.read_scope();
                self.public_data_plane
                    .record_source_decision(
                        PublicDataPlaneDiagnosticKind::SourceSelected,
                        PublicScanSource::IndexedArtifacts,
                        PublicScanRange::new(source_range.from_block, target),
                        read_scope,
                        "indexed artifact public scan rows selected",
                    )
                    .await;
                match session.page_for_block_range(source_range.from_block, target) {
                    Ok(IndexedWalletArtifactPageOutcome::Page(page)) => {
                        let checkpoint = page.checkpoint_block;
                        let apply = WalletScanApply::indexed_rows(
                            source_range.from_block,
                            checkpoint,
                            page.into_scan_rows(),
                            read_scope,
                            WalletIndexedCatchUpSource::IndexedArtifacts,
                        );
                        self.record_public_scan_apply_result(&apply).await?;
                        return self.public_scan_answer_from_apply(apply).await;
                    }
                    Ok(IndexedWalletArtifactPageOutcome::Exhausted { checkpoint_block }) => {
                        debug!(
                            from_block = source_range.from_block,
                            target,
                            checkpoint_block,
                            "indexed artifact public scan rows exhausted; falling back"
                        );
                        artifact_fallback_reason = Some(format!(
                            "indexed artifact exhausted at checkpoint {checkpoint_block}; falling back"
                        ));
                    }
                    Err(err) => {
                        let err = WalletStartupSyncError::from(err).without_url();
                        warn!(
                            err = %err,
                            from_block = source_range.from_block,
                            target,
                            "indexed artifact public scan rows failed; falling back"
                        );
                        artifact_fallback_reason = Some(format!("indexed artifact failed: {err}"));
                    }
                }
            }
        }

        let squid_probe_configured = self.chain.sync.quick_sync_endpoint.is_some();
        if let Some(session) = self
            .probe_squid_indexed_wallet_source_for_label("public_scan_rows")
            .await
        {
            let squid_read_scope = session.read_scope();
            let target = session.indexed_height().min(source_range.to_block);
            if source_range.from_block <= target {
                let page_kind = IndexedWalletPageKind::for_from_block(
                    source_range.from_block,
                    self.chain.deployment.v2_start_block,
                );
                let to_block = page_kind.to_block(
                    source_range.from_block,
                    target,
                    self.chain.deployment.v2_start_block,
                    self.chain.sync.indexed_wallet_block_range,
                );
                if let Some(reason) = artifact_fallback_reason.take() {
                    self.record_public_scan_fallback(
                        PublicScanSource::Squid,
                        PublicScanRange::new(source_range.from_block, to_block),
                        squid_read_scope,
                        reason,
                    )
                    .await;
                }
                self.public_data_plane
                    .record_source_decision(
                        PublicDataPlaneDiagnosticKind::SourceSelected,
                        PublicScanSource::Squid,
                        PublicScanRange::new(source_range.from_block, to_block),
                        squid_read_scope,
                        "Squid public scan rows selected",
                    )
                    .await;
                match IndexedWalletPage::fetch(
                    session.client(),
                    page_kind,
                    source_range.from_block,
                    to_block,
                )
                .await
                {
                    Ok(page) => {
                        let checkpoint = page.checkpoint_block;
                        let apply = WalletScanApply::indexed_rows(
                            source_range.from_block,
                            checkpoint,
                            page.into_scan_rows(),
                            squid_read_scope,
                            WalletIndexedCatchUpSource::Squid,
                        );
                        self.record_public_scan_apply_result(&apply).await?;
                        return self.public_scan_answer_from_apply(apply).await;
                    }
                    Err(err) => {
                        let err = WalletStartupSyncError::from(err).without_url();
                        warn!(
                            err = %err,
                            from_block = source_range.from_block,
                            to_block,
                            "Squid public scan rows failed; falling back to RPC"
                        );
                        let rpc_source = self.rpc_scan_source_for_range(source_range.from_block);
                        let rpc_read_scope = self.begin_public_scan_read();
                        self.record_public_scan_fallback(
                            rpc_source,
                            source_range,
                            rpc_read_scope,
                            format!("Squid failed: {err}"),
                        )
                        .await;
                        return self
                            .public_scan_rows_from_rpc(source_range, rpc_read_scope)
                            .await;
                    }
                }
            }
        } else if squid_probe_configured {
            let rpc_read_scope = self.begin_public_scan_read();
            self.record_public_scan_fallback(
                self.rpc_scan_source_for_range(source_range.from_block),
                source_range,
                rpc_read_scope,
                "Squid unavailable; falling back to RPC",
            )
            .await;
        }

        let rpc_read_scope = self.begin_public_scan_read();
        if let Some(reason) = artifact_fallback_reason.take() {
            self.record_public_scan_fallback(
                self.rpc_scan_source_for_range(source_range.from_block),
                source_range,
                rpc_read_scope,
                reason,
            )
            .await;
        }
        self.public_scan_rows_from_rpc(source_range, rpc_read_scope)
            .await
    }

    /// Recovery may fetch whole indexed artifacts, but must not query a wallet-selected block.
    pub(in crate::chain) async fn output_poi_source_block_rows(
        &self,
        block_number: u64,
    ) -> Result<PublicScanRowsAnswer, ChainError> {
        if let Some(apply) = self
            .public_data_plane
            .cached_wallet_scan_apply(block_number, block_number)
            .await
        {
            return self.public_scan_answer_from_apply(apply).await;
        }
        let range = PublicScanRange::new(block_number, block_number);
        let read_scope = self.begin_public_scan_read();
        let session = IndexedWalletArtifactSession::prepare(
            &self.chain,
            block_number,
            block_number,
            read_scope,
            &self.public_data_plane,
            None,
        )
        .await;
        let page = session.and_then(|session| {
            let Some(session) = session else {
                return Ok(None);
            };
            session
                .page_for_block_range(block_number, block_number)
                .map(|outcome| match outcome {
                    IndexedWalletArtifactPageOutcome::Page(page) => Some(page),
                    IndexedWalletArtifactPageOutcome::Exhausted { .. } => None,
                })
        });
        let page = match page {
            Ok(Some(page)) => page,
            unavailable => {
                if let Err(err) = unavailable {
                    warn!(
                        err = %WalletStartupSyncError::from(err).without_url(),
                        "output POI source block artifacts failed"
                    );
                } else {
                    debug!("output POI source block artifacts unavailable");
                }
                return Ok(PublicScanRowsAnswer::Missing {
                    range,
                    epoch: self.public_data_plane.current_epoch(),
                });
            }
        };
        let apply = WalletScanApply::indexed_rows(
            block_number,
            page.checkpoint_block,
            page.into_scan_rows(),
            read_scope,
            WalletIndexedCatchUpSource::IndexedArtifacts,
        );
        self.record_public_scan_apply_result(&apply).await?;
        self.public_data_plane
            .record_source_decision(
                PublicDataPlaneDiagnosticKind::SourceSelected,
                PublicScanSource::IndexedArtifacts,
                range,
                read_scope,
                "output POI source block artifact rows selected",
            )
            .await;
        self.public_scan_answer_from_apply(apply).await
    }

    async fn public_scan_rows_from_rpc(
        &self,
        source_range: PublicScanRange,
        read_scope: PublicScanReadScope,
    ) -> Result<PublicScanRowsAnswer, ChainError> {
        let events = self
            .fetch_wallet_rpc_backfill_events(
                source_range.from_block,
                source_range.from_block,
                source_range.to_block,
                RpcTargetPolicy::AllowFinalizedPrefix,
                &self.cancel,
                read_scope,
            )
            .await
            .map_err(|err| match err {
                WalletStartupSyncError::Cancelled => ChainError::BackfillRequestFailed,
                WalletStartupSyncError::IncompleteRpcCoverage { .. }
                | WalletStartupSyncError::UnprovenRpcEndpoint { .. } => {
                    ChainError::BackfillRequestFailed
                }
                WalletStartupSyncError::Chain(err) => err,
                WalletStartupSyncError::Indexed(err) => ChainError::IndexedCatchUpUnavailable {
                    from_block: source_range.from_block,
                    archive_until_block: self.chain.sync.archive_until_block,
                    reason: err.to_string(),
                },
            })?;
        if let Some(apply) = events.acquisition_applies.first() {
            self.public_data_plane
                .record_source_decision(
                    PublicDataPlaneDiagnosticKind::SourceSelected,
                    apply.rows.source,
                    PublicScanRange::new(apply.from_block, apply.to_block),
                    apply.read_scope,
                    "RPC public scan rows selected",
                )
                .await;
        }
        for apply in &events.acquisition_applies {
            self.record_public_scan_apply_result(apply).await?;
        }
        if let Some(apply) = events.delivery_applies.into_iter().next() {
            self.public_scan_answer_from_apply(apply).await
        } else {
            Ok(PublicScanRowsAnswer::Missing {
                range: source_range,
                epoch: read_scope.epoch(),
            })
        }
    }

    async fn public_scan_answer_from_apply(
        &self,
        apply: WalletScanApply,
    ) -> Result<PublicScanRowsAnswer, ChainError> {
        let range = PublicScanRange::new(apply.from_block, apply.to_block);
        let source = apply.rows.source;
        let read_scope = apply.read_scope;
        self.public_data_plane
            .public_scan_commit_permit(range, source, read_scope)
            .await
            .map_err(ChainError::from)?;
        Ok(apply.into())
    }

    pub(super) async fn record_public_scan_apply_result(
        &self,
        apply: &WalletScanApply,
    ) -> Result<PublicDataPlaneEpoch, PublicDataPlaneError> {
        self.public_data_plane.record_public_scan_apply(apply).await
    }

    pub(super) async fn record_public_scan_fallback(
        &self,
        fallback_source: PublicScanSource,
        range: PublicScanRange,
        read_scope: PublicScanReadScope,
        reason: impl Into<String>,
    ) {
        self.public_data_plane
            .record_source_decision(
                PublicDataPlaneDiagnosticKind::SourceFallback,
                fallback_source,
                range,
                read_scope,
                reason,
            )
            .await;
    }

    pub(in crate::chain) async fn record_public_scan_apply(&self, apply: &WalletScanApply) {
        if let Err(err) = self.record_public_scan_apply_result(apply).await {
            debug!(
                ?err,
                from_block = apply.from_block,
                to_block = apply.to_block,
                source = ?apply.rows.source,
                "public scan rows were not recorded"
            );
        }
    }

    pub(super) async fn restage_captured_public_scan_applies(
        &self,
        applies: &[WalletScanApply],
    ) -> bool {
        for apply in applies {
            if let Err(err) = self.record_public_scan_apply_result(apply).await {
                debug!(
                    ?err,
                    from_block = apply.from_block,
                    to_block = apply.to_block,
                    source = ?apply.rows.source,
                    "captured public scan suffix could not be restaged"
                );
                return false;
            }
        }
        true
    }

    pub(in crate::chain) async fn apply_cached_public_scan_coverage(
        &self,
        cfg: &WalletConfig,
        start_block: u64,
        last_scanned: u64,
        target_block: u64,
        handle: &WalletHandle,
        sender: &mpsc::Sender<BackfillEvent>,
        progress: crate::types::WalletSchedulableProgress,
    ) -> CachedPublicScanApplyOutcome {
        let mut checkpoint = last_scanned;
        let target_result = handle
            .start_backfill(&cfg.cache_key, sender, progress, target_block)
            .await;
        let driver = match target_result {
            WalletBackfillStartResult::Accepted { grant, .. } => grant.activate(),
            WalletBackfillStartResult::Rejected { .. } => {
                return CachedPublicScanApplyOutcome {
                    checkpoint,
                    finished: false,
                };
            }
        };
        loop {
            let from_block = wallet_backfill_from_block(checkpoint, start_block);
            if from_block > target_block {
                let result = driver.finish(&cfg.cache_key, target_block).await;
                let finished = matches!(result, WalletBackfillFinishResult::Ready { .. });
                if !finished {
                    driver.retire(&cfg.cache_key).await;
                }
                return CachedPublicScanApplyOutcome {
                    checkpoint,
                    finished,
                };
            }
            let Some(apply) = self
                .public_data_plane
                .cached_wallet_scan_apply(from_block, target_block)
                .await
            else {
                driver.retire(&cfg.cache_key).await;
                return CachedPublicScanApplyOutcome {
                    checkpoint,
                    finished: false,
                };
            };
            let apply_to = apply.to_block;
            let read_scope = apply.read_scope;
            self.public_data_plane
                .record_source_decision(
                    PublicDataPlaneDiagnosticKind::SourceSelected,
                    PublicScanSource::CachedCoverage,
                    PublicScanRange::new(from_block, apply_to),
                    read_scope,
                    "cached public scan data selected",
                )
                .await;
            let apply_result = driver.apply(&cfg.cache_key, apply).await;
            let Some(committed_to) = apply_result.accepted_committed_to() else {
                debug!(
                    ?apply_result,
                    cache_key = %cfg.cache_key,
                    from_block,
                    apply_to,
                    "cached public coverage was not committed"
                );
                driver.retire(&cfg.cache_key).await;
                return CachedPublicScanApplyOutcome {
                    checkpoint,
                    finished: false,
                };
            };
            checkpoint = committed_to;
            if committed_to < apply_to {
                driver.retire(&cfg.cache_key).await;
                return CachedPublicScanApplyOutcome {
                    checkpoint,
                    finished: false,
                };
            }
        }
    }

    /// Warms the uncovered leading part of `prefix`, the startup window's
    /// blocks at or before a delivered wallet cursor, in the background.
    ///
    /// Blocks already covered by a contiguous cached run that ends at the
    /// prefix's end are skipped. At most one warm task runs per chain.
    pub(in crate::chain) async fn start_public_scan_window_warm(
        self: &Arc<Self>,
        prefix: PublicScanRange,
    ) {
        let cached_from = self
            .public_data_plane
            .cached_wallet_scan_suffix(prefix.from_block, prefix.to_block)
            .await
            .and_then(|applies| applies.first().map(|apply| apply.from_block));
        let warm_to = cached_from.map_or(Some(prefix.to_block), |cached_from| {
            cached_from.checked_sub(1)
        });
        let Some(warm_to) = warm_to.filter(|warm_to| *warm_to >= prefix.from_block) else {
            return;
        };
        let range = PublicScanRange::new(prefix.from_block, warm_to);
        let service = Arc::clone(self);
        let started = self
            .public_data_plane
            .try_start_public_window_warm(&self.cancel, move |cancel| {
                service.warm_public_scan_window(range, cancel)
            });
        debug!(
            from_block = range.from_block,
            to_block = range.to_block,
            started,
            "public scan window warm requested"
        );
    }

    /// Acquires `range` through the adaptive RPC fetch under its own read
    /// scope and records it as reusable public rows. It never touches wallet
    /// state, and a failure ends the task without retrying.
    async fn warm_public_scan_window(
        self: Arc<Self>,
        range: PublicScanRange,
        cancel: CancellationToken,
    ) {
        let started = Instant::now();
        let read_scope = self.begin_public_scan_read();
        let outcome = match self
            .fetch_wallet_rpc_backfill_events(
                range.from_block,
                range.to_block.saturating_add(1),
                range.to_block,
                RpcTargetPolicy::RequireRequestedTarget,
                &cancel,
                read_scope,
            )
            .await
        {
            Ok(fetched) => match self
                .public_data_plane
                .commit_completed_wallet_scan_acquisition(range, &fetched.acquisition_applies)
                .await
            {
                Ok(_) => "committed",
                Err(err) => {
                    debug!(?err, "public scan window warm commit rejected");
                    "commit_rejected"
                }
            },
            Err(WalletStartupSyncError::Cancelled) => "cancelled",
            Err(WalletStartupSyncError::Chain(err)) => {
                debug!(err = %err.without_url(), "public scan window warm fetch failed");
                "failed"
            }
            // The RPC-only fetch never returns `Indexed`, so only `Chain` can
            // carry a transport error.
            Err(err) => {
                debug!(err = %err, "public scan window warm fetch failed");
                "failed"
            }
        };
        debug!(
            from_block = range.from_block,
            to_block = range.to_block,
            elapsed_ms = started.elapsed().as_millis(),
            outcome,
            "public scan window warm finished"
        );
    }
}
