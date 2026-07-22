use super::{
    Arc, AtomicBool, AtomicU64, BackfillEvent, BackfillRequest, CancellationToken, ChainConfig,
    ChainError, ChainHandle, ChainPublicDataPlane, ChainService, DbStore, Duration,
    GlobalPoiPolicy, HashMap, IndexedWalletArtifactPageOutcome, IndexedWalletArtifactSession,
    IndexedWalletCatchUpSourceOrder, IndexedWalletPage, IndexedWalletPageKind, Instant, JoinHandle,
    JoinSet, LogBatch, MerkleForestDbExt, Mutex, Ordering, Provider, ProviderHandle,
    PublicCoverageAnswer, PublicDataPlaneDiagnosticKind, PublicDataPlaneEpoch,
    PublicDataPlaneError, PublicDataPlaneHandle, PublicScanRange, PublicScanReadScope,
    PublicScanRowsAnswer, PublicScanSource, QueryRpcPool, QuickSyncClient, RwLock,
    SyncProgressSender, WalletBackfillFinishResult, WalletBackfillRejectReason,
    WalletBackfillResetResult, WalletBackfillStartResult, WalletConfig, WalletHandle,
    WalletIndexedCatchUpSource, WalletIndexedCatchUpStatusGuard, WalletObservation,
    WalletPoiRuntime, WalletReadiness, WalletReadinessError, WalletRegistration,
    WalletResetReplayPlan, WalletScanApply, WalletStartupSyncCandidate, WalletStartupSyncError,
    WalletStartupSyncStrategy, WalletWorkerServices, artifact_failure_can_fallback_to_squid,
    broadcast, build_provider_with_http_client, debug, info, mpsc, oneshot,
    send_wallet_startup_events, should_hedge_wallet_startup, sort_logs, spawn_backfill_loop,
    spawn_head_poller, spawn_live_log_loop, spawn_pending_tip_loop, spawn_txid_public_cache_loop,
    spawn_wallet_lag_fallback_loop, squid_tail_target_after_artifact, wait_or_cancel,
    wallet_backfill_from_block, wallet_cache_store, wallet_finish_result_removes_cursor,
    wallet_finish_retry_request, wallet_remote_target_before_cached_suffix,
    wallet_startup_warm_from_block, wallet_sync_target, warn, watch,
};

pub(in crate::chain) async fn send_wallet_reset(
    cache_key: &str,
    sender: &mpsc::Sender<BackfillEvent>,
    handle: &WalletHandle,
    intent_id: u64,
    from_block: u64,
    replay_plan: WalletResetReplayPlan,
    committed_to: u64,
) -> WalletBackfillResetResult {
    let (response, result_rx) = oneshot::channel();
    if let Err(err) = sender
        .send(BackfillEvent::Reset {
            token: handle.mint_reset_token(intent_id),
            from_block,
            replay_plan,
            response,
        })
        .await
    {
        warn!(
            ?err,
            cache_key, from_block, "failed to send wallet reset command"
        );
        return WalletBackfillResetResult::Rejected {
            committed_to,
            reason: WalletBackfillRejectReason::Shutdown,
        };
    }
    match result_rx.await {
        Ok(result) => result,
        Err(err) => {
            warn!(?err, cache_key, from_block, "wallet reset response dropped");
            WalletBackfillResetResult::Rejected {
                committed_to,
                reason: WalletBackfillRejectReason::Shutdown,
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct PublicScanPagePlan {
    source_range: PublicScanRange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct WalletShortStartupPlan {
    acquisition: PublicScanRange,
    delivery: PublicScanRange,
}

struct WalletRpcBackfillEvents {
    acquisition_applies: Vec<WalletScanApply>,
    delivery_applies: Vec<WalletScanApply>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RpcTargetPolicy {
    RequireRequestedTarget,
    AllowFinalizedPrefix,
}

impl WalletShortStartupPlan {
    pub(super) fn new(
        start_block: u64,
        last_scanned: u64,
        sync_target: u64,
        block_range: u64,
    ) -> Option<Self> {
        if !should_hedge_wallet_startup(last_scanned, start_block, sync_target, block_range) {
            return None;
        }
        Some(Self {
            acquisition: PublicScanRange::new(
                wallet_startup_warm_from_block(start_block, sync_target, block_range),
                sync_target,
            ),
            delivery: PublicScanRange::new(
                wallet_backfill_from_block(last_scanned, start_block),
                sync_target,
            ),
        })
    }

    const fn acquisition_tuple(self) -> (u64, u64) {
        (self.acquisition.from_block, self.acquisition.to_block)
    }

    fn acquisition_prefix_before_delivery(self) -> Option<PublicScanRange> {
        let to_block = self.delivery.from_block.checked_sub(1)?;
        (self.acquisition.from_block <= to_block)
            .then(|| PublicScanRange::new(self.acquisition.from_block, to_block))
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct CachedPublicScanApplyOutcome {
    pub(super) checkpoint: u64,
    pub(super) finished: bool,
}

fn wallet_has_persistence_failure(handle: &WalletHandle) -> bool {
    matches!(
        handle.readiness(),
        WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
    )
}

struct SquidIndexedWalletReadSession {
    client: QuickSyncClient,
    indexed_height: u64,
    read_scope: PublicScanReadScope,
}

impl SquidIndexedWalletReadSession {
    const fn client(&self) -> &QuickSyncClient {
        &self.client
    }

    const fn indexed_height(&self) -> u64 {
        self.indexed_height
    }

    const fn read_scope(&self) -> PublicScanReadScope {
        self.read_scope
    }
}

impl PublicScanPagePlan {
    fn new(range: PublicScanRange, chain: &ChainConfig) -> Self {
        let rpc_to = Self::bounded_to_block(range.from_block, range.to_block, chain.block_range);
        let indexed_page_kind =
            IndexedWalletPageKind::for_from_block(range.from_block, chain.v2_start_block);
        let indexed_to = indexed_page_kind.to_block(
            range.from_block,
            range.to_block,
            chain.v2_start_block,
            chain.indexed_wallet_block_range.max(1),
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
    pub(super) const fn chain_id(&self) -> u64 {
        self.chain.chain_id
    }

    async fn wallet_registration_gate(&self, cache_key: &str) -> Arc<Mutex<()>> {
        let mut gates = self.wallet_registration_gates.lock().await;
        Arc::clone(
            gates
                .entry(cache_key.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(()))),
        )
    }

    pub(super) fn next_wallet_reset_intent(&self) -> u64 {
        self.wallet_reset_intent_next.fetch_add(1, Ordering::AcqRel)
    }

    fn observe_wallet_reset_intent_floor(&self, highest_accepted_reset_intent: u64) {
        let floor_next = highest_accepted_reset_intent.saturating_add(1);
        let mut current = self.wallet_reset_intent_next.load(Ordering::Acquire);
        while current < floor_next {
            match self.wallet_reset_intent_next.compare_exchange(
                current,
                floor_next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }

    pub(super) fn begin_public_scan_read(&self) -> PublicScanReadScope {
        self.public_data_plane.begin_public_scan_read()
    }

    #[must_use]
    pub fn public_data_plane(self: &Arc<Self>) -> PublicDataPlaneHandle {
        PublicDataPlaneHandle::new(Arc::clone(self))
    }

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
                        warn!(
                            ?err,
                            from_block = source_range.from_block,
                            target,
                            "indexed artifact public scan rows failed; falling back"
                        );
                        artifact_fallback_reason = Some(format!("indexed artifact failed: {err}"));
                    }
                }
            }
        }

        let squid_probe_configured = self.chain.quick_sync_endpoint.is_some();
        if let Some(session) = self
            .probe_squid_indexed_wallet_source_for_label("public_scan_rows")
            .await
        {
            let squid_read_scope = session.read_scope();
            let target = session.indexed_height().min(source_range.to_block);
            if source_range.from_block <= target {
                let page_kind = IndexedWalletPageKind::for_from_block(
                    source_range.from_block,
                    self.chain.v2_start_block,
                );
                let to_block = page_kind.to_block(
                    source_range.from_block,
                    target,
                    self.chain.v2_start_block,
                    self.chain.indexed_wallet_block_range,
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
                        warn!(
                            ?err,
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
                    archive_until_block: self.chain.archive_until_block,
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

    pub(super) const fn rpc_scan_source_for_range(&self, from_block: u64) -> PublicScanSource {
        if self.chain.archive_until_block > 0 && from_block <= self.chain.archive_until_block {
            PublicScanSource::ArchiveRpc
        } else {
            PublicScanSource::Rpc
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

    async fn record_public_scan_apply_result(
        &self,
        apply: &WalletScanApply,
    ) -> Result<PublicDataPlaneEpoch, PublicDataPlaneError> {
        self.public_data_plane.record_public_scan_apply(apply).await
    }

    async fn record_public_scan_fallback(
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

    pub(super) async fn record_public_scan_apply(&self, apply: &WalletScanApply) {
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

    async fn restage_captured_public_scan_applies(&self, applies: &[WalletScanApply]) -> bool {
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

    pub(super) async fn apply_cached_public_scan_coverage(
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

    pub async fn start(
        db: Arc<DbStore>,
        chain: ChainConfig,
        poi_policy: GlobalPoiPolicy,
    ) -> Result<Arc<Self>, ChainError> {
        if chain.archive_until_block > 0
            && chain.archive_rpc_url.is_none()
            && chain.deployment_block <= chain.archive_until_block
        {
            warn!(
                chain_id = chain.chain_id,
                archive_until_block = chain.archive_until_block,
                "archive RPC URL not configured; using regular RPC providers for archive-range fallback"
            );
        }
        let archive_provider = match chain.archive_rpc_url.as_ref() {
            Some(url) => Some(
                build_provider_with_http_client(url, chain.http_client.as_ref())
                    .await
                    .map_err(ChainError::ProviderBuild)?,
            ),
            None => None,
        };

        let rpcs = chain.rpcs.clone();
        let fallback_rpc = rpcs
            .random_provider()
            .ok_or_else(|| ChainError::NoHealthyRpc)?;
        let (rpc, initial_head, initial_safe_head) = fetch_initial_head(&chain, rpcs.as_ref())
            .await
            .unwrap_or((fallback_rpc, 0, 0));

        let (forest, last_processed, snapshot_path, last_anchor) = db
            .load_or_initialize_forest(
                &chain,
                initial_safe_head,
                Some(&rpc.provider),
                archive_provider.as_ref(),
            )
            .await?;

        let (head_tx, _head_rx) = watch::channel(initial_head);
        let (safe_head_tx, safe_head_rx) = watch::channel(initial_safe_head);
        let (forest_last_tx, forest_last_rx) = watch::channel(last_processed);
        let (live_log_tx, _live_log_rx) = broadcast::channel(64);
        let (backfill_tx, backfill_rx) = mpsc::channel(128);
        let cancel = CancellationToken::new();
        let mut public_data_plane =
            ChainPublicDataPlane::new(Arc::clone(&db), Arc::new(AtomicU64::new(0)));
        if let GlobalPoiPolicy::IndexedArtifacts {
            artifact_source,
            rpc_url,
            ..
        } = &poi_policy
        {
            let poi_artifact_persistence = public_data_plane.poi_artifact_persistence();
            let poi_cache_service = crate::poi_cache::PoiCacheService::new_with_persistence(
                Arc::clone(&db),
                artifact_source.clone(),
                chain.http_client.clone(),
                poi_artifact_persistence,
            )?
            .with_poi_rpc_url(rpc_url.clone());
            public_data_plane =
                public_data_plane.with_poi_cache_service(Arc::new(poi_cache_service));
        }
        let service = Arc::new(Self {
            chain,
            poi_policy,
            db,
            forest,
            head_tx,
            safe_head_tx,
            forest_last_tx,
            live_log_tx,
            backfill_tx,
            archive_provider: archive_provider.clone(),
            wallets: RwLock::new(HashMap::new()),
            wallet_registration_gates: Mutex::new(HashMap::new()),
            cancel: cancel.clone(),
            live_log_task: Mutex::new(None),
            anchor_last: AtomicU64::new(last_anchor),
            txid_public_cache_started: AtomicBool::new(false),
            wallet_actor_next: AtomicU64::new(1),
            wallet_reset_intent_next: AtomicU64::new(1),
            public_data_plane,
        });

        spawn_head_poller(service.clone(), rpcs.clone());
        let live_log_task = spawn_live_log_loop(
            service.clone(),
            rpcs.clone(),
            archive_provider.clone(),
            forest_last_rx,
            safe_head_rx.clone(),
            snapshot_path,
            cancel.clone(),
        );
        *service.live_log_task.lock().await = Some(live_log_task);
        spawn_pending_tip_loop(
            service.clone(),
            rpcs.clone(),
            archive_provider.clone(),
            service.head_tx.subscribe(),
            safe_head_rx.clone(),
            cancel.clone(),
        );
        spawn_wallet_lag_fallback_loop(service.clone(), safe_head_rx.clone(), cancel.clone());
        spawn_backfill_loop(
            service.clone(),
            backfill_rx,
            rpcs,
            archive_provider,
            safe_head_rx,
            cancel,
        );

        Ok(service)
    }

    #[must_use]
    pub fn handle(&self) -> ChainHandle {
        ChainHandle {
            forest: self.forest.clone(),
            head_rx: self.head_tx.subscribe(),
            safe_head_rx: self.safe_head_tx.subscribe(),
            forest_last_rx: self.forest_last_tx.subscribe(),
            live_log_rx: self.live_log_tx.subscribe(),
        }
    }

    pub async fn wallet_handle(&self, cache_key: &str) -> Option<WalletHandle> {
        self.wallets
            .read()
            .await
            .get(cache_key)
            .filter(|registration| !Self::wallet_registration_is_terminal(registration))
            .map(|registration| registration.handle.clone())
    }

    fn wallet_registration_is_terminal(registration: &WalletRegistration) -> bool {
        !registration.handle.is_current_actor()
            || !registration.handle.lifecycle().allows_durable_commits()
            || matches!(registration.handle.readiness(), WalletReadiness::Shutdown)
            || registration.worker.is_finished()
    }

    fn spawn_wallet_terminal_reaper(self: &Arc<Self>, handle: WalletHandle) {
        let service = Arc::downgrade(self);
        let mut observation_rx = handle.subscribe_observation();
        tokio::spawn(async move {
            loop {
                if observation_rx.borrow().readiness() == &WalletReadiness::Shutdown {
                    break;
                }
                if observation_rx.changed().await.is_err() {
                    return;
                }
            }
            if let Some(service) = service.upgrade() {
                service.reap_terminal_wallet_registration(&handle).await;
            }
        });
    }

    async fn reap_terminal_wallet_registration(&self, handle: &WalletHandle) {
        let cache_key = handle.cache_key.as_str();
        let registration_gate = self.wallet_registration_gate(cache_key).await;
        let registration_guard = registration_gate.lock().await;
        let registration = {
            let mut wallets = self.wallets.write().await;
            let is_exact_terminal = wallets.get(cache_key).is_some_and(|registration| {
                registration.handle.same_actor_as(handle)
                    && Self::wallet_registration_is_terminal(registration)
            });
            is_exact_terminal
                .then(|| wallets.remove(cache_key))
                .flatten()
        };
        let Some(registration) = registration else {
            return;
        };
        Self::begin_wallet_shutdown(&registration);
        drop(registration_guard);
        self.finish_wallet_retirement(cache_key, registration).await;
    }

    fn spawn_txid_public_cache_loop_once(self: &Arc<Self>) {
        if self.txid_public_cache_started.swap(true, Ordering::AcqRel) {
            return;
        }
        spawn_txid_public_cache_loop(Arc::clone(self), self.cancel.clone());
    }

    fn spawn_txid_public_cache_loop_when_ready(
        self: &Arc<Self>,
        observation_rx: watch::Receiver<WalletObservation>,
        cancel: CancellationToken,
    ) {
        let service = Arc::clone(self);
        tokio::spawn(async move {
            if wait_for_wallet_ready(observation_rx, cancel).await {
                service.spawn_txid_public_cache_loop_once();
            }
        });
    }

    pub async fn reset_wallet(
        &self,
        cache_key: &str,
        from_block: Option<u64>,
    ) -> Result<(), ChainError> {
        let (handle, backfill_sender, start_block, sync_to_block) = {
            let wallets = self.wallets.read().await;
            let registration = wallets.get(cache_key).ok_or(ChainError::WalletNotFound)?;
            (
                registration.handle.clone(),
                registration.backfill_sender.clone(),
                registration.start_block,
                registration.sync_to_block,
            )
        };

        let reset_from = from_block.unwrap_or(start_block);
        let safe_head = *self.safe_head_tx.borrow();
        let sync_target = wallet_sync_target(safe_head, sync_to_block);
        let reset_intent_id = self.next_wallet_reset_intent();
        let replay_plan =
            WalletResetReplayPlan::new(start_block, sync_target, sync_to_block.is_none());
        let reset_result = send_wallet_reset(
            cache_key,
            &backfill_sender,
            &handle,
            reset_intent_id,
            reset_from,
            replay_plan,
            handle.last_scanned_raw(),
        )
        .await;
        if reset_result.reset_generation().is_none() {
            warn!(?reset_result, cache_key = %cache_key, from_block = reset_from, "wallet reset rejected");
            return Err(ChainError::WalletResetRejected(reset_result));
        }
        if reset_result.committed() {
            info!(cache_key = %cache_key, from_block = reset_from, "wallet reset rewind committed; actor owns replay admission");
        } else {
            info!(cache_key = %cache_key, from_block = reset_from, "wallet reset accepted and pending actor-owned replay");
        }
        Ok(())
    }

    pub(super) async fn try_indexed_wallet_tail_catch_up(
        &self,
        cache_key: &str,
        from_block: u64,
        target_block: u64,
        progress: crate::types::WalletSchedulableProgress,
        sender: &mpsc::Sender<BackfillEvent>,
    ) -> Option<u64> {
        if from_block > target_block {
            return None;
        }
        let (cfg, start_block, handle, cancel) = {
            let wallets = self.wallets.read().await;
            let registration = wallets.get(cache_key)?;
            if !registration.cfg.use_indexed_wallet_catch_up {
                debug!(cache_key = %cache_key, "indexed wallet tail fallback disabled");
                return None;
            }
            (
                registration.cfg.clone(),
                registration.start_block,
                registration.handle.clone(),
                registration.cancel.clone(),
            )
        };
        // Ticket must still match current view generation before using the range.
        let progress = handle.revalidate_schedulable_progress(progress)?;
        let last_scanned = from_block.saturating_sub(1);
        let started = Instant::now();
        let checkpoint = self
            .indexed_wallet_catch_up(
                &cfg,
                start_block,
                last_scanned,
                target_block,
                &handle,
                &cancel,
                IndexedWalletCatchUpSourceOrder::SquidFirst,
                true,
                (sender, progress),
            )
            .await;
        if checkpoint < from_block {
            debug!(
                cache_key = %cache_key,
                from_block,
                target_block,
                checkpoint,
                elapsed_ms = started.elapsed().as_millis(),
                "indexed wallet tail fallback did not advance"
            );
            return None;
        }
        info!(
            cache_key = %cache_key,
            from_block,
            target_block,
            checkpoint,
            elapsed_ms = started.elapsed().as_millis(),
            "indexed wallet tail fallback complete"
        );
        Some(checkpoint)
    }

    /// Registers or returns the active wallet actor for the configured cache key.
    ///
    /// # Panics
    ///
    /// Panics if the internal prepared-worker activation invariant is violated.
    pub async fn register_wallet(
        self: &Arc<Self>,
        cfg: WalletConfig,
    ) -> Result<WalletHandle, ChainError> {
        let cache_key = cfg.cache_key.clone();
        let registration_gate = self.wallet_registration_gate(&cache_key).await;
        let registration_guard = registration_gate.lock().await;
        if self.cancel.is_cancelled() {
            return Err(ChainError::Shutdown);
        }
        let terminal_registration = {
            let mut wallets = self.wallets.write().await;
            if let Some(existing) = wallets.get(cache_key.as_str())
                && !Self::wallet_registration_is_terminal(existing)
            {
                if existing.handle.readiness().is_ready() {
                    self.spawn_txid_public_cache_loop_once();
                }
                return Ok(existing.handle.clone());
            }
            wallets.remove(cache_key.as_str())
        };
        if let Some(registration) = terminal_registration {
            Self::begin_wallet_shutdown(&registration);
            self.finish_wallet_retirement(cache_key.as_str(), registration)
                .await;
        }

        let mut cfg = cfg;
        let start_block = cfg.start_block.unwrap_or(self.chain.deployment_block);
        cfg.start_block = Some(start_block);

        let mut last_scanned = start_block.saturating_sub(1);
        let cache_store = wallet_cache_store(&self.db, &cfg);
        if let Ok(Some(meta)) = cache_store.get_wallet_meta(&cfg.cache_key) {
            last_scanned = meta.last_scanned_block;
        }
        match cache_store.get_wallet_sync_actor_state(cfg.chain.chain_id, &cfg.cache_key) {
            Ok(Some(state)) => {
                self.observe_wallet_reset_intent_floor(state.highest_accepted_reset_intent);
            }
            Ok(None) => {}
            Err(err) => {
                warn!(?err, cache_key = %cfg.cache_key, "failed to restore wallet reset intent floor");
                return Err(err.into());
            }
        }

        let safe_head = *self.safe_head_tx.borrow();
        let sync_target = wallet_sync_target(safe_head, cfg.sync_to_block);
        info!(
            cache_key = %cfg.cache_key,
            chain_id = cfg.chain.chain_id,
            start_block,
            last_scanned,
            safe_head,
            sync_to_block = ?cfg.sync_to_block,
            sync_target,
            indexed_wallet_catch_up = cfg.use_indexed_wallet_catch_up,
            indexed_artifact_source = self.chain.indexed_artifact_source.is_some(),
            "registering wallet sync"
        );

        let initial_utxos = match cache_store.load_wallet_utxos(&cfg.cache_key) {
            Ok(cached) => cached,
            Err(err) => {
                warn!(?err, cache_key = %cfg.cache_key, "failed to load wallet cache");
                Vec::new()
            }
        };
        if last_scanned < start_block {
            last_scanned = start_block.saturating_sub(1);
        }

        let actor_id = self.wallet_actor_next.fetch_add(1, Ordering::AcqRel);
        let cancel = self.cancel.child_token();
        let live_rx = self.live_log_tx.subscribe();
        let (backfill_sender, backfill_rx) = mpsc::channel(128);
        let mut prepared: crate::wallet::PreparedWalletWorker =
            crate::wallet::prepare_wallet_worker(
                WalletWorkerServices {
                    db: self.db.clone(),
                    rpcs: self.chain.rpcs.clone(),
                    http_client: self.chain.http_client.clone(),
                    indexed_artifact_source: self.chain.indexed_artifact_source.clone(),
                    poi_runtime: WalletPoiRuntime::from_policy(
                        &self.poi_policy,
                        self.chain.http_client.as_ref(),
                    ),
                    forest: self.forest.clone(),
                    backfill_tx: self.backfill_tx.clone(),
                    backfill_sender: backfill_sender.clone(),
                    public_data_plane: self.public_data_plane.clone(),
                },
                cfg.clone(),
                actor_id,
                live_rx,
                backfill_rx,
                cancel.clone(),
                initial_utxos,
                last_scanned,
            )
            .await?;

        let worker = prepared.take_worker();
        let mut activation_failure = None;
        let handle = {
            let mut wallets = self.wallets.write().await;
            if self.cancel.is_cancelled() {
                drop(wallets);
                drop(registration_guard);
                cancel.cancel();
                let _ = worker.await;
                return Err(ChainError::Shutdown);
            }
            let handle = prepared.handle().clone();
            wallets.insert(
                cache_key.to_string(),
                WalletRegistration {
                    handle,
                    cfg: cfg.clone(),
                    cancel: cancel.clone(),
                    worker,
                    observation: prepared.observation_publisher(),
                    backfill_sender: backfill_sender.clone(),
                    start_block,
                    sync_to_block: cfg.sync_to_block,
                },
            );
            match prepared.activate() {
                Ok(handle) => Some(handle),
                Err(err) => {
                    let registration = wallets
                        .remove(cache_key.as_str())
                        .expect("failed activation registration must remain installed");
                    activation_failure = Some((err, registration));
                    None
                }
            }
        };
        if let Some((err, registration)) = activation_failure {
            Self::begin_wallet_retirement(&registration);
            drop(registration_guard);
            self.finish_wallet_retirement(cache_key.as_str(), registration)
                .await;
            return Err(err);
        }
        let handle = handle.expect("successful activation returns a wallet handle");

        self.spawn_wallet_terminal_reaper(handle.clone());
        self.spawn_txid_public_cache_loop_when_ready(
            handle.subscribe_observation(),
            cancel.clone(),
        );

        let service = Arc::clone(self);
        let catch_up_cfg = cfg.clone();
        let catch_up_handle = handle.clone();
        let catch_up_cancel = cancel;
        tokio::spawn(async move {
            let Some(sync_target) = wait_for_startup_sync_target(
                service.safe_head_tx.subscribe(),
                catch_up_cfg.sync_to_block,
                sync_target,
                &catch_up_cancel,
            )
            .await
            else {
                return;
            };

            // Only schedule from one public view snapshot (cursor + generation).
            let Some(startup) = catch_up_handle
                .wait_schedulable_progress(&catch_up_cancel)
                .await
            else {
                return;
            };
            let startup_target_lease = if sync_target > startup.last_scanned {
                match catch_up_handle
                    .reserve_sync_target(
                        &catch_up_cfg.cache_key,
                        &backfill_sender,
                        startup,
                        sync_target,
                    )
                    .await
                {
                    Ok(lease) => Some(lease),
                    Err(reason) => {
                        debug!(
                            ?reason,
                            cache_key = %catch_up_cfg.cache_key,
                            sync_target,
                            "wallet startup target reservation rejected"
                        );
                        return;
                    }
                }
            } else {
                None
            };
            let short_startup_plan = WalletShortStartupPlan::new(
                start_block,
                startup.last_scanned,
                sync_target,
                service.chain.block_range,
            );
            let short_window_is_cached = if let Some(plan) = short_startup_plan {
                service
                    .public_data_plane
                    .cached_wallet_scan_suffix(
                        plan.acquisition.from_block,
                        plan.acquisition.to_block,
                    )
                    .await
                    .is_some()
            } else {
                true
            };
            let cached_outcome = if short_window_is_cached {
                service
                    .apply_cached_public_scan_coverage(
                        &catch_up_cfg,
                        start_block,
                        startup.last_scanned,
                        sync_target,
                        &catch_up_handle,
                        &backfill_sender,
                        startup,
                    )
                    .await
            } else {
                CachedPublicScanApplyOutcome {
                    checkpoint: startup.last_scanned,
                    finished: false,
                }
            };
            if cached_outcome.finished {
                return;
            }
            if wallet_has_persistence_failure(&catch_up_handle) {
                let Some(progress) = catch_up_handle.revalidate_schedulable_progress(startup)
                else {
                    return;
                };
                service
                    .enqueue_wallet_backfill(
                        &catch_up_cfg,
                        start_block,
                        cached_outcome.checkpoint,
                        sync_target,
                        catch_up_cfg.sync_to_block.is_none(),
                        &catch_up_handle,
                        progress,
                        backfill_sender,
                        false,
                        short_startup_plan,
                    )
                    .await;
                return;
            }
            let Some(startup) = catch_up_handle.revalidate_schedulable_progress(startup) else {
                return;
            };
            if service
                .short_wallet_startup_sync(
                    &catch_up_cfg,
                    start_block,
                    startup,
                    sync_target,
                    short_startup_plan,
                    backfill_sender.clone(),
                    &catch_up_handle,
                    &catch_up_cancel,
                )
                .await
            {
                return;
            }
            if wallet_has_persistence_failure(&catch_up_handle) {
                let Some(progress) = catch_up_handle.revalidate_schedulable_progress(startup)
                else {
                    return;
                };
                service
                    .enqueue_wallet_backfill(
                        &catch_up_cfg,
                        start_block,
                        progress.last_scanned,
                        sync_target,
                        catch_up_cfg.sync_to_block.is_none(),
                        &catch_up_handle,
                        progress,
                        backfill_sender,
                        false,
                        short_startup_plan,
                    )
                    .await;
                return;
            }

            let Some(checkpoint_progress) = catch_up_handle
                .wait_schedulable_progress(&catch_up_cancel)
                .await
            else {
                return;
            };
            let Some(progress) = startup.revalidate(Some(checkpoint_progress)) else {
                debug!(
                    cache_key = %catch_up_cfg.cache_key,
                    startup_reset_generation = startup.reset_generation,
                    current_reset_generation = checkpoint_progress.reset_generation,
                    "wallet startup sync superseded by reset"
                );
                return;
            };
            let mut checkpoint = progress.last_scanned;
            let mut cached_suffix = service
                .public_data_plane
                .cached_wallet_scan_suffix(
                    wallet_backfill_from_block(checkpoint, start_block),
                    sync_target,
                )
                .await;
            let cached_suffix_from = cached_suffix
                .as_ref()
                .and_then(|applies| applies.first())
                .map(|apply| apply.from_block);
            let historical_target =
                wallet_remote_target_before_cached_suffix(sync_target, cached_suffix_from);
            if let Some(cached_suffix_from) = cached_suffix_from {
                debug!(
                    cache_key = %catch_up_cfg.cache_key,
                    checkpoint,
                    historical_target,
                    cached_suffix_from,
                    sync_target,
                    "historical wallet catch-up capped before cached public suffix"
                );
            }
            if let Some(plan) = short_startup_plan
                && catch_up_cfg.use_indexed_wallet_catch_up
            {
                match service
                    .wallet_startup_artifact_candidate(&catch_up_cfg, plan, &catch_up_cancel)
                    .await
                {
                    Ok(Some(candidate)) => {
                        let acquisition_apply_count = candidate.acquisition_applies.len();
                        if let Some(progress) = service
                            .commit_and_deliver_short_startup_candidate(
                                &catch_up_cfg,
                                startup,
                                sync_target,
                                plan,
                                candidate,
                                &backfill_sender,
                                &catch_up_handle,
                                &catch_up_cancel,
                            )
                            .await
                        {
                            debug!(
                                cache_key = %catch_up_cfg.cache_key,
                                acquisition_apply_count,
                                "wallet startup artifact acquisition delivered"
                            );
                            if catch_up_cfg.sync_to_block.is_none() {
                                service
                                    .enqueue_wallet_backfill(
                                        &catch_up_cfg,
                                        start_block,
                                        sync_target,
                                        sync_target,
                                        true,
                                        &catch_up_handle,
                                        progress,
                                        backfill_sender,
                                        true,
                                        None,
                                    )
                                    .await;
                            }
                            return;
                        }
                    }
                    Ok(None) => {}
                    Err(err) => {
                        debug!(err = %err, cache_key = %catch_up_cfg.cache_key, "wallet startup artifact fallback failed");
                    }
                }
            }
            if short_startup_plan.is_none() && catch_up_cfg.use_indexed_wallet_catch_up {
                checkpoint = service
                    .indexed_wallet_catch_up(
                        &catch_up_cfg,
                        start_block,
                        checkpoint,
                        historical_target,
                        &catch_up_handle,
                        &catch_up_cancel,
                        IndexedWalletCatchUpSourceOrder::ArtifactsFirst,
                        false,
                        (&backfill_sender, progress),
                    )
                    .await;
            } else if short_startup_plan.is_none() {
                debug!(cache_key = %catch_up_cfg.cache_key, "indexed wallet catch-up disabled");
            }
            if catch_up_cancel.is_cancelled() {
                return;
            }
            // Superseded if view generation advanced or reset-pending (no public progress).
            let Some(mut progress) = catch_up_handle.revalidate_schedulable_progress(startup)
            else {
                debug!(
                    cache_key = %catch_up_cfg.cache_key,
                    startup_reset_generation = startup.reset_generation,
                    current_reset_generation = ?catch_up_handle
                        .view_state()
                        .reset_generation(),
                    "wallet startup sync superseded by reset"
                );
                return;
            };
            if short_startup_plan.is_none()
                && checkpoint < sync_target
                && let Some(suffix) = cached_suffix.take()
                && suffix.first().is_some_and(|apply| {
                    apply.from_block == wallet_backfill_from_block(checkpoint, start_block)
                })
            {
                let suffix_applies = suffix.len();
                let suffix_restaged = service.restage_captured_public_scan_applies(&suffix).await;
                if suffix_restaged
                    && send_wallet_startup_events(
                        &catch_up_cfg.cache_key,
                        suffix,
                        Some(sync_target),
                        progress,
                        &backfill_sender,
                        &catch_up_handle,
                    )
                    .await
                {
                    debug!(
                        cache_key = %catch_up_cfg.cache_key,
                        checkpoint,
                        sync_target,
                        suffix_applies,
                        "captured public scan suffix delivered after historical catch-up"
                    );
                    if catch_up_cfg.sync_to_block.is_none()
                        && let Some(progress) =
                            catch_up_handle.revalidate_schedulable_progress(startup)
                    {
                        service
                            .enqueue_wallet_backfill(
                                &catch_up_cfg,
                                start_block,
                                sync_target,
                                sync_target,
                                true,
                                &catch_up_handle,
                                progress,
                                backfill_sender,
                                true,
                                None,
                            )
                            .await;
                    }
                    return;
                }
                let Some(refreshed_progress) =
                    catch_up_handle.revalidate_schedulable_progress(startup)
                else {
                    return;
                };
                checkpoint = refreshed_progress.last_scanned;
                progress = refreshed_progress;
                debug!(
                    cache_key = %catch_up_cfg.cache_key,
                    checkpoint,
                    sync_target,
                    "captured public scan suffix was rejected; continuing with normal backfill"
                );
            }
            service
                .enqueue_wallet_backfill(
                    &catch_up_cfg,
                    start_block,
                    checkpoint,
                    sync_target,
                    catch_up_cfg.sync_to_block.is_none(),
                    &catch_up_handle,
                    progress,
                    backfill_sender,
                    !wallet_has_persistence_failure(&catch_up_handle),
                    short_startup_plan,
                )
                .await;
            drop(startup_target_lease);
        });

        Ok(handle)
    }

    async fn enqueue_wallet_backfill(
        &self,
        cfg: &WalletConfig,
        start_block: u64,
        mut last_scanned: u64,
        sync_target: u64,
        follow_safe_head: bool,
        handle: &WalletHandle,
        progress: crate::types::WalletSchedulableProgress,
        backfill_sender: mpsc::Sender<BackfillEvent>,
        try_cached_coverage: bool,
        short_startup_plan: Option<WalletShortStartupPlan>,
    ) {
        if sync_target > 0 && try_cached_coverage && short_startup_plan.is_none() {
            let cached_outcome = self
                .apply_cached_public_scan_coverage(
                    cfg,
                    start_block,
                    last_scanned,
                    sync_target,
                    handle,
                    &backfill_sender,
                    progress,
                )
                .await;
            last_scanned = cached_outcome.checkpoint;
            if cached_outcome.finished {
                return;
            }
        }
        let from_block = wallet_backfill_from_block(last_scanned, start_block);

        // When safe_head has not been set yet (still 0) we cannot tell whether
        // the wallet is caught up, so we always enqueue a backfill request and
        // let the backfill loop wait for safe_head to become available.
        let needs_backfill = follow_safe_head || sync_target == 0 || from_block <= sync_target;

        if needs_backfill {
            let target_result = handle
                .start_backfill(&cfg.cache_key, &backfill_sender, progress, sync_target)
                .await;
            debug!(?target_result, cache_key = %cfg.cache_key, "wallet target update result");
            let driver = match target_result {
                WalletBackfillStartResult::Accepted { grant, .. } => grant.activate(),
                WalletBackfillStartResult::Rejected { .. } => return,
            };
            let request = if let Some(plan) = short_startup_plan {
                let acquisition_range = if self
                    .cached_wallet_startup_acquisition_prefix(plan)
                    .await
                    .is_some()
                {
                    (plan.delivery.from_block, plan.acquisition.to_block)
                } else {
                    plan.acquisition_tuple()
                };
                BackfillRequest::add_with_acquisition(
                    cfg.cache_key.clone(),
                    from_block,
                    sync_target,
                    follow_safe_head,
                    from_block,
                    acquisition_range,
                    driver,
                )
            } else {
                BackfillRequest::add(
                    cfg.cache_key.clone(),
                    from_block,
                    sync_target,
                    follow_safe_head,
                    from_block,
                    driver,
                )
            };
            if let Err(err) = self.backfill_tx.try_send(request) {
                warn!(
                    ?err,
                    cache_key = %cfg.cache_key,
                    "backfill loop unavailable after target update"
                );
                if let BackfillRequest::Add { driver, .. } = err.into_inner() {
                    driver
                        .fail(&cfg.cache_key, WalletReadinessError::BackfillUnavailable)
                        .await;
                }
            }
        } else {
            let start_result = handle
                .start_backfill(&cfg.cache_key, &backfill_sender, progress, sync_target)
                .await;
            let result = match start_result {
                WalletBackfillStartResult::Accepted { grant, .. } => {
                    let driver = grant.activate();
                    let result = driver.finish(&cfg.cache_key, sync_target).await;
                    if wallet_finish_result_removes_cursor(&result) {
                        driver.retire(&cfg.cache_key).await;
                    } else {
                        let request = wallet_finish_retry_request(
                            cfg.cache_key.to_string(),
                            sync_target,
                            false,
                            from_block,
                            &result,
                            driver,
                        );
                        if let Err(err) = self.backfill_tx.try_send(request) {
                            warn!(?err, cache_key = %cfg.cache_key, sync_target, "failed to enqueue fixed-target finish retry");
                            if let BackfillRequest::Add { driver, .. } = err.into_inner() {
                                driver
                                    .fail(&cfg.cache_key, WalletReadinessError::BackfillUnavailable)
                                    .await;
                            }
                        }
                    }
                    result
                }
                WalletBackfillStartResult::Rejected {
                    committed_to,
                    reason,
                } => WalletBackfillFinishResult::Rejected {
                    committed_to,
                    reason,
                },
            };
            debug!(?result, cache_key = %cfg.cache_key, "wallet finish result");
        }
    }

    async fn short_wallet_startup_sync(
        self: &Arc<Self>,
        cfg: &WalletConfig,
        start_block: u64,
        progress: crate::types::WalletSchedulableProgress,
        sync_target: u64,
        plan: Option<WalletShortStartupPlan>,
        backfill_sender: mpsc::Sender<BackfillEvent>,
        handle: &WalletHandle,
        cancel: &CancellationToken,
    ) -> bool {
        let last_scanned = progress.last_scanned;
        let Some(plan) = plan else {
            return false;
        };

        let started = Instant::now();
        info!(
            cache_key = %cfg.cache_key,
            start_block,
            last_scanned,
            sync_target,
            block_range = self.chain.block_range,
            "wallet startup hedge started"
        );

        let hedge_cancel = cancel.child_token();
        let mut candidates = JoinSet::new();

        let rpc_service = Arc::clone(self);
        let rpc_cfg = cfg.clone();
        let rpc_cancel = hedge_cancel.child_token();
        candidates.spawn(async move {
            let result = Arc::clone(&rpc_service)
                .wallet_startup_rpc_candidate(&rpc_cfg, plan, rpc_cancel)
                .await;
            (WalletStartupSyncStrategy::Rpc, result)
        });

        if cfg.use_indexed_wallet_catch_up {
            let indexed_service = Arc::clone(self);
            let indexed_cfg = cfg.clone();
            let indexed_cancel = hedge_cancel.child_token();
            candidates.spawn(async move {
                let result = Arc::clone(&indexed_service)
                    .wallet_startup_indexed_candidate(&indexed_cfg, plan, indexed_cancel)
                    .await;
                (WalletStartupSyncStrategy::Indexed, result)
            });
        }

        let mut failures = 0_u8;
        let mut selected = None;
        while !candidates.is_empty() && selected.is_none() {
            let joined = tokio::select! {
                () = cancel.cancelled() => None,
                joined = candidates.join_next() => joined,
            };
            let Some(joined) = joined else {
                break;
            };
            match joined {
                Ok((strategy, Ok(candidate))) => selected = Some((strategy, candidate)),
                Ok((strategy, Err(err))) => {
                    failures = failures.saturating_add(1);
                    debug!(
                        err = %err,
                        cache_key = %cfg.cache_key,
                        strategy = strategy.as_str(),
                        failures,
                        "wallet startup hedge candidate failed"
                    );
                }
                Err(err) => {
                    failures = failures.saturating_add(1);
                    debug!(
                        ?err,
                        cache_key = %cfg.cache_key,
                        failures,
                        "wallet startup hedge candidate task failed"
                    );
                }
            }
        }

        let outer_cancelled = cancel.is_cancelled();
        hedge_cancel.cancel();
        candidates.abort_all();
        let mut cancelled_loser = false;
        while let Some(joined) = candidates.join_next().await {
            match joined {
                Ok((_, Err(WalletStartupSyncError::Cancelled))) => cancelled_loser = true,
                Ok((strategy, Err(err))) => {
                    debug!(?err, strategy = strategy.as_str(), cache_key = %cfg.cache_key, "wallet startup hedge loser candidate failed");
                }
                Ok((_, Ok(_))) => {}
                Err(err) => {
                    if err.is_cancelled() {
                        cancelled_loser = true;
                    } else {
                        debug!(?err, cache_key = %cfg.cache_key, "wallet startup hedge loser task failed");
                    }
                }
            }
        }

        if let Some((strategy, candidate)) = selected {
            let follow_safe_head = cfg.sync_to_block.is_none();
            let winner = candidate.strategy;
            let candidate_elapsed_ms = candidate.elapsed_ms;
            let acquisition_apply_count = candidate.acquisition_applies.len();
            let committed_progress = self
                .commit_and_deliver_short_startup_candidate(
                    cfg,
                    progress,
                    sync_target,
                    plan,
                    candidate,
                    &backfill_sender,
                    handle,
                    cancel,
                )
                .await;
            let sent = committed_progress.is_some();
            if let Some(progress) = committed_progress
                && follow_safe_head
            {
                self.enqueue_wallet_backfill(
                    cfg,
                    start_block,
                    sync_target,
                    sync_target,
                    true,
                    handle,
                    progress,
                    backfill_sender.clone(),
                    true,
                    None,
                )
                .await;
            }
            info!(
                cache_key = %cfg.cache_key,
                winner = winner.as_str(),
                reported_by = strategy.as_str(),
                candidate_elapsed_ms,
                acquisition_apply_count,
                follow_safe_head,
                elapsed_ms = started.elapsed().as_millis(),
                cancelled_loser,
                sent,
                "wallet startup hedge complete"
            );
            return sent;
        }

        if outer_cancelled {
            debug!(
                cache_key = %cfg.cache_key,
                elapsed_ms = started.elapsed().as_millis(),
                "short wallet startup cancelled"
            );
        } else {
            warn!(
                cache_key = %cfg.cache_key,
                elapsed_ms = started.elapsed().as_millis(),
                "short wallet startup sources failed; falling back to startup continuation"
            );
        }
        false
    }

    async fn commit_and_deliver_short_startup_candidate(
        &self,
        cfg: &WalletConfig,
        progress: crate::types::WalletSchedulableProgress,
        sync_target: u64,
        plan: WalletShortStartupPlan,
        candidate: WalletStartupSyncCandidate,
        backfill_sender: &mpsc::Sender<BackfillEvent>,
        handle: &WalletHandle,
        cancel: &CancellationToken,
    ) -> Option<crate::types::WalletSchedulableProgress> {
        if cancel.is_cancelled() {
            return None;
        }
        let progress = handle.revalidate_schedulable_progress(progress)?;
        if let Err(err) = self
            .public_data_plane
            .commit_completed_short_startup_acquisition(
                plan.acquisition,
                &candidate.acquisition_applies,
            )
            .await
        {
            debug!(
                ?err,
                cache_key = %cfg.cache_key,
                strategy = candidate.strategy.as_str(),
                "wallet startup candidate commit rejected"
            );
            return None;
        }
        send_wallet_startup_events(
            &cfg.cache_key,
            candidate.applies,
            Some(sync_target),
            progress,
            backfill_sender,
            handle,
        )
        .await
        .then_some(progress)
    }

    async fn cached_wallet_startup_acquisition_prefix(
        &self,
        plan: WalletShortStartupPlan,
    ) -> Option<Vec<WalletScanApply>> {
        let range = plan.acquisition_prefix_before_delivery()?;
        self.public_data_plane
            .cached_wallet_scan_exact(range.from_block, range.to_block)
            .await
    }

    pub(super) async fn wallet_startup_rpc_candidate(
        self: Arc<Self>,
        cfg: &WalletConfig,
        plan: WalletShortStartupPlan,
        cancel: CancellationToken,
    ) -> Result<WalletStartupSyncCandidate, WalletStartupSyncError> {
        let started = Instant::now();
        let deliver_from_block = plan.delivery.from_block;
        let sync_target = plan.acquisition.to_block;
        let cached_prefix = self.cached_wallet_startup_acquisition_prefix(plan).await;
        let fetch_from_block = cached_prefix
            .as_ref()
            .map_or(plan.acquisition.from_block, |_| deliver_from_block);
        let mut cached_suffix = self
            .public_data_plane
            .cached_wallet_scan_suffix(deliver_from_block, sync_target)
            .await;
        let cached_suffix_from = cached_suffix
            .as_ref()
            .and_then(|applies| applies.first())
            .map(|apply| apply.from_block);
        let remote_to_block =
            wallet_remote_target_before_cached_suffix(sync_target, cached_suffix_from);
        let (mut fetched_applies, mut events) = if fetch_from_block <= remote_to_block {
            let fetched = self
                .fetch_wallet_rpc_backfill_events(
                    fetch_from_block,
                    deliver_from_block,
                    remote_to_block,
                    RpcTargetPolicy::RequireRequestedTarget,
                    &cancel,
                    self.begin_public_scan_read(),
                )
                .await?;
            (fetched.acquisition_applies, fetched.delivery_applies)
        } else {
            (Vec::new(), Vec::new())
        };
        let mut acquisition_applies = cached_prefix.unwrap_or_default();
        acquisition_applies.append(&mut fetched_applies);
        if let Some(cached_suffix) = cached_suffix.as_mut() {
            acquisition_applies.extend(cached_suffix.iter().cloned());
            events.append(cached_suffix);
        }
        debug!(
            cache_key = %cfg.cache_key,
            fetch_from_block,
            deliver_from_block,
            remote_to_block,
            cached_suffix_from,
            sync_target,
            events = events.len(),
            elapsed_ms = started.elapsed().as_millis(),
            "wallet startup RPC candidate complete"
        );
        Ok(WalletStartupSyncCandidate {
            strategy: WalletStartupSyncStrategy::Rpc,
            acquisition_applies,
            applies: events,
            elapsed_ms: started.elapsed().as_millis(),
        })
    }

    async fn wallet_startup_indexed_candidate(
        self: Arc<Self>,
        cfg: &WalletConfig,
        plan: WalletShortStartupPlan,
        cancel: CancellationToken,
    ) -> Result<WalletStartupSyncCandidate, WalletStartupSyncError> {
        let started = Instant::now();
        let source_read_scope = self.begin_public_scan_read();
        let endpoint = self
            .chain
            .quick_sync_endpoint
            .clone()
            .ok_or(WalletStartupSyncError::Cancelled)?;
        let client = match self.chain.http_client.clone() {
            Some(http_client) => QuickSyncClient::with_http_client(endpoint, http_client),
            None => QuickSyncClient::new(endpoint),
        };
        let probe_started = Instant::now();
        let probe = wait_or_cancel(&cancel, client.probe_indexed_wallet_support()).await??;
        debug!(
            cache_key = %cfg.cache_key,
            elapsed_ms = probe_started.elapsed().as_millis(),
            "indexed wallet hedge probe complete"
        );

        let deliver_from_block = plan.delivery.from_block;
        let sync_target = plan.acquisition.to_block;
        let cached_prefix = self.cached_wallet_startup_acquisition_prefix(plan).await;
        let mut cached_suffix = self
            .public_data_plane
            .cached_wallet_scan_suffix(deliver_from_block, sync_target)
            .await;
        let cached_suffix_from = cached_suffix
            .as_ref()
            .and_then(|applies| applies.first())
            .map(|apply| apply.from_block);
        let remote_target =
            wallet_remote_target_before_cached_suffix(sync_target, cached_suffix_from);
        let warm_from_block = plan.acquisition.from_block;
        let target = probe.height.min(remote_target);
        let mut from_block = cached_prefix
            .as_ref()
            .map_or(warm_from_block, |_| deliver_from_block);
        let mut checkpoint = from_block.saturating_sub(1);
        let mut acquisition_applies = cached_prefix.unwrap_or_default();
        let mut events = Vec::new();
        info!(
            cache_key = %cfg.cache_key,
            indexed_height = probe.height,
            sync_target,
            deliver_from_block,
            warm_from_block,
            cached_suffix_from,
            remote_target,
            from_block,
            target,
            indexed_block_range = self.chain.indexed_wallet_block_range,
            "indexed wallet hedge target"
        );

        while from_block <= target {
            if cancel.is_cancelled() {
                return Err(WalletStartupSyncError::Cancelled);
            }
            let read_scope = source_read_scope;
            let page_started = Instant::now();
            let page_kind =
                IndexedWalletPageKind::for_from_block(from_block, self.chain.v2_start_block);
            let to_block = page_kind.to_block(
                from_block,
                target,
                self.chain.v2_start_block,
                self.chain.indexed_wallet_block_range,
            );
            let fetch_started = Instant::now();
            let page = wait_or_cancel(
                &cancel,
                IndexedWalletPage::fetch(&client, page_kind, from_block, to_block),
            )
            .await??;
            let fetch_elapsed_ms = fetch_started.elapsed().as_millis();
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
            checkpoint = page.checkpoint_block;
            let mut page_rows = page.into_scan_rows();
            let fetched_apply = WalletScanApply::indexed_rows(
                from_block,
                checkpoint,
                page_rows.clone(),
                read_scope,
                WalletIndexedCatchUpSource::Squid,
            );
            acquisition_applies.push(fetched_apply);
            let delivery_page_from = from_block.max(deliver_from_block);
            if delivery_page_from <= checkpoint {
                page_rows.retain_block_range(delivery_page_from, checkpoint);
                events.push(WalletScanApply::indexed_rows(
                    delivery_page_from,
                    checkpoint,
                    page_rows,
                    read_scope,
                    WalletIndexedCatchUpSource::Squid,
                ));
            }
            debug!(
                cache_key = %cfg.cache_key,
                page_kind = page_kind.as_str(),
                from_block,
                to_block,
                checkpoint,
                transact_rows,
                shield_rows,
                legacy_encrypted_rows,
                legacy_generated_rows,
                nullifier_rows,
                row_count,
                fetch_elapsed_ms,
                parse_elapsed_ms,
                elapsed_ms = page_started.elapsed().as_millis(),
                "indexed wallet hedge page complete"
            );
            from_block = checkpoint.saturating_add(1);
        }

        if checkpoint < remote_target {
            let tail_fetch_from = checkpoint.saturating_add(1).max(warm_from_block);
            let tail_deliver_from = tail_fetch_from.max(deliver_from_block);
            let mut tail_events = self
                .fetch_wallet_rpc_backfill_events(
                    tail_fetch_from,
                    tail_deliver_from,
                    remote_target,
                    RpcTargetPolicy::RequireRequestedTarget,
                    &cancel,
                    self.begin_public_scan_read(),
                )
                .await?;
            acquisition_applies.append(&mut tail_events.acquisition_applies);
            events.append(&mut tail_events.delivery_applies);
        }
        if let Some(cached_suffix) = cached_suffix.as_mut() {
            acquisition_applies.extend(cached_suffix.iter().cloned());
            events.append(cached_suffix);
        }
        Ok(WalletStartupSyncCandidate {
            strategy: WalletStartupSyncStrategy::Indexed,
            acquisition_applies,
            applies: events,
            elapsed_ms: started.elapsed().as_millis(),
        })
    }

    async fn wallet_startup_artifact_candidate(
        &self,
        cfg: &WalletConfig,
        plan: WalletShortStartupPlan,
        cancel: &CancellationToken,
    ) -> Result<Option<WalletStartupSyncCandidate>, WalletStartupSyncError> {
        let started = Instant::now();
        if cancel.is_cancelled() {
            return Err(WalletStartupSyncError::Cancelled);
        }
        let cached_prefix = self.cached_wallet_startup_acquisition_prefix(plan).await;
        let acquisition_from = cached_prefix
            .as_ref()
            .map_or(plan.acquisition.from_block, |_| plan.delivery.from_block);
        let Some(session) = wait_or_cancel(
            cancel,
            self.prepare_indexed_wallet_artifact_session(
                cfg,
                acquisition_from,
                plan.acquisition.to_block,
                cfg.progress_tx.as_ref(),
            ),
        )
        .await?
        else {
            return Ok(None);
        };
        let read_scope = session.read_scope();
        self.public_data_plane
            .record_source_decision(
                PublicDataPlaneDiagnosticKind::SourceFallback,
                PublicScanSource::IndexedArtifacts,
                plan.acquisition,
                read_scope,
                "short wallet startup hedge failed; attempting indexed artifacts",
            )
            .await;

        let deliver_from_block = plan.delivery.from_block;
        let sync_target = plan.acquisition.to_block;
        let mut cached_suffix = self
            .public_data_plane
            .cached_wallet_scan_suffix(deliver_from_block, sync_target)
            .await;
        let cached_suffix_from = cached_suffix
            .as_ref()
            .and_then(|applies| applies.first())
            .map(|apply| apply.from_block);
        let remote_target =
            wallet_remote_target_before_cached_suffix(sync_target, cached_suffix_from);
        let mut from_block = acquisition_from;
        let target = session.target_block().min(remote_target);
        let mut acquisition_applies = cached_prefix.unwrap_or_default();
        let mut events = Vec::new();
        while from_block <= target {
            if cancel.is_cancelled() {
                return Err(WalletStartupSyncError::Cancelled);
            }
            let page_kind =
                IndexedWalletPageKind::for_from_block(from_block, self.chain.v2_start_block);
            let to_block = page_kind.to_block(
                from_block,
                target,
                self.chain.v2_start_block,
                self.chain.indexed_wallet_block_range,
            );
            let page = match session.page_for_block_range(from_block, to_block)? {
                IndexedWalletArtifactPageOutcome::Page(page) => page,
                IndexedWalletArtifactPageOutcome::Exhausted { .. } => return Ok(None),
            };
            let checkpoint = page.checkpoint_block;
            let mut page_rows = page.into_scan_rows();
            let fetched_apply = WalletScanApply::indexed_rows(
                from_block,
                checkpoint,
                page_rows.clone(),
                read_scope,
                WalletIndexedCatchUpSource::IndexedArtifacts,
            );
            acquisition_applies.push(fetched_apply);
            let delivery_from = from_block.max(plan.delivery.from_block);
            if delivery_from <= checkpoint {
                page_rows.retain_block_range(delivery_from, checkpoint);
                events.push(WalletScanApply::indexed_rows(
                    delivery_from,
                    checkpoint,
                    page_rows,
                    read_scope,
                    WalletIndexedCatchUpSource::IndexedArtifacts,
                ));
            }
            from_block = checkpoint.saturating_add(1);
        }
        if target < remote_target {
            let tail_fetch_from = target.saturating_add(1).max(acquisition_from);
            let tail_deliver_from = tail_fetch_from.max(deliver_from_block);
            let mut tail_events = self
                .fetch_wallet_rpc_backfill_events(
                    tail_fetch_from,
                    tail_deliver_from,
                    remote_target,
                    RpcTargetPolicy::RequireRequestedTarget,
                    cancel,
                    self.begin_public_scan_read(),
                )
                .await?;
            acquisition_applies.append(&mut tail_events.acquisition_applies);
            events.append(&mut tail_events.delivery_applies);
        }
        if let Some(cached_suffix) = cached_suffix.as_mut() {
            acquisition_applies.extend(cached_suffix.iter().cloned());
            events.append(cached_suffix);
        }
        debug!(
            cache_key = %cfg.cache_key,
            acquisition_from = plan.acquisition.from_block,
            delivery_from = plan.delivery.from_block,
            target,
            events = events.len(),
            elapsed_ms = started.elapsed().as_millis(),
            "wallet startup artifact fallback complete"
        );
        Ok(Some(WalletStartupSyncCandidate {
            strategy: WalletStartupSyncStrategy::Indexed,
            acquisition_applies,
            applies: events,
            elapsed_ms: started.elapsed().as_millis(),
        }))
    }

    async fn fetch_wallet_rpc_backfill_events(
        &self,
        fetch_from_block: u64,
        deliver_from_block: u64,
        to_block: u64,
        target_policy: RpcTargetPolicy,
        cancel: &CancellationToken,
        read_scope: PublicScanReadScope,
    ) -> Result<WalletRpcBackfillEvents, WalletStartupSyncError> {
        if fetch_from_block > to_block {
            return Ok(WalletRpcBackfillEvents {
                acquisition_applies: Vec::new(),
                delivery_applies: Vec::new(),
            });
        }
        let rpc = self
            .chain
            .rpcs
            .random_provider()
            .ok_or(ChainError::NoHealthyRpc)?;
        let started = Instant::now();
        let provider_head = match wait_or_cancel(cancel, rpc.provider.get_block_number()).await? {
            Ok(provider_head) => provider_head,
            Err(err) => {
                let err = ChainError::from(err);
                if err.should_mark_rpc_unhealthy() {
                    self.chain.rpcs.mark_bad_provider(&rpc);
                }
                return Err(err.into());
            }
        };
        let proven_to_block = provider_head.saturating_sub(self.chain.finality_depth);
        if target_policy == RpcTargetPolicy::RequireRequestedTarget && proven_to_block < to_block {
            debug!(
                fetch_from_block,
                deliver_from_block,
                requested_to_block = to_block,
                provider_head,
                proven_to_block,
                finality_depth = self.chain.finality_depth,
                "RPC wallet startup source does not cover the required target"
            );
            return Err(WalletStartupSyncError::IncompleteRpcCoverage {
                requested_to: to_block,
                proven_to: proven_to_block,
            });
        }
        if fetch_from_block > proven_to_block {
            debug!(
                fetch_from_block,
                deliver_from_block,
                requested_to_block = to_block,
                provider_head,
                proven_to_block,
                finality_depth = self.chain.finality_depth,
                "RPC wallet scan source has no proven coverage for requested range"
            );
            return Ok(WalletRpcBackfillEvents {
                acquisition_applies: Vec::new(),
                delivery_applies: Vec::new(),
            });
        }
        let to_block = to_block.min(proven_to_block);
        let fetch_logs_started = Instant::now();
        let mut logs = match wait_or_cancel(
            cancel,
            self.chain.fetch_logs_for_range(
                &rpc.provider,
                self.archive_provider.as_ref(),
                fetch_from_block,
                to_block,
            ),
        )
        .await?
        {
            Ok(logs) => logs,
            Err(err) => {
                if err.should_mark_rpc_unhealthy() {
                    self.chain.rpcs.mark_bad_provider(&rpc);
                }
                return Err(err.into());
            }
        };
        debug!(
            fetch_from_block,
            deliver_from_block,
            to_block,
            num_logs = logs.len(),
            elapsed_ms = fetch_logs_started.elapsed().as_millis(),
            "fetched hedged wallet RPC logs"
        );
        sort_logs(&mut logs);

        let timestamps_started = Instant::now();
        let block_timestamps = match wait_or_cancel(
            cancel,
            self.chain.fetch_log_block_timestamps(
                &rpc.provider,
                self.archive_provider.as_ref(),
                &logs,
            ),
        )
        .await?
        {
            Ok(block_timestamps) => block_timestamps,
            Err(err) => {
                if err.should_mark_rpc_unhealthy() {
                    self.chain.rpcs.mark_bad_provider(&rpc);
                }
                return Err(err.into());
            }
        };
        debug!(
            fetch_from_block,
            deliver_from_block,
            to_block,
            num_logs = logs.len(),
            elapsed_ms = timestamps_started.elapsed().as_millis(),
            "fetched hedged wallet RPC log block timestamps"
        );

        if let Some(archive_endpoint) = self
            .chain
            .archive_boundary_crossed_by(fetch_from_block, to_block)
        {
            let archive_hash = wait_or_cancel(
                cancel,
                self.chain.fetch_block_hash(
                    &rpc.provider,
                    self.archive_provider.as_ref(),
                    archive_endpoint,
                ),
            )
            .await??;
            if archive_hash.is_none() {
                return Err(WalletStartupSyncError::UnprovenRpcEndpoint {
                    block_number: archive_endpoint,
                });
            }
        }

        let block_hash_started = Instant::now();
        let to_block_hash = match wait_or_cancel(
            cancel,
            self.chain
                .fetch_block_hash(&rpc.provider, self.archive_provider.as_ref(), to_block),
        )
        .await?
        {
            Ok(hash) => {
                if hash.is_none() {
                    return Err(WalletStartupSyncError::UnprovenRpcEndpoint {
                        block_number: to_block,
                    });
                }
                hash
            }
            Err(err) => return Err(err.into()),
        };
        debug!(
            to_block,
            elapsed_ms = block_hash_started.elapsed().as_millis(),
            "fetched hedged wallet RPC block hash"
        );

        let batch = Arc::new(LogBatch {
            from_block: fetch_from_block,
            to_block,
            logs,
            block_timestamps,
            to_block_hash,
            read_scope,
        });
        debug!(
            fetch_from_block,
            deliver_from_block,
            to_block,
            elapsed_ms = started.elapsed().as_millis(),
            "hedged wallet RPC backfill candidate complete"
        );
        let source = self.rpc_scan_source_for_range(fetch_from_block);
        let fetched_apply =
            WalletScanApply::rows_from_log_batch(fetch_from_block, to_block, &batch, source)
                .map_err(ChainError::from)?;
        let delivery_applies = if deliver_from_block > to_block {
            Vec::new()
        } else {
            vec![
                WalletScanApply::rows_from_log_batch(deliver_from_block, to_block, &batch, source)
                    .map_err(ChainError::from)?,
            ]
        };
        Ok(WalletRpcBackfillEvents {
            acquisition_applies: vec![fetched_apply],
            delivery_applies,
        })
    }

    async fn probe_squid_indexed_wallet_source(
        &self,
        cfg: &WalletConfig,
    ) -> Option<SquidIndexedWalletReadSession> {
        self.probe_squid_indexed_wallet_source_for_label(&cfg.cache_key)
            .await
    }

    async fn probe_squid_indexed_wallet_source_for_label(
        &self,
        cache_key: &str,
    ) -> Option<SquidIndexedWalletReadSession> {
        let Some(endpoint) = self.chain.quick_sync_endpoint.clone() else {
            debug!(cache_key = %cache_key, "no indexed endpoint configured; using RPC wallet backfill");
            return None;
        };
        let client = match self.chain.http_client.clone() {
            Some(http_client) => QuickSyncClient::with_http_client(endpoint, http_client),
            None => QuickSyncClient::new(endpoint),
        };
        let read_scope = self.begin_public_scan_read();
        let probe_started = Instant::now();
        let probe = match client.probe_indexed_wallet_support().await {
            Ok(probe) => probe,
            Err(err) => {
                warn!(
                    ?err,
                    cache_key = %cache_key,
                    "indexed wallet probe failed; using RPC backfill"
                );
                return None;
            }
        };
        debug!(
            cache_key = %cache_key,
            elapsed_ms = probe_started.elapsed().as_millis(),
            "indexed wallet probe complete"
        );
        Some(SquidIndexedWalletReadSession {
            client,
            indexed_height: probe.height,
            read_scope,
        })
    }

    async fn probe_squid_tail_after_artifact(
        &self,
        cfg: &WalletConfig,
        from_block: u64,
        artifact_target: u64,
        safe_head: u64,
    ) -> Option<(SquidIndexedWalletReadSession, u64)> {
        if artifact_target >= safe_head {
            return None;
        }
        let session = self.probe_squid_indexed_wallet_source(cfg).await?;
        let target = squid_tail_target_after_artifact(
            from_block,
            artifact_target,
            safe_head,
            session.indexed_height(),
        )?;
        Some((session, target))
    }

    async fn prepare_indexed_wallet_artifact_session(
        &self,
        cfg: &WalletConfig,
        from_block: u64,
        safe_head: u64,
        progress_tx: Option<&SyncProgressSender>,
    ) -> Option<IndexedWalletArtifactSession> {
        self.prepare_indexed_wallet_artifact_session_for_label(
            &cfg.cache_key,
            from_block,
            safe_head,
            progress_tx,
        )
        .await
    }

    async fn prepare_indexed_wallet_artifact_session_for_label(
        &self,
        cache_key: &str,
        from_block: u64,
        safe_head: u64,
        progress_tx: Option<&SyncProgressSender>,
    ) -> Option<IndexedWalletArtifactSession> {
        self.chain.indexed_artifact_source.as_ref()?;
        let read_scope = self.begin_public_scan_read();
        let range = PublicScanRange::new(from_block, safe_head);
        self.public_data_plane
            .record_source_decision(
                PublicDataPlaneDiagnosticKind::ArtifactProgress,
                PublicScanSource::IndexedArtifacts,
                range,
                read_scope,
                "wallet-scan artifact preparation started",
            )
            .await;
        let artifact_session_started = Instant::now();
        match IndexedWalletArtifactSession::prepare(
            &self.chain,
            from_block,
            safe_head,
            read_scope,
            &self.public_data_plane,
            progress_tx,
        )
        .await
        {
            Ok(Some(session)) => {
                self.public_data_plane
                    .record_source_decision(
                        PublicDataPlaneDiagnosticKind::ArtifactProgress,
                        PublicScanSource::IndexedArtifacts,
                        range,
                        read_scope,
                        format!(
                            "wallet-scan artifact preparation complete: {} chunks",
                            session.chunk_count()
                        ),
                    )
                    .await;
                debug!(
                    cache_key = %cache_key,
                    from_block,
                    safe_head,
                    latest_indexed_block = session.latest_indexed_block(),
                    catalog_count = session.catalog_count(),
                    chunk_count = session.chunk_count(),
                    elapsed_ms = artifact_session_started.elapsed().as_millis(),
                    "indexed wallet artifact session prepared"
                );
                Some(session)
            }
            Ok(None) => {
                self.public_data_plane
                    .record_source_decision(
                        PublicDataPlaneDiagnosticKind::ArtifactProgress,
                        PublicScanSource::IndexedArtifacts,
                        range,
                        read_scope,
                        "wallet-scan artifact preparation unavailable",
                    )
                    .await;
                self.public_data_plane
                    .record_source_decision(
                        PublicDataPlaneDiagnosticKind::SourceFallback,
                        PublicScanSource::IndexedArtifacts,
                        range,
                        read_scope,
                        "wallet-scan artifact preparation unavailable; falling back",
                    )
                    .await;
                debug!(
                    cache_key = %cache_key,
                    from_block,
                    safe_head,
                    elapsed_ms = artifact_session_started.elapsed().as_millis(),
                    "indexed wallet artifact session unavailable"
                );
                None
            }
            Err(err) => {
                self.public_data_plane
                    .record_source_decision(
                        PublicDataPlaneDiagnosticKind::ArtifactProgress,
                        PublicScanSource::IndexedArtifacts,
                        range,
                        read_scope,
                        "wallet-scan artifact preparation failed",
                    )
                    .await;
                self.public_data_plane
                    .record_source_decision(
                        PublicDataPlaneDiagnosticKind::SourceFallback,
                        PublicScanSource::IndexedArtifacts,
                        range,
                        read_scope,
                        "wallet-scan artifact preparation failed; falling back",
                    )
                    .await;
                warn!(
                    ?err,
                    cache_key = %cache_key,
                    from_block,
                    safe_head,
                    elapsed_ms = artifact_session_started.elapsed().as_millis(),
                    "indexed wallet artifact session failed; falling back to configured indexed sources"
                );
                None
            }
        }
    }

    pub async fn unregister_wallet(&self, handle: &WalletHandle) {
        let cache_key = handle.cache_key.as_str();
        let registration_gate = self.wallet_registration_gate(cache_key).await;
        let registration_guard = registration_gate.lock().await;
        let registration = {
            let mut wallets = self.wallets.write().await;
            let is_current = wallets
                .get(cache_key)
                .is_some_and(|registration| registration.handle.same_actor_as(handle));
            is_current.then(|| wallets.remove(cache_key)).flatten()
        };
        let Some(registration) = registration else {
            return;
        };
        Self::begin_wallet_retirement(&registration);
        drop(registration_guard);
        self.finish_wallet_retirement(cache_key, registration).await;
    }

    fn begin_wallet_retirement(registration: &WalletRegistration) {
        registration
            .handle
            .retire_actor_with_publisher(&registration.observation);
        registration.cancel.cancel();
    }

    fn begin_wallet_shutdown(registration: &WalletRegistration) {
        registration
            .handle
            .retire_actor_for_shutdown(&registration.observation);
        registration.cancel.cancel();
    }

    async fn finish_wallet_retirement(&self, cache_key: &str, registration: WalletRegistration) {
        if self
            .backfill_tx
            .send(BackfillRequest::Remove {
                cache_key: cache_key.to_string(),
                actor_id: registration.handle.actor_id(),
            })
            .await
            .is_err()
        {
            warn!(cache_key = %cache_key, "failed to remove backfill cursor");
        }
        if let Err(err) = registration.worker.await {
            warn!(?err, cache_key = %cache_key, "wallet worker failed during retirement");
        }
    }

    pub async fn unregister_all_wallets(&self) {
        let registrations = self.wallets.write().await.drain().collect::<Vec<_>>();
        for (_, registration) in &registrations {
            Self::begin_wallet_retirement(registration);
        }
        for (cache_key, registration) in registrations {
            self.finish_wallet_retirement(&cache_key, registration)
                .await;
        }
    }

    pub async fn shutdown(&self) {
        self.cancel.cancel();
        let registrations = self.wallets.write().await.drain().collect::<Vec<_>>();
        for (_, registration) in &registrations {
            Self::begin_wallet_shutdown(registration);
        }
        for (cache_key, registration) in registrations {
            self.finish_wallet_retirement(&cache_key, registration)
                .await;
        }
        self.public_data_plane.shutdown().await;
        await_live_log_task_shutdown(&self.live_log_task, self.chain.chain_id).await;
    }

    pub(super) async fn indexed_wallet_catch_up(
        &self,
        cfg: &WalletConfig,
        start_block: u64,
        last_scanned: u64,
        safe_head: u64,
        handle: &WalletHandle,
        cancel: &CancellationToken,
        source_order: IndexedWalletCatchUpSourceOrder,
        expose_status: bool,
        queued_sender: (
            &mpsc::Sender<BackfillEvent>,
            crate::types::WalletSchedulableProgress,
        ),
    ) -> u64 {
        if safe_head == 0 {
            debug!(cache_key = %cfg.cache_key, "safe head unavailable; skipping indexed wallet catch-up");
            return last_scanned;
        }
        let mut last_scanned = last_scanned;
        let initial_last_scanned = last_scanned;
        let mut from_block = last_scanned.saturating_add(1).max(start_block);
        let Some(status_guard) =
            WalletIndexedCatchUpStatusGuard::claim(handle, expose_status).await
        else {
            debug!(cache_key = %cfg.cache_key, "indexed wallet catch-up already active");
            return last_scanned;
        };
        let (sender, progress) = queued_sender;
        let cached_outcome = self
            .apply_cached_public_scan_coverage(
                cfg,
                start_block,
                last_scanned,
                safe_head,
                handle,
                sender,
                progress,
            )
            .await;
        if cached_outcome.checkpoint > last_scanned {
            last_scanned = cached_outcome.checkpoint;
            from_block = last_scanned.saturating_add(1).max(start_block);
            if cached_outcome.finished || from_block > safe_head {
                return last_scanned;
            }
        }
        if wallet_has_persistence_failure(handle) {
            return last_scanned;
        }
        let artifact_progress_tx = if last_scanned == initial_last_scanned {
            cfg.progress_tx.as_ref()
        } else {
            None
        };
        let mut artifact_session =
            if source_order == IndexedWalletCatchUpSourceOrder::ArtifactsFirst {
                self.prepare_indexed_wallet_artifact_session(
                    cfg,
                    from_block,
                    safe_head,
                    artifact_progress_tx,
                )
                .await
            } else {
                None
            };
        let catch_up_started = Instant::now();
        let mut squid_session = None;
        let (mut indexed_source, mut indexed_height, mut target, mut using_artifact) =
            if source_order == IndexedWalletCatchUpSourceOrder::SquidFirst {
                if let Some(session) = self.probe_squid_indexed_wallet_source(cfg).await {
                    let height = session.indexed_height();
                    let target = height.min(safe_head);
                    if from_block <= target {
                        squid_session = Some(session);
                        (WalletIndexedCatchUpSource::Squid, height, target, false)
                    } else {
                        status_guard.set(
                            WalletIndexedCatchUpSource::IndexedArtifacts,
                            from_block,
                            safe_head,
                        );
                        artifact_session = self
                            .prepare_indexed_wallet_artifact_session(
                                cfg,
                                from_block,
                                safe_head,
                                artifact_progress_tx,
                            )
                            .await;
                        let Some(session) = artifact_session.as_ref() else {
                            self.record_public_scan_fallback(
                                self.rpc_scan_source_for_range(from_block),
                                PublicScanRange::new(from_block, safe_head),
                                self.begin_public_scan_read(),
                                "indexed wallet artifacts unavailable after Squid tail gap; falling back to RPC",
                            )
                            .await;
                            return last_scanned;
                        };
                        (
                            WalletIndexedCatchUpSource::IndexedArtifacts,
                            session.latest_indexed_block(),
                            session.target_block(),
                            true,
                        )
                    }
                } else {
                    status_guard.set(
                        WalletIndexedCatchUpSource::IndexedArtifacts,
                        from_block,
                        safe_head,
                    );
                    artifact_session = self
                        .prepare_indexed_wallet_artifact_session(
                            cfg,
                            from_block,
                            safe_head,
                            artifact_progress_tx,
                        )
                        .await;
                    let Some(session) = artifact_session.as_ref() else {
                        self.record_public_scan_fallback(
                            self.rpc_scan_source_for_range(from_block),
                            PublicScanRange::new(from_block, safe_head),
                            self.begin_public_scan_read(),
                            "indexed wallet sources unavailable; falling back to RPC",
                        )
                        .await;
                        return last_scanned;
                    };
                    (
                        WalletIndexedCatchUpSource::IndexedArtifacts,
                        session.latest_indexed_block(),
                        session.target_block(),
                        true,
                    )
                }
            } else if let Some(session) = artifact_session.as_ref() {
                (
                    WalletIndexedCatchUpSource::IndexedArtifacts,
                    session.latest_indexed_block(),
                    session.target_block(),
                    true,
                )
            } else {
                let Some(session) = self.probe_squid_indexed_wallet_source(cfg).await else {
                    self.record_public_scan_fallback(
                        self.rpc_scan_source_for_range(from_block),
                        PublicScanRange::new(from_block, safe_head),
                        self.begin_public_scan_read(),
                        "Squid unavailable for indexed wallet catch-up; falling back to RPC",
                    )
                    .await;
                    return last_scanned;
                };
                let height = session.indexed_height();
                squid_session = Some(session);
                (
                    WalletIndexedCatchUpSource::Squid,
                    height,
                    height.min(safe_head),
                    false,
                )
            };
        status_guard.set(indexed_source, from_block, target);
        let source_decision_read_scope = if using_artifact {
            artifact_session
                .as_ref()
                .expect("artifact session is configured for artifact catch-up")
                .read_scope()
        } else {
            squid_session
                .as_ref()
                .expect("Squid session is configured for Squid catch-up")
                .read_scope()
        };
        self.public_data_plane
            .record_source_decision(
                PublicDataPlaneDiagnosticKind::SourceSelected,
                indexed_source.into(),
                PublicScanRange::new(from_block, target),
                source_decision_read_scope,
                "indexed wallet catch-up source selected",
            )
            .await;
        info!(
            cache_key = %cfg.cache_key,
            indexed_source = indexed_source.as_str(),
            indexed_height,
            catch_up_ceiling = safe_head,
            from_block,
            target,
            indexed_block_range = self.chain.indexed_wallet_block_range,
            "indexed wallet catch-up target"
        );
        if from_block > target {
            let squid_tail = if using_artifact {
                self.probe_squid_tail_after_artifact(cfg, from_block, target, safe_head)
                    .await
            } else {
                None
            };
            if let Some((session, squid_target)) = squid_tail {
                let artifact_target = target;
                indexed_height = session.indexed_height();
                let squid_tail_read_scope = session.read_scope();
                squid_session = Some(session);
                artifact_session = None;
                using_artifact = false;
                indexed_source = WalletIndexedCatchUpSource::Squid;
                target = squid_target;
                status_guard.set(indexed_source, from_block, target);
                self.public_data_plane
                    .record_source_decision(
                        PublicDataPlaneDiagnosticKind::SourceFallback,
                        PublicScanSource::Squid,
                        PublicScanRange::new(from_block, target),
                        squid_tail_read_scope,
                        "artifact source exhausted before Squid tail",
                    )
                    .await;
                info!(
                    cache_key = %cfg.cache_key,
                    indexed_source = indexed_source.as_str(),
                    indexed_height,
                    safe_head,
                    from_block,
                    artifact_target,
                    target,
                    indexed_block_range = self.chain.indexed_wallet_block_range,
                    "indexed wallet artifact tail target"
                );
            } else {
                debug!(
                    cache_key = %cfg.cache_key,
                    elapsed_ms = catch_up_started.elapsed().as_millis(),
                    "indexed wallet catch-up skipped; cache already at target"
                );
                return last_scanned;
            }
        }
        let mut checkpoint = last_scanned;
        let target_result = handle
            .start_backfill(&cfg.cache_key, sender, progress, target)
            .await;
        let driver = match target_result {
            WalletBackfillStartResult::Accepted { grant, .. } => grant.activate(),
            WalletBackfillStartResult::Rejected { .. } => return checkpoint,
        };
        loop {
            if from_block > target {
                let squid_tail = if using_artifact {
                    self.probe_squid_tail_after_artifact(cfg, from_block, target, safe_head)
                        .await
                } else {
                    None
                };
                let Some((session, squid_target)) = squid_tail else {
                    break;
                };
                let artifact_target = target;
                indexed_height = session.indexed_height();
                let squid_tail_read_scope = session.read_scope();
                squid_session = Some(session);
                artifact_session = None;
                using_artifact = false;
                indexed_source = WalletIndexedCatchUpSource::Squid;
                target = squid_target;
                status_guard.set(indexed_source, from_block, target);
                self.public_data_plane
                    .record_source_decision(
                        PublicDataPlaneDiagnosticKind::SourceFallback,
                        PublicScanSource::Squid,
                        PublicScanRange::new(from_block, target),
                        squid_tail_read_scope,
                        "artifact source exhausted before Squid tail",
                    )
                    .await;
                info!(
                    cache_key = %cfg.cache_key,
                    indexed_source = indexed_source.as_str(),
                    indexed_height,
                    safe_head,
                    from_block,
                    artifact_target,
                    target,
                    indexed_block_range = self.chain.indexed_wallet_block_range,
                    "indexed wallet artifact tail target"
                );
                continue;
            }
            if cancel.is_cancelled() {
                driver.retire(&cfg.cache_key).await;
                return checkpoint;
            }
            let page_started = Instant::now();
            let page_kind =
                IndexedWalletPageKind::for_from_block(from_block, self.chain.v2_start_block);
            let to_block = page_kind.to_block(
                from_block,
                target,
                self.chain.v2_start_block,
                self.chain.indexed_wallet_block_range,
            );
            let fetch_started = Instant::now();
            let read_scope = if using_artifact {
                artifact_session
                    .as_ref()
                    .expect("artifact session is configured for artifact catch-up")
                    .read_scope()
            } else {
                squid_session
                    .as_ref()
                    .expect("Squid session is configured for Squid catch-up")
                    .read_scope()
            };
            let page_result = if using_artifact {
                artifact_session
                    .as_ref()
                    .expect("artifact session is configured for artifact catch-up")
                    .page_for_block_range(from_block, to_block)
            } else {
                IndexedWalletPage::fetch(
                    squid_session
                        .as_ref()
                        .expect("Squid session is configured for Squid catch-up")
                        .client(),
                    page_kind,
                    from_block,
                    to_block,
                )
                .await
                .map(IndexedWalletArtifactPageOutcome::Page)
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
                    if artifact_failure_can_fallback_to_squid(
                        using_artifact,
                        checkpoint,
                        last_scanned,
                    ) {
                        warn!(
                            ?err,
                            cache_key = %cfg.cache_key,
                            fallback_from = checkpoint,
                            "indexed wallet artifact page failed before checkpoint; falling back to Squid"
                        );
                        let Some(session) = self.probe_squid_indexed_wallet_source(cfg).await
                        else {
                            driver.retire(&cfg.cache_key).await;
                            return checkpoint;
                        };
                        indexed_height = session.indexed_height();
                        let fallback_read_scope = session.read_scope();
                        squid_session = Some(session);
                        artifact_session = None;
                        using_artifact = false;
                        indexed_source = WalletIndexedCatchUpSource::Squid;
                        target = indexed_height.min(safe_head);
                        status_guard.set(indexed_source, from_block, target);
                        self.public_data_plane
                            .record_source_decision(
                                PublicDataPlaneDiagnosticKind::SourceFallback,
                                PublicScanSource::Squid,
                                PublicScanRange::new(from_block, target),
                                fallback_read_scope,
                                "artifact page failed before checkpoint",
                            )
                            .await;
                        info!(
                            cache_key = %cfg.cache_key,
                            indexed_source = indexed_source.as_str(),
                            indexed_height,
                            safe_head,
                            from_block,
                            target,
                            indexed_block_range = self.chain.indexed_wallet_block_range,
                            "indexed wallet fallback target"
                        );
                        if from_block > target {
                            debug!(
                                cache_key = %cfg.cache_key,
                                indexed_source = indexed_source.as_str(),
                                indexed_height,
                                target,
                                elapsed_ms = catch_up_started.elapsed().as_millis(),
                                "indexed wallet fallback skipped; cache already at target"
                            );
                            driver.retire(&cfg.cache_key).await;
                            return checkpoint;
                        }
                        continue;
                    }
                    if !using_artifact
                        && source_order == IndexedWalletCatchUpSourceOrder::SquidFirst
                        && checkpoint == last_scanned
                    {
                        warn!(
                            ?err,
                            cache_key = %cfg.cache_key,
                            fallback_from = checkpoint,
                            "indexed wallet Squid page failed before checkpoint; falling back to artifacts"
                        );
                        status_guard.set(
                            WalletIndexedCatchUpSource::IndexedArtifacts,
                            from_block,
                            safe_head,
                        );
                        artifact_session = self
                            .prepare_indexed_wallet_artifact_session(
                                cfg,
                                from_block,
                                safe_head,
                                artifact_progress_tx,
                            )
                            .await;
                        let Some(session) = artifact_session.as_ref() else {
                            driver.retire(&cfg.cache_key).await;
                            return checkpoint;
                        };
                        squid_session = None;
                        using_artifact = true;
                        indexed_source = WalletIndexedCatchUpSource::IndexedArtifacts;
                        indexed_height = session.latest_indexed_block();
                        target = session.target_block();
                        status_guard.set(indexed_source, from_block, target);
                        self.public_data_plane
                            .record_source_decision(
                                PublicDataPlaneDiagnosticKind::SourceFallback,
                                PublicScanSource::IndexedArtifacts,
                                PublicScanRange::new(from_block, target),
                                artifact_session
                                    .as_ref()
                                    .expect("artifact session is configured for artifact catch-up")
                                    .read_scope(),
                                "Squid page failed before checkpoint",
                            )
                            .await;
                        info!(
                            cache_key = %cfg.cache_key,
                            indexed_source = indexed_source.as_str(),
                            indexed_height,
                            safe_head,
                            from_block,
                            target,
                            indexed_block_range = self.chain.indexed_wallet_block_range,
                            "indexed wallet fallback target"
                        );
                        if from_block > target {
                            debug!(
                                cache_key = %cfg.cache_key,
                                indexed_source = indexed_source.as_str(),
                                indexed_height,
                                target,
                                elapsed_ms = catch_up_started.elapsed().as_millis(),
                                "indexed wallet fallback skipped; cache already at target"
                            );
                            driver.retire(&cfg.cache_key).await;
                            return checkpoint;
                        }
                        continue;
                    }
                    warn!(
                        ?err,
                        cache_key = %cfg.cache_key,
                        indexed_source = indexed_source.as_str(),
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
                    return checkpoint;
                }
            };
            let fetch_elapsed_ms = fetch_started.elapsed().as_millis();
            if cancel.is_cancelled() {
                driver.retire(&cfg.cache_key).await;
                return checkpoint;
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
                indexed_source,
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
                return checkpoint;
            }
            let apply_result = driver.apply(&cfg.cache_key, apply).await;
            let Some(committed_checkpoint) = apply_result.accepted_committed_to() else {
                warn!(
                    ?apply_result,
                    cache_key = %cfg.cache_key,
                    from_block,
                    to_block = page_checkpoint,
                    "indexed wallet delta was not committed; using RPC backfill from committed cursor"
                );
                driver.retire(&cfg.cache_key).await;
                return checkpoint;
            };
            checkpoint = committed_checkpoint;
            debug!(
                cache_key = %cfg.cache_key,
                indexed_source = indexed_source.as_str(),
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
                status_guard.set(indexed_source, from_block, target);
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
        checkpoint
    }
}

pub(super) async fn await_live_log_task_shutdown(
    live_log_task: &Mutex<Option<JoinHandle<()>>>,
    chain_id: u64,
) {
    let live_log_task = live_log_task.lock().await.take();
    if let Some(task) = live_log_task
        && let Err(err) = task.await
        && !err.is_cancelled()
    {
        warn!(?err, chain_id, "live log worker failed during shutdown");
    }
}

pub(super) async fn wait_for_wallet_ready(
    mut observation_rx: watch::Receiver<WalletObservation>,
    cancel: CancellationToken,
) -> bool {
    loop {
        match observation_rx.borrow().readiness() {
            WalletReadiness::Ready => return !cancel.is_cancelled(),
            WalletReadiness::Shutdown => return false,
            WalletReadiness::Syncing | WalletReadiness::Failed(_) => {}
        }
        tokio::select! {
            () = cancel.cancelled() => return false,
            changed = observation_rx.changed() => {
                if changed.is_err() {
                    return false;
                }
            },
        }
    }
}

pub(super) async fn wait_for_startup_sync_target(
    mut safe_head_rx: watch::Receiver<u64>,
    sync_to_block: Option<u64>,
    current_target: u64,
    cancel: &CancellationToken,
) -> Option<u64> {
    if current_target > 0 || sync_to_block.is_some() {
        return Some(current_target);
    }
    loop {
        let safe_head = *safe_head_rx.borrow();
        if safe_head > 0 {
            return Some(wallet_sync_target(safe_head, sync_to_block));
        }
        tokio::select! {
            () = cancel.cancelled() => return None,
            changed = safe_head_rx.changed() => {
                if changed.is_err() {
                    return None;
                }
            },
        }
    }
}

async fn fetch_initial_head(
    chain: &ChainConfig,
    rpcs: &QueryRpcPool,
) -> Option<(ProviderHandle, u64, u64)> {
    let attempts = rpcs.len().max(3);
    for attempt in 0..attempts {
        let Some(rpc) = rpcs.random_provider() else {
            warn!(
                attempt,
                "no healthy rpc providers available for initial block number"
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
            continue;
        };
        match rpc.provider.get_block_number().await {
            Ok(head) => {
                let safe_head = head
                    .saturating_sub(chain.finality_depth)
                    .max(chain.deployment_block);
                return Some((rpc, head, safe_head));
            }
            Err(err) => {
                warn!(
                    ?err,
                    attempt,
                    rpc = rpc.url.as_str(),
                    "failed to fetch initial block number, retrying..."
                );
                rpcs.mark_bad_provider(&rpc);
                if attempt + 1 < attempts {
                    let backoff_power = match attempt {
                        0 => 0,
                        1 => 1,
                        _ => 2,
                    };
                    tokio::time::sleep(Duration::from_millis(500 * 2u64.pow(backoff_power))).await;
                }
            }
        }
    }
    None
}
