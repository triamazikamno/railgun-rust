use crate::chain::{
    IndexedWalletArtifactPageOutcome, IndexedWalletPage, IndexedWalletPageKind, JoinSet,
    WalletIndexedCatchUpSource, WalletStartupSyncCandidate, WalletStartupSyncStrategy,
    should_hedge_wallet_startup, wallet_startup_warm_from_block,
};

use super::{
    Arc, CancellationToken, ChainService, Instant, PublicDataPlaneDiagnosticKind, PublicScanRange,
    PublicScanSource, QuickSyncClient, RpcTargetPolicy, WalletConfig, WalletScanApply,
    WalletStartupSyncError, WalletSyncContext, debug, info, send_wallet_startup_events,
    wait_or_cancel, wallet_backfill_from_block, wallet_remote_target_before_cached_suffix, warn,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::chain) struct WalletShortStartupPlan {
    pub(super) acquisition: PublicScanRange,
    delivery: PublicScanRange,
}

impl WalletShortStartupPlan {
    pub(in crate::chain) fn new(
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

    pub(super) fn acquisition_prefix_before_delivery(self) -> Option<PublicScanRange> {
        let to_block = self.delivery.from_block.checked_sub(1)?;
        (self.acquisition.from_block <= to_block)
            .then(|| PublicScanRange::new(self.acquisition.from_block, to_block))
    }
}

impl ChainService {
    pub(super) async fn short_wallet_startup_sync(
        self: &Arc<Self>,
        ctx: WalletSyncContext<'_>,
        progress: crate::types::WalletSchedulableProgress,
        sync_target: u64,
        plan: Option<WalletShortStartupPlan>,
        cancel: &CancellationToken,
    ) -> bool {
        let WalletSyncContext {
            cfg, start_block, ..
        } = ctx;
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
            block_range = self.chain.sync.block_range,
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
                        err = %err.without_url(),
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
                    debug!(err = %err.without_url(), strategy = strategy.as_str(), cache_key = %cfg.cache_key, "wallet startup hedge loser candidate failed");
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
                    ctx,
                    progress,
                    sync_target,
                    plan,
                    candidate,
                    cancel,
                )
                .await;
            let sent = committed_progress.is_some();
            if let Some(progress) = committed_progress
                && follow_safe_head
            {
                self.enqueue_wallet_backfill(
                    ctx,
                    sync_target,
                    sync_target,
                    true,
                    progress,
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

    pub(super) async fn commit_and_deliver_short_startup_candidate(
        self: &Arc<Self>,
        ctx: WalletSyncContext<'_>,
        progress: crate::types::WalletSchedulableProgress,
        sync_target: u64,
        plan: WalletShortStartupPlan,
        candidate: WalletStartupSyncCandidate,
        cancel: &CancellationToken,
    ) -> Option<crate::types::WalletSchedulableProgress> {
        let WalletSyncContext {
            cfg,
            handle,
            backfill_sender,
            ..
        } = ctx;
        if cancel.is_cancelled() {
            return None;
        }
        let progress = handle.revalidate_schedulable_progress(progress)?;
        // Candidates acquire from the delivery start, or from the window start
        // when they reuse an exact cached prefix. Commit only what they hold.
        let acquisition = PublicScanRange::new(
            candidate
                .acquisition_applies
                .first()
                .map_or(plan.delivery.from_block, |apply| {
                    apply.from_block.min(plan.delivery.from_block)
                }),
            plan.acquisition.to_block,
        );
        if let Err(err) = self
            .public_data_plane
            .commit_completed_wallet_scan_acquisition(acquisition, &candidate.acquisition_applies)
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
        let delivered = send_wallet_startup_events(
            &cfg.cache_key,
            candidate.applies,
            Some(sync_target),
            progress,
            backfill_sender,
            handle,
        )
        .await;
        if delivered && let Some(prefix) = plan.acquisition_prefix_before_delivery() {
            self.start_public_scan_window_warm(prefix).await;
        }
        delivered.then_some(progress)
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

    pub(in crate::chain) async fn wallet_startup_rpc_candidate(
        self: Arc<Self>,
        cfg: &WalletConfig,
        plan: WalletShortStartupPlan,
        cancel: CancellationToken,
    ) -> Result<WalletStartupSyncCandidate, WalletStartupSyncError> {
        let started = Instant::now();
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
        let remote_to_block =
            wallet_remote_target_before_cached_suffix(sync_target, cached_suffix_from);
        let (mut fetched_applies, mut events) = if deliver_from_block <= remote_to_block {
            let fetched = self
                .fetch_wallet_rpc_backfill_events(
                    deliver_from_block,
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
            .sync
            .quick_sync_endpoint
            .clone()
            .ok_or(WalletStartupSyncError::Cancelled)?;
        let client = QuickSyncClient::with_http_client(endpoint, self.chain.http_client.clone());
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
        // Pages start at the delivery boundary. When the indexed height is
        // below it, no page is requested and the RPC tail covers the range.
        let target = probe.height.min(remote_target);
        let mut from_block = deliver_from_block;
        let mut checkpoint = from_block.saturating_sub(1);
        let mut acquisition_applies = cached_prefix.unwrap_or_default();
        let mut events = Vec::new();
        info!(
            cache_key = %cfg.cache_key,
            indexed_height = probe.height,
            sync_target,
            deliver_from_block,
            cached_suffix_from,
            remote_target,
            from_block,
            target,
            indexed_block_range = self.chain.sync.indexed_wallet_block_range,
            "indexed wallet hedge target"
        );

        while from_block <= target {
            if cancel.is_cancelled() {
                return Err(WalletStartupSyncError::Cancelled);
            }
            let read_scope = source_read_scope;
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
            let tail_from = checkpoint.saturating_add(1).max(deliver_from_block);
            let mut tail_events = self
                .fetch_wallet_rpc_backfill_events(
                    tail_from,
                    tail_from,
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

    pub(super) async fn wallet_startup_artifact_candidate(
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
        let deliver_from_block = plan.delivery.from_block;
        let sync_target = plan.acquisition.to_block;
        // Chunks are selected for the delivery range only. A selected chunk is
        // fetched whole even when it also covers blocks before the cursor, and
        // no chunk is fetched when the artifact target is below the range.
        let Some(session) = wait_or_cancel(
            cancel,
            self.prepare_indexed_wallet_artifact_session(
                cfg,
                deliver_from_block,
                sync_target,
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
                plan.delivery,
                read_scope,
                "short wallet startup hedge failed; attempting indexed artifacts",
            )
            .await;

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
        let mut from_block = deliver_from_block;
        let target = session.target_block().min(remote_target);
        let mut acquisition_applies = cached_prefix.unwrap_or_default();
        let mut events = Vec::new();
        while from_block <= target {
            if cancel.is_cancelled() {
                return Err(WalletStartupSyncError::Cancelled);
            }
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
            let delivery_from = from_block.max(deliver_from_block);
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
            let tail_from = target.saturating_add(1).max(deliver_from_block);
            let mut tail_events = self
                .fetch_wallet_rpc_backfill_events(
                    tail_from,
                    tail_from,
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
            delivery_from = deliver_from_block,
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
}
