use railgun_wallet::Utxo;

use crate::wallet::handle::WalletPrivateViewTicket;

use super::{
    AcceptedBackfillOwnerDropped, AcceptedIndexedJobOwnerDropped, Arc, BackfillEvent,
    BackfillRequest, CancellationToken, ChainPoiSubmitterHandle, ChainPublicDataPlane, DbStore,
    FixedBytes, FuturesUnordered, IndexedArtifactSourceConfig, Instant, LocalPoiStatusReader,
    MerkleForest, PendingOutputPoiContextIntent, PendingWalletReset, PoiCorpusRevision,
    PoiMaintenanceController, PoiRpcClient, RwLock, SharedLogBatch, WalletActorState,
    WalletBackfillDoneOutcome, WalletBackfillGrant, WalletBackfillRejectReason, WalletCacheError,
    WalletCacheStore, WalletCheckpointMutation, WalletConfig, WalletHandle,
    WalletLiveMetadataFlush, WalletPendingSpentMarkOutcome, WalletPersistState,
    WalletPoiJobTracker, WalletPoiRefreshSelection, WalletPoiRuntime,
    WalletPoiStatusRefreshCommitRequest, WalletPrivateApplyClient, WalletPrivateApplyRequest,
    WalletPrivateMutationAuthority, WalletPrivateRequest, WalletPrivateRequestError,
    WalletProgressPersist, WalletRemoteDone, WalletResetCommitOutcome, WalletResetCommitRequest,
    WalletResetReplayPlan, WalletResetRewindOutcome, WalletSyncToken, WalletUtxo,
    accepted_backfill_owner_dropped, apply_owned_poi_private_delta_on_actor_with_active_lists,
    broadcast, clear_local_pending_spent, commit_pending_output_contexts, debug, info,
    mark_local_pending_spent, mpsc, oneshot, persist_wallet_reset_replay_admission_with_token,
    reset_replay_from_block, wallet_poi_status_refresh_needed_for_selection, wallet_utxo_counts,
    warn, watch,
};

/// State and services the wallet actor task works with across loop iterations.
pub(super) struct WalletActorLoop<'a> {
    pub(super) cfg: WalletConfig,
    pub(super) cache_store: Arc<dyn WalletCacheStore>,
    pub(super) utxos: Arc<RwLock<Vec<WalletUtxo>>>,
    pub(super) worker_handle: WalletHandle,
    pub(super) cancel: CancellationToken,
    /// Borrowed because the task's public POI client borrows it for the whole loop.
    pub(super) poi_runtime: &'a WalletPoiRuntime,
    pub(super) public_data_plane: ChainPublicDataPlane,
    pub(super) active_poi_list_keys: Vec<FixedBytes<32>>,
    pub(super) actor_state: WalletActorState,
    pub(super) persist_state: WalletPersistState,
    pub(super) last_scanned: u64,
    pub(super) db: Arc<DbStore>,
    pub(super) poi_submitter: ChainPoiSubmitterHandle,
    /// Accepted jobs whose owners the actor watches so it can retire them.
    pub(super) accepted_backfill_liveness: FuturesUnordered<AcceptedBackfillOwnerDropped>,
    pub(super) accepted_indexed_job_liveness: FuturesUnordered<AcceptedIndexedJobOwnerDropped>,
    pub(super) live_metadata_flush: WalletLiveMetadataFlush,
    pub(super) readiness_started: Instant,
    pub(super) backfill_complete_block: Option<u64>,
    pub(super) backfill_sender: mpsc::Sender<BackfillEvent>,
    pub(super) backfill_tx: mpsc::Sender<BackfillRequest>,
    pub(super) poi_maintenance: PoiMaintenanceController,
    pub(super) remote_done_tx: mpsc::Sender<WalletRemoteDone>,
    pub(super) private_apply: WalletPrivateApplyClient,
    pub(super) poi_jobs: WalletPoiJobTracker,
    pub(super) poi_refreshing_tx: watch::Sender<bool>,
    pub(super) http_client: Option<reqwest::Client>,
    pub(super) indexed_artifact_source: Option<IndexedArtifactSourceConfig>,
    pub(super) forest: Arc<RwLock<MerkleForest>>,
    pub(super) worker_started: Instant,
    pub(super) last_poi_corpus_revision: PoiCorpusRevision,
    pub(super) blocked_shield_refresh_pending: bool,
    pub(super) poi_status_client: Option<&'a PoiRpcClient>,
}

/// What the pre-ready POI status refresh did, for the backfill completion log.
#[derive(Default)]
struct PreReadyPoiRefresh {
    status_changed: bool,
    rejection: Option<WalletBackfillRejectReason>,
    refresh_elapsed_ms: u128,
    local_cache_available: bool,
}

impl WalletActorLoop<'_> {
    /// Refreshes POI statuses from the local corpus when `selection` needs it.
    /// Returns `None` when no refresh was attempted.
    pub(super) async fn commit_local_poi_status_refresh(
        &mut self,
        selection: WalletPoiRefreshSelection,
    ) -> Option<Result<bool, WalletBackfillRejectReason>> {
        let reset_generation = self.actor_state.reset_generation();
        let refresh_needed = self
            .poi_status_refresh_needed(reset_generation, selection)
            .await;
        if refresh_needed {
            if let Some(status_reader) = self.local_poi_status_reader().await {
                Some(
                    self.commit_poi_status_refresh(&status_reader, reset_generation, selection)
                        .await,
                )
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Whether `selection` has POI statuses to refresh, or a failed refresh to retry.
    async fn poi_status_refresh_needed(
        &self,
        reset_generation: u64,
        selection: WalletPoiRefreshSelection,
    ) -> bool {
        let locked = self.utxos.read().await;
        self.actor_state
            .has_failed_poi_status_refresh(reset_generation, selection)
            || wallet_poi_status_refresh_needed_for_selection(
                &locked,
                &self.active_poi_list_keys,
                selection,
            )
    }

    /// Actor-safe: only a local corpus reader, never the remote proxy or fallback.
    async fn local_poi_status_reader(&self) -> Option<LocalPoiStatusReader> {
        self.poi_runtime
            .local_status_reader(
                &self.public_data_plane,
                &self.cfg,
                &self.active_poi_list_keys,
            )
            .await
    }

    async fn commit_poi_status_refresh(
        &mut self,
        status_reader: &LocalPoiStatusReader,
        reset_generation: u64,
        selection: WalletPoiRefreshSelection,
    ) -> Result<bool, WalletBackfillRejectReason> {
        WalletPoiStatusRefreshCommitRequest {
            cache_store: self.cache_store.as_ref(),
            cfg: &self.cfg,
            utxos: &self.utxos,
            worker_handle: &self.worker_handle,
            last_scanned: self.last_scanned,
            reset_generation,
            actor_state: &mut self.actor_state,
            persist_state: &mut self.persist_state,
            status_reader,
            active_poi_list_keys: &self.active_poi_list_keys,
            selection,
            cancel: &self.cancel,
        }
        .commit()
        .await
    }

    /// Reads the latest committed PPOI corpus revision and records what changed.
    fn observe_poi_corpus_revision(
        &mut self,
        revision_rx: &mut watch::Receiver<PoiCorpusRevision>,
    ) -> PoiCorpusRevision {
        let revision = *revision_rx.borrow_and_update();
        let _ =
            self.actor_state
                .transition_active(&self.worker_handle, &self.cancel, |mut state| {
                    state.observe_poi_corpus_revision(revision != self.last_poi_corpus_revision);
                });
        self.blocked_shield_refresh_pending |= revision.blocked_shields_revision
            != self.last_poi_corpus_revision.blocked_shields_revision;
        self.last_poi_corpus_revision = revision;
        revision
    }

    /// Finishes a backfill job: persists owed progress, refreshes POI statuses before
    /// the wallet reports ready, marks the backfill complete, then refreshes again and
    /// requests POI maintenance.
    pub(super) async fn apply_backfill_done(
        &mut self,
        poi_corpus_revision_rx: &mut Option<watch::Receiver<PoiCorpusRevision>>,
        last_block: u64,
        job_token: WalletSyncToken,
    ) -> WalletBackfillDoneOutcome {
        let current_reset_generation = self.actor_state.reset_generation();
        if let Err(reason) = self
            .persist_backfill_completion(current_reset_generation, job_token)
            .await
        {
            return WalletBackfillDoneOutcome::Rejected(reason);
        }
        let pre_ready = self
            .refresh_poi_statuses_before_ready(poi_corpus_revision_rx, current_reset_generation)
            .await;
        if let Some(reason) = pre_ready.rejection {
            return WalletBackfillDoneOutcome::Rejected(reason);
        }
        let snapshot = self.utxos.read().await;
        let (unspent, spent) = wallet_utxo_counts(&snapshot);
        self.backfill_complete_block = Some(last_block);
        info!(
            cache_key = %self.cfg.cache_key,
            last_scanned = self.last_scanned,
            total = snapshot.len(),
            unspent,
            spent,
            pre_ready_poi_status_changed = pre_ready.status_changed,
            pre_ready_local_cache_available = pre_ready.local_cache_available,
            pre_ready_poi_status_refresh_elapsed_ms = pre_ready.refresh_elapsed_ms,
            ready_elapsed_ms = self.readiness_started.elapsed().as_millis(),
            worker_elapsed_ms = self.worker_started.elapsed().as_millis(),
            "wallet backfill complete"
        );
        drop(snapshot);
        tokio::task::yield_now().await;

        if self.poi_status_client.is_some() {
            self.refresh_poi_statuses_after_ready(current_reset_generation)
                .await;
            let _ = self.request_poi_maintenance(false);
        }
        WalletBackfillDoneOutcome::Finished {
            poi_corpus_revision: poi_corpus_revision_rx
                .as_ref()
                .map(|_| self.last_poi_corpus_revision),
        }
    }

    /// Persists progress still owed by a full persist or cache reset, then records the
    /// backfill job's durable completion.
    async fn persist_backfill_completion(
        &mut self,
        current_reset_generation: u64,
        job_token: WalletSyncToken,
    ) -> Result<(), WalletBackfillRejectReason> {
        let should_persist = self.persist_state.needs_full_persist
            || self.persist_state.pending_cache_reset.is_some();
        let authority = WalletPrivateMutationAuthority::new(
            &self.worker_handle,
            current_reset_generation,
            &self.cancel,
        );
        let snapshot = self.utxos.read().await;
        let persist_result = if should_persist {
            match authority.acquire().await {
                Ok(permit) => match self.persist_state.persist_progress(
                    self.cache_store.as_ref(),
                    &permit,
                    WalletProgressPersist {
                        cache_key: &self.cfg.cache_key,
                        snapshot: &snapshot,
                        last_scanned: self.last_scanned,
                        checkpoint: WalletCheckpointMutation::Preserve,
                        changed: false,
                    },
                ) {
                    Ok(_) => {
                        self.live_metadata_flush
                            .mark_persisted(self.last_scanned, Instant::now());
                        Ok(())
                    }
                    Err(err) => {
                        warn!(?err, cache_key = %self.cfg.cache_key, "failed to update wallet cache metadata");
                        Err(WalletBackfillRejectReason::PersistenceFailed)
                    }
                },
                Err(reason) => {
                    warn!(?reason, cache_key = %self.cfg.cache_key, "wallet target metadata persist rejected");
                    Err(reason)
                }
            }
        } else {
            Ok(())
        };
        drop(snapshot);
        persist_result?;
        self.actor_state
            .transition_active(&self.worker_handle, &self.cancel, |mut state| {
                state.durable_backfill_completion_commit_ok(job_token)
            })?;
        Ok(())
    }

    /// Refreshes POI statuses from the local corpus before the wallet reports ready,
    /// rejecting completion when the PPOI corpus moved underneath the refresh.
    async fn refresh_poi_statuses_before_ready(
        &mut self,
        poi_corpus_revision_rx: &mut Option<watch::Receiver<PoiCorpusRevision>>,
        current_reset_generation: u64,
    ) -> PreReadyPoiRefresh {
        let mut pre_ready = PreReadyPoiRefresh::default();
        if self.poi_status_client.is_some() {
            if let Some(revision_rx) = poi_corpus_revision_rx.as_mut() {
                self.observe_poi_corpus_revision(revision_rx);
            }
            let refresh_revision = self.last_poi_corpus_revision;
            let pre_ready_selection = self.pre_ready_poi_refresh_selection();
            if self
                .poi_status_refresh_needed(current_reset_generation, pre_ready_selection)
                .await
            {
                self.commit_pre_ready_poi_refresh(
                    current_reset_generation,
                    pre_ready_selection,
                    &mut pre_ready,
                )
                .await;
            }
            if let Some(revision_rx) = poi_corpus_revision_rx.as_mut()
                && self.observe_poi_corpus_revision(revision_rx) != refresh_revision
            {
                pre_ready.rejection = Some(WalletBackfillRejectReason::ApplyFailed);
            }
            if pre_ready.rejection.is_none() {
                self.blocked_shield_refresh_pending = false;
                let _ = self.actor_state.transition_active(
                    &self.worker_handle,
                    &self.cancel,
                    |mut state| state.set_poi_corpus_refresh_pending(false),
                );
            }
        } else if self.blocked_shield_refresh_pending {
            pre_ready.rejection = Some(WalletBackfillRejectReason::ApplyFailed);
        }
        pre_ready
    }

    /// A pending blocked-shield change needs a corpus-revision refresh; otherwise the
    /// refresh covers required and recoverable statuses.
    const fn pre_ready_poi_refresh_selection(&self) -> WalletPoiRefreshSelection {
        if self.blocked_shield_refresh_pending {
            WalletPoiRefreshSelection::CorpusRevision {
                blocked_shields_changed: true,
            }
        } else {
            WalletPoiRefreshSelection::RequiredOrRecoverable
        }
    }

    async fn commit_pre_ready_poi_refresh(
        &mut self,
        current_reset_generation: u64,
        selection: WalletPoiRefreshSelection,
        pre_ready: &mut PreReadyPoiRefresh,
    ) {
        if let Some(status_reader) = self.local_poi_status_reader().await {
            pre_ready.local_cache_available = true;
            let status_refresh_started = Instant::now();
            match self
                .commit_poi_status_refresh(&status_reader, current_reset_generation, selection)
                .await
            {
                Ok(changed) => {
                    pre_ready.status_changed = changed;
                }
                Err(reason) => {
                    warn!(?reason, cache_key = %self.cfg.cache_key, "pre-ready wallet POI status refresh rejected");
                    pre_ready.rejection = Some(reason);
                }
            }
            pre_ready.refresh_elapsed_ms = status_refresh_started.elapsed().as_millis();
            debug!(
                cache_key = %self.cfg.cache_key,
                changed = pre_ready.status_changed,
                status_refresh_elapsed_ms = pre_ready.refresh_elapsed_ms,
                "pre-ready wallet POI status refresh visible"
            );
            tokio::task::yield_now().await;
        } else if self.blocked_shield_refresh_pending {
            pre_ready.rejection = Some(WalletBackfillRejectReason::ApplyFailed);
        }
    }

    async fn refresh_poi_statuses_after_ready(&mut self, current_reset_generation: u64) {
        let post_ready_selection = WalletPoiRefreshSelection::RequiredOrRecoverable;
        if self
            .poi_status_refresh_needed(current_reset_generation, post_ready_selection)
            .await
            && let Some(status_reader) = self.local_poi_status_reader().await
        {
            match self
                .commit_poi_status_refresh(
                    &status_reader,
                    current_reset_generation,
                    post_ready_selection,
                )
                .await
            {
                Ok(changed) => {
                    debug!(
                        cache_key = %self.cfg.cache_key,
                        changed,
                        "post-ready local wallet POI status refresh committed"
                    );
                }
                Err(reason) => {
                    warn!(?reason, cache_key = %self.cfg.cache_key, "post-ready wallet POI status refresh rejected");
                }
            }
        }
    }

    /// Drives a pending wallet reset: commits its rewind and, with `admit_replay`,
    /// admits its replay and retires the durable replay plan. Returns `None` when
    /// no reset is pending.
    pub(super) async fn try_drive_pending_reset(
        &mut self,
        live_rx: &mut broadcast::Receiver<SharedLogBatch>,
        admit_replay: bool,
    ) -> Option<WalletResetCommitOutcome> {
        let pending = self.actor_state.pending_reset()?;
        let rewind_was_pending = !self.actor_state.pending_reset_rewind_committed();
        let outcome = if self.actor_state.pending_reset_rewind_committed() {
            WalletResetCommitOutcome {
                rewind: WalletResetRewindOutcome::Committed {
                    committed_to: self.last_scanned,
                },
            }
        } else {
            WalletResetCommitRequest {
                cache_store: self.cache_store.as_ref(),
                cfg: &self.cfg,
                utxos: &self.utxos,
                worker_handle: &self.worker_handle,
                pending,
                highest_accepted_reset_intent: self.actor_state.highest_accepted_reset_intent(),
                actor_state: &mut self.actor_state,
                cancel: &self.cancel,
                last_scanned: &mut self.last_scanned,
                persist_state: &mut self.persist_state,
                live_metadata_flush: &mut self.live_metadata_flush,
            }
            .commit()
            .await
        };
        if outcome.rewind.committed() {
            if rewind_was_pending {
                self.readiness_started = Instant::now();
                self.backfill_complete_block = None;
                *live_rx = live_rx.resubscribe();
            }

            if admit_replay && self.actor_state.pending_reset_replay_admitted().is_none() {
                self.admit_pending_reset_replay(pending);
            }

            if admit_replay && self.actor_state.pending_reset_replay_admitted().is_some() {
                self.retire_pending_reset_replay_plan(pending).await;
            }
        }
        Some(outcome)
    }

    /// Accepts the reset's replay target and records whether its replay was admitted.
    fn admit_pending_reset_replay(&mut self, pending: PendingWalletReset) {
        let replay_plan = pending.replay_plan();
        let replay_from = reset_replay_from_block(self.last_scanned, replay_plan.start_block);
        let token = self
            .worker_handle
            .mint_sync_token(self.actor_state.reset_generation());
        let accepted = self
            .actor_state
            .transition_active(&self.worker_handle, &self.cancel, |mut state| {
                state.accept_target(token, replay_plan.target_block)
            })
            .unwrap_or(false);
        let admitted = if !accepted {
            false
        } else if replay_plan.target_block > 0 && replay_from > replay_plan.target_block {
            let _ = self.actor_state.transition_active(
                &self.worker_handle,
                &self.cancel,
                |mut state| state.complete_backfill_job(token),
            );
            self.backfill_complete_block = self.actor_state.completed_target_block();
            true
        } else {
            self.dispatch_reset_replay_backfill(token, replay_from, replay_plan)
        };
        let _ =
            self.actor_state
                .transition_active(&self.worker_handle, &self.cancel, |mut state| {
                    state.set_pending_reset_replay_admitted(
                        admitted.then_some((token, replay_from)),
                    );
                });
    }

    /// Hands the reset replay to the backfill loop as an accepted job.
    /// Returns whether the backfill loop took it.
    fn dispatch_reset_replay_backfill(
        &mut self,
        token: WalletSyncToken,
        replay_from: u64,
        replay_plan: WalletResetReplayPlan,
    ) -> bool {
        let (liveness, receiver) = oneshot::channel();
        self.accepted_backfill_liveness
            .push(accepted_backfill_owner_dropped(token, receiver));
        let driver = WalletBackfillGrant::for_actor_accepted_job_with_cancel(
            token,
            self.backfill_sender.clone(),
            liveness,
            self.cancel.clone(),
        )
        .activate();
        let request = BackfillRequest::add(
            self.cfg.cache_key.clone(),
            replay_from,
            replay_plan.target_block,
            replay_plan.follow_safe_head,
            replay_from,
            driver,
        );
        match self.backfill_tx.try_send(request) {
            Ok(()) => {
                let _ = self.actor_state.transition_active(
                    &self.worker_handle,
                    &self.cancel,
                    |mut state| state.backfill_dispatch_admitted(token),
                );
                true
            }
            Err(err) => {
                warn!(?err, cache_key = %self.cfg.cache_key, replay_from, target_block = replay_plan.target_block, "wallet reset replay enqueue failed");
                let _ = self.actor_state.transition_active(
                    &self.worker_handle,
                    &self.cancel,
                    |mut state| {
                        state.fail_job_backfill_unavailable(token);
                    },
                );
                false
            }
        }
    }

    /// Persists that the reset replay was admitted and clears the pending reset.
    async fn retire_pending_reset_replay_plan(&mut self, pending: PendingWalletReset) {
        let authority = WalletPrivateMutationAuthority::new(
            &self.worker_handle,
            self.actor_state.reset_generation(),
            &self.cancel,
        );
        match authority.acquire().await {
            Ok(permit) => {
                let persist_result = permit.with_active_apply(|token| {
                    persist_wallet_reset_replay_admission_with_token(
                        &token,
                        &permit,
                        self.cache_store.as_ref(),
                        &self.cfg,
                        self.actor_state.highest_accepted_reset_intent(),
                    )?;
                    self.actor_state.transition(&token, |mut state| {
                        state.durable_reset_replay_commit_ok(pending.intent_id());
                        state.clear_pending_reset();
                    });
                    Ok::<(), WalletCacheError>(())
                });
                match persist_result {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        warn!(?err, cache_key = %self.cfg.cache_key, intent_id = pending.intent_id(), "failed to retire durable wallet reset replay plan");
                        let _ = permit.with_active_apply(|token| {
                            self.actor_state.transition(&token, |mut state| {
                                state.reset_replay_persist_failed(pending.intent_id());
                            });
                        });
                    }
                    Err(reason) => {
                        debug!(?reason, cache_key = %self.cfg.cache_key, intent_id = pending.intent_id(), "wallet reset replay-plan retirement rejected");
                    }
                }
            }
            Err(reason) => {
                debug!(?reason, cache_key = %self.cfg.cache_key, intent_id = pending.intent_id(), "wallet reset replay-plan retirement skipped");
            }
        }
    }

    /// Commits a private POI delta that a remote job sent back to the actor.
    pub(super) async fn handle_private_apply(&self, apply_req: WalletPrivateApplyRequest) {
        let WalletPrivateApplyRequest {
            reset_generation,
            delta,
            reply,
        } = apply_req;
        let result = apply_owned_poi_private_delta_on_actor_with_active_lists(
            &self.worker_handle,
            &self.cancel,
            reset_generation,
            self.db.as_ref(),
            self.cache_store.as_ref(),
            &self.cfg,
            &self.active_poi_list_keys,
            delta,
        )
        .await;
        let _ = reply.send(result);
    }

    /// Answers a private-state request from a wallet handle.
    pub(super) async fn handle_private_request(&self, request: WalletPrivateRequest) {
        match request {
            WalletPrivateRequest::MarkLocalPendingSpent {
                utxos,
                tx_hash,
                reply,
            } => {
                self.handle_mark_local_pending_spent(utxos, tx_hash, reply)
                    .await;
            }
            WalletPrivateRequest::ClearLocalPendingSpent { reply } => {
                self.handle_clear_local_pending_spent(reply).await;
            }
            WalletPrivateRequest::CreatePendingOutputContexts {
                ticket,
                contexts,
                reply,
            } => {
                self.handle_create_pending_output_contexts(ticket, contexts, reply)
                    .await;
            }
        }
    }

    async fn handle_mark_local_pending_spent(
        &self,
        utxos: Vec<Utxo>,
        tx_hash: Option<FixedBytes<32>>,
        reply: oneshot::Sender<Result<WalletPendingSpentMarkOutcome, WalletPrivateRequestError>>,
    ) {
        let result = match self
            .actor_state
            .validate_pending_overlay_request(&self.worker_handle, &self.cancel)
        {
            Ok(reset_generation) => {
                mark_local_pending_spent(
                    &self.worker_handle,
                    &self.cancel,
                    reset_generation,
                    utxos,
                    tx_hash,
                )
                .await
            }
            Err(err) => Err(err),
        };
        let _ = reply.send(result);
    }

    async fn handle_clear_local_pending_spent(
        &self,
        reply: oneshot::Sender<Result<bool, WalletPrivateRequestError>>,
    ) {
        let result = match self
            .actor_state
            .validate_pending_overlay_request(&self.worker_handle, &self.cancel)
        {
            Ok(reset_generation) => {
                clear_local_pending_spent(&self.worker_handle, &self.cancel, reset_generation).await
            }
            Err(err) => Err(err),
        };
        let _ = reply.send(result);
    }

    async fn handle_create_pending_output_contexts(
        &self,
        ticket: WalletPrivateViewTicket,
        contexts: Vec<PendingOutputPoiContextIntent>,
        reply: oneshot::Sender<Result<usize, WalletPrivateRequestError>>,
    ) {
        let result = match self.actor_state.validate_private_request(
            &self.worker_handle,
            &self.cancel,
            ticket,
            self.last_scanned,
            false,
        ) {
            Ok(reset_generation) => {
                commit_pending_output_contexts(
                    &self.worker_handle,
                    &self.cancel,
                    self.db.as_ref(),
                    self.cache_store.as_ref(),
                    &self.cfg,
                    reset_generation,
                    &self.active_poi_list_keys,
                    &self.poi_submitter,
                    &contexts,
                )
                .await
            }
            Err(err) => Err(err),
        };
        let _ = reply.send(result);
    }
}
