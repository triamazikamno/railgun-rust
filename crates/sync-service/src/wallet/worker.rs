use super::handle::LOCAL_PENDING_SPENT_TTL;
use super::pending_output_poi::pending_output_poi_handoff_context;
use super::{
    Arc, AtomicU64, BackfillEvent, CancellationToken, ChainError, ChainPublicDataPlane, DbStore,
    DeferredForcedSubmissions, Duration, FixedBytes, FuturesUnordered, HashSet,
    IndexedArtifactSourceConfig, Instant, Instrument, LocalPoiStatusReader, MerkleForest, Mutex,
    OutputPoiRecoveryRun, PendingOutputPoiContextIntent, PendingOutputPoiTentativeAttemptKey,
    PendingOutputPoiTentativeCandidate, PendingOutputPoiTentativeLocalStatus, PendingWalletReset,
    PoiMaintenanceController, PoiMaintenanceError, PoiProxyFallback, PoiRemoteJobKey, PoiRpcClient,
    PoiStatusReader, PublicPoiCorpusHandle, PublicPoiCorpusKey, RwLock,
    SenderCandidateRecoveryReport, SenderUnshieldAttempts, SharedLogBatch, SyncProgressStage,
    SyncProgressUpdate, WALLET_POI_REFRESH_INTERVAL, WalletActorCommitToken, WalletActorCredential,
    WalletActorLifecycleCell, WalletActorState, WalletBackfillApplyResult,
    WalletBackfillFinishResult, WalletBackfillGrant, WalletBackfillOwnerDisposition,
    WalletBackfillOwnerSignal, WalletBackfillRejectReason, WalletBackfillResetResult,
    WalletBackfillStartResult, WalletCacheError, WalletCacheStore, WalletCheckpointMutation,
    WalletConfig, WalletCurrentSnapshot, WalletHandle, WalletInactiveReason,
    WalletIndexedCatchUpCommand, WalletIndexedCatchUpLease, WalletLiveMetadataFlush,
    WalletLogDelta, WalletObservationPublisher, WalletPendingOverlay, WalletPendingOverlayUpdate,
    WalletPendingResetRecord, WalletPendingSpent, WalletPendingSpentMarkOutcome,
    WalletPersistState, WalletPoiRefreshSelection, WalletPoiRuntime, WalletPrivateApplyClient,
    WalletPrivateApplyRequest, WalletPrivateCommit, WalletPrivateMutationAuthority,
    WalletPrivateMutationPermit, WalletPrivatePoiClients, WalletPrivateRequest,
    WalletPrivateRequestError, WalletProgressPersist, WalletProgressPrivateEffects,
    WalletReadinessError, WalletRemoteDone, WalletResetReplayPlan, WalletResetRewindStatus,
    WalletScanApply, WalletScanRowsPayload, WalletSyncActorStateCommit, WalletSyncActorStateRecord,
    WalletSyncToken, WalletUtxo, WalletUtxoMutation, WalletViewState, WalletWorkerServices,
    apply_owned_poi_private_delta_on_actor_with_active_lists,
    apply_wallet_delta_to_vec_with_outcome, broadcast, chain_pending_overlay_matches, debug,
    default_active_poi_list_keys, force_resubmit_matching_pending_output_pois_authorized, info,
    mark_valid_output_poi_recoveries_authorized, mpsc, now_epoch_secs, oneshot,
    pending_output_poi_observation_state_updates, pending_output_poi_rewind_state_updates,
    pending_overlay_from_delta, prepare_pending_output_poi_tentative_candidates,
    process_pending_output_poi_observations_authorized,
    read_pending_output_poi_tentative_local_statuses,
    refresh_wallet_poi_statuses_remote_authorized, refresh_wallet_poi_statuses_selected,
    rewind_wallet_utxos, sender_transaction_candidate_rewind_ids,
    submit_pending_output_poi_tentative_candidates,
    verify_submitted_pending_output_pois_with_config_authorized, wallet_poi_status_refresh_needed,
    wallet_poi_status_refresh_needed_for_selection, wallet_ppoi_workflow_status_after_mutations,
    wallet_utxo_stable_identity, warn, watch,
};
use crate::PublicScanSource;
use crate::chain::ChainPoiSubmitterHandle;
use crate::types::BackfillRequest;
use crate::types::{PoiCorpusRevision, WalletSyncTargetLease};
use futures::{FutureExt, StreamExt};
use std::collections::{BTreeMap, BTreeSet};
use std::panic::AssertUnwindSafe;
use tokio::task::{JoinHandle, JoinSet};

mod commit;
mod local_pending_spent;
mod output_poi;
mod poi_maintenance;

use commit::{
    WALLET_RESET_RETRY_INTERVAL, WalletBackfillDoneOutcome, WalletPoiStatusRefreshCommitRequest,
    WalletResetCommitOutcome, WalletResetCommitRequest, WalletResetRewindOutcome,
    WalletScanCommitRequest, accepted_backfill_owner_dropped, accepted_indexed_job_owner_dropped,
    persist_wallet_reset_acceptance_with_token, persist_wallet_reset_replay_admission_with_token,
    reset_replay_from_block, reset_result_after_accept, signal_restored_reset_attempt,
    validate_restored_pending_reset,
};
use local_pending_spent::{
    clear_local_pending_spent, expire_local_pending_spent, mark_local_pending_spent,
    prune_local_pending_spent, wait_for_local_pending_spent_expiry,
};
use output_poi::{
    PendingOutputPoiTentativeAttemptTracker, commit_pending_output_contexts,
    refresh_tentative_pending_output_poi_statuses, spawn_pending_output_poi_tentative_job,
};
use poi_maintenance::{
    current_ppoi_workflow_status_for_candidate_report, next_poi_corpus_revision,
    on_poi_maintenance_done, request_poi_maintenance, wallet_poi_refresh_interval,
};

const fn wallet_private_request_error(
    reason: &WalletBackfillRejectReason,
) -> WalletPrivateRequestError {
    match reason {
        WalletBackfillRejectReason::Shutdown => WalletPrivateRequestError::Inactive,
        WalletBackfillRejectReason::PersistenceFailed => {
            WalletPrivateRequestError::PersistenceFailed
        }
        WalletBackfillRejectReason::StaleGeneration { .. }
        | WalletBackfillRejectReason::StaleResetIntent { .. }
        | WalletBackfillRejectReason::StaleDataPlaneEpoch { .. }
        | WalletBackfillRejectReason::NonContiguous { .. }
        | WalletBackfillRejectReason::ApplyFailed
        | WalletBackfillRejectReason::TargetNotReached { .. }
        | WalletBackfillRejectReason::TargetExceeded { .. } => WalletPrivateRequestError::StaleView,
    }
}

pub(crate) struct PreparedWalletWorker {
    handle: Option<WalletHandle>,
    has_restored_pending_reset: bool,
    cancel: CancellationToken,
    activation_tx: Option<oneshot::Sender<()>>,
    worker: Option<JoinHandle<()>>,
    observation: Arc<WalletObservationPublisher>,
}

impl PreparedWalletWorker {
    pub(crate) const fn has_restored_pending_reset(&self) -> bool {
        self.has_restored_pending_reset
    }

    pub(crate) const fn handle(&self) -> &WalletHandle {
        self.handle
            .as_ref()
            .expect("prepared wallet worker must own its handle")
    }

    pub(crate) const fn take_worker(&mut self) -> JoinHandle<()> {
        self.worker
            .take()
            .expect("prepared wallet worker must own its completion handle")
    }

    pub(crate) fn observation_publisher(&self) -> Arc<WalletObservationPublisher> {
        Arc::clone(&self.observation)
    }

    pub(crate) fn activate(mut self) -> Result<WalletHandle, ChainError> {
        if self.worker.is_some() {
            return Err(ChainError::WalletResetFailed);
        }
        if !self.handle().activate_actor() {
            return Err(ChainError::WalletResetFailed);
        }
        if self
            .activation_tx
            .take()
            .expect("prepared wallet worker must own its activation sender")
            .send(())
            .is_err()
        {
            return Err(ChainError::WalletResetFailed);
        }
        let handle = self
            .handle
            .take()
            .expect("prepared wallet worker must own its handle");
        Ok(handle)
    }
}

impl Drop for PreparedWalletWorker {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.retire_actor_with_publisher(&self.observation);
            self.cancel.cancel();
        }
    }
}

/// Background POI jobs started by the wallet actor.
///
/// The worker's supervising task owns the set, so it outlives the actor task even when the actor
/// panics. Once the actor task ends, the supervisor aborts every job still running and waits for
/// each to terminate, releasing the jobs' data-plane and runtime-lease clones.
#[derive(Clone, Default)]
struct WalletPoiJobTracker {
    jobs: Arc<std::sync::Mutex<JoinSet<()>>>,
}

impl WalletPoiJobTracker {
    fn spawn(&self, job: impl std::future::Future<Output = ()> + Send + 'static) {
        let mut jobs = self
            .jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Reap finished jobs so the set stays bounded by the jobs still running.
        while jobs.try_join_next().is_some() {}
        jobs.spawn(job);
    }

    /// Aborts every tracked job and waits for each to terminate. Called by the supervisor after
    /// the actor task ends; the actor is the only spawner, so no job is added afterwards.
    async fn shutdown(&self) {
        let mut jobs = std::mem::take(
            &mut *self
                .jobs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        jobs.shutdown().await;
    }
}

pub(crate) async fn prepare_wallet_worker(
    services: WalletWorkerServices,
    cfg: WalletConfig,
    actor_id: u64,
    mut live_rx: broadcast::Receiver<SharedLogBatch>,
    mut backfill_rx: mpsc::Receiver<BackfillEvent>,
    cancel: CancellationToken,
    initial_utxos: Vec<WalletUtxo>,
    initial_last_scanned: u64,
) -> Result<PreparedWalletWorker, ChainError> {
    let utxos = Arc::new(RwLock::new(initial_utxos));
    let pending_overlay = Arc::new(RwLock::new(WalletPendingOverlay::default()));
    let last_scanned_state = Arc::new(AtomicU64::new(initial_last_scanned));
    let next_sync_job_id = Arc::new(AtomicU64::new(1));
    let active_actor_id = Arc::new(AtomicU64::new(actor_id));
    let authority_lock = Arc::new(Mutex::new(()));
    let WalletWorkerServices {
        db,
        http_client,
        indexed_artifact_source,
        poi_runtime,
        forest,
        backfill_tx,
        backfill_sender,
        public_data_plane,
        poi_submitter,
    } = services;
    let mut poi_corpus_handle = None;
    let mut last_poi_corpus_revision = PoiCorpusRevision::default();
    let mut blocked_shield_refresh_pending = false;
    let mut poi_corpus_revision_rx = if poi_runtime.is_indexed_artifacts() {
        let corpus = public_data_plane
            .ensure_poi_corpus(PublicPoiCorpusKey::wallet_default(cfg.chain.chain_id))
            .await
            .map_err(ChainError::from)?;
        poi_corpus_handle = Some(corpus.clone());
        let mut revision_rx = corpus.committed_revision_rx();
        last_poi_corpus_revision = *revision_rx.borrow_and_update();
        blocked_shield_refresh_pending = last_poi_corpus_revision.revision > 0;
        Some(revision_rx)
    } else {
        None
    };
    let cache_store = wallet_cache_store(&db, &cfg);
    let active_poi_list_keys = default_active_poi_list_keys();
    let initial_ppoi_workflow_projection = wallet_ppoi_workflow_status_after_mutations(
        cache_store.as_ref(),
        &cfg,
        &active_poi_list_keys,
        0,
        &[],
        &[],
        &[],
        &[],
        &[],
        &[],
    )?;
    let restored_sync_state =
        cache_store.get_wallet_sync_actor_state(cfg.chain.chain_id, &cfg.cache_key)?;
    let restored_pending_reset = restored_sync_state
        .as_ref()
        .and_then(|state| state.pending_reset.as_ref())
        .map(|pending| {
            PendingWalletReset::new(
                pending.intent_id,
                pending.from_block,
                1,
                WalletResetReplayPlan::new(
                    pending.replay_start_block,
                    pending.replay_target_block,
                    pending.follow_safe_head,
                ),
            )
        });
    if let Some(pending) = restored_pending_reset {
        validate_restored_pending_reset(&cfg, initial_last_scanned, pending)?;
    }
    let has_restored_pending_reset = restored_pending_reset.is_some();
    let restored_highest_reset_intent = restored_sync_state
        .as_ref()
        .map_or(0, |state| state.highest_accepted_reset_intent);
    let initial_reset_generation = u64::from(restored_pending_reset.is_some());
    let reset_generation_state = Arc::new(AtomicU64::new(initial_reset_generation));
    let initial_view = if let Some(pending) = &restored_pending_reset {
        WalletViewState::ResetPending {
            intent_id: pending.intent_id(),
            from_block: pending.rewind_from_block(),
            reset_generation: pending.reset_generation(),
        }
    } else {
        let initial_utxos = utxos
            .try_read()
            .map(|guard| guard.clone())
            .unwrap_or_default();
        WalletViewState::Current(WalletCurrentSnapshot::new(
            initial_last_scanned,
            0,
            initial_reset_generation,
            Arc::<[WalletUtxo]>::from(initial_utxos),
            Arc::new(WalletPendingOverlay::default()),
        ))
    };
    let (actor_state, observation_rx) = WalletActorState::new(
        cfg.chain.chain_id,
        actor_id,
        initial_reset_generation,
        initial_last_scanned,
        restored_highest_reset_intent,
        restored_pending_reset,
        blocked_shield_refresh_pending,
        initial_view,
    );
    let observation = actor_state.observation_publisher();
    observation.publish_ppoi_workflow_projection(
        initial_ppoi_workflow_projection.status,
        initial_ppoi_workflow_projection.submissions,
    );
    let (rev_tx, rev_rx) = watch::channel(0_u64);
    let (reset_generation_tx, reset_generation_rx) = watch::channel(initial_reset_generation);
    let (poi_refresh_tx, mut poi_refresh_rx) = mpsc::channel(1);
    let (pending_overlay_tx, mut pending_overlay_rx) = mpsc::channel(8);
    let (private_request_tx, mut private_request_rx) = mpsc::channel(8);
    let (indexed_catch_up_status_tx, mut indexed_catch_up_status_rx) = mpsc::unbounded_channel();
    let (poi_refreshing_tx, poi_refreshing_rx) = watch::channel(false);
    let (indexed_catch_up_tx, indexed_catch_up_rx) = watch::channel(None);
    let handle = WalletHandle {
        cache_key: cfg.cache_key.clone(),
        chain: cfg.chain,
        actor_id,
        active_actor_id,
        lifecycle: Arc::new(WalletActorLifecycleCell::new_prepared()),
        authority_lock,
        utxos: utxos.clone(),
        pending_overlay,
        last_scanned: last_scanned_state,
        reset_generation: reset_generation_state,
        reset_generation_rx,
        next_sync_job_id,
        observation: Arc::downgrade(&observation),
        observation_rx,
        rev_rx,
        poi_refreshing_rx,
        indexed_catch_up_rx,
        pending_overlay_tx,
        private_request_tx,
        poi_refresh_tx,
        indexed_catch_up_status_tx,
        rev_tx,
        reset_generation_tx,
        indexed_catch_up_tx,
    };
    let (startup_replay_tx, startup_replay_rx) = if restored_pending_reset.is_some() {
        let (tx, rx) = oneshot::channel();
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    let (activation_tx, activation_rx) = oneshot::channel();

    let chain_id = cfg.chain.chain_id;
    let worker_handle = handle.clone();
    let worker_panic_handle = handle.clone();
    let worker_observation = Arc::clone(&observation);
    let maintenance_observation = Arc::clone(&observation);
    let worker_cache_key = cfg.cache_key.clone();
    let prepared_cancel = cancel.clone();
    let poi_jobs = WalletPoiJobTracker::default();
    let supervisor_poi_jobs = poi_jobs.clone();
    let actor_worker = tokio::spawn(async move {
        let mut startup_replay_tx = startup_replay_tx;
        let worker_started = Instant::now();
        let mut last_scanned = initial_last_scanned;
        let snapshot = utxos.read().await;
        let (unspent, spent) = wallet_utxo_counts(&snapshot);
        info!(
            cache_key = %cfg.cache_key,
            total = snapshot.len(),
            unspent,
            spent,
            last_scanned,
            "loaded wallet cache"
        );
        drop(snapshot);

        let mut backfill_complete_block: Option<u64> = None;
        let mut live_receiver_lagged = false;
        let mut persist_state = WalletPersistState::default();
        let mut live_metadata_flush = WalletLiveMetadataFlush::new(last_scanned, worker_started);
        let poi_status_client = Some(poi_runtime.public_client());
        let mut pending_reset_retry = tokio::time::interval_at(
            tokio::time::Instant::now() + WALLET_RESET_RETRY_INTERVAL,
            WALLET_RESET_RETRY_INTERVAL,
        );
        pending_reset_retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut poi_status_refresh_interval = wallet_poi_refresh_interval();
        if poi_status_client.is_some() {
            let locked = utxos.read().await;
            debug!(
                cache_key = %cfg.cache_key,
                poi_refresh_needed = wallet_poi_status_refresh_needed(&locked, &active_poi_list_keys),
                "startup wallet POI status refresh will run after backfill if needed"
            );
        }

        let mut readiness_started = worker_started;
        let (remote_done_tx, mut remote_done_rx) = mpsc::channel::<WalletRemoteDone>(8);
        // Jobs re-enter here for private POI commits; actor is sole UTXO mirror writer.
        let (private_apply_tx, mut private_apply_rx) =
            mpsc::channel::<WalletPrivateApplyRequest>(32);
        let private_apply = WalletPrivateApplyClient::new(private_apply_tx);
        let mut poi_maintenance = PoiMaintenanceController::new();
        // Tentative attempts are actor-lifetime only; safe-head maintenance never consults this set.
        let mut pending_output_poi_tentative_attempts =
            PendingOutputPoiTentativeAttemptTracker::default();
        let mut actor_state = actor_state;
        let mut accepted_backfill_liveness = FuturesUnordered::new();
        let mut accepted_indexed_job_liveness = FuturesUnordered::new();
        macro_rules! commit_local_poi_status_refresh {
            ($selection:expr) => {{
                let selection = $selection;
                let reset_generation = actor_state.reset_generation();
                let refresh_needed = {
                    let locked = utxos.read().await;
                    actor_state.has_failed_poi_status_refresh(reset_generation, selection)
                        || wallet_poi_status_refresh_needed_for_selection(
                            &locked,
                            &active_poi_list_keys,
                            selection,
                        )
                };
                if refresh_needed {
                    if let Some(status_reader) = poi_runtime
                        .local_status_reader(&public_data_plane, &cfg, &active_poi_list_keys)
                        .await
                    {
                        Some(
                            (WalletPoiStatusRefreshCommitRequest {
                                cache_store: cache_store.as_ref(),
                                cfg: &cfg,
                                utxos: &utxos,
                                worker_handle: &worker_handle,
                                last_scanned,
                                reset_generation,
                                actor_state: &mut actor_state,
                                persist_state: &mut persist_state,
                                status_reader: &status_reader,
                                active_poi_list_keys: &active_poi_list_keys,
                                selection,
                                cancel: &cancel,
                            })
                            .commit()
                            .await,
                        )
                    } else {
                        None
                    }
                } else {
                    None
                }
            }};
        }
        macro_rules! try_drive_pending_reset {
            ($admit_replay:expr) => {{
                if let Some(pending) = actor_state.pending_reset() {
                    let rewind_was_pending = !actor_state.pending_reset_rewind_committed();
                    let outcome = if actor_state.pending_reset_rewind_committed() {
                        WalletResetCommitOutcome {
                            rewind: WalletResetRewindOutcome::Committed {
                                committed_to: last_scanned,
                            },
                        }
                    } else {
                        WalletResetCommitRequest {
                            cache_store: cache_store.as_ref(),
                            cfg: &cfg,
                            utxos: &utxos,
                            worker_handle: &worker_handle,
                            pending,
                            highest_accepted_reset_intent: actor_state
                                .highest_accepted_reset_intent(),
                            actor_state: &mut actor_state,
                            cancel: &cancel,
                            last_scanned: &mut last_scanned,
                            persist_state: &mut persist_state,
                            live_metadata_flush: &mut live_metadata_flush,
                        }
                        .commit()
                        .await
                    };
                    if outcome.rewind.committed() {
                        if rewind_was_pending {
                            readiness_started = Instant::now();
                            backfill_complete_block = None;
                            live_rx = live_rx.resubscribe();
                        }

                        if $admit_replay && actor_state.pending_reset_replay_admitted().is_none() {
                            let replay_plan = pending.replay_plan();
                            let replay_from =
                                reset_replay_from_block(last_scanned, replay_plan.start_block);
                            let token =
                                worker_handle.mint_sync_token(actor_state.reset_generation());
                            let accepted = actor_state
                                .transition_active(&worker_handle, &cancel, |mut state| {
                                    let accepted = state.accept_target(
                                        token,
                                        replay_plan.target_block,
                                    );
                                    accepted
                                })
                                .unwrap_or(false);
                            let admitted = if !accepted {
                                false
                            } else if replay_plan.target_block > 0
                                && replay_from > replay_plan.target_block
                            {
                                let _ = actor_state.transition_active(
                                    &worker_handle,
                                    &cancel,
                                    |mut state| state.complete_backfill_job(token),
                                );
                                backfill_complete_block = actor_state.completed_target_block();
                                true
                            } else {
                                let (liveness, receiver) = oneshot::channel();
                                accepted_backfill_liveness
                                    .push(accepted_backfill_owner_dropped(token, receiver));
                                let driver = WalletBackfillGrant::for_actor_accepted_job_with_cancel(
                                    token,
                                    backfill_sender.clone(),
                                    liveness,
                                    cancel.clone(),
                                )
                                .activate();
                                let request = BackfillRequest::add(
                                    cfg.cache_key.clone(),
                                    replay_from,
                                    replay_plan.target_block,
                                    replay_plan.follow_safe_head,
                                    replay_from,
                                    driver,
                                );
                                match backfill_tx.try_send(request) {
                                    Ok(()) => {
                                        let _ = actor_state.transition_active(
                                            &worker_handle,
                                            &cancel,
                                            |mut state| state.backfill_dispatch_admitted(token),
                                        );
                                        true
                                    }
                                    Err(err) => {
                                        warn!(?err, cache_key = %cfg.cache_key, replay_from, target_block = replay_plan.target_block, "wallet reset replay enqueue failed");
                                        let _ = actor_state.transition_active(
                                            &worker_handle,
                                            &cancel,
                                            |mut state| {
                                                state.fail_job_backfill_unavailable(token);
                                            },
                                        );
                                        false
                                    }
                                }
                            };
                            let _ = actor_state.transition_active(
                                &worker_handle,
                                &cancel,
                                |mut state| {
                                    state.set_pending_reset_replay_admitted(
                                        admitted.then_some((token, replay_from)),
                                    );
                                },
                            );
                        }

                        if $admit_replay && actor_state.pending_reset_replay_admitted().is_some() {
                            let authority = WalletPrivateMutationAuthority::new(
                                &worker_handle,
                                actor_state.reset_generation(),
                                &cancel,
                            );
                            match authority.acquire().await {
                                Ok(permit) => {
                                    let persist_result = permit.with_active_apply(|token| {
                                        persist_wallet_reset_replay_admission_with_token(
                                            &token,
                                            &permit,
                                            cache_store.as_ref(),
                                            &cfg,
                                            actor_state.highest_accepted_reset_intent(),
                                        )?;
                                        actor_state.transition(&token, |mut state| {
                                            state.durable_reset_replay_commit_ok(
                                                pending.intent_id(),
                                            );
                                            state.clear_pending_reset();
                                        });
                                        Ok::<(), WalletCacheError>(())
                                    });
                                    match persist_result {
                                        Ok(Ok(())) => {}
                                        Ok(Err(err)) => {
                                            warn!(?err, cache_key = %cfg.cache_key, intent_id = pending.intent_id(), "failed to retire durable wallet reset replay plan");
                                            let _ = permit.with_active_apply(|token| {
                                                actor_state.transition(&token, |mut state| {
                                                    state.reset_replay_persist_failed(
                                                        pending.intent_id(),
                                                    );
                                                });
                                            });
                                        }
                                        Err(reason) => {
                                            debug!(?reason, cache_key = %cfg.cache_key, intent_id = pending.intent_id(), "wallet reset replay-plan retirement rejected");
                                        }
                                    }
                                }
                                Err(reason) => {
                                    debug!(?reason, cache_key = %cfg.cache_key, intent_id = pending.intent_id(), "wallet reset replay-plan retirement skipped");
                                }
                            }
                        }
                    }
                    Some(outcome)
                } else {
                    None
                }
            }};
        }
        macro_rules! apply_backfill_done {
            ($last_block:expr, $token:expr) => {{
                let last_block = $last_block;
                let job_token = $token;
                let current_reset_generation = actor_state.reset_generation();
                let should_persist = persist_state.needs_full_persist
                    || persist_state.pending_cache_reset.is_some();
                let authority = WalletPrivateMutationAuthority::new(
                    &worker_handle,
                    current_reset_generation,
                    &cancel,
                );
                let snapshot = utxos.read().await;
                let persist_result = if should_persist {
                    match authority.acquire().await {
                        Ok(permit) => {
                            let persisted = match persist_state.persist_progress(
                                cache_store.as_ref(),
                                &permit,
                                WalletProgressPersist {
                                    cache_key: &cfg.cache_key,
                                    snapshot: &snapshot,
                                    last_scanned,
                                    checkpoint: WalletCheckpointMutation::Preserve,
                                    changed: false,
                                },
                            ) {
                                Ok(_) => {
                                    live_metadata_flush.mark_persisted(last_scanned, Instant::now());
                                    Ok(())
                                }
                                Err(err) => {
                                    warn!(?err, cache_key = %cfg.cache_key, "failed to update wallet cache metadata");
                                    Err(WalletBackfillRejectReason::PersistenceFailed)
                                }
                            };
                            persisted
                        }
                        Err(reason) => {
                            warn!(?reason, cache_key = %cfg.cache_key, "wallet target metadata persist rejected");
                            Err(reason)
                        }
                    }
                } else {
                    Ok(())
                };
                drop(snapshot);
                if let Err(reason) = persist_result {
                    WalletBackfillDoneOutcome::Rejected(reason)
                } else if let Err(reason) = actor_state.transition_active(
                    &worker_handle,
                    &cancel,
                    |mut state| state.durable_backfill_completion_commit_ok(job_token),
                ) {
                    WalletBackfillDoneOutcome::Rejected(reason)
                } else {
                let mut pre_ready_poi_status_changed = false;
                let mut pre_ready_poi_status_rejection = None;
                let mut pre_ready_poi_status_refresh_elapsed_ms = 0_u128;
                let mut pre_ready_local_cache_available = false;
                if poi_status_client.is_some() {
                    if let Some(revision_rx) = poi_corpus_revision_rx.as_mut() {
                        let revision = *revision_rx.borrow_and_update();
                        let _ = actor_state.transition_active(
                            &worker_handle,
                            &cancel,
                            |mut state| {
                                state.observe_poi_corpus_revision(
                                    revision != last_poi_corpus_revision,
                                );
                            },
                        );
                        blocked_shield_refresh_pending |= revision.blocked_shields_revision
                            != last_poi_corpus_revision.blocked_shields_revision;
                        last_poi_corpus_revision = revision;
                    }
                    let refresh_revision = last_poi_corpus_revision;
                    let pre_ready_selection = if blocked_shield_refresh_pending {
                        WalletPoiRefreshSelection::CorpusRevision {
                            blocked_shields_changed: true,
                        }
                    } else {
                        WalletPoiRefreshSelection::RequiredOrRecoverable
                    };
                    let refresh_needed = {
                        let locked = utxos.read().await;
                        actor_state.has_failed_poi_status_refresh(
                            current_reset_generation,
                            pre_ready_selection,
                        ) || wallet_poi_status_refresh_needed_for_selection(
                            &locked,
                            &active_poi_list_keys,
                            pre_ready_selection,
                        )
                    };
                    if refresh_needed {
                        // Actor-safe: only local corpus (never remote proxy/fallback).
                        if let Some(status_reader) = poi_runtime
                            .local_status_reader(&public_data_plane, &cfg, &active_poi_list_keys)
                            .await
                        {
                            pre_ready_local_cache_available = true;
                            let status_refresh_started = Instant::now();
                            match (WalletPoiStatusRefreshCommitRequest {
                                cache_store: cache_store.as_ref(),
                                cfg: &cfg,
                                utxos: &utxos,
                                worker_handle: &worker_handle,
                                last_scanned,
                                reset_generation: current_reset_generation,
                                actor_state: &mut actor_state,
                                persist_state: &mut persist_state,
                                status_reader: &status_reader,
                                active_poi_list_keys: &active_poi_list_keys,
                                selection: pre_ready_selection,
                                cancel: &cancel,
                            })
                            .commit()
                            .await
                            {
                                Ok(changed) => {
                                    pre_ready_poi_status_changed = changed;
                                }
                                Err(reason) => {
                                    warn!(?reason, cache_key = %cfg.cache_key, "pre-ready wallet POI status refresh rejected");
                                    pre_ready_poi_status_rejection = Some(reason);
                                }
                            }
                            pre_ready_poi_status_refresh_elapsed_ms =
                                status_refresh_started.elapsed().as_millis();
                            debug!(
                                cache_key = %cfg.cache_key,
                                changed = pre_ready_poi_status_changed,
                                status_refresh_elapsed_ms = pre_ready_poi_status_refresh_elapsed_ms,
                                "pre-ready wallet POI status refresh visible"
                            );
                            tokio::task::yield_now().await;
                        } else if blocked_shield_refresh_pending {
                            pre_ready_poi_status_rejection =
                                Some(WalletBackfillRejectReason::ApplyFailed);
                        }
                    }
                    if let Some(revision_rx) = poi_corpus_revision_rx.as_mut() {
                        let revision = *revision_rx.borrow_and_update();
                        let _ = actor_state.transition_active(
                            &worker_handle,
                            &cancel,
                            |mut state| {
                                state.observe_poi_corpus_revision(
                                    revision != last_poi_corpus_revision,
                                );
                            },
                        );
                        blocked_shield_refresh_pending |= revision.blocked_shields_revision
                            != last_poi_corpus_revision.blocked_shields_revision;
                        last_poi_corpus_revision = revision;
                        if revision != refresh_revision {
                            pre_ready_poi_status_rejection =
                                Some(WalletBackfillRejectReason::ApplyFailed);
                        }
                    }
                    if pre_ready_poi_status_rejection.is_none() {
                        blocked_shield_refresh_pending = false;
                        let _ = actor_state.transition_active(
                            &worker_handle,
                            &cancel,
                            |mut state| state.set_poi_corpus_refresh_pending(false),
                        );
                    }
                } else if blocked_shield_refresh_pending {
                    pre_ready_poi_status_rejection = Some(WalletBackfillRejectReason::ApplyFailed);
                }
                if let Some(reason) = pre_ready_poi_status_rejection {
                    WalletBackfillDoneOutcome::Rejected(reason)
                } else {
                let snapshot = utxos.read().await;
                let (unspent, spent) = wallet_utxo_counts(&snapshot);
                backfill_complete_block = Some(last_block);
                info!(
                    cache_key = %cfg.cache_key,
                    last_scanned,
                    total = snapshot.len(),
                    unspent,
                    spent,
                    pre_ready_poi_status_changed,
                    pre_ready_local_cache_available,
                    pre_ready_poi_status_refresh_elapsed_ms,
                    ready_elapsed_ms = readiness_started.elapsed().as_millis(),
                    worker_elapsed_ms = worker_started.elapsed().as_millis(),
                    "wallet backfill complete"
                );
                drop(snapshot);
                tokio::task::yield_now().await;

                if poi_status_client.is_some() {
                    let post_ready_selection = WalletPoiRefreshSelection::RequiredOrRecoverable;
                    let refresh_needed = {
                        let locked = utxos.read().await;
                        actor_state.has_failed_poi_status_refresh(
                            current_reset_generation,
                            post_ready_selection,
                        ) || wallet_poi_status_refresh_needed_for_selection(
                            &locked,
                            &active_poi_list_keys,
                            post_ready_selection,
                        )
                    };
                    if refresh_needed
                        && let Some(status_reader) = poi_runtime
                            .local_status_reader(&public_data_plane, &cfg, &active_poi_list_keys)
                            .await
                    {
                        match (WalletPoiStatusRefreshCommitRequest {
                            cache_store: cache_store.as_ref(),
                            cfg: &cfg,
                            utxos: &utxos,
                            worker_handle: &worker_handle,
                            last_scanned,
                            reset_generation: current_reset_generation,
                            actor_state: &mut actor_state,
                            persist_state: &mut persist_state,
                            status_reader: &status_reader,
                            active_poi_list_keys: &active_poi_list_keys,
                            selection: post_ready_selection,
                            cancel: &cancel,
                        })
                        .commit()
                        .await
                        {
                            Ok(changed) => {
                                debug!(
                                    cache_key = %cfg.cache_key,
                                    changed,
                                    "post-ready local wallet POI status refresh committed"
                                );
                            }
                            Err(reason) => {
                                warn!(?reason, cache_key = %cfg.cache_key, "post-ready wallet POI status refresh rejected");
                            }
                        }
                    }
                    let _ = request_poi_maintenance(
                        &mut poi_maintenance,
                        &remote_done_tx,
                        &private_apply,
                        &poi_jobs,
                        &poi_refreshing_tx,
                        &worker_handle,
                        &cancel,
                        &db,
                        &cache_store,
                        &cfg,
                        &public_data_plane,
                        http_client.as_ref(),
                        indexed_artifact_source.as_ref(),
                        &poi_runtime,
                        &poi_submitter,
                        &forest,
                        &utxos,
                        &active_poi_list_keys,
                        false,
                    );
                }
                WalletBackfillDoneOutcome::Finished {
                    poi_corpus_revision: poi_corpus_revision_rx
                        .as_ref()
                        .map(|_| last_poi_corpus_revision),
                }
                }
                }
            }};
        }
        if actor_state.pending_reset().is_some() && try_drive_pending_reset!(false).is_some() {
            signal_restored_reset_attempt(&mut startup_replay_tx);
        }

        // Prepared-worker cancellation drops the sender, so this cannot hang. Once activation is
        // accepted, let the active loop observe cancellation and publish terminal readiness.
        let activated = activation_rx.await.is_ok();
        if !activated {
            return;
        }
        if actor_state.pending_reset().is_some() {
            let _ = try_drive_pending_reset!(true);
        }
        loop {
            tokio::select! {
                () = cancel.cancelled() => break,
                expiry = wait_for_local_pending_spent_expiry(&worker_handle) => {
                    if let Err(error) = expire_local_pending_spent(
                        &worker_handle,
                        &cancel,
                        actor_state.reset_generation(),
                        expiry,
                    ).await {
                        debug!(%error, cache_key = %cfg.cache_key, "local pending-spend expiry skipped");
                    }
                }
                Some((token, signal)) = accepted_backfill_liveness.next(), if !accepted_backfill_liveness.is_empty() => {
                    let WalletBackfillOwnerSignal {
                        disposition,
                        acknowledgement,
                    } = signal;
                    let changed = actor_state
                        .transition_active(&worker_handle, &cancel, |mut state| {
                            state.apply_backfill_owner_disposition(token, disposition)
                        })
                        .unwrap_or(false);
                    if changed {
                        if disposition == WalletBackfillOwnerDisposition::BenignRetirement
                            && !actor_state.has_active_backfill_job()
                        {
                            backfill_complete_block = actor_state.completed_target_block();
                            if poi_corpus_revision_rx.as_ref().is_some_and(|revision_rx| {
                                *revision_rx.borrow() != last_poi_corpus_revision
                            }) {
                                let _ = actor_state.transition_active(
                                    &worker_handle,
                                    &cancel,
                                    |mut state| state.observe_poi_corpus_revision(true),
                                );
                            }
                            let _revision_fence = match poi_corpus_handle.as_ref() {
                                Some(corpus) => Some(corpus.revision_read_fence().await),
                                None => None,
                            };
                            if let Some(revision_rx) = poi_corpus_revision_rx.as_mut() {
                                let revision = *revision_rx.borrow_and_update();
                                let blocked_shields_changed = revision.blocked_shields_revision
                                    != last_poi_corpus_revision.blocked_shields_revision;
                                let revision_changed = revision != last_poi_corpus_revision;
                                let _ = actor_state.transition_active(
                                    &worker_handle,
                                    &cancel,
                                    |mut state| {
                                        state.observe_poi_corpus_revision(revision_changed);
                                    },
                                );
                                last_poi_corpus_revision = revision;
                                blocked_shield_refresh_pending |= blocked_shields_changed;
                                if actor_state.poi_corpus_refresh_pending() {
                                    let selection = WalletPoiRefreshSelection::CorpusRevision {
                                        blocked_shields_changed: blocked_shield_refresh_pending,
                                    };
                                    let result = commit_local_poi_status_refresh!(selection);
                                    let refresh_still_needed = result.is_none() && {
                                        let locked = utxos.read().await;
                                        wallet_poi_status_refresh_needed_for_selection(
                                            &locked,
                                            &active_poi_list_keys,
                                            selection,
                                        )
                                    };
                                    match result {
                                        None if refresh_still_needed => {
                                            let _ = actor_state.transition_active(
                                                &worker_handle,
                                                &cancel,
                                                |mut state| {
                                                    state.set_poi_corpus_refresh_pending(true);
                                                },
                                            );
                                        }
                                        Some(Ok(_)) | None => {
                                            blocked_shield_refresh_pending = false;
                                            let _ = actor_state.transition_active(
                                                &worker_handle,
                                                &cancel,
                                                |mut state| {
                                                    state.set_poi_corpus_refresh_pending(false);
                                                },
                                            );
                                        }
                                        Some(Err(reason)) => {
                                            warn!(?reason, cache_key = %cfg.cache_key, "target retirement POI status refresh rejected");
                                            let _ = actor_state.transition_active(
                                                &worker_handle,
                                                &cancel,
                                                |mut state| {
                                                    state.set_poi_corpus_refresh_pending(true);
                                                },
                                            );
                                        }
                                    }
                                }
                            }
                        } else if disposition == WalletBackfillOwnerDisposition::DriverLost {
                            backfill_complete_block = None;
                        }
                    }
                    if let Some(acknowledgement) = acknowledgement {
                        let _ = acknowledgement.send(());
                    }
                }
                Some(token) = accepted_indexed_job_liveness.next(), if !accepted_indexed_job_liveness.is_empty() => {
                    let retired = actor_state
                        .transition_active(&worker_handle, &cancel, |mut state| {
                            state.retire_job(token)
                        })
                        .unwrap_or(false);
                    if retired {
                        let authority = WalletPrivateMutationAuthority::new(
                            &worker_handle,
                            actor_state.reset_generation(),
                            &cancel,
                        );
                        if let Ok(permit) = authority.acquire().await
                            && let Err(reason) = permit.publish_indexed_catch_up(None)
                        {
                            debug!(?reason, cache_key = %cfg.cache_key, "indexed wallet catch-up abandonment status clear rejected");
                        }
                    }
                }
                Some(apply_req) = private_apply_rx.recv() => {
                    let WalletPrivateApplyRequest {
                        reset_generation,
                        delta,
                        reply,
                    } = apply_req;
                    let result = apply_owned_poi_private_delta_on_actor_with_active_lists(
                        &worker_handle,
                        &cancel,
                        reset_generation,
                        db.as_ref(),
                        cache_store.as_ref(),
                        &cfg,
                        &active_poi_list_keys,
                        delta,
                    )
                    .await;
                    let _ = reply.send(result);
                }
                Some(done) = remote_done_rx.recv() => {
                    match done {
                        WalletRemoteDone::PoiMaintenance {
                            credential,
                            key,
                            recovered,
                            candidate_report,
                            recovery_error,
                            forced_pending_attempts,
                            submitted,
                            verified_completed,
                            verified_pending,
                            verified_errors,
                        } => {
                            // Always complete phase first (may start deferred force follow-up).
                            on_poi_maintenance_done(
                                &mut poi_maintenance,
                                &remote_done_tx,
                                &private_apply,
                                &poi_jobs,
                                &poi_refreshing_tx,
                                &worker_handle,
                                &cancel,
                                &db,
                                &cache_store,
                                &cfg,
                                &public_data_plane,
                                http_client.as_ref(),
                                indexed_artifact_source.as_ref(),
                                &poi_runtime,
                                &poi_submitter,
                                &forest,
                                &utxos,
                                &active_poi_list_keys,
                                key,
                            );
                            if !credential.is_current(&worker_handle) {
                                debug!(
                                    cache_key = %cfg.cache_key,
                                    ?key,
                                    "stale poi maintenance result dropped"
                                );
                                continue;
                            }
                            if recovered > 0 {
                                let authority = WalletPrivateMutationAuthority::new(
                                    &worker_handle,
                                    actor_state.reset_generation(),
                                    &cancel,
                                );
                                authority
                                    .notify_changed_if(true, "poi_maintenance_remote_done")
                                    .await;
                            }
                            let published = maintenance_observation.ppoi_workflow_status();
                            let candidate_report_is_current = cache_store
                                .list_sender_transaction_candidates(
                                    cfg.chain.chain_id,
                                    &cfg.cache_key,
                                )
                                .is_ok_and(|candidates| {
                                    candidate_report.matches_candidates(&candidates)
                                        && candidate_report.matches_pending_contexts(cache_store.as_ref(), &cfg).unwrap_or(false)
                                });
                            let refined = if candidate_report_is_current {
                                current_ppoi_workflow_status_for_candidate_report(
                                    cache_store.as_ref(),
                                    &cfg,
                                    &active_poi_list_keys,
                                    published,
                                    &candidate_report,
                                )
                            } else {
                                None
                            };
                            let workflow_status = refined.unwrap_or_else(|| {
                                let mut status = published;
                                if status.awaiting_recovery == 0 {
                                    status.awaiting_public_txid_data = 0;
                                    status.awaiting_poi_data = 0;
                                    status.retrying_recovery = 0;
                                    status.recovery_needs_attention = 0;
                                }
                                status
                            });
                            maintenance_observation.publish_ppoi_workflow_status(workflow_status);
                            if let Some(error) = recovery_error.as_ref() {
                                warn!(
                                    ?error,
                                    cache_key = %cfg.cache_key,
                                    "wallet POI remote maintenance completed with candidate recovery error"
                                );
                            }
                            debug!(
                                cache_key = %cfg.cache_key,
                                recovered,
                                candidate_materialized = candidate_report.materialized,
                                candidate_retired_locally_valid = candidate_report.retired_locally_valid,
                                candidate_awaiting_public_txid_data = candidate_report.awaiting_public_txid_data,
                                candidate_awaiting_poi_data = candidate_report.awaiting_poi_data,
                                candidate_retrying = candidate_report.retrying,
                                candidate_needs_attention = candidate_report.needs_attention,
                                candidate_covered_by_pending_contexts =
                                    candidate_report.covered_by_pending_contexts,
                                candidate_stale_revision_skips =
                                    candidate_report.stale_revision_skips,
                                candidate_unshield_awaiting_validation =
                                    candidate_report.unshield_awaiting_validation,
                                candidate_unshields_validated =
                                    candidate_report.unshields_validated,
                                candidate_report_is_current,
                                forced_pending_attempts,
                                submitted,
                                verified_completed,
                                verified_pending,
                                verified_errors,
                                candidate_recovery_succeeded = candidate_report_is_current
                                    && recovery_error.is_none()
                                    && candidate_report.awaiting_public_txid_data == 0
                                    && candidate_report.awaiting_poi_data == 0
                                    && candidate_report.retrying == 0
                                    && candidate_report.needs_attention == 0,
                                "wallet POI remote maintenance complete"
                            );
                        }
                        WalletRemoteDone::PoiMaintenanceAborted {
                            credential,
                            key,
                            reason,
                        } => {
                            on_poi_maintenance_done(
                                &mut poi_maintenance,
                                &remote_done_tx,
                                &private_apply,
                                &poi_jobs,
                                &poi_refreshing_tx,
                                &worker_handle,
                                &cancel,
                                &db,
                                &cache_store,
                                &cfg,
                                &public_data_plane,
                                http_client.as_ref(),
                                indexed_artifact_source.as_ref(),
                                &poi_runtime,
                                &poi_submitter,
                                &forest,
                                &utxos,
                                &active_poi_list_keys,
                                key,
                            );
                            if credential.is_current(&worker_handle) {
                                warn!(
                                    category = reason,
                                    "wallet POI maintenance aborted before completion"
                                );
                            } else {
                                debug!(
                                    category = reason,
                                    "stale wallet POI maintenance abort dropped"
                                );
                            }
                        }
                        WalletRemoteDone::PendingOutputPoiTentative {
                            credential,
                            accepted_candidates,
                            retryable,
                            accepted,
                            missing_txid,
                            remote_failure,
                            context_stale,
                            authority_stale: _authority_stale,
                        } => {
                            if !credential.is_current(&worker_handle) {
                                debug!("stale tentative pending output POI result dropped");
                                continue;
                            }
                            pending_output_poi_tentative_attempts
                                .accept(credential.reset_generation, &accepted_candidates);
                            pending_output_poi_tentative_attempts
                                .release_retryable(credential.reset_generation, &retryable);
                            if !accepted_candidates.is_empty() {
                                refresh_tentative_pending_output_poi_statuses(
                                    &worker_handle,
                                    &cancel,
                                    poi_corpus_handle.as_ref(),
                                    &cfg,
                                    &active_poi_list_keys,
                                    credential.reset_generation,
                                    &mut pending_output_poi_tentative_attempts,
                                )
                                .await;
                            }
                            info!(
                                accepted,
                                missing_txid,
                                remote_failure,
                                context_stale,
                                retryable = retryable.len(),
                                "tentative pending output POI submission complete"
                            );
                        }
                    }
                }
                _ = pending_reset_retry.tick(), if actor_state.pending_reset().is_some() => {
                    if let Some(outcome) = try_drive_pending_reset!(true) {
                        debug!(?outcome.rewind, cache_key = %cfg.cache_key, "wallet pending reset retry completed");
                        signal_restored_reset_attempt(&mut startup_replay_tx);
                    }
                }
                Some(refresh_request) = poi_refresh_rx.recv() => {
                    let Some(_client) = poi_status_client.as_ref() else {
                        continue;
                    };
                    if actor_state.pending_reset().is_some() {
                        let _ = poi_maintenance.request(
                            refresh_request.force_output_poi_recovery,
                            false,
                            None,
                        );
                        debug!(
                            cache_key = %cfg.cache_key,
                            "wallet POI refresh latched while reset commit is pending"
                        );
                        continue;
                    }
                    if backfill_complete_block.is_none() {
                        let _ = poi_maintenance.request(
                            refresh_request.force_output_poi_recovery,
                            false,
                            None,
                        );
                        debug!(
                            cache_key = %cfg.cache_key,
                            "wallet POI refresh latched until backfill complete"
                        );
                        continue;
                    }
                    let current_reset_generation = actor_state.reset_generation();
                    // Local-only status refresh on actor; remote readers must not block the loop.
                    if let Some(status_reader) = poi_runtime
                        .local_status_reader(&public_data_plane, &cfg, &active_poi_list_keys)
                        .await
                    {
                        match (WalletPoiStatusRefreshCommitRequest {
                            cache_store: cache_store.as_ref(),
                            cfg: &cfg,
                            utxos: &utxos,
                            worker_handle: &worker_handle,
                            last_scanned,
                            reset_generation: current_reset_generation,
                            actor_state: &mut actor_state,
                            persist_state: &mut persist_state,
                            status_reader: &status_reader,
                            active_poi_list_keys: &active_poi_list_keys,
                            selection: WalletPoiRefreshSelection::Recoverable,
                            cancel: &cancel,
                        })
                        .commit()
                        .await
                        {
                            Ok(changed) => {
                                debug!(
                                    cache_key = %cfg.cache_key,
                                    changed,
                                    "manual local wallet POI status refresh committed"
                                );
                            }
                            Err(reason) => {
                                warn!(?reason, cache_key = %cfg.cache_key, "manual wallet POI status refresh rejected");
                            }
                        }
                    }
                    let _ = request_poi_maintenance(
                        &mut poi_maintenance,
                        &remote_done_tx,
                        &private_apply,
                        &poi_jobs,
                        &poi_refreshing_tx,
                        &worker_handle,
                        &cancel,
                        &db,
                        &cache_store,
                        &cfg,
                        &public_data_plane,
                        http_client.as_ref(),
                        indexed_artifact_source.as_ref(),
                        &poi_runtime,
                        &poi_submitter,
                        &forest,
                        &utxos,
                        &active_poi_list_keys,
                        refresh_request.force_output_poi_recovery,
                    );
                }
                Some(command) = indexed_catch_up_status_rx.recv() => {
                    let authority = WalletPrivateMutationAuthority::new(
                        &worker_handle,
                        actor_state.reset_generation(),
                        &cancel,
                    );
                    match authority.acquire().await {
                        Ok(permit) => {
                            match command {
                                WalletIndexedCatchUpCommand::Claim { response } => {
                                    let token =
                                        worker_handle.mint_sync_token(actor_state.reset_generation());
                                    let accepted = permit
                                        .with_active_apply(|apply_token| {
                                            actor_state.transition(&apply_token, |mut state| {
                                                state.accept_indexed_catch_up(token)
                                            })
                                        })
                                        .unwrap_or(false);
                                    let lease = if accepted {
                                        let (liveness, receiver) = oneshot::channel();
                                        accepted_indexed_job_liveness
                                            .push(accepted_indexed_job_owner_dropped(token, receiver));
                                        Some(WalletIndexedCatchUpLease::for_actor_accepted_job(
                                            token,
                                            liveness,
                                        ))
                                    } else {
                                        None
                                    };
                                    if let Err(lease) = response.send(lease) {
                                        drop(lease);
                                        let retired = permit
                                            .with_active_apply(|apply_token| {
                                                actor_state.transition(&apply_token, |mut state| {
                                                    state.retire_job(token)
                                                })
                                            })
                                            .unwrap_or(false);
                                        if retired
                                            && let Err(reason) =
                                                permit.publish_indexed_catch_up(None)
                                        {
                                            debug!(?reason, cache_key = %cfg.cache_key, "indexed wallet catch-up dropped-claim status clear rejected");
                                        }
                                        debug!(cache_key = %cfg.cache_key, ?token, "indexed wallet catch-up claim receiver dropped");
                                    }
                                }
                                WalletIndexedCatchUpCommand::Publish { token, status } => {
                                    let published = permit
                                        .with_active_apply(|apply_token| {
                                            actor_state.transition(&apply_token, |mut state| {
                                                state.publish_indexed_catch_up(token, status)
                                            })
                                        })
                                        .unwrap_or(false);
                                    if published {
                                        if let Err(reason) =
                                            permit.publish_indexed_catch_up(Some(status))
                                        {
                                            debug!(?reason, cache_key = %cfg.cache_key, "indexed wallet catch-up status publication rejected");
                                        }
                                    } else {
                                        debug!(cache_key = %cfg.cache_key, ?token, "stale indexed wallet catch-up status publication ignored");
                                    }
                                }
                            }
                        }
                        Err(reason) => {
                            if let WalletIndexedCatchUpCommand::Claim { response } = command {
                                let _ = response.send(None);
                            }
                            debug!(?reason, cache_key = %cfg.cache_key, "indexed wallet catch-up status publication skipped");
                        }
                    }
                }
                Some(request) = private_request_rx.recv() => {
                    match request {
                        WalletPrivateRequest::MarkLocalPendingSpent {
                            utxos,
                            tx_hash,
                            reply,
                        } => {
                            let result = match actor_state.validate_pending_overlay_request(
                                &worker_handle,
                                &cancel,
                            ) {
                                Ok(reset_generation) => {
                                    mark_local_pending_spent(
                                        &worker_handle,
                                        &cancel,
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
                        WalletPrivateRequest::ClearLocalPendingSpent { reply } => {
                            let result = match actor_state.validate_pending_overlay_request(
                                &worker_handle,
                                &cancel,
                            ) {
                                Ok(reset_generation) => {
                                    clear_local_pending_spent(
                                        &worker_handle,
                                        &cancel,
                                        reset_generation,
                                    )
                                    .await
                                }
                                Err(err) => Err(err),
                            };
                            let _ = reply.send(result);
                        }
                        WalletPrivateRequest::CreatePendingOutputContexts {
                            ticket,
                            contexts,
                            reply,
                        } => {
                            let result = match actor_state.validate_private_request(
                                &worker_handle,
                                &cancel,
                                ticket,
                                last_scanned,
                                false,
                            ) {
                                Ok(reset_generation) => {
                                    commit_pending_output_contexts(
                                        &worker_handle,
                                        &cancel,
                                        db.as_ref(),
                                        cache_store.as_ref(),
                                        &cfg,
                                        reset_generation,
                                        &active_poi_list_keys,
                                        &poi_submitter,
                                        &contexts,
                                    )
                                    .await
                                }
                                Err(err) => Err(err),
                            };
                            let _ = reply.send(result);
                        }
                    }
                }
                Some(request) = pending_overlay_rx.recv() => {
                    let current_reset_generation = actor_state.reset_generation();
                    let request_is_current = actor_state.pending_reset().is_none()
                        && request.reset_generation == current_reset_generation
                        && request.last_scanned == last_scanned;
                    let accepted = request_is_current
                        && actor_state
                            .transition_active(&worker_handle, &cancel, |mut state| {
                                state.accept_pending_overlay(request.token, request.last_scanned)
                            })
                            .unwrap_or(false);
                    if !accepted {
                        debug!(
                            cache_key = %cfg.cache_key,
                            token = ?request.token,
                            request_reset_generation = request.reset_generation,
                            current_reset_generation,
                            request_last_scanned = request.last_scanned,
                            current_last_scanned = last_scanned,
                            pending_reset = actor_state.pending_reset().is_some(),
                            "ignoring stale pending overlay update"
                        );
                        continue;
                    }
                    pending_output_poi_tentative_attempts
                        .clear_generation(current_reset_generation);
                    let authority = WalletPrivateMutationAuthority::new(
                        &worker_handle,
                        current_reset_generation,
                        &cancel,
                    );
                    let permit = match authority.acquire().await {
                        Ok(guard) => guard,
                        Err(reason) => {
                            debug!(?reason, cache_key = %cfg.cache_key, "pending overlay update rejected");
                            let _ = actor_state.transition_active(
                                &worker_handle,
                                &cancel,
                                |mut state| state.retire_job(request.token),
                            );
                            continue;
                        }
                    };
                    if !actor_state.pending_overlay_is_current(request.token, request.last_scanned)
                        || permit.revalidate().is_err()
                    {
                        let _ = permit.with_active_apply(|token| {
                            actor_state.transition(&token, |mut state| {
                                state.retire_job(request.token);
                            });
                        });
                        continue;
                    }
                    let mut tentative_observations = Vec::new();
                    let mut overlay = match request.update {
                        WalletPendingOverlayUpdate::Clear => {
                            pending_output_poi_tentative_attempts.clear();
                            WalletPendingOverlay::default()
                        }
                        WalletPendingOverlayUpdate::PublicRows(rows) => {
                            let delta = match rows.payload {
                                WalletScanRowsPayload::Rows(rows) => {
                                    WalletLogDelta::from_rows(&rows, &cfg.scan_keys)
                                }
                                WalletScanRowsPayload::EmptyCoverage => WalletLogDelta {
                                    utxos: Vec::new(),
                                    nullifiers: Vec::new(),
                                    commitment_observations: Vec::new(),
                                    sender_scan_outputs: Vec::new(),
                                },
                                #[cfg(test)]
                                WalletScanRowsPayload::IndexedDeltaForTest { delta } => *delta,
                            };
                            tentative_observations = delta.commitment_observations.clone();
                            pending_output_poi_tentative_attempts.prune_for_observations(
                                actor_state.reset_generation(),
                                &tentative_observations,
                            );
                            let delta = WalletLogDelta {
                                commitment_observations: Vec::new(),
                                ..delta
                            };
                            let confirmed = utxos.read().await;
                            if !actor_state
                                .pending_overlay_is_current(request.token, request.last_scanned)
                                || permit.revalidate().is_err()
                            {
                                let _ = permit.with_active_apply(|token| {
                                    actor_state.transition(&token, |mut state| {
                                        state.retire_job(request.token);
                                    });
                                });
                                continue;
                            }
                            pending_overlay_from_delta(&cfg, &confirmed, delta)
                        }
                    };
                    pending_output_poi_tentative_attempts.apply_to_overlay(
                        actor_state.reset_generation(),
                        &mut overlay,
                        now_epoch_secs(),
                    );
                    let changed = match permit.replace_chain_pending_overlay(overlay).await {
                        Ok(changed) => changed,
                        Err(reason) => {
                            debug!(?reason, cache_key = %cfg.cache_key, "pending overlay update rejected before publication");
                            let _ = permit.with_active_apply(|token| {
                                actor_state.transition(&token, |mut state| {
                                    state.retire_job(request.token);
                                });
                            });
                            continue;
                        }
                    };
                    if let Err(reason) = permit.notify_if_changed(changed).await {
                        debug!(?reason, cache_key = %cfg.cache_key, "pending overlay revision publication rejected");
                    }
                    let _ = permit.with_active_apply(|token| {
                        actor_state.transition(&token, |mut state| {
                            state.retire_job(request.token);
                        });
                    });
                    drop(permit);
                    if !tentative_observations.is_empty() {
                        let observation_count = tentative_observations.len();
                        let mut candidate_count = 0;
                        let mut reserved_count = 0;
                        let tentative_candidates =
                            match prepare_pending_output_poi_tentative_candidates(
                                cache_store.as_ref(),
                                &cfg,
                                &active_poi_list_keys,
                                &tentative_observations,
                            )
                            {
                                Ok(candidates) => {
                                    candidate_count = candidates.len();
                                    let reserved = candidates
                                        .into_iter()
                                        .filter(|candidate| {
                                            pending_output_poi_tentative_attempts.reserve(
                                                actor_state.reset_generation(),
                                                candidate.clone(),
                                            )
                                        })
                                        .collect::<Vec<_>>();
                                    reserved_count = reserved.len();
                                    reserved
                                }
                                Err(_err) => Vec::new(),
                            };
                        if reserved_count > 0 {
                            info!(
                                observations = observation_count,
                                candidates = candidate_count,
                                reserved = reserved_count,
                                "tentative pending output POI candidates scheduled"
                            );
                        }
                        if !tentative_candidates.is_empty() {
                            spawn_pending_output_poi_tentative_job(
                                &poi_jobs,
                                &worker_handle,
                                &cancel,
                                &remote_done_tx,
                                &cache_store,
                                &cfg,
                                &poi_runtime,
                                &poi_submitter,
                                &active_poi_list_keys,
                                tentative_candidates,
                            );
                        }
                    }
                }
                revision = next_poi_corpus_revision(&mut poi_corpus_revision_rx) => {
                    let Some(mut revision) = revision else {
                        poi_corpus_revision_rx = None;
                        continue;
                    };
                    let _ = actor_state.transition_active(
                        &worker_handle,
                        &cancel,
                        |mut state| {
                            state.observe_poi_corpus_revision(
                                revision != last_poi_corpus_revision,
                            );
                        },
                    );
                    let _revision_fence = match poi_corpus_handle.as_ref() {
                        Some(corpus) => Some(corpus.revision_read_fence().await),
                        None => None,
                    };
                    if let Some(revision_rx) = poi_corpus_revision_rx.as_mut() {
                        revision = *revision_rx.borrow_and_update();
                    }
                    refresh_tentative_pending_output_poi_statuses(
                        &worker_handle,
                        &cancel,
                        poi_corpus_handle.as_ref(),
                        &cfg,
                        &active_poi_list_keys,
                        actor_state.reset_generation(),
                        &mut pending_output_poi_tentative_attempts,
                    )
                    .await;
                    let _ = actor_state.transition_active(
                        &worker_handle,
                        &cancel,
                        |mut state| {
                            state.observe_poi_corpus_revision(
                                revision != last_poi_corpus_revision,
                            );
                        },
                    );
                    debug!(
                        cache_key = %cfg.cache_key,
                        revision = revision.revision,
                        blocked_shields_revision = revision.blocked_shields_revision,
                        backfill_complete = backfill_complete_block.is_some(),
                        reset_pending = actor_state.pending_reset().is_some(),
                        "committed PPOI corpus revision observed"
                    );
                    let blocked_shields_changed = revision.blocked_shields_revision
                        != last_poi_corpus_revision.blocked_shields_revision;
                    last_poi_corpus_revision = revision;
                    blocked_shield_refresh_pending |= blocked_shields_changed;
                    if backfill_complete_block.is_some()
                        && actor_state.pending_reset().is_none()
                        && let Some(result) = commit_local_poi_status_refresh!(
                            WalletPoiRefreshSelection::CorpusRevision {
                                blocked_shields_changed: blocked_shield_refresh_pending,
                            }
                        )
                    {
                        match result {
                            Ok(changed) => {
                                blocked_shield_refresh_pending = false;
                                let _ = actor_state.transition_active(
                                    &worker_handle,
                                    &cancel,
                                    |mut state| state.set_poi_corpus_refresh_pending(false),
                                );
                                debug!(
                                    cache_key = %cfg.cache_key,
                                    revision = revision.revision,
                                    changed,
                                    "corpus revision local wallet POI status refresh committed"
                                );
                            }
                            Err(reason) => warn!(
                                ?reason,
                                cache_key = %cfg.cache_key,
                                revision = revision.revision,
                                "corpus revision wallet POI status refresh rejected"
                            ),
                        }
                    }
                    if actor_state.poi_corpus_refresh_pending() {
                        let selection = WalletPoiRefreshSelection::CorpusRevision {
                            blocked_shields_changed: blocked_shield_refresh_pending,
                        };
                        let refresh_still_needed = {
                            let locked = utxos.read().await;
                            wallet_poi_status_refresh_needed_for_selection(
                                &locked,
                                &active_poi_list_keys,
                                selection,
                            )
                        };
                        if !refresh_still_needed {
                            blocked_shield_refresh_pending = false;
                            let _ = actor_state.transition_active(
                                &worker_handle,
                                &cancel,
                                |mut state| state.set_poi_corpus_refresh_pending(false),
                            );
                        }
                    }
                }
                _ = poi_status_refresh_interval.tick(), if poi_status_client.is_some() && backfill_complete_block.is_some() && actor_state.pending_reset().is_none() => {
                    let Some(_client) = poi_status_client.as_ref() else {
                        continue;
                    };
                    if let Some(revision_rx) = poi_corpus_revision_rx.as_mut() {
                        let revision = *revision_rx.borrow_and_update();
                        let _ = actor_state.transition_active(
                            &worker_handle,
                            &cancel,
                            |mut state| {
                                state.observe_poi_corpus_revision(
                                    revision != last_poi_corpus_revision,
                                );
                            },
                        );
                        blocked_shield_refresh_pending |= revision.blocked_shields_revision
                            != last_poi_corpus_revision.blocked_shields_revision;
                        last_poi_corpus_revision = revision;
                    }
                    let _revision_fence = match poi_corpus_handle.as_ref() {
                        Some(corpus) => Some(corpus.revision_read_fence().await),
                        None => None,
                    };
                    let now = now_epoch_secs();
                    let selection = if actor_state.poi_corpus_refresh_pending()
                        || blocked_shield_refresh_pending
                    {
                        WalletPoiRefreshSelection::CorpusRevision {
                            blocked_shields_changed: blocked_shield_refresh_pending,
                        }
                    } else if let Some(failed_selection) = actor_state
                        .failed_poi_status_refresh_selection(actor_state.reset_generation())
                    {
                        failed_selection
                    } else {
                        WalletPoiRefreshSelection::RecoverableStale { now }
                    };
                    if let Some(result) = commit_local_poi_status_refresh!(
                        selection
                    ) {
                        match result {
                            Ok(changed) => {
                                blocked_shield_refresh_pending = false;
                                let _ = actor_state.transition_active(
                                    &worker_handle,
                                    &cancel,
                                    |mut state| state.set_poi_corpus_refresh_pending(false),
                                );
                                debug!(
                                    cache_key = %cfg.cache_key,
                                    changed,
                                    "periodic local wallet POI status refresh committed"
                                );
                            }
                            Err(reason) => {
                                warn!(?reason, cache_key = %cfg.cache_key, "periodic wallet POI status refresh rejected");
                            }
                        }
                    }
                    if actor_state.poi_corpus_refresh_pending() {
                        let refresh_still_needed = {
                            let locked = utxos.read().await;
                            wallet_poi_status_refresh_needed_for_selection(
                                &locked,
                                &active_poi_list_keys,
                                selection,
                            )
                        };
                        if !refresh_still_needed {
                            blocked_shield_refresh_pending = false;
                            let _ = actor_state.transition_active(
                                &worker_handle,
                                &cancel,
                                |mut state| state.set_poi_corpus_refresh_pending(false),
                            );
                        }
                    }
                    let _ = request_poi_maintenance(
                        &mut poi_maintenance,
                        &remote_done_tx,
                        &private_apply,
                        &poi_jobs,
                        &poi_refreshing_tx,
                        &worker_handle,
                        &cancel,
                        &db,
                        &cache_store,
                        &cfg,
                        &public_data_plane,
                        http_client.as_ref(),
                        indexed_artifact_source.as_ref(),
                        &poi_runtime,
                        &poi_submitter,
                        &forest,
                        &utxos,
                        &active_poi_list_keys,
                        false,
                    );
                }
                Some(event) = backfill_rx.recv() => {
                    match event {
                        #[cfg(test)]
                        BackfillEvent::PanicForTest => {
                            panic!("test wallet actor panic");
                        }
                        #[cfg(test)]
                        BackfillEvent::HoldTrackedPoiJobForTest { sentinel, started } => {
                            let held_data_plane = public_data_plane.clone();
                            poi_jobs.spawn(async move {
                                let _held = (held_data_plane, sentinel);
                                let _ = started.send(());
                                std::future::pending::<()>().await;
                            });
                        }
                        BackfillEvent::ReserveTarget { target_block, token, response } => {
                            if let Err(reason) = actor_state.validate_sync_token_current(
                                token,
                                &worker_handle,
                                &cancel,
                            ) {
                                let _ = response.send(Err(reason));
                                continue;
                            }
                            if try_drive_pending_reset!(true).is_some()
                                && actor_state.pending_reset().is_some()
                            {
                                let reason = if actor_state.has_persistence_failure() {
                                    WalletBackfillRejectReason::PersistenceFailed
                                } else {
                                    WalletBackfillRejectReason::Shutdown
                                };
                                let _ = response.send(Err(reason));
                                continue;
                            }
                            let accepted = actor_state
                                .transition_active(&worker_handle, &cancel, |mut state| {
                                    state.accept_sync_target(token, target_block)
                                })
                                .unwrap_or(false);
                            if !accepted {
                                let _ = response.send(Err(WalletBackfillRejectReason::Shutdown));
                                continue;
                            }
                            let (liveness, receiver) = oneshot::channel();
                            accepted_backfill_liveness
                                .push(accepted_backfill_owner_dropped(token, receiver));
                            let lease = WalletSyncTargetLease::for_actor_accepted_job(
                                token,
                                backfill_sender.clone(),
                                liveness,
                            );
                            if let Err(lease) = response.send(Ok(lease)) {
                                drop(lease);
                                let _ = actor_state.transition_active(
                                    &worker_handle,
                                    &cancel,
                                    |mut state| state.retire_job(token),
                                );
                            }
                        }
                        BackfillEvent::Start { target_block, token, response } => {
                            if let Err(reason) = actor_state.validate_sync_token_current(
                                token,
                                &worker_handle,
                                &cancel,
                            ) {
                                let _ = response.send(WalletBackfillStartResult::Rejected {
                                    committed_to: last_scanned,
                                    reason,
                                });
                                continue;
                            }
                            if try_drive_pending_reset!(true).is_some()
                                && actor_state.pending_reset().is_some()
                            {
                                let reason = if actor_state.has_persistence_failure() {
                                    WalletBackfillRejectReason::PersistenceFailed
                                } else {
                                    WalletBackfillRejectReason::Shutdown
                                };
                                let _ = response.send(WalletBackfillStartResult::Rejected {
                                    committed_to: last_scanned,
                                    reason,
                                });
                                continue;
                            }
                            let accepted = actor_state
                                .transition_active(&worker_handle, &cancel, |mut state| {
                                    state.accept_target(token, target_block)
                                })
                                .unwrap_or(false);
                            if !accepted {
                                let _ = response.send(WalletBackfillStartResult::Rejected {
                                    committed_to: last_scanned,
                                    reason: WalletBackfillRejectReason::Shutdown,
                                });
                                continue;
                            }
                            let (liveness, receiver) = oneshot::channel();
                            accepted_backfill_liveness
                                .push(accepted_backfill_owner_dropped(token, receiver));
                            backfill_complete_block = None;
                            let result = WalletBackfillStartResult::Accepted {
                                committed_to: last_scanned,
                                target_block,
                                    grant: WalletBackfillGrant::for_actor_accepted_job_with_cancel(
                                        token,
                                        backfill_sender.clone(),
                                        liveness,
                                        cancel.clone(),
                                    ),
                            };
                            match response.send(result) {
                                Ok(()) => {
                                    let _ = actor_state.transition_active(
                                        &worker_handle,
                                        &cancel,
                                        |mut state| state.backfill_dispatch_admitted(token),
                                    );
                                }
                                Err(result) => {
                                    drop(result);
                                    let _ = actor_state.transition_active(
                                        &worker_handle,
                                        &cancel,
                                        |mut state| state.retire_job(token),
                                    );
                                    debug!(cache_key = %cfg.cache_key, ?token, "wallet backfill start receiver dropped");
                                }
                            }
                        }
                        BackfillEvent::Apply { apply, token, response } => {
                            if let Some(outcome) = try_drive_pending_reset!(true)
                                && actor_state.pending_reset().is_some()
                            {
                                let reason = match outcome.rewind {
                                    WalletResetRewindOutcome::Deferred { reason, .. } => reason,
                                    WalletResetRewindOutcome::Committed { .. }
                                        if actor_state.has_persistence_failure() =>
                                    {
                                        WalletBackfillRejectReason::PersistenceFailed
                                    }
                                    WalletResetRewindOutcome::Committed { .. } =>
                                        WalletBackfillRejectReason::Shutdown,
                                };
                                let _ = actor_state.transition_active(
                                    &worker_handle,
                                    &cancel,
                                    |mut state| {
                                        state.retire_job(token);
                                    },
                                );
                                let result = WalletBackfillApplyResult::Rejected {
                                    committed_to: last_scanned,
                                    reason,
                                };
                                if let Err(err) = response.send(result) {
                                    debug!(?err, cache_key = %cfg.cache_key, "failed to send pending-reset wallet scan apply result");
                                }
                                continue;
                            }
                            let current_reset_generation = actor_state.reset_generation();
                            if let Err(reason) = actor_state.validate_active_backfill_token(
                                token,
                                &worker_handle,
                                &cancel,
                            ) {
                                let result = WalletBackfillApplyResult::Rejected {
                                    committed_to: last_scanned,
                                    reason,
                                };
                                if let Err(err) = response.send(result) {
                                    debug!(?err, cache_key = %cfg.cache_key, "failed to send inactive wallet scan apply result");
                                }
                                continue;
                            }
                            let outcome = WalletScanCommitRequest {
                                cache_store: cache_store.as_ref(),
                                cfg: &cfg,
                                utxos: &utxos,
                                worker_handle: &worker_handle,
                                apply,
                                job_token: token,
                                current_reset_generation,
                                event_reset_generation: token.reset_generation(),
                                actor_state: &mut actor_state,
                                cancel: &cancel,
                                last_scanned: &mut last_scanned,
                                persist_state: &mut persist_state,
                                live_metadata_flush: &mut live_metadata_flush,
                                public_data_plane: &public_data_plane,
                            }
                            .commit()
                            .await;
                            if outcome.changed && poi_status_client.is_some() {
                                let _ = request_poi_maintenance(
                                    &mut poi_maintenance,
                                    &remote_done_tx,
                                    &private_apply,
                                    &poi_jobs,
                                    &poi_refreshing_tx,
                                    &worker_handle,
                                    &cancel,
                                    &db,
                                    &cache_store,
                                    &cfg,
                                    &public_data_plane,
                                    http_client.as_ref(),
                                    indexed_artifact_source.as_ref(),
                                    &poi_runtime,
                                    &poi_submitter,
                                    &forest,
                                    &utxos,
                                    &active_poi_list_keys,
                                    false,
                                );
                            }
                            if let Err(err) = response.send(outcome.result) {
                                debug!(?err, cache_key = %cfg.cache_key, "failed to send wallet scan apply result");
                            }
                        }
                        BackfillEvent::Finish { target_block, token, response } => {
                            let current_reset_generation = actor_state.reset_generation();
                            if let Err(reason) = actor_state.validate_active_backfill_token(
                                token,
                                &worker_handle,
                                &cancel,
                            ) {
                                let result = WalletBackfillFinishResult::Rejected {
                                    committed_to: last_scanned,
                                    reason,
                                };
                                if let Err(err) = response.send(result) {
                                    debug!(?err, cache_key = %cfg.cache_key, "failed to send stale wallet target result");
                                }
                                continue;
                            }
                            if let Some(outcome) = try_drive_pending_reset!(true)
                                && actor_state.pending_reset().is_some()
                            {
                                let reason = match outcome.rewind {
                                    WalletResetRewindOutcome::Deferred { reason, .. } => reason,
                                    WalletResetRewindOutcome::Committed { .. }
                                        if actor_state.has_persistence_failure() =>
                                    {
                                        WalletBackfillRejectReason::PersistenceFailed
                                    }
                                    WalletResetRewindOutcome::Committed { .. } =>
                                        WalletBackfillRejectReason::Shutdown,
                                };
                                let result = WalletBackfillFinishResult::Rejected {
                                    committed_to: last_scanned,
                                    reason,
                                };
                                if let Err(err) = response.send(result) {
                                    debug!(?err, cache_key = %cfg.cache_key, "failed to send pending-reset wallet target result");
                                }
                                continue;
                            }
                            let Some(required_target) = actor_state
                                .transition_active(&worker_handle, &cancel, |mut state| {
                                    state.update_target(token, target_block)
                                })
                                .ok()
                                .flatten()
                            else {
                                let _ = response.send(WalletBackfillFinishResult::Rejected {
                                    committed_to: last_scanned,
                                    reason: WalletBackfillRejectReason::Shutdown,
                                });
                                continue;
                            };
                            if required_target == 0 || required_target > last_scanned {
                                debug!(
                                    cache_key = %cfg.cache_key,
                                    target_block = required_target,
                                    last_scanned,
                                    reset_generation = current_reset_generation,
                                    "wallet target recorded; cursor has not reached target"
                                );
                                backfill_complete_block = None;
                                let result = WalletBackfillFinishResult::Rejected {
                                    committed_to: last_scanned,
                                    reason: WalletBackfillRejectReason::TargetNotReached {
                                        target_block: required_target,
                                    },
                                };
                                if let Err(err) = response.send(result) {
                                    debug!(?err, cache_key = %cfg.cache_key, "failed to send pending wallet target result");
                                }
                                continue;
                            }
                            let finish_outcome = apply_backfill_done!(required_target, token);
                            let result = match finish_outcome {
                                WalletBackfillDoneOutcome::Finished {
                                    poi_corpus_revision,
                                } => {
                                    let _revision_fence = match poi_corpus_handle.as_ref() {
                                        Some(corpus) => Some(corpus.revision_read_fence().await),
                                        None => None,
                                    };
                                    if poi_corpus_revision.is_some_and(|applied_revision| {
                                            poi_corpus_revision_rx
                                                .as_mut()
                                                .is_some_and(|revision_rx| {
                                                    *revision_rx.borrow_and_update()
                                                        != applied_revision
                                                })
                                        })
                                    {
                                        WalletBackfillFinishResult::Rejected {
                                            committed_to: last_scanned,
                                            reason: WalletBackfillRejectReason::ApplyFailed,
                                        }
                                    } else {
                                        let completed = actor_state
                                            .transition_active(
                                                &worker_handle,
                                                &cancel,
                                                |mut state| state.complete_backfill_job(token),
                                            )
                                            .unwrap_or(false);
                                        if completed {
                                            if actor_state.has_active_backfill_job() {
                                                backfill_complete_block = None;
                                            }
                                            WalletBackfillFinishResult::Ready {
                                                committed_to: last_scanned,
                                            }
                                        } else {
                                            WalletBackfillFinishResult::Rejected {
                                                committed_to: last_scanned,
                                                reason: WalletBackfillRejectReason::Shutdown,
                                            }
                                        }
                                    }
                                }
                                WalletBackfillDoneOutcome::Rejected(reason) => {
                                    let _ = actor_state.transition_active(
                                        &worker_handle,
                                        &cancel,
                                        |mut state| {
                                            if reason == WalletBackfillRejectReason::PersistenceFailed {
                                                state.backfill_completion_persist_failed(token);
                                            } else {
                                                state.retire_job(token);
                                            }
                                        },
                                    );
                                    WalletBackfillFinishResult::Rejected {
                                        committed_to: last_scanned,
                                        reason,
                                    }
                                }
                            };
                            if let Err(err) = response.send(result) {
                                debug!(?err, cache_key = %cfg.cache_key, "failed to send wallet target result");
                            }
                        }
                        BackfillEvent::JobFailed { token, reason, response } => {
                            if actor_state.validate_active_backfill_token(
                                token,
                                &worker_handle,
                                &cancel,
                            )
                            .is_ok()
                            {
                                let _ = actor_state.transition_active(
                                    &worker_handle,
                                    &cancel,
                                    |mut state| match reason {
                                        WalletReadinessError::BackfillUnavailable => {
                                            state.fail_job_backfill_unavailable(token)
                                        }
                                        WalletReadinessError::TargetNotReached { target_block } => {
                                            state.fail_job_target_not_reached(token, target_block)
                                        }
                                        WalletReadinessError::ApplyFailed => {
                                            state.fail_job_apply_failed(token)
                                        }
                                        WalletReadinessError::PersistenceFailed => false,
                                    },
                                );
                            }
                            let _ = response.send(());
                        }
                        BackfillEvent::Reset { token, from_block, replay_plan, response } => {
                            if let Err(reason) = actor_state.validate_reset_token_current(
                                token,
                                &worker_handle,
                                &cancel,
                            ) {
                                let result = WalletBackfillResetResult::Rejected {
                                    committed_to: last_scanned,
                                    reason,
                                };
                                if let Err(err) = response.send(result) {
                                    debug!(?err, cache_key = %cfg.cache_key, "failed to send shutdown wallet reset result");
                                }
                                continue;
                            }
                            let intent_id = token.intent_id();

                            if intent_id <= actor_state.highest_accepted_reset_intent() {
                                let result = WalletBackfillResetResult::Rejected {
                                    committed_to: last_scanned,
                                    reason: WalletBackfillRejectReason::StaleResetIntent {
                                        accepted: actor_state.highest_accepted_reset_intent(),
                                        actual: intent_id,
                                    },
                                };
                                if let Err(err) = response.send(result) {
                                    debug!(?err, cache_key = %cfg.cache_key, "failed to send stale wallet reset result");
                                }
                                continue;
                            }
                            let current_reset_generation = actor_state.reset_generation();
                            let acceptance_authority = WalletPrivateMutationAuthority::new(
                                &worker_handle,
                                current_reset_generation,
                                &cancel,
                            );
                            let acceptance_permit = match acceptance_authority.acquire().await {
                                Ok(permit) => permit,
                                Err(reason) => {
                                    let result = WalletBackfillResetResult::Rejected {
                                        committed_to: last_scanned,
                                        reason,
                                    };
                                    if let Err(err) = response.send(result) {
                                        debug!(?err, cache_key = %cfg.cache_key, "failed to send reset authority rejection");
                                    }
                                    continue;
                                }
                            };
                            let reset_from_block = actor_state.pending_reset()
                                .map_or(from_block, |pending| {
                                    pending.rewind_from_block().min(from_block)
                                });
                            let replay_plan = PendingWalletReset::merge_replay_plan(
                                actor_state.pending_reset(),
                                replay_plan,
                            );
                            let next_reset_generation = current_reset_generation.wrapping_add(1);
                            let accepted_pending_reset = PendingWalletReset::new(
                                intent_id,
                                reset_from_block,
                                next_reset_generation,
                                replay_plan,
                            );
                            // AcceptReset transition: durable accept + generation + actor_state +
                            // publications under one active-apply fence (no split after durable write).
                            let accept_result = acceptance_permit.with_active_apply(|token| {
                                persist_wallet_reset_acceptance_with_token(
                                    &token,
                                    &acceptance_permit,
                                    cache_store.as_ref(),
                                    &cfg,
                                    intent_id,
                                    accepted_pending_reset,
                                )?;
                                acceptance_permit
                                    .apply_set_reset_generation(&token, next_reset_generation);
                                let reset_intent_id = accepted_pending_reset.intent_id();
                                let reset_from = accepted_pending_reset.rewind_from_block();
                                let reset_view = WalletViewState::ResetPending {
                                    intent_id: reset_intent_id,
                                    from_block: reset_from,
                                    reset_generation: next_reset_generation,
                                };
                                let clear_indexed_catch_up = actor_state.transition_with_view(
                                    &token,
                                    reset_view,
                                    |mut state| state.accept_reset(accepted_pending_reset),
                                );
                                // Force intent is generation-scoped; do not carry across rewind.
                                poi_maintenance.clear_force_on_reset();
                                if clear_indexed_catch_up {
                                    acceptance_permit
                                        .apply_publish_indexed_catch_up(&token, None);
                                }
                                Ok::<(), WalletCacheError>(())
                            });
                            match accept_result {
                                Ok(Ok(())) => {
                                    accepted_backfill_liveness.clear();
                                    accepted_indexed_job_liveness.clear();
                                    pending_output_poi_tentative_attempts.clear();
                                }
                                Ok(Err(err)) => {
                                    warn!(?err, cache_key = %cfg.cache_key, intent_id, from_block, "failed to persist wallet reset acceptance");
                                    let result = WalletBackfillResetResult::Rejected {
                                        committed_to: last_scanned,
                                        reason: WalletBackfillRejectReason::PersistenceFailed,
                                    };
                                    if let Err(err) = response.send(result) {
                                        debug!(?err, cache_key = %cfg.cache_key, "failed to send wallet reset persistence failure");
                                    }
                                    continue;
                                }
                                Err(reason) => {
                                    let result = WalletBackfillResetResult::Rejected {
                                        committed_to: last_scanned,
                                        reason,
                                    };
                                    if let Err(err) = response.send(result) {
                                        debug!(?err, cache_key = %cfg.cache_key, "failed to send reset acceptance rejection");
                                    }
                                    continue;
                                }
                            }
                            drop(acceptance_permit);
                            let outcome = try_drive_pending_reset!(true)
                                .expect("pending reset was installed before commit");
                            // Accept already succeeded: public result is always Accepted.
                            let result =
                                reset_result_after_accept(next_reset_generation, outcome);
                            if let Err(err) = response.send(result) {
                                debug!(?err, cache_key = %cfg.cache_key, "failed to send wallet reset result");
                            }
                        }
                    }
                }
                result = live_rx.recv(), if backfill_complete_block.is_some() && actor_state.pending_reset().is_none() => {
                    match result {
                        Ok(batch) => {
                            if cfg.sync_to_block.is_some() {
                                continue;
                            }
                            if backfill_complete_block.is_none()
                                || batch.to_block <= last_scanned
                            {
                                live_receiver_lagged = false;
                                continue;
                            }
                            let expected_from_block = last_scanned.saturating_add(1);
                            if batch.from_block > expected_from_block {
                                warn!(
                                    cache_key = %cfg.cache_key,
                                    expected_from_block,
                                    batch_from_block = batch.from_block,
                                    batch_to_block = batch.to_block,
                                    live_receiver_lagged,
                                    "wallet live log gap detected; requesting backfill"
                                );
                                let current_reset_generation = actor_state.reset_generation();
                                let token = worker_handle.mint_sync_token(current_reset_generation);
                                let accepted = actor_state
                                    .transition_active(&worker_handle, &cancel, |mut state| {
                                        state.accept_target(token, batch.to_block)
                                    })
                                    .unwrap_or(false);
                                if !accepted {
                                    continue;
                                }
                                let (liveness, receiver) = oneshot::channel();
                                accepted_backfill_liveness
                                    .push(accepted_backfill_owner_dropped(token, receiver));
                                let driver = WalletBackfillGrant::for_actor_accepted_job_with_cancel(
                                    token,
                                    backfill_sender.clone(),
                                    liveness,
                                    cancel.clone(),
                                )
                                .activate();
                                match backfill_tx.try_send(BackfillRequest::add(
                                    cfg.cache_key.clone(),
                                    expected_from_block,
                                    batch.to_block,
                                    true,
                                    expected_from_block,
                                    driver,
                                )) {
                                    Ok(()) => {
                                        let _ = actor_state.transition_active(
                                            &worker_handle,
                                            &cancel,
                                            |mut state| state.backfill_dispatch_admitted(token),
                                        );
                                        backfill_complete_block = None;
                                        live_rx = live_rx.resubscribe();
                                    }
                                    Err(err) => {
                                        warn!(?err, cache_key = %cfg.cache_key, "failed to request wallet live gap backfill");
                                        let _ = actor_state.transition_active(
                                            &worker_handle,
                                            &cancel,
                                            |mut state| {
                                                state.fail_job_backfill_unavailable(token);
                                            },
                                        );
                                    }
                                }
                                live_receiver_lagged = false;
                                continue;
                            }
                            live_receiver_lagged = false;
                            // POI status refresh is never inline on live scan (may be remote).
                            // request_poi_maintenance runs after successful commit.
                            let apply = match WalletScanApply::rows_from_log_batch(
                                expected_from_block,
                                batch.to_block,
                                &batch,
                                PublicScanSource::Rpc,
                            ) {
                                Ok(apply) => apply,
                                Err(err) => {
                                    warn!(?err, cache_key = %cfg.cache_key, from_block = expected_from_block, to_block = batch.to_block, "failed to normalize wallet live logs");
                                    continue;
                                }
                            };
                            let current_reset_generation = actor_state.reset_generation();
                            let live_token = worker_handle.mint_sync_token(current_reset_generation);
                            let accepted = actor_state
                                .transition_active(&worker_handle, &cancel, |mut state| {
                                    state.accept_target(live_token, batch.to_block)
                                })
                                .unwrap_or(false);
                            if !accepted {
                                continue;
                            }
                            let outcome = WalletScanCommitRequest {
                                cache_store: cache_store.as_ref(),
                                cfg: &cfg,
                                utxos: &utxos,
                                worker_handle: &worker_handle,
                                apply,
                                job_token: live_token,
                                current_reset_generation,
                                event_reset_generation: live_token.reset_generation(),
                                actor_state: &mut actor_state,
                                cancel: &cancel,
                                last_scanned: &mut last_scanned,
                                persist_state: &mut persist_state,
                                live_metadata_flush: &mut live_metadata_flush,
                                public_data_plane: &public_data_plane,
                            }
                            .commit()
                            .await;
                            match outcome.result {
                                WalletBackfillApplyResult::Committed { .. }
                                | WalletBackfillApplyResult::AlreadyCovered { .. } => {
                                    let _ = actor_state.transition_active(
                                        &worker_handle,
                                        &cancel,
                                        |mut state| state.retire_job(live_token),
                                    );
                                    if outcome.changed && poi_status_client.is_some() {
                                        let _ = request_poi_maintenance(
                                            &mut poi_maintenance,
                                            &remote_done_tx,
                                            &private_apply,
                                            &poi_jobs,
                                            &poi_refreshing_tx,
                                            &worker_handle,
                                            &cancel,
                                            &db,
                                            &cache_store,
                                            &cfg,
                                            &public_data_plane,
                                            http_client.as_ref(),
                                            indexed_artifact_source.as_ref(),
                                            &poi_runtime,
                                            &poi_submitter,
                                            &forest,
                                            &utxos,
                                            &active_poi_list_keys,
                                            false,
                                        );
                                    }
                                }
                                WalletBackfillApplyResult::Rejected {
                                    reason: WalletBackfillRejectReason::PersistenceFailed,
                                    ..
                                } => {
                                    // Keep the accepted live job as the owner of its exact failed
                                    // range and let the normal backfill loop apply persistence backoff.
                                    let (liveness, receiver) = oneshot::channel();
                                    accepted_backfill_liveness.push(
                                        accepted_backfill_owner_dropped(live_token, receiver),
                                    );
                                    let driver = WalletBackfillGrant::for_actor_accepted_job_with_cancel(
                                        live_token,
                                        backfill_sender.clone(),
                                        liveness,
                                        cancel.clone(),
                                    )
                                    .activate();
                                    let retry = BackfillRequest::add(
                                        cfg.cache_key.clone(),
                                        expected_from_block,
                                        batch.to_block,
                                        false,
                                        expected_from_block,
                                        driver,
                                    );
                                    match backfill_tx.try_send(retry) {
                                        Ok(()) => {
                                            let _ = actor_state.transition_active(
                                                &worker_handle,
                                                &cancel,
                                                |mut state| {
                                                    state.backfill_dispatch_admitted(live_token)
                                                },
                                            );
                                            backfill_complete_block = None;
                                            live_rx = live_rx.resubscribe();
                                        }
                                        Err(err) => {
                                            warn!(?err, cache_key = %cfg.cache_key, from_block = expected_from_block, to_block = batch.to_block, "failed to enqueue wallet live persistence retry");
                                            let _ = actor_state.transition_active(
                                                &worker_handle,
                                                &cancel,
                                                |mut state| {
                                                    state.fail_job_backfill_unavailable(live_token);
                                                },
                                            );
                                        }
                                    }
                                }
                                WalletBackfillApplyResult::Rejected { reason, .. } => {
                                    let _ = actor_state.transition_active(
                                        &worker_handle,
                                        &cancel,
                                        |mut state| state.retire_job(live_token),
                                    );
                                    warn!(?reason, cache_key = %cfg.cache_key, "wallet live scan batch rejected");
                                }
                            }
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            live_receiver_lagged = true;
                            warn!(cache_key = %cfg.cache_key, skipped, "wallet live log receiver lagged");
                        }
                    }
                }
            }
        }
        // Cancellation and terminal observation share the lifecycle fence. Registration
        // retirement may win first, in which case this epilogue cannot publish again.
        let _ = worker_handle.publish_terminal_shutdown_if_allowed(|token| {
            actor_state.transition_terminal_shutdown(
                &token,
                WalletInactiveReason::Shutdown,
                worker_handle.authority_reset_generation(),
            );
            if let Err(err) = worker_handle.indexed_catch_up_tx.send(None) {
                debug!(?err, cache_key = %cfg.cache_key, "failed to clear indexed wallet catch-up status on shutdown");
            }
        });
    }
    .instrument(tracing::info_span!("wallet", chain_id)));
    let worker = tokio::spawn(async move {
        if let Err(err) = actor_worker.await {
            warn!(?err, cache_key = %worker_cache_key, "wallet worker task failed");
            worker_panic_handle.terminalize_panicked_actor(&worker_observation);
        }
        supervisor_poi_jobs.shutdown().await;
    });

    let prepared = PreparedWalletWorker {
        handle: Some(handle),
        has_restored_pending_reset,
        cancel: prepared_cancel,
        activation_tx: Some(activation_tx),
        worker: Some(worker),
        observation,
    };
    if let Some(startup_replay_rx) = startup_replay_rx {
        startup_replay_rx
            .await
            .map_err(|_| ChainError::WalletResetFailed)?;
    }
    Ok(prepared)
}

pub(crate) fn wallet_cache_store(
    db: &Arc<DbStore>,
    cfg: &WalletConfig,
) -> Arc<dyn WalletCacheStore> {
    cfg.cache_store
        .clone()
        .unwrap_or_else(|| Arc::clone(db) as Arc<dyn WalletCacheStore>)
}

pub(super) fn dedupe_wallet_utxos(utxos: &mut Vec<WalletUtxo>) {
    let mut seen = HashSet::new();
    utxos.retain(|wallet_utxo| seen.insert((wallet_utxo.utxo.tree, wallet_utxo.utxo.position)));
}

fn wallet_utxo_counts(utxos: &[WalletUtxo]) -> (usize, usize) {
    let spent = utxos.iter().filter(|utxo| utxo.is_spent()).count();
    (utxos.len().saturating_sub(spent), spent)
}

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod tests;
