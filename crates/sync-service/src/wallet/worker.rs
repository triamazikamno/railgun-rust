use super::handle::LOCAL_PENDING_SPENT_TTL;
use super::pending_output_poi::pending_output_poi_handoff_context;
use super::{
    Arc, AtomicU64, BackfillEvent, CancellationToken, ChainError, ChainPublicDataPlane, DbStore,
    DeferredForcedSubmissions, Duration, FixedBytes, FuturesUnordered, HashSet,
    IndexedArtifactSourceConfig, Instant, Instrument, LocalPoiStatusReader, MerkleForest, Mutex,
    OutputPoiRecoveryRun, PendingOutputPoiContextIntent, PendingOutputPoiTentativeAttemptKey,
    PendingOutputPoiTentativeCandidate, PendingOutputPoiTentativeLocalStatus, PendingWalletReset,
    PoiMaintenanceController, PoiMaintenanceError, PoiPrivateRows, PoiProxyFallback,
    PoiRemoteJobKey, PoiRpcClient, PoiStatusReader, PublicPoiCorpusHandle, PublicPoiCorpusKey,
    RwLock, SenderCandidateRecoveryReport, SenderUnshieldAttempts, SharedLogBatch,
    SyncProgressStage, SyncProgressUpdate, WALLET_POI_REFRESH_INTERVAL, WalletActorCommitToken,
    WalletActorCredential, WalletActorLifecycleCell, WalletActorState, WalletBackfillApplyResult,
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

mod actor_loop;
mod commit;
mod local_pending_spent;
mod output_poi;
mod poi_maintenance;

use actor_loop::WalletActorLoop;
use commit::{
    AcceptedBackfillOwnerDropped, AcceptedIndexedJobOwnerDropped, WALLET_RESET_RETRY_INTERVAL,
    WalletBackfillDoneOutcome, WalletPoiStatusRefreshCommitRequest, WalletResetCommitOutcome,
    WalletResetCommitRequest, WalletResetRewindOutcome, WalletScanCommitRequest,
    accepted_backfill_owner_dropped, accepted_indexed_job_owner_dropped,
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
    wallet_poi_refresh_interval,
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
        PoiPrivateRows::default(),
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
        let last_scanned = initial_last_scanned;
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

        let backfill_complete_block: Option<u64> = None;
        let mut live_receiver_lagged = false;
        let persist_state = WalletPersistState::default();
        let live_metadata_flush = WalletLiveMetadataFlush::new(last_scanned, worker_started);
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

        let readiness_started = worker_started;
        let (remote_done_tx, mut remote_done_rx) = mpsc::channel::<WalletRemoteDone>(8);
        // Jobs re-enter here for private POI commits; actor is sole UTXO mirror writer.
        let (private_apply_tx, mut private_apply_rx) =
            mpsc::channel::<WalletPrivateApplyRequest>(32);
        let private_apply = WalletPrivateApplyClient::new(private_apply_tx);
        let poi_maintenance = PoiMaintenanceController::new();
        // Tentative attempts are actor-lifetime only; safe-head maintenance never consults this set.
        let mut pending_output_poi_tentative_attempts =
            PendingOutputPoiTentativeAttemptTracker::default();
        let mut actor = WalletActorLoop {
            cfg,
            cache_store,
            utxos,
            worker_handle,
            cancel,
            poi_runtime: &poi_runtime,
            public_data_plane,
            active_poi_list_keys,
            actor_state,
            persist_state,
            last_scanned,
            db,
            poi_submitter,
            accepted_backfill_liveness: FuturesUnordered::new(),
            accepted_indexed_job_liveness: FuturesUnordered::new(),
            live_metadata_flush,
            readiness_started,
            backfill_complete_block,
            backfill_sender,
            backfill_tx,
            poi_maintenance,
            remote_done_tx,
            private_apply,
            poi_jobs,
            poi_refreshing_tx,
            http_client,
            indexed_artifact_source,
            forest,
        };
        macro_rules! apply_backfill_done {
            ($last_block:expr, $token:expr) => {{
                let last_block = $last_block;
                let job_token = $token;
                let current_reset_generation = actor.actor_state.reset_generation();
                let should_persist = actor.persist_state.needs_full_persist
                    || actor.persist_state.pending_cache_reset.is_some();
                let authority = WalletPrivateMutationAuthority::new(
                    &actor.worker_handle,
                    current_reset_generation,
                    &actor.cancel,
                );
                let snapshot = actor.utxos.read().await;
                let persist_result = if should_persist {
                    match authority.acquire().await {
                        Ok(permit) => {
                            let persisted = match actor.persist_state.persist_progress(
                                actor.cache_store.as_ref(),
                                &permit,
                                WalletProgressPersist {
                                    cache_key: &actor.cfg.cache_key,
                                    snapshot: &snapshot,
                                    last_scanned: actor.last_scanned,
                                    checkpoint: WalletCheckpointMutation::Preserve,
                                    changed: false,
                                },
                            ) {
                                Ok(_) => {
                                    actor.live_metadata_flush.mark_persisted(actor.last_scanned, Instant::now());
                                    Ok(())
                                }
                                Err(err) => {
                                    warn!(?err, cache_key = %actor.cfg.cache_key, "failed to update wallet cache metadata");
                                    Err(WalletBackfillRejectReason::PersistenceFailed)
                                }
                            };
                            persisted
                        }
                        Err(reason) => {
                            warn!(?reason, cache_key = %actor.cfg.cache_key, "wallet target metadata persist rejected");
                            Err(reason)
                        }
                    }
                } else {
                    Ok(())
                };
                drop(snapshot);
                if let Err(reason) = persist_result {
                    WalletBackfillDoneOutcome::Rejected(reason)
                } else if let Err(reason) = actor.actor_state.transition_active(
                    &actor.worker_handle,
                    &actor.cancel,
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
                        let _ = actor.actor_state.transition_active(
                            &actor.worker_handle,
                            &actor.cancel,
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
                        let locked = actor.utxos.read().await;
                        actor.actor_state.has_failed_poi_status_refresh(
                            current_reset_generation,
                            pre_ready_selection,
                        ) || wallet_poi_status_refresh_needed_for_selection(
                            &locked,
                            &actor.active_poi_list_keys,
                            pre_ready_selection,
                        )
                    };
                    if refresh_needed {
                        // Actor-safe: only local corpus (never remote proxy/fallback).
                        if let Some(status_reader) = actor.poi_runtime
                            .local_status_reader(&actor.public_data_plane, &actor.cfg, &actor.active_poi_list_keys)
                            .await
                        {
                            pre_ready_local_cache_available = true;
                            let status_refresh_started = Instant::now();
                            match (WalletPoiStatusRefreshCommitRequest {
                                cache_store: actor.cache_store.as_ref(),
                                cfg: &actor.cfg,
                                utxos: &actor.utxos,
                                worker_handle: &actor.worker_handle,
                                last_scanned: actor.last_scanned,
                                reset_generation: current_reset_generation,
                                actor_state: &mut actor.actor_state,
                                persist_state: &mut actor.persist_state,
                                status_reader: &status_reader,
                                active_poi_list_keys: &actor.active_poi_list_keys,
                                selection: pre_ready_selection,
                                cancel: &actor.cancel,
                            })
                            .commit()
                            .await
                            {
                                Ok(changed) => {
                                    pre_ready_poi_status_changed = changed;
                                }
                                Err(reason) => {
                                    warn!(?reason, cache_key = %actor.cfg.cache_key, "pre-ready wallet POI status refresh rejected");
                                    pre_ready_poi_status_rejection = Some(reason);
                                }
                            }
                            pre_ready_poi_status_refresh_elapsed_ms =
                                status_refresh_started.elapsed().as_millis();
                            debug!(
                                cache_key = %actor.cfg.cache_key,
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
                        let _ = actor.actor_state.transition_active(
                            &actor.worker_handle,
                            &actor.cancel,
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
                        let _ = actor.actor_state.transition_active(
                            &actor.worker_handle,
                            &actor.cancel,
                            |mut state| state.set_poi_corpus_refresh_pending(false),
                        );
                    }
                } else if blocked_shield_refresh_pending {
                    pre_ready_poi_status_rejection = Some(WalletBackfillRejectReason::ApplyFailed);
                }
                if let Some(reason) = pre_ready_poi_status_rejection {
                    WalletBackfillDoneOutcome::Rejected(reason)
                } else {
                let snapshot = actor.utxos.read().await;
                let (unspent, spent) = wallet_utxo_counts(&snapshot);
                actor.backfill_complete_block = Some(last_block);
                info!(
                    cache_key = %actor.cfg.cache_key,
                    last_scanned = actor.last_scanned,
                    total = snapshot.len(),
                    unspent,
                    spent,
                    pre_ready_poi_status_changed,
                    pre_ready_local_cache_available,
                    pre_ready_poi_status_refresh_elapsed_ms,
                    ready_elapsed_ms = actor.readiness_started.elapsed().as_millis(),
                    worker_elapsed_ms = worker_started.elapsed().as_millis(),
                    "wallet backfill complete"
                );
                drop(snapshot);
                tokio::task::yield_now().await;

                if poi_status_client.is_some() {
                    let post_ready_selection = WalletPoiRefreshSelection::RequiredOrRecoverable;
                    let refresh_needed = {
                        let locked = actor.utxos.read().await;
                        actor.actor_state.has_failed_poi_status_refresh(
                            current_reset_generation,
                            post_ready_selection,
                        ) || wallet_poi_status_refresh_needed_for_selection(
                            &locked,
                            &actor.active_poi_list_keys,
                            post_ready_selection,
                        )
                    };
                    if refresh_needed
                        && let Some(status_reader) = actor.poi_runtime
                            .local_status_reader(&actor.public_data_plane, &actor.cfg, &actor.active_poi_list_keys)
                            .await
                    {
                        match (WalletPoiStatusRefreshCommitRequest {
                            cache_store: actor.cache_store.as_ref(),
                            cfg: &actor.cfg,
                            utxos: &actor.utxos,
                            worker_handle: &actor.worker_handle,
                            last_scanned: actor.last_scanned,
                            reset_generation: current_reset_generation,
                            actor_state: &mut actor.actor_state,
                            persist_state: &mut actor.persist_state,
                            status_reader: &status_reader,
                            active_poi_list_keys: &actor.active_poi_list_keys,
                            selection: post_ready_selection,
                            cancel: &actor.cancel,
                        })
                        .commit()
                        .await
                        {
                            Ok(changed) => {
                                debug!(
                                    cache_key = %actor.cfg.cache_key,
                                    changed,
                                    "post-ready local wallet POI status refresh committed"
                                );
                            }
                            Err(reason) => {
                                warn!(?reason, cache_key = %actor.cfg.cache_key, "post-ready wallet POI status refresh rejected");
                            }
                        }
                    }
                    let _ = actor.request_poi_maintenance(false);
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
        if actor.actor_state.pending_reset().is_some() && actor.try_drive_pending_reset(&mut live_rx, false).await.is_some() {
            signal_restored_reset_attempt(&mut startup_replay_tx);
        }

        // Prepared-worker cancellation drops the sender, so this cannot hang. Once activation is
        // accepted, let the active loop observe cancellation and publish terminal readiness.
        let activated = activation_rx.await.is_ok();
        if !activated {
            return;
        }
        if actor.actor_state.pending_reset().is_some() {
            let _ = actor.try_drive_pending_reset(&mut live_rx, true).await;
        }
        loop {
            tokio::select! {
                () = actor.cancel.cancelled() => break,
                expiry = wait_for_local_pending_spent_expiry(&actor.worker_handle) => {
                    if let Err(error) = expire_local_pending_spent(
                        &actor.worker_handle,
                        &actor.cancel,
                        actor.actor_state.reset_generation(),
                        expiry,
                    ).await {
                        debug!(%error, cache_key = %actor.cfg.cache_key, "local pending-spend expiry skipped");
                    }
                }
                Some((token, signal)) = actor.accepted_backfill_liveness.next(), if !actor.accepted_backfill_liveness.is_empty() => {
                    let WalletBackfillOwnerSignal {
                        disposition,
                        acknowledgement,
                    } = signal;
                    let changed = actor.actor_state
                        .transition_active(&actor.worker_handle, &actor.cancel, |mut state| {
                            state.apply_backfill_owner_disposition(token, disposition)
                        })
                        .unwrap_or(false);
                    if changed {
                        if disposition == WalletBackfillOwnerDisposition::BenignRetirement
                            && !actor.actor_state.has_active_backfill_job()
                        {
                            actor.backfill_complete_block = actor.actor_state.completed_target_block();
                            if poi_corpus_revision_rx.as_ref().is_some_and(|revision_rx| {
                                *revision_rx.borrow() != last_poi_corpus_revision
                            }) {
                                let _ = actor.actor_state.transition_active(
                                    &actor.worker_handle,
                                    &actor.cancel,
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
                                let _ = actor.actor_state.transition_active(
                                    &actor.worker_handle,
                                    &actor.cancel,
                                    |mut state| {
                                        state.observe_poi_corpus_revision(revision_changed);
                                    },
                                );
                                last_poi_corpus_revision = revision;
                                blocked_shield_refresh_pending |= blocked_shields_changed;
                                if actor.actor_state.poi_corpus_refresh_pending() {
                                    let selection = WalletPoiRefreshSelection::CorpusRevision {
                                        blocked_shields_changed: blocked_shield_refresh_pending,
                                    };
                                    let result = actor.commit_local_poi_status_refresh(selection).await;
                                    let refresh_still_needed = result.is_none() && {
                                        let locked = actor.utxos.read().await;
                                        wallet_poi_status_refresh_needed_for_selection(
                                            &locked,
                                            &actor.active_poi_list_keys,
                                            selection,
                                        )
                                    };
                                    match result {
                                        None if refresh_still_needed => {
                                            let _ = actor.actor_state.transition_active(
                                                &actor.worker_handle,
                                                &actor.cancel,
                                                |mut state| {
                                                    state.set_poi_corpus_refresh_pending(true);
                                                },
                                            );
                                        }
                                        Some(Ok(_)) | None => {
                                            blocked_shield_refresh_pending = false;
                                            let _ = actor.actor_state.transition_active(
                                                &actor.worker_handle,
                                                &actor.cancel,
                                                |mut state| {
                                                    state.set_poi_corpus_refresh_pending(false);
                                                },
                                            );
                                        }
                                        Some(Err(reason)) => {
                                            warn!(?reason, cache_key = %actor.cfg.cache_key, "target retirement POI status refresh rejected");
                                            let _ = actor.actor_state.transition_active(
                                                &actor.worker_handle,
                                                &actor.cancel,
                                                |mut state| {
                                                    state.set_poi_corpus_refresh_pending(true);
                                                },
                                            );
                                        }
                                    }
                                }
                            }
                        } else if disposition == WalletBackfillOwnerDisposition::DriverLost {
                            actor.backfill_complete_block = None;
                        }
                    }
                    if let Some(acknowledgement) = acknowledgement {
                        let _ = acknowledgement.send(());
                    }
                }
                Some(token) = actor.accepted_indexed_job_liveness.next(), if !actor.accepted_indexed_job_liveness.is_empty() => {
                    let retired = actor.actor_state
                        .transition_active(&actor.worker_handle, &actor.cancel, |mut state| {
                            state.retire_job(token)
                        })
                        .unwrap_or(false);
                    if retired {
                        let authority = WalletPrivateMutationAuthority::new(
                            &actor.worker_handle,
                            actor.actor_state.reset_generation(),
                            &actor.cancel,
                        );
                        if let Ok(permit) = authority.acquire().await
                            && let Err(reason) = permit.publish_indexed_catch_up(None)
                        {
                            debug!(?reason, cache_key = %actor.cfg.cache_key, "indexed wallet catch-up abandonment status clear rejected");
                        }
                    }
                }
                Some(apply_req) = private_apply_rx.recv() => actor.handle_private_apply(apply_req).await,
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
                            actor.on_poi_maintenance_done(key);
                            if !credential.is_current(&actor.worker_handle) {
                                debug!(
                                    cache_key = %actor.cfg.cache_key,
                                    ?key,
                                    "stale poi maintenance result dropped"
                                );
                                continue;
                            }
                            if recovered > 0 {
                                let authority = WalletPrivateMutationAuthority::new(
                                    &actor.worker_handle,
                                    actor.actor_state.reset_generation(),
                                    &actor.cancel,
                                );
                                authority
                                    .notify_changed_if(true, "poi_maintenance_remote_done")
                                    .await;
                            }
                            let published = maintenance_observation.ppoi_workflow_status();
                            let candidate_report_is_current = actor.cache_store
                                .list_sender_transaction_candidates(
                                    actor.cfg.chain.chain_id,
                                    &actor.cfg.cache_key,
                                )
                                .is_ok_and(|candidates| {
                                    candidate_report.matches_candidates(&candidates)
                                        && candidate_report.matches_pending_contexts(actor.cache_store.as_ref(), &actor.cfg).unwrap_or(false)
                                });
                            let refined = if candidate_report_is_current {
                                current_ppoi_workflow_status_for_candidate_report(
                                    actor.cache_store.as_ref(),
                                    &actor.cfg,
                                    &actor.active_poi_list_keys,
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
                                    cache_key = %actor.cfg.cache_key,
                                    "wallet POI remote maintenance completed with candidate recovery error"
                                );
                            }
                            debug!(
                                cache_key = %actor.cfg.cache_key,
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
                            actor.on_poi_maintenance_done(key);
                            if credential.is_current(&actor.worker_handle) {
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
                            if !credential.is_current(&actor.worker_handle) {
                                debug!("stale tentative pending output POI result dropped");
                                continue;
                            }
                            pending_output_poi_tentative_attempts
                                .accept(credential.reset_generation, &accepted_candidates);
                            pending_output_poi_tentative_attempts
                                .release_retryable(credential.reset_generation, &retryable);
                            if !accepted_candidates.is_empty() {
                                refresh_tentative_pending_output_poi_statuses(
                                    &actor.worker_handle,
                                    &actor.cancel,
                                    poi_corpus_handle.as_ref(),
                                    &actor.cfg,
                                    &actor.active_poi_list_keys,
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
                _ = pending_reset_retry.tick(), if actor.actor_state.pending_reset().is_some() => {
                    if let Some(outcome) = actor.try_drive_pending_reset(&mut live_rx, true).await {
                        debug!(?outcome.rewind, cache_key = %actor.cfg.cache_key, "wallet pending reset retry completed");
                        signal_restored_reset_attempt(&mut startup_replay_tx);
                    }
                }
                Some(refresh_request) = poi_refresh_rx.recv() => {
                    let Some(_client) = poi_status_client.as_ref() else {
                        continue;
                    };
                    if actor.actor_state.pending_reset().is_some() {
                        let _ = actor.poi_maintenance.request(
                            refresh_request.force_output_poi_recovery,
                            false,
                            None,
                        );
                        debug!(
                            cache_key = %actor.cfg.cache_key,
                            "wallet POI refresh latched while reset commit is pending"
                        );
                        continue;
                    }
                    if actor.backfill_complete_block.is_none() {
                        let _ = actor.poi_maintenance.request(
                            refresh_request.force_output_poi_recovery,
                            false,
                            None,
                        );
                        debug!(
                            cache_key = %actor.cfg.cache_key,
                            "wallet POI refresh latched until backfill complete"
                        );
                        continue;
                    }
                    let current_reset_generation = actor.actor_state.reset_generation();
                    // Local-only status refresh on actor; remote readers must not block the loop.
                    if let Some(status_reader) = actor.poi_runtime
                        .local_status_reader(&actor.public_data_plane, &actor.cfg, &actor.active_poi_list_keys)
                        .await
                    {
                        match (WalletPoiStatusRefreshCommitRequest {
                            cache_store: actor.cache_store.as_ref(),
                            cfg: &actor.cfg,
                            utxos: &actor.utxos,
                            worker_handle: &actor.worker_handle,
                            last_scanned: actor.last_scanned,
                            reset_generation: current_reset_generation,
                            actor_state: &mut actor.actor_state,
                            persist_state: &mut actor.persist_state,
                            status_reader: &status_reader,
                            active_poi_list_keys: &actor.active_poi_list_keys,
                            selection: WalletPoiRefreshSelection::Recoverable,
                            cancel: &actor.cancel,
                        })
                        .commit()
                        .await
                        {
                            Ok(changed) => {
                                debug!(
                                    cache_key = %actor.cfg.cache_key,
                                    changed,
                                    "manual local wallet POI status refresh committed"
                                );
                            }
                            Err(reason) => {
                                warn!(?reason, cache_key = %actor.cfg.cache_key, "manual wallet POI status refresh rejected");
                            }
                        }
                    }
                    let _ = actor.request_poi_maintenance(refresh_request.force_output_poi_recovery);
                }
                Some(command) = indexed_catch_up_status_rx.recv() => {
                    let authority = WalletPrivateMutationAuthority::new(
                        &actor.worker_handle,
                        actor.actor_state.reset_generation(),
                        &actor.cancel,
                    );
                    match authority.acquire().await {
                        Ok(permit) => {
                            match command {
                                WalletIndexedCatchUpCommand::Claim { response } => {
                                    let token =
                                        actor.worker_handle.mint_sync_token(actor.actor_state.reset_generation());
                                    let accepted = permit
                                        .with_active_apply(|apply_token| {
                                            actor.actor_state.transition(&apply_token, |mut state| {
                                                state.accept_indexed_catch_up(token)
                                            })
                                        })
                                        .unwrap_or(false);
                                    let lease = if accepted {
                                        let (liveness, receiver) = oneshot::channel();
                                        actor.accepted_indexed_job_liveness
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
                                                actor.actor_state.transition(&apply_token, |mut state| {
                                                    state.retire_job(token)
                                                })
                                            })
                                            .unwrap_or(false);
                                        if retired
                                            && let Err(reason) =
                                                permit.publish_indexed_catch_up(None)
                                        {
                                            debug!(?reason, cache_key = %actor.cfg.cache_key, "indexed wallet catch-up dropped-claim status clear rejected");
                                        }
                                        debug!(cache_key = %actor.cfg.cache_key, ?token, "indexed wallet catch-up claim receiver dropped");
                                    }
                                }
                                WalletIndexedCatchUpCommand::Publish { token, status } => {
                                    let published = permit
                                        .with_active_apply(|apply_token| {
                                            actor.actor_state.transition(&apply_token, |mut state| {
                                                state.publish_indexed_catch_up(token, status)
                                            })
                                        })
                                        .unwrap_or(false);
                                    if published {
                                        if let Err(reason) =
                                            permit.publish_indexed_catch_up(Some(status))
                                        {
                                            debug!(?reason, cache_key = %actor.cfg.cache_key, "indexed wallet catch-up status publication rejected");
                                        }
                                    } else {
                                        debug!(cache_key = %actor.cfg.cache_key, ?token, "stale indexed wallet catch-up status publication ignored");
                                    }
                                }
                            }
                        }
                        Err(reason) => {
                            if let WalletIndexedCatchUpCommand::Claim { response } = command {
                                let _ = response.send(None);
                            }
                            debug!(?reason, cache_key = %actor.cfg.cache_key, "indexed wallet catch-up status publication skipped");
                        }
                    }
                }
                Some(request) = private_request_rx.recv() => actor.handle_private_request(request).await,
                Some(request) = pending_overlay_rx.recv() => {
                    let current_reset_generation = actor.actor_state.reset_generation();
                    let request_is_current = actor.actor_state.pending_reset().is_none()
                        && request.reset_generation == current_reset_generation
                        && request.last_scanned == actor.last_scanned;
                    let accepted = request_is_current
                        && actor.actor_state
                            .transition_active(&actor.worker_handle, &actor.cancel, |mut state| {
                                state.accept_pending_overlay(request.token, request.last_scanned)
                            })
                            .unwrap_or(false);
                    if !accepted {
                        debug!(
                            cache_key = %actor.cfg.cache_key,
                            token = ?request.token,
                            request_reset_generation = request.reset_generation,
                            current_reset_generation,
                            request_last_scanned = request.last_scanned,
                            current_last_scanned = actor.last_scanned,
                            pending_reset = actor.actor_state.pending_reset().is_some(),
                            "ignoring stale pending overlay update"
                        );
                        continue;
                    }
                    pending_output_poi_tentative_attempts
                        .clear_generation(current_reset_generation);
                    let authority = WalletPrivateMutationAuthority::new(
                        &actor.worker_handle,
                        current_reset_generation,
                        &actor.cancel,
                    );
                    let permit = match authority.acquire().await {
                        Ok(guard) => guard,
                        Err(reason) => {
                            debug!(?reason, cache_key = %actor.cfg.cache_key, "pending overlay update rejected");
                            let _ = actor.actor_state.transition_active(
                                &actor.worker_handle,
                                &actor.cancel,
                                |mut state| state.retire_job(request.token),
                            );
                            continue;
                        }
                    };
                    if !actor.actor_state.pending_overlay_is_current(request.token, request.last_scanned)
                        || permit.revalidate().is_err()
                    {
                        let _ = permit.with_active_apply(|token| {
                            actor.actor_state.transition(&token, |mut state| {
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
                                    WalletLogDelta::from_rows(&rows, &actor.cfg.scan_keys)
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
                                actor.actor_state.reset_generation(),
                                &tentative_observations,
                            );
                            let delta = WalletLogDelta {
                                commitment_observations: Vec::new(),
                                ..delta
                            };
                            let confirmed = actor.utxos.read().await;
                            if !actor.actor_state
                                .pending_overlay_is_current(request.token, request.last_scanned)
                                || permit.revalidate().is_err()
                            {
                                let _ = permit.with_active_apply(|token| {
                                    actor.actor_state.transition(&token, |mut state| {
                                        state.retire_job(request.token);
                                    });
                                });
                                continue;
                            }
                            pending_overlay_from_delta(&actor.cfg, &confirmed, delta)
                        }
                    };
                    pending_output_poi_tentative_attempts.apply_to_overlay(
                        actor.actor_state.reset_generation(),
                        &mut overlay,
                        now_epoch_secs(),
                    );
                    let changed = match permit.replace_chain_pending_overlay(overlay).await {
                        Ok(changed) => changed,
                        Err(reason) => {
                            debug!(?reason, cache_key = %actor.cfg.cache_key, "pending overlay update rejected before publication");
                            let _ = permit.with_active_apply(|token| {
                                actor.actor_state.transition(&token, |mut state| {
                                    state.retire_job(request.token);
                                });
                            });
                            continue;
                        }
                    };
                    if let Err(reason) = permit.notify_if_changed(changed).await {
                        debug!(?reason, cache_key = %actor.cfg.cache_key, "pending overlay revision publication rejected");
                    }
                    let _ = permit.with_active_apply(|token| {
                        actor.actor_state.transition(&token, |mut state| {
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
                                actor.cache_store.as_ref(),
                                &actor.cfg,
                                &actor.active_poi_list_keys,
                                &tentative_observations,
                            )
                            {
                                Ok(candidates) => {
                                    candidate_count = candidates.len();
                                    let reserved = candidates
                                        .into_iter()
                                        .filter(|candidate| {
                                            pending_output_poi_tentative_attempts.reserve(
                                                actor.actor_state.reset_generation(),
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
                                &actor.poi_jobs,
                                &actor.worker_handle,
                                &actor.cancel,
                                &actor.remote_done_tx,
                                &actor.cache_store,
                                &actor.cfg,
                                actor.poi_runtime,
                                &actor.poi_submitter,
                                &actor.active_poi_list_keys,
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
                    let _ = actor.actor_state.transition_active(
                        &actor.worker_handle,
                        &actor.cancel,
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
                        &actor.worker_handle,
                        &actor.cancel,
                        poi_corpus_handle.as_ref(),
                        &actor.cfg,
                        &actor.active_poi_list_keys,
                        actor.actor_state.reset_generation(),
                        &mut pending_output_poi_tentative_attempts,
                    )
                    .await;
                    let _ = actor.actor_state.transition_active(
                        &actor.worker_handle,
                        &actor.cancel,
                        |mut state| {
                            state.observe_poi_corpus_revision(
                                revision != last_poi_corpus_revision,
                            );
                        },
                    );
                    debug!(
                        cache_key = %actor.cfg.cache_key,
                        revision = revision.revision,
                        blocked_shields_revision = revision.blocked_shields_revision,
                        backfill_complete = actor.backfill_complete_block.is_some(),
                        reset_pending = actor.actor_state.pending_reset().is_some(),
                        "committed PPOI corpus revision observed"
                    );
                    let blocked_shields_changed = revision.blocked_shields_revision
                        != last_poi_corpus_revision.blocked_shields_revision;
                    last_poi_corpus_revision = revision;
                    blocked_shield_refresh_pending |= blocked_shields_changed;
                    if actor.backfill_complete_block.is_some()
                        && actor.actor_state.pending_reset().is_none()
                        && let Some(result) = actor.commit_local_poi_status_refresh(
                            WalletPoiRefreshSelection::CorpusRevision {
                                blocked_shields_changed: blocked_shield_refresh_pending,
                            }
                        ).await
                    {
                        match result {
                            Ok(changed) => {
                                blocked_shield_refresh_pending = false;
                                let _ = actor.actor_state.transition_active(
                                    &actor.worker_handle,
                                    &actor.cancel,
                                    |mut state| state.set_poi_corpus_refresh_pending(false),
                                );
                                debug!(
                                    cache_key = %actor.cfg.cache_key,
                                    revision = revision.revision,
                                    changed,
                                    "corpus revision local wallet POI status refresh committed"
                                );
                            }
                            Err(reason) => warn!(
                                ?reason,
                                cache_key = %actor.cfg.cache_key,
                                revision = revision.revision,
                                "corpus revision wallet POI status refresh rejected"
                            ),
                        }
                    }
                    if actor.actor_state.poi_corpus_refresh_pending() {
                        let selection = WalletPoiRefreshSelection::CorpusRevision {
                            blocked_shields_changed: blocked_shield_refresh_pending,
                        };
                        let refresh_still_needed = {
                            let locked = actor.utxos.read().await;
                            wallet_poi_status_refresh_needed_for_selection(
                                &locked,
                                &actor.active_poi_list_keys,
                                selection,
                            )
                        };
                        if !refresh_still_needed {
                            blocked_shield_refresh_pending = false;
                            let _ = actor.actor_state.transition_active(
                                &actor.worker_handle,
                                &actor.cancel,
                                |mut state| state.set_poi_corpus_refresh_pending(false),
                            );
                        }
                    }
                }
                _ = poi_status_refresh_interval.tick(), if poi_status_client.is_some() && actor.backfill_complete_block.is_some() && actor.actor_state.pending_reset().is_none() => {
                    let Some(_client) = poi_status_client.as_ref() else {
                        continue;
                    };
                    if let Some(revision_rx) = poi_corpus_revision_rx.as_mut() {
                        let revision = *revision_rx.borrow_and_update();
                        let _ = actor.actor_state.transition_active(
                            &actor.worker_handle,
                            &actor.cancel,
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
                    let selection = if actor.actor_state.poi_corpus_refresh_pending()
                        || blocked_shield_refresh_pending
                    {
                        WalletPoiRefreshSelection::CorpusRevision {
                            blocked_shields_changed: blocked_shield_refresh_pending,
                        }
                    } else if let Some(failed_selection) = actor.actor_state
                        .failed_poi_status_refresh_selection(actor.actor_state.reset_generation())
                    {
                        failed_selection
                    } else {
                        WalletPoiRefreshSelection::RecoverableStale { now }
                    };
                    if let Some(result) = actor.commit_local_poi_status_refresh(selection).await {
                        match result {
                            Ok(changed) => {
                                blocked_shield_refresh_pending = false;
                                let _ = actor.actor_state.transition_active(
                                    &actor.worker_handle,
                                    &actor.cancel,
                                    |mut state| state.set_poi_corpus_refresh_pending(false),
                                );
                                debug!(
                                    cache_key = %actor.cfg.cache_key,
                                    changed,
                                    "periodic local wallet POI status refresh committed"
                                );
                            }
                            Err(reason) => {
                                warn!(?reason, cache_key = %actor.cfg.cache_key, "periodic wallet POI status refresh rejected");
                            }
                        }
                    }
                    if actor.actor_state.poi_corpus_refresh_pending() {
                        let refresh_still_needed = {
                            let locked = actor.utxos.read().await;
                            wallet_poi_status_refresh_needed_for_selection(
                                &locked,
                                &actor.active_poi_list_keys,
                                selection,
                            )
                        };
                        if !refresh_still_needed {
                            blocked_shield_refresh_pending = false;
                            let _ = actor.actor_state.transition_active(
                                &actor.worker_handle,
                                &actor.cancel,
                                |mut state| state.set_poi_corpus_refresh_pending(false),
                            );
                        }
                    }
                    let _ = actor.request_poi_maintenance(false);
                }
                Some(event) = backfill_rx.recv() => {
                    match event {
                        #[cfg(test)]
                        BackfillEvent::PanicForTest => {
                            panic!("test wallet actor panic");
                        }
                        #[cfg(test)]
                        BackfillEvent::HoldTrackedPoiJobForTest { sentinel, started } => {
                            let held_data_plane = actor.public_data_plane.clone();
                            actor.poi_jobs.spawn(async move {
                                let _held = (held_data_plane, sentinel);
                                let _ = started.send(());
                                std::future::pending::<()>().await;
                            });
                        }
                        BackfillEvent::ReserveTarget { target_block, token, response } => {
                            if let Err(reason) = actor.actor_state.validate_sync_token_current(
                                token,
                                &actor.worker_handle,
                                &actor.cancel,
                            ) {
                                let _ = response.send(Err(reason));
                                continue;
                            }
                            if actor.try_drive_pending_reset(&mut live_rx, true).await.is_some()
                                && actor.actor_state.pending_reset().is_some()
                            {
                                let reason = if actor.actor_state.has_persistence_failure() {
                                    WalletBackfillRejectReason::PersistenceFailed
                                } else {
                                    WalletBackfillRejectReason::Shutdown
                                };
                                let _ = response.send(Err(reason));
                                continue;
                            }
                            let accepted = actor.actor_state
                                .transition_active(&actor.worker_handle, &actor.cancel, |mut state| {
                                    state.accept_sync_target(token, target_block)
                                })
                                .unwrap_or(false);
                            if !accepted {
                                let _ = response.send(Err(WalletBackfillRejectReason::Shutdown));
                                continue;
                            }
                            let (liveness, receiver) = oneshot::channel();
                            actor.accepted_backfill_liveness
                                .push(accepted_backfill_owner_dropped(token, receiver));
                            let lease = WalletSyncTargetLease::for_actor_accepted_job(
                                token,
                                actor.backfill_sender.clone(),
                                liveness,
                            );
                            if let Err(lease) = response.send(Ok(lease)) {
                                drop(lease);
                                let _ = actor.actor_state.transition_active(
                                    &actor.worker_handle,
                                    &actor.cancel,
                                    |mut state| state.retire_job(token),
                                );
                            }
                        }
                        BackfillEvent::Start { target_block, token, response } => {
                            if let Err(reason) = actor.actor_state.validate_sync_token_current(
                                token,
                                &actor.worker_handle,
                                &actor.cancel,
                            ) {
                                let _ = response.send(WalletBackfillStartResult::Rejected {
                                    committed_to: actor.last_scanned,
                                    reason,
                                });
                                continue;
                            }
                            if actor.try_drive_pending_reset(&mut live_rx, true).await.is_some()
                                && actor.actor_state.pending_reset().is_some()
                            {
                                let reason = if actor.actor_state.has_persistence_failure() {
                                    WalletBackfillRejectReason::PersistenceFailed
                                } else {
                                    WalletBackfillRejectReason::Shutdown
                                };
                                let _ = response.send(WalletBackfillStartResult::Rejected {
                                    committed_to: actor.last_scanned,
                                    reason,
                                });
                                continue;
                            }
                            let accepted = actor.actor_state
                                .transition_active(&actor.worker_handle, &actor.cancel, |mut state| {
                                    state.accept_target(token, target_block)
                                })
                                .unwrap_or(false);
                            if !accepted {
                                let _ = response.send(WalletBackfillStartResult::Rejected {
                                    committed_to: actor.last_scanned,
                                    reason: WalletBackfillRejectReason::Shutdown,
                                });
                                continue;
                            }
                            let (liveness, receiver) = oneshot::channel();
                            actor.accepted_backfill_liveness
                                .push(accepted_backfill_owner_dropped(token, receiver));
                            actor.backfill_complete_block = None;
                            let result = WalletBackfillStartResult::Accepted {
                                committed_to: actor.last_scanned,
                                target_block,
                                    grant: WalletBackfillGrant::for_actor_accepted_job_with_cancel(
                                        token,
                                        actor.backfill_sender.clone(),
                                        liveness,
                                        actor.cancel.clone(),
                                    ),
                            };
                            match response.send(result) {
                                Ok(()) => {
                                    let _ = actor.actor_state.transition_active(
                                        &actor.worker_handle,
                                        &actor.cancel,
                                        |mut state| state.backfill_dispatch_admitted(token),
                                    );
                                }
                                Err(result) => {
                                    drop(result);
                                    let _ = actor.actor_state.transition_active(
                                        &actor.worker_handle,
                                        &actor.cancel,
                                        |mut state| state.retire_job(token),
                                    );
                                    debug!(cache_key = %actor.cfg.cache_key, ?token, "wallet backfill start receiver dropped");
                                }
                            }
                        }
                        BackfillEvent::Apply { apply, token, response } => {
                            if let Some(outcome) = actor.try_drive_pending_reset(&mut live_rx, true).await
                                && actor.actor_state.pending_reset().is_some()
                            {
                                let reason = match outcome.rewind {
                                    WalletResetRewindOutcome::Deferred { reason, .. } => reason,
                                    WalletResetRewindOutcome::Committed { .. }
                                        if actor.actor_state.has_persistence_failure() =>
                                    {
                                        WalletBackfillRejectReason::PersistenceFailed
                                    }
                                    WalletResetRewindOutcome::Committed { .. } =>
                                        WalletBackfillRejectReason::Shutdown,
                                };
                                let _ = actor.actor_state.transition_active(
                                    &actor.worker_handle,
                                    &actor.cancel,
                                    |mut state| {
                                        state.retire_job(token);
                                    },
                                );
                                let result = WalletBackfillApplyResult::Rejected {
                                    committed_to: actor.last_scanned,
                                    reason,
                                };
                                if let Err(err) = response.send(result) {
                                    debug!(?err, cache_key = %actor.cfg.cache_key, "failed to send pending-reset wallet scan apply result");
                                }
                                continue;
                            }
                            let current_reset_generation = actor.actor_state.reset_generation();
                            if let Err(reason) = actor.actor_state.validate_active_backfill_token(
                                token,
                                &actor.worker_handle,
                                &actor.cancel,
                            ) {
                                let result = WalletBackfillApplyResult::Rejected {
                                    committed_to: actor.last_scanned,
                                    reason,
                                };
                                if let Err(err) = response.send(result) {
                                    debug!(?err, cache_key = %actor.cfg.cache_key, "failed to send inactive wallet scan apply result");
                                }
                                continue;
                            }
                            let outcome = WalletScanCommitRequest {
                                cache_store: actor.cache_store.as_ref(),
                                cfg: &actor.cfg,
                                utxos: &actor.utxos,
                                worker_handle: &actor.worker_handle,
                                apply,
                                job_token: token,
                                current_reset_generation,
                                event_reset_generation: token.reset_generation(),
                                actor_state: &mut actor.actor_state,
                                cancel: &actor.cancel,
                                last_scanned: &mut actor.last_scanned,
                                persist_state: &mut actor.persist_state,
                                live_metadata_flush: &mut actor.live_metadata_flush,
                                public_data_plane: &actor.public_data_plane,
                            }
                            .commit()
                            .await;
                            if outcome.changed && poi_status_client.is_some() {
                                let _ = actor.request_poi_maintenance(false);
                            }
                            if let Err(err) = response.send(outcome.result) {
                                debug!(?err, cache_key = %actor.cfg.cache_key, "failed to send wallet scan apply result");
                            }
                        }
                        BackfillEvent::Finish { target_block, token, response } => {
                            let current_reset_generation = actor.actor_state.reset_generation();
                            if let Err(reason) = actor.actor_state.validate_active_backfill_token(
                                token,
                                &actor.worker_handle,
                                &actor.cancel,
                            ) {
                                let result = WalletBackfillFinishResult::Rejected {
                                    committed_to: actor.last_scanned,
                                    reason,
                                };
                                if let Err(err) = response.send(result) {
                                    debug!(?err, cache_key = %actor.cfg.cache_key, "failed to send stale wallet target result");
                                }
                                continue;
                            }
                            if let Some(outcome) = actor.try_drive_pending_reset(&mut live_rx, true).await
                                && actor.actor_state.pending_reset().is_some()
                            {
                                let reason = match outcome.rewind {
                                    WalletResetRewindOutcome::Deferred { reason, .. } => reason,
                                    WalletResetRewindOutcome::Committed { .. }
                                        if actor.actor_state.has_persistence_failure() =>
                                    {
                                        WalletBackfillRejectReason::PersistenceFailed
                                    }
                                    WalletResetRewindOutcome::Committed { .. } =>
                                        WalletBackfillRejectReason::Shutdown,
                                };
                                let result = WalletBackfillFinishResult::Rejected {
                                    committed_to: actor.last_scanned,
                                    reason,
                                };
                                if let Err(err) = response.send(result) {
                                    debug!(?err, cache_key = %actor.cfg.cache_key, "failed to send pending-reset wallet target result");
                                }
                                continue;
                            }
                            let Some(required_target) = actor.actor_state
                                .transition_active(&actor.worker_handle, &actor.cancel, |mut state| {
                                    state.update_target(token, target_block)
                                })
                                .ok()
                                .flatten()
                            else {
                                let _ = response.send(WalletBackfillFinishResult::Rejected {
                                    committed_to: actor.last_scanned,
                                    reason: WalletBackfillRejectReason::Shutdown,
                                });
                                continue;
                            };
                            if required_target == 0 || required_target > actor.last_scanned {
                                debug!(
                                    cache_key = %actor.cfg.cache_key,
                                    target_block = required_target,
                                    last_scanned = actor.last_scanned,
                                    reset_generation = current_reset_generation,
                                    "wallet target recorded; cursor has not reached target"
                                );
                                actor.backfill_complete_block = None;
                                let result = WalletBackfillFinishResult::Rejected {
                                    committed_to: actor.last_scanned,
                                    reason: WalletBackfillRejectReason::TargetNotReached {
                                        target_block: required_target,
                                    },
                                };
                                if let Err(err) = response.send(result) {
                                    debug!(?err, cache_key = %actor.cfg.cache_key, "failed to send pending wallet target result");
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
                                            committed_to: actor.last_scanned,
                                            reason: WalletBackfillRejectReason::ApplyFailed,
                                        }
                                    } else {
                                        let completed = actor.actor_state
                                            .transition_active(
                                                &actor.worker_handle,
                                                &actor.cancel,
                                                |mut state| state.complete_backfill_job(token),
                                            )
                                            .unwrap_or(false);
                                        if completed {
                                            if actor.actor_state.has_active_backfill_job() {
                                                actor.backfill_complete_block = None;
                                            }
                                            WalletBackfillFinishResult::Ready {
                                                committed_to: actor.last_scanned,
                                            }
                                        } else {
                                            WalletBackfillFinishResult::Rejected {
                                                committed_to: actor.last_scanned,
                                                reason: WalletBackfillRejectReason::Shutdown,
                                            }
                                        }
                                    }
                                }
                                WalletBackfillDoneOutcome::Rejected(reason) => {
                                    let _ = actor.actor_state.transition_active(
                                        &actor.worker_handle,
                                        &actor.cancel,
                                        |mut state| {
                                            if reason == WalletBackfillRejectReason::PersistenceFailed {
                                                state.backfill_completion_persist_failed(token);
                                            } else {
                                                state.retire_job(token);
                                            }
                                        },
                                    );
                                    WalletBackfillFinishResult::Rejected {
                                        committed_to: actor.last_scanned,
                                        reason,
                                    }
                                }
                            };
                            if let Err(err) = response.send(result) {
                                debug!(?err, cache_key = %actor.cfg.cache_key, "failed to send wallet target result");
                            }
                        }
                        BackfillEvent::JobFailed { token, reason, response } => {
                            if actor.actor_state.validate_active_backfill_token(
                                token,
                                &actor.worker_handle,
                                &actor.cancel,
                            )
                            .is_ok()
                            {
                                let _ = actor.actor_state.transition_active(
                                    &actor.worker_handle,
                                    &actor.cancel,
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
                            if let Err(reason) = actor.actor_state.validate_reset_token_current(
                                token,
                                &actor.worker_handle,
                                &actor.cancel,
                            ) {
                                let result = WalletBackfillResetResult::Rejected {
                                    committed_to: actor.last_scanned,
                                    reason,
                                };
                                if let Err(err) = response.send(result) {
                                    debug!(?err, cache_key = %actor.cfg.cache_key, "failed to send shutdown wallet reset result");
                                }
                                continue;
                            }
                            let intent_id = token.intent_id();

                            if intent_id <= actor.actor_state.highest_accepted_reset_intent() {
                                let result = WalletBackfillResetResult::Rejected {
                                    committed_to: actor.last_scanned,
                                    reason: WalletBackfillRejectReason::StaleResetIntent {
                                        accepted: actor.actor_state.highest_accepted_reset_intent(),
                                        actual: intent_id,
                                    },
                                };
                                if let Err(err) = response.send(result) {
                                    debug!(?err, cache_key = %actor.cfg.cache_key, "failed to send stale wallet reset result");
                                }
                                continue;
                            }
                            let current_reset_generation = actor.actor_state.reset_generation();
                            let acceptance_authority = WalletPrivateMutationAuthority::new(
                                &actor.worker_handle,
                                current_reset_generation,
                                &actor.cancel,
                            );
                            let acceptance_permit = match acceptance_authority.acquire().await {
                                Ok(permit) => permit,
                                Err(reason) => {
                                    let result = WalletBackfillResetResult::Rejected {
                                        committed_to: actor.last_scanned,
                                        reason,
                                    };
                                    if let Err(err) = response.send(result) {
                                        debug!(?err, cache_key = %actor.cfg.cache_key, "failed to send reset authority rejection");
                                    }
                                    continue;
                                }
                            };
                            let reset_from_block = actor.actor_state.pending_reset()
                                .map_or(from_block, |pending| {
                                    pending.rewind_from_block().min(from_block)
                                });
                            let replay_plan = PendingWalletReset::merge_replay_plan(
                                actor.actor_state.pending_reset(),
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
                                    actor.cache_store.as_ref(),
                                    &actor.cfg,
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
                                let clear_indexed_catch_up = actor.actor_state.transition_with_view(
                                    &token,
                                    reset_view,
                                    |mut state| state.accept_reset(accepted_pending_reset),
                                );
                                // Force intent is generation-scoped; do not carry across rewind.
                                actor.poi_maintenance.clear_force_on_reset();
                                if clear_indexed_catch_up {
                                    acceptance_permit
                                        .apply_publish_indexed_catch_up(&token, None);
                                }
                                Ok::<(), WalletCacheError>(())
                            });
                            match accept_result {
                                Ok(Ok(())) => {
                                    actor.accepted_backfill_liveness.clear();
                                    actor.accepted_indexed_job_liveness.clear();
                                    pending_output_poi_tentative_attempts.clear();
                                }
                                Ok(Err(err)) => {
                                    warn!(?err, cache_key = %actor.cfg.cache_key, intent_id, from_block, "failed to persist wallet reset acceptance");
                                    let result = WalletBackfillResetResult::Rejected {
                                        committed_to: actor.last_scanned,
                                        reason: WalletBackfillRejectReason::PersistenceFailed,
                                    };
                                    if let Err(err) = response.send(result) {
                                        debug!(?err, cache_key = %actor.cfg.cache_key, "failed to send wallet reset persistence failure");
                                    }
                                    continue;
                                }
                                Err(reason) => {
                                    let result = WalletBackfillResetResult::Rejected {
                                        committed_to: actor.last_scanned,
                                        reason,
                                    };
                                    if let Err(err) = response.send(result) {
                                        debug!(?err, cache_key = %actor.cfg.cache_key, "failed to send reset acceptance rejection");
                                    }
                                    continue;
                                }
                            }
                            drop(acceptance_permit);
                            let outcome = actor.try_drive_pending_reset(&mut live_rx, true).await
                                .expect("pending reset was installed before commit");
                            // Accept already succeeded: public result is always Accepted.
                            let result =
                                reset_result_after_accept(next_reset_generation, outcome);
                            if let Err(err) = response.send(result) {
                                debug!(?err, cache_key = %actor.cfg.cache_key, "failed to send wallet reset result");
                            }
                        }
                    }
                }
                result = live_rx.recv(), if actor.backfill_complete_block.is_some() && actor.actor_state.pending_reset().is_none() => {
                    match result {
                        Ok(batch) => {
                            if actor.cfg.sync_to_block.is_some() {
                                continue;
                            }
                            if actor.backfill_complete_block.is_none()
                                || batch.to_block <= actor.last_scanned
                            {
                                live_receiver_lagged = false;
                                continue;
                            }
                            let expected_from_block = actor.last_scanned.saturating_add(1);
                            if batch.from_block > expected_from_block {
                                warn!(
                                    cache_key = %actor.cfg.cache_key,
                                    expected_from_block,
                                    batch_from_block = batch.from_block,
                                    batch_to_block = batch.to_block,
                                    live_receiver_lagged,
                                    "wallet live log gap detected; requesting backfill"
                                );
                                let current_reset_generation = actor.actor_state.reset_generation();
                                let token = actor.worker_handle.mint_sync_token(current_reset_generation);
                                let accepted = actor.actor_state
                                    .transition_active(&actor.worker_handle, &actor.cancel, |mut state| {
                                        state.accept_target(token, batch.to_block)
                                    })
                                    .unwrap_or(false);
                                if !accepted {
                                    continue;
                                }
                                let (liveness, receiver) = oneshot::channel();
                                actor.accepted_backfill_liveness
                                    .push(accepted_backfill_owner_dropped(token, receiver));
                                let driver = WalletBackfillGrant::for_actor_accepted_job_with_cancel(
                                    token,
                                    actor.backfill_sender.clone(),
                                    liveness,
                                    actor.cancel.clone(),
                                )
                                .activate();
                                match actor.backfill_tx.try_send(BackfillRequest::add(
                                    actor.cfg.cache_key.clone(),
                                    expected_from_block,
                                    batch.to_block,
                                    true,
                                    expected_from_block,
                                    driver,
                                )) {
                                    Ok(()) => {
                                        let _ = actor.actor_state.transition_active(
                                            &actor.worker_handle,
                                            &actor.cancel,
                                            |mut state| state.backfill_dispatch_admitted(token),
                                        );
                                        actor.backfill_complete_block = None;
                                        live_rx = live_rx.resubscribe();
                                    }
                                    Err(err) => {
                                        warn!(?err, cache_key = %actor.cfg.cache_key, "failed to request wallet live gap backfill");
                                        let _ = actor.actor_state.transition_active(
                                            &actor.worker_handle,
                                            &actor.cancel,
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
                                    warn!(?err, cache_key = %actor.cfg.cache_key, from_block = expected_from_block, to_block = batch.to_block, "failed to normalize wallet live logs");
                                    continue;
                                }
                            };
                            let current_reset_generation = actor.actor_state.reset_generation();
                            let live_token = actor.worker_handle.mint_sync_token(current_reset_generation);
                            let accepted = actor.actor_state
                                .transition_active(&actor.worker_handle, &actor.cancel, |mut state| {
                                    state.accept_target(live_token, batch.to_block)
                                })
                                .unwrap_or(false);
                            if !accepted {
                                continue;
                            }
                            let outcome = WalletScanCommitRequest {
                                cache_store: actor.cache_store.as_ref(),
                                cfg: &actor.cfg,
                                utxos: &actor.utxos,
                                worker_handle: &actor.worker_handle,
                                apply,
                                job_token: live_token,
                                current_reset_generation,
                                event_reset_generation: live_token.reset_generation(),
                                actor_state: &mut actor.actor_state,
                                cancel: &actor.cancel,
                                last_scanned: &mut actor.last_scanned,
                                persist_state: &mut actor.persist_state,
                                live_metadata_flush: &mut actor.live_metadata_flush,
                                public_data_plane: &actor.public_data_plane,
                            }
                            .commit()
                            .await;
                            match outcome.result {
                                WalletBackfillApplyResult::Committed { .. }
                                | WalletBackfillApplyResult::AlreadyCovered { .. } => {
                                    let _ = actor.actor_state.transition_active(
                                        &actor.worker_handle,
                                        &actor.cancel,
                                        |mut state| state.retire_job(live_token),
                                    );
                                    if outcome.changed && poi_status_client.is_some() {
                                        let _ = actor.request_poi_maintenance(false);
                                    }
                                }
                                WalletBackfillApplyResult::Rejected {
                                    reason: WalletBackfillRejectReason::PersistenceFailed,
                                    ..
                                } => {
                                    // Keep the accepted live job as the owner of its exact failed
                                    // range and let the normal backfill loop apply persistence backoff.
                                    let (liveness, receiver) = oneshot::channel();
                                    actor.accepted_backfill_liveness.push(
                                        accepted_backfill_owner_dropped(live_token, receiver),
                                    );
                                    let driver = WalletBackfillGrant::for_actor_accepted_job_with_cancel(
                                        live_token,
                                        actor.backfill_sender.clone(),
                                        liveness,
                                        actor.cancel.clone(),
                                    )
                                    .activate();
                                    let retry = BackfillRequest::add(
                                        actor.cfg.cache_key.clone(),
                                        expected_from_block,
                                        batch.to_block,
                                        false,
                                        expected_from_block,
                                        driver,
                                    );
                                    match actor.backfill_tx.try_send(retry) {
                                        Ok(()) => {
                                            let _ = actor.actor_state.transition_active(
                                                &actor.worker_handle,
                                                &actor.cancel,
                                                |mut state| {
                                                    state.backfill_dispatch_admitted(live_token)
                                                },
                                            );
                                            actor.backfill_complete_block = None;
                                            live_rx = live_rx.resubscribe();
                                        }
                                        Err(err) => {
                                            warn!(?err, cache_key = %actor.cfg.cache_key, from_block = expected_from_block, to_block = batch.to_block, "failed to enqueue wallet live persistence retry");
                                            let _ = actor.actor_state.transition_active(
                                                &actor.worker_handle,
                                                &actor.cancel,
                                                |mut state| {
                                                    state.fail_job_backfill_unavailable(live_token);
                                                },
                                            );
                                        }
                                    }
                                }
                                WalletBackfillApplyResult::Rejected { reason, .. } => {
                                    let _ = actor.actor_state.transition_active(
                                        &actor.worker_handle,
                                        &actor.cancel,
                                        |mut state| state.retire_job(live_token),
                                    );
                                    warn!(?reason, cache_key = %actor.cfg.cache_key, "wallet live scan batch rejected");
                                }
                            }
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            live_receiver_lagged = true;
                            warn!(cache_key = %actor.cfg.cache_key, skipped, "wallet live log receiver lagged");
                        }
                    }
                }
            }
        }
        // Cancellation and terminal observation share the lifecycle fence. Registration
        // retirement may win first, in which case this epilogue cannot publish again.
        let _ = actor.worker_handle.publish_terminal_shutdown_if_allowed(|token| {
            actor.actor_state.transition_terminal_shutdown(
                &token,
                WalletInactiveReason::Shutdown,
                actor.worker_handle.authority_reset_generation(),
            );
            if let Err(err) = actor.worker_handle.indexed_catch_up_tx.send(None) {
                debug!(?err, cache_key = %actor.cfg.cache_key, "failed to clear indexed wallet catch-up status on shutdown");
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
