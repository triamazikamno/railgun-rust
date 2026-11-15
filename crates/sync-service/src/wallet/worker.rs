use super::handle::LOCAL_PENDING_SPENT_TTL;
use super::pending_output_poi::{
    PendingOutputPoiTentativeSubmissionResult, pending_output_poi_handoff_context,
};
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
    WalletReadinessError, WalletResetReplayPlan, WalletResetRewindStatus, WalletScanApply,
    WalletScanRowsPayload, WalletSyncActorStateCommit, WalletSyncActorStateRecord, WalletSyncToken,
    WalletUtxo, WalletUtxoMutation, WalletViewState, WalletWorkerServices,
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
mod backfill_events;
mod commit;
mod indexed_catch_up;
mod live_logs;
mod local_pending_spent;
mod output_poi;
mod pending_overlay;
mod poi_maintenance;
mod poi_refresh;

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
    clear_local_pending_spent, mark_local_pending_spent, prune_local_pending_spent,
    wait_for_local_pending_spent_expiry,
};
use output_poi::{
    PendingOutputPoiTentativeAttemptTracker, commit_pending_output_contexts,
    refresh_tentative_pending_output_poi_statuses, spawn_pending_output_poi_tentative_job,
};
use poi_maintenance::{
    PoiMaintenanceOutcome, next_poi_corpus_revision, wallet_poi_refresh_interval,
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

/// Remote work completion messages re-entering the wallet actor (never applied off-loop bookkeeping only).
#[derive(Debug)]
enum WalletRemoteDone {
    PoiMaintenance {
        credential: WalletActorCredential,
        key: PoiRemoteJobKey,
        outcome: Box<PoiMaintenanceOutcome>,
    },
    PoiMaintenanceAborted {
        credential: WalletActorCredential,
        key: PoiRemoteJobKey,
        reason: &'static str,
    },
    PendingOutputPoiTentative {
        credential: WalletActorCredential,
        result: PendingOutputPoiTentativeSubmissionResult,
    },
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
    live_rx: broadcast::Receiver<SharedLogBatch>,
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
    let poi_corpus_revision_rx = if poi_runtime.is_indexed_artifacts() {
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
        let pending_output_poi_tentative_attempts =
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
            worker_started,
            last_poi_corpus_revision,
            blocked_shield_refresh_pending,
            poi_status_client,
            maintenance_observation,
            pending_output_poi_tentative_attempts,
            poi_corpus_handle,
            live_rx,
            poi_corpus_revision_rx,
            live_receiver_lagged: false,
        };
        if actor.actor_state.pending_reset().is_some() && actor.try_drive_pending_reset(false).await.is_some() {
            signal_restored_reset_attempt(&mut startup_replay_tx);
        }

        // Prepared-worker cancellation drops the sender, so this cannot hang. Once activation is
        // accepted, let the active loop observe cancellation and publish terminal readiness.
        let activated = activation_rx.await.is_ok();
        if !activated {
            return;
        }
        if actor.actor_state.pending_reset().is_some() {
            let _ = actor.try_drive_pending_reset(true).await;
        }
        loop {
            tokio::select! {
                () = actor.cancel.cancelled() => break,
                expiry = wait_for_local_pending_spent_expiry(&actor.worker_handle) => actor.handle_local_pending_spent_expiry(expiry).await,
                Some((token, signal)) = actor.accepted_backfill_liveness.next(), if !actor.accepted_backfill_liveness.is_empty() => actor.handle_backfill_owner_signal(token, signal).await,
                Some(token) = actor.accepted_indexed_job_liveness.next(), if !actor.accepted_indexed_job_liveness.is_empty() => actor.handle_indexed_job_owner_dropped(token).await,
                Some(apply_req) = private_apply_rx.recv() => actor.handle_private_apply(apply_req).await,
                Some(done) = remote_done_rx.recv() => actor.handle_remote_done(done).await,
                _ = pending_reset_retry.tick(), if actor.actor_state.pending_reset().is_some() => {
                    if let Some(outcome) = actor.try_drive_pending_reset(true).await {
                        debug!(?outcome.rewind, cache_key = %actor.cfg.cache_key, "wallet pending reset retry completed");
                        signal_restored_reset_attempt(&mut startup_replay_tx);
                    }
                }
                Some(refresh_request) = poi_refresh_rx.recv() => actor.handle_poi_refresh_request(refresh_request).await,
                Some(command) = indexed_catch_up_status_rx.recv() => actor.handle_indexed_catch_up_command(command).await,
                Some(request) = private_request_rx.recv() => actor.handle_private_request(request).await,
                Some(request) = pending_overlay_rx.recv() => actor.handle_pending_overlay(request).await,
                revision = next_poi_corpus_revision(&mut actor.poi_corpus_revision_rx) => actor.handle_poi_corpus_revision(revision).await,
                _ = poi_status_refresh_interval.tick(), if actor.poi_status_client.is_some() && actor.backfill_complete_block.is_some() && actor.actor_state.pending_reset().is_none() => actor.handle_poi_status_tick().await,
                Some(event) = backfill_rx.recv() => actor.handle_backfill_event(event).await,
                result = actor.live_rx.recv(), if actor.backfill_complete_block.is_some() && actor.actor_state.pending_reset().is_none() => {
                    if actor.handle_live_logs(result).await.is_break() {
                        break;
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
