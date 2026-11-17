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
mod startup;

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
use startup::{
    WalletActorInbox, WalletPoiCorpusStart, initial_wallet_view, new_prepared_wallet_handle,
    open_wallet_poi_corpus, restore_wallet_sync_state,
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

/// Per-wallet inputs for [`prepare_wallet_worker`].
pub(crate) struct WalletWorkerStart {
    pub(crate) actor_id: u64,
    pub(crate) live_rx: broadcast::Receiver<SharedLogBatch>,
    pub(crate) backfill_rx: mpsc::Receiver<BackfillEvent>,
    pub(crate) cancel: CancellationToken,
    pub(crate) initial_utxos: Vec<WalletUtxo>,
    pub(crate) initial_last_scanned: u64,
}

pub(crate) async fn prepare_wallet_worker(
    services: WalletWorkerServices,
    cfg: WalletConfig,
    start: WalletWorkerStart,
) -> Result<PreparedWalletWorker, ChainError> {
    let utxos = Arc::new(RwLock::new(start.initial_utxos));
    let poi_corpus = open_wallet_poi_corpus(
        &services.poi_runtime,
        &services.public_data_plane,
        cfg.chain.chain_id,
    )
    .await?;
    let cache_store = wallet_cache_store(&services.db, &cfg);
    let active_poi_list_keys = default_active_poi_list_keys();
    let initial_ppoi_workflow_projection = wallet_ppoi_workflow_status_after_mutations(
        cache_store.as_ref(),
        &cfg,
        &active_poi_list_keys,
        0,
        PoiPrivateRows::default(),
    )?;
    let (restored_pending_reset, restored_highest_reset_intent) =
        restore_wallet_sync_state(cache_store.as_ref(), &cfg, start.initial_last_scanned)?;
    let has_restored_pending_reset = restored_pending_reset.is_some();
    let initial_reset_generation = u64::from(has_restored_pending_reset);
    let initial_view = initial_wallet_view(
        restored_pending_reset.as_ref(),
        &utxos,
        start.initial_last_scanned,
        initial_reset_generation,
    );
    let (actor_state, observation_rx) = WalletActorState::new(
        cfg.chain.chain_id,
        start.actor_id,
        initial_reset_generation,
        start.initial_last_scanned,
        restored_highest_reset_intent,
        restored_pending_reset,
        poi_corpus.blocked_shield_refresh_pending,
        initial_view,
    );
    let observation = actor_state.observation_publisher();
    observation.publish_ppoi_workflow_projection(
        initial_ppoi_workflow_projection.status,
        initial_ppoi_workflow_projection.submissions,
    );
    let (handle, inbox, poi_refreshing_tx) = new_prepared_wallet_handle(
        &cfg,
        start.actor_id,
        &utxos,
        &observation,
        observation_rx,
        start.initial_last_scanned,
        initial_reset_generation,
    );
    let (startup_replay_tx, startup_replay_rx) = if has_restored_pending_reset {
        let (tx, rx) = oneshot::channel();
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    let (activation_tx, activation_rx) = oneshot::channel();

    let prepared_cancel = start.cancel.clone();
    let worker = spawn_wallet_actor(WalletActorStart {
        worker_handle: handle.clone(),
        maintenance_observation: Arc::clone(&observation),
        services,
        cfg,
        cache_store,
        utxos,
        cancel: start.cancel,
        active_poi_list_keys,
        actor_state,
        poi_jobs: WalletPoiJobTracker::default(),
        poi_refreshing_tx,
        poi_corpus,
        live_rx: start.live_rx,
        last_scanned: start.initial_last_scanned,
        inbox,
        backfill_rx: start.backfill_rx,
        activation_rx,
        startup_replay_tx,
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

/// Everything the spawned actor task owns.
struct WalletActorStart {
    services: WalletWorkerServices,
    cfg: WalletConfig,
    cache_store: Arc<dyn WalletCacheStore>,
    utxos: Arc<RwLock<Vec<WalletUtxo>>>,
    worker_handle: WalletHandle,
    cancel: CancellationToken,
    active_poi_list_keys: Vec<FixedBytes<32>>,
    actor_state: WalletActorState,
    maintenance_observation: Arc<WalletObservationPublisher>,
    poi_jobs: WalletPoiJobTracker,
    poi_refreshing_tx: watch::Sender<bool>,
    poi_corpus: WalletPoiCorpusStart,
    live_rx: broadcast::Receiver<SharedLogBatch>,
    last_scanned: u64,
    inbox: WalletActorInbox,
    backfill_rx: mpsc::Receiver<BackfillEvent>,
    activation_rx: oneshot::Receiver<()>,
    startup_replay_tx: Option<oneshot::Sender<()>>,
}

/// Spawns the actor task, and the supervisor that terminalizes a panicked actor and then shuts
/// down the actor's POI jobs.
fn spawn_wallet_actor(start: WalletActorStart) -> JoinHandle<()> {
    let chain_id = start.cfg.chain.chain_id;
    let worker_panic_handle = start.worker_handle.clone();
    let worker_observation = Arc::clone(&start.maintenance_observation);
    let worker_cache_key = start.cfg.cache_key.clone();
    let supervisor_poi_jobs = start.poi_jobs.clone();
    let actor_worker =
        tokio::spawn(run_wallet_actor(start).instrument(tracing::info_span!("wallet", chain_id)));
    tokio::spawn(async move {
        if let Err(err) = actor_worker.await {
            warn!(?err, cache_key = %worker_cache_key, "wallet worker task failed");
            worker_panic_handle.terminalize_panicked_actor(&worker_observation);
        }
        supervisor_poi_jobs.shutdown().await;
    })
}

/// The actor loop's event sources besides its own fields.
struct WalletActorEvents {
    inbox: WalletActorInbox,
    backfill_rx: mpsc::Receiver<BackfillEvent>,
    remote_done_rx: mpsc::Receiver<WalletRemoteDone>,
    private_apply_rx: mpsc::Receiver<WalletPrivateApplyRequest>,
    pending_reset_retry: tokio::time::Interval,
    poi_status_refresh_interval: tokio::time::Interval,
}

/// Runs the wallet actor: drives a restored reset, waits for activation, serves events until
/// cancellation, then publishes terminal shutdown.
async fn run_wallet_actor(mut start: WalletActorStart) {
    let worker_started = Instant::now();
    let last_scanned = start.last_scanned;
    log_loaded_wallet_cache(&start.utxos, &start.cfg, last_scanned).await;

    let poi_runtime = start.services.poi_runtime;
    let poi_status_client = Some(poi_runtime.public_client());
    let pending_reset_retry = wallet_reset_retry_interval();
    let poi_status_refresh_interval = wallet_poi_refresh_interval();
    if poi_status_client.is_some() {
        log_startup_poi_refresh(&start.utxos, &start.cfg, &start.active_poi_list_keys).await;
    }

    let (remote_done_tx, remote_done_rx) = mpsc::channel::<WalletRemoteDone>(8);
    // Jobs re-enter here for private POI commits; actor is sole UTXO mirror writer.
    let (private_apply_tx, private_apply_rx) = mpsc::channel::<WalletPrivateApplyRequest>(32);
    let mut events = WalletActorEvents {
        inbox: start.inbox,
        backfill_rx: start.backfill_rx,
        remote_done_rx,
        private_apply_rx,
        pending_reset_retry,
        poi_status_refresh_interval,
    };
    let mut actor = WalletActorLoop {
        cfg: start.cfg,
        cache_store: start.cache_store,
        utxos: start.utxos,
        worker_handle: start.worker_handle,
        cancel: start.cancel,
        poi_runtime: &poi_runtime,
        public_data_plane: start.services.public_data_plane,
        active_poi_list_keys: start.active_poi_list_keys,
        actor_state: start.actor_state,
        persist_state: WalletPersistState::default(),
        last_scanned,
        db: start.services.db,
        poi_submitter: start.services.poi_submitter,
        accepted_backfill_liveness: FuturesUnordered::new(),
        accepted_indexed_job_liveness: FuturesUnordered::new(),
        live_metadata_flush: WalletLiveMetadataFlush::new(last_scanned, worker_started),
        readiness_started: worker_started,
        backfill_complete_block: None,
        backfill_sender: start.services.backfill_sender,
        backfill_tx: start.services.backfill_tx,
        poi_maintenance: PoiMaintenanceController::new(),
        remote_done_tx,
        private_apply: WalletPrivateApplyClient::new(private_apply_tx),
        poi_jobs: start.poi_jobs,
        poi_refreshing_tx: start.poi_refreshing_tx,
        http_client: start.services.http_client,
        indexed_artifact_source: start.services.indexed_artifact_source,
        forest: start.services.forest,
        worker_started,
        last_poi_corpus_revision: start.poi_corpus.last_revision,
        blocked_shield_refresh_pending: start.poi_corpus.blocked_shield_refresh_pending,
        poi_status_client,
        maintenance_observation: start.maintenance_observation,
        // Tentative attempts are actor-lifetime only; safe-head maintenance never consults this set.
        pending_output_poi_tentative_attempts: PendingOutputPoiTentativeAttemptTracker::default(),
        poi_corpus_handle: start.poi_corpus.handle,
        live_rx: start.live_rx,
        poi_corpus_revision_rx: start.poi_corpus.revision_rx,
        live_receiver_lagged: false,
    };
    actor
        .run(
            start.activation_rx,
            &mut events,
            &mut start.startup_replay_tx,
        )
        .await;
}

async fn log_loaded_wallet_cache(
    utxos: &RwLock<Vec<WalletUtxo>>,
    cfg: &WalletConfig,
    last_scanned: u64,
) {
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
}

async fn log_startup_poi_refresh(
    utxos: &RwLock<Vec<WalletUtxo>>,
    cfg: &WalletConfig,
    active_poi_list_keys: &[FixedBytes<32>],
) {
    let locked = utxos.read().await;
    debug!(
        cache_key = %cfg.cache_key,
        poi_refresh_needed = wallet_poi_status_refresh_needed(&locked, active_poi_list_keys),
        "startup wallet POI status refresh will run after backfill if needed"
    );
}

fn wallet_reset_retry_interval() -> tokio::time::Interval {
    let mut interval = tokio::time::interval_at(
        tokio::time::Instant::now() + WALLET_RESET_RETRY_INTERVAL,
        WALLET_RESET_RETRY_INTERVAL,
    );
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    interval
}

impl WalletActorLoop<'_> {
    /// Drives a restored reset without replay admission, waits for activation, then drives it
    /// with replay admission, serves events and publishes terminal shutdown.
    async fn run(
        &mut self,
        activation_rx: oneshot::Receiver<()>,
        events: &mut WalletActorEvents,
        startup_replay_tx: &mut Option<oneshot::Sender<()>>,
    ) {
        if self.actor_state.pending_reset().is_some()
            && self.try_drive_pending_reset(false).await.is_some()
        {
            signal_restored_reset_attempt(startup_replay_tx);
        }

        // Prepared-worker cancellation drops the sender, so this cannot hang. Once activation is
        // accepted, let the active loop observe cancellation and publish terminal readiness.
        let activated = activation_rx.await.is_ok();
        if !activated {
            return;
        }
        if self.actor_state.pending_reset().is_some() {
            let _ = self.try_drive_pending_reset(true).await;
        }
        self.run_active(events, startup_replay_tx).await;
        self.publish_terminal_shutdown();
    }

    /// Serves actor events until cancellation, or until a live-log batch ends the loop.
    async fn run_active(
        &mut self,
        events: &mut WalletActorEvents,
        startup_replay_tx: &mut Option<oneshot::Sender<()>>,
    ) {
        loop {
            tokio::select! {
                () = self.cancel.cancelled() => break,
                expiry = wait_for_local_pending_spent_expiry(&self.worker_handle) => self.handle_local_pending_spent_expiry(expiry).await,
                Some((token, signal)) = self.accepted_backfill_liveness.next(), if !self.accepted_backfill_liveness.is_empty() => self.handle_backfill_owner_signal(token, signal).await,
                Some(token) = self.accepted_indexed_job_liveness.next(), if !self.accepted_indexed_job_liveness.is_empty() => self.handle_indexed_job_owner_dropped(token).await,
                Some(apply_req) = events.private_apply_rx.recv() => self.handle_private_apply(apply_req).await,
                Some(done) = events.remote_done_rx.recv() => self.handle_remote_done(done).await,
                _ = events.pending_reset_retry.tick(), if self.actor_state.pending_reset().is_some() => self.retry_pending_reset(startup_replay_tx).await,
                Some(refresh_request) = events.inbox.poi_refresh_rx.recv() => self.handle_poi_refresh_request(refresh_request).await,
                Some(command) = events.inbox.indexed_catch_up_status_rx.recv() => self.handle_indexed_catch_up_command(command).await,
                Some(request) = events.inbox.private_request_rx.recv() => self.handle_private_request(request).await,
                Some(request) = events.inbox.pending_overlay_rx.recv() => self.handle_pending_overlay(request).await,
                revision = next_poi_corpus_revision(&mut self.poi_corpus_revision_rx) => self.handle_poi_corpus_revision(revision).await,
                _ = events.poi_status_refresh_interval.tick(), if self.poi_status_ticks_apply() => self.handle_poi_status_tick().await,
                Some(event) = events.backfill_rx.recv() => self.handle_backfill_event(event).await,
                result = self.live_rx.recv(), if self.backfill_settled() => {
                    if self.handle_live_logs(result).await.is_break() {
                        break;
                    }
                }
            }
        }
    }

    async fn retry_pending_reset(&mut self, startup_replay_tx: &mut Option<oneshot::Sender<()>>) {
        if let Some(outcome) = self.try_drive_pending_reset(true).await {
            debug!(?outcome.rewind, cache_key = %self.cfg.cache_key, "wallet pending reset retry completed");
            signal_restored_reset_attempt(startup_replay_tx);
        }
    }

    /// Backfill has completed and no reset is pending, so live logs and POI status ticks apply.
    const fn backfill_settled(&self) -> bool {
        self.backfill_complete_block.is_some() && self.actor_state.pending_reset().is_none()
    }

    /// POI status ticks need a POI client and a settled backfill.
    const fn poi_status_ticks_apply(&self) -> bool {
        self.poi_status_client.is_some() && self.backfill_settled()
    }

    fn publish_terminal_shutdown(&mut self) {
        // Cancellation and terminal observation share the lifecycle fence. Registration
        // retirement may win first, in which case this epilogue cannot publish again.
        let _ = self.worker_handle.publish_terminal_shutdown_if_allowed(|token| {
            self.actor_state.transition_terminal_shutdown(
                &token,
                WalletInactiveReason::Shutdown,
                self.worker_handle.authority_reset_generation(),
            );
            if let Err(err) = self.worker_handle.indexed_catch_up_tx.send(None) {
                debug!(?err, cache_key = %self.cfg.cache_key, "failed to clear indexed wallet catch-up status on shutdown");
            }
        });
    }
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
