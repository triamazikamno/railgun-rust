pub(super) const WALLET_POI_STATUS_BATCH_SIZE: usize = 1000;
pub(super) const WALLET_POI_RECOVERABLE_REFRESH_AFTER: Duration = Duration::from_mins(1);
pub(super) const WALLET_POI_REFRESH_INTERVAL: Duration = Duration::from_secs(15);
pub(super) const LOCAL_PENDING_SPENT_TTL: Duration = Duration::from_mins(10);
pub(super) const OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER: Duration = Duration::from_mins(10);
pub(super) const OUTPUT_POI_RECOVERY_PROOF_FAILURE_RETRY_AFTER: Duration = Duration::from_hours(24);
pub(super) const OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER: Duration = Duration::from_hours(24);
pub(super) const PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER: Duration = Duration::from_mins(5);
pub(super) const OUTPUT_POI_RECOVERY_VERIFY_PROOF: bool = true;
pub(super) const OUTPUT_POI_RECOVERY_SLOW_STEP_AFTER: Duration = Duration::from_secs(5);
pub(super) const EVM_CHAIN_TYPE: u8 = 0;
pub(super) const RETIRED_WALLET_ACTOR_ID: u64 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WalletPoiRefreshSelection {
    Required,
    RequiredOrRecoverable,
    RecoverableStale { now: u64 },
    Recoverable,
    CorpusRevision { blocked_shields_changed: bool },
}

impl WalletPoiRefreshSelection {
    pub(super) const fn as_str(&self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::RequiredOrRecoverable => "required_or_recoverable",
            Self::RecoverableStale { .. } => "recoverable_stale",
            Self::Recoverable => "recoverable",
            Self::CorpusRevision { .. } => "corpus_revision",
        }
    }

    pub(super) fn matches_wallet_utxo(
        self,
        wallet_utxo: &WalletUtxo,
        active_list_keys: &[FixedBytes<32>],
    ) -> bool {
        match self {
            Self::Required => {
                wallet_utxo.utxo.poi.refreshed_at.is_none()
                    || active_list_keys
                        .iter()
                        .any(|list_key| !wallet_utxo.utxo.poi.statuses.contains_key(list_key))
            }
            Self::RequiredOrRecoverable => {
                Self::Required.matches_wallet_utxo(wallet_utxo, active_list_keys)
                    || wallet_utxo
                        .utxo
                        .poi
                        .has_recoverable_status_for_lists(active_list_keys)
            }
            Self::Recoverable => wallet_utxo
                .utxo
                .poi
                .has_recoverable_status_for_lists(active_list_keys),
            Self::CorpusRevision {
                blocked_shields_changed,
            } => {
                wallet_utxo
                    .utxo
                    .poi
                    .has_recoverable_status_for_lists(active_list_keys)
                    || (blocked_shields_changed
                        && matches!(
                            wallet_utxo.utxo.poi.commitment_kind,
                            UtxoCommitmentKind::Shield
                        ))
            }
            Self::RecoverableStale { now } => {
                wallet_utxo
                    .utxo
                    .poi
                    .has_recoverable_status_for_lists(active_list_keys)
                    && wallet_utxo
                        .utxo
                        .poi
                        .refreshed_at
                        .is_none_or(|refreshed_at| {
                            now.saturating_sub(refreshed_at)
                                >= WALLET_POI_RECOVERABLE_REFRESH_AFTER.as_secs()
                        })
            }
        }
    }
}

use super::pending_output_poi::WalletPpoiWorkflowProjection;
use super::{
    Arc, AtomicU64, BTreeMap, BackfillEvent, CancellationToken, Duration, FixedBytes, Mutex,
    Ordering, OutputPoiRecoveryAction, OutputPoiRecoveryRecord, OwnedMutexGuard,
    PendingOutputPoiContextIntent, PendingOutputPoiContextRecord, PoiStatus, PublicPoiCorpusHandle,
    RwLock, SenderCandidatePublicDataFence, SenderTransactionCandidate,
    SenderTransactionCandidateUnshield, SyncProgressUpdate, Utxo, UtxoCommitmentKind,
    UtxoPoiMetadata, UtxoSource, WalletActorApplyToken, WalletActorCommitToken,
    WalletActorLifecycle, WalletActorLifecycleCell, WalletActorTerminalToken,
    WalletBackfillRejectReason, WalletBackfillStartResult, WalletCacheError, WalletCacheKey,
    WalletCurrentSnapshot, WalletInactiveReason, WalletIndexedCatchUpStatus, WalletObservation,
    WalletObservationPublisher, WalletPendingSpentMarkOutcome, WalletPpoiWorkflowStatus,
    WalletPrivateRequestError, WalletReadiness, WalletResetToken, WalletScanRows, WalletSyncToken,
    WalletUtxo, WalletViewState, Weak, chain_pending_overlay_matches, debug, mpsc, now_epoch_secs,
    oneshot, wallet_utxo_stable_identity, warn, watch,
};
use crate::types::{ChainKey, PoiCorpusRevision, SyncProgressSender, WalletSyncTargetLease};

mod authority;
mod poi_delta;

/// The tracing target the split-out submodules log under, as before the split.
const LOG_TARGET: &str = module_path!();

pub(crate) use authority::{
    WalletPrivateMutationAuthority, WalletPrivateMutationPermit, WalletPrivateRemoteAuthority,
};
pub(crate) use poi_delta::{
    ExpectedPoiCorpusRevision, ExpectedPoiListState, ExpectedPoiStatus, ExpectedRecordState,
    ExpectedWalletOutput, LocallyValidPendingListsDelta, OutputRecoveryDelta, OwnedPoiPrivateDelta,
    PendingContextTerminalDelta, PendingOutputPoiSubject, PendingOutputPoiSubmissionPredicate,
    PendingOutputPoiValidationEvidence, PendingSubmissionDelta, PoiPrivateApplyOutcome,
    PoiStatusRefreshDelta, RecoveredOutgoingSubmissionDelta, RecoveredOutgoingSubmissionSibling,
    SenderCandidateLocallyValidDelta, SenderCandidateMaterializationDelta,
    SenderCandidateReconstructionDelta, SenderCandidateUnshieldUpdateDelta,
    SenderCandidateUnshieldValidatedDelta, VerifiedValidDelta, WalletPrivateApplyClient,
    WalletPrivateApplyRequest,
};

#[derive(Debug, Clone)]
pub struct WalletHandle {
    pub cache_key: WalletCacheKey,
    pub(super) chain: ChainKey,
    pub(super) actor_id: u64,
    pub(super) active_actor_id: Arc<AtomicU64>,
    pub(super) lifecycle: Arc<WalletActorLifecycleCell>,
    pub(super) authority_lock: Arc<Mutex<()>>,
    pub(super) utxos: Arc<RwLock<Vec<WalletUtxo>>>,
    pub(super) pending_overlay: Arc<RwLock<WalletPendingOverlay>>,
    pub(super) last_scanned: Arc<AtomicU64>,
    pub(super) reset_generation: Arc<AtomicU64>,
    /// Private remote-job invalidation. Updated synchronously with reset generation.
    pub(super) reset_generation_rx: watch::Receiver<u64>,
    pub(super) next_sync_job_id: Arc<AtomicU64>,
    pub(super) observation: Weak<WalletObservationPublisher>,
    pub(super) observation_rx: watch::Receiver<WalletObservation>,
    pub rev_rx: watch::Receiver<u64>,
    pub poi_refreshing_rx: watch::Receiver<bool>,
    pub indexed_catch_up_rx: watch::Receiver<Option<WalletIndexedCatchUpStatus>>,
    pub(super) pending_overlay_tx: mpsc::Sender<WalletPendingOverlayRequest>,
    pub(super) private_request_tx: mpsc::Sender<WalletPrivateRequest>,
    pub(super) poi_refresh_tx: mpsc::Sender<WalletPoiRefreshRequest>,
    pub(super) indexed_catch_up_status_tx: mpsc::UnboundedSender<WalletIndexedCatchUpCommand>,
    pub(super) rev_tx: watch::Sender<u64>,
    pub(super) reset_generation_tx: watch::Sender<u64>,
    pub(super) indexed_catch_up_tx: watch::Sender<Option<WalletIndexedCatchUpStatus>>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct WalletActorTokenAuthority<'a> {
    handle: &'a WalletHandle,
}

impl WalletActorTokenAuthority<'_> {
    #[must_use]
    pub(crate) const fn chain_id(self) -> u64 {
        self.handle.chain.chain_id
    }

    #[must_use]
    pub(crate) const fn actor_id(self) -> u64 {
        self.handle.actor_id
    }
}

#[derive(Debug)]
pub(crate) struct WalletIndexedCatchUpLease {
    token: WalletSyncToken,
    _liveness: oneshot::Sender<()>,
}

impl WalletIndexedCatchUpLease {
    #[must_use]
    pub(super) const fn for_actor_accepted_job(
        token: WalletSyncToken,
        liveness: oneshot::Sender<()>,
    ) -> Self {
        Self {
            token,
            _liveness: liveness,
        }
    }

    #[must_use]
    pub(crate) const fn token(&self) -> WalletSyncToken {
        self.token
    }
}

#[derive(Debug)]
pub(super) struct WalletPendingOverlayRequest {
    pub(super) update: WalletPendingOverlayUpdate,
    pub(super) token: WalletSyncToken,
    pub(super) reset_generation: u64,
    pub(super) last_scanned: u64,
}

#[derive(Debug)]
pub(super) enum WalletPendingOverlayUpdate {
    PublicRows(WalletScanRows),
    Clear,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum WalletPrivateViewTicket {
    Current {
        reset_generation: u64,
        last_scanned: u64,
    },
    ResetPending {
        reset_generation: u64,
    },
}

impl WalletPrivateViewTicket {
    pub(super) const fn reset_generation(self) -> u64 {
        match self {
            Self::Current {
                reset_generation, ..
            }
            | Self::ResetPending { reset_generation } => reset_generation,
        }
    }
}

#[derive(Debug)]
pub(super) enum WalletPrivateRequest {
    MarkLocalPendingSpent {
        utxos: Vec<Utxo>,
        tx_hash: Option<FixedBytes<32>>,
        reply: oneshot::Sender<Result<WalletPendingSpentMarkOutcome, WalletPrivateRequestError>>,
    },
    ClearLocalPendingSpent {
        reply: oneshot::Sender<Result<bool, WalletPrivateRequestError>>,
    },
    CreatePendingOutputContexts {
        ticket: WalletPrivateViewTicket,
        contexts: Vec<PendingOutputPoiContextIntent>,
        reply: oneshot::Sender<Result<usize, WalletPrivateRequestError>>,
    },
}

#[derive(Debug)]
pub(super) enum WalletIndexedCatchUpCommand {
    Claim {
        response: oneshot::Sender<Option<WalletIndexedCatchUpLease>>,
    },
    Publish {
        token: WalletSyncToken,
        status: WalletIndexedCatchUpStatus,
    },
}

pub(super) use crate::types::WalletPendingOverlay;

impl WalletHandle {
    #[must_use]
    pub(crate) const fn chain_key(&self) -> &ChainKey {
        &self.chain
    }

    #[must_use]
    pub(crate) fn same_actor_as(&self, other: &Self) -> bool {
        self.chain == other.chain
            && self.cache_key == other.cache_key
            && self.actor_id == other.actor_id
            && Arc::ptr_eq(&self.active_actor_id, &other.active_actor_id)
    }

    #[must_use]
    pub(crate) const fn actor_id(&self) -> u64 {
        self.actor_id
    }

    #[must_use]
    pub(crate) fn is_current_actor(&self) -> bool {
        self.actor_id != RETIRED_WALLET_ACTOR_ID
            && self.active_actor_id.load(Ordering::Acquire) == self.actor_id
    }

    #[must_use]
    pub(crate) fn lifecycle(&self) -> WalletActorLifecycle {
        self.lifecycle.get()
    }

    pub(crate) fn activate_actor(&self) -> bool {
        self.lifecycle.activate()
    }

    /// Exactly one terminal Shutdown publish while Stopping and still current.
    /// Runs `publish` under the lifecycle fence so retire cannot interleave.
    pub(crate) fn publish_terminal_shutdown_if_allowed(
        &self,
        publish: impl for<'a> FnOnce(WalletActorTerminalToken<'a>),
    ) -> bool {
        self.lifecycle
            .publish_terminal_shutdown_if_allowed(self.is_current_actor(), publish)
    }

    pub(super) fn revalidate_durable_commit(
        &self,
        cancel: &CancellationToken,
        expected_reset_generation: u64,
    ) -> Result<(), WalletBackfillRejectReason> {
        if cancel.is_cancelled() {
            return Err(WalletBackfillRejectReason::Shutdown);
        }
        if !self.lifecycle().allows_durable_commits() || !self.is_current_actor() {
            return Err(WalletBackfillRejectReason::Shutdown);
        }
        let current_reset_generation = self.authority_reset_generation();
        if current_reset_generation != expected_reset_generation {
            return Err(WalletBackfillRejectReason::StaleGeneration {
                expected: current_reset_generation,
                actual: expected_reset_generation,
            });
        }
        Ok(())
    }

    async fn actor_authority(
        &self,
        cancel: &CancellationToken,
        expected_reset_generation: u64,
    ) -> Result<OwnedMutexGuard<()>, WalletBackfillRejectReason> {
        let guard = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(WalletBackfillRejectReason::Shutdown),
            guard = Arc::clone(&self.authority_lock).lock_owned() => guard,
        };
        if !self.lifecycle().allows_durable_commits() || !self.is_current_actor() {
            return Err(WalletBackfillRejectReason::Shutdown);
        }
        let current_reset_generation = self.authority_reset_generation();
        if current_reset_generation != expected_reset_generation {
            return Err(WalletBackfillRejectReason::StaleGeneration {
                expected: current_reset_generation,
                actual: expected_reset_generation,
            });
        }
        Ok(guard)
    }

    pub(crate) fn retire_actor_with_publisher(&self, observation: &WalletObservationPublisher) {
        self.retire_actor_with_observation(Some(observation), WalletInactiveReason::Retired);
    }

    pub(crate) fn retire_actor_for_shutdown(&self, observation: &WalletObservationPublisher) {
        self.retire_actor_with_observation(Some(observation), WalletInactiveReason::Shutdown);
    }

    fn retire_actor_with_observation(
        &self,
        observation: Option<&WalletObservationPublisher>,
        reason: WalletInactiveReason,
    ) {
        self.lifecycle.mark_retired(|| {
            self.active_actor_id
                .store(RETIRED_WALLET_ACTOR_ID, Ordering::Release);
            if let Some(observation) = observation {
                observation.publish_terminal(reason, self.authority_reset_generation());
            }
        });
    }

    pub(crate) fn terminalize_panicked_actor(&self, observation: &WalletObservationPublisher) {
        let _ = self.publish_terminal_shutdown_if_allowed(|_token| {
            observation.publish_terminal(
                WalletInactiveReason::Shutdown,
                self.authority_reset_generation(),
            );
        });
    }

    /// Final validation + synchronous private apply under the lifecycle fence.
    /// Rejects if not Active/current, cancelled, or reset generation is stale.
    pub(crate) fn with_active_apply<R>(
        &self,
        cancel: &CancellationToken,
        expected_reset_generation: u64,
        apply: impl for<'a> FnOnce(WalletActorApplyToken<'a>) -> R,
    ) -> Result<R, WalletBackfillRejectReason> {
        match self
            .lifecycle
            .with_active_apply(self.is_current_actor(), |token| {
                if cancel.is_cancelled() {
                    return Err(WalletBackfillRejectReason::Shutdown);
                }
                let current_reset_generation = self.authority_reset_generation();
                if current_reset_generation != expected_reset_generation {
                    return Err(WalletBackfillRejectReason::StaleGeneration {
                        expected: current_reset_generation,
                        actual: expected_reset_generation,
                    });
                }
                Ok(apply(token))
            }) {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(reason)) => Err(reason),
            Err(()) => Err(WalletBackfillRejectReason::Shutdown),
        }
    }

    pub(super) fn with_active_private_request<R>(
        &self,
        cancel: &CancellationToken,
        request: impl FnOnce() -> Result<R, WalletPrivateRequestError>,
    ) -> Result<R, WalletPrivateRequestError> {
        self.lifecycle
            .with_active_request(self.is_current_actor(), || {
                if cancel.is_cancelled() {
                    Err(WalletPrivateRequestError::Inactive)
                } else {
                    request()
                }
            })
            .unwrap_or(Err(WalletPrivateRequestError::Inactive))
    }

    pub(crate) fn mint_sync_token(&self, reset_generation: u64) -> WalletSyncToken {
        WalletSyncToken::mint(
            WalletActorTokenAuthority { handle: self },
            reset_generation,
            self.next_sync_job_id.fetch_add(1, Ordering::AcqRel),
        )
    }

    /// Start generation-scoped backfill from a public progress ticket.
    ///
    /// Revalidates `progress` before requesting acceptance. Only the actor constructs the
    /// returned lease after recording the job and its liveness monitor.
    pub(crate) async fn start_backfill(
        &self,
        cache_key: &str,
        sender: &mpsc::Sender<BackfillEvent>,
        progress: crate::types::WalletSchedulableProgress,
        target_block: u64,
    ) -> WalletBackfillStartResult {
        let Some(progress) = self.revalidate_schedulable_progress(progress) else {
            let current = self.schedulable_progress();
            return WalletBackfillStartResult::Rejected {
                committed_to: self.last_scanned_raw(),
                reason: WalletBackfillRejectReason::StaleGeneration {
                    expected: current.map_or(progress.reset_generation, |p| p.reset_generation),
                    actual: progress.reset_generation,
                },
            };
        };
        let (response, result_rx) = oneshot::channel();
        if let Err(err) = sender
            .send(BackfillEvent::Start {
                target_block,
                token: self.mint_sync_token(progress.reset_generation),
                response,
            })
            .await
        {
            warn!(
                ?err,
                cache_key, target_block, "failed to send wallet backfill start"
            );
            return WalletBackfillStartResult::Rejected {
                committed_to: self.last_scanned_raw(),
                reason: WalletBackfillRejectReason::Shutdown,
            };
        }
        result_rx
            .await
            .unwrap_or(WalletBackfillStartResult::Rejected {
                committed_to: self.last_scanned_raw(),
                reason: WalletBackfillRejectReason::Shutdown,
            })
    }

    pub(crate) async fn reserve_sync_target(
        &self,
        cache_key: &str,
        sender: &mpsc::Sender<BackfillEvent>,
        progress: crate::types::WalletSchedulableProgress,
        target_block: u64,
    ) -> Result<WalletSyncTargetLease, WalletBackfillRejectReason> {
        let Some(progress) = self.revalidate_schedulable_progress(progress) else {
            let current = self.schedulable_progress();
            return Err(WalletBackfillRejectReason::StaleGeneration {
                expected: current.map_or(progress.reset_generation, |p| p.reset_generation),
                actual: progress.reset_generation,
            });
        };
        let (response, result_rx) = oneshot::channel();
        sender
            .send(BackfillEvent::ReserveTarget {
                target_block,
                token: self.mint_sync_token(progress.reset_generation),
                response,
            })
            .await
            .map_err(|err| {
                warn!(
                    ?err,
                    cache_key, target_block, "failed to reserve wallet sync target"
                );
                WalletBackfillRejectReason::Shutdown
            })?;
        result_rx
            .await
            .unwrap_or(Err(WalletBackfillRejectReason::Shutdown))
    }

    /// Revalidate a stored progress ticket against the current public view.
    ///
    /// Returns refreshed progress (same generation, possibly advanced cursor) or `None` if
    /// the view is reset-pending or the generation changed.
    #[must_use]
    pub(crate) fn revalidate_schedulable_progress(
        &self,
        progress: crate::types::WalletSchedulableProgress,
    ) -> Option<crate::types::WalletSchedulableProgress> {
        progress.revalidate(self.schedulable_progress())
    }

    pub(crate) const fn mint_reset_token(&self, intent_id: u64) -> WalletResetToken {
        WalletResetToken::mint(WalletActorTokenAuthority { handle: self }, intent_id)
    }

    /// Current cursor only when view is [`WalletViewState::Current`].
    /// Returns `None` while reset is pending (do not treat pre-reset cursor as current).
    #[must_use]
    pub fn last_scanned(&self) -> Option<u64> {
        self.view_state().last_scanned_current()
    }

    /// Raw durable cursor for actor-internal use (may be pre-reset while public view is pending).
    ///
    /// Never use for catch-up / hedge / lag scheduling — use [`Self::last_scanned`],
    /// [`Self::schedulable_progress`], or [`Self::wait_schedulable_progress`].
    #[must_use]
    pub(crate) fn last_scanned_raw(&self) -> u64 {
        self.last_scanned.load(Ordering::Relaxed)
    }

    /// Generation-scoped public progress ticket from one view observation.
    ///
    /// Returns `None` while reset-pending. This is the only public scheduling capability;
    /// pass it through to [`Self::start_backfill`] / catch-up APIs (revalidated at start).
    #[must_use]
    pub fn schedulable_progress(&self) -> Option<crate::types::WalletSchedulableProgress> {
        self.view_state().schedulable_progress()
    }

    /// Wait until the public view is [`WalletViewState::Current`], then return
    /// view-stamped `(last_scanned, reset_generation)` for scheduling.
    ///
    /// Generation comes from the view snapshot only — never from authority generation —
    /// so `AcceptReset` cannot pair an old cursor with a newly advanced atomic generation.
    pub(crate) async fn wait_schedulable_progress(
        &self,
        cancel: &CancellationToken,
    ) -> Option<crate::types::WalletSchedulableProgress> {
        let mut observation_rx = self.observation_rx.clone();
        loop {
            if cancel.is_cancelled() {
                return None;
            }
            let observation = observation_rx.borrow_and_update().clone();
            if let Some(progress) = observation.view().schedulable_progress() {
                return Some(progress);
            }
            tokio::select! {
                () = cancel.cancelled() => return None,
                changed = observation_rx.changed() => {
                    if changed.is_err() {
                        return None;
                    }
                }
            }
        }
    }

    #[must_use]
    pub fn view_state(&self) -> WalletViewState {
        self.observation().view().clone()
    }

    #[must_use]
    pub fn readiness(&self) -> WalletReadiness {
        self.observation().readiness().clone()
    }

    #[must_use]
    pub fn observation(&self) -> WalletObservation {
        self.observation_rx.borrow().clone()
    }

    #[must_use]
    pub fn subscribe_observation(&self) -> watch::Receiver<WalletObservation> {
        self.observation_rx.clone()
    }

    /// Authority reset generation for token revalidation and actor minting.
    ///
    /// Not for public scheduling: may advance before [`WalletViewState`] is republished.
    /// Use [`Self::schedulable_progress`] / [`Self::wait_schedulable_progress`] instead.
    #[must_use]
    pub(crate) fn authority_reset_generation(&self) -> u64 {
        self.reset_generation.load(Ordering::Relaxed)
    }

    pub(crate) fn set_indexed_catch_up(
        &self,
        lease: &WalletIndexedCatchUpLease,
        status: WalletIndexedCatchUpStatus,
    ) {
        if let Err(err) =
            self.indexed_catch_up_status_tx
                .send(WalletIndexedCatchUpCommand::Publish {
                    token: lease.token(),
                    status,
                })
        {
            debug!(?err, cache_key = %self.cache_key, "failed to request indexed wallet catch-up status publication");
        }
    }

    pub(crate) async fn try_claim_indexed_catch_up(&self) -> Option<WalletIndexedCatchUpLease> {
        let (response, result) = oneshot::channel();
        if self
            .indexed_catch_up_status_tx
            .send(WalletIndexedCatchUpCommand::Claim { response })
            .is_err()
        {
            return None;
        }
        result.await.unwrap_or(None)
    }

    fn notify_changed_with_projection(&self, utxos: &[WalletUtxo], overlay: &WalletPendingOverlay) {
        self.increment_revision();
        if self.observation_rx.borrow().view().is_current() {
            self.publish_view_current_projection(utxos, overlay);
        }
    }

    fn increment_revision(&self) {
        let rev = self.rev_rx.borrow().wrapping_add(1);
        if let Err(err) = self.rev_tx.send(rev) {
            debug!(?err, cache_key = %self.cache_key, "failed to send wallet revision");
        }
    }

    /// Publish full private projection as [`WalletViewState::Current`].
    /// Call only with mirrors that match actor-owned state at this apply.
    fn current_view_projection(
        &self,
        utxos: &[WalletUtxo],
        overlay: &WalletPendingOverlay,
    ) -> WalletViewState {
        let last_scanned = self.last_scanned.load(Ordering::Relaxed);
        let revision = *self.rev_rx.borrow();
        let reset_generation = self.authority_reset_generation();
        let snapshot = WalletCurrentSnapshot::new(
            last_scanned,
            revision,
            reset_generation,
            Arc::<[WalletUtxo]>::from(utxos.to_vec()),
            Arc::new(overlay.clone()),
        );
        WalletViewState::Current(snapshot)
    }

    fn publish_view_current_projection(
        &self,
        utxos: &[WalletUtxo],
        overlay: &WalletPendingOverlay,
    ) {
        let view = self.current_view_projection(utxos, overlay);
        if let Some(observation) = self.observation.upgrade() {
            observation.publish_view(view);
        }
    }

    /// Pending tip overlay only when view is [`WalletViewState::Current`].
    /// Sole public source is the published projection (not the live lock).
    #[must_use]
    pub fn pending_overlay(&self) -> Option<Arc<WalletPendingOverlay>> {
        self.current_snapshot()
            .map(|snapshot| Arc::clone(&snapshot.pending_overlay))
    }

    async fn request_pending_overlay_update(
        &self,
        update: WalletPendingOverlayUpdate,
        reset_generation: u64,
        last_scanned: u64,
    ) -> bool {
        let token = self.mint_sync_token(reset_generation);
        self.pending_overlay_tx
            .send(WalletPendingOverlayRequest {
                update,
                token,
                reset_generation,
                last_scanned,
            })
            .await
            .is_ok()
    }

    pub(crate) async fn request_pending_overlay_rows(
        &self,
        rows: WalletScanRows,
        reset_generation: u64,
        last_scanned: u64,
    ) -> bool {
        self.request_pending_overlay_update(
            WalletPendingOverlayUpdate::PublicRows(rows),
            reset_generation,
            last_scanned,
        )
        .await
    }

    pub(crate) async fn request_pending_overlay_clear(
        &self,
        reset_generation: u64,
        last_scanned: u64,
    ) -> bool {
        self.request_pending_overlay_update(
            WalletPendingOverlayUpdate::Clear,
            reset_generation,
            last_scanned,
        )
        .await
    }

    /// UTXO snapshot only when view is [`WalletViewState::Current`].
    /// Returns `None` while reset is pending.
    #[must_use]
    pub fn utxos_snapshot(&self) -> Option<Arc<[WalletUtxo]>> {
        self.current_snapshot()
            .map(|snapshot| Arc::clone(&snapshot.utxos))
    }

    /// Coherent current private snapshot from the published view, or `None` while reset-pending.
    ///
    /// This is the sole public private-projection choke point (UTXOs + pending overlay + stamps).
    #[must_use]
    pub fn current_snapshot(&self) -> Option<Arc<WalletCurrentSnapshot>> {
        self.view_state().current_snapshot()
    }

    fn private_request_ticket(&self) -> Result<WalletPrivateViewTicket, WalletPrivateRequestError> {
        match self.view_state() {
            WalletViewState::Current(snapshot) => Ok(WalletPrivateViewTicket::Current {
                reset_generation: snapshot.reset_generation,
                last_scanned: snapshot.last_scanned,
            }),
            WalletViewState::ResetPending {
                reset_generation, ..
            } => Ok(WalletPrivateViewTicket::ResetPending { reset_generation }),
            WalletViewState::Inactive { .. } => Err(WalletPrivateRequestError::Inactive),
        }
    }

    pub async fn mark_pending_spent_utxos(
        &self,
        utxos: &[Utxo],
        tx_hash: Option<FixedBytes<32>>,
    ) -> Result<WalletPendingSpentMarkOutcome, WalletPrivateRequestError> {
        let (reply, result) = oneshot::channel();
        self.private_request_tx
            .send(WalletPrivateRequest::MarkLocalPendingSpent {
                utxos: utxos.to_vec(),
                tx_hash,
                reply,
            })
            .await
            .map_err(|_| WalletPrivateRequestError::Inactive)?;
        result
            .await
            .unwrap_or(Err(WalletPrivateRequestError::Inactive))
    }

    /// Clears every local submitted-transaction lock for this wallet as one explicit action.
    pub async fn clear_all_local_pending_spent(&self) -> Result<bool, WalletPrivateRequestError> {
        let (reply, result) = oneshot::channel();
        self.private_request_tx
            .send(WalletPrivateRequest::ClearLocalPendingSpent { reply })
            .await
            .map_err(|_| WalletPrivateRequestError::Inactive)?;
        result
            .await
            .unwrap_or(Err(WalletPrivateRequestError::Inactive))
    }

    pub async fn create_pending_output_poi_contexts(
        &self,
        contexts: Vec<PendingOutputPoiContextIntent>,
    ) -> Result<usize, WalletPrivateRequestError> {
        let ticket = self.private_request_ticket()?;
        let (reply, result) = oneshot::channel();
        self.private_request_tx
            .send(WalletPrivateRequest::CreatePendingOutputContexts {
                ticket,
                contexts,
                reply,
            })
            .await
            .map_err(|_| WalletPrivateRequestError::Inactive)?;
        result
            .await
            .unwrap_or(Err(WalletPrivateRequestError::Inactive))
    }

    async fn replace_chain_pending_overlay_authorized(
        &self,
        next: WalletPendingOverlay,
        permit: &WalletPrivateMutationPermit<'_>,
    ) -> Result<bool, WalletBackfillRejectReason> {
        permit.revalidate()?;
        let now = now_epoch_secs();
        let confirmed_spent: Vec<_> = {
            let utxos = self.utxos.read().await;
            permit.revalidate()?;
            utxos
                .iter()
                .filter(|utxo| utxo.is_spent())
                .cloned()
                .collect()
        };
        let mut overlay = self.pending_overlay.write().await;
        permit.with_active_apply(|_token| {
            let chain_changed = !chain_pending_overlay_matches(&overlay, &next);
            let before_local = overlay.local_pending_spent.len();
            overlay.local_pending_spent.retain(|spent| {
                if confirmed_spent
                    .iter()
                    .any(|utxo| spent.matches_local_utxo(utxo))
                {
                    return false;
                }
                let submitted_at = spent.block_timestamp.unwrap_or(now);
                now.saturating_sub(submitted_at) < LOCAL_PENDING_SPENT_TTL.as_secs()
            });
            let local_changed = overlay.local_pending_spent.len() != before_local;
            overlay.new_utxos = next.new_utxos;
            overlay.pending_spent = next.pending_spent;
            chain_changed || local_changed
        })
    }

    pub async fn refresh_poi_statuses(&self) -> bool {
        self.poi_refresh_tx
            .send(WalletPoiRefreshRequest {
                force_output_poi_recovery: true,
            })
            .await
            .is_ok()
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct WalletPoiRefreshRequest {
    pub(super) force_output_poi_recovery: bool,
}

#[cfg(test)]
pub(super) mod test_support;
