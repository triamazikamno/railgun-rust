//! Wallet actor ownership core.
//!
//! Invariants:
//! 1. Only the wallet actor mutates private durable state and publishes mirrors.
//! 2. Actor turns do local work / spawn remote jobs; they do not await remote POI/RPC.
//! 3. Remote POI jobs re-enter via [`crate::wallet::WalletPrivateApplyClient`] (or the
//!    worker's `WalletRemoteDone` messages) for durable apply; jobs never write UTXO mirrors
//!    directly.
//! 4. Remote results apply only if actor credential is still current.
//! 5. While durable pending reset is set, published private view is fenced; chain
//!    scheduling uses public `schedulable_progress` / `wait_schedulable_progress` only
//!    (cursor + generation from one view snapshot; never authority generation).
//!
//! Lifecycle is separate from [`CancellationToken`]: cancel stops async work and may
//! drive Prepared/Active → Stopping; publication authority is lifecycle-based.
//!
//! The lifecycle fence is a short `std::sync::Mutex` used only for lifecycle transitions
//! and Active/Stopping private applies. It must never be held across remote I/O.

use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::types::{
    WalletBackfillOwnerDisposition, WalletBackfillRejectReason, WalletInactiveReason,
    WalletIndexedCatchUpStatus, WalletObservation, WalletPpoiSubmissionStatus,
    WalletPpoiWorkflowStatus, WalletPrivateRequestError, WalletReadiness, WalletReadinessError,
    WalletResetReplayPlan, WalletResetToken, WalletSyncToken, WalletViewState,
};

use super::handle::{WalletPoiRefreshSelection, WalletPrivateViewTicket};
use super::pending_output_poi::WalletPpoiWorkflowProjection;

/// Publication and apply authority for a wallet actor instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub(crate) enum WalletActorLifecycle {
    /// Bootstrap may apply durable state, but the actor is not registered or mailbox-active yet.
    Prepared = 0,
    /// Normal apply and publish.
    Active = 1,
    /// Cancel observed while still current; exactly one terminal Shutdown publish; no durable commits.
    Stopping = 2,
    /// Unregistered, replaced, or service-retired; apply nothing.
    Retired = 3,
}

impl WalletActorLifecycle {
    /// Durable private commits and non-terminal publications.
    pub(crate) const fn allows_durable_commits(self) -> bool {
        matches!(self, Self::Prepared | Self::Active)
    }

    /// Terminal Shutdown readiness only.
    pub(crate) const fn allows_terminal_shutdown_publish(self) -> bool {
        matches!(self, Self::Stopping)
    }
}

#[derive(Debug)]
struct LifecycleInner {
    state: WalletActorLifecycle,
    terminal_shutdown_published: bool,
}

/// Shared lifecycle cell for all [`crate::wallet::WalletHandle`] clones of one actor.
#[derive(Debug)]
pub(crate) struct WalletActorLifecycleCell {
    fence: Mutex<LifecycleInner>,
}

#[derive(Debug)]
pub(crate) struct WalletObservationPublisher {
    sender: watch::Sender<WalletObservation>,
}

impl WalletObservationPublisher {
    pub(crate) fn new(
        initial_view: WalletViewState,
    ) -> (Arc<Self>, watch::Receiver<WalletObservation>) {
        let (sender, receiver) = watch::channel(WalletObservation::new(
            initial_view,
            WalletReadiness::Syncing,
        ));
        (Arc::new(Self { sender }), receiver)
    }

    pub(crate) fn publish_readiness(&self, readiness: WalletReadiness) {
        let _ = self.sender.send_if_modified(|published| {
            if published.readiness() == &readiness {
                false
            } else {
                *published = WalletObservation::with_ppoi_workflow_projection(
                    published.view().clone(),
                    readiness,
                    *published.ppoi_workflow_status(),
                    published.ppoi_submission_statuses_arc(),
                );
                true
            }
        });
    }

    pub(crate) fn publish_view(&self, view: WalletViewState) {
        let _ = self.sender.send_if_modified(|published| {
            let submissions = if matches!(&view, WalletViewState::Current(_)) {
                published.ppoi_submission_statuses_arc()
            } else {
                Arc::from([])
            };
            let observation = WalletObservation::with_ppoi_workflow_projection(
                view,
                published.readiness().clone(),
                *published.ppoi_workflow_status(),
                submissions,
            );
            if published == &observation {
                false
            } else {
                published.clone_from(&observation);
                true
            }
        });
    }

    pub(crate) fn publish(&self, view: WalletViewState, readiness: WalletReadiness) {
        let _ = self.sender.send_if_modified(|published| {
            let submissions = if matches!(&view, WalletViewState::Current(_)) {
                published.ppoi_submission_statuses_arc()
            } else {
                Arc::from([])
            };
            let observation = WalletObservation::with_ppoi_workflow_projection(
                view,
                readiness,
                *published.ppoi_workflow_status(),
                submissions,
            );
            if published == &observation {
                false
            } else {
                published.clone_from(&observation);
                true
            }
        });
    }

    fn publish_with_ppoi_workflow_projection(
        &self,
        view: WalletViewState,
        readiness: WalletReadiness,
        projection: WalletPpoiWorkflowProjection,
    ) {
        let submissions = if matches!(&view, WalletViewState::Current(_)) {
            projection.submissions
        } else {
            Arc::from([])
        };
        let observation = WalletObservation::with_ppoi_workflow_projection(
            view,
            readiness,
            projection.status,
            submissions,
        );
        let _ = self.sender.send_if_modified(|published| {
            if published == &observation {
                false
            } else {
                published.clone_from(&observation);
                true
            }
        });
    }

    pub(crate) fn publish_ppoi_workflow_projection(
        &self,
        status: WalletPpoiWorkflowStatus,
        submissions: Arc<[WalletPpoiSubmissionStatus]>,
    ) {
        let _ = self.sender.send_if_modified(|published| {
            let submissions = if matches!(published.view(), WalletViewState::Current(_)) {
                submissions
            } else {
                Arc::from([])
            };
            if published.ppoi_workflow_status() == &status
                && published.ppoi_submission_statuses() == submissions.as_ref()
            {
                false
            } else {
                *published = WalletObservation::with_ppoi_workflow_projection(
                    published.view().clone(),
                    published.readiness().clone(),
                    status,
                    submissions,
                );
                true
            }
        });
    }

    pub(crate) fn publish_ppoi_workflow_status(&self, status: WalletPpoiWorkflowStatus) {
        let submissions = self.sender.borrow().ppoi_submission_statuses_arc();
        self.publish_ppoi_workflow_projection(status, submissions);
    }

    pub(crate) fn ppoi_workflow_status(&self) -> WalletPpoiWorkflowStatus {
        *self.sender.borrow().ppoi_workflow_status()
    }

    pub(crate) fn publish_terminal(&self, reason: WalletInactiveReason, reset_generation: u64) {
        let status = self.ppoi_workflow_status().cleared();
        let observation = WalletObservation::with_ppoi_workflow_projection(
            WalletViewState::Inactive {
                reason,
                reset_generation,
            },
            WalletReadiness::Shutdown,
            status,
            Arc::from([]),
        );
        self.sender.send_replace(observation);
    }
}

impl Default for WalletActorLifecycleCell {
    fn default() -> Self {
        Self::new()
    }
}

impl WalletActorLifecycleCell {
    pub(crate) const fn new() -> Self {
        Self::with_state(WalletActorLifecycle::Active)
    }

    pub(crate) const fn new_prepared() -> Self {
        Self::with_state(WalletActorLifecycle::Prepared)
    }

    const fn with_state(state: WalletActorLifecycle) -> Self {
        Self {
            fence: Mutex::new(LifecycleInner {
                state,
                terminal_shutdown_published: false,
            }),
        }
    }

    fn with_fence<R>(&self, f: impl FnOnce(&mut LifecycleInner) -> R) -> R {
        let mut guard = self
            .fence
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut guard)
    }

    pub(crate) fn get(&self) -> WalletActorLifecycle {
        self.with_fence(|inner| inner.state)
    }

    /// Prepared → Active. Registration must be installed before this transition.
    pub(crate) fn activate(&self) -> bool {
        self.with_fence(|inner| {
            if inner.state == WalletActorLifecycle::Prepared {
                inner.state = WalletActorLifecycle::Active;
                true
            } else {
                false
            }
        })
    }

    /// Any → Retired under the lifecycle fence. Invokes `flip_identity` before unlock
    /// so identity and lifecycle flip atomically w.r.t. terminal publish.
    pub(crate) fn mark_retired(&self, flip_identity: impl FnOnce()) {
        self.with_fence(|inner| {
            inner.state = WalletActorLifecycle::Retired;
            // Poison terminal take so a concurrent shutdown path cannot publish after retire.
            inner.terminal_shutdown_published = true;
            flip_identity();
        });
    }

    /// Moves a current Prepared/Active actor to Stopping and performs its one terminal
    /// publication while holding the lifecycle fence.
    pub(crate) fn publish_terminal_shutdown_if_allowed(
        &self,
        is_current: bool,
        publish: impl for<'a> FnOnce(WalletActorTerminalToken<'a>),
    ) -> bool {
        self.with_fence(|inner| {
            if is_current
                && matches!(
                    inner.state,
                    WalletActorLifecycle::Prepared | WalletActorLifecycle::Active
                )
            {
                inner.state = WalletActorLifecycle::Stopping;
            }
            if !inner.state.allows_terminal_shutdown_publish()
                || inner.terminal_shutdown_published
                || !is_current
            {
                return false;
            }
            inner.terminal_shutdown_published = true;
            publish(WalletActorTerminalToken {
                _fence: PhantomData,
            });
            true
        })
    }

    /// Runs `apply` only while lifecycle allows private commits and `is_current` is true,
    /// holding the lifecycle fence for the entire synchronous apply (never across remote I/O).
    ///
    /// The apply token is lifetime-bound via HRTB so it cannot escape the closure.
    pub(crate) fn with_active_apply<R>(
        &self,
        is_current: bool,
        apply: impl for<'a> FnOnce(WalletActorApplyToken<'a>) -> R,
    ) -> Result<R, ()> {
        self.with_fence(|inner| {
            if !inner.state.allows_durable_commits() || !is_current {
                return Err(());
            }
            Ok(apply(WalletActorApplyToken {
                _fence: PhantomData,
            }))
        })
    }

    /// Runs request admission only while the mailbox actor is Active and current.
    pub(crate) fn with_active_request<R>(
        &self,
        is_current: bool,
        request: impl FnOnce() -> R,
    ) -> Result<R, ()> {
        self.with_fence(|inner| {
            if inner.state != WalletActorLifecycle::Active || !is_current {
                return Err(());
            }
            Ok(request())
        })
    }
}

/// Proof that a private apply is running under the lifecycle fence while apply-authorized.
/// Lifetime is bound to the fence hold; cannot escape [`WalletActorLifecycleCell::with_active_apply`].
#[derive(Debug)]
pub(crate) struct WalletActorApplyToken<'a> {
    _fence: PhantomData<&'a LifecycleInner>,
}

/// Proof that terminal readiness publication is running under the stopping lifecycle fence.
#[derive(Debug)]
pub(crate) struct WalletActorTerminalToken<'a> {
    _fence: PhantomData<&'a LifecycleInner>,
}

/// Alias used by durable commit constructors (same capability as apply token).
pub(crate) type WalletActorCommitToken<'a> = WalletActorApplyToken<'a>;

#[derive(Debug, Clone, Copy)]
pub(super) struct PendingWalletReset {
    intent_id: u64,
    from_block: u64,
    reset_generation: u64,
    replay_plan: WalletResetReplayPlan,
}

impl PendingWalletReset {
    pub(super) const fn new(
        intent_id: u64,
        from_block: u64,
        reset_generation: u64,
        replay_plan: WalletResetReplayPlan,
    ) -> Self {
        Self {
            intent_id,
            from_block,
            reset_generation,
            replay_plan,
        }
    }

    pub(super) const fn intent_id(self) -> u64 {
        self.intent_id
    }

    pub(super) const fn rewind_from_block(self) -> u64 {
        self.from_block
    }

    pub(super) const fn reset_generation(self) -> u64 {
        self.reset_generation
    }

    pub(super) const fn replay_plan(self) -> WalletResetReplayPlan {
        self.replay_plan
    }

    pub(super) fn merge_replay_plan(
        existing: Option<Self>,
        incoming: WalletResetReplayPlan,
    ) -> WalletResetReplayPlan {
        existing.map_or(incoming, |pending| WalletResetReplayPlan {
            start_block: pending.replay_plan.start_block.min(incoming.start_block),
            target_block: pending.replay_plan.target_block.max(incoming.target_block),
            follow_safe_head: pending.replay_plan.follow_safe_head || incoming.follow_safe_head,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WalletActorJobKind {
    SyncTarget,
    Backfill,
    PendingOverlay,
    IndexedCatchUp,
}

#[derive(Debug, Clone)]
struct WalletActorJob {
    reset_generation: u64,
    kind: WalletActorJobKind,
    target_block: Option<u64>,
    indexed_status: Option<WalletIndexedCatchUpStatus>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WalletRequiredPersistRange {
    from_block: u64,
    to_block: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WalletProgressPersistenceRequirement {
    reset_generation: u64,
    range: WalletRequiredPersistRange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WalletCompletionPersistenceRequirement {
    reset_generation: u64,
    token: WalletSyncToken,
    target_block: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WalletJobFailureReason {
    BackfillUnavailable,
    TargetNotReached { target_block: u64 },
    ApplyFailed,
}

impl WalletJobFailureReason {
    const fn readiness_error(&self) -> WalletReadinessError {
        match self {
            Self::BackfillUnavailable => WalletReadinessError::BackfillUnavailable,
            Self::TargetNotReached { target_block } => WalletReadinessError::TargetNotReached {
                target_block: *target_block,
            },
            Self::ApplyFailed => WalletReadinessError::ApplyFailed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WalletJobFailure {
    token: WalletSyncToken,
    target_block: u64,
    reason: WalletJobFailureReason,
}

#[derive(Debug, Default)]
struct WalletPoiPersistenceRequirements {
    reset_generation: Option<u64>,
    required: bool,
    required_or_recoverable: bool,
    recoverable_stale: Option<u64>,
    recoverable: bool,
    corpus_revision: Option<bool>,
}

impl WalletPoiPersistenceRequirements {
    const fn is_empty(&self) -> bool {
        !self.required
            && !self.required_or_recoverable
            && self.recoverable_stale.is_none()
            && !self.recoverable
            && self.corpus_revision.is_none()
    }

    fn insert(&mut self, reset_generation: u64, selection: WalletPoiRefreshSelection) {
        if self.is_empty() {
            self.reset_generation = Some(reset_generation);
        }
        if self.reset_generation != Some(reset_generation) {
            return;
        }
        match selection {
            WalletPoiRefreshSelection::Required => self.required = true,
            WalletPoiRefreshSelection::RequiredOrRecoverable => {
                self.required_or_recoverable = true;
            }
            WalletPoiRefreshSelection::RecoverableStale { now } => {
                self.recoverable_stale =
                    Some(self.recoverable_stale.map_or(now, |old| old.max(now)));
            }
            WalletPoiRefreshSelection::Recoverable => self.recoverable = true,
            WalletPoiRefreshSelection::CorpusRevision {
                blocked_shields_changed,
            } => {
                self.corpus_revision =
                    Some(self.corpus_revision.is_some_and(|old| old) || blocked_shields_changed);
            }
        }
    }

    fn remove(&mut self, reset_generation: u64, selection: WalletPoiRefreshSelection) -> bool {
        if self.reset_generation != Some(reset_generation) {
            return false;
        }
        let removed = match selection {
            WalletPoiRefreshSelection::Required => std::mem::take(&mut self.required),
            WalletPoiRefreshSelection::RequiredOrRecoverable => {
                std::mem::take(&mut self.required_or_recoverable)
            }
            WalletPoiRefreshSelection::RecoverableStale { now } => {
                let covered = self
                    .recoverable_stale
                    .is_some_and(|required| now >= required);
                if covered {
                    self.recoverable_stale = None;
                }
                covered
            }
            WalletPoiRefreshSelection::Recoverable => std::mem::take(&mut self.recoverable),
            WalletPoiRefreshSelection::CorpusRevision {
                blocked_shields_changed,
            } => {
                let covered = self
                    .corpus_revision
                    .is_some_and(|required| !required || blocked_shields_changed);
                if covered {
                    self.corpus_revision = None;
                }
                covered
            }
        };
        if self.is_empty() {
            self.reset_generation = None;
        }
        removed
    }

    fn contains(&self, reset_generation: u64, selection: WalletPoiRefreshSelection) -> bool {
        if self.reset_generation != Some(reset_generation) {
            return false;
        }
        match selection {
            WalletPoiRefreshSelection::Required => self.required,
            WalletPoiRefreshSelection::RequiredOrRecoverable => self.required_or_recoverable,
            WalletPoiRefreshSelection::RecoverableStale { now } => {
                self.recoverable_stale == Some(now)
            }
            WalletPoiRefreshSelection::Recoverable => self.recoverable,
            WalletPoiRefreshSelection::CorpusRevision {
                blocked_shields_changed,
            } => self.corpus_revision == Some(blocked_shields_changed),
        }
    }

    fn next(&self, reset_generation: u64) -> Option<WalletPoiRefreshSelection> {
        if self.reset_generation != Some(reset_generation) {
            return None;
        }
        if self.required {
            Some(WalletPoiRefreshSelection::Required)
        } else if self.required_or_recoverable {
            Some(WalletPoiRefreshSelection::RequiredOrRecoverable)
        } else if let Some(now) = self.recoverable_stale {
            Some(WalletPoiRefreshSelection::RecoverableStale { now })
        } else if self.recoverable {
            Some(WalletPoiRefreshSelection::Recoverable)
        } else {
            self.corpus_revision.map(|blocked_shields_changed| {
                WalletPoiRefreshSelection::CorpusRevision {
                    blocked_shields_changed,
                }
            })
        }
    }

    const fn rebase(&mut self, reset_generation: u64) {
        if !self.is_empty() {
            self.reset_generation = Some(reset_generation);
        }
    }
}

/// Canonical wallet actor state. All fields stay private to this module so mutation and
/// readiness publication cannot be split across actor awaits.
pub(super) struct WalletActorState {
    chain_id: u64,
    actor_id: u64,
    reset_generation: u64,
    last_scanned: u64,
    completed_target_block: Option<u64>,
    poi_persistence_requirements: WalletPoiPersistenceRequirements,
    reset_replay_persistence_requirement: Option<u64>,
    progress_persistence_requirement: Option<WalletProgressPersistenceRequirement>,
    completion_persistence_requirement: Option<WalletCompletionPersistenceRequirement>,
    job_failures: BTreeMap<u64, WalletJobFailure>,
    poi_corpus_refresh_pending: bool,
    shutdown: bool,
    highest_accepted_reset_intent: u64,
    pending_reset: Option<PendingWalletReset>,
    pending_reset_rewind_committed: bool,
    pending_reset_replay_admitted: Option<WalletSyncToken>,
    pending_reset_progress_start_block: Option<u64>,
    active_jobs: BTreeMap<u64, WalletActorJob>,
    highest_accepted_backfill_job_id: u64,
    latest_pending_overlay_job: Option<u64>,
    observation: Arc<WalletObservationPublisher>,
}

/// HRTB-bound mutation facade. Its constructor and state borrow are private, so the borrow
/// cannot escape a synchronous [`WalletActorState::transition`] call.
pub(super) struct WalletActorMutation<'a> {
    state: &'a mut WalletActorState,
}

impl WalletActorState {
    pub(super) fn new(
        chain_id: u64,
        actor_id: u64,
        reset_generation: u64,
        last_scanned: u64,
        highest_accepted_reset_intent: u64,
        pending_reset: Option<PendingWalletReset>,
        poi_corpus_refresh_pending: bool,
        initial_view: WalletViewState,
    ) -> (Self, watch::Receiver<WalletObservation>) {
        let (observation, observation_rx) = WalletObservationPublisher::new(initial_view);
        (
            Self {
                chain_id,
                actor_id,
                reset_generation,
                last_scanned,
                completed_target_block: None,
                poi_persistence_requirements: WalletPoiPersistenceRequirements::default(),
                reset_replay_persistence_requirement: None,
                progress_persistence_requirement: None,
                completion_persistence_requirement: None,
                job_failures: BTreeMap::new(),
                poi_corpus_refresh_pending,
                shutdown: false,
                highest_accepted_reset_intent,
                pending_reset,
                pending_reset_rewind_committed: false,
                pending_reset_replay_admitted: None,
                pending_reset_progress_start_block: None,
                active_jobs: BTreeMap::new(),
                highest_accepted_backfill_job_id: 0,
                latest_pending_overlay_job: None,
                observation,
            },
            observation_rx,
        )
    }

    pub(super) fn observation_publisher(&self) -> Arc<WalletObservationPublisher> {
        Arc::clone(&self.observation)
    }

    /// Lifecycle-authorized synchronous transition. The mutation facade cannot escape this
    /// call, and typed readiness is derived and published before it returns.
    pub(super) fn transition<R>(
        &mut self,
        _token: &WalletActorApplyToken<'_>,
        transition: impl for<'a> FnOnce(WalletActorMutation<'a>) -> R,
    ) -> R {
        let result = transition(WalletActorMutation { state: self });
        self.publish_derived_readiness();
        result
    }

    pub(super) fn transition_with_view<R>(
        &mut self,
        _token: &WalletActorApplyToken<'_>,
        view: WalletViewState,
        transition: impl for<'a> FnOnce(WalletActorMutation<'a>) -> R,
    ) -> R {
        let result = transition(WalletActorMutation { state: self });
        self.observation.publish(view, self.derived_readiness());
        result
    }

    pub(super) fn transition_with_view_and_ppoi_workflow_projection<R>(
        &mut self,
        _token: &WalletActorApplyToken<'_>,
        view: WalletViewState,
        projection: WalletPpoiWorkflowProjection,
        transition: impl for<'a> FnOnce(WalletActorMutation<'a>) -> R,
    ) -> R {
        let result = transition(WalletActorMutation { state: self });
        self.observation.publish_with_ppoi_workflow_projection(
            view,
            self.derived_readiness(),
            projection,
        );
        result
    }

    pub(super) fn transition_active<R>(
        &mut self,
        handle: &crate::wallet::WalletHandle,
        cancel: &CancellationToken,
        transition: impl for<'a> FnOnce(WalletActorMutation<'a>) -> R,
    ) -> Result<R, WalletBackfillRejectReason> {
        let reset_generation = self.reset_generation;
        handle.with_active_apply(cancel, reset_generation, |token| {
            self.transition(&token, transition)
        })
    }

    /// Dedicated terminal transition. The caller must hold the terminal lifecycle fence.
    pub(super) fn transition_terminal_shutdown(
        &mut self,
        _token: &WalletActorTerminalToken<'_>,
        reason: WalletInactiveReason,
        reset_generation: u64,
    ) {
        self.shutdown = true;
        self.active_jobs.clear();
        self.latest_pending_overlay_job = None;
        self.pending_reset_replay_admitted = None;
        self.pending_reset_progress_start_block = None;
        self.poi_persistence_requirements = WalletPoiPersistenceRequirements::default();
        self.reset_replay_persistence_requirement = None;
        self.progress_persistence_requirement = None;
        self.completion_persistence_requirement = None;
        self.job_failures.clear();
        self.observation.publish_terminal(reason, reset_generation);
    }

    fn publish_derived_readiness(&self) {
        self.observation.publish_readiness(self.derived_readiness());
    }

    fn derived_readiness(&self) -> WalletReadiness {
        if self.shutdown {
            return WalletReadiness::Shutdown;
        }
        if self.has_persistence_failure() {
            return WalletReadiness::Failed(WalletReadinessError::PersistenceFailed);
        }
        if let Some(failure) = self.job_failures.values().next() {
            return WalletReadiness::Failed(failure.reason.readiness_error());
        }
        if self.pending_reset.is_some() || self.poi_corpus_refresh_pending {
            return WalletReadiness::Syncing;
        }
        if self.active_jobs.values().any(|job| {
            matches!(
                job.kind,
                WalletActorJobKind::SyncTarget
                    | WalletActorJobKind::Backfill
                    | WalletActorJobKind::IndexedCatchUp
            )
        }) {
            return WalletReadiness::Syncing;
        }
        match self.completed_target_block {
            Some(target_block) if target_block > 0 && self.last_scanned >= target_block => {
                WalletReadiness::Ready
            }
            _ => WalletReadiness::Syncing,
        }
    }

    pub(super) const fn reset_generation(&self) -> u64 {
        self.reset_generation
    }

    pub(super) const fn completed_target_block(&self) -> Option<u64> {
        self.completed_target_block
    }

    pub(super) const fn highest_accepted_reset_intent(&self) -> u64 {
        self.highest_accepted_reset_intent
    }

    pub(super) const fn pending_reset(&self) -> Option<PendingWalletReset> {
        self.pending_reset
    }

    pub(super) const fn pending_reset_rewind_committed(&self) -> bool {
        self.pending_reset_rewind_committed
    }

    pub(super) const fn pending_reset_replay_admitted(&self) -> Option<WalletSyncToken> {
        self.pending_reset_replay_admitted
    }

    pub(super) fn progress_start_block(&self, token: WalletSyncToken) -> Option<u64> {
        if self.pending_reset_replay_admitted == Some(token) {
            self.pending_reset_progress_start_block
        } else {
            None
        }
    }

    pub(super) const fn poi_corpus_refresh_pending(&self) -> bool {
        self.poi_corpus_refresh_pending
    }

    pub(super) const fn has_persistence_failure(&self) -> bool {
        !self.poi_persistence_requirements.is_empty()
            || self.reset_replay_persistence_requirement.is_some()
            || self.progress_persistence_requirement.is_some()
            || self.completion_persistence_requirement.is_some()
    }

    pub(super) fn failed_poi_status_refresh_selection(
        &self,
        reset_generation: u64,
    ) -> Option<WalletPoiRefreshSelection> {
        self.poi_persistence_requirements.next(reset_generation)
    }

    pub(super) fn has_failed_poi_status_refresh(
        &self,
        reset_generation: u64,
        selection: WalletPoiRefreshSelection,
    ) -> bool {
        self.poi_persistence_requirements
            .contains(reset_generation, selection)
    }

    pub(super) fn has_active_backfill_job(&self) -> bool {
        self.active_jobs
            .values()
            .any(|job| job.kind == WalletActorJobKind::Backfill)
    }

    pub(super) fn active_backfill_target(&self) -> Option<u64> {
        self.active_jobs
            .values()
            .filter(|job| job.kind == WalletActorJobKind::Backfill)
            .filter_map(|job| job.target_block)
            .max()
    }

    pub(super) fn pending_overlay_is_current(
        &self,
        token: WalletSyncToken,
        last_scanned: u64,
    ) -> bool {
        self.has_active_job(token)
            && self.latest_pending_overlay_job == Some(token.job_id())
            && last_scanned == self.last_scanned
            && self
                .active_jobs
                .get(&token.job_id())
                .is_some_and(|job| job.kind == WalletActorJobKind::PendingOverlay)
    }

    pub(super) fn validate_sync_token_current(
        &self,
        token: WalletSyncToken,
        handle: &crate::wallet::WalletHandle,
        cancel: &CancellationToken,
    ) -> Result<(), WalletBackfillRejectReason> {
        if cancel.is_cancelled()
            || !handle.is_current_actor()
            || token.chain_id() != self.chain_id
            || token.actor_id() != self.actor_id
            || token.actor_id() != handle.actor_id
        {
            return Err(WalletBackfillRejectReason::Shutdown);
        }
        if token.reset_generation() != self.reset_generation {
            return Err(WalletBackfillRejectReason::StaleGeneration {
                expected: self.reset_generation,
                actual: token.reset_generation(),
            });
        }
        Ok(())
    }

    pub(super) fn validate_active_backfill_token(
        &self,
        token: WalletSyncToken,
        handle: &crate::wallet::WalletHandle,
        cancel: &CancellationToken,
    ) -> Result<(), WalletBackfillRejectReason> {
        self.validate_sync_token_current(token, handle, cancel)?;
        if !self.is_active_job(token, WalletActorJobKind::Backfill) {
            return Err(WalletBackfillRejectReason::Shutdown);
        }
        Ok(())
    }

    pub(super) fn validate_reset_token_current(
        &self,
        token: WalletResetToken,
        handle: &crate::wallet::WalletHandle,
        cancel: &CancellationToken,
    ) -> Result<(), WalletBackfillRejectReason> {
        if cancel.is_cancelled()
            || !handle.is_current_actor()
            || token.chain_id() != self.chain_id
            || token.actor_id() != self.actor_id
            || token.actor_id() != handle.actor_id
        {
            return Err(WalletBackfillRejectReason::Shutdown);
        }
        Ok(())
    }

    pub(super) fn validate_private_request(
        &self,
        handle: &crate::wallet::WalletHandle,
        cancel: &CancellationToken,
        ticket: WalletPrivateViewTicket,
        last_scanned: u64,
        require_cursor: bool,
    ) -> Result<u64, WalletPrivateRequestError> {
        handle.with_active_private_request(cancel, || {
            let reset_generation = ticket.reset_generation();
            if self.pending_reset.is_some() {
                return Err(WalletPrivateRequestError::ResetPending);
            }
            let WalletPrivateViewTicket::Current {
                last_scanned: request_last_scanned,
                ..
            } = ticket
            else {
                return Err(WalletPrivateRequestError::StaleView);
            };
            if reset_generation != self.reset_generation
                || (require_cursor && request_last_scanned != last_scanned)
            {
                return Err(WalletPrivateRequestError::StaleView);
            }
            Ok(reset_generation)
        })
    }

    pub(super) fn validate_pending_overlay_request(
        &self,
        handle: &crate::wallet::WalletHandle,
        cancel: &CancellationToken,
    ) -> Result<u64, WalletPrivateRequestError> {
        handle.with_active_private_request(cancel, || Ok(self.reset_generation))
    }

    fn is_active_job(&self, token: WalletSyncToken, kind: WalletActorJobKind) -> bool {
        token.chain_id() == self.chain_id
            && token.actor_id() == self.actor_id
            && token.reset_generation() == self.reset_generation
            && self.active_jobs.get(&token.job_id()).is_some_and(|job| {
                job.reset_generation == token.reset_generation() && job.kind == kind
            })
    }

    fn has_active_job(&self, token: WalletSyncToken) -> bool {
        token.chain_id() == self.chain_id
            && token.actor_id() == self.actor_id
            && token.reset_generation() == self.reset_generation
            && self
                .active_jobs
                .get(&token.job_id())
                .is_some_and(|job| job.reset_generation == token.reset_generation())
    }
}

impl WalletActorMutation<'_> {
    fn accept_job(&mut self, token: WalletSyncToken, kind: WalletActorJobKind) -> bool {
        if token.chain_id() != self.state.chain_id
            || token.actor_id() != self.state.actor_id
            || token.reset_generation() != self.state.reset_generation
        {
            return false;
        }
        if let Some(job) = self.state.active_jobs.get(&token.job_id()) {
            return job.kind == kind && job.reset_generation == token.reset_generation();
        }
        if kind == WalletActorJobKind::Backfill {
            if token.job_id() <= self.state.highest_accepted_backfill_job_id {
                return false;
            }
            self.state.highest_accepted_backfill_job_id = token.job_id();
        }
        self.state.active_jobs.insert(
            token.job_id(),
            WalletActorJob {
                reset_generation: token.reset_generation(),
                kind,
                target_block: None,
                indexed_status: None,
            },
        );
        if kind == WalletActorJobKind::PendingOverlay {
            self.state.latest_pending_overlay_job = Some(token.job_id());
        }
        true
    }

    pub(super) fn durable_poi_status_commit_ok(
        &mut self,
        reset_generation: u64,
        selection: WalletPoiRefreshSelection,
    ) {
        self.state
            .poi_persistence_requirements
            .remove(reset_generation, selection);
    }

    pub(super) fn poi_status_persist_failed(
        &mut self,
        reset_generation: u64,
        selection: WalletPoiRefreshSelection,
    ) {
        if reset_generation == self.state.reset_generation {
            self.state
                .poi_persistence_requirements
                .insert(reset_generation, selection);
        }
    }

    pub(super) fn durable_reset_replay_commit_ok(&mut self, intent_id: u64) {
        if self.state.reset_replay_persistence_requirement == Some(intent_id) {
            self.state.reset_replay_persistence_requirement = None;
        }
    }

    pub(super) const fn reset_replay_persist_failed(&mut self, intent_id: u64) {
        self.state.reset_replay_persistence_requirement = Some(intent_id);
    }

    pub(super) fn sync_progress_persist_failed(
        &mut self,
        token: WalletSyncToken,
        from_block: u64,
        to_block: u64,
    ) -> bool {
        if from_block > to_block
            || from_block != self.state.last_scanned.saturating_add(1)
            || !self
                .state
                .is_active_job(token, WalletActorJobKind::Backfill)
        {
            return false;
        }
        let incoming = WalletRequiredPersistRange {
            from_block,
            to_block,
        };
        self.state.progress_persistence_requirement = Some(
            self.state
                .progress_persistence_requirement
                .filter(|required| required.reset_generation == token.reset_generation())
                .map_or_else(
                    || WalletProgressPersistenceRequirement {
                        reset_generation: token.reset_generation(),
                        range: incoming,
                    },
                    |required| WalletProgressPersistenceRequirement {
                        reset_generation: required.reset_generation,
                        range: WalletRequiredPersistRange {
                            from_block: required.range.from_block.min(incoming.from_block),
                            to_block: required.range.to_block.max(incoming.to_block),
                        },
                    },
                ),
        );
        true
    }

    pub(super) fn durable_sync_progress_commit_ok(
        &mut self,
        token: WalletSyncToken,
        from_block: u64,
        to_block: u64,
    ) -> bool {
        if from_block > to_block
            || from_block != self.state.last_scanned.saturating_add(1)
            || !self
                .state
                .is_active_job(token, WalletActorJobKind::Backfill)
        {
            return false;
        }
        self.state.last_scanned = to_block;
        if let Some(mut required) = self.state.progress_persistence_requirement
            && required.reset_generation == token.reset_generation()
        {
            if required.range.to_block <= to_block {
                self.state.progress_persistence_requirement = None;
            } else {
                required.range.from_block =
                    required.range.from_block.max(to_block.saturating_add(1));
                self.state.progress_persistence_requirement = Some(required);
            }
        }
        true
    }

    pub(super) fn backfill_completion_persist_failed(&mut self, token: WalletSyncToken) -> bool {
        if !self
            .state
            .is_active_job(token, WalletActorJobKind::Backfill)
        {
            return false;
        }
        let Some(target_block) = self
            .state
            .active_jobs
            .get(&token.job_id())
            .and_then(|job| job.target_block)
        else {
            return false;
        };
        let incoming = WalletCompletionPersistenceRequirement {
            reset_generation: token.reset_generation(),
            token,
            target_block,
        };
        self.state.completion_persistence_requirement = Some(
            self.state
                .completion_persistence_requirement
                .filter(|required| required.reset_generation == token.reset_generation())
                .map_or(incoming, |required| {
                    if incoming.target_block > required.target_block
                        || (incoming.target_block == required.target_block
                            && incoming.token.job_id() < required.token.job_id())
                    {
                        incoming
                    } else {
                        required
                    }
                }),
        );
        true
    }

    pub(super) fn durable_backfill_completion_commit_ok(&mut self, token: WalletSyncToken) -> bool {
        if !self
            .state
            .is_active_job(token, WalletActorJobKind::Backfill)
        {
            return false;
        }
        let Some(target_block) = self
            .state
            .active_jobs
            .get(&token.job_id())
            .and_then(|job| job.target_block)
        else {
            return false;
        };
        if !self
            .state
            .completion_persistence_requirement
            .is_some_and(|required| {
                required.reset_generation == token.reset_generation()
                    && required.target_block <= target_block
            })
        {
            return false;
        }
        self.state.completion_persistence_requirement = None;
        true
    }

    pub(super) const fn set_poi_corpus_refresh_pending(&mut self, pending: bool) {
        self.state.poi_corpus_refresh_pending = pending;
    }

    pub(super) const fn observe_poi_corpus_revision(&mut self, changed: bool) {
        self.state.poi_corpus_refresh_pending |= changed;
    }

    pub(super) const fn mark_pending_reset_rewind_committed(&mut self, last_scanned: u64) {
        self.state.pending_reset_rewind_committed = true;
        self.state.last_scanned = last_scanned;
    }

    pub(super) const fn set_pending_reset_replay_admitted(
        &mut self,
        replay: Option<(WalletSyncToken, u64)>,
    ) {
        self.state.pending_reset_replay_admitted = match replay {
            Some((token, _)) => Some(token),
            None => None,
        };
        self.state.pending_reset_progress_start_block = match replay {
            Some((_, progress_start_block)) => Some(progress_start_block),
            None => None,
        };
    }

    pub(super) const fn clear_pending_reset(&mut self) {
        self.state.pending_reset = None;
        self.state.pending_reset_rewind_committed = false;
    }

    pub(super) fn accept_target(&mut self, token: WalletSyncToken, target_block: u64) -> bool {
        if self.state.has_active_job(token) || !self.accept_job(token, WalletActorJobKind::Backfill)
        {
            return false;
        }
        self.state
            .active_jobs
            .get_mut(&token.job_id())
            .expect("accepted backfill job exists")
            .target_block = Some(target_block);
        true
    }

    pub(super) fn accept_sync_target(&mut self, token: WalletSyncToken, target_block: u64) -> bool {
        if self.state.has_active_job(token)
            || !self.accept_job(token, WalletActorJobKind::SyncTarget)
        {
            return false;
        }
        self.state
            .active_jobs
            .get_mut(&token.job_id())
            .expect("accepted sync target job exists")
            .target_block = Some(target_block);
        true
    }

    pub(super) fn update_target(
        &mut self,
        token: WalletSyncToken,
        target_block: u64,
    ) -> Option<u64> {
        if !self
            .state
            .is_active_job(token, WalletActorJobKind::Backfill)
        {
            return None;
        }
        let job = self
            .state
            .active_jobs
            .get_mut(&token.job_id())
            .expect("validated backfill job exists");
        let target_block = job
            .target_block
            .map_or(target_block, |current| current.max(target_block));
        job.target_block = Some(target_block);
        Some(target_block)
    }

    pub(super) fn complete_backfill_job(&mut self, token: WalletSyncToken) -> bool {
        if !self
            .state
            .is_active_job(token, WalletActorJobKind::Backfill)
        {
            return false;
        }
        let Some(target_block) = self
            .state
            .active_jobs
            .get(&token.job_id())
            .filter(|job| job.kind == WalletActorJobKind::Backfill)
            .and_then(|job| job.target_block)
        else {
            return false;
        };
        self.state.completed_target_block = Some(
            self.state
                .completed_target_block
                .map_or(target_block, |completed| completed.max(target_block)),
        );
        self.retire_job(token)
    }

    pub(super) fn retire_job(&mut self, token: WalletSyncToken) -> bool {
        if !self.state.has_active_job(token) {
            return false;
        }
        self.remove_job(token)
    }

    fn remove_job(&mut self, token: WalletSyncToken) -> bool {
        let retired = self.state.active_jobs.remove(&token.job_id()).is_some();
        if retired && self.state.pending_reset_replay_admitted == Some(token) {
            self.state.pending_reset_replay_admitted = None;
            self.state.pending_reset_progress_start_block = None;
        }
        retired
    }

    fn fail_job(&mut self, token: WalletSyncToken, reason: WalletJobFailureReason) -> bool {
        if !self.state.has_active_job(token) {
            return false;
        }
        let target_block = self
            .state
            .active_jobs
            .get(&token.job_id())
            .and_then(|job| job.target_block)
            .unwrap_or(self.state.last_scanned);
        let retired = self.remove_job(token);
        if retired {
            self.state
                .job_failures
                .entry(token.job_id())
                .or_insert(WalletJobFailure {
                    token,
                    target_block,
                    reason,
                });
        }
        retired
    }

    pub(super) fn fail_job_backfill_unavailable(&mut self, token: WalletSyncToken) -> bool {
        self.fail_job(token, WalletJobFailureReason::BackfillUnavailable)
    }

    pub(super) fn fail_job_target_not_reached(
        &mut self,
        token: WalletSyncToken,
        target_block: u64,
    ) -> bool {
        self.fail_job(
            token,
            WalletJobFailureReason::TargetNotReached { target_block },
        )
    }

    pub(super) fn fail_job_apply_failed(&mut self, token: WalletSyncToken) -> bool {
        self.fail_job(token, WalletJobFailureReason::ApplyFailed)
    }

    pub(super) fn backfill_dispatch_admitted(&mut self, token: WalletSyncToken) -> bool {
        if !self
            .state
            .is_active_job(token, WalletActorJobKind::Backfill)
        {
            return false;
        }
        let Some(target_block) = self
            .state
            .active_jobs
            .get(&token.job_id())
            .and_then(|job| job.target_block)
        else {
            return false;
        };
        let before = self.state.job_failures.len();
        self.state.job_failures.retain(|_, failure| {
            failure.token.reset_generation() != token.reset_generation()
                || failure.target_block > target_block
        });
        self.state.job_failures.len() != before
    }

    pub(super) fn apply_backfill_owner_disposition(
        &mut self,
        token: WalletSyncToken,
        disposition: WalletBackfillOwnerDisposition,
    ) -> bool {
        match disposition {
            WalletBackfillOwnerDisposition::BenignRetirement => self.retire_job(token),
            WalletBackfillOwnerDisposition::DriverLost => self.fail_job_backfill_unavailable(token),
        }
    }

    pub(super) fn accept_indexed_catch_up(&mut self, token: WalletSyncToken) -> bool {
        if self
            .state
            .active_jobs
            .values()
            .any(|job| job.kind == WalletActorJobKind::IndexedCatchUp)
        {
            return false;
        }
        self.accept_job(token, WalletActorJobKind::IndexedCatchUp)
    }

    pub(super) fn publish_indexed_catch_up(
        &mut self,
        token: WalletSyncToken,
        status: WalletIndexedCatchUpStatus,
    ) -> bool {
        if !self
            .state
            .is_active_job(token, WalletActorJobKind::IndexedCatchUp)
        {
            return false;
        }
        self.state
            .active_jobs
            .get_mut(&token.job_id())
            .expect("validated indexed catch-up job exists")
            .indexed_status = Some(status);
        true
    }

    pub(super) fn accept_pending_overlay(
        &mut self,
        token: WalletSyncToken,
        last_scanned: u64,
    ) -> bool {
        token.reset_generation() == self.state.reset_generation
            && last_scanned == self.state.last_scanned
            && self
                .state
                .latest_pending_overlay_job
                .is_none_or(|latest| token.job_id() > latest)
            && self.accept_job(token, WalletActorJobKind::PendingOverlay)
    }

    pub(super) fn accept_reset(&mut self, pending: PendingWalletReset) -> bool {
        self.state
            .poi_persistence_requirements
            .rebase(pending.reset_generation);
        self.state.reset_replay_persistence_requirement = None;
        self.state.progress_persistence_requirement = None;
        self.state.completion_persistence_requirement = None;
        self.state.job_failures.clear();
        self.state.highest_accepted_reset_intent = pending.intent_id;
        self.state.pending_reset = Some(pending);
        self.state.reset_generation = pending.reset_generation;
        self.state.pending_reset_rewind_committed = false;
        self.state.pending_reset_replay_admitted = None;
        self.state.pending_reset_progress_start_block = None;
        let indexed_catch_up_was_active = self
            .state
            .active_jobs
            .values()
            .any(|job| job.kind == WalletActorJobKind::IndexedCatchUp);
        self.state.active_jobs.clear();
        self.state.latest_pending_overlay_job = None;
        self.state.completed_target_block = None;
        indexed_catch_up_was_active
    }
}

/// Credential for remote POI jobs re-entering the actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct WalletActorCredential {
    pub actor_id: u64,
    pub reset_generation: u64,
}

impl WalletActorCredential {
    #[must_use]
    pub(crate) fn current_for(handle: &crate::wallet::WalletHandle) -> Self {
        Self {
            actor_id: handle.actor_id(),
            reset_generation: handle.authority_reset_generation(),
        }
    }

    #[must_use]
    pub(crate) fn is_current(self, handle: &crate::wallet::WalletHandle) -> bool {
        handle.is_current_actor()
            && handle.actor_id() == self.actor_id
            && handle.authority_reset_generation() == self.reset_generation
            && handle.lifecycle().allows_durable_commits()
    }
}

/// Precise in-flight key for remote POI maintenance (one concurrent maintenance job per generation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct PoiRemoteJobKey {
    pub actor_id: u64,
    pub reset_generation: u64,
    pub kind: PoiRemoteJobKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum PoiRemoteJobKind {
    /// Verify submitted + optional force-resubmit + recovery + submit observations.
    Maintenance,
}

#[cfg(test)]
impl WalletActorLifecycleCell {
    /// Prepared/Active → Stopping. Returns true if this call performed the transition.
    pub(crate) fn mark_stopping(&self) -> bool {
        self.mark_stopping_with(|| {})
    }

    /// Prepared/Active → Stopping, publishing terminal session state under the fence.
    pub(crate) fn mark_stopping_with(&self, publish: impl FnOnce()) -> bool {
        self.with_fence(|inner| {
            if matches!(
                inner.state,
                WalletActorLifecycle::Prepared | WalletActorLifecycle::Active
            ) {
                inner.state = WalletActorLifecycle::Stopping;
                publish();
                true
            } else {
                false
            }
        })
    }
}

#[cfg(test)]
impl WalletActorState {
    pub(super) fn set_observation_publisher_for_test(
        &mut self,
        observation: Arc<WalletObservationPublisher>,
    ) {
        self.observation = observation;
    }

    pub(super) const fn last_scanned(&self) -> u64 {
        self.last_scanned
    }

    pub(super) fn test_readiness(&self) -> WalletReadiness {
        self.derived_readiness()
    }

    pub(super) fn test_active_job_count(&self) -> usize {
        self.active_jobs.len()
    }

    pub(super) fn test_job_failure_count(&self) -> usize {
        self.job_failures.len()
    }

    pub(super) const fn test_highest_accepted_backfill_job_id(&self) -> u64 {
        self.highest_accepted_backfill_job_id
    }

    pub(super) fn test_active_backfill_target_for(&self, token: WalletSyncToken) -> Option<u64> {
        self.active_jobs
            .get(&token.job_id())
            .filter(|job| job.kind == WalletActorJobKind::Backfill)
            .and_then(|job| job.target_block)
    }

    pub(super) fn test_persistence_range_for(&self, token: WalletSyncToken) -> Option<(u64, u64)> {
        self.progress_persistence_requirement
            .filter(|required| required.reset_generation == token.reset_generation())
            .map(|required| (required.range.from_block, required.range.to_block))
    }

    pub(super) fn test_completion_requirement(&self) -> Option<(WalletSyncToken, u64)> {
        self.completion_persistence_requirement
            .map(|required| (required.token, required.target_block))
    }

    pub(super) const fn test_reset_replay_requirement(&self) -> Option<u64> {
        self.reset_replay_persistence_requirement
    }

    pub(super) fn test_has_job_failure(&self, token: WalletSyncToken) -> bool {
        self.job_failures
            .get(&token.job_id())
            .is_some_and(|failure| failure.token == token)
    }

    pub(super) fn test_poi_requirement_count(&self) -> usize {
        usize::from(self.poi_persistence_requirements.required)
            + usize::from(self.poi_persistence_requirements.required_or_recoverable)
            + usize::from(
                self.poi_persistence_requirements
                    .recoverable_stale
                    .is_some(),
            )
            + usize::from(self.poi_persistence_requirements.recoverable)
            + usize::from(self.poi_persistence_requirements.corpus_revision.is_some())
    }

    pub(super) fn test_indexed_status(
        &self,
        token: WalletSyncToken,
    ) -> Option<&WalletIndexedCatchUpStatus> {
        self.active_jobs
            .get(&token.job_id())
            .and_then(|job| job.indexed_status.as_ref())
    }

    pub(super) fn test_transition<R>(
        &mut self,
        transition: impl for<'a> FnOnce(WalletActorMutation<'a>) -> R,
    ) -> R {
        let token = WalletActorApplyToken {
            _fence: PhantomData,
        };
        self.transition(&token, transition)
    }
}

#[cfg(test)]
impl WalletActorMutation<'_> {
    pub(super) const fn update_cursor(&mut self, last_scanned: u64) {
        self.state.last_scanned = last_scanned;
    }

    pub(super) fn test_accept_backfill_job_id(&mut self, token: WalletSyncToken) -> bool {
        self.accept_job(token, WalletActorJobKind::Backfill)
    }
}

#[cfg(test)]
mod tests;
