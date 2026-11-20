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

mod lifecycle_cell;
mod mutation;
mod observation_publisher;
mod poi_persistence;
mod state;

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
mod tests;
