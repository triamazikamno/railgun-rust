#[cfg(test)]
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::wallet::WalletActorTokenAuthority;

use super::{WalletReadinessError, WalletResetRewindStatus, WalletScanApply};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletBackfillRejectReason {
    StaleGeneration {
        expected: u64,
        actual: u64,
    },
    NonContiguous {
        expected_from: u64,
        actual_from: u64,
    },
    ApplyFailed,
    PersistenceFailed,
    TargetNotReached {
        target_block: u64,
    },
    TargetExceeded {
        target_block: u64,
        requested_to: u64,
    },
    Shutdown,
    StaleDataPlaneEpoch {
        expected: u64,
        actual: u64,
    },
    StaleResetIntent {
        accepted: u64,
        actual: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletBackfillApplyResult {
    Committed {
        committed_to: u64,
    },
    AlreadyCovered {
        committed_to: u64,
    },
    Rejected {
        committed_to: u64,
        reason: WalletBackfillRejectReason,
    },
}

impl WalletBackfillApplyResult {
    #[must_use]
    pub const fn committed_to(&self) -> u64 {
        match self {
            Self::Committed { committed_to }
            | Self::AlreadyCovered { committed_to }
            | Self::Rejected { committed_to, .. } => *committed_to,
        }
    }

    #[must_use]
    pub const fn accepted_committed_to(&self) -> Option<u64> {
        match self {
            Self::Committed { committed_to } | Self::AlreadyCovered { committed_to } => {
                Some(*committed_to)
            }
            Self::Rejected { .. } => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum WalletBackfillStartResult {
    Accepted {
        committed_to: u64,
        target_block: u64,
        grant: WalletBackfillGrant,
    },
    Rejected {
        committed_to: u64,
        reason: WalletBackfillRejectReason,
    },
}

impl WalletBackfillStartResult {
    #[must_use]
    pub const fn committed_to(&self) -> u64 {
        match self {
            Self::Accepted { committed_to, .. } | Self::Rejected { committed_to, .. } => {
                *committed_to
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletBackfillFinishResult {
    Ready {
        committed_to: u64,
    },
    Rejected {
        committed_to: u64,
        reason: WalletBackfillRejectReason,
    },
}

impl WalletBackfillFinishResult {
    #[must_use]
    pub const fn committed_to(&self) -> u64 {
        match self {
            Self::Ready { committed_to } | Self::Rejected { committed_to, .. } => *committed_to,
        }
    }
}

/// Public result of a wallet reset request.
///
/// **Invariant:** once `AcceptReset` has durably succeeded, the result is always
/// [`Accepted`](Self::Accepted) with a rewind status. [`Rejected`](Self::Rejected)
/// means the reset was never accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletBackfillResetResult {
    Accepted {
        reset_generation: u64,
        rewind: WalletResetRewindStatus,
    },
    Rejected {
        committed_to: u64,
        reason: WalletBackfillRejectReason,
    },
}

impl WalletBackfillResetResult {
    #[must_use]
    pub const fn accepted_committed(reset_generation: u64, committed_to: u64) -> Self {
        Self::Accepted {
            reset_generation,
            rewind: WalletResetRewindStatus::Committed { committed_to },
        }
    }

    #[must_use]
    pub const fn accepted_pending(
        reset_generation: u64,
        committed_to: u64,
        last_attempt: Option<WalletBackfillRejectReason>,
    ) -> Self {
        Self::Accepted {
            reset_generation,
            rewind: WalletResetRewindStatus::Pending {
                committed_to,
                last_attempt,
            },
        }
    }

    #[must_use]
    pub const fn rejected(committed_to: u64, reason: WalletBackfillRejectReason) -> Self {
        Self::Rejected {
            committed_to,
            reason,
        }
    }

    #[must_use]
    pub const fn committed_to(&self) -> u64 {
        match self {
            Self::Accepted { rewind, .. } => rewind.committed_to(),
            Self::Rejected { committed_to, .. } => *committed_to,
        }
    }

    #[must_use]
    pub const fn reset_generation(&self) -> Option<u64> {
        match self {
            Self::Accepted {
                reset_generation, ..
            } => Some(*reset_generation),
            Self::Rejected { .. } => None,
        }
    }

    #[must_use]
    pub const fn committed(&self) -> bool {
        matches!(
            self,
            Self::Accepted {
                rewind: WalletResetRewindStatus::Committed { .. },
                ..
            }
        )
    }

    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted { .. })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct WalletSyncToken {
    chain_id: u64,
    actor_id: u64,
    reset_generation: u64,
    job_id: u64,
}

impl WalletSyncToken {
    #[must_use]
    pub(crate) const fn mint(
        authority: WalletActorTokenAuthority<'_>,
        reset_generation: u64,
        job_id: u64,
    ) -> Self {
        Self {
            chain_id: authority.chain_id(),
            actor_id: authority.actor_id(),
            reset_generation,
            job_id,
        }
    }

    #[must_use]
    pub(crate) const fn chain_id(self) -> u64 {
        self.chain_id
    }

    #[must_use]
    pub(crate) const fn actor_id(self) -> u64 {
        self.actor_id
    }

    #[must_use]
    pub(crate) const fn reset_generation(self) -> u64 {
        self.reset_generation
    }

    #[must_use]
    pub(crate) const fn job_id(self) -> u64 {
        self.job_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct WalletResetToken {
    chain_id: u64,
    actor_id: u64,
    intent_id: u64,
}

impl WalletResetToken {
    #[must_use]
    pub(crate) const fn mint(authority: WalletActorTokenAuthority<'_>, intent_id: u64) -> Self {
        Self {
            chain_id: authority.chain_id(),
            actor_id: authority.actor_id(),
            intent_id,
        }
    }

    #[must_use]
    pub(crate) const fn chain_id(self) -> u64 {
        self.chain_id
    }

    #[must_use]
    pub(crate) const fn actor_id(self) -> u64 {
        self.actor_id
    }

    #[must_use]
    pub(crate) const fn intent_id(self) -> u64 {
        self.intent_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WalletBackfillOwnerDisposition {
    BenignRetirement,
    DriverLost,
}

#[derive(Debug)]
pub(crate) struct WalletBackfillOwnerSignal {
    pub(crate) disposition: WalletBackfillOwnerDisposition,
    pub(crate) acknowledgement: Option<oneshot::Sender<()>>,
}

#[derive(Debug)]
struct WalletBackfillOwner {
    token: WalletSyncToken,
    sender: mpsc::Sender<BackfillEvent>,
    liveness: oneshot::Sender<WalletBackfillOwnerSignal>,
    cancel: CancellationToken,
}

impl WalletBackfillOwner {
    fn signal(
        self,
        disposition: WalletBackfillOwnerDisposition,
        acknowledgement: Option<oneshot::Sender<()>>,
    ) {
        let _ = self.liveness.send(WalletBackfillOwnerSignal {
            disposition,
            acknowledgement,
        });
    }
}

/// An actor-accepted backfill job that has not yet been activated by a driver.
/// Dropping a grant is benign cancellation.
#[derive(Debug)]
pub struct WalletBackfillGrant {
    inner: Option<WalletBackfillOwner>,
}

/// Actor-owned readiness target held across staged public-source work.
#[derive(Debug)]
pub(crate) struct WalletSyncTargetLease {
    owner: Option<WalletBackfillOwner>,
}

impl WalletSyncTargetLease {
    pub(crate) fn for_actor_accepted_job(
        token: WalletSyncToken,
        sender: mpsc::Sender<BackfillEvent>,
        liveness: oneshot::Sender<WalletBackfillOwnerSignal>,
    ) -> Self {
        Self {
            owner: Some(WalletBackfillOwner {
                token,
                sender,
                liveness,
                cancel: CancellationToken::new(),
            }),
        }
    }
}

impl Drop for WalletSyncTargetLease {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.take() {
            owner.signal(WalletBackfillOwnerDisposition::BenignRetirement, None);
        }
    }
}

impl PartialEq for WalletBackfillGrant {
    fn eq(&self, other: &Self) -> bool {
        self.token() == other.token()
    }
}

impl Eq for WalletBackfillGrant {}

impl WalletBackfillGrant {
    #[cfg(test)]
    pub(crate) fn for_actor_accepted_job(
        token: WalletSyncToken,
        sender: mpsc::Sender<BackfillEvent>,
        liveness: oneshot::Sender<WalletBackfillOwnerSignal>,
    ) -> Self {
        Self::for_actor_accepted_job_with_cancel(token, sender, liveness, CancellationToken::new())
    }

    pub(crate) const fn for_actor_accepted_job_with_cancel(
        token: WalletSyncToken,
        sender: mpsc::Sender<BackfillEvent>,
        liveness: oneshot::Sender<WalletBackfillOwnerSignal>,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            inner: Some(WalletBackfillOwner {
                token,
                sender,
                liveness,
                cancel,
            }),
        }
    }

    pub(crate) const fn token(&self) -> WalletSyncToken {
        self.inner
            .as_ref()
            .expect("backfill grant is present")
            .token
    }

    #[must_use]
    pub(crate) fn activate(mut self) -> WalletBackfillDriver {
        WalletBackfillDriver {
            inner: self.inner.take(),
        }
    }
}

impl Drop for WalletBackfillGrant {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            inner.signal(WalletBackfillOwnerDisposition::BenignRetirement, None);
        }
    }
}

/// Unique owner of an activated actor backfill job.
/// Dropping it without actor completion or explicit retirement reports driver loss.
#[derive(Debug)]
pub struct WalletBackfillDriver {
    inner: Option<WalletBackfillOwner>,
}

impl PartialEq for WalletBackfillDriver {
    fn eq(&self, other: &Self) -> bool {
        self.token() == other.token()
    }
}

impl Eq for WalletBackfillDriver {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WalletResetReplayPlan {
    pub(crate) start_block: u64,
    pub(crate) target_block: u64,
    pub(crate) follow_safe_head: bool,
}

impl WalletResetReplayPlan {
    #[must_use]
    pub(crate) const fn new(start_block: u64, target_block: u64, follow_safe_head: bool) -> Self {
        Self {
            start_block,
            target_block,
            follow_safe_head,
        }
    }
}

impl WalletBackfillDriver {
    const fn inner(&self) -> &WalletBackfillOwner {
        self.inner.as_ref().expect("backfill driver is present")
    }

    pub(crate) const fn token(&self) -> WalletSyncToken {
        self.inner().token
    }

    pub(crate) fn supersedes(&self, active: &Self) -> bool {
        let incoming = self.token();
        let active = active.token();
        (
            incoming.chain_id(),
            incoming.actor_id(),
            incoming.reset_generation(),
            incoming.job_id(),
        ) > (
            active.chain_id(),
            active.actor_id(),
            active.reset_generation(),
            active.job_id(),
        )
    }

    pub(crate) const fn sender(&self) -> &mpsc::Sender<BackfillEvent> {
        &self.inner().sender
    }

    pub(crate) fn cancellation_token(&self) -> CancellationToken {
        self.inner().cancel.clone()
    }

    pub(crate) async fn apply(
        &self,
        cache_key: &str,
        apply: WalletScanApply,
    ) -> WalletBackfillApplyResult {
        let requested_to = apply.to_block;
        let (response, result_rx) = oneshot::channel();
        if let Err(err) = self
            .sender()
            .send(BackfillEvent::Apply {
                apply,
                token: self.token(),
                response,
            })
            .await
        {
            warn!(?err, cache_key, "failed to send wallet scan batch");
            return WalletBackfillApplyResult::Rejected {
                committed_to: requested_to.saturating_sub(1),
                reason: WalletBackfillRejectReason::Shutdown,
            };
        }
        match result_rx.await {
            Ok(result) => result,
            Err(err) => {
                warn!(?err, cache_key, "wallet scan batch response dropped");
                WalletBackfillApplyResult::Rejected {
                    committed_to: requested_to.saturating_sub(1),
                    reason: WalletBackfillRejectReason::Shutdown,
                }
            }
        }
    }

    pub(crate) async fn finish(
        &self,
        cache_key: &str,
        target_block: u64,
    ) -> WalletBackfillFinishResult {
        let (response, result_rx) = oneshot::channel();
        if let Err(err) = self
            .sender()
            .send(BackfillEvent::Finish {
                target_block,
                token: self.token(),
                response,
            })
            .await
        {
            warn!(
                ?err,
                cache_key, target_block, "failed to send wallet target update"
            );
            return WalletBackfillFinishResult::Rejected {
                committed_to: target_block.saturating_sub(1),
                reason: WalletBackfillRejectReason::Shutdown,
            };
        }
        match result_rx.await {
            Ok(result) => result,
            Err(err) => {
                warn!(
                    ?err,
                    cache_key, target_block, "wallet target response dropped"
                );
                WalletBackfillFinishResult::Rejected {
                    committed_to: target_block.saturating_sub(1),
                    reason: WalletBackfillRejectReason::Shutdown,
                }
            }
        }
    }

    pub(crate) async fn retire(mut self, _cache_key: &str) {
        if let Some(inner) = self.inner.take() {
            let (acknowledgement, acknowledged) = oneshot::channel();
            inner.signal(
                WalletBackfillOwnerDisposition::BenignRetirement,
                Some(acknowledgement),
            );
            let _ = acknowledged.await;
        }
    }

    pub(crate) async fn fail(self, cache_key: &str, reason: WalletReadinessError) {
        let (response, result_rx) = oneshot::channel();
        if let Err(err) = self
            .sender()
            .send(BackfillEvent::JobFailed {
                token: self.token(),
                reason,
                response,
            })
            .await
        {
            warn!(?err, cache_key, "failed to send wallet job failure");
            return;
        }
        if let Err(err) = result_rx.await {
            warn!(?err, cache_key, "wallet job failure response dropped");
        }
    }
}

impl Drop for WalletBackfillDriver {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            inner.signal(WalletBackfillOwnerDisposition::DriverLost, None);
        }
    }
}

#[derive(Debug)]
pub(crate) enum BackfillEvent {
    #[cfg(test)]
    PanicForTest,
    /// Spawns a tracked POI job that holds `sentinel` and a data-plane clone until aborted.
    #[cfg(test)]
    HoldTrackedPoiJobForTest {
        sentinel: Arc<()>,
        started: oneshot::Sender<()>,
    },
    ReserveTarget {
        target_block: u64,
        token: WalletSyncToken,
        response: oneshot::Sender<Result<WalletSyncTargetLease, WalletBackfillRejectReason>>,
    },
    Start {
        target_block: u64,
        token: WalletSyncToken,
        response: oneshot::Sender<WalletBackfillStartResult>,
    },
    Apply {
        apply: WalletScanApply,
        token: WalletSyncToken,
        response: oneshot::Sender<WalletBackfillApplyResult>,
    },
    Finish {
        target_block: u64,
        token: WalletSyncToken,
        response: oneshot::Sender<WalletBackfillFinishResult>,
    },
    JobFailed {
        token: WalletSyncToken,
        reason: WalletReadinessError,
        response: oneshot::Sender<()>,
    },
    Reset {
        token: WalletResetToken,
        from_block: u64,
        replay_plan: WalletResetReplayPlan,
        response: oneshot::Sender<WalletBackfillResetResult>,
    },
}

#[derive(Debug)]
pub(crate) enum BackfillRequest {
    Add {
        cache_key: String,
        from_block: u64,
        to_block: u64,
        follow_safe_head: bool,
        progress_start_block: u64,
        acquisition_range: Option<(u64, u64)>,
        /// Leading startup-window blocks at or before the cursor, warmed in
        /// the background once the cursor has delivered its target.
        startup_warm_range: Option<(u64, u64)>,
        driver: WalletBackfillDriver,
    },
    Remove {
        cache_key: String,
        actor_id: u64,
        response: oneshot::Sender<()>,
    },
}

impl BackfillRequest {
    pub(crate) fn add(
        cache_key: impl Into<String>,
        from_block: u64,
        to_block: u64,
        follow_safe_head: bool,
        progress_start_block: u64,
        driver: WalletBackfillDriver,
    ) -> Self {
        Self::Add {
            cache_key: cache_key.into(),
            from_block,
            to_block,
            follow_safe_head,
            progress_start_block,
            acquisition_range: None,
            startup_warm_range: None,
            driver,
        }
    }

    pub(crate) fn add_with_acquisition(
        cache_key: impl Into<String>,
        from_block: u64,
        to_block: u64,
        follow_safe_head: bool,
        progress_start_block: u64,
        acquisition_range: (u64, u64),
        driver: WalletBackfillDriver,
    ) -> Self {
        Self::Add {
            cache_key: cache_key.into(),
            from_block,
            to_block,
            follow_safe_head,
            progress_start_block,
            acquisition_range: Some(acquisition_range),
            startup_warm_range: None,
            driver,
        }
    }

    #[must_use]
    pub(crate) const fn with_startup_warm_range(
        mut self,
        startup_warm_range: Option<(u64, u64)>,
    ) -> Self {
        if let Self::Add {
            startup_warm_range: range,
            ..
        } = &mut self
        {
            *range = startup_warm_range;
        }
        self
    }
}

#[cfg(test)]
impl WalletSyncToken {
    #[must_use]
    pub(crate) const fn for_test(
        chain_id: u64,
        actor_id: u64,
        reset_generation: u64,
        job_id: u64,
    ) -> Self {
        Self {
            chain_id,
            actor_id,
            reset_generation,
            job_id,
        }
    }
}

#[cfg(test)]
impl WalletResetToken {
    #[must_use]
    pub(crate) const fn for_test(chain_id: u64, actor_id: u64, intent_id: u64) -> Self {
        Self {
            chain_id,
            actor_id,
            intent_id,
        }
    }
}

#[cfg(test)]
impl WalletSyncTargetLease {
    pub(crate) const fn token(&self) -> WalletSyncToken {
        self.owner.as_ref().expect("target lease is present").token
    }
}

#[cfg(test)]
impl WalletBackfillGrant {
    pub(crate) fn from_token(token: WalletSyncToken, sender: mpsc::Sender<BackfillEvent>) -> Self {
        let (liveness, _receiver) = oneshot::channel();
        Self::for_actor_accepted_job(token, sender, liveness)
    }
}

#[cfg(test)]
impl WalletBackfillDriver {
    pub(crate) fn from_token(token: WalletSyncToken, sender: mpsc::Sender<BackfillEvent>) -> Self {
        WalletBackfillGrant::from_token(token, sender).activate()
    }
}
