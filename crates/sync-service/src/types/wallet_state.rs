use std::sync::Arc;

use alloy::primitives::FixedBytes;
use railgun_wallet::WalletUtxo;

use super::WalletBackfillRejectReason;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WalletPrivateRequestError {
    #[error("wallet actor is inactive")]
    Inactive,
    #[error("wallet reset is pending")]
    ResetPending,
    #[error("wallet private request is stale")]
    StaleView,
    #[error("wallet private request persistence failed")]
    PersistenceFailed,
}

/// Pending tip overlay (chain + local) projected against the current cursor.
#[derive(Debug, Clone, Default)]
pub struct WalletPendingOverlay {
    pub new_utxos: Vec<WalletUtxo>,
    pub pending_spent: Vec<WalletPendingSpent>,
    pub local_pending_spent: Vec<WalletPendingSpent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletPendingSpent {
    pub tree: u32,
    pub position: u64,
    pub stable_identity: Option<Vec<u8>>,
    pub tx_hash: Option<FixedBytes<32>>,
    pub block_number: Option<u64>,
    pub block_timestamp: Option<u64>,
}

impl WalletPendingSpent {
    #[must_use]
    pub const fn key(&self) -> (u32, u64) {
        (self.tree, self.position)
    }

    #[must_use]
    pub const fn from_source(
        utxo: &railgun_wallet::Utxo,
        source: &railgun_wallet::UtxoSource,
    ) -> Self {
        Self {
            tree: utxo.tree,
            position: utxo.position,
            stable_identity: None,
            tx_hash: Some(source.tx_hash),
            block_number: Some(source.block_number),
            block_timestamp: Some(source.block_timestamp),
        }
    }

    #[must_use]
    pub(crate) fn submitted(
        utxo: &railgun_wallet::Utxo,
        tx_hash: Option<FixedBytes<32>>,
        now: u64,
    ) -> Self {
        let wallet_utxo = railgun_wallet::WalletUtxo::new(utxo.clone());
        Self {
            tree: utxo.tree,
            position: utxo.position,
            stable_identity: Some(railgun_wallet::wallet_cache::wallet_utxo_stable_identity(
                &wallet_utxo,
            )),
            tx_hash,
            block_number: None,
            block_timestamp: Some(now),
        }
    }

    #[must_use]
    pub fn matches_local_utxo(&self, utxo: &railgun_wallet::WalletUtxo) -> bool {
        self.key() == (utxo.utxo.tree, utxo.utxo.position)
            && self.stable_identity.as_ref()
                == Some(&railgun_wallet::wallet_cache::wallet_utxo_stable_identity(
                    utxo,
                ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletPendingSpentMarkOutcome {
    Marked,
    AlreadyProtected,
}

/// Coherent current private wallet projection (only valid when not reset-pending).
///
/// Includes confirmed UTXOs and pending tip overlay. Published atomically inside
/// [`WalletObservation`]; public observers must not read live mirrors.
#[derive(Debug, Clone)]
pub struct WalletCurrentSnapshot {
    pub last_scanned: u64,
    pub utxos: Arc<[WalletUtxo]>,
    pub pending_overlay: Arc<WalletPendingOverlay>,
    pub revision: u64,
    pub reset_generation: u64,
}

impl WalletCurrentSnapshot {
    #[must_use]
    pub fn new(
        last_scanned: u64,
        revision: u64,
        reset_generation: u64,
        utxos: impl Into<Arc<[WalletUtxo]>>,
        pending_overlay: impl Into<Arc<WalletPendingOverlay>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            last_scanned,
            utxos: utxos.into(),
            pending_overlay: pending_overlay.into(),
            revision,
            reset_generation,
        })
    }
}

/// Generation-scoped public progress taken from one [`WalletObservation`].
///
/// This is the **only** capability that authorizes generation-scoped public chain work
/// (backfill, indexed catch-up, lag/tail fallback). Call sites must not compose a public
/// cursor with a separately loaded generation, and bare `reset_generation: u64` is not a
/// public scheduling input.
///
/// Deferred work stores this ticket and revalidates it before start; range and generation
/// travel as one unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletSchedulableProgress {
    pub last_scanned: u64,
    pub reset_generation: u64,
}

impl WalletSchedulableProgress {
    /// Still current if `now` is Current and same generation. Returns the refreshed snapshot
    /// (cursor may have advanced within the generation).
    #[must_use]
    pub const fn revalidate(self, now: Option<Self>) -> Option<Self> {
        match now {
            Some(now) if now.reset_generation == self.reset_generation => Some(now),
            _ => None,
        }
    }

    /// True when `now` is still the same scheduling generation.
    #[must_use]
    pub const fn still_current(self, now: Option<Self>) -> bool {
        self.revalidate(now).is_some()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletInactiveReason {
    Shutdown,
    Retired,
}

/// Private-view and terminal session state carried by [`WalletObservation`].
///
/// While [`ResetPending`](Self::ResetPending), public readers must not treat
/// pre-reset private projection (cursor, UTXOs, pending overlay) as current.
///
/// [`Current`](Self::Current) carries the full published projection. Authority generation
/// (token invalidation) may advance before the view is republished; schedulers must not
/// mix those surfaces.
#[derive(Debug, Clone)]
pub enum WalletViewState {
    /// Full private projection; the only public source for UTXOs / pending overlay.
    Current(Arc<WalletCurrentSnapshot>),
    ResetPending {
        intent_id: u64,
        from_block: u64,
        reset_generation: u64,
    },
    Inactive {
        reason: WalletInactiveReason,
        reset_generation: u64,
    },
}

impl PartialEq for WalletViewState {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Current(left), Self::Current(right)) => {
                left.last_scanned == right.last_scanned
                    && left.revision == right.revision
                    && left.reset_generation == right.reset_generation
                    && Arc::ptr_eq(&left.utxos, &right.utxos)
                    && Arc::ptr_eq(&left.pending_overlay, &right.pending_overlay)
            }
            (
                Self::ResetPending {
                    intent_id: li,
                    from_block: lf,
                    reset_generation: lg,
                },
                Self::ResetPending {
                    intent_id: ri,
                    from_block: rf,
                    reset_generation: rg,
                },
            ) => li == ri && lf == rf && lg == rg,
            (
                Self::Inactive {
                    reason: left_reason,
                    reset_generation: left_generation,
                },
                Self::Inactive {
                    reason: right_reason,
                    reset_generation: right_generation,
                },
            ) => left_reason == right_reason && left_generation == right_generation,
            _ => false,
        }
    }
}

impl Eq for WalletViewState {}

impl WalletViewState {
    #[must_use]
    pub const fn is_current(&self) -> bool {
        matches!(self, Self::Current(_))
    }

    #[must_use]
    pub const fn inactive_reason(&self) -> Option<WalletInactiveReason> {
        match self {
            Self::Inactive { reason, .. } => Some(*reason),
            Self::Current(_) | Self::ResetPending { .. } => None,
        }
    }

    #[must_use]
    pub fn current_snapshot(&self) -> Option<Arc<WalletCurrentSnapshot>> {
        match self {
            Self::Current(snapshot) => Some(Arc::clone(snapshot)),
            Self::ResetPending { .. } | Self::Inactive { .. } => None,
        }
    }

    #[must_use]
    pub fn last_scanned_current(&self) -> Option<u64> {
        match self {
            Self::Current(snapshot) => Some(snapshot.last_scanned),
            Self::ResetPending { .. } | Self::Inactive { .. } => None,
        }
    }

    /// Public schedulable progress from this snapshot, if view is current.
    #[must_use]
    pub fn schedulable_progress(&self) -> Option<WalletSchedulableProgress> {
        match self {
            Self::Current(snapshot) => Some(WalletSchedulableProgress {
                last_scanned: snapshot.last_scanned,
                reset_generation: snapshot.reset_generation,
            }),
            Self::ResetPending { .. } | Self::Inactive { .. } => None,
        }
    }

    #[must_use]
    pub fn reset_generation(&self) -> u64 {
        match self {
            Self::Current(snapshot) => snapshot.reset_generation,
            Self::ResetPending {
                reset_generation, ..
            }
            | Self::Inactive {
                reset_generation, ..
            } => *reset_generation,
        }
    }
}

/// Status of the `CommitResetRewind` transition after `AcceptReset` has already succeeded
/// (or for restored/retry rewinds of an already-accepted pending reset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletResetRewindStatus {
    /// Rewind durably applied; mirrors match rewound state.
    Committed { committed_to: u64 },
    /// Accept holds; rewind not done yet (shutdown, persist fail, retrying).
    Pending {
        committed_to: u64,
        /// Diagnostic only — never upgrades accept to Rejected.
        last_attempt: Option<WalletBackfillRejectReason>,
    },
}

impl WalletResetRewindStatus {
    #[must_use]
    pub const fn committed_to(&self) -> u64 {
        match self {
            Self::Committed { committed_to } | Self::Pending { committed_to, .. } => *committed_to,
        }
    }

    #[must_use]
    pub const fn is_committed(&self) -> bool {
        matches!(self, Self::Committed { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WalletReadinessError {
    #[error("wallet backfill is unavailable")]
    BackfillUnavailable,
    #[error("wallet sync target {target_block} was not reached")]
    TargetNotReached { target_block: u64 },
    #[error("wallet sync state could not be persisted")]
    PersistenceFailed,
    #[error("wallet sync update could not be applied")]
    ApplyFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WalletReadinessWaitError {
    #[error("wallet readiness failed: {0}")]
    Failed(#[source] WalletReadinessError),
    #[error("wallet sync shut down before becoming ready")]
    Shutdown,
    #[error("wallet observation channel closed before becoming ready")]
    ChannelClosed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletReadiness {
    Syncing,
    Ready,
    Failed(WalletReadinessError),
    Shutdown,
}

impl WalletReadiness {
    #[must_use]
    pub const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready)
    }

    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Ready | Self::Failed(_) | Self::Shutdown)
    }
}

/// Privacy-safe aggregate of external sender-created pending-output PPOI work.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WalletPpoiWorkflowStatus {
    pub awaiting_recovery: u64,
    pub awaiting_public_txid_data: u64,
    pub awaiting_poi_data: u64,
    pub retrying_recovery: u64,
    pub recovery_needs_attention: u64,
    pub awaiting_submission: u64,
    pub awaiting_validation: u64,
    pub needs_attention: u64,
    pub validation_revision: u64,
}

impl WalletPpoiWorkflowStatus {
    #[must_use]
    pub const fn has_outstanding(&self) -> bool {
        self.awaiting_recovery > 0
            || self.awaiting_submission > 0
            || self.awaiting_validation > 0
            || self.needs_attention > 0
    }

    #[must_use]
    pub const fn outstanding_count(&self) -> u64 {
        self.awaiting_recovery
            .saturating_add(self.awaiting_submission)
            .saturating_add(self.awaiting_validation)
            .saturating_add(self.needs_attention)
    }

    #[must_use]
    pub const fn cleared(self) -> Self {
        Self {
            awaiting_recovery: 0,
            awaiting_public_txid_data: 0,
            awaiting_poi_data: 0,
            retrying_recovery: 0,
            recovery_needs_attention: 0,
            awaiting_submission: 0,
            awaiting_validation: 0,
            needs_attention: 0,
            validation_revision: self.validation_revision,
        }
    }
}

/// Latest successful PPOI submission acknowledgement for one sender-created output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletPpoiSubmissionStatus {
    pub output_commitment: FixedBytes<32>,
    pub last_submission_at: u64,
}

/// One authoritative public observation of a wallet actor's private projection and readiness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletObservation {
    view: WalletViewState,
    readiness: WalletReadiness,
    ppoi_workflow_status: WalletPpoiWorkflowStatus,
    ppoi_submission_statuses: Arc<[WalletPpoiSubmissionStatus]>,
}

impl WalletObservation {
    pub(crate) fn new(view: WalletViewState, readiness: WalletReadiness) -> Self {
        Self::with_ppoi_workflow_status(view, readiness, WalletPpoiWorkflowStatus::default())
    }

    pub(crate) fn with_ppoi_workflow_status(
        view: WalletViewState,
        readiness: WalletReadiness,
        ppoi_workflow_status: WalletPpoiWorkflowStatus,
    ) -> Self {
        Self::with_ppoi_workflow_projection(view, readiness, ppoi_workflow_status, Arc::from([]))
    }

    pub(crate) fn with_ppoi_workflow_projection(
        view: WalletViewState,
        readiness: WalletReadiness,
        ppoi_workflow_status: WalletPpoiWorkflowStatus,
        ppoi_submission_statuses: Arc<[WalletPpoiSubmissionStatus]>,
    ) -> Self {
        assert_eq!(
            matches!(&view, WalletViewState::Inactive { .. }),
            readiness == WalletReadiness::Shutdown
        );
        assert!(
            !matches!(&view, WalletViewState::ResetPending { .. })
                || readiness != WalletReadiness::Ready
        );
        Self {
            view,
            readiness,
            ppoi_workflow_status,
            ppoi_submission_statuses,
        }
    }

    #[must_use]
    pub const fn view(&self) -> &WalletViewState {
        &self.view
    }

    #[must_use]
    pub const fn readiness(&self) -> &WalletReadiness {
        &self.readiness
    }

    #[must_use]
    pub const fn ppoi_workflow_status(&self) -> &WalletPpoiWorkflowStatus {
        &self.ppoi_workflow_status
    }

    #[must_use]
    pub fn ppoi_submission_statuses(&self) -> &[WalletPpoiSubmissionStatus] {
        &self.ppoi_submission_statuses
    }

    pub(crate) fn ppoi_submission_statuses_arc(&self) -> Arc<[WalletPpoiSubmissionStatus]> {
        Arc::clone(&self.ppoi_submission_statuses)
    }
}
