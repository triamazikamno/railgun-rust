use super::saved_poi_compatibility::{
    saved_pending_context_is_compatible, saved_pending_context_matches_public_transaction,
};
use std::collections::BTreeSet;
use std::ops::ControlFlow;

use crate::chain::PendingOutputPoiSubmitIntent;
use broadcaster_core::transact::PreTxPoi;
use poi::error::PoiRpcError;
use serde::Serialize;

use super::{
    BTreeMap, BlindedCommitmentData, CancellationToken, ChainPublicDataPlane,
    CommitmentObservation, DbStore, DeferredForceKind, EVM_CHAIN_TYPE, ExpectedPoiCorpusRevision,
    ExpectedPoiListState, ExpectedPoiStatus, ExpectedRecordState, ExpectedWalletOutput, FixedBytes,
    Instant, LocallyValidPendingListsDelta, OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
    OutputPoiRecoveryAction, OutputPoiRecoveryRecord, OutputPoiRecoveryStatus, OutputRecoveryDelta,
    OwnedPoiPrivateDelta, PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER, PendingContextTerminalDelta,
    PendingOutputPoiContextRecord, PendingOutputPoiObservation, PendingOutputPoiRole,
    PendingOutputPoiSubject, PendingOutputPoiSubmissionPredicate,
    PendingOutputPoiValidationEvidence, PendingSubmissionDelta, PoiError, PoiPrivateApplyOutcome,
    PoiStatus, PoiStatusReader, PoiStatusRefreshDelta, PublicPoiCorpusHandle, PublicPoiCorpusKey,
    RecoveredOutgoingSubmissionDelta, RecoveredOutgoingSubmissionSibling,
    SenderCandidateLocallyValidDelta, SenderCandidateMaterializationDelta,
    SenderCandidateReconstructionDelta, SenderCandidateUnshieldUpdateDelta,
    SenderCandidateUnshieldValidatedDelta, SingleCommitmentProofContext, TransactProofRoute, U256,
    Utxo, UtxoCommitmentKind, UtxoPoiMetadata, VerifiedValidDelta, WalletCacheError,
    WalletCacheKey, WalletCacheStore, WalletCheckpointMutation, WalletConfig, WalletHandle,
    WalletPoiRuntime, WalletPpoiSubmissionStatus, WalletPpoiWorkflowStatus, WalletPrivateCommit,
    WalletPrivateMutationAuthority, WalletPrivateMutationPermit, WalletPrivatePoiClients,
    WalletPrivateRemoteError, WalletPrivateRemoteStale, WalletUtxo, WalletUtxoMutation, debug,
    default_active_poi_list_keys, force_resubmit_pending_output_poi_context, info,
    new_output_poi_recovery_record, now_epoch_secs, saved_poi_compatibility,
    sender_candidate_recovery, warn,
};

mod delta_apply;
mod recovered_outgoing;
mod subject;
mod tentative;
mod verification;
mod workflow_status;

mod observations;
mod owned_delta;
mod record_matching;
mod remote_attempts;
mod submission_pass;
mod submission_plan;
mod submission_preflight;

pub(crate) use observations::*;
pub(super) use owned_delta::*;
pub(super) use record_matching::*;
#[allow(clippy::wildcard_imports)]
use remote_attempts::*;
#[allow(clippy::wildcard_imports)]
use submission_plan::*;
pub(super) use submission_preflight::*;

/// Keeps the tracing target of the moved items at this module's path.
const LOG_TARGET: &str = module_path!();

use delta_apply::apply_poi_private_delta_inline;
use subject::{PendingOutputPoiSubjectMatch, pending_output_poi_subject_matches_snapshot};
pub(super) use subject::{
    PendingOutputPoiSubmitIdentity, current_pending_output_poi_subject,
    pending_output_poi_context_matches_wallet_utxo, pending_output_poi_submit_identity,
};
pub(super) use tentative::{
    PendingOutputPoiTentativeAttemptKey, PendingOutputPoiTentativeCandidate,
    PendingOutputPoiTentativeLocalStatus, PendingOutputPoiTentativeSubmissionResult,
    prepare_pending_output_poi_tentative_candidates,
    read_pending_output_poi_tentative_local_statuses,
    submit_pending_output_poi_tentative_candidates,
};
#[cfg(test)]
pub(super) use verification::reconcile_pending_output_poi_local_statuses;
pub(super) use verification::verify_submitted_pending_output_pois_with_config_authorized;
pub(super) use workflow_status::{
    PoiPrivateRows, WalletPpoiWorkflowProjection, wallet_ppoi_workflow_status_after_mutations,
};

#[derive(Default)]
pub(super) struct PendingOutputPoiStateUpdates {
    pub(super) context_updates: Vec<PendingOutputPoiContextRecord>,
    pub(super) context_deletes: Vec<FixedBytes<32>>,
    pub(super) recovery_deletes: Vec<FixedBytes<32>>,
}

/// Preflight result for generation-scoped remote pending-output POI submit.
///
/// Remote disclosure must not start unless [`Self::Ready`]. Authority loss aborts the
/// whole multi-context job; other not-current reasons skip only that candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PendingOutputPoiPreflight {
    Ready,
    NotCurrent,
    AuthorityStale,
}

/// Remote attempt after a successful preflight (durable apply is still postflight-gated).
#[derive(Debug)]
pub(super) enum PendingOutputPoiRemoteAttempt {
    NotCurrent,
    AuthorityStale,
    /// The submission scheduler did not admit the transaction; nothing was
    /// sent, and the caller skips its TXID this pass without a durable write.
    Deferred,
    /// Preflight failed structural build (missing pre-tx POIs); caller may mark terminal.
    MissingPreTransactionPois,
    Succeeded {
        submitted_list_keys: Vec<FixedBytes<32>>,
    },
    /// Remote failure; `error` is the text recorded in `SubmitFailed`.
    Failed {
        error: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingOutputPoiSubmissionPlan {
    /// Which lists the plan targets. `ForceMatching` is a user/API force-resubmit of
    /// matching contexts, with no recovery-retry gate.
    predicate: PendingOutputPoiSubmissionPredicate,
    list_keys: Vec<FixedBytes<32>>,
    expected_recovery: ExpectedRecordState,
    force_submission_retry: bool,
}

/// Borrowed inputs one pending-output POI submission pass shares across its records.
struct PendingOutputPoiSubmissionPass<'a> {
    authority: &'a WalletPrivateMutationAuthority<'a>,
    public_data_plane: &'a ChainPublicDataPlane,
    db: &'a DbStore,
    cache_store: &'a dyn WalletCacheStore,
    cfg: &'a WalletConfig,
    active_list_keys: &'a [FixedBytes<32>],
    private_poi: &'a WalletPrivatePoiClients,
    records: &'a [PendingOutputPoiContextRecord],
    forced_txids: &'a BTreeMap<U256, DeferredForceKind>,
    force_submission_retry: bool,
    now: u64,
}

/// What a submission pass carries from one record to the next.
#[derive(Default)]
struct PendingOutputPoiSubmissionPassState {
    route: Option<TransactProofRoute>,
    deferred_txids: BTreeSet<U256>,
    submitted_contexts: usize,
}

/// A standard submission's subject and plan, recorded through its pass.
struct StandardAttempt<'a> {
    pass: &'a PendingOutputPoiSubmissionPass<'a>,
    record: &'a PendingOutputPoiContextRecord,
    subject: PendingOutputPoiSubject,
    plan: PendingOutputPoiSubmissionPlan,
    expected_context_fingerprint: Vec<u8>,
}

/// One pending output context's proofs on their way to the POI gateway; the
/// preflight re-checks each send.
struct GatewaySubmission<'a> {
    preflight: &'a PendingOutputPoiSubmissionPreflight<'a>,
    private_poi: &'a WalletPrivatePoiClients,
    observation: &'a PendingOutputPoiObservation,
}

/// Borrowed inputs of one submission-plan preflight. Building one checks nothing;
/// [`Self::run`] checks the plan each time it is called.
pub(super) struct PendingOutputPoiSubmissionPreflight<'a> {
    pub(super) authority: &'a WalletPrivateMutationAuthority<'a>,
    pub(super) public_data_plane: &'a ChainPublicDataPlane,
    pub(super) cache_store: &'a dyn WalletCacheStore,
    pub(super) cfg: &'a WalletConfig,
    pub(super) active_list_keys: &'a [FixedBytes<32>],
    pub(super) expected: &'a PendingOutputPoiContextRecord,
    pub(super) subject: &'a PendingOutputPoiSubject,
    pub(super) plan: &'a PendingOutputPoiSubmissionPlan,
}

#[cfg(test)]
pub(super) mod test_support;
