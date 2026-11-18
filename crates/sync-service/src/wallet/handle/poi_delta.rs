//! The expected-state checks and private POI deltas remote jobs hand back to the wallet actor.

#[allow(clippy::wildcard_imports)]
use super::*;
#[derive(Debug, Clone, PartialEq, Eq)]
struct ExpectedPoiIdentity {
    commitment_kind: UtxoCommitmentKind,
    commitment: FixedBytes<32>,
    npk: FixedBytes<32>,
    blinded_commitment: FixedBytes<32>,
}

impl ExpectedPoiIdentity {
    const fn new(poi: &UtxoPoiMetadata) -> Self {
        Self {
            commitment_kind: poi.commitment_kind,
            commitment: poi.commitment,
            npk: poi.npk,
            blinded_commitment: poi.blinded_commitment,
        }
    }

    fn matches(&self, poi: &UtxoPoiMetadata) -> bool {
        poi.commitment_kind == self.commitment_kind
            && poi.commitment == self.commitment
            && poi.npk == self.npk
            && poi.blinded_commitment == self.blinded_commitment
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ExpectedWalletOutput {
    stable_identity: Vec<u8>,
    tree: u32,
    position: u64,
    source: UtxoSource,
    poi_identity: ExpectedPoiIdentity,
}

impl ExpectedWalletOutput {
    pub(crate) fn new(wallet_utxo: &WalletUtxo) -> Self {
        Self {
            stable_identity: wallet_utxo_stable_identity(wallet_utxo),
            tree: wallet_utxo.utxo.tree,
            position: wallet_utxo.utxo.position,
            source: wallet_utxo.utxo.source.clone(),
            poi_identity: ExpectedPoiIdentity::new(&wallet_utxo.utxo.poi),
        }
    }

    pub(crate) fn matches(&self, wallet_utxo: &WalletUtxo) -> bool {
        !wallet_utxo.is_spent()
            && wallet_utxo_stable_identity(wallet_utxo) == self.stable_identity
            && wallet_utxo.utxo.tree == self.tree
            && wallet_utxo.utxo.position == self.position
            && wallet_utxo.utxo.source == self.source
            && self.poi_identity.matches(&wallet_utxo.utxo.poi)
    }

    pub(crate) const fn output_commitment(&self) -> FixedBytes<32> {
        self.poi_identity.commitment
    }

    #[cfg(test)]
    pub(crate) const fn blinded_commitment(&self) -> FixedBytes<32> {
        self.poi_identity.blinded_commitment
    }

    pub(crate) const fn candidate_identity(&self) -> (u32, u64, FixedBytes<32>) {
        (self.tree, self.position, self.poi_identity.commitment)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExpectedPoiListState {
    statuses: BTreeMap<FixedBytes<32>, Option<PoiStatus>>,
}

impl ExpectedPoiListState {
    pub(crate) fn new(poi: &UtxoPoiMetadata, list_keys: &[FixedBytes<32>]) -> Self {
        Self {
            statuses: list_keys
                .iter()
                .copied()
                .map(|list_key| (list_key, poi.statuses.get(&list_key).copied()))
                .collect(),
        }
    }

    pub(crate) fn matches_recoverable_or_valid(
        &self,
        poi: &UtxoPoiMetadata,
        list_keys: &[FixedBytes<32>],
    ) -> bool {
        self.statuses
            .keys()
            .all(|list_key| list_keys.contains(list_key))
            && list_keys.iter().all(|list_key| {
                self.statuses.get(list_key).is_some_and(|expected| {
                    let current = poi.statuses.get(list_key).copied();
                    expected
                        .as_ref()
                        .is_none_or(|status| status.is_recoverable() || *status == PoiStatus::Valid)
                        && current.is_none_or(|status| {
                            status.is_recoverable() || status == PoiStatus::Valid
                        })
                })
            })
    }

    pub(crate) fn matches_valid(
        &self,
        poi: &UtxoPoiMetadata,
        list_keys: &[FixedBytes<32>],
    ) -> bool {
        self.statuses
            .keys()
            .all(|list_key| list_keys.contains(list_key))
            && list_keys.iter().all(|list_key| {
                self.statuses.get(list_key) == Some(&Some(PoiStatus::Valid))
                    && poi.statuses.get(list_key) == Some(&PoiStatus::Valid)
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExpectedRecordState {
    Absent,
    Present(Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExpectedPoiStatus {
    Recoverable,
    Valid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PendingOutputPoiSubmissionPredicate {
    Missing,
    RetrySubmitted,
    ForceMatching,
}

/// Exact actor-owned subject for a pending-output POI side effect.
/// External subjects authorize context/recovery mutation, never UTXO mutation.
#[derive(Debug, Clone)]
pub(crate) enum PendingOutputPoiSubject {
    Owned(ExpectedWalletOutput),
    External {
        output_commitment: FixedBytes<32>,
        derived_blinded_commitment: FixedBytes<32>,
    },
}

impl PendingOutputPoiSubject {
    pub(crate) const fn output_commitment(&self) -> FixedBytes<32> {
        match self {
            Self::Owned(expected) => expected.output_commitment(),
            Self::External {
                output_commitment, ..
            } => *output_commitment,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RecoveredOutgoingSubmissionSibling {
    pub(crate) subject: PendingOutputPoiSubject,
    pub(crate) expected_context_fingerprint: Vec<u8>,
    pub(crate) plan: super::super::pending_output_poi::PendingOutputPoiSubmissionPlan,
}

/// Evidence that authorizes retirement of an exact pending-output POI context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PendingOutputPoiValidationEvidence {
    /// Every required active list was durably recorded as submitted before status verification.
    SubmittedStatus,
    /// The exact owned output was authoritatively refreshed as Valid for every required list.
    OwnedStatusRefresh,
}

/// Chain POI corpus revision a local proof source was read at.
///
/// A commit that consumes a local proof carries this instead of a corpus fence guard, and the
/// actor rechecks it under a short corpus read fence before writing.
#[derive(Debug, Clone)]
pub(crate) struct ExpectedPoiCorpusRevision {
    pub(crate) corpus: PublicPoiCorpusHandle,
    pub(crate) revision: PoiCorpusRevision,
}

/// Owned semantic POI intent for actor re-entry (jobs never write mirrors or stale rows).
#[derive(Debug, Clone)]
pub(crate) enum OwnedPoiPrivateDelta {
    /// Restore the consumed scan candidate without applying the replay to wallet state.
    SenderCandidateReconstruction(SenderCandidateReconstructionDelta),
    /// Retire an exact sender candidate after the actor re-reads local artifact POI status, or
    /// keep only its remaining unshield work when `unshield` is set.
    SenderCandidateLocallyValid(SenderCandidateLocallyValidDelta),
    /// Install standard external pending/recovery siblings, reuse exact wallet-owned substitutes,
    /// and consume their scan candidate in one actor-owned durable commit.
    SenderCandidateMaterialization(SenderCandidateMaterializationDelta),
    /// Record, narrow, or retire a sender candidate's unshield work without completing any
    /// validation.
    SenderCandidateUnshieldUpdate(SenderCandidateUnshieldUpdateDelta),
    /// Complete unshield TXIDs after the actor re-reads them Valid on every active list.
    SenderCandidateUnshieldValidated(SenderCandidateUnshieldValidatedDelta),
    /// Fold a recovery action into the exact predecessor, optionally replacing a pending
    /// context whose predecessor is also exact.
    OutputRecovery(OutputRecoveryDelta),
    /// Apply a completed submission to the current context/recovery records.
    PendingSubmission(PendingSubmissionDelta),
    /// Apply one recovered sender transaction/list result to every exact output sibling.
    RecoveredOutgoingSubmission(RecoveredOutgoingSubmissionDelta),
    /// Mark a still-current context terminal after a structural submission failure.
    PendingContextTerminal(PendingContextTerminalDelta),
    /// Mark list keys Valid only for the stable output and target-list state that were verified.
    VerifiedValid(VerifiedValidDelta),
    /// Reconcile only the list keys proven Valid by the local POI corpus. The context remains
    /// pending when other active lists still need submission.
    LocallyValidPendingLists(LocallyValidPendingListsDelta),
    /// Apply remotely-read statuses only to currently matching unspent UTXOs.
    PoiStatusRefresh(PoiStatusRefreshDelta),
}

#[derive(Debug, Clone)]
pub(crate) struct SenderCandidateReconstructionDelta {
    pub(crate) candidate: SenderTransactionCandidate,
    pub(crate) replay_fence: super::super::saved_poi_compatibility::SenderCandidateReplayFence,
    pub(crate) expected_group: Vec<(
        PendingOutputPoiContextRecord,
        Option<OutputPoiRecoveryRecord>,
    )>,
}

#[derive(Debug, Clone)]
pub(crate) struct SenderCandidateLocallyValidDelta {
    pub(crate) expected_candidate: SenderTransactionCandidate,
    pub(crate) corpus: PublicPoiCorpusHandle,
    pub(crate) public_data_fence: SenderCandidatePublicDataFence,
    pub(crate) unshield: Option<SenderTransactionCandidateUnshield>,
}

#[derive(Debug, Clone)]
pub(crate) struct SenderCandidateMaterializationDelta {
    pub(crate) expected_candidate: SenderTransactionCandidate,
    pub(crate) public_data_fence: SenderCandidatePublicDataFence,
    pub(crate) active_list_keys: Vec<FixedBytes<32>>,
    pub(crate) pending_updates: Vec<PendingOutputPoiContextRecord>,
    pub(crate) recovery_updates: Vec<OutputPoiRecoveryRecord>,
    pub(crate) owned_substitutes: Vec<ExpectedWalletOutput>,
    pub(crate) proof_outputs: Vec<FixedBytes<32>>,
    /// Exact unresolved predecessors when replacing proofs from an obsolete circuit.
    pub(crate) replacement_group: Vec<(
        PendingOutputPoiContextRecord,
        Option<OutputPoiRecoveryRecord>,
    )>,
    /// Completed external outputs remain witness evidence without new pending records.
    pub(crate) external_valid_substitutes: Vec<Utxo>,
    /// Corpus revision the candidate's proofs were built from.
    pub(crate) expected_corpus: ExpectedPoiCorpusRevision,
    /// Remaining unshield work; when set the candidate is kept instead of consumed.
    pub(crate) unshield: Option<SenderTransactionCandidateUnshield>,
}

#[derive(Debug, Clone)]
pub(crate) struct SenderCandidateUnshieldUpdateDelta {
    pub(crate) expected_candidate: SenderTransactionCandidate,
    pub(crate) public_data_fence: SenderCandidatePublicDataFence,
    pub(crate) replacement: Option<SenderTransactionCandidate>,
}

#[derive(Debug, Clone)]
pub(crate) struct SenderCandidateUnshieldValidatedDelta {
    pub(crate) expected_candidate: SenderTransactionCandidate,
    pub(crate) validated_txids: Vec<FixedBytes<32>>,
    pub(crate) corpus: PublicPoiCorpusHandle,
}

#[derive(Debug, Clone)]
pub(crate) struct OutputRecoveryDelta {
    pub(crate) expected_output: ExpectedWalletOutput,
    pub(crate) active_list_keys: Vec<FixedBytes<32>>,
    pub(crate) target_list_keys: Vec<FixedBytes<32>>,
    pub(crate) required_poi_status: ExpectedPoiStatus,
    pub(crate) pending_update: Box<Option<(ExpectedRecordState, PendingOutputPoiContextRecord)>>,
    pub(crate) expected_recovery: ExpectedRecordState,
    pub(crate) action: OutputPoiRecoveryAction,
    pub(crate) now: u64,
    /// Set only when the commit consumes a proof built from the local corpus.
    pub(crate) expected_corpus: Option<ExpectedPoiCorpusRevision>,
    /// Source scan epoch used to reconstruct missing sender notes.
    pub(crate) replay_fence:
        Option<super::super::saved_poi_compatibility::SenderCandidateReplayFence>,
}

#[derive(Debug, Clone)]
pub(crate) struct PendingSubmissionDelta {
    pub(crate) subject: PendingOutputPoiSubject,
    pub(crate) expected_context_fingerprint: Vec<u8>,
    pub(crate) expected_recovery: ExpectedRecordState,
    pub(crate) active_list_keys: Vec<FixedBytes<32>>,
    pub(crate) list_keys: Vec<FixedBytes<32>>,
    pub(crate) predicate: PendingOutputPoiSubmissionPredicate,
    pub(crate) merge_submitted_list_keys: bool,
    pub(crate) action: OutputPoiRecoveryAction,
    pub(crate) now: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct RecoveredOutgoingSubmissionDelta {
    pub(crate) siblings: Vec<RecoveredOutgoingSubmissionSibling>,
    pub(crate) owned_substitutes: Vec<ExpectedWalletOutput>,
    pub(crate) external_valid_substitutes: Vec<FixedBytes<32>>,
    pub(crate) expected_corpus: Option<ExpectedPoiCorpusRevision>,
    pub(crate) active_list_keys: Vec<FixedBytes<32>>,
    pub(crate) list_keys: Vec<FixedBytes<32>>,
    pub(crate) merge_submitted_list_keys: bool,
    pub(crate) action: OutputPoiRecoveryAction,
    pub(crate) now: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct PendingContextTerminalDelta {
    pub(crate) subject: PendingOutputPoiSubject,
    pub(crate) expected_context_fingerprint: Vec<u8>,
    pub(crate) expected_recovery: ExpectedRecordState,
    pub(crate) active_list_keys: Vec<FixedBytes<32>>,
    pub(crate) target_list_keys: Vec<FixedBytes<32>>,
    pub(crate) error: String,
}

#[derive(Debug, Clone)]
pub(crate) struct VerifiedValidDelta {
    pub(crate) subject: PendingOutputPoiSubject,
    pub(crate) evidence: PendingOutputPoiValidationEvidence,
    pub(crate) expected_context_fingerprint: Vec<u8>,
    pub(crate) expected_recovery: ExpectedRecordState,
    pub(crate) expected_poi_list_state: Option<ExpectedPoiListState>,
    pub(crate) active_list_keys: Vec<FixedBytes<32>>,
    pub(crate) valid_list_keys: Vec<FixedBytes<32>>,
    pub(crate) now: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct LocallyValidPendingListsDelta {
    pub(crate) subject: PendingOutputPoiSubject,
    pub(crate) expected_context_fingerprint: Vec<u8>,
    pub(crate) expected_recovery: ExpectedRecordState,
    pub(crate) active_list_keys: Vec<FixedBytes<32>>,
    pub(crate) valid_list_keys: Vec<FixedBytes<32>>,
    pub(crate) now: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct PoiStatusRefreshDelta {
    pub(crate) active_list_keys: Vec<FixedBytes<32>>,
    pub(crate) expected_poi_by_blinded_commitment: BTreeMap<FixedBytes<32>, UtxoPoiMetadata>,
    pub(crate) statuses_by_blinded_commitment:
        BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PoiStatus>>,
    pub(crate) refreshed_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PoiPrivateApplyOutcome {
    Applied {
        utxo_changed: bool,
    },
    Skipped,
    /// The chain POI corpus advanced after the commit's local proof source was read; nothing
    /// was written and a later maintenance run prepares the work again.
    SkippedStaleCorpusRevision,
}

/// Job → actor private apply request. Actor is the sole UTXO/durable private writer.
pub(crate) struct WalletPrivateApplyRequest {
    pub reset_generation: u64,
    pub delta: OwnedPoiPrivateDelta,
    pub reply: oneshot::Sender<Result<PoiPrivateApplyOutcome, WalletCacheError>>,
}

/// Client used by remote jobs to re-enter the actor for private POI commits.
#[derive(Clone)]
pub(crate) struct WalletPrivateApplyClient {
    tx: mpsc::Sender<WalletPrivateApplyRequest>,
}

impl WalletPrivateApplyClient {
    pub(crate) const fn new(tx: mpsc::Sender<WalletPrivateApplyRequest>) -> Self {
        Self { tx }
    }

    pub(crate) async fn apply(
        &self,
        reset_generation: u64,
        delta: OwnedPoiPrivateDelta,
    ) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(WalletPrivateApplyRequest {
                reset_generation,
                delta,
                reply: reply_tx,
            })
            .await
            .map_err(|_| WalletCacheError::Crypto)?;
        reply_rx.await.map_err(|_| WalletCacheError::Crypto)?
    }
}
