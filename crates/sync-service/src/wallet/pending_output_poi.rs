use super::saved_poi_compatibility::{
    saved_pending_context_is_compatible, saved_pending_context_matches_public_transaction,
};
use std::collections::BTreeSet;
use std::ops::ControlFlow;
use std::sync::Arc;

use crate::SenderTransactionCandidate;
use crate::chain::PendingOutputPoiSubmitIntent;
use poi::error::PoiRpcError;

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
mod tentative;
mod verification;

use delta_apply::apply_poi_private_delta_inline;
pub(super) use tentative::{
    PendingOutputPoiTentativeAttemptKey, PendingOutputPoiTentativeCandidate,
    PendingOutputPoiTentativeLocalStatus, prepare_pending_output_poi_tentative_candidates,
    read_pending_output_poi_tentative_local_statuses,
    submit_pending_output_poi_tentative_candidates,
};
#[cfg(test)]
pub(super) use verification::reconcile_pending_output_poi_local_statuses;
pub(super) use verification::verify_submitted_pending_output_pois_with_config_authorized;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct WalletPpoiWorkflowProjection {
    pub(super) status: WalletPpoiWorkflowStatus,
    pub(super) submissions: Arc<[WalletPpoiSubmissionStatus]>,
}

pub(super) fn wallet_ppoi_workflow_status_after_mutations(
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    validation_revision: u64,
    pending_updates: &[PendingOutputPoiContextRecord],
    pending_deletes: &[FixedBytes<32>],
    recovery_updates: &[OutputPoiRecoveryRecord],
    recovery_deletes: &[FixedBytes<32>],
    candidate_updates: &[SenderTransactionCandidate],
    candidate_deletes: &[FixedBytes<32>],
) -> Result<WalletPpoiWorkflowProjection, WalletCacheError> {
    let mut recoveries = cache_store
        .list_output_poi_recoveries(cfg.chain.chain_id, &cfg.cache_key)?
        .into_iter()
        .map(|record| (record.output_commitment, record))
        .collect::<BTreeMap<_, _>>();
    for recovery in recovery_updates {
        recoveries.insert(recovery.output_commitment, recovery.clone());
    }
    for output_commitment in recovery_deletes {
        recoveries.remove(output_commitment);
    }
    let mut contexts = cache_store
        .list_pending_output_poi_contexts(cfg.chain.chain_id, &cfg.cache_key)?
        .into_iter()
        .map(|record| (record.output_commitment, record))
        .collect::<BTreeMap<_, _>>();
    for context in pending_updates {
        contexts.insert(context.output_commitment, context.clone());
    }
    for output_commitment in pending_deletes {
        contexts.remove(output_commitment);
    }
    let mut candidates = cache_store
        .list_sender_transaction_candidates(cfg.chain.chain_id, &cfg.cache_key)?
        .into_iter()
        .map(|candidate| (candidate.semantic_id(), candidate))
        .collect::<BTreeMap<_, _>>();
    for candidate in candidate_updates {
        candidates.insert(candidate.semantic_id(), candidate.clone());
    }
    for candidate_id in candidate_deletes {
        candidates.remove(candidate_id);
    }
    let mut status = WalletPpoiWorkflowStatus {
        validation_revision,
        ..WalletPpoiWorkflowStatus::default()
    };
    let mut submissions = Vec::new();
    for candidate in candidates.values() {
        if let Some(unshield) = &candidate.unshield {
            status.awaiting_recovery = status
                .awaiting_recovery
                .saturating_add(u64::try_from(unshield.railgun_txids.len()).unwrap_or(u64::MAX));
            if unshield.outputs_handed_off {
                continue;
            }
        }
        let mut has_unknown_output = false;
        let mut all_outputs_owned = true;
        for output in &candidate.outputs {
            let Some(note) = output.note.as_ref() else {
                has_unknown_output = true;
                continue;
            };
            if note.npk
                != railgun_wallet::Note::npk_for(cfg.scan_keys.master_public_key, note.random)
            {
                all_outputs_owned = false;
                if !contexts.contains_key(&output.commitment) {
                    status.awaiting_recovery = status.awaiting_recovery.saturating_add(1);
                }
            }
        }
        // An unqualified candidate with no external output, such as a self-paid partial
        // unshield with only owned change, still represents unresolved work.
        if has_unknown_output || (candidate.unshield.is_none() && all_outputs_owned) {
            status.awaiting_recovery = status.awaiting_recovery.saturating_add(1);
        }
    }
    for context in contexts.values() {
        let Some(observation) = context.observation.as_ref() else {
            continue;
        };
        let required_active_lists = context
            .list_keys()
            .into_iter()
            .filter(|list_key| active_list_keys.contains(list_key))
            .collect::<Vec<_>>();
        if required_active_lists.is_empty() {
            continue;
        }
        let recovery = recoveries.get(&context.output_commitment);
        let matching_valid_recovery = recovery.is_some_and(|recovery| {
            recovery.source_tx_hash == observation.tx_hash
                && recovery.status == OutputPoiRecoveryStatus::Valid
        });
        let recovery_needs_attention = recovery.is_some_and(|recovery| {
            recovery.source_tx_hash != observation.tx_hash
                || !matches!(
                    recovery.status,
                    OutputPoiRecoveryStatus::Recoverable
                        | OutputPoiRecoveryStatus::Submitted
                        | OutputPoiRecoveryStatus::Valid
                )
        });
        if let Some(last_submission_at) = recovery
            .filter(|recovery| recovery.source_tx_hash == observation.tx_hash)
            .and_then(|recovery| recovery.last_submission_at)
            .filter(|last_submission_at| *last_submission_at != 0)
            && context
                .submitted_poi_list_keys
                .iter()
                .any(|list_key| active_list_keys.contains(list_key))
        {
            submissions.push(WalletPpoiSubmissionStatus {
                output_commitment: context.output_commitment,
                last_submission_at,
            });
        }
        if context.output_role == PendingOutputPoiRole::Change {
            continue;
        }
        if context.terminal_error.is_some() || recovery_needs_attention {
            status.needs_attention = status.needs_attention.saturating_add(1);
        } else if !matching_valid_recovery
            && !saved_pending_context_is_compatible(context, &required_active_lists)
        {
            status.awaiting_recovery = status.awaiting_recovery.saturating_add(1);
        } else if matching_valid_recovery
            || required_active_lists
                .iter()
                .all(|list_key| context.submitted_poi_list_keys.contains(list_key))
        {
            status.awaiting_validation = status.awaiting_validation.saturating_add(1);
        } else {
            status.awaiting_submission = status.awaiting_submission.saturating_add(1);
        }
    }
    Ok(WalletPpoiWorkflowProjection {
        status,
        submissions: Arc::from(submissions),
    })
}

fn wallet_ppoi_workflow_status_after_validation(
    permit: &WalletPrivateMutationPermit<'_>,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    retired_output_commitment: FixedBytes<32>,
) -> Result<WalletPpoiWorkflowProjection, WalletCacheError> {
    let pending_deletes = [retired_output_commitment];
    let recovery_deletes = [retired_output_commitment];
    wallet_ppoi_workflow_status_after_mutations(
        cache_store,
        cfg,
        active_list_keys,
        permit
            .ppoi_workflow_status()
            .validation_revision
            .saturating_add(1),
        &[],
        &pending_deletes,
        &[],
        &recovery_deletes,
        &[],
        &[],
    )
}

pub(super) async fn process_pending_output_poi_observations_authorized(
    authority: &WalletPrivateMutationAuthority<'_>,
    public_data_plane: &ChainPublicDataPlane,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    private_poi: Option<&WalletPrivatePoiClients>,
    force_submission_retry: bool,
) -> usize {
    let started = Instant::now();
    let Some(private_poi) = private_poi else {
        return 0;
    };
    // No long-lived permit: remote submit uses authority revalidation; semantic
    // intents acquire a short permit only when the actor folds them into current state.
    if authority.revalidate().is_err() {
        debug!(
            chain_id = cfg.chain.chain_id,
            "pending output POI submission skipped"
        );
        return 0;
    }
    let submitted_contexts = submit_observed_pending_output_pois_inner(
        authority,
        public_data_plane,
        db,
        cache_store,
        cfg,
        active_list_keys,
        private_poi,
        force_submission_retry,
    )
    .await
    .unwrap_or_else(|_| {
        warn!(
            chain_id = cfg.chain.chain_id,
            "failed to submit observed pending output POI contexts"
        );
        0
    });
    if submitted_contexts > 0 {
        debug!(
            chain_id = cfg.chain.chain_id,
            submitted_contexts,
            elapsed_ms = started.elapsed().as_millis(),
            "submitted observed pending output POI contexts"
        );
    }
    submitted_contexts
}

#[derive(Default)]
pub(super) struct PendingOutputPoiStateUpdates {
    pub(super) context_updates: Vec<PendingOutputPoiContextRecord>,
    pub(super) context_deletes: Vec<FixedBytes<32>>,
    pub(super) recovery_deletes: Vec<FixedBytes<32>>,
}

pub(super) fn pending_output_poi_observation_state_updates(
    cache_store: &dyn WalletCacheStore,
    chain_id: u64,
    wallet_id: &WalletCacheKey,
    observations: &[CommitmentObservation],
) -> Result<PendingOutputPoiStateUpdates, WalletCacheError> {
    let mut updates = PendingOutputPoiStateUpdates::default();
    for observation in observations {
        let output_commitment = FixedBytes::from(observation.commitment.to_be_bytes::<32>());
        let Some(mut record) =
            cache_store.get_pending_output_poi_context(chain_id, wallet_id, &output_commitment)?
        else {
            continue;
        };
        let observed = PendingOutputPoiObservation {
            output_tree: u64::from(observation.tree),
            output_position: observation.position,
            tx_hash: observation.source.tx_hash,
            block_number: observation.source.block_number,
            block_timestamp: observation.source.block_timestamp,
        };
        let observation_changed = record.observe(observed.clone());
        let recovery_mismatch = if observation_changed {
            false
        } else {
            cache_store
                .get_output_poi_recovery(chain_id, wallet_id, &output_commitment)?
                .is_some_and(|recovery| recovery.source_tx_hash != observed.tx_hash)
        };
        if observation_changed || recovery_mismatch {
            // An observation identifies the post-transaction recovery subject. Any state
            // derived from a different (or previously cleared) observation must be retired
            // in the same durable scan commit before this subject becomes submit-ready.
            record.submitted_poi_list_keys.clear();
            record.terminal_error = None;
            updates.context_updates.push(record);
            updates.recovery_deletes.push(output_commitment);
        }
    }
    Ok(updates)
}

pub(crate) fn is_missing_railgun_txid_error(error: &PoiError) -> bool {
    let PoiError::RpcRequest {
        source: PoiRpcError::JsonRpc { message, .. },
    } = error
    else {
        return false;
    };
    let normalized = message
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|character| character.to_ascii_lowercase())
        .collect::<String>();
    normalized.contains("couldnotfindrailguntxid")
}

/// Send-ready copy of a newly created context for the chain PPOI submitter,
/// holding the proofs of its required lists that are currently active. `None`
/// when the context submits by transact proof or lacks one of those proofs,
/// the same rule the missing-list preflight applies.
pub(super) fn pending_output_poi_handoff_context(
    record: &PendingOutputPoiContextRecord,
    active_list_keys: &[FixedBytes<32>],
) -> Option<SingleCommitmentProofContext> {
    if record.txid_merkleroot_index.is_some()
        || record.output_role == PendingOutputPoiRole::RecoveredOutgoing
    {
        return None;
    }
    let mut list_keys = record.list_keys();
    list_keys.retain(|list_key| active_list_keys.contains(list_key));
    if list_keys.is_empty() {
        return None;
    }
    let pre_transaction_pois = record.retain_poi_lists(&list_keys);
    if pre_transaction_pois.len() != list_keys.len()
        || !saved_pending_context_is_compatible(record, &list_keys)
    {
        return None;
    }
    Some(SingleCommitmentProofContext {
        txid_version: record.txid_version.clone(),
        railgun_txid: record.railgun_txid,
        utxo_tree_in: record.utxo_tree_in,
        commitment: record.output_commitment,
        npk: record.output_npk,
        pre_transaction_pois_per_txid_leaf_per_list: pre_transaction_pois,
    })
}

pub(super) fn pending_output_poi_rewind_state_updates(
    cache_store: &dyn WalletCacheStore,
    chain_id: u64,
    wallet_id: &WalletCacheKey,
    rewind_from_block: u64,
    wallet_utxos_before_rewind: &[WalletUtxo],
) -> Result<PendingOutputPoiStateUpdates, WalletCacheError> {
    let mut updates = PendingOutputPoiStateUpdates::default();
    for mut record in cache_store.list_pending_output_poi_contexts(chain_id, wallet_id)? {
        let rewound_external_observation = record.observation.as_ref().is_some_and(|observation| {
            observation.block_number >= rewind_from_block
                && matches!(
                    record.output_role,
                    PendingOutputPoiRole::Recipient
                        | PendingOutputPoiRole::BroadcasterFee
                        | PendingOutputPoiRole::RecoveredOutgoing
                )
                && (record.output_role == PendingOutputPoiRole::RecoveredOutgoing
                    || !wallet_utxos_before_rewind.iter().any(|wallet_utxo| {
                        wallet_utxo.utxo.poi.commitment == record.output_commitment
                    }))
        });
        if !rewound_external_observation {
            continue;
        }

        updates.recovery_deletes.push(record.output_commitment);
        if record.output_role == PendingOutputPoiRole::RecoveredOutgoing {
            // Sender-recovery records are wholly derived from this observation. Unlike recipient
            // intents, they have no pre-observation context to retain for canonical replay.
            updates.context_deletes.push(record.output_commitment);
        } else {
            record.observation = None;
            record.submitted_poi_list_keys.clear();
            record.terminal_error = None;
            updates.context_updates.push(record);
        }
    }
    Ok(updates)
}

pub(super) async fn submit_observed_pending_output_pois_inner(
    authority: &WalletPrivateMutationAuthority<'_>,
    public_data_plane: &ChainPublicDataPlane,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    private_poi: &WalletPrivatePoiClients,
    force_submission_retry: bool,
) -> Result<usize, WalletCacheError> {
    submit_observed_pending_output_pois_impl(
        authority,
        public_data_plane,
        cfg,
        active_list_keys,
        db,
        cache_store,
        private_poi,
        force_submission_retry,
    )
    .await
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingOutputPoiSubmissionKind {
    Missing,
    RetrySubmitted,
    /// User/API force-resubmit of matching contexts (no recovery-retry gate).
    ForceMatching,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingOutputPoiSubmissionPlan {
    kind: PendingOutputPoiSubmissionKind,
    list_keys: Vec<FixedBytes<32>>,
    expected_recovery: ExpectedRecordState,
    force_submission_retry: bool,
}

impl PendingOutputPoiSubmissionPlan {
    const fn missing(
        list_keys: Vec<FixedBytes<32>>,
        expected_recovery: ExpectedRecordState,
    ) -> Self {
        Self {
            kind: PendingOutputPoiSubmissionKind::Missing,
            list_keys,
            expected_recovery,
            force_submission_retry: false,
        }
    }

    const fn retry_submitted(
        list_keys: Vec<FixedBytes<32>>,
        expected_recovery: ExpectedRecordState,
        force_submission_retry: bool,
    ) -> Self {
        Self {
            kind: PendingOutputPoiSubmissionKind::RetrySubmitted,
            list_keys,
            expected_recovery,
            force_submission_retry,
        }
    }

    /// Force-resubmit plan: active list keys already on the context (submitted or not).
    pub(super) const fn force_matching(
        list_keys: Vec<FixedBytes<32>>,
        expected_recovery: ExpectedRecordState,
    ) -> Self {
        Self {
            kind: PendingOutputPoiSubmissionKind::ForceMatching,
            list_keys,
            expected_recovery,
            force_submission_retry: true,
        }
    }

    pub(super) fn retain_current_recoverable(
        &mut self,
        context: &PendingOutputPoiContextRecord,
        active_list_keys: &[FixedBytes<32>],
        poi: Option<&UtxoPoiMetadata>,
    ) {
        self.list_keys = recoverable_pending_submission_list_keys(
            context,
            active_list_keys,
            poi,
            self.predicate(),
        );
    }

    pub(super) fn list_keys(&self) -> &[FixedBytes<32>] {
        &self.list_keys
    }

    pub(super) fn expected_recovery(&self) -> ExpectedRecordState {
        self.expected_recovery.clone()
    }

    pub(super) const fn predicate(&self) -> PendingOutputPoiSubmissionPredicate {
        match self.kind {
            PendingOutputPoiSubmissionKind::Missing => PendingOutputPoiSubmissionPredicate::Missing,
            PendingOutputPoiSubmissionKind::RetrySubmitted => {
                PendingOutputPoiSubmissionPredicate::RetrySubmitted
            }
            PendingOutputPoiSubmissionKind::ForceMatching => {
                PendingOutputPoiSubmissionPredicate::ForceMatching
            }
        }
    }

    const fn submit_intent(&self) -> PendingOutputPoiSubmitIntent {
        match self.kind {
            PendingOutputPoiSubmissionKind::Missing => PendingOutputPoiSubmitIntent::Missing,
            PendingOutputPoiSubmissionKind::RetrySubmitted => {
                PendingOutputPoiSubmitIntent::RetrySubmitted
            }
            PendingOutputPoiSubmissionKind::ForceMatching => {
                PendingOutputPoiSubmitIntent::ForceMatching
            }
        }
    }

    /// How a deferral of this plan stays forced for later passes, if at all.
    const fn deferred_force_kind(&self) -> Option<DeferredForceKind> {
        if matches!(self.kind, PendingOutputPoiSubmissionKind::ForceMatching) {
            Some(DeferredForceKind::ForceMatching)
        } else if self.force_submission_retry {
            Some(DeferredForceKind::RetrySubmitted)
        } else {
            None
        }
    }
}

struct RecoveredOutgoingSubmissionMember {
    record: PendingOutputPoiContextRecord,
    subject: PendingOutputPoiSubject,
    plan: PendingOutputPoiSubmissionPlan,
    expected_context_fingerprint: Vec<u8>,
}

struct RecoveredOutgoingSubmissionGroup {
    members: Vec<RecoveredOutgoingSubmissionMember>,
    owned_substitutes: Vec<ExpectedWalletOutput>,
    external_valid_substitutes: Vec<FixedBytes<32>>,
    expected_corpus: Option<ExpectedPoiCorpusRevision>,
    proofs: Vec<(FixedBytes<32>, broadcaster_core::transact::PreTxPoi)>,
}

struct RecoveredOutgoingGroupEvidence<'a> {
    proofs: Vec<(FixedBytes<32>, broadcaster_core::transact::PreTxPoi)>,
    owned_outputs: Vec<&'a WalletUtxo>,
    external_valid_substitutes: Vec<FixedBytes<32>>,
}

fn recovered_outgoing_group_records<'a>(
    records: &'a [PendingOutputPoiContextRecord],
    seed: &PendingOutputPoiContextRecord,
) -> Option<Vec<&'a PendingOutputPoiContextRecord>> {
    if seed.output_role != PendingOutputPoiRole::RecoveredOutgoing
        || seed.source_operation_id.is_none()
    {
        return None;
    }
    let records = records
        .iter()
        .filter(|record| {
            record.output_role == PendingOutputPoiRole::RecoveredOutgoing
                && record.chain_id == seed.chain_id
                && record.wallet_id == seed.wallet_id
                && record.source_operation_id == seed.source_operation_id
        })
        .collect::<Vec<_>>();
    (!records.is_empty()).then_some(records)
}

fn recovered_outgoing_group_evidence<'a>(
    records: &[&PendingOutputPoiContextRecord],
    wallet_utxos: &'a [WalletUtxo],
    list_keys: &[FixedBytes<32>],
    external_valid: &BTreeMap<FixedBytes<32>, BTreeSet<FixedBytes<32>>>,
) -> Option<RecoveredOutgoingGroupEvidence<'a>> {
    let leader = *records.first()?;
    let leader_observation = leader.observation.as_ref()?;
    let transaction_material = rmp_serde::to_vec(&(
        &leader.txid_version,
        leader.utxo_tree_in,
        leader.railgun_txid,
        leader.txid_merkleroot_index,
        &leader.source_operation_id,
    ))
    .ok()?;
    if leader.txid_merkleroot_index.is_none()
        || leader.required_poi_list_keys.is_empty()
        || list_keys.is_empty()
        || records.iter().any(|record| {
            record.observation.as_ref().is_none_or(|observation| {
                observation.tx_hash != leader_observation.tx_hash
                    || observation.block_number != leader_observation.block_number
                    || observation.block_timestamp != leader_observation.block_timestamp
            }) || rmp_serde::to_vec(&(
                &record.txid_version,
                record.utxo_tree_in,
                record.railgun_txid,
                record.txid_merkleroot_index,
                &record.source_operation_id,
            ))
            .ok()
            .as_ref()
                != Some(&transaction_material)
        })
    {
        return None;
    }

    let mut external_outputs = BTreeSet::new();
    let mut immutable_outputs = BTreeSet::new();
    let mut retained_proofs = BTreeMap::new();
    for record in records {
        for (list_key, per_leaf) in &record.pre_transaction_pois_per_txid_leaf_per_list {
            let encoded = rmp_serde::to_vec(per_leaf).ok()?;
            if retained_proofs
                .insert(*list_key, encoded.clone())
                .is_some_and(|previous| previous != encoded)
            {
                return None;
            }
        }
        let observation = record.observation.as_ref()?;
        let identity = pending_output_poi_submit_identity(record, observation)?;
        if !external_outputs.insert(identity.derived_blinded_commitment)
            || !immutable_outputs.insert((
                observation.output_tree,
                observation.output_position,
                record.output_commitment,
                record.output_npk,
            ))
        {
            return None;
        }
    }

    let mut proofs = Vec::with_capacity(list_keys.len());
    let mut proof_outputs = None;
    for list_key in list_keys {
        let mut retained = records.iter().filter_map(|record| {
            record
                .pre_transaction_pois_per_txid_leaf_per_list
                .get(list_key)
        });
        let per_leaf = retained.next()?;
        let encoded = rmp_serde::to_vec(per_leaf).ok()?;
        if retained.any(|other| rmp_serde::to_vec(other).ok().as_ref() != Some(&encoded)) {
            return None;
        }
        let mut values = per_leaf.values();
        let poi = values.next()?.clone();
        if values.next().is_some()
            || poi
                .blinded_commitments_out
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len()
                != poi.blinded_commitments_out.len()
        {
            return None;
        }
        let outputs = poi
            .blinded_commitments_out
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if proof_outputs
            .as_ref()
            .is_some_and(|expected| expected != &outputs)
        {
            return None;
        }
        proof_outputs = Some(outputs);
        proofs.push((*list_key, poi));
    }
    let proof_outputs = proof_outputs?;
    if !external_outputs.is_subset(&proof_outputs) {
        return None;
    }
    let mut owned_outputs = Vec::new();
    let mut external_valid_substitutes = BTreeSet::new();
    for list_key in list_keys {
        let unresolved = records
            .iter()
            .filter(|record| record.list_keys().contains(list_key))
            .filter_map(|record| {
                record
                    .observation
                    .as_ref()
                    .and_then(|observation| pending_output_poi_submit_identity(record, observation))
            })
            .map(|identity| identity.derived_blinded_commitment)
            .collect::<BTreeSet<_>>();
        for blinded_commitment in proof_outputs.difference(&unresolved) {
            let mut matches = wallet_utxos.iter().filter(|output| {
                !output.is_spent()
                    && output.utxo.poi.blinded_commitment == *blinded_commitment
                    && output.utxo.source.tx_hash == leader_observation.tx_hash
                    && output.utxo.source.block_number == leader_observation.block_number
                    && output.utxo.poi.is_valid_for_lists(&[*list_key])
            });
            let Some(output) = matches.next() else {
                if external_valid
                    .get(list_key)
                    .is_some_and(|valid| valid.contains(blinded_commitment))
                {
                    external_valid_substitutes.insert(*blinded_commitment);
                    continue;
                }
                return None;
            };
            if matches.next().is_some() {
                return None;
            }
            if !owned_outputs.iter().any(|existing: &&WalletUtxo| {
                existing.utxo.poi.blinded_commitment == *blinded_commitment
            }) {
                owned_outputs.push(output);
            }
        }
    }
    Some(RecoveredOutgoingGroupEvidence {
        proofs,
        owned_outputs,
        external_valid_substitutes: external_valid_substitutes.into_iter().collect(),
    })
}

fn recovered_outgoing_owned_substitutes_match(
    expected: &[ExpectedWalletOutput],
    current: &[&WalletUtxo],
) -> bool {
    expected.len() == current.len()
        && expected.iter().all(|expected| {
            current
                .iter()
                .filter(|output| expected.matches(output))
                .count()
                == 1
        })
        && current.iter().all(|output| {
            expected
                .iter()
                .filter(|expected| expected.matches(output))
                .count()
                == 1
        })
}

async fn recovered_outgoing_external_valid_evidence(
    public_data_plane: &ChainPublicDataPlane,
    cfg: &WalletConfig,
    seed: &PendingOutputPoiContextRecord,
    list_keys: &[FixedBytes<32>],
) -> (
    BTreeMap<FixedBytes<32>, BTreeSet<FixedBytes<32>>>,
    Option<ExpectedPoiCorpusRevision>,
) {
    let Ok(corpus) = public_data_plane
        .ensure_poi_corpus(PublicPoiCorpusKey::wallet_default(cfg.chain.chain_id))
        .await
    else {
        return (BTreeMap::new(), None);
    };
    let _fence = corpus.revision_read_fence().await;
    let outputs = seed
        .pre_transaction_pois_per_txid_leaf_per_list
        .values()
        .flat_map(|per_leaf| per_leaf.values())
        .flat_map(|poi| poi.blinded_commitments_out.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let revision = *corpus.committed_revision_rx().borrow();
    let Some(valid) = super::saved_poi_compatibility::corpus_valid_outputs_by_list(
        &corpus,
        cfg.chain.chain_id,
        list_keys,
        &outputs,
    )
    .await
    else {
        return (BTreeMap::new(), None);
    };
    (valid, Some(ExpectedPoiCorpusRevision { corpus, revision }))
}

impl PendingOutputPoiSubmissionPass<'_> {
    async fn prepare_recovered_outgoing_submission_group(
        &self,
        seed: &PendingOutputPoiContextRecord,
        force_submission_retry: bool,
    ) -> Result<Option<RecoveredOutgoingSubmissionGroup>, WalletCacheError> {
        let Self {
            authority,
            public_data_plane,
            cache_store,
            cfg,
            active_list_keys,
            records,
            now,
            ..
        } = *self;
        let Some(group_records) = recovered_outgoing_group_records(records, seed) else {
            return Ok(None);
        };
        let Some(canonical) = group_records
            .iter()
            .min_by_key(|record| record.output_commitment)
        else {
            return Ok(None);
        };
        if canonical.output_commitment != seed.output_commitment {
            return Ok(None);
        }
        let snapshot = authority
            .wallet_utxos()
            .await
            .map_err(|_| WalletCacheError::Crypto)?;
        let (external_valid, expected_corpus) = recovered_outgoing_external_valid_evidence(
            public_data_plane,
            cfg,
            seed,
            active_list_keys,
        )
        .await;
        let mut members = Vec::with_capacity(group_records.len());
        for record in &group_records {
            if record.observation.is_none() {
                return Ok(None);
            }
            if record.terminal_error.is_some() {
                return Ok(None);
            }
            let Some(identity) = record
                .observation
                .as_ref()
                .and_then(|observation| pending_output_poi_submit_identity(record, observation))
            else {
                return Ok(None);
            };
            if record.required_poi_list_keys
                != super::saved_poi_compatibility::unresolved_output_lists(
                    active_list_keys,
                    identity.derived_blinded_commitment,
                    &external_valid,
                )
            {
                return Ok(None);
            }
            let Some(recovery) = cache_store.get_output_poi_recovery(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &record.output_commitment,
            )?
            else {
                return Ok(None);
            };
            let Some(expected_recovery) = expected_recovery_state(Some(&recovery)) else {
                return Ok(None);
            };
            let Some((subject, current_output)) =
                current_pending_output_poi_subject(authority, cfg, record).await
            else {
                return Ok(None);
            };
            if !matches!(&subject, PendingOutputPoiSubject::External { .. })
                || current_output.is_some()
            {
                return Ok(None);
            }
            let mut plan = PendingOutputPoiSubmissionPlan::missing(
                record.missing_list_keys(),
                expected_recovery,
            );
            plan.retain_current_recoverable(
                record,
                active_list_keys,
                current_output.as_ref().map(|output| &output.utxo.poi),
            );
            if plan.list_keys.is_empty()
                && recovery.submission_retry_allowed(now, force_submission_retry)
            {
                plan = PendingOutputPoiSubmissionPlan::retry_submitted(
                    record.list_keys(),
                    plan.expected_recovery.clone(),
                    force_submission_retry,
                );
                plan.retain_current_recoverable(
                    record,
                    active_list_keys,
                    current_output.as_ref().map(|output| &output.utxo.poi),
                );
            }
            let Some(expected_context_fingerprint) = pending_output_poi_context_fingerprint(record)
            else {
                return Ok(None);
            };
            members.push(RecoveredOutgoingSubmissionMember {
                record: (*record).clone(),
                subject,
                plan,
                expected_context_fingerprint,
            });
        }
        let list_keys = members
            .iter()
            .flat_map(|member| member.plan.list_keys().iter().copied())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if list_keys.is_empty()
            || expected_corpus.is_none()
            || members.iter().any(|member| {
                !saved_pending_context_matches_public_transaction(
                    public_data_plane,
                    cfg,
                    &member.record,
                    &member.record.list_keys(),
                )
            })
        {
            return Ok(None);
        }
        let Some(evidence) = recovered_outgoing_group_evidence(
            &group_records,
            &snapshot,
            &list_keys,
            &external_valid,
        ) else {
            return Ok(None);
        };
        Ok(Some(RecoveredOutgoingSubmissionGroup {
            members,
            owned_substitutes: evidence
                .owned_outputs
                .into_iter()
                .map(ExpectedWalletOutput::new)
                .collect(),
            expected_corpus,
            external_valid_substitutes: evidence.external_valid_substitutes,
            proofs: evidence.proofs,
        }))
    }

    async fn recovered_outgoing_submission_group_current(
        &self,
        group: &RecoveredOutgoingSubmissionGroup,
    ) -> Result<PendingOutputPoiPreflight, WalletCacheError> {
        let Self {
            authority,
            public_data_plane,
            cache_store,
            cfg,
            active_list_keys,
            ..
        } = *self;
        if authority.revalidate().is_err() {
            return Ok(PendingOutputPoiPreflight::AuthorityStale);
        }
        let Some(seed) = group.members.first() else {
            return Ok(PendingOutputPoiPreflight::NotCurrent);
        };
        let current_records =
            cache_store.list_pending_output_poi_contexts(cfg.chain.chain_id, &cfg.cache_key)?;
        let Some(current_group) = recovered_outgoing_group_records(&current_records, &seed.record)
        else {
            return Ok(PendingOutputPoiPreflight::NotCurrent);
        };
        let expected_fingerprints = group
            .members
            .iter()
            .map(|member| member.expected_context_fingerprint.clone())
            .collect::<BTreeSet<_>>();
        let current_fingerprints = current_group
            .iter()
            .filter_map(|record| pending_output_poi_context_fingerprint(record))
            .collect::<BTreeSet<_>>();
        let snapshot = authority
            .wallet_utxos()
            .await
            .map_err(|_| WalletCacheError::Crypto)?;
        let list_keys = group
            .proofs
            .iter()
            .map(|(list_key, _)| *list_key)
            .collect::<Vec<_>>();
        let external_valid = if let Some(expected) = &group.expected_corpus {
            let outputs = group
                .proofs
                .iter()
                .flat_map(|(_, poi)| poi.blinded_commitments_out.iter().copied())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let Some(valid) = super::saved_poi_compatibility::corpus_valid_outputs_by_list(
                &expected.corpus,
                cfg.chain.chain_id,
                active_list_keys,
                &outputs,
            )
            .await
            else {
                return Ok(PendingOutputPoiPreflight::NotCurrent);
            };
            valid
        } else {
            BTreeMap::new()
        };
        let current_evidence = recovered_outgoing_group_evidence(
            &current_group,
            &snapshot,
            &list_keys,
            &external_valid,
        );
        if current_group.len() != group.members.len()
            || current_fingerprints.len() != current_group.len()
            || current_fingerprints != expected_fingerprints
            || current_evidence.as_ref().is_none_or(|evidence| {
                !recovered_outgoing_owned_substitutes_match(
                    &group.owned_substitutes,
                    &evidence.owned_outputs,
                )
            })
        {
            return Ok(PendingOutputPoiPreflight::NotCurrent);
        }
        for member in &group.members {
            let Some(identity) = member.record.observation.as_ref().and_then(|observation| {
                pending_output_poi_submit_identity(&member.record, observation)
            }) else {
                return Ok(PendingOutputPoiPreflight::NotCurrent);
            };
            if member.record.required_poi_list_keys
                != super::saved_poi_compatibility::unresolved_output_lists(
                    active_list_keys,
                    identity.derived_blinded_commitment,
                    &external_valid,
                )
            {
                return Ok(PendingOutputPoiPreflight::NotCurrent);
            }
            if member.plan.list_keys.is_empty() {
                let recovery = cache_store.get_output_poi_recovery(
                    cfg.chain.chain_id,
                    &cfg.cache_key,
                    &member.record.output_commitment,
                )?;
                if !expected_recovery_matches(&member.plan.expected_recovery, recovery.as_ref())
                    || !recoverable_pending_submission_list_keys(
                        &member.record,
                        active_list_keys,
                        None,
                        member.plan.predicate(),
                    )
                    .is_empty()
                {
                    return Ok(PendingOutputPoiPreflight::NotCurrent);
                }
                continue;
            }
            match pending_output_poi_submission_plan_current(
                authority,
                public_data_plane,
                cache_store,
                cfg,
                active_list_keys,
                &member.record,
                &member.subject,
                &member.plan,
            )
            .await?
            {
                PendingOutputPoiPreflight::Ready => {}
                not_ready => return Ok(not_ready),
            }
        }
        // Acquire the corpus fence only after the wallet actor awaits above. A corpus writer
        // may need that actor, so holding its read guard across an actor request can deadlock.
        let Ok(_corpus_fence) =
            hold_expected_poi_corpus_revision(group.expected_corpus.as_ref()).await
        else {
            return Ok(PendingOutputPoiPreflight::NotCurrent);
        };
        let final_records =
            cache_store.list_pending_output_poi_contexts(cfg.chain.chain_id, &cfg.cache_key)?;
        let Some(final_group) = recovered_outgoing_group_records(&final_records, &seed.record)
        else {
            return Ok(PendingOutputPoiPreflight::NotCurrent);
        };
        let final_fingerprints = final_group
            .iter()
            .filter_map(|record| pending_output_poi_context_fingerprint(record))
            .collect::<BTreeSet<_>>();
        if authority.revalidate().is_err()
            || final_group.len() != group.members.len()
            || final_fingerprints != expected_fingerprints
        {
            return Ok(PendingOutputPoiPreflight::NotCurrent);
        }
        for member in &group.members {
            let recovery = cache_store.get_output_poi_recovery(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &member.record.output_commitment,
            )?;
            if !expected_recovery_matches(&member.plan.expected_recovery, recovery.as_ref()) {
                return Ok(PendingOutputPoiPreflight::NotCurrent);
            }
        }
        Ok(PendingOutputPoiPreflight::Ready)
    }

    async fn submit_recovered_outgoing_submission_group(
        &self,
        group: &RecoveredOutgoingSubmissionGroup,
        route: &mut Option<TransactProofRoute>,
    ) -> Result<PendingOutputPoiRemoteAttempt, WalletCacheError> {
        let Self {
            cfg, private_poi, ..
        } = *self;
        let Some(leader) = group.members.first() else {
            return Ok(PendingOutputPoiRemoteAttempt::NotCurrent);
        };
        let Some(txid_merkleroot_index) = leader.record.txid_merkleroot_index else {
            return Ok(PendingOutputPoiRemoteAttempt::NotCurrent);
        };
        let forced = group
            .members
            .iter()
            .filter_map(|member| member.plan.deferred_force_kind())
            .max();
        let Some(route) = transact_proof_route(
            private_poi,
            route,
            cfg.chain.chain_id,
            &leader.record,
            forced,
        )
        .await
        else {
            return Ok(PendingOutputPoiRemoteAttempt::Deferred);
        };
        for (list_key, poi) in &group.proofs {
            let result = private_poi
                .submit_transact_proof(
                    route,
                    || async {
                        Ok(matches!(
                            self.recovered_outgoing_submission_group_current(group)
                                .await?,
                            PendingOutputPoiPreflight::Ready
                        ))
                    },
                    &leader.record.txid_version,
                    EVM_CHAIN_TYPE,
                    cfg.chain.chain_id,
                    list_key,
                    txid_merkleroot_index,
                    poi,
                )
                .await;
            match result {
                Ok(()) => {}
                Err(WalletPrivateRemoteError::Stale(WalletPrivateRemoteStale::Authority)) => {
                    return Ok(PendingOutputPoiRemoteAttempt::AuthorityStale);
                }
                Err(WalletPrivateRemoteError::Stale(WalletPrivateRemoteStale::Subject)) => {
                    return Ok(PendingOutputPoiRemoteAttempt::NotCurrent);
                }
                Err(WalletPrivateRemoteError::Check(error)) => return Err(error),
                Err(WalletPrivateRemoteError::Remote(error)) => {
                    return Ok(PendingOutputPoiRemoteAttempt::Failed {
                        error: error.to_string(),
                    });
                }
            }
        }
        Ok(PendingOutputPoiRemoteAttempt::Succeeded {
            submitted_list_keys: group.proofs.iter().map(|(list_key, _)| *list_key).collect(),
        })
    }
}

fn recoverable_pending_submission_list_keys(
    context: &PendingOutputPoiContextRecord,
    active_list_keys: &[FixedBytes<32>],
    poi: Option<&UtxoPoiMetadata>,
    predicate: PendingOutputPoiSubmissionPredicate,
) -> Vec<FixedBytes<32>> {
    let submitted_list_keys = &context.submitted_poi_list_keys;
    let mut list_keys = match predicate {
        PendingOutputPoiSubmissionPredicate::Missing => context.missing_list_keys(),
        PendingOutputPoiSubmissionPredicate::RetrySubmitted => context
            .list_keys()
            .into_iter()
            .filter(|list_key| submitted_list_keys.contains(list_key))
            .collect(),
        PendingOutputPoiSubmissionPredicate::ForceMatching => context.list_keys(),
    };
    list_keys.retain(|list_key| {
        active_list_keys.contains(list_key)
            && poi.is_none_or(|poi| {
                poi.statuses
                    .get(list_key)
                    .is_none_or(|status| status.is_recoverable())
            })
    });
    list_keys
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

impl PendingOutputPoiSubmissionPass<'_> {
    fn force_retry(&self, record: &PendingOutputPoiContextRecord) -> bool {
        self.force_submission_retry || self.forced_txids.contains_key(&record.railgun_txid)
    }

    async fn resubmit_forced(
        &self,
        state: &mut PendingOutputPoiSubmissionPassState,
        record: &PendingOutputPoiContextRecord,
    ) -> ControlFlow<()> {
        match force_resubmit_pending_output_poi_context(
            self.authority,
            self.public_data_plane,
            self.db,
            self.cache_store,
            self.cfg,
            self.active_list_keys,
            record,
            self.private_poi,
            &mut state.route,
            self.now,
        )
        .await
        {
            Some(PendingOutputPoiRemoteAttempt::Succeeded { .. }) => state.submitted_contexts += 1,
            Some(PendingOutputPoiRemoteAttempt::Deferred) => {
                state.deferred_txids.insert(record.railgun_txid);
            }
            Some(PendingOutputPoiRemoteAttempt::AuthorityStale) => return ControlFlow::Break(()),
            Some(
                PendingOutputPoiRemoteAttempt::NotCurrent
                | PendingOutputPoiRemoteAttempt::MissingPreTransactionPois
                | PendingOutputPoiRemoteAttempt::Failed { .. },
            )
            | None => {}
        }
        ControlFlow::Continue(())
    }

    async fn submit_record(
        &self,
        state: &mut PendingOutputPoiSubmissionPassState,
        record: &PendingOutputPoiContextRecord,
    ) -> Result<ControlFlow<()>, WalletCacheError> {
        if record.observation.is_none() || record.terminal_error.is_some() {
            return Ok(ControlFlow::Continue(()));
        }
        if record.output_role == PendingOutputPoiRole::RecoveredOutgoing {
            return self.submit_recovered_group(state, record).await;
        }
        self.submit_standard(state, record).await
    }

    async fn submit_recovered_group(
        &self,
        state: &mut PendingOutputPoiSubmissionPassState,
        record: &PendingOutputPoiContextRecord,
    ) -> Result<ControlFlow<()>, WalletCacheError> {
        let force_submission_retry = self.force_retry(record);
        let chain_id = self.cfg.chain.chain_id;
        let Some(group) = self
            .prepare_recovered_outgoing_submission_group(record, force_submission_retry)
            .await?
        else {
            return Ok(ControlFlow::Continue(()));
        };
        let remote_attempt = self
            .submit_recovered_outgoing_submission_group(&group, &mut state.route)
            .await?;
        debug!(
            chain_id,
            force_submission_retry,
            retry_submitted = group.members.iter().any(|member| {
                matches!(
                    member.plan.kind,
                    PendingOutputPoiSubmissionKind::RetrySubmitted
                )
            }),
            "pending output POI retry-submitted group due"
        );
        let (submitted_list_keys, merge_submitted_list_keys, action, submitted) =
            match remote_attempt {
                PendingOutputPoiRemoteAttempt::AuthorityStale => return Ok(ControlFlow::Break(())),
                PendingOutputPoiRemoteAttempt::NotCurrent
                | PendingOutputPoiRemoteAttempt::MissingPreTransactionPois => {
                    return Ok(ControlFlow::Continue(()));
                }
                PendingOutputPoiRemoteAttempt::Deferred => {
                    state.deferred_txids.insert(record.railgun_txid);
                    return Ok(ControlFlow::Continue(()));
                }
                PendingOutputPoiRemoteAttempt::Succeeded {
                    submitted_list_keys,
                } => (
                    submitted_list_keys,
                    true,
                    OutputPoiRecoveryAction::Submitted {
                        retry_after: PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER,
                    },
                    true,
                ),
                PendingOutputPoiRemoteAttempt::Failed { error } => (
                    group.proofs.iter().map(|(list_key, _)| *list_key).collect(),
                    false,
                    OutputPoiRecoveryAction::SubmitFailed {
                        error,
                        retry_after: OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
                    },
                    false,
                ),
            };
        if !matches!(
            self.recovered_outgoing_submission_group_current(&group)
                .await?,
            PendingOutputPoiPreflight::Ready
        ) {
            return Ok(ControlFlow::Continue(()));
        }
        let siblings = group
            .members
            .iter()
            .map(|member| RecoveredOutgoingSubmissionSibling {
                subject: member.subject.clone(),
                expected_context_fingerprint: member.expected_context_fingerprint.clone(),
                plan: member.plan.clone(),
            })
            .collect::<Vec<_>>();
        let sibling_count = siblings.len();
        match apply_poi_private_delta(
            self.authority,
            self.db,
            self.cache_store,
            self.cfg,
            OwnedPoiPrivateDelta::RecoveredOutgoingSubmission(RecoveredOutgoingSubmissionDelta {
                siblings,
                owned_substitutes: group.owned_substitutes.clone(),
                external_valid_substitutes: group.external_valid_substitutes.clone(),
                expected_corpus: group.expected_corpus.clone(),
                active_list_keys: self.active_list_keys.to_vec(),
                list_keys: submitted_list_keys,
                merge_submitted_list_keys,
                action,
                now: self.now,
            }),
        )
        .await
        {
            Ok(PoiPrivateApplyOutcome::Applied { .. }) => {
                if submitted {
                    state.submitted_contexts += sibling_count;
                }
            }
            Ok(
                PoiPrivateApplyOutcome::Skipped
                | PoiPrivateApplyOutcome::SkippedStaleCorpusRevision,
            ) => {}
            Err(_) => warn!(
                chain_id,
                "failed to atomically persist recovered outgoing POI submission state"
            ),
        }
        Ok(ControlFlow::Continue(()))
    }

    async fn submit_standard(
        &self,
        state: &mut PendingOutputPoiSubmissionPassState,
        record: &PendingOutputPoiContextRecord,
    ) -> Result<ControlFlow<()>, WalletCacheError> {
        let force_submission_retry = self.force_retry(record);
        let chain_id = self.cfg.chain.chain_id;
        let Some(observation) = record.observation.as_ref() else {
            return Ok(ControlFlow::Continue(()));
        };
        let recovery = self.cache_store.get_output_poi_recovery(
            chain_id,
            &self.cfg.cache_key,
            &record.output_commitment,
        )?;
        let Some(expected_recovery) = expected_recovery_state(recovery.as_ref()) else {
            return Ok(ControlFlow::Continue(()));
        };
        let Some((subject, current_output)) =
            current_pending_output_poi_subject(self.authority, self.cfg, record).await
        else {
            return Ok(ControlFlow::Continue(()));
        };
        let mut plan =
            PendingOutputPoiSubmissionPlan::missing(record.missing_list_keys(), expected_recovery);
        plan.retain_current_recoverable(
            record,
            self.active_list_keys,
            current_output.as_ref().map(|output| &output.utxo.poi),
        );
        if plan.list_keys.is_empty()
            && let Some(recovery) = recovery.as_ref()
            && recovery.submission_retry_allowed(self.now, force_submission_retry)
        {
            plan = PendingOutputPoiSubmissionPlan::retry_submitted(
                record.list_keys(),
                plan.expected_recovery.clone(),
                force_submission_retry,
            );
            plan.retain_current_recoverable(
                record,
                self.active_list_keys,
                current_output.as_ref().map(|output| &output.utxo.poi),
            );
        }
        if plan.list_keys.is_empty() {
            return Ok(ControlFlow::Continue(()));
        }
        debug!(
            chain_id,
            force_submission_retry,
            retry_submitted = matches!(plan.kind, PendingOutputPoiSubmissionKind::RetrySubmitted),
            "pending output POI submission due"
        );
        let Some(expected_context_fingerprint) = pending_output_poi_context_fingerprint(record)
        else {
            return Ok(ControlFlow::Continue(()));
        };
        let remote_attempt = preflight_and_remote_submit_pending_output_poi(
            self.authority,
            self.public_data_plane,
            self.cache_store,
            self.cfg,
            self.active_list_keys,
            record,
            observation,
            &subject,
            &plan,
            self.private_poi,
            &mut state.route,
        )
        .await?;
        let (list_keys, merge_submitted_list_keys, action, submitted) = match remote_attempt {
            PendingOutputPoiRemoteAttempt::NotCurrent => return Ok(ControlFlow::Continue(())),
            PendingOutputPoiRemoteAttempt::Deferred => {
                state.deferred_txids.insert(record.railgun_txid);
                return Ok(ControlFlow::Continue(()));
            }
            PendingOutputPoiRemoteAttempt::AuthorityStale => return Ok(ControlFlow::Break(())),
            PendingOutputPoiRemoteAttempt::MissingPreTransactionPois => {
                if apply_poi_private_delta(
                    self.authority,
                    self.db,
                    self.cache_store,
                    self.cfg,
                    OwnedPoiPrivateDelta::PendingContextTerminal(PendingContextTerminalDelta {
                        subject: subject.clone(),
                        expected_context_fingerprint,
                        expected_recovery: plan.expected_recovery.clone(),
                        active_list_keys: self.active_list_keys.to_vec(),
                        target_list_keys: plan.list_keys.clone(),
                        error: "missing pre-transaction POI for pending output".to_string(),
                    }),
                )
                .await
                .is_err()
                {
                    warn!(
                        chain_id,
                        "failed to atomically persist pending output POI terminal state"
                    );
                }
                return Ok(ControlFlow::Continue(()));
            }
            PendingOutputPoiRemoteAttempt::Succeeded {
                submitted_list_keys,
            } => (
                submitted_list_keys,
                true,
                OutputPoiRecoveryAction::Submitted {
                    retry_after: PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER,
                },
                true,
            ),
            PendingOutputPoiRemoteAttempt::Failed { error } => (
                plan.list_keys.clone(),
                false,
                OutputPoiRecoveryAction::SubmitFailed {
                    error,
                    retry_after: OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
                },
                false,
            ),
        };
        if !self
            .pending_output_poi_submission_side_effect_current(record, &subject, &plan)
            .await?
        {
            return Ok(ControlFlow::Continue(()));
        }
        match apply_poi_private_delta(
            self.authority,
            self.db,
            self.cache_store,
            self.cfg,
            OwnedPoiPrivateDelta::PendingSubmission(PendingSubmissionDelta {
                subject: subject.clone(),
                expected_context_fingerprint,
                expected_recovery: plan.expected_recovery.clone(),
                active_list_keys: self.active_list_keys.to_vec(),
                list_keys,
                predicate: plan.predicate(),
                merge_submitted_list_keys,
                action,
                now: self.now,
            }),
        )
        .await
        {
            Ok(PoiPrivateApplyOutcome::Applied { .. }) => {
                if submitted {
                    state.submitted_contexts += 1;
                }
            }
            Ok(
                PoiPrivateApplyOutcome::Skipped
                | PoiPrivateApplyOutcome::SkippedStaleCorpusRevision,
            ) => {}
            Err(_) if submitted => warn!(
                chain_id,
                "failed to atomically persist pending output POI submitted state"
            ),
            Err(_) => warn!(
                chain_id,
                "failed to atomically persist pending output POI submit-failure state"
            ),
        }
        if !submitted {
            warn!(
                chain_id,
                "pending output POI submission failed; keeping context retryable"
            );
        }
        Ok(ControlFlow::Continue(()))
    }
}

async fn submit_observed_pending_output_pois_impl(
    authority: &WalletPrivateMutationAuthority<'_>,
    public_data_plane: &ChainPublicDataPlane,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    private_poi: &WalletPrivatePoiClients,
    force_submission_retry: bool,
) -> Result<usize, WalletCacheError> {
    let chain_id = cfg.chain.chain_id;
    let records = cache_store.list_pending_output_poi_contexts(chain_id, &cfg.cache_key)?;
    let now = now_epoch_secs();
    debug!(
        chain_id,
        records = records.len(),
        force_submission_retry,
        "pending output POI retry-submitted scan started"
    );
    let forced_txids = private_poi.deferred_forced_txids();
    let pass = PendingOutputPoiSubmissionPass {
        authority,
        public_data_plane,
        db,
        cache_store,
        cfg,
        active_list_keys,
        private_poi,
        records: &records,
        forced_txids: &forced_txids,
        force_submission_retry,
        now,
    };
    let mut state = PendingOutputPoiSubmissionPassState::default();
    let order = private_poi.submission_order_by_key(records.iter().collect::<Vec<_>>(), |record| {
        record.railgun_txid
    });
    for record in order {
        if state.deferred_txids.contains(&record.railgun_txid) {
            continue;
        }
        if state
            .route
            .as_ref()
            .is_some_and(|current| current.railgun_txid() != record.railgun_txid)
        {
            state.route = None;
        }
        // A forced submission deferred by an earlier pass is still forced the same way.
        let step =
            if forced_txids.get(&record.railgun_txid) == Some(&DeferredForceKind::ForceMatching) {
                pass.resubmit_forced(&mut state, record).await
            } else {
                pass.submit_record(&mut state, record).await?
            };
        if step.is_break() {
            break;
        }
    }
    Ok(state.submitted_contexts)
}

/// The pass's route for `record`'s transaction, reserved on its first
/// transact proof and reused by its later records. `None` when deferred.
async fn transact_proof_route<'a>(
    private_poi: &WalletPrivatePoiClients,
    route: &'a mut Option<TransactProofRoute>,
    chain_id: u64,
    record: &PendingOutputPoiContextRecord,
    forced: Option<DeferredForceKind>,
) -> Option<&'a TransactProofRoute> {
    if route
        .as_ref()
        .is_none_or(|current| current.railgun_txid() != record.railgun_txid)
    {
        // Drop another transaction's route before reserving this one.
        *route = None;
        *route = Some(
            private_poi
                .reserve_transact_route(chain_id, record.railgun_txid, forced)
                .await
                .ok()?,
        );
        private_poi.end_forced_deferral(record.railgun_txid);
    }
    route.as_ref()
}

async fn submit_pending_output_poi_context_via_gateway(
    authority: &WalletPrivateMutationAuthority<'_>,
    public_data_plane: &ChainPublicDataPlane,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    subject: &PendingOutputPoiSubject,
    plan: &PendingOutputPoiSubmissionPlan,
    private_poi: &WalletPrivatePoiClients,
    chain_id: u64,
    record: &PendingOutputPoiContextRecord,
    context: SingleCommitmentProofContext,
    observation: &PendingOutputPoiObservation,
    submitted_list_keys: &[FixedBytes<32>],
    route: &mut Option<TransactProofRoute>,
) -> Result<PendingOutputPoiRemoteAttempt, WalletCacheError> {
    if let Some(txid_merkleroot_index) = record.txid_merkleroot_index {
        let Some(route) = transact_proof_route(
            private_poi,
            route,
            chain_id,
            record,
            plan.deferred_force_kind(),
        )
        .await
        else {
            return Ok(PendingOutputPoiRemoteAttempt::Deferred);
        };
        for list_key in submitted_list_keys {
            let Some(per_leaf) = context
                .pre_transaction_pois_per_txid_leaf_per_list
                .get(list_key)
            else {
                continue;
            };
            for poi in per_leaf.values() {
                let result = private_poi
                    .submit_transact_proof(
                        route,
                        || async {
                            Ok(matches!(
                                pending_output_poi_submission_plan_current(
                                    authority,
                                    public_data_plane,
                                    cache_store,
                                    cfg,
                                    active_list_keys,
                                    record,
                                    subject,
                                    plan,
                                )
                                .await?,
                                PendingOutputPoiPreflight::Ready
                            ))
                        },
                        &record.txid_version,
                        EVM_CHAIN_TYPE,
                        chain_id,
                        list_key,
                        txid_merkleroot_index,
                        poi,
                    )
                    .await;
                match result {
                    Ok(()) => {}
                    Err(WalletPrivateRemoteError::Stale(WalletPrivateRemoteStale::Authority)) => {
                        return Ok(PendingOutputPoiRemoteAttempt::AuthorityStale);
                    }
                    Err(WalletPrivateRemoteError::Stale(WalletPrivateRemoteStale::Subject)) => {
                        return Ok(PendingOutputPoiRemoteAttempt::NotCurrent);
                    }
                    Err(WalletPrivateRemoteError::Check(error)) => return Err(error),
                    Err(WalletPrivateRemoteError::Remote(error)) => {
                        return Ok(PendingOutputPoiRemoteAttempt::Failed {
                            error: error.to_string(),
                        });
                    }
                }
            }
        }
        Ok(PendingOutputPoiRemoteAttempt::Succeeded {
            submitted_list_keys: submitted_list_keys.to_vec(),
        })
    } else {
        let result = private_poi
            .submit_single_commitment_proofs(
                || async {
                    Ok(matches!(
                        pending_output_poi_submission_plan_current(
                            authority,
                            public_data_plane,
                            cache_store,
                            cfg,
                            active_list_keys,
                            record,
                            subject,
                            plan,
                        )
                        .await?,
                        PendingOutputPoiPreflight::Ready
                    ))
                },
                plan.submit_intent(),
                &record.txid_version,
                EVM_CHAIN_TYPE,
                chain_id,
                context,
                observation.output_tree,
                observation.output_position,
            )
            .await;
        match result {
            Ok(()) => Ok(PendingOutputPoiRemoteAttempt::Succeeded {
                submitted_list_keys: submitted_list_keys.to_vec(),
            }),
            Err(WalletPrivateRemoteError::Stale(WalletPrivateRemoteStale::Authority)) => {
                Ok(PendingOutputPoiRemoteAttempt::AuthorityStale)
            }
            Err(WalletPrivateRemoteError::Stale(WalletPrivateRemoteStale::Subject)) => {
                Ok(PendingOutputPoiRemoteAttempt::NotCurrent)
            }
            Err(WalletPrivateRemoteError::Check(error)) => Err(error),
            Err(WalletPrivateRemoteError::Remote(failure)) => {
                Ok(PendingOutputPoiRemoteAttempt::Failed {
                    error: failure.summary,
                })
            }
        }
    }
}

pub(super) fn new_pending_output_poi_recovery_record(
    chain_id: u64,
    record: &PendingOutputPoiContextRecord,
    observation: &PendingOutputPoiObservation,
    status: OutputPoiRecoveryStatus,
    now: u64,
) -> OutputPoiRecoveryRecord {
    OutputPoiRecoveryRecord {
        chain_id,
        wallet_id: record.wallet_id.clone(),
        output_commitment: record.output_commitment,
        source_tx_hash: observation.tx_hash,
        tx_input: None,
        status,
        created_at: now,
        updated_at: now,
        last_detection_at: None,
        last_submission_at: None,
        next_retry_at: None,
        attempt_count: 0,
        last_error: None,
    }
}

fn expected_poi_status_matches(
    poi: &UtxoPoiMetadata,
    list_keys: &[FixedBytes<32>],
    expected: ExpectedPoiStatus,
) -> bool {
    match expected {
        ExpectedPoiStatus::Recoverable => poi_statuses_are_recoverable_for_lists(poi, list_keys),
        ExpectedPoiStatus::Valid => poi.is_valid_for_lists(list_keys),
    }
}

fn poi_statuses_are_recoverable_for_lists(
    poi: &UtxoPoiMetadata,
    list_keys: &[FixedBytes<32>],
) -> bool {
    list_keys.iter().all(|list_key| {
        poi.statuses
            .get(list_key)
            .is_none_or(|status| status.is_recoverable())
    })
}

fn sender_materialization_pending_matches(
    current: &PendingOutputPoiContextRecord,
    expected: &PendingOutputPoiContextRecord,
) -> bool {
    let mut normalized = current.clone();
    normalized
        .submitted_poi_list_keys
        .clone_from(&expected.submitted_poi_list_keys);
    normalized
        .terminal_error
        .clone_from(&expected.terminal_error);
    pending_output_poi_context_fingerprint(&normalized)
        == pending_output_poi_context_fingerprint(expected)
}

fn sender_materialization_recovery_matches(
    current: &OutputPoiRecoveryRecord,
    expected: &OutputPoiRecoveryRecord,
) -> bool {
    let mut normalized = current.clone();
    normalized.status = expected.status;
    normalized.attempt_count = expected.attempt_count;
    normalized.last_error.clone_from(&expected.last_error);
    normalized.last_submission_at = expected.last_submission_at;
    normalized.next_retry_at = expected.next_retry_at;
    output_poi_recovery_fingerprint(&normalized) == output_poi_recovery_fingerprint(expected)
}

fn expected_pending_context_matches(
    expected: &ExpectedRecordState,
    current: Option<&PendingOutputPoiContextRecord>,
) -> bool {
    match (expected, current) {
        (ExpectedRecordState::Absent, None) => true,
        (ExpectedRecordState::Present(expected), Some(current)) => {
            pending_output_poi_context_fingerprint(current).as_ref() == Some(expected)
        }
        _ => false,
    }
}

fn expected_recovery_matches(
    expected: &ExpectedRecordState,
    current: Option<&OutputPoiRecoveryRecord>,
) -> bool {
    match (expected, current) {
        (ExpectedRecordState::Absent, None) => true,
        (ExpectedRecordState::Present(expected), Some(current)) => {
            output_poi_recovery_fingerprint(current).as_ref() == Some(expected)
        }
        _ => false,
    }
}

fn pending_submission_predicate_matches(
    context: &PendingOutputPoiContextRecord,
    list_keys: &[FixedBytes<32>],
    predicate: PendingOutputPoiSubmissionPredicate,
) -> bool {
    let context_list_keys = context.list_keys();
    match predicate {
        PendingOutputPoiSubmissionPredicate::Missing => {
            let missing = context.missing_list_keys();
            list_keys.iter().all(|list_key| missing.contains(list_key))
        }
        PendingOutputPoiSubmissionPredicate::RetrySubmitted => list_keys.iter().all(|list_key| {
            context_list_keys.contains(list_key)
                && context.submitted_poi_list_keys.contains(list_key)
        }),
        PendingOutputPoiSubmissionPredicate::ForceMatching => list_keys
            .iter()
            .all(|list_key| context_list_keys.contains(list_key)),
    }
}

fn prune_nonrecoverable_unsubmitted_poi_lists(
    context: &mut PendingOutputPoiContextRecord,
    poi: &UtxoPoiMetadata,
    active_list_keys: &[FixedBytes<32>],
) {
    let submitted_poi_list_keys = context.submitted_poi_list_keys.clone();
    let should_retain = |list_key: &FixedBytes<32>| {
        submitted_poi_list_keys.contains(list_key)
            || !active_list_keys.contains(list_key)
            || poi
                .statuses
                .get(list_key)
                .is_none_or(|status| status.is_recoverable())
    };
    context.required_poi_list_keys.retain(&should_retain);
    context
        .pre_transaction_pois_per_txid_leaf_per_list
        .retain(|list_key, _| should_retain(list_key));
}

pub(super) const fn output_poi_recovery_default_status(
    action: &OutputPoiRecoveryAction,
) -> OutputPoiRecoveryStatus {
    match action {
        OutputPoiRecoveryAction::Detected { status, .. } => *status,
        OutputPoiRecoveryAction::CacheTxInput { .. } | OutputPoiRecoveryAction::ExtendContext => {
            OutputPoiRecoveryStatus::Recoverable
        }
        OutputPoiRecoveryAction::Submitted { .. } => OutputPoiRecoveryStatus::Submitted,
        OutputPoiRecoveryAction::SubmitFailed { .. } => OutputPoiRecoveryStatus::SubmitFailed,
        OutputPoiRecoveryAction::Valid => OutputPoiRecoveryStatus::Valid,
    }
}

/// Route private POI durable writes: jobs re-enter the actor; tests/inline use short permit.
///
/// Invariant: only the wallet actor turn mutates private UTXO mirrors. Jobs must attach
/// [`WalletPrivateApplyClient`] via [`WalletPrivateMutationAuthority::with_apply_client`].
pub(super) async fn apply_poi_private_delta(
    authority: &WalletPrivateMutationAuthority<'_>,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    delta: OwnedPoiPrivateDelta,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    if let Some(client) = authority.apply_client() {
        return client.apply(authority.reset_generation(), delta).await;
    }
    let active_list_keys = default_active_poi_list_keys();
    apply_poi_private_delta_inline(authority, db, cache_store, cfg, &active_list_keys, delta).await
}

/// Actor-turn apply of an owned POI delta (sole private writer path).
#[cfg(test)]
pub(super) async fn apply_owned_poi_private_delta_on_actor(
    handle: &WalletHandle,
    cancel: &CancellationToken,
    reset_generation: u64,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    delta: OwnedPoiPrivateDelta,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    let authority = WalletPrivateMutationAuthority::new(handle, reset_generation, cancel);
    let active_list_keys = default_active_poi_list_keys();
    apply_poi_private_delta_inline(&authority, db, cache_store, cfg, &active_list_keys, delta).await
}

/// Actor-turn apply using the actor's current active-list configuration.
pub(super) async fn apply_owned_poi_private_delta_on_actor_with_active_lists(
    handle: &WalletHandle,
    cancel: &CancellationToken,
    reset_generation: u64,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    delta: OwnedPoiPrivateDelta,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    let authority = WalletPrivateMutationAuthority::new(handle, reset_generation, cancel);
    apply_poi_private_delta_inline(&authority, db, cache_store, cfg, active_list_keys, delta).await
}

/// Holds the chain POI corpus read fence for a commit that consumes a local proof.
///
/// Call after the mutation permit and any public-data commit guard, and keep the returned guard
/// through the durable commit. Returns the stale outcome, with the fence released, when the
/// corpus revision changed after the proof source was read. A commit without an expected
/// revision takes no corpus fence.
async fn hold_expected_poi_corpus_revision(
    expected: Option<&ExpectedPoiCorpusRevision>,
) -> Result<Option<tokio::sync::OwnedRwLockReadGuard<()>>, PoiPrivateApplyOutcome> {
    let Some(expected) = expected else {
        return Ok(None);
    };
    let revision_fence = expected.corpus.revision_read_fence().await;
    if *expected.corpus.committed_revision_rx().borrow() != expected.revision {
        return Err(PoiPrivateApplyOutcome::SkippedStaleCorpusRevision);
    }
    Ok(Some(revision_fence))
}

pub(super) struct PendingOutputPoiSubmitIdentity {
    pub(super) derived_blinded_commitment: FixedBytes<32>,
}

pub(super) fn pending_output_poi_submit_identity(
    record: &PendingOutputPoiContextRecord,
    observation: &PendingOutputPoiObservation,
) -> Option<PendingOutputPoiSubmitIdentity> {
    let output_tree = u32::try_from(observation.output_tree).ok()?;
    record.txid_leaf_hash()?;
    Some(PendingOutputPoiSubmitIdentity {
        derived_blinded_commitment: UtxoPoiMetadata::blinded_commitment_for(
            record.output_commitment,
            record.output_npk,
            output_tree,
            observation.output_position,
        ),
    })
}

pub(super) fn pending_output_poi_context_matches_wallet_utxo(
    cfg: &WalletConfig,
    wallet_utxo: &WalletUtxo,
    record: &PendingOutputPoiContextRecord,
) -> bool {
    if record.chain_id != cfg.chain.chain_id
        || record.wallet_id != cfg.cache_key.as_str()
        || record.output_commitment != wallet_utxo.utxo.poi.commitment
    {
        return false;
    }
    let Some(observation) = record.observation.as_ref() else {
        return false;
    };
    if observation.output_tree != u64::from(wallet_utxo.utxo.tree)
        || observation.output_position != wallet_utxo.utxo.position
        || observation.tx_hash != wallet_utxo.utxo.source.tx_hash
    {
        return false;
    }
    pending_output_poi_submit_identity(record, observation).is_some_and(|identity| {
        identity.derived_blinded_commitment == wallet_utxo.utxo.poi.blinded_commitment
    })
}

enum PendingOutputPoiSubjectMatch {
    Owned(Box<WalletUtxo>),
    External,
}

impl PendingOutputPoiSubjectMatch {
    const fn poi(&self) -> Option<&UtxoPoiMetadata> {
        match self {
            Self::Owned(output) => Some(&output.utxo.poi),
            Self::External => None,
        }
    }
}

fn pending_output_poi_subject_matches_snapshot(
    cfg: &WalletConfig,
    snapshot: &[WalletUtxo],
    record: &PendingOutputPoiContextRecord,
    subject: &PendingOutputPoiSubject,
) -> Option<PendingOutputPoiSubjectMatch> {
    if record.chain_id != cfg.chain.chain_id || record.wallet_id != cfg.cache_key.as_str() {
        return None;
    }
    let observation = record.observation.as_ref()?;
    let identity = pending_output_poi_submit_identity(record, observation)?;
    match subject {
        PendingOutputPoiSubject::Owned(expected_output) => snapshot
            .iter()
            .find(|output| {
                expected_output.matches(output)
                    && pending_output_poi_context_matches_wallet_utxo(cfg, output, record)
            })
            .cloned()
            .map(Box::new)
            .map(PendingOutputPoiSubjectMatch::Owned),
        PendingOutputPoiSubject::External {
            output_commitment,
            derived_blinded_commitment,
        } => {
            if !matches!(
                record.output_role,
                PendingOutputPoiRole::Recipient
                    | PendingOutputPoiRole::BroadcasterFee
                    | PendingOutputPoiRole::RecoveredOutgoing
            ) || record.output_commitment != *output_commitment
                || identity.derived_blinded_commitment != *derived_blinded_commitment
                || snapshot.iter().any(|output| {
                    !output.is_spent() && output.utxo.poi.commitment == record.output_commitment
                })
            {
                return None;
            }
            Some(PendingOutputPoiSubjectMatch::External)
        }
    }
}

pub(super) async fn current_pending_output_poi_subject(
    authority: &WalletPrivateMutationAuthority<'_>,
    cfg: &WalletConfig,
    record: &PendingOutputPoiContextRecord,
) -> Option<(PendingOutputPoiSubject, Option<WalletUtxo>)> {
    if authority.revalidate().is_err()
        || authority.chain_id() != cfg.chain.chain_id
        || authority.wallet_id() != &cfg.cache_key
        || record.chain_id != cfg.chain.chain_id
        || record.wallet_id != cfg.cache_key.as_str()
    {
        return None;
    }
    let observation = record.observation.as_ref()?;
    let identity = pending_output_poi_submit_identity(record, observation)?;
    let snapshot = authority.wallet_utxos().await.ok()?;
    let matching_output = snapshot.iter().find(|output| {
        !output.is_spent() && pending_output_poi_context_matches_wallet_utxo(cfg, output, record)
    });
    let result = if let Some(output) = matching_output {
        (
            PendingOutputPoiSubject::Owned(ExpectedWalletOutput::new(output)),
            Some(output.clone()),
        )
    } else {
        if !matches!(
            record.output_role,
            PendingOutputPoiRole::Recipient
                | PendingOutputPoiRole::BroadcasterFee
                | PendingOutputPoiRole::RecoveredOutgoing
        ) || snapshot.iter().any(|output| {
            !output.is_spent() && output.utxo.poi.commitment == record.output_commitment
        }) {
            return None;
        }
        (
            PendingOutputPoiSubject::External {
                output_commitment: record.output_commitment,
                derived_blinded_commitment: identity.derived_blinded_commitment,
            },
            None,
        )
    };
    authority.revalidate().is_ok().then_some(result)
}

/// Sole preflight gate before remote pending-output POI disclosure.
pub(super) async fn pending_output_poi_submission_plan_current(
    authority: &WalletPrivateMutationAuthority<'_>,
    public_data_plane: &ChainPublicDataPlane,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    expected: &PendingOutputPoiContextRecord,
    subject: &PendingOutputPoiSubject,
    plan: &PendingOutputPoiSubmissionPlan,
) -> Result<PendingOutputPoiPreflight, WalletCacheError> {
    if authority.revalidate().is_err() {
        debug!(
            chain_id = cfg.chain.chain_id,
            "pending output POI submission skipped before plan validation"
        );
        return Ok(PendingOutputPoiPreflight::AuthorityStale);
    }
    if authority.chain_id() != cfg.chain.chain_id
        || authority.wallet_id() != &cfg.cache_key
        || !saved_pending_context_matches_public_transaction(
            public_data_plane,
            cfg,
            expected,
            &plan.list_keys,
        )
    {
        return Ok(PendingOutputPoiPreflight::NotCurrent);
    }
    let Some(current) = cache_store.get_pending_output_poi_context(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &expected.output_commitment,
    )?
    else {
        return Ok(PendingOutputPoiPreflight::NotCurrent);
    };
    if pending_output_poi_context_fingerprint(&current)
        != pending_output_poi_context_fingerprint(expected)
    {
        debug!(
            chain_id = cfg.chain.chain_id,
            "pending output POI submission skipped; context changed"
        );
        return Ok(PendingOutputPoiPreflight::NotCurrent);
    }
    if plan.list_keys.is_empty()
        || plan
            .list_keys
            .iter()
            .any(|list_key| !active_list_keys.contains(list_key))
    {
        return Ok(PendingOutputPoiPreflight::NotCurrent);
    }
    let current_recovery = cache_store.get_output_poi_recovery(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &expected.output_commitment,
    )?;
    if !expected_recovery_matches(&plan.expected_recovery, current_recovery.as_ref()) {
        debug!(
            chain_id = cfg.chain.chain_id,
            "pending output POI submission skipped; recovery predecessor changed"
        );
        return Ok(PendingOutputPoiPreflight::NotCurrent);
    }
    let Some(current_observation) = current.observation.as_ref() else {
        return Ok(PendingOutputPoiPreflight::NotCurrent);
    };
    if current_recovery
        .as_ref()
        .is_some_and(|recovery| recovery.source_tx_hash != current_observation.tx_hash)
    {
        debug!(
            chain_id = cfg.chain.chain_id,
            "pending output POI submission skipped; recovery source transaction does not match context observation"
        );
        return Ok(PendingOutputPoiPreflight::NotCurrent);
    }
    match plan.kind {
        PendingOutputPoiSubmissionKind::Missing => {
            let mut current_missing = current.missing_list_keys();
            current_missing.retain(|list_key| active_list_keys.contains(list_key));
            if plan
                .list_keys
                .iter()
                .any(|list_key| !current_missing.contains(list_key))
            {
                debug!(
                    chain_id = cfg.chain.chain_id,
                    "pending output POI submission skipped; missing-list state changed"
                );
                return Ok(PendingOutputPoiPreflight::NotCurrent);
            }
        }
        PendingOutputPoiSubmissionKind::RetrySubmitted => {
            let current_list_keys = current.list_keys();
            if plan.list_keys.iter().any(|list_key| {
                !current_list_keys.contains(list_key)
                    || !current.submitted_poi_list_keys.contains(list_key)
            }) {
                debug!(
                    chain_id = cfg.chain.chain_id,
                    "pending output POI retry skipped; submitted-list state changed"
                );
                return Ok(PendingOutputPoiPreflight::NotCurrent);
            }
            if !current_recovery.as_ref().is_some_and(|record| {
                record.submission_retry_allowed(now_epoch_secs(), plan.force_submission_retry)
            }) {
                debug!(
                    chain_id = cfg.chain.chain_id,
                    "pending output POI retry skipped; recovery state changed"
                );
                return Ok(PendingOutputPoiPreflight::NotCurrent);
            }
        }
        PendingOutputPoiSubmissionKind::ForceMatching => {
            let current_list_keys = current.list_keys();
            if plan
                .list_keys
                .iter()
                .any(|list_key| !current_list_keys.contains(list_key))
            {
                debug!(
                    chain_id = cfg.chain.chain_id,
                    "forced pending output POI skipped; list keys no longer on context"
                );
                return Ok(PendingOutputPoiPreflight::NotCurrent);
            }
        }
    }
    let Ok(snapshot) = authority.wallet_utxos().await else {
        debug!(
            chain_id = cfg.chain.chain_id,
            "pending output POI submission skipped before wallet state check"
        );
        return Ok(if authority.revalidate().is_err() {
            PendingOutputPoiPreflight::AuthorityStale
        } else {
            PendingOutputPoiPreflight::NotCurrent
        });
    };
    let Some(subject_match) =
        pending_output_poi_subject_matches_snapshot(cfg, &snapshot, &current, subject)
    else {
        debug!(
            chain_id = cfg.chain.chain_id,
            "pending output POI submission skipped; subject no longer matches wallet state"
        );
        return Ok(PendingOutputPoiPreflight::NotCurrent);
    };
    let current_recoverable_list_keys = recoverable_pending_submission_list_keys(
        &current,
        active_list_keys,
        subject_match.poi(),
        plan.predicate(),
    );
    if current_recoverable_list_keys != plan.list_keys {
        debug!(
            chain_id = cfg.chain.chain_id,
            planned_poi_lists = plan.list_keys.len(),
            current_recoverable_poi_lists = current_recoverable_list_keys.len(),
            "pending output POI submission skipped; recoverable target-list subset changed"
        );
        return Ok(PendingOutputPoiPreflight::NotCurrent);
    }
    let Some(postflight_context) = cache_store.get_pending_output_poi_context(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &expected.output_commitment,
    )?
    else {
        return Ok(PendingOutputPoiPreflight::NotCurrent);
    };
    let postflight_recovery = cache_store.get_output_poi_recovery(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &expected.output_commitment,
    )?;
    let Some(final_context) = cache_store.get_pending_output_poi_context(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &expected.output_commitment,
    )?
    else {
        return Ok(PendingOutputPoiPreflight::NotCurrent);
    };
    if pending_output_poi_context_fingerprint(&postflight_context)
        != pending_output_poi_context_fingerprint(expected)
        || pending_output_poi_context_fingerprint(&final_context)
            != pending_output_poi_context_fingerprint(expected)
        || !expected_recovery_matches(&plan.expected_recovery, postflight_recovery.as_ref())
        || postflight_recovery.as_ref().is_some_and(|recovery| {
            final_context
                .observation
                .as_ref()
                .is_none_or(|observation| recovery.source_tx_hash != observation.tx_hash)
        })
    {
        return Ok(PendingOutputPoiPreflight::NotCurrent);
    }
    if authority.revalidate().is_err() {
        debug!(
            chain_id = cfg.chain.chain_id,
            "pending output POI submission skipped after plan validation"
        );
        return Ok(PendingOutputPoiPreflight::AuthorityStale);
    }
    Ok(PendingOutputPoiPreflight::Ready)
}

impl PendingOutputPoiSubmissionPass<'_> {
    async fn pending_output_poi_submission_side_effect_current(
        &self,
        expected: &PendingOutputPoiContextRecord,
        subject: &PendingOutputPoiSubject,
        plan: &PendingOutputPoiSubmissionPlan,
    ) -> Result<bool, WalletCacheError> {
        let Self {
            authority,
            public_data_plane,
            cache_store,
            cfg,
            active_list_keys,
            ..
        } = *self;
        Ok(matches!(
            pending_output_poi_submission_plan_current(
                authority,
                public_data_plane,
                cache_store,
                cfg,
                active_list_keys,
                expected,
                subject,
                plan,
            )
            .await?,
            PendingOutputPoiPreflight::Ready
        ))
    }
}

/// Sole production choke point for remote pending-output POI submission:
/// preflight → build context → remote await. Durable apply remains caller's postflight.
pub(super) async fn preflight_and_remote_submit_pending_output_poi(
    authority: &WalletPrivateMutationAuthority<'_>,
    public_data_plane: &ChainPublicDataPlane,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    record: &PendingOutputPoiContextRecord,
    observation: &PendingOutputPoiObservation,
    subject: &PendingOutputPoiSubject,
    plan: &PendingOutputPoiSubmissionPlan,
    private_poi: &WalletPrivatePoiClients,
    route: &mut Option<TransactProofRoute>,
) -> Result<PendingOutputPoiRemoteAttempt, WalletCacheError> {
    if record.observation.as_ref() != Some(observation)
        || !saved_pending_context_matches_public_transaction(
            public_data_plane,
            cfg,
            record,
            &plan.list_keys,
        )
    {
        return Ok(PendingOutputPoiRemoteAttempt::NotCurrent);
    }
    match pending_output_poi_submission_plan_current(
        authority,
        public_data_plane,
        cache_store,
        cfg,
        active_list_keys,
        record,
        subject,
        plan,
    )
    .await?
    {
        PendingOutputPoiPreflight::Ready => {}
        PendingOutputPoiPreflight::NotCurrent => {
            return Ok(PendingOutputPoiRemoteAttempt::NotCurrent);
        }
        PendingOutputPoiPreflight::AuthorityStale => {
            return Ok(PendingOutputPoiRemoteAttempt::AuthorityStale);
        }
    }

    let pre_transaction_pois = record.retain_poi_lists(&plan.list_keys);
    if pre_transaction_pois.len() != plan.list_keys.len() {
        return Ok(PendingOutputPoiRemoteAttempt::MissingPreTransactionPois);
    }
    if pending_output_poi_submit_identity(record, observation).is_none() {
        warn!(
            chain_id = cfg.chain.chain_id,
            "pending output POI context has invalid output tree"
        );
        return Ok(PendingOutputPoiRemoteAttempt::NotCurrent);
    }
    let context = SingleCommitmentProofContext {
        txid_version: record.txid_version.clone(),
        railgun_txid: record.railgun_txid,
        utxo_tree_in: record.utxo_tree_in,
        commitment: record.output_commitment,
        npk: record.output_npk,
        pre_transaction_pois_per_txid_leaf_per_list: pre_transaction_pois,
    };
    let submitted_list_keys = plan.list_keys.clone();
    debug!(
        chain_id = cfg.chain.chain_id,
        pre_tx_poi_lists = context.pre_transaction_pois_per_txid_leaf_per_list.len(),
        plan_kind = ?plan.kind,
        "submitting pending output POI context"
    );
    submit_pending_output_poi_context_via_gateway(
        authority,
        public_data_plane,
        cache_store,
        cfg,
        active_list_keys,
        subject,
        plan,
        private_poi,
        cfg.chain.chain_id,
        record,
        context,
        observation,
        &submitted_list_keys,
        route,
    )
    .await
}

pub(super) fn pending_output_poi_context_fingerprint(
    record: &PendingOutputPoiContextRecord,
) -> Option<Vec<u8>> {
    rmp_serde::to_vec(record).ok()
}

fn output_poi_recovery_fingerprint(record: &OutputPoiRecoveryRecord) -> Option<Vec<u8>> {
    rmp_serde::to_vec(record).ok()
}

pub(super) fn expected_pending_context_state(
    record: Option<&PendingOutputPoiContextRecord>,
) -> Option<ExpectedRecordState> {
    match record {
        Some(record) => {
            pending_output_poi_context_fingerprint(record).map(ExpectedRecordState::Present)
        }
        None => Some(ExpectedRecordState::Absent),
    }
}

pub(super) fn expected_recovery_state(
    record: Option<&OutputPoiRecoveryRecord>,
) -> Option<ExpectedRecordState> {
    match record {
        Some(record) => output_poi_recovery_fingerprint(record).map(ExpectedRecordState::Present),
        None => Some(ExpectedRecordState::Absent),
    }
}

#[cfg(test)]
pub(super) mod test_support;
