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
    Some(single_commitment_proof_context(
        record,
        pre_transaction_pois,
    ))
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

impl PendingOutputPoiSubmissionPlan {
    const fn new(
        predicate: PendingOutputPoiSubmissionPredicate,
        list_keys: Vec<FixedBytes<32>>,
        expected_recovery: ExpectedRecordState,
        force_submission_retry: bool,
    ) -> Self {
        Self {
            predicate,
            list_keys,
            expected_recovery,
            force_submission_retry,
        }
    }

    const fn missing(
        list_keys: Vec<FixedBytes<32>>,
        expected_recovery: ExpectedRecordState,
    ) -> Self {
        Self::new(
            PendingOutputPoiSubmissionPredicate::Missing,
            list_keys,
            expected_recovery,
            false,
        )
    }

    const fn retry_submitted(
        list_keys: Vec<FixedBytes<32>>,
        expected_recovery: ExpectedRecordState,
        force_submission_retry: bool,
    ) -> Self {
        Self::new(
            PendingOutputPoiSubmissionPredicate::RetrySubmitted,
            list_keys,
            expected_recovery,
            force_submission_retry,
        )
    }

    /// Force-resubmit plan: active list keys already on the context (submitted or not).
    pub(super) const fn force_matching(
        list_keys: Vec<FixedBytes<32>>,
        expected_recovery: ExpectedRecordState,
    ) -> Self {
        Self::new(
            PendingOutputPoiSubmissionPredicate::ForceMatching,
            list_keys,
            expected_recovery,
            true,
        )
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
        self.predicate
    }

    const fn submit_intent(&self) -> PendingOutputPoiSubmitIntent {
        match self.predicate {
            PendingOutputPoiSubmissionPredicate::Missing => PendingOutputPoiSubmitIntent::Missing,
            PendingOutputPoiSubmissionPredicate::RetrySubmitted => {
                PendingOutputPoiSubmitIntent::RetrySubmitted
            }
            PendingOutputPoiSubmissionPredicate::ForceMatching => {
                PendingOutputPoiSubmitIntent::ForceMatching
            }
        }
    }

    /// How a deferral of this plan stays forced for later passes, if at all.
    const fn deferred_force_kind(&self) -> Option<DeferredForceKind> {
        if matches!(
            self.predicate,
            PendingOutputPoiSubmissionPredicate::ForceMatching
        ) {
            Some(DeferredForceKind::ForceMatching)
        } else if self.force_submission_retry {
            Some(DeferredForceKind::RetrySubmitted)
        } else {
            None
        }
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

    async fn submit_standard(
        &self,
        state: &mut PendingOutputPoiSubmissionPassState,
        record: &PendingOutputPoiContextRecord,
    ) -> Result<ControlFlow<()>, WalletCacheError> {
        let Some(observation) = record.observation.as_ref() else {
            return Ok(ControlFlow::Continue(()));
        };
        let recovery = self.cache_store.get_output_poi_recovery(
            self.cfg.chain.chain_id,
            &self.cfg.cache_key,
            &record.output_commitment,
        )?;
        let Some(expected_recovery) = expected_recovery_state(recovery.as_ref()) else {
            return Ok(ControlFlow::Continue(()));
        };
        let Some((subject, plan)) = self
            .due_standard_plan(record, recovery.as_ref(), expected_recovery)
            .await
        else {
            return Ok(ControlFlow::Continue(()));
        };
        let Some(expected_context_fingerprint) = pending_output_poi_context_fingerprint(record)
        else {
            return Ok(ControlFlow::Continue(()));
        };
        let remote_attempt = preflight_and_remote_submit_pending_output_poi(
            &self.preflight(record, &subject, &plan),
            observation,
            self.private_poi,
            &mut state.route,
        )
        .await?;
        StandardAttempt {
            pass: self,
            record,
            subject,
            plan,
            expected_context_fingerprint,
        }
        .record(state, remote_attempt)
        .await
    }

    /// The record's current subject and its due plan: its missing lists or,
    /// when none is recoverable and the recovery allows a retry, its submitted
    /// ones. `None` when nothing is due.
    async fn due_standard_plan(
        &self,
        record: &PendingOutputPoiContextRecord,
        recovery: Option<&OutputPoiRecoveryRecord>,
        expected_recovery: ExpectedRecordState,
    ) -> Option<(PendingOutputPoiSubject, PendingOutputPoiSubmissionPlan)> {
        let force_submission_retry = self.force_retry(record);
        let (subject, current_output) =
            current_pending_output_poi_subject(self.authority, self.cfg, record).await?;
        let poi = current_output.as_ref().map(|output| &output.utxo.poi);
        let mut plan =
            PendingOutputPoiSubmissionPlan::missing(record.missing_list_keys(), expected_recovery);
        plan.retain_current_recoverable(record, self.active_list_keys, poi);
        if plan.list_keys.is_empty()
            && recovery.is_some_and(|recovery| {
                recovery.submission_retry_allowed(self.now, force_submission_retry)
            })
        {
            plan = PendingOutputPoiSubmissionPlan::retry_submitted(
                record.list_keys(),
                plan.expected_recovery.clone(),
                force_submission_retry,
            );
            plan.retain_current_recoverable(record, self.active_list_keys, poi);
        }
        if plan.list_keys.is_empty() {
            return None;
        }
        debug!(
            chain_id = self.cfg.chain.chain_id,
            force_submission_retry,
            retry_submitted = matches!(
                plan.predicate,
                PendingOutputPoiSubmissionPredicate::RetrySubmitted
            ),
            "pending output POI submission due"
        );
        Some((subject, plan))
    }
}

/// A standard submission's subject and plan, recorded through its pass.
struct StandardAttempt<'a> {
    pass: &'a PendingOutputPoiSubmissionPass<'a>,
    record: &'a PendingOutputPoiContextRecord,
    subject: PendingOutputPoiSubject,
    plan: PendingOutputPoiSubmissionPlan,
    expected_context_fingerprint: Vec<u8>,
}

impl StandardAttempt<'_> {
    /// Records the remote attempt's outcome while the plan is still current,
    /// and says whether the pass goes on.
    async fn record(
        self,
        state: &mut PendingOutputPoiSubmissionPassState,
        remote_attempt: PendingOutputPoiRemoteAttempt,
    ) -> Result<ControlFlow<()>, WalletCacheError> {
        let (list_keys, action, submitted) = match remote_attempt {
            PendingOutputPoiRemoteAttempt::NotCurrent => return Ok(ControlFlow::Continue(())),
            PendingOutputPoiRemoteAttempt::Deferred => {
                state.deferred_txids.insert(self.record.railgun_txid);
                return Ok(ControlFlow::Continue(()));
            }
            PendingOutputPoiRemoteAttempt::AuthorityStale => return Ok(ControlFlow::Break(())),
            PendingOutputPoiRemoteAttempt::MissingPreTransactionPois => {
                self.mark_terminal().await;
                return Ok(ControlFlow::Continue(()));
            }
            PendingOutputPoiRemoteAttempt::Succeeded {
                submitted_list_keys,
            } => (
                submitted_list_keys,
                OutputPoiRecoveryAction::Submitted {
                    retry_after: PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER,
                },
                true,
            ),
            PendingOutputPoiRemoteAttempt::Failed { error } => (
                self.plan.list_keys.clone(),
                OutputPoiRecoveryAction::SubmitFailed {
                    error,
                    retry_after: OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
                },
                false,
            ),
        };
        if !self
            .pass
            .pending_output_poi_submission_side_effect_current(
                self.record,
                &self.subject,
                &self.plan,
            )
            .await?
        {
            return Ok(ControlFlow::Continue(()));
        }
        let chain_id = self.pass.cfg.chain.chain_id;
        let applied = self.persist_submission(list_keys, action, submitted).await;
        if applied && submitted {
            state.submitted_contexts += 1;
        }
        if !submitted {
            warn!(
                chain_id,
                "pending output POI submission failed; keeping context retryable"
            );
        }
        Ok(ControlFlow::Continue(()))
    }

    /// Marks the pending context terminal because its pre-transaction POIs are missing.
    async fn mark_terminal(self) {
        let pass = self.pass;
        if apply_poi_private_delta(
            pass.authority,
            pass.db,
            pass.cache_store,
            pass.cfg,
            OwnedPoiPrivateDelta::PendingContextTerminal(PendingContextTerminalDelta {
                subject: self.subject,
                expected_context_fingerprint: self.expected_context_fingerprint,
                expected_recovery: self.plan.expected_recovery,
                active_list_keys: pass.active_list_keys.to_vec(),
                target_list_keys: self.plan.list_keys,
                error: "missing pre-transaction POI for pending output".to_string(),
            }),
        )
        .await
        .is_err()
        {
            warn!(
                chain_id = pass.cfg.chain.chain_id,
                "failed to atomically persist pending output POI terminal state"
            );
        }
    }

    /// Persists the submission result and returns whether it was applied;
    /// submitted list keys are merged only on success.
    async fn persist_submission(
        self,
        list_keys: Vec<FixedBytes<32>>,
        action: OutputPoiRecoveryAction,
        submitted: bool,
    ) -> bool {
        let pass = self.pass;
        let predicate = self.plan.predicate();
        match apply_poi_private_delta(
            pass.authority,
            pass.db,
            pass.cache_store,
            pass.cfg,
            OwnedPoiPrivateDelta::PendingSubmission(PendingSubmissionDelta {
                subject: self.subject,
                expected_context_fingerprint: self.expected_context_fingerprint,
                expected_recovery: self.plan.expected_recovery,
                active_list_keys: pass.active_list_keys.to_vec(),
                list_keys,
                predicate,
                merge_submitted_list_keys: submitted,
                action,
                now: pass.now,
            }),
        )
        .await
        {
            Ok(PoiPrivateApplyOutcome::Applied { .. }) => true,
            Ok(
                PoiPrivateApplyOutcome::Skipped
                | PoiPrivateApplyOutcome::SkippedStaleCorpusRevision,
            ) => false,
            Err(_) if submitted => {
                warn!(
                    chain_id = pass.cfg.chain.chain_id,
                    "failed to atomically persist pending output POI submitted state"
                );
                false
            }
            Err(_) => {
                warn!(
                    chain_id = pass.cfg.chain.chain_id,
                    "failed to atomically persist pending output POI submit-failure state"
                );
                false
            }
        }
    }
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

/// One pending output context's proofs on their way to the POI gateway; the
/// preflight re-checks each send.
struct GatewaySubmission<'a> {
    preflight: &'a PendingOutputPoiSubmissionPreflight<'a>,
    private_poi: &'a WalletPrivatePoiClients,
    observation: &'a PendingOutputPoiObservation,
}

impl GatewaySubmission<'_> {
    async fn submit(
        &self,
        context: SingleCommitmentProofContext,
        route: &mut Option<TransactProofRoute>,
    ) -> Result<PendingOutputPoiRemoteAttempt, WalletCacheError> {
        if let Some(txid_merkleroot_index) = self.preflight.expected.txid_merkleroot_index {
            self.submit_transact_proofs(&context, txid_merkleroot_index, route)
                .await
        } else {
            self.submit_single_commitment(context).await
        }
    }

    /// Sends each planned list's transact proofs over the transaction's route.
    async fn submit_transact_proofs(
        &self,
        context: &SingleCommitmentProofContext,
        txid_merkleroot_index: u64,
        route: &mut Option<TransactProofRoute>,
    ) -> Result<PendingOutputPoiRemoteAttempt, WalletCacheError> {
        let PendingOutputPoiSubmissionPreflight {
            cfg,
            expected: record,
            plan,
            ..
        } = *self.preflight;
        let chain_id = cfg.chain.chain_id;
        let Some(route) = transact_proof_route(
            self.private_poi,
            route,
            chain_id,
            record,
            plan.deferred_force_kind(),
        )
        .await
        else {
            return Ok(PendingOutputPoiRemoteAttempt::Deferred);
        };
        for list_key in &plan.list_keys {
            let Some(per_leaf) = context
                .pre_transaction_pois_per_txid_leaf_per_list
                .get(list_key)
            else {
                continue;
            };
            for poi in per_leaf.values() {
                let result = self
                    .private_poi
                    .submit_transact_proof(
                        route,
                        || self.preflight.ready(),
                        &record.txid_version,
                        EVM_CHAIN_TYPE,
                        chain_id,
                        list_key,
                        txid_merkleroot_index,
                        poi,
                    )
                    .await;
                if let Err(error) = result {
                    return failed_remote_attempt(error, |failure| failure.to_string());
                }
            }
        }
        Ok(PendingOutputPoiRemoteAttempt::Succeeded {
            submitted_list_keys: plan.list_keys.clone(),
        })
    }

    /// Hands the context's single-commitment proofs off to the chain submitter.
    async fn submit_single_commitment(
        &self,
        context: SingleCommitmentProofContext,
    ) -> Result<PendingOutputPoiRemoteAttempt, WalletCacheError> {
        let PendingOutputPoiSubmissionPreflight {
            cfg,
            expected: record,
            plan,
            ..
        } = *self.preflight;
        let result = self
            .private_poi
            .submit_single_commitment_proofs(
                || self.preflight.ready(),
                plan.submit_intent(),
                &record.txid_version,
                EVM_CHAIN_TYPE,
                cfg.chain.chain_id,
                context,
                self.observation.output_tree,
                self.observation.output_position,
            )
            .await;
        match result {
            Ok(()) => Ok(PendingOutputPoiRemoteAttempt::Succeeded {
                submitted_list_keys: plan.list_keys.clone(),
            }),
            Err(error) => failed_remote_attempt(error, |failure| failure.summary),
        }
    }
}

/// The attempt a failed remote submission ends as, or the preflight's store error.
fn failed_remote_attempt<E>(
    error: WalletPrivateRemoteError<E, WalletCacheError>,
    summary: impl FnOnce(E) -> String,
) -> Result<PendingOutputPoiRemoteAttempt, WalletCacheError> {
    match error {
        WalletPrivateRemoteError::Stale(WalletPrivateRemoteStale::Authority) => {
            Ok(PendingOutputPoiRemoteAttempt::AuthorityStale)
        }
        WalletPrivateRemoteError::Stale(WalletPrivateRemoteStale::Subject) => {
            Ok(PendingOutputPoiRemoteAttempt::NotCurrent)
        }
        WalletPrivateRemoteError::Check(check_error) => Err(check_error),
        WalletPrivateRemoteError::Remote(failure) => Ok(PendingOutputPoiRemoteAttempt::Failed {
            error: summary(failure),
        }),
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
    expected_record_matches(expected, current)
}

fn expected_recovery_matches(
    expected: &ExpectedRecordState,
    current: Option<&OutputPoiRecoveryRecord>,
) -> bool {
    expected_record_matches(expected, current)
}

/// Whether `current` is still the record `expected` saw: both absent, or a
/// present record whose fingerprint is unchanged.
fn expected_record_matches<T: Serialize>(
    expected: &ExpectedRecordState,
    current: Option<&T>,
) -> bool {
    match (expected, current) {
        (ExpectedRecordState::Absent, None) => true,
        (ExpectedRecordState::Present(expected), Some(current)) => {
            record_fingerprint(current).as_ref() == Some(expected)
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
    apply_owned_poi_private_delta_on_actor_with_active_lists(
        handle,
        cancel,
        reset_generation,
        db,
        cache_store,
        cfg,
        &default_active_poi_list_keys(),
        delta,
    )
    .await
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

impl PendingOutputPoiSubmissionPreflight<'_> {
    /// Whether every preflight stage still passes.
    async fn ready(&self) -> Result<bool, WalletCacheError> {
        Ok(matches!(
            self.run().await?,
            PendingOutputPoiPreflight::Ready
        ))
    }

    /// Sole preflight gate before remote pending-output POI disclosure. Runs every
    /// preflight stage in order and returns the first verdict that is not `Ready`.
    pub(super) async fn run(&self) -> Result<PendingOutputPoiPreflight, WalletCacheError> {
        if self.authority.revalidate().is_err() {
            debug!(
                chain_id = self.cfg.chain.chain_id,
                "pending output POI submission skipped before plan validation"
            );
            return Ok(PendingOutputPoiPreflight::AuthorityStale);
        }
        if !self.scope_current() {
            return Ok(PendingOutputPoiPreflight::NotCurrent);
        }
        let Some(current) = self.stored_context()? else {
            return Ok(PendingOutputPoiPreflight::NotCurrent);
        };
        if !self.plan_current(&current)? {
            return Ok(PendingOutputPoiPreflight::NotCurrent);
        }
        if let Some(verdict) = self.wallet_subject_verdict(&current).await {
            return Ok(verdict);
        }
        if !self.postflight_unchanged()? {
            return Ok(PendingOutputPoiPreflight::NotCurrent);
        }
        if self.authority.revalidate().is_err() {
            debug!(
                chain_id = self.cfg.chain.chain_id,
                "pending output POI submission skipped after plan validation"
            );
            return Ok(PendingOutputPoiPreflight::AuthorityStale);
        }
        Ok(PendingOutputPoiPreflight::Ready)
    }

    /// Whether the authority and the saved context still belong to this chain, wallet and
    /// public transaction.
    fn scope_current(&self) -> bool {
        self.authority.chain_id() == self.cfg.chain.chain_id
            && self.authority.wallet_id() == &self.cfg.cache_key
            && saved_pending_context_matches_public_transaction(
                self.public_data_plane,
                self.cfg,
                self.expected,
                &self.plan.list_keys,
            )
    }

    /// Loads the stored pending context, or `None` when it is gone or no longer matches
    /// `expected`.
    fn stored_context(&self) -> Result<Option<PendingOutputPoiContextRecord>, WalletCacheError> {
        let Some(current) = self.cache_store.get_pending_output_poi_context(
            self.cfg.chain.chain_id,
            &self.cfg.cache_key,
            &self.expected.output_commitment,
        )?
        else {
            return Ok(None);
        };
        if pending_output_poi_context_fingerprint(&current)
            != pending_output_poi_context_fingerprint(self.expected)
        {
            debug!(
                chain_id = self.cfg.chain.chain_id,
                "pending output POI submission skipped; context changed"
            );
            return Ok(None);
        }
        Ok(Some(current))
    }

    /// Whether the plan targets at least one list and only active lists.
    fn plan_lists_active(&self) -> bool {
        !self.plan.list_keys.is_empty()
            && self
                .plan
                .list_keys
                .iter()
                .all(|list_key| self.active_list_keys.contains(list_key))
    }

    /// Whether the plan still applies: its lists are active, the stored recovery record matches
    /// the plan and the context observation, and the plan kind's list state still holds.
    fn plan_current(
        &self,
        current: &PendingOutputPoiContextRecord,
    ) -> Result<bool, WalletCacheError> {
        if !self.plan_lists_active() {
            return Ok(false);
        }
        let current_recovery = self.cache_store.get_output_poi_recovery(
            self.cfg.chain.chain_id,
            &self.cfg.cache_key,
            &self.expected.output_commitment,
        )?;
        if !expected_recovery_matches(&self.plan.expected_recovery, current_recovery.as_ref()) {
            debug!(
                chain_id = self.cfg.chain.chain_id,
                "pending output POI submission skipped; recovery predecessor changed"
            );
            return Ok(false);
        }
        let Some(current_observation) = current.observation.as_ref() else {
            return Ok(false);
        };
        if current_recovery
            .as_ref()
            .is_some_and(|recovery| recovery.source_tx_hash != current_observation.tx_hash)
        {
            debug!(
                chain_id = self.cfg.chain.chain_id,
                "pending output POI submission skipped; recovery source transaction does not match context observation"
            );
            return Ok(false);
        }
        Ok(self.plan_kind_state_current(current, current_recovery.as_ref()))
    }

    /// Whether the context's list state still allows this plan kind's submission.
    fn plan_kind_state_current(
        &self,
        current: &PendingOutputPoiContextRecord,
        current_recovery: Option<&OutputPoiRecoveryRecord>,
    ) -> bool {
        let plan = self.plan;
        match plan.predicate {
            PendingOutputPoiSubmissionPredicate::Missing => {
                let mut current_missing = current.missing_list_keys();
                current_missing.retain(|list_key| self.active_list_keys.contains(list_key));
                if plan
                    .list_keys
                    .iter()
                    .any(|list_key| !current_missing.contains(list_key))
                {
                    debug!(
                        chain_id = self.cfg.chain.chain_id,
                        "pending output POI submission skipped; missing-list state changed"
                    );
                    return false;
                }
            }
            PendingOutputPoiSubmissionPredicate::RetrySubmitted => {
                let current_list_keys = current.list_keys();
                if plan.list_keys.iter().any(|list_key| {
                    !current_list_keys.contains(list_key)
                        || !current.submitted_poi_list_keys.contains(list_key)
                }) {
                    debug!(
                        chain_id = self.cfg.chain.chain_id,
                        "pending output POI retry skipped; submitted-list state changed"
                    );
                    return false;
                }
                if !current_recovery.is_some_and(|record| {
                    record.submission_retry_allowed(now_epoch_secs(), plan.force_submission_retry)
                }) {
                    debug!(
                        chain_id = self.cfg.chain.chain_id,
                        "pending output POI retry skipped; recovery state changed"
                    );
                    return false;
                }
            }
            PendingOutputPoiSubmissionPredicate::ForceMatching => {
                let current_list_keys = current.list_keys();
                if plan
                    .list_keys
                    .iter()
                    .any(|list_key| !current_list_keys.contains(list_key))
                {
                    debug!(
                        chain_id = self.cfg.chain.chain_id,
                        "forced pending output POI skipped; list keys no longer on context"
                    );
                    return false;
                }
            }
        }
        true
    }

    /// Checks the subject and its recoverable lists against the wallet snapshot. Returns the
    /// verdict to stop with, or `None` to continue.
    async fn wallet_subject_verdict(
        &self,
        current: &PendingOutputPoiContextRecord,
    ) -> Option<PendingOutputPoiPreflight> {
        let Ok(snapshot) = self.authority.wallet_utxos().await else {
            debug!(
                chain_id = self.cfg.chain.chain_id,
                "pending output POI submission skipped before wallet state check"
            );
            return Some(if self.authority.revalidate().is_err() {
                PendingOutputPoiPreflight::AuthorityStale
            } else {
                PendingOutputPoiPreflight::NotCurrent
            });
        };
        let Some(subject_match) =
            pending_output_poi_subject_matches_snapshot(self.cfg, &snapshot, current, self.subject)
        else {
            debug!(
                chain_id = self.cfg.chain.chain_id,
                "pending output POI submission skipped; subject no longer matches wallet state"
            );
            return Some(PendingOutputPoiPreflight::NotCurrent);
        };
        let current_recoverable_list_keys = recoverable_pending_submission_list_keys(
            current,
            self.active_list_keys,
            subject_match.poi(),
            self.plan.predicate(),
        );
        if current_recoverable_list_keys != self.plan.list_keys {
            debug!(
                chain_id = self.cfg.chain.chain_id,
                planned_poi_lists = self.plan.list_keys.len(),
                current_recoverable_poi_lists = current_recoverable_list_keys.len(),
                "pending output POI submission skipped; recoverable target-list subset changed"
            );
            return Some(PendingOutputPoiPreflight::NotCurrent);
        }
        None
    }

    /// Rereads the context and recovery after the wallet check and confirms neither changed.
    fn postflight_unchanged(&self) -> Result<bool, WalletCacheError> {
        let Some(postflight_context) = self.cache_store.get_pending_output_poi_context(
            self.cfg.chain.chain_id,
            &self.cfg.cache_key,
            &self.expected.output_commitment,
        )?
        else {
            return Ok(false);
        };
        let postflight_recovery = self.cache_store.get_output_poi_recovery(
            self.cfg.chain.chain_id,
            &self.cfg.cache_key,
            &self.expected.output_commitment,
        )?;
        let Some(final_context) = self.cache_store.get_pending_output_poi_context(
            self.cfg.chain.chain_id,
            &self.cfg.cache_key,
            &self.expected.output_commitment,
        )?
        else {
            return Ok(false);
        };
        let expected_fingerprint = pending_output_poi_context_fingerprint(self.expected);
        Ok(
            pending_output_poi_context_fingerprint(&postflight_context) == expected_fingerprint
                && pending_output_poi_context_fingerprint(&final_context) == expected_fingerprint
                && expected_recovery_matches(
                    &self.plan.expected_recovery,
                    postflight_recovery.as_ref(),
                )
                && !postflight_recovery.as_ref().is_some_and(|recovery| {
                    final_context
                        .observation
                        .as_ref()
                        .is_none_or(|observation| recovery.source_tx_hash != observation.tx_hash)
                }),
        )
    }
}

impl PendingOutputPoiSubmissionPass<'_> {
    async fn pending_output_poi_submission_side_effect_current(
        &self,
        expected: &PendingOutputPoiContextRecord,
        subject: &PendingOutputPoiSubject,
        plan: &PendingOutputPoiSubmissionPlan,
    ) -> Result<bool, WalletCacheError> {
        Ok(matches!(
            self.preflight(expected, subject, plan).run().await?,
            PendingOutputPoiPreflight::Ready
        ))
    }

    /// The preflight for submitting `plan` on `expected` in this pass.
    const fn preflight<'p>(
        &'p self,
        expected: &'p PendingOutputPoiContextRecord,
        subject: &'p PendingOutputPoiSubject,
        plan: &'p PendingOutputPoiSubmissionPlan,
    ) -> PendingOutputPoiSubmissionPreflight<'p> {
        PendingOutputPoiSubmissionPreflight {
            authority: self.authority,
            public_data_plane: self.public_data_plane,
            cache_store: self.cache_store,
            cfg: self.cfg,
            active_list_keys: self.active_list_keys,
            expected,
            subject,
            plan,
        }
    }
}

/// Sole production choke point for remote pending-output POI submission:
/// preflight → build context → remote await. Durable apply remains caller's postflight.
pub(super) async fn preflight_and_remote_submit_pending_output_poi(
    preflight: &PendingOutputPoiSubmissionPreflight<'_>,
    observation: &PendingOutputPoiObservation,
    private_poi: &WalletPrivatePoiClients,
    route: &mut Option<TransactProofRoute>,
) -> Result<PendingOutputPoiRemoteAttempt, WalletCacheError> {
    let PendingOutputPoiSubmissionPreflight {
        public_data_plane,
        cfg,
        expected: record,
        plan,
        ..
    } = *preflight;
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
    match preflight.run().await? {
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
    let context = single_commitment_proof_context(record, pre_transaction_pois);
    debug!(
        chain_id = cfg.chain.chain_id,
        pre_tx_poi_lists = context.pre_transaction_pois_per_txid_leaf_per_list.len(),
        plan_kind = ?plan.predicate,
        "submitting pending output POI context"
    );
    GatewaySubmission {
        preflight,
        private_poi,
        observation,
    }
    .submit(context, route)
    .await
}

/// The record's single-commitment proof context over its selected
/// pre-transaction POIs.
fn single_commitment_proof_context(
    record: &PendingOutputPoiContextRecord,
    pre_transaction_pois: BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PreTxPoi>>,
) -> SingleCommitmentProofContext {
    SingleCommitmentProofContext {
        txid_version: record.txid_version.clone(),
        railgun_txid: record.railgun_txid,
        utxo_tree_in: record.utxo_tree_in,
        commitment: record.output_commitment,
        npk: record.output_npk,
        pre_transaction_pois_per_txid_leaf_per_list: pre_transaction_pois,
    }
}

pub(super) fn pending_output_poi_context_fingerprint(
    record: &PendingOutputPoiContextRecord,
) -> Option<Vec<u8>> {
    record_fingerprint(record)
}

fn output_poi_recovery_fingerprint(record: &OutputPoiRecoveryRecord) -> Option<Vec<u8>> {
    record_fingerprint(record)
}

/// The record's rmp-serde bytes, which predecessor checks compare.
fn record_fingerprint<T: Serialize>(record: &T) -> Option<Vec<u8>> {
    rmp_serde::to_vec(record).ok()
}

pub(super) fn expected_pending_context_state(
    record: Option<&PendingOutputPoiContextRecord>,
) -> Option<ExpectedRecordState> {
    expected_record_state(record)
}

pub(super) fn expected_recovery_state(
    record: Option<&OutputPoiRecoveryRecord>,
) -> Option<ExpectedRecordState> {
    expected_record_state(record)
}

/// The expected state of an optional record. `None` when a present record
/// can't be fingerprinted.
fn expected_record_state<T: Serialize>(record: Option<&T>) -> Option<ExpectedRecordState> {
    match record {
        Some(record) => record_fingerprint(record).map(ExpectedRecordState::Present),
        None => Some(ExpectedRecordState::Absent),
    }
}

#[cfg(test)]
pub(super) mod test_support;
