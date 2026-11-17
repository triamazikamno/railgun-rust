//! Applying output recovery and pending output POI submission deltas.

use std::collections::BTreeSet;

use crate::wallet::pending_output_poi::recovered_outgoing::{
    RecoveredOutgoingGroupEvidence, recovered_outgoing_group_evidence,
    recovered_outgoing_group_records, recovered_outgoing_owned_substitutes_match,
};
use crate::wallet::pending_output_poi::{
    BTreeMap, ExpectedPoiStatus, ExpectedRecordState, ExpectedWalletOutput, FixedBytes,
    OutputPoiRecoveryAction, OutputPoiRecoveryRecord, OutputPoiRecoveryStatus, OutputRecoveryDelta,
    PendingOutputPoiContextRecord, PendingOutputPoiObservation, PendingOutputPoiRole,
    PendingOutputPoiSubject, PendingOutputPoiSubjectMatch, PendingOutputPoiSubmissionKind,
    PendingSubmissionDelta, PoiPrivateApplyOutcome, PoiPrivateRows,
    RecoveredOutgoingSubmissionDelta, RecoveredOutgoingSubmissionSibling, WalletCacheError,
    WalletCacheStore, WalletConfig, WalletPrivateMutationPermit, WalletUtxo,
    expected_pending_context_matches, expected_poi_status_matches, expected_recovery_matches,
    hold_expected_poi_corpus_revision, new_output_poi_recovery_record,
    new_pending_output_poi_recovery_record, output_poi_recovery_default_status,
    pending_output_poi_context_fingerprint, pending_output_poi_context_matches_wallet_utxo,
    pending_output_poi_subject_matches_snapshot, pending_output_poi_submit_identity,
    pending_submission_predicate_matches, poi_statuses_are_recoverable_for_lists,
    prune_nonrecoverable_unsubmitted_poi_lists, recoverable_pending_submission_list_keys,
    saved_pending_context_is_compatible, saved_poi_compatibility,
    wallet_ppoi_workflow_status_after_mutations,
};

use super::{
    PendingOutputStore, PoiApplyTurn, commit_durable_apply, lists_are_active,
    recovery_matches_source,
};

/// Adds each list key the context does not already record as submitted.
fn add_submitted_list_keys<'a>(
    context: &mut PendingOutputPoiContextRecord,
    list_keys: impl IntoIterator<Item = &'a FixedBytes<32>>,
) {
    for list_key in list_keys {
        if !context.submitted_poi_list_keys.contains(list_key) {
            context.submitted_poi_list_keys.push(*list_key);
        }
    }
}

pub(super) async fn apply_output_recovery(
    turn: PoiApplyTurn<'_>,
    delta: OutputRecoveryDelta,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    let PoiApplyTurn {
        permit,
        snapshot,
        cache_store,
        cfg,
        ..
    } = turn;
    // Match sender reconstruction lock ordering: public data, then corpus, then commit.
    let _public_commit_guard = match delta.replay_fence.as_ref() {
        Some(fence) => Some(fence.public_data_plane.acquire_commit_guard().await),
        None => None,
    };
    if delta
        .replay_fence
        .as_ref()
        .is_some_and(|fence| fence.public_data_plane.current_epoch() != fence.epoch)
    {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    // Held through the commit when this record consumes a local proof.
    let _revision_fence =
        match hold_expected_poi_corpus_revision(delta.expected_corpus.as_ref()).await {
            Ok(revision_fence) => revision_fence,
            Err(stale) => {
                drop(permit);
                return Ok(stale);
            }
        };
    let Some(wallet_utxo) = recovery_target_output(&snapshot, &delta) else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    let store = PendingOutputStore {
        cache_store,
        cfg,
        output_commitment: delta.expected_output.output_commitment(),
    };
    if !pending_update_is_current(store, wallet_utxo, &delta)? {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    let Some(mut recovery) = checked_output_recovery(store, wallet_utxo, &delta)? else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    recovery.apply_action(delta.action, delta.now);
    let pending_updates: Vec<_> = (*delta.pending_update)
        .map(|(_, update)| update)
        .into_iter()
        .collect();
    let recovery_updates = [recovery];
    let rows = PoiPrivateRows {
        pending_updates: &pending_updates,
        recovery_updates: &recovery_updates,
        ..PoiPrivateRows::default()
    };
    let workflow_status = store.workflow_after_mutations(&permit, &delta.active_list_keys, rows)?;
    commit_durable_apply(permit, cache_store, rows, workflow_status)
}

/// The snapshot UTXO of the expected output, when the target lists are active and its POI status
/// is the required one.
fn recovery_target_output<'s>(
    snapshot: &'s [WalletUtxo],
    delta: &OutputRecoveryDelta,
) -> Option<&'s WalletUtxo> {
    let wallet_utxo = snapshot
        .iter()
        .find(|wallet_utxo| delta.expected_output.matches(wallet_utxo))?;
    (lists_are_active(&delta.active_list_keys, &delta.target_list_keys)
        && expected_poi_status_matches(
            &wallet_utxo.utxo.poi,
            &delta.target_list_keys,
            delta.required_poi_status,
        ))
    .then_some(wallet_utxo)
}

/// Whether the delta's pending update, if any, still replaces the expected stored context and
/// matches the output's UTXO. The context is read only when there is an update.
fn pending_update_is_current(
    store: PendingOutputStore<'_>,
    wallet_utxo: &WalletUtxo,
    delta: &OutputRecoveryDelta,
) -> Result<bool, WalletCacheError> {
    let Some((expected_pending, update)) = &*delta.pending_update else {
        return Ok(true);
    };
    let current = store.context()?;
    Ok(
        expected_pending_context_matches(expected_pending, current.as_ref())
            && pending_output_poi_context_matches_wallet_utxo(store.cfg, wallet_utxo, update),
    )
}

/// The output's stored recovery, or a new one, when the stored recovery is the expected one from
/// the output's source. A Valid recovery is replaced only by a Valid action, or by a recovery of
/// a Recoverable subset.
fn checked_output_recovery(
    store: PendingOutputStore<'_>,
    wallet_utxo: &WalletUtxo,
    delta: &OutputRecoveryDelta,
) -> Result<Option<OutputPoiRecoveryRecord>, WalletCacheError> {
    let current_recovery = store.recovery()?;
    let current_is_valid = current_recovery
        .as_ref()
        .is_some_and(|record| record.status == OutputPoiRecoveryStatus::Valid);
    let valid_recovery_is_stale_for_subset =
        current_is_valid && delta.required_poi_status == ExpectedPoiStatus::Recoverable;
    if !recovery_matches_source(
        &delta.expected_recovery,
        current_recovery.as_ref(),
        wallet_utxo.utxo.source.tx_hash,
    ) {
        return Ok(None);
    }
    let replaces_valid = valid_recovery_is_stale_for_subset
        || matches!(&delta.action, OutputPoiRecoveryAction::Valid);
    if current_is_valid && !replaces_valid {
        return Ok(None);
    }
    Ok(Some(current_recovery.unwrap_or_else(|| {
        new_output_poi_recovery_record(
            store.cfg,
            wallet_utxo,
            output_poi_recovery_default_status(&delta.action),
            delta.now,
        )
    })))
}

pub(super) fn apply_pending_submission(
    turn: PoiApplyTurn<'_>,
    delta: PendingSubmissionDelta,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    let PoiApplyTurn {
        permit,
        snapshot,
        cache_store,
        cfg,
        ..
    } = turn;
    let store = PendingOutputStore {
        cache_store,
        cfg,
        output_commitment: delta.subject.output_commitment(),
    };
    let Some(checked) = check_pending_submission(store, &snapshot, &delta)? else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    let CheckedSubmission {
        mut context,
        subject_match,
        recovery,
        observation,
    } = checked;
    if delta.merge_submitted_list_keys {
        add_submitted_list_keys(&mut context, &delta.list_keys);
        if let Some(poi) = subject_match.poi() {
            prune_nonrecoverable_unsubmitted_poi_lists(&mut context, poi, &delta.active_list_keys);
        }
    }
    let mut recovery = recovery.unwrap_or_else(|| {
        new_pending_output_poi_recovery_record(
            cfg.chain.chain_id,
            &context,
            &observation,
            output_poi_recovery_default_status(&delta.action),
            delta.now,
        )
    });
    recovery.apply_action(delta.action, delta.now);
    let pending_updates: Vec<_> = delta
        .merge_submitted_list_keys
        .then_some(context)
        .into_iter()
        .collect();
    let recovery_updates = [recovery];
    let rows = PoiPrivateRows {
        pending_updates: &pending_updates,
        recovery_updates: &recovery_updates,
        ..PoiPrivateRows::default()
    };
    let workflow_status = store.workflow_after_mutations(&permit, &delta.active_list_keys, rows)?;
    commit_durable_apply(permit, cache_store, rows, workflow_status)
}

/// A stored context, its snapshot match, its recovery and its observation, after a pending
/// submission's checks.
struct CheckedSubmission {
    context: PendingOutputPoiContextRecord,
    subject_match: PendingOutputPoiSubjectMatch,
    recovery: Option<OutputPoiRecoveryRecord>,
    observation: PendingOutputPoiObservation,
}

fn check_pending_submission(
    store: PendingOutputStore<'_>,
    snapshot: &[WalletUtxo],
    delta: &PendingSubmissionDelta,
) -> Result<Option<CheckedSubmission>, WalletCacheError> {
    if !lists_are_active(&delta.active_list_keys, &delta.list_keys) {
        return Ok(None);
    }
    let Some(context) = store.context()? else {
        return Ok(None);
    };
    if !context_accepts_submission(&context, delta) {
        return Ok(None);
    }
    let Some(subject_match) =
        pending_output_poi_subject_matches_snapshot(store.cfg, snapshot, &context, &delta.subject)
    else {
        return Ok(None);
    };
    if subject_match
        .poi()
        .is_some_and(|poi| !poi_statuses_are_recoverable_for_lists(poi, &delta.list_keys))
    {
        return Ok(None);
    }
    let recovery = store.recovery()?;
    let Some(observation) = context.observation.clone() else {
        return Ok(None);
    };
    if !submission_recovery_is_current(&delta.expected_recovery, recovery.as_ref(), &observation) {
        return Ok(None);
    }
    Ok(Some(CheckedSubmission {
        context,
        subject_match,
        recovery,
        observation,
    }))
}

/// Whether the context still has the expected fingerprint, is not terminal and matches the
/// submission predicate for the delta's lists.
fn context_accepts_submission(
    context: &PendingOutputPoiContextRecord,
    delta: &PendingSubmissionDelta,
) -> bool {
    pending_output_poi_context_fingerprint(context).as_ref()
        == Some(&delta.expected_context_fingerprint)
        && context.terminal_error.is_none()
        && pending_submission_predicate_matches(context, &delta.list_keys, delta.predicate)
}

/// Whether the stored recovery is the expected one from the observed source and is not yet
/// Valid.
fn submission_recovery_is_current(
    expected_recovery: &ExpectedRecordState,
    recovery: Option<&OutputPoiRecoveryRecord>,
    observation: &PendingOutputPoiObservation,
) -> bool {
    recovery_matches_source(expected_recovery, recovery, observation.tx_hash)
        && recovery.is_none_or(|record| record.status != OutputPoiRecoveryStatus::Valid)
}

/// Wallet state a recovered outgoing submission's siblings are checked against.
struct RecoveredOutgoingCheck<'a> {
    cache_store: &'a dyn WalletCacheStore,
    cfg: &'a WalletConfig,
    snapshot: &'a [WalletUtxo],
    active_list_keys: &'a [FixedBytes<32>],
    now: u64,
}

/// Current contexts and recoveries of a submission's siblings, in sibling order.
type CurrentSiblingRecords = (
    Vec<PendingOutputPoiContextRecord>,
    Vec<OutputPoiRecoveryRecord>,
);

impl RecoveredOutgoingCheck<'_> {
    /// The current context and recovery of every sibling, or `None` when any sibling is not
    /// current.
    fn current_sibling_records(
        &self,
        siblings: &[RecoveredOutgoingSubmissionSibling],
    ) -> Result<Option<CurrentSiblingRecords>, WalletCacheError> {
        let mut current_contexts = Vec::with_capacity(siblings.len());
        let mut current_recoveries = Vec::with_capacity(siblings.len());
        let mut output_commitments = BTreeSet::new();
        for sibling in siblings {
            let output_commitment = sibling.subject.output_commitment();
            if !matches!(&sibling.subject, PendingOutputPoiSubject::External { .. })
                || !output_commitments.insert(output_commitment)
            {
                return Ok(None);
            }
            let Some((current_context, current_recovery)) =
                self.current_sibling_record(sibling, output_commitment)?
            else {
                return Ok(None);
            };
            current_contexts.push(current_context);
            current_recoveries.push(current_recovery);
        }
        Ok(Some((current_contexts, current_recoveries)))
    }

    fn current_sibling_record(
        &self,
        sibling: &RecoveredOutgoingSubmissionSibling,
        output_commitment: FixedBytes<32>,
    ) -> Result<Option<(PendingOutputPoiContextRecord, OutputPoiRecoveryRecord)>, WalletCacheError>
    {
        let Some(current_context) = self.cache_store.get_pending_output_poi_context(
            self.cfg.chain.chain_id,
            &self.cfg.cache_key,
            &output_commitment,
        )?
        else {
            return Ok(None);
        };
        if !self.sibling_context_is_current(sibling, &current_context) {
            return Ok(None);
        }
        let Some(current_recovery) = self.cache_store.get_output_poi_recovery(
            self.cfg.chain.chain_id,
            &self.cfg.cache_key,
            &output_commitment,
        )?
        else {
            return Ok(None);
        };
        let Some(observation) = current_context.observation.as_ref() else {
            return Ok(None);
        };
        if !self.sibling_recovery_is_current(sibling, &current_recovery, observation) {
            return Ok(None);
        }
        Ok(Some((current_context, current_recovery)))
    }

    fn sibling_context_is_current(
        &self,
        sibling: &RecoveredOutgoingSubmissionSibling,
        context: &PendingOutputPoiContextRecord,
    ) -> bool {
        context.output_role == PendingOutputPoiRole::RecoveredOutgoing
            && pending_output_poi_context_fingerprint(context).as_ref()
                == Some(&sibling.expected_context_fingerprint)
            && context.terminal_error.is_none()
            && pending_submission_predicate_matches(
                context,
                sibling.plan.list_keys(),
                sibling.plan.predicate(),
            )
            && recoverable_pending_submission_list_keys(
                context,
                self.active_list_keys,
                None,
                sibling.plan.predicate(),
            ) == sibling.plan.list_keys
            && saved_pending_context_is_compatible(context, &context.list_keys())
            && pending_output_poi_subject_matches_snapshot(
                self.cfg,
                self.snapshot,
                context,
                &sibling.subject,
            )
            .is_some()
    }

    fn sibling_recovery_is_current(
        &self,
        sibling: &RecoveredOutgoingSubmissionSibling,
        recovery: &OutputPoiRecoveryRecord,
        observation: &PendingOutputPoiObservation,
    ) -> bool {
        expected_recovery_matches(&sibling.plan.expected_recovery, Some(recovery))
            && recovery.status != OutputPoiRecoveryStatus::Valid
            && recovery.source_tx_hash == observation.tx_hash
            && (sibling.plan.kind != PendingOutputPoiSubmissionKind::RetrySubmitted
                || recovery.submission_retry_allowed(self.now, sibling.plan.force_submission_retry))
    }
}

/// Distinct output blinded commitments the group's pre-transaction POIs cover.
fn group_blinded_outputs(group: &[&PendingOutputPoiContextRecord]) -> Vec<FixedBytes<32>> {
    group
        .iter()
        .flat_map(|context| context.pre_transaction_pois_per_txid_leaf_per_list.values())
        .flat_map(|per_leaf| per_leaf.values())
        .flat_map(|poi| poi.blinded_commitments_out.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
}

/// Whether every group member still requires exactly the lists its output has not resolved.
fn group_requires_unresolved_lists(
    group: &[&PendingOutputPoiContextRecord],
    active_list_keys: &[FixedBytes<32>],
    external_valid: &BTreeMap<FixedBytes<32>, BTreeSet<FixedBytes<32>>>,
) -> bool {
    group.iter().all(|context| {
        context
            .observation
            .as_ref()
            .and_then(|observation| pending_output_poi_submit_identity(context, observation))
            .is_some_and(|identity| {
                context.required_poi_list_keys
                    == saved_poi_compatibility::unresolved_output_lists(
                        active_list_keys,
                        identity.derived_blinded_commitment,
                        external_valid,
                    )
            })
    })
}

/// Whether the group's current evidence names exactly the delta's substitutes.
fn evidence_matches_substitutes(
    evidence: &RecoveredOutgoingGroupEvidence<'_>,
    owned_substitutes: &[ExpectedWalletOutput],
    external_valid_substitutes: &[FixedBytes<32>],
) -> bool {
    recovered_outgoing_owned_substitutes_match(owned_substitutes, &evidence.owned_outputs)
        && evidence
            .external_valid_substitutes
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            == external_valid_substitutes
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
}

pub(super) async fn apply_recovered_outgoing_submission(
    turn: PoiApplyTurn<'_>,
    delta: RecoveredOutgoingSubmissionDelta,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    let PoiApplyTurn {
        permit,
        snapshot,
        cache_store,
        cfg,
        ..
    } = turn;
    if delta.siblings.is_empty() || !lists_are_active(&delta.active_list_keys, &delta.list_keys) {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    RecoveredOutgoingSubmission {
        cache_store,
        cfg,
        snapshot,
        delta,
    }
    .validate_and_commit(permit)
    .await
}

/// A recovered outgoing submission delta and the wallet state it is checked against.
struct RecoveredOutgoingSubmission<'a> {
    cache_store: &'a dyn WalletCacheStore,
    cfg: &'a WalletConfig,
    snapshot: Vec<WalletUtxo>,
    delta: RecoveredOutgoingSubmissionDelta,
}

impl RecoveredOutgoingSubmission<'_> {
    /// Validates the siblings and their group under the corpus fence, then commits their rows.
    /// Each skip keeps its permit release order relative to the fence.
    async fn validate_and_commit(
        &self,
        permit: WalletPrivateMutationPermit<'_>,
    ) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
        let delta = &self.delta;
        let _corpus_fence =
            match hold_expected_poi_corpus_revision(delta.expected_corpus.as_ref()).await {
                Ok(fence) => fence,
                Err(stale) => return Ok(stale),
            };
        if !self.planned_lists_match() {
            return Ok(PoiPrivateApplyOutcome::Skipped);
        }
        let Some((current_contexts, current_recoveries)) =
            self.check().current_sibling_records(&delta.siblings)?
        else {
            drop(permit);
            return Ok(PoiPrivateApplyOutcome::Skipped);
        };
        let Some(seed) = current_contexts.first() else {
            drop(permit);
            return Ok(PoiPrivateApplyOutcome::Skipped);
        };
        let all_contexts = self
            .cache_store
            .list_pending_output_poi_contexts(self.cfg.chain.chain_id, &self.cfg.cache_key)?;
        let Some(current_group) = recovered_outgoing_group_records(&all_contexts, seed) else {
            drop(permit);
            return Ok(PoiPrivateApplyOutcome::Skipped);
        };
        let Some(external_valid) = self.unresolved_group_valid(&current_group).await else {
            return Ok(PoiPrivateApplyOutcome::Skipped);
        };
        if !self.group_evidence_matches(&current_group, current_contexts.len(), &external_valid) {
            drop(permit);
            return Ok(PoiPrivateApplyOutcome::Skipped);
        }
        let (pending_updates, recovery_updates) = self.rows(current_contexts, current_recoveries);
        let rows = PoiPrivateRows {
            pending_updates: &pending_updates,
            recovery_updates: &recovery_updates,
            ..PoiPrivateRows::default()
        };
        let workflow_status = wallet_ppoi_workflow_status_after_mutations(
            self.cache_store,
            self.cfg,
            &delta.active_list_keys,
            permit.ppoi_workflow_status().validation_revision,
            rows,
        )?;
        commit_durable_apply(permit, self.cache_store, rows, workflow_status)
    }

    /// Whether the delta's lists are exactly the union of its siblings' planned lists.
    fn planned_lists_match(&self) -> bool {
        let planned_union = self
            .delta
            .siblings
            .iter()
            .flat_map(|sibling| sibling.plan.list_keys().iter().copied())
            .collect::<BTreeSet<_>>();
        self.delta
            .list_keys
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            == planned_union
    }

    fn check(&self) -> RecoveredOutgoingCheck<'_> {
        RecoveredOutgoingCheck {
            cache_store: self.cache_store,
            cfg: self.cfg,
            snapshot: &self.snapshot,
            active_list_keys: &self.delta.active_list_keys,
            now: self.delta.now,
        }
    }

    /// The group's outputs by active list on which they are Valid, when every member still
    /// requires exactly its unresolved lists; `None` when the corpus read fails or a member does
    /// not.
    async fn unresolved_group_valid(
        &self,
        group: &[&PendingOutputPoiContextRecord],
    ) -> Option<BTreeMap<FixedBytes<32>, BTreeSet<FixedBytes<32>>>> {
        let external_valid = if let Some(expected) = &self.delta.expected_corpus {
            let outputs = group_blinded_outputs(group);
            saved_poi_compatibility::corpus_valid_outputs_by_list(
                &expected.corpus,
                self.cfg.chain.chain_id,
                &self.delta.active_list_keys,
                &outputs,
            )
            .await?
        } else {
            BTreeMap::new()
        };
        group_requires_unresolved_lists(group, &self.delta.active_list_keys, &external_valid)
            .then_some(external_valid)
    }

    /// Whether the group has one member per sibling and its current evidence names exactly the
    /// delta's substitutes.
    fn group_evidence_matches(
        &self,
        group: &[&PendingOutputPoiContextRecord],
        member_count: usize,
        external_valid: &BTreeMap<FixedBytes<32>, BTreeSet<FixedBytes<32>>>,
    ) -> bool {
        let current_evidence = recovered_outgoing_group_evidence(
            group,
            &self.snapshot,
            &self.delta.list_keys,
            external_valid,
        );
        group.len() == member_count
            && current_evidence.as_ref().is_some_and(|evidence| {
                evidence_matches_substitutes(
                    evidence,
                    &self.delta.owned_substitutes,
                    &self.delta.external_valid_substitutes,
                )
            })
    }

    /// The context and recovery updates of each sibling that has lists in the delta, in sibling
    /// order.
    fn rows(
        &self,
        current_contexts: Vec<PendingOutputPoiContextRecord>,
        current_recoveries: Vec<OutputPoiRecoveryRecord>,
    ) -> (
        Vec<PendingOutputPoiContextRecord>,
        Vec<OutputPoiRecoveryRecord>,
    ) {
        let delta = &self.delta;
        let mut pending_updates = Vec::with_capacity(current_contexts.len());
        let mut recovery_updates = Vec::with_capacity(current_contexts.len());
        for ((mut context, mut recovery), sibling) in current_contexts
            .into_iter()
            .zip(current_recoveries)
            .zip(&delta.siblings)
        {
            let member_lists = delta
                .list_keys
                .iter()
                .filter(|list_key| sibling.plan.list_keys.contains(list_key))
                .collect::<Vec<_>>();
            if member_lists.is_empty() {
                continue;
            }
            recovery.apply_action(delta.action.clone(), delta.now);
            recovery_updates.push(recovery);
            if delta.merge_submitted_list_keys {
                add_submitted_list_keys(&mut context, member_lists);
                pending_updates.push(context);
            }
        }
        (pending_updates, recovery_updates)
    }
}
