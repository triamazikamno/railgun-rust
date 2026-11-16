//! Applying output recovery and pending output POI submission deltas.

use std::collections::BTreeSet;

use crate::wallet::pending_output_poi::recovered_outgoing::{
    RecoveredOutgoingGroupEvidence, recovered_outgoing_group_evidence,
    recovered_outgoing_group_records, recovered_outgoing_owned_substitutes_match,
};
use crate::wallet::pending_output_poi::{
    BTreeMap, ExpectedPoiStatus, ExpectedWalletOutput, FixedBytes, OutputPoiRecoveryAction,
    OutputPoiRecoveryRecord, OutputPoiRecoveryStatus, OutputRecoveryDelta,
    PendingOutputPoiContextRecord, PendingOutputPoiObservation, PendingOutputPoiRole,
    PendingOutputPoiSubject, PendingOutputPoiSubmissionKind, PendingSubmissionDelta,
    PoiPrivateApplyOutcome, PoiPrivateRows, RecoveredOutgoingSubmissionDelta,
    RecoveredOutgoingSubmissionSibling, WalletCacheError, WalletCacheStore, WalletConfig,
    WalletUtxo, expected_pending_context_matches, expected_poi_status_matches,
    expected_recovery_matches, hold_expected_poi_corpus_revision, new_output_poi_recovery_record,
    new_pending_output_poi_recovery_record, output_poi_recovery_default_status,
    pending_output_poi_context_fingerprint, pending_output_poi_context_matches_wallet_utxo,
    pending_output_poi_subject_matches_snapshot, pending_output_poi_submit_identity,
    pending_submission_predicate_matches, poi_statuses_are_recoverable_for_lists,
    prune_nonrecoverable_unsubmitted_poi_lists, recoverable_pending_submission_list_keys,
    saved_pending_context_is_compatible, saved_poi_compatibility,
    wallet_ppoi_workflow_status_after_mutations,
};

use super::{PoiApplyTurn, commit_durable_apply, lists_are_active, recovery_matches_source};

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
    let OutputRecoveryDelta {
        expected_output,
        active_list_keys,
        target_list_keys,
        required_poi_status,
        pending_update,
        expected_recovery,
        action,
        now,
        expected_corpus,
        replay_fence,
    } = delta;
    // Match sender reconstruction lock ordering: public data, then corpus, then commit.
    let _public_commit_guard = match replay_fence.as_ref() {
        Some(fence) => Some(fence.public_data_plane.acquire_commit_guard().await),
        None => None,
    };
    if replay_fence
        .as_ref()
        .is_some_and(|fence| fence.public_data_plane.current_epoch() != fence.epoch)
    {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    // Held through the commit when this record consumes a local proof.
    let _revision_fence = match hold_expected_poi_corpus_revision(expected_corpus.as_ref()).await {
        Ok(revision_fence) => revision_fence,
        Err(stale) => {
            drop(permit);
            return Ok(stale);
        }
    };
    let Some(wallet_utxo) = snapshot
        .iter()
        .find(|wallet_utxo| expected_output.matches(wallet_utxo))
    else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    if !lists_are_active(&active_list_keys, &target_list_keys)
        || !expected_poi_status_matches(
            &wallet_utxo.utxo.poi,
            &target_list_keys,
            required_poi_status,
        )
    {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }

    let pending_update = if let Some((expected_pending, update)) = *pending_update {
        let current = cache_store.get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &expected_output.output_commitment(),
        )?;
        if !expected_pending_context_matches(&expected_pending, current.as_ref())
            || !pending_output_poi_context_matches_wallet_utxo(cfg, wallet_utxo, &update)
        {
            drop(permit);
            return Ok(PoiPrivateApplyOutcome::Skipped);
        }
        Some(update)
    } else {
        None
    };
    let current_recovery = cache_store.get_output_poi_recovery(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &expected_output.output_commitment(),
    )?;
    let valid_recovery_is_stale_for_subset = current_recovery
        .as_ref()
        .is_some_and(|record| record.status == OutputPoiRecoveryStatus::Valid)
        && required_poi_status == ExpectedPoiStatus::Recoverable;
    if !recovery_matches_source(
        &expected_recovery,
        current_recovery.as_ref(),
        wallet_utxo.utxo.source.tx_hash,
    ) || (current_recovery
        .as_ref()
        .is_some_and(|record| record.status == OutputPoiRecoveryStatus::Valid)
        && !valid_recovery_is_stale_for_subset
        && !matches!(&action, OutputPoiRecoveryAction::Valid))
    {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    let mut recovery = current_recovery.unwrap_or_else(|| {
        new_output_poi_recovery_record(
            cfg,
            wallet_utxo,
            output_poi_recovery_default_status(&action),
            now,
        )
    });
    recovery.apply_action(action, now);
    let pending_updates: Vec<_> = pending_update.into_iter().collect();
    let recovery_updates = [recovery];
    let rows = PoiPrivateRows {
        pending_updates: &pending_updates,
        recovery_updates: &recovery_updates,
        ..PoiPrivateRows::default()
    };
    let workflow_status = wallet_ppoi_workflow_status_after_mutations(
        cache_store,
        cfg,
        &active_list_keys,
        permit.ppoi_workflow_status().validation_revision,
        rows,
    )?;
    commit_durable_apply(permit, cache_store, rows, workflow_status)
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
    let PendingSubmissionDelta {
        subject,
        expected_context_fingerprint,
        expected_recovery,
        active_list_keys,
        list_keys,
        predicate,
        merge_submitted_list_keys,
        action,
        now,
    } = delta;
    if !lists_are_active(&active_list_keys, &list_keys) {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    let Some(mut current_context) = cache_store.get_pending_output_poi_context(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &subject.output_commitment(),
    )?
    else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    if pending_output_poi_context_fingerprint(&current_context).as_ref()
        != Some(&expected_context_fingerprint)
        || current_context.terminal_error.is_some()
        || !pending_submission_predicate_matches(&current_context, &list_keys, predicate)
    {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    let Some(subject_match) =
        pending_output_poi_subject_matches_snapshot(cfg, &snapshot, &current_context, &subject)
    else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    if subject_match
        .poi()
        .is_some_and(|poi| !poi_statuses_are_recoverable_for_lists(poi, &list_keys))
    {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    let current_recovery = cache_store.get_output_poi_recovery(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &subject.output_commitment(),
    )?;
    let Some(observation) = current_context.observation.clone() else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    if !recovery_matches_source(
        &expected_recovery,
        current_recovery.as_ref(),
        observation.tx_hash,
    ) || current_recovery
        .as_ref()
        .is_some_and(|record| record.status == OutputPoiRecoveryStatus::Valid)
    {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    if merge_submitted_list_keys {
        add_submitted_list_keys(&mut current_context, &list_keys);
        if let Some(poi) = subject_match.poi() {
            prune_nonrecoverable_unsubmitted_poi_lists(
                &mut current_context,
                poi,
                &active_list_keys,
            );
        }
    }
    let mut recovery = current_recovery.unwrap_or_else(|| {
        new_pending_output_poi_recovery_record(
            cfg.chain.chain_id,
            &current_context,
            &observation,
            output_poi_recovery_default_status(&action),
            now,
        )
    });
    recovery.apply_action(action, now);
    let pending_updates: Vec<_> = merge_submitted_list_keys
        .then_some(current_context)
        .into_iter()
        .collect();
    let recovery_updates = [recovery];
    let rows = PoiPrivateRows {
        pending_updates: &pending_updates,
        recovery_updates: &recovery_updates,
        ..PoiPrivateRows::default()
    };
    let workflow_status = wallet_ppoi_workflow_status_after_mutations(
        cache_store,
        cfg,
        &active_list_keys,
        permit.ppoi_workflow_status().validation_revision,
        rows,
    )?;
    commit_durable_apply(permit, cache_store, rows, workflow_status)
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
    let RecoveredOutgoingSubmissionDelta {
        siblings,
        owned_substitutes,
        external_valid_substitutes,
        expected_corpus,
        active_list_keys,
        list_keys,
        merge_submitted_list_keys,
        action,
        now,
    } = delta;
    if siblings.is_empty() || !lists_are_active(&active_list_keys, &list_keys) {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    let _corpus_fence = match hold_expected_poi_corpus_revision(expected_corpus.as_ref()).await {
        Ok(fence) => fence,
        Err(stale) => return Ok(stale),
    };
    let planned_union = siblings
        .iter()
        .flat_map(|sibling| sibling.plan.list_keys().iter().copied())
        .collect::<BTreeSet<_>>();
    if list_keys.iter().copied().collect::<BTreeSet<_>>() != planned_union {
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    let check = RecoveredOutgoingCheck {
        cache_store,
        cfg,
        snapshot: &snapshot,
        active_list_keys: &active_list_keys,
        now,
    };
    let Some((current_contexts, current_recoveries)) = check.current_sibling_records(&siblings)?
    else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    let Some(seed) = current_contexts.first() else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    let all_contexts =
        cache_store.list_pending_output_poi_contexts(cfg.chain.chain_id, &cfg.cache_key)?;
    let Some(current_group) = recovered_outgoing_group_records(&all_contexts, seed) else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    let external_valid = if let Some(expected) = &expected_corpus {
        let outputs = group_blinded_outputs(&current_group);
        let Some(valid) = saved_poi_compatibility::corpus_valid_outputs_by_list(
            &expected.corpus,
            cfg.chain.chain_id,
            &active_list_keys,
            &outputs,
        )
        .await
        else {
            return Ok(PoiPrivateApplyOutcome::Skipped);
        };
        valid
    } else {
        BTreeMap::new()
    };
    if !group_requires_unresolved_lists(&current_group, &active_list_keys, &external_valid) {
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    let current_evidence =
        recovered_outgoing_group_evidence(&current_group, &snapshot, &list_keys, &external_valid);
    if current_group.len() != current_contexts.len()
        || current_evidence.as_ref().is_none_or(|evidence| {
            !evidence_matches_substitutes(evidence, &owned_substitutes, &external_valid_substitutes)
        })
    {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }

    let mut pending_updates = Vec::with_capacity(current_contexts.len());
    let mut recovery_updates = Vec::with_capacity(current_contexts.len());
    for ((mut context, mut recovery), sibling) in current_contexts
        .into_iter()
        .zip(current_recoveries)
        .zip(&siblings)
    {
        let member_lists = list_keys
            .iter()
            .filter(|list_key| sibling.plan.list_keys.contains(list_key))
            .collect::<Vec<_>>();
        if member_lists.is_empty() {
            continue;
        }
        recovery.apply_action(action.clone(), now);
        recovery_updates.push(recovery);
        if merge_submitted_list_keys {
            add_submitted_list_keys(&mut context, member_lists);
            pending_updates.push(context);
        }
    }
    let rows = PoiPrivateRows {
        pending_updates: &pending_updates,
        recovery_updates: &recovery_updates,
        ..PoiPrivateRows::default()
    };
    let workflow_status = wallet_ppoi_workflow_status_after_mutations(
        cache_store,
        cfg,
        &active_list_keys,
        permit.ppoi_workflow_status().validation_revision,
        rows,
    )?;
    commit_durable_apply(permit, cache_store, rows, workflow_status)
}
