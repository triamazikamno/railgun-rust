//! Applying terminal, locally valid, verified valid and POI status refresh deltas.

use crate::wallet::pending_output_poi::workflow_status::wallet_ppoi_workflow_status_after_validation;
use crate::wallet::pending_output_poi::{
    BTreeMap, FixedBytes, LocallyValidPendingListsDelta, OutputPoiRecoveryAction,
    OutputPoiRecoveryStatus, PendingContextTerminalDelta, PendingOutputPoiSubject,
    PendingOutputPoiSubjectMatch, PendingOutputPoiValidationEvidence, PoiPrivateApplyOutcome,
    PoiPrivateRows, PoiStatus, PoiStatusRefreshDelta, VerifiedValidDelta, WalletCacheError,
    new_output_poi_recovery_record, output_poi_recovery_default_status,
    pending_output_poi_context_fingerprint, pending_output_poi_subject_matches_snapshot,
    poi_statuses_are_recoverable_for_lists, wallet_ppoi_workflow_status_after_mutations,
};

use super::{
    ActiveApplyCommit, PoiApplyTurn, commit_active_apply, commit_durable_apply, lists_are_active,
    recovery_matches_source,
};

pub(super) fn apply_pending_context_terminal(
    turn: PoiApplyTurn<'_>,
    delta: PendingContextTerminalDelta,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    let PoiApplyTurn {
        permit,
        snapshot,
        cache_store,
        cfg,
        ..
    } = turn;
    let PendingContextTerminalDelta {
        subject,
        expected_context_fingerprint,
        expected_recovery,
        active_list_keys,
        target_list_keys,
        error,
    } = delta;
    if !lists_are_active(&active_list_keys, &target_list_keys) {
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
        .is_some_and(|poi| !poi_statuses_are_recoverable_for_lists(poi, &target_list_keys))
    {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    let Some(observation) = current_context.observation.as_ref() else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    let current_recovery = cache_store.get_output_poi_recovery(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &subject.output_commitment(),
    )?;
    if !recovery_matches_source(
        &expected_recovery,
        current_recovery.as_ref(),
        observation.tx_hash,
    ) {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    current_context.terminal_error = Some(error);
    let pending_updates = [current_context];
    let rows = PoiPrivateRows {
        pending_updates: &pending_updates,
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

pub(super) async fn apply_locally_valid_pending_lists(
    turn: PoiApplyTurn<'_>,
    delta: LocallyValidPendingListsDelta,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    let PoiApplyTurn {
        permit,
        mut snapshot,
        cache_store,
        cfg,
        ..
    } = turn;
    let LocallyValidPendingListsDelta {
        subject,
        expected_context_fingerprint,
        expected_recovery,
        active_list_keys,
        valid_list_keys,
        now,
    } = delta;
    let output_commitment = subject.output_commitment();
    if !lists_are_active(&active_list_keys, &valid_list_keys) {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    let Some(mut current_context) = cache_store.get_pending_output_poi_context(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &output_commitment,
    )?
    else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    if pending_output_poi_context_fingerprint(&current_context).as_ref()
        != Some(&expected_context_fingerprint)
        || valid_list_keys
            .iter()
            .any(|list_key| !current_context.list_keys().contains(list_key))
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
    let Some(observation) = current_context.observation.as_ref() else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    let current_recovery = cache_store.get_output_poi_recovery(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &output_commitment,
    )?;
    if !recovery_matches_source(
        &expected_recovery,
        current_recovery.as_ref(),
        observation.tx_hash,
    ) {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }

    let mut changed = false;
    let mut recovery_updates = Vec::new();
    let mut recovery_deletes = Vec::new();
    if matches!(&subject_match, PendingOutputPoiSubjectMatch::Owned(_)) {
        let PendingOutputPoiSubject::Owned(expected_output) = &subject else {
            drop(permit);
            return Ok(PoiPrivateApplyOutcome::Skipped);
        };
        let Some(wallet_utxo) = snapshot
            .iter_mut()
            .find(|wallet_utxo| expected_output.matches(wallet_utxo))
        else {
            drop(permit);
            return Ok(PoiPrivateApplyOutcome::Skipped);
        };
        let valid_statuses = valid_list_keys
            .iter()
            .copied()
            .map(|list_key| (list_key, PoiStatus::Valid))
            .collect::<BTreeMap<_, _>>();
        changed = wallet_utxo.utxo.poi.apply_status_refresh(
            &valid_list_keys,
            Some(&valid_statuses),
            wallet_utxo
                .utxo
                .poi
                .refreshed_at
                .map_or(now, |refreshed_at| refreshed_at.max(now)),
        ) > 0;
    }

    current_context
        .required_poi_list_keys
        .retain(|list_key| !valid_list_keys.contains(list_key));
    current_context
        .pre_transaction_pois_per_txid_leaf_per_list
        .retain(|list_key, _| !valid_list_keys.contains(list_key));
    current_context
        .submitted_poi_list_keys
        .retain(|list_key| !valid_list_keys.contains(list_key));
    let remaining_active_lists = current_context
        .list_keys()
        .into_iter()
        .filter(|list_key| active_list_keys.contains(list_key))
        .collect::<Vec<_>>();
    let complete = remaining_active_lists.is_empty();
    let pending_updates = if complete {
        Vec::new()
    } else {
        vec![current_context]
    };
    let pending_deletes: Vec<FixedBytes<32>> =
        complete.then_some(output_commitment).into_iter().collect();
    if complete {
        if let Some(wallet_output) = match &subject_match {
            PendingOutputPoiSubjectMatch::Owned(output) => Some(output),
            PendingOutputPoiSubjectMatch::External => None,
        } {
            let mut recovery = current_recovery.unwrap_or_else(|| {
                new_output_poi_recovery_record(
                    cfg,
                    wallet_output,
                    OutputPoiRecoveryStatus::Valid,
                    now,
                )
            });
            recovery.apply_action(OutputPoiRecoveryAction::Valid, now);
            recovery_updates.push(recovery);
        } else {
            recovery_deletes.push(output_commitment);
        }
    } else if current_recovery
        .as_ref()
        .is_some_and(|recovery| recovery.status == OutputPoiRecoveryStatus::Valid)
    {
        let mut recovery = current_recovery
            .clone()
            .expect("Valid recovery status was checked above");
        recovery.apply_action(
            OutputPoiRecoveryAction::Detected {
                status: OutputPoiRecoveryStatus::Recoverable,
                retry_after: None,
                last_error: None,
                increment_attempts: false,
            },
            now,
        );
        recovery_updates.push(recovery);
    }
    let rows = PoiPrivateRows {
        pending_updates: &pending_updates,
        pending_deletes: &pending_deletes,
        recovery_updates: &recovery_updates,
        recovery_deletes: &recovery_deletes,
        ..PoiPrivateRows::default()
    };
    let workflow_status = wallet_ppoi_workflow_status_after_mutations(
        cache_store,
        cfg,
        &active_list_keys,
        permit.ppoi_workflow_status().validation_revision,
        rows,
    )?;
    commit_active_apply(
        permit,
        cache_store,
        ActiveApplyCommit {
            snapshot,
            utxos_changed: changed,
            rows,
            workflow: Some(workflow_status),
        },
    )
    .await
}

pub(super) async fn apply_verified_valid(
    turn: PoiApplyTurn<'_>,
    delta: VerifiedValidDelta,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    let PoiApplyTurn {
        permit,
        mut snapshot,
        cache_store,
        cfg,
        ..
    } = turn;
    let VerifiedValidDelta {
        subject,
        evidence,
        expected_context_fingerprint,
        expected_recovery,
        expected_poi_list_state,
        active_list_keys,
        valid_list_keys,
        now,
    } = delta;
    let output_commitment = subject.output_commitment();
    let Some(current_context) = cache_store.get_pending_output_poi_context(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &output_commitment,
    )?
    else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    let Some(subject_match) =
        pending_output_poi_subject_matches_snapshot(cfg, &snapshot, &current_context, &subject)
    else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    let current_list_keys = current_context.list_keys();
    let submitted_lists_match = valid_list_keys
        .iter()
        .all(|list_key| current_context.submitted_poi_list_keys.contains(list_key));
    let evidence_matches = match evidence {
        PendingOutputPoiValidationEvidence::SubmittedStatus => submitted_lists_match,
        PendingOutputPoiValidationEvidence::OwnedStatusRefresh => {
            matches!(
                &subject_match,
                PendingOutputPoiSubjectMatch::Owned(output)
                    if expected_poi_list_state.as_ref().is_some_and(|expected| {
                        expected.matches_valid(&output.utxo.poi, &valid_list_keys)
                    })
            )
        }
    };
    if !lists_are_active(&active_list_keys, &valid_list_keys)
        || pending_output_poi_context_fingerprint(&current_context).as_ref()
            != Some(&expected_context_fingerprint)
        || valid_list_keys
            .iter()
            .any(|list_key| !current_list_keys.contains(list_key))
        || !evidence_matches
    {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    let Some(observation) = current_context.observation.as_ref() else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    let current_recovery = cache_store.get_output_poi_recovery(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &output_commitment,
    )?;
    if !recovery_matches_source(
        &expected_recovery,
        current_recovery.as_ref(),
        observation.tx_hash,
    ) {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }

    if matches!(subject_match, PendingOutputPoiSubjectMatch::External) {
        if expected_poi_list_state.is_some() {
            drop(permit);
            return Ok(PoiPrivateApplyOutcome::Skipped);
        }
        let workflow_candidate = wallet_ppoi_workflow_status_after_validation(
            &permit,
            cache_store,
            cfg,
            &active_list_keys,
            output_commitment,
        )?;
        let pending_deletes = [output_commitment];
        let recovery_deletes = [output_commitment];
        return commit_durable_apply(
            permit,
            cache_store,
            PoiPrivateRows {
                pending_deletes: &pending_deletes,
                recovery_deletes: &recovery_deletes,
                ..PoiPrivateRows::default()
            },
            workflow_candidate,
        );
    }

    let PendingOutputPoiSubject::Owned(expected_output) = subject else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    let Some(wallet_utxo) = snapshot
        .iter_mut()
        .find(|wallet_utxo| expected_output.matches(wallet_utxo))
    else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    let Some(expected_poi_list_state) = expected_poi_list_state else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    let poi_state_matches = match evidence {
        PendingOutputPoiValidationEvidence::SubmittedStatus => expected_poi_list_state
            .matches_recoverable_or_valid(&wallet_utxo.utxo.poi, &valid_list_keys),
        PendingOutputPoiValidationEvidence::OwnedStatusRefresh => {
            expected_poi_list_state.matches_valid(&wallet_utxo.utxo.poi, &valid_list_keys)
        }
    };
    if !poi_state_matches {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    let valid_statuses = valid_list_keys
        .iter()
        .copied()
        .map(|list_key| (list_key, PoiStatus::Valid))
        .collect::<BTreeMap<_, _>>();
    let refreshed_at = wallet_utxo
        .utxo
        .poi
        .refreshed_at
        .map_or(now, |current| current.max(now));
    let changed = wallet_utxo.utxo.poi.apply_status_refresh(
        &valid_list_keys,
        Some(&valid_statuses),
        refreshed_at,
    ) > 0;
    let recovery_action = if wallet_utxo
        .utxo
        .poi
        .has_recoverable_status_for_lists(&active_list_keys)
    {
        OutputPoiRecoveryAction::Detected {
            status: OutputPoiRecoveryStatus::Recoverable,
            retry_after: None,
            last_error: None,
            increment_attempts: false,
        }
    } else {
        OutputPoiRecoveryAction::Valid
    };
    let mut recovery = current_recovery.unwrap_or_else(|| {
        new_output_poi_recovery_record(
            cfg,
            wallet_utxo,
            output_poi_recovery_default_status(&recovery_action),
            now,
        )
    });
    recovery.apply_action(recovery_action, now);
    let workflow_candidate = wallet_ppoi_workflow_status_after_validation(
        &permit,
        cache_store,
        cfg,
        &active_list_keys,
        output_commitment,
    )?;
    let recovery_updates_owned = [recovery];
    let pending_deletes_owned = [output_commitment];
    commit_active_apply(
        permit,
        cache_store,
        ActiveApplyCommit {
            snapshot,
            utxos_changed: changed,
            rows: PoiPrivateRows {
                pending_deletes: &pending_deletes_owned,
                recovery_updates: &recovery_updates_owned,
                ..PoiPrivateRows::default()
            },
            workflow: Some(workflow_candidate),
        },
    )
    .await
}

pub(super) async fn apply_poi_status_refresh(
    turn: PoiApplyTurn<'_>,
    delta: PoiStatusRefreshDelta,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    let PoiApplyTurn {
        permit,
        mut snapshot,
        cache_store,
        ..
    } = turn;
    let PoiStatusRefreshDelta {
        active_list_keys,
        expected_poi_by_blinded_commitment,
        statuses_by_blinded_commitment,
        refreshed_at,
    } = delta;
    let mut changed = false;
    for wallet_utxo in snapshot.iter_mut().filter(|utxo| !utxo.is_spent()) {
        let Some(statuses) =
            statuses_by_blinded_commitment.get(&wallet_utxo.utxo.poi.blinded_commitment)
        else {
            continue;
        };
        if expected_poi_by_blinded_commitment.get(&wallet_utxo.utxo.poi.blinded_commitment)
            != Some(&wallet_utxo.utxo.poi)
        {
            continue;
        }
        changed |= wallet_utxo.utxo.poi.apply_status_refresh(
            &active_list_keys,
            Some(statuses),
            refreshed_at,
        ) > 0;
    }
    if !changed {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    commit_active_apply(
        permit,
        cache_store,
        ActiveApplyCommit {
            snapshot,
            utxos_changed: true,
            ..ActiveApplyCommit::default()
        },
    )
    .await
}
