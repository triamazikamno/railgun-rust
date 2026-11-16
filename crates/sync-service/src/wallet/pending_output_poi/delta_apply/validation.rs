//! Applying terminal, locally valid, verified valid and POI status refresh deltas.

use crate::wallet::pending_output_poi::workflow_status::wallet_ppoi_workflow_status_after_validation;
use crate::wallet::pending_output_poi::{
    BTreeMap, ExpectedPoiListState, ExpectedRecordState, FixedBytes, LocallyValidPendingListsDelta,
    OutputPoiRecoveryAction, OutputPoiRecoveryRecord, OutputPoiRecoveryStatus,
    PendingContextTerminalDelta, PendingOutputPoiContextRecord, PendingOutputPoiSubject,
    PendingOutputPoiSubjectMatch, PendingOutputPoiValidationEvidence, PoiPrivateApplyOutcome,
    PoiPrivateRows, PoiStatus, PoiStatusRefreshDelta, VerifiedValidDelta, WalletCacheError,
    WalletConfig, WalletPpoiWorkflowProjection, WalletPrivateMutationPermit, WalletUtxo,
    new_output_poi_recovery_record, output_poi_recovery_default_status,
    pending_output_poi_context_fingerprint, pending_output_poi_subject_matches_snapshot,
    poi_statuses_are_recoverable_for_lists,
};

use super::{
    ActiveApplyCommit, PendingOutputStore, PoiApplyTurn, commit_active_apply, commit_durable_apply,
    lists_are_active, recovery_matches_source,
};

/// A stored context, its snapshot match and its recovery, after a delta's checks.
struct CheckedPendingOutput {
    context: PendingOutputPoiContextRecord,
    subject_match: PendingOutputPoiSubjectMatch,
    recovery: Option<OutputPoiRecoveryRecord>,
}

impl PendingOutputStore<'_> {
    /// The checked pending output, when the context has an observation and the stored recovery
    /// is `expected_recovery` and came from the observed source transaction.
    fn checked(
        self,
        context: PendingOutputPoiContextRecord,
        subject_match: PendingOutputPoiSubjectMatch,
        expected_recovery: &ExpectedRecordState,
    ) -> Result<Option<CheckedPendingOutput>, WalletCacheError> {
        let Some(observation) = context.observation.as_ref() else {
            return Ok(None);
        };
        let recovery = self.recovery()?;
        if !recovery_matches_source(expected_recovery, recovery.as_ref(), observation.tx_hash) {
            return Ok(None);
        }
        Ok(Some(CheckedPendingOutput {
            context,
            subject_match,
            recovery,
        }))
    }

    fn workflow_after_validation(
        self,
        permit: &WalletPrivateMutationPermit<'_>,
        active_list_keys: &[FixedBytes<32>],
    ) -> Result<WalletPpoiWorkflowProjection, WalletCacheError> {
        wallet_ppoi_workflow_status_after_validation(
            permit,
            self.cache_store,
            self.cfg,
            active_list_keys,
            self.output_commitment,
        )
    }
}

/// Whether the context still has the expected fingerprint and names every list in
/// `valid_list_keys`.
fn context_matches_expected(
    context: &PendingOutputPoiContextRecord,
    expected_context_fingerprint: &[u8],
    valid_list_keys: &[FixedBytes<32>],
) -> bool {
    if pending_output_poi_context_fingerprint(context).as_deref()
        != Some(expected_context_fingerprint)
    {
        return false;
    }
    let context_list_keys = context.list_keys();
    valid_list_keys
        .iter()
        .all(|list_key| context_list_keys.contains(list_key))
}

/// The snapshot UTXO of an owned subject; `None` for an external subject or a missing UTXO.
fn owned_snapshot_output<'s>(
    subject: &PendingOutputPoiSubject,
    snapshot: &'s mut [WalletUtxo],
) -> Option<&'s mut WalletUtxo> {
    let PendingOutputPoiSubject::Owned(expected_output) = subject else {
        return None;
    };
    snapshot
        .iter_mut()
        .find(|wallet_utxo| expected_output.matches(wallet_utxo))
}

/// Marks the UTXO Valid on `valid_list_keys`, refreshed no earlier than `now`; whether its POI
/// changed.
fn mark_lists_valid(
    wallet_utxo: &mut WalletUtxo,
    valid_list_keys: &[FixedBytes<32>],
    now: u64,
) -> bool {
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
    wallet_utxo
        .utxo
        .poi
        .apply_status_refresh(valid_list_keys, Some(&valid_statuses), refreshed_at)
        > 0
}

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
    let store = PendingOutputStore {
        cache_store,
        cfg,
        output_commitment: delta.subject.output_commitment(),
    };
    let Some(checked) = check_pending_context_terminal(store, &snapshot, &delta)? else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    let mut current_context = checked.context;
    current_context.terminal_error = Some(delta.error);
    let pending_updates = [current_context];
    let rows = PoiPrivateRows {
        pending_updates: &pending_updates,
        ..PoiPrivateRows::default()
    };
    let workflow_status = store.workflow_after_mutations(&permit, &delta.active_list_keys, rows)?;
    commit_durable_apply(permit, cache_store, rows, workflow_status)
}

fn check_pending_context_terminal(
    store: PendingOutputStore<'_>,
    snapshot: &[WalletUtxo],
    delta: &PendingContextTerminalDelta,
) -> Result<Option<CheckedPendingOutput>, WalletCacheError> {
    if !lists_are_active(&delta.active_list_keys, &delta.target_list_keys) {
        return Ok(None);
    }
    let Some(context) = store.context()? else {
        return Ok(None);
    };
    if pending_output_poi_context_fingerprint(&context).as_ref()
        != Some(&delta.expected_context_fingerprint)
    {
        return Ok(None);
    }
    let Some(subject_match) =
        pending_output_poi_subject_matches_snapshot(store.cfg, snapshot, &context, &delta.subject)
    else {
        return Ok(None);
    };
    if subject_match
        .poi()
        .is_some_and(|poi| !poi_statuses_are_recoverable_for_lists(poi, &delta.target_list_keys))
    {
        return Ok(None);
    }
    store.checked(context, subject_match, &delta.expected_recovery)
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
    let store = PendingOutputStore {
        cache_store,
        cfg,
        output_commitment: delta.subject.output_commitment(),
    };
    let Some(checked) = check_locally_valid_pending_lists(store, &snapshot, &delta)? else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    let changed = if matches!(
        &checked.subject_match,
        PendingOutputPoiSubjectMatch::Owned(_)
    ) {
        let Some(wallet_utxo) = owned_snapshot_output(&delta.subject, &mut snapshot) else {
            drop(permit);
            return Ok(PoiPrivateApplyOutcome::Skipped);
        };
        mark_lists_valid(wallet_utxo, &delta.valid_list_keys, delta.now)
    } else {
        false
    };
    let pending_rows = locally_valid_rows(store, &delta, checked);
    let rows = pending_rows.private_rows();
    let workflow_status = store.workflow_after_mutations(&permit, &delta.active_list_keys, rows)?;
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

fn check_locally_valid_pending_lists(
    store: PendingOutputStore<'_>,
    snapshot: &[WalletUtxo],
    delta: &LocallyValidPendingListsDelta,
) -> Result<Option<CheckedPendingOutput>, WalletCacheError> {
    if !lists_are_active(&delta.active_list_keys, &delta.valid_list_keys) {
        return Ok(None);
    }
    let Some(context) = store.context()? else {
        return Ok(None);
    };
    if !context_matches_expected(
        &context,
        &delta.expected_context_fingerprint,
        &delta.valid_list_keys,
    ) {
        return Ok(None);
    }
    let Some(subject_match) =
        pending_output_poi_subject_matches_snapshot(store.cfg, snapshot, &context, &delta.subject)
    else {
        return Ok(None);
    };
    store.checked(context, subject_match, &delta.expected_recovery)
}

/// Pending and recovery rows a delta writes.
#[derive(Default)]
struct PendingRows {
    pending_updates: Vec<PendingOutputPoiContextRecord>,
    pending_deletes: Vec<FixedBytes<32>>,
    recovery_updates: Vec<OutputPoiRecoveryRecord>,
    recovery_deletes: Vec<FixedBytes<32>>,
}

impl PendingRows {
    fn private_rows(&self) -> PoiPrivateRows<'_> {
        PoiPrivateRows {
            pending_updates: &self.pending_updates,
            pending_deletes: &self.pending_deletes,
            recovery_updates: &self.recovery_updates,
            recovery_deletes: &self.recovery_deletes,
            ..PoiPrivateRows::default()
        }
    }
}

/// The rows a locally valid delta writes. The context keeps its other lists, or is deleted once
/// no active list remains; a completed owned output's recovery turns Valid, a completed external
/// output's recovery is deleted, and an incomplete output's Valid recovery is reopened.
fn locally_valid_rows(
    store: PendingOutputStore<'_>,
    delta: &LocallyValidPendingListsDelta,
    checked: CheckedPendingOutput,
) -> PendingRows {
    let CheckedPendingOutput {
        mut context,
        subject_match,
        recovery,
    } = checked;
    let valid_list_keys = &delta.valid_list_keys;
    context
        .required_poi_list_keys
        .retain(|list_key| !valid_list_keys.contains(list_key));
    context
        .pre_transaction_pois_per_txid_leaf_per_list
        .retain(|list_key, _| !valid_list_keys.contains(list_key));
    context
        .submitted_poi_list_keys
        .retain(|list_key| !valid_list_keys.contains(list_key));
    if context
        .list_keys()
        .into_iter()
        .any(|list_key| delta.active_list_keys.contains(&list_key))
    {
        return PendingRows {
            pending_updates: vec![context],
            recovery_updates: reopened_recovery(recovery, delta.now).into_iter().collect(),
            ..PendingRows::default()
        };
    }
    let mut rows = PendingRows {
        pending_deletes: vec![store.output_commitment],
        ..PendingRows::default()
    };
    match subject_match {
        PendingOutputPoiSubjectMatch::Owned(wallet_output) => {
            let mut recovery = recovery.unwrap_or_else(|| {
                new_output_poi_recovery_record(
                    store.cfg,
                    &wallet_output,
                    OutputPoiRecoveryStatus::Valid,
                    delta.now,
                )
            });
            recovery.apply_action(OutputPoiRecoveryAction::Valid, delta.now);
            rows.recovery_updates.push(recovery);
        }
        PendingOutputPoiSubjectMatch::External => {
            rows.recovery_deletes.push(store.output_commitment);
        }
    }
    rows
}

/// A Valid recovery reopened as Recoverable, because its output still has active lists to prove.
fn reopened_recovery(
    recovery: Option<OutputPoiRecoveryRecord>,
    now: u64,
) -> Option<OutputPoiRecoveryRecord> {
    let mut recovery =
        recovery.filter(|recovery| recovery.status == OutputPoiRecoveryStatus::Valid)?;
    recovery.apply_action(
        OutputPoiRecoveryAction::Detected {
            status: OutputPoiRecoveryStatus::Recoverable,
            retry_after: None,
            last_error: None,
            increment_attempts: false,
        },
        now,
    );
    Some(recovery)
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
    let store = PendingOutputStore {
        cache_store,
        cfg,
        output_commitment: delta.subject.output_commitment(),
    };
    let Some(checked) = check_verified_valid(store, &snapshot, &delta)? else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    if matches!(
        checked.subject_match,
        PendingOutputPoiSubjectMatch::External
    ) {
        if delta.expected_poi_list_state.is_some() {
            drop(permit);
            return Ok(PoiPrivateApplyOutcome::Skipped);
        }
        return commit_verified_external(permit, store, &delta.active_list_keys);
    }
    let Some(wallet_utxo) = owned_snapshot_output(&delta.subject, &mut snapshot) else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    let Some(expected_poi_list_state) = delta.expected_poi_list_state.as_ref() else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    if !owned_poi_state_matches(&delta, expected_poi_list_state, wallet_utxo) {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    let changed = mark_lists_valid(wallet_utxo, &delta.valid_list_keys, delta.now);
    let recovery = verified_recovery(cfg, wallet_utxo, checked.recovery, &delta);
    let workflow_candidate = store.workflow_after_validation(&permit, &delta.active_list_keys)?;
    let recovery_updates_owned = [recovery];
    let pending_deletes_owned = [store.output_commitment];
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

fn check_verified_valid(
    store: PendingOutputStore<'_>,
    snapshot: &[WalletUtxo],
    delta: &VerifiedValidDelta,
) -> Result<Option<CheckedPendingOutput>, WalletCacheError> {
    let Some(context) = store.context()? else {
        return Ok(None);
    };
    let Some(subject_match) =
        pending_output_poi_subject_matches_snapshot(store.cfg, snapshot, &context, &delta.subject)
    else {
        return Ok(None);
    };
    let evidence_matches = verified_evidence_matches(delta, &context, &subject_match);
    if !lists_are_active(&delta.active_list_keys, &delta.valid_list_keys)
        || !context_matches_expected(
            &context,
            &delta.expected_context_fingerprint,
            &delta.valid_list_keys,
        )
    {
        return Ok(None);
    }
    if !evidence_matches {
        return Ok(None);
    }
    store.checked(context, subject_match, &delta.expected_recovery)
}

/// Whether the delta's evidence holds: every valid list was recorded as submitted, or the owned
/// output's POI was refreshed as Valid on them.
fn verified_evidence_matches(
    delta: &VerifiedValidDelta,
    context: &PendingOutputPoiContextRecord,
    subject_match: &PendingOutputPoiSubjectMatch,
) -> bool {
    let submitted_lists_match = delta
        .valid_list_keys
        .iter()
        .all(|list_key| context.submitted_poi_list_keys.contains(list_key));
    match delta.evidence {
        PendingOutputPoiValidationEvidence::SubmittedStatus => submitted_lists_match,
        PendingOutputPoiValidationEvidence::OwnedStatusRefresh => {
            matches!(
                subject_match,
                PendingOutputPoiSubjectMatch::Owned(output)
                    if delta.expected_poi_list_state.as_ref().is_some_and(|expected| {
                        expected.matches_valid(&output.utxo.poi, &delta.valid_list_keys)
                    })
            )
        }
    }
}

/// Deletes a verified external output's context and recovery durably.
fn commit_verified_external(
    permit: WalletPrivateMutationPermit<'_>,
    store: PendingOutputStore<'_>,
    active_list_keys: &[FixedBytes<32>],
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    let workflow_candidate = store.workflow_after_validation(&permit, active_list_keys)?;
    let pending_deletes = [store.output_commitment];
    let recovery_deletes = [store.output_commitment];
    commit_durable_apply(
        permit,
        store.cache_store,
        PoiPrivateRows {
            pending_deletes: &pending_deletes,
            recovery_deletes: &recovery_deletes,
            ..PoiPrivateRows::default()
        },
        workflow_candidate,
    )
}

/// Whether the owned UTXO's POI is in the state the evidence expects on the valid lists.
fn owned_poi_state_matches(
    delta: &VerifiedValidDelta,
    expected_poi_list_state: &ExpectedPoiListState,
    wallet_utxo: &WalletUtxo,
) -> bool {
    match delta.evidence {
        PendingOutputPoiValidationEvidence::SubmittedStatus => expected_poi_list_state
            .matches_recoverable_or_valid(&wallet_utxo.utxo.poi, &delta.valid_list_keys),
        PendingOutputPoiValidationEvidence::OwnedStatusRefresh => {
            expected_poi_list_state.matches_valid(&wallet_utxo.utxo.poi, &delta.valid_list_keys)
        }
    }
}

/// The owned output's recovery after verification: Valid, or Recoverable while an active list is
/// still recoverable on its refreshed POI.
fn verified_recovery(
    cfg: &WalletConfig,
    wallet_utxo: &WalletUtxo,
    current_recovery: Option<OutputPoiRecoveryRecord>,
    delta: &VerifiedValidDelta,
) -> OutputPoiRecoveryRecord {
    let recovery_action = if wallet_utxo
        .utxo
        .poi
        .has_recoverable_status_for_lists(&delta.active_list_keys)
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
            delta.now,
        )
    });
    recovery.apply_action(recovery_action, delta.now);
    recovery
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
