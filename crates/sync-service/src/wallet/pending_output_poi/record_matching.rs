#[allow(clippy::wildcard_imports)]
use super::*;

pub(in crate::wallet) fn new_pending_output_poi_recovery_record(
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

pub(super) fn expected_poi_status_matches(
    poi: &UtxoPoiMetadata,
    list_keys: &[FixedBytes<32>],
    expected: ExpectedPoiStatus,
) -> bool {
    match expected {
        ExpectedPoiStatus::Recoverable => poi_statuses_are_recoverable_for_lists(poi, list_keys),
        ExpectedPoiStatus::Valid => poi.is_valid_for_lists(list_keys),
    }
}

pub(super) fn poi_statuses_are_recoverable_for_lists(
    poi: &UtxoPoiMetadata,
    list_keys: &[FixedBytes<32>],
) -> bool {
    list_keys.iter().all(|list_key| {
        poi.statuses
            .get(list_key)
            .is_none_or(|status| status.is_recoverable())
    })
}

pub(super) fn sender_materialization_pending_matches(
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

pub(super) fn sender_materialization_recovery_matches(
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

pub(super) fn expected_pending_context_matches(
    expected: &ExpectedRecordState,
    current: Option<&PendingOutputPoiContextRecord>,
) -> bool {
    expected_record_matches(expected, current)
}

pub(super) fn expected_recovery_matches(
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

pub(super) fn pending_submission_predicate_matches(
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

pub(super) fn prune_nonrecoverable_unsubmitted_poi_lists(
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

pub(in crate::wallet) const fn output_poi_recovery_default_status(
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

pub(in crate::wallet) fn pending_output_poi_context_fingerprint(
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

pub(in crate::wallet) fn expected_pending_context_state(
    record: Option<&PendingOutputPoiContextRecord>,
) -> Option<ExpectedRecordState> {
    expected_record_state(record)
}

pub(in crate::wallet) fn expected_recovery_state(
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
