use std::sync::Arc;

use crate::SenderTransactionCandidate;

use super::{
    BTreeMap, FixedBytes, OutputPoiRecoveryRecord, OutputPoiRecoveryStatus,
    PendingOutputPoiContextRecord, PendingOutputPoiRole, WalletCacheError, WalletCacheStore,
    WalletConfig, WalletPpoiSubmissionStatus, WalletPpoiWorkflowStatus,
    WalletPrivateMutationPermit, saved_pending_context_is_compatible,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::wallet) struct WalletPpoiWorkflowProjection {
    pub(in crate::wallet) status: WalletPpoiWorkflowStatus,
    pub(in crate::wallet) submissions: Arc<[WalletPpoiSubmissionStatus]>,
}

/// Private POI rows one commit writes; rows left at the default write nothing.
#[derive(Clone, Copy, Default)]
pub(in crate::wallet) struct PoiPrivateRows<'a> {
    pub(in crate::wallet) pending_updates: &'a [PendingOutputPoiContextRecord],
    pub(in crate::wallet) pending_deletes: &'a [FixedBytes<32>],
    pub(in crate::wallet) recovery_updates: &'a [OutputPoiRecoveryRecord],
    pub(in crate::wallet) recovery_deletes: &'a [FixedBytes<32>],
    pub(in crate::wallet) candidate_updates: &'a [SenderTransactionCandidate],
    pub(in crate::wallet) candidate_deletes: &'a [FixedBytes<32>],
}

pub(in crate::wallet) fn wallet_ppoi_workflow_status_after_mutations(
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    validation_revision: u64,
    rows: PoiPrivateRows<'_>,
) -> Result<WalletPpoiWorkflowProjection, WalletCacheError> {
    let mut recoveries = cache_store
        .list_output_poi_recoveries(cfg.chain.chain_id, &cfg.cache_key)?
        .into_iter()
        .map(|record| (record.output_commitment, record))
        .collect::<BTreeMap<_, _>>();
    for recovery in rows.recovery_updates {
        recoveries.insert(recovery.output_commitment, recovery.clone());
    }
    for output_commitment in rows.recovery_deletes {
        recoveries.remove(output_commitment);
    }
    let mut contexts = cache_store
        .list_pending_output_poi_contexts(cfg.chain.chain_id, &cfg.cache_key)?
        .into_iter()
        .map(|record| (record.output_commitment, record))
        .collect::<BTreeMap<_, _>>();
    for context in rows.pending_updates {
        contexts.insert(context.output_commitment, context.clone());
    }
    for output_commitment in rows.pending_deletes {
        contexts.remove(output_commitment);
    }
    let mut candidates = cache_store
        .list_sender_transaction_candidates(cfg.chain.chain_id, &cfg.cache_key)?
        .into_iter()
        .map(|candidate| (candidate.semantic_id(), candidate))
        .collect::<BTreeMap<_, _>>();
    for candidate in rows.candidate_updates {
        candidates.insert(candidate.semantic_id(), candidate.clone());
    }
    for candidate_id in rows.candidate_deletes {
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

pub(super) fn wallet_ppoi_workflow_status_after_validation(
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
        PoiPrivateRows {
            pending_deletes: &pending_deletes,
            recovery_deletes: &recovery_deletes,
            ..PoiPrivateRows::default()
        },
    )
}
