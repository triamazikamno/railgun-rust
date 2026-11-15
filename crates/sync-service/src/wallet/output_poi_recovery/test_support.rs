use super::*;
use crate::wallet::pending_output_poi::test_support::{
    pending_output_poi_context_still_current_unchecked, pending_output_poi_recovery_update,
    submit_pending_output_poi_context,
};
use crate::wallet::{
    PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER, PendingOutputPoiSubmitter,
    SingleCommitmentProofContext,
};
pub(in crate::wallet) use public_cache::{
    PublicCacheTxidRecoveryRequest, recovered_output_txid_data_from_public_cache,
};

async fn force_resubmit_matching_pending_output_pois_unchecked(
    db: &DbStore,
    cfg: &WalletConfig,
    wallet_utxos: &[WalletUtxo],
    active_list_keys: &[FixedBytes<32>],
    submitter: &dyn PendingOutputPoiSubmitter,
) -> usize {
    if active_list_keys.is_empty() {
        return 0;
    }

    let now = now_epoch_secs();
    let mut attempted_contexts = 0usize;
    for candidate in output_poi_recovery_candidates(wallet_utxos, active_list_keys) {
        let output_commitment = candidate.utxo.poi.commitment;
        let mut record = match db.get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &output_commitment,
        ) {
            Ok(Some(record)) => record,
            Ok(None) => continue,
            Err(_) => {
                warn!(
                    chain_id = cfg.chain.chain_id,
                    "failed to load matching pending output POI context"
                );
                continue;
            }
        };
        if record.terminal_error.is_some()
            || !pending_output_poi_context_matches_wallet_utxo(cfg, candidate, &record)
        {
            continue;
        }

        let mut submitted_list_keys = record.list_keys();
        submitted_list_keys.retain(|list_key| active_list_keys.contains(list_key));
        if submitted_list_keys.is_empty() {
            continue;
        }
        let pre_transaction_pois = record.retain_poi_lists(&submitted_list_keys);
        if pre_transaction_pois.len() != submitted_list_keys.len() {
            record.terminal_error =
                Some("missing pre-transaction POI for pending output".to_string());
            if db.put_pending_output_poi_context(&record).is_err() {
                warn!(
                    chain_id = cfg.chain.chain_id,
                    "failed to mark pending output POI context terminal"
                );
            }
            continue;
        }
        let Some(observation) = record.observation.clone() else {
            continue;
        };
        let context = SingleCommitmentProofContext {
            txid_version: record.txid_version.clone(),
            railgun_txid: record.railgun_txid,
            utxo_tree_in: record.utxo_tree_in,
            commitment: record.output_commitment,
            npk: record.output_npk,
            pre_transaction_pois_per_txid_leaf_per_list: pre_transaction_pois,
        };
        attempted_contexts += 1;
        match submit_pending_output_poi_context(
            submitter,
            cfg.chain.chain_id,
            &record,
            &context,
            &observation,
            &submitted_list_keys,
        )
        .await
        {
            Ok(()) => {
                match pending_output_poi_context_still_current_unchecked(
                    db,
                    cfg.chain.chain_id,
                    &cfg.cache_key,
                    &record,
                ) {
                    Ok(true) => {}
                    Ok(false) => continue,
                    Err(_) => {
                        warn!(
                            chain_id = cfg.chain.chain_id,
                            "failed to revalidate resubmitted pending output POI context"
                        );
                        continue;
                    }
                }
                for list_key in &submitted_list_keys {
                    if !record.submitted_poi_list_keys.contains(list_key) {
                        record.submitted_poi_list_keys.push(*list_key);
                    }
                }
                let Ok(pending_recovery) = pending_output_poi_recovery_update(
                    db,
                    cfg.chain.chain_id,
                    &record,
                    &observation,
                    now,
                    OutputPoiRecoveryAction::Submitted {
                        retry_after: PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER,
                    },
                ) else {
                    warn!(
                        chain_id = cfg.chain.chain_id,
                        "failed to prepare resubmitted pending output POI recovery state"
                    );
                    continue;
                };
                let mut recovery_updates = vec![pending_recovery];
                if record.wallet_id != cfg.cache_key.as_str() {
                    recovery_updates.push(output_poi_recovery_record_update(
                        db,
                        cfg,
                        candidate,
                        now,
                        OutputPoiRecoveryAction::Submitted {
                            retry_after: OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
                        },
                    ));
                }
                if db.put_pending_output_poi_context(&record).is_err() {
                    warn!(
                        chain_id = cfg.chain.chain_id,
                        "failed to persist resubmitted pending output POI context"
                    );
                    continue;
                }
                for recovery in &recovery_updates {
                    if db.put_output_poi_recovery(recovery).is_err() {
                        warn!(
                            chain_id = cfg.chain.chain_id,
                            "failed to persist resubmitted pending output POI recovery state"
                        );
                    }
                }
            }
            Err(err) => {
                match pending_output_poi_context_still_current_unchecked(
                    db,
                    cfg.chain.chain_id,
                    &cfg.cache_key,
                    &record,
                ) {
                    Ok(true) => {}
                    Ok(false) => continue,
                    Err(_) => {
                        warn!(
                            chain_id = cfg.chain.chain_id,
                            "failed to revalidate failed pending output POI resubmission"
                        );
                        continue;
                    }
                }
                let recovery = output_poi_recovery_record_update(
                    db,
                    cfg,
                    candidate,
                    now,
                    OutputPoiRecoveryAction::SubmitFailed {
                        error: err.to_string(),
                        retry_after: OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
                    },
                );
                if db.put_output_poi_recovery(&recovery).is_err() {
                    warn!(
                        chain_id = cfg.chain.chain_id,
                        "failed to persist failed pending output POI resubmission state"
                    );
                }
                warn!(
                    chain_id = cfg.chain.chain_id,
                    "forced pending output POI resubmission failed"
                );
            }
        }
    }

    attempted_contexts
}

pub(in crate::wallet) async fn force_resubmit_matching_pending_output_pois(
    db: &DbStore,
    cfg: &WalletConfig,
    wallet_utxos: &[WalletUtxo],
    active_list_keys: &[FixedBytes<32>],
    submitter: &dyn PendingOutputPoiSubmitter,
) -> usize {
    force_resubmit_matching_pending_output_pois_unchecked(
        db,
        cfg,
        wallet_utxos,
        active_list_keys,
        submitter,
    )
    .await
}

pub(super) fn output_poi_recovery_record_update(
    db: &DbStore,
    cfg: &WalletConfig,
    candidate: &WalletUtxo,
    now: u64,
    action: OutputPoiRecoveryAction,
) -> OutputPoiRecoveryRecord {
    let existing = db
        .get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &candidate.utxo.poi.commitment,
        )
        .ok()
        .flatten();
    let default_status = match &action {
        OutputPoiRecoveryAction::Detected { status, .. } => *status,
        OutputPoiRecoveryAction::CacheTxInput { .. } | OutputPoiRecoveryAction::ExtendContext => {
            OutputPoiRecoveryStatus::Recoverable
        }
        OutputPoiRecoveryAction::Submitted { .. } => OutputPoiRecoveryStatus::Submitted,
        OutputPoiRecoveryAction::SubmitFailed { .. } => OutputPoiRecoveryStatus::SubmitFailed,
        OutputPoiRecoveryAction::Valid => OutputPoiRecoveryStatus::Valid,
    };
    let mut record = existing
        .unwrap_or_else(|| new_output_poi_recovery_record(cfg, candidate, default_status, now));
    record.apply_action(action, now);
    record
}
