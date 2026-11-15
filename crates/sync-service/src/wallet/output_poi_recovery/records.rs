//! Output recovery and pending-context records and their persistence.

use crate::wallet::{
    BTreeMap, PendingOutputPoiObservation, PendingOutputPoiRole, PreTransactionPoiMap,
};

use super::{
    Arc, DEFAULT_TXID_VERSION, DbStore, ExpectedPoiStatus, ExpectedWalletOutput, FixedBytes,
    OutputPoiRecoveryAction, OutputPoiRecoveryRecord, OutputPoiRecoveryStatus, OutputRecoveryDelta,
    OwnedPoiPrivateDelta, PendingOutputPoiContextRecord, RecoveryChunk, RecoveryFailure, RwLock,
    Utxo, UtxoCommitmentKind, WalletCacheStore, WalletConfig, WalletPrivateMutationAuthority,
    WalletUtxo, apply_poi_private_delta, debug, expected_recovery_state, hex, now_epoch_secs, warn,
};

pub(in crate::wallet) fn pending_output_poi_context_from_recovery(
    cfg: &WalletConfig,
    candidate: &WalletUtxo,
    recovery_chunk: &RecoveryChunk,
    txid_merkleroot_index: u64,
    pre_transaction_pois: PreTransactionPoiMap,
    active_list_keys: &[FixedBytes<32>],
    now: u64,
) -> PendingOutputPoiContextRecord {
    pending_output_poi_context_from_output_recovery(
        cfg,
        &candidate.utxo,
        recovery_chunk,
        txid_merkleroot_index,
        pre_transaction_pois,
        active_list_keys,
        PendingOutputPoiRole::Change,
        format!(
            "recovered-output-poi:{}",
            hex::encode(candidate.utxo.source.tx_hash)
        ),
        now,
    )
}

pub(in crate::wallet) fn pending_output_poi_context_from_output_recovery(
    cfg: &WalletConfig,
    output: &Utxo,
    recovery_chunk: &RecoveryChunk,
    txid_merkleroot_index: u64,
    pre_transaction_pois: PreTransactionPoiMap,
    active_list_keys: &[FixedBytes<32>],
    output_role: PendingOutputPoiRole,
    source_operation_id: String,
    now: u64,
) -> PendingOutputPoiContextRecord {
    PendingOutputPoiContextRecord {
        chain_id: cfg.chain.chain_id,
        wallet_id: cfg.cache_key.to_string(),
        txid_version: DEFAULT_TXID_VERSION.to_string(),
        output_commitment: output.poi.commitment,
        output_npk: output.poi.npk,
        utxo_tree_in: u64::from(recovery_chunk.chunk.tree_number),
        railgun_txid: recovery_chunk.chunk.railgun_txid(),
        txid_merkleroot_index: Some(txid_merkleroot_index),
        pre_transaction_pois_per_txid_leaf_per_list: pre_transaction_pois,
        required_poi_list_keys: active_list_keys.to_vec(),
        output_role,
        created_at: now,
        source_operation_id: Some(source_operation_id),
        observation: Some(PendingOutputPoiObservation {
            output_tree: u64::from(output.tree),
            output_position: output.position,
            tx_hash: output.source.tx_hash,
            block_number: output.source.block_number,
            block_timestamp: output.source.block_timestamp,
        }),
        submitted_poi_list_keys: Vec::new(),
        terminal_error: None,
    }
}

pub(in crate::wallet) fn newly_recoverable_output_poi_list_keys(
    context: &PendingOutputPoiContextRecord,
    recoverable_list_keys: &[FixedBytes<32>],
) -> Vec<FixedBytes<32>> {
    let represented_list_keys = context.list_keys();
    recoverable_list_keys
        .iter()
        .copied()
        .filter(|list_key| !represented_list_keys.contains(list_key))
        .collect()
}

pub(in crate::wallet) fn extend_pending_output_poi_context(
    context: &PendingOutputPoiContextRecord,
    new_list_keys: &[FixedBytes<32>],
    mut new_pre_transaction_pois: PreTransactionPoiMap,
) -> PendingOutputPoiContextRecord {
    let mut extended = context.clone();
    extended
        .pre_transaction_pois_per_txid_leaf_per_list
        .retain(|list_key, per_leaf| {
            crate::wallet::saved_poi_compatibility::saved_poi_map_is_compatible(
                &BTreeMap::from([(*list_key, per_leaf.clone())]),
                &[*list_key],
            )
        });
    extended.submitted_poi_list_keys.retain(|list_key| {
        extended
            .pre_transaction_pois_per_txid_leaf_per_list
            .contains_key(list_key)
    });
    if extended.required_poi_list_keys.is_empty() {
        extended.required_poi_list_keys = extended.list_keys();
    }
    for list_key in new_list_keys {
        if let Some(per_leaf) = new_pre_transaction_pois.remove(list_key) {
            extended
                .pre_transaction_pois_per_txid_leaf_per_list
                .insert(*list_key, per_leaf);
        }
        if !extended.required_poi_list_keys.contains(list_key) {
            extended.required_poi_list_keys.push(*list_key);
        }
    }
    extended
}

pub(in crate::wallet) fn log_forced_output_poi_recovery_regeneration(
    cfg: &WalletConfig,
    _candidate: &WalletUtxo,
    _existing_pending_context: &PendingOutputPoiContextRecord,
) {
    debug!(
        chain_id = cfg.chain.chain_id,
        "force-regenerating recovered output POI context"
    );
}

pub(in crate::wallet) fn new_output_poi_recovery_record(
    cfg: &WalletConfig,
    candidate: &WalletUtxo,
    status: OutputPoiRecoveryStatus,
    now: u64,
) -> OutputPoiRecoveryRecord {
    new_output_poi_recovery_record_for_output(cfg, &candidate.utxo, status, now)
}

pub(in crate::wallet) fn new_output_poi_recovery_record_for_output(
    cfg: &WalletConfig,
    output: &Utxo,
    status: OutputPoiRecoveryStatus,
    now: u64,
) -> OutputPoiRecoveryRecord {
    OutputPoiRecoveryRecord {
        chain_id: cfg.chain.chain_id,
        wallet_id: cfg.cache_key.to_string(),
        output_commitment: output.poi.commitment,
        source_tx_hash: output.source.tx_hash,
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

pub(in crate::wallet) async fn record_output_poi_recovery_failure(
    authority: &WalletPrivateMutationAuthority<'_>,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    candidate: &WalletUtxo,
    active_list_keys: &[FixedBytes<32>],
    target_list_keys: &[FixedBytes<32>],
    failure: RecoveryFailure,
    now: u64,
) {
    let status = failure.status;
    let message = failure.message;
    let Ok(current_recovery) = cache_store.get_output_poi_recovery(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &candidate.utxo.poi.commitment,
    ) else {
        warn!(
            chain_id = cfg.chain.chain_id,
            "failed to load output POI recovery failure predecessor"
        );
        return;
    };
    let Some(expected_recovery) = expected_recovery_state(current_recovery.as_ref()) else {
        return;
    };
    if apply_poi_private_delta(
        authority,
        db,
        cache_store,
        cfg,
        OwnedPoiPrivateDelta::OutputRecovery(OutputRecoveryDelta {
            expected_output: ExpectedWalletOutput::new(candidate),
            active_list_keys: active_list_keys.to_vec(),
            target_list_keys: target_list_keys.to_vec(),
            required_poi_status: ExpectedPoiStatus::Recoverable,
            pending_update: Box::new(None),
            expected_recovery,
            action: OutputPoiRecoveryAction::Detected {
                status,
                retry_after: failure.retry_after,
                last_error: Some(message.clone()),
                increment_attempts: true,
            },
            now,
            expected_corpus: None,
            replay_fence: None,
        }),
    )
    .await
    .is_err()
    {
        warn!(
            chain_id = cfg.chain.chain_id,
            "failed to persist output POI recovery failure state"
        );
    }
    debug!(
        chain_id = cfg.chain.chain_id,
        status = ?status,
        "output POI recovery skipped"
    );
}

pub(in crate::wallet) async fn mark_valid_output_poi_recoveries(
    authority: &WalletPrivateMutationAuthority<'_>,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    wallet_utxos: &[WalletUtxo],
    active_list_keys: &[FixedBytes<32>],
) {
    if active_list_keys.is_empty() {
        return;
    }
    let now = now_epoch_secs();
    for wallet_utxo in wallet_utxos.iter().filter(|wallet_utxo| {
        !wallet_utxo.is_spent()
            && wallet_utxo.utxo.poi.is_valid_for_lists(active_list_keys)
            && wallet_utxo.utxo.poi.commitment_kind == UtxoCommitmentKind::Transact
    }) {
        let Ok(Some(record)) = cache_store.get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &wallet_utxo.utxo.poi.commitment,
        ) else {
            continue;
        };
        if record.status == OutputPoiRecoveryStatus::Valid {
            continue;
        }
        let Some(expected_recovery) = expected_recovery_state(Some(&record)) else {
            continue;
        };
        if apply_poi_private_delta(
            authority,
            db,
            cache_store,
            cfg,
            OwnedPoiPrivateDelta::OutputRecovery(OutputRecoveryDelta {
                expected_output: ExpectedWalletOutput::new(wallet_utxo),
                active_list_keys: active_list_keys.to_vec(),
                target_list_keys: active_list_keys.to_vec(),
                required_poi_status: ExpectedPoiStatus::Valid,
                pending_update: Box::new(None),
                expected_recovery,
                action: OutputPoiRecoveryAction::Valid,
                now,
                expected_corpus: None,
                replay_fence: None,
            }),
        )
        .await
        .is_err()
        {
            warn!(
                chain_id = cfg.chain.chain_id,
                "failed to mark output POI recovery valid"
            );
        }
    }
}

pub(in crate::wallet) async fn mark_valid_output_poi_recoveries_authorized(
    authority: &WalletPrivateMutationAuthority<'_>,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    utxos: &Arc<RwLock<Vec<WalletUtxo>>>,
    active_list_keys: &[FixedBytes<32>],
) {
    if authority.revalidate().is_err() {
        debug!(
            chain_id = cfg.chain.chain_id,
            "mark output POI recoveries valid skipped"
        );
        return;
    }
    let snapshot = utxos.read().await.clone();
    mark_valid_output_poi_recoveries(authority, db, cache_store, cfg, &snapshot, active_list_keys)
        .await;
}
