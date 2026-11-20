use super::*;

#[test]
fn opaque_wallet_private_v2_rows_are_isolated_by_namespace_and_kind() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let first = WalletPrivateNamespaceId::new(1, wallet_cache_key(0x31));
    let second = WalletPrivateNamespaceId::new(1, wallet_cache_key(0x32));
    let semantic_output_commitment = FixedBytes::from([0xcc; 32]);
    let row = OpaqueWalletPrivateRow {
        row_id: vec![0x10, 0x20, 0x30],
        payload: b"opaque-ciphertext".to_vec(),
    };
    assert_ne!(row.row_id, semantic_output_commitment.as_slice());

    store
        .put_opaque_wallet_private_row(
            &first,
            WalletPrivateRecordKind::PendingOutputPoiContext,
            &row,
        )
        .expect("put first pending row");
    store
        .put_opaque_wallet_private_row(
            &second,
            WalletPrivateRecordKind::PendingOutputPoiContext,
            &OpaqueWalletPrivateRow {
                row_id: row.row_id.clone(),
                payload: b"other-wallet".to_vec(),
            },
        )
        .expect("put second pending row");
    store
        .put_opaque_wallet_private_row(
            &first,
            WalletPrivateRecordKind::OutputPoiRecovery,
            &OpaqueWalletPrivateRow {
                row_id: row.row_id.clone(),
                payload: b"other-kind".to_vec(),
            },
        )
        .expect("put first recovery row");

    assert_eq!(
        store
            .get_opaque_wallet_private_row(
                &first,
                WalletPrivateRecordKind::PendingOutputPoiContext,
                &row.row_id,
            )
            .expect("get first pending row"),
        Some(row.clone())
    );
    assert_eq!(
        store
            .list_opaque_wallet_private_rows(
                &second,
                WalletPrivateRecordKind::PendingOutputPoiContext,
            )
            .expect("list second pending rows")[0]
            .payload,
        b"other-wallet"
    );
    assert_eq!(
        store
            .list_opaque_wallet_private_rows(&first, WalletPrivateRecordKind::OutputPoiRecovery,)
            .expect("list first recovery rows")[0]
            .payload,
        b"other-kind"
    );

    let txn = store.db.begin_read().expect("begin raw v2 read");
    let pending_table = txn
        .open_table(PENDING_OUTPUT_POI_CONTEXT_V2_TABLE)
        .expect("open pending v2 table");
    for entry in pending_table.iter().expect("iterate pending v2 rows") {
        let (key, _) = entry.expect("read pending v2 row");
        assert!(
            !key.value()
                .contains(&alloy::hex::encode(semantic_output_commitment))
        );
    }
    drop(pending_table);
    drop(txn);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn opaque_wallet_private_rows_commit_atomically_with_plaintext_state() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let namespace = WalletPrivateNamespaceId::new(1, wallet_cache_key(0x33));
    let meta = WalletMeta {
        last_scanned_block: 55,
        updated_at: 10,
        last_scanned_block_hash: Some([0x44; 32]),
    };
    let actor_state = WalletSyncActorStateRecord {
        chain_id: namespace.chain_id,
        wallet_id: namespace.wallet_id.to_string(),
        highest_accepted_reset_intent: 9,
        pending_reset: None,
        updated_at: 11,
    };
    let pending = [OpaqueWalletPrivateRow {
        row_id: vec![0x01],
        payload: b"pending-ciphertext".to_vec(),
    }];
    let recoveries = [OpaqueWalletPrivateRow {
        row_id: vec![0x02],
        payload: b"recovery-ciphertext".to_vec(),
    }];
    let candidate_delete_id = vec![0x03];
    let candidate_update_id = vec![0x04];
    store
        .put_opaque_wallet_private_row(
            &namespace,
            WalletPrivateRecordKind::SenderTransactionCandidate,
            &OpaqueWalletPrivateRow {
                row_id: candidate_delete_id.clone(),
                payload: b"candidate-delete".to_vec(),
            },
        )
        .expect("seed candidate to delete");
    store
        .put_opaque_wallet_private_row(
            &namespace,
            WalletPrivateRecordKind::SenderTransactionCandidate,
            &OpaqueWalletPrivateRow {
                row_id: candidate_update_id.clone(),
                payload: b"candidate-old".to_vec(),
            },
        )
        .expect("seed candidate to update");
    let candidate_updates = [OpaqueWalletPrivateRow {
        row_id: candidate_update_id.clone(),
        payload: b"candidate-new".to_vec(),
    }];
    let candidate_deletes = [candidate_delete_id.clone()];
    let batch = WalletPrivateStateBatch {
        namespace: &namespace,
        utxos: WalletUtxoRowMutation::Preserve,
        metadata: WalletMetaMutation::Set(&meta),
        sync_actor_state: Some(&actor_state),
        pending_output_contexts: OpaqueWalletPrivateRowMutation {
            updates: &pending,
            deletes: &[],
        },
        output_poi_recoveries: OpaqueWalletPrivateRowMutation {
            updates: &recoveries,
            deletes: &[],
        },
        sender_transaction_candidates: OpaqueWalletPrivateRowMutation {
            updates: &candidate_updates,
            deletes: &candidate_deletes,
        },
    };

    let result: Result<(), DbError> = store.batch_commit_wallet_private_state_with(&batch, |_| {
        Err(DbError::Io(std::io::Error::other("injected failure")))
    });
    assert!(result.is_err());
    assert!(
        store
            .get_wallet_meta(&namespace.wallet_id)
            .expect("load rolled-back metadata")
            .is_none()
    );
    assert_eq!(
        store
            .list_opaque_wallet_private_rows(
                &namespace,
                WalletPrivateRecordKind::PendingOutputPoiContext,
            )
            .expect("list rolled-back pending rows"),
        [] as [OpaqueWalletPrivateRow; 0]
    );
    assert_eq!(
        store
            .get_opaque_wallet_private_row(
                &namespace,
                WalletPrivateRecordKind::SenderTransactionCandidate,
                &candidate_update_id,
            )
            .expect("load rolled-back candidate update")
            .expect("rolled-back candidate present")
            .payload,
        b"candidate-old"
    );
    assert!(
        store
            .get_opaque_wallet_private_row(
                &namespace,
                WalletPrivateRecordKind::SenderTransactionCandidate,
                &candidate_delete_id,
            )
            .expect("load rolled-back candidate delete")
            .is_some()
    );

    store
        .batch_commit_wallet_private_state(&batch)
        .expect("commit private state batch");
    assert_eq!(
        store
            .get_wallet_meta(&namespace.wallet_id)
            .expect("load committed metadata")
            .expect("metadata present")
            .last_scanned_block,
        55
    );
    assert_eq!(
        store
            .get_wallet_sync_actor_state(namespace.chain_id, namespace.wallet_id.as_str())
            .expect("load committed actor state"),
        Some(actor_state)
    );
    assert_eq!(
        store
            .list_opaque_wallet_private_rows(
                &namespace,
                WalletPrivateRecordKind::OutputPoiRecovery,
            )
            .expect("list committed recoveries"),
        recoveries
    );
    assert_eq!(
        store
            .get_opaque_wallet_private_row(
                &namespace,
                WalletPrivateRecordKind::SenderTransactionCandidate,
                &candidate_update_id,
            )
            .expect("load committed candidate update")
            .expect("updated candidate present")
            .payload,
        b"candidate-new"
    );
    assert!(
        store
            .get_opaque_wallet_private_row(
                &namespace,
                WalletPrivateRecordKind::SenderTransactionCandidate,
                &candidate_delete_id,
            )
            .expect("load committed candidate delete")
            .is_none()
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn typed_db_store_pending_and_recovery_records_use_plaintext_v2_encoding() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let namespace = WalletPrivateNamespaceId::new(1, wallet_cache_key(0x34));
    let pending = sample_pending_output_record(
        namespace.chain_id,
        namespace.wallet_id.as_str(),
        FixedBytes::from([0x71; 32]),
    );
    let recovery = sample_output_poi_recovery_record(
        namespace.chain_id,
        namespace.wallet_id.as_str(),
        FixedBytes::from([0x72; 32]),
    );

    store
        .put_pending_output_poi_context(&pending)
        .expect("put typed pending context");
    store
        .put_output_poi_recovery(&recovery)
        .expect("put typed recovery");

    assert_eq!(
        store
            .get_pending_output_poi_context(
                namespace.chain_id,
                namespace.wallet_id.as_str(),
                &pending.output_commitment,
            )
            .expect("get typed pending context")
            .expect("pending context present")
            .output_npk,
        pending.output_npk
    );
    assert_eq!(
        store
            .get_output_poi_recovery(
                namespace.chain_id,
                namespace.wallet_id.as_str(),
                &recovery.output_commitment,
            )
            .expect("get typed recovery")
            .expect("recovery present")
            .source_tx_hash,
        recovery.source_tx_hash
    );
    assert_eq!(
        store
            .list_wallet_private_v1_rows(&namespace)
            .expect("list v1 rows")
            .pending_output_contexts,
        [] as [crate::WalletPrivateV1Row; 0]
    );
    let opaque_pending = store
        .list_opaque_wallet_private_rows(
            &namespace,
            WalletPrivateRecordKind::PendingOutputPoiContext,
        )
        .expect("list opaque pending rows");
    assert_eq!(
        opaque_pending[0].row_id,
        pending.output_commitment.as_slice()
    );
    assert_eq!(
        decode::<PendingOutputPoiContextRecord>(&opaque_pending[0].payload)
            .expect("decode plaintext DbStore payload")
            .output_commitment,
        pending.output_commitment
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn typed_db_store_reads_shipped_v1_wallet_private_records() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let namespace = WalletPrivateNamespaceId::new(1, wallet_cache_key(0x37));
    let pending = sample_pending_output_record(
        namespace.chain_id,
        namespace.wallet_id.as_str(),
        FixedBytes::from([0x91; 32]),
    );
    let recovery = sample_output_poi_recovery_record(
        namespace.chain_id,
        namespace.wallet_id.as_str(),
        FixedBytes::from([0x92; 32]),
    );
    put_raw_pending_output_record(
        &store,
        &pending.key(),
        &encode(&pending).expect("encode v1 pending"),
    );
    put_raw_output_poi_recovery_record(
        &store,
        &recovery.key(),
        &encode(&recovery).expect("encode v1 recovery"),
    );

    assert_eq!(
        store
            .get_pending_output_poi_context(
                namespace.chain_id,
                namespace.wallet_id.as_str(),
                &pending.output_commitment,
            )
            .expect("get v1 pending")
            .expect("v1 pending present")
            .output_commitment,
        pending.output_commitment
    );
    let recoveries = store
        .list_output_poi_recoveries(namespace.chain_id, namespace.wallet_id.as_str())
        .expect("list v1 recoveries");
    assert_eq!(recoveries.len(), 1);
    assert_eq!(recoveries[0].output_commitment, recovery.output_commitment);
    assert_eq!(recoveries[0].source_tx_hash, recovery.source_tx_hash);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn typed_wallet_private_crud_consumes_shipped_v1_rows() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let namespace = WalletPrivateNamespaceId::new(1, wallet_cache_key(0x38));
    let pending = sample_pending_output_record(
        namespace.chain_id,
        namespace.wallet_id.as_str(),
        FixedBytes::from([0xa1; 32]),
    );
    let recovery = sample_output_poi_recovery_record(
        namespace.chain_id,
        namespace.wallet_id.as_str(),
        FixedBytes::from([0xa2; 32]),
    );
    put_raw_pending_output_record(
        &store,
        &pending.key(),
        &encode(&pending).expect("encode v1 pending"),
    );
    put_raw_output_poi_recovery_record(
        &store,
        &recovery.key(),
        &encode(&recovery).expect("encode v1 recovery"),
    );

    store
        .delete_pending_output_poi_context(
            namespace.chain_id,
            namespace.wallet_id.as_str(),
            &pending.output_commitment,
        )
        .expect("delete v1 pending");
    store
        .delete_output_poi_recovery(
            namespace.chain_id,
            namespace.wallet_id.as_str(),
            &recovery.output_commitment,
        )
        .expect("delete v1 recovery");
    assert!(
        store
            .get_pending_output_poi_context(
                namespace.chain_id,
                namespace.wallet_id.as_str(),
                &pending.output_commitment,
            )
            .expect("read deleted pending")
            .is_none()
    );
    assert!(
        store
            .get_output_poi_recovery(
                namespace.chain_id,
                namespace.wallet_id.as_str(),
                &recovery.output_commitment,
            )
            .expect("read deleted recovery")
            .is_none()
    );
    let v1_rows = store
        .list_wallet_private_v1_rows(&namespace)
        .expect("list remaining v1 rows");
    assert_eq!(
        v1_rows.pending_output_contexts,
        [] as [crate::WalletPrivateV1Row; 0]
    );
    assert_eq!(
        v1_rows.output_poi_recoveries,
        [] as [crate::WalletPrivateV1Row; 0]
    );
    assert!(
        store
            .wallet_private_compaction_requested()
            .expect("read committed compaction marker")
    );

    put_raw_pending_output_record(
        &store,
        &pending.key(),
        &encode(&pending).expect("encode replacement v1 pending"),
    );
    store
        .put_pending_output_poi_context(&pending)
        .expect("put consumes matching v1 pending");
    assert_eq!(
        store
            .list_wallet_private_v1_rows(&namespace)
            .expect("list v1 rows after typed pending put")
            .pending_output_contexts,
        [] as [crate::WalletPrivateV1Row; 0]
    );
    put_raw_pending_output_record(
        &store,
        &pending.key(),
        &encode(&pending).expect("encode shadow v1 pending"),
    );
    store
        .delete_pending_output_poi_context(
            namespace.chain_id,
            namespace.wallet_id.as_str(),
            &pending.output_commitment,
        )
        .expect("delete both pending versions");
    assert!(
        store
            .get_pending_output_poi_context(
                namespace.chain_id,
                namespace.wallet_id.as_str(),
                &pending.output_commitment,
            )
            .expect("read dual-version deletion")
            .is_none()
    );
    store
        .delete_pending_output_poi_context(
            namespace.chain_id,
            namespace.wallet_id.as_str(),
            &pending.output_commitment,
        )
        .expect("repeat pending deletion");

    put_raw_output_poi_recovery_record(
        &store,
        &recovery.key(),
        &encode(&recovery).expect("encode replacement v1 recovery"),
    );
    store
        .put_output_poi_recovery(&recovery)
        .expect("put consumes matching v1 recovery");
    assert_eq!(
        store
            .list_wallet_private_v1_rows(&namespace)
            .expect("list v1 rows after typed put")
            .output_poi_recoveries,
        [] as [crate::WalletPrivateV1Row; 0]
    );
    put_raw_output_poi_recovery_record(
        &store,
        &recovery.key(),
        &encode(&recovery).expect("encode shadow v1 recovery"),
    );
    store
        .delete_output_poi_recovery(
            namespace.chain_id,
            namespace.wallet_id.as_str(),
            &recovery.output_commitment,
        )
        .expect("delete both recovery versions");
    assert!(
        store
            .get_output_poi_recovery(
                namespace.chain_id,
                namespace.wallet_id.as_str(),
                &recovery.output_commitment,
            )
            .expect("read dual-version recovery deletion")
            .is_none()
    );
    store
        .delete_output_poi_recovery(
            namespace.chain_id,
            namespace.wallet_id.as_str(),
            &recovery.output_commitment,
        )
        .expect("repeat recovery deletion");

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
