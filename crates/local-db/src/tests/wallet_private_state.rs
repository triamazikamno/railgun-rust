use super::*;

#[test]
fn wallet_sync_actor_state_records_round_trip_and_list_by_chain() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");

    let record = WalletSyncActorStateRecord {
        chain_id: 1,
        wallet_id: wallet_cache_key(0x0a).to_string(),
        highest_accepted_reset_intent: 9,
        pending_reset: Some(WalletPendingResetRecord {
            intent_id: 9,
            from_block: 42,
            replay_start_block: 40,
            replay_target_block: 100,
            follow_safe_head: true,
        }),
        updated_at: 123,
    };
    store
        .put_wallet_sync_actor_state(&record)
        .expect("store wallet sync actor state");
    store
        .put_wallet_sync_actor_state(&WalletSyncActorStateRecord {
            chain_id: 2,
            wallet_id: wallet_cache_key(0x0b).to_string(),
            highest_accepted_reset_intent: 1,
            pending_reset: None,
            updated_at: 456,
        })
        .expect("store other chain wallet sync actor state");

    assert_eq!(
        store
            .get_wallet_sync_actor_state(1, &record.wallet_id)
            .expect("load wallet sync actor state")
            .expect("wallet sync actor state present"),
        record
    );
    let chain_records = store
        .list_wallet_sync_actor_states_for_chain(1)
        .expect("list wallet sync actor states");
    assert_eq!(chain_records, vec![record]);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn wallet_private_namespace_deletion_is_complete_isolated_and_idempotent() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let target = WalletPrivateNamespaceId::new(
        1,
        WalletCacheKey::new("0zk-test-wallet", 1, Address::from([0x11; 20])),
    );
    let other_wallet = WalletPrivateNamespaceId::new(1, wallet_cache_key(0x22));
    let target_meta = WalletMeta {
        last_scanned_block: 42,
        updated_at: 10,
        last_scanned_block_hash: Some([0x11; 32]),
    };
    let other_meta = WalletMeta {
        last_scanned_block: 84,
        updated_at: 20,
        last_scanned_block_hash: Some([0x22; 32]),
    };
    let target_actor_state = WalletSyncActorStateRecord {
        chain_id: target.chain_id,
        wallet_id: target.wallet_id.to_string(),
        highest_accepted_reset_intent: 3,
        pending_reset: None,
        updated_at: 30,
    };
    let other_wallet_actor_state = WalletSyncActorStateRecord {
        chain_id: other_wallet.chain_id,
        wallet_id: other_wallet.wallet_id.to_string(),
        highest_accepted_reset_intent: 4,
        pending_reset: None,
        updated_at: 40,
    };
    let other_chain_actor_state = WalletSyncActorStateRecord {
        chain_id: 2,
        wallet_id: target.wallet_id.to_string(),
        highest_accepted_reset_intent: 5,
        pending_reset: None,
        updated_at: 50,
    };
    let target_pending_a = sample_pending_output_record(
        target.chain_id,
        target.wallet_id.as_str(),
        FixedBytes::from([0x31; 32]),
    );
    let target_pending_b = sample_pending_output_record(
        target.chain_id,
        target.wallet_id.as_str(),
        FixedBytes::from([0x32; 32]),
    );
    let other_wallet_pending = sample_pending_output_record(
        other_wallet.chain_id,
        other_wallet.wallet_id.as_str(),
        FixedBytes::from([0x33; 32]),
    );
    let other_chain_pending =
        sample_pending_output_record(2, target.wallet_id.as_str(), FixedBytes::from([0x34; 32]));
    let target_recovery = sample_output_poi_recovery_record(
        target.chain_id,
        target.wallet_id.as_str(),
        FixedBytes::from([0x41; 32]),
    );
    let other_wallet_recovery = sample_output_poi_recovery_record(
        other_wallet.chain_id,
        other_wallet.wallet_id.as_str(),
        FixedBytes::from([0x42; 32]),
    );
    let other_chain_recovery = sample_output_poi_recovery_record(
        2,
        target.wallet_id.as_str(),
        FixedBytes::from([0x43; 32]),
    );
    let target_v1_pending = sample_pending_output_record(
        target.chain_id,
        target.wallet_id.as_str(),
        FixedBytes::from([0x35; 32]),
    );
    let target_v1_recovery = sample_output_poi_recovery_record(
        target.chain_id,
        target.wallet_id.as_str(),
        FixedBytes::from([0x44; 32]),
    );
    let public_poi_cache =
        sample_poi_artifact_cache_record(target.chain_id, FixedBytes::from([0x51; 32]));

    store
        .put_wallet_utxo(&target.wallet_id, "utxo-1", b"target-1")
        .expect("store first target UTXO");
    store
        .put_wallet_utxo(&target.wallet_id, "utxo-2", b"target-2")
        .expect("store second target UTXO");
    store
        .put_wallet_utxo(&target.wallet_id, "~legacy", b"target-legacy")
        .expect("store lexical-boundary target UTXO");
    store
        .put_wallet_utxo(&target.wallet_id, "legacy|utxo", b"delimiter-supported")
        .expect("store delimiter-bearing target UTXO");
    store
        .put_wallet_utxo(&other_wallet.wallet_id, "utxo-1", b"other")
        .expect("store other wallet UTXO");
    store
        .put_wallet_meta(&target.wallet_id, &target_meta)
        .expect("store target metadata");
    store
        .put_wallet_meta(&other_wallet.wallet_id, &other_meta)
        .expect("store other wallet metadata");
    for actor_state in [
        &target_actor_state,
        &other_wallet_actor_state,
        &other_chain_actor_state,
    ] {
        store
            .put_wallet_sync_actor_state(actor_state)
            .expect("store actor state");
    }
    for pending in [
        &target_pending_a,
        &target_pending_b,
        &other_wallet_pending,
        &other_chain_pending,
    ] {
        store
            .put_pending_output_poi_context(pending)
            .expect("store pending output context");
    }
    for recovery in [
        &target_recovery,
        &other_wallet_recovery,
        &other_chain_recovery,
    ] {
        store
            .put_output_poi_recovery(recovery)
            .expect("store output recovery");
    }
    let candidate_row = OpaqueWalletPrivateRow {
        row_id: vec![0x61; 32],
        payload: b"target-candidate".to_vec(),
    };
    store
        .put_opaque_wallet_private_row(
            &target,
            WalletPrivateRecordKind::SenderTransactionCandidate,
            &candidate_row,
        )
        .expect("store target candidate");
    store
        .put_opaque_wallet_private_row(
            &other_wallet,
            WalletPrivateRecordKind::SenderTransactionCandidate,
            &OpaqueWalletPrivateRow {
                row_id: candidate_row.row_id.clone(),
                payload: b"other-candidate".to_vec(),
            },
        )
        .expect("store other candidate");
    put_raw_pending_output_record(
        &store,
        &target_v1_pending.key(),
        &encode(&target_v1_pending).expect("encode target v1 pending context"),
    );
    put_raw_output_poi_recovery_record(
        &store,
        &target_v1_recovery.key(),
        &encode(&target_v1_recovery).expect("encode target v1 recovery"),
    );
    store
        .put_poi_artifact_cache(&public_poi_cache)
        .expect("store public POI cache");

    let report = store
        .delete_wallet_private_namespace(&target)
        .expect("delete target wallet-private namespace");
    assert_eq!(
        report,
        WalletPrivateNamespaceDeletionReport {
            wallet_utxo_rows: 4,
            wallet_meta_rows: 1,
            wallet_sync_actor_state_rows: 1,
            pending_output_poi_context_rows: 3,
            output_poi_recovery_rows: 2,
            sender_transaction_candidate_rows: 1,
        }
    );
    assert_eq!(
        store
            .list_wallet_utxos(&target.wallet_id)
            .expect("list deleted target UTXOs"),
        [] as [crate::WalletUtxoRecord; 0]
    );
    assert!(
        store
            .get_wallet_meta(&target.wallet_id)
            .expect("load deleted target metadata")
            .is_none()
    );
    assert!(
        store
            .get_wallet_sync_actor_state(target.chain_id, target.wallet_id.as_str())
            .expect("load deleted target actor state")
            .is_none()
    );
    assert_eq!(
        store
            .get_opaque_wallet_private_row(
                &other_wallet,
                WalletPrivateRecordKind::SenderTransactionCandidate,
                &candidate_row.row_id,
            )
            .expect("load isolated candidate")
            .expect("isolated candidate present")
            .payload,
        b"other-candidate"
    );
    assert!(
        store
            .list_pending_output_poi_contexts(target.chain_id, target.wallet_id.as_str())
            .expect("list deleted target pending contexts")
            .is_empty()
    );
    assert!(
        store
            .list_output_poi_recoveries(target.chain_id, target.wallet_id.as_str())
            .expect("list deleted target recoveries")
            .is_empty()
    );

    assert_eq!(
        store
            .list_wallet_utxos(&other_wallet.wallet_id)
            .expect("list other wallet UTXOs")
            .len(),
        1
    );
    assert!(
        store
            .get_wallet_meta(&other_wallet.wallet_id)
            .expect("load other wallet metadata")
            .is_some()
    );
    assert!(
        store
            .get_wallet_sync_actor_state(other_wallet.chain_id, other_wallet.wallet_id.as_str())
            .expect("load other wallet actor state")
            .is_some()
    );
    assert_eq!(
        store
            .list_pending_output_poi_contexts(
                other_wallet.chain_id,
                other_wallet.wallet_id.as_str(),
            )
            .expect("list other wallet pending contexts")
            .len(),
        1
    );
    assert_eq!(
        store
            .list_output_poi_recoveries(other_wallet.chain_id, other_wallet.wallet_id.as_str(),)
            .expect("list other wallet recoveries")
            .len(),
        1
    );
    assert!(
        store
            .get_wallet_sync_actor_state(2, target.wallet_id.as_str())
            .expect("load other chain actor state")
            .is_some()
    );
    assert_eq!(
        store
            .list_pending_output_poi_contexts(2, target.wallet_id.as_str())
            .expect("list other chain pending contexts")
            .len(),
        1
    );
    assert_eq!(
        store
            .list_output_poi_recoveries(2, target.wallet_id.as_str())
            .expect("list other chain recoveries")
            .len(),
        1
    );
    assert!(
        store
            .get_poi_artifact_cache(
                public_poi_cache.chain_type,
                public_poi_cache.chain_id,
                &public_poi_cache.txid_version,
                &public_poi_cache.list_key,
            )
            .expect("load preserved public POI cache")
            .is_some()
    );

    assert_eq!(
        store
            .delete_wallet_private_namespace(&target)
            .expect("repeat target namespace deletion"),
        WalletPrivateNamespaceDeletionReport::default()
    );
    assert_eq!(
        store
            .delete_wallet_private_namespace(&WalletPrivateNamespaceId::new(
                99,
                wallet_cache_key(0x99)
            ),)
            .expect("delete empty namespace"),
        WalletPrivateNamespaceDeletionReport::default()
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn wallet_private_namespace_deletion_rolls_back_before_commit_failure() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let identity = WalletPrivateNamespaceId::new(1, wallet_cache_key(0x11));
    let actor_state = WalletSyncActorStateRecord {
        chain_id: identity.chain_id,
        wallet_id: identity.wallet_id.to_string(),
        highest_accepted_reset_intent: 3,
        pending_reset: None,
        updated_at: 30,
    };
    let pending = sample_pending_output_record(
        identity.chain_id,
        identity.wallet_id.as_str(),
        FixedBytes::from([0x61; 32]),
    );
    let recovery = sample_output_poi_recovery_record(
        identity.chain_id,
        identity.wallet_id.as_str(),
        FixedBytes::from([0x62; 32]),
    );
    store
        .put_wallet_utxo(&identity.wallet_id, "utxo-1", b"target")
        .expect("store target UTXO");
    store
        .put_wallet_meta(
            &identity.wallet_id,
            &WalletMeta {
                last_scanned_block: 42,
                updated_at: 10,
                last_scanned_block_hash: None,
            },
        )
        .expect("store target metadata");
    store
        .put_wallet_sync_actor_state(&actor_state)
        .expect("store target actor state");
    store
        .put_pending_output_poi_context(&pending)
        .expect("store target pending context");
    store
        .put_output_poi_recovery(&recovery)
        .expect("store target recovery");

    let result = store.delete_wallet_private_namespace_transaction(&identity, || {
        Err(DbError::Io(std::io::Error::other(
            "injected pre-commit failure",
        )))
    });
    assert!(result.is_err());
    assert_eq!(
        store
            .list_wallet_utxos(&identity.wallet_id)
            .expect("list rolled-back UTXOs")
            .len(),
        1
    );
    assert!(
        store
            .get_wallet_meta(&identity.wallet_id)
            .expect("load rolled-back metadata")
            .is_some()
    );
    assert!(
        store
            .get_wallet_sync_actor_state(identity.chain_id, identity.wallet_id.as_str())
            .expect("load rolled-back actor state")
            .is_some()
    );
    assert_eq!(
        store
            .list_pending_output_poi_contexts(identity.chain_id, identity.wallet_id.as_str())
            .expect("list rolled-back pending contexts")
            .len(),
        1
    );
    assert_eq!(
        store
            .list_output_poi_recoveries(identity.chain_id, identity.wallet_id.as_str())
            .expect("list rolled-back recoveries")
            .len(),
        1
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn wallet_private_state_and_vault_records_commit_atomically() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let namespace = WalletPrivateNamespaceId::new(1, wallet_cache_key(0x21));
    let utxos = [("new-utxo".to_string(), b"new-payload".to_vec())];
    let meta = WalletMeta {
        last_scanned_block: 90,
        updated_at: 10,
        last_scanned_block_hash: None,
    };
    let actor_state = WalletSyncActorStateRecord {
        chain_id: namespace.chain_id,
        wallet_id: namespace.wallet_id.to_string(),
        highest_accepted_reset_intent: 7,
        pending_reset: None,
        updated_at: 20,
    };
    let (vault_key, vault_payload) = ("wallet-chain-metadata|21", b"encrypted-metadata");

    store
        .batch_commit_wallet_private_state_with(
            &WalletPrivateStateBatch {
                namespace: &namespace,
                utxos: WalletUtxoRowMutation::Replace(&utxos),
                metadata: WalletMetaMutation::Set(&meta),
                sync_actor_state: Some(&actor_state),
                pending_output_contexts: OpaqueWalletPrivateRowMutation::default(),
                output_poi_recoveries: OpaqueWalletPrivateRowMutation::default(),
                sender_transaction_candidates: OpaqueWalletPrivateRowMutation::default(),
            },
            |tables| tables.insert(DESKTOP_WALLET_VAULT, vault_key, vault_payload),
        )
        .expect("commit private state and vault record");

    assert_eq!(
        store
            .list_wallet_utxos(&namespace.wallet_id)
            .expect("list committed UTXOs")[0]
            .payload
            .as_slice(),
        b"new-payload"
    );
    let stored_meta = store
        .get_wallet_meta(&namespace.wallet_id)
        .expect("load committed metadata")
        .expect("committed metadata present");
    assert_eq!(stored_meta.last_scanned_block, meta.last_scanned_block);
    assert_eq!(stored_meta.updated_at, meta.updated_at);
    assert_eq!(
        stored_meta.last_scanned_block_hash,
        meta.last_scanned_block_hash
    );
    assert_eq!(
        store
            .get_wallet_sync_actor_state(namespace.chain_id, namespace.wallet_id.as_str())
            .expect("load committed actor state"),
        Some(actor_state)
    );
    assert_eq!(
        get_app_row(&store, DESKTOP_WALLET_VAULT, vault_key),
        Some(vault_payload.to_vec())
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn wallet_private_state_and_vault_records_roll_back_before_commit_failure() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let namespace = WalletPrivateNamespaceId::new(1, wallet_cache_key(0x22));
    let original_meta = WalletMeta {
        last_scanned_block: 150,
        updated_at: 1,
        last_scanned_block_hash: Some([0xaa; 32]),
    };
    let original_actor_state = WalletSyncActorStateRecord {
        chain_id: namespace.chain_id,
        wallet_id: namespace.wallet_id.to_string(),
        highest_accepted_reset_intent: 4,
        pending_reset: None,
        updated_at: 1,
    };
    store
        .put_wallet_utxo(&namespace.wallet_id, "old-utxo", b"old-payload")
        .expect("seed old UTXO");
    store
        .put_wallet_meta(&namespace.wallet_id, &original_meta)
        .expect("seed old metadata");
    store
        .put_wallet_sync_actor_state(&original_actor_state)
        .expect("seed old actor state");
    put_app_row(
        &store,
        DESKTOP_WALLET_VAULT,
        "wallet-chain-metadata|22",
        b"old-encrypted-metadata",
    );

    let replacement_utxos = [("new-utxo".to_string(), b"new-payload".to_vec())];
    let replacement_meta = WalletMeta {
        last_scanned_block: 90,
        updated_at: 2,
        last_scanned_block_hash: None,
    };
    let replacement_actor_state = WalletSyncActorStateRecord {
        chain_id: namespace.chain_id,
        wallet_id: namespace.wallet_id.to_string(),
        highest_accepted_reset_intent: 5,
        pending_reset: None,
        updated_at: 2,
    };
    let vault_key = "wallet-chain-metadata|22";
    let result: Result<(), DbError> = store.batch_commit_wallet_private_state_with(
        &WalletPrivateStateBatch {
            namespace: &namespace,
            utxos: WalletUtxoRowMutation::Replace(&replacement_utxos),
            metadata: WalletMetaMutation::Set(&replacement_meta),
            sync_actor_state: Some(&replacement_actor_state),
            pending_output_contexts: OpaqueWalletPrivateRowMutation::default(),
            output_poi_recoveries: OpaqueWalletPrivateRowMutation::default(),
            sender_transaction_candidates: OpaqueWalletPrivateRowMutation::default(),
        },
        |tables| {
            tables.insert(DESKTOP_WALLET_VAULT, vault_key, b"new-encrypted-metadata")?;
            Err(DbError::Io(std::io::Error::other(
                "injected pre-commit failure",
            )))
        },
    );

    assert!(result.is_err());
    let stored_utxos = store
        .list_wallet_utxos(&namespace.wallet_id)
        .expect("list rolled-back UTXOs");
    assert_eq!(stored_utxos.len(), 1);
    assert_eq!(stored_utxos[0].utxo_id, "old-utxo");
    assert_eq!(stored_utxos[0].payload.as_slice(), b"old-payload");
    let stored_meta = store
        .get_wallet_meta(&namespace.wallet_id)
        .expect("load rolled-back metadata")
        .expect("rolled-back metadata present");
    assert_eq!(
        stored_meta.last_scanned_block,
        original_meta.last_scanned_block
    );
    assert_eq!(stored_meta.updated_at, original_meta.updated_at);
    assert_eq!(
        stored_meta.last_scanned_block_hash,
        original_meta.last_scanned_block_hash
    );
    assert_eq!(
        store
            .get_wallet_sync_actor_state(namespace.chain_id, namespace.wallet_id.as_str())
            .expect("load rolled-back actor state"),
        Some(original_actor_state)
    );
    assert_eq!(
        get_app_row(&store, DESKTOP_WALLET_VAULT, vault_key),
        Some(b"old-encrypted-metadata".to_vec())
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
