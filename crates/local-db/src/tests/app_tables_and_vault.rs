use super::*;

#[test]
fn app_tables_read_empty_before_first_write_and_round_trip() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let table = AppTable::new("test_app_table");
    let read_back = |store: &DbStore| {
        store.read_app_tables(|tables| {
            Ok::<_, DbError>((tables.get(table, "a|1")?, tables.list_prefix(table, "a|")?))
        })
    };

    assert_eq!(
        read_back(&store).expect("read unwritten app table"),
        (None, Vec::new())
    );

    store
        .write_app_tables(|tables| {
            tables.insert(table, "a|2", b"second")?;
            tables.insert(table, "b|1", b"outside")?;
            tables.insert(table, "a|1", b"first")?;
            Ok::<_, DbError>(())
        })
        .expect("write app table");
    assert_eq!(
        read_back(&store).expect("read app table"),
        (
            Some(b"first".to_vec()),
            vec![
                ("a|1".to_string(), b"first".to_vec()),
                ("a|2".to_string(), b"second".to_vec()),
            ]
        )
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn reserved_app_table_name_fails_and_persists_nothing() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let wallet_id = wallet_cache_key(0x31);
    store
        .put_wallet_utxo(&wallet_id, "utxo", b"stored")
        .expect("seed wallet UTXO");
    let app_table = AppTable::new("test_app_table");
    let reserved = AppTable::new("wallet_utxo");

    let result: Result<(), DbError> = store.write_app_tables(|tables| {
        tables.insert(app_table, "key", b"value")?;
        let rejected = tables.insert(reserved, "utxo", b"overwritten");
        assert!(matches!(
            rejected,
            Err(DbError::ReservedTableName {
                table: "wallet_utxo"
            })
        ));
        Ok(())
    });
    assert!(matches!(
        result,
        Err(DbError::ReservedTableName {
            table: "wallet_utxo"
        })
    ));
    assert!(matches!(
        store.read_app_tables(|tables| tables.get(reserved, "utxo")),
        Err(DbError::ReservedTableName {
            table: "wallet_utxo"
        })
    ));
    assert_eq!(
        store
            .read_app_tables(|tables| tables.get(app_table, "key"))
            .expect("read app table"),
        None
    );
    let utxos = store
        .list_wallet_utxos(&wallet_id)
        .expect("list wallet UTXOs");
    assert_eq!(utxos.len(), 1);
    assert_eq!(utxos[0].payload.as_slice(), b"stored");

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn application_owned_table_names_are_not_reserved() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");

    for name in [
        "desktop_wallet_vault_v1",
        "app_settings_v1",
        "fee_note_assurance_pending",
        "fee_note_assurance_terminal",
    ] {
        let table = AppTable::new(name);
        put_app_row(&store, table, "key", name.as_bytes());
        assert_eq!(
            get_app_row(&store, table, "key").as_deref(),
            Some(name.as_bytes())
        );
    }

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

/// Removes `delete_keys` plus one absent key, inserts `put_records`, and reports what each
/// remove found, or fails after writing when `fail` is set.
fn replace_vault_rows(
    tables: &mut AppTableWriter<'_>,
    delete_keys: &[String],
    put_records: &[(String, Vec<u8>)],
    fail: bool,
) -> Result<Vec<bool>, DbError> {
    let removed = delete_keys
        .iter()
        .map(String::as_str)
        .chain(["wallet-meta|absent"])
        .map(|key| tables.remove(DESKTOP_WALLET_VAULT, key))
        .collect::<Result<Vec<_>, _>>()?;
    for (key, payload) in put_records {
        tables.insert(DESKTOP_WALLET_VAULT, key, payload)?;
    }
    if fail {
        return Err(DbError::Io(std::io::Error::other(
            "injected wallet deletion failure",
        )));
    }
    Ok(removed)
}

#[test]
fn wallet_deletion_batch_is_atomic_across_namespaces_and_vault_records() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let namespaces = [
        WalletPrivateNamespaceId::new(1, wallet_cache_key(0x71)),
        WalletPrivateNamespaceId::new(137, wallet_cache_key(0x72)),
    ];
    for (index, namespace) in namespaces.iter().enumerate() {
        store
            .put_wallet_utxo(&namespace.wallet_id, "utxo", b"encrypted")
            .expect("store wallet UTXO");
        store
            .put_wallet_meta(
                &namespace.wallet_id,
                &WalletMeta {
                    last_scanned_block: index as u64,
                    updated_at: 10,
                    last_scanned_block_hash: None,
                },
            )
            .expect("store wallet metadata");
        store
            .put_wallet_sync_actor_state(&WalletSyncActorStateRecord {
                chain_id: namespace.chain_id,
                wallet_id: namespace.wallet_id.to_string(),
                highest_accepted_reset_intent: 3,
                pending_reset: None,
                updated_at: 30,
            })
            .expect("store wallet sync actor state");
        store
            .put_pending_output_poi_context(&sample_pending_output_record(
                namespace.chain_id,
                namespace.wallet_id.as_str(),
                FixedBytes::from([0x81 + index as u8; 32]),
            ))
            .expect("store pending output context");
        store
            .put_output_poi_recovery(&sample_output_poi_recovery_record(
                namespace.chain_id,
                namespace.wallet_id.as_str(),
                FixedBytes::from([0x91 + index as u8; 32]),
            ))
            .expect("store output recovery");
    }
    let delete_keys = vec![
        "wallet-meta|delete-a".to_string(),
        "wallet-view|delete-b".to_string(),
    ];
    let put_records = vec![
        ("hardware-reservation|a".to_string(), b"reserved-a".to_vec()),
        ("hardware-reservation|b".to_string(), b"reserved-b".to_vec()),
    ];
    put_app_row(&store, DESKTOP_WALLET_VAULT, &delete_keys[0], b"metadata");
    put_app_row(&store, DESKTOP_WALLET_VAULT, &delete_keys[1], b"view");
    put_app_row(
        &store,
        DESKTOP_WALLET_VAULT,
        &put_records[0].0,
        b"old-reservation",
    );
    put_app_row(&store, DESKTOP_WALLET_VAULT, "wallet-meta|other", b"other");
    let delete_wallet = |fail: bool| {
        store.delete_wallet_namespaces_with(&namespaces, |tables| {
            replace_vault_rows(tables, &delete_keys, &put_records, fail)
        })
    };

    assert!(matches!(
        delete_wallet(true),
        Err(DbError::Io(error)) if error.to_string() == "injected wallet deletion failure"
    ));
    for namespace in &namespaces {
        assert_eq!(
            store
                .list_wallet_utxos(&namespace.wallet_id)
                .expect("list rolled-back wallet UTXOs")
                .len(),
            1
        );
        assert!(
            store
                .get_wallet_meta(&namespace.wallet_id)
                .expect("load rolled-back wallet metadata")
                .is_some()
        );
        assert!(
            store
                .get_wallet_sync_actor_state(namespace.chain_id, namespace.wallet_id.as_str())
                .expect("load rolled-back wallet sync actor state")
                .is_some()
        );
        assert_eq!(
            store
                .list_pending_output_poi_contexts(namespace.chain_id, namespace.wallet_id.as_str(),)
                .expect("list rolled-back pending output contexts")
                .len(),
            1
        );
        assert_eq!(
            store
                .list_output_poi_recoveries(namespace.chain_id, namespace.wallet_id.as_str())
                .expect("list rolled-back output recoveries")
                .len(),
            1
        );
    }
    for key in &delete_keys {
        assert!(get_app_row(&store, DESKTOP_WALLET_VAULT, key).is_some());
    }
    assert_eq!(
        get_app_row(&store, DESKTOP_WALLET_VAULT, &put_records[0].0)
            .expect("original updated vault record present"),
        b"old-reservation"
    );
    assert!(get_app_row(&store, DESKTOP_WALLET_VAULT, &put_records[1].0).is_none());

    assert_eq!(
        delete_wallet(false).expect("commit wallet deletion"),
        (
            WalletPrivateNamespaceDeletionReport {
                wallet_utxo_rows: 2,
                wallet_meta_rows: 2,
                wallet_sync_actor_state_rows: 2,
                pending_output_poi_context_rows: 2,
                output_poi_recovery_rows: 2,
                sender_transaction_candidate_rows: 0,
            },
            vec![true, true, false],
        )
    );
    for namespace in &namespaces {
        assert_eq!(
            store
                .list_wallet_utxos(&namespace.wallet_id)
                .expect("list deleted wallet UTXOs"),
            [] as [crate::WalletUtxoRecord; 0]
        );
    }
    for key in &delete_keys {
        assert!(get_app_row(&store, DESKTOP_WALLET_VAULT, key).is_none());
    }
    for (key, payload) in &put_records {
        assert_eq!(
            get_app_row(&store, DESKTOP_WALLET_VAULT, key).as_ref(),
            Some(payload)
        );
    }
    assert_eq!(
        get_app_row(&store, DESKTOP_WALLET_VAULT, "wallet-meta|other")
            .expect("unrelated vault record present"),
        b"other"
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
