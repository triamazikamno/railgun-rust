use super::*;

#[test]
fn schema_seven_legacy_composite_wallet_rows_migrate_explicitly() {
    let root_dir = temp_db_root();
    let chain_id = 1;
    let contract = Address::from([0x12; 20]);
    let legacy_wallet_id = format!("composite-wallet|{chain_id}|{contract}");
    let wallet_id = WalletCacheKey::new("composite-wallet", chain_id, contract);
    let meta = WalletMeta {
        last_scanned_block: 42,
        updated_at: 99,
        last_scanned_block_hash: Some([7u8; 32]),
    };
    let utxo_key = format!("{legacy_wallet_id}|utxo-1");
    let pending =
        sample_pending_output_record(chain_id, &legacy_wallet_id, FixedBytes::from([0x94; 32]));
    let recovery = sample_output_poi_recovery_record(
        chain_id,
        &legacy_wallet_id,
        FixedBytes::from([0x95; 32]),
    );

    {
        let store = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        put_raw_wallet_meta(
            &store,
            &legacy_wallet_id,
            &encode(&meta).expect("encode legacy wallet meta"),
        );
        put_raw_wallet_utxo(&store, &utxo_key, b"legacy-utxo");
        put_raw_pending_output_record(
            &store,
            &schema_seven_pending_output_key(&pending),
            &encode(&pending).expect("encode legacy pending context"),
        );
        put_raw_output_poi_recovery_record(
            &store,
            &recovery.key(),
            &encode(&recovery).expect("encode legacy output recovery"),
        );
        store
            .write_meta(&Meta {
                schema_version: 7,
                app_version: "schema-7-composite-wallet".to_string(),
                created_at: 123,
            })
            .expect("write schema-7 meta");
    }

    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open schema-7 composite-wallet db");
    assert_eq!(CURRENT_SCHEMA_VERSION, 12);
    assert_eq!(
        store
            .read_meta()
            .expect("read schema-7 meta")
            .expect("schema-7 meta present")
            .schema_version,
        CURRENT_SCHEMA_VERSION
    );
    assert!(
        store
            .get_wallet_meta(&wallet_id)
            .expect("read pre-migration wallet meta")
            .is_none()
    );
    assert_eq!(
        store
            .list_wallet_utxos(&wallet_id)
            .expect("read pre-migration wallet UTXOs"),
        [] as [crate::WalletUtxoRecord; 0]
    );
    let pending_rows = store
        .list_pending_output_poi_contexts(chain_id, wallet_id.as_str())
        .expect("read normalized pending context");
    assert_eq!(pending_rows.len(), 1);
    assert_eq!(pending_rows[0].wallet_id, wallet_id.as_str());

    store
        .migrate_legacy_composite_wallet_keys()
        .expect("migrate schema-7 composite-wallet rows");
    let migrated_meta = store
        .get_wallet_meta(&wallet_id)
        .expect("read wallet meta")
        .expect("wallet meta present");
    assert_eq!(migrated_meta.last_scanned_block, meta.last_scanned_block);
    assert_eq!(migrated_meta.updated_at, meta.updated_at);
    assert_eq!(
        migrated_meta.last_scanned_block_hash,
        meta.last_scanned_block_hash
    );
    assert_eq!(
        store
            .list_wallet_utxos(&wallet_id)
            .expect("read wallet UTXOs"),
        vec![crate::WalletUtxoRecord {
            utxo_id: "utxo-1".to_string(),
            payload: b"legacy-utxo".to_vec(),
        }]
    );
    let recovery_rows = store
        .list_output_poi_recoveries(chain_id, wallet_id.as_str())
        .expect("read migrated output recovery");
    assert_eq!(recovery_rows.len(), 1);
    assert_eq!(recovery_rows[0].wallet_id, wallet_id.as_str());

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove migrated db");
}

#[test]
fn schema_eleven_legacy_composite_wallet_rows_migrate_explicitly() {
    let root_dir = temp_db_root();
    let chain_id = 137;
    let contract = Address::from([0x23; 20]);
    let legacy_wallet_id = format!("leftover-wallet|{chain_id}|{contract}");
    let wallet_id = WalletCacheKey::new("leftover-wallet", chain_id, contract);
    let recovery = sample_output_poi_recovery_record(
        chain_id,
        &legacy_wallet_id,
        FixedBytes::from([0x96; 32]),
    );
    let legacy_utxo_key = format!("{legacy_wallet_id}|utxo-leftover");
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    put_raw_wallet_meta(
        &store,
        &legacy_wallet_id,
        &encode(&WalletMeta {
            last_scanned_block: 7,
            updated_at: 8,
            last_scanned_block_hash: None,
        })
        .expect("encode leftover wallet meta"),
    );
    put_raw_wallet_utxo(&store, &legacy_utxo_key, b"leftover-utxo");
    put_raw_output_poi_recovery_record(
        &store,
        &recovery.key(),
        &encode(&recovery).expect("encode leftover recovery"),
    );
    store
        .write_meta(&Meta {
            schema_version: 11,
            app_version: "schema-11".to_string(),
            created_at: 456,
        })
        .expect("write schema-11 meta");
    drop(store);
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open schema-11 composite-wallet db");
    store
        .migrate_legacy_composite_wallet_keys()
        .expect("migrate schema-11 composite-wallet rows");
    store
        .migrate_legacy_composite_wallet_keys()
        .expect("rescan canonical wallet rows");
    assert_eq!(CURRENT_SCHEMA_VERSION, 12);
    assert_eq!(
        store
            .read_meta()
            .expect("read schema-11 meta")
            .expect("schema-11 meta present")
            .schema_version,
        CURRENT_SCHEMA_VERSION
    );
    assert_eq!(
        store
            .list_wallet_utxos(&wallet_id)
            .expect("read leftover UTXO")[0]
            .payload,
        b"leftover-utxo"
    );
    assert_eq!(
        store
            .list_output_poi_recoveries(chain_id, wallet_id.as_str())
            .expect("read leftover recovery")[0]
            .wallet_id,
        wallet_id.as_str()
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove migrated db");
}

#[test]
fn schema_eleven_legacy_composite_wallet_collision_rolls_back_atomically() {
    let root_dir = temp_db_root();
    let chain_id = 1;
    let contract = Address::from([0x34; 20]);
    let legacy_wallet_id = format!("collision-wallet|{chain_id}|{contract}");
    let wallet_id = WalletCacheKey::new("collision-wallet", chain_id, contract);
    let legacy_utxo_key = format!("{legacy_wallet_id}|utxo-collision");
    let legacy_meta = encode(&WalletMeta {
        last_scanned_block: 1,
        updated_at: 2,
        last_scanned_block_hash: None,
    })
    .expect("encode legacy collision meta");
    let destination_meta = encode(&WalletMeta {
        last_scanned_block: 3,
        updated_at: 4,
        last_scanned_block_hash: None,
    })
    .expect("encode destination collision meta");
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    put_raw_wallet_meta(&store, &legacy_wallet_id, &legacy_meta);
    put_raw_wallet_meta(&store, wallet_id.as_str(), &destination_meta);
    put_raw_wallet_utxo(&store, &legacy_utxo_key, b"collision-utxo");
    let schema_eleven = Meta {
        schema_version: 11,
        app_version: "schema-11".to_string(),
        created_at: 789,
    };
    store
        .write_meta(&schema_eleven)
        .expect("write schema-11 meta");

    assert!(matches!(
        store.migrate_legacy_composite_wallet_keys(),
        Err(DbError::SchemaMigrationDestinationConflict { table, key })
            if table == "wallet_meta" && key == wallet_id.as_str()
    ));
    assert_eq!(
        store
            .read_meta()
            .expect("read retained meta")
            .expect("meta present")
            .schema_version,
        11
    );
    let txn = store.db.begin_read().expect("begin retained row read");
    let meta_table = txn
        .open_table(WALLET_META_TABLE)
        .expect("open wallet meta table");
    assert_eq!(
        meta_table
            .get(legacy_wallet_id.as_str())
            .expect("read legacy meta")
            .expect("legacy meta present")
            .value(),
        legacy_meta.as_slice()
    );
    assert_eq!(
        meta_table
            .get(wallet_id.as_str())
            .expect("read destination meta")
            .expect("destination meta present")
            .value(),
        destination_meta.as_slice()
    );
    let utxo_table = txn
        .open_table(WALLET_UTXO_TABLE)
        .expect("open wallet UTXO table");
    assert_eq!(
        utxo_table
            .get(legacy_utxo_key.as_str())
            .expect("read legacy UTXO")
            .expect("legacy UTXO present")
            .value(),
        b"collision-utxo"
    );
    let destination_utxo_key = format!("{wallet_id}|utxo-collision");
    assert!(
        utxo_table
            .get(destination_utxo_key.as_str())
            .expect("read destination UTXO")
            .is_none()
    );
    drop(txn);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove collision db");
}

#[test]
fn schema_seven_migration_moves_alpha_wallet_cache_rows_atomically() {
    let root_dir = temp_db_root();
    let wallet_id = wallet_cache_key(0x42);
    let row_id = "ab".repeat(32);
    let legacy_key = format!("wallet-cache-row|{wallet_id}|{row_id}");
    let unrelated_key = "wallet-chain-meta|opaque-wallet";
    let payload = b"alpha-6-encrypted-row";
    let pending_output =
        sample_pending_output_record(1, wallet_id.as_str(), FixedBytes::from([0x91; 32]));
    let legacy_pending_key = schema_seven_pending_output_key(&pending_output);
    let pending_payload = encode(&pending_output).expect("encode alpha pending context");

    {
        let store = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        put_app_row(&store, DESKTOP_WALLET_VAULT, &legacy_key, payload);
        put_app_row(
            &store,
            DESKTOP_WALLET_VAULT,
            unrelated_key,
            b"encrypted metadata",
        );
        put_app_row(&store, APP_SETTINGS, "wallet-settings", b"settings");
        put_raw_pending_output_record(&store, &legacy_pending_key, &pending_payload);
        store
            .write_meta(&Meta {
                schema_version: 7,
                app_version: "0.1.0-alpha.6".to_string(),
                created_at: 123,
            })
            .expect("write schema-7 meta");
    }

    let reopened = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("migrate schema-7 db");
    let meta = reopened
        .read_meta()
        .expect("read migrated meta")
        .expect("migrated meta present");
    assert_eq!(meta.schema_version, CURRENT_SCHEMA_VERSION);
    assert_eq!(meta.created_at, 123);
    assert_eq!(
        reopened
            .list_wallet_utxos(&wallet_id)
            .expect("list migrated UTXOs"),
        vec![crate::WalletUtxoRecord {
            utxo_id: row_id,
            payload: payload.to_vec(),
        }]
    );
    assert!(get_app_row(&reopened, DESKTOP_WALLET_VAULT, &legacy_key).is_none());
    assert_eq!(
        decode::<PendingOutputPoiContextRecord>(
            &reopened
                .list_wallet_private_v1_rows(&WalletPrivateNamespaceId::new(
                    pending_output.chain_id,
                    wallet_id.clone(),
                ))
                .expect("load migrated pending context")
                .pending_output_contexts[0]
                .payload,
        )
        .expect("decode migrated pending context")
        .wallet_id,
        wallet_id.as_str()
    );
    assert!(!raw_pending_output_record_exists(
        &reopened,
        &legacy_pending_key
    ));
    assert_eq!(
        get_app_row(&reopened, DESKTOP_WALLET_VAULT, unrelated_key).expect("metadata present"),
        b"encrypted metadata"
    );
    assert_eq!(
        get_app_row(&reopened, APP_SETTINGS, "wallet-settings").expect("settings present"),
        b"settings"
    );
    assert!(
        !fs::read_dir(root_dir.join("railgun"))
            .expect("read railgun dir")
            .any(|entry| entry
                .expect("read dir entry")
                .file_name()
                .to_string_lossy()
                .starts_with("db.redb.bak."))
    );

    drop(reopened);
    let reopened = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("reopen migrated db");
    assert_eq!(
        reopened
            .list_wallet_utxos(&wallet_id)
            .expect("list idempotently migrated UTXOs")
            .len(),
        1
    );
    let namespace = WalletPrivateNamespaceId::new(pending_output.chain_id, wallet_id);
    assert_eq!(
        reopened
            .delete_wallet_private_namespace(&namespace)
            .expect("delete migrated namespace")
            .pending_output_poi_context_rows,
        1
    );
    assert!(!raw_pending_output_record_exists(
        &reopened,
        &legacy_pending_key
    ));
    assert!(!raw_pending_output_record_exists(
        &reopened,
        &pending_output.key()
    ));
    drop(reopened);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
