use super::*;

#[test]
fn opening_schema_seven_malformed_cache_fixture_preserves_table_set_and_rows() {
    let root_dir = temp_db_root();
    let railgun_dir = root_dir.join("railgun");
    fs::create_dir_all(&railgun_dir).expect("create alpha railgun dir");
    let database_path = railgun_dir.join("db.redb");
    let wallet_id = wallet_cache_key(0x44);
    let row_id = "ef".repeat(32);
    let valid_key = format!("wallet-cache-row|{wallet_id}|{row_id}");
    let malformed_key = format!("wallet-cache-row|not-hex|{}", "ab".repeat(32));
    let valid_payload = b"alpha-encrypted-row";
    let malformed_payload = b"malformed-key-payload";
    let schema_seven_meta = encode(&Meta {
        schema_version: 7,
        app_version: "0.1.0-alpha.6".to_string(),
        created_at: 123,
    })
    .expect("encode schema-7 meta");

    let db = Database::create(&database_path).expect("create alpha database");
    let txn = db.begin_write().expect("begin alpha fixture write");
    txn.open_table(META_TABLE).expect("create alpha meta table");
    txn.open_table(BLOB_INDEX_TABLE)
        .expect("create alpha blob table");
    txn.open_table(MERKLE_FOREST_INDEX_TABLE)
        .expect("create alpha Merkle table");
    txn.open_table(ZKEY_INDEX_TABLE)
        .expect("create alpha zkey table");
    txn.open_table(WALLET_UTXO_TABLE)
        .expect("create alpha UTXO table");
    txn.open_table(WALLET_META_TABLE)
        .expect("create alpha wallet meta table");
    txn.open_table(RAW_PENDING_FEE_NOTE_ASSURANCE_TABLE)
        .expect("create alpha pending assurance table");
    txn.open_table(RAW_TERMINAL_FEE_NOTE_ASSURANCE_TABLE)
        .expect("create alpha terminal assurance table");
    txn.open_table(PENDING_OUTPUT_POI_CONTEXT_TABLE)
        .expect("create alpha pending output table");
    txn.open_table(OUTPUT_POI_RECOVERY_TABLE)
        .expect("create alpha output recovery table");
    txn.open_table(POI_ARTIFACT_CACHE_TABLE)
        .expect("create alpha POI cache table");
    txn.open_table(RAW_APP_SETTINGS_TABLE)
        .expect("create alpha settings table");
    {
        let mut table = txn
            .open_table(RAW_DESKTOP_WALLET_VAULT_TABLE)
            .expect("create alpha vault table");
        table
            .insert(valid_key.as_str(), valid_payload.as_slice())
            .expect("insert valid alpha row");
        table
            .insert(malformed_key.as_str(), malformed_payload.as_slice())
            .expect("insert malformed alpha row");
    }
    {
        let mut table = txn.open_table(META_TABLE).expect("open alpha meta table");
        table
            .insert("meta", schema_seven_meta.as_slice())
            .expect("insert schema-7 meta");
    }
    txn.commit().expect("commit alpha fixture");

    let read_txn = db.begin_read().expect("begin alpha table read");
    let tables_before = read_txn
        .list_tables()
        .expect("list alpha tables")
        .map(|table| table.name().to_string())
        .collect::<BTreeSet<_>>();
    assert!(!tables_before.contains(WALLET_SYNC_ACTOR_STATE_TABLE.name()));
    drop(read_txn);
    drop(db);

    assert!(matches!(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        }),
        Err(DbError::InvalidLegacyDesktopWalletCacheRowKey { .. })
    ));

    let db = Database::open(&database_path).expect("reopen failed alpha migration");
    let read_txn = db.begin_read().expect("begin retained fixture read");
    let tables_after = read_txn
        .list_tables()
        .expect("list retained tables")
        .map(|table| table.name().to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(tables_after, tables_before);
    assert!(!tables_after.contains(WALLET_SYNC_ACTOR_STATE_TABLE.name()));
    {
        let table = read_txn.open_table(META_TABLE).expect("open retained meta");
        assert_eq!(
            table
                .get("meta")
                .expect("read retained meta")
                .expect("retained meta present")
                .value(),
            schema_seven_meta.as_slice()
        );
    }
    {
        let table = read_txn
            .open_table(RAW_DESKTOP_WALLET_VAULT_TABLE)
            .expect("open retained vault");
        assert_eq!(
            table
                .get(valid_key.as_str())
                .expect("read retained valid row")
                .expect("retained valid row present")
                .value(),
            valid_payload
        );
        assert_eq!(
            table
                .get(malformed_key.as_str())
                .expect("read retained malformed row")
                .expect("retained malformed row present")
                .value(),
            malformed_payload
        );
    }
    assert!(
        read_txn
            .open_table(WALLET_UTXO_TABLE)
            .expect("open retained UTXO table")
            .is_empty()
            .expect("read retained UTXO table")
    );

    drop(read_txn);
    let txn = db.begin_write().expect("begin fixture repair");
    {
        let mut table = txn
            .open_table(RAW_DESKTOP_WALLET_VAULT_TABLE)
            .expect("open fixture vault");
        table
            .remove(malformed_key.as_str())
            .expect("remove malformed fixture row");
    }
    txn.commit().expect("commit fixture repair");
    drop(db);

    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("migrate repaired alpha fixture");
    let read_txn = store.db.begin_read().expect("begin migrated table read");
    let migrated_tables = read_txn
        .list_tables()
        .expect("list migrated tables")
        .map(|table| table.name().to_string())
        .collect::<BTreeSet<_>>();
    let mut expected_tables = tables_before;
    expected_tables.insert(WALLET_SYNC_ACTOR_STATE_TABLE.name().to_string());
    expected_tables.insert(PENDING_OUTPUT_POI_CONTEXT_V2_TABLE.name().to_string());
    expected_tables.insert(OUTPUT_POI_RECOVERY_V2_TABLE.name().to_string());
    expected_tables.insert(POI_CORPUS_JOURNAL_TABLE.name().to_string());
    expected_tables.insert(POI_SIDECAR_STATE_TABLE.name().to_string());
    expected_tables.insert(SENDER_TRANSACTION_CANDIDATE_V1_TABLE.name().to_string());
    assert_eq!(migrated_tables, expected_tables);
    drop(read_txn);
    assert_eq!(
        store
            .read_meta()
            .expect("read migrated meta")
            .expect("migrated meta present")
            .schema_version,
        CURRENT_SCHEMA_VERSION
    );
    assert_eq!(
        store
            .list_wallet_utxos(&wallet_id)
            .expect("list migrated fixture rows"),
        vec![crate::WalletUtxoRecord {
            utxo_id: row_id,
            payload: valid_payload.to_vec(),
        }]
    );
    assert!(get_app_row(&store, DESKTOP_WALLET_VAULT, &valid_key).is_none());

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn reopen_older_schema_db_backs_up_and_recreates() {
    let root_dir = temp_db_root();
    let wallet_id = wallet_cache_key(0x51);

    {
        let store = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");

        let wallet_meta = WalletMeta {
            last_scanned_block: 42,
            updated_at: 99,
            last_scanned_block_hash: Some([7u8; 32]),
        };
        store
            .put_wallet_meta(&wallet_id, &wallet_meta)
            .expect("write wallet meta");

        store
            .write_meta(&Meta {
                schema_version: 3,
                app_version: "0.0.0".to_string(),
                created_at: 123,
            })
            .expect("write schema-3 meta");
    }

    let reopened = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("reopen db");

    assert!(
        reopened
            .get_wallet_meta(&wallet_id)
            .expect("load wallet meta")
            .is_none()
    );

    let meta = reopened
        .read_meta()
        .expect("read meta")
        .expect("meta present");
    assert_eq!(meta.schema_version, CURRENT_SCHEMA_VERSION);
    assert!(
        fs::read_dir(root_dir.join("railgun"))
            .expect("read railgun dir")
            .any(|entry| entry
                .expect("read dir entry")
                .file_name()
                .to_string_lossy()
                .starts_with("db.redb.bak."))
    );

    drop(reopened);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn schema_ten_to_current_adds_only_new_tables() {
    let root_dir = temp_db_root();
    let db = create_raw_fixture(&root_dir, 10, &SCHEMA_TEN_TABLES);
    let txn = db.begin_write().expect("begin schema-10 row write");
    txn.open_table(RAW_DESKTOP_WALLET_VAULT_TABLE)
        .expect("open vault table")
        .insert("vault-row", b"vault-payload".as_slice())
        .expect("insert vault row");
    txn.commit().expect("commit schema-10 row");
    drop(db);
    let before = SCHEMA_TEN_TABLES
        .iter()
        .map(|table| table.name().to_string())
        .collect::<BTreeSet<_>>();

    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("migrate schema 10 to current");
    let read_txn = store.db.begin_read().expect("read current tables");
    let after = read_txn
        .list_tables()
        .expect("list current tables")
        .map(|table| table.name().to_string())
        .collect::<BTreeSet<_>>();
    drop(read_txn);
    assert_eq!(
        after.difference(&before).cloned().collect::<Vec<_>>(),
        vec![
            POI_SIDECAR_STATE_TABLE.name().to_string(),
            SENDER_TRANSACTION_CANDIDATE_V1_TABLE.name().to_string(),
        ]
    );
    assert_eq!(
        store
            .read_meta()
            .expect("read meta")
            .expect("meta present")
            .schema_version,
        CURRENT_SCHEMA_VERSION
    );
    assert_eq!(
        get_app_row(&store, DESKTOP_WALLET_VAULT, "vault-row").expect("vault row present"),
        b"vault-payload"
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

fn schema_eleven_sidecar_watermark() -> PoiPublisherManifestWatermarkRecord {
    PoiPublisherManifestWatermarkRecord {
        publisher_pubkey: FixedBytes::from([0x61; 32]),
        accepted_sequence: 12,
        accepted_manifest_hash: Some(FixedBytes::from([0x62; 32])),
        updated_at: 1_700_000_000,
    }
}

fn schema_eleven_sidecar_rows() -> BTreeMap<String, Vec<u8>> {
    let watermark = schema_eleven_sidecar_watermark();
    let health = PoiCorpusRpcHealthRecord {
        chain_type: 0,
        chain_id: 1,
        txid_version: "V2_PoseidonMerkle".to_string(),
        list_key: FixedBytes::from([0x63; 32]),
        cache_generation: 4,
        last_successful_rpc_sync_at_ms: Some(1_700_000_000_123),
        updated_at: 1_700_000_001,
    };
    BTreeMap::from([
        (
            POI_ARTIFACT_CACHE_GENERATION_KEY.to_string(),
            encode(&4_u64).expect("encode generation"),
        ),
        (
            watermark.key(),
            encode(&watermark).expect("encode watermark"),
        ),
        (
            health.key(),
            encode(&health).expect("encode corpus RPC health"),
        ),
    ])
}

/// Writes a schema-11 database whose POI sidecar state still lives in `app_settings_v1`.
fn create_schema_eleven_sidecar_fixture(conflicting_generation: Option<&[u8]>) -> PathBuf {
    let root_dir = temp_db_root();
    let tables = [
        SCHEMA_TEN_TABLES.as_slice(),
        &[SENDER_TRANSACTION_CANDIDATE_V1_TABLE],
    ]
    .concat();
    let db = create_raw_fixture(&root_dir, 11, &tables);
    let txn = db.begin_write().expect("begin schema-11 row write");
    {
        let mut table = txn
            .open_table(RAW_APP_SETTINGS_TABLE)
            .expect("open settings table");
        for (key, value) in schema_eleven_sidecar_rows() {
            table
                .insert(key.as_str(), value.as_slice())
                .expect("insert sidecar row");
        }
        for key in ["wallet-settings", "ui-state", "gateway-state"] {
            table
                .insert(key, key.as_bytes())
                .expect("insert settings row");
        }
    }
    {
        let mut table = txn
            .open_table(RAW_DESKTOP_WALLET_VAULT_TABLE)
            .expect("open vault table");
        table
            .insert("vault-a", b"vault-a-payload".as_slice())
            .expect("insert first vault row");
        table
            .insert("vault-b", b"vault-b-payload".as_slice())
            .expect("insert second vault row");
    }
    if let Some(payload) = conflicting_generation {
        txn.open_table(POI_SIDECAR_STATE_TABLE)
            .expect("create sidecar table")
            .insert(POI_ARTIFACT_CACHE_GENERATION_KEY, payload)
            .expect("insert conflicting generation");
    }
    txn.commit().expect("commit schema-11 fixture");
    root_dir
}

/// Creates `<root>/railgun/db.redb` with `tables` and a `Meta` row at `schema_version`.
fn create_raw_fixture(
    root_dir: &std::path::Path,
    schema_version: u32,
    tables: &[ByteTableDefinition],
) -> Database {
    let railgun_dir = root_dir.join("railgun");
    fs::create_dir_all(&railgun_dir).expect("create railgun dir");
    let db = Database::create(railgun_dir.join("db.redb")).expect("create fixture database");
    let txn = db.begin_write().expect("begin fixture write");
    for table in tables {
        txn.open_table(*table).expect("create fixture table");
    }
    let meta = encode(&Meta {
        schema_version,
        app_version: format!("schema-{schema_version}"),
        created_at: 123,
    })
    .expect("encode fixture meta");
    txn.open_table(META_TABLE)
        .expect("open meta table")
        .insert(META_KEY, meta.as_slice())
        .expect("insert fixture meta");
    txn.commit().expect("commit fixture tables");
    db
}

fn raw_table_rows(
    db: &Database,
    definition: crate::ByteTableDefinition,
) -> BTreeMap<String, Vec<u8>> {
    let txn = db.begin_read().expect("begin raw table read");
    let table = txn.open_table(definition).expect("open raw table");
    table
        .iter()
        .expect("iterate raw table")
        .map(|entry| {
            let (key, value) = entry.expect("read raw row");
            (key.value().to_string(), value.value().to_vec())
        })
        .collect()
}

fn has_database_backup(root_dir: &std::path::Path) -> bool {
    fs::read_dir(root_dir.join("railgun"))
        .expect("read railgun dir")
        .any(|entry| {
            entry
                .expect("read dir entry")
                .file_name()
                .to_string_lossy()
                .starts_with("db.redb.bak.")
        })
}

#[test]
fn schema_eleven_moves_poi_sidecar_state_out_of_app_settings() {
    let root_dir = create_schema_eleven_sidecar_fixture(None);
    let db = Database::open(root_dir.join("railgun").join("db.redb")).expect("open fixture");
    let settings_before = raw_table_rows(&db, RAW_APP_SETTINGS_TABLE);
    let vault_before = raw_table_rows(&db, RAW_DESKTOP_WALLET_VAULT_TABLE);
    drop(db);
    let sidecar = schema_eleven_sidecar_rows();
    let (moved, kept): (BTreeMap<_, _>, BTreeMap<_, _>) = settings_before
        .into_iter()
        .partition(|(key, _)| sidecar.contains_key(key));
    assert_eq!(moved, sidecar);

    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("migrate schema-11 fixture");
    assert_eq!(raw_table_rows(&store.db, POI_SIDECAR_STATE_TABLE), moved);
    assert_eq!(raw_table_rows(&store.db, RAW_APP_SETTINGS_TABLE), kept);
    assert_eq!(
        raw_table_rows(&store.db, RAW_DESKTOP_WALLET_VAULT_TABLE),
        vault_before
    );
    assert_eq!(
        store
            .read_meta()
            .expect("read migrated meta")
            .expect("meta present")
            .schema_version,
        CURRENT_SCHEMA_VERSION
    );
    assert!(!has_database_backup(&root_dir));
    assert_eq!(
        store
            .poi_artifact_cache_generation()
            .expect("read moved generation"),
        4
    );
    let watermark = schema_eleven_sidecar_watermark();
    assert_eq!(
        store
            .get_poi_publisher_manifest_watermark(&watermark.publisher_pubkey)
            .expect("read moved watermark"),
        Some(watermark)
    );
    drop(store);

    let reopened = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("reopen migrated db");
    assert_eq!(raw_table_rows(&reopened.db, POI_SIDECAR_STATE_TABLE), moved);
    assert_eq!(raw_table_rows(&reopened.db, RAW_APP_SETTINGS_TABLE), kept);
    assert_eq!(
        raw_table_rows(&reopened.db, RAW_DESKTOP_WALLET_VAULT_TABLE),
        vault_before
    );
    assert_eq!(
        reopened
            .read_meta()
            .expect("read reopened meta")
            .expect("meta present")
            .schema_version,
        CURRENT_SCHEMA_VERSION
    );

    drop(reopened);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn schema_eleven_sidecar_destination_conflict_leaves_database_unchanged() {
    let conflicting = encode(&9_u64).expect("encode conflicting generation");
    let root_dir = create_schema_eleven_sidecar_fixture(Some(&conflicting));
    let database_path = root_dir.join("railgun").join("db.redb");
    let db = Database::open(&database_path).expect("open fixture");
    let meta_before = raw_table_rows(&db, META_TABLE);
    let settings_before = raw_table_rows(&db, RAW_APP_SETTINGS_TABLE);
    drop(db);

    assert!(matches!(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        }),
        Err(DbError::SchemaMigrationDestinationConflict {
            table: "poi_sidecar_state_v1",
            key,
        }) if key == POI_ARTIFACT_CACHE_GENERATION_KEY
    ));

    let db = Database::open(&database_path).expect("open rejected database");
    assert_eq!(raw_table_rows(&db, META_TABLE), meta_before);
    assert_eq!(raw_table_rows(&db, RAW_APP_SETTINGS_TABLE), settings_before);
    assert_eq!(
        raw_table_rows(&db, POI_SIDECAR_STATE_TABLE),
        BTreeMap::from([(POI_ARTIFACT_CACHE_GENERATION_KEY.to_string(), conflicting)])
    );
    assert!(!has_database_backup(&root_dir));

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn schema_eleven_sidecar_migration_failure_rolls_back() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    for (key, value) in schema_eleven_sidecar_rows() {
        put_app_row(&store, APP_SETTINGS, &key, &value);
    }
    let schema_eleven = Meta {
        schema_version: 11,
        app_version: "0.3.0-rc.1".to_string(),
        created_at: 124,
    };
    store
        .write_meta(&schema_eleven)
        .expect("write schema-11 meta");
    let settings_before = raw_table_rows(&store.db, RAW_APP_SETTINGS_TABLE);

    let result = store.run_migrations_transaction(&schema_eleven, 12, || {
        Err(DbError::Io(std::io::Error::other(
            "injected migration failure",
        )))
    });
    assert!(result.is_err());
    assert_eq!(
        store
            .read_meta()
            .expect("read rolled-back meta")
            .expect("meta present")
            .schema_version,
        11
    );
    assert_eq!(
        raw_table_rows(&store.db, RAW_APP_SETTINGS_TABLE),
        settings_before
    );
    assert!(raw_table_rows(&store.db, POI_SIDECAR_STATE_TABLE).is_empty());

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn newer_schema_is_rejected_without_replacing_database() {
    let root_dir = temp_db_root();
    {
        let store = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        store
            .write_meta(&Meta {
                schema_version: CURRENT_SCHEMA_VERSION + 1,
                app_version: "future".to_string(),
                created_at: 456,
            })
            .expect("write future meta");
    }

    assert!(matches!(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        }),
        Err(DbError::UnsupportedSchemaVersion { version })
            if version == CURRENT_SCHEMA_VERSION + 1
    ));
    let db = Database::open(root_dir.join("railgun").join("db.redb"))
        .expect("open rejected database directly");
    let txn = db.begin_read().expect("read rejected database");
    let table = txn
        .open_table(META_TABLE)
        .expect("open rejected meta table");
    let meta: Meta = decode(
        table
            .get(META_KEY)
            .expect("read rejected meta")
            .expect("rejected meta present")
            .value(),
    )
    .expect("decode rejected meta");
    assert_eq!(meta.schema_version, CURRENT_SCHEMA_VERSION + 1);

    drop(table);
    drop(txn);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
