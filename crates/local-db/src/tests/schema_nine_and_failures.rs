use super::*;

#[test]
fn schema_nine_released_poi_corpus_fixture_preserves_record_and_binds_generation() {
    #[derive(serde::Serialize)]
    struct ReleasedSchemaNinePoiArtifactCacheRecord {
        chain_type: u8,
        chain_id: u64,
        txid_version: String,
        list_key: FixedBytes<32>,
        source: PoiCacheRecordSource,
        validation: PoiCorpusValidationRecord,
        last_accepted_manifest_sequence: u64,
        base_descriptor: PoiArtifactDescriptorRecord,
        applied_delta_descriptors: Vec<PoiArtifactDescriptorRecord>,
        blocked_shields_descriptor: PoiArtifactDescriptorRecord,
        artifact_tip_index: Option<u64>,
        artifact_tip_root: Option<FixedBytes<32>>,
        current_tip_index: u64,
        current_tip_root: FixedBytes<32>,
        cache_payload: Vec<u8>,
        last_successful_rpc_sync_at_ms: Option<u64>,
        updated_at: u64,
    }

    let root_dir = temp_db_root();
    let fixture = sample_poi_artifact_cache_record(1, FixedBytes::from([0xa1; 32]));
    let key = fixture.key();
    let payload = encode(&ReleasedSchemaNinePoiArtifactCacheRecord {
        chain_type: fixture.chain_type,
        chain_id: fixture.chain_id,
        txid_version: fixture.txid_version.clone(),
        list_key: fixture.list_key,
        source: fixture.source,
        validation: fixture.validation.clone(),
        last_accepted_manifest_sequence: fixture.legacy_observed_manifest_sequence,
        base_descriptor: fixture.base_descriptor.clone(),
        applied_delta_descriptors: fixture.applied_delta_descriptors.clone(),
        blocked_shields_descriptor: fixture.blocked_shields_descriptor.clone(),
        artifact_tip_index: fixture.artifact_tip_index,
        artifact_tip_root: fixture.artifact_tip_root,
        current_tip_index: fixture.current_tip_index,
        current_tip_root: fixture.current_tip_root,
        cache_payload: fixture.cache_payload.clone(),
        last_successful_rpc_sync_at_ms: fixture.legacy_last_successful_rpc_sync_at_ms,
        updated_at: fixture.updated_at,
    })
    .expect("encode released schema-9 fixture");
    {
        let store = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open fixture db");
        put_raw_poi_artifact_record(&store, &key, &payload);
        put_app_row(
            &store,
            APP_SETTINGS,
            POI_ARTIFACT_CACHE_GENERATION_KEY,
            &encode(&4_u64).expect("encode generation"),
        );
        store
            .write_meta(&Meta {
                schema_version: 9,
                app_version: "0.1.0-alpha.9".to_string(),
                created_at: 321,
            })
            .expect("write schema-9 meta");
    }

    let reopened = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("migrate released schema-9 fixture");
    let migrated = reopened
        .get_poi_artifact_cache(0, 1, "V3_PoseidonMerkle", &fixture.list_key)
        .expect("read migrated corpus")
        .expect("migrated corpus present");
    assert_eq!(migrated.cache_generation, 4);
    assert_eq!(migrated.cache_payload, fixture.cache_payload);
    assert_eq!(
        reopened
            .poi_artifact_cache_generation()
            .expect("read moved generation"),
        4
    );
    assert_eq!(
        reopened
            .read_meta()
            .expect("read migrated meta")
            .expect("meta present")
            .schema_version,
        CURRENT_SCHEMA_VERSION
    );

    drop(reopened);
    fs::remove_dir_all(root_dir).expect("remove fixture db");
}

#[test]
fn schema_nine_poi_corpus_migration_rejects_key_conflict_without_mutation() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let record = sample_poi_artifact_cache_record(1, FixedBytes::from([0xa2; 32]));
    let conflicting_key = PoiArtifactCacheRecord::key_for(
        record.chain_type,
        137,
        &record.txid_version,
        &record.list_key,
    );
    let payload = encode(&record).expect("encode conflicting corpus");
    put_raw_poi_artifact_record(&store, &conflicting_key, &payload);
    let schema_nine = Meta {
        schema_version: 9,
        app_version: "0.1.0-alpha.9".to_string(),
        created_at: 322,
    };
    store.write_meta(&schema_nine).expect("write schema-9 meta");

    assert!(matches!(
        store.run_migrations_transaction(&schema_nine, 10, || Ok(())),
        Err(DbError::InvalidSchemaNinePpoiCorpusRecord { key }) if key == conflicting_key
    ));
    assert_eq!(
        store
            .read_meta()
            .expect("read retained meta")
            .expect("meta present")
            .schema_version,
        9
    );
    assert_eq!(
        store
            .db
            .begin_read()
            .expect("begin retained row read")
            .open_table(POI_ARTIFACT_CACHE_TABLE)
            .expect("open POI corpus table")
            .get(conflicting_key.as_str())
            .expect("read retained row")
            .expect("retained row present")
            .value(),
        payload.as_slice()
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn schema_nine_poi_corpus_migration_rejects_malformed_row_without_mutation() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let key =
        PoiArtifactCacheRecord::key_for(0, 1, "V3_PoseidonMerkle", &FixedBytes::from([0xa3; 32]));
    let payload = b"not-msgpack";
    put_raw_poi_artifact_record(&store, &key, payload);
    let schema_nine = Meta {
        schema_version: 9,
        app_version: "0.1.0-alpha.9".to_string(),
        created_at: 323,
    };
    store.write_meta(&schema_nine).expect("write schema-9 meta");

    assert!(matches!(
        store.run_migrations_transaction(&schema_nine, 10, || Ok(())),
        Err(DbError::InvalidSchemaNinePpoiCorpusRecord { key: invalid }) if invalid == key
    ));
    assert_eq!(
        store
            .read_meta()
            .expect("read retained meta")
            .expect("meta present")
            .schema_version,
        9
    );
    assert_eq!(
        store
            .db
            .begin_read()
            .expect("begin retained row read")
            .open_table(POI_ARTIFACT_CACHE_TABLE)
            .expect("open POI corpus table")
            .get(key.as_str())
            .expect("read retained row")
            .expect("retained row present")
            .value(),
        payload
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn schema_eight_to_current_preserves_existing_rows() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open store");
    put_app_row(&store, APP_SETTINGS, "schema-nine-sentinel", b"preserved");
    store
        .write_meta(&Meta {
            schema_version: 8,
            app_version: "pre-canonicalization".to_string(),
            created_at: 123,
        })
        .expect("write schema-eight metadata");
    drop(store);

    let reopened = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("migrate schema eight to current");
    assert_eq!(
        reopened
            .read_meta()
            .expect("read metadata")
            .expect("metadata present")
            .schema_version,
        CURRENT_SCHEMA_VERSION
    );
    assert_eq!(
        get_app_row(&reopened, APP_SETTINGS, "schema-nine-sentinel").expect("sentinel present"),
        b"preserved"
    );

    drop(reopened);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn schema_seven_migration_failure_rolls_back_rows_and_version() {
    let root_dir = temp_db_root();
    let wallet_id = wallet_cache_key(0x43);
    let row_id = "cd".repeat(32);
    let legacy_key = format!("wallet-cache-row|{wallet_id}|{row_id}");
    let pending_output =
        sample_pending_output_record(1, wallet_id.as_str(), FixedBytes::from([0x92; 32]));
    let legacy_pending_key = schema_seven_pending_output_key(&pending_output);
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    put_app_row(&store, DESKTOP_WALLET_VAULT, &legacy_key, b"encrypted");
    put_raw_pending_output_record(
        &store,
        &legacy_pending_key,
        &encode(&pending_output).expect("encode alpha pending context"),
    );
    let schema_seven = Meta {
        schema_version: 7,
        app_version: "0.1.0-alpha.6".to_string(),
        created_at: 123,
    };
    store
        .write_meta(&schema_seven)
        .expect("write schema-7 meta");

    let result = store.run_migrations_transaction(&schema_seven, 8, || {
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
        7
    );
    assert_eq!(
        get_app_row(&store, DESKTOP_WALLET_VAULT, &legacy_key).expect("legacy row present"),
        b"encrypted"
    );
    assert_eq!(
        store
            .list_wallet_utxos(&wallet_id)
            .expect("list rolled-back target rows"),
        [] as [crate::WalletUtxoRecord; 0]
    );
    assert!(raw_pending_output_record_exists(
        &store,
        &legacy_pending_key
    ));
    assert!(!raw_pending_output_record_exists(
        &store,
        &pending_output.key()
    ));

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn schema_seven_migration_rejects_malformed_pending_context_without_mutation() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let malformed_key = format!("1|{}", "ab".repeat(32));
    put_raw_pending_output_record(&store, &malformed_key, b"not-msgpack");
    let schema_seven = Meta {
        schema_version: 7,
        app_version: "0.1.0-alpha.6".to_string(),
        created_at: 123,
    };
    store
        .write_meta(&schema_seven)
        .expect("write schema-7 meta");

    assert!(matches!(
        store.run_migrations_transaction(&schema_seven, 8, || Ok(())),
        Err(DbError::InvalidSchemaSevenPendingOutputPoiContext { .. })
    ));
    assert_eq!(
        store
            .read_meta()
            .expect("read retained meta")
            .expect("meta present")
            .schema_version,
        7
    );
    assert!(raw_pending_output_record_exists(&store, &malformed_key));

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn schema_seven_migration_rejects_incomplete_pending_context_without_mutation() {
    #[derive(serde::Serialize)]
    struct IdentityOnlyPendingOutputContext {
        chain_id: u64,
        wallet_id: String,
        output_commitment: FixedBytes<32>,
    }

    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let wallet_id = WalletCacheKey::from_opaque_bytes(b"incomplete-pending-wallet")
        .expect("incomplete pending wallet key");
    let identity = IdentityOnlyPendingOutputContext {
        chain_id: 1,
        wallet_id: wallet_id.to_string(),
        output_commitment: FixedBytes::from([0x93; 32]),
    };
    let legacy_key = format!(
        "{}|{}",
        identity.chain_id,
        alloy::hex::encode(identity.output_commitment)
    );
    let canonical_key = PendingOutputPoiContextRecord::key_for(
        identity.chain_id,
        wallet_id.as_str(),
        &identity.output_commitment,
    );
    let payload = encode(&identity).expect("encode incomplete pending context");
    put_raw_pending_output_record(&store, &legacy_key, &payload);
    let schema_seven = Meta {
        schema_version: 7,
        app_version: "0.1.0-alpha.6".to_string(),
        created_at: 123,
    };
    store
        .write_meta(&schema_seven)
        .expect("write schema-7 meta");

    assert!(matches!(
        store.run_migrations_transaction(&schema_seven, 8, || Ok(())),
        Err(DbError::InvalidSchemaSevenPendingOutputPoiContext { .. })
    ));
    assert_eq!(
        store
            .read_meta()
            .expect("read retained meta")
            .expect("meta present")
            .schema_version,
        7
    );
    assert_eq!(
        store
            .db
            .begin_read()
            .expect("begin retained row read")
            .open_table(PENDING_OUTPUT_POI_CONTEXT_TABLE)
            .expect("open pending table")
            .get(legacy_key.as_str())
            .expect("read retained source row")
            .expect("source row present")
            .value(),
        payload.as_slice()
    );
    assert!(!raw_pending_output_record_exists(&store, &canonical_key));

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn schema_seven_migration_rejects_malformed_cache_rows_without_mutation() {
    let root_dir = temp_db_root();
    let malformed_key = format!("wallet-cache-row|not-hex|{}", "ab".repeat(32));
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    put_app_row(&store, DESKTOP_WALLET_VAULT, &malformed_key, b"encrypted");
    let schema_seven = Meta {
        schema_version: 7,
        app_version: "0.1.0-alpha.6".to_string(),
        created_at: 123,
    };
    store
        .write_meta(&schema_seven)
        .expect("write schema-7 meta");

    assert!(matches!(
        store.run_migrations_transaction(&schema_seven, 8, || Ok(())),
        Err(DbError::InvalidLegacyDesktopWalletCacheRowKey { .. })
    ));
    assert_eq!(
        store
            .read_meta()
            .expect("read unchanged meta")
            .expect("meta present")
            .schema_version,
        7
    );
    assert_eq!(
        get_app_row(&store, DESKTOP_WALLET_VAULT, &malformed_key).expect("malformed row present"),
        b"encrypted"
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
