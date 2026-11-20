use super::*;

#[test]
fn pending_output_poi_context_roundtrip_and_listing() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");

    let wallet_id = wallet_cache_key(0x01).to_string();
    let other_wallet_id = wallet_cache_key(0x02).to_string();
    let record = sample_pending_output_record(1, &wallet_id, FixedBytes::from([0x77; 32]));
    store
        .put_pending_output_poi_context(&record)
        .expect("store pending output POI context");

    let loaded = store
        .get_pending_output_poi_context(
            record.chain_id,
            &record.wallet_id,
            &record.output_commitment,
        )
        .expect("load pending output POI context")
        .expect("record present");
    assert_eq!(loaded.wallet_id, record.wallet_id);
    assert_eq!(loaded.txid_version, record.txid_version);
    assert_eq!(loaded.output_npk, record.output_npk);
    assert_eq!(loaded.output_role, PendingOutputPoiRole::Recipient);
    assert_eq!(loaded.required_poi_list_keys, record.required_poi_list_keys);
    assert!(loaded.observation.is_none());
    assert_eq!(loaded.submitted_poi_list_keys, [] as [FixedBytes<32>; 0]);
    assert!(loaded.terminal_error.is_none());

    let records = store
        .list_pending_output_poi_contexts(record.chain_id, &record.wallet_id)
        .expect("list pending output POI contexts");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].output_commitment, record.output_commitment);
    assert!(
        store
            .list_pending_output_poi_contexts(2, &record.wallet_id)
            .expect("list other chain pending output POI contexts")
            .is_empty()
    );
    assert!(
        store
            .list_pending_output_poi_contexts(record.chain_id, &other_wallet_id)
            .expect("list other wallet pending output POI contexts")
            .is_empty()
    );
    store
        .delete_pending_output_poi_context(
            record.chain_id,
            &record.wallet_id,
            &record.output_commitment,
        )
        .expect("delete pending output POI context");
    assert!(
        store
            .get_pending_output_poi_context(
                record.chain_id,
                &record.wallet_id,
                &record.output_commitment,
            )
            .expect("load deleted pending output POI context")
            .is_none()
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn output_poi_recovery_roundtrip_and_wallet_listing() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");

    let record = sample_output_poi_recovery_record(
        1,
        wallet_cache_key(0x0a).as_str(),
        FixedBytes::from([0x44; 32]),
    );
    let other_wallet = OutputPoiRecoveryRecord {
        wallet_id: wallet_cache_key(0x0b).to_string(),
        output_commitment: FixedBytes::from([0x66; 32]),
        ..record.clone()
    };

    store
        .put_output_poi_recovery(&record)
        .expect("store recovery record");
    store
        .put_output_poi_recovery(&other_wallet)
        .expect("store other wallet recovery record");

    let loaded = store
        .get_output_poi_recovery(
            record.chain_id,
            &record.wallet_id,
            &record.output_commitment,
        )
        .expect("load recovery record")
        .expect("record present");
    assert_eq!(loaded.status, OutputPoiRecoveryStatus::NotSelfOriginated);
    assert_eq!(loaded.source_tx_hash, record.source_tx_hash);
    assert_eq!(loaded.tx_input, record.tx_input);
    assert_eq!(loaded.last_error, record.last_error);

    let records = store
        .list_output_poi_recoveries(record.chain_id, &record.wallet_id)
        .expect("list wallet recovery records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].output_commitment, record.output_commitment);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn poi_publisher_manifest_watermarks_round_trip_and_are_isolated() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let first = PoiPublisherManifestWatermarkRecord {
        publisher_pubkey: FixedBytes::from([0x11; 32]),
        accepted_sequence: 7,
        accepted_manifest_hash: None,
        updated_at: u64::MAX,
    };
    let second = PoiPublisherManifestWatermarkRecord {
        publisher_pubkey: FixedBytes::from([0x22; 32]),
        accepted_sequence: 9,
        accepted_manifest_hash: None,
        updated_at: u64::MAX,
    };
    assert_eq!(
        first.key(),
        format!(
            "railgun:ppoi-sidecar:v1:publisher-manifest-watermark:{}",
            "11".repeat(32)
        )
    );

    store
        .advance_poi_publisher_manifest_watermark(first.publisher_pubkey, first.accepted_sequence)
        .expect("store first publisher watermark");
    store
        .advance_poi_publisher_manifest_watermark(second.publisher_pubkey, second.accepted_sequence)
        .expect("store second publisher watermark");
    put_app_row(&store, APP_SETTINGS, "wallet-settings", b"settings-v1");

    let loaded_first = store
        .get_poi_publisher_manifest_watermark(&first.publisher_pubkey)
        .expect("load first publisher watermark")
        .expect("first publisher watermark present");
    let loaded_second = store
        .get_poi_publisher_manifest_watermark(&second.publisher_pubkey)
        .expect("load second publisher watermark")
        .expect("second publisher watermark present");
    assert_ne!(loaded_first.updated_at, first.updated_at);
    assert_ne!(loaded_second.updated_at, second.updated_at);
    let mut expected_first = first.clone();
    expected_first.updated_at = loaded_first.updated_at;
    let mut expected_second = second.clone();
    expected_second.updated_at = loaded_second.updated_at;
    assert_eq!(loaded_first, expected_first);
    assert_eq!(loaded_second, expected_second);
    let retained = store
        .advance_poi_publisher_manifest_watermark(first.publisher_pubkey, 5)
        .expect("retain monotonic publisher watermark")
        .0;
    assert_eq!(retained.accepted_sequence, 7);
    assert!(
        store
            .get_poi_publisher_manifest_watermark(&FixedBytes::from([0x33; 32]))
            .expect("load missing publisher watermark")
            .is_none()
    );
    assert_eq!(
        get_app_row(&store, APP_SETTINGS, "wallet-settings")
            .expect("unrelated app setting present"),
        b"settings-v1"
    );

    let mismatched_key = PoiPublisherManifestWatermarkRecord::key_for(&second.publisher_pubkey);
    store
        .put_raw_poi_sidecar_state_for_test(
            &mismatched_key,
            &encode(&first).expect("encode watermark"),
        )
        .expect("store mismatched publisher watermark");
    assert!(matches!(
        store.get_poi_publisher_manifest_watermark(&second.publisher_pubkey),
        Err(DbError::InvalidPpoiSidecarRecord { .. })
    ));

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn poi_v4_publisher_manifest_binding_is_atomic_and_durable() {
    let root_dir = temp_db_root();
    let publisher = FixedBytes::from([0x51; 32]);
    let first_hash = FixedBytes::from([0x52; 32]);
    let second_hash = FixedBytes::from([0x53; 32]);
    {
        let store = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        store
            .advance_poi_publisher_manifest_watermark(publisher, 7)
            .expect("seed unbound legacy watermark");
        assert!(matches!(
            store
                .observe_poi_v4_publisher_manifest(publisher, 7, first_hash)
                .expect("bind publication"),
            PoiPublisherManifestObservation::Accepted { changed: true, .. }
        ));
        assert!(matches!(
            store
                .observe_poi_v4_publisher_manifest(publisher, 7, first_hash)
                .expect("observe same publication"),
            PoiPublisherManifestObservation::Accepted { changed: false, .. }
        ));
        assert!(matches!(
            store
                .observe_poi_v4_publisher_manifest(publisher, 7, second_hash)
                .expect("reject equivocation"),
            PoiPublisherManifestObservation::Equivocation { .. }
        ));
    }
    let reopened = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("reopen db");
    let watermark = reopened
        .get_poi_publisher_manifest_watermark(&publisher)
        .expect("read watermark")
        .expect("watermark present");
    assert_eq!(watermark.accepted_sequence, 7);
    assert_eq!(watermark.accepted_manifest_hash, Some(first_hash));
    let (retained, advanced) = reopened
        .advance_poi_publisher_manifest_watermark(publisher, 7)
        .expect("equal legacy observation preserves binding");
    assert!(!advanced);
    assert_eq!(retained.accepted_manifest_hash, Some(first_hash));
    assert!(matches!(
        reopened
            .observe_poi_v4_publisher_manifest(publisher, 6, first_hash)
            .expect("reject rollback"),
        PoiPublisherManifestObservation::Rollback { .. }
    ));
    let (unbound, advanced) = reopened
        .advance_poi_publisher_manifest_watermark(publisher, 8)
        .expect("higher legacy observation advances unbound");
    assert!(advanced);
    assert_eq!(unbound.accepted_manifest_hash, None);
    assert!(matches!(
        reopened
            .observe_poi_v4_publisher_manifest(publisher, 8, second_hash)
            .expect("bind higher publication"),
        PoiPublisherManifestObservation::Accepted { changed: true, .. }
    ));

    drop(reopened);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn poi_corpus_rpc_health_records_round_trip_and_are_isolated() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let first = PoiCorpusRpcHealthRecord {
        chain_type: 0,
        chain_id: 1,
        txid_version: "V3|PoseidonMerkle".to_string(),
        list_key: FixedBytes::from([0x44; 32]),
        cache_generation: 3,
        last_successful_rpc_sync_at_ms: Some(1_700_000_000_123),
        updated_at: u64::MAX,
    };
    let second = PoiCorpusRpcHealthRecord {
        chain_type: 0,
        chain_id: 137,
        txid_version: "V3|PoseidonMerkle".to_string(),
        list_key: FixedBytes::from([0x55; 32]),
        cache_generation: 4,
        last_successful_rpc_sync_at_ms: None,
        updated_at: u64::MAX,
    };
    assert_eq!(
        first.key(),
        format!(
            "railgun:ppoi-sidecar:v1:corpus-rpc-health:00:0000000000000001:{}:{}",
            alloy::hex::encode(first.txid_version.as_bytes()),
            "44".repeat(32)
        )
    );
    assert_ne!(
        first.key(),
        PoiCorpusRpcHealthRecord::key_for(1, first.chain_id, &first.txid_version, &first.list_key,)
    );
    assert_ne!(
        first.key(),
        PoiCorpusRpcHealthRecord::key_for(
            first.chain_type,
            2,
            &first.txid_version,
            &first.list_key,
        )
    );
    assert_ne!(
        first.key(),
        PoiCorpusRpcHealthRecord::key_for(
            first.chain_type,
            first.chain_id,
            "V3|Poseidon|Merkle",
            &first.list_key,
        )
    );
    assert_ne!(
        first.key(),
        PoiCorpusRpcHealthRecord::key_for(
            first.chain_type,
            first.chain_id,
            &first.txid_version,
            &FixedBytes::from([0x45; 32]),
        )
    );

    store
        .put_poi_corpus_rpc_health(&first)
        .expect("store first corpus RPC health");
    store
        .put_poi_corpus_rpc_health(&second)
        .expect("store second corpus RPC health");

    let loaded_first = store
        .get_poi_corpus_rpc_health(
            first.chain_type,
            first.chain_id,
            &first.txid_version,
            &first.list_key,
        )
        .expect("load first corpus RPC health")
        .expect("first corpus RPC health present");
    let loaded_second = store
        .get_poi_corpus_rpc_health(
            second.chain_type,
            second.chain_id,
            &second.txid_version,
            &second.list_key,
        )
        .expect("load second corpus RPC health")
        .expect("second corpus RPC health present");
    assert_ne!(loaded_first.updated_at, first.updated_at);
    assert_ne!(loaded_second.updated_at, second.updated_at);
    let mut expected_first = first.clone();
    expected_first.updated_at = loaded_first.updated_at;
    let mut expected_second = second.clone();
    expected_second.updated_at = loaded_second.updated_at;
    assert_eq!(loaded_first, expected_first);
    assert_eq!(loaded_second, expected_second);
    assert!(
        store
            .get_poi_corpus_rpc_health(
                first.chain_type,
                first.chain_id,
                "V2_PoseidonMerkle",
                &first.list_key,
            )
            .expect("load isolated corpus RPC health")
            .is_none()
    );

    let mismatched_key = PoiCorpusRpcHealthRecord::key_for(
        second.chain_type,
        second.chain_id,
        &second.txid_version,
        &second.list_key,
    );
    store
        .put_raw_poi_sidecar_state_for_test(
            &mismatched_key,
            &encode(&first).expect("encode corpus RPC health"),
        )
        .expect("store mismatched corpus RPC health");
    assert!(matches!(
        store.get_poi_corpus_rpc_health(
            second.chain_type,
            second.chain_id,
            &second.txid_version,
            &second.list_key,
        ),
        Err(DbError::InvalidPpoiSidecarRecord { .. })
    ));

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn poi_artifact_cache_scan_isolates_undecodable_rows() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let record = sample_poi_artifact_cache_record(1, FixedBytes::from([0x61; 32]));
    store
        .put_poi_artifact_cache(&record)
        .expect("store valid POI corpus");
    let undecodable_key = PoiArtifactCacheRecord::key_for(
        record.chain_type,
        138,
        &record.txid_version,
        &record.list_key,
    );
    let txn = store.db.begin_write().expect("begin malformed row write");
    {
        let mut table = txn
            .open_table(POI_ARTIFACT_CACHE_TABLE)
            .expect("open POI corpus table");
        table
            .insert(undecodable_key.as_str(), &[0xc1_u8][..])
            .expect("insert malformed POI corpus");
    }
    txn.commit().expect("commit malformed row");

    let mismatched_key = PoiArtifactCacheRecord::key_for(
        record.chain_type,
        137,
        &record.txid_version,
        &record.list_key,
    );
    let txn = store.db.begin_write().expect("begin mismatched row write");
    {
        let mut table = txn
            .open_table(POI_ARTIFACT_CACHE_TABLE)
            .expect("open POI corpus table");
        table
            .insert(
                mismatched_key.as_str(),
                encode(&record)
                    .expect("encode mismatched POI corpus")
                    .as_slice(),
            )
            .expect("insert mismatched POI corpus");
    }
    txn.commit().expect("commit mismatched row");

    assert!(matches!(
        store.get_poi_artifact_cache(
            record.chain_type,
            137,
            &record.txid_version,
            &record.list_key,
        ),
        Err(DbError::InvalidPpoiCorpusRecord { .. })
    ));
    assert!(matches!(
        store
            .inspect_poi_artifact_cache(
                record.chain_type,
                137,
                &record.txid_version,
                &record.list_key,
            )
            .expect("inspect mismatched corpus"),
        StoredRecord::Corrupt { .. }
    ));
    assert!(matches!(
        store
            .inspect_poi_artifact_cache(
                record.chain_type,
                138,
                &record.txid_version,
                &record.list_key,
            )
            .expect("inspect undecodable corpus"),
        StoredRecord::Corrupt { .. }
    ));

    let scan = store
        .scan_poi_artifact_caches()
        .expect("scan POI corpus records");
    assert_eq!(scan.records.len(), 1);
    let mut expected = record.clone();
    expected.updated_at = scan.records[0].updated_at;
    assert_eq!(scan.records, vec![expected]);
    assert_eq!(scan.invalid_keys, vec![mismatched_key, undecodable_key]);

    let mut replacement = record;
    replacement.chain_id = 138;
    store
        .put_poi_artifact_cache(&replacement)
        .expect("replace corrupt canonical corpus");
    assert!(matches!(
        store
            .inspect_poi_artifact_cache(
                replacement.chain_type,
                replacement.chain_id,
                &replacement.txid_version,
                &replacement.list_key,
            )
            .expect("inspect replacement corpus"),
        StoredRecord::Valid(_)
    ));

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn clear_poi_artifact_cache_removes_only_poi_artifact_records() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");

    let record_a = sample_poi_artifact_cache_record(1, FixedBytes::from([0x11; 32]));
    let record_b = sample_poi_artifact_cache_record(137, FixedBytes::from([0x22; 32]));
    store
        .put_poi_artifact_cache(&record_a)
        .expect("store first POI artifact cache");
    store
        .put_poi_artifact_cache(&record_b)
        .expect("store second POI artifact cache");
    put_app_row(&store, APP_SETTINGS, "wallet-settings", b"settings-v1");
    put_app_row(
        &store,
        DESKTOP_WALLET_VAULT,
        "vault|meta",
        b"encrypted metadata",
    );

    let (removed, generation) = store
        .clear_poi_artifact_cache_with_generation()
        .expect("clear POI artifact cache");

    assert_eq!(removed, 2);
    assert_eq!(generation, 1);
    assert_eq!(
        store
            .poi_artifact_cache_generation()
            .expect("load POI artifact cache generation"),
        generation
    );
    assert!(
        store
            .get_poi_artifact_cache(
                record_a.chain_type,
                record_a.chain_id,
                &record_a.txid_version,
                &record_a.list_key,
            )
            .expect("load first cleared POI artifact cache")
            .is_none()
    );
    assert!(
        store
            .get_poi_artifact_cache(
                record_b.chain_type,
                record_b.chain_id,
                &record_b.txid_version,
                &record_b.list_key,
            )
            .expect("load second cleared POI artifact cache")
            .is_none()
    );
    assert_eq!(
        get_app_row(&store, APP_SETTINGS, "wallet-settings").expect("settings still present"),
        b"settings-v1"
    );
    assert_eq!(
        get_app_row(&store, DESKTOP_WALLET_VAULT, "vault|meta")
            .expect("vault metadata still present"),
        b"encrypted metadata"
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
