use super::*;

#[tokio::test]
async fn indexed_artifacts_status_refresh_does_not_call_remote_pois_per_list() {
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut wallet_utxos = vec![test_wallet_utxo(1)];
    let blinded_commitment = wallet_utxos[0].utxo.poi.blinded_commitment;
    let mut cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        1,
        DEFAULT_TXID_VERSION,
        list_key,
    ));
    cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: *blinded_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply artifact event");
    cache.accept_current_roots();
    let cfg = wallet_config(U256::ZERO);
    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let public_data_plane = test_public_data_plane_with_poi_service(&db);
    seed_data_plane_poi_cache(&public_data_plane, cfg.chain.chain_id, list_key, cache).await;
    let mock = spawn_poi_rpc(serde_json::json!({})).await;
    let poi_runtime = test_artifact_poi_runtime();
    let status_reader = poi_runtime
        .status_reader_for_job(&public_data_plane, &cfg, &list_keys)
        .await
        .expect("local POI status reader");

    let outcome = refresh_wallet_poi_statuses_selected(
        status_reader.as_reader(),
        cfg.chain.chain_id,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(outcome.changed);
    assert!(outcome.complete);
    assert_eq!(
        wallet_utxos[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );
    assert!(
        mock.requests
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "remote ppoi_pois_per_list should not be called"
    );
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn poi_proxy_status_refresh_calls_remote_pois_per_list_without_local_ingestion() {
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut wallet_utxos = vec![test_wallet_utxo(1)];
    let blinded_commitment = wallet_utxos[0].utxo.poi.blinded_commitment;
    let mock = spawn_poi_rpc(serde_json::json!({
        hex::encode_prefixed(blinded_commitment): {
            hex::encode(list_key): "Valid",
        }
    }))
    .await;
    let cfg = wallet_config(U256::ZERO);
    let poi_runtime = WalletPoiRuntime::from_policy(
        &GlobalPoiPolicy::PoiProxy {
            rpc_url: mock.url.clone().into(),
        },
        None,
    );
    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let public_data_plane = ChainPublicDataPlane::new(Arc::clone(&db), Arc::new(AtomicU64::new(0)));
    let status_reader = poi_runtime
        .status_reader_for_job(&public_data_plane, &cfg, &list_keys)
        .await
        .expect("remote POI status reader");

    let outcome = refresh_wallet_poi_statuses_selected(
        status_reader.as_reader(),
        cfg.chain.chain_id,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    let request = mock
        .requests
        .recv_timeout(Duration::from_secs(2))
        .expect("remote status request");
    assert_eq!(request["method"], "ppoi_pois_per_list");
    assert!(outcome.changed);
    assert!(outcome.complete);
    assert_eq!(
        wallet_utxos[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn indexed_artifacts_proxy_fallback_calls_remote_when_corpus_unavailable() {
    let list_key = FixedBytes::from([0x12; 32]);
    let list_keys = vec![list_key];
    let mut wallet_utxos = vec![test_wallet_utxo(1)];
    let blinded_commitment = wallet_utxos[0].utxo.poi.blinded_commitment;
    let mock = spawn_poi_rpc(serde_json::json!({
        hex::encode_prefixed(blinded_commitment): {
            hex::encode(list_key): "Valid",
        }
    }))
    .await;
    let cfg = wallet_config(U256::ZERO);
    let poi_runtime = test_artifact_poi_runtime_with_fallback(mock.url.clone());
    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let public_data_plane = test_public_data_plane_with_poi_service(&db);
    let status_reader = poi_runtime
        .status_reader_for_job(&public_data_plane, &cfg, &list_keys)
        .await
        .expect("fallback POI status reader");

    let outcome = refresh_wallet_poi_statuses_selected(
        status_reader.as_reader(),
        cfg.chain.chain_id,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(outcome.changed);
    assert!(outcome.complete);
    assert_eq!(
        wallet_utxos[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );
    let request = mock
        .requests
        .recv_timeout(Duration::from_secs(2))
        .expect("remote fallback status request");
    assert_eq!(request["method"], "ppoi_pois_per_list");
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn indexed_artifacts_proxy_fallback_does_not_probe_remote_for_ready_local_missing() {
    let list_key = FixedBytes::from([0x13; 32]);
    let list_keys = vec![list_key];
    let mut wallet_utxos = vec![test_wallet_utxo(1)];
    let mock = spawn_poi_rpc(serde_json::json!({})).await;
    let cfg = wallet_config(U256::ZERO);
    let poi_runtime = test_artifact_poi_runtime_with_fallback(mock.url.clone());
    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let public_data_plane = test_public_data_plane_with_poi_service(&db);
    let mut cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        cfg.chain.chain_id,
        DEFAULT_TXID_VERSION,
        list_key,
    ));
    cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: [0x99; 32],
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply artifact event");
    cache.accept_current_roots();
    seed_data_plane_poi_cache(&public_data_plane, cfg.chain.chain_id, list_key, cache).await;
    let status_reader = poi_runtime
        .status_reader_for_job(&public_data_plane, &cfg, &list_keys)
        .await
        .expect("local POI status reader");

    let outcome = refresh_wallet_poi_statuses_selected(
        status_reader.as_reader(),
        cfg.chain.chain_id,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(outcome.changed);
    assert!(outcome.complete);
    assert_eq!(
        wallet_utxos[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Missing)
    );
    assert!(
        mock.requests
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "ready local missing must not trigger remote fallback"
    );
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_poi_status_client_uses_configured_rpc_url() {
    let list_key = FixedBytes::from([0x11; 32]);
    let mock = spawn_poi_rpc(serde_json::json!({})).await;
    let rpc_url = SensitiveUrl::from(mock.url.clone());
    let client = wallet_poi_status_client(&rpc_url, None);

    client
        .pois_per_list(DEFAULT_TXID_VERSION, EVM_CHAIN_TYPE, 1, &[list_key], &[])
        .await
        .expect("POI status request");

    let request = mock
        .requests
        .recv_timeout(Duration::from_secs(2))
        .expect("configured POI RPC request");
    assert_eq!(request["method"], "ppoi_pois_per_list");
}

#[tokio::test]
async fn poi_proxy_merkle_proof_source_calls_remote_merkle_proofs() {
    let list_key = FixedBytes::from([0x11; 32]);
    let blinded_commitment = FixedBytes::from([0x22; 32]);
    let mock = spawn_poi_rpc(serde_json::json!([{
        "leaf": hex::encode_prefixed(blinded_commitment),
        "elements": [],
        "indices": "0x00",
        "root": "0x00",
    }]))
    .await;
    let client = PoiRpcClient::new(mock.url.clone());

    let proofs = client
        .poi_merkle_proofs(
            DEFAULT_TXID_VERSION,
            EVM_CHAIN_TYPE,
            1,
            &list_key,
            &[blinded_commitment],
        )
        .await
        .expect("remote proof response");

    let request = mock
        .requests
        .recv_timeout(Duration::from_secs(2))
        .expect("remote proof request");
    assert_eq!(request["method"], "ppoi_merkle_proofs");
    assert_eq!(proofs.len(), 1);
    assert_eq!(proofs[0].leaf, U256::from_be_bytes(blinded_commitment.0));
}

#[tokio::test]
async fn local_poi_merkle_proof_source_reads_cache_without_remote_merkle_proofs() {
    let list_key = FixedBytes::from([0x11; 32]);
    let blinded_commitment = FixedBytes::from([0x22; 32]);
    let mut cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        1,
        DEFAULT_TXID_VERSION,
        list_key,
    ));
    cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: *blinded_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply artifact event");
    cache.accept_current_roots();
    let local_caches = WalletLocalPoiCaches::new_for_test(BTreeMap::from([(list_key, cache)]));
    let source = LocalPoiMerkleProofSource::new(local_caches);

    let proofs = source
        .poi_merkle_proofs(
            DEFAULT_TXID_VERSION,
            EVM_CHAIN_TYPE,
            1,
            &list_key,
            &[blinded_commitment],
        )
        .await
        .expect("local proof");

    assert_eq!(proofs.len(), 1);
    assert_eq!(proofs[0].leaf, U256::from_be_bytes(blinded_commitment.0));
}
