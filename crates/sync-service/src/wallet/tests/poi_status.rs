use super::*;

#[test]
fn output_poi_recovery_proof_panic_uses_long_backoff() {
    let panic_err = PreTransactionPoiError::Prover(ProverError::WorkerPanic("boom".to_string()));
    assert_eq!(
        output_poi_recovery_proof_retry_after(&panic_err),
        OUTPUT_POI_RECOVERY_PROOF_FAILURE_RETRY_AFTER
    );

    let transient_err = PreTransactionPoiError::InputCountMismatch {
        expected: 1,
        got: 0,
    };
    assert_eq!(
        output_poi_recovery_proof_retry_after(&transient_err),
        OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER
    );
}

#[tokio::test]
async fn poi_status_refresh_chunks_unspent_utxos() {
    let client = RecordingPoiStatusClient::default();
    let list_keys = vec![FixedBytes::from([0x11; 32]), FixedBytes::from([0x22; 32])];
    let mut wallet_utxos = (0..=WALLET_POI_STATUS_BATCH_SIZE)
        .map(|position| test_wallet_utxo(position as u64))
        .collect::<Vec<_>>();

    let outcome = refresh_wallet_poi_statuses_selected(
        &client,
        1,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(outcome.changed);
    assert!(outcome.complete);
    let calls = client.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].0, list_keys);
    assert_eq!(calls[0].1.len(), WALLET_POI_STATUS_BATCH_SIZE);
    assert_eq!(calls[1].0, list_keys);
    assert_eq!(calls[1].1.len(), 1);
    assert!(wallet_utxos.iter().all(|wallet_utxo| {
        wallet_utxo.utxo.poi.is_valid_for_lists(&list_keys)
            && wallet_utxo.utxo.poi.refreshed_at.is_some()
    }));
}

#[tokio::test]
async fn remote_poi_status_refresh_uses_gateway_and_actor_intent_apply() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let list_key = FixedBytes::from([0x31; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-remote-status");
    let wallet_utxo = test_wallet_utxo(31);
    let mut handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let transport = Arc::new(RecordingPoiStatusClient::default());
    let private_poi =
        WalletPrivatePoiClients::for_status(authority.remote_authority(), transport.clone());

    let changed = refresh_wallet_poi_statuses_remote_authorized(
        &authority,
        &private_poi,
        &store,
        &store,
        &cfg,
        &[list_key],
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(changed);
    assert_eq!(transport.calls().len(), 1);
    let snapshot = handle.current_snapshot().expect("current wallet view");
    let refreshed = snapshot
        .utxos
        .iter()
        .find(|utxo| utxo.utxo.poi.commitment == wallet_utxo.utxo.poi.commitment)
        .expect("refreshed UTXO");
    assert_eq!(
        refreshed.utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn delayed_remote_status_intent_does_not_overwrite_newer_local_status() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let list_key = FixedBytes::from([0x32; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-status-cas");
    let wallet_utxo = test_wallet_utxo(32);
    let blinded_commitment = wallet_utxo.utxo.poi.blinded_commitment;
    let expected_poi = wallet_utxo.utxo.poi.clone();
    let mut handle = test_wallet_handle(vec![wallet_utxo]);
    handle.cache_key = cfg.cache_key.clone();
    {
        let mut current = handle.utxos.write().await;
        let _ = current[0].utxo.poi.apply_status_refresh(
            &[list_key],
            Some(&BTreeMap::from([(list_key, PoiStatus::Valid)])),
            200,
        );
    }
    let cancel = CancellationToken::new();
    let outcome = apply_owned_poi_private_delta_on_actor(
        &handle,
        &cancel,
        0,
        &store,
        &store,
        &cfg,
        OwnedPoiPrivateDelta::PoiStatusRefresh(PoiStatusRefreshDelta {
            active_list_keys: vec![list_key],
            expected_poi_by_blinded_commitment: BTreeMap::from([(
                blinded_commitment,
                expected_poi,
            )]),
            statuses_by_blinded_commitment: BTreeMap::from([(
                blinded_commitment,
                BTreeMap::from([(list_key, PoiStatus::Missing)]),
            )]),
            refreshed_at: 100,
        }),
    )
    .await
    .expect("apply delayed remote status intent");

    assert_eq!(outcome, PoiPrivateApplyOutcome::Skipped);
    let current = handle.utxos.read().await;
    assert_eq!(
        current[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );
    assert_eq!(current[0].utxo.poi.refreshed_at, Some(200));

    drop(current);
    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn local_poi_status_refresh_reads_cache_without_remote_pois_per_list() {
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut wallet_utxos = vec![test_wallet_utxo(1), test_wallet_utxo(2)];
    let valid_blinded_commitment = wallet_utxos[0].utxo.poi.blinded_commitment;
    let missing_blinded_commitment = wallet_utxos[1].utxo.poi.blinded_commitment;
    let mut cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        1,
        DEFAULT_TXID_VERSION,
        list_key,
    ));
    cache
        .apply_poi_leaves(0, &[U256::from_be_bytes(valid_blinded_commitment.0)])
        .expect("apply local poi leaf");
    let local_caches = WalletLocalPoiCaches::new_for_test(BTreeMap::from([(list_key, cache)]));
    let local_reader = LocalPoiStatusReader::new(local_caches);
    let unused_remote = RecordingPoiStatusClient::default();

    let outcome = refresh_wallet_poi_statuses_selected(
        &local_reader,
        1,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(outcome.changed);
    assert!(outcome.complete);
    assert_eq!(
        unused_remote.calls(),
        [] as [(Vec<FixedBytes<32>>, Vec<BlindedCommitmentData>); 0]
    );
    assert_eq!(
        wallet_utxos[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );
    assert_eq!(
        wallet_utxos[1].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Missing)
    );
    assert_eq!(
        wallet_utxos[0].utxo.poi.blinded_commitment,
        valid_blinded_commitment
    );
    assert_eq!(
        wallet_utxos[1].utxo.poi.blinded_commitment,
        missing_blinded_commitment
    );
}

#[tokio::test]
async fn observed_local_valid_context_suppresses_submission_after_restart() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let list_key = FixedBytes::from([0x41; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-local-valid-restart");
    let wallet_utxo = test_wallet_utxo(41);
    let pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    store
        .put_pending_output_poi_context(&pending)
        .expect("store observed context");
    let mut handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let reader = local_status_reader_for_lists(
        wallet_utxo.utxo.poi.blinded_commitment,
        &[list_key],
        &[list_key],
    );

    let outcome = super::super::pending_output_poi::reconcile_pending_output_poi_local_statuses(
        &authority,
        &reader,
        store.as_ref(),
        &cfg,
        store.as_ref(),
        &[list_key],
    )
    .await;
    assert_eq!(outcome.completed, 1);
    assert_eq!(outcome.pending, 0);

    let submitter = Arc::new(RecordingPendingOutputPoiSubmitter::default());
    let private_poi =
        WalletPrivatePoiClients::for_submit(authority.remote_authority(), submitter.clone());
    assert_eq!(
        process_pending_output_poi_observations_authorized(
            &authority,
            &test_public_data_plane_with_poi_service(&store),
            store.as_ref(),
            store.as_ref(),
            &cfg,
            &[list_key],
            Some(&private_poi),
            false,
        )
        .await,
        0
    );
    assert_eq!(submitter.calls(), [] as [(FixedBytes<32>, u64, u64); 0]);
    assert!(
        store
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &pending.output_commitment
            )
            .expect("load completed context")
            .is_none()
    );
    assert_eq!(
        store
            .get_output_poi_recovery(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &pending.output_commitment
            )
            .expect("load completed recovery")
            .expect("owned valid recovery")
            .status,
        OutputPoiRecoveryStatus::Valid
    );
    assert_eq!(
        handle.utxos.read().await[0]
            .utxo
            .poi
            .statuses
            .get(&list_key),
        Some(&PoiStatus::Valid)
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn external_local_valid_context_completes_without_submission() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let list_key = FixedBytes::from([0x42; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-external-local-valid");
    let pending =
        external_pending_output_record(&cfg, 0x42, list_key, PendingOutputPoiRole::Recipient);
    let identity = pending_output_poi_submit_identity(
        &pending,
        pending
            .observation
            .as_ref()
            .expect("observed external context"),
    )
    .expect("external submit identity");
    store
        .put_pending_output_poi_context(&pending)
        .expect("store external context");
    let mut handle = test_wallet_handle(Vec::new());
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let reader = local_status_reader_for_lists(
        identity.derived_blinded_commitment,
        &[list_key],
        &[list_key],
    );

    let outcome = super::super::pending_output_poi::reconcile_pending_output_poi_local_statuses(
        &authority,
        &reader,
        store.as_ref(),
        &cfg,
        store.as_ref(),
        &[list_key],
    )
    .await;
    assert_eq!(outcome.completed, 1);
    let submitter = Arc::new(RecordingPendingOutputPoiSubmitter::default());
    let private_poi =
        WalletPrivatePoiClients::for_submit(authority.remote_authority(), submitter.clone());
    assert_eq!(
        process_pending_output_poi_observations_authorized(
            &authority,
            &test_public_data_plane_with_poi_service(&store),
            store.as_ref(),
            store.as_ref(),
            &cfg,
            &[list_key],
            Some(&private_poi),
            false,
        )
        .await,
        0
    );
    assert_eq!(submitter.calls(), [] as [(FixedBytes<32>, u64, u64); 0]);
    assert!(
        store
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &pending.output_commitment
            )
            .expect("load completed external context")
            .is_none()
    );
    assert!(
        store
            .get_output_poi_recovery(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &pending.output_commitment
            )
            .expect("load external recovery")
            .is_none()
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn partial_local_validity_submits_only_unresolved_list() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let list_a = FixedBytes::from([0x43; 32]);
    let list_b = FixedBytes::from([0x44; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-partial-local-valid");
    let wallet_utxo = test_wallet_utxo(43);
    let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, list_a);
    pending.required_poi_list_keys.push(list_b);
    pending.pre_transaction_pois_per_txid_leaf_per_list.insert(
        list_b,
        BTreeMap::from([(FixedBytes::from([0x77; 32]), sample_pre_tx_poi(0x77))]),
    );
    store
        .put_pending_output_poi_context(&pending)
        .expect("store partial context");
    let mut handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let reader = local_status_reader_for_lists(
        wallet_utxo.utxo.poi.blinded_commitment,
        &[list_a, list_b],
        &[list_a],
    );

    let outcome = super::super::pending_output_poi::reconcile_pending_output_poi_local_statuses(
        &authority,
        &reader,
        store.as_ref(),
        &cfg,
        store.as_ref(),
        &[list_a, list_b],
    )
    .await;
    assert_eq!(outcome.completed, 0);
    assert_eq!(outcome.pending, 1);
    let submitter = Arc::new(RecordingPendingOutputPoiSubmitter::default());
    let private_poi =
        WalletPrivatePoiClients::for_submit(authority.remote_authority(), submitter.clone());
    assert_eq!(
        process_pending_output_poi_observations_authorized(
            &authority,
            &test_public_data_plane_with_poi_service(&store),
            store.as_ref(),
            store.as_ref(),
            &cfg,
            &[list_a, list_b],
            Some(&private_poi),
            false,
        )
        .await,
        1
    );
    assert_eq!(submitter.list_key_calls(), vec![vec![list_b]]);
    assert_eq!(
        handle.utxos.read().await[0].utxo.poi.statuses.get(&list_a),
        Some(&PoiStatus::Valid)
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn local_missing_status_keeps_canonical_submission_eligible() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let list_key = FixedBytes::from([0x45; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-local-missing");
    let wallet_utxo = test_wallet_utxo(45);
    let pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    store
        .put_pending_output_poi_context(&pending)
        .expect("store missing context");
    let mut handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let reader =
        local_status_reader_for_lists(wallet_utxo.utxo.poi.blinded_commitment, &[list_key], &[]);
    let outcome = super::super::pending_output_poi::reconcile_pending_output_poi_local_statuses(
        &authority,
        &reader,
        store.as_ref(),
        &cfg,
        store.as_ref(),
        &[list_key],
    )
    .await;
    assert_eq!(outcome.completed, 0);
    assert_eq!(outcome.pending, 0);

    let submitter = Arc::new(RecordingPendingOutputPoiSubmitter::default());
    let private_poi =
        WalletPrivatePoiClients::for_submit(authority.remote_authority(), submitter.clone());
    assert_eq!(
        process_pending_output_poi_observations_authorized(
            &authority,
            &test_public_data_plane_with_poi_service(&store),
            store.as_ref(),
            store.as_ref(),
            &cfg,
            &[list_key],
            Some(&private_poi),
            false,
        )
        .await,
        1
    );
    assert_eq!(submitter.list_key_calls(), vec![vec![list_key]]);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

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

#[tokio::test]
async fn live_poi_tail_applies_public_leaves_and_validates_root() {
    let list_key = FixedBytes::from([7_u8; 32]);
    let blinded_commitment = FixedBytes::from([0x33; 32]);
    let artifact_commitment = FixedBytes::from([0x22; 32]);
    let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
    let mut expected_cache = PoiCache::new(identity.clone());
    expected_cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: *artifact_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply artifact artifact_bound event");
    expected_cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 1,
            blinded_commitment: *blinded_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Shield,
        }])
        .expect("apply expected leaf");
    let expected_root = *expected_cache
        .current_roots()
        .get(&0)
        .expect("expected root");
    let leaves = vec![U256::from_be_bytes(blinded_commitment.0)];
    let mock =
        spawn_poi_rpc_sequence(vec![poi_leaf_response(&leaves), serde_json::json!(true)]).await;
    let client = PoiRpcClient::new(mock.url.clone());
    let mut cache = PoiCache::new(identity);
    cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: *artifact_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply artifact artifact_bound event");
    cache.accept_current_roots();

    let outcome = sync_live_poi_event_tail(&client, &mut cache)
        .await
        .expect("live tail sync");

    let request = mock
        .requests
        .recv_timeout(Duration::from_secs(2))
        .expect("remote leaf request");
    assert_eq!(request["method"], "ppoi_poi_merkletree_leaves");
    let request = mock
        .requests
        .recv_timeout(Duration::from_secs(2))
        .expect("remote root validation request");
    assert_eq!(request["method"], "ppoi_validate_poi_merkleroots");
    assert_eq!(outcome.events, 1);
    assert_eq!(outcome.start_index, 1);
    assert_eq!(outcome.next_event_index, 2);
    assert_eq!(cache.current_roots().get(&0), Some(&expected_root));
    let proof = cache
        .poi_merkle_proofs(&[blinded_commitment])
        .expect("proof after live root validation");
    assert_eq!(proof[0].leaf, U256::from_be_bytes(blinded_commitment.0));
}

#[tokio::test]
async fn live_poi_tail_stops_at_merkle_zero_padding() {
    let list_key = FixedBytes::from([8_u8; 32]);
    let blinded_commitment = FixedBytes::from([0x44; 32]);
    let artifact_commitment = FixedBytes::from([0x22; 32]);
    let zero_leaf = FixedBytes::from(MERKLE_ZERO_VALUE.to_be_bytes::<32>());
    let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
    let mut expected_cache = PoiCache::new(identity.clone());
    expected_cache
        .apply_verified_artifact_events(&[
            poi::artifacts::SnapshotEvent {
                event_index: 0,
                blinded_commitment: *artifact_commitment,
                signature: [0_u8; 64],
                event_type: PoiEventType::Transact,
            },
            poi::artifacts::SnapshotEvent {
                event_index: 1,
                blinded_commitment: *blinded_commitment,
                signature: [0_u8; 64],
                event_type: PoiEventType::Shield,
            },
        ])
        .expect("apply expected leaves");
    let expected_root = *expected_cache
        .current_roots()
        .get(&0)
        .expect("expected root");
    let leaves = vec![
        U256::from_be_bytes(blinded_commitment.0),
        MERKLE_ZERO_VALUE,
        U256::from_be_bytes([0x55; 32]),
    ];
    let mock =
        spawn_poi_rpc_sequence(vec![poi_leaf_response(&leaves), serde_json::json!(true)]).await;
    let client = PoiRpcClient::new(mock.url.clone());
    let mut cache = PoiCache::new(identity);
    cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: *artifact_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply artifact artifact_bound event");
    cache.accept_current_roots();

    let outcome = sync_live_poi_event_tail(&client, &mut cache)
        .await
        .expect("live tail sync");

    assert_eq!(outcome.events, 1);
    assert_eq!(outcome.start_index, 1);
    assert_eq!(outcome.next_event_index, 2);
    assert_eq!(cache.current_roots().get(&0), Some(&expected_root));
    assert!(cache.position(&zero_leaf).is_none());
}

#[test]
fn dense_merkle_tree_matches_forest_proof_and_removal_roots() {
    let mut forest = MerkleForest::default();
    for position in [0_u64, 1, 2, 7, 8, 9, 42] {
        forest
            .insert_leaf(MerkleTreeUpdate {
                tree_number: 0,
                tree_position: position,
                hash: U256::from(position + 100),
            })
            .expect("insert leaf");
    }

    let mut dense = DenseMerkleTree::from_forest_prefix(&forest, 0, 43);
    let dense_proof = dense.prove(7);
    let sparse_proof = forest
        .prove_with_leaf_count(0, 7, 43)
        .expect("sparse proof");
    assert_eq!(dense_proof.root, sparse_proof.root);
    assert_eq!(dense_proof.leaf, sparse_proof.leaf);
    assert_eq!(dense_proof.path_elements, sparse_proof.path_elements);
    assert_eq!(dense_proof.path_indices, sparse_proof.path_indices);

    for position in (10_u64..43).rev() {
        dense.remove_leaf(position);
    }
    let dense_short_proof = dense.prove(7);
    let sparse_short_proof = forest
        .prove_with_leaf_count(0, 7, 10)
        .expect("sparse short proof");
    assert_eq!(dense_short_proof.root, sparse_short_proof.root);
    assert_eq!(
        dense_short_proof.path_elements,
        sparse_short_proof.path_elements
    );
}

#[tokio::test]
async fn tailed_cache_install_skips_when_current_cache_advanced() {
    let list_key = FixedBytes::from([0x11; 32]);
    let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
    let initial_commitment = FixedBytes::from([0x22; 32]);
    let stale_tail_commitment = FixedBytes::from([0x33; 32]);
    let current_tail_commitment = FixedBytes::from([0x44; 32]);

    let mut initial_cache = PoiCache::new(identity);
    initial_cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: *initial_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply initial event");
    initial_cache.accept_current_roots();
    let original_next_event_index = initial_cache.progress().next_event_index;

    let local_caches =
        WalletLocalPoiCaches::new_for_test(BTreeMap::from([(list_key, initial_cache.clone())]));
    let mut stale_tail_cache = initial_cache;
    stale_tail_cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 1,
            blinded_commitment: *stale_tail_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply stale tail event");

    {
        let mut locked = local_caches.write().await;
        let current = locked.get_mut(&list_key).expect("current cache");
        current
            .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
                event_index: 1,
                blinded_commitment: *current_tail_commitment,
                signature: [0_u8; 64],
                event_type: PoiEventType::Transact,
            }])
            .expect("advance current cache");
        current.accept_current_roots();
    }

    let installed = install_tailed_poi_cache_if_current(
        &local_caches,
        list_key,
        stale_tail_cache,
        original_next_event_index,
    )
    .await;

    let locked = local_caches.read().await;
    let current = locked.get(&list_key).expect("current cache");
    assert!(!installed);
    assert!(current.position(&current_tail_commitment).is_some());
    assert!(current.position(&stale_tail_commitment).is_none());
}

#[tokio::test]
async fn poi_status_refresh_needed_after_indexed_delta_discovers_utxo() {
    let client = RecordingPoiStatusClient::default();
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let cfg = wallet_config(U256::ZERO);
    let mut wallet_utxos = Vec::new();
    let delta = WalletLogDelta {
        utxos: vec![test_wallet_utxo(1).utxo],
        nullifiers: Vec::new(),
        commitment_observations: Vec::new(),
        sender_scan_outputs: Vec::new(),
    };

    assert!(apply_wallet_delta_to_vec(&cfg, &mut wallet_utxos, delta));
    assert!(wallet_poi_status_refresh_needed(&wallet_utxos, &list_keys));

    let outcome = refresh_wallet_poi_statuses_selected(
        &client,
        cfg.chain.chain_id,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(outcome.changed);
    assert!(outcome.complete);
    assert!(!wallet_poi_status_refresh_needed(&wallet_utxos, &list_keys));
    assert_eq!(client.calls().len(), 1);
    assert_eq!(
        wallet_utxos[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );
    assert!(wallet_utxos[0].utxo.poi.refreshed_at.is_some());
}

#[test]
fn stale_missing_poi_status_is_refresh_needed_after_ttl() {
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut wallet_utxo = test_wallet_utxo(1);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    wallet_utxo.utxo.poi.refreshed_at = Some(100);
    let wallet_utxos = vec![wallet_utxo];

    assert!(!wallet_poi_status_refresh_needed_for_selection(
        &wallet_utxos,
        &list_keys,
        WalletPoiRefreshSelection::RecoverableStale {
            now: 100 + WALLET_POI_RECOVERABLE_REFRESH_AFTER.as_secs() - 1,
        },
    ));
    assert!(wallet_poi_status_refresh_needed_for_selection(
        &wallet_utxos,
        &list_keys,
        WalletPoiRefreshSelection::RecoverableStale {
            now: 100 + WALLET_POI_RECOVERABLE_REFRESH_AFTER.as_secs(),
        },
    ));
}

#[test]
fn stale_transact_missing_without_pending_context_is_timer_retryable() {
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut wallet_utxo = test_wallet_utxo_with_kind(1, UtxoCommitmentKind::Transact);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    wallet_utxo.utxo.poi.refreshed_at = Some(100);
    let wallet_utxos = vec![wallet_utxo];

    assert!(wallet_poi_status_refresh_needed_for_selection(
        &wallet_utxos,
        &list_keys,
        WalletPoiRefreshSelection::RecoverableStale {
            now: 100 + WALLET_POI_RECOVERABLE_REFRESH_AFTER.as_secs(),
        },
    ));
}

#[test]
fn stale_shield_missing_remains_timer_retryable_without_pending_context() {
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut wallet_utxo = test_wallet_utxo_with_kind(1, UtxoCommitmentKind::Shield);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    wallet_utxo.utxo.poi.refreshed_at = Some(100);
    let wallet_utxos = vec![wallet_utxo];

    assert!(wallet_poi_status_refresh_needed_for_selection(
        &wallet_utxos,
        &list_keys,
        WalletPoiRefreshSelection::RecoverableStale {
            now: 100 + WALLET_POI_RECOVERABLE_REFRESH_AFTER.as_secs(),
        },
    ));
}

#[test]
fn blocked_shield_revision_rechecks_all_owned_shield_statuses() {
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut blocked = test_wallet_utxo_with_kind(1, UtxoCommitmentKind::Shield);
    blocked
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::ShieldBlocked);
    blocked.utxo.poi.refreshed_at = Some(100);
    let mut valid_shield = test_wallet_utxo_with_kind(2, UtxoCommitmentKind::Shield);
    valid_shield
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Valid);
    valid_shield.utxo.poi.refreshed_at = Some(100);
    let mut valid_transact = test_wallet_utxo_with_kind(3, UtxoCommitmentKind::Transact);
    valid_transact
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Valid);
    valid_transact.utxo.poi.refreshed_at = Some(100);
    let selection = WalletPoiRefreshSelection::CorpusRevision {
        blocked_shields_changed: true,
    };

    assert!(selection.matches_wallet_utxo(&blocked, &list_keys));
    assert!(selection.matches_wallet_utxo(&valid_shield, &list_keys));
    assert!(!selection.matches_wallet_utxo(&valid_transact, &list_keys));
    assert!(
        !WalletPoiRefreshSelection::CorpusRevision {
            blocked_shields_changed: false,
        }
        .matches_wallet_utxo(&blocked, &list_keys)
    );
}

#[tokio::test]
async fn forced_recoverable_poi_refresh_batches_missing_utxos() {
    let client = RecordingPoiStatusClient::default();
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut valid = test_wallet_utxo(0);
    valid.utxo.poi.statuses.insert(list_key, PoiStatus::Valid);
    valid.utxo.poi.refreshed_at = Some(100);
    let mut missing_one = test_wallet_utxo(1);
    missing_one
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    missing_one.utxo.poi.refreshed_at = Some(100);
    let mut missing_two = test_wallet_utxo(2);
    missing_two
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    missing_two.utxo.poi.refreshed_at = Some(100);
    let mut wallet_utxos = vec![valid, missing_one, missing_two];

    let outcome = refresh_wallet_poi_statuses_selected(
        &client,
        1,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::Recoverable,
    )
    .await;

    assert!(outcome.changed);
    assert!(outcome.complete);
    let calls = client.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1.len(), 2);
    assert!(
        wallet_utxos
            .iter()
            .all(|wallet_utxo| wallet_utxo.utxo.poi.is_valid_for_lists(&list_keys))
    );
}

#[tokio::test]
async fn required_or_recoverable_poi_refresh_skips_currently_valid_utxos() {
    let client = RecordingPoiStatusClient::default();
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut valid = test_wallet_utxo(0);
    valid.utxo.poi.statuses.insert(list_key, PoiStatus::Valid);
    valid.utxo.poi.refreshed_at = Some(100);
    let mut valid_without_refresh_time = test_wallet_utxo(1);
    valid_without_refresh_time
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Valid);
    let mut missing = test_wallet_utxo(2);
    missing
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    missing.utxo.poi.refreshed_at = Some(100);
    let mut wallet_utxos = vec![valid, valid_without_refresh_time, missing];

    let outcome = refresh_wallet_poi_statuses_selected(
        &client,
        1,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(outcome.changed);
    assert!(outcome.complete);
    let calls = client.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1.len(), 2);
    assert_eq!(wallet_utxos[0].utxo.poi.refreshed_at, Some(100));
    assert!(wallet_utxos[1].utxo.poi.refreshed_at.is_some());
    assert_eq!(
        wallet_utxos[2].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );
}

#[tokio::test]
async fn poi_status_refresh_timestamp_only_update_is_changed() {
    let client = RecordingPoiStatusClient::default();
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut valid_without_refresh_time = test_wallet_utxo(1);
    valid_without_refresh_time
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Valid);
    let mut wallet_utxos = vec![valid_without_refresh_time];

    assert!(wallet_poi_status_refresh_needed(&wallet_utxos, &list_keys));
    let outcome = refresh_wallet_poi_statuses_selected(
        &client,
        1,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(outcome.changed);
    assert!(outcome.complete);
    assert!(!wallet_poi_status_refresh_needed(&wallet_utxos, &list_keys));
    assert_eq!(client.calls().len(), 1);
    assert_eq!(
        wallet_utxos[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );
    assert!(wallet_utxos[0].utxo.poi.refreshed_at.is_some());
}

#[tokio::test]
async fn poi_status_refresh_keeps_failed_chunks_unknown() {
    let client = RecordingPoiStatusClient::default();
    client.fail_call(0);
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut wallet_utxos = (0..=WALLET_POI_STATUS_BATCH_SIZE)
        .map(|position| test_wallet_utxo(position as u64))
        .collect::<Vec<_>>();

    let outcome = refresh_wallet_poi_statuses_selected(
        &client,
        1,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(outcome.changed);
    assert!(!outcome.complete);
    assert_eq!(client.calls().len(), 2);
    assert_eq!(
        wallet_utxos[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Unknown)
    );
    assert_eq!(wallet_utxos[0].utxo.poi.refreshed_at, None);
    assert_eq!(
        wallet_utxos[WALLET_POI_STATUS_BATCH_SIZE]
            .utxo
            .poi
            .statuses
            .get(&list_key),
        Some(&PoiStatus::Valid)
    );
    assert!(
        wallet_utxos[WALLET_POI_STATUS_BATCH_SIZE]
            .utxo
            .poi
            .refreshed_at
            .is_some()
    );
}

#[tokio::test]
async fn poi_status_refresh_reports_incomplete_when_failed_read_is_unchanged() {
    let client = RecordingPoiStatusClient::default();
    client.fail_call(0);
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut wallet_utxos = vec![test_wallet_utxo(1)];
    wallet_utxos[0]
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Unknown);

    let outcome = refresh_wallet_poi_statuses_selected(
        &client,
        1,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(!outcome.changed);
    assert!(!outcome.complete);
    assert_eq!(client.calls().len(), 1);
}

#[tokio::test]
async fn private_status_gateway_revalidates_same_generation_subject() {
    let candidate = test_wallet_utxo(64);
    let blinded_commitment = candidate.utxo.poi.blinded_commitment;
    let handle = test_wallet_handle(vec![candidate]);
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let transport = Arc::new(RecordingPoiStatusClient::default());
    let private_poi =
        WalletPrivatePoiClients::for_status(authority.remote_authority(), transport.clone());
    let list_key = FixedBytes::from([0x64; 32]);
    let request_data = [BlindedCommitmentData::transact(blinded_commitment)];
    let (resolution_started_tx, resolution_started_rx) = oneshot::channel();
    let (release_resolution_tx, release_resolution_rx) = oneshot::channel();

    let statuses = async {
        resolution_started_tx
            .send(())
            .expect("signal status-source resolution wait");
        release_resolution_rx
            .await
            .expect("release status-source resolution wait");
        private_poi
            .pois_per_list(
                || async {
                    Ok::<bool, std::convert::Infallible>(authority.wallet_utxos().await.is_ok_and(
                        |utxos| {
                            utxos.iter().any(|utxo| {
                                !utxo.is_spent()
                                    && utxo.utxo.poi.blinded_commitment == blinded_commitment
                            })
                        },
                    ))
                },
                DEFAULT_TXID_VERSION,
                EVM_CHAIN_TYPE,
                1,
                &[list_key],
                &request_data,
            )
            .await
    };
    tokio::pin!(statuses);
    tokio::select! {
        result = &mut statuses => panic!("status request finished before resolution was released: {result:?}"),
        started = resolution_started_rx => started.expect("status-source resolution started"),
    }

    handle.utxos.write().await.clear();
    release_resolution_tx
        .send(())
        .expect("release status-source resolution");
    assert!(matches!(
        statuses.await,
        Err(super::super::WalletPrivateRemoteError::Stale(
            super::super::WalletPrivateRemoteStale::Subject
        ))
    ));
    assert!(
        transport.calls().is_empty(),
        "same-generation stale subject must not reach status transport"
    );
}

#[tokio::test]
async fn private_remote_gateway_cancels_in_flight_effect_on_reset() {
    let handle = test_wallet_handle(vec![test_wallet_utxo(65)]);
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let (started_tx, started_rx) = oneshot::channel();
    let (_release_tx, release_rx) = oneshot::channel();
    let transport = Arc::new(BlockingPoiStatusReader::new(started_tx, release_rx));
    let private_poi = WalletPrivatePoiClients::for_status(authority.remote_authority(), transport);
    let list_key = FixedBytes::from([0x65; 32]);
    let list_keys = [list_key];
    let request_data = [BlindedCommitmentData::transact(FixedBytes::from(
        [0x66; 32],
    ))];

    let statuses = private_poi.pois_per_list(
        || async { Ok::<bool, std::convert::Infallible>(true) },
        DEFAULT_TXID_VERSION,
        EVM_CHAIN_TYPE,
        1,
        &list_keys,
        &request_data,
    );
    tokio::pin!(statuses);
    tokio::select! {
        result = &mut statuses => panic!("private effect finished before transport blocked: {result:?}"),
        started = started_rx => started.expect("private transport started"),
    }

    assert_eq!(handle.advance_reset_generation().await, Some(1));
    let result = tokio::time::timeout(Duration::from_secs(1), statuses)
        .await
        .expect("generation invalidation must cancel private effect");
    assert!(matches!(
        result,
        Err(super::super::WalletPrivateRemoteError::Stale(
            super::super::WalletPrivateRemoteStale::Authority
        ))
    ));
}

#[tokio::test]
async fn recovery_actor_skips_when_output_becomes_valid_before_apply() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-recovery-became-valid");
    let list_key = FixedBytes::from([0x71; 32]);
    let mut wallet_utxo = test_wallet_utxo(71);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    let pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    let expected_output = ExpectedWalletOutput::new(&wallet_utxo);
    let mut handle = test_wallet_handle(vec![wallet_utxo]);
    handle.cache_key = cfg.cache_key.clone();
    handle.utxos.write().await[0]
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Valid);
    let cancel = CancellationToken::new();
    let outcome = apply_owned_poi_private_delta_on_actor(
        &handle,
        &cancel,
        0,
        &store,
        &store,
        &cfg,
        OwnedPoiPrivateDelta::OutputRecovery(OutputRecoveryDelta {
            replay_fence: None,
            expected_output,
            active_list_keys: vec![list_key],
            target_list_keys: vec![list_key],
            required_poi_status: ExpectedPoiStatus::Recoverable,
            pending_update: Box::new(Some((ExpectedRecordState::Absent, pending.clone()))),
            expected_recovery: ExpectedRecordState::Absent,
            action: OutputPoiRecoveryAction::Detected {
                status: OutputPoiRecoveryStatus::Recoverable,
                retry_after: None,
                last_error: None,
                increment_attempts: false,
            },
            now: 10,
            expected_corpus: None,
        }),
    )
    .await
    .expect("apply recovery intent");
    assert_eq!(outcome, PoiPrivateApplyOutcome::Skipped);
    assert!(
        store
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &pending.output_commitment
            )
            .expect("load context")
            .is_none(),
        "valid output must not gain a recovered pending context"
    );
    assert!(
        store
            .get_output_poi_recovery(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &pending.output_commitment
            )
            .expect("load recovery")
            .is_none(),
        "valid output must not gain recovery metadata"
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn owned_status_refresh_validation_rejects_validity_downgrade_before_apply() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-owned-valid-downgrade");
    let list_key = FixedBytes::from([0x72; 32]);
    let mut wallet_utxo = test_wallet_utxo(72);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Valid);
    let pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let expected_context_fingerprint =
        pending_output_poi_context_fingerprint(&pending).expect("pending context fingerprint");
    let expected_output = ExpectedWalletOutput::new(&wallet_utxo);
    let expected_poi_list_state = ExpectedPoiListState::new(&wallet_utxo.utxo.poi, &[list_key]);
    let mut handle = test_wallet_handle(vec![wallet_utxo]);
    handle.cache_key = cfg.cache_key.clone();
    handle.utxos.write().await[0]
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Unknown);
    let cancel = CancellationToken::new();

    let outcome = apply_owned_poi_private_delta_on_actor(
        &handle,
        &cancel,
        0,
        &store,
        &store,
        &cfg,
        OwnedPoiPrivateDelta::VerifiedValid(VerifiedValidDelta {
            subject: PendingOutputPoiSubject::Owned(expected_output),
            evidence: PendingOutputPoiValidationEvidence::OwnedStatusRefresh,
            expected_context_fingerprint,
            expected_recovery: ExpectedRecordState::Absent,
            expected_poi_list_state: Some(expected_poi_list_state),
            active_list_keys: vec![list_key],
            valid_list_keys: vec![list_key],
            now: 12,
        }),
    )
    .await
    .expect("apply stale owned-status validation");

    assert_eq!(outcome, PoiPrivateApplyOutcome::Skipped);
    assert!(
        store
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &pending.output_commitment,
            )
            .expect("load context")
            .is_some()
    );
    assert!(
        store
            .get_output_poi_recovery(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &pending.output_commitment,
            )
            .expect("load recovery")
            .is_none()
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn stale_submission_behind_verified_valid_cannot_resurrect_or_downgrade() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-verified-before-submission");
    let list_key = FixedBytes::from([0x72; 32]);
    let mut wallet_utxo = test_wallet_utxo(72);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::ProofSubmitted);
    let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let mut recovery = output_poi_recovery_record(
        cfg.chain.chain_id,
        &cfg.cache_key,
        wallet_utxo.utxo.poi.commitment,
        OutputPoiRecoveryStatus::Submitted,
        Some(20),
    );
    recovery.source_tx_hash = wallet_utxo.utxo.source.tx_hash;
    store
        .put_output_poi_recovery(&recovery)
        .expect("store recovery");
    let expected_context_fingerprint =
        pending_output_poi_context_fingerprint(&pending).expect("pending context fingerprint");
    let expected_recovery =
        super::super::expected_recovery_state(Some(&recovery)).expect("recovery fingerprint");
    let expected_output = ExpectedWalletOutput::new(&wallet_utxo);
    let expected_poi_list_state = ExpectedPoiListState::new(&wallet_utxo.utxo.poi, &[list_key]);
    let stale_submission = OwnedPoiPrivateDelta::PendingSubmission(PendingSubmissionDelta {
        subject: PendingOutputPoiSubject::Owned(expected_output.clone()),
        expected_context_fingerprint: expected_context_fingerprint.clone(),
        expected_recovery,
        active_list_keys: vec![list_key],
        list_keys: vec![list_key],
        predicate: PendingOutputPoiSubmissionPredicate::RetrySubmitted,
        merge_submitted_list_keys: false,
        action: OutputPoiRecoveryAction::SubmitFailed {
            error: "stale submission failure".to_string(),
            retry_after: Duration::from_secs(30),
        },
        now: 11,
    });
    let verified = OwnedPoiPrivateDelta::VerifiedValid(VerifiedValidDelta {
        subject: PendingOutputPoiSubject::Owned(expected_output),
        evidence: PendingOutputPoiValidationEvidence::SubmittedStatus,
        expected_context_fingerprint,
        expected_recovery: super::super::expected_recovery_state(Some(&recovery))
            .expect("recovery fingerprint"),
        expected_poi_list_state: Some(expected_poi_list_state),
        active_list_keys: vec![list_key],
        valid_list_keys: vec![list_key],
        now: 12,
    });
    let mut handle = test_wallet_handle(vec![wallet_utxo]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();

    assert!(matches!(
        apply_owned_poi_private_delta_on_actor(
            &handle, &cancel, 0, &store, &store, &cfg, verified,
        )
        .await
        .expect("apply verified intent"),
        PoiPrivateApplyOutcome::Applied { .. }
    ));
    assert_eq!(
        apply_owned_poi_private_delta_on_actor(
            &handle,
            &cancel,
            0,
            &store,
            &store,
            &cfg,
            stale_submission,
        )
        .await
        .expect("apply queued stale submission"),
        PoiPrivateApplyOutcome::Skipped
    );
    assert!(
        store
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &pending.output_commitment,
            )
            .expect("load context")
            .is_none()
    );
    assert_eq!(
        store
            .get_output_poi_recovery(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &pending.output_commitment,
            )
            .expect("load recovery")
            .expect("recovery present")
            .status,
        OutputPoiRecoveryStatus::Valid
    );
    assert_eq!(
        handle.utxos.read().await[0]
            .utxo
            .poi
            .statuses
            .get(&list_key),
        Some(&PoiStatus::Valid)
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn verified_valid_rejects_changed_context_or_shield_blocked_but_accepts_recoverable() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-stale-verified");
    let list_key = FixedBytes::from([0x73; 32]);
    let mut wallet_utxo = test_wallet_utxo(73);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::ProofSubmitted);
    let expected_output = ExpectedWalletOutput::new(&wallet_utxo);
    let expected_poi_list_state = ExpectedPoiListState::new(&wallet_utxo.utxo.poi, &[list_key]);
    let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let expected_context_fingerprint =
        pending_output_poi_context_fingerprint(&pending).expect("pending context fingerprint");
    let mut handle = test_wallet_handle(vec![wallet_utxo]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let workflow_before = WalletPpoiWorkflowStatus {
        awaiting_validation: 1,
        validation_revision: 11,
        ..WalletPpoiWorkflowStatus::default()
    };
    handle
        .observation
        .upgrade()
        .expect("observation publisher")
        .publish_ppoi_workflow_status(workflow_before);

    let stale_authority_outcome = apply_owned_poi_private_delta_on_actor(
        &handle,
        &cancel,
        1,
        &store,
        &store,
        &cfg,
        OwnedPoiPrivateDelta::VerifiedValid(VerifiedValidDelta {
            subject: PendingOutputPoiSubject::Owned(expected_output.clone()),
            evidence: PendingOutputPoiValidationEvidence::SubmittedStatus,
            expected_context_fingerprint: expected_context_fingerprint.clone(),
            expected_recovery: ExpectedRecordState::Absent,
            expected_poi_list_state: Some(expected_poi_list_state.clone()),
            active_list_keys: vec![list_key],
            valid_list_keys: vec![list_key],
            now: 19,
        }),
    )
    .await;
    assert!(matches!(
        stale_authority_outcome,
        Err(WalletCacheError::Crypto)
    ));
    assert_eq!(
        handle.observation().ppoi_workflow_status(),
        &workflow_before
    );

    let mut changed_context = pending.clone();
    changed_context.source_operation_id = Some("newer-context".to_string());
    store
        .put_pending_output_poi_context(&changed_context)
        .expect("replace context");
    let changed_context_outcome = apply_owned_poi_private_delta_on_actor(
        &handle,
        &cancel,
        0,
        &store,
        &store,
        &cfg,
        OwnedPoiPrivateDelta::VerifiedValid(VerifiedValidDelta {
            subject: PendingOutputPoiSubject::Owned(expected_output.clone()),
            evidence: PendingOutputPoiValidationEvidence::SubmittedStatus,
            expected_context_fingerprint: expected_context_fingerprint.clone(),
            expected_recovery: ExpectedRecordState::Absent,
            expected_poi_list_state: Some(expected_poi_list_state.clone()),
            active_list_keys: vec![list_key],
            valid_list_keys: vec![list_key],
            now: 20,
        }),
    )
    .await
    .expect("apply stale-context verification");
    assert_eq!(changed_context_outcome, PoiPrivateApplyOutcome::Skipped);
    assert_eq!(
        handle.observation().ppoi_workflow_status(),
        &workflow_before
    );

    store
        .put_pending_output_poi_context(&pending)
        .expect("restore context");
    handle.utxos.write().await[0]
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::ShieldBlocked);
    let shield_blocked_outcome = apply_owned_poi_private_delta_on_actor(
        &handle,
        &cancel,
        0,
        &store,
        &store,
        &cfg,
        OwnedPoiPrivateDelta::VerifiedValid(VerifiedValidDelta {
            subject: PendingOutputPoiSubject::Owned(expected_output.clone()),
            evidence: PendingOutputPoiValidationEvidence::SubmittedStatus,
            expected_context_fingerprint: expected_context_fingerprint.clone(),
            expected_recovery: ExpectedRecordState::Absent,
            expected_poi_list_state: Some(expected_poi_list_state.clone()),
            active_list_keys: vec![list_key],
            valid_list_keys: vec![list_key],
            now: 21,
        }),
    )
    .await
    .expect("apply shield-blocked verification");
    assert_eq!(shield_blocked_outcome, PoiPrivateApplyOutcome::Skipped);
    assert_eq!(
        handle.utxos.read().await[0]
            .utxo
            .poi
            .statuses
            .get(&list_key),
        Some(&PoiStatus::ShieldBlocked)
    );

    handle.utxos.write().await[0]
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Unknown);
    let recoverable_status_outcome = apply_owned_poi_private_delta_on_actor(
        &handle,
        &cancel,
        0,
        &store,
        &store,
        &cfg,
        OwnedPoiPrivateDelta::VerifiedValid(VerifiedValidDelta {
            subject: PendingOutputPoiSubject::Owned(expected_output),
            evidence: PendingOutputPoiValidationEvidence::SubmittedStatus,
            expected_context_fingerprint,
            expected_recovery: ExpectedRecordState::Absent,
            expected_poi_list_state: Some(expected_poi_list_state),
            active_list_keys: vec![list_key],
            valid_list_keys: vec![list_key],
            now: 22,
        }),
    )
    .await
    .expect("apply recoverable-status verification");
    assert!(matches!(
        recoverable_status_outcome,
        PoiPrivateApplyOutcome::Applied { .. }
    ));
    assert!(
        store
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &pending.output_commitment,
            )
            .expect("load context")
            .is_none()
    );
    assert_eq!(
        handle.utxos.read().await[0]
            .utxo
            .poi
            .statuses
            .get(&list_key),
        Some(&PoiStatus::Valid)
    );
    assert_eq!(
        handle.observation().ppoi_workflow_status(),
        &WalletPpoiWorkflowStatus {
            validation_revision: 12,
            ..WalletPpoiWorkflowStatus::default()
        }
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

fn poi_leaf_response(leaves: &[U256]) -> serde_json::Value {
    serde_json::to_value(
        leaves
            .iter()
            .map(|leaf| format!("0x{leaf:064x}"))
            .collect::<Vec<_>>(),
    )
    .expect("leaves JSON")
}

fn local_status_reader_for_lists(
    blinded_commitment: FixedBytes<32>,
    list_keys: &[FixedBytes<32>],
    valid_list_keys: &[FixedBytes<32>],
) -> LocalPoiStatusReader {
    let caches = list_keys
        .iter()
        .copied()
        .map(|list_key| {
            let mut cache = PoiCache::new(PoiCacheIdentity::new(
                EVM_CHAIN_TYPE,
                1,
                DEFAULT_TXID_VERSION,
                list_key,
            ));
            if valid_list_keys.contains(&list_key) {
                cache
                    .apply_poi_leaves(0, &[U256::from_be_bytes(blinded_commitment.0)])
                    .expect("apply local POI leaf");
            }
            (list_key, cache)
        })
        .collect();
    LocalPoiStatusReader::new(WalletLocalPoiCaches::new_for_test(caches))
}
