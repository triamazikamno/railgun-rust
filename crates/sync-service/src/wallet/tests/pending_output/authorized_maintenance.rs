use super::*;

#[tokio::test]
async fn authorized_pending_output_poi_skips_output_that_no_longer_needs_poi() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let list_key = FixedBytes::from([0x96; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-1");
    let mut wallet_utxo = test_wallet_utxo(16);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Valid);
    let pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let mut handle = test_wallet_handle(vec![wallet_utxo]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let submitter = Arc::new(RecordingPendingOutputPoiSubmitter::default());
    let private_poi =
        WalletPrivatePoiClients::for_submit(authority.remote_authority(), submitter.clone());

    let submitted = process_pending_output_poi_observations_authorized(
        &authority,
        &test_public_data_plane_with_poi_service(&store),
        store.as_ref(),
        store.as_ref(),
        &cfg,
        &[list_key],
        Some(&private_poi),
        false,
    )
    .await;

    assert_eq!(submitted, 0);
    assert_eq!(submitter.calls(), [] as [(FixedBytes<32>, u64, u64); 0]);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn pending_output_poi_maintenance_is_scoped_to_wallet_id() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let chain_id = 1;
    let list_key = FixedBytes::from([0xa1; 32]);
    let wallet_a_commitment = FixedBytes::from([0xa2; 32]);
    let wallet_b_commitment = FixedBytes::from([0xa3; 32]);
    let wallet_a_id = test_cache_key("wallet-a");
    let wallet_b_id = test_cache_key("wallet-b");
    let mut wallet_a = pending_output_record(chain_id, wallet_a_commitment, list_key);
    wallet_a.wallet_id = wallet_a_id.to_string();
    wallet_a.observation = Some(local_db::PendingOutputPoiObservation {
        output_tree: 3,
        output_position: 12,
        tx_hash: source(12).tx_hash,
        block_number: 12,
        block_timestamp: 1_700_000_012,
    });
    let mut wallet_b = pending_output_record(chain_id, wallet_b_commitment, list_key);
    wallet_b.wallet_id = wallet_b_id.to_string();
    wallet_b.observation = Some(local_db::PendingOutputPoiObservation {
        output_tree: 4,
        output_position: 13,
        tx_hash: source(13).tx_hash,
        block_number: 13,
        block_timestamp: 1_700_000_013,
    });
    store
        .put_pending_output_poi_context(&wallet_a)
        .expect("store wallet A pending context");
    store
        .put_pending_output_poi_context(&wallet_b)
        .expect("store wallet B pending context");
    let submitter = RecordingPendingOutputPoiSubmitter::default();

    process_pending_output_poi_observations(
        &store,
        chain_id,
        wallet_a_id.as_str(),
        &[],
        Some(&submitter),
    )
    .await;

    assert_eq!(submitter.calls(), vec![(wallet_a_commitment, 3, 12)]);
    let wallet_a = store
        .get_pending_output_poi_context(chain_id, wallet_a_id.as_str(), &wallet_a_commitment)
        .expect("load wallet A pending context")
        .expect("wallet A pending context present");
    assert_eq!(wallet_a.submitted_poi_list_keys, vec![list_key]);
    let mut wallet_b = store
        .get_pending_output_poi_context(chain_id, wallet_b_id.as_str(), &wallet_b_commitment)
        .expect("load wallet B pending context")
        .expect("wallet B pending context present");
    assert_eq!(wallet_b.submitted_poi_list_keys, [] as [FixedBytes<32>; 0]);

    wallet_b.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&wallet_b)
        .expect("mark wallet B submitted");
    let wallet_a_identity = pending_output_poi_submit_identity(
        &wallet_a,
        wallet_a.observation.as_ref().expect("wallet A observation"),
    )
    .expect("wallet A identity");
    let wallet_b_identity = pending_output_poi_submit_identity(
        &wallet_b,
        wallet_b.observation.as_ref().expect("wallet B observation"),
    )
    .expect("wallet B identity");
    assert_ne!(
        wallet_a_identity.derived_blinded_commitment,
        wallet_b_identity.derived_blinded_commitment
    );
    let client = RecordingPoiStatusClient::default();

    let outcome = verify_submitted_pending_output_pois(
        &client,
        &store,
        chain_id,
        wallet_a_id.as_str(),
        &[list_key],
    )
    .await;

    assert_eq!(outcome.completed, 1);
    assert_eq!(outcome.pending, 0);
    assert!(
        store
            .get_pending_output_poi_context(chain_id, wallet_a_id.as_str(), &wallet_a_commitment)
            .expect("load wallet A pending context")
            .is_none()
    );
    assert!(
        store
            .get_pending_output_poi_context(chain_id, wallet_b_id.as_str(), &wallet_b_commitment)
            .expect("load wallet B pending context")
            .is_some()
    );
    let calls = client.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, vec![list_key]);
    assert_eq!(
        calls[0].1[0].blinded_commitment,
        wallet_a_identity.derived_blinded_commitment
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn submitted_pending_output_poi_verification_allows_retry_after_missing_delay() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x92; 32]);
    let list_key = FixedBytes::from([0x93; 32]);
    let mut pending = pending_output_record(chain_id, output_commitment, list_key);
    pending.observation = Some(local_db::PendingOutputPoiObservation {
        output_tree: 3,
        output_position: 13,
        tx_hash: source(13).tx_hash,
        block_number: 13,
        block_timestamp: 1_700_000_013,
    });
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let client = RecordingPoiStatusClient::default();
    client.set_default_status(PoiStatus::Missing);

    let outcome = verify_submitted_pending_output_pois(
        &client,
        &store,
        chain_id,
        test_cache_key("wallet-1").as_str(),
        &[list_key],
    )
    .await;

    assert_eq!(outcome.completed, 0);
    assert_eq!(outcome.pending, 1);
    let mut recovery = store
        .get_output_poi_recovery(chain_id, &pending.wallet_id, &output_commitment)
        .expect("load recovery")
        .expect("recovery present");
    assert_eq!(recovery.status, OutputPoiRecoveryStatus::Submitted);
    assert!(recovery.next_retry_at.is_some());
    recovery.next_retry_at = Some(0);
    store
        .put_output_poi_recovery(&recovery)
        .expect("force retry due");
    let submitter = RecordingPendingOutputPoiSubmitter::default();

    process_pending_output_poi_observations_inner(
        &store,
        chain_id,
        test_cache_key("wallet-1").as_str(),
        &[],
        Some(&submitter),
        false,
    )
    .await;

    assert_eq!(submitter.calls(), vec![(output_commitment, 3, 13)]);
    let updated = store
        .get_output_poi_recovery(chain_id, &pending.wallet_id, &output_commitment)
        .expect("load updated recovery")
        .expect("recovery present");
    assert!(updated.next_retry_at.is_some_and(|next| next > 0));

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn indexed_artifacts_pending_verification_uses_local_cache_without_remote_status() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let public_data_plane = test_public_data_plane_with_poi_service(&store);
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x94; 32]);
    let list_key = FixedBytes::from([0x95; 32]);
    let mut pending = pending_output_record(chain_id, output_commitment, list_key);
    let cache_key = test_cache_key("test");
    pending.wallet_id = cache_key.to_string();
    pending.observation = Some(local_db::PendingOutputPoiObservation {
        output_tree: 3,
        output_position: 14,
        tx_hash: source(14).tx_hash,
        block_number: 14,
        block_timestamp: 1_700_000_014,
    });
    pending.submitted_poi_list_keys = vec![list_key];
    let derived_blinded_commitment = pending_output_poi_submit_identity(
        &pending,
        pending.observation.as_ref().expect("observation"),
    )
    .expect("identity")
    .derived_blinded_commitment;
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let mut cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        chain_id,
        DEFAULT_TXID_VERSION,
        list_key,
    ));
    cache
        .apply_poi_leaves(0, &[U256::from_be_bytes(derived_blinded_commitment.0)])
        .expect("apply local POI leaf");
    let cfg = wallet_config(U256::ZERO);
    seed_data_plane_poi_cache(&public_data_plane, chain_id, list_key, cache).await;
    let mock = spawn_poi_rpc(serde_json::json!({})).await;
    let remote_client = PoiRpcClient::new(mock.url.clone());
    let poi_runtime = test_artifact_poi_runtime();

    let outcome = verify_submitted_pending_output_pois_with_config(
        &public_data_plane,
        &poi_runtime,
        &remote_client,
        &cfg,
        store.as_ref(),
        &[list_key],
    )
    .await;

    assert_eq!(outcome.completed, 1);
    assert!(
        store
            .get_pending_output_poi_context(chain_id, cache_key.as_str(), &output_commitment)
            .expect("load pending")
            .is_none()
    );
    assert!(
        mock.requests
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "remote ppoi_pois_per_list should not be called"
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn pending_output_poi_submission_failure_remains_retryable() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x78; 32]);
    let list_key = FixedBytes::from([0x45; 32]);
    store
        .put_pending_output_poi_context(&pending_output_record(
            chain_id,
            output_commitment,
            list_key,
        ))
        .expect("store pending context");
    let submitter = RecordingPendingOutputPoiSubmitter::default();
    submitter.fail_next();
    let observation = CommitmentObservation {
        tree: 13,
        position: 35,
        commitment: U256::from_be_bytes(output_commitment.0),
        source: source(9),
    };

    process_pending_output_poi_observations(
        &store,
        chain_id,
        test_cache_key("wallet-1").as_str(),
        &[observation],
        Some(&submitter),
    )
    .await;
    let failed = store
        .get_pending_output_poi_context(
            chain_id,
            test_cache_key("wallet-1").as_str(),
            &output_commitment,
        )
        .expect("load pending context")
        .expect("pending context present");
    assert!(failed.observation.is_some());
    assert_eq!(failed.submitted_poi_list_keys, [] as [FixedBytes<32>; 0]);
    assert!(failed.terminal_error.is_none());

    process_pending_output_poi_observations(
        &store,
        chain_id,
        test_cache_key("wallet-1").as_str(),
        &[],
        Some(&submitter),
    )
    .await;

    let retried = store
        .get_pending_output_poi_context(
            chain_id,
            test_cache_key("wallet-1").as_str(),
            &output_commitment,
        )
        .expect("load retried pending context")
        .expect("pending context present");
    assert_eq!(retried.submitted_poi_list_keys, vec![list_key]);
    assert_eq!(submitter.calls().len(), 2);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn authorized_pending_output_submission_cancels_without_mutating_context() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let chain_id = 1;
    let list_key = FixedBytes::from([0xb2; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-1");
    let wallet_utxo = test_wallet_utxo(8);
    let output_commitment = wallet_utxo.utxo.poi.commitment;
    let pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let mut handle = test_wallet_handle(vec![wallet_utxo]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let submitter = Arc::new(BlockingPendingOutputPoiSubmitter::new(
        started_tx, release_rx,
    ));
    let task_store = Arc::clone(&store);
    let task_handle = handle.clone();
    let task_cancel = cancel.clone();
    let task_submitter = Arc::clone(&submitter);
    let task_cfg = cfg.clone();
    let task = tokio::spawn(async move {
        let authority = WalletPrivateMutationAuthority::new(&task_handle, 0, &task_cancel);
        let private_poi =
            WalletPrivatePoiClients::for_submit(authority.remote_authority(), task_submitter);
        process_pending_output_poi_observations_authorized(
            &authority,
            &test_public_data_plane_with_poi_service(&task_store),
            task_store.as_ref(),
            task_store.as_ref(),
            &task_cfg,
            &[list_key],
            Some(&private_poi),
            false,
        )
        .await
    });

    tokio::time::timeout(Duration::from_secs(2), started_rx)
        .await
        .expect("submission started")
        .expect("submission start signal");
    cancel.cancel();
    release_tx.send(()).expect("release submitter");

    assert_eq!(task.await.expect("submission task"), 0);
    assert_eq!(submitter.calls(), [] as [(FixedBytes<32>, u64, u64); 0]);
    let loaded = store
        .get_pending_output_poi_context(
            chain_id,
            test_cache_key("wallet-1").as_str(),
            &output_commitment,
        )
        .expect("load pending context")
        .expect("pending context present");
    assert_eq!(loaded.submitted_poi_list_keys, [] as [FixedBytes<32>; 0]);
    assert!(
        store
            .get_output_poi_recovery(
                chain_id,
                test_cache_key("wallet-1").as_str(),
                &output_commitment,
            )
            .expect("load recovery")
            .is_none()
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn authorized_pending_output_verification_skips_changed_context_after_await() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0xb3; 32]);
    let list_key = FixedBytes::from([0xb4; 32]);
    let mut pending = pending_output_record(chain_id, output_commitment, list_key);
    pending.observation = Some(local_db::PendingOutputPoiObservation {
        output_tree: 9,
        output_position: 10,
        tx_hash: source(10).tx_hash,
        block_number: 10,
        block_timestamp: 1_700_000_010,
    });
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-1");
    let mut handle = test_wallet_handle(Vec::new());
    handle.cache_key = cfg.cache_key.clone();
    let workflow_before = WalletPpoiWorkflowStatus {
        awaiting_validation: 1,
        validation_revision: 6,
        ..WalletPpoiWorkflowStatus::default()
    };
    handle
        .observation
        .upgrade()
        .expect("observation publisher")
        .publish_ppoi_workflow_status(workflow_before);
    let cancel = CancellationToken::new();
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let reader = Arc::new(BlockingPoiStatusReader::new(started_tx, release_rx));
    let task_store = Arc::clone(&store);
    let task_handle = handle.clone();
    let task_cancel = cancel.clone();
    let task_reader = Arc::clone(&reader);
    let task_cfg = cfg.clone();
    let task = tokio::spawn(async move {
        let authority = WalletPrivateMutationAuthority::new(&task_handle, 0, &task_cancel);
        verify_submitted_pending_output_pois_authorized_with_projection(
            &authority,
            task_reader.as_ref(),
            task_store.as_ref(),
            &task_cfg,
            task_store.as_ref(),
            &[list_key],
        )
        .await
    });

    tokio::time::timeout(Duration::from_secs(2), started_rx)
        .await
        .expect("verification started")
        .expect("verification start signal");
    let mut changed = pending.clone();
    changed.terminal_error = Some("changed while status read was pending".to_string());
    store
        .put_pending_output_poi_context(&changed)
        .expect("change pending context");
    release_tx.send(()).expect("release status reader");

    let outcome = task.await.expect("verification task");
    assert_eq!(outcome.completed, 0);
    assert_eq!(outcome.pending, 0);
    assert_eq!(outcome.errors, 0);
    let loaded = store
        .get_pending_output_poi_context(
            chain_id,
            test_cache_key("wallet-1").as_str(),
            &output_commitment,
        )
        .expect("load pending context")
        .expect("pending context still present");
    assert_eq!(loaded.terminal_error, changed.terminal_error);
    assert_eq!(
        handle.observation().ppoi_workflow_status(),
        &workflow_before
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn recovered_output_poi_context_resubmits_after_retry_time() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x79; 32]);
    let list_key = FixedBytes::from([0x47; 32]);
    let mut pending = pending_output_record(chain_id, output_commitment, list_key);
    pending.observation = Some(local_db::PendingOutputPoiObservation {
        output_tree: 14,
        output_position: 36,
        tx_hash: source(11).tx_hash,
        block_number: 11,
        block_timestamp: 1_700_000_011,
    });
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    store
        .put_output_poi_recovery(&output_poi_recovery_record(
            chain_id,
            &pending.wallet_id,
            output_commitment,
            OutputPoiRecoveryStatus::Submitted,
            Some(0),
        ))
        .expect("store recovery state");
    let submitter = RecordingPendingOutputPoiSubmitter::default();

    process_pending_output_poi_observations(
        &store,
        chain_id,
        test_cache_key("wallet-1").as_str(),
        &[],
        Some(&submitter),
    )
    .await;

    let loaded = store
        .get_output_poi_recovery(chain_id, &pending.wallet_id, &output_commitment)
        .expect("load recovery state")
        .expect("recovery state present");
    assert_eq!(loaded.status, OutputPoiRecoveryStatus::Submitted);
    assert!(loaded.last_submission_at.is_some());
    assert!(loaded.next_retry_at.is_some_and(|next| next > 0));
    assert_eq!(submitter.calls(), vec![(output_commitment, 14, 36)]);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn recovered_output_poi_context_resubmits_when_forced_before_retry_time() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x7a; 32]);
    let list_key = FixedBytes::from([0x48; 32]);
    let mut pending = pending_output_record(chain_id, output_commitment, list_key);
    pending.observation = Some(local_db::PendingOutputPoiObservation {
        output_tree: 15,
        output_position: 37,
        tx_hash: source(12).tx_hash,
        block_number: 12,
        block_timestamp: 1_700_000_012,
    });
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    store
        .put_output_poi_recovery(&output_poi_recovery_record(
            chain_id,
            &pending.wallet_id,
            output_commitment,
            OutputPoiRecoveryStatus::Submitted,
            Some(u64::MAX),
        ))
        .expect("store recovery state");
    let submitter = RecordingPendingOutputPoiSubmitter::default();

    process_pending_output_poi_observations(
        &store,
        chain_id,
        test_cache_key("wallet-1").as_str(),
        &[],
        Some(&submitter),
    )
    .await;
    assert_eq!(submitter.calls(), [] as [(FixedBytes<32>, u64, u64); 0]);

    process_pending_output_poi_observations_inner(
        &store,
        chain_id,
        test_cache_key("wallet-1").as_str(),
        &[],
        Some(&submitter),
        true,
    )
    .await;

    assert_eq!(submitter.calls(), vec![(output_commitment, 15, 37)]);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
