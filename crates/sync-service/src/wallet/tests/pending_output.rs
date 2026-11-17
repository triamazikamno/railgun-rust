use super::*;

#[tokio::test]
async fn pending_output_poi_matches_undecryptable_observation_and_marks_submitted() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x77; 32]);
    let list_key = FixedBytes::from([0x44; 32]);
    store
        .put_pending_output_poi_context(&pending_output_record(
            chain_id,
            output_commitment,
            list_key,
        ))
        .expect("store pending context");
    let submitter = RecordingPendingOutputPoiSubmitter::default();
    let observation = CommitmentObservation {
        tree: 12,
        position: 34,
        commitment: U256::from_be_bytes(output_commitment.0),
        source: source(8),
    };

    process_pending_output_poi_observations(
        &store,
        chain_id,
        test_cache_key("wallet-1").as_str(),
        &[observation],
        Some(&submitter),
    )
    .await;

    let loaded = store
        .get_pending_output_poi_context(
            chain_id,
            test_cache_key("wallet-1").as_str(),
            &output_commitment,
        )
        .expect("load pending context")
        .expect("pending context present");
    let observed = loaded.observation.expect("observation recorded");
    assert_eq!(observed.output_tree, 12);
    assert_eq!(observed.output_position, 34);
    assert_eq!(observed.tx_hash, source(8).tx_hash);
    assert_eq!(loaded.submitted_poi_list_keys, vec![list_key]);
    assert_eq!(submitter.calls(), vec![(output_commitment, 12, 34)]);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn pending_tip_tentative_submission_is_non_durable_and_safe_head_remains_eligible() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cfg = wallet_config(U256::ZERO);
    let output_commitment = FixedBytes::from([0x78; 32]);
    let list_key = FixedBytes::from([0x45; 32]);
    let observed_source = source(8);
    let mut record = pending_output_record(cfg.chain.chain_id, output_commitment, list_key);
    record.wallet_id = cfg.cache_key.to_string();
    assert!(record.observation.is_none());
    store
        .put_pending_output_poi_context(&record)
        .expect("store pending context");

    let mut handle = test_wallet_handle(Vec::new());
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let observation = CommitmentObservation {
        tree: 12,
        position: 34,
        commitment: U256::from_be_bytes(output_commitment.0),
        source: observed_source,
    };
    let candidates = prepare_pending_output_poi_tentative_candidates(
        store.as_ref(),
        &cfg,
        &[list_key],
        std::slice::from_ref(&observation),
    )
    .expect("prepare tentative candidate");
    assert_eq!(
        candidates.len(),
        1,
        "matching observation must be a candidate"
    );
    let candidate_key = candidates[0].attempt_key();

    let nonmatching = CommitmentObservation {
        commitment: U256::from_be_bytes([0x79; 32]),
        ..observation.clone()
    };
    assert!(
        prepare_pending_output_poi_tentative_candidates(
            store.as_ref(),
            &cfg,
            &[list_key],
            std::slice::from_ref(&nonmatching),
        )
        .expect("prepare nonmatching candidate")
        .is_empty()
    );

    let submitter = Arc::new(RecordingPendingOutputPoiSubmitter::default());
    let private_poi =
        WalletPrivatePoiClients::for_submit(authority.remote_authority(), submitter.clone());
    submitter.fail_next_missing_railgun_txid();
    let failed = submit_pending_output_poi_tentative_candidates(
        &authority,
        store.as_ref(),
        &cfg,
        &[list_key],
        &candidates,
        &private_poi,
    )
    .await;
    assert_eq!(
        failed.succeeded,
        [] as [super::super::pending_output_poi::PendingOutputPoiTentativeAttemptKey; 0]
    );
    assert_eq!(failed.retryable, vec![candidate_key.clone()]);
    assert_eq!(failed.accepted, 0);
    assert_eq!(failed.missing_txid, 1);
    assert_eq!(failed.remote_failure, 0);
    assert_eq!(failed.context_stale, 0);
    assert!(!failed.authority_stale);
    let after_tentative = store
        .get_pending_output_poi_context(cfg.chain.chain_id, &cfg.cache_key, &output_commitment)
        .expect("load context after tentative submission")
        .expect("context after tentative submission");
    assert!(after_tentative.observation.is_none());
    assert_eq!(
        after_tentative.submitted_poi_list_keys,
        [] as [FixedBytes<32>; 0]
    );
    assert!(after_tentative.terminal_error.is_none());
    assert!(
        store
            .get_output_poi_recovery(cfg.chain.chain_id, &cfg.cache_key, &output_commitment)
            .expect("load recovery after tentative submission")
            .is_none()
    );

    submitter.fail_next_other_remote_error();
    let remote_failed = submit_pending_output_poi_tentative_candidates(
        &authority,
        store.as_ref(),
        &cfg,
        &[list_key],
        &candidates,
        &private_poi,
    )
    .await;
    assert_eq!(
        remote_failed.succeeded,
        [] as [super::super::pending_output_poi::PendingOutputPoiTentativeAttemptKey; 0]
    );
    assert_eq!(remote_failed.retryable, vec![candidate_key.clone()]);
    assert_eq!(remote_failed.accepted, 0);
    assert_eq!(remote_failed.missing_txid, 0);
    assert_eq!(remote_failed.remote_failure, 1);
    assert_eq!(remote_failed.context_stale, 0);
    assert!(!remote_failed.authority_stale);

    let succeeded = submit_pending_output_poi_tentative_candidates(
        &authority,
        store.as_ref(),
        &cfg,
        &[list_key],
        &candidates,
        &private_poi,
    )
    .await;
    assert_eq!(succeeded.succeeded, vec![candidate_key.clone()]);
    assert_eq!(
        succeeded.retryable,
        [] as [super::super::pending_output_poi::PendingOutputPoiTentativeAttemptKey; 0]
    );
    assert_eq!(succeeded.accepted, 1);
    assert_eq!(succeeded.missing_txid, 0);
    assert_eq!(succeeded.remote_failure, 0);
    assert_eq!(succeeded.context_stale, 0);
    assert!(!succeeded.authority_stale);
    let after_success = store
        .get_pending_output_poi_context(cfg.chain.chain_id, &cfg.cache_key, &output_commitment)
        .expect("load context after tentative success")
        .expect("context after tentative success");
    assert!(after_success.observation.is_none());
    assert_eq!(
        after_success.submitted_poi_list_keys,
        [] as [FixedBytes<32>; 0]
    );
    assert!(after_success.terminal_error.is_none());
    assert!(
        store
            .get_output_poi_recovery(cfg.chain.chain_id, &cfg.cache_key, &output_commitment)
            .expect("load recovery after tentative failure")
            .is_none()
    );

    let changed_observation = CommitmentObservation {
        position: 35,
        ..observation.clone()
    };
    let changed_candidates = prepare_pending_output_poi_tentative_candidates(
        store.as_ref(),
        &cfg,
        &[list_key],
        std::slice::from_ref(&changed_observation),
    )
    .expect("prepare changed candidate");
    assert_eq!(changed_candidates.len(), 1);
    assert_ne!(candidate_key, changed_candidates[0].attempt_key());

    let updates = pending_output_poi_observation_state_updates(
        store.as_ref(),
        cfg.chain.chain_id,
        &cfg.cache_key,
        std::slice::from_ref(&observation),
    )
    .expect("prepare safe-head observation");
    for output_commitment in updates.recovery_deletes {
        store
            .delete_output_poi_recovery(cfg.chain.chain_id, &cfg.cache_key, &output_commitment)
            .expect("delete safe-head recovery");
    }
    for record in updates.context_updates {
        store
            .put_pending_output_poi_context(&record)
            .expect("persist safe-head observation");
    }

    let submitted = submit_observed_pending_output_pois_inner(
        &authority,
        &test_public_data_plane_with_poi_service(&store),
        store.as_ref(),
        store.as_ref(),
        &cfg,
        &[list_key],
        &private_poi,
        false,
    )
    .await
    .expect("safe-head submission");
    assert_eq!(submitted, 1, "safe-head path must remain eligible");
    assert_eq!(
        store
            .get_pending_output_poi_context(cfg.chain.chain_id, &cfg.cache_key, &output_commitment)
            .expect("load safe-head context")
            .expect("safe-head context")
            .submitted_poi_list_keys,
        vec![list_key]
    );

    cancel.cancel();
    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn recovered_pending_output_poi_uses_transact_proof_submission() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x79; 32]);
    let list_key = FixedBytes::from([0x47; 32]);
    let mut record = pending_output_record(chain_id, output_commitment, list_key);
    record.txid_merkleroot_index = Some(105_572);
    let expected_blinded_commitment = record
        .pre_transaction_pois_per_txid_leaf_per_list
        .get(&list_key)
        .expect("list")
        .values()
        .next()
        .expect("poi")
        .blinded_commitments_out[0];
    store
        .put_pending_output_poi_context(&record)
        .expect("store pending context");
    let submitter = RecordingPendingOutputPoiSubmitter::default();
    let observation = CommitmentObservation {
        tree: 12,
        position: 34,
        commitment: U256::from_be_bytes(output_commitment.0),
        source: source(8),
    };

    process_pending_output_poi_observations(
        &store,
        chain_id,
        test_cache_key("wallet-1").as_str(),
        &[observation],
        Some(&submitter),
    )
    .await;

    let loaded = store
        .get_pending_output_poi_context(
            chain_id,
            test_cache_key("wallet-1").as_str(),
            &output_commitment,
        )
        .expect("load pending context")
        .expect("pending context present");
    assert_eq!(loaded.submitted_poi_list_keys, vec![list_key]);
    assert_eq!(
        submitter.calls(),
        vec![(expected_blinded_commitment, 105_572, 0)]
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn pending_output_poi_matches_wallet_owned_observation_and_keeps_utxo() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let chain_id = 1;
    let utxo = test_wallet_utxo(36).utxo;
    let output_commitment = FixedBytes::from(utxo.note.commitment().to_be_bytes::<32>());
    let list_key = FixedBytes::from([0x46; 32]);
    store
        .put_pending_output_poi_context(&pending_output_record(
            chain_id,
            output_commitment,
            list_key,
        ))
        .expect("store pending context");
    let submitter = RecordingPendingOutputPoiSubmitter::default();
    let observation = CommitmentObservation {
        tree: utxo.tree,
        position: utxo.position,
        commitment: utxo.note.commitment(),
        source: source(10),
    };
    let delta = WalletLogDelta {
        utxos: vec![utxo],
        nullifiers: Vec::new(),
        commitment_observations: vec![observation],
        sender_scan_outputs: Vec::new(),
    };

    process_pending_output_poi_observations(
        &store,
        chain_id,
        test_cache_key("wallet-1").as_str(),
        &delta.commitment_observations,
        Some(&submitter),
    )
    .await;
    let mut wallet_utxos = Vec::new();
    let changed = apply_wallet_delta_to_vec(&wallet_config(U256::ZERO), &mut wallet_utxos, delta);

    assert!(changed);
    assert_eq!(wallet_utxos.len(), 1);
    assert_eq!(wallet_utxos[0].utxo.position, 36);
    let loaded = store
        .get_pending_output_poi_context(
            chain_id,
            test_cache_key("wallet-1").as_str(),
            &output_commitment,
        )
        .expect("load pending context")
        .expect("pending context present");
    assert!(loaded.observation.is_some());
    assert_eq!(loaded.submitted_poi_list_keys, vec![list_key]);
    assert_eq!(submitter.calls(), vec![(output_commitment, 2, 36)]);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn submitted_pending_output_poi_verification_deletes_valid_context() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x90; 32]);
    let list_key = FixedBytes::from([0x91; 32]);
    let mut pending = pending_output_record(chain_id, output_commitment, list_key);
    pending.observation = Some(local_db::PendingOutputPoiObservation {
        output_tree: 3,
        output_position: 12,
        tx_hash: source(12).tx_hash,
        block_number: 12,
        block_timestamp: 1_700_000_012,
    });
    pending.submitted_poi_list_keys = vec![list_key];
    pending = previous_key_pending_context(&pending);
    let derived_blinded_commitment = pending_output_poi_submit_identity(
        &pending,
        pending.observation.as_ref().expect("observation"),
    )
    .expect("identity")
    .derived_blinded_commitment;
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let client = RecordingPoiStatusClient::default();

    let outcome = verify_submitted_pending_output_pois(
        &client,
        &store,
        chain_id,
        test_cache_key("wallet-1").as_str(),
        &[list_key],
    )
    .await;

    assert_eq!(outcome.completed, 1);
    assert_eq!(outcome.pending, 0);
    assert!(
        store
            .get_pending_output_poi_context(
                chain_id,
                test_cache_key("wallet-1").as_str(),
                &output_commitment,
            )
            .expect("load pending")
            .is_none()
    );
    let calls = client.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, vec![list_key]);
    assert_eq!(calls[0].1[0].blinded_commitment, derived_blinded_commitment);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn proxy_refresh_reconciles_owned_valid_context_after_submission_persistence_failure() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = RecordingCacheStore::new(Arc::clone(&store));
    let chain_id = 1;
    let list_key = FixedBytes::from([0x94; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-1");
    let mut wallet_utxo = test_wallet_utxo(14);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    let output_commitment = wallet_utxo.utxo.poi.commitment;
    let source_tx_hash = wallet_utxo.utxo.source.tx_hash;
    let pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let mut handle = test_wallet_handle(vec![wallet_utxo]);
    handle.cache_key = cfg.cache_key.clone();
    handle
        .observation
        .upgrade()
        .expect("observation publisher")
        .publish_ppoi_workflow_status(WalletPpoiWorkflowStatus {
            awaiting_submission: 1,
            ..WalletPpoiWorkflowStatus::default()
        });
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let submitter = Arc::new(RecordingPendingOutputPoiSubmitter::default());
    let submit_poi =
        WalletPrivatePoiClients::for_submit(authority.remote_authority(), submitter.clone());
    cache_store.fail_next_commit();

    assert_eq!(
        process_pending_output_poi_observations_authorized(
            &authority,
            &test_public_data_plane_with_poi_service(&store),
            store.as_ref(),
            &cache_store,
            &cfg,
            &[list_key],
            Some(&submit_poi),
            false,
        )
        .await,
        0
    );
    assert_eq!(submitter.calls().len(), 1);
    assert_eq!(
        store
            .get_pending_output_poi_context(chain_id, &cfg.cache_key, &output_commitment)
            .expect("load pending context")
            .expect("pending context preserved")
            .submitted_poi_list_keys,
        [] as [FixedBytes<32>; 0]
    );
    assert!(
        store
            .get_output_poi_recovery(chain_id, &cfg.cache_key, &output_commitment)
            .expect("load recovery")
            .is_none()
    );
    assert_eq!(
        handle.observation().ppoi_workflow_status(),
        &WalletPpoiWorkflowStatus {
            awaiting_submission: 1,
            ..WalletPpoiWorkflowStatus::default()
        }
    );

    let transport = Arc::new(RecordingPoiStatusClient::default());
    let private_poi =
        WalletPrivatePoiClients::for_status(authority.remote_authority(), transport.clone());
    let poi_runtime = WalletPoiRuntime::from_policy(
        &GlobalPoiPolicy::PoiProxy {
            rpc_url: Url::parse("http://127.0.0.1:1")
                .expect("POI RPC URL")
                .into(),
        },
        None,
    );
    let public_data_plane =
        ChainPublicDataPlane::new(Arc::clone(&store), Arc::new(AtomicU64::new(0)));
    let revision_before = *handle.rev_rx.borrow();

    assert!(
        refresh_wallet_poi_statuses_remote_authorized(
            &authority,
            &private_poi,
            store.as_ref(),
            &cache_store,
            &cfg,
            &[list_key],
            WalletPoiRefreshSelection::RequiredOrRecoverable,
        )
        .await
    );
    assert_eq!(
        handle.utxos.read().await[0]
            .utxo
            .poi
            .statuses
            .get(&list_key),
        Some(&PoiStatus::Valid),
        "maintenance refresh must project Valid before verification"
    );
    assert_eq!(
        handle.observation().ppoi_workflow_status(),
        &WalletPpoiWorkflowStatus {
            awaiting_submission: 1,
            ..WalletPpoiWorkflowStatus::default()
        }
    );
    let outcome = verify_submitted_pending_output_pois_with_config_authorized(
        &authority,
        &public_data_plane,
        &poi_runtime,
        &private_poi,
        &cfg,
        store.as_ref(),
        &cache_store,
        &[list_key],
    )
    .await;

    assert_eq!(outcome.completed, 1);
    assert_eq!(outcome.pending, 0);
    assert_eq!(outcome.errors, 0);
    assert!(
        store
            .get_pending_output_poi_context(chain_id, &cfg.cache_key, &output_commitment)
            .expect("load pending")
            .is_none()
    );
    let recovery = store
        .get_output_poi_recovery(chain_id, &cfg.cache_key, &output_commitment)
        .expect("load recovery")
        .expect("recovery present");
    assert_eq!(recovery.status, OutputPoiRecoveryStatus::Valid);
    assert_eq!(recovery.source_tx_hash, source_tx_hash);
    let snapshot = handle.utxos.read().await;
    assert_eq!(
        snapshot[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );
    drop(snapshot);
    let persisted =
        <DbStore as WalletCacheStore>::load_wallet_utxos(store.as_ref(), &cfg.cache_key)
            .expect("load persisted wallet utxos");
    assert_eq!(
        persisted[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );
    assert_ne!(*handle.rev_rx.borrow(), revision_before);
    assert_eq!(transport.calls().len(), 1);
    assert_eq!(
        handle.observation().ppoi_workflow_status(),
        &WalletPpoiWorkflowStatus {
            validation_revision: 1,
            ..WalletPpoiWorkflowStatus::default()
        }
    );

    drop(public_data_plane);
    drop(cache_store);
    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn omitted_active_list_becoming_missing_keeps_recovery_recoverable() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let verified_list_key = FixedBytes::from([0x97; 32]);
    let omitted_list_key = FixedBytes::from([0x98; 32]);
    let active_list_keys = [verified_list_key, omitted_list_key];
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-omitted-list-became-missing");
    let mut wallet_utxo = test_wallet_utxo(18);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(verified_list_key, PoiStatus::ProofSubmitted);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(omitted_list_key, PoiStatus::Valid);
    let output_commitment = wallet_utxo.utxo.poi.commitment;
    let source_tx_hash = wallet_utxo.utxo.source.tx_hash;
    let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, verified_list_key);
    pending.submitted_poi_list_keys = vec![verified_list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let mut recovery = output_poi_recovery_record(
        cfg.chain.chain_id,
        &cfg.cache_key,
        output_commitment,
        OutputPoiRecoveryStatus::Submitted,
        Some(123),
    );
    recovery.source_tx_hash = source_tx_hash;
    recovery.attempt_count = 7;
    store
        .put_output_poi_recovery(&recovery)
        .expect("store recovery");
    let mut handle = test_wallet_handle(vec![wallet_utxo]);
    handle.cache_key = cfg.cache_key.clone();
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
            &active_list_keys,
        )
        .await
    });

    tokio::time::timeout(Duration::from_secs(2), started_rx)
        .await
        .expect("verification started")
        .expect("verification start signal");
    handle.utxos.write().await[0]
        .utxo
        .poi
        .statuses
        .insert(omitted_list_key, PoiStatus::Missing);
    release_tx.send(()).expect("release verification");

    let outcome = task.await.expect("verification task");
    assert_eq!(outcome.completed, 1);
    assert_eq!(outcome.pending, 0);
    assert_eq!(outcome.errors, 0);
    assert!(
        store
            .get_pending_output_poi_context(cfg.chain.chain_id, &cfg.cache_key, &output_commitment,)
            .expect("load pending context")
            .is_none()
    );
    let recovery = store
        .get_output_poi_recovery(cfg.chain.chain_id, &cfg.cache_key, &output_commitment)
        .expect("load recovery")
        .expect("recovery present");
    assert_eq!(recovery.status, OutputPoiRecoveryStatus::Recoverable);
    assert_eq!(recovery.source_tx_hash, source_tx_hash);
    assert_eq!(recovery.attempt_count, 7);
    let current = handle.utxos.read().await;
    assert_eq!(
        current[0].utxo.poi.statuses.get(&verified_list_key),
        Some(&PoiStatus::Valid)
    );
    assert_eq!(
        current[0].utxo.poi.statuses.get(&omitted_list_key),
        Some(&PoiStatus::Missing)
    );
    drop(current);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn verified_valid_rejects_mismatched_recovery_source() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let list_key = FixedBytes::from([0x99; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-verified-source-replacement");
    let mut wallet_utxo = test_wallet_utxo(19);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::ProofSubmitted);
    let output_commitment = wallet_utxo.utxo.poi.commitment;
    let source_tx_hash = wallet_utxo.utxo.source.tx_hash;
    let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let mut stale_recovery = output_poi_recovery_record(
        cfg.chain.chain_id,
        &cfg.cache_key,
        output_commitment,
        OutputPoiRecoveryStatus::Submitted,
        Some(123),
    );
    stale_recovery.tx_input = Some(vec![0xde, 0xad]);
    assert_ne!(stale_recovery.source_tx_hash, source_tx_hash);
    store
        .put_output_poi_recovery(&stale_recovery)
        .expect("store stale recovery");
    let mut handle = test_wallet_handle(vec![wallet_utxo]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let client = RecordingPoiStatusClient::default();

    let outcome = verify_submitted_pending_output_pois_authorized_with_projection(
        &authority,
        &client,
        &store,
        &cfg,
        &store,
        &[list_key],
    )
    .await;

    assert_eq!(outcome.completed, 0);
    assert_eq!(outcome.pending, 0);
    assert_eq!(outcome.errors, 0);
    assert!(
        store
            .get_pending_output_poi_context(cfg.chain.chain_id, &cfg.cache_key, &output_commitment,)
            .expect("load pending context")
            .is_some()
    );
    let recovery = store
        .get_output_poi_recovery(cfg.chain.chain_id, &cfg.cache_key, &output_commitment)
        .expect("load recovery")
        .expect("recovery present");
    assert_eq!(recovery.source_tx_hash, stale_recovery.source_tx_hash);
    assert_eq!(recovery.status, stale_recovery.status);
    assert_eq!(recovery.tx_input, stale_recovery.tx_input);
    assert_eq!(recovery.attempt_count, stale_recovery.attempt_count);
    assert_eq!(
        handle.utxos.read().await[0]
            .utxo
            .poi
            .statuses
            .get(&list_key),
        Some(&PoiStatus::ProofSubmitted)
    );
    assert_eq!(
        client.calls(),
        [] as [(Vec<FixedBytes<32>>, Vec<BlindedCommitmentData>); 0]
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn authorized_pending_output_poi_retry_resubmits_submitted_lists() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let chain_id = 1;
    let list_key = FixedBytes::from([0x95; 32]);
    let valid_unsubmitted_list_key = FixedBytes::from([0x96; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-1");
    let mut wallet_utxo = test_wallet_utxo(15);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::ProofSubmitted);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(valid_unsubmitted_list_key, PoiStatus::Valid);
    let output_commitment = wallet_utxo.utxo.poi.commitment;
    let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    pending.required_poi_list_keys = vec![list_key, valid_unsubmitted_list_key];
    pending.submitted_poi_list_keys = vec![list_key];
    pending.pre_transaction_pois_per_txid_leaf_per_list.insert(
        valid_unsubmitted_list_key,
        BTreeMap::from([(FixedBytes::from([0x96; 32]), sample_pre_tx_poi(0x16))]),
    );
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let now = now_epoch_secs();
    let mut recovery = output_poi_recovery_record(
        chain_id,
        &cfg.cache_key,
        output_commitment,
        OutputPoiRecoveryStatus::Submitted,
        Some(now.saturating_sub(1)),
    );
    recovery.source_tx_hash = wallet_utxo.utxo.source.tx_hash;
    store
        .put_output_poi_recovery(&recovery)
        .expect("store recovery");
    let mut handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let submitter = Arc::new(RecordingPendingOutputPoiSubmitter::default());
    let private_poi =
        WalletPrivatePoiClients::for_submit(authority.remote_authority(), submitter.clone());

    let obsolete = previous_key_pending_context(&pending);
    store
        .put_pending_output_poi_context(&obsolete)
        .expect("persist previous-key pending proof");
    assert_eq!(
        process_pending_output_poi_observations_authorized(
            &authority,
            &test_public_data_plane_with_poi_service(&store),
            store.as_ref(),
            store.as_ref(),
            &cfg,
            &[list_key, valid_unsubmitted_list_key],
            Some(&private_poi),
            true
        )
        .await,
        0
    );
    assert_eq!(submitter.calls(), [] as [(FixedBytes<32>, u64, u64); 0]);
    assert_eq!(
        pending_output_poi_context_fingerprint(
            &store
                .get_pending_output_poi_context(
                    cfg.chain.chain_id,
                    &cfg.cache_key,
                    &pending.output_commitment
                )
                .expect("old context query")
                .expect("old context preserved")
        ),
        pending_output_poi_context_fingerprint(&obsolete)
    );
    store
        .put_pending_output_poi_context(&pending)
        .expect("restore current proof fixture");

    let submitted = process_pending_output_poi_observations_authorized(
        &authority,
        &test_public_data_plane_with_poi_service(&store),
        store.as_ref(),
        store.as_ref(),
        &cfg,
        &[list_key, valid_unsubmitted_list_key],
        Some(&private_poi),
        false,
    )
    .await;

    assert_eq!(submitted, 1);
    assert_eq!(submitter.list_key_calls(), vec![vec![list_key]]);
    assert_eq!(
        submitter.calls(),
        vec![(
            output_commitment,
            u64::from(wallet_utxo.utxo.tree),
            wallet_utxo.utxo.position,
        ),]
    );
    let recovery = store
        .get_output_poi_recovery(chain_id, &cfg.cache_key, &output_commitment)
        .expect("load recovery")
        .expect("recovery present");
    assert_eq!(recovery.status, OutputPoiRecoveryStatus::Submitted);
    assert_eq!(recovery.attempt_count, 1);
    assert!(recovery.next_retry_at.is_some_and(|next| next > now));
    let context = store
        .get_pending_output_poi_context(chain_id, &cfg.cache_key, &output_commitment)
        .expect("load pending context")
        .expect("pending context present");
    assert_eq!(context.list_keys(), vec![list_key]);
    assert_eq!(context.submitted_poi_list_keys, vec![list_key]);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn existing_context_submits_missing_subset_and_prunes_nonrecoverable_unsubmitted_lists() {
    for (case, nonrecoverable_status) in [PoiStatus::Valid, PoiStatus::ShieldBlocked]
        .into_iter()
        .enumerate()
    {
        let root_dir = temp_db_root();
        let store = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let recoverable_list_key = FixedBytes::from([0xa1; 32]);
        let nonrecoverable_list_key = FixedBytes::from([0xa2; 32]);
        let active_list_keys = [recoverable_list_key, nonrecoverable_list_key];
        let mut cfg = wallet_config(U256::ZERO);
        cfg.cache_key = test_cache_key(format!("wallet-existing-context-subset-{case}"));
        let mut wallet_utxo = test_wallet_utxo(90 + case as u64);
        wallet_utxo
            .utxo
            .poi
            .statuses
            .insert(recoverable_list_key, PoiStatus::Missing);
        wallet_utxo
            .utxo
            .poi
            .statuses
            .insert(nonrecoverable_list_key, nonrecoverable_status);
        let output_commitment = wallet_utxo.utxo.poi.commitment;
        let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, recoverable_list_key);
        pending.required_poi_list_keys = active_list_keys.to_vec();
        pending.pre_transaction_pois_per_txid_leaf_per_list.insert(
            nonrecoverable_list_key,
            BTreeMap::from([(FixedBytes::from([0xa3; 32]), sample_pre_tx_poi(0x17))]),
        );
        store
            .put_pending_output_poi_context(&pending)
            .expect("store pending context");
        let mut handle = test_wallet_handle(vec![wallet_utxo.clone()]);
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
            &active_list_keys,
            Some(&private_poi),
            false,
        )
        .await;

        assert_eq!(submitted, 1);
        assert_eq!(
            submitter.list_key_calls(),
            vec![vec![recoverable_list_key]],
            "{nonrecoverable_status:?} list must not reach submission transport"
        );
        let persisted = store
            .get_pending_output_poi_context(cfg.chain.chain_id, &cfg.cache_key, &output_commitment)
            .expect("load pending context")
            .expect("pending context present");
        assert_eq!(persisted.list_keys(), vec![recoverable_list_key]);
        assert_eq!(
            persisted.submitted_poi_list_keys,
            vec![recoverable_list_key]
        );
        assert_eq!(
            persisted
                .pre_transaction_pois_per_txid_leaf_per_list
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            vec![recoverable_list_key]
        );

        drop(store);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }
}

#[tokio::test]
async fn pending_submission_preflight_repeatedly_rejects_recovery_source_mismatch() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let list_key = FixedBytes::from([0x97; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-recovery-source-mismatch");
    let mut wallet_utxo = test_wallet_utxo(17);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    let output_commitment = wallet_utxo.utxo.poi.commitment;
    let pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let recovery = output_poi_recovery_record(
        cfg.chain.chain_id,
        &cfg.cache_key,
        output_commitment,
        OutputPoiRecoveryStatus::Recoverable,
        None,
    );
    assert_ne!(
        recovery.source_tx_hash,
        pending.observation.as_ref().expect("observation").tx_hash
    );
    store
        .put_output_poi_recovery(&recovery)
        .expect("store mismatched recovery");
    let mut handle = test_wallet_handle(vec![wallet_utxo]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let submitter = Arc::new(RecordingPendingOutputPoiSubmitter::default());
    let private_poi =
        WalletPrivatePoiClients::for_submit(authority.remote_authority(), submitter.clone());

    for _ in 0..2 {
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
    }
    assert!(
        submitter.calls().is_empty(),
        "mismatched recovery source must never reach submission transport"
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

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
