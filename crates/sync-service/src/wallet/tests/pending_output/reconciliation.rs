use super::*;

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
