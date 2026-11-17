use super::*;

#[tokio::test]
async fn authorized_external_pending_outputs_submit_without_sender_utxos() {
    for (byte, role) in [
        (0xa4_u8, PendingOutputPoiRole::Recipient),
        (0xa5_u8, PendingOutputPoiRole::BroadcasterFee),
    ] {
        let root_dir = temp_db_root();
        let store = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let list_key = FixedBytes::from([byte.wrapping_add(1); 32]);
        let mut cfg = wallet_config(U256::ZERO);
        cfg.cache_key = test_cache_key(format!("wallet-external-{byte}"));
        let pending = external_pending_output_record(&cfg, byte, list_key, role);
        store
            .put_pending_output_poi_context(&pending)
            .expect("store external pending context");
        let mut handle = test_wallet_handle(Vec::new());
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

        assert_eq!(submitted, 1);
        assert_eq!(submitter.calls().len(), 1);
        assert!(handle.utxos.read().await.is_empty());
        let persisted = store
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &pending.output_commitment,
            )
            .expect("load external pending context")
            .expect("external context remains pending verification");
        assert_eq!(persisted.submitted_poi_list_keys, vec![list_key]);
        let recovery = store
            .get_output_poi_recovery(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &pending.output_commitment,
            )
            .expect("load external recovery")
            .expect("external recovery present");
        assert_eq!(recovery.status, OutputPoiRecoveryStatus::Submitted);
        assert_eq!(
            recovery.source_tx_hash,
            pending.observation.as_ref().expect("observation").tx_hash
        );

        drop(store);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }
}

/// Maintenance hands single-commitment proofs to the chain submitter without
/// waiting for the POI node, and a failed chain attempt reaches the wallet on
/// its next handoff.
#[tokio::test]
async fn pending_output_handoff_does_not_wait_for_chain_send_and_reports_chain_failure() {
    // Far below `POI_MAINTENANCE_WATCHDOG`; a run that waited on the stalled
    // send would never finish.
    const RUN_LIMIT: Duration = Duration::from_secs(10);
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let list_key = FixedBytes::from([0xb5; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-chain-handoff-failure");
    let pending =
        external_pending_output_record(&cfg, 0xb4, list_key, PendingOutputPoiRole::Recipient);
    store
        .put_pending_output_poi_context(&pending)
        .expect("store external pending context");
    let transport = Arc::new(RecordingPoiTransport::default());
    transport.script(ScriptedSend::Fail("POI node unavailable"));
    transport.script(ScriptedSend::Stall);
    let submitter_cancel = CancellationToken::new();
    let (poi_submitter, submitter_task) = ChainPoiSubmitterHandle::spawn_for_test(
        cfg.chain.chain_id,
        Arc::clone(&transport) as Arc<dyn PendingOutputPoiSubmitter>,
        submitter_cancel.clone(),
    );
    let mut handle = test_wallet_handle(Vec::new());
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let private_poi = WalletPrivatePoiClients::for_handoff(
        authority.remote_authority(),
        Arc::new(poi_submitter.clone()),
    );
    let needs_attention = || {
        wallet_ppoi_workflow_status_after_mutations(
            store.as_ref(),
            &cfg,
            &[list_key],
            0,
            PoiPrivateRows::default(),
        )
        .expect("workflow status")
        .status
        .needs_attention
    };

    let submitted = tokio::time::timeout(
        RUN_LIMIT,
        process_pending_output_poi_observations_authorized(
            &authority,
            &test_public_data_plane_with_poi_service(&store),
            store.as_ref(),
            store.as_ref(),
            &cfg,
            &[list_key],
            Some(&private_poi),
            false,
        ),
    )
    .await
    .expect("first handoff does not wait for the POI node");
    assert_eq!(submitted, 1, "the handoff is recorded as a submission");
    assert_eq!(needs_attention(), 0);
    let started = std::time::Instant::now();
    while transport.sends().is_empty() {
        assert!(started.elapsed() < RUN_LIMIT, "chain send never started");
        tokio::task::yield_now().await;
    }
    // Let the driver record the failed attempt before the next handoff.
    poi_submitter
        .prepare(Vec::new())
        .await
        .expect("chain submitter running");
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }

    let submitted = tokio::time::timeout(
        RUN_LIMIT,
        process_pending_output_poi_observations_authorized(
            &authority,
            &test_public_data_plane_with_poi_service(&store),
            store.as_ref(),
            store.as_ref(),
            &cfg,
            &[list_key],
            Some(&private_poi),
            true,
        ),
    )
    .await
    .expect("retry handoff does not wait for the stalled chain send");
    assert_eq!(submitted, 0);
    let recovery = store
        .get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &pending.output_commitment,
        )
        .expect("load recovery")
        .expect("recovery present");
    assert_eq!(recovery.status, OutputPoiRecoveryStatus::SubmitFailed);
    assert_eq!(needs_attention(), 1);
    while transport.sends().len() < 2 {
        assert!(started.elapsed() < RUN_LIMIT, "chain retry never started");
        tokio::task::yield_now().await;
    }
    let observation = pending.observation.as_ref().expect("observation");
    assert_eq!(
        transport
            .sends()
            .iter()
            .map(|send| (send.commitment, send.tree, send.position))
            .collect::<Vec<_>>(),
        vec![
            (
                pending.output_commitment,
                observation.output_tree,
                observation.output_position,
            );
            2
        ],
        "the retry handoff resends the failed tuple"
    );

    submitter_cancel.cancel();
    submitter_task.await.expect("chain submitter exits");
    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn external_submission_rejects_scan_replacement_before_remote_transport() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = RecordingCacheStore::new(Arc::clone(&store));
    let list_key = FixedBytes::from([0xb1; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-external-submit-scan-replacement");
    let pending =
        external_pending_output_record(&cfg, 0xb0, list_key, PendingOutputPoiRole::Recipient);
    store
        .put_pending_output_poi_context(&pending)
        .expect("store external pending context");
    let mut replacement = pending.clone();
    let replacement_observation = replacement.observation.as_mut().expect("observation");
    replacement_observation.tx_hash = FixedBytes::from([0xb2; 32]);
    replacement_observation.block_number += 1;
    cache_store.replace_context_before_recovery_read(3, replacement.clone());

    let mut handle = test_wallet_handle(Vec::new());
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let submitter = Arc::new(RecordingPendingOutputPoiSubmitter::default());
    let private_poi =
        WalletPrivatePoiClients::for_submit(authority.remote_authority(), submitter.clone());
    let observation = pending.observation.clone().expect("observation");
    let identity = pending_output_poi_submit_identity(&pending, &observation).expect("identity");
    let subject = PendingOutputPoiSubject::External {
        output_commitment: pending.output_commitment,
        derived_blinded_commitment: identity.derived_blinded_commitment,
    };
    let plan = super::super::PendingOutputPoiSubmissionPlan::force_matching(
        vec![list_key],
        ExpectedRecordState::Absent,
    );

    let attempt = preflight_and_remote_submit_pending_output_poi(
        &PendingOutputPoiSubmissionPreflight {
            authority: &authority,
            public_data_plane: &test_public_data_plane_with_poi_service(&store),
            cache_store: &cache_store,
            cfg: &cfg,
            active_list_keys: &[list_key],
            expected: &pending,
            subject: &subject,
            plan: &plan,
        },
        &observation,
        &private_poi,
        &mut None,
    )
    .await
    .expect("submit result");

    assert!(matches!(
        attempt,
        super::super::PendingOutputPoiRemoteAttempt::NotCurrent
    ));
    assert_eq!(submitter.calls(), [] as [(FixedBytes<32>, u64, u64); 0]);
    assert_eq!(
        store
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &pending.output_commitment,
            )
            .expect("load replacement context")
            .as_ref()
            .and_then(pending_output_poi_context_fingerprint),
        pending_output_poi_context_fingerprint(&replacement),
    );

    drop(cache_store);
    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn authorized_external_pending_output_force_retry_resubmits_without_sender_utxo() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let list_key = FixedBytes::from([0xa7; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-external-force-retry");
    let mut pending =
        external_pending_output_record(&cfg, 0xa6, list_key, PendingOutputPoiRole::Recipient);
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store external pending context");
    let mut recovery = output_poi_recovery_record(
        cfg.chain.chain_id,
        &cfg.cache_key,
        pending.output_commitment,
        OutputPoiRecoveryStatus::Submitted,
        Some(u64::MAX),
    );
    recovery.source_tx_hash = pending.observation.as_ref().expect("observation").tx_hash;
    store
        .put_output_poi_recovery(&recovery)
        .expect("store external recovery");
    let mut handle = test_wallet_handle(Vec::new());
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
            &[list_key],
            Some(&private_poi),
            true
        )
        .await,
        0
    );
    let obsolete_utxos = Arc::new(RwLock::new(Vec::new()));
    assert_eq!(
        force_resubmit_matching_pending_output_pois_authorized(
            &authority,
            &test_public_data_plane_with_poi_service(&store),
            store.as_ref(),
            store.as_ref(),
            &cfg,
            &obsolete_utxos,
            &[list_key],
            &private_poi
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
    assert_eq!(
        process_pending_output_poi_observations_authorized(
            &authority,
            &test_public_data_plane_with_poi_service(&store),
            store.as_ref(),
            store.as_ref(),
            &cfg,
            &[list_key],
            Some(&private_poi),
            true,
        )
        .await,
        1
    );
    assert_eq!(submitter.calls().len(), 1);
    let empty_utxos = Arc::new(RwLock::new(Vec::new()));
    assert_eq!(
        force_resubmit_matching_pending_output_pois_authorized(
            &authority,
            &test_public_data_plane_with_poi_service(&store),
            store.as_ref(),
            store.as_ref(),
            &cfg,
            &empty_utxos,
            &[list_key],
            &private_poi,
        )
        .await,
        1
    );
    assert_eq!(submitter.calls().len(), 2);
    assert!(handle.utxos.read().await.is_empty());

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn authorized_external_pending_output_verification_retires_private_state() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let list_key = FixedBytes::from([0xa9; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-external-verification");
    let mut pending =
        external_pending_output_record(&cfg, 0xa8, list_key, PendingOutputPoiRole::BroadcasterFee);
    pending.submitted_poi_list_keys = vec![list_key];
    pending = previous_key_pending_context(&pending);
    store
        .put_pending_output_poi_context(&pending)
        .expect("store external pending context");
    let mut recovery = output_poi_recovery_record(
        cfg.chain.chain_id,
        &cfg.cache_key,
        pending.output_commitment,
        OutputPoiRecoveryStatus::Submitted,
        Some(123),
    );
    recovery.source_tx_hash = pending.observation.as_ref().expect("observation").tx_hash;
    store
        .put_output_poi_recovery(&recovery)
        .expect("store external recovery");
    let mut handle = test_wallet_handle(Vec::new());
    handle.cache_key = cfg.cache_key.clone();
    handle
        .observation
        .upgrade()
        .expect("observation publisher")
        .publish_ppoi_workflow_status(WalletPpoiWorkflowStatus {
            awaiting_validation: 1,
            ..WalletPpoiWorkflowStatus::default()
        });
    let revision_before = *handle.rev_rx.borrow();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
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

    let outcome = verify_submitted_pending_output_pois_with_config_authorized(
        &authority,
        &public_data_plane,
        &poi_runtime,
        &private_poi,
        &cfg,
        store.as_ref(),
        store.as_ref(),
        &[list_key],
    )
    .await;

    assert_eq!(outcome.completed, 1);
    assert_eq!(outcome.errors, 0);
    assert!(
        store
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &pending.output_commitment,
            )
            .expect("load pending context")
            .is_none()
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
    assert!(handle.utxos.read().await.is_empty());
    assert_eq!(transport.calls().len(), 1);
    assert_eq!(*handle.rev_rx.borrow(), revision_before);
    assert_eq!(
        handle.observation().ppoi_workflow_status(),
        &WalletPpoiWorkflowStatus {
            validation_revision: 1,
            ..WalletPpoiWorkflowStatus::default()
        }
    );

    drop(public_data_plane);
    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn external_proxy_verification_rejects_scan_replacement_before_remote_transport() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = RecordingCacheStore::new(Arc::clone(&store));
    let list_key = FixedBytes::from([0xb4; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-external-verify-scan-replacement");
    let mut pending =
        external_pending_output_record(&cfg, 0xb3, list_key, PendingOutputPoiRole::BroadcasterFee);
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store external pending context");
    let mut replacement = pending.clone();
    let replacement_observation = replacement.observation.as_mut().expect("observation");
    replacement_observation.tx_hash = FixedBytes::from([0xb5; 32]);
    replacement_observation.block_number += 1;
    replacement.submitted_poi_list_keys.clear();
    cache_store.replace_context_before_recovery_read(2, replacement.clone());

    let mut handle = test_wallet_handle(Vec::new());
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
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

    assert_eq!(outcome.completed, 0);
    assert_eq!(outcome.pending, 0);
    assert_eq!(outcome.errors, 0);
    assert_eq!(
        transport.calls(),
        [] as [(Vec<FixedBytes<32>>, Vec<BlindedCommitmentData>); 0]
    );
    assert_eq!(
        store
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &pending.output_commitment,
            )
            .expect("load replacement context")
            .as_ref()
            .and_then(pending_output_poi_context_fingerprint),
        pending_output_poi_context_fingerprint(&replacement),
    );

    drop(public_data_plane);
    drop(cache_store);
    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn submitted_external_proxy_verification_rejects_mismatched_recovery_before_remote() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let list_key = FixedBytes::from([0xab; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-stale-external-proxy-verification");
    let mut pending =
        external_pending_output_record(&cfg, 0xaa, list_key, PendingOutputPoiRole::Recipient);
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store external pending context");
    let stale_recovery = output_poi_recovery_record(
        cfg.chain.chain_id,
        &cfg.cache_key,
        pending.output_commitment,
        OutputPoiRecoveryStatus::Submitted,
        Some(123),
    );
    assert_ne!(
        stale_recovery.source_tx_hash,
        pending.observation.as_ref().expect("observation").tx_hash
    );
    store
        .put_output_poi_recovery(&stale_recovery)
        .expect("store stale recovery");
    let mut handle = test_wallet_handle(Vec::new());
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
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

    let outcome = verify_submitted_pending_output_pois_with_config_authorized(
        &authority,
        &public_data_plane,
        &poi_runtime,
        &private_poi,
        &cfg,
        store.as_ref(),
        store.as_ref(),
        &[list_key],
    )
    .await;

    assert_eq!(outcome.completed, 0);
    assert_eq!(outcome.pending, 0);
    assert_eq!(outcome.errors, 0);
    assert_eq!(
        transport.calls(),
        [] as [(Vec<FixedBytes<32>>, Vec<BlindedCommitmentData>); 0]
    );
    assert!(
        store
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &pending.output_commitment,
            )
            .expect("load pending context")
            .is_some()
    );

    drop(public_data_plane);
    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn unsubmitted_external_pending_output_cannot_use_owned_valid_reconciliation() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let list_key = FixedBytes::from([0xaa; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-unsubmitted-external-verification");
    let pending =
        external_pending_output_record(&cfg, 0xa9, list_key, PendingOutputPoiRole::Recipient);
    store
        .put_pending_output_poi_context(&pending)
        .expect("store external pending context");
    let mut handle = test_wallet_handle(Vec::new());
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
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

    let outcome = verify_submitted_pending_output_pois_with_config_authorized(
        &authority,
        &public_data_plane,
        &poi_runtime,
        &private_poi,
        &cfg,
        store.as_ref(),
        store.as_ref(),
        &[list_key],
    )
    .await;

    assert_eq!(outcome.completed, 0);
    assert_eq!(outcome.pending, 0);
    assert_eq!(outcome.errors, 0);
    assert_eq!(
        transport.calls(),
        [] as [(Vec<FixedBytes<32>>, Vec<BlindedCommitmentData>); 0]
    );
    assert!(
        store
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &pending.output_commitment,
            )
            .expect("load pending context")
            .is_some()
    );

    drop(public_data_plane);
    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn authorized_external_pending_output_persistence_failure_does_not_commit() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = RecordingCacheStore::new(Arc::clone(&store));
    let list_key = FixedBytes::from([0xab; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-external-persist-failure");
    let pending =
        external_pending_output_record(&cfg, 0xaa, list_key, PendingOutputPoiRole::Recipient);
    store
        .put_pending_output_poi_context(&pending)
        .expect("store external pending context");
    let mut handle = test_wallet_handle(Vec::new());
    handle.cache_key = cfg.cache_key.clone();
    let workflow_before = WalletPpoiWorkflowStatus {
        awaiting_validation: 1,
        validation_revision: 4,
        ..WalletPpoiWorkflowStatus::default()
    };
    handle
        .observation
        .upgrade()
        .expect("observation publisher")
        .publish_ppoi_workflow_status(workflow_before);
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let submitter = Arc::new(RecordingPendingOutputPoiSubmitter::default());
    let private_poi =
        WalletPrivatePoiClients::for_submit(authority.remote_authority(), submitter.clone());
    cache_store.fail_next_commit();

    let submitted = process_pending_output_poi_observations_authorized(
        &authority,
        &test_public_data_plane_with_poi_service(&store),
        store.as_ref(),
        &cache_store,
        &cfg,
        &[list_key],
        Some(&private_poi),
        false,
    )
    .await;

    assert_eq!(submitted, 0);
    assert_eq!(submitter.calls().len(), 1);
    let persisted = store
        .get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &pending.output_commitment,
        )
        .expect("load pending context")
        .expect("pending context preserved");
    assert_eq!(persisted.submitted_poi_list_keys, [] as [FixedBytes<32>; 0]);
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
    assert_eq!(
        handle.observation().ppoi_workflow_status(),
        &workflow_before
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn authorized_external_verification_persistence_failure_does_not_retire_context() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = RecordingCacheStore::new(Arc::clone(&store));
    let list_key = FixedBytes::from([0xad; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-external-verify-persist-failure");
    let mut pending =
        external_pending_output_record(&cfg, 0xac, list_key, PendingOutputPoiRole::BroadcasterFee);
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store external pending context");
    let mut recovery = output_poi_recovery_record(
        cfg.chain.chain_id,
        &cfg.cache_key,
        pending.output_commitment,
        OutputPoiRecoveryStatus::Submitted,
        Some(123),
    );
    recovery.source_tx_hash = pending.observation.as_ref().expect("observation").tx_hash;
    store
        .put_output_poi_recovery(&recovery)
        .expect("store external recovery");
    let mut handle = test_wallet_handle(Vec::new());
    handle.cache_key = cfg.cache_key.clone();
    let workflow_before = WalletPpoiWorkflowStatus {
        awaiting_validation: 1,
        validation_revision: 5,
        ..WalletPpoiWorkflowStatus::default()
    };
    handle
        .observation
        .upgrade()
        .expect("observation publisher")
        .publish_ppoi_workflow_status(workflow_before);
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    cache_store.fail_next_commit();

    let outcome = verify_submitted_pending_output_pois_authorized_with_projection(
        &authority,
        &RecordingPoiStatusClient::default(),
        store.as_ref(),
        &cfg,
        &cache_store,
        &[list_key],
    )
    .await;

    assert_eq!(outcome.completed, 0);
    assert_eq!(outcome.errors, 1);
    assert!(
        store
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &pending.output_commitment,
            )
            .expect("load pending context")
            .is_some()
    );
    let persisted_recovery = store
        .get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &pending.output_commitment,
        )
        .expect("load recovery")
        .expect("recovery preserved");
    assert_eq!(persisted_recovery.source_tx_hash, recovery.source_tx_hash);
    assert_eq!(persisted_recovery.status, recovery.status);
    assert_eq!(persisted_recovery.attempt_count, recovery.attempt_count);
    assert!(handle.utxos.read().await.is_empty());
    assert_eq!(
        handle.observation().ppoi_workflow_status(),
        &workflow_before
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn authorized_external_verification_projection_failure_does_not_commit() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = RecordingCacheStore::new(Arc::clone(&store));
    let list_key = FixedBytes::from([0xaf; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-external-verify-projection-failure");
    let mut pending =
        external_pending_output_record(&cfg, 0xae, list_key, PendingOutputPoiRole::BroadcasterFee);
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store external pending context");
    let mut recovery = output_poi_recovery_record(
        cfg.chain.chain_id,
        &cfg.cache_key,
        pending.output_commitment,
        OutputPoiRecoveryStatus::Submitted,
        Some(123),
    );
    recovery.source_tx_hash = pending.observation.as_ref().expect("observation").tx_hash;
    store
        .put_output_poi_recovery(&recovery)
        .expect("store external recovery");
    let mut handle = test_wallet_handle(Vec::new());
    handle.cache_key = cfg.cache_key.clone();
    let workflow_before = WalletPpoiWorkflowStatus {
        awaiting_validation: 1,
        validation_revision: 7,
        ..WalletPpoiWorkflowStatus::default()
    };
    handle
        .observation
        .upgrade()
        .expect("observation publisher")
        .publish_ppoi_workflow_status(workflow_before);
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    cache_store.fail_pending_output_list_call(1);
    let commit_calls_before = cache_store.state().meta_calls;

    let outcome = verify_submitted_pending_output_pois_authorized_with_projection(
        &authority,
        &RecordingPoiStatusClient::default(),
        store.as_ref(),
        &cfg,
        &cache_store,
        &[list_key],
    )
    .await;

    assert_eq!(outcome.completed, 0);
    assert_eq!(outcome.errors, 1);
    assert_eq!(cache_store.state().meta_calls, commit_calls_before);
    assert!(
        store
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &pending.output_commitment,
            )
            .expect("load pending context")
            .is_some()
    );
    let persisted_recovery = store
        .get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &pending.output_commitment,
        )
        .expect("load recovery")
        .expect("recovery preserved");
    assert_eq!(persisted_recovery.source_tx_hash, recovery.source_tx_hash);
    assert_eq!(persisted_recovery.status, recovery.status);
    assert_eq!(persisted_recovery.attempt_count, recovery.attempt_count);
    assert_eq!(
        handle.observation().ppoi_workflow_status(),
        &workflow_before
    );

    drop(cache_store);
    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
