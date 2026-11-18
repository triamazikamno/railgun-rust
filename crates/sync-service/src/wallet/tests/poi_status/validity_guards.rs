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
        Err(crate::wallet::WalletPrivateRemoteError::Stale(
            crate::wallet::WalletPrivateRemoteStale::Subject
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
        Err(crate::wallet::WalletPrivateRemoteError::Stale(
            crate::wallet::WalletPrivateRemoteStale::Authority
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
        crate::wallet::expected_recovery_state(Some(&recovery)).expect("recovery fingerprint");
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
        expected_recovery: crate::wallet::expected_recovery_state(Some(&recovery))
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
