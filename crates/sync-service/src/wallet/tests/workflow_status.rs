use super::*;

#[test]
fn wallet_ppoi_workflow_status_classifies_only_observed_active_contexts() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let cfg = wallet_config(U256::ZERO);
    let active_list = FixedBytes::from([0xc0; 32]);
    let inactive_list = FixedBytes::from([0xc1; 32]);

    let mut awaiting_submission =
        external_pending_output_record(&cfg, 0xc2, active_list, PendingOutputPoiRole::Recipient);
    awaiting_submission.submitted_poi_list_keys.clear();
    let mut awaiting_validation = external_pending_output_record(
        &cfg,
        0xc3,
        active_list,
        PendingOutputPoiRole::BroadcasterFee,
    );
    awaiting_validation.submitted_poi_list_keys = vec![active_list];
    let mut acknowledged_recovery = output_poi_recovery_record(
        cfg.chain.chain_id,
        &cfg.cache_key,
        awaiting_validation.output_commitment,
        OutputPoiRecoveryStatus::Submitted,
        None,
    );
    acknowledged_recovery.source_tx_hash = awaiting_validation
        .observation
        .as_ref()
        .expect("acknowledged observation")
        .tx_hash;
    acknowledged_recovery.last_submission_at = Some(42);
    let mut terminal = external_pending_output_record(
        &cfg,
        0xc4,
        active_list,
        PendingOutputPoiRole::RecoveredOutgoing,
    );
    terminal.terminal_error = Some("test-only terminal error".to_string());
    terminal.submitted_poi_list_keys = vec![active_list];
    let failed =
        external_pending_output_record(&cfg, 0xc5, active_list, PendingOutputPoiRole::Recipient);
    let mut unobserved =
        external_pending_output_record(&cfg, 0xc6, active_list, PendingOutputPoiRole::Recipient);
    unobserved.observation = None;
    let inactive =
        external_pending_output_record(&cfg, 0xc7, inactive_list, PendingOutputPoiRole::Recipient);
    let mut stale =
        external_pending_output_record(&cfg, 0xc8, active_list, PendingOutputPoiRole::Recipient);
    stale.submitted_poi_list_keys = vec![active_list];
    for context in [
        &awaiting_submission,
        &awaiting_validation,
        &terminal,
        &failed,
        &unobserved,
        &inactive,
        &stale,
    ] {
        store
            .put_pending_output_poi_context(context)
            .expect("store pending context");
    }
    store
        .put_output_poi_recovery(&acknowledged_recovery)
        .expect("store acknowledged recovery");
    let failed_observation = failed.observation.as_ref().expect("observed context");
    let mut failed_recovery = output_poi_recovery_record(
        cfg.chain.chain_id,
        &cfg.cache_key,
        failed.output_commitment,
        OutputPoiRecoveryStatus::SubmitFailed,
        None,
    );
    failed_recovery.source_tx_hash = failed_observation.tx_hash;
    failed_recovery.last_submission_at = Some(77);
    store
        .put_output_poi_recovery(&failed_recovery)
        .expect("store failed recovery");
    let mut no_timestamp_recovery = output_poi_recovery_record(
        cfg.chain.chain_id,
        &cfg.cache_key,
        terminal.output_commitment,
        OutputPoiRecoveryStatus::Submitted,
        None,
    );
    no_timestamp_recovery.source_tx_hash = terminal
        .observation
        .as_ref()
        .expect("terminal observation")
        .tx_hash;
    store
        .put_output_poi_recovery(&no_timestamp_recovery)
        .expect("store no-timestamp recovery");
    let mut stale_recovery = output_poi_recovery_record(
        cfg.chain.chain_id,
        &cfg.cache_key,
        stale.output_commitment,
        OutputPoiRecoveryStatus::SubmitFailed,
        None,
    );
    stale_recovery.last_submission_at = Some(99);
    store
        .put_output_poi_recovery(&stale_recovery)
        .expect("store stale recovery");

    let status = wallet_ppoi_workflow_status_for_test(&store, &cfg, &[active_list], 9);

    assert_eq!(status.awaiting_submission, 1);
    assert_eq!(status.awaiting_validation, 1);
    assert_eq!(status.needs_attention, 3);
    assert_eq!(status.validation_revision, 9);

    let projection = wallet_ppoi_workflow_status_after_mutations(
        &store,
        &cfg,
        &[active_list],
        9,
        PoiPrivateRows::default(),
    )
    .expect("derive submission projection");
    assert_eq!(
        projection.submissions.as_ref(),
        &[WalletPpoiSubmissionStatus {
            output_commitment: awaiting_validation.output_commitment,
            last_submission_at: 42,
        }]
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn wallet_ppoi_submission_projection_includes_change_without_external_workflow_count() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let cfg = wallet_config(U256::ZERO);
    let active_list = FixedBytes::from([0xd8; 32]);
    let mut context =
        external_pending_output_record(&cfg, 0xd9, active_list, PendingOutputPoiRole::Change);
    context.submitted_poi_list_keys = vec![active_list];
    let mut recovery = output_poi_recovery_record(
        cfg.chain.chain_id,
        &cfg.cache_key,
        context.output_commitment,
        OutputPoiRecoveryStatus::Submitted,
        None,
    );
    recovery.source_tx_hash = context
        .observation
        .as_ref()
        .expect("change observation")
        .tx_hash;
    recovery.last_submission_at = Some(123);
    store
        .put_pending_output_poi_context(&context)
        .expect("store change context");
    store
        .put_output_poi_recovery(&recovery)
        .expect("store change recovery");

    let status = wallet_ppoi_workflow_status_for_test(&store, &cfg, &[active_list], 0);
    assert_eq!(status, WalletPpoiWorkflowStatus::default());

    let projection = wallet_ppoi_workflow_status_after_mutations(
        &store,
        &cfg,
        &[active_list],
        0,
        PoiPrivateRows::default(),
    )
    .expect("derive change submission projection");
    assert_eq!(
        projection.submissions.as_ref(),
        &[WalletPpoiSubmissionStatus {
            output_commitment: context.output_commitment,
            last_submission_at: 123,
        }]
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn wallet_ppoi_workflow_status_transitions_candidate_output_without_double_counting() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let cfg = wallet_config(U256::ZERO);
    let active_list = FixedBytes::from([0xca; 32]);
    let input = test_wallet_utxo(0xcb);
    let mut candidate =
        sender_candidate_for_spent_input(cfg.cache_key.clone(), &input, source(0xcc));
    let owned_note = Note {
        token_hash: U256::from(7),
        value: U256::from(4),
        random: [0xce; 16],
        npk: Note::npk_for(cfg.scan_keys.master_public_key, [0xce; 16]),
    };
    candidate.outputs.push(SenderTransactionCandidateOutput {
        tree: 3,
        position: 5,
        commitment: FixedBytes::from(owned_note.commitment().to_be_bytes::<32>()),
        note: Some(owned_note),
    });
    candidate.outputs.push(SenderTransactionCandidateOutput {
        tree: 3,
        position: 6,
        commitment: FixedBytes::from([0xef; 32]),
        note: None,
    });
    candidate
        .validate()
        .expect("candidate with owned and unknown outputs");

    let awaiting_recovery = wallet_ppoi_workflow_status_after_mutations(
        &store,
        &cfg,
        &[active_list],
        0,
        PoiPrivateRows {
            candidate_updates: std::slice::from_ref(&candidate),
            ..PoiPrivateRows::default()
        },
    )
    .expect("derive candidate workflow status")
    .status;
    assert_eq!(awaiting_recovery.awaiting_recovery, 2);
    assert_eq!(awaiting_recovery.outstanding_count(), 2);

    // Each unresolved unshield TXID is one unit; handed-off outputs no longer count.
    let candidate_awaiting_recovery = |candidate: &SenderTransactionCandidate| {
        wallet_ppoi_workflow_status_after_mutations(
            &store,
            &cfg,
            &[active_list],
            0,
            PoiPrivateRows {
                candidate_updates: std::slice::from_ref(candidate),
                ..PoiPrivateRows::default()
            },
        )
        .expect("derive unshield workflow status")
        .status
        .awaiting_recovery
    };
    let with_unshield = |outputs_handed_off| {
        candidate
            .clone()
            .with_unshield(Some(SenderTransactionCandidateUnshield {
                railgun_txids: vec![FixedBytes::from([0x01; 32]), FixedBytes::from([0x02; 32])],
                outputs_handed_off,
            }))
            .expect("candidate with unshield work")
    };
    assert_eq!(candidate_awaiting_recovery(&with_unshield(true)), 2);
    assert_eq!(candidate_awaiting_recovery(&with_unshield(false)), 4);
    let mut spend_only = candidate.clone();
    spend_only.outputs.clear();
    assert_eq!(candidate_awaiting_recovery(&spend_only), 1);
    // Owned-only change is still unresolved work; a stored TXID replaces that placeholder.
    let mut owned_only = candidate.clone();
    owned_only.outputs = vec![candidate.outputs[1].clone()];
    assert_eq!(candidate_awaiting_recovery(&owned_only), 1);
    let owned_only_unshield = owned_only
        .with_unshield(Some(SenderTransactionCandidateUnshield {
            railgun_txids: vec![FixedBytes::from([0x01; 32])],
            outputs_handed_off: false,
        }))
        .expect("owned-only candidate with unshield work");
    assert_eq!(candidate_awaiting_recovery(&owned_only_unshield), 1);

    let mut materialized = external_pending_output_record(
        &cfg,
        0xcd,
        active_list,
        PendingOutputPoiRole::RecoveredOutgoing,
    );
    materialized.output_commitment = candidate.outputs[0].commitment;
    let after_materialization = wallet_ppoi_workflow_status_after_mutations(
        &store,
        &cfg,
        &[active_list],
        0,
        PoiPrivateRows {
            pending_updates: &[materialized],
            candidate_updates: std::slice::from_ref(&candidate),
            ..PoiPrivateRows::default()
        },
    )
    .expect("derive materialized workflow status")
    .status;
    assert_eq!(after_materialization.awaiting_recovery, 1);
    assert_eq!(after_materialization.awaiting_submission, 1);
    assert_eq!(after_materialization.outstanding_count(), 2);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn wallet_ppoi_workflow_status_keeps_matching_valid_recovery_awaiting_reconciliation() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let cfg = wallet_config(U256::ZERO);
    let active_list = FixedBytes::from([0xc8; 32]);
    let mut context = previous_key_pending_context(&external_pending_output_record(
        &cfg,
        0xc9,
        active_list,
        PendingOutputPoiRole::Recipient,
    ));
    context.submitted_poi_list_keys = vec![active_list];
    let mut recovery = output_poi_recovery_record(
        cfg.chain.chain_id,
        &cfg.cache_key,
        context.output_commitment,
        OutputPoiRecoveryStatus::Valid,
        None,
    );
    recovery.source_tx_hash = context.observation.as_ref().expect("observation").tx_hash;
    recovery.last_submission_at = Some(4);
    store
        .put_pending_output_poi_context(&context)
        .expect("store pending context");
    store
        .put_output_poi_recovery(&recovery)
        .expect("store valid recovery");

    let status = wallet_ppoi_workflow_status_for_test(&store, &cfg, &[active_list], 3);

    assert_eq!(
        status,
        WalletPpoiWorkflowStatus {
            awaiting_validation: 1,
            validation_revision: 3,
            ..WalletPpoiWorkflowStatus::default()
        }
    );

    recovery.last_submission_at = Some(8);
    let updated = wallet_ppoi_workflow_status_after_mutations(
        &store,
        &cfg,
        &[active_list],
        3,
        PoiPrivateRows {
            recovery_updates: std::slice::from_ref(&recovery),
            ..PoiPrivateRows::default()
        },
    )
    .expect("derive updated submission projection");
    assert_eq!(updated.submissions[0].last_submission_at, 8);

    let deleted = wallet_ppoi_workflow_status_after_mutations(
        &store,
        &cfg,
        &[active_list],
        3,
        PoiPrivateRows {
            recovery_deletes: std::slice::from_ref(&context.output_commitment),
            ..PoiPrivateRows::default()
        },
    )
    .expect("derive deleted submission projection");
    assert!(deleted.submissions.is_empty());

    let validation_deleted = wallet_ppoi_workflow_status_after_mutations(
        &store,
        &cfg,
        &[active_list],
        4,
        PoiPrivateRows {
            pending_deletes: std::slice::from_ref(&context.output_commitment),
            recovery_deletes: std::slice::from_ref(&context.output_commitment),
            ..PoiPrivateRows::default()
        },
    )
    .expect("derive validation deletion projection");
    assert!(validation_deleted.submissions.is_empty());

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn successful_submission_intent_survives_timestamp_only_poi_refresh() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-submission-timestamp-refresh");
    let list_key = FixedBytes::from([0x74; 32]);
    let mut wallet_utxo = test_wallet_utxo(74);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    let expected_output = ExpectedWalletOutput::new(&wallet_utxo);
    let pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    let expected_context_fingerprint =
        pending_output_poi_context_fingerprint(&pending).expect("pending context fingerprint");
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let mut handle = test_wallet_handle(vec![wallet_utxo]);
    handle.cache_key = cfg.cache_key.clone();
    handle.utxos.write().await[0].utxo.poi.refreshed_at = Some(100);
    let cancel = CancellationToken::new();

    let outcome = apply_owned_poi_private_delta_on_actor(
        &handle,
        &cancel,
        0,
        &store,
        &store,
        &cfg,
        OwnedPoiPrivateDelta::PendingSubmission(PendingSubmissionDelta {
            subject: PendingOutputPoiSubject::Owned(expected_output),
            expected_context_fingerprint,
            expected_recovery: ExpectedRecordState::Absent,
            active_list_keys: vec![list_key],
            list_keys: vec![list_key],
            predicate: PendingOutputPoiSubmissionPredicate::Missing,
            merge_submitted_list_keys: true,
            action: OutputPoiRecoveryAction::Submitted {
                retry_after: PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER,
            },
            now: 10,
        }),
    )
    .await
    .expect("apply successful submission intent");

    assert!(matches!(
        outcome,
        PoiPrivateApplyOutcome::Applied {
            utxo_changed: false
        }
    ));
    assert_eq!(
        handle.utxos.read().await[0].utxo.poi.refreshed_at,
        Some(100)
    );
    assert_eq!(
        store
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &pending.output_commitment,
            )
            .expect("load pending context")
            .expect("pending context present")
            .submitted_poi_list_keys,
        vec![list_key]
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn submission_workflow_projection_failure_aborts_before_commit_and_retry_converges() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = RecordingCacheStore::new(Arc::clone(&store));
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-submission-workflow-projection-failure");
    let list_key = FixedBytes::from([0x73; 32]);
    let mut wallet_utxo = test_wallet_utxo(73);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    let expected_output = ExpectedWalletOutput::new(&wallet_utxo);
    let pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    let expected_context_fingerprint =
        pending_output_poi_context_fingerprint(&pending).expect("pending context fingerprint");
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let mut handle = test_wallet_handle(vec![wallet_utxo]);
    handle.cache_key = cfg.cache_key.clone();
    let workflow_before = WalletPpoiWorkflowStatus {
        awaiting_submission: 1,
        ..WalletPpoiWorkflowStatus::default()
    };
    handle
        .observation
        .upgrade()
        .expect("observation publisher")
        .publish_ppoi_workflow_status(workflow_before);
    let cancel = CancellationToken::new();
    let submission_delta = || {
        OwnedPoiPrivateDelta::PendingSubmission(PendingSubmissionDelta {
            subject: PendingOutputPoiSubject::Owned(expected_output.clone()),
            expected_context_fingerprint: expected_context_fingerprint.clone(),
            expected_recovery: ExpectedRecordState::Absent,
            active_list_keys: vec![list_key],
            list_keys: vec![list_key],
            predicate: PendingOutputPoiSubmissionPredicate::Missing,
            merge_submitted_list_keys: true,
            action: OutputPoiRecoveryAction::Submitted {
                retry_after: PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER,
            },
            now: 10,
        })
    };
    cache_store.fail_pending_output_list_call(0);
    let commit_calls_before = cache_store.state().meta_calls;

    let failure = apply_owned_poi_private_delta_on_actor(
        &handle,
        &cancel,
        0,
        store.as_ref(),
        &cache_store,
        &cfg,
        submission_delta(),
    )
    .await;

    assert!(matches!(failure, Err(WalletCacheError::Crypto)));
    assert_eq!(cache_store.state().meta_calls, commit_calls_before);
    let retained = store
        .get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &pending.output_commitment,
        )
        .expect("load retained pending context")
        .expect("pending context retained");
    assert_eq!(retained.submitted_poi_list_keys, [] as [FixedBytes<32>; 0]);
    assert_eq!(
        handle.observation().ppoi_workflow_status(),
        &workflow_before
    );

    let applied = apply_owned_poi_private_delta_on_actor(
        &handle,
        &cancel,
        0,
        store.as_ref(),
        &cache_store,
        &cfg,
        submission_delta(),
    )
    .await
    .expect("retry submission after transient projection failure");

    assert_eq!(
        applied,
        PoiPrivateApplyOutcome::Applied {
            utxo_changed: false,
        }
    );
    assert_eq!(cache_store.state().meta_calls, commit_calls_before + 1);
    assert_eq!(
        handle.observation().ppoi_workflow_status(),
        &WalletPpoiWorkflowStatus {
            awaiting_validation: 1,
            ..WalletPpoiWorkflowStatus::default()
        }
    );

    drop(cache_store);
    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn successful_submission_intent_preserves_newer_unrelated_list_status() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-submission-unrelated-list-refresh");
    let list_key = FixedBytes::from([0x75; 32]);
    let unrelated_list_key = FixedBytes::from([0x76; 32]);
    let mut wallet_utxo = test_wallet_utxo(75);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    let expected_output = ExpectedWalletOutput::new(&wallet_utxo);
    let pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    let expected_context_fingerprint =
        pending_output_poi_context_fingerprint(&pending).expect("pending context fingerprint");
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let mut handle = test_wallet_handle(vec![wallet_utxo]);
    handle.cache_key = cfg.cache_key.clone();
    handle.utxos.write().await[0]
        .utxo
        .poi
        .statuses
        .insert(unrelated_list_key, PoiStatus::ShieldBlocked);
    let cancel = CancellationToken::new();

    let outcome = apply_owned_poi_private_delta_on_actor(
        &handle,
        &cancel,
        0,
        &store,
        &store,
        &cfg,
        OwnedPoiPrivateDelta::PendingSubmission(PendingSubmissionDelta {
            subject: PendingOutputPoiSubject::Owned(expected_output),
            expected_context_fingerprint,
            expected_recovery: ExpectedRecordState::Absent,
            active_list_keys: vec![list_key, unrelated_list_key],
            list_keys: vec![list_key],
            predicate: PendingOutputPoiSubmissionPredicate::Missing,
            merge_submitted_list_keys: true,
            action: OutputPoiRecoveryAction::Submitted {
                retry_after: PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER,
            },
            now: 10,
        }),
    )
    .await
    .expect("apply successful submission intent");

    assert!(matches!(
        outcome,
        PoiPrivateApplyOutcome::Applied {
            utxo_changed: false
        }
    ));
    let current = handle.utxos.read().await;
    assert_eq!(
        current[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Missing)
    );
    assert_eq!(
        current[0].utxo.poi.statuses.get(&unrelated_list_key),
        Some(&PoiStatus::ShieldBlocked)
    );
    drop(current);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
