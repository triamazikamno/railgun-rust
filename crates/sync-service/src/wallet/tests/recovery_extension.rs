use super::*;

#[tokio::test]
async fn output_recovery_mixed_statuses_request_and_persist_only_recoverable_lists() {
    for (case, unrelated_status) in [PoiStatus::Valid, PoiStatus::ShieldBlocked]
        .into_iter()
        .enumerate()
    {
        let root_dir = temp_db_root();
        let store = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        let mut cfg = wallet_config(U256::ZERO);
        cfg.cache_key = test_cache_key(format!("wallet-mixed-recovery-{case}"));
        let recoverable_list_key = FixedBytes::from([0x61; 32]);
        let unrelated_list_key = FixedBytes::from([0x62; 32]);
        let active_list_keys = [recoverable_list_key, unrelated_list_key];
        let mut candidate = test_wallet_utxo(80 + case as u64);
        candidate
            .utxo
            .poi
            .statuses
            .insert(recoverable_list_key, PoiStatus::Missing);
        candidate
            .utxo
            .poi
            .statuses
            .insert(unrelated_list_key, unrelated_status);
        let recoverable_list_keys =
            recoverable_output_poi_list_keys(&candidate.utxo.poi, &active_list_keys);
        assert_eq!(recoverable_list_keys, vec![recoverable_list_key]);

        let mut handle = test_wallet_handle(vec![candidate.clone()]);
        handle.cache_key = cfg.cache_key.clone();
        let cancel = CancellationToken::new();

        let pending = matching_pending_output_record(&cfg, &candidate, recoverable_list_key);
        let mut unrelated_context = external_pending_output_record(
            &cfg,
            0xb0 + case as u8,
            unrelated_list_key,
            PendingOutputPoiRole::BroadcasterFee,
        );
        unrelated_context.submitted_poi_list_keys = vec![unrelated_list_key];
        store
            .put_pending_output_poi_context(&unrelated_context)
            .expect("store unrelated pending context");
        let outcome = apply_owned_poi_private_delta_on_actor(
            &handle,
            &cancel,
            0,
            &store,
            &store,
            &cfg,
            OwnedPoiPrivateDelta::OutputRecovery(OutputRecoveryDelta {
                replay_fence: None,
                expected_output: ExpectedWalletOutput::new(&candidate),
                active_list_keys: active_list_keys.to_vec(),
                target_list_keys: recoverable_list_keys.clone(),
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
        .expect("persist mixed-status recovery intent");
        assert!(matches!(
            outcome,
            PoiPrivateApplyOutcome::Applied {
                utxo_changed: false
            }
        ));
        assert_eq!(
            handle.observation().ppoi_workflow_status(),
            &WalletPpoiWorkflowStatus {
                awaiting_submission: 1,
                awaiting_validation: 1,
                ..WalletPpoiWorkflowStatus::default()
            },
            "target-list recovery must retain unrelated active-list workflow"
        );
        let persisted = store
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &candidate.utxo.poi.commitment,
            )
            .expect("load pending context")
            .expect("pending context present");
        assert_eq!(persisted.required_poi_list_keys, vec![recoverable_list_key]);
        assert_eq!(
            persisted
                .pre_transaction_pois_per_txid_leaf_per_list
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            vec![recoverable_list_key]
        );
        assert_eq!(
            store
                .get_output_poi_recovery(
                    cfg.chain.chain_id,
                    &cfg.cache_key,
                    &candidate.utxo.poi.commitment,
                )
                .expect("load recovery")
                .expect("recovery present")
                .source_tx_hash,
            candidate.utxo.source.tx_hash
        );

        drop(store);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }
}

#[tokio::test]
async fn ordinary_recovery_reopens_valid_output_for_new_active_missing_list() {
    assert_valid_output_recovery_recovers_new_active_list(false).await;
}

#[tokio::test]
async fn forced_recovery_reopens_valid_output_for_new_active_missing_list() {
    assert_valid_output_recovery_recovers_new_active_list(true).await;
}

#[tokio::test]
async fn output_recovery_extends_newly_missing_list_and_submits_only_it() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-incremental-recovery");
    let list_a = FixedBytes::from([0x81; 32]);
    let list_b = FixedBytes::from([0x82; 32]);
    let active_list_keys = [list_a, list_b];
    let mut wallet_utxo = test_wallet_utxo(81);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_a, PoiStatus::ProofSubmitted);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_b, PoiStatus::Valid);

    let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, list_a);
    pending.submitted_poi_list_keys = vec![list_a];
    let original_observation = pending.observation.clone();
    let original_created_at = pending.created_at;
    let original_source_operation_id = pending.source_operation_id.clone();
    let txid_leaf = *pending
        .pre_transaction_pois_per_txid_leaf_per_list
        .get(&list_a)
        .and_then(|per_leaf| per_leaf.keys().next())
        .expect("list A proof leaf");
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");

    let mut recovery = output_poi_recovery_record(
        cfg.chain.chain_id,
        &cfg.cache_key,
        wallet_utxo.utxo.poi.commitment,
        OutputPoiRecoveryStatus::Submitted,
        Some(u64::MAX),
    );
    recovery.source_tx_hash = wallet_utxo.utxo.source.tx_hash;
    recovery.tx_input = Some(vec![0xde, 0xad]);
    recovery.updated_at = 7;
    recovery.last_detection_at = Some(3);
    recovery.last_submission_at = Some(6);
    recovery.attempt_count = 4;
    store
        .put_output_poi_recovery(&recovery)
        .expect("store submitted recovery");

    let mut handle = test_wallet_handle(vec![wallet_utxo]);
    handle.cache_key = cfg.cache_key.clone();
    handle.utxos.write().await[0]
        .utxo
        .poi
        .statuses
        .insert(list_b, PoiStatus::Missing);
    let current_output = handle.utxos.read().await[0].clone();
    let recoverable_list_keys =
        recoverable_output_poi_list_keys(&current_output.utxo.poi, &active_list_keys);
    assert_eq!(recoverable_list_keys, vec![list_a, list_b]);
    let new_list_keys = newly_recoverable_output_poi_list_keys(&pending, &recoverable_list_keys);
    assert_eq!(new_list_keys, vec![list_b]);
    let obsolete = previous_key_pending_context(&pending);
    assert_eq!(
        matching_pending_output_poi_context_disposition(&obsolete, &[list_a], false),
        MatchingPendingOutputPoiContextDisposition::Regenerate
    );
    let rebuilt_extension = extend_pending_output_poi_context(
        &obsolete,
        &new_list_keys,
        BTreeMap::from([(
            list_b,
            BTreeMap::from([(txid_leaf, sample_pre_tx_poi(0x20))]),
        )]),
    );
    assert!(
        !rebuilt_extension
            .pre_transaction_pois_per_txid_leaf_per_list
            .contains_key(&list_a)
    );
    assert_eq!(
        rebuilt_extension.submitted_poi_list_keys,
        [] as [FixedBytes<32>; 0]
    );
    let extended = extend_pending_output_poi_context(
        &pending,
        &new_list_keys,
        BTreeMap::from([(
            list_b,
            BTreeMap::from([(txid_leaf, sample_pre_tx_poi(0x20))]),
        )]),
    );
    let expected_context_fingerprint =
        pending_output_poi_context_fingerprint(&pending).expect("pending context fingerprint");
    let expected_recovery =
        super::super::expected_recovery_state(Some(&recovery)).expect("recovery fingerprint");
    let cancel = CancellationToken::new();
    let extension_delta = |expected_corpus: Option<ExpectedPoiCorpusRevision>| {
        OwnedPoiPrivateDelta::OutputRecovery(OutputRecoveryDelta {
            replay_fence: None,
            expected_output: ExpectedWalletOutput::new(&current_output),
            active_list_keys: active_list_keys.to_vec(),
            target_list_keys: new_list_keys.clone(),
            required_poi_status: ExpectedPoiStatus::Recoverable,
            pending_update: Box::new(Some((
                ExpectedRecordState::Present(expected_context_fingerprint.clone()),
                extended.clone(),
            ))),
            expected_recovery: expected_recovery.clone(),
            action: OutputPoiRecoveryAction::ExtendContext,
            now: 10,
            expected_corpus,
        })
    };

    let corpus_caches = WalletLocalPoiCaches::new();
    let corpus = PublicPoiCorpusHandle::new_for_test(corpus_caches.clone());
    let proof_revision = ExpectedPoiCorpusRevision {
        corpus: corpus.clone(),
        revision: *corpus.committed_revision_rx().borrow(),
    };
    {
        let _write_fence = corpus_caches.revision_write_fence().await;
        corpus_caches.publish_committed_revision(false);
    }
    assert_eq!(
        apply_owned_poi_private_delta_on_actor(
            &handle,
            &cancel,
            0,
            store.as_ref(),
            store.as_ref(),
            &cfg,
            extension_delta(Some(proof_revision)),
        )
        .await
        .expect("reject extension proofs from an older corpus revision"),
        PoiPrivateApplyOutcome::SkippedStaleCorpusRevision
    );
    let unchanged_context = store
        .get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &pending.output_commitment,
        )
        .expect("load context after stale proof")
        .expect("context present after stale proof");
    assert_eq!(
        pending_output_poi_context_fingerprint(&unchanged_context),
        Some(expected_context_fingerprint.clone())
    );
    let unchanged_recovery = store
        .get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &pending.output_commitment,
        )
        .expect("load recovery after stale proof");
    assert_eq!(
        super::super::expected_recovery_state(unchanged_recovery.as_ref()),
        Some(expected_recovery.clone())
    );

    let extension_outcome = apply_owned_poi_private_delta_on_actor(
        &handle,
        &cancel,
        0,
        store.as_ref(),
        store.as_ref(),
        &cfg,
        extension_delta(None),
    )
    .await
    .expect("apply incremental recovery extension");
    assert!(matches!(
        extension_outcome,
        PoiPrivateApplyOutcome::Applied {
            utxo_changed: false
        }
    ));

    let extended = store
        .get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &pending.output_commitment,
        )
        .expect("load extended context")
        .expect("extended context present");
    assert_eq!(extended.required_poi_list_keys, vec![list_a, list_b]);
    assert_eq!(extended.submitted_poi_list_keys, vec![list_a]);
    assert_eq!(extended.observation, original_observation);
    assert_eq!(extended.created_at, original_created_at);
    assert_eq!(extended.source_operation_id, original_source_operation_id);
    assert_eq!(extended.terminal_error, None);
    assert_eq!(
        extended
            .pre_transaction_pois_per_txid_leaf_per_list
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        vec![list_a, list_b]
    );
    let preserved_recovery = store
        .get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &pending.output_commitment,
        )
        .expect("load preserved recovery")
        .expect("recovery present");
    assert_eq!(
        preserved_recovery.status,
        OutputPoiRecoveryStatus::Submitted
    );
    assert_eq!(preserved_recovery.tx_input, Some(vec![0xde, 0xad]));
    assert_eq!(preserved_recovery.updated_at, 7);
    assert_eq!(preserved_recovery.last_detection_at, Some(3));
    assert_eq!(preserved_recovery.last_submission_at, Some(6));
    assert_eq!(preserved_recovery.next_retry_at, Some(u64::MAX));
    assert_eq!(preserved_recovery.attempt_count, 4);

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
    assert_eq!(submitter.list_key_calls(), vec![vec![list_b]]);
    let submitted_context = store
        .get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &pending.output_commitment,
        )
        .expect("load submitted context")
        .expect("submitted context present");
    assert_eq!(
        submitted_context.submitted_poi_list_keys,
        vec![list_a, list_b]
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn output_recovery_extension_skips_concurrent_context_change() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-incremental-recovery-race");
    let list_a = FixedBytes::from([0x83; 32]);
    let list_b = FixedBytes::from([0x84; 32]);
    let mut wallet_utxo = test_wallet_utxo(83);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_a, PoiStatus::ProofSubmitted);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_b, PoiStatus::Missing);
    let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, list_a);
    pending.submitted_poi_list_keys = vec![list_a];
    let expected_context_fingerprint =
        pending_output_poi_context_fingerprint(&pending).expect("pending context fingerprint");
    let txid_leaf = *pending
        .pre_transaction_pois_per_txid_leaf_per_list
        .get(&list_a)
        .and_then(|per_leaf| per_leaf.keys().next())
        .expect("list A proof leaf");
    let extended = extend_pending_output_poi_context(
        &pending,
        &[list_b],
        BTreeMap::from([(
            list_b,
            BTreeMap::from([(txid_leaf, sample_pre_tx_poi(0x21))]),
        )]),
    );
    let mut changed_pending = pending.clone();
    changed_pending.source_operation_id = Some("concurrent-context".to_string());
    store
        .put_pending_output_poi_context(&changed_pending)
        .expect("store concurrent context");
    let mut recovery = output_poi_recovery_record(
        cfg.chain.chain_id,
        &cfg.cache_key,
        wallet_utxo.utxo.poi.commitment,
        OutputPoiRecoveryStatus::Submitted,
        Some(u64::MAX),
    );
    recovery.source_tx_hash = wallet_utxo.utxo.source.tx_hash;
    store
        .put_output_poi_recovery(&recovery)
        .expect("store recovery");
    let expected_recovery =
        super::super::expected_recovery_state(Some(&recovery)).expect("recovery fingerprint");
    let mut handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    handle.cache_key = cfg.cache_key.clone();
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
            expected_output: ExpectedWalletOutput::new(&wallet_utxo),
            active_list_keys: vec![list_b],
            target_list_keys: vec![list_b],
            required_poi_status: ExpectedPoiStatus::Recoverable,
            pending_update: Box::new(Some((
                ExpectedRecordState::Present(expected_context_fingerprint),
                extended,
            ))),
            expected_recovery,
            action: OutputPoiRecoveryAction::ExtendContext,
            now: 10,
            expected_corpus: None,
        }),
    )
    .await
    .expect("apply stale recovery extension");
    assert_eq!(outcome, PoiPrivateApplyOutcome::Skipped);
    let current = store
        .get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &pending.output_commitment,
        )
        .expect("load current context")
        .expect("current context present");
    assert_eq!(
        current.source_operation_id.as_deref(),
        Some("concurrent-context")
    );
    assert_eq!(current.required_poi_list_keys, vec![list_a]);
    assert!(
        !current
            .pre_transaction_pois_per_txid_leaf_per_list
            .contains_key(&list_b)
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn force_regenerates_matching_terminal_context_for_same_list() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-terminal-force-regeneration");
    let list_key = FixedBytes::from([0x87; 32]);
    let mut wallet_utxo = test_wallet_utxo(87);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    let mut terminal = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    terminal.submitted_poi_list_keys = vec![list_key];
    terminal.terminal_error = Some("old terminal failure".to_string());
    assert_eq!(
        matching_pending_output_poi_context_disposition(&terminal, &[list_key], false),
        MatchingPendingOutputPoiContextDisposition::Skip
    );
    assert_eq!(
        matching_pending_output_poi_context_disposition(&terminal, &[list_key], true),
        MatchingPendingOutputPoiContextDisposition::Regenerate
    );
    store
        .put_pending_output_poi_context(&terminal)
        .expect("store terminal context");

    let mut recovery = output_poi_recovery_record(
        cfg.chain.chain_id,
        &cfg.cache_key,
        wallet_utxo.utxo.poi.commitment,
        OutputPoiRecoveryStatus::SubmitFailed,
        Some(u64::MAX),
    );
    recovery.source_tx_hash = wallet_utxo.utxo.source.tx_hash;
    store
        .put_output_poi_recovery(&recovery)
        .expect("store failed recovery");
    let expected_context_fingerprint =
        pending_output_poi_context_fingerprint(&terminal).expect("terminal context fingerprint");
    let expected_recovery =
        super::super::expected_recovery_state(Some(&recovery)).expect("recovery fingerprint");

    let mut regenerated = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    let txid_leaf = *regenerated
        .pre_transaction_pois_per_txid_leaf_per_list
        .get(&list_key)
        .and_then(|per_leaf| per_leaf.keys().next())
        .expect("regenerated proof leaf");
    regenerated.pre_transaction_pois_per_txid_leaf_per_list = BTreeMap::from([(
        list_key,
        BTreeMap::from([(txid_leaf, sample_pre_tx_poi(0x30))]),
    )]);
    regenerated.output_role = PendingOutputPoiRole::Change;
    regenerated.created_at = 999;
    regenerated.source_operation_id = Some("forced-regeneration".to_string());
    assert_eq!(
        regenerated.submitted_poi_list_keys,
        [] as [FixedBytes<32>; 0]
    );
    assert!(regenerated.terminal_error.is_none());

    let mut handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    handle.cache_key = cfg.cache_key.clone();
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
            expected_output: ExpectedWalletOutput::new(&wallet_utxo),
            active_list_keys: vec![list_key],
            target_list_keys: vec![list_key],
            required_poi_status: ExpectedPoiStatus::Recoverable,
            pending_update: Box::new(Some((
                ExpectedRecordState::Present(expected_context_fingerprint),
                regenerated.clone(),
            ))),
            expected_recovery,
            action: OutputPoiRecoveryAction::Detected {
                status: OutputPoiRecoveryStatus::Recoverable,
                retry_after: None,
                last_error: None,
                increment_attempts: false,
            },
            now: 999,
            expected_corpus: None,
        }),
    )
    .await
    .expect("apply forced terminal regeneration");
    assert!(matches!(outcome, PoiPrivateApplyOutcome::Applied { .. }));

    let current = store
        .get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &wallet_utxo.utxo.poi.commitment,
        )
        .expect("load regenerated context")
        .expect("regenerated context present");
    assert_eq!(
        pending_output_poi_context_fingerprint(&current),
        pending_output_poi_context_fingerprint(&regenerated)
    );
    assert!(current.terminal_error.is_none());
    assert_eq!(current.submitted_poi_list_keys, [] as [FixedBytes<32>; 0]);
    assert!(
        super::super::saved_poi_compatibility::saved_pending_context_is_compatible(
            &current,
            &[list_key]
        )
    );
    assert_eq!(
        store
            .get_output_poi_recovery(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &wallet_utxo.utxo.poi.commitment,
            )
            .expect("load regenerated recovery")
            .expect("regenerated recovery present")
            .status,
        OutputPoiRecoveryStatus::Recoverable
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn force_terminal_regeneration_skips_concurrent_context_replacement() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-terminal-force-race");
    let list_key = FixedBytes::from([0x88; 32]);
    let mut wallet_utxo = test_wallet_utxo(88);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    let mut terminal = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    terminal.submitted_poi_list_keys = vec![list_key];
    terminal.terminal_error = Some("old terminal failure".to_string());
    store
        .put_pending_output_poi_context(&terminal)
        .expect("store terminal context");
    let expected_context_fingerprint =
        pending_output_poi_context_fingerprint(&terminal).expect("terminal context fingerprint");

    let mut recovery = output_poi_recovery_record(
        cfg.chain.chain_id,
        &cfg.cache_key,
        wallet_utxo.utxo.poi.commitment,
        OutputPoiRecoveryStatus::SubmitFailed,
        Some(u64::MAX),
    );
    recovery.source_tx_hash = wallet_utxo.utxo.source.tx_hash;
    store
        .put_output_poi_recovery(&recovery)
        .expect("store failed recovery");
    let expected_recovery =
        super::super::expected_recovery_state(Some(&recovery)).expect("recovery fingerprint");

    let mut regenerated = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    regenerated.output_role = PendingOutputPoiRole::Change;
    regenerated.source_operation_id = Some("stale-regeneration".to_string());
    let mut concurrent = terminal.clone();
    concurrent.source_operation_id = Some("concurrent-terminal-context".to_string());
    concurrent.terminal_error = Some("newer terminal failure".to_string());
    store
        .put_pending_output_poi_context(&concurrent)
        .expect("store concurrent terminal context");

    let mut handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    handle.cache_key = cfg.cache_key.clone();
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
            expected_output: ExpectedWalletOutput::new(&wallet_utxo),
            active_list_keys: vec![list_key],
            target_list_keys: vec![list_key],
            required_poi_status: ExpectedPoiStatus::Recoverable,
            pending_update: Box::new(Some((
                ExpectedRecordState::Present(expected_context_fingerprint),
                regenerated,
            ))),
            expected_recovery,
            action: OutputPoiRecoveryAction::Detected {
                status: OutputPoiRecoveryStatus::Recoverable,
                retry_after: None,
                last_error: None,
                increment_attempts: false,
            },
            now: 999,
            expected_corpus: None,
        }),
    )
    .await
    .expect("apply stale forced terminal regeneration");
    assert_eq!(outcome, PoiPrivateApplyOutcome::Skipped);

    let current = store
        .get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &wallet_utxo.utxo.poi.commitment,
        )
        .expect("load concurrent context")
        .expect("concurrent context present");
    assert_eq!(
        pending_output_poi_context_fingerprint(&current),
        pending_output_poi_context_fingerprint(&concurrent)
    );
    assert_eq!(
        current.source_operation_id.as_deref(),
        Some("concurrent-terminal-context")
    );
    assert_eq!(
        current.terminal_error.as_deref(),
        Some("newer terminal failure")
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

async fn assert_valid_output_recovery_recovers_new_active_list(force_retry: bool) {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key(format!("wallet-valid-new-list-{force_retry}"));
    let list_a = FixedBytes::from([0x85; 32]);
    let list_b = FixedBytes::from([0x86; 32]);
    let active_list_keys = [list_a, list_b];
    let mut wallet_utxo = test_wallet_utxo(if force_retry { 86 } else { 85 });
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_a, PoiStatus::Valid);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_b, PoiStatus::Missing);

    let mut recovery = output_poi_recovery_record(
        cfg.chain.chain_id,
        &cfg.cache_key,
        wallet_utxo.utxo.poi.commitment,
        OutputPoiRecoveryStatus::Valid,
        None,
    );
    recovery.source_tx_hash = wallet_utxo.utxo.source.tx_hash;
    store
        .put_output_poi_recovery(&recovery)
        .expect("store valid recovery");
    assert!(
        store
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &wallet_utxo.utxo.poi.commitment,
            )
            .expect("load pending context")
            .is_none()
    );

    let recoverable_list_keys =
        recoverable_output_poi_list_keys(&wallet_utxo.utxo.poi, &active_list_keys);
    assert_eq!(recoverable_list_keys, vec![list_b]);
    assert!(!recovery.retry_allowed(10, force_retry));
    assert!(!output_poi_recovery_retry_allowed_for_lists(
        &recovery,
        10,
        force_retry,
        &[],
    ));
    assert!(output_poi_recovery_retry_allowed_for_lists(
        &recovery,
        10,
        force_retry,
        &recoverable_list_keys,
    ));

    let pending = matching_pending_output_record(&cfg, &wallet_utxo, list_b);
    let expected_recovery =
        super::super::expected_recovery_state(Some(&recovery)).expect("recovery fingerprint");
    let mut handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    handle.cache_key = cfg.cache_key.clone();
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
            expected_output: ExpectedWalletOutput::new(&wallet_utxo),
            active_list_keys: active_list_keys.to_vec(),
            target_list_keys: recoverable_list_keys,
            required_poi_status: ExpectedPoiStatus::Recoverable,
            pending_update: Box::new(Some((ExpectedRecordState::Absent, pending.clone()))),
            expected_recovery,
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
    .expect("apply recovery for newly active list");
    assert!(matches!(
        outcome,
        PoiPrivateApplyOutcome::Applied {
            utxo_changed: false
        }
    ));

    let recovered_context = store
        .get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &wallet_utxo.utxo.poi.commitment,
        )
        .expect("load recovered context")
        .expect("recovered context present");
    assert_eq!(recovered_context.list_keys(), vec![list_b]);
    assert!(
        !recovered_context
            .pre_transaction_pois_per_txid_leaf_per_list
            .contains_key(&list_a)
    );
    assert_eq!(
        store
            .get_output_poi_recovery(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &wallet_utxo.utxo.poi.commitment,
            )
            .expect("load recovered state")
            .expect("recovered state present")
            .status,
        OutputPoiRecoveryStatus::Recoverable
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
