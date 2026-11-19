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
        [] as [crate::wallet::pending_output_poi::PendingOutputPoiTentativeAttemptKey; 0]
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
        [] as [crate::wallet::pending_output_poi::PendingOutputPoiTentativeAttemptKey; 0]
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
        [] as [crate::wallet::pending_output_poi::PendingOutputPoiTentativeAttemptKey; 0]
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
