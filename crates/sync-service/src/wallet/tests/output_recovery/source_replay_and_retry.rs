use super::*;

#[tokio::test]
async fn owned_output_recovery_replays_source_rows_without_persisting_sender_state() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let mut group = saved_poi_migration_tests::migration_group(
        "ppoi_3x3_external_previous.json",
        "owned-output-source-replay",
    );
    let external = group.outputs[0].clone();
    let mut change = WalletUtxo::new(Utxo::new(
        Note::new_change(
            group.cfg.scan_keys.master_public_key,
            group.input.utxo.token_address(),
            U256::from(10),
            [0x73; 16],
        ),
        external.tree,
        external.position + 1,
        external.source.clone(),
        UtxoCommitmentKind::Transact,
    ));
    change
        .utxo
        .poi
        .statuses
        .insert(group.list_key, PoiStatus::Missing);
    group.outputs.push(change.utxo.clone());
    let wallet_utxos = vec![group.input.clone(), change.clone()];
    let mut forest = MerkleForest::new();
    forest
        .insert_leaf(MerkleTreeUpdate {
            tree_number: group.input.utxo.tree,
            tree_position: group.input.utxo.position,
            hash: group.input.utxo.note.commitment(),
        })
        .expect("retain spent input leaf");
    let merkle_root = forest
        .prove_with_leaf_count(group.input.utxo.tree, group.input.utxo.position, 1)
        .expect("spent input proof")
        .root;
    let plane = ChainPublicDataPlane::new(Arc::clone(&store), Arc::new(AtomicU64::new(0)));
    let _public_fence = saved_poi_migration_tests::seed_migration_public_rows(
        &plane,
        &group,
        "ppoi_3x3_external_previous.json",
        merkle_root,
        false,
    )
    .await;
    let mut handle = test_wallet_handle(wallet_utxos.clone());
    handle.cache_key = group.cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let private_poi = WalletPrivatePoiClients::for_submit(
        authority.remote_authority(),
        Arc::new(RecordingPendingOutputPoiSubmitter::default()),
    );
    let runtime = test_artifact_poi_runtime();
    let active_lists = [group.list_key];
    let request = OutputPoiRecoveryRequest {
        authority: &authority,
        db: store.as_ref(),
        cache_store: store.as_ref(),
        cfg: &group.cfg,
        public_data_plane: &plane,
        http_client: None,
        indexed_artifact_source: None,
        forest: Arc::new(forest),
        poi_client: runtime.public_client(),
        private_poi: &private_poi,
        poi_runtime: &runtime,
        active_list_keys: &active_lists,
        wallet_utxos: &wallet_utxos,
        force_retry: true,
    };
    let wallet_nullifiers = WalletNullifierIndex::new(&wallet_utxos, &group.cfg.scan_keys);
    let build = || {
        build_output_poi_recovery_chunk_from_public_cache(PublicTxidRecoveryBuildRequest {
            request: &request,
            candidate: &change,
            source_tx_hash: change.utxo.source.tx_hash,
            output_commitment: change.utxo.poi.commitment,
            wallet_nullifiers: &wallet_nullifiers,
            required_poi_list_keys: &active_lists,
            spending_public_key: group.cfg.spending_public_key.expect("synthetic sender key"),
            candidate_started: Instant::now(),
        })
    };
    let unavailable = build()
        .await
        .expect_err("missing source block can be retried");
    assert_eq!(unavailable.status, OutputPoiRecoveryStatus::TxFetchFailed);
    assert!(unavailable.retry_after.is_some());
    saved_poi_migration_tests::seed_migration_source_block(&plane, &group, 43).await;
    let chunk = build()
        .await
        .expect("recover external sibling from source ciphertext");
    assert_eq!(chunk.chunk.outputs.len(), 2);
    assert_eq!(
        chunk.chunk.outputs[0].commitment(),
        external.note.commitment()
    );
    assert_eq!(
        chunk.chunk.outputs[1].commitment(),
        change.utxo.note.commitment()
    );
    assert_eq!(
        chunk.chunk.inputs[0].utxo.poi.commitment,
        group.input.utxo.poi.commitment
    );
    assert!(
        store
            .list_sender_transaction_candidates(group.cfg.chain.chain_id, &group.cfg.cache_key,)
            .expect("sender state remains absent")
            .is_empty()
    );
    assert!(
        store
            .list_pending_output_poi_contexts(group.cfg.chain.chain_id, &group.cfg.cache_key,)
            .expect("builder creates no pending records")
            .is_empty()
    );
    assert!(
        store
            .get_output_poi_recovery(
                group.cfg.chain.chain_id,
                &group.cfg.cache_key,
                &change.utxo.poi.commitment,
            )
            .expect("builder creates no recovery records")
            .is_none()
    );

    let before = handle
        .utxos
        .read()
        .await
        .iter()
        .map(|utxo| {
            railgun_wallet::wallet_cache::serialize_wallet_utxo(utxo).expect("wallet snapshot")
        })
        .collect::<Vec<_>>();
    let replay_fence = chunk
        .replay_fence
        .expect("carry source epoch to actor commit");
    plane
        .reset_public_cache()
        .await
        .expect("invalidate replay evidence");
    let recovery_delta = |replay_fence| {
        OwnedPoiPrivateDelta::OutputRecovery(OutputRecoveryDelta {
            replay_fence,
            expected_output: ExpectedWalletOutput::new(&change),
            active_list_keys: active_lists.to_vec(),
            target_list_keys: active_lists.to_vec(),
            required_poi_status: ExpectedPoiStatus::Recoverable,
            pending_update: Box::new(None),
            expected_recovery: ExpectedRecordState::Absent,
            action: OutputPoiRecoveryAction::Detected {
                status: OutputPoiRecoveryStatus::Recoverable,
                retry_after: None,
                last_error: None,
                increment_attempts: false,
            },
            now: 1,
            expected_corpus: None,
        })
    };
    assert_eq!(
        apply_owned_poi_private_delta_on_actor(
            &handle,
            &cancel,
            0,
            store.as_ref(),
            store.as_ref(),
            &group.cfg,
            recovery_delta(Some(replay_fence)),
        )
        .await
        .expect("reject stale source epoch"),
        PoiPrivateApplyOutcome::Skipped
    );
    assert!(
        store
            .get_output_poi_recovery(
                group.cfg.chain.chain_id,
                &group.cfg.cache_key,
                &change.utxo.poi.commitment,
            )
            .expect("stale replay makes no durable writes")
            .is_none()
    );
    assert!(matches!(
        apply_owned_poi_private_delta_on_actor(
            &handle,
            &cancel,
            0,
            store.as_ref(),
            store.as_ref(),
            &group.cfg,
            recovery_delta(None),
        )
        .await
        .expect("same predecessor remains admissible without stale evidence"),
        PoiPrivateApplyOutcome::Applied {
            utxo_changed: false
        }
    ));
    let after = handle
        .utxos
        .read()
        .await
        .iter()
        .map(|utxo| {
            railgun_wallet::wallet_cache::serialize_wallet_utxo(utxo).expect("wallet snapshot")
        })
        .collect::<Vec<_>>();
    assert_eq!(after, before);
    drop(plane);
    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn stale_cached_output_recovery_source_stops_before_transport() {
    assert_stale_output_recovery_source_stops_before_transport(true).await;
}

#[tokio::test]
async fn stale_uncached_output_recovery_source_stops_before_transport() {
    assert_stale_output_recovery_source_stops_before_transport(false).await;
}

#[test]
fn output_poi_recovery_retry_skips_permanent_statuses() {
    let due = output_poi_recovery_record(
        1,
        "wallet-1",
        FixedBytes::from([0x80; 32]),
        OutputPoiRecoveryStatus::Submitted,
        Some(10),
    );
    assert!(due.retry_allowed(11, false));

    let not_self = output_poi_recovery_record(
        1,
        "wallet-1",
        FixedBytes::from([0x81; 32]),
        OutputPoiRecoveryStatus::NotSelfOriginated,
        Some(0),
    );
    assert!(!not_self.retry_allowed(11, false));

    let missing_inputs = output_poi_recovery_record(
        1,
        "wallet-1",
        FixedBytes::from([0x82; 32]),
        OutputPoiRecoveryStatus::MissingWalletInputs,
        None,
    );
    assert!(!missing_inputs.retry_allowed(11, false));

    let missing_outputs = output_poi_recovery_record(
        1,
        "wallet-1",
        FixedBytes::from([0x86; 32]),
        OutputPoiRecoveryStatus::MissingWalletOutputs,
        None,
    );
    assert!(!missing_outputs.retry_allowed(11, false));

    let valid = output_poi_recovery_record(
        1,
        "wallet-1",
        FixedBytes::from([0x83; 32]),
        OutputPoiRecoveryStatus::Valid,
        Some(0),
    );
    assert!(!valid.retry_allowed(11, false));
}

#[test]
fn forced_output_poi_recovery_retry_ignores_future_retry_for_retryable_status() {
    let future = output_poi_recovery_record(
        1,
        "wallet-1",
        FixedBytes::from([0x83; 32]),
        OutputPoiRecoveryStatus::ProofGenerationFailed,
        Some(999_999),
    );
    assert!(!future.retry_allowed(11, false));
    assert!(future.retry_allowed(11, true));

    let not_self = output_poi_recovery_record(
        1,
        "wallet-1",
        FixedBytes::from([0x84; 32]),
        OutputPoiRecoveryStatus::NotSelfOriginated,
        Some(0),
    );
    assert!(!not_self.retry_allowed(11, true));

    let unsupported_shape = output_poi_recovery_record(
        1,
        "wallet-1",
        FixedBytes::from([0x85; 32]),
        OutputPoiRecoveryStatus::UnsupportedShape,
        None,
    );
    assert!(!unsupported_shape.retry_allowed(11, false));
    assert!(unsupported_shape.retry_allowed(11, true));

    let missing_outputs = output_poi_recovery_record(
        1,
        "wallet-1",
        FixedBytes::from([0x86; 32]),
        OutputPoiRecoveryStatus::MissingWalletOutputs,
        None,
    );
    assert!(!missing_outputs.retry_allowed(11, false));
    assert!(missing_outputs.retry_allowed(11, true));
}

async fn assert_stale_output_recovery_source_stops_before_transport(cached_input: bool) {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let nullifying_key = uint!(9_U256);
    let mut cfg = wallet_config(nullifying_key);
    cfg.cache_key = test_cache_key(if cached_input {
        "wallet-stale-cached-recovery"
    } else {
        "wallet-stale-uncached-recovery"
    });
    let list_key = FixedBytes::from([0x21; 32]);
    let required_poi_list_keys = [list_key];
    let mut input = test_wallet_utxo(0);
    let mut candidate = test_wallet_utxo(8);
    candidate
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    input.spent = Some(candidate.utxo.source.clone());
    let wallet_utxos = vec![input, candidate.clone()];

    let mut stale_recovery = output_poi_recovery_record(
        cfg.chain.chain_id,
        &cfg.cache_key,
        candidate.utxo.poi.commitment,
        OutputPoiRecoveryStatus::Recoverable,
        None,
    );
    if cached_input {
        stale_recovery.tx_input = Some(vec![0xde, 0xad]);
    }
    assert_ne!(stale_recovery.source_tx_hash, candidate.utxo.source.tx_hash);
    store
        .put_output_poi_recovery(&stale_recovery)
        .expect("store stale recovery");

    let mut handle = test_wallet_handle(wallet_utxos.clone());
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let private_poi = WalletPrivatePoiClients::for_submit(
        authority.remote_authority(),
        Arc::new(RecordingPendingOutputPoiSubmitter::default()),
    );
    let (rpc_url, rpc_requests) =
        spawn_http_response(serde_json::json!({}).to_string().into_bytes()).await;
    let poi_client = PoiRpcClient::new(rpc_url);
    let public_data_plane =
        ChainPublicDataPlane::new(Arc::clone(&store), Arc::new(AtomicU64::new(0)));
    let poi_runtime = test_artifact_poi_runtime();
    let forest = Arc::new(MerkleForest::new());
    let wallet_nullifiers = WalletNullifierIndex::new(&wallet_utxos, &cfg.scan_keys);
    let request = OutputPoiRecoveryRequest {
        authority: &authority,
        db: store.as_ref(),
        cache_store: store.as_ref(),
        cfg: &cfg,
        public_data_plane: &public_data_plane,
        http_client: None,
        indexed_artifact_source: None,
        forest: Arc::clone(&forest),
        poi_client: &poi_client,
        private_poi: &private_poi,
        poi_runtime: &poi_runtime,
        active_list_keys: &required_poi_list_keys,
        wallet_utxos: &wallet_utxos,
        force_retry: true,
    };
    let failure =
        build_output_poi_recovery_chunk_from_public_cache(PublicTxidRecoveryBuildRequest {
            request: &request,
            candidate: &candidate,
            source_tx_hash: candidate.utxo.source.tx_hash,
            output_commitment: candidate.utxo.poi.commitment,
            wallet_nullifiers: &wallet_nullifiers,
            required_poi_list_keys: &required_poi_list_keys,
            spending_public_key: [uint!(4_U256), uint!(5_U256)],
            candidate_started: Instant::now(),
        })
        .await
        .expect_err("stale recovery source must be rejected");

    assert_eq!(failure.status, OutputPoiRecoveryStatus::TxFetchFailed);
    assert_eq!(failure.category, "tx_fetch_failed");
    assert!(
        failure
            .message
            .contains("source transaction does not match")
    );
    assert!(
        rpc_requests
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "stale recovery source must not fetch transaction calldata"
    );

    drop(public_data_plane);
    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
