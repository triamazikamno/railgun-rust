use super::*;

#[test]
fn output_poi_recovery_action_caches_tx_input_without_resetting_state() {
    let mut record = output_poi_recovery_record(
        1,
        "wallet",
        FixedBytes::from([0x44; 32]),
        OutputPoiRecoveryStatus::ProofGenerationFailed,
        Some(20),
    );
    record.attempt_count = 3;
    record.last_error = Some("previous".to_string());

    record.apply_action(
        OutputPoiRecoveryAction::CacheTxInput {
            tx_input: vec![0xde, 0xad],
        },
        10,
    );

    assert_eq!(record.tx_input, Some(vec![0xde, 0xad]));
    assert_eq!(
        record.status,
        OutputPoiRecoveryStatus::ProofGenerationFailed
    );
    assert_eq!(record.updated_at, 10);
    assert_eq!(record.last_detection_at, Some(10));
    assert_eq!(record.next_retry_at, Some(20));
    assert_eq!(record.attempt_count, 3);
    assert_eq!(record.last_error.as_deref(), Some("previous"));
}

#[test]
fn output_poi_recovery_action_records_detected_failure() {
    let mut record = output_poi_recovery_record(
        1,
        "wallet",
        FixedBytes::from([0x44; 32]),
        OutputPoiRecoveryStatus::Recoverable,
        None,
    );

    record.apply_action(
        OutputPoiRecoveryAction::Detected {
            status: OutputPoiRecoveryStatus::DecodeFailed,
            retry_after: Some(Duration::from_secs(30)),
            last_error: Some("decode failed".to_string()),
            increment_attempts: true,
        },
        10,
    );

    assert_eq!(record.status, OutputPoiRecoveryStatus::DecodeFailed);
    assert_eq!(record.updated_at, 10);
    assert_eq!(record.last_detection_at, Some(10));
    assert_eq!(record.next_retry_at, Some(40));
    assert_eq!(record.attempt_count, 1);
    assert_eq!(record.last_error.as_deref(), Some("decode failed"));
}

#[test]
fn output_poi_recovery_action_records_recovered_context() {
    let mut record = output_poi_recovery_record(
        1,
        "wallet",
        FixedBytes::from([0x44; 32]),
        OutputPoiRecoveryStatus::ProofGenerationFailed,
        Some(20),
    );
    record.attempt_count = 2;
    record.last_error = Some("old".to_string());

    record.apply_action(
        OutputPoiRecoveryAction::Detected {
            status: OutputPoiRecoveryStatus::Recoverable,
            retry_after: None,
            last_error: None,
            increment_attempts: false,
        },
        10,
    );

    assert_eq!(record.status, OutputPoiRecoveryStatus::Recoverable);
    assert_eq!(record.updated_at, 10);
    assert_eq!(record.last_detection_at, Some(10));
    assert_eq!(record.next_retry_at, None);
    assert_eq!(record.attempt_count, 2);
    assert_eq!(record.last_error, None);
}

#[test]
fn output_poi_recovery_action_records_submit_success() {
    let mut record = output_poi_recovery_record(
        1,
        "wallet",
        FixedBytes::from([0x44; 32]),
        OutputPoiRecoveryStatus::Recoverable,
        None,
    );
    record.last_error = Some("old".to_string());

    record.apply_action(
        OutputPoiRecoveryAction::Submitted {
            retry_after: Duration::from_mins(1),
        },
        10,
    );

    assert_eq!(record.status, OutputPoiRecoveryStatus::Submitted);
    assert_eq!(record.updated_at, 10);
    assert_eq!(record.last_submission_at, Some(10));
    assert_eq!(record.next_retry_at, Some(70));
    assert_eq!(record.attempt_count, 1);
    assert_eq!(record.last_error, None);
}

#[test]
fn output_poi_recovery_action_records_submit_failure() {
    let mut record = output_poi_recovery_record(
        1,
        "wallet",
        FixedBytes::from([0x44; 32]),
        OutputPoiRecoveryStatus::Recoverable,
        None,
    );

    record.apply_action(
        OutputPoiRecoveryAction::SubmitFailed {
            error: "submit failed".to_string(),
            retry_after: Duration::from_mins(1),
        },
        10,
    );

    assert_eq!(record.status, OutputPoiRecoveryStatus::SubmitFailed);
    assert_eq!(record.updated_at, 10);
    assert_eq!(record.last_submission_at, None);
    assert_eq!(record.next_retry_at, Some(70));
    assert_eq!(record.attempt_count, 1);
    assert_eq!(record.last_error.as_deref(), Some("submit failed"));
}

#[test]
fn output_poi_recovery_action_marks_valid_without_touching_history() {
    let mut record = output_poi_recovery_record(
        1,
        "wallet",
        FixedBytes::from([0x44; 32]),
        OutputPoiRecoveryStatus::Submitted,
        Some(20),
    );
    record.last_detection_at = Some(4);
    record.last_submission_at = Some(5);
    record.attempt_count = 2;
    record.last_error = Some("old".to_string());

    record.apply_action(OutputPoiRecoveryAction::Valid, 10);

    assert_eq!(record.status, OutputPoiRecoveryStatus::Valid);
    assert_eq!(record.updated_at, 10);
    assert_eq!(record.last_detection_at, Some(4));
    assert_eq!(record.last_submission_at, Some(5));
    assert_eq!(record.next_retry_at, None);
    assert_eq!(record.attempt_count, 2);
    assert_eq!(record.last_error, None);
}

#[test]
fn pending_output_submit_identity_derives_status_query_blinded_commitment() {
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x77; 32]);
    let list_key = FixedBytes::from([0x11; 32]);
    let record = pending_output_record(chain_id, output_commitment, list_key);
    let observation = local_db::PendingOutputPoiObservation {
        output_tree: 3,
        output_position: 42,
        tx_hash: source(11).tx_hash,
        block_number: 11,
        block_timestamp: 1_700_000_011,
    };

    let identity =
        pending_output_poi_submit_identity(&record, &observation).expect("submit identity");

    assert_eq!(
        identity.derived_blinded_commitment,
        UtxoPoiMetadata::blinded_commitment_for(
            record.output_commitment,
            record.output_npk,
            observation.output_tree as u32,
            observation.output_position,
        )
    );
}

#[test]
fn pending_output_submit_identity_accepts_included_txid_leaf_for_recovery() {
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x77; 32]);
    let list_key = FixedBytes::from([0x11; 32]);
    let included_txid_leaf = FixedBytes::from([0x99; 32]);
    let mut record = pending_output_record(chain_id, output_commitment, list_key);
    let dummy_txid_leaf = FixedBytes::from(
        railgun_txid_leaf_hash(record.railgun_txid, record.utxo_tree_in).to_be_bytes::<32>(),
    );
    record.txid_merkleroot_index = Some(105_572);
    record.pre_transaction_pois_per_txid_leaf_per_list = BTreeMap::from([(
        list_key,
        BTreeMap::from([(included_txid_leaf, sample_pre_tx_poi(0x10))]),
    )]);
    let observation = local_db::PendingOutputPoiObservation {
        output_tree: 3,
        output_position: 42,
        tx_hash: source(11).tx_hash,
        block_number: 11,
        block_timestamp: 1_700_000_011,
    };

    pending_output_poi_submit_identity(&record, &observation).expect("submit identity");

    assert_ne!(included_txid_leaf, dummy_txid_leaf);
}

#[test]
fn output_start_global_position_handles_nonzero_output_index_across_tree_boundary() {
    let utxo = Utxo::new(
        Note {
            token_hash: uint!(1_U256),
            value: uint!(10_U256),
            random: [0u8; 16],
            npk: uint!(2_U256),
        },
        3,
        1,
        source(17),
        UtxoCommitmentKind::Transact,
    );

    let start_global = output_start_global_position(&utxo, 2).expect("start global");

    assert_eq!(start_global / u128::from(TREE_LEAF_COUNT), 2);
    assert_eq!(start_global % u128::from(TREE_LEAF_COUNT), 65_535);
    assert_eq!(
        start_global,
        u128::from(utxo.tree) * u128::from(TREE_LEAF_COUNT) + u128::from(utxo.position) - 2
    );
}

#[tokio::test]
async fn candidate_effect_commits_spent_snapshot_and_artifact_bound_atomically() {
    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = RecordingCacheStore::new(Arc::clone(&db));
    let wallet_id = test_cache_key("cache-key");
    let spent_source = source(0x51);
    let mut input = test_wallet_utxo(7);
    input.spent = Some(spent_source.clone());
    let snapshot = vec![input.clone()];
    let candidate = sender_candidate_for_spent_input(wallet_id.clone(), &input, spent_source);
    let handle = test_wallet_handle(snapshot.clone());
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let permit = authority.acquire().await.expect("wallet authority");
    let mut persist_state = WalletPersistState::default();

    let full = persist_state
        .persist_progress_with_private_effects(
            &cache_store,
            &permit,
            WalletProgressPersist {
                cache_key: wallet_id.as_str(),
                snapshot: &snapshot,
                last_scanned: 10,
                checkpoint: WalletCheckpointMutation::Set {
                    last_scanned_block: 10,
                    last_scanned_block_hash: Some([0x10; 32]),
                },
                changed: false,
            },
            WalletProgressPrivateEffects {
                sender_transaction_candidate_updates: std::slice::from_ref(&candidate),
                ..WalletProgressPrivateEffects::default()
            },
        )
        .expect("persist candidate effects");

    assert!(full, "candidate effects require a full durable commit");
    assert_eq!(cache_store.state().store_calls, 1);
    let persisted = <DbStore as WalletCacheStore>::load_wallet_utxos(db.as_ref(), &wallet_id)
        .expect("load persisted snapshot");
    assert_eq!(persisted.len(), 1);
    assert_eq!(persisted[0].spent, input.spent);
    assert_eq!(
        <DbStore as WalletCacheStore>::get_wallet_meta(db.as_ref(), &wallet_id)
            .expect("load artifact_bound")
            .expect("artifact_bound present")
            .last_scanned_block,
        10
    );
    assert!(
        <DbStore as WalletCacheStore>::get_sender_transaction_candidate(
            db.as_ref(),
            1,
            &wallet_id,
            &candidate.semantic_id(),
        )
        .expect("load candidate")
        .is_some()
    );

    let mut replacement_source = candidate.source.clone();
    replacement_source.block_timestamp += 1;
    let mut replacement_input = input;
    replacement_input.spent = Some(replacement_source.clone());
    let replacement_snapshot = vec![replacement_input.clone()];
    let replacement =
        sender_candidate_for_spent_input(wallet_id.clone(), &replacement_input, replacement_source);
    for expected in [&replacement, &replacement] {
        persist_state
            .persist_progress_with_private_effects(
                &cache_store,
                &permit,
                WalletProgressPersist {
                    cache_key: wallet_id.as_str(),
                    snapshot: &replacement_snapshot,
                    last_scanned: 10,
                    checkpoint: WalletCheckpointMutation::Preserve,
                    changed: false,
                },
                WalletProgressPrivateEffects {
                    sender_transaction_candidate_updates: std::slice::from_ref(expected),
                    ..WalletProgressPrivateEffects::default()
                },
            )
            .expect("replace candidate evidence");
    }
    let candidates = <DbStore as WalletCacheStore>::list_sender_transaction_candidates(
        db.as_ref(),
        1,
        &wallet_id,
    )
    .expect("list replaced candidate");
    assert_eq!(candidates.len(), 1);
    assert_eq!(
        candidates[0].encode().expect("encode stored candidate"),
        replacement.encode().expect("encode replacement")
    );

    drop(permit);
    drop(cache_store);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn automatic_recovery_policy_uses_local_proofs_only_and_retains_candidate() {
    let root_dir = temp_db_root();
    let wallet_id = test_cache_key("candidate-maintenance-wallet");
    let spent_source = source(0x53);
    let mut input = test_wallet_utxo(9);
    input.spent = Some(spent_source.clone());
    let candidate = sender_candidate_for_spent_input(wallet_id.clone(), &input, spent_source);
    {
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open seed db");
        db.put_opaque_wallet_private_row(
            &candidate.namespace(),
            WalletPrivateRecordKind::SenderTransactionCandidate,
            &OpaqueWalletPrivateRow {
                row_id: candidate.row_identity(),
                payload: candidate.encode().expect("encode candidate"),
            },
        )
        .expect("persist candidate before restart");
    }

    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("reopen db"),
    );
    let cache_store = RecordingCacheStore::new(Arc::clone(&db));
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = wallet_id.clone();
    let mut handle = test_wallet_handle(vec![input.clone()]);
    handle.cache_key = wallet_id.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let rpc_url = Url::parse("http://127.0.0.1:1").expect("POI RPC URL");
    let poi_runtime = WalletPoiRuntime::from_policy(
        &GlobalPoiPolicy::PoiProxy {
            rpc_url: rpc_url.clone().into(),
        },
        None,
    );
    let poi_client = poi_runtime.public_client().clone();
    let private_poi = WalletPrivatePoiClients::for_submit(
        authority.remote_authority(),
        Arc::new(RecordingPendingOutputPoiSubmitter::default()),
    );
    let public_data_plane = ChainPublicDataPlane::new(Arc::clone(&db), Arc::new(AtomicU64::new(0)));
    let forest = Arc::new(RwLock::new(MerkleForest::new()));
    let active_list_keys = default_active_poi_list_keys();
    let resolver_forest = Arc::new(MerkleForest::new());
    let resolver_wallet_utxos = std::slice::from_ref(&input);
    // Owned-output and sender automatic recovery share this resolver; neither may use remote proofs.
    let proxy_resolver_request = OutputPoiRecoveryRequest {
        authority: &authority,
        db: db.as_ref(),
        cache_store: &cache_store,
        cfg: &cfg,
        public_data_plane: &public_data_plane,
        http_client: None,
        indexed_artifact_source: None,
        forest: Arc::clone(&resolver_forest),
        poi_client: &poi_client,
        private_poi: &private_poi,
        poi_runtime: &poi_runtime,
        active_list_keys: &active_list_keys,
        wallet_utxos: resolver_wallet_utxos,
        force_retry: false,
    };
    assert!(matches!(
        proxy_resolver_request
            .resolve_proof_source(&active_list_keys)
            .await,
        OutputPoiProofSourceResolution::Unavailable
    ));
    let fallback_runtime = test_artifact_poi_runtime_with_fallback(rpc_url);
    let fallback_poi_client = fallback_runtime.public_client().clone();
    let fallback_resolver_request = OutputPoiRecoveryRequest {
        authority: &authority,
        db: db.as_ref(),
        cache_store: &cache_store,
        cfg: &cfg,
        public_data_plane: &public_data_plane,
        http_client: None,
        indexed_artifact_source: None,
        forest: Arc::clone(&resolver_forest),
        poi_client: &fallback_poi_client,
        private_poi: &private_poi,
        poi_runtime: &fallback_runtime,
        active_list_keys: &active_list_keys,
        wallet_utxos: resolver_wallet_utxos,
        force_retry: false,
    };
    assert!(matches!(
        fallback_resolver_request
            .resolve_proof_source(&active_list_keys)
            .await,
        OutputPoiProofSourceResolution::Unavailable
    ));
    // A local resolution records its corpus revision instead of holding the corpus fence, so the
    // corpus writer is never queued behind proof preparation.
    let local_public_data_plane = test_public_data_plane_with_poi_service(&db);
    for list_key in active_list_keys.iter().copied() {
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
            .expect("seed local POI event");
        seed_data_plane_poi_cache(
            &local_public_data_plane,
            cfg.chain.chain_id,
            list_key,
            cache,
        )
        .await;
    }
    let local_runtime = test_artifact_poi_runtime();
    let local_poi_client = local_runtime.public_client().clone();
    let local_resolver_request = OutputPoiRecoveryRequest {
        authority: &authority,
        db: db.as_ref(),
        cache_store: &cache_store,
        cfg: &cfg,
        public_data_plane: &local_public_data_plane,
        http_client: None,
        indexed_artifact_source: None,
        forest: Arc::clone(&resolver_forest),
        poi_client: &local_poi_client,
        private_poi: &private_poi,
        poi_runtime: &local_runtime,
        active_list_keys: &active_list_keys,
        wallet_utxos: resolver_wallet_utxos,
        force_retry: false,
    };
    let local_resolution = local_resolver_request
        .resolve_proof_source(&active_list_keys)
        .await;
    let OutputPoiProofSourceResolution::Local {
        revision, corpus, ..
    } = &local_resolution
    else {
        panic!("a ready local corpus resolves to a local proof source");
    };
    let corpus_caches = corpus.local_caches();
    let write_fence =
        tokio::time::timeout(Duration::from_secs(1), corpus_caches.revision_write_fence())
            .await
            .expect("corpus writer acquires the fence while a local resolution is alive");
    corpus_caches.publish_committed_revision(false);
    drop(write_fence);
    assert_ne!(*corpus.committed_revision_rx().borrow(), *revision);
    drop(local_resolution);
    drop(local_public_data_plane);
    let recovered = (OutputPoiRecoveryRun {
        authority: &authority,
        db: db.as_ref(),
        cache_store: &cache_store,
        cfg: &cfg,
        public_data_plane: &public_data_plane,
        http_client: None,
        indexed_artifact_source: None,
        poi_runtime: &poi_runtime,
        forest: &forest,
        utxos: &handle.utxos,
        client: &poi_client,
        private_poi: &private_poi,
        active_list_keys: &active_list_keys,
        force_retry: false,
        unshield_attempts: &SenderUnshieldAttempts::default(),
    })
    .recover_missing()
    .await;

    assert_eq!(recovered.recovered, 0, "the bounded fixture has no prover");
    assert!(recovered.error.is_none());
    assert_eq!(recovered.candidate_report.awaiting_poi_data, 1);
    assert_eq!(recovered.candidate_report.needs_attention, 0);
    assert_eq!(cache_store.state().candidate_list_calls, 1);
    assert!(
        cache_store
            .get_sender_transaction_candidate(1, &wallet_id, &candidate.semantic_id())
            .expect("reload candidate after maintenance")
            .is_some()
    );

    let fallback = (OutputPoiRecoveryRun {
        authority: &authority,
        db: db.as_ref(),
        cache_store: &cache_store,
        cfg: &cfg,
        public_data_plane: &public_data_plane,
        http_client: None,
        indexed_artifact_source: None,
        poi_runtime: &fallback_runtime,
        forest: &forest,
        utxos: &handle.utxos,
        client: &fallback_poi_client,
        private_poi: &private_poi,
        active_list_keys: &active_list_keys,
        force_retry: false,
        unshield_attempts: &SenderUnshieldAttempts::default(),
    })
    .recover_missing()
    .await;
    assert_eq!(fallback.recovered, 0);
    assert_eq!(fallback.candidate_report.awaiting_poi_data, 1);
    assert_eq!(fallback.candidate_report.needs_attention, 0);
    assert!(
        cache_store
            .get_sender_transaction_candidate(1, &wallet_id, &candidate.semantic_id())
            .expect("reload fallback candidate")
            .is_some()
    );

    cache_store.fail_next_candidate_list();
    let failed = (OutputPoiRecoveryRun {
        authority: &authority,
        db: db.as_ref(),
        cache_store: &cache_store,
        cfg: &cfg,
        public_data_plane: &public_data_plane,
        http_client: None,
        indexed_artifact_source: None,
        poi_runtime: &poi_runtime,
        forest: &forest,
        utxos: &handle.utxos,
        client: &poi_client,
        private_poi: &private_poi,
        active_list_keys: &active_list_keys,
        force_retry: false,
        unshield_attempts: &SenderUnshieldAttempts::default(),
    })
    .recover_missing()
    .await;
    assert_eq!(failed.recovered, 0);
    assert!(matches!(
        failed.error,
        Some(PoiMaintenanceError::SenderCandidateList(_))
    ));
    assert_eq!(cache_store.state().candidate_list_calls, 3);

    drop(public_data_plane);
    drop(cache_store);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn output_poi_recovery_commit_round_trip_does_not_hold_the_corpus_fence() {
    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let list_key = FixedBytes::from([0x61; 32]);
    let spending_public_key = [uint!(4_U256), uint!(5_U256)];
    let mut cfg = wallet_config(U256::ZERO);
    cfg.scan_keys = ViewingKeyData::from_spending_public_key([7_u8; 32], spending_public_key);
    cfg.cache_key = test_cache_key("corpus-fence-cycle");
    cfg.spending_public_key = Some(spending_public_key);
    cfg.poi_recovery_prover = Some(ProverService::new_with_db(&ArtifactSource::default(), &db));

    let mut input = test_wallet_utxo(0);
    let mut output = test_wallet_utxo(8);
    output
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    input.spent = Some(output.utxo.source.clone());
    let mut forest = MerkleForest::new();
    forest
        .insert_leaf(MerkleTreeUpdate {
            tree_number: input.utxo.tree,
            tree_position: input.utxo.position,
            hash: input.utxo.note.commitment(),
        })
        .expect("insert input leaf");
    let merkle_root = forest
        .prove_with_leaf_count(input.utxo.tree, input.utxo.position, 1)
        .expect("input proof")
        .root;
    let graph_response = serde_json::json!({
        "data": {
            "transactions": [{
                "id": "0x00",
                "blockNumber": output.utxo.source.block_number.to_string(),
                "blockTimestamp": output.utxo.source.block_timestamp.to_string(),
                "transactionHash": hex::encode_prefixed(output.utxo.source.tx_hash),
                "merkleRoot": hex::encode_prefixed(FixedBytes::from(merkle_root.to_be_bytes::<32>())),
                "nullifiers": [hex::encode_prefixed(FixedBytes::from(
                    input.utxo.nullifier(cfg.scan_keys.nullifying_key).to_be_bytes::<32>()
                ))],
                "commitments": [hex::encode_prefixed(output.utxo.poi.commitment)],
                "boundParamsHash": "0x33",
                "hasUnshield": false,
                "utxoTreeIn": input.utxo.tree.to_string(),
                "utxoTreeOut": output.utxo.tree.to_string(),
                "utxoBatchStartPositionOut": output.utxo.position.to_string(),
            }]
        }
    })
    .to_string()
    .into_bytes();
    let (graph_endpoint, _graph_requests) = spawn_http_response(graph_response).await;
    cfg.quick_sync_endpoint = Some(graph_endpoint);
    let poi_mock = spawn_poi_rpc_sequence(vec![
        serde_json::json!({
            "validatedTxidIndex": 0,
            "validatedMerkleroot": null,
        }),
        serde_json::json!(true),
    ])
    .await;
    let poi_client = PoiRpcClient::new(poi_mock.url.clone());

    // The input is in the local corpus, so the proof source resolves locally and the preflight
    // passes. Its roots are never validated, so proof generation fails before proving and the
    // job commits a failure record through the actor.
    let public_data_plane = test_public_data_plane_with_poi_service(&db);
    let mut poi_cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        cfg.chain.chain_id,
        DEFAULT_TXID_VERSION,
        list_key,
    ));
    poi_cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: *input.utxo.poi.blinded_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("seed input POI event");
    seed_data_plane_poi_cache(&public_data_plane, cfg.chain.chain_id, list_key, poi_cache).await;
    let corpus_caches = public_data_plane
        .ensure_poi_corpus(PublicPoiCorpusKey::wallet_default(cfg.chain.chain_id))
        .await
        .expect("POI corpus")
        .local_caches();

    let output_commitment = output.utxo.poi.commitment;
    let wallet_utxos = vec![input, output];
    let mut handle = test_wallet_handle(wallet_utxos.clone());
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let (apply_tx, mut apply_rx) = mpsc::channel(1);
    let apply_client = WalletPrivateApplyClient::new(apply_tx);
    let authority =
        WalletPrivateMutationAuthority::new(&handle, 0, &cancel).with_apply_client(&apply_client);
    let private_poi = WalletPrivatePoiClients::for_submit(
        authority.remote_authority(),
        Arc::new(RecordingPendingOutputPoiSubmitter::default()),
    );
    let poi_runtime = test_artifact_poi_runtime();
    let active_list_keys = [list_key];

    // The actor side of the round trip: a corpus writer runs first and must not queue behind a
    // job-held corpus read guard. It publishes a new revision, which a failure record that
    // consumes no local proof commits across.
    let actor_handle = handle.clone();
    let actor_db = Arc::clone(&db);
    let actor_cancel = cancel.clone();
    let actor_cfg = cfg.clone();
    let actor = async move {
        let request = apply_rx
            .recv()
            .await
            .expect("output recovery commit request");
        let write_fence =
            tokio::time::timeout(Duration::from_secs(2), corpus_caches.revision_write_fence())
                .await
                .expect("corpus writer acquires while the job awaits the actor");
        corpus_caches.publish_committed_revision(false);
        drop(write_fence);
        let result = apply_owned_poi_private_delta_on_actor_with_active_lists(
            &actor_handle,
            &actor_cancel,
            request.reset_generation,
            actor_db.as_ref(),
            actor_db.as_ref(),
            &actor_cfg,
            &[list_key],
            request.delta,
        )
        .await;
        request.reply.send(result).expect("send actor result");
    };
    let recovery = recover_missing_output_pois(OutputPoiRecoveryRequest {
        authority: &authority,
        db: db.as_ref(),
        cache_store: db.as_ref(),
        cfg: &cfg,
        public_data_plane: &public_data_plane,
        http_client: None,
        indexed_artifact_source: None,
        forest: Arc::new(forest),
        poi_client: &poi_client,
        private_poi: &private_poi,
        poi_runtime: &poi_runtime,
        active_list_keys: &active_list_keys,
        wallet_utxos: &wallet_utxos,
        force_retry: false,
    });
    let (recovered, ()) = tokio::time::timeout(
        Duration::from_secs(10),
        Box::pin(async { tokio::join!(recovery, actor) }),
    )
    .await
    .expect("output POI recovery finishes without the maintenance watchdog");

    assert_eq!(recovered, 0);
    let record = db
        .get_output_poi_recovery(cfg.chain.chain_id, &cfg.cache_key, &output_commitment)
        .expect("load recovery record")
        .expect("failure record commits after the corpus revision changed");
    assert_eq!(
        record.status,
        OutputPoiRecoveryStatus::ProofGenerationFailed
    );
    assert!(
        record
            .last_error
            .as_deref()
            .is_some_and(|error| error.contains("root validation required")),
        "the job reached proof generation from a local resolution: {record:?}"
    );

    drop(public_data_plane);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn pending_output_and_recovery_reads_route_through_wallet_cache_store() {
    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let chain_id = 1;
    let wallet_id = test_cache_key("wallet-1");
    let output_commitment = FixedBytes::from([0x73; 32]);
    let pending = pending_output_record(chain_id, output_commitment, FixedBytes::from([0x74; 32]));
    db.put_pending_output_poi_context(&pending)
        .expect("seed pending context");
    db.put_output_poi_recovery(&output_poi_recovery_record(
        chain_id,
        wallet_id.as_str(),
        output_commitment,
        OutputPoiRecoveryStatus::Recoverable,
        None,
    ))
    .expect("seed recovery");
    let cache_store = RecordingCacheStore::new(Arc::clone(&db));
    let observation = CommitmentObservation {
        tree: 12,
        position: 34,
        commitment: U256::from_be_bytes(output_commitment.0),
        source: source(8),
    };

    let updates =
        pending_output_poi_observation_updates(&cache_store, chain_id, &wallet_id, &[observation])
            .expect("prepare observation update");
    assert_eq!(updates.len(), 1);
    assert!(
        cache_store
            .get_output_poi_recovery(chain_id, &wallet_id, &output_commitment)
            .expect("load recovery through cache store")
            .is_some()
    );
    assert_eq!(cache_store.state().pending_output_read_calls, 1);
    assert_eq!(cache_store.state().output_recovery_read_calls, 1);

    drop(cache_store);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn live_metadata_flush_waits_for_interval_or_block_threshold() {
    let now = Instant::now();
    let flush = WalletLiveMetadataFlush::new(100, now);

    assert!(!flush.should_flush(100 + WALLET_METADATA_LIVE_FLUSH_BLOCKS - 1, now));
    assert!(flush.should_flush(100 + WALLET_METADATA_LIVE_FLUSH_BLOCKS, now));
    assert!(flush.should_flush(101, now + WALLET_METADATA_LIVE_FLUSH_INTERVAL));
}

#[test]
fn live_metadata_flush_mark_persisted_resets_thresholds() {
    let now = Instant::now();
    let mut flush = WalletLiveMetadataFlush::new(100, now);

    flush.mark_persisted(125, now + WALLET_METADATA_LIVE_FLUSH_INTERVAL);

    assert!(!flush.should_flush(125, now + WALLET_METADATA_LIVE_FLUSH_INTERVAL));
    assert!(!flush.should_flush(
        125 + WALLET_METADATA_LIVE_FLUSH_BLOCKS - 1,
        now + WALLET_METADATA_LIVE_FLUSH_INTERVAL
    ));
    assert!(flush.should_flush(
        125 + WALLET_METADATA_LIVE_FLUSH_BLOCKS,
        now + WALLET_METADATA_LIVE_FLUSH_INTERVAL
    ));
}

#[tokio::test]
async fn output_poi_recovery_public_row_with_older_input_root_keeps_original_poi_inputs() {
    let spending_public_key = [uint!(4_U256), uint!(5_U256)];
    let scan_keys = ViewingKeyData::from_spending_public_key([7_u8; 32], spending_public_key);
    let mut input = test_wallet_utxo(0);
    let output = test_wallet_utxo(8);
    input.spent = Some(output.utxo.source.clone());
    // The transaction proved against the one-leaf root. Leaves 1-7 arrived before its outputs at
    // position 8, and leaves from 8 on stand in for later growth.
    let mut forest = MerkleForest::new();
    for position in 0..16 {
        forest
            .insert_leaf(MerkleTreeUpdate {
                tree_number: input.utxo.tree,
                tree_position: position,
                hash: if position == input.utxo.position {
                    input.utxo.note.commitment()
                } else {
                    U256::from(position + 12)
                },
            })
            .expect("insert input tree leaf");
    }
    let original_proof = forest
        .prove_with_leaf_count(input.utxo.tree, input.utxo.position, 1)
        .expect("original input proof");
    let forest = Arc::new(forest);
    let bound_params_hash = U256::from(0x33_u64);
    let nullifiers = vec![input.utxo.nullifier(scan_keys.nullifying_key)];
    let original_inputs = vec![InputWitness {
        utxo: input.utxo.clone(),
        merkle_proof: original_proof,
    }];
    let original_outputs = vec![output.utxo.note.clone()];
    let original_chunk = TransactionPlanChunk {
        tree_number: input.utxo.tree,
        merkle_root: original_proof.root,
        inputs: original_inputs.clone(),
        outputs: original_outputs.clone(),
        has_unshield: false,
        public_inputs: PublicInputs::from_parts(
            original_proof.root,
            bound_params_hash,
            nullifiers.clone(),
            &original_outputs,
        ),
        private_inputs: PrivateInputs::from_inputs(
            input.utxo.token_address(),
            &original_inputs,
            &original_outputs,
            &scan_keys,
            &RecoverySpendPublicKey {
                spending_public_key,
            },
        ),
        signature: [U256::ZERO; 3],
    };
    let row = PublicTxidTransaction {
        txid_index: 12,
        transaction: TxidPublicCacheTransaction {
            id: "12".to_string(),
            transaction_hash: output.utxo.source.tx_hash,
            block_number: output.utxo.source.block_number,
            block_timestamp: output.utxo.source.block_timestamp,
            nullifiers,
            commitments: vec![output.utxo.note.commitment()],
            bound_params_hash,
            has_unshield: false,
            unshield_preimage: None,
            utxo_tree_in: u64::from(input.utxo.tree),
            utxo_tree_out: u64::from(output.utxo.tree),
            utxo_batch_start_position_out: output.utxo.position,
        },
    };
    let wallet_utxos = vec![input, output.clone()];
    let wallet_nullifiers = WalletNullifierIndex::new(&wallet_utxos, &scan_keys);

    let recovered = build_output_poi_recovery_chunk_from_public_rows(
        &output,
        &wallet_nullifiers,
        &[row],
        None,
        &[],
        &forest,
        &[],
        spending_public_key,
        &scan_keys,
    )
    .await
    .expect("recover chunk without the transaction root");

    assert_ne!(recovered.chunk.merkle_root, original_chunk.merkle_root);
    let output_start_global = U256::from(recovered.output_start_global);
    let txid_data = PostTransactionPoiData {
        txid_leaf_hash: FixedBytes::from(
            railgun_txid_leaf_hash_with_output_start(
                original_chunk.railgun_txid(),
                u64::from(original_chunk.tree_number),
                output_start_global,
            )
            .to_be_bytes::<32>(),
        ),
        txid_merkleroot: FixedBytes::from([0x77; 32]),
        txid_merkleroot_index: 12,
        txid_merkle_proof_indices: U256::from(12_u64),
        txid_merkle_proof_path_elements: vec![U256::from(9_u64); TREE_DEPTH],
        utxo_batch_global_start_position_out: output_start_global,
    };
    let original_chunk_inputs = original_chunk
        .post_transaction_poi_inputs(&txid_data)
        .expect("original POI chunk inputs");
    let poi_proofs = original_chunk_inputs
        .blinded_commitments_in
        .iter()
        .map(|blinded| PoiMerkleProof {
            leaf: U256::from_be_bytes(blinded.0),
            elements: vec![U256::from(5_u64); TREE_DEPTH],
            indices: U256::ZERO,
            root: U256::from(6_u64),
        })
        .collect::<Vec<_>>();
    let poi_proof_inputs = |chunk: &TransactionPlanChunk| {
        let proof_inputs = chunk
            .post_transaction_poi_inputs(&txid_data)
            .expect("POI chunk inputs")
            .proof_inputs(&poi_proofs)
            .expect("POI proof inputs");
        // PoiProofInputs has no PartialEq; its Debug output lists every circuit input.
        format!("{proof_inputs:?}")
    };
    assert_eq!(
        poi_proof_inputs(&recovered.chunk),
        poi_proof_inputs(&original_chunk)
    );
}

#[tokio::test]
async fn output_poi_recovery_chunk_uses_cached_calldata_only_for_missing_output_notes() {
    let spending_public_key = [uint!(4_U256), uint!(5_U256)];
    let scan_keys = ViewingKeyData::from_spending_public_key([7_u8; 32], spending_public_key);
    let broadcaster_keys =
        ViewingKeyData::from_spending_public_key([8_u8; 32], [uint!(6_U256), uint!(7_U256)]);
    let sender = scan_keys.address_data();
    let broadcaster = broadcaster_keys.address_data();
    let mut input = test_wallet_utxo(0);
    let source = source(44);
    input.spent = Some(source.clone());
    let token = input.utxo.token_address();
    let fee_note = Note::new_change(
        broadcaster.master_public_key,
        token,
        U256::from(2_u8),
        [0x51; 16],
    );
    let change_note = Note::new_change(
        scan_keys.master_public_key,
        token,
        U256::from(3_u8),
        [0x52; 16],
    );
    let output = WalletUtxo::new(Utxo::new(
        change_note.clone(),
        input.utxo.tree,
        9,
        source,
        UtxoCommitmentKind::Transact,
    ));
    let fee_ciphertext = CommitmentCiphertext::from(
        NoteCiphertext::try_from_note(
            &fee_note,
            &sender,
            &broadcaster,
            &scan_keys.viewing_private_key,
        )
        .expect("encrypt fee note"),
    );
    let change_ciphertext = CommitmentCiphertext::from(
        NoteCiphertext::try_from_note(
            &change_note,
            &sender,
            &sender,
            &scan_keys.viewing_private_key,
        )
        .expect("encrypt change note"),
    );
    let unshield_note = Note::new_unshield(Address::from([0x56; 20]), token, U256::from(7_u8));

    let mut forest = MerkleForest::new();
    forest
        .insert_leaf(MerkleTreeUpdate {
            tree_number: input.utxo.tree,
            tree_position: input.utxo.position,
            hash: input.utxo.note.commitment(),
        })
        .expect("insert input leaf");
    let merkle_root = forest
        .prove_with_leaf_count(input.utxo.tree, input.utxo.position, 1)
        .expect("input proof")
        .root;
    let forest = Arc::new(forest);
    let transaction = Transaction {
        proof: SnarkProof::default(),
        merkleRoot: FixedBytes::from(merkle_root.to_be_bytes::<32>()),
        nullifiers: vec![FixedBytes::from(
            input
                .utxo
                .nullifier(scan_keys.nullifying_key)
                .to_be_bytes::<32>(),
        )],
        commitments: vec![
            FixedBytes::from(fee_note.commitment().to_be_bytes::<32>()),
            output.utxo.poi.commitment,
            FixedBytes::from(unshield_note.commitment().to_be_bytes::<32>()),
        ],
        boundParams: BoundParams::new_unshield(
            input.utxo.tree,
            EVM_CHAIN_TYPE,
            1,
            vec![fee_ciphertext, change_ciphertext],
            Address::ZERO,
            FixedBytes::ZERO,
        ),
        unshieldPreimage: CommitmentPreimage::new_unshield(&unshield_note, token),
    };
    let calldata = executeCall {
        _transactions: vec![transaction],
        _actionData: RelayAdapt7702ActionData {
            requireSuccess: true,
            minGasLimit: uint!(123_U256),
            calls: vec![Call {
                to: Address::from([0x99; 20]),
                data: Bytes::from(vec![0xab, 0xcd]),
                value: U256::ZERO,
            }],
        },
        _signature: Bytes::from(vec![0x12, 0x34]),
    }
    .abi_encode();
    assert_eq!(&calldata[..4], &[0xc6, 0x1e, 0x6b, 0x9d]);
    let decoded_transactions =
        decode_railgun_transactions(&calldata).expect("decode 7702 recovery calldata");
    let wallet_utxos = vec![input.clone(), output.clone()];
    let wallet_nullifiers = WalletNullifierIndex::new(&wallet_utxos, &scan_keys);

    let decoded = &decoded_transactions[0];
    let public_row = PublicTxidTransaction {
        txid_index: 5,
        transaction: TxidPublicCacheTransaction {
            id: "5".to_string(),
            transaction_hash: output.utxo.source.tx_hash,
            block_number: output.utxo.source.block_number,
            block_timestamp: output.utxo.source.block_timestamp,
            nullifiers: decoded
                .nullifiers
                .iter()
                .map(|nullifier| U256::from_be_bytes(nullifier.0))
                .collect(),
            commitments: decoded
                .commitments
                .iter()
                .map(|commitment| U256::from_be_bytes(commitment.0))
                .collect(),
            bound_params_hash: decoded.boundParams.hash(),
            has_unshield: true,
            unshield_preimage: Some(decoded.unshieldPreimage.abi_encode()),
            utxo_tree_in: u64::from(input.utxo.tree),
            utxo_tree_out: u64::from(output.utxo.tree),
            utxo_batch_start_position_out: 8,
        },
    };
    let chunk = build_output_poi_recovery_chunk_from_public_rows(
        &output,
        &wallet_nullifiers,
        &[public_row],
        None,
        &decoded_transactions,
        &forest,
        &[],
        spending_public_key,
        &scan_keys,
    )
    .await
    .expect("build unshield recovery chunk from calldata");

    assert!(chunk.chunk.has_unshield);
    assert_eq!(chunk.chunk.outputs.len(), 3);
    assert_eq!(chunk.chunk.private_output_count(), Some(2));
    assert_eq!(chunk.chunk.outputs[0].commitment(), fee_note.commitment());
    assert_eq!(chunk.chunk.outputs[0].npk, fee_note.npk);
    assert_eq!(chunk.chunk.outputs[0].value, fee_note.value);
    assert_eq!(
        chunk.chunk.outputs[1].commitment(),
        change_note.commitment()
    );
    assert_eq!(
        chunk.chunk.outputs[2].commitment(),
        unshield_note.commitment()
    );
    assert_eq!(chunk.chunk.private_inputs.npk_out[0], fee_note.npk);
    assert_eq!(chunk.chunk.private_inputs.value_out[0], fee_note.value);
    assert_eq!(
        chunk.output_start_global,
        u128::from(output.utxo.tree) * u128::from(TREE_LEAF_COUNT)
            + u128::from(output.utxo.position)
            - 1
    );
}

#[tokio::test]
async fn output_poi_recovery_chunk_uses_public_row_and_sender_candidate_without_calldata() {
    let spending_public_key = [uint!(4_U256), uint!(5_U256)];
    let scan_keys = ViewingKeyData::from_spending_public_key([7_u8; 32], spending_public_key);
    let mut input = test_wallet_utxo(0);
    let source = source(44);
    input.spent = Some(source.clone());
    let token = input.utxo.token_address();
    let fee_note = Note::new_change(U256::from(99), token, U256::from(2_u8), [0x51; 16]);
    let change_note = Note::new_change(
        scan_keys.master_public_key,
        token,
        U256::from(3_u8),
        [0x52; 16],
    );
    let output = WalletUtxo::new(Utxo::new(
        change_note.clone(),
        input.utxo.tree,
        9,
        source.clone(),
        UtxoCommitmentKind::Transact,
    ));
    let unshield_note = Note::new_unshield(Address::from([0x56; 20]), token, U256::from(7_u8));
    let unshield_preimage = CommitmentPreimage::new_unshield(&unshield_note, token);
    let mut forest = MerkleForest::new();
    forest
        .insert_leaf(MerkleTreeUpdate {
            tree_number: input.utxo.tree,
            tree_position: input.utxo.position,
            hash: input.utxo.note.commitment(),
        })
        .expect("insert input leaf");
    let forest = Arc::new(forest);
    let row = PublicTxidTransaction {
        txid_index: 12,
        transaction: TxidPublicCacheTransaction {
            id: "12".to_string(),
            transaction_hash: source.tx_hash,
            block_number: source.block_number,
            block_timestamp: source.block_timestamp,
            nullifiers: vec![input.utxo.nullifier(scan_keys.nullifying_key)],
            commitments: vec![
                fee_note.commitment(),
                change_note.commitment(),
                unshield_note.commitment(),
            ],
            bound_params_hash: U256::from(88),
            has_unshield: true,
            unshield_preimage: Some(unshield_preimage.abi_encode()),
            utxo_tree_in: u64::from(input.utxo.tree),
            utxo_tree_out: u64::from(input.utxo.tree),
            utxo_batch_start_position_out: 8,
        },
    };
    let sender_candidate = SenderTransactionCandidate::new(
        1,
        test_cache_key("public-row-output-notes"),
        source,
        vec![SenderTransactionCandidateSpend {
            tree: input.utxo.tree,
            position: input.utxo.position,
            commitment: input.utxo.poi.commitment,
        }],
        vec![
            SenderTransactionCandidateOutput {
                tree: output.utxo.tree,
                position: 8,
                commitment: FixedBytes::from(fee_note.commitment().to_be_bytes::<32>()),
                note: Some(fee_note.clone()),
            },
            SenderTransactionCandidateOutput {
                tree: output.utxo.tree,
                position: 9,
                commitment: output.utxo.poi.commitment,
                note: Some(change_note),
            },
        ],
    )
    .expect("sender candidate");
    let wallet_utxos = vec![input, output.clone()];
    let wallet_nullifiers = WalletNullifierIndex::new(&wallet_utxos, &scan_keys);

    let chunk = build_output_poi_recovery_chunk_from_public_rows(
        &output,
        &wallet_nullifiers,
        std::slice::from_ref(&row),
        Some(&sender_candidate),
        &[],
        &forest,
        &[],
        spending_public_key,
        &scan_keys,
    )
    .await
    .expect("build recovery chunk from public row");

    assert_eq!(chunk.target_txid_index, Some(12));
    assert_eq!(chunk.chunk.outputs.len(), 3);
    assert_eq!(chunk.chunk.outputs[0].commitment(), fee_note.commitment());
    assert_eq!(
        chunk.chunk.outputs[2].commitment(),
        unshield_note.commitment()
    );

    let failure = build_output_poi_recovery_chunk_from_public_rows(
        &output,
        &wallet_nullifiers,
        &[],
        Some(&sender_candidate),
        &[],
        &forest,
        &[],
        spending_public_key,
        &scan_keys,
    )
    .await
    .expect_err("missing public row must fail closed");
    assert_eq!(failure.status, OutputPoiRecoveryStatus::NotSelfOriginated);
    assert_eq!(failure.category, "public_row_not_unique_or_missing");

    let mut insufficient_row = row;
    insufficient_row.transaction.unshield_preimage = None;
    let failure = build_output_poi_recovery_chunk_from_public_rows(
        &output,
        &wallet_nullifiers,
        &[insufficient_row],
        Some(&sender_candidate),
        &[],
        &forest,
        &[],
        spending_public_key,
        &scan_keys,
    )
    .await
    .expect_err("missing selected-source unshield preimage must fail closed");
    assert_eq!(failure.status, OutputPoiRecoveryStatus::UnsupportedShape);
    assert!(failure.retry_after.is_none());
    assert_eq!(failure.category, "unshield_preimage_unavailable_or_invalid");
}

#[test]
fn output_poi_recovery_reports_missing_private_output_indexes() {
    let scan_keys =
        ViewingKeyData::from_spending_public_key([7_u8; 32], [uint!(4_U256), uint!(5_U256)]);
    let mut input = test_wallet_utxo(0);
    let output = test_wallet_utxo(8);
    let mut missing_private_output = test_wallet_utxo(9);
    missing_private_output.utxo.source = output.utxo.source.clone();
    missing_private_output.utxo.note.value = U256::from(11_u8);
    missing_private_output.utxo.poi.commitment = FixedBytes::from(
        missing_private_output
            .utxo
            .note
            .commitment()
            .to_be_bytes::<32>(),
    );
    input.spent = Some(output.utxo.source.clone());
    let mut forest = MerkleForest::new();
    forest
        .insert_leaf(MerkleTreeUpdate {
            tree_number: input.utxo.tree,
            tree_position: input.utxo.position,
            hash: input.utxo.note.commitment(),
        })
        .expect("insert input leaf");
    let merkle_root = forest
        .prove_with_leaf_count(input.utxo.tree, input.utxo.position, 1)
        .expect("input proof")
        .root;
    let missing_commitment = missing_private_output.utxo.poi.commitment;
    let transaction = Transaction {
        proof: SnarkProof::default(),
        merkleRoot: FixedBytes::from(merkle_root.to_be_bytes::<32>()),
        nullifiers: vec![FixedBytes::from(
            input
                .utxo
                .nullifier(scan_keys.nullifying_key)
                .to_be_bytes::<32>(),
        )],
        commitments: vec![output.utxo.poi.commitment, missing_commitment],
        boundParams: BoundParams::new_transact(
            input.utxo.tree,
            EVM_CHAIN_TYPE,
            1,
            Vec::new(),
            Address::ZERO,
            FixedBytes::ZERO,
        ),
        unshieldPreimage: CommitmentPreimage::empty(),
    };
    let wallet_utxos = vec![input, output.clone()];
    let wallet_nullifiers = WalletNullifierIndex::new(&wallet_utxos, &scan_keys);

    let failure = build_output_poi_recovery_chunk(
        &output,
        &wallet_nullifiers,
        &[transaction],
        &forest,
        &[],
        [uint!(4_U256), uint!(5_U256)],
        &scan_keys,
    )
    .expect_err("missing private output should fail");

    assert_eq!(
        failure.status,
        OutputPoiRecoveryStatus::MissingWalletOutputs
    );
    assert_eq!(failure.category, "missing_wallet_outputs");
    assert!(failure.message.contains("missing_private_outputs=1/2"));
    assert!(failure.message.contains("1:"));
    assert!(failure.message.contains(&hex::encode(missing_commitment)));
}

#[tokio::test]
async fn local_output_poi_proof_preflight_fails_before_expensive_recovery_when_cache_missing() {
    let nullifying_key = uint!(9_U256);
    let cfg = wallet_config(nullifying_key);
    let list_key = FixedBytes::from([0x11; 32]);
    let mut input = test_wallet_utxo(0);
    let output = test_wallet_utxo(8);
    input.spent = Some(output.utxo.source.clone());
    let transaction = recovery_test_transaction(&input, &output, nullifying_key);
    let wallet_utxos = vec![input, output.clone()];
    let wallet_nullifiers = WalletNullifierIndex::new(&wallet_utxos, &cfg.scan_keys);
    let mut cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        cfg.chain.chain_id,
        DEFAULT_TXID_VERSION,
        list_key,
    ));
    cache.accept_current_roots();
    let local_caches = WalletLocalPoiCaches::new_for_test(BTreeMap::from([(list_key, cache)]));
    let source = LocalPoiMerkleProofSource::new(local_caches);

    let failure = preflight_local_output_poi_input_proofs(
        Some(&source),
        &cfg,
        &output,
        &wallet_utxos,
        &wallet_nullifiers,
        &[transaction],
        &[list_key],
    )
    .await
    .expect_err("missing local proof preflight should fail");

    assert_eq!(
        failure.status,
        OutputPoiRecoveryStatus::ProofGenerationFailed
    );
    assert!(failure.message.contains("missing POI cache proof data"));
    assert_eq!(
        failure.retry_after,
        Some(OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER)
    );
}

#[tokio::test]
async fn local_output_poi_proof_preflight_checks_transaction_inputs() {
    let nullifying_key = uint!(9_U256);
    let cfg = wallet_config(nullifying_key);
    let list_key = FixedBytes::from([0x11; 32]);
    let mut input = test_wallet_utxo(0);
    let output = test_wallet_utxo(8);
    input.spent = Some(output.utxo.source.clone());
    let transaction = recovery_test_transaction(&input, &output, nullifying_key);
    let wallet_utxos = vec![input.clone(), output.clone()];
    let wallet_nullifiers = WalletNullifierIndex::new(&wallet_utxos, &cfg.scan_keys);
    let mut cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        cfg.chain.chain_id,
        DEFAULT_TXID_VERSION,
        list_key,
    ));
    cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: *input.utxo.poi.blinded_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply input POI event");
    let local_caches = WalletLocalPoiCaches::new_for_test(BTreeMap::from([(list_key, cache)]));
    let source = LocalPoiMerkleProofSource::new(local_caches);

    preflight_local_output_poi_input_proofs(
        Some(&source),
        &cfg,
        &output,
        &wallet_utxos,
        &wallet_nullifiers,
        &[transaction],
        &[list_key],
    )
    .await
    .expect("input proof preflight succeeds");
}

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
