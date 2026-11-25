use super::*;

#[tokio::test]
async fn sender_candidate_batch_refreshes_validated_txid_coverage_once() {
    let list_key = FixedBytes::from([0x31; 32]);
    let mut input = test_wallet_utxo(0x32);
    let candidate = sender_candidate_for_spent_input(
        WalletCacheKey::from_opaque_bytes(b"batch-refresh-candidate").expect("cache key"),
        &input,
        source(0x33),
    );
    input.spent = Some(candidate.source.clone());
    let second_candidate =
        sender_candidate_for_spent_input(candidate.wallet_id.clone(), &input, source(0x34));
    let mut cfg = wallet_config(input.utxo.nullifier(U256::ZERO));
    cfg.cache_key = candidate.wallet_id.clone();
    cfg.scan_keys.nullifying_key = U256::ZERO;
    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    for persisted in [&candidate, &second_candidate] {
        db.put_opaque_wallet_private_row(
            &persisted.namespace(),
            WalletPrivateRecordKind::SenderTransactionCandidate,
            &OpaqueWalletPrivateRow {
                row_id: persisted.row_identity(),
                payload: persisted.encode().expect("encode candidate"),
            },
        )
        .expect("persist candidate");
    }
    cfg.spending_public_key = Some([U256::ZERO; 2]);
    cfg.poi_recovery_prover = Some(ProverService::new_with_db(
        &ArtifactSource::default(),
        &db,
        None,
    ));

    let mut poi_cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        cfg.chain.chain_id,
        DEFAULT_TXID_VERSION,
        list_key,
    ));
    poi_cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: [0x99; 32],
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply unrelated output event");
    poi_cache.accept_current_roots();
    let public_data_plane = test_public_data_plane_with_poi_service(&db);
    seed_data_plane_poi_cache(&public_data_plane, cfg.chain.chain_id, list_key, poi_cache).await;
    let foreign_graph_response = serde_json::json!({
        "data": {
            "transactions": [{
                "id": "0x00",
                "blockNumber": "1",
                "blockTimestamp": "1700000001",
                "transactionHash": hex::encode_prefixed(FixedBytes::<32>::from([0x99; 32])),
                "merkleRoot": "0x01",
                "nullifiers": ["0xaa"],
                "commitments": ["0xbb"],
                "boundParamsHash": "0xcc",
                "hasUnshield": false,
                "utxoTreeIn": "0",
                "utxoTreeOut": "0",
                "utxoBatchStartPositionOut": "0",
            }]
        }
    })
    .to_string()
    .into_bytes();
    let (graph_endpoint, _graph_requests) = spawn_http_response(foreign_graph_response).await;
    public_data_plane
        .sync_txid_public_cache(PublicTxidSyncRequest {
            key: DataPlanePublicTxidCacheKey::new(
                ChainScope {
                    chain_type: ChainType::Evm,
                    chain_id: cfg.chain.chain_id,
                    railgun_contract: cfg.chain.contract,
                },
                DEFAULT_TXID_VERSION,
            ),
            endpoint: Some(&graph_endpoint),
            http_client: None,
            latest: DataPlanePublicTxidLatestValidated {
                txid_index: 0,
                merkleroot: None,
            },
            indexed_artifact_source: None,
        })
        .await
        .expect("seed validated foreign TXID row");

    let poi_mock = spawn_poi_rpc_sequence(vec![
        serde_json::json!({
            "validatedTxidIndex": 0,
            "validatedMerkleroot": null,
        }),
        serde_json::json!(true),
    ])
    .await;
    let runtime = test_artifact_poi_runtime_with_fallback(poi_mock.url);
    cfg.quick_sync_endpoint =
        Some(Url::parse("http://127.0.0.1:1").expect("unused configured GraphQL endpoint"));
    let mut handle = test_wallet_handle(vec![input.clone()]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let private_poi = WalletPrivatePoiClients::new(
        authority.remote_authority(),
        PoiRpcClient::new(Url::parse("http://127.0.0.1:1").expect("unused POI endpoint")),
        Arc::new(ChainPoiSubmitterHandle::detached_for_test()),
    );
    let forest = Arc::new(MerkleForest::new());
    let wallet_utxos = vec![input.clone()];
    let report = materialize_sender_transaction_candidates(SenderCandidateRecoveryRequest {
        output_recovery: OutputPoiRecoveryRequest {
            authority: &authority,
            db: db.as_ref(),
            cache_store: db.as_ref(),
            cfg: &cfg,
            public_data_plane: &public_data_plane,
            http_client: None,
            indexed_artifact_source: None,
            forest: Arc::clone(&forest),
            poi_client: runtime.public_client(),
            private_poi: &private_poi,
            poi_runtime: &runtime,
            active_list_keys: &[list_key],
            wallet_utxos: &wallet_utxos,
            force_retry: false,
        },
        candidates: vec![candidate, second_candidate],
        unshield_attempts: &SenderUnshieldAttempts::default(),
    })
    .await;

    assert_eq!(
        report.awaiting_public_txid_data, 2,
        "unexpected batch refresh report: {report:?}"
    );
    assert_eq!(report.retrying, 0);
    let latest_request = poi_mock
        .requests
        .recv_timeout(Duration::from_secs(2))
        .expect("latest validated TXID request");
    assert_eq!(latest_request["method"], "ppoi_validated_txid");
    let global_checkpoint_request = poi_mock
        .requests
        .recv_timeout(Duration::from_secs(2))
        .expect("global latest checkpoint validation request");
    assert_eq!(
        global_checkpoint_request["method"],
        "ppoi_validate_txid_merkleroot"
    );
    assert_eq!(global_checkpoint_request["params"]["tree"], 0);
    assert_eq!(global_checkpoint_request["params"]["index"], 0);
    // The null-root latest marker is validated globally, once for the shared batch refresh.
    assert!(poi_mock.requests.try_recv().is_err());
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn locally_valid_sender_candidate_retires_without_public_or_remote_effects() {
    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let mut cfg = wallet_config(U256::from(17));
    cfg.cache_key = test_cache_key("local-retirement");
    let active_list_keys = vec![FixedBytes::from([0x41; 32]), FixedBytes::from([0x42; 32])];
    let mut input = test_wallet_utxo(1);
    let source = source(0x71);
    input.spent = Some(source.clone());
    let external_note = Note {
        token_hash: U256::from(7),
        value: U256::from(9),
        random: [0x5a; 16],
        npk: U256::from(11),
    };
    let owned_note = Note::new_change(
        cfg.scan_keys.master_public_key,
        Address::from([0x22; 20]),
        U256::from(3),
        [0x6b; 16],
    );
    let external_output = SenderTransactionCandidateOutput {
        tree: 3,
        position: 4,
        commitment: FixedBytes::from(external_note.commitment().to_be_bytes::<32>()),
        note: Some(external_note),
    };
    let owned_output = SenderTransactionCandidateOutput {
        tree: 3,
        position: 5,
        commitment: FixedBytes::from(owned_note.commitment().to_be_bytes::<32>()),
        note: Some(owned_note.clone()),
    };
    let candidate = SenderTransactionCandidate::new(
        cfg.chain.chain_id,
        cfg.cache_key.clone(),
        source,
        vec![SenderTransactionCandidateSpend {
            tree: input.utxo.tree,
            position: input.utxo.position,
            commitment: input.utxo.poi.commitment,
        }],
        vec![external_output.clone(), owned_output.clone()],
    )
    .expect("local-only candidate");
    let owned_change = WalletUtxo {
        utxo: Utxo::new(
            owned_note,
            owned_output.tree,
            owned_output.position,
            candidate.source.clone(),
            UtxoCommitmentKind::Transact,
        ),
        spent: None,
    };
    let wallet_utxos = vec![input.clone(), owned_change];
    let expected_wallet_utxos = wallet_utxos.clone();
    db.put_opaque_wallet_private_row(
        &candidate.namespace(),
        WalletPrivateRecordKind::SenderTransactionCandidate,
        &OpaqueWalletPrivateRow {
            row_id: candidate.row_identity(),
            payload: candidate.encode().expect("encode candidate"),
        },
    )
    .expect("persist candidate");
    let mut pending_owned_context = pending_output_record(
        cfg.chain.chain_id,
        owned_output.commitment,
        active_list_keys[0],
    );
    pending_owned_context.wallet_id = cfg.cache_key.to_string();
    pending_owned_context.output_npk = FixedBytes::from(
        owned_output
            .note
            .as_ref()
            .expect("owned output note")
            .npk
            .to_be_bytes::<32>(),
    );
    pending_owned_context.observation = Some(local_db::PendingOutputPoiObservation {
        output_tree: u64::from(owned_output.tree),
        output_position: owned_output.position,
        tx_hash: candidate.source.tx_hash,
        block_number: candidate.source.block_number,
        block_timestamp: candidate.source.block_timestamp,
    });
    let second_list_key = active_list_keys[1];
    pending_owned_context
        .required_poi_list_keys
        .push(second_list_key);
    pending_owned_context
        .pre_transaction_pois_per_txid_leaf_per_list
        .insert(
            second_list_key,
            BTreeMap::from([(FixedBytes::from([0x56; 32]), sample_pre_tx_poi(0x11))]),
        );
    db.put_pending_output_poi_context(&pending_owned_context)
        .expect("persist pending owned context");
    let external_blinded_commitment = Utxo::new(
        external_output.note.clone().expect("external note"),
        external_output.tree,
        external_output.position,
        candidate.source.clone(),
        UtxoCommitmentKind::Transact,
    )
    .poi
    .blinded_commitment;
    // Retirement needs public qualification: one artifact-bounded TXID row without an unshield.
    let txid_transaction = IndexedRailgunTransaction {
        id: "local_retirement".to_string(),
        block_number: U64::from(candidate.source.block_number),
        block_timestamp: U64::from(candidate.source.block_timestamp),
        transaction_hash: candidate.source.tx_hash,
        merkle_root: FixedBytes::from([0x22; 32]),
        nullifiers: vec![input.utxo.nullifier(cfg.scan_keys.nullifying_key)],
        commitments: vec![
            U256::from_be_bytes(external_output.commitment.0),
            U256::from_be_bytes(owned_output.commitment.0),
        ],
        bound_params_hash: U256::from(2),
        has_unshield: false,
        unshield_token: None,
        unshield_to_address: None,
        unshield_value: None,
        utxo_tree_in: U64::from(input.utxo.tree),
        utxo_tree_out: U64::from(external_output.tree),
        utxo_batch_start_position_out: U64::from(external_output.position),
    };
    seed_single_txid_artifact(db.as_ref(), &cfg, txid_transaction).await;

    let public_data_plane = test_public_data_plane_with_poi_service(&db);
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
                blinded_commitment: external_blinded_commitment.0,
                signature: [0_u8; 64],
                event_type: PoiEventType::Transact,
            }])
            .expect("seed valid local status");
        cache.accept_current_roots();
        seed_data_plane_poi_cache(&public_data_plane, cfg.chain.chain_id, list_key, cache).await;
    }

    let mut handle = test_wallet_handle(wallet_utxos.clone());
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let remote_status = Arc::new(RecordingPoiStatusClient::default());
    let remote_submit = Arc::new(RecordingPendingOutputPoiSubmitter::default());
    let private_poi = WalletPrivatePoiClients::for_test(
        WalletPrivateMutationAuthority::new(&handle, 0, &cancel).remote_authority(),
        remote_status.clone(),
        remote_submit.clone(),
    );
    let poi_runtime = test_artifact_poi_runtime();
    let forest = Arc::new(MerkleForest::new());
    let (apply_tx, mut apply_rx) = mpsc::channel(1);
    let apply_client = WalletPrivateApplyClient::new(apply_tx);
    let authority =
        WalletPrivateMutationAuthority::new(&handle, 0, &cancel).with_apply_client(&apply_client);
    let mixed_report = materialize_sender_transaction_candidates(SenderCandidateRecoveryRequest {
        output_recovery: OutputPoiRecoveryRequest {
            authority: &authority,
            db: db.as_ref(),
            cache_store: db.as_ref(),
            cfg: &cfg,
            public_data_plane: &public_data_plane,
            http_client: None,
            indexed_artifact_source: None,
            forest,
            poi_client: poi_runtime.public_client(),
            private_poi: &private_poi,
            poi_runtime: &poi_runtime,
            active_list_keys: &active_list_keys,
            wallet_utxos: &wallet_utxos,
            force_retry: false,
        },
        candidates: vec![candidate.clone()],
        unshield_attempts: &SenderUnshieldAttempts::default(),
    })
    .await;

    assert_eq!(mixed_report.covered_by_pending_contexts, 1);
    assert_eq!(mixed_report.materialized, 0);
    assert_eq!(mixed_report.retired_locally_valid, 0);
    assert!(apply_rx.try_recv().is_err());
    assert!(
        db.get_sender_transaction_candidate(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &candidate.semantic_id(),
        )
        .expect("load covered candidate")
        .is_some()
    );
    assert_eq!(
        remote_status.calls(),
        [] as [(Vec<FixedBytes<32>>, Vec<BlindedCommitmentData>); 0]
    );
    assert_eq!(remote_submit.calls(), [] as [(FixedBytes<32>, u64, u64); 0]);
    db.delete_pending_output_poi_context(
        cfg.chain.chain_id,
        cfg.cache_key.as_str(),
        &owned_output.commitment,
    )
    .expect("remove pending owned context");

    let actor_handle = handle.clone();
    let actor_db = Arc::clone(&db);
    let actor_cancel = cancel.clone();
    let actor_cfg = cfg.clone();
    let actor_active_list_keys = active_list_keys.clone();
    let actor = async move {
        let request = apply_rx
            .recv()
            .await
            .expect("local retirement actor request");
        let result = apply_owned_poi_private_delta_on_actor_with_active_lists(
            &actor_handle,
            &actor_cancel,
            request.reset_generation,
            actor_db.as_ref(),
            actor_db.as_ref(),
            &actor_cfg,
            &actor_active_list_keys,
            request.delta,
        )
        .await;
        request.reply.send(result).expect("send actor result");
    };
    let unshield_attempts = SenderUnshieldAttempts::default();
    let recovery = materialize_sender_transaction_candidates(SenderCandidateRecoveryRequest {
        output_recovery: OutputPoiRecoveryRequest {
            authority: &authority,
            db: db.as_ref(),
            cache_store: db.as_ref(),
            cfg: &cfg,
            public_data_plane: &public_data_plane,
            http_client: None,
            indexed_artifact_source: None,
            forest: Arc::new(MerkleForest::new()),
            poi_client: poi_runtime.public_client(),
            private_poi: &private_poi,
            poi_runtime: &poi_runtime,
            active_list_keys: &active_list_keys,
            wallet_utxos: &wallet_utxos,
            force_retry: false,
        },
        candidates: vec![candidate.clone()],
        unshield_attempts: &unshield_attempts,
    });
    let (report, ()) = tokio::join!(recovery, actor);

    assert_eq!(report.retired_locally_valid, 1);
    assert_eq!(report.materialized, 0);
    assert_eq!(report.completed(), 1);
    assert!(
        db.get_sender_transaction_candidate(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &candidate.semantic_id()
        )
        .expect("load retired candidate")
        .is_none()
    );
    let current_wallet_utxos = handle.utxos.read().await;
    assert_eq!(current_wallet_utxos.len(), expected_wallet_utxos.len());
    for (current, expected) in current_wallet_utxos.iter().zip(&expected_wallet_utxos) {
        assert_eq!(
            wallet_utxo_stable_identity(current),
            wallet_utxo_stable_identity(expected)
        );
        assert_eq!(current.spent, expected.spent);
    }
    drop(current_wallet_utxos);
    assert!(
        db.list_pending_output_poi_contexts(cfg.chain.chain_id, &cfg.cache_key)
            .expect("list pending contexts")
            .is_empty()
    );
    assert!(
        db.list_output_poi_recoveries(cfg.chain.chain_id, &cfg.cache_key)
            .expect("list recovery rows")
            .is_empty()
    );
    let observation = handle.observation();
    let workflow_status = observation.ppoi_workflow_status();
    assert_eq!(workflow_status.awaiting_recovery, 0);
    assert_eq!(workflow_status.outstanding_count(), 0);
    assert_eq!(
        remote_status.calls(),
        [] as [(Vec<FixedBytes<32>>, Vec<BlindedCommitmentData>); 0]
    );
    assert_eq!(remote_submit.calls(), [] as [(FixedBytes<32>, u64, u64); 0]);

    db.put_opaque_wallet_private_row(
        &candidate.namespace(),
        WalletPrivateRecordKind::SenderTransactionCandidate,
        &OpaqueWalletPrivateRow {
            row_id: candidate.row_identity(),
            payload: candidate.encode().expect("re-encode candidate"),
        },
    )
    .expect("restore candidate");
    let corpus = public_data_plane
        .ensure_poi_corpus(PublicPoiCorpusKey::wallet_default(cfg.chain.chain_id))
        .await
        .expect("reload local corpus");
    let mut missing_cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        cfg.chain.chain_id,
        DEFAULT_TXID_VERSION,
        active_list_keys[1],
    ));
    missing_cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: [0x99; 32],
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("seed missing local status");
    missing_cache.accept_current_roots();
    corpus
        .local_caches()
        .write()
        .await
        .insert(active_list_keys[1], missing_cache);

    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let report = materialize_sender_transaction_candidates(SenderCandidateRecoveryRequest {
        output_recovery: OutputPoiRecoveryRequest {
            authority: &authority,
            db: db.as_ref(),
            cache_store: db.as_ref(),
            cfg: &cfg,
            public_data_plane: &public_data_plane,
            http_client: None,
            indexed_artifact_source: None,
            forest: Arc::new(MerkleForest::new()),
            poi_client: poi_runtime.public_client(),
            private_poi: &private_poi,
            poi_runtime: &poi_runtime,
            active_list_keys: &active_list_keys,
            wallet_utxos: &wallet_utxos,
            force_retry: false,
        },
        candidates: vec![candidate.clone()],
        unshield_attempts: &SenderUnshieldAttempts::default(),
    })
    .await;
    assert_eq!(report.retired_locally_valid, 0);
    assert_eq!(report.materialized, 0);
    assert_eq!(report.completed(), 0);
    assert!(
        db.get_sender_transaction_candidate(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &candidate.semantic_id()
        )
        .expect("load retained candidate")
        .is_some()
    );
    let current_wallet_utxos = handle.utxos.read().await;
    assert_eq!(current_wallet_utxos.len(), expected_wallet_utxos.len());
    for (current, expected) in current_wallet_utxos.iter().zip(&expected_wallet_utxos) {
        assert_eq!(
            wallet_utxo_stable_identity(current),
            wallet_utxo_stable_identity(expected)
        );
        assert_eq!(current.spent, expected.spent);
    }
    assert_eq!(
        remote_status.calls(),
        [] as [(Vec<FixedBytes<32>>, Vec<BlindedCommitmentData>); 0]
    );
    assert_eq!(remote_submit.calls(), [] as [(FixedBytes<32>, u64, u64); 0]);

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn partial_outer_txid_coverage_refreshes_before_candidate_attention() {
    let list_key = FixedBytes::from([0x41; 32]);
    let mut first_input = test_wallet_utxo(1);
    let mut second_input = test_wallet_utxo(2);
    let candidate_source = source(0x42);
    first_input.spent = Some(candidate_source.clone());
    second_input.spent = Some(candidate_source.clone());
    let first_note = Note {
        token_hash: U256::from(7),
        value: U256::from(9),
        random: [0x43; 16],
        npk: U256::from(11),
    };
    let second_note = Note {
        token_hash: U256::from(7),
        value: U256::from(10),
        random: [0x44; 16],
        npk: U256::from(12),
    };
    let candidate = SenderTransactionCandidate::new(
        1,
        WalletCacheKey::from_opaque_bytes(b"partial-outer-txid-candidate").expect("cache key"),
        candidate_source.clone(),
        vec![
            SenderTransactionCandidateSpend {
                tree: first_input.utxo.tree,
                position: first_input.utxo.position,
                commitment: first_input.utxo.poi.commitment,
            },
            SenderTransactionCandidateSpend {
                tree: second_input.utxo.tree,
                position: second_input.utxo.position,
                commitment: second_input.utxo.poi.commitment,
            },
        ],
        vec![
            SenderTransactionCandidateOutput {
                tree: 3,
                position: 4,
                commitment: FixedBytes::from(first_note.commitment().to_be_bytes::<32>()),
                note: Some(first_note),
            },
            SenderTransactionCandidateOutput {
                tree: 3,
                position: 5,
                commitment: FixedBytes::from(second_note.commitment().to_be_bytes::<32>()),
                note: Some(second_note),
            },
        ],
    )
    .expect("partial-coverage candidate");
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = candidate.wallet_id.clone();
    cfg.spending_public_key = Some([U256::ZERO; 2]);
    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    cfg.poi_recovery_prover = Some(ProverService::new_with_db(
        &ArtifactSource::default(),
        &db,
        None,
    ));
    db.put_opaque_wallet_private_row(
        &candidate.namespace(),
        WalletPrivateRecordKind::SenderTransactionCandidate,
        &OpaqueWalletPrivateRow {
            row_id: candidate.row_identity(),
            payload: candidate.encode().expect("encode candidate"),
        },
    )
    .expect("persist candidate");

    let mut poi_cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        cfg.chain.chain_id,
        DEFAULT_TXID_VERSION,
        list_key,
    ));
    poi_cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: [0x99; 32],
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply unrelated output event");
    poi_cache.accept_current_roots();
    let public_data_plane = test_public_data_plane_with_poi_service(&db);
    seed_data_plane_poi_cache(&public_data_plane, cfg.chain.chain_id, list_key, poi_cache).await;
    let txid_row = |id: &str, input: &WalletUtxo, output: &SenderTransactionCandidateOutput| {
        serde_json::json!({
            "id": id,
            "blockNumber": candidate.source.block_number.to_string(),
            "blockTimestamp": candidate.source.block_timestamp.to_string(),
            "transactionHash": hex::encode_prefixed(candidate.source.tx_hash),
            "merkleRoot": "0x01",
            "nullifiers": [hex::encode_prefixed(FixedBytes::from(
                input.utxo.nullifier(cfg.scan_keys.nullifying_key).to_be_bytes::<32>()
            ))],
            "commitments": [hex::encode_prefixed(output.commitment)],
            "boundParamsHash": "0x02",
            "hasUnshield": false,
            "utxoTreeIn": input.utxo.tree.to_string(),
            "utxoTreeOut": output.tree.to_string(),
            "utxoBatchStartPositionOut": output.position.to_string(),
        })
    };
    let stale_graph_response = serde_json::json!({
        "data": { "transactions": [txid_row("0x00", &first_input, &candidate.outputs[0])] }
    })
    .to_string()
    .into_bytes();
    let refresh_graph_response = serde_json::json!({
        "data": { "transactions": [txid_row("0x01", &second_input, &candidate.outputs[1])] }
    })
    .to_string()
    .into_bytes();
    let (stale_graph_endpoint, _stale_requests) = spawn_http_response(stale_graph_response).await;
    let cache_key = DataPlanePublicTxidCacheKey::new(
        ChainScope {
            chain_type: ChainType::Evm,
            chain_id: cfg.chain.chain_id,
            railgun_contract: cfg.chain.contract,
        },
        DEFAULT_TXID_VERSION,
    );
    public_data_plane
        .sync_txid_public_cache(PublicTxidSyncRequest {
            key: cache_key,
            endpoint: Some(&stale_graph_endpoint),
            http_client: None,
            latest: DataPlanePublicTxidLatestValidated {
                txid_index: 0,
                merkleroot: None,
            },
            indexed_artifact_source: None,
        })
        .await
        .expect("seed partial validated TXID coverage");
    let wallet_utxos = vec![first_input, second_input];
    let mut handle = test_wallet_handle(wallet_utxos.clone());
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let private_poi = WalletPrivatePoiClients::new(
        authority.remote_authority(),
        PoiRpcClient::new(Url::parse("http://127.0.0.1:1").expect("unused POI endpoint")),
        Arc::new(ChainPoiSubmitterHandle::detached_for_test()),
    );
    let forest = Arc::new(MerkleForest::new());
    cfg.quick_sync_endpoint =
        Some(Url::parse("http://127.0.0.1:1").expect("unused configured GraphQL endpoint"));
    let current_poi_mock = spawn_poi_rpc_sequence(vec![
        serde_json::json!({
            "validatedTxidIndex": 0,
            "validatedMerkleroot": null,
        }),
        serde_json::json!(true),
    ])
    .await;
    let current_runtime = test_artifact_poi_runtime_with_fallback(current_poi_mock.url);
    let still_partial = materialize_sender_transaction_candidates(SenderCandidateRecoveryRequest {
        output_recovery: OutputPoiRecoveryRequest {
            authority: &authority,
            db: db.as_ref(),
            cache_store: db.as_ref(),
            cfg: &cfg,
            public_data_plane: &public_data_plane,
            http_client: None,
            indexed_artifact_source: None,
            forest: Arc::clone(&forest),
            poi_client: current_runtime.public_client(),
            private_poi: &private_poi,
            poi_runtime: &current_runtime,
            active_list_keys: &[list_key],
            wallet_utxos: &wallet_utxos,
            force_retry: false,
        },
        candidates: vec![candidate.clone()],
        unshield_attempts: &SenderUnshieldAttempts::default(),
    })
    .await;
    assert_eq!(
        still_partial.awaiting_public_txid_data, 2,
        "unexpected current-boundary report: {still_partial:?}"
    );
    assert_eq!(still_partial.needs_attention, 0);
    let current_latest_request = current_poi_mock
        .requests
        .recv_timeout(Duration::from_secs(2))
        .expect("current latest validated TXID request");
    assert_eq!(current_latest_request["method"], "ppoi_validated_txid");
    let current_checkpoint_request = current_poi_mock
        .requests
        .recv_timeout(Duration::from_secs(2))
        .expect("current global latest checkpoint validation request");
    assert_eq!(
        current_checkpoint_request["method"],
        "ppoi_validate_txid_merkleroot"
    );
    assert_eq!(current_checkpoint_request["params"]["tree"], 0);
    assert_eq!(current_checkpoint_request["params"]["index"], 0);
    // The null-root marker is validated at the global latest index before candidate attention.
    assert!(current_poi_mock.requests.try_recv().is_err());

    let (refresh_endpoint, refresh_requests) = spawn_http_response(refresh_graph_response).await;
    cfg.quick_sync_endpoint = Some(refresh_endpoint);
    let poi_mock = spawn_poi_rpc_sequence(vec![
        serde_json::json!({
            "validatedTxidIndex": 1,
            "validatedMerkleroot": null,
        }),
        serde_json::json!(true),
    ])
    .await;
    let runtime = test_artifact_poi_runtime_with_fallback(poi_mock.url);
    let report = materialize_sender_transaction_candidates(SenderCandidateRecoveryRequest {
        output_recovery: OutputPoiRecoveryRequest {
            authority: &authority,
            db: db.as_ref(),
            cache_store: db.as_ref(),
            cfg: &cfg,
            public_data_plane: &public_data_plane,
            http_client: None,
            indexed_artifact_source: None,
            forest: Arc::clone(&forest),
            poi_client: runtime.public_client(),
            private_poi: &private_poi,
            poi_runtime: &runtime,
            active_list_keys: &[list_key],
            wallet_utxos: &wallet_utxos,
            force_retry: false,
        },
        candidates: vec![candidate],
        unshield_attempts: &SenderUnshieldAttempts::default(),
    })
    .await;

    assert_eq!(report.needs_attention, 0, "unexpected report: {report:?}");
    assert_eq!(report.retrying, 2, "unexpected report: {report:?}");
    assert!(
        refresh_requests
            .recv_timeout(Duration::from_secs(2))
            .is_ok()
    );
    let latest_request = poi_mock
        .requests
        .recv_timeout(Duration::from_secs(2))
        .expect("latest validated TXID request");
    assert_eq!(latest_request["method"], "ppoi_validated_txid");
    let checkpoint_request = poi_mock
        .requests
        .recv_timeout(Duration::from_secs(2))
        .expect("global latest checkpoint validation request");
    assert_eq!(
        checkpoint_request["method"],
        "ppoi_validate_txid_merkleroot"
    );
    assert_eq!(checkpoint_request["params"]["tree"], 0);
    assert_eq!(checkpoint_request["params"]["index"], 1);
    // The second null-root marker is validated globally before candidate attention.
    assert!(poi_mock.requests.try_recv().is_err());
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
