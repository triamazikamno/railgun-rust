use super::*;

#[tokio::test]
async fn public_cache_txid_recovery_refreshes_stale_marker_for_known_target() {
    let spending_public_key = [uint!(4_U256), uint!(5_U256)];
    let scan_keys = ViewingKeyData::from_spending_public_key([7_u8; 32], spending_public_key);
    let mut input = test_wallet_utxo(0);
    let output = test_wallet_utxo(8);
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
    let wallet_utxos = vec![input, output.clone()];
    let wallet_nullifiers = WalletNullifierIndex::new(&wallet_utxos, &scan_keys);
    let transaction =
        recovery_test_transaction(&wallet_utxos[0], &output, scan_keys.nullifying_key);
    let transaction = Transaction {
        merkleRoot: FixedBytes::from(merkle_root.to_be_bytes::<32>()),
        boundParams: BoundParams::new_transact(
            wallet_utxos[0].utxo.tree,
            EVM_CHAIN_TYPE,
            1,
            Vec::new(),
            Address::ZERO,
            FixedBytes::ZERO,
        ),
        ..transaction
    };
    let bound_params_hash = transaction.boundParams.hash();
    let mut recovery_chunk = build_output_poi_recovery_chunk(
        &output,
        &wallet_nullifiers,
        std::slice::from_ref(&transaction),
        &forest,
        &[],
        spending_public_key,
        &scan_keys,
    )
    .expect("build recovery chunk");

    let graph_response = serde_json::json!({
        "data": {
            "transactions": [
                {
                    "id": "0x00",
                    "blockNumber": "1",
                    "blockTimestamp": "1700000001",
                    "transactionHash": hex::encode_prefixed(FixedBytes::<32>::from([0x99; 32])),
                    "merkleRoot": hex::encode_prefixed(FixedBytes::<32>::from([0x98; 32])),
                    "nullifiers": ["0xaa"],
                    "commitments": ["0xbb"],
                    "boundParamsHash": "0xcc",
                    "hasUnshield": false,
                    "utxoTreeIn": "0",
                    "utxoTreeOut": "0",
                    "utxoBatchStartPositionOut": "0",
                },
                {
                    "id": "0x01",
                    "blockNumber": output.utxo.source.block_number.to_string(),
                    "blockTimestamp": output.utxo.source.block_timestamp.to_string(),
                    "transactionHash": hex::encode_prefixed(output.utxo.source.tx_hash),
                    "merkleRoot": hex::encode_prefixed(FixedBytes::from(merkle_root.to_be_bytes::<32>())),
                    "nullifiers": [hex::encode_prefixed(transaction.nullifiers[0])],
                    "commitments": [hex::encode_prefixed(output.utxo.poi.commitment)],
                    "boundParamsHash": hex::encode_prefixed(FixedBytes::from(bound_params_hash.to_be_bytes::<32>())),
                    "hasUnshield": false,
                    "utxoTreeIn": wallet_utxos[0].utxo.tree.to_string(),
                    "utxoTreeOut": output.utxo.tree.to_string(),
                    "utxoBatchStartPositionOut": output.utxo.position.to_string(),
                }
            ]
        }
    });
    let seed_leaf = railgun_txid_leaf_hash_with_output_start(
        compute_railgun_txid_parts(
            &[U256::from(0xaa_u64)],
            &[U256::from(0xbb_u64)],
            U256::from(0xcc_u64),
        ),
        0,
        U256::ZERO,
    );
    let expected_leaf = railgun_txid_leaf_hash_with_output_start(
        recovery_chunk.chunk.railgun_txid(),
        u64::from(recovery_chunk.chunk.tree_number),
        U256::from(recovery_chunk.output_start_global),
    );
    let latest_root = FixedBytes::from(
        DenseMerkleTree::from_ordered_leaves(vec![seed_leaf, expected_leaf], 2)
            .root()
            .to_be_bytes::<32>(),
    );
    let seed_graph_response = serde_json::json!({
        "data": {
            "transactions": [graph_response["data"]["transactions"][0].clone()]
        }
    });
    let recovery_graph_response = serde_json::json!({
        "data": {
            "transactions": [graph_response["data"]["transactions"][1].clone()]
        }
    });
    let seed_graph_response = seed_graph_response.to_string().into_bytes();
    let recovery_graph_response = recovery_graph_response.to_string().into_bytes();
    let (graph_endpoint, _graph_requests) = spawn_http_response(seed_graph_response).await;
    let (recovery_endpoint, recovery_requests) = spawn_http_response(recovery_graph_response).await;
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let public_data_plane =
        ChainPublicDataPlane::new(Arc::clone(&store), Arc::new(AtomicU64::new(0)));
    let txid_scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::ZERO,
    };
    public_data_plane
        .sync_txid_public_cache(PublicTxidSyncRequest {
            key: DataPlanePublicTxidCacheKey::new(txid_scope.clone(), DEFAULT_TXID_VERSION),
            endpoint: Some(&graph_endpoint),
            http_client: None,
            latest: DataPlanePublicTxidLatestValidated {
                txid_index: 0,
                merkleroot: None,
            },
            indexed_artifact_source: None,
        })
        .await
        .expect("seed public txid cache through typed data plane");
    let expected_leaf = railgun_txid_leaf_hash_with_output_start(
        recovery_chunk.chunk.railgun_txid(),
        u64::from(recovery_chunk.chunk.tree_number),
        U256::from(recovery_chunk.output_start_global),
    );
    let direct_error = public_data_plane
        .txid_public_proof(&PublicTxidProofRequest {
            key: DataPlanePublicTxidCacheKey::new(txid_scope, DEFAULT_TXID_VERSION),
            target: PublicTxidProofTarget::UnknownIndex {
                expected_leaf_hash: expected_leaf,
                output_start_global: recovery_chunk.output_start_global,
            },
        })
        .expect_err("stale marker must not prove the unknown target beyond it");
    assert!(matches!(
        direct_error,
        crate::txid_cache::TxidPublicCacheError::MissingTarget
            | crate::txid_cache::TxidPublicCacheError::CacheNotReady {
                required_index: 1,
                ..
            }
    ));
    recovery_chunk.target_txid_index = Some(1);
    let poi_mock = spawn_poi_rpc_sequence(vec![serde_json::json!({
        "validatedTxidIndex": 1,
        "validatedMerkleroot": hex::encode_prefixed(latest_root),
    })])
    .await;
    let poi_client = PoiRpcClient::new(poi_mock.url.clone());
    let mut cfg = wallet_config(scan_keys.nullifying_key);
    cfg.quick_sync_endpoint = Some(recovery_endpoint);

    recovered_output_txid_data_from_public_cache(PublicCacheTxidRecoveryRequest {
        public_data_plane: &public_data_plane,
        cfg: &cfg,
        poi_client: &poi_client,
        http_client: None,
        indexed_artifact_source: None,
        recovery_chunk: &recovery_chunk,
        started: Instant::now(),
    })
    .await
    .expect("current marker sync should recover the unknown target");
    let refresh_request = recovery_requests
        .recv_timeout(Duration::from_secs(2))
        .expect("recovery refresh request");
    assert!(refresh_request.contains("\"offset\":1"));

    let latest_request = poi_mock
        .requests
        .recv_timeout(Duration::from_secs(2))
        .expect("latest validated marker request");
    assert_eq!(latest_request["method"], "ppoi_validated_txid");
    assert!(
        poi_mock
            .requests
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "latest-root recovery must not issue a target validation request"
    );
    let latest = public_data_plane
        .cached_txid_latest_validated(&DataPlanePublicTxidCacheKey::new(
            ChainScope {
                chain_type: ChainType::Evm,
                chain_id: cfg.chain.chain_id,
                railgun_contract: cfg.chain.contract,
            },
            DEFAULT_TXID_VERSION,
        ))
        .expect("read refreshed marker")
        .expect("refreshed marker present");
    assert_eq!(latest.txid_index, 1);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn public_cache_txid_recovery_uses_artifact_bound_before_latest_refresh() {
    let bound_params_hash = U256::from(0x33_u64);
    let chunk = RecoveryChunk {
        replay_fence: None,
        chunk: railgun_wallet::tx::TransactionPlanChunk {
            tree_number: 0,
            merkle_root: U256::ZERO,
            inputs: Vec::new(),
            outputs: Vec::new(),
            has_unshield: false,
            public_inputs: PublicInputs {
                merkle_root: U256::ZERO,
                bound_params_hash,
                nullifiers: vec![U256::from(1_u64)],
                commitments_out: vec![U256::from(2_u64)],
            },
            private_inputs: PrivateInputs {
                token_address: U256::ZERO,
                random_in: Vec::new(),
                value_in: Vec::new(),
                path_elements: Vec::new(),
                leaves_indices: Vec::new(),
                value_out: Vec::new(),
                public_key: [U256::ZERO; 2],
                npk_out: Vec::new(),
                nullifying_key: U256::ZERO,
            },
            signature: [U256::ZERO; 3],
        },
        output_start_global: 0,
        target_txid_index: Some(0),
    };
    let txid_transaction = IndexedRailgunTransaction {
        id: "artifact_bound".to_string(),
        block_number: U256::from(1_u64),
        block_timestamp: U256::from(1_700_000_001_u64),
        transaction_hash: FixedBytes::from([0x11; 32]),
        merkle_root: FixedBytes::from([0x22; 32]),
        nullifiers: vec![U256::from(1_u64)],
        commitments: vec![U256::from(2_u64)],
        bound_params_hash,
        has_unshield: false,
        unshield_token: None,
        unshield_to_address: None,
        unshield_value: None,
        utxo_tree_in: U64::from(0),
        utxo_tree_out: U64::from(0),
        utxo_batch_start_position_out: U64::from(0),
    };
    let cache_key = TxidPublicCacheKey {
        chain_type: 0,
        chain_id: 1,
        railgun_contract: Address::ZERO,
        txid_version: DEFAULT_TXID_VERSION,
    };
    let artifact_leaf =
        railgun_txid_leaf_hash_with_output_start(chunk.chunk.railgun_txid(), 0, U256::ZERO);
    let artifact_root = FixedBytes::from(
        DenseMerkleTree::from_ordered_leaves(vec![artifact_leaf], 1)
            .root()
            .to_be_bytes::<32>(),
    );
    let artifact_path = DenseMerkleTree::from_ordered_leaves(vec![artifact_leaf], 1)
        .prove(0)
        .path_elements
        .to_vec();
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    seed_verified_artifact_bound_for_test(
        store.as_ref(),
        cache_key,
        vec![txid_transaction],
        artifact_root,
    )
    .await
    .expect("persist verified artifact artifact_bound");
    let public_data_plane =
        ChainPublicDataPlane::new(Arc::clone(&store), Arc::new(AtomicU64::new(0)));
    let mut cfg = wallet_config(U256::ZERO);
    cfg.quick_sync_endpoint = Some(Url::parse("http://127.0.0.1:1/graphql").expect("squid URL"));

    {
        let poi_mock = spawn_poi_rpc_sequence(Vec::new()).await;
        let poi_client = PoiRpcClient::new(poi_mock.url.clone());
        let result = recovered_output_txid_data_from_public_cache(PublicCacheTxidRecoveryRequest {
            public_data_plane: &public_data_plane,
            cfg: &cfg,
            poi_client: &poi_client,
            http_client: None,
            indexed_artifact_source: None,
            recovery_chunk: &chunk,
            started: Instant::now(),
        })
        .await;

        assert!(
            poi_mock
                .requests
                .recv_timeout(Duration::from_millis(100))
                .is_err(),
            "artifact-bounded recovery must not request POI TXID validation"
        );

        let recovered = result.expect("authenticated artifact_bound recovery failed");
        assert_eq!(recovered.poi_data.txid_merkleroot, artifact_root);
        assert_eq!(recovered.poi_data.txid_merkleroot_index, 0);
        assert_eq!(recovered.poi_data.txid_merkle_proof_indices, U256::ZERO);
        assert_eq!(
            recovered.poi_data.txid_merkle_proof_path_elements,
            artifact_path
        );
    }

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn public_broadcaster_partial_unshield_keeps_candidate_after_scan_and_maintenance() {
    let fixture = partial_unshield_fixture(
        "public-broadcaster-partial-unshield",
        UnshieldFixtureShape::OutputsValid,
    )
    .await;
    let unshield_attempts = SenderUnshieldAttempts::default();
    let report = Box::pin(run_partial_unshield_maintenance(
        &fixture,
        &unshield_attempts,
    ))
    .await;

    let stored = fixture
        .stored_candidate()
        .expect("an unresolved unshield must keep its sender candidate");
    assert_eq!(
        stored.unshield,
        Some(SenderTransactionCandidateUnshield {
            railgun_txids: vec![fixture.railgun_txid],
            outputs_handed_off: true,
        }),
        "valid outputs are handed off and only the unshield TXID remains"
    );
    assert_eq!(report.retired_locally_valid, 0);
    assert!(
        report.retrying >= 1,
        "no prover keeps the unshield retrying"
    );
    assert!(
        fixture
            .db
            .list_pending_output_poi_contexts(fixture.cfg.chain.chain_id, &fixture.cfg.cache_key)
            .expect("list pending contexts")
            .is_empty(),
        "already-valid fee and change outputs need no pending context"
    );
    let current_wallet_utxos = fixture.handle.utxos.read().await;
    assert_eq!(current_wallet_utxos.len(), fixture.wallet_utxos.len());
    for (current, expected) in current_wallet_utxos.iter().zip(&fixture.wallet_utxos) {
        assert_eq!(
            wallet_utxo_stable_identity(current),
            wallet_utxo_stable_identity(expected)
        );
        assert_eq!(current.spent, expected.spent);
    }
    drop(current_wallet_utxos);
    assert!(
        fixture
            .handle
            .observation()
            .ppoi_workflow_status()
            .outstanding_count()
            >= 1,
        "the unshield remains outstanding PPOI work"
    );

    unshield_attempts.expire_all();
    let rerun = Box::pin(run_partial_unshield_maintenance(
        &fixture,
        &unshield_attempts,
    ))
    .await;
    assert_eq!(
        fixture
            .stored_candidate()
            .map(|candidate| candidate.unshield),
        Some(stored.unshield),
        "a rerun keeps the handed-off unshield work"
    );
    assert_eq!(rerun.retired_locally_valid, 0);
    assert!(rerun.retrying >= 1);

    let PartialUnshieldFixture { root_dir, db, .. } = fixture;
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn covered_partial_unshield_records_txid_without_handing_off_outputs() {
    let fixture = partial_unshield_fixture(
        "covered-partial-unshield",
        UnshieldFixtureShape::OutputsCovered,
    )
    .await;
    let unshield_attempts = SenderUnshieldAttempts::default();
    let report = Box::pin(run_partial_unshield_maintenance(
        &fixture,
        &unshield_attempts,
    ))
    .await;

    assert_eq!(report.covered_by_pending_contexts, 2);
    assert_eq!(
        fixture
            .stored_candidate()
            .expect("covered candidate is retained")
            .unshield,
        Some(SenderTransactionCandidateUnshield {
            railgun_txids: vec![fixture.railgun_txid],
            outputs_handed_off: false,
        }),
        "covered outputs keep their fallback while the unshield TXID is recorded"
    );

    let PartialUnshieldFixture { root_dir, db, .. } = fixture;
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

/// Owned change needs no sender proof, so a self-broadcast partial unshield retires without a
/// prover once its unshield reads Valid, leaving the change to the wallet's own PPOI work.
#[tokio::test]
async fn self_broadcast_partial_unshield_retires_without_prover() {
    let fixture = partial_unshield_fixture(
        "self-broadcast-partial-unshield",
        UnshieldFixtureShape::SelfBroadcast,
    )
    .await;
    let change = &fixture.wallet_utxos[1];
    let attempts = SenderUnshieldAttempts::default();
    Box::pin(run_partial_unshield_maintenance(&fixture, &attempts)).await;

    assert_eq!(
        fixture
            .stored_candidate()
            .expect("an unresolved unshield keeps the candidate")
            .unshield,
        Some(SenderTransactionCandidateUnshield {
            railgun_txids: vec![fixture.railgun_txid],
            outputs_handed_off: true,
        }),
        "owned change is handed off and only the unshield TXID remains"
    );
    let current_change = fixture
        .handle
        .utxos
        .read()
        .await
        .iter()
        .find(|utxo| wallet_utxo_stable_identity(utxo) == wallet_utxo_stable_identity(change))
        .cloned()
        .expect("change UTXO");
    assert_ne!(
        current_change.utxo.poi.statuses.get(&fixture.list_key),
        Some(&PoiStatus::Valid),
        "handing off does not mark the change Valid"
    );
    assert!(
        fixture
            .db
            .list_pending_output_poi_contexts(fixture.cfg.chain.chain_id, &fixture.cfg.cache_key)
            .expect("list pending contexts")
            .is_empty()
    );
    assert!(
        fixture
            .db
            .get_output_poi_recovery(
                fixture.cfg.chain.chain_id,
                &fixture.cfg.cache_key,
                &change.utxo.poi.commitment,
            )
            .expect("load change recovery")
            .is_none()
    );

    seed_valid_unshield(&fixture).await;
    Box::pin(run_partial_unshield_maintenance(&fixture, &attempts)).await;
    assert!(fixture.stored_candidate().is_none());
    assert_eq!(fixture.published_workflow().outstanding_count(), 0);
    assert_eq!(
        fixture.submitter.calls(),
        [] as [(FixedBytes<32>, u64, u64); 0]
    );

    let PartialUnshieldFixture { root_dir, db, .. } = fixture;
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn handed_off_unshield_submission_is_paced_and_completes_only_when_valid() {
    let fixture = partial_unshield_fixture(
        "handed-off-unshield-submission",
        UnshieldFixtureShape::OutputsValid,
    )
    .await;
    Box::pin(run_partial_unshield_maintenance(
        &fixture,
        &SenderUnshieldAttempts::default(),
    ))
    .await;
    let handed_off = fixture.stored_candidate().expect("handed-off candidate");
    assert!(
        handed_off
            .unshield
            .as_ref()
            .is_some_and(|unshield| unshield.outputs_handed_off)
    );
    let handed_off = handed_off.encode().expect("encode handed-off candidate");
    let unchanged = || {
        fixture
            .stored_candidate()
            .map(|candidate| candidate.encode().expect("encode stored candidate"))
            .as_deref()
            == Some(handed_off.as_slice())
    };
    let calls = || fixture.submitter.calls().len();
    let proofs: PreTransactionPoiMap = BTreeMap::from([(
        fixture.list_key,
        BTreeMap::from([(
            FixedBytes::from([0xd1; 32]),
            current_poi_fixture("ppoi_3x3").pre_tx_poi,
        )]),
    )]);
    let mut previous = external_pending_output_record(
        &fixture.cfg,
        0xd2,
        fixture.list_key,
        PendingOutputPoiRole::RecoveredOutgoing,
    );
    previous
        .pre_transaction_pois_per_txid_leaf_per_list
        .clone_from(&proofs);
    let previous_proofs =
        previous_key_pending_context(&previous).pre_transaction_pois_per_txid_leaf_per_list;
    let cached = |proofs: &PreTransactionPoiMap| {
        BTreeMap::from([(fixture.railgun_txid, (0_u64, proofs.clone()))])
    };
    let cancel = CancellationToken::new();
    let attempts = SenderUnshieldAttempts::default();

    let rejected = Box::pin(process_stored_sender_unshields(
        &fixture,
        &attempts,
        &cancel,
        cached(&previous_proofs),
    ))
    .await;
    assert_eq!(
        calls(),
        0,
        "previous-key proofs are rejected before transport"
    );
    assert_eq!(rejected.unshield_awaiting_validation, 0);

    // 1. A Missing unshield with a proof is submitted once and keeps its candidate unchanged.
    let submitted = Box::pin(process_stored_sender_unshields(
        &fixture,
        &attempts,
        &cancel,
        cached(&proofs),
    ))
    .await;
    assert_eq!(calls(), 1);
    assert_eq!(submitted.unshield_awaiting_validation, 1);
    assert!(unchanged());

    // 2. Before the submitted interval nothing is resent.
    let waiting = Box::pin(process_stored_sender_unshields(
        &fixture,
        &attempts,
        &cancel,
        BTreeMap::new(),
    ))
    .await;
    assert_eq!(calls(), 1);
    assert_eq!(waiting.unshield_awaiting_validation, 1);

    // A retryable transport failure keeps the candidate and is paced.
    attempts.expire_all();
    fixture.submitter.fail_next();
    let failed = Box::pin(process_stored_sender_unshields(
        &fixture,
        &attempts,
        &cancel,
        cached(&proofs),
    ))
    .await;
    assert_eq!(calls(), 2);
    assert_eq!(
        (failed.retrying, failed.unshield_awaiting_validation),
        (1, 0)
    );
    assert!(unchanged());
    let paced = Box::pin(process_stored_sender_unshields(
        &fixture,
        &attempts,
        &cancel,
        cached(&proofs),
    ))
    .await;
    assert_eq!(
        calls(),
        2,
        "the failed submission waits for its retry interval"
    );
    assert_eq!(paced.retrying, 1);

    // 3. After the interval it is resubmitted; the node's duplicate acknowledgement is success.
    attempts.expire_all();
    let resubmitted = Box::pin(process_stored_sender_unshields(
        &fixture,
        &attempts,
        &cancel,
        cached(&proofs),
    ))
    .await;
    assert_eq!(calls(), 3);
    assert_eq!(
        (
            resubmitted.retrying,
            resubmitted.needs_attention,
            resubmitted.unshield_awaiting_validation,
        ),
        (0, 0, 1)
    );

    // 4. A restart forgets in-memory pacing and resubmits.
    let restarted = Box::pin(process_stored_sender_unshields(
        &fixture,
        &SenderUnshieldAttempts::default(),
        &cancel,
        cached(&proofs),
    ))
    .await;
    assert_eq!(calls(), 4);
    assert_eq!(restarted.unshield_awaiting_validation, 1);

    // 5. A stale job authority transmits nothing.
    let stale = CancellationToken::new();
    stale.cancel();
    let stale_report = Box::pin(process_stored_sender_unshields(
        &fixture,
        &SenderUnshieldAttempts::default(),
        &stale,
        cached(&proofs),
    ))
    .await;
    assert_eq!(calls(), 4);
    assert_eq!(stale_report.unshield_awaiting_validation, 0);
    assert!(unchanged());

    // 6. Only a later local Valid read completes the unshield, with no proof and no prover.
    seed_valid_unshield(&fixture).await;
    let revision = fixture.published_workflow().validation_revision;
    let validated = Box::pin(process_stored_sender_unshields(
        &fixture,
        &attempts,
        &cancel,
        BTreeMap::new(),
    ))
    .await;
    assert_eq!(calls(), 4);
    assert_eq!(validated.unshields_validated, 1);
    assert!(fixture.stored_candidate().is_none());
    let workflow = fixture.published_workflow();
    assert_eq!(workflow.validation_revision, revision + 1);
    assert_eq!(workflow.outstanding_count(), 0);

    let PartialUnshieldFixture { root_dir, db, .. } = fixture;
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn routed_unshield_waits_for_admission_then_sends_over_its_own_route() {
    let mut fixture = partial_unshield_fixture(
        "routed-unshield-submission",
        UnshieldFixtureShape::OutputsValid,
    )
    .await;
    Box::pin(run_partial_unshield_maintenance(
        &fixture,
        &SenderUnshieldAttempts::default(),
    ))
    .await;
    // No spacing and one route, so another transaction's admission defers the unshield.
    let scheduler = PoiSubmissionScheduler::new(
        PoiSubmissionSchedulerConfig {
            min_admission_gap: Duration::ZERO,
            max_admission_gap: Duration::ZERO,
            max_open_routes: 1,
        },
        rand::SeedableRng::seed_from_u64(0),
    );
    let routes = RecordingRoutes::new();
    fixture.routing = Some(routes.routing(Arc::clone(&scheduler)));
    let PoiSubmissionAdmission::Admitted(other) =
        scheduler.try_reserve(fixture.cfg.chain.chain_id, U256::MAX)
    else {
        panic!("an idle scheduler admits");
    };
    let proofs: PreTransactionPoiMap = BTreeMap::from([(
        fixture.list_key,
        BTreeMap::from([(
            FixedBytes::from([0xd1; 32]),
            current_poi_fixture("ppoi_3x3").pre_tx_poi,
        )]),
    )]);
    let cached = || BTreeMap::from([(fixture.railgun_txid, (0_u64, proofs.clone()))]);
    let cancel = CancellationToken::new();
    let attempts = SenderUnshieldAttempts::default();

    let deferred = Box::pin(process_stored_sender_unshields(
        &fixture,
        &attempts,
        &cancel,
        cached(),
    ))
    .await;
    assert_eq!(
        (
            deferred.retrying,
            deferred.needs_attention,
            deferred.unshield_awaiting_validation,
        ),
        (1, 0, 0),
        "a deferred unshield stays outstanding without needing attention"
    );
    assert_eq!(routes.opens(), 0, "a deferral opens no route");

    // The freed route admits it on the next pass, with no pacing delay.
    drop(other);
    let submitted = Box::pin(process_stored_sender_unshields(
        &fixture,
        &attempts,
        &cancel,
        cached(),
    ))
    .await;
    assert_eq!(submitted.unshield_awaiting_validation, 1);
    let routed = routes.routes();
    assert_eq!(routed.len(), 1);
    assert_eq!(routed[0].transact_sends(), vec![(0, fixture.list_key)]);
    assert!(
        fixture.submitter.calls().is_empty(),
        "routed proofs never use the shared client"
    );

    seed_valid_unshield(&fixture).await;
    let validated = Box::pin(process_stored_sender_unshields(
        &fixture,
        &attempts,
        &cancel,
        BTreeMap::new(),
    ))
    .await;
    assert_eq!(validated.unshields_validated, 1);
    assert!(fixture.stored_candidate().is_none());
    assert_eq!(routes.routes().len(), 1, "a Valid unshield is not resent");

    let PartialUnshieldFixture { root_dir, db, .. } = fixture;
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn shield_blocked_refund_retires_spend_only_candidate_without_submission() {
    let fixture = partial_unshield_fixture(
        "shield-blocked-refund",
        UnshieldFixtureShape::UnshieldOnly {
            input_blocked: true,
        },
    )
    .await;
    commit_unshield_only_scan(&fixture).await;
    assert!(fixture.stored_candidate().is_some());

    let report = Box::pin(run_partial_unshield_maintenance(
        &fixture,
        &SenderUnshieldAttempts::default(),
    ))
    .await;

    assert!(
        fixture.stored_candidate().is_none(),
        "no PPOI can be built for a blocked input, so the refund leaves no work"
    );
    assert_eq!(
        fixture.submitter.calls(),
        [] as [(FixedBytes<32>, u64, u64); 0]
    );
    assert_eq!(report.unshields_validated, 0);
    let workflow = fixture.published_workflow();
    assert_eq!(workflow.outstanding_count(), 0);
    assert_eq!(workflow.validation_revision, 0);
    assert!(
        fixture
            .db
            .list_pending_output_poi_contexts(fixture.cfg.chain.chain_id, &fixture.cfg.cache_key)
            .expect("list pending contexts")
            .is_empty()
    );

    let PartialUnshieldFixture { root_dir, db, .. } = fixture;
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

/// State left by a Repair-wallet-cache rewind before the spend: the input is unspent, no
/// candidate exists and the public TXID row is cached. Rescanning recovers the unshield.
#[tokio::test]
async fn rescanned_unshield_only_spend_recreates_candidate_and_completes_unshield() {
    let fixture = partial_unshield_fixture(
        "rescanned-unshield-only",
        UnshieldFixtureShape::UnshieldOnly {
            input_blocked: false,
        },
    )
    .await;
    assert!(fixture.stored_candidate().is_none());

    let discovered = commit_unshield_only_scan(&fixture).await;
    let expected = fixture
        .candidate
        .encode()
        .expect("encode spend-only candidate");
    assert_eq!(
        discovered
            .iter()
            .map(|candidate| candidate.encode().expect("encode discovered candidate"))
            .collect::<Vec<_>>(),
        vec![expected.clone()]
    );
    assert_eq!(
        fixture
            .stored_candidate()
            .map(|candidate| candidate.encode().expect("encode stored candidate")),
        Some(expected)
    );

    let attempts = SenderUnshieldAttempts::default();
    let handed_off = Box::pin(run_partial_unshield_maintenance(&fixture, &attempts)).await;
    assert_eq!(
        fixture
            .stored_candidate()
            .and_then(|candidate| candidate.unshield),
        Some(SenderTransactionCandidateUnshield {
            railgun_txids: vec![fixture.railgun_txid],
            outputs_handed_off: true,
        })
    );
    assert!(
        handed_off.retrying >= 1,
        "no prover keeps the unshield retrying"
    );

    seed_valid_unshield(&fixture).await;
    let revision = fixture.published_workflow().validation_revision;
    let completed = Box::pin(run_partial_unshield_maintenance(&fixture, &attempts)).await;
    assert!(fixture.stored_candidate().is_none());
    assert_eq!(completed.unshields_validated, 1);
    assert_eq!(
        fixture.published_workflow().validation_revision,
        revision + 1
    );
    assert_eq!(
        fixture.submitter.calls(),
        [] as [(FixedBytes<32>, u64, u64); 0]
    );

    let PartialUnshieldFixture { root_dir, db, .. } = fixture;
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

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
    cfg.poi_recovery_prover = Some(ProverService::new_with_db(&ArtifactSource::default(), &db));

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
        block_number: U256::from(candidate.source.block_number),
        block_timestamp: U256::from(candidate.source.block_timestamp),
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
    cfg.poi_recovery_prover = Some(ProverService::new_with_db(&ArtifactSource::default(), &db));
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

/// Seeds a verified TXID artifact bound containing only `txid_transaction`.
async fn seed_single_txid_artifact(
    db: &DbStore,
    cfg: &WalletConfig,
    txid_transaction: IndexedRailgunTransaction,
) {
    let artifact_leaf = txid_transaction.txid_leaf_hash();
    let artifact_root = FixedBytes::from(
        DenseMerkleTree::from_ordered_leaves(vec![artifact_leaf], 1)
            .root()
            .to_be_bytes::<32>(),
    );
    seed_verified_artifact_bound_for_test(
        db,
        TxidPublicCacheKey {
            chain_type: 0,
            chain_id: cfg.chain.chain_id,
            railgun_contract: cfg.chain.contract,
            txid_version: DEFAULT_TXID_VERSION,
        },
        vec![txid_transaction],
        artifact_root,
    )
    .await
    .expect("persist verified sender artifact bound");
}

/// A public-broadcaster spend paying a broadcaster fee, wallet change and an unshield, or a full
/// unshield for `UnshieldOnly`, or change and an unshield for `SelfBroadcast`. The unshield
/// (keyed by its Railgun TXID) stays Missing.
async fn partial_unshield_fixture(
    name: &str,
    shape: UnshieldFixtureShape,
) -> PartialUnshieldFixture {
    let unshield_only = matches!(shape, UnshieldFixtureShape::UnshieldOnly { .. });
    let self_broadcast = matches!(shape, UnshieldFixtureShape::SelfBroadcast);
    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let list_key = FixedBytes::from([0xc0; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key(name);
    cfg.scan_keys =
        ViewingKeyData::from_spending_public_key([7; 32], [U256::from(11), U256::from(12)]);
    let broadcaster =
        ViewingKeyData::from_spending_public_key([9; 32], [U256::from(13), U256::from(14)]);
    let spend_source = source(0xc1);
    let token = Address::from([0xc2; 20]);
    let input = test_wallet_utxo(7);
    let input_nullifier = input.utxo.nullifier(cfg.scan_keys.nullifying_key);
    let fee_note = Note::new_change(
        broadcaster.master_public_key,
        token,
        U256::from(1),
        [0xc3; 16],
    );
    let change_note = Note::new_change(
        cfg.scan_keys.master_public_key,
        token,
        U256::from(4),
        [0xc4; 16],
    );
    let unshield_note = Note::new_unshield(Address::from([0xc5; 20]), token, U256::from(5));
    let output_tree = 3_u32;
    let fee_position = 4_u64;
    let change_position = if self_broadcast {
        fee_position
    } else {
        fee_position + 1
    };
    let sender_output = |note: &Note, receiver: &ViewingKeyData, position: u64| SenderScanOutput {
        tree: output_tree,
        position,
        commitment: note.commitment(),
        ciphertext: NoteCiphertext::try_from_note(
            note,
            &cfg.scan_keys.address_data(),
            &receiver.address_data(),
            &cfg.scan_keys.viewing_private_key,
        )
        .expect("encrypt sender output")
        .into(),
        source: spend_source.clone(),
    };

    let candidate = if unshield_only {
        // The candidate a scan of the spend must produce; `commit_unshield_only_scan` does that.
        SenderTransactionCandidate::new(
            cfg.chain.chain_id,
            cfg.cache_key.clone(),
            spend_source.clone(),
            vec![SenderTransactionCandidateSpend {
                tree: input.utxo.tree,
                position: input.utxo.position,
                commitment: input.utxo.poi.commitment,
            }],
            Vec::new(),
        )
        .expect("spend-only sender candidate")
    } else {
        // Discovery: the scan sees the wallet spend and the sender-encrypted outputs, but the
        // unshield commitment carries no ciphertext.
        let nullifier_sources =
            HashMap::from([((input.utxo.tree, input_nullifier), spend_source.clone())]);
        let mut sender_outputs = vec![sender_output(&change_note, &cfg.scan_keys, change_position)];
        if !self_broadcast {
            sender_outputs.insert(0, sender_output(&fee_note, &broadcaster, fee_position));
        }
        let mut discovered = sender_scan_candidate_inputs(
            std::slice::from_ref(&input),
            cfg.scan_keys.nullifying_key,
            &nullifier_sources,
            sender_outputs,
            &cfg.scan_keys,
        );
        assert_eq!(
            discovered.len(),
            1,
            "the scan discovers one sender candidate"
        );
        let candidate = discovered
            .remove(0)
            .into_record(cfg.chain.chain_id, cfg.cache_key.clone())
            .expect("sender candidate record");
        assert_eq!(candidate.outputs.len(), if self_broadcast { 1 } else { 2 });
        assert!(candidate.outputs.iter().all(|output| output.note.is_some()));
        db.put_opaque_wallet_private_row(
            &candidate.namespace(),
            WalletPrivateRecordKind::SenderTransactionCandidate,
            &OpaqueWalletPrivateRow {
                row_id: candidate.row_identity(),
                payload: candidate.encode().expect("encode sender candidate"),
            },
        )
        .expect("persist sender candidate");
        candidate
    };

    let mut spent_input = input.clone();
    spent_input.spent = Some(spend_source.clone());
    let change = WalletUtxo::new(Utxo::new(
        change_note.clone(),
        output_tree,
        change_position,
        spend_source.clone(),
        UtxoCommitmentKind::Transact,
    ));
    let change_blinded_commitment = change.utxo.poi.blinded_commitment;
    let fee_blinded_commitment = Utxo::new(
        fee_note.clone(),
        output_tree,
        fee_position,
        spend_source.clone(),
        UtxoCommitmentKind::Transact,
    )
    .poi
    .blinded_commitment;
    let mut wallet_utxos = vec![spent_input];
    let mut commitments = Vec::new();
    if !unshield_only {
        wallet_utxos.push(change);
        if !self_broadcast {
            commitments.push(fee_note.commitment());
        }
        commitments.push(change_note.commitment());
    }
    commitments.push(unshield_note.commitment());

    let txid_transaction = IndexedRailgunTransaction {
        id: "public_broadcaster_partial_unshield".to_string(),
        block_number: U256::from(spend_source.block_number),
        block_timestamp: U256::from(spend_source.block_timestamp),
        transaction_hash: spend_source.tx_hash,
        merkle_root: FixedBytes::from([0x22; 32]),
        nullifiers: vec![input_nullifier],
        commitments,
        bound_params_hash: U256::from(2),
        has_unshield: true,
        unshield_token: None,
        unshield_to_address: None,
        unshield_value: None,
        utxo_tree_in: U64::from(input.utxo.tree),
        utxo_tree_out: U64::from(output_tree),
        utxo_batch_start_position_out: U64::from(fee_position),
    };
    let railgun_txid = txid_transaction.railgun_txid();
    seed_single_txid_artifact(db.as_ref(), &cfg, txid_transaction).await;
    let public_data_plane = test_public_data_plane_with_poi_service(&db);
    let (rows, _) = public_data_plane
        .txid_transactions_for_outer_hash_with_authority(
            &DataPlanePublicTxidCacheKey::new(
                ChainScope {
                    chain_type: ChainType::Evm,
                    chain_id: cfg.chain.chain_id,
                    railgun_contract: cfg.chain.contract,
                },
                DEFAULT_TXID_VERSION,
            ),
            spend_source.tx_hash,
        )
        .expect("load artifact-bounded sender row");
    assert_eq!(rows.len(), 1, "maintenance can see the unshield TXID row");

    let mut cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        cfg.chain.chain_id,
        DEFAULT_TXID_VERSION,
        list_key,
    ));
    let valid_blinded_commitments = match shape {
        UnshieldFixtureShape::OutputsValid => {
            vec![fee_blinded_commitment, change_blinded_commitment]
        }
        // Keep the corpus ready without making anything Valid.
        UnshieldFixtureShape::UnshieldOnly { .. } | UnshieldFixtureShape::SelfBroadcast => {
            vec![FixedBytes::from([0xc9; 32])]
        }
        UnshieldFixtureShape::OutputsCovered => {
            let proofs: PreTransactionPoiMap = BTreeMap::from([(
                list_key,
                BTreeMap::from([(
                    FixedBytes::from([0xc6; 32]),
                    current_poi_fixture("ppoi_3x3").pre_tx_poi,
                )]),
            )]);
            for (byte, output) in [(0xc7, &candidate.outputs[0]), (0xc8, &candidate.outputs[1])] {
                let mut pending = external_pending_output_record(
                    &cfg,
                    byte,
                    list_key,
                    PendingOutputPoiRole::RecoveredOutgoing,
                );
                pending.output_commitment = output.commitment;
                pending.output_npk = FixedBytes::from(
                    output
                        .note
                        .as_ref()
                        .expect("sender note")
                        .npk
                        .to_be_bytes::<32>(),
                );
                pending.observation = Some(local_db::PendingOutputPoiObservation {
                    output_tree: u64::from(output.tree),
                    output_position: output.position,
                    tx_hash: spend_source.tx_hash,
                    block_number: spend_source.block_number,
                    block_timestamp: spend_source.block_timestamp,
                });
                pending
                    .pre_transaction_pois_per_txid_leaf_per_list
                    .clone_from(&proofs);
                db.put_pending_output_poi_context(&pending)
                    .expect("store compatible pending context");
            }
            // Keep the corpus ready without making the fee or change Valid.
            vec![FixedBytes::from([0xc9; 32])]
        }
    };
    cache
        .apply_verified_artifact_events(
            &valid_blinded_commitments
                .iter()
                .zip(0_u64..)
                .map(
                    |(blinded_commitment, event_index)| poi::artifacts::SnapshotEvent {
                        event_index,
                        blinded_commitment: blinded_commitment.0,
                        signature: [0_u8; 64],
                        event_type: PoiEventType::Transact,
                    },
                )
                .collect::<Vec<_>>(),
        )
        .expect("seed local PPOI statuses");
    if matches!(
        shape,
        UnshieldFixtureShape::UnshieldOnly {
            input_blocked: true
        }
    ) {
        cache
            .apply_blocked_shields(&[poi::poi::BlockedShield {
                commitment_hash: hex::encode_prefixed(input.utxo.poi.commitment),
                blinded_commitment: hex::encode_prefixed(input.utxo.poi.blinded_commitment),
                block_reason: None,
                signature: hex::encode_prefixed([0_u8; 64]),
            }])
            .expect("seed blocked input shield");
    }
    cache.accept_current_roots();
    seed_data_plane_poi_cache(&public_data_plane, cfg.chain.chain_id, list_key, cache).await;

    let mut handle = test_wallet_handle(if unshield_only {
        vec![input]
    } else {
        wallet_utxos.clone()
    });
    handle.cache_key = cfg.cache_key.clone();
    PartialUnshieldFixture {
        root_dir,
        db,
        cfg,
        list_key,
        candidate,
        railgun_txid: FixedBytes::from(railgun_txid.to_be_bytes::<32>()),
        wallet_utxos,
        handle,
        public_data_plane,
        submitter: Arc::new(RecordingPendingOutputPoiSubmitter::default()),
        routing: None,
    }
}

/// Scan the fixture's unshield-only spend as scan commit does: apply its nullifier-only delta,
/// then persist the spent mark with the discovered sender candidates.
async fn commit_unshield_only_scan(
    fixture: &PartialUnshieldFixture,
) -> Vec<SenderTransactionCandidate> {
    let input = &fixture.wallet_utxos[0].utxo;
    let mut scanned = fixture.handle.utxos.read().await.clone();
    let outcome = apply_wallet_delta_to_vec_with_outcome(
        &fixture.cfg,
        &mut scanned,
        WalletLogDelta {
            utxos: Vec::new(),
            nullifiers: vec![SpentNullifier {
                tree: input.tree,
                nullifier: input.nullifier(fixture.cfg.scan_keys.nullifying_key),
                source: fixture.candidate.source.clone(),
            }],
            commitment_observations: Vec::new(),
            sender_scan_outputs: Vec::new(),
        },
    );
    let changed = outcome.changed;
    let candidates = outcome
        .sender_scan_candidates
        .into_iter()
        .map(|candidate| {
            candidate
                .into_record(fixture.cfg.chain.chain_id, fixture.cfg.cache_key.clone())
                .expect("sender candidate record")
        })
        .collect::<Vec<_>>();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&fixture.handle, 0, &cancel);
    let permit = authority.acquire().await.expect("wallet authority");
    WalletPersistState::default()
        .persist_progress_with_private_effects(
            fixture.db.as_ref(),
            &permit,
            WalletProgressPersist {
                cache_key: fixture.cfg.cache_key.as_str(),
                snapshot: &scanned,
                last_scanned: fixture.candidate.source.block_number,
                checkpoint: WalletCheckpointMutation::Set {
                    last_scanned_block: fixture.candidate.source.block_number,
                    last_scanned_block_hash: None,
                },
                changed,
            },
            WalletProgressPrivateEffects {
                sender_transaction_candidate_updates: &candidates,
                ..WalletProgressPrivateEffects::default()
            },
        )
        .expect("persist scanned spend");
    drop(permit);
    *fixture.handle.utxos.write().await = scanned;
    candidates
}

/// Mark the fixture's unshield TXID Valid in its local PPOI list, as a corpus sync would.
async fn seed_valid_unshield(fixture: &PartialUnshieldFixture) {
    let corpus = fixture
        .public_data_plane
        .ensure_poi_corpus(PublicPoiCorpusKey::wallet_default(
            fixture.cfg.chain.chain_id,
        ))
        .await
        .expect("POI corpus");
    let local_caches = corpus.local_caches();
    let mut caches = local_caches.write().await;
    let cache = caches
        .get_mut(&fixture.list_key)
        .expect("seeded PPOI list cache");
    let event_index = cache.progress().next_event_index;
    cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index,
            blinded_commitment: fixture.railgun_txid.0,
            signature: [0_u8; 64],
            event_type: PoiEventType::Unshield,
        }])
        .expect("seed Valid unshield");
    cache.accept_current_roots();
}

/// Run one maintenance pass with private commits re-entering a test actor loop.
async fn run_partial_unshield_maintenance(
    fixture: &PartialUnshieldFixture,
    unshield_attempts: &SenderUnshieldAttempts,
) -> super::super::SenderCandidateRecoveryReport {
    let cancel = CancellationToken::new();
    let private_poi = WalletPrivatePoiClients::for_test(
        WalletPrivateMutationAuthority::new(&fixture.handle, 0, &cancel).remote_authority(),
        Arc::new(RecordingPoiStatusClient::default()),
        fixture.submitter.clone(),
    )
    .with_submission_routing(
        fixture.routing.clone(),
        DeferredForcedSubmissions::default(),
    );
    let poi_runtime = test_artifact_poi_runtime();
    let forest = Arc::new(RwLock::new(MerkleForest::new()));
    let active_list_keys = [fixture.list_key];
    let (apply_tx, mut apply_rx) = mpsc::channel(1);
    let apply_client = WalletPrivateApplyClient::new(apply_tx);
    let authority = WalletPrivateMutationAuthority::new(&fixture.handle, 0, &cancel)
        .with_apply_client(&apply_client);
    let actor = fixture.apply_private_commits(&mut apply_rx, &cancel);
    let maintenance = (OutputPoiRecoveryRun {
        authority: &authority,
        db: fixture.db.as_ref(),
        cache_store: fixture.db.as_ref(),
        cfg: &fixture.cfg,
        public_data_plane: &fixture.public_data_plane,
        http_client: None,
        indexed_artifact_source: None,
        poi_runtime: &poi_runtime,
        forest: &forest,
        utxos: &fixture.handle.utxos,
        client: poi_runtime.public_client(),
        private_poi: &private_poi,
        active_list_keys: &active_list_keys,
        force_retry: false,
        unshield_attempts,
    })
    .recover_missing();
    // The apply client outlives maintenance, so the actor loop only ends when maintenance does.
    tokio::select! {
        recovered = maintenance => recovered.candidate_report,
        () = actor => unreachable!("the apply channel stays open during maintenance"),
    }
}

/// Run the unshield step for the stored candidate with `cached_proofs`, with private commits
/// re-entering a test actor loop. `cancel` stands for the job authority's lifecycle.
async fn process_stored_sender_unshields(
    fixture: &PartialUnshieldFixture,
    attempts: &SenderUnshieldAttempts,
    cancel: &CancellationToken,
    cached_proofs: BTreeMap<FixedBytes<32>, (u64, PreTransactionPoiMap)>,
) -> super::super::SenderCandidateRecoveryReport {
    let candidate = fixture.stored_candidate().expect("stored sender candidate");
    let private_poi = WalletPrivatePoiClients::for_test(
        WalletPrivateMutationAuthority::new(&fixture.handle, 0, cancel).remote_authority(),
        Arc::new(RecordingPoiStatusClient::default()),
        fixture.submitter.clone(),
    )
    .with_submission_routing(
        fixture.routing.clone(),
        DeferredForcedSubmissions::default(),
    );
    let poi_runtime = test_artifact_poi_runtime();
    let active_list_keys = [fixture.list_key];
    let (apply_tx, mut apply_rx) = mpsc::channel(1);
    let apply_client = WalletPrivateApplyClient::new(apply_tx);
    let authority = WalletPrivateMutationAuthority::new(&fixture.handle, 0, cancel)
        .with_apply_client(&apply_client);
    let request = OutputPoiRecoveryRequest {
        authority: &authority,
        db: fixture.db.as_ref(),
        cache_store: fixture.db.as_ref(),
        cfg: &fixture.cfg,
        public_data_plane: &fixture.public_data_plane,
        http_client: None,
        indexed_artifact_source: None,
        forest: Arc::new(MerkleForest::new()),
        poi_client: poi_runtime.public_client(),
        private_poi: &private_poi,
        poi_runtime: &poi_runtime,
        active_list_keys: &active_list_keys,
        wallet_utxos: &fixture.wallet_utxos,
        force_retry: false,
    };
    let data_key = DataPlanePublicTxidCacheKey::new(
        ChainScope {
            chain_type: ChainType::Evm,
            chain_id: fixture.cfg.chain.chain_id,
            railgun_contract: fixture.cfg.chain.contract,
        },
        DEFAULT_TXID_VERSION,
    );
    let (rows, row_authority) = fixture
        .public_data_plane
        .txid_transactions_for_outer_hash_with_authority(&data_key, candidate.source.tx_hash)
        .expect("load unshield TXID row");
    let public_data_fence = SenderCandidatePublicDataFence::new(
        &fixture.public_data_plane,
        data_key,
        fixture.public_data_plane.current_epoch(),
        rows,
        row_authority,
    );
    let wallet_nullifiers =
        WalletNullifierIndex::new(&fixture.wallet_utxos, &fixture.cfg.scan_keys);
    let work = async {
        let proof_source_resolution = request.resolve_proof_source(&active_list_keys).await;
        let eligible = BTreeSet::from([fixture.railgun_txid]);
        let valid =
            sender_unshield_valid_txids(&request, &proof_source_resolution, &eligible).await;
        let mut report = super::super::SenderCandidateRecoveryReport::default();
        Box::pin(process_sender_candidate_unshields(
            &request,
            &mut report,
            attempts,
            &mut BTreeSet::new(),
            SenderUnshieldInputs {
                candidate,
                eligible,
                valid,
                qualified: &[],
                wallet_nullifiers: &wallet_nullifiers,
                public_data_fence: &public_data_fence,
                proof_source_resolution: &proof_source_resolution,
                cached_proofs,
            },
        ))
        .await;
        report
    };
    let actor = fixture.apply_private_commits(&mut apply_rx, cancel);
    // The apply client outlives the unshield work, so the actor loop only ends when it does.
    tokio::select! {
        report = work => report,
        () = actor => unreachable!("the apply channel stays open during unshield work"),
    }
}
