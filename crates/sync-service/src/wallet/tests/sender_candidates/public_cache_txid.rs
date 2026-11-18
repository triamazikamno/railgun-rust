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
