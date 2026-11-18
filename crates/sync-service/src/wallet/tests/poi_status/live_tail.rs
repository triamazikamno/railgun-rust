use super::*;

#[tokio::test]
async fn live_poi_tail_applies_public_leaves_and_validates_root() {
    let list_key = FixedBytes::from([7_u8; 32]);
    let blinded_commitment = FixedBytes::from([0x33; 32]);
    let artifact_commitment = FixedBytes::from([0x22; 32]);
    let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
    let mut expected_cache = PoiCache::new(identity.clone());
    expected_cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: *artifact_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply artifact artifact_bound event");
    expected_cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 1,
            blinded_commitment: *blinded_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Shield,
        }])
        .expect("apply expected leaf");
    let expected_root = *expected_cache
        .current_roots()
        .get(&0)
        .expect("expected root");
    let leaves = vec![U256::from_be_bytes(blinded_commitment.0)];
    let mock =
        spawn_poi_rpc_sequence(vec![poi_leaf_response(&leaves), serde_json::json!(true)]).await;
    let client = PoiRpcClient::new(mock.url.clone());
    let mut cache = PoiCache::new(identity);
    cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: *artifact_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply artifact artifact_bound event");
    cache.accept_current_roots();

    let outcome = sync_live_poi_event_tail(&client, &mut cache)
        .await
        .expect("live tail sync");

    let request = mock
        .requests
        .recv_timeout(Duration::from_secs(2))
        .expect("remote leaf request");
    assert_eq!(request["method"], "ppoi_poi_merkletree_leaves");
    let request = mock
        .requests
        .recv_timeout(Duration::from_secs(2))
        .expect("remote root validation request");
    assert_eq!(request["method"], "ppoi_validate_poi_merkleroots");
    assert_eq!(outcome.events, 1);
    assert_eq!(outcome.start_index, 1);
    assert_eq!(outcome.next_event_index, 2);
    assert_eq!(cache.current_roots().get(&0), Some(&expected_root));
    let proof = cache
        .poi_merkle_proofs(&[blinded_commitment])
        .expect("proof after live root validation");
    assert_eq!(proof[0].leaf, U256::from_be_bytes(blinded_commitment.0));
}

#[tokio::test]
async fn live_poi_tail_stops_at_merkle_zero_padding() {
    let list_key = FixedBytes::from([8_u8; 32]);
    let blinded_commitment = FixedBytes::from([0x44; 32]);
    let artifact_commitment = FixedBytes::from([0x22; 32]);
    let zero_leaf = FixedBytes::from(MERKLE_ZERO_VALUE.to_be_bytes::<32>());
    let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
    let mut expected_cache = PoiCache::new(identity.clone());
    expected_cache
        .apply_verified_artifact_events(&[
            poi::artifacts::SnapshotEvent {
                event_index: 0,
                blinded_commitment: *artifact_commitment,
                signature: [0_u8; 64],
                event_type: PoiEventType::Transact,
            },
            poi::artifacts::SnapshotEvent {
                event_index: 1,
                blinded_commitment: *blinded_commitment,
                signature: [0_u8; 64],
                event_type: PoiEventType::Shield,
            },
        ])
        .expect("apply expected leaves");
    let expected_root = *expected_cache
        .current_roots()
        .get(&0)
        .expect("expected root");
    let leaves = vec![
        U256::from_be_bytes(blinded_commitment.0),
        MERKLE_ZERO_VALUE,
        U256::from_be_bytes([0x55; 32]),
    ];
    let mock =
        spawn_poi_rpc_sequence(vec![poi_leaf_response(&leaves), serde_json::json!(true)]).await;
    let client = PoiRpcClient::new(mock.url.clone());
    let mut cache = PoiCache::new(identity);
    cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: *artifact_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply artifact artifact_bound event");
    cache.accept_current_roots();

    let outcome = sync_live_poi_event_tail(&client, &mut cache)
        .await
        .expect("live tail sync");

    assert_eq!(outcome.events, 1);
    assert_eq!(outcome.start_index, 1);
    assert_eq!(outcome.next_event_index, 2);
    assert_eq!(cache.current_roots().get(&0), Some(&expected_root));
    assert!(cache.position(&zero_leaf).is_none());
}

#[test]
fn dense_merkle_tree_matches_forest_proof_and_removal_roots() {
    let mut forest = MerkleForest::default();
    for position in [0_u64, 1, 2, 7, 8, 9, 42] {
        forest
            .insert_leaf(MerkleTreeUpdate {
                tree_number: 0,
                tree_position: position,
                hash: U256::from(position + 100),
            })
            .expect("insert leaf");
    }

    let mut dense = DenseMerkleTree::from_forest_prefix(&forest, 0, 43);
    let dense_proof = dense.prove(7);
    let sparse_proof = forest
        .prove_with_leaf_count(0, 7, 43)
        .expect("sparse proof");
    assert_eq!(dense_proof.root, sparse_proof.root);
    assert_eq!(dense_proof.leaf, sparse_proof.leaf);
    assert_eq!(dense_proof.path_elements, sparse_proof.path_elements);
    assert_eq!(dense_proof.path_indices, sparse_proof.path_indices);

    for position in (10_u64..43).rev() {
        dense.remove_leaf(position);
    }
    let dense_short_proof = dense.prove(7);
    let sparse_short_proof = forest
        .prove_with_leaf_count(0, 7, 10)
        .expect("sparse short proof");
    assert_eq!(dense_short_proof.root, sparse_short_proof.root);
    assert_eq!(
        dense_short_proof.path_elements,
        sparse_short_proof.path_elements
    );
}

#[tokio::test]
async fn tailed_cache_install_skips_when_current_cache_advanced() {
    let list_key = FixedBytes::from([0x11; 32]);
    let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
    let initial_commitment = FixedBytes::from([0x22; 32]);
    let stale_tail_commitment = FixedBytes::from([0x33; 32]);
    let current_tail_commitment = FixedBytes::from([0x44; 32]);

    let mut initial_cache = PoiCache::new(identity);
    initial_cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: *initial_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply initial event");
    initial_cache.accept_current_roots();
    let original_next_event_index = initial_cache.progress().next_event_index;

    let local_caches =
        WalletLocalPoiCaches::new_for_test(BTreeMap::from([(list_key, initial_cache.clone())]));
    let mut stale_tail_cache = initial_cache;
    stale_tail_cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 1,
            blinded_commitment: *stale_tail_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply stale tail event");

    {
        let mut locked = local_caches.write().await;
        let current = locked.get_mut(&list_key).expect("current cache");
        current
            .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
                event_index: 1,
                blinded_commitment: *current_tail_commitment,
                signature: [0_u8; 64],
                event_type: PoiEventType::Transact,
            }])
            .expect("advance current cache");
        current.accept_current_roots();
    }

    let installed = install_tailed_poi_cache_if_current(
        &local_caches,
        list_key,
        stale_tail_cache,
        original_next_event_index,
    )
    .await;

    let locked = local_caches.read().await;
    let current = locked.get(&list_key).expect("current cache");
    assert!(!installed);
    assert!(current.position(&current_tail_commitment).is_some());
    assert!(current.position(&stale_tail_commitment).is_none());
}

fn poi_leaf_response(leaves: &[U256]) -> serde_json::Value {
    serde_json::to_value(
        leaves
            .iter()
            .map(|leaf| format!("0x{leaf:064x}"))
            .collect::<Vec<_>>(),
    )
    .expect("leaves JSON")
}
