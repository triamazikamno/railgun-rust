use super::*;

#[tokio::test]
async fn txid_public_cache_skips_unavailable_artifact_when_local_cache_is_sufficient() {
    let root_dir = temp_db_root();
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let key = TxidPublicCacheKey {
        chain_type: 0,
        chain_id: 1,
        railgun_contract: artifact_scope().railgun_contract,
        txid_version: "V2_PoseidonMerkle",
    };
    let cache = TxidPublicCache::new(&db, key);
    let row = indexed_transaction(0x21, 0x02, 0x01, 0x03);
    let root = root_for_single_leaf(row.txid_leaf_hash());
    let artifact_chunk = public_txid_artifact_chunk(0, std::slice::from_ref(&row), Some(root));
    let (artifact_source, _artifact_server) = public_txid_artifact_source(vec![artifact_chunk]);

    cache
        .sync_with_artifact_source(
            None,
            None,
            TxidPublicLatestValidated {
                txid_index: 0,
                merkleroot: Some(root),
            },
            Some(&artifact_source),
        )
        .await
        .expect("seed artifact-only validated cache");

    let unavailable_source = unavailable_artifact_source();
    cache
        .sync_with_artifact_source(
            None,
            None,
            TxidPublicLatestValidated {
                txid_index: 0,
                merkleroot: Some(root),
            },
            Some(&unavailable_source),
        )
        .await
        .expect("sufficient local cache should avoid artifact fetch");

    let proof =
        txid_public_proof_for_recovered_output(&db, key, row.txid_leaf_hash(), 0, 0, Some(root))
            .expect("local proof should still be available");
    assert_eq!(proof.target_txid_index, 0);

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_artifact_bounded_proof_survives_restart_and_stops_at_bound() {
    let root_dir = temp_db_root();
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let key = test_cache_key();
    let first = indexed_transaction(0x61, 0x02, 0x01, 0x03);
    let second = indexed_transaction(0x62, 0x04, 0x05, 0x06);
    let second_leaf = second.txid_leaf_hash();
    let second_output_start = second.output_start_global();
    let root = txid_root_for_transactions(&[first.clone(), second.clone()]);
    let chunk = public_txid_artifact_chunk(0, &[first.clone(), second.clone()], Some(root));
    let (source, _server) = public_txid_artifact_source(vec![chunk]);
    let cache = TxidPublicCache::new(&db, key);

    cache
        .sync_to_indexed_tip(None, None, Some(&source))
        .await
        .expect("apply verified artifact bound");
    let proof = txid_public_artifact_bounded_proof(
        &db,
        key,
        None,
        first.txid_leaf_hash(),
        first.output_start_global(),
    )
    .expect("unknown target should use artifact bound");
    assert_eq!(proof.root_txid_index, 1);

    drop(db);
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("reopen db");
    let proof =
        txid_public_artifact_bounded_proof(&db, key, Some(1), second_leaf, second_output_start)
            .expect("known target should use artifact bound after restart");
    assert_eq!(proof.root_txid_index, 1);
    let after_bound = txid_public_artifact_bounded_proof(
        &db,
        key,
        Some(2),
        first.txid_leaf_hash(),
        first.output_start_global(),
    );
    assert!(matches!(
        after_bound,
        Err(crate::txid_cache::TxidPublicCacheError::CacheNotReady {
            required_index: 2,
            ..
        })
    ));

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_cache_accepts_rootless_same_index_latest_from_local_rows() {
    let root_dir = temp_db_root();
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let key = TxidPublicCacheKey {
        chain_type: 0,
        chain_id: 1,
        railgun_contract: artifact_scope().railgun_contract,
        txid_version: TEST_TXID_VERSION,
    };
    let cache = TxidPublicCache::new(&db, key);
    let row = indexed_transaction(0x31, 0x02, 0x01, 0x03);
    let root = root_for_single_leaf(row.txid_leaf_hash());
    let artifact_chunk = public_txid_artifact_chunk(0, std::slice::from_ref(&row), Some(root));
    let (artifact_source, _artifact_server) = public_txid_artifact_source(vec![artifact_chunk]);

    cache
        .sync_with_artifact_source(
            None,
            None,
            TxidPublicLatestValidated {
                txid_index: 0,
                merkleroot: Some(root),
            },
            Some(&artifact_source),
        )
        .await
        .expect("seed rooted latest marker and local row");

    let permit = cache.begin_write().await;
    let mut legacy_manifest = cache
        .load_or_new_manifest()
        .expect("load rooted legacy manifest");
    legacy_manifest.checkpoints.clear();
    legacy_manifest
        .write_to(&permit)
        .expect("write rooted legacy manifest");
    drop(permit);

    let unavailable_source = unavailable_artifact_source();
    cache
        .sync_with_artifact_source(
            None,
            None,
            TxidPublicLatestValidated {
                txid_index: 0,
                merkleroot: Some(root),
            },
            Some(&unavailable_source),
        )
        .await
        .expect("rooted legacy manifest should backfill latest checkpoint");
    let migrated_manifest = cache
        .load_manifest()
        .expect("load migrated rooted manifest")
        .expect("migrated rooted manifest present");
    assert_eq!(migrated_manifest.checkpoints.len(), 1);
    assert_eq!(
        migrated_manifest
            .checkpoints
            .get(&0)
            .map(|checkpoint| checkpoint.merkleroot),
        Some(root)
    );

    cache
        .sync_with_artifact_source(
            None,
            None,
            TxidPublicLatestValidated {
                txid_index: 0,
                merkleroot: None,
            },
            Some(&unavailable_source),
        )
        .await
        .expect("rootless same-index latest should be certified from readable local rows");

    let manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    assert_eq!(manifest.latest_validated_txid_index, Some(0));
    assert_eq!(manifest.latest_validated_merkleroot, None);
    assert_eq!(manifest.validated_cached_txid_index, Some(0));
    let cached_latest = cache
        .cached_latest_validated()
        .expect("read certified latest")
        .expect("latest marker present");
    assert_eq!(cached_latest.txid_index, 0);
    assert_eq!(cached_latest.merkleroot, None);

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_cache_skips_unavailable_artifact_when_background_cache_is_sufficient() {
    let root_dir = temp_db_root();
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let key = TxidPublicCacheKey {
        chain_type: 0,
        chain_id: 1,
        railgun_contract: artifact_scope().railgun_contract,
        txid_version: "V2_PoseidonMerkle",
    };
    let cache = TxidPublicCache::new(&db, key);
    let row = indexed_transaction(0x41, 0x02, 0x01, 0x03);
    let root = root_for_single_leaf(row.txid_leaf_hash());
    let artifact_chunk = public_txid_artifact_chunk(0, std::slice::from_ref(&row), Some(root));
    let (artifact_source, _artifact_server) = public_txid_artifact_source(vec![artifact_chunk]);

    let fetched = cache
        .sync_to_indexed_tip(None, None, Some(&artifact_source))
        .await
        .expect("seed background artifact cache");
    assert_eq!(fetched, 1);
    let seeded_manifest = cache
        .load_manifest()
        .expect("load seeded manifest")
        .expect("seeded manifest present");
    assert_eq!(seeded_manifest.validated_cached_txid_index, Some(0));
    assert_eq!(seeded_manifest.latest_validated_txid_index, None);
    assert_eq!(seeded_manifest.latest_validated_merkleroot, None);

    let unavailable_source = unavailable_artifact_source();
    cache
        .sync_with_artifact_source(
            None,
            None,
            TxidPublicLatestValidated {
                txid_index: 0,
                merkleroot: Some(root),
            },
            Some(&unavailable_source),
        )
        .await
        .expect("background cache should satisfy latest validation without artifact fetch");

    let manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    assert_eq!(manifest.latest_validated_txid_index, Some(0));
    assert_eq!(manifest.latest_validated_merkleroot, Some(root));
    let proof =
        txid_public_proof_for_recovered_output(&db, key, row.txid_leaf_hash(), 0, 0, Some(root))
            .expect("local proof should still be available");
    assert_eq!(proof.target_txid_index, 0);

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_cache_rollback_preserves_persisted_suffix_and_artifact_provenance() {
    let root_dir = temp_db_root();
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let key = TxidPublicCacheKey {
        chain_type: 0,
        chain_id: 1,
        railgun_contract: artifact_scope().railgun_contract,
        txid_version: "V2_PoseidonMerkle",
    };
    let cache = TxidPublicCache::new(&db, key);
    let first = indexed_transaction(0x41, 0x02, 0x01, 0x03);
    let second = indexed_transaction(0x42, 0x04, 0x05, 0x06);
    let root = txid_root_for_transactions(&[first.clone(), second.clone()]);
    let rollback_root = root_for_single_leaf(first.txid_leaf_hash());
    let artifact_chunk =
        public_txid_artifact_chunk(0, &[first.clone(), second.clone()], Some(root));
    let (artifact_source, _artifact_server) = public_txid_artifact_source(vec![artifact_chunk]);

    cache
        .sync_with_artifact_source(
            None,
            None,
            TxidPublicLatestValidated {
                txid_index: 1,
                merkleroot: Some(root),
            },
            Some(&artifact_source),
        )
        .await
        .expect("seed artifact-only cache above rollback point");

    let unavailable_source = unavailable_artifact_source();
    cache
        .sync_with_artifact_source(
            None,
            None,
            TxidPublicLatestValidated {
                txid_index: 0,
                merkleroot: Some(rollback_root),
            },
            Some(&unavailable_source),
        )
        .await
        .expect("sufficient local cache should satisfy lower latest");

    let manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    assert_eq!(manifest.latest_validated_txid_index, Some(0));
    assert_eq!(manifest.latest_validated_merkleroot, Some(rollback_root));
    assert_eq!(manifest.validated_cached_txid_index, Some(0));
    assert_eq!(manifest.artifact_cached_txid_index, Some(1));
    assert_eq!(manifest.next_txid_index, 2);
    assert!(
        row_for_txid_index(&manifest, &db, 1)
            .expect("read retained suffix")
            .is_some_and(|row| row.transaction.transaction_hash == second.transaction_hash)
    );
    assert_eq!(
        index_entries_for_hash(&db, key, second.transaction_hash)
            .expect("read retained suffix index")
            .len(),
        1
    );
    let proof = txid_public_proof_for_recovered_output(
        &db,
        key,
        first.txid_leaf_hash(),
        0,
        0,
        Some(rollback_root),
    )
    .expect("clamped validated prefix should still be usable");
    assert_eq!(proof.target_txid_index, 0);

    drop(db);
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("reopen db after rollback");
    let cache = TxidPublicCache::new(&db, key);
    let manifest = cache
        .load_manifest()
        .expect("load reopened manifest")
        .expect("reopened manifest present");
    assert_eq!(manifest.artifact_cached_txid_index, Some(1));
    assert_eq!(manifest.next_txid_index, 2);
    assert!(
        row_for_txid_index(&manifest, &db, 1)
            .expect("read reopened retained suffix")
            .is_some_and(|row| row.transaction.transaction_hash == second.transaction_hash)
    );

    let canonical = indexed_transaction(0x43, 0x07, 0x08, 0x09);
    let (endpoint, _requests) =
        spawn_graphql_response(public_txid_response(std::slice::from_ref(&canonical)));
    cache
        .sync_to_graph_tip(&endpoint, None)
        .await
        .expect("reacquire canonical row after rollback");
    let manifest = cache
        .load_manifest()
        .expect("load manifest after canonical reacquisition")
        .expect("manifest after canonical reacquisition present");
    assert_eq!(manifest.next_txid_index, 3);
    assert_eq!(
        row_for_txid_index(&manifest, &db, 1)
            .expect("read retained suffix after append")
            .expect("retained suffix present")
            .transaction
            .transaction_hash,
        second.transaction_hash
    );
    assert_eq!(
        row_for_txid_index(&manifest, &db, 2)
            .expect("read appended canonical row")
            .expect("appended canonical row present")
            .transaction
            .transaction_hash,
        canonical.transaction_hash
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_cache_returns_not_ready_for_root_mismatch_without_correction() {
    let root_dir = temp_db_root();
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let key = TxidPublicCacheKey {
        chain_type: 0,
        chain_id: 1,
        railgun_contract: artifact_scope().railgun_contract,
        txid_version: "V2_PoseidonMerkle",
    };
    let cache = TxidPublicCache::new(&db, key);
    let stale_row = indexed_transaction(0x41, 0x02, 0x01, 0x03);
    let stale_root = root_for_single_leaf(stale_row.txid_leaf_hash());
    let stale_chunk =
        public_txid_artifact_chunk(0, std::slice::from_ref(&stale_row), Some(stale_root));
    let (stale_source, _stale_server) = public_txid_artifact_source(vec![stale_chunk]);
    let fetched = cache
        .sync_to_indexed_tip(None, None, Some(&stale_source))
        .await
        .expect("seed background artifact cache");
    assert_eq!(fetched, 1);
    let seeded_manifest = cache
        .load_manifest()
        .expect("load seeded manifest")
        .expect("seeded manifest present");
    assert_eq!(seeded_manifest.validated_cached_txid_index, Some(0));
    assert_eq!(seeded_manifest.latest_validated_txid_index, None);
    assert_eq!(seeded_manifest.latest_validated_merkleroot, None);

    let corrected_row = indexed_transaction(0x42, 0x04, 0x05, 0x06);
    let corrected_root = root_for_single_leaf(corrected_row.txid_leaf_hash());
    assert_ne!(stale_root, corrected_root);
    let (empty_source, _empty_server) = public_txid_empty_artifact_source();
    let error = cache
        .sync_with_artifact_source(
            None,
            None,
            TxidPublicLatestValidated {
                txid_index: 0,
                merkleroot: Some(corrected_root),
            },
            Some(&empty_source),
        )
        .await
        .expect_err("mismatched high-water cache should remain not ready without correction");
    assert!(matches!(
        error,
        crate::txid_cache::TxidPublicCacheError::CacheNotReady {
            next_index: 0,
            required_index: 0,
        }
    ));

    let manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    assert_eq!(manifest.validated_cached_txid_index, None);
    assert_eq!(manifest.latest_validated_txid_index, None);
    assert_eq!(manifest.latest_validated_merkleroot, None);
    assert_eq!(manifest.artifact_cached_txid_index, None);
    let row = row_for_txid_index(&manifest, &db, 0)
        .expect("read stale row")
        .expect("stale row present");
    assert_eq!(row.transaction.transaction_hash, stale_row.transaction_hash);

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_cache_background_falls_back_to_graphql_after_zero_artifact_progress() {
    let root_dir = temp_db_root();
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let key = TxidPublicCacheKey {
        chain_type: 0,
        chain_id: 1,
        railgun_contract: artifact_scope().railgun_contract,
        txid_version: "V2_PoseidonMerkle",
    };
    let cache = TxidPublicCache::new(&db, key);
    let later_artifact_row = indexed_transaction(0x51, 0x02, 0x01, 0x03);
    let later_chunk = public_txid_artifact_chunk(1000, &[later_artifact_row], None);
    let (artifact_source, _artifact_server) = public_txid_artifact_source(vec![later_chunk]);
    let graph_row = indexed_transaction(0x52, 0x04, 0x05, 0x06);
    let (graph_endpoint, graph_requests) =
        spawn_graphql_response(public_txid_response(std::slice::from_ref(&graph_row)));

    let fetched = cache
        .sync_to_indexed_tip(Some(&graph_endpoint), None, Some(&artifact_source))
        .await
        .expect("GraphQL fallback should fill the missing prefix");

    assert_eq!(fetched, 1);
    let manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    assert_eq!(manifest.next_txid_index, 1);
    assert_eq!(manifest.artifact_cached_txid_index, None);
    let request = graph_requests
        .recv_timeout(Duration::from_secs(5))
        .expect("GraphQL fallback request received");
    assert!(request.contains("PublicTxidPage"));

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_cache_truncates_artifact_chunk_past_latest_validated() {
    let root_dir = temp_db_root();
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let key = TxidPublicCacheKey {
        chain_type: 0,
        chain_id: 1,
        railgun_contract: artifact_scope().railgun_contract,
        txid_version: "V2_PoseidonMerkle",
    };
    let cache = TxidPublicCache::new(&db, key);
    let first = indexed_transaction(0x21, 0x02, 0x01, 0x03);
    let second = indexed_transaction(0x22, 0x04, 0x05, 0x06);
    let first_root = txid_root_for_transactions(std::slice::from_ref(&first));
    let chunk_root = txid_root_for_transactions(&[first.clone(), second.clone()]);
    let artifact_chunk = public_txid_artifact_chunk(0, &[first.clone(), second], Some(chunk_root));
    let (artifact_source, _artifact_server) = public_txid_artifact_source(vec![artifact_chunk]);
    let graph_endpoint = Url::parse("http://127.0.0.1:1/graphql").expect("unused mock URL");

    cache
        .sync_with_artifact_source(
            Some(&graph_endpoint),
            None,
            TxidPublicLatestValidated {
                txid_index: 0,
                merkleroot: Some(first_root),
            },
            Some(&artifact_source),
        )
        .await
        .expect("artifact prefix should populate only the validated row");

    let manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    assert_eq!(manifest.validated_cached_txid_index, Some(0));
    assert_eq!(manifest.artifact_cached_txid_index, Some(0));
    assert_eq!(manifest.next_txid_index, 1);
    let row = row_for_txid_index(&manifest, &db, 0)
        .expect("read validated prefix row")
        .expect("validated prefix row present");
    assert_eq!(row.transaction.transaction_hash, first.transaction_hash);
    assert!(
        row_for_txid_index(&manifest, &db, 1)
            .expect("read unvalidated tail row")
            .is_none()
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_artifact_prefix_survives_squid_tail_failure() {
    let root_dir = temp_db_root();
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let key = test_cache_key();
    let first = indexed_transaction(0x41, 0x02, 0x01, 0x03);
    let second = indexed_transaction(0x42, 0x04, 0x05, 0x06);
    let first_root = root_for_single_leaf(first.txid_leaf_hash());
    let latest_root = txid_root_for_transactions(&[first.clone(), second]);
    let first_chunk = public_txid_artifact_chunk(0, std::slice::from_ref(&first), Some(first_root));
    let (artifact_source, _artifact_server) = public_txid_artifact_source(vec![first_chunk]);
    let (endpoint, _requests) = spawn_graphql_response(public_txid_response(&[]));
    let cache = TxidPublicCache::new(&db, key);

    let error = cache
        .sync_with_artifact_source(
            Some(&endpoint),
            None,
            TxidPublicLatestValidated {
                txid_index: 1,
                merkleroot: Some(latest_root),
            },
            Some(&artifact_source),
        )
        .await
        .expect_err("missing Squid tail must fail after artifact prefix progress");
    assert!(matches!(
        error,
        crate::txid_cache::TxidPublicCacheError::CacheNotReady {
            next_index: 1,
            required_index: 1,
        }
    ));
    let manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("artifact prefix manifest persisted");
    assert_eq!(manifest.validated_cached_txid_index, Some(0));
    assert_eq!(manifest.artifact_cached_txid_index, Some(0));
    assert_eq!(
        row_for_txid_index(&manifest, &db, 0)
            .expect("read artifact prefix")
            .expect("artifact prefix row present")
            .transaction
            .transaction_hash,
        first.transaction_hash
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_cache_artifact_only_partial_prefix_has_no_provenance_marker() {
    let root_dir = temp_db_root();
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let key = TxidPublicCacheKey {
        chain_type: 0,
        chain_id: 1,
        railgun_contract: artifact_scope().railgun_contract,
        txid_version: "V2_PoseidonMerkle",
    };
    let cache = TxidPublicCache::new(&db, key);
    let first = indexed_transaction(0x21, 0x02, 0x01, 0x03);
    let second = indexed_transaction(0x22, 0x04, 0x05, 0x06);
    let chunk_root = txid_root_for_transactions(&[first.clone(), second.clone()]);
    let spanning_chunk = public_txid_artifact_chunk(0, &[first.clone(), second], Some(chunk_root));
    let (artifact_source, _artifact_server) = public_txid_artifact_source(vec![spanning_chunk]);

    let error = cache
        .sync_with_artifact_source(
            None,
            None,
            TxidPublicLatestValidated {
                txid_index: 0,
                merkleroot: None,
            },
            Some(&artifact_source),
        )
        .await
        .expect_err("artifact-only partial progress needs an authoritative bounded root");
    assert!(matches!(
        error,
        crate::txid_cache::TxidPublicCacheError::CacheNotReady {
            next_index: 0,
            required_index: 0,
        }
    ));

    let manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    assert_eq!(manifest.validated_cached_txid_index, Some(0));
    assert_eq!(manifest.artifact_cached_txid_index, None);
    assert_eq!(manifest.next_txid_index, 1);
    let row = row_for_txid_index(&manifest, &db, 0)
        .expect("read validated prefix row")
        .expect("validated prefix row present");
    assert_eq!(row.transaction.transaction_hash, first.transaction_hash);
    assert!(
        row_for_txid_index(&manifest, &db, 1)
            .expect("read unvalidated tail row")
            .is_none()
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_cache_artifact_only_advances_from_inside_chunk() {
    let root_dir = temp_db_root();
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let key = TxidPublicCacheKey {
        chain_type: 0,
        chain_id: 1,
        railgun_contract: artifact_scope().railgun_contract,
        txid_version: "V2_PoseidonMerkle",
    };
    let cache = TxidPublicCache::new(&db, key);
    let first = indexed_transaction(0x31, 0x02, 0x01, 0x03);
    let second = indexed_transaction(0x32, 0x04, 0x05, 0x06);
    let first_root = txid_root_for_transactions(std::slice::from_ref(&first));
    let first_chunk = public_txid_artifact_chunk(0, std::slice::from_ref(&first), Some(first_root));
    let (first_source, _first_server) = public_txid_artifact_source(vec![first_chunk]);
    cache
        .sync_with_artifact_source(
            None,
            None,
            TxidPublicLatestValidated {
                txid_index: 0,
                merkleroot: Some(first_root),
            },
            Some(&first_source),
        )
        .await
        .expect("seed artifact-only validated row");

    let chunk_root = txid_root_for_transactions(&[first.clone(), second.clone()]);
    let (empty_source, _empty_server) = public_txid_empty_artifact_source();
    let error = cache
        .sync_with_artifact_source(
            None,
            None,
            TxidPublicLatestValidated {
                txid_index: 1,
                merkleroot: Some(chunk_root),
            },
            Some(&empty_source),
        )
        .await
        .expect_err("short artifact marker should retry after available progress is exhausted");
    assert!(matches!(
        error,
        crate::txid_cache::TxidPublicCacheError::CacheNotReady {
            next_index: 1,
            required_index: 1,
        }
    ));

    let covering_chunk = public_txid_artifact_chunk(0, &[first, second.clone()], Some(chunk_root));
    let (covering_source, _covering_server) = public_txid_artifact_source(vec![covering_chunk]);
    cache
        .sync_with_artifact_source(
            None,
            None,
            TxidPublicLatestValidated {
                txid_index: 1,
                merkleroot: Some(chunk_root),
            },
            Some(&covering_source),
        )
        .await
        .expect("artifact-only overlapping chunk should advance cache");

    let manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    assert_eq!(manifest.validated_cached_txid_index, Some(1));
    assert_eq!(manifest.next_txid_index, 2);
    let row = row_for_txid_index(&manifest, &db, 1)
        .expect("read overlapped artifact row")
        .expect("overlapped artifact row present");
    assert_eq!(row.transaction.transaction_hash, second.transaction_hash);

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_cache_artifact_only_refreshes_changed_validated_root() {
    let root_dir = temp_db_root();
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let key = TxidPublicCacheKey {
        chain_type: 0,
        chain_id: 1,
        railgun_contract: artifact_scope().railgun_contract,
        txid_version: "V2_PoseidonMerkle",
    };
    let cache = TxidPublicCache::new(&db, key);
    let old_row = indexed_transaction(0x31, 0x02, 0x01, 0x03);
    let old_root = root_for_single_leaf(old_row.txid_leaf_hash());
    let old_chunk = public_txid_artifact_chunk(0, std::slice::from_ref(&old_row), Some(old_root));
    let (old_source, _old_server) = public_txid_artifact_source(vec![old_chunk]);
    cache
        .sync_with_artifact_source(
            None,
            None,
            TxidPublicLatestValidated {
                txid_index: 0,
                merkleroot: Some(old_root),
            },
            Some(&old_source),
        )
        .await
        .expect("seed artifact-only validated row");

    let new_row = indexed_transaction(0x32, 0x04, 0x05, 0x06);
    let new_root = root_for_single_leaf(new_row.txid_leaf_hash());
    let new_chunk = public_txid_artifact_chunk(0, std::slice::from_ref(&new_row), Some(new_root));
    let (new_source, _new_server) = public_txid_artifact_source(vec![new_chunk]);
    cache
        .sync_with_artifact_source(
            None,
            None,
            TxidPublicLatestValidated {
                txid_index: 0,
                merkleroot: Some(new_root),
            },
            Some(&new_source),
        )
        .await
        .expect("changed validated root should refresh artifact-only row");

    let manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    assert_eq!(manifest.latest_validated_merkleroot, Some(new_root));
    assert_eq!(manifest.validated_cached_txid_index, Some(0));
    let row = row_for_txid_index(&manifest, &db, 0)
        .expect("read refreshed row")
        .expect("refreshed row present");
    assert_eq!(row.transaction.transaction_hash, new_row.transaction_hash);

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_legacy_markerless_cache_fetches_artifacts_from_zero() {
    let root_dir = temp_db_root();
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let key = test_cache_key();
    let row = indexed_transaction(0xa1, 0x02, 0x01, 0x03);
    let root = root_for_single_leaf(row.txid_leaf_hash());
    let chunk = public_txid_artifact_chunk(0, std::slice::from_ref(&row), Some(root));
    let (artifact_source, artifact_server) = public_txid_artifact_source(vec![chunk]);
    let cache = TxidPublicCache::new(&db, key);

    seed_validated_pages(&db, key, vec![vec![row.clone()]]).await;

    cache
        .sync_with_artifact_source(
            None,
            None,
            TxidPublicLatestValidated {
                txid_index: 0,
                merkleroot: Some(root),
            },
            Some(&artifact_source),
        )
        .await
        .expect("legacy markerless cache should establish artifact provenance");

    let manifest = cache
        .load_manifest()
        .expect("load migrated manifest")
        .expect("migrated manifest present");
    assert_eq!(manifest.artifact_cached_txid_index, Some(0));
    assert_eq!(
        row_for_txid_index(&manifest, &db, 0)
            .expect("read migrated row")
            .expect("migrated row present")
            .transaction
            .transaction_hash,
        row.transaction_hash
    );
    assert!(artifact_server.request_count_excluding(&["/manifest"]) > 0);

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_cache_falls_back_to_graphql_when_artifact_descriptors_are_unavailable() {
    let root_dir = temp_db_root();
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let key = TxidPublicCacheKey {
        chain_type: 0,
        chain_id: 1,
        railgun_contract: artifact_scope().railgun_contract,
        txid_version: "V2_PoseidonMerkle",
    };
    let cache = TxidPublicCache::new(&db, key);
    let graph_row = indexed_transaction(0x55, 0x04, 0x05, 0x06);
    let graph_root = root_for_single_leaf(graph_row.txid_leaf_hash());
    let (artifact_source, _artifact_server) = public_txid_empty_artifact_source();
    let (graph_endpoint, graph_requests) =
        spawn_graphql_response(public_txid_response(std::slice::from_ref(&graph_row)));

    cache
        .sync_with_artifact_source(
            Some(&graph_endpoint),
            None,
            TxidPublicLatestValidated {
                txid_index: 0,
                merkleroot: Some(graph_root),
            },
            Some(&artifact_source),
        )
        .await
        .expect("GraphQL fallback should populate cache");

    let manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    assert_eq!(manifest.validated_cached_txid_index, Some(0));
    let row = row_for_txid_index(&manifest, &db, 0)
        .expect("read fallback row")
        .expect("fallback row present");
    assert_eq!(row.transaction.transaction_hash, graph_row.transaction_hash);
    let request = graph_requests
        .recv_timeout(Duration::from_secs(5))
        .expect("GraphQL fallback request received");
    assert!(request.contains("PublicTxidPage"));

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
