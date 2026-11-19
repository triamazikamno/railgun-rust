use super::*;

#[tokio::test]
async fn txid_public_background_does_not_retain_superseded_prior_tail() {
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
    let first = indexed_transaction(0x70, 0x02, 0x01, 0x03);
    let first_root = root_for_single_leaf(first.txid_leaf_hash());
    let seed_chunk = public_txid_artifact_chunk(0, std::slice::from_ref(&first), Some(first_root));
    let (seed_source, _seed_server) = public_txid_artifact_source(vec![seed_chunk]);
    cache
        .sync_with_artifact_source(
            None,
            None,
            TxidPublicLatestValidated {
                txid_index: 0,
                merkleroot: Some(first_root),
            },
            Some(&seed_source),
        )
        .await
        .expect("seed first validated row");

    let prior_tail = public_txid_artifact_chunk(0, std::slice::from_ref(&first), Some(first_root));
    let retained_cid = raw_cid(&prior_tail.bytes).to_string();
    let second = indexed_transaction(0x71, 0x04, 0x05, 0x06);
    let prefix_root = txid_root_for_transactions(&[first.clone(), second.clone()]);
    let current_chunk =
        public_txid_artifact_chunk(1, std::slice::from_ref(&second), Some(prefix_root));
    let (source, _server) = public_txid_artifact_source_with_catalogs(vec![
        (1, vec![prior_tail.clone()]),
        (2, vec![prior_tail, current_chunk]),
    ]);

    let fetched = cache
        .sync_to_indexed_tip(None, None, Some(&source))
        .await
        .expect("current chunk should apply without prior-tail maintenance");

    assert_eq!(fetched, 1);
    let manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    assert_eq!(manifest.validated_cached_txid_index, Some(1));
    let second_row = row_for_txid_index(&manifest, &db, 1)
        .expect("read current row")
        .expect("current row present");
    assert_eq!(
        second_row.transaction.transaction_hash,
        second.transaction_hash
    );
    assert!(
        db.get_blob_meta(
            crate::txid_cache::TXID_CACHE_BLOB_KIND,
            &crate::txid_cache::artifact_chunk_blob_id(key, &retained_cid),
        )
        .expect("read prior-tail chunk metadata")
        .is_none(),
        "superseded prior tails must not be fetched solely for retention"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_background_does_not_retain_unsealed_final_chunk() {
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
    let row = indexed_transaction(0x76, 0x02, 0x01, 0x03);
    let root = root_for_single_leaf(row.txid_leaf_hash());
    let chunk = public_txid_artifact_chunk(0, std::slice::from_ref(&row), Some(root));
    let cid = raw_cid(&chunk.bytes).to_string();
    let (source, _server) = public_txid_artifact_source(vec![chunk]);

    assert_eq!(
        cache
            .sync_to_indexed_tip(None, None, Some(&source))
            .await
            .expect("background artifact sync"),
        1
    );

    assert!(
        db.get_blob_meta(
            crate::txid_cache::TXID_CACHE_BLOB_KIND,
            &crate::txid_cache::artifact_chunk_blob_id(key, &cid),
        )
        .expect("read transient chunk metadata")
        .is_none(),
        "planner-classified transient final chunks must not be retained"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_ignores_speculative_lifecycle_flags_on_final_chunk() {
    for stream_complete in [false, true] {
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
        let row = indexed_transaction(0x77 + u8::from(stream_complete), 0x02, 0x01, 0x03);
        let root = root_for_single_leaf(row.txid_leaf_hash());
        let mut chunk = public_txid_artifact_chunk(0, std::slice::from_ref(&row), Some(root));
        chunk.descriptor.metadata.stream_complete = stream_complete;
        chunk.descriptor.metadata.chunk_sealed = !stream_complete;
        let cid = raw_cid(&chunk.bytes).to_string();
        let (source, _server) = public_txid_artifact_source(vec![chunk]);

        cache
            .sync_with_artifact_source(
                None,
                None,
                TxidPublicLatestValidated {
                    txid_index: 0,
                    merkleroot: Some(root),
                },
                Some(&source),
            )
            .await
            .expect("validated format-v1 artifact sync");

        assert!(
            db.get_blob_meta(
                crate::txid_cache::TXID_CACHE_BLOB_KIND,
                &crate::txid_cache::artifact_chunk_blob_id(key, &cid),
            )
            .expect("read final chunk metadata")
            .is_none(),
            "format-v1 sealing and completion flags must not change retention"
        );

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }
}

#[tokio::test]
async fn txid_public_second_unchanged_cycle_fetches_no_chunks() {
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
    let first = indexed_transaction(0x79, 0x02, 0x01, 0x03);
    let second = indexed_transaction(0x7a, 0x04, 0x05, 0x06);
    let first_root = root_for_single_leaf(first.txid_leaf_hash());
    let prefix_root = txid_root_for_transactions(&[first.clone(), second.clone()]);
    let first_chunk = public_txid_artifact_chunk(0, std::slice::from_ref(&first), Some(first_root));
    let first_path = ipfs_car_path(&raw_cid(&first_chunk.bytes));
    let second_chunk =
        public_txid_artifact_chunk(1, std::slice::from_ref(&second), Some(prefix_root));
    let second_path = ipfs_car_path(&raw_cid(&second_chunk.bytes));
    let (source, server) = public_txid_artifact_source(vec![first_chunk, second_chunk]);

    cache
        .sync_to_indexed_tip(None, None, Some(&source))
        .await
        .expect("first background cycle");
    let first_requests = server.request_count(&first_path);
    let second_requests = server.request_count(&second_path);
    let catalog_requests =
        server.request_count_excluding(&["/manifest", first_path.as_str(), second_path.as_str()]);

    assert_eq!(
        cache
            .sync_to_indexed_tip(None, None, Some(&source))
            .await
            .expect("second background cycle"),
        0
    );
    assert_eq!(server.request_count(&first_path), first_requests);
    assert_eq!(server.request_count(&second_path), second_requests);
    assert_eq!(
        server.request_count_excluding(&["/manifest", first_path.as_str(), second_path.as_str(),]),
        catalog_requests,
        "a locally sufficient unchanged cycle need not inspect catalogs"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_corrupt_retained_blob_is_refetched() {
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
    let first = indexed_transaction(0x7b, 0x02, 0x01, 0x03);
    let second = indexed_transaction(0x7c, 0x04, 0x05, 0x06);
    let first_root = root_for_single_leaf(first.txid_leaf_hash());
    let prefix_root = txid_root_for_transactions(&[first.clone(), second.clone()]);
    let first_chunk = public_txid_artifact_chunk(0, std::slice::from_ref(&first), Some(first_root));
    let first_bytes = first_chunk.bytes.clone();
    let first_cid = raw_cid(&first_bytes).to_string();
    let first_path = ipfs_car_path(&raw_cid(&first_bytes));
    let second_chunk =
        public_txid_artifact_chunk(1, std::slice::from_ref(&second), Some(prefix_root));
    let (source, server) = public_txid_artifact_source(vec![first_chunk, second_chunk]);

    cache
        .sync_to_indexed_tip(None, None, Some(&source))
        .await
        .expect("seed retained stable chunk");
    let meta = db
        .get_blob_meta(
            crate::txid_cache::TXID_CACHE_BLOB_KIND,
            &crate::txid_cache::artifact_chunk_blob_id(key, &first_cid),
        )
        .expect("read retained chunk metadata")
        .expect("stable first chunk retained");
    let retained_path = db.resolve_path(&meta.relative_path);
    fs::write(&retained_path, b"corrupt").expect("corrupt retained chunk");
    let requests_before = server.request_count(&first_path);

    let artifact_source = crate::txid_cache::artifact::TxidPublicArtifactSource::new(
        &source,
        None,
        artifact_scope(),
        TEST_TXID_VERSION,
    );
    let plan = artifact_source
        .fetch_current_chunks(&cache, 0, Some(0))
        .await
        .expect("corrupt demanded chunk refetched");
    let permit = cache.begin_write().await;
    let read_scope = permit.scope();
    drop(permit);
    crate::txid_cache::artifact::TxidPublicArtifactMaintenance::new(
        plan.stable_current,
        read_scope,
    )
    .run(&cache)
    .await;

    assert_eq!(server.request_count(&first_path), requests_before + 1);
    assert_eq!(
        fs::read(retained_path).expect("read repaired retained chunk"),
        first_bytes
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_validated_artifact_retains_planner_stable_non_final_bounded_chunk() {
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
    let first = indexed_transaction(0x74, 0x02, 0x01, 0x03);
    let second = indexed_transaction(0x75, 0x04, 0x05, 0x06);
    let first_root = root_for_single_leaf(first.txid_leaf_hash());
    let prefix_root = txid_root_for_transactions(&[first.clone(), second.clone()]);
    let first_chunk = public_txid_artifact_chunk(0, std::slice::from_ref(&first), Some(first_root));
    let first_cid = raw_cid(&first_chunk.bytes).to_string();
    let first_bytes = first_chunk.bytes.clone();
    let second_chunk =
        public_txid_artifact_chunk(1, std::slice::from_ref(&second), Some(prefix_root));
    let second_cid = raw_cid(&second_chunk.bytes).to_string();
    let (source, _server) = public_txid_artifact_source(vec![first_chunk, second_chunk]);

    cache
        .sync_with_artifact_source(
            None,
            None,
            TxidPublicLatestValidated {
                txid_index: 1,
                merkleroot: Some(prefix_root),
            },
            Some(&source),
        )
        .await
        .expect("validated artifact sync applies current chunks");

    let first_meta = db
        .get_blob_meta(
            crate::txid_cache::TXID_CACHE_BLOB_KIND,
            &crate::txid_cache::artifact_chunk_blob_id(key, &first_cid),
        )
        .expect("read first chunk metadata")
        .expect("non-final current chunk metadata present");
    let retained_first = fs::read(db.resolve_path(&first_meta.relative_path))
        .expect("read retained first current chunk");
    assert_eq!(retained_first, first_bytes);
    assert!(
        db.get_blob_meta(
            crate::txid_cache::TXID_CACHE_BLOB_KIND,
            &crate::txid_cache::artifact_chunk_blob_id(key, &second_cid),
        )
        .expect("read final current chunk metadata")
        .is_none(),
        "final latest chunk should not be retained as reusable prior context"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_background_does_not_fetch_prior_only_catalog() {
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
    let first = indexed_transaction(0x72, 0x02, 0x01, 0x03);
    let first_root = root_for_single_leaf(first.txid_leaf_hash());
    let seed_chunk = public_txid_artifact_chunk(0, std::slice::from_ref(&first), Some(first_root));
    let (seed_source, _seed_server) = public_txid_artifact_source(vec![seed_chunk]);
    cache
        .sync_with_artifact_source(
            None,
            None,
            TxidPublicLatestValidated {
                txid_index: 0,
                merkleroot: Some(first_root),
            },
            Some(&seed_source),
        )
        .await
        .expect("seed first validated row");

    let prior_tail = public_txid_artifact_chunk(0, std::slice::from_ref(&first), Some(first_root));
    let retained_cid = raw_cid(&prior_tail.bytes).to_string();
    let second = indexed_transaction(0x73, 0x04, 0x05, 0x06);
    let prefix_root = txid_root_for_transactions(&[first.clone(), second.clone()]);
    let current_chunk =
        public_txid_artifact_chunk(1, std::slice::from_ref(&second), Some(prefix_root));
    let (source, _server) = public_txid_artifact_source_with_catalogs(vec![
        (1, vec![prior_tail]),
        (2, vec![current_chunk]),
    ]);

    let fetched = cache
        .sync_to_indexed_tip(None, None, Some(&source))
        .await
        .expect("current chunk should apply without prior-only catalog maintenance");

    assert_eq!(fetched, 1);
    let manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    assert_eq!(manifest.validated_cached_txid_index, Some(1));
    let second_row = row_for_txid_index(&manifest, &db, 1)
        .expect("read current row")
        .expect("current row present");
    assert_eq!(
        second_row.transaction.transaction_hash,
        second.transaction_hash
    );
    assert!(
        db.get_blob_meta(
            crate::txid_cache::TXID_CACHE_BLOB_KIND,
            &crate::txid_cache::artifact_chunk_blob_id(key, &retained_cid),
        )
        .expect("read prior-tail chunk metadata")
        .is_none(),
        "a non-current prior catalog must not be fetched for retention"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_background_artifact_provenance_skips_prior_tail_and_graphql() {
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
    let first = indexed_transaction(0x6c, 0x02, 0x01, 0x03);
    let second = indexed_transaction(0x6d, 0x04, 0x05, 0x06);
    let prefix_root = txid_root_for_transactions(&[first.clone(), second.clone()]);
    let seed_chunk =
        public_txid_artifact_chunk(0, &[first.clone(), second.clone()], Some(prefix_root));
    let (seed_source, _seed_server) = public_txid_artifact_source(vec![seed_chunk]);
    cache
        .sync_with_artifact_source(
            None,
            None,
            TxidPublicLatestValidated {
                txid_index: 1,
                merkleroot: Some(prefix_root),
            },
            Some(&seed_source),
        )
        .await
        .expect("seed validated artifact progress");
    let manifest = cache
        .load_manifest()
        .expect("load artifact manifest")
        .expect("artifact manifest present");
    assert_eq!(manifest.artifact_cached_txid_index, Some(1));

    let first_root = root_for_single_leaf(first.txid_leaf_hash());
    let prior_tail = public_txid_artifact_chunk(0, std::slice::from_ref(&first), Some(first_root));
    let retained_cid = raw_cid(&prior_tail.bytes).to_string();
    let retained_id = crate::txid_cache::artifact_chunk_blob_id(key, &retained_cid);
    let current_tail =
        public_txid_artifact_chunk(1, std::slice::from_ref(&second), Some(prefix_root));
    let (retention_source, _retention_server) = public_txid_artifact_source_with_catalogs(vec![
        (1, vec![prior_tail.clone()]),
        (2, vec![prior_tail, current_tail]),
    ]);

    let fetched = cache
        .sync_to_indexed_tip(None, None, Some(&retention_source))
        .await
        .expect("no-progress background pass should complete");

    assert_eq!(fetched, 0);
    assert!(
        db.get_blob_meta(crate::txid_cache::TXID_CACHE_BLOB_KIND, &retained_id)
            .expect("read prior-tail chunk metadata")
            .is_none(),
        "no-progress background sync must not fetch prior tails"
    );

    let (graph_endpoint, graph_requests) = spawn_graphql_response(public_txid_response(&[]));
    let fetched = cache
        .sync_to_indexed_tip(Some(&graph_endpoint), None, Some(&retention_source))
        .await
        .expect("configured GraphQL background pass should complete");

    assert_eq!(fetched, 0);
    assert!(
        graph_requests
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "an empty artifact plan must not query configured GraphQL"
    );
    assert!(
        db.get_blob_meta(crate::txid_cache::TXID_CACHE_BLOB_KIND, &retained_id)
            .expect("read prior-tail chunk metadata after configured pass")
            .is_none(),
        "configured GraphQL must not trigger prior-tail retention"
    );

    let (empty_source, _empty_server) = public_txid_empty_artifact_source();
    let (empty_endpoint, empty_requests) = spawn_graphql_response(public_txid_response(&[]));
    let fetched = cache
        .sync_to_indexed_tip(Some(&empty_endpoint), None, Some(&empty_source))
        .await
        .expect("empty artifact background pass should complete");

    assert_eq!(fetched, 0);
    assert!(
        empty_requests
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "empty artifact mode must not query configured GraphQL"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_stale_retention_scope_does_not_write_raw_artifact_chunk() {
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
    let row = indexed_transaction(0x7c, 0x02, 0x01, 0x03);
    let root = root_for_single_leaf(row.txid_leaf_hash());
    let chunk = public_txid_artifact_chunk(0, std::slice::from_ref(&row), Some(root));
    let cid = raw_cid(&chunk.bytes).to_string();
    let permit = cache.begin_write().await;
    let read_scope = permit.scope();
    drop(permit);

    crate::txid_cache::reset_txid_public_cache(&db)
        .await
        .expect("reset public TXID cache");
    let err = cache
        .begin_write_for_scope(read_scope)
        .await
        .and_then(|permit| permit.retain_artifact_chunks(std::slice::from_ref(&chunk)))
        .expect_err("stale retention scope must not acquire a write permit");

    assert!(matches!(
        err,
        crate::txid_cache::TxidPublicCacheError::StalePublicCacheGeneration { .. }
    ));
    assert!(
        db.get_blob_meta(
            crate::txid_cache::TXID_CACHE_BLOB_KIND,
            &crate::txid_cache::artifact_chunk_blob_id(key, &cid),
        )
        .expect("read stale retained chunk metadata")
        .is_none(),
        "stale retention must not recreate raw artifact metadata after reset"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_optional_prior_tail_failure_does_not_block_current_chunk() {
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
    let first = indexed_transaction(0x66, 0x02, 0x01, 0x03);
    let first_root = root_for_single_leaf(first.txid_leaf_hash());
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
        .expect("seed first validated row");

    let mut malformed_prior_tail =
        public_txid_artifact_chunk_from_payload(0, 0, 1, &[], Some(first_root));
    malformed_prior_tail.descriptor.metadata.stream_partition = Some(TEST_TXID_VERSION.to_string());
    let malformed_cid = raw_cid(&malformed_prior_tail.bytes).to_string();
    let second = indexed_transaction(0x67, 0x04, 0x05, 0x06);
    let prefix_root = txid_root_for_transactions(&[first.clone(), second.clone()]);
    let current_chunk =
        public_txid_artifact_chunk(1, std::slice::from_ref(&second), Some(prefix_root));
    let (source, _server) = public_txid_artifact_source_with_catalogs(vec![
        (1, vec![malformed_prior_tail.clone()]),
        (2, vec![malformed_prior_tail, current_chunk]),
    ]);

    cache
        .sync_with_artifact_source(
            None,
            None,
            TxidPublicLatestValidated {
                txid_index: 1,
                merkleroot: Some(prefix_root),
            },
            Some(&source),
        )
        .await
        .expect("current chunk should apply despite optional retention failure");

    let manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    assert_eq!(manifest.validated_cached_txid_index, Some(1));
    let second_row = row_for_txid_index(&manifest, &db, 1)
        .expect("read current row")
        .expect("current row present");
    assert_eq!(
        second_row.transaction.transaction_hash,
        second.transaction_hash
    );
    assert!(
        db.get_blob_meta(
            crate::txid_cache::TXID_CACHE_BLOB_KIND,
            &crate::txid_cache::artifact_chunk_blob_id(key, &malformed_cid),
        )
        .expect("read malformed chunk metadata")
        .is_none(),
        "failed optional retention must not write chunk metadata"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_prior_only_catalog_failure_does_not_block_current_progress() {
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
    let first = indexed_transaction(0x6a, 0x02, 0x01, 0x03);
    let first_root = root_for_single_leaf(first.txid_leaf_hash());
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
        .expect("seed first validated row");

    let missing_prior_catalog_bytes = b"missing prior catalog";
    let missing_prior_catalog = IndexedArtifactDescriptor {
        dataset_kind: IndexedDatasetKind::PublicTxid,
        scope: artifact_scope(),
        range: IndexedArtifactRange {
            kind: IndexedArtifactRangeKind::TxidIndex,
            start: 0,
            end: 0,
        },
        row_count: 1,
        cid: raw_cid(missing_prior_catalog_bytes).to_string(),
        sha256: FixedBytes::from_slice(&Sha256::digest(missing_prior_catalog_bytes)),
        byte_size: missing_prior_catalog_bytes.len() as u64,
        encoding_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
        compression: CompressionAlgorithm::None,
        metadata: DatasetDescriptorMetadata {
            catalog_generation: Some(1),
            stream_partition: Some(TEST_TXID_VERSION.to_string()),
            ..DatasetDescriptorMetadata::default()
        },
    };
    let second = indexed_transaction(0x6b, 0x04, 0x05, 0x06);
    let prefix_root = txid_root_for_transactions(&[first.clone(), second.clone()]);
    let current_chunk =
        public_txid_artifact_chunk(1, std::slice::from_ref(&second), Some(prefix_root));
    let (source, _server) = public_txid_artifact_source_with_extra_catalogs(
        vec![(2, vec![current_chunk])],
        vec![missing_prior_catalog],
    );

    let fetched = cache
        .sync_to_indexed_tip(None, None, Some(&source))
        .await
        .expect("missing prior-only catalog must not block current TXID progress");

    assert_eq!(fetched, 1);
    let manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    assert_eq!(manifest.validated_cached_txid_index, Some(1));
    let second_row = row_for_txid_index(&manifest, &db, 1)
        .expect("read current row")
        .expect("current row present");
    assert_eq!(
        second_row.transaction.transaction_hash,
        second.transaction_hash
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_optional_prior_tail_root_mismatch_does_not_write_retention() {
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
    let first = indexed_transaction(0x68, 0x02, 0x01, 0x03);
    let first_root = root_for_single_leaf(first.txid_leaf_hash());
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
        .expect("seed first validated row");

    let wrong_root = FixedBytes::from([0xee; 32]);
    assert_ne!(wrong_root, first_root);
    let invalid_prior_tail =
        public_txid_artifact_chunk(0, std::slice::from_ref(&first), Some(wrong_root));
    let invalid_cid = raw_cid(&invalid_prior_tail.bytes).to_string();
    let second = indexed_transaction(0x69, 0x04, 0x05, 0x06);
    let prefix_root = txid_root_for_transactions(&[first.clone(), second.clone()]);
    let current_chunk =
        public_txid_artifact_chunk(1, std::slice::from_ref(&second), Some(prefix_root));
    let (source, _server) = public_txid_artifact_source_with_catalogs(vec![
        (1, vec![invalid_prior_tail.clone()]),
        (2, vec![invalid_prior_tail, current_chunk]),
    ]);

    cache
        .sync_with_artifact_source(
            None,
            None,
            TxidPublicLatestValidated {
                txid_index: 1,
                merkleroot: Some(prefix_root),
            },
            Some(&source),
        )
        .await
        .expect("current chunk should apply despite optional root verification failure");

    let manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    assert_eq!(manifest.validated_cached_txid_index, Some(1));
    let second_row = row_for_txid_index(&manifest, &db, 1)
        .expect("read current row")
        .expect("current row present");
    assert_eq!(
        second_row.transaction.transaction_hash,
        second.transaction_hash
    );
    assert!(
        db.get_blob_meta(
            crate::txid_cache::TXID_CACHE_BLOB_KIND,
            &crate::txid_cache::artifact_chunk_blob_id(key, &invalid_cid),
        )
        .expect("read invalid retained chunk metadata")
        .is_none(),
        "root-mismatched optional retention must not write chunk metadata"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
