use super::*;

#[tokio::test]
async fn txid_public_full_range_artifact_root_mismatch_falls_back_to_graphql() {
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
    let graph_row = indexed_transaction(0x44, 0x04, 0x05, 0x06);
    let graph_root = root_for_single_leaf(graph_row.txid_leaf_hash());
    let artifact_row = indexed_transaction(0x11, 0x02, 0x01, 0x03);
    let artifact_root = root_for_single_leaf(artifact_row.txid_leaf_hash());
    assert_ne!(artifact_root, graph_root);
    let artifact_chunk =
        public_txid_artifact_chunk(0, std::slice::from_ref(&artifact_row), Some(artifact_root));
    let (endpoint, requests) =
        spawn_graphql_response(public_txid_response(std::slice::from_ref(&graph_row)));

    cache
        .sync_with_artifact_chunks(
            &endpoint,
            None,
            TxidPublicLatestValidated {
                txid_index: 0,
                merkleroot: Some(graph_root),
            },
            Some(&[artifact_chunk]),
        )
        .await
        .expect("GraphQL fallback should replace stale full-range artifact");

    let manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    assert_eq!(manifest.validated_cached_txid_index, Some(0));
    assert_eq!(manifest.latest_validated_merkleroot, Some(graph_root));
    let row = row_for_txid_index(&manifest, &db, 0)
        .expect("read fallback row")
        .expect("fallback row present");
    assert_eq!(row.transaction.transaction_hash, graph_row.transaction_hash);
    let request = requests
        .recv_timeout(Duration::from_secs(5))
        .expect("GraphQL fallback request received");
    assert!(request.contains("PublicTxidPage"));

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_corrective_failure_preserves_published_manifest_and_page_bytes() {
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
    let old_first = indexed_transaction(0x31, 0x02, 0x01, 0x03);
    let old_second = indexed_transaction(0x32, 0x04, 0x05, 0x06);
    let (prefetch_endpoint, _prefetch_requests) = spawn_graphql_response(public_txid_response(&[
        old_first.clone(),
        old_second.clone(),
    ]));
    cache
        .sync_to_graph_tip(&prefetch_endpoint, None)
        .await
        .expect("seed persisted graph-tip cache");
    let before_manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    assert_eq!(before_manifest.pages.len(), 1);
    let persisted_page_ref = before_manifest.pages[0].clone();
    let before_page = persisted_page_ref
        .read(&db, key)
        .expect("read persisted page");
    assert_eq!(before_page.rows.len(), 2);
    let manifest_path = db.blob_path(
        crate::txid_cache::TXID_CACHE_BLOB_KIND,
        &crate::txid_cache::manifest_file_name(key),
    );
    let before_manifest_bytes = fs::read(&manifest_path).expect("read persisted manifest blob");
    let page_path = db.resolve_path(&persisted_page_ref.relative_path);
    let before_page_bytes = fs::read(&page_path).expect("read persisted page blob");

    let artifact_first = indexed_transaction(0x41, 0x07, 0x08, 0x09);
    let artifact_second = indexed_transaction(0x42, 0x0a, 0x0b, 0x0c);
    let first_root = root_for_single_leaf(artifact_first.txid_leaf_hash());
    let first_chunk = public_txid_artifact_chunk(0, &[artifact_first], Some(first_root));
    let bad_second_chunk =
        public_txid_artifact_chunk(1, &[artifact_second], Some(FixedBytes::from([0xee; 32])));
    let graph_first = indexed_transaction(0x51, 0x0d, 0x0e, 0x0f);
    let graph_second = indexed_transaction(0x52, 0x10, 0x11, 0x12);
    let graph_root = FixedBytes::from([0x99; 32]);
    let (endpoint, requests) =
        spawn_graphql_response(public_txid_response(&[graph_first, graph_second]));

    let error = cache
        .sync_with_artifact_chunks(
            &endpoint,
            None,
            TxidPublicLatestValidated {
                txid_index: 1,
                merkleroot: Some(graph_root),
            },
            Some(&[first_chunk, bad_second_chunk]),
        )
        .await
        .expect_err("invalid GraphQL correction must fail closed");
    assert!(matches!(
        error,
        crate::txid_cache::TxidPublicCacheError::RootMismatch
    ));
    let after_manifest = cache
        .load_manifest()
        .expect("reload manifest")
        .expect("manifest present");
    assert_eq!(
        after_manifest.next_txid_index,
        before_manifest.next_txid_index
    );
    assert_eq!(
        after_manifest.validated_cached_txid_index,
        before_manifest.validated_cached_txid_index
    );
    assert_eq!(
        after_manifest.latest_validated_txid_index,
        before_manifest.latest_validated_txid_index
    );
    assert_eq!(
        after_manifest.latest_validated_merkleroot,
        before_manifest.latest_validated_merkleroot
    );
    assert_eq!(
        after_manifest.artifact_cached_txid_index,
        before_manifest.artifact_cached_txid_index
    );
    assert_eq!(after_manifest.pages.len(), before_manifest.pages.len());
    assert_eq!(
        after_manifest.pages[0].relative_path,
        persisted_page_ref.relative_path
    );
    let after_page = after_manifest.pages[0]
        .read(&db, key)
        .expect("read preserved page");
    assert_eq!(after_page.rows.len(), 2);
    assert_eq!(
        after_page.rows[0].transaction.transaction_hash,
        old_first.transaction_hash
    );
    assert_eq!(
        after_page.rows[1].transaction.transaction_hash,
        old_second.transaction_hash
    );
    assert_eq!(
        fs::read(&manifest_path).expect("read preserved manifest blob"),
        before_manifest_bytes
    );
    assert_eq!(
        fs::read(&page_path).expect("read preserved page blob"),
        before_page_bytes
    );
    let request = requests
        .recv_timeout(Duration::from_secs(5))
        .expect("corrective GraphQL request received");
    assert!(request.contains("PublicTxidPage"));

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_cache_prefers_configured_artifact_source_before_graphql() {
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
    let artifact_row = indexed_transaction(0x21, 0x02, 0x01, 0x03);
    let graph_row = indexed_transaction(0x44, 0x04, 0x05, 0x06);
    let artifact_root = root_for_single_leaf(artifact_row.txid_leaf_hash());
    let artifact_chunk =
        public_txid_artifact_chunk(0, std::slice::from_ref(&artifact_row), Some(artifact_root));
    let (artifact_source, _artifact_server) = public_txid_artifact_source(vec![artifact_chunk]);
    let (graph_endpoint, graph_requests) =
        spawn_graphql_response(public_txid_response(&[graph_row]));

    cache
        .sync_with_artifact_source(
            Some(&graph_endpoint),
            None,
            TxidPublicLatestValidated {
                txid_index: 0,
                merkleroot: Some(artifact_root),
            },
            Some(&artifact_source),
        )
        .await
        .expect("artifact source should populate cache");

    let manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    assert_eq!(manifest.validated_cached_txid_index, Some(0));
    let row = row_for_txid_index(&manifest, &db, 0)
        .expect("read artifact row")
        .expect("artifact row present");
    assert_eq!(
        row.transaction.transaction_hash,
        artifact_row.transaction_hash
    );
    assert!(
        graph_requests
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "GraphQL fallback should not be used after artifact sync succeeds"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_rejects_overlapping_catalogs_in_current_snapshot() {
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
    let old_first = indexed_transaction(0x61, 0x02, 0x01, 0x03);
    let old_root = txid_root_for_transactions(std::slice::from_ref(&old_first));
    let old_tail = public_txid_artifact_chunk(0, std::slice::from_ref(&old_first), Some(old_root));
    let new_first = indexed_transaction(0x62, 0x04, 0x05, 0x06);
    let second = indexed_transaction(0x63, 0x07, 0x08, 0x09);
    let new_root = txid_root_for_transactions(&[new_first.clone(), second.clone()]);
    let replacement = public_txid_artifact_chunk(0, &[new_first.clone(), second], Some(new_root));
    let (artifact_source, _artifact_server) = public_txid_artifact_source_with_catalogs(vec![
        (1, vec![old_tail]),
        (2, vec![replacement]),
    ]);

    let error = cache
        .sync_with_artifact_source(
            None,
            None,
            TxidPublicLatestValidated {
                txid_index: 1,
                merkleroot: Some(new_root),
            },
            Some(&artifact_source),
        )
        .await
        .expect_err("one current snapshot must not contain overlapping TXID catalogs");

    assert!(matches!(
        error,
        crate::txid_cache::TxidPublicCacheError::MetadataMismatch(message)
            if message.contains("overlapping chunks")
    ));
    assert!(cache.load_manifest().expect("load manifest").is_none());

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_format_v1_ignores_partitioned_catalog_context() {
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
    let row = indexed_transaction(0x61, 0x02, 0x01, 0x03);
    let root = root_for_single_leaf(row.txid_leaf_hash());
    let current = public_txid_artifact_chunk(0, std::slice::from_ref(&row), Some(root));
    let missing_catalog_bytes = b"authenticated successor catalog descriptor";
    let successor_descriptor = IndexedArtifactDescriptor {
        dataset_kind: IndexedDatasetKind::PublicTxid,
        scope: artifact_scope(),
        range: IndexedArtifactRange {
            kind: IndexedArtifactRangeKind::TxidIndex,
            start: 1,
            end: 1,
        },
        row_count: 1,
        cid: raw_cid(missing_catalog_bytes).to_string(),
        sha256: prefixed_sha256(missing_catalog_bytes),
        byte_size: missing_catalog_bytes.len() as u64,
        encoding_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
        compression: CompressionAlgorithm::None,
        metadata: DatasetDescriptorMetadata {
            catalog_generation: Some(1),
            stream_partition: Some(TEST_TXID_VERSION.to_string()),
            ..DatasetDescriptorMetadata::default()
        },
    };
    let (config, _server) = public_txid_artifact_source_with_extra_catalogs(
        vec![(1, vec![current])],
        vec![successor_descriptor],
    );
    let source = crate::txid_cache::artifact::TxidPublicArtifactSource::new(
        &config,
        None,
        artifact_scope(),
        TEST_TXID_VERSION,
    );

    let plan = source
        .fetch_current_chunks(&cache, 0, Some(0))
        .await
        .expect("successor descriptor should not require its catalog body");

    assert_eq!(plan.required.len(), 1);
    assert_eq!(plan.stable_current, [] as [VerifiedIndexedArtifactChunk; 0]);

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_rejects_overlapping_current_snapshot_repack() {
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
    let original_rows = (0_u8..10)
        .map(|offset| {
            indexed_transaction(0x70 + offset, 0x20 + offset, 0x30 + offset, 0x40 + offset)
        })
        .collect::<Vec<_>>();
    let original_root = txid_root_for_transactions(&original_rows);
    let original_tail = public_txid_artifact_chunk(0, &original_rows, Some(original_root));
    let (seed_source, _seed_server) = public_txid_artifact_source(vec![original_tail.clone()]);
    cache
        .sync_with_artifact_source(
            None,
            None,
            TxidPublicLatestValidated {
                txid_index: 9,
                merkleroot: Some(original_root),
            },
            Some(&seed_source),
        )
        .await
        .expect("seed stable prior TXID rows");
    let before_manifest = cache
        .load_manifest()
        .expect("load seeded manifest")
        .expect("seeded manifest present");
    let before_row_5 = row_for_txid_index(&before_manifest, &db, 5)
        .expect("read row 5 before invalid repack")
        .expect("row 5 present before invalid repack");
    let before_row_9 = row_for_txid_index(&before_manifest, &db, 9)
        .expect("read row 9 before invalid repack")
        .expect("row 9 present before invalid repack");

    let next_rows = (0_u8..10)
        .map(|offset| {
            indexed_transaction(0x90 + offset, 0x50 + offset, 0x60 + offset, 0x70 + offset)
        })
        .collect::<Vec<_>>();
    let all_rows = original_rows
        .iter()
        .chain(next_rows.iter())
        .cloned()
        .collect::<Vec<_>>();
    let next_root = txid_root_for_transactions(&all_rows);
    let current_tail = public_txid_artifact_chunk(10, &next_rows, Some(next_root));
    let repacked_rows = (0_u8..10)
        .map(|offset| {
            indexed_transaction(0xb0 + offset, 0x80 + offset, 0x90 + offset, 0xa0 + offset)
        })
        .collect::<Vec<_>>();
    let repacked_prefix = original_rows
        .iter()
        .take(5)
        .chain(repacked_rows.iter())
        .cloned()
        .collect::<Vec<_>>();
    let repacked_root = txid_root_for_transactions(&repacked_prefix);
    let invalid_repack = public_txid_artifact_chunk(5, &repacked_rows, Some(repacked_root));
    let (artifact_source, _artifact_server) = public_txid_artifact_source_with_catalogs(vec![
        (1, vec![original_tail]),
        (2, vec![current_tail]),
        (3, vec![invalid_repack]),
    ]);

    let error = cache
        .sync_to_indexed_tip(None, None, Some(&artifact_source))
        .await
        .expect_err("overlapping current catalogs must reject the invalid repack");

    assert!(matches!(
        error,
        crate::txid_cache::TxidPublicCacheError::MetadataMismatch(message)
            if message.contains("overlapping chunks")
    ));
    let after_manifest = cache
        .load_manifest()
        .expect("load manifest after invalid repack")
        .expect("manifest present after invalid repack");
    assert_eq!(after_manifest.validated_cached_txid_index, Some(9));
    assert_eq!(after_manifest.next_txid_index, 10);
    let after_row_5 = row_for_txid_index(&after_manifest, &db, 5)
        .expect("read row 5 after invalid repack")
        .expect("row 5 present after invalid repack");
    let after_row_9 = row_for_txid_index(&after_manifest, &db, 9)
        .expect("read row 9 after invalid repack")
        .expect("row 9 present after invalid repack");
    assert_eq!(
        after_row_5.transaction.transaction_hash,
        before_row_5.transaction.transaction_hash
    );
    assert_eq!(
        after_row_9.transaction.transaction_hash,
        before_row_9.transaction.transaction_hash
    );
    assert!(
        row_for_txid_index(&after_manifest, &db, 10)
            .expect("read row 10 after invalid repack")
            .is_none(),
        "invalid stream view must not append current rows after the prior conflict"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
