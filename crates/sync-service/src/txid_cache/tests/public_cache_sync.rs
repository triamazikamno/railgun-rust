use super::*;

#[tokio::test]
async fn txid_public_cache_isolates_contracts_on_the_same_chain_and_db() {
    let root_dir = temp_db_root();
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let key_a = TxidPublicCacheKey {
        chain_type: 0,
        chain_id: 1,
        railgun_contract: Address::from([0xaa; 20]),
        txid_version: TEST_TXID_VERSION,
    };
    let key_b = TxidPublicCacheKey {
        railgun_contract: Address::from([0xbb; 20]),
        ..key_a
    };
    let row_a = indexed_transaction(0x31, 0x02, 0x01, 0x03);
    let row_b = indexed_transaction(0x32, 0x04, 0x05, 0x06);

    for (key, row) in [(key_a, row_a.clone()), (key_b, row_b.clone())] {
        let cache = TxidPublicCache::new(&db, key);
        let permit = cache.begin_write().await;
        let mut manifest = permit
            .cache()
            .load_or_new_manifest()
            .expect("load contract manifest");
        let page =
            crate::txid_cache::TxidPublicCachePage::from_indexed_transactions(key, 0, vec![row]);
        manifest
            .append_page_after_prefix_validation(&permit, &page)
            .expect("append page");
        crate::txid_cache::update_index_for_page(&permit, &page).expect("write contract index");
        manifest.validated_cached_txid_index = Some(0);
        manifest.latest_validated_txid_index = Some(0);
        manifest.write_to(&permit).expect("write contract manifest");
    }

    let manifest_a = TxidPublicCache::new(&db, key_a)
        .load_manifest()
        .expect("load contract A manifest")
        .expect("contract A manifest present");
    let manifest_b = TxidPublicCache::new(&db, key_b)
        .load_manifest()
        .expect("load contract B manifest")
        .expect("contract B manifest present");
    assert_eq!(manifest_a.railgun_contract, key_a.railgun_contract);
    assert_eq!(manifest_b.railgun_contract, key_b.railgun_contract);
    assert_ne!(
        crate::txid_cache::cache_id(key_a),
        crate::txid_cache::cache_id(key_b)
    );
    assert_ne!(
        crate::txid_cache::manifest_file_name(key_a),
        crate::txid_cache::manifest_file_name(key_b)
    );
    assert_ne!(
        crate::txid_cache::page_file_name(key_a, 0),
        crate::txid_cache::page_file_name(key_b, 0)
    );
    assert_ne!(
        crate::txid_cache::index_shard_file_name(key_a, 0x31),
        crate::txid_cache::index_shard_file_name(key_b, 0x31)
    );
    assert_ne!(
        crate::txid_cache::artifact_chunk_blob_id(key_a, "shared-cid"),
        crate::txid_cache::artifact_chunk_blob_id(key_b, "shared-cid")
    );
    assert_ne!(
        crate::txid_cache::artifact_chunk_file_name(key_a, "shared-cid"),
        crate::txid_cache::artifact_chunk_file_name(key_b, "shared-cid")
    );

    let retained_chunk = public_txid_artifact_chunk(
        0,
        std::slice::from_ref(&row_b),
        Some(root_for_single_leaf(row_b.txid_leaf_hash())),
    );
    let retained_cid = retained_chunk.descriptor.cid.clone();
    let permit = TxidPublicCache::new(&db, key_b).begin_write().await;
    permit
        .retain_artifact_chunks(std::slice::from_ref(&retained_chunk))
        .expect("retain contract B raw chunk");
    drop(permit);
    assert!(
        db.get_blob_meta(
            crate::txid_cache::TXID_CACHE_BLOB_KIND,
            &crate::txid_cache::artifact_chunk_blob_id(key_b, &retained_cid),
        )
        .expect("read contract B retained chunk")
        .is_some()
    );
    assert!(
        db.get_blob_meta(
            crate::txid_cache::TXID_CACHE_BLOB_KIND,
            &crate::txid_cache::artifact_chunk_blob_id(key_a, &retained_cid),
        )
        .expect("read contract A retained chunk")
        .is_none()
    );

    let page_a = manifest_a.pages[0]
        .read(&db, key_a)
        .expect("read contract A page");
    let page_b = manifest_b.pages[0]
        .read(&db, key_b)
        .expect("read contract B page");
    assert_ne!(
        manifest_a.pages[0].relative_path,
        manifest_b.pages[0].relative_path
    );
    assert_eq!(page_a.railgun_contract, key_a.railgun_contract);
    assert_eq!(page_b.railgun_contract, key_b.railgun_contract);
    assert_eq!(
        page_a.rows[0].transaction.transaction_hash,
        row_a.transaction_hash
    );
    assert_eq!(
        page_b.rows[0].transaction.transaction_hash,
        row_b.transaction_hash
    );
    let index_a = load_index_shard(&db, key_a, 0x31).expect("read contract A index");
    let index_b = load_index_shard(&db, key_b, 0x32).expect("read contract B index");
    assert_eq!(index_a.railgun_contract, key_a.railgun_contract);
    assert_eq!(index_b.railgun_contract, key_b.railgun_contract);
    assert_eq!(index_a.entries.len(), 1);
    assert_eq!(index_b.entries.len(), 1);
    assert!(
        load_index_shard(&db, key_b, 0x31)
            .expect("read isolated contract B index shard")
            .entries
            .is_empty()
    );
    assert!(matches!(
        manifest_a.pages[0].read(&db, key_b),
        Err(crate::txid_cache::TxidPublicCacheError::MetadataMismatch(_))
    ));
    assert!(matches!(
        txid_public_proof_for_recovered_output(
            &db,
            key_b,
            row_a.txid_leaf_hash(),
            row_a.output_start_global(),
            0,
            None,
        ),
        Err(crate::txid_cache::TxidPublicCacheError::MissingTarget)
    ));

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_stable_maintenance_rechecks_cache_before_rewriting() {
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
    let chunk = public_txid_artifact_chunk(
        0,
        std::slice::from_ref(&row),
        Some(root_for_single_leaf(row.txid_leaf_hash())),
    );
    let read_scope = cache.begin_write().await.scope();

    crate::txid_cache::artifact::TxidPublicArtifactMaintenance::retain_stable_chunk(
        &cache,
        chunk.clone(),
        read_scope,
    )
    .await;
    let id = crate::txid_cache::artifact_chunk_blob_id(key, &chunk.descriptor.cid);
    let mut meta = db
        .get_blob_meta(crate::txid_cache::TXID_CACHE_BLOB_KIND, &id)
        .expect("read retained artifact metadata")
        .expect("stable artifact retained");
    meta.updated_at = 1;
    db.put_blob_meta(crate::txid_cache::TXID_CACHE_BLOB_KIND, &id, &meta)
        .expect("mark retained metadata");

    crate::txid_cache::artifact::TxidPublicArtifactMaintenance::retain_stable_chunk(
        &cache, chunk, read_scope,
    )
    .await;

    assert_eq!(
        db.get_blob_meta(crate::txid_cache::TXID_CACHE_BLOB_KIND, &id)
            .expect("reread retained artifact metadata")
            .expect("stable artifact remains retained")
            .updated_at,
        1,
        "overlapping maintenance must not rewrite existing file metadata"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_cache_rebuild_leaves_contractless_v2_cache_untouched() {
    let root_dir = temp_db_root();
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let legacy_id = format!("0|1|{TEST_TXID_VERSION}");
    let legacy_name = "0-1-V2_PoseidonMerkle-manifest.msgpack";
    let legacy_bytes = b"contractless-v2-cache";
    let legacy_path = db.blob_path(crate::txid_cache::TXID_CACHE_BLOB_KIND, legacy_name);
    db.ensure_blob_dir(crate::txid_cache::TXID_CACHE_BLOB_KIND)
        .expect("ensure TXID cache dir");
    fs::write(&legacy_path, legacy_bytes).expect("write v2 cache file");
    db.put_blob_meta(
        crate::txid_cache::TXID_CACHE_BLOB_KIND,
        &legacy_id,
        &BlobMeta {
            format_version: 2,
            relative_path: DbStore::relative_blob_path(
                crate::txid_cache::TXID_CACHE_BLOB_KIND,
                legacy_name,
            ),
            content_hash: Sha256::digest(legacy_bytes).into(),
            source_hash: None,
            source_sequence: None,
            created_at: 1,
            updated_at: 1,
            last_accessed_at: 1,
            last_block: None,
        },
    )
    .expect("write v2 cache metadata");
    let key = TxidPublicCacheKey {
        chain_type: 0,
        chain_id: 1,
        railgun_contract: Address::from([0xcc; 20]),
        txid_version: TEST_TXID_VERSION,
    };
    let cache = TxidPublicCache::new(&db, key);
    assert!(cache.load_manifest().expect("load current cache").is_none());

    let permit = cache.begin_write().await;
    permit
        .cache()
        .load_or_new_manifest()
        .expect("new current manifest")
        .write_to(&permit)
        .expect("write current manifest");
    drop(permit);

    assert!(
        legacy_path.exists(),
        "v2 cache file must not be destructively migrated"
    );
    assert!(
        db.get_blob_meta(crate::txid_cache::TXID_CACHE_BLOB_KIND, &legacy_id)
            .expect("read v2 metadata")
            .is_some(),
        "v2 cache metadata must remain untouched"
    );
    let current_meta = db
        .get_blob_meta(
            crate::txid_cache::TXID_CACHE_BLOB_KIND,
            &crate::txid_cache::cache_id(key),
        )
        .expect("read current metadata")
        .expect("current metadata present");
    assert_eq!(
        current_meta.format_version,
        crate::txid_cache::TXID_CACHE_FORMAT_VERSION
    );
    assert_ne!(
        current_meta.relative_path,
        DbStore::relative_blob_path(crate::txid_cache::TXID_CACHE_BLOB_KIND, legacy_name)
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_cache_syncs_broad_page_and_builds_proof() {
    let root_dir = temp_db_root();
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let (endpoint, requests) = spawn_graphql(
        r#"{"data":{"transactions":[{"id":"0x0001","blockNumber":"12","blockTimestamp":"1700000012","transactionHash":"0x1111111111111111111111111111111111111111111111111111111111111111","merkleRoot":"0x2222222222222222222222222222222222222222222222222222222222222222","nullifiers":["0x01"],"commitments":["0x02"],"boundParamsHash":"0x03","hasUnshield":false,"utxoTreeIn":"0","utxoTreeOut":"0","utxoBatchStartPositionOut":"0"}]}}"#,
    );
    let key = TxidPublicCacheKey {
        chain_type: 0,
        chain_id: 1,
        railgun_contract: artifact_scope().railgun_contract,
        txid_version: "V2_PoseidonMerkle",
    };
    let cache = TxidPublicCache::new(&db, key);

    cache
        .sync(
            &endpoint,
            None,
            TxidPublicLatestValidated {
                txid_index: 0,
                merkleroot: None,
            },
        )
        .await
        .expect("sync public txid cache");
    let manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    let page = manifest.pages[0].read(&db, key).expect("read page");
    let expected_leaf = U256::from_be_bytes(page.rows[0].txid_leaf_hash.0);
    assert!(matches!(
        txid_public_proof_for_recovered_output(
            &db,
            key,
            expected_leaf,
            page.rows[0].transaction.output_start_global(),
            0,
            None,
        ),
        Err(crate::txid_cache::TxidPublicCacheError::CacheNotReady {
            required_index: 0,
            ..
        })
    ));
    let expected_root = FixedBytes::from(
        DenseMerkleTree::from_ordered_leaves(vec![expected_leaf], 1)
            .root()
            .to_be_bytes::<32>(),
    );
    let permit = cache.begin_write().await;
    let mut authenticated_manifest = cache
        .load_or_new_manifest()
        .expect("load authenticated manifest");
    authenticated_manifest.latest_validated_merkleroot = Some(expected_root);
    authenticated_manifest
        .insert_checkpoint(
            0,
            expected_root,
            crate::txid_cache::TxidPublicCheckpointSource::LatestValidated,
        )
        .expect("insert authenticated root");
    authenticated_manifest
        .write_to(&permit)
        .expect("write authenticated manifest");
    drop(permit);
    let index_entries = index_entries_for_hash(&db, key, page.rows[0].transaction.transaction_hash)
        .expect("read tx hash index");
    assert_eq!(index_entries.len(), 1);
    assert_eq!(index_entries[0].txid_index, 0);
    let proof = txid_public_proof_for_recovered_output(
        &db,
        key,
        expected_leaf,
        page.rows[0].transaction.output_start_global(),
        0,
        Some(expected_root),
    )
    .expect("build cached txid proof");

    assert_eq!(proof.target_txid_index, 0);
    assert_eq!(proof.root_txid_index, 0);
    assert_eq!(proof.proof.leaf, expected_leaf);
    let cached = txid_public_transaction_for_recovered_output(
        &db,
        key,
        page.rows[0].transaction.transaction_hash,
        page.rows[0].transaction.commitments[0]
            .to_be_bytes::<32>()
            .into(),
    )
    .expect("lookup recovered output row");
    assert_eq!(cached.txid_index, 0);
    assert_eq!(
        cache
            .cached_latest_validated()
            .expect("read latest validated")
            .expect("latest validated present")
            .txid_index,
        0
    );
    cache
        .put_latest_validated(TxidPublicLatestValidated {
            txid_index: 12,
            merkleroot: Some(FixedBytes::from([0x33; 32])),
        })
        .await
        .expect("update latest validated");
    assert!(
        cache
            .cached_latest_validated()
            .expect("read unsupported latest validated")
            .is_none(),
        "unsupported test-seeded latest marker must not be returned"
    );
    let request = requests
        .recv_timeout(Duration::from_secs(5))
        .expect("request received");
    assert!(request.contains("PublicTxidPage"));
    assert!(!request.contains("transactionHash_eq"));
    assert!(!request.contains("commitments_containsAll"));

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_cache_refreshes_prefetched_rows_when_validated() {
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
    let stale = indexed_transaction(0x11, 0x02, 0x01, 0x03);
    let stale_tail = indexed_transaction(0x12, 0x07, 0x08, 0x09);
    let corrected = indexed_transaction(0x22, 0x04, 0x05, 0x06);
    let corrected_tail = indexed_transaction(0x23, 0x0a, 0x0b, 0x0c);
    let corrected_final = indexed_transaction(0x24, 0x0d, 0x0e, 0x0f);
    let (prefetch_endpoint, _prefetch_requests) =
        spawn_graphql_response(public_txid_response(&[stale.clone(), stale_tail]));

    cache
        .sync_to_graph_tip(&prefetch_endpoint, None)
        .await
        .expect("prefetch stale graph-tip row");
    let stale_cached = txid_public_transaction_for_recovered_output(
        &db,
        key,
        stale.transaction_hash,
        fixed_bytes_from_u256(stale.commitments[0]),
    )
    .expect("stale graph-tip row cached");
    assert_eq!(
        stale_cached.transaction.transaction_hash,
        stale.transaction_hash
    );
    let before_manifest = cache
        .load_manifest()
        .expect("load manifest before correction")
        .expect("manifest before correction present");
    let before_page_ref = before_manifest.pages[0].clone();
    let before_page_bytes = fs::read(db.resolve_path(&before_page_ref.relative_path))
        .expect("read page before correction");

    let corrected_leaf = corrected.txid_leaf_hash();
    let corrected_root = txid_root_for_transactions(&[
        corrected.clone(),
        corrected_tail.clone(),
        corrected_final.clone(),
    ]);
    let (validated_endpoint, _validated_requests) =
        spawn_graphql_response(public_txid_response(&[
            corrected.clone(),
            corrected_tail.clone(),
            corrected_final.clone(),
        ]));
    cache
        .sync(
            &validated_endpoint,
            None,
            TxidPublicLatestValidated {
                txid_index: 2,
                merkleroot: Some(corrected_root),
            },
        )
        .await
        .expect("refresh newly validated row");

    let manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    let refreshed_row = row_for_txid_index(&manifest, &db, 0)
        .expect("read refreshed row")
        .expect("refreshed row present");
    assert_eq!(
        refreshed_row.txid_leaf_hash,
        FixedBytes::from(corrected_leaf.to_be_bytes::<32>())
    );
    assert_eq!(manifest.validated_cached_txid_index, Some(2));
    assert_eq!(manifest.next_txid_index, 3);
    assert_eq!(manifest.pages.len(), 1);
    assert_ne!(
        manifest.pages[0].relative_path,
        before_page_ref.relative_path
    );
    assert_eq!(
        fs::read(db.resolve_path(&before_page_ref.relative_path))
            .expect("read preserved page after correction"),
        before_page_bytes
    );
    let refreshed_tail = row_for_txid_index(&manifest, &db, 1)
        .expect("read refreshed tail")
        .expect("refreshed tail present");
    assert_eq!(
        refreshed_tail.transaction.transaction_hash,
        corrected_tail.transaction_hash
    );
    let refreshed_final = row_for_txid_index(&manifest, &db, 2)
        .expect("read refreshed final row")
        .expect("refreshed final row present");
    assert_eq!(
        refreshed_final.transaction.transaction_hash,
        corrected_final.transaction_hash
    );
    assert!(
        index_entries_for_hash(&db, key, stale.transaction_hash)
            .expect("read stale tx hash index")
            .is_empty()
    );
    let corrected_cached = txid_public_transaction_for_recovered_output(
        &db,
        key,
        corrected.transaction_hash,
        fixed_bytes_from_u256(corrected.commitments[0]),
    )
    .expect("corrected row cached");
    assert_eq!(
        corrected_cached.transaction.transaction_hash,
        corrected.transaction_hash
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_cache_completes_multi_page_graph_tip_append() {
    let root_dir = temp_db_root();
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let key = test_cache_key();
    let page_size = crate::txid_cache::TXID_CACHE_PAGE_SIZE.get();
    let rows = (0..=page_size)
        .map(|offset| {
            let offset = offset as u8;
            indexed_transaction(
                offset,
                offset.wrapping_add(1),
                offset.wrapping_add(2),
                offset.wrapping_add(3),
            )
        })
        .collect::<Vec<_>>();
    let (endpoint, _requests) = spawn_graphql_responses(vec![
        public_txid_response(&rows[..page_size]),
        public_txid_response(&rows[page_size..]),
    ]);

    let fetched = TxidPublicCache::new(&db, key)
        .sync_to_graph_tip(&endpoint, None)
        .await
        .expect("multi-page graph-tip append should complete");
    assert_eq!(fetched, (page_size + 1) as u64);
    let manifest = TxidPublicCache::new(&db, key)
        .load_manifest()
        .expect("load multi-page manifest")
        .expect("multi-page manifest present");
    assert_eq!(manifest.next_txid_index, (page_size + 1) as u64);
    assert_eq!(manifest.pages.len(), 2);
    assert_eq!(manifest.pages[0].start_index, 0);
    assert_eq!(manifest.pages[1].start_index, page_size as u64);

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_cache_lookup_prefers_validated_duplicate_over_unvalidated_stale() {
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
    let filler = indexed_transaction(0x11, 0x01, 0x02, 0x03);
    let stale_duplicate = indexed_transaction(0x44, 0x02, 0x03, 0x04);
    let canonical = indexed_transaction(0x44, 0x02, 0x05, 0x06);
    let (prefetch_endpoint, _prefetch_requests) =
        spawn_graphql_response(public_txid_response(&[filler, stale_duplicate.clone()]));

    cache
        .sync_to_graph_tip(&prefetch_endpoint, None)
        .await
        .expect("prefetch stale duplicate row");
    let (validated_endpoint, _validated_requests) =
        spawn_graphql_response(public_txid_response(std::slice::from_ref(&canonical)));
    cache
        .sync(
            &validated_endpoint,
            None,
            TxidPublicLatestValidated {
                txid_index: 0,
                merkleroot: None,
            },
        )
        .await
        .expect("refresh canonical validated row");

    let manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    assert_eq!(manifest.validated_cached_txid_index, Some(0));
    let stale_row = row_for_txid_index(&manifest, &db, 1)
        .expect("read stale row")
        .expect("stale row present");
    assert_eq!(
        stale_row.transaction.transaction_hash,
        canonical.transaction_hash
    );
    let index_entries = index_entries_for_hash(&db, key, canonical.transaction_hash)
        .expect("read duplicate tx hash index");
    assert_eq!(index_entries.len(), 2);

    let cached = txid_public_transaction_for_recovered_output(
        &db,
        key,
        canonical.transaction_hash,
        fixed_bytes_from_u256(canonical.commitments[0]),
    )
    .expect("validated duplicate should win over stale graph-tip duplicate");

    assert_eq!(cached.txid_index, 0);
    assert_eq!(cached.transaction.nullifiers, canonical.nullifiers);

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
