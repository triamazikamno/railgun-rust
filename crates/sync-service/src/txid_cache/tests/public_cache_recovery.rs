use super::*;

#[tokio::test]
async fn txid_public_cache_recovery_catchup_stops_after_target_page() {
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
    let target = indexed_transaction(0x77, 0x02, 0x03, 0x04);
    let (endpoint, requests) =
        spawn_graphql_response(public_txid_response(std::slice::from_ref(&target)));

    let cached = cache
        .sync_until_recovered_output_with_page_size(
            &endpoint,
            None,
            target.transaction_hash,
            fixed_bytes_from_u256(target.commitments[0]),
            NonZeroUsize::new(1).expect("test page size is non-zero"),
        )
        .await
        .expect("target row should be returned from first page");

    assert_eq!(cached.txid_index, 0);
    assert_eq!(cached.transaction.transaction_hash, target.transaction_hash);
    let request = requests
        .recv_timeout(Duration::from_secs(5))
        .expect("request received");
    assert!(request.contains("PublicTxidPage"));
    assert!(
        requests.recv_timeout(Duration::from_millis(100)).is_err(),
        "targeted recovery catch-up should not request pages after the target page"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_cache_recovery_refreshes_rewritten_rows_below_high_water_mark() {
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
    let stale = indexed_transaction(0x11, 0x01, 0x02, 0x03);
    let stale_tail = indexed_transaction(0x12, 0x04, 0x05, 0x06);
    let canonical = indexed_transaction(0x77, 0x09, 0x0a, 0x0b);
    let (prefetch_endpoint, _prefetch_requests) =
        spawn_graphql_response(public_txid_response(&[stale.clone(), stale_tail]));
    cache
        .sync_to_graph_tip(&prefetch_endpoint, None)
        .await
        .expect("prefetch stale graph-tip rows");
    let manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    assert_eq!(manifest.next_txid_index, 2);
    assert_eq!(manifest.validated_cached_txid_index, None);

    let (recovery_endpoint, requests) =
        spawn_graphql_response(public_txid_response(std::slice::from_ref(&canonical)));
    let cached = cache
        .sync_until_recovered_output_with_page_size(
            &recovery_endpoint,
            None,
            canonical.transaction_hash,
            fixed_bytes_from_u256(canonical.commitments[0]),
            NonZeroUsize::new(1).expect("test page size is non-zero"),
        )
        .await
        .expect("target row below high-water mark should be refreshed and returned");

    assert_eq!(cached.txid_index, 0);
    assert_eq!(
        cached.transaction.transaction_hash,
        canonical.transaction_hash
    );
    let request = requests
        .recv_timeout(Duration::from_secs(5))
        .expect("recovery request received");
    assert!(request.contains("\"offset\":0"));
    let manifest = cache
        .load_manifest()
        .expect("reload manifest")
        .expect("manifest present");
    assert_eq!(manifest.next_txid_index, 2);
    let refreshed = row_for_txid_index(&manifest, &db, 0)
        .expect("read refreshed row")
        .expect("refreshed row present");
    assert_eq!(
        refreshed.transaction.transaction_hash,
        canonical.transaction_hash
    );
    assert!(
        index_entries_for_hash(&db, key, stale.transaction_hash)
            .expect("read stale index")
            .is_empty()
    );
    let canonical_entries =
        index_entries_for_hash(&db, key, canonical.transaction_hash).expect("read canonical index");
    assert_eq!(canonical_entries.len(), 1);
    assert_eq!(canonical_entries[0].txid_index, 0);

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_cache_retries_incomplete_validated_refresh_for_same_latest() {
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
    let corrected = indexed_transaction(0x22, 0x04, 0x05, 0x06);
    let corrected_leaf = corrected.txid_leaf_hash();
    let corrected_root = root_for_single_leaf(corrected_leaf);
    let (prefetch_endpoint, _prefetch_requests) =
        spawn_graphql_response(public_txid_response(std::slice::from_ref(&stale)));

    cache
        .sync_to_graph_tip(&prefetch_endpoint, None)
        .await
        .expect("prefetch stale graph-tip row");
    let (empty_endpoint, _empty_requests) = spawn_graphql_response(public_txid_response(&[]));
    let error = cache
        .sync(
            &empty_endpoint,
            None,
            TxidPublicLatestValidated {
                txid_index: 0,
                merkleroot: Some(corrected_root),
            },
        )
        .await
        .expect_err("empty validated refresh must not record unsupported latest metadata");
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
    assert_eq!(manifest.latest_validated_txid_index, None);
    assert_eq!(manifest.validated_cached_txid_index, None);
    assert_eq!(manifest.next_txid_index, 1);
    assert_eq!(
        row_for_txid_index(&manifest, &db, 0)
            .expect("read stale row")
            .expect("stale row present")
            .transaction
            .transaction_hash,
        stale.transaction_hash
    );
    assert!(
        cache
            .cached_latest_validated()
            .expect("read latest validated")
            .is_none(),
        "unsupported latest marker must not be returned"
    );
    let err = txid_public_proof_for_recovered_output_at_index(
        &db,
        key,
        0,
        corrected_leaf,
        corrected.output_start_global(),
        0,
        Some(corrected_root),
    )
    .expect_err("stale graph-tip row should not be trusted as validated");
    assert!(matches!(
        err,
        crate::txid_cache::TxidPublicCacheError::CacheNotReady {
            next_index: 0,
            required_index: 0,
        }
    ));

    let (corrected_endpoint, _corrected_requests) =
        spawn_graphql_response(public_txid_response(std::slice::from_ref(&corrected)));
    cache
        .sync(
            &corrected_endpoint,
            None,
            TxidPublicLatestValidated {
                txid_index: 0,
                merkleroot: Some(corrected_root),
            },
        )
        .await
        .expect("same latest retries incomplete validated refresh");

    let manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    assert_eq!(manifest.validated_cached_txid_index, Some(0));
    let refreshed_row = row_for_txid_index(&manifest, &db, 0)
        .expect("read refreshed row")
        .expect("refreshed row present");
    assert_eq!(
        refreshed_row.txid_leaf_hash,
        FixedBytes::from(corrected_leaf.to_be_bytes::<32>())
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_latest_validated_waits_for_graph_tip_sync_manifest_write() {
    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let key = TxidPublicCacheKey {
        chain_type: 0,
        chain_id: 1,
        railgun_contract: artifact_scope().railgun_contract,
        txid_version: "V2_PoseidonMerkle",
    };
    let graph_row = indexed_transaction(0x33, 0x07, 0x08, 0x09);
    let (endpoint, requests, release_response) =
        spawn_delayed_graphql_response(public_txid_response(&[graph_row]));
    let sync_turn = crate::txid_cache::TXID_CACHE_SYNC_LOCK.lock().await;
    let sync_db = Arc::clone(&db);
    let sync_endpoint = endpoint.clone();
    let sync_handle = tokio::spawn(async move {
        TxidPublicCache::new(sync_db.as_ref(), key)
            .sync_to_graph_tip(&sync_endpoint, None)
            .await
    });
    tokio::task::yield_now().await;
    drop(sync_turn);
    tokio::task::spawn_blocking(move || requests.recv_timeout(Duration::from_mins(2)))
        .await
        .expect("join request receiver")
        .expect("graph-tip request received");

    let latest_db = Arc::clone(&db);
    let latest_handle = tokio::spawn(async move {
        TxidPublicCache::new(latest_db.as_ref(), key)
            .put_latest_validated(TxidPublicLatestValidated {
                txid_index: 12,
                merkleroot: Some(FixedBytes::from([0x44; 32])),
            })
            .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!latest_handle.is_finished());

    release_response.send(()).expect("release graph response");
    sync_handle
        .await
        .expect("join graph-tip sync")
        .expect("graph-tip sync succeeds");
    latest_handle
        .await
        .expect("join latest update")
        .expect("latest update succeeds");
    let manifest = TxidPublicCache::new(db.as_ref(), key)
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    assert_eq!(manifest.next_txid_index, 1);
    assert_eq!(manifest.latest_validated_txid_index, Some(12));
    assert_eq!(
        manifest.latest_validated_merkleroot,
        Some(FixedBytes::from([0x44; 32]))
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_cache_local_sufficiency_waits_for_background_sync_lock() {
    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let key = TxidPublicCacheKey {
        chain_type: 0,
        chain_id: 1,
        railgun_contract: artifact_scope().railgun_contract,
        txid_version: "V2_PoseidonMerkle",
    };
    let first = indexed_transaction(0x41, 0x02, 0x01, 0x03);
    let first_root = root_for_single_leaf(first.txid_leaf_hash());
    let first_chunk = public_txid_artifact_chunk(0, std::slice::from_ref(&first), Some(first_root));
    let (artifact_source, _artifact_server) = public_txid_artifact_source(vec![first_chunk]);
    let fetched = TxidPublicCache::new(db.as_ref(), key)
        .sync_to_indexed_tip(None, None, Some(&artifact_source))
        .await
        .expect("seed artifact cache");
    assert_eq!(fetched, 1);
    let seeded_manifest = TxidPublicCache::new(db.as_ref(), key)
        .load_manifest()
        .expect("load seeded manifest")
        .expect("seeded manifest present");
    assert_eq!(seeded_manifest.next_txid_index, 1);
    assert_eq!(seeded_manifest.validated_cached_txid_index, Some(0));
    assert_eq!(seeded_manifest.latest_validated_txid_index, None);

    let second = indexed_transaction(0x52, 0x04, 0x05, 0x06);
    let (endpoint, requests, release_response) =
        spawn_delayed_graphql_response(public_txid_response(std::slice::from_ref(&second)));
    let sync_turn = crate::txid_cache::TXID_CACHE_SYNC_LOCK.lock().await;
    let sync_db = Arc::clone(&db);
    let sync_endpoint = endpoint.clone();
    let sync_handle = tokio::spawn(async move {
        TxidPublicCache::new(sync_db.as_ref(), key)
            .sync_to_graph_tip(&sync_endpoint, None)
            .await
    });
    tokio::task::yield_now().await;
    drop(sync_turn);
    tokio::task::spawn_blocking(move || requests.recv_timeout(Duration::from_mins(2)))
        .await
        .expect("join request receiver")
        .expect("graph-tip request received");

    let local_db = Arc::clone(&db);
    let unavailable_source = unavailable_artifact_source();
    let local_handle = tokio::spawn(async move {
        TxidPublicCache::new(local_db.as_ref(), key)
            .sync_with_artifact_source(
                None,
                None,
                TxidPublicLatestValidated {
                    txid_index: 0,
                    merkleroot: Some(first_root),
                },
                Some(&unavailable_source),
            )
            .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !local_handle.is_finished(),
        "local-sufficiency metadata update must wait for the background sync lock"
    );

    release_response.send(()).expect("release graph response");
    sync_handle
        .await
        .expect("join graph-tip sync")
        .expect("graph-tip sync succeeds");
    local_handle
        .await
        .expect("join local sufficiency sync")
        .expect("local sufficiency sync succeeds");

    let manifest = TxidPublicCache::new(db.as_ref(), key)
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    assert_eq!(manifest.next_txid_index, 2);
    assert_eq!(manifest.validated_cached_txid_index, Some(0));
    assert_eq!(manifest.latest_validated_txid_index, Some(0));
    assert_eq!(manifest.latest_validated_merkleroot, Some(first_root));
    let second_row = row_for_txid_index(&manifest, &db, 1)
        .expect("read background row")
        .expect("background row present");
    assert_eq!(
        second_row.transaction.transaction_hash,
        second.transaction_hash
    );

    let changed = indexed_transaction(0x61, 0x07, 0x08, 0x09);
    let changed_root = root_for_single_leaf(changed.txid_leaf_hash());
    let changed_chunk =
        public_txid_artifact_chunk(0, std::slice::from_ref(&changed), Some(changed_root));
    let (changed_source, _changed_server) = public_txid_artifact_source(vec![changed_chunk]);
    {
        let cache = TxidPublicCache::new(db.as_ref(), key);
        let permit = cache.begin_write().await;
        let mut manifest = permit
            .cache()
            .load_or_new_manifest()
            .expect("load background replacement manifest");
        manifest.artifact_cached_txid_index = None;
        manifest
            .write_to(&permit)
            .expect("clear artifact provenance for replacement");
    }
    let replaced = TxidPublicCache::new(db.as_ref(), key)
        .sync_to_indexed_tip(None, None, Some(&changed_source))
        .await
        .expect("background artifact replacement succeeds");
    assert_eq!(replaced, 1);
    let manifest = TxidPublicCache::new(db.as_ref(), key)
        .load_manifest()
        .expect("reload replacement manifest")
        .expect("replacement manifest present");
    assert_eq!(manifest.latest_validated_txid_index, None);
    assert_eq!(manifest.latest_validated_merkleroot, None);
    assert_eq!(manifest.validated_cached_txid_index, Some(0));
    assert_eq!(manifest.artifact_cached_txid_index, Some(0));
    assert_eq!(
        row_for_txid_index(&manifest, &db, 0)
            .expect("read replaced row")
            .expect("replaced row present")
            .transaction
            .transaction_hash,
        changed.transaction_hash
    );
    assert!(
        TxidPublicCache::new(db.as_ref(), key)
            .cached_latest_validated()
            .expect("read cleared latest marker")
            .is_none()
    );
    let artifact_rows = crate::txid_cache::artifact_bounded_transactions_for_outer_hash(
        &db,
        key,
        changed.transaction_hash,
    )
    .expect("read artifact-bounded replacement row");
    assert_eq!(artifact_rows.len(), 1);
    assert!(matches!(
        validated_transactions_for_outer_hash(&db, key, changed.transaction_hash),
        Err(crate::txid_cache::TxidPublicCacheError::CacheNotReady { .. })
    ));

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_cache_rejects_oversized_graph_offset_without_writing_page() {
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
    let next_txid_index = i32::MAX as u64 + 1;
    let manifest = crate::txid_cache::TxidPublicCacheManifest {
        format_version: crate::txid_cache::TXID_CACHE_FORMAT_VERSION,
        chain_type: key.chain_type,
        chain_id: key.chain_id,
        railgun_contract: key.railgun_contract,
        txid_version: key.txid_version.to_string(),
        page_size: crate::txid_cache::TXID_CACHE_PAGE_SIZE.get(),
        next_txid_index,
        latest_validated_txid_index: None,
        latest_validated_merkleroot: None,
        validated_cached_txid_index: None,
        artifact_cached_txid_index: None,
        checkpoints: BTreeMap::new(),
        pages: Vec::new(),
    };
    {
        let permit = cache.begin_write().await;
        manifest.write_to(&permit).expect("seed manifest");
    }
    //noinspection HttpUrlsUsage
    let endpoint = Url::parse("http://127.0.0.1:1/graphql").expect("unused mock URL");

    let err = cache
        .sync_to_graph_tip(&endpoint, None)
        .await
        .expect_err("oversized graph offset should fail before fetching a page");

    assert!(matches!(
        err,
        crate::txid_cache::TxidPublicCacheError::Sync(
            merkletree::errors::SyncError::UnexpectedFormat(message)
        ) if message.contains("exceeds GraphQL Int max")
    ));
    let manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    assert_eq!(manifest.next_txid_index, next_txid_index);
    assert!(manifest.pages.is_empty());

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_cache_rejects_validated_gap_before_graphql_request() {
    let root_dir = temp_db_root();
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let key = test_cache_key();
    let row = indexed_transaction(0x41, 0x02, 0x01, 0x03);
    let mut manifest = seed_validated_pages(&db, key, vec![vec![row]]).await;
    manifest.validated_cached_txid_index = Some(1);
    {
        let permit = TxidPublicCache::new(&db, key).begin_write().await;
        manifest
            .write_to(&permit)
            .expect("write gapped validated progress");
    }

    let (endpoint, requests) = spawn_graphql_response(public_txid_response(&[]));
    let error = TxidPublicCache::new(&db, key)
        .sync(
            &endpoint,
            None,
            TxidPublicLatestValidated {
                txid_index: 2,
                merkleroot: None,
            },
        )
        .await
        .expect_err("a validated gap must be rejected before GraphQL");
    assert!(matches!(
        error,
        crate::txid_cache::TxidPublicCacheError::MissingLeaf { index: 1 }
    ));
    assert!(
        requests.recv_timeout(Duration::from_millis(100)).is_err(),
        "validated gap must not issue a GraphQL request"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_cached_latest_ignores_rootless_high_water_without_rows() {
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
    let manifest = crate::txid_cache::TxidPublicCacheManifest {
        format_version: crate::txid_cache::TXID_CACHE_FORMAT_VERSION,
        chain_type: key.chain_type,
        chain_id: key.chain_id,
        railgun_contract: key.railgun_contract,
        txid_version: key.txid_version.to_string(),
        page_size: crate::txid_cache::TXID_CACHE_PAGE_SIZE.get(),
        next_txid_index: 1,
        latest_validated_txid_index: Some(0),
        latest_validated_merkleroot: None,
        validated_cached_txid_index: Some(0),
        artifact_cached_txid_index: None,
        checkpoints: BTreeMap::new(),
        pages: Vec::new(),
    };
    {
        let cache = TxidPublicCache::new(&db, key);
        let permit = cache.begin_write().await;
        manifest.write_to(&permit).expect("seed unsupported marker");
    }

    let latest = TxidPublicCache::new(&db, key)
        .cached_latest_validated()
        .expect("read cached latest marker");

    assert!(
        latest.is_none(),
        "rootless latest marker must require readable rows, not only high-water metadata"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
