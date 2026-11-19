use super::*;

#[tokio::test]
async fn txid_public_artifact_chunks_materialize_out_of_order() {
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
    let first = indexed_transaction(0x11, 0x02, 0x01, 0x03);
    let second = indexed_transaction(0x22, 0x04, 0x05, 0x06);
    let first_root = txid_root_for_transactions(std::slice::from_ref(&first));
    let second_root = txid_root_for_transactions(&[first.clone(), second.clone()]);
    let chunks = vec![
        public_txid_artifact_chunk(1, std::slice::from_ref(&second), Some(second_root)),
        public_txid_artifact_chunk(0, std::slice::from_ref(&first), Some(first_root)),
    ];
    let cache = TxidPublicCache::new(&db, key);
    let permit = cache.begin_write().await;
    let mut manifest = permit
        .cache()
        .load_or_new_manifest()
        .expect("load manifest");

    let applied = manifest
        .apply_artifact_chunks(&permit, &chunks)
        .expect("apply artifact chunks");

    assert_eq!(applied, 2);
    assert_eq!(manifest.validated_cached_txid_index, Some(1));
    assert_eq!(manifest.artifact_cached_txid_index, Some(1));
    let first_row = row_for_txid_index(&manifest, &db, 0)
        .expect("read first row")
        .expect("first row present");
    let second_row = row_for_txid_index(&manifest, &db, 1)
        .expect("read second row")
        .expect("second row present");
    assert_eq!(
        first_row.transaction.transaction_hash,
        first.transaction_hash
    );
    assert_eq!(
        second_row.transaction.transaction_hash,
        second.transaction_hash
    );

    drop(permit);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_artifact_apply_ignores_chunks_already_covered_by_progress() {
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
    let row = indexed_transaction(0x11, 0x02, 0x01, 0x03);
    let root = root_for_single_leaf(row.txid_leaf_hash());
    let chunk = public_txid_artifact_chunk(0, std::slice::from_ref(&row), Some(root));
    let permit = cache.begin_write().await;
    let mut manifest = permit
        .cache()
        .load_or_new_manifest()
        .expect("load manifest");
    let applied = manifest
        .apply_artifact_chunks(&permit, std::slice::from_ref(&chunk))
        .expect("initial artifact chunk applies");
    assert_eq!(applied, 1);
    manifest.write_to(&permit).expect("write manifest");
    let mut reloaded = permit
        .cache()
        .load_or_new_manifest()
        .expect("reload manifest");

    let stale_applied = reloaded
        .apply_artifact_chunks(&permit, std::slice::from_ref(&chunk))
        .expect("stale artifact chunk should be ignored");

    assert_eq!(stale_applied, 0);
    assert_eq!(reloaded.validated_cached_txid_index, Some(0));

    let second = indexed_transaction(0x22, 0x04, 0x05, 0x06);
    let spanning_root = txid_root_for_transactions(&[row.clone(), second.clone()]);
    let spanning_chunk = public_txid_artifact_chunk(0, &[row, second], Some(spanning_root));
    let stale_bounded_applied = reloaded
        .apply_artifact_chunks_bounded(
            &permit,
            std::slice::from_ref(&spanning_chunk),
            Some(0),
            Some(root),
            0,
        )
        .expect("stale spanning artifact chunk should be ignored");
    assert_eq!(stale_bounded_applied, 0);
    assert_eq!(reloaded.validated_cached_txid_index, Some(0));

    drop(permit);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn txid_public_artifact_chunk_splits_multi_page_chunk() {
    let page_size = NonZeroUsize::new(2).expect("test page size is non-zero");
    let transactions = (0_u8..3)
        .map(|index| indexed_transaction(index + 1, 0x02, 0x01, 0x03))
        .collect::<Vec<_>>();
    let chunk = public_txid_artifact_chunk(0, &transactions, None);

    let pages =
        crate::txid_cache::artifact::test_support::materialize_artifact_pages_with_page_size(
            &chunk, page_size,
        )
        .expect("materialize pages");

    assert_eq!(pages.len(), 2);
    assert_eq!(pages[0].start_index, 0);
    assert_eq!(pages[0].rows.len(), page_size.get());
    assert_eq!(pages[1].start_index, page_size.get() as u64);
    assert_eq!(pages[1].rows.len(), 1);
}

#[test]
fn txid_public_artifact_unshield_sidecar_enriches_rows_and_legacy_remains_readable() {
    let preimage = test_unshield_preimage(0x11);
    let mut transaction = indexed_transaction(1, 2, 3, 4);
    transaction.has_unshield = true;
    transaction.commitments = vec![preimage.hash()];
    let encoded = preimage.abi_encode();
    let chunk = public_txid_artifact_chunk_with_unshield_sidecar(
        7,
        std::slice::from_ref(&transaction),
        &[(7, encoded.clone())],
    );

    let pages =
        crate::txid_cache::artifact::test_support::materialize_artifact_pages_with_page_size(
            &chunk,
            NonZeroUsize::new(10).expect("page size"),
        )
        .expect("materialize artifact sidecar");
    assert_eq!(
        pages[0].rows[0].transaction.unshield_preimage,
        Some(encoded)
    );

    let legacy = public_txid_artifact_chunk(7, &[transaction], None);
    let pages =
        crate::txid_cache::artifact::test_support::materialize_artifact_pages_with_page_size(
            &legacy,
            NonZeroUsize::new(10).expect("page size"),
        )
        .expect("materialize legacy artifact");
    assert_eq!(pages[0].rows[0].transaction.unshield_preimage, None);
}

#[test]
fn txid_public_artifact_rejects_mismatched_unshield_sidecar() {
    let expected = test_unshield_preimage(0x11);
    let mut transaction = indexed_transaction(1, 2, 3, 4);
    transaction.has_unshield = true;
    transaction.commitments = vec![expected.hash()];
    let chunk = public_txid_artifact_chunk_with_unshield_sidecar(
        0,
        &[transaction],
        &[(0, test_unshield_preimage(0x22).abi_encode())],
    );

    let error =
        crate::txid_cache::artifact::test_support::materialize_artifact_pages_with_page_size(
            &chunk,
            NonZeroUsize::new(10).expect("page size"),
        )
        .expect_err("mismatched unshield sidecar must fail");
    assert!(error.to_string().contains("does not match its commitment"));
}

#[test]
fn txid_public_artifact_rejects_duplicate_unshield_sidecar_indexes() {
    let preimage = test_unshield_preimage(0x11);
    let mut first = indexed_transaction(1, 2, 3, 4);
    first.has_unshield = true;
    first.commitments = vec![preimage.hash()];
    let mut second = indexed_transaction(2, 3, 4, 5);
    second.has_unshield = true;
    second.commitments = vec![preimage.hash()];
    let encoded = preimage.abi_encode();
    let chunk = public_txid_artifact_chunk_with_unshield_sidecar(
        0,
        &[first, second],
        &[(0, encoded.clone()), (0, encoded)],
    );

    let error =
        crate::txid_cache::artifact::test_support::materialize_artifact_pages_with_page_size(
            &chunk,
            NonZeroUsize::new(10).expect("page size"),
        )
        .expect_err("duplicate sidecar indexes must fail");
    assert!(error.to_string().contains("not strictly increasing"));
}

#[tokio::test]
async fn txid_public_artifact_failure_before_progress_falls_back_to_graphql() {
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
    let bad_artifact_row = indexed_transaction(0x11, 0x02, 0x01, 0x03);
    let bad_chunk = public_txid_artifact_chunk(0, &[bad_artifact_row], None);
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
            Some(&[bad_chunk]),
        )
        .await
        .expect("GraphQL fallback should populate cache after artifact failure");

    let manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    assert_eq!(manifest.validated_cached_txid_index, Some(0));
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
async fn txid_public_artifact_only_failure_before_progress_returns_error() {
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
    let artifact_row = indexed_transaction(0x44, 0x04, 0x05, 0x06);
    let bad_chunk = public_txid_artifact_chunk(
        0,
        std::slice::from_ref(&artifact_row),
        Some(FixedBytes::from([0xff; 32])),
    );
    let (artifact_source, _artifact_server) = public_txid_artifact_source(vec![bad_chunk]);

    let error = cache
        .sync_with_artifact_source(
            None,
            None,
            TxidPublicLatestValidated {
                txid_index: 0,
                merkleroot: Some(root_for_single_leaf(artifact_row.txid_leaf_hash())),
            },
            Some(&artifact_source),
        )
        .await
        .expect_err("artifact-only sync should return pre-progress artifact failure");

    assert!(matches!(
        error,
        crate::txid_cache::TxidPublicCacheError::MetadataMismatch(message)
            if message.contains("Merkle root mismatch")
    ));
    assert!(
        cache.load_manifest().expect("load manifest").is_none(),
        "failed artifact-only sync should not write successful progress"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
