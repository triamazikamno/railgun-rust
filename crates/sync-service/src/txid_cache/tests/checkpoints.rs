use super::*;

#[test]
fn txid_public_v4_legacy_manifest_defaults_checkpoints_without_dropping_pages() {
    #[derive(Serialize)]
    struct LegacyManifest<'a> {
        format_version: u32,
        chain_type: u8,
        chain_id: u64,
        railgun_contract: Address,
        txid_version: &'a str,
        page_size: usize,
        next_txid_index: u64,
        latest_validated_txid_index: Option<u64>,
        latest_validated_merkleroot: Option<FixedBytes<32>>,
        validated_cached_txid_index: Option<u64>,
        artifact_cached_txid_index: Option<u64>,
        pages: Vec<crate::txid_cache::TxidPublicCachePageRef>,
    }

    let key = test_cache_key();
    let mut manifest: crate::txid_cache::TxidPublicCacheManifest = key.into();
    let page_ref = crate::txid_cache::TxidPublicCachePageRef {
        start_index: 0,
        row_count: 1,
        relative_path: "txid-public/page-0.msgpack".to_string(),
    };
    manifest.next_txid_index = 1;
    manifest.pages.push(page_ref.clone());
    let bytes = rmp_serde::to_vec_named(&LegacyManifest {
        format_version: manifest.format_version,
        chain_type: manifest.chain_type,
        chain_id: manifest.chain_id,
        railgun_contract: manifest.railgun_contract,
        txid_version: &manifest.txid_version,
        page_size: manifest.page_size,
        next_txid_index: manifest.next_txid_index,
        latest_validated_txid_index: manifest.latest_validated_txid_index,
        latest_validated_merkleroot: manifest.latest_validated_merkleroot,
        validated_cached_txid_index: manifest.validated_cached_txid_index,
        artifact_cached_txid_index: manifest.artifact_cached_txid_index,
        pages: manifest.pages,
    })
    .expect("encode legacy v4 manifest");
    let decoded: crate::txid_cache::TxidPublicCacheManifest =
        rmp_serde::from_slice(&bytes).expect("decode legacy v4 manifest");

    assert_eq!(
        decoded.format_version,
        crate::txid_cache::TXID_CACHE_FORMAT_VERSION
    );
    assert_eq!(decoded.pages.len(), 1);
    assert_eq!(decoded.pages[0].start_index, page_ref.start_index);
    assert_eq!(decoded.pages[0].row_count, page_ref.row_count);
    assert_eq!(decoded.pages[0].relative_path, page_ref.relative_path);
    assert!(decoded.checkpoints.is_empty());
}

#[test]
fn txid_public_checkpoint_conflicting_roots_fail() {
    let key = test_cache_key();
    let mut manifest: crate::txid_cache::TxidPublicCacheManifest = key.into();
    manifest.next_txid_index = 1;
    manifest
        .insert_checkpoint(
            0,
            FixedBytes::from([0x11; 32]),
            crate::txid_cache::TxidPublicCheckpointSource::IndexedArtifact,
        )
        .expect("insert checkpoint");
    assert!(matches!(
        manifest.insert_checkpoint(
            0,
            FixedBytes::from([0x22; 32]),
            crate::txid_cache::TxidPublicCheckpointSource::LatestValidated,
        ),
        Err(crate::txid_cache::TxidPublicCacheError::RootMismatch)
    ));
}

#[test]
fn txid_public_checkpoint_replacement_keeps_only_immutable_prefix() {
    let key = test_cache_key();
    let mut manifest: crate::txid_cache::TxidPublicCacheManifest = key.into();
    manifest.next_txid_index = 20;
    for index in [2, 10, 19] {
        manifest
            .insert_checkpoint(
                index,
                FixedBytes::from([index as u8; 32]),
                crate::txid_cache::TxidPublicCheckpointSource::IndexedArtifact,
            )
            .expect("insert checkpoint");
    }

    manifest.invalidate_checkpoints_from(10);

    assert_eq!(
        manifest.checkpoints.keys().copied().collect::<Vec<_>>(),
        vec![2]
    );
}

#[tokio::test]
async fn txid_public_exact_append_preserves_historical_checkpoint() {
    let root_dir = temp_db_root();
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let key = test_cache_key();
    let cache = TxidPublicCache::new(&db, key);
    let first = indexed_transaction(0x71, 0x02, 0x01, 0x03);
    let second = indexed_transaction(0x72, 0x04, 0x05, 0x06);
    let permit = cache.begin_write().await;
    let mut manifest = permit.cache().load_or_new_manifest().expect("manifest");
    let first_page = crate::txid_cache::TxidPublicCachePage::from_indexed_transactions(
        key,
        0,
        vec![first.clone()],
    );
    manifest
        .append_page_after_prefix_validation(&permit, &first_page)
        .expect("append first page");
    let first_root = root_for_single_leaf(first.txid_leaf_hash());
    manifest
        .insert_checkpoint(
            0,
            first_root,
            crate::txid_cache::TxidPublicCheckpointSource::IndexedArtifact,
        )
        .expect("insert historical checkpoint");
    let second_page =
        crate::txid_cache::TxidPublicCachePage::from_indexed_transactions(key, 1, vec![second]);
    manifest
        .append_page_after_prefix_validation(&permit, &second_page)
        .expect("append latest page");

    assert_eq!(
        manifest
            .checkpoints
            .get(&0)
            .map(|checkpoint| checkpoint.merkleroot),
        Some(first_root)
    );

    drop(permit);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_later_artifact_chunk_preserves_earlier_checkpoint() {
    let root_dir = temp_db_root();
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let key = test_cache_key();
    let cache = TxidPublicCache::new(&db, key);
    let first = indexed_transaction(0x73, 0x02, 0x01, 0x03);
    let second = indexed_transaction(0x74, 0x04, 0x05, 0x06);
    let first_chunk = public_txid_artifact_chunk(
        0,
        std::slice::from_ref(&first),
        Some(root_for_single_leaf(first.txid_leaf_hash())),
    );
    let (first_source, _first_server) = public_txid_artifact_source(vec![first_chunk]);
    cache
        .sync_to_indexed_tip(None, None, Some(&first_source))
        .await
        .expect("apply first artifact chunk");

    let second_chunk = public_txid_artifact_chunk(
        1,
        std::slice::from_ref(&second),
        Some(txid_root_for_transactions(&[first.clone(), second.clone()])),
    );
    let (second_source, _second_server) = public_txid_artifact_source(vec![second_chunk]);
    cache
        .sync_to_indexed_tip(None, None, Some(&second_source))
        .await
        .expect("apply later artifact chunk");

    let manifest = cache
        .load_manifest()
        .expect("load artifact manifest")
        .expect("artifact manifest present");
    assert!(manifest.checkpoints.contains_key(&0));
    assert!(manifest.checkpoints.contains_key(&1));

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn txid_public_completed_checkpoint_candidates_are_boundary_only_and_ascending() {
    let through = TREE_LEAF_COUNT * 2 + 17;
    assert_eq!(
        crate::txid_cache::checkpoints::checkpoint_candidate_indexes(through, false),
        vec![TREE_LEAF_COUNT - 1, TREE_LEAF_COUNT * 2 - 1, through]
    );
    assert_eq!(
        crate::txid_cache::checkpoints::checkpoint_candidate_indexes(through, true),
        vec![TREE_LEAF_COUNT - 1, TREE_LEAF_COUNT * 2 - 1]
    );
}

#[tokio::test]
async fn txid_public_checkpoint_commit_rejects_stale_generation() {
    let root_dir = temp_db_root();
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let key = test_cache_key();
    let cache = TxidPublicCache::new(&db, key);
    let permit = cache.begin_write().await;
    let read_scope = permit.scope();
    drop(permit);

    crate::txid_cache::reset_txid_public_cache(&db)
        .await
        .expect("reset TXID cache");
    let error = cache
        .commit_checkpoint(crate::txid_cache::TxidPublicCheckpointCandidate {
            root_txid_index: TREE_LEAF_COUNT - 1,
            tree: 0,
            index: TREE_LEAF_COUNT - 1,
            merkleroot: FixedBytes::from([0x11; 32]),
            read_scope,
        })
        .await
        .expect_err("stale checkpoint candidate must be rejected");
    assert!(matches!(
        error,
        crate::txid_cache::TxidPublicCacheError::StalePublicCacheGeneration { .. }
    ));

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
