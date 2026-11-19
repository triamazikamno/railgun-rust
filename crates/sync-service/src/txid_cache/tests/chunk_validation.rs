use super::*;

#[tokio::test]
async fn txid_public_artifact_chunk_rejects_same_tree_boundary_crossing() {
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
    let rows = vec![
        indexed_transaction(0x11, 0x02, 0x01, 0x03),
        indexed_transaction(0x12, 0x04, 0x05, 0x06),
    ];
    let chunk = public_txid_artifact_chunk(
        TREE_LEAF_COUNT - 1,
        &rows,
        Some(FixedBytes::from([0x44; 32])),
    );
    let cache = TxidPublicCache::new(&db, key);
    let permit = cache.begin_write().await;
    let mut manifest = permit
        .cache()
        .load_or_new_manifest()
        .expect("load manifest");
    manifest.validated_cached_txid_index = Some(TREE_LEAF_COUNT - 2);

    let error = manifest
        .apply_artifact_chunks(&permit, &[chunk])
        .expect_err("same-tree boundary crossing should fail");

    assert!(matches!(
        error,
        crate::txid_cache::TxidPublicCacheError::MetadataMismatch(message)
            if message.contains("spans multiple TXID trees")
    ));
    assert_eq!(
        manifest.validated_cached_txid_index,
        Some(TREE_LEAF_COUNT - 2)
    );

    drop(permit);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_artifact_chunk_waits_for_missing_prefix_rows() {
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
    let prefix_root = txid_root_for_transactions(&[first, second.clone()]);
    let chunk = public_txid_artifact_chunk(1, &[second], Some(prefix_root));
    let cache = TxidPublicCache::new(&db, key);
    let permit = cache.begin_write().await;
    let mut manifest = permit
        .cache()
        .load_or_new_manifest()
        .expect("load manifest");
    manifest.validated_cached_txid_index = Some(0);

    let error = manifest
        .apply_artifact_chunks(&permit, &[chunk])
        .expect_err("missing prefix row should fail");

    assert!(matches!(
        error,
        crate::txid_cache::TxidPublicCacheError::MissingLeaf { index: 0 }
    ));
    assert_eq!(manifest.validated_cached_txid_index, Some(0));

    drop(permit);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_artifact_chunk_rejects_prefix_root_mismatch() {
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
    let first_chunk = public_txid_artifact_chunk(0, &[first], Some(first_root));
    let cache = TxidPublicCache::new(&db, key);
    let permit = cache.begin_write().await;
    let mut manifest = permit
        .cache()
        .load_or_new_manifest()
        .expect("load manifest");
    manifest
        .apply_artifact_chunks(&permit, &[first_chunk])
        .expect("seed prefix row");
    let bad_second_chunk =
        public_txid_artifact_chunk(1, &[second], Some(FixedBytes::from([0xee; 32])));

    let error = manifest
        .apply_artifact_chunks(&permit, &[bad_second_chunk])
        .expect_err("prefix root mismatch should fail");

    assert!(matches!(
        error,
        crate::txid_cache::TxidPublicCacheError::MetadataMismatch(message)
            if message.contains("Merkle root mismatch")
    ));
    assert_eq!(manifest.validated_cached_txid_index, Some(0));

    drop(permit);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_artifact_chunk_rejects_missing_root_without_progress() {
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
    let row = indexed_transaction(0x11, 0x02, 0x01, 0x03);
    let chunk = public_txid_artifact_chunk(0, &[row], None);
    let cache = TxidPublicCache::new(&db, key);
    let permit = cache.begin_write().await;
    let mut manifest = permit
        .cache()
        .load_or_new_manifest()
        .expect("load manifest");

    let error = manifest
        .apply_artifact_chunks(&permit, &[chunk])
        .expect_err("missing root should fail");

    assert!(matches!(
        error,
        crate::txid_cache::TxidPublicCacheError::MetadataMismatch(message)
            if message.contains("missing Merkle root")
    ));
    assert_eq!(manifest.validated_cached_txid_index, None);
    assert!(manifest.pages.is_empty());

    drop(permit);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_artifact_chunk_rejects_root_mismatch_and_previous_section_without_progress() {
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
    let row = indexed_transaction(0x11, 0x02, 0x01, 0x03);
    let chunk = public_txid_artifact_chunk(
        0,
        std::slice::from_ref(&row),
        Some(FixedBytes::from([0xff; 32])),
    );
    let cache = TxidPublicCache::new(&db, key);
    let permit = cache.begin_write().await;
    let mut manifest = permit
        .cache()
        .load_or_new_manifest()
        .expect("load manifest");

    let error = manifest
        .apply_artifact_chunks(&permit, &[chunk])
        .expect_err("root mismatch should fail");

    assert!(matches!(
        error,
        crate::txid_cache::TxidPublicCacheError::MetadataMismatch(message)
            if message.contains("Merkle root mismatch")
    ));
    assert_eq!(manifest.validated_cached_txid_index, None);
    assert!(manifest.pages.is_empty());

    let rows = std::slice::from_ref(&row);
    let previous_section_chunk = verified_public_txid_artifact_chunk(
        0,
        rows,
        Some(txid_root_for_transactions(rows)),
        public_txid_artifact_envelope_in_section(
            0,
            0,
            1,
            1,
            &public_txid_artifact_payload(0, rows),
        ),
    );

    let error = manifest
        .apply_artifact_chunks(&permit, &[previous_section_chunk])
        .expect_err("chunk with only the previous record section should fail");

    assert!(matches!(
        error,
        crate::txid_cache::TxidPublicCacheError::Artifact(
            crate::indexed_artifacts::IndexedArtifactManifestError::ChunkSectionMissing {
                section_id: PUBLIC_TXID_RECORD_SECTION_ID
            }
        )
    ));
    assert_eq!(manifest.validated_cached_txid_index, None);
    assert!(manifest.pages.is_empty());

    drop(permit);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn txid_public_artifact_rejects_extreme_row_count_without_allocation() {
    let chunk = public_txid_artifact_chunk_from_payload(0, 0, u64::MAX, &[], None);

    let error = Vec::<crate::txid_cache::TxidPublicCachePage>::try_from(&chunk)
        .expect_err("extreme row count should be rejected as format error");

    assert!(matches!(
        error,
        crate::txid_cache::TxidPublicCacheError::MetadataMismatch(message)
            if message.contains("row count mismatch")
    ));
}

#[test]
fn txid_public_artifact_rejects_extreme_vector_count_without_allocation() {
    let mut payload = Vec::new();
    write_u64(&mut payload, 0);
    write_string(&mut payload, "0x00");
    write_u64(&mut payload, 12);
    write_u64(&mut payload, 1_700_000_012);
    payload.extend_from_slice(&[0xaa; 32]);
    payload.extend_from_slice(&[0x21; 32]);
    write_u64(&mut payload, 1);
    write_u64(&mut payload, 1);
    write_u32(&mut payload, u32::MAX);
    let chunk = public_txid_artifact_chunk_from_payload(0, 0, 1, &payload, None);

    let error = Vec::<crate::txid_cache::TxidPublicCachePage>::try_from(&chunk)
        .expect_err("extreme vector count should be rejected as format error");

    assert!(matches!(
        error,
        crate::txid_cache::TxidPublicCacheError::MetadataMismatch(message)
            if message.contains("ended while reading nullifiers")
    ));
}

#[test]
fn txid_public_cache_root_conflict_above_artifact_bound_preserves_provenance() {
    let key = test_cache_key();
    let mut manifest: crate::txid_cache::TxidPublicCacheManifest = key.into();
    manifest.next_txid_index = 6;
    manifest.validated_cached_txid_index = Some(5);
    manifest.latest_validated_txid_index = Some(5);
    manifest.latest_validated_merkleroot = Some(FixedBytes::from([0x11; 32]));
    manifest.artifact_cached_txid_index = Some(2);
    manifest
        .insert_checkpoint(
            5,
            FixedBytes::from([0x11; 32]),
            crate::txid_cache::TxidPublicCheckpointSource::LatestValidated,
        )
        .expect("insert stale checkpoint");

    assert!(
        manifest.reconcile_validated_progress_for_latest(TxidPublicLatestValidated {
            txid_index: 5,
            merkleroot: Some(FixedBytes::from([0x22; 32])),
        })
    );
    assert_eq!(manifest.latest_validated_txid_index, None);
    assert_eq!(manifest.latest_validated_merkleroot, None);
    assert_eq!(manifest.validated_cached_txid_index, Some(2));
    assert_eq!(manifest.artifact_cached_txid_index, Some(2));
    assert!(manifest.checkpoints.is_empty());
}
