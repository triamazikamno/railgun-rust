use super::*;

#[tokio::test]
async fn txid_public_artifact_only_accepts_format_v1_without_stream_partition() {
    txid_public_artifact_only_handles_format_v1_stream_partition(None).await;
}

#[tokio::test]
async fn txid_public_format_v1_serialization_omits_stream_partition() {
    txid_public_artifact_only_handles_format_v1_stream_partition(Some("other-txid-version")).await;
}

#[tokio::test]
async fn txid_public_format_v1_rejects_non_v2_cache_identity() {
    let root_dir = temp_db_root();
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let key = TxidPublicCacheKey {
        chain_type: 0,
        chain_id: 1,
        railgun_contract: artifact_scope().railgun_contract,
        txid_version: "future-txid-version",
    };
    let cache = TxidPublicCache::new(&db, key);
    let artifact_row = indexed_transaction(0x45, 0x04, 0x05, 0x06);
    let artifact_root = root_for_single_leaf(artifact_row.txid_leaf_hash());
    let chunk =
        public_txid_artifact_chunk(0, std::slice::from_ref(&artifact_row), Some(artifact_root));
    let (artifact_source, _artifact_server) = public_txid_artifact_source(vec![chunk]);

    let error = cache
        .sync_with_artifact_source(
            None,
            None,
            TxidPublicLatestValidated {
                txid_index: 0,
                merkleroot: Some(artifact_root),
            },
            Some(&artifact_source),
        )
        .await
        .expect_err("format-v1 artifacts must not satisfy another TXID identity");

    assert!(matches!(
        error,
        crate::txid_cache::TxidPublicCacheError::CacheNotReady {
            next_index: 0,
            required_index: 0,
        }
    ));
    assert!(cache.load_manifest().expect("load manifest").is_none());

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_rejects_malformed_current_catalog_even_with_internal_partition() {
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
    let artifact_row = indexed_transaction(0x46, 0x04, 0x05, 0x06);
    let artifact_root = root_for_single_leaf(artifact_row.txid_leaf_hash());
    let chunk =
        public_txid_artifact_chunk(0, std::slice::from_ref(&artifact_row), Some(artifact_root));
    let malformed_other_partition = IndexedArtifactDescriptor {
        dataset_kind: IndexedDatasetKind::PublicTxid,
        scope: artifact_scope(),
        range: IndexedArtifactRange {
            kind: IndexedArtifactRangeKind::TxidIndex,
            start: 0,
            end: 0,
        },
        row_count: 1,
        cid: "bafyignored".to_string(),
        sha256: FixedBytes::from([0xaa; 32]),
        byte_size: 1,
        encoding_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
        compression: CompressionAlgorithm::None,
        metadata: DatasetDescriptorMetadata {
            stream_partition: Some("other-txid-version".to_string()),
            ..DatasetDescriptorMetadata::default()
        },
    };
    let (artifact_source, _artifact_server) = public_txid_artifact_source_with_extra_catalogs(
        vec![(1, vec![chunk])],
        vec![malformed_other_partition],
    );

    let error = cache
        .sync_with_artifact_source(
            None,
            None,
            TxidPublicLatestValidated {
                txid_index: 0,
                merkleroot: Some(artifact_root),
            },
            Some(&artifact_source),
        )
        .await
        .expect_err("all format-v1 current catalogs must be valid");

    assert!(matches!(
        error,
        crate::txid_cache::TxidPublicCacheError::Artifact(_)
    ));
    assert!(cache.load_manifest().expect("load manifest").is_none());

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_rejects_overlapping_internal_partitions_in_format_v1() {
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
    let requested_row = indexed_transaction(0x47, 0x04, 0x05, 0x06);
    let requested_root = root_for_single_leaf(requested_row.txid_leaf_hash());
    let requested_chunk = public_txid_artifact_chunk(
        0,
        std::slice::from_ref(&requested_row),
        Some(requested_root),
    );
    let other_row = indexed_transaction(0x48, 0x07, 0x08, 0x09);
    let other_root = root_for_single_leaf(other_row.txid_leaf_hash());
    let mut other_chunk =
        public_txid_artifact_chunk(0, std::slice::from_ref(&other_row), Some(other_root));
    other_chunk.descriptor.metadata.stream_partition = Some("other-txid-version".to_string());
    let (artifact_source, _artifact_server) =
        public_txid_artifact_source(vec![requested_chunk, other_chunk]);

    let error = cache
        .sync_with_artifact_source(
            None,
            None,
            TxidPublicLatestValidated {
                txid_index: 0,
                merkleroot: Some(requested_root),
            },
            Some(&artifact_source),
        )
        .await
        .expect_err("format-v1 has one implicit TXID identity");

    assert!(matches!(
        error,
        crate::txid_cache::TxidPublicCacheError::MetadataMismatch(message)
            if message.contains("overlapping chunks")
    ));
    assert!(cache.load_manifest().expect("load manifest").is_none());

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

async fn txid_public_artifact_only_handles_format_v1_stream_partition(
    stream_partition: Option<&str>,
) {
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
    let artifact_row = indexed_transaction(0x45, 0x04, 0x05, 0x06);
    let artifact_root = root_for_single_leaf(artifact_row.txid_leaf_hash());
    let mut chunk =
        public_txid_artifact_chunk(0, std::slice::from_ref(&artifact_row), Some(artifact_root));
    chunk.descriptor.metadata.stream_partition = stream_partition.map(str::to_string);
    let (artifact_source, _artifact_server) = public_txid_artifact_source(vec![chunk]);

    let result = cache
        .sync_with_artifact_source(
            None,
            None,
            TxidPublicLatestValidated {
                txid_index: 0,
                merkleroot: Some(artifact_root),
            },
            Some(&artifact_source),
        )
        .await;

    result.expect("format-v1 serialization omits internal partition metadata");
    assert_eq!(
        cache
            .load_manifest()
            .expect("load manifest")
            .expect("manifest present")
            .validated_cached_txid_index,
        Some(0)
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_artifact_only_empty_source_does_not_write_latest_marker() {
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
    let (artifact_source, _artifact_server) = public_txid_empty_artifact_source();

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
        .expect_err("artifact-only empty source must not claim latest support");

    assert!(matches!(
        error,
        crate::txid_cache::TxidPublicCacheError::CacheNotReady {
            next_index: 0,
            required_index: 0,
        }
    ));
    assert!(
        cache.load_manifest().expect("load manifest").is_none(),
        "empty artifact-only sync must not write unsupported latest metadata"
    );
    assert!(
        cache
            .cached_latest_validated()
            .expect("read latest marker")
            .is_none(),
        "empty artifact-only sync must not return unsupported latest metadata"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
