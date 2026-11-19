use super::*;

#[test]
fn txid_root_index_uses_latest_index_in_same_tree() {
    assert_eq!(txid_root_index_for_target(5, 9), 9);
}

#[test]
fn txid_root_index_uses_full_tree_when_latest_is_later_tree() {
    assert_eq!(
        txid_root_index_for_target(5, TREE_LEAF_COUNT + 9),
        TREE_LEAF_COUNT - 1
    );
}

#[tokio::test]
async fn all_match_lookup_returns_zero_one_and_multiple_rows_in_index_order_across_pages() {
    let root_dir = temp_db_root();
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let key = test_cache_key();
    let target_hash = FixedBytes::from([0x22; 32]);
    let pages = vec![
        vec![
            indexed_transaction(0x11, 0x01, 0x02, 0x03),
            indexed_transaction(0x22, 0x04, 0x05, 0x06),
        ],
        vec![
            indexed_transaction(0x22, 0x07, 0x08, 0x09),
            indexed_transaction(0x33, 0x0a, 0x0b, 0x0c),
        ],
    ];
    seed_validated_pages(&db, key, pages).await;

    assert!(
        validated_transactions_for_outer_hash(&db, key, FixedBytes::from([0x44; 32]))
            .expect("lookup absent outer hash")
            .is_empty()
    );
    let one = validated_transactions_for_outer_hash(&db, key, FixedBytes::from([0x33; 32]))
        .expect("lookup one inner transaction");
    assert_eq!(one.len(), 1);
    assert_eq!(one[0].txid_index, 3);

    let multiple = validated_transactions_for_outer_hash(&db, key, target_hash)
        .expect("lookup all inner transactions");
    assert_eq!(
        multiple
            .iter()
            .map(|entry| entry.txid_index)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(multiple[0].transaction.nullifiers, vec![U256::from(0x05)]);
    assert_eq!(multiple[1].transaction.commitments, vec![U256::from(0x07)]);

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn all_match_lookup_fails_on_unreadable_later_validated_page() {
    let root_dir = temp_db_root();
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let key = test_cache_key();
    let manifest = seed_validated_pages(
        &db,
        key,
        vec![
            vec![indexed_transaction(0x22, 0x01, 0x02, 0x03)],
            vec![indexed_transaction(0x33, 0x04, 0x05, 0x06)],
        ],
    )
    .await;
    let later_page_path = db.resolve_path(&manifest.pages[1].relative_path);
    fs::remove_file(&later_page_path).expect("remove later page");

    assert!(matches!(
        validated_transactions_for_outer_hash(&db, key, FixedBytes::from([0x22; 32])),
        Err(crate::txid_cache::TxidPublicCacheError::Io(error))
            if error.kind() == std::io::ErrorKind::NotFound
    ));

    fs::write(&later_page_path, b"malformed page").expect("write malformed later page");
    assert!(matches!(
        validated_transactions_for_outer_hash(&db, key, FixedBytes::from([0x22; 32])),
        Err(crate::txid_cache::TxidPublicCacheError::Decode(_))
    ));

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn all_match_lookup_rejects_gapped_and_overlapping_validated_coverage() {
    let root_dir = temp_db_root();
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let key = test_cache_key();
    let mut manifest = seed_validated_pages(
        &db,
        key,
        vec![
            vec![
                indexed_transaction(0x22, 0x01, 0x02, 0x03),
                indexed_transaction(0x11, 0x04, 0x05, 0x06),
            ],
            vec![indexed_transaction(0x22, 0x07, 0x08, 0x09)],
        ],
    )
    .await;

    manifest.pages[1].start_index = 3;
    let permit = TxidPublicCache::new(&db, key).begin_write().await;
    manifest.write_to(&permit).expect("write gapped manifest");
    drop(permit);
    assert!(matches!(
        validated_transactions_for_outer_hash(&db, key, FixedBytes::from([0x22; 32])),
        Err(crate::txid_cache::TxidPublicCacheError::MissingLeaf { index: 2 })
    ));

    manifest.pages[1].start_index = 1;
    let permit = TxidPublicCache::new(&db, key).begin_write().await;
    manifest
        .write_to(&permit)
        .expect("write overlapping manifest");
    drop(permit);
    assert!(matches!(
        validated_transactions_for_outer_hash(&db, key, FixedBytes::from([0x22; 32])),
        Err(crate::txid_cache::TxidPublicCacheError::MetadataMismatch(message))
            if message.contains("overlaps")
    ));

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn all_match_lookup_does_not_stop_at_advisory_hash_index_entry() {
    let root_dir = temp_db_root();
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let key = test_cache_key();
    let target_hash = FixedBytes::from([0x22; 32]);
    seed_validated_pages(
        &db,
        key,
        vec![vec![
            indexed_transaction(0x22, 0x01, 0x02, 0x03),
            indexed_transaction(0x22, 0x04, 0x05, 0x06),
        ]],
    )
    .await;
    let permit = TxidPublicCache::new(&db, key).begin_write().await;
    let mut index = load_index_shard(&db, key, target_hash.0[0]).expect("load hash index");
    index.entries.truncate(1);
    write_index_shard(&permit, &index).expect("write advisory one-row index");
    drop(permit);

    let matches = validated_transactions_for_outer_hash(&db, key, target_hash)
        .expect("lookup all rows independently of advisory index");
    assert_eq!(
        matches
            .iter()
            .map(|entry| entry.txid_index)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn safe_file_component_replaces_path_separators() {
    assert_eq!(
        safe_file_component("V2/Poseidon:Merkle"),
        "V2_Poseidon_Merkle"
    );
}
