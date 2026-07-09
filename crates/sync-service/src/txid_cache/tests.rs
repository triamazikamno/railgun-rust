use super::{
    TxidPublicCache, TxidPublicCacheKey, TxidPublicLatestValidated, index_entries_for_hash,
    safe_file_component, txid_public_proof_for_recovered_output,
    txid_public_proof_for_recovered_output_at_index, txid_public_transaction_for_recovered_output,
    txid_root_index_for_target,
};
use crate::indexed_artifacts::{
    ChainScope, ChainType, CompressionAlgorithm, DatasetDescriptorMetadata,
    INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION, INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION,
    INDEXED_ARTIFACT_CHUNK_MAGIC, IndexedArtifactCatalog, IndexedArtifactChainEntry,
    IndexedArtifactDescriptor, IndexedArtifactManifest, IndexedArtifactRange,
    IndexedArtifactRangeKind, IndexedDatasetKind, LatestIndexedHeight, PublisherIdentity,
    VerifiedIndexedArtifactChunk,
};
use crate::types::{IndexedArtifactManifestSource, IndexedArtifactSourceConfig};
use alloy::primitives::{Address, FixedBytes, U64, U256};
use broadcaster_core::tree::TREE_LEAF_COUNT;
use cid::Cid;
use ed25519_dalek::SigningKey;
use local_db::{BlobMeta, DbConfig, DbStore};
use merkletree::quick::IndexedRailgunTransaction;
use merkletree::tree::DenseMerkleTree;
use multihash_codetable::{Code, MultihashDigest};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::{Cursor, Read, Write};
use std::net::TcpListener;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;
use url::Url;

static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);
const RAW_CODEC: u64 = 0x55;
const TEST_TXID_VERSION: &str = "V2_PoseidonMerkle";

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

#[test]
fn safe_file_component_replaces_path_separators() {
    assert_eq!(
        safe_file_component("V2/Poseidon:Merkle"),
        "V2_Poseidon_Merkle"
    );
}

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
        let page = super::TxidPublicCachePage::from_indexed_transactions(key, 0, vec![row]);
        manifest.append_page(&permit, &page).expect("append page");
        super::update_index_for_page(&permit, &page).expect("write contract index");
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
    assert_ne!(super::cache_id(key_a), super::cache_id(key_b));
    assert_ne!(
        super::manifest_file_name(key_a),
        super::manifest_file_name(key_b)
    );
    assert_ne!(
        super::page_file_name(key_a, 0),
        super::page_file_name(key_b, 0)
    );
    assert_ne!(
        super::index_shard_file_name(key_a, 0x31),
        super::index_shard_file_name(key_b, 0x31)
    );
    assert_ne!(
        super::artifact_chunk_blob_id(key_a, "shared-cid"),
        super::artifact_chunk_blob_id(key_b, "shared-cid")
    );
    assert_ne!(
        super::artifact_chunk_file_name(key_a, "shared-cid"),
        super::artifact_chunk_file_name(key_b, "shared-cid")
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
            super::TXID_CACHE_BLOB_KIND,
            &super::artifact_chunk_blob_id(key_b, &retained_cid),
        )
        .expect("read contract B retained chunk")
        .is_some()
    );
    assert!(
        db.get_blob_meta(
            super::TXID_CACHE_BLOB_KIND,
            &super::artifact_chunk_blob_id(key_a, &retained_cid),
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
    let index_a = super::load_index_shard(&db, key_a, 0x31).expect("read contract A index");
    let index_b = super::load_index_shard(&db, key_b, 0x32).expect("read contract B index");
    assert_eq!(index_a.railgun_contract, key_a.railgun_contract);
    assert_eq!(index_b.railgun_contract, key_b.railgun_contract);
    assert_eq!(index_a.entries.len(), 1);
    assert_eq!(index_b.entries.len(), 1);
    assert!(
        super::load_index_shard(&db, key_b, 0x31)
            .expect("read isolated contract B index shard")
            .entries
            .is_empty()
    );
    assert!(matches!(
        manifest_a.pages[0].read(&db, key_b),
        Err(super::TxidPublicCacheError::MetadataMismatch(_))
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
        Err(super::TxidPublicCacheError::MissingTarget)
    ));

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_cache_v3_rebuild_leaves_contractless_v2_cache_untouched() {
    let root_dir = temp_db_root();
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let legacy_id = format!("0|1|{TEST_TXID_VERSION}");
    let legacy_name = "0-1-V2_PoseidonMerkle-manifest.msgpack";
    let legacy_bytes = b"contractless-v2-cache";
    let legacy_path = db.blob_path(super::TXID_CACHE_BLOB_KIND, legacy_name);
    db.ensure_blob_dir(super::TXID_CACHE_BLOB_KIND)
        .expect("ensure TXID cache dir");
    fs::write(&legacy_path, legacy_bytes).expect("write v2 cache file");
    db.put_blob_meta(
        super::TXID_CACHE_BLOB_KIND,
        &legacy_id,
        &BlobMeta {
            format_version: 2,
            relative_path: DbStore::relative_blob_path(super::TXID_CACHE_BLOB_KIND, legacy_name),
            content_hash: Sha256::digest(legacy_bytes).into(),
            source_hash: None,
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
    assert!(cache.load_manifest().expect("load v3 cache").is_none());

    let permit = cache.begin_write().await;
    permit
        .cache()
        .load_or_new_manifest()
        .expect("new v3 manifest")
        .write_to(&permit)
        .expect("write v3 manifest");
    drop(permit);

    assert!(
        legacy_path.exists(),
        "v2 cache file must not be destructively migrated"
    );
    assert!(
        db.get_blob_meta(super::TXID_CACHE_BLOB_KIND, &legacy_id)
            .expect("read v2 metadata")
            .is_some(),
        "v2 cache metadata must remain untouched"
    );
    let v3_meta = db
        .get_blob_meta(super::TXID_CACHE_BLOB_KIND, &super::cache_id(key))
        .expect("read v3 metadata")
        .expect("v3 metadata present");
    assert_eq!(v3_meta.format_version, 3);
    assert_ne!(
        v3_meta.relative_path,
        DbStore::relative_blob_path(super::TXID_CACHE_BLOB_KIND, legacy_name)
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
        None,
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
        cached.transaction.merkle_root,
        U256::from_be_bytes([0x22; 32])
    );
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
    let corrected = indexed_transaction(0x22, 0x04, 0x05, 0x06);
    let (prefetch_endpoint, _prefetch_requests) =
        spawn_graphql_response(public_txid_response(vec![stale.clone()]));

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

    let corrected_leaf = corrected.txid_leaf_hash();
    let corrected_root = root_for_single_leaf(corrected_leaf);
    let (validated_endpoint, _validated_requests) =
        spawn_graphql_response(public_txid_response(vec![corrected.clone()]));
    cache
        .sync(
            &validated_endpoint,
            None,
            TxidPublicLatestValidated {
                txid_index: 0,
                merkleroot: Some(corrected_root),
            },
        )
        .await
        .expect("refresh newly validated row");

    let manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    let refreshed_row = super::row_for_txid_index(&manifest, &db, 0)
        .expect("read refreshed row")
        .expect("refreshed row present");
    assert_eq!(
        refreshed_row.txid_leaf_hash,
        FixedBytes::from(corrected_leaf.to_be_bytes::<32>())
    );
    assert_eq!(manifest.validated_cached_txid_index, Some(0));
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
        spawn_graphql_response(public_txid_response(vec![filler, stale_duplicate.clone()]));

    cache
        .sync_to_graph_tip(&prefetch_endpoint, None)
        .await
        .expect("prefetch stale duplicate row");
    let (validated_endpoint, _validated_requests) =
        spawn_graphql_response(public_txid_response(vec![canonical.clone()]));
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
    let stale_row = super::row_for_txid_index(&manifest, &db, 1)
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
    let (endpoint, requests) = spawn_graphql_response(public_txid_response(vec![target.clone()]));

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
        spawn_graphql_response(public_txid_response(vec![stale.clone(), stale_tail]));
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
        spawn_graphql_response(public_txid_response(vec![canonical.clone()]));
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
    let refreshed = super::row_for_txid_index(&manifest, &db, 0)
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
        spawn_graphql_response(public_txid_response(vec![stale]));

    cache
        .sync_to_graph_tip(&prefetch_endpoint, None)
        .await
        .expect("prefetch stale graph-tip row");
    let (empty_endpoint, _empty_requests) = spawn_graphql_response(public_txid_response(vec![]));
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
        super::TxidPublicCacheError::CacheNotReady {
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
        super::TxidPublicCacheError::CacheNotReady {
            next_index: 0,
            required_index: 0,
        }
    ));

    let (corrected_endpoint, _corrected_requests) =
        spawn_graphql_response(public_txid_response(vec![corrected.clone()]));
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
    let refreshed_row = super::row_for_txid_index(&manifest, &db, 0)
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
        spawn_delayed_graphql_response(public_txid_response(vec![graph_row]));
    let sync_turn = super::TXID_CACHE_SYNC_LOCK.lock().await;
    let sync_db = Arc::clone(&db);
    let sync_endpoint = endpoint.clone();
    let sync_handle = tokio::spawn(async move {
        TxidPublicCache::new(sync_db.as_ref(), key)
            .sync_to_graph_tip(&sync_endpoint, None)
            .await
    });
    tokio::task::yield_now().await;
    drop(sync_turn);
    tokio::task::spawn_blocking(move || requests.recv_timeout(Duration::from_secs(120)))
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
        spawn_delayed_graphql_response(public_txid_response(vec![second.clone()]));
    let sync_turn = super::TXID_CACHE_SYNC_LOCK.lock().await;
    let sync_db = Arc::clone(&db);
    let sync_endpoint = endpoint.clone();
    let sync_handle = tokio::spawn(async move {
        TxidPublicCache::new(sync_db.as_ref(), key)
            .sync_to_graph_tip(&sync_endpoint, None)
            .await
    });
    tokio::task::yield_now().await;
    drop(sync_turn);
    tokio::task::spawn_blocking(move || requests.recv_timeout(Duration::from_secs(120)))
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
    let second_row = super::row_for_txid_index(&manifest, &db, 1)
        .expect("read background row")
        .expect("background row present");
    assert_eq!(
        second_row.transaction.transaction_hash,
        second.transaction_hash
    );

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
    let manifest = super::TxidPublicCacheManifest {
        format_version: super::TXID_CACHE_FORMAT_VERSION,
        chain_type: key.chain_type,
        chain_id: key.chain_id,
        railgun_contract: key.railgun_contract,
        txid_version: key.txid_version.to_string(),
        page_size: super::TXID_CACHE_PAGE_SIZE.get(),
        next_txid_index,
        latest_validated_txid_index: None,
        latest_validated_merkleroot: None,
        validated_cached_txid_index: None,
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
        super::TxidPublicCacheError::Sync(
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
    let manifest = super::TxidPublicCacheManifest {
        format_version: super::TXID_CACHE_FORMAT_VERSION,
        chain_type: key.chain_type,
        chain_id: key.chain_id,
        railgun_contract: key.railgun_contract,
        txid_version: key.txid_version.to_string(),
        page_size: super::TXID_CACHE_PAGE_SIZE.get(),
        next_txid_index: 1,
        latest_validated_txid_index: Some(0),
        latest_validated_merkleroot: None,
        validated_cached_txid_index: Some(0),
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

#[tokio::test]
async fn txid_public_artifact_chunks_materialize_out_of_order_with_checkpoint_roots() {
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
    let first_row = super::row_for_txid_index(&manifest, &db, 0)
        .expect("read first row")
        .expect("first row present");
    let second_row = super::row_for_txid_index(&manifest, &db, 1)
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
    let transactions = (0..=super::TXID_CACHE_PAGE_SIZE.get())
        .map(|index| indexed_transaction((index % 251 + 1) as u8, 0x02, 0x01, 0x03))
        .collect::<Vec<_>>();
    let chunk = public_txid_artifact_chunk(0, &transactions, None);

    let pages = Vec::<super::TxidPublicCachePage>::try_from(&chunk).expect("materialize pages");

    assert_eq!(pages.len(), 2);
    assert_eq!(pages[0].start_index, 0);
    assert_eq!(pages[0].rows.len(), super::TXID_CACHE_PAGE_SIZE.get());
    assert_eq!(
        pages[1].start_index,
        super::TXID_CACHE_PAGE_SIZE.get() as u64
    );
    assert_eq!(pages[1].rows.len(), 1);
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
        spawn_graphql_response(public_txid_response(vec![graph_row.clone()]));

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
    let row = super::row_for_txid_index(&manifest, &db, 0)
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
        super::TxidPublicCacheError::MetadataMismatch(message)
            if message.contains("Merkle root mismatch")
    ));
    assert!(
        cache.load_manifest().expect("load manifest").is_none(),
        "failed artifact-only sync should not write successful progress"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_artifact_only_rejects_missing_stream_partition() {
    txid_public_artifact_only_rejects_unsupported_stream_partition(None).await;
}

#[tokio::test]
async fn txid_public_artifact_only_rejects_different_stream_partition() {
    txid_public_artifact_only_rejects_unsupported_stream_partition(Some("other-txid-version"))
        .await;
}

#[tokio::test]
async fn txid_public_ignores_malformed_catalog_for_different_stream_partition() {
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

    cache
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
        .expect("different partition catalog must not affect TXID sync");

    let manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    assert_eq!(manifest.validated_cached_txid_index, Some(0));

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_accepts_matching_chunk_from_multi_partition_catalog() {
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

    cache
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
        .expect("multi-partition catalog should expose requested TXID chunk");

    let manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    assert_eq!(manifest.validated_cached_txid_index, Some(0));
    let row = super::row_for_txid_index(&manifest, &db, 0)
        .expect("read requested row")
        .expect("requested row present");
    assert_eq!(
        row.transaction.transaction_hash,
        requested_row.transaction_hash
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

async fn txid_public_artifact_only_rejects_unsupported_stream_partition(
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
        .expect_err("unsupported partition must not satisfy artifact-only latest sync");

    assert!(matches!(
        error,
        super::TxidPublicCacheError::CacheNotReady {
            next_index: 0,
            required_index: 0,
        }
    ));
    assert!(
        cache.load_manifest().expect("load manifest").is_none(),
        "unsupported partition must not write public TXID progress or latest metadata"
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
        super::TxidPublicCacheError::CacheNotReady {
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
        spawn_graphql_response(public_txid_response(vec![graph_row.clone()]));

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
    let row = super::row_for_txid_index(&manifest, &db, 0)
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
async fn txid_public_artifact_failure_after_partial_apply_falls_back_to_graphql() {
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
    let (prefetch_endpoint, _prefetch_requests) =
        spawn_graphql_response(public_txid_response(vec![
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

    let artifact_first = indexed_transaction(0x41, 0x07, 0x08, 0x09);
    let artifact_second = indexed_transaction(0x42, 0x0a, 0x0b, 0x0c);
    let first_root = root_for_single_leaf(artifact_first.txid_leaf_hash());
    let first_chunk = public_txid_artifact_chunk(0, &[artifact_first], Some(first_root));
    let bad_second_chunk =
        public_txid_artifact_chunk(1, &[artifact_second], Some(FixedBytes::from([0xee; 32])));
    let graph_first = indexed_transaction(0x51, 0x0d, 0x0e, 0x0f);
    let graph_second = indexed_transaction(0x52, 0x10, 0x11, 0x12);
    let graph_root = txid_root_for_transactions(&[graph_first.clone(), graph_second.clone()]);
    let (endpoint, requests) = spawn_graphql_response(public_txid_response(vec![
        graph_first.clone(),
        graph_second.clone(),
    ]));

    cache
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
        .expect("artifact failure before durable progress should fall back to GraphQL");
    let after_manifest = cache
        .load_manifest()
        .expect("reload manifest")
        .expect("manifest present");
    assert_eq!(after_manifest.validated_cached_txid_index, Some(1));
    assert_eq!(after_manifest.latest_validated_merkleroot, Some(graph_root));
    let after_page = after_manifest.pages[0]
        .read(&db, key)
        .expect("read fallback page");
    assert_eq!(after_page.rows.len(), 2);
    assert_eq!(
        after_page.rows[0].transaction.transaction_hash,
        graph_first.transaction_hash
    );
    assert_eq!(
        after_page.rows[1].transaction.transaction_hash,
        graph_second.transaction_hash
    );
    let request = requests
        .recv_timeout(Duration::from_secs(5))
        .expect("GraphQL fallback request received");
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
        spawn_graphql_response(public_txid_response(vec![graph_row]));

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
    let row = super::row_for_txid_index(&manifest, &db, 0)
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
async fn txid_public_artifact_uses_planner_for_replaced_final_tail() {
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

    cache
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
        .expect("planner should select only replacement current TXID chunk");

    let manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    assert_eq!(manifest.next_txid_index, 2);
    assert_eq!(manifest.validated_cached_txid_index, Some(1));
    let first_row = super::row_for_txid_index(&manifest, &db, 0)
        .expect("read first row")
        .expect("first row present");
    assert_eq!(
        first_row.transaction.transaction_hash,
        new_first.transaction_hash
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_rejects_current_repack_over_stable_prior_tail() {
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
    let original_rows = (0..10)
        .map(|offset| {
            let offset = offset as u8;
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
    let before_row_5 = super::row_for_txid_index(&before_manifest, &db, 5)
        .expect("read row 5 before invalid repack")
        .expect("row 5 present before invalid repack");
    let before_row_9 = super::row_for_txid_index(&before_manifest, &db, 9)
        .expect("read row 9 before invalid repack")
        .expect("row 9 present before invalid repack");

    let next_rows = (0..10)
        .map(|offset| {
            let offset = offset as u8;
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
    let repacked_rows = (0..10)
        .map(|offset| {
            let offset = offset as u8;
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
        .expect_err("stable prior-tail conflict must reject the invalid current repack");

    assert!(matches!(
        error,
        super::TxidPublicCacheError::MetadataMismatch(message)
            if message.contains("stable chunk")
    ));
    let after_manifest = cache
        .load_manifest()
        .expect("load manifest after invalid repack")
        .expect("manifest present after invalid repack");
    assert_eq!(after_manifest.validated_cached_txid_index, Some(9));
    assert_eq!(after_manifest.next_txid_index, 10);
    let after_row_5 = super::row_for_txid_index(&after_manifest, &db, 5)
        .expect("read row 5 after invalid repack")
        .expect("row 5 present after invalid repack");
    let after_row_9 = super::row_for_txid_index(&after_manifest, &db, 9)
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
        super::row_for_txid_index(&after_manifest, &db, 10)
            .expect("read row 10 after invalid repack")
            .is_none(),
        "invalid stream view must not append current rows after the prior conflict"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_background_retains_prior_tail_when_current_chunk_advances() {
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
    let retained_bytes = prior_tail.bytes.clone();
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
        .expect("current chunk should apply and prior tail should be retained");

    assert_eq!(fetched, 1);
    let manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    assert_eq!(manifest.validated_cached_txid_index, Some(1));
    let second_row = super::row_for_txid_index(&manifest, &db, 1)
        .expect("read current row")
        .expect("current row present");
    assert_eq!(
        second_row.transaction.transaction_hash,
        second.transaction_hash
    );
    let meta = db
        .get_blob_meta(
            super::TXID_CACHE_BLOB_KIND,
            &super::artifact_chunk_blob_id(key, &retained_cid),
        )
        .expect("read retained chunk metadata")
        .expect("prior tail chunk metadata present");
    let retained = fs::read(db.resolve_path(&meta.relative_path)).expect("read retained chunk");
    assert_eq!(retained, retained_bytes);

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_validated_artifact_retains_non_final_current_chunk() {
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
            super::TXID_CACHE_BLOB_KIND,
            &super::artifact_chunk_blob_id(key, &first_cid),
        )
        .expect("read first chunk metadata")
        .expect("non-final current chunk metadata present");
    let retained_first = fs::read(db.resolve_path(&first_meta.relative_path))
        .expect("read retained first current chunk");
    assert_eq!(retained_first, first_bytes);
    assert!(
        db.get_blob_meta(
            super::TXID_CACHE_BLOB_KIND,
            &super::artifact_chunk_blob_id(key, &second_cid),
        )
        .expect("read final current chunk metadata")
        .is_none(),
        "final latest chunk should not be retained as reusable prior context"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_background_retains_prior_tail_not_repeated_by_current_catalog() {
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
    let retained_bytes = prior_tail.bytes.clone();
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
        .expect("current chunk should apply and non-repeated prior tail should be retained");

    assert_eq!(fetched, 1);
    let manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    assert_eq!(manifest.validated_cached_txid_index, Some(1));
    let second_row = super::row_for_txid_index(&manifest, &db, 1)
        .expect("read current row")
        .expect("current row present");
    assert_eq!(
        second_row.transaction.transaction_hash,
        second.transaction_hash
    );
    let meta = db
        .get_blob_meta(
            super::TXID_CACHE_BLOB_KIND,
            &super::artifact_chunk_blob_id(key, &retained_cid),
        )
        .expect("read retained chunk metadata")
        .expect("prior tail chunk metadata present");
    let retained = fs::read(db.resolve_path(&meta.relative_path)).expect("read retained chunk");
    assert_eq!(retained, retained_bytes);

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_background_artifact_retains_prior_tail_after_progress() {
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
    let first = indexed_transaction(0x64, 0x02, 0x01, 0x03);
    let second = indexed_transaction(0x65, 0x04, 0x05, 0x06);
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

    let first_root = root_for_single_leaf(first.txid_leaf_hash());
    let prior_tail = public_txid_artifact_chunk(0, std::slice::from_ref(&first), Some(first_root));
    let retained_cid = raw_cid(&prior_tail.bytes).to_string();
    let retained_bytes = prior_tail.bytes.clone();
    let current_tail =
        public_txid_artifact_chunk(1, std::slice::from_ref(&second), Some(prefix_root));
    let (retention_source, _retention_server) = public_txid_artifact_source_with_catalogs(vec![
        (1, vec![prior_tail.clone()]),
        (2, vec![prior_tail, current_tail]),
    ]);

    let fetched = cache
        .sync_to_indexed_tip(None, None, Some(&retention_source))
        .await
        .expect("background retention pass should not need current rows");

    assert_eq!(fetched, 0);
    let meta = db
        .get_blob_meta(
            super::TXID_CACHE_BLOB_KIND,
            &super::artifact_chunk_blob_id(key, &retained_cid),
        )
        .expect("read retained chunk metadata")
        .expect("prior tail chunk metadata present");
    let retained = fs::read(db.resolve_path(&meta.relative_path)).expect("read retained chunk");
    assert_eq!(retained, retained_bytes);

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_background_retains_prior_tail_with_graphql_fallback_configured() {
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

    let first_root = root_for_single_leaf(first.txid_leaf_hash());
    let prior_tail = public_txid_artifact_chunk(0, std::slice::from_ref(&first), Some(first_root));
    let retained_cid = raw_cid(&prior_tail.bytes).to_string();
    let retained_bytes = prior_tail.bytes.clone();
    let current_tail =
        public_txid_artifact_chunk(1, std::slice::from_ref(&second), Some(prefix_root));
    let (retention_source, _retention_server) = public_txid_artifact_source_with_catalogs(vec![
        (1, vec![prior_tail.clone()]),
        (2, vec![prior_tail, current_tail]),
    ]);
    let (graph_endpoint, graph_requests) = spawn_graphql_response(public_txid_response(vec![]));

    let fetched = cache
        .sync_to_indexed_tip(Some(&graph_endpoint), None, Some(&retention_source))
        .await
        .expect("retention should run after no-progress GraphQL fallback");

    assert_eq!(fetched, 0);
    let request = graph_requests
        .recv_timeout(Duration::from_secs(5))
        .expect("GraphQL fallback request received");
    assert!(request.contains("PublicTxidPage"));
    let meta = db
        .get_blob_meta(
            super::TXID_CACHE_BLOB_KIND,
            &super::artifact_chunk_blob_id(key, &retained_cid),
        )
        .expect("read retained chunk metadata")
        .expect("prior tail chunk metadata present");
    let retained = fs::read(db.resolve_path(&meta.relative_path)).expect("read retained chunk");
    assert_eq!(retained, retained_bytes);

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

    super::reset_txid_public_cache(&db)
        .await
        .expect("reset public TXID cache");
    let err = cache
        .begin_write_for_scope(read_scope)
        .await
        .and_then(|permit| permit.retain_artifact_chunks(std::slice::from_ref(&chunk)))
        .expect_err("stale retention scope must not acquire a write permit");

    assert!(matches!(
        err,
        super::TxidPublicCacheError::StalePublicCacheGeneration { .. }
    ));
    assert!(
        db.get_blob_meta(
            super::TXID_CACHE_BLOB_KIND,
            &super::artifact_chunk_blob_id(key, &cid),
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
        public_txid_artifact_chunk_from_payload(0, 0, 1, Vec::new(), Some(first_root));
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
    let second_row = super::row_for_txid_index(&manifest, &db, 1)
        .expect("read current row")
        .expect("current row present");
    assert_eq!(
        second_row.transaction.transaction_hash,
        second.transaction_hash
    );
    assert!(
        db.get_blob_meta(
            super::TXID_CACHE_BLOB_KIND,
            &super::artifact_chunk_blob_id(key, &malformed_cid),
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
    let second_row = super::row_for_txid_index(&manifest, &db, 1)
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
    let second_row = super::row_for_txid_index(&manifest, &db, 1)
        .expect("read current row")
        .expect("current row present");
    assert_eq!(
        second_row.transaction.transaction_hash,
        second.transaction_hash
    );
    assert!(
        db.get_blob_meta(
            super::TXID_CACHE_BLOB_KIND,
            &super::artifact_chunk_blob_id(key, &invalid_cid),
        )
        .expect("read invalid retained chunk metadata")
        .is_none(),
        "root-mismatched optional retention must not write chunk metadata"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

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

    let unavailable_source = unavailable_artifact_source();
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
async fn txid_public_cache_rollback_without_root_clamps_validated_progress() {
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
    let artifact_chunk = public_txid_artifact_chunk(0, &[first.clone(), second], Some(root));
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
                merkleroot: None,
            },
            Some(&unavailable_source),
        )
        .await
        .expect("sufficient local cache should satisfy lower rootless latest");

    let manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    assert_eq!(manifest.latest_validated_txid_index, Some(0));
    assert_eq!(manifest.latest_validated_merkleroot, None);
    assert_eq!(manifest.validated_cached_txid_index, Some(0));
    let proof =
        txid_public_proof_for_recovered_output(&db, key, first.txid_leaf_hash(), 0, 0, None)
            .expect("clamped validated prefix should still be usable");
    assert_eq!(proof.target_txid_index, 0);

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_cache_rejects_root_mismatched_high_water_without_correction() {
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
        .expect_err("mismatched high-water cache should require a corrective source");
    assert!(matches!(error, super::TxidPublicCacheError::RootMismatch));

    let manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    assert_eq!(manifest.validated_cached_txid_index, Some(0));
    assert_eq!(manifest.latest_validated_txid_index, None);
    assert_eq!(manifest.latest_validated_merkleroot, None);
    let row = super::row_for_txid_index(&manifest, &db, 0)
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
        spawn_graphql_response(public_txid_response(vec![graph_row.clone()]));

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
    let row = super::row_for_txid_index(&manifest, &db, 0)
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
    assert_eq!(manifest.next_txid_index, 1);
    let row = super::row_for_txid_index(&manifest, &db, 0)
        .expect("read validated prefix row")
        .expect("validated prefix row present");
    assert_eq!(row.transaction.transaction_hash, first.transaction_hash);
    assert!(
        super::row_for_txid_index(&manifest, &db, 1)
            .expect("read unvalidated tail row")
            .is_none()
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_cache_artifact_only_truncates_spanning_chunk_to_validated_prefix() {
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

    cache
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
        .expect("artifact-only spanning chunk should populate validated prefix");

    let manifest = cache
        .load_manifest()
        .expect("load manifest")
        .expect("manifest present");
    assert_eq!(manifest.validated_cached_txid_index, Some(0));
    assert_eq!(manifest.next_txid_index, 1);
    let row = super::row_for_txid_index(&manifest, &db, 0)
        .expect("read validated prefix row")
        .expect("validated prefix row present");
    assert_eq!(row.transaction.transaction_hash, first.transaction_hash);
    assert!(
        super::row_for_txid_index(&manifest, &db, 1)
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
    let row = super::row_for_txid_index(&manifest, &db, 1)
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
    let row = super::row_for_txid_index(&manifest, &db, 0)
        .expect("read refreshed row")
        .expect("refreshed row present");
    assert_eq!(row.transaction.transaction_hash, new_row.transaction_hash);

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
        spawn_graphql_response(public_txid_response(vec![graph_row.clone()]));

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
    let row = super::row_for_txid_index(&manifest, &db, 0)
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
        super::TxidPublicCacheError::MetadataMismatch(message)
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
        super::TxidPublicCacheError::MissingLeaf { index: 0 }
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
        super::TxidPublicCacheError::MetadataMismatch(message)
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
        super::TxidPublicCacheError::MetadataMismatch(message)
            if message.contains("missing Merkle root")
    ));
    assert_eq!(manifest.validated_cached_txid_index, None);
    assert!(manifest.pages.is_empty());

    drop(permit);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn txid_public_artifact_chunk_rejects_root_mismatch_without_progress() {
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
    let chunk = public_txid_artifact_chunk(0, &[row], Some(FixedBytes::from([0xff; 32])));
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
        super::TxidPublicCacheError::MetadataMismatch(message)
            if message.contains("Merkle root mismatch")
    ));
    assert_eq!(manifest.validated_cached_txid_index, None);
    assert!(manifest.pages.is_empty());

    drop(permit);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn txid_public_artifact_rejects_extreme_row_count_without_allocation() {
    let chunk = public_txid_artifact_chunk_from_payload(0, 0, u64::MAX, Vec::new(), None);

    let error = Vec::<super::TxidPublicCachePage>::try_from(&chunk)
        .expect_err("extreme row count should be rejected as format error");

    assert!(matches!(
        error,
        super::TxidPublicCacheError::MetadataMismatch(message)
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
    payload.extend_from_slice(&[0x55; 32]);
    write_u32(&mut payload, u32::MAX);
    let chunk = public_txid_artifact_chunk_from_payload(0, 0, 1, payload, None);

    let error = Vec::<super::TxidPublicCachePage>::try_from(&chunk)
        .expect_err("extreme vector count should be rejected as format error");

    assert!(matches!(
        error,
        super::TxidPublicCacheError::MetadataMismatch(message)
            if message.contains("ended while reading nullifiers")
    ));
}

fn temp_db_root() -> PathBuf {
    let dir = std::env::temp_dir().join("railgun-broadcaster-txid-cache-tests");
    fs::create_dir_all(&dir).expect("create temp db dir");
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let counter = TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    dir.join(format!("db-{pid}-{nanos}-{counter}"))
}

fn indexed_transaction(
    tx_hash_byte: u8,
    commitment: u8,
    nullifier: u8,
    bound_params_hash: u8,
) -> IndexedRailgunTransaction {
    IndexedRailgunTransaction {
        id: format!("0x{tx_hash_byte:04x}"),
        block_number: U256::from(12),
        block_timestamp: U256::from(1_700_000_012_u64),
        transaction_hash: FixedBytes::from([tx_hash_byte; 32]),
        merkle_root: FixedBytes::from([0x55; 32]),
        nullifiers: vec![U256::from(nullifier)],
        commitments: vec![U256::from(commitment)],
        bound_params_hash: U256::from(bound_params_hash),
        has_unshield: false,
        utxo_tree_in: U64::from(0),
        utxo_tree_out: U64::from(0),
        utxo_batch_start_position_out: U64::from(0),
    }
}

fn public_txid_response(transactions: Vec<IndexedRailgunTransaction>) -> String {
    serde_json::json!({ "data": { "transactions": transactions } }).to_string()
}

fn fixed_bytes_from_u256(value: U256) -> FixedBytes<32> {
    FixedBytes::from(value.to_be_bytes::<32>())
}

fn root_for_single_leaf(leaf: U256) -> FixedBytes<32> {
    let tree = DenseMerkleTree::from_ordered_leaves(vec![leaf], 1);
    FixedBytes::from(tree.prove(0).root.to_be_bytes::<32>())
}

fn txid_root_for_transactions(transactions: &[IndexedRailgunTransaction]) -> FixedBytes<32> {
    let leaves = transactions
        .iter()
        .map(IndexedRailgunTransaction::txid_leaf_hash)
        .collect::<Vec<_>>();
    FixedBytes::from(
        DenseMerkleTree::from_ordered_leaves(leaves, transactions.len() as u64)
            .root()
            .to_be_bytes::<32>(),
    )
}

fn public_txid_artifact_chunk(
    start_index: u64,
    transactions: &[IndexedRailgunTransaction],
    root: Option<FixedBytes<32>>,
) -> VerifiedIndexedArtifactChunk {
    let payload = public_txid_artifact_payload(start_index, transactions);
    let uncompressed =
        public_txid_artifact_envelope(start_index, transactions.len() as u64, &payload);
    let bytes = zstd::stream::encode_all(Cursor::new(uncompressed), 3).expect("compress chunk");
    let byte_size = bytes.len() as u64;
    let sha256 = FixedBytes::from_slice(&Sha256::digest(&bytes));
    let last_index = start_index + transactions.len() as u64 - 1;
    VerifiedIndexedArtifactChunk {
        descriptor: IndexedArtifactDescriptor {
            dataset_kind: IndexedDatasetKind::PublicTxid,
            scope: artifact_scope(),
            range: IndexedArtifactRange {
                kind: IndexedArtifactRangeKind::TxidIndex,
                start: start_index,
                end: last_index,
            },
            row_count: transactions.len() as u64,
            cid: format!("bafytest{start_index}"),
            sha256,
            byte_size,
            encoding_version: INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION,
            compression: CompressionAlgorithm::Zstd,
            metadata: DatasetDescriptorMetadata {
                root,
                checkpoint_block: Some(
                    transactions
                        .iter()
                        .map(|transaction| transaction.block_number.to())
                        .max()
                        .unwrap_or(0),
                ),
                last_indexed_block: None,
                tree_number: None,
                leaf_count: None,
                start_block: None,
                end_block: None,
                stream_partition: Some(TEST_TXID_VERSION.to_string()),
                ..DatasetDescriptorMetadata::default()
            },
        },
        bytes,
    }
}

fn public_txid_artifact_chunk_from_payload(
    start_index: u64,
    end_index: u64,
    row_count: u64,
    payload: Vec<u8>,
    root: Option<FixedBytes<32>>,
) -> VerifiedIndexedArtifactChunk {
    let uncompressed =
        public_txid_artifact_envelope_with_end(start_index, end_index, row_count, &payload);
    let bytes = zstd::stream::encode_all(Cursor::new(uncompressed), 3).expect("compress chunk");
    VerifiedIndexedArtifactChunk {
        descriptor: IndexedArtifactDescriptor {
            dataset_kind: IndexedDatasetKind::PublicTxid,
            scope: artifact_scope(),
            range: IndexedArtifactRange {
                kind: IndexedArtifactRangeKind::TxidIndex,
                start: start_index,
                end: end_index,
            },
            row_count,
            cid: format!("bafymalformed{start_index}"),
            sha256: FixedBytes::from_slice(&Sha256::digest(&bytes)),
            byte_size: bytes.len() as u64,
            encoding_version: INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION,
            compression: CompressionAlgorithm::Zstd,
            metadata: DatasetDescriptorMetadata {
                root,
                checkpoint_block: None,
                last_indexed_block: None,
                tree_number: None,
                leaf_count: None,
                start_block: None,
                end_block: None,
                ..DatasetDescriptorMetadata::default()
            },
        },
        bytes,
    }
}

fn public_txid_artifact_envelope(start_index: u64, row_count: u64, payload: &[u8]) -> Vec<u8> {
    public_txid_artifact_envelope_with_end(
        start_index,
        start_index + row_count - 1,
        row_count,
        payload,
    )
}

fn public_txid_artifact_envelope_with_end(
    start_index: u64,
    end_index: u64,
    row_count: u64,
    payload: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(INDEXED_ARTIFACT_CHUNK_MAGIC);
    write_u16(&mut bytes, INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION);
    bytes.push(3);
    bytes.push(0);
    write_u64(&mut bytes, 1);
    write_string(&mut bytes, "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    bytes.push(1);
    write_u64(&mut bytes, start_index);
    write_u64(&mut bytes, end_index);
    write_u64(&mut bytes, row_count);
    write_u64(&mut bytes, payload.len() as u64);
    write_u16(&mut bytes, 1);
    write_u16(&mut bytes, 1);
    write_u64(&mut bytes, 0);
    write_u64(&mut bytes, payload.len() as u64);
    bytes.extend_from_slice(payload);
    bytes
}

fn public_txid_artifact_payload(
    start_index: u64,
    transactions: &[IndexedRailgunTransaction],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (offset, transaction) in transactions.iter().enumerate() {
        write_u64(&mut bytes, start_index + offset as u64);
        write_string(&mut bytes, &transaction.id);
        write_u64(&mut bytes, transaction.block_number.to());
        write_u64(&mut bytes, transaction.block_timestamp.to());
        bytes.extend_from_slice(&[0xaa; 32]);
        bytes.extend_from_slice(transaction.transaction_hash.as_slice());
        write_u64(&mut bytes, 1);
        write_u64(&mut bytes, 1);
        bytes.extend_from_slice(transaction.merkle_root.as_slice());
        write_u256_vec(&mut bytes, &transaction.nullifiers);
        write_u256_vec(&mut bytes, &transaction.commitments);
        bytes.extend_from_slice(&transaction.bound_params_hash.to_be_bytes::<32>());
        bytes.push(u8::from(transaction.has_unshield));
        write_u64(&mut bytes, transaction.utxo_tree_in.to());
        write_u64(&mut bytes, transaction.utxo_tree_out.to());
        write_u64(&mut bytes, transaction.utxo_batch_start_position_out.to());
    }
    bytes
}

fn artifact_scope() -> ChainScope {
    ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            .parse()
            .expect("scope address"),
    }
}

fn public_txid_artifact_source(
    chunks: Vec<VerifiedIndexedArtifactChunk>,
) -> (IndexedArtifactSourceConfig, PathServer) {
    public_txid_artifact_source_with_catalogs(vec![(1, chunks)])
}

fn public_txid_artifact_source_with_catalogs(
    catalogs: Vec<(u64, Vec<VerifiedIndexedArtifactChunk>)>,
) -> (IndexedArtifactSourceConfig, PathServer) {
    public_txid_artifact_source_with_extra_catalogs(catalogs, Vec::new())
}

fn public_txid_artifact_source_with_extra_catalogs(
    catalogs: Vec<(u64, Vec<VerifiedIndexedArtifactChunk>)>,
    extra_catalog_descriptors: Vec<IndexedArtifactDescriptor>,
) -> (IndexedArtifactSourceConfig, PathServer) {
    let scope = artifact_scope();
    let mut catalog_descriptors = Vec::new();
    let mut catalog_blocks = Vec::new();
    let mut all_chunks = Vec::new();
    for (generation, chunks) in catalogs {
        let chunks = chunks
            .into_iter()
            .map(with_real_chunk_cid)
            .collect::<Vec<_>>();
        let catalog = IndexedArtifactCatalog {
            format_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
            dataset_kind: IndexedDatasetKind::PublicTxid,
            scope: scope.clone(),
            chunks: chunks
                .iter()
                .map(|chunk| chunk.descriptor.clone())
                .collect(),
        };
        let catalog_bytes = serde_json::to_vec(&catalog).expect("catalog JSON");
        let catalog_cid = raw_cid(&catalog_bytes);
        let catalog_stream_partition = shared_stream_partition(&chunks);
        let catalog_descriptor = IndexedArtifactDescriptor {
            dataset_kind: IndexedDatasetKind::PublicTxid,
            scope: scope.clone(),
            range: IndexedArtifactRange {
                kind: IndexedArtifactRangeKind::TxidIndex,
                start: chunks
                    .iter()
                    .map(|chunk| chunk.descriptor.range.start)
                    .min()
                    .unwrap_or(0),
                end: chunks
                    .iter()
                    .map(|chunk| chunk.descriptor.range.end)
                    .max()
                    .unwrap_or(0),
            },
            row_count: chunks.iter().map(|chunk| chunk.descriptor.row_count).sum(),
            cid: catalog_cid.to_string(),
            sha256: prefixed_sha256(&catalog_bytes),
            byte_size: catalog_bytes.len() as u64,
            encoding_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
            compression: CompressionAlgorithm::None,
            metadata: DatasetDescriptorMetadata {
                catalog_generation: Some(generation),
                stream_partition: catalog_stream_partition,
                ..DatasetDescriptorMetadata::default()
            },
        };
        catalog_descriptors.push(catalog_descriptor);
        catalog_blocks.push((catalog_cid, catalog_bytes));
        all_chunks.extend(chunks);
    }
    catalog_descriptors.extend(extra_catalog_descriptors);
    signed_artifact_source(scope, catalog_descriptors, catalog_blocks, all_chunks)
}

fn shared_stream_partition(chunks: &[VerifiedIndexedArtifactChunk]) -> Option<String> {
    let mut partitions = chunks
        .iter()
        .map(|chunk| chunk.descriptor.metadata.stream_partition.as_deref());
    let first = partitions.next()??;
    partitions
        .all(|partition| partition == Some(first))
        .then(|| first.to_string())
}

fn public_txid_empty_artifact_source() -> (IndexedArtifactSourceConfig, PathServer) {
    signed_artifact_source(artifact_scope(), Vec::new(), Vec::new(), Vec::new())
}

fn unavailable_artifact_source() -> IndexedArtifactSourceConfig {
    IndexedArtifactSourceConfig {
        trusted_publisher_pubkey: FixedBytes::from([0x22; 32]),
        manifest_source: IndexedArtifactManifestSource::Url(
            Url::parse("http://127.0.0.1:1/manifest").expect("manifest URL"),
        ),
        gateway_urls: vec![Url::parse("http://127.0.0.1:1").expect("gateway URL")],
        max_manifest_age: None,
        concurrency: 4,
        max_in_flight_bytes: 64 * 1024 * 1024,
    }
}

fn signed_artifact_source(
    scope: ChainScope,
    catalogs: Vec<IndexedArtifactDescriptor>,
    catalog_blocks: Vec<(Cid, Vec<u8>)>,
    chunks: Vec<VerifiedIndexedArtifactChunk>,
) -> (IndexedArtifactSourceConfig, PathServer) {
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let latest_indexed_block = chunks
        .iter()
        .filter_map(|chunk| chunk.descriptor.metadata.checkpoint_block)
        .max()
        .unwrap_or(0);
    let mut manifest = IndexedArtifactManifest::new(
        1_700_000_000_000,
        1,
        PublisherIdentity::ed25519(FixedBytes::ZERO),
        vec![IndexedArtifactChainEntry {
            scope: scope.clone(),
            latest_indexed: vec![LatestIndexedHeight {
                dataset_kind: IndexedDatasetKind::PublicTxid,
                block_number: latest_indexed_block,
                block_hash: FixedBytes::from([0x09_u8; 32]),
            }],
            catalogs,
        }],
    );
    manifest
        .sign_manifest(&signing_key)
        .expect("sign indexed artifact manifest");
    let manifest_bytes = serde_json::to_vec(&manifest).expect("manifest JSON");
    let mut routes = HashMap::from([("/manifest".to_string(), manifest_bytes)]);
    for (cid, bytes) in catalog_blocks {
        routes.insert(ipfs_car_path(&cid), car_bytes(cid, &[(cid, bytes)]));
    }
    for chunk in chunks {
        let cid = Cid::try_from(chunk.descriptor.cid.as_str()).expect("valid chunk CID");
        routes.insert(ipfs_car_path(&cid), car_bytes(cid, &[(cid, chunk.bytes)]));
    }
    let server = PathServer::spawn(routes);
    let config = IndexedArtifactSourceConfig {
        trusted_publisher_pubkey: FixedBytes::from(signing_key.verifying_key().to_bytes()),
        manifest_source: IndexedArtifactManifestSource::Url(
            server.url.join("/manifest").expect("manifest URL"),
        ),
        gateway_urls: vec![server.url.clone()],
        max_manifest_age: None,
        concurrency: 4,
        max_in_flight_bytes: 64 * 1024 * 1024,
    };
    (config, server)
}

fn with_real_chunk_cid(mut chunk: VerifiedIndexedArtifactChunk) -> VerifiedIndexedArtifactChunk {
    let cid = raw_cid(&chunk.bytes);
    chunk.descriptor.cid = cid.to_string();
    chunk.descriptor.sha256 = prefixed_sha256(&chunk.bytes);
    chunk.descriptor.byte_size = chunk.bytes.len() as u64;
    chunk
}

fn prefixed_sha256(bytes: &[u8]) -> FixedBytes<32> {
    FixedBytes::from_slice(&Sha256::digest(bytes))
}

fn raw_cid(bytes: &[u8]) -> Cid {
    Cid::new_v1(RAW_CODEC, Code::Sha2_256.digest(bytes))
}

fn ipfs_car_path(cid: &Cid) -> String {
    format!("/ipfs/{cid}?format=car&dag-scope=entity")
}

fn car_bytes(root: Cid, blocks: &[(Cid, Vec<u8>)]) -> Vec<u8> {
    let header = car_header(root);
    let mut car = Vec::new();
    write_varint(header.len(), &mut car);
    car.extend_from_slice(&header);
    for (cid, block) in blocks {
        let cid_bytes = cid.to_bytes();
        write_varint(cid_bytes.len() + block.len(), &mut car);
        car.extend_from_slice(&cid_bytes);
        car.extend_from_slice(block);
    }
    car
}

fn car_header(root: Cid) -> Vec<u8> {
    let mut header = Vec::new();
    header.push(0xa2);
    write_cbor_text("roots", &mut header);
    header.push(0x81);
    header.extend_from_slice(&[0xd8, 0x2a]);
    let mut cid_link = vec![0_u8];
    cid_link.extend_from_slice(&root.to_bytes());
    write_cbor_bytes(&cid_link, &mut header);
    write_cbor_text("version", &mut header);
    header.push(0x01);
    header
}

fn write_cbor_text(value: &str, out: &mut Vec<u8>) {
    write_cbor_len(0x60, value.len(), out);
    out.extend_from_slice(value.as_bytes());
}

fn write_cbor_bytes(value: &[u8], out: &mut Vec<u8>) {
    write_cbor_len(0x40, value.len(), out);
    out.extend_from_slice(value);
}

fn write_cbor_len(major: u8, len: usize, out: &mut Vec<u8>) {
    match len {
        0..=23 => out.push(major | u8::try_from(len).expect("small len")),
        24..=0xff => out.extend_from_slice(&[major | 24, u8::try_from(len).expect("u8 len")]),
        0x100..=0xffff => {
            out.push(major | 25);
            out.extend_from_slice(&u16::try_from(len).expect("u16 len").to_be_bytes());
        }
        _ => panic!("fixture length too large"),
    }
}

fn write_varint(mut value: usize, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((u8::try_from(value & 0x7f).expect("varint byte")) | 0x80);
        value >>= 7;
    }
    out.push(u8::try_from(value).expect("varint final byte"));
}

struct PathServer {
    url: Url,
}

impl PathServer {
    fn spawn(routes: HashMap<String, Vec<u8>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let url = Url::parse(&format!(
            "http://{}",
            listener.local_addr().expect("local addr")
        ))
        .expect("mock server URL");
        let request_count = routes.len().saturating_mul(8);
        let routes = Arc::new(routes);
        std::thread::spawn({
            let routes = Arc::clone(&routes);
            move || {
                for _ in 0..request_count {
                    let (stream, _) = listener.accept().expect("accept request");
                    let routes = Arc::clone(&routes);
                    std::thread::spawn(move || handle_path_request(stream, routes));
                }
            }
        });
        Self { url }
    }
}

fn handle_path_request(mut stream: std::net::TcpStream, routes: Arc<HashMap<String, Vec<u8>>>) {
    let path = read_request_path(&mut stream);
    let (status, reason, body) = routes
        .get(&path)
        .map_or((404_u16, "NOT FOUND", Vec::new()), |body| {
            (200_u16, "OK", body.clone())
        });
    let headers = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).expect("headers");
    stream.write_all(&body).expect("body");
}

fn read_request_path(stream: &mut std::net::TcpStream) -> String {
    let mut request = Vec::new();
    let mut buf = [0_u8; 1024];
    loop {
        let read = stream.read(&mut buf).expect("read request");
        assert!(read > 0, "client closed before request headers");
        request.extend_from_slice(&buf[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let request_text = String::from_utf8_lossy(&request);
    request_text
        .split_whitespace()
        .nth(1)
        .expect("request path")
        .to_string()
}

fn write_string(bytes: &mut Vec<u8>, value: &str) {
    write_u16(bytes, value.len() as u16);
    bytes.extend_from_slice(value.as_bytes());
}

fn write_u256_vec(bytes: &mut Vec<u8>, values: &[U256]) {
    write_u32(bytes, values.len() as u32);
    for value in values {
        bytes.extend_from_slice(&value.to_be_bytes::<32>());
    }
}

fn write_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn spawn_graphql(response_body: &'static str) -> (Url, mpsc::Receiver<String>) {
    spawn_graphql_response(response_body.to_string())
}

fn spawn_graphql_response(response_body: String) -> (Url, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
    let url = Url::parse(&format!(
        "http://{}/graphql",
        listener.local_addr().expect("local addr")
    ))
    .expect("mock url");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept request");
        let mut request = [0_u8; 4096];
        let read = stream.read(&mut request).expect("read request");
        let request = String::from_utf8_lossy(&request[..read]).to_string();
        tx.send(request).expect("send request");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            response_body.len(),
            response_body
        );
        stream
            .write_all(response.as_bytes())
            .expect("write response");
    });
    (url, rx)
}

fn spawn_delayed_graphql_response(
    response_body: String,
) -> (Url, mpsc::Receiver<String>, mpsc::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
    let url = Url::parse(&format!(
        "http://{}/graphql",
        listener.local_addr().expect("local addr")
    ))
    .expect("mock url");
    let (request_tx, request_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept request");
        let mut request = [0_u8; 4096];
        let read = stream.read(&mut request).expect("read request");
        let request = String::from_utf8_lossy(&request[..read]).to_string();
        request_tx.send(request).expect("send request");
        release_rx.recv().expect("wait for response release");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            response_body.len(),
            response_body
        );
        stream
            .write_all(response.as_bytes())
            .expect("write response");
    });
    (url, request_rx, release_tx)
}
