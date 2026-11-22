use super::*;

use super::super::{Address, Duration, QueryRpcPool};
use crate::{IndexedArtifactManifestSource, IndexedArtifactSourceConfig};
use alloy::primitives::U256;
use local_db::DbConfig;
use merkletree::tree::MerkleTreeUpdate;
use url::Url;

#[tokio::test]
async fn persist_indexed_forest_snapshot_writes_reorg_metadata() {
    let root_dir = temp_db_root("persist-indexed-forest-snapshot");
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    db.ensure_blob_dir("merkle_forest")
        .expect("create merkle forest blob dir");
    let mut chain = chain_config();
    // A caller-supplied deployment must retain its scan start and cache identity.
    chain.deployment.chain_id = 999_999;
    chain.deployment.contract = Address::from([0x42; 20]);
    chain.deployment.deployment_block = 100;
    let (_, last_processed, _, _) = db
        .load_or_initialize_forest(&chain, 0, None, None)
        .await
        .expect("initialize custom deployment");
    assert_eq!(last_processed, 99);
    let relative = DbStore::relative_blob_path(
        "merkle_forest",
        &format!(
            "forest-{}-{}.msgpack",
            chain.deployment.chain_id, chain.deployment.contract
        ),
    );
    let snapshot_path = db.resolve_path(&relative);
    let mut forest = MerkleForest::new();
    forest
        .insert_leaf(MerkleTreeUpdate {
            tree_number: 0,
            tree_position: 0,
            hash: U256::from(1),
        })
        .expect("insert leaf");
    forest.compute_roots();
    let block_hash = [0x44; 32];

    persist_indexed_forest_snapshot(&db, &chain, &snapshot_path, 123, block_hash, &forest)
        .expect("persist snapshot");

    let meta = db
        .get_merkle_forest_meta(
            chain.deployment.chain_id,
            &chain.deployment.contract.to_string(),
        )
        .expect("read forest meta")
        .expect("forest meta present");
    assert_eq!(meta.last_block, 123);
    assert_eq!(meta.hash, block_hash);
    let snapshot = MerkleForestSnapshot::load(
        &snapshot_path,
        chain.deployment.chain_id,
        chain.deployment.contract,
    )
    .expect("load snapshot")
    .expect("snapshot present");
    assert_eq!(snapshot.last_processed_block, 123);

    drop(db);
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("reopen db");
    let (_, last_processed, _, _) = db
        .load_or_initialize_forest(&chain, 123, None, None)
        .await
        .expect("restore custom deployment");
    assert_eq!(last_processed, 123);
    assert!(
        db.get_merkle_forest_meta(1, &chain.deployment.contract.to_string())
            .expect("read different chain")
            .is_none()
    );
    assert!(
        db.get_merkle_forest_meta(chain.deployment.chain_id, &Address::ZERO.to_string())
            .expect("read different contract")
            .is_none()
    );
    drop(db);
    std::fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn skips_indexed_forest_catch_up_for_small_tail_with_or_without_sources() {
    let mut chain = chain_config();
    chain.sync.block_range = 100;

    assert!(chain.should_skip_indexed_forest_catch_up(101, 200));
    assert!(chain.should_skip_indexed_forest_catch_up(200, 200));
    // An empty tail, including a start without a safe head.
    assert!(chain.should_skip_indexed_forest_catch_up(201, 200));
    assert!(chain.should_skip_indexed_forest_catch_up(1, 0));

    chain.sync.indexed_artifact_source = Some(indexed_artifact_source());
    chain.sync.quick_sync_endpoint = Some(Url::parse("https://squid.example").expect("url"));
    assert!(chain.should_skip_indexed_forest_catch_up(101, 200));
}

#[test]
fn uses_indexed_forest_catch_up_for_large_tail() {
    let mut chain = chain_config();
    chain.sync.indexed_artifact_source = Some(indexed_artifact_source());
    chain.sync.block_range = 100;

    assert!(!chain.should_skip_indexed_forest_catch_up(100, 200));
}

fn chain_config() -> ChainConfig {
    ChainConfig {
        deployment: broadcaster_core::deployment::RailgunDeployment {
            chain_id: 1,
            contract: Address::ZERO,
            deployment_block: 1,
            v2_start_block: 1,
            legacy_shield_block: 1,
            relay_adapt_contract: None,
            relay_adapt_7702_contract: Address::ZERO,
            relay_adapt_7702_delegates: &[],
            relay_adapt_history: &[],
        },
        sync: crate::RailgunSyncOptions {
            archive_until_block: 0,
            block_range: 100,
            indexed_wallet_block_range: 100,
            poll_interval: Duration::from_secs(1),
            quick_sync_endpoint: None,
            indexed_artifact_source: None,
            anchor_interval: 0,
            anchor_retention: 0,
        },
        rpcs: Arc::new(QueryRpcPool::new(
            vec![Url::parse("http://127.0.0.1:8545").expect("rpc url")],
            Duration::from_secs(1),
        )),
        archive_rpc_url: None,
        archive_rpc_http_client: None,
        block_time: Duration::from_secs(12),
        finality_depth: 0,
        http_client: reqwest::Client::new(),
        progress_tx: None,
        poi_submission_routes: None,
    }
}

fn indexed_artifact_source() -> IndexedArtifactSourceConfig {
    IndexedArtifactSourceConfig {
        trusted_publisher_pubkey: FixedBytes::from([0x22; 32]),
        manifest_source: IndexedArtifactManifestSource::Url(
            Url::parse("https://artifact.example/manifest.json").expect("url"),
        ),
        gateway_urls: vec![Url::parse("https://gateway.example").expect("url")],
        gateway_pool: None,
        manifest_reuse: crate::IndexedArtifactManifestReuse::default(),
        max_manifest_age: None,
        concurrency: 6,
        max_in_flight_bytes: 64 * 1024 * 1024,
        amount_statistics_ipns_name: None,
    }
}

fn temp_db_root(name: &str) -> PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("sync-service-{name}-{unique}"));
    std::fs::create_dir_all(&dir).expect("create temp db dir");
    dir
}
