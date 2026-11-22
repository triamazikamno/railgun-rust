use super::*;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::indexed_artifacts::{
    CompressionAlgorithm, DatasetDescriptorMetadata, INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
    INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION, INDEXED_ARTIFACT_CHUNK_MAGIC, IndexedArtifactCatalog,
    IndexedArtifactChainEntry, IndexedArtifactDescriptor, IndexedArtifactRange,
    LatestIndexedHeight, PublisherIdentity,
};
use crate::types::{IndexedArtifactManifestSource, IndexedArtifactSourceConfig};
use alloy::primitives::{Address, FixedBytes};
use broadcaster_core::query_rpc_pool::QueryRpcPool;
use cid::Cid;
use ed25519_dalek::SigningKey;
use multihash_codetable::{Code, MultihashDigest};
use sha2::{Digest, Sha256};
use url::Url;

#[test]
fn merkle_artifact_probe_accepts_commitment_latest_covering_start() {
    let scope = scope();
    let manifest = manifest_with_catalogs(scope.clone(), 200);

    let probe = MerkleArtifactProbe::from_manifest(&manifest, &scope, 120, 200)
        .expect("merkle artifacts available");

    assert_eq!(probe.indexed_through_block, 200);
    assert_eq!(probe.indexed_through_block_hash, [0x22; 32]);
    assert_eq!(probe.catch_up_target(), 200);
    assert_eq!(probe.commitment_catalog_count, 1);
    assert_eq!(probe.checkpoint_catalog_count, 1);
}

#[test]
fn merkle_artifact_probe_requires_signed_latest_at_or_before_target() {
    let scope = scope();
    let manifest = manifest_with_catalogs(scope.clone(), 200);

    let probe = MerkleArtifactProbe::from_manifest(&manifest, &scope, 120, 180);

    assert_eq!(probe, None);
}

#[test]
fn commitment_artifact_page_decodes_merkle_updates() {
    let chunk = commitment_chunk(scope(), vec![(TREE_LEAF_COUNT, 101, [0x11; 32])], 101);

    let page = CommitmentArtifactPage::try_from(&chunk).expect("commitment page");

    assert_eq!(page.checkpoint_block, 101);
    assert_eq!(page.updates[0].tree_number, 1);
    assert_eq!(page.updates[0].tree_position, 0);
    assert_eq!(page.updates[0].hash, U256::from_be_bytes([0x11; 32]));
}

#[test]
fn commitment_artifact_page_rejects_mismatched_block_coverage() {
    let mut chunk = commitment_chunk(scope(), vec![(TREE_LEAF_COUNT, 101, [0x11; 32])], 101);
    chunk.descriptor.metadata.start_block = Some(100);
    chunk.descriptor.metadata.end_block = Some(101);

    let Err(error) = CommitmentArtifactPage::try_from(&chunk) else {
        panic!("commitment block coverage mismatch");
    };

    assert!(
        error
            .to_string()
            .contains("block coverage metadata does not match decoded records")
    );
}

#[test]
fn commitment_artifact_page_accepts_sparse_tree_positions() {
    let chunk = commitment_chunk(
        scope(),
        vec![(0, 101, [0x11; 32]), (2, 101, [0x22; 32])],
        101,
    );

    let page = CommitmentArtifactPage::try_from(&chunk).expect("sparse commitment page");

    assert_eq!(page.updates.len(), 2);
    assert_eq!(page.updates[0].tree_position, 0);
    assert_eq!(page.updates[1].tree_position, 2);
}

#[test]
fn commitment_artifact_page_rejects_extreme_count_without_allocation() {
    let mut payload = Vec::new();
    write_u64(&mut payload, u64::MAX);
    let chunk = chunk(
        scope(),
        IndexedDatasetKind::Commitments,
        0,
        0,
        payload,
        101,
        DatasetDescriptorMetadata {
            start_block: Some(101),
            end_block: Some(101),
            last_indexed_block: Some(101),
            ..Default::default()
        },
    );

    let Err(error) = CommitmentArtifactPage::try_from(&chunk) else {
        panic!("extreme commitment count should fail as a format error");
    };

    assert!(
        error
            .to_string()
            .contains("ended while reading commitment global_position")
    );
}

#[test]
fn commitment_chunk_selection_requires_safe_block_coverage() {
    let mut descriptor =
        commitment_chunk(scope(), vec![(TREE_LEAF_COUNT, 101, [0x11; 32])], 101).descriptor;

    assert!(
        MerkleArtifactSession::commitment_chunk_in_block_range(&descriptor, 100, 101)
            .expect("coverage valid")
    );
    assert!(
        !MerkleArtifactSession::commitment_chunk_in_block_range(&descriptor, 100, 100)
            .expect("coverage valid")
    );

    descriptor.metadata.start_block = None;
    assert!(MerkleArtifactSession::commitment_chunk_in_block_range(&descriptor, 100, 101).is_err());
}

#[test]
fn merkle_checkpoint_artifact_page_verifies_root_and_metadata() {
    let leaves = vec![U256::from(1), U256::from(2)];
    let root = DenseMerkleTree::from_ordered_leaves(leaves.iter().copied(), 2).root();
    let chunk = checkpoint_chunk(scope(), 2, 2, root, 123, &leaves);

    let page = MerkleCheckpointArtifactPage::try_from(&chunk).expect("checkpoint page");

    assert_eq!(page.tree_number, 2);
    assert_eq!(page.leaf_count, 2);
    assert_eq!(page.last_indexed_block, 123);
    assert_eq!(page.leaves, leaves);
}

#[test]
fn merkle_checkpoint_artifact_page_rejects_root_metadata_mismatch() {
    let leaves = vec![U256::from(1), U256::from(2)];
    let root = DenseMerkleTree::from_ordered_leaves(leaves.iter().copied(), 2).root();
    let mut chunk = checkpoint_chunk(scope(), 2, 2, root, 123, &leaves);
    chunk.descriptor.metadata.root = Some(FixedBytes::from([0xee; 32]));

    let Err(error) = MerkleCheckpointArtifactPage::try_from(&chunk) else {
        panic!("checkpoint root metadata mismatch");
    };

    assert!(
        error
            .to_string()
            .contains("checkpoint descriptor root metadata mismatch")
    );
}

#[test]
fn merkle_checkpoint_artifact_page_rejects_computed_root_mismatch() {
    let leaves = vec![U256::from(1), U256::from(2)];
    let wrong_root = U256::from(3);
    let chunk = checkpoint_chunk(scope(), 2, 2, wrong_root, 123, &leaves);

    let Err(error) = MerkleCheckpointArtifactPage::try_from(&chunk) else {
        panic!("checkpoint computed root mismatch");
    };

    assert!(error.to_string().contains("checkpoint root mismatch"));
}

#[test]
fn merkle_checkpoint_artifact_page_rejects_extreme_leaf_count_without_allocation() {
    let root = U256::from(3);
    let mut payload = Vec::new();
    write_u32(&mut payload, 0);
    write_u64(&mut payload, u64::MAX);
    payload.extend_from_slice(&root.to_be_bytes::<32>());
    write_u64(&mut payload, 123);
    let chunk = chunk(
        scope(),
        IndexedDatasetKind::MerkleCheckpoint,
        0,
        0,
        payload,
        123,
        DatasetDescriptorMetadata {
            root: Some(FixedBytes::from(root.to_be_bytes::<32>())),
            tree_number: Some(0),
            leaf_count: Some(u64::MAX),
            last_indexed_block: Some(123),
            ..Default::default()
        },
    );

    let error = MerkleCheckpointArtifactPage::try_from(&chunk)
        .expect_err("extreme checkpoint leaf count should fail as a format error");

    assert!(error.to_string().contains("exceeds tree capacity"));
}

#[test]
fn apply_merkle_artifact_pages_installs_checkpoints_then_sorted_commitments() {
    let mut forest = MerkleForest::new();
    let checkpoint_leaves = vec![U256::from(1), U256::from(2)];
    let checkpoint = MerkleCheckpointArtifactPage {
        tree_number: 0,
        leaf_count: 2,
        last_indexed_block: 100,
        leaves: checkpoint_leaves,
    };
    let commitments = CommitmentArtifactPage {
        updates: vec![
            MerkleTreeUpdate {
                tree_number: 0,
                tree_position: 3,
                hash: U256::from(4),
            },
            MerkleTreeUpdate {
                tree_number: 0,
                tree_position: 2,
                hash: U256::from(3),
            },
        ],
        checkpoint_block: 110,
    };

    let session = artifact_session(100, 110, vec![checkpoint], vec![commitments]);
    let progress = session.apply_into(&mut forest).expect("apply artifacts");

    assert_eq!(progress.latest_commitment_block, 110);
    assert_eq!(progress.commitments, 4);
    assert_eq!(forest.leaf_at(0, 0), Some(U256::from(1)));
    assert_eq!(forest.leaf_at(0, 1), Some(U256::from(2)));
    assert_eq!(forest.leaf_at(0, 2), Some(U256::from(3)));
    assert_eq!(forest.leaf_at(0, 3), Some(U256::from(4)));
}

#[test]
fn apply_merkle_artifact_pages_replaces_stale_checkpoint_tree() {
    let mut forest = MerkleForest::new();
    forest
        .insert_leaf(MerkleTreeUpdate {
            tree_number: 0,
            tree_position: 5,
            hash: U256::from(99),
        })
        .expect("insert stale leaf");
    let checkpoint = MerkleCheckpointArtifactPage {
        tree_number: 0,
        leaf_count: 2,
        last_indexed_block: 100,
        leaves: vec![U256::from(1), U256::from(2)],
    };

    let session = artifact_session(50, 100, vec![checkpoint], Vec::new());
    let progress = session.apply_into(&mut forest).expect("apply checkpoint");

    let expected_root =
        DenseMerkleTree::from_ordered_leaves([U256::from(1), U256::from(2)], 2).root();
    assert_eq!(progress.latest_commitment_block, 100);
    assert_eq!(progress.commitments, 2);
    assert_eq!(forest.leaf_at(0, 0), Some(U256::from(1)));
    assert_eq!(forest.leaf_at(0, 1), Some(U256::from(2)));
    assert_eq!(forest.leaf_at(0, 5), None);
    assert_eq!(forest.roots().get(&0), Some(&expected_root));
}

#[test]
fn apply_merkle_artifact_pages_keeps_same_block_commitment_in_other_tree_after_checkpoint() {
    let mut forest = MerkleForest::new();
    let checkpoint = MerkleCheckpointArtifactPage {
        tree_number: 0,
        leaf_count: 1,
        last_indexed_block: 100,
        leaves: vec![U256::from(1)],
    };
    let commitments = CommitmentArtifactPage {
        updates: vec![
            MerkleTreeUpdate {
                tree_number: 0,
                tree_position: 0,
                hash: U256::from(1),
            },
            MerkleTreeUpdate {
                tree_number: 1,
                tree_position: 0,
                hash: U256::from(2),
            },
        ],
        checkpoint_block: 100,
    };

    let session = artifact_session(50, 100, vec![checkpoint], vec![commitments]);
    let progress = session.apply_into(&mut forest).expect("apply artifacts");

    assert_eq!(progress.latest_commitment_block, 100);
    assert_eq!(progress.commitments, 2);
    assert_eq!(forest.leaf_at(0, 0), Some(U256::from(1)));
    assert_eq!(forest.leaf_at(1, 0), Some(U256::from(2)));
}

#[test]
fn apply_merkle_artifact_pages_reconstructs_from_commitments_without_checkpoint() {
    let mut forest = MerkleForest::new();
    let commitments = CommitmentArtifactPage {
        updates: vec![
            MerkleTreeUpdate {
                tree_number: 1,
                tree_position: 1,
                hash: U256::from(11),
            },
            MerkleTreeUpdate {
                tree_number: 1,
                tree_position: 0,
                hash: U256::from(10),
            },
        ],
        checkpoint_block: 120,
    };

    let session = artifact_session(100, 120, Vec::new(), vec![commitments]);
    let progress = session.apply_into(&mut forest).expect("apply artifacts");

    assert_eq!(progress.latest_commitment_block, 120);
    assert_eq!(progress.commitments, 2);
    assert_eq!(forest.leaf_at(1, 0), Some(U256::from(10)));
    assert_eq!(forest.leaf_at(1, 1), Some(U256::from(11)));
}

#[test]
fn merkle_checkpoint_failure_falls_back_to_commitment_replay() {
    let bad_checkpoint = checkpoint_chunk(
        scope(),
        0,
        2,
        U256::from(99),
        100,
        &[U256::from(1), U256::from(2)],
    );
    let checkpoint_pages = MerkleArtifactSession::decode_checkpoint_pages_best_effort(
        1,
        50,
        120,
        vec![bad_checkpoint],
    );
    assert_eq!(checkpoint_pages, [] as [MerkleCheckpointArtifactPage; 0]);
    let commitment_chunk = commitment_chunk(
        scope(),
        vec![(0, 101, [0x11; 32]), (1, 102, [0x22; 32])],
        102,
    );
    let commitment_page =
        CommitmentArtifactPage::try_from(&commitment_chunk).expect("valid commitment page");
    let mut forest = MerkleForest::new();

    let session = artifact_session(50, 102, checkpoint_pages, vec![commitment_page]);
    let progress = session
        .apply_into(&mut forest)
        .expect("reconstruct from commitments");

    assert_eq!(progress.latest_commitment_block, 102);
    assert_eq!(progress.commitments, 2);
    assert_eq!(forest.leaf_at(0, 0), Some(U256::from_be_bytes([0x11; 32])));
    assert_eq!(forest.leaf_at(0, 1), Some(U256::from_be_bytes([0x22; 32])));
}

#[tokio::test]
async fn merkle_artifact_catch_up_skips_commitment_chunks_covered_by_checkpoints() {
    let checkpoint = served_chunk(valid_checkpoint_chunk(4, 120));
    let first = served_chunk(commitment_chunk_for_positions(0..2, 101));
    let second = served_chunk(commitment_chunk_for_positions(2..4, 110));
    let gateway = ArtifactGatewayFixture::spawn(&[&checkpoint], &[&first, &second]);

    let mut forest = MerkleForest::new();
    let catch_up = run_merkle_artifact_catch_up_into(&mut forest, &gateway.chain, 100, 200, None)
        .await
        .expect("merkle artifact catch-up")
        .expect("merkle artifacts available");

    assert!(!gateway.requested(&first));
    assert!(!gateway.requested(&second));
    let mut expected = MerkleForest::new();
    artifact_session(
        100,
        ARTIFACT_INDEXED_THROUGH,
        vec![MerkleCheckpointArtifactPage::try_from(&checkpoint).expect("checkpoint page")],
        vec![
            CommitmentArtifactPage::try_from(&first).expect("first commitment page"),
            CommitmentArtifactPage::try_from(&second).expect("second commitment page"),
        ],
    )
    .apply_into(&mut expected)
    .expect("apply checkpoints and commitments together");
    assert_eq!(catch_up.target_block, ARTIFACT_INDEXED_THROUGH);
    assert_eq!(catch_up.target_block_hash, ARTIFACT_INDEXED_THROUGH_HASH);
    assert_eq!(forest.roots(), expected.roots());
}

#[tokio::test]
async fn merkle_artifact_catch_up_fetches_commitment_chunk_extending_past_checkpoint() {
    // The checkpoint covers positions 0..=2; the chunk's last position is the first
    // uncovered one.
    let checkpoint = served_chunk(valid_checkpoint_chunk(3, 120));
    let commitments = served_chunk(commitment_chunk_for_positions(1..4, 121));
    let gateway = ArtifactGatewayFixture::spawn(&[&checkpoint], &[&commitments]);

    let mut forest = MerkleForest::new();
    run_merkle_artifact_catch_up_into(&mut forest, &gateway.chain, 100, 200, None)
        .await
        .expect("merkle artifact catch-up")
        .expect("merkle artifacts available");

    assert!(gateway.requested(&commitments));
    assert_eq!(forest.roots(), forest_with_leaves(4).roots());
}

#[tokio::test]
async fn merkle_artifact_catch_up_replays_commitments_when_checkpoint_fails_verification() {
    let checkpoint = served_chunk(checkpoint_chunk(
        scope(),
        0,
        2,
        U256::from(99),
        120,
        &test_checkpoint_leaves(2),
    ));
    let commitments = served_chunk(commitment_chunk_for_positions(0..2, 110));
    let gateway = ArtifactGatewayFixture::spawn(&[&checkpoint], &[&commitments]);

    let mut forest = MerkleForest::new();
    run_merkle_artifact_catch_up_into(&mut forest, &gateway.chain, 100, 200, None)
        .await
        .expect("merkle artifact catch-up")
        .expect("commitment artifacts replace the failed checkpoint");

    assert!(gateway.requested(&checkpoint));
    assert!(gateway.requested(&commitments));
    assert_eq!(forest.roots(), forest_with_leaves(2).roots());
}

const ARTIFACT_INDEXED_THROUGH: u64 = 150;
const ARTIFACT_INDEXED_THROUGH_HASH: [u8; 32] = [0x44; 32];

/// A local gateway serving one signed manifest whose `MerkleCheckpoint` and `Commitments`
/// catalogs hold the given chunks, and a chain configured to read it.
struct ArtifactGatewayFixture {
    chain: ChainConfig,
    requested_paths: Arc<Mutex<Vec<String>>>,
}

impl ArtifactGatewayFixture {
    fn spawn(
        checkpoint_chunks: &[&VerifiedIndexedArtifactChunk],
        commitment_chunks: &[&VerifiedIndexedArtifactChunk],
    ) -> Self {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let mut routes = HashMap::new();
        let mut catalogs = Vec::new();
        for (dataset_kind, chunks) in [
            (IndexedDatasetKind::MerkleCheckpoint, checkpoint_chunks),
            (IndexedDatasetKind::Commitments, commitment_chunks),
        ] {
            for chunk in chunks {
                routes.insert(car_path(&chunk.descriptor.cid), car_bytes(&chunk.bytes));
            }
            let catalog = IndexedArtifactCatalog {
                format_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
                dataset_kind,
                scope: scope(),
                chunks: chunks
                    .iter()
                    .map(|chunk| chunk.descriptor.clone())
                    .collect(),
            };
            let catalog_bytes = serde_json::to_vec(&catalog).expect("catalog json");
            let catalog_cid = raw_cid(&catalog_bytes).to_string();
            routes.insert(car_path(&catalog_cid), car_bytes(&catalog_bytes));
            catalogs.push(IndexedArtifactDescriptor {
                range: IndexedArtifactRange {
                    kind: IndexedArtifactRangeKind::TreePosition,
                    start: chunks
                        .iter()
                        .map(|chunk| chunk.descriptor.range.start)
                        .min()
                        .expect("catalog chunks"),
                    end: chunks
                        .iter()
                        .map(|chunk| chunk.descriptor.range.end)
                        .max()
                        .expect("catalog chunks"),
                },
                row_count: chunks.iter().map(|chunk| chunk.descriptor.row_count).sum(),
                cid: catalog_cid,
                sha256: prefixed_sha256(&catalog_bytes),
                byte_size: u64::try_from(catalog_bytes.len()).expect("catalog byte size"),
                ..catalog_descriptor(scope(), dataset_kind)
            });
        }
        let mut manifest = IndexedArtifactManifest::new(
            1_700_000_000_000,
            1,
            PublisherIdentity::ed25519(FixedBytes::from(signing_key.verifying_key().to_bytes())),
            vec![IndexedArtifactChainEntry {
                scope: scope(),
                latest_indexed: vec![LatestIndexedHeight {
                    dataset_kind: IndexedDatasetKind::Commitments,
                    block_number: ARTIFACT_INDEXED_THROUGH,
                    block_hash: FixedBytes::from(ARTIFACT_INDEXED_THROUGH_HASH),
                }],
                catalogs,
            }],
        );
        manifest.sign_manifest(&signing_key).expect("sign manifest");
        routes.insert(
            "/manifest.json".to_string(),
            serde_json::to_vec(&manifest).expect("manifest json"),
        );

        let (gateway_url, requested_paths) = spawn_path_gateway(routes);
        let source = IndexedArtifactSourceConfig {
            trusted_publisher_pubkey: FixedBytes::from(signing_key.verifying_key().to_bytes()),
            manifest_source: IndexedArtifactManifestSource::Url(
                gateway_url.join("/manifest.json").expect("manifest url"),
            ),
            gateway_urls: vec![gateway_url],
            gateway_pool: None,
            manifest_reuse: crate::IndexedArtifactManifestReuse::default(),
            max_manifest_age: None,
            concurrency: 1,
            max_in_flight_bytes: 1024 * 1024,
            amount_statistics_ipns_name: None,
        };
        Self {
            chain: artifact_chain_config(source),
            requested_paths,
        }
    }

    fn requested(&self, chunk: &VerifiedIndexedArtifactChunk) -> bool {
        self.requested_paths
            .lock()
            .expect("gateway paths lock")
            .contains(&car_path(&chunk.descriptor.cid))
    }
}

fn artifact_chain_config(source: IndexedArtifactSourceConfig) -> ChainConfig {
    let scope = scope();
    ChainConfig {
        deployment: broadcaster_core::deployment::RailgunDeployment {
            chain_id: scope.chain_id,
            contract: scope.railgun_contract,
            deployment_block: 0,
            v2_start_block: 0,
            legacy_shield_block: 0,
            relay_adapt_contract: None,
            relay_adapt_7702_contract: Address::ZERO,
            relay_adapt_7702_delegates: &[],
            relay_adapt_history: &[],
        },
        sync: crate::RailgunSyncOptions {
            archive_until_block: 0,
            block_range: 100,
            indexed_wallet_block_range: 100,
            poll_interval: Duration::from_millis(1),
            quick_sync_endpoint: None,
            indexed_artifact_source: Some(source),
            anchor_interval: 1000,
            anchor_retention: 5,
        },
        rpcs: Arc::new(QueryRpcPool::new(
            vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
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

/// Serves `routes` by request path and records every requested path.
fn spawn_path_gateway(routes: HashMap<String, Vec<u8>>) -> (Url, Arc<Mutex<Vec<String>>>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind artifact gateway");
    let url = Url::parse(&format!(
        "http://{}",
        listener.local_addr().expect("gateway address")
    ))
    .expect("gateway url");
    let requested_paths = Arc::new(Mutex::new(Vec::new()));
    let recorded_paths = Arc::clone(&requested_paths);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                return;
            };
            let Some(path) = read_request_path(&mut stream) else {
                continue;
            };
            recorded_paths
                .lock()
                .expect("gateway paths lock")
                .push(path.clone());
            let (status, body) = routes
                .get(&path)
                .map_or(("404 Not Found", &[][..]), |body| {
                    ("200 OK", body.as_slice())
                });
            let headers = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(headers.as_bytes());
            let _ = stream.write_all(body);
        }
    });
    (url, requested_paths)
}

fn read_request_path(stream: &mut std::net::TcpStream) -> Option<String> {
    let mut request = Vec::new();
    let mut buf = [0_u8; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut buf).ok()?;
        if read == 0 {
            return None;
        }
        request.extend_from_slice(&buf[..read]);
    }
    String::from_utf8_lossy(&request)
        .split_whitespace()
        .nth(1)
        .map(str::to_owned)
}

fn car_path(cid: &str) -> String {
    format!("/ipfs/{cid}?format=car&dag-scope=entity")
}

fn raw_cid(bytes: &[u8]) -> Cid {
    Cid::new_v1(0x55, Code::Sha2_256.digest(bytes))
}

/// A single-block `CARv1` whose root is the raw block itself.
fn car_bytes(block: &[u8]) -> Vec<u8> {
    let root = raw_cid(block);
    let mut header = vec![0xa2];
    write_cbor_len(0x60, "roots".len(), &mut header);
    header.extend_from_slice(b"roots");
    header.extend_from_slice(&[0x81, 0xd8, 0x2a]);
    let mut cid_link = vec![0_u8];
    cid_link.extend_from_slice(&root.to_bytes());
    write_cbor_len(0x40, cid_link.len(), &mut header);
    header.extend_from_slice(&cid_link);
    write_cbor_len(0x60, "version".len(), &mut header);
    header.extend_from_slice(b"version");
    header.push(0x01);

    let mut car = Vec::new();
    write_varint(header.len(), &mut car);
    car.extend_from_slice(&header);
    let cid_bytes = root.to_bytes();
    write_varint(cid_bytes.len() + block.len(), &mut car);
    car.extend_from_slice(&cid_bytes);
    car.extend_from_slice(block);
    car
}

fn write_cbor_len(major: u8, len: usize, out: &mut Vec<u8>) {
    match len {
        0..=23 => out.push(major | u8::try_from(len).expect("small len")),
        24..=0xff => out.extend_from_slice(&[major | 0x18, u8::try_from(len).expect("u8 len")]),
        _ => panic!("fixture length too large"),
    }
}

fn write_varint(mut value: usize, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push(u8::try_from(value & 0x7f).expect("varint byte") | 0x80);
        value >>= 7;
    }
    out.push(u8::try_from(value).expect("varint final byte"));
}

/// Gives a test chunk the raw CID of its bytes so a gateway can serve it.
fn served_chunk(mut chunk: VerifiedIndexedArtifactChunk) -> VerifiedIndexedArtifactChunk {
    chunk.descriptor.cid = raw_cid(&chunk.bytes).to_string();
    chunk
}

fn test_leaf(tree_position: u64) -> [u8; 32] {
    [u8::try_from(tree_position + 1).expect("test leaf byte"); 32]
}

fn test_checkpoint_leaves(leaf_count: u64) -> Vec<U256> {
    (0..leaf_count)
        .map(|tree_position| U256::from_be_bytes(test_leaf(tree_position)))
        .collect()
}

fn valid_checkpoint_chunk(
    leaf_count: u64,
    last_indexed_block: u64,
) -> VerifiedIndexedArtifactChunk {
    let leaves = test_checkpoint_leaves(leaf_count);
    let root = DenseMerkleTree::from_ordered_leaves(leaves.iter().copied(), leaf_count).root();
    checkpoint_chunk(scope(), 0, leaf_count, root, last_indexed_block, &leaves)
}

fn commitment_chunk_for_positions(
    positions: std::ops::Range<u64>,
    block_number: u64,
) -> VerifiedIndexedArtifactChunk {
    commitment_chunk(
        scope(),
        positions
            .map(|position| (position, block_number, test_leaf(position)))
            .collect(),
        block_number,
    )
}

fn forest_with_leaves(leaf_count: u64) -> MerkleForest {
    let mut forest = MerkleForest::new();
    for tree_position in 0..leaf_count {
        forest
            .insert_leaf(MerkleTreeUpdate {
                tree_number: 0,
                tree_position,
                hash: U256::from_be_bytes(test_leaf(tree_position)),
            })
            .expect("insert expected leaf");
    }
    forest.compute_roots();
    forest
}

fn manifest_with_catalogs(scope: ChainScope, latest_block: u64) -> IndexedArtifactManifest {
    IndexedArtifactManifest::new(
        1_700_000_000_000,
        1,
        PublisherIdentity::ed25519(FixedBytes::from([0x11; 32])),
        vec![IndexedArtifactChainEntry {
            scope: scope.clone(),
            latest_indexed: vec![LatestIndexedHeight {
                dataset_kind: IndexedDatasetKind::Commitments,
                block_number: latest_block,
                block_hash: FixedBytes::from([0x22; 32]),
            }],
            catalogs: vec![
                catalog_descriptor(scope.clone(), IndexedDatasetKind::Commitments),
                catalog_descriptor(scope, IndexedDatasetKind::MerkleCheckpoint),
            ],
        }],
    )
}

fn artifact_session(
    _from_block: u64,
    target_block: u64,
    checkpoint_pages: Vec<MerkleCheckpointArtifactPage>,
    commitment_pages: Vec<CommitmentArtifactPage>,
) -> MerkleArtifactSession {
    MerkleArtifactSession {
        target_block,
        target_block_hash: [0x22; 32],
        checkpoint_pages,
        commitment_pages,
    }
}

fn catalog_descriptor(
    scope: ChainScope,
    dataset_kind: IndexedDatasetKind,
) -> IndexedArtifactDescriptor {
    IndexedArtifactDescriptor {
        dataset_kind,
        scope,
        range: IndexedArtifactRange {
            kind: IndexedArtifactRangeKind::TreePosition,
            start: 0,
            end: TREE_LEAF_COUNT,
        },
        row_count: 1,
        cid: "bafymerkletest".to_string(),
        sha256: FixedBytes::from([0x33; 32]),
        byte_size: 1,
        encoding_version: INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION,
        compression: CompressionAlgorithm::None,
        metadata: DatasetDescriptorMetadata::default(),
    }
}

fn commitment_chunk(
    scope: ChainScope,
    rows: Vec<(u64, u64, [u8; 32])>,
    checkpoint_block: u64,
) -> VerifiedIndexedArtifactChunk {
    let start = rows.first().map_or(0, |row| row.0);
    let end = rows.last().map_or(0, |row| row.0);
    let start_block = rows.iter().map(|row| row.1).min();
    let end_block = rows.iter().map(|row| row.1).max();
    let mut payload = Vec::new();
    write_u64(&mut payload, rows.len() as u64);
    for (global_position, block_number, hash) in rows {
        write_u64(&mut payload, global_position);
        write_source(&mut payload, block_number);
        payload.push(0);
        write_u32(
            &mut payload,
            u32::try_from(global_position / TREE_LEAF_COUNT).expect("tree number"),
        );
        write_u64(&mut payload, global_position % TREE_LEAF_COUNT);
        payload.extend_from_slice(&hash);
    }
    chunk(
        scope,
        IndexedDatasetKind::Commitments,
        start,
        end,
        payload,
        checkpoint_block,
        DatasetDescriptorMetadata {
            checkpoint_block: Some(checkpoint_block),
            start_block,
            end_block,
            last_indexed_block: Some(checkpoint_block),
            ..Default::default()
        },
    )
}

fn checkpoint_chunk(
    scope: ChainScope,
    tree_number: u32,
    leaf_count: u64,
    root: U256,
    last_indexed_block: u64,
    leaves: &[U256],
) -> VerifiedIndexedArtifactChunk {
    let mut payload = Vec::new();
    write_u32(&mut payload, tree_number);
    write_u64(&mut payload, leaf_count);
    payload.extend_from_slice(&root.to_be_bytes::<32>());
    write_u64(&mut payload, last_indexed_block);
    for leaf in leaves {
        payload.extend_from_slice(&leaf.to_be_bytes::<32>());
    }
    let start = u64::from(tree_number) * TREE_LEAF_COUNT;
    let end = start + leaf_count - 1;
    chunk(
        scope,
        IndexedDatasetKind::MerkleCheckpoint,
        start,
        end,
        payload,
        last_indexed_block,
        DatasetDescriptorMetadata {
            root: Some(FixedBytes::from(root.to_be_bytes::<32>())),
            checkpoint_block: Some(last_indexed_block),
            tree_number: Some(u16::try_from(tree_number).expect("tree number metadata")),
            leaf_count: Some(leaf_count),
            start_block: None,
            end_block: None,
            last_indexed_block: Some(last_indexed_block),
            ..DatasetDescriptorMetadata::default()
        },
    )
}

fn chunk(
    scope: ChainScope,
    dataset_kind: IndexedDatasetKind,
    start: u64,
    end: u64,
    payload: Vec<u8>,
    checkpoint_block: u64,
    metadata: DatasetDescriptorMetadata,
) -> VerifiedIndexedArtifactChunk {
    let row_count = match dataset_kind {
        IndexedDatasetKind::Commitments => u64::from_le_bytes(
            payload[0..8]
                .try_into()
                .expect("commitment row count bytes"),
        ),
        IndexedDatasetKind::MerkleCheckpoint => metadata.leaf_count.expect("leaf count"),
        IndexedDatasetKind::WalletScan | IndexedDatasetKind::PublicTxid => 0,
    };
    let section_id = match dataset_kind {
        IndexedDatasetKind::Commitments => COMMITMENT_RECORD_SECTION_ID,
        IndexedDatasetKind::MerkleCheckpoint => MERKLE_CHECKPOINT_SECTION_ID,
        IndexedDatasetKind::WalletScan | IndexedDatasetKind::PublicTxid => 1,
    };
    let bytes = chunk_bytes(
        &scope,
        dataset_kind,
        start,
        end,
        row_count,
        section_id,
        payload,
    );
    let descriptor = IndexedArtifactDescriptor {
        dataset_kind,
        scope,
        range: IndexedArtifactRange {
            kind: IndexedArtifactRangeKind::TreePosition,
            start,
            end,
        },
        row_count,
        cid: "bafymerklechunk".to_string(),
        sha256: prefixed_sha256(&bytes),
        byte_size: u64::try_from(bytes.len()).expect("chunk byte size"),
        encoding_version: INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION,
        compression: CompressionAlgorithm::None,
        metadata: DatasetDescriptorMetadata {
            checkpoint_block: Some(checkpoint_block),
            ..metadata
        },
    };
    VerifiedIndexedArtifactChunk { descriptor, bytes }
}

fn chunk_bytes(
    scope: &ChainScope,
    dataset_kind: IndexedDatasetKind,
    start: u64,
    end: u64,
    row_count: u64,
    section_id: u16,
    payload: Vec<u8>,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(INDEXED_ARTIFACT_CHUNK_MAGIC);
    write_u16(&mut bytes, INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION);
    bytes.push(match dataset_kind {
        IndexedDatasetKind::WalletScan => 0,
        IndexedDatasetKind::Commitments => 1,
        IndexedDatasetKind::MerkleCheckpoint => 2,
        IndexedDatasetKind::PublicTxid => 3,
    });
    bytes.push(0);
    write_u64(&mut bytes, scope.chain_id);
    write_string(
        &mut bytes,
        &format!(
            "0x{}",
            alloy::hex::encode(scope.railgun_contract.as_slice())
        ),
    );
    bytes.push(2);
    write_u64(&mut bytes, start);
    write_u64(&mut bytes, end);
    write_u64(&mut bytes, row_count);
    write_u64(
        &mut bytes,
        u64::try_from(payload.len()).expect("payload len"),
    );
    write_u16(&mut bytes, 1);
    write_u16(&mut bytes, section_id);
    write_u64(&mut bytes, 0);
    write_u64(
        &mut bytes,
        u64::try_from(payload.len()).expect("payload len"),
    );
    bytes.extend(payload);
    bytes
}

fn write_source(bytes: &mut Vec<u8>, block_number: u64) {
    write_u64(bytes, block_number);
}

fn write_string(bytes: &mut Vec<u8>, value: &str) {
    write_u16(bytes, u16::try_from(value.len()).expect("string len"));
    bytes.extend_from_slice(value.as_bytes());
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

fn prefixed_sha256(bytes: &[u8]) -> FixedBytes<32> {
    FixedBytes::from_slice(&Sha256::digest(bytes))
}

fn scope() -> ChainScope {
    ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            .parse()
            .expect("scope address"),
    }
}
