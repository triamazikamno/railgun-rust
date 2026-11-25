use super::artifact::PUBLIC_TXID_RECORD_SECTION_ID;
use super::index::{load_index_shard, test_support::index_entries_for_hash, write_index_shard};
use super::paths::safe_file_component;
use super::proof::{
    row_for_txid_index, test_support::txid_public_transaction_for_recovered_output,
    txid_root_index_for_target,
};
use super::{
    TxidPublicCache, TxidPublicCacheKey, TxidPublicLatestValidated,
    txid_public_artifact_bounded_proof, txid_public_proof_for_recovered_output,
    txid_public_proof_for_recovered_output_at_index, validated_transactions_for_outer_hash,
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
use alloy::primitives::{Address, FixedBytes, U64, U256, Uint};
use alloy::sol_types::SolValue;
use broadcaster_core::contracts::railgun::{CommitmentPreimage, TokenData};
use broadcaster_core::tree::TREE_LEAF_COUNT;
use cid::Cid;
use ed25519_dalek::SigningKey;
use local_db::{BlobMeta, DbConfig, DbStore};
use merkletree::quick::IndexedRailgunTransaction;
use merkletree::tree::DenseMerkleTree;
use multihash_codetable::{Code, MultihashDigest};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{Cursor, Read, Write};
use std::net::TcpListener;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use url::Url;

static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);
const RAW_CODEC: u64 = 0x55;
const TEST_TXID_VERSION: &str = "V2_PoseidonMerkle";

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

fn test_cache_key() -> TxidPublicCacheKey<'static> {
    TxidPublicCacheKey {
        chain_type: 0,
        chain_id: 1,
        railgun_contract: artifact_scope().railgun_contract,
        txid_version: TEST_TXID_VERSION,
    }
}

async fn seed_validated_pages(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    pages: Vec<Vec<IndexedRailgunTransaction>>,
) -> super::TxidPublicCacheManifest {
    let cache = TxidPublicCache::new(db, key);
    let permit = cache.begin_write().await;
    let mut manifest = permit
        .cache()
        .load_or_new_manifest()
        .expect("load manifest");
    let mut start_index = 0_u64;
    for transactions in pages {
        assert!(!transactions.is_empty(), "test pages must not be empty");
        let row_count = transactions.len() as u64;
        let page =
            super::TxidPublicCachePage::from_indexed_transactions(key, start_index, transactions);
        manifest
            .append_page_after_prefix_validation(&permit, &page)
            .expect("append page");
        super::update_index_for_page(&permit, &page).expect("update advisory index");
        start_index += row_count;
    }
    let latest = start_index.checked_sub(1).expect("at least one test row");
    manifest.validated_cached_txid_index = Some(latest);
    manifest.latest_validated_txid_index = Some(latest);
    manifest.latest_validated_merkleroot = None;
    manifest.write_to(&permit).expect("write manifest");
    manifest
}

fn indexed_transaction(
    tx_hash_byte: u8,
    commitment: u8,
    nullifier: u8,
    bound_params_hash: u8,
) -> IndexedRailgunTransaction {
    IndexedRailgunTransaction {
        id: format!("0x{tx_hash_byte:04x}"),
        block_number: U64::from(12),
        block_timestamp: U64::from(1_700_000_012_u64),
        transaction_hash: FixedBytes::from([tx_hash_byte; 32]),
        merkle_root: FixedBytes::from([0x55; 32]),
        nullifiers: vec![U256::from(nullifier)],
        commitments: vec![U256::from(commitment)],
        bound_params_hash: U256::from(bound_params_hash),
        has_unshield: false,
        unshield_token: None,
        unshield_to_address: None,
        unshield_value: None,
        utxo_tree_in: U64::from(0),
        utxo_tree_out: U64::from(0),
        utxo_batch_start_position_out: U64::from(0),
    }
}

fn public_txid_response(transactions: &[IndexedRailgunTransaction]) -> String {
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
    verified_public_txid_artifact_chunk(start_index, transactions, root, uncompressed)
}

fn public_txid_artifact_chunk_with_unshield_sidecar(
    start_index: u64,
    transactions: &[IndexedRailgunTransaction],
    preimages: &[(u64, Vec<u8>)],
) -> VerifiedIndexedArtifactChunk {
    let records = public_txid_artifact_payload(start_index, transactions);
    let mut sidecar = Vec::new();
    write_u32(&mut sidecar, preimages.len() as u32);
    for (txid_index, encoded) in preimages {
        write_u64(&mut sidecar, *txid_index);
        write_u16(&mut sidecar, encoded.len() as u16);
        sidecar.extend_from_slice(encoded);
    }
    let uncompressed = public_txid_artifact_envelope_with_sidecar(
        start_index,
        transactions.len() as u64,
        &records,
        &sidecar,
    );
    verified_public_txid_artifact_chunk(start_index, transactions, None, uncompressed)
}

fn verified_public_txid_artifact_chunk(
    start_index: u64,
    transactions: &[IndexedRailgunTransaction],
    root: Option<FixedBytes<32>>,
    uncompressed: Vec<u8>,
) -> VerifiedIndexedArtifactChunk {
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
                ..DatasetDescriptorMetadata::default()
            },
        },
        bytes,
    }
}

fn test_unshield_preimage(marker: u8) -> CommitmentPreimage {
    CommitmentPreimage {
        npk: FixedBytes::from([marker; 32]),
        token: TokenData {
            tokenType: 0,
            tokenAddress: Address::from([0x33; 20]),
            tokenSubID: U256::ZERO,
        },
        value: Uint::<120, 2>::from(42_u64),
    }
}

fn public_txid_artifact_chunk_from_payload(
    start_index: u64,
    end_index: u64,
    row_count: u64,
    payload: &[u8],
    root: Option<FixedBytes<32>>,
) -> VerifiedIndexedArtifactChunk {
    let uncompressed =
        public_txid_artifact_envelope_with_end(start_index, end_index, row_count, payload);
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
    public_txid_artifact_envelope_in_section(
        start_index,
        end_index,
        row_count,
        PUBLIC_TXID_RECORD_SECTION_ID,
        payload,
    )
}

fn public_txid_artifact_envelope_in_section(
    start_index: u64,
    end_index: u64,
    row_count: u64,
    section_id: u16,
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
    write_u16(&mut bytes, section_id);
    write_u64(&mut bytes, 0);
    write_u64(&mut bytes, payload.len() as u64);
    bytes.extend_from_slice(payload);
    bytes
}

fn public_txid_artifact_envelope_with_sidecar(
    start_index: u64,
    row_count: u64,
    records: &[u8],
    sidecar: &[u8],
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
    write_u64(&mut bytes, start_index + row_count - 1);
    write_u64(&mut bytes, row_count);
    write_u64(&mut bytes, (records.len() + sidecar.len()) as u64);
    write_u16(&mut bytes, 2);
    write_u16(&mut bytes, PUBLIC_TXID_RECORD_SECTION_ID);
    write_u64(&mut bytes, 0);
    write_u64(&mut bytes, records.len() as u64);
    write_u16(&mut bytes, 2);
    write_u64(&mut bytes, records.len() as u64);
    write_u64(&mut bytes, sidecar.len() as u64);
    bytes.extend_from_slice(records);
    bytes.extend_from_slice(sidecar);
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
    for (_generation, chunks) in catalogs {
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
            metadata: DatasetDescriptorMetadata::default(),
        };
        catalog_descriptors.push(catalog_descriptor);
        catalog_blocks.push((catalog_cid, catalog_bytes));
        all_chunks.extend(chunks);
    }
    catalog_descriptors.extend(extra_catalog_descriptors);
    signed_artifact_source(&scope, catalog_descriptors, catalog_blocks, all_chunks)
}

fn public_txid_empty_artifact_source() -> (IndexedArtifactSourceConfig, PathServer) {
    signed_artifact_source(&artifact_scope(), Vec::new(), Vec::new(), Vec::new())
}

fn unavailable_artifact_source() -> IndexedArtifactSourceConfig {
    IndexedArtifactSourceConfig {
        trusted_publisher_pubkey: FixedBytes::from([0x22; 32]),
        manifest_source: IndexedArtifactManifestSource::Url(
            Url::parse("http://127.0.0.1:1/manifest").expect("manifest URL"),
        ),
        gateway_urls: vec![Url::parse("http://127.0.0.1:1").expect("gateway URL")],
        gateway_pool: None,
        manifest_reuse: crate::IndexedArtifactManifestReuse::default(),
        max_manifest_age: None,
        concurrency: 4,
        max_in_flight_bytes: 64 * 1024 * 1024,
        amount_statistics_ipns_name: None,
    }
}

fn signed_artifact_source(
    scope: &ChainScope,
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
        gateway_pool: None,
        manifest_reuse: crate::IndexedArtifactManifestReuse::default(),
        max_manifest_age: None,
        concurrency: 4,
        max_in_flight_bytes: 64 * 1024 * 1024,
        amount_statistics_ipns_name: None,
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
        24..=0xff => out.extend_from_slice(&[major | 0x18, u8::try_from(len).expect("u8 len")]),
        0x100..=0xffff => {
            out.push(major | 0x19);
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
    requests: Arc<Mutex<Vec<String>>>,
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
        let requests = Arc::new(Mutex::new(Vec::new()));
        std::thread::spawn({
            let routes = Arc::clone(&routes);
            let requests = Arc::clone(&requests);
            move || {
                for _ in 0..request_count {
                    let (stream, _) = listener.accept().expect("accept request");
                    let routes = Arc::clone(&routes);
                    let requests = Arc::clone(&requests);
                    std::thread::spawn(move || handle_path_request(stream, &routes, &requests));
                }
            }
        });
        Self { url, requests }
    }

    fn request_count(&self, path: &str) -> usize {
        self.requests
            .lock()
            .expect("path server request lock")
            .iter()
            .filter(|request| request.as_str() == path)
            .count()
    }

    fn request_count_excluding(&self, excluded: &[&str]) -> usize {
        self.requests
            .lock()
            .expect("path server request lock")
            .iter()
            .filter(|request| !excluded.contains(&request.as_str()))
            .count()
    }
}

fn handle_path_request(
    mut stream: std::net::TcpStream,
    routes: &Arc<HashMap<String, Vec<u8>>>,
    requests: &Arc<Mutex<Vec<String>>>,
) {
    let path = read_request_path(&mut stream);
    requests
        .lock()
        .expect("path server request lock")
        .push(path.clone());
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

fn spawn_graphql_responses(response_bodies: Vec<String>) -> (Url, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
    let url = Url::parse(&format!(
        "http://{}/graphql",
        listener.local_addr().expect("local addr")
    ))
    .expect("mock url");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for response_body in response_bodies {
            let (mut stream, _) = listener.accept().expect("accept request");
            let mut request = [0_u8; 4096];
            let read = stream.read(&mut request).expect("read request");
            let request = String::from_utf8_lossy(&request[..read]).to_string();
            tx.send(request).expect("send request");
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            stream
                .write_all(response.as_bytes())
                .expect("write response");
        }
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

mod artifact_chunks;
mod artifact_fallback;
mod artifact_formats;
mod artifact_progress;
mod background_retention;
mod checkpoints;
mod chunk_validation;
mod lookups;
mod public_cache_recovery;
mod public_cache_sync;
