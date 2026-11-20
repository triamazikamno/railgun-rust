use super::*;

pub(super) fn checkpointed_wallet_artifact_source(
    scope: &ChainScope,
    start: u64,
    end: u64,
    checkpoint_block: u64,
) -> TestArtifactSource {
    checkpointed_wallet_artifact_source_controlled(scope, start, end, checkpoint_block, false).0
}

pub(super) fn checkpointed_wallet_artifact_source_with_blocked_manifest(
    scope: &ChainScope,
    start: u64,
    end: u64,
    checkpoint_block: u64,
) -> (TestArtifactSource, PathServerBlockControl) {
    let (source, block) =
        checkpointed_wallet_artifact_source_controlled(scope, start, end, checkpoint_block, true);
    (source, block.expect("blocked manifest control"))
}

pub(super) fn checkpointed_wallet_artifact_source_controlled(
    scope: &ChainScope,
    start: u64,
    end: u64,
    checkpoint_block: u64,
    block_manifest: bool,
) -> (TestArtifactSource, Option<PathServerBlockControl>) {
    checkpointed_wallet_artifact_source_controlled_with_requests(
        scope,
        start,
        end,
        checkpoint_block,
        block_manifest,
        3,
        None,
        false,
    )
}

pub(super) fn checkpointed_wallet_artifact_source_controlled_with_requests(
    scope: &ChainScope,
    start: u64,
    end: u64,
    checkpoint_block: u64,
    block_manifest: bool,
    request_count: usize,
    split_at: Option<u64>,
    omit_last_chunk: bool,
) -> (TestArtifactSource, Option<PathServerBlockControl>) {
    let chunk_ranges = split_at.map_or_else(
        || vec![(start, end)],
        |split_at| {
            assert!(start < split_at && split_at <= end);
            vec![(start, split_at - 1), (split_at, end)]
        },
    );
    let chunks = chunk_ranges
        .into_iter()
        .map(|(chunk_start, chunk_end)| {
            let bytes = empty_wallet_scan_chunk_bytes(scope, chunk_start, chunk_end);
            let cid = raw_cid(&bytes);
            let descriptor = wallet_artifact_descriptor(
                scope.clone(),
                chunk_start,
                chunk_end,
                0,
                cid,
                &bytes,
                DatasetDescriptorMetadata {
                    catalog_generation: Some(1),
                    checkpoint_block: Some(chunk_end.min(checkpoint_block)),
                    ..Default::default()
                },
                CompressionAlgorithm::None,
            );
            (descriptor, cid, bytes)
        })
        .collect::<Vec<_>>();
    wallet_artifact_source_for_chunks(
        scope,
        chunks,
        block_manifest,
        request_count,
        omit_last_chunk,
    )
}

pub(super) fn wallet_artifact_source_for_chunks(
    scope: &ChainScope,
    chunks: Vec<(IndexedArtifactDescriptor, Cid, Vec<u8>)>,
    block_manifest: bool,
    request_count: usize,
    omit_last_chunk: bool,
) -> (TestArtifactSource, Option<PathServerBlockControl>) {
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let start = chunks.first().expect("first chunk").0.range.start;
    let end = chunks.last().expect("last chunk").0.range.end;
    let chunk_descriptors = chunks
        .iter()
        .map(|(descriptor, _, _)| descriptor.clone())
        .collect::<Vec<_>>();
    let row_count = chunk_descriptors.iter().map(|chunk| chunk.row_count).sum();
    let catalog = IndexedArtifactCatalog {
        format_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
        dataset_kind: IndexedDatasetKind::WalletScan,
        scope: scope.clone(),
        chunks: chunk_descriptors.clone(),
    };
    let catalog_bytes = serde_json::to_vec(&catalog).expect("catalog json");
    let catalog_cid = raw_cid(&catalog_bytes);
    let catalog_descriptor = wallet_artifact_descriptor(
        scope.clone(),
        start,
        end,
        row_count,
        catalog_cid,
        &catalog_bytes,
        DatasetDescriptorMetadata {
            catalog_generation: Some(1),
            checkpoint_block: Some(end),
            ..Default::default()
        },
        CompressionAlgorithm::None,
    );
    let mut manifest = IndexedArtifactManifest::new(
        1_700_000_000_000,
        1,
        PublisherIdentity::ed25519(FixedBytes::from(signing_key.verifying_key().to_bytes())),
        vec![IndexedArtifactChainEntry {
            scope: scope.clone(),
            latest_indexed: vec![LatestIndexedHeight {
                dataset_kind: IndexedDatasetKind::WalletScan,
                block_number: end,
                block_hash: FixedBytes::from([0x22; 32]),
            }],
            catalogs: vec![catalog_descriptor],
        }],
    );
    manifest.sign_manifest(&signing_key).expect("sign manifest");
    let manifest_bytes = serde_json::to_vec(&manifest).expect("manifest json");
    let mut routes = HashMap::from([
        ("/manifest.json".to_string(), manifest_bytes),
        (
            format!("/ipfs/{catalog_cid}?format=car&dag-scope=entity"),
            car_bytes(catalog_cid, &[(catalog_cid, catalog_bytes)]),
        ),
    ]);
    let chunk_count = chunks.len();
    for (index, (_, cid, bytes)) in chunks.into_iter().enumerate() {
        if omit_last_chunk && index + 1 == chunk_count {
            continue;
        }
        routes.insert(
            format!("/ipfs/{cid}?format=car&dag-scope=entity"),
            car_bytes(cid, &[(cid, bytes)]),
        );
    }
    let (server, block) = if block_manifest {
        let (server, block) = PathServer::spawn_with_blocked_path(
            routes,
            request_count,
            "/manifest.json".to_string(),
        );
        (server, Some(block))
    } else {
        (PathServer::spawn(routes, request_count), None)
    };
    let manifest_url = server.url.join("/manifest.json").expect("manifest url");
    let config = IndexedArtifactSourceConfig {
        trusted_publisher_pubkey: FixedBytes::from(signing_key.verifying_key().to_bytes()),
        manifest_source: IndexedArtifactManifestSource::Url(manifest_url),
        gateway_urls: vec![server.url.clone()],
        gateway_pool: None,
        manifest_reuse: crate::IndexedArtifactManifestReuse::default(),
        max_manifest_age: None,
        concurrency: 1,
        max_in_flight_bytes: 1024 * 1024,
    };
    (
        TestArtifactSource {
            config,
            server,
            chunk_descriptors,
        },
        block,
    )
}

pub(super) fn wallet_artifact_descriptor(
    scope: ChainScope,
    start: u64,
    end: u64,
    row_count: u64,
    cid: Cid,
    bytes: &[u8],
    metadata: DatasetDescriptorMetadata,
    compression: CompressionAlgorithm,
) -> IndexedArtifactDescriptor {
    IndexedArtifactDescriptor {
        dataset_kind: IndexedDatasetKind::WalletScan,
        scope,
        range: IndexedArtifactRange {
            kind: IndexedArtifactRangeKind::Block,
            start,
            end,
        },
        row_count,
        cid: cid.to_string(),
        sha256: FixedBytes::from_slice(&Sha256::digest(bytes)),
        byte_size: u64::try_from(bytes.len()).expect("artifact byte size"),
        encoding_version: INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION,
        compression,
        metadata,
    }
}

pub(super) fn empty_wallet_scan_chunk_bytes(scope: &ChainScope, start: u64, end: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(INDEXED_ARTIFACT_CHUNK_MAGIC);
    write_u16(&mut bytes, INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION);
    bytes.push(0);
    bytes.push(0);
    write_u64(&mut bytes, scope.chain_id);
    write_string(
        &mut bytes,
        &format!(
            "0x{}",
            alloy::hex::encode(scope.railgun_contract.as_slice())
        ),
    );
    bytes.push(0);
    write_u64(&mut bytes, start);
    write_u64(&mut bytes, end);
    write_u64(&mut bytes, 0);
    write_u64(&mut bytes, 0);
    write_u16(&mut bytes, 0);
    bytes
}

pub(super) fn raw_cid(bytes: &[u8]) -> Cid {
    Cid::new_v1(0x55, Code::Sha2_256.digest(bytes))
}

pub(super) fn car_bytes(root: Cid, blocks: &[(Cid, Vec<u8>)]) -> Vec<u8> {
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

pub(super) fn car_header(root: Cid) -> Vec<u8> {
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

pub(super) fn write_cbor_text(value: &str, out: &mut Vec<u8>) {
    write_cbor_len(0x60, value.len(), out);
    out.extend_from_slice(value.as_bytes());
}

pub(super) fn write_cbor_bytes(value: &[u8], out: &mut Vec<u8>) {
    write_cbor_len(0x40, value.len(), out);
    out.extend_from_slice(value);
}

pub(super) fn write_cbor_len(major: u8, len: usize, out: &mut Vec<u8>) {
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

pub(super) fn write_varint(mut value: usize, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((u8::try_from(value & 0x7f).expect("varint byte")) | 0x80);
        value >>= 7;
    }
    out.push(u8::try_from(value).expect("varint final byte"));
}

pub(super) fn write_string(bytes: &mut Vec<u8>, value: &str) {
    write_u16(bytes, u16::try_from(value.len()).expect("string len"));
    bytes.extend_from_slice(value.as_bytes());
}

pub(super) fn write_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

pub(super) fn write_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}
