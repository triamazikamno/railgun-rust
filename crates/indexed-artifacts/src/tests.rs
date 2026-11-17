use super::*;

#[test]
fn manifest_signature_verifies_with_typed_scope() {
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let mut manifest = IndexedArtifactManifest::new(
        42,
        7,
        PublisherIdentity::ed25519(FixedBytes::ZERO),
        vec![IndexedArtifactChainEntry {
            scope: scope(),
            latest_indexed: vec![LatestIndexedHeight {
                dataset_kind: IndexedDatasetKind::PublicTxid,
                block_number: 20,
                block_hash: FixedBytes::from([0xcc; 32]),
            }],
            catalogs: Vec::new(),
        }],
    );

    manifest.sign_manifest(&signing_key).expect("sign manifest");

    manifest
        .verify_trusted_signature(&signing_key.verifying_key().to_bytes())
        .expect("manifest verifies");
}

#[test]
fn format_v1_manifest_signature_verifies_after_legacy_deserialization() {
    #[derive(Serialize)]
    struct FormatV1Metadata {
        root: Option<FixedBytes<32>>,
        checkpoint_block: Option<u64>,
        tree_number: Option<u16>,
        leaf_count: Option<u64>,
        start_block: Option<u64>,
        end_block: Option<u64>,
        last_indexed_block: Option<u64>,
    }

    #[derive(Serialize)]
    struct FormatV1Descriptor {
        dataset_kind: IndexedDatasetKind,
        scope: ChainScope,
        range: IndexedArtifactRange,
        row_count: u64,
        cid: String,
        sha256: FixedBytes<32>,
        byte_size: u64,
        encoding_version: u16,
        compression: CompressionAlgorithm,
        metadata: FormatV1Metadata,
    }

    #[derive(Serialize)]
    struct FormatV1ChainEntry {
        scope: ChainScope,
        latest_indexed: Vec<LatestIndexedHeight>,
        catalogs: Vec<FormatV1Descriptor>,
    }

    #[derive(Serialize)]
    struct FormatV1ManifestBody {
        format_version: u16,
        issued_at_ms: u64,
        sequence: u64,
        publisher: PublisherIdentity,
        chains: Vec<FormatV1ChainEntry>,
    }

    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let publisher =
        PublisherIdentity::ed25519(FixedBytes::from(signing_key.verifying_key().to_bytes()));
    let descriptor = IndexedArtifactDescriptor {
        dataset_kind: IndexedDatasetKind::PublicTxid,
        scope: scope(),
        range: IndexedArtifactRange {
            kind: IndexedArtifactRangeKind::TxidIndex,
            start: 0,
            end: 9,
        },
        row_count: 10,
        cid: "bafy-format-v1-catalog".to_string(),
        sha256: FixedBytes::from([0x33; 32]),
        byte_size: 123,
        encoding_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
        compression: CompressionAlgorithm::None,
        metadata: DatasetDescriptorMetadata {
            root: Some(FixedBytes::from([0x55; 32])),
            checkpoint_block: Some(100),
            last_indexed_block: Some(100),
            ..Default::default()
        },
    };
    let legacy_body = FormatV1ManifestBody {
        format_version: INDEXED_ARTIFACT_MANIFEST_FORMAT_VERSION,
        issued_at_ms: 42,
        sequence: 7,
        publisher: publisher.clone(),
        chains: vec![FormatV1ChainEntry {
            scope: scope(),
            latest_indexed: vec![LatestIndexedHeight {
                dataset_kind: IndexedDatasetKind::PublicTxid,
                block_number: 100,
                block_hash: FixedBytes::from([0x77; 32]),
            }],
            catalogs: vec![FormatV1Descriptor {
                dataset_kind: descriptor.dataset_kind,
                scope: descriptor.scope.clone(),
                range: descriptor.range.clone(),
                row_count: descriptor.row_count,
                cid: descriptor.cid.clone(),
                sha256: descriptor.sha256,
                byte_size: descriptor.byte_size,
                encoding_version: descriptor.encoding_version,
                compression: descriptor.compression,
                metadata: FormatV1Metadata {
                    root: descriptor.metadata.root,
                    checkpoint_block: descriptor.metadata.checkpoint_block,
                    tree_number: descriptor.metadata.tree_number,
                    leaf_count: descriptor.metadata.leaf_count,
                    start_block: descriptor.metadata.start_block,
                    end_block: descriptor.metadata.end_block,
                    last_indexed_block: descriptor.metadata.last_indexed_block,
                },
            }],
        }],
    };
    let legacy_body_bytes = serde_json::to_vec(&legacy_body).expect("serialize v1 body");
    let mut manifest = IndexedArtifactManifest {
        format_version: INDEXED_ARTIFACT_MANIFEST_FORMAT_VERSION,
        issued_at_ms: 42,
        sequence: 7,
        publisher,
        chains: vec![IndexedArtifactChainEntry {
            scope: scope(),
            latest_indexed: vec![LatestIndexedHeight {
                dataset_kind: IndexedDatasetKind::PublicTxid,
                block_number: 100,
                block_hash: FixedBytes::from([0x77; 32]),
            }],
            catalogs: vec![descriptor],
        }],
        publisher_signature: None,
    };
    manifest.publisher_signature = Some(FixedBytes::from(
        signing_key.sign(&legacy_body_bytes).to_bytes(),
    ));

    assert_eq!(
        manifest
            .deterministic_body_bytes()
            .expect("serialize current v1 body"),
        legacy_body_bytes
    );
    let wire = serde_json::to_vec(&manifest).expect("serialize signed v1 manifest");
    let wire_text = std::str::from_utf8(&wire).expect("v1 JSON");
    assert!(!wire_text.contains("catalog_generation"));
    assert!(!wire_text.contains("stream_partition"));
    assert!(!wire_text.contains("stream_complete"));
    assert!(!wire_text.contains("chunk_sealed"));
    let decoded: IndexedArtifactManifest =
        serde_json::from_slice(&wire).expect("deserialize old producer manifest");
    decoded
        .verify_trusted_signature(&signing_key.verifying_key().to_bytes())
        .expect("old producer signature verifies");

    let mut injected: serde_json::Value =
        serde_json::from_slice(&wire).expect("parse signed v1 manifest");
    let metadata = injected
        .pointer_mut("/chains/0/catalogs/0/metadata")
        .and_then(serde_json::Value::as_object_mut)
        .expect("catalog metadata object");
    metadata.insert("catalog_generation".to_string(), serde_json::json!(99));
    metadata.insert(
        "stream_partition".to_string(),
        serde_json::json!("attacker-controlled"),
    );
    metadata.insert("stream_complete".to_string(), serde_json::json!(true));
    metadata.insert("chunk_sealed".to_string(), serde_json::json!(true));
    metadata.insert(
        "decoded_envelope_byte_size".to_string(),
        serde_json::json!(999),
    );
    let injected: IndexedArtifactManifest =
        serde_json::from_value(injected).expect("deserialize v1 manifest with injected metadata");
    let injected_metadata = &injected.chains[0].catalogs[0].metadata;
    assert_eq!(injected_metadata.catalog_generation, None);
    assert_eq!(injected_metadata.stream_partition, None);
    assert!(!injected_metadata.stream_complete);
    assert!(!injected_metadata.chunk_sealed);
    assert_eq!(injected_metadata.decoded_envelope_byte_size, None);
    injected
        .verify_trusted_signature(&signing_key.verifying_key().to_bytes())
        .expect("unsigned injected metadata cannot affect v1 verification");
}

#[test]
fn typed_fields_serialize_as_lowercase_prefixed_hex() {
    let descriptor = IndexedArtifactDescriptor {
        dataset_kind: IndexedDatasetKind::PublicTxid,
        scope: scope(),
        range: IndexedArtifactRange {
            kind: IndexedArtifactRangeKind::TxidIndex,
            start: 1,
            end: 2,
        },
        row_count: 2,
        cid: "bafy".to_string(),
        sha256: FixedBytes::from([0xab; 32]),
        byte_size: 10,
        encoding_version: CHUNK_FORMAT_VERSION,
        compression: CompressionAlgorithm::Zstd,
        metadata: DatasetDescriptorMetadata {
            root: Some(FixedBytes::from([0xcd; 32])),
            catalog_generation: Some(9),
            stream_partition: Some("txid-v3:list-a".to_string()),
            stream_complete: true,
            chunk_sealed: true,
            decoded_envelope_byte_size: Some(123),
            ..Default::default()
        },
    };

    let json = serde_json::to_string(&descriptor).expect("serialize descriptor");

    assert!(json.contains("\"railgun_contract\":\"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\""));
    assert!(json.contains(
        "\"sha256\":\"0xabababababababababababababababababababababababababababababababab\""
    ));
    assert!(json.contains(
        "\"root\":\"0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\""
    ));
    assert!(!json.contains("catalog_generation"));
    assert!(!json.contains("stream_partition"));
    assert!(!json.contains("stream_complete"));
    assert!(!json.contains("chunk_sealed"));
    assert!(!json.contains("decoded_envelope_byte_size"));
}

#[test]
fn range_intersection_is_inclusive() {
    let range = range(IndexedArtifactRangeKind::Block, 10, 20);

    assert!(range.intersects(0, 10));
    assert!(range.intersects(20, 30));
    assert!(range.intersects(12, 18));
    assert!(!range.intersects(0, 9));
    assert!(!range.intersects(21, 30));
}

#[test]
fn range_intersection_rejects_inverted_ranges() {
    assert!(!range(IndexedArtifactRangeKind::Block, 10, 20).intersects(21, 20));
    assert!(!range(IndexedArtifactRangeKind::Block, 20, 10).intersects(0, 30));
}

#[test]
fn descriptor_matches_dataset_scope_and_range_kind() {
    let scope = scope();
    let mut other_scope = scope.clone();
    other_scope.chain_id = 2;
    let descriptor = descriptor(
        IndexedDatasetKind::PublicTxid,
        scope.clone(),
        IndexedArtifactRangeKind::TxidIndex,
        10,
        20,
    );

    assert!(descriptor.matches(
        IndexedDatasetKind::PublicTxid,
        &scope,
        IndexedArtifactRangeKind::TxidIndex,
    ));
    assert!(!descriptor.matches(
        IndexedDatasetKind::WalletScan,
        &scope,
        IndexedArtifactRangeKind::TxidIndex,
    ));
    assert!(!descriptor.matches(
        IndexedDatasetKind::PublicTxid,
        &scope,
        IndexedArtifactRangeKind::Block,
    ));
    assert!(!descriptor.matches(
        IndexedDatasetKind::PublicTxid,
        &other_scope,
        IndexedArtifactRangeKind::TxidIndex,
    ));
}

#[test]
fn descriptor_matches_range_requires_identity_and_intersection() {
    let scope = scope();
    let descriptor = descriptor(
        IndexedDatasetKind::WalletScan,
        scope.clone(),
        IndexedArtifactRangeKind::Block,
        10,
        20,
    );

    assert!(descriptor.matches_range(
        IndexedDatasetKind::WalletScan,
        &scope,
        IndexedArtifactRangeKind::Block,
        20,
        30,
    ));
    assert!(!descriptor.matches_range(
        IndexedDatasetKind::WalletScan,
        &scope,
        IndexedArtifactRangeKind::Block,
        21,
        30,
    ));
    assert!(!descriptor.matches_range(
        IndexedDatasetKind::WalletScan,
        &scope,
        IndexedArtifactRangeKind::TxidIndex,
        10,
        20,
    ));
}

#[test]
fn chunk_envelope_round_trips_header_and_payload() {
    let envelope = ChunkEnvelope::new(
        ChunkEnvelopeHeader::new(
            IndexedDatasetKind::PublicTxid,
            scope(),
            IndexedArtifactRange {
                kind: IndexedArtifactRangeKind::TxidIndex,
                start: 0,
                end: 2,
            },
            3,
            6,
            vec![ChunkSection {
                section_id: 1,
                offset: 1,
                byte_length: 3,
            }],
        ),
        b"abcdef".to_vec(),
    );

    let encoded = envelope.encode().expect("encode envelope");
    let decoded = ChunkEnvelope::decode(&encoded).expect("decode envelope");

    assert_eq!(decoded, envelope);
    assert_eq!(decoded.payload(), b"abcdef");
    assert_eq!(decoded.section_payload(1).expect("section"), b"bcd");
}

#[test]
fn decoded_envelope_sections_borrow_the_single_owned_buffer() {
    let envelope = ChunkEnvelope::new(
        ChunkEnvelopeHeader::new(
            IndexedDatasetKind::PublicTxid,
            scope(),
            range(IndexedArtifactRangeKind::TxidIndex, 0, 2),
            3,
            6,
            vec![ChunkSection {
                section_id: 1,
                offset: 1,
                byte_length: 3,
            }],
        ),
        b"abcdef".to_vec(),
    );

    let decoded = ChunkEnvelope::decode_owned(envelope.encode().expect("encode envelope"))
        .expect("decode envelope");
    let payload = decoded.payload();
    let section = decoded.section_payload(1).expect("section");

    assert!(decoded.payload_offset > 0);
    assert_eq!(section.as_ptr(), payload[1..].as_ptr());
    assert_eq!(section, b"bcd");
}

#[test]
fn chunk_decode_counts_the_full_envelope_against_advertised_size() {
    let envelope = ChunkEnvelope::new(
        ChunkEnvelopeHeader::new(
            IndexedDatasetKind::PublicTxid,
            scope(),
            range(IndexedArtifactRangeKind::TxidIndex, 0, 2),
            3,
            6,
            vec![ChunkSection {
                section_id: 1,
                offset: 0,
                byte_length: 6,
            }],
        ),
        b"abcdef".to_vec(),
    );
    let encoded = envelope.encode().expect("encode envelope");
    let compressed = compress_bytes(&encoded, CompressionAlgorithm::Zstd).expect("compress");
    let mut descriptor = descriptor(
        IndexedDatasetKind::PublicTxid,
        scope(),
        IndexedArtifactRangeKind::TxidIndex,
        0,
        2,
    );
    descriptor.row_count = 3;
    descriptor.byte_size = u64::try_from(compressed.len()).expect("compressed size");
    descriptor.metadata.decoded_envelope_byte_size =
        Some(u64::try_from(encoded.len()).expect("decoded size"));

    let decoded = decode_chunk_bytes(&descriptor, &compressed).expect("exact size decodes");

    assert_eq!(decoded, envelope);
    descriptor.metadata.decoded_envelope_byte_size = Some(
        u64::try_from(encoded.len())
            .expect("decoded size")
            .saturating_sub(1),
    );
    assert!(matches!(
        decode_chunk_bytes(&descriptor, &compressed),
        Err(ChunkError::DecodedEnvelopeTooLarge { actual, maximum })
            if actual == u64::try_from(encoded.len()).expect("decoded size")
                && maximum + 1 == actual
    ));

    descriptor.metadata.decoded_envelope_byte_size =
        Some(u64::try_from(encoded.len()).expect("decoded size") + 1);
    assert!(matches!(
        decode_chunk_bytes(&descriptor, &compressed),
        Err(ChunkError::DescriptorDecodedEnvelopeByteSizeMismatch { expected, actual })
            if expected == actual + 1
                && actual == u64::try_from(encoded.len()).expect("decoded size")
    ));
}

#[test]
fn legacy_chunk_decode_obeys_injected_dataset_bound() {
    let envelope = ChunkEnvelope::new(
        ChunkEnvelopeHeader::new(
            IndexedDatasetKind::Commitments,
            scope(),
            range(IndexedArtifactRangeKind::TreePosition, 0, 0),
            1,
            4,
            vec![ChunkSection {
                section_id: 1,
                offset: 0,
                byte_length: 4,
            }],
        ),
        b"data".to_vec(),
    );
    let encoded = envelope.encode().expect("encode envelope");
    let compressed = compress_bytes(&encoded, CompressionAlgorithm::Zstd).expect("compress");
    let mut descriptor = descriptor(
        IndexedDatasetKind::Commitments,
        scope(),
        IndexedArtifactRangeKind::TreePosition,
        0,
        0,
    );
    descriptor.row_count = 1;
    descriptor.byte_size = u64::try_from(compressed.len()).expect("compressed size");
    let injected_limit = u64::try_from(encoded.len())
        .expect("decoded size")
        .saturating_sub(1);

    assert!(matches!(
        decode_chunk_bytes_with_limit(&descriptor, &compressed, injected_limit),
        Err(ChunkError::DecodedEnvelopeTooLarge { actual, maximum })
            if actual == injected_limit + 1 && maximum == injected_limit
    ));
}

#[test]
fn limited_zstd_decode_accepts_exact_boundary_and_rejects_one_more_byte() {
    const LIMIT: u64 = 1_024;
    let exact = vec![0x5a; LIMIT as usize];
    let exact_compressed = compress_bytes(&exact, CompressionAlgorithm::Zstd).expect("compress");

    assert_eq!(
        decompress_bytes_with_limit(&exact_compressed, CompressionAlgorithm::Zstd, LIMIT)
            .expect("exact limit decodes"),
        exact
    );

    let oversized = vec![0x5a; LIMIT as usize + 1];
    let oversized_compressed =
        compress_bytes(&oversized, CompressionAlgorithm::Zstd).expect("compress");
    assert!(matches!(
        decompress_bytes_with_limit(&oversized_compressed, CompressionAlgorithm::Zstd, LIMIT),
        Err(ChunkError::DecodedEnvelopeTooLarge {
            actual: 1_025,
            maximum: LIMIT
        })
    ));
}

#[test]
fn limited_zstd_decode_rejects_tiny_expansion_bomb() {
    const LIMIT: u64 = 128;
    let expanded = vec![0_u8; 16 * 1_024];
    let compressed =
        compress_bytes(&expanded, CompressionAlgorithm::Zstd).expect("compress bomb fixture");
    assert!(compressed.len() < LIMIT as usize);

    assert!(matches!(
        decompress_bytes_with_limit(&compressed, CompressionAlgorithm::Zstd, LIMIT),
        Err(ChunkError::DecodedEnvelopeTooLarge {
            actual: 129,
            maximum: LIMIT
        })
    ));
}

#[test]
fn zstd_decode_rejects_frames_above_window_log_limit() {
    // Empty frame with a non-single-segment 64 MiB window (window_log 26).
    let oversized_window_frame = [0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x80, 0x01, 0x00, 0x00];

    assert!(matches!(
        decompress_bytes_with_limit(&oversized_window_frame, CompressionAlgorithm::Zstd, 64),
        Err(ChunkError::Compression(_))
    ));
}

#[test]
fn decoded_envelope_dataset_caps_are_fixed_and_absolute() {
    assert_eq!(
        IndexedDatasetKind::WalletScan.decoded_envelope_byte_limit(),
        64 * 1024 * 1024
    );
    assert_eq!(
        IndexedDatasetKind::PublicTxid.decoded_envelope_byte_limit(),
        32 * 1024 * 1024
    );
    assert_eq!(
        IndexedDatasetKind::Commitments.decoded_envelope_byte_limit(),
        8 * 1024 * 1024
    );
    assert_eq!(
        IndexedDatasetKind::MerkleCheckpoint.decoded_envelope_byte_limit(),
        4 * 1024 * 1024
    );
    for dataset_kind in [
        IndexedDatasetKind::WalletScan,
        IndexedDatasetKind::PublicTxid,
        IndexedDatasetKind::Commitments,
        IndexedDatasetKind::MerkleCheckpoint,
    ] {
        let maximum = dataset_kind.decoded_envelope_byte_limit();
        assert!(maximum <= INDEXED_ARTIFACT_MAX_DECODED_ENVELOPE_BYTES);
        let mut descriptor =
            descriptor(dataset_kind, scope(), IndexedArtifactRangeKind::Block, 0, 0);
        descriptor.metadata.decoded_envelope_byte_size = Some(maximum + 1);
        assert!(matches!(
            descriptor.decoded_envelope_byte_size_charge(),
            Err(ChunkError::DecodedEnvelopeTooLarge {
                actual,
                maximum: enforced_maximum,
            }) if actual == maximum + 1 && enforced_maximum == maximum
        ));
    }
}

#[test]
fn legacy_descriptor_without_decoded_size_uses_dataset_cap() {
    let descriptor = descriptor(
        IndexedDatasetKind::Commitments,
        scope(),
        IndexedArtifactRangeKind::TreePosition,
        0,
        0,
    );
    let json = serde_json::to_string(&descriptor).expect("serialize legacy descriptor");

    assert!(!json.contains("decoded_envelope_byte_size"));
    let decoded: IndexedArtifactDescriptor =
        serde_json::from_str(&json).expect("deserialize legacy descriptor");
    assert_eq!(decoded.metadata.decoded_envelope_byte_size, None);
    assert_eq!(
        decoded
            .decoded_envelope_byte_size_charge()
            .expect("legacy charge"),
        INDEXED_ARTIFACT_COMMITMENTS_MAX_DECODED_ENVELOPE_BYTES
    );
}

#[test]
fn chunk_envelope_rejects_duplicate_section_ids() {
    let header = ChunkEnvelopeHeader::new(
        IndexedDatasetKind::PublicTxid,
        scope(),
        IndexedArtifactRange {
            kind: IndexedArtifactRangeKind::TxidIndex,
            start: 0,
            end: 1,
        },
        2,
        2,
        vec![
            ChunkSection {
                section_id: 1,
                offset: 0,
                byte_length: 1,
            },
            ChunkSection {
                section_id: 1,
                offset: 1,
                byte_length: 1,
            },
        ],
    );

    let error = header
        .validate_for_payload(b"ab")
        .expect_err("duplicate section id should fail validation");

    assert!(matches!(
        error,
        ChunkError::DuplicateSection { section_id: 1 }
    ));
}

#[test]
fn chunk_envelope_rejects_overlapping_section_ranges() {
    let header = ChunkEnvelopeHeader::new(
        IndexedDatasetKind::WalletScan,
        scope(),
        IndexedArtifactRange {
            kind: IndexedArtifactRangeKind::Block,
            start: 0,
            end: 1,
        },
        2,
        6,
        vec![
            ChunkSection {
                section_id: 1,
                offset: 0,
                byte_length: 4,
            },
            ChunkSection {
                section_id: 2,
                offset: 3,
                byte_length: 2,
            },
        ],
    );

    let error = header
        .validate_for_payload(b"abcdef")
        .expect_err("overlapping section ranges should fail validation");

    assert!(matches!(
        error,
        ChunkError::OverlappingSections {
            first_section_id: 1,
            first_start: 0,
            first_end: 4,
            second_section_id: 2,
            second_start: 3,
            second_end: 5,
        }
    ));
}

#[test]
fn chunk_envelope_accepts_adjacent_section_ranges() {
    let envelope = ChunkEnvelope::new(
        ChunkEnvelopeHeader::new(
            IndexedDatasetKind::WalletScan,
            scope(),
            IndexedArtifactRange {
                kind: IndexedArtifactRangeKind::Block,
                start: 0,
                end: 1,
            },
            2,
            6,
            vec![
                ChunkSection {
                    section_id: 1,
                    offset: 0,
                    byte_length: 3,
                },
                ChunkSection {
                    section_id: 2,
                    offset: 3,
                    byte_length: 3,
                },
            ],
        ),
        b"abcdef".to_vec(),
    );

    let decoded = ChunkEnvelope::decode(&envelope.encode().expect("encode envelope"))
        .expect("decode adjacent sections");

    assert_eq!(decoded.section_payload(1).expect("first section"), b"abc");
    assert_eq!(decoded.section_payload(2).expect("second section"), b"def");
}

#[test]
fn chunk_envelope_accepts_unsorted_non_overlapping_section_ranges() {
    let envelope = ChunkEnvelope::new(
        ChunkEnvelopeHeader::new(
            IndexedDatasetKind::WalletScan,
            scope(),
            IndexedArtifactRange {
                kind: IndexedArtifactRangeKind::Block,
                start: 0,
                end: 1,
            },
            2,
            6,
            vec![
                ChunkSection {
                    section_id: 2,
                    offset: 3,
                    byte_length: 3,
                },
                ChunkSection {
                    section_id: 1,
                    offset: 0,
                    byte_length: 3,
                },
            ],
        ),
        b"abcdef".to_vec(),
    );

    let decoded = ChunkEnvelope::decode(&envelope.encode().expect("encode envelope"))
        .expect("decode unsorted sections");

    assert_eq!(decoded.section_payload(1).expect("first section"), b"abc");
    assert_eq!(decoded.section_payload(2).expect("second section"), b"def");
}

#[test]
fn chunk_planner_groups_by_size_and_range_kind() {
    let items = [
        ChunkPlanItem {
            range: range(IndexedArtifactRangeKind::Block, 0, 9),
            row_count: 10,
            compressed_byte_size: 4,
        },
        ChunkPlanItem {
            range: range(IndexedArtifactRangeKind::Block, 10, 19),
            row_count: 10,
            compressed_byte_size: 4,
        },
        ChunkPlanItem {
            range: range(IndexedArtifactRangeKind::TxidIndex, 20, 29),
            row_count: 10,
            compressed_byte_size: 4,
        },
    ];
    let planned = plan_chunks(
        &items,
        ChunkPlanningConfig {
            target_compressed_bytes: 8,
            soft_min_compressed_bytes: 4,
            soft_max_compressed_bytes: 8,
            hard_max_compressed_bytes: 16,
        },
    )
    .expect("plan chunks");

    assert_eq!(planned.len(), 2);
    assert_eq!(
        planned[0].range,
        range(IndexedArtifactRangeKind::Block, 0, 19)
    );
    assert_eq!(planned[0].item_count, 2);
    assert_eq!(
        planned[1].range,
        range(IndexedArtifactRangeKind::TxidIndex, 20, 29)
    );
}

#[test]
fn stream_planner_replaces_extends_and_consolidates_superseded_final_tails() {
    for (old_start, old_end, new_start, new_end) in
        [(10, 19, 10, 19), (10, 19, 10, 24), (10, 19, 0, 24)]
    {
        let old = StreamFixture::descriptor(
            IndexedDatasetKind::WalletScan,
            IndexedArtifactRangeKind::Block,
            old_start,
            old_end,
            1,
        );
        let new = StreamFixture::descriptor(
            IndexedDatasetKind::WalletScan,
            IndexedArtifactRangeKind::Block,
            new_start,
            new_end,
            2,
        );
        let request = StreamFixture::request(
            IndexedDatasetKind::WalletScan,
            IndexedArtifactRangeKind::Block,
            new_start,
            new_end,
        );

        let plan = plan_from_descriptors(&[old.clone(), new.clone()], &request)
            .expect("plan canonical stream");
        let reversed_plan = plan_from_descriptors(&[new.clone(), old.clone()], &request)
            .expect("plan canonical stream from reversed input");

        assert_eq!(required_cids(&plan), vec![new.cid.clone()]);
        assert_eq!(plan, reversed_plan);
        assert_non_overlapping(&plan.required_current_chunks);
    }
}

#[test]
fn stream_planner_empty_catalog_replaces_superseded_final_tail() {
    let old_tail = StreamFixture::descriptor(
        IndexedDatasetKind::WalletScan,
        IndexedArtifactRangeKind::Block,
        100,
        110,
        1,
    );
    let empty_replacement = empty_catalog(
        IndexedDatasetKind::WalletScan,
        IndexedArtifactRangeKind::Block,
        100,
        110,
        2,
    );

    let plan = IndexedArtifactStreamPlan::plan(
        &[
            catalog_for_descriptors(Some(1), vec![old_tail]),
            empty_replacement,
        ],
        &StreamFixture::request(
            IndexedDatasetKind::WalletScan,
            IndexedArtifactRangeKind::Block,
            100,
            110,
        ),
    )
    .expect("empty replacement catalog covers superseded tail");

    assert_eq!(
        plan.required_current_chunks,
        [] as [IndexedArtifactPlannedChunk; 0]
    );
    assert_eq!(coverage_ranges(&plan), vec![(100, 110)]);
}

#[test]
fn stream_planner_partial_newer_coverage_preserves_older_remainders() {
    let older_coverage = empty_catalog(
        IndexedDatasetKind::WalletScan,
        IndexedArtifactRangeKind::Block,
        100,
        200,
        1,
    );
    let newer_coverage = empty_catalog(
        IndexedDatasetKind::WalletScan,
        IndexedArtifactRangeKind::Block,
        150,
        160,
        2,
    );

    let plan = IndexedArtifactStreamPlan::plan(
        &[older_coverage, newer_coverage],
        &StreamFixture::request(
            IndexedDatasetKind::WalletScan,
            IndexedArtifactRangeKind::Block,
            100,
            200,
        ),
    )
    .expect("partial newer coverage keeps older non-overlapping coverage");

    assert_eq!(
        plan.required_current_chunks,
        [] as [IndexedArtifactPlannedChunk; 0]
    );
    assert_eq!(
        coverage_ranges(&plan),
        vec![(100, 149), (150, 160), (161, 200)]
    );
}

#[test]
fn stream_planner_partial_newer_coverage_preserves_non_empty_catalog_remainders() {
    let older_chunk = StreamFixture::descriptor(
        IndexedDatasetKind::WalletScan,
        IndexedArtifactRangeKind::Block,
        120,
        130,
        1,
    );
    let older_sparse_coverage = catalog_with_range(1, 100, 200, vec![older_chunk.clone()]);
    let newer_coverage = empty_catalog(
        IndexedDatasetKind::WalletScan,
        IndexedArtifactRangeKind::Block,
        150,
        160,
        2,
    );

    let plan = IndexedArtifactStreamPlan::plan(
        &[older_sparse_coverage, newer_coverage],
        &StreamFixture::request(
            IndexedDatasetKind::WalletScan,
            IndexedArtifactRangeKind::Block,
            100,
            200,
        ),
    )
    .expect("partial newer coverage keeps sparse catalog remainders");

    assert_eq!(required_cids(&plan), vec![older_chunk.cid]);
    let ranges = coverage_ranges(&plan);
    assert!(ranges.contains(&(100, 149)));
    assert!(ranges.contains(&(150, 160)));
    assert!(ranges.contains(&(161, 200)));
    assert!(!ranges.contains(&(100, 200)));
}

#[test]
fn stream_planner_empty_catalog_does_not_suppress_stable_chunks() {
    let sealed_tail = StreamFixture::descriptor(
        IndexedDatasetKind::WalletScan,
        IndexedArtifactRangeKind::Block,
        100,
        110,
        1,
    )
    .sealed();
    let empty_replacement = empty_catalog(
        IndexedDatasetKind::WalletScan,
        IndexedArtifactRangeKind::Block,
        100,
        110,
        2,
    );

    let plan = IndexedArtifactStreamPlan::plan(
        &[
            catalog_for_descriptors(Some(1), vec![sealed_tail.clone()]),
            empty_replacement,
        ],
        &StreamFixture::request(
            IndexedDatasetKind::WalletScan,
            IndexedArtifactRangeKind::Block,
            100,
            110,
        ),
    )
    .expect("empty coverage does not replace sealed chunks");

    assert_eq!(required_cids(&plan), vec![sealed_tail.cid]);
}

#[test]
fn stream_planner_empty_catalog_rejects_partial_superseded_tail_coverage() {
    let old_tail = StreamFixture::descriptor(
        IndexedDatasetKind::WalletScan,
        IndexedArtifactRangeKind::Block,
        100,
        110,
        1,
    );
    let partial_empty_replacement = empty_catalog(
        IndexedDatasetKind::WalletScan,
        IndexedArtifactRangeKind::Block,
        105,
        110,
        2,
    );

    assert!(matches!(
        IndexedArtifactStreamPlan::plan(
            &[
                catalog_for_descriptors(Some(1), vec![old_tail]),
                partial_empty_replacement,
            ],
            &StreamFixture::request(
                IndexedDatasetKind::WalletScan,
                IndexedArtifactRangeKind::Block,
                100,
                110,
            ),
        ),
        Err(
            IndexedArtifactStreamPlanError::SupersededRequestedRangeGap {
                start: 100,
                end: 110
            }
        )
    ));
}

#[test]
fn stream_planner_retains_prior_tail_only_after_later_chunk_seals_it() {
    let old_tail = StreamFixture::descriptor(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        0,
        9,
        1,
    );
    let request = StreamFixture::request(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        10,
        19,
    );

    let plan_without_later = plan_from_descriptors(std::slice::from_ref(&old_tail), &request)
        .expect("plan without later chunk");

    assert_eq!(
        plan_without_later.required_current_chunks,
        [] as [IndexedArtifactPlannedChunk; 0]
    );
    assert_eq!(
        plan_without_later.optional_prior_tail_retention,
        [] as [IndexedArtifactPlannedChunk; 0]
    );

    let current_tail = StreamFixture::descriptor(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        10,
        19,
        2,
    );
    let plan = plan_from_descriptors(&[current_tail.clone(), old_tail.clone()], &request)
        .expect("plan with later chunk");

    assert_eq!(required_cids(&plan), vec![current_tail.cid]);
    assert_eq!(optional_cids(&plan), vec![old_tail.cid]);
    assert_eq!(
        plan.optional_prior_tail_retention[0].placement,
        IndexedArtifactPlannedChunkPlacement::OptionalPriorTail
    );
}

#[test]
fn stream_planner_classifies_current_chunk_stability() {
    let transient_tail = StreamFixture::descriptor(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        10,
        19,
        1,
    );
    let request = StreamFixture::request(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        0,
        19,
    );

    let transient_plan = plan_from_descriptors(std::slice::from_ref(&transient_tail), &request)
        .expect("plan transient final chunk");
    assert_eq!(
        transient_plan.required_current_chunks[0].placement,
        IndexedArtifactPlannedChunkPlacement::CurrentTransient
    );

    for stable_tail in [
        transient_tail.clone().sealed(),
        transient_tail.clone().complete(),
    ] {
        let stable_plan = plan_from_descriptors(std::slice::from_ref(&stable_tail), &request)
            .expect("plan explicitly stable final chunk");
        assert_eq!(
            stable_plan.required_current_chunks[0].placement,
            IndexedArtifactPlannedChunkPlacement::CurrentStable
        );
    }

    let first = StreamFixture::descriptor(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        0,
        9,
        1,
    );
    let non_final_plan = plan_from_descriptors(&[first.clone(), transient_tail], &request)
        .expect("plan non-final current chunk");
    assert_eq!(
        non_final_plan.required_current_chunks[0].descriptor.cid,
        first.cid
    );
    assert_eq!(
        non_final_plan.required_current_chunks[0].placement,
        IndexedArtifactPlannedChunkPlacement::CurrentStable
    );
}

#[test]
fn stream_planner_uses_adjacent_catalog_descriptor_as_stability_context() {
    let current = StreamFixture::descriptor(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        0,
        9,
        1,
    )
    .partition("list-a");
    let current_catalog = catalog_with_range(1, 0, 9, vec![current]);
    let successor_catalog = StreamFixture::descriptor(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        10,
        19,
        1,
    )
    .partition("list-a");
    let request = StreamFixture::partitioned_request(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        0,
        9,
        "list-a",
    );

    let plan = IndexedArtifactStreamPlan::plan_with_catalog_descriptor_context(
        std::slice::from_ref(&current_catalog),
        &[current_catalog.descriptor.clone(), successor_catalog],
        &request,
    )
    .expect("same-generation successor catalog stabilizes the current tail");

    assert_eq!(
        plan.required_current_chunks[0].placement,
        IndexedArtifactPlannedChunkPlacement::CurrentStable
    );

    let other_partition_successor = StreamFixture::descriptor(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        10,
        19,
        1,
    )
    .partition("list-b");
    let exact_partition_plan = IndexedArtifactStreamPlan::plan_with_catalog_descriptor_context(
        std::slice::from_ref(&current_catalog),
        &[
            current_catalog.descriptor.clone(),
            other_partition_successor,
        ],
        &request,
    )
    .expect("other-partition context remains independently plannable");
    assert_eq!(
        exact_partition_plan.required_current_chunks[0].placement,
        IndexedArtifactPlannedChunkPlacement::CurrentTransient
    );

    let wallet_current = StreamFixture::descriptor(
        IndexedDatasetKind::WalletScan,
        IndexedArtifactRangeKind::Block,
        100,
        110,
        1,
    );
    let wallet_catalog = catalog_with_range(1, 100, 110, vec![wallet_current]);
    let wallet_successor = StreamFixture::descriptor(
        IndexedDatasetKind::WalletScan,
        IndexedArtifactRangeKind::Block,
        200,
        210,
        1,
    );
    let sparse_wallet_plan = IndexedArtifactStreamPlan::plan_with_catalog_descriptor_context(
        std::slice::from_ref(&wallet_catalog),
        &[wallet_catalog.descriptor.clone(), wallet_successor],
        &StreamFixture::request(
            IndexedDatasetKind::WalletScan,
            IndexedArtifactRangeKind::Block,
            100,
            110,
        ),
    )
    .expect("sparse wallet successor context remains plannable");
    assert_eq!(
        sparse_wallet_plan.required_current_chunks[0].placement,
        IndexedArtifactPlannedChunkPlacement::CurrentStable
    );
}

#[test]
fn stream_planner_rejects_repack_after_prior_tail_becomes_non_final() {
    let old_tail = StreamFixture::descriptor(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        0,
        9,
        1,
    );
    let later_chunk = StreamFixture::descriptor(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        10,
        19,
        2,
    );
    let illegal_repack = StreamFixture::descriptor(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        5,
        14,
        3,
    );

    assert!(matches!(
        plan_from_descriptors(
            &[old_tail, later_chunk, illegal_repack],
            &StreamFixture::request(
                IndexedDatasetKind::PublicTxid,
                IndexedArtifactRangeKind::TxidIndex,
                5,
                14,
            ),
        ),
        Err(IndexedArtifactStreamPlanError::StableChunkConflict {
            existing_start: 0,
            existing_end: 9,
            attempted_start: 5,
            attempted_end: 14,
        })
    ));
}

#[test]
fn stream_planner_accepts_snapshot_without_generation_and_rejects_requested_range_gaps() {
    let missing_generation = descriptor(
        IndexedDatasetKind::PublicTxid,
        scope(),
        IndexedArtifactRangeKind::TxidIndex,
        0,
        9,
    );
    let request = StreamFixture::request(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        0,
        9,
    );

    let plan = plan_from_descriptors(&[missing_generation], &request)
        .expect("format-v1 snapshot does not require generation metadata");
    assert_eq!(plan.required_current_chunks.len(), 1);

    let old_tail = StreamFixture::descriptor(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        0,
        19,
        1,
    );
    let partial_replacement = StreamFixture::descriptor(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        10,
        19,
        2,
    );
    let requested_gap = StreamFixture::request(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        0,
        19,
    );

    assert!(matches!(
        plan_from_descriptors(&[old_tail, partial_replacement], &requested_gap),
        Err(IndexedArtifactStreamPlanError::SupersededRequestedRangeGap { start: 0, end: 19 })
    ));
}

#[test]
fn stream_planner_keeps_sealed_tails_and_enforces_complete_terminal_tails() {
    let sealed_tail = StreamFixture::descriptor(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        0,
        9,
        1,
    )
    .sealed();
    let next_tail = StreamFixture::descriptor(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        10,
        19,
        2,
    );
    let sealed_request = StreamFixture::request(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        0,
        9,
    );

    let plan = plan_from_descriptors(&[next_tail, sealed_tail.clone()], &sealed_request)
        .expect("sealed tail remains current");

    assert_eq!(required_cids(&plan), vec![sealed_tail.cid.clone()]);

    let conflicting_replacement = StreamFixture::descriptor(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        0,
        9,
        2,
    );
    assert!(matches!(
        plan_from_descriptors(&[sealed_tail, conflicting_replacement], &sealed_request),
        Err(IndexedArtifactStreamPlanError::StableChunkConflict { .. })
    ));

    let complete_tail = StreamFixture::descriptor(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        0,
        9,
        1,
    )
    .complete();
    let mut repeated_complete = complete_tail.clone();
    repeated_complete.metadata.catalog_generation = Some(2);

    plan_from_descriptors(
        &[complete_tail.clone(), repeated_complete],
        &StreamFixture::request(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            0,
            9,
        ),
    )
    .expect("identical complete tail may repeat");

    let extension_after_complete = StreamFixture::descriptor(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        10,
        19,
        2,
    );
    assert!(matches!(
        plan_from_descriptors(
            &[complete_tail, extension_after_complete],
            &StreamFixture::request(
                IndexedDatasetKind::PublicTxid,
                IndexedArtifactRangeKind::TxidIndex,
                10,
                19,
            ),
        ),
        Err(IndexedArtifactStreamPlanError::StreamCompleteExtended {
            complete_end: 9,
            attempted_end: 19
        })
    ));
}

#[test]
fn stream_planner_rejects_empty_coverage_after_complete_tail() {
    let complete_tail = StreamFixture::descriptor(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        0,
        9,
        1,
    )
    .complete();
    let catalogs = vec![
        catalog_for_descriptors(Some(1), vec![complete_tail]),
        empty_catalog(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            10,
            19,
            2,
        ),
    ];

    assert!(matches!(
        IndexedArtifactStreamPlan::plan(
            &catalogs,
            &StreamFixture::request(
                IndexedDatasetKind::PublicTxid,
                IndexedArtifactRangeKind::TxidIndex,
                10,
                19,
            ),
        ),
        Err(IndexedArtifactStreamPlanError::StreamCompleteExtended {
            complete_end: 9,
            attempted_end: 19
        })
    ));
}

#[test]
fn stream_planner_rejects_complete_metadata_on_non_final_chunks() {
    let first_chunk = StreamFixture::descriptor(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        0,
        9,
        1,
    )
    .complete();
    let final_chunk = StreamFixture::descriptor(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        10,
        19,
        1,
    )
    .complete();

    assert!(matches!(
        plan_from_descriptors(
            &[first_chunk.clone(), final_chunk.clone()],
            &StreamFixture::request(
                IndexedDatasetKind::PublicTxid,
                IndexedArtifactRangeKind::TxidIndex,
                0,
                19,
            ),
        ),
        Err(IndexedArtifactStreamPlanError::StreamCompleteExtended {
            complete_end: 9,
            attempted_end: 19
        })
    ));

    let extension_after_complete = StreamFixture::descriptor(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        20,
        29,
        2,
    );
    assert!(matches!(
        plan_from_descriptors(
            &[first_chunk, final_chunk, extension_after_complete],
            &StreamFixture::request(
                IndexedDatasetKind::PublicTxid,
                IndexedArtifactRangeKind::TxidIndex,
                20,
                29,
            ),
        ),
        Err(IndexedArtifactStreamPlanError::StreamCompleteExtended {
            complete_end: 9,
            attempted_end: 19
        })
    ));
}

#[test]
fn stream_planner_rejects_complete_coverage_followed_by_extension() {
    let mut complete_coverage = empty_catalog(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        0,
        9,
        1,
    );
    complete_coverage.descriptor.metadata.stream_complete = true;
    let extension = StreamFixture::descriptor(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        10,
        19,
        1,
    );

    assert!(matches!(
        IndexedArtifactStreamPlan::plan(
            &[
                complete_coverage,
                catalog_for_descriptors(Some(1), vec![extension]),
            ],
            &StreamFixture::request(
                IndexedDatasetKind::PublicTxid,
                IndexedArtifactRangeKind::TxidIndex,
                0,
                19,
            ),
        ),
        Err(IndexedArtifactStreamPlanError::StreamCompleteExtended {
            complete_end: 9,
            attempted_end: 19
        })
    ));
}

#[test]
fn stream_planner_rejects_chunk_inside_complete_empty_coverage() {
    let mut complete_coverage = empty_catalog(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        100,
        200,
        1,
    );
    complete_coverage.descriptor.metadata.stream_complete = true;
    let later_in_range = StreamFixture::descriptor(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        150,
        160,
        2,
    );

    assert!(matches!(
        IndexedArtifactStreamPlan::plan(
            &[
                complete_coverage,
                catalog_for_descriptors(Some(2), vec![later_in_range]),
            ],
            &StreamFixture::request(
                IndexedDatasetKind::PublicTxid,
                IndexedArtifactRangeKind::TxidIndex,
                100,
                200,
            ),
        ),
        Err(IndexedArtifactStreamPlanError::StableChunkConflict {
            existing_start: 100,
            existing_end: 200,
            attempted_start: 150,
            attempted_end: 160,
        })
    ));
}

#[test]
fn stream_planner_allows_repeated_complete_tail() {
    let first_chunk = StreamFixture::descriptor(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        0,
        9,
        1,
    )
    .complete();
    let mut repeated = first_chunk.clone();
    repeated.metadata.catalog_generation = Some(2);

    let plan = plan_from_descriptors(
        &[first_chunk.clone(), repeated],
        &StreamFixture::request(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            0,
            9,
        ),
    )
    .expect("identical complete tail may repeat");

    assert_eq!(required_cids(&plan), vec![first_chunk.cid]);
}

#[test]
fn stream_planner_allows_decoded_size_metadata_rollout_for_stable_chunk() {
    let legacy = StreamFixture::descriptor(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        0,
        9,
        1,
    )
    .sealed();
    let mut enriched = legacy.clone();
    enriched.metadata.catalog_generation = Some(2);
    enriched.metadata.decoded_envelope_byte_size = Some(123);

    let plan = plan_from_descriptors(
        &[legacy.clone(), enriched.clone()],
        &StreamFixture::request(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            0,
            9,
        ),
    )
    .expect("optional decoded-size metadata may be added to a stable chunk");

    assert_eq!(required_cids(&plan), vec![legacy.cid]);

    let mut conflicting = enriched.clone();
    conflicting.metadata.catalog_generation = Some(3);
    conflicting.metadata.decoded_envelope_byte_size = Some(124);
    assert!(matches!(
        plan_from_descriptors(
            &[enriched, conflicting],
            &StreamFixture::request(
                IndexedDatasetKind::PublicTxid,
                IndexedArtifactRangeKind::TxidIndex,
                0,
                9,
            ),
        ),
        Err(IndexedArtifactStreamPlanError::StableChunkConflict { .. })
    ));
}

#[test]
fn stream_planner_wallet_scan_ignores_partitions_but_partitioned_datasets_are_independent() {
    let wallet_tree_a = StreamFixture::descriptor(
        IndexedDatasetKind::WalletScan,
        IndexedArtifactRangeKind::Block,
        0,
        9,
        1,
    )
    .partition("tree-a");
    let wallet_tree_b = StreamFixture::descriptor(
        IndexedDatasetKind::WalletScan,
        IndexedArtifactRangeKind::Block,
        5,
        14,
        1,
    )
    .partition("tree-b");

    assert!(matches!(
        plan_from_descriptors(
            &[wallet_tree_a, wallet_tree_b],
            &StreamFixture::request(
                IndexedDatasetKind::WalletScan,
                IndexedArtifactRangeKind::Block,
                0,
                14,
            ),
        ),
        Err(IndexedArtifactStreamPlanError::SameGenerationOverlap {
            partition: None,
            ..
        })
    ));

    let txid_partition_a = StreamFixture::descriptor(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        0,
        9,
        1,
    )
    .partition("list-a");
    let txid_partition_b = StreamFixture::descriptor(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        0,
        9,
        1,
    )
    .partition("list-b");

    let plan = plan_from_descriptors(
        &[txid_partition_b.clone(), txid_partition_a.clone()],
        &StreamFixture::partitioned_request(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            0,
            9,
            "list-a",
        ),
    )
    .expect("partitioned TXID stream remains independently plannable");

    assert_eq!(required_cids(&plan), vec![txid_partition_a.cid.clone()]);
    assert_eq!(
        plan.required_current_chunks[0].stream.partition.as_deref(),
        Some("list-a")
    );
    assert_non_overlapping_by_partition(&plan.required_current_chunks);

    let plan = plan_from_descriptors(
        &[txid_partition_b.clone(), txid_partition_a],
        &StreamFixture::partitioned_request(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            0,
            9,
            "list-b",
        ),
    )
    .expect("second partition remains independently plannable");

    assert_eq!(required_cids(&plan), vec![txid_partition_b.cid]);
}

#[test]
fn stream_planner_exact_partition_rejects_unpartitioned_and_other_partitions() {
    let unpartitioned = StreamFixture::descriptor(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        0,
        9,
        1,
    );
    let other_partition = StreamFixture::descriptor(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        0,
        9,
        1,
    )
    .partition("list-b");

    let plan = plan_from_descriptors(
        &[unpartitioned, other_partition],
        &StreamFixture::partitioned_request(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            0,
            9,
            "list-a",
        ),
    )
    .expect("irrelevant partitions are ignored");

    assert_eq!(
        plan.required_current_chunks,
        [] as [IndexedArtifactPlannedChunk; 0]
    );
    assert_eq!(
        plan.required_current_coverage,
        [] as [IndexedArtifactStreamCoverage; 0]
    );
}

#[test]
fn stream_planner_deduplicates_wallet_scan_block_repeats_with_ignored_partitions() {
    let sealed_tree_a = StreamFixture::descriptor(
        IndexedDatasetKind::WalletScan,
        IndexedArtifactRangeKind::Block,
        0,
        9,
        1,
    )
    .partition("tree-a")
    .sealed();
    let mut repeated_tree_b = sealed_tree_a.clone();
    repeated_tree_b.metadata.catalog_generation = Some(2);
    repeated_tree_b.metadata.stream_partition = Some("tree-b".to_string());

    let plan = plan_from_descriptors(
        &[sealed_tree_a.clone(), repeated_tree_b],
        &StreamFixture::request(
            IndexedDatasetKind::WalletScan,
            IndexedArtifactRangeKind::Block,
            0,
            9,
        ),
    )
    .expect("ignored wallet-scan partition metadata does not conflict on identical content");

    assert_eq!(required_cids(&plan), vec![sealed_tree_a.cid]);
}

fn scope() -> ChainScope {
    ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xbb; 20]),
    }
}

fn range(kind: IndexedArtifactRangeKind, start: u64, end: u64) -> IndexedArtifactRange {
    IndexedArtifactRange { kind, start, end }
}

fn descriptor(
    dataset_kind: IndexedDatasetKind,
    scope: ChainScope,
    range_kind: IndexedArtifactRangeKind,
    start: u64,
    end: u64,
) -> IndexedArtifactDescriptor {
    IndexedArtifactDescriptor {
        dataset_kind,
        scope,
        range: range(range_kind, start, end),
        row_count: end.saturating_sub(start).saturating_add(1),
        cid: "bafy".to_string(),
        sha256: FixedBytes::from([0xab; 32]),
        byte_size: 10,
        encoding_version: CHUNK_FORMAT_VERSION,
        compression: CompressionAlgorithm::Zstd,
        metadata: DatasetDescriptorMetadata::default(),
    }
}

struct StreamFixture;

impl StreamFixture {
    fn request(
        dataset_kind: IndexedDatasetKind,
        range_kind: IndexedArtifactRangeKind,
        start: u64,
        end: u64,
    ) -> IndexedArtifactStreamPlanRequest {
        IndexedArtifactStreamPlanRequest::new(
            dataset_kind,
            scope(),
            range_kind,
            start,
            end,
            default_partition_policy(dataset_kind, range_kind),
        )
    }

    fn partitioned_request(
        dataset_kind: IndexedDatasetKind,
        range_kind: IndexedArtifactRangeKind,
        start: u64,
        end: u64,
        partition: &str,
    ) -> IndexedArtifactStreamPlanRequest {
        IndexedArtifactStreamPlanRequest::new(
            dataset_kind,
            scope(),
            range_kind,
            start,
            end,
            IndexedArtifactStreamPartitionPolicy::Exact(partition.to_string()),
        )
    }

    fn descriptor(
        dataset_kind: IndexedDatasetKind,
        range_kind: IndexedArtifactRangeKind,
        start: u64,
        end: u64,
        generation: u64,
    ) -> IndexedArtifactDescriptor {
        let mut descriptor = descriptor(dataset_kind, scope(), range_kind, start, end);
        descriptor.cid = format!("bafy-{dataset_kind:?}-{range_kind:?}-{generation}-{start}-{end}");
        descriptor.metadata.catalog_generation = Some(generation);
        descriptor
    }
}

trait StreamDescriptorTestExt {
    fn partition(self, partition: &str) -> IndexedArtifactDescriptor;
    fn sealed(self) -> IndexedArtifactDescriptor;
    fn complete(self) -> IndexedArtifactDescriptor;
}

impl StreamDescriptorTestExt for IndexedArtifactDescriptor {
    fn partition(mut self, partition: &str) -> IndexedArtifactDescriptor {
        self.metadata.stream_partition = Some(partition.to_string());
        self.cid = format!("{}-{partition}", self.cid);
        self
    }

    fn sealed(mut self) -> IndexedArtifactDescriptor {
        self.metadata.chunk_sealed = true;
        self
    }

    fn complete(mut self) -> IndexedArtifactDescriptor {
        self.metadata.stream_complete = true;
        self
    }
}

fn plan_from_descriptors(
    descriptors: &[IndexedArtifactDescriptor],
    request: &IndexedArtifactStreamPlanRequest,
) -> Result<IndexedArtifactStreamPlan, IndexedArtifactStreamPlanError> {
    IndexedArtifactStreamPlan::plan(&catalogs_for_descriptors(descriptors), request)
}

fn default_partition_policy(
    dataset_kind: IndexedDatasetKind,
    range_kind: IndexedArtifactRangeKind,
) -> IndexedArtifactStreamPartitionPolicy {
    if dataset_kind == IndexedDatasetKind::WalletScan
        && range_kind == IndexedArtifactRangeKind::Block
    {
        IndexedArtifactStreamPartitionPolicy::Ignore
    } else {
        IndexedArtifactStreamPartitionPolicy::Unpartitioned
    }
}

fn catalogs_for_descriptors(
    descriptors: &[IndexedArtifactDescriptor],
) -> Vec<IndexedArtifactStreamCatalog> {
    let mut by_generation: BTreeMap<Option<u64>, Vec<IndexedArtifactDescriptor>> = BTreeMap::new();
    for descriptor in descriptors {
        by_generation
            .entry(descriptor.metadata.catalog_generation)
            .or_default()
            .push(descriptor.clone());
    }

    by_generation
        .into_iter()
        .map(|(generation, chunks)| catalog_for_descriptors(generation, chunks))
        .collect()
}

fn catalog_for_descriptors(
    generation: Option<u64>,
    chunks: Vec<IndexedArtifactDescriptor>,
) -> IndexedArtifactStreamCatalog {
    let first = chunks.first().expect("test catalog has chunks");
    let range_start = chunks
        .iter()
        .map(|chunk| chunk.range.start)
        .min()
        .expect("catalog range start");
    let range_end = chunks
        .iter()
        .map(|chunk| chunk.range.end)
        .max()
        .expect("catalog range end");
    let row_count = chunks
        .iter()
        .map(|chunk| chunk.row_count)
        .fold(0_u64, u64::saturating_add);
    let mut descriptor = first.clone();
    descriptor.range.start = range_start;
    descriptor.range.end = range_end;
    descriptor.row_count = row_count;
    descriptor.cid = format!(
        "bafy-catalog-{}-{range_start}-{range_end}",
        generation.unwrap_or(0)
    );
    descriptor.metadata.catalog_generation = generation;
    IndexedArtifactStreamCatalog::new(descriptor, chunks)
}

fn catalog_with_range(
    generation: u64,
    start: u64,
    end: u64,
    chunks: Vec<IndexedArtifactDescriptor>,
) -> IndexedArtifactStreamCatalog {
    let mut catalog = catalog_for_descriptors(Some(generation), chunks);
    catalog.descriptor.range.start = start;
    catalog.descriptor.range.end = end;
    catalog.descriptor.cid = format!("bafy-catalog-{generation}-{start}-{end}");
    catalog
}

fn empty_catalog(
    dataset_kind: IndexedDatasetKind,
    range_kind: IndexedArtifactRangeKind,
    start: u64,
    end: u64,
    generation: u64,
) -> IndexedArtifactStreamCatalog {
    let mut descriptor = descriptor(dataset_kind, scope(), range_kind, start, end);
    descriptor.row_count = 0;
    descriptor.cid = format!("bafy-empty-catalog-{generation}-{start}-{end}");
    descriptor.metadata.catalog_generation = Some(generation);
    IndexedArtifactStreamCatalog::new(descriptor, Vec::new())
}

fn required_cids(plan: &IndexedArtifactStreamPlan) -> Vec<String> {
    plan.required_current_chunks
        .iter()
        .map(|entry| entry.descriptor.cid.clone())
        .collect()
}

fn coverage_ranges(plan: &IndexedArtifactStreamPlan) -> Vec<(u64, u64)> {
    plan.required_current_coverage
        .iter()
        .map(|descriptor| (descriptor.range.start, descriptor.range.end))
        .collect()
}

fn optional_cids(plan: &IndexedArtifactStreamPlan) -> Vec<String> {
    plan.optional_prior_tail_retention
        .iter()
        .map(|entry| entry.descriptor.cid.clone())
        .collect()
}

fn assert_non_overlapping(entries: &[IndexedArtifactPlannedChunk]) {
    for window in entries.windows(2) {
        assert!(
            !window[0].descriptor.range.intersects(
                window[1].descriptor.range.start,
                window[1].descriptor.range.end,
            ),
            "required current chunks overlap: {:?} and {:?}",
            window[0].descriptor.range,
            window[1].descriptor.range
        );
    }
}

fn assert_non_overlapping_by_partition(entries: &[IndexedArtifactPlannedChunk]) {
    for (index, left) in entries.iter().enumerate() {
        for right in entries.iter().skip(index + 1) {
            if left.descriptor.metadata.stream_partition
                == right.descriptor.metadata.stream_partition
            {
                assert!(
                    !left
                        .descriptor
                        .range
                        .intersects(right.descriptor.range.start, right.descriptor.range.end,),
                    "same partition required current chunks overlap: {:?} and {:?}",
                    left.descriptor.range,
                    right.descriptor.range
                );
            }
        }
    }
}
