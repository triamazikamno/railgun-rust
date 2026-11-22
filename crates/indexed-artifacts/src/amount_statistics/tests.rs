use super::*;
use crate::ChainType;

#[test]
fn snapshot_round_trips() {
    let snapshot = sample_snapshot();

    let encoded = encode_amount_statistics_snapshot(&snapshot).expect("encode snapshot");

    assert_eq!(
        decode_amount_statistics_snapshot(&encoded.bytes).expect("decode snapshot"),
        snapshot
    );
}

#[test]
fn encoding_is_byte_identical_whatever_the_input_order() {
    let snapshot = sample_snapshot();
    let reordered = reversed(snapshot.clone());
    assert_ne!(reordered, snapshot);

    let expected = encode_amount_statistics_snapshot(&snapshot).expect("encode snapshot");

    assert_eq!(
        encode_amount_statistics_snapshot(&snapshot).expect("encode again"),
        expected
    );
    assert_eq!(
        encode_amount_statistics_snapshot(&reordered).expect("encode reordered"),
        expected
    );
}

#[test]
fn value_bucket_is_bit_length() {
    assert_eq!(amount_value_bucket(U256::ZERO), 0);
    assert_eq!(amount_value_bucket(U256::from(1_u64)), 1);
    assert_eq!(amount_value_bucket(U256::from(997_500_000_u64)), 30);
    assert_eq!(amount_value_bucket(U256::MAX), 256);
}

#[test]
fn decode_rejects_unknown_encoding_version() {
    let bytes = compress_bytes(
        br#"{"encoding_version":2,"tokens":"a future layout"}"#,
        CompressionAlgorithm::Zstd,
    )
    .expect("compress");

    assert!(matches!(
        decode_amount_statistics_snapshot(&bytes),
        Err(AmountStatisticsError::UnsupportedEncodingVersion(2))
    ));
}

#[test]
fn decode_stops_at_decoded_limit() {
    let oversized = vec![0_u8; 2 * AMOUNT_STATISTICS_MAX_DECODED_BYTES as usize];
    let bytes = compress_bytes(&oversized, CompressionAlgorithm::Zstd).expect("compress");
    assert!(bytes.len() as u64 <= AMOUNT_STATISTICS_MAX_COMPRESSED_BYTES);

    let error = decode_amount_statistics_snapshot(&bytes).expect_err("decoded size over limit");

    assert!(matches!(
        error,
        AmountStatisticsError::DecodedTooLarge { actual, maximum }
            if actual == AMOUNT_STATISTICS_MAX_DECODED_BYTES + 1
                && maximum == AMOUNT_STATISTICS_MAX_DECODED_BYTES
    ));
}

#[test]
fn signing_fixture_manifest_reproduces_fixture() {
    let signed =
        AmountStatisticsManifestEnvelope::sign(&fixture_manifest(), &fixture_signing_key())
            .expect("sign manifest");

    assert_eq!(
        signed,
        fixture_envelope(),
        "regenerated fixture:\n{}",
        serde_json::to_string_pretty(&signed).expect("encode envelope")
    );
}

#[test]
fn fixture_verifies_as_committed_and_reencoded_around_its_unchanged_body() {
    let envelope = fixture_envelope();
    let reencoded = format!(
        "{{ \"signature\" : {},\n\t\"publisher\": {} , \"body\":{} }}",
        serde_json::to_string(&envelope.signature).expect("encode signature"),
        serde_json::to_string_pretty(&envelope.publisher).expect("encode publisher"),
        serde_json::to_string(&envelope.body).expect("encode body"),
    );

    let committed = envelope
        .verify_trusted(&fixture_publisher_key())
        .expect("committed fixture verifies");
    let reencoded = AmountStatisticsManifestEnvelope::from_json_slice(reencoded.as_bytes())
        .expect("parse envelope")
        .verify_trusted(&fixture_publisher_key())
        .expect("re-encoded envelope verifies");

    assert_eq!(committed, fixture_manifest());
    assert_eq!(reencoded, committed);
}

#[test]
fn altered_body_is_rejected() {
    let mut envelope = fixture_envelope();
    envelope.body = envelope
        .body
        .replacen("\"sequence\":42", "\"sequence\":43", 1);

    assert!(matches!(
        envelope.verify_trusted(&fixture_publisher_key()),
        Err(AmountStatisticsError::Signature(_))
    ));
}

#[test]
fn manifest_from_another_key_is_rejected() {
    let other_key = SigningKey::from_bytes(&[8; 32]);
    assert!(matches!(
        fixture_envelope().verify_trusted(&other_key.verifying_key().to_bytes()),
        Err(AmountStatisticsError::PublisherKeyMismatch { .. })
    ));

    let mut forged = AmountStatisticsManifestEnvelope::sign(&fixture_manifest(), &other_key)
        .expect("sign with other key");
    forged.publisher = fixture_envelope().publisher;
    assert!(matches!(
        forged.verify_trusted(&fixture_publisher_key()),
        Err(AmountStatisticsError::Signature(_))
    ));
}

#[test]
fn body_verifies_as_received_with_unknown_fields() {
    let publisher = PublisherIdentity::ed25519(FixedBytes::from(fixture_publisher_key()));
    // Re-serialising this body would reorder keys, drop whitespace and drop the
    // unknown field, so it only verifies over the bytes as received.
    let body = format!(
        r#"{{ "sequence": 7, "format_version": 1, "chains": [], "added_later": {{ "x": 1 }},
            "publisher": {}, "issued_at_ms": 5 }}"#,
        serde_json::to_string(&publisher).expect("encode publisher")
    );
    let signature = FixedBytes::from(fixture_signing_key().sign(body.as_bytes()).to_bytes());
    let envelope = AmountStatisticsManifestEnvelope {
        body,
        publisher: publisher.clone(),
        signature,
    };

    let manifest = envelope
        .verify_trusted(&fixture_publisher_key())
        .expect("body verifies as received");

    assert_eq!(
        manifest,
        AmountStatisticsManifest {
            format_version: AMOUNT_STATISTICS_MANIFEST_FORMAT_VERSION,
            issued_at_ms: 5,
            sequence: 7,
            publisher,
            chains: Vec::new(),
        }
    );
}

fn sample_snapshot() -> AmountStatisticsSnapshot {
    AmountStatisticsSnapshot {
        encoding_version: AMOUNT_STATISTICS_SNAPSHOT_ENCODING_VERSION,
        scope: ChainScope {
            chain_type: ChainType::Evm,
            chain_id: 1,
            railgun_contract: Address::from([0xbb; 20]),
        },
        covered_block: AmountStatisticsCoveredBlock {
            number: 21_000_000,
            hash: FixedBytes::from([0x11; 32]),
            timestamp: 1_699_999_988,
        },
        tokens: vec![token_statistics(0x01), token_statistics(0x02)],
    }
}

fn token_statistics(address_byte: u8) -> TokenAmountStatistics {
    TokenAmountStatistics {
        token: Address::from([address_byte; 20]),
        pool_balance: U256::from(3_800_u64),
        shields_last_24h: 1,
        shields_last_30d: 5,
        unshields_last_24h: 0,
        unshields_last_30d: 42,
        repeated_shield_amounts: vec![
            RepeatedShieldAmount {
                value: U256::from(997_500_000_u64),
                trees: vec![tree_count(0, 152, 3), tree_count(4, 35, 1)],
            },
            RepeatedShieldAmount {
                value: U256::from(1_995_000_000_u64),
                trees: vec![tree_count(0, 1, 0), tree_count(1, 1, 1)],
            },
        ],
        shield_value_buckets: vec![
            TreeShieldValueBuckets {
                tree: 0,
                buckets: vec![bucket(30, 152), bucket(31, 1)],
            },
            TreeShieldValueBuckets {
                tree: 1,
                buckets: vec![bucket(31, 1)],
            },
            TreeShieldValueBuckets {
                tree: 4,
                buckets: vec![bucket(30, 35)],
            },
        ],
        repeated_unshield_amounts: vec![
            RepeatedUnshieldAmount {
                value: U256::from(1_000_000_000_u64),
                last_30d: 40,
            },
            RepeatedUnshieldAmount {
                value: U256::from(2_000_000_000_u64),
                last_30d: 2,
            },
        ],
    }
}

const fn tree_count(tree: u32, all_time: u64, last_30d: u64) -> TreeShieldAmountCount {
    TreeShieldAmountCount {
        tree,
        all_time,
        last_30d,
    }
}

const fn bucket(bit_length: u16, count: u64) -> ShieldValueBucketCount {
    ShieldValueBucketCount { bit_length, count }
}

fn reversed(mut snapshot: AmountStatisticsSnapshot) -> AmountStatisticsSnapshot {
    snapshot.tokens.reverse();
    for token in &mut snapshot.tokens {
        token.repeated_shield_amounts.reverse();
        for amount in &mut token.repeated_shield_amounts {
            amount.trees.reverse();
        }
        token.shield_value_buckets.reverse();
        for tree in &mut token.shield_value_buckets {
            tree.buckets.reverse();
        }
        token.repeated_unshield_amounts.reverse();
    }
    snapshot
}

fn fixture_signing_key() -> SigningKey {
    SigningKey::from_bytes(&AMOUNT_STATISTICS_FIXTURE_SIGNING_KEY_SEED)
}

fn fixture_publisher_key() -> [u8; 32] {
    fixture_signing_key().verifying_key().to_bytes()
}

fn fixture_envelope() -> AmountStatisticsManifestEnvelope {
    AmountStatisticsManifestEnvelope::from_json_slice(
        AMOUNT_STATISTICS_MANIFEST_ENVELOPE_FIXTURE.as_bytes(),
    )
    .expect("parse fixture envelope")
}

fn fixture_manifest() -> AmountStatisticsManifest {
    AmountStatisticsManifest {
        format_version: AMOUNT_STATISTICS_MANIFEST_FORMAT_VERSION,
        issued_at_ms: 1_700_000_000_000,
        sequence: 42,
        publisher: PublisherIdentity::ed25519(FixedBytes::from(fixture_publisher_key())),
        chains: vec![
            AmountStatisticsChainEntry {
                scope: ChainScope {
                    chain_type: ChainType::Evm,
                    chain_id: 1,
                    railgun_contract: Address::from([0xbb; 20]),
                },
                covered_block: AmountStatisticsCoveredBlock {
                    number: 21_000_000,
                    hash: FixedBytes::from([0x11; 32]),
                    timestamp: 1_699_999_988,
                },
                snapshot: AmountStatisticsSnapshotDescriptor {
                    cid: "bafkreiethereumamountstatistics".to_owned(),
                    sha256: FixedBytes::from([0x22; 32]),
                    byte_size: 1234,
                    encoding_version: AMOUNT_STATISTICS_SNAPSHOT_ENCODING_VERSION,
                    compression: CompressionAlgorithm::Zstd,
                },
            },
            AmountStatisticsChainEntry {
                scope: ChainScope {
                    chain_type: ChainType::Evm,
                    chain_id: 137,
                    railgun_contract: Address::from([0xcc; 20]),
                },
                covered_block: AmountStatisticsCoveredBlock {
                    number: 65_000_000,
                    hash: FixedBytes::from([0x33; 32]),
                    timestamp: 1_699_999_996,
                },
                snapshot: AmountStatisticsSnapshotDescriptor {
                    cid: "bafkreipolygonamountstatistics".to_owned(),
                    sha256: FixedBytes::from([0x44; 32]),
                    byte_size: 5678,
                    encoding_version: AMOUNT_STATISTICS_SNAPSHOT_ENCODING_VERSION,
                    compression: CompressionAlgorithm::Zstd,
                },
            },
        ],
    }
}
