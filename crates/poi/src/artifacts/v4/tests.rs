use super::*;
use alloy::hex;
use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, KeyInit, Mac};
use multibase::Base;
use sha2::Sha256;

use super::catalog::expected_checkpoint_chunk_count;
use super::event::{
    EVENT_HEADER_FIXED_BYTES, EVENT_MAGIC, EVENT_RECORD_BYTES, encoding_discriminant,
    expected_event_artifact_size,
};
use super::limits::{
    checked_car_response_limit, require_event_artifact_size, require_manifest_size,
};
use crate::artifacts::manifest::ArtifactDescriptor;
use crate::artifacts::snapshot::SnapshotEvent;
use crate::artifacts::verify::VerifyError;
use crate::poi::{PoiEventType, SignedBlockedShield, SignedPoiEvent};

const GOLDEN_BODY_HASHES: [&str; 6] = [
    "30535cbb6ce23b841d21df5eed9efa1ef644c1cb24da46d40d63cab1dc90f59c",
    "487956c9329cd53153cb43fcfd70d2d5bbf85f3d540b208849c0a3be4eb0eec7",
    "93e6e21cf06524b7b1dad99f4d06bfbd3d01411e6ed0b987b56c8822aa4f62fc",
    "e0edb1cd85ab8b33fe5d43cc676d4b275c60736e4028240052e41bea1659485c",
    "78769462650f91068703148ba86411955aad42abce3fe88c5e58023edacbafbb",
    "503cd8d3715c34549fc0d3ecfa8bb098dbe7f44e2b71c35ed9e1e703bb3c3cdd",
];
const IPNS_TEST_ROOT_SEED: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const IPNS_TEST_CHILD_PUBLIC_KEY: [u8; 32] = [
    0x56, 0xf6, 0xdf, 0x31, 0x02, 0xdf, 0x04, 0x67, 0xda, 0x6a, 0x5a, 0xdc, 0x7e, 0xf6, 0xff, 0x57,
    0x7f, 0xab, 0xf2, 0x94, 0x4f, 0xd1, 0xbd, 0x60, 0x6f, 0x6a, 0x47, 0x46, 0x4f, 0x22, 0xab, 0xc9,
];
const IPNS_TEST_PEER_ID: &str = "12D3KooWFfqZkgZyH41hEVExsTkwAEVk9bTmHdLTP99uD1uwWo52";
const IPNS_TEST_NAME: &str = "k51qzi5uqu5dicmabkge4lkunc4bkd198u9xicp5espmw5zdzbafkez7hyh5ft";
const MANIFEST_SIGNATURE_TEST_SEED: [u8; 32] = [7; 32];
const GOLDEN_SIGNED_BODY_HASH: &str =
    "b69109db5c1b989d9ae3ade3a5b06ec9e3eefd379405a7a4e4d373f1bf2b3c48";
const GOLDEN_SIGNATURE_HASH: &str =
    "e8427b380f033519b42a40cd0a37d11d7920a7c4bda42e78f674500b618e15de";

#[test]
fn v4_ipns_derivation_vector_binds_domains_and_public_identity() {
    assert_eq!(IPNS_KDF_SALT, b"railgun-indexer/ipns-key-derivation/v1");
    assert_eq!(IPNS_KDF_INFO, b"poi-artifact/chunked-manifest/v4");

    let mut extract = Hmac::<Sha256>::new_from_slice(IPNS_KDF_SALT)
        .expect("HMAC accepts an arbitrary salt length");
    extract.update(&IPNS_TEST_ROOT_SEED);
    let pseudorandom_key = extract.finalize().into_bytes();
    let mut expand = Hmac::<Sha256>::new_from_slice(&pseudorandom_key)
        .expect("SHA-256 pseudorandom key has a valid HMAC length");
    expand.update(IPNS_KDF_INFO);
    expand.update(&[1]);
    let mut child_seed: [u8; 32] = expand.finalize().into_bytes().into();
    let keypair = libp2p_identity::Keypair::ed25519_from_bytes(&mut child_seed)
        .expect("vector child seed is a valid ed25519 seed");
    child_seed.fill(0);
    let public_key = keypair
        .public()
        .try_into_ed25519()
        .expect("vector key is ed25519")
        .to_bytes();
    let peer_id = keypair.public().to_peer_id();
    let ipns_name = cid::Cid::new_v1(0x72, *peer_id.as_ref())
        .to_string_of_base(Base::Base36Lower)
        .expect("peer ID is a valid libp2p-key CID");

    assert_eq!(public_key, IPNS_TEST_CHILD_PUBLIC_KEY);
    assert_eq!(peer_id.to_base58(), IPNS_TEST_PEER_ID);
    assert_eq!(ipns_name, IPNS_TEST_NAME);
}

#[test]
fn event_artifact_roundtrip_has_deterministic_timestamp_free_bytes() {
    let artifact = EventArtifact::new(
        scope(),
        EventArtifactKind::Checkpoint,
        None,
        root(1),
        vec![event(0, 1)],
    )
    .expect("event artifact");
    let bytes = artifact.to_bytes().expect("event bytes");
    let decoded = EventArtifact::read(&bytes).expect("decode event bytes");
    let descriptor = artifact.descriptor("bafyevent").expect("descriptor");

    assert_eq!(decoded, artifact);
    assert_eq!(
        descriptor.verify_bytes(&bytes).expect("verify bytes"),
        artifact
    );
    let mut wrong_size = descriptor;
    wrong_size.artifact.byte_size -= 1;
    assert!(matches!(
        wrong_size.validate(),
        Err(Error::EventDescriptorByteSizeMismatch { .. })
    ));
    assert_eq!(&bytes[0..8], EVENT_MAGIC);
    assert_eq!(
        bytes.len(),
        EVENT_HEADER_FIXED_BYTES + 17 + EVENT_RECORD_BYTES
    );
    assert!(!bytes.windows(9).any(|window| window == b"timestamp"));
}

#[test]
fn event_semantic_verification_rejects_invalid_list_signature() {
    let signing_key = SigningKey::from_bytes(&[0x31; 32]);
    let scope = Scope::new(
        FixedBytes::from(signing_key.verifying_key().to_bytes()),
        0,
        1,
        "V2_PoseidonMerkle",
    );
    let artifact = EventArtifact::new(
        scope,
        EventArtifactKind::Checkpoint,
        None,
        root(2),
        vec![
            signed_event(&signing_key, 0, 0x32),
            signed_event(&signing_key, 1, 0x33),
        ],
    )
    .expect("event artifact");
    artifact.verify_signatures().expect("valid event signature");

    let mut invalid = artifact;
    invalid.events[1].event_type = PoiEventType::Transact;
    invalid.events[1].signature = [0_u8; 64];
    match invalid
        .verify_signatures()
        .expect_err("invalid event signature")
    {
        Error::EventVerify {
            event_index,
            source,
        } => {
            assert_eq!(event_index, 1);
            assert!(matches!(source, VerifyError::Signature(_)));
        }
        other => panic!("unexpected verification error: {other:?}"),
    }
}

#[test]
fn event_semantic_verification_accepts_historical_unsigned_shield() {
    let signing_key = SigningKey::from_bytes(&[0x31; 32]);
    let scope = Scope::new(
        FixedBytes::from(signing_key.verifying_key().to_bytes()),
        0,
        1,
        "V2_PoseidonMerkle",
    );
    let mut event = signed_event(&signing_key, 0, 0x32);
    event.signature = [0; 64];
    let artifact = EventArtifact::new(
        scope,
        EventArtifactKind::Checkpoint,
        None,
        root(2),
        vec![event],
    )
    .expect("event artifact");

    artifact
        .verify_signatures()
        .expect("historical unsigned Shield event");
}

#[test]
fn blocked_artifact_verification_binds_scope_count_and_signatures() {
    let signing_key = SigningKey::from_bytes(&[0x41; 32]);
    let scope = Scope::new(
        FixedBytes::from(signing_key.verifying_key().to_bytes()),
        0,
        1,
        "V2_PoseidonMerkle",
    );
    let record = signed_blocked_shield(&signing_key, 0x42);
    let artifact =
        BlockedShieldsArtifact::from_signed_records(scope.clone(), std::slice::from_ref(&record));
    let bytes = artifact.to_bytes().expect("blocked bytes");
    let descriptor = BlockedShieldsDescriptor {
        artifact: ArtifactDescriptor::from_bytes("bafyblocked", &bytes),
        format_version: FORMAT_VERSION,
        scope: scope.clone(),
        row_count: 1,
        encoding: ArtifactEncoding::CanonicalJson,
        compression: Compression::Identity,
    };
    descriptor
        .verify_bytes(&bytes)
        .expect("valid blocked artifact");

    let mut wrong_count = descriptor.clone();
    wrong_count.row_count = 2;
    assert!(matches!(
        wrong_count.verify_bytes(&bytes),
        Err(Error::DescriptorBodyMismatch)
    ));
    let mut wrong_scope = descriptor.clone();
    wrong_scope.scope.txid_version.push_str("-other");
    assert!(matches!(
        wrong_scope.verify_bytes(&bytes),
        Err(Error::DescriptorBodyMismatch)
    ));

    let mut invalid_record = record;
    invalid_record.signature = "00".repeat(64);
    let invalid_artifact = BlockedShieldsArtifact::from_signed_records(scope, &[invalid_record]);
    let invalid_bytes = invalid_artifact.to_bytes().expect("invalid blocked bytes");
    let invalid_descriptor = BlockedShieldsDescriptor {
        artifact: ArtifactDescriptor::from_bytes("bafyinvalidblocked", &invalid_bytes),
        ..descriptor
    };
    assert!(matches!(
        invalid_descriptor.verify_bytes(&invalid_bytes),
        Err(Error::Verify(_))
    ));
}

#[test]
fn blocked_artifact_byte_limit_is_shared_by_descriptor_writer_and_reader() {
    let mut descriptor = BlockedShieldsDescriptor {
        artifact: fake_artifact("bafyblocked", BLOCKED_SHIELDS_ARTIFACT_MAX_BYTES, 0x42),
        format_version: FORMAT_VERSION,
        scope: scope(),
        row_count: 0,
        encoding: ArtifactEncoding::CanonicalJson,
        compression: Compression::Identity,
    };
    descriptor
        .validate()
        .expect("exact blocked artifact byte limit");
    descriptor.artifact.byte_size += 1;
    assert!(matches!(
        descriptor.validate(),
        Err(Error::BlockedShieldsArtifactByteLimitExceeded { byte_size })
            if byte_size == BLOCKED_SHIELDS_ARTIFACT_MAX_BYTES + 1
    ));

    let oversized_bytes = vec![
        b' ';
        usize::try_from(BLOCKED_SHIELDS_ARTIFACT_MAX_BYTES + 1)
            .expect("blocked artifact limit fits usize")
    ];
    assert!(matches!(
        BlockedShieldsArtifact::read(&oversized_bytes),
        Err(Error::BlockedShieldsArtifactByteLimitExceeded { .. })
    ));

    let oversized_record = SignedBlockedShield {
        commitment_hash: "00".repeat(32),
        blinded_commitment: "11".repeat(32),
        signature: "22".repeat(64),
        block_reason: Some(
            "x".repeat(
                usize::try_from(BLOCKED_SHIELDS_ARTIFACT_MAX_BYTES)
                    .expect("blocked artifact limit fits usize"),
            ),
        ),
    };
    let oversized_artifact =
        BlockedShieldsArtifact::from_signed_records(scope(), &[oversized_record]);
    assert!(matches!(
        oversized_artifact.to_bytes(),
        Err(Error::BlockedShieldsArtifactByteLimitExceeded { .. })
    ));
}

#[test]
fn event_artifact_rejects_malformed_unsupported_and_oversized_bytes() {
    let artifact = EventArtifact::new(
        scope(),
        EventArtifactKind::Checkpoint,
        None,
        root(1),
        vec![event(0, 1)],
    )
    .expect("event artifact");
    let mut bytes = artifact.to_bytes().expect("event bytes");

    bytes.push(0);
    assert!(matches!(
        EventArtifact::read(&bytes),
        Err(Error::EventByteLengthMismatch { .. })
    ));
    bytes.pop();
    bytes[14] = u8::MAX;
    assert!(matches!(
        EventArtifact::read(&bytes),
        Err(Error::UnsupportedEncoding)
    ));
    bytes[14] = encoding_discriminant(ArtifactEncoding::PoiEventBinary);
    bytes[15] = u8::MAX;
    assert!(matches!(
        EventArtifact::read(&bytes),
        Err(Error::UnsupportedCompression)
    ));
    require_event_artifact_size(EVENT_ARTIFACT_MAX_BYTES).expect("exact event byte limit");
    assert!(matches!(
        EventArtifact::read(&vec![0; 4 * 1024 * 1024 + 1]),
        Err(Error::EventArtifactByteLimitExceeded { .. })
    ));
}

#[test]
fn checkpoint_catalog_rejects_gap_overlap_root_mismatch_and_nonfinal_partial() {
    let first = chunk(0, CHECKPOINT_EVENT_SPAN, None, root(1), 1);
    let second = chunk(CHECKPOINT_EVENT_SPAN, 2, Some(root(1)), root(2), 2);
    CheckpointCatalog::new(scope(), vec![first.clone(), second.clone()]).expect("valid catalog");

    let gap = chunk(CHECKPOINT_EVENT_SPAN * 2, 2, Some(root(1)), root(2), 2);
    assert!(matches!(
        CheckpointCatalog::new(scope(), vec![first.clone(), gap]),
        Err(Error::RangeGapOrOverlap)
    ));

    let overlap = chunk(0, CHECKPOINT_EVENT_SPAN, None, root(2), 2);
    assert!(matches!(
        CheckpointCatalog::new(scope(), vec![first.clone(), overlap]),
        Err(Error::RangeGapOrOverlap)
    ));

    let mut wrong_root = second.clone();
    wrong_root.start_root = Some(root(9));
    assert!(matches!(
        CheckpointCatalog::new(scope(), vec![first.clone(), wrong_root]),
        Err(Error::RangeGapOrOverlap)
    ));

    let mut wrong_scope = second;
    wrong_scope.scope.chain_id += 1;
    assert!(matches!(
        CheckpointCatalog::new(scope(), vec![first, wrong_scope]),
        Err(Error::ScopeMismatch)
    ));

    let partial = chunk(0, 2, None, root(1), 1);
    let after_partial = chunk(2, 2, Some(root(1)), root(2), 2);
    assert!(matches!(
        CheckpointCatalog::new(scope(), vec![partial, after_partial]),
        Err(Error::PartialCheckpointNotFinal)
    ));
}

#[test]
fn checkpoint_catalog_requires_empty_chunks_and_aggregate_together() {
    let nonempty_aggregate = CheckpointCatalog {
        format_version: FORMAT_VERSION,
        scope: scope(),
        range: Some(EventRange {
            start_index: 0,
            end_index: 1,
        }),
        row_count: 2,
        checkpoint_root: Some(root(1)),
        chunks: vec![],
    };
    assert!(matches!(
        nonempty_aggregate.validate(),
        Err(Error::InvalidCheckpointAggregate)
    ));

    let zero_aggregate_with_chunk = CheckpointCatalog {
        format_version: FORMAT_VERSION,
        scope: scope(),
        range: None,
        row_count: 0,
        checkpoint_root: None,
        chunks: vec![chunk(0, 2, None, root(1), 1)],
    };
    assert!(matches!(
        zero_aggregate_with_chunk.validate(),
        Err(Error::InvalidCheckpointAggregate)
    ));
}

#[test]
fn checkpoint_catalog_descriptor_requires_exact_chunk_count() {
    let empty_catalog = CheckpointCatalog::new(scope(), vec![]).expect("empty catalog");
    let mut empty_descriptor = empty_catalog
        .descriptor("bafyemptycatalog")
        .expect("empty descriptor");
    empty_descriptor.chunk_count = 1;
    assert!(matches!(
        empty_descriptor.validate(),
        Err(Error::CheckpointChunkCountMismatch {
            expected: 0,
            actual: 1
        })
    ));

    let catalog = CheckpointCatalog::new(
        scope(),
        vec![
            chunk(0, CHECKPOINT_EVENT_SPAN, None, root(1), 1),
            chunk(CHECKPOINT_EVENT_SPAN, 2, Some(root(1)), root(2), 2),
        ],
    )
    .expect("two-chunk catalog");
    let mut descriptor = catalog.descriptor("bafycatalog").expect("descriptor");
    descriptor.chunk_count = 1;
    assert!(matches!(
        descriptor.validate(),
        Err(Error::CheckpointChunkCountMismatch {
            expected: 2,
            actual: 1
        })
    ));
}

#[test]
fn catalog_decode_requires_canonical_bytes_and_exact_descriptor_binding() {
    let catalog =
        CheckpointCatalog::new(scope(), vec![chunk(0, 2, None, root(1), 1)]).expect("catalog");
    let bytes = catalog.to_bytes().expect("catalog bytes");
    let descriptor = catalog.descriptor("bafycatalog").expect("descriptor");
    assert_eq!(descriptor.verify_bytes(&bytes).expect("verify"), catalog);

    let mut whitespace = vec![b' '];
    whitespace.extend_from_slice(&bytes);
    assert!(matches!(
        CheckpointCatalog::read(&whitespace),
        Err(Error::NonCanonicalBytes)
    ));

    let mut mutated = descriptor;
    mutated.row_count += 1;
    assert!(matches!(
        mutated.verify_bytes(&bytes),
        Err(Error::InvalidCheckpointAggregate | Error::DescriptorBodyMismatch)
    ));

    let unsupported = String::from_utf8(bytes)
        .expect("JSON")
        .replace("\"poi_event_binary\"", "\"future_encoding\"");
    assert!(matches!(
        CheckpointCatalog::read(unsupported.as_bytes()),
        Err(Error::Json(_))
    ));
    let bytes = catalog.to_bytes().expect("catalog bytes");
    let unsupported = String::from_utf8(bytes).expect("JSON").replacen(
        "\"identity\"",
        "\"future_compression\"",
        1,
    );
    assert!(matches!(
        CheckpointCatalog::read(unsupported.as_bytes()),
        Err(Error::Json(_))
    ));
}

#[test]
fn manifest_signature_is_domain_separated_and_descriptor_bound() {
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let mut manifest = publication_graph(GraphKind::Partial).0;
    manifest.sign_manifest(&signing_key).expect("sign");
    manifest.verify_signature().expect("verify");

    let mut wrong_domain = manifest.clone();
    wrong_domain.publisher_signature = Some(FixedBytes::from(
        signing_key
            .sign(&wrong_domain.canonical_body_bytes().expect("body"))
            .to_bytes(),
    ));
    assert!(matches!(
        wrong_domain.verify_signature(),
        Err(Error::Signature(_))
    ));

    let mut mutated = manifest;
    mutated.entries[0]
        .checkpoint_catalog
        .artifact
        .cid
        .push_str("-mutated");
    assert!(matches!(
        mutated.verify_signature(),
        Err(Error::Signature(_))
    ));
}

#[test]
fn canonical_manifest_signature_matches_golden_vector() {
    let signing_key = SigningKey::from_bytes(&MANIFEST_SIGNATURE_TEST_SEED);
    let mut manifest = publication_graph(GraphKind::Partial).0;
    manifest.sign_manifest(&signing_key).expect("sign manifest");

    assert_eq!(MANIFEST_SIGNATURE_DOMAIN, b"railgun-poi-manifest-v4\0");
    let body = manifest.canonical_body_bytes().expect("canonical body");
    assert_eq!(
        hex::encode(super::super::manifest::content_hash(&body)),
        GOLDEN_SIGNED_BODY_HASH
    );
    let signature = manifest
        .publisher_signature
        .as_ref()
        .expect("publisher signature");
    assert_eq!(
        hex::encode(super::super::manifest::content_hash(signature.as_slice())),
        GOLDEN_SIGNATURE_HASH
    );
    manifest
        .verify_trusted_signature(&signing_key.verifying_key().to_bytes())
        .expect("golden signature verifies");
}

#[test]
fn manifest_rejects_wrong_format_duplicate_scope_and_noncanonical_bytes() {
    let mut wrong_format = publication_graph(GraphKind::Zero).0;
    wrong_format.format_version = 3;
    assert!(matches!(
        wrong_format.validate(),
        Err(Error::WrongFormat { version: 3 })
    ));

    let mut duplicate = publication_graph(GraphKind::Partial).0;
    duplicate.entries.push(duplicate.entries[0].clone());
    assert!(matches!(duplicate.validate(), Err(Error::DuplicateScope)));

    let manifest = publication_graph(GraphKind::Zero).0;
    let bytes = manifest.to_bytes().expect("manifest bytes");
    let mut whitespace = bytes.clone();
    whitespace.push(b'\n');
    assert!(matches!(
        Manifest::read(&whitespace),
        Err(Error::NonCanonicalBytes)
    ));
    let unknown = String::from_utf8(bytes)
        .expect("JSON")
        .replacen('{', "{\"unknown\":true,", 1);
    assert!(matches!(
        Manifest::read(unknown.as_bytes()),
        Err(Error::Json(_))
    ));
}

#[test]
fn manifest_size_limit_is_shared_by_producer_and_consumer_paths() {
    require_manifest_size(MANIFEST_MAX_BYTES).expect("exact manifest byte limit");
    assert!(matches!(
        require_manifest_size(MANIFEST_MAX_BYTES + 1),
        Err(Error::ManifestByteLimitExceeded { .. })
    ));

    let mut body_boundary = publication_graph(GraphKind::Zero).0;
    let base_body_size = usize_to_u64(
        body_boundary
            .canonical_body_bytes()
            .expect("base body")
            .len(),
    )
    .expect("base body size");
    body_boundary.entries[0]
        .blocked_shields
        .artifact
        .cid
        .push_str(&"v".repeat(
            usize::try_from(MANIFEST_MAX_BYTES - base_body_size).expect("body padding fits usize"),
        ));
    assert_eq!(
        usize_to_u64(
            body_boundary
                .canonical_body_bytes()
                .expect("exact-limit body")
                .len()
        )
        .expect("exact body size"),
        MANIFEST_MAX_BYTES
    );
    body_boundary.entries[0]
        .blocked_shields
        .artifact
        .cid
        .push('v');

    assert!(matches!(
        body_boundary.canonical_body_bytes(),
        Err(Error::ManifestByteLimitExceeded { .. })
    ));
    assert!(matches!(
        body_boundary.to_bytes(),
        Err(Error::ManifestByteLimitExceeded { .. })
    ));
    assert!(matches!(
        body_boundary.sign_manifest(&SigningKey::from_bytes(&[7; 32])),
        Err(Error::ManifestByteLimitExceeded { .. })
    ));
    body_boundary.publisher_signature = Some(FixedBytes::ZERO);
    assert!(matches!(
        body_boundary.verify_signature(),
        Err(Error::ManifestByteLimitExceeded { .. })
    ));

    let mut full_boundary = publication_graph(GraphKind::Zero).0;
    full_boundary.publisher_signature = Some(FixedBytes::ZERO);
    let base_full_size = usize_to_u64(full_boundary.to_bytes().expect("base manifest").len())
        .expect("base manifest size");
    full_boundary.entries[0]
        .blocked_shields
        .artifact
        .cid
        .push_str(
            &"v".repeat(
                usize::try_from(MANIFEST_MAX_BYTES - base_full_size)
                    .expect("manifest padding fits usize"),
            ),
        );
    let exact_limit_bytes = full_boundary.to_bytes().expect("exact-limit manifest");
    assert_eq!(
        usize_to_u64(exact_limit_bytes.len()).expect("exact manifest size"),
        MANIFEST_MAX_BYTES
    );
    assert_eq!(
        Manifest::read(&exact_limit_bytes).expect("read exact-limit manifest"),
        full_boundary
    );

    full_boundary.entries[0]
        .blocked_shields
        .artifact
        .cid
        .push('v');
    assert!(matches!(
        full_boundary.to_bytes(),
        Err(Error::ManifestByteLimitExceeded { .. })
    ));
    let oversized_wire = serde_json::to_vec(&full_boundary).expect("oversized fixture bytes");
    assert_eq!(
        usize_to_u64(oversized_wire.len()).expect("oversized manifest size"),
        MANIFEST_MAX_BYTES + 1
    );
    assert!(matches!(
        Manifest::read(&oversized_wire),
        Err(Error::ManifestByteLimitExceeded { .. })
    ));
}

#[test]
fn entry_validation_covers_zero_tail_bridge_and_root_rules() {
    for kind in [
        GraphKind::Zero,
        GraphKind::Partial,
        GraphKind::OneChunk,
        GraphKind::MultiChunk,
        GraphKind::EmptyCheckpointTail,
        GraphKind::RetainedBridges,
    ] {
        publication_graph(kind).0.validate().expect("valid graph");
    }

    let mut missing_tail = publication_graph(GraphKind::EmptyCheckpointTail).0;
    missing_tail.entries[0].current_tail = None;
    assert!(matches!(
        missing_tail.validate(),
        Err(Error::InvalidCurrentTail)
    ));

    let mut root_mismatch = publication_graph(GraphKind::RetainedBridges).0;
    root_mismatch.entries[0].retained_bridges[1].start_root = Some(root(99));
    assert!(matches!(
        root_mismatch.validate(),
        Err(Error::RangeGapOrOverlap)
    ));

    let mut too_many = publication_graph(GraphKind::RetainedBridges).0;
    too_many.entries[0].retained_bridges = vec![too_many.entries[0].retained_bridges[0].clone(); 8];
    assert!(matches!(
        too_many.validate(),
        Err(Error::TooManyRetainedBridges { count: 8 })
    ));
}

#[test]
fn resource_limits_accept_boundaries_and_reject_oversize_or_overflow() {
    assert_eq!(expected_checkpoint_chunk_count(0).expect("empty"), 0);
    assert_eq!(expected_checkpoint_chunk_count(1).expect("partial"), 1);
    assert_eq!(
        expected_checkpoint_chunk_count(CHECKPOINT_EVENT_SPAN).expect("full"),
        1
    );
    assert_eq!(
        expected_checkpoint_chunk_count(CHECKPOINT_EVENT_SPAN + 1).expect("full and partial"),
        2
    );
    validate_catalog_limits(
        CATALOG_MAX_BYTES,
        CATALOG_MAX_BYTES,
        CATALOG_MAX_DESCRIPTORS,
    )
    .expect("exact catalog limits");
    assert!(matches!(
        validate_catalog_limits(
            CATALOG_MAX_BYTES + 1,
            CATALOG_MAX_BYTES,
            CATALOG_MAX_DESCRIPTORS,
        ),
        Err(Error::CatalogByteLimitExceeded { .. })
    ));
    assert!(matches!(
        validate_catalog_limits(0, 0, CATALOG_MAX_DESCRIPTORS + 1),
        Err(Error::CatalogDescriptorLimitExceeded { .. })
    ));
    assert!(matches!(
        EventRange::new(0, u64::MAX),
        Err(Error::InvalidRange { .. })
    ));
    assert!(matches!(
        checked_car_response_limit(u64::MAX),
        Err(Error::ArithmeticOverflow)
    ));

    let descriptors = publication_graph(GraphKind::MultiChunk)
        .1
        .into_iter()
        .flat_map(|catalog| catalog.chunks)
        .collect::<Vec<_>>();
    let limits = checked_event_plan_limits(&descriptors).expect("checked plan limits");
    assert_eq!(limits.descriptor_count, 2);
    assert_eq!(limits.record_count, CHECKPOINT_EVENT_SPAN + 2);
    RetrievalLimits::for_event(&descriptors[0])
        .expect("event limits")
        .checked_usize()
        .expect("usize limits");
}

#[test]
fn six_publication_graphs_match_producer_consumer_golden_hashes() {
    let kinds = [
        GraphKind::Zero,
        GraphKind::Partial,
        GraphKind::OneChunk,
        GraphKind::MultiChunk,
        GraphKind::EmptyCheckpointTail,
        GraphKind::RetainedBridges,
    ];
    for (index, kind) in kinds.into_iter().enumerate() {
        let (manifest, catalogs) = publication_graph(kind);
        let body = manifest.canonical_body_bytes().expect("producer body");
        assert_eq!(
            hex::encode(super::super::manifest::content_hash(&body)),
            GOLDEN_BODY_HASHES[index]
        );

        let manifest_bytes = manifest.to_bytes().expect("producer manifest");
        let consumed = Manifest::read(&manifest_bytes).expect("consumer manifest");
        assert_eq!(
            consumed.canonical_body_bytes().expect("consumer body"),
            body
        );
        for catalog in catalogs {
            let catalog_bytes = catalog.to_bytes().expect("producer catalog");
            let descriptor = catalog
                .descriptor("bafygolden")
                .expect("catalog descriptor");
            assert_eq!(
                descriptor
                    .verify_bytes(&catalog_bytes)
                    .expect("consumer catalog"),
                catalog
            );
        }
    }
}

#[derive(Clone, Copy)]
enum GraphKind {
    Zero,
    Partial,
    OneChunk,
    MultiChunk,
    EmptyCheckpointTail,
    RetainedBridges,
}

fn publication_graph(kind: GraphKind) -> (Manifest, Vec<CheckpointCatalog>) {
    let scope = scope();
    let (catalog, event_count, current_root, current_tail, retained_bridges) = match kind {
        GraphKind::Zero => (
            CheckpointCatalog::new(scope.clone(), vec![]).expect("empty catalog"),
            0,
            None,
            None,
            vec![],
        ),
        GraphKind::Partial => (
            CheckpointCatalog::new(scope.clone(), vec![chunk(0, 3, None, root(3), 1)])
                .expect("partial catalog"),
            3,
            Some(root(3)),
            None,
            vec![],
        ),
        GraphKind::OneChunk => (
            CheckpointCatalog::new(
                scope.clone(),
                vec![chunk(0, CHECKPOINT_EVENT_SPAN, None, root(1), 1)],
            )
            .expect("one chunk catalog"),
            CHECKPOINT_EVENT_SPAN,
            Some(root(1)),
            None,
            vec![],
        ),
        GraphKind::MultiChunk => (
            CheckpointCatalog::new(
                scope.clone(),
                vec![
                    chunk(0, CHECKPOINT_EVENT_SPAN, None, root(1), 1),
                    chunk(CHECKPOINT_EVENT_SPAN, 2, Some(root(1)), root(2), 2),
                ],
            )
            .expect("multi chunk catalog"),
            CHECKPOINT_EVENT_SPAN + 2,
            Some(root(2)),
            None,
            vec![],
        ),
        GraphKind::EmptyCheckpointTail => (
            CheckpointCatalog::new(scope.clone(), vec![]).expect("empty catalog"),
            3,
            Some(root(3)),
            Some(event_descriptor(
                EventArtifactKind::CurrentTail,
                0,
                3,
                None,
                root(3),
                3,
            )),
            vec![],
        ),
        GraphKind::RetainedBridges => (
            CheckpointCatalog::new(scope.clone(), vec![chunk(0, 10, None, root(10), 1)])
                .expect("bridge catalog"),
            12,
            Some(root(12)),
            Some(event_descriptor(
                EventArtifactKind::CurrentTail,
                10,
                2,
                Some(root(10)),
                root(12),
                4,
            )),
            vec![
                event_descriptor(EventArtifactKind::Bridge, 4, 3, Some(root(4)), root(7), 2),
                event_descriptor(EventArtifactKind::Bridge, 7, 3, Some(root(7)), root(10), 3),
            ],
        ),
    };
    let catalog_descriptor = catalog
        .descriptor("bafycatalog")
        .expect("catalog descriptor");
    let entry = ManifestEntry {
        scope: scope.clone(),
        event_count,
        current_tip_index: event_count.checked_sub(1),
        current_root,
        checkpoint_catalog: catalog_descriptor,
        current_tail,
        retained_bridges,
        blocked_shields: BlockedShieldsDescriptor {
            artifact: fake_artifact("bafyblocked", 64, 90),
            format_version: FORMAT_VERSION,
            scope,
            row_count: 0,
            encoding: ArtifactEncoding::CanonicalJson,
            compression: Compression::Identity,
        },
    };
    (
        Manifest::new(
            1_700_000_000_000,
            42,
            FixedBytes::from([9; 32]),
            vec![entry],
        ),
        vec![catalog],
    )
}

fn scope() -> Scope {
    Scope::new(FixedBytes::from([1; 32]), 0, 1, "V3_PoseidonMerkle")
}

fn chunk(
    start_index: u64,
    row_count: u64,
    start_root: Option<FixedBytes<32>>,
    end_root: FixedBytes<32>,
    marker: u8,
) -> EventArtifactDescriptor {
    event_descriptor(
        EventArtifactKind::Checkpoint,
        start_index,
        row_count,
        start_root,
        end_root,
        marker,
    )
}

fn event_descriptor(
    kind: EventArtifactKind,
    start_index: u64,
    row_count: u64,
    start_root: Option<FixedBytes<32>>,
    end_root: FixedBytes<32>,
    marker: u8,
) -> EventArtifactDescriptor {
    let end_index = start_index
        .checked_add(row_count - 1)
        .expect("fixture range");
    EventArtifactDescriptor {
        artifact: fake_artifact(
            &format!("bafyevent{marker}"),
            expected_event_artifact_size(&scope(), row_count).expect("fixture size"),
            marker,
        ),
        format_version: FORMAT_VERSION,
        scope: scope(),
        kind,
        range: EventRange {
            start_index,
            end_index,
        },
        row_count,
        encoding: ArtifactEncoding::PoiEventBinary,
        compression: Compression::Identity,
        start_root,
        end_root,
    }
}

fn fake_artifact(cid: &str, byte_size: u64, marker: u8) -> ArtifactDescriptor {
    ArtifactDescriptor {
        cid: cid.to_string(),
        sha256: FixedBytes::from([marker; 32]),
        byte_size,
    }
}

fn root(marker: u8) -> FixedBytes<32> {
    FixedBytes::from([marker; 32])
}

fn event(event_index: u64, marker: u8) -> SnapshotEvent {
    SnapshotEvent {
        event_index,
        blinded_commitment: [marker; 32],
        signature: [marker + 1; 64],
        event_type: PoiEventType::Shield,
    }
}

fn signed_event(signing_key: &SigningKey, event_index: u64, marker: u8) -> SnapshotEvent {
    let mut event = SignedPoiEvent {
        index: event_index,
        blinded_commitment: FixedBytes::from([marker; 32]),
        signature: String::new(),
        event_type: PoiEventType::Shield,
    };
    let signature = signing_key
        .sign(&super::super::verify::canonical_poi_event_message(&event))
        .to_bytes();
    event.signature = hex::encode_prefixed(signature);
    SnapshotEvent {
        event_index,
        blinded_commitment: event.blinded_commitment.0,
        signature,
        event_type: event.event_type,
    }
}

fn signed_blocked_shield(signing_key: &SigningKey, marker: u8) -> SignedBlockedShield {
    let mut record = SignedBlockedShield {
        commitment_hash: hex::encode_prefixed([marker + 1; 32]),
        blinded_commitment: hex::encode_prefixed([marker; 32]),
        block_reason: Some("blocked".to_string()),
        signature: String::new(),
    };
    record.signature = hex::encode_prefixed(
        signing_key
            .sign(&super::super::verify::canonical_blocked_shield_message(
                &record,
            ))
            .to_bytes(),
    );
    record
}
