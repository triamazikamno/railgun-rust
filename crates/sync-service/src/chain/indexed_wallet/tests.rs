use super::*;

use std::collections::BTreeMap;

use super::super::PublicDataPlaneEpoch;
use super::coverage::{
    WalletScanArtifactCoverage, WalletScanCoverageRange, wallet_scan_artifact_target_block,
};
use super::decode::{
    WALLET_LEGACY_GENERATED_SECTION_ID, WALLET_NULLIFIER_SECTION_ID, WALLET_TRANSACT_SECTION_ID,
};
use super::session::{IndexedWalletArtifactChunk, IndexedWalletArtifactProbe};
use crate::indexed_artifacts::{
    ChainScope, ChainType, CompressionAlgorithm, DatasetDescriptorMetadata,
    INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION, INDEXED_ARTIFACT_CHUNK_MAGIC, IndexedArtifactChainEntry,
    IndexedArtifactDescriptor, IndexedArtifactManifest, IndexedArtifactRange,
    IndexedArtifactRangeKind, IndexedArtifactStreamCatalog, IndexedDatasetKind,
    LatestIndexedHeight, PublisherIdentity, VerifiedIndexedArtifactChunk,
};
use alloy::primitives::{Address, FixedBytes, FixedBytes as AlloyFixedBytes, U256, Uint};
use alloy::sol_types::SolValue;
use broadcaster_core::contracts::railgun::{
    CommitmentCiphertext, LegacyCommitmentPreimage, TokenData,
};
use broadcaster_core::crypto::railgun::ViewingKeyData;
use railgun_wallet::scan::parse_indexed_wallet_delta;
use sha2::{Digest, Sha256};

#[test]
fn indexed_wallet_artifact_probe_accepts_latest_covering_range() {
    let scope = scope();
    let manifest = manifest_with_latest_and_catalog(
        scope.clone(),
        200,
        Some(IndexedArtifactRange {
            kind: IndexedArtifactRangeKind::Block,
            start: 100,
            end: 150,
        }),
    );

    let probe = IndexedWalletArtifactProbe::from_manifest(&manifest, &scope, 120, 180)
        .expect("wallet scan artifacts available");

    assert_eq!(probe.latest_indexed_block, 200);
    assert_eq!(probe.catalog_count, 1);
}

#[test]
fn indexed_wallet_artifact_probe_accepts_latest_below_safe_head() {
    let scope = scope();
    let manifest = manifest_with_latest_and_catalog(
        scope.clone(),
        149,
        Some(IndexedArtifactRange {
            kind: IndexedArtifactRangeKind::Block,
            start: 100,
            end: 149,
        }),
    );

    let probe = IndexedWalletArtifactProbe::from_manifest(&manifest, &scope, 120, 180)
        .expect("partial wallet scan artifacts available");

    assert_eq!(probe.latest_indexed_block, 149);
    assert_eq!(probe.catalog_count, 1);
}

#[test]
fn indexed_wallet_artifact_probe_rejects_latest_without_matching_catalog() {
    let scope = scope();
    let manifest = manifest_with_latest_and_catalog(scope.clone(), 149, None);

    let probe = IndexedWalletArtifactProbe::from_manifest(&manifest, &scope, 120, 180);

    assert_eq!(probe, None);
}

#[test]
fn indexed_wallet_artifact_probe_rejects_latest_below_start() {
    let scope = scope();
    let manifest = manifest_with_latest_and_catalog(scope.clone(), 119, None);

    let probe = IndexedWalletArtifactProbe::from_manifest(&manifest, &scope, 120, 180);

    assert_eq!(probe, None);
}

#[test]
fn indexed_wallet_artifact_probe_rejects_missing_scope() {
    let manifest = manifest_with_latest_and_catalog(scope(), 200, None);
    let missing_scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 137,
        railgun_contract: Address::from([0xcc; 20]),
    };

    let probe = IndexedWalletArtifactProbe::from_manifest(&manifest, &missing_scope, 120, 180);

    assert_eq!(probe, None);
}

#[test]
fn indexed_wallet_artifact_page_decodes_rows_for_existing_scan_path() {
    let scope = scope();
    let nullifier = [0x42; 32];
    let legacy_random = std::array::from_fn(|index| index as u8);
    let chunk = wallet_scan_chunk(
        scope,
        100,
        110,
        vec![
            (
                WALLET_NULLIFIER_SECTION_ID,
                nullifier_section(105, 7, nullifier),
            ),
            (
                WALLET_LEGACY_GENERATED_SECTION_ID,
                legacy_generated_section(106, 3, 9, legacy_random),
            ),
        ],
        2,
    );

    let page = IndexedWalletPage::try_from(&chunk).expect("decode page");

    assert_eq!(page.checkpoint_block, 110);
    assert_eq!(page.nullifier_rows, 1);
    assert_eq!(page.legacy_generated_rows, 1);
    assert_eq!(page.nullifiers[0].tree_number, 7);
    assert_eq!(page.nullifiers[0].nullifier, U256::from_be_bytes(nullifier));
    assert_eq!(page.nullifiers[0].source.block_number, 105);
    assert_eq!(page.legacy_generated_commitments[0].tree_number, 3);
    assert_eq!(page.legacy_generated_commitments[0].tree_position, 9);
    assert_eq!(
        page.legacy_generated_commitments[0].encrypted_random.0,
        AlloyFixedBytes::from(<[u8; 32]>::try_from(&legacy_random[..32]).expect("first word"))
    );
    assert_eq!(
        page.legacy_generated_commitments[0].encrypted_random.1,
        AlloyFixedBytes::from(
            <[u8; 16]>::try_from(&legacy_random[48..64]).expect("second word suffix")
        )
    );

    let keys = ViewingKeyData::from_spending_public_key([1; 32], [U256::ZERO; 2]);
    let delta = parse_indexed_wallet_delta(
        &page.transact_commitments,
        &page.shield_commitments,
        &page.legacy_encrypted_commitments,
        &page.legacy_generated_commitments,
        &page.nullifiers,
        &keys,
    );

    assert_eq!(delta.nullifiers.len(), 1);
    assert_eq!(delta.nullifiers[0].tree, 7);
    assert_eq!(
        delta.nullifiers[0].nullifier,
        U256::from_be_bytes(nullifier)
    );
    assert_eq!(delta.commitment_observations.len(), 1);
    assert_eq!(delta.commitment_observations[0].tree, 3);
    assert_eq!(delta.commitment_observations[0].position, 9);
}

#[test]
fn indexed_wallet_artifact_preserves_complete_transact_ciphertext() {
    let ciphertext = CommitmentCiphertext {
        ciphertext: std::array::from_fn(|index| FixedBytes::from([index as u8 + 1; 32])),
        blindedSenderViewingKey: FixedBytes::from([0x11; 32]),
        blindedReceiverViewingKey: FixedBytes::from([0x22; 32]),
        annotationData: vec![0x33, 0x34].into(),
        memo: vec![0x44, 0x45].into(),
    };
    let chunk = wallet_scan_chunk(
        scope(),
        100,
        110,
        vec![(
            WALLET_TRANSACT_SECTION_ID,
            transact_section(105, 7, 9, U256::from(10), &ciphertext),
        )],
        1,
    );

    let page = IndexedWalletPage::try_from(&chunk).expect("decode transact page");
    let row = &page.transact_commitments[0];

    assert_eq!(row.tree_number, 7);
    assert_eq!(row.tree_position, 9);
    assert_eq!(row.hash, U256::from(10));
    assert_eq!(row.ciphertext, ciphertext.ciphertext);
    assert_eq!(
        row.blinded_sender_viewing_key,
        ciphertext.blindedSenderViewingKey
    );
    assert_eq!(
        row.blinded_receiver_viewing_key,
        ciphertext.blindedReceiverViewingKey
    );
    assert_eq!(row.annotation_data, ciphertext.annotationData);
    assert_eq!(row.memo, ciphertext.memo);
    assert_eq!(row.source.block_number, 105);
    assert_eq!(row.source.block_timestamp, 1_700_000_105);
    assert_eq!(row.source.tx_hash, FixedBytes::from([1; 32]));
}

#[test]
fn indexed_wallet_artifact_page_rejects_row_count_mismatch() {
    let chunk = wallet_scan_chunk(
        scope(),
        100,
        110,
        vec![(
            WALLET_NULLIFIER_SECTION_ID,
            nullifier_section(105, 7, [0x42; 32]),
        )],
        2,
    );

    let Err(error) = IndexedWalletPage::try_from(&chunk) else {
        panic!("row count mismatch should fail");
    };

    assert!(
        matches!(error, SyncError::UnexpectedFormat(message) if message.contains("row count mismatch"))
    );
}

#[test]
fn indexed_wallet_artifact_page_rejects_duplicate_section_id() {
    let chunk = wallet_scan_chunk(
        scope(),
        100,
        110,
        vec![
            (
                WALLET_NULLIFIER_SECTION_ID,
                nullifier_section(105, 7, [0x42; 32]),
            ),
            (
                WALLET_NULLIFIER_SECTION_ID,
                nullifier_section(106, 8, [0x43; 32]),
            ),
        ],
        2,
    );

    let Err(error) = IndexedWalletPage::try_from(&chunk) else {
        panic!("duplicate wallet_scan section id should fail");
    };

    assert!(
        matches!(error, SyncError::UnexpectedFormat(message) if message.contains("appears more than once"))
    );
}

#[test]
fn indexed_wallet_artifact_page_rejects_out_of_range_source_block() {
    let chunk = wallet_scan_chunk(
        scope(),
        100,
        110,
        vec![(
            WALLET_NULLIFIER_SECTION_ID,
            nullifier_section(111, 7, [0x42; 32]),
        )],
        1,
    );

    let Err(error) = IndexedWalletPage::try_from(&chunk) else {
        panic!("out-of-range wallet_scan source should fail");
    };

    assert!(
        matches!(error, SyncError::UnexpectedFormat(message) if message.contains("outside chunk block range"))
    );
}

#[test]
fn indexed_wallet_artifact_page_rejects_extreme_section_count_without_allocation() {
    let mut section = Vec::new();
    write_u64(&mut section, u64::MAX);
    let chunk = wallet_scan_chunk(
        scope(),
        100,
        110,
        vec![(WALLET_NULLIFIER_SECTION_ID, section)],
        u64::MAX,
    );

    let Err(error) = IndexedWalletPage::try_from(&chunk) else {
        panic!("extreme section row count should fail as a format error");
    };

    assert!(
        matches!(error, SyncError::UnexpectedFormat(message) if message.contains("ended while reading source block_number"))
    );
}

#[test]
fn indexed_wallet_artifact_page_accepts_fully_sparse_requested_range() {
    let session = artifact_session_with_coverage(200, Vec::new(), &[(100, 200)]);

    let page = session
        .page_for_block_range(100, 200)
        .expect("fully sparse range should decode")
        .expect("latest indexed block covers range");

    assert_eq!(page.checkpoint_block, 200);
    assert_eq!(page.transact_rows, 0);
    assert_eq!(page.shield_rows, 0);
    assert_eq!(page.legacy_encrypted_rows, 0);
    assert_eq!(page.legacy_generated_rows, 0);
    assert_eq!(page.nullifier_rows, 0);
}

#[test]
fn indexed_wallet_artifact_target_stops_at_catalog_checkpoint() {
    let coverage = WalletScanArtifactCoverage {
        ranges: vec![WalletScanCoverageRange {
            start: 100,
            end: 200,
            checkpoint_block: 175,
        }],
    };

    let target =
        wallet_scan_artifact_target_block(&coverage, &[], 100, 200).expect("valid coverage target");

    assert_eq!(target, Some(175));
}

#[test]
fn indexed_wallet_artifact_target_stops_at_chunk_checkpoint() {
    let coverage = coverage_from_ranges(&[(100, 200)]);
    let mut descriptor = wallet_scan_chunk(scope(), 100, 200, Vec::new(), 0).descriptor;
    descriptor.metadata.checkpoint_block = Some(180);

    let target = wallet_scan_artifact_target_block(&coverage, &[descriptor], 100, 200)
        .expect("valid chunk target");

    assert_eq!(target, Some(180));
}

#[test]
fn indexed_wallet_artifact_target_accepts_proven_sparse_coverage() {
    let coverage = coverage_from_ranges(&[(100, 200)]);

    let target =
        wallet_scan_artifact_target_block(&coverage, &[], 100, 200).expect("valid sparse target");

    assert_eq!(target, Some(200));
}

#[test]
fn indexed_wallet_artifact_page_rejects_unproven_empty_requested_range() {
    let session = artifact_session(200, Vec::new());

    let Err(error) = session.page_for_block_range(100, 200) else {
        panic!("unproven empty artifact coverage should fail");
    };

    assert!(
        matches!(error, SyncError::UnexpectedFormat(message) if message.contains("coverage does not include"))
    );
}

#[test]
fn indexed_wallet_artifact_page_accepts_sparse_requested_prefix_and_suffix() {
    let chunk = wallet_scan_chunk(
        scope(),
        150,
        180,
        vec![(
            WALLET_NULLIFIER_SECTION_ID,
            nullifier_section(175, 7, [0x42; 32]),
        )],
        1,
    );
    let session = artifact_session_with_coverage(200, vec![chunk], &[(100, 200)]);

    let page = session
        .page_for_block_range(100, 200)
        .expect("sparse prefix and suffix should decode")
        .expect("latest indexed block covers range");

    assert_eq!(page.checkpoint_block, 200);
    assert_eq!(page.nullifier_rows, 1);
    assert_eq!(page.nullifiers[0].source.block_number, 175);
}

#[test]
fn indexed_wallet_artifact_page_accepts_sparse_gap_between_chunks() {
    let first_chunk = wallet_scan_chunk(
        scope(),
        100,
        110,
        vec![(
            WALLET_NULLIFIER_SECTION_ID,
            nullifier_section(105, 7, [0x11; 32]),
        )],
        1,
    );
    let second_chunk = wallet_scan_chunk(
        scope(),
        150,
        160,
        vec![(
            WALLET_NULLIFIER_SECTION_ID,
            nullifier_section(155, 7, [0x22; 32]),
        )],
        1,
    );
    let session =
        artifact_session_with_coverage(160, vec![first_chunk, second_chunk], &[(100, 160)]);

    let page = session
        .page_for_block_range(100, 160)
        .expect("sparse gap should decode")
        .expect("latest indexed block covers range");

    assert_eq!(page.checkpoint_block, 160);
    assert_eq!(page.nullifier_rows, 2);
    assert_eq!(page.nullifiers[0].source.block_number, 105);
    assert_eq!(page.nullifiers[1].source.block_number, 155);
}

#[test]
fn indexed_wallet_artifact_page_stops_before_unproven_sparse_gap() {
    let first_chunk = wallet_scan_chunk(
        scope(),
        100,
        110,
        vec![(
            WALLET_NULLIFIER_SECTION_ID,
            nullifier_section(105, 7, [0x11; 32]),
        )],
        1,
    );
    let second_chunk = wallet_scan_chunk(
        scope(),
        150,
        160,
        vec![(
            WALLET_NULLIFIER_SECTION_ID,
            nullifier_section(155, 7, [0x22; 32]),
        )],
        1,
    );
    let session = artifact_session(160, vec![first_chunk, second_chunk]);

    let page = session
        .page_for_block_range(100, 160)
        .expect("page should stop before unproven coverage gap")
        .expect("latest indexed block covers range");

    assert_eq!(page.checkpoint_block, 110);
    assert_eq!(page.nullifier_rows, 1);
    assert_eq!(page.nullifiers[0].source.block_number, 105);
}

#[test]
fn indexed_wallet_uses_new_authoritative_snapshot_without_merging() {
    let scope = scope();
    let old_tail = wallet_scan_chunk(
        scope.clone(),
        100,
        110,
        vec![(
            WALLET_NULLIFIER_SECTION_ID,
            nullifier_section(105, 7, [0x11; 32]),
        )],
        1,
    );
    let current_tail = wallet_scan_chunk(
        scope,
        100,
        120,
        vec![(
            WALLET_NULLIFIER_SECTION_ID,
            nullifier_section(115, 7, [0x22; 32]),
        )],
        1,
    );

    let old_selected = selected_wallet_scan_chunks(std::slice::from_ref(&old_tail), 100, 110)
        .expect("select old snapshot");
    let old_page = artifact_session(110, old_selected)
        .page_for_block_range(100, 110)
        .expect("old snapshot page should decode")
        .expect("old snapshot covers range");
    assert_eq!(old_page.nullifiers[0].source.block_number, 105);

    let selected =
        selected_wallet_scan_chunks(&[current_tail], 100, 120).expect("select new snapshot");
    let session = artifact_session(120, selected);
    let page = session
        .page_for_block_range(100, 120)
        .expect("current tail page should decode")
        .expect("latest indexed block covers range");

    assert_eq!(page.nullifier_rows, 1);
    assert_eq!(page.nullifiers[0].source.block_number, 115);
    assert_eq!(
        page.nullifiers[0].nullifier,
        U256::from_be_bytes([0x22; 32])
    );
}

#[test]
fn indexed_wallet_rejects_overlapping_current_snapshot_catalogs() {
    let scope = scope();
    let old_tail = wallet_scan_chunk(
        scope.clone(),
        100,
        110,
        vec![(
            WALLET_NULLIFIER_SECTION_ID,
            nullifier_section(105, 7, [0x11; 32]),
        )],
        1,
    );
    let catalogs = vec![
        wallet_scan_catalog(0, vec![old_tail.descriptor]),
        empty_wallet_scan_catalog(scope.clone(), 0, 100, 110),
    ];

    let error =
        IndexedWalletArtifactSession::select_current_stream_plan(&catalogs, &scope, 100, 110)
            .expect_err("overlapping current snapshot catalogs must fail");
    assert!(error.to_string().contains("overlap"));
}

#[test]
fn indexed_wallet_snapshot_does_not_use_nonintersecting_catalog_context() {
    let scope = scope();
    let current = with_catalog_generation(
        wallet_scan_chunk(
            scope.clone(),
            100,
            110,
            vec![(
                WALLET_NULLIFIER_SECTION_ID,
                nullifier_section(105, 7, [0x11; 32]),
            )],
            1,
        ),
        1,
    );
    let current_catalog = wallet_scan_catalog(1, vec![current.descriptor]);
    let successor_catalog = empty_wallet_scan_catalog(scope.clone(), 1, 200, 210).descriptor;

    let plan = IndexedWalletArtifactSession::select_current_stream_plan(
        std::slice::from_ref(&current_catalog),
        &scope,
        100,
        110,
    )
    .expect("current catalog should plan without external catalog context");

    assert!(!plan.required_current_chunks[0].is_stable_current());
    assert_eq!(successor_catalog.range.start, 200);
}

#[test]
fn indexed_wallet_artifact_selection_rejects_stable_consolidation() {
    let scope = scope();
    let sealed_prefix = with_catalog_generation(
        wallet_scan_chunk(
            scope.clone(),
            100,
            110,
            vec![(
                WALLET_NULLIFIER_SECTION_ID,
                nullifier_section(105, 7, [0x11; 32]),
            )],
            1,
        ),
        1,
    );
    let generation_tail = with_catalog_generation(
        wallet_scan_chunk(
            scope.clone(),
            111,
            120,
            vec![(
                WALLET_NULLIFIER_SECTION_ID,
                nullifier_section(115, 7, [0x22; 32]),
            )],
            1,
        ),
        1,
    );
    let consolidated = with_catalog_generation(
        wallet_scan_chunk(
            scope,
            100,
            120,
            vec![(
                WALLET_NULLIFIER_SECTION_ID,
                nullifier_section(115, 7, [0x33; 32]),
            )],
            1,
        ),
        2,
    );

    let error =
        selected_wallet_scan_chunks(&[sealed_prefix, generation_tail, consolidated], 100, 120)
            .expect_err("stable consolidation should fail");

    assert!(
        matches!(error, SyncError::UnexpectedFormat(message) if message.contains("stable chunk"))
    );
}

#[test]
fn indexed_wallet_artifact_selection_rejects_sealed_tail_replacement() {
    let scope = scope();
    let sealed_tail = with_chunk_sealed(with_catalog_generation(
        wallet_scan_chunk(
            scope.clone(),
            100,
            110,
            vec![(
                WALLET_NULLIFIER_SECTION_ID,
                nullifier_section(105, 7, [0x11; 32]),
            )],
            1,
        ),
        1,
    ));
    let replacement = with_catalog_generation(
        wallet_scan_chunk(
            scope,
            100,
            120,
            vec![(
                WALLET_NULLIFIER_SECTION_ID,
                nullifier_section(115, 7, [0x22; 32]),
            )],
            1,
        ),
        2,
    );

    let error = selected_wallet_scan_chunks(&[sealed_tail, replacement], 100, 120)
        .expect_err("sealed tail replacement should fail");

    assert!(
        matches!(error, SyncError::UnexpectedFormat(message) if message.contains("stable chunk"))
    );
}

#[test]
fn indexed_wallet_artifact_selection_rejects_complete_stream_extension() {
    let scope = scope();
    let complete_tail = with_stream_complete(with_catalog_generation(
        wallet_scan_chunk(
            scope.clone(),
            100,
            110,
            vec![(
                WALLET_NULLIFIER_SECTION_ID,
                nullifier_section(105, 7, [0x11; 32]),
            )],
            1,
        ),
        1,
    ));
    let extension = with_catalog_generation(
        wallet_scan_chunk(
            scope,
            111,
            120,
            vec![(
                WALLET_NULLIFIER_SECTION_ID,
                nullifier_section(115, 7, [0x22; 32]),
            )],
            1,
        ),
        2,
    );

    let error = selected_wallet_scan_chunks(&[complete_tail, extension], 100, 120)
        .expect_err("complete stream extension should fail");

    assert!(
        matches!(error, SyncError::UnexpectedFormat(message) if message.contains("complete tail"))
    );
}

#[test]
fn indexed_wallet_artifact_page_rejects_source_after_checkpoint() {
    let chunk = with_checkpoint_block(
        wallet_scan_chunk(
            scope(),
            100,
            110,
            vec![(
                WALLET_NULLIFIER_SECTION_ID,
                nullifier_section(106, 7, [0x42; 32]),
            )],
            1,
        ),
        105,
    );

    let Err(error) = IndexedWalletPage::try_from(&chunk) else {
        panic!("post-checkpoint wallet_scan source should fail");
    };

    assert!(
        matches!(error, SyncError::UnexpectedFormat(message) if message.contains("exceeds checkpoint"))
    );
}

#[test]
fn indexed_wallet_artifact_page_stops_at_checkpointed_chunk() {
    let chunk = with_checkpoint_block(
        wallet_scan_chunk(
            scope(),
            100,
            110,
            vec![(
                WALLET_NULLIFIER_SECTION_ID,
                nullifier_section(104, 7, [0x42; 32]),
            )],
            1,
        ),
        105,
    );
    let session = artifact_session(110, vec![chunk]);

    let page = session
        .page_for_block_range(100, 110)
        .expect("checkpointed page should decode")
        .expect("latest indexed block covers range");

    assert_eq!(page.checkpoint_block, 105);
    assert_eq!(page.nullifier_rows, 1);
    assert_eq!(page.nullifiers[0].source.block_number, 104);
}

#[test]
fn indexed_wallet_artifact_page_returns_exhaustion_after_open_tail_checkpoint() {
    let chunk = with_checkpoint_block(
        wallet_scan_chunk(
            scope(),
            100,
            200,
            vec![(
                WALLET_NULLIFIER_SECTION_ID,
                nullifier_section(140, 7, [0x42; 32]),
            )],
            1,
        ),
        150,
    );
    let session = artifact_session(200, vec![chunk]);

    let first_page = session
        .page_for_block_range(100, 200)
        .expect("checkpointed page should decode")
        .expect("latest indexed block covers range");
    assert_eq!(first_page.checkpoint_block, 150);

    let next_page = session
        .page_for_block_range(151, 200)
        .expect("open tail after checkpoint should not be a format error");
    assert!(matches!(
        next_page,
        IndexedWalletArtifactPageOutcome::Exhausted {
            checkpoint_block: 150,
        }
    ));
}

#[test]
fn indexed_wallet_artifact_page_rejects_checkpoint_before_chunk_range() {
    let chunk = with_checkpoint_block(
        wallet_scan_chunk(
            scope(),
            100,
            110,
            vec![(
                WALLET_NULLIFIER_SECTION_ID,
                nullifier_section(105, 7, [0x42; 32]),
            )],
            1,
        ),
        90,
    );

    let Err(error) = IndexedWalletPage::try_from(&chunk) else {
        panic!("pre-range checkpoint should fail");
    };

    assert!(
        matches!(error, SyncError::UnexpectedFormat(message) if message.contains("before range start"))
    );
}

#[test]
fn indexed_wallet_artifact_page_decodes_only_requested_chunk_range() {
    let valid_chunk = wallet_scan_chunk(
        scope(),
        100,
        110,
        vec![(
            WALLET_NULLIFIER_SECTION_ID,
            nullifier_section(105, 7, [0x11; 32]),
        )],
        1,
    );
    let invalid_later_chunk = wallet_scan_chunk(
        scope(),
        150,
        160,
        vec![(
            WALLET_NULLIFIER_SECTION_ID,
            nullifier_section(161, 7, [0x22; 32]),
        )],
        1,
    );
    let session = artifact_session(160, vec![valid_chunk, invalid_later_chunk]);

    let page = session
        .page_for_block_range(100, 110)
        .expect("first page should not decode later chunk")
        .expect("latest indexed block covers range");

    assert_eq!(page.checkpoint_block, 110);
    assert_eq!(page.nullifier_rows, 1);
    assert_eq!(page.nullifiers[0].source.block_number, 105);
}

fn manifest_with_latest_and_catalog(
    scope: ChainScope,
    latest_block: u64,
    catalog_range: Option<IndexedArtifactRange>,
) -> IndexedArtifactManifest {
    let catalogs = catalog_range
        .map(|range| {
            let range_end = range.end;
            vec![IndexedArtifactDescriptor {
                dataset_kind: IndexedDatasetKind::WalletScan,
                scope: scope.clone(),
                range,
                row_count: 42,
                cid: "bafywalletscan".to_string(),
                sha256: FixedBytes::from([0x11; 32]),
                byte_size: 1234,
                encoding_version: INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION,
                compression: CompressionAlgorithm::Zstd,
                metadata: DatasetDescriptorMetadata {
                    catalog_generation: Some(1),
                    checkpoint_block: Some(range_end),
                    ..Default::default()
                },
            }]
        })
        .unwrap_or_default();
    IndexedArtifactManifest::new(
        1_700_000_000_000,
        1,
        PublisherIdentity::ed25519(FixedBytes::from([0x11; 32])),
        vec![IndexedArtifactChainEntry {
            scope,
            latest_indexed: vec![LatestIndexedHeight {
                dataset_kind: IndexedDatasetKind::WalletScan,
                block_number: latest_block,
                block_hash: FixedBytes::from([0x22; 32]),
            }],
            catalogs,
        }],
    )
}

fn scope() -> ChainScope {
    ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xbb; 20]),
    }
}

fn wallet_scan_chunk(
    scope: ChainScope,
    start: u64,
    end: u64,
    sections: Vec<(u16, Vec<u8>)>,
    row_count: u64,
) -> VerifiedIndexedArtifactChunk {
    let mut payload = Vec::new();
    let mut section_headers = Vec::new();
    for (section_id, section_payload) in sections {
        let offset = u64::try_from(payload.len()).expect("section offset");
        payload.extend(section_payload);
        let byte_length = u64::try_from(payload.len()).expect("section end") - offset;
        section_headers.push((section_id, offset, byte_length));
    }

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
    write_u64(&mut bytes, row_count);
    write_u64(
        &mut bytes,
        u64::try_from(payload.len()).expect("payload len"),
    );
    write_u16(
        &mut bytes,
        u16::try_from(section_headers.len()).expect("section count"),
    );
    for (section_id, offset, byte_length) in section_headers {
        write_u16(&mut bytes, section_id);
        write_u64(&mut bytes, offset);
        write_u64(&mut bytes, byte_length);
    }
    bytes.extend(payload);

    let descriptor = IndexedArtifactDescriptor {
        dataset_kind: IndexedDatasetKind::WalletScan,
        scope,
        range: IndexedArtifactRange {
            kind: IndexedArtifactRangeKind::Block,
            start,
            end,
        },
        row_count,
        cid: "bafywalletchunk".to_string(),
        sha256: prefixed_sha256(&bytes),
        byte_size: u64::try_from(bytes.len()).expect("chunk byte size"),
        encoding_version: INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION,
        compression: CompressionAlgorithm::None,
        metadata: DatasetDescriptorMetadata {
            catalog_generation: Some(1),
            checkpoint_block: Some(end),
            ..Default::default()
        },
    };
    VerifiedIndexedArtifactChunk { descriptor, bytes }
}

fn artifact_session(
    latest_indexed_block: u64,
    chunks: Vec<VerifiedIndexedArtifactChunk>,
) -> IndexedWalletArtifactSession {
    let mut chunk_descriptors = Vec::new();
    let mut indexed_chunks = Vec::new();
    let mut coverage = WalletScanArtifactCoverage::default();
    for (index, chunk) in chunks.into_iter().enumerate() {
        let descriptor = chunk.descriptor.clone();
        let range = descriptor.range.clone();
        coverage
            .add_descriptor(&descriptor)
            .expect("wallet scan test chunk coverage");
        chunk_descriptors.push(descriptor);
        indexed_chunks.push(IndexedWalletArtifactChunk {
            descriptor_index: index,
            range,
            chunk,
        });
    }
    IndexedWalletArtifactSession {
        probe: IndexedWalletArtifactProbe {
            latest_indexed_block,
            catalog_count: chunk_descriptors.len(),
        },
        target_block: latest_indexed_block,
        chunk_descriptors,
        chunks: indexed_chunks,
        coverage,
        read_scope: test_public_scan_read_scope(),
    }
}

fn artifact_session_with_coverage(
    latest_indexed_block: u64,
    chunks: Vec<VerifiedIndexedArtifactChunk>,
    ranges: &[(u64, u64)],
) -> IndexedWalletArtifactSession {
    let mut session = artifact_session(latest_indexed_block, chunks);
    session.probe.catalog_count = ranges.len();
    session.coverage = coverage_from_ranges(ranges);
    session
}

const fn test_public_scan_read_scope() -> PublicScanReadScope {
    PublicScanReadScope::new(PublicDataPlaneEpoch::new(0))
}

fn coverage_from_ranges(ranges: &[(u64, u64)]) -> WalletScanArtifactCoverage {
    let mut coverage = WalletScanArtifactCoverage::default();
    coverage
        .ranges
        .extend(ranges.iter().map(|(start, end)| WalletScanCoverageRange {
            start: *start,
            end: *end,
            checkpoint_block: *end,
        }));
    coverage
        .ranges
        .sort_by_key(|range| (range.start, range.end));
    coverage
}

fn selected_wallet_scan_chunks(
    chunks: &[VerifiedIndexedArtifactChunk],
    from_block: u64,
    target_block: u64,
) -> Result<Vec<VerifiedIndexedArtifactChunk>, SyncError> {
    let scope = chunks
        .first()
        .expect("at least one wallet scan chunk")
        .descriptor
        .scope
        .clone();
    let catalogs = stream_catalogs_for_chunks(chunks);
    let selected = IndexedWalletArtifactSession::select_current_stream_plan(
        &catalogs,
        &scope,
        from_block,
        target_block,
    )?
    .required_current_chunks;
    Ok(selected
        .into_iter()
        .map(|entry| {
            chunks
                .iter()
                .find(|chunk| chunk.descriptor == entry.descriptor)
                .expect("selected descriptor has chunk bytes")
                .clone()
        })
        .collect())
}

fn stream_catalogs_for_chunks(
    chunks: &[VerifiedIndexedArtifactChunk],
) -> Vec<IndexedArtifactStreamCatalog> {
    let mut by_generation = BTreeMap::<u64, Vec<IndexedArtifactDescriptor>>::new();
    for chunk in chunks {
        let generation = chunk
            .descriptor
            .metadata
            .catalog_generation
            .expect("test chunk generation");
        by_generation
            .entry(generation)
            .or_default()
            .push(chunk.descriptor.clone());
    }
    by_generation
        .into_iter()
        .map(|(generation, chunks)| wallet_scan_catalog(generation, chunks))
        .collect()
}

fn wallet_scan_catalog(
    generation: u64,
    chunks: Vec<IndexedArtifactDescriptor>,
) -> IndexedArtifactStreamCatalog {
    let first = chunks.first().expect("wallet scan test catalog chunk");
    let start = chunks
        .iter()
        .map(|chunk| chunk.range.start)
        .min()
        .expect("catalog start");
    let end = chunks
        .iter()
        .map(|chunk| chunk.range.end)
        .max()
        .expect("catalog end");
    let row_count = chunks
        .iter()
        .map(|chunk| chunk.row_count)
        .fold(0_u64, u64::saturating_add);
    let mut descriptor = first.clone();
    descriptor.range.start = start;
    descriptor.range.end = end;
    descriptor.row_count = row_count;
    descriptor.cid = format!("bafywalletcatalog-{generation}-{start}-{end}");
    descriptor.metadata.catalog_generation = Some(generation);
    descriptor.metadata.checkpoint_block = Some(end);
    IndexedArtifactStreamCatalog::new(descriptor, chunks)
}

fn empty_wallet_scan_catalog(
    scope: ChainScope,
    generation: u64,
    start: u64,
    end: u64,
) -> IndexedArtifactStreamCatalog {
    let descriptor = IndexedArtifactDescriptor {
        dataset_kind: IndexedDatasetKind::WalletScan,
        scope,
        range: IndexedArtifactRange {
            kind: IndexedArtifactRangeKind::Block,
            start,
            end,
        },
        row_count: 0,
        cid: format!("bafywalletcatalog-empty-{generation}-{start}-{end}"),
        sha256: FixedBytes::from([0xee; 32]),
        byte_size: 0,
        encoding_version: INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION,
        compression: CompressionAlgorithm::Zstd,
        metadata: DatasetDescriptorMetadata {
            catalog_generation: Some(generation),
            checkpoint_block: Some(end),
            ..Default::default()
        },
    };
    IndexedArtifactStreamCatalog::new(descriptor, Vec::new())
}

fn with_catalog_generation(
    mut chunk: VerifiedIndexedArtifactChunk,
    generation: u64,
) -> VerifiedIndexedArtifactChunk {
    chunk.descriptor.metadata.catalog_generation = Some(generation);
    chunk
}

fn with_checkpoint_block(
    mut chunk: VerifiedIndexedArtifactChunk,
    checkpoint_block: u64,
) -> VerifiedIndexedArtifactChunk {
    chunk.descriptor.metadata.checkpoint_block = Some(checkpoint_block);
    chunk
}

fn with_chunk_sealed(mut chunk: VerifiedIndexedArtifactChunk) -> VerifiedIndexedArtifactChunk {
    chunk.descriptor.metadata.chunk_sealed = true;
    chunk
}

fn with_stream_complete(mut chunk: VerifiedIndexedArtifactChunk) -> VerifiedIndexedArtifactChunk {
    chunk.descriptor.metadata.stream_complete = true;
    chunk
}

fn nullifier_section(block_number: u64, tree_number: u32, nullifier: [u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_u64(&mut bytes, 1);
    write_source(&mut bytes, block_number, 1);
    write_u32(&mut bytes, tree_number);
    bytes.extend_from_slice(&nullifier);
    bytes
}

fn transact_section(
    block_number: u64,
    tree_number: u32,
    tree_position: u64,
    commitment: U256,
    ciphertext: &CommitmentCiphertext,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_u64(&mut bytes, 1);
    write_source(&mut bytes, block_number, 1);
    write_u32(&mut bytes, tree_number);
    write_u64(&mut bytes, tree_position);
    bytes.extend_from_slice(&commitment.to_be_bytes::<32>());
    write_bytes(&mut bytes, &ciphertext.abi_encode());
    bytes
}

fn legacy_generated_section(
    block_number: u64,
    tree_number: u32,
    tree_position: u64,
    encrypted_random: [u8; 64],
) -> Vec<u8> {
    let preimage = LegacyCommitmentPreimage {
        npk: U256::from(1),
        token: TokenData {
            tokenType: 0,
            tokenAddress: Address::ZERO,
            tokenSubID: U256::ZERO,
        },
        value: Uint::<120, 2>::from(1),
    };
    let mut bytes = Vec::new();
    write_u64(&mut bytes, 1);
    write_source(&mut bytes, block_number, 2);
    write_u32(&mut bytes, tree_number);
    write_u64(&mut bytes, tree_position);
    bytes.extend_from_slice(&[0x33; 32]);
    write_bytes(&mut bytes, &preimage.abi_encode());
    bytes.extend_from_slice(&encrypted_random);
    bytes
}

fn write_source(bytes: &mut Vec<u8>, block_number: u64, log_index: u64) {
    write_u64(bytes, block_number);
    write_u64(bytes, block_number + 1_700_000_000);
    bytes.extend_from_slice(&[log_index as u8; 32]);
}

fn write_bytes(bytes: &mut Vec<u8>, value: &[u8]) {
    write_u32(bytes, u32::try_from(value.len()).expect("byte vec len"));
    bytes.extend_from_slice(value);
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
