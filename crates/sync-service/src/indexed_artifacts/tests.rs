use super::*;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering as AtomicOrdering},
};
use std::time::Duration;

use alloy::primitives::FixedBytes;
use chrono::Utc;
use cid::Cid;
use ed25519_dalek::SigningKey;
use libp2p_identity::Keypair;
use multihash_codetable::{Code, MultihashDigest};
use railgun_indexed_artifacts::{
    IndexedArtifactStreamCatalog, IndexedArtifactStreamPlan, IndexedArtifactStreamPlanRequest,
};
use url::Url;

const LIBP2P_KEY_CODEC: u64 = 0x72;
const RAW_CODEC: u64 = 0x55;
/// The chunk hedge delay private to `trustless-artifacts`.
const CHUNK_HEDGE_DELAY: Duration = Duration::from_secs(5);

#[test]
fn wallet_maintenance_key_includes_full_cache_identity() {
    let mut first = chunk_descriptor(scope(), 0, 9);
    first.metadata.catalog_generation = Some(1);
    let mut second = first.clone();
    second.metadata.catalog_generation = Some(2);

    assert_ne!(
        IndexedArtifactMaintenanceKey::wallet_chunk(&first, 0),
        IndexedArtifactMaintenanceKey::wallet_chunk(&second, 0),
    );
}

#[test]
fn manifest_validation_accepts_signature_sequence_freshness_and_scope() {
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let scope = scope();
    let mut manifest = manifest_for_scope(scope.clone(), now_ms());
    manifest.sign_manifest(&signing_key).expect("sign manifest");
    let config = config(
        signing_key.verifying_key().to_bytes(),
        Some(Duration::from_mins(1)),
    );

    validate_manifest(
        &manifest,
        &config,
        &scope,
        Some(manifest.sequence),
        UNIX_EPOCH + Duration::from_millis(now_ms()),
    )
    .expect("manifest validates");
}

#[test]
fn manifest_validation_rejects_untrusted_publisher() {
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let scope = scope();
    let mut manifest = manifest_for_scope(scope.clone(), now_ms());
    manifest.sign_manifest(&signing_key).expect("sign manifest");
    let config = config([8_u8; 32], None);

    let err = validate_manifest(
        &manifest,
        &config,
        &scope,
        None,
        UNIX_EPOCH + Duration::from_millis(now_ms()),
    )
    .expect_err("publisher mismatch rejected");

    assert!(matches!(
        err,
        IndexedArtifactManifestError::PublisherKeyMismatch { .. }
    ));
}

#[test]
fn manifest_validation_rejects_missing_scope_and_catalog_scope_mismatch() {
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let scope = scope();
    let other_scope = ChainScope {
        chain_id: 56,
        ..scope
    };
    let mut manifest = manifest_for_scope(scope.clone(), now_ms());
    manifest.sign_manifest(&signing_key).expect("sign manifest");
    let config = config(signing_key.verifying_key().to_bytes(), None);

    let missing = validate_manifest(
        &manifest,
        &config,
        &other_scope,
        None,
        UNIX_EPOCH + Duration::from_millis(now_ms()),
    )
    .expect_err("missing scope rejected");
    assert!(matches!(
        missing,
        IndexedArtifactManifestError::MissingChainScope { .. }
    ));

    manifest.chains[0].catalogs[0].scope = other_scope;
    manifest
        .sign_manifest(&signing_key)
        .expect("resign manifest");
    let mismatch = validate_manifest(
        &manifest,
        &config,
        &scope,
        None,
        UNIX_EPOCH + Duration::from_millis(now_ms()),
    )
    .expect_err("catalog mismatch rejected");
    assert!(matches!(
        mismatch,
        IndexedArtifactManifestError::CatalogScopeMismatch { .. }
    ));
}

#[test]
fn manifest_validation_rejects_rollback_and_stale_first_manifest() {
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let scope = scope();
    let mut manifest = manifest_for_scope(scope.clone(), now_ms());
    manifest.sign_manifest(&signing_key).expect("sign manifest");
    let config = config(
        signing_key.verifying_key().to_bytes(),
        Some(Duration::from_secs(1)),
    );

    let rollback = validate_manifest(
        &manifest,
        &config,
        &scope,
        Some(manifest.sequence + 1),
        UNIX_EPOCH + Duration::from_millis(now_ms()),
    )
    .expect_err("rollback rejected");
    assert!(matches!(
        rollback,
        IndexedArtifactManifestError::ManifestSequenceRollback { .. }
    ));

    let stale = validate_manifest(
        &manifest,
        &config,
        &scope,
        None,
        UNIX_EPOCH + Duration::from_millis(now_ms() + 2_000),
    )
    .expect_err("stale manifest rejected");
    assert!(matches!(
        stale,
        IndexedArtifactManifestError::ManifestStale { .. }
    ));
}

#[test]
fn manifest_validation_rejects_stale_advanced_manifest() {
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let scope = scope();
    let mut manifest = manifest_for_scope(scope.clone(), now_ms());
    manifest.sequence = 11;
    manifest.sign_manifest(&signing_key).expect("sign manifest");
    let config = config(
        signing_key.verifying_key().to_bytes(),
        Some(Duration::from_secs(1)),
    );

    let stale = validate_manifest(
        &manifest,
        &config,
        &scope,
        Some(10),
        UNIX_EPOCH + Duration::from_millis(now_ms() + 2_000),
    )
    .expect_err("stale advanced manifest rejected");

    assert!(matches!(
        stale,
        IndexedArtifactManifestError::ManifestStale { .. }
    ));
}

#[tokio::test]
async fn ipns_manifest_fetch_falls_back_to_next_valid_candidate() {
    let ipns_keypair = test_ipns_keypair();
    let ipns_name = ipns_name(&ipns_keypair);
    let scope = scope();
    let trusted_signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let bad_signing_key = SigningKey::from_bytes(&[8_u8; 32]);

    let mut valid_manifest = manifest_for_scope(scope.clone(), now_ms());
    valid_manifest.sequence = 10;
    valid_manifest
        .sign_manifest(&trusted_signing_key)
        .expect("sign valid manifest");
    let valid_manifest_bytes = serde_json::to_vec(&valid_manifest).expect("valid JSON");
    let valid_manifest_cid = raw_cid(&valid_manifest_bytes);

    let mut invalid_manifest = manifest_for_scope(scope.clone(), now_ms());
    invalid_manifest.sequence = 11;
    invalid_manifest
        .sign_manifest(&bad_signing_key)
        .expect("sign invalid manifest");
    let invalid_manifest_bytes = serde_json::to_vec(&invalid_manifest).expect("invalid JSON");
    let invalid_manifest_cid = raw_cid(&invalid_manifest_bytes);

    let ipns_path = format!("/ipns/{ipns_name}?format=ipns-record");
    let invalid_manifest_path = format!("/ipfs/{invalid_manifest_cid}?format=raw");
    let valid_manifest_path = format!("/ipfs/{valid_manifest_cid}?format=raw");
    let high_gateway = PathServer::spawn(
        HashMap::from([
            (
                ipns_path.clone(),
                ipns_record(&ipns_keypair, format!("/ipfs/{invalid_manifest_cid}"), 2),
            ),
            (invalid_manifest_path, invalid_manifest_bytes),
        ]),
        4,
    );
    let low_gateway = PathServer::spawn(
        HashMap::from([
            (
                ipns_path,
                ipns_record(&ipns_keypair, format!("/ipfs/{valid_manifest_cid}"), 1),
            ),
            (valid_manifest_path, valid_manifest_bytes),
        ]),
        3,
    );
    let mut config = config(trusted_signing_key.verifying_key().to_bytes(), None);
    config.manifest_source = IndexedArtifactManifestSource::IpnsName(ipns_name);
    config.gateway_urls = vec![high_gateway.url.clone(), low_gateway.url.clone()];
    let client = IndexedArtifactManifestClient::new(config, reqwest::Client::new());

    let fetched = client
        .fetch_manifest(&scope, None, SystemTime::now())
        .await
        .expect("fallback manifest accepted");

    assert_eq!(fetched.sequence, valid_manifest.sequence);
}

#[tokio::test]
async fn manifest_reuse_serves_second_consumer_without_gateway_requests() {
    let ipns_keypair = test_ipns_keypair();
    let ipns_name = ipns_name(&ipns_keypair);
    let scope = scope();
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let (manifest, manifest_bytes) = signed_manifest(&signing_key, &scope);
    let manifest_cid = raw_cid(&manifest_bytes);
    let ipns_path = format!("/ipns/{ipns_name}?format=ipns-record");
    let gateway = ManifestGateway::spawn(
        HashMap::from([
            (
                ipns_path.clone(),
                ipns_record(&ipns_keypair, format!("/ipfs/{manifest_cid}"), 1),
            ),
            (format!("/ipfs/{manifest_cid}?format=raw"), manifest_bytes),
        ]),
        0,
    );
    let mut config = config(signing_key.verifying_key().to_bytes(), None);
    config.manifest_source = IndexedArtifactManifestSource::IpnsName(ipns_name);
    config.gateway_urls = vec![gateway.url.clone()];
    let forest = IndexedArtifactManifestClient::new(config.clone(), reqwest::Client::new());
    let wallet = IndexedArtifactManifestClient::new(config, reqwest::Client::new());

    let fetched = forest
        .fetch_manifest_with_metadata(&scope, None, SystemTime::now())
        .await
        .expect("forest manifest verifies");
    let requests = gateway.request_paths();
    assert!(
        requests.contains(&ipns_path),
        "first consumer resolves IPNS"
    );
    let reused = wallet
        .fetch_manifest_with_metadata(&scope, None, SystemTime::now())
        .await
        .expect("wallet manifest reused");

    assert_eq!(
        gateway.request_paths(),
        requests,
        "second consumer should make no IPNS or CID request"
    );
    assert_eq!(reused.manifest, manifest);
    assert!(reused.preferred_gateway_index.is_some());
    assert_eq!(
        reused.preferred_gateway_index,
        fetched.preferred_gateway_index
    );
}

#[tokio::test]
async fn manifest_reuse_refetches_after_failure_failed_revalidation_or_window() {
    let scope = scope();
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let (_, manifest_bytes) = signed_manifest(&signing_key, &scope);
    let (config, gateway) = recorded_cid_manifest_source(
        &signing_key,
        manifest_bytes,
        Some(Duration::from_mins(1)),
        0,
    );
    let client = IndexedArtifactManifestClient::new(config, reqwest::Client::new());
    let fresh = UNIX_EPOCH + Duration::from_millis(now_ms());
    let stale = fresh + Duration::from_mins(2);

    client
        .fetch_manifest_with_metadata(&scope, None, stale)
        .await
        .expect_err("stale manifest rejected");
    client
        .fetch_manifest_with_metadata(&scope, None, fresh)
        .await
        .expect("fresh manifest verifies");
    assert_eq!(gateway.request_count(), 2, "a failed fetch is not stored");

    client
        .fetch_manifest_with_metadata(&scope, None, stale)
        .await
        .expect_err("stored manifest is stale at the new time");
    assert_eq!(
        gateway.request_count(),
        3,
        "a stored manifest that fails validation is fetched again"
    );
    client
        .fetch_manifest_with_metadata(&scope, None, fresh)
        .await
        .expect("stored manifest reused");
    assert_eq!(gateway.request_count(), 3);

    tokio::time::pause();
    tokio::time::advance(MANIFEST_REUSE_WINDOW).await;
    tokio::time::resume();
    client
        .fetch_manifest_with_metadata(&scope, None, fresh)
        .await
        .expect("manifest verifies after the window");
    assert_eq!(
        gateway.request_count(),
        4,
        "a manifest older than the window is fetched again"
    );
}

#[tokio::test]
async fn manifest_reuse_shares_one_fetch_between_concurrent_consumers() {
    let scope = scope();
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let (manifest, manifest_bytes) = signed_manifest(&signing_key, &scope);
    let (config, gateway) = recorded_cid_manifest_source(&signing_key, manifest_bytes, None, 0);
    let first = IndexedArtifactManifestClient::new(config.clone(), reqwest::Client::new());
    let second = IndexedArtifactManifestClient::new(config, reqwest::Client::new());
    let now = SystemTime::now();

    let (first, second) = tokio::join!(
        first.fetch_manifest_with_metadata(&scope, None, now),
        second.fetch_manifest_with_metadata(&scope, None, now),
    );

    assert_eq!(first.expect("first manifest").manifest, manifest);
    assert_eq!(second.expect("second manifest").manifest, manifest);
    assert_eq!(gateway.request_count(), 1);
}

#[tokio::test]
async fn manifest_reuse_fetches_again_after_cancelled_fetch() {
    let scope = scope();
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let (manifest, manifest_bytes) = signed_manifest(&signing_key, &scope);
    let (config, gateway) = recorded_cid_manifest_source(&signing_key, manifest_bytes, None, 1);
    let client = IndexedArtifactManifestClient::new(config, reqwest::Client::new());
    let now = SystemTime::now();

    tokio::select! {
        _ = client.fetch_manifest_with_metadata(&scope, None, now) => {
            panic!("stalled manifest fetch finished");
        }
        () = gateway.wait_for_requests(1) => {}
    }
    let fetched = tokio::time::timeout(
        Duration::from_secs(5),
        client.fetch_manifest_with_metadata(&scope, None, now),
    )
    .await
    .expect("cancelled fetch released the manifest entry")
    .expect("manifest verifies after cancellation");

    assert_eq!(fetched.manifest, manifest);
    assert_eq!(gateway.request_count(), 2);
}

#[test]
fn catalog_verification_checks_descriptor_hash_scope_and_chunks() {
    let scope = scope();
    let catalog = IndexedArtifactCatalog {
        format_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
        dataset_kind: IndexedDatasetKind::WalletScan,
        scope: scope.clone(),
        chunks: vec![chunk_descriptor(scope.clone(), 0, 50)],
    };
    let bytes = serde_json::to_vec(&catalog).expect("catalog json");
    let descriptor = catalog_descriptor(scope, 0, 50, &bytes);

    let verified = verify_catalog_bytes(&descriptor, &bytes).expect("catalog verifies");

    assert_eq!(verified.chunks.len(), 1);

    let mut wrong_hash = descriptor;
    wrong_hash.sha256 = FixedBytes::from([99_u8; 32]);
    assert!(matches!(
        verify_catalog_bytes(&wrong_hash, &bytes),
        Err(IndexedArtifactManifestError::ArtifactHashMismatch { .. })
    ));

    let mut wrong_chunk = catalog;
    wrong_chunk.chunks[0].range.end = 101;
    let wrong_chunk_bytes = serde_json::to_vec(&wrong_chunk).expect("catalog json");
    let wrong_chunk_descriptor =
        catalog_descriptor(wrong_chunk.scope.clone(), 0, 100, &wrong_chunk_bytes);
    assert!(matches!(
        verify_catalog_bytes(&wrong_chunk_descriptor, &wrong_chunk_bytes),
        Err(IndexedArtifactManifestError::CatalogChunkRangeMismatch { .. })
    ));
}

#[test]
fn catalog_verification_accepts_format_v1_without_generation() {
    let scope = scope();
    let catalog = IndexedArtifactCatalog {
        format_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
        dataset_kind: IndexedDatasetKind::WalletScan,
        scope: scope.clone(),
        chunks: vec![chunk_descriptor(scope.clone(), 0, 50)],
    };
    let bytes = serde_json::to_vec(&catalog).expect("catalog json");
    let mut descriptor = catalog_descriptor(scope, 0, 50, &bytes);
    descriptor.metadata.catalog_generation = None;

    let verified = verify_catalog_bytes(&descriptor, &bytes).expect("v1 catalog verifies");

    assert_eq!(verified.chunks.len(), 1);
    assert_eq!(verified.chunks[0].metadata.catalog_generation, None);
}

#[test]
fn catalog_verification_accepts_empty_format_v1_catalog_without_generation() {
    let scope = scope();
    let catalog = IndexedArtifactCatalog {
        format_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
        dataset_kind: IndexedDatasetKind::WalletScan,
        scope: scope.clone(),
        chunks: Vec::new(),
    };
    let bytes = serde_json::to_vec(&catalog).expect("catalog json");
    let mut descriptor = catalog_descriptor_with_metadata(
        scope,
        0,
        50,
        0,
        &bytes,
        DatasetDescriptorMetadata::default(),
    );
    descriptor.metadata.catalog_generation = None;

    let verified = verify_catalog_bytes(&descriptor, &bytes).expect("empty v1 catalog verifies");

    assert_eq!(verified.chunks, [] as [IndexedArtifactDescriptor; 0]);
}

#[test]
fn catalog_verification_rejects_aggregate_range_mismatch() {
    let scope = scope();
    let chunk = chunk_descriptor_for_dataset(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        scope.clone(),
        0,
        50,
    );
    let catalog = IndexedArtifactCatalog {
        format_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
        dataset_kind: IndexedDatasetKind::PublicTxid,
        scope: scope.clone(),
        chunks: vec![chunk.clone()],
    };
    let bytes = serde_json::to_vec(&catalog).expect("catalog json");
    let descriptor = catalog_descriptor_for_dataset_with_metadata(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        scope,
        0,
        100,
        chunk.row_count,
        &bytes,
        catalog_metadata(1),
    );

    let err = verify_catalog_bytes(&descriptor, &bytes).expect_err("aggregate range rejected");

    assert!(matches!(
        err,
        IndexedArtifactManifestError::CatalogAggregateRangeMismatch { .. }
    ));
}

#[test]
fn catalog_verification_accepts_sparse_wallet_scan_catalog_coverage() {
    let scope = scope();
    let catalog = IndexedArtifactCatalog {
        format_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
        dataset_kind: IndexedDatasetKind::WalletScan,
        scope: scope.clone(),
        chunks: vec![chunk_descriptor(scope.clone(), 150, 180)],
    };
    let bytes = serde_json::to_vec(&catalog).expect("catalog json");
    let descriptor =
        catalog_descriptor_with_metadata(scope.clone(), 100, 200, 5, &bytes, catalog_metadata(1));

    let verified = verify_catalog_bytes(&descriptor, &bytes).expect("sparse catalog verifies");
    let plan = IndexedArtifactStreamPlan::plan(
        &[IndexedArtifactStreamCatalog::new(
            descriptor,
            verified.chunks,
        )],
        &IndexedArtifactStreamPlanRequest::new(
            IndexedDatasetKind::WalletScan,
            scope,
            IndexedArtifactRangeKind::Block,
            100,
            200,
            IndexedArtifactStreamPartitionPolicy::Ignore,
        ),
    )
    .expect("sparse catalog remains plannable");

    assert_eq!(plan.required_current_chunks.len(), 1);
    assert_eq!(plan.required_current_chunks[0].descriptor.range.start, 150);
    assert_eq!(plan.required_current_chunks[0].descriptor.range.end, 180);
    assert!(
        plan.required_current_coverage
            .iter()
            .any(|coverage| { coverage.range.start == 100 && coverage.range.end == 200 })
    );
}

#[test]
fn catalog_verification_rejects_aggregate_row_count_mismatch() {
    let scope = scope();
    let catalog = IndexedArtifactCatalog {
        format_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
        dataset_kind: IndexedDatasetKind::WalletScan,
        scope: scope.clone(),
        chunks: vec![chunk_descriptor(scope.clone(), 0, 50)],
    };
    let bytes = serde_json::to_vec(&catalog).expect("catalog json");
    let descriptor = catalog_descriptor_with_metadata(scope, 0, 50, 6, &bytes, catalog_metadata(1));

    let err = verify_catalog_bytes(&descriptor, &bytes).expect_err("row count rejected");

    assert!(matches!(
        err,
        IndexedArtifactManifestError::CatalogAggregateRowCountMismatch { .. }
    ));
}

#[test]
fn catalog_verification_rejects_empty_catalog_with_nonzero_row_count() {
    let scope = scope();
    let catalog = IndexedArtifactCatalog {
        format_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
        dataset_kind: IndexedDatasetKind::WalletScan,
        scope: scope.clone(),
        chunks: Vec::new(),
    };
    let bytes = serde_json::to_vec(&catalog).expect("catalog json");
    let descriptor = catalog_descriptor_with_metadata(scope, 0, 50, 1, &bytes, catalog_metadata(1));

    let err = verify_catalog_bytes(&descriptor, &bytes).expect_err("empty row count rejected");

    assert!(matches!(
        err,
        IndexedArtifactManifestError::EmptyCatalogRowCountMismatch { .. }
    ));
}

#[test]
fn catalog_verification_omits_internal_only_stream_metadata_from_v1() {
    let scope = scope();
    let catalog_metadata = DatasetDescriptorMetadata {
        catalog_generation: Some(42),
        stream_partition: Some("catalog-partition".to_string()),
        stream_complete: true,
        chunk_sealed: true,
        ..DatasetDescriptorMetadata::default()
    };
    let mut list_a = chunk_descriptor_for_dataset(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        scope.clone(),
        0,
        9,
    );
    list_a.cid = "bafytxid-list-a".to_string();
    list_a.metadata.stream_partition = Some("list-a".to_string());
    list_a.metadata.stream_complete = false;
    list_a.metadata.chunk_sealed = false;
    let mut list_b = chunk_descriptor_for_dataset(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        scope.clone(),
        0,
        9,
    );
    list_b.cid = "bafytxid-list-b".to_string();
    list_b.metadata.stream_partition = Some("list-b".to_string());
    list_b.metadata.stream_complete = false;
    list_b.metadata.chunk_sealed = false;
    let catalog_row_count = list_a.row_count + list_b.row_count;
    let catalog = IndexedArtifactCatalog {
        format_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
        dataset_kind: IndexedDatasetKind::PublicTxid,
        scope: scope.clone(),
        chunks: vec![list_a, list_b],
    };
    let bytes = serde_json::to_vec(&catalog).expect("catalog json");
    let descriptor = catalog_descriptor_for_dataset_with_metadata(
        IndexedDatasetKind::PublicTxid,
        IndexedArtifactRangeKind::TxidIndex,
        scope,
        0,
        9,
        catalog_row_count,
        &bytes,
        catalog_metadata,
    );

    let verified = verify_catalog_bytes(&descriptor, &bytes).expect("catalog verifies");

    let list_a_metadata = &verified.chunks[0].metadata;
    assert_eq!(list_a_metadata.catalog_generation, None);
    assert_eq!(list_a_metadata.stream_partition, None);
    assert!(!list_a_metadata.stream_complete);
    assert!(!list_a_metadata.chunk_sealed);
    let list_b_metadata = &verified.chunks[1].metadata;
    assert_eq!(list_b_metadata.catalog_generation, None);
    assert_eq!(list_b_metadata.stream_partition, None);
    assert!(!list_b_metadata.stream_complete);
    assert!(!list_b_metadata.chunk_sealed);

    assert_eq!(descriptor.metadata.catalog_generation, Some(42));
}

#[test]
fn catalog_verification_does_not_restore_omitted_generation_metadata() {
    let scope = scope();
    let mut chunk = chunk_descriptor(scope.clone(), 0, 50);
    chunk.metadata.catalog_generation = Some(7);
    let catalog = IndexedArtifactCatalog {
        format_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
        dataset_kind: IndexedDatasetKind::WalletScan,
        scope: scope.clone(),
        chunks: vec![chunk],
    };
    let bytes = serde_json::to_vec(&catalog).expect("catalog json");
    let descriptor =
        catalog_descriptor_with_metadata(scope, 0, 50, 5, &bytes, catalog_metadata(42));

    let verified = verify_catalog_bytes(&descriptor, &bytes).expect("catalog verifies");

    let metadata = &verified.chunks[0].metadata;
    assert_eq!(metadata.catalog_generation, None);
}

#[test]
fn authoritative_snapshots_replace_ranges_without_historical_merging() {
    let scope = scope();
    let mut old_chunk = chunk_descriptor(scope.clone(), 0, 50);
    old_chunk.cid = "bafy-old-current-chunk".to_string();
    let mut new_chunk = old_chunk.clone();
    new_chunk.cid = "bafy-new-current-chunk".to_string();
    new_chunk.sha256 = FixedBytes::from([0x99; 32]);

    let snapshot = |generation: u64, chunk: IndexedArtifactDescriptor| {
        let mut descriptor = chunk.clone();
        descriptor.cid = format!("bafy-catalog-{generation}");
        descriptor.metadata.catalog_generation = Some(generation);
        IndexedArtifactStreamCatalog::from(VerifiedIndexedArtifactCatalog {
            descriptor,
            catalog: IndexedArtifactCatalog {
                format_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
                dataset_kind: IndexedDatasetKind::WalletScan,
                scope: scope.clone(),
                chunks: vec![chunk],
            },
        })
    };
    let old_snapshot = snapshot(1, old_chunk);
    let new_snapshot = snapshot(2, new_chunk);
    let request = IndexedArtifactStreamPlanRequest::new(
        IndexedDatasetKind::WalletScan,
        scope,
        IndexedArtifactRangeKind::Block,
        0,
        50,
        IndexedArtifactStreamPartitionPolicy::Ignore,
    );

    let old_plan = IndexedArtifactStreamPlan::plan(std::slice::from_ref(&old_snapshot), &request)
        .expect("old snapshot plans independently");
    let new_plan = IndexedArtifactStreamPlan::plan(std::slice::from_ref(&new_snapshot), &request)
        .expect("new snapshot plans independently");
    assert_eq!(
        old_plan.required_current_chunks[0].descriptor.cid,
        "bafy-old-current-chunk"
    );
    assert_eq!(
        new_plan.required_current_chunks[0].descriptor.cid,
        "bafy-new-current-chunk"
    );
    assert!(matches!(
        IndexedArtifactStreamPlan::plan(&[old_snapshot, new_snapshot], &request),
        Err(IndexedArtifactStreamPlanError::SameGenerationOverlap { .. })
    ));
}

#[tokio::test]
async fn fetch_catalog_accepts_format_v1_without_generation() {
    let scope = scope();
    let catalog = IndexedArtifactCatalog {
        format_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
        dataset_kind: IndexedDatasetKind::WalletScan,
        scope: scope.clone(),
        chunks: Vec::new(),
    };
    let bytes = serde_json::to_vec(&catalog).expect("catalog json");
    let cid = raw_cid(&bytes);
    let mut descriptor = catalog_descriptor_with_metadata(
        scope,
        0,
        50,
        0,
        &bytes,
        DatasetDescriptorMetadata::default(),
    );
    descriptor.cid = cid.to_string();
    descriptor.metadata.catalog_generation = None;
    let server = ChunkServer::spawn(HashMap::from([(
        descriptor.cid.clone(),
        ChunkResponse::new(&bytes, Duration::ZERO),
    )]));
    let skipped = ChunkServer::spawn(HashMap::from([(
        descriptor.cid.clone(),
        ChunkResponse::new(&bytes, Duration::ZERO),
    )]));
    let mut source_config = config([7_u8; 32], None);
    source_config.gateway_urls = vec![server.url.clone(), skipped.url.clone()];
    let client = IndexedArtifactManifestClient::new(source_config, reqwest::Client::new());

    let verified = client
        .fetch_catalog(&descriptor)
        .await
        .expect("missing generation is valid for v1");

    assert_eq!(
        verified.catalog.chunks,
        [] as [IndexedArtifactDescriptor; 0]
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        server.request_paths().len() + skipped.request_paths().len(),
        1,
        "catalog should be fetched once across configured gateways"
    );
}

#[tokio::test]
async fn explicit_url_manifest_has_no_preferred_gateway() {
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let scope = scope();
    let mut manifest = manifest_for_scope(scope.clone(), now_ms());
    manifest.sign_manifest(&signing_key).expect("sign manifest");
    let bytes = serde_json::to_vec(&manifest).expect("manifest json");
    let server = PathServer::spawn(HashMap::from([("/manifest".to_string(), bytes)]), 1);
    let url = server.url.join("/manifest").expect("manifest URL");
    let mut source_config = config(signing_key.verifying_key().to_bytes(), None);
    source_config.manifest_source = IndexedArtifactManifestSource::Url(url);
    let client = IndexedArtifactManifestClient::new(source_config, reqwest::Client::new());

    let fetched = client
        .fetch_manifest_with_metadata(&scope, None, UNIX_EPOCH + Duration::from_millis(now_ms()))
        .await
        .expect("explicit URL manifest verifies");

    assert_eq!(fetched.preferred_gateway_index, None);
    assert_eq!(fetched.manifest.sequence, manifest.sequence);
}

#[tokio::test]
async fn fetch_catalog_preferred_gateway_falls_back_after_verification_failure() {
    let scope = scope();
    let catalog = IndexedArtifactCatalog {
        format_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
        dataset_kind: IndexedDatasetKind::WalletScan,
        scope: scope.clone(),
        chunks: Vec::new(),
    };
    let bytes = serde_json::to_vec(&catalog).expect("catalog json");
    let cid = raw_cid(&bytes);
    let mut descriptor = catalog_descriptor_with_metadata(
        scope,
        0,
        50,
        0,
        &bytes,
        DatasetDescriptorMetadata::default(),
    );
    descriptor.cid = cid.to_string();
    let first = ChunkServer::spawn(HashMap::from([(
        descriptor.cid.clone(),
        ChunkResponse::new(&bytes, Duration::ZERO),
    )]));
    let skipped = ChunkServer::spawn(HashMap::from([(
        descriptor.cid.clone(),
        ChunkResponse::new(&bytes, Duration::ZERO),
    )]));
    let preferred = ChunkServer::spawn(HashMap::from([(
        descriptor.cid.clone(),
        ChunkResponse::new(b"wrong catalog bytes", Duration::ZERO),
    )]));
    let mut source_config = config([7_u8; 32], None);
    source_config.gateway_urls = vec![
        first.url.clone(),
        skipped.url.clone(),
        preferred.url.clone(),
    ];
    let client = IndexedArtifactManifestClient::new(source_config, reqwest::Client::new());

    client
        .fetch_catalog_with_preferred_gateway(&descriptor, Some(2))
        .await
        .expect("fallback catalog verifies");

    assert_eq!(preferred.request_paths().len(), 1);
    let healthy_fallback_requests = first.request_paths().len() + skipped.request_paths().len();
    assert_eq!(healthy_fallback_requests, 1);
    assert_eq!(
        preferred.request_paths().len() + healthy_fallback_requests,
        2
    );
}

#[test]
fn chunk_verification_checks_descriptor_hash_and_size() {
    let bytes = b"verified chunk".to_vec();
    let descriptor = chunk_descriptor_for_bytes(scope(), 0, 10, raw_cid(&bytes), &bytes);

    let verified = verify_chunk_bytes(descriptor.clone(), bytes.clone()).expect("chunk verifies");

    assert_eq!(verified.bytes, bytes);

    let mut wrong_size = descriptor.clone();
    wrong_size.byte_size += 1;
    assert!(matches!(
        verify_chunk_bytes(wrong_size, bytes.clone()),
        Err(IndexedArtifactManifestError::ArtifactByteSizeMismatch { .. })
    ));

    let mut wrong_hash = descriptor;
    wrong_hash.sha256 = FixedBytes::from([7_u8; 32]);
    assert!(matches!(
        verify_chunk_bytes(wrong_hash, bytes),
        Err(IndexedArtifactManifestError::ArtifactHashMismatch { .. })
    ));
}

#[tokio::test]
async fn bounded_chunk_fetch_preserves_order_when_responses_complete_out_of_order() {
    let scope = scope();
    let chunk_bytes = vec![
        b"first chunk".to_vec(),
        b"second chunk".to_vec(),
        b"third chunk".to_vec(),
    ];
    let descriptors = descriptors_for_bytes(&scope, &chunk_bytes);
    let server = ChunkServer::spawn(
        descriptors
            .iter()
            .zip(chunk_bytes.iter())
            .map(|(descriptor, bytes)| {
                let delay = if descriptor.range.start == 0 {
                    Duration::from_millis(150)
                } else {
                    Duration::from_millis(20)
                };
                (descriptor.cid.clone(), ChunkResponse::new(bytes, delay))
            })
            .collect(),
    );
    let mut config = config([7_u8; 32], None);
    config.gateway_urls = vec![server.url.clone()];
    config.concurrency = 3;
    config.max_in_flight_bytes = 1024;
    let client = IndexedArtifactManifestClient::new(config, reqwest::Client::new());

    let fetched = client
        .fetch_chunks_bounded(&descriptors)
        .await
        .expect("chunks fetch");

    assert_eq!(
        fetched
            .iter()
            .map(|chunk| chunk.bytes.as_slice())
            .collect::<Vec<_>>(),
        chunk_bytes.iter().map(Vec::as_slice).collect::<Vec<_>>()
    );
    assert!(server.max_active() > 1, "chunks should fetch in parallel");
}

#[tokio::test]
async fn bounded_chunk_fetch_uses_configured_concurrency() {
    let scope = scope();
    let chunk_bytes = vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()];
    let descriptors = descriptors_for_bytes(&scope, &chunk_bytes);
    let server = ChunkServer::spawn(responses_for_descriptors(
        &descriptors,
        &chunk_bytes,
        Duration::from_millis(40),
    ));
    let mut config = config([7_u8; 32], None);
    config.gateway_urls = vec![server.url.clone()];
    config.concurrency = 1;
    config.max_in_flight_bytes = 1024;
    let client = IndexedArtifactManifestClient::new(config, reqwest::Client::new());

    client
        .fetch_chunks_bounded(&descriptors)
        .await
        .expect("chunks fetch");

    assert_eq!(server.max_active(), 1);
}

#[tokio::test]
async fn bounded_chunk_fetch_enforces_in_flight_byte_budget() {
    let scope = scope();
    let chunk_bytes = vec![b"aaaaa".to_vec(), b"bbbbb".to_vec(), b"ccccc".to_vec()];
    let descriptors = descriptors_for_bytes(&scope, &chunk_bytes);
    let server = ChunkServer::spawn(responses_for_descriptors(
        &descriptors,
        &chunk_bytes,
        Duration::from_millis(75),
    ));
    let mut config = config([7_u8; 32], None);
    config.gateway_urls = vec![server.url.clone()];
    config.concurrency = 3;
    config.max_in_flight_bytes = 10;
    let client = IndexedArtifactManifestClient::new(config, reqwest::Client::new());

    let fetched = client
        .fetch_chunks_bounded(&descriptors)
        .await
        .expect("chunks fetch");

    assert_eq!(fetched.len(), descriptors.len());
    assert!(
        server.max_active() <= 2,
        "byte budget should cap active 5-byte chunks at two"
    );
}

#[tokio::test(start_paused = true)]
async fn bounded_chunk_fetch_skips_hedge_without_byte_budget_room() {
    let (task, stalled, serving, byte_size) =
        spawn_chunk_fetch_with_stalled_preferred_gateway(1, 1, ChunkBatchPreference::ChunkHash);

    yield_until("the stalled gateway receives the chunk request", || {
        stalled.request_count() == 1
    })
    .await;
    tokio::time::advance(CHUNK_HEDGE_DELAY).await;
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        serving.request_count(),
        0,
        "no hedge starts without budget room"
    );
    // The first attempt continues until its header timeout, then falls back as before.
    tokio::time::advance(Duration::from_mins(5)).await;
    yield_until("the chunk fetch finishes", || task.is_finished()).await;
    let batch = task
        .await
        .expect("join fetch task")
        .expect("fallback gateway serves the chunk");

    assert_eq!(batch.chunks.len(), 1);
    assert_eq!(serving.request_count(), 1);
    assert_eq!(
        batch.metrics.max_observed_in_flight_bytes, byte_size,
        "a skipped hedge takes no byte charge"
    );
}

#[tokio::test(start_paused = true)]
async fn bounded_chunk_fetch_charges_hedge_to_byte_budget() {
    let (task, stalled, serving, byte_size) =
        spawn_chunk_fetch_with_stalled_preferred_gateway(1, 2, ChunkBatchPreference::ChunkHash);

    yield_until("the stalled gateway receives the chunk request", || {
        stalled.request_count() == 1
    })
    .await;
    tokio::time::advance(CHUNK_HEDGE_DELAY).await;
    yield_until("the chunk fetch finishes", || task.is_finished()).await;
    let batch = task
        .await
        .expect("join fetch task")
        .expect("hedge gateway serves the chunk");

    assert_eq!(batch.chunks.len(), 1);
    assert_eq!(serving.request_count(), 1);
    assert_eq!(
        batch.metrics.max_observed_in_flight_bytes,
        byte_size * 2,
        "the hedge is charged to the byte budget"
    );
}

#[tokio::test]
async fn bounded_chunk_fetch_starts_at_batch_preferred_gateway() {
    // Budget room for a hedge bounds the run if the first request stalls.
    let (task, stalled, serving, _) = spawn_chunk_fetch_with_stalled_preferred_gateway(
        1,
        2,
        ChunkBatchPreference::ServingGateway,
    );

    let batch = task
        .await
        .expect("join fetch task")
        .expect("manifest gateway serves the chunk");

    assert_eq!(batch.chunks.len(), 1);
    assert_eq!(serving.request_count(), 1);
    assert_eq!(
        stalled.request_count(),
        0,
        "the stalled hash-preferred gateway receives no chunk request"
    );
}

#[tokio::test(start_paused = true)]
async fn bounded_chunk_fetch_leaves_stalled_batch_preferred_gateway_after_hedge() {
    // Both chunks also hash-prefer the stalled gateway, so neither keeping the batch
    // preference nor falling back to the hash sends the second chunk elsewhere.
    let started = tokio::time::Instant::now();
    let (task, stalled, serving, _) = spawn_chunk_fetch_with_stalled_preferred_gateway(
        2,
        2,
        ChunkBatchPreference::StalledGateway,
    );

    yield_until(
        "the stalled gateway receives the first chunk request",
        || stalled.request_count() == 1,
    )
    .await;
    tokio::time::advance(CHUNK_HEDGE_DELAY).await;
    yield_until("the chunk fetch finishes", || task.is_finished()).await;
    let batch = task
        .await
        .expect("join fetch task")
        .expect("serving gateway serves both chunks");

    assert_eq!(batch.chunks.len(), 2);
    assert_eq!(
        stalled.request_count(),
        1,
        "the second chunk skips the stalled gateway"
    );
    assert_eq!(serving.request_count(), 2);
    assert_eq!(
        started.elapsed(),
        CHUNK_HEDGE_DELAY,
        "only the first chunk waits for a hedge"
    );
}

#[test]
fn artifact_gateway_preference_uses_descriptor_identity() {
    let scope = scope();
    let mut descriptors = descriptors_for_bytes(&scope, &[b"gateway identity".to_vec()]);
    let mut descriptor = descriptors.pop().expect("descriptor");
    descriptor.sha256.0[0] = 17;

    assert_eq!(preferred_artifact_gateway_index(&descriptor), 17);
}

#[tokio::test]
async fn bounded_chunk_fetch_rejects_invalid_limits_before_network() {
    let scope = scope();
    let bytes = b"oversized".to_vec();
    let descriptor = chunk_descriptor_for_bytes(scope, 0, 1, raw_cid(&bytes), &bytes);
    let mut source_config = config([7_u8; 32], None);
    source_config.concurrency = 0;
    let client = IndexedArtifactManifestClient::new(source_config, reqwest::Client::new());

    let zero_concurrency = client
        .fetch_chunks_bounded(std::slice::from_ref(&descriptor))
        .await
        .expect_err("zero concurrency rejected");
    assert!(matches!(
        zero_concurrency,
        IndexedArtifactManifestError::InvalidChunkConcurrency
    ));

    let mut source_config = config([7_u8; 32], None);
    source_config.max_in_flight_bytes = 1;
    let client = IndexedArtifactManifestClient::new(source_config, reqwest::Client::new());
    let oversized = client
        .fetch_chunks_bounded(&[descriptor])
        .await
        .expect_err("oversized chunk rejected");
    assert!(matches!(
        oversized,
        IndexedArtifactManifestError::ChunkExceedsInFlightBudget { .. }
    ));
}

#[tokio::test]
async fn bounded_chunk_fetch_rejects_advertised_decoded_size_before_network() {
    let bytes = b"oversized decoded envelope".to_vec();
    let mut descriptor = chunk_descriptor_for_bytes(scope(), 0, 1, raw_cid(&bytes), &bytes);
    descriptor.metadata.decoded_envelope_byte_size =
        Some(IndexedDatasetKind::WalletScan.decoded_envelope_byte_limit() + 1);
    let client =
        IndexedArtifactManifestClient::new(config([7_u8; 32], None), reqwest::Client::new());

    let error = client
        .fetch_chunks_bounded(&[descriptor])
        .await
        .expect_err("oversized decoded envelope rejected before retrieval");

    assert!(matches!(
        error,
        IndexedArtifactManifestError::ChunkDecodedEnvelopeTooLarge {
            actual,
            maximum: INDEXED_ARTIFACT_WALLET_SCAN_MAX_DECODED_ENVELOPE_BYTES,
        } if actual == INDEXED_ARTIFACT_WALLET_SCAN_MAX_DECODED_ENVELOPE_BYTES + 1
    ));
}

#[tokio::test]
async fn bounded_chunk_fetch_charges_legacy_descriptor_by_compressed_size() {
    let bytes = b"legacy descriptor".to_vec();
    let mut descriptor = chunk_descriptor_for_bytes(scope(), 0, 1, raw_cid(&bytes), &bytes);
    descriptor.metadata.decoded_envelope_byte_size = None;
    let mut source_config = config([7_u8; 32], None);
    source_config.max_in_flight_bytes = descriptor.byte_size;
    let client = IndexedArtifactManifestClient::new(source_config, reqwest::Client::new());

    let error = client
        .fetch_chunks_bounded(&[descriptor])
        .await
        .expect_err("missing gateway rejects after byte-budget admission");

    assert!(!matches!(
        error,
        IndexedArtifactManifestError::ChunkExceedsInFlightBudget { .. }
    ));
}

#[test]
fn stager_holds_later_chunks_until_gap_is_filled() {
    let scope = scope();
    let mut stager = VerifiedIndexedArtifactChunkStager::new(
        IndexedDatasetKind::PublicTxid,
        scope.clone(),
        IndexedArtifactRangeKind::TxidIndex,
        0,
    );

    stager
        .stage(verified_chunk(
            chunk_descriptor_for_dataset(
                IndexedDatasetKind::PublicTxid,
                IndexedArtifactRangeKind::TxidIndex,
                scope.clone(),
                10,
                19,
            ),
            b"later".to_vec(),
        ))
        .expect("stage later chunk");

    assert_eq!(
        stager.drain_contiguous().expect("drain"),
        [] as [VerifiedIndexedArtifactChunk; 0]
    );
    assert_eq!(stager.next_range_start(), 0);
    assert_eq!(stager.staged_len(), 1);

    stager
        .stage(verified_chunk(
            chunk_descriptor_for_dataset(
                IndexedDatasetKind::PublicTxid,
                IndexedArtifactRangeKind::TxidIndex,
                scope,
                0,
                9,
            ),
            b"first".to_vec(),
        ))
        .expect("stage first chunk");

    let ready = stager.drain_contiguous().expect("drain ready chunks");

    assert_eq!(
        ready
            .iter()
            .map(|chunk| (chunk.descriptor.range.start, chunk.descriptor.range.end))
            .collect::<Vec<_>>(),
        vec![(0, 9), (10, 19)]
    );
    assert_eq!(stager.next_range_start(), 20);
    assert!(stager.is_empty());
}

#[test]
fn stager_rejects_mismatched_and_overlapping_chunks() {
    let scope = scope();
    let mut stager = VerifiedIndexedArtifactChunkStager::new(
        IndexedDatasetKind::WalletScan,
        scope.clone(),
        IndexedArtifactRangeKind::Block,
        10,
    );

    let before_progress = stager
        .stage(verified_chunk(
            chunk_descriptor_for_dataset(
                IndexedDatasetKind::WalletScan,
                IndexedArtifactRangeKind::Block,
                scope.clone(),
                0,
                9,
            ),
            Vec::new(),
        ))
        .expect_err("past progress rejected");
    assert!(matches!(
        before_progress,
        IndexedArtifactManifestError::StagedChunkBeforeProgress { .. }
    ));

    let wrong_dataset = stager
        .stage(verified_chunk(
            chunk_descriptor_for_dataset(
                IndexedDatasetKind::PublicTxid,
                IndexedArtifactRangeKind::Block,
                scope.clone(),
                10,
                19,
            ),
            Vec::new(),
        ))
        .expect_err("wrong dataset rejected");
    assert!(matches!(
        wrong_dataset,
        IndexedArtifactManifestError::StagedChunkDatasetMismatch { .. }
    ));

    stager
        .stage(verified_chunk(
            chunk_descriptor_for_dataset(
                IndexedDatasetKind::WalletScan,
                IndexedArtifactRangeKind::Block,
                scope.clone(),
                10,
                20,
            ),
            Vec::new(),
        ))
        .expect("stage first chunk");

    let overlap = stager
        .stage(verified_chunk(
            chunk_descriptor_for_dataset(
                IndexedDatasetKind::WalletScan,
                IndexedArtifactRangeKind::Block,
                scope,
                20,
                30,
            ),
            Vec::new(),
        ))
        .expect_err("overlap rejected");
    assert!(matches!(
        overlap,
        IndexedArtifactManifestError::StagedChunkRangeOverlap { .. }
    ));
}

#[test]
fn stager_rejects_partial_stale_chunk_without_blocking_progress() {
    let scope = scope();
    let mut stager = VerifiedIndexedArtifactChunkStager::new(
        IndexedDatasetKind::WalletScan,
        scope.clone(),
        IndexedArtifactRangeKind::Block,
        10,
    );

    let partial_stale = stager
        .stage(verified_chunk(
            chunk_descriptor_for_dataset(
                IndexedDatasetKind::WalletScan,
                IndexedArtifactRangeKind::Block,
                scope.clone(),
                5,
                15,
            ),
            Vec::new(),
        ))
        .expect_err("partially stale chunk rejected");
    assert!(matches!(
        partial_stale,
        IndexedArtifactManifestError::StagedChunkBeforeProgress { .. }
    ));
    assert_eq!(stager.staged_len(), 0);

    stager
        .stage(verified_chunk(
            chunk_descriptor_for_dataset(
                IndexedDatasetKind::WalletScan,
                IndexedArtifactRangeKind::Block,
                scope,
                10,
                15,
            ),
            Vec::new(),
        ))
        .expect("exact next chunk stages");

    let ready = stager.drain_contiguous().expect("drain exact chunk");

    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].descriptor.range.start, 10);
    assert_eq!(ready[0].descriptor.range.end, 15);
    assert_eq!(stager.next_range_start(), 16);
    assert!(stager.is_empty());
}

fn manifest_for_scope(scope: ChainScope, issued_at_ms: u64) -> IndexedArtifactManifest {
    IndexedArtifactManifest::new(
        issued_at_ms,
        10,
        PublisherIdentity::ed25519(FixedBytes::ZERO),
        vec![IndexedArtifactChainEntry {
            latest_indexed: vec![LatestIndexedHeight {
                dataset_kind: IndexedDatasetKind::WalletScan,
                block_number: 100,
                block_hash: FixedBytes::from([9_u8; 32]),
            }],
            catalogs: vec![IndexedArtifactDescriptor {
                dataset_kind: IndexedDatasetKind::WalletScan,
                scope: scope.clone(),
                range: IndexedArtifactRange {
                    kind: IndexedArtifactRangeKind::Block,
                    start: 0,
                    end: 100,
                },
                row_count: 5,
                cid: "bafycatalog".to_string(),
                sha256: FixedBytes::from([4_u8; 32]),
                byte_size: 256,
                encoding_version: INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION,
                compression: CompressionAlgorithm::Zstd,
                metadata: DatasetDescriptorMetadata::default(),
            }],
            scope,
        }],
    )
}

fn catalog_descriptor(
    scope: ChainScope,
    start: u64,
    end: u64,
    bytes: &[u8],
) -> IndexedArtifactDescriptor {
    catalog_descriptor_with_metadata(scope, start, end, 5, bytes, catalog_metadata(1))
}

fn catalog_descriptor_with_metadata(
    scope: ChainScope,
    start: u64,
    end: u64,
    row_count: u64,
    bytes: &[u8],
    metadata: DatasetDescriptorMetadata,
) -> IndexedArtifactDescriptor {
    catalog_descriptor_for_dataset_with_metadata(
        IndexedDatasetKind::WalletScan,
        IndexedArtifactRangeKind::Block,
        scope,
        start,
        end,
        row_count,
        bytes,
        metadata,
    )
}

#[allow(clippy::too_many_arguments)]
fn catalog_descriptor_for_dataset_with_metadata(
    dataset_kind: IndexedDatasetKind,
    range_kind: IndexedArtifactRangeKind,
    scope: ChainScope,
    start: u64,
    end: u64,
    row_count: u64,
    bytes: &[u8],
    metadata: DatasetDescriptorMetadata,
) -> IndexedArtifactDescriptor {
    IndexedArtifactDescriptor {
        dataset_kind,
        scope,
        range: IndexedArtifactRange {
            kind: range_kind,
            start,
            end,
        },
        row_count,
        cid: "bafycatalog".to_string(),
        sha256: FixedBytes::from_slice(&Sha256::digest(bytes)),
        byte_size: u64::try_from(bytes.len()).expect("catalog size"),
        encoding_version: INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION,
        compression: CompressionAlgorithm::Zstd,
        metadata,
    }
}

fn catalog_metadata(generation: u64) -> DatasetDescriptorMetadata {
    DatasetDescriptorMetadata {
        catalog_generation: Some(generation),
        ..DatasetDescriptorMetadata::default()
    }
}

fn chunk_descriptor(scope: ChainScope, start: u64, end: u64) -> IndexedArtifactDescriptor {
    IndexedArtifactDescriptor {
        dataset_kind: IndexedDatasetKind::WalletScan,
        scope,
        range: IndexedArtifactRange {
            kind: IndexedArtifactRangeKind::Block,
            start,
            end,
        },
        row_count: 5,
        cid: "bafychunk".to_string(),
        sha256: FixedBytes::from([5_u8; 32]),
        byte_size: 128,
        encoding_version: INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION,
        compression: CompressionAlgorithm::Zstd,
        metadata: DatasetDescriptorMetadata::default(),
    }
}

fn descriptors_for_bytes(scope: &ChainScope, chunks: &[Vec<u8>]) -> Vec<IndexedArtifactDescriptor> {
    chunks
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            let start = u64::try_from(index).expect("index fits") * 10;
            chunk_descriptor_for_bytes(scope.clone(), start, start + 10, raw_cid(bytes), bytes)
        })
        .collect()
}

fn chunk_descriptor_for_bytes(
    scope: ChainScope,
    start: u64,
    end: u64,
    cid: Cid,
    bytes: &[u8],
) -> IndexedArtifactDescriptor {
    IndexedArtifactDescriptor {
        dataset_kind: IndexedDatasetKind::WalletScan,
        scope,
        range: IndexedArtifactRange {
            kind: IndexedArtifactRangeKind::Block,
            start,
            end,
        },
        row_count: 5,
        cid: cid.to_string(),
        sha256: FixedBytes::from_slice(&Sha256::digest(bytes)),
        byte_size: u64::try_from(bytes.len()).expect("chunk size"),
        encoding_version: INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION,
        compression: CompressionAlgorithm::Zstd,
        metadata: DatasetDescriptorMetadata {
            decoded_envelope_byte_size: Some(
                u64::try_from(bytes.len()).expect("decoded envelope size"),
            ),
            ..DatasetDescriptorMetadata::default()
        },
    }
}

fn chunk_descriptor_for_dataset(
    dataset_kind: IndexedDatasetKind,
    range_kind: IndexedArtifactRangeKind,
    scope: ChainScope,
    start: u64,
    end: u64,
) -> IndexedArtifactDescriptor {
    IndexedArtifactDescriptor {
        dataset_kind,
        scope,
        range: IndexedArtifactRange {
            kind: range_kind,
            start,
            end,
        },
        row_count: end.saturating_sub(start).saturating_add(1),
        cid: format!("bafychunk{start}"),
        sha256: FixedBytes::from([5_u8; 32]),
        byte_size: 0,
        encoding_version: INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION,
        compression: CompressionAlgorithm::Zstd,
        metadata: DatasetDescriptorMetadata::default(),
    }
}

fn verified_chunk(
    descriptor: IndexedArtifactDescriptor,
    bytes: Vec<u8>,
) -> VerifiedIndexedArtifactChunk {
    VerifiedIndexedArtifactChunk { descriptor, bytes }
}

fn responses_for_descriptors(
    descriptors: &[IndexedArtifactDescriptor],
    chunks: &[Vec<u8>],
    delay: Duration,
) -> HashMap<String, ChunkResponse> {
    descriptors
        .iter()
        .zip(chunks.iter())
        .map(|(descriptor, bytes)| (descriptor.cid.clone(), ChunkResponse::new(bytes, delay)))
        .collect()
}

pub(crate) fn raw_cid(bytes: &[u8]) -> Cid {
    Cid::new_v1(RAW_CODEC, Code::Sha2_256.digest(bytes))
}

pub(crate) fn car_bytes(root: Cid, blocks: &[(Cid, Vec<u8>)]) -> Vec<u8> {
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
        24..=0xff => {
            out.extend_from_slice(&[major | 0x18, u8::try_from(len).expect("u8 len")]);
        }
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

#[derive(Clone)]
struct ChunkResponse {
    body: Vec<u8>,
    delay: Duration,
}

impl ChunkResponse {
    fn new(bytes: &[u8], delay: Duration) -> Self {
        let cid = raw_cid(bytes);
        Self {
            body: car_bytes(cid, &[(cid, bytes.to_vec())]),
            delay,
        }
    }
}

struct ChunkServer {
    url: Url,
    max_active: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<String>>>,
}

impl ChunkServer {
    fn spawn(responses: HashMap<String, ChunkResponse>) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind server");
        let url = Url::parse(&format!(
            "http://{}",
            listener.local_addr().expect("local addr")
        ))
        .expect("server URL");
        let responses = Arc::new(responses);
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let request_count = responses.len();
        std::thread::spawn({
            let responses = Arc::clone(&responses);
            let active = Arc::clone(&active);
            let max_active = Arc::clone(&max_active);
            let requests = Arc::clone(&requests);
            move || {
                for _ in 0..request_count {
                    let (stream, _) = listener.accept().expect("accept request");
                    let responses = Arc::clone(&responses);
                    let active = Arc::clone(&active);
                    let max_active = Arc::clone(&max_active);
                    let requests = Arc::clone(&requests);
                    std::thread::spawn(move || {
                        handle_chunk_request(stream, &responses, &active, &max_active, &requests);
                    });
                }
            }
        });

        Self {
            url,
            max_active,
            requests,
        }
    }

    fn max_active(&self) -> usize {
        self.max_active.load(AtomicOrdering::SeqCst)
    }

    fn request_paths(&self) -> Vec<String> {
        self.requests.lock().expect("requests lock").clone()
    }
}

/// Serves `routes` on every connection and records each request path. The
/// first `stalled` connections get no response until the client drops them.
pub(crate) struct ManifestGateway {
    pub(crate) url: Url,
    requests: Arc<Mutex<Vec<String>>>,
}

impl ManifestGateway {
    pub(crate) fn spawn(routes: HashMap<String, Vec<u8>>, stalled: usize) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind server");
        let url = Url::parse(&format!(
            "http://{}",
            listener.local_addr().expect("local addr")
        ))
        .expect("server URL");
        let routes = Arc::new(routes);
        let requests = Arc::new(Mutex::new(Vec::new()));
        std::thread::spawn({
            let requests = Arc::clone(&requests);
            move || {
                for (index, stream) in listener.incoming().enumerate() {
                    let Ok(mut stream) = stream else {
                        return;
                    };
                    let routes = Arc::clone(&routes);
                    let requests = Arc::clone(&requests);
                    std::thread::spawn(move || {
                        let path = read_request_path(&mut stream);
                        requests.lock().expect("requests lock").push(path.clone());
                        if index < stalled {
                            // Hold the request until the client drops the connection.
                            let _ = std::io::copy(&mut stream, &mut std::io::sink());
                        } else {
                            write_path_response(&mut stream, &routes, &path);
                        }
                    });
                }
            }
        });

        Self { url, requests }
    }

    pub(crate) fn request_paths(&self) -> Vec<String> {
        self.requests.lock().expect("requests lock").clone()
    }

    pub(crate) fn request_count(&self) -> usize {
        self.requests.lock().expect("requests lock").len()
    }

    pub(crate) async fn wait_for_requests(&self, count: usize) {
        while self.request_count() < count {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

fn signed_manifest(
    signing_key: &SigningKey,
    scope: &ChainScope,
) -> (IndexedArtifactManifest, Vec<u8>) {
    let mut manifest = manifest_for_scope(scope.clone(), now_ms());
    manifest.sign_manifest(signing_key).expect("sign manifest");
    let bytes = serde_json::to_vec(&manifest).expect("manifest JSON");
    (manifest, bytes)
}

/// A manifest CID source with one recording gateway that serves `manifest_bytes`.
fn recorded_cid_manifest_source(
    signing_key: &SigningKey,
    manifest_bytes: Vec<u8>,
    max_manifest_age: Option<Duration>,
    stalled: usize,
) -> (IndexedArtifactSourceConfig, ManifestGateway) {
    let manifest_cid = raw_cid(&manifest_bytes);
    let gateway = ManifestGateway::spawn(
        HashMap::from([(format!("/ipfs/{manifest_cid}?format=raw"), manifest_bytes)]),
        stalled,
    );
    let mut config = config(signing_key.verifying_key().to_bytes(), max_manifest_age);
    config.manifest_source = IndexedArtifactManifestSource::Cid(manifest_cid.to_string());
    config.gateway_urls = vec![gateway.url.clone()];
    (config, gateway)
}

/// The batch preference passed to a chunk fetch with a stalled gateway.
#[derive(Clone, Copy)]
enum ChunkBatchPreference {
    /// No batch preference: each chunk starts at its hash-preferred gateway.
    ChunkHash,
    /// The serving gateway, as when that gateway served the manifest.
    ServingGateway,
    /// The stalled gateway, as when it served the manifest but stalls on chunks.
    StalledGateway,
}

/// Spawns a fetch of `chunk_count` equal-sized chunks that all hash-prefer a
/// gateway that never answers; the other gateway serves every chunk. The
/// stalled gateway holds its first request, or every request when the batch
/// prefers it. The byte budget holds `budget_charges` charges of one chunk's
/// size, and chunk concurrency is one.
fn spawn_chunk_fetch_with_stalled_preferred_gateway(
    chunk_count: usize,
    budget_charges: u64,
    preference: ChunkBatchPreference,
) -> (
    tokio::task::JoinHandle<Result<IndexedArtifactChunkFetchBatch, IndexedArtifactManifestError>>,
    ManifestGateway,
    ManifestGateway,
    u64,
) {
    let hash_gateway_index = |bytes: &Vec<u8>| {
        let descriptor = descriptors_for_bytes(&scope(), std::slice::from_ref(bytes)).remove(0);
        preferred_artifact_gateway_index(&descriptor) % 2
    };
    let mut payloads =
        (0_usize..).map(|n| format!("hedged indexed artifact chunk {n:04}").into_bytes());
    let first = payloads.next().expect("first chunk payload");
    let stalled_index = hash_gateway_index(&first);
    let chunks = std::iter::once(first)
        .chain(payloads.filter(|bytes| hash_gateway_index(bytes) == stalled_index))
        .take(chunk_count)
        .collect::<Vec<_>>();
    let descriptors = descriptors_for_bytes(&scope(), &chunks);
    let routes = chunks
        .into_iter()
        .map(|bytes| {
            let cid = raw_cid(&bytes);
            (
                format!("/ipfs/{cid}?format=car&dag-scope=entity"),
                car_bytes(cid, &[(cid, bytes)]),
            )
        })
        .collect::<HashMap<_, _>>();
    let (stalled_requests, preferred_gateway_index) = match preference {
        ChunkBatchPreference::ChunkHash => (1, None),
        ChunkBatchPreference::ServingGateway => (1, Some(1 - stalled_index)),
        ChunkBatchPreference::StalledGateway => (usize::MAX, Some(stalled_index)),
    };
    let stalled = ManifestGateway::spawn(routes.clone(), stalled_requests);
    let serving = ManifestGateway::spawn(routes, 0);
    let mut gateway_urls = vec![serving.url.clone()];
    gateway_urls.insert(stalled_index, stalled.url.clone());
    let byte_size = descriptors[0].byte_size;
    let mut config = config([7_u8; 32], None);
    config.gateway_urls = gateway_urls;
    config.concurrency = 1;
    config.max_in_flight_bytes = byte_size * budget_charges;
    let client = IndexedArtifactManifestClient::new(config, reqwest::Client::new());
    let task = tokio::spawn(async move {
        client
            .fetch_chunks_bounded_with_verified_progress(
                &descriptors,
                preferred_gateway_index,
                |_, _, _| {},
            )
            .await
    });
    (task, stalled, serving, byte_size)
}

/// Yields until `condition` holds, without letting paused time advance.
pub(crate) async fn yield_until(what: &str, mut condition: impl FnMut() -> bool) {
    for _ in 0..100_000 {
        if condition() {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("timed out waiting until {what}");
}

struct PathServer {
    url: Url,
}

impl PathServer {
    fn spawn(routes: HashMap<String, Vec<u8>>, request_count: usize) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind server");
        let url = Url::parse(&format!(
            "http://{}",
            listener.local_addr().expect("local addr")
        ))
        .expect("server URL");
        let routes = Arc::new(routes);
        std::thread::spawn({
            let routes = Arc::clone(&routes);
            move || {
                for _ in 0..request_count {
                    let (stream, _) = listener.accept().expect("accept request");
                    let routes = Arc::clone(&routes);
                    std::thread::spawn(move || handle_path_request(stream, &routes));
                }
            }
        });

        Self { url }
    }
}

fn handle_chunk_request(
    mut stream: std::net::TcpStream,
    responses: &HashMap<String, ChunkResponse>,
    active: &AtomicUsize,
    max_active: &AtomicUsize,
    requests: &Mutex<Vec<String>>,
) {
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
    let path = request_text
        .split_whitespace()
        .nth(1)
        .expect("request path")
        .to_string();
    requests.lock().expect("requests lock").push(path.clone());
    let cid = path
        .strip_prefix("/ipfs/")
        .and_then(|path| path.split('?').next())
        .expect("CID path");
    let response = responses.get(cid).expect("registered response");
    let current = active.fetch_add(1, AtomicOrdering::SeqCst) + 1;
    max_active.fetch_max(current, AtomicOrdering::SeqCst);
    std::thread::sleep(response.delay);

    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.body.len()
    );
    stream.write_all(headers.as_bytes()).expect("headers");
    stream.write_all(&response.body).expect("body");
    active.fetch_sub(1, AtomicOrdering::SeqCst);
}

fn handle_path_request(mut stream: std::net::TcpStream, routes: &HashMap<String, Vec<u8>>) {
    let path = read_request_path(&mut stream);
    write_path_response(&mut stream, routes, &path);
}

fn write_path_response(
    stream: &mut std::net::TcpStream,
    routes: &HashMap<String, Vec<u8>>,
    path: &str,
) {
    let (status, reason, body) = routes
        .get(path)
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

pub(crate) fn test_ipns_keypair() -> Keypair {
    Keypair::ed25519_from_bytes([9_u8; 32]).expect("test keypair")
}

pub(crate) fn ipns_name(keypair: &Keypair) -> String {
    let peer_id = keypair.public().to_peer_id();
    Cid::new_v1(LIBP2P_KEY_CODEC, *peer_id.as_ref()).to_string()
}

pub(crate) fn ipns_record(keypair: &Keypair, value: String, sequence: u64) -> Vec<u8> {
    rust_ipns::Record::new(
        keypair,
        value,
        Utc::now() + chrono::Duration::seconds(60 * 60 * 24 * 365),
        sequence,
        Duration::from_nanos(60),
    )
    .expect("IPNS record")
    .encode()
    .expect("encoded IPNS record")
}

pub(crate) fn scope() -> ChainScope {
    ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"
            .parse()
            .expect("scope address"),
    }
}

pub(crate) fn config(
    pubkey: [u8; 32],
    max_manifest_age: Option<Duration>,
) -> IndexedArtifactSourceConfig {
    IndexedArtifactSourceConfig {
        trusted_publisher_pubkey: FixedBytes::from(pubkey),
        manifest_source: IndexedArtifactManifestSource::Cid("bafymanifest".to_string()),
        gateway_urls: Vec::new(),
        gateway_pool: None,
        manifest_reuse: IndexedArtifactManifestReuse::default(),
        max_manifest_age,
        concurrency: 6,
        max_in_flight_bytes: 64 * 1024 * 1024,
        amount_statistics_ipns_name: None,
    }
}

const fn now_ms() -> u64 {
    1_700_000_000_000
}
