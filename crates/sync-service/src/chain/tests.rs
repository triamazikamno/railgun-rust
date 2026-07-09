use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, mpsc as std_mpsc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::primitives::{Address, FixedBytes};
use alloy::sol_types::SolEvent;
use broadcaster_core::query_rpc_pool::QueryRpcPool;
use broadcaster_core::transact::DEFAULT_TXID_VERSION;
use cid::Cid;
use ed25519_dalek::SigningKey;
use local_db::{DbConfig, DbStore};
use merkletree::tree::MerkleForest;
use multihash_codetable::{Code, MultihashDigest};
use railgun_wallet::scan::WalletScanInputRows;
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock, broadcast, mpsc, watch};
use tokio_util::sync::CancellationToken;
use url::Url;

use super::service::{
    await_live_log_task_shutdown, send_wallet_scan_apply, send_wallet_target,
    wait_for_startup_sync_target, wait_for_wallet_ready,
};
use super::{
    ChainError, ChainPublicDataPlane, ChainService, CommitmentBatch, ForestReorgDecision,
    GeneratedCommitmentBatch, IndexedWalletArtifactProbe, IndexedWalletCatchUpSourceOrder,
    IndexedWalletPageKind, Nullified, Nullifiers, PublicCoverageAnswer,
    PublicDataPlaneDiagnosticKind, PublicDataPlaneError, PublicPoiCorpusKey,
    PublicScanCoverageWrite, PublicScanRange, PublicScanRowsAnswer, PublicScanSource,
    RailgunLegacyShieldEvents, Shield, Transact, WalletBackfill, WalletTailFallbackState,
    WalletWorkerServices, artifact_failure_can_fallback_to_squid,
    combined_log_event_signatures_for_range, complete_stream_checkpoint,
    drain_pending_backfill_requests, pending_tip_from_block, pending_tip_provider_covers_target,
    send_wallet_startup_events, should_hedge_wallet_startup, spawn_backfill_loop,
    spawn_wallet_worker, squid_tail_target_after_artifact, wallet_backfill_from_block,
    wallet_backfill_lag_blocks, wallet_finish_result_removes_cursor,
    wallet_reorg_backfill_from_block, wallet_startup_hedge_block_count, wallet_sync_target,
    wallet_tail_fallback_lag_threshold_blocks,
};
use crate::indexed_artifacts::{
    ChainScope, ChainType, CompressionAlgorithm, DatasetDescriptorMetadata,
    INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION, INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION,
    INDEXED_ARTIFACT_CHUNK_MAGIC, IndexedArtifactCatalog, IndexedArtifactChainEntry,
    IndexedArtifactDescriptor, IndexedArtifactManifest, IndexedArtifactRange,
    IndexedArtifactRangeKind, IndexedDatasetKind, LatestIndexedHeight, PublisherIdentity,
};
use crate::types::{
    BackfillEvent, BackfillRequest, ChainConfig, ChainKey, GlobalPoiPolicy,
    IndexedArtifactManifestSource, IndexedArtifactSourceConfig, LogBatch,
    PoiArtifactManifestSource, PoiArtifactSourceConfig, PoiProxyFallback,
    WalletBackfillApplyResult, WalletBackfillFinishResult, WalletBackfillLease,
    WalletBackfillRejectReason, WalletConfig, WalletIndexedCatchUpSource, WalletReadiness,
    WalletReadinessError, WalletScanApply, WalletScanRowsPayload, WalletSyncToken,
};
use crate::types::{PublicDataPlaneEpoch, PublicScanReadScope};
use crate::wallet::WalletPoiRuntime;

fn test_wallet_backfill(target_block: u64, follow_safe_head: bool) -> WalletBackfill {
    let (sender, _receiver) = mpsc::channel(1);
    WalletBackfill::new(
        100,
        target_block,
        follow_safe_head,
        100,
        test_backfill_lease(sender, 0, 1),
        std::time::Instant::now(),
    )
}

fn test_poi_artifact_source_config() -> PoiArtifactSourceConfig {
    PoiArtifactSourceConfig {
        trusted_publisher_pubkey: FixedBytes::from([0x42; 32]),
        manifest_source: PoiArtifactManifestSource::Url(
            Url::parse("http://127.0.0.1:1/poi-manifest.json").expect("POI manifest URL"),
        ),
        gateway_urls: Vec::new(),
        max_manifest_age: None,
    }
}

fn test_proxy_poi_policy() -> GlobalPoiPolicy {
    GlobalPoiPolicy::PoiProxy {
        rpc_url: Url::parse("http://127.0.0.1:1").expect("POI RPC URL"),
    }
}

fn test_wallet_poi_runtime() -> WalletPoiRuntime {
    WalletPoiRuntime::from_policy(&test_proxy_poi_policy(), None)
}

fn test_indexed_poi_policy() -> GlobalPoiPolicy {
    GlobalPoiPolicy::IndexedArtifacts {
        artifact_source: test_poi_artifact_source_config(),
        rpc_url: Url::parse("http://127.0.0.1:1").expect("POI RPC URL"),
        wallet_read_fallback: PoiProxyFallback::Disabled,
    }
}

fn test_sync_token(reset_generation: u64, job_id: u64) -> WalletSyncToken {
    WalletSyncToken::for_test(1, 1, reset_generation, job_id)
}

fn test_backfill_lease(
    sender: mpsc::Sender<BackfillEvent>,
    reset_generation: u64,
    job_id: u64,
) -> WalletBackfillLease {
    WalletBackfillLease::from_token(test_sync_token(reset_generation, job_id), sender)
}

fn test_scope() -> ChainScope {
    ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::ZERO,
    }
}

#[test]
fn complete_stream_checkpoint_uses_target_for_non_full_pages() {
    let checkpoint = complete_stream_checkpoint(2, 10, 100, [20_u64, 40].into_iter());

    assert_eq!(checkpoint, 100);
}

#[test]
fn complete_stream_checkpoint_stops_before_partial_final_block() {
    let checkpoint = complete_stream_checkpoint(3, 3, 100, [20_u64, 25, 25].into_iter());

    assert_eq!(checkpoint, 24);
}

#[test]
fn wallet_backfill_starts_after_indexed_checkpoint() {
    assert_eq!(wallet_backfill_from_block(99, 10), 100);
    assert_eq!(wallet_backfill_from_block(0, 10), 10);
}

#[test]
fn open_ended_wallet_backfill_target_tracks_safe_head() {
    let mut cursor = test_wallet_backfill(100, true);

    cursor.refresh_target(105);
    assert_eq!(cursor.target_block, 105);

    cursor.refresh_target(103);
    assert_eq!(cursor.target_block, 105);
}

#[test]
fn fixed_wallet_backfill_target_does_not_follow_safe_head() {
    let mut cursor = test_wallet_backfill(100, false);

    cursor.refresh_target(105);

    assert_eq!(cursor.target_block, 100);
}

#[test]
fn zero_wallet_backfill_target_initializes_from_safe_head() {
    let mut cursor = test_wallet_backfill(0, false);

    cursor.refresh_target(105);

    assert_eq!(cursor.target_block, 105);
}

#[test]
fn wallet_backfill_persistence_retry_keeps_replay_start() {
    let now = std::time::Instant::now();
    let mut cursor = WalletBackfill::new(
        100,
        120,
        false,
        100,
        test_backfill_lease(mpsc::channel(1).0, 1, 1),
        now,
    );

    cursor.retry_after_rejected_apply(120, now);

    assert_eq!(cursor.from_block, 100);
}

#[test]
fn wallet_backfill_retryable_finish_rewinds_cursor_instead_of_removing() {
    let now = std::time::Instant::now();
    let mut cursor = WalletBackfill::new(
        121,
        120,
        false,
        100,
        test_backfill_lease(mpsc::channel(1).0, 1, 1),
        now,
    );
    let result = WalletBackfillFinishResult::Rejected {
        committed_to: 120,
        reason: WalletBackfillRejectReason::PersistenceFailed,
    };

    assert!(!wallet_finish_result_removes_cursor(&result));
    cursor.retry_after_rejected_finish(result.committed_to(), now);

    assert_eq!(cursor.from_block, 100);
}

#[test]
fn wallet_backfill_terminal_finish_results_remove_cursor() {
    assert!(wallet_finish_result_removes_cursor(
        &WalletBackfillFinishResult::Ready { committed_to: 120 }
    ));
    assert!(wallet_finish_result_removes_cursor(
        &WalletBackfillFinishResult::Rejected {
            committed_to: 120,
            reason: WalletBackfillRejectReason::Shutdown,
        }
    ));
    assert!(wallet_finish_result_removes_cursor(
        &WalletBackfillFinishResult::Rejected {
            committed_to: 120,
            reason: WalletBackfillRejectReason::StaleGeneration {
                expected: 2,
                actual: 1,
            },
        }
    ));
}

#[tokio::test]
async fn concurrent_register_wallet_returns_single_actor_handle() {
    let root_dir = temp_db_root("concurrent-register-wallet");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::ZERO,
    };
    let rpc_url = Url::parse("http://127.0.0.1:1").expect("rpc url");
    let chain = ChainConfig {
        chain_id: scope.chain_id,
        contract: scope.railgun_contract,
        rpcs: Arc::new(QueryRpcPool::new(
            vec![rpc_url.clone()],
            Duration::from_secs(1),
        )),
        archive_rpc_url: None,
        archive_until_block: 0,
        deployment_block: 0,
        v2_start_block: 0,
        legacy_shield_block: 0,
        block_range: 100,
        indexed_wallet_block_range: 100,
        poll_interval: Duration::from_millis(1),
        finality_depth: 0,
        quick_sync_endpoint: None,
        indexed_artifact_source: None,
        anchor_interval: 1000,
        anchor_retention: 5,
        http_client: None,
        progress_tx: None,
    };
    let (head_tx, _head_rx) = watch::channel(0);
    let (safe_head_tx, _safe_head_rx) = watch::channel(0);
    let (forest_last_tx, _forest_last_rx) = watch::channel(0);
    let (live_log_tx, _live_log_rx) = broadcast::channel(8);
    let (backfill_tx, _backfill_rx) = mpsc::channel(8);
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = Arc::new(ChainService {
        chain,
        poi_policy: test_proxy_poi_policy(),
        db: Arc::clone(&db),
        forest: Arc::new(RwLock::new(MerkleForest::new())),
        head_tx,
        safe_head_tx,
        forest_last_tx,
        live_log_tx,
        backfill_tx,
        archive_provider: None,
        wallets: RwLock::new(HashMap::new()),
        wallet_registration_gates: Mutex::new(HashMap::new()),
        cancel: CancellationToken::new(),
        live_log_task: Mutex::new(None),
        anchor_last: std::sync::atomic::AtomicU64::new(0),
        txid_public_cache_started: std::sync::atomic::AtomicBool::new(false),
        wallet_actor_next: std::sync::atomic::AtomicU64::new(1),
        wallet_reset_intent_next: std::sync::atomic::AtomicU64::new(1),
        public_data_plane,
    });
    let mut cfg = test_wallet_config(&scope, rpc_url);
    cfg.quick_sync_endpoint = None;
    cfg.sync_to_block = Some(0);
    cfg.use_indexed_wallet_catch_up = false;

    let (first, second) = tokio::join!(
        service.register_wallet(cfg.clone()),
        service.register_wallet(cfg),
    );
    let first = first.expect("register first wallet");
    let second = second.expect("register second wallet");

    assert_eq!(first.actor_id(), second.actor_id());
    assert_eq!(first.actor_id(), 1);
    assert_eq!(service.wallets.read().await.len(), 1);
    assert_eq!(
        service
            .wallet_actor_next
            .load(std::sync::atomic::Ordering::Acquire),
        2
    );

    service.unregister_wallet("test").await;
    service.cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn artifact_poi_corpus_survives_wallet_unregister_reregister() {
    let root_dir = temp_db_root("artifact-poi-corpus-reregister");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::ZERO,
    };
    let rpc_url = Url::parse("http://127.0.0.1:1").expect("rpc url");
    let chain = test_chain_config(
        &scope,
        Arc::new(QueryRpcPool::new(
            vec![rpc_url.clone()],
            Duration::from_secs(1),
        )),
        None,
    );
    let poi_policy = test_indexed_poi_policy();
    let public_data_plane = if let GlobalPoiPolicy::IndexedArtifacts {
        artifact_source,
        rpc_url,
        ..
    } = &poi_policy
    {
        ChainPublicDataPlane::new(
            Arc::clone(&db),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        )
        .with_poi_cache_service(Arc::new(
            crate::poi_cache::PoiCacheService::new(Arc::clone(&db), artifact_source.clone(), None)
                .with_poi_rpc_url(rpc_url.clone()),
        ))
    } else {
        unreachable!("test policy is artifact-backed")
    };
    let service = test_chain_service_with_policy(
        Arc::clone(&db),
        chain,
        public_data_plane.clone(),
        poi_policy,
    );
    let mut cfg = test_wallet_config(&scope, rpc_url);
    cfg.sync_to_block = Some(0);
    cfg.use_indexed_wallet_catch_up = false;
    let corpus_key = PublicPoiCorpusKey::new(0, scope.chain_id, DEFAULT_TXID_VERSION);

    let first = service
        .register_wallet(cfg.clone())
        .await
        .expect("register artifact wallet");
    let first_corpus = public_data_plane
        .ensure_poi_corpus(corpus_key.clone())
        .await
        .expect("first POI corpus")
        .local_caches();
    service.unregister_wallet(&cfg.cache_key).await;

    let second = service
        .register_wallet(cfg.clone())
        .await
        .expect("re-register artifact wallet");
    let second_corpus = public_data_plane
        .ensure_poi_corpus(corpus_key)
        .await
        .expect("second POI corpus")
        .local_caches();

    assert_ne!(first.actor_id(), second.actor_id());
    assert!(Arc::ptr_eq(&first_corpus, &second_corpus));
    service.unregister_wallet(&cfg.cache_key).await;
    service.shutdown().await;
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn active_backfill_drains_reset_replacement_request() {
    let (request_tx, mut request_rx) = mpsc::channel(4);
    let (old_sender, mut old_receiver) = mpsc::channel(1);
    let (new_sender, _new_receiver) = mpsc::channel(1);
    let mut cursors = HashMap::new();
    cursors.insert(
        "test".to_string(),
        WalletBackfill::new(
            100,
            1_000,
            true,
            100,
            test_backfill_lease(old_sender, 0, 1),
            std::time::Instant::now(),
        ),
    );

    request_tx
        .try_send(BackfillRequest::Add {
            cache_key: "test".to_string(),
            from_block: 80,
            to_block: 150,
            follow_safe_head: true,
            progress_start_block: 80,
            lease: test_backfill_lease(new_sender, 1, 2),
        })
        .expect("queue reset replacement backfill");

    drain_pending_backfill_requests(&mut request_rx, &mut cursors).await;

    let cursor = cursors.get("test").expect("cursor retained");
    assert_eq!(cursor.from_block, 80);
    assert_eq!(cursor.target_block, 150);
    assert!(cursor.follow_safe_head);
    assert_eq!(cursor.progress_start_block, 80);
    assert_eq!(cursor.lease.token().reset_generation(), 1);
    match old_receiver.recv().await.expect("old job retired") {
        BackfillEvent::JobRetired { token } => {
            assert_eq!(token.job_id(), 1);
            assert_eq!(token.reset_generation(), 0);
        }
        event => panic!("unexpected retirement event: {event:?}"),
    }
}

#[tokio::test]
async fn active_backfill_ignores_stale_replacement_request() {
    let (request_tx, mut request_rx) = mpsc::channel(4);
    let (active_sender, mut active_receiver) = mpsc::channel(1);
    let (stale_sender, mut stale_receiver) = mpsc::channel(1);
    let mut cursors = HashMap::new();
    cursors.insert(
        "test".to_string(),
        WalletBackfill::new(
            100,
            1_000,
            true,
            100,
            test_backfill_lease(active_sender, 1, 2),
            std::time::Instant::now(),
        ),
    );

    request_tx
        .try_send(BackfillRequest::Add {
            cache_key: "test".to_string(),
            from_block: 80,
            to_block: 150,
            follow_safe_head: true,
            progress_start_block: 80,
            lease: test_backfill_lease(stale_sender, 0, 1),
        })
        .expect("queue stale replacement backfill");

    drain_pending_backfill_requests(&mut request_rx, &mut cursors).await;

    let cursor = cursors.get("test").expect("active cursor retained");
    assert_eq!(cursor.from_block, 100);
    assert_eq!(cursor.target_block, 1_000);
    assert_eq!(cursor.lease.token().reset_generation(), 1);
    assert_eq!(cursor.lease.token().job_id(), 2);
    match stale_receiver.recv().await.expect("stale job retired") {
        BackfillEvent::JobRetired { token } => {
            assert_eq!(token.job_id(), 1);
            assert_eq!(token.reset_generation(), 0);
        }
        event => panic!("unexpected retirement event: {event:?}"),
    }
    assert!(active_receiver.try_recv().is_err());
}

#[test]
fn wallet_tail_fallback_thresholds_are_chain_specific() {
    assert_eq!(wallet_tail_fallback_lag_threshold_blocks(1), 10);
    assert_eq!(wallet_tail_fallback_lag_threshold_blocks(56), 15);
    assert_eq!(wallet_tail_fallback_lag_threshold_blocks(137), 22);
    assert_eq!(wallet_tail_fallback_lag_threshold_blocks(42161), 45);
}

#[test]
fn wallet_tail_fallback_requires_lag_stall_and_cooldown() {
    let now = std::time::Instant::now();
    let (sender, _receiver) = mpsc::channel(1);
    let mut cursor = WalletBackfill::new(
        100,
        160,
        true,
        100,
        test_backfill_lease(sender, 0, 1),
        now - std::time::Duration::from_secs(20),
    );

    assert_eq!(
        wallet_backfill_lag_blocks(cursor.from_block, cursor.target_block),
        61
    );
    assert!(cursor.should_try_indexed_tail_fallback(
        42161,
        now,
        std::time::Duration::from_secs(15),
        std::time::Duration::from_secs(60),
    ));

    cursor.mark_indexed_tail_attempt(now);
    assert!(!cursor.should_try_indexed_tail_fallback(
        42161,
        now + std::time::Duration::from_secs(30),
        std::time::Duration::from_secs(15),
        std::time::Duration::from_secs(60),
    ));
    assert!(cursor.should_try_indexed_tail_fallback(
        42161,
        now + std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(15),
        std::time::Duration::from_secs(60),
    ));

    cursor.mark_progress(150, now + std::time::Duration::from_secs(60));
    assert!(!cursor.should_try_indexed_tail_fallback(
        42161,
        now + std::time::Duration::from_secs(70),
        std::time::Duration::from_secs(15),
        std::time::Duration::from_secs(60),
    ));
}

#[test]
fn ready_wallet_tail_fallback_state_tracks_progress_and_cooldown() {
    let now = std::time::Instant::now();
    let mut state = WalletTailFallbackState::new(100, now - std::time::Duration::from_secs(20));

    assert!(state.should_try_indexed_tail_fallback(
        42161,
        101,
        160,
        now,
        std::time::Duration::from_secs(15),
        std::time::Duration::from_secs(60),
    ));

    state.mark_indexed_tail_attempt(now);
    assert!(!state.should_try_indexed_tail_fallback(
        42161,
        101,
        160,
        now + std::time::Duration::from_secs(30),
        std::time::Duration::from_secs(15),
        std::time::Duration::from_secs(60),
    ));

    state.update_last_scanned(130, now + std::time::Duration::from_secs(30));
    assert!(!state.should_try_indexed_tail_fallback(
        42161,
        131,
        190,
        now + std::time::Duration::from_secs(40),
        std::time::Duration::from_secs(15),
        std::time::Duration::from_secs(60),
    ));

    assert!(state.should_try_indexed_tail_fallback(
        42161,
        131,
        190,
        now + std::time::Duration::from_secs(90),
        std::time::Duration::from_secs(15),
        std::time::Duration::from_secs(60),
    ));
}

#[tokio::test]
async fn startup_sync_target_waits_for_safe_head_when_open_ended() {
    let (safe_head_tx, safe_head_rx) = watch::channel(0);
    let cancel = CancellationToken::new();
    let waiter = wait_for_startup_sync_target(safe_head_rx, None, 0, &cancel);

    safe_head_tx.send(123).expect("send safe head");

    assert_eq!(waiter.await, Some(123));
}

#[tokio::test]
async fn startup_sync_target_uses_existing_fixed_target_without_waiting() {
    let (_safe_head_tx, safe_head_rx) = watch::channel(0);
    let cancel = CancellationToken::new();

    assert_eq!(
        wait_for_startup_sync_target(safe_head_rx, Some(900), 900, &cancel).await,
        Some(900)
    );
}

#[test]
fn indexed_wallet_artifact_target_uses_lesser_of_artifact_height_and_safe_head() {
    let probe = IndexedWalletArtifactProbe {
        latest_indexed_block: 150,
        catalog_count: 1,
    };

    assert_eq!(probe.catch_up_target(200), 150);
    assert_eq!(probe.catch_up_target(120), 120);
}

#[test]
fn squid_tail_after_artifact_continues_only_when_squid_covers_more_blocks() {
    assert_eq!(
        squid_tail_target_after_artifact(151, 150, 200, 180),
        Some(180)
    );
    assert_eq!(
        squid_tail_target_after_artifact(151, 150, 200, 250),
        Some(200)
    );
    assert_eq!(squid_tail_target_after_artifact(151, 150, 200, 150), None);
    assert_eq!(squid_tail_target_after_artifact(201, 150, 200, 250), None);
    assert_eq!(squid_tail_target_after_artifact(151, 200, 200, 250), None);
}

#[test]
fn artifact_failure_falls_back_to_squid_only_before_checkpoint() {
    assert!(artifact_failure_can_fallback_to_squid(true, 99, 99));
    assert!(!artifact_failure_can_fallback_to_squid(true, 100, 99));
    assert!(!artifact_failure_can_fallback_to_squid(false, 99, 99));
}

#[test]
fn wallet_reorg_backfill_starts_after_forest_reset() {
    assert_eq!(wallet_reorg_backfill_from_block(250, 100), 250);
    assert_eq!(wallet_reorg_backfill_from_block(50, 100), 100);
}

#[test]
fn pending_tip_sticks_to_slightly_lagging_wallet_progress() {
    assert_eq!(pending_tip_from_block(1_000, 995, 500), 996);
    assert_eq!(pending_tip_from_block(1_000, 1_000, 500), 1_001);
    assert_eq!(pending_tip_from_block(1_000, 1_001, 500), 1_001);
}

#[test]
fn pending_tip_does_not_expand_to_historical_wallet_lag() {
    assert_eq!(pending_tip_from_block(1_000, 100, 500), 1_001);
}

#[test]
fn pending_tip_provider_must_cover_target() {
    assert!(pending_tip_provider_covers_target(1_010, 1_010));
    assert!(pending_tip_provider_covers_target(1_011, 1_010));
    assert!(!pending_tip_provider_covers_target(1_009, 1_010));
}

#[test]
fn wallet_sync_target_caps_to_debug_block() {
    assert_eq!(wallet_sync_target(1_000, None), 1_000);
    assert_eq!(wallet_sync_target(1_000, Some(900)), 900);
    assert_eq!(wallet_sync_target(1_000, Some(1_100)), 1_000);
    assert_eq!(wallet_sync_target(0, Some(900)), 900);
}

#[test]
fn forest_reorg_decision_skips_without_comparable_hashes() {
    assert_eq!(
        ForestReorgDecision::from_confirmed_hash(100, 100, [0u8; 32], Some([1u8; 32])),
        ForestReorgDecision::Skip
    );
    assert_eq!(
        ForestReorgDecision::from_confirmed_hash(100, 99, [1u8; 32], Some([2u8; 32])),
        ForestReorgDecision::Skip
    );
    assert_eq!(
        ForestReorgDecision::from_confirmed_hash(100, 100, [1u8; 32], None),
        ForestReorgDecision::Skip
    );
}

#[test]
fn forest_reorg_decision_requires_confirmed_mismatch() {
    assert_eq!(
        ForestReorgDecision::from_confirmed_hash(100, 100, [1u8; 32], Some([1u8; 32])),
        ForestReorgDecision::Match
    );
    assert_eq!(
        ForestReorgDecision::from_confirmed_hash(100, 100, [1u8; 32], Some([2u8; 32])),
        ForestReorgDecision::Mismatch
    );
}

#[test]
fn wallet_startup_hedge_is_limited_to_one_rpc_range() {
    assert_eq!(wallet_startup_hedge_block_count(100, 10, 110), Some(10));
    assert!(should_hedge_wallet_startup(100, 10, 110, 10, false));
    assert!(!should_hedge_wallet_startup(100, 10, 111, 10, false));
    assert!(!should_hedge_wallet_startup(100, 10, 0, 10, false));
    assert!(!should_hedge_wallet_startup(100, 10, 110, 0, false));
    assert!(!should_hedge_wallet_startup(110, 10, 110, 10, false));
    assert!(!should_hedge_wallet_startup(100, 10, 110, 10, true));
}

#[test]
fn combined_log_event_signatures_cover_homogeneous_ranges() {
    let legacy = combined_log_event_signatures_for_range(10, 99, 100, 200)
        .expect("legacy range can be combined");
    assert_eq!(legacy.len(), 4);
    assert!(legacy.contains(&CommitmentBatch::SIGNATURE_HASH));
    assert!(legacy.contains(&GeneratedCommitmentBatch::SIGNATURE_HASH));
    assert!(legacy.contains(&Nullifiers::SIGNATURE_HASH));
    assert!(legacy.contains(&Nullified::SIGNATURE_HASH));

    let legacy_shield = combined_log_event_signatures_for_range(100, 200, 100, 200)
        .expect("legacy shield range can be combined");
    assert_eq!(legacy_shield.len(), 4);
    assert!(legacy_shield.contains(&Transact::SIGNATURE_HASH));
    assert!(legacy_shield.contains(&RailgunLegacyShieldEvents::Shield::SIGNATURE_HASH));
    assert!(legacy_shield.contains(&Nullifiers::SIGNATURE_HASH));
    assert!(legacy_shield.contains(&Nullified::SIGNATURE_HASH));

    let modern = combined_log_event_signatures_for_range(201, 300, 100, 200)
        .expect("modern range can be combined");
    assert_eq!(modern.len(), 4);
    assert!(modern.contains(&Transact::SIGNATURE_HASH));
    assert!(modern.contains(&Shield::SIGNATURE_HASH));
    assert!(modern.contains(&Nullifiers::SIGNATURE_HASH));
    assert!(modern.contains(&Nullified::SIGNATURE_HASH));
}

#[test]
fn combined_log_event_signatures_skip_boundary_crossing_ranges() {
    assert!(combined_log_event_signatures_for_range(99, 100, 100, 200).is_none());
    assert!(combined_log_event_signatures_for_range(200, 201, 100, 200).is_none());
}

#[test]
fn indexed_wallet_page_kind_is_legacy_only_before_v2_start() {
    assert_eq!(
        IndexedWalletPageKind::for_from_block(99, 100),
        IndexedWalletPageKind::Legacy
    );
    assert_eq!(
        IndexedWalletPageKind::for_from_block(100, 100),
        IndexedWalletPageKind::Modern
    );
    assert_eq!(
        IndexedWalletPageKind::for_from_block(99, 0),
        IndexedWalletPageKind::Modern
    );
}

#[test]
fn indexed_wallet_to_block_splits_at_v2_start() {
    assert_eq!(
        IndexedWalletPageKind::Legacy.to_block(50, 200_000, 100, 300_000),
        99
    );
    assert_eq!(
        IndexedWalletPageKind::Modern.to_block(100, 200_000, 100, 300_000),
        200_000
    );
    assert_eq!(
        IndexedWalletPageKind::Legacy.to_block(50, 60, 100, 300_000),
        60
    );
}

#[test]
fn indexed_wallet_to_block_uses_configured_range() {
    assert_eq!(
        IndexedWalletPageKind::Modern.to_block(100, 10_000_000, 0, 1_000_000),
        1_000_099
    );
    assert_eq!(
        IndexedWalletPageKind::Modern.to_block(100, 10_000_000, 0, 5_000_000),
        5_000_099
    );
}

#[tokio::test]
async fn txid_background_waits_for_wallet_ready() {
    let (ready_tx, ready_rx) = tokio::sync::watch::channel(WalletReadiness::Syncing);
    let cancel = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(wait_for_wallet_ready(ready_rx, cancel));

    tokio::task::yield_now().await;
    assert!(!task.is_finished());

    ready_tx
        .send(WalletReadiness::Ready)
        .expect("ready receiver");
    let ready = tokio::time::timeout(std::time::Duration::from_secs(1), task)
        .await
        .expect("ready wait completed")
        .expect("ready task completed");
    assert!(ready);
}

#[tokio::test]
async fn txid_background_wait_exits_when_wallet_cancelled() {
    let (_ready_tx, ready_rx) = tokio::sync::watch::channel(WalletReadiness::Syncing);
    let cancel = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(wait_for_wallet_ready(ready_rx, cancel.clone()));

    cancel.cancel();
    let ready = tokio::time::timeout(std::time::Duration::from_secs(1), task)
        .await
        .expect("ready wait completed")
        .expect("ready task completed");
    assert!(!ready);
}

#[tokio::test]
async fn txid_background_wait_exits_when_wallet_readiness_fails() {
    let (ready_tx, ready_rx) = tokio::sync::watch::channel(WalletReadiness::Syncing);
    let cancel = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(wait_for_wallet_ready(ready_rx, cancel));

    ready_tx
        .send(WalletReadiness::Failed(
            WalletReadinessError::BackfillUnavailable,
        ))
        .expect("ready receiver");
    let ready = tokio::time::timeout(std::time::Duration::from_secs(1), task)
        .await
        .expect("ready wait completed")
        .expect("ready task completed");
    assert!(!ready);
}

#[test]
fn wallet_apply_result_accepted_progress_advances_only_committed_results() {
    assert_eq!(
        WalletBackfillApplyResult::Committed { committed_to: 105 }.accepted_committed_to(),
        Some(105)
    );
    assert_eq!(
        WalletBackfillApplyResult::AlreadyCovered { committed_to: 105 }.accepted_committed_to(),
        Some(105)
    );
    assert_eq!(
        WalletBackfillApplyResult::Rejected {
            committed_to: 999,
            reason: WalletBackfillRejectReason::Shutdown,
        }
        .accepted_committed_to(),
        None
    );
}

#[test]
fn rpc_and_indexed_wallet_scan_applies_use_normalized_rows() {
    let read_scope = PublicScanReadScope::new(PublicDataPlaneEpoch::new(0));
    let batch = Arc::new(LogBatch {
        from_block: 10,
        to_block: 20,
        logs: Vec::new(),
        block_timestamps: HashMap::new(),
        to_block_hash: Some([7; 32]),
        read_scope,
    });

    let rpc_apply = WalletScanApply::rows_from_log_batch(10, 20, batch, PublicScanSource::Rpc)
        .expect("normalize RPC rows");
    let indexed_apply = WalletScanApply::indexed_rows(
        10,
        20,
        WalletScanInputRows::default(),
        read_scope,
        WalletIndexedCatchUpSource::Squid,
    );

    assert!(matches!(
        &rpc_apply.rows.payload,
        WalletScanRowsPayload::Rows(_)
    ));
    assert!(matches!(
        &indexed_apply.rows.payload,
        WalletScanRowsPayload::Rows(_)
    ));
    assert_eq!(rpc_apply.rows.to_block_hash, Some([7; 32]));
    assert_eq!(indexed_apply.rows.to_block_hash, None);
}

#[tokio::test]
async fn wallet_send_helpers_reject_when_worker_channel_closed() {
    let (sender, receiver) = mpsc::channel(1);
    drop(receiver);
    let batch = Arc::new(LogBatch {
        from_block: 101,
        to_block: 105,
        logs: Vec::new(),
        block_timestamps: HashMap::new(),
        to_block_hash: None,
        read_scope: PublicScanReadScope::new(PublicDataPlaneEpoch::new(0)),
    });
    let token = test_sync_token(0, 1);

    assert_eq!(
        send_wallet_scan_apply(
            "test",
            &sender,
            WalletScanApply::rows_from_log_batch(101, 105, batch, PublicScanSource::Rpc)
                .expect("normalize empty log payload"),
            token,
        )
        .await,
        WalletBackfillApplyResult::Rejected {
            committed_to: 104,
            reason: WalletBackfillRejectReason::Shutdown,
        }
    );
    assert_eq!(
        send_wallet_target("test", &sender, 105, token).await,
        WalletBackfillFinishResult::Rejected {
            committed_to: 104,
            reason: WalletBackfillRejectReason::Shutdown,
        }
    );
}

#[tokio::test]
async fn wallet_backfill_loop_does_not_commit_later_wallet_past_target() {
    let root_dir = temp_db_root("wallet-backfill-target-bound");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xcc; 20]),
    };
    let rpc = JsonRpcServer::spawn(vec![serde_json::json!([]), serde_json::Value::Null]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let chain = ChainConfig {
        chain_id: scope.chain_id,
        contract: scope.railgun_contract,
        rpcs: Arc::clone(&rpcs),
        archive_rpc_url: None,
        archive_until_block: 0,
        deployment_block: 0,
        v2_start_block: 0,
        legacy_shield_block: 0,
        block_range: 100,
        indexed_wallet_block_range: 100,
        poll_interval: Duration::from_millis(1),
        finality_depth: 0,
        quick_sync_endpoint: None,
        indexed_artifact_source: None,
        anchor_interval: 1000,
        anchor_retention: 5,
        http_client: None,
        progress_tx: None,
    };
    let (head_tx, _head_rx) = watch::channel(0);
    let (safe_head_tx, safe_head_rx) = watch::channel(199);
    let (forest_last_tx, _forest_last_rx) = watch::channel(0);
    let (live_log_tx, wallet_a_live_rx) = broadcast::channel(8);
    let wallet_b_live_rx = live_log_tx.subscribe();
    let (backfill_request_tx, backfill_request_rx) = mpsc::channel(8);
    let loop_cancel = CancellationToken::new();
    let worker_cancel = CancellationToken::new();
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = Arc::new(ChainService {
        chain: chain.clone(),
        poi_policy: test_proxy_poi_policy(),
        db: Arc::clone(&db),
        forest: Arc::new(RwLock::new(MerkleForest::new())),
        head_tx,
        safe_head_tx,
        forest_last_tx,
        live_log_tx,
        backfill_tx: backfill_request_tx.clone(),
        archive_provider: None,
        wallets: RwLock::new(HashMap::new()),
        wallet_registration_gates: Mutex::new(HashMap::new()),
        cancel: loop_cancel.clone(),
        live_log_task: Mutex::new(None),
        anchor_last: std::sync::atomic::AtomicU64::new(0),
        txid_public_cache_started: std::sync::atomic::AtomicBool::new(false),
        wallet_actor_next: std::sync::atomic::AtomicU64::new(1),
        wallet_reset_intent_next: std::sync::atomic::AtomicU64::new(1),
        public_data_plane: public_data_plane.clone(),
    });
    let (wallet_a_tx, wallet_a_rx) = mpsc::channel(8);
    let (wallet_b_tx, wallet_b_rx) = mpsc::channel(8);
    let mut wallet_a_cfg = test_wallet_config(&scope, rpc.url.clone());
    wallet_a_cfg.cache_key = "wallet-a".to_string();
    wallet_a_cfg.sync_to_block = Some(199);
    wallet_a_cfg.quick_sync_endpoint = None;
    wallet_a_cfg.use_indexed_wallet_catch_up = false;
    let mut wallet_b_cfg = test_wallet_config(&scope, rpc.url.clone());
    wallet_b_cfg.cache_key = "wallet-b".to_string();
    wallet_b_cfg.sync_to_block = Some(130);
    wallet_b_cfg.quick_sync_endpoint = None;
    wallet_b_cfg.use_indexed_wallet_catch_up = false;

    let wallet_a = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),
            rpcs: Arc::clone(&rpcs),
            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx.clone(),
            backfill_sender: wallet_a_tx.clone(),
            public_data_plane: public_data_plane.clone(),
        },
        wallet_a_cfg,
        1,
        wallet_a_live_rx,
        wallet_a_rx,
        worker_cancel.clone(),
        Vec::new(),
        99,
    )
    .await
    .expect("spawn wallet a");
    let wallet_b = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),
            rpcs: Arc::clone(&rpcs),
            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx.clone(),
            backfill_sender: wallet_b_tx.clone(),
            public_data_plane: public_data_plane.clone(),
        },
        wallet_b_cfg,
        2,
        wallet_b_live_rx,
        wallet_b_rx,
        worker_cancel.clone(),
        Vec::new(),
        119,
    )
    .await
    .expect("spawn wallet b");
    spawn_backfill_loop(
        Arc::clone(&service),
        backfill_request_rx,
        Arc::clone(&rpcs),
        None,
        safe_head_rx,
        loop_cancel.clone(),
    );
    let wallet_a_token = wallet_a.mint_sync_token(0);
    let wallet_b_token = wallet_b.mint_sync_token(0);
    let wallet_a_lease = send_wallet_target("wallet-a", &wallet_a_tx, 199, wallet_a_token)
        .await
        .accepted_lease()
        .expect("wallet A target accepted");
    let wallet_b_lease = send_wallet_target("wallet-b", &wallet_b_tx, 130, wallet_b_token)
        .await
        .accepted_lease()
        .expect("wallet B target accepted");
    backfill_request_tx
        .send(BackfillRequest::Add {
            cache_key: "wallet-a".to_string(),
            from_block: 100,
            to_block: 199,
            follow_safe_head: false,
            progress_start_block: 100,
            lease: wallet_a_lease,
        })
        .await
        .expect("send wallet A backfill request");
    backfill_request_tx
        .send(BackfillRequest::Add {
            cache_key: "wallet-b".to_string(),
            from_block: 120,
            to_block: 130,
            follow_safe_head: false,
            progress_start_block: 120,
            lease: wallet_b_lease,
        })
        .await
        .expect("send wallet B backfill request");

    tokio::time::timeout(Duration::from_secs(2), async {
        while wallet_a.last_scanned() != 199
            || wallet_b.last_scanned() != 130
            || !wallet_a.readiness().is_ready()
            || !wallet_b.readiness().is_ready()
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("wallet backfill loop completed");

    assert_eq!(wallet_a.last_scanned(), 199);
    assert_eq!(wallet_b.last_scanned(), 130);
    assert_eq!(
        db.get_wallet_meta("wallet-b")
            .expect("wallet B meta read")
            .expect("wallet B meta")
            .last_scanned_block,
        130,
    );
    assert!(
        rpc.requests
            .recv_timeout(Duration::from_secs(1))
            .expect("logs request")
            .contains("eth_getLogs")
    );
    let diagnostics = public_data_plane.diagnostics().await;
    assert!(diagnostics.events.iter().any(|event| {
        event.kind == PublicDataPlaneDiagnosticKind::SourceSelected
            && event.source == Some(PublicScanSource::Rpc)
            && event.range.is_some()
            && event.epoch == PublicDataPlaneEpoch::new(0)
    }));

    worker_cancel.cancel();
    loop_cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn indexed_wallet_catch_up_hands_artifact_exhaustion_to_squid_tail() {
    let root_dir = temp_db_root("indexed-wallet-artifact-exhaustion-tail");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xbb; 20]),
    };
    let artifact_source = checkpointed_wallet_artifact_source(scope.clone(), 100, 200, 150);
    let squid = GraphqlServer::spawn(vec![
        r#"{"data":{"squidStatus":{"height":"200"},"transactCommitments":[],"shieldCommitments":[],"nullifiers":[],"legacyEncryptedCommitments":[],"legacyGeneratedCommitments":[]}}"#,
        r#"{"data":{"transactCommitments":[],"shieldCommitments":[],"nullifiers":[]}}"#,
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
        Duration::from_secs(1),
    ));
    let chain = ChainConfig {
        chain_id: scope.chain_id,
        contract: scope.railgun_contract,
        rpcs: Arc::clone(&rpcs),
        archive_rpc_url: None,
        archive_until_block: 0,
        deployment_block: 0,
        v2_start_block: 0,
        legacy_shield_block: 0,
        block_range: 100,
        indexed_wallet_block_range: 100,
        poll_interval: Duration::from_millis(1),
        finality_depth: 0,
        quick_sync_endpoint: Some(squid.url.clone()),
        indexed_artifact_source: Some(artifact_source.config),
        anchor_interval: 1000,
        anchor_retention: 5,
        http_client: None,
        progress_tx: None,
    };
    let (head_tx, _head_rx) = watch::channel(0);
    let (safe_head_tx, _safe_head_rx) = watch::channel(200);
    let (forest_last_tx, _forest_last_rx) = watch::channel(0);
    let (live_log_tx, live_log_rx) = broadcast::channel(8);
    let (service_backfill_tx, _service_backfill_rx) = mpsc::channel(1);
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = Arc::new(ChainService {
        chain: chain.clone(),
        poi_policy: test_proxy_poi_policy(),
        db: Arc::clone(&db),
        forest: Arc::new(RwLock::new(MerkleForest::new())),
        head_tx,
        safe_head_tx,
        forest_last_tx,
        live_log_tx,
        backfill_tx: service_backfill_tx,
        archive_provider: None,
        wallets: RwLock::new(HashMap::new()),
        wallet_registration_gates: Mutex::new(HashMap::new()),
        cancel: CancellationToken::new(),
        live_log_task: Mutex::new(None),
        anchor_last: std::sync::atomic::AtomicU64::new(0),
        txid_public_cache_started: std::sync::atomic::AtomicBool::new(false),
        wallet_actor_next: std::sync::atomic::AtomicU64::new(1),
        wallet_reset_intent_next: std::sync::atomic::AtomicU64::new(1),
        public_data_plane: public_data_plane.clone(),
    });
    let (wallet_backfill_tx, wallet_backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(1);
    let worker_cancel = CancellationToken::new();
    let wallet_cfg = test_wallet_config(&scope, squid.url.clone());
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),
            rpcs,
            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: wallet_backfill_tx.clone(),
            public_data_plane,
        },
        wallet_cfg.clone(),
        1,
        live_log_rx,
        wallet_backfill_rx,
        worker_cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");

    let checkpoint = service
        .indexed_wallet_catch_up(
            &wallet_cfg,
            0,
            100,
            200,
            &handle,
            &worker_cancel,
            IndexedWalletCatchUpSourceOrder::ArtifactsFirst,
            true,
            (&wallet_backfill_tx, 0),
        )
        .await;

    assert_eq!(checkpoint, 200);
    assert_eq!(handle.last_scanned(), 200);
    assert_eq!(
        handle
            .indexed_catch_up_rx
            .borrow()
            .as_ref()
            .map(|status| status.source),
        Some(WalletIndexedCatchUpSource::Squid)
    );
    let probe_request = squid
        .requests
        .recv_timeout(Duration::from_secs(1))
        .expect("squid probe request");
    assert!(probe_request.contains("query WalletProbe"));
    let page_request = squid
        .requests
        .recv_timeout(Duration::from_secs(1))
        .expect("squid tail page request");
    assert!(page_request.contains("query IndexedWalletPage"));
    assert!(page_request.contains(r#""fromBlock":"151""#));
    assert!(page_request.contains(r#""toBlock":"200""#));

    worker_cancel.cancel();
    drop(db);
    drop(artifact_source.server);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn indexed_wallet_artifact_prepare_scope_rejects_epoch_invalidated_before_apply() {
    let root_dir = temp_db_root("indexed-wallet-artifact-stale-prepare-scope");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xbb; 20]),
    };
    let (artifact_source, block) =
        checkpointed_wallet_artifact_source_with_blocked_manifest(scope.clone(), 100, 150, 150);
    let PathServerBlockControl {
        request_started,
        release,
    } = block;
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
        Duration::from_secs(1),
    ));
    let chain = ChainConfig {
        chain_id: scope.chain_id,
        contract: scope.railgun_contract,
        rpcs: Arc::clone(&rpcs),
        archive_rpc_url: None,
        archive_until_block: 0,
        deployment_block: 0,
        v2_start_block: 0,
        legacy_shield_block: 0,
        block_range: 100,
        indexed_wallet_block_range: 100,
        poll_interval: Duration::from_millis(1),
        finality_depth: 0,
        quick_sync_endpoint: Some(Url::parse("http://127.0.0.1:1").expect("squid url")),
        indexed_artifact_source: Some(artifact_source.config),
        anchor_interval: 1000,
        anchor_retention: 5,
        http_client: None,
        progress_tx: None,
    };
    let (head_tx, _head_rx) = watch::channel(0);
    let (safe_head_tx, _safe_head_rx) = watch::channel(150);
    let (forest_last_tx, _forest_last_rx) = watch::channel(0);
    let (live_log_tx, live_log_rx) = broadcast::channel(8);
    let (service_backfill_tx, _service_backfill_rx) = mpsc::channel(1);
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = Arc::new(ChainService {
        chain: chain.clone(),
        poi_policy: test_proxy_poi_policy(),
        db: Arc::clone(&db),
        forest: Arc::new(RwLock::new(MerkleForest::new())),
        head_tx,
        safe_head_tx,
        forest_last_tx,
        live_log_tx,
        backfill_tx: service_backfill_tx,
        archive_provider: None,
        wallets: RwLock::new(HashMap::new()),
        wallet_registration_gates: Mutex::new(HashMap::new()),
        cancel: CancellationToken::new(),
        live_log_task: Mutex::new(None),
        anchor_last: std::sync::atomic::AtomicU64::new(0),
        txid_public_cache_started: std::sync::atomic::AtomicBool::new(false),
        wallet_actor_next: std::sync::atomic::AtomicU64::new(1),
        wallet_reset_intent_next: std::sync::atomic::AtomicU64::new(1),
        public_data_plane: public_data_plane.clone(),
    });
    let (wallet_backfill_tx, wallet_backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(1);
    let worker_cancel = CancellationToken::new();
    let wallet_cfg = test_wallet_config(
        &scope,
        Url::parse("http://127.0.0.1:1").expect("quick-sync url"),
    );
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),
            rpcs,
            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: wallet_backfill_tx.clone(),
            public_data_plane: public_data_plane.clone(),
        },
        wallet_cfg.clone(),
        1,
        live_log_rx,
        wallet_backfill_rx,
        worker_cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");
    let catch_up_service = Arc::clone(&service);
    let catch_up_cfg = wallet_cfg.clone();
    let catch_up_handle = handle.clone();
    let catch_up_cancel = worker_cancel.clone();
    let catch_up_sender = wallet_backfill_tx.clone();
    let catch_up = tokio::spawn(async move {
        catch_up_service
            .indexed_wallet_catch_up(
                &catch_up_cfg,
                0,
                100,
                150,
                &catch_up_handle,
                &catch_up_cancel,
                IndexedWalletCatchUpSourceOrder::ArtifactsFirst,
                true,
                (&catch_up_sender, 0),
            )
            .await
    });
    tokio::time::timeout(
        Duration::from_secs(2),
        tokio::task::spawn_blocking(move || {
            request_started
                .recv()
                .expect("artifact manifest fetch started")
        }),
    )
    .await
    .expect("artifact manifest fetch started")
    .expect("manifest wait task completed");

    public_data_plane
        .invalidate_public_scan_coverage_from(101)
        .await;
    release.send(()).expect("release artifact manifest fetch");
    let checkpoint = catch_up.await.expect("indexed catch-up task");

    assert_eq!(checkpoint, 100);
    assert_eq!(handle.last_scanned(), 100);
    assert!(matches!(
        public_data_plane
            .cached_public_scan_coverage(PublicScanRange::new(101, 150))
            .await,
        PublicCoverageAnswer::Missing { .. }
    ));
    let diagnostics = public_data_plane.diagnostics().await;
    assert!(diagnostics.events.iter().any(|event| {
        event.kind == PublicDataPlaneDiagnosticKind::CoverageRejected
            && event.source == Some(PublicScanSource::IndexedArtifacts)
            && event.range == Some(PublicScanRange::new(101, 150))
    }));

    worker_cancel.cancel();
    drop(db);
    drop(artifact_source.server);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn cached_public_coverage_partial_segment_does_not_publish_ready() {
    let root_dir = temp_db_root("cached-coverage-no-intermediate-ready");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
        Duration::from_secs(1),
    ));
    let chain = test_chain_config(&scope, Arc::clone(&rpcs), None);
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane.clone());
    let cfg = test_wallet_config(&scope, Url::parse("http://127.0.0.1:1").expect("url"));
    public_data_plane
        .record_public_scan_coverage(PublicScanCoverageWrite {
            range: PublicScanRange::new(101, 150),
            source: PublicScanSource::Rpc,
            row_count: 0,
            read_scope: PublicScanReadScope::new(PublicDataPlaneEpoch::new(0)),
        })
        .await
        .expect("record cached coverage");
    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),
            rpcs,
            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: backfill_tx.clone(),
            public_data_plane: public_data_plane.clone(),
        },
        cfg.clone(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");

    let outcome = service
        .apply_cached_public_scan_coverage(&cfg, 0, 100, 200, &handle, &backfill_tx, 0)
        .await;

    assert_eq!(outcome.checkpoint, 150);
    assert!(!outcome.finished);
    assert_eq!(handle.last_scanned(), 150);
    assert_eq!(handle.readiness(), WalletReadiness::Syncing);
    assert!(!*handle.ready_rx.borrow());

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn public_scan_coverage_arbitrates_uncached_range_through_sources() {
    let root_dir = temp_db_root("public-coverage-source-arbitration");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xbb; 20]),
    };
    let artifact_source = checkpointed_wallet_artifact_source(scope.clone(), 100, 150, 150);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
        Duration::from_secs(1),
    ));
    let chain = test_chain_config(&scope, Arc::clone(&rpcs), Some(artifact_source.config));
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane.clone());

    let answer = service
        .public_data_plane()
        .public_scan_coverage(PublicScanRange::new(100, 150))
        .await
        .expect("public coverage answer");

    assert!(matches!(
        answer,
        PublicCoverageAnswer::ReplayableEmpty {
            range: PublicScanRange {
                from_block: 100,
                to_block: 150
            },
            source: PublicScanSource::IndexedArtifacts,
            epoch: PublicDataPlaneEpoch { value: 0 },
        }
    ));
    let diagnostics = public_data_plane.diagnostics().await;
    assert!(diagnostics.events.iter().any(|event| {
        event.kind == PublicDataPlaneDiagnosticKind::SourceSelected
            && event.source == Some(PublicScanSource::IndexedArtifacts)
            && event.range == Some(PublicScanRange::new(100, 150))
    }));

    drop(db);
    drop(artifact_source.server);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn public_scan_coverage_distinguishes_row_bearing_cached_coverage() {
    let root_dir = temp_db_root("public-coverage-row-bearing-cache");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xbb; 20]),
    };
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
        Duration::from_secs(1),
    ));
    let chain = test_chain_config(&scope, Arc::clone(&rpcs), None);
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let range = PublicScanRange::new(100, 110);
    public_data_plane
        .record_public_scan_coverage(PublicScanCoverageWrite {
            range,
            source: PublicScanSource::Rpc,
            row_count: 7,
            read_scope: public_data_plane.begin_public_scan_read(),
        })
        .await
        .expect("record row-bearing coverage");
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane.clone());

    let answer = service
        .public_data_plane()
        .public_scan_coverage(range)
        .await
        .expect("public coverage answer");

    assert_eq!(
        answer,
        PublicCoverageAnswer::CoveredWithRows {
            range,
            source: PublicScanSource::Rpc,
            epoch: PublicDataPlaneEpoch::new(0),
        }
    );
    assert!(
        public_data_plane
            .cached_empty_wallet_scan_apply(range.from_block, range.to_block)
            .await
            .is_none(),
        "row-bearing coverage must not be replayed as empty coverage"
    );

    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn public_scan_rows_rejects_source_result_after_epoch_invalidation() {
    let root_dir = temp_db_root("public-scan-rows-stale-source-result");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xbb; 20]),
    };
    let (artifact_source, block) =
        checkpointed_wallet_artifact_source_with_blocked_manifest(scope.clone(), 100, 150, 150);
    let PathServerBlockControl {
        request_started,
        release,
    } = block;
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
        Duration::from_secs(1),
    ));
    let chain = test_chain_config(&scope, Arc::clone(&rpcs), Some(artifact_source.config));
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane.clone());
    let public_handle = service.public_data_plane();
    let scan_task = tokio::spawn(async move {
        public_handle
            .public_scan_rows(PublicScanRange::new(100, 150))
            .await
    });

    tokio::time::timeout(
        Duration::from_secs(2),
        tokio::task::spawn_blocking(move || {
            request_started
                .recv()
                .expect("artifact manifest fetch started")
        }),
    )
    .await
    .expect("artifact manifest fetch started")
    .expect("manifest wait task completed");
    public_data_plane
        .invalidate_public_scan_coverage_from(100)
        .await;
    release.send(()).expect("release artifact manifest fetch");

    let error = scan_task
        .await
        .expect("public scan task completed")
        .expect_err("stale public scan rows must be rejected");
    assert!(matches!(
        error,
        ChainError::PublicDataPlane(PublicDataPlaneError::StaleEpoch {
            expected: 1,
            actual: 0
        })
    ));
    let diagnostics = public_data_plane.diagnostics().await;
    assert!(diagnostics.events.iter().any(|event| {
        event.kind == PublicDataPlaneDiagnosticKind::CoverageRejected
            && event.source == Some(PublicScanSource::IndexedArtifacts)
            && event.range == Some(PublicScanRange::new(100, 150))
    }));

    drop(db);
    drop(artifact_source.server);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn public_scan_rows_rpc_fallback_returns_only_bounded_proven_range() {
    let root_dir = temp_db_root("public-scan-rpc-bounded-proven-range");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xbb; 20]),
    };
    let rpc = JsonRpcServer::spawn(vec![
        serde_json::json!("0x96"),
        serde_json::json!([]),
        serde_json::Value::Null,
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, Arc::clone(&rpcs), None);
    chain.block_range = 100;
    chain.indexed_wallet_block_range = 1_000;
    chain.finality_depth = 0;
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane.clone());

    let answer = service
        .public_data_plane()
        .public_scan_rows(PublicScanRange::new(100, 500))
        .await
        .expect("public scan rows");

    let PublicScanRowsAnswer::Rows(rows) = answer else {
        panic!("RPC fallback should return normalized rows");
    };
    assert_eq!(rows.range, PublicScanRange::new(100, 150));
    assert_eq!(rows.source, PublicScanSource::Rpc);
    assert_eq!(rows.row_count(), 0);
    assert!(matches!(
        public_data_plane
            .cached_public_scan_coverage(PublicScanRange::new(100, 150))
            .await,
        PublicCoverageAnswer::ReplayableEmpty { .. }
    ));
    assert!(matches!(
        public_data_plane
            .cached_public_scan_coverage(PublicScanRange::new(151, 199))
            .await,
        PublicCoverageAnswer::Missing { .. }
    ));
    let _block_number_request = rpc
        .requests
        .recv_timeout(Duration::from_secs(1))
        .expect("block number request");
    let logs_request = rpc
        .requests
        .recv_timeout(Duration::from_secs(1))
        .expect("logs request");
    assert!(logs_request.contains("eth_getLogs"));
    assert!(logs_request.contains(r#""fromBlock":"0x64""#));
    assert!(logs_request.contains(r#""toBlock":"0x96""#));
    assert!(!logs_request.contains(r#""toBlock":"0x1f4""#));

    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn public_scan_rows_records_squid_to_rpc_fallback_diagnostic() {
    let root_dir = temp_db_root("public-scan-squid-rpc-fallback-diagnostic");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xbb; 20]),
    };
    let squid = GraphqlServer::spawn(vec![
        r#"{"data":{"squidStatus":{"height":"150"},"transactCommitments":[],"shieldCommitments":[],"nullifiers":[],"legacyEncryptedCommitments":[],"legacyGeneratedCommitments":[]}}"#,
        r#"{"errors":[{"message":"boom"}]}"#,
    ]);
    let rpc = JsonRpcServer::spawn(vec![
        serde_json::json!("0x96"),
        serde_json::json!([]),
        serde_json::Value::Null,
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, Arc::clone(&rpcs), None);
    chain.quick_sync_endpoint = Some(squid.url.clone());
    chain.block_range = 100;
    chain.indexed_wallet_block_range = 100;
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane.clone());

    let answer = service
        .public_data_plane()
        .public_scan_rows(PublicScanRange::new(100, 150))
        .await
        .expect("public scan rows fallback");

    let PublicScanRowsAnswer::Rows(rows) = answer else {
        panic!("RPC fallback should return normalized rows");
    };
    assert_eq!(rows.range, PublicScanRange::new(100, 150));
    assert_eq!(rows.source, PublicScanSource::Rpc);
    let diagnostics = public_data_plane.diagnostics().await;
    assert!(diagnostics.events.iter().any(|event| {
        event.kind == PublicDataPlaneDiagnosticKind::SourceSelected
            && event.source == Some(PublicScanSource::Squid)
            && event.range == Some(PublicScanRange::new(100, 150))
    }));
    assert!(diagnostics.events.iter().any(|event| {
        event.kind == PublicDataPlaneDiagnosticKind::SourceFallback
            && event.source == Some(PublicScanSource::Rpc)
            && event.range == Some(PublicScanRange::new(100, 150))
            && event.reason.contains("Squid failed")
    }));
    assert!(diagnostics.events.iter().any(|event| {
        event.kind == PublicDataPlaneDiagnosticKind::SourceSelected
            && event.source == Some(PublicScanSource::Rpc)
            && event.range == Some(PublicScanRange::new(100, 150))
    }));

    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn public_scan_rows_records_archive_rpc_fallback_diagnostic_at_boundary() {
    let root_dir = temp_db_root("public-scan-archive-rpc-fallback-diagnostic");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xbb; 20]),
    };
    let squid = GraphqlServer::spawn(vec![
        r#"{"data":{"squidStatus":{"height":"150"},"transactCommitments":[],"shieldCommitments":[],"nullifiers":[],"legacyEncryptedCommitments":[],"legacyGeneratedCommitments":[]}}"#,
        r#"{"errors":[{"message":"boom"}]}"#,
    ]);
    let rpc = JsonRpcServer::spawn(vec![
        serde_json::json!("0x96"),
        serde_json::json!([]),
        serde_json::json!([]),
        serde_json::Value::Null,
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, Arc::clone(&rpcs), None);
    chain.quick_sync_endpoint = Some(squid.url.clone());
    chain.archive_until_block = 100;
    chain.block_range = 100;
    chain.indexed_wallet_block_range = 100;
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane.clone());

    let answer = service
        .public_data_plane()
        .public_scan_rows(PublicScanRange::new(100, 150))
        .await
        .expect("public scan rows archive fallback");

    let PublicScanRowsAnswer::Rows(rows) = answer else {
        panic!("Archive RPC fallback should return normalized rows");
    };
    assert_eq!(rows.range, PublicScanRange::new(100, 150));
    assert_eq!(rows.source, PublicScanSource::ArchiveRpc);
    assert_eq!(
        public_data_plane
            .cached_public_scan_coverage(PublicScanRange::new(100, 150))
            .await,
        PublicCoverageAnswer::ReplayableEmpty {
            range: PublicScanRange::new(100, 150),
            source: PublicScanSource::ArchiveRpc,
            epoch: PublicDataPlaneEpoch::new(0),
        }
    );
    let diagnostics = public_data_plane.diagnostics().await;
    assert!(diagnostics.events.iter().any(|event| {
        event.kind == PublicDataPlaneDiagnosticKind::SourceFallback
            && event.source == Some(PublicScanSource::ArchiveRpc)
            && event.range == Some(PublicScanRange::new(100, 150))
            && event.reason.contains("Squid failed")
    }));
    assert!(diagnostics.events.iter().any(|event| {
        event.kind == PublicDataPlaneDiagnosticKind::SourceSelected
            && event.source == Some(PublicScanSource::ArchiveRpc)
            && event.range == Some(PublicScanRange::new(100, 150))
    }));
    assert!(diagnostics.events.iter().any(|event| {
        event.kind == PublicDataPlaneDiagnosticKind::CoverageRecorded
            && event.source == Some(PublicScanSource::ArchiveRpc)
            && event.range == Some(PublicScanRange::new(100, 150))
    }));

    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn chain_shutdown_waits_for_live_log_worker() {
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        let _ = release_rx.await;
    });
    let live_log_task = Arc::new(tokio::sync::Mutex::new(Some(task)));
    let waiter_task = tokio::spawn({
        let live_log_task = Arc::clone(&live_log_task);
        async move {
            await_live_log_task_shutdown(live_log_task.as_ref(), 1).await;
        }
    });

    tokio::task::yield_now().await;
    assert!(!waiter_task.is_finished());

    release_tx.send(()).expect("release live log worker");
    tokio::time::timeout(std::time::Duration::from_secs(1), waiter_task)
        .await
        .expect("shutdown wait completed")
        .expect("shutdown task completed");
    assert!(live_log_task.lock().await.is_none());
}

#[tokio::test]
async fn wallet_startup_events_send_target_before_follow_safe_head_backfill_runs() {
    let root_dir = temp_db_root("wallet-startup-events-token");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cancel = CancellationToken::new();
    let (_live_tx, live_rx) = broadcast::channel(1);
    let (worker_tx, worker_rx) = mpsc::channel(1);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(1);
    let scope = test_scope();
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),
            rpcs: Arc::new(QueryRpcPool::new(
                vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                Duration::from_secs(1),
            )),
            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: worker_tx,
            public_data_plane: ChainPublicDataPlane::new(
                Arc::clone(&db),
                Arc::new(std::sync::atomic::AtomicU64::new(0)),
            ),
        },
        test_wallet_config(
            &scope,
            Url::parse("http://127.0.0.1:1").expect("quick sync url"),
        ),
        1,
        live_rx,
        worker_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");
    let (sender, mut receiver) = mpsc::channel(4);
    let batch = Arc::new(LogBatch {
        from_block: 101,
        to_block: 105,
        logs: Vec::new(),
        block_timestamps: HashMap::new(),
        to_block_hash: None,
        read_scope: PublicScanReadScope::new(PublicDataPlaneEpoch::new(0)),
    });

    let sender_clone = sender.clone();
    let send_task = tokio::spawn(async move {
        send_wallet_startup_events(
            "test",
            vec![
                WalletScanApply::rows_from_log_batch(101, 105, batch, PublicScanSource::Rpc)
                    .expect("normalize empty log payload"),
            ],
            Some(105),
            7,
            &sender_clone,
            &handle,
        )
        .await
    });

    let Some(BackfillEvent::Target {
        target_block,
        token,
        sender,
        response,
    }) = receiver.recv().await
    else {
        panic!("startup target should accept the token first");
    };
    assert_eq!(target_block, 105);
    assert_eq!(token.reset_generation(), 7);
    response
        .send(WalletBackfillFinishResult::Accepted {
            committed_to: 100,
            target_block,
            lease: WalletBackfillLease::from_token(token, sender),
        })
        .expect("send initial target result");

    let Some(BackfillEvent::Apply {
        apply,
        token: apply_token,
        response,
    }) = receiver.recv().await
    else {
        panic!("startup logs should be sent first");
    };
    assert_eq!(apply.from_block, 101);
    assert_eq!(apply.to_block, 105);
    let WalletScanRowsPayload::Rows(rows) = apply.rows.payload else {
        panic!("startup apply should contain normalized rows");
    };
    assert_eq!(rows.row_count(), 0);
    assert_eq!(apply_token, token);
    response
        .send(WalletBackfillApplyResult::Committed { committed_to: 105 })
        .expect("send apply result");
    let Some(BackfillEvent::Target {
        target_block,
        token: finish_token,
        sender: _,
        response,
    }) = receiver.recv().await
    else {
        panic!("startup target should be sent after logs");
    };
    assert_eq!(target_block, 105);
    assert_eq!(finish_token, token);
    response
        .send(WalletBackfillFinishResult::Ready { committed_to: 105 })
        .expect("send target result");
    assert!(send_task.await.expect("send task completed"));
    assert!(receiver.try_recv().is_err());
    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_startup_events_treat_leading_ready_as_success() {
    let root_dir = temp_db_root("wallet-startup-events-leading-ready");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cancel = CancellationToken::new();
    let (_live_tx, live_rx) = broadcast::channel(1);
    let (worker_tx, worker_rx) = mpsc::channel(1);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(1);
    let scope = test_scope();
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),
            rpcs: Arc::new(QueryRpcPool::new(
                vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                Duration::from_secs(1),
            )),
            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: worker_tx,
            public_data_plane: ChainPublicDataPlane::new(
                Arc::clone(&db),
                Arc::new(std::sync::atomic::AtomicU64::new(0)),
            ),
        },
        test_wallet_config(
            &scope,
            Url::parse("http://127.0.0.1:1").expect("quick sync url"),
        ),
        1,
        live_rx,
        worker_rx,
        cancel.clone(),
        Vec::new(),
        105,
    )
    .await
    .expect("spawn wallet worker");
    let (sender, mut receiver) = mpsc::channel(4);
    let batch = Arc::new(LogBatch {
        from_block: 101,
        to_block: 105,
        logs: Vec::new(),
        block_timestamps: HashMap::new(),
        to_block_hash: None,
        read_scope: PublicScanReadScope::new(PublicDataPlaneEpoch::new(0)),
    });

    let sender_clone = sender.clone();
    let send_task = tokio::spawn(async move {
        send_wallet_startup_events(
            "test",
            vec![
                WalletScanApply::rows_from_log_batch(101, 105, batch, PublicScanSource::Rpc)
                    .expect("normalize empty log payload"),
            ],
            Some(105),
            0,
            &sender_clone,
            &handle,
        )
        .await
    });

    let Some(BackfillEvent::Target {
        target_block,
        response,
        ..
    }) = receiver.recv().await
    else {
        panic!("startup target should be sent");
    };
    assert_eq!(target_block, 105);
    response
        .send(WalletBackfillFinishResult::Ready { committed_to: 105 })
        .expect("send ready target result");
    assert!(send_task.await.expect("send task completed"));
    assert!(receiver.try_recv().is_err());

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_startup_events_retire_token_on_apply_failure() {
    let root_dir = temp_db_root("wallet-startup-events-retire-failure");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cancel = CancellationToken::new();
    let (_live_tx, live_rx) = broadcast::channel(1);
    let (worker_tx, worker_rx) = mpsc::channel(1);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(1);
    let scope = test_scope();
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),
            rpcs: Arc::new(QueryRpcPool::new(
                vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                Duration::from_secs(1),
            )),
            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: worker_tx,
            public_data_plane: ChainPublicDataPlane::new(
                Arc::clone(&db),
                Arc::new(std::sync::atomic::AtomicU64::new(0)),
            ),
        },
        test_wallet_config(
            &scope,
            Url::parse("http://127.0.0.1:1").expect("quick sync url"),
        ),
        1,
        live_rx,
        worker_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");
    let (sender, mut receiver) = mpsc::channel(4);
    let batch = Arc::new(LogBatch {
        from_block: 101,
        to_block: 105,
        logs: Vec::new(),
        block_timestamps: HashMap::new(),
        to_block_hash: None,
        read_scope: PublicScanReadScope::new(PublicDataPlaneEpoch::new(0)),
    });

    let sender_clone = sender.clone();
    let send_task = tokio::spawn(async move {
        send_wallet_startup_events(
            "test",
            vec![
                WalletScanApply::rows_from_log_batch(101, 105, batch, PublicScanSource::Rpc)
                    .expect("normalize empty log payload"),
            ],
            Some(105),
            0,
            &sender_clone,
            &handle,
        )
        .await
    });

    let Some(BackfillEvent::Target {
        target_block,
        token,
        sender,
        response,
    }) = receiver.recv().await
    else {
        panic!("startup target should be sent");
    };
    response
        .send(WalletBackfillFinishResult::Accepted {
            committed_to: 100,
            target_block,
            lease: WalletBackfillLease::from_token(token, sender),
        })
        .expect("send target result");

    let Some(BackfillEvent::Apply { response, .. }) = receiver.recv().await else {
        panic!("startup apply should be sent");
    };
    response
        .send(WalletBackfillApplyResult::Rejected {
            committed_to: 100,
            reason: WalletBackfillRejectReason::ApplyFailed,
        })
        .expect("send apply failure");

    let Some(BackfillEvent::JobRetired { token: retired }) = receiver.recv().await else {
        panic!("startup token should be retired");
    };
    assert_eq!(retired, token);
    assert!(!send_task.await.expect("send task completed"));
    assert!(receiver.try_recv().is_err());

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_startup_events_retire_partial_token_without_done_block() {
    let root_dir = temp_db_root("wallet-startup-events-retire-partial");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cancel = CancellationToken::new();
    let (_live_tx, live_rx) = broadcast::channel(1);
    let (worker_tx, worker_rx) = mpsc::channel(1);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(1);
    let scope = test_scope();
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),
            rpcs: Arc::new(QueryRpcPool::new(
                vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
                Duration::from_secs(1),
            )),
            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: worker_tx,
            public_data_plane: ChainPublicDataPlane::new(
                Arc::clone(&db),
                Arc::new(std::sync::atomic::AtomicU64::new(0)),
            ),
        },
        test_wallet_config(
            &scope,
            Url::parse("http://127.0.0.1:1").expect("quick sync url"),
        ),
        1,
        live_rx,
        worker_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");
    let (sender, mut receiver) = mpsc::channel(4);
    let batch = Arc::new(LogBatch {
        from_block: 101,
        to_block: 105,
        logs: Vec::new(),
        block_timestamps: HashMap::new(),
        to_block_hash: None,
        read_scope: PublicScanReadScope::new(PublicDataPlaneEpoch::new(0)),
    });

    let sender_clone = sender.clone();
    let send_task = tokio::spawn(async move {
        send_wallet_startup_events(
            "test",
            vec![
                WalletScanApply::rows_from_log_batch(101, 105, batch, PublicScanSource::Rpc)
                    .expect("normalize empty log payload"),
            ],
            None,
            0,
            &sender_clone,
            &handle,
        )
        .await
    });

    let Some(BackfillEvent::Target {
        target_block,
        token,
        sender,
        response,
    }) = receiver.recv().await
    else {
        panic!("startup target should be sent");
    };
    response
        .send(WalletBackfillFinishResult::Accepted {
            committed_to: 100,
            target_block,
            lease: WalletBackfillLease::from_token(token, sender),
        })
        .expect("send target result");

    let Some(BackfillEvent::Apply { response, .. }) = receiver.recv().await else {
        panic!("startup apply should be sent");
    };
    response
        .send(WalletBackfillApplyResult::Committed { committed_to: 105 })
        .expect("send apply success");

    let Some(BackfillEvent::JobRetired { token: retired }) = receiver.recv().await else {
        panic!("partial startup token should be retired");
    };
    assert_eq!(retired, token);
    assert!(send_task.await.expect("send task completed"));
    assert!(receiver.try_recv().is_err());

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

fn test_chain_config(
    scope: &ChainScope,
    rpcs: Arc<QueryRpcPool>,
    indexed_artifact_source: Option<IndexedArtifactSourceConfig>,
) -> ChainConfig {
    ChainConfig {
        chain_id: scope.chain_id,
        contract: scope.railgun_contract,
        rpcs,
        archive_rpc_url: None,
        archive_until_block: 0,
        deployment_block: 0,
        v2_start_block: 0,
        legacy_shield_block: 0,
        block_range: 100,
        indexed_wallet_block_range: 100,
        poll_interval: Duration::from_millis(1),
        finality_depth: 0,
        quick_sync_endpoint: None,
        indexed_artifact_source,
        anchor_interval: 1000,
        anchor_retention: 5,
        http_client: None,
        progress_tx: None,
    }
}

fn test_chain_service(
    db: Arc<DbStore>,
    chain: ChainConfig,
    public_data_plane: ChainPublicDataPlane,
) -> Arc<ChainService> {
    test_chain_service_with_policy(db, chain, public_data_plane, test_proxy_poi_policy())
}

fn test_chain_service_with_policy(
    db: Arc<DbStore>,
    chain: ChainConfig,
    public_data_plane: ChainPublicDataPlane,
    poi_policy: GlobalPoiPolicy,
) -> Arc<ChainService> {
    let (head_tx, _head_rx) = watch::channel(0);
    let (safe_head_tx, _safe_head_rx) = watch::channel(0);
    let (forest_last_tx, _forest_last_rx) = watch::channel(0);
    let (live_log_tx, _live_log_rx) = broadcast::channel(8);
    let (backfill_tx, _backfill_rx) = mpsc::channel(1);
    Arc::new(ChainService {
        chain,
        poi_policy,
        db,
        forest: Arc::new(RwLock::new(MerkleForest::new())),
        head_tx,
        safe_head_tx,
        forest_last_tx,
        live_log_tx,
        backfill_tx,
        archive_provider: None,
        wallets: RwLock::new(HashMap::new()),
        wallet_registration_gates: Mutex::new(HashMap::new()),
        cancel: CancellationToken::new(),
        live_log_task: Mutex::new(None),
        anchor_last: std::sync::atomic::AtomicU64::new(0),
        txid_public_cache_started: std::sync::atomic::AtomicBool::new(false),
        wallet_actor_next: std::sync::atomic::AtomicU64::new(1),
        wallet_reset_intent_next: std::sync::atomic::AtomicU64::new(1),
        public_data_plane,
    })
}

struct TestArtifactSource {
    config: IndexedArtifactSourceConfig,
    server: PathServer,
}

struct PathServerBlockControl {
    request_started: std_mpsc::Receiver<()>,
    release: std_mpsc::Sender<()>,
}

struct PathServerBlock {
    path: String,
    request_started: std_mpsc::Sender<()>,
    release: std::sync::Mutex<std_mpsc::Receiver<()>>,
}

struct PathServer {
    url: Url,
}

impl PathServer {
    fn spawn(routes: HashMap<String, Vec<u8>>, request_count: usize) -> Self {
        Self::spawn_with_block(routes, request_count, None)
    }

    fn spawn_with_blocked_path(
        routes: HashMap<String, Vec<u8>>,
        request_count: usize,
        blocked_path: String,
    ) -> (Self, PathServerBlockControl) {
        let (request_started_tx, request_started) = std_mpsc::channel();
        let (release, release_rx) = std_mpsc::channel();
        let server = Self::spawn_with_block(
            routes,
            request_count,
            Some(Arc::new(PathServerBlock {
                path: blocked_path,
                request_started: request_started_tx,
                release: std::sync::Mutex::new(release_rx),
            })),
        );
        (
            server,
            PathServerBlockControl {
                request_started,
                release,
            },
        )
    }

    fn spawn_with_block(
        routes: HashMap<String, Vec<u8>>,
        request_count: usize,
        block: Option<Arc<PathServerBlock>>,
    ) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind path server");
        let url = Url::parse(&format!(
            "http://{}",
            listener.local_addr().expect("local addr")
        ))
        .expect("path server url");
        let routes = Arc::new(routes);
        std::thread::spawn({
            let routes = Arc::clone(&routes);
            move || {
                for _ in 0..request_count {
                    let (stream, _) = listener.accept().expect("accept path request");
                    let routes = Arc::clone(&routes);
                    let block = block.clone();
                    std::thread::spawn(move || handle_path_request(stream, routes, block));
                }
            }
        });
        Self { url }
    }
}

struct GraphqlServer {
    url: Url,
    requests: std_mpsc::Receiver<String>,
}

struct JsonRpcServer {
    url: Url,
    requests: std_mpsc::Receiver<String>,
}

impl GraphqlServer {
    fn spawn(responses: Vec<&'static str>) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind graphql server");
        let url = Url::parse(&format!(
            "http://{}",
            listener.local_addr().expect("local addr")
        ))
        .expect("graphql server url");
        let (request_tx, requests) = std_mpsc::channel();
        std::thread::spawn(move || {
            for response in responses {
                let (stream, _) = listener.accept().expect("accept graphql request");
                handle_graphql_request(stream, response, &request_tx);
            }
        });
        Self { url, requests }
    }
}

impl JsonRpcServer {
    fn spawn(responses: Vec<serde_json::Value>) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind json-rpc server");
        let url = Url::parse(&format!(
            "http://{}",
            listener.local_addr().expect("local addr")
        ))
        .expect("json-rpc server url");
        let (request_tx, requests) = std_mpsc::channel();
        std::thread::spawn(move || {
            for response in responses {
                let (stream, _) = listener.accept().expect("accept json-rpc request");
                handle_json_rpc_request(stream, response, &request_tx);
            }
        });
        Self { url, requests }
    }
}

fn handle_path_request(
    mut stream: std::net::TcpStream,
    routes: Arc<HashMap<String, Vec<u8>>>,
    block: Option<Arc<PathServerBlock>>,
) {
    let path = read_request_path(&mut stream);
    if let Some(block) = block.as_ref()
        && block.path == path
    {
        block
            .request_started
            .send(())
            .expect("signal blocked path request");
        block
            .release
            .lock()
            .expect("blocked path release lock")
            .recv()
            .expect("release blocked path request");
    }
    let (status, reason, body) = routes
        .get(&path)
        .map_or((404_u16, "NOT FOUND", Vec::new()), |body| {
            (200_u16, "OK", body.clone())
        });
    let headers = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).expect("write headers");
    stream.write_all(&body).expect("write body");
}

fn handle_graphql_request(
    mut stream: std::net::TcpStream,
    response: &'static str,
    requests: &std_mpsc::Sender<String>,
) {
    let request = read_http_request(&mut stream);
    requests.send(request).expect("record graphql request");
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.len()
    );
    stream.write_all(headers.as_bytes()).expect("write headers");
    stream.write_all(response.as_bytes()).expect("write body");
}

fn handle_json_rpc_request(
    mut stream: std::net::TcpStream,
    response: serde_json::Value,
    requests: &std_mpsc::Sender<String>,
) {
    let request = read_http_request(&mut stream);
    requests
        .send(request.clone())
        .expect("record json-rpc request");
    let body_start = request
        .find("\r\n\r\n")
        .map_or(request.len(), |index| index + 4);
    let id = serde_json::from_str::<serde_json::Value>(&request[body_start..])
        .ok()
        .and_then(|value| value.get("id").cloned())
        .unwrap_or_else(|| serde_json::json!(1));
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": response,
    })
    .to_string();
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).expect("write headers");
    stream.write_all(body.as_bytes()).expect("write body");
}

fn read_request_path(stream: &mut std::net::TcpStream) -> String {
    read_http_request(stream)
        .split_whitespace()
        .nth(1)
        .expect("request path")
        .to_string()
}

fn read_http_request(stream: &mut std::net::TcpStream) -> String {
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
    let header_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("header terminator")
        + 4;
    let headers = String::from_utf8_lossy(&request[..header_end]);
    let mut content_length = 0_usize;
    for line in headers.lines() {
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().expect("content length");
        }
    }
    while request.len() < header_end + content_length {
        let read = stream.read(&mut buf).expect("read request body");
        assert!(read > 0, "client closed before request body");
        request.extend_from_slice(&buf[..read]);
    }
    String::from_utf8_lossy(&request).to_string()
}

fn checkpointed_wallet_artifact_source(
    scope: ChainScope,
    start: u64,
    end: u64,
    checkpoint_block: u64,
) -> TestArtifactSource {
    checkpointed_wallet_artifact_source_controlled(scope, start, end, checkpoint_block, false).0
}

fn checkpointed_wallet_artifact_source_with_blocked_manifest(
    scope: ChainScope,
    start: u64,
    end: u64,
    checkpoint_block: u64,
) -> (TestArtifactSource, PathServerBlockControl) {
    let (source, block) =
        checkpointed_wallet_artifact_source_controlled(scope, start, end, checkpoint_block, true);
    (source, block.expect("blocked manifest control"))
}

fn checkpointed_wallet_artifact_source_controlled(
    scope: ChainScope,
    start: u64,
    end: u64,
    checkpoint_block: u64,
    block_manifest: bool,
) -> (TestArtifactSource, Option<PathServerBlockControl>) {
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let chunk_bytes = empty_wallet_scan_chunk_bytes(&scope, start, end);
    let chunk_cid = raw_cid(&chunk_bytes);
    let chunk_descriptor = wallet_artifact_descriptor(
        scope.clone(),
        start,
        end,
        0,
        chunk_cid,
        &chunk_bytes,
        DatasetDescriptorMetadata {
            catalog_generation: Some(1),
            checkpoint_block: Some(checkpoint_block),
            ..Default::default()
        },
        CompressionAlgorithm::None,
    );
    let catalog = IndexedArtifactCatalog {
        format_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
        dataset_kind: IndexedDatasetKind::WalletScan,
        scope: scope.clone(),
        chunks: vec![chunk_descriptor],
    };
    let catalog_bytes = serde_json::to_vec(&catalog).expect("catalog json");
    let catalog_cid = raw_cid(&catalog_bytes);
    let catalog_descriptor = wallet_artifact_descriptor(
        scope.clone(),
        start,
        end,
        0,
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
    let chunk_path = format!("/ipfs/{chunk_cid}?format=car&dag-scope=entity");
    let routes = HashMap::from([
        ("/manifest.json".to_string(), manifest_bytes),
        (
            format!("/ipfs/{catalog_cid}?format=car&dag-scope=entity"),
            car_bytes(catalog_cid, &[(catalog_cid, catalog_bytes)]),
        ),
        (
            chunk_path.clone(),
            car_bytes(chunk_cid, &[(chunk_cid, chunk_bytes)]),
        ),
    ]);
    let (server, block) = if block_manifest {
        let (server, block) =
            PathServer::spawn_with_blocked_path(routes, 3, "/manifest.json".to_string());
        (server, Some(block))
    } else {
        (PathServer::spawn(routes, 3), None)
    };
    let manifest_url = server.url.join("/manifest.json").expect("manifest url");
    let config = IndexedArtifactSourceConfig {
        trusted_publisher_pubkey: FixedBytes::from(signing_key.verifying_key().to_bytes()),
        manifest_source: IndexedArtifactManifestSource::Url(manifest_url),
        gateway_urls: vec![server.url.clone()],
        max_manifest_age: None,
        concurrency: 1,
        max_in_flight_bytes: 1024 * 1024,
    };
    (TestArtifactSource { config, server }, block)
}

fn wallet_artifact_descriptor(
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

fn empty_wallet_scan_chunk_bytes(scope: &ChainScope, start: u64, end: u64) -> Vec<u8> {
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

fn test_wallet_config(scope: &ChainScope, quick_sync_endpoint: Url) -> WalletConfig {
    WalletConfig {
        chain: ChainKey {
            chain_id: scope.chain_id,
            contract: scope.railgun_contract,
        },
        cache_key: "test".to_string(),
        start_block: Some(0),
        sync_to_block: None,
        quick_sync_endpoint: Some(quick_sync_endpoint),
        scan_keys: broadcaster_core::crypto::railgun::ViewingKeyData {
            viewing_private_key: [0u8; 32],
            viewing_public_key: [0u8; 32],
            nullifying_key: alloy::primitives::U256::ZERO,
            master_public_key: alloy::primitives::U256::ZERO,
        },
        spending_public_key: None,
        progress_tx: None,
        cache_store: None,
        poi_recovery_prover: None,
        use_indexed_wallet_catch_up: true,
    }
}

fn raw_cid(bytes: &[u8]) -> Cid {
    Cid::new_v1(0x55, Code::Sha2_256.digest(bytes))
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

fn write_string(bytes: &mut Vec<u8>, value: &str) {
    write_u16(bytes, u16::try_from(value.len()).expect("string len"));
    bytes.extend_from_slice(value.as_bytes());
}

fn write_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn temp_db_root(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    std::env::temp_dir().join(format!("sync-service-{name}-{unique}"))
}
