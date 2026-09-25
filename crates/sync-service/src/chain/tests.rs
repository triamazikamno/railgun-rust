use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, mpsc as std_mpsc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::primitives::{Address, FixedBytes, U256, hex};
use alloy::sol_types::SolEvent;
use alloy_rpc_types_eth::Log;
use broadcaster_core::notes::Note;
use broadcaster_core::query_rpc_pool::{LogSpanEndpoint, QueryRpcPool};
use broadcaster_core::transact::DEFAULT_TXID_VERSION;
use broadcaster_core::utxo::{Utxo, UtxoCommitmentKind, UtxoSource, WalletUtxo};
use cid::Cid;
use ed25519_dalek::SigningKey;
use local_db::{
    BlobMeta, DbConfig, DbStore, WalletCacheKey, WalletMeta, WalletPendingResetRecord,
    WalletSyncActorStateRecord,
};
use merkletree::tree::{MerkleForest, MerkleTreeUpdate};
use multihash_codetable::{Code, MultihashDigest};
use poi::cache::{PoiCache, PoiCacheIdentity};
use poi::poi::{PoiEventType, PoiStatus};
use railgun_wallet::scan::{IndexedNullifierInput, WalletScanInputRows};
use railgun_wallet::tx::PoiMerkleProofSource;
use railgun_wallet::wallet_cache::serialize_wallet_utxo;
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock, broadcast, mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;
use url::Url;

fn test_cache_key(value: impl AsRef<[u8]>) -> WalletCacheKey {
    WalletCacheKey::from_opaque_bytes(value.as_ref()).expect("non-empty test wallet cache key")
}

use super::backfill::{
    ForestLag, WalletBackfill, WalletTailFallbackState, wallet_tail_fallback_lag_threshold_blocks,
    wallet_tail_fallback_stale_timeout,
};
use super::data_plane::{PublicScanCoverageWrite, PublicScanRows};
use super::indexed_wallet::{complete_stream_checkpoint, wallet_startup_hedge_block_count};
use super::logs::combined_log_event_signatures_for_range;
use super::merkle_artifacts::run_merkle_artifact_catch_up_into;
use super::poi_submitter::test_support::{RecordedSend, RecordingPoiTransport};
use super::poi_submitter::{ChainPoiSubmitterDriver, ChainPoiSubmitterHandle};
use super::service::{
    IndexedWalletCatchUpOutcome, WalletShortStartupPlan, await_live_log_task_shutdown,
    wait_for_startup_sync_target, wait_for_wallet_ready,
};
use super::workers::{
    ForestStallTracker, HEAD_READ_STAGGER, INDEXED_TAIL_FALLBACK_COOLDOWN, INITIAL_HEAD_DEADLINE,
    IndexedForestSources, IndexedForestTrigger, WalletBackfillSlot,
    drain_pending_backfill_requests, pending_tip_from_block, pending_tip_provider_covers_target,
    read_head_bounded, reconcile_retained_acquisition, spawn_head_poller,
    wallet_lag_fallback_state_for_test,
};
use super::{
    ChainError, ChainPublicDataPlane, ChainService, CommitmentBatch, ForestReorgDecision,
    GeneratedCommitmentBatch, IndexedWalletArtifactPageOutcome, IndexedWalletArtifactSession,
    IndexedWalletCatchUpSourceOrder, IndexedWalletPageKind, LogRangeLimit, MerkleForestDbExt,
    Nullified, Nullifiers, PublicCoverageAnswer, PublicDataPlaneDiagnosticKind,
    PublicDataPlaneError, PublicPoiCorpusKey, PublicScanRange, PublicScanRowsAnswer,
    PublicScanSource, RailgunLegacyShieldEvents, Shield, Transact, TransportError,
    WalletIndexedCatchUpStatusGuard, WalletStartupSyncError, WalletWorkerServices,
    artifact_failure_can_fallback_to_squid, send_wallet_startup_events,
    should_hedge_wallet_startup, sort_logs, spawn_backfill_loop, spawn_live_log_loop,
    squid_tail_target_after_artifact, wallet_backfill_from_block,
    wallet_finish_result_removes_cursor, wallet_finish_retry_request,
    wallet_remote_target_before_cached_suffix, wallet_reorg_backfill_from_block,
    wallet_startup_warm_from_block, wallet_sync_target,
};
use super::{LocalPoiQueryUnavailable, LocalPoiRootValidation, LocalPoiStatusLookup};
use crate::SyncManager;
use crate::indexed_artifacts::{
    ChainScope, ChainType, CompressionAlgorithm, DatasetDescriptorMetadata,
    INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION, INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION,
    INDEXED_ARTIFACT_CHUNK_MAGIC, IndexedArtifactCatalog, IndexedArtifactChainEntry,
    IndexedArtifactChunkEnvelope, IndexedArtifactChunkEnvelopeHeader, IndexedArtifactChunkSection,
    IndexedArtifactDescriptor, IndexedArtifactManifest, IndexedArtifactRange,
    IndexedArtifactRangeKind, IndexedDatasetKind, LatestIndexedHeight, PublisherIdentity,
};
use crate::types::{
    BackfillEvent, BackfillRequest, ChainConfig, ChainKey, GlobalPoiPolicy,
    IndexedArtifactManifestSource, IndexedArtifactSourceConfig, LogBatch,
    PoiArtifactManifestSource, PoiArtifactSourceConfig, PoiProxyFallback, SyncProgressStage,
    SyncProgressUnit, WalletBackfillApplyResult, WalletBackfillDriver, WalletBackfillFinishResult,
    WalletBackfillGrant, WalletBackfillOwnerDisposition, WalletBackfillOwnerSignal,
    WalletBackfillRejectReason, WalletBackfillStartResult, WalletConfig, WalletCurrentSnapshot,
    WalletInactiveReason, WalletIndexedCatchUpSource, WalletObservation, WalletPendingOverlay,
    WalletReadiness, WalletReadinessError, WalletScanApply, WalletScanRowsPayload, WalletSyncToken,
    WalletViewState,
};
use crate::types::{PublicDataPlaneEpoch, PublicScanReadScope};
use crate::wallet::test_support::spawn_wallet_worker;
use crate::wallet::{WalletHandle, WalletPoiRuntime};

fn test_wallet_backfill(target_block: u64, follow_safe_head: bool) -> WalletBackfill {
    let (sender, _receiver) = mpsc::channel(1);
    WalletBackfill::new(
        100,
        target_block,
        follow_safe_head,
        100,
        None,
        test_backfill_driver(sender, 0, 1),
        std::time::Instant::now(),
    )
}

fn test_wallet_observation(readiness: WalletReadiness) -> WalletObservation {
    let view = if readiness == WalletReadiness::Shutdown {
        WalletViewState::Inactive {
            reason: WalletInactiveReason::Shutdown,
            reset_generation: 0,
        }
    } else {
        WalletViewState::Current(WalletCurrentSnapshot::new(
            0,
            0,
            0,
            Arc::<[WalletUtxo]>::from(Vec::new()),
            Arc::new(WalletPendingOverlay::default()),
        ))
    };
    WalletObservation::new(view, readiness)
}

fn test_poi_artifact_source_config() -> PoiArtifactSourceConfig {
    PoiArtifactSourceConfig {
        trusted_publisher_pubkey: FixedBytes::from([0x42; 32]),
        manifest_source: PoiArtifactManifestSource::Url(
            Url::parse("http://127.0.0.1:1/poi-manifest.json")
                .expect("POI manifest URL")
                .into(),
        ),
        gateway_urls: Vec::new(),
        gateway_pool: None,
        max_manifest_age: None,
    }
}

fn test_proxy_poi_policy() -> GlobalPoiPolicy {
    GlobalPoiPolicy::PoiProxy {
        rpc_url: Url::parse("http://127.0.0.1:1")
            .expect("POI RPC URL")
            .into(),
    }
}

fn test_wallet_poi_runtime() -> WalletPoiRuntime {
    WalletPoiRuntime::from_policy(&test_proxy_poi_policy(), None)
}

fn test_indexed_poi_policy() -> GlobalPoiPolicy {
    GlobalPoiPolicy::IndexedArtifacts {
        artifact_source: test_poi_artifact_source_config(),
        rpc_url: Url::parse("http://127.0.0.1:1")
            .expect("POI RPC URL")
            .into(),
        wallet_read_fallback: PoiProxyFallback::Disabled,
    }
}

fn test_sync_token(reset_generation: u64, job_id: u64) -> WalletSyncToken {
    WalletSyncToken::for_test(1, 1, reset_generation, job_id)
}

fn test_backfill_driver(
    sender: mpsc::Sender<BackfillEvent>,
    reset_generation: u64,
    job_id: u64,
) -> WalletBackfillDriver {
    test_backfill_driver_for_actor(sender, 1, reset_generation, job_id)
}

fn test_backfill_driver_for_actor(
    sender: mpsc::Sender<BackfillEvent>,
    actor_id: u64,
    reset_generation: u64,
    job_id: u64,
) -> WalletBackfillDriver {
    WalletBackfillDriver::from_token(
        WalletSyncToken::for_test(1, actor_id, reset_generation, job_id),
        sender,
    )
}

fn test_backfill_driver_with_retirement_signal(
    sender: mpsc::Sender<BackfillEvent>,
    actor_id: u64,
    reset_generation: u64,
    job_id: u64,
) -> (
    WalletBackfillDriver,
    oneshot::Receiver<WalletBackfillOwnerSignal>,
) {
    let (liveness, receiver) = oneshot::channel();
    let grant = WalletBackfillGrant::for_actor_accepted_job(
        WalletSyncToken::for_test(1, actor_id, reset_generation, job_id),
        sender,
        liveness,
    );
    (grant.activate(), receiver)
}

const SYNTHETIC_BACKFILL_JOB_ID: u64 = u64::MAX;

async fn assert_test_backfill_actor_current(service: &Arc<ChainService>, handle: &WalletHandle) {
    assert!(
        service
            .wallet
            .read()
            .await
            .as_ref()
            .is_some_and(|registration| registration.handle.same_actor_as(handle)),
        "installed service actor must remain current before synthetic backfill"
    );
}

async fn acknowledge_next_wallet_removal(rx: &mut mpsc::Receiver<BackfillRequest>) {
    loop {
        match rx.recv().await.expect("backfill receiver remains active") {
            BackfillRequest::Add {
                driver, cache_key, ..
            } => {
                driver.retire(&cache_key).await;
            }
            BackfillRequest::Remove { response, .. } => {
                response.send(()).expect("acknowledge wallet removal");
                return;
            }
        }
    }
}

async fn send_wallet_scan_apply(
    cache_key: &str,
    sender: &mpsc::Sender<BackfillEvent>,
    apply: WalletScanApply,
    token: WalletSyncToken,
) -> WalletBackfillApplyResult {
    WalletBackfillDriver::from_token(token, sender.clone())
        .apply(cache_key, apply)
        .await
}

async fn send_wallet_target(
    _cache_key: &str,
    sender: &mpsc::Sender<BackfillEvent>,
    target_block: u64,
    token: WalletSyncToken,
) -> WalletBackfillStartResult {
    let (response, result_rx) = oneshot::channel();
    if sender
        .send(BackfillEvent::Start {
            target_block,
            token,
            response,
        })
        .await
        .is_err()
    {
        return WalletBackfillStartResult::Rejected {
            committed_to: target_block.saturating_sub(1),
            reason: WalletBackfillRejectReason::Shutdown,
        };
    }
    result_rx
        .await
        .unwrap_or(WalletBackfillStartResult::Rejected {
            committed_to: target_block.saturating_sub(1),
            reason: WalletBackfillRejectReason::Shutdown,
        })
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
fn wallet_startup_warm_from_block_is_bounded_by_start_and_range() {
    assert_eq!(wallet_startup_warm_from_block(100, 110, 10), 101);
    assert_eq!(wallet_startup_warm_from_block(105, 110, 10), 105);
    assert_eq!(wallet_startup_warm_from_block(0, 3, 10), 0);
}

#[test]
fn historical_remote_target_stops_before_cached_warm_suffix() {
    assert_eq!(
        wallet_remote_target_before_cached_suffix(10_000, Some(9_501)),
        9_500
    );
    assert_eq!(
        wallet_remote_target_before_cached_suffix(10_000, None),
        10_000
    );
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
fn wallet_backfill_accepted_progress_resets_persistence_retry() {
    let now = std::time::Instant::now();
    let mut cursor = WalletBackfill::new(
        100,
        120,
        false,
        100,
        None,
        test_backfill_driver(mpsc::channel(1).0, 1, 1),
        now,
    );

    cursor.retry_after_rejected_apply(120);
    cursor.defer_persistence_retry(now, Duration::from_millis(10));

    assert_eq!(cursor.from_block, 100);
    assert_eq!(cursor.last_advanced_at, now);
    assert!(!cursor.is_runnable(now + Duration::from_millis(999)));
    assert!(cursor.is_runnable(now + Duration::from_secs(1)));

    cursor.mark_already_covered(121, now + Duration::from_secs(1));
    assert!(cursor.persistence_retry_at().is_none());
    assert!(cursor.is_runnable(now + Duration::from_secs(1)));
    cursor.defer_persistence_retry(now + Duration::from_secs(1), Duration::from_millis(10));
    assert!(!cursor.is_runnable(now + Duration::from_millis(1_999)));
    assert!(cursor.is_runnable(now + Duration::from_secs(2)));
    cursor.mark_progress(101, now + Duration::from_secs(1));
    assert!(cursor.persistence_retry_at().is_none());
    assert!(cursor.is_runnable(now + Duration::from_secs(1)));
}

#[test]
fn wallet_backfill_retryable_finish_rewinds_cursor_instead_of_removing() {
    let now = std::time::Instant::now();
    let mut cursor = WalletBackfill::new(
        121,
        120,
        false,
        100,
        None,
        test_backfill_driver(mpsc::channel(1).0, 1, 1),
        now,
    );
    let result = WalletBackfillFinishResult::Rejected {
        committed_to: 120,
        reason: WalletBackfillRejectReason::PersistenceFailed,
    };

    assert!(!wallet_finish_result_removes_cursor(&result));
    cursor.retry_after_rejected_finish(result.committed_to());
    cursor.defer_persistence_retry(now, Duration::from_secs(1));

    assert_eq!(cursor.from_block, 100);
    assert!(!cursor.is_runnable(now));
    assert!(cursor.is_runnable(now + Duration::from_secs(1)));
}

#[tokio::test]
async fn ready_tail_persistence_failure_queues_active_driver_for_retry() {
    let result = WalletBackfillFinishResult::Rejected {
        committed_to: 120,
        reason: WalletBackfillRejectReason::PersistenceFailed,
    };
    let token = test_sync_token(1, 1);
    let (event_sender, _event_receiver) = mpsc::channel(1);
    let (liveness, mut disposition) = oneshot::channel();
    let driver =
        WalletBackfillGrant::for_actor_accepted_job(token, event_sender, liveness).activate();

    let request = wallet_finish_retry_request("test".to_string(), 120, false, 100, &result, driver);
    assert!(matches!(
        disposition.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));

    let BackfillRequest::Add {
        from_block,
        to_block,
        progress_start_block,
        driver,
        ..
    } = request
    else {
        panic!("ready-tail finish retry must retain an active driver");
    };
    assert_eq!(from_block, 121);
    assert_eq!(to_block, 120);
    assert_eq!(progress_start_block, 100);
    assert_eq!(driver.token(), token);

    tokio::join!(
        async {
            driver.retire("test").await;
        },
        async {
            let signal = disposition.await.expect("driver retirement disposition");
            assert_eq!(
                signal.disposition,
                WalletBackfillOwnerDisposition::BenignRetirement
            );
            signal
                .acknowledgement
                .expect("explicit retirement requests acknowledgement")
                .send(())
                .expect("driver waits for retirement acknowledgement");
        }
    );
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
async fn restored_replay_is_published_before_startup_planner_can_supersede_it() {
    let root_dir = temp_db_root("service-restored-replay-admission");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc_url = Url::parse("http://127.0.0.1:1").expect("rpc url");
    let chain = test_chain_config(
        &scope,
        Arc::new(QueryRpcPool::new(
            vec![rpc_url.clone()],
            Duration::from_secs(1),
        )),
        None,
    );
    let service = test_chain_service_with_backfill(
        Arc::clone(&db),
        chain,
        ChainPublicDataPlane::new(
            Arc::clone(&db),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ),
        test_proxy_poi_policy(),
    );
    let (service, mut backfill_rx) = service;
    let mut cfg = test_wallet_config(&scope, rpc_url);
    cfg.start_block = Some(100);
    cfg.use_indexed_wallet_catch_up = false;
    db.put_wallet_meta(
        &cfg.cache_key,
        &WalletMeta {
            last_scanned_block: 79,
            updated_at: 1,
            last_scanned_block_hash: None,
        },
    )
    .expect("seed post-rewind cursor");
    db.put_wallet_sync_actor_state(&WalletSyncActorStateRecord {
        chain_id: cfg.chain.chain_id,
        wallet_id: cfg.cache_key.to_string(),
        highest_accepted_reset_intent: 7,
        pending_reset: Some(WalletPendingResetRecord {
            intent_id: 7,
            from_block: 80,
            replay_start_block: 80,
            replay_target_block: 99,
            follow_safe_head: false,
        }),
        updated_at: 1,
    })
    .expect("seed restored replay");

    let handle = service
        .register_wallet(cfg.clone())
        .await
        .expect("register wallet");
    let request = tokio::time::timeout(Duration::from_secs(1), backfill_rx.recv())
        .await
        .expect("restored replay Add arrives")
        .expect("backfill channel remains open");
    let BackfillRequest::Add {
        from_block,
        to_block,
        driver,
        cache_key,
        ..
    } = request
    else {
        panic!("restored replay must be the first backfill request");
    };
    assert_eq!((from_block, to_block), (80, 99));
    assert_eq!(driver.token().actor_id(), handle.actor_id());
    assert!(
        service
            .wallet
            .read()
            .await
            .as_ref()
            .is_some_and(|registration| registration.handle.same_actor_as(&handle))
    );
    assert_eq!(handle.readiness(), WalletReadiness::Syncing);

    service.safe_head_tx.send_replace(120);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), backfill_rx.recv())
            .await
            .is_err(),
        "generic startup must wait for restored replay completion"
    );
    assert_eq!(handle.readiness(), WalletReadiness::Syncing);

    driver.retire(&cache_key).await;
    let unregistering = tokio::spawn({
        let service = Arc::clone(&service);
        let handle = handle.clone();
        async move { service.unregister_wallet(&handle).await }
    });
    let remove = tokio::time::timeout(Duration::from_secs(1), backfill_rx.recv())
        .await
        .expect("wallet removal request arrives")
        .expect("backfill channel remains open");
    let BackfillRequest::Remove { response, .. } = remove else {
        panic!("wallet cleanup must request removal");
    };
    response.send(()).expect("acknowledge wallet removal");
    tokio::time::timeout(Duration::from_secs(1), unregistering)
        .await
        .expect("wallet unregister completes")
        .expect("wallet unregister task joins");
    service.cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn zero_head_backfill_loop_retires_and_replaces_target_zero_wallets() {
    let root_dir = temp_db_root("zero-head-backfill-retirement");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc_url = Url::parse("http://127.0.0.1:1").expect("rpc url");
    let chain = test_chain_config(
        &scope,
        Arc::new(QueryRpcPool::new(
            vec![rpc_url.clone()],
            Duration::from_secs(1),
        )),
        None,
    );
    let (service, backfill_rx) = test_chain_service_with_backfill(
        Arc::clone(&db),
        chain,
        ChainPublicDataPlane::new(
            Arc::clone(&db),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ),
        test_proxy_poi_policy(),
    );
    spawn_backfill_loop(
        Arc::clone(&service),
        backfill_rx,
        service.chain.rpcs.clone(),
        None,
        service.safe_head_tx.subscribe(),
        service.cancel.clone(),
    );

    let old = install_test_backfill_actor(&service, &scope, rpc_url.clone(), "zero-head-old").await;
    let (barrier_tx, barrier_rx) = oneshot::channel();
    service
        .backfill_tx
        .send(BackfillRequest::Remove {
            cache_key: old.cache_key.to_string(),
            actor_id: old.actor_id().saturating_add(1),
            response: barrier_tx,
        })
        .await
        .expect("send zero-head parked-state probe");
    tokio::time::timeout(Duration::from_secs(1), barrier_rx)
        .await
        .expect("zero-head loop acknowledges parked-state probe")
        .expect("zero-head probe acknowledgement remains connected");
    tokio::task::yield_now().await;

    tokio::time::timeout(Duration::from_secs(1), service.unregister_wallet(&old))
        .await
        .expect("unregister completes while safe head remains zero");
    assert!(service.wallet.read().await.is_none());

    let middle =
        install_test_backfill_actor(&service, &scope, rpc_url.clone(), "zero-head-middle").await;
    let (middle_barrier_tx, middle_barrier_rx) = oneshot::channel();
    service
        .backfill_tx
        .send(BackfillRequest::Remove {
            cache_key: middle.cache_key.to_string(),
            actor_id: middle.actor_id().saturating_add(1),
            response: middle_barrier_tx,
        })
        .await
        .expect("send second zero-head parked-state probe");
    tokio::time::timeout(Duration::from_secs(1), middle_barrier_rx)
        .await
        .expect("second zero-head probe is acknowledged")
        .expect("second zero-head probe acknowledgement remains connected");

    let mut successor_cfg = test_wallet_config(&scope, rpc_url);
    successor_cfg.cache_key = test_cache_key("zero-head-successor");
    successor_cfg.sync_to_block = Some(0);
    successor_cfg.use_indexed_wallet_catch_up = false;
    let successor = tokio::time::timeout(
        Duration::from_secs(1),
        service.replace_wallet(successor_cfg),
    )
    .await
    .expect("replace completes while safe head remains zero")
    .expect("replace succeeds");
    assert!(
        service
            .wallet_handle(successor.cache_key.as_str())
            .await
            .is_some_and(|handle| handle.same_actor_as(&successor))
    );

    tokio::time::timeout(
        Duration::from_secs(1),
        service.unregister_wallet(&successor),
    )
    .await
    .expect("successor unregister completes");
    service.cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
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
        deployment: broadcaster_core::deployment::RailgunDeployment {
            chain_id: scope.chain_id,
            contract: scope.railgun_contract,
            deployment_block: 0,
            v2_start_block: 0,
            legacy_shield_block: 0,
            relay_adapt_contract: Address::ZERO,
            relay_adapt_7702_contract: Address::ZERO,
        },
        sync: crate::RailgunSyncOptions {
            archive_until_block: 0,
            block_range: 100,
            indexed_wallet_block_range: 100,
            poll_interval: Duration::from_millis(1),
            quick_sync_endpoint: None,
            indexed_artifact_source: None,
            anchor_interval: 1000,
            anchor_retention: 5,
        },
        rpcs: Arc::new(QueryRpcPool::new(
            vec![rpc_url.clone()],
            Duration::from_secs(1),
        )),
        archive_rpc_url: None,
        block_time: Duration::from_secs(12),
        finality_depth: 0,
        http_client: reqwest::Client::new(),
        progress_tx: None,
    };
    let (head_tx, _head_rx) = watch::channel(0);
    let (safe_head_tx, _safe_head_rx) = watch::channel(0);
    let (forest_last_tx, _forest_last_rx) = watch::channel(0);
    let (live_log_tx, _live_log_rx) = broadcast::channel(8);
    let (backfill_tx, mut backfill_rx) = mpsc::channel(8);
    let backfill_task = tokio::spawn(async move {
        while let Some(request) = backfill_rx.recv().await {
            match request {
                BackfillRequest::Add {
                    driver, cache_key, ..
                } => {
                    driver.retire(&cache_key).await;
                }
                BackfillRequest::Remove { response, .. } => {
                    let _ = response.send(());
                }
            }
        }
    });
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
        wallet: RwLock::new(None),
        wallet_registration_gate: Mutex::new(()),
        cancel: CancellationToken::new(),
        live_log_task: std::sync::Mutex::new(None),
        poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        poi_submitter_task: std::sync::Mutex::new(None),
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
        service.register_wallet(cfg.clone()),
    );
    let first = first.expect("register first wallet");
    let second = second.expect("register second wallet");

    assert_eq!(first.actor_id(), second.actor_id());
    assert_eq!(first.actor_id(), 1);
    assert!(service.wallet.read().await.is_some());
    assert_eq!(
        service
            .wallet_actor_next
            .load(std::sync::atomic::Ordering::Acquire),
        2
    );

    first.publish_readiness_for_test(&WalletReadiness::Ready);
    assert_eq!(first.readiness(), WalletReadiness::Ready);
    let retained_observation = first.subscribe_observation();
    let held_authority = first.hold_actor_authority_for_test().await;
    tokio::time::timeout(Duration::from_secs(1), service.unregister_wallet(&first))
        .await
        .expect("unregister awaits the wallet worker without authority-lock contention");
    assert_eq!(
        retained_observation.borrow().readiness(),
        &WalletReadiness::Shutdown
    );
    assert!(matches!(
        retained_observation.borrow().view(),
        WalletViewState::Inactive {
            reason: WalletInactiveReason::Retired,
            ..
        }
    ));
    drop(held_authority);
    let mut distinct_a = cfg.clone();
    distinct_a.cache_key = test_cache_key("distinct-a");
    let mut distinct_b = cfg.clone();
    distinct_b.cache_key = test_cache_key("distinct-b");
    let (distinct_a, distinct_b) = tokio::join!(
        service.register_wallet(distinct_a),
        service.register_wallet(distinct_b),
    );
    assert_eq!(
        [distinct_a.is_ok(), distinct_b.is_ok()]
            .into_iter()
            .filter(|registered| *registered)
            .count(),
        1
    );
    let distinct_conflicts = usize::from(matches!(
        &distinct_a,
        Err(ChainError::WalletAlreadyRegistered)
    )) + usize::from(matches!(
        &distinct_b,
        Err(ChainError::WalletAlreadyRegistered)
    ));
    assert_eq!(distinct_conflicts, 1);
    let distinct_handle = distinct_a.or(distinct_b).expect("one distinct wallet wins");
    service.unregister_wallet(&distinct_handle).await;
    service.cancel.cancel();
    drop(service);
    backfill_task
        .await
        .expect("backfill acknowledgement task joins");
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn unexpected_terminal_wallet_is_reaped_and_concurrent_retry_replaces_once() {
    let root_dir = temp_db_root("unexpected-terminal-wallet-replacement");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc_url = Url::parse("http://127.0.0.1:1").expect("rpc url");
    let (service, mut backfill_rx) = test_chain_service_with_backfill(
        Arc::clone(&db),
        test_chain_config(
            &scope,
            Arc::new(QueryRpcPool::new(
                vec![rpc_url.clone()],
                Duration::from_secs(1),
            )),
            None,
        ),
        ChainPublicDataPlane::new(
            Arc::clone(&db),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ),
        test_proxy_poi_policy(),
    );
    let mut cfg = test_wallet_config(&scope, rpc_url);
    cfg.sync_to_block = Some(0);
    cfg.use_indexed_wallet_catch_up = false;
    let terminal = service
        .register_wallet(cfg.clone())
        .await
        .expect("register terminal wallet");
    let worker_cancel = service
        .wallet
        .read()
        .await
        .as_ref()
        .expect("terminal wallet registration")
        .cancel
        .clone();

    worker_cancel.cancel();
    tokio::time::timeout(Duration::from_secs(1), async {
        while terminal.readiness() != WalletReadiness::Shutdown {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("unexpected worker termination published shutdown");
    assert!(service.wallet_handle(&cfg.cache_key).await.is_none());

    let mut displaced_cfg = cfg.clone();
    displaced_cfg.cache_key = test_cache_key("terminal-displaced-by-b");
    let registering_cfg = displaced_cfg.clone();
    let registering = tokio::spawn({
        let service = Arc::clone(&service);
        async move { service.register_wallet(registering_cfg).await }
    });
    acknowledge_next_wallet_removal(&mut backfill_rx).await;
    let displaced = registering
        .await
        .expect("wallet B registration task joins")
        .expect("register wallet B after terminal wallet A");
    assert!(
        service
            .wallet_handle(displaced_cfg.cache_key.as_str())
            .await
            .is_some_and(|handle| handle.same_actor_as(&displaced))
    );
    let unregistering = tokio::spawn({
        let service = Arc::clone(&service);
        let displaced = displaced.clone();
        async move { service.unregister_wallet(&displaced).await }
    });
    acknowledge_next_wallet_removal(&mut backfill_rx).await;
    unregistering.await.expect("wallet B unregister task joins");

    let (first, second) = tokio::join!(
        service.register_wallet(cfg.clone()),
        service.register_wallet(cfg.clone()),
    );
    let first = first.expect("register first replacement");
    let second = second.expect("register concurrent replacement");
    assert_ne!(first.actor_id(), terminal.actor_id());
    assert_eq!(first.actor_id(), second.actor_id());
    assert_eq!(
        service
            .wallet_actor_next
            .load(std::sync::atomic::Ordering::Acquire),
        4,
        "concurrent retry must create exactly one fresh actor"
    );

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let wallet = service.wallet.read().await;
            if wallet
                .as_ref()
                .is_some_and(|registration| registration.handle.same_actor_as(&first))
            {
                break;
            }
            drop(wallet);
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("stale terminal reaper preserved the replacement");
    assert!(
        service
            .wallet_handle(&cfg.cache_key)
            .await
            .is_some_and(|handle| handle.same_actor_as(&first))
    );

    let unregistering = tokio::spawn({
        let service = Arc::clone(&service);
        let first = first.clone();
        async move { service.unregister_wallet(&first).await }
    });
    acknowledge_next_wallet_removal(&mut backfill_rx).await;
    unregistering.await.expect("first actor cleanup joins");
    service.cancel.cancel();
    drop(terminal);
    drop(first);
    drop(second);
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn terminal_reaper_cleanup_failure_shuts_down_service_before_successor_install() {
    let root_dir = temp_db_root("terminal-reaper-cleanup-failure");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc_url = Url::parse("http://127.0.0.1:1").expect("rpc url");
    let service = test_chain_service(
        Arc::clone(&db),
        test_chain_config(
            &scope,
            Arc::new(QueryRpcPool::new(
                vec![rpc_url.clone()],
                Duration::from_secs(1),
            )),
            None,
        ),
        ChainPublicDataPlane::new(
            Arc::clone(&db),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ),
    );
    let mut terminal_cfg = test_wallet_config(&scope, rpc_url.clone());
    terminal_cfg.sync_to_block = Some(0);
    terminal_cfg.use_indexed_wallet_catch_up = false;
    let terminal = service
        .register_wallet(terminal_cfg.clone())
        .await
        .expect("register terminal wallet");
    let worker_cancel = service
        .wallet
        .read()
        .await
        .as_ref()
        .expect("terminal registration")
        .cancel
        .clone();
    worker_cancel.cancel();
    tokio::time::timeout(Duration::from_secs(1), async {
        while terminal.readiness() != WalletReadiness::Shutdown {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("terminal worker reaches shutdown");
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if service.wallet.read().await.is_none() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("terminal reaper takes the registration before successor retry");

    let mut successor_cfg = terminal_cfg;
    successor_cfg.cache_key = test_cache_key("reaper-failure-successor");
    let registering = tokio::spawn({
        let service = Arc::clone(&service);
        async move { service.register_wallet(successor_cfg).await }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while !service.cancel.is_cancelled() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("terminal reaper failure shuts down service");
    let result = tokio::time::timeout(Duration::from_secs(1), registering)
        .await
        .expect("successor registration resolves")
        .expect("successor registration task joins");
    assert!(matches!(result, Err(ChainError::Shutdown)));
    assert!(service.wallet.read().await.is_none());
    drop(terminal);
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn replace_wallet_waits_for_old_worker_and_fences_stale_removal() {
    let root_dir = temp_db_root("replace-wallet-ordering");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc_url = Url::parse("http://127.0.0.1:1").expect("rpc url");
    let (service, mut backfill_rx) = test_chain_service_with_backfill(
        Arc::clone(&db),
        test_chain_config(
            &scope,
            Arc::new(QueryRpcPool::new(
                vec![rpc_url.clone()],
                Duration::from_secs(1),
            )),
            None,
        ),
        ChainPublicDataPlane::new(
            Arc::clone(&db),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ),
        test_proxy_poi_policy(),
    );
    let mut old_cfg = test_wallet_config(&scope, rpc_url.clone());
    old_cfg.sync_to_block = Some(0);
    old_cfg.use_indexed_wallet_catch_up = false;
    let old_handle = service
        .register_wallet(old_cfg)
        .await
        .expect("register old wallet");
    old_handle.publish_readiness_for_test(&WalletReadiness::Ready);

    let (worker_finished_tx, worker_finished_rx) = oneshot::channel();
    let (release_worker_tx, release_worker_rx) = oneshot::channel();
    {
        let mut wallet = service.wallet.write().await;
        let registration = wallet.as_mut().expect("old registration");
        let old_worker = std::mem::replace(&mut registration.worker, tokio::spawn(async {}));
        registration.worker = tokio::spawn(async move {
            old_worker.await.expect("old worker completed");
            let _ = worker_finished_tx.send(());
            let _ = release_worker_rx.await;
        });
    }

    let mut successor_cfg = test_wallet_config(&scope, rpc_url);
    successor_cfg.cache_key = test_cache_key("replacement-successor");
    successor_cfg.sync_to_block = Some(0);
    successor_cfg.use_indexed_wallet_catch_up = false;
    let replacing = tokio::spawn({
        let service = Arc::clone(&service);
        async move { service.replace_wallet(successor_cfg).await }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while old_handle.readiness() != WalletReadiness::Shutdown {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("replacement retires old actor");
    tokio::time::timeout(Duration::from_secs(1), worker_finished_rx)
        .await
        .expect("old worker reaches controlled cleanup blocker")
        .expect("controlled cleanup notification is sent");
    let remove_response = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match backfill_rx
                .recv()
                .await
                .expect("backfill loop remains active")
            {
                BackfillRequest::Add {
                    driver, cache_key, ..
                } => {
                    driver.retire(&cache_key).await;
                }
                BackfillRequest::Remove { response, .. } => break response,
            }
        }
    })
    .await
    .expect("replacement sends backfill removal");
    for _ in 0..8 {
        assert!(service.wallet.read().await.is_none());
        assert!(!replacing.is_finished());
        tokio::task::yield_now().await;
    }

    release_worker_tx.send(()).expect("release old worker");
    remove_response
        .send(())
        .expect("acknowledge retired backfill cursor");
    let successor = tokio::time::timeout(Duration::from_secs(1), replacing)
        .await
        .expect("replacement completes after worker cleanup")
        .expect("replacement task joins")
        .expect("replacement succeeds");
    assert!(
        service
            .wallet_handle(successor.cache_key.as_str())
            .await
            .is_some_and(|handle| handle.same_actor_as(&successor))
    );

    service.unregister_wallet(&old_handle).await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert!(
        service
            .wallet_handle(successor.cache_key.as_str())
            .await
            .is_some_and(|handle| handle.same_actor_as(&successor))
    );
    let unregistering = tokio::spawn({
        let service = Arc::clone(&service);
        let successor = successor.clone();
        async move { service.unregister_wallet(&successor).await }
    });
    loop {
        match backfill_rx
            .recv()
            .await
            .expect("backfill loop remains active")
        {
            BackfillRequest::Add {
                driver, cache_key, ..
            } => {
                driver.retire(&cache_key).await;
            }
            BackfillRequest::Remove { response, .. } => {
                response.send(()).expect("acknowledge successor removal");
                break;
            }
        }
    }
    unregistering.await.expect("successor cleanup joins");
    service.cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn replace_wallet_owned_operation_survives_caller_abort() {
    let root_dir = temp_db_root("replace-wallet-backfill-ack");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc_url = Url::parse("http://127.0.0.1:1").expect("rpc url");
    let (service, mut backfill_rx) = test_chain_service_with_backfill(
        Arc::clone(&db),
        test_chain_config(
            &scope,
            Arc::new(QueryRpcPool::new(
                vec![rpc_url.clone()],
                Duration::from_secs(1),
            )),
            None,
        ),
        ChainPublicDataPlane::new(
            Arc::clone(&db),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ),
        test_proxy_poi_policy(),
    );
    let mut old_cfg = test_wallet_config(&scope, rpc_url.clone());
    old_cfg.sync_to_block = Some(0);
    old_cfg.use_indexed_wallet_catch_up = false;
    let old_handle = service
        .register_wallet(old_cfg)
        .await
        .expect("register old wallet");
    old_handle.publish_readiness_for_test(&WalletReadiness::Ready);

    let mut successor_cfg = test_wallet_config(&scope, rpc_url);
    successor_cfg.cache_key = test_cache_key("ack-successor");
    successor_cfg.sync_to_block = Some(0);
    successor_cfg.use_indexed_wallet_catch_up = false;
    let successor_cache_key = successor_cfg.cache_key.clone();
    let replacing = tokio::spawn({
        let service = Arc::clone(&service);
        async move { service.replace_wallet(successor_cfg).await }
    });

    let response = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match backfill_rx
                .recv()
                .await
                .expect("backfill loop remains active")
            {
                BackfillRequest::Add {
                    driver, cache_key, ..
                } => {
                    driver.retire(&cache_key).await;
                }
                BackfillRequest::Remove { response, .. } => break response,
            }
        }
    })
    .await
    .expect("replacement sends backfill removal");
    assert!(
        !replacing.is_finished(),
        "replacement must await removal ack"
    );
    assert!(service.wallet.read().await.is_none());
    replacing.abort();
    response
        .send(())
        .expect("send backfill removal acknowledgement");
    let successor = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let Some(handle) = service.wallet_handle(&successor_cache_key).await {
                break handle;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("owned replacement completes after caller abort");
    assert!(
        service
            .wallet_handle(successor.cache_key.as_str())
            .await
            .is_some_and(|handle| handle.same_actor_as(&successor))
    );
    service.unregister_wallet(&old_handle).await;
    let unregistering = tokio::spawn({
        let service = Arc::clone(&service);
        let successor = successor.clone();
        async move { service.unregister_wallet(&successor).await }
    });
    loop {
        match backfill_rx
            .recv()
            .await
            .expect("backfill loop remains active")
        {
            BackfillRequest::Add {
                driver, cache_key, ..
            } => {
                driver.retire(&cache_key).await;
            }
            BackfillRequest::Remove { response, .. } => {
                response.send(()).expect("acknowledge successor removal");
                break;
            }
        }
    }
    unregistering.await.expect("successor cleanup joins");
    service.cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn replace_wallet_leaves_slot_empty_when_old_worker_cleanup_panics() {
    let root_dir = temp_db_root("replace-wallet-worker-panic");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc_url = Url::parse("http://127.0.0.1:1").expect("rpc url");
    let (service, mut backfill_rx) = test_chain_service_with_backfill(
        Arc::clone(&db),
        test_chain_config(
            &scope,
            Arc::new(QueryRpcPool::new(
                vec![rpc_url.clone()],
                Duration::from_secs(1),
            )),
            None,
        ),
        ChainPublicDataPlane::new(
            Arc::clone(&db),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ),
        test_proxy_poi_policy(),
    );
    let mut old_cfg = test_wallet_config(&scope, rpc_url.clone());
    old_cfg.sync_to_block = Some(0);
    old_cfg.use_indexed_wallet_catch_up = false;
    let old_handle = service
        .register_wallet(old_cfg)
        .await
        .expect("register old wallet");
    old_handle.publish_readiness_for_test(&WalletReadiness::Ready);
    {
        let mut wallet = service.wallet.write().await;
        let registration = wallet.as_mut().expect("old registration");
        let original = std::mem::replace(&mut registration.worker, tokio::spawn(async {}));
        registration.worker = tokio::spawn(async move {
            let _ = original.await;
            panic!("intentional retirement worker panic");
        });
    }

    let mut successor_cfg = test_wallet_config(&scope, rpc_url);
    successor_cfg.cache_key = test_cache_key("panic-successor");
    successor_cfg.sync_to_block = Some(0);
    successor_cfg.use_indexed_wallet_catch_up = false;
    let replacing = tokio::spawn({
        let service = Arc::clone(&service);
        async move { service.replace_wallet(successor_cfg).await }
    });
    let response = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match backfill_rx
                .recv()
                .await
                .expect("backfill loop remains active")
            {
                BackfillRequest::Add {
                    driver, cache_key, ..
                } => {
                    driver.retire(&cache_key).await;
                }
                BackfillRequest::Remove { response, .. } => break response,
            }
        }
    })
    .await
    .expect("replacement sends backfill removal");
    response
        .send(())
        .expect("send backfill removal acknowledgement");
    let error = tokio::time::timeout(Duration::from_secs(1), replacing)
        .await
        .expect("replacement completes after cleanup failure")
        .expect("replacement task joins")
        .expect_err("worker panic must reject replacement");
    assert!(matches!(error, ChainError::WalletWorkerRetirementFailed));
    assert!(service.wallet.read().await.is_none());
    assert!(
        service
            .wallet_handle(old_handle.cache_key.as_str())
            .await
            .is_none()
    );
    service.cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn reset_wallets_serializes_replacement_until_actor_authority_is_released() {
    let root_dir = temp_db_root("reset-wallet-replacement-ordering");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc_url = Url::parse("http://127.0.0.1:1").expect("rpc url");
    let (service, mut backfill_rx) = test_chain_service_with_backfill(
        Arc::clone(&db),
        test_chain_config(
            &scope,
            Arc::new(QueryRpcPool::new(
                vec![rpc_url.clone()],
                Duration::from_secs(1),
            )),
            None,
        ),
        ChainPublicDataPlane::new(
            Arc::clone(&db),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ),
        test_proxy_poi_policy(),
    );
    let mut old_cfg = test_wallet_config(&scope, rpc_url.clone());
    old_cfg.sync_to_block = Some(0);
    old_cfg.use_indexed_wallet_catch_up = false;
    let old_handle = service
        .register_wallet(old_cfg)
        .await
        .expect("register old wallet");
    old_handle.publish_readiness_for_test(&WalletReadiness::Ready);
    let authority = old_handle.hold_actor_authority_for_test().await;
    let resetting = tokio::spawn({
        let service = Arc::clone(&service);
        async move { service.reset_wallets(0, 0).await }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if service.wallet_registration_gate.try_lock().is_err() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("reset owns registration gate");

    let mut successor_cfg = test_wallet_config(&scope, rpc_url);
    successor_cfg.cache_key = test_cache_key("reset-successor");
    successor_cfg.sync_to_block = Some(0);
    successor_cfg.use_indexed_wallet_catch_up = false;
    let replacing = tokio::spawn({
        let service = Arc::clone(&service);
        async move { service.replace_wallet(successor_cfg).await }
    });
    for _ in 0..8 {
        assert!(!resetting.is_finished());
        assert!(!replacing.is_finished());
        assert!(service.wallet.read().await.is_some());
        tokio::task::yield_now().await;
    }
    drop(authority);
    tokio::time::timeout(Duration::from_secs(1), resetting)
        .await
        .expect("reset completes after authority release")
        .expect("reset task joins");

    let response = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match backfill_rx
                .recv()
                .await
                .expect("backfill loop remains active")
            {
                BackfillRequest::Add {
                    driver, cache_key, ..
                } => {
                    driver.retire(&cache_key).await;
                }
                BackfillRequest::Remove { response, .. } => break response,
            }
        }
    })
    .await
    .expect("replacement sends backfill removal");
    response
        .send(())
        .expect("send backfill removal acknowledgement");
    let successor = tokio::time::timeout(Duration::from_secs(1), replacing)
        .await
        .expect("replacement completes after reset")
        .expect("replacement task joins")
        .expect("replacement succeeds");
    assert!(
        service
            .wallet_handle(successor.cache_key.as_str())
            .await
            .is_some_and(|handle| handle.same_actor_as(&successor))
    );
    let unregistering = tokio::spawn({
        let service = Arc::clone(&service);
        let successor = successor.clone();
        async move { service.unregister_wallet(&successor).await }
    });
    loop {
        match backfill_rx
            .recv()
            .await
            .expect("backfill loop remains active")
        {
            BackfillRequest::Add {
                driver, cache_key, ..
            } => {
                driver.retire(&cache_key).await;
            }
            BackfillRequest::Remove { response, .. } => {
                response.send(()).expect("acknowledge successor removal");
                break;
            }
        }
    }
    unregistering.await.expect("successor cleanup joins");
    service.cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_lag_fallback_resets_timing_for_same_key_reincarnation() {
    let root_dir = temp_db_root("wallet-lag-reincarnation");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc_url = Url::parse("http://127.0.0.1:1").expect("rpc url");
    let (service, mut backfill_rx) = test_chain_service_with_backfill(
        Arc::clone(&db),
        test_chain_config(
            &scope,
            Arc::new(QueryRpcPool::new(
                vec![rpc_url.clone()],
                Duration::from_secs(1),
            )),
            None,
        ),
        ChainPublicDataPlane::new(
            Arc::clone(&db),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ),
        test_proxy_poi_policy(),
    );
    let mut cfg = test_wallet_config(&scope, rpc_url);
    cfg.use_indexed_wallet_catch_up = true;
    cfg.sync_to_block = Some(1_000);
    let first = service
        .register_wallet(cfg.clone())
        .await
        .expect("register first actor");
    first.publish_readiness_for_test(&WalletReadiness::Ready);
    let mut state = None;
    let now = std::time::Instant::now();
    let first_state = wallet_lag_fallback_state_for_test(&service, &mut state, 1_000, now)
        .await
        .expect("first lag state");
    assert_eq!(first_state.0, first.actor_id());
    assert!(!first_state.1);
    let first_attempt = wallet_lag_fallback_state_for_test(
        &service,
        &mut state,
        1_000,
        now + Duration::from_secs(20),
    )
    .await
    .expect("first lag attempt state");
    assert_eq!(first_attempt.0, first.actor_id());
    assert!(first_attempt.1);

    let unregistering = tokio::spawn({
        let service = Arc::clone(&service);
        let first = first.clone();
        async move { service.unregister_wallet(&first).await }
    });
    acknowledge_next_wallet_removal(&mut backfill_rx).await;
    unregistering.await.expect("first actor cleanup joins");
    let second = service
        .register_wallet(cfg)
        .await
        .expect("register reincarnated actor");
    second.publish_readiness_for_test(&WalletReadiness::Ready);
    let second_state = wallet_lag_fallback_state_for_test(
        &service,
        &mut state,
        1_000,
        now + Duration::from_secs(21),
    )
    .await
    .expect("reincarnated lag state");
    assert_eq!(second_state.0, second.actor_id());
    assert!(!second_state.1);
    let unregistering = tokio::spawn({
        let service = Arc::clone(&service);
        let second = second.clone();
        async move { service.unregister_wallet(&second).await }
    });
    acknowledge_next_wallet_removal(&mut backfill_rx).await;
    unregistering.await.expect("second actor cleanup joins");
    service.cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn manager_resets_persisted_cache_once_and_every_registered_public_data_plane() {
    let root_dir = temp_db_root("manager-public-cache-reset");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open manager reset db"),
    );
    let rpc_url = Url::parse("http://127.0.0.1:1").expect("rpc url");
    let txid_kind = crate::txid_cache::TXID_CACHE_BLOB_KIND;
    let txid_name = "manager-reset-page.bin";
    let txid_id = "manager-reset-page";
    db.ensure_blob_dir(txid_kind).expect("ensure TXID blob dir");
    fs::write(db.blob_path(txid_kind, txid_name), b"TXID cache").expect("write TXID cache file");
    db.put_blob_meta(
        txid_kind,
        txid_id,
        &BlobMeta {
            format_version: 1,
            relative_path: DbStore::relative_blob_path(txid_kind, txid_name),
            content_hash: Sha256::digest(b"TXID cache").into(),
            source_hash: None,
            source_sequence: None,
            created_at: 1,
            updated_at: 1,
            last_accessed_at: 1,
            last_block: None,
        },
    )
    .expect("write TXID cache metadata");
    assert_eq!(
        db.poi_artifact_cache_generation()
            .expect("initial POI cache generation"),
        0
    );
    let scopes = [
        ChainScope {
            chain_type: ChainType::Evm,
            chain_id: 1,
            railgun_contract: Address::from([0x11; 20]),
        },
        ChainScope {
            chain_type: ChainType::Evm,
            chain_id: 2,
            railgun_contract: Address::from([0x22; 20]),
        },
    ];
    let mut registered = Vec::new();
    let manager = SyncManager::new(Arc::clone(&db), test_proxy_poi_policy())
        .expect("acquire manager ownership");
    for scope in scopes {
        let chain = test_chain_config(
            &scope,
            Arc::new(QueryRpcPool::new(
                vec![rpc_url.clone()],
                Duration::from_secs(1),
            )),
            None,
        );
        let key = ChainKey {
            chain_id: chain.deployment.chain_id,
            contract: chain.deployment.contract,
        };
        let public_data_plane = ChainPublicDataPlane::new(
            Arc::clone(&db),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        );
        let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
        assert!(service.wallet.read().await.is_none());
        manager.insert_chain_for_test(key, Arc::clone(&service));
        registered.push((key, service));
    }

    let report = manager
        .reset_public_sync_caches()
        .await
        .expect("manager accepts public cache reset");

    assert_eq!(report.chains.len(), 2);
    assert_eq!(
        report
            .chains
            .iter()
            .map(|reset| reset.chain.chain_id)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(report.failed_chain_count(), 0);
    let persisted = report
        .persisted
        .as_ref()
        .expect("persisted manager reset succeeds");
    assert_eq!(persisted.txid_blob_entries_removed, 1);
    assert_eq!(persisted.total_removed_entries(), 1);
    assert_eq!(report.total_removed_entries, 1);
    assert_eq!(
        db.poi_artifact_cache_generation()
            .expect("POI cache generation after manager reset"),
        0,
        "raw public cache reset preserves the serving-corpus generation"
    );
    for (key, service) in &registered {
        let reset = report
            .chains
            .iter()
            .find(|reset| reset.chain == *key)
            .expect("registered chain reset result")
            .result
            .as_ref()
            .expect("registered chain reset succeeds");
        assert_eq!(reset.previous_epoch, PublicDataPlaneEpoch::new(0));
        assert_eq!(reset.new_epoch, PublicDataPlaneEpoch::new(1));
        assert_eq!(
            service.public_data_plane().diagnostics().await.epoch,
            PublicDataPlaneEpoch::new(1),
        );
        assert!(service.wallet.read().await.is_none());
    }

    manager.shutdown().await;
    drop(registered);
    drop(manager);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove manager reset db");
}

#[tokio::test]
async fn manager_public_cache_reset_reports_empty_inventory() {
    let root_dir = temp_db_root("manager-empty-public-cache-reset");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open empty manager reset db"),
    );
    let manager = SyncManager::new(Arc::clone(&db), test_proxy_poi_policy())
        .expect("acquire manager ownership");

    let report = manager
        .reset_public_sync_caches()
        .await
        .expect("manager accepts public cache reset");

    assert!(report.is_empty());
    assert_eq!(report.total_removed_entries, 0);
    assert_eq!(report.failed_chain_count(), 0);
    manager.shutdown().await;
    drop(manager);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove empty manager reset db");
}

#[tokio::test]
async fn session_removal_routes_by_handle_and_rejects_cross_service_actor_collision() {
    let root_a = temp_db_root("session-removal-chain-a");
    let root_b = temp_db_root("session-removal-chain-b");
    let root_reincarnated = temp_db_root("session-removal-chain-a-reincarnated");
    let db_a = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_a.clone(),
        })
        .expect("open chain A db"),
    );
    let db_b = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_b.clone(),
        })
        .expect("open chain B db"),
    );
    let db_reincarnated = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_reincarnated.clone(),
        })
        .expect("open reincarnated chain A db"),
    );
    let scope_a = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xaa; 20]),
    };
    let scope_b = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xbb; 20]),
    };
    let rpc_url = Url::parse("http://127.0.0.1:1").expect("rpc url");
    let chain_a = test_chain_config(
        &scope_a,
        Arc::new(QueryRpcPool::new(
            vec![rpc_url.clone()],
            Duration::from_secs(1),
        )),
        None,
    );
    let chain_b = test_chain_config(
        &scope_b,
        Arc::new(QueryRpcPool::new(
            vec![rpc_url.clone()],
            Duration::from_secs(1),
        )),
        None,
    );
    let chain_a_key = ChainKey {
        chain_id: chain_a.deployment.chain_id,
        contract: chain_a.deployment.contract,
    };
    let chain_b_key = ChainKey {
        chain_id: chain_b.deployment.chain_id,
        contract: chain_b.deployment.contract,
    };
    let service_a = test_chain_service(
        Arc::clone(&db_a),
        chain_a,
        ChainPublicDataPlane::new(
            Arc::clone(&db_a),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ),
    );
    let service_b = test_chain_service(
        Arc::clone(&db_b),
        chain_b,
        ChainPublicDataPlane::new(
            Arc::clone(&db_b),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ),
    );
    let manager = SyncManager::new(Arc::clone(&db_a), test_proxy_poi_policy())
        .expect("acquire manager ownership");
    manager.insert_chain_for_test(chain_a_key, Arc::clone(&service_a));
    manager.insert_chain_for_test(chain_b_key, Arc::clone(&service_b));

    let shared_cache_key = test_cache_key("shared-session");
    let mut cfg_a = test_wallet_config(&scope_a, rpc_url.clone());
    cfg_a.cache_key = shared_cache_key.clone();
    cfg_a.sync_to_block = Some(0);
    cfg_a.use_indexed_wallet_catch_up = false;
    let mut cfg_b = test_wallet_config(&scope_b, rpc_url.clone());
    cfg_b.cache_key = shared_cache_key.clone();
    cfg_b.sync_to_block = Some(0);
    cfg_b.use_indexed_wallet_catch_up = false;

    let handle_a = manager
        .add_wallet(cfg_a.clone())
        .await
        .expect("register chain A");
    let handle_b = manager.add_wallet(cfg_b).await.expect("register chain B");
    assert_eq!(handle_a.actor_id(), 1);
    assert_eq!(handle_b.actor_id(), 1);

    service_b.unregister_wallet(&handle_a).await;
    assert!(service_a.wallet_handle(&shared_cache_key).await.is_some());
    assert!(service_b.wallet_handle(&shared_cache_key).await.is_some());

    manager
        .remove_wallet_session(&handle_a)
        .await
        .expect("remove chain A session by handle");
    assert!(service_a.wallet_handle(&shared_cache_key).await.is_none());
    assert_eq!(
        service_b
            .wallet_handle(&shared_cache_key)
            .await
            .expect("chain B actor remains registered")
            .actor_id(),
        handle_b.actor_id(),
    );

    let replacement_a = manager
        .add_wallet(cfg_a)
        .await
        .expect("register replacement chain A actor");
    assert_ne!(replacement_a.actor_id(), handle_a.actor_id());
    service_a.unregister_wallet(&handle_a).await;
    manager
        .remove_wallet_session(&handle_a)
        .await
        .expect("stale manager removal is a no-op");
    assert_eq!(
        service_a
            .wallet_handle(&shared_cache_key)
            .await
            .expect("replacement chain A actor remains registered")
            .actor_id(),
        replacement_a.actor_id(),
    );

    let reincarnated_chain_a = test_chain_config(
        &scope_a,
        Arc::new(QueryRpcPool::new(
            vec![rpc_url.clone()],
            Duration::from_secs(1),
        )),
        None,
    );
    let reincarnated_service_a = test_chain_service(
        Arc::clone(&db_reincarnated),
        reincarnated_chain_a,
        ChainPublicDataPlane::new(
            Arc::clone(&db_reincarnated),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ),
    );
    let mut reincarnated_cfg_a = test_wallet_config(&scope_a, rpc_url);
    reincarnated_cfg_a.cache_key = shared_cache_key.clone();
    reincarnated_cfg_a.sync_to_block = Some(0);
    reincarnated_cfg_a.use_indexed_wallet_catch_up = false;
    let reincarnated_handle_a = reincarnated_service_a
        .register_wallet(reincarnated_cfg_a)
        .await
        .expect("register reincarnated chain A actor");
    assert_eq!(reincarnated_handle_a.actor_id(), handle_a.actor_id());
    assert_eq!(reincarnated_handle_a.chain_key(), handle_a.chain_key());

    reincarnated_service_a.unregister_wallet(&handle_a).await;
    assert!(
        reincarnated_service_a
            .wallet_handle(&shared_cache_key)
            .await
            .is_some(),
        "a stale handle must not retire an actor from a reincarnated service",
    );
    let current_handle_clone = reincarnated_handle_a.clone();
    reincarnated_service_a
        .unregister_wallet(&current_handle_clone)
        .await;
    assert!(
        reincarnated_service_a
            .wallet_handle(&shared_cache_key)
            .await
            .is_none(),
        "a clone of the current handle must unregister its actor",
    );
    reincarnated_service_a.shutdown().await;

    manager.remove_all_wallets().await;
    manager.shutdown().await;
    drop(handle_a);
    drop(handle_b);
    drop(replacement_a);
    drop(reincarnated_handle_a);
    drop(current_handle_clone);
    drop(service_a);
    drop(service_b);
    drop(reincarnated_service_a);
    drop(manager);
    drop(db_a);
    drop(db_b);
    drop(db_reincarnated);
    fs::remove_dir_all(root_a).expect("remove chain A temp db dir");
    fs::remove_dir_all(root_b).expect("remove chain B temp db dir");
    fs::remove_dir_all(root_reincarnated).expect("remove reincarnated chain A temp db dir");
}

#[tokio::test]
async fn shutdown_terminalizes_readiness_and_awaits_owned_worker_panic() {
    let root_dir = temp_db_root("wallet-shutdown-owned-worker");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc_url = Url::parse("http://127.0.0.1:1").expect("rpc url");
    let (service, mut backfill_rx) = test_chain_service_with_backfill(
        Arc::clone(&db),
        test_chain_config(
            &scope,
            Arc::new(QueryRpcPool::new(
                vec![rpc_url.clone()],
                Duration::from_secs(1),
            )),
            None,
        ),
        ChainPublicDataPlane::new(
            Arc::clone(&db),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ),
        test_proxy_poi_policy(),
    );
    let mut cfg = test_wallet_config(&scope, rpc_url);
    cfg.sync_to_block = Some(0);
    cfg.use_indexed_wallet_catch_up = false;
    let handle = service.register_wallet(cfg).await.expect("register wallet");
    handle.publish_readiness_for_test(&WalletReadiness::Ready);
    assert_eq!(handle.readiness(), WalletReadiness::Ready);
    let mut retained_observation = handle.subscribe_observation();
    let held_authority = handle.hold_actor_authority_for_test().await;

    let (owned_worker_completed_tx, owned_worker_completed_rx) = oneshot::channel();
    let (release_owned_worker_tx, release_owned_worker_rx) = oneshot::channel();
    {
        let mut wallet = service.wallet.write().await;
        let registration = wallet.as_mut().expect("wallet registration");
        let owned_worker = std::mem::replace(&mut registration.worker, tokio::spawn(async {}));
        registration.worker = tokio::spawn(async move {
            owned_worker.await.expect("owned wallet worker completed");
            let _ = owned_worker_completed_tx.send(());
            let _ = release_owned_worker_rx.await;
            panic!("controlled wallet worker panic");
        });
    }

    let shutdown_service = Arc::clone(&service);
    let shutdown = tokio::spawn(async move {
        shutdown_service.shutdown().await;
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while retained_observation.borrow().readiness() != &WalletReadiness::Shutdown {
            retained_observation
                .changed()
                .await
                .expect("retirement keeps readiness sender alive");
        }
    })
    .await
    .expect("shutdown terminalized retained readiness");
    assert!(matches!(
        retained_observation.borrow().view(),
        WalletViewState::Inactive {
            reason: WalletInactiveReason::Shutdown,
            ..
        }
    ));
    tokio::time::timeout(Duration::from_secs(1), owned_worker_completed_rx)
        .await
        .expect("shutdown cancelled and awaited the wallet worker despite authority contention")
        .expect("owned worker reached retirement barrier");
    acknowledge_next_wallet_removal(&mut backfill_rx).await;
    assert!(
        !shutdown.is_finished(),
        "shutdown must await its owned worker"
    );

    release_owned_worker_tx
        .send(())
        .expect("release owned worker panic");
    tokio::time::timeout(Duration::from_secs(1), shutdown)
        .await
        .expect("shutdown completed after owned worker exit")
        .expect("shutdown task completed");
    assert_eq!(handle.readiness(), WalletReadiness::Shutdown);
    drop(held_authority);

    drop(handle);
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_startup_reuses_recent_rows_before_short_tail_hedge() {
    let root_dir = temp_db_root("wallet-startup-recent-rows");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc_url = Url::parse("http://127.0.0.1:1").expect("rpc url");
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc_url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    chain.sync.quick_sync_endpoint = Some(rpc_url.clone());
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    public_data_plane
        .record_recent_public_scan_rows(crate::chain::PublicScanRows {
            range: PublicScanRange::new(101, 110),
            source: PublicScanSource::Rpc,
            to_block_hash: Some([0x11; 32]),
            rows: WalletScanInputRows {
                nullifiers: vec![IndexedNullifierInput {
                    tree_number: 1,
                    nullifier: U256::from(1),
                    source: UtxoSource {
                        tx_hash: FixedBytes::from([0x22; 32]),
                        block_number: 105,
                        block_timestamp: 1_700_000_105,
                    },
                }],
                ..WalletScanInputRows::default()
            },
            epoch: public_data_plane.current_epoch(),
        })
        .await
        .expect("record recent public rows");
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
    service.safe_head_tx.send_replace(110);
    let mut cfg = test_wallet_config(&scope, rpc_url);
    cfg.start_block = Some(101);
    cfg.sync_to_block = Some(110);

    let mut handle = service.register_wallet(cfg).await.expect("register wallet");
    tokio::time::timeout(Duration::from_secs(1), handle.wait_until_ready())
        .await
        .expect("cached recent rows made wallet ready")
        .expect("wallet readiness succeeded");

    assert_eq!(handle.last_scanned(), Some(110));
    service.unregister_all_wallets().await;
    service.shutdown().await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_startup_replays_empty_coverage_endpoint_hash_to_checkpoint() {
    let root_dir = temp_db_root("wallet-startup-empty-coverage-hash");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc_url = Url::parse("http://127.0.0.1:1").expect("rpc url");
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc_url.clone()],
        Duration::from_secs(1),
    ));
    let chain = test_chain_config(&scope, rpcs, None);
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    public_data_plane
        .record_recent_public_scan_rows(PublicScanRows {
            range: PublicScanRange::new(101, 110),
            source: PublicScanSource::Rpc,
            to_block_hash: Some([0x44; 32]),
            rows: WalletScanInputRows::default(),
            epoch: public_data_plane.current_epoch(),
        })
        .await
        .expect("record empty public coverage");
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
    service.safe_head_tx.send_replace(110);
    let mut cfg = test_wallet_config(&scope, rpc_url);
    cfg.start_block = Some(101);
    cfg.sync_to_block = Some(110);
    let cache_key = cfg.cache_key.clone();

    let mut handle = service.register_wallet(cfg).await.expect("register wallet");
    tokio::time::timeout(Duration::from_secs(1), handle.wait_until_ready())
        .await
        .expect("cached empty coverage made wallet ready")
        .expect("wallet readiness succeeded");

    let checkpoint = db
        .get_wallet_meta(&cache_key)
        .expect("read wallet checkpoint")
        .expect("wallet checkpoint present");
    assert_eq!(checkpoint.last_scanned_block, 110);
    assert_eq!(checkpoint.last_scanned_block_hash, Some([0x44; 32]));

    service.unregister_all_wallets().await;
    service.shutdown().await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn indexed_disabled_short_startup_warms_and_reuses_full_rpc_window() {
    let root_dir = temp_db_root("wallet-switch-rpc-rows");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let target_block = 110;
    let (release_warm, warm_gate) = std_mpsc::channel();
    let rpc = JsonRpcServer::spawn_handler(gated_get_logs_handler(
        log_range_rpc_handler(
            vec![rpc_nullifiers_log_with_timestamp(
                scope.railgun_contract,
                105,
            )],
            target_block,
            |_, _, _| None,
        ),
        vec![((101, 105), warm_gate)],
    ));
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    chain.sync.block_range = 10;
    chain.finality_depth = 0;
    chain.sync.quick_sync_endpoint = None;
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
    service.safe_head_tx.send_replace(target_block);

    let mut first_cfg = test_wallet_config(&scope, rpc.url.clone());
    first_cfg.cache_key = test_cache_key("wallet-a");
    first_cfg.start_block = Some(101);
    first_cfg.sync_to_block = Some(target_block);
    first_cfg.use_indexed_wallet_catch_up = false;
    let first_cache_key = first_cfg.cache_key.clone();
    db.put_wallet_meta(
        &first_cfg.cache_key,
        &WalletMeta {
            last_scanned_block: 105,
            updated_at: 1,
            last_scanned_block_hash: None,
        },
    )
    .expect("seed first wallet cursor");
    let mut first = service
        .register_wallet(first_cfg)
        .await
        .expect("register first wallet");
    tokio::time::timeout(Duration::from_secs(2), first.wait_until_ready())
        .await
        .expect("first wallet RPC startup completed")
        .expect("wallet readiness succeeded");
    assert_eq!(first.last_scanned(), Some(target_block));

    // The warm request for the pre-cursor blocks is still held by the mock,
    // so readiness did not wait for it.
    let mut bodies = Vec::new();
    yield_until("held background warm request", || {
        bodies.extend(rpc.drain_request_bodies());
        get_logs_ranges(&bodies).contains(&(101, 105))
    })
    .await;
    assert!(service.public_data_plane.public_window_warm_running());
    service
        .start_public_scan_window_warm(PublicScanRange::new(101, 105))
        .await;

    release_warm.send(()).expect("release warm request");
    yield_until("background warm finished", || {
        !service.public_data_plane.public_window_warm_running()
    })
    .await;
    bodies.extend(rpc.drain_request_bodies());
    assert_eq!(
        get_logs_ranges(&bodies),
        vec![(106, 110), (101, 105)],
        "delivery fetches only blocks after the cursor; one warm task fetches the rest"
    );
    assert!(
        service
            .public_data_plane
            .cached_wallet_scan_exact(101, target_block)
            .await
            .is_some(),
        "warming makes the whole window reusable"
    );
    assert_eq!(first.last_scanned(), Some(target_block));
    assert_eq!(
        db.get_wallet_meta(&first_cache_key)
            .expect("read first wallet cursor")
            .expect("first wallet cursor present")
            .last_scanned_block,
        target_block,
        "warming does not move the wallet cursor"
    );

    service.unregister_all_wallets().await;

    let mut second_cfg = test_wallet_config(&scope, rpc.url.clone());
    second_cfg.cache_key = test_cache_key("wallet-b");
    second_cfg.start_block = Some(101);
    second_cfg.sync_to_block = Some(target_block);
    second_cfg.use_indexed_wallet_catch_up = false;
    db.put_wallet_meta(
        &second_cfg.cache_key,
        &WalletMeta {
            last_scanned_block: 104,
            updated_at: 1,
            last_scanned_block_hash: None,
        },
    )
    .expect("seed replacement wallet cursor");
    let mut second = service
        .register_wallet(second_cfg)
        .await
        .expect("register replacement wallet");
    tokio::time::timeout(Duration::from_secs(1), second.wait_until_ready())
        .await
        .expect("replacement wallet reused RPC rows")
        .expect("wallet readiness succeeded");

    assert_eq!(second.last_scanned(), Some(target_block));
    assert!(
        rpc.drain_request_bodies().is_empty(),
        "replacement wallet must not issue another RPC request"
    );
    service.unregister_all_wallets().await;
    service.shutdown().await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_startup_reuses_sliding_cached_prefix_and_retains_new_tail() {
    let root_dir = temp_db_root("wallet-switch-sliding-rpc-window");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc = JsonRpcServer::spawn(vec![
        serde_json::json!("0x6e"),
        serde_json::json!([]),
        rpc_block(110, 1_700_000_110, 0x11),
        serde_json::json!("0x6e"),
        serde_json::json!([]),
        rpc_block(105, 1_700_000_105, 0x33),
        serde_json::json!("0x6f"),
        serde_json::json!([]),
        rpc_block(111, 1_700_000_111, 0x22),
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    chain.sync.block_range = 10;
    chain.finality_depth = 0;
    chain.sync.quick_sync_endpoint = None;
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
    service.safe_head_tx.send_replace(110);

    let mut first_cfg = test_wallet_config(&scope, rpc.url.clone());
    first_cfg.cache_key = test_cache_key("sliding-wallet-a");
    first_cfg.start_block = Some(101);
    first_cfg.sync_to_block = Some(110);
    first_cfg.use_indexed_wallet_catch_up = false;
    db.put_wallet_meta(
        &first_cfg.cache_key,
        &WalletMeta {
            last_scanned_block: 105,
            updated_at: 1,
            last_scanned_block_hash: None,
        },
    )
    .expect("seed first wallet cursor");
    let mut first = service
        .register_wallet(first_cfg)
        .await
        .expect("register first wallet");
    tokio::time::timeout(Duration::from_secs(2), first.wait_until_ready())
        .await
        .expect("first wallet RPC startup completed")
        .expect("first wallet readiness succeeded");
    assert_eq!(first.last_scanned(), Some(110));

    let mut first_bodies = Vec::new();
    yield_until("first wallet delivery and window warm", || {
        first_bodies.extend(rpc.drain_request_bodies());
        first_bodies.len() == 6 && !service.public_data_plane.public_window_warm_running()
    })
    .await;
    assert_eq!(
        get_logs_ranges(&first_bodies),
        vec![(106, 110), (101, 105)],
        "delivery precedes warming of the pre-cursor blocks"
    );

    service.unregister_all_wallets().await;
    service.safe_head_tx.send_replace(111);

    let mut second_cfg = test_wallet_config(&scope, rpc.url.clone());
    second_cfg.cache_key = test_cache_key("sliding-wallet-b");
    second_cfg.start_block = Some(101);
    second_cfg.sync_to_block = Some(111);
    second_cfg.use_indexed_wallet_catch_up = false;
    db.put_wallet_meta(
        &second_cfg.cache_key,
        &WalletMeta {
            last_scanned_block: 110,
            updated_at: 1,
            last_scanned_block_hash: None,
        },
    )
    .expect("seed replacement wallet cursor");
    let mut second = service
        .register_wallet(second_cfg)
        .await
        .expect("register replacement wallet");
    tokio::time::timeout(Duration::from_secs(2), second.wait_until_ready())
        .await
        .expect("replacement wallet RPC startup completed")
        .expect("replacement wallet readiness succeeded");
    assert_eq!(second.last_scanned(), Some(111));

    let second_requests = (0..3)
        .map(|_| {
            rpc.requests
                .recv_timeout(Duration::from_secs(1))
                .expect("replacement wallet RPC request")
        })
        .collect::<Vec<_>>();
    let second_get_logs = second_requests
        .iter()
        .find(|request| request.contains("eth_getLogs"))
        .expect("replacement wallet eth_getLogs request");
    assert!(second_get_logs.contains(r#""fromBlock":"0x6f""#));
    assert!(second_get_logs.contains(r#""toBlock":"0x6f""#));

    service.unregister_all_wallets().await;

    let mut third_cfg = test_wallet_config(&scope, rpc.url.clone());
    third_cfg.cache_key = test_cache_key("sliding-wallet-a");
    third_cfg.start_block = Some(101);
    third_cfg.sync_to_block = Some(111);
    third_cfg.use_indexed_wallet_catch_up = false;
    let mut third = service
        .register_wallet(third_cfg)
        .await
        .expect("register first wallet again");
    tokio::time::timeout(Duration::from_secs(1), third.wait_until_ready())
        .await
        .expect("first wallet reused retained new tail")
        .expect("first wallet readiness succeeded after switch back");
    assert_eq!(third.last_scanned(), Some(111));
    assert!(
        rpc.requests.try_recv().is_err(),
        "switching back at the same target must not issue another RPC request"
    );

    service.unregister_all_wallets().await;
    service.shutdown().await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_startup_fetches_cursor_gap_before_cached_suffix_then_warms_prefix() {
    let root_dir = temp_db_root("wallet-startup-leading-gap");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let gap_block = 105;
    let target_block = 110;
    let rpc = JsonRpcServer::spawn(vec![
        serde_json::json!(format!("{target_block:#x}")),
        serde_json::json!([rpc_nullifiers_log(scope.railgun_contract, gap_block)]),
        rpc_block(gap_block, 1_700_000_105, 0x11),
        rpc_block(gap_block, 1_700_000_105, 0x11),
        serde_json::json!(format!("{target_block:#x}")),
        serde_json::json!([]),
        rpc_block(104, 1_700_000_104, 0x44),
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    chain.sync.block_range = 10;
    chain.finality_depth = 0;
    chain.sync.quick_sync_endpoint = None;
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    public_data_plane
        .record_recent_public_scan_rows(PublicScanRows {
            range: PublicScanRange::new(106, target_block),
            source: PublicScanSource::Rpc,
            to_block_hash: Some([0x22; 32]),
            rows: WalletScanInputRows {
                nullifiers: vec![IndexedNullifierInput {
                    tree_number: 1,
                    nullifier: U256::from(7),
                    source: UtxoSource {
                        tx_hash: FixedBytes::from([0x22; 32]),
                        block_number: 106,
                        block_timestamp: 1_700_000_106,
                    },
                }],
                ..WalletScanInputRows::default()
            },
            epoch: public_data_plane.current_epoch(),
        })
        .await
        .expect("seed cached suffix");
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
    service.safe_head_tx.send_replace(target_block);

    let mut cfg = test_wallet_config(&scope, rpc.url.clone());
    cfg.cache_key = test_cache_key("wallet-leading-gap");
    cfg.start_block = Some(101);
    cfg.sync_to_block = Some(target_block);
    db.put_wallet_meta(
        &cfg.cache_key,
        &WalletMeta {
            last_scanned_block: 104,
            updated_at: 1,
            last_scanned_block_hash: None,
        },
    )
    .expect("seed wallet cursor");

    let mut handle = service.register_wallet(cfg).await.expect("register wallet");
    tokio::time::timeout(Duration::from_secs(2), handle.wait_until_ready())
        .await
        .expect("gap plus cached suffix completed")
        .expect("wallet readiness succeeded");
    assert_eq!(handle.last_scanned(), Some(target_block));

    let mut bodies = Vec::new();
    yield_until("gap delivery and window warm", || {
        bodies.extend(rpc.drain_request_bodies());
        bodies.len() == 7 && !service.public_data_plane.public_window_warm_running()
    })
    .await;
    assert_eq!(
        get_logs_ranges(&bodies),
        vec![(105, 105), (101, 104)],
        "only the gap after the cursor is fetched before delivery"
    );
    assert!(
        service
            .public_data_plane
            .cached_wallet_scan_exact(101, target_block)
            .await
            .is_some()
    );

    service.unregister_all_wallets().await;
    service.shutdown().await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn historical_catch_up_delivers_captured_suffix_after_cache_eviction() {
    let root_dir = temp_db_root("wallet-historical-captured-suffix");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let (artifact_source, manifest_block) =
        checkpointed_wallet_artifact_source_with_blocked_manifest(&scope, 101, 150, 150);
    let PathServerBlockControl {
        request_started,
        release,
    } = manifest_block;
    let rpc = JsonRpcServer::spawn(vec![serde_json::json!([])]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, Some(artifact_source.config.clone()));
    chain.sync.block_range = 10;
    chain.finality_depth = 0;
    chain.sync.quick_sync_endpoint = None;
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    public_data_plane
        .record_recent_public_scan_rows(PublicScanRows {
            range: PublicScanRange::new(151, 200),
            source: PublicScanSource::Rpc,
            to_block_hash: Some([0x22; 32]),
            rows: WalletScanInputRows {
                nullifiers: vec![IndexedNullifierInput {
                    tree_number: 1,
                    nullifier: U256::from(151),
                    source: UtxoSource {
                        tx_hash: FixedBytes::from([0x22; 32]),
                        block_number: 151,
                        block_timestamp: 1_700_000_151,
                    },
                }],
                ..WalletScanInputRows::default()
            },
            epoch: public_data_plane.current_epoch(),
        })
        .await
        .expect("seed captured suffix");
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane.clone());
    service.safe_head_tx.send_replace(200);
    let mut cfg = test_wallet_config(&scope, rpc.url.clone());
    cfg.cache_key = test_cache_key("captured-suffix-wallet");
    cfg.start_block = Some(101);
    cfg.sync_to_block = Some(200);
    db.put_wallet_meta(
        &cfg.cache_key,
        &WalletMeta {
            last_scanned_block: 100,
            updated_at: 1,
            last_scanned_block_hash: None,
        },
    )
    .expect("seed wallet cursor");

    let mut handle = service.register_wallet(cfg).await.expect("register wallet");
    wait_for_std_signal(request_started, "artifact manifest request started").await;
    for block_number in 201..=205 {
        public_data_plane
            .record_recent_public_scan_rows(PublicScanRows {
                range: PublicScanRange::new(block_number, block_number),
                source: PublicScanSource::Rpc,
                to_block_hash: Some([0x33; 32]),
                rows: WalletScanInputRows {
                    nullifiers: vec![IndexedNullifierInput {
                        tree_number: 1,
                        nullifier: U256::from(block_number),
                        source: UtxoSource {
                            tx_hash: FixedBytes::from([0x33; 32]),
                            block_number,
                            block_timestamp: block_number.saturating_add(1_700_000_000),
                        },
                    }],
                    ..WalletScanInputRows::default()
                },
                epoch: public_data_plane.current_epoch(),
            })
            .await
            .expect("record newer pending-tip page");
    }
    assert!(
        public_data_plane
            .cached_wallet_scan_apply(151, 200)
            .await
            .is_none(),
        "test must evict the original suffix from the shared cache"
    );
    release.send(()).expect("release artifact manifest");

    tokio::time::timeout(Duration::from_secs(2), handle.wait_until_ready())
        .await
        .expect("captured suffix startup completed")
        .expect("wallet readiness succeeded");
    assert_eq!(handle.last_scanned(), Some(200));
    assert!(
        rpc.requests.try_recv().is_err(),
        "captured suffix delivery must not refetch the evicted range through RPC"
    );

    service.unregister_all_wallets().await;
    service.shutdown().await;
    drop(service);
    drop(public_data_plane);
    drop(artifact_source.server);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_startup_rpc_candidate_skips_pre_cursor_blocks_when_delivery_is_cached() {
    let root_dir = temp_db_root("wallet-startup-exact-delivery-boundary");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc = JsonRpcServer::spawn_handler(
        |_| serde_json::json!({ "error": rpc_error(-32601, "unexpected request") }),
    );
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    chain.sync.block_range = 10;
    chain.finality_depth = 0;
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    public_data_plane
        .record_recent_public_scan_rows(PublicScanRows {
            range: PublicScanRange::new(106, 110),
            source: PublicScanSource::Rpc,
            to_block_hash: Some([0x22; 32]),
            rows: WalletScanInputRows::default(),
            epoch: public_data_plane.current_epoch(),
        })
        .await
        .expect("seed exact-boundary cached suffix");
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
    let mut cfg = test_wallet_config(&scope, rpc.url.clone());
    cfg.start_block = Some(101);

    let candidate = Arc::clone(&service)
        .wallet_startup_rpc_candidate(
            &cfg,
            WalletShortStartupPlan::new(101, 105, 110, 10).expect("short startup plan"),
            CancellationToken::new(),
        )
        .await
        .expect("RPC startup candidate");

    assert_eq!(
        candidate
            .applies
            .iter()
            .map(|apply| (apply.from_block, apply.to_block))
            .collect::<Vec<_>>(),
        vec![(106, 110)],
        "only the delivery suffix is returned to the wallet",
    );
    assert_eq!(
        candidate
            .acquisition_applies
            .first()
            .map(|apply| apply.from_block),
        Some(106),
        "the candidate holds no blocks at or before the cursor",
    );
    assert!(
        rpc.requests.try_recv().is_err(),
        "a cached delivery range needs no RPC request before delivery"
    );

    service.shutdown().await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_startup_rpc_candidate_rejects_zero_provider_coverage() {
    // Every head is below the target. A lagging head doesn't mark a provider
    // unhealthy, so only the read's tried set keeps it from asking one twice.
    let servers = (0..4)
        .map(|_| {
            JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 100, |_, _, _| None))
        })
        .collect::<Vec<_>>();

    let (result, _) = run_wallet_startup_rpc_candidate(
        "wallet-startup-zero-rpc-coverage",
        servers.iter().map(|server| server.url.clone()).collect(),
    )
    .await;

    assert!(matches!(
        result,
        Err(WalletStartupSyncError::IncompleteRpcCoverage {
            requested_to: 110,
            proven_to: 100,
        })
    ));
    let mut head_reads = servers
        .iter()
        .map(|server| {
            let bodies = server.drain_request_bodies();
            assert!(
                bodies
                    .iter()
                    .all(|body| body["method"] == "eth_blockNumber"),
                "only head reads: {bodies:?}"
            );
            bodies.len()
        })
        .collect::<Vec<_>>();
    head_reads.sort_unstable();
    assert_eq!(
        head_reads,
        vec![0, 1, 1, 1],
        "the read stops after three distinct providers"
    );
}

/// Runs the short startup RPC candidate that delivers blocks 106..=110 on a
/// pool of `rpc_urls`, and returns its delivery applies and the pool.
async fn run_wallet_startup_rpc_candidate(
    name: &str,
    rpc_urls: Vec<Url>,
) -> (
    Result<Vec<WalletScanApply>, WalletStartupSyncError>,
    Arc<QueryRpcPool>,
) {
    let root_dir = temp_db_root(name);
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpcs = Arc::new(QueryRpcPool::new(rpc_urls, Duration::from_mins(1)));
    let mut chain = test_chain_config(&scope, Arc::clone(&rpcs), None);
    chain.sync.block_range = 10;
    chain.finality_depth = 0;
    let public_data_plane = ChainPublicDataPlane::new(Arc::clone(&db), Arc::new(AtomicU64::new(0)));
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
    let mut cfg = test_wallet_config(
        &scope,
        Url::parse("http://127.0.0.1:1").expect("unused Squid URL"),
    );
    cfg.start_block = Some(101);

    let result = Arc::clone(&service)
        .wallet_startup_rpc_candidate(
            &cfg,
            WalletShortStartupPlan::new(101, 105, 110, 10).expect("short startup plan"),
            CancellationToken::new(),
        )
        .await
        .map(|candidate| candidate.applies);
    service.shutdown().await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
    (result, rpcs)
}

#[tokio::test]
async fn wallet_startup_rpc_candidate_fails_over_after_provider_error() {
    let scope = test_scope();
    // The first range read, on whichever provider is picked first, gets HTTP 503.
    let get_logs_reads = Arc::new(AtomicU64::new(0));
    let servers = (0..2)
        .map(|_| {
            let get_logs_reads = Arc::clone(&get_logs_reads);
            let serve = log_range_rpc_handler(
                vec![rpc_nullifiers_log_with_timestamp(
                    scope.railgun_contract,
                    108,
                )],
                110,
                |_, _, _| None,
            );
            JsonRpcServer::spawn_handler_with_status(move |request| {
                if request["method"] == "eth_getLogs"
                    && get_logs_reads.fetch_add(1, Ordering::AcqRel) == 0
                {
                    return Err(503);
                }
                Ok(serve(request))
            })
        })
        .collect::<Vec<_>>();

    let (result, rpcs) = run_wallet_startup_rpc_candidate(
        "wallet-startup-rpc-failover-after-error",
        servers.iter().map(|server| server.url.clone()).collect(),
    )
    .await;

    let applies = result.expect("the second provider completes the read");
    assert_eq!(applies.len(), 1);
    let WalletScanRowsPayload::Rows(rows) = &applies[0].rows.payload else {
        panic!("RPC delivery rows expected");
    };
    assert_eq!(rows.nullifiers.len(), 1);
    for server in &servers {
        assert_eq!(
            get_logs_ranges(&server.drain_request_bodies()),
            vec![(106, 110)],
            "each provider is asked for the range once"
        );
    }
    assert_eq!(
        rpcs.available_providers().len(),
        1,
        "the failed provider cools down"
    );
}

#[tokio::test]
async fn wallet_startup_rpc_candidate_fails_over_when_provider_head_is_behind() {
    // The first head read, on whichever provider is picked first, is below
    // the required target 110.
    let head_reads = Arc::new(AtomicU64::new(0));
    let servers = (0..2)
        .map(|_| {
            let head_reads = Arc::clone(&head_reads);
            let serve = log_range_rpc_handler(Vec::new(), 110, |_, _, _| None);
            JsonRpcServer::spawn_handler(move |request| {
                if request["method"] == "eth_blockNumber"
                    && head_reads.fetch_add(1, Ordering::AcqRel) == 0
                {
                    return serde_json::json!({ "result": "0x64" });
                }
                serve(request)
            })
        })
        .collect::<Vec<_>>();

    let (result, rpcs) = run_wallet_startup_rpc_candidate(
        "wallet-startup-rpc-failover-behind-head",
        servers.iter().map(|server| server.url.clone()).collect(),
    )
    .await;

    let applies = result.expect("the provider whose head covers the target completes the read");
    assert_eq!(
        applies
            .iter()
            .map(|apply| (apply.from_block, apply.to_block))
            .collect::<Vec<_>>(),
        vec![(106, 110)]
    );
    let mut ranges = servers
        .iter()
        .map(|server| get_logs_ranges(&server.drain_request_bodies()))
        .collect::<Vec<_>>();
    ranges.sort();
    assert_eq!(
        ranges,
        vec![Vec::new(), vec![(106, 110)]],
        "only the provider that covers the target reads the range"
    );
    assert_eq!(
        rpcs.available_providers().len(),
        2,
        "a lagging head doesn't mark the provider unhealthy"
    );
}

#[tokio::test]
async fn wallet_startup_rpc_candidate_rejects_missing_endpoint_block() {
    let root_dir = temp_db_root("wallet-startup-missing-rpc-endpoint");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc = JsonRpcServer::spawn(vec![
        serde_json::json!("0x6e"),
        serde_json::json!([]),
        serde_json::Value::Null,
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    chain.sync.block_range = 10;
    chain.finality_depth = 0;
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
    let mut cfg = test_wallet_config(&scope, rpc.url.clone());
    cfg.start_block = Some(101);

    let result = Arc::clone(&service)
        .wallet_startup_rpc_candidate(
            &cfg,
            WalletShortStartupPlan::new(101, 105, 110, 10).expect("short startup plan"),
            CancellationToken::new(),
        )
        .await;

    assert!(matches!(
        result,
        Err(WalletStartupSyncError::UnprovenRpcEndpoint { block_number: 110 })
    ));
    assert!(
        service
            .public_data_plane
            .cached_wallet_scan_suffix(101, 110)
            .await
            .is_none()
    );
    service.shutdown().await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_startup_rpc_candidate_requires_archive_boundary_proof() {
    let root_dir = temp_db_root("wallet-startup-missing-archive-endpoint");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    // Either provider fails the same way; the read must not try the other.
    let rpc_servers = (0..2)
        .map(|_| {
            JsonRpcServer::spawn(vec![
                serde_json::json!("0x6e"),
                serde_json::json!([]),
                serde_json::json!([]),
                serde_json::Value::Null,
            ])
        })
        .collect::<Vec<_>>();
    let rpcs = Arc::new(QueryRpcPool::new(
        rpc_servers
            .iter()
            .map(|server| server.url.clone())
            .collect(),
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    // The delivery range 106..=110 crosses this archive boundary.
    chain.sync.archive_until_block = 107;
    chain.sync.block_range = 10;
    chain.finality_depth = 0;
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
    let mut cfg = test_wallet_config(&scope, rpc_servers[0].url.clone());
    cfg.start_block = Some(101);

    let result = Arc::clone(&service)
        .wallet_startup_rpc_candidate(
            &cfg,
            WalletShortStartupPlan::new(101, 105, 110, 10).expect("short startup plan"),
            CancellationToken::new(),
        )
        .await;

    assert!(matches!(
        result,
        Err(WalletStartupSyncError::UnprovenRpcEndpoint { block_number: 107 })
    ));
    let mut request_counts = rpc_servers
        .iter()
        .map(|server| server.requests.try_iter().count())
        .collect::<Vec<_>>();
    request_counts.sort_unstable();
    assert_eq!(
        request_counts,
        vec![0, 4],
        "a read that reaches the archive range stays on one provider"
    );
    assert!(
        service
            .public_data_plane
            .cached_wallet_scan_suffix(101, 110)
            .await
            .is_none()
    );
    service.shutdown().await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn multi_page_squid_winner_aborts_blocked_rpc_loser_before_publication() {
    let root_dir = temp_db_root("wallet-startup-hedge-isolation");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let replacement_wallet_utxo = WalletUtxo::new(Utxo::new(
        Note {
            token_hash: U256::from(1),
            value: U256::from(10),
            random: [0x33; 16],
            npk: U256::from(2),
        },
        1,
        9,
        UtxoSource {
            tx_hash: FixedBytes::from([0x55; 32]),
            block_number: 100,
            block_timestamp: 1_700_000_100,
        },
        UtxoCommitmentKind::Transact,
    ));
    let replacement_nullifier = replacement_wallet_utxo.utxo.nullifier(U256::ZERO);
    let (rpc, rpc_block) = JsonRpcServer::spawn_with_blocked_response(
        vec![
            serde_json::json!("0x6a"),
            serde_json::json!([rpc_nullifiers_log_with_value(
                scope.railgun_contract,
                101,
                replacement_nullifier,
            )]),
            rpc_block(101, 1_700_000_101, 0x11),
            rpc_block(106, 1_700_000_106, 0x22),
        ],
        1,
    );
    let mut squid_responses = vec![
        r#"{"data":{"squidStatus":{"height":"106"},"transactCommitments":[],"shieldCommitments":[],"nullifiers":[],"legacyEncryptedCommitments":[],"legacyGeneratedCommitments":[]}}"#
            .to_string(),
    ];
    squid_responses.extend((101..=106).map(|block_number| {
        let nullifier = if block_number == 101 {
            replacement_nullifier
        } else {
            U256::from(block_number)
        };
        indexed_wallet_nullifier_page(block_number, nullifier)
    }));
    let (squid, squid_block) = GraphqlServer::spawn_owned_with_blocked_response(squid_responses, 0);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    chain.sync.block_range = 6;
    chain.sync.indexed_wallet_block_range = 1;
    chain.finality_depth = 0;
    chain.sync.quick_sync_endpoint = Some(squid.url.clone());
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane.clone());
    service.safe_head_tx.send_replace(106);

    let mut first_cfg = test_wallet_config(&scope, squid.url.clone());
    first_cfg.cache_key = test_cache_key("hedge-isolation-wallet-a");
    first_cfg.start_block = Some(101);
    first_cfg.sync_to_block = Some(106);
    db.put_wallet_meta(
        &first_cfg.cache_key,
        &WalletMeta {
            last_scanned_block: 100,
            updated_at: 1,
            last_scanned_block_hash: None,
        },
    )
    .expect("seed first wallet cursor");
    let mut first = service
        .register_wallet(first_cfg)
        .await
        .expect("register first wallet");

    let PathServerBlockControl {
        request_started: squid_request_started,
        release: squid_release,
    } = squid_block;
    let PathServerBlockControl {
        request_started: rpc_request_started,
        release: rpc_release,
    } = rpc_block;
    wait_for_std_signal(squid_request_started, "Squid candidate reached its request").await;
    wait_for_std_signal(rpc_request_started, "RPC loser reached its log request").await;
    squid_release
        .send(())
        .expect("release Squid candidate after RPC loser is blocked");
    tokio::time::timeout(Duration::from_secs(2), first.wait_until_ready())
        .await
        .expect("Squid winner delivered while RPC response remained blocked")
        .expect("wallet readiness succeeded");
    assert_eq!(first.last_scanned(), Some(106));
    rpc_release
        .send(())
        .expect("release terminated RPC request for fixture cleanup");

    let replay = public_data_plane
        .cached_wallet_scan_suffix(101, 106)
        .await
        .expect("complete Squid acquisition remains replayable");
    assert_eq!(
        replay.len(),
        1,
        "six Squid pages should compact into one run"
    );
    let WalletScanRowsPayload::Rows(rows) = &replay[0].rows.payload else {
        panic!("Squid winner rows expected");
    };
    assert_eq!(rows.nullifiers.len(), 6);
    assert_eq!(rows.nullifiers[0].source.block_number, 101);
    assert_eq!(rows.nullifiers[0].nullifier, replacement_nullifier);
    let first_rpc_requests = (0..2)
        .map(|_| {
            rpc.requests
                .recv_timeout(Duration::from_secs(1))
                .expect("RPC loser request")
        })
        .collect::<Vec<_>>();
    assert!(
        first_rpc_requests
            .iter()
            .any(|request| request.contains("eth_getLogs"))
    );
    let squid_requests = (0..7)
        .map(|_| {
            squid
                .requests
                .recv_timeout(Duration::from_secs(1))
                .expect("Squid winner request")
        })
        .collect::<Vec<_>>();
    for block_number in 101..=106 {
        assert!(squid_requests.iter().any(|request| {
            request.contains(&format!("\"fromBlock\":\"{block_number}\""))
                && request.contains(&format!("\"toBlock\":\"{block_number}\""))
        }));
    }

    service.unregister_all_wallets().await;
    let mut second_cfg = test_wallet_config(&scope, squid.url.clone());
    second_cfg.cache_key = test_cache_key("hedge-isolation-wallet-b");
    second_cfg.start_block = Some(101);
    second_cfg.sync_to_block = Some(106);
    db.put_wallet_meta(
        &second_cfg.cache_key,
        &WalletMeta {
            last_scanned_block: 100,
            updated_at: 1,
            last_scanned_block_hash: None,
        },
    )
    .expect("seed replacement wallet cursor");
    db.put_wallet_utxo(
        &second_cfg.cache_key,
        "1:9",
        &serialize_wallet_utxo(&replacement_wallet_utxo).expect("serialize replacement UTXO"),
    )
    .expect("seed replacement wallet UTXO");
    let mut second = service
        .register_wallet(second_cfg)
        .await
        .expect("register replacement wallet");
    tokio::time::timeout(Duration::from_secs(1), second.wait_until_ready())
        .await
        .expect("replacement wallet replayed Squid winner acquisition")
        .expect("wallet readiness succeeded");
    assert_eq!(second.last_scanned(), Some(106));
    let replacement_snapshot = second
        .utxos_snapshot()
        .expect("replacement wallet snapshot");
    assert_eq!(
        replacement_snapshot[0]
            .spent
            .as_ref()
            .expect("leading Squid nullifier marks UTXO spent")
            .block_number,
        101,
    );
    assert!(rpc.requests.try_recv().is_err());
    assert!(squid.requests.try_recv().is_err());

    service.unregister_all_wallets().await;
    service.shutdown().await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn failed_short_startup_hedge_uses_artifact_chunk_spanning_cursor_and_reuses_it() {
    let root_dir = temp_db_root("wallet-startup-artifact-fallback-window");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    // One chunk covers 101..=110, across the first wallet's cursor at 105.
    let artifact_source = checkpointed_wallet_artifact_source(&scope, 101, 110, 110);
    let squid = GraphqlServer::spawn(vec![
        r#"{"errors":[{"message":"indexed source unavailable"}]}"#,
    ]);
    // The RPC head stays below every requested target, so the standalone
    // candidate and the background warm both fail before any data request.
    let rpc = JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 100, |_, _, _| None));
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, Some(artifact_source.config.clone()));
    chain.sync.block_range = 10;
    chain.sync.indexed_wallet_block_range = 10;
    chain.finality_depth = 0;
    chain.sync.quick_sync_endpoint = Some(squid.url.clone());
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
    service.safe_head_tx.send_replace(110);

    let mut first_cfg = test_wallet_config(&scope, squid.url.clone());
    first_cfg.cache_key = test_cache_key("artifact-fallback-wallet-a");
    first_cfg.start_block = Some(101);
    first_cfg.sync_to_block = Some(110);
    db.put_wallet_meta(
        &first_cfg.cache_key,
        &WalletMeta {
            last_scanned_block: 105,
            updated_at: 1,
            last_scanned_block_hash: None,
        },
    )
    .expect("seed first wallet cursor");
    let mut first = service
        .register_wallet(first_cfg)
        .await
        .expect("register first wallet");
    tokio::time::timeout(Duration::from_secs(2), first.wait_until_ready())
        .await
        .expect("artifact fallback startup completed")
        .expect("wallet readiness succeeded");
    assert_eq!(first.last_scanned(), Some(110));
    assert_eq!(
        artifact_source.server.request_count(),
        3,
        "manifest, catalog, and the whole chunk spanning the cursor"
    );
    assert!(
        squid
            .requests
            .recv_timeout(Duration::from_secs(1))
            .expect("failed Squid hedge request")
            .contains("query WalletProbe")
    );

    let mut bodies = Vec::new();
    yield_until("failed hedge RPC and background warm head reads", || {
        bodies.extend(rpc.drain_request_bodies());
        bodies.len() == 2 && !service.public_data_plane.public_window_warm_running()
    })
    .await;
    assert!(
        bodies
            .iter()
            .all(|body| body["method"] == "eth_blockNumber"),
        "neither RPC path issued a data request"
    );
    assert_eq!(
        service
            .public_data_plane
            .cached_wallet_scan_suffix(101, 110)
            .await
            .and_then(|applies| applies.first().map(|apply| apply.from_block)),
        Some(106),
        "chunk rows before the cursor are neither delivered nor recorded"
    );

    service.unregister_all_wallets().await;

    let mut second_cfg = test_wallet_config(&scope, squid.url.clone());
    second_cfg.cache_key = test_cache_key("artifact-fallback-wallet-b");
    second_cfg.start_block = Some(101);
    second_cfg.sync_to_block = Some(110);
    db.put_wallet_meta(
        &second_cfg.cache_key,
        &WalletMeta {
            last_scanned_block: 105,
            updated_at: 1,
            last_scanned_block_hash: None,
        },
    )
    .expect("seed replacement wallet cursor");
    let mut second = service
        .register_wallet(second_cfg)
        .await
        .expect("register replacement wallet");
    tokio::time::timeout(Duration::from_secs(1), second.wait_until_ready())
        .await
        .expect("replacement wallet reused artifact rows")
        .expect("wallet readiness succeeded");
    assert_eq!(second.last_scanned(), Some(110));
    assert_eq!(
        artifact_source.server.request_count(),
        3,
        "replacement wallet should reuse the cached delivery range without HTTP"
    );
    assert!(rpc.drain_request_bodies().is_empty());
    assert!(squid.requests.try_recv().is_err());

    service.unregister_all_wallets().await;
    service.shutdown().await;
    drop(service);
    drop(db);
    drop(artifact_source.server);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn artifact_poi_corpus_survives_wallet_scope_replacement() {
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
                .expect("initialize POI cache generation")
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
    let list_key = FixedBytes::from([0x31; 32]);
    let blinded_commitment = FixedBytes::from([0x32; 32]);
    let mut cache = PoiCache::new(PoiCacheIdentity::new(
        0,
        scope.chain_id,
        DEFAULT_TXID_VERSION,
        list_key,
    ));
    cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: *blinded_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("seed public POI corpus event");
    cache.accept_current_roots();
    let accepted_root = match &cache.progress().root_validation {
        poi::cache::PoiCacheRootValidation::Validated { roots } => {
            roots.values().next().copied().expect("accepted POI root")
        }
        other => panic!("expected accepted POI roots, got {other:?}"),
    };
    public_data_plane
        .ensure_poi_corpus(PublicPoiCorpusKey::new(
            0,
            scope.chain_id,
            DEFAULT_TXID_VERSION,
        ))
        .await
        .expect("public POI corpus")
        .local_caches()
        .write()
        .await
        .insert(list_key, cache);
    let data_plane_handle = service.public_data_plane();
    assert_eq!(
        data_plane_handle
            .validate_local_poi_roots(DEFAULT_TXID_VERSION, list_key, &[accepted_root])
            .await
            .expect("validate accepted local POI root"),
        LocalPoiRootValidation::Accepted
    );
    assert_eq!(
        data_plane_handle
            .validate_local_poi_roots(
                DEFAULT_TXID_VERSION,
                list_key,
                &[FixedBytes::from([0xff; 32])],
            )
            .await
            .expect("validate absent local POI root"),
        LocalPoiRootValidation::Unavailable(LocalPoiQueryUnavailable::SubmittedRootAbsent {
            list_key,
        })
    );
    assert_eq!(
        data_plane_handle
            .local_poi_statuses(DEFAULT_TXID_VERSION, &[list_key], &blinded_commitment,)
            .await
            .expect("query local POI status"),
        LocalPoiStatusLookup::Valid(BTreeMap::from([(list_key, PoiStatus::Valid)]))
    );
    assert_eq!(
        data_plane_handle
            .local_poi_statuses(
                DEFAULT_TXID_VERSION,
                &[list_key],
                &FixedBytes::from([0xfe; 32]),
            )
            .await
            .expect("query unresolved local POI status"),
        LocalPoiStatusLookup::Unavailable(LocalPoiQueryUnavailable::StatusUnresolved { list_key })
    );
    let proof_source = service
        .public_data_plane()
        .local_poi_merkle_proof_source(DEFAULT_TXID_VERSION)
        .await
        .expect("chain-owned local POI proof source");
    let proofs = proof_source
        .poi_merkle_proofs(
            DEFAULT_TXID_VERSION,
            0,
            scope.chain_id,
            &list_key,
            &[blinded_commitment],
        )
        .await
        .expect("proof from chain-owned local corpus");
    assert_eq!(proofs.len(), 1);
    assert_eq!(proofs[0].leaf, U256::from_be_bytes(blinded_commitment.0));
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
    service.unregister_all_wallets().await;

    let second = service
        .register_wallet(cfg.clone())
        .await
        .expect("re-register artifact wallet");
    let second_corpus = public_data_plane
        .ensure_poi_corpus(corpus_key)
        .await
        .expect("second POI corpus")
        .local_caches();
    service.unregister_wallet(&first).await;

    assert_ne!(first.actor_id(), second.actor_id());
    assert!(first_corpus.ptr_eq(&second_corpus));
    assert_eq!(
        service
            .wallet_handle(&cfg.cache_key)
            .await
            .expect("replacement actor remains registered")
            .actor_id(),
        second.actor_id()
    );
    service.unregister_all_wallets().await;
    service.shutdown().await;
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn active_backfill_drains_reset_replacement_request() {
    let (request_tx, mut request_rx) = mpsc::channel(4);
    let (old_sender, old_receiver) = mpsc::channel(1);
    let (new_sender, _new_receiver) = mpsc::channel(1);
    let mut cursor = Some(WalletBackfillSlot {
        cache_key: "test".to_string(),
        cursor: WalletBackfill::new(
            100,
            1_000,
            true,
            100,
            None,
            test_backfill_driver(old_sender, 0, 1),
            std::time::Instant::now(),
        ),
    });

    request_tx
        .try_send(BackfillRequest::Add {
            cache_key: "test".to_string(),
            from_block: 80,
            to_block: 150,
            follow_safe_head: true,
            progress_start_block: 80,
            acquisition_range: None,
            startup_warm_range: None,
            driver: test_backfill_driver(new_sender, 1, 2),
        })
        .expect("queue reset replacement backfill");

    drain_pending_backfill_requests(&mut request_rx, &mut cursor, Some(("test", 1))).await;

    let cursor = &cursor.expect("cursor retained").cursor;
    assert_eq!(cursor.from_block, 80);
    assert_eq!(cursor.target_block, 150);
    assert!(cursor.follow_safe_head);
    assert_eq!(cursor.progress_start_block, 80);
    assert_eq!(cursor.driver.token().reset_generation(), 1);
    assert!(old_receiver.is_empty());
}

#[tokio::test]
async fn stale_actor_backfill_remove_cannot_remove_replacement_cursor() {
    let (request_tx, mut request_rx) = mpsc::channel(1);
    let (event_tx, _event_rx) = mpsc::channel(1);
    let replacement_token = WalletSyncToken::for_test(1, 2, 0, 1);
    let (remove_response, remove_ack) = oneshot::channel();
    let mut cursor = Some(WalletBackfillSlot {
        cache_key: "test".to_string(),
        cursor: WalletBackfill::new(
            100,
            120,
            false,
            100,
            None,
            WalletBackfillDriver::from_token(replacement_token, event_tx),
            std::time::Instant::now(),
        ),
    });
    request_tx
        .try_send(BackfillRequest::Remove {
            cache_key: "test".to_string(),
            actor_id: 1,
            response: remove_response,
        })
        .expect("queue stale actor removal");

    drain_pending_backfill_requests(&mut request_rx, &mut cursor, None).await;
    remove_ack.await.expect("stale removal acknowledged");

    assert_eq!(
        cursor
            .as_ref()
            .expect("replacement cursor remains")
            .cursor
            .driver
            .token(),
        replacement_token,
    );
}

#[tokio::test]
async fn active_backfill_ignores_stale_replacement_request() {
    let (request_tx, mut request_rx) = mpsc::channel(4);
    let (active_sender, active_receiver) = mpsc::channel(1);
    let (stale_sender, stale_receiver) = mpsc::channel(1);
    let mut cursor = Some(WalletBackfillSlot {
        cache_key: "test".to_string(),
        cursor: WalletBackfill::new(
            100,
            1_000,
            true,
            100,
            None,
            test_backfill_driver(active_sender, 1, 2),
            std::time::Instant::now(),
        ),
    });

    request_tx
        .try_send(BackfillRequest::Add {
            cache_key: "other-wallet".to_string(),
            from_block: 80,
            to_block: 150,
            follow_safe_head: true,
            progress_start_block: 80,
            acquisition_range: None,
            startup_warm_range: None,
            driver: test_backfill_driver(stale_sender, 0, 1),
        })
        .expect("queue stale replacement backfill");

    drain_pending_backfill_requests(&mut request_rx, &mut cursor, Some(("test", 1))).await;

    let cursor = &cursor.expect("active cursor retained").cursor;
    assert_eq!(cursor.from_block, 100);
    assert_eq!(cursor.target_block, 1_000);
    assert_eq!(cursor.driver.token().reset_generation(), 1);
    assert_eq!(cursor.driver.token().job_id(), 2);
    assert!(stale_receiver.is_empty());
    assert!(active_receiver.is_empty());
}

#[tokio::test]
async fn active_backfill_ignores_same_key_stale_token_request() {
    let (request_tx, mut request_rx) = mpsc::channel(2);
    let (active_sender, _active_receiver) = mpsc::channel(1);
    let (stale_sender, _stale_receiver) = mpsc::channel(1);
    let (stale_driver, stale_retirement) =
        test_backfill_driver_with_retirement_signal(stale_sender, 1, 0, 1);
    let mut cursor = Some(WalletBackfillSlot {
        cache_key: "test".to_string(),
        cursor: WalletBackfill::new(
            100,
            1_000,
            true,
            100,
            None,
            test_backfill_driver_for_actor(active_sender, 1, 0, 2),
            std::time::Instant::now(),
        ),
    });
    request_tx
        .try_send(BackfillRequest::Add {
            cache_key: "test".to_string(),
            from_block: 80,
            to_block: 150,
            follow_safe_head: true,
            progress_start_block: 80,
            acquisition_range: None,
            startup_warm_range: None,
            driver: stale_driver,
        })
        .expect("queue same-key stale request");

    let draining = tokio::spawn(async move {
        drain_pending_backfill_requests(&mut request_rx, &mut cursor, Some(("test", 1))).await;
        cursor
    });
    let signal = tokio::time::timeout(Duration::from_secs(1), stale_retirement)
        .await
        .expect("same-key stale driver retirement is signalled")
        .expect("same-key stale driver retirement signal arrives");
    assert_eq!(
        signal.disposition,
        WalletBackfillOwnerDisposition::BenignRetirement
    );
    if let Some(acknowledgement) = signal.acknowledgement {
        acknowledgement
            .send(())
            .expect("acknowledge same-key stale driver retirement");
    }
    let cursor = draining.await.expect("backfill admission task joins");
    let cursor = &cursor.expect("active cursor retained").cursor;
    assert_eq!(cursor.from_block, 100);
    assert_eq!(cursor.target_block, 1_000);
    assert_eq!(cursor.driver.token().job_id(), 2);
}

#[tokio::test]
async fn old_backfill_add_after_remove_cannot_replace_successor() {
    let (request_tx, mut request_rx) = mpsc::channel(4);
    let (old_sender, _old_receiver) = mpsc::channel(1);
    let (stale_sender, _stale_receiver) = mpsc::channel(1);
    let (successor_sender, _successor_receiver) = mpsc::channel(1);
    let (stale_driver, stale_retirement) =
        test_backfill_driver_with_retirement_signal(stale_sender, 1, 1, 2);
    let mut cursor = Some(WalletBackfillSlot {
        cache_key: "test".to_string(),
        cursor: WalletBackfill::new(
            100,
            120,
            false,
            100,
            None,
            test_backfill_driver_for_actor(old_sender, 1, 1, 1),
            std::time::Instant::now(),
        ),
    });
    request_tx
        .try_send(BackfillRequest::Remove {
            cache_key: "test".to_string(),
            actor_id: 1,
            response: oneshot::channel().0,
        })
        .expect("queue old removal");
    request_tx
        .try_send(BackfillRequest::Add {
            cache_key: "test".to_string(),
            from_block: 200,
            to_block: 220,
            follow_safe_head: false,
            progress_start_block: 200,
            acquisition_range: None,
            startup_warm_range: None,
            driver: test_backfill_driver_for_actor(successor_sender, 2, 1, 3),
        })
        .expect("queue successor add");
    request_tx
        .try_send(BackfillRequest::Add {
            cache_key: "test".to_string(),
            from_block: 150,
            to_block: 170,
            follow_safe_head: false,
            progress_start_block: 150,
            acquisition_range: None,
            startup_warm_range: None,
            driver: stale_driver,
        })
        .expect("queue stale old add");

    let draining = tokio::spawn(async move {
        drain_pending_backfill_requests(&mut request_rx, &mut cursor, Some(("test", 2))).await;
        cursor
    });
    let signal = tokio::time::timeout(Duration::from_secs(1), stale_retirement)
        .await
        .expect("stale old driver retirement is signalled")
        .expect("stale old driver retirement signal arrives");
    assert_eq!(
        signal.disposition,
        WalletBackfillOwnerDisposition::BenignRetirement
    );
    if let Some(acknowledgement) = signal.acknowledgement {
        acknowledgement
            .send(())
            .expect("acknowledge stale old driver retirement");
    }
    let cursor = draining.await.expect("backfill admission task joins");

    let cursor = &cursor.expect("successor cursor installed").cursor;
    assert_eq!(cursor.from_block, 200);
    assert_eq!(cursor.target_block, 220);
    assert_eq!(cursor.driver.token().actor_id(), 2);
}

#[test]
fn wallet_tail_fallback_threshold_uses_ten_blocks_or_45_seconds() {
    assert_eq!(
        wallet_tail_fallback_lag_threshold_blocks(Duration::from_secs(12)),
        10
    );
    assert_eq!(
        wallet_tail_fallback_lag_threshold_blocks(Duration::from_millis(250)),
        180
    );
}

#[test]
fn wallet_tail_fallback_requires_lag_stall_and_cooldown() {
    let now = std::time::Instant::now();
    let (sender, _receiver) = mpsc::channel(1);
    let mut cursor = WalletBackfill::new(
        100,
        279,
        true,
        100,
        None,
        test_backfill_driver(sender, 0, 1),
        now.checked_sub(std::time::Duration::from_secs(20))
            .expect("test instant supports 20 second subtraction"),
    );

    assert!(!cursor.should_try_indexed_tail_fallback(
        Duration::from_millis(250),
        25_000,
        now,
        std::time::Duration::from_secs(15),
        std::time::Duration::from_mins(1),
    ));
    cursor.target_block = 280;
    assert!(cursor.should_try_indexed_tail_fallback(
        Duration::from_millis(250),
        25_000,
        now,
        std::time::Duration::from_secs(15),
        std::time::Duration::from_mins(1),
    ));

    cursor.mark_indexed_tail_attempt(now);
    assert!(!cursor.should_try_indexed_tail_fallback(
        Duration::from_millis(250),
        25_000,
        now + std::time::Duration::from_secs(30),
        std::time::Duration::from_secs(15),
        std::time::Duration::from_mins(1),
    ));
    assert!(cursor.should_try_indexed_tail_fallback(
        Duration::from_millis(250),
        25_000,
        now + std::time::Duration::from_mins(1),
        std::time::Duration::from_secs(15),
        std::time::Duration::from_mins(1),
    ));

    cursor.mark_progress(150, now + std::time::Duration::from_mins(1));
    cursor.target_block = 331;
    assert!(!cursor.should_try_indexed_tail_fallback(
        Duration::from_millis(250),
        25_000,
        now + std::time::Duration::from_secs(70),
        std::time::Duration::from_secs(15),
        std::time::Duration::from_mins(1),
    ));
}

#[test]
fn wallet_tail_fallback_retries_while_rpc_backfill_crawls_far_behind() {
    let now = std::time::Instant::now();
    let block_time = Duration::from_millis(250);
    let rpc_crawl_lag_blocks = 50 * 500;
    let min_stall = std::time::Duration::from_secs(15);
    let cooldown = std::time::Duration::from_mins(1);
    let (sender, _receiver) = mpsc::channel(1);
    let mut cursor = WalletBackfill::new(
        100,
        200 + rpc_crawl_lag_blocks,
        true,
        100,
        None,
        test_backfill_driver(sender, 0, 1),
        now,
    );

    // Steady progress keeps the stall rule quiet; the far-behind rule waits
    // for the cooldown since the backfill started.
    let at = now + std::time::Duration::from_secs(59);
    cursor.mark_progress(150, at);
    assert!(!cursor.should_try_indexed_tail_fallback(
        block_time,
        rpc_crawl_lag_blocks,
        at,
        min_stall,
        cooldown,
    ));
    let at = now + std::time::Duration::from_mins(1);
    cursor.mark_progress(199, at);
    assert!(cursor.should_try_indexed_tail_fallback(
        block_time,
        rpc_crawl_lag_blocks,
        at,
        min_stall,
        cooldown,
    ));
    cursor.mark_progress(201, at);
    assert!(!cursor.should_try_indexed_tail_fallback(
        block_time,
        rpc_crawl_lag_blocks,
        at,
        min_stall,
        cooldown,
    ));

    cursor.target_block += rpc_crawl_lag_blocks;
    cursor.mark_indexed_tail_attempt(at);
    let at = now + std::time::Duration::from_secs(119);
    cursor.mark_progress(250, at);
    assert!(!cursor.should_try_indexed_tail_fallback(
        block_time,
        rpc_crawl_lag_blocks,
        at,
        min_stall,
        cooldown,
    ));
    let at = now + std::time::Duration::from_mins(2);
    cursor.mark_progress(300, at);
    assert!(cursor.should_try_indexed_tail_fallback(
        block_time,
        rpc_crawl_lag_blocks,
        at,
        min_stall,
        cooldown,
    ));
}

#[test]
fn ready_wallet_tail_fallback_state_tracks_progress_and_cooldown() {
    let now = std::time::Instant::now();
    let mut state = WalletTailFallbackState::new(
        100,
        now.checked_sub(std::time::Duration::from_secs(20))
            .expect("test instant supports 20 second subtraction"),
    );

    assert!(!state.should_try_indexed_tail_fallback(
        Duration::from_millis(250),
        101,
        280,
        now,
        std::time::Duration::from_secs(15),
        std::time::Duration::from_mins(1),
    ));
    assert!(state.should_try_indexed_tail_fallback(
        Duration::from_millis(250),
        101,
        281,
        now,
        std::time::Duration::from_secs(15),
        std::time::Duration::from_mins(1),
    ));

    state.mark_indexed_tail_attempt(now);
    assert!(!state.should_try_indexed_tail_fallback(
        Duration::from_millis(250),
        101,
        281,
        now + std::time::Duration::from_secs(30),
        std::time::Duration::from_secs(15),
        std::time::Duration::from_mins(1),
    ));

    state.update_last_scanned(130, now + std::time::Duration::from_secs(30));
    assert!(!state.should_try_indexed_tail_fallback(
        Duration::from_millis(250),
        131,
        311,
        now + std::time::Duration::from_secs(40),
        std::time::Duration::from_secs(15),
        std::time::Duration::from_mins(1),
    ));

    assert!(state.should_try_indexed_tail_fallback(
        Duration::from_millis(250),
        131,
        311,
        now + std::time::Duration::from_secs(90),
        std::time::Duration::from_secs(15),
        std::time::Duration::from_mins(1),
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
    assert!(should_hedge_wallet_startup(100, 10, 110, 10));
    assert!(!should_hedge_wallet_startup(100, 10, 111, 10));
    assert!(!should_hedge_wallet_startup(100, 10, 0, 10));
    assert!(!should_hedge_wallet_startup(100, 10, 110, 0));
    assert!(!should_hedge_wallet_startup(110, 10, 110, 10));
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
    let (ready_tx, ready_rx) =
        tokio::sync::watch::channel(test_wallet_observation(WalletReadiness::Syncing));
    let cancel = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(wait_for_wallet_ready(ready_rx, cancel));

    tokio::task::yield_now().await;
    assert!(!task.is_finished());

    ready_tx
        .send(test_wallet_observation(WalletReadiness::Ready))
        .expect("ready receiver");
    let ready = tokio::time::timeout(std::time::Duration::from_secs(1), task)
        .await
        .expect("ready wait completed")
        .expect("ready task completed");
    assert!(ready);
}

#[tokio::test]
async fn txid_background_wait_exits_when_wallet_cancelled() {
    let (_ready_tx, ready_rx) =
        tokio::sync::watch::channel(test_wallet_observation(WalletReadiness::Syncing));
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
async fn txid_background_wait_survives_recoverable_wallet_failure() {
    let (ready_tx, ready_rx) =
        tokio::sync::watch::channel(test_wallet_observation(WalletReadiness::Syncing));
    let cancel = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(wait_for_wallet_ready(ready_rx, cancel));

    ready_tx
        .send(test_wallet_observation(WalletReadiness::Failed(
            WalletReadinessError::BackfillUnavailable,
        )))
        .expect("ready receiver");
    tokio::task::yield_now().await;
    assert!(!task.is_finished());

    ready_tx
        .send(test_wallet_observation(WalletReadiness::Ready))
        .expect("ready receiver");
    let ready = tokio::time::timeout(std::time::Duration::from_secs(1), task)
        .await
        .expect("ready wait completed")
        .expect("ready task completed");
    assert!(ready);
}

#[tokio::test]
async fn txid_background_wait_exits_when_wallet_shuts_down() {
    let (ready_tx, ready_rx) =
        tokio::sync::watch::channel(test_wallet_observation(WalletReadiness::Syncing));
    let cancel = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(wait_for_wallet_ready(ready_rx, cancel));

    ready_tx
        .send(test_wallet_observation(WalletReadiness::Shutdown))
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

    let rpc_apply = WalletScanApply::rows_from_log_batch(10, 20, &batch, PublicScanSource::Rpc)
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
            WalletScanApply::rows_from_log_batch(101, 105, &batch, PublicScanSource::Rpc)
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
        WalletBackfillStartResult::Rejected {
            committed_to: 104,
            reason: WalletBackfillRejectReason::Shutdown,
        }
    );
}

#[tokio::test]
async fn backfill_slot_rejects_different_wallet_without_changing_active_target() {
    let root_dir = temp_db_root("backfill-slot-different-wallet");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc = JsonRpcServer::spawn(Vec::new());
    let service = test_chain_service(
        Arc::clone(&db),
        test_chain_config(
            &scope,
            Arc::new(QueryRpcPool::new(
                vec![rpc.url.clone()],
                Duration::from_secs(1),
            )),
            None,
        ),
        ChainPublicDataPlane::new(
            Arc::clone(&db),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ),
    );
    let active = install_test_backfill_actor(&service, &scope, rpc.url.clone(), "wallet-a").await;
    let active_cache_key = active.cache_key.as_str().to_string();
    let active_actor_id = active.actor_id();
    let (active_sender, _active_receiver) = mpsc::channel(1);
    let (other_sender, _other_receiver) = mpsc::channel(1);
    let (other_driver, other_retirement) =
        test_backfill_driver_with_retirement_signal(other_sender, 2, 0, SYNTHETIC_BACKFILL_JOB_ID);
    let mut cursor = Some(WalletBackfillSlot {
        cache_key: active_cache_key.clone(),
        cursor: WalletBackfill::new(
            100,
            199,
            false,
            100,
            None,
            test_backfill_driver_for_actor(
                active_sender,
                active_actor_id,
                0,
                SYNTHETIC_BACKFILL_JOB_ID,
            ),
            std::time::Instant::now(),
        ),
    });
    let (request_tx, mut request_rx) = mpsc::channel(1);
    request_tx
        .send(BackfillRequest::Add {
            cache_key: test_cache_key("wallet-b").as_str().to_string(),
            from_block: 120,
            to_block: 130,
            follow_safe_head: false,
            progress_start_block: 120,
            acquisition_range: None,
            startup_warm_range: None,
            driver: other_driver,
        })
        .await
        .expect("queue different-wallet request");
    assert_test_backfill_actor_current(&service, &active).await;

    let active_cache_key_for_drain = active_cache_key.clone();
    let draining = tokio::spawn(async move {
        drain_pending_backfill_requests(
            &mut request_rx,
            &mut cursor,
            Some((active_cache_key_for_drain.as_str(), active_actor_id)),
        )
        .await;
        cursor
    });
    let signal = tokio::time::timeout(Duration::from_secs(1), other_retirement)
        .await
        .expect("different-wallet driver retirement is signalled")
        .expect("different-wallet driver retirement signal arrives");
    assert_eq!(
        signal.disposition,
        WalletBackfillOwnerDisposition::BenignRetirement
    );
    if let Some(acknowledgement) = signal.acknowledgement {
        acknowledgement
            .send(())
            .expect("acknowledge different-wallet driver retirement");
    }
    let cursor = draining.await.expect("backfill admission task joins");
    let cursor = &cursor.expect("active cursor retained").cursor;
    assert_eq!(cursor.from_block, 100);
    assert_eq!(cursor.target_block, 199);
    assert_eq!(cursor.driver.token().actor_id(), active_actor_id);
    assert_eq!(cursor.driver.token().job_id(), SYNTHETIC_BACKFILL_JOB_ID);

    service.unregister_wallet(&active).await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_backfill_loop_rebases_non_contiguous_cursor_to_actor_progress() {
    let root_dir = temp_db_root("wallet-backfill-non-contiguous-rebase");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc = JsonRpcServer::spawn(vec![
        serde_json::json!([]),
        rpc_block(105, 1_700_000_105, 0x11),
        serde_json::json!([]),
        rpc_block(110, 1_700_000_110, 0x22),
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, Arc::clone(&rpcs), None);
    chain.sync.block_range = 100;
    chain.sync.poll_interval = Duration::from_millis(1);
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let (service, backfill_request_rx) = test_chain_service_with_backfill(
        Arc::clone(&db),
        chain,
        public_data_plane,
        test_proxy_poi_policy(),
    );
    let backfill_request_tx = service.backfill_tx.clone();
    let registered = install_test_backfill_actor(&service, &scope, rpc.url.clone(), "test").await;
    let cache_key = registered.cache_key.as_str().to_string();
    let (_safe_head_tx, safe_head_rx) = watch::channel(110);
    let cancel = CancellationToken::new();
    spawn_backfill_loop(
        Arc::clone(&service),
        backfill_request_rx,
        Arc::clone(&rpcs),
        None,
        safe_head_rx,
        cancel.clone(),
    );

    let (wallet_tx, mut wallet_rx) = mpsc::channel(4);
    let actor = tokio::spawn(async move {
        let Some(BackfillEvent::Apply {
            apply, response, ..
        }) = wallet_rx.recv().await
        else {
            panic!("stale wallet backfill apply expected");
        };
        assert_eq!((apply.from_block, apply.to_block), (100, 110));
        response
            .send(WalletBackfillApplyResult::Rejected {
                committed_to: 105,
                reason: WalletBackfillRejectReason::NonContiguous {
                    expected_from: 106,
                    actual_from: 100,
                },
            })
            .expect("reject stale wallet backfill apply");

        let Some(BackfillEvent::Apply {
            apply, response, ..
        }) = wallet_rx.recv().await
        else {
            panic!("rebased wallet backfill apply expected");
        };
        assert_eq!((apply.from_block, apply.to_block), (106, 110));
        response
            .send(WalletBackfillApplyResult::Committed { committed_to: 110 })
            .expect("commit rebased wallet backfill apply");

        let Some(BackfillEvent::Finish {
            target_block,
            response,
            ..
        }) = wallet_rx.recv().await
        else {
            panic!("wallet backfill finish expected");
        };
        assert_eq!(target_block, 110);
        response
            .send(WalletBackfillFinishResult::Ready { committed_to: 110 })
            .expect("finish rebased wallet backfill");
    });

    assert_test_backfill_actor_current(&service, &registered).await;
    backfill_request_tx
        .send(BackfillRequest::add(
            &cache_key,
            100,
            110,
            false,
            100,
            test_backfill_driver_for_actor(
                wallet_tx,
                registered.actor_id(),
                0,
                SYNTHETIC_BACKFILL_JOB_ID,
            ),
        ))
        .await
        .expect("send stale wallet backfill request");

    tokio::time::timeout(Duration::from_secs(2), actor)
        .await
        .expect("rebased wallet backfill completed")
        .expect("actor response task completed");

    service.unregister_wallet(&registered).await;
    cancel.cancel();
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_backfill_loop_delivers_tail_before_warming_startup_gap_once() {
    let root_dir = temp_db_root("wallet-backfill-cached-suffix");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc = JsonRpcServer::spawn(vec![
        serde_json::json!([]),
        rpc_block(110, 1_700_000_110, 0x22),
        serde_json::json!("0x6e"),
        serde_json::json!([rpc_nullifiers_log(scope.railgun_contract, 103)]),
        rpc_block(103, 1_700_000_103, 0x13),
        rpc_block(105, 1_700_000_105, 0x11),
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, Arc::clone(&rpcs), None);
    chain.sync.block_range = 100;
    chain.sync.poll_interval = Duration::from_millis(1);
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    public_data_plane
        .record_recent_public_scan_rows(PublicScanRows {
            range: PublicScanRange::new(106, 110),
            source: PublicScanSource::Rpc,
            to_block_hash: Some([0x22; 32]),
            rows: WalletScanInputRows {
                nullifiers: vec![IndexedNullifierInput {
                    tree_number: 1,
                    nullifier: U256::from(7),
                    source: UtxoSource {
                        tx_hash: FixedBytes::from([0x22; 32]),
                        block_number: 106,
                        block_timestamp: 1_700_000_106,
                    },
                }],
                ..WalletScanInputRows::default()
            },
            epoch: public_data_plane.current_epoch(),
        })
        .await
        .expect("seed cached suffix");
    for block_number in 200..204 {
        public_data_plane
            .record_recent_public_scan_rows(PublicScanRows {
                range: PublicScanRange::new(block_number, block_number),
                source: PublicScanSource::Rpc,
                to_block_hash: Some([0x33; 32]),
                rows: WalletScanInputRows {
                    nullifiers: vec![IndexedNullifierInput {
                        tree_number: 1,
                        nullifier: U256::from(block_number),
                        source: UtxoSource {
                            tx_hash: FixedBytes::from([0x33; 32]),
                            block_number,
                            block_timestamp: block_number.saturating_add(1_700_000_000),
                        },
                    }],
                    ..WalletScanInputRows::default()
                },
                epoch: public_data_plane.current_epoch(),
            })
            .await
            .expect("seed newer row page");
    }
    let (service, backfill_request_rx) = test_chain_service_with_backfill(
        Arc::clone(&db),
        chain,
        public_data_plane,
        test_proxy_poi_policy(),
    );
    let backfill_request_tx = service.backfill_tx.clone();
    let registered = install_test_backfill_actor(&service, &scope, rpc.url.clone(), "test").await;
    let cache_key = registered.cache_key.as_str().to_string();
    let (_safe_head_tx, safe_head_rx) = watch::channel(110);
    let cancel = CancellationToken::new();
    spawn_backfill_loop(
        Arc::clone(&service),
        backfill_request_rx,
        Arc::clone(&rpcs),
        None,
        safe_head_rx,
        cancel.clone(),
    );

    let (wallet_tx, mut wallet_rx) = mpsc::channel(4);
    let actor = tokio::spawn(async move {
        let Some(BackfillEvent::Apply {
            apply, response, ..
        }) = wallet_rx.recv().await
        else {
            panic!("delivery apply expected");
        };
        assert_eq!((apply.from_block, apply.to_block), (106, 110));
        assert_eq!(apply.rows.source, PublicScanSource::Rpc);
        response
            .send(WalletBackfillApplyResult::Committed { committed_to: 110 })
            .expect("commit delivery apply");

        let Some(BackfillEvent::Finish {
            target_block,
            response,
            ..
        }) = wallet_rx.recv().await
        else {
            panic!("wallet backfill finish expected");
        };
        assert_eq!(target_block, 110);
        response
            .send(WalletBackfillFinishResult::Ready { committed_to: 110 })
            .expect("finish cached suffix backfill");
    });

    assert_test_backfill_actor_current(&service, &registered).await;
    backfill_request_tx
        .send(
            BackfillRequest::add_with_acquisition(
                &cache_key,
                106,
                110,
                false,
                106,
                (106, 110),
                test_backfill_driver_for_actor(
                    wallet_tx,
                    registered.actor_id(),
                    0,
                    SYNTHETIC_BACKFILL_JOB_ID,
                ),
            )
            .with_startup_warm_range(Some((100, 105))),
        )
        .await
        .expect("send wallet backfill request");
    tokio::time::timeout(Duration::from_secs(2), actor)
        .await
        .expect("cached suffix backfill completed")
        .expect("actor response task completed");

    let mut bodies = Vec::new();
    yield_until("delivery tail and startup gap warm", || {
        bodies.extend(rpc.drain_request_bodies());
        bodies.len() == 6 && !service.public_data_plane.public_window_warm_running()
    })
    .await;
    assert_eq!(
        get_logs_ranges(&bodies),
        vec![(106, 110), (100, 105)],
        "the tail is delivered first and the gap is warmed exactly once"
    );
    assert!(
        service
            .public_data_plane
            .cached_wallet_scan_exact(100, 110)
            .await
            .is_some(),
        "delivery and warming together leave the window replayable"
    );

    service.unregister_wallet(&registered).await;
    cancel.cancel();
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_backfill_loop_reuses_cached_prefix_before_fetching_delivery_tail() {
    let root_dir = temp_db_root("wallet-backfill-cached-prefix");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc = JsonRpcServer::spawn(vec![
        serde_json::json!([]),
        rpc_block(110, 1_700_000_110, 0x22),
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, Arc::clone(&rpcs), None);
    chain.sync.block_range = 100;
    chain.sync.poll_interval = Duration::from_millis(1);
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    public_data_plane
        .record_recent_public_scan_rows(PublicScanRows {
            range: PublicScanRange::new(100, 105),
            source: PublicScanSource::Rpc,
            to_block_hash: Some([0x11; 32]),
            rows: WalletScanInputRows::default(),
            epoch: public_data_plane.current_epoch(),
        })
        .await
        .expect("seed cached acquisition prefix");
    let (service, backfill_request_rx) = test_chain_service_with_backfill(
        Arc::clone(&db),
        chain,
        public_data_plane,
        test_proxy_poi_policy(),
    );
    let backfill_request_tx = service.backfill_tx.clone();
    let registered = install_test_backfill_actor(&service, &scope, rpc.url.clone(), "test").await;
    let cache_key = registered.cache_key.as_str().to_string();
    let (_safe_head_tx, safe_head_rx) = watch::channel(110);
    let cancel = CancellationToken::new();
    spawn_backfill_loop(
        Arc::clone(&service),
        backfill_request_rx,
        Arc::clone(&rpcs),
        None,
        safe_head_rx,
        cancel.clone(),
    );

    let (wallet_tx, mut wallet_rx) = mpsc::channel(4);
    let actor = tokio::spawn(async move {
        let Some(BackfillEvent::Apply {
            apply, response, ..
        }) = wallet_rx.recv().await
        else {
            panic!("delivery tail apply expected");
        };
        assert_eq!((apply.from_block, apply.to_block), (106, 110));
        response
            .send(WalletBackfillApplyResult::Committed { committed_to: 110 })
            .expect("commit delivery tail");

        let Some(BackfillEvent::Finish {
            target_block,
            response,
            ..
        }) = wallet_rx.recv().await
        else {
            panic!("wallet backfill finish expected");
        };
        assert_eq!(target_block, 110);
        response
            .send(WalletBackfillFinishResult::Ready { committed_to: 110 })
            .expect("finish cached-prefix backfill");
    });

    assert_test_backfill_actor_current(&service, &registered).await;
    backfill_request_tx
        .send(BackfillRequest::add_with_acquisition(
            &cache_key,
            106,
            110,
            false,
            106,
            (100, 110),
            test_backfill_driver_for_actor(
                wallet_tx,
                registered.actor_id(),
                0,
                SYNTHETIC_BACKFILL_JOB_ID,
            ),
        ))
        .await
        .expect("send wallet backfill request");
    tokio::time::timeout(Duration::from_secs(2), actor)
        .await
        .expect("cached-prefix backfill completed")
        .expect("actor response task completed");

    let requests = (0..2)
        .map(|_| {
            rpc.requests
                .recv_timeout(Duration::from_secs(1))
                .expect("RPC delivery-tail request")
        })
        .collect::<Vec<_>>();
    let get_logs = requests
        .iter()
        .find(|request| request.contains("eth_getLogs"))
        .expect("eth_getLogs request");
    assert!(get_logs.contains(r#""fromBlock":"0x6a""#));
    assert!(get_logs.contains(r#""toBlock":"0x6e""#));
    assert!(rpc.requests.try_recv().is_err());
    assert!(
        service
            .public_data_plane
            .cached_wallet_scan_exact(100, 110)
            .await
            .is_some(),
        "successful scheduler acquisition must retain the merged warm window"
    );

    service.unregister_wallet(&registered).await;
    cancel.cancel();
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_backfill_loop_reacquires_prefix_invalidated_before_tail_commit() {
    let root_dir = temp_db_root("wallet-backfill-invalidated-prefix");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let (rpc, blocked_tail) = JsonRpcServer::spawn_with_blocked_response(
        vec![
            serde_json::json!([]),
            rpc_block(110, 1_700_000_110, 0x22),
            serde_json::json!([]),
            rpc_block(110, 1_700_000_110, 0x33),
        ],
        0,
    );
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, Arc::clone(&rpcs), None);
    chain.sync.block_range = 100;
    chain.sync.poll_interval = Duration::from_millis(1);
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    public_data_plane
        .record_recent_public_scan_rows(PublicScanRows {
            range: PublicScanRange::new(100, 105),
            source: PublicScanSource::Rpc,
            to_block_hash: Some([0x11; 32]),
            rows: WalletScanInputRows::default(),
            epoch: public_data_plane.current_epoch(),
        })
        .await
        .expect("seed cached acquisition prefix");
    let (service, backfill_request_rx) = test_chain_service_with_backfill(
        Arc::clone(&db),
        chain,
        public_data_plane.clone(),
        test_proxy_poi_policy(),
    );
    let backfill_request_tx = service.backfill_tx.clone();
    let registered = install_test_backfill_actor(&service, &scope, rpc.url.clone(), "test").await;
    let cache_key = registered.cache_key.as_str().to_string();
    let (_safe_head_tx, safe_head_rx) = watch::channel(110);
    let cancel = CancellationToken::new();
    spawn_backfill_loop(
        Arc::clone(&service),
        backfill_request_rx,
        Arc::clone(&rpcs),
        None,
        safe_head_rx,
        cancel.clone(),
    );

    let (wallet_tx, mut wallet_rx) = mpsc::channel(4);
    let actor = tokio::spawn(async move {
        let Some(BackfillEvent::Apply {
            apply, response, ..
        }) = wallet_rx.recv().await
        else {
            panic!("delivery tail apply expected");
        };
        assert_eq!((apply.from_block, apply.to_block), (106, 110));
        response
            .send(WalletBackfillApplyResult::Committed { committed_to: 110 })
            .expect("commit delivery tail");

        let Some(BackfillEvent::Finish {
            target_block,
            response,
            ..
        }) = wallet_rx.recv().await
        else {
            panic!("wallet backfill finish expected after prefix reacquisition");
        };
        assert_eq!(target_block, 110);
        response
            .send(WalletBackfillFinishResult::Ready { committed_to: 110 })
            .expect("finish reacquired-prefix backfill");
    });

    assert_test_backfill_actor_current(&service, &registered).await;
    backfill_request_tx
        .send(BackfillRequest::add_with_acquisition(
            &cache_key,
            106,
            110,
            false,
            106,
            (100, 110),
            test_backfill_driver_for_actor(
                wallet_tx,
                registered.actor_id(),
                0,
                SYNTHETIC_BACKFILL_JOB_ID,
            ),
        ))
        .await
        .expect("send wallet backfill request");
    let PathServerBlockControl {
        request_started,
        release,
    } = blocked_tail;
    tokio::task::spawn_blocking(move || request_started.recv_timeout(Duration::from_secs(1)))
        .await
        .expect("blocked response wait task")
        .expect("tail request started after cached-prefix decision");
    public_data_plane
        .invalidate_public_scan_coverage_from(100)
        .await;
    release.send(()).expect("release tail response");

    tokio::time::timeout(Duration::from_secs(2), actor)
        .await
        .expect("invalidated-prefix backfill completed")
        .expect("actor response task completed");
    let requests = (0..4)
        .map(|_| {
            rpc.requests
                .recv_timeout(Duration::from_secs(1))
                .expect("RPC acquisition request")
        })
        .collect::<Vec<_>>();
    let get_logs = requests
        .iter()
        .filter(|request| request.contains("eth_getLogs"))
        .collect::<Vec<_>>();
    assert_eq!(get_logs.len(), 2);
    assert!(get_logs[0].contains(r#""fromBlock":"0x6a""#));
    assert!(get_logs[0].contains(r#""toBlock":"0x6e""#));
    assert!(get_logs[1].contains(r#""fromBlock":"0x64""#));
    assert!(get_logs[1].contains(r#""toBlock":"0x6e""#));
    assert!(
        public_data_plane
            .cached_wallet_scan_exact(100, 110)
            .await
            .is_some(),
        "prefix invalidation must force full acquisition restoration before finish"
    );

    service.unregister_wallet(&registered).await;
    cancel.cancel();
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_backfill_loop_reacquires_full_window_after_stale_cached_delivery() {
    let root_dir = temp_db_root("wallet-backfill-stale-acquisition");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc = JsonRpcServer::spawn(vec![
        serde_json::json!([]),
        rpc_block(105, 1_700_000_105, 0x11),
        serde_json::json!([]),
        rpc_block(110, 1_700_000_110, 0x22),
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, Arc::clone(&rpcs), None);
    chain.sync.block_range = 100;
    chain.sync.poll_interval = Duration::from_millis(1);
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    public_data_plane
        .record_recent_public_scan_rows(PublicScanRows {
            range: PublicScanRange::new(106, 110),
            source: PublicScanSource::Rpc,
            to_block_hash: Some([0x22; 32]),
            rows: WalletScanInputRows::default(),
            epoch: public_data_plane.current_epoch(),
        })
        .await
        .expect("seed cached delivery suffix");
    let (service, backfill_request_rx) = test_chain_service_with_backfill(
        Arc::clone(&db),
        chain,
        public_data_plane.clone(),
        test_proxy_poi_policy(),
    );
    let backfill_request_tx = service.backfill_tx.clone();
    let registered = install_test_backfill_actor(&service, &scope, rpc.url.clone(), "test").await;
    let cache_key = registered.cache_key.as_str().to_string();
    let (_safe_head_tx, safe_head_rx) = watch::channel(110);
    let cancel = CancellationToken::new();
    spawn_backfill_loop(
        Arc::clone(&service),
        backfill_request_rx,
        Arc::clone(&rpcs),
        None,
        safe_head_rx,
        cancel.clone(),
    );

    let (wallet_tx, mut wallet_rx) = mpsc::channel(4);
    let invalidation_plane = public_data_plane.clone();
    let actor = tokio::spawn(async move {
        let Some(BackfillEvent::Apply {
            apply, response, ..
        }) = wallet_rx.recv().await
        else {
            panic!("initial cached suffix apply expected");
        };
        assert_eq!((apply.from_block, apply.to_block), (106, 110));
        assert_eq!(apply.rows.source, PublicScanSource::CachedCoverage);
        let stale_epoch = apply.read_scope.epoch();
        let current_epoch = invalidation_plane
            .invalidate_public_scan_coverage_from(100)
            .await;
        response
            .send(WalletBackfillApplyResult::Rejected {
                committed_to: 105,
                reason: WalletBackfillRejectReason::StaleDataPlaneEpoch {
                    expected: current_epoch.value,
                    actual: stale_epoch.value,
                },
            })
            .expect("reject invalidated cached suffix");

        let Some(BackfillEvent::Apply {
            apply, response, ..
        }) = wallet_rx.recv().await
        else {
            panic!("reacquired suffix apply expected");
        };
        assert_eq!(
            (apply.from_block, apply.to_block),
            (106, 110),
            "reacquisition must still deliver only the wallet suffix",
        );
        assert_eq!(apply.read_scope.epoch(), current_epoch);
        response
            .send(WalletBackfillApplyResult::Committed { committed_to: 110 })
            .expect("commit reacquired suffix");

        let Some(BackfillEvent::Finish {
            target_block,
            response,
            ..
        }) = wallet_rx.recv().await
        else {
            panic!("wallet backfill finish expected");
        };
        assert_eq!(target_block, 110);
        response
            .send(WalletBackfillFinishResult::Ready { committed_to: 110 })
            .expect("finish reacquired backfill");
    });

    assert_test_backfill_actor_current(&service, &registered).await;
    backfill_request_tx
        .send(BackfillRequest::add_with_acquisition(
            &cache_key,
            106,
            110,
            false,
            106,
            (100, 110),
            test_backfill_driver_for_actor(
                wallet_tx,
                registered.actor_id(),
                0,
                SYNTHETIC_BACKFILL_JOB_ID,
            ),
        ))
        .await
        .expect("send wallet backfill request");
    tokio::time::timeout(Duration::from_secs(2), actor)
        .await
        .expect("reacquired wallet backfill completed")
        .expect("actor response task completed");

    let requests = (0..4)
        .map(|_| {
            rpc.requests
                .recv_timeout(Duration::from_secs(1))
                .expect("RPC acquisition request")
        })
        .collect::<Vec<_>>();
    let get_logs = requests
        .iter()
        .filter(|request| request.contains("eth_getLogs"))
        .collect::<Vec<_>>();
    assert_eq!(get_logs.len(), 2);
    assert!(get_logs[0].contains(r#""fromBlock":"0x64""#));
    assert!(get_logs[0].contains(r#""toBlock":"0x69""#));
    assert!(get_logs[1].contains(r#""fromBlock":"0x64""#));
    assert!(get_logs[1].contains(r#""toBlock":"0x6e""#));
    assert!(
        service
            .public_data_plane
            .cached_wallet_scan_suffix(100, 110)
            .await
            .is_some(),
        "retry must restore the full acquisition window",
    );

    service.unregister_wallet(&registered).await;
    cancel.cancel();
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn retained_acquisition_reconciliation_restores_missing_cache_without_moving_delivery_cursor()
{
    let root_dir = temp_db_root("retained-acquisition-reconciliation");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc = JsonRpcServer::spawn(Vec::new());
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let chain = test_chain_config(&scope, Arc::clone(&rpcs), None);
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane.clone());
    let (sender, _receiver) = mpsc::channel(1);
    let mut cursor = WalletBackfill::new(
        106,
        110,
        false,
        106,
        Some((100, 105)),
        test_backfill_driver(sender, 0, 1),
        std::time::Instant::now(),
    );
    let apply = WalletScanApply::rows(
        100,
        105,
        WalletScanInputRows::default(),
        public_data_plane.begin_public_scan_read(),
        PublicScanSource::Rpc,
        Some([0x11; 32]),
    );
    public_data_plane
        .commit_completed_wallet_scan_acquisition(PublicScanRange::new(100, 105), &[apply])
        .await
        .expect("commit retained acquisition");
    cursor.finish_retained_acquisition();
    let mut cursor = Some(WalletBackfillSlot {
        cache_key: String::from("test"),
        cursor,
    });

    public_data_plane
        .invalidate_public_scan_coverage_from(100)
        .await;
    assert!(!reconcile_retained_acquisition(&service, &mut cursor).await);

    let active_cursor = &cursor.as_ref().expect("cursor remains active").cursor;
    assert_eq!(active_cursor.acquisition_range(), Some((100, 105)));
    assert_eq!(active_cursor.retained_acquisition_range(), Some((100, 105)));
    assert_eq!(active_cursor.from_block, 106);

    let apply = WalletScanApply::rows(
        100,
        105,
        WalletScanInputRows::default(),
        public_data_plane.begin_public_scan_read(),
        PublicScanSource::Rpc,
        Some([0x22; 32]),
    );
    public_data_plane
        .commit_completed_wallet_scan_acquisition(PublicScanRange::new(100, 105), &[apply])
        .await
        .expect("recommit retained acquisition");
    cursor
        .as_mut()
        .expect("cursor remains active")
        .cursor
        .finish_retained_acquisition();
    public_data_plane
        .invalidate_public_scan_coverage_from(100)
        .await;
    assert!(reconcile_retained_acquisition(&service, &mut cursor).await);
    let cursor = &cursor.as_ref().expect("cursor remains active").cursor;
    assert_eq!(cursor.acquisition_range(), None);
    assert_eq!(cursor.retained_acquisition_range(), None);
    assert_eq!(cursor.from_block, 106);

    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_backfill_loop_abandons_malformed_warm_gap_before_delivering_tail() {
    let root_dir = temp_db_root("wallet-backfill-malformed-warm-gap");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let mut malformed_log = rpc_nullifiers_log(scope.railgun_contract, 103);
    malformed_log["data"] = serde_json::json!("0x01");
    let rpc = JsonRpcServer::spawn(vec![
        serde_json::json!([malformed_log]),
        rpc_block(103, 1_700_000_103, 0x13),
        rpc_block(105, 1_700_000_105, 0x11),
        serde_json::json!([]),
        rpc_block(110, 1_700_000_110, 0x22),
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, Arc::clone(&rpcs), None);
    chain.sync.block_range = 100;
    chain.sync.poll_interval = Duration::from_millis(1);
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let (service, backfill_request_rx) = test_chain_service_with_backfill(
        Arc::clone(&db),
        chain,
        public_data_plane,
        test_proxy_poi_policy(),
    );
    let backfill_request_tx = service.backfill_tx.clone();
    let registered = install_test_backfill_actor(&service, &scope, rpc.url.clone(), "test").await;
    let cache_key = registered.cache_key.as_str().to_string();
    let (_safe_head_tx, safe_head_rx) = watch::channel(110);
    let cancel = CancellationToken::new();
    spawn_backfill_loop(
        Arc::clone(&service),
        backfill_request_rx,
        Arc::clone(&rpcs),
        None,
        safe_head_rx,
        cancel.clone(),
    );

    let (wallet_tx, mut wallet_rx) = mpsc::channel(4);
    let actor = tokio::spawn(async move {
        let Some(BackfillEvent::Apply {
            apply, response, ..
        }) = wallet_rx.recv().await
        else {
            panic!("delivery apply expected");
        };
        assert_eq!((apply.from_block, apply.to_block), (106, 110));
        response
            .send(WalletBackfillApplyResult::Committed { committed_to: 110 })
            .expect("commit delivery apply");
        let Some(BackfillEvent::Finish {
            target_block,
            response,
            ..
        }) = wallet_rx.recv().await
        else {
            panic!("wallet backfill finish expected");
        };
        assert_eq!(target_block, 110);
        response
            .send(WalletBackfillFinishResult::Ready { committed_to: 110 })
            .expect("finish malformed warm backfill");
    });

    assert_test_backfill_actor_current(&service, &registered).await;
    backfill_request_tx
        .send(BackfillRequest::add_with_acquisition(
            &cache_key,
            106,
            110,
            false,
            106,
            (100, 105),
            test_backfill_driver_for_actor(
                wallet_tx,
                registered.actor_id(),
                0,
                SYNTHETIC_BACKFILL_JOB_ID,
            ),
        ))
        .await
        .expect("send malformed warm backfill request");
    tokio::time::timeout(Duration::from_secs(2), actor)
        .await
        .expect("malformed warm backfill completed")
        .expect("actor response task completed");

    let mut requests: Vec<String> = Vec::new();
    while requests
        .iter()
        .filter(|request| request.contains("eth_getLogs"))
        .count()
        < 2
    {
        requests.push(
            rpc.requests
                .recv_timeout(Duration::from_secs(1))
                .expect("RPC backfill request"),
        );
    }
    let get_logs = requests
        .iter()
        .filter(|request| request.contains("eth_getLogs"))
        .collect::<Vec<_>>();
    assert_eq!(
        get_logs
            .iter()
            .filter(|request| request.contains(r#""fromBlock":"0x64""#))
            .count(),
        1,
        "malformed warm acquisition must be fetched at most once"
    );
    assert!(get_logs.iter().any(|request| {
        request.contains(r#""fromBlock":"0x64""#) && request.contains(r#""toBlock":"0x69""#)
    }));
    assert!(get_logs.iter().any(|request| {
        request.contains(r#""fromBlock":"0x6a""#) && request.contains(r#""toBlock":"0x6e""#)
    }));

    service.unregister_wallet(&registered).await;
    cancel.cancel();
    drop(service);
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
    let (artifact_source, manifest_block) =
        checkpointed_wallet_artifact_source_with_blocked_manifest(&scope, 100, 200, 150);
    // The startup race's Squid candidate holds its first page and stalls on
    // its second while the artifact session wins; the tail probe follows.
    let (squid, race_page_block) = GraphqlServer::spawn_owned_with_blocked_response(
        vec![
            squid_wallet_probe(200),
            squid_wallet_page_with_nullifier(120),
            squid_wallet_page_with_nullifier(170),
            squid_wallet_probe(200),
            r#"{"data":{"transactCommitments":[],"shieldCommitments":[],"nullifiers":[]}}"#
                .to_owned(),
        ],
        2,
    );
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
        Duration::from_secs(1),
    ));
    let chain = ChainConfig {
        deployment: broadcaster_core::deployment::RailgunDeployment {
            chain_id: scope.chain_id,
            contract: scope.railgun_contract,
            deployment_block: 0,
            v2_start_block: 0,
            legacy_shield_block: 0,
            relay_adapt_contract: Address::ZERO,
            relay_adapt_7702_contract: Address::ZERO,
        },
        sync: crate::RailgunSyncOptions {
            archive_until_block: 0,
            // Shorter than the 50-block tail after the artifact checkpoint,
            // so Squid is probed for it.
            block_range: 25,
            indexed_wallet_block_range: 50,
            poll_interval: Duration::from_millis(1),
            quick_sync_endpoint: Some(squid.url.clone()),
            indexed_artifact_source: Some(artifact_source.config),
            anchor_interval: 1000,
            anchor_retention: 5,
        },
        rpcs: Arc::clone(&rpcs),
        archive_rpc_url: None,
        block_time: Duration::from_secs(12),
        finality_depth: 0,
        http_client: reqwest::Client::new(),
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
        wallet: RwLock::new(None),
        wallet_registration_gate: Mutex::new(()),
        cancel: CancellationToken::new(),
        live_log_task: std::sync::Mutex::new(None),
        poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        poi_submitter_task: std::sync::Mutex::new(None),
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
            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: wallet_backfill_tx.clone(),
            public_data_plane,
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
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

    let catch_up = service.indexed_wallet_catch_up(
        &wallet_cfg,
        0,
        100,
        200,
        &handle,
        &worker_cancel,
        IndexedWalletCatchUpSourceOrder::ArtifactsFirst,
        true,
        (
            &wallet_backfill_tx,
            crate::types::WalletSchedulableProgress {
                last_scanned: 100,
                reset_generation: 0,
            },
        ),
    );
    let release_race_page = async {
        wait_for_std_signal(
            race_page_block.request_started,
            "race Squid page request started",
        )
        .await;
        manifest_block
            .release
            .send(())
            .expect("release artifact manifest");
        yield_until("artifact pages committed", || {
            handle.last_scanned() == Some(150)
        })
        .await;
        race_page_block
            .release
            .send(())
            .expect("release race Squid page");
    };
    let (checkpoint, ()) = tokio::join!(catch_up, release_race_page);

    assert_eq!(checkpoint, 200);
    assert_eq!(handle.last_scanned(), Some(200));
    assert_eq!(
        handle
            .indexed_catch_up_rx
            .borrow()
            .as_ref()
            .map(|status| status.source),
        Some(WalletIndexedCatchUpSource::Squid)
    );
    assert!(
        matches!(
            service
                .public_data_plane
                .cached_public_scan_coverage(PublicScanRange::new(101, 150))
                .await,
            PublicCoverageAnswer::ReplayableEmpty {
                source: PublicScanSource::IndexedArtifacts,
                ..
            }
        ),
        "the held Squid row at block 120 is discarded"
    );
    let requests = squid.requests.try_iter().collect::<Vec<_>>();
    assert_eq!(requests.len(), 5);
    assert!(requests[0].contains("query WalletProbe"));
    assert!(requests[1].contains(r#""fromBlock":"101""#));
    assert!(requests[2].contains(r#""fromBlock":"151""#));
    let probe_request = &requests[3];
    assert!(probe_request.contains("query WalletProbe"));
    let page_request = &requests[4];
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
        checkpointed_wallet_artifact_source_with_blocked_manifest(&scope, 100, 150, 150);
    let PathServerBlockControl {
        request_started,
        release,
    } = block;
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
        Duration::from_secs(1),
    ));
    let chain = ChainConfig {
        deployment: broadcaster_core::deployment::RailgunDeployment {
            chain_id: scope.chain_id,
            contract: scope.railgun_contract,
            deployment_block: 0,
            v2_start_block: 0,
            legacy_shield_block: 0,
            relay_adapt_contract: Address::ZERO,
            relay_adapt_7702_contract: Address::ZERO,
        },
        sync: crate::RailgunSyncOptions {
            archive_until_block: 0,
            block_range: 100,
            indexed_wallet_block_range: 100,
            poll_interval: Duration::from_millis(1),
            quick_sync_endpoint: Some(Url::parse("http://127.0.0.1:1").expect("squid url")),
            indexed_artifact_source: Some(artifact_source.config),
            anchor_interval: 1000,
            anchor_retention: 5,
        },
        rpcs: Arc::clone(&rpcs),
        archive_rpc_url: None,
        block_time: Duration::from_secs(12),
        finality_depth: 0,
        http_client: reqwest::Client::new(),
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
        wallet: RwLock::new(None),
        wallet_registration_gate: Mutex::new(()),
        cancel: CancellationToken::new(),
        live_log_task: std::sync::Mutex::new(None),
        poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        poi_submitter_task: std::sync::Mutex::new(None),
        anchor_last: std::sync::atomic::AtomicU64::new(0),
        txid_public_cache_started: std::sync::atomic::AtomicBool::new(false),
        wallet_actor_next: std::sync::atomic::AtomicU64::new(1),
        wallet_reset_intent_next: std::sync::atomic::AtomicU64::new(1),
        public_data_plane: public_data_plane.clone(),
    });
    let (wallet_backfill_tx, wallet_backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(1);
    let worker_cancel = CancellationToken::new();
    let (progress_tx, progress_rx) = watch::channel(None);
    let mut wallet_cfg = test_wallet_config(
        &scope,
        Url::parse("http://127.0.0.1:1").expect("quick-sync url"),
    );
    wallet_cfg.progress_tx = Some(progress_tx);
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),
            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: wallet_backfill_tx.clone(),
            public_data_plane: public_data_plane.clone(),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
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
                (
                    &catch_up_sender,
                    crate::types::WalletSchedulableProgress {
                        last_scanned: 100,
                        reset_generation: 0,
                    },
                ),
            )
            .await
    });
    tokio::time::timeout(
        Duration::from_secs(2),
        tokio::task::spawn_blocking(move || {
            request_started
                .recv()
                .expect("artifact manifest fetch started");
        }),
    )
    .await
    .expect("artifact manifest fetch started")
    .expect("manifest wait task completed");
    let preparation = progress_rx
        .borrow()
        .expect("wallet artifact preparation progress");
    assert_eq!(preparation.stage, SyncProgressStage::PreparingUtxoIndex);
    assert_eq!(preparation.unit, SyncProgressUnit::ArtifactPreparation);
    assert_eq!(preparation.source, Some(PublicScanSource::IndexedArtifacts));
    assert_eq!(preparation.percent(), 5);

    public_data_plane
        .invalidate_public_scan_coverage_from(101)
        .await;
    release.send(()).expect("release artifact manifest fetch");
    let checkpoint = catch_up.await.expect("indexed catch-up task");
    let retained_progress = progress_rx
        .borrow()
        .expect("pre-invalidation artifact progress");
    assert_eq!(retained_progress, preparation);

    assert_eq!(checkpoint, 100);
    assert_eq!(handle.last_scanned(), Some(100));
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
async fn wallet_retirement_interrupts_active_rpc_backfill_and_reuses_coordinator() {
    let root_dir = temp_db_root("wallet-retirement-active-rpc");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let (rpc, blocked) = JsonRpcServer::spawn_with_blocked_response(vec![serde_json::json!([])], 0);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, Arc::clone(&rpcs), None);
    chain.sync.block_range = 10;
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let (service, backfill_rx) = test_chain_service_with_backfill(
        Arc::clone(&db),
        chain,
        public_data_plane,
        test_proxy_poi_policy(),
    );
    let registered =
        install_test_backfill_actor(&service, &scope, rpc.url.clone(), "retired").await;
    let actor_cancel = service
        .wallet
        .read()
        .await
        .as_ref()
        .expect("registered wallet")
        .cancel
        .clone();
    let (_safe_head_tx, safe_head_rx) = watch::channel(110);
    let loop_cancel = CancellationToken::new();
    spawn_backfill_loop(
        Arc::clone(&service),
        backfill_rx,
        Arc::clone(&rpcs),
        None,
        safe_head_rx,
        loop_cancel.clone(),
    );

    let (wallet_tx, mut wallet_rx) = mpsc::channel(1);
    let (liveness, mut retirement) = oneshot::channel();
    let driver = WalletBackfillGrant::for_actor_accepted_job_with_cancel(
        WalletSyncToken::for_test(1, registered.actor_id(), 0, SYNTHETIC_BACKFILL_JOB_ID),
        wallet_tx,
        liveness,
        actor_cancel,
    )
    .activate();
    service
        .backfill_tx
        .send(BackfillRequest::add(
            registered.cache_key.as_str(),
            100,
            110,
            false,
            100,
            driver,
        ))
        .await
        .expect("queue active backfill");
    wait_for_std_signal(blocked.request_started, "active RPC request started").await;

    let unregistering = tokio::spawn({
        let service = Arc::clone(&service);
        let registered = registered.clone();
        async move { service.unregister_wallet(&registered).await }
    });
    let signal = tokio::time::timeout(Duration::from_secs(1), &mut retirement)
        .await
        .expect("active driver retirement signalled")
        .expect("active driver retirement signal received");
    assert_eq!(
        signal.disposition,
        WalletBackfillOwnerDisposition::BenignRetirement
    );
    signal
        .acknowledgement
        .expect("active retirement acknowledgement")
        .send(())
        .expect("acknowledge active driver retirement");
    tokio::time::timeout(Duration::from_secs(1), unregistering)
        .await
        .expect("wallet retirement completes while RPC is blocked")
        .expect("wallet retirement task joins");

    blocked
        .release
        .send(())
        .expect("release retired RPC request");
    assert!(
        wallet_rx.try_recv().is_err(),
        "retired RPC must not reach actor"
    );

    let mut successor_cfg = test_wallet_config(&scope, rpc.url);
    successor_cfg.cache_key = test_cache_key("retirement-successor");
    successor_cfg.sync_to_block = Some(0);
    successor_cfg.use_indexed_wallet_catch_up = false;
    let successor = service
        .register_wallet(successor_cfg)
        .await
        .expect("successor admission after active RPC retirement");
    assert_ne!(successor.actor_id(), registered.actor_id());
    service.unregister_wallet(&successor).await;
    loop_cancel.cancel();
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn indexed_catch_up_cancellation_is_typed_after_driver_acceptance() {
    let scope = test_scope();
    let probe = r#"{"data":{"squidStatus":{"height":"110"},"transactCommitments":[],"shieldCommitments":[],"nullifiers":[],"legacyEncryptedCommitments":[],"legacyGeneratedCommitments":[]}}"#;
    let (squid, blocked) = GraphqlServer::spawn_owned_with_blocked_response(
        vec![
            probe.to_string(),
            indexed_wallet_nullifier_page(101, U256::ZERO),
        ],
        1,
    );
    let context = IndexedCatchUpTestContext::new(&scope, squid.url.clone(), None, 100, 100).await;
    let service = Arc::clone(&context.service);
    let cfg = context.wallet_cfg.clone();
    let handle = context.handle.clone();
    let cancel = context.cancel.clone();
    let sender = context.wallet_backfill_tx.clone();
    let catch_up = tokio::spawn(async move {
        service
            .indexed_wallet_catch_up_outcome(
                &cfg,
                0,
                100,
                110,
                &handle,
                &cancel,
                IndexedWalletCatchUpSourceOrder::SquidFirst,
                true,
                (
                    &sender,
                    crate::types::WalletSchedulableProgress {
                        last_scanned: 100,
                        reset_generation: 0,
                    },
                ),
            )
            .await
    });
    wait_for_std_signal(blocked.request_started, "indexed page request started").await;
    context.cancel.cancel();
    let outcome = tokio::time::timeout(Duration::from_secs(1), catch_up)
        .await
        .expect("indexed cancellation returns while page is blocked")
        .expect("indexed catch-up task joins");
    assert_eq!(outcome, IndexedWalletCatchUpOutcome::Cancelled(100));
    assert!(
        context
            .handle
            .last_scanned()
            .is_none_or(|last_scanned| last_scanned <= 100)
    );
    tokio::time::timeout(Duration::from_secs(1), async {
        while context.handle.indexed_catch_up_rx.borrow().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancelled indexed status clears");
    blocked
        .release
        .send(())
        .expect("release cancelled indexed page");
    context.cleanup();
}

#[tokio::test]
async fn wallet_snapshot_does_not_fetch_optional_prior_endpoint() {
    let BlockedWalletOptionalMaintenanceFixture {
        root_dir,
        db,
        public_data_plane,
        chain,
        artifact_source,
        optional_block,
        optional_descriptor: _,
    } = blocked_wallet_optional_maintenance_fixture("wallet-optional-nonblocking");
    let PathServerBlockControl {
        request_started,
        release: _,
    } = optional_block;
    let read_scope = public_data_plane.begin_public_scan_read();

    let session = tokio::time::timeout(
        Duration::from_secs(2),
        IndexedWalletArtifactSession::prepare(
            &chain,
            110,
            120,
            read_scope,
            &public_data_plane,
            None,
        ),
    )
    .await
    .expect("required wallet artifact preparation was not blocked by optional retention")
    .expect("prepare wallet artifacts")
    .expect("wallet artifact session");
    let page = match session
        .page_for_block_range(110, 120)
        .expect("required wallet rows are available")
    {
        IndexedWalletArtifactPageOutcome::Page(page) => page,
        IndexedWalletArtifactPageOutcome::Exhausted { .. } => {
            panic!("required wallet artifact page")
        }
    };
    assert_eq!(page.checkpoint_block, 120);

    assert!(
        request_started
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "current snapshot reads must not fetch optional prior-tail chunks"
    );

    public_data_plane.shutdown().await;
    drop(public_data_plane);
    drop(chain);
    drop(artifact_source.server);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn superseded_wallet_descriptor_stays_uncached_after_invalidation() {
    let BlockedWalletOptionalMaintenanceFixture {
        root_dir,
        db,
        public_data_plane,
        chain,
        artifact_source,
        optional_block,
        optional_descriptor,
    } = blocked_wallet_optional_maintenance_fixture("wallet-optional-stale");
    let PathServerBlockControl {
        request_started,
        release: _,
    } = optional_block;
    let read_scope = public_data_plane.begin_public_scan_read();
    IndexedWalletArtifactSession::prepare(&chain, 110, 120, read_scope, &public_data_plane, None)
        .await
        .expect("prepare wallet artifacts")
        .expect("wallet artifact session");
    assert!(
        request_started
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "superseded optional descriptor must not be fetched"
    );

    public_data_plane
        .invalidate_public_scan_coverage_from(110)
        .await;

    assert!(
        public_data_plane
            .cached_wallet_scan_artifact_chunk(&optional_descriptor)
            .is_none(),
        "superseded descriptors must remain uncached"
    );

    public_data_plane.shutdown().await;
    drop(public_data_plane);
    drop(chain);
    drop(artifact_source.server);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_artifact_prepare_reuses_retained_chunks() {
    let root_dir = temp_db_root("wallet-artifact-warm-cache-reuse");
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
    let (artifact_source, block) = checkpointed_wallet_artifact_source_controlled_with_requests(
        &scope,
        100,
        150,
        150,
        false,
        6,
        Some(125),
        false,
    );
    assert!(block.is_none());
    let retained_descriptor = artifact_source.chunk_descriptors[0].clone();
    let transient_descriptor = artifact_source.chunk_descriptors[1].clone();
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
        Duration::from_secs(1),
    ));
    let chain = test_chain_config(&scope, rpcs, Some(artifact_source.config.clone()));
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );

    IndexedWalletArtifactSession::prepare(
        &chain,
        100,
        150,
        public_data_plane.begin_public_scan_read(),
        &public_data_plane,
        None,
    )
    .await
    .expect("prepare cold wallet artifacts")
    .expect("cold wallet artifact session");
    for _ in 0..100 {
        if public_data_plane
            .cached_wallet_scan_artifact_chunk(&retained_descriptor)
            .is_some()
            && public_data_plane
                .cached_wallet_scan_transient_artifact_chunk(&transient_descriptor)
                .is_some()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        public_data_plane
            .cached_wallet_scan_artifact_chunk(&retained_descriptor)
            .is_some(),
        "stable wallet artifact chunk was not retained"
    );
    assert!(
        public_data_plane
            .cached_wallet_scan_transient_artifact_chunk(&transient_descriptor)
            .is_some(),
        "transient wallet artifact chunk was not retained"
    );
    assert_eq!(artifact_source.server.request_count(), 4);

    IndexedWalletArtifactSession::prepare(
        &chain,
        100,
        150,
        public_data_plane.begin_public_scan_read(),
        &public_data_plane,
        None,
    )
    .await
    .expect("prepare warm wallet artifacts")
    .expect("warm wallet artifact session");
    assert_eq!(
        artifact_source.server.request_count(),
        5,
        "warm preparation should reuse the manifest, stable history and the unchanged transient tail"
    );

    public_data_plane.shutdown().await;
    drop(public_data_plane);
    drop(chain);
    drop(artifact_source.server);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn partial_cached_replay_does_not_publish_regressive_artifact_preparation() {
    let scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xbb; 20]),
    };
    let artifact_source = checkpointed_wallet_artifact_source(&scope, 100, 200, 200);
    let mut context = IndexedCatchUpTestContext::new(
        &scope,
        Url::parse("http://127.0.0.1:1").expect("quick-sync url"),
        Some(artifact_source.config.clone()),
        100,
        100,
    )
    .await;
    context
        .public_data_plane
        .record_public_scan_coverage(PublicScanCoverageWrite {
            range: PublicScanRange::new(101, 150),
            source: PublicScanSource::Rpc,
            row_count: 0,
            read_scope: context.public_data_plane.begin_public_scan_read(),
        })
        .await
        .expect("record cached prefix");
    let (progress_tx, progress_rx) = watch::channel(None);
    context.wallet_cfg.progress_tx = Some(progress_tx);

    let checkpoint = context
        .spawn_catch_up(200, IndexedWalletCatchUpSourceOrder::ArtifactsFirst)
        .await
        .expect("indexed catch-up task");

    assert_eq!(checkpoint, 200);
    assert!(
        progress_rx.borrow().is_none(),
        "artifact preparation must not overwrite progress after cached indexing begins"
    );
    context.cleanup();
    drop(artifact_source.server);
}

#[tokio::test]
async fn verified_stable_chunk_is_retained_when_later_chunk_fails() {
    let root_dir = temp_db_root("wallet-artifact-partial-retention");
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
    let (artifact_source, block) = checkpointed_wallet_artifact_source_controlled_with_requests(
        &scope,
        100,
        150,
        150,
        false,
        4,
        Some(125),
        true,
    );
    assert!(block.is_none());
    let stable_descriptor = artifact_source.chunk_descriptors[0].clone();
    let failed_tail_descriptor = artifact_source.chunk_descriptors[1].clone();
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
        Duration::from_secs(1),
    ));
    let chain = test_chain_config(&scope, rpcs, Some(artifact_source.config.clone()));
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );

    let preparation = IndexedWalletArtifactSession::prepare(
        &chain,
        100,
        150,
        public_data_plane.begin_public_scan_read(),
        &public_data_plane,
        None,
    )
    .await;
    assert!(
        preparation.is_err(),
        "missing tail chunk must fail preparation"
    );
    for _ in 0..100 {
        if public_data_plane
            .cached_wallet_scan_artifact_chunk(&stable_descriptor)
            .is_some()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        public_data_plane
            .cached_wallet_scan_artifact_chunk(&stable_descriptor)
            .is_some(),
        "verified stable chunk should survive a later fetch failure"
    );
    assert!(
        public_data_plane
            .cached_wallet_scan_artifact_chunk(&failed_tail_descriptor)
            .is_none()
    );

    public_data_plane.shutdown().await;
    drop(public_data_plane);
    drop(chain);
    drop(artifact_source.server);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn indexed_wallet_initial_squid_probe_keeps_pre_probe_read_scope() {
    let scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xbb; 20]),
    };
    let (squid, block) = GraphqlServer::spawn_with_blocked_response(
        vec![
            r#"{"data":{"squidStatus":{"height":"150"},"transactCommitments":[],"shieldCommitments":[],"nullifiers":[],"legacyEncryptedCommitments":[],"legacyGeneratedCommitments":[]}}"#,
            r#"{"data":{"transactCommitments":[],"shieldCommitments":[],"nullifiers":[]}}"#,
        ],
        0,
    );
    let context = IndexedCatchUpTestContext::new(&scope, squid.url.clone(), None, 100, 100).await;
    let catch_up = context.spawn_catch_up(150, IndexedWalletCatchUpSourceOrder::SquidFirst);

    wait_for_std_signal(block.request_started, "initial Squid probe started").await;
    context
        .public_data_plane
        .invalidate_public_scan_coverage_from(101)
        .await;
    block.release.send(()).expect("release initial Squid probe");
    let checkpoint = catch_up.await.expect("indexed catch-up task");

    assert_eq!(checkpoint, 100);
    assert_eq!(context.handle.last_scanned(), Some(100));
    assert!(matches!(
        context
            .public_data_plane
            .cached_public_scan_coverage(PublicScanRange::new(101, 150))
            .await,
        PublicCoverageAnswer::Missing { .. }
    ));
    let diagnostics = context.public_data_plane.diagnostics().await;
    assert!(diagnostics.events.iter().any(|event| {
        event.kind == PublicDataPlaneDiagnosticKind::CoverageRejected
            && event.source == Some(PublicScanSource::Squid)
            && event.range == Some(PublicScanRange::new(101, 150))
    }));

    context.cleanup();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn indexed_wallet_squid_transition_probe_keeps_pre_probe_read_scope() {
    let scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xbb; 20]),
    };
    let artifact_source = checkpointed_wallet_artifact_source(&scope, 100, 200, 150);
    // The startup race's Squid candidate sees Squid behind the wallet, so
    // the blocked response is the transition probe after the artifact pages.
    let (squid, block) = GraphqlServer::spawn_with_blocked_response(
        vec![
            r#"{"data":{"squidStatus":{"height":"100"},"transactCommitments":[],"shieldCommitments":[],"nullifiers":[],"legacyEncryptedCommitments":[],"legacyGeneratedCommitments":[]}}"#,
            r#"{"data":{"squidStatus":{"height":"200"},"transactCommitments":[],"shieldCommitments":[],"nullifiers":[],"legacyEncryptedCommitments":[],"legacyGeneratedCommitments":[]}}"#,
            r#"{"data":{"transactCommitments":[],"shieldCommitments":[],"nullifiers":[]}}"#,
        ],
        1,
    );
    let context = IndexedCatchUpTestContext::new(
        &scope,
        squid.url.clone(),
        Some(artifact_source.config.clone()),
        100,
        100,
    )
    .await;
    // The tail 151..=300 after the artifact checkpoint is longer than one
    // RPC page, so Squid is probed for it.
    let catch_up = context.spawn_catch_up(300, IndexedWalletCatchUpSourceOrder::ArtifactsFirst);

    wait_for_std_signal(block.request_started, "Squid transition probe started").await;
    assert_eq!(context.handle.last_scanned(), Some(150));
    context
        .public_data_plane
        .invalidate_public_scan_coverage_from(151)
        .await;
    block
        .release
        .send(())
        .expect("release Squid transition probe");
    let checkpoint = catch_up.await.expect("indexed catch-up task");

    assert_eq!(checkpoint, 150);
    assert_eq!(context.handle.last_scanned(), Some(150));
    assert!(matches!(
        context
            .public_data_plane
            .cached_public_scan_coverage(PublicScanRange::new(151, 200))
            .await,
        PublicCoverageAnswer::Missing { .. }
    ));
    let diagnostics = context.public_data_plane.diagnostics().await;
    assert!(diagnostics.events.iter().any(|event| {
        event.kind == PublicDataPlaneDiagnosticKind::CoverageRejected
            && event.source == Some(PublicScanSource::Squid)
            && event.range == Some(PublicScanRange::new(151, 200))
    }));

    context.cleanup();
    drop(artifact_source.server);
}

#[tokio::test]
async fn artifact_wallet_catch_up_sends_one_page_tail_to_rpc_without_squid() {
    let root_dir = temp_db_root("artifact-wallet-one-page-tail");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    // Artifacts reach block 150, one 50-block RPC page short of the target.
    let (artifact_source, manifest_block) =
        checkpointed_wallet_artifact_source_with_blocked_manifest(&scope, 100, 200, 150);
    // The startup race's Squid candidate sees Squid behind the wallet. The
    // second response would answer a tail probe.
    let squid = GraphqlServer::spawn_controlled(
        vec![squid_wallet_probe(100), squid_wallet_probe(200)],
        None,
    );
    let rpc = JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 200, |_, _, _| None));
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(
        &scope,
        Arc::clone(&rpcs),
        Some(artifact_source.config.clone()),
    );
    chain.sync.block_range = 50;
    chain.sync.indexed_wallet_block_range = 50;
    chain.finality_depth = 0;
    chain.sync.quick_sync_endpoint = Some(squid.url.clone());
    let public_data_plane = ChainPublicDataPlane::new(Arc::clone(&db), Arc::new(AtomicU64::new(0)));
    let (service, backfill_rx) = test_chain_service_with_backfill(
        Arc::clone(&db),
        chain,
        public_data_plane,
        test_proxy_poi_policy(),
    );
    service.safe_head_tx.send_replace(200);
    spawn_backfill_loop(
        Arc::clone(&service),
        backfill_rx,
        rpcs,
        None,
        service.safe_head_tx.subscribe(),
        service.cancel.clone(),
    );

    let mut cfg = test_wallet_config(&scope, squid.url.clone());
    cfg.cache_key = test_cache_key("artifact-one-page-tail");
    cfg.start_block = Some(101);
    cfg.sync_to_block = Some(200);
    db.put_wallet_meta(
        &cfg.cache_key,
        &WalletMeta {
            last_scanned_block: 100,
            updated_at: 1,
            last_scanned_block_hash: None,
        },
    )
    .expect("seed wallet cursor");
    let mut handle = service.register_wallet(cfg).await.expect("register wallet");
    // Artifacts win the race once the race's Squid probe has been answered.
    let mut squid_requests = Vec::new();
    yield_until("race Squid probe", || {
        squid_requests.extend(squid.requests.try_iter());
        !squid_requests.is_empty()
    })
    .await;
    manifest_block
        .release
        .send(())
        .expect("release artifact manifest");
    tokio::time::timeout(Duration::from_secs(5), handle.wait_until_ready())
        .await
        .expect("RPC backfill delivered the tail")
        .expect("wallet readiness succeeded");

    assert_eq!(handle.last_scanned(), Some(200));
    assert_eq!(
        get_logs_ranges(&rpc.drain_request_bodies()).first(),
        Some(&(151, 200)),
        "RPC backfill reads the tail after the artifact checkpoint"
    );
    // The TXID cache loop may query Squid once the wallet is ready, but it
    // never sends a wallet probe.
    squid_requests.extend(squid.requests.try_iter());
    assert_eq!(
        squid_requests
            .iter()
            .filter(|request| request.contains("query WalletProbe"))
            .count(),
        1,
        "no Squid probe for the one-page tail"
    );

    service.unregister_all_wallets().await;
    service.shutdown().await;
    drop(service);
    drop(artifact_source.server);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test(start_paused = true)]
async fn artifact_wallet_catch_up_stops_waiting_for_hung_squid_tail_probe_at_deadline() {
    let scope = test_scope();
    let (artifact_source, manifest_block) =
        checkpointed_wallet_artifact_source_with_blocked_manifest(&scope, 100, 200, 150);
    // The race's Squid candidate sees Squid behind the wallet, and the tail
    // probe after the artifact checkpoint gets no answer.
    let (squid, tail_probe) = GraphqlServer::spawn_owned_with_blocked_response(
        vec![squid_wallet_probe(100), squid_wallet_probe(300)],
        1,
    );
    let context = IndexedCatchUpTestContext::new(
        &scope,
        squid.url.clone(),
        Some(artifact_source.config.clone()),
        100,
        100,
    )
    .await;
    // The tail 151..=300 is longer than one 100-block RPC page.
    let catch_up = context.spawn_catch_up(300, IndexedWalletCatchUpSourceOrder::ArtifactsFirst);

    // Busy-yielding keeps the paused clock still until the tail probe is held.
    yield_until("race Squid probe", || squid.requests.try_recv().is_ok()).await;
    manifest_block
        .release
        .send(())
        .expect("release artifact manifest");
    yield_until("Squid tail probe", || {
        tail_probe.request_started.try_recv().is_ok()
    })
    .await;
    assert_eq!(context.handle.last_scanned(), Some(150));

    let deadline = super::logs::INDEXED_SQUID_STEP_DEADLINE;
    tokio::time::advance(deadline.saturating_sub(Duration::from_millis(1))).await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert!(
        !catch_up.is_finished(),
        "the probe is awaited until the deadline"
    );
    tokio::time::advance(Duration::from_millis(1)).await;
    yield_until("catch-up after the deadline", || catch_up.is_finished()).await;
    assert_eq!(
        catch_up.await.expect("indexed catch-up task"),
        150,
        "RPC backfill resumes from the artifact checkpoint"
    );

    tail_probe
        .release
        .send(())
        .expect("release Squid tail probe");
    context.cleanup();
    drop(artifact_source.server);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn indexed_wallet_squid_session_is_not_restamped_between_pages() {
    let scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xbb; 20]),
    };
    let (squid, block) = GraphqlServer::spawn_with_blocked_response(
        vec![
            r#"{"data":{"squidStatus":{"height":"200"},"transactCommitments":[],"shieldCommitments":[],"nullifiers":[],"legacyEncryptedCommitments":[],"legacyGeneratedCommitments":[]}}"#,
            r#"{"data":{"transactCommitments":[],"shieldCommitments":[],"nullifiers":[]}}"#,
            r#"{"data":{"transactCommitments":[],"shieldCommitments":[],"nullifiers":[]}}"#,
        ],
        2,
    );
    let context = IndexedCatchUpTestContext::new(&scope, squid.url.clone(), None, 100, 50).await;
    let catch_up = context.spawn_catch_up(200, IndexedWalletCatchUpSourceOrder::SquidFirst);

    wait_for_std_signal(block.request_started, "second Squid page request started").await;
    assert_eq!(context.handle.last_scanned(), Some(150));
    context
        .public_data_plane
        .invalidate_public_scan_coverage_from(151)
        .await;
    block.release.send(()).expect("release second Squid page");
    let checkpoint = catch_up.await.expect("indexed catch-up task");

    assert_eq!(checkpoint, 150);
    assert_eq!(context.handle.last_scanned(), Some(150));
    assert!(matches!(
        context
            .public_data_plane
            .cached_public_scan_coverage(PublicScanRange::new(151, 200))
            .await,
        PublicCoverageAnswer::Missing { .. }
    ));
    let diagnostics = context.public_data_plane.diagnostics().await;
    assert!(diagnostics.events.iter().any(|event| {
        event.kind == PublicDataPlaneDiagnosticKind::CoverageRejected
            && event.source == Some(PublicScanSource::Squid)
            && event.range == Some(PublicScanRange::new(151, 200))
    }));

    context.cleanup();
}

fn squid_wallet_probe(height: u64) -> String {
    format!(
        r#"{{"data":{{"squidStatus":{{"height":"{height}"}},"transactCommitments":[],"shieldCommitments":[],"nullifiers":[],"legacyEncryptedCommitments":[],"legacyGeneratedCommitments":[]}}}}"#
    )
}

/// A modern Squid wallet page holding one nullifier at `block`.
fn squid_wallet_page_with_nullifier(block: u64) -> String {
    format!(
        r#"{{"data":{{"transactCommitments":[],"shieldCommitments":[],"nullifiers":[{{"id":"0x{id}","transactionHash":"0x{tx}","blockNumber":"{block}","blockTimestamp":"{timestamp}","treeNumber":0,"nullifier":"0x{block:x}"}}]}}}}"#,
        id = "33".repeat(64),
        tx = "aa".repeat(32),
        timestamp = 1_700_000_000 + block,
    )
}

#[tokio::test]
async fn squid_wallet_candidate_holds_ordered_pages_within_row_budget() {
    use super::service::SquidWalletCandidateOutcome;

    let scope = test_scope();
    let squid = GraphqlServer::spawn_controlled(
        vec![
            squid_wallet_probe(200),
            squid_wallet_page_with_nullifier(120),
            squid_wallet_page_with_nullifier(170),
            squid_wallet_probe(200),
            squid_wallet_page_with_nullifier(120),
            squid_wallet_probe(100),
        ],
        None,
    );
    let context = IndexedCatchUpTestContext::new(&scope, squid.url.clone(), None, 100, 50).await;
    let service = &context.service;
    let cfg = &context.wallet_cfg;

    let SquidWalletCandidateOutcome::Ready(candidate) =
        service.squid_wallet_candidate(cfg, 101, 180, 2).await
    else {
        panic!("the Squid candidate holds every page through its target");
    };
    assert_eq!(candidate.target, 180);
    assert_eq!(candidate.rows, 2);
    let pages = candidate
        .pages
        .iter()
        .map(|(from_block, page)| (*from_block, page.checkpoint_block, page.nullifiers.len()))
        .collect::<Vec<_>>();
    assert_eq!(pages, vec![(101, 150, 1), (151, 180, 1)]);
    assert!(matches!(
        service.squid_wallet_candidate(cfg, 101, 180, 0).await,
        SquidWalletCandidateOutcome::OverBudget {
            target: 180,
            rows: 1
        }
    ));
    assert!(
        matches!(
            service.squid_wallet_candidate(cfg, 101, 180, 2).await,
            SquidWalletCandidateOutcome::NoResult
        ),
        "a Squid source behind the wallet yields no result"
    );

    let requests = squid.requests.try_iter().collect::<Vec<_>>();
    assert_eq!(
        requests.len(),
        6,
        "neither the over-budget nor the behind candidate requests another page"
    );
    assert!(requests[1].contains(r#""fromBlock":"101""#));
    assert!(requests[1].contains(r#""toBlock":"150""#));
    assert!(requests[2].contains(r#""fromBlock":"151""#));
    assert!(requests[2].contains(r#""toBlock":"180""#));
    assert!(requests[3].contains("query WalletProbe"));
    assert!(requests[5].contains("query WalletProbe"));

    context.cleanup();
}

#[tokio::test]
async fn stalled_artifact_manifest_lets_squid_win_wallet_catch_up() {
    let scope = test_scope();
    let (mut artifact_source, manifest_block) =
        checkpointed_wallet_artifact_source_with_blocked_manifest(&scope, 100, 250, 250);
    let gateway_port = artifact_source.server.url.port().expect("gateway port");
    artifact_source.config.manifest_source = IndexedArtifactManifestSource::Url(
        credential_url(gateway_port)
            .join("/manifest.json")
            .expect("manifest url"),
    );
    artifact_source.config.gateway_urls = vec![credential_url(gateway_port)];
    // The first Squid page waits until the manifest request is in flight.
    let (squid, squid_page_block) = GraphqlServer::spawn_owned_with_blocked_response(
        vec![
            squid_wallet_probe(200),
            squid_wallet_page_with_nullifier(120),
            squid_wallet_page_with_nullifier(170),
        ],
        1,
    );
    let squid_port = squid.url.port().expect("Squid port");
    let events = CapturedEvents::default();
    let guard = events.capture();
    let context = IndexedCatchUpTestContext::new(
        &scope,
        credential_url(squid_port),
        Some(artifact_source.config.clone()),
        100,
        50,
    )
    .await;

    let catch_up = context.spawn_catch_up(250, IndexedWalletCatchUpSourceOrder::ArtifactsFirst);
    wait_for_std_signal(
        manifest_block.request_started,
        "artifact manifest request started",
    )
    .await;
    squid_page_block
        .release
        .send(())
        .expect("release first Squid page");
    let checkpoint = catch_up.await.expect("indexed catch-up task");
    manifest_block
        .release
        .send(())
        .expect("release artifact manifest");
    // Give a request from the dropped artifact candidate time to arrive.
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(guard);

    assert_eq!(checkpoint, 200, "Squid commits through its indexed height");
    assert_eq!(context.handle.last_scanned(), Some(200));
    assert!(matches!(
        context
            .public_data_plane
            .cached_public_scan_coverage(PublicScanRange::new(101, 200))
            .await,
        PublicCoverageAnswer::CoveredWithRows {
            range,
            source: PublicScanSource::Squid,
            ..
        } if range == PublicScanRange::new(101, 200)
    ));
    assert!(
        matches!(
            context
                .public_data_plane
                .cached_public_scan_coverage(PublicScanRange::new(201, 250))
                .await,
            PublicCoverageAnswer::Missing { .. }
        ),
        "blocks past the Squid target are left for the RPC tail"
    );
    assert_eq!(
        squid.requests.try_iter().count(),
        3,
        "held pages are committed without being fetched again"
    );
    assert_eq!(
        artifact_source.server.request_count(),
        1,
        "the dropped artifact candidate issues no request after the manifest"
    );

    let started = events.find("wallet catch-up race started");
    for (field, value) in [
        ("from_block", "101"),
        ("safe_head", "250"),
        ("gap_blocks", "150"),
        ("candidates", "indexed_artifacts,squid"),
    ] {
        assert_eq!(
            started.get(field).map(String::as_str),
            Some(value),
            "{field}"
        );
    }
    let candidate_end = |source: &str| {
        events
            .events()
            .into_iter()
            .filter(|event| {
                event
                    .get("message")
                    .is_some_and(|message| message == "wallet catch-up race candidate finished")
                    && event.get("source").is_some_and(|value| value == source)
            })
            .collect::<Vec<_>>()
    };
    let squid_end = candidate_end("squid");
    assert_eq!(squid_end.len(), 1);
    for (field, value) in [("outcome", "ready"), ("target", "200"), ("squid_rows", "2")] {
        assert_eq!(
            squid_end[0].get(field).map(String::as_str),
            Some(value),
            "{field}"
        );
    }
    assert!(squid_end[0].contains_key("elapsed_ms"));
    let artifact_end = candidate_end("indexed_artifacts");
    assert_eq!(artifact_end.len(), 1);
    assert_eq!(
        artifact_end[0].get("outcome").map(String::as_str),
        Some("cancelled")
    );
    let winner = events.find("wallet catch-up race won");
    assert_eq!(winner.get("source").map(String::as_str), Some("squid"));
    assert_eq!(winner.get("target").map(String::as_str), Some("200"));
    assert!(winner.contains_key("elapsed_ms"));
    let endpoints = [squid_port, gateway_port].map(|port| format!("127.0.0.1:{port}"));
    for event in events.events() {
        for value in event.values() {
            assert!(
                ["secret", "user:", "key-abc"]
                    .into_iter()
                    .chain(endpoints.iter().map(String::as_str))
                    .all(|needle| !value.contains(needle)),
                "log value {value:?} exposes an endpoint"
            );
        }
    }

    context.cleanup();
}

#[tokio::test]
async fn wallet_catch_up_race_without_a_source_falls_back_to_rpc() {
    let scope = test_scope();
    // Artifacts end at block 50, below the wallet's next block, and the
    // Squid probe fails.
    let artifact_source = checkpointed_wallet_artifact_source(&scope, 1, 50, 50);
    let squid = GraphqlServer::spawn(vec![
        r#"{"errors":[{"message":"indexed source unavailable"}]}"#,
    ]);
    let context = IndexedCatchUpTestContext::new(
        &scope,
        squid.url.clone(),
        Some(artifact_source.config.clone()),
        100,
        50,
    )
    .await;

    let checkpoint = context
        .spawn_catch_up(200, IndexedWalletCatchUpSourceOrder::ArtifactsFirst)
        .await
        .expect("indexed catch-up task");

    assert_eq!(checkpoint, 100);
    assert_eq!(context.handle.last_scanned(), Some(100));
    assert!(matches!(
        context
            .public_data_plane
            .cached_public_scan_coverage(PublicScanRange::new(101, 200))
            .await,
        PublicCoverageAnswer::Missing { .. }
    ));
    assert_eq!(
        squid.requests.try_iter().count(),
        1,
        "only the race probe reaches Squid"
    );
    let diagnostics = context.public_data_plane.diagnostics().await;
    assert!(diagnostics.events.iter().any(|event| {
        event.kind == PublicDataPlaneDiagnosticKind::SourceFallback
            && event.source == Some(PublicScanSource::Rpc)
            && event.range == Some(PublicScanRange::new(101, 200))
    }));

    context.cleanup();
    drop(artifact_source.server);
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
            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: backfill_tx.clone(),
            public_data_plane: public_data_plane.clone(),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
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
        .apply_cached_public_scan_coverage(
            &cfg,
            0,
            100,
            200,
            &handle,
            &backfill_tx,
            crate::types::WalletSchedulableProgress {
                last_scanned: 100,
                reset_generation: 0,
            },
        )
        .await;

    assert_eq!(outcome.checkpoint, 150);
    assert!(!outcome.finished);
    assert_eq!(handle.last_scanned(), Some(150));
    assert_eq!(handle.readiness(), WalletReadiness::Syncing);

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
    let artifact_source = checkpointed_wallet_artifact_source(&scope, 100, 150, 150);
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
            .cached_wallet_scan_apply(range.from_block, range.to_block)
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
        checkpointed_wallet_artifact_source_with_blocked_manifest(&scope, 100, 150, 150);
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
                .expect("artifact manifest fetch started");
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
        rpc_block(150, 1_700_000_150, 0x15),
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, Arc::clone(&rpcs), None);
    chain.sync.block_range = 100;
    chain.sync.indexed_wallet_block_range = 1_000;
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
    let _block_hash_request = rpc
        .requests
        .recv_timeout(Duration::from_secs(1))
        .expect("block hash request");
    let replay = service
        .public_data_plane()
        .public_scan_rows(PublicScanRange::new(100, 150))
        .await
        .expect("replay cached RPC public scan rows");
    assert!(matches!(
        replay,
        PublicScanRowsAnswer::CompleteCoverage {
            range: PublicScanRange {
                from_block: 100,
                to_block: 150,
            },
            row_count: 0,
            ..
        }
    ));
    assert!(
        rpc.requests.try_recv().is_err(),
        "ordinary public scan RPC rows must remain reusable",
    );

    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn public_scan_rows_rpc_fallback_does_not_reuse_missing_endpoint_coverage() {
    let root_dir = temp_db_root("public-scan-rpc-missing-endpoint");
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
        serde_json::json!("0x96"),
        serde_json::json!([]),
        rpc_block(150, 1_700_000_150, 0x15),
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    chain.sync.block_range = 100;
    chain.sync.indexed_wallet_block_range = 1_000;
    chain.finality_depth = 0;
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane.clone());
    let range = PublicScanRange::new(100, 500);

    let error = service
        .public_data_plane()
        .public_scan_rows(range)
        .await
        .expect_err("missing RPC endpoint must reject the public scan");
    assert!(matches!(error, ChainError::BackfillRequestFailed));
    assert!(matches!(
        public_data_plane
            .cached_public_scan_coverage(PublicScanRange::new(100, 150))
            .await,
        PublicCoverageAnswer::Missing { .. }
    ));

    let retry = service
        .public_data_plane()
        .public_scan_rows(range)
        .await
        .expect("later scan must query RPC rather than reuse rejected coverage");
    assert!(matches!(
        retry,
        PublicScanRowsAnswer::Rows(PublicScanRows {
            range: PublicScanRange {
                from_block: 100,
                to_block: 150,
            },
            ..
        })
    ));

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
        rpc_block(150, 1_700_000_150, 0x15),
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, Arc::clone(&rpcs), None);
    chain.sync.quick_sync_endpoint = Some(squid.url.clone());
    chain.sync.block_range = 100;
    chain.sync.indexed_wallet_block_range = 100;
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
        rpc_block(100, 1_700_000_100, 0x10),
        rpc_block(150, 1_700_000_150, 0x15),
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, Arc::clone(&rpcs), None);
    chain.sync.quick_sync_endpoint = Some(squid.url.clone());
    chain.sync.archive_until_block = 100;
    chain.sync.block_range = 100;
    chain.sync.indexed_wallet_block_range = 100;
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
async fn public_scan_rows_rejects_missing_archive_boundary_without_recording_coverage() {
    let root_dir = temp_db_root("public-scan-missing-archive-boundary");
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
        serde_json::json!([]),
        serde_json::Value::Null,
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    chain.sync.archive_until_block = 100;
    chain.sync.block_range = 100;
    chain.sync.indexed_wallet_block_range = 100;
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane.clone());

    let error = service
        .public_data_plane()
        .public_scan_rows(PublicScanRange::new(100, 150))
        .await
        .expect_err("missing archive boundary must reject the public scan");
    assert!(matches!(error, ChainError::BackfillRequestFailed));
    assert!(matches!(
        public_data_plane
            .cached_public_scan_coverage(PublicScanRange::new(100, 150))
            .await,
        PublicCoverageAnswer::Missing { .. }
    ));

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
    let live_log_task = Arc::new(std::sync::Mutex::new(Some(task)));
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
    assert!(
        live_log_task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_none()
    );
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
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
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
                WalletScanApply::rows_from_log_batch(101, 105, &batch, PublicScanSource::Rpc)
                    .expect("normalize empty log payload"),
            ],
            Some(105),
            crate::types::WalletSchedulableProgress {
                last_scanned: 100,
                reset_generation: 0,
            },
            &sender_clone,
            &handle,
        )
        .await
    });

    let Some(BackfillEvent::Start {
        target_block,
        token,
        response,
    }) = receiver.recv().await
    else {
        panic!("startup target should accept the token first");
    };
    assert_eq!(target_block, 105);
    assert_eq!(token.reset_generation(), 0);
    response
        .send(WalletBackfillStartResult::Accepted {
            committed_to: 100,
            target_block,
            grant: WalletBackfillGrant::from_token(token, sender.clone()),
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
    let Some(BackfillEvent::Finish {
        target_block,
        token: finish_token,
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
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
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
                WalletScanApply::rows_from_log_batch(101, 105, &batch, PublicScanSource::Rpc)
                    .expect("normalize empty log payload"),
            ],
            Some(105),
            crate::types::WalletSchedulableProgress {
                last_scanned: 0,
                reset_generation: 0,
            },
            &sender_clone,
            &handle,
        )
        .await
    });

    let Some(BackfillEvent::Start {
        target_block,
        token,
        response,
    }) = receiver.recv().await
    else {
        panic!("startup target should be sent");
    };
    assert_eq!(target_block, 105);
    response
        .send(WalletBackfillStartResult::Accepted {
            committed_to: 105,
            target_block,
            grant: WalletBackfillGrant::from_token(token, sender.clone()),
        })
        .expect("send accepted start result");
    let Some(BackfillEvent::Apply { response, .. }) = receiver.recv().await else {
        panic!("startup apply should be sent");
    };
    response
        .send(WalletBackfillApplyResult::AlreadyCovered { committed_to: 105 })
        .expect("send covered apply result");
    let Some(BackfillEvent::Finish { response, .. }) = receiver.recv().await else {
        panic!("startup finish should be sent");
    };
    response
        .send(WalletBackfillFinishResult::Ready { committed_to: 105 })
        .expect("send ready finish result");
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
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
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
                WalletScanApply::rows_from_log_batch(101, 105, &batch, PublicScanSource::Rpc)
                    .expect("normalize empty log payload"),
            ],
            Some(105),
            crate::types::WalletSchedulableProgress {
                last_scanned: 0,
                reset_generation: 0,
            },
            &sender_clone,
            &handle,
        )
        .await
    });

    let Some(BackfillEvent::Start {
        target_block,
        token,
        response,
    }) = receiver.recv().await
    else {
        panic!("startup target should be sent");
    };
    response
        .send(WalletBackfillStartResult::Accepted {
            committed_to: 100,
            target_block,
            grant: WalletBackfillGrant::from_token(token, sender.clone()),
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
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
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
                WalletScanApply::rows_from_log_batch(101, 105, &batch, PublicScanSource::Rpc)
                    .expect("normalize empty log payload"),
            ],
            None,
            crate::types::WalletSchedulableProgress {
                last_scanned: 0,
                reset_generation: 0,
            },
            &sender_clone,
            &handle,
        )
        .await
    });

    let Some(BackfillEvent::Start {
        target_block,
        token,
        response,
    }) = receiver.recv().await
    else {
        panic!("startup target should be sent");
    };
    response
        .send(WalletBackfillStartResult::Accepted {
            committed_to: 100,
            target_block,
            grant: WalletBackfillGrant::from_token(token, sender.clone()),
        })
        .expect("send target result");

    let Some(BackfillEvent::Apply { response, .. }) = receiver.recv().await else {
        panic!("startup apply should be sent");
    };
    response
        .send(WalletBackfillApplyResult::Committed { committed_to: 105 })
        .expect("send apply success");

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
        deployment: broadcaster_core::deployment::RailgunDeployment {
            chain_id: scope.chain_id,
            contract: scope.railgun_contract,
            deployment_block: 0,
            v2_start_block: 0,
            legacy_shield_block: 0,
            relay_adapt_contract: Address::ZERO,
            relay_adapt_7702_contract: Address::ZERO,
        },
        sync: crate::RailgunSyncOptions {
            archive_until_block: 0,
            block_range: 100,
            indexed_wallet_block_range: 100,
            poll_interval: Duration::from_millis(1),
            quick_sync_endpoint: None,
            indexed_artifact_source,
            anchor_interval: 1000,
            anchor_retention: 5,
        },
        rpcs,
        archive_rpc_url: None,
        block_time: Duration::from_secs(12),
        finality_depth: 0,
        http_client: reqwest::Client::new(),
        progress_tx: None,
    }
}

struct IndexedCatchUpTestContext {
    root_dir: PathBuf,
    db: Arc<DbStore>,
    service: Arc<ChainService>,
    public_data_plane: ChainPublicDataPlane,
    wallet_cfg: WalletConfig,
    handle: WalletHandle,
    wallet_backfill_tx: mpsc::Sender<BackfillEvent>,
    cancel: CancellationToken,
    last_scanned: u64,
}

async fn wait_for_std_signal(receiver: std_mpsc::Receiver<()>, message: &'static str) {
    tokio::time::timeout(
        Duration::from_secs(2),
        tokio::task::spawn_blocking(move || receiver.recv().expect(message)),
    )
    .await
    .expect(message)
    .expect("signal wait task completed");
}

impl IndexedCatchUpTestContext {
    async fn new(
        scope: &ChainScope,
        quick_sync_endpoint: Url,
        indexed_artifact_source: Option<IndexedArtifactSourceConfig>,
        last_scanned: u64,
        indexed_wallet_block_range: u64,
    ) -> Self {
        let root_dir = temp_db_root("indexed-wallet-read-session");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let rpcs = Arc::new(QueryRpcPool::new(
            vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
            Duration::from_secs(1),
        ));
        let mut chain = test_chain_config(scope, Arc::clone(&rpcs), indexed_artifact_source);
        chain.sync.quick_sync_endpoint = Some(quick_sync_endpoint.clone());
        chain.sync.indexed_wallet_block_range = indexed_wallet_block_range;
        let public_data_plane = ChainPublicDataPlane::new(
            Arc::clone(&db),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        );
        let service = test_chain_service(Arc::clone(&db), chain, public_data_plane.clone());
        let (wallet_backfill_tx, wallet_backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(1);
        let cancel = CancellationToken::new();
        let wallet_cfg = test_wallet_config(scope, quick_sync_endpoint);
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                http_client: None,
                indexed_artifact_source: None,
                poi_runtime: test_wallet_poi_runtime(),
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: wallet_backfill_tx.clone(),
                public_data_plane: public_data_plane.clone(),
                poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
            },
            wallet_cfg.clone(),
            1,
            service.live_log_tx.subscribe(),
            wallet_backfill_rx,
            cancel.clone(),
            Vec::new(),
            last_scanned,
        )
        .await
        .expect("spawn wallet worker");
        Self {
            root_dir,
            db,
            service,
            public_data_plane,
            wallet_cfg,
            handle,
            wallet_backfill_tx,
            cancel,
            last_scanned,
        }
    }

    fn spawn_catch_up(
        &self,
        safe_head: u64,
        source_order: IndexedWalletCatchUpSourceOrder,
    ) -> tokio::task::JoinHandle<u64> {
        let service = Arc::clone(&self.service);
        let cfg = self.wallet_cfg.clone();
        let handle = self.handle.clone();
        let cancel = self.cancel.clone();
        let sender = self.wallet_backfill_tx.clone();
        let last_scanned = self.last_scanned;
        tokio::spawn(async move {
            service
                .indexed_wallet_catch_up(
                    &cfg,
                    0,
                    last_scanned,
                    safe_head,
                    &handle,
                    &cancel,
                    source_order,
                    true,
                    (
                        &sender,
                        crate::types::WalletSchedulableProgress {
                            last_scanned,
                            reset_generation: 0,
                        },
                    ),
                )
                .await
        })
    }

    fn cleanup(self) {
        let Self {
            root_dir,
            db,
            service,
            public_data_plane,
            handle,
            cancel,
            ..
        } = self;
        cancel.cancel();
        drop(handle);
        drop(service);
        drop(public_data_plane);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }
}

#[tokio::test]
async fn indexed_status_guard_drop_retires_claim_and_clears_status() {
    let scope = test_scope();
    let context = IndexedCatchUpTestContext::new(
        &scope,
        Url::parse("http://127.0.0.1:1").expect("quick sync URL"),
        None,
        100,
        10,
    )
    .await;
    let token = context.handle.mint_sync_token(0);
    let driver = match send_wallet_target("test", &context.wallet_backfill_tx, 100, token).await {
        WalletBackfillStartResult::Accepted { grant, .. } => grant.activate(),
        result @ WalletBackfillStartResult::Rejected { .. } => {
            panic!("initial backfill start rejected: {result:?}")
        }
    };
    assert_eq!(
        driver.finish("test", 100).await,
        WalletBackfillFinishResult::Ready { committed_to: 100 }
    );
    let guard = WalletIndexedCatchUpStatusGuard::claim(&context.handle, true)
        .await
        .expect("indexed status guard claim");
    guard.set(WalletIndexedCatchUpSource::Squid, 101, 200);
    tokio::time::timeout(Duration::from_secs(1), async {
        while context.handle.indexed_catch_up_rx.borrow().is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("guard status published");

    drop(guard);

    tokio::time::timeout(Duration::from_secs(1), async {
        while context.handle.indexed_catch_up_rx.borrow().is_some()
            || context.handle.readiness() != WalletReadiness::Ready
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("guard drop cleared status and restored readiness");
    context.cleanup();
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
    test_chain_service_with_backfill(db, chain, public_data_plane, poi_policy).0
}

fn test_chain_service_with_backfill(
    db: Arc<DbStore>,
    chain: ChainConfig,
    public_data_plane: ChainPublicDataPlane,
    poi_policy: GlobalPoiPolicy,
) -> (Arc<ChainService>, mpsc::Receiver<BackfillRequest>) {
    test_chain_service_with_poi_submitter(
        db,
        chain,
        public_data_plane,
        poi_policy,
        ChainPoiSubmitterHandle::detached_for_test(),
    )
}

fn test_chain_service_with_poi_submitter(
    db: Arc<DbStore>,
    chain: ChainConfig,
    public_data_plane: ChainPublicDataPlane,
    poi_policy: GlobalPoiPolicy,
    poi_submitter: ChainPoiSubmitterHandle,
) -> (Arc<ChainService>, mpsc::Receiver<BackfillRequest>) {
    let (head_tx, _head_rx) = watch::channel(0);
    let (safe_head_tx, _safe_head_rx) = watch::channel(0);
    let (forest_last_tx, _forest_last_rx) = watch::channel(0);
    let (live_log_tx, _live_log_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    (
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
            wallet: RwLock::new(None),
            wallet_registration_gate: Mutex::new(()),
            cancel: CancellationToken::new(),
            live_log_task: std::sync::Mutex::new(None),
            poi_submitter,
            poi_submitter_task: std::sync::Mutex::new(None),
            anchor_last: std::sync::atomic::AtomicU64::new(0),
            txid_public_cache_started: std::sync::atomic::AtomicBool::new(false),
            wallet_actor_next: std::sync::atomic::AtomicU64::new(1),
            wallet_reset_intent_next: std::sync::atomic::AtomicU64::new(1),
            public_data_plane,
        }),
        backfill_rx,
    )
}

async fn install_test_backfill_actor(
    service: &Arc<ChainService>,
    scope: &ChainScope,
    rpc_url: Url,
    cache_key: &str,
) -> WalletHandle {
    let mut cfg = test_wallet_config(scope, rpc_url);
    cfg.cache_key = test_cache_key(cache_key);
    cfg.sync_to_block = Some(0);
    cfg.use_indexed_wallet_catch_up = false;
    service
        .register_wallet(cfg)
        .await
        .expect("register matching backfill actor")
}

#[tokio::test]
async fn merkle_artifact_catch_up_targets_indexed_height_past_last_commitment() {
    let scope = test_scope();
    let indexed_through_hash = [0x44; 32];
    let leaves = [(0, U256::from(11)), (1, U256::from(12))];
    // Commitments are indexed through block 120, but the newest commitment is at block 110.
    let artifact_source =
        commitment_artifact_source(&scope, 120, indexed_through_hash, 110, &leaves);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
        Duration::from_secs(1),
    ));
    let chain = test_chain_config(&scope, rpcs, Some(artifact_source.config.clone()));

    let mut forest = MerkleForest::new();
    let catch_up = run_merkle_artifact_catch_up_into(&mut forest, &chain, 100, 150, None)
        .await
        .expect("merkle artifact catch-up")
        .expect("commitment artifacts are complete through the indexed height");

    assert_eq!(catch_up.target_block, 120);
    assert_eq!(catch_up.target_block_hash, indexed_through_hash);
    let mut expected = MerkleForest::new();
    for (tree_position, hash) in leaves {
        expected
            .insert_leaf(MerkleTreeUpdate {
                tree_number: 0,
                tree_position,
                hash,
            })
            .expect("insert expected leaf");
    }
    expected.compute_roots();
    assert_eq!(forest.roots(), expected.roots());
}

struct TestArtifactSource {
    config: IndexedArtifactSourceConfig,
    server: PathServer,
    chunk_descriptors: Vec<IndexedArtifactDescriptor>,
}

struct BlockedWalletOptionalMaintenanceFixture {
    root_dir: PathBuf,
    db: Arc<DbStore>,
    public_data_plane: ChainPublicDataPlane,
    chain: ChainConfig,
    artifact_source: TestArtifactSource,
    optional_block: PathServerBlockControl,
    optional_descriptor: IndexedArtifactDescriptor,
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
    requests: Arc<AtomicU64>,
    paths: Arc<std::sync::Mutex<Vec<String>>>,
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
        let requests = Arc::new(AtomicU64::new(0));
        let paths = Arc::new(std::sync::Mutex::new(Vec::new()));
        std::thread::spawn({
            let routes = Arc::clone(&routes);
            let requests = Arc::clone(&requests);
            let paths = Arc::clone(&paths);
            move || {
                for _ in 0..request_count {
                    let (stream, _) = listener.accept().expect("accept path request");
                    requests.fetch_add(1, Ordering::AcqRel);
                    let routes = Arc::clone(&routes);
                    let block = block.clone();
                    let paths = Arc::clone(&paths);
                    std::thread::spawn(move || {
                        handle_path_request(stream, &routes, block.as_deref(), &paths);
                    });
                }
            }
        });
        Self {
            url,
            requests,
            paths,
        }
    }

    fn request_count(&self) -> u64 {
        self.requests.load(Ordering::Acquire)
    }

    /// Paths of the requests read so far, in arrival order.
    fn requested_paths(&self) -> Vec<String> {
        self.paths.lock().expect("path server paths lock").clone()
    }
}

struct GraphqlServer {
    url: Url,
    requests: std_mpsc::Receiver<String>,
}

struct GraphqlServerBlock {
    request_started: std_mpsc::Sender<()>,
    release: std::sync::Mutex<std_mpsc::Receiver<()>>,
}

struct JsonRpcServer {
    url: Url,
    requests: std_mpsc::Receiver<String>,
}

impl GraphqlServer {
    fn spawn(responses: Vec<&'static str>) -> Self {
        Self::spawn_controlled(responses.into_iter().map(str::to_owned).collect(), None)
    }

    fn spawn_with_blocked_response(
        responses: Vec<&'static str>,
        blocked_response: usize,
    ) -> (Self, PathServerBlockControl) {
        Self::spawn_owned_with_blocked_response(
            responses.into_iter().map(str::to_owned).collect(),
            blocked_response,
        )
    }

    fn spawn_owned_with_blocked_response(
        responses: Vec<String>,
        blocked_response: usize,
    ) -> (Self, PathServerBlockControl) {
        let (request_started_tx, request_started) = std_mpsc::channel();
        let (release, release_rx) = std_mpsc::channel();
        let block = Arc::new(GraphqlServerBlock {
            request_started: request_started_tx,
            release: std::sync::Mutex::new(release_rx),
        });
        let server = Self::spawn_controlled(responses, Some((blocked_response, block)));
        (
            server,
            PathServerBlockControl {
                request_started,
                release,
            },
        )
    }

    fn spawn_controlled(
        responses: Vec<String>,
        blocked_response: Option<(usize, Arc<GraphqlServerBlock>)>,
    ) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind graphql server");
        let url = Url::parse(&format!(
            "http://{}",
            listener.local_addr().expect("local addr")
        ))
        .expect("graphql server url");
        let (request_tx, requests) = std_mpsc::channel();
        std::thread::spawn(move || {
            for (response_index, response) in responses.into_iter().enumerate() {
                let (stream, _) = listener.accept().expect("accept graphql request");
                let block = blocked_response.as_ref().and_then(|(index, block)| {
                    (*index == response_index).then(|| Arc::clone(block))
                });
                handle_graphql_request(stream, &response, &request_tx, block);
            }
        });
        Self { url, requests }
    }
}

impl JsonRpcServer {
    fn spawn(responses: Vec<serde_json::Value>) -> Self {
        Self::spawn_controlled(responses, None)
    }

    fn spawn_with_blocked_response(
        responses: Vec<serde_json::Value>,
        blocked_response: usize,
    ) -> (Self, PathServerBlockControl) {
        let (request_started_tx, request_started) = std_mpsc::channel();
        let (release, release_rx) = std_mpsc::channel();
        let block = Arc::new(GraphqlServerBlock {
            request_started: request_started_tx,
            release: std::sync::Mutex::new(release_rx),
        });
        let server = Self::spawn_controlled(responses, Some((blocked_response, block)));
        (
            server,
            PathServerBlockControl {
                request_started,
                release,
            },
        )
    }

    fn spawn_controlled(
        responses: Vec<serde_json::Value>,
        blocked_response: Option<(usize, Arc<GraphqlServerBlock>)>,
    ) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind json-rpc server");
        let url = Url::parse(&format!(
            "http://{}",
            listener.local_addr().expect("local addr")
        ))
        .expect("json-rpc server url");
        let (request_tx, requests) = std_mpsc::channel();
        std::thread::spawn(move || {
            for (response_index, response) in responses.into_iter().enumerate() {
                let (stream, _) = listener.accept().expect("accept json-rpc request");
                let block = blocked_response.as_ref().and_then(|(index, block)| {
                    (*index == response_index).then(|| Arc::clone(block))
                });
                handle_json_rpc_request(stream, &response, &request_tx, block);
            }
        });
        Self { url, requests }
    }
}

fn rpc_nullifiers_log(contract: Address, block_number: u64) -> serde_json::Value {
    rpc_nullifiers_log_with_value(contract, block_number, U256::from(7))
}

fn rpc_nullifiers_log_with_value(
    contract: Address,
    block_number: u64,
    nullifier: U256,
) -> serde_json::Value {
    let encoded = Nullifiers {
        treeNumber: U256::from(1),
        nullifier: vec![nullifier],
    }
    .encode_log_data();
    let topics = encoded
        .topics()
        .iter()
        .map(|topic| format!("{topic:#x}"))
        .collect::<Vec<_>>();
    serde_json::json!({
        "address": format!("{contract:#x}"),
        "topics": topics,
        "data": format!("0x{}", hex::encode(encoded.data)),
        "blockHash": format!("{:#x}", FixedBytes::<32>::from([0x11; 32])),
        "blockNumber": format!("{block_number:#x}"),
        "transactionHash": format!("{:#x}", FixedBytes::<32>::from([0x33; 32])),
        "transactionIndex": "0x0",
        "logIndex": "0x0",
        "removed": false,
    })
}

fn indexed_wallet_nullifier_page(block_number: u64, nullifier: U256) -> String {
    serde_json::json!({
        "data": {
            "transactCommitments": [],
            "shieldCommitments": [],
            "nullifiers": [{
                "id": format!("0x{}", "33".repeat(64)),
                "transactionHash": format!("0x{}", "aa".repeat(32)),
                "blockNumber": block_number.to_string(),
                "blockTimestamp": block_number.saturating_add(1_700_000_000).to_string(),
                "treeNumber": 1,
                "nullifier": format!("{nullifier:#x}"),
            }],
        }
    })
    .to_string()
}

fn rpc_block(block_number: u64, timestamp: u64, hash_byte: u8) -> serde_json::Value {
    let zero_hash = format!("{:#x}", FixedBytes::<32>::ZERO);
    serde_json::json!({
        "hash": format!("{:#x}", FixedBytes::<32>::from([hash_byte; 32])),
        "parentHash": zero_hash,
        "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        "miner": format!("{:#x}", Address::ZERO),
        "stateRoot": zero_hash,
        "transactionsRoot": zero_hash,
        "receiptsRoot": zero_hash,
        "logsBloom": format!("0x{}", "00".repeat(256)),
        "difficulty": "0x0",
        "number": format!("{block_number:#x}"),
        "gasLimit": "0x0",
        "gasUsed": "0x0",
        "timestamp": format!("{timestamp:#x}"),
        "extraData": "0x",
        "mixHash": zero_hash,
        "nonce": "0x0000000000000000",
        "transactions": [],
        "uncles": [],
    })
}

fn handle_path_request(
    mut stream: std::net::TcpStream,
    routes: &HashMap<String, Vec<u8>>,
    block: Option<&PathServerBlock>,
    paths: &std::sync::Mutex<Vec<String>>,
) {
    let path = read_request_path(&mut stream);
    paths
        .lock()
        .expect("path server paths lock")
        .push(path.clone());
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
    response: &str,
    requests: &std_mpsc::Sender<String>,
    block: Option<Arc<GraphqlServerBlock>>,
) {
    let request = read_http_request(&mut stream);
    requests.send(request).expect("record graphql request");
    if let Some(block) = block {
        block
            .request_started
            .send(())
            .expect("signal blocked GraphQL response");
        block
            .release
            .lock()
            .expect("blocked GraphQL release lock")
            .recv()
            .expect("release blocked GraphQL response");
    }
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.len()
    );
    let _ = stream.write_all(headers.as_bytes());
    let _ = stream.write_all(response.as_bytes());
}

fn handle_json_rpc_request(
    mut stream: std::net::TcpStream,
    response: &serde_json::Value,
    requests: &std_mpsc::Sender<String>,
    block: Option<Arc<GraphqlServerBlock>>,
) {
    let request = read_http_request(&mut stream);
    requests
        .send(request.clone())
        .expect("record json-rpc request");
    if let Some(block) = block {
        block
            .request_started
            .send(())
            .expect("signal blocked JSON-RPC response");
        block
            .release
            .lock()
            .expect("blocked JSON-RPC release lock")
            .recv()
            .expect("release blocked JSON-RPC response");
    }
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
    let result = stream
        .write_all(headers.as_bytes())
        .and_then(|()| stream.write_all(body.as_bytes()));
    if let Err(error) = result {
        // Hedge losers may close their connection before a blocked fixture response is released.
        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::NotConnected
            ),
            "write JSON-RPC response: {error}"
        );
    }
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
    scope: &ChainScope,
    start: u64,
    end: u64,
    checkpoint_block: u64,
) -> TestArtifactSource {
    checkpointed_wallet_artifact_source_controlled(scope, start, end, checkpoint_block, false).0
}

fn blocked_wallet_optional_maintenance_fixture(
    name: &str,
) -> BlockedWalletOptionalMaintenanceFixture {
    let root_dir = temp_db_root(name);
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
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let optional_bytes = empty_wallet_scan_chunk_bytes(&scope, 100, 109);
    let optional_cid = raw_cid(&optional_bytes);
    let optional_descriptor = wallet_artifact_descriptor(
        scope.clone(),
        100,
        109,
        0,
        optional_cid,
        &optional_bytes,
        DatasetDescriptorMetadata {
            catalog_generation: Some(1),
            checkpoint_block: Some(109),
            ..Default::default()
        },
        CompressionAlgorithm::None,
    );
    let required_bytes = empty_wallet_scan_chunk_bytes(&scope, 110, 120);
    let required_cid = raw_cid(&required_bytes);
    let required_descriptor = wallet_artifact_descriptor(
        scope.clone(),
        110,
        120,
        0,
        required_cid,
        &required_bytes,
        DatasetDescriptorMetadata {
            catalog_generation: Some(1),
            checkpoint_block: Some(120),
            ..Default::default()
        },
        CompressionAlgorithm::None,
    );
    let catalog = IndexedArtifactCatalog {
        format_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
        dataset_kind: IndexedDatasetKind::WalletScan,
        scope: scope.clone(),
        chunks: vec![optional_descriptor.clone(), required_descriptor],
    };
    let catalog_bytes = serde_json::to_vec(&catalog).expect("catalog json");
    let catalog_cid = raw_cid(&catalog_bytes);
    let catalog_descriptor = wallet_artifact_descriptor(
        scope.clone(),
        100,
        120,
        0,
        catalog_cid,
        &catalog_bytes,
        DatasetDescriptorMetadata {
            catalog_generation: Some(1),
            checkpoint_block: Some(120),
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
                block_number: 120,
                block_hash: FixedBytes::from([0x22; 32]),
            }],
            catalogs: vec![catalog_descriptor],
        }],
    );
    manifest.sign_manifest(&signing_key).expect("sign manifest");
    let manifest_bytes = serde_json::to_vec(&manifest).expect("manifest json");
    let optional_path = format!("/ipfs/{optional_cid}?format=car&dag-scope=entity");
    let routes = HashMap::from([
        ("/manifest.json".to_string(), manifest_bytes),
        (
            format!("/ipfs/{catalog_cid}?format=car&dag-scope=entity"),
            car_bytes(catalog_cid, &[(catalog_cid, catalog_bytes)]),
        ),
        (
            optional_path.clone(),
            car_bytes(optional_cid, &[(optional_cid, optional_bytes)]),
        ),
        (
            format!("/ipfs/{required_cid}?format=car&dag-scope=entity"),
            car_bytes(required_cid, &[(required_cid, required_bytes)]),
        ),
    ]);
    let (server, optional_block) = PathServer::spawn_with_blocked_path(routes, 4, optional_path);
    let config = IndexedArtifactSourceConfig {
        trusted_publisher_pubkey: FixedBytes::from(signing_key.verifying_key().to_bytes()),
        manifest_source: IndexedArtifactManifestSource::Url(
            server.url.join("/manifest.json").expect("manifest url"),
        ),
        gateway_urls: vec![server.url.clone()],
        gateway_pool: None,
        manifest_reuse: crate::IndexedArtifactManifestReuse::default(),
        max_manifest_age: None,
        concurrency: 1,
        max_in_flight_bytes: 1024 * 1024,
    };
    let artifact_source = TestArtifactSource {
        config,
        server,
        chunk_descriptors: vec![optional_descriptor.clone()],
    };
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
        Duration::from_secs(1),
    ));
    let chain = test_chain_config(&scope, rpcs, Some(artifact_source.config.clone()));
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    BlockedWalletOptionalMaintenanceFixture {
        root_dir,
        db,
        public_data_plane,
        chain,
        artifact_source,
        optional_block,
        optional_descriptor,
    }
}

fn checkpointed_wallet_artifact_source_with_blocked_manifest(
    scope: &ChainScope,
    start: u64,
    end: u64,
    checkpoint_block: u64,
) -> (TestArtifactSource, PathServerBlockControl) {
    let (source, block) =
        checkpointed_wallet_artifact_source_controlled(scope, start, end, checkpoint_block, true);
    (source, block.expect("blocked manifest control"))
}

fn checkpointed_wallet_artifact_source_controlled(
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

fn checkpointed_wallet_artifact_source_controlled_with_requests(
    scope: &ChainScope,
    start: u64,
    end: u64,
    checkpoint_block: u64,
    block_manifest: bool,
    request_count: usize,
    split_at: Option<u64>,
    omit_last_chunk: bool,
) -> (TestArtifactSource, Option<PathServerBlockControl>) {
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
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
    let chunk_descriptors = chunks
        .iter()
        .map(|(descriptor, _, _)| descriptor.clone())
        .collect::<Vec<_>>();
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

/// Serves a signed manifest with one Commitments catalog holding one chunk. Every leaf is in
/// tree 0 and sits at `commitment_block`; the manifest reports Commitments indexed through
/// `indexed_through_block`. The server answers one full catch-up (manifest, catalog, chunk).
fn commitment_artifact_source(
    scope: &ChainScope,
    indexed_through_block: u64,
    indexed_through_hash: [u8; 32],
    commitment_block: u64,
    leaves: &[(u64, U256)],
) -> TestArtifactSource {
    commitment_artifact_source_controlled(
        scope,
        indexed_through_block,
        indexed_through_hash,
        commitment_block,
        leaves,
        false,
    )
    .0
}

/// Like [`commitment_artifact_source`], but holds the manifest request until released.
fn commitment_artifact_source_with_blocked_manifest(
    scope: &ChainScope,
    indexed_through_block: u64,
    indexed_through_hash: [u8; 32],
    commitment_block: u64,
    leaves: &[(u64, U256)],
) -> (TestArtifactSource, PathServerBlockControl) {
    let (source, block) = commitment_artifact_source_controlled(
        scope,
        indexed_through_block,
        indexed_through_hash,
        commitment_block,
        leaves,
        true,
    );
    (source, block.expect("blocked manifest control"))
}

fn commitment_artifact_source_controlled(
    scope: &ChainScope,
    indexed_through_block: u64,
    indexed_through_hash: [u8; 32],
    commitment_block: u64,
    leaves: &[(u64, U256)],
    block_manifest: bool,
) -> (TestArtifactSource, Option<PathServerBlockControl>) {
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let start = leaves.first().map_or(0, |leaf| leaf.0);
    let end = leaves.last().map_or(0, |leaf| leaf.0);
    let row_count = u64::try_from(leaves.len()).expect("commitment row count");
    let range = IndexedArtifactRange {
        kind: IndexedArtifactRangeKind::TreePosition,
        start,
        end,
    };
    let mut payload = Vec::new();
    write_u64(&mut payload, row_count);
    for (tree_position, hash) in leaves {
        write_u64(&mut payload, *tree_position);
        write_u64(&mut payload, commitment_block);
        payload.push(0);
        payload.extend_from_slice(&0_u32.to_le_bytes());
        write_u64(&mut payload, *tree_position);
        payload.extend_from_slice(&hash.to_be_bytes::<32>());
    }
    let payload_len = u64::try_from(payload.len()).expect("commitment payload len");
    let chunk_bytes = IndexedArtifactChunkEnvelope::new(
        IndexedArtifactChunkEnvelopeHeader::new(
            IndexedDatasetKind::Commitments,
            scope.clone(),
            range.clone(),
            row_count,
            payload_len,
            vec![IndexedArtifactChunkSection {
                section_id: 1,
                offset: 0,
                byte_length: payload_len,
            }],
        ),
        payload,
    )
    .encode()
    .expect("encode commitment chunk");
    let chunk_cid = raw_cid(&chunk_bytes);
    let chunk_descriptor = IndexedArtifactDescriptor {
        dataset_kind: IndexedDatasetKind::Commitments,
        range: range.clone(),
        ..wallet_artifact_descriptor(
            scope.clone(),
            start,
            end,
            row_count,
            chunk_cid,
            &chunk_bytes,
            DatasetDescriptorMetadata {
                checkpoint_block: Some(commitment_block),
                start_block: Some(commitment_block),
                end_block: Some(commitment_block),
                ..Default::default()
            },
            CompressionAlgorithm::None,
        )
    };
    let catalog = IndexedArtifactCatalog {
        format_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
        dataset_kind: IndexedDatasetKind::Commitments,
        scope: scope.clone(),
        chunks: vec![chunk_descriptor.clone()],
    };
    let catalog_bytes = serde_json::to_vec(&catalog).expect("catalog json");
    let catalog_cid = raw_cid(&catalog_bytes);
    let catalog_descriptor = IndexedArtifactDescriptor {
        dataset_kind: IndexedDatasetKind::Commitments,
        range,
        ..wallet_artifact_descriptor(
            scope.clone(),
            start,
            end,
            row_count,
            catalog_cid,
            &catalog_bytes,
            DatasetDescriptorMetadata::default(),
            CompressionAlgorithm::None,
        )
    };
    let mut manifest = IndexedArtifactManifest::new(
        1_700_000_000_000,
        1,
        PublisherIdentity::ed25519(FixedBytes::from(signing_key.verifying_key().to_bytes())),
        vec![IndexedArtifactChainEntry {
            scope: scope.clone(),
            latest_indexed: vec![LatestIndexedHeight {
                dataset_kind: IndexedDatasetKind::Commitments,
                block_number: indexed_through_block,
                block_hash: FixedBytes::from(indexed_through_hash),
            }],
            catalogs: vec![catalog_descriptor],
        }],
    );
    manifest.sign_manifest(&signing_key).expect("sign manifest");
    let manifest_bytes = serde_json::to_vec(&manifest).expect("manifest json");
    let routes = HashMap::from([
        ("/manifest.json".to_string(), manifest_bytes),
        (
            format!("/ipfs/{catalog_cid}?format=car&dag-scope=entity"),
            car_bytes(catalog_cid, &[(catalog_cid, catalog_bytes)]),
        ),
        (
            format!("/ipfs/{chunk_cid}?format=car&dag-scope=entity"),
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
    let config = IndexedArtifactSourceConfig {
        trusted_publisher_pubkey: FixedBytes::from(signing_key.verifying_key().to_bytes()),
        manifest_source: IndexedArtifactManifestSource::Url(
            server.url.join("/manifest.json").expect("manifest url"),
        ),
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
            chunk_descriptors: vec![chunk_descriptor],
        },
        block,
    )
}

fn test_wallet_config(scope: &ChainScope, quick_sync_endpoint: Url) -> WalletConfig {
    WalletConfig {
        chain: ChainKey {
            chain_id: scope.chain_id,
            contract: scope.railgun_contract,
        },
        cache_key: test_cache_key("test"),
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

static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_db_root(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let counter = TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("sync-service-{name}-{unique}-{counter}"))
}

fn rpc_error_response(code: i64, message: &str) -> ChainError {
    let payload = serde_json::json!({ "code": code, "message": message }).to_string();
    ChainError::Rpc(TransportError::ErrorResp(
        serde_json::from_str(&payload).expect("JSON-RPC error payload"),
    ))
}

#[test]
fn log_range_limit_classifies_only_observed_provider_rejections() {
    let block_span = |max_blocks| Some(LogRangeLimit::BlockSpan { max_blocks });
    for (code, message, expected) in [
        (
            -32001,
            "Block range too large: maximum allowed is 50 blocks",
            block_span(Some(50)),
        ),
        (
            -32000,
            "log query range must not exceed 25 blocks",
            block_span(Some(25)),
        ),
        (
            -32000,
            "eth_getLogs is limited to 0 - 50 blocks range",
            block_span(Some(50)),
        ),
        (
            35,
            "ranges over 10000 blocks are not supported on freemium",
            block_span(Some(10_000)),
        ),
        (
            -32600,
            "You can make eth_getLogs requests with up to a 10 block range. Based on your parameters, this block range should work: [0x1e4a1c8e, 0x1e4a1c97]",
            block_span(Some(10)),
        ),
        (
            -32005,
            "query returned more than 10000 results",
            Some(LogRangeLimit::ResultSize),
        ),
        (
            -32005,
            "Query returned more than 10000 results. Try with this block range [0x1, 0x2].",
            Some(LogRangeLimit::ResultSize),
        ),
        (
            -32000,
            "log query range must not exceed the plan's blocks",
            block_span(None),
        ),
        (-32000, "header not found", None),
    ] {
        assert_eq!(
            rpc_error_response(code, message).log_range_limit(),
            expected,
            "{message}"
        );
    }

    // A cancelled log fetch is not an endpoint failure.
    assert!(!ChainError::LogFetchCancelled.should_mark_rpc_unhealthy());
    assert!(matches!(
        WalletStartupSyncError::from(ChainError::LogFetchCancelled),
        WalletStartupSyncError::Cancelled
    ));
    // An unverified archive endpoint says nothing about the regular endpoint.
    assert!(!ChainError::ArchiveRpcUnverified.should_mark_rpc_unhealthy());
}

#[tokio::test]
async fn startup_and_chain_errors_without_url_remove_endpoint_from_display() {
    use alloy_provider::Provider as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind unused port");
    let port = listener.local_addr().expect("listener addr").port();
    drop(listener);
    let url = Url::parse(&format!("http://127.0.0.1:{port}/key-abc")).expect("rpc url");
    let squid_err = reqwest::Client::new()
        .get(url.as_str())
        .send()
        .await
        .expect_err("closed port refuses the request");
    let err = WalletStartupSyncError::Indexed(merkletree::errors::SyncError::Request(squid_err));

    let unredacted = err.to_string();
    assert!(unredacted.contains("key-abc"), "{unredacted}");
    let redacted = err.without_url().to_string();
    assert!(
        !redacted.contains("key-abc") && !redacted.contains("127.0.0.1"),
        "{redacted}"
    );

    let rpcs = QueryRpcPool::new(vec![url], Duration::from_secs(1));
    let rpc = rpcs.random_provider().expect("rpc provider");
    let err = ChainError::from(
        rpc.provider
            .get_block_number()
            .await
            .expect_err("closed port refuses the request"),
    );

    let unredacted = err.to_string();
    assert!(unredacted.contains("key-abc"), "{unredacted}");
    let redacted = err.without_url().to_string();
    assert!(
        !redacted.contains("key-abc") && !redacted.contains("127.0.0.1"),
        "{redacted}"
    );
}

impl JsonRpcServer {
    /// Serves every request with `handler`, which maps the parsed request body
    /// to the response's `result` or `error` member.
    fn spawn_handler(
        handler: impl Fn(&serde_json::Value) -> serde_json::Value + Send + 'static,
    ) -> Self {
        Self::spawn_handler_with_status(move |body| Ok(handler(body)))
    }

    /// Like `spawn_handler`, but a handler `Err(status)` answers with that
    /// HTTP status and an empty body.
    fn spawn_handler_with_status(
        handler: impl Fn(&serde_json::Value) -> Result<serde_json::Value, u16> + Send + 'static,
    ) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind json-rpc server");
        let url = Url::parse(&format!(
            "http://{}",
            listener.local_addr().expect("local addr")
        ))
        .expect("json-rpc server url");
        let (request_tx, requests) = std_mpsc::channel();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.expect("accept json-rpc request");
                let request = read_http_request(&mut stream);
                let body = json_rpc_request_body(&request);
                if request_tx.send(request).is_err() {
                    break;
                }
                let (status, response) = match handler(&body) {
                    Ok(mut response) => {
                        response["jsonrpc"] = serde_json::json!("2.0");
                        response["id"] = body["id"].clone();
                        (200, response.to_string())
                    }
                    Err(status) => (status, String::new()),
                };
                let headers = format!(
                    "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    if status == 200 { "OK" } else { "Error" },
                    response.len()
                );
                let _ = stream
                    .write_all(headers.as_bytes())
                    .and_then(|()| stream.write_all(response.as_bytes()));
            }
        });
        Self { url, requests }
    }

    fn drain_request_bodies(&self) -> Vec<serde_json::Value> {
        self.requests
            .try_iter()
            .map(|request| json_rpc_request_body(&request))
            .collect()
    }
}

fn json_rpc_request_body(request: &str) -> serde_json::Value {
    let body_start = request
        .find("\r\n\r\n")
        .map_or(request.len(), |index| index + 4);
    serde_json::from_str(&request[body_start..]).expect("json-rpc request body")
}

fn hex_quantity(value: &serde_json::Value) -> u64 {
    let hex = value.as_str().expect("hex quantity");
    u64::from_str_radix(hex.trim_start_matches("0x"), 16).expect("hex quantity")
}

const fn test_block_timestamp(block_number: u64) -> u64 {
    1_700_000_000 + block_number
}

fn rpc_nullifiers_log_with_timestamp(contract: Address, block_number: u64) -> serde_json::Value {
    let mut log = rpc_nullifiers_log(contract, block_number);
    log["blockTimestamp"] = serde_json::json!(format!("{:#x}", test_block_timestamp(block_number)));
    log
}

fn rpc_error(code: i64, message: &str) -> serde_json::Value {
    serde_json::json!({ "code": code, "message": message })
}

fn reject_spans_over_25(
    from_block: u64,
    to_block: u64,
    _log_count: usize,
) -> Option<serde_json::Value> {
    (to_block - from_block + 1 > 25)
        .then(|| rpc_error(-32000, "log query range must not exceed 25 blocks"))
}

/// Serves `eth_getLogs` from `logs` unless `reject` returns an error for the
/// requested range and its log count, plus block-number and header reads.
fn log_range_rpc_handler(
    logs: Vec<serde_json::Value>,
    head: u64,
    reject: impl Fn(u64, u64, usize) -> Option<serde_json::Value> + Send + 'static,
) -> impl Fn(&serde_json::Value) -> serde_json::Value + Send + 'static {
    move |request: &serde_json::Value| {
        let params = &request["params"];
        match request["method"].as_str() {
            Some("eth_getLogs") => {
                let from_block = hex_quantity(&params[0]["fromBlock"]);
                let to_block = hex_quantity(&params[0]["toBlock"]);
                let matching = logs
                    .iter()
                    .filter(|log| {
                        (from_block..=to_block).contains(&hex_quantity(&log["blockNumber"]))
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                reject(from_block, to_block, matching.len()).map_or_else(
                    || serde_json::json!({ "result": matching }),
                    |error| serde_json::json!({ "error": error }),
                )
            }
            Some("eth_blockNumber") => serde_json::json!({ "result": format!("{head:#x}") }),
            Some("eth_getBlockByNumber") => {
                let block_number = hex_quantity(&params[0]);
                serde_json::json!({
                    "result": rpc_block(block_number, test_block_timestamp(block_number), 0x11),
                })
            }
            _ => serde_json::json!({ "error": rpc_error(-32601, "method not found") }),
        }
    }
}

/// Serves requests through `serve`, holding each listed `eth_getLogs` range,
/// in order, until its receiver yields.
fn gated_get_logs_handler(
    serve: impl Fn(&serde_json::Value) -> serde_json::Value + Send + 'static,
    gates: Vec<((u64, u64), std_mpsc::Receiver<()>)>,
) -> impl Fn(&serde_json::Value) -> serde_json::Value + Send + 'static {
    let gates = std::sync::Mutex::new(std::collections::VecDeque::from(gates));
    move |request: &serde_json::Value| {
        if request["method"] == "eth_getLogs" {
            let range = (
                hex_quantity(&request["params"][0]["fromBlock"]),
                hex_quantity(&request["params"][0]["toBlock"]),
            );
            let gate = {
                let mut gates = gates.lock().expect("gate lock");
                if gates.front().is_some_and(|(gated, _)| *gated == range) {
                    gates.pop_front()
                } else {
                    None
                }
            };
            if let Some((_, release)) = gate {
                let _ = release.recv();
            }
        }
        serve(request)
    }
}

fn get_logs_ranges(bodies: &[serde_json::Value]) -> Vec<(u64, u64)> {
    bodies
        .iter()
        .filter(|body| body["method"] == "eth_getLogs")
        .map(|body| {
            (
                hex_quantity(&body["params"][0]["fromBlock"]),
                hex_quantity(&body["params"][0]["toBlock"]),
            )
        })
        .collect()
}

fn header_blocks(bodies: &[serde_json::Value]) -> Vec<u64> {
    bodies
        .iter()
        .filter(|body| body["method"] == "eth_getBlockByNumber")
        .map(|body| hex_quantity(&body["params"][0]))
        .collect()
}

fn log_fetch_chain(scope: &ChainScope, rpc_url: Url, block_range: u64) -> ChainConfig {
    let rpcs = Arc::new(QueryRpcPool::new(vec![rpc_url], Duration::from_secs(1)));
    let mut chain = test_chain_config(scope, rpcs, None);
    chain.sync.block_range = block_range;
    chain
}

async fn fetch_sorted_logs(
    chain: &ChainConfig,
    from_block: u64,
    to_block: u64,
) -> Result<Vec<Log>, ChainError> {
    let rpc = chain.rpcs.random_provider().expect("rpc provider");
    let mut logs = chain
        .fetch_logs_for_range(&rpc, None, from_block, to_block, &CancellationToken::new())
        .await?;
    sort_logs(&mut logs);
    Ok(logs)
}

#[tokio::test]
async fn log_fetch_narrows_to_endpoint_span_limit_and_reuses_it() {
    let scope = test_scope();
    let logs = [1003, 1100, 1250, 1499, 1520]
        .into_iter()
        .map(|block| rpc_nullifiers_log(scope.railgun_contract, block))
        .collect::<Vec<_>>();
    let unlimited =
        JsonRpcServer::spawn_handler(log_range_rpc_handler(logs.clone(), 1600, |_, _, _| None));
    let limited =
        JsonRpcServer::spawn_handler(log_range_rpc_handler(logs, 1600, reject_spans_over_25));
    let mut unlimited_chain = log_fetch_chain(&scope, unlimited.url.clone(), 500);
    let limited_chain = log_fetch_chain(&scope, limited.url.clone(), 500);

    let expected = fetch_sorted_logs(&unlimited_chain, 1001, 1500)
        .await
        .expect("unlimited endpoint logs");
    let fetched = fetch_sorted_logs(&limited_chain, 1001, 1500)
        .await
        .expect("span-limited endpoint completes the logical range");

    assert_eq!(expected.len(), 4);
    assert_eq!(fetched, expected);
    let expected_ranges = std::iter::once((1001, 1500))
        .chain((0..20).map(|chunk| (1001 + chunk * 25, 1025 + chunk * 25)))
        .collect::<Vec<(u64, u64)>>();
    assert_eq!(
        get_logs_ranges(&limited.drain_request_bodies()),
        expected_ranges,
        "one rejected request, then contiguous spans of the parsed limit"
    );

    let second = fetch_sorted_logs(&limited_chain, 1501, 1550)
        .await
        .expect("second range on the same pool");
    assert_eq!(second.len(), 1);
    assert_eq!(
        get_logs_ranges(&limited.drain_request_bodies()),
        vec![(1501, 1525), (1526, 1550)],
        "later ranges reuse the learned span without a wide request"
    );

    // Through an archive provider, the archive learns its own span while the
    // regular provider's slot keeps the full range.
    unlimited_chain.sync.archive_until_block = 1250;
    let archive = broadcaster_core::provider::build_provider(&limited.url)
        .await
        .expect("archive provider");
    let rpc = unlimited_chain
        .rpcs
        .random_provider()
        .expect("rpc provider");
    let mut through_archive = unlimited_chain
        .fetch_logs_for_range(&rpc, Some(&archive), 1001, 1500, &CancellationToken::new())
        .await
        .expect("archive and regular providers complete the logical range");
    sort_logs(&mut through_archive);
    assert_eq!(through_archive, expected);
    assert_eq!(
        get_logs_ranges(&limited.drain_request_bodies()),
        std::iter::once((1001, 1250))
            .chain((0..10).map(|chunk| (1001 + chunk * 25, 1025 + chunk * 25)))
            .collect::<Vec<(u64, u64)>>(),
        "the archive range narrows on the archive's own rejection"
    );
    assert_eq!(
        unlimited_chain.rpcs.log_span(LogSpanEndpoint::Archive, 500),
        25
    );
    assert_eq!(
        unlimited_chain
            .rpcs
            .log_span(LogSpanEndpoint::Provider(0), 500),
        500
    );
}

#[tokio::test]
async fn log_fetch_splits_result_size_rejection_without_narrowing_span() {
    let scope = test_scope();
    let logs = [1003, 1100, 1250, 1499]
        .into_iter()
        .map(|block| rpc_nullifiers_log(scope.railgun_contract, block))
        .collect::<Vec<_>>();
    let server =
        JsonRpcServer::spawn_handler(log_range_rpc_handler(logs, 1600, |_, _, log_count| {
            (log_count > 3).then(|| rpc_error(-32005, "query returned more than 10000 results"))
        }));
    let chain = log_fetch_chain(&scope, server.url.clone(), 500);

    let fetched = fetch_sorted_logs(&chain, 1001, 1500)
        .await
        .expect("result-size rejection is split");

    assert_eq!(fetched.len(), 4);
    assert_eq!(
        get_logs_ranges(&server.drain_request_bodies()),
        vec![(1001, 1500), (1001, 1250), (1251, 1500)],
        "only the rejected request is split"
    );
    assert_eq!(
        chain.rpcs.log_span(LogSpanEndpoint::Provider(0), 500),
        500,
        "result-size rejections leave the learned span unchanged"
    );
}

#[tokio::test]
async fn log_fetch_returns_unrecognized_and_single_block_rejections() {
    let scope = test_scope();
    let events = CapturedEvents::default();
    let _guard = events.capture();
    let unrecognized =
        JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 1600, |_, _, _| {
            Some(rpc_error(-32000, "header not found"))
        }));
    let chain = log_fetch_chain(&scope, unrecognized.url.clone(), 500);

    let err = fetch_sorted_logs(&chain, 1001, 1500)
        .await
        .expect_err("unrecognized error is returned");

    assert!(matches!(err, ChainError::Rpc(_)) && err.log_range_limit().is_none());
    assert_eq!(
        get_logs_ranges(&unrecognized.drain_request_bodies()),
        vec![(1001, 1500)],
        "unrecognized errors are not retried"
    );
    assert_eq!(chain.rpcs.log_span(LogSpanEndpoint::Provider(0), 500), 500);
    let unmatched = events.find("eth_getLogs error is not a recognized range limit");
    assert_eq!(unmatched.get("code").map(String::as_str), Some("-32000"));

    let saturated =
        JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 1600, |_, _, _| {
            Some(rpc_error(-32005, "query returned more than 10000 results"))
        }));
    let chain = log_fetch_chain(&scope, saturated.url.clone(), 500);

    let err = fetch_sorted_logs(&chain, 1001, 1004)
        .await
        .expect_err("single-block rejection is an endpoint failure");

    assert_eq!(err.log_range_limit(), Some(LogRangeLimit::ResultSize));
    assert!(err.should_mark_rpc_unhealthy());
    assert_eq!(
        get_logs_ranges(&saturated.drain_request_bodies()),
        vec![(1001, 1004), (1001, 1002), (1001, 1001)]
    );
}

#[tokio::test]
async fn log_block_timestamps_request_headers_only_for_blocks_without_log_timestamps() {
    let scope = test_scope();
    let contract = scope.railgun_contract;
    let server =
        JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 1600, |_, _, _| None));
    let chain = log_fetch_chain(&scope, server.url.clone(), 100);
    let rpc = chain.rpcs.random_provider().expect("rpc provider");
    let log = |block_number, with_timestamp| {
        serde_json::from_value::<Log>(if with_timestamp {
            rpc_nullifiers_log_with_timestamp(contract, block_number)
        } else {
            rpc_nullifiers_log(contract, block_number)
        })
        .expect("RPC log")
    };
    let partial = [
        log(1003, true),
        log(1050, false),
        log(1070, true),
        log(1070, false),
    ];
    let without_timestamps = [log(1003, false), log(1050, false), log(1070, false)];

    let from_logs = chain
        .fetch_log_block_timestamps(&rpc.provider, None, &partial)
        .await
        .expect("partial log timestamps");
    assert_eq!(
        header_blocks(&server.drain_request_bodies()),
        vec![1050],
        "headers are requested only for blocks whose logs all lack a timestamp"
    );
    let from_headers = chain
        .fetch_log_block_timestamps(&rpc.provider, None, &without_timestamps)
        .await
        .expect("header timestamps");
    assert_eq!(
        header_blocks(&server.drain_request_bodies()),
        vec![1003, 1050, 1070]
    );

    assert_eq!(from_logs, from_headers);
}

#[tokio::test]
async fn wallet_startup_rpc_candidate_completes_on_span_limited_endpoint() {
    let root_dir = temp_db_root("wallet-startup-span-limited-rpc");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc = JsonRpcServer::spawn_handler(log_range_rpc_handler(
        vec![rpc_nullifiers_log_with_timestamp(
            scope.railgun_contract,
            190,
        )],
        200,
        reject_spans_over_25,
    ));
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, Arc::clone(&rpcs), None);
    chain.sync.block_range = 100;
    chain.finality_depth = 0;
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
    let mut cfg = test_wallet_config(&scope, rpc.url.clone());
    cfg.start_block = Some(1);

    let candidate = Arc::clone(&service)
        .wallet_startup_rpc_candidate(
            &cfg,
            WalletShortStartupPlan::new(1, 150, 200, 100).expect("short startup plan"),
            CancellationToken::new(),
        )
        .await
        .expect("RPC startup candidate completes through narrower requests");

    assert_eq!(candidate.applies.len(), 1);
    let WalletScanRowsPayload::Rows(rows) = &candidate.applies[0].rows.payload else {
        panic!("RPC delivery rows expected");
    };
    assert_eq!(rows.nullifiers.len(), 1);
    assert_eq!(
        rows.nullifiers[0].source.block_timestamp,
        test_block_timestamp(190)
    );
    let bodies = rpc.drain_request_bodies();
    assert_eq!(
        get_logs_ranges(&bodies),
        vec![(151, 200), (151, 175), (176, 200)],
        "the delivery range after the cursor completes through narrower requests"
    );
    assert_eq!(
        header_blocks(&bodies),
        vec![200],
        "log timestamps replace header reads; the endpoint confirmation read still runs"
    );
    assert_eq!(
        rpcs.available_providers().len(),
        1,
        "a range-limited endpoint stays eligible"
    );

    service.shutdown().await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn log_fetch_diagnostics_record_adaptation_without_endpoint_url() {
    let scope = test_scope();
    let server = JsonRpcServer::spawn_handler(log_range_rpc_handler(
        vec![
            rpc_nullifiers_log_with_timestamp(scope.railgun_contract, 1003),
            rpc_nullifiers_log(scope.railgun_contract, 1050),
        ],
        1600,
        reject_spans_over_25,
    ));
    let port = server.url.port().expect("mock RPC port");
    let credential_url = Url::parse(&format!("http://user:secret@127.0.0.1:{port}/key-abc"))
        .expect("credential-bearing RPC URL");
    let chain = log_fetch_chain(&scope, credential_url.clone(), 100);
    let rpc = chain.rpcs.random_provider().expect("rpc provider");
    let events = CapturedEvents::default();
    let guard = events.capture();

    let logs = chain
        .fetch_logs_for_range(&rpc, None, 1001, 1100, &CancellationToken::new())
        .await
        .expect("span-limited logs");
    let timestamps = chain
        .fetch_log_block_timestamps(&rpc.provider, None, &logs)
        .await
        .expect("log block timestamps");
    drop(guard);
    assert_eq!(timestamps.len(), 2);

    let field = |event: &BTreeMap<String, String>, name: &str| {
        event
            .get(name)
            .cloned()
            .unwrap_or_else(|| panic!("missing {name} field"))
    };
    let adaptation = events.find("narrowed eth_getLogs request after provider range limit");
    for (name, value) in [
        ("logical_from", "1001"),
        ("logical_to", "1100"),
        ("rejected_span", "100"),
        ("next_span", "25"),
        ("endpoint", "0"),
        ("kind", "block_span"),
    ] {
        assert_eq!(field(&adaptation, name), value, "{name}");
    }
    let range = events.find("logical log range fetch finished");
    assert_eq!(field(&range, "get_logs_requests"), "5");
    assert_eq!(field(&range, "rpc_index"), "0");
    let coverage = events.find("log block timestamp coverage");
    assert_eq!(field(&coverage, "blocks_from_logs"), "1");
    assert_eq!(field(&coverage, "headers_requested"), "1");
    assert!(coverage.contains_key("elapsed_ms"));

    let forbidden = [
        credential_url.as_str(),
        "127.0.0.1",
        "user",
        "secret",
        "key-abc",
    ];
    for event in events.events() {
        for value in event.values() {
            assert!(
                forbidden.iter().all(|needle| !value.contains(needle)),
                "diagnostic value {value:?} exposes the endpoint"
            );
        }
    }
}

#[tokio::test]
async fn wallet_startup_hedge_failure_logs_omit_endpoint_url() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind refused RPC port");
    let port = listener.local_addr().expect("refused RPC addr").port();
    drop(listener);
    let credential_url = Url::parse(&format!("http://user:secret@127.0.0.1:{port}/key-abc"))
        .expect("credential-bearing RPC URL");
    let root_dir = temp_db_root("wallet-startup-hedge-url-redaction");
    let events = CapturedEvents::default();
    let guard = events.capture();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![credential_url],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    chain.sync.block_range = 10;
    chain.sync.indexed_wallet_block_range = 10;
    chain.finality_depth = 0;
    let public_data_plane = ChainPublicDataPlane::new(Arc::clone(&db), Arc::new(AtomicU64::new(0)));
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
    service.safe_head_tx.send_replace(110);

    // Only the RPC candidate runs, and its head read is refused.
    let mut cfg = test_wallet_config(
        &scope,
        Url::parse("http://127.0.0.1:1").expect("unused Squid URL"),
    );
    cfg.cache_key = test_cache_key("hedge-url-redaction");
    cfg.start_block = Some(101);
    cfg.sync_to_block = Some(110);
    cfg.use_indexed_wallet_catch_up = false;
    db.put_wallet_meta(
        &cfg.cache_key,
        &WalletMeta {
            last_scanned_block: 105,
            updated_at: 1,
            last_scanned_block_hash: None,
        },
    )
    .expect("seed wallet cursor");
    let _handle = service.register_wallet(cfg).await.expect("register wallet");
    let hedge_failed = |event: &BTreeMap<String, String>| {
        event
            .get("message")
            .is_some_and(|message| message == "wallet startup hedge candidate failed")
    };
    yield_until("failed wallet startup hedge candidate", || {
        events.events().iter().any(hedge_failed)
    })
    .await;

    service.unregister_all_wallets().await;
    service.shutdown().await;
    drop(guard);

    let failure = events.find("wallet startup hedge candidate failed");
    let err = failure.get("err").expect("hedge failure err field");
    assert!(
        err.starts_with("rpc error"),
        "the candidate failed on the transport error: {err:?}"
    );
    let endpoint = format!("127.0.0.1:{port}");
    let forbidden = ["secret", "user:", "key-abc", endpoint.as_str()];
    for event in events.events() {
        for value in event.values() {
            assert!(
                forbidden.iter().all(|needle| !value.contains(needle)),
                "log value {value:?} exposes the endpoint"
            );
        }
    }

    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn chain_rpc_failure_logs_omit_endpoint_url() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind refused RPC port");
    let port = listener.local_addr().expect("refused RPC addr").port();
    drop(listener);
    let events = CapturedEvents::default();
    let guard = events.capture();
    let fixture = LiveForestFixture::spawn(
        "chain-rpc-failure-url-redaction",
        vec![credential_url(port)],
        Url::parse("http://127.0.0.1:1").expect("unused Squid URL"),
        50,
        200,
    )
    .await;
    let service = &fixture.service;
    let chain = &service.chain;
    // A recorded hash for the forest block makes the live loop read it back.
    service
        .db
        .update_merkle_forest_meta(
            chain.deployment.chain_id,
            &chain.deployment.contract.to_string(),
            &service.db.resolve_path(&DbStore::relative_blob_path(
                "merkle_forest",
                "live-forest.msgpack",
            )),
            50,
            merkletree::persist::SNAPSHOT_VERSION,
            [0xaa; 32],
        )
        .expect("persist forest meta for block 50");
    service.safe_head_tx.send(200).expect("wake live loop");
    yield_until("failed reorg check", || {
        events.events().iter().any(|event| {
            event
                .get("message")
                .is_some_and(|m| m == "reorg check failed")
        })
    })
    .await;

    // A separate pool keeps the live loop's cooldown from hiding the head read.
    spawn_head_poller(
        Arc::clone(service),
        Arc::new(QueryRpcPool::new(
            vec![credential_url(port)],
            Duration::from_secs(1),
        )),
    );
    yield_until("failed head read", || {
        events.events().iter().any(|event| {
            event
                .get("message")
                .is_some_and(|m| m == "failed to fetch latest block")
        })
    })
    .await;
    fixture.stop().await;
    drop(guard);

    for message in ["reorg check failed", "failed to fetch latest block"] {
        let event = events.find(message);
        assert_eq!(
            event.get("rpc_index").map(String::as_str),
            Some("0"),
            "{message}"
        );
        let err = event.get("err").expect("err field");
        assert!(
            err.starts_with("rpc error"),
            "{message} logs the transport error: {err:?}"
        );
    }
    let endpoint = format!("127.0.0.1:{port}");
    let forbidden = ["secret", "user:", "key-abc", endpoint.as_str()];
    for event in events.events() {
        for value in event.values() {
            assert!(
                forbidden.iter().all(|needle| !value.contains(needle)),
                "log value {value:?} exposes the endpoint"
            );
        }
    }
}

/// Starts `count` JSON-RPC endpoints with head `head`. The first `hung`
/// block-number reads, counted across all of them, get no answer until the
/// returned release flag is set.
fn head_servers_with_hung_first_reads(
    count: usize,
    hung: u64,
    head: u64,
) -> (
    Vec<JsonRpcServer>,
    Arc<AtomicU64>,
    Arc<std::sync::atomic::AtomicBool>,
) {
    let head_reads = Arc::new(AtomicU64::new(0));
    let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let servers = (0..count)
        .map(|_| {
            let head_reads = Arc::clone(&head_reads);
            let release = Arc::clone(&release);
            let serve = log_range_rpc_handler(Vec::new(), head, |_, _, _| None);
            JsonRpcServer::spawn_handler(move |request| {
                if request["method"] == "eth_blockNumber"
                    && head_reads.fetch_add(1, Ordering::AcqRel) < hung
                {
                    while !release.load(Ordering::Acquire) {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
                serve(request)
            })
        })
        .collect();
    (servers, head_reads, release)
}

#[tokio::test(start_paused = true)]
async fn bounded_head_read_uses_answering_provider_beside_hung_one() {
    let (_hung, hung_port) = silent_server();
    let answering =
        JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 200, |_, _, _| None));
    let rpcs = QueryRpcPool::new(
        vec![
            Url::parse(&format!("http://127.0.0.1:{hung_port}")).expect("hung RPC URL"),
            answering.url.clone(),
        ],
        Duration::from_mins(1),
    );
    let started = tokio::time::Instant::now();
    let read = tokio::spawn(async move {
        read_head_bounded(&rpcs)
            .await
            .map(|(rpc, head)| (rpc.index, head))
    });
    // Busy-yielding keeps the paused clock still while the answer arrives.
    yield_until("head read", || read.is_finished()).await;

    assert_eq!(read.await.expect("head read task"), Some((1, 200)));
    assert_eq!(
        started.elapsed(),
        Duration::ZERO,
        "no stagger or deadline wait"
    );
}

#[tokio::test(start_paused = true)]
async fn bounded_head_read_gives_up_at_deadline_when_every_provider_hangs() {
    let hung = (0..4).map(|_| silent_server()).collect::<Vec<_>>();
    // Per-request timeouts as in production, longer than the deadline.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("RPC client");
    let rpcs = QueryRpcPool::with_http_client(
        hung.iter()
            .map(|(_, port)| Url::parse(&format!("http://127.0.0.1:{port}")).expect("hung RPC URL"))
            .collect(),
        Duration::from_mins(1),
        client,
    );
    let started = tokio::time::Instant::now();

    // Nothing answers, so the paused clock runs forward through the read's
    // timers.
    assert!(read_head_bounded(&rpcs).await.is_none());
    let elapsed = started.elapsed();
    assert!(
        (INITIAL_HEAD_DEADLINE..INITIAL_HEAD_DEADLINE + Duration::from_secs(1)).contains(&elapsed),
        "the read ends at its deadline, got {elapsed:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn bounded_head_read_staggers_past_hung_providers() {
    let (servers, head_reads, release) = head_servers_with_hung_first_reads(4, 3, 300);
    let rpcs = QueryRpcPool::new(
        servers.iter().map(|server| server.url.clone()).collect(),
        Duration::from_mins(1),
    );
    let started = tokio::time::Instant::now();
    let read = tokio::spawn(async move { read_head_bounded(&rpcs).await.map(|(_, head)| head) });

    // Busy-yielding keeps the paused clock still between the steps.
    yield_until("three hung head reads", || {
        head_reads.load(Ordering::Acquire) >= 3
    })
    .await;
    tokio::time::advance(HEAD_READ_STAGGER).await;
    yield_until("staggered head read", || read.is_finished()).await;

    assert_eq!(read.await.expect("head read task"), Some(300));
    assert_eq!(
        head_reads.load(Ordering::Acquire),
        4,
        "the fourth provider starts at the stagger"
    );
    assert!(started.elapsed() < INITIAL_HEAD_DEADLINE);
    release.store(true, Ordering::Release);
}

#[tokio::test(start_paused = true)]
async fn head_poller_publishes_first_safe_head_past_hung_providers() {
    let (servers, head_reads, release) = head_servers_with_hung_first_reads(4, 3, 300);
    let (root_dir, db) = open_forest_db("head-poller-hung-providers");
    let rpcs = Arc::new(QueryRpcPool::new(
        servers.iter().map(|server| server.url.clone()).collect(),
        Duration::from_mins(1),
    ));
    let chain = test_chain_config(&test_scope(), Arc::clone(&rpcs), None);
    let public_data_plane = ChainPublicDataPlane::new(Arc::clone(&db), Arc::new(AtomicU64::new(0)));
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
    let safe_head_rx = service.safe_head_tx.subscribe();
    let started = tokio::time::Instant::now();

    // A headless start: no safe head is known yet.
    spawn_head_poller(Arc::clone(&service), rpcs);
    yield_until("three hung head reads", || {
        head_reads.load(Ordering::Acquire) >= 3
    })
    .await;
    tokio::time::advance(HEAD_READ_STAGGER).await;
    yield_until("first safe head", || *safe_head_rx.borrow() == 300).await;
    assert!(
        started.elapsed() < INITIAL_HEAD_DEADLINE,
        "no hung provider's request is waited out"
    );

    service.cancel.cancel();
    release.store(true, Ordering::Release);
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

/// Records `sync_service` tracing events as field-name to value maps.
#[derive(Clone, Default)]
struct CapturedEvents(Arc<std::sync::Mutex<Vec<BTreeMap<String, String>>>>);

impl CapturedEvents {
    fn capture(&self) -> CaptureGuard {
        // With one registered dispatcher, tracing-core resolves a callsite first
        // hit on another test thread against that thread's empty default and
        // caches it as disabled. A second live dispatcher keeps interest computed
        // across every registered dispatcher, including this thread's capture.
        let registered = tracing::Dispatch::new(CaptureSubscriber(self.clone()));
        CaptureGuard {
            _default: tracing::subscriber::set_default(CaptureSubscriber(self.clone())),
            _registered: registered,
        }
    }

    fn events(&self) -> Vec<BTreeMap<String, String>> {
        self.0.lock().expect("captured events lock").clone()
    }

    fn with_message(&self, message: &str) -> Vec<BTreeMap<String, String>> {
        self.events()
            .into_iter()
            .filter(|event| event.get("message").is_some_and(|value| value == message))
            .collect()
    }

    fn find(&self, message: &str) -> BTreeMap<String, String> {
        self.events()
            .into_iter()
            .find(|event| event.get("message").is_some_and(|value| value == message))
            .unwrap_or_else(|| panic!("missing {message:?} event"))
    }
}

struct CaptureGuard {
    _default: tracing::subscriber::DefaultGuard,
    _registered: tracing::Dispatch,
}

struct CaptureSubscriber(CapturedEvents);

struct CapturedFields<'a>(&'a mut BTreeMap<String, String>);

impl tracing::field::Visit for CapturedFields<'_> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.insert(field.name().to_owned(), value.to_owned());
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }
}

impl tracing::Subscriber for CaptureSubscriber {
    fn register_callsite(
        &self,
        _metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }

    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target().starts_with("sync_service")
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = BTreeMap::new();
        event.record(&mut CapturedFields(&mut fields));
        self.0.0.lock().expect("captured events lock").push(fields);
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

const SQUID_EMPTY_COMMITMENTS: &str = r#"{"data":{"commitments":[]}}"#;

/// Loads the startup forest from block 1 with an artifact source and a Squid
/// endpoint (height 300) configured, and returns the forest block plus the
/// artifact and Squid request counts.
async fn load_startup_forest_with_indexed_sources(name: &str, safe_head: u64) -> (u64, u64, usize) {
    let scope = test_scope();
    let artifact_source = checkpointed_wallet_artifact_source(&scope, 1, 50, 50);
    let squid = GraphqlServer::spawn(vec![
        r#"{"data":{"squidStatus":{"height":"300"}}}"#,
        SQUID_EMPTY_COMMITMENTS,
    ]);
    let root_dir = temp_db_root(name);
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let confirmer =
        JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 500, |_, _, _| None));
    let rpcs = confirming_pool_without_rpc_candidate(&confirmer.url);
    let mut chain = test_chain_config(&scope, rpcs, Some(artifact_source.config.clone()));
    chain.sync.quick_sync_endpoint = Some(squid.url.clone());

    let (_, forest_block, _, _) = db
        .load_or_initialize_forest(&chain, safe_head, None, None)
        .await
        .expect("load startup forest");

    let requests = (
        forest_block,
        artifact_source.server.request_count(),
        squid.requests.try_iter().count(),
    );
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
    requests
}

#[tokio::test]
async fn startup_forest_catch_up_skips_indexed_sources_only_for_short_tails() {
    // From block 1, safe head 100 leaves a tail of exactly `block_range` blocks.
    let (forest_block, artifact_requests, squid_requests) =
        load_startup_forest_with_indexed_sources("startup-forest-short-tail", 100).await;
    assert_eq!(forest_block, 0, "live RPC sync owns the short tail");
    assert_eq!(artifact_requests, 0, "no artifact request for a short tail");
    assert_eq!(squid_requests, 0, "no Squid request for a short tail");

    let (forest_block, artifact_requests, squid_requests) =
        load_startup_forest_with_indexed_sources("startup-forest-long-tail", 500).await;
    assert!(artifact_requests > 0, "artifact catch-up is tried first");
    assert_eq!(squid_requests, 2, "Squid height and commitments");
    assert_eq!(forest_block, 300, "Squid catches up to its indexed height");
}

/// A `Transact` log that adds one commitment at `tree_position` of tree 0.
fn rpc_transact_log(contract: Address, block_number: u64, tree_position: u64) -> serde_json::Value {
    rpc_event_log(
        contract,
        block_number,
        &Transact {
            treeNumber: U256::ZERO,
            startPosition: U256::from(tree_position),
            hash: vec![FixedBytes::from(
                U256::from(tree_position + 1_000).to_be_bytes::<32>(),
            )],
            ciphertext: Vec::new(),
        }
        .encode_log_data(),
    )
}

/// A `Transact` log whose commitments, from position 0 of tree 0, carry
/// ciphertext, so wallet scan rows decode them.
fn rpc_transact_outputs_log(
    contract: Address,
    block_number: u64,
    hashes: Vec<FixedBytes<32>>,
) -> serde_json::Value {
    let ciphertext = merkletree::slow::types::CommitmentCiphertext {
        ciphertext: [FixedBytes::ZERO; 4],
        blindedSenderViewingKey: FixedBytes::ZERO,
        blindedReceiverViewingKey: FixedBytes::ZERO,
        annotationData: alloy::primitives::Bytes::new(),
        memo: alloy::primitives::Bytes::new(),
    };
    rpc_event_log(
        contract,
        block_number,
        &Transact {
            treeNumber: U256::ZERO,
            startPosition: U256::ZERO,
            ciphertext: vec![ciphertext; hashes.len()],
            hash: hashes,
        }
        .encode_log_data(),
    )
}

fn rpc_event_log(
    contract: Address,
    block_number: u64,
    encoded: &alloy::primitives::LogData,
) -> serde_json::Value {
    let topics = encoded
        .topics()
        .iter()
        .map(|topic| format!("{topic:#x}"))
        .collect::<Vec<_>>();
    serde_json::json!({
        "address": format!("{contract:#x}"),
        "topics": topics,
        "data": format!("0x{}", hex::encode(&encoded.data)),
        "blockHash": format!("{:#x}", FixedBytes::<32>::from([0x11; 32])),
        "blockNumber": format!("{block_number:#x}"),
        "transactionHash": format!("{:#x}", FixedBytes::<32>::from([0x33; 32])),
        "transactionIndex": "0x0",
        "logIndex": "0x0",
        "removed": false,
    })
}

/// Binds a listener that never accepts: connections complete in the backlog,
/// and requests on them never receive response headers.
fn silent_server() -> (std::net::TcpListener, u16) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind silent server");
    let port = listener.local_addr().expect("silent server addr").port();
    (listener, port)
}

/// Accepts and closes every connection waiting on `listener`, returning how
/// many there were.
fn drain_backlog_connections(listener: &std::net::TcpListener) -> usize {
    listener
        .set_nonblocking(true)
        .expect("nonblocking silent server");
    std::iter::from_fn(|| listener.accept().ok()).count()
}

fn credential_url(port: u16) -> Url {
    Url::parse(&format!("http://user:secret@127.0.0.1:{port}/key-abc"))
        .expect("credential-bearing URL")
}

fn forest_meta(db: &DbStore, chain: &ChainConfig) -> Option<(u64, [u8; 32])> {
    db.get_merkle_forest_meta(
        chain.deployment.chain_id,
        &chain.deployment.contract.to_string(),
    )
    .expect("read forest meta")
    .map(|meta| (meta.last_block, meta.hash))
}

fn open_forest_db(name: &str) -> (PathBuf, Arc<DbStore>) {
    let root_dir = temp_db_root(name);
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    (root_dir, Arc::new(db))
}

/// Writes a one-leaf forest snapshot at `block`, with `hash` in its forest
/// metadata, and returns the forest, the snapshot path, and its bytes.
fn seed_loaded_forest(
    db: &DbStore,
    chain: &ChainConfig,
    block: u64,
    hash: [u8; 32],
) -> (MerkleForest, PathBuf, Vec<u8>) {
    db.ensure_blob_dir("merkle_forest")
        .expect("create merkle forest blob dir");
    let snapshot_path = db.resolve_path(&DbStore::relative_blob_path(
        "merkle_forest",
        &format!(
            "forest-{}-{}.msgpack",
            chain.deployment.chain_id, chain.deployment.contract
        ),
    ));
    let mut loaded = MerkleForest::new();
    loaded
        .insert_leaf(MerkleTreeUpdate {
            tree_number: 1,
            tree_position: 0,
            hash: U256::from(5),
        })
        .expect("insert loaded leaf");
    loaded.compute_roots();
    merkletree::persist::MerkleForestSnapshot::write(
        &snapshot_path,
        chain.deployment.chain_id,
        chain.deployment.contract,
        block,
        &loaded,
    )
    .expect("seed loaded snapshot");
    db.update_merkle_forest_meta(
        chain.deployment.chain_id,
        &chain.deployment.contract.to_string(),
        &snapshot_path,
        block,
        merkletree::persist::SNAPSHOT_VERSION,
        hash,
    )
    .expect("seed loaded forest meta");
    let snapshot_bytes = fs::read(&snapshot_path).expect("read seeded snapshot");
    (loaded, snapshot_path, snapshot_bytes)
}

/// A pool whose one provider, at `url`, confirms indexed forest targets, while
/// its learned one-block log span puts every tail longer than one page over
/// the RPC forest request budget, so no RPC forest candidate starts.
fn confirming_pool_without_rpc_candidate(url: &Url) -> Arc<QueryRpcPool> {
    let rpcs = Arc::new(QueryRpcPool::new(vec![url.clone()], Duration::from_secs(1)));
    rpcs.narrow_log_span(LogSpanEndpoint::Provider(0), 1);
    rpcs
}

fn race_finished_events(events: &CapturedEvents, candidate: &str) -> Vec<BTreeMap<String, String>> {
    events
        .events()
        .into_iter()
        .filter(|event| {
            event
                .get("message")
                .is_some_and(|message| message == "merkle forest catch-up candidate finished")
                && event
                    .get("candidate")
                    .is_some_and(|value| value == candidate)
        })
        .collect()
}

#[tokio::test]
async fn startup_rpc_forest_candidate_matches_sequential_log_application() {
    let scope = test_scope();
    // A 963-block tail from block 1, ten pages of 100 blocks.
    let logs = [
        (1, 0),
        (99, 1),
        (100, 2),
        (101, 3),
        (250, 4),
        (512, 5),
        (963, 6),
    ]
    .into_iter()
    .map(|(block_number, tree_position)| {
        rpc_transact_log(scope.railgun_contract, block_number, tree_position)
    })
    .collect::<Vec<_>>();
    let servers = (0..3)
        .map(|_| {
            JsonRpcServer::spawn_handler(log_range_rpc_handler(logs.clone(), 963, |_, _, _| None))
        })
        .collect::<Vec<_>>();
    let (root_dir, db) = open_forest_db("startup-rpc-forest-candidate");
    let rpcs = Arc::new(QueryRpcPool::new(
        servers.iter().map(|server| server.url.clone()).collect(),
        Duration::from_secs(1),
    ));
    let chain = test_chain_config(&scope, rpcs, None);

    let (forest, forest_block, snapshot_path, _) = db
        .load_or_initialize_forest(&chain, 963, None, None)
        .await
        .expect("load startup forest");

    let mut expected = MerkleForest::new();
    expected
        .apply_commitment_updates_from_logs(
            &logs
                .iter()
                .map(|log| serde_json::from_value::<Log>(log.clone()).expect("rpc log"))
                .collect::<Vec<_>>(),
        )
        .expect("apply logs in order");
    expected.compute_roots();
    assert_eq!(forest_block, 963, "the RPC candidate reaches the safe head");
    assert_eq!(forest.read().await.roots(), expected.roots());
    assert_eq!(
        forest_meta(&db, &chain),
        Some((963, [0x11; 32])),
        "the winner's target and confirmed hash are persisted"
    );
    let snapshot = merkletree::persist::MerkleForestSnapshot::load(
        &snapshot_path,
        chain.deployment.chain_id,
        chain.deployment.contract,
    )
    .expect("load snapshot")
    .expect("snapshot present");
    assert_eq!(snapshot.last_processed_block, 963);
    assert_eq!(snapshot.forest.roots(), expected.roots());

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn startup_forest_race_starts_no_rpc_candidate_over_budget_or_archive_boundary() {
    for (name, archive_until_block, learned_span) in
        [("over-budget", 0, Some(5)), ("archive-boundary", 10, None)]
    {
        let scope = test_scope();
        let rpc =
            JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 500, |_, _, _| None));
        let squid = GraphqlServer::spawn(vec![
            r#"{"data":{"squidStatus":{"height":"300"}}}"#,
            SQUID_EMPTY_COMMITMENTS,
        ]);
        let (root_dir, db) = open_forest_db(&format!("startup-forest-race-{name}"));
        let rpcs = Arc::new(QueryRpcPool::new(
            vec![rpc.url.clone()],
            Duration::from_secs(1),
        ));
        if let Some(span) = learned_span {
            // 500 blocks in 5-block requests is over the 64-request budget.
            rpcs.narrow_log_span(LogSpanEndpoint::Provider(0), span);
        }
        let mut chain = test_chain_config(&scope, rpcs, None);
        chain.sync.archive_until_block = archive_until_block;
        chain.sync.quick_sync_endpoint = Some(squid.url.clone());
        let events = CapturedEvents::default();
        let guard = events.capture();

        let (_, forest_block, _, _) = db
            .load_or_initialize_forest(&chain, 500, None, None)
            .await
            .expect("load startup forest");
        drop(guard);

        assert_eq!(
            forest_block, 300,
            "{name}: Squid catch-up applies as before"
        );
        assert_eq!(squid.requests.try_iter().count(), 2, "{name}");
        // The provider still confirms the Squid target.
        assert!(
            get_logs_ranges(&rpc.drain_request_bodies()).is_empty(),
            "{name}: no RPC forest candidate request"
        );
        let started = events.find("merkle forest catch-up race started");
        assert_eq!(
            started.get("candidates").map(String::as_str),
            Some("indexed"),
            "{name}"
        );
        assert!(race_finished_events(&events, "rpc").is_empty(), "{name}");

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }
}

#[tokio::test]
async fn stalled_artifact_gateway_lets_rpc_forest_candidate_win() {
    let scope = test_scope();
    let (gateway, gateway_port) = silent_server();
    let (squid, squid_port) = silent_server();
    let rpc = JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 500, |_, _, _| None));
    let rpc_port = rpc.url.port().expect("rpc port");
    let mut artifact_config = checkpointed_wallet_artifact_source(&scope, 1, 50, 50).config;
    let gateway_url = Url::parse(&format!("http://127.0.0.1:{gateway_port}")).expect("gateway url");
    artifact_config.manifest_source =
        IndexedArtifactManifestSource::Url(gateway_url.join("/manifest.json").expect("url"));
    artifact_config.gateway_urls = vec![gateway_url];
    let (root_dir, db) = open_forest_db("startup-forest-stalled-artifacts");
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![credential_url(rpc_port)],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, Some(artifact_config));
    chain.sync.quick_sync_endpoint = Some(credential_url(squid_port));
    let events = CapturedEvents::default();
    let guard = events.capture();

    let (_, forest_block, _, _) = db
        .load_or_initialize_forest(&chain, 500, None, None)
        .await
        .expect("load startup forest");
    // Give a request from the dropped indexed candidate time to arrive.
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(guard);

    assert_eq!(forest_block, 500, "the RPC candidate wins at the safe head");
    assert_eq!(forest_meta(&db, &chain), Some((500, [0x11; 32])));
    assert_eq!(
        drain_backlog_connections(&gateway),
        1,
        "only the stalled manifest request reaches the gateway"
    );
    assert_eq!(drain_backlog_connections(&squid), 0, "Squid is never asked");

    let started = events.find("merkle forest catch-up race started");
    for (field, value) in [
        ("tail_blocks", "500"),
        ("candidates", "indexed,rpc"),
        ("estimated_rpc_requests", "5"),
        ("rpc_request_budget", "64"),
    ] {
        assert_eq!(
            started.get(field).map(String::as_str),
            Some(value),
            "{field}"
        );
    }
    let rpc_end = race_finished_events(&events, "rpc");
    assert_eq!(rpc_end.len(), 1);
    for (field, value) in [
        ("outcome", "confirmed"),
        ("source", "rpc"),
        ("target", "500"),
        ("get_logs_requests", "5"),
    ] {
        assert_eq!(
            rpc_end[0].get(field).map(String::as_str),
            Some(value),
            "{field}"
        );
    }
    assert!(rpc_end[0].contains_key("elapsed_ms"));
    let indexed_end = race_finished_events(&events, "indexed");
    assert_eq!(indexed_end.len(), 1);
    assert_eq!(
        indexed_end[0].get("outcome").map(String::as_str),
        Some("cancelled")
    );
    let winner = events.find("merkle forest catch-up race won");
    assert_eq!(winner.get("source").map(String::as_str), Some("rpc"));
    assert_eq!(winner.get("target").map(String::as_str), Some("500"));
    assert!(winner.contains_key("elapsed_ms"));
    let endpoints = [rpc_port, squid_port, gateway_port].map(|port| format!("127.0.0.1:{port}"));
    for event in events.events() {
        for value in event.values() {
            assert!(
                ["secret", "user:", "key-abc"]
                    .into_iter()
                    .chain(endpoints.iter().map(String::as_str))
                    .all(|needle| !value.contains(needle)),
                "log value {value:?} exposes an endpoint"
            );
        }
    }

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn startup_forest_progress_stays_with_leading_rpc_candidate() {
    let scope = test_scope();
    let (artifact_source, manifest_block) =
        checkpointed_wallet_artifact_source_with_blocked_manifest(&scope, 1, 50, 50);
    let (release_last_page, last_page_gate) = std_mpsc::channel();
    let rpc = JsonRpcServer::spawn_handler(gated_get_logs_handler(
        log_range_rpc_handler(Vec::new(), 500, |_, _, _| None),
        vec![((401, 500), last_page_gate)],
    ));
    let (root_dir, db) = open_forest_db("startup-forest-monotonic-progress");
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, Some(artifact_source.config.clone()));
    let (progress_tx, progress_rx) = watch::channel(None);
    chain.progress_tx = Some(progress_tx);
    let events = CapturedEvents::default();
    let _guard = events.capture();
    let load = tokio::spawn({
        let db = Arc::clone(&db);
        async move {
            db.load_or_initialize_forest(&chain, 500, None, None)
                .await
                .map(|(_, forest_block, _, _)| forest_block)
        }
    });

    wait_for_std_signal(manifest_block.request_started, "artifact manifest request").await;
    yield_until("RPC pages before the gated one", || {
        progress_rx.borrow().is_some_and(|update| {
            update.unit == SyncProgressUnit::Block && update.current_block == 400
        })
    })
    .await;
    let leading = *progress_rx.borrow();
    // The lagging artifact candidate reports manifest progress, then yields nothing.
    manifest_block
        .release
        .send(())
        .expect("release artifact manifest");
    yield_until("indexed candidate end", || {
        !race_finished_events(&events, "indexed").is_empty()
    })
    .await;
    assert_eq!(
        *progress_rx.borrow(),
        leading,
        "artifact progress must not replace the leading block progress"
    );

    release_last_page.send(()).expect("release last RPC page");
    let forest_block = load
        .await
        .expect("startup forest task")
        .expect("load startup forest");
    assert_eq!(forest_block, 500);
    let last = progress_rx.borrow().expect("final progress");
    assert_eq!(
        (last.unit, last.current_block),
        (SyncProgressUnit::Block, 500)
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn startup_forest_relays_artifact_preparation_progress() {
    let scope = test_scope();
    let (artifact_source, manifest_block) =
        checkpointed_wallet_artifact_source_with_blocked_manifest(&scope, 1, 50, 50);
    let rpc = JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 500, |_, _, _| None));
    let (root_dir, db) = open_forest_db("startup-forest-artifact-preparation");
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, Some(artifact_source.config.clone()));
    // The tail starts below the archive boundary, so no RPC candidate
    // publishes block progress over the artifact preparation.
    chain.sync.archive_until_block = 10;
    let (progress_tx, progress_rx) = watch::channel(None);
    chain.progress_tx = Some(progress_tx);
    let load = tokio::spawn({
        let db = Arc::clone(&db);
        async move {
            db.load_or_initialize_forest(&chain, 500, None, None)
                .await
                .map(|_| ())
        }
    });

    wait_for_std_signal(manifest_block.request_started, "artifact manifest request").await;
    yield_until("manifest start progress", || {
        progress_rx.borrow().is_some_and(|update| {
            update.unit == SyncProgressUnit::ArtifactPreparation && update.current_block == 5
        })
    })
    .await;

    manifest_block
        .release
        .send(())
        .expect("release artifact manifest");
    load.await
        .expect("startup forest task")
        .expect("load startup forest");

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn fast_artifact_forest_candidate_wins_and_stops_rpc_candidate() {
    let scope = test_scope();
    let leaves = [(0, U256::from(11)), (1, U256::from(12))];
    // Indexed through block 120 with the hash the confirming provider serves.
    // Confirmation waits until the RPC candidate has published its first page.
    let artifact_source = commitment_artifact_source(&scope, 120, [0x11; 32], 110, &leaves);
    let (release_confirmation, confirmation_gate) = std_mpsc::channel::<()>();
    let serve_confirmer = log_range_rpc_handler(Vec::new(), 500, |_, _, _| None);
    let confirmer = JsonRpcServer::spawn_handler(move |request: &serde_json::Value| {
        if request["method"] == "eth_getBlockByNumber" {
            let _ = confirmation_gate.recv();
        }
        serve_confirmer(request)
    });
    let (second_page_started_tx, second_page_started) = std_mpsc::channel();
    let (release_second_page, second_page_gate) = std_mpsc::channel();
    let serve_pool = gated_get_logs_handler(
        log_range_rpc_handler(Vec::new(), 500, |_, _, _| None),
        vec![((101, 200), second_page_gate)],
    );
    let pool_rpc = JsonRpcServer::spawn_handler(move |request: &serde_json::Value| {
        if request["method"] == "eth_getLogs"
            && hex_quantity(&request["params"][0]["fromBlock"]) == 101
        {
            let _ = second_page_started_tx.send(());
        }
        serve_pool(request)
    });
    let (root_dir, db) = open_forest_db("startup-forest-fast-artifacts");
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![pool_rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, Some(artifact_source.config.clone()));
    let (progress_tx, progress_rx) = watch::channel(None);
    chain.progress_tx = Some(progress_tx);
    let provider = QueryRpcPool::new(vec![confirmer.url.clone()], Duration::from_secs(1))
        .random_provider()
        .expect("confirming provider");
    let events = CapturedEvents::default();
    let _guard = events.capture();

    // The second page's request follows delivery of the first page.
    let confirm_after_first_page = async move {
        wait_for_std_signal(second_page_started, "second RPC page request").await;
        drop(release_confirmation);
    };
    let (loaded, ()) = tokio::join!(
        db.load_or_initialize_forest(&chain, 500, Some(&provider), None),
        confirm_after_first_page
    );
    let (forest, forest_block, _, _) = loaded.expect("load startup forest");

    assert_eq!(
        forest_block, 120,
        "the artifact candidate wins at its target"
    );
    assert_eq!(forest_meta(&db, &chain), Some((120, [0x11; 32])));
    let mut expected = MerkleForest::new();
    for (tree_position, hash) in leaves {
        expected
            .insert_leaf(MerkleTreeUpdate {
                tree_number: 0,
                tree_position,
                hash,
            })
            .expect("insert expected leaf");
    }
    expected.compute_roots();
    assert_eq!(forest.read().await.roots(), expected.roots());
    let last = progress_rx.borrow().expect("final progress");
    assert_eq!(
        last.unit,
        SyncProgressUnit::ArtifactApplied,
        "the winner's completion follows the loser's block progress"
    );
    let rpc_end = race_finished_events(&events, "rpc");
    assert_eq!(rpc_end.len(), 1);
    assert_eq!(
        rpc_end[0].get("outcome").map(String::as_str),
        Some("cancelled")
    );
    assert_eq!(
        rpc_end[0].get("get_logs_requests").map(String::as_str),
        Some("2"),
        "the held second page counts"
    );
    // The held page arrived before the win; free it.
    pool_rpc.drain_request_bodies();
    release_second_page
        .send(())
        .expect("release second RPC page");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        pool_rpc.drain_request_bodies().is_empty(),
        "the cancelled RPC candidate sends no further request"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn failed_forest_race_keeps_loaded_forest_and_writes_nothing() {
    let scope = test_scope();
    let leaves = [(0, U256::from(11)), (1, U256::from(12))];
    // The confirming provider serves hash 0x11 for the artifact target.
    let artifact_source = commitment_artifact_source(&scope, 120, [0x44; 32], 110, &leaves);
    let confirmer =
        JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 500, |_, _, _| None));
    let failing =
        JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 500, |_, _, _| {
            Some(rpc_error(-32000, "unavailable"))
        }));
    let (root_dir, db) = open_forest_db("startup-forest-race-fails");
    // Without a cooldown, the failed provider's index stays available, so the
    // artifact target is still confirmed on the passed-in provider.
    let rpcs = Arc::new(QueryRpcPool::new(vec![failing.url.clone()], Duration::ZERO));
    let chain = test_chain_config(&scope, rpcs, Some(artifact_source.config.clone()));
    let provider = QueryRpcPool::new(vec![confirmer.url.clone()], Duration::from_secs(1))
        .random_provider()
        .expect("confirming provider");
    // The loaded block's hash is canonical, so the race runs.
    let (loaded, snapshot_path, snapshot_bytes) = seed_loaded_forest(&db, &chain, 10, [0x11; 32]);
    let events = CapturedEvents::default();
    let guard = events.capture();

    let (forest, forest_block, _, _) = db
        .load_or_initialize_forest(&chain, 500, Some(&provider), None)
        .await
        .expect("load startup forest");
    drop(guard);

    events.find(
        "artifact-backed merkle forest target hash mismatch; falling back to configured indexed sources",
    );
    assert!(
        !get_logs_ranges(&failing.drain_request_bodies()).is_empty(),
        "the RPC candidate ran and failed"
    );
    assert_eq!(forest_block, 10, "startup keeps the loaded forest");
    assert_eq!(forest.read().await.roots(), loaded.roots());
    assert_eq!(forest_meta(&db, &chain), Some((10, [0x11; 32])));
    assert_eq!(
        fs::read(&snapshot_path).expect("read snapshot"),
        snapshot_bytes,
        "no candidate writes the snapshot"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn reorged_loaded_forest_skips_startup_catch_up() {
    let scope = test_scope();
    let leaves = [(0, U256::from(11)), (1, U256::from(12))];
    // Would win the race: indexed through block 120 with the served hash.
    let artifact_source = commitment_artifact_source(&scope, 120, [0x11; 32], 110, &leaves);
    // Serves hash 0x11 for every block, so the loaded block 10 has reorged.
    let rpc = JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 500, |_, _, _| None));
    let (root_dir, db) = open_forest_db("startup-forest-reorged");
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let chain = test_chain_config(&scope, rpcs, Some(artifact_source.config.clone()));
    let provider = QueryRpcPool::new(vec![rpc.url.clone()], Duration::from_secs(1))
        .random_provider()
        .expect("provider");
    let (loaded, snapshot_path, snapshot_bytes) = seed_loaded_forest(&db, &chain, 10, [0x10; 32]);

    let (forest, forest_block, _, _) = db
        .load_or_initialize_forest(&chain, 500, Some(&provider), None)
        .await
        .expect("load startup forest");

    assert_eq!(forest_block, 10, "the live reorg check owns the rewind");
    assert_eq!(forest.read().await.roots(), loaded.roots());
    assert_eq!(
        forest_meta(&db, &chain),
        Some((10, [0x10; 32])),
        "the metadata that shows the reorg is kept"
    );
    assert_eq!(
        fs::read(&snapshot_path).expect("read snapshot"),
        snapshot_bytes
    );
    assert!(
        get_logs_ranges(&rpc.drain_request_bodies()).is_empty(),
        "no RPC candidate"
    );
    assert_eq!(
        artifact_source.server.request_count(),
        0,
        "no artifact candidate"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test(start_paused = true)]
async fn headless_chain_start_skips_forest_catch_up_and_live_loop_rewinds_first() {
    let scope = test_scope();
    let (squid, squid_port) = silent_server();
    let (gateway, gateway_port) = silent_server();
    let gateway_url = Url::parse(&format!("http://127.0.0.1:{gateway_port}")).expect("gateway URL");
    // Every provider hangs until `recovered`. It then serves hash 0x11 for
    // every block and holds range reads until `logs_released`.
    let recovered = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let logs_released = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hung_reads = Arc::new(AtomicU64::new(0));
    let rpc_servers = (0..3)
        .map(|_| {
            let recovered = Arc::clone(&recovered);
            let logs_released = Arc::clone(&logs_released);
            let hung_reads = Arc::clone(&hung_reads);
            let serve = log_range_rpc_handler(Vec::new(), 200, |_, _, _| None);
            JsonRpcServer::spawn_handler(move |request| {
                if !recovered.load(Ordering::Acquire) {
                    hung_reads.fetch_add(1, Ordering::AcqRel);
                    while !recovered.load(Ordering::Acquire) {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
                if request["method"] == "eth_getLogs" {
                    while !logs_released.load(Ordering::Acquire) {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
                serve(request)
            })
        })
        .collect::<Vec<_>>();
    let (root_dir, db) = open_forest_db("headless-chain-start");
    let rpcs = Arc::new(QueryRpcPool::new(
        rpc_servers
            .iter()
            .map(|server| server.url.clone())
            .collect(),
        Duration::from_mins(1),
    ));
    let mut chain = test_chain_config(
        &scope,
        rpcs,
        Some(IndexedArtifactSourceConfig {
            trusted_publisher_pubkey: FixedBytes::ZERO,
            manifest_source: IndexedArtifactManifestSource::Url(
                gateway_url.join("/manifest.json").expect("manifest URL"),
            ),
            gateway_urls: vec![gateway_url],
            gateway_pool: None,
            manifest_reuse: crate::IndexedArtifactManifestReuse::default(),
            max_manifest_age: None,
            concurrency: 1,
            max_in_flight_bytes: 1024 * 1024,
        }),
    );
    chain.sync.quick_sync_endpoint =
        Some(Url::parse(&format!("http://127.0.0.1:{squid_port}")).expect("Squid URL"));
    seed_loaded_forest(&db, &chain, 50, [0xaa; 32]);
    let lease = crate::runtime_admission::DbRuntimeLease::acquire(
        &db,
        crate::runtime_admission::DbRuntimeOwnerKind::SyncManager,
    )
    .expect("runtime lease");

    let started = tokio::time::Instant::now();
    let prepare = tokio::spawn(ChainService::prepare(
        Arc::clone(&db),
        chain,
        test_proxy_poi_policy(),
        lease,
        None,
    ));
    // Busy-yielding keeps the paused clock still until every provider holds
    // a head read. Each provider then stays blocked, so chain start could
    // not finish if it sent any provider another request.
    yield_until("hung head reads", || {
        hung_reads.load(Ordering::Acquire) == 3
    })
    .await;
    tokio::time::advance(INITIAL_HEAD_DEADLINE).await;
    yield_until("chain start", || prepare.is_finished()).await;
    let prepared = prepare
        .await
        .expect("chain start task")
        .expect("chain start without a safe head");

    assert_eq!(
        started.elapsed(),
        INITIAL_HEAD_DEADLINE,
        "chain start waits only for the head deadline"
    );
    assert_eq!(drain_backlog_connections(&squid), 0, "no Squid request");
    assert_eq!(drain_backlog_connections(&gateway), 0, "no gateway request");

    // The providers recover and report a different hash for the loaded block.
    let service = prepared.activate();
    let forest_rx = service.forest_last_tx.subscribe();
    assert_eq!(*forest_rx.borrow(), 50);
    recovered.store(true, Ordering::Release);
    // Range reads are held, so no log can apply before the rewind.
    yield_until("reorg rewind", || *forest_rx.borrow() == 0).await;
    assert_eq!(*service.safe_head_tx.borrow(), 200);

    logs_released.store(true, Ordering::Release);
    service.shutdown().await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

const SQUID_HEIGHT_300: &str = r#"{"data":{"squidStatus":{"height":"300"}}}"#;

/// Two tree-0 leaves at block 110, served by the commitment artifact fixtures.
fn artifact_forest_leaves() -> [(u64, U256); 2] {
    [(0, U256::from(11)), (1, U256::from(12))]
}

/// Chain config with the artifact source and Squid endpoint configured, and a
/// pool that confirms indexed targets through `confirmer` but starts no RPC
/// forest candidate.
fn indexed_forest_chain(
    artifact_config: IndexedArtifactSourceConfig,
    squid_url: Url,
    confirmer: &Url,
) -> ChainConfig {
    let mut chain = test_chain_config(
        &test_scope(),
        confirming_pool_without_rpc_candidate(confirmer),
        Some(artifact_config),
    );
    chain.sync.quick_sync_endpoint = Some(squid_url);
    chain
}

/// Loads the startup forest on a separate task, returning the forest block.
fn spawn_forest_load(
    db: &Arc<DbStore>,
    chain: &ChainConfig,
    safe_head: u64,
) -> tokio::task::JoinHandle<u64> {
    let db = Arc::clone(db);
    let chain = chain.clone();
    tokio::spawn(async move {
        db.load_or_initialize_forest(&chain, safe_head, None, None)
            .await
            .map(|(_, forest_block, _, _)| forest_block)
            .expect("load startup forest")
    })
}

#[tokio::test]
async fn unconfirmed_artifact_forest_candidate_keeps_loaded_forest() {
    let scope = test_scope();
    // Carries its own hash for block 120, but no provider can confirm it.
    let artifact_source =
        commitment_artifact_source(&scope, 120, [0x11; 32], 110, &artifact_forest_leaves());
    let (root_dir, db) = open_forest_db("startup-forest-unconfirmed-artifacts");
    let rpcs = Arc::new(QueryRpcPool::new(Vec::new(), Duration::from_secs(1)));
    let chain = test_chain_config(&scope, rpcs, Some(artifact_source.config.clone()));
    let (loaded, snapshot_path, snapshot_bytes) = seed_loaded_forest(&db, &chain, 10, [0x10; 32]);
    let events = CapturedEvents::default();
    let guard = events.capture();

    let (forest, forest_block, _, _) = db
        .load_or_initialize_forest(&chain, 500, None, None)
        .await
        .expect("load startup forest");
    drop(guard);

    let unconfirmed =
        events.find("no provider available to confirm the indexed merkle forest target");
    assert_eq!(
        unconfirmed.get("source").map(String::as_str),
        Some("indexed_artifacts")
    );
    assert_eq!(unconfirmed.get("target").map(String::as_str), Some("120"));
    assert_eq!(forest_block, 10, "startup keeps the loaded forest");
    assert_eq!(forest.read().await.roots(), loaded.roots());
    assert_eq!(forest_meta(&db, &chain), Some((10, [0x10; 32])));
    assert_eq!(
        fs::read(&snapshot_path).expect("read snapshot"),
        snapshot_bytes,
        "the unconfirmed artifact forest is not persisted"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn artifact_forest_squid_step_follows_tail_length_and_confirmation() {
    // Artifacts confirm at block 120; Squid is indexed through 300.
    for (name, safe_head, squid_target_confirmed, forest_target, squid_requests) in [
        ("one-page-tail", 200, true, 120, 0),
        ("long-tail", 500, true, 300, 2),
        ("long-tail-unconfirmed-squid", 500, false, 120, 2),
    ] {
        let scope = test_scope();
        let artifact_source =
            commitment_artifact_source(&scope, 120, [0x11; 32], 110, &artifact_forest_leaves());
        let squid = GraphqlServer::spawn(vec![SQUID_HEIGHT_300, SQUID_EMPTY_COMMITMENTS]);
        let serve = log_range_rpc_handler(Vec::new(), 500, |_, _, _| None);
        let confirmer = JsonRpcServer::spawn_handler(move |request: &serde_json::Value| {
            if !squid_target_confirmed
                && request["method"] == "eth_getBlockByNumber"
                && hex_quantity(&request["params"][0]) == 300
            {
                return serde_json::json!({ "result": null });
            }
            serve(request)
        });
        let (root_dir, db) = open_forest_db(&format!("startup-forest-squid-step-{name}"));
        let chain = indexed_forest_chain(
            artifact_source.config.clone(),
            squid.url.clone(),
            &confirmer.url,
        );
        let events = CapturedEvents::default();
        let guard = events.capture();

        let (_, forest_block, _, _) = db
            .load_or_initialize_forest(&chain, safe_head, None, None)
            .await
            .expect("load startup forest");
        drop(guard);

        assert_eq!(forest_block, forest_target, "{name}");
        assert_eq!(
            forest_meta(&db, &chain),
            Some((forest_target, [0x11; 32])),
            "{name}"
        );
        let requests = squid.requests.try_iter().collect::<Vec<_>>();
        assert_eq!(requests.len(), squid_requests, "{name}");
        if let Some(commitments) = requests.get(1) {
            assert_eq!(
                json_rpc_request_body(commitments)["variables"]["blockNumber"],
                "121",
                "{name}: Squid runs on top of the artifact forest"
            );
        } else {
            // Nor does a Squid hedge start while artifacts finish in time.
            let skipped = events.find("Squid step skipped for one-page tail");
            assert_eq!(skipped.get("tail_blocks").map(String::as_str), Some("80"));
        }

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }
}

#[tokio::test(start_paused = true)]
async fn artifact_forest_at_safe_head_does_not_wait_on_hung_squid() {
    let scope = test_scope();
    let artifact_source =
        commitment_artifact_source(&scope, 120, [0x11; 32], 110, &artifact_forest_leaves());
    let (squid, squid_port) = silent_server();
    let confirmer =
        JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 500, |_, _, _| None));
    let (root_dir, db) = open_forest_db("startup-forest-artifacts-at-safe-head");
    let chain = indexed_forest_chain(
        artifact_source.config.clone(),
        Url::parse(&format!("http://127.0.0.1:{squid_port}")).expect("squid url"),
        &confirmer.url,
    );

    // A 120-block tail from block 1 that artifacts close exactly.
    let load = spawn_forest_load(&db, &chain, 120);
    // The paused clock stands still, so the load cannot wait on Squid or a timer.
    yield_until("artifact forest installed", || load.is_finished()).await;

    assert_eq!(load.await.expect("startup forest task"), 120);
    assert_eq!(forest_meta(&db, &chain), Some((120, [0x11; 32])));
    assert_eq!(drain_backlog_connections(&squid), 0, "Squid is never asked");

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test(start_paused = true)]
async fn hung_squid_step_returns_artifact_forest_at_deadline() {
    let scope = test_scope();
    let artifact_source =
        commitment_artifact_source(&scope, 120, [0x11; 32], 110, &artifact_forest_leaves());
    let (squid, squid_status) =
        GraphqlServer::spawn_with_blocked_response(vec![SQUID_HEIGHT_300], 0);
    let confirmer =
        JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 500, |_, _, _| None));
    let (root_dir, db) = open_forest_db("startup-forest-hung-squid-step");
    let chain = indexed_forest_chain(
        artifact_source.config.clone(),
        squid.url.clone(),
        &confirmer.url,
    );
    let events = CapturedEvents::default();
    let _guard = events.capture();

    let load = spawn_forest_load(&db, &chain, 500);
    yield_until("Squid status request", || {
        squid_status.request_started.try_recv().is_ok()
    })
    .await;
    tokio::time::advance(
        super::logs::INDEXED_SQUID_STEP_DEADLINE.saturating_sub(Duration::from_secs(1)),
    )
    .await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert!(
        !load.is_finished(),
        "the Squid step runs until its deadline"
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    yield_until("artifact forest installed", || load.is_finished()).await;

    assert_eq!(load.await.expect("startup forest task"), 120);
    assert_eq!(forest_meta(&db, &chain), Some((120, [0x11; 32])));
    let passed = events.find("Squid step deadline passed");
    assert_eq!(passed.get("tail_blocks").map(String::as_str), Some("380"));
    assert!(passed.contains_key("elapsed_ms"));
    squid_status.release.send(()).expect("release Squid status");

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test(start_paused = true)]
async fn hung_artifacts_start_squid_hedge_after_delay() {
    let hedge_delay = super::forest_db::FOREST_SQUID_HEDGE_DELAY;
    let scope = test_scope();
    let (artifact_source, manifest_block) = commitment_artifact_source_with_blocked_manifest(
        &scope,
        120,
        [0x11; 32],
        110,
        &artifact_forest_leaves(),
    );
    let squid = GraphqlServer::spawn(vec![SQUID_HEIGHT_300, SQUID_EMPTY_COMMITMENTS]);
    let confirmer =
        JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 500, |_, _, _| None));
    let (root_dir, db) = open_forest_db("startup-forest-hung-artifacts");
    let chain = indexed_forest_chain(
        artifact_source.config.clone(),
        squid.url.clone(),
        &confirmer.url,
    );
    let events = CapturedEvents::default();
    let _guard = events.capture();

    let load = spawn_forest_load(&db, &chain, 500);
    yield_until("artifact manifest request", || {
        manifest_block.request_started.try_recv().is_ok()
    })
    .await;
    tokio::time::advance(hedge_delay.saturating_sub(Duration::from_secs(1))).await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        squid.requests.try_iter().count(),
        0,
        "no Squid request before the hedge delay"
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    yield_until("Squid forest installed", || load.is_finished()).await;

    assert_eq!(load.await.expect("startup forest task"), 300);
    assert_eq!(forest_meta(&db, &chain), Some((300, [0x11; 32])));
    let requests = squid.requests.try_iter().collect::<Vec<_>>();
    assert_eq!(requests.len(), 2, "Squid height and commitments");
    assert_eq!(
        json_rpc_request_body(&requests[1])["variables"]["blockNumber"],
        "1",
        "Squid catches up from the loaded forest"
    );
    assert_eq!(
        artifact_source.server.request_count(),
        1,
        "the dropped artifact candidate sends nothing after the held manifest"
    );
    let hedge = events.find("artifact forest hedge started");
    assert_eq!(
        hedge.get("trigger").map(String::as_str),
        Some("hedge_delay")
    );
    assert!(hedge.contains_key("elapsed_ms"));
    manifest_block
        .release
        .send(())
        .expect("release artifact manifest");

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test(start_paused = true)]
async fn failed_artifacts_start_squid_hedge_without_delay() {
    let scope = test_scope();
    // Wallet-scan artifacts only, so forest artifact catch-up yields nothing.
    let artifact_source = checkpointed_wallet_artifact_source(&scope, 1, 50, 50);
    let squid = GraphqlServer::spawn(vec![SQUID_HEIGHT_300, SQUID_EMPTY_COMMITMENTS]);
    let confirmer =
        JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 500, |_, _, _| None));
    let (root_dir, db) = open_forest_db("startup-forest-failed-artifacts");
    let chain = indexed_forest_chain(
        artifact_source.config.clone(),
        squid.url.clone(),
        &confirmer.url,
    );

    let load = spawn_forest_load(&db, &chain, 500);
    // The paused clock stands still, so the hedge delay never elapses.
    yield_until("Squid forest installed", || load.is_finished()).await;

    assert_eq!(load.await.expect("startup forest task"), 300);
    assert!(
        artifact_source.server.request_count() > 0,
        "artifacts ran first"
    );
    assert_eq!(squid.requests.try_iter().count(), 2);
    assert_eq!(forest_meta(&db, &chain), Some((300, [0x11; 32])));

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test(start_paused = true)]
async fn unconfirmed_squid_hedge_leaves_artifact_candidate_running() {
    let scope = test_scope();
    let (artifact_source, manifest_block) = commitment_artifact_source_with_blocked_manifest(
        &scope,
        120,
        [0x11; 32],
        110,
        &artifact_forest_leaves(),
    );
    // The hedge from the loaded forest, then the step on top of artifacts.
    let squid = GraphqlServer::spawn(vec![
        SQUID_HEIGHT_300,
        SQUID_EMPTY_COMMITMENTS,
        SQUID_HEIGHT_300,
        SQUID_EMPTY_COMMITMENTS,
    ]);
    // Returns no block for the Squid target.
    let serve = log_range_rpc_handler(Vec::new(), 500, |_, _, _| None);
    let confirmer = JsonRpcServer::spawn_handler(move |request: &serde_json::Value| {
        if request["method"] == "eth_getBlockByNumber" && hex_quantity(&request["params"][0]) == 300
        {
            return serde_json::json!({ "result": null });
        }
        serve(request)
    });
    let (root_dir, db) = open_forest_db("startup-forest-unconfirmed-squid-hedge");
    let chain = indexed_forest_chain(
        artifact_source.config.clone(),
        squid.url.clone(),
        &confirmer.url,
    );
    let events = CapturedEvents::default();
    let _guard = events.capture();
    let squid_unconfirmed = || {
        events.events().iter().any(|event| {
            event.get("message").is_some_and(|message| {
                message == "indexed merkle forest target block hash unconfirmed"
            }) && event.get("source").is_some_and(|source| source == "squid")
        })
    };

    let load = spawn_forest_load(&db, &chain, 500);
    yield_until("artifact manifest request", || {
        manifest_block.request_started.try_recv().is_ok()
    })
    .await;
    tokio::time::advance(super::forest_db::FOREST_SQUID_HEDGE_DELAY).await;
    yield_until("unconfirmed Squid hedge", squid_unconfirmed).await;
    manifest_block
        .release
        .send(())
        .expect("release artifact manifest");
    yield_until("artifact forest installed", || load.is_finished()).await;

    assert_eq!(load.await.expect("startup forest task"), 120);
    assert_eq!(
        forest_meta(&db, &chain),
        Some((120, [0x11; 32])),
        "only the confirmed artifact forest is persisted"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

struct LiveForestFixture {
    root_dir: PathBuf,
    service: Arc<ChainService>,
    forest_rx: watch::Receiver<u64>,
    snapshot_path: PathBuf,
    task: tokio::task::JoinHandle<()>,
}

impl LiveForestFixture {
    /// Starts the live forest loop at `forest_block` behind a fixed
    /// `safe_head`, with the given RPC endpoints and a Squid endpoint.
    async fn spawn(
        name: &str,
        rpc_urls: Vec<Url>,
        squid_url: Url,
        forest_block: u64,
        safe_head: u64,
    ) -> Self {
        let rpcs = Arc::new(QueryRpcPool::new(rpc_urls, Duration::from_secs(1)));
        Self::spawn_with(
            name,
            rpcs,
            forest_block,
            safe_head,
            ChainPoiSubmitterHandle::detached_for_test(),
            |chain| {
                chain.sync.quick_sync_endpoint = Some(squid_url);
            },
        )
        .await
    }

    /// Starts the live forest loop with 10-block pages, so a lag of more than
    /// 640 blocks is far behind, one provider that stays available after a
    /// failed request, and a Squid endpoint.
    async fn spawn_far_behind(
        name: &str,
        rpc_url: Url,
        squid_url: Url,
        forest_block: u64,
        safe_head: u64,
        progress_tx: Option<crate::types::SyncProgressSender>,
    ) -> Self {
        let rpcs = Arc::new(QueryRpcPool::new(vec![rpc_url], Duration::ZERO));
        Self::spawn_with(
            name,
            rpcs,
            forest_block,
            safe_head,
            ChainPoiSubmitterHandle::detached_for_test(),
            move |chain| {
                chain.sync.block_range = 10;
                chain.sync.quick_sync_endpoint = Some(squid_url);
                chain.progress_tx = progress_tx;
            },
        )
        .await
    }

    async fn spawn_with(
        name: &str,
        rpcs: Arc<QueryRpcPool>,
        forest_block: u64,
        safe_head: u64,
        poi_submitter: ChainPoiSubmitterHandle,
        configure: impl FnOnce(&mut ChainConfig),
    ) -> Self {
        let root_dir = temp_db_root(name);
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        db.ensure_blob_dir("merkle_forest")
            .expect("create merkle forest blob dir");
        let snapshot_path = db.resolve_path(&DbStore::relative_blob_path(
            "merkle_forest",
            "live-forest.msgpack",
        ));
        let mut chain = test_chain_config(&test_scope(), Arc::clone(&rpcs), None);
        configure(&mut chain);
        let public_data_plane =
            ChainPublicDataPlane::new(Arc::clone(&db), Arc::new(AtomicU64::new(0)));
        let service = test_chain_service_with_poi_submitter(
            db,
            chain,
            public_data_plane,
            test_proxy_poi_policy(),
            poi_submitter,
        )
        .0;
        service.forest_last_tx.send_replace(forest_block);
        service.safe_head_tx.send_replace(safe_head);
        let forest_rx = service.forest_last_tx.subscribe();
        let task = spawn_live_log_loop(
            Arc::clone(&service),
            rpcs,
            None,
            service.forest_last_tx.subscribe(),
            service.safe_head_tx.subscribe(),
            snapshot_path.clone(),
            service.cancel.clone(),
        );
        // Let the loop start its stall period at the current paused instant.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        Self {
            root_dir,
            service,
            forest_rx,
            snapshot_path,
            task,
        }
    }

    fn meta(&self) -> Option<(u64, [u8; 32])> {
        forest_meta(&self.service.db, &self.service.chain)
    }

    /// Last block of the persisted forest snapshot, if one was written.
    fn snapshot_block(&self) -> Option<u64> {
        let deployment = &self.service.chain.deployment;
        merkletree::persist::MerkleForestSnapshot::load(
            &self.snapshot_path,
            deployment.chain_id,
            deployment.contract,
        )
        .expect("read forest snapshot")
        .map(|snapshot| snapshot.last_processed_block)
    }

    fn stall_period(&self) -> Duration {
        wallet_tail_fallback_stale_timeout(self.service.chain.block_time)
    }

    async fn stop(self) {
        let Self {
            root_dir,
            service,
            task,
            ..
        } = self;
        service.cancel.cancel();
        task.await.expect("live forest loop exits");
        drop(service);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }
}

/// Yields until `ready` holds. Busy-yielding keeps a paused clock from
/// auto-advancing while mock servers answer on OS threads.
async fn yield_until(what: &str, mut ready: impl FnMut() -> bool) {
    let started = std::time::Instant::now();
    while !ready() {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "timed out waiting for {what}"
        );
        tokio::task::yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn stalled_live_forest_catches_up_from_squid_when_rpc_pages_fail() {
    let scope = test_scope();
    // The one indexed commitment is a prepared output at tree 0, position 1.
    let squid = GraphqlServer::spawn(vec![
        r#"{"data":{"squidStatus":{"height":"150"}}}"#,
        r#"{"data":{"commitments":[{"id":"0x11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111","treeNumber":"0","treePosition":"1","batchStartTreePosition":"1","blockNumber":"100","hash":"77"}]}}"#,
    ]);
    let prepared = FixedBytes::from(U256::from(77).to_be_bytes::<32>());
    let list = FixedBytes::from([0x1a; 32]);
    // Confirms the Squid target; getLogs fails so RPC cannot advance.
    let rpc = JsonRpcServer::spawn_handler(|request| match request["method"].as_str() {
        Some("eth_getBlockByNumber") => {
            let block_number = hex_quantity(&request["params"][0]);
            serde_json::json!({
                "result": rpc_block(block_number, test_block_timestamp(block_number), 0x11),
            })
        }
        _ => serde_json::json!({ "error": rpc_error(-32000, "unavailable") }),
    });
    let transport = Arc::new(RecordingPoiTransport::default());
    let submitter_cancel = CancellationToken::new();
    let (poi_submitter, submitter_task) = ChainPoiSubmitterHandle::spawn_for_test(
        scope.chain_id,
        Arc::clone(&transport) as Arc<dyn crate::wallet::PendingOutputPoiSubmitter>,
        submitter_cancel.clone(),
    );
    poi_submitter
        .prepare(vec![poi::poi::SingleCommitmentProofContext {
            txid_version: DEFAULT_TXID_VERSION.to_string(),
            railgun_txid: U256::from(7),
            utxo_tree_in: 0,
            commitment: prepared,
            npk: FixedBytes::from([0x22; 32]),
            pre_transaction_pois_per_txid_leaf_per_list: BTreeMap::from([(list, BTreeMap::new())]),
        }])
        .await
        .expect("prepare output context");
    let events = CapturedEvents::default();
    let _guard = events.capture();
    let squid_url = squid.url.clone();
    let fixture = LiveForestFixture::spawn_with(
        "live-forest-stall-squid",
        Arc::new(QueryRpcPool::new(
            vec![rpc.url.clone()],
            Duration::from_secs(1),
        )),
        50,
        200,
        poi_submitter,
        move |chain| {
            chain.sync.quick_sync_endpoint = Some(squid_url);
        },
    )
    .await;
    let stall = fixture.stall_period();

    tokio::time::advance(stall.saturating_sub(Duration::from_secs(1))).await;
    assert_eq!(
        squid.requests.try_iter().count(),
        0,
        "no Squid request before the stall period"
    );

    tokio::time::advance(Duration::from_secs(1)).await;
    yield_until("Squid stall fallback", || {
        *fixture.forest_rx.borrow() == 150
    })
    .await;
    assert_eq!(
        squid.requests.try_iter().count(),
        2,
        "Squid height and commitments"
    );
    let chain = &fixture.service.chain;
    let meta = fixture
        .service
        .db
        .get_merkle_forest_meta(
            chain.deployment.chain_id,
            &chain.deployment.contract.to_string(),
        )
        .expect("read forest meta")
        .expect("forest meta persisted");
    assert_eq!(meta.last_block, 150);
    let records = events.with_message("live forest progress");
    assert_eq!(
        records.len(),
        1,
        "one record per published block: {records:?}"
    );
    assert_eq!(
        (
            records[0].get("cause").map(String::as_str),
            records[0].get("forest_block").map(String::as_str),
        ),
        (Some("stall_install"), Some("150"))
    );
    yield_until("PPOI send", || !transport.sends().is_empty()).await;
    assert_eq!(
        transport.sends(),
        vec![RecordedSend {
            commitment: prepared,
            tree: 0,
            position: 1,
            lists: vec![list],
        }]
    );

    fixture.stop().await;
    submitter_cancel.cancel();
    submitter_task.await.expect("submitter exits");
}

#[tokio::test(start_paused = true)]
async fn advancing_live_forest_issues_no_squid_requests() {
    let squid = GraphqlServer::spawn(vec![r#"{"data":{"squidStatus":{"height":"400"}}}"#]);
    let (release_page, page_gate) = std_mpsc::channel::<()>();
    let serve = log_range_rpc_handler(Vec::new(), 400, |_, _, _| None);
    let rpc = JsonRpcServer::spawn_handler(move |request| {
        if request["method"] == "eth_getLogs" {
            // Hold each page until the test has advanced the paused clock.
            let _ = page_gate.recv();
        }
        serve(request)
    });
    let fixture = LiveForestFixture::spawn(
        "live-forest-advancing",
        vec![rpc.url.clone()],
        squid.url.clone(),
        0,
        400,
    )
    .await;
    let stall = fixture.stall_period();
    fixture
        .service
        .safe_head_tx
        .send(400)
        .expect("wake live loop");

    // Each page lands within the stall period; together they span more than it.
    for page in 1..=3_u64 {
        tokio::time::advance(stall.saturating_sub(Duration::from_secs(20))).await;
        release_page.send(()).expect("release live page");
        yield_until("live forest page", || {
            *fixture.forest_rx.borrow() == page * 100
        })
        .await;
    }
    assert_eq!(squid.requests.try_iter().count(), 0);

    fixture.stop().await;
}

#[tokio::test(start_paused = true)]
async fn live_batch_sends_prepared_output_ppoi_proofs() {
    let scope = test_scope();
    let prepared = FixedBytes::from([0xc2; 32]);
    let list = FixedBytes::from([0x1a; 32]);
    let log = rpc_transact_outputs_log(
        scope.railgun_contract,
        50,
        vec![FixedBytes::from([0xc1; 32]), prepared],
    );
    let rpc = JsonRpcServer::spawn_handler(log_range_rpc_handler(vec![log], 100, |_, _, _| None));
    let transport = Arc::new(RecordingPoiTransport::default());
    let submitter_cancel = CancellationToken::new();
    let (poi_submitter, submitter_task) = ChainPoiSubmitterHandle::spawn_for_test(
        scope.chain_id,
        Arc::clone(&transport) as Arc<dyn crate::wallet::PendingOutputPoiSubmitter>,
        submitter_cancel.clone(),
    );
    poi_submitter
        .prepare(vec![poi::poi::SingleCommitmentProofContext {
            txid_version: DEFAULT_TXID_VERSION.to_string(),
            railgun_txid: U256::from(7),
            utxo_tree_in: 0,
            commitment: prepared,
            npk: FixedBytes::from([0x22; 32]),
            pre_transaction_pois_per_txid_leaf_per_list: BTreeMap::from([(list, BTreeMap::new())]),
        }])
        .await
        .expect("prepare output context");
    let fixture = LiveForestFixture::spawn_with(
        "live-forest-ppoi-submit",
        Arc::new(QueryRpcPool::new(
            vec![rpc.url.clone()],
            Duration::from_secs(1),
        )),
        0,
        100,
        poi_submitter,
        |_| {},
    )
    .await;
    fixture
        .service
        .safe_head_tx
        .send(100)
        .expect("wake live loop");

    yield_until("live batch applied", || *fixture.forest_rx.borrow() == 100).await;
    yield_until("PPOI send", || !transport.sends().is_empty()).await;
    assert_eq!(
        transport.sends(),
        vec![RecordedSend {
            commitment: prepared,
            tree: 0,
            position: 1,
            lists: vec![list],
        }]
    );

    fixture.stop().await;
    submitter_cancel.cancel();
    submitter_task.await.expect("submitter exits");
}

/// Reported bug: switching away from the sender wallet before its transaction
/// finalizes left the outputs' PPOI proofs unsent.
#[tokio::test(start_paused = true)]
async fn created_output_ppoi_context_is_sent_after_sender_wallet_retires() {
    let scope = test_scope();
    let output = FixedBytes::from([0xc2; 32]);
    let list = poi::poi::default_active_poi_list_keys()[0];
    let log = rpc_transact_outputs_log(
        scope.railgun_contract,
        50,
        vec![FixedBytes::from([0xc1; 32]), output],
    );
    let rpc = JsonRpcServer::spawn_handler(log_range_rpc_handler(vec![log], 100, |_, _, _| None));
    let transport = Arc::new(RecordingPoiTransport::default());
    let submitter_cancel = CancellationToken::new();
    let (poi_submitter, driver) = ChainPoiSubmitterDriver::unspawned_for_test(
        scope.chain_id,
        Arc::clone(&transport) as Arc<dyn crate::wallet::PendingOutputPoiSubmitter>,
    );
    let fixture = LiveForestFixture::spawn_with(
        "live-forest-ppoi-sender-retired",
        Arc::new(QueryRpcPool::new(
            vec![rpc.url.clone()],
            Duration::from_secs(1),
        )),
        0,
        100,
        poi_submitter.clone(),
        |_| {},
    )
    .await;
    let mut cfg = test_wallet_config(
        &scope,
        Url::parse("http://127.0.0.1:1").expect("unused quick-sync url"),
    );
    cfg.cache_key = test_cache_key("ppoi-sender");
    cfg.quick_sync_endpoint = None;
    // No startup scan: the sender never observes its own output, so only the
    // chain's live rows can place it.
    cfg.sync_to_block = Some(0);
    cfg.use_indexed_wallet_catch_up = false;
    let sender = fixture
        .service
        .register_wallet(cfg)
        .await
        .expect("register sender wallet");

    let create_sender = sender.clone();
    let create = tokio::spawn(async move {
        create_sender
            .create_pending_output_poi_contexts(vec![crate::types::PendingOutputPoiContextIntent {
                txid_version: DEFAULT_TXID_VERSION.to_string(),
                output_commitment: output,
                output_npk: FixedBytes::from([0x22; 32]),
                utxo_tree_in: 0,
                railgun_txid: U256::from(7),
                pre_transaction_pois_per_txid_leaf_per_list: BTreeMap::from([(
                    list,
                    BTreeMap::new(),
                )]),
                required_poi_list_keys: vec![list],
                output_role: local_db::PendingOutputPoiRole::Recipient,
            }])
            .await
    });
    // Nothing else enqueues while no context is pending, so the one queued
    // command is the create's prepare.
    yield_until("prepare queued", || driver.queued_commands_for_test() == 1).await;
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    assert!(
        !create.is_finished(),
        "the create reply waits for the chain to hold the context"
    );
    let submitter_task = driver.spawn(submitter_cancel.clone());
    assert_eq!(create.await.expect("create task"), Ok(1));

    fixture.service.unregister_wallet(&sender).await;
    assert!(fixture.service.wallet.read().await.is_none());
    fixture
        .service
        .safe_head_tx
        .send(100)
        .expect("wake live loop");

    yield_until("live batch applied", || *fixture.forest_rx.borrow() == 100).await;
    yield_until("PPOI send", || !transport.sends().is_empty()).await;
    assert_eq!(
        transport.sends(),
        vec![RecordedSend {
            commitment: output,
            tree: 0,
            position: 1,
            lists: vec![list],
        }]
    );

    fixture.stop().await;
    submitter_cancel.cancel();
    submitter_task.await.expect("submitter exits");
}

#[tokio::test(start_paused = true)]
async fn failed_live_squid_fallback_waits_for_cooldown() {
    let failure = r#"{"errors":[{"message":"indexer unavailable"}]}"#;
    let squid = GraphqlServer::spawn(vec![failure, failure]);
    let events = CapturedEvents::default();
    let _guard = events.capture();
    // The stall fallback needs an available provider to confirm a target;
    // Squid fails first, so this one is never contacted.
    let fixture = LiveForestFixture::spawn(
        "live-forest-squid-cooldown",
        vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
        squid.url.clone(),
        50,
        200,
    )
    .await;
    let stall = fixture.stall_period();
    let attempts = || {
        events
            .events()
            .iter()
            .filter(|event| {
                event.get("message").is_some_and(|message| {
                    message == "live merkle forest stall fallback to Squid finished"
                })
            })
            .count()
    };

    tokio::time::advance(stall).await;
    yield_until("first Squid attempt", || attempts() == 1).await;
    assert_eq!(squid.requests.try_iter().count(), 1);

    tokio::time::advance(stall.saturating_sub(Duration::from_secs(1))).await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert_eq!(attempts(), 1, "no retry before the cooldown elapses");
    assert_eq!(squid.requests.try_iter().count(), 0);

    tokio::time::advance(Duration::from_secs(1)).await;
    yield_until("second Squid attempt", || attempts() == 2).await;
    assert_eq!(squid.requests.try_iter().count(), 1);
    assert_eq!(*fixture.forest_rx.borrow(), 50);

    fixture.stop().await;
}

#[tokio::test(start_paused = true)]
async fn stalled_live_forest_checks_reorg_before_squid_fallback() {
    let (squid, commitments) = GraphqlServer::spawn_with_blocked_response(
        vec![
            r#"{"data":{"squidStatus":{"height":"150"}}}"#,
            SQUID_EMPTY_COMMITMENTS,
        ],
        1,
    );
    // Block headers carry hash 0xbb, except that block 50 has none until
    // `block_50_unconfirmed` clears; getLogs fails so RPC cannot advance.
    let block_50_unconfirmed = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let rpc = JsonRpcServer::spawn_handler({
        let block_50_unconfirmed = Arc::clone(&block_50_unconfirmed);
        move |request| match request["method"].as_str() {
            Some("eth_getBlockByNumber") => {
                let block_number = hex_quantity(&request["params"][0]);
                if block_number == 50 && block_50_unconfirmed.load(Ordering::Acquire) {
                    return serde_json::json!({ "result": null });
                }
                serde_json::json!({
                    "result": rpc_block(block_number, test_block_timestamp(block_number), 0xbb),
                })
            }
            _ => serde_json::json!({ "error": rpc_error(-32000, "unavailable") }),
        }
    });
    let events = CapturedEvents::default();
    let _guard = events.capture();
    let fixture = LiveForestFixture::spawn(
        "live-forest-stall-reorg",
        vec![rpc.url.clone()],
        squid.url.clone(),
        50,
        200,
    )
    .await;
    let service = &fixture.service;
    let chain = &service.chain;
    service
        .db
        .update_merkle_forest_meta(
            chain.deployment.chain_id,
            &chain.deployment.contract.to_string(),
            &service.db.resolve_path(&DbStore::relative_blob_path(
                "merkle_forest",
                "live-forest.msgpack",
            )),
            50,
            merkletree::persist::SNAPSHOT_VERSION,
            [0xaa; 32],
        )
        .expect("persist forest meta for block 50");

    // Without a confirmed hash for block 50, the stall fallback waits for
    // another stall period.
    tokio::time::advance(fixture.stall_period()).await;
    yield_until("deferred stall fallback", || {
        !events
            .with_message(
                "live merkle forest stall fallback deferred after an inconclusive reorg check",
            )
            .is_empty()
    })
    .await;
    assert_eq!(squid.requests.try_iter().count(), 0);
    assert_eq!(*fixture.forest_rx.borrow(), 50);
    assert_eq!(fixture.meta(), Some((50, [0xaa; 32])));
    // The live page after the deferral fails and cools the only provider down.
    yield_until("failed live RPC page", || {
        !events
            .with_message("failed to fetch logs, retrying...")
            .is_empty()
    })
    .await;
    yield_until("provider cooldown", || {
        !chain.rpcs.available_providers().is_empty()
    })
    .await;

    block_50_unconfirmed.store(false, Ordering::Release);
    tokio::time::advance(fixture.stall_period()).await;
    yield_until("Squid commitments request", || {
        commitments.request_started.try_recv().is_ok()
    })
    .await;
    assert_eq!(
        *fixture.forest_rx.borrow(),
        0,
        "the reorged forest resets before the Squid catch-up"
    );
    let requests = squid.requests.try_iter().collect::<Vec<_>>();
    assert_eq!(requests.len(), 2, "Squid height and commitments");
    assert_eq!(
        json_rpc_request_body(&requests[1])["variables"]["blockNumber"],
        "1",
        "Squid catches up from the reset block"
    );

    commitments
        .release
        .send(())
        .expect("release Squid commitments");
    yield_until("Squid stall fallback", || {
        *fixture.forest_rx.borrow() == 150
    })
    .await;

    fixture.stop().await;
}

#[tokio::test(start_paused = true)]
async fn hung_squid_stall_fallback_times_out_and_live_rpc_resumes() {
    let (squid, squid_port) = silent_server();
    let recovered = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let serve = log_range_rpc_handler(Vec::new(), 200, |_, _, _| None);
    let rpc = JsonRpcServer::spawn_handler({
        let recovered = Arc::clone(&recovered);
        move |request| {
            if request["method"] == "eth_getLogs" && !recovered.load(Ordering::Acquire) {
                return serde_json::json!({ "error": rpc_error(-32000, "unavailable") });
            }
            serve(request)
        }
    });
    let events = CapturedEvents::default();
    let _guard = events.capture();
    let fixture = LiveForestFixture::spawn(
        "live-forest-hung-squid",
        vec![rpc.url.clone()],
        Url::parse(&format!("http://127.0.0.1:{squid_port}")).expect("squid url"),
        50,
        200,
    )
    .await;
    let rpcs = Arc::clone(&fixture.service.chain.rpcs);
    let finished = || {
        events
            .events()
            .into_iter()
            .filter(|event| {
                event.get("message").is_some_and(|message| {
                    message == "live merkle forest stall fallback to Squid finished"
                })
            })
            .collect::<Vec<_>>()
    };

    // A live page fails and the only provider cools down.
    fixture
        .service
        .safe_head_tx
        .send(200)
        .expect("wake live loop");
    yield_until("failed live RPC page", || {
        rpcs.available_providers().is_empty()
    })
    .await;
    // The stall fallback starts only with a provider to confirm its target.
    yield_until("provider cooldown", || {
        !rpcs.available_providers().is_empty()
    })
    .await;

    tokio::time::advance(fixture.stall_period()).await;
    // Only the silent Squid's timers are pending during the fallback, so the
    // paused clock may run through its header timeouts and retry delays.
    let fallback_started = tokio::time::Instant::now();
    while finished().is_empty() {
        assert!(
            fallback_started.elapsed() < Duration::from_mins(10),
            "the Squid stall fallback never finished"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let elapsed = fallback_started.elapsed();
    assert!(
        (Duration::from_secs(127)..=Duration::from_secs(129)).contains(&elapsed),
        "four 30 s header timeouts and 1, 2 and 4 s retry delays, got {elapsed:?}"
    );
    assert_eq!(
        finished()[0].get("outcome").map(String::as_str),
        Some("not_applied")
    );
    assert_eq!(*fixture.forest_rx.borrow(), 50);
    drain_backlog_connections(&squid);

    // Once the provider recovers, the live loop pages from RPC within the
    // Squid cooldown.
    recovered.store(true, Ordering::Release);
    yield_until("provider cooldown", || {
        !rpcs.available_providers().is_empty()
    })
    .await;
    fixture
        .service
        .safe_head_tx
        .send(200)
        .expect("wake live loop");
    yield_until("live RPC pages", || *fixture.forest_rx.borrow() == 200).await;
    assert_eq!(finished().len(), 1, "no Squid retry within the cooldown");
    assert_eq!(drain_backlog_connections(&squid), 0);

    fixture.stop().await;
}

const fn test_forest_lag(far_behind: bool) -> ForestLag {
    ForestLag {
        estimated_requests: if far_behind { 100 } else { 2 },
        far_behind,
    }
}

#[test]
fn forest_stall_tracker_starts_far_behind_attempts_at_once() {
    let squid = IndexedForestSources {
        artifacts: false,
        squid: true,
    };
    let artifacts = IndexedForestSources {
        artifacts: true,
        squid: false,
    };
    let stall_period = Duration::from_mins(2);
    let start = tokio::time::Instant::now();

    // An advancing forest whose lag exceeds the budget is due at once, from
    // either indexed source, but only with a provider to confirm a target.
    let mut tracker = ForestStallTracker::new(stall_period);
    tracker.observe(100, 10_000, test_forest_lag(true), start);
    let advanced = start + Duration::from_secs(1);
    tracker.observe(110, 10_000, test_forest_lag(true), advanced);
    assert_eq!(
        tracker.due(advanced, squid, true),
        Some(IndexedForestTrigger::FarBehind)
    );
    assert_eq!(
        tracker.due(advanced, artifacts, true),
        Some(IndexedForestTrigger::FarBehind)
    );
    assert_eq!(tracker.due(advanced, squid, false), None);

    // A finished attempt defers the next one by the cooldown from its finish.
    let finished = advanced + Duration::from_secs(30);
    tracker.finish_far_behind_attempt(finished);
    let retry = finished + INDEXED_TAIL_FALLBACK_COOLDOWN;
    assert_eq!(tracker.deadline(squid), Some(retry));
    let before_retry =
        finished + INDEXED_TAIL_FALLBACK_COOLDOWN.saturating_sub(Duration::from_millis(1));
    assert_eq!(tracker.due(before_retry, squid, true), None);
    assert_eq!(
        tracker.due(retry, squid, true),
        Some(IndexedForestTrigger::FarBehind)
    );

    // A lag within the budget stays on the Squid-only stall rule.
    let mut tracker = ForestStallTracker::new(stall_period);
    tracker.observe(100, 200, test_forest_lag(false), start);
    let before_stall = start + stall_period.saturating_sub(Duration::from_millis(1));
    assert_eq!(tracker.due(before_stall, squid, true), None);
    let stalled = start + stall_period;
    assert_eq!(
        tracker.due(stalled, squid, true),
        Some(IndexedForestTrigger::Stall)
    );
    assert_eq!(tracker.due(stalled, squid, false), None);
    assert_eq!(tracker.deadline(artifacts), None);
    assert_eq!(tracker.due(stalled, artifacts, true), None);
}

#[test]
fn short_lag_is_far_behind_with_restricted_log_spans() {
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
        Duration::from_secs(1),
    ));
    let chain = test_chain_config(&test_scope(), Arc::clone(&rpcs), None);
    assert_eq!(
        chain.live_forest_lag(0, 200),
        ForestLag {
            estimated_requests: 2,
            far_behind: false,
        },
        "two pages at the configured range"
    );

    rpcs.narrow_log_span(LogSpanEndpoint::Provider(0), 2);
    assert_eq!(
        chain.live_forest_lag(0, 200),
        ForestLag {
            estimated_requests: 100,
            far_behind: true,
        }
    );
}

/// Advances the paused clock by `step`, then releases one held live page and
/// waits until the loop applies it.
async fn advance_and_apply_live_page(
    fixture: &LiveForestFixture,
    release_page: &std_mpsc::Sender<()>,
    step: Duration,
) {
    let before = *fixture.forest_rx.borrow();
    tokio::time::advance(step).await;
    release_page.send(()).expect("release live page");
    yield_until("live page", || *fixture.forest_rx.borrow() > before).await;
}

/// Serves `serve`, but fails every `eth_getLogs` after the first `pages`.
/// `get_logs` counts the `eth_getLogs` requests.
fn live_pages_then_fail(
    pages: u64,
    get_logs: Arc<AtomicU64>,
    serve: impl Fn(&serde_json::Value) -> serde_json::Value + Send + 'static,
) -> impl Fn(&serde_json::Value) -> serde_json::Value + Send + 'static {
    move |request: &serde_json::Value| {
        if request["method"] == "eth_getLogs" && get_logs.fetch_add(1, Ordering::AcqRel) >= pages {
            return serde_json::json!({ "error": rpc_error(-32000, "unavailable") });
        }
        serve(request)
    }
}

fn progress_record(
    cause: &str,
    forest_block: u64,
    safe_head: u64,
    estimated_requests: u64,
    far_behind: bool,
) -> BTreeMap<String, String> {
    [
        ("message", "live forest progress".to_owned()),
        ("chain_id", "1".to_owned()),
        ("cause", cause.to_owned()),
        ("forest_block", forest_block.to_string()),
        ("safe_head", safe_head.to_string()),
        ("estimated_requests", estimated_requests.to_string()),
        ("far_behind", far_behind.to_string()),
    ]
    .into_iter()
    .map(|(field, value)| (field.to_owned(), value))
    .collect()
}

#[tokio::test(start_paused = true)]
async fn far_behind_live_forest_keeps_paging_through_hung_squid_attempts() {
    let (squid, squid_port) = silent_server();
    let (release_page, page_gate) = std_mpsc::channel::<()>();
    let serve = log_range_rpc_handler(Vec::new(), 10_000, |_, _, _| None);
    let rpc = JsonRpcServer::spawn_handler(move |request| {
        if request["method"] == "eth_getLogs" {
            // Hold each page until the test has advanced the paused clock.
            let _ = page_gate.recv();
        }
        serve(request)
    });
    let events = CapturedEvents::default();
    let _guard = events.capture();
    let started = tokio::time::Instant::now();
    let fixture = LiveForestFixture::spawn_far_behind(
        "live-forest-far-behind-hung-squid",
        rpc.url.clone(),
        Url::parse(&format!("http://127.0.0.1:{squid_port}")).expect("squid url"),
        0,
        10_000,
        None,
    )
    .await;
    let triggered = || {
        events
            .with_message("far-behind live forest catch-up triggered")
            .len()
    };
    let finished = || events.with_message("far-behind live forest catch-up finished");
    let step = Duration::from_secs(5);
    // The attempt starts without waiting for a stall.
    yield_until("far-behind attempt", || triggered() == 1).await;

    // Pages keep applying while Squid's requests time out and retry.
    let mut pages = 0;
    while finished().is_empty() {
        assert!(pages < 60, "the hung attempt never finished");
        advance_and_apply_live_page(&fixture, &release_page, step).await;
        pages += 1;
    }
    let attempt = finished().remove(0);
    assert_eq!(
        attempt.get("outcome").map(String::as_str),
        Some("no_result")
    );
    assert!(pages >= 20, "live pages during the attempt: {pages}");
    let elapsed_ms = attempt["elapsed_ms"].parse().expect("attempt elapsed ms");
    let retry_at = started + Duration::from_millis(elapsed_ms) + INDEXED_TAIL_FALLBACK_COOLDOWN;

    // The repeated attempt waits for the cooldown, and pages keep applying.
    while triggered() == 1 {
        let now = tokio::time::Instant::now();
        assert!(now < retry_at + 2 * step, "no attempt after the cooldown");
        advance_and_apply_live_page(&fixture, &release_page, step).await;
        if tokio::time::Instant::now() < retry_at {
            assert_eq!(triggered(), 1, "no attempt within the cooldown");
        }
    }
    for _ in 0..3 {
        advance_and_apply_live_page(&fixture, &release_page, step).await;
    }
    assert_eq!(triggered(), 2);
    assert_eq!(finished().len(), 1, "the repeated attempt is still running");

    fixture.stop().await;
    drain_backlog_connections(&squid);
}

#[tokio::test(start_paused = true)]
async fn far_behind_attempt_is_installed_when_it_finishes() {
    let squid = GraphqlServer::spawn(vec![
        r#"{"data":{"squidStatus":{"height":"10000"}}}"#,
        r#"{"errors":[{"message":"indexer unavailable"}]}"#,
        r#"{"data":{"squidStatus":{"height":"10000"}}}"#,
        SQUID_EMPTY_COMMITMENTS,
    ]);
    // Live pages fail, so only indexed attempts advance the forest.
    let get_logs = Arc::new(AtomicU64::new(0));
    let rpc = JsonRpcServer::spawn_handler(live_pages_then_fail(
        0,
        Arc::clone(&get_logs),
        log_range_rpc_handler(Vec::new(), 10_000, |_, _, _| None),
    ));
    let (progress_tx, progress_rx) = watch::channel(None);
    let events = CapturedEvents::default();
    let _guard = events.capture();
    let fixture = LiveForestFixture::spawn_far_behind(
        "live-forest-far-behind-install",
        rpc.url.clone(),
        squid.url.clone(),
        0,
        10_000,
        Some(progress_tx),
    )
    .await;
    let triggered = || {
        events
            .with_message("far-behind live forest catch-up triggered")
            .len()
    };

    // The first attempt fails after Squid reports its height, past the point
    // where a reporting catch-up publishes progress.
    yield_until("failed attempt and a live page after it", || {
        !events
            .with_message("far-behind live forest catch-up finished")
            .is_empty()
            && get_logs.load(Ordering::Acquire) >= 2
    })
    .await;
    assert_eq!(squid.requests.try_iter().count(), 2);
    assert_eq!(
        *progress_rx.borrow(),
        None,
        "a failed attempt publishes no progress"
    );

    tokio::time::advance(INDEXED_TAIL_FALLBACK_COOLDOWN.saturating_sub(Duration::from_secs(1)))
        .await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert_eq!(triggered(), 1, "no retry before the cooldown");
    assert_eq!(squid.requests.try_iter().count(), 0);

    // From here the clock and the safe head stay put: the finished attempt
    // alone wakes the loop to install it.
    tokio::time::advance(Duration::from_secs(1)).await;
    yield_until("indexed install", || *fixture.forest_rx.borrow() == 10_000).await;
    assert_eq!(triggered(), 2);
    assert_eq!(fixture.meta(), Some((10_000, [0x11; 32])));
    let completion = progress_rx.borrow().expect("completion progress");
    assert_eq!(
        (completion.current_block, completion.target_block),
        (10_000, 10_000)
    );

    fixture.stop().await;
}

#[tokio::test(start_paused = true)]
async fn far_behind_candidate_waits_for_a_conclusive_reorg_check() {
    // Squid holds its commitments until the forest metadata is seeded, so no
    // candidate exists before then.
    let (squid, commitments) = GraphqlServer::spawn_with_blocked_response(
        vec![
            r#"{"data":{"squidStatus":{"height":"10000"}}}"#,
            SQUID_EMPTY_COMMITMENTS,
        ],
        1,
    );
    // Live pages fail, and block 50 has no header until
    // `block_50_unconfirmed` clears.
    let block_50_unconfirmed = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let serve = live_pages_then_fail(
        0,
        Arc::new(AtomicU64::new(0)),
        log_range_rpc_handler(Vec::new(), 10_000, |_, _, _| None),
    );
    let rpc = JsonRpcServer::spawn_handler({
        let block_50_unconfirmed = Arc::clone(&block_50_unconfirmed);
        move |request| {
            if request["method"] == "eth_getBlockByNumber"
                && hex_quantity(&request["params"][0]) == 50
                && block_50_unconfirmed.load(Ordering::Acquire)
            {
                return serde_json::json!({ "result": null });
            }
            serve(request)
        }
    });
    let (progress_tx, progress_rx) = watch::channel(None);
    let events = CapturedEvents::default();
    let _guard = events.capture();
    let fixture = LiveForestFixture::spawn_far_behind(
        "live-forest-far-behind-unconfirmed-reorg-check",
        rpc.url.clone(),
        squid.url.clone(),
        50,
        10_000,
        Some(progress_tx),
    )
    .await;
    let results = || {
        events
            .with_message("far-behind live forest catch-up result")
            .into_iter()
            .filter_map(|record| record.get("outcome").cloned())
            .collect::<Vec<_>>()
    };

    yield_until("Squid commitments request", || {
        commitments.request_started.try_recv().is_ok()
    })
    .await;
    let chain = &fixture.service.chain;
    fixture
        .service
        .db
        .update_merkle_forest_meta(
            chain.deployment.chain_id,
            &chain.deployment.contract.to_string(),
            &fixture.snapshot_path,
            50,
            merkletree::persist::SNAPSHOT_VERSION,
            [0x11; 32],
        )
        .expect("persist forest meta for block 50");
    commitments
        .release
        .send(())
        .expect("release Squid commitments");

    // The attempt finishes with a candidate, and the loop runs a reorg check
    // and a failed live page after it.
    yield_until("finished attempt and a live page after it", || {
        events
            .with_message("far-behind live forest catch-up finished")
            .iter()
            .any(|record| record.get("target").map(String::as_str) == Some("10000"))
            && events
                .with_message("failed to fetch logs, retrying...")
                .len()
                >= 2
    })
    .await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        *fixture.forest_rx.borrow(),
        50,
        "an unconfirmed forest block hash holds the candidate"
    );
    assert_eq!(fixture.meta(), Some((50, [0x11; 32])));
    assert_eq!(fixture.snapshot_block(), None);
    assert!(
        !events
            .with_message("live forest progress")
            .iter()
            .any(|record| record.get("cause").map(String::as_str) == Some("indexed_install"))
    );
    assert!(
        results().is_empty(),
        "no install outcome yet: {:?}",
        results()
    );
    assert_eq!(*progress_rx.borrow(), None);

    // Once block 50 confirms the stored hash, the next check installs the
    // held candidate.
    block_50_unconfirmed.store(false, Ordering::Release);
    fixture
        .service
        .safe_head_tx
        .send(10_000)
        .expect("wake live loop");
    yield_until("indexed install", || *fixture.forest_rx.borrow() == 10_000).await;
    assert_eq!(fixture.meta(), Some((10_000, [0x11; 32])));
    assert_eq!(fixture.snapshot_block(), Some(10_000));
    let completion = progress_rx.borrow().expect("completion progress");
    assert_eq!(
        (completion.current_block, completion.target_block),
        (10_000, 10_000)
    );
    // The first attempt's candidate installs, within its cooldown.
    assert_eq!(results(), vec!["installed".to_owned()]);
    assert_eq!(
        events
            .with_message("far-behind live forest catch-up triggered")
            .len(),
        1
    );

    fixture.stop().await;
}

#[tokio::test(start_paused = true)]
async fn live_forest_progress_records_each_published_block() {
    // Squid holds its height answer until the test releases it.
    let (squid, squid_height) = GraphqlServer::spawn_with_blocked_response(
        vec![
            r#"{"data":{"squidStatus":{"height":"10000"}}}"#,
            SQUID_EMPTY_COMMITMENTS,
        ],
        0,
    );
    // Two live pages succeed and later ones fail. The first read of block 10
    // returns no block, so the first page fails its endpoint confirmation.
    let get_logs = Arc::new(AtomicU64::new(0));
    let serve = live_pages_then_fail(
        2,
        Arc::clone(&get_logs),
        log_range_rpc_handler(Vec::new(), 10_000, |_, _, _| None),
    );
    let endpoint_unproven = std::sync::atomic::AtomicBool::new(true);
    let rpc = JsonRpcServer::spawn_handler(move |request| {
        if request["method"] == "eth_getBlockByNumber"
            && hex_quantity(&request["params"][0]) == 10
            && endpoint_unproven.swap(false, Ordering::AcqRel)
        {
            return serde_json::json!({ "result": null });
        }
        serve(request)
    });
    let events = CapturedEvents::default();
    let _guard = events.capture();
    let fixture = LiveForestFixture::spawn_far_behind(
        "live-forest-progress-records",
        rpc.url.clone(),
        squid.url.clone(),
        0,
        10_000,
        None,
    )
    .await;
    let records = || events.with_message("live forest progress");

    yield_until("unproven live page", || {
        !events
            .with_message("live RPC range does not prove its endpoint")
            .is_empty()
    })
    .await;
    assert!(records().is_empty(), "an unapplied page has no record");

    fixture
        .service
        .safe_head_tx
        .send(10_000)
        .expect("wake live loop");
    yield_until("applied live page and a failed one", || {
        *fixture.forest_rx.borrow() == 10 && get_logs.load(Ordering::Acquire) == 3
    })
    .await;
    squid_height.release.send(()).expect("release Squid height");
    yield_until("indexed install", || *fixture.forest_rx.borrow() == 10_000).await;

    assert_eq!(
        records(),
        vec![
            progress_record("rpc_apply", 10, 10_000, 999, true),
            progress_record("indexed_install", 10_000, 10_000, 0, false),
        ]
    );

    fixture.stop().await;
}

#[tokio::test(start_paused = true)]
async fn far_behind_result_is_dropped_once_live_rpc_passes_its_target() {
    let (squid, commitments) = GraphqlServer::spawn_with_blocked_response(
        vec![
            r#"{"data":{"squidStatus":{"height":"30"}}}"#,
            SQUID_EMPTY_COMMITMENTS,
        ],
        1,
    );
    // Four live pages apply, through block 40; later pages fail.
    let get_logs = Arc::new(AtomicU64::new(0));
    let rpc = JsonRpcServer::spawn_handler(live_pages_then_fail(
        4,
        Arc::clone(&get_logs),
        log_range_rpc_handler(Vec::new(), 10_000, |_, _, _| None),
    ));
    let (progress_tx, progress_rx) = watch::channel(None);
    let events = CapturedEvents::default();
    let _guard = events.capture();
    let fixture = LiveForestFixture::spawn_far_behind(
        "live-forest-far-behind-passed",
        rpc.url.clone(),
        squid.url.clone(),
        0,
        10_000,
        Some(progress_tx),
    )
    .await;

    let mut attempt_running = false;
    yield_until("live pages past the attempt's target", || {
        attempt_running |= commitments.request_started.try_recv().is_ok();
        attempt_running
            && *fixture.forest_rx.borrow() == 40
            && get_logs.load(Ordering::Acquire) >= 5
    })
    .await;
    commitments
        .release
        .send(())
        .expect("release Squid commitments");
    yield_until("far-behind result", || {
        !events
            .with_message("far-behind live forest catch-up result")
            .is_empty()
    })
    .await;

    let result = events.find("far-behind live forest catch-up result");
    assert_eq!(
        (
            result.get("target").map(String::as_str),
            result.get("outcome").map(String::as_str),
        ),
        (Some("30"), Some("forest_at_target"))
    );
    assert_eq!(*fixture.forest_rx.borrow(), 40);
    assert_eq!(fixture.meta(), Some((40, [0x11; 32])));
    assert_eq!(fixture.snapshot_block(), Some(40));
    assert_eq!(*progress_rx.borrow(), None, "no completion progress");

    fixture.stop().await;
}

#[tokio::test(start_paused = true)]
async fn reorg_during_far_behind_attempt_aborts_it() {
    let (squid, commitments) = GraphqlServer::spawn_with_blocked_response(
        vec![
            r#"{"data":{"squidStatus":{"height":"10000"}}}"#,
            SQUID_EMPTY_COMMITMENTS,
        ],
        1,
    );
    // The first live page waits until the attempt is running. Block 60 proves
    // that page with hash 0x11, then reorgs to 0xbb for the reorg check.
    let (release_page, page_gate) = std_mpsc::channel::<()>();
    let block_60_reads = AtomicU64::new(0);
    let serve = live_pages_then_fail(
        1,
        Arc::new(AtomicU64::new(0)),
        log_range_rpc_handler(Vec::new(), 10_000, |_, _, _| None),
    );
    let rpc = JsonRpcServer::spawn_handler(move |request| {
        if request["method"] == "eth_getLogs" {
            let _ = page_gate.recv();
        }
        if request["method"] == "eth_getBlockByNumber"
            && hex_quantity(&request["params"][0]) == 60
            && block_60_reads.fetch_add(1, Ordering::AcqRel) > 0
        {
            return serde_json::json!({
                "result": rpc_block(60, test_block_timestamp(60), 0xbb),
            });
        }
        serve(request)
    });
    let events = CapturedEvents::default();
    let _guard = events.capture();
    let fixture = LiveForestFixture::spawn_far_behind(
        "live-forest-far-behind-reorg",
        rpc.url.clone(),
        squid.url.clone(),
        50,
        10_000,
        None,
    )
    .await;

    yield_until("Squid commitments request", || {
        commitments.request_started.try_recv().is_ok()
    })
    .await;
    drop(release_page);
    yield_until("aborted attempt", || {
        !events
            .with_message("far-behind live forest catch-up aborted by a reorg rewind")
            .is_empty()
    })
    .await;
    assert_eq!(
        Arc::strong_count(&fixture.service),
        2,
        "the aborted attempt dropped its service handle"
    );

    // The held Squid answer now reaches no attempt.
    commitments
        .release
        .send(())
        .expect("release Squid commitments");
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert_eq!(*fixture.forest_rx.borrow(), 0);
    assert_eq!(fixture.meta(), Some((0, [0; 32])));
    assert!(
        events
            .with_message("far-behind live forest catch-up finished")
            .is_empty()
    );
    assert_eq!(
        events.with_message("live forest progress"),
        vec![
            progress_record("rpc_apply", 60, 10_000, 994, true),
            progress_record("reorg_reset", 0, 10_000, 1000, true),
        ]
    );

    fixture.stop().await;
}

#[tokio::test(start_paused = true)]
async fn far_behind_attempt_blocks_the_stall_trigger_and_ends_with_shutdown() {
    let (squid, commitments) = GraphqlServer::spawn_with_blocked_response(
        vec![
            r#"{"data":{"squidStatus":{"height":"600"}}}"#,
            SQUID_EMPTY_COMMITMENTS,
        ],
        1,
    );
    // One live page brings the lag within the request budget; later pages fail.
    let get_logs = Arc::new(AtomicU64::new(0));
    let rpc = JsonRpcServer::spawn_handler(live_pages_then_fail(
        1,
        Arc::clone(&get_logs),
        log_range_rpc_handler(Vec::new(), 650, |_, _, _| None),
    ));
    let events = CapturedEvents::default();
    let _guard = events.capture();
    let fixture = LiveForestFixture::spawn_far_behind(
        "live-forest-far-behind-stall-shutdown",
        rpc.url.clone(),
        squid.url.clone(),
        0,
        650,
        None,
    )
    .await;

    let mut attempt_running = false;
    yield_until("far-behind attempt and live pages", || {
        attempt_running |= commitments.request_started.try_recv().is_ok();
        attempt_running
            && *fixture.forest_rx.borrow() == 10
            && get_logs.load(Ordering::Acquire) == 2
    })
    .await;

    // The forest has stalled within the budget, so the stall trigger is due.
    // A stall fallback would hang behind the held Squid answer; the loop pages
    // instead.
    tokio::time::advance(fixture.stall_period()).await;
    fixture
        .service
        .safe_head_tx
        .send(650)
        .expect("wake live loop");
    yield_until("live page after the stall period", || {
        get_logs.load(Ordering::Acquire) == 3
    })
    .await;
    assert!(
        events
            .with_message("live merkle forest stall fallback to Squid finished")
            .is_empty()
    );
    assert_eq!(
        Arc::strong_count(&fixture.service),
        3,
        "the fixture, the loop and the attempt hold the service"
    );

    // Shutdown during the attempt: `ChainService::shutdown` awaits this task.
    let LiveForestFixture {
        root_dir,
        service,
        task,
        ..
    } = fixture;
    service.cancel.cancel();
    task.await.expect("live forest loop exits");
    assert_eq!(
        Arc::strong_count(&service),
        1,
        "the attempt's service handle"
    );
    assert_eq!(
        Arc::strong_count(&service.chain.rpcs),
        1,
        "the loop's and the attempt's pool handles"
    );
    assert_eq!(*service.forest_last_tx.borrow(), 10);
    assert_eq!(
        forest_meta(&service.db, &service.chain),
        Some((10, [0x11; 32])),
        "only the live page persisted"
    );

    drop(commitments);
    drop(service);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn short_startup_with_indexed_sources_behind_cursor_delivers_from_rpc_after_cursor() {
    let root_dir = temp_db_root("short-startup-indexed-behind-cursor");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    // Both indexed sources stop at block 103, below the wallet cursor at 105.
    let artifact_source = checkpointed_wallet_artifact_source(&scope, 101, 103, 103);
    let squid = GraphqlServer::spawn(vec![
        r#"{"data":{"squidStatus":{"height":"103"},"transactCommitments":[],"shieldCommitments":[],"nullifiers":[],"legacyEncryptedCommitments":[],"legacyGeneratedCommitments":[]}}"#,
    ]);
    // A head below the target fails the standalone RPC candidate, the Squid
    // tail, and the background warm, while the backfill loop's range fetch
    // (which does not read the head) still succeeds.
    let rpc = JsonRpcServer::spawn_handler(log_range_rpc_handler(
        vec![rpc_nullifiers_log_with_timestamp(
            scope.railgun_contract,
            108,
        )],
        100,
        |_, _, _| None,
    ));
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(
        &scope,
        Arc::clone(&rpcs),
        Some(artifact_source.config.clone()),
    );
    chain.sync.block_range = 10;
    chain.sync.indexed_wallet_block_range = 10;
    chain.finality_depth = 0;
    chain.sync.quick_sync_endpoint = Some(squid.url.clone());
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let (service, backfill_rx) = test_chain_service_with_backfill(
        Arc::clone(&db),
        chain,
        public_data_plane,
        test_proxy_poi_policy(),
    );
    service.safe_head_tx.send_replace(110);
    spawn_backfill_loop(
        Arc::clone(&service),
        backfill_rx,
        rpcs,
        None,
        service.safe_head_tx.subscribe(),
        service.cancel.clone(),
    );

    let mut cfg = test_wallet_config(&scope, squid.url.clone());
    cfg.cache_key = test_cache_key("indexed-behind-cursor");
    cfg.start_block = Some(101);
    cfg.sync_to_block = Some(110);
    db.put_wallet_meta(
        &cfg.cache_key,
        &WalletMeta {
            last_scanned_block: 105,
            updated_at: 1,
            last_scanned_block_hash: None,
        },
    )
    .expect("seed wallet cursor");
    let mut handle = service.register_wallet(cfg).await.expect("register wallet");
    tokio::time::timeout(Duration::from_secs(2), handle.wait_until_ready())
        .await
        .expect("RPC delivery after the cursor completed")
        .expect("wallet readiness succeeded");
    assert_eq!(handle.last_scanned(), Some(110));

    // Head reads: the standalone candidate, the Squid tail, and the warm.
    let mut bodies = Vec::new();
    yield_until("startup requests and failed background warm", || {
        bodies.extend(rpc.drain_request_bodies());
        bodies
            .iter()
            .filter(|body| body["method"] == "eth_blockNumber")
            .count()
            == 3
            && !service.public_data_plane.public_window_warm_running()
    })
    .await;
    assert_eq!(
        get_logs_ranges(&bodies),
        vec![(106, 110)],
        "delivery comes from one RPC range that starts after the cursor"
    );
    let squid_requests = squid.requests.try_iter().collect::<Vec<_>>();
    assert_eq!(squid_requests.len(), 1);
    assert!(
        squid_requests[0].contains("query WalletProbe"),
        "Squid is probed for its height but no rows are requested"
    );
    // Manifest and catalog reads are metadata and may run (the TXID cache
    // loop also reads the manifest once the wallet is ready); chunks are data.
    let artifact_paths = artifact_source.server.requested_paths();
    assert!(artifact_paths.iter().any(|path| path == "/manifest.json"));
    assert!(
        artifact_source.chunk_descriptors.iter().all(|chunk| {
            let chunk_path = format!("/ipfs/{}?format=car&dag-scope=entity", chunk.cid);
            !artifact_paths.contains(&chunk_path)
        }),
        "the artifacts end before the cursor, so no chunk is fetched: {artifact_paths:?}"
    );
    assert_eq!(
        service
            .public_data_plane
            .cached_wallet_scan_suffix(101, 110)
            .await
            .and_then(|applies| applies.first().map(|apply| apply.from_block)),
        Some(106)
    );

    service.unregister_all_wallets().await;
    service.shutdown().await;
    drop(service);
    drop(artifact_source.server);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn short_startup_squid_tail_below_cursor_starts_at_delivery_boundary() {
    let root_dir = temp_db_root("short-startup-squid-tail-below-cursor");
    let events = CapturedEvents::default();
    let _guard = events.capture();
    let hedge_winner = || {
        events
            .events()
            .into_iter()
            .find(|event| {
                event
                    .get("message")
                    .is_some_and(|message| message == "wallet startup hedge complete")
            })
            .and_then(|event| event.get("winner").cloned())
    };
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    // Squid stops at block 103, below the wallet cursor at 105.
    let squid = GraphqlServer::spawn(vec![
        r#"{"data":{"squidStatus":{"height":"103"},"transactCommitments":[],"shieldCommitments":[],"nullifiers":[],"legacyEncryptedCommitments":[],"legacyGeneratedCommitments":[]}}"#,
    ]);
    // The standalone RPC candidate reads the head first, before the Squid
    // probe completes, and fails on a head below the target. The Squid
    // candidate's RPC tail and the background warm see a head that covers it.
    // The winner assertion below fails the test if that order ever changes.
    let serve = log_range_rpc_handler(
        vec![rpc_nullifiers_log_with_timestamp(
            scope.railgun_contract,
            108,
        )],
        110,
        |_, _, _| None,
    );
    let head_reads = AtomicU64::new(0);
    let rpc = JsonRpcServer::spawn_handler(move |request| {
        if request["method"] == "eth_blockNumber" && head_reads.fetch_add(1, Ordering::Relaxed) == 0
        {
            serde_json::json!({ "result": "0x64" })
        } else {
            serve(request)
        }
    });
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    chain.sync.block_range = 10;
    chain.sync.indexed_wallet_block_range = 10;
    chain.finality_depth = 0;
    chain.sync.quick_sync_endpoint = Some(squid.url.clone());
    let public_data_plane = ChainPublicDataPlane::new(Arc::clone(&db), Arc::new(AtomicU64::new(0)));
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
    service.safe_head_tx.send_replace(110);

    let mut cfg = test_wallet_config(&scope, squid.url.clone());
    cfg.cache_key = test_cache_key("squid-tail-below-cursor");
    cfg.start_block = Some(101);
    cfg.sync_to_block = Some(110);
    db.put_wallet_meta(
        &cfg.cache_key,
        &WalletMeta {
            last_scanned_block: 105,
            updated_at: 1,
            last_scanned_block_hash: None,
        },
    )
    .expect("seed wallet cursor");
    let mut handle = service.register_wallet(cfg).await.expect("register wallet");
    tokio::time::timeout(Duration::from_secs(2), handle.wait_until_ready())
        .await
        .expect("Squid RPC tail delivery completed")
        .expect("wallet readiness succeeded");
    assert_eq!(handle.last_scanned(), Some(110));

    // Endpoint-block reads: the Squid tail's and the warm's.
    let mut bodies = Vec::new();
    yield_until("Squid tail delivery and background warm", || {
        bodies.extend(rpc.drain_request_bodies());
        header_blocks(&bodies).len() == 2
            && !service.public_data_plane.public_window_warm_running()
            && hedge_winner().is_some()
    })
    .await;
    assert_eq!(
        hedge_winner().as_deref(),
        Some("indexed"),
        "the Squid candidate delivered through its RPC tail"
    );
    assert_eq!(
        get_logs_ranges(&bodies),
        vec![(106, 110), (101, 105)],
        "the RPC tail starts at the delivery boundary, not after the Squid height; \
         the prefix is fetched by the warm after delivery"
    );

    service.unregister_all_wallets().await;
    service.shutdown().await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn startup_window_warm_stops_on_public_cache_reset_and_shutdown() {
    let root_dir = temp_db_root("startup-window-warm-reset");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let (release_first, first_gate) = std_mpsc::channel();
    let (release_second, second_gate) = std_mpsc::channel();
    let (release_third, third_gate) = std_mpsc::channel();
    let rpc = JsonRpcServer::spawn_handler(gated_get_logs_handler(
        log_range_rpc_handler(Vec::new(), 200, reject_spans_over_25),
        vec![
            ((1, 25), first_gate),
            ((26, 50), second_gate),
            ((101, 125), third_gate),
        ],
    ));
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    chain.sync.block_range = 100;
    chain.finality_depth = 0;
    let public_data_plane = ChainPublicDataPlane::new(Arc::clone(&db), Arc::new(AtomicU64::new(0)));
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
    let window = PublicScanRange::new(1, 100);
    let mut bodies = Vec::new();

    // The first split request completes, then the reset lands before the
    // warm task can issue the next one.
    service.start_public_scan_window_warm(window).await;
    yield_until("first split request", || {
        bodies.extend(rpc.drain_request_bodies());
        get_logs_ranges(&bodies).contains(&(1, 25))
    })
    .await;
    release_first.send(()).expect("release first split request");
    service
        .public_data_plane
        .reset_public_cache()
        .await
        .expect("reset between split requests");
    assert!(!service.public_data_plane.public_window_warm_running());
    bodies.extend(rpc.drain_request_bodies());
    assert_eq!(get_logs_ranges(&bodies), vec![(1, 100), (1, 25)]);

    // A later warm starts, and a reset cancels its in-flight request.
    service.start_public_scan_window_warm(window).await;
    assert!(
        service.public_data_plane.public_window_warm_running(),
        "the slot is free after a reset"
    );
    yield_until("second split request in flight", || {
        bodies.extend(rpc.drain_request_bodies());
        get_logs_ranges(&bodies).contains(&(26, 50))
    })
    .await;
    service
        .public_data_plane
        .reset_public_cache()
        .await
        .expect("reset during an in-flight request");
    assert!(!service.public_data_plane.public_window_warm_running());
    release_second.send(()).expect("release cancelled request");
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    bodies.extend(rpc.drain_request_bodies());
    assert_eq!(
        get_logs_ranges(&bodies),
        vec![(1, 100), (1, 25), (1, 25), (26, 50)],
        "no request follows either reset"
    );
    assert!(
        header_blocks(&bodies).is_empty(),
        "cancelled warms never prove an endpoint block"
    );

    // A held reset permit blocks new starts; after its release a warm runs
    // uninterrupted and proves its range end.
    let permit = service
        .public_data_plane()
        .acquire_public_cache_reset_permit()
        .await;
    service.start_public_scan_window_warm(window).await;
    assert!(
        !service.public_data_plane.public_window_warm_running(),
        "no warm starts while a reset permit is held"
    );
    drop(permit);
    service.start_public_scan_window_warm(window).await;
    yield_until("warm after resets", || {
        !service.public_data_plane.public_window_warm_running()
    })
    .await;
    bodies.extend(rpc.drain_request_bodies());
    assert_eq!(
        get_logs_ranges(&bodies)[4..],
        [(1, 25), (26, 50), (51, 75), (76, 100)]
    );
    assert_eq!(
        header_blocks(&bodies),
        vec![100],
        "the uninterrupted warm reads its endpoint block"
    );
    assert!(
        service
            .public_data_plane
            .cached_wallet_scan_exact(1, 100)
            .await
            .is_some(),
        "an uninterrupted warm records the window as reusable coverage"
    );

    // Chain-service shutdown stops a warm whose request is in flight and
    // closes the slot to later starts.
    let later_window = PublicScanRange::new(101, 200);
    service.start_public_scan_window_warm(later_window).await;
    yield_until("warm request in flight at shutdown", || {
        bodies.extend(rpc.drain_request_bodies());
        get_logs_ranges(&bodies).contains(&(101, 125))
    })
    .await;
    service.shutdown().await;
    assert!(!service.public_data_plane.public_window_warm_running());
    service.start_public_scan_window_warm(later_window).await;
    assert!(
        !service.public_data_plane.public_window_warm_running(),
        "no warm starts after shutdown"
    );
    release_third.send(()).expect("release cancelled request");
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    bodies.extend(rpc.drain_request_bodies());
    assert_eq!(
        get_logs_ranges(&bodies)[8..],
        [(101, 125)],
        "no request follows shutdown"
    );
    assert_eq!(header_blocks(&bodies), vec![100]);

    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
