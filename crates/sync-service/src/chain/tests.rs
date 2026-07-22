use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, mpsc as std_mpsc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::primitives::{Address, FixedBytes, U256, hex};
use alloy::sol_types::SolEvent;
use broadcaster_core::notes::Note;
use broadcaster_core::query_rpc_pool::QueryRpcPool;
use broadcaster_core::transact::DEFAULT_TXID_VERSION;
use broadcaster_core::utxo::{Utxo, UtxoCommitmentKind, UtxoSource, WalletUtxo};
use cid::Cid;
use ed25519_dalek::SigningKey;
use local_db::{BlobMeta, DbConfig, DbStore, WalletCacheKey, WalletMeta};
use merkletree::tree::MerkleForest;
use multihash_codetable::{Code, MultihashDigest};
use poi::cache::{PoiCache, PoiCacheIdentity};
use poi::poi::PoiEventType;
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
    WalletBackfill, WalletTailFallbackState, wallet_tail_fallback_lag_threshold_blocks,
};
use super::data_plane::{PublicScanCoverageWrite, PublicScanRows};
use super::indexed_wallet::{complete_stream_checkpoint, wallet_startup_hedge_block_count};
use super::logs::combined_log_event_signatures_for_range;
use super::service::{
    WalletShortStartupPlan, await_live_log_task_shutdown, wait_for_startup_sync_target,
    wait_for_wallet_ready,
};
use super::workers::{
    drain_pending_backfill_requests, pending_tip_from_block, pending_tip_provider_covers_target,
};
use super::{
    ChainError, ChainPublicDataPlane, ChainService, CommitmentBatch, ForestReorgDecision,
    GeneratedCommitmentBatch, IndexedWalletArtifactPageOutcome, IndexedWalletArtifactSession,
    IndexedWalletCatchUpSourceOrder, IndexedWalletPageKind, Nullified, Nullifiers,
    PublicCoverageAnswer, PublicDataPlaneDiagnosticKind, PublicDataPlaneError, PublicPoiCorpusKey,
    PublicScanRange, PublicScanRowsAnswer, PublicScanSource, RailgunLegacyShieldEvents, Shield,
    Transact, WalletIndexedCatchUpStatusGuard, WalletStartupSyncError, WalletWorkerServices,
    artifact_failure_can_fallback_to_squid, send_wallet_startup_events,
    should_hedge_wallet_startup, spawn_backfill_loop, squid_tail_target_after_artifact,
    wallet_backfill_from_block, wallet_backfill_lag_blocks, wallet_finish_result_removes_cursor,
    wallet_finish_retry_request, wallet_remote_target_before_cached_suffix,
    wallet_reorg_backfill_from_block, wallet_startup_warm_from_block, wallet_sync_target,
};
use crate::SyncManager;
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
    PoiArtifactManifestSource, PoiArtifactSourceConfig, PoiProxyFallback, SyncProgressStage,
    SyncProgressUnit, WalletBackfillApplyResult, WalletBackfillDriver, WalletBackfillFinishResult,
    WalletBackfillGrant, WalletBackfillOwnerDisposition, WalletBackfillRejectReason,
    WalletBackfillStartResult, WalletConfig, WalletCurrentSnapshot, WalletInactiveReason,
    WalletIndexedCatchUpSource, WalletObservation, WalletPendingOverlay, WalletReadiness,
    WalletReadinessError, WalletScanApply, WalletScanRowsPayload, WalletSyncToken, WalletViewState,
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
    WalletBackfillDriver::from_token(test_sync_token(reset_generation, job_id), sender)
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
    service.cancel.cancel();
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
    let mut cfg = test_wallet_config(&scope, rpc_url);
    cfg.sync_to_block = Some(0);
    cfg.use_indexed_wallet_catch_up = false;
    let terminal = service
        .register_wallet(cfg.clone())
        .await
        .expect("register terminal wallet");
    let worker_cancel = service
        .wallets
        .read()
        .await
        .get(terminal.cache_key.as_str())
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
        3,
        "concurrent retry must create exactly one fresh actor"
    );

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let wallets = service.wallets.read().await;
            if wallets.len() == 1
                && wallets
                    .get(first.cache_key.as_str())
                    .is_some_and(|registration| registration.handle.same_actor_as(&first))
            {
                break;
            }
            drop(wallets);
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

    service.unregister_wallet(&first).await;
    service.cancel.cancel();
    drop(terminal);
    drop(first);
    drop(second);
    drop(service);
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
    let manager = SyncManager::new(Arc::clone(&db), test_proxy_poi_policy());
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
            chain_id: chain.chain_id,
            contract: chain.contract,
        };
        let public_data_plane = ChainPublicDataPlane::new(
            Arc::clone(&db),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        );
        let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
        assert!(service.wallets.read().await.is_empty());
        manager
            .insert_chain_for_test(key, Arc::clone(&service))
            .await;
        registered.push((key, service));
    }

    let report = manager.reset_public_sync_caches().await;

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
        assert!(service.wallets.read().await.is_empty());
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
    let manager = SyncManager::new(Arc::clone(&db), test_proxy_poi_policy());

    let report = manager.reset_public_sync_caches().await;

    assert!(report.is_empty());
    assert_eq!(report.total_removed_entries, 0);
    assert_eq!(report.failed_chain_count(), 0);
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
        chain_id: chain_a.chain_id,
        contract: chain_a.contract,
    };
    let chain_b_key = ChainKey {
        chain_id: chain_b.chain_id,
        contract: chain_b.contract,
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
    let manager = SyncManager::new(Arc::clone(&db_a), test_proxy_poi_policy());
    manager
        .insert_chain_for_test(chain_a_key, Arc::clone(&service_a))
        .await;
    manager
        .insert_chain_for_test(chain_b_key, Arc::clone(&service_b))
        .await;

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
        let mut wallets = service.wallets.write().await;
        let registration = wallets
            .get_mut(handle.cache_key.as_str())
            .expect("wallet registration");
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
    chain.quick_sync_endpoint = Some(rpc_url.clone());
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
    let log_block = 105;
    let target_block = 110;
    let log_response = serde_json::json!([rpc_nullifiers_log(scope.railgun_contract, log_block,)]);
    let responses = [
        serde_json::json!(format!("{target_block:#x}")),
        log_response.clone(),
        rpc_block(log_block, 1_700_000_105, 0x11),
        rpc_block(target_block, 1_700_000_110, 0x22),
        serde_json::json!(format!("{target_block:#x}")),
        log_response,
        rpc_block(log_block, 1_700_000_105, 0x11),
        rpc_block(target_block, 1_700_000_110, 0x22),
    ];
    let rpc = JsonRpcServer::spawn(responses.into());
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    chain.block_range = 10;
    chain.finality_depth = 0;
    chain.quick_sync_endpoint = None;
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

    let first_requests = (0..4)
        .map(|_| {
            rpc.requests
                .recv_timeout(Duration::from_secs(1))
                .expect("first wallet RPC request")
        })
        .collect::<Vec<_>>();
    assert!(
        first_requests
            .iter()
            .any(|request| request.contains("eth_getLogs"))
    );
    let get_logs = first_requests
        .iter()
        .find(|request| request.contains("eth_getLogs"))
        .expect("first wallet eth_getLogs request");
    assert!(get_logs.contains(r#""fromBlock":"0x65""#));
    assert!(get_logs.contains(r#""toBlock":"0x6e""#));

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
        rpc.requests.try_recv().is_err(),
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
        serde_json::json!("0x6f"),
        serde_json::json!([]),
        rpc_block(111, 1_700_000_111, 0x22),
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    chain.block_range = 10;
    chain.finality_depth = 0;
    chain.quick_sync_endpoint = None;
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

    let first_requests = (0..3)
        .map(|_| {
            rpc.requests
                .recv_timeout(Duration::from_secs(1))
                .expect("first wallet RPC request")
        })
        .collect::<Vec<_>>();
    let first_get_logs = first_requests
        .iter()
        .find(|request| request.contains("eth_getLogs"))
        .expect("first wallet eth_getLogs request");
    assert!(first_get_logs.contains(r#""fromBlock":"0x65""#));
    assert!(first_get_logs.contains(r#""toBlock":"0x6e""#));

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
async fn wallet_startup_warms_pre_cursor_gap_before_cached_suffix() {
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
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    chain.block_range = 10;
    chain.finality_depth = 0;
    chain.quick_sync_endpoint = None;
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

    let requests = (0..4)
        .map(|_| {
            rpc.requests
                .recv_timeout(Duration::from_secs(1))
                .expect("RPC gap request")
        })
        .collect::<Vec<_>>();
    let get_logs = requests
        .iter()
        .find(|request| request.contains("eth_getLogs"))
        .expect("eth_getLogs request");
    assert!(get_logs.contains(r#""fromBlock":"0x65""#));
    assert!(get_logs.contains(r#""toBlock":"0x69""#));

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
    chain.block_range = 10;
    chain.finality_depth = 0;
    chain.quick_sync_endpoint = None;
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
async fn wallet_startup_rpc_candidate_acquires_before_exact_delivery_boundary() {
    let root_dir = temp_db_root("wallet-startup-exact-delivery-boundary");
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
        rpc_block(105, 1_700_000_105, 0x11),
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    chain.block_range = 10;
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
    let coverage_events_before_candidate = public_data_plane
        .diagnostics()
        .await
        .events
        .iter()
        .filter(|event| event.kind == PublicDataPlaneDiagnosticKind::CoverageRecorded)
        .count();
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

    assert_eq!(candidate.applies.len(), 1);
    assert_eq!(
        (
            candidate.applies[0].from_block,
            candidate.applies[0].to_block
        ),
        (106, 110),
        "only the delivery suffix is returned to the wallet",
    );
    let requests = (0..3)
        .map(|_| {
            rpc.requests
                .recv_timeout(Duration::from_secs(1))
                .expect("RPC acquisition request")
        })
        .collect::<Vec<_>>();
    let get_logs = requests
        .iter()
        .find(|request| request.contains("eth_getLogs"))
        .expect("eth_getLogs request");
    assert!(get_logs.contains(r#""fromBlock":"0x65""#));
    assert!(get_logs.contains(r#""toBlock":"0x69""#));
    let retained_before_selection = service
        .public_data_plane
        .cached_wallet_scan_suffix(101, 110)
        .await
        .expect("pre-existing delivery suffix remains cached");
    assert_eq!(
        retained_before_selection
            .first()
            .expect("cached delivery suffix")
            .from_block,
        106,
        "an unselected candidate must not publish the missing acquisition prefix",
    );
    assert_eq!(
        service
            .public_data_plane
            .diagnostics()
            .await
            .events
            .iter()
            .filter(|event| event.kind == PublicDataPlaneDiagnosticKind::CoverageRecorded)
            .count(),
        coverage_events_before_candidate,
        "candidate acquisition must not mutate row or coverage state",
    );
    service
        .public_data_plane
        .commit_completed_short_startup_acquisition(
            PublicScanRange::new(101, 110),
            &candidate.acquisition_applies,
        )
        .await
        .expect("commit selected RPC acquisition");
    assert!(
        service
            .public_data_plane
            .cached_wallet_scan_suffix(101, 110)
            .await
            .is_some(),
        "explicit winner commit must retain the full acquisition window",
    );

    service.shutdown().await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_startup_rpc_candidate_rejects_zero_provider_coverage() {
    let root_dir = temp_db_root("wallet-startup-zero-rpc-coverage");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc = JsonRpcServer::spawn(vec![serde_json::json!("0x64")]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    chain.block_range = 10;
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
        Err(WalletStartupSyncError::IncompleteRpcCoverage {
            requested_to: 110,
            proven_to: 100,
        })
    ));
    assert!(
        rpc.requests
            .recv_timeout(Duration::from_secs(1))
            .expect("RPC head request")
            .contains("eth_blockNumber")
    );
    assert!(rpc.requests.try_recv().is_err());
    service.shutdown().await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
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
    chain.block_range = 10;
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
    let rpc = JsonRpcServer::spawn(vec![
        serde_json::json!("0x6e"),
        serde_json::json!([]),
        serde_json::json!([]),
        serde_json::Value::Null,
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    chain.archive_until_block = 105;
    chain.block_range = 10;
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
        Err(WalletStartupSyncError::UnprovenRpcEndpoint { block_number: 105 })
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
async fn multi_page_squid_startup_retains_leading_rows_for_replacement_wallet() {
    let root_dir = temp_db_root("indexed-wallet-warm-window");
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
            random: [0x11; 16],
            npk: U256::from(2),
        },
        1,
        7,
        UtxoSource {
            tx_hash: FixedBytes::from([0x55; 32]),
            block_number: 100,
            block_timestamp: 1_700_000_100,
        },
        UtxoCommitmentKind::Transact,
    ));
    let replacement_nullifier = replacement_wallet_utxo.utxo.nullifier(U256::ZERO);
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
    let squid = GraphqlServer::spawn_owned(squid_responses);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![Url::parse("http://127.0.0.1:1").expect("RPC URL")],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    chain.block_range = 6;
    chain.indexed_wallet_block_range = 1;
    chain.finality_depth = 0;
    chain.quick_sync_endpoint = Some(squid.url.clone());
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
    service.safe_head_tx.send_replace(106);

    let mut first_cfg = test_wallet_config(&scope, squid.url.clone());
    first_cfg.cache_key = test_cache_key("indexed-wallet-a");
    first_cfg.start_block = Some(101);
    first_cfg.sync_to_block = Some(106);
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
        .expect("indexed warm startup completed")
        .expect("wallet readiness succeeded");
    assert_eq!(first.last_scanned(), Some(106));
    let first_requests = (0..7)
        .map(|_| {
            squid
                .requests
                .recv_timeout(Duration::from_secs(1))
                .expect("first wallet indexed request")
        })
        .collect::<Vec<_>>();
    for block_number in 101..=106 {
        assert!(first_requests.iter().any(|request| {
            request.contains(&format!("\"fromBlock\":\"{block_number}\""))
                && request.contains(&format!("\"toBlock\":\"{block_number}\""))
        }));
    }
    let replay = service
        .public_data_plane
        .cached_wallet_scan_suffix(101, 106)
        .await
        .expect("full multi-page Squid acquisition is replayable");
    assert_eq!(
        replay.len(),
        1,
        "six Squid pages should compact into one run"
    );
    let WalletScanRowsPayload::Rows(rows) = &replay[0].rows.payload else {
        panic!("compacted Squid rows expected");
    };
    assert_eq!(rows.nullifiers.len(), 6);
    assert_eq!(rows.nullifiers[0].source.block_number, 101);
    assert_eq!(rows.nullifiers[0].nullifier, replacement_nullifier);

    service.unregister_all_wallets().await;

    let mut second_cfg = test_wallet_config(&scope, squid.url.clone());
    second_cfg.cache_key = test_cache_key("indexed-wallet-b");
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
        "1:7",
        &serialize_wallet_utxo(&replacement_wallet_utxo).expect("serialize replacement UTXO"),
    )
    .expect("seed replacement wallet UTXO");
    let mut second = service
        .register_wallet(second_cfg)
        .await
        .expect("register replacement wallet");
    tokio::time::timeout(Duration::from_secs(1), second.wait_until_ready())
        .await
        .expect("replacement wallet reused indexed warm window")
        .expect("wallet readiness succeeded");
    assert_eq!(second.last_scanned(), Some(106));
    let replacement_snapshot = second
        .utxos_snapshot()
        .expect("replacement wallet snapshot");
    let spent = replacement_snapshot[0]
        .spent
        .as_ref()
        .expect("leading cached nullifier marks replacement UTXO spent");
    assert_eq!(spent.block_number, 101);
    assert!(
        squid.requests.try_recv().is_err(),
        "replacement wallet must not issue another indexed request"
    );

    service.unregister_all_wallets().await;
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
    let squid = GraphqlServer::spawn_owned(squid_responses);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    chain.block_range = 6;
    chain.indexed_wallet_block_range = 1;
    chain.finality_depth = 0;
    chain.quick_sync_endpoint = Some(squid.url.clone());
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

    let PathServerBlockControl {
        request_started: rpc_request_started,
        release: rpc_release,
    } = rpc_block;
    tokio::time::timeout(
        Duration::from_secs(2),
        tokio::task::spawn_blocking(move || {
            rpc_request_started.recv().expect("RPC log request blocked");
        }),
    )
    .await
    .expect("RPC loser reached its log request")
    .expect("RPC block wait completed");
    tokio::time::timeout(Duration::from_secs(2), first.wait_until_ready())
        .await
        .expect("Squid winner delivered while RPC response remained blocked")
        .expect("wallet readiness succeeded");
    rpc_release
        .send(())
        .expect("release terminated RPC request for fixture cleanup");

    let replay = public_data_plane
        .cached_wallet_scan_suffix(101, 106)
        .await
        .expect("complete Squid acquisition remains replayable");
    let WalletScanRowsPayload::Rows(rows) = &replay[0].rows.payload else {
        panic!("Squid winner rows expected");
    };
    assert_eq!(rows.nullifiers.len(), 6);
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
    assert_eq!(squid_requests.len(), 7);

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
async fn failed_short_startup_hedge_uses_artifact_window_and_reuses_it() {
    let root_dir = temp_db_root("wallet-startup-artifact-fallback-window");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let artifact_source = checkpointed_wallet_artifact_source(&scope, 101, 110, 110);
    let squid = GraphqlServer::spawn(vec![
        r#"{"errors":[{"message":"indexed source unavailable"}]}"#,
    ]);
    let rpc = JsonRpcServer::spawn(vec![serde_json::json!("0x64")]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, Some(artifact_source.config.clone()));
    chain.block_range = 10;
    chain.indexed_wallet_block_range = 10;
    chain.finality_depth = 0;
    chain.quick_sync_endpoint = Some(squid.url.clone());
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
    assert_eq!(artifact_source.server.request_count(), 3);
    assert!(
        rpc.requests
            .recv_timeout(Duration::from_secs(1))
            .expect("failed RPC hedge request")
            .contains("eth_blockNumber")
    );
    assert!(
        squid
            .requests
            .recv_timeout(Duration::from_secs(1))
            .expect("failed Squid hedge request")
            .contains("query WalletProbe")
    );

    service.unregister_all_wallets().await;

    let mut second_cfg = test_wallet_config(&scope, squid.url.clone());
    second_cfg.cache_key = test_cache_key("artifact-fallback-wallet-b");
    second_cfg.start_block = Some(101);
    second_cfg.sync_to_block = Some(110);
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
        .expect("replacement wallet reused artifact warm window")
        .expect("wallet readiness succeeded");
    assert_eq!(second.last_scanned(), Some(110));
    assert_eq!(
        artifact_source.server.request_count(),
        3,
        "replacement wallet should reuse the cached acquisition window without HTTP"
    );
    assert!(rpc.requests.try_recv().is_err());
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
    let mut cursors = HashMap::new();
    cursors.insert(
        "test".to_string(),
        WalletBackfill::new(
            100,
            1_000,
            true,
            100,
            None,
            test_backfill_driver(old_sender, 0, 1),
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
            acquisition_range: None,
            driver: test_backfill_driver(new_sender, 1, 2),
        })
        .expect("queue reset replacement backfill");

    drain_pending_backfill_requests(&mut request_rx, &mut cursors).await;

    let cursor = cursors.get("test").expect("cursor retained");
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
    let mut cursors = HashMap::from([(
        "test".to_string(),
        WalletBackfill::new(
            100,
            120,
            false,
            100,
            None,
            WalletBackfillDriver::from_token(replacement_token, event_tx),
            std::time::Instant::now(),
        ),
    )]);
    request_tx
        .try_send(BackfillRequest::Remove {
            cache_key: "test".to_string(),
            actor_id: 1,
        })
        .expect("queue stale actor removal");

    drain_pending_backfill_requests(&mut request_rx, &mut cursors).await;

    assert_eq!(
        cursors
            .get("test")
            .expect("replacement cursor remains")
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
    let mut cursors = HashMap::new();
    cursors.insert(
        "test".to_string(),
        WalletBackfill::new(
            100,
            1_000,
            true,
            100,
            None,
            test_backfill_driver(active_sender, 1, 2),
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
            acquisition_range: None,
            driver: test_backfill_driver(stale_sender, 0, 1),
        })
        .expect("queue stale replacement backfill");

    drain_pending_backfill_requests(&mut request_rx, &mut cursors).await;

    let cursor = cursors.get("test").expect("active cursor retained");
    assert_eq!(cursor.from_block, 100);
    assert_eq!(cursor.target_block, 1_000);
    assert_eq!(cursor.driver.token().reset_generation(), 1);
    assert_eq!(cursor.driver.token().job_id(), 2);
    assert!(stale_receiver.is_empty());
    assert!(active_receiver.is_empty());
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
        None,
        test_backfill_driver(sender, 0, 1),
        now.checked_sub(std::time::Duration::from_secs(20))
            .expect("test instant supports 20 second subtraction"),
    );

    assert_eq!(
        wallet_backfill_lag_blocks(cursor.from_block, cursor.target_block),
        61
    );
    assert!(cursor.should_try_indexed_tail_fallback(
        42161,
        now,
        std::time::Duration::from_secs(15),
        std::time::Duration::from_mins(1),
    ));

    cursor.mark_indexed_tail_attempt(now);
    assert!(!cursor.should_try_indexed_tail_fallback(
        42161,
        now + std::time::Duration::from_secs(30),
        std::time::Duration::from_secs(15),
        std::time::Duration::from_mins(1),
    ));
    assert!(cursor.should_try_indexed_tail_fallback(
        42161,
        now + std::time::Duration::from_mins(1),
        std::time::Duration::from_secs(15),
        std::time::Duration::from_mins(1),
    ));

    cursor.mark_progress(150, now + std::time::Duration::from_mins(1));
    assert!(!cursor.should_try_indexed_tail_fallback(
        42161,
        now + std::time::Duration::from_secs(70),
        std::time::Duration::from_secs(15),
        std::time::Duration::from_mins(1),
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

    assert!(state.should_try_indexed_tail_fallback(
        42161,
        101,
        160,
        now,
        std::time::Duration::from_secs(15),
        std::time::Duration::from_mins(1),
    ));

    state.mark_indexed_tail_attempt(now);
    assert!(!state.should_try_indexed_tail_fallback(
        42161,
        101,
        160,
        now + std::time::Duration::from_secs(30),
        std::time::Duration::from_secs(15),
        std::time::Duration::from_mins(1),
    ));

    state.update_last_scanned(130, now + std::time::Duration::from_secs(30));
    assert!(!state.should_try_indexed_tail_fallback(
        42161,
        131,
        190,
        now + std::time::Duration::from_secs(40),
        std::time::Duration::from_secs(15),
        std::time::Duration::from_mins(1),
    ));

    assert!(state.should_try_indexed_tail_fallback(
        42161,
        131,
        190,
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
    let rpc = JsonRpcServer::spawn(vec![
        serde_json::json!([]),
        rpc_block(199, 1_700_000_199, 0x11),
    ]);
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
    wallet_a_cfg.cache_key = test_cache_key("wallet-a");
    wallet_a_cfg.sync_to_block = Some(199);
    wallet_a_cfg.quick_sync_endpoint = None;
    wallet_a_cfg.use_indexed_wallet_catch_up = false;
    let mut wallet_b_cfg = test_wallet_config(&scope, rpc.url.clone());
    let wallet_b_cache_key = test_cache_key("wallet-b");
    wallet_b_cfg.cache_key = wallet_b_cache_key.clone();
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
    let wallet_a_lease =
        match send_wallet_target("wallet-a", &wallet_a_tx, 199, wallet_a_token).await {
            WalletBackfillStartResult::Accepted { grant, .. } => grant.activate(),
            result @ WalletBackfillStartResult::Rejected { .. } => {
                panic!("wallet A target rejected: {result:?}")
            }
        };
    let wallet_b_lease =
        match send_wallet_target("wallet-b", &wallet_b_tx, 130, wallet_b_token).await {
            WalletBackfillStartResult::Accepted { grant, .. } => grant.activate(),
            result @ WalletBackfillStartResult::Rejected { .. } => {
                panic!("wallet B target rejected: {result:?}")
            }
        };
    backfill_request_tx
        .send(BackfillRequest::Add {
            cache_key: "wallet-a".to_string(),
            from_block: 100,
            to_block: 199,
            follow_safe_head: false,
            progress_start_block: 100,
            acquisition_range: None,
            driver: wallet_a_lease,
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
            acquisition_range: None,
            driver: wallet_b_lease,
        })
        .await
        .expect("send wallet B backfill request");

    tokio::time::timeout(Duration::from_secs(2), async {
        while wallet_a.last_scanned() != Some(199)
            || wallet_b.last_scanned() != Some(130)
            || !wallet_a.readiness().is_ready()
            || !wallet_b.readiness().is_ready()
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("wallet backfill loop completed");

    assert_eq!(wallet_a.last_scanned(), Some(199));
    assert_eq!(wallet_b.last_scanned(), Some(130));
    assert_eq!(
        db.get_wallet_meta(&wallet_b_cache_key)
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
    chain.block_range = 100;
    chain.poll_interval = Duration::from_millis(1);
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
    let (backfill_request_tx, backfill_request_rx) = mpsc::channel(1);
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

    backfill_request_tx
        .send(BackfillRequest::add(
            "test",
            100,
            110,
            false,
            100,
            test_backfill_driver(wallet_tx, 0, 1),
        ))
        .await
        .expect("send stale wallet backfill request");

    tokio::time::timeout(Duration::from_secs(2), actor)
        .await
        .expect("rebased wallet backfill completed")
        .expect("actor response task completed");

    cancel.cancel();
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_backfill_loop_acquires_warm_gap_before_delivering_cached_suffix() {
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
        rpc_block(105, 1_700_000_105, 0x11),
        serde_json::json!([]),
        rpc_block(110, 1_700_000_110, 0x22),
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, Arc::clone(&rpcs), None);
    chain.block_range = 100;
    chain.poll_interval = Duration::from_millis(1);
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
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
    let (backfill_request_tx, backfill_request_rx) = mpsc::channel(1);
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
            panic!("cached suffix apply expected");
        };
        assert_eq!((apply.from_block, apply.to_block), (106, 110));
        assert_eq!(apply.rows.source, PublicScanSource::CachedCoverage);
        response
            .send(WalletBackfillApplyResult::Committed { committed_to: 110 })
            .expect("commit cached suffix");

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

    backfill_request_tx
        .send(BackfillRequest::add_with_acquisition(
            "test",
            106,
            110,
            false,
            106,
            (100, 110),
            test_backfill_driver(wallet_tx, 0, 1),
        ))
        .await
        .expect("send wallet backfill request");
    tokio::time::timeout(Duration::from_secs(2), actor)
        .await
        .expect("cached suffix backfill completed")
        .expect("actor response task completed");

    let requests = (0..2)
        .map(|_| {
            rpc.requests
                .recv_timeout(Duration::from_secs(1))
                .expect("RPC gap request")
        })
        .collect::<Vec<_>>();
    let get_logs = requests
        .iter()
        .find(|request| request.contains("eth_getLogs"))
        .expect("eth_getLogs request");
    assert!(get_logs.contains(r#""fromBlock":"0x64""#));
    assert!(get_logs.contains(r#""toBlock":"0x69""#));
    assert!(rpc.requests.try_recv().is_err());
    assert!(
        service
            .public_data_plane
            .cached_wallet_scan_suffix(100, 110)
            .await
            .is_some(),
        "successful scheduler acquisition must retain the full warm window"
    );

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
    chain.block_range = 100;
    chain.poll_interval = Duration::from_millis(1);
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
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
    let (backfill_request_tx, backfill_request_rx) = mpsc::channel(1);
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

    backfill_request_tx
        .send(BackfillRequest::add_with_acquisition(
            "test",
            106,
            110,
            false,
            106,
            (100, 110),
            test_backfill_driver(wallet_tx, 0, 1),
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
    chain.block_range = 100;
    chain.poll_interval = Duration::from_millis(1);
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
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane.clone());
    let (backfill_request_tx, backfill_request_rx) = mpsc::channel(1);
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

    backfill_request_tx
        .send(BackfillRequest::add_with_acquisition(
            "test",
            106,
            110,
            false,
            106,
            (100, 110),
            test_backfill_driver(wallet_tx, 0, 1),
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
    chain.block_range = 100;
    chain.poll_interval = Duration::from_millis(1);
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
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane.clone());
    let (backfill_request_tx, backfill_request_rx) = mpsc::channel(1);
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

    backfill_request_tx
        .send(BackfillRequest::add_with_acquisition(
            "test",
            106,
            110,
            false,
            106,
            (100, 110),
            test_backfill_driver(wallet_tx, 0, 1),
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
    let artifact_source = checkpointed_wallet_artifact_source(&scope, 100, 200, 150);
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
            (
                &wallet_backfill_tx,
                crate::types::WalletSchedulableProgress {
                    last_scanned: 100,
                    reset_generation: 0,
                },
            ),
        )
        .await;

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
    let (progress_tx, progress_rx) = watch::channel(None);
    let mut wallet_cfg = test_wallet_config(
        &scope,
        Url::parse("http://127.0.0.1:1").expect("quick-sync url"),
    );
    wallet_cfg.progress_tx = Some(progress_tx);
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
        6,
        "warm preparation should reuse stable history and the unchanged transient tail"
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
    let (squid, block) = GraphqlServer::spawn_with_blocked_response(
        vec![
            r#"{"data":{"squidStatus":{"height":"200"},"transactCommitments":[],"shieldCommitments":[],"nullifiers":[],"legacyEncryptedCommitments":[],"legacyGeneratedCommitments":[]}}"#,
            r#"{"data":{"transactCommitments":[],"shieldCommitments":[],"nullifiers":[]}}"#,
        ],
        0,
    );
    let context = IndexedCatchUpTestContext::new(
        &scope,
        squid.url.clone(),
        Some(artifact_source.config.clone()),
        100,
        100,
    )
    .await;
    let catch_up = context.spawn_catch_up(200, IndexedWalletCatchUpSourceOrder::ArtifactsFirst);

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
    chain.block_range = 100;
    chain.indexed_wallet_block_range = 1_000;
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
        rpc_block(100, 1_700_000_100, 0x10),
        rpc_block(150, 1_700_000_150, 0x15),
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
    chain.archive_until_block = 100;
    chain.block_range = 100;
    chain.indexed_wallet_block_range = 100;
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
        chain.quick_sync_endpoint = Some(quick_sync_endpoint.clone());
        chain.indexed_wallet_block_range = indexed_wallet_block_range;
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
        std::thread::spawn({
            let routes = Arc::clone(&routes);
            let requests = Arc::clone(&requests);
            move || {
                for _ in 0..request_count {
                    let (stream, _) = listener.accept().expect("accept path request");
                    requests.fetch_add(1, Ordering::AcqRel);
                    let routes = Arc::clone(&routes);
                    let block = block.clone();
                    std::thread::spawn(move || {
                        handle_path_request(stream, &routes, block.as_deref());
                    });
                }
            }
        });
        Self { url, requests }
    }

    fn request_count(&self) -> u64 {
        self.requests.load(Ordering::Acquire)
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

    fn spawn_owned(responses: Vec<String>) -> Self {
        Self::spawn_controlled(responses, None)
    }

    fn spawn_with_blocked_response(
        responses: Vec<&'static str>,
        blocked_response: usize,
    ) -> (Self, PathServerBlockControl) {
        let (request_started_tx, request_started) = std_mpsc::channel();
        let (release, release_rx) = std_mpsc::channel();
        let block = Arc::new(GraphqlServerBlock {
            request_started: request_started_tx,
            release: std::sync::Mutex::new(release_rx),
        });
        let server = Self::spawn_controlled(
            responses.into_iter().map(str::to_owned).collect(),
            Some((blocked_response, block)),
        );
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
    stream.write_all(headers.as_bytes()).expect("write headers");
    stream.write_all(response.as_bytes()).expect("write body");
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
