use super::commit::wallet_scan_progress_update;
use super::poi_maintenance::{
    PoiMaintenanceAbortReason, ppoi_workflow_status_with_candidate_report,
    run_poi_maintenance_with_watchdog, sync_poi_refreshing_from_controller,
    wallet_poi_refresh_interval_with_period,
};
use super::test_support::spawn_wallet_worker;
use super::*;
use crate::types::WalletResetToken;
use crate::wallet::actor::PoiRemoteJobKind;
use std::sync::atomic::Ordering;

#[tokio::test]
async fn maintenance_watchdog_converts_timeout_and_panic_to_sanitized_abort_reasons() {
    let timeout =
        run_poi_maintenance_with_watchdog(std::future::pending::<()>(), Duration::from_millis(1))
            .await
            .expect_err("maintenance timeout should abort");
    assert_eq!(timeout, PoiMaintenanceAbortReason::Timeout);
    assert_eq!(timeout.category(), "timeout");

    let panic = run_poi_maintenance_with_watchdog(
        async { panic!("test maintenance panic") },
        Duration::from_secs(1),
    )
    .await
    .expect_err("maintenance panic should abort");
    assert_eq!(panic, PoiMaintenanceAbortReason::Panic);
    assert_eq!(panic.category(), "panic");
}

#[test]
fn wallet_scan_progress_retains_configured_baseline_across_pages() {
    const DEPLOYMENT_BLOCK: u64 = 14_737_691;
    const CURRENT_BLOCK: u64 = 25_305_894;
    const TARGET_BLOCK: u64 = 25_537_418;

    let observed_page = wallet_scan_progress_update(
        Some(DEPLOYMENT_BLOCK),
        25_083_449,
        CURRENT_BLOCK,
        TARGET_BLOCK,
        PublicScanSource::Rpc,
    );
    let later_page = wallet_scan_progress_update(
        Some(DEPLOYMENT_BLOCK),
        CURRENT_BLOCK.saturating_add(1),
        25_500_000,
        TARGET_BLOCK,
        PublicScanSource::ArchiveRpc,
    );

    assert_eq!(observed_page.start_block, DEPLOYMENT_BLOCK);
    assert_eq!(observed_page.percent(), 97);
    assert_eq!(observed_page.source, Some(PublicScanSource::Rpc));
    assert_eq!(later_page.start_block, DEPLOYMENT_BLOCK);
    assert!(later_page.percent() >= observed_page.percent());
    assert_eq!(later_page.source, Some(PublicScanSource::ArchiveRpc));

    let fallback = wallet_scan_progress_update(
        None,
        25_083_449,
        CURRENT_BLOCK,
        TARGET_BLOCK,
        PublicScanSource::CachedCoverage,
    );
    assert_eq!(fallback.start_block, 25_083_449);
    assert_eq!(fallback.percent(), 49);
    assert_eq!(fallback.source, Some(PublicScanSource::CachedCoverage));
}
use crate::{WalletPpoiSubmissionStatus, WalletPpoiWorkflowStatus, WalletReadiness};

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use alloy::primitives::{Address, FixedBytes, U256};
use async_trait::async_trait;
use broadcaster_core::contracts::railgun::CommitmentCiphertext;
use broadcaster_core::crypto::railgun::ViewingKeyData;
use broadcaster_core::notes::Note;
use broadcaster_core::transact::DEFAULT_TXID_VERSION;
use local_db::{
    DbConfig, DbStore, OpaqueWalletPrivateRow, OutputPoiRecoveryRecord, OutputPoiRecoveryStatus,
    PendingOutputPoiContextRecord, PendingOutputPoiObservation, PendingOutputPoiRole,
    WalletCacheKey, WalletMeta, WalletPrivateRecordKind,
};
use merkletree::tree::MerkleForest;
use poi::artifacts::SnapshotEvent;
use poi::cache::{PoiCache, PoiCacheIdentity};
use poi::error::PoiError;
use poi::poi::{BlindedCommitmentData, PoiEventType};
use tokio::sync::{RwLock, broadcast, mpsc, oneshot, watch};
use url::Url;

use railgun_wallet::scan::{
    CommitmentObservation, SenderScanOutput, SpentNullifier, WalletLogDelta,
};
use railgun_wallet::{NoteCiphertext, PoiStatus, Utxo, UtxoCommitmentKind, UtxoSource, WalletUtxo};

use crate::chain::ChainPublicDataPlane;
use crate::types::{
    BackfillRequest, ChainKey, GlobalPoiPolicy, LogBatch, PoiArtifactManifestSource,
    PoiArtifactSourceConfig, PoiProxyFallback, PublicDataPlaneEpoch, PublicScanReadScope,
    WalletBackfillDriver, WalletConfig, WalletIndexedCatchUpSource, WalletIndexedCatchUpStatus,
    WalletObservation, WalletPendingSpent, WalletScanRows,
};
use crate::wallet::handle::{
    PendingOutputPoiSubject, WalletPendingOverlayRequest, WalletPrivateViewTicket,
};
use crate::wallet::pending_output_poi::{
    PendingOutputPoiPreflight, PendingOutputPoiSubmissionPlan, current_pending_output_poi_subject,
    expected_recovery_state, pending_output_poi_submission_plan_current,
    pending_output_poi_submit_identity,
};
use crate::wallet::{EVM_CHAIN_TYPE, WalletActorLifecycle};

#[test]
fn tentative_failed_identity_is_released_for_retry() {
    let mut tracker = PendingOutputPoiTentativeAttemptTracker::default();
    let candidate = PendingOutputPoiTentativeCandidate::for_test();
    let key = candidate.attempt_key();
    assert!(tracker.reserve(0, candidate.clone()));
    assert!(!tracker.reserve(0, candidate.clone()));
    tracker.release_retryable(0, std::slice::from_ref(&key));
    assert!(tracker.reserve(0, candidate));
}

#[test]
fn tentative_valid_projection_requires_exact_overlay_identity() {
    let candidate = PendingOutputPoiTentativeCandidate::for_test();
    let list_key = candidate.list_keys()[0];
    let mut tracker = PendingOutputPoiTentativeAttemptTracker::default();
    assert!(tracker.reserve(0, candidate.clone()));
    tracker.accept(0, std::slice::from_ref(&candidate));
    tracker.record_local_statuses(
        0,
        &[PendingOutputPoiTentativeLocalStatus {
            candidate,
            valid_list_keys: vec![list_key],
        }],
    );

    let mut wallet_utxo = test_wallet_utxo(3, 2);
    wallet_utxo.utxo.tree = 1;
    wallet_utxo.utxo.source = UtxoSource {
        tx_hash: FixedBytes::from([0x22; 32]),
        block_number: 3,
        block_timestamp: 4,
    };
    wallet_utxo.utxo.poi.commitment = FixedBytes::from([0x11; 32]);
    wallet_utxo.utxo.poi.statuses.clear();
    let mut overlay = WalletPendingOverlay {
        new_utxos: vec![wallet_utxo],
        ..WalletPendingOverlay::default()
    };
    assert!(tracker.apply_to_overlay(0, &mut overlay, 10));
    assert_eq!(
        overlay.new_utxos[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );

    overlay.new_utxos[0].utxo.position += 1;
    overlay.new_utxos[0].utxo.poi.statuses.clear();
    assert!(!tracker.apply_to_overlay(0, &mut overlay, 11));
    assert!(overlay.new_utxos[0].utxo.poi.statuses.is_empty());
}

#[test]
fn tentative_attempt_pruning_requires_current_exact_observation() {
    let candidate = PendingOutputPoiTentativeCandidate::for_test();
    let key = candidate.attempt_key();
    let mut tracker = PendingOutputPoiTentativeAttemptTracker::default();
    assert!(tracker.reserve(0, candidate.clone()));
    tracker.accept(0, std::slice::from_ref(&candidate));
    tracker.record_local_statuses(
        0,
        &[PendingOutputPoiTentativeLocalStatus {
            candidate: candidate.clone(),
            valid_list_keys: vec![candidate.list_keys()[0]],
        }],
    );
    let mut wallet_utxo = test_wallet_utxo(3, 2);
    wallet_utxo.utxo.tree = 1;
    wallet_utxo.utxo.source = UtxoSource {
        tx_hash: FixedBytes::from([0x22; 32]),
        block_number: 3,
        block_timestamp: 4,
    };
    wallet_utxo.utxo.poi.commitment = FixedBytes::from([0x11; 32]);
    let mut overlay = WalletPendingOverlay {
        new_utxos: vec![wallet_utxo],
        ..WalletPendingOverlay::default()
    };

    tracker.prune_for_observations(0, std::slice::from_ref(candidate.observation()));
    assert!(tracker.attempts.contains_key(&(0, key.clone())));
    assert!(tracker.apply_to_overlay(0, &mut overlay, 10));

    let mut changed_coordinate = candidate.observation().clone();
    changed_coordinate.position += 1;
    tracker.prune_for_observations(0, &[changed_coordinate]);
    assert!(!tracker.attempts.contains_key(&(0, key.clone())));
    assert!(!tracker.valid_lists.contains_key(&(0, key)));
    overlay.new_utxos[0].utxo.poi.statuses.clear();
    assert!(!tracker.apply_to_overlay(0, &mut overlay, 11));

    let mut source_changed_tracker = PendingOutputPoiTentativeAttemptTracker::default();
    assert!(source_changed_tracker.reserve(0, candidate.clone()));
    source_changed_tracker.accept(0, std::slice::from_ref(&candidate));
    source_changed_tracker.record_local_statuses(
        0,
        &[PendingOutputPoiTentativeLocalStatus {
            candidate: candidate.clone(),
            valid_list_keys: vec![candidate.list_keys()[0]],
        }],
    );
    let mut changed_source = candidate.observation().clone();
    changed_source.source.tx_hash = FixedBytes::from([0xaa; 32]);
    source_changed_tracker.prune_for_observations(0, &[changed_source]);
    assert!(source_changed_tracker.attempts.is_empty());
    assert!(source_changed_tracker.valid_lists.is_empty());
}

#[test]
fn tentative_validity_is_monotonic_until_pruned() {
    let candidate = PendingOutputPoiTentativeCandidate::for_test();
    let key = candidate.attempt_key();
    let first_list = candidate.list_keys()[0];
    let second_list = candidate.list_keys()[1];
    let mut tracker = PendingOutputPoiTentativeAttemptTracker::default();
    assert!(tracker.reserve(0, candidate.clone()));
    tracker.accept(0, std::slice::from_ref(&candidate));

    assert_eq!(
        tracker.record_local_statuses(
            0,
            &[PendingOutputPoiTentativeLocalStatus {
                candidate: candidate.clone(),
                valid_list_keys: vec![first_list],
            }],
        ),
        (1, 1)
    );
    assert_eq!(
        tracker.record_local_statuses(
            0,
            &[PendingOutputPoiTentativeLocalStatus {
                candidate: candidate.clone(),
                valid_list_keys: Vec::new(),
            }],
        ),
        (0, 0)
    );
    assert_eq!(
        tracker.record_local_statuses(
            0,
            &[PendingOutputPoiTentativeLocalStatus {
                candidate: candidate.clone(),
                valid_list_keys: vec![second_list],
            }],
        ),
        (1, 1)
    );
    tracker.accept(0, std::slice::from_ref(&candidate));
    assert_eq!(
        tracker.valid_lists[&(0, key)],
        BTreeSet::from([first_list, second_list])
    );
}

#[tokio::test]
async fn committed_corpus_revision_waiter_observes_latest_revision() {
    let (revision_tx, revision_rx) = watch::channel(PoiCorpusRevision::default());
    let mut revision_rx = Some(revision_rx);

    let first = PoiCorpusRevision {
        revision: 1,
        blocked_shields_revision: 0,
    };
    revision_tx.send_replace(first);
    assert_eq!(
        next_poi_corpus_revision(&mut revision_rx).await,
        Some(first)
    );
    let latest = PoiCorpusRevision {
        revision: 3,
        blocked_shields_revision: 2,
    };
    revision_tx.send_replace(latest);
    assert_eq!(
        next_poi_corpus_revision(&mut revision_rx).await,
        Some(latest)
    );
    drop(revision_tx);
    assert_eq!(next_poi_corpus_revision(&mut revision_rx).await, None);
}

#[tokio::test]
async fn wallet_poi_refresh_interval_is_not_restarted_by_other_work() {
    let period = Duration::from_millis(100);
    let mut interval = wallet_poi_refresh_interval_with_period(period);

    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    tokio::time::timeout(Duration::from_millis(70), interval.tick())
        .await
        .expect("persistent refresh interval should retain its original deadline");
}

#[tokio::test]
async fn poi_refresh_projection_does_not_wait_for_authority_lock() {
    let root_dir = temp_db_root("poi-refresh-projection-lock");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
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
            backfill_sender: backfill_tx,
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");
    let (poi_refreshing_tx, poi_refreshing_rx) = watch::channel(false);
    let mut controller = PoiMaintenanceController::new();
    controller
        .request(
            false,
            true,
            Some(WalletActorCredential::current_for(&handle)),
        )
        .expect("start maintenance controller");

    let _authority_guard = handle.authority_lock.lock().await;
    sync_poi_refreshing_from_controller(&controller, &poi_refreshing_tx, &handle, &cancel);
    assert!(*poi_refreshing_rx.borrow());

    let key = WalletActorCredential::current_for(&handle);
    assert!(controller.request(true, true, Some(key)).is_none());
    assert!(controller.on_job_done(PoiRemoteJobKey {
        actor_id: key.actor_id,
        reset_generation: key.reset_generation,
        kind: PoiRemoteJobKind::Maintenance,
    }));
    sync_poi_refreshing_from_controller(&controller, &poi_refreshing_tx, &handle, &cancel);
    assert!(!*poi_refreshing_rx.borrow());
    assert!(controller.try_start(true, Some(key)).is_some());

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

fn test_public_data_plane(db: &Arc<DbStore>) -> ChainPublicDataPlane {
    ChainPublicDataPlane::new(Arc::clone(db), Arc::new(AtomicU64::new(0)))
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

fn test_artifact_poi_runtime() -> WalletPoiRuntime {
    WalletPoiRuntime::from_policy(
        &GlobalPoiPolicy::IndexedArtifacts {
            artifact_source: test_poi_artifact_source_config(),
            rpc_url: Url::parse("http://127.0.0.1:1")
                .expect("POI RPC URL")
                .into(),
            wallet_read_fallback: PoiProxyFallback::Disabled,
        },
        None,
    )
}

fn test_public_data_plane_with_poi_service(db: &Arc<DbStore>) -> ChainPublicDataPlane {
    ChainPublicDataPlane::new(Arc::clone(db), Arc::new(AtomicU64::new(0))).with_poi_cache_service(
        Arc::new(
            crate::poi_cache::PoiCacheService::new(
                Arc::clone(db),
                test_poi_artifact_source_config(),
                None,
            )
            .expect("initialize POI cache generation")
            .with_poi_rpc_url(Url::parse("http://127.0.0.1:1").expect("POI RPC URL")),
        ),
    )
}

async fn wait_for_readiness(
    readiness_rx: &mut watch::Receiver<WalletObservation>,
    expected: WalletReadiness,
) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while readiness_rx.borrow().readiness() != &expected {
            readiness_rx
                .changed()
                .await
                .expect("wallet readiness sender remains active");
        }
    })
    .await
    .expect("wallet readiness transition");
}

#[tokio::test]
async fn committed_corpus_revision_publishes_syncing_before_blocked_refresh_commit() {
    let root_dir = temp_db_root("wallet-corpus-revision-readiness");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cfg = wallet_config();
    let list_key = default_active_poi_list_keys()[0];
    let mut wallet_utxo = test_wallet_utxo(100, 7);
    let blinded_commitment = wallet_utxo.utxo.poi.blinded_commitment;
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    wallet_utxo.utxo.poi.refreshed_at = Some(now_epoch_secs());

    let public_data_plane = test_public_data_plane_with_poi_service(&db);
    let corpus = public_data_plane
        .ensure_poi_corpus(PublicPoiCorpusKey::wallet_default(cfg.chain.chain_id))
        .await
        .expect("POI corpus");
    let local_caches = corpus.local_caches();
    let mut initial_cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        cfg.chain.chain_id,
        DEFAULT_TXID_VERSION,
        list_key,
    ));
    initial_cache
        .apply_poi_leaves(0, &[U256::from(1)])
        .expect("seed ready POI corpus");
    initial_cache.accept_current_roots();
    local_caches.write().await.insert(list_key, initial_cache);

    let (live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),
            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_artifact_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: backfill_tx.clone(),
            public_data_plane: public_data_plane.clone(),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        cfg,
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        vec![wallet_utxo],
        100,
    )
    .await
    .expect("spawn wallet worker");
    assert_eq!(
        send_target_token(&backfill_tx, 100, handle.mint_sync_token(0)).await,
        WalletBackfillFinishResult::Ready { committed_to: 100 }
    );
    let mut readiness_rx = handle.subscribe_observation();
    wait_for_readiness(&mut readiness_rx, WalletReadiness::Ready).await;

    let held = Arc::clone(&handle.authority_lock).lock_owned().await;
    let mut advanced_cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        1,
        DEFAULT_TXID_VERSION,
        list_key,
    ));
    advanced_cache
        .apply_verified_artifact_events(&[SnapshotEvent {
            event_index: 0,
            blinded_commitment: *blinded_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply valid POI event");
    advanced_cache.accept_current_roots();
    let revision_fence = local_caches.revision_write_fence().await;
    local_caches.write().await.insert(list_key, advanced_cache);
    local_caches.publish_committed_revision(true);

    wait_for_readiness(&mut readiness_rx, WalletReadiness::Syncing).await;
    assert_eq!(
        handle
            .current_snapshot()
            .expect("blocked wallet view")
            .utxos[0]
            .utxo
            .poi
            .statuses
            .get(&list_key),
        Some(&PoiStatus::Missing),
        "the old status remains published while durable refresh is blocked"
    );

    drop(revision_fence);
    drop(held);
    wait_for_readiness(&mut readiness_rx, WalletReadiness::Ready).await;
    assert_eq!(
        handle
            .current_snapshot()
            .expect("refreshed wallet view")
            .utxos[0]
            .utxo
            .poi
            .statuses
            .get(&list_key),
        Some(&PoiStatus::Valid)
    );

    cancel.cancel();
    drop(live_tx);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn live_scan_publishes_syncing_before_blocked_commit() {
    let root_dir = temp_db_root("wallet-live-readiness-before-commit");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let (live_tx, live_rx) = broadcast::channel(8);
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
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");
    assert_eq!(
        send_target_token(&backfill_tx, 100, handle.mint_sync_token(0)).await,
        WalletBackfillFinishResult::Ready { committed_to: 100 }
    );
    let mut readiness_rx = handle.subscribe_observation();
    wait_for_readiness(&mut readiness_rx, WalletReadiness::Ready).await;

    let held = Arc::clone(&handle.authority_lock).lock_owned().await;
    live_tx
        .send(logs_payload(101, 101))
        .expect("live receiver remains active");

    wait_for_readiness(&mut readiness_rx, WalletReadiness::Syncing).await;
    assert_eq!(handle.last_scanned(), Some(100));

    drop(held);
    wait_for_readiness(&mut readiness_rx, WalletReadiness::Ready).await;
    assert_eq!(handle.last_scanned(), Some(101));

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn cancellation_interrupts_actor_authority_acquisition() {
    let root_dir = temp_db_root("wallet-cancel-authority-wait");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let (live_tx, live_rx) = broadcast::channel(8);
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
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");
    assert_eq!(
        send_target_token(&backfill_tx, 100, handle.mint_sync_token(0)).await,
        WalletBackfillFinishResult::Ready { committed_to: 100 }
    );
    let mut readiness_rx = handle.subscribe_observation();
    wait_for_readiness(&mut readiness_rx, WalletReadiness::Ready).await;

    let held = Arc::clone(&handle.authority_lock).lock_owned().await;
    live_tx
        .send(logs_payload(101, 101))
        .expect("live receiver remains active");
    wait_for_readiness(&mut readiness_rx, WalletReadiness::Syncing).await;

    cancel.cancel();
    tokio::time::timeout(
        Duration::from_secs(1),
        wait_for_readiness(&mut readiness_rx, WalletReadiness::Shutdown),
    )
    .await
    .expect("worker cancellation bypassed authority contention");
    drop(held);

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

fn test_wallet_poi_runtime() -> WalletPoiRuntime {
    WalletPoiRuntime::from_policy(
        &GlobalPoiPolicy::PoiProxy {
            rpc_url: Url::parse("http://127.0.0.1:1")
                .expect("POI RPC URL")
                .into(),
        },
        None,
    )
}

const fn test_public_scan_read_scope() -> PublicScanReadScope {
    PublicScanReadScope::new(PublicDataPlaneEpoch::new(0))
}

#[tokio::test]
async fn wallet_worker_restores_submitted_external_ppoi_workflow_status() {
    let root_dir = temp_db_root("wallet-ppoi-workflow-restore");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cfg = wallet_config();
    let list_key = default_active_poi_list_keys()[0];
    let output = test_wallet_utxo_with_random(110, 17, [0x31; 16]);
    let mut context =
        observed_external_pending_output_context(&cfg, &output, list_key, &source(110, 0xd0));
    context.terminal_error = None;
    context.pre_transaction_pois_per_txid_leaf_per_list = current_pending_proof_map(list_key);
    let recovery =
        output_poi_recovery_for_pending_context(&context, OutputPoiRecoveryStatus::Submitted);
    db.put_pending_output_poi_context(&context)
        .expect("seed pending context");
    db.put_output_poi_recovery(&recovery)
        .expect("seed recovery");

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
            backfill_sender: backfill_tx,
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        cfg,
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");

    let status = *handle.observation().ppoi_workflow_status();
    assert_eq!(status.awaiting_submission, 0);
    assert_eq!(status.awaiting_validation, 1);
    assert_eq!(status.needs_attention, 0);
    assert_eq!(status.validation_revision, 0);

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn current_candidate_report_moves_submitted_unshields_and_attention_out_of_recovery() {
    let root_dir = temp_db_root("wallet-candidate-report-refinement");
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let cfg = wallet_config();
    // A spend-only wallet: both outstanding units are handed-off unshields.
    for (position, byte) in [(7, 0xd4), (8, 0xd5)] {
        let spent = test_wallet_utxo(105, position);
        let candidate = crate::SenderTransactionCandidate::new(
            cfg.chain.chain_id,
            cfg.cache_key.clone(),
            source(110, byte),
            vec![crate::SenderTransactionCandidateSpend {
                tree: spent.utxo.tree,
                position: spent.utxo.position,
                commitment: spent.utxo.poi.commitment,
            }],
            Vec::new(),
        )
        .expect("sender candidate")
        .with_unshield(Some(crate::SenderTransactionCandidateUnshield {
            railgun_txids: vec![FixedBytes::from([byte; 32])],
            outputs_handed_off: true,
        }))
        .expect("sender candidate with unshield work");
        db.put_opaque_wallet_private_row(
            &candidate.namespace(),
            WalletPrivateRecordKind::SenderTransactionCandidate,
            &OpaqueWalletPrivateRow {
                row_id: candidate.row_identity(),
                payload: candidate.encode().expect("encode sender candidate"),
            },
        )
        .expect("seed sender candidate");
    }
    let report = SenderCandidateRecoveryReport {
        unshield_awaiting_validation: 1,
        needs_attention: 1,
        ..SenderCandidateRecoveryReport::default()
    };
    let active_list_keys = default_active_poi_list_keys();
    let refined = current_ppoi_workflow_status_for_candidate_report(
        &db,
        &cfg,
        &active_list_keys,
        WalletPpoiWorkflowStatus::default(),
        &report,
    )
    .expect("derive refined status");
    assert_eq!(
        refined,
        WalletPpoiWorkflowStatus {
            awaiting_recovery: 1,
            awaiting_validation: 1,
            recovery_needs_attention: 1,
            ..WalletPpoiWorkflowStatus::default()
        }
    );
    assert_eq!(refined.outstanding_count(), 2);
    // A later pass without durable mutations refines the same base, not the published status.
    assert_eq!(
        current_ppoi_workflow_status_for_candidate_report(
            &db,
            &cfg,
            &active_list_keys,
            refined,
            &report,
        ),
        Some(refined)
    );
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");

    let clamped = ppoi_workflow_status_with_candidate_report(
        WalletPpoiWorkflowStatus {
            awaiting_recovery: 1,
            ..WalletPpoiWorkflowStatus::default()
        },
        &SenderCandidateRecoveryReport {
            unshield_awaiting_validation: 3,
            ..SenderCandidateRecoveryReport::default()
        },
    );
    assert_eq!(
        (clamped.awaiting_recovery, clamped.awaiting_validation),
        (0, 1)
    );
}

#[tokio::test]
async fn maintenance_completion_discards_waiting_details_when_replayed_pending_subject_changes() {
    for replace_subject in [false, true] {
        let root_dir = temp_db_root("wallet-maintenance-subject-publication");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
        let mut cfg = wallet_config();
        cfg.cache_store = Some(cache_store.clone());
        let list_key = default_active_poi_list_keys()[0];
        let output = test_wallet_utxo_with_random(110, 17, [0x31; 16]);
        let mut context =
            observed_external_pending_output_context(&cfg, &output, list_key, &source(110, 0xd0));
        context.terminal_error = None;
        context.submitted_poi_list_keys.clear();
        let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../../core/tests/fixtures/ppoi_3x3_previous.json"
        ))
        .expect("actual previous-key proof");
        let proof: broadcaster_core::transact::PreTxPoi =
            serde_json::from_value(fixture["pre_tx_poi"].clone()).expect("decode old proof");
        context.pre_transaction_pois_per_txid_leaf_per_list = BTreeMap::from([(
            list_key,
            BTreeMap::from([(FixedBytes::from([0x41; 32]), proof)]),
        )]);
        let recovery =
            output_poi_recovery_for_pending_context(&context, OutputPoiRecoveryStatus::Recoverable);
        db.put_pending_output_poi_context(&context)
            .expect("seed pending subject");
        db.put_output_poi_recovery(&recovery)
            .expect("seed replay recovery");
        if replace_subject {
            let mut replacement = context.clone();
            replacement.source_operation_id = Some("replacement-after-replay-snapshot".into());
            *cache_store
                .replay_pending_replacement
                .lock()
                .expect("arm replay race") = Some(replacement);
        }
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                http_client: None,
                indexed_artifact_source: None,
                poi_runtime: test_artifact_poi_runtime(),
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane_with_poi_service(&db),
                poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
            },
            cfg,
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            Vec::new(),
            100,
        )
        .await
        .expect("spawn worker");
        assert_eq!(
            handle
                .observation()
                .ppoi_workflow_status()
                .awaiting_recovery,
            1
        );
        assert_eq!(
            send_target_token(&backfill_tx, 100, handle.mint_sync_token(0)).await,
            WalletBackfillFinishResult::Ready { committed_to: 100 }
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            while cache_store.recovery_reads.load(Ordering::SeqCst) < 2
                || *handle.poi_refreshing_rx.borrow()
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            // Drain a subsequent actor request so the completion branch has published.
            handle
                .clear_all_local_pending_spent()
                .await
                .expect("actor completion barrier");
        })
        .await
        .expect("maintenance completion");
        let status = *handle.observation().ppoi_workflow_status();
        assert_eq!(status.awaiting_recovery, 1);
        assert_eq!(
            status.awaiting_public_txid_data,
            u64::from(!replace_subject),
            "only the current replay subject may publish its wait detail"
        );
        assert_eq!(status.retrying_recovery, 0);
        assert!(
            cache_store
                .replay_pending_replacement
                .lock()
                .expect("replay race consumed")
                .is_none()
        );
        cancel.cancel();
        drop(handle);
        drop(cache_store);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct FailingCacheStoreState {
    store_calls: usize,
    meta_calls: usize,
    last_chain_id: Option<u64>,
    fail_next_store: bool,
    fail_next_meta: bool,
    fail_next_actor_state: bool,
    fail_next_actor_state_put: bool,
    fail_next_reset_replay_retirement: bool,
}

struct FailingCacheStore {
    db: Arc<DbStore>,
    state: Mutex<FailingCacheStoreState>,
    actor_state: Mutex<Option<WalletSyncActorStateRecord>>,
    recovery_reads: AtomicU64,
    replay_pending_replacement: Mutex<Option<PendingOutputPoiContextRecord>>,
}

impl FailingCacheStore {
    fn new(db: Arc<DbStore>) -> Self {
        Self {
            db,
            state: Mutex::default(),
            actor_state: Mutex::default(),
            recovery_reads: AtomicU64::new(0),
            replay_pending_replacement: Mutex::default(),
        }
    }

    fn fail_next_store(&self) {
        self.state.lock().expect("cache state").fail_next_store = true;
    }

    fn fail_next_meta(&self) {
        self.state.lock().expect("cache state").fail_next_meta = true;
    }

    fn fail_next_actor_state(&self) {
        self.state
            .lock()
            .expect("cache state")
            .fail_next_actor_state = true;
    }

    fn fail_next_actor_state_put(&self) {
        self.state
            .lock()
            .expect("cache state")
            .fail_next_actor_state_put = true;
    }

    fn fail_next_reset_replay_retirement(&self) {
        self.state
            .lock()
            .expect("cache state")
            .fail_next_reset_replay_retirement = true;
    }

    fn seed_actor_state(&self, state: WalletSyncActorStateRecord) {
        *self.actor_state.lock().expect("actor state") = Some(state);
    }

    fn actor_state(&self) -> Option<WalletSyncActorStateRecord> {
        self.actor_state.lock().expect("actor state").clone()
    }

    fn state(&self) -> FailingCacheStoreState {
        *self.state.lock().expect("cache state")
    }
}

impl WalletCacheStore for FailingCacheStore {
    fn commit_wallet_private_state(
        &self,
        commit: WalletPrivateCommit<'_>,
    ) -> Result<(), WalletCacheError> {
        self.state.lock().expect("cache state").last_chain_id = Some(commit.chain_id());
        if matches!(commit.utxo_mutation(), WalletUtxoMutation::Replace(_)) {
            let mut state = self.state.lock().expect("cache state");
            state.store_calls += 1;
            if state.fail_next_store {
                state.fail_next_store = false;
                return Err(WalletCacheError::Crypto);
            }
        } else {
            let mut state = self.state.lock().expect("cache state");
            state.meta_calls += 1;
            if state.fail_next_meta {
                state.fail_next_meta = false;
                return Err(WalletCacheError::Crypto);
            }
        }
        let actor_state = commit.sync_actor_state().cloned();
        <DbStore as WalletCacheStore>::commit_wallet_private_state(self.db.as_ref(), commit)?;
        if let Some(state) = actor_state {
            *self.actor_state.lock().expect("actor state") = Some(state);
        }
        Ok(())
    }

    fn load_wallet_utxos(
        &self,
        _wallet_id: &WalletCacheKey,
    ) -> Result<Vec<WalletUtxo>, WalletCacheError> {
        Ok(Vec::new())
    }

    fn get_wallet_meta(
        &self,
        _wallet_id: &WalletCacheKey,
    ) -> Result<Option<WalletMeta>, WalletCacheError> {
        Ok(None)
    }

    fn get_wallet_sync_actor_state(
        &self,
        _chain_id: u64,
        _wallet_id: &WalletCacheKey,
    ) -> Result<Option<WalletSyncActorStateRecord>, WalletCacheError> {
        let mut state = self.state.lock().expect("cache state");
        if state.fail_next_actor_state {
            state.fail_next_actor_state = false;
            return Err(WalletCacheError::Crypto);
        }
        Ok(self.actor_state.lock().expect("actor state").clone())
    }

    fn put_wallet_sync_actor_state(
        &self,
        commit: WalletSyncActorStateCommit<'_>,
    ) -> Result<(), WalletCacheError> {
        let mut store_state = self.state.lock().expect("cache state");
        if commit.state().pending_reset.is_none() && store_state.fail_next_reset_replay_retirement {
            store_state.fail_next_reset_replay_retirement = false;
            return Err(WalletCacheError::Crypto);
        }
        if store_state.fail_next_actor_state_put {
            store_state.fail_next_actor_state_put = false;
            return Err(WalletCacheError::Crypto);
        }
        drop(store_state);
        self.db.put_wallet_sync_actor_state(commit.state())?;
        *self.actor_state.lock().expect("actor state") = Some(commit.state().clone());
        Ok(())
    }

    fn get_pending_output_poi_context(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
        output_commitment: &FixedBytes<32>,
    ) -> Result<Option<PendingOutputPoiContextRecord>, WalletCacheError> {
        <DbStore as WalletCacheStore>::get_pending_output_poi_context(
            self.db.as_ref(),
            chain_id,
            wallet_id,
            output_commitment,
        )
    }

    fn list_pending_output_poi_contexts(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
    ) -> Result<Vec<PendingOutputPoiContextRecord>, WalletCacheError> {
        <DbStore as WalletCacheStore>::list_pending_output_poi_contexts(
            self.db.as_ref(),
            chain_id,
            wallet_id,
        )
    }

    fn get_output_poi_recovery(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
        output_commitment: &FixedBytes<32>,
    ) -> Result<Option<OutputPoiRecoveryRecord>, WalletCacheError> {
        // Replay selects the source from its first recovery read, then captures the
        // predecessor on its second. Replace the durable subject after that snapshot.
        if self.recovery_reads.fetch_add(1, Ordering::SeqCst) == 1
            && let Some(replacement) = self
                .replay_pending_replacement
                .lock()
                .expect("replay replacement")
                .take()
        {
            self.db.put_pending_output_poi_context(&replacement)?;
        }
        <DbStore as WalletCacheStore>::get_output_poi_recovery(
            self.db.as_ref(),
            chain_id,
            wallet_id,
            output_commitment,
        )
    }

    fn list_output_poi_recoveries(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
    ) -> Result<Vec<OutputPoiRecoveryRecord>, WalletCacheError> {
        <DbStore as WalletCacheStore>::list_output_poi_recoveries(
            self.db.as_ref(),
            chain_id,
            wallet_id,
        )
    }

    fn get_sender_transaction_candidate(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
        outer_transaction_hash: &FixedBytes<32>,
    ) -> Result<Option<crate::SenderTransactionCandidate>, WalletCacheError> {
        <DbStore as WalletCacheStore>::get_sender_transaction_candidate(
            self.db.as_ref(),
            chain_id,
            wallet_id,
            outer_transaction_hash,
        )
    }

    fn list_sender_transaction_candidates(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
    ) -> Result<Vec<crate::SenderTransactionCandidate>, WalletCacheError> {
        <DbStore as WalletCacheStore>::list_sender_transaction_candidates(
            self.db.as_ref(),
            chain_id,
            wallet_id,
        )
    }
}

struct BlockingPoiStatusReader {
    started: tokio::sync::Mutex<Option<oneshot::Sender<()>>>,
    release: tokio::sync::Mutex<Option<oneshot::Receiver<()>>>,
    status: PoiStatus,
}

impl BlockingPoiStatusReader {
    fn new(started: oneshot::Sender<()>, release: oneshot::Receiver<()>) -> Self {
        Self {
            started: tokio::sync::Mutex::new(Some(started)),
            release: tokio::sync::Mutex::new(Some(release)),
            status: PoiStatus::Valid,
        }
    }
}

#[async_trait]
impl PoiStatusReader for BlockingPoiStatusReader {
    async fn pois_per_list(
        &self,
        _txid_version: &str,
        _chain_type: u8,
        _chain_id: u64,
        list_keys: &[FixedBytes<32>],
        blinded_commitment_datas: &[BlindedCommitmentData],
    ) -> Result<BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PoiStatus>>, PoiError> {
        if let Some(started) = self.started.lock().await.take() {
            let _ = started.send(());
        }
        if let Some(release) = self.release.lock().await.take() {
            let _ = release.await;
        }
        Ok(blinded_commitment_datas
            .iter()
            .map(|data| {
                (
                    data.blinded_commitment,
                    list_keys
                        .iter()
                        .copied()
                        .map(|list_key| (list_key, self.status))
                        .collect(),
                )
            })
            .collect())
    }
}

struct UnavailablePoiStatusReader;

#[async_trait]
impl PoiStatusReader for UnavailablePoiStatusReader {
    async fn pois_per_list(
        &self,
        _txid_version: &str,
        _chain_type: u8,
        _chain_id: u64,
        _list_keys: &[FixedBytes<32>],
        _blinded_commitment_datas: &[BlindedCommitmentData],
    ) -> Result<BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PoiStatus>>, PoiError> {
        Err(PoiError::MerkleRootsRejected)
    }
}

struct FixedPoiStatusReader(PoiStatus);

#[async_trait]
impl PoiStatusReader for FixedPoiStatusReader {
    async fn pois_per_list(
        &self,
        _txid_version: &str,
        _chain_type: u8,
        _chain_id: u64,
        list_keys: &[FixedBytes<32>],
        blinded_commitment_datas: &[BlindedCommitmentData],
    ) -> Result<BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PoiStatus>>, PoiError> {
        Ok(blinded_commitment_datas
            .iter()
            .map(|data| {
                (
                    data.blinded_commitment,
                    list_keys
                        .iter()
                        .copied()
                        .map(|list_key| (list_key, self.0))
                        .collect(),
                )
            })
            .collect())
    }
}

async fn send_apply(
    handle: &WalletHandle,
    sender: &mpsc::Sender<BackfillEvent>,
    apply: WalletScanApply,
    reset_generation: u64,
) -> WalletBackfillApplyResult {
    send_apply_token(sender, apply, handle.mint_sync_token(reset_generation)).await
}

async fn send_apply_token(
    sender: &mpsc::Sender<BackfillEvent>,
    apply: WalletScanApply,
    token: WalletSyncToken,
) -> WalletBackfillApplyResult {
    match send_start_token(sender, apply.to_block, token).await {
        WalletBackfillStartResult::Accepted { grant, .. } => {
            let driver = grant.activate();
            let result = driver.apply("test", apply).await;
            driver.retire("test").await;
            result
        }
        WalletBackfillStartResult::Rejected {
            committed_to,
            reason,
        } => WalletBackfillApplyResult::Rejected {
            committed_to,
            reason,
        },
    }
}

async fn send_target(
    handle: &WalletHandle,
    sender: &mpsc::Sender<BackfillEvent>,
    target_block: u64,
    reset_generation: u64,
) -> WalletBackfillFinishResult {
    send_target_token(
        sender,
        target_block,
        handle.mint_sync_token(reset_generation),
    )
    .await
}

async fn send_target_token(
    sender: &mpsc::Sender<BackfillEvent>,
    target_block: u64,
    token: WalletSyncToken,
) -> WalletBackfillFinishResult {
    match send_start_token(sender, target_block, token).await {
        WalletBackfillStartResult::Accepted { grant, .. } => {
            let driver = grant.activate();
            let result = driver.finish("test", target_block).await;
            if !matches!(result, WalletBackfillFinishResult::Ready { .. }) {
                driver.retire("test").await;
            }
            result
        }
        WalletBackfillStartResult::Rejected {
            committed_to,
            reason,
        } => WalletBackfillFinishResult::Rejected {
            committed_to,
            reason,
        },
    }
}

async fn send_start_token(
    sender: &mpsc::Sender<BackfillEvent>,
    target_block: u64,
    token: WalletSyncToken,
) -> WalletBackfillStartResult {
    let (response, result_rx) = oneshot::channel();
    sender
        .send(BackfillEvent::Start {
            target_block,
            token,
            response,
        })
        .await
        .expect("send target");
    result_rx.await.expect("target response")
}

fn assert_start_accepted(
    result: WalletBackfillStartResult,
    token: WalletSyncToken,
    committed_to: u64,
    target_block: u64,
) -> WalletBackfillDriver {
    match result {
        WalletBackfillStartResult::Accepted {
            committed_to: actual_committed_to,
            target_block: actual_target_block,
            grant,
        } => {
            assert_eq!(actual_committed_to, committed_to);
            assert_eq!(actual_target_block, target_block);
            assert_eq!(grant.token(), token);
            grant.activate()
        }
        other @ WalletBackfillStartResult::Rejected { .. } => {
            panic!("expected accepted target, got {other:?}")
        }
    }
}

fn accepted_test_backfill_owner(
    state: &mut WalletActorState,
    token: WalletSyncToken,
    target_block: u64,
) -> (
    WalletBackfillGrant,
    oneshot::Receiver<WalletBackfillOwnerSignal>,
) {
    assert!(state.test_transition(|mut state| state.accept_target(token, target_block)));
    let (sender, _receiver) = mpsc::channel(1);
    let (liveness, receiver) = oneshot::channel();
    (
        WalletBackfillGrant::for_actor_accepted_job(token, sender, liveness),
        receiver,
    )
}

fn test_actor_state(last_scanned: u64) -> WalletActorState {
    test_actor_state_with_observation(last_scanned).0
}

fn test_actor_state_with_observation(
    last_scanned: u64,
) -> (WalletActorState, watch::Receiver<WalletObservation>) {
    WalletActorState::new(
        1,
        1,
        0,
        last_scanned,
        0,
        None,
        false,
        WalletViewState::Current(WalletCurrentSnapshot::new(
            last_scanned,
            0,
            0,
            Arc::<[WalletUtxo]>::from(Vec::new()),
            Arc::new(WalletPendingOverlay::default()),
        )),
    )
}

fn test_actor_state_for_handle(
    handle: &WalletHandle,
    last_scanned: u64,
) -> (WalletActorState, watch::Receiver<WalletObservation>) {
    let mut state = test_actor_state(last_scanned);
    state.set_observation_publisher_for_test(
        handle
            .observation
            .upgrade()
            .expect("test handle owns observation publisher"),
    );
    (state, handle.subscribe_observation())
}

async fn unacknowledged_test_backfill_disposition(
    token: WalletSyncToken,
    liveness: oneshot::Receiver<WalletBackfillOwnerSignal>,
) -> WalletBackfillOwnerDisposition {
    let (actual_token, signal) = accepted_backfill_owner_dropped(token, liveness).await;
    assert_eq!(actual_token, token);
    assert!(signal.acknowledgement.is_none());
    signal.disposition
}

#[tokio::test]
async fn dropped_start_response_receiver_retires_accepted_owner() {
    let mut state = test_actor_state(100);
    let token = WalletSyncToken::for_test(1, 1, 0, 1);
    let (grant, liveness) = accepted_test_backfill_owner(&mut state, token, 200);
    let (response, result_rx) = oneshot::channel();
    drop(result_rx);

    let result = WalletBackfillStartResult::Accepted {
        committed_to: 100,
        target_block: 200,
        grant,
    };
    drop(
        response
            .send(result)
            .expect_err("start receiver was dropped"),
    );

    assert_eq!(
        unacknowledged_test_backfill_disposition(token, liveness).await,
        WalletBackfillOwnerDisposition::BenignRetirement
    );
    assert!(
        state.test_transition(|mut state| state.apply_backfill_owner_disposition(
            token,
            WalletBackfillOwnerDisposition::BenignRetirement,
        ))
    );
    assert_eq!(state.test_active_job_count(), 0);
}

#[tokio::test]
async fn dropped_delivered_start_result_retires_accepted_owner() {
    let mut state = test_actor_state(100);
    let token = WalletSyncToken::for_test(1, 1, 0, 1);
    let (grant, liveness) = accepted_test_backfill_owner(&mut state, token, 200);
    let (response, result_rx) = oneshot::channel();
    response
        .send(WalletBackfillStartResult::Accepted {
            committed_to: 100,
            target_block: 200,
            grant,
        })
        .expect("deliver accepted start result");

    drop(result_rx.await.expect("receive accepted start result"));

    assert_eq!(
        unacknowledged_test_backfill_disposition(token, liveness).await,
        WalletBackfillOwnerDisposition::BenignRetirement
    );
    assert!(
        state.test_transition(|mut state| state.apply_backfill_owner_disposition(
            token,
            WalletBackfillOwnerDisposition::BenignRetirement,
        ))
    );
    assert_eq!(state.test_active_job_count(), 0);
}

#[tokio::test]
async fn dropping_unactivated_backfill_grant_restores_completed_readiness_without_fault() {
    let mut state = test_actor_state(100);
    let completed = WalletSyncToken::for_test(1, 1, 0, 1);
    assert!(state.test_transition(|mut state| state.accept_target(completed, 100)));
    assert!(state.test_transition(|mut state| state.complete_backfill_job(completed)));
    assert_eq!(state.test_readiness(), WalletReadiness::Ready);

    let newer = WalletSyncToken::for_test(1, 1, 0, 2);
    let (grant, liveness) = accepted_test_backfill_owner(&mut state, newer, 200);
    assert_eq!(state.test_readiness(), WalletReadiness::Syncing);
    drop(grant);

    assert_eq!(
        unacknowledged_test_backfill_disposition(newer, liveness).await,
        WalletBackfillOwnerDisposition::BenignRetirement
    );
    assert!(
        state.test_transition(|mut state| state.apply_backfill_owner_disposition(
            newer,
            WalletBackfillOwnerDisposition::BenignRetirement,
        ))
    );
    assert_eq!(state.completed_target_block(), Some(100));
    assert_eq!(state.test_job_failure_count(), 0);
    assert_eq!(state.test_readiness(), WalletReadiness::Ready);
}

#[tokio::test]
async fn sync_target_lease_bridges_partial_source_and_successor_admission() {
    let mut state = test_actor_state(100);
    let completed = WalletSyncToken::for_test(1, 1, 0, 1);
    assert!(state.test_transition(|mut state| state.accept_target(completed, 100)));
    assert!(state.test_transition(|mut state| state.complete_backfill_job(completed)));
    assert_eq!(state.test_readiness(), WalletReadiness::Ready);

    let target_token = WalletSyncToken::for_test(1, 1, 0, 2);
    assert!(state.test_transition(|mut state| state.accept_sync_target(target_token, 200)));
    let (sender, _receiver) = mpsc::channel(1);
    let (target_liveness, target_dropped) = oneshot::channel();
    let target_lease =
        WalletSyncTargetLease::for_actor_accepted_job(target_token, sender, target_liveness);
    assert_eq!(target_lease.token(), target_token);

    let partial = WalletSyncToken::for_test(1, 1, 0, 3);
    assert!(state.test_transition(|mut state| state.accept_target(partial, 150)));
    state.test_transition(|mut state| state.update_cursor(150));
    assert!(state.test_transition(|mut state| state.retire_job(partial)));
    let indexed = WalletSyncToken::for_test(1, 1, 0, 4);
    assert!(state.test_transition(|mut state| state.accept_indexed_catch_up(indexed)));
    assert!(state.test_transition(|mut state| state.retire_job(indexed)));
    assert_eq!(state.test_readiness(), WalletReadiness::Syncing);

    let successor = WalletSyncToken::for_test(1, 1, 0, 5);
    assert!(state.test_transition(|mut state| state.accept_target(successor, 200)));
    drop(target_lease);
    assert_eq!(
        unacknowledged_test_backfill_disposition(target_token, target_dropped).await,
        WalletBackfillOwnerDisposition::BenignRetirement
    );
    assert!(
        state.test_transition(|mut state| state.apply_backfill_owner_disposition(
            target_token,
            WalletBackfillOwnerDisposition::BenignRetirement,
        ))
    );
    assert_eq!(state.test_readiness(), WalletReadiness::Syncing);

    state.test_transition(|mut state| state.update_cursor(200));
    assert!(state.test_transition(|mut state| state.complete_backfill_job(successor)));
    assert_eq!(state.test_readiness(), WalletReadiness::Ready);
}

#[test]
fn multiple_backfill_targets_recompute_from_job_records() {
    let mut state = test_actor_state(200);
    let first = WalletSyncToken::for_test(1, 1, 0, 1);
    let second = WalletSyncToken::for_test(1, 1, 0, 2);
    assert!(state.test_transition(|mut state| state.accept_target(first, 150)));
    assert!(state.test_transition(|mut state| state.accept_target(second, 200)));

    assert!(state.test_transition(|mut state| state.complete_backfill_job(first)));
    assert_eq!(state.completed_target_block(), Some(150));
    assert_eq!(state.test_readiness(), WalletReadiness::Syncing);
    assert!(state.test_transition(|mut state| state.retire_job(second)));
    assert_eq!(state.test_readiness(), WalletReadiness::Ready);
}

#[tokio::test]
async fn dropped_backfill_request_reports_active_driver_loss() {
    let mut state = test_actor_state(100);
    let completed = WalletSyncToken::for_test(1, 1, 0, 1);
    assert!(state.test_transition(|mut state| state.accept_target(completed, 100)));
    assert!(state.test_transition(|mut state| state.complete_backfill_job(completed)));
    assert_eq!(state.test_readiness(), WalletReadiness::Ready);

    let token = WalletSyncToken::for_test(1, 1, 0, 2);
    let (grant, liveness) = accepted_test_backfill_owner(&mut state, token, 200);
    assert_eq!(state.test_readiness(), WalletReadiness::Syncing);
    drop(BackfillRequest::add(
        "test",
        101,
        200,
        false,
        101,
        grant.activate(),
    ));

    assert_eq!(
        unacknowledged_test_backfill_disposition(token, liveness).await,
        WalletBackfillOwnerDisposition::DriverLost
    );
    assert!(state.test_transition(|mut state| {
        state.apply_backfill_owner_disposition(token, WalletBackfillOwnerDisposition::DriverLost)
    }));
    assert_eq!(state.test_active_job_count(), 0);
    assert_eq!(
        state.test_readiness(),
        WalletReadiness::Failed(WalletReadinessError::BackfillUnavailable)
    );
}

#[tokio::test]
async fn persistence_retry_completion_ignores_subsequent_driver_drop() {
    let mut state = test_actor_state(100);
    let token = WalletSyncToken::for_test(1, 1, 0, 1);
    let (grant, liveness) = accepted_test_backfill_owner(&mut state, token, 100);
    let driver = grant.activate();

    assert!(state.test_transition(|mut state| { state.backfill_completion_persist_failed(token) }));

    assert_eq!(state.test_active_backfill_target_for(token), Some(100));
    assert!(
        state.test_transition(|mut state| { state.durable_backfill_completion_commit_ok(token) })
    );
    assert!(state.test_transition(|mut state| state.complete_backfill_job(token)));
    assert_eq!(state.test_readiness(), WalletReadiness::Ready);
    drop(driver);
    assert_eq!(
        unacknowledged_test_backfill_disposition(token, liveness).await,
        WalletBackfillOwnerDisposition::DriverLost
    );
    assert!(!state.test_transition(|mut state| {
        state.apply_backfill_owner_disposition(token, WalletBackfillOwnerDisposition::DriverLost)
    }));
    assert_eq!(state.test_readiness(), WalletReadiness::Ready);
}

#[tokio::test]
async fn dropped_indexed_owner_clears_exact_job_status_and_readiness() {
    let mut state = test_actor_state(100);
    let completed = WalletSyncToken::for_test(1, 1, 0, 1);
    assert!(state.test_transition(|mut state| state.accept_target(completed, 100)));
    assert!(state.test_transition(|mut state| state.complete_backfill_job(completed)));
    let token = WalletSyncToken::for_test(1, 1, 0, 2);
    assert!(state.test_transition(|mut state| state.accept_indexed_catch_up(token)));
    let status = WalletIndexedCatchUpStatus {
        source: WalletIndexedCatchUpSource::IndexedArtifacts,
        from_block: 101,
        target_block: 200,
    };
    assert!(state.test_transition(|mut state| state.publish_indexed_catch_up(token, status)));
    assert_eq!(state.test_indexed_status(token), Some(&status));
    let (liveness, receiver) = oneshot::channel();
    let lease = WalletIndexedCatchUpLease::for_actor_accepted_job(token, liveness);
    drop(lease);

    assert_eq!(
        accepted_indexed_job_owner_dropped(token, receiver).await,
        token
    );
    assert!(state.test_transition(|mut state| state.retire_job(token)));
    assert_eq!(state.test_readiness(), WalletReadiness::Ready);
}

const fn test_reset_token(intent_id: u64) -> WalletResetToken {
    WalletResetToken::for_test(1, 1, intent_id)
}

async fn send_reset(
    sender: &mpsc::Sender<BackfillEvent>,
    intent_id: u64,
    from_block: u64,
) -> WalletBackfillResetResult {
    let (response, result_rx) = oneshot::channel();
    sender
        .send(BackfillEvent::Reset {
            token: test_reset_token(intent_id),
            from_block,
            replay_plan: WalletResetReplayPlan::new(0, 0, true),
            response,
        })
        .await
        .expect("send reset");
    result_rx.await.expect("reset response")
}

fn logs_apply(from_block: u64, to_block: u64) -> WalletScanApply {
    WalletScanApply::rows_from_log_batch(
        from_block,
        to_block,
        &logs_payload(from_block, to_block),
        PublicScanSource::Rpc,
    )
    .expect("normalize empty log payload")
}

fn logs_payload(from_block: u64, to_block: u64) -> Arc<LogBatch> {
    Arc::new(LogBatch {
        from_block,
        to_block,
        logs: Vec::new(),
        block_timestamps: HashMap::new(),
        to_block_hash: None,
        read_scope: test_public_scan_read_scope(),
    })
}

fn indexed_delta_batch(from_block: u64, to_block: u64, delta: WalletLogDelta) -> WalletScanApply {
    WalletScanApply::indexed_delta_for_test(
        from_block,
        to_block,
        delta,
        test_public_scan_read_scope(),
        WalletIndexedCatchUpSource::IndexedArtifacts,
    )
}

fn pending_overlay_rows_from_delta(
    from_block: u64,
    to_block: u64,
    delta: WalletLogDelta,
) -> WalletScanRows {
    indexed_delta_batch(from_block, to_block, delta).rows
}

fn empty_delta() -> WalletLogDelta {
    WalletLogDelta {
        utxos: Vec::new(),
        nullifiers: Vec::new(),
        commitment_observations: Vec::new(),
        sender_scan_outputs: Vec::new(),
    }
}

fn sender_scan_output(sender: &ViewingKeyData, source: UtxoSource) -> SenderScanOutput {
    let receiver =
        ViewingKeyData::from_spending_public_key([9; 32], [U256::from(13), U256::from(14)]);
    let note = Note::new_change(
        receiver.master_public_key,
        Address::ZERO,
        U256::from(30),
        [0x31; 16],
    );
    let ciphertext: CommitmentCiphertext = NoteCiphertext::try_from_note(
        &note,
        &sender.address_data(),
        &receiver.address_data(),
        &sender.viewing_private_key,
    )
    .expect("encrypt sender output")
    .into();
    SenderScanOutput {
        tree: 3,
        position: 10,
        commitment: note.commitment(),
        ciphertext,
        source,
    }
}

#[tokio::test]
async fn wallet_worker_applies_live_batch_queued_before_done() {
    let root_dir = temp_db_root("wallet-worker-live-before-done");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let (live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let public_data_plane = test_public_data_plane(&db);
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
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");
    live_tx
        .send(Arc::new(LogBatch {
            from_block: 101,
            to_block: 101,
            logs: Vec::new(),
            block_timestamps: HashMap::new(),
            to_block_hash: None,
            read_scope: test_public_scan_read_scope(),
        }))
        .expect("live receiver");
    tokio::task::yield_now().await;
    assert_eq!(handle.last_scanned(), Some(100));

    let initial_token = handle.mint_sync_token(0);
    assert_eq!(
        send_target_token(&backfill_tx, 100, initial_token).await,
        WalletBackfillFinishResult::Ready { committed_to: 100 }
    );
    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.last_scanned() != Some(101) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("queued live batch applied after done");

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_live_persist_failure_retains_exact_retry_until_cursor_recovers() {
    let root_dir = temp_db_root("wallet-worker-live-persist-failure");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    let mut cfg = wallet_config();
    cfg.cache_store = Some(cache_store.clone());
    let (live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, mut backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let public_data_plane = test_public_data_plane(&db);
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
        cfg,
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");

    let initial_token = handle.mint_sync_token(0);
    assert_eq!(
        send_target_token(&backfill_tx, 100, initial_token).await,
        WalletBackfillFinishResult::Ready { committed_to: 100 }
    );
    cache_store.fail_next_meta();
    live_tx
        .send(Arc::new(LogBatch {
            from_block: 101,
            to_block: 101,
            logs: Vec::new(),
            block_timestamps: HashMap::new(),
            to_block_hash: None,
            read_scope: test_public_scan_read_scope(),
        }))
        .expect("live receiver");

    tokio::time::timeout(Duration::from_secs(1), async {
        while !matches!(
            handle.readiness(),
            WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
        ) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("live persist failure observed");

    assert_eq!(handle.last_scanned(), Some(100));
    assert!(!handle.readiness().is_ready());
    assert_eq!(cache_store.state().meta_calls, 1);

    let retry = tokio::time::timeout(Duration::from_secs(1), backfill_request_rx.recv())
        .await
        .expect("live persistence retry requested")
        .expect("backfill request channel open");
    let BackfillRequest::Add {
        from_block,
        to_block,
        follow_safe_head,
        progress_start_block,
        driver,
        ..
    } = retry
    else {
        panic!("expected live persistence retry request");
    };
    assert_eq!((from_block, to_block), (101, 101));
    assert_eq!(progress_start_block, 101);
    assert!(!follow_safe_head);

    assert_eq!(
        send_target(&handle, &backfill_tx, 100, 0).await,
        WalletBackfillFinishResult::Ready { committed_to: 100 }
    );
    assert_eq!(
        handle.readiness(),
        WalletReadiness::Failed(WalletReadinessError::PersistenceFailed),
        "cursorless completion for unrelated work must not recover failed live progress"
    );

    assert_eq!(
        driver.apply("test", logs_apply(101, 101)).await,
        WalletBackfillApplyResult::Committed { committed_to: 101 }
    );
    assert_eq!(
        driver.finish("test", 101).await,
        WalletBackfillFinishResult::Ready { committed_to: 101 }
    );
    assert_eq!(handle.last_scanned(), Some(101));
    assert_eq!(handle.readiness(), WalletReadiness::Ready);

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_backfill_partial_indexed_tail_leaves_wallet_non_ready() {
    let root_dir = temp_db_root("wallet-partial-indexed-tail-non-ready");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let public_data_plane = test_public_data_plane(&db);
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
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        900,
    )
    .await
    .expect("spawn wallet worker");
    assert_eq!(
        send_target(&handle, &backfill_tx, 900, 0).await,
        WalletBackfillFinishResult::Ready { committed_to: 900 }
    );
    assert_eq!(handle.readiness(), WalletReadiness::Ready);
    let tail_token = handle.mint_sync_token(0);
    let tail_lease = assert_start_accepted(
        send_start_token(&backfill_tx, 1000, tail_token).await,
        tail_token,
        900,
        1000,
    );
    assert_eq!(
        tail_lease
            .apply("test", indexed_delta_batch(901, 950, empty_delta()))
            .await,
        WalletBackfillApplyResult::Committed { committed_to: 950 }
    );

    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.last_scanned() != Some(950) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("partial indexed tail applied");
    assert_eq!(handle.readiness(), WalletReadiness::Syncing);
    assert!(!handle.readiness().is_ready());
    assert_eq!(handle.readiness(), WalletReadiness::Syncing);

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_worker_applies_indexed_tail_delta_after_prior_wallet_delta() {
    let root_dir = temp_db_root("wallet-worker-indexed-tail-order");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
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
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");
    let wallet_utxo = test_wallet_utxo(105, 7);
    let nullifier = wallet_utxo.utxo.nullifier(U256::ZERO);

    assert_eq!(
        send_apply(
            &handle,
            &backfill_tx,
            indexed_delta_batch(
                101,
                110,
                WalletLogDelta {
                    utxos: vec![wallet_utxo.utxo.clone()],
                    nullifiers: Vec::new(),
                    commitment_observations: Vec::new(),
                    sender_scan_outputs: Vec::new(),
                },
            ),
            0,
        )
        .await,
        WalletBackfillApplyResult::Committed { committed_to: 110 }
    );
    assert_eq!(
        send_apply(
            &handle,
            &backfill_tx,
            indexed_delta_batch(
                111,
                120,
                WalletLogDelta {
                    utxos: Vec::new(),
                    nullifiers: vec![SpentNullifier {
                        tree: wallet_utxo.utxo.tree,
                        nullifier,
                        source: source(120, 0x78),
                    }],
                    commitment_observations: Vec::new(),
                    sender_scan_outputs: Vec::new(),
                },
            ),
            0,
        )
        .await,
        WalletBackfillApplyResult::Committed { committed_to: 120 }
    );

    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.last_scanned() != Some(120) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("indexed deltas applied");

    let snapshot = handle.utxos.read().await;
    assert_eq!(snapshot.len(), 1);
    assert!(snapshot[0].spent.is_some());
    assert_eq!(
        handle.pending_overlay.read().await.local_pending_spent,
        [] as [WalletPendingSpent; 0]
    );

    cancel.cancel();
    drop(snapshot);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_worker_rejects_persistence_failure_without_swapping_state() {
    let root_dir = temp_db_root("wallet-worker-apply-persist-failure");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    cache_store.fail_next_store();
    let mut cfg = wallet_config();
    cfg.cache_store = Some(cache_store.clone());
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
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        cfg,
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");
    assert_eq!(
        send_apply(
            &handle,
            &backfill_tx,
            indexed_delta_batch(
                101,
                110,
                WalletLogDelta {
                    utxos: vec![test_wallet_utxo(105, 7).utxo],
                    nullifiers: Vec::new(),
                    commitment_observations: Vec::new(),
                    sender_scan_outputs: Vec::new(),
                },
            ),
            0,
        )
        .await,
        WalletBackfillApplyResult::Rejected {
            committed_to: 100,
            reason: WalletBackfillRejectReason::PersistenceFailed,
        }
    );

    assert_eq!(handle.last_scanned(), Some(100));
    assert_eq!(
        handle.readiness(),
        WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
    );
    assert!(!handle.readiness().is_ready());
    assert_eq!(*handle.rev_rx.borrow(), 0);
    assert!(handle.utxos.read().await.is_empty());
    assert_eq!(cache_store.state().store_calls, 1);

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_scan_candidate_persist_failure_keeps_checkpoint_and_pending_context() {
    let root_dir = temp_db_root("wallet-worker-spent-pending-context-persist-failure");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    cache_store.fail_next_store();
    let mut cfg = wallet_config();
    let scan_keys =
        ViewingKeyData::from_spending_public_key([7; 32], [U256::from(11), U256::from(12)]);
    cfg.scan_keys = scan_keys;
    cfg.cache_store = Some(cache_store.clone());
    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let wallet_utxo = test_wallet_utxo(105, 7);
    let output_commitment = wallet_utxo.utxo.poi.commitment;
    db.put_pending_output_poi_context(&pending_output_context_for_wallet_utxo(&cfg, &wallet_utxo))
        .expect("store pending context");
    let nullifier = wallet_utxo.utxo.nullifier(scan_keys.nullifying_key);
    let spent_source = source(110, 0x77);
    db.put_wallet_meta(
        &cfg.cache_key,
        &WalletMeta {
            last_scanned_block: 100,
            updated_at: 1,
            last_scanned_block_hash: Some([0x64; 32]),
        },
    )
    .expect("seed checkpoint");
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),

            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: backfill_tx.clone(),
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        cfg.clone(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        vec![wallet_utxo.clone()],
        100,
    )
    .await
    .expect("spawn wallet worker");

    assert_eq!(
        send_apply(
            &handle,
            &backfill_tx,
            indexed_delta_batch(
                101,
                110,
                WalletLogDelta {
                    utxos: Vec::new(),
                    nullifiers: vec![SpentNullifier {
                        tree: wallet_utxo.utxo.tree,
                        nullifier,
                        source: spent_source.clone(),
                    }],
                    commitment_observations: Vec::new(),
                    sender_scan_outputs: vec![
                        sender_scan_output(&scan_keys, spent_source.clone(),)
                    ],
                },
            ),
            0,
        )
        .await,
        WalletBackfillApplyResult::Rejected {
            committed_to: 100,
            reason: WalletBackfillRejectReason::PersistenceFailed,
        }
    );

    assert_eq!(handle.last_scanned(), Some(100));
    let snapshot = handle.utxos.read().await;
    assert_eq!(snapshot.len(), 1);
    assert!(snapshot[0].spent.is_none());
    assert_eq!(
        db.get_wallet_meta(&cfg.cache_key)
            .expect("load retained checkpoint")
            .expect("checkpoint present")
            .last_scanned_block,
        100
    );
    assert!(
        cache_store
            .list_sender_transaction_candidates(cfg.chain.chain_id, &cfg.cache_key)
            .expect("list candidates")
            .is_empty()
    );
    assert!(
        db.get_pending_output_poi_context(cfg.chain.chain_id, &cfg.cache_key, &output_commitment)
            .expect("load pending context")
            .is_some()
    );

    cancel.cancel();
    drop(snapshot);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_scan_commit_discards_spent_pending_context_with_progress() {
    let root_dir = temp_db_root("wallet-worker-spent-pending-context-commit");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let mut cfg = wallet_config();
    let scan_keys =
        ViewingKeyData::from_spending_public_key([7; 32], [U256::from(11), U256::from(12)]);
    cfg.scan_keys = scan_keys;
    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let wallet_utxo = test_wallet_utxo(105, 7);
    let output_commitment = wallet_utxo.utxo.poi.commitment;
    db.put_pending_output_poi_context(&pending_output_context_for_wallet_utxo(&cfg, &wallet_utxo))
        .expect("store pending context");
    let nullifier = wallet_utxo.utxo.nullifier(scan_keys.nullifying_key);
    let spent_source = source(110, 0x77);
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),

            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: backfill_tx.clone(),
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        cfg.clone(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        vec![wallet_utxo.clone()],
        100,
    )
    .await
    .expect("spawn wallet worker");

    assert_eq!(
        handle
            .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), None)
            .await,
        Ok(WalletPendingSpentMarkOutcome::Marked)
    );
    assert_eq!(
        send_apply(
            &handle,
            &backfill_tx,
            indexed_delta_batch(
                101,
                110,
                WalletLogDelta {
                    utxos: Vec::new(),
                    nullifiers: vec![SpentNullifier {
                        tree: wallet_utxo.utxo.tree,
                        nullifier,
                        source: spent_source.clone(),
                    }],
                    commitment_observations: Vec::new(),
                    sender_scan_outputs: vec![
                        sender_scan_output(&scan_keys, spent_source.clone(),)
                    ],
                },
            ),
            0,
        )
        .await,
        WalletBackfillApplyResult::Committed { committed_to: 110 }
    );

    assert_eq!(handle.last_scanned(), Some(110));
    let snapshot = handle.utxos.read().await;
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].spent, Some(spent_source.clone()));
    let persisted = db
        .load_wallet_utxos(&cfg.cache_key)
        .expect("load persisted wallet snapshot");
    assert_eq!(persisted[0].spent, Some(spent_source.clone()));
    let candidates = db
        .list_sender_transaction_candidates(cfg.chain.chain_id, &cfg.cache_key)
        .expect("list persisted candidates");
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].source, spent_source);
    assert!(
        db.get_pending_output_poi_context(cfg.chain.chain_id, &cfg.cache_key, &output_commitment)
            .expect("load pending context")
            .is_none()
    );

    cancel.cancel();
    drop(snapshot);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_pending_overlay_update_runs_through_actor_mailbox() {
    let root_dir = temp_db_root("wallet-pending-overlay-mailbox");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let wallet_utxo = test_wallet_utxo(105, 7);
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),

            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: backfill_tx.clone(),
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        vec![wallet_utxo.clone()],
        100,
    )
    .await
    .expect("spawn wallet worker");
    let spent_source = source(101, 0xaa);
    let pending_spent = WalletPendingSpent {
        tree: wallet_utxo.utxo.tree,
        position: wallet_utxo.utxo.position,
        stable_identity: None,
        tx_hash: Some(spent_source.tx_hash),
        block_number: Some(spent_source.block_number),
        block_timestamp: Some(spent_source.block_timestamp),
    };

    assert!(
        handle
            .request_pending_overlay_rows(
                pending_overlay_rows_from_delta(
                    101,
                    101,
                    WalletLogDelta {
                        utxos: Vec::new(),
                        nullifiers: vec![SpentNullifier {
                            tree: wallet_utxo.utxo.tree,
                            nullifier: wallet_utxo
                                .utxo
                                .nullifier(wallet_config().scan_keys.nullifying_key),
                            source: spent_source,
                        }],
                        commitment_observations: Vec::new(),
                        sender_scan_outputs: Vec::new(),
                    },
                ),
                0,
                100,
            )
            .await
    );

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let overlay = handle.pending_overlay().expect("current view");
            if overlay.pending_spent == vec![pending_spent.clone()] {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("pending overlay update applied through mailbox");

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_pending_overlay_rejects_older_job_after_newer_overlay() {
    let root_dir = temp_db_root("wallet-pending-overlay-reverse-order");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let wallet_utxo = test_wallet_utxo(105, 7);
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),

            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: backfill_tx.clone(),
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        vec![wallet_utxo.clone()],
        100,
    )
    .await
    .expect("spawn wallet worker");
    let older_token = handle.mint_sync_token(0);
    let newer_token = handle.mint_sync_token(0);
    let older_source = source(101, 0xaa);
    let newer_source = source(102, 0xbb);
    let older_spent = WalletPendingSpent {
        tree: wallet_utxo.utxo.tree,
        position: wallet_utxo.utxo.position,
        stable_identity: None,
        tx_hash: Some(older_source.tx_hash),
        block_number: Some(older_source.block_number),
        block_timestamp: Some(older_source.block_timestamp),
    };
    let newer_spent = WalletPendingSpent {
        tx_hash: Some(newer_source.tx_hash),
        block_number: Some(newer_source.block_number),
        block_timestamp: Some(newer_source.block_timestamp),
        ..older_spent.clone()
    };
    let nullifier = wallet_utxo
        .utxo
        .nullifier(wallet_config().scan_keys.nullifying_key);

    handle
        .pending_overlay_tx
        .send(WalletPendingOverlayRequest {
            update: WalletPendingOverlayUpdate::PublicRows(pending_overlay_rows_from_delta(
                102,
                102,
                WalletLogDelta {
                    utxos: Vec::new(),
                    nullifiers: vec![SpentNullifier {
                        tree: wallet_utxo.utxo.tree,
                        nullifier,
                        source: newer_source,
                    }],
                    commitment_observations: Vec::new(),
                    sender_scan_outputs: Vec::new(),
                },
            )),
            token: newer_token,
            reset_generation: 0,
            last_scanned: 100,
        })
        .await
        .expect("send newer overlay");

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let overlay = handle.pending_overlay().expect("current view");
            if overlay.pending_spent == vec![newer_spent.clone()] {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("newer pending overlay applied");

    handle
        .pending_overlay_tx
        .send(WalletPendingOverlayRequest {
            update: WalletPendingOverlayUpdate::PublicRows(pending_overlay_rows_from_delta(
                101,
                101,
                WalletLogDelta {
                    utxos: Vec::new(),
                    nullifiers: vec![SpentNullifier {
                        tree: wallet_utxo.utxo.tree,
                        nullifier,
                        source: older_source,
                    }],
                    commitment_observations: Vec::new(),
                    sender_scan_outputs: Vec::new(),
                },
            )),
            token: older_token,
            reset_generation: 0,
            last_scanned: 100,
        })
        .await
        .expect("send older overlay");
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert_eq!(
        handle
            .pending_overlay()
            .expect("current view")
            .pending_spent,
        vec![newer_spent]
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_retired_backfill_job_rejects_late_apply() {
    let root_dir = temp_db_root("wallet-retired-job-late-apply");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
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
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");
    let token = handle.mint_sync_token(0);

    let lease = assert_start_accepted(
        send_start_token(&backfill_tx, 150, token).await,
        token,
        100,
        150,
    );
    lease.retire("test").await;

    let (response, result_rx) = oneshot::channel();
    backfill_tx
        .send(BackfillEvent::Apply {
            apply: indexed_delta_batch(
                101,
                110,
                WalletLogDelta {
                    utxos: Vec::new(),
                    nullifiers: Vec::new(),
                    commitment_observations: Vec::new(),
                    sender_scan_outputs: Vec::new(),
                },
            ),
            token,
            response,
        })
        .await
        .expect("send late apply");
    assert_eq!(
        result_rx.await.expect("late apply response"),
        WalletBackfillApplyResult::Rejected {
            committed_to: 100,
            reason: WalletBackfillRejectReason::Shutdown,
        }
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_reset_rejects_stale_actor_token() {
    let root_dir = temp_db_root("wallet-reset-stale-actor-token");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
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
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");

    let (response, result_rx) = oneshot::channel();
    backfill_tx
        .send(BackfillEvent::Reset {
            token: WalletResetToken::for_test(1, 2, 1),
            from_block: 80,
            replay_plan: WalletResetReplayPlan::new(0, 0, true),
            response,
        })
        .await
        .expect("send stale reset");
    assert_eq!(
        result_rx.await.expect("reset response"),
        WalletBackfillResetResult::Rejected {
            committed_to: 100,
            reason: WalletBackfillRejectReason::Shutdown,
        }
    );
    assert_eq!(handle.authority_reset_generation(), 0);
    assert_eq!(handle.last_scanned(), Some(100));

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_generic_persistence_and_late_retired_job_failures_are_noops() {
    let root_dir = temp_db_root("wallet-late-job-failed-retired");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
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
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");

    let token = handle.mint_sync_token(0);
    let lease = assert_start_accepted(
        send_start_token(&backfill_tx, 200, token).await,
        token,
        100,
        200,
    );
    let (response, result_rx) = oneshot::channel();
    backfill_tx
        .send(BackfillEvent::JobFailed {
            token,
            reason: WalletReadinessError::PersistenceFailed,
            response,
        })
        .await
        .expect("generic persistence job failure");
    result_rx.await.expect("job failure response");
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert_eq!(handle.readiness(), WalletReadiness::Syncing);

    lease.retire("test").await;
    tokio::time::sleep(Duration::from_millis(25)).await;
    let (response, result_rx) = oneshot::channel();
    backfill_tx
        .send(BackfillEvent::JobFailed {
            token,
            reason: WalletReadinessError::BackfillUnavailable,
            response,
        })
        .await
        .expect("late job failure");
    result_rx.await.expect("job failure response");
    tokio::time::sleep(Duration::from_millis(25)).await;

    assert!(!matches!(handle.readiness(), WalletReadiness::Failed(_)));

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_raw_minted_token_does_not_authorize_apply() {
    let root_dir = temp_db_root("wallet-raw-token-apply-rejected");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
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
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");
    let token = handle.mint_sync_token(0);
    let (response, result_rx) = oneshot::channel();
    backfill_tx
        .send(BackfillEvent::Apply {
            apply: indexed_delta_batch(101, 110, empty_delta()),
            token,
            response,
        })
        .await
        .expect("send raw-token apply");

    assert_eq!(
        result_rx.await.expect("raw-token apply response"),
        WalletBackfillApplyResult::Rejected {
            committed_to: 100,
            reason: WalletBackfillRejectReason::Shutdown,
        }
    );
    assert_eq!(handle.last_scanned(), Some(100));

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_never_accepted_job_retired_is_noop() {
    let root_dir = temp_db_root("wallet-never-accepted-retire-noop");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
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
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");
    let token = handle.mint_sync_token(0);

    let _lease = assert_start_accepted(
        send_start_token(&backfill_tx, 150, token).await,
        token,
        100,
        150,
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn wallet_actor_retired_job_bookkeeping_is_bounded() {
    let mut actor_state = test_actor_state(0);

    for job_id in 1..=10_000 {
        let token = WalletSyncToken::for_test(1, 1, 0, job_id);
        assert!(actor_state.test_transition(|mut state| state.accept_target(token, 0)));
        assert!(actor_state.test_transition(|mut state| state.retire_job(token)));
    }

    assert_eq!(actor_state.test_active_job_count(), 0);
    assert_eq!(actor_state.test_highest_accepted_backfill_job_id(), 10_000);
    assert!(!actor_state.test_transition(|mut state| {
        state.test_accept_backfill_job_id(WalletSyncToken::for_test(1, 1, 0, 10_000))
    }));
    assert!(actor_state.test_transition(|mut state| {
        state.accept_target(WalletSyncToken::for_test(1, 1, 0, 10_001), 0)
    }));
}

#[tokio::test]
async fn wallet_retired_backfill_job_rejects_late_target() {
    let root_dir = temp_db_root("wallet-retired-job-late-target");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
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
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");
    let token = handle.mint_sync_token(0);

    let lease = assert_start_accepted(
        send_start_token(&backfill_tx, 150, token).await,
        token,
        100,
        150,
    );
    lease.retire("test").await;

    assert_eq!(
        send_target_token(&backfill_tx, 150, token).await,
        WalletBackfillFinishResult::Rejected {
            committed_to: 100,
            reason: WalletBackfillRejectReason::Shutdown,
        }
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_reset_acceptance_persist_failure_keeps_generation_current() {
    let root_dir = temp_db_root("wallet-reset-acceptance-persist-failure");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    let mut cfg = wallet_config();
    cfg.cache_store = Some(cache_store.clone());
    let (live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, mut backfill_request_rx) = mpsc::channel(8);
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
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        cfg,
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");

    cache_store.fail_next_actor_state_put();
    assert_eq!(
        send_reset(&backfill_tx, 1, 50).await,
        WalletBackfillResetResult::Rejected {
            committed_to: 100,
            reason: WalletBackfillRejectReason::PersistenceFailed,
        }
    );
    assert_eq!(handle.authority_reset_generation(), 0);

    let token = handle.mint_sync_token(handle.authority_reset_generation());
    let lease = assert_start_accepted(
        send_start_token(&backfill_tx, 110, token).await,
        token,
        100,
        110,
    );
    assert_eq!(
        lease
            .apply("test", indexed_delta_batch(101, 110, empty_delta()))
            .await,
        WalletBackfillApplyResult::Committed { committed_to: 110 }
    );
    assert_eq!(
        lease.finish("test", 110).await,
        WalletBackfillFinishResult::Ready { committed_to: 110 }
    );

    live_tx
        .send(Arc::new(LogBatch {
            from_block: 120,
            to_block: 120,
            logs: Vec::new(),
            block_timestamps: HashMap::new(),
            to_block_hash: None,
            read_scope: test_public_scan_read_scope(),
        }))
        .expect("live receiver");
    let request = tokio::time::timeout(Duration::from_secs(1), backfill_request_rx.recv())
        .await
        .expect("live gap backfill requested")
        .expect("backfill request");
    let BackfillRequest::Add {
        from_block,
        to_block,
        driver,
        ..
    } = request
    else {
        panic!("expected live-gap add request");
    };
    assert_eq!(from_block, 111);
    assert_eq!(to_block, 120);
    assert_eq!(driver.token().reset_generation(), 0);

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_reset_replay_is_admitted_when_response_receiver_is_dropped() {
    let root_dir = temp_db_root("wallet-reset-dropped-response");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cfg = wallet_config();
    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, mut backfill_request_rx) = mpsc::channel(8);
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
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        cfg.clone(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        vec![test_wallet_utxo(105, 7)],
        120,
    )
    .await
    .expect("spawn wallet worker");

    let (response, result_rx) = oneshot::channel();
    drop(result_rx);
    backfill_tx
        .send(BackfillEvent::Reset {
            token: test_reset_token(1),
            from_block: 100,
            replay_plan: WalletResetReplayPlan::new(0, 150, false),
            response,
        })
        .await
        .expect("send reset with dropped response receiver");

    let request = tokio::time::timeout(Duration::from_secs(1), backfill_request_rx.recv())
        .await
        .expect("actor-owned reset replay admitted")
        .expect("backfill request channel open");
    let BackfillRequest::Add {
        from_block,
        to_block,
        follow_safe_head,
        driver,
        ..
    } = request
    else {
        panic!("expected reset replay add request");
    };
    assert_eq!(from_block, 100);
    assert_eq!(to_block, 150);
    assert!(!follow_safe_head);
    assert_eq!(driver.token().reset_generation(), 1);

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let state = db
                .get_wallet_sync_actor_state(cfg.chain.chain_id, &cfg.cache_key)
                .expect("load wallet sync actor state")
                .expect("wallet sync actor state");
            if state.pending_reset.is_none() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("durable reset plan retired after actor-owned admission");
    assert!(backfill_request_rx.try_recv().is_err());

    cancel.cancel();
    drop(handle);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_reset_replay_is_readmitted_after_durable_retirement_failure() {
    let root_dir = temp_db_root("wallet-reset-replay-readmission");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    cache_store.fail_next_reset_replay_retirement();
    let mut cfg = wallet_config();
    cfg.cache_store = Some(cache_store);
    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, mut backfill_request_rx) = mpsc::channel(8);
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
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        cfg,
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        vec![test_wallet_utxo(105, 7)],
        120,
    )
    .await
    .expect("spawn wallet worker");

    let (response, result_rx) = oneshot::channel();
    backfill_tx
        .send(BackfillEvent::Reset {
            token: test_reset_token(1),
            from_block: 100,
            replay_plan: WalletResetReplayPlan::new(0, 150, false),
            response,
        })
        .await
        .expect("send reset");
    assert_eq!(
        result_rx.await.expect("reset response"),
        WalletBackfillResetResult::accepted_committed(1, 99)
    );
    let first_lease = match tokio::time::timeout(Duration::from_secs(1), backfill_request_rx.recv())
        .await
        .expect("first reset replay admitted")
        .expect("first reset replay request")
    {
        BackfillRequest::Add { driver, .. } => driver,
        BackfillRequest::Remove { .. } => panic!("expected reset replay add request"),
    };
    let first_token = first_lease.token();

    first_lease.retire("test").await;
    let (response, result_rx) = oneshot::channel();
    backfill_tx
        .send(BackfillEvent::Apply {
            apply: indexed_delta_batch(100, 100, empty_delta()),
            token: first_token,
            response,
        })
        .await
        .expect("send event after reset replay retirement");
    assert_eq!(
        result_rx.await.expect("retired replay response"),
        WalletBackfillApplyResult::Rejected {
            committed_to: 99,
            reason: WalletBackfillRejectReason::Shutdown,
        }
    );

    let second_lease =
        match tokio::time::timeout(Duration::from_secs(1), backfill_request_rx.recv())
            .await
            .expect("reset replay readmitted")
            .expect("readmitted reset replay request")
        {
            BackfillRequest::Add { driver, .. } => driver,
            BackfillRequest::Remove { .. } => panic!("expected reset replay add request"),
        };
    let second_token = second_lease.token();
    assert_ne!(second_token, first_token);

    cancel.cancel();
    drop(handle);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_dropped_overlapping_backfill_response_preserves_covering_job() {
    let root_dir = temp_db_root("wallet-dropped-backfill-response");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
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
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");
    assert_eq!(
        send_target(&handle, &backfill_tx, 100, 0).await,
        WalletBackfillFinishResult::Ready { committed_to: 100 }
    );

    let covering_token = handle.mint_sync_token(0);
    let covering_lease = assert_start_accepted(
        send_start_token(&backfill_tx, 200, covering_token).await,
        covering_token,
        100,
        200,
    );
    let dropped_token = handle.mint_sync_token(0);
    let (response, result_rx) = oneshot::channel();
    drop(result_rx);
    backfill_tx
        .send(BackfillEvent::Start {
            target_block: 150,
            token: dropped_token,
            response,
        })
        .await
        .expect("send target with dropped response receiver");

    let (response, result_rx) = oneshot::channel();
    backfill_tx
        .send(BackfillEvent::Apply {
            apply: indexed_delta_batch(101, 110, empty_delta()),
            token: dropped_token,
            response,
        })
        .await
        .expect("send late apply for dropped handoff");
    assert_eq!(
        result_rx.await.expect("late apply response"),
        WalletBackfillApplyResult::Rejected {
            committed_to: 100,
            reason: WalletBackfillRejectReason::Shutdown,
        }
    );
    assert_eq!(handle.readiness(), WalletReadiness::Syncing);

    assert_eq!(
        covering_lease
            .apply("test", indexed_delta_batch(101, 200, empty_delta()))
            .await,
        WalletBackfillApplyResult::Committed { committed_to: 200 }
    );
    assert_eq!(
        covering_lease.finish("test", 200).await,
        WalletBackfillFinishResult::Ready { committed_to: 200 }
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_pending_reset_retry_retires_rejected_target_job() {
    let root_dir = temp_db_root("wallet-reset-retry-retires-job");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    let mut cfg = wallet_config();
    cfg.cache_store = Some(cache_store.clone());
    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, mut backfill_request_rx) = mpsc::channel(8);
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
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        cfg,
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        vec![test_wallet_utxo(105, 7)],
        120,
    )
    .await
    .expect("spawn wallet worker");

    cache_store.fail_next_store();
    assert_eq!(
        send_reset(&backfill_tx, 1, 100).await,
        WalletBackfillResetResult::accepted_pending(
            1,
            120,
            Some(WalletBackfillRejectReason::PersistenceFailed),
        )
    );
    let token = handle.mint_sync_token(1);
    cache_store.fail_next_store();
    assert!(matches!(
        send_start_token(&backfill_tx, 130, token).await,
        WalletBackfillStartResult::Rejected {
            reason: WalletBackfillRejectReason::PersistenceFailed
                | WalletBackfillRejectReason::Shutdown,
            ..
        }
    ));

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let state = db
                .get_wallet_sync_actor_state(1, handle.cache_key.as_str())
                .expect("load wallet sync actor state");
            if state.is_some_and(|state| state.pending_reset.is_none()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("pending reset retry committed");

    assert_eq!(
        send_target_token(&backfill_tx, 130, token).await,
        WalletBackfillFinishResult::Rejected {
            committed_to: 99,
            reason: WalletBackfillRejectReason::Shutdown,
        }
    );

    let replay_lease = match backfill_request_rx
        .recv()
        .await
        .expect("actor-owned reset replay request")
    {
        BackfillRequest::Add { driver, .. } => driver,
        BackfillRequest::Remove { .. } => panic!("expected reset replay add request"),
    };
    assert_eq!(
        replay_lease
            .apply("test", indexed_delta_batch(100, 130, empty_delta()))
            .await,
        WalletBackfillApplyResult::Committed { committed_to: 130 }
    );
    assert_eq!(
        replay_lease.finish("test", 130).await,
        WalletBackfillFinishResult::Ready { committed_to: 130 }
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_reset_boundary_ahead_of_lagging_cursor_does_not_synthesize_progress() {
    let root_dir = temp_db_root("wallet-reset-boundary-lagging-cursor");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
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
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        50,
    )
    .await
    .expect("spawn wallet worker");

    assert_eq!(
        send_reset(&backfill_tx, 1, 100).await,
        WalletBackfillResetResult::accepted_committed(1, 50)
    );
    assert_eq!(handle.last_scanned(), Some(50));
    assert_eq!(
        db.get_wallet_meta(&handle.cache_key)
            .expect("load meta")
            .expect("meta persisted")
            .last_scanned_block,
        50
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_reset_covered_positive_replay_target_completes_without_queued_job() {
    let root_dir = temp_db_root("wallet-reset-covered-replay-target");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, mut backfill_request_rx) = mpsc::channel(8);
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
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        120,
    )
    .await
    .expect("spawn wallet worker");

    let (response, result_rx) = oneshot::channel();
    backfill_tx
        .send(BackfillEvent::Reset {
            token: test_reset_token(1),
            from_block: 121,
            replay_plan: WalletResetReplayPlan::new(0, 100, false),
            response,
        })
        .await
        .expect("send covered-target reset");
    assert_eq!(
        result_rx.await.expect("reset response"),
        WalletBackfillResetResult::accepted_committed(1, 120)
    );
    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.readiness() != WalletReadiness::Ready {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("covered replay target becomes ready");

    assert_eq!(handle.last_scanned(), Some(120));
    assert!(backfill_request_rx.try_recv().is_err());

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_newer_reset_merges_pending_reset_boundary() {
    let root_dir = temp_db_root("wallet-reset-newer-merge");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    let mut cfg = wallet_config();
    cfg.cache_store = Some(cache_store.clone());
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
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        cfg.clone(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        vec![test_wallet_utxo(105, 7)],
        120,
    )
    .await
    .expect("spawn wallet worker");

    cache_store.fail_next_store();
    assert_eq!(
        send_reset(&backfill_tx, 1, 100).await,
        WalletBackfillResetResult::accepted_pending(
            1,
            120,
            Some(WalletBackfillRejectReason::PersistenceFailed),
        )
    );
    // Accept held, rewind failed: public view is fenced.
    assert_eq!(handle.last_scanned(), None);
    assert_eq!(handle.last_scanned_raw(), 120);
    assert_eq!(
        send_reset(&backfill_tx, 2, 80).await,
        WalletBackfillResetResult::accepted_committed(2, 79)
    );
    assert_eq!(handle.last_scanned(), Some(79));
    assert!(handle.utxos.read().await.is_empty());
    let state = db
        .get_wallet_sync_actor_state(cfg.chain.chain_id, &cfg.cache_key)
        .expect("load sync actor state")
        .expect("sync actor state");
    assert_eq!(state.highest_accepted_reset_intent, 2);
    assert!(state.pending_reset.is_none());
    assert_eq!(
        send_reset(&backfill_tx, 1, 70).await,
        WalletBackfillResetResult::Rejected {
            committed_to: 79,
            reason: WalletBackfillRejectReason::StaleResetIntent {
                accepted: 2,
                actual: 1,
            },
        }
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_reset_commit_clears_stale_pending_overlay() {
    let root_dir = temp_db_root("wallet-reset-clears-pending-overlay");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let wallet_utxo = test_wallet_utxo(105, 7);
    let expired_wallet_utxo = test_wallet_utxo(106, 8);
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),

            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: backfill_tx.clone(),
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        vec![wallet_utxo.clone(), expired_wallet_utxo.clone()],
        120,
    )
    .await
    .expect("spawn wallet worker");
    let spent_source = source(121, 0xaa);
    let pending_spent = WalletPendingSpent {
        tree: wallet_utxo.utxo.tree,
        position: wallet_utxo.utxo.position,
        stable_identity: None,
        tx_hash: Some(spent_source.tx_hash),
        block_number: Some(spent_source.block_number),
        block_timestamp: Some(spent_source.block_timestamp),
    };
    assert!(
        handle
            .request_pending_overlay_rows(
                pending_overlay_rows_from_delta(
                    121,
                    121,
                    WalletLogDelta {
                        utxos: Vec::new(),
                        nullifiers: vec![SpentNullifier {
                            tree: wallet_utxo.utxo.tree,
                            nullifier: wallet_utxo
                                .utxo
                                .nullifier(wallet_config().scan_keys.nullifying_key),
                            source: spent_source,
                        }],
                        commitment_observations: Vec::new(),
                        sender_scan_outputs: Vec::new(),
                    },
                ),
                0,
                120,
            )
            .await
    );
    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.pending_overlay().map(|o| o.pending_spent.clone())
            != Some(vec![pending_spent.clone()])
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("pending overlay applied");
    let now = now_epoch_secs();
    let recent_local =
        WalletPendingSpent::submitted(&wallet_utxo.utxo, Some([0xbb; 32].into()), now);
    let expired_local = WalletPendingSpent::submitted(
        &expired_wallet_utxo.utxo,
        Some([0xcc; 32].into()),
        now.saturating_sub(LOCAL_PENDING_SPENT_TTL.as_secs() + 1),
    );
    {
        let mut overlay = handle.pending_overlay.write().await;
        overlay.local_pending_spent = vec![recent_local.clone(), expired_local];
    }

    assert_eq!(
        send_reset(&backfill_tx, 1, 100).await,
        WalletBackfillResetResult::accepted_committed(1, 99)
    );
    let overlay = handle.pending_overlay().expect("current after rewind");
    assert_eq!(overlay.pending_spent, [] as [WalletPendingSpent; 0]);
    assert!(overlay.new_utxos.is_empty());
    assert_eq!(overlay.local_pending_spent, vec![recent_local]);
    assert!(overlay.local_pending_spent[0].matches_local_utxo(&wallet_utxo));

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_live_gap_backfill_queue_full_marks_job_failed() {
    let root_dir = temp_db_root("wallet-live-gap-queue-full");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let (live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, mut backfill_request_rx) = mpsc::channel(1);
    backfill_request_tx
        .try_send(BackfillRequest::Remove {
            cache_key: "blocked".to_string(),
            actor_id: 0,
            response: oneshot::channel().0,
        })
        .expect("fill backfill request queue");
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
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");
    assert_eq!(
        send_target(&handle, &backfill_tx, 100, 0).await,
        WalletBackfillFinishResult::Ready { committed_to: 100 }
    );
    live_tx
        .send(Arc::new(LogBatch {
            from_block: 120,
            to_block: 120,
            logs: Vec::new(),
            block_timestamps: HashMap::new(),
            to_block_hash: None,
            read_scope: test_public_scan_read_scope(),
        }))
        .expect("live receiver");
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if matches!(
                handle.readiness(),
                WalletReadiness::Failed(WalletReadinessError::BackfillUnavailable)
            ) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("backfill unavailable readiness observed");
    assert!(backfill_request_rx.try_recv().is_ok());

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_target_does_not_publish_ready_while_other_backfill_active() {
    let root_dir = temp_db_root("wallet-target-active-job-gate");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
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
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");

    let initial_token = handle.mint_sync_token(0);
    assert_eq!(
        send_target_token(&backfill_tx, 100, initial_token).await,
        WalletBackfillFinishResult::Ready { committed_to: 100 }
    );
    let gap_token = handle.mint_sync_token(0);
    let _gap_lease = assert_start_accepted(
        send_start_token(&backfill_tx, 150, gap_token).await,
        gap_token,
        100,
        150,
    );
    let covered_token = handle.mint_sync_token(0);
    let covered_lease = assert_start_accepted(
        send_start_token(&backfill_tx, 100, covered_token).await,
        covered_token,
        100,
        100,
    );
    assert_eq!(
        covered_lease.finish("test", 100).await,
        WalletBackfillFinishResult::Ready { committed_to: 100 }
    );
    assert_eq!(handle.readiness(), WalletReadiness::Syncing);
    assert!(!handle.readiness().is_ready());

    let (response, result_rx) = oneshot::channel();
    backfill_tx
        .send(BackfillEvent::Apply {
            apply: indexed_delta_batch(101, 110, empty_delta()),
            token: covered_token,
            response,
        })
        .await
        .expect("send late covered-token apply");
    assert_eq!(
        result_rx.await.expect("late apply result"),
        WalletBackfillApplyResult::Rejected {
            committed_to: 100,
            reason: WalletBackfillRejectReason::Shutdown,
        }
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_reset_rejects_persistence_failure_without_publishing_rewind() {
    let root_dir = temp_db_root("wallet-reset-persist-failure");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    let mut cfg = wallet_config();
    cfg.cache_store = Some(cache_store.clone());
    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let initial_utxo = test_wallet_utxo(105, 7);
    let list_key = default_active_poi_list_keys()[0];
    let external_output = test_wallet_utxo_with_random(110, 17, [0x17; 16]);
    let stale_context = observed_external_pending_output_context(
        &cfg,
        &external_output,
        list_key,
        &source(110, 0xd1),
    );
    let stale_recovery =
        output_poi_recovery_for_pending_context(&stale_context, OutputPoiRecoveryStatus::Submitted);
    let candidate_source = source(110, 0xd3);
    let candidate_note = Note {
        token_hash: U256::from(7),
        value: U256::from(9),
        random: [0x5a; 16],
        npk: U256::from(11),
    };
    let sender_candidate = crate::SenderTransactionCandidate::new(
        cfg.chain.chain_id,
        cfg.cache_key.clone(),
        candidate_source.clone(),
        vec![crate::SenderTransactionCandidateSpend {
            tree: initial_utxo.utxo.tree,
            position: initial_utxo.utxo.position,
            commitment: initial_utxo.utxo.poi.commitment,
        }],
        vec![crate::SenderTransactionCandidateOutput {
            tree: 3,
            position: 18,
            commitment: FixedBytes::from(candidate_note.commitment().to_be_bytes::<32>()),
            note: Some(candidate_note),
        }],
    )
    .expect("sender candidate")
    // Unshield work the rewind removes without completing any validation.
    .with_unshield(Some(crate::SenderTransactionCandidateUnshield {
        railgun_txids: vec![FixedBytes::from([0xd4; 32])],
        outputs_handed_off: false,
    }))
    .expect("sender candidate with unshield work");
    db.put_opaque_wallet_private_row(
        &sender_candidate.namespace(),
        WalletPrivateRecordKind::SenderTransactionCandidate,
        &OpaqueWalletPrivateRow {
            row_id: sender_candidate.row_identity(),
            payload: sender_candidate.encode().expect("encode sender candidate"),
        },
    )
    .expect("seed sender candidate");
    let recovered_output = test_wallet_utxo_with_random(110, 18, [0x18; 16]);
    let mut recovered_context = observed_external_pending_output_context(
        &cfg,
        &recovered_output,
        list_key,
        &candidate_source,
    );
    recovered_context.output_role = PendingOutputPoiRole::RecoveredOutgoing;
    recovered_context.source_operation_id = Some("recovered-sender-output-poi:test".to_string());
    let recovered_recovery = output_poi_recovery_for_pending_context(
        &recovered_context,
        OutputPoiRecoveryStatus::Submitted,
    );
    db.put_pending_output_poi_context(&recovered_context)
        .expect("seed recovered outgoing context");
    db.put_output_poi_recovery(&recovered_recovery)
        .expect("seed recovered outgoing recovery");
    assert_ne!(
        stale_context.output_commitment, initial_utxo.utxo.poi.commitment,
        "external test context must not alias the rewound owned output"
    );
    db.put_pending_output_poi_context(&stale_context)
        .expect("seed external pending context");
    db.put_output_poi_recovery(&stale_recovery)
        .expect("seed external recovery");
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),

            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: backfill_tx.clone(),
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        cfg.clone(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        vec![initial_utxo],
        120,
    )
    .await
    .expect("spawn wallet worker");
    let workflow_initial = *handle.observation().ppoi_workflow_status();
    assert_eq!(workflow_initial.needs_attention, 2);
    assert_eq!(
        workflow_initial.awaiting_recovery, 2,
        "the candidate's external output and its unshield TXID"
    );
    assert_eq!(workflow_initial.validation_revision, 0);

    assert_eq!(
        send_target(&handle, &backfill_tx, 120, 0).await,
        WalletBackfillFinishResult::Ready { committed_to: 120 }
    );
    let rev_before_reset = *handle.rev_rx.borrow();
    let store_calls_before_reset = cache_store.state().store_calls;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if handle
                .observation()
                .ppoi_workflow_status()
                .awaiting_poi_data
                == 1
                && handle
                    .observation()
                    .ppoi_workflow_status()
                    .retrying_recovery
                    == 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("sender local POI recovery wait state is published");
    let workflow_before_reset = *handle.observation().ppoi_workflow_status();
    cache_store.fail_next_store();

    assert_eq!(
        send_reset(&backfill_tx, 1, 100).await,
        WalletBackfillResetResult::accepted_pending(
            1,
            120,
            Some(WalletBackfillRejectReason::PersistenceFailed),
        )
    );

    assert_eq!(handle.authority_reset_generation(), 1);
    // Accept succeeded, rewind failed: public view is fenced (not pre-reset current).
    let reset_pending_observation = handle.observation();
    assert!(matches!(
        reset_pending_observation.view(),
        WalletViewState::ResetPending {
            intent_id: 1,
            from_block: 100,
            reset_generation: 1,
        }
    ));
    assert_eq!(
        reset_pending_observation.readiness(),
        &WalletReadiness::Syncing
    );
    assert_eq!(handle.last_scanned(), None);
    assert!(handle.utxos_snapshot().is_none());
    assert!(handle.pending_overlay().is_none());
    assert!(handle.current_snapshot().is_none());
    assert_eq!(handle.last_scanned_raw(), 120);
    assert_eq!(handle.readiness(), WalletReadiness::Syncing);
    assert!(!handle.readiness().is_ready());
    assert_eq!(*handle.rev_rx.borrow(), rev_before_reset);
    assert_eq!(
        reset_pending_observation.ppoi_workflow_status(),
        &workflow_before_reset
    );
    let retained_context = db
        .get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &stale_context.output_commitment,
        )
        .expect("load external context after failed rewind")
        .expect("failed rewind retains external context");
    assert_eq!(retained_context.observation, stale_context.observation);
    assert_eq!(
        retained_context.submitted_poi_list_keys,
        stale_context.submitted_poi_list_keys
    );
    assert_eq!(
        retained_context.terminal_error,
        stale_context.terminal_error
    );
    assert!(
        db.get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &stale_context.output_commitment,
        )
        .expect("load recovery after failed rewind")
        .is_some(),
        "failed atomic rewind must retain the matching recovery"
    );
    assert!(
        cache_store
            .get_sender_transaction_candidate(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &sender_candidate.semantic_id(),
            )
            .expect("load candidate after failed rewind")
            .is_some(),
        "failed atomic rewind must retain the sender candidate"
    );
    assert!(
        db.get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &recovered_context.output_commitment,
        )
        .expect("load recovered context after failed rewind")
        .is_some(),
        "failed atomic rewind must retain derived sender context"
    );
    assert!(
        db.get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &recovered_context.output_commitment,
        )
        .expect("load recovered recovery after failed rewind")
        .is_some(),
        "failed atomic rewind must retain derived sender recovery"
    );
    assert_eq!(
        cache_store.state().store_calls,
        store_calls_before_reset + 1
    );
    let state = db
        .get_wallet_sync_actor_state(1, handle.cache_key.as_str())
        .expect("load wallet sync actor state")
        .expect("wallet sync actor state persisted");
    assert_eq!(state.highest_accepted_reset_intent, 1);
    assert_eq!(state.pending_reset.expect("pending reset").from_block, 100);

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if handle.last_scanned() == Some(99) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("actor-owned reset retry commits rewind");
    assert!(handle.utxos.read().await.is_empty());
    let rewound_context = db
        .get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &stale_context.output_commitment,
        )
        .expect("load external context after rewind retry")
        .expect("external proof context is retained");
    assert!(rewound_context.observation.is_none());
    assert_eq!(
        rewound_context.submitted_poi_list_keys,
        [] as [FixedBytes<32>; 0]
    );
    assert!(rewound_context.terminal_error.is_none());
    assert!(
        db.get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &stale_context.output_commitment,
        )
        .expect("load recovery after rewind retry")
        .is_none()
    );
    assert!(
        cache_store
            .get_sender_transaction_candidate(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &sender_candidate.semantic_id(),
            )
            .expect("load candidate after rewind retry")
            .is_none()
    );
    assert!(
        db.get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &recovered_context.output_commitment,
        )
        .expect("load recovered context after rewind retry")
        .is_none()
    );
    assert!(
        db.get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &recovered_context.output_commitment,
        )
        .expect("load recovered recovery after rewind retry")
        .is_none()
    );
    let rewind_observation = handle.observation();
    let WalletViewState::Current(rewound) = rewind_observation.view() else {
        panic!("successful rewind must publish Current");
    };
    assert_eq!(rewound.last_scanned, 99);
    assert_eq!(rewind_observation.readiness(), &WalletReadiness::Syncing);
    assert_eq!(
        rewind_observation.ppoi_workflow_status(),
        &WalletPpoiWorkflowStatus::default()
    );
    assert_ne!(*handle.rev_rx.borrow(), rev_before_reset);
    let state = db
        .get_wallet_sync_actor_state(1, handle.cache_key.as_str())
        .expect("reload wallet sync actor state")
        .expect("wallet sync actor state persisted");
    assert!(state.pending_reset.is_none());

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn reset_current_publication_follows_canonical_apply_and_failure_changes_nothing() {
    let root_dir = temp_db_root("wallet-reset-canonical-publication-order");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    let mut cfg = wallet_config();
    cfg.cache_store = Some(cache_store.clone());
    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let initial_utxo = test_wallet_utxo(105, 7);
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),

            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: backfill_tx,
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        cfg.clone(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        vec![initial_utxo],
        120,
    )
    .await
    .expect("spawn wallet worker");
    assert_eq!(handle.advance_reset_generation().await, Some(1));
    handle.publish_view_for_test(WalletViewState::ResetPending {
        intent_id: 1,
        from_block: 100,
        reset_generation: 1,
    });
    let pending = PendingWalletReset::new(1, 100, 1, WalletResetReplayPlan::new(0, 150, false));
    let (mut actor_state, _unused_observation_rx) = WalletActorState::new(
        1,
        1,
        1,
        120,
        1,
        Some(pending),
        false,
        WalletViewState::ResetPending {
            intent_id: 1,
            from_block: 100,
            reset_generation: 1,
        },
    );
    actor_state.set_observation_publisher_for_test(
        handle
            .observation
            .upgrade()
            .expect("test handle owns observation publisher"),
    );
    let readiness_rx = handle.subscribe_observation();
    let mut last_scanned = 120;
    let mut persist_state = WalletPersistState {
        needs_full_persist: true,
        pending_cache_reset: Some(7),
    };
    let initial_flush_at = Instant::now();
    let mut live_metadata_flush = WalletLiveMetadataFlush::new(120, initial_flush_at);
    let mut observation_rx = handle.subscribe_observation();
    let _ = observation_rx.borrow_and_update();

    cache_store.fail_next_store();
    let failed = WalletResetCommitRequest {
        cache_store: cache_store.as_ref(),
        cfg: &cfg,
        utxos: &handle.utxos,
        worker_handle: &handle,
        pending,
        highest_accepted_reset_intent: 1,
        actor_state: &mut actor_state,
        cancel: &cancel,
        last_scanned: &mut last_scanned,
        persist_state: &mut persist_state,
        live_metadata_flush: &mut live_metadata_flush,
    }
    .commit()
    .await;
    assert_eq!(
        failed.rewind,
        WalletResetRewindOutcome::Deferred {
            committed_to: 120,
            reason: WalletBackfillRejectReason::PersistenceFailed,
        }
    );
    assert_eq!(last_scanned, 120);
    assert_eq!(actor_state.last_scanned(), 120);
    assert!(!actor_state.pending_reset_rewind_committed());
    assert_eq!(handle.last_scanned_raw(), 120);
    assert!(persist_state.needs_full_persist);
    assert_eq!(persist_state.pending_cache_reset, Some(7));
    assert_eq!(live_metadata_flush.last_persisted_block, 120);
    assert_eq!(live_metadata_flush.last_persisted_at, initial_flush_at);
    assert!(matches!(
        observation_rx.borrow().view().clone(),
        WalletViewState::ResetPending { .. }
    ));
    assert!(
        !observation_rx
            .has_changed()
            .expect("observation sender remains active")
    );
    assert_eq!(handle.utxos.read().await.len(), 1);

    let committed = WalletResetCommitRequest {
        cache_store: cache_store.as_ref(),
        cfg: &cfg,
        utxos: &handle.utxos,
        worker_handle: &handle,
        pending,
        highest_accepted_reset_intent: 1,
        actor_state: &mut actor_state,
        cancel: &cancel,
        last_scanned: &mut last_scanned,
        persist_state: &mut persist_state,
        live_metadata_flush: &mut live_metadata_flush,
    }
    .commit()
    .await;
    assert_eq!(
        committed.rewind,
        WalletResetRewindOutcome::Committed { committed_to: 99 }
    );
    assert_eq!(last_scanned, 99);
    assert_eq!(actor_state.last_scanned(), 99);
    assert!(actor_state.pending_reset_rewind_committed());
    assert_eq!(actor_state.test_readiness(), WalletReadiness::Syncing);
    assert_eq!(handle.last_scanned_raw(), 99);
    assert_eq!(handle.readiness(), WalletReadiness::Syncing);
    assert_eq!(readiness_rx.borrow().readiness(), &WalletReadiness::Syncing);
    assert!(!persist_state.needs_full_persist);
    assert_eq!(persist_state.pending_cache_reset, None);
    assert_eq!(live_metadata_flush.last_persisted_block, 99);
    assert!(
        observation_rx
            .has_changed()
            .expect("rewound observation was published")
    );
    let observation = observation_rx.borrow_and_update().clone();
    let WalletViewState::Current(current) = observation.view().clone() else {
        panic!("first post-reset publication must be Current");
    };
    assert_eq!(observation.readiness(), &WalletReadiness::Syncing);
    assert_eq!(current.last_scanned, actor_state.last_scanned());
    assert_eq!(current.last_scanned, last_scanned);
    assert_eq!(current.reset_generation, actor_state.reset_generation());
    assert!(current.utxos.is_empty());

    cancel.cancel();
    drop(handle);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_reset_commit_publishes_retained_ppoi_submissions_with_current_view() {
    let root_dir = temp_db_root("wallet-reset-ppoi-projection");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    let mut cfg = wallet_config();
    cfg.cache_store = Some(cache_store.clone());
    let list_key = default_active_poi_list_keys()[0];
    let preserved_output = test_wallet_utxo_with_random(90, 17, [0xd1; 16]);
    let preserved_context = observed_external_pending_output_context(
        &cfg,
        &preserved_output,
        list_key,
        &source(90, 0xd1),
    );
    let preserved_recovery = output_poi_recovery_for_pending_context(
        &preserved_context,
        OutputPoiRecoveryStatus::Submitted,
    );
    db.put_pending_output_poi_context(&preserved_context)
        .expect("seed retained pending context");
    db.put_output_poi_recovery(&preserved_recovery)
        .expect("seed retained recovery");

    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let prepared = prepare_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),
            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: backfill_tx,
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        cfg.clone(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        vec![test_wallet_utxo(105, 7)],
        120,
    )
    .await
    .expect("prepare wallet worker");
    assert!(prepared.handle().activate_actor());
    let handle = prepared.handle();
    assert_eq!(handle.advance_reset_generation().await, Some(1));

    let expected_submission = WalletPpoiSubmissionStatus {
        output_commitment: preserved_context.output_commitment,
        last_submission_at: preserved_recovery
            .last_submission_at
            .expect("submission time"),
    };
    assert_eq!(
        handle.observation().ppoi_submission_statuses(),
        std::slice::from_ref(&expected_submission)
    );

    let mut observation_rx = handle.subscribe_observation();
    let _ = observation_rx.borrow_and_update();
    handle.publish_view_for_test(WalletViewState::ResetPending {
        intent_id: 1,
        from_block: 100,
        reset_generation: 1,
    });
    assert!(
        observation_rx
            .has_changed()
            .expect("observation sender remains active")
    );
    let reset_pending_observation = observation_rx.borrow_and_update().clone();
    assert!(matches!(
        reset_pending_observation.view(),
        WalletViewState::ResetPending { .. }
    ));
    assert_eq!(
        reset_pending_observation.ppoi_submission_statuses(),
        [] as [WalletPpoiSubmissionStatus; 0]
    );

    let pending = PendingWalletReset::new(1, 100, 1, WalletResetReplayPlan::new(0, 150, false));
    let (mut actor_state, _unused_observation_rx) = WalletActorState::new(
        1,
        1,
        1,
        120,
        1,
        Some(pending),
        false,
        WalletViewState::ResetPending {
            intent_id: 1,
            from_block: 100,
            reset_generation: 1,
        },
    );
    actor_state.set_observation_publisher_for_test(
        handle
            .observation
            .upgrade()
            .expect("test handle owns observation publisher"),
    );
    let mut last_scanned = 120;
    let mut persist_state = WalletPersistState {
        needs_full_persist: true,
        pending_cache_reset: Some(7),
    };
    let initial_flush_at = Instant::now();
    let mut live_metadata_flush = WalletLiveMetadataFlush::new(120, initial_flush_at);

    let committed = WalletResetCommitRequest {
        cache_store: cache_store.as_ref(),
        cfg: &cfg,
        utxos: &handle.utxos,
        worker_handle: handle,
        pending,
        highest_accepted_reset_intent: 1,
        actor_state: &mut actor_state,
        cancel: &cancel,
        last_scanned: &mut last_scanned,
        persist_state: &mut persist_state,
        live_metadata_flush: &mut live_metadata_flush,
    }
    .commit()
    .await;
    assert_eq!(
        committed.rewind,
        WalletResetRewindOutcome::Committed { committed_to: 99 }
    );

    assert!(
        observation_rx
            .has_changed()
            .expect("rewound observation was published")
    );
    let observation = observation_rx.borrow_and_update().clone();
    assert!(matches!(observation.view(), WalletViewState::Current(_)));
    assert_eq!(
        observation.ppoi_submission_statuses(),
        std::slice::from_ref(&expected_submission)
    );

    cancel.cancel();
    drop(prepared);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db root");
}

#[tokio::test]
async fn wallet_reset_commit_discards_pending_contexts_for_rewound_outputs() {
    let root_dir = temp_db_root("wallet-reset-pending-context-cleanup");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    let mut cfg = wallet_config();
    cfg.cache_store = Some(cache_store.clone());
    let initial_utxo = test_wallet_utxo(105, 7);
    let output_commitment = initial_utxo.utxo.poi.commitment;
    db.put_pending_output_poi_context(&pending_output_context_for_wallet_utxo(&cfg, &initial_utxo))
        .expect("seed pending context");
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
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        cfg.clone(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        vec![initial_utxo],
        120,
    )
    .await
    .expect("spawn wallet worker");

    assert_eq!(
        send_reset(&backfill_tx, 1, 100).await,
        WalletBackfillResetResult::accepted_committed(1, 99)
    );

    assert_eq!(handle.last_scanned(), Some(99));
    assert!(handle.utxos.read().await.is_empty());
    let state = db
        .get_wallet_sync_actor_state(cfg.chain.chain_id, &cfg.cache_key)
        .expect("load wallet sync actor state")
        .expect("wallet sync actor state persisted");
    assert_eq!(state.highest_accepted_reset_intent, 1);
    assert!(state.pending_reset.is_none());
    assert!(
        db.get_pending_output_poi_context(cfg.chain.chain_id, &cfg.cache_key, &output_commitment)
            .expect("load pending context")
            .is_none()
    );
    assert_eq!(cache_store.state().store_calls, 1);

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_reset_rewinds_external_pending_observation_for_canonical_replay() {
    let root_dir = temp_db_root("wallet-reset-external-pending-observation");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cfg = wallet_config();
    let list_key = default_active_poi_list_keys()[0];
    let external_output = test_wallet_utxo_with_random(110, 17, [0x17; 16]);
    let mut stale_context = observed_external_pending_output_context(
        &cfg,
        &external_output,
        list_key,
        &source(110, 0xd2),
    );
    stale_context.pre_transaction_pois_per_txid_leaf_per_list = current_pending_proof_map(list_key);
    let stale_observation = stale_context
        .observation
        .clone()
        .expect("stale observation");
    let stale_identity = pending_output_poi_submit_identity(&stale_context, &stale_observation)
        .expect("stale external identity");
    let stale_subject = PendingOutputPoiSubject::External {
        output_commitment: stale_context.output_commitment,
        derived_blinded_commitment: stale_identity.derived_blinded_commitment,
    };
    let stale_recovery =
        output_poi_recovery_for_pending_context(&stale_context, OutputPoiRecoveryStatus::Submitted);
    let stale_plan = PendingOutputPoiSubmissionPlan::force_matching(
        vec![list_key],
        expected_recovery_state(Some(&stale_recovery)).expect("recovery fingerprint"),
    );
    db.put_pending_output_poi_context(&stale_context)
        .expect("seed external pending context");
    db.put_output_poi_recovery(&stale_recovery)
        .expect("seed stale external recovery");

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
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        cfg.clone(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        120,
    )
    .await
    .expect("spawn wallet worker");

    assert_eq!(
        send_reset(&backfill_tx, 1, 100).await,
        WalletBackfillResetResult::accepted_committed(1, 99)
    );
    assert_eq!(
        handle.observation().ppoi_workflow_status(),
        &WalletPpoiWorkflowStatus::default()
    );
    let rewound = db
        .get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &stale_context.output_commitment,
        )
        .expect("load rewound external context")
        .expect("retain immutable external proof context");
    assert!(rewound.observation.is_none());
    assert_eq!(rewound.submitted_poi_list_keys, [] as [FixedBytes<32>; 0]);
    assert!(rewound.terminal_error.is_none());
    assert_eq!(rewound.railgun_txid, stale_context.railgun_txid);
    assert_eq!(
        rewound.pre_transaction_pois_per_txid_leaf_per_list.len(),
        stale_context
            .pre_transaction_pois_per_txid_leaf_per_list
            .len()
    );
    assert!(
        db.get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &stale_context.output_commitment,
        )
        .expect("load rewound recovery")
        .is_none()
    );

    let authority = WalletPrivateMutationAuthority::new(&handle, 1, &cancel);
    assert_eq!(
        pending_output_poi_submission_plan_current(
            &authority,
            &test_public_data_plane(&db),
            db.as_ref(),
            &cfg,
            &[list_key],
            &stale_context,
            &stale_subject,
            &stale_plan,
        )
        .await
        .expect("stale submission preflight"),
        PendingOutputPoiPreflight::NotCurrent,
        "a submission planned from the rewound observation must be rejected"
    );

    db.put_pending_output_poi_context(&stale_context)
        .expect("reseed legacy stale observation to exercise scan reconciliation");
    db.put_output_poi_recovery(&stale_recovery)
        .expect("reseed legacy stale recovery to exercise scan reconciliation");
    let canonical_source = source(105, 0xe2);
    let canonical_observation = CommitmentObservation {
        tree: 3,
        position: 21,
        commitment: U256::from_be_bytes(stale_context.output_commitment.0),
        source: canonical_source.clone(),
    };
    assert_eq!(
        send_apply(
            &handle,
            &backfill_tx,
            indexed_delta_batch(
                100,
                110,
                WalletLogDelta {
                    utxos: Vec::new(),
                    nullifiers: Vec::new(),
                    commitment_observations: vec![canonical_observation],
                    sender_scan_outputs: Vec::new(),
                },
            ),
            1,
        )
        .await,
        WalletBackfillApplyResult::Committed { committed_to: 110 }
    );

    let canonical = db
        .get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &stale_context.output_commitment,
        )
        .expect("load canonical external context")
        .expect("canonical external context");
    let observed = canonical
        .observation
        .as_ref()
        .expect("canonical observation attached");
    assert_eq!(observed.output_tree, 3);
    assert_eq!(observed.output_position, 21);
    assert_eq!(observed.tx_hash, canonical_source.tx_hash);
    assert_eq!(canonical.submitted_poi_list_keys, [] as [FixedBytes<32>; 0]);
    assert!(canonical.terminal_error.is_none());
    assert_eq!(canonical.missing_list_keys(), vec![list_key]);
    assert_eq!(
        handle.observation().ppoi_workflow_status(),
        &WalletPpoiWorkflowStatus {
            awaiting_submission: 1,
            ..WalletPpoiWorkflowStatus::default()
        }
    );
    assert!(
        db.get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &canonical.output_commitment,
        )
        .expect("load canonical recovery state")
        .is_none()
    );

    let (canonical_subject, owned_output) =
        current_pending_output_poi_subject(&authority, &cfg, &canonical)
            .await
            .expect("canonical external subject is authorized");
    assert!(owned_output.is_none());
    let canonical_plan = PendingOutputPoiSubmissionPlan::force_matching(
        vec![list_key],
        expected_recovery_state(None).expect("absent recovery state"),
    );
    assert_eq!(
        pending_output_poi_submission_plan_current(
            &authority,
            &test_public_data_plane(&db),
            db.as_ref(),
            &cfg,
            &[list_key],
            &canonical,
            &canonical_subject,
            &canonical_plan,
        )
        .await
        .expect("canonical submission preflight"),
        PendingOutputPoiPreflight::Ready
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn prepared_restored_replay_waits_for_activation_before_backfill_admission() {
    let root_dir = temp_db_root("wallet-reset-prepared-replay-admission");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let mut cfg = wallet_config();
    cfg.start_block = Some(100);
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
    .expect("seed bounded restored replay");

    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_event_tx, backfill_event_rx) = mpsc::channel(8);
    let (backfill_request_tx, mut backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let mut prepared = prepare_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),
            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: backfill_event_tx.clone(),
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        cfg.clone(),
        1,
        live_rx,
        backfill_event_rx,
        cancel.clone(),
        Vec::new(),
        79,
    )
    .await
    .expect("prepare restored wallet worker");

    assert!(backfill_request_rx.try_recv().is_err());
    assert_eq!(
        db.get_wallet_sync_actor_state(cfg.chain.chain_id, &cfg.cache_key)
            .expect("read durable actor state")
            .expect("durable actor state")
            .pending_reset
            .expect("durable replay remains before activation")
            .replay_target_block,
        99
    );

    let worker = prepared.take_worker();
    let handle = prepared.activate().expect("activate prepared worker");
    let request = tokio::time::timeout(Duration::from_secs(1), backfill_request_rx.recv())
        .await
        .expect("restored replay admission arrives after activation")
        .expect("backfill request channel remains open");
    let BackfillRequest::Add {
        from_block,
        to_block,
        driver,
        cache_key,
        ..
    } = request
    else {
        panic!("restored replay must admit an Add request");
    };
    assert_eq!((from_block, to_block), (80, 99));
    assert_eq!(driver.token().actor_id(), handle.actor_id());
    assert_eq!(handle.readiness(), WalletReadiness::Syncing);
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let pending_reset = db
                .get_wallet_sync_actor_state(cfg.chain.chain_id, &cfg.cache_key)
                .expect("read actor state after admission")
                .expect("durable actor state after admission")
                .pending_reset;
            if pending_reset.is_none() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("durable replay retirement follows admission");

    driver.retire(&cache_key).await;
    cancel.cancel();
    worker.await.expect("wallet worker shuts down cleanly");
    drop(backfill_event_tx);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_worker_restores_durable_pending_reset_before_accepting_older_intents() {
    let root_dir = temp_db_root("wallet-reset-restore-pending");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cfg = wallet_config();
    db.put_wallet_sync_actor_state(&WalletSyncActorStateRecord {
        chain_id: cfg.chain.chain_id,
        wallet_id: cfg.cache_key.to_string(),
        highest_accepted_reset_intent: 7,
        pending_reset: Some(WalletPendingResetRecord {
            intent_id: 7,
            from_block: 100,
            replay_start_block: 0,
            replay_target_block: 0,
            follow_safe_head: true,
        }),
        updated_at: 1,
    })
    .expect("seed wallet sync actor state");
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
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        cfg.clone(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        vec![test_wallet_utxo(105, 7)],
        120,
    )
    .await
    .expect("spawn wallet worker");

    assert_eq!(handle.authority_reset_generation(), 1);
    assert_eq!(handle.last_scanned(), Some(99));
    assert!(handle.utxos.read().await.is_empty());
    assert_eq!(
        send_reset(&backfill_tx, 7, 90).await,
        WalletBackfillResetResult::Rejected {
            committed_to: 99,
            reason: WalletBackfillRejectReason::StaleResetIntent {
                accepted: 7,
                actual: 7,
            },
        }
    );

    let state = db
        .get_wallet_sync_actor_state(cfg.chain.chain_id, &cfg.cache_key)
        .expect("load wallet sync actor state")
        .expect("wallet sync actor state persisted");
    assert_eq!(state.highest_accepted_reset_intent, 7);
    assert!(state.pending_reset.is_none());

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_worker_restored_pending_reset_waits_for_first_actor_replay_attempt() {
    let root_dir = temp_db_root("wallet-reset-restore-failed-replay");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    let mut cfg = wallet_config();
    cache_store.seed_actor_state(WalletSyncActorStateRecord {
        chain_id: cfg.chain.chain_id,
        wallet_id: cfg.cache_key.to_string(),
        highest_accepted_reset_intent: 7,
        pending_reset: Some(WalletPendingResetRecord {
            intent_id: 7,
            from_block: 100,
            replay_start_block: 0,
            replay_target_block: 0,
            follow_safe_head: true,
        }),
        updated_at: 1,
    });
    cache_store.fail_next_store();
    cfg.cache_store = Some(cache_store.clone());
    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let handle = tokio::time::timeout(
        Duration::from_secs(1),
        spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                http_client: None,
                indexed_artifact_source: None,
                poi_runtime: test_wallet_poi_runtime(),
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx,
                public_data_plane: test_public_data_plane(&db),
                poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
            },
            cfg,
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            vec![test_wallet_utxo(105, 7)],
            120,
        ),
    )
    .await
    .expect("restored pending reset first attempt should complete")
    .expect("spawn wallet worker");

    assert_eq!(
        cache_store.state().store_calls,
        1,
        "worker must not expose the handle before the first rewind attempt"
    );
    assert_eq!(handle.authority_reset_generation(), 1);
    // Public observation is fenced: pre-reset cursor/UTXOs are not current.
    let observation = handle.observation();
    assert!(matches!(
        observation.view(),
        WalletViewState::ResetPending {
            intent_id: 7,
            from_block: 100,
            reset_generation: 1,
        }
    ));
    assert_eq!(observation.readiness(), &WalletReadiness::Syncing);
    assert_eq!(handle.last_scanned(), None);
    assert!(handle.utxos_snapshot().is_none());
    assert!(handle.pending_overlay().is_none());
    assert!(handle.current_snapshot().is_none());
    assert_eq!(handle.last_scanned_raw(), 120);
    assert_eq!(handle.readiness(), WalletReadiness::Syncing);
    assert!(
        cache_store
            .actor_state()
            .expect("restored actor state")
            .pending_reset
            .is_some()
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn incompatible_restored_pending_reset_is_rejected_before_private_state_write() {
    let root_dir = temp_db_root("wallet-reset-incompatible-restored-plan");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    let mut cfg = wallet_config();
    cfg.start_block = Some(100);
    let cache_key = cfg.cache_key.clone();
    let original_meta = WalletMeta {
        last_scanned_block: 120,
        updated_at: 9,
        last_scanned_block_hash: Some([0x91; 32]),
    };
    db.put_wallet_meta(&cache_key, &original_meta)
        .expect("seed wallet cursor");
    cfg.cache_store = Some(cache_store.clone());

    assert!(
        validate_restored_pending_reset(
            &cfg,
            120,
            PendingWalletReset::new(7, 80, 1, WalletResetReplayPlan::new(80, 99, false),),
        )
        .is_ok(),
        "bounded replay through the configured-start boundary must remain valid"
    );

    for (replay_start_block, replay_target_block) in [(100, 150), (80, 98)] {
        cache_store.seed_actor_state(WalletSyncActorStateRecord {
            chain_id: cfg.chain.chain_id,
            wallet_id: cfg.cache_key.to_string(),
            highest_accepted_reset_intent: 7,
            pending_reset: Some(WalletPendingResetRecord {
                intent_id: 7,
                from_block: 80,
                replay_start_block,
                replay_target_block,
                follow_safe_head: false,
            }),
            updated_at: 1,
        });
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();

        let result = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                http_client: None,
                indexed_artifact_source: None,
                poi_runtime: test_wallet_poi_runtime(),
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx,
                public_data_plane: test_public_data_plane(&db),
                poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
            },
            cfg.clone(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            vec![test_wallet_utxo(105, 7)],
            120,
        )
        .await;

        let Err(ChainError::IncompatiblePendingWalletResetReplay {
            post_rewind_cursor,
            configured_start_block,
            replay_start_block: actual_start,
            replay_target_block: actual_target,
            follow_safe_head,
            required_replay_start_block,
            required_replay_target_block,
        }) = result
        else {
            panic!("incompatible restored replay must be rejected");
        };
        assert_eq!(post_rewind_cursor, 79);
        assert_eq!(configured_start_block, 100);
        assert_eq!(actual_start, replay_start_block);
        assert_eq!(actual_target, replay_target_block);
        assert!(!follow_safe_head);
        assert_eq!(required_replay_start_block, 80);
        assert_eq!(required_replay_target_block, 99);
        assert_eq!(cache_store.state().store_calls, 0);
        assert_eq!(cache_store.state().meta_calls, 0);
        let unchanged_meta = db
            .get_wallet_meta(&cache_key)
            .expect("load unchanged wallet cursor")
            .expect("wallet cursor remains");
        assert_eq!(
            unchanged_meta.last_scanned_block,
            original_meta.last_scanned_block
        );
        assert_eq!(unchanged_meta.updated_at, original_meta.updated_at);
        assert_eq!(
            unchanged_meta.last_scanned_block_hash,
            original_meta.last_scanned_block_hash
        );
        let restored = cache_store
            .actor_state()
            .expect("restored actor state remains");
        let pending = restored
            .pending_reset
            .expect("pending reset remains preserved");
        assert_eq!(pending.replay_start_block, replay_start_block);
        assert_eq!(pending.replay_target_block, replay_target_block);

        cancel.cancel();
    }

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_worker_rejects_bootstrap_when_actor_state_read_fails() {
    let root_dir = temp_db_root("wallet-reset-actor-state-read-fails");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    cache_store.fail_next_actor_state();
    let mut cfg = wallet_config();
    cfg.cache_store = Some(cache_store);
    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let public_data_plane = test_public_data_plane(&db);

    let result = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),

            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: backfill_tx,
            public_data_plane: public_data_plane.clone(),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        cfg,
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        vec![test_wallet_utxo(105, 7)],
        120,
    )
    .await;

    assert!(matches!(
        result,
        Err(ChainError::WalletCache(WalletCacheError::Crypto))
    ));
    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn dropping_prepared_wallet_worker_retires_unregistered_actor() {
    let root_dir = temp_db_root("wallet-prepared-registration-cancelled");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let prepared = prepare_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),

            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: backfill_tx,
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        0,
    )
    .await
    .expect("prepare wallet worker");
    let handle = prepared.handle().clone();
    let retained_observation = handle.subscribe_observation();
    assert_eq!(handle.lifecycle(), WalletActorLifecycle::Prepared);
    assert!(matches!(
        retained_observation.borrow().view(),
        WalletViewState::Current(_)
    ));
    assert_eq!(
        retained_observation.borrow().readiness(),
        &WalletReadiness::Syncing
    );

    drop(prepared);

    assert_eq!(handle.lifecycle(), WalletActorLifecycle::Retired);
    assert!(!handle.is_current_actor());
    assert!(cancel.is_cancelled());
    assert_eq!(
        retained_observation.borrow().view(),
        &WalletViewState::Inactive {
            reason: WalletInactiveReason::Retired,
            reset_generation: 0,
        }
    );
    assert_eq!(
        retained_observation.borrow().readiness(),
        &WalletReadiness::Shutdown
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_worker_publishes_shutdown_readiness_on_cancel() {
    let root_dir = temp_db_root("wallet-shutdown-readiness");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cfg = wallet_config();
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
            backfill_sender: backfill_tx,
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        cfg,
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        0,
    )
    .await
    .expect("spawn wallet worker");
    let mut readiness_rx = handle.subscribe_observation();

    cancel.cancel();

    tokio::time::timeout(Duration::from_secs(1), async {
        while readiness_rx.borrow().readiness() != &WalletReadiness::Shutdown {
            readiness_rx
                .changed()
                .await
                .expect("shutdown readiness should be published before channel closes");
        }
    })
    .await
    .expect("shutdown readiness published");
    let observation = readiness_rx.borrow().clone();
    assert_eq!(observation.readiness(), &WalletReadiness::Shutdown);
    assert_eq!(
        observation.view(),
        &WalletViewState::Inactive {
            reason: WalletInactiveReason::Shutdown,
            reset_generation: 0,
        }
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn inner_wallet_actor_panic_publishes_coherent_terminal_observation() {
    let root_dir = temp_db_root("wallet-inner-panic-observation");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
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
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel,
        Vec::new(),
        0,
    )
    .await
    .expect("spawn wallet worker");
    let mut observation_rx = handle.subscribe_observation();

    backfill_tx
        .send(BackfillEvent::PanicForTest)
        .await
        .expect("deliver actor panic trigger");
    tokio::time::timeout(Duration::from_secs(1), async {
        while observation_rx.borrow().readiness() != &WalletReadiness::Shutdown {
            observation_rx
                .changed()
                .await
                .expect("panic fallback publishes before closure");
        }
    })
    .await
    .expect("panic fallback observation");

    let observation = observation_rx.borrow().clone();
    assert_eq!(observation.readiness(), &WalletReadiness::Shutdown);
    assert!(matches!(
        observation.view(),
        WalletViewState::Inactive {
            reason: WalletInactiveReason::Shutdown,
            ..
        }
    ));

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_actor_panic_aborts_tracked_poi_jobs_before_supervisor_completes() {
    let root_dir = temp_db_root("wallet-panic-aborts-tracked-poi-jobs");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let mut prepared = prepare_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),
            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: backfill_tx.clone(),
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel,
        Vec::new(),
        0,
    )
    .await
    .expect("prepare wallet worker");
    let supervisor = prepared.take_worker();
    let _handle = prepared.activate().expect("activate wallet worker");

    let sentinel = Arc::new(());
    let job_sentinel = Arc::downgrade(&sentinel);
    let (started_tx, started_rx) = oneshot::channel();
    backfill_tx
        .send(BackfillEvent::HoldTrackedPoiJobForTest {
            sentinel,
            started: started_tx,
        })
        .await
        .expect("deliver tracked job trigger");
    tokio::time::timeout(Duration::from_secs(1), started_rx)
        .await
        .expect("tracked job starts")
        .expect("tracked job start signal");
    assert!(job_sentinel.upgrade().is_some(), "tracked job is running");

    backfill_tx
        .send(BackfillEvent::PanicForTest)
        .await
        .expect("deliver actor panic trigger");
    tokio::time::timeout(Duration::from_secs(2), supervisor)
        .await
        .expect("supervisor completes after the actor panic")
        .expect("supervisor task");

    assert!(
        job_sentinel.upgrade().is_none(),
        "the supervisor aborts and awaits tracked jobs before it completes"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_retire_actor_does_not_wait_on_authority_lock() {
    let root_dir = temp_db_root("wallet-retire-without-authority-lock");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
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
            backfill_sender: backfill_tx,
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        0,
    )
    .await
    .expect("spawn wallet worker");

    let lock = Arc::clone(&handle.authority_lock);
    let held = lock.lock_owned().await;
    let retire_handle = handle.clone();
    let retired = tokio::task::spawn_blocking(move || {
        retire_handle.retire_actor();
        retire_handle.lifecycle()
    })
    .await
    .expect("retire task");
    assert_eq!(retired, WalletActorLifecycle::Retired);
    assert!(!handle.is_current_actor());
    drop(held);

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_reset_rejects_retired_actor_without_side_effects() {
    let root_dir = temp_db_root("wallet-reset-retired-actor");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    let mut cfg = wallet_config();
    cfg.cache_store = Some(cache_store.clone());
    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let initial_utxo = test_wallet_utxo(105, 7);
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),

            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: backfill_tx.clone(),
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        cfg,
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        vec![initial_utxo],
        120,
    )
    .await
    .expect("spawn wallet worker");

    assert_eq!(
        send_target(&handle, &backfill_tx, 120, 0).await,
        WalletBackfillFinishResult::Ready { committed_to: 120 }
    );
    let rev_before_reset = *handle.rev_rx.borrow();
    let store_calls_before_reset = cache_store.state().store_calls;
    handle.retire_actor();
    assert_eq!(handle.lifecycle(), WalletActorLifecycle::Retired);

    assert_eq!(
        send_reset(&backfill_tx, 1, 100).await,
        WalletBackfillResetResult::Rejected {
            committed_to: 120,
            reason: WalletBackfillRejectReason::Shutdown,
        }
    );

    assert_eq!(handle.authority_reset_generation(), 0);
    assert_eq!(handle.last_scanned(), None);
    assert_eq!(handle.last_scanned_raw(), 120);
    assert_eq!(
        handle.view_state().inactive_reason(),
        Some(WalletInactiveReason::Retired)
    );
    assert_eq!(handle.readiness(), WalletReadiness::Shutdown);
    assert_eq!(*handle.rev_rx.borrow(), rev_before_reset);
    let snapshot = handle.utxos.read().await;
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].utxo.source.block_number, 105);
    assert_eq!(cache_store.state().store_calls, store_calls_before_reset);

    cancel.cancel();
    drop(snapshot);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_poi_refresh_rejects_persistence_failure_without_swapping_state() {
    let root_dir = temp_db_root("wallet-poi-refresh-persist-failure");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    cache_store.fail_next_store();
    let mut cfg = wallet_config();
    cfg.chain.chain_id = 42_161;
    cfg.cache_store = Some(cache_store.clone());
    let checkpoint = WalletMeta {
        last_scanned_block: 100,
        updated_at: 88,
        last_scanned_block_hash: Some([0xb6; 32]),
    };
    db.put_wallet_meta(&cfg.cache_key, &checkpoint)
        .expect("seed POI refresh checkpoint");
    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let public_data_plane = test_public_data_plane(&db);
    let active_poi_list_keys = default_active_poi_list_keys();
    let mut stale_utxo = test_wallet_utxo(105, 7);
    stale_utxo.utxo.poi.statuses.extend(
        active_poi_list_keys
            .iter()
            .copied()
            .map(|list_key| (list_key, PoiStatus::Missing)),
    );
    stale_utxo.utxo.poi.refreshed_at = Some(1);
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),

            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: backfill_tx,
            public_data_plane: public_data_plane.clone(),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        cfg.clone(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        vec![stale_utxo],
        100,
    )
    .await
    .expect("spawn wallet worker");
    let mut persist_state = WalletPersistState::default();
    let (mut actor_state, mut readiness_rx) = test_actor_state_for_handle(&handle, 100);
    let poi_runtime = test_wallet_poi_runtime();
    // Unit test of commit request: job-style reader is fine (not actor path).
    let status_source = poi_runtime
        .status_reader_for_job(&public_data_plane, &cfg, &active_poi_list_keys)
        .await
        .expect("POI status reader");

    let selection = WalletPoiRefreshSelection::RecoverableStale { now: u64::MAX };
    let result = WalletPoiStatusRefreshCommitRequest {
        cache_store: cache_store.as_ref(),
        cfg: &cfg,
        utxos: &handle.utxos,
        worker_handle: &handle,
        last_scanned: 100,
        reset_generation: 0,
        actor_state: &mut actor_state,
        persist_state: &mut persist_state,
        status_reader: status_source.as_reader(),
        active_poi_list_keys: &active_poi_list_keys,
        selection,
        cancel: &cancel,
    }
    .commit()
    .await;

    assert_eq!(result, Err(WalletBackfillRejectReason::PersistenceFailed));
    assert_eq!(
        readiness_rx.borrow().readiness(),
        &WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
    );
    assert_eq!(cache_store.state().last_chain_id, Some(cfg.chain.chain_id));
    let _ = readiness_rx.borrow_and_update();
    assert_eq!(*handle.rev_rx.borrow(), 0);
    let snapshot = handle.utxos.read().await;
    assert!(
        snapshot[0]
            .utxo
            .poi
            .statuses
            .values()
            .all(|status| status == &PoiStatus::Missing)
    );
    assert_eq!(snapshot[0].utxo.poi.refreshed_at, Some(1));
    assert_eq!(cache_store.state().store_calls, 1);
    drop(snapshot);

    assert_eq!(
        WalletPoiStatusRefreshCommitRequest {
            cache_store: cache_store.as_ref(),
            cfg: &cfg,
            utxos: &handle.utxos,
            worker_handle: &handle,
            last_scanned: 100,
            reset_generation: 0,
            actor_state: &mut actor_state,
            persist_state: &mut persist_state,
            status_reader: status_source.as_reader(),
            active_poi_list_keys: &active_poi_list_keys,
            selection,
            cancel: &cancel,
        }
        .commit()
        .await,
        Ok(true)
    );
    assert!(!actor_state.has_persistence_failure());
    assert!(
        readiness_rx
            .has_changed()
            .expect("observation publisher remains active")
    );
    let recovered_observation = readiness_rx.borrow().clone();
    let WalletViewState::Current(recovered_view) = recovered_observation.view() else {
        panic!("successful POI recovery must publish Current");
    };
    assert_eq!(recovered_view.revision, 1);
    assert!(!recovered_view.utxos[0].utxo.poi.statuses.is_empty());
    assert!(
        recovered_view.utxos[0]
            .utxo
            .poi
            .statuses
            .values()
            .any(|status| status != &PoiStatus::Missing)
    );
    assert_eq!(recovered_observation.readiness(), &WalletReadiness::Syncing);
    let retained_checkpoint = db
        .get_wallet_meta(&cfg.cache_key)
        .expect("read retained POI refresh checkpoint")
        .expect("POI refresh checkpoint present");
    assert_eq!(retained_checkpoint.last_scanned_block, 100);
    assert_eq!(retained_checkpoint.updated_at, 88);
    assert_eq!(
        retained_checkpoint.last_scanned_block_hash,
        Some([0xb6; 32])
    );
    let snapshot = handle.utxos.read().await;
    assert!(!snapshot[0].utxo.poi.statuses.is_empty());

    cancel.cancel();
    drop(snapshot);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn same_selection_reader_failure_retains_poi_failure_until_projection_is_obsolete() {
    let root_dir = temp_db_root("wallet-poi-obsolete-failed-selection");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    cache_store.fail_next_store();
    let mut cfg = wallet_config();
    cfg.cache_store = Some(cache_store.clone());
    let active_poi_list_keys = default_active_poi_list_keys();
    let mut initial_utxo = test_wallet_utxo(100, 7);
    assert_ne!(
        initial_utxo
            .utxo
            .poi
            .mark_statuses_unknown_for_lists(&active_poi_list_keys),
        0
    );
    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let public_data_plane = test_public_data_plane(&db);
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),

            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: backfill_tx,
            public_data_plane: public_data_plane.clone(),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        cfg.clone(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        vec![initial_utxo.clone()],
        100,
    )
    .await
    .expect("spawn wallet worker");
    let mut persist_state = WalletPersistState::default();
    let (mut actor_state, readiness_rx) = test_actor_state_for_handle(&handle, 100);
    let failed_selection = WalletPoiRefreshSelection::RequiredOrRecoverable;
    let unavailable_status_reader = UnavailablePoiStatusReader;
    let valid_status_reader = FixedPoiStatusReader(PoiStatus::Valid);

    assert_eq!(
        WalletPoiStatusRefreshCommitRequest {
            cache_store: cache_store.as_ref(),
            cfg: &cfg,
            utxos: &handle.utxos,
            worker_handle: &handle,
            last_scanned: 100,
            reset_generation: 0,
            actor_state: &mut actor_state,
            persist_state: &mut persist_state,
            status_reader: &valid_status_reader,
            active_poi_list_keys: &active_poi_list_keys,
            selection: failed_selection,
            cancel: &cancel,
        }
        .commit()
        .await,
        Err(WalletBackfillRejectReason::PersistenceFailed)
    );
    assert_eq!(
        readiness_rx.borrow().readiness(),
        &WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
    );

    assert_eq!(
        WalletPoiStatusRefreshCommitRequest {
            cache_store: cache_store.as_ref(),
            cfg: &cfg,
            utxos: &handle.utxos,
            worker_handle: &handle,
            last_scanned: 100,
            reset_generation: 0,
            actor_state: &mut actor_state,
            persist_state: &mut persist_state,
            status_reader: &unavailable_status_reader,
            active_poi_list_keys: &active_poi_list_keys,
            selection: WalletPoiRefreshSelection::Recoverable,
            cancel: &cancel,
        }
        .commit()
        .await,
        Ok(false)
    );
    assert!(actor_state.has_failed_poi_status_refresh(0, failed_selection));

    assert_eq!(
        WalletPoiStatusRefreshCommitRequest {
            cache_store: cache_store.as_ref(),
            cfg: &cfg,
            utxos: &handle.utxos,
            worker_handle: &handle,
            last_scanned: 100,
            reset_generation: 0,
            actor_state: &mut actor_state,
            persist_state: &mut persist_state,
            status_reader: &unavailable_status_reader,
            active_poi_list_keys: &active_poi_list_keys,
            selection: failed_selection,
            cancel: &cancel,
        }
        .commit()
        .await,
        Ok(false)
    );
    assert!(actor_state.has_failed_poi_status_refresh(0, failed_selection));
    assert_eq!(
        readiness_rx.borrow().readiness(),
        &WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
    );
    assert_eq!(cache_store.state().store_calls, 1);

    let mut last_scanned = 100;
    let mut live_metadata_flush = WalletLiveMetadataFlush::new(100, Instant::now());
    let job_token = WalletSyncToken::for_test(1, 1, 0, 1);
    assert!(actor_state.test_transition(|mut state| state.accept_target(job_token, 101)));
    let spent_source = source(101, 0xaa);
    let outcome = WalletScanCommitRequest {
        cache_store: cache_store.as_ref(),
        cfg: &cfg,
        utxos: &handle.utxos,
        worker_handle: &handle,
        apply: indexed_delta_batch(
            101,
            101,
            WalletLogDelta {
                utxos: Vec::new(),
                nullifiers: vec![SpentNullifier {
                    tree: initial_utxo.utxo.tree,
                    nullifier: initial_utxo.utxo.nullifier(cfg.scan_keys.nullifying_key),
                    source: spent_source,
                }],
                commitment_observations: Vec::new(),
                sender_scan_outputs: Vec::new(),
            },
        ),
        job_token,
        current_reset_generation: 0,
        event_reset_generation: 0,
        actor_state: &mut actor_state,
        cancel: &cancel,
        last_scanned: &mut last_scanned,
        persist_state: &mut persist_state,
        live_metadata_flush: &mut live_metadata_flush,
        public_data_plane: &public_data_plane,
    }
    .commit()
    .await;
    assert_eq!(
        outcome.result,
        WalletBackfillApplyResult::Committed { committed_to: 101 }
    );
    assert!(handle.utxos.read().await[0].is_spent());
    let durable_utxos =
        <DbStore as WalletCacheStore>::load_wallet_utxos(db.as_ref(), &cfg.cache_key)
            .expect("load durably spent wallet output");
    assert_eq!(durable_utxos.len(), 1);
    assert!(durable_utxos[0].is_spent());
    assert!(actor_state.has_failed_poi_status_refresh(0, failed_selection));
    assert_eq!(cache_store.state().store_calls, 2);

    assert_eq!(
        WalletPoiStatusRefreshCommitRequest {
            cache_store: cache_store.as_ref(),
            cfg: &cfg,
            utxos: &handle.utxos,
            worker_handle: &handle,
            last_scanned,
            reset_generation: 0,
            actor_state: &mut actor_state,
            persist_state: &mut persist_state,
            status_reader: &valid_status_reader,
            active_poi_list_keys: &active_poi_list_keys,
            selection: failed_selection,
            cancel: &cancel,
        }
        .commit()
        .await,
        Ok(false)
    );
    assert!(!actor_state.has_persistence_failure());
    assert_eq!(cache_store.state().store_calls, 2);

    cancel.cancel();
    drop(handle);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_poi_refresh_rejects_when_reset_arrives_during_status_fetch() {
    let root_dir = temp_db_root("wallet-poi-refresh-reset-race");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    let mut cfg = wallet_config();
    cfg.cache_store = Some(cache_store.clone());
    let active_poi_list_keys = default_active_poi_list_keys();
    let initial_utxo = test_wallet_utxo(105, 7);
    let (started_tx, started_rx) = oneshot::channel();
    let (release, release_rx) = oneshot::channel();
    let status_reader = Arc::new(BlockingPoiStatusReader::new(started_tx, release_rx));
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
            backfill_sender: backfill_tx,
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        cfg.clone(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        vec![initial_utxo],
        100,
    )
    .await
    .expect("spawn wallet worker");
    let (actor_state, readiness_rx) = test_actor_state_for_handle(&handle, 100);
    let commit_cache_store = Arc::clone(&cache_store);
    let commit_cfg = cfg.clone();
    let commit_handle = handle.clone();
    let commit_cancel = cancel.clone();
    let commit_active_poi_list_keys = active_poi_list_keys.clone();
    let commit_status_reader = Arc::clone(&status_reader);
    let commit_task = tokio::spawn(async move {
        let mut persist_state = WalletPersistState::default();
        let mut actor_state = actor_state;
        WalletPoiStatusRefreshCommitRequest {
            cache_store: commit_cache_store.as_ref(),
            cfg: &commit_cfg,
            utxos: &commit_handle.utxos,
            worker_handle: &commit_handle,
            last_scanned: 100,
            reset_generation: 0,
            actor_state: &mut actor_state,
            persist_state: &mut persist_state,
            status_reader: commit_status_reader.as_ref(),
            active_poi_list_keys: &commit_active_poi_list_keys,
            selection: WalletPoiRefreshSelection::RequiredOrRecoverable,
            cancel: &commit_cancel,
        }
        .commit()
        .await
    });
    tokio::time::timeout(Duration::from_secs(2), started_rx)
        .await
        .expect("status request started")
        .expect("status request signal sent");

    assert_eq!(handle.advance_reset_generation().await, Some(1));
    release.send(()).expect("release status reader");
    let result = commit_task.await.expect("commit task");

    assert!(matches!(
        result,
        Err(WalletBackfillRejectReason::StaleGeneration {
            expected: 1,
            actual: 0
        })
    ));
    assert_eq!(readiness_rx.borrow().readiness(), &WalletReadiness::Syncing);
    assert_eq!(*handle.rev_rx.borrow(), 0);
    let snapshot = handle.utxos.read().await;
    assert!(snapshot[0].utxo.poi.statuses.is_empty());
    assert!(snapshot[0].utxo.poi.refreshed_at.is_none());
    assert_eq!(cache_store.state().store_calls, 0);

    cancel.cancel();
    drop(snapshot);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_scan_commit_does_not_perform_inline_poi_status_refresh() {
    // Architectural invariant: scan commit never awaits POI status I/O.
    // Remote/local status refresh is scheduled via PoiMaintenanceJob instead.
    const DEPLOYMENT_BLOCK: u64 = 14_737_691;
    const PAGE_FROM_BLOCK: u64 = 25_083_449;
    const CURRENT_BLOCK: u64 = 25_305_894;
    const TARGET_BLOCK: u64 = 25_537_418;
    let root_dir = temp_db_root("wallet-scan-commit-no-inline-poi");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    let mut cfg = wallet_config();
    cfg.cache_store = Some(cache_store.clone());
    cfg.start_block = Some(DEPLOYMENT_BLOCK);
    let (progress_tx, progress_rx) = watch::channel(None);
    cfg.progress_tx = Some(progress_tx);
    let wallet_utxo = test_wallet_utxo(CURRENT_BLOCK, 7);
    let (started_tx, _started_rx) = oneshot::channel();
    let (_release, release_rx) = oneshot::channel();
    // If scan commit still awaited status refresh, this would hang forever.
    let _blocking_reader = Arc::new(BlockingPoiStatusReader::new(started_tx, release_rx));
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
            backfill_sender: backfill_tx,
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        cfg.clone(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        PAGE_FROM_BLOCK.saturating_sub(1),
    )
    .await
    .expect("spawn wallet worker");
    let mut last_scanned = PAGE_FROM_BLOCK.saturating_sub(1);
    let mut persist_state = WalletPersistState::default();
    let mut live_metadata_flush =
        WalletLiveMetadataFlush::new(PAGE_FROM_BLOCK.saturating_sub(1), Instant::now());
    let (mut actor_state, _readiness_rx) =
        test_actor_state_for_handle(&handle, PAGE_FROM_BLOCK.saturating_sub(1));
    let job_token = WalletSyncToken::for_test(1, 1, 0, 1);
    assert!(actor_state.test_transition(|mut state| state.accept_target(job_token, TARGET_BLOCK)));
    let public_data_plane = test_public_data_plane(&db);
    let outcome = tokio::time::timeout(
        Duration::from_secs(2),
        WalletScanCommitRequest {
            cache_store: cache_store.as_ref(),
            cfg: &cfg,
            utxos: &handle.utxos,
            worker_handle: &handle,
            apply: indexed_delta_batch(
                PAGE_FROM_BLOCK,
                CURRENT_BLOCK,
                WalletLogDelta {
                    utxos: vec![wallet_utxo.utxo],
                    nullifiers: Vec::new(),
                    commitment_observations: Vec::new(),
                    sender_scan_outputs: Vec::new(),
                },
            ),
            job_token,
            current_reset_generation: 0,
            event_reset_generation: 0,
            actor_state: &mut actor_state,
            cancel: &cancel,
            last_scanned: &mut last_scanned,
            persist_state: &mut persist_state,
            live_metadata_flush: &mut live_metadata_flush,
            public_data_plane: &public_data_plane,
        }
        .commit(),
    )
    .await
    .expect("scan commit must not block on POI status I/O");

    assert!(matches!(
        outcome.result,
        WalletBackfillApplyResult::Committed { .. }
    ));
    assert!(outcome.changed);
    assert_eq!(handle.last_scanned(), Some(CURRENT_BLOCK));
    let observed_progress = progress_rx.borrow().expect("wallet scan progress");
    assert_eq!(observed_progress.start_block, DEPLOYMENT_BLOCK);
    assert_eq!(observed_progress.current_block, CURRENT_BLOCK);
    assert_eq!(observed_progress.target_block, TARGET_BLOCK);
    assert_eq!(observed_progress.percent(), 97);
    assert_eq!(
        observed_progress.source,
        Some(PublicScanSource::IndexedArtifacts)
    );

    let mut later_apply = indexed_delta_batch(
        CURRENT_BLOCK.saturating_add(1),
        TARGET_BLOCK,
        WalletLogDelta {
            utxos: Vec::new(),
            nullifiers: Vec::new(),
            commitment_observations: Vec::new(),
            sender_scan_outputs: Vec::new(),
        },
    );
    later_apply.rows.source = PublicScanSource::Rpc;
    let later_outcome = WalletScanCommitRequest {
        cache_store: cache_store.as_ref(),
        cfg: &cfg,
        utxos: &handle.utxos,
        worker_handle: &handle,
        apply: later_apply,
        job_token,
        current_reset_generation: 0,
        event_reset_generation: 0,
        actor_state: &mut actor_state,
        cancel: &cancel,
        last_scanned: &mut last_scanned,
        persist_state: &mut persist_state,
        live_metadata_flush: &mut live_metadata_flush,
        public_data_plane: &public_data_plane,
    }
    .commit()
    .await;
    assert!(matches!(
        later_outcome.result,
        WalletBackfillApplyResult::Committed { .. }
    ));
    let completed_progress = progress_rx
        .borrow()
        .expect("completed wallet scan progress");
    assert_eq!(completed_progress.start_block, DEPLOYMENT_BLOCK);
    assert_eq!(completed_progress.current_block, TARGET_BLOCK);
    assert_eq!(completed_progress.percent(), 100);
    assert_eq!(completed_progress.source, Some(PublicScanSource::Rpc));

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn readiness_transitions_recover_only_matching_persistence_failure() {
    let (mut state, readiness_rx) = test_actor_state_with_observation(10);
    let completed = WalletSyncToken::for_test(1, 1, 0, 1);
    state.test_transition(|mut state| {
        assert!(state.accept_target(completed, 10));
        assert!(state.complete_backfill_job(completed));
    });
    assert_eq!(readiness_rx.borrow().readiness(), &WalletReadiness::Ready);

    state.test_transition(|mut state| {
        state.poi_status_persist_failed(0, WalletPoiRefreshSelection::RequiredOrRecoverable);
    });
    assert_eq!(
        readiness_rx.borrow().readiness(),
        &WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
    );

    state.test_transition(|mut state| state.durable_reset_replay_commit_ok(1));
    assert_eq!(
        readiness_rx.borrow().readiness(),
        &WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
    );

    state.test_transition(|mut state| {
        state.durable_poi_status_commit_ok(0, WalletPoiRefreshSelection::RequiredOrRecoverable);
    });
    assert_eq!(readiness_rx.borrow().readiness(), &WalletReadiness::Ready);

    let pending = WalletSyncToken::for_test(1, 1, 0, 2);
    state.test_transition(|mut state| {
        assert!(state.accept_target(pending, 20));
        assert!(state.sync_progress_persist_failed(pending, 11, 20));
    });
    assert_eq!(
        readiness_rx.borrow().readiness(),
        &WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
    );
    state.test_transition(|mut state| {
        assert!(state.durable_sync_progress_commit_ok(pending, 11, 20));
    });
    assert_eq!(state.last_scanned(), 20);
    assert_eq!(readiness_rx.borrow().readiness(), &WalletReadiness::Syncing);

    let failed_job = WalletSyncToken::for_test(1, 1, 0, 3);
    state.test_transition(|mut state| {
        assert!(state.accept_target(failed_job, 30));
        assert!(state.fail_job_backfill_unavailable(failed_job));
    });
    assert_eq!(state.last_scanned(), 20);
    assert_eq!(
        readiness_rx.borrow().readiness(),
        &WalletReadiness::Failed(WalletReadinessError::BackfillUnavailable)
    );

    let replacement = WalletSyncToken::for_test(1, 1, 0, 4);
    state.test_transition(|mut state| {
        assert!(state.accept_target(replacement, 30));
        assert!(state.backfill_dispatch_admitted(replacement));
    });
    assert_eq!(readiness_rx.borrow().readiness(), &WalletReadiness::Syncing);
}

#[tokio::test]
async fn wallet_scan_exact_retry_clears_matching_persistence_failure() {
    let root_dir = temp_db_root("wallet-scan-commit-clears-persistence-failed");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    let mut cfg = wallet_config();
    cfg.cache_store = Some(cache_store.clone());
    let wallet_utxo = test_wallet_utxo(105, 7);
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
            backfill_sender: backfill_tx,
            public_data_plane: test_public_data_plane(&db),
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
    let mut last_scanned = 100;
    let mut persist_state = WalletPersistState::default();
    let mut live_metadata_flush = WalletLiveMetadataFlush::new(100, Instant::now());
    let (mut actor_state, mut readiness_rx) = test_actor_state_for_handle(&handle, 100);
    let job_token = WalletSyncToken::for_test(1, 1, 0, 1);
    actor_state.test_transition(|mut state| {
        assert!(state.accept_target(job_token, 110));
        assert!(state.sync_progress_persist_failed(job_token, 101, 110));
    });
    assert_eq!(
        readiness_rx.borrow_and_update().readiness(),
        &WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
    );
    assert_eq!(
        actor_state.test_readiness(),
        WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
    );
    let public_data_plane = test_public_data_plane(&db);
    let outcome = WalletScanCommitRequest {
        cache_store: cache_store.as_ref(),
        cfg: &cfg,
        utxos: &handle.utxos,
        worker_handle: &handle,
        apply: indexed_delta_batch(
            101,
            110,
            WalletLogDelta {
                utxos: vec![wallet_utxo.utxo],
                nullifiers: Vec::new(),
                commitment_observations: Vec::new(),
                sender_scan_outputs: Vec::new(),
            },
        ),
        job_token,
        current_reset_generation: 0,
        event_reset_generation: 0,
        actor_state: &mut actor_state,
        cancel: &cancel,
        last_scanned: &mut last_scanned,
        persist_state: &mut persist_state,
        live_metadata_flush: &mut live_metadata_flush,
        public_data_plane: &public_data_plane,
    }
    .commit()
    .await;

    assert!(matches!(
        outcome.result,
        WalletBackfillApplyResult::Committed { .. }
    ));
    assert_eq!(last_scanned, 110);
    assert_eq!(actor_state.last_scanned(), 110);
    assert!(
        readiness_rx
            .has_changed()
            .expect("observation publisher remains active")
    );
    let recovered_observation = readiness_rx.borrow().clone();
    let WalletViewState::Current(recovered_view) = recovered_observation.view() else {
        panic!("successful scan recovery must publish Current");
    };
    assert_eq!(recovered_view.last_scanned, 110);
    assert_eq!(recovered_view.revision, 1);
    assert_eq!(
        recovered_observation.readiness(),
        &WalletReadiness::Syncing,
        "successful scan must publish recovered readiness, not leave PersistenceFailed"
    );
    assert!(!matches!(
        actor_state.test_readiness(),
        WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
    ));

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_worker_marks_ready_after_queued_indexed_startup_delta() {
    let root_dir = temp_db_root("wallet-worker-indexed-startup-ready");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
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
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");

    let token = handle.mint_sync_token(0);
    let lease = assert_start_accepted(
        send_start_token(&backfill_tx, 200, token).await,
        token,
        100,
        200,
    );
    assert_eq!(
        lease
            .apply("test", indexed_delta_batch(101, 200, empty_delta()))
            .await,
        WalletBackfillApplyResult::Committed { committed_to: 200 }
    );
    assert_eq!(
        lease.finish("test", 200).await,
        WalletBackfillFinishResult::Ready { committed_to: 200 }
    );

    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.last_scanned() != Some(200) || handle.readiness() != WalletReadiness::Ready {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("indexed startup done marked ready");

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_worker_rejects_non_contiguous_log_batch() {
    let root_dir = temp_db_root("wallet-worker-log-gap");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
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
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");

    assert_eq!(
        send_apply(&handle, &backfill_tx, logs_apply(105, 110), 0).await,
        WalletBackfillApplyResult::Rejected {
            committed_to: 100,
            reason: WalletBackfillRejectReason::NonContiguous {
                expected_from: 101,
                actual_from: 105,
            },
        }
    );
    assert_eq!(handle.last_scanned(), Some(100));

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_worker_bounds_shared_log_payload_to_apply_range_and_target() {
    let root_dir = temp_db_root("wallet-worker-bounded-shared-log-payload");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let mut cfg = wallet_config();
    cfg.sync_to_block = Some(130);
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
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        cfg,
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        119,
    )
    .await
    .expect("spawn wallet worker");

    assert_eq!(
        send_apply(
            &handle,
            &backfill_tx,
            WalletScanApply::rows_from_log_batch(
                120,
                130,
                &logs_payload(100, 199),
                PublicScanSource::Rpc,
            )
            .expect("normalize shared log payload"),
            0,
        )
        .await,
        WalletBackfillApplyResult::Committed { committed_to: 130 }
    );
    assert_eq!(handle.last_scanned(), Some(130));
    assert_eq!(
        send_apply(
            &handle,
            &backfill_tx,
            WalletScanApply::rows_from_log_batch(
                131,
                199,
                &logs_payload(100, 199),
                PublicScanSource::Rpc,
            )
            .expect("normalize shared log payload"),
            0,
        )
        .await,
        WalletBackfillApplyResult::Rejected {
            committed_to: 130,
            reason: WalletBackfillRejectReason::TargetExceeded {
                target_block: 130,
                requested_to: 199,
            },
        }
    );
    assert_eq!(handle.last_scanned(), Some(130));

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_dropped_indexed_claim_response_retires_exact_accepted_job() {
    let root_dir = temp_db_root("wallet-dropped-indexed-claim-response");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
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
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");
    assert_eq!(
        send_target(&handle, &backfill_tx, 100, 0).await,
        WalletBackfillFinishResult::Ready { committed_to: 100 }
    );

    let (response, result_rx) = oneshot::channel();
    drop(result_rx);
    handle
        .indexed_catch_up_status_tx
        .send(WalletIndexedCatchUpCommand::Claim { response })
        .expect("send indexed claim with dropped response receiver");

    let lease = tokio::time::timeout(Duration::from_secs(1), handle.try_claim_indexed_catch_up())
        .await
        .expect("second indexed claim completed")
        .expect("dropped first claim must be retired");
    drop(lease);
    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.readiness() != WalletReadiness::Ready {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("indexed claim retirement republished readiness");

    let shutdown_lease = handle
        .try_claim_indexed_catch_up()
        .await
        .expect("indexed claim before shutdown");
    handle.set_indexed_catch_up(
        &shutdown_lease,
        WalletIndexedCatchUpStatus {
            source: WalletIndexedCatchUpSource::Squid,
            from_block: 101,
            target_block: 200,
        },
    );
    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.indexed_catch_up_rx.borrow().is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("indexed status published before shutdown");
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.readiness() != WalletReadiness::Shutdown
            || handle.indexed_catch_up_rx.borrow().is_some()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("shutdown cleared indexed status and active job");
    drop(shutdown_lease);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_handle_rejects_duplicate_indexed_catch_up_claim_until_cleared() {
    let root_dir = temp_db_root("wallet-worker-indexed-catch-up-lease");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
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
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");

    assert_eq!(
        send_target(&handle, &backfill_tx, 100, 0).await,
        WalletBackfillFinishResult::Ready { committed_to: 100 }
    );
    assert_eq!(handle.readiness(), WalletReadiness::Ready);

    let first_lease = handle
        .try_claim_indexed_catch_up()
        .await
        .expect("first indexed catch-up claim");
    assert_eq!(handle.readiness(), WalletReadiness::Syncing);
    assert!(handle.try_claim_indexed_catch_up().await.is_none());
    let first_status = WalletIndexedCatchUpStatus {
        source: WalletIndexedCatchUpSource::IndexedArtifacts,
        from_block: 101,
        target_block: 200,
    };
    handle.set_indexed_catch_up(&first_lease, first_status);
    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.indexed_catch_up_rx.borrow().is_none() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("indexed catch-up status published");
    assert_eq!(
        handle.indexed_catch_up_rx.borrow().as_ref(),
        Some(&first_status)
    );
    drop(first_lease);
    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.indexed_catch_up_rx.borrow().is_some() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("indexed catch-up status cleared");
    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.readiness() != WalletReadiness::Ready {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("indexed catch-up readiness restored");
    let second_lease = handle
        .try_claim_indexed_catch_up()
        .await
        .expect("second indexed catch-up claim");
    let second_status = WalletIndexedCatchUpStatus {
        source: WalletIndexedCatchUpSource::Squid,
        from_block: 201,
        target_block: 300,
    };
    handle.set_indexed_catch_up(&second_lease, second_status);
    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.indexed_catch_up_rx.borrow().as_ref() != Some(&second_status) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("second indexed catch-up status published");

    assert!(send_reset(&backfill_tx, 1, 50).await.committed());
    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.indexed_catch_up_rx.borrow().is_some() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("reset cleared indexed catch-up status");
    drop(second_lease);

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_worker_ignores_done_after_non_contiguous_indexed_delta() {
    let root_dir = temp_db_root("wallet-worker-indexed-tail-non-contiguous-done");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
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
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        150,
    )
    .await
    .expect("spawn wallet worker");

    assert_eq!(
        send_apply(
            &handle,
            &backfill_tx,
            indexed_delta_batch(101, 200, empty_delta()),
            0
        )
        .await,
        WalletBackfillApplyResult::Rejected {
            committed_to: 150,
            reason: WalletBackfillRejectReason::NonContiguous {
                expected_from: 151,
                actual_from: 101,
            },
        }
    );
    let done_token = handle.mint_sync_token(0);
    let _done_lease = assert_start_accepted(
        send_start_token(&backfill_tx, 200, done_token).await,
        done_token,
        150,
        200,
    );
    assert_eq!(handle.last_scanned(), Some(150));
    assert_eq!(
        send_apply(
            &handle,
            &backfill_tx,
            indexed_delta_batch(151, 151, empty_delta()),
            0
        )
        .await,
        WalletBackfillApplyResult::Committed { committed_to: 151 }
    );

    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.last_scanned() == Some(150) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("marker delta processed");
    assert_eq!(handle.last_scanned(), Some(151));

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_worker_ignores_stale_indexed_tail_events_after_reset() {
    let root_dir = temp_db_root("wallet-worker-indexed-tail-reset");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
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
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");

    assert_eq!(
        send_reset(&backfill_tx, 1, 80).await,
        WalletBackfillResetResult::accepted_committed(1, 79)
    );
    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.authority_reset_generation() != 1 || handle.last_scanned() != Some(79) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("reset applied");

    assert_eq!(
        send_apply(
            &handle,
            &backfill_tx,
            indexed_delta_batch(
                101,
                150,
                WalletLogDelta {
                    utxos: vec![test_wallet_utxo(120, 1).utxo],
                    nullifiers: Vec::new(),
                    commitment_observations: Vec::new(),
                    sender_scan_outputs: Vec::new(),
                },
            ),
            0,
        )
        .await,
        WalletBackfillApplyResult::Rejected {
            committed_to: 79,
            reason: WalletBackfillRejectReason::StaleGeneration {
                expected: 1,
                actual: 0,
            },
        }
    );
    assert!(matches!(
        send_target(&handle, &backfill_tx, 150, 0).await,
        WalletBackfillFinishResult::Rejected {
            reason: WalletBackfillRejectReason::StaleGeneration { .. },
            ..
        }
    ));
    assert!(matches!(
        send_apply(&handle, &backfill_tx, logs_apply(101, 150), 0).await,
        WalletBackfillApplyResult::Rejected {
            reason: WalletBackfillRejectReason::StaleGeneration { .. },
            ..
        }
    ));
    assert_eq!(handle.last_scanned(), Some(79));

    assert!(matches!(
        send_apply(
            &handle,
            &backfill_tx,
            indexed_delta_batch(101, 150, empty_delta()),
            1
        )
        .await,
        WalletBackfillApplyResult::Rejected {
            reason: WalletBackfillRejectReason::NonContiguous { .. },
            ..
        }
    ));
    let current_target_token = handle.mint_sync_token(1);
    let current_target_lease = assert_start_accepted(
        send_start_token(&backfill_tx, 150, current_target_token).await,
        current_target_token,
        79,
        150,
    );
    current_target_lease.retire("test").await;
    assert_eq!(
        send_apply(
            &handle,
            &backfill_tx,
            indexed_delta_batch(80, 90, empty_delta()),
            1,
        )
        .await,
        WalletBackfillApplyResult::Committed { committed_to: 90 }
    );
    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.last_scanned() != Some(90) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("current delta applied");

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_worker_requests_backfill_after_live_receiver_lag() {
    let root_dir = temp_db_root("wallet-worker-live-lag-gap");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let (live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, mut backfill_request_rx) = mpsc::channel(8);
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
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");
    for block in 101..=120 {
        live_tx
            .send(Arc::new(LogBatch {
                from_block: block,
                to_block: block,
                logs: Vec::new(),
                block_timestamps: HashMap::new(),
                to_block_hash: None,
                read_scope: test_public_scan_read_scope(),
            }))
            .expect("live receiver");
    }
    tokio::task::yield_now().await;
    assert_eq!(handle.last_scanned(), Some(100));

    assert_eq!(
        send_target(&handle, &backfill_tx, 100, 0).await,
        WalletBackfillFinishResult::Ready { committed_to: 100 }
    );
    let request = tokio::time::timeout(Duration::from_secs(1), backfill_request_rx.recv())
        .await
        .expect("live gap backfill requested")
        .expect("backfill request channel open");
    let BackfillRequest::Add {
        cache_key,
        from_block,
        to_block,
        follow_safe_head,
        driver,
        ..
    } = request
    else {
        panic!("expected add backfill request");
    };
    assert_eq!(cache_key, handle.cache_key.to_string());
    assert_eq!(from_block, 101);
    assert!(to_block > from_block);
    assert!(follow_safe_head);
    assert_eq!(driver.token().reset_generation(), 0);
    assert_eq!(handle.last_scanned(), Some(100));

    assert_eq!(
        driver.apply("test", logs_apply(from_block, to_block)).await,
        WalletBackfillApplyResult::Committed {
            committed_to: to_block
        }
    );
    assert_eq!(
        driver.finish("test", to_block).await,
        WalletBackfillFinishResult::Ready {
            committed_to: to_block
        }
    );
    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.last_scanned() != Some(to_block) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("recovery backfill applied");

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_private_mailbox_publishes_coherent_local_pending_spends() {
    let wallet_utxo = test_wallet_utxo(105, 7);
    let (root_dir, db, _cache_store, handle, cancel, _backfill_tx, _live_tx) =
        spawn_consumer_api_wallet("wallet-private-local-pending", vec![wallet_utxo.clone()]).await;
    let initial_revision = handle
        .current_snapshot()
        .expect("current wallet view")
        .revision;
    let tx_hash = FixedBytes::from([0x71; 32]);

    assert_eq!(
        handle
            .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), Some(tx_hash))
            .await,
        Ok(WalletPendingSpentMarkOutcome::Marked)
    );
    let marked = handle.current_snapshot().expect("marked wallet view");
    assert_eq!(marked.utxos.len(), 1);
    assert!(marked.revision > initial_revision);
    assert_eq!(marked.pending_overlay.local_pending_spent.len(), 1);
    let initial_block_timestamp = marked.pending_overlay.local_pending_spent[0]
        .block_timestamp
        .expect("submitted lock timestamp");
    assert_eq!(
        marked.pending_overlay.local_pending_spent[0].tx_hash,
        Some(tx_hash)
    );
    assert_eq!(
        handle
            .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), Some(tx_hash))
            .await,
        Ok(WalletPendingSpentMarkOutcome::AlreadyProtected)
    );
    assert_eq!(
        handle
            .current_snapshot()
            .expect("duplicate mark view")
            .revision,
        marked.revision
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        handle
            .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), Some(tx_hash))
            .await,
        Ok(WalletPendingSpentMarkOutcome::Marked),
        "a submitted same-hash lock renews its expiry timestamp"
    );
    let renewed = handle.current_snapshot().expect("renewed mark view");
    assert!(renewed.revision > marked.revision);
    assert!(
        renewed.pending_overlay.local_pending_spent[0]
            .block_timestamp
            .is_some_and(|timestamp| timestamp > initial_block_timestamp),
        "renewal must advance the stored expiry timestamp"
    );

    let missing = test_wallet_utxo(106, 99);
    assert_eq!(
        handle
            .mark_pending_spent_utxos(std::slice::from_ref(&missing.utxo), None)
            .await,
        Ok(WalletPendingSpentMarkOutcome::Marked),
        "the actor retains a latent intent until an identical input replays"
    );
    assert!(
        handle
            .current_snapshot()
            .expect("latent input view")
            .pending_overlay
            .local_pending_spent
            .iter()
            .any(|spent| spent.matches_local_utxo(&missing))
    );
    let mut stale_replacement = wallet_utxo.utxo.clone();
    stale_replacement.note.value = U256::from(999);
    assert_eq!(
        handle
            .mark_pending_spent_utxos(std::slice::from_ref(&stale_replacement), None)
            .await,
        Ok(WalletPendingSpentMarkOutcome::Marked),
        "a distinct latent identity may coexist at the same tree position"
    );
    assert_eq!(
        handle
            .mark_pending_spent_utxos(std::slice::from_ref(&missing.utxo), None)
            .await,
        Ok(WalletPendingSpentMarkOutcome::AlreadyProtected),
        "a duplicate latent intent does not refresh its timestamp"
    );
    assert!(
        handle
            .current_snapshot()
            .expect("replayed input view")
            .pending_overlay
            .local_pending_spent
            .iter()
            .any(|spent| spent.matches_local_utxo(&missing))
    );
    assert_eq!(handle.clear_all_local_pending_spent().await, Ok(true));
    assert_eq!(
        handle
            .current_snapshot()
            .expect("cleared wallet view")
            .pending_overlay
            .local_pending_spent,
        [] as [WalletPendingSpent; 0]
    );
    {
        let mut overlay = handle.pending_overlay.write().await;
        overlay.pending_spent.push(WalletPendingSpent::from_source(
            &wallet_utxo.utxo,
            &source(106, 0x72),
        ));
    }
    assert_eq!(
        handle
            .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), None)
            .await,
        Ok(WalletPendingSpentMarkOutcome::Marked),
        "the local intent remains latent while chain pending state protects the position"
    );
    handle.pending_overlay.write().await.pending_spent.clear();
    handle.utxos.write().await[0].spent = Some(source(107, 0x73));
    assert_eq!(
        handle
            .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), None)
            .await,
        Ok(WalletPendingSpentMarkOutcome::Marked),
        "a confirmed spend retires the local intent for the exact input"
    );
    assert_eq!(
        handle.pending_overlay.read().await.local_pending_spent,
        [] as [WalletPendingSpent; 0]
    );

    handle.retire_actor();
    assert_eq!(
        handle
            .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), None)
            .await,
        Err(WalletPrivateRequestError::Inactive)
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_private_mailbox_clears_mixed_visible_and_latent_spend_intents() {
    let visible = test_wallet_utxo(105, 7);
    let latent = test_wallet_utxo(106, 8);
    let (root_dir, db, _cache_store, handle, cancel, _backfill_tx, _live_tx) =
        spawn_consumer_api_wallet("wallet-private-mixed-pending", vec![visible.clone()]).await;

    assert_eq!(
        handle
            .mark_pending_spent_utxos(&[visible.utxo.clone(), latent.utxo.clone()], None)
            .await,
        Ok(WalletPendingSpentMarkOutcome::Marked)
    );
    let overlay = handle.pending_overlay.read().await.clone();
    assert_eq!(overlay.local_pending_spent.len(), 2);
    assert!(
        overlay
            .local_pending_spent
            .iter()
            .any(|spent| spent.matches_local_utxo(&visible))
    );
    assert!(
        overlay
            .local_pending_spent
            .iter()
            .any(|spent| spent.matches_local_utxo(&latent))
    );

    assert_eq!(handle.clear_all_local_pending_spent().await, Ok(true));
    handle.utxos.write().await.push(latent);
    assert_eq!(
        handle.pending_overlay.read().await.local_pending_spent,
        [] as [WalletPendingSpent; 0]
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test(start_paused = true)]
async fn wallet_private_mailbox_expires_local_spend_intent_without_other_commands() {
    let wallet_utxo = test_wallet_utxo(105, 7);
    let (root_dir, db, _cache_store, handle, cancel, _backfill_tx, _live_tx) =
        spawn_consumer_api_wallet("wallet-private-pending-expiry", vec![wallet_utxo.clone()]).await;
    assert_eq!(
        handle
            .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), None)
            .await,
        Ok(WalletPendingSpentMarkOutcome::Marked)
    );

    tokio::time::advance(LOCAL_PENDING_SPENT_TTL + Duration::from_secs(1)).await;
    for _ in 0..10 {
        if handle
            .pending_overlay
            .read()
            .await
            .local_pending_spent
            .is_empty()
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        handle.pending_overlay.read().await.local_pending_spent,
        [] as [WalletPendingSpent; 0]
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_private_mailbox_orders_mark_before_clear_across_command_kinds() {
    let wallet_utxo = test_wallet_utxo(105, 7);
    let (root_dir, db, _cache_store, handle, cancel, _backfill_tx, _live_tx) =
        spawn_consumer_api_wallet("wallet-private-command-order", vec![wallet_utxo.clone()]).await;
    let snapshot = handle.current_snapshot().expect("current wallet view");
    let revision = snapshot.revision;
    let held = Arc::clone(&handle.authority_lock).lock_owned().await;
    let (mark_reply, mark_result) = oneshot::channel();
    handle
        .private_request_tx
        .send(WalletPrivateRequest::MarkLocalPendingSpent {
            utxos: vec![wallet_utxo.utxo],
            tx_hash: None,
            reply: mark_reply,
        })
        .await
        .expect("queue mark request");
    let (clear_reply, clear_result) = oneshot::channel();
    handle
        .private_request_tx
        .send(WalletPrivateRequest::ClearLocalPendingSpent { reply: clear_reply })
        .await
        .expect("queue clear request");
    wait_for_sender_capacity(&handle.private_request_tx, 7, "ordered private commands").await;

    drop(held);
    assert_eq!(
        mark_result.await.expect("mark result"),
        Ok(WalletPendingSpentMarkOutcome::Marked)
    );
    assert_eq!(clear_result.await.expect("clear result"), Ok(true));
    let final_snapshot = handle.current_snapshot().expect("final wallet view");
    assert_eq!(
        final_snapshot.pending_overlay.local_pending_spent,
        [] as [WalletPendingSpent; 0]
    );
    assert_eq!(final_snapshot.revision, revision.wrapping_add(2));

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn pending_output_context_mailbox_stamps_deduplicates_and_fences_persistence() {
    let wallet_utxo = test_wallet_utxo(105, 7);
    let (root_dir, db, cache_store, handle, cancel, _backfill_tx, _live_tx) =
        spawn_consumer_api_wallet("wallet-private-pending-context", vec![wallet_utxo.clone()])
            .await;
    let cfg = wallet_config();
    let context = pending_output_context_intent_for_wallet_utxo(&wallet_utxo);
    let checkpoint = WalletMeta {
        last_scanned_block: 100,
        updated_at: 77,
        last_scanned_block_hash: Some([0xa5; 32]),
    };
    db.put_wallet_meta(&cfg.cache_key, &checkpoint)
        .expect("seed checkpoint metadata");
    let revision_before = handle
        .current_snapshot()
        .expect("current wallet view")
        .revision;

    assert_eq!(
        handle
            .create_pending_output_poi_contexts(vec![context.clone()])
            .await,
        Ok(1)
    );
    let persisted = db
        .get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &context.output_commitment,
        )
        .expect("read pending context")
        .expect("persisted pending context");
    assert_eq!(persisted.chain_id, cfg.chain.chain_id);
    assert_eq!(persisted.wallet_id, cfg.cache_key.as_str());
    assert!(persisted.created_at > 0);
    assert!(persisted.txid_merkleroot_index.is_none());
    assert!(persisted.source_operation_id.is_none());
    assert!(persisted.observation.is_none());
    assert_eq!(persisted.submitted_poi_list_keys, [] as [FixedBytes<32>; 0]);
    assert!(persisted.terminal_error.is_none());
    let retained_checkpoint = db
        .get_wallet_meta(&cfg.cache_key)
        .expect("read retained checkpoint")
        .expect("checkpoint present");
    assert_eq!(retained_checkpoint.last_scanned_block, 100);
    assert_eq!(retained_checkpoint.updated_at, 77);
    assert_eq!(
        retained_checkpoint.last_scanned_block_hash,
        Some([0xa5; 32])
    );
    assert_eq!(
        handle
            .current_snapshot()
            .expect("wallet view after context persistence")
            .revision,
        revision_before,
        "context persistence must not publish an unrelated wallet-view revision"
    );

    let mut advanced = persisted;
    advanced.observation = Some(PendingOutputPoiObservation {
        output_tree: 3,
        output_position: 4,
        tx_hash: FixedBytes::from([0x79; 32]),
        block_number: 120,
        block_timestamp: 1_700_000_120,
    });
    advanced.submitted_poi_list_keys = vec![FixedBytes::from([0x7a; 32])];
    db.put_pending_output_poi_context(&advanced)
        .expect("advance pending context state");
    assert_eq!(
        handle
            .create_pending_output_poi_contexts(vec![context.clone()])
            .await,
        Ok(0),
        "duplicate creation must not overwrite actor-owned workflow state"
    );
    let retained = db
        .get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &context.output_commitment,
        )
        .expect("read retained pending context")
        .expect("retained pending context");
    assert_eq!(retained.observation, advanced.observation);
    assert_eq!(
        retained.submitted_poi_list_keys,
        advanced.submitted_poi_list_keys
    );

    let mut first = context.clone();
    first.output_commitment = FixedBytes::from([0x81; 32]);
    first.output_npk = FixedBytes::from([0x91; 32]);
    let mut duplicate = first.clone();
    duplicate.output_npk = FixedBytes::from([0x92; 32]);
    assert_eq!(
        handle
            .create_pending_output_poi_contexts(vec![first.clone(), duplicate])
            .await,
        Ok(1),
        "the first matching commitment in one request must win"
    );
    let deduplicated = db
        .get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &first.output_commitment,
        )
        .expect("read deduplicated pending context")
        .expect("deduplicated pending context");
    assert_eq!(deduplicated.output_npk, first.output_npk);
    assert!(deduplicated.observation.is_none());
    assert_eq!(
        deduplicated.submitted_poi_list_keys,
        [] as [FixedBytes<32>; 0]
    );
    assert!(deduplicated.terminal_error.is_none());

    cache_store.fail_next_meta();
    let mut failed = context;
    failed.output_commitment = FixedBytes::from([0x82; 32]);
    assert_eq!(
        handle
            .create_pending_output_poi_contexts(vec![failed.clone()])
            .await,
        Err(WalletPrivateRequestError::PersistenceFailed)
    );
    assert!(
        db.get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &failed.output_commitment,
        )
        .expect("read failed pending context")
        .is_none()
    );
    assert_eq!(
        handle
            .current_snapshot()
            .expect("wallet view after failed persistence")
            .revision,
        revision_before
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn reset_pending_private_commands_prefer_active_then_retired_session_state() {
    let wallet_utxo = test_wallet_utxo(105, 7);
    let (root_dir, db, cache_store, handle, cancel, backfill_tx, _live_tx) =
        spawn_consumer_api_wallet(
            "wallet-private-reset-pending-retired",
            vec![wallet_utxo.clone()],
        )
        .await;
    let cfg = wallet_config();
    let context = pending_output_context_intent_for_wallet_utxo(&wallet_utxo);
    assert_eq!(
        handle
            .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), None)
            .await,
        Ok(WalletPendingSpentMarkOutcome::Marked)
    );
    let revision = *handle.rev_rx.borrow();

    cache_store.fail_next_store();
    assert_eq!(
        send_reset(&backfill_tx, 1, 80).await,
        WalletBackfillResetResult::accepted_pending(
            1,
            100,
            Some(WalletBackfillRejectReason::PersistenceFailed),
        )
    );
    assert!(matches!(
        handle.view_state(),
        WalletViewState::ResetPending { .. }
    ));
    assert_eq!(
        handle
            .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), None)
            .await,
        Ok(WalletPendingSpentMarkOutcome::AlreadyProtected)
    );
    assert_eq!(handle.clear_all_local_pending_spent().await, Ok(true));
    assert_eq!(
        handle
            .create_pending_output_poi_contexts(vec![context.clone()])
            .await,
        Err(WalletPrivateRequestError::ResetPending)
    );
    let revision_after_clear = *handle.rev_rx.borrow();
    assert!(revision_after_clear > revision);
    assert_eq!(
        handle.pending_overlay.read().await.local_pending_spent,
        [] as [WalletPendingSpent; 0]
    );
    assert!(
        db.get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &context.output_commitment,
        )
        .expect("read reset-pending context")
        .is_none()
    );

    handle.retire_actor();
    cancel.cancel();
    assert_eq!(
        handle.view_state().inactive_reason(),
        Some(WalletInactiveReason::Retired)
    );
    assert_private_command_error(
        &handle,
        &wallet_utxo,
        context.clone(),
        WalletPrivateRequestError::Inactive,
    )
    .await;
    assert_eq!(*handle.rev_rx.borrow(), revision_after_clear);
    assert_eq!(
        handle.pending_overlay.read().await.local_pending_spent,
        [] as [WalletPendingSpent; 0]
    );
    assert!(
        db.get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &context.output_commitment,
        )
        .expect("read retired context")
        .is_none()
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn reset_pending_private_commands_prefer_worker_shutdown_state() {
    let wallet_utxo = test_wallet_utxo(105, 7);
    let (root_dir, db, cache_store, handle, cancel, backfill_tx, _live_tx) =
        spawn_consumer_api_wallet(
            "wallet-private-reset-pending-shutdown",
            vec![wallet_utxo.clone()],
        )
        .await;
    let cfg = wallet_config();
    let context = pending_output_context_intent_for_wallet_utxo(&wallet_utxo);
    assert_eq!(
        handle
            .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), None)
            .await,
        Ok(WalletPendingSpentMarkOutcome::Marked)
    );
    let revision = *handle.rev_rx.borrow();

    cache_store.fail_next_store();
    assert!(matches!(
        send_reset(&backfill_tx, 1, 80).await,
        WalletBackfillResetResult::Accepted {
            rewind: WalletResetRewindStatus::Pending { .. },
            ..
        }
    ));
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.view_state().inactive_reason() != Some(WalletInactiveReason::Shutdown) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("worker publishes terminal shutdown view");

    assert_private_command_error(
        &handle,
        &wallet_utxo,
        context.clone(),
        WalletPrivateRequestError::Inactive,
    )
    .await;
    assert_private_command_state_unchanged(&handle, revision).await;
    assert!(
        db.get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &context.output_commitment,
        )
        .expect("read shutdown context")
        .is_none()
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_private_mailbox_rejects_queued_stale_stamps() {
    let wallet_utxo = test_wallet_utxo(105, 7);
    let (root_dir, db, _cache_store, handle, cancel, _backfill_tx, _live_tx) =
        spawn_consumer_api_wallet("wallet-private-stale-queue", vec![wallet_utxo.clone()]).await;
    let cfg = wallet_config();
    let context = pending_output_context_intent_for_wallet_utxo(&wallet_utxo);
    let (context_reply, context_result) = oneshot::channel();
    handle
        .private_request_tx
        .send(WalletPrivateRequest::CreatePendingOutputContexts {
            ticket: WalletPrivateViewTicket::Current {
                reset_generation: 1,
                last_scanned: 100,
            },
            contexts: vec![context.clone()],
            reply: context_reply,
        })
        .await
        .expect("queue stale pending-context request");
    assert_eq!(
        context_result
            .await
            .expect("stale pending-context response"),
        Err(WalletPrivateRequestError::StaleView)
    );
    assert!(
        db.get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &context.output_commitment,
        )
        .expect("read stale pending context")
        .is_none()
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn dequeued_clear_all_rejects_shutdown_without_mutation() {
    let wallet_utxo = test_wallet_utxo(105, 7);
    let (root_dir, db, _cache_store, handle, cancel, _backfill_tx, _live_tx) =
        spawn_consumer_api_wallet("wallet-private-clear-shutdown", vec![wallet_utxo.clone()]).await;
    assert_eq!(
        handle
            .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), None)
            .await,
        Ok(WalletPendingSpentMarkOutcome::Marked)
    );
    let revision_before = handle
        .current_snapshot()
        .expect("marked wallet view")
        .revision;
    let held = Arc::clone(&handle.authority_lock).lock_owned().await;
    let (clear_reply, clear_result) = oneshot::channel();
    handle
        .private_request_tx
        .send(WalletPrivateRequest::ClearLocalPendingSpent { reply: clear_reply })
        .await
        .expect("queue clear-all request");
    wait_for_sender_capacity(&handle.private_request_tx, 8, "dequeued clear-all").await;

    cancel.cancel();
    drop(held);
    assert_eq!(
        clear_result.await.expect("clear-all result"),
        Err(WalletPrivateRequestError::Inactive)
    );
    assert_eq!(
        handle.view_state().inactive_reason(),
        Some(WalletInactiveReason::Shutdown)
    );
    assert_eq!(*handle.rev_rx.borrow(), revision_before);
    assert_eq!(
        handle
            .pending_overlay
            .read()
            .await
            .local_pending_spent
            .len(),
        1
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn dequeued_pending_context_rejects_retirement_without_persistence() {
    let wallet_utxo = test_wallet_utxo(105, 7);
    let (root_dir, db, _cache_store, handle, cancel, _backfill_tx, _live_tx) =
        spawn_consumer_api_wallet(
            "wallet-private-context-retirement",
            vec![wallet_utxo.clone()],
        )
        .await;
    let cfg = wallet_config();
    let context = pending_output_context_intent_for_wallet_utxo(&wallet_utxo);
    let held = Arc::clone(&handle.authority_lock).lock_owned().await;
    let snapshot = handle
        .current_snapshot()
        .expect("current pending-context view");
    let (context_reply, context_result) = oneshot::channel();
    handle
        .private_request_tx
        .send(WalletPrivateRequest::CreatePendingOutputContexts {
            ticket: WalletPrivateViewTicket::Current {
                reset_generation: snapshot.reset_generation,
                last_scanned: snapshot.last_scanned,
            },
            contexts: vec![context],
            reply: context_reply,
        })
        .await
        .expect("queue pending-context request");
    wait_for_sender_capacity(&handle.private_request_tx, 8, "dequeued retirement context").await;

    handle.retire_actor();
    drop(held);
    assert_eq!(
        context_result.await.expect("pending-context result"),
        Err(WalletPrivateRequestError::Inactive)
    );
    assert!(
        db.list_pending_output_poi_contexts(cfg.chain.chain_id, &cfg.cache_key)
            .expect("list pending contexts")
            .is_empty()
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn current_mailbox_requests_queued_behind_reset_are_rejected() {
    let wallet_utxo = test_wallet_utxo(105, 7);
    let (root_dir, db, _cache_store, handle, cancel, backfill_tx, _live_tx) =
        spawn_consumer_api_wallet("wallet-private-queued-reset", vec![wallet_utxo.clone()]).await;
    let cfg = wallet_config();
    let context = pending_output_context_intent_for_wallet_utxo(&wallet_utxo);
    let context_commitment = context.output_commitment;
    let held = Arc::clone(&handle.authority_lock).lock_owned().await;
    let (reset_response, reset_result) = oneshot::channel();
    backfill_tx
        .send(BackfillEvent::Reset {
            token: test_reset_token(1),
            from_block: 80,
            replay_plan: WalletResetReplayPlan::new(0, 0, true),
            response: reset_response,
        })
        .await
        .expect("queue reset");
    wait_for_sender_capacity(&backfill_tx, 8, "dequeued reset").await;

    let mark_handle = handle.clone();
    let mark_utxo = wallet_utxo.utxo.clone();
    let mark = tokio::spawn(async move {
        mark_handle
            .mark_pending_spent_utxos(std::slice::from_ref(&mark_utxo), None)
            .await
    });
    let context_handle = handle.clone();
    let create = tokio::spawn(async move {
        context_handle
            .create_pending_output_poi_contexts(vec![context])
            .await
    });
    wait_for_sender_capacity(&handle.private_request_tx, 6, "queued reset commands").await;

    drop(held);
    assert_eq!(
        reset_result
            .await
            .expect("reset response")
            .reset_generation(),
        Some(1)
    );
    assert!(matches!(
        mark.await.expect("pending-spend task"),
        Ok(WalletPendingSpentMarkOutcome::Marked)
    ));
    assert!(matches!(
        create.await.expect("pending-context task"),
        Err(WalletPrivateRequestError::ResetPending | WalletPrivateRequestError::StaleView)
    ));
    assert!(
        db.get_pending_output_poi_context(cfg.chain.chain_id, &cfg.cache_key, &context_commitment,)
            .expect("read reset-fenced pending context")
            .is_none()
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

fn wallet_config() -> WalletConfig {
    WalletConfig {
        chain: ChainKey {
            chain_id: 1,
            contract: Address::ZERO,
        },
        cache_key: WalletCacheKey::from_opaque_bytes(b"test")
            .expect("non-empty test wallet cache key"),
        start_block: Some(0),
        sync_to_block: None,
        quick_sync_endpoint: None,
        scan_keys: ViewingKeyData {
            viewing_private_key: [0u8; 32],
            viewing_public_key: [0u8; 32],
            nullifying_key: U256::ZERO,
            master_public_key: U256::ZERO,
        },
        spending_public_key: None,
        progress_tx: None,
        cache_store: None,
        poi_recovery_prover: None,
        use_indexed_wallet_catch_up: true,
    }
}

fn source(block_number: u64, byte: u8) -> UtxoSource {
    UtxoSource {
        tx_hash: FixedBytes::from([byte; 32]),
        block_number,
        block_timestamp: 1_700_000_000 + block_number,
    }
}

fn test_wallet_utxo(block_number: u64, position: u64) -> WalletUtxo {
    test_wallet_utxo_with_random(block_number, position, [0; 16])
}

fn test_wallet_utxo_with_random(block_number: u64, position: u64, random: [u8; 16]) -> WalletUtxo {
    WalletUtxo::new(Utxo::new(
        Note {
            token_hash: U256::from(1),
            value: U256::from(10),
            random,
            npk: U256::from(u64::from(random[0]) + 2),
        },
        2,
        position,
        source(block_number, block_number as u8),
        UtxoCommitmentKind::Transact,
    ))
}

fn pending_output_context_for_wallet_utxo(
    cfg: &WalletConfig,
    wallet_utxo: &WalletUtxo,
) -> PendingOutputPoiContextRecord {
    PendingOutputPoiContextRecord {
        chain_id: cfg.chain.chain_id,
        wallet_id: cfg.cache_key.to_string(),
        txid_version: DEFAULT_TXID_VERSION.to_string(),
        output_commitment: wallet_utxo.utxo.poi.commitment,
        output_npk: wallet_utxo.utxo.poi.npk,
        utxo_tree_in: u64::from(wallet_utxo.utxo.tree),
        railgun_txid: U256::from(7),
        txid_merkleroot_index: None,
        pre_transaction_pois_per_txid_leaf_per_list: BTreeMap::new(),
        required_poi_list_keys: Vec::new(),
        output_role: PendingOutputPoiRole::Recipient,
        created_at: 123,
        source_operation_id: None,
        observation: None,
        submitted_poi_list_keys: Vec::new(),
        terminal_error: None,
    }
}

fn current_pending_proof_map(list_key: FixedBytes<32>) -> crate::wallet::PreTransactionPoiMap {
    let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../../core/tests/fixtures/ppoi_3x3.json"
    ))
    .expect("current proof fixture");
    let proof = serde_json::from_value(fixture["pre_tx_poi"].clone()).expect("current proof");
    let leaf = serde_json::from_value(fixture["public_context"]["txid_leaf_hash"].clone())
        .expect("current proof leaf");
    BTreeMap::from([(list_key, BTreeMap::from([(leaf, proof)]))])
}

fn observed_external_pending_output_context(
    cfg: &WalletConfig,
    output: &WalletUtxo,
    list_key: FixedBytes<32>,
    observed_source: &UtxoSource,
) -> PendingOutputPoiContextRecord {
    let mut context = pending_output_context_for_wallet_utxo(cfg, output);
    context.pre_transaction_pois_per_txid_leaf_per_list =
        BTreeMap::from([(list_key, BTreeMap::new())]);
    context.required_poi_list_keys = vec![list_key];
    context.observation = Some(PendingOutputPoiObservation {
        output_tree: u64::from(output.utxo.tree),
        output_position: output.utxo.position,
        tx_hash: observed_source.tx_hash,
        block_number: observed_source.block_number,
        block_timestamp: observed_source.block_timestamp,
    });
    context.submitted_poi_list_keys = vec![list_key];
    context.terminal_error = Some("stale observation terminal state".to_string());
    context
}

fn output_poi_recovery_for_pending_context(
    context: &PendingOutputPoiContextRecord,
    status: OutputPoiRecoveryStatus,
) -> OutputPoiRecoveryRecord {
    OutputPoiRecoveryRecord {
        chain_id: context.chain_id,
        wallet_id: context.wallet_id.clone(),
        output_commitment: context.output_commitment,
        source_tx_hash: context
            .observation
            .as_ref()
            .expect("observed pending context")
            .tx_hash,
        tx_input: None,
        status,
        created_at: 123,
        updated_at: 124,
        last_detection_at: None,
        last_submission_at: Some(124),
        next_retry_at: Some(125),
        attempt_count: 1,
        last_error: None,
    }
}

fn pending_output_context_intent_for_wallet_utxo(
    wallet_utxo: &WalletUtxo,
) -> PendingOutputPoiContextIntent {
    PendingOutputPoiContextIntent {
        txid_version: DEFAULT_TXID_VERSION.to_string(),
        output_commitment: wallet_utxo.utxo.poi.commitment,
        output_npk: wallet_utxo.utxo.poi.npk,
        utxo_tree_in: u64::from(wallet_utxo.utxo.tree),
        railgun_txid: U256::from(7),
        pre_transaction_pois_per_txid_leaf_per_list: BTreeMap::new(),
        required_poi_list_keys: Vec::new(),
        output_role: PendingOutputPoiRole::Recipient,
    }
}

async fn assert_private_command_error(
    handle: &WalletHandle,
    wallet_utxo: &WalletUtxo,
    context: PendingOutputPoiContextIntent,
    expected: WalletPrivateRequestError,
) {
    assert_eq!(
        handle
            .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), None)
            .await,
        Err(expected)
    );
    assert_eq!(handle.clear_all_local_pending_spent().await, Err(expected));
    assert_eq!(
        handle
            .create_pending_output_poi_contexts(vec![context])
            .await,
        Err(expected)
    );
}

async fn assert_private_command_state_unchanged(handle: &WalletHandle, revision: u64) {
    assert_eq!(*handle.rev_rx.borrow(), revision);
    assert_eq!(
        handle
            .pending_overlay
            .read()
            .await
            .local_pending_spent
            .len(),
        1
    );
}

async fn spawn_consumer_api_wallet(
    name: &str,
    initial_utxos: Vec<WalletUtxo>,
) -> (
    std::path::PathBuf,
    Arc<DbStore>,
    Arc<FailingCacheStore>,
    WalletHandle,
    CancellationToken,
    mpsc::Sender<BackfillEvent>,
    broadcast::Sender<SharedLogBatch>,
) {
    let root_dir = temp_db_root(name);
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    let mut cfg = wallet_config();
    cfg.cache_store = Some(cache_store.clone());
    cfg.sync_to_block = Some(100);
    cfg.use_indexed_wallet_catch_up = false;
    let (live_tx, live_rx) = broadcast::channel(8);
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
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        cfg,
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        initial_utxos,
        100,
    )
    .await
    .expect("spawn wallet worker");
    (
        root_dir,
        db,
        cache_store,
        handle,
        cancel,
        backfill_tx,
        live_tx,
    )
}

async fn wait_for_sender_capacity<T>(sender: &mpsc::Sender<T>, expected: usize, label: &str) {
    let reached = tokio::time::timeout(Duration::from_secs(1), async {
        while sender.capacity() != expected {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        reached.is_ok(),
        "{label}: expected sender capacity {expected}, got {}",
        sender.capacity()
    );
}

fn temp_db_root(name: &str) -> std::path::PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("sync-service-{name}-{unique}"));
    fs::create_dir_all(&dir).expect("create temp db dir");
    dir
}
