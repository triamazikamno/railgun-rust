use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, mpsc as std_mpsc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::primitives::{Address, FixedBytes, U256, hex};
use alloy::sol_types::{SolEvent, SolValue};
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
    IndexedWalletCatchUpOutcome, WalletShortStartupPlan, WalletSyncContext,
    await_live_log_task_shutdown, wait_for_startup_sync_target, wait_for_wallet_ready,
};
use super::workers::{
    ForestStallTracker, HEAD_READ_STAGGER, INDEXED_TAIL_FALLBACK_COOLDOWN, INITIAL_HEAD_DEADLINE,
    IndexedForestSources, IndexedForestTrigger, WalletBackfillSlot,
    drain_pending_backfill_requests, pending_tip_from_block, pending_tip_provider_covers_target,
    read_head_bounded, reconcile_retained_acquisition, spawn_head_poller,
    wallet_lag_fallback_state_for_test,
};
use super::{
    ChainError, ChainPublicDataPlane, ChainService, CommitmentBatch, ForestMetaCheck,
    ForestReorgDecision, GeneratedCommitmentBatch, IndexedWalletArtifactPageOutcome,
    IndexedWalletArtifactSession, IndexedWalletCatchUpSourceOrder, IndexedWalletPageKind,
    LogRangeLimit, MerkleForestDbExt, Nullified, Nullifiers, PublicCoverageAnswer,
    PublicDataPlaneDiagnosticKind, PublicDataPlaneError, PublicPoiCorpusKey, PublicScanRange,
    PublicScanRowsAnswer, PublicScanSource, RailgunLegacyShieldEvents, Shield, Transact,
    TransportError, WalletIndexedCatchUpStatusGuard, WalletStartupSyncError, WalletWorkerServices,
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

const SYNTHETIC_BACKFILL_JOB_ID: u64 = u64::MAX;

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
            relay_adapt_contract: None,
            relay_adapt_7702_contract: Address::ZERO,
            relay_adapt_7702_delegates: &[],
            relay_adapt_history: &[],
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
        archive_rpc_http_client: None,
        block_time: Duration::from_secs(12),
        finality_depth: 0,
        http_client: reqwest::Client::new(),
        progress_tx: None,
        poi_submission_routes: None,
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
                    WalletSyncContext {
                        cfg: &cfg,
                        start_block: 0,
                        handle: &handle,
                        backfill_sender: &sender,
                    },
                    last_scanned,
                    safe_head,
                    &cancel,
                    source_order,
                    true,
                    crate::types::WalletSchedulableProgress {
                        last_scanned,
                        reset_generation: 0,
                    },
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
            txid_public_cache_task: std::sync::Mutex::new(None),
            amount_statistics: crate::amount_statistics::ChainAmountStatistics::default(),
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

static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_db_root(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let counter = TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("sync-service-{name}-{unique}-{counter}"))
}

const SQUID_EMPTY_COMMITMENTS: &str = r#"{"data":{"commitments":[]}}"#;

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

const fn test_forest_lag(far_behind: bool) -> ForestLag {
    ForestLag {
        estimated_requests: if far_behind { 100 } else { 2 },
        far_behind,
    }
}

mod forest_fixture;
mod http_servers;
mod log_capture;
mod rpc_logs;
mod wallet_artifacts;

#[allow(clippy::wildcard_imports)]
use forest_fixture::*;
#[allow(clippy::wildcard_imports)]
use http_servers::*;
#[allow(clippy::wildcard_imports)]
use log_capture::*;
#[allow(clippy::wildcard_imports)]
use rpc_logs::*;
#[allow(clippy::wildcard_imports)]
use wallet_artifacts::*;

mod backfill_cursor;
mod indexed_catch_up;
mod live_forest;
mod public_scan;
mod rpc_reads;
mod startup_forest;
mod sync_targets;
mod wallet_lifecycle;
mod wallet_startup;
