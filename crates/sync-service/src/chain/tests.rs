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
    // A blocked path holds its body, not its headers, so the attempt outlives
    // the gateway response-header time limit.
    if let Some(block) = block.as_ref()
        && block.path == path
    {
        stream.flush().expect("flush blocked path headers");
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
    wallet_artifact_source_for_chunks(
        scope,
        chunks,
        block_manifest,
        request_count,
        omit_last_chunk,
    )
}

fn wallet_artifact_source_for_chunks(
    scope: &ChainScope,
    chunks: Vec<(IndexedArtifactDescriptor, Cid, Vec<u8>)>,
    block_manifest: bool,
    request_count: usize,
    omit_last_chunk: bool,
) -> (TestArtifactSource, Option<PathServerBlockControl>) {
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let start = chunks.first().expect("first chunk").0.range.start;
    let end = chunks.last().expect("last chunk").0.range.end;
    let chunk_descriptors = chunks
        .iter()
        .map(|(descriptor, _, _)| descriptor.clone())
        .collect::<Vec<_>>();
    let row_count = chunk_descriptors.iter().map(|chunk| chunk.row_count).sum();
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
        row_count,
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

const SQUID_HEIGHT_300: &str = r#"{"data":{"squidStatus":{"height":"300"}}}"#;

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

const fn test_forest_lag(far_behind: bool) -> ForestLag {
    ForestLag {
        estimated_requests: if far_behind { 100 } else { 2 },
        far_behind,
    }
}

mod backfill_cursor;
mod indexed_catch_up;
mod live_forest;
mod public_scan;
mod rpc_reads;
mod startup_forest;
mod sync_targets;
mod wallet_lifecycle;
mod wallet_startup;
