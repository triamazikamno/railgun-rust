use super::{
    CalldataRecoveryBuildRequest, DEFAULT_TXID_VERSION, EVM_CHAIN_TYPE, ExpectedPoiListState,
    ExpectedPoiStatus, ExpectedRecordState, ExpectedWalletOutput, LOCAL_PENDING_SPENT_TTL,
    LocalPoiMerkleProofSource, LocalPoiStatusReader, MatchingPendingOutputPoiContextDisposition,
    OUTPUT_POI_RECOVERY_PROOF_FAILURE_RETRY_AFTER, OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
    OutputPoiRecoveryRequest, OutputRecoveryRemoteProofSource, OwnedPoiPrivateDelta,
    PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER, PendingOutputPoiSubmissionPredicate,
    PendingOutputPoiSubmitter, PoiPrivateApplyOutcome, PoiStatusReader,
    PublicCacheTxidRecoveryRequest, WALLET_METADATA_LIVE_FLUSH_BLOCKS,
    WALLET_METADATA_LIVE_FLUSH_INTERVAL, WALLET_POI_RECOVERABLE_REFRESH_AFTER,
    WALLET_POI_STATUS_BATCH_SIZE, WalletActorLifecycleCell, WalletHandle, WalletLiveMetadataFlush,
    WalletNullifierIndex, WalletPendingOverlay, WalletPendingSpent, WalletPersistState,
    WalletPoiRefreshRequest, WalletPoiRefreshSelection, WalletPoiRuntime,
    WalletPrivateMutationAuthority, WalletPrivatePoiClients, WalletProgressPersist,
    WalletViewState, apply_owned_poi_private_delta_on_actor, apply_wallet_delta_to_vec,
    apply_wallet_delta_to_vec_with_outcome, build_output_poi_recovery_chunk,
    build_output_poi_recovery_chunk_from_calldata, decode_railgun_transactions,
    discard_pending_output_poi_contexts_for_spent_outputs, extend_pending_output_poi_context,
    force_resubmit_matching_pending_output_pois,
    force_resubmit_matching_pending_output_pois_authorized, install_tailed_poi_cache_if_current,
    matching_pending_output_poi_context_disposition, newly_recoverable_output_poi_list_keys,
    now_epoch_secs, output_poi_recovery_candidates, output_poi_recovery_proof_retry_after,
    output_poi_recovery_retry_allowed_for_lists, output_start_global_position,
    pending_output_poi_context_fingerprint, pending_output_poi_context_matches_wallet_utxo,
    pending_output_poi_submit_identity, pending_overlay_from_delta,
    preflight_and_remote_submit_pending_output_poi, preflight_local_output_poi_input_proofs,
    process_pending_output_poi_observations, process_pending_output_poi_observations_authorized,
    process_pending_output_poi_observations_inner, recoverable_output_poi_list_keys,
    recovered_output_txid_data_from_public_cache, recovery_input_merkle_tree_for_root,
    refresh_wallet_poi_statuses_remote_authorized, refresh_wallet_poi_statuses_selected,
    rewind_wallet_utxos, spent_source_for_utxo, sync_live_poi_event_tail,
    verify_submitted_pending_output_pois, verify_submitted_pending_output_pois_authorized,
    verify_submitted_pending_output_pois_authorized_with_projection,
    verify_submitted_pending_output_pois_with_config,
    verify_submitted_pending_output_pois_with_config_authorized, wallet_poi_status_client,
    wallet_poi_status_refresh_needed, wallet_poi_status_refresh_needed_for_selection,
};
use crate::chain::{
    ChainPublicDataPlane, PublicPoiCorpusKey, PublicTxidCacheKey as DataPlanePublicTxidCacheKey,
    PublicTxidLatestValidated as DataPlanePublicTxidLatestValidated, PublicTxidProofRequest,
    PublicTxidProofTarget, PublicTxidSyncRequest,
};
use crate::indexed_artifacts::{ChainScope, ChainType};
use crate::types::{
    ChainKey, GlobalPoiPolicy, PoiArtifactManifestSource, PoiArtifactSourceConfig,
    PoiProxyFallback, WalletCacheStore, WalletConfig, WalletCurrentSnapshot, WalletPrivateCommit,
    WalletReadiness, WalletSchedulableProgress, WalletSyncActorStateCommit,
};
use alloy::hex;
use alloy::primitives::{Address, Bytes, FixedBytes, U256};
use alloy::sol_types::SolCall;
use alloy::uint;
use async_trait::async_trait;
use broadcaster_core::contracts::railgun::{
    BoundParams, Call, CommitmentPreimage, RelayAdapt7702ActionData, SnarkProof, Transaction,
    executeCall,
};
use broadcaster_core::crypto::railgun::ViewingKeyData;
use broadcaster_core::notes::Note;
use broadcaster_core::query_rpc_pool::QueryRpcPool;
use broadcaster_core::transact::{
    MERKLE_ZERO_VALUE, PreTxPoi, SnarkJsProof, railgun_txid_leaf_hash,
    railgun_txid_leaf_hash_with_output_start,
};
use broadcaster_core::tree::TREE_LEAF_COUNT;
use local_db::{
    DbConfig, DbStore, OutputPoiRecoveryAction, OutputPoiRecoveryRecord, OutputPoiRecoveryStatus,
    PendingOutputPoiContextRecord, PendingOutputPoiRole, WalletMeta, WalletSyncActorStateRecord,
};
use merkletree::tree::{DenseMerkleTree, MerkleForest, MerkleTreeUpdate};
use poi::cache::{PoiCache, PoiCacheIdentity};
use poi::error::PoiError;
use poi::poi::{
    BlindedCommitmentData, PoiEventType, PoiMerkleProof, PoiRpcClient, SingleCommitmentProofContext,
};
use railgun_wallet::prover::ProverError;
use railgun_wallet::scan::{CommitmentObservation, SpentNullifier, WalletLogDelta};
use railgun_wallet::tx::{PoiMerkleProofSource, PreTransactionPoiError};
use railgun_wallet::wallet_cache::WalletCacheError;
use railgun_wallet::{
    NoteCiphertext, PoiStatus, Utxo, UtxoCommitmentKind, UtxoPoiMetadata, UtxoSource, WalletUtxo,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{RwLock, mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;
use url::Url;

static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_db_root() -> PathBuf {
    let dir = std::env::temp_dir().join("railgun-broadcaster-sync-service-tests");
    fs::create_dir_all(&dir).expect("create temp db dir");
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let counter = TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    dir.join(format!("db-{pid}-{nanos}-{counter}"))
}

fn source(byte: u8) -> UtxoSource {
    UtxoSource {
        tx_hash: FixedBytes::from([byte; 32]),
        block_number: u64::from(byte),
        block_timestamp: 1_700_000_000 + u64::from(byte),
    }
}

fn wallet_config(nullifying_key: U256) -> WalletConfig {
    WalletConfig {
        chain: ChainKey {
            chain_id: 1,
            contract: Address::ZERO,
        },
        cache_key: "test".to_string(),
        start_block: Some(0),
        sync_to_block: None,
        quick_sync_endpoint: None,
        scan_keys: ViewingKeyData {
            viewing_private_key: [0u8; 32],
            viewing_public_key: [0u8; 32],
            nullifying_key,
            master_public_key: U256::ZERO,
        },
        spending_public_key: None,
        progress_tx: None,
        cache_store: None,
        poi_recovery_prover: None,
        use_indexed_wallet_catch_up: true,
    }
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

fn test_artifact_poi_runtime() -> WalletPoiRuntime {
    WalletPoiRuntime::from_policy(
        &GlobalPoiPolicy::IndexedArtifacts {
            artifact_source: test_poi_artifact_source_config(),
            rpc_url: Url::parse("http://127.0.0.1:1").expect("POI RPC URL"),
            wallet_read_fallback: PoiProxyFallback::Disabled,
        },
        None,
    )
}

fn test_artifact_poi_runtime_with_fallback(rpc_url: Url) -> WalletPoiRuntime {
    WalletPoiRuntime::from_policy(
        &GlobalPoiPolicy::IndexedArtifacts {
            artifact_source: test_poi_artifact_source_config(),
            rpc_url,
            wallet_read_fallback: PoiProxyFallback::OnCorpusUnavailable,
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
            .with_poi_rpc_url(Url::parse("http://127.0.0.1:1").expect("POI RPC URL")),
        ),
    )
}

async fn seed_data_plane_poi_cache(
    public_data_plane: &ChainPublicDataPlane,
    chain_id: u64,
    list_key: FixedBytes<32>,
    cache: PoiCache,
) {
    let corpus = public_data_plane
        .ensure_poi_corpus(PublicPoiCorpusKey::wallet_default(chain_id))
        .await
        .expect("POI corpus");
    corpus.local_caches().write().await.insert(list_key, cache);
}

fn test_wallet_utxo(position: u64) -> WalletUtxo {
    test_wallet_utxo_with_kind(position, UtxoCommitmentKind::Transact)
}

fn test_wallet_handle(utxos: Vec<WalletUtxo>) -> WalletHandle {
    let (ready_tx, ready_rx) = watch::channel(false);
    drop(ready_tx);
    let (_readiness_tx, readiness_rx) = watch::channel(WalletReadiness::Syncing);
    let (rev_tx, rev_rx) = watch::channel(0_u64);
    let (reset_generation_tx, reset_generation_rx) = watch::channel(0_u64);
    let (view_tx, view_rx) = watch::channel(WalletViewState::Current(WalletCurrentSnapshot::new(
        0,
        0,
        0,
        Arc::<[WalletUtxo]>::from(utxos.clone()),
        Arc::new(WalletPendingOverlay::default()),
    )));
    let (pending_overlay_tx, _pending_overlay_rx) = mpsc::channel(1);
    let (poi_refresh_tx, _poi_refresh_rx) = mpsc::channel(1);
    let (_poi_refreshing_tx, poi_refreshing_rx) = watch::channel(false);
    let (indexed_catch_up_tx, indexed_catch_up_rx) = watch::channel(None);
    let (indexed_catch_up_status_tx, _indexed_catch_up_status_rx) = mpsc::unbounded_channel();
    WalletHandle {
        cache_key: "cache-key".to_string(),
        chain_id: 1,
        actor_id: 1,
        active_actor_id: Arc::new(AtomicU64::new(1)),
        lifecycle: Arc::new(WalletActorLifecycleCell::new()),
        authority_lock: Arc::new(tokio::sync::Mutex::new(())),
        utxos: Arc::new(RwLock::new(utxos)),
        pending_overlay: Arc::new(RwLock::new(WalletPendingOverlay::default())),
        last_scanned: Arc::new(AtomicU64::new(0)),
        reset_generation: Arc::new(AtomicU64::new(0)),
        reset_generation_rx,
        next_sync_job_id: Arc::new(AtomicU64::new(1)),
        ready_rx,
        readiness_rx,
        rev_rx,
        view_rx,
        poi_refreshing_rx,
        indexed_catch_up_rx,
        pending_overlay_tx,
        poi_refresh_tx,
        indexed_catch_up_status_tx,
        rev_tx,
        reset_generation_tx,
        view_tx,
        indexed_catch_up_tx,
    }
}

fn local_pending_spent_for(utxo: &WalletUtxo, submitted_at: u64) -> WalletPendingSpent {
    WalletPendingSpent {
        tree: utxo.utxo.tree,
        position: utxo.utxo.position,
        tx_hash: Some(FixedBytes::from([0x77; 32])),
        block_number: None,
        block_timestamp: Some(submitted_at),
    }
}

fn test_wallet_utxo_with_kind(position: u64, kind: UtxoCommitmentKind) -> WalletUtxo {
    WalletUtxo::new(Utxo::new(
        Note {
            token_hash: uint!(1_U256),
            value: uint!(10_U256),
            random: [0u8; 16],
            npk: uint!(2_U256),
        },
        2,
        position,
        source((position % 200) as u8 + 1),
        kind,
    ))
}

fn recovery_test_transaction(
    input: &WalletUtxo,
    output: &WalletUtxo,
    nullifying_key: U256,
) -> Transaction {
    Transaction {
        proof: SnarkProof::default(),
        merkleRoot: FixedBytes::ZERO,
        nullifiers: vec![FixedBytes::from(
            input.utxo.nullifier(nullifying_key).to_be_bytes::<32>(),
        )],
        commitments: vec![output.utxo.poi.commitment],
        boundParams: BoundParams::new_transact(
            input.utxo.tree,
            EVM_CHAIN_TYPE,
            1,
            Vec::new(),
            Address::ZERO,
            FixedBytes::ZERO,
        ),
        unshieldPreimage: CommitmentPreimage::empty(),
    }
}

#[test]
fn rewind_wallet_utxos_preserves_pre_reorg_outputs() {
    let kept_unspent = test_wallet_utxo(1);
    let mut kept_spent = test_wallet_utxo(2);
    kept_spent.spent = Some(source(4));
    let mut reopened_spend = test_wallet_utxo(3);
    reopened_spend.spent = Some(source(12));
    let dropped_output = test_wallet_utxo(20);
    let dropped_commitment = dropped_output.utxo.poi.commitment;

    let mut wallet_utxos = vec![kept_unspent, kept_spent, reopened_spend, dropped_output];
    let rewind = rewind_wallet_utxos(&mut wallet_utxos, 10);

    assert!(rewind.changed);
    assert_eq!(rewind.removed_output_commitments, vec![dropped_commitment]);
    assert_eq!(wallet_utxos.len(), 3);
    assert!(wallet_utxos.iter().any(|utxo| utxo.utxo.position == 1));
    assert!(wallet_utxos.iter().any(|utxo| {
        utxo.utxo.position == 2
            && utxo
                .spent
                .as_ref()
                .is_some_and(|spent| spent.block_number == 4)
    }));
    assert!(
        wallet_utxos
            .iter()
            .any(|utxo| utxo.utxo.position == 3 && utxo.spent.is_none())
    );
    assert!(!wallet_utxos.iter().any(|utxo| utxo.utxo.position == 20));
}

#[derive(Default)]
struct RecordingPoiStatusClient {
    calls: Mutex<Vec<(Vec<FixedBytes<32>>, Vec<BlindedCommitmentData>)>>,
    fail_calls: Mutex<HashSet<usize>>,
    default_status: Mutex<Option<PoiStatus>>,
    statuses: Mutex<HashMap<FixedBytes<32>, PoiStatus>>,
}

struct MockPoiRpc {
    url: Url,
    requests: std_mpsc::Receiver<serde_json::Value>,
}

impl RecordingPoiStatusClient {
    fn fail_call(&self, call_index: usize) {
        self.fail_calls
            .lock()
            .expect("fail calls")
            .insert(call_index);
    }

    fn set_default_status(&self, status: PoiStatus) {
        *self.default_status.lock().expect("default status") = Some(status);
    }

    fn calls(&self) -> Vec<(Vec<FixedBytes<32>>, Vec<BlindedCommitmentData>)> {
        self.calls.lock().expect("poi calls").clone()
    }
}

async fn spawn_poi_rpc(result: serde_json::Value) -> MockPoiRpc {
    spawn_poi_rpc_sequence(vec![result]).await
}

async fn spawn_poi_rpc_sequence(results: Vec<serde_json::Value>) -> MockPoiRpc {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock POI RPC");
    let url = Url::parse(&format!(
        "http://{}",
        listener.local_addr().expect("local addr")
    ))
    .expect("mock POI RPC URL");
    let (tx, requests) = std_mpsc::channel();
    tokio::spawn(async move {
        for result in results {
            let (mut socket, _) = listener.accept().await.expect("accept request");
            let mut bytes = Vec::new();
            let mut buf = [0_u8; 1024];
            let (body_start, content_length) = loop {
                let read = socket.read(&mut buf).await.expect("read request");
                assert!(
                    read > 0,
                    "mock POI RPC connection closed before request body"
                );
                bytes.extend_from_slice(&buf[..read]);
                if let Some(lengths) = http_body_bounds(&bytes) {
                    break lengths;
                }
            };
            let body = &bytes[body_start..body_start + content_length];
            let request: serde_json::Value = serde_json::from_slice(body).expect("request JSON");
            tx.send(request.clone()).expect("record request");
            let response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": request["id"].clone(),
                "result": result,
            })
            .to_string();
            let headers = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                response.len()
            );
            socket
                .write_all(headers.as_bytes())
                .await
                .expect("write headers");
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write body");
        }
    });
    MockPoiRpc { url, requests }
}

fn poi_leaf_response(leaves: &[U256]) -> serde_json::Value {
    serde_json::to_value(
        leaves
            .iter()
            .map(|leaf| format!("0x{leaf:064x}"))
            .collect::<Vec<_>>(),
    )
    .expect("leaves JSON")
}

async fn spawn_http_response(body: Vec<u8>) -> (Url, std_mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock HTTP server");
    let url = Url::parse(&format!(
        "http://{}",
        listener.local_addr().expect("local addr")
    ))
    .expect("mock HTTP URL");
    let (tx, requests) = std_mpsc::channel();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept request");
        let mut bytes = Vec::new();
        let mut buf = [0_u8; 1024];
        loop {
            let read = socket.read(&mut buf).await.expect("read request");
            assert!(read > 0, "mock HTTP connection closed before request");
            bytes.extend_from_slice(&buf[..read]);
            if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        tx.send(String::from_utf8_lossy(&bytes).to_string())
            .expect("record request");
        let headers = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        socket
            .write_all(headers.as_bytes())
            .await
            .expect("write headers");
        socket.write_all(&body).await.expect("write body");
    });
    (url, requests)
}

fn http_body_bounds(bytes: &[u8]) -> Option<(usize, usize)> {
    let body_start = bytes.windows(4).position(|window| window == b"\r\n\r\n")? + 4;
    let headers = std::str::from_utf8(&bytes[..body_start]).ok()?;
    let content_length = headers.lines().find_map(|line| {
        line.strip_prefix("content-length:")
            .or_else(|| line.strip_prefix("Content-Length:"))
            .and_then(|value| value.trim().parse::<usize>().ok())
    })?;
    (bytes.len() >= body_start + content_length).then_some((body_start, content_length))
}

#[async_trait]
impl PoiStatusReader for RecordingPoiStatusClient {
    async fn pois_per_list(
        &self,
        _txid_version: &str,
        _chain_type: u8,
        _chain_id: u64,
        list_keys: &[FixedBytes<32>],
        blinded_commitment_datas: &[BlindedCommitmentData],
    ) -> Result<BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PoiStatus>>, PoiError> {
        let call_index = {
            let mut calls = self.calls.lock().expect("poi calls");
            let call_index = calls.len();
            calls.push((list_keys.to_vec(), blinded_commitment_datas.to_vec()));
            call_index
        };
        if self
            .fail_calls
            .lock()
            .expect("fail calls")
            .contains(&call_index)
        {
            return Err(PoiError::MerkleRootsRejected);
        }
        let default_status = self
            .default_status
            .lock()
            .expect("default status")
            .unwrap_or(PoiStatus::Valid);
        let statuses = self.statuses.lock().expect("statuses").clone();
        Ok(blinded_commitment_datas
            .iter()
            .map(|data| {
                let status = statuses
                    .get(&data.blinded_commitment)
                    .copied()
                    .unwrap_or(default_status);
                (
                    data.blinded_commitment,
                    list_keys
                        .iter()
                        .copied()
                        .map(|list_key| (list_key, status))
                        .collect(),
                )
            })
            .collect())
    }
}

#[derive(Default)]
struct RecordingPendingOutputPoiSubmitter {
    calls: Mutex<Vec<(FixedBytes<32>, u64, u64)>>,
    list_key_calls: Mutex<Vec<Vec<FixedBytes<32>>>>,
    fail_next: Mutex<bool>,
}

impl RecordingPendingOutputPoiSubmitter {
    fn fail_next(&self) {
        *self.fail_next.lock().expect("fail next") = true;
    }

    fn calls(&self) -> Vec<(FixedBytes<32>, u64, u64)> {
        self.calls.lock().expect("submission calls").clone()
    }

    fn list_key_calls(&self) -> Vec<Vec<FixedBytes<32>>> {
        self.list_key_calls
            .lock()
            .expect("submission list key calls")
            .clone()
    }
}

#[async_trait]
impl PendingOutputPoiSubmitter for RecordingPendingOutputPoiSubmitter {
    async fn submit_single_commitment_proofs(
        &self,
        _txid_version: &str,
        _chain_type: u8,
        _chain_id: u64,
        context: &SingleCommitmentProofContext,
        utxo_tree_out: u64,
        utxo_position_out: u64,
    ) -> Result<(), PoiError> {
        self.list_key_calls
            .lock()
            .expect("submission list key calls")
            .push(
                context
                    .pre_transaction_pois_per_txid_leaf_per_list
                    .keys()
                    .copied()
                    .collect(),
            );
        self.calls.lock().expect("submission calls").push((
            context.commitment,
            utxo_tree_out,
            utxo_position_out,
        ));
        let mut fail_next = self.fail_next.lock().expect("fail next");
        if *fail_next {
            *fail_next = false;
            return Err(PoiError::MerkleRootsRejected);
        }
        Ok(())
    }

    async fn submit_transact_proof(
        &self,
        _txid_version: &str,
        _chain_type: u8,
        _chain_id: u64,
        list_key: &FixedBytes<32>,
        txid_merkleroot_index: u64,
        poi: &PreTxPoi,
    ) -> Result<(), PoiError> {
        self.list_key_calls
            .lock()
            .expect("submission list key calls")
            .push(vec![*list_key]);
        self.calls.lock().expect("submission calls").push((
            poi.blinded_commitments_out
                .first()
                .copied()
                .unwrap_or_default(),
            txid_merkleroot_index,
            0,
        ));
        let mut fail_next = self.fail_next.lock().expect("fail next");
        if *fail_next {
            *fail_next = false;
            return Err(PoiError::MerkleRootsRejected);
        }
        Ok(())
    }
}

struct BlockingPendingOutputPoiSubmitter {
    started: tokio::sync::Mutex<Option<oneshot::Sender<()>>>,
    release: tokio::sync::Mutex<Option<oneshot::Receiver<()>>>,
    calls: Mutex<Vec<(FixedBytes<32>, u64, u64)>>,
}

#[derive(Default)]
struct RecordingPoiProofSource {
    calls: AtomicU64,
    list_keys: Mutex<Vec<FixedBytes<32>>>,
}

struct ResetAfterFirstPendingOutputPoiSubmitter {
    handle: WalletHandle,
    calls: AtomicU64,
}

impl ResetAfterFirstPendingOutputPoiSubmitter {
    fn new(handle: WalletHandle) -> Self {
        Self {
            handle,
            calls: AtomicU64::new(0),
        }
    }

    fn calls(&self) -> u64 {
        self.calls.load(Ordering::Acquire)
    }
}

#[async_trait]
impl PendingOutputPoiSubmitter for ResetAfterFirstPendingOutputPoiSubmitter {
    async fn submit_single_commitment_proofs(
        &self,
        _txid_version: &str,
        _chain_type: u8,
        _chain_id: u64,
        _context: &SingleCommitmentProofContext,
        _utxo_tree_out: u64,
        _utxo_position_out: u64,
    ) -> Result<(), PoiError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        let _ = self.handle.advance_reset_generation().await;
        Ok(())
    }

    async fn submit_transact_proof(
        &self,
        _txid_version: &str,
        _chain_type: u8,
        _chain_id: u64,
        _list_key: &FixedBytes<32>,
        _txid_merkleroot_index: u64,
        _poi: &PreTxPoi,
    ) -> Result<(), PoiError> {
        let call = self.calls.fetch_add(1, Ordering::AcqRel);
        if call == 0 {
            let _ = self.handle.advance_reset_generation().await;
        }
        Ok(())
    }
}

impl RecordingPoiProofSource {
    fn calls(&self) -> u64 {
        self.calls.load(Ordering::Acquire)
    }

    fn list_keys(&self) -> Vec<FixedBytes<32>> {
        self.list_keys.lock().expect("proof list keys").clone()
    }
}

#[async_trait]
impl PoiMerkleProofSource for RecordingPoiProofSource {
    async fn poi_merkle_proofs(
        &self,
        _txid_version: &str,
        _chain_type: u8,
        _chain_id: u64,
        list_key: &FixedBytes<32>,
        _blinded_commitments: &[FixedBytes<32>],
    ) -> Result<Vec<PoiMerkleProof>, PreTransactionPoiError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        self.list_keys
            .lock()
            .expect("proof list keys")
            .push(*list_key);
        Err(PreTransactionPoiError::ProofSource(
            "recording proof source called".to_string(),
        ))
    }
}

impl BlockingPendingOutputPoiSubmitter {
    fn new(started: oneshot::Sender<()>, release: oneshot::Receiver<()>) -> Self {
        Self {
            started: tokio::sync::Mutex::new(Some(started)),
            release: tokio::sync::Mutex::new(Some(release)),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<(FixedBytes<32>, u64, u64)> {
        self.calls
            .lock()
            .expect("blocking submission calls")
            .clone()
    }

    async fn wait_for_release(&self) {
        if let Some(started) = self.started.lock().await.take() {
            let _ = started.send(());
        }
        if let Some(release) = self.release.lock().await.take() {
            let _ = release.await;
        }
    }
}

#[async_trait]
impl PendingOutputPoiSubmitter for BlockingPendingOutputPoiSubmitter {
    async fn submit_single_commitment_proofs(
        &self,
        _txid_version: &str,
        _chain_type: u8,
        _chain_id: u64,
        context: &SingleCommitmentProofContext,
        utxo_tree_out: u64,
        utxo_position_out: u64,
    ) -> Result<(), PoiError> {
        self.wait_for_release().await;
        self.calls.lock().expect("blocking submission calls").push((
            context.commitment,
            utxo_tree_out,
            utxo_position_out,
        ));
        Ok(())
    }

    async fn submit_transact_proof(
        &self,
        _txid_version: &str,
        _chain_type: u8,
        _chain_id: u64,
        _list_key: &FixedBytes<32>,
        txid_merkleroot_index: u64,
        poi: &PreTxPoi,
    ) -> Result<(), PoiError> {
        self.wait_for_release().await;
        self.calls.lock().expect("blocking submission calls").push((
            poi.blinded_commitments_out
                .first()
                .copied()
                .unwrap_or_default(),
            txid_merkleroot_index,
            0,
        ));
        Ok(())
    }
}

struct BlockingPoiStatusReader {
    started: tokio::sync::Mutex<Option<oneshot::Sender<()>>>,
    release: tokio::sync::Mutex<Option<oneshot::Receiver<()>>>,
}

impl BlockingPoiStatusReader {
    fn new(started: oneshot::Sender<()>, release: oneshot::Receiver<()>) -> Self {
        Self {
            started: tokio::sync::Mutex::new(Some(started)),
            release: tokio::sync::Mutex::new(Some(release)),
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
                        .map(|list_key| (list_key, PoiStatus::Valid))
                        .collect(),
                )
            })
            .collect())
    }
}

fn sample_pre_tx_poi(byte: u8) -> PreTxPoi {
    PreTxPoi {
        snark_proof: SnarkJsProof {
            pi_a: [U256::from(byte), U256::from(byte + 1)],
            pi_b: [
                [U256::from(byte + 2), U256::from(byte + 3)],
                [U256::from(byte + 4), U256::from(byte + 5)],
            ],
            pi_c: [U256::from(byte + 6), U256::from(byte + 7)],
        },
        txid_merkleroot: FixedBytes::from([byte; 32]),
        poi_merkleroots: vec![FixedBytes::from([byte + 1; 32])],
        blinded_commitments_out: vec![FixedBytes::from([byte + 2; 32])],
        railgun_txid_if_has_unshield: Bytes::copy_from_slice(&[0_u8]),
    }
}

fn pending_output_record(
    chain_id: u64,
    output_commitment: FixedBytes<32>,
    list_key: FixedBytes<32>,
) -> PendingOutputPoiContextRecord {
    let txid_leaf = FixedBytes::from([0x55; 32]);
    PendingOutputPoiContextRecord {
        chain_id,
        wallet_id: "wallet-1".to_string(),
        txid_version: DEFAULT_TXID_VERSION.to_string(),
        output_commitment,
        output_npk: FixedBytes::from([0x66; 32]),
        utxo_tree_in: 9,
        railgun_txid: uint!(7_U256),
        txid_merkleroot_index: None,
        pre_transaction_pois_per_txid_leaf_per_list: BTreeMap::from([(
            list_key,
            BTreeMap::from([(txid_leaf, sample_pre_tx_poi(0x10))]),
        )]),
        required_poi_list_keys: vec![list_key],
        output_role: PendingOutputPoiRole::Recipient,
        created_at: 123,
        source_operation_id: None,
        observation: None,
        submitted_poi_list_keys: Vec::new(),
        terminal_error: None,
    }
}

fn matching_pending_output_record(
    cfg: &WalletConfig,
    wallet_utxo: &WalletUtxo,
    list_key: FixedBytes<32>,
) -> PendingOutputPoiContextRecord {
    let mut record = pending_output_record(
        cfg.chain.chain_id,
        wallet_utxo.utxo.poi.commitment,
        list_key,
    );
    record.wallet_id = cfg.cache_key.clone();
    record.output_npk = wallet_utxo.utxo.poi.npk;
    record.observation = Some(local_db::PendingOutputPoiObservation {
        output_tree: u64::from(wallet_utxo.utxo.tree),
        output_position: wallet_utxo.utxo.position,
        tx_hash: wallet_utxo.utxo.source.tx_hash,
        block_number: wallet_utxo.utxo.source.block_number,
        block_timestamp: wallet_utxo.utxo.source.block_timestamp,
    });
    record
}

fn output_poi_recovery_record(
    chain_id: u64,
    wallet_id: &str,
    output_commitment: FixedBytes<32>,
    status: OutputPoiRecoveryStatus,
    next_retry_at: Option<u64>,
) -> OutputPoiRecoveryRecord {
    OutputPoiRecoveryRecord {
        chain_id,
        wallet_id: wallet_id.to_string(),
        output_commitment,
        source_tx_hash: FixedBytes::from([0x99; 32]),
        tx_input: None,
        status,
        created_at: 1,
        updated_at: 1,
        last_detection_at: Some(1),
        last_submission_at: None,
        next_retry_at,
        attempt_count: 0,
        last_error: None,
    }
}

#[test]
fn output_poi_recovery_action_caches_tx_input_without_resetting_state() {
    let mut record = output_poi_recovery_record(
        1,
        "wallet",
        FixedBytes::from([0x44; 32]),
        OutputPoiRecoveryStatus::ProofGenerationFailed,
        Some(20),
    );
    record.attempt_count = 3;
    record.last_error = Some("previous".to_string());

    record.apply_action(
        OutputPoiRecoveryAction::CacheTxInput {
            tx_input: vec![0xde, 0xad],
        },
        10,
    );

    assert_eq!(record.tx_input, Some(vec![0xde, 0xad]));
    assert_eq!(
        record.status,
        OutputPoiRecoveryStatus::ProofGenerationFailed
    );
    assert_eq!(record.updated_at, 10);
    assert_eq!(record.last_detection_at, Some(10));
    assert_eq!(record.next_retry_at, Some(20));
    assert_eq!(record.attempt_count, 3);
    assert_eq!(record.last_error.as_deref(), Some("previous"));
}

#[test]
fn output_poi_recovery_action_records_detected_failure() {
    let mut record = output_poi_recovery_record(
        1,
        "wallet",
        FixedBytes::from([0x44; 32]),
        OutputPoiRecoveryStatus::Recoverable,
        None,
    );

    record.apply_action(
        OutputPoiRecoveryAction::Detected {
            status: OutputPoiRecoveryStatus::DecodeFailed,
            retry_after: Some(Duration::from_secs(30)),
            last_error: Some("decode failed".to_string()),
            increment_attempts: true,
        },
        10,
    );

    assert_eq!(record.status, OutputPoiRecoveryStatus::DecodeFailed);
    assert_eq!(record.updated_at, 10);
    assert_eq!(record.last_detection_at, Some(10));
    assert_eq!(record.next_retry_at, Some(40));
    assert_eq!(record.attempt_count, 1);
    assert_eq!(record.last_error.as_deref(), Some("decode failed"));
}

#[test]
fn output_poi_recovery_action_records_recovered_context() {
    let mut record = output_poi_recovery_record(
        1,
        "wallet",
        FixedBytes::from([0x44; 32]),
        OutputPoiRecoveryStatus::ProofGenerationFailed,
        Some(20),
    );
    record.attempt_count = 2;
    record.last_error = Some("old".to_string());

    record.apply_action(
        OutputPoiRecoveryAction::Detected {
            status: OutputPoiRecoveryStatus::Recoverable,
            retry_after: None,
            last_error: None,
            increment_attempts: false,
        },
        10,
    );

    assert_eq!(record.status, OutputPoiRecoveryStatus::Recoverable);
    assert_eq!(record.updated_at, 10);
    assert_eq!(record.last_detection_at, Some(10));
    assert_eq!(record.next_retry_at, None);
    assert_eq!(record.attempt_count, 2);
    assert_eq!(record.last_error, None);
}

#[test]
fn output_poi_recovery_action_records_submit_success() {
    let mut record = output_poi_recovery_record(
        1,
        "wallet",
        FixedBytes::from([0x44; 32]),
        OutputPoiRecoveryStatus::Recoverable,
        None,
    );
    record.last_error = Some("old".to_string());

    record.apply_action(
        OutputPoiRecoveryAction::Submitted {
            retry_after: Duration::from_secs(60),
        },
        10,
    );

    assert_eq!(record.status, OutputPoiRecoveryStatus::Submitted);
    assert_eq!(record.updated_at, 10);
    assert_eq!(record.last_submission_at, Some(10));
    assert_eq!(record.next_retry_at, Some(70));
    assert_eq!(record.attempt_count, 1);
    assert_eq!(record.last_error, None);
}

#[test]
fn output_poi_recovery_action_records_submit_failure() {
    let mut record = output_poi_recovery_record(
        1,
        "wallet",
        FixedBytes::from([0x44; 32]),
        OutputPoiRecoveryStatus::Recoverable,
        None,
    );

    record.apply_action(
        OutputPoiRecoveryAction::SubmitFailed {
            error: "submit failed".to_string(),
            retry_after: Duration::from_secs(60),
        },
        10,
    );

    assert_eq!(record.status, OutputPoiRecoveryStatus::SubmitFailed);
    assert_eq!(record.updated_at, 10);
    assert_eq!(record.last_submission_at, None);
    assert_eq!(record.next_retry_at, Some(70));
    assert_eq!(record.attempt_count, 1);
    assert_eq!(record.last_error.as_deref(), Some("submit failed"));
}

#[test]
fn output_poi_recovery_action_marks_valid_without_touching_history() {
    let mut record = output_poi_recovery_record(
        1,
        "wallet",
        FixedBytes::from([0x44; 32]),
        OutputPoiRecoveryStatus::Submitted,
        Some(20),
    );
    record.last_detection_at = Some(4);
    record.last_submission_at = Some(5);
    record.attempt_count = 2;
    record.last_error = Some("old".to_string());

    record.apply_action(OutputPoiRecoveryAction::Valid, 10);

    assert_eq!(record.status, OutputPoiRecoveryStatus::Valid);
    assert_eq!(record.updated_at, 10);
    assert_eq!(record.last_detection_at, Some(4));
    assert_eq!(record.last_submission_at, Some(5));
    assert_eq!(record.next_retry_at, None);
    assert_eq!(record.attempt_count, 2);
    assert_eq!(record.last_error, None);
}

#[test]
fn pending_output_submit_identity_derives_status_query_blinded_commitment() {
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x77; 32]);
    let list_key = FixedBytes::from([0x11; 32]);
    let record = pending_output_record(chain_id, output_commitment, list_key);
    let observation = local_db::PendingOutputPoiObservation {
        output_tree: 3,
        output_position: 42,
        tx_hash: source(11).tx_hash,
        block_number: 11,
        block_timestamp: 1_700_000_011,
    };

    let identity =
        pending_output_poi_submit_identity(&record, &observation).expect("submit identity");

    assert_eq!(
        identity.derived_blinded_commitment,
        UtxoPoiMetadata::blinded_commitment_for(
            record.output_commitment,
            record.output_npk,
            observation.output_tree as u32,
            observation.output_position,
        )
    );
}

#[test]
fn pending_output_submit_identity_uses_included_txid_leaf_for_recovery() {
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x77; 32]);
    let list_key = FixedBytes::from([0x11; 32]);
    let included_txid_leaf = FixedBytes::from([0x99; 32]);
    let mut record = pending_output_record(chain_id, output_commitment, list_key);
    let dummy_txid_leaf = FixedBytes::from(
        railgun_txid_leaf_hash(record.railgun_txid, record.utxo_tree_in).to_be_bytes::<32>(),
    );
    record.txid_merkleroot_index = Some(105_572);
    record.pre_transaction_pois_per_txid_leaf_per_list = BTreeMap::from([(
        list_key,
        BTreeMap::from([(included_txid_leaf, sample_pre_tx_poi(0x10))]),
    )]);
    let observation = local_db::PendingOutputPoiObservation {
        output_tree: 3,
        output_position: 42,
        tx_hash: source(11).tx_hash,
        block_number: 11,
        block_timestamp: 1_700_000_011,
    };

    let identity =
        pending_output_poi_submit_identity(&record, &observation).expect("submit identity");

    assert_eq!(identity.txid_leaf_hash, included_txid_leaf);
    assert_ne!(identity.txid_leaf_hash, dummy_txid_leaf);
}

#[test]
fn output_start_global_position_handles_nonzero_output_index_across_tree_boundary() {
    let utxo = Utxo::new(
        Note {
            token_hash: uint!(1_U256),
            value: uint!(10_U256),
            random: [0u8; 16],
            npk: uint!(2_U256),
        },
        3,
        1,
        source(17),
        UtxoCommitmentKind::Transact,
    );

    let start_global = output_start_global_position(&utxo, 2).expect("start global");

    assert_eq!(start_global / u128::from(TREE_LEAF_COUNT), 2);
    assert_eq!(start_global % u128::from(TREE_LEAF_COUNT), 65_535);
    assert_eq!(
        start_global,
        u128::from(utxo.tree) * u128::from(TREE_LEAF_COUNT) + u128::from(utxo.position) - 2
    );
}

#[derive(Debug, Clone, Copy, Default)]
struct RecordingCacheState {
    store_calls: usize,
    meta_calls: usize,
    reset_calls: usize,
    fail_next_store: bool,
}

struct RecordingCacheStore {
    db: Arc<DbStore>,
    state: Mutex<RecordingCacheState>,
}

impl RecordingCacheStore {
    fn new(db: Arc<DbStore>) -> Self {
        Self {
            db,
            state: Mutex::default(),
        }
    }

    fn fail_next_store(&self) {
        self.state.lock().expect("cache state").fail_next_store = true;
    }

    fn state(&self) -> RecordingCacheState {
        *self.state.lock().expect("cache state")
    }
}

impl WalletCacheStore for RecordingCacheStore {
    fn commit_wallet_private_state(
        &self,
        commit: WalletPrivateCommit<'_>,
    ) -> Result<(), WalletCacheError> {
        if commit.replace_wallet_utxos() {
            let mut state = self.state.lock().expect("cache state");
            state.store_calls += 1;
            if state.fail_next_store {
                state.fail_next_store = false;
                return Err(WalletCacheError::Crypto);
            }
        } else {
            self.state.lock().expect("cache state").meta_calls += 1;
        }
        for record in commit.pending_output_context_updates() {
            self.db.put_pending_output_poi_context(record)?;
        }
        for output_commitment in commit.pending_output_context_deletes() {
            self.db.delete_pending_output_poi_context(
                commit.pending_output_context_chain_id(),
                commit.wallet_id(),
                output_commitment,
            )?;
        }
        for record in commit.output_poi_recovery_updates() {
            self.db.put_output_poi_recovery(record)?;
        }
        if let Some(state) = commit.sync_actor_state() {
            self.db.put_wallet_sync_actor_state(state)?;
        }
        Ok(())
    }

    fn load_wallet_utxos(&self, _wallet_id: &str) -> Result<Vec<WalletUtxo>, WalletCacheError> {
        Ok(Vec::new())
    }

    fn get_wallet_meta(&self, _wallet_id: &str) -> Result<Option<WalletMeta>, WalletCacheError> {
        Ok(None)
    }

    fn get_wallet_sync_actor_state(
        &self,
        _chain_id: u64,
        _wallet_id: &str,
    ) -> Result<Option<WalletSyncActorStateRecord>, WalletCacheError> {
        Ok(None)
    }

    fn put_wallet_sync_actor_state(
        &self,
        commit: WalletSyncActorStateCommit<'_>,
    ) -> Result<(), WalletCacheError> {
        self.db.put_wallet_sync_actor_state(commit.state())?;
        Ok(())
    }
}

#[test]
fn live_metadata_flush_waits_for_interval_or_block_threshold() {
    let now = Instant::now();
    let flush = WalletLiveMetadataFlush::new(100, now);

    assert!(!flush.should_flush(100 + WALLET_METADATA_LIVE_FLUSH_BLOCKS - 1, now));
    assert!(flush.should_flush(100 + WALLET_METADATA_LIVE_FLUSH_BLOCKS, now));
    assert!(flush.should_flush(101, now + WALLET_METADATA_LIVE_FLUSH_INTERVAL));
}

#[test]
fn live_metadata_flush_mark_persisted_resets_thresholds() {
    let now = Instant::now();
    let mut flush = WalletLiveMetadataFlush::new(100, now);

    flush.mark_persisted(125, now + WALLET_METADATA_LIVE_FLUSH_INTERVAL);

    assert!(!flush.should_flush(125, now + WALLET_METADATA_LIVE_FLUSH_INTERVAL));
    assert!(!flush.should_flush(
        125 + WALLET_METADATA_LIVE_FLUSH_BLOCKS - 1,
        now + WALLET_METADATA_LIVE_FLUSH_INTERVAL
    ));
    assert!(flush.should_flush(
        125 + WALLET_METADATA_LIVE_FLUSH_BLOCKS,
        now + WALLET_METADATA_LIVE_FLUSH_INTERVAL
    ));
}

#[test]
fn recovery_input_tree_search_finds_root_before_later_commitments() {
    let first_input = test_wallet_utxo(0);
    let mut forest_before_later = MerkleForest::new();
    forest_before_later
        .insert_leaf(MerkleTreeUpdate {
            tree_number: first_input.utxo.tree,
            tree_position: first_input.utxo.position,
            hash: first_input.utxo.note.commitment(),
        })
        .expect("insert input leaf");
    let expected_root = forest_before_later
        .prove_with_leaf_count(first_input.utxo.tree, first_input.utxo.position, 1)
        .expect("historical proof")
        .root;

    let mut forest_after_later = forest_before_later;
    forest_after_later
        .insert_leaf(MerkleTreeUpdate {
            tree_number: first_input.utxo.tree,
            tree_position: 1,
            hash: uint!(12_U256),
        })
        .expect("insert later leaf");
    forest_after_later
        .insert_leaf(MerkleTreeUpdate {
            tree_number: first_input.utxo.tree,
            tree_position: 2,
            hash: uint!(13_U256),
        })
        .expect("insert second later leaf");

    let current_proof = forest_after_later
        .prove_with_leaf_count(first_input.utxo.tree, first_input.utxo.position, 3)
        .expect("current proof");
    assert_ne!(current_proof.root, expected_root);

    let input_merkle = recovery_input_merkle_tree_for_root(
        &forest_after_later,
        first_input.utxo.tree,
        &first_input,
        3,
        expected_root,
    )
    .expect("find historical root");
    let recovered_proof = input_merkle.tree.prove(first_input.utxo.position);

    assert_eq!(recovered_proof.root, expected_root);
    assert_eq!(recovered_proof.leaf, first_input.utxo.note.commitment());
}

#[test]
fn output_poi_recovery_chunk_decrypts_missing_unshield_fee_output_from_calldata() {
    let spending_public_key = [uint!(4_U256), uint!(5_U256)];
    let scan_keys = ViewingKeyData::from_spending_public_key([7_u8; 32], spending_public_key);
    let broadcaster_keys =
        ViewingKeyData::from_spending_public_key([8_u8; 32], [uint!(6_U256), uint!(7_U256)]);
    let sender = scan_keys.address_data();
    let broadcaster = broadcaster_keys.address_data();
    let mut input = test_wallet_utxo(0);
    let source = source(44);
    input.spent = Some(source.clone());
    let token = input.utxo.token_address();
    let fee_note = Note::new_change(
        broadcaster.master_public_key,
        token,
        U256::from(2_u8),
        [0x51; 16],
    );
    let change_note = Note::new_change(
        scan_keys.master_public_key,
        token,
        U256::from(3_u8),
        [0x52; 16],
    );
    let output = WalletUtxo::new(Utxo::new(
        change_note.clone(),
        input.utxo.tree,
        9,
        source.clone(),
        UtxoCommitmentKind::Transact,
    ));
    let fee_ciphertext = NoteCiphertext::try_from_note(
        &fee_note,
        &sender,
        &broadcaster,
        &scan_keys.viewing_private_key,
    )
    .expect("encrypt fee note")
    .into_commitment_ciphertext();
    let change_ciphertext = NoteCiphertext::try_from_note(
        &change_note,
        &sender,
        &sender,
        &scan_keys.viewing_private_key,
    )
    .expect("encrypt change note")
    .into_commitment_ciphertext();
    let unshield_note = Note::new_unshield(Address::from([0x56; 20]), token, U256::from(7_u8));

    let mut forest = MerkleForest::new();
    forest
        .insert_leaf(MerkleTreeUpdate {
            tree_number: input.utxo.tree,
            tree_position: input.utxo.position,
            hash: input.utxo.note.commitment(),
        })
        .expect("insert input leaf");
    let merkle_root = forest
        .prove_with_leaf_count(input.utxo.tree, input.utxo.position, 1)
        .expect("input proof")
        .root;
    let transaction = Transaction {
        proof: SnarkProof::default(),
        merkleRoot: FixedBytes::from(merkle_root.to_be_bytes::<32>()),
        nullifiers: vec![FixedBytes::from(
            input
                .utxo
                .nullifier(scan_keys.nullifying_key)
                .to_be_bytes::<32>(),
        )],
        commitments: vec![
            FixedBytes::from(fee_note.commitment().to_be_bytes::<32>()),
            output.utxo.poi.commitment,
            FixedBytes::from(unshield_note.commitment().to_be_bytes::<32>()),
        ],
        boundParams: BoundParams::new_unshield(
            input.utxo.tree,
            EVM_CHAIN_TYPE,
            1,
            vec![fee_ciphertext, change_ciphertext],
            Address::ZERO,
            FixedBytes::ZERO,
        ),
        unshieldPreimage: CommitmentPreimage::new_unshield(&unshield_note, token),
    };
    let calldata = executeCall {
        _transactions: vec![transaction],
        _actionData: RelayAdapt7702ActionData {
            requireSuccess: true,
            minGasLimit: uint!(123_U256),
            calls: vec![Call {
                to: Address::from([0x99; 20]),
                data: Bytes::from(vec![0xab, 0xcd]),
                value: U256::ZERO,
            }],
        },
        _signature: Bytes::from(vec![0x12, 0x34]),
    }
    .abi_encode();
    assert_eq!(&calldata[..4], &[0xc6, 0x1e, 0x6b, 0x9d]);
    let decoded_transactions =
        decode_railgun_transactions(&calldata).expect("decode 7702 recovery calldata");
    let wallet_utxos = vec![input, output.clone()];
    let wallet_nullifiers = WalletNullifierIndex::new(&wallet_utxos, &scan_keys);

    let chunk = build_output_poi_recovery_chunk(
        &output,
        &wallet_nullifiers,
        &decoded_transactions,
        &forest,
        &[],
        spending_public_key,
        &scan_keys,
    )
    .expect("build unshield recovery chunk from calldata");

    assert!(chunk.chunk.has_unshield);
    assert_eq!(chunk.chunk.outputs.len(), 3);
    assert_eq!(chunk.chunk.private_output_count(), Some(2));
    assert_eq!(chunk.chunk.outputs[0].commitment(), fee_note.commitment());
    assert_eq!(chunk.chunk.outputs[0].npk, fee_note.npk);
    assert_eq!(chunk.chunk.outputs[0].value, fee_note.value);
    assert_eq!(
        chunk.chunk.outputs[1].commitment(),
        change_note.commitment()
    );
    assert_eq!(
        chunk.chunk.outputs[2].commitment(),
        unshield_note.commitment()
    );
    assert_eq!(chunk.chunk.private_inputs.npk_out[0], fee_note.npk);
    assert_eq!(chunk.chunk.private_inputs.value_out[0], fee_note.value);
    assert_eq!(
        chunk.output_start_global,
        u128::from(output.utxo.tree) * u128::from(TREE_LEAF_COUNT)
            + u128::from(output.utxo.position)
            - 1
    );
}

#[test]
fn output_poi_recovery_reports_missing_private_output_indexes() {
    let scan_keys =
        ViewingKeyData::from_spending_public_key([7_u8; 32], [uint!(4_U256), uint!(5_U256)]);
    let mut input = test_wallet_utxo(0);
    let output = test_wallet_utxo(8);
    let mut missing_private_output = test_wallet_utxo(9);
    missing_private_output.utxo.source = output.utxo.source.clone();
    missing_private_output.utxo.note.value = U256::from(11_u8);
    missing_private_output.utxo.poi.commitment = FixedBytes::from(
        missing_private_output
            .utxo
            .note
            .commitment()
            .to_be_bytes::<32>(),
    );
    input.spent = Some(output.utxo.source.clone());
    let mut forest = MerkleForest::new();
    forest
        .insert_leaf(MerkleTreeUpdate {
            tree_number: input.utxo.tree,
            tree_position: input.utxo.position,
            hash: input.utxo.note.commitment(),
        })
        .expect("insert input leaf");
    let merkle_root = forest
        .prove_with_leaf_count(input.utxo.tree, input.utxo.position, 1)
        .expect("input proof")
        .root;
    let missing_commitment = missing_private_output.utxo.poi.commitment;
    let transaction = Transaction {
        proof: SnarkProof::default(),
        merkleRoot: FixedBytes::from(merkle_root.to_be_bytes::<32>()),
        nullifiers: vec![FixedBytes::from(
            input
                .utxo
                .nullifier(scan_keys.nullifying_key)
                .to_be_bytes::<32>(),
        )],
        commitments: vec![output.utxo.poi.commitment, missing_commitment],
        boundParams: BoundParams::new_transact(
            input.utxo.tree,
            EVM_CHAIN_TYPE,
            1,
            Vec::new(),
            Address::ZERO,
            FixedBytes::ZERO,
        ),
        unshieldPreimage: CommitmentPreimage::empty(),
    };
    let wallet_utxos = vec![input, output.clone()];
    let wallet_nullifiers = WalletNullifierIndex::new(&wallet_utxos, &scan_keys);

    let failure = build_output_poi_recovery_chunk(
        &output,
        &wallet_nullifiers,
        &[transaction],
        &forest,
        &[],
        [uint!(4_U256), uint!(5_U256)],
        &scan_keys,
    )
    .expect_err("missing private output should fail");

    assert_eq!(
        failure.status,
        OutputPoiRecoveryStatus::MissingWalletOutputs
    );
    assert!(failure.message.contains("missing_private_outputs=1/2"));
    assert!(failure.message.contains("1:"));
    assert!(failure.message.contains(&hex::encode(missing_commitment)));
}

#[tokio::test]
async fn public_cache_txid_recovery_refreshes_stale_marker_for_unknown_target() {
    let spending_public_key = [uint!(4_U256), uint!(5_U256)];
    let scan_keys = ViewingKeyData::from_spending_public_key([7_u8; 32], spending_public_key);
    let mut input = test_wallet_utxo(0);
    let output = test_wallet_utxo(8);
    input.spent = Some(output.utxo.source.clone());
    let mut forest = MerkleForest::new();
    forest
        .insert_leaf(MerkleTreeUpdate {
            tree_number: input.utxo.tree,
            tree_position: input.utxo.position,
            hash: input.utxo.note.commitment(),
        })
        .expect("insert input leaf");
    let merkle_root = forest
        .prove_with_leaf_count(input.utxo.tree, input.utxo.position, 1)
        .expect("input proof")
        .root;
    let wallet_utxos = vec![input, output.clone()];
    let wallet_nullifiers = WalletNullifierIndex::new(&wallet_utxos, &scan_keys);
    let transaction =
        recovery_test_transaction(&wallet_utxos[0], &output, scan_keys.nullifying_key);
    let transaction = Transaction {
        merkleRoot: FixedBytes::from(merkle_root.to_be_bytes::<32>()),
        boundParams: BoundParams::new_transact(
            wallet_utxos[0].utxo.tree,
            EVM_CHAIN_TYPE,
            1,
            Vec::new(),
            Address::ZERO,
            FixedBytes::ZERO,
        ),
        ..transaction
    };
    let bound_params_hash = transaction.boundParams.hash();
    let recovery_chunk = build_output_poi_recovery_chunk(
        &output,
        &wallet_nullifiers,
        std::slice::from_ref(&transaction),
        &forest,
        &[],
        spending_public_key,
        &scan_keys,
    )
    .expect("build recovery chunk");

    let graph_response = serde_json::json!({
        "data": {
            "transactions": [
                {
                    "id": "0x00",
                    "blockNumber": "1",
                    "blockTimestamp": "1700000001",
                    "transactionHash": hex::encode_prefixed(FixedBytes::<32>::from([0x99; 32])),
                    "merkleRoot": hex::encode_prefixed(FixedBytes::<32>::from([0x98; 32])),
                    "nullifiers": ["0xaa"],
                    "commitments": ["0xbb"],
                    "boundParamsHash": "0xcc",
                    "hasUnshield": false,
                    "utxoTreeIn": "0",
                    "utxoTreeOut": "0",
                    "utxoBatchStartPositionOut": "0",
                },
                {
                    "id": "0x01",
                    "blockNumber": output.utxo.source.block_number.to_string(),
                    "blockTimestamp": output.utxo.source.block_timestamp.to_string(),
                    "transactionHash": hex::encode_prefixed(output.utxo.source.tx_hash),
                    "merkleRoot": hex::encode_prefixed(FixedBytes::from(merkle_root.to_be_bytes::<32>())),
                    "nullifiers": [hex::encode_prefixed(transaction.nullifiers[0])],
                    "commitments": [hex::encode_prefixed(output.utxo.poi.commitment)],
                    "boundParamsHash": hex::encode_prefixed(FixedBytes::from(bound_params_hash.to_be_bytes::<32>())),
                    "hasUnshield": false,
                    "utxoTreeIn": wallet_utxos[0].utxo.tree.to_string(),
                    "utxoTreeOut": output.utxo.tree.to_string(),
                    "utxoBatchStartPositionOut": output.utxo.position.to_string(),
                }
            ]
        }
    })
    .to_string()
    .into_bytes();
    let (graph_endpoint, _graph_requests) = spawn_http_response(graph_response).await;
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let public_data_plane =
        ChainPublicDataPlane::new(Arc::clone(&store), Arc::new(AtomicU64::new(0)));
    let txid_scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::ZERO,
    };
    public_data_plane
        .sync_txid_public_cache(PublicTxidSyncRequest {
            key: DataPlanePublicTxidCacheKey::new(txid_scope.clone(), DEFAULT_TXID_VERSION),
            endpoint: Some(&graph_endpoint),
            http_client: None,
            latest: DataPlanePublicTxidLatestValidated {
                txid_index: 0,
                merkleroot: None,
            },
            indexed_artifact_source: None,
        })
        .await
        .expect("seed public txid cache through typed data plane");
    let expected_leaf = railgun_txid_leaf_hash_with_output_start(
        recovery_chunk.chunk.railgun_txid(),
        u64::from(recovery_chunk.chunk.tree_number),
        U256::from(recovery_chunk.output_start_global),
    );
    let direct_error = public_data_plane
        .txid_public_proof(PublicTxidProofRequest {
            key: DataPlanePublicTxidCacheKey::new(txid_scope, DEFAULT_TXID_VERSION),
            target: PublicTxidProofTarget::UnknownIndex {
                expected_leaf_hash: expected_leaf,
                output_start_global: recovery_chunk.output_start_global,
            },
        })
        .expect_err("stale marker must not prove the unknown target beyond it");
    assert!(matches!(
        direct_error,
        crate::txid_cache::TxidPublicCacheError::CacheNotReady {
            required_index: 1,
            ..
        }
    ));
    let poi_mock = spawn_poi_rpc_sequence(vec![
        serde_json::json!({
            "validatedTxidIndex": 1,
            "validatedMerkleroot": null,
        }),
        serde_json::json!(true),
    ])
    .await;
    let poi_client = PoiRpcClient::new(poi_mock.url.clone());
    let mut cfg = wallet_config(scan_keys.nullifying_key);
    cfg.quick_sync_endpoint = Some(graph_endpoint);

    let recovered = recovered_output_txid_data_from_public_cache(PublicCacheTxidRecoveryRequest {
        public_data_plane: &public_data_plane,
        cfg: &cfg,
        poi_client: &poi_client,
        http_client: None,
        indexed_artifact_source: None,
        source_tx_hash: output.utxo.source.tx_hash,
        output_commitment: output.utxo.poi.commitment,
        recovery_chunk: &recovery_chunk,
        started: Instant::now(),
    })
    .await
    .expect("current marker sync should recover the unknown target");

    assert_eq!(recovered.target_txid_index, 1);
    let latest_request = poi_mock
        .requests
        .recv_timeout(Duration::from_secs(2))
        .expect("latest validated marker request");
    assert_eq!(latest_request["method"], "ppoi_validated_txid");
    let validate_request = poi_mock
        .requests
        .recv_timeout(Duration::from_secs(2))
        .expect("root validation request");
    assert_eq!(validate_request["method"], "ppoi_validate_txid_merkleroot");
    let latest = public_data_plane
        .cached_txid_latest_validated(&DataPlanePublicTxidCacheKey::new(
            ChainScope {
                chain_type: ChainType::Evm,
                chain_id: cfg.chain.chain_id,
                railgun_contract: cfg.chain.contract,
            },
            DEFAULT_TXID_VERSION,
        ))
        .expect("read refreshed marker")
        .expect("refreshed marker present");
    assert_eq!(latest.txid_index, 1);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn output_poi_recovery_proof_panic_uses_long_backoff() {
    let panic_err = PreTransactionPoiError::Prover(ProverError::WorkerPanic("boom".to_string()));
    assert_eq!(
        output_poi_recovery_proof_retry_after(&panic_err),
        OUTPUT_POI_RECOVERY_PROOF_FAILURE_RETRY_AFTER
    );

    let transient_err = PreTransactionPoiError::InputCountMismatch {
        expected: 1,
        got: 0,
    };
    assert_eq!(
        output_poi_recovery_proof_retry_after(&transient_err),
        OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER
    );
}

#[tokio::test]
async fn poi_status_refresh_chunks_unspent_utxos() {
    let client = RecordingPoiStatusClient::default();
    let list_keys = vec![FixedBytes::from([0x11; 32]), FixedBytes::from([0x22; 32])];
    let mut wallet_utxos = (0..=WALLET_POI_STATUS_BATCH_SIZE)
        .map(|position| test_wallet_utxo(position as u64))
        .collect::<Vec<_>>();

    let changed = refresh_wallet_poi_statuses_selected(
        &client,
        1,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(changed);
    let calls = client.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].0, list_keys);
    assert_eq!(calls[0].1.len(), WALLET_POI_STATUS_BATCH_SIZE);
    assert_eq!(calls[1].0, list_keys);
    assert_eq!(calls[1].1.len(), 1);
    assert!(wallet_utxos.iter().all(|wallet_utxo| {
        wallet_utxo.utxo.poi.is_valid_for_lists(&list_keys)
            && wallet_utxo.utxo.poi.refreshed_at.is_some()
    }));
}

#[tokio::test]
async fn remote_poi_status_refresh_uses_gateway_and_actor_intent_apply() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let list_key = FixedBytes::from([0x31; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = "wallet-remote-status".to_string();
    let wallet_utxo = test_wallet_utxo(31);
    let mut handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let transport = Arc::new(RecordingPoiStatusClient::default());
    let private_poi =
        WalletPrivatePoiClients::for_status(authority.remote_authority(), transport.clone());

    let changed = refresh_wallet_poi_statuses_remote_authorized(
        &authority,
        &private_poi,
        &store,
        &store,
        &cfg,
        &[list_key],
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(changed);
    assert_eq!(transport.calls().len(), 1);
    let snapshot = handle.current_snapshot().expect("current wallet view");
    let refreshed = snapshot
        .utxos
        .iter()
        .find(|utxo| utxo.utxo.poi.commitment == wallet_utxo.utxo.poi.commitment)
        .expect("refreshed UTXO");
    assert_eq!(
        refreshed.utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn delayed_remote_status_intent_does_not_overwrite_newer_local_status() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let list_key = FixedBytes::from([0x32; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = "wallet-status-cas".to_string();
    let wallet_utxo = test_wallet_utxo(32);
    let blinded_commitment = wallet_utxo.utxo.poi.blinded_commitment;
    let expected_poi = wallet_utxo.utxo.poi.clone();
    let mut handle = test_wallet_handle(vec![wallet_utxo]);
    handle.cache_key = cfg.cache_key.clone();
    {
        let mut current = handle.utxos.write().await;
        let _ = current[0].utxo.poi.apply_status_refresh(
            &[list_key],
            Some(&BTreeMap::from([(list_key, PoiStatus::Valid)])),
            200,
        );
    }
    let cancel = CancellationToken::new();
    let outcome = apply_owned_poi_private_delta_on_actor(
        &handle,
        &cancel,
        0,
        &store,
        &store,
        &cfg,
        OwnedPoiPrivateDelta::PoiStatusRefresh {
            active_list_keys: vec![list_key],
            expected_poi_by_blinded_commitment: BTreeMap::from([(
                blinded_commitment,
                expected_poi,
            )]),
            statuses_by_blinded_commitment: BTreeMap::from([(
                blinded_commitment,
                BTreeMap::from([(list_key, PoiStatus::Missing)]),
            )]),
            refreshed_at: 100,
        },
    )
    .await
    .expect("apply delayed remote status intent");

    assert_eq!(outcome, PoiPrivateApplyOutcome::Skipped);
    let current = handle.utxos.read().await;
    assert_eq!(
        current[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );
    assert_eq!(current[0].utxo.poi.refreshed_at, Some(200));

    drop(current);
    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn local_poi_status_refresh_reads_cache_without_remote_pois_per_list() {
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut wallet_utxos = vec![test_wallet_utxo(1), test_wallet_utxo(2)];
    let valid_blinded_commitment = wallet_utxos[0].utxo.poi.blinded_commitment;
    let missing_blinded_commitment = wallet_utxos[1].utxo.poi.blinded_commitment;
    let mut cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        1,
        DEFAULT_TXID_VERSION,
        list_key,
    ));
    cache
        .apply_poi_leaves(0, &[U256::from_be_bytes(valid_blinded_commitment.0)])
        .expect("apply local poi leaf");
    let local_caches = Arc::new(RwLock::new(BTreeMap::from([(list_key, cache)])));
    let local_reader = LocalPoiStatusReader::new(local_caches);
    let unused_remote = RecordingPoiStatusClient::default();

    let changed = refresh_wallet_poi_statuses_selected(
        &local_reader,
        1,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(changed);
    assert!(unused_remote.calls().is_empty());
    assert_eq!(
        wallet_utxos[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );
    assert_eq!(
        wallet_utxos[1].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Missing)
    );
    assert_eq!(
        wallet_utxos[0].utxo.poi.blinded_commitment,
        valid_blinded_commitment
    );
    assert_eq!(
        wallet_utxos[1].utxo.poi.blinded_commitment,
        missing_blinded_commitment
    );
}

#[tokio::test]
async fn indexed_artifacts_status_refresh_does_not_call_remote_pois_per_list() {
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut wallet_utxos = vec![test_wallet_utxo(1)];
    let blinded_commitment = wallet_utxos[0].utxo.poi.blinded_commitment;
    let mut cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        1,
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
        .expect("apply artifact event");
    cache.accept_current_roots();
    let cfg = wallet_config(U256::ZERO);
    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let public_data_plane = test_public_data_plane_with_poi_service(&db);
    seed_data_plane_poi_cache(&public_data_plane, cfg.chain.chain_id, list_key, cache).await;
    let mock = spawn_poi_rpc(serde_json::json!({})).await;
    let poi_runtime = test_artifact_poi_runtime();
    let status_reader = poi_runtime
        .status_reader_for_job(&public_data_plane, &cfg, &list_keys)
        .await
        .expect("local POI status reader");

    let changed = refresh_wallet_poi_statuses_selected(
        status_reader.as_reader(),
        cfg.chain.chain_id,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(changed);
    assert_eq!(
        wallet_utxos[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );
    assert!(
        mock.requests
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "remote ppoi_pois_per_list should not be called"
    );
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn poi_proxy_status_refresh_calls_remote_pois_per_list_without_local_ingestion() {
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut wallet_utxos = vec![test_wallet_utxo(1)];
    let blinded_commitment = wallet_utxos[0].utxo.poi.blinded_commitment;
    let mock = spawn_poi_rpc(serde_json::json!({
        hex::encode_prefixed(blinded_commitment): {
            hex::encode(list_key): "Valid",
        }
    }))
    .await;
    let cfg = wallet_config(U256::ZERO);
    let poi_runtime = WalletPoiRuntime::from_policy(
        &GlobalPoiPolicy::PoiProxy {
            rpc_url: mock.url.clone(),
        },
        None,
    );
    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let public_data_plane = ChainPublicDataPlane::new(Arc::clone(&db), Arc::new(AtomicU64::new(0)));
    let status_reader = poi_runtime
        .status_reader_for_job(&public_data_plane, &cfg, &list_keys)
        .await
        .expect("remote POI status reader");

    let changed = refresh_wallet_poi_statuses_selected(
        status_reader.as_reader(),
        cfg.chain.chain_id,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    let request = mock
        .requests
        .recv_timeout(Duration::from_secs(2))
        .expect("remote status request");
    assert_eq!(request["method"], "ppoi_pois_per_list");
    assert!(changed);
    assert_eq!(
        wallet_utxos[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn indexed_artifacts_proxy_fallback_calls_remote_when_corpus_unavailable() {
    let list_key = FixedBytes::from([0x12; 32]);
    let list_keys = vec![list_key];
    let mut wallet_utxos = vec![test_wallet_utxo(1)];
    let blinded_commitment = wallet_utxos[0].utxo.poi.blinded_commitment;
    let mock = spawn_poi_rpc(serde_json::json!({
        hex::encode_prefixed(blinded_commitment): {
            hex::encode(list_key): "Valid",
        }
    }))
    .await;
    let cfg = wallet_config(U256::ZERO);
    let poi_runtime = test_artifact_poi_runtime_with_fallback(mock.url.clone());
    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let public_data_plane = test_public_data_plane_with_poi_service(&db);
    let status_reader = poi_runtime
        .status_reader_for_job(&public_data_plane, &cfg, &list_keys)
        .await
        .expect("fallback POI status reader");

    let changed = refresh_wallet_poi_statuses_selected(
        status_reader.as_reader(),
        cfg.chain.chain_id,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(changed);
    assert_eq!(
        wallet_utxos[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );
    let request = mock
        .requests
        .recv_timeout(Duration::from_secs(2))
        .expect("remote fallback status request");
    assert_eq!(request["method"], "ppoi_pois_per_list");
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn indexed_artifacts_proxy_fallback_does_not_probe_remote_for_ready_local_missing() {
    let list_key = FixedBytes::from([0x13; 32]);
    let list_keys = vec![list_key];
    let mut wallet_utxos = vec![test_wallet_utxo(1)];
    let mock = spawn_poi_rpc(serde_json::json!({})).await;
    let cfg = wallet_config(U256::ZERO);
    let poi_runtime = test_artifact_poi_runtime_with_fallback(mock.url.clone());
    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let public_data_plane = test_public_data_plane_with_poi_service(&db);
    let mut cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        cfg.chain.chain_id,
        DEFAULT_TXID_VERSION,
        list_key,
    ));
    cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: [0x99; 32],
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply artifact event");
    cache.accept_current_roots();
    seed_data_plane_poi_cache(&public_data_plane, cfg.chain.chain_id, list_key, cache).await;
    let status_reader = poi_runtime
        .status_reader_for_job(&public_data_plane, &cfg, &list_keys)
        .await
        .expect("local POI status reader");

    let changed = refresh_wallet_poi_statuses_selected(
        status_reader.as_reader(),
        cfg.chain.chain_id,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(changed);
    assert_eq!(
        wallet_utxos[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Missing)
    );
    assert!(
        mock.requests
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "ready local missing must not trigger remote fallback"
    );
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_poi_status_client_uses_configured_rpc_url() {
    let list_key = FixedBytes::from([0x11; 32]);
    let mock = spawn_poi_rpc(serde_json::json!({})).await;
    let client = wallet_poi_status_client(&mock.url, None).expect("POI client");

    client
        .pois_per_list(DEFAULT_TXID_VERSION, EVM_CHAIN_TYPE, 1, &[list_key], &[])
        .await
        .expect("POI status request");

    let request = mock
        .requests
        .recv_timeout(Duration::from_secs(2))
        .expect("configured POI RPC request");
    assert_eq!(request["method"], "ppoi_pois_per_list");
}

#[tokio::test]
async fn poi_proxy_merkle_proof_source_calls_remote_merkle_proofs() {
    let list_key = FixedBytes::from([0x11; 32]);
    let blinded_commitment = FixedBytes::from([0x22; 32]);
    let mock = spawn_poi_rpc(serde_json::json!([{
        "leaf": hex::encode_prefixed(blinded_commitment),
        "elements": [],
        "indices": "0x00",
        "root": "0x00",
    }]))
    .await;
    let client = PoiRpcClient::new(mock.url.clone());

    let proofs = client
        .poi_merkle_proofs(
            DEFAULT_TXID_VERSION,
            EVM_CHAIN_TYPE,
            1,
            &list_key,
            &[blinded_commitment],
        )
        .await
        .expect("remote proof response");

    let request = mock
        .requests
        .recv_timeout(Duration::from_secs(2))
        .expect("remote proof request");
    assert_eq!(request["method"], "ppoi_merkle_proofs");
    assert_eq!(proofs.len(), 1);
    assert_eq!(proofs[0].leaf, U256::from_be_bytes(blinded_commitment.0));
}

#[tokio::test]
async fn local_poi_merkle_proof_source_reads_cache_without_remote_merkle_proofs() {
    let list_key = FixedBytes::from([0x11; 32]);
    let blinded_commitment = FixedBytes::from([0x22; 32]);
    let mut cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        1,
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
        .expect("apply artifact event");
    cache.accept_current_roots();
    let local_caches = Arc::new(RwLock::new(BTreeMap::from([(list_key, cache)])));
    let source = LocalPoiMerkleProofSource::new(local_caches);

    let proofs = source
        .poi_merkle_proofs(
            DEFAULT_TXID_VERSION,
            EVM_CHAIN_TYPE,
            1,
            &list_key,
            &[blinded_commitment],
        )
        .await
        .expect("local proof");

    assert_eq!(proofs.len(), 1);
    assert_eq!(proofs[0].leaf, U256::from_be_bytes(blinded_commitment.0));
}

#[tokio::test]
async fn local_output_poi_proof_preflight_fails_before_expensive_recovery_when_cache_missing() {
    let nullifying_key = uint!(9_U256);
    let cfg = wallet_config(nullifying_key);
    let list_key = FixedBytes::from([0x11; 32]);
    let mut input = test_wallet_utxo(0);
    let output = test_wallet_utxo(8);
    input.spent = Some(output.utxo.source.clone());
    let transaction = recovery_test_transaction(&input, &output, nullifying_key);
    let wallet_utxos = vec![input, output.clone()];
    let wallet_nullifiers = WalletNullifierIndex::new(&wallet_utxos, &cfg.scan_keys);
    let mut cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        cfg.chain.chain_id,
        DEFAULT_TXID_VERSION,
        list_key,
    ));
    cache.accept_current_roots();
    let local_caches = Arc::new(RwLock::new(BTreeMap::from([(list_key, cache)])));
    let source = LocalPoiMerkleProofSource::new(local_caches);

    let failure = preflight_local_output_poi_input_proofs(
        Some(&source),
        &cfg,
        &output,
        &wallet_utxos,
        &wallet_nullifiers,
        &[transaction],
        &[list_key],
    )
    .await
    .expect_err("missing local proof preflight should fail");

    assert_eq!(
        failure.status,
        OutputPoiRecoveryStatus::ProofGenerationFailed
    );
    assert!(failure.message.contains("missing POI cache proof data"));
    assert_eq!(
        failure.retry_after,
        Some(OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER)
    );
}

#[tokio::test]
async fn local_output_poi_proof_preflight_checks_transaction_inputs() {
    let nullifying_key = uint!(9_U256);
    let cfg = wallet_config(nullifying_key);
    let list_key = FixedBytes::from([0x11; 32]);
    let mut input = test_wallet_utxo(0);
    let output = test_wallet_utxo(8);
    input.spent = Some(output.utxo.source.clone());
    let transaction = recovery_test_transaction(&input, &output, nullifying_key);
    let wallet_utxos = vec![input.clone(), output.clone()];
    let wallet_nullifiers = WalletNullifierIndex::new(&wallet_utxos, &cfg.scan_keys);
    let mut cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        cfg.chain.chain_id,
        DEFAULT_TXID_VERSION,
        list_key,
    ));
    cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: *input.utxo.poi.blinded_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply input POI event");
    let local_caches = Arc::new(RwLock::new(BTreeMap::from([(list_key, cache)])));
    let source = LocalPoiMerkleProofSource::new(local_caches);

    preflight_local_output_poi_input_proofs(
        Some(&source),
        &cfg,
        &output,
        &wallet_utxos,
        &wallet_nullifiers,
        &[transaction],
        &[list_key],
    )
    .await
    .expect("input proof preflight succeeds");
}

async fn assert_stale_output_recovery_source_stops_before_transport(cached_input: bool) {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let nullifying_key = uint!(9_U256);
    let mut cfg = wallet_config(nullifying_key);
    cfg.cache_key = if cached_input {
        "wallet-stale-cached-recovery".to_string()
    } else {
        "wallet-stale-uncached-recovery".to_string()
    };
    let list_key = FixedBytes::from([0x21; 32]);
    let required_poi_list_keys = [list_key];
    let mut input = test_wallet_utxo(0);
    let mut candidate = test_wallet_utxo(8);
    candidate
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    input.spent = Some(candidate.utxo.source.clone());
    let wallet_utxos = vec![input, candidate.clone()];

    let mut stale_recovery = output_poi_recovery_record(
        cfg.chain.chain_id,
        &cfg.cache_key,
        candidate.utxo.poi.commitment,
        OutputPoiRecoveryStatus::Recoverable,
        None,
    );
    if cached_input {
        stale_recovery.tx_input = Some(vec![0xde, 0xad]);
    }
    assert_ne!(stale_recovery.source_tx_hash, candidate.utxo.source.tx_hash);
    store
        .put_output_poi_recovery(&stale_recovery)
        .expect("store stale recovery");

    let mut handle = test_wallet_handle(wallet_utxos.clone());
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let proof_transport = Arc::new(RecordingPoiProofSource::default());
    let private_poi =
        WalletPrivatePoiClients::for_proofs(authority.remote_authority(), proof_transport.clone());
    let (rpc_url, rpc_requests) =
        spawn_http_response(serde_json::json!({}).to_string().into_bytes()).await;
    let rpcs = QueryRpcPool::new(vec![rpc_url.clone()], Duration::from_secs(1));
    let poi_client = PoiRpcClient::new(rpc_url);
    let public_data_plane =
        ChainPublicDataPlane::new(Arc::clone(&store), Arc::new(AtomicU64::new(0)));
    let poi_runtime = test_artifact_poi_runtime();
    let forest = MerkleForest::new();
    let wallet_nullifiers = WalletNullifierIndex::new(&wallet_utxos, &cfg.scan_keys);
    let request = OutputPoiRecoveryRequest {
        authority: &authority,
        db: store.as_ref(),
        cache_store: store.as_ref(),
        cfg: &cfg,
        public_data_plane: &public_data_plane,
        rpcs: &rpcs,
        http_client: None,
        indexed_artifact_source: None,
        forest: &forest,
        poi_client: &poi_client,
        private_poi: &private_poi,
        poi_runtime: &poi_runtime,
        active_list_keys: &required_poi_list_keys,
        wallet_utxos: &wallet_utxos,
        force_retry: true,
    };
    let mut fetched_inputs = HashMap::new();

    let failure = build_output_poi_recovery_chunk_from_calldata(CalldataRecoveryBuildRequest {
        request: &request,
        candidate: &candidate,
        source_tx_hash: candidate.utxo.source.tx_hash,
        output_commitment: candidate.utxo.poi.commitment,
        fetched_inputs: &mut fetched_inputs,
        wallet_nullifiers: &wallet_nullifiers,
        required_poi_list_keys: &required_poi_list_keys,
        spending_public_key: [uint!(4_U256), uint!(5_U256)],
        now: now_epoch_secs(),
        candidate_started: Instant::now(),
    })
    .await
    .expect_err("stale recovery source must be rejected");

    assert_eq!(failure.status, OutputPoiRecoveryStatus::TxFetchFailed);
    assert!(
        failure
            .message
            .contains("source transaction does not match")
    );
    assert!(fetched_inputs.is_empty());
    let remote_proof_source = OutputRecoveryRemoteProofSource {
        private_poi: &private_poi,
        authority: &authority,
        db: store.as_ref(),
        cfg: &cfg,
        candidate: &candidate,
        required_poi_list_keys: &required_poi_list_keys,
    };
    assert!(matches!(
        remote_proof_source
            .poi_merkle_proofs(
                DEFAULT_TXID_VERSION,
                EVM_CHAIN_TYPE,
                cfg.chain.chain_id,
                &list_key,
                &[candidate.utxo.poi.blinded_commitment],
            )
            .await,
        Err(PreTransactionPoiError::ProofSource(_))
    ));
    assert!(
        rpc_requests
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "stale recovery source must not fetch transaction calldata"
    );
    assert_eq!(
        proof_transport.calls(),
        0,
        "stale recovery source must not reach POI proof transport"
    );

    drop(public_data_plane);
    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn stale_cached_output_recovery_source_stops_before_transport() {
    assert_stale_output_recovery_source_stops_before_transport(true).await;
}

#[tokio::test]
async fn stale_uncached_output_recovery_source_stops_before_transport() {
    assert_stale_output_recovery_source_stops_before_transport(false).await;
}

#[tokio::test]
async fn live_poi_tail_applies_public_leaves_and_validates_root() {
    let list_key = FixedBytes::from([7_u8; 32]);
    let blinded_commitment = FixedBytes::from([0x33; 32]);
    let artifact_commitment = FixedBytes::from([0x22; 32]);
    let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
    let mut expected_cache = PoiCache::new(identity.clone());
    expected_cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: *artifact_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply artifact checkpoint event");
    expected_cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 1,
            blinded_commitment: *blinded_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Shield,
        }])
        .expect("apply expected leaf");
    let expected_root = *expected_cache
        .current_roots()
        .get(&0)
        .expect("expected root");
    let leaves = vec![U256::from_be_bytes(blinded_commitment.0)];
    let mock =
        spawn_poi_rpc_sequence(vec![poi_leaf_response(&leaves), serde_json::json!(true)]).await;
    let client = PoiRpcClient::new(mock.url.clone());
    let mut cache = PoiCache::new(identity);
    cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: *artifact_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply artifact checkpoint event");
    cache.accept_current_roots();

    let outcome = sync_live_poi_event_tail(&client, &mut cache)
        .await
        .expect("live tail sync");

    let request = mock
        .requests
        .recv_timeout(Duration::from_secs(2))
        .expect("remote leaf request");
    assert_eq!(request["method"], "ppoi_poi_merkletree_leaves");
    let request = mock
        .requests
        .recv_timeout(Duration::from_secs(2))
        .expect("remote root validation request");
    assert_eq!(request["method"], "ppoi_validate_poi_merkleroots");
    assert_eq!(outcome.events, 1);
    assert_eq!(outcome.start_index, 1);
    assert_eq!(outcome.next_event_index, 2);
    assert_eq!(cache.current_roots().get(&0), Some(&expected_root));
    let proof = cache
        .poi_merkle_proofs(&[blinded_commitment])
        .expect("proof after live root validation");
    assert_eq!(proof[0].leaf, U256::from_be_bytes(blinded_commitment.0));
}

#[tokio::test]
async fn live_poi_tail_stops_at_merkle_zero_padding() {
    let list_key = FixedBytes::from([8_u8; 32]);
    let blinded_commitment = FixedBytes::from([0x44; 32]);
    let artifact_commitment = FixedBytes::from([0x22; 32]);
    let zero_leaf = FixedBytes::from(MERKLE_ZERO_VALUE.to_be_bytes::<32>());
    let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
    let mut expected_cache = PoiCache::new(identity.clone());
    expected_cache
        .apply_verified_artifact_events(&[
            poi::artifacts::SnapshotEvent {
                event_index: 0,
                blinded_commitment: *artifact_commitment,
                signature: [0_u8; 64],
                event_type: PoiEventType::Transact,
            },
            poi::artifacts::SnapshotEvent {
                event_index: 1,
                blinded_commitment: *blinded_commitment,
                signature: [0_u8; 64],
                event_type: PoiEventType::Shield,
            },
        ])
        .expect("apply expected leaves");
    let expected_root = *expected_cache
        .current_roots()
        .get(&0)
        .expect("expected root");
    let leaves = vec![
        U256::from_be_bytes(blinded_commitment.0),
        MERKLE_ZERO_VALUE,
        U256::from_be_bytes([0x55; 32]),
    ];
    let mock =
        spawn_poi_rpc_sequence(vec![poi_leaf_response(&leaves), serde_json::json!(true)]).await;
    let client = PoiRpcClient::new(mock.url.clone());
    let mut cache = PoiCache::new(identity);
    cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: *artifact_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply artifact checkpoint event");
    cache.accept_current_roots();

    let outcome = sync_live_poi_event_tail(&client, &mut cache)
        .await
        .expect("live tail sync");

    assert_eq!(outcome.events, 1);
    assert_eq!(outcome.start_index, 1);
    assert_eq!(outcome.next_event_index, 2);
    assert_eq!(cache.current_roots().get(&0), Some(&expected_root));
    assert!(cache.position(&zero_leaf).is_none());
}

#[test]
fn dense_merkle_tree_matches_forest_proof_and_removal_roots() {
    let mut forest = MerkleForest::default();
    for position in [0_u64, 1, 2, 7, 8, 9, 42] {
        forest
            .insert_leaf(MerkleTreeUpdate {
                tree_number: 0,
                tree_position: position,
                hash: U256::from(position + 100),
            })
            .expect("insert leaf");
    }

    let mut dense = DenseMerkleTree::from_forest_prefix(&forest, 0, 43);
    let dense_proof = dense.prove(7);
    let sparse_proof = forest
        .prove_with_leaf_count(0, 7, 43)
        .expect("sparse proof");
    assert_eq!(dense_proof.root, sparse_proof.root);
    assert_eq!(dense_proof.leaf, sparse_proof.leaf);
    assert_eq!(dense_proof.path_elements, sparse_proof.path_elements);
    assert_eq!(dense_proof.path_indices, sparse_proof.path_indices);

    for position in (10_u64..43).rev() {
        dense.remove_leaf(position);
    }
    let dense_short_proof = dense.prove(7);
    let sparse_short_proof = forest
        .prove_with_leaf_count(0, 7, 10)
        .expect("sparse short proof");
    assert_eq!(dense_short_proof.root, sparse_short_proof.root);
    assert_eq!(
        dense_short_proof.path_elements,
        sparse_short_proof.path_elements
    );
}

#[tokio::test]
async fn tailed_cache_install_skips_when_current_cache_advanced() {
    let list_key = FixedBytes::from([0x11; 32]);
    let identity = PoiCacheIdentity::new(EVM_CHAIN_TYPE, 1, DEFAULT_TXID_VERSION, list_key);
    let initial_commitment = FixedBytes::from([0x22; 32]);
    let stale_tail_commitment = FixedBytes::from([0x33; 32]);
    let current_tail_commitment = FixedBytes::from([0x44; 32]);

    let mut initial_cache = PoiCache::new(identity);
    initial_cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: *initial_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply initial event");
    initial_cache.accept_current_roots();
    let original_next_event_index = initial_cache.progress().next_event_index;

    let local_caches = Arc::new(RwLock::new(BTreeMap::from([(
        list_key,
        initial_cache.clone(),
    )])));
    let mut stale_tail_cache = initial_cache;
    stale_tail_cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 1,
            blinded_commitment: *stale_tail_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply stale tail event");

    {
        let mut locked = local_caches.write().await;
        let current = locked.get_mut(&list_key).expect("current cache");
        current
            .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
                event_index: 1,
                blinded_commitment: *current_tail_commitment,
                signature: [0_u8; 64],
                event_type: PoiEventType::Transact,
            }])
            .expect("advance current cache");
        current.accept_current_roots();
    }

    let installed = install_tailed_poi_cache_if_current(
        &local_caches,
        list_key,
        stale_tail_cache,
        original_next_event_index,
    )
    .await;

    let locked = local_caches.read().await;
    let current = locked.get(&list_key).expect("current cache");
    assert!(!installed);
    assert!(current.position(&current_tail_commitment).is_some());
    assert!(current.position(&stale_tail_commitment).is_none());
}

#[tokio::test]
async fn poi_status_refresh_needed_after_indexed_delta_discovers_utxo() {
    let client = RecordingPoiStatusClient::default();
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let cfg = wallet_config(U256::ZERO);
    let mut wallet_utxos = Vec::new();
    let delta = WalletLogDelta {
        utxos: vec![test_wallet_utxo(1).utxo],
        nullifiers: Vec::new(),
        commitment_observations: Vec::new(),
    };

    assert!(apply_wallet_delta_to_vec(&cfg, &mut wallet_utxos, delta));
    assert!(wallet_poi_status_refresh_needed(&wallet_utxos, &list_keys));

    let changed = refresh_wallet_poi_statuses_selected(
        &client,
        cfg.chain.chain_id,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(changed);
    assert!(!wallet_poi_status_refresh_needed(&wallet_utxos, &list_keys));
    assert_eq!(client.calls().len(), 1);
    assert_eq!(
        wallet_utxos[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );
    assert!(wallet_utxos[0].utxo.poi.refreshed_at.is_some());
}

#[test]
fn stale_missing_poi_status_is_refresh_needed_after_ttl() {
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut wallet_utxo = test_wallet_utxo(1);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    wallet_utxo.utxo.poi.refreshed_at = Some(100);
    let wallet_utxos = vec![wallet_utxo];

    assert!(!wallet_poi_status_refresh_needed_for_selection(
        &wallet_utxos,
        &list_keys,
        WalletPoiRefreshSelection::RecoverableStale {
            now: 100 + WALLET_POI_RECOVERABLE_REFRESH_AFTER.as_secs() - 1,
        },
    ));
    assert!(wallet_poi_status_refresh_needed_for_selection(
        &wallet_utxos,
        &list_keys,
        WalletPoiRefreshSelection::RecoverableStale {
            now: 100 + WALLET_POI_RECOVERABLE_REFRESH_AFTER.as_secs(),
        },
    ));
}

#[test]
fn stale_transact_missing_without_pending_context_is_timer_retryable() {
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut wallet_utxo = test_wallet_utxo_with_kind(1, UtxoCommitmentKind::Transact);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    wallet_utxo.utxo.poi.refreshed_at = Some(100);
    let wallet_utxos = vec![wallet_utxo];

    assert!(wallet_poi_status_refresh_needed_for_selection(
        &wallet_utxos,
        &list_keys,
        WalletPoiRefreshSelection::RecoverableStale {
            now: 100 + WALLET_POI_RECOVERABLE_REFRESH_AFTER.as_secs(),
        },
    ));
}

#[test]
fn stale_shield_missing_remains_timer_retryable_without_pending_context() {
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut wallet_utxo = test_wallet_utxo_with_kind(1, UtxoCommitmentKind::Shield);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    wallet_utxo.utxo.poi.refreshed_at = Some(100);
    let wallet_utxos = vec![wallet_utxo];

    assert!(wallet_poi_status_refresh_needed_for_selection(
        &wallet_utxos,
        &list_keys,
        WalletPoiRefreshSelection::RecoverableStale {
            now: 100 + WALLET_POI_RECOVERABLE_REFRESH_AFTER.as_secs(),
        },
    ));
}

#[tokio::test]
async fn forced_recoverable_poi_refresh_batches_missing_utxos() {
    let client = RecordingPoiStatusClient::default();
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut valid = test_wallet_utxo(0);
    valid.utxo.poi.statuses.insert(list_key, PoiStatus::Valid);
    valid.utxo.poi.refreshed_at = Some(100);
    let mut missing_one = test_wallet_utxo(1);
    missing_one
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    missing_one.utxo.poi.refreshed_at = Some(100);
    let mut missing_two = test_wallet_utxo(2);
    missing_two
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    missing_two.utxo.poi.refreshed_at = Some(100);
    let mut wallet_utxos = vec![valid, missing_one, missing_two];

    let changed = refresh_wallet_poi_statuses_selected(
        &client,
        1,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::Recoverable,
    )
    .await;

    assert!(changed);
    let calls = client.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1.len(), 2);
    assert!(
        wallet_utxos
            .iter()
            .all(|wallet_utxo| wallet_utxo.utxo.poi.is_valid_for_lists(&list_keys))
    );
}

#[tokio::test]
async fn required_or_recoverable_poi_refresh_skips_currently_valid_utxos() {
    let client = RecordingPoiStatusClient::default();
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut valid = test_wallet_utxo(0);
    valid.utxo.poi.statuses.insert(list_key, PoiStatus::Valid);
    valid.utxo.poi.refreshed_at = Some(100);
    let mut valid_without_refresh_time = test_wallet_utxo(1);
    valid_without_refresh_time
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Valid);
    let mut missing = test_wallet_utxo(2);
    missing
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    missing.utxo.poi.refreshed_at = Some(100);
    let mut wallet_utxos = vec![valid, valid_without_refresh_time, missing];

    let changed = refresh_wallet_poi_statuses_selected(
        &client,
        1,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(changed);
    let calls = client.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1.len(), 2);
    assert_eq!(wallet_utxos[0].utxo.poi.refreshed_at, Some(100));
    assert!(wallet_utxos[1].utxo.poi.refreshed_at.is_some());
    assert_eq!(
        wallet_utxos[2].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );
}

#[tokio::test]
async fn poi_status_refresh_timestamp_only_update_is_changed() {
    let client = RecordingPoiStatusClient::default();
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut valid_without_refresh_time = test_wallet_utxo(1);
    valid_without_refresh_time
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Valid);
    let mut wallet_utxos = vec![valid_without_refresh_time];

    assert!(wallet_poi_status_refresh_needed(&wallet_utxos, &list_keys));
    let changed = refresh_wallet_poi_statuses_selected(
        &client,
        1,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(changed);
    assert!(!wallet_poi_status_refresh_needed(&wallet_utxos, &list_keys));
    assert_eq!(client.calls().len(), 1);
    assert_eq!(
        wallet_utxos[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );
    assert!(wallet_utxos[0].utxo.poi.refreshed_at.is_some());
}

#[tokio::test]
async fn poi_status_refresh_keeps_failed_chunks_unknown() {
    let client = RecordingPoiStatusClient::default();
    client.fail_call(0);
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut wallet_utxos = (0..=WALLET_POI_STATUS_BATCH_SIZE)
        .map(|position| test_wallet_utxo(position as u64))
        .collect::<Vec<_>>();

    let changed = refresh_wallet_poi_statuses_selected(
        &client,
        1,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(changed);
    assert_eq!(client.calls().len(), 2);
    assert_eq!(
        wallet_utxos[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Unknown)
    );
    assert_eq!(wallet_utxos[0].utxo.poi.refreshed_at, None);
    assert_eq!(
        wallet_utxos[WALLET_POI_STATUS_BATCH_SIZE]
            .utxo
            .poi
            .statuses
            .get(&list_key),
        Some(&PoiStatus::Valid)
    );
    assert!(
        wallet_utxos[WALLET_POI_STATUS_BATCH_SIZE]
            .utxo
            .poi
            .refreshed_at
            .is_some()
    );
}

#[tokio::test]
async fn pending_output_poi_matches_undecryptable_observation_and_marks_submitted() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x77; 32]);
    let list_key = FixedBytes::from([0x44; 32]);
    store
        .put_pending_output_poi_context(&pending_output_record(
            chain_id,
            output_commitment,
            list_key,
        ))
        .expect("store pending context");
    let submitter = RecordingPendingOutputPoiSubmitter::default();
    let observation = CommitmentObservation {
        tree: 12,
        position: 34,
        commitment: U256::from_be_bytes(output_commitment.0),
        source: source(8),
    };

    process_pending_output_poi_observations(
        &store,
        chain_id,
        "wallet-1",
        &[observation],
        Some(&submitter),
    )
    .await;

    let loaded = store
        .get_pending_output_poi_context(chain_id, "wallet-1", &output_commitment)
        .expect("load pending context")
        .expect("pending context present");
    let observed = loaded.observation.expect("observation recorded");
    assert_eq!(observed.output_tree, 12);
    assert_eq!(observed.output_position, 34);
    assert_eq!(observed.tx_hash, source(8).tx_hash);
    assert_eq!(loaded.submitted_poi_list_keys, vec![list_key]);
    assert_eq!(submitter.calls(), vec![(output_commitment, 12, 34)]);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn recovered_pending_output_poi_uses_transact_proof_submission() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x79; 32]);
    let list_key = FixedBytes::from([0x47; 32]);
    let mut record = pending_output_record(chain_id, output_commitment, list_key);
    record.txid_merkleroot_index = Some(105_572);
    let expected_blinded_commitment = record
        .pre_transaction_pois_per_txid_leaf_per_list
        .get(&list_key)
        .expect("list")
        .values()
        .next()
        .expect("poi")
        .blinded_commitments_out[0];
    store
        .put_pending_output_poi_context(&record)
        .expect("store pending context");
    let submitter = RecordingPendingOutputPoiSubmitter::default();
    let observation = CommitmentObservation {
        tree: 12,
        position: 34,
        commitment: U256::from_be_bytes(output_commitment.0),
        source: source(8),
    };

    process_pending_output_poi_observations(
        &store,
        chain_id,
        "wallet-1",
        &[observation],
        Some(&submitter),
    )
    .await;

    let loaded = store
        .get_pending_output_poi_context(chain_id, "wallet-1", &output_commitment)
        .expect("load pending context")
        .expect("pending context present");
    assert_eq!(loaded.submitted_poi_list_keys, vec![list_key]);
    assert_eq!(
        submitter.calls(),
        vec![(expected_blinded_commitment, 105_572, 0)]
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn pending_output_poi_matches_wallet_owned_observation_and_keeps_utxo() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let chain_id = 1;
    let utxo = test_wallet_utxo(36).utxo;
    let output_commitment = FixedBytes::from(utxo.note.commitment().to_be_bytes::<32>());
    let list_key = FixedBytes::from([0x46; 32]);
    store
        .put_pending_output_poi_context(&pending_output_record(
            chain_id,
            output_commitment,
            list_key,
        ))
        .expect("store pending context");
    let submitter = RecordingPendingOutputPoiSubmitter::default();
    let observation = CommitmentObservation {
        tree: utxo.tree,
        position: utxo.position,
        commitment: utxo.note.commitment(),
        source: source(10),
    };
    let delta = WalletLogDelta {
        utxos: vec![utxo],
        nullifiers: Vec::new(),
        commitment_observations: vec![observation],
    };

    process_pending_output_poi_observations(
        &store,
        chain_id,
        "wallet-1",
        &delta.commitment_observations,
        Some(&submitter),
    )
    .await;
    let mut wallet_utxos = Vec::new();
    let changed = apply_wallet_delta_to_vec(&wallet_config(U256::ZERO), &mut wallet_utxos, delta);

    assert!(changed);
    assert_eq!(wallet_utxos.len(), 1);
    assert_eq!(wallet_utxos[0].utxo.position, 36);
    let loaded = store
        .get_pending_output_poi_context(chain_id, "wallet-1", &output_commitment)
        .expect("load pending context")
        .expect("pending context present");
    assert!(loaded.observation.is_some());
    assert_eq!(loaded.submitted_poi_list_keys, vec![list_key]);
    assert_eq!(submitter.calls(), vec![(output_commitment, 2, 36)]);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn submitted_pending_output_poi_verification_deletes_valid_context() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x90; 32]);
    let list_key = FixedBytes::from([0x91; 32]);
    let mut pending = pending_output_record(chain_id, output_commitment, list_key);
    pending.observation = Some(local_db::PendingOutputPoiObservation {
        output_tree: 3,
        output_position: 12,
        tx_hash: source(12).tx_hash,
        block_number: 12,
        block_timestamp: 1_700_000_012,
    });
    pending.submitted_poi_list_keys = vec![list_key];
    let derived_blinded_commitment = pending_output_poi_submit_identity(
        &pending,
        pending.observation.as_ref().expect("observation"),
    )
    .expect("identity")
    .derived_blinded_commitment;
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let client = RecordingPoiStatusClient::default();

    let outcome =
        verify_submitted_pending_output_pois(&client, &store, chain_id, "wallet-1", &[list_key])
            .await;

    assert_eq!(outcome.completed, 1);
    assert_eq!(outcome.pending, 0);
    assert!(
        store
            .get_pending_output_poi_context(chain_id, "wallet-1", &output_commitment)
            .expect("load pending")
            .is_none()
    );
    let calls = client.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, vec![list_key]);
    assert_eq!(calls[0].1[0].blinded_commitment, derived_blinded_commitment);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn proxy_maintenance_refresh_before_verification_reconciles_valid_context() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let chain_id = 1;
    let list_key = FixedBytes::from([0x94; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = "wallet-1".to_string();
    let mut wallet_utxo = test_wallet_utxo(14);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::ProofSubmitted);
    let output_commitment = wallet_utxo.utxo.poi.commitment;
    let source_tx_hash = wallet_utxo.utxo.source.tx_hash;
    let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let mut recovery = output_poi_recovery_record(
        chain_id,
        &cfg.cache_key,
        output_commitment,
        OutputPoiRecoveryStatus::Submitted,
        Some(123),
    );
    recovery.source_tx_hash = source_tx_hash;
    store
        .put_output_poi_recovery(&recovery)
        .expect("store recovery");
    let mut handle = test_wallet_handle(vec![wallet_utxo]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let transport = Arc::new(RecordingPoiStatusClient::default());
    let private_poi =
        WalletPrivatePoiClients::for_status(authority.remote_authority(), transport.clone());
    let poi_runtime = WalletPoiRuntime::from_policy(
        &GlobalPoiPolicy::PoiProxy {
            rpc_url: Url::parse("http://127.0.0.1:1").expect("POI RPC URL"),
        },
        None,
    );
    let public_data_plane =
        ChainPublicDataPlane::new(Arc::clone(&store), Arc::new(AtomicU64::new(0)));
    let revision_before = *handle.rev_rx.borrow();

    assert!(
        refresh_wallet_poi_statuses_remote_authorized(
            &authority,
            &private_poi,
            store.as_ref(),
            store.as_ref(),
            &cfg,
            &[list_key],
            WalletPoiRefreshSelection::RequiredOrRecoverable,
        )
        .await
    );
    assert_eq!(
        handle.utxos.read().await[0]
            .utxo
            .poi
            .statuses
            .get(&list_key),
        Some(&PoiStatus::Valid),
        "maintenance refresh must project Valid before verification"
    );

    let outcome = verify_submitted_pending_output_pois_with_config_authorized(
        &authority,
        &public_data_plane,
        &poi_runtime,
        &private_poi,
        &cfg,
        store.as_ref(),
        store.as_ref(),
        &[list_key],
    )
    .await;

    assert_eq!(outcome.completed, 1);
    assert_eq!(outcome.pending, 0);
    assert_eq!(outcome.errors, 0);
    assert!(
        store
            .get_pending_output_poi_context(chain_id, &cfg.cache_key, &output_commitment)
            .expect("load pending")
            .is_none()
    );
    assert_eq!(
        store
            .get_output_poi_recovery(chain_id, &cfg.cache_key, &output_commitment)
            .expect("load recovery")
            .expect("recovery present")
            .status,
        OutputPoiRecoveryStatus::Valid
    );
    let snapshot = handle.utxos.read().await;
    assert_eq!(
        snapshot[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );
    drop(snapshot);
    let persisted =
        <DbStore as WalletCacheStore>::load_wallet_utxos(store.as_ref(), &cfg.cache_key)
            .expect("load persisted wallet utxos");
    assert_eq!(
        persisted[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );
    assert_ne!(*handle.rev_rx.borrow(), revision_before);
    assert_eq!(transport.calls().len(), 2);

    drop(public_data_plane);
    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn omitted_active_list_becoming_missing_keeps_recovery_recoverable() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let verified_list_key = FixedBytes::from([0x97; 32]);
    let omitted_list_key = FixedBytes::from([0x98; 32]);
    let active_list_keys = [verified_list_key, omitted_list_key];
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = "wallet-omitted-list-became-missing".to_string();
    let mut wallet_utxo = test_wallet_utxo(18);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(verified_list_key, PoiStatus::ProofSubmitted);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(omitted_list_key, PoiStatus::Valid);
    let output_commitment = wallet_utxo.utxo.poi.commitment;
    let source_tx_hash = wallet_utxo.utxo.source.tx_hash;
    let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, verified_list_key);
    pending.submitted_poi_list_keys = vec![verified_list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let mut recovery = output_poi_recovery_record(
        cfg.chain.chain_id,
        &cfg.cache_key,
        output_commitment,
        OutputPoiRecoveryStatus::Submitted,
        Some(123),
    );
    recovery.source_tx_hash = source_tx_hash;
    recovery.attempt_count = 7;
    store
        .put_output_poi_recovery(&recovery)
        .expect("store recovery");
    let mut handle = test_wallet_handle(vec![wallet_utxo]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let reader = Arc::new(BlockingPoiStatusReader::new(started_tx, release_rx));
    let task_store = Arc::clone(&store);
    let task_handle = handle.clone();
    let task_cancel = cancel.clone();
    let task_reader = Arc::clone(&reader);
    let task_cfg = cfg.clone();
    let task = tokio::spawn(async move {
        let authority = WalletPrivateMutationAuthority::new(&task_handle, 0, &task_cancel);
        verify_submitted_pending_output_pois_authorized_with_projection(
            &authority,
            task_reader.as_ref(),
            task_store.as_ref(),
            &task_cfg,
            task_store.as_ref(),
            &active_list_keys,
        )
        .await
    });

    tokio::time::timeout(Duration::from_secs(2), started_rx)
        .await
        .expect("verification started")
        .expect("verification start signal");
    handle.utxos.write().await[0]
        .utxo
        .poi
        .statuses
        .insert(omitted_list_key, PoiStatus::Missing);
    release_tx.send(()).expect("release verification");

    let outcome = task.await.expect("verification task");
    assert_eq!(outcome.completed, 1);
    assert_eq!(outcome.pending, 0);
    assert_eq!(outcome.errors, 0);
    assert!(
        store
            .get_pending_output_poi_context(cfg.chain.chain_id, &cfg.cache_key, &output_commitment,)
            .expect("load pending context")
            .is_none()
    );
    let recovery = store
        .get_output_poi_recovery(cfg.chain.chain_id, &cfg.cache_key, &output_commitment)
        .expect("load recovery")
        .expect("recovery present");
    assert_eq!(recovery.status, OutputPoiRecoveryStatus::Recoverable);
    assert_eq!(recovery.source_tx_hash, source_tx_hash);
    assert_eq!(recovery.attempt_count, 7);
    let current = handle.utxos.read().await;
    assert_eq!(
        current[0].utxo.poi.statuses.get(&verified_list_key),
        Some(&PoiStatus::Valid)
    );
    assert_eq!(
        current[0].utxo.poi.statuses.get(&omitted_list_key),
        Some(&PoiStatus::Missing)
    );
    drop(current);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn verified_valid_reinitializes_mismatched_recovery_source() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let list_key = FixedBytes::from([0x99; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = "wallet-verified-source-replacement".to_string();
    let mut wallet_utxo = test_wallet_utxo(19);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::ProofSubmitted);
    let output_commitment = wallet_utxo.utxo.poi.commitment;
    let source_tx_hash = wallet_utxo.utxo.source.tx_hash;
    let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let mut stale_recovery = output_poi_recovery_record(
        cfg.chain.chain_id,
        &cfg.cache_key,
        output_commitment,
        OutputPoiRecoveryStatus::Submitted,
        Some(123),
    );
    stale_recovery.tx_input = Some(vec![0xde, 0xad]);
    assert_ne!(stale_recovery.source_tx_hash, source_tx_hash);
    store
        .put_output_poi_recovery(&stale_recovery)
        .expect("store stale recovery");
    let mut handle = test_wallet_handle(vec![wallet_utxo]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let client = RecordingPoiStatusClient::default();

    let outcome = verify_submitted_pending_output_pois_authorized_with_projection(
        &authority,
        &client,
        &store,
        &cfg,
        &store,
        &[list_key],
    )
    .await;

    assert_eq!(outcome.completed, 1);
    assert_eq!(outcome.errors, 0);
    assert!(
        store
            .get_pending_output_poi_context(cfg.chain.chain_id, &cfg.cache_key, &output_commitment,)
            .expect("load pending context")
            .is_none()
    );
    let recovery = store
        .get_output_poi_recovery(cfg.chain.chain_id, &cfg.cache_key, &output_commitment)
        .expect("load recovery")
        .expect("recovery present");
    assert_eq!(recovery.source_tx_hash, source_tx_hash);
    assert_eq!(recovery.status, OutputPoiRecoveryStatus::Valid);
    assert_eq!(recovery.tx_input, None);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn authorized_pending_output_poi_retry_resubmits_submitted_lists() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let chain_id = 1;
    let list_key = FixedBytes::from([0x95; 32]);
    let valid_unsubmitted_list_key = FixedBytes::from([0x96; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = "wallet-1".to_string();
    let mut wallet_utxo = test_wallet_utxo(15);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::ProofSubmitted);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(valid_unsubmitted_list_key, PoiStatus::Valid);
    let output_commitment = wallet_utxo.utxo.poi.commitment;
    let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    pending.required_poi_list_keys = vec![list_key, valid_unsubmitted_list_key];
    pending.submitted_poi_list_keys = vec![list_key];
    pending.pre_transaction_pois_per_txid_leaf_per_list.insert(
        valid_unsubmitted_list_key,
        BTreeMap::from([(FixedBytes::from([0x96; 32]), sample_pre_tx_poi(0x16))]),
    );
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let now = now_epoch_secs();
    let mut recovery = output_poi_recovery_record(
        chain_id,
        &cfg.cache_key,
        output_commitment,
        OutputPoiRecoveryStatus::Submitted,
        Some(now.saturating_sub(1)),
    );
    recovery.source_tx_hash = wallet_utxo.utxo.source.tx_hash;
    store
        .put_output_poi_recovery(&recovery)
        .expect("store recovery");
    let mut handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let submitter = Arc::new(RecordingPendingOutputPoiSubmitter::default());
    let private_poi =
        WalletPrivatePoiClients::for_submit(authority.remote_authority(), submitter.clone());

    let submitted = process_pending_output_poi_observations_authorized(
        &authority,
        &store,
        &store,
        &cfg,
        &[list_key, valid_unsubmitted_list_key],
        Some(&private_poi),
        false,
    )
    .await;

    assert_eq!(submitted, 1);
    assert_eq!(submitter.list_key_calls(), vec![vec![list_key]]);
    assert_eq!(
        submitter.calls(),
        vec![(
            output_commitment,
            u64::from(wallet_utxo.utxo.tree),
            wallet_utxo.utxo.position,
        ),]
    );
    let recovery = store
        .get_output_poi_recovery(chain_id, &cfg.cache_key, &output_commitment)
        .expect("load recovery")
        .expect("recovery present");
    assert_eq!(recovery.status, OutputPoiRecoveryStatus::Submitted);
    assert_eq!(recovery.attempt_count, 1);
    assert!(recovery.next_retry_at.is_some_and(|next| next > now));
    let context = store
        .get_pending_output_poi_context(chain_id, &cfg.cache_key, &output_commitment)
        .expect("load pending context")
        .expect("pending context present");
    assert_eq!(context.list_keys(), vec![list_key]);
    assert_eq!(context.submitted_poi_list_keys, vec![list_key]);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn existing_context_submits_missing_subset_and_prunes_nonrecoverable_unsubmitted_lists() {
    for (case, nonrecoverable_status) in [PoiStatus::Valid, PoiStatus::ShieldBlocked]
        .into_iter()
        .enumerate()
    {
        let root_dir = temp_db_root();
        let store = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        let recoverable_list_key = FixedBytes::from([0xa1; 32]);
        let nonrecoverable_list_key = FixedBytes::from([0xa2; 32]);
        let active_list_keys = [recoverable_list_key, nonrecoverable_list_key];
        let mut cfg = wallet_config(U256::ZERO);
        cfg.cache_key = format!("wallet-existing-context-subset-{case}");
        let mut wallet_utxo = test_wallet_utxo(90 + case as u64);
        wallet_utxo
            .utxo
            .poi
            .statuses
            .insert(recoverable_list_key, PoiStatus::Missing);
        wallet_utxo
            .utxo
            .poi
            .statuses
            .insert(nonrecoverable_list_key, nonrecoverable_status);
        let output_commitment = wallet_utxo.utxo.poi.commitment;
        let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, recoverable_list_key);
        pending.required_poi_list_keys = active_list_keys.to_vec();
        pending.pre_transaction_pois_per_txid_leaf_per_list.insert(
            nonrecoverable_list_key,
            BTreeMap::from([(FixedBytes::from([0xa3; 32]), sample_pre_tx_poi(0x17))]),
        );
        store
            .put_pending_output_poi_context(&pending)
            .expect("store pending context");
        let mut handle = test_wallet_handle(vec![wallet_utxo.clone()]);
        handle.cache_key = cfg.cache_key.clone();
        let cancel = CancellationToken::new();
        let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
        let submitter = Arc::new(RecordingPendingOutputPoiSubmitter::default());
        let private_poi =
            WalletPrivatePoiClients::for_submit(authority.remote_authority(), submitter.clone());

        let submitted = process_pending_output_poi_observations_authorized(
            &authority,
            &store,
            &store,
            &cfg,
            &active_list_keys,
            Some(&private_poi),
            false,
        )
        .await;

        assert_eq!(submitted, 1);
        assert_eq!(
            submitter.list_key_calls(),
            vec![vec![recoverable_list_key]],
            "{nonrecoverable_status:?} list must not reach submission transport"
        );
        let persisted = store
            .get_pending_output_poi_context(cfg.chain.chain_id, &cfg.cache_key, &output_commitment)
            .expect("load pending context")
            .expect("pending context present");
        assert_eq!(persisted.list_keys(), vec![recoverable_list_key]);
        assert_eq!(
            persisted.submitted_poi_list_keys,
            vec![recoverable_list_key]
        );
        assert_eq!(
            persisted
                .pre_transaction_pois_per_txid_leaf_per_list
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            vec![recoverable_list_key]
        );

        drop(store);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }
}

#[tokio::test]
async fn pending_submission_preflight_repeatedly_rejects_recovery_source_mismatch() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let list_key = FixedBytes::from([0x97; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = "wallet-recovery-source-mismatch".to_string();
    let mut wallet_utxo = test_wallet_utxo(17);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    let output_commitment = wallet_utxo.utxo.poi.commitment;
    let pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let recovery = output_poi_recovery_record(
        cfg.chain.chain_id,
        &cfg.cache_key,
        output_commitment,
        OutputPoiRecoveryStatus::Recoverable,
        None,
    );
    assert_ne!(
        recovery.source_tx_hash,
        pending.observation.as_ref().expect("observation").tx_hash
    );
    store
        .put_output_poi_recovery(&recovery)
        .expect("store mismatched recovery");
    let mut handle = test_wallet_handle(vec![wallet_utxo]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let submitter = Arc::new(RecordingPendingOutputPoiSubmitter::default());
    let private_poi =
        WalletPrivatePoiClients::for_submit(authority.remote_authority(), submitter.clone());

    for _ in 0..2 {
        assert_eq!(
            process_pending_output_poi_observations_authorized(
                &authority,
                &store,
                &store,
                &cfg,
                &[list_key],
                Some(&private_poi),
                false,
            )
            .await,
            0
        );
    }
    assert!(
        submitter.calls().is_empty(),
        "mismatched recovery source must never reach submission transport"
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn authorized_pending_output_poi_skips_output_that_no_longer_needs_poi() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let list_key = FixedBytes::from([0x96; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = "wallet-1".to_string();
    let mut wallet_utxo = test_wallet_utxo(16);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Valid);
    let pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let mut handle = test_wallet_handle(vec![wallet_utxo]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let submitter = Arc::new(RecordingPendingOutputPoiSubmitter::default());
    let private_poi =
        WalletPrivatePoiClients::for_submit(authority.remote_authority(), submitter.clone());

    let submitted = process_pending_output_poi_observations_authorized(
        &authority,
        &store,
        &store,
        &cfg,
        &[list_key],
        Some(&private_poi),
        false,
    )
    .await;

    assert_eq!(submitted, 0);
    assert!(submitter.calls().is_empty());

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn pending_output_poi_maintenance_is_scoped_to_wallet_id() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let chain_id = 1;
    let list_key = FixedBytes::from([0xa1; 32]);
    let wallet_a_commitment = FixedBytes::from([0xa2; 32]);
    let wallet_b_commitment = FixedBytes::from([0xa3; 32]);
    let mut wallet_a = pending_output_record(chain_id, wallet_a_commitment, list_key);
    wallet_a.wallet_id = "wallet-a".to_string();
    wallet_a.observation = Some(local_db::PendingOutputPoiObservation {
        output_tree: 3,
        output_position: 12,
        tx_hash: source(12).tx_hash,
        block_number: 12,
        block_timestamp: 1_700_000_012,
    });
    let mut wallet_b = pending_output_record(chain_id, wallet_b_commitment, list_key);
    wallet_b.wallet_id = "wallet-b".to_string();
    wallet_b.observation = Some(local_db::PendingOutputPoiObservation {
        output_tree: 4,
        output_position: 13,
        tx_hash: source(13).tx_hash,
        block_number: 13,
        block_timestamp: 1_700_000_013,
    });
    store
        .put_pending_output_poi_context(&wallet_a)
        .expect("store wallet A pending context");
    store
        .put_pending_output_poi_context(&wallet_b)
        .expect("store wallet B pending context");
    let submitter = RecordingPendingOutputPoiSubmitter::default();

    process_pending_output_poi_observations(&store, chain_id, "wallet-a", &[], Some(&submitter))
        .await;

    assert_eq!(submitter.calls(), vec![(wallet_a_commitment, 3, 12)]);
    let wallet_a = store
        .get_pending_output_poi_context(chain_id, "wallet-a", &wallet_a_commitment)
        .expect("load wallet A pending context")
        .expect("wallet A pending context present");
    assert_eq!(wallet_a.submitted_poi_list_keys, vec![list_key]);
    let mut wallet_b = store
        .get_pending_output_poi_context(chain_id, "wallet-b", &wallet_b_commitment)
        .expect("load wallet B pending context")
        .expect("wallet B pending context present");
    assert!(wallet_b.submitted_poi_list_keys.is_empty());

    wallet_b.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&wallet_b)
        .expect("mark wallet B submitted");
    let wallet_a_identity = pending_output_poi_submit_identity(
        &wallet_a,
        wallet_a.observation.as_ref().expect("wallet A observation"),
    )
    .expect("wallet A identity");
    let wallet_b_identity = pending_output_poi_submit_identity(
        &wallet_b,
        wallet_b.observation.as_ref().expect("wallet B observation"),
    )
    .expect("wallet B identity");
    assert_ne!(
        wallet_a_identity.derived_blinded_commitment,
        wallet_b_identity.derived_blinded_commitment
    );
    let client = RecordingPoiStatusClient::default();

    let outcome =
        verify_submitted_pending_output_pois(&client, &store, chain_id, "wallet-a", &[list_key])
            .await;

    assert_eq!(outcome.completed, 1);
    assert_eq!(outcome.pending, 0);
    assert!(
        store
            .get_pending_output_poi_context(chain_id, "wallet-a", &wallet_a_commitment)
            .expect("load wallet A pending context")
            .is_none()
    );
    assert!(
        store
            .get_pending_output_poi_context(chain_id, "wallet-b", &wallet_b_commitment)
            .expect("load wallet B pending context")
            .is_some()
    );
    let calls = client.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, vec![list_key]);
    assert_eq!(
        calls[0].1[0].blinded_commitment,
        wallet_a_identity.derived_blinded_commitment
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn submitted_pending_output_poi_verification_allows_retry_after_missing_delay() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x92; 32]);
    let list_key = FixedBytes::from([0x93; 32]);
    let mut pending = pending_output_record(chain_id, output_commitment, list_key);
    pending.observation = Some(local_db::PendingOutputPoiObservation {
        output_tree: 3,
        output_position: 13,
        tx_hash: source(13).tx_hash,
        block_number: 13,
        block_timestamp: 1_700_000_013,
    });
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let client = RecordingPoiStatusClient::default();
    client.set_default_status(PoiStatus::Missing);

    let outcome =
        verify_submitted_pending_output_pois(&client, &store, chain_id, "wallet-1", &[list_key])
            .await;

    assert_eq!(outcome.completed, 0);
    assert_eq!(outcome.pending, 1);
    let mut recovery = store
        .get_output_poi_recovery(chain_id, &pending.wallet_id, &output_commitment)
        .expect("load recovery")
        .expect("recovery present");
    assert_eq!(recovery.status, OutputPoiRecoveryStatus::Submitted);
    assert!(recovery.next_retry_at.is_some());
    recovery.next_retry_at = Some(0);
    store
        .put_output_poi_recovery(&recovery)
        .expect("force retry due");
    let submitter = RecordingPendingOutputPoiSubmitter::default();

    process_pending_output_poi_observations_inner(
        &store,
        chain_id,
        "wallet-1",
        &[],
        Some(&submitter),
        false,
    )
    .await;

    assert_eq!(submitter.calls(), vec![(output_commitment, 3, 13)]);
    let updated = store
        .get_output_poi_recovery(chain_id, &pending.wallet_id, &output_commitment)
        .expect("load updated recovery")
        .expect("recovery present");
    assert!(updated.next_retry_at.is_some_and(|next| next > 0));

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn indexed_artifacts_pending_verification_uses_local_cache_without_remote_status() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let public_data_plane = test_public_data_plane_with_poi_service(&store);
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x94; 32]);
    let list_key = FixedBytes::from([0x95; 32]);
    let mut pending = pending_output_record(chain_id, output_commitment, list_key);
    pending.wallet_id = "test".to_string();
    pending.observation = Some(local_db::PendingOutputPoiObservation {
        output_tree: 3,
        output_position: 14,
        tx_hash: source(14).tx_hash,
        block_number: 14,
        block_timestamp: 1_700_000_014,
    });
    pending.submitted_poi_list_keys = vec![list_key];
    let derived_blinded_commitment = pending_output_poi_submit_identity(
        &pending,
        pending.observation.as_ref().expect("observation"),
    )
    .expect("identity")
    .derived_blinded_commitment;
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let mut cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        chain_id,
        DEFAULT_TXID_VERSION,
        list_key,
    ));
    cache
        .apply_poi_leaves(0, &[U256::from_be_bytes(derived_blinded_commitment.0)])
        .expect("apply local POI leaf");
    let cfg = wallet_config(U256::ZERO);
    seed_data_plane_poi_cache(&public_data_plane, chain_id, list_key, cache).await;
    let mock = spawn_poi_rpc(serde_json::json!({})).await;
    let remote_client = PoiRpcClient::new(mock.url.clone());
    let poi_runtime = test_artifact_poi_runtime();

    let outcome = verify_submitted_pending_output_pois_with_config(
        &public_data_plane,
        &poi_runtime,
        &remote_client,
        &cfg,
        store.as_ref(),
        &[list_key],
    )
    .await;

    assert_eq!(outcome.completed, 1);
    assert!(
        store
            .get_pending_output_poi_context(chain_id, "test", &output_commitment)
            .expect("load pending")
            .is_none()
    );
    assert!(
        mock.requests
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "remote ppoi_pois_per_list should not be called"
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn pending_output_poi_submission_failure_remains_retryable() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x78; 32]);
    let list_key = FixedBytes::from([0x45; 32]);
    store
        .put_pending_output_poi_context(&pending_output_record(
            chain_id,
            output_commitment,
            list_key,
        ))
        .expect("store pending context");
    let submitter = RecordingPendingOutputPoiSubmitter::default();
    submitter.fail_next();
    let observation = CommitmentObservation {
        tree: 13,
        position: 35,
        commitment: U256::from_be_bytes(output_commitment.0),
        source: source(9),
    };

    process_pending_output_poi_observations(
        &store,
        chain_id,
        "wallet-1",
        &[observation],
        Some(&submitter),
    )
    .await;
    let failed = store
        .get_pending_output_poi_context(chain_id, "wallet-1", &output_commitment)
        .expect("load pending context")
        .expect("pending context present");
    assert!(failed.observation.is_some());
    assert!(failed.submitted_poi_list_keys.is_empty());
    assert!(failed.terminal_error.is_none());

    process_pending_output_poi_observations(&store, chain_id, "wallet-1", &[], Some(&submitter))
        .await;

    let retried = store
        .get_pending_output_poi_context(chain_id, "wallet-1", &output_commitment)
        .expect("load retried pending context")
        .expect("pending context present");
    assert_eq!(retried.submitted_poi_list_keys, vec![list_key]);
    assert_eq!(submitter.calls().len(), 2);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn authorized_pending_output_submission_cancels_without_mutating_context() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let chain_id = 1;
    let list_key = FixedBytes::from([0xb2; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = "wallet-1".to_string();
    let wallet_utxo = test_wallet_utxo(8);
    let output_commitment = wallet_utxo.utxo.poi.commitment;
    let pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let handle = test_wallet_handle(vec![wallet_utxo]);
    let cancel = CancellationToken::new();
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let submitter = Arc::new(BlockingPendingOutputPoiSubmitter::new(
        started_tx, release_rx,
    ));
    let task_store = Arc::clone(&store);
    let task_handle = handle.clone();
    let task_cancel = cancel.clone();
    let task_submitter = Arc::clone(&submitter);
    let task_cfg = cfg.clone();
    let task = tokio::spawn(async move {
        let authority = WalletPrivateMutationAuthority::new(&task_handle, 0, &task_cancel);
        let private_poi =
            WalletPrivatePoiClients::for_submit(authority.remote_authority(), task_submitter);
        process_pending_output_poi_observations_authorized(
            &authority,
            task_store.as_ref(),
            task_store.as_ref(),
            &task_cfg,
            &[list_key],
            Some(&private_poi),
            false,
        )
        .await
    });

    tokio::time::timeout(Duration::from_secs(2), started_rx)
        .await
        .expect("submission started")
        .expect("submission start signal");
    cancel.cancel();
    release_tx.send(()).expect("release submitter");

    assert_eq!(task.await.expect("submission task"), 0);
    assert!(submitter.calls().is_empty());
    let loaded = store
        .get_pending_output_poi_context(chain_id, "wallet-1", &output_commitment)
        .expect("load pending context")
        .expect("pending context present");
    assert!(loaded.submitted_poi_list_keys.is_empty());
    assert!(
        store
            .get_output_poi_recovery(chain_id, "wallet-1", &output_commitment)
            .expect("load recovery")
            .is_none()
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn authorized_pending_output_verification_skips_changed_context_after_await() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0xb3; 32]);
    let list_key = FixedBytes::from([0xb4; 32]);
    let mut pending = pending_output_record(chain_id, output_commitment, list_key);
    pending.observation = Some(local_db::PendingOutputPoiObservation {
        output_tree: 9,
        output_position: 10,
        tx_hash: source(10).tx_hash,
        block_number: 10,
        block_timestamp: 1_700_000_010,
    });
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let handle = test_wallet_handle(Vec::new());
    let cancel = CancellationToken::new();
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let reader = Arc::new(BlockingPoiStatusReader::new(started_tx, release_rx));
    let task_store = Arc::clone(&store);
    let task_handle = handle.clone();
    let task_cancel = cancel.clone();
    let task_reader = Arc::clone(&reader);
    let task = tokio::spawn(async move {
        let authority = WalletPrivateMutationAuthority::new(&task_handle, 0, &task_cancel);
        verify_submitted_pending_output_pois_authorized(
            &authority,
            task_reader.as_ref(),
            task_store.as_ref(),
            chain_id,
            "wallet-1",
            &[list_key],
        )
        .await
    });

    tokio::time::timeout(Duration::from_secs(2), started_rx)
        .await
        .expect("verification started")
        .expect("verification start signal");
    let mut changed = pending.clone();
    changed.terminal_error = Some("changed while status read was pending".to_string());
    store
        .put_pending_output_poi_context(&changed)
        .expect("change pending context");
    release_tx.send(()).expect("release status reader");

    let outcome = task.await.expect("verification task");
    assert_eq!(outcome.completed, 0);
    assert_eq!(outcome.pending, 0);
    assert_eq!(outcome.errors, 0);
    let loaded = store
        .get_pending_output_poi_context(chain_id, "wallet-1", &output_commitment)
        .expect("load pending context")
        .expect("pending context still present");
    assert_eq!(loaded.terminal_error, changed.terminal_error);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn recovered_output_poi_context_resubmits_after_retry_time() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x79; 32]);
    let list_key = FixedBytes::from([0x47; 32]);
    let mut pending = pending_output_record(chain_id, output_commitment, list_key);
    pending.observation = Some(local_db::PendingOutputPoiObservation {
        output_tree: 14,
        output_position: 36,
        tx_hash: source(11).tx_hash,
        block_number: 11,
        block_timestamp: 1_700_000_011,
    });
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    store
        .put_output_poi_recovery(&output_poi_recovery_record(
            chain_id,
            &pending.wallet_id,
            output_commitment,
            OutputPoiRecoveryStatus::Submitted,
            Some(0),
        ))
        .expect("store recovery state");
    let submitter = RecordingPendingOutputPoiSubmitter::default();

    process_pending_output_poi_observations(&store, chain_id, "wallet-1", &[], Some(&submitter))
        .await;

    let loaded = store
        .get_output_poi_recovery(chain_id, &pending.wallet_id, &output_commitment)
        .expect("load recovery state")
        .expect("recovery state present");
    assert_eq!(loaded.status, OutputPoiRecoveryStatus::Submitted);
    assert!(loaded.last_submission_at.is_some());
    assert!(loaded.next_retry_at.is_some_and(|next| next > 0));
    assert_eq!(submitter.calls(), vec![(output_commitment, 14, 36)]);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn recovered_output_poi_context_resubmits_when_forced_before_retry_time() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x7a; 32]);
    let list_key = FixedBytes::from([0x48; 32]);
    let mut pending = pending_output_record(chain_id, output_commitment, list_key);
    pending.observation = Some(local_db::PendingOutputPoiObservation {
        output_tree: 15,
        output_position: 37,
        tx_hash: source(12).tx_hash,
        block_number: 12,
        block_timestamp: 1_700_000_012,
    });
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    store
        .put_output_poi_recovery(&output_poi_recovery_record(
            chain_id,
            &pending.wallet_id,
            output_commitment,
            OutputPoiRecoveryStatus::Submitted,
            Some(u64::MAX),
        ))
        .expect("store recovery state");
    let submitter = RecordingPendingOutputPoiSubmitter::default();

    process_pending_output_poi_observations(&store, chain_id, "wallet-1", &[], Some(&submitter))
        .await;
    assert!(submitter.calls().is_empty());

    process_pending_output_poi_observations_inner(
        &store,
        chain_id,
        "wallet-1",
        &[],
        Some(&submitter),
        true,
    )
    .await;

    assert_eq!(submitter.calls(), vec![(output_commitment, 15, 37)]);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn pending_output_poi_context_matches_wallet_output_identity() {
    let cfg = wallet_config(U256::ZERO);
    let list_key = FixedBytes::from([0x49; 32]);
    let wallet_utxo = test_wallet_utxo(38);
    let record = matching_pending_output_record(&cfg, &wallet_utxo, list_key);

    assert_eq!(record.wallet_id, cfg.cache_key);

    assert!(pending_output_poi_context_matches_wallet_utxo(
        &cfg,
        &wallet_utxo,
        &record
    ));

    let mut wrong_wallet = record.clone();
    wrong_wallet.wallet_id = "other-wallet".to_string();
    assert!(!pending_output_poi_context_matches_wallet_utxo(
        &cfg,
        &wallet_utxo,
        &wrong_wallet
    ));

    let mut wrong_position = record.clone();
    wrong_position
        .observation
        .as_mut()
        .expect("observation")
        .output_position += 1;
    assert!(!pending_output_poi_context_matches_wallet_utxo(
        &cfg,
        &wallet_utxo,
        &wrong_position
    ));

    let mut wrong_npk = record;
    wrong_npk.output_npk = FixedBytes::from([0x88; 32]);
    assert!(!pending_output_poi_context_matches_wallet_utxo(
        &cfg,
        &wallet_utxo,
        &wrong_npk
    ));
}

#[tokio::test]
async fn force_resubmits_matching_pending_output_despite_permanent_recovery_state() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let cfg = wallet_config(U256::ZERO);
    let list_key = FixedBytes::from([0x4a; 32]);
    let mut wallet_utxo = test_wallet_utxo(39);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    store
        .put_output_poi_recovery(&output_poi_recovery_record(
            cfg.chain.chain_id,
            &cfg.cache_key,
            wallet_utxo.utxo.poi.commitment,
            OutputPoiRecoveryStatus::MissingWalletOutputs,
            None,
        ))
        .expect("store recovery state");
    let submitter = RecordingPendingOutputPoiSubmitter::default();

    let submitted = force_resubmit_matching_pending_output_pois(
        &store,
        &cfg,
        &[wallet_utxo.clone()],
        &[list_key],
        &submitter,
    )
    .await;

    assert_eq!(submitted, 1);
    assert_eq!(
        submitter.calls(),
        vec![(
            wallet_utxo.utxo.poi.commitment,
            u64::from(wallet_utxo.utxo.tree),
            wallet_utxo.utxo.position,
        ),]
    );
    let recovery = store
        .get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &wallet_utxo.utxo.poi.commitment,
        )
        .expect("load recovery")
        .expect("recovery present");
    assert_eq!(recovery.status, OutputPoiRecoveryStatus::Submitted);
    assert!(recovery.last_submission_at.is_some());
    assert!(recovery.next_retry_at.is_some());

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn force_resubmitted_recovered_pending_output_uses_pending_retry_delay() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let cfg = wallet_config(U256::ZERO);
    let list_key = FixedBytes::from([0x4c; 32]);
    let mut wallet_utxo = test_wallet_utxo(41);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    pending.wallet_id.clone_from(&cfg.cache_key);
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let submitter = RecordingPendingOutputPoiSubmitter::default();

    let submitted = force_resubmit_matching_pending_output_pois(
        &store,
        &cfg,
        &[wallet_utxo.clone()],
        &[list_key],
        &submitter,
    )
    .await;

    assert_eq!(submitted, 1);
    assert_eq!(
        submitter.calls(),
        vec![(
            wallet_utxo.utxo.poi.commitment,
            u64::from(wallet_utxo.utxo.tree),
            wallet_utxo.utxo.position,
        ),]
    );
    let recovery = store
        .get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &wallet_utxo.utxo.poi.commitment,
        )
        .expect("load recovery")
        .expect("recovery present");
    let last_submission_at = recovery
        .last_submission_at
        .expect("last submission timestamp");
    assert_eq!(recovery.status, OutputPoiRecoveryStatus::Submitted);
    assert_eq!(recovery.attempt_count, 1);
    assert_eq!(
        recovery.next_retry_at,
        Some(last_submission_at + PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER.as_secs())
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn authorized_force_submits_only_recoverable_subset() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = "wallet-force-mixed-statuses".to_string();
    let list_a = FixedBytes::from([0x4d; 32]);
    let list_b = FixedBytes::from([0x4e; 32]);
    let mut wallet_utxo = test_wallet_utxo(42);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_a, PoiStatus::Missing);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_b, PoiStatus::ShieldBlocked);
    let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, list_a);
    let leaf = FixedBytes::from([0x4f; 32]);
    pending.required_poi_list_keys = vec![list_a, list_b];
    pending.submitted_poi_list_keys = vec![list_a, list_b];
    pending
        .pre_transaction_pois_per_txid_leaf_per_list
        .insert(list_b, BTreeMap::from([(leaf, sample_pre_tx_poi(0x12))]));
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let mut handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let submitter = Arc::new(RecordingPendingOutputPoiSubmitter::default());
    let private_poi =
        WalletPrivatePoiClients::for_submit(authority.remote_authority(), submitter.clone());
    let utxos = Arc::new(RwLock::new(vec![wallet_utxo]));

    let attempted = force_resubmit_matching_pending_output_pois_authorized(
        &authority,
        &store,
        &store,
        &cfg,
        &utxos,
        &[list_a, list_b],
        &private_poi,
    )
    .await;

    assert_eq!(attempted, 1);
    assert_eq!(
        submitter.list_key_calls(),
        vec![vec![list_a]],
        "force must exclude the shield-blocked list from transport"
    );
    let persisted = store
        .get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &pending.output_commitment,
        )
        .expect("load pending context")
        .expect("pending context present");
    assert_eq!(persisted.list_keys(), vec![list_a, list_b]);
    assert_eq!(persisted.submitted_poi_list_keys, vec![list_a, list_b]);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn force_resubmit_preflight_skips_spent_output_before_remote_submit() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = "wallet-force-spent".to_string();
    let list_key = FixedBytes::from([0x51; 32]);
    let mut wallet_utxo = test_wallet_utxo(51);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    // Discovery snapshot still has the UTXO, but live handle is empty (spent/removed).
    let mut handle = test_wallet_handle(Vec::new());
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let submitter = Arc::new(RecordingPendingOutputPoiSubmitter::default());
    let private_poi =
        WalletPrivatePoiClients::for_submit(authority.remote_authority(), submitter.clone());

    let utxos = Arc::new(tokio::sync::RwLock::new(vec![wallet_utxo]));
    let attempted = force_resubmit_matching_pending_output_pois_authorized(
        &authority,
        &store,
        &store,
        &cfg,
        &utxos,
        &[list_key],
        &private_poi,
    )
    .await;

    assert_eq!(attempted, 0);
    assert!(
        submitter.calls().is_empty(),
        "remote submit must not start when live UTXO no longer matches"
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn force_resubmit_preflight_aborts_on_stale_generation() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = "wallet-force-stale".to_string();
    let list_key = FixedBytes::from([0x52; 32]);
    let mut wallet_utxo = test_wallet_utxo(52);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let mut handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    handle.cache_key = cfg.cache_key.clone();
    assert_eq!(handle.advance_reset_generation().await, Some(1));
    handle.notify_changed().await;
    let cancel = CancellationToken::new();
    // Authority still binds generation 0; handle is at 1.
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let submitter = Arc::new(RecordingPendingOutputPoiSubmitter::default());
    let private_poi =
        WalletPrivatePoiClients::for_submit(authority.remote_authority(), submitter.clone());

    let utxos = Arc::new(tokio::sync::RwLock::new(vec![wallet_utxo]));
    let attempted = force_resubmit_matching_pending_output_pois_authorized(
        &authority,
        &store,
        &store,
        &cfg,
        &utxos,
        &[list_key],
        &private_poi,
    )
    .await;

    assert_eq!(attempted, 0);
    assert!(
        submitter.calls().is_empty(),
        "remote submit must not start when authority generation is stale"
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn multi_proof_submit_revalidates_between_remote_calls() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = "wallet-multi-proof".to_string();
    let list_a = FixedBytes::from([0x61; 32]);
    let list_b = FixedBytes::from([0x62; 32]);
    let mut wallet_utxo = test_wallet_utxo(61);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_a, PoiStatus::Missing);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_b, PoiStatus::Missing);
    let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, list_a);
    pending.txid_merkleroot_index = Some(105_572);
    pending.required_poi_list_keys = vec![list_a, list_b];
    pending.submitted_poi_list_keys = vec![list_a, list_b];
    let leaf = FixedBytes::from([0x99; 32]);
    pending.pre_transaction_pois_per_txid_leaf_per_list = BTreeMap::from([
        (list_a, BTreeMap::from([(leaf, sample_pre_tx_poi(0x10))])),
        (list_b, BTreeMap::from([(leaf, sample_pre_tx_poi(0x11))])),
    ]);
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let mut handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let submitter = Arc::new(ResetAfterFirstPendingOutputPoiSubmitter::new(
        handle.clone(),
    ));
    let private_poi =
        WalletPrivatePoiClients::for_submit(authority.remote_authority(), submitter.clone());
    let observation = pending.observation.clone().expect("observation");
    let plan = super::PendingOutputPoiSubmissionPlan::force_matching(
        vec![list_a, list_b],
        ExpectedRecordState::Absent,
    );
    let active_lists = [list_a, list_b];

    let attempt = preflight_and_remote_submit_pending_output_poi(
        &authority,
        &store,
        &cfg,
        &active_lists,
        &pending,
        &observation,
        &plan,
        &private_poi,
    )
    .await
    .expect("submit result");
    assert!(
        matches!(
            attempt,
            super::PendingOutputPoiRemoteAttempt::AuthorityStale
                | super::PendingOutputPoiRemoteAttempt::NotCurrent
        ),
        "expected generation fence mid multi-proof, got {attempt:?}"
    );
    assert_eq!(
        submitter.calls(),
        1,
        "first submit returns after advancing generation; second must not start"
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn output_recovery_mixed_statuses_request_and_persist_only_recoverable_lists() {
    for (case, unrelated_status) in [PoiStatus::Valid, PoiStatus::ShieldBlocked]
        .into_iter()
        .enumerate()
    {
        let root_dir = temp_db_root();
        let store = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        let mut cfg = wallet_config(U256::ZERO);
        cfg.cache_key = format!("wallet-mixed-recovery-{case}");
        let recoverable_list_key = FixedBytes::from([0x61; 32]);
        let unrelated_list_key = FixedBytes::from([0x62; 32]);
        let active_list_keys = [recoverable_list_key, unrelated_list_key];
        let mut candidate = test_wallet_utxo(80 + case as u64);
        candidate
            .utxo
            .poi
            .statuses
            .insert(recoverable_list_key, PoiStatus::Missing);
        candidate
            .utxo
            .poi
            .statuses
            .insert(unrelated_list_key, unrelated_status);
        let recoverable_list_keys =
            recoverable_output_poi_list_keys(&candidate.utxo.poi, &active_list_keys);
        assert_eq!(recoverable_list_keys, vec![recoverable_list_key]);

        let mut handle = test_wallet_handle(vec![candidate.clone()]);
        handle.cache_key = cfg.cache_key.clone();
        let cancel = CancellationToken::new();
        let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
        let proof_transport = Arc::new(RecordingPoiProofSource::default());
        let private_poi = WalletPrivatePoiClients::for_proofs(
            authority.remote_authority(),
            proof_transport.clone(),
        );
        let source = OutputRecoveryRemoteProofSource {
            private_poi: &private_poi,
            authority: &authority,
            db: &store,
            cfg: &cfg,
            candidate: &candidate,
            required_poi_list_keys: &recoverable_list_keys,
        };

        assert!(matches!(
            source
                .poi_merkle_proofs(
                    DEFAULT_TXID_VERSION,
                    EVM_CHAIN_TYPE,
                    cfg.chain.chain_id,
                    &recoverable_list_key,
                    &[candidate.utxo.poi.blinded_commitment],
                )
                .await,
            Err(PreTransactionPoiError::ProofSource(_))
        ));
        assert_eq!(proof_transport.list_keys(), vec![recoverable_list_key]);
        assert!(matches!(
            source
                .poi_merkle_proofs(
                    DEFAULT_TXID_VERSION,
                    EVM_CHAIN_TYPE,
                    cfg.chain.chain_id,
                    &unrelated_list_key,
                    &[candidate.utxo.poi.blinded_commitment],
                )
                .await,
            Err(PreTransactionPoiError::ProofSource(_))
        ));
        assert_eq!(
            proof_transport.list_keys(),
            vec![recoverable_list_key],
            "unrelated {unrelated_status:?} list must not reach proof transport"
        );

        let pending = matching_pending_output_record(&cfg, &candidate, recoverable_list_key);
        let outcome = apply_owned_poi_private_delta_on_actor(
            &handle,
            &cancel,
            0,
            &store,
            &store,
            &cfg,
            OwnedPoiPrivateDelta::OutputRecovery {
                expected_output: ExpectedWalletOutput::new(&candidate),
                active_list_keys: recoverable_list_keys.clone(),
                required_poi_status: ExpectedPoiStatus::Recoverable,
                pending_update: Some((ExpectedRecordState::Absent, pending.clone())),
                expected_recovery: ExpectedRecordState::Absent,
                action: OutputPoiRecoveryAction::Detected {
                    status: OutputPoiRecoveryStatus::Recoverable,
                    retry_after: None,
                    last_error: None,
                    increment_attempts: false,
                },
                now: 10,
            },
        )
        .await
        .expect("persist mixed-status recovery intent");
        assert!(matches!(
            outcome,
            PoiPrivateApplyOutcome::Applied {
                utxo_changed: false
            }
        ));
        let persisted = store
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &candidate.utxo.poi.commitment,
            )
            .expect("load pending context")
            .expect("pending context present");
        assert_eq!(persisted.required_poi_list_keys, vec![recoverable_list_key]);
        assert_eq!(
            persisted
                .pre_transaction_pois_per_txid_leaf_per_list
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            vec![recoverable_list_key]
        );
        assert_eq!(
            store
                .get_output_poi_recovery(
                    cfg.chain.chain_id,
                    &cfg.cache_key,
                    &candidate.utxo.poi.commitment,
                )
                .expect("load recovery")
                .expect("recovery present")
                .source_tx_hash,
            candidate.utxo.source.tx_hash
        );

        drop(store);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }
}

async fn assert_valid_output_recovery_recovers_new_active_list(force_retry: bool) {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = format!("wallet-valid-new-list-{force_retry}");
    let list_a = FixedBytes::from([0x85; 32]);
    let list_b = FixedBytes::from([0x86; 32]);
    let active_list_keys = [list_a, list_b];
    let mut wallet_utxo = test_wallet_utxo(if force_retry { 86 } else { 85 });
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_a, PoiStatus::Valid);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_b, PoiStatus::Missing);

    let mut recovery = output_poi_recovery_record(
        cfg.chain.chain_id,
        &cfg.cache_key,
        wallet_utxo.utxo.poi.commitment,
        OutputPoiRecoveryStatus::Valid,
        None,
    );
    recovery.source_tx_hash = wallet_utxo.utxo.source.tx_hash;
    store
        .put_output_poi_recovery(&recovery)
        .expect("store valid recovery");
    assert!(
        store
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &wallet_utxo.utxo.poi.commitment,
            )
            .expect("load pending context")
            .is_none()
    );

    let recoverable_list_keys =
        recoverable_output_poi_list_keys(&wallet_utxo.utxo.poi, &active_list_keys);
    assert_eq!(recoverable_list_keys, vec![list_b]);
    assert!(!recovery.retry_allowed(10, force_retry));
    assert!(!output_poi_recovery_retry_allowed_for_lists(
        &recovery,
        10,
        force_retry,
        &[],
    ));
    assert!(output_poi_recovery_retry_allowed_for_lists(
        &recovery,
        10,
        force_retry,
        &recoverable_list_keys,
    ));

    let pending = matching_pending_output_record(&cfg, &wallet_utxo, list_b);
    let expected_recovery =
        super::expected_recovery_state(Some(&recovery)).expect("recovery fingerprint");
    let mut handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let outcome = apply_owned_poi_private_delta_on_actor(
        &handle,
        &cancel,
        0,
        &store,
        &store,
        &cfg,
        OwnedPoiPrivateDelta::OutputRecovery {
            expected_output: ExpectedWalletOutput::new(&wallet_utxo),
            active_list_keys: recoverable_list_keys,
            required_poi_status: ExpectedPoiStatus::Recoverable,
            pending_update: Some((ExpectedRecordState::Absent, pending.clone())),
            expected_recovery,
            action: OutputPoiRecoveryAction::Detected {
                status: OutputPoiRecoveryStatus::Recoverable,
                retry_after: None,
                last_error: None,
                increment_attempts: false,
            },
            now: 10,
        },
    )
    .await
    .expect("apply recovery for newly active list");
    assert!(matches!(
        outcome,
        PoiPrivateApplyOutcome::Applied {
            utxo_changed: false
        }
    ));

    let recovered_context = store
        .get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &wallet_utxo.utxo.poi.commitment,
        )
        .expect("load recovered context")
        .expect("recovered context present");
    assert_eq!(recovered_context.list_keys(), vec![list_b]);
    assert!(
        !recovered_context
            .pre_transaction_pois_per_txid_leaf_per_list
            .contains_key(&list_a)
    );
    assert_eq!(
        store
            .get_output_poi_recovery(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &wallet_utxo.utxo.poi.commitment,
            )
            .expect("load recovered state")
            .expect("recovered state present")
            .status,
        OutputPoiRecoveryStatus::Recoverable
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn ordinary_recovery_reopens_valid_output_for_new_active_missing_list() {
    assert_valid_output_recovery_recovers_new_active_list(false).await;
}

#[tokio::test]
async fn forced_recovery_reopens_valid_output_for_new_active_missing_list() {
    assert_valid_output_recovery_recovers_new_active_list(true).await;
}

#[tokio::test]
async fn output_recovery_extends_newly_missing_list_and_submits_only_it() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = "wallet-incremental-recovery".to_string();
    let list_a = FixedBytes::from([0x81; 32]);
    let list_b = FixedBytes::from([0x82; 32]);
    let active_list_keys = [list_a, list_b];
    let mut wallet_utxo = test_wallet_utxo(81);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_a, PoiStatus::ProofSubmitted);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_b, PoiStatus::Valid);

    let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, list_a);
    pending.submitted_poi_list_keys = vec![list_a];
    let original_observation = pending.observation.clone();
    let original_created_at = pending.created_at;
    let original_source_operation_id = pending.source_operation_id.clone();
    let txid_leaf = *pending
        .pre_transaction_pois_per_txid_leaf_per_list
        .get(&list_a)
        .and_then(|per_leaf| per_leaf.keys().next())
        .expect("list A proof leaf");
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");

    let mut recovery = output_poi_recovery_record(
        cfg.chain.chain_id,
        &cfg.cache_key,
        wallet_utxo.utxo.poi.commitment,
        OutputPoiRecoveryStatus::Submitted,
        Some(u64::MAX),
    );
    recovery.source_tx_hash = wallet_utxo.utxo.source.tx_hash;
    recovery.tx_input = Some(vec![0xde, 0xad]);
    recovery.updated_at = 7;
    recovery.last_detection_at = Some(3);
    recovery.last_submission_at = Some(6);
    recovery.attempt_count = 4;
    store
        .put_output_poi_recovery(&recovery)
        .expect("store submitted recovery");

    let mut handle = test_wallet_handle(vec![wallet_utxo]);
    handle.cache_key = cfg.cache_key.clone();
    handle.utxos.write().await[0]
        .utxo
        .poi
        .statuses
        .insert(list_b, PoiStatus::Missing);
    let current_output = handle.utxos.read().await[0].clone();
    let recoverable_list_keys =
        recoverable_output_poi_list_keys(&current_output.utxo.poi, &active_list_keys);
    assert_eq!(recoverable_list_keys, vec![list_a, list_b]);
    let new_list_keys = newly_recoverable_output_poi_list_keys(&pending, &recoverable_list_keys);
    assert_eq!(new_list_keys, vec![list_b]);
    let extended = extend_pending_output_poi_context(
        &pending,
        &new_list_keys,
        BTreeMap::from([(
            list_b,
            BTreeMap::from([(txid_leaf, sample_pre_tx_poi(0x20))]),
        )]),
    );
    let expected_context_fingerprint =
        pending_output_poi_context_fingerprint(&pending).expect("pending context fingerprint");
    let expected_recovery =
        super::expected_recovery_state(Some(&recovery)).expect("recovery fingerprint");
    let cancel = CancellationToken::new();

    let extension_outcome = apply_owned_poi_private_delta_on_actor(
        &handle,
        &cancel,
        0,
        &store,
        &store,
        &cfg,
        OwnedPoiPrivateDelta::OutputRecovery {
            expected_output: ExpectedWalletOutput::new(&current_output),
            active_list_keys: new_list_keys.clone(),
            required_poi_status: ExpectedPoiStatus::Recoverable,
            pending_update: Some((
                ExpectedRecordState::Present(expected_context_fingerprint),
                extended,
            )),
            expected_recovery,
            action: OutputPoiRecoveryAction::ExtendContext,
            now: 10,
        },
    )
    .await
    .expect("apply incremental recovery extension");
    assert!(matches!(
        extension_outcome,
        PoiPrivateApplyOutcome::Applied {
            utxo_changed: false
        }
    ));

    let extended = store
        .get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &pending.output_commitment,
        )
        .expect("load extended context")
        .expect("extended context present");
    assert_eq!(extended.required_poi_list_keys, vec![list_a, list_b]);
    assert_eq!(extended.submitted_poi_list_keys, vec![list_a]);
    assert_eq!(extended.observation, original_observation);
    assert_eq!(extended.created_at, original_created_at);
    assert_eq!(extended.source_operation_id, original_source_operation_id);
    assert_eq!(extended.terminal_error, None);
    assert_eq!(
        extended
            .pre_transaction_pois_per_txid_leaf_per_list
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        vec![list_a, list_b]
    );
    let preserved_recovery = store
        .get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &pending.output_commitment,
        )
        .expect("load preserved recovery")
        .expect("recovery present");
    assert_eq!(
        preserved_recovery.status,
        OutputPoiRecoveryStatus::Submitted
    );
    assert_eq!(preserved_recovery.tx_input, Some(vec![0xde, 0xad]));
    assert_eq!(preserved_recovery.updated_at, 7);
    assert_eq!(preserved_recovery.last_detection_at, Some(3));
    assert_eq!(preserved_recovery.last_submission_at, Some(6));
    assert_eq!(preserved_recovery.next_retry_at, Some(u64::MAX));
    assert_eq!(preserved_recovery.attempt_count, 4);

    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let submitter = Arc::new(RecordingPendingOutputPoiSubmitter::default());
    let private_poi =
        WalletPrivatePoiClients::for_submit(authority.remote_authority(), submitter.clone());
    let submitted = process_pending_output_poi_observations_authorized(
        &authority,
        &store,
        &store,
        &cfg,
        &active_list_keys,
        Some(&private_poi),
        false,
    )
    .await;
    assert_eq!(submitted, 1);
    assert_eq!(submitter.list_key_calls(), vec![vec![list_b]]);
    let submitted_context = store
        .get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &pending.output_commitment,
        )
        .expect("load submitted context")
        .expect("submitted context present");
    assert_eq!(
        submitted_context.submitted_poi_list_keys,
        vec![list_a, list_b]
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn output_recovery_extension_skips_concurrent_context_change() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = "wallet-incremental-recovery-race".to_string();
    let list_a = FixedBytes::from([0x83; 32]);
    let list_b = FixedBytes::from([0x84; 32]);
    let mut wallet_utxo = test_wallet_utxo(83);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_a, PoiStatus::ProofSubmitted);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_b, PoiStatus::Missing);
    let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, list_a);
    pending.submitted_poi_list_keys = vec![list_a];
    let expected_context_fingerprint =
        pending_output_poi_context_fingerprint(&pending).expect("pending context fingerprint");
    let txid_leaf = *pending
        .pre_transaction_pois_per_txid_leaf_per_list
        .get(&list_a)
        .and_then(|per_leaf| per_leaf.keys().next())
        .expect("list A proof leaf");
    let extended = extend_pending_output_poi_context(
        &pending,
        &[list_b],
        BTreeMap::from([(
            list_b,
            BTreeMap::from([(txid_leaf, sample_pre_tx_poi(0x21))]),
        )]),
    );
    let mut changed_pending = pending.clone();
    changed_pending.source_operation_id = Some("concurrent-context".to_string());
    store
        .put_pending_output_poi_context(&changed_pending)
        .expect("store concurrent context");
    let mut recovery = output_poi_recovery_record(
        cfg.chain.chain_id,
        &cfg.cache_key,
        wallet_utxo.utxo.poi.commitment,
        OutputPoiRecoveryStatus::Submitted,
        Some(u64::MAX),
    );
    recovery.source_tx_hash = wallet_utxo.utxo.source.tx_hash;
    store
        .put_output_poi_recovery(&recovery)
        .expect("store recovery");
    let expected_recovery =
        super::expected_recovery_state(Some(&recovery)).expect("recovery fingerprint");
    let mut handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();

    let outcome = apply_owned_poi_private_delta_on_actor(
        &handle,
        &cancel,
        0,
        &store,
        &store,
        &cfg,
        OwnedPoiPrivateDelta::OutputRecovery {
            expected_output: ExpectedWalletOutput::new(&wallet_utxo),
            active_list_keys: vec![list_b],
            required_poi_status: ExpectedPoiStatus::Recoverable,
            pending_update: Some((
                ExpectedRecordState::Present(expected_context_fingerprint),
                extended,
            )),
            expected_recovery,
            action: OutputPoiRecoveryAction::ExtendContext,
            now: 10,
        },
    )
    .await
    .expect("apply stale recovery extension");
    assert_eq!(outcome, PoiPrivateApplyOutcome::Skipped);
    let current = store
        .get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &pending.output_commitment,
        )
        .expect("load current context")
        .expect("current context present");
    assert_eq!(
        current.source_operation_id.as_deref(),
        Some("concurrent-context")
    );
    assert_eq!(current.required_poi_list_keys, vec![list_a]);
    assert!(
        !current
            .pre_transaction_pois_per_txid_leaf_per_list
            .contains_key(&list_b)
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn force_regenerates_matching_terminal_context_for_same_list() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = "wallet-terminal-force-regeneration".to_string();
    let list_key = FixedBytes::from([0x87; 32]);
    let mut wallet_utxo = test_wallet_utxo(87);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    let mut terminal = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    terminal.submitted_poi_list_keys = vec![list_key];
    terminal.terminal_error = Some("old terminal failure".to_string());
    let old_proof_root = terminal
        .pre_transaction_pois_per_txid_leaf_per_list
        .get(&list_key)
        .and_then(|per_leaf| per_leaf.values().next())
        .expect("old proof material")
        .txid_merkleroot;
    assert_eq!(
        matching_pending_output_poi_context_disposition(&terminal, &[list_key], false),
        MatchingPendingOutputPoiContextDisposition::Skip
    );
    assert_eq!(
        matching_pending_output_poi_context_disposition(&terminal, &[list_key], true),
        MatchingPendingOutputPoiContextDisposition::Regenerate
    );
    store
        .put_pending_output_poi_context(&terminal)
        .expect("store terminal context");

    let mut recovery = output_poi_recovery_record(
        cfg.chain.chain_id,
        &cfg.cache_key,
        wallet_utxo.utxo.poi.commitment,
        OutputPoiRecoveryStatus::SubmitFailed,
        Some(u64::MAX),
    );
    recovery.source_tx_hash = wallet_utxo.utxo.source.tx_hash;
    store
        .put_output_poi_recovery(&recovery)
        .expect("store failed recovery");
    let expected_context_fingerprint =
        pending_output_poi_context_fingerprint(&terminal).expect("terminal context fingerprint");
    let expected_recovery =
        super::expected_recovery_state(Some(&recovery)).expect("recovery fingerprint");

    let mut regenerated = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    let txid_leaf = *regenerated
        .pre_transaction_pois_per_txid_leaf_per_list
        .get(&list_key)
        .and_then(|per_leaf| per_leaf.keys().next())
        .expect("regenerated proof leaf");
    regenerated.pre_transaction_pois_per_txid_leaf_per_list = BTreeMap::from([(
        list_key,
        BTreeMap::from([(txid_leaf, sample_pre_tx_poi(0x30))]),
    )]);
    regenerated.output_role = PendingOutputPoiRole::Change;
    regenerated.created_at = 999;
    regenerated.source_operation_id = Some("forced-regeneration".to_string());
    assert!(regenerated.submitted_poi_list_keys.is_empty());
    assert!(regenerated.terminal_error.is_none());

    let mut handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let outcome = apply_owned_poi_private_delta_on_actor(
        &handle,
        &cancel,
        0,
        &store,
        &store,
        &cfg,
        OwnedPoiPrivateDelta::OutputRecovery {
            expected_output: ExpectedWalletOutput::new(&wallet_utxo),
            active_list_keys: vec![list_key],
            required_poi_status: ExpectedPoiStatus::Recoverable,
            pending_update: Some((
                ExpectedRecordState::Present(expected_context_fingerprint),
                regenerated.clone(),
            )),
            expected_recovery,
            action: OutputPoiRecoveryAction::Detected {
                status: OutputPoiRecoveryStatus::Recoverable,
                retry_after: None,
                last_error: None,
                increment_attempts: false,
            },
            now: 999,
        },
    )
    .await
    .expect("apply forced terminal regeneration");
    assert!(matches!(outcome, PoiPrivateApplyOutcome::Applied { .. }));

    let current = store
        .get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &wallet_utxo.utxo.poi.commitment,
        )
        .expect("load regenerated context")
        .expect("regenerated context present");
    assert_eq!(
        pending_output_poi_context_fingerprint(&current),
        pending_output_poi_context_fingerprint(&regenerated)
    );
    assert!(current.terminal_error.is_none());
    assert!(current.submitted_poi_list_keys.is_empty());
    assert_ne!(
        current
            .pre_transaction_pois_per_txid_leaf_per_list
            .get(&list_key)
            .and_then(|per_leaf| per_leaf.values().next())
            .expect("regenerated proof material")
            .txid_merkleroot,
        old_proof_root
    );
    assert_eq!(
        store
            .get_output_poi_recovery(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &wallet_utxo.utxo.poi.commitment,
            )
            .expect("load regenerated recovery")
            .expect("regenerated recovery present")
            .status,
        OutputPoiRecoveryStatus::Recoverable
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn force_terminal_regeneration_skips_concurrent_context_replacement() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = "wallet-terminal-force-race".to_string();
    let list_key = FixedBytes::from([0x88; 32]);
    let mut wallet_utxo = test_wallet_utxo(88);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    let mut terminal = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    terminal.submitted_poi_list_keys = vec![list_key];
    terminal.terminal_error = Some("old terminal failure".to_string());
    store
        .put_pending_output_poi_context(&terminal)
        .expect("store terminal context");
    let expected_context_fingerprint =
        pending_output_poi_context_fingerprint(&terminal).expect("terminal context fingerprint");

    let mut recovery = output_poi_recovery_record(
        cfg.chain.chain_id,
        &cfg.cache_key,
        wallet_utxo.utxo.poi.commitment,
        OutputPoiRecoveryStatus::SubmitFailed,
        Some(u64::MAX),
    );
    recovery.source_tx_hash = wallet_utxo.utxo.source.tx_hash;
    store
        .put_output_poi_recovery(&recovery)
        .expect("store failed recovery");
    let expected_recovery =
        super::expected_recovery_state(Some(&recovery)).expect("recovery fingerprint");

    let mut regenerated = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    regenerated.output_role = PendingOutputPoiRole::Change;
    regenerated.source_operation_id = Some("stale-regeneration".to_string());
    let mut concurrent = terminal.clone();
    concurrent.source_operation_id = Some("concurrent-terminal-context".to_string());
    concurrent.terminal_error = Some("newer terminal failure".to_string());
    store
        .put_pending_output_poi_context(&concurrent)
        .expect("store concurrent terminal context");

    let mut handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let outcome = apply_owned_poi_private_delta_on_actor(
        &handle,
        &cancel,
        0,
        &store,
        &store,
        &cfg,
        OwnedPoiPrivateDelta::OutputRecovery {
            expected_output: ExpectedWalletOutput::new(&wallet_utxo),
            active_list_keys: vec![list_key],
            required_poi_status: ExpectedPoiStatus::Recoverable,
            pending_update: Some((
                ExpectedRecordState::Present(expected_context_fingerprint),
                regenerated,
            )),
            expected_recovery,
            action: OutputPoiRecoveryAction::Detected {
                status: OutputPoiRecoveryStatus::Recoverable,
                retry_after: None,
                last_error: None,
                increment_attempts: false,
            },
            now: 999,
        },
    )
    .await
    .expect("apply stale forced terminal regeneration");
    assert_eq!(outcome, PoiPrivateApplyOutcome::Skipped);

    let current = store
        .get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &wallet_utxo.utxo.poi.commitment,
        )
        .expect("load concurrent context")
        .expect("concurrent context present");
    assert_eq!(
        pending_output_poi_context_fingerprint(&current),
        pending_output_poi_context_fingerprint(&concurrent)
    );
    assert_eq!(
        current.source_operation_id.as_deref(),
        Some("concurrent-terminal-context")
    );
    assert_eq!(
        current.terminal_error.as_deref(),
        Some("newer terminal failure")
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn remote_proof_gateway_revalidates_after_source_resolution_wait() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = "wallet-proof-resolution-race".to_string();
    let list_key = FixedBytes::from([0x63; 32]);
    let active_list_keys = [list_key];
    let mut candidate = test_wallet_utxo(63);
    candidate
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    let mut handle = test_wallet_handle(vec![candidate.clone()]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let transport = Arc::new(RecordingPoiProofSource::default());
    let private_poi =
        WalletPrivatePoiClients::for_proofs(authority.remote_authority(), transport.clone());
    let source = OutputRecoveryRemoteProofSource {
        private_poi: &private_poi,
        authority: &authority,
        db: &store,
        cfg: &cfg,
        candidate: &candidate,
        required_poi_list_keys: &active_list_keys,
    };
    let commitment = candidate.utxo.poi.blinded_commitment;
    let (resolution_started_tx, resolution_started_rx) = oneshot::channel();
    let (release_resolution_tx, release_resolution_rx) = oneshot::channel();

    {
        let proof = async {
            resolution_started_tx
                .send(())
                .expect("signal source resolution wait");
            release_resolution_rx
                .await
                .expect("release source resolution wait");
            source
                .poi_merkle_proofs(
                    DEFAULT_TXID_VERSION,
                    EVM_CHAIN_TYPE,
                    cfg.chain.chain_id,
                    &list_key,
                    &[commitment],
                )
                .await
        };
        tokio::pin!(proof);
        tokio::select! {
            result = &mut proof => panic!("proof request finished before resolution was released: {result:?}"),
            started = resolution_started_rx => started.expect("source resolution started"),
        }

        assert_eq!(handle.advance_reset_generation().await, Some(1));
        release_resolution_tx
            .send(())
            .expect("release source resolution");
        assert!(matches!(
            proof.as_mut().await,
            Err(PreTransactionPoiError::ProofSource(_))
        ));
    }
    assert_eq!(
        transport.calls(),
        0,
        "stale fallback must not call remote poi_merkle_proofs"
    );

    drop(source);
    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn remote_proof_gateway_rejects_mixed_candidate_with_no_recoverable_lists() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = "wallet-proof-became-valid".to_string();
    let list_key = FixedBytes::from([0x67; 32]);
    let unrelated_list_key = FixedBytes::from([0x68; 32]);
    let active_list_keys = [list_key, unrelated_list_key];
    let mut candidate = test_wallet_utxo(67);
    candidate
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    candidate
        .utxo
        .poi
        .statuses
        .insert(unrelated_list_key, PoiStatus::ShieldBlocked);
    let recoverable_list_keys =
        recoverable_output_poi_list_keys(&candidate.utxo.poi, &active_list_keys);
    assert_eq!(recoverable_list_keys, vec![list_key]);
    let mut handle = test_wallet_handle(vec![candidate.clone()]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let transport = Arc::new(RecordingPoiProofSource::default());
    let private_poi =
        WalletPrivatePoiClients::for_proofs(authority.remote_authority(), transport.clone());
    let source = OutputRecoveryRemoteProofSource {
        private_poi: &private_poi,
        authority: &authority,
        db: &store,
        cfg: &cfg,
        candidate: &candidate,
        required_poi_list_keys: &recoverable_list_keys,
    };
    let (resolution_started_tx, resolution_started_rx) = oneshot::channel();
    let (release_resolution_tx, release_resolution_rx) = oneshot::channel();
    {
        let proof = async {
            resolution_started_tx
                .send(())
                .expect("signal source resolution wait");
            release_resolution_rx
                .await
                .expect("release source resolution wait");
            source
                .poi_merkle_proofs(
                    DEFAULT_TXID_VERSION,
                    EVM_CHAIN_TYPE,
                    1,
                    &list_key,
                    &[candidate.utxo.poi.blinded_commitment],
                )
                .await
        };
        tokio::pin!(proof);
        tokio::select! {
            result = &mut proof => panic!("proof request finished before resolution was released: {result:?}"),
            started = resolution_started_rx => started.expect("source resolution started"),
        }

        handle.utxos.write().await[0]
            .utxo
            .poi
            .statuses
            .insert(list_key, PoiStatus::Valid);
        release_resolution_tx
            .send(())
            .expect("release source resolution");

        assert!(matches!(
            proof.as_mut().await,
            Err(PreTransactionPoiError::ProofSource(_))
        ));
    }
    assert_eq!(transport.calls(), 0);

    drop(source);
    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn private_status_gateway_revalidates_same_generation_subject() {
    let candidate = test_wallet_utxo(64);
    let blinded_commitment = candidate.utxo.poi.blinded_commitment;
    let handle = test_wallet_handle(vec![candidate]);
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let transport = Arc::new(RecordingPoiStatusClient::default());
    let private_poi =
        WalletPrivatePoiClients::for_status(authority.remote_authority(), transport.clone());
    let list_key = FixedBytes::from([0x64; 32]);
    let request_data = [BlindedCommitmentData::transact(blinded_commitment)];
    let (resolution_started_tx, resolution_started_rx) = oneshot::channel();
    let (release_resolution_tx, release_resolution_rx) = oneshot::channel();

    let statuses = async {
        resolution_started_tx
            .send(())
            .expect("signal status-source resolution wait");
        release_resolution_rx
            .await
            .expect("release status-source resolution wait");
        private_poi
            .pois_per_list(
                || async {
                    Ok::<bool, std::convert::Infallible>(authority.wallet_utxos().await.is_ok_and(
                        |utxos| {
                            utxos.iter().any(|utxo| {
                                !utxo.is_spent()
                                    && utxo.utxo.poi.blinded_commitment == blinded_commitment
                            })
                        },
                    ))
                },
                DEFAULT_TXID_VERSION,
                EVM_CHAIN_TYPE,
                1,
                &[list_key],
                &request_data,
            )
            .await
    };
    tokio::pin!(statuses);
    tokio::select! {
        result = &mut statuses => panic!("status request finished before resolution was released: {result:?}"),
        started = resolution_started_rx => started.expect("status-source resolution started"),
    }

    handle.utxos.write().await.clear();
    release_resolution_tx
        .send(())
        .expect("release status-source resolution");
    assert!(matches!(
        statuses.await,
        Err(super::WalletPrivateRemoteError::Stale(
            super::WalletPrivateRemoteStale::Subject
        ))
    ));
    assert!(
        transport.calls().is_empty(),
        "same-generation stale subject must not reach status transport"
    );
}

#[tokio::test]
async fn private_remote_gateway_cancels_in_flight_effect_on_reset() {
    let handle = test_wallet_handle(vec![test_wallet_utxo(65)]);
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let (started_tx, started_rx) = oneshot::channel();
    let (_release_tx, release_rx) = oneshot::channel();
    let transport = Arc::new(BlockingPoiStatusReader::new(started_tx, release_rx));
    let private_poi = WalletPrivatePoiClients::for_status(authority.remote_authority(), transport);
    let list_key = FixedBytes::from([0x65; 32]);
    let list_keys = [list_key];
    let request_data = [BlindedCommitmentData::transact(FixedBytes::from(
        [0x66; 32],
    ))];

    let statuses = private_poi.pois_per_list(
        || async { Ok::<bool, std::convert::Infallible>(true) },
        DEFAULT_TXID_VERSION,
        EVM_CHAIN_TYPE,
        1,
        &list_keys,
        &request_data,
    );
    tokio::pin!(statuses);
    tokio::select! {
        result = &mut statuses => panic!("private effect finished before transport blocked: {result:?}"),
        started = started_rx => started.expect("private transport started"),
    }

    assert_eq!(handle.advance_reset_generation().await, Some(1));
    let result = tokio::time::timeout(Duration::from_secs(1), statuses)
        .await
        .expect("generation invalidation must cancel private effect");
    assert!(matches!(
        result,
        Err(super::WalletPrivateRemoteError::Stale(
            super::WalletPrivateRemoteStale::Authority
        ))
    ));
}

#[tokio::test]
async fn recovery_actor_skips_when_output_becomes_valid_before_apply() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = "wallet-recovery-became-valid".to_string();
    let list_key = FixedBytes::from([0x71; 32]);
    let mut wallet_utxo = test_wallet_utxo(71);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    let pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    let expected_output = ExpectedWalletOutput::new(&wallet_utxo);
    let mut handle = test_wallet_handle(vec![wallet_utxo]);
    handle.cache_key = cfg.cache_key.clone();
    handle.utxos.write().await[0]
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Valid);
    let cancel = CancellationToken::new();
    let outcome = apply_owned_poi_private_delta_on_actor(
        &handle,
        &cancel,
        0,
        &store,
        &store,
        &cfg,
        OwnedPoiPrivateDelta::OutputRecovery {
            expected_output,
            active_list_keys: vec![list_key],
            required_poi_status: ExpectedPoiStatus::Recoverable,
            pending_update: Some((ExpectedRecordState::Absent, pending.clone())),
            expected_recovery: ExpectedRecordState::Absent,
            action: OutputPoiRecoveryAction::Detected {
                status: OutputPoiRecoveryStatus::Recoverable,
                retry_after: None,
                last_error: None,
                increment_attempts: false,
            },
            now: 10,
        },
    )
    .await
    .expect("apply recovery intent");
    assert_eq!(outcome, PoiPrivateApplyOutcome::Skipped);
    assert!(
        store
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &pending.output_commitment
            )
            .expect("load context")
            .is_none(),
        "valid output must not gain a recovered pending context"
    );
    assert!(
        store
            .get_output_poi_recovery(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &pending.output_commitment
            )
            .expect("load recovery")
            .is_none(),
        "valid output must not gain recovery metadata"
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn successful_submission_intent_survives_timestamp_only_poi_refresh() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = "wallet-submission-timestamp-refresh".to_string();
    let list_key = FixedBytes::from([0x74; 32]);
    let mut wallet_utxo = test_wallet_utxo(74);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    let expected_output = ExpectedWalletOutput::new(&wallet_utxo);
    let pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    let expected_context_fingerprint =
        pending_output_poi_context_fingerprint(&pending).expect("pending context fingerprint");
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let mut handle = test_wallet_handle(vec![wallet_utxo]);
    handle.cache_key = cfg.cache_key.clone();
    handle.utxos.write().await[0].utxo.poi.refreshed_at = Some(100);
    let cancel = CancellationToken::new();

    let outcome = apply_owned_poi_private_delta_on_actor(
        &handle,
        &cancel,
        0,
        &store,
        &store,
        &cfg,
        OwnedPoiPrivateDelta::PendingSubmission {
            expected_output,
            expected_context_fingerprint,
            expected_recovery: ExpectedRecordState::Absent,
            active_list_keys: vec![list_key],
            list_keys: vec![list_key],
            predicate: PendingOutputPoiSubmissionPredicate::Missing,
            merge_submitted_list_keys: true,
            action: OutputPoiRecoveryAction::Submitted {
                retry_after: PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER,
            },
            now: 10,
        },
    )
    .await
    .expect("apply successful submission intent");

    assert!(matches!(
        outcome,
        PoiPrivateApplyOutcome::Applied {
            utxo_changed: false
        }
    ));
    assert_eq!(
        handle.utxos.read().await[0].utxo.poi.refreshed_at,
        Some(100)
    );
    assert_eq!(
        store
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &pending.output_commitment,
            )
            .expect("load pending context")
            .expect("pending context present")
            .submitted_poi_list_keys,
        vec![list_key]
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn successful_submission_intent_preserves_newer_unrelated_list_status() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = "wallet-submission-unrelated-list-refresh".to_string();
    let list_key = FixedBytes::from([0x75; 32]);
    let unrelated_list_key = FixedBytes::from([0x76; 32]);
    let mut wallet_utxo = test_wallet_utxo(75);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    let expected_output = ExpectedWalletOutput::new(&wallet_utxo);
    let pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    let expected_context_fingerprint =
        pending_output_poi_context_fingerprint(&pending).expect("pending context fingerprint");
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let mut handle = test_wallet_handle(vec![wallet_utxo]);
    handle.cache_key = cfg.cache_key.clone();
    handle.utxos.write().await[0]
        .utxo
        .poi
        .statuses
        .insert(unrelated_list_key, PoiStatus::ShieldBlocked);
    let cancel = CancellationToken::new();

    let outcome = apply_owned_poi_private_delta_on_actor(
        &handle,
        &cancel,
        0,
        &store,
        &store,
        &cfg,
        OwnedPoiPrivateDelta::PendingSubmission {
            expected_output,
            expected_context_fingerprint,
            expected_recovery: ExpectedRecordState::Absent,
            active_list_keys: vec![list_key, unrelated_list_key],
            list_keys: vec![list_key],
            predicate: PendingOutputPoiSubmissionPredicate::Missing,
            merge_submitted_list_keys: true,
            action: OutputPoiRecoveryAction::Submitted {
                retry_after: PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER,
            },
            now: 10,
        },
    )
    .await
    .expect("apply successful submission intent");

    assert!(matches!(
        outcome,
        PoiPrivateApplyOutcome::Applied {
            utxo_changed: false
        }
    ));
    let current = handle.utxos.read().await;
    assert_eq!(
        current[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Missing)
    );
    assert_eq!(
        current[0].utxo.poi.statuses.get(&unrelated_list_key),
        Some(&PoiStatus::ShieldBlocked)
    );
    drop(current);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn stale_submission_behind_verified_valid_cannot_resurrect_or_downgrade() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = "wallet-verified-before-submission".to_string();
    let list_key = FixedBytes::from([0x72; 32]);
    let mut wallet_utxo = test_wallet_utxo(72);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::ProofSubmitted);
    let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let mut recovery = output_poi_recovery_record(
        cfg.chain.chain_id,
        &cfg.cache_key,
        wallet_utxo.utxo.poi.commitment,
        OutputPoiRecoveryStatus::Submitted,
        Some(20),
    );
    recovery.source_tx_hash = wallet_utxo.utxo.source.tx_hash;
    store
        .put_output_poi_recovery(&recovery)
        .expect("store recovery");
    let expected_context_fingerprint =
        pending_output_poi_context_fingerprint(&pending).expect("pending context fingerprint");
    let expected_recovery =
        super::expected_recovery_state(Some(&recovery)).expect("recovery fingerprint");
    let expected_output = ExpectedWalletOutput::new(&wallet_utxo);
    let expected_poi_list_state = ExpectedPoiListState::new(&wallet_utxo.utxo.poi, &[list_key]);
    let stale_submission = OwnedPoiPrivateDelta::PendingSubmission {
        expected_output: expected_output.clone(),
        expected_context_fingerprint: expected_context_fingerprint.clone(),
        expected_recovery,
        active_list_keys: vec![list_key],
        list_keys: vec![list_key],
        predicate: PendingOutputPoiSubmissionPredicate::RetrySubmitted,
        merge_submitted_list_keys: false,
        action: OutputPoiRecoveryAction::SubmitFailed {
            error: "stale submission failure".to_string(),
            retry_after: Duration::from_secs(30),
        },
        now: 11,
    };
    let verified = OwnedPoiPrivateDelta::VerifiedValid {
        output_commitment: pending.output_commitment,
        expected_context_fingerprint,
        expected_output,
        expected_poi_list_state,
        active_list_keys: vec![list_key],
        valid_list_keys: vec![list_key],
        now: 12,
    };
    let mut handle = test_wallet_handle(vec![wallet_utxo]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();

    assert!(matches!(
        apply_owned_poi_private_delta_on_actor(
            &handle, &cancel, 0, &store, &store, &cfg, verified,
        )
        .await
        .expect("apply verified intent"),
        PoiPrivateApplyOutcome::Applied { .. }
    ));
    assert_eq!(
        apply_owned_poi_private_delta_on_actor(
            &handle,
            &cancel,
            0,
            &store,
            &store,
            &cfg,
            stale_submission,
        )
        .await
        .expect("apply queued stale submission"),
        PoiPrivateApplyOutcome::Skipped
    );
    assert!(
        store
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &pending.output_commitment,
            )
            .expect("load context")
            .is_none()
    );
    assert_eq!(
        store
            .get_output_poi_recovery(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &pending.output_commitment,
            )
            .expect("load recovery")
            .expect("recovery present")
            .status,
        OutputPoiRecoveryStatus::Valid
    );
    assert_eq!(
        handle.utxos.read().await[0]
            .utxo
            .poi
            .statuses
            .get(&list_key),
        Some(&PoiStatus::Valid)
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn verified_valid_rejects_changed_context_or_shield_blocked_but_accepts_recoverable() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = "wallet-stale-verified".to_string();
    let list_key = FixedBytes::from([0x73; 32]);
    let mut wallet_utxo = test_wallet_utxo(73);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::ProofSubmitted);
    let expected_output = ExpectedWalletOutput::new(&wallet_utxo);
    let expected_poi_list_state = ExpectedPoiListState::new(&wallet_utxo.utxo.poi, &[list_key]);
    let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let expected_context_fingerprint =
        pending_output_poi_context_fingerprint(&pending).expect("pending context fingerprint");
    let mut handle = test_wallet_handle(vec![wallet_utxo]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();

    let mut changed_context = pending.clone();
    changed_context.source_operation_id = Some("newer-context".to_string());
    store
        .put_pending_output_poi_context(&changed_context)
        .expect("replace context");
    let changed_context_outcome = apply_owned_poi_private_delta_on_actor(
        &handle,
        &cancel,
        0,
        &store,
        &store,
        &cfg,
        OwnedPoiPrivateDelta::VerifiedValid {
            output_commitment: pending.output_commitment,
            expected_context_fingerprint: expected_context_fingerprint.clone(),
            expected_output: expected_output.clone(),
            expected_poi_list_state: expected_poi_list_state.clone(),
            active_list_keys: vec![list_key],
            valid_list_keys: vec![list_key],
            now: 20,
        },
    )
    .await
    .expect("apply stale-context verification");
    assert_eq!(changed_context_outcome, PoiPrivateApplyOutcome::Skipped);

    store
        .put_pending_output_poi_context(&pending)
        .expect("restore context");
    handle.utxos.write().await[0]
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::ShieldBlocked);
    let shield_blocked_outcome = apply_owned_poi_private_delta_on_actor(
        &handle,
        &cancel,
        0,
        &store,
        &store,
        &cfg,
        OwnedPoiPrivateDelta::VerifiedValid {
            output_commitment: pending.output_commitment,
            expected_context_fingerprint: expected_context_fingerprint.clone(),
            expected_output: expected_output.clone(),
            expected_poi_list_state: expected_poi_list_state.clone(),
            active_list_keys: vec![list_key],
            valid_list_keys: vec![list_key],
            now: 21,
        },
    )
    .await
    .expect("apply shield-blocked verification");
    assert_eq!(shield_blocked_outcome, PoiPrivateApplyOutcome::Skipped);
    assert_eq!(
        handle.utxos.read().await[0]
            .utxo
            .poi
            .statuses
            .get(&list_key),
        Some(&PoiStatus::ShieldBlocked)
    );

    handle.utxos.write().await[0]
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Unknown);
    let recoverable_status_outcome = apply_owned_poi_private_delta_on_actor(
        &handle,
        &cancel,
        0,
        &store,
        &store,
        &cfg,
        OwnedPoiPrivateDelta::VerifiedValid {
            output_commitment: pending.output_commitment,
            expected_context_fingerprint,
            expected_output,
            expected_poi_list_state,
            active_list_keys: vec![list_key],
            valid_list_keys: vec![list_key],
            now: 22,
        },
    )
    .await
    .expect("apply recoverable-status verification");
    assert!(matches!(
        recoverable_status_outcome,
        PoiPrivateApplyOutcome::Applied { .. }
    ));
    assert!(
        store
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &pending.output_commitment,
            )
            .expect("load context")
            .is_none()
    );
    assert_eq!(
        handle.utxos.read().await[0]
            .utxo
            .poi
            .statuses
            .get(&list_key),
        Some(&PoiStatus::Valid)
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn force_resubmit_ignores_nonmatching_pending_output_context() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let cfg = wallet_config(U256::ZERO);
    let list_key = FixedBytes::from([0x4b; 32]);
    let mut wallet_utxo = test_wallet_utxo(40);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    pending.output_npk = FixedBytes::from([0x89; 32]);
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let submitter = RecordingPendingOutputPoiSubmitter::default();

    let submitted = force_resubmit_matching_pending_output_pois(
        &store,
        &cfg,
        &[wallet_utxo],
        &[list_key],
        &submitter,
    )
    .await;

    assert_eq!(submitted, 0);
    assert!(submitter.calls().is_empty());

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn output_poi_recovery_retry_skips_permanent_statuses() {
    let due = output_poi_recovery_record(
        1,
        "wallet-1",
        FixedBytes::from([0x80; 32]),
        OutputPoiRecoveryStatus::Submitted,
        Some(10),
    );
    assert!(due.retry_allowed(11, false));

    let not_self = output_poi_recovery_record(
        1,
        "wallet-1",
        FixedBytes::from([0x81; 32]),
        OutputPoiRecoveryStatus::NotSelfOriginated,
        Some(0),
    );
    assert!(!not_self.retry_allowed(11, false));

    let missing_inputs = output_poi_recovery_record(
        1,
        "wallet-1",
        FixedBytes::from([0x82; 32]),
        OutputPoiRecoveryStatus::MissingWalletInputs,
        None,
    );
    assert!(!missing_inputs.retry_allowed(11, false));

    let missing_outputs = output_poi_recovery_record(
        1,
        "wallet-1",
        FixedBytes::from([0x86; 32]),
        OutputPoiRecoveryStatus::MissingWalletOutputs,
        None,
    );
    assert!(!missing_outputs.retry_allowed(11, false));

    let valid = output_poi_recovery_record(
        1,
        "wallet-1",
        FixedBytes::from([0x83; 32]),
        OutputPoiRecoveryStatus::Valid,
        Some(0),
    );
    assert!(!valid.retry_allowed(11, false));
}

#[test]
fn forced_output_poi_recovery_retry_ignores_future_retry_for_retryable_status() {
    let future = output_poi_recovery_record(
        1,
        "wallet-1",
        FixedBytes::from([0x83; 32]),
        OutputPoiRecoveryStatus::ProofGenerationFailed,
        Some(999_999),
    );
    assert!(!future.retry_allowed(11, false));
    assert!(future.retry_allowed(11, true));

    let not_self = output_poi_recovery_record(
        1,
        "wallet-1",
        FixedBytes::from([0x84; 32]),
        OutputPoiRecoveryStatus::NotSelfOriginated,
        Some(0),
    );
    assert!(!not_self.retry_allowed(11, true));

    let unsupported_shape = output_poi_recovery_record(
        1,
        "wallet-1",
        FixedBytes::from([0x85; 32]),
        OutputPoiRecoveryStatus::UnsupportedShape,
        None,
    );
    assert!(!unsupported_shape.retry_allowed(11, false));
    assert!(unsupported_shape.retry_allowed(11, true));

    let missing_outputs = output_poi_recovery_record(
        1,
        "wallet-1",
        FixedBytes::from([0x86; 32]),
        OutputPoiRecoveryStatus::MissingWalletOutputs,
        None,
    );
    assert!(!missing_outputs.retry_allowed(11, false));
    assert!(missing_outputs.retry_allowed(11, true));
}

#[tokio::test]
async fn failed_full_persist_forces_next_no_change_batch_to_store_snapshot() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = RecordingCacheStore::new(Arc::clone(&store));
    cache_store.fail_next_store();
    let snapshot = Vec::new();
    let handle = test_wallet_handle(snapshot.clone());
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let permit = authority.acquire().await.expect("wallet authority");
    let mut persist_state = WalletPersistState::default();

    assert!(
        persist_state
            .persist_progress(
                &cache_store,
                &permit,
                WalletProgressPersist {
                    cache_key: "wallet",
                    snapshot: &snapshot,
                    last_scanned: 10,
                    last_scanned_block_hash: None,
                    changed: true,
                },
            )
            .is_err()
    );
    assert!(persist_state.needs_full_persist);
    assert_eq!(cache_store.state().store_calls, 1);
    assert_eq!(cache_store.state().meta_calls, 0);

    let persisted_full_snapshot = persist_state
        .persist_progress(
            &cache_store,
            &permit,
            WalletProgressPersist {
                cache_key: "wallet",
                snapshot: &snapshot,
                last_scanned: 11,
                last_scanned_block_hash: None,
                changed: false,
            },
        )
        .expect("retry full persist");
    assert!(persisted_full_snapshot);
    assert!(!persist_state.needs_full_persist);
    assert_eq!(cache_store.state().store_calls, 2);
    assert_eq!(cache_store.state().meta_calls, 0);

    let persisted_full_snapshot = persist_state
        .persist_progress(
            &cache_store,
            &permit,
            WalletProgressPersist {
                cache_key: "wallet",
                snapshot: &snapshot,
                last_scanned: 12,
                last_scanned_block_hash: None,
                changed: false,
            },
        )
        .expect("metadata-only persist");
    assert!(!persisted_full_snapshot);
    assert_eq!(cache_store.state().store_calls, 2);
    assert_eq!(cache_store.state().meta_calls, 1);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn pending_cache_reset_blocks_metadata_only_until_full_snapshot_succeeds() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = RecordingCacheStore::new(Arc::clone(&store));
    cache_store.fail_next_store();
    let snapshot = Vec::new();
    let handle = test_wallet_handle(snapshot.clone());
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let permit = authority.acquire().await.expect("wallet authority");
    let mut persist_state = WalletPersistState {
        needs_full_persist: true,
        pending_cache_reset: Some(9),
    };

    assert!(
        persist_state
            .persist_progress(
                &cache_store,
                &permit,
                WalletProgressPersist {
                    cache_key: "wallet",
                    snapshot: &snapshot,
                    last_scanned: 10,
                    last_scanned_block_hash: None,
                    changed: false,
                },
            )
            .is_err()
    );
    assert_eq!(persist_state.pending_cache_reset, Some(9));
    assert_eq!(cache_store.state().reset_calls, 0);
    assert_eq!(cache_store.state().store_calls, 1);
    assert_eq!(cache_store.state().meta_calls, 0);

    let persisted_full_snapshot = persist_state
        .persist_progress(
            &cache_store,
            &permit,
            WalletProgressPersist {
                cache_key: "wallet",
                snapshot: &snapshot,
                last_scanned: 10,
                last_scanned_block_hash: None,
                changed: false,
            },
        )
        .expect("reset then full persist");
    assert!(persisted_full_snapshot);
    assert_eq!(persist_state.pending_cache_reset, None);
    assert!(!persist_state.needs_full_persist);
    assert_eq!(cache_store.state().reset_calls, 0);
    assert_eq!(cache_store.state().store_calls, 2);
    assert_eq!(cache_store.state().meta_calls, 0);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn notify_changed_increments_revision() {
    let (ready_tx, ready_rx) = watch::channel(false);
    drop(ready_tx);
    let (_readiness_tx, readiness_rx) = watch::channel(WalletReadiness::Syncing);
    let (rev_tx, rev_rx) = watch::channel(0_u64);
    let (reset_generation_tx, reset_generation_rx) = watch::channel(0_u64);
    let (view_tx, view_rx) = watch::channel(WalletViewState::Current(WalletCurrentSnapshot::new(
        0,
        0,
        0,
        Arc::<[WalletUtxo]>::from(Vec::new()),
        Arc::new(WalletPendingOverlay::default()),
    )));
    let (pending_overlay_tx, _pending_overlay_rx) = mpsc::channel(1);
    let (poi_refresh_tx, _poi_refresh_rx) = mpsc::channel(1);
    let (_poi_refreshing_tx, poi_refreshing_rx) = watch::channel(false);
    let (indexed_catch_up_tx, indexed_catch_up_rx) = watch::channel(None);
    let (indexed_catch_up_status_tx, _indexed_catch_up_status_rx) = mpsc::unbounded_channel();
    let handle = WalletHandle {
        cache_key: "cache-key".to_string(),
        chain_id: 1,
        actor_id: 1,
        active_actor_id: Arc::new(AtomicU64::new(1)),
        lifecycle: Arc::new(WalletActorLifecycleCell::new()),
        authority_lock: Arc::new(tokio::sync::Mutex::new(())),
        utxos: Arc::new(RwLock::new(Vec::new())),
        pending_overlay: Arc::new(RwLock::new(WalletPendingOverlay::default())),
        last_scanned: Arc::new(AtomicU64::new(0)),
        reset_generation: Arc::new(AtomicU64::new(0)),
        reset_generation_rx,
        next_sync_job_id: Arc::new(AtomicU64::new(1)),
        ready_rx,
        readiness_rx,
        rev_rx,
        view_rx,
        poi_refreshing_rx,
        indexed_catch_up_rx,
        pending_overlay_tx,
        poi_refresh_tx,
        indexed_catch_up_status_tx,
        rev_tx,
        reset_generation_tx,
        view_tx,
        indexed_catch_up_tx,
    };

    handle.notify_changed().await;
    assert_eq!(*handle.rev_rx.borrow(), 1);

    handle.notify_changed().await;
    assert_eq!(*handle.rev_rx.borrow(), 2);
}

#[tokio::test]
async fn schedulable_progress_uses_view_stamped_generation_not_authority() {
    let handle = test_wallet_handle(Vec::new());
    assert_eq!(
        handle.schedulable_progress(),
        Some(WalletSchedulableProgress {
            last_scanned: 0,
            reset_generation: 0,
        })
    );

    // AcceptReset-style window: authority advances before view is republished.
    assert_eq!(handle.advance_reset_generation().await, Some(1));
    assert_eq!(handle.authority_reset_generation(), 1);
    assert_eq!(
        handle.schedulable_progress(),
        Some(WalletSchedulableProgress {
            last_scanned: 0,
            reset_generation: 0,
        }),
        "public scheduling must not pair the current view cursor with authority generation"
    );

    let cancel = CancellationToken::new();
    let progress = handle
        .wait_schedulable_progress(&cancel)
        .await
        .expect("current view is schedulable");
    assert_eq!(
        progress,
        WalletSchedulableProgress {
            last_scanned: 0,
            reset_generation: 0,
        }
    );
}

#[test]
fn schedulable_progress_revalidate_rejects_generation_mismatch() {
    let ticket = WalletSchedulableProgress {
        last_scanned: 100,
        reset_generation: 0,
    };
    let same_gen_advanced = WalletSchedulableProgress {
        last_scanned: 150,
        reset_generation: 0,
    };
    let new_gen = WalletSchedulableProgress {
        last_scanned: 50,
        reset_generation: 1,
    };
    assert_eq!(
        ticket.revalidate(Some(same_gen_advanced)),
        Some(same_gen_advanced)
    );
    assert_eq!(ticket.revalidate(Some(new_gen)), None);
    assert_eq!(ticket.revalidate(None), None);
    assert!(ticket.still_current(Some(same_gen_advanced)));
    assert!(!ticket.still_current(Some(new_gen)));
}

#[tokio::test]
async fn start_backfill_rejects_stale_progress_ticket() {
    let handle = test_wallet_handle(Vec::new());
    let (sender, _rx) = mpsc::channel(1);
    // Advance view generation by republishing Current with new authority gen.
    assert_eq!(handle.advance_reset_generation().await, Some(1));
    handle.notify_changed().await;
    assert_eq!(
        handle.schedulable_progress().map(|p| p.reset_generation),
        Some(1)
    );

    let stale = WalletSchedulableProgress {
        last_scanned: 0,
        reset_generation: 0,
    };
    let result = handle.start_backfill("cache", &sender, stale, 10).await;
    assert!(
        matches!(
            result,
            crate::types::WalletBackfillFinishResult::Rejected {
                reason: crate::types::WalletBackfillRejectReason::StaleGeneration { .. },
                ..
            }
        ),
        "stale progress ticket must not mint generation-scoped work: {result:?}"
    );
}

#[tokio::test]
async fn wallet_handle_manual_poi_refresh_sends_forced_recovery_request() {
    let (ready_tx, ready_rx) = watch::channel(false);
    drop(ready_tx);
    let (_readiness_tx, readiness_rx) = watch::channel(WalletReadiness::Syncing);
    let (rev_tx, rev_rx) = watch::channel(0_u64);
    let (reset_generation_tx, reset_generation_rx) = watch::channel(0_u64);
    let (view_tx, view_rx) = watch::channel(WalletViewState::Current(WalletCurrentSnapshot::new(
        0,
        0,
        0,
        Arc::<[WalletUtxo]>::from(Vec::new()),
        Arc::new(WalletPendingOverlay::default()),
    )));
    let (pending_overlay_tx, _pending_overlay_rx) = mpsc::channel(1);
    let (poi_refresh_tx, mut poi_refresh_rx) = mpsc::channel::<WalletPoiRefreshRequest>(1);
    let (_poi_refreshing_tx, poi_refreshing_rx) = watch::channel(false);
    let (indexed_catch_up_tx, indexed_catch_up_rx) = watch::channel(None);
    let (indexed_catch_up_status_tx, _indexed_catch_up_status_rx) = mpsc::unbounded_channel();
    let handle = WalletHandle {
        cache_key: "cache-key".to_string(),
        chain_id: 1,
        actor_id: 1,
        active_actor_id: Arc::new(AtomicU64::new(1)),
        lifecycle: Arc::new(WalletActorLifecycleCell::new()),
        authority_lock: Arc::new(tokio::sync::Mutex::new(())),
        utxos: Arc::new(RwLock::new(Vec::new())),
        pending_overlay: Arc::new(RwLock::new(WalletPendingOverlay::default())),
        last_scanned: Arc::new(AtomicU64::new(0)),
        reset_generation: Arc::new(AtomicU64::new(0)),
        reset_generation_rx,
        next_sync_job_id: Arc::new(AtomicU64::new(1)),
        ready_rx,
        readiness_rx,
        rev_rx,
        view_rx,
        poi_refreshing_rx,
        indexed_catch_up_rx,
        pending_overlay_tx,
        poi_refresh_tx,
        indexed_catch_up_status_tx,
        rev_tx,
        reset_generation_tx,
        view_tx,
        indexed_catch_up_tx,
    };

    assert!(handle.refresh_poi_statuses().await);

    let request = poi_refresh_rx.recv().await.expect("refresh request");
    assert!(request.force_output_poi_recovery);
}

#[test]
fn spent_nullifiers_are_scoped_by_tree() {
    let nullifying_key = uint!(42_U256);
    let utxo_tree_one = Utxo::new(
        Note {
            token_hash: uint!(1_U256),
            value: uint!(10_U256),
            random: [0u8; 16],
            npk: uint!(2_U256),
        },
        1,
        7,
        source(1),
        UtxoCommitmentKind::Transact,
    );
    let utxo_tree_two = Utxo::new(
        utxo_tree_one.note.clone(),
        2,
        7,
        source(2),
        UtxoCommitmentKind::Transact,
    );
    let shared_nullifier = utxo_tree_one.nullifier(nullifying_key);
    let spent_source = source(9);
    let nullifier_sources = HashMap::from([((2, shared_nullifier), spent_source.clone())]);

    assert_eq!(
        spent_source_for_utxo(&utxo_tree_one, nullifying_key, &nullifier_sources,),
        None,
    );
    assert_eq!(
        spent_source_for_utxo(&utxo_tree_two, nullifying_key, &nullifier_sources),
        Some(spent_source),
    );
}

#[test]
fn indexed_delta_marks_matching_utxo_spent() {
    let nullifying_key = uint!(42_U256);
    let cfg = wallet_config(nullifying_key);
    let utxo = Utxo::new(
        Note {
            token_hash: uint!(1_U256),
            value: uint!(10_U256),
            random: [0u8; 16],
            npk: uint!(2_U256),
        },
        2,
        7,
        source(1),
        UtxoCommitmentKind::Transact,
    );
    let spent_source = source(9);
    let nullifier = utxo.nullifier(nullifying_key);
    let mut wallet_utxos = vec![WalletUtxo::new(utxo)];
    let delta = WalletLogDelta {
        utxos: Vec::new(),
        nullifiers: vec![SpentNullifier {
            tree: 2,
            nullifier,
            source: spent_source.clone(),
        }],
        commitment_observations: Vec::new(),
    };

    let changed = apply_wallet_delta_to_vec(&cfg, &mut wallet_utxos, delta);

    assert!(changed);
    assert_eq!(wallet_utxos[0].spent, Some(spent_source));
}

#[test]
fn indexed_delta_reports_spent_output_commitment() {
    let nullifying_key = uint!(42_U256);
    let cfg = wallet_config(nullifying_key);
    let utxo = Utxo::new(
        Note {
            token_hash: uint!(1_U256),
            value: uint!(10_U256),
            random: [0u8; 16],
            npk: uint!(2_U256),
        },
        2,
        7,
        source(1),
        UtxoCommitmentKind::Transact,
    );
    let output_commitment = utxo.poi.commitment;
    let nullifier = utxo.nullifier(nullifying_key);
    let mut wallet_utxos = vec![WalletUtxo::new(utxo)];
    let delta = WalletLogDelta {
        utxos: Vec::new(),
        nullifiers: vec![SpentNullifier {
            tree: 2,
            nullifier,
            source: source(9),
        }],
        commitment_observations: Vec::new(),
    };

    let outcome = apply_wallet_delta_to_vec_with_outcome(&cfg, &mut wallet_utxos, delta);

    assert!(outcome.changed);
    assert_eq!(outcome.spent_output_commitments, vec![output_commitment]);
}

#[test]
fn pending_overlay_marks_matching_confirmed_utxo_pending_spent() {
    let nullifying_key = uint!(42_U256);
    let cfg = wallet_config(nullifying_key);
    let wallet_utxo = test_wallet_utxo(7);
    let nullifier = wallet_utxo.utxo.nullifier(nullifying_key);
    let spent_source = source(9);
    let delta = WalletLogDelta {
        utxos: Vec::new(),
        nullifiers: vec![SpentNullifier {
            tree: wallet_utxo.utxo.tree,
            nullifier,
            source: spent_source.clone(),
        }],
        commitment_observations: Vec::new(),
    };

    let overlay = pending_overlay_from_delta(&cfg, &[wallet_utxo], delta);

    assert!(overlay.new_utxos.is_empty());
    assert_eq!(overlay.pending_spent.len(), 1);
    assert_eq!(overlay.pending_spent[0].key(), (2, 7));
    assert_eq!(overlay.pending_spent[0].tx_hash, Some(spent_source.tx_hash));
    assert_eq!(
        overlay.pending_spent[0].block_number,
        Some(spent_source.block_number)
    );
}

#[tokio::test]
async fn local_pending_spent_expires_after_successful_overlay_refresh() {
    let wallet_utxo = test_wallet_utxo(7);
    let handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    let submitted_at = now_epoch_secs().saturating_sub(LOCAL_PENDING_SPENT_TTL.as_secs() + 1);
    {
        let mut overlay = handle.pending_overlay.write().await;
        overlay
            .local_pending_spent
            .push(local_pending_spent_for(&wallet_utxo, submitted_at));
    }

    handle
        .set_chain_pending_overlay(WalletPendingOverlay::default())
        .await;

    assert!(
        handle
            .pending_overlay()
            .expect("current view")
            .local_pending_spent
            .is_empty()
    );
}

#[tokio::test]
async fn local_pending_spent_retains_recent_submissions() {
    let wallet_utxo = test_wallet_utxo(7);
    let handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    let submitted_at = now_epoch_secs();
    {
        let mut overlay = handle.pending_overlay.write().await;
        overlay
            .local_pending_spent
            .push(local_pending_spent_for(&wallet_utxo, submitted_at));
    }

    handle
        .set_chain_pending_overlay(WalletPendingOverlay::default())
        .await;

    assert_eq!(
        handle
            .pending_overlay()
            .expect("current view")
            .local_pending_spent
            .len(),
        1
    );
}

#[tokio::test]
async fn local_pending_spent_updates_existing_submitted_tx_hash() {
    let wallet_utxo = test_wallet_utxo(7);
    let handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    let first_hash = FixedBytes::from([0x11; 32]);
    let replacement_hash = FixedBytes::from([0x22; 32]);

    handle
        .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), Some(first_hash))
        .await;
    handle
        .mark_pending_spent_utxos(
            std::slice::from_ref(&wallet_utxo.utxo),
            Some(replacement_hash),
        )
        .await;

    let overlay = handle.pending_overlay().expect("current view");
    assert_eq!(overlay.local_pending_spent.len(), 1);
    assert_eq!(
        overlay.local_pending_spent[0].tx_hash,
        Some(replacement_hash)
    );
}

#[tokio::test]
async fn local_pending_spent_prunes_when_chain_pending_covers_key() {
    let wallet_utxo = test_wallet_utxo(7);
    let handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    let submitted_at = now_epoch_secs();
    let pending_spent = local_pending_spent_for(&wallet_utxo, submitted_at);
    {
        let mut overlay = handle.pending_overlay.write().await;
        overlay.local_pending_spent.push(pending_spent.clone());
    }

    handle
        .set_chain_pending_overlay(WalletPendingOverlay {
            pending_spent: vec![pending_spent],
            ..WalletPendingOverlay::default()
        })
        .await;

    let overlay = handle.pending_overlay().expect("current view");
    assert!(overlay.local_pending_spent.is_empty());
    assert_eq!(overlay.pending_spent.len(), 1);
}

#[tokio::test]
async fn local_pending_spent_prunes_when_confirmed_spent_covers_key() {
    let mut wallet_utxo = test_wallet_utxo(7);
    let pending_spent = local_pending_spent_for(&wallet_utxo, now_epoch_secs());
    wallet_utxo.spent = Some(source(9));
    let handle = test_wallet_handle(vec![wallet_utxo]);
    {
        let mut overlay = handle.pending_overlay.write().await;
        overlay.local_pending_spent.push(pending_spent);
    }

    handle
        .set_chain_pending_overlay(WalletPendingOverlay::default())
        .await;

    assert!(
        handle
            .pending_overlay()
            .expect("current view")
            .local_pending_spent
            .is_empty()
    );
}

#[tokio::test]
async fn clear_local_pending_spent_removes_manual_locks() {
    let wallet_utxo = test_wallet_utxo(7);
    let handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    {
        let mut overlay = handle.pending_overlay.write().await;
        overlay
            .local_pending_spent
            .push(local_pending_spent_for(&wallet_utxo, now_epoch_secs()));
    }

    assert!(handle.clear_local_pending_spent().await);
    assert!(
        handle
            .pending_overlay()
            .expect("current view")
            .local_pending_spent
            .is_empty()
    );
    assert!(!handle.clear_local_pending_spent().await);
}

#[test]
fn spent_output_discards_pending_output_poi_context() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x91; 32]);
    store
        .put_pending_output_poi_context(&pending_output_record(
            chain_id,
            output_commitment,
            FixedBytes::from([0x92; 32]),
        ))
        .expect("store pending context");

    discard_pending_output_poi_contexts_for_spent_outputs(
        &store,
        chain_id,
        "wallet-1",
        &[output_commitment],
    )
    .expect("discard spent pending output context");

    assert!(
        store
            .get_pending_output_poi_context(chain_id, "wallet-1", &output_commitment)
            .expect("load pending context")
            .is_none()
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn output_poi_recovery_candidates_skip_spent_utxos() {
    let list_key = FixedBytes::from([0x93; 32]);
    let mut spent = test_wallet_utxo(7);
    spent.utxo.poi.statuses.insert(list_key, PoiStatus::Missing);
    spent.spent = Some(source(9));
    let mut unspent = test_wallet_utxo(8);
    unspent
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    let wallet_utxos = vec![spent, unspent];

    let candidates = output_poi_recovery_candidates(&wallet_utxos, &[list_key]);

    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].utxo.position, 8);
}

#[test]
fn indexed_delta_preserves_unmatched_utxo() {
    let nullifying_key = uint!(42_U256);
    let cfg = wallet_config(nullifying_key);
    let utxo = Utxo::new(
        Note {
            token_hash: uint!(1_U256),
            value: uint!(10_U256),
            random: [0u8; 16],
            npk: uint!(2_U256),
        },
        2,
        7,
        source(1),
        UtxoCommitmentKind::Transact,
    );
    let nullifier = utxo.nullifier(nullifying_key);
    let mut wallet_utxos = vec![WalletUtxo::new(utxo)];
    let delta = WalletLogDelta {
        utxos: Vec::new(),
        nullifiers: vec![SpentNullifier {
            tree: 3,
            nullifier,
            source: source(9),
        }],
        commitment_observations: Vec::new(),
    };

    let changed = apply_wallet_delta_to_vec(&cfg, &mut wallet_utxos, delta);

    assert!(!changed);
    assert!(wallet_utxos[0].spent.is_none());
}
