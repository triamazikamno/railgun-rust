use super::delta::{
    sender_scan_candidate_inputs, spent_source_for_utxo,
    test_support::{
        apply_wallet_delta_to_vec, discard_pending_output_poi_contexts_for_spent_outputs,
    },
};
use super::handle::{
    LOCAL_PENDING_SPENT_TTL, WALLET_POI_RECOVERABLE_REFRESH_AFTER, WalletPoiRefreshRequest,
    test_support::{WALLET_METADATA_LIVE_FLUSH_BLOCKS, WALLET_METADATA_LIVE_FLUSH_INTERVAL},
};
use super::local_poi_cache::test_support::install_tailed_poi_cache_if_current;
use super::output_poi_recovery::test_support::{
    PublicCacheTxidRecoveryRequest, force_resubmit_matching_pending_output_pois,
    recovered_output_txid_data_from_public_cache,
};
use super::output_poi_recovery::{
    MatchingPendingOutputPoiContextDisposition, OutputPoiProofSourceResolution,
    PublicTxidRecoveryBuildRequest, RecoveryChunk, RecoverySpendPublicKey, WalletNullifierIndex,
    build_output_poi_recovery_chunk, build_output_poi_recovery_chunk_from_public_cache,
    build_output_poi_recovery_chunk_from_public_rows, decode_railgun_transactions,
    extend_pending_output_poi_context, matching_pending_output_poi_context_disposition,
    newly_recoverable_output_poi_list_keys, output_poi_recovery_proof_retry_after,
    output_poi_recovery_retry_allowed_for_lists, output_start_global_position,
    preflight_local_output_poi_input_proofs, recoverable_output_poi_list_keys,
};
use super::pending_output_poi::{
    PoiPrivateRows, pending_output_poi_observation_state_updates,
    pending_output_poi_submit_identity, prepare_pending_output_poi_tentative_candidates,
    test_support::{
        pending_output_poi_observation_updates, process_pending_output_poi_observations,
        process_pending_output_poi_observations_inner, verify_submitted_pending_output_pois,
        verify_submitted_pending_output_pois_authorized_with_projection,
        verify_submitted_pending_output_pois_with_config,
    },
    wallet_ppoi_workflow_status_after_mutations,
};
use super::persist::PoiMaintenanceError;
use super::sender_candidate_recovery::{
    SenderCandidatePublicDataFence, SenderCandidateRecoveryRequest, SenderUnshieldAttempts,
    SenderUnshieldInputs, materialize_sender_transaction_candidates,
    process_sender_candidate_unshields, sender_unshield_valid_txids,
};
use super::test_support::sync_live_poi_event_tail;
use super::{
    DEFAULT_TXID_VERSION, DeferredForceKind, DeferredForcedSubmissions, EVM_CHAIN_TYPE,
    ExpectedPoiCorpusRevision, ExpectedPoiListState, ExpectedPoiStatus, ExpectedRecordState,
    ExpectedWalletOutput, LocalPoiMerkleProofSource, LocalPoiStatusReader,
    OUTPUT_POI_RECOVERY_PROOF_FAILURE_RETRY_AFTER, OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
    OutputPoiRecoveryRequest, OutputPoiRecoveryRun, OutputRecoveryDelta, OwnedPoiPrivateDelta,
    PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER, PendingOutputPoiSubject,
    PendingOutputPoiSubmissionPredicate, PendingOutputPoiSubmissionPreflight,
    PendingOutputPoiSubmitter, PendingOutputPoiValidationEvidence, PendingSubmissionDelta,
    PoiMaintenanceController, PoiPrivateApplyOutcome, PoiStatusReader, PoiStatusRefreshDelta,
    RecoveredOutgoingSubmissionDelta, RecoveredOutgoingSubmissionSibling,
    SenderCandidateMaterializationDelta, VerifiedValidDelta, WALLET_POI_STATUS_BATCH_SIZE,
    WalletActorLifecycleCell, WalletHandle, WalletLiveMetadataFlush, WalletObservationPublisher,
    WalletPendingOverlay, WalletPendingSpent, WalletPersistState, WalletPoiRefreshSelection,
    WalletPoiRuntime, WalletPrivateApplyClient, WalletPrivateApplyRequest,
    WalletPrivateMutationAuthority, WalletPrivatePoiClients, WalletProgressPersist,
    WalletProgressPrivateEffects, WalletViewState, apply_owned_poi_private_delta_on_actor,
    apply_owned_poi_private_delta_on_actor_with_active_lists,
    apply_wallet_delta_to_vec_with_outcome, default_active_poi_list_keys,
    force_resubmit_matching_pending_output_pois_authorized, now_epoch_secs,
    output_poi_recovery_candidates, pending_output_poi_context_fingerprint,
    pending_output_poi_context_matches_wallet_utxo, pending_overlay_from_delta,
    preflight_and_remote_submit_pending_output_poi,
    process_pending_output_poi_observations_authorized, recover_missing_output_pois,
    refresh_wallet_poi_statuses_remote_authorized, refresh_wallet_poi_statuses_selected,
    rewind_wallet_utxos, submit_observed_pending_output_pois_inner,
    submit_pending_output_poi_tentative_candidates,
    verify_submitted_pending_output_pois_with_config_authorized, wallet_poi_status_client,
    wallet_poi_status_refresh_needed, wallet_poi_status_refresh_needed_for_selection,
};
use crate::chain::PublicTxidTransaction;
use crate::chain::poi_submitter_test_support::{RecordingPoiTransport, ScriptedSend};
use crate::chain::{
    ChainPoiSubmitterHandle, ChainPublicDataPlane, PublicPoiCorpusHandle, PublicPoiCorpusKey,
    PublicTxidCacheKey as DataPlanePublicTxidCacheKey, PublicTxidDataAuthority,
    PublicTxidLatestValidated as DataPlanePublicTxidLatestValidated, PublicTxidProofRequest,
    PublicTxidProofTarget, PublicTxidSyncRequest,
};
use crate::indexed_artifacts::{ChainScope, ChainType};
use crate::poi_submission::test_support::{RecordingRoutes, seeded_scheduler};
use crate::poi_submission::{
    MAX_ADMISSION_GAP, PoiSubmissionAdmission, PoiSubmissionRouting, PoiSubmissionScheduler,
    PoiSubmissionSchedulerConfig,
};
use crate::txid_cache::TxidPublicCacheTransaction;
use crate::txid_cache::{TxidPublicCacheKey, seed_verified_artifact_bound_for_test};
use crate::types::{
    ChainKey, GlobalPoiPolicy, PendingOutputPoiContextIntent, PoiArtifactManifestSource,
    PoiArtifactSourceConfig, PoiProxyFallback, WalletCacheStore, WalletCheckpointMutation,
    WalletConfig, WalletCurrentSnapshot, WalletInactiveReason, WalletLocalPoiCaches,
    WalletPpoiSubmissionStatus, WalletPpoiWorkflowStatus, WalletPrivateCommit,
    WalletPrivateRequestError, WalletSchedulableProgress, WalletSyncActorStateCommit,
    WalletUtxoMutation,
};
use crate::{
    SenderTransactionCandidate, SenderTransactionCandidateOutput, SenderTransactionCandidateSpend,
    SenderTransactionCandidateUnshield,
};
use alloy::hex;
use alloy::primitives::{Address, Bytes, FixedBytes, U64, U256};
use alloy::sol_types::{SolCall, SolValue};
use alloy::uint;
use async_trait::async_trait;
use broadcaster_core::contracts::railgun::{
    BoundParams, Call, CommitmentCiphertext, CommitmentPreimage, RelayAdapt7702ActionData,
    SnarkProof, Transaction, executeCall,
};
use broadcaster_core::crypto::railgun::ViewingKeyData;
use broadcaster_core::notes::Note;
use broadcaster_core::transact::{
    MERKLE_ZERO_VALUE, PreTxPoi, compute_railgun_txid_parts, railgun_txid_leaf_hash,
    railgun_txid_leaf_hash_with_output_start,
};
use broadcaster_core::tree::{TREE_DEPTH, TREE_LEAF_COUNT};
use local_db::{
    DbConfig, DbStore, OpaqueWalletPrivateRow, OutputPoiRecoveryAction, OutputPoiRecoveryRecord,
    OutputPoiRecoveryStatus, PendingOutputPoiContextRecord, PendingOutputPoiRole, WalletCacheKey,
    WalletMeta, WalletPrivateRecordKind, WalletSyncActorStateRecord,
};
use merkletree::quick::IndexedRailgunTransaction;
use merkletree::tree::{DenseMerkleTree, MerkleForest, MerkleTreeUpdate};
use poi::SensitiveUrl;
use poi::cache::{PoiCache, PoiCacheIdentity};
use poi::error::{PoiError, PoiRpcError};
use poi::poi::{
    BlindedCommitmentData, PoiEventType, PoiMerkleProof, PoiRpcClient, SingleCommitmentProofContext,
};
use railgun_wallet::artifacts::ArtifactSource;
use railgun_wallet::prover::{ProverError, ProverService};
use railgun_wallet::scan::{
    CommitmentObservation, SenderScanOutput, SpentNullifier, WalletLogDelta,
};
use railgun_wallet::tx::{
    InputWitness, PoiMerkleProofSource, PostTransactionPoiData, PreTransactionPoiError,
    PreTransactionPoiMap, PrivateInputs, PublicInputs, TransactionPlanChunk,
};
use railgun_wallet::wallet_cache::{WalletCacheError, wallet_utxo_stable_identity};
use railgun_wallet::{
    NoteCiphertext, PoiStatus, Utxo, UtxoCommitmentKind, UtxoPoiMetadata, UtxoSource, WalletUtxo,
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::ops::{Deref, DerefMut};
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

fn sender_candidate_for_spent_input(
    wallet_id: WalletCacheKey,
    input: &WalletUtxo,
    spent_source: UtxoSource,
) -> SenderTransactionCandidate {
    let note = Note {
        token_hash: U256::from(7),
        value: U256::from(9),
        random: [0x5a; 16],
        npk: U256::from(11),
    };
    SenderTransactionCandidate::new(
        1,
        wallet_id,
        spent_source,
        vec![SenderTransactionCandidateSpend {
            tree: input.utxo.tree,
            position: input.utxo.position,
            commitment: input.utxo.poi.commitment,
        }],
        vec![SenderTransactionCandidateOutput {
            tree: 3,
            position: 4,
            commitment: FixedBytes::from(note.commitment().to_be_bytes::<32>()),
            note: Some(note),
        }],
    )
    .expect("valid sender candidate")
}

async fn sender_candidate_public_data_fence(
    db: &Arc<DbStore>,
    cfg: &WalletConfig,
    candidate: &SenderTransactionCandidate,
    input: &WalletUtxo,
    output_commitment: FixedBytes<32>,
    row_timestamp: u64,
) -> (ChainPublicDataPlane, SenderCandidatePublicDataFence) {
    let graph_response = serde_json::json!({
        "data": {
            "transactions": [{
                "id": "0x00",
                "blockNumber": candidate.source.block_number.to_string(),
                "blockTimestamp": row_timestamp.to_string(),
                "transactionHash": hex::encode_prefixed(candidate.source.tx_hash),
                "merkleRoot": "0x01",
                "nullifiers": [hex::encode_prefixed(FixedBytes::from(
                    input.utxo.nullifier(cfg.scan_keys.nullifying_key).to_be_bytes::<32>()
                ))],
                "commitments": [hex::encode_prefixed(output_commitment)],
                "boundParamsHash": "0x02",
                "hasUnshield": false,
                "utxoTreeIn": input.utxo.tree.to_string(),
                "utxoTreeOut": "3",
                "utxoBatchStartPositionOut": "4",
            }]
        }
    })
    .to_string()
    .into_bytes();
    let (endpoint, _requests) = spawn_http_response(graph_response).await;
    let public_data_plane = ChainPublicDataPlane::new(Arc::clone(db), Arc::new(AtomicU64::new(0)));
    let cache_key = DataPlanePublicTxidCacheKey::new(
        ChainScope {
            chain_type: ChainType::Evm,
            chain_id: cfg.chain.chain_id,
            railgun_contract: cfg.chain.contract,
        },
        DEFAULT_TXID_VERSION,
    );
    public_data_plane
        .sync_txid_public_cache(PublicTxidSyncRequest {
            key: cache_key.clone(),
            endpoint: Some(&endpoint),
            http_client: None,
            latest: DataPlanePublicTxidLatestValidated {
                txid_index: 0,
                merkleroot: None,
            },
            indexed_artifact_source: None,
        })
        .await
        .expect("seed sender public TXID row");
    let rows = public_data_plane
        .txid_transactions_for_outer_hash(&cache_key, candidate.source.tx_hash)
        .expect("load sender public TXID row");
    let fence = SenderCandidatePublicDataFence::new(
        &public_data_plane,
        cache_key,
        public_data_plane.current_epoch(),
        rows,
        PublicTxidDataAuthority::LatestValidated,
    );
    (public_data_plane, fence)
}

fn test_cache_key(value: impl AsRef<[u8]>) -> WalletCacheKey {
    WalletCacheKey::from_opaque_bytes(value.as_ref()).expect("non-empty test wallet cache key")
}

/// Expected revision of a private corpus that nothing advances, so the actor-side recheck passes.
fn current_poi_corpus_revision() -> ExpectedPoiCorpusRevision {
    let corpus = PublicPoiCorpusHandle::new_for_test(WalletLocalPoiCaches::new());
    let revision = *corpus.committed_revision_rx().borrow();
    ExpectedPoiCorpusRevision { corpus, revision }
}

fn wallet_config(nullifying_key: U256) -> WalletConfig {
    WalletConfig {
        chain: ChainKey {
            chain_id: 1,
            contract: Address::ZERO,
        },
        cache_key: test_cache_key("test"),
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

fn test_artifact_poi_runtime_with_fallback(rpc_url: Url) -> WalletPoiRuntime {
    WalletPoiRuntime::from_policy(
        &GlobalPoiPolicy::IndexedArtifacts {
            artifact_source: test_poi_artifact_source_config(),
            rpc_url: rpc_url.into(),
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
            .expect("initialize POI cache generation")
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

struct TestWalletHandle {
    handle: WalletHandle,
    _observation: Arc<WalletObservationPublisher>,
}

impl Deref for TestWalletHandle {
    type Target = WalletHandle;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl DerefMut for TestWalletHandle {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.handle
    }
}

fn test_wallet_handle(utxos: Vec<WalletUtxo>) -> TestWalletHandle {
    let (rev_tx, rev_rx) = watch::channel(0_u64);
    let (reset_generation_tx, reset_generation_rx) = watch::channel(0_u64);
    let (observation, observation_rx) =
        WalletObservationPublisher::new(WalletViewState::Current(WalletCurrentSnapshot::new(
            0,
            0,
            0,
            Arc::<[WalletUtxo]>::from(utxos.clone()),
            Arc::new(WalletPendingOverlay::default()),
        )));
    let (pending_overlay_tx, _pending_overlay_rx) = mpsc::channel(1);
    let (private_request_tx, _private_request_rx) = mpsc::channel(1);
    let (poi_refresh_tx, _poi_refresh_rx) = mpsc::channel(1);
    let (_poi_refreshing_tx, poi_refreshing_rx) = watch::channel(false);
    let (indexed_catch_up_tx, indexed_catch_up_rx) = watch::channel(None);
    let (indexed_catch_up_status_tx, _indexed_catch_up_status_rx) = mpsc::unbounded_channel();
    let handle = WalletHandle {
        cache_key: test_cache_key("cache-key"),
        chain: ChainKey {
            chain_id: 1,
            contract: Address::ZERO,
        },
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
        observation: Arc::downgrade(&observation),
        observation_rx,
        rev_rx,
        poi_refreshing_rx,
        indexed_catch_up_rx,
        pending_overlay_tx,
        private_request_tx,
        poi_refresh_tx,
        indexed_catch_up_status_tx,
        rev_tx,
        reset_generation_tx,
        indexed_catch_up_tx,
    };
    TestWalletHandle {
        handle,
        _observation: observation,
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
    next_remote_error: Mutex<Option<RecordingPendingOutputPoiRemoteError>>,
}

#[derive(Clone, Copy)]
enum RecordingPendingOutputPoiRemoteError {
    MissingRailgunTxid,
    Other,
}

impl RecordingPendingOutputPoiSubmitter {
    fn fail_next(&self) {
        *self.fail_next.lock().expect("fail next") = true;
    }

    fn fail_next_missing_railgun_txid(&self) {
        *self.next_remote_error.lock().expect("remote error") =
            Some(RecordingPendingOutputPoiRemoteError::MissingRailgunTxid);
    }

    fn fail_next_other_remote_error(&self) {
        *self.next_remote_error.lock().expect("remote error") =
            Some(RecordingPendingOutputPoiRemoteError::Other);
    }

    fn take_error(&self) -> Option<PoiError> {
        if let Some(error) = self.next_remote_error.lock().expect("remote error").take() {
            let message = match error {
                RecordingPendingOutputPoiRemoteError::MissingRailgunTxid => {
                    "Could not find railgun txid"
                }
                RecordingPendingOutputPoiRemoteError::Other => "different remote failure",
            };
            return Some(PoiError::RpcRequest {
                source: PoiRpcError::JsonRpc {
                    code: -1,
                    message: message.to_owned(),
                    data: None,
                },
            });
        }
        let mut fail_next = self.fail_next.lock().expect("fail next");
        if *fail_next {
            *fail_next = false;
            Some(PoiError::MerkleRootsRejected)
        } else {
            None
        }
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
        if let Some(error) = self.take_error() {
            return Err(error);
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
        if let Some(error) = self.take_error() {
            return Err(error);
        }
        Ok(())
    }
}

struct BlockingPendingOutputPoiSubmitter {
    started: tokio::sync::Mutex<Option<oneshot::Sender<()>>>,
    release: tokio::sync::Mutex<Option<oneshot::Receiver<()>>>,
    calls: Mutex<Vec<(FixedBytes<32>, u64, u64)>>,
}

struct ResetAfterFirstPendingOutputPoiSubmitter {
    handle: WalletHandle,
    calls: AtomicU64,
}

struct InvalidateOwnedSubstituteAfterSubmitter {
    handle: WalletHandle,
    list_key: FixedBytes<32>,
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

#[async_trait]
impl PendingOutputPoiSubmitter for InvalidateOwnedSubstituteAfterSubmitter {
    async fn submit_single_commitment_proofs(
        &self,
        _txid_version: &str,
        _chain_type: u8,
        _chain_id: u64,
        _context: &SingleCommitmentProofContext,
        _utxo_tree_out: u64,
        _utxo_position_out: u64,
    ) -> Result<(), PoiError> {
        unreachable!("recovered outgoing group uses transact submission")
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
        self.calls.fetch_add(1, Ordering::AcqRel);
        self.handle.utxos.write().await[0]
            .utxo
            .poi
            .statuses
            .insert(self.list_key, PoiStatus::Missing);
        Ok(())
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

fn sample_pre_tx_poi(_byte: u8) -> PreTxPoi {
    current_poi_fixture("ppoi_3x3").pre_tx_poi
}

#[derive(serde::Deserialize)]
struct CurrentPoiFixture {
    pre_tx_poi: PreTxPoi,
    public_context: CurrentPoiPublicContext,
}

#[derive(serde::Deserialize)]
struct CurrentPoiPublicContext {
    commitments_out: Vec<U256>,
    output_npks: Vec<U256>,
    output_values: Vec<U256>,
    output_start_global: U256,
    railgun_txid: U256,
    input_tree: u64,
}

fn current_poi_fixture(name: &str) -> CurrentPoiFixture {
    let bytes: &[u8] = match name {
        "ppoi_3x3" => include_bytes!("../../../core/tests/fixtures/ppoi_3x3.json"),
        "ppoi_3x3_two_outputs" => {
            include_bytes!("../../../core/tests/fixtures/ppoi_3x3_two_outputs.json")
        }
        _ => panic!("unknown PPOI test fixture"),
    };
    serde_json::from_slice(bytes).expect("current proof fixture")
}

fn previous_key_pending_context(
    context: &PendingOutputPoiContextRecord,
) -> PendingOutputPoiContextRecord {
    let fixture: CurrentPoiFixture = serde_json::from_slice(include_bytes!(
        "../../../core/tests/fixtures/ppoi_3x3_previous.json"
    ))
    .expect("previous-key proof fixture");
    let mut old = context.clone();
    for per_leaf in old.pre_transaction_pois_per_txid_leaf_per_list.values_mut() {
        for poi in per_leaf.values_mut() {
            *poi = fixture.pre_tx_poi.clone();
        }
    }
    old
}

fn pending_output_record(
    chain_id: u64,
    output_commitment: FixedBytes<32>,
    list_key: FixedBytes<32>,
) -> PendingOutputPoiContextRecord {
    let txid_leaf = FixedBytes::from([0x55; 32]);
    PendingOutputPoiContextRecord {
        chain_id,
        wallet_id: test_cache_key("wallet-1").to_string(),
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
    record.wallet_id = cfg.cache_key.to_string();
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

fn external_pending_output_record(
    cfg: &WalletConfig,
    byte: u8,
    list_key: FixedBytes<32>,
    output_role: PendingOutputPoiRole,
) -> PendingOutputPoiContextRecord {
    let mut record =
        pending_output_record(cfg.chain.chain_id, FixedBytes::from([byte; 32]), list_key);
    record.wallet_id = cfg.cache_key.to_string();
    record.output_role = output_role;
    record.observation = Some(local_db::PendingOutputPoiObservation {
        output_tree: u64::from(byte),
        output_position: u64::from(byte) + 1,
        tx_hash: source(byte).tx_hash,
        block_number: u64::from(byte),
        block_timestamp: 1_700_000_000 + u64::from(byte),
    });
    record
}

fn recovered_outgoing_pending_group(
    cfg: &WalletConfig,
    list_key: FixedBytes<32>,
) -> Vec<PendingOutputPoiContextRecord> {
    let source = source(0xd0);
    let fixture = current_poi_fixture("ppoi_3x3_two_outputs");
    let global: u128 = fixture.public_context.output_start_global.to();
    let material = BTreeMap::from([(
        list_key,
        BTreeMap::from([(FixedBytes::from([0xd3; 32]), fixture.pre_tx_poi.clone())]),
    )]);
    fixture
        .public_context
        .commitments_out
        .iter()
        .enumerate()
        .map(|(index, commitment)| {
            let mut record = external_pending_output_record(
                cfg,
                0xd1 + u8::try_from(index).expect("bounded output index"),
                list_key,
                PendingOutputPoiRole::RecoveredOutgoing,
            );
            record.txid_merkleroot_index = Some(77);
            record.source_operation_id = Some("test-recovered-sender-inner-7".to_string());
            record.output_commitment = FixedBytes::from(commitment.to_be_bytes::<32>());
            record.output_npk =
                FixedBytes::from(fixture.public_context.output_npks[index].to_be_bytes::<32>());
            record.utxo_tree_in = fixture.public_context.input_tree;
            record.railgun_txid = fixture.public_context.railgun_txid;
            let position = global + u128::try_from(index).expect("bounded index");
            record.observation = Some(local_db::PendingOutputPoiObservation {
                output_tree: u64::try_from(position / u128::from(TREE_LEAF_COUNT))
                    .expect("output tree"),
                output_position: u64::try_from(position % u128::from(TREE_LEAF_COUNT))
                    .expect("output position"),
                tx_hash: source.tx_hash,
                block_number: source.block_number,
                block_timestamp: source.block_timestamp,
            });
            record.pre_transaction_pois_per_txid_leaf_per_list = material.clone();
            record
        })
        .collect()
}

fn seed_recovered_outgoing_pending_group(
    store: &DbStore,
    cfg: &WalletConfig,
    records: &[PendingOutputPoiContextRecord],
) {
    for record in records {
        store
            .put_pending_output_poi_context(record)
            .expect("store recovered outgoing context");
        let mut recovery = output_poi_recovery_record(
            cfg.chain.chain_id,
            &cfg.cache_key,
            record.output_commitment,
            OutputPoiRecoveryStatus::Recoverable,
            None,
        );
        recovery.source_tx_hash = record.observation.as_ref().expect("observation").tx_hash;
        store
            .put_output_poi_recovery(&recovery)
            .expect("store recovered outgoing recovery");
    }
}

struct SenderMaterializationTestFixture {
    cfg: WalletConfig,
    candidate: SenderTransactionCandidate,
    input: WalletUtxo,
    pending: Vec<PendingOutputPoiContextRecord>,
    recoveries: Vec<OutputPoiRecoveryRecord>,
    fence: SenderCandidatePublicDataFence,
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

fn wallet_ppoi_workflow_status_for_test(
    store: &DbStore,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    validation_revision: u64,
) -> WalletPpoiWorkflowStatus {
    wallet_ppoi_workflow_status_after_mutations(
        store,
        cfg,
        active_list_keys,
        validation_revision,
        PoiPrivateRows::default(),
    )
    .expect("derive workflow status")
    .status
}

#[derive(Debug, Clone, Copy, Default)]
struct RecordingCacheState {
    store_calls: usize,
    meta_calls: usize,
    reset_calls: usize,
    pending_output_read_calls: usize,
    pending_output_list_calls: usize,
    output_recovery_read_calls: usize,
    fail_next_store: bool,
    fail_next_commit: bool,
    fail_pending_output_list_call: Option<usize>,
    candidate_list_calls: usize,
    fail_next_candidate_list: bool,
}

struct RecordingCacheStore {
    db: Arc<DbStore>,
    state: Mutex<RecordingCacheState>,
    context_replacement: Mutex<Option<(usize, PendingOutputPoiContextRecord)>>,
}

impl RecordingCacheStore {
    fn new(db: Arc<DbStore>) -> Self {
        Self {
            db,
            state: Mutex::default(),
            context_replacement: Mutex::default(),
        }
    }

    fn replace_context_before_recovery_read(
        &self,
        call_index: usize,
        replacement: PendingOutputPoiContextRecord,
    ) {
        *self.context_replacement.lock().expect("replacement state") =
            Some((call_index, replacement));
    }

    fn fail_next_store(&self) {
        self.state.lock().expect("cache state").fail_next_store = true;
    }

    fn fail_next_commit(&self) {
        self.state.lock().expect("cache state").fail_next_commit = true;
    }

    fn fail_pending_output_list_call(&self, call_index: usize) {
        self.state
            .lock()
            .expect("cache state")
            .fail_pending_output_list_call = Some(call_index);
    }

    fn fail_next_candidate_list(&self) {
        self.state
            .lock()
            .expect("cache state")
            .fail_next_candidate_list = true;
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
        if matches!(commit.utxo_mutation(), WalletUtxoMutation::Replace(_)) {
            let mut state = self.state.lock().expect("cache state");
            state.store_calls += 1;
            if state.fail_next_store {
                state.fail_next_store = false;
                return Err(WalletCacheError::Crypto);
            }
        } else {
            self.state.lock().expect("cache state").meta_calls += 1;
        }
        let mut state = self.state.lock().expect("cache state");
        if state.fail_next_commit {
            state.fail_next_commit = false;
            return Err(WalletCacheError::Crypto);
        }
        drop(state);
        <DbStore as WalletCacheStore>::commit_wallet_private_state(self.db.as_ref(), commit)
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
        Ok(None)
    }

    fn put_wallet_sync_actor_state(
        &self,
        commit: WalletSyncActorStateCommit<'_>,
    ) -> Result<(), WalletCacheError> {
        self.db.put_wallet_sync_actor_state(commit.state())?;
        Ok(())
    }

    fn get_pending_output_poi_context(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
        output_commitment: &FixedBytes<32>,
    ) -> Result<Option<PendingOutputPoiContextRecord>, WalletCacheError> {
        self.state
            .lock()
            .expect("cache state")
            .pending_output_read_calls += 1;
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
        let mut state = self.state.lock().expect("cache state");
        state.pending_output_read_calls += 1;
        let call_index = state.pending_output_list_calls;
        state.pending_output_list_calls += 1;
        if state.fail_pending_output_list_call == Some(call_index) {
            state.fail_pending_output_list_call = None;
            return Err(WalletCacheError::Crypto);
        }
        drop(state);
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
        let call_index = {
            let mut state = self.state.lock().expect("cache state");
            let call_index = state.output_recovery_read_calls;
            state.output_recovery_read_calls += 1;
            call_index
        };
        let replacement = {
            let mut replacement = self.context_replacement.lock().expect("replacement state");
            if replacement
                .as_ref()
                .is_some_and(|(replace_at, _)| *replace_at == call_index)
            {
                replacement.take().map(|(_, replacement)| replacement)
            } else {
                None
            }
        };
        if let Some(replacement) = replacement {
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
        self.state
            .lock()
            .expect("cache state")
            .output_recovery_read_calls += 1;
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
        let mut state = self.state.lock().expect("cache state");
        state.candidate_list_calls += 1;
        if state.fail_next_candidate_list {
            state.fail_next_candidate_list = false;
            return Err(WalletCacheError::Crypto);
        }
        drop(state);
        <DbStore as WalletCacheStore>::list_sender_transaction_candidates(
            self.db.as_ref(),
            chain_id,
            wallet_id,
        )
    }
}

struct PartialUnshieldFixture {
    root_dir: PathBuf,
    db: Arc<DbStore>,
    cfg: WalletConfig,
    list_key: FixedBytes<32>,
    candidate: SenderTransactionCandidate,
    railgun_txid: FixedBytes<32>,
    wallet_utxos: Vec<WalletUtxo>,
    handle: TestWalletHandle,
    public_data_plane: ChainPublicDataPlane,
    /// Records every unshield POI transmission made by the fixture's maintenance runs.
    submitter: Arc<RecordingPendingOutputPoiSubmitter>,
    /// Per-transaction routes for the fixture's submissions; `None` uses `submitter`.
    routing: Option<PoiSubmissionRouting>,
}

impl PartialUnshieldFixture {
    fn stored_candidate(&self) -> Option<SenderTransactionCandidate> {
        self.db
            .get_sender_transaction_candidate(
                self.cfg.chain.chain_id,
                &self.cfg.cache_key,
                &self.candidate.semantic_id(),
            )
            .expect("load sender candidate")
    }

    fn published_workflow(&self) -> WalletPpoiWorkflowStatus {
        *self.handle.observation().ppoi_workflow_status()
    }

    /// Test actor loop: apply each private commit on the fixture wallet until the channel closes.
    async fn apply_private_commits(
        &self,
        apply_rx: &mut mpsc::Receiver<WalletPrivateApplyRequest>,
        cancel: &CancellationToken,
    ) {
        let active_list_keys = [self.list_key];
        while let Some(request) = apply_rx.recv().await {
            let result = apply_owned_poi_private_delta_on_actor_with_active_lists(
                &self.handle,
                cancel,
                request.reset_generation,
                self.db.as_ref(),
                self.db.as_ref(),
                &self.cfg,
                &active_list_keys,
                request.delta,
            )
            .await;
            request.reply.send(result).expect("send actor result");
        }
    }
}

#[derive(Clone, Copy)]
enum UnshieldFixtureShape {
    /// The fee and change PPOIs are Valid locally.
    OutputsValid,
    /// Compatible pending contexts cover the fee and change.
    OutputsCovered,
    /// A full unshield with no private outputs, optionally spending a Shield-blocked input. The
    /// block is known only to the local corpus: the stored statuses of the spent input are not
    /// refreshed. The spend is not scanned yet: the input is unspent and no candidate is stored.
    UnshieldOnly { input_blocked: bool },
    /// A self-broadcast partial unshield: owned change and the unshield, with no broadcaster
    /// fee. The change PPOI is not Valid locally.
    SelfBroadcast,
}

#[path = "saved_poi_compatibility/tests.rs"]
mod saved_poi_migration_tests;

mod external_pending_output;
mod force_resubmit;
mod output_recovery;
mod pending_output;
mod poi_status;
mod recovered_outgoing;
mod recovery_extension;
mod sender_candidates;
mod sender_materialization;
mod utxo_state;
mod workflow_status;
