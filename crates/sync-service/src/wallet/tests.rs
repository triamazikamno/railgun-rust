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

mod pending_output_records;
mod pending_output_submitters;
mod poi_status_mocks;
mod recording_cache_store;

#[allow(clippy::wildcard_imports)]
use pending_output_records::*;
#[allow(clippy::wildcard_imports)]
use pending_output_submitters::*;
#[allow(clippy::wildcard_imports)]
use poi_status_mocks::*;
#[allow(clippy::wildcard_imports)]
use recording_cache_store::*;

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
