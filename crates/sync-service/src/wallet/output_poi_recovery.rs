use super::saved_poi_compatibility::saved_pending_context_is_compatible;
use railgun_wallet::ProverService;
use railgun_wallet::tx::PoiMerkleProofSource;

use crate::types::PoiCorpusRevision;

use super::{
    Arc, ChainPublicDataPlane, ChainScope, ChainType, DEFAULT_TXID_VERSION, DbStore, Duration,
    EVM_CHAIN_TYPE, ExpectedPoiCorpusRevision, ExpectedPoiStatus, ExpectedRecordState,
    ExpectedWalletOutput, FixedBytes, HashMap, IndexedArtifactSourceConfig, InputWitness, Instant,
    LocalPoiMerkleProofSource, MerkleForest, Note, OUTPUT_POI_RECOVERY_PROOF_FAILURE_RETRY_AFTER,
    OUTPUT_POI_RECOVERY_SLOW_STEP_AFTER, OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
    OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER, OUTPUT_POI_RECOVERY_VERIFY_PROOF,
    OutputPoiRecoveryAction, OutputPoiRecoveryRecord, OutputPoiRecoveryStatus, OutputRecoveryDelta,
    OwnedPoiPrivateDelta, PendingOutputPoiContextRecord, PoiPrivateApplyOutcome, PoiRpcClient,
    PoiStatus, PostTransactionPoiData, PostTransactionPoiGenerationRequest, PreTransactionPoiError,
    PreTransactionPoiMap, PrivateInputs, ProverError, PublicInputs, PublicPoiCorpusHandle,
    PublicPoiCorpusKey, PublicTxidCacheKey, PublicTxidLatestValidated, PublicTxidProofRequest,
    PublicTxidProofTarget, PublicTxidSyncRequest, PublicTxidTransaction, RwLock, TREE_LEAF_COUNT,
    TransactionPlanChunk, TxidPublicCacheError, TxidPublicProof, U256, Utxo, UtxoCommitmentKind,
    UtxoPoiMetadata, ValidatedRailgunTxidStatus, WalletCacheStore, WalletConfig, WalletPoiRuntime,
    WalletPrivateMutationAuthority, WalletPrivatePoiClients, WalletUtxo, apply_poi_private_delta,
    debug, expected_pending_context_state, expected_recovery_state, generate_post_transaction_pois,
    hex, log_local_poi_cache_unavailable, now_epoch_secs,
    pending_output_poi_context_matches_wallet_utxo, railgun_txid_leaf_hash_with_output_start,
    submit_observed_pending_output_pois_inner, warn,
};
mod public_cache;

pub(super) use public_cache::{
    PublicCacheTxidRecoveryRequest, PublicCacheTxidRefreshRequest, RecoveredOutputTxidData,
    public_txid_rows_for_outer_hash, recovered_output_txid_data_from_public_cache,
    refresh_public_txid_cache,
};

mod chunk;
pub(super) use chunk::{
    PublicTxidRecoveryBuildRequest, build_output_poi_recovery_chunk_from_public_cache,
    build_recovery_chunk_for_public_transaction, preflight_local_recovery_chunk_input_proofs,
};
#[cfg(test)]
pub(super) use chunk::{
    RecoverySpendPublicKey, build_output_poi_recovery_chunk_from_public_rows,
    decode_railgun_transactions, output_start_global_position,
};

#[cfg(test)]
mod calldata_chunk;
#[cfg(test)]
pub(super) use calldata_chunk::{
    build_output_poi_recovery_chunk, preflight_local_output_poi_input_proofs,
};

mod force_resubmit;
pub(super) use force_resubmit::{
    force_resubmit_matching_pending_output_pois_authorized,
    force_resubmit_pending_output_poi_context,
};

mod records;

mod candidate_policy;
mod candidate_recovery;
mod recovery_failures;
mod recovery_request;
mod recovery_scan;

pub(super) use candidate_policy::*;
pub(super) use recovery_scan::*;

/// Keeps the tracing target of the moved items at this module's path.
const LOG_TARGET: &str = module_path!();
pub(super) use records::{
    extend_pending_output_poi_context, mark_valid_output_poi_recoveries,
    mark_valid_output_poi_recoveries_authorized, new_output_poi_recovery_record,
    new_output_poi_recovery_record_for_output, newly_recoverable_output_poi_list_keys,
    pending_output_poi_context_from_output_recovery,
};
use records::{
    log_forced_output_poi_recovery_regeneration, pending_output_poi_context_from_recovery,
    record_output_poi_recovery_failure,
};

pub(super) struct OutputPoiRecoveryRequest<'a> {
    pub(super) authority: &'a WalletPrivateMutationAuthority<'a>,
    pub(super) db: &'a DbStore,
    pub(super) cache_store: &'a dyn WalletCacheStore,
    pub(super) cfg: &'a WalletConfig,
    pub(super) public_data_plane: &'a ChainPublicDataPlane,
    pub(super) http_client: Option<&'a reqwest::Client>,
    pub(super) indexed_artifact_source: Option<&'a IndexedArtifactSourceConfig>,
    pub(super) forest: Arc<MerkleForest>,
    pub(super) poi_client: &'a PoiRpcClient,
    pub(super) private_poi: &'a WalletPrivatePoiClients,
    pub(super) poi_runtime: &'a WalletPoiRuntime,
    pub(super) active_list_keys: &'a [FixedBytes<32>],
    pub(super) wallet_utxos: &'a [WalletUtxo],
    pub(super) force_retry: bool,
}

pub(super) enum OutputPoiProofSourceResolution {
    /// A ready local proof source and the corpus revision it was read at. No corpus fence is
    /// held; a commit that consumes its proofs rechecks `revision` on the wallet actor.
    Local {
        source: LocalPoiMerkleProofSource,
        revision: PoiCorpusRevision,
        corpus: PublicPoiCorpusHandle,
    },
    Unavailable,
}

impl OutputPoiProofSourceResolution {
    pub(super) fn expected_corpus_revision(&self) -> Option<ExpectedPoiCorpusRevision> {
        match self {
            Self::Local {
                revision, corpus, ..
            } => Some(ExpectedPoiCorpusRevision {
                corpus: corpus.clone(),
                revision: *revision,
            }),
            Self::Unavailable => None,
        }
    }
}

pub(super) struct WalletNullifierIndex<'a> {
    pub(super) wallet_utxos: &'a [WalletUtxo],
    pub(super) by_tree_nullifier: HashMap<(u32, U256), usize>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum MatchingPendingOutputPoiContextDisposition {
    Skip,
    Extend(Vec<FixedBytes<32>>),
    Regenerate,
}

#[derive(Debug)]
pub(super) struct RecoveryChunk {
    pub(super) chunk: TransactionPlanChunk,
    pub(super) output_start_global: u128,
    pub(super) target_txid_index: Option<u64>,
    pub(super) replay_fence: Option<super::saved_poi_compatibility::SenderCandidateReplayFence>,
}

#[derive(Debug, Clone)]
pub(super) struct RecoveryFailure {
    pub(super) status: OutputPoiRecoveryStatus,
    pub(super) message: String,
    pub(super) retry_after: Option<Duration>,
    pub(super) category: &'static str,
}

/// Inputs shared by every candidate of one recovery scan.
struct RecoveryScan<'a> {
    request: &'a OutputPoiRecoveryRequest<'a>,
    wallet_nullifiers: WalletNullifierIndex<'a>,
    spending_public_key: [U256; 2],
    prover: &'a ProverService,
    now: u64,
}

/// What one candidate adds to the scan totals.
enum CandidateOutcome {
    Recovered,
    StaleCorpusRevision,
    Skipped,
}

/// A candidate that passed the pending-context and retry gates, with the POI lists it still needs.
struct CandidateRecovery<'a> {
    scan: &'a RecoveryScan<'a>,
    candidate: &'a WalletUtxo,
    started: Instant,
    list_keys: Vec<FixedBytes<32>>,
    expected_pending_context: ExpectedRecordState,
    pending_context_extension: Option<PendingOutputPoiContextRecord>,
}

/// The rebuilt transaction chunk and its recovered TXID data.
struct Reconstruction {
    chunk: RecoveryChunk,
    txid_data: RecoveredOutputTxidData,
}

#[cfg(test)]
pub(super) mod test_support;
