use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use alloy::hex;
use alloy::primitives::{Bytes, FixedBytes, U256};
use alloy::sol_types::SolCall;
use async_trait::async_trait;
use broadcaster_core::contracts::railgun::{
    CommitmentCiphertext, Transaction, executeCall, relayCall, transactCall,
};
use broadcaster_core::crypto::aes_gcm::{decrypt_in_place_16b_iv, split_iv_tag};
use broadcaster_core::crypto::shared_key::shared_symmetric_key;
use broadcaster_core::query_rpc_pool::QueryRpcPool;
use broadcaster_core::transact::{DEFAULT_TXID_VERSION, railgun_txid_leaf_hash_with_output_start};
use broadcaster_core::tree::TREE_LEAF_COUNT;
use futures::stream::FuturesUnordered;
use merkletree::tree::{DenseMerkleTree, MerkleForest};
use railgun_wallet::prover::ProverError;
use railgun_wallet::tx::{
    InputWitness, PoiMerkleProofSource, PostTransactionPoiData,
    PostTransactionPoiGenerationRequest, PreTransactionPoiError, PreTransactionPoiMap,
    PrivateInputs, PublicInputs, TransactionPlanChunk, generate_post_transaction_pois,
};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::{Mutex, OwnedMutexGuard, RwLock, broadcast, mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, info, warn};

use local_db::{
    DbStore, OutputPoiRecoveryAction, OutputPoiRecoveryRecord, OutputPoiRecoveryStatus,
    PendingOutputPoiContextRecord, PendingOutputPoiObservation, PendingOutputPoiRole,
    WalletCacheKey, WalletPendingResetRecord, WalletSyncActorStateRecord,
};
use poi::error::PoiError;
use poi::poi::{
    BlindedCommitmentData, BlindedCommitmentType, PoiMerkleProof, PoiRpcClient,
    SingleCommitmentProofContext, ValidatedRailgunTxidStatus, default_active_poi_list_keys,
};
use railgun_wallet::scan::{CommitmentObservation, WalletLogDelta};
use railgun_wallet::wallet_cache::{WalletCacheError, wallet_utxo_stable_identity};
use railgun_wallet::{
    Note, PoiStatus, RailgunSpendSigner, Utxo, UtxoCommitmentKind, UtxoPoiMetadata, UtxoSource,
    WalletUtxo,
};

use crate::chain::{
    ChainError, ChainPublicDataPlane, PublicPoiCorpusKey, PublicTxidCacheKey,
    PublicTxidLatestValidated, PublicTxidProofRequest, PublicTxidProofTarget,
    PublicTxidSyncRequest,
};
use crate::indexed_artifacts::{ChainScope, ChainType};
use crate::txid_cache::TxidPublicCacheError;
use crate::types::{
    BackfillEvent, GlobalPoiPolicy, IndexedArtifactSourceConfig, PendingOutputPoiContextIntent,
    PoiProxyFallback, SharedLogBatch, SyncProgressStage, SyncProgressUpdate,
    WalletBackfillApplyResult, WalletBackfillFinishResult, WalletBackfillGrant,
    WalletBackfillOwnerDisposition, WalletBackfillOwnerSignal, WalletBackfillRejectReason,
    WalletBackfillResetResult, WalletBackfillStartResult, WalletCacheStore,
    WalletCheckpointMutation, WalletConfig, WalletCurrentSnapshot, WalletInactiveReason,
    WalletIndexedCatchUpStatus, WalletLocalPoiCaches, WalletObservation,
    WalletPendingSpentMarkOutcome, WalletPpoiWorkflowStatus, WalletPrivateCommit,
    WalletPrivateRequestError, WalletReadiness, WalletReadinessError, WalletReadinessWaitError,
    WalletResetReplayPlan, WalletResetRewindStatus, WalletResetToken, WalletScanApply,
    WalletScanRows, WalletScanRowsPayload, WalletSyncActorStateCommit, WalletSyncToken,
    WalletUtxoMutation, WalletViewState,
};

mod actor;
mod delta;
mod handle;
mod local_poi_cache;
mod output_poi_recovery;
mod pending_output_poi;
mod persist;
mod poi_maintenance;
mod poi_refresh;
mod poi_sources;
mod private_remote;
mod worker;

use actor::{PendingWalletReset, WalletActorState};
pub(crate) use actor::{
    PoiRemoteJobKey, WalletActorApplyToken, WalletActorCommitToken, WalletActorCredential,
    WalletActorLifecycle, WalletActorLifecycleCell, WalletActorTerminalToken,
    WalletObservationPublisher, WalletRemoteDone,
};
use delta::{
    apply_wallet_delta_to_vec_with_outcome, chain_pending_overlay_matches, rewind_wallet_utxos,
};
use handle::{
    EVM_CHAIN_TYPE, ExpectedPoiListState, ExpectedPoiStatus, ExpectedRecordState,
    ExpectedWalletOutput, OUTPUT_POI_RECOVERY_PROOF_FAILURE_RETRY_AFTER,
    OUTPUT_POI_RECOVERY_ROOT_SEARCH_LEAVES, OUTPUT_POI_RECOVERY_SLOW_STEP_AFTER,
    OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER, OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
    OUTPUT_POI_RECOVERY_VERIFY_PROOF, PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER,
    PendingOutputPoiSubject, PendingOutputPoiSubmissionPredicate,
    PendingOutputPoiValidationEvidence, WALLET_POI_REFRESH_INTERVAL, WALLET_POI_STATUS_BATCH_SIZE,
    WalletIndexedCatchUpCommand, WalletPendingOverlayUpdate, WalletPoiRefreshSelection,
    WalletPrivateRemoteAuthority, WalletPrivateRequest,
};
pub(crate) use handle::{
    OwnedPoiPrivateDelta, PoiPrivateApplyOutcome, WalletActorTokenAuthority,
    WalletIndexedCatchUpLease, WalletPrivateApplyClient, WalletPrivateApplyRequest,
    WalletPrivateMutationAuthority, WalletPrivateMutationPermit,
};
use local_poi_cache::log_local_poi_cache_unavailable;
use output_poi_recovery::{
    OutputPoiRecoveryRequest, force_resubmit_matching_pending_output_pois_authorized,
    mark_valid_output_poi_recoveries, mark_valid_output_poi_recoveries_authorized,
    new_output_poi_recovery_record, output_poi_recovery_candidates, recover_missing_output_pois,
};
use pending_output_poi::{
    PendingOutputPoiPreflight, PendingOutputPoiRemoteAttempt, PendingOutputPoiSubmissionPlan,
    apply_owned_poi_private_delta_on_actor, apply_poi_private_delta,
    current_pending_output_poi_subject, expected_pending_context_state, expected_recovery_state,
    pending_output_poi_context_fingerprint, pending_output_poi_context_matches_wallet_utxo,
    pending_output_poi_observation_state_updates, pending_output_poi_rewind_state_updates,
    pending_output_poi_submission_plan_current, preflight_and_remote_submit_pending_output_poi,
    process_pending_output_poi_observations_authorized, submit_observed_pending_output_pois_inner,
    verify_submitted_pending_output_pois_with_config_authorized, wallet_ppoi_workflow_status,
    wallet_ppoi_workflow_status_after_mutations,
};
pub(crate) use persist::WalletPoiRuntime;
use persist::{
    OutputPoiRecoveryRun, WalletLiveMetadataFlush, WalletPersistState, WalletProgressPersist,
    WalletProgressPrivateEffects, blinded_commitment_type, now_epoch_secs,
    wallet_poi_status_refresh_needed, wallet_poi_status_refresh_needed_for_selection,
};
use poi_maintenance::PoiMaintenanceController;
use poi_refresh::{
    refresh_wallet_poi_statuses_remote_authorized, refresh_wallet_poi_statuses_selected,
};
use poi_sources::PendingOutputPoiSubmitter;
pub(crate) use poi_sources::{LocalPoiStatusReader, PoiStatusReader};
use private_remote::{WalletPrivatePoiClients, WalletPrivateRemoteError, WalletPrivateRemoteStale};

pub use crate::types::{WalletPendingOverlay, WalletPendingSpent};
pub(crate) use delta::pending_overlay_from_delta;
pub use handle::WalletHandle;
pub(crate) use persist::{WalletWorkerServices, wallet_poi_status_client};
pub use poi_sources::LocalPoiMerkleProofSource;
pub(crate) use worker::{PreparedWalletWorker, prepare_wallet_worker, wallet_cache_store};

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) mod test_support {
    pub(crate) use super::poi_refresh::test_support::{
        LivePoiTailError, live_tail_candidate_cache, sync_live_poi_event_tail,
    };
    pub(crate) use super::worker::test_support::spawn_wallet_worker;
}
