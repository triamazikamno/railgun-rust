use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
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
use merkletree::tree::{DenseMerkleTree, MerkleForest};
use railgun_wallet::prover::ProverError;
use railgun_wallet::tx::{
    InputWitness, PoiMerkleProofSource, PostTransactionPoiData,
    PostTransactionPoiGenerationRequest, PreTransactionPoiError, PreTransactionPoiMap,
    PrivateInputs, PublicInputs, TransactionPlanChunk, generate_post_transaction_pois,
};
use serde::Deserialize;
use serde_json::json;
use thiserror::Error;
use tokio::sync::{Mutex, OwnedMutexGuard, RwLock, broadcast, mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, info, warn};

use local_db::{
    DbStore, OutputPoiRecoveryAction, OutputPoiRecoveryRecord, OutputPoiRecoveryStatus,
    PendingOutputPoiContextRecord, PendingOutputPoiObservation, PendingOutputPoiRole,
    WalletPendingResetRecord, WalletSyncActorStateRecord,
};
use poi::artifacts::SnapshotEvent;
use poi::cache::{POI_MERKLETREE_LEAVES_PAGE_SIZE, PoiCache, PoiCacheError, PoiCacheIdentity};
use poi::error::{PoiError, PoiRpcError};
use poi::poi::{
    BlindedCommitmentData, BlindedCommitmentType, PoiMerkleProof, PoiRpcClient,
    SingleCommitmentProofContext, ValidatedRailgunTxidStatus, default_active_poi_list_keys,
};
use railgun_wallet::scan::{CommitmentObservation, WalletLogDelta};
use railgun_wallet::wallet_cache::WalletCacheError;
use railgun_wallet::{
    Note, PoiStatus, RailgunSpendSigner, Utxo, UtxoCommitmentKind, UtxoPoiMetadata, UtxoSource,
    WalletUtxo,
};
use url::Url;

use crate::chain::ChainPublicDataPlane;
use crate::poi_artifacts::{PersistedPoiArtifactCache, PoiArtifactIngestor, load_persisted_cache};
use crate::txid_cache::{
    TxidPublicCache, TxidPublicCacheError, TxidPublicCacheKey, TxidPublicLatestValidated,
    txid_public_proof_for_recovered_output, txid_public_proof_for_recovered_output_at_index,
};
use crate::types::{
    BackfillEvent, BackfillRequest, IndexedArtifactSourceConfig, PoiReadSource, SharedLogBatch,
    SyncProgressStage, SyncProgressUpdate, WalletBackfillApplyResult, WalletBackfillFinishResult,
    WalletBackfillLease, WalletBackfillRejectReason, WalletBackfillResetResult, WalletCacheStore,
    WalletConfig, WalletIndexedCatchUpStatus, WalletLocalPoiCaches, WalletPrivateCommit,
    WalletReadiness, WalletReadinessError, WalletResetReplayPlan, WalletResetToken,
    WalletScanApply, WalletScanRows, WalletScanRowsPayload, WalletSyncActorStateCommit,
    WalletSyncToken,
};

mod delta;
mod handle;
mod local_poi_cache;
mod output_poi_recovery;
mod pending_output_poi;
mod persist;
mod poi_refresh;
mod poi_sources;
mod worker;

use delta::*;
use handle::*;
pub(crate) use handle::{
    WalletAcceptedBackfillJob, WalletActorTokenAuthority, WalletIndexedCatchUpLease,
    WalletPrivateMutationAuthority, WalletPrivateMutationPermit,
};
use local_poi_cache::*;
use output_poi_recovery::*;
use pending_output_poi::*;
use persist::*;
use poi_refresh::*;
use poi_sources::*;

#[cfg(test)]
pub(crate) use delta::apply_wallet_delta_to_vec;
pub(crate) use delta::pending_overlay_from_delta;
pub use handle::{WalletHandle, WalletPendingOverlay, WalletPendingSpent};
#[cfg(test)]
pub(crate) use pending_output_poi::process_pending_output_poi_observations;
pub(crate) use persist::{WalletWorkerServices, wallet_poi_status_client};
#[cfg(test)]
pub(crate) use poi_refresh::LivePoiTailError;
pub(crate) use poi_refresh::{live_tail_candidate_cache, sync_live_poi_event_tail};
pub use poi_sources::LocalPoiMerkleProofSource;
#[cfg(test)]
use worker::wallet_poi_status_reader_source;
pub(crate) use worker::{spawn_wallet_worker, wallet_cache_store};

#[cfg(test)]
mod tests;
