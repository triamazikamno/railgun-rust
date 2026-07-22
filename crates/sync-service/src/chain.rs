use crate::txid_cache::{TxidPublicCache, TxidPublicCacheKey};
use crate::types::{
    BackfillEvent, BackfillRequest, ChainConfig, GlobalPoiPolicy, LogBatch, PublicDataPlaneEpoch,
    PublicScanReadScope, PublicScanSource, SharedLogBatch, SyncProgressSender, SyncProgressStage,
    SyncProgressUpdate, WalletBackfillApplyResult, WalletBackfillDriver,
    WalletBackfillFinishResult, WalletBackfillRejectReason, WalletBackfillResetResult,
    WalletBackfillStartResult, WalletConfig, WalletIndexedCatchUpSource,
    WalletIndexedCatchUpStatus, WalletObservation, WalletReadiness, WalletReadinessError,
    WalletResetReplayPlan, WalletScanApply, WalletScanRows, WalletScanRowsPayload,
};
use crate::wallet::{
    WalletHandle, WalletObservationPublisher, WalletPoiRuntime, WalletWorkerServices,
    wallet_cache_store,
};
use alloy::eips::BlockNumberOrTag;
use alloy::primitives::{Address, FixedBytes};
use alloy::sol_types::SolEvent;
use alloy_provider::{DynProvider, Provider};
use alloy_rpc_types_eth::{Filter, Log};
use alloy_transport::TransportError;
use async_trait::async_trait;
use broadcaster_core::provider::build_provider_with_http_client;
use broadcaster_core::query_rpc_pool::{ProviderHandle, QueryRpcPool};
use broadcaster_core::transact::DEFAULT_TXID_VERSION;
use local_db::DbStore;
use merkletree::errors::SyncError;
use merkletree::persist::{MerkleForestSnapshot, PersistError, SNAPSHOT_VERSION};
use merkletree::quick::{
    DEFAULT_PAGE_SIZE, QuickSyncClient, QuickSyncConfig, run_quick_sync_into_with_progress,
};
use merkletree::slow::CommitmentUpdateError;
use merkletree::slow::types::{
    CommitmentBatch, GeneratedCommitmentBatch, Nullified, Nullifiers, RailgunLegacyShieldEvents,
    Shield, Transact,
};
use merkletree::tree::MerkleForest;
use railgun_wallet::UtxoSource;
use railgun_wallet::scan::{
    IndexedLegacyEncryptedCommitmentInput, IndexedLegacyGeneratedCommitmentInput,
    IndexedNullifierInput, IndexedShieldCommitmentInput, IndexedTransactCommitmentInput,
    WalletScanError, WalletScanInputRows,
};
use railgun_wallet::wallet_cache::WalletCacheError;
use std::cmp::min;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock, broadcast, mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, info, warn};

mod backfill;
mod data_plane;
mod forest_db;
mod indexed_wallet;
mod logs;
mod merkle_artifacts;
mod service;
mod types;
mod workers;

use backfill::{WalletBackfill, WalletTailFallbackState, wallet_backfill_lag_blocks};
pub(crate) use data_plane::{
    ChainPublicDataPlane, PublicPoiCorpusHandle, PublicPoiCorpusKey, PublicTxidCacheKey,
    PublicTxidLatestValidated, PublicTxidProofRequest, PublicTxidProofTarget,
    PublicTxidSyncRequest,
};
use forest_db::MerkleForestDbExt;
use indexed_wallet::{
    IndexedWalletArtifactPageOutcome, IndexedWalletArtifactSession, IndexedWalletPage,
    artifact_failure_can_fallback_to_squid, send_wallet_startup_events,
    should_hedge_wallet_startup, squid_tail_target_after_artifact, wait_or_cancel,
    wallet_backfill_from_block, wallet_remote_target_before_cached_suffix,
    wallet_reorg_backfill_from_block, wallet_startup_warm_from_block, wallet_sync_target,
};
use logs::{anchor_file_name, fetch_logs_for_range_with_provider, parse_anchor_block, sort_logs};
use merkle_artifacts::run_merkle_artifact_catch_up_into;
use types::{
    EVM_CHAIN_TYPE, ForestReorgDecision, IndexedWalletCatchUpSourceOrder, IndexedWalletPageKind,
    PendingTipWalletRegistration, TXID_PUBLIC_CACHE_SYNC_INTERVAL, WalletIndexedCatchUpStatusGuard,
    WalletRegistration, WalletStartupSyncCandidate, WalletStartupSyncError,
    WalletStartupSyncStrategy, send_sync_progress,
};
use workers::{
    spawn_backfill_loop, spawn_head_poller, spawn_live_log_loop, spawn_pending_tip_loop,
    spawn_txid_public_cache_loop, spawn_wallet_lag_fallback_loop,
    wallet_finish_result_removes_cursor, wallet_finish_retry_request,
};

pub use data_plane::{
    ChainPublicSyncCacheReset, LocalPoiQueryUnavailable, LocalPoiRootValidation,
    LocalPoiStatusLookup, PoiArtifactCacheRetry, PoiArtifactPersistenceHandle,
    PublicCoverageAnswer, PublicDataPlaneDiagnostic, PublicDataPlaneDiagnosticKind,
    PublicDataPlaneDiagnostics, PublicDataPlaneError, PublicDataPlaneHandle, PublicScanRange,
    PublicScanRows, PublicScanRowsAnswer, PublicSyncCacheReset,
};
pub use types::{ChainError, ChainHandle, ChainService};

fn artifact_chunk_progress(
    completed_chunks: usize,
    total_chunks: usize,
    start_progress: u64,
    done_progress: u64,
) -> u64 {
    let total = u64::try_from(total_chunks).unwrap_or(u64::MAX);
    if total == 0 {
        return done_progress;
    }
    let completed = u64::try_from(completed_chunks).unwrap_or(total).min(total);
    start_progress.saturating_add(
        done_progress
            .saturating_sub(start_progress)
            .saturating_mul(completed)
            / total,
    )
}

#[cfg(test)]
mod tests;
