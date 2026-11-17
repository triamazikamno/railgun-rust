use super::logs::{
    FOREST_RPC_REQUEST_BUDGET, LogPage, LogRequestBudget, ParallelLogStats, ProviderLogStats,
    log_filter_count_for_range,
};
use super::service::send_wallet_reset;
use super::{
    BlockNumberOrTag, CancellationToken, ChainConfig, ChainError, ChainService, DbStore,
    DynProvider, FixedBytes, ForestMetaCheck, ForestReorgDecision, HashMap, HashSet, Instant, Log,
    LogRangeFetch, LogSpanEndpoint, MerkleForest, MerkleForestDbExt, MerkleForestSnapshot,
    Ordering, Path, PersistError, Provider, ProviderHandle, SNAPSHOT_VERSION, SharedLogBatch,
    WalletBackfillApplyResult, WalletBackfillDriver, WalletBackfillRejectReason,
    WalletResetReplayPlan, anchor_file_name, build_provider_with_http_client, debug,
    fetch_logs_for_range_with_provider, info, parse_anchor_block, wallet_reorg_backfill_from_block,
    wallet_sync_target, warn,
};
use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

/// The tracing target these submodules log under, as before they were split out.
const LOG_TARGET: &str = module_path!();

mod forest;
mod parallel_logs;
mod rpc_reads;
mod wallet_cursor;

pub(super) use forest::LiveForestProgressCause;
pub(super) use rpc_reads::ForestLag;
#[cfg(test)]
pub(super) use wallet_cursor::wallet_tail_fallback_lag_threshold_blocks;
pub(super) use wallet_cursor::{
    WalletBackfill, WalletTailFallbackState, wallet_backfill_lag_blocks,
    wallet_tail_fallback_stale_timeout,
};

#[cfg(test)]
mod tests;
