use super::{
    Arc, AtomicBool, AtomicU64, BackfillEvent, BackfillRequest, CancellationToken, ChainConfig,
    ChainPublicDataPlane, CommitmentUpdateError, DbStore, DynProvider, GlobalPoiPolicy, JoinHandle,
    MerkleForest, Mutex, PersistError, PublicDataPlaneError, RwLock, SharedLogBatch, SyncError,
    SyncProgressSender, SyncProgressUpdate, TransportError, WalletBackfillResetResult,
    WalletCacheError, WalletConfig, WalletHandle, WalletIndexedCatchUpSource,
    WalletIndexedCatchUpStatus, WalletObservationPublisher, WalletScanApply, WalletScanError,
    broadcast, debug, mpsc, watch,
};
use alloy_transport::{RpcError, TransportErrorKind};
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use super::poi_submitter::ChainPoiSubmitterHandle;
use crate::wallet::WalletIndexedCatchUpLease;

pub(super) const EVM_CHAIN_TYPE: u8 = 0;
pub(super) const TXID_PUBLIC_CACHE_SYNC_INTERVAL: Duration = Duration::from_mins(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ForestReorgDecision {
    Skip,
    Match,
    Mismatch,
}

impl ForestReorgDecision {
    pub(super) fn from_confirmed_hash(
        last_processed: u64,
        meta_last_block: u64,
        stored_hash: [u8; 32],
        confirmed_current_hash: Option<[u8; 32]>,
    ) -> Self {
        if stored_hash == [0u8; 32] || meta_last_block != last_processed {
            return Self::Skip;
        }

        match confirmed_current_hash {
            Some(current_hash) if current_hash == stored_hash => Self::Match,
            Some(_) => Self::Mismatch,
            None => Self::Skip,
        }
    }
}

/// Stored forest metadata checked against the confirmed chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ForestMetaCheck {
    /// Nothing to compare: the forest precedes deployment, no forest metadata
    /// is stored, or the metadata records no hash.
    Unchecked,
    /// The metadata records a block other than the forest's progress.
    StaleMeta,
    /// No confirmed hash was read for the block.
    Unconfirmed,
    Match,
    Mismatch {
        current_hash: [u8; 32],
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum IndexedWalletPageKind {
    Legacy,
    Modern,
}

impl IndexedWalletPageKind {
    pub(super) const fn for_from_block(from_block: u64, v2_start_block: u64) -> Self {
        if v2_start_block > 0 && from_block < v2_start_block {
            Self::Legacy
        } else {
            Self::Modern
        }
    }

    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Modern => "modern",
        }
    }

    pub(super) fn to_block(
        self,
        from_block: u64,
        target: u64,
        v2_start_block: u64,
        indexed_wallet_block_range: u64,
    ) -> u64 {
        let range_end = std::cmp::min(
            from_block.saturating_add(indexed_wallet_block_range.saturating_sub(1)),
            target,
        );
        match self {
            Self::Legacy if v2_start_block > 0 => range_end.min(v2_start_block.saturating_sub(1)),
            Self::Legacy | Self::Modern => range_end,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WalletStartupSyncStrategy {
    Rpc,
    Indexed,
}

impl WalletStartupSyncStrategy {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Rpc => "rpc",
            Self::Indexed => "indexed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum IndexedWalletCatchUpSourceOrder {
    ArtifactsFirst,
    SquidFirst,
}

pub(super) struct WalletIndexedCatchUpStatusGuard<'a> {
    handle: &'a WalletHandle,
    expose_status: bool,
    lease: WalletIndexedCatchUpLease,
}

impl<'a> WalletIndexedCatchUpStatusGuard<'a> {
    pub(super) async fn claim(handle: &'a WalletHandle, expose_status: bool) -> Option<Self> {
        let lease = handle.try_claim_indexed_catch_up().await?;
        Some(Self {
            handle,
            expose_status,
            lease,
        })
    }

    pub(super) fn set(
        &self,
        source: WalletIndexedCatchUpSource,
        from_block: u64,
        target_block: u64,
    ) {
        if self.expose_status {
            self.handle.set_indexed_catch_up(
                &self.lease,
                WalletIndexedCatchUpStatus {
                    source,
                    from_block,
                    target_block,
                },
            );
        }
    }
}

#[derive(Debug)]
pub(super) enum WalletStartupSyncError {
    Cancelled,
    IncompleteRpcCoverage { requested_to: u64, proven_to: u64 },
    UnprovenRpcEndpoint { block_number: u64 },
    Chain(ChainError),
    Indexed(SyncError),
}

impl std::fmt::Display for WalletStartupSyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => f.write_str("cancelled"),
            Self::IncompleteRpcCoverage {
                requested_to,
                proven_to,
            } => write!(
                f,
                "RPC source covers through {proven_to}, below required block {requested_to}"
            ),
            Self::UnprovenRpcEndpoint { block_number } => {
                write!(f, "RPC source did not prove endpoint block {block_number}")
            }
            Self::Chain(err) => write!(f, "{err}"),
            Self::Indexed(err) => write!(f, "{err}"),
        }
    }
}

impl WalletStartupSyncError {
    /// Returns this error with any reqwest request URL removed, for logging.
    /// Covers `Chain` transport errors (see `ChainError::without_url`) and
    /// Squid request errors (`SyncError::Request`).
    pub(super) fn without_url(self) -> Self {
        match self {
            Self::Chain(err) => Self::Chain(err.without_url()),
            Self::Indexed(SyncError::Request(err)) => {
                Self::Indexed(SyncError::Request(err.without_url()))
            }
            other => other,
        }
    }
}

impl From<ChainError> for WalletStartupSyncError {
    fn from(err: ChainError) -> Self {
        match err {
            ChainError::LogFetchCancelled => Self::Cancelled,
            err => Self::Chain(err),
        }
    }
}

impl From<SyncError> for WalletStartupSyncError {
    fn from(err: SyncError) -> Self {
        Self::Indexed(err)
    }
}

#[derive(Debug)]
pub(super) struct WalletStartupSyncCandidate {
    pub(super) strategy: WalletStartupSyncStrategy,
    pub(super) acquisition_applies: Vec<WalletScanApply>,
    pub(super) applies: Vec<WalletScanApply>,
    pub(super) elapsed_ms: u128,
}

pub(super) fn send_sync_progress(
    progress_tx: Option<&SyncProgressSender>,
    update: SyncProgressUpdate,
) {
    if let Some(progress_tx) = progress_tx
        && let Err(err) = progress_tx.send(Some(update))
    {
        debug!(?err, "failed to send sync progress update");
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("provider build error: {0}")]
    ProviderBuild(TransportError),
    #[error("rpc error: {0}")]
    Rpc(#[from] TransportError),
    #[error("archive rpc url required for blocks <= {0}")]
    ArchiveRpcRequired(u64),
    #[error("archive RPC endpoint is not verified")]
    ArchiveRpcUnverified,
    #[error(
        "indexed catch-up unavailable from block {from_block}; archive RPC fallback required through block {archive_until_block}: {reason}"
    )]
    IndexedCatchUpUnavailable {
        from_block: u64,
        archive_until_block: u64,
        reason: String,
    },
    #[error("snapshot error: {0}")]
    Snapshot(#[from] PersistError),
    #[error("wallet scan error: {0}")]
    WalletScan(#[from] WalletScanError),
    #[error("public data-plane error: {0}")]
    PublicDataPlane(#[from] PublicDataPlaneError),
    #[error("commitment update error: {0}")]
    CommitmentUpdate(#[from] CommitmentUpdateError),
    #[error("db error: {0}")]
    Db(#[from] local_db::DbError),
    #[error("wallet cache error: {0}")]
    WalletCache(#[from] WalletCacheError),
    #[error("no healthy rpc available")]
    NoHealthyRpc,
    #[error("log fetch cancelled")]
    LogFetchCancelled,
    #[error("log request budget of {0} exceeded")]
    LogRequestBudgetExceeded(u64),
    #[error("wallet not found")]
    WalletNotFound,
    #[error("a different wallet is already registered")]
    WalletAlreadyRegistered,
    #[error("wallet reset failed")]
    WalletResetFailed,
    #[error(
        "restored wallet reset replay {replay_start_block}..={replay_target_block} (follow_safe_head={follow_safe_head}) is incompatible with post-rewind cursor {post_rewind_cursor}: replay must start no later than {required_replay_start_block}, and a bounded replay below configured start block {configured_start_block} must cover through {required_replay_target_block}"
    )]
    IncompatiblePendingWalletResetReplay {
        post_rewind_cursor: u64,
        configured_start_block: u64,
        replay_start_block: u64,
        replay_target_block: u64,
        follow_safe_head: bool,
        required_replay_start_block: u64,
        required_replay_target_block: u64,
    },
    #[error("chain service is shut down")]
    Shutdown,
    #[error("wallet reset rejected: {0:?}")]
    WalletResetRejected(WalletBackfillResetResult),
    #[error("backfill request failed")]
    BackfillRequestFailed,
    #[error("wallet backfill retirement cleanup failed")]
    WalletBackfillRetirementFailed,
    #[error("wallet worker failed during retirement")]
    WalletWorkerRetirementFailed,
    #[error("wallet replacement task failed")]
    WalletReplacementTaskFailed,
}

impl From<mpsc::error::SendError<BackfillEvent>> for ChainError {
    fn from(_: mpsc::error::SendError<BackfillEvent>) -> Self {
        Self::WalletResetFailed
    }
}

impl From<mpsc::error::SendError<BackfillRequest>> for ChainError {
    fn from(_: mpsc::error::SendError<BackfillRequest>) -> Self {
        Self::BackfillRequestFailed
    }
}

/// Provider limit named by a rejected `eth_getLogs` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LogRangeLimit {
    /// The requested block span exceeded the endpoint's limit, which the
    /// message states as `max_blocks` when it parses.
    BlockSpan { max_blocks: Option<u64> },
    /// The request matched more logs than the endpoint returns at once.
    ResultSize,
}

fn leading_block_count(text: &str) -> Option<u64> {
    text.split(|c: char| !c.is_ascii_digit())
        .next()
        .and_then(|digits| digits.parse().ok())
}

/// Removes the request URL from a reqwest transport failure.
///
/// Alloy's reqwest transport boxes the `reqwest::Error` inside
/// [`TransportErrorKind::Custom`], and that error's `Display` appends the full
/// request URL with only userinfo stripped, so credentials in the path or query
/// reach logs. Alloy exposes the boxed source only by reference, so the
/// redaction must take ownership to call `reqwest::Error::without_url`. The
/// downcast only matches when alloy-transport-http and this crate resolve the
/// same `reqwest` version, which the unit test enforces. Any other error is
/// returned unchanged.
pub(super) fn transport_error_without_url(err: TransportError) -> TransportError {
    match err {
        RpcError::Transport(TransportErrorKind::Custom(source)) => {
            match source.downcast::<reqwest::Error>() {
                Ok(err) => TransportErrorKind::custom((*err).without_url()),
                Err(source) => RpcError::Transport(TransportErrorKind::Custom(source)),
            }
        }
        other => other,
    }
}

impl ChainError {
    /// Returns this error with any reqwest request URL removed from transport
    /// failures, for logging. See `transport_error_without_url`.
    pub(super) fn without_url(self) -> Self {
        match self {
            Self::Rpc(err) => Self::Rpc(transport_error_without_url(err)),
            Self::ProviderBuild(err) => Self::ProviderBuild(transport_error_without_url(err)),
            other => other,
        }
    }

    /// Classifies an `eth_getLogs` rejection caused by a provider's range limit.
    ///
    /// JSON-RPC has no standard code for these rejections, and Alloy exposes
    /// only the error payload's code and message. This adapter therefore
    /// matches the observed message shapes narrowly; anything else stays
    /// unclassified and keeps the existing error handling.
    pub(crate) fn log_range_limit(&self) -> Option<LogRangeLimit> {
        let Self::Rpc(TransportError::ErrorResp(resp)) = self else {
            return None;
        };
        let message = resp.message.as_ref();
        let block_span = |count: &str| LogRangeLimit::BlockSpan {
            max_blocks: leading_block_count(count),
        };
        if let Some((_, rest)) = message.split_once("Block range too large: maximum allowed is ") {
            return Some(block_span(rest));
        }
        if let Some((_, rest)) = message.split_once("log query range must not exceed ") {
            return Some(block_span(rest));
        }
        if let Some((_, rest)) = message.split_once("ranges over ")
            && rest.contains(" blocks are not supported")
        {
            return Some(block_span(rest));
        }
        if let Some((_, rest)) = message.split_once("eth_getLogs requests with up to a ")
            && rest.contains(" block range")
        {
            return Some(block_span(rest));
        }
        if let Some((_, rest)) = message.split_once("eth_getLogs is limited to ")
            && rest.contains("blocks range")
        {
            return Some(block_span(
                rest.split_once(" - ").map_or("", |(_, count)| count),
            ));
        }
        let lowercase = message.to_ascii_lowercase();
        if let Some((_, rest)) = lowercase.split_once("query returned more than ")
            && rest.contains("results")
        {
            return Some(LogRangeLimit::ResultSize);
        }
        None
    }

    pub(crate) fn is_rpc_throttled(&self) -> bool {
        match self {
            Self::Rpc(TransportError::ErrorResp(resp)) => resp.message.contains("limit exceeded"),
            Self::Rpc(TransportError::Transport(resp)) => resp
                .as_http_error()
                .is_some_and(|err| err.status == 429 || err.body.contains("limit exceeded")),
            _ => false,
        }
    }

    pub(crate) const fn should_mark_rpc_unhealthy(&self) -> bool {
        !matches!(
            self,
            Self::ArchiveRpcRequired(_)
                | Self::ArchiveRpcUnverified
                | Self::IndexedCatchUpUnavailable { .. }
                | Self::NoHealthyRpc
                | Self::LogFetchCancelled
                | Self::LogRequestBudgetExceeded(_)
        )
    }

    pub(super) fn is_block_range_beyond_current_head(&self) -> bool {
        matches!(self, Self::Rpc(TransportError::ErrorResp(resp)) if resp.message.contains("block range extends beyond current head block"))
    }
}

#[derive(Clone)]
pub(super) struct PendingTipWalletRegistration {
    pub(super) cache_key: String,
    pub(super) handle: WalletHandle,
    pub(super) reset_generation: u64,
    pub(super) last_scanned: u64,
    pub(super) from_block: u64,
    pub(super) target_block: u64,
}

#[derive(Debug)]
pub struct ChainHandle {
    pub forest: Arc<RwLock<MerkleForest>>,
    pub head_rx: watch::Receiver<u64>,
    pub safe_head_rx: watch::Receiver<u64>,
    pub forest_last_rx: watch::Receiver<u64>,
    pub live_log_rx: broadcast::Receiver<SharedLogBatch>,
}

pub(super) struct WalletRegistration {
    pub(super) handle: WalletHandle,
    pub(super) cfg: WalletConfig,
    pub(super) cancel: CancellationToken,
    pub(super) worker: JoinHandle<()>,
    pub(super) observation: Arc<WalletObservationPublisher>,
    pub(super) backfill_sender: mpsc::Sender<BackfillEvent>,
    pub(super) start_block: u64,
    pub(super) sync_to_block: Option<u64>,
}

pub struct ChainService {
    pub(super) chain: ChainConfig,
    pub(super) poi_policy: GlobalPoiPolicy,
    pub(super) db: Arc<DbStore>,
    pub(super) forest: Arc<RwLock<MerkleForest>>,
    pub(super) head_tx: watch::Sender<u64>,
    pub(super) safe_head_tx: watch::Sender<u64>,
    pub(super) forest_last_tx: watch::Sender<u64>,
    pub(super) live_log_tx: broadcast::Sender<SharedLogBatch>,
    pub(super) backfill_tx: mpsc::Sender<BackfillRequest>,
    pub(super) archive_provider: Option<DynProvider>,
    pub(super) wallet: RwLock<Option<WalletRegistration>>,
    pub(super) wallet_registration_gate: Mutex<()>,
    pub(super) cancel: CancellationToken,
    pub(super) live_log_task: StdMutex<Option<JoinHandle<()>>>,
    pub(super) poi_submitter: ChainPoiSubmitterHandle,
    pub(super) poi_submitter_task: StdMutex<Option<JoinHandle<()>>>,
    pub(super) anchor_last: AtomicU64,
    pub(super) txid_public_cache_started: AtomicBool,
    pub(super) wallet_actor_next: AtomicU64,
    pub(super) wallet_reset_intent_next: AtomicU64,
    pub(super) public_data_plane: ChainPublicDataPlane,
}
