use super::*;

pub(super) const EVM_CHAIN_TYPE: u8 = 0;
pub(super) const TXID_PUBLIC_CACHE_SYNC_INTERVAL: Duration = Duration::from_secs(5 * 60);

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
    claimed: bool,
}

impl<'a> WalletIndexedCatchUpStatusGuard<'a> {
    pub(super) fn claim(handle: &'a WalletHandle, expose_status: bool) -> Option<Self> {
        if !handle.try_claim_indexed_catch_up() {
            return None;
        }
        Some(Self {
            handle,
            expose_status,
            claimed: true,
        })
    }

    pub(super) fn set(
        &self,
        source: WalletIndexedCatchUpSource,
        from_block: u64,
        target_block: u64,
    ) {
        if self.expose_status {
            self.handle
                .set_indexed_catch_up(WalletIndexedCatchUpStatus {
                    source,
                    from_block,
                    target_block,
                });
        }
    }
}

impl Drop for WalletIndexedCatchUpStatusGuard<'_> {
    fn drop(&mut self) {
        if self.claimed {
            self.handle.clear_indexed_catch_up();
        }
    }
}

#[derive(Debug)]
pub(super) enum WalletStartupSyncError {
    Cancelled,
    Chain(ChainError),
    Indexed(SyncError),
}

impl std::fmt::Display for WalletStartupSyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => f.write_str("cancelled"),
            Self::Chain(err) => write!(f, "{err}"),
            Self::Indexed(err) => write!(f, "{err}"),
        }
    }
}

impl From<ChainError> for WalletStartupSyncError {
    fn from(err: ChainError) -> Self {
        Self::Chain(err)
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
    #[error("commitment update error: {0}")]
    CommitmentUpdate(#[from] CommitmentUpdateError),
    #[error("db error: {0}")]
    Db(#[from] local_db::DbError),
    #[error("no healthy rpc available")]
    NoHealthyRpc,
    #[error("wallet not found")]
    WalletNotFound,
    #[error("wallet reset failed")]
    WalletResetFailed(#[from] mpsc::error::SendError<BackfillEvent>),
    #[error("wallet reset rejected: {0:?}")]
    WalletResetRejected(WalletBackfillResetResult),
    #[error("backfill request failed")]
    BackfillRequestFailed(#[from] mpsc::error::SendError<BackfillRequest>),
}

impl ChainError {
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
                | Self::IndexedCatchUpUnavailable { .. }
                | Self::NoHealthyRpc
        )
    }

    pub(super) fn is_block_range_beyond_current_head(&self) -> bool {
        matches!(self, Self::Rpc(TransportError::ErrorResp(resp)) if resp.message.contains("block range extends beyond current head block"))
    }
}

#[derive(Clone)]
pub(super) struct PendingTipWalletRegistration {
    pub(super) cache_key: String,
    pub(super) cfg: WalletConfig,
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
    pub(super) backfill_sender: mpsc::Sender<BackfillEvent>,
    pub(super) start_block: u64,
    pub(super) sync_to_block: Option<u64>,
}

pub struct ChainService {
    pub(super) chain: ChainConfig,
    pub(super) db: Arc<DbStore>,
    pub(super) forest: Arc<RwLock<MerkleForest>>,
    pub(super) head_tx: watch::Sender<u64>,
    pub(super) safe_head_tx: watch::Sender<u64>,
    pub(super) forest_last_tx: watch::Sender<u64>,
    pub(super) live_log_tx: broadcast::Sender<SharedLogBatch>,
    pub(super) backfill_tx: mpsc::Sender<BackfillRequest>,
    pub(super) archive_provider: Option<DynProvider>,
    pub(super) wallets: RwLock<HashMap<String, WalletRegistration>>,
    pub(super) cancel: CancellationToken,
    pub(super) live_log_task: Mutex<Option<JoinHandle<()>>>,
    pub(super) anchor_last: AtomicU64,
    pub(super) txid_public_cache_started: AtomicBool,
    pub(super) wallet_actor_next: AtomicU64,
    pub(super) wallet_reset_intent_next: AtomicU64,
    pub(super) public_data_epoch: Arc<AtomicU64>,
}
