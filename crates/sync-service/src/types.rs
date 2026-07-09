use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::primitives::{Address, FixedBytes, U256, address};
use alloy_rpc_types_eth::Log;
use broadcaster_core::query_rpc_pool::QueryRpcPool;
use local_db::{
    DbStore, OutputPoiRecoveryRecord, PendingOutputPoiContextRecord, WalletMeta,
    WalletSyncActorStateRecord,
};
use poi::cache::PoiCache;
#[cfg(test)]
use railgun_wallet::scan::WalletLogDelta;
use railgun_wallet::scan::{WalletScanError, WalletScanInputRows, WalletScanKeys};
use railgun_wallet::wallet_cache::{WalletCacheDbExt, WalletCacheError, serialize_wallet_utxo};
use railgun_wallet::{ProverService, WalletUtxo};
use tokio::sync::{RwLock, mpsc, oneshot, watch};
use tracing::warn;
use url::Url;

use crate::indexed_artifacts::{ChainScope, ChainType};
use crate::wallet::WalletActorTokenAuthority;

pub const DEFAULT_INDEXED_WALLET_BLOCK_RANGE: u64 = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncProgressStage {
    SynchronizingCommitments,
    PreparingUtxoIndex,
    IndexingUtxos,
}

impl SyncProgressStage {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SynchronizingCommitments => "Synchronizing commitments",
            Self::PreparingUtxoIndex => "Preparing UTXO index",
            Self::IndexingUtxos => "Indexing UTXOs",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncProgressUnit {
    Block,
    ArtifactPreparation,
    ArtifactChunk { completed: u64, total: u64 },
    ArtifactApplied,
    CommitmentTail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncProgressUpdate {
    pub stage: SyncProgressStage,
    pub unit: SyncProgressUnit,
    pub start_block: u64,
    pub current_block: u64,
    pub target_block: u64,
}

impl SyncProgressUpdate {
    #[must_use]
    pub const fn new(
        stage: SyncProgressStage,
        start_block: u64,
        current_block: u64,
        target_block: u64,
    ) -> Self {
        Self::with_unit(
            stage,
            SyncProgressUnit::Block,
            start_block,
            current_block,
            target_block,
        )
    }

    #[must_use]
    pub const fn artifact_preparation(
        stage: SyncProgressStage,
        current_progress: u64,
        target_progress: u64,
    ) -> Self {
        Self::with_unit(
            stage,
            SyncProgressUnit::ArtifactPreparation,
            0,
            current_progress,
            target_progress,
        )
    }

    #[must_use]
    pub const fn artifact_chunk(
        stage: SyncProgressStage,
        current_progress: u64,
        target_progress: u64,
        completed_chunks: u64,
        total_chunks: u64,
    ) -> Self {
        Self::with_unit(
            stage,
            SyncProgressUnit::ArtifactChunk {
                completed: completed_chunks,
                total: total_chunks,
            },
            0,
            current_progress,
            target_progress,
        )
    }

    #[must_use]
    pub const fn artifact_applied(stage: SyncProgressStage) -> Self {
        Self::with_unit(stage, SyncProgressUnit::ArtifactApplied, 0, 100, 100)
    }

    #[must_use]
    pub const fn commitment_tail(start_block: u64, current_block: u64, target_block: u64) -> Self {
        Self::with_unit(
            SyncProgressStage::SynchronizingCommitments,
            SyncProgressUnit::CommitmentTail,
            start_block,
            current_block,
            target_block,
        )
    }

    #[must_use]
    pub const fn with_unit(
        stage: SyncProgressStage,
        unit: SyncProgressUnit,
        start_block: u64,
        current_block: u64,
        target_block: u64,
    ) -> Self {
        Self {
            stage,
            unit,
            start_block,
            current_block,
            target_block,
        }
    }

    #[must_use]
    pub const fn percent(self) -> u8 {
        if self.target_block <= self.start_block {
            return 100;
        }
        let current_block = if self.current_block < self.start_block {
            self.start_block
        } else if self.current_block > self.target_block {
            self.target_block
        } else {
            self.current_block
        };
        let completed = current_block - self.start_block;
        let total = self.target_block - self.start_block;
        ((completed.saturating_mul(100)) / total) as u8
    }
}

pub type SyncProgressSender = watch::Sender<Option<SyncProgressUpdate>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletIndexedCatchUpSource {
    Squid,
    IndexedArtifacts,
}

impl WalletIndexedCatchUpSource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Squid => "squid",
            Self::IndexedArtifacts => "indexed_artifacts",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicScanSource {
    CachedCoverage,
    IndexedArtifacts,
    Squid,
    Rpc,
    ArchiveRpc,
}

impl PublicScanSource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CachedCoverage => "cached_coverage",
            Self::IndexedArtifacts => "indexed_artifacts",
            Self::Squid => "squid",
            Self::Rpc => "rpc",
            Self::ArchiveRpc => "archive_rpc",
        }
    }
}

impl From<WalletIndexedCatchUpSource> for PublicScanSource {
    fn from(source: WalletIndexedCatchUpSource) -> Self {
        match source {
            WalletIndexedCatchUpSource::Squid => Self::Squid,
            WalletIndexedCatchUpSource::IndexedArtifacts => Self::IndexedArtifacts,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletIndexedCatchUpStatus {
    pub source: WalletIndexedCatchUpSource,
    pub from_block: u64,
    pub target_block: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoiArtifactCachePhase {
    Idle,
    LoadingPersisted,
    Resetting,
    FetchingManifest,
    DownloadingBase,
    ApplyingDeltas,
    SyncingBlockedShields,
    LiveTailing,
    ValidatingRoots,
    Ready,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoiArtifactCacheListProgress {
    pub list_key: FixedBytes<32>,
    pub current_event_index: Option<u64>,
    pub target_event_index: Option<u64>,
    pub ready_for_wallet_checks: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoiArtifactCacheProgress {
    pub chain_id: u64,
    pub phase: PoiArtifactCachePhase,
    pub completed_lists: usize,
    pub total_lists: usize,
    pub current_list_key: Option<FixedBytes<32>>,
    pub current_event_index: Option<u64>,
    pub target_event_index: Option<u64>,
    pub list_progress: Vec<PoiArtifactCacheListProgress>,
    pub ready_for_wallet_checks: bool,
    pub last_error: Option<String>,
}

impl PoiArtifactCacheProgress {
    #[must_use]
    pub fn percent(&self) -> u8 {
        if self.is_ready() {
            return 100;
        }
        if self.total_lists == 0 {
            return 0;
        }

        let completed_lists = self.completed_lists.min(self.total_lists);
        let mut basis_points = completed_lists.saturating_mul(10_000) / self.total_lists;
        if completed_lists < self.total_lists
            && let (Some(current), Some(target)) =
                (self.current_event_index, self.target_event_index)
            && target > 0
        {
            let current = current.min(target);
            basis_points = basis_points.saturating_add(
                current.saturating_mul(10_000) as usize
                    / (target as usize).saturating_mul(self.total_lists),
            );
        }
        (basis_points.min(10_000) / 100) as u8
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(
            self.phase,
            PoiArtifactCachePhase::LoadingPersisted
                | PoiArtifactCachePhase::Resetting
                | PoiArtifactCachePhase::FetchingManifest
                | PoiArtifactCachePhase::DownloadingBase
                | PoiArtifactCachePhase::ApplyingDeltas
                | PoiArtifactCachePhase::SyncingBlockedShields
                | PoiArtifactCachePhase::LiveTailing
                | PoiArtifactCachePhase::ValidatingRoots
        )
    }

    #[must_use]
    pub const fn is_ready(&self) -> bool {
        matches!(self.phase, PoiArtifactCachePhase::Ready) && self.ready_for_wallet_checks
    }

    #[must_use]
    pub const fn is_error(&self) -> bool {
        matches!(self.phase, PoiArtifactCachePhase::Error)
    }
}

pub type LocalPoiCaches = Arc<RwLock<BTreeMap<FixedBytes<32>, PoiCache>>>;
pub type WalletLocalPoiCaches = LocalPoiCaches;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoiArtifactSourceConfig {
    pub trusted_publisher_pubkey: FixedBytes<32>,
    pub manifest_source: PoiArtifactManifestSource,
    pub gateway_urls: Vec<Url>,
    pub max_manifest_age: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoiArtifactManifestSource {
    Url(Url),
    Cid(String),
    IpnsName(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoiProxyFallback {
    Disabled,
    OnCorpusUnavailable,
}

impl PoiProxyFallback {
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        matches!(self, Self::OnCorpusUnavailable)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GlobalPoiPolicy {
    IndexedArtifacts {
        artifact_source: PoiArtifactSourceConfig,
        rpc_url: Url,
        wallet_read_fallback: PoiProxyFallback,
    },
    PoiProxy {
        rpc_url: Url,
    },
}

impl GlobalPoiPolicy {
    #[must_use]
    pub const fn rpc_url(&self) -> &Url {
        match self {
            Self::IndexedArtifacts { rpc_url, .. } | Self::PoiProxy { rpc_url } => rpc_url,
        }
    }

    #[must_use]
    pub const fn is_indexed_artifacts(&self) -> bool {
        matches!(self, Self::IndexedArtifacts { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedArtifactSourceConfig {
    pub trusted_publisher_pubkey: FixedBytes<32>,
    pub manifest_source: IndexedArtifactManifestSource,
    pub gateway_urls: Vec<Url>,
    pub max_manifest_age: Option<Duration>,
    pub concurrency: usize,
    pub max_in_flight_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexedArtifactManifestSource {
    Url(Url),
    Cid(String),
    IpnsName(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChainKey {
    pub chain_id: u64,
    pub contract: Address,
}

#[derive(Clone)]
pub struct ChainConfig {
    pub chain_id: u64,
    pub contract: Address,
    pub rpcs: Arc<QueryRpcPool>,
    pub archive_rpc_url: Option<Url>,
    pub archive_until_block: u64,
    pub deployment_block: u64,
    pub v2_start_block: u64,
    pub legacy_shield_block: u64,
    pub block_range: u64,
    pub indexed_wallet_block_range: u64,
    pub poll_interval: Duration,
    pub finality_depth: u64,
    pub quick_sync_endpoint: Option<Url>,
    pub indexed_artifact_source: Option<IndexedArtifactSourceConfig>,
    pub anchor_interval: u64,
    pub anchor_retention: usize,
    /// Optional pre-configured HTTP client (e.g. with proxy support) for
    /// quick-sync and other internal HTTP requests.
    pub http_client: Option<reqwest::Client>,
    pub progress_tx: Option<SyncProgressSender>,
}

impl ChainConfig {
    pub(crate) const fn indexed_artifact_scope(&self) -> ChainScope {
        ChainScope {
            chain_type: ChainType::Evm,
            chain_id: self.chain_id,
            railgun_contract: self.contract,
        }
    }

    pub(crate) fn should_skip_merkle_artifact_catch_up(
        &self,
        from_block: u64,
        safe_head: u64,
    ) -> bool {
        self.indexed_artifact_source.is_some()
            && from_block <= safe_head
            && safe_head.saturating_sub(from_block).saturating_add(1) <= self.block_range
    }
}

#[derive(Debug, Clone)]
pub struct ChainConfigDefaults {
    pub chain_id: u64,
    pub contract: Address,
    pub relay_adapt_contract: Address,
    pub relay_adapt_7702_contract: Address,
    pub multicall_contract: Address,
    pub rpc_urls: Vec<Url>,
    pub quick_sync_endpoint: Option<Url>,
    pub indexed_wallet_block_range: u64,
    pub deployment_block: u64,
    pub v2_start_block: u64,
    pub legacy_shield_block: u64,
    pub archive_until_block: u64,
    pub finality_depth: u64,
    pub anchor_interval: u64,
    pub anchor_retention: usize,
}

impl ChainConfigDefaults {
    pub fn for_chain(chain_id: u64) -> Option<Self> {
        match chain_id {
            1 => Some(Self {
                chain_id,
                contract: address!("0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"),
                relay_adapt_contract: address!("0xAc9f360Ae85469B27aEDdEaFC579Ef2d052aD405"),
                relay_adapt_7702_contract: address!("0x2df3d82c06339387a4532c685daaf39a218cf56e"),
                multicall_contract: address!("0xcA11bde05977b3631167028862bE2a173976CA11"),
                rpc_urls: default_rpc_urls(&[
                    "https://ethereum-public.nodies.app",
                    "https://ethereum-rpc.publicnode.com",
                    "https://rpc.eth.gateway.fm",
                    "https://public-eth.nownodes.io",
                    "https://eth.api.pocket.network",
                    "https://mainnet.rpc.sentio.xyz",
                    "https://eth.drpc.org",
                ]),
                quick_sync_endpoint: Some(
                    Url::parse("https://rail-squid.squids.live/squid-railgun-ethereum-v2/graphql")
                        .expect("valid ethereum quick sync endpoint"),
                ),
                indexed_wallet_block_range: 300_000,
                deployment_block: 14_737_691,
                v2_start_block: 16_076_750,
                legacy_shield_block: 16_790_263,
                archive_until_block: 15_537_393,
                finality_depth: 12,
                anchor_interval: 1000,
                anchor_retention: 5,
            }),
            56 => Some(Self {
                chain_id,
                contract: address!("0x590162bf4b50f6576a459b75309ee21d92178a10"),
                relay_adapt_contract: address!("0xf82d00fc51f730f42a00f85e74895a2849fff2dd"),
                relay_adapt_7702_contract: address!("0x6fa84bc1587cc90978dc9535d4d38dc74fa4b522"),
                multicall_contract: address!("0xcA11bde05977b3631167028862bE2a173976CA11"),
                rpc_urls: default_rpc_urls(&[
                    "https://bsc.publicnode.com",
                    "https://binance-smart-chain-public.nodies.app",
                    "https://bsc-mainnet.nodereal.io/v1/64a9df0874fb4a93b9d0a3849de012d3",
                    "https://bsc.rpc.blxrbdn.com",
                    "https://bsc.drpc.org",
                ]),
                quick_sync_endpoint: Some(
                    Url::parse("https://rail-squid.squids.live/squid-railgun-bsc-v2/graphql")
                        .expect("valid bsc quick sync endpoint"),
                ),
                indexed_wallet_block_range: 1_000_000,
                deployment_block: 17_633_701,
                v2_start_block: 23_478_204,
                legacy_shield_block: 26_313_947,
                archive_until_block: 0,
                finality_depth: 15,
                anchor_interval: 1000,
                anchor_retention: 5,
            }),
            137 => Some(Self {
                chain_id,
                contract: address!("0x19b620929f97b7b990801496c3b361ca5def8c71"),
                relay_adapt_contract: address!("0xF82d00fC51F730F42A00F85E74895a2849ffF2Dd"),
                relay_adapt_7702_contract: address!("0x6fa84bc1587cc90978dc9535d4d38dc74fa4b522"),
                multicall_contract: address!("0xcA11bde05977b3631167028862bE2a173976CA11"),
                rpc_urls: default_rpc_urls(&[
                    "https://rpc-mainnet.matic.quiknode.pro",
                    "https://polygon-public.nodies.app",
                    "https://polygon-bor-rpc.publicnode.com",
                    "https://poly.api.pocket.network",
                    "https://polygon.drpc.org",
                ]),
                quick_sync_endpoint: Some(
                    Url::parse("https://rail-squid.squids.live/squid-railgun-polygon-v2/graphql")
                        .expect("valid polygon quick sync endpoint"),
                ),
                indexed_wallet_block_range: 1_000_000,
                deployment_block: 28_083_766,
                v2_start_block: 36_219_104,
                legacy_shield_block: 40_143_539,
                archive_until_block: 0,
                finality_depth: 256,
                anchor_interval: 1000,
                anchor_retention: 5,
            }),
            42161 => Some(Self {
                chain_id,
                contract: address!("0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"),
                relay_adapt_contract: address!("0xB4F2d77bD12c6b548Ae398244d7FAD4ABCE4D89b"),
                relay_adapt_7702_contract: address!("0x6fa84bc1587cc90978dc9535d4d38dc74fa4b522"),
                multicall_contract: address!("0xcA11bde05977b3631167028862bE2a173976CA11"),
                rpc_urls: default_rpc_urls(&[
                    "https://arbitrum-one-public.nodies.app",
                    "https://arb1.arbitrum.io/rpc",
                    "https://arbitrum-one.public.blastapi.io",
                    "https://arbitrum-one-rpc.publicnode.com",
                    "https://api.zan.top/arb-one",
                    "https://arbitrum.rpc.subquery.network/public",
                    "https://arb1.lava.build",
                    "https://arbitrum.gateway.tenderly.co",
                ]),
                quick_sync_endpoint: Some(
                    Url::parse("https://rail-squid.squids.live/squid-railgun-arbitrum-v2/graphql")
                        .expect("valid arbitrum quick sync endpoint"),
                ),
                indexed_wallet_block_range: 5_000_000,
                deployment_block: 56_109_834,
                v2_start_block: 0,
                legacy_shield_block: 68_196_853,
                archive_until_block: 0,
                finality_depth: 64,
                anchor_interval: 1000,
                anchor_retention: 5,
            }),
            _ => None,
        }
    }
}

fn default_rpc_urls(urls: &[&str]) -> Vec<Url> {
    urls.iter()
        .map(|url| Url::parse(url).expect("valid default rpc url"))
        .collect()
}

pub struct WalletPrivateCommit<'a> {
    wallet_id: &'a str,
    utxos: &'a [WalletUtxo],
    replace_wallet_utxos: bool,
    last_scanned_block: u64,
    last_scanned_block_hash: Option<[u8; 32]>,
    sync_actor_state: Option<&'a WalletSyncActorStateRecord>,
    pending_output_context_chain_id: u64,
    pending_output_context_updates: &'a [PendingOutputPoiContextRecord],
    pending_output_context_deletes: &'a [FixedBytes<32>],
    output_poi_recovery_updates: &'a [OutputPoiRecoveryRecord],
}

pub struct WalletSyncActorStateCommit<'a> {
    state: &'a WalletSyncActorStateRecord,
}

impl<'a> WalletSyncActorStateCommit<'a> {
    #[must_use]
    pub(crate) fn new(
        _token: &crate::wallet::WalletActorCommitToken<'_>,
        permit: &'a crate::wallet::WalletPrivateMutationPermit<'_>,
        state: &'a WalletSyncActorStateRecord,
    ) -> Self {
        debug_assert_eq!(permit.wallet_id(), state.wallet_id.as_str());
        Self { state }
    }

    #[must_use]
    pub const fn state(&self) -> &WalletSyncActorStateRecord {
        self.state
    }
}

impl<'a> WalletPrivateCommit<'a> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        _token: &crate::wallet::WalletActorCommitToken<'_>,
        permit: &'a crate::wallet::WalletPrivateMutationPermit<'_>,
        chain_id: u64,
        utxos: &'a [WalletUtxo],
        replace_wallet_utxos: bool,
        last_scanned_block: u64,
        last_scanned_block_hash: Option<[u8; 32]>,
        pending_output_context_updates: &'a [PendingOutputPoiContextRecord],
        pending_output_context_deletes: &'a [FixedBytes<32>],
        output_poi_recovery_updates: &'a [OutputPoiRecoveryRecord],
    ) -> Self {
        Self {
            wallet_id: permit.wallet_id(),
            utxos,
            replace_wallet_utxos,
            last_scanned_block,
            last_scanned_block_hash,
            sync_actor_state: None,
            pending_output_context_chain_id: chain_id,
            pending_output_context_updates,
            pending_output_context_deletes,
            output_poi_recovery_updates,
        }
    }

    #[must_use]
    pub const fn wallet_id(&self) -> &str {
        self.wallet_id
    }

    #[must_use]
    pub const fn utxos(&self) -> &[WalletUtxo] {
        self.utxos
    }

    #[must_use]
    pub const fn replace_wallet_utxos(&self) -> bool {
        self.replace_wallet_utxos
    }

    #[must_use]
    pub const fn last_scanned_block(&self) -> u64 {
        self.last_scanned_block
    }

    #[must_use]
    pub const fn last_scanned_block_hash(&self) -> Option<[u8; 32]> {
        self.last_scanned_block_hash
    }

    #[must_use]
    pub const fn with_sync_actor_state(
        mut self,
        sync_actor_state: &'a WalletSyncActorStateRecord,
    ) -> Self {
        self.sync_actor_state = Some(sync_actor_state);
        self
    }

    #[must_use]
    pub const fn sync_actor_state(&self) -> Option<&WalletSyncActorStateRecord> {
        self.sync_actor_state
    }

    #[must_use]
    pub const fn pending_output_context_chain_id(&self) -> u64 {
        self.pending_output_context_chain_id
    }

    #[must_use]
    pub const fn pending_output_context_updates(&self) -> &[PendingOutputPoiContextRecord] {
        self.pending_output_context_updates
    }

    #[must_use]
    pub const fn pending_output_context_deletes(&self) -> &[FixedBytes<32>] {
        self.pending_output_context_deletes
    }

    #[must_use]
    pub const fn output_poi_recovery_updates(&self) -> &[OutputPoiRecoveryRecord] {
        self.output_poi_recovery_updates
    }
}

pub trait WalletCacheStore: Send + Sync {
    fn commit_wallet_private_state(
        &self,
        commit: WalletPrivateCommit<'_>,
    ) -> Result<(), WalletCacheError>;

    fn load_wallet_utxos(&self, wallet_id: &str) -> Result<Vec<WalletUtxo>, WalletCacheError>;

    fn get_wallet_meta(&self, wallet_id: &str) -> Result<Option<WalletMeta>, WalletCacheError>;

    fn get_wallet_sync_actor_state(
        &self,
        chain_id: u64,
        wallet_id: &str,
    ) -> Result<Option<WalletSyncActorStateRecord>, WalletCacheError>;

    fn put_wallet_sync_actor_state(
        &self,
        commit: WalletSyncActorStateCommit<'_>,
    ) -> Result<(), WalletCacheError>;
}

impl WalletCacheStore for DbStore {
    fn commit_wallet_private_state(
        &self,
        commit: WalletPrivateCommit<'_>,
    ) -> Result<(), WalletCacheError> {
        let utxo_entries = if commit.replace_wallet_utxos() {
            Some(wallet_utxo_entries(commit.utxos())?)
        } else {
            None
        };
        let meta = WalletMeta {
            last_scanned_block: commit.last_scanned_block(),
            updated_at: wallet_cache_now_epoch_secs()?,
            last_scanned_block_hash: commit.last_scanned_block_hash(),
        };
        self.batch_commit_wallet_private_state(
            commit.wallet_id(),
            utxo_entries.as_deref(),
            Some(&meta),
            commit.sync_actor_state(),
            commit.pending_output_context_updates(),
            commit.pending_output_context_chain_id(),
            commit.pending_output_context_deletes(),
            commit.output_poi_recovery_updates(),
        )?;
        Ok(())
    }

    fn load_wallet_utxos(&self, wallet_id: &str) -> Result<Vec<WalletUtxo>, WalletCacheError> {
        WalletCacheDbExt::load_wallet_utxos(self, wallet_id)
    }

    fn get_wallet_meta(&self, wallet_id: &str) -> Result<Option<WalletMeta>, WalletCacheError> {
        Ok(DbStore::get_wallet_meta(self, wallet_id)?)
    }

    fn get_wallet_sync_actor_state(
        &self,
        chain_id: u64,
        wallet_id: &str,
    ) -> Result<Option<WalletSyncActorStateRecord>, WalletCacheError> {
        Ok(DbStore::get_wallet_sync_actor_state(
            self, chain_id, wallet_id,
        )?)
    }

    fn put_wallet_sync_actor_state(
        &self,
        commit: WalletSyncActorStateCommit<'_>,
    ) -> Result<(), WalletCacheError> {
        Ok(DbStore::put_wallet_sync_actor_state(self, commit.state())?)
    }
}

fn wallet_utxo_entries(utxos: &[WalletUtxo]) -> Result<Vec<(String, Vec<u8>)>, WalletCacheError> {
    utxos
        .iter()
        .map(|utxo| {
            Ok((
                format!("{}:{}", utxo.utxo.tree, utxo.utxo.position),
                serialize_wallet_utxo(utxo)?,
            ))
        })
        .collect()
}

fn wallet_cache_now_epoch_secs() -> Result<u64, std::io::Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(std::io::Error::other)
}

#[derive(Clone)]
pub struct WalletConfig {
    pub chain: ChainKey,
    pub cache_key: String,
    pub start_block: Option<u64>,
    pub sync_to_block: Option<u64>,
    pub quick_sync_endpoint: Option<Url>,
    pub scan_keys: WalletScanKeys,
    pub spending_public_key: Option<[U256; 2]>,
    pub progress_tx: Option<SyncProgressSender>,
    pub cache_store: Option<Arc<dyn WalletCacheStore>>,
    pub poi_recovery_prover: Option<ProverService>,
    pub use_indexed_wallet_catch_up: bool,
}

#[cfg(test)]
mod tests {
    use super::{
        ChainConfigDefaults, PoiArtifactCachePhase, PoiArtifactCacheProgress, SyncProgressStage,
        SyncProgressUnit, SyncProgressUpdate,
    };

    #[test]
    fn default_indexed_wallet_ranges_are_chain_specific() {
        assert_eq!(
            ChainConfigDefaults::for_chain(1)
                .unwrap()
                .indexed_wallet_block_range,
            300_000
        );
        assert_eq!(
            ChainConfigDefaults::for_chain(56)
                .unwrap()
                .indexed_wallet_block_range,
            1_000_000
        );
        assert_eq!(
            ChainConfigDefaults::for_chain(137)
                .unwrap()
                .indexed_wallet_block_range,
            1_000_000
        );
        assert_eq!(
            ChainConfigDefaults::for_chain(42161)
                .unwrap()
                .indexed_wallet_block_range,
            5_000_000
        );
    }

    #[test]
    fn default_rpc_urls_include_fallbacks() {
        assert_eq!(
            ChainConfigDefaults::for_chain(1).unwrap().rpc_urls[0].as_str(),
            "https://ethereum-public.nodies.app/"
        );
        assert!(ChainConfigDefaults::for_chain(1).unwrap().rpc_urls.len() > 1);
        assert!(ChainConfigDefaults::for_chain(56).unwrap().rpc_urls.len() > 1);
        assert!(ChainConfigDefaults::for_chain(137).unwrap().rpc_urls.len() > 1);
        assert!(
            ChainConfigDefaults::for_chain(42161)
                .unwrap()
                .rpc_urls
                .len()
                > 1
        );
    }

    #[test]
    fn sync_progress_percent_uses_block_distance() {
        let progress =
            SyncProgressUpdate::new(SyncProgressStage::SynchronizingCommitments, 100, 150, 300);

        assert_eq!(progress.percent(), 25);
    }

    #[test]
    fn sync_progress_percent_uses_chunk_distance_for_utxo_prep() {
        let progress = SyncProgressUpdate::artifact_chunk(
            SyncProgressStage::PreparingUtxoIndex,
            25,
            100,
            3,
            12,
        );

        assert_eq!(progress.percent(), 25);
        assert_eq!(
            progress.unit,
            SyncProgressUnit::ArtifactChunk {
                completed: 3,
                total: 12
            }
        );
    }

    #[test]
    fn sync_progress_percent_is_clamped() {
        let early = SyncProgressUpdate::new(SyncProgressStage::IndexingUtxos, 100, 99, 300);
        let late = SyncProgressUpdate::new(SyncProgressStage::IndexingUtxos, 100, 400, 300);

        assert_eq!(early.percent(), 0);
        assert_eq!(late.percent(), 100);
    }

    #[test]
    fn poi_artifact_cache_progress_percent_handles_zero_totals() {
        let progress = PoiArtifactCacheProgress {
            chain_id: 1,
            phase: PoiArtifactCachePhase::LoadingPersisted,
            completed_lists: 0,
            total_lists: 0,
            current_list_key: None,
            current_event_index: None,
            target_event_index: None,
            list_progress: Vec::new(),
            ready_for_wallet_checks: false,
            last_error: None,
        };

        assert_eq!(progress.percent(), 0);
        assert!(progress.is_active());
        assert!(!progress.is_ready());
        assert!(!progress.is_error());
    }

    #[test]
    fn poi_artifact_cache_progress_reports_ready_and_error_state() {
        let ready = PoiArtifactCacheProgress {
            chain_id: 1,
            phase: PoiArtifactCachePhase::Ready,
            completed_lists: 1,
            total_lists: 1,
            current_list_key: None,
            current_event_index: None,
            target_event_index: None,
            list_progress: Vec::new(),
            ready_for_wallet_checks: true,
            last_error: None,
        };
        let error = PoiArtifactCacheProgress {
            phase: PoiArtifactCachePhase::Error,
            ready_for_wallet_checks: false,
            last_error: Some("failed".to_string()),
            ..ready.clone()
        };

        assert_eq!(ready.percent(), 100);
        assert!(ready.is_ready());
        assert!(error.is_error());
        assert!(!error.is_active());
    }
}

#[derive(Debug, Clone)]
pub struct LogBatch {
    pub from_block: u64,
    pub to_block: u64,
    pub logs: Vec<Log>,
    pub block_timestamps: HashMap<u64, u64>,
    pub to_block_hash: Option<[u8; 32]>,
    pub read_scope: PublicScanReadScope,
}

pub type SharedLogBatch = Arc<LogBatch>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicDataPlaneEpoch {
    pub value: u64,
}

impl PublicDataPlaneEpoch {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self { value }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicScanReadScope {
    epoch: PublicDataPlaneEpoch,
}

impl PublicScanReadScope {
    #[must_use]
    pub(crate) const fn new(epoch: PublicDataPlaneEpoch) -> Self {
        Self { epoch }
    }

    #[must_use]
    pub const fn epoch(self) -> PublicDataPlaneEpoch {
        self.epoch
    }
}

#[derive(Debug)]
pub(crate) enum WalletScanRowsPayload {
    Rows(Box<WalletScanInputRows>),
    EmptyCoverage,
    #[cfg(test)]
    IndexedDeltaForTest {
        delta: Box<WalletLogDelta>,
    },
}

#[derive(Debug)]
pub(crate) struct WalletScanRows {
    pub(crate) from_block: u64,
    pub(crate) to_block: u64,
    pub(crate) source: PublicScanSource,
    pub(crate) to_block_hash: Option<[u8; 32]>,
    pub(crate) payload: WalletScanRowsPayload,
}

impl WalletScanRows {
    #[must_use]
    pub(crate) const fn new(
        from_block: u64,
        to_block: u64,
        source: PublicScanSource,
        to_block_hash: Option<[u8; 32]>,
        payload: WalletScanRowsPayload,
    ) -> Self {
        Self {
            from_block,
            to_block,
            source,
            to_block_hash,
            payload,
        }
    }

    #[must_use]
    pub(crate) fn covers(&self, from_block: u64, to_block: u64) -> bool {
        self.from_block == from_block
            && self.to_block == to_block
            && match &self.payload {
                WalletScanRowsPayload::Rows(_) | WalletScanRowsPayload::EmptyCoverage => true,
                #[cfg(test)]
                WalletScanRowsPayload::IndexedDeltaForTest { .. } => true,
            }
    }

    #[must_use]
    pub(crate) fn row_count(&self) -> usize {
        match &self.payload {
            WalletScanRowsPayload::Rows(rows) => rows.row_count(),
            WalletScanRowsPayload::EmptyCoverage => 0,
            #[cfg(test)]
            WalletScanRowsPayload::IndexedDeltaForTest { .. } => 0,
        }
    }
}

#[derive(Debug)]
pub(crate) struct WalletScanApply {
    pub(crate) from_block: u64,
    pub(crate) to_block: u64,
    pub(crate) rows: WalletScanRows,
    pub(crate) read_scope: PublicScanReadScope,
}

impl WalletScanApply {
    #[must_use]
    pub(crate) const fn new(
        from_block: u64,
        to_block: u64,
        rows: WalletScanRows,
        read_scope: PublicScanReadScope,
    ) -> Self {
        Self {
            from_block,
            to_block,
            rows,
            read_scope,
        }
    }

    #[must_use]
    pub(crate) fn rows(
        from_block: u64,
        to_block: u64,
        rows: WalletScanInputRows,
        read_scope: PublicScanReadScope,
        source: PublicScanSource,
        to_block_hash: Option<[u8; 32]>,
    ) -> Self {
        Self::new(
            from_block,
            to_block,
            WalletScanRows::new(
                from_block,
                to_block,
                source,
                to_block_hash,
                WalletScanRowsPayload::Rows(Box::new(rows)),
            ),
            read_scope,
        )
    }

    pub(crate) fn rows_from_log_batch(
        from_block: u64,
        to_block: u64,
        batch: SharedLogBatch,
        source: PublicScanSource,
    ) -> Result<Self, WalletScanError> {
        let read_scope = batch.read_scope;
        let filtered_logs: Vec<_> = batch
            .logs
            .iter()
            .filter(|log| {
                log.block_number
                    .is_some_and(|block| block >= from_block && block <= to_block)
            })
            .cloned()
            .collect();
        let rows = WalletScanInputRows::from_logs(&filtered_logs, &batch.block_timestamps)?;
        let to_block_hash = if batch.to_block == to_block {
            batch.to_block_hash
        } else {
            None
        };
        Ok(Self::rows(
            from_block,
            to_block,
            rows,
            read_scope,
            source,
            to_block_hash,
        ))
    }

    #[must_use]
    pub(crate) fn row_count(&self) -> usize {
        self.rows.row_count()
    }

    #[must_use]
    pub(crate) fn indexed_rows(
        from_block: u64,
        to_block: u64,
        rows: WalletScanInputRows,
        read_scope: PublicScanReadScope,
        source: WalletIndexedCatchUpSource,
    ) -> Self {
        Self::rows(from_block, to_block, rows, read_scope, source.into(), None)
    }

    #[must_use]
    pub(crate) fn empty_coverage(
        from_block: u64,
        to_block: u64,
        read_scope: PublicScanReadScope,
        source: PublicScanSource,
    ) -> Self {
        Self::new(
            from_block,
            to_block,
            WalletScanRows::new(
                from_block,
                to_block,
                source,
                None,
                WalletScanRowsPayload::EmptyCoverage,
            ),
            read_scope,
        )
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn indexed_delta_for_test(
        from_block: u64,
        to_block: u64,
        delta: WalletLogDelta,
        read_scope: PublicScanReadScope,
        source: WalletIndexedCatchUpSource,
    ) -> Self {
        Self::new(
            from_block,
            to_block,
            WalletScanRows::new(
                from_block,
                to_block,
                source.into(),
                None,
                WalletScanRowsPayload::IndexedDeltaForTest {
                    delta: Box::new(delta),
                },
            ),
            read_scope,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletBackfillRejectReason {
    StaleGeneration {
        expected: u64,
        actual: u64,
    },
    NonContiguous {
        expected_from: u64,
        actual_from: u64,
    },
    ApplyFailed,
    PersistenceFailed,
    TargetNotReached {
        target_block: u64,
    },
    TargetExceeded {
        target_block: u64,
        requested_to: u64,
    },
    Shutdown,
    StaleDataPlaneEpoch {
        expected: u64,
        actual: u64,
    },
    StaleResetIntent {
        accepted: u64,
        actual: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletBackfillApplyResult {
    Committed {
        committed_to: u64,
    },
    AlreadyCovered {
        committed_to: u64,
    },
    Rejected {
        committed_to: u64,
        reason: WalletBackfillRejectReason,
    },
}

impl WalletBackfillApplyResult {
    #[must_use]
    pub const fn committed_to(&self) -> u64 {
        match self {
            Self::Committed { committed_to }
            | Self::AlreadyCovered { committed_to }
            | Self::Rejected { committed_to, .. } => *committed_to,
        }
    }

    #[must_use]
    pub const fn accepted_committed_to(&self) -> Option<u64> {
        match self {
            Self::Committed { committed_to } | Self::AlreadyCovered { committed_to } => {
                Some(*committed_to)
            }
            Self::Rejected { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletBackfillFinishResult {
    Accepted {
        committed_to: u64,
        target_block: u64,
        lease: WalletBackfillLease,
    },
    Ready {
        committed_to: u64,
    },
    Rejected {
        committed_to: u64,
        reason: WalletBackfillRejectReason,
    },
}

impl WalletBackfillFinishResult {
    #[must_use]
    pub const fn committed_to(&self) -> u64 {
        match self {
            Self::Accepted { committed_to, .. }
            | Self::Ready { committed_to }
            | Self::Rejected { committed_to, .. } => *committed_to,
        }
    }

    #[must_use]
    pub fn accepted_lease(&self) -> Option<WalletBackfillLease> {
        match self {
            Self::Accepted { lease, .. } => Some(lease.clone()),
            Self::Ready { .. } | Self::Rejected { .. } => None,
        }
    }
}

/// Pending tip overlay (chain + local) projected against the current cursor.
#[derive(Debug, Clone, Default)]
pub struct WalletPendingOverlay {
    pub new_utxos: Vec<WalletUtxo>,
    pub pending_spent: Vec<WalletPendingSpent>,
    pub local_pending_spent: Vec<WalletPendingSpent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletPendingSpent {
    pub tree: u32,
    pub position: u64,
    pub tx_hash: Option<FixedBytes<32>>,
    pub block_number: Option<u64>,
    pub block_timestamp: Option<u64>,
}

impl WalletPendingSpent {
    #[must_use]
    pub const fn key(&self) -> (u32, u64) {
        (self.tree, self.position)
    }

    pub fn from_source(utxo: &railgun_wallet::Utxo, source: railgun_wallet::UtxoSource) -> Self {
        Self {
            tree: utxo.tree,
            position: utxo.position,
            tx_hash: Some(source.tx_hash),
            block_number: Some(source.block_number),
            block_timestamp: Some(source.block_timestamp),
        }
    }

    #[cfg(test)]
    pub fn submitted(
        utxo: &railgun_wallet::Utxo,
        tx_hash: Option<FixedBytes<32>>,
        now: u64,
    ) -> Self {
        Self {
            tree: utxo.tree,
            position: utxo.position,
            tx_hash,
            block_number: None,
            block_timestamp: Some(now),
        }
    }
}

/// Coherent current private wallet projection (only valid when not reset-pending).
///
/// Includes confirmed UTXOs and pending tip overlay. Published atomically via
/// [`WalletViewState::Current`]; public observers must not read live mirrors.
#[derive(Debug, Clone)]
pub struct WalletCurrentSnapshot {
    pub last_scanned: u64,
    pub utxos: Arc<[WalletUtxo]>,
    pub pending_overlay: Arc<WalletPendingOverlay>,
    pub revision: u64,
    pub reset_generation: u64,
}

impl WalletCurrentSnapshot {
    #[must_use]
    pub fn new(
        last_scanned: u64,
        revision: u64,
        reset_generation: u64,
        utxos: impl Into<Arc<[WalletUtxo]>>,
        pending_overlay: impl Into<Arc<WalletPendingOverlay>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            last_scanned,
            utxos: utxos.into(),
            pending_overlay: pending_overlay.into(),
            revision,
            reset_generation,
        })
    }
}

/// Generation-scoped public progress taken from one [`WalletViewState`] observation.
///
/// This is the **only** capability that authorizes generation-scoped public chain work
/// (backfill, indexed catch-up, lag/tail fallback). Call sites must not compose a public
/// cursor with a separately loaded generation, and bare `reset_generation: u64` is not a
/// public scheduling input.
///
/// Deferred work stores this ticket and revalidates it before start; range and generation
/// travel as one unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletSchedulableProgress {
    pub last_scanned: u64,
    pub reset_generation: u64,
}

impl WalletSchedulableProgress {
    /// Still current if `now` is Current and same generation. Returns the refreshed snapshot
    /// (cursor may have advanced within the generation).
    #[must_use]
    pub const fn revalidate(self, now: Option<Self>) -> Option<Self> {
        match now {
            Some(now) if now.reset_generation == self.reset_generation => Some(now),
            _ => None,
        }
    }

    /// True when `now` is still the same scheduling generation.
    #[must_use]
    pub const fn still_current(self, now: Option<Self>) -> bool {
        self.revalidate(now).is_some()
    }
}

/// Single-source public private-view state for a wallet actor.
///
/// While [`ResetPending`](Self::ResetPending), public readers must not treat
/// pre-reset private projection (cursor, UTXOs, pending overlay) as current.
///
/// [`Current`](Self::Current) carries the full published projection. Authority generation
/// (token invalidation) may advance before the view is republished; schedulers must not
/// mix those surfaces.
#[derive(Debug, Clone)]
pub enum WalletViewState {
    /// Full private projection; the only public source for UTXOs / pending overlay.
    Current(Arc<WalletCurrentSnapshot>),
    ResetPending {
        intent_id: u64,
        from_block: u64,
        reset_generation: u64,
    },
}

impl PartialEq for WalletViewState {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Current(left), Self::Current(right)) => {
                left.last_scanned == right.last_scanned
                    && left.revision == right.revision
                    && left.reset_generation == right.reset_generation
                    && Arc::ptr_eq(&left.utxos, &right.utxos)
                    && Arc::ptr_eq(&left.pending_overlay, &right.pending_overlay)
            }
            (
                Self::ResetPending {
                    intent_id: li,
                    from_block: lf,
                    reset_generation: lg,
                },
                Self::ResetPending {
                    intent_id: ri,
                    from_block: rf,
                    reset_generation: rg,
                },
            ) => li == ri && lf == rf && lg == rg,
            _ => false,
        }
    }
}

impl Eq for WalletViewState {}

impl WalletViewState {
    #[must_use]
    pub fn is_current(&self) -> bool {
        matches!(self, Self::Current(_))
    }

    #[must_use]
    pub fn current_snapshot(&self) -> Option<Arc<WalletCurrentSnapshot>> {
        match self {
            Self::Current(snapshot) => Some(Arc::clone(snapshot)),
            Self::ResetPending { .. } => None,
        }
    }

    #[must_use]
    pub fn last_scanned_current(&self) -> Option<u64> {
        match self {
            Self::Current(snapshot) => Some(snapshot.last_scanned),
            Self::ResetPending { .. } => None,
        }
    }

    /// Public schedulable progress from this snapshot, if view is current.
    #[must_use]
    pub fn schedulable_progress(&self) -> Option<WalletSchedulableProgress> {
        match self {
            Self::Current(snapshot) => Some(WalletSchedulableProgress {
                last_scanned: snapshot.last_scanned,
                reset_generation: snapshot.reset_generation,
            }),
            Self::ResetPending { .. } => None,
        }
    }

    #[must_use]
    pub fn reset_generation(&self) -> u64 {
        match self {
            Self::Current(snapshot) => snapshot.reset_generation,
            Self::ResetPending {
                reset_generation, ..
            } => *reset_generation,
        }
    }
}

/// Status of the CommitResetRewind transition after AcceptReset has already succeeded
/// (or for restored/retry rewinds of an already-accepted pending reset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletResetRewindStatus {
    /// Rewind durably applied; mirrors match rewound state.
    Committed { committed_to: u64 },
    /// Accept holds; rewind not done yet (shutdown, persist fail, retrying).
    Pending {
        committed_to: u64,
        /// Diagnostic only — never upgrades accept to Rejected.
        last_attempt: Option<WalletBackfillRejectReason>,
    },
}

impl WalletResetRewindStatus {
    #[must_use]
    pub const fn committed_to(&self) -> u64 {
        match self {
            Self::Committed { committed_to } | Self::Pending { committed_to, .. } => *committed_to,
        }
    }

    #[must_use]
    pub const fn is_committed(&self) -> bool {
        matches!(self, Self::Committed { .. })
    }
}

/// Public result of a wallet reset request.
///
/// **Invariant:** once AcceptReset has durably succeeded, the result is always
/// [`Accepted`](Self::Accepted) with a rewind status. [`Rejected`](Self::Rejected)
/// means the reset was never accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletBackfillResetResult {
    Accepted {
        reset_generation: u64,
        rewind: WalletResetRewindStatus,
    },
    Rejected {
        committed_to: u64,
        reason: WalletBackfillRejectReason,
    },
}

impl WalletBackfillResetResult {
    #[must_use]
    pub const fn accepted_committed(reset_generation: u64, committed_to: u64) -> Self {
        Self::Accepted {
            reset_generation,
            rewind: WalletResetRewindStatus::Committed { committed_to },
        }
    }

    #[must_use]
    pub const fn accepted_pending(
        reset_generation: u64,
        committed_to: u64,
        last_attempt: Option<WalletBackfillRejectReason>,
    ) -> Self {
        Self::Accepted {
            reset_generation,
            rewind: WalletResetRewindStatus::Pending {
                committed_to,
                last_attempt,
            },
        }
    }

    #[must_use]
    pub const fn rejected(committed_to: u64, reason: WalletBackfillRejectReason) -> Self {
        Self::Rejected {
            committed_to,
            reason,
        }
    }

    #[must_use]
    pub const fn committed_to(&self) -> u64 {
        match self {
            Self::Accepted { rewind, .. } => rewind.committed_to(),
            Self::Rejected { committed_to, .. } => *committed_to,
        }
    }

    #[must_use]
    pub const fn reset_generation(&self) -> Option<u64> {
        match self {
            Self::Accepted {
                reset_generation, ..
            } => Some(*reset_generation),
            Self::Rejected { .. } => None,
        }
    }

    #[must_use]
    pub const fn committed(&self) -> bool {
        matches!(
            self,
            Self::Accepted {
                rewind: WalletResetRewindStatus::Committed { .. },
                ..
            }
        )
    }

    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletReadinessError {
    BackfillUnavailable,
    TargetNotReached { target_block: u64 },
    PersistenceFailed,
    ApplyFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletReadiness {
    Syncing,
    Ready,
    Failed(WalletReadinessError),
    Shutdown,
}

impl WalletReadiness {
    #[must_use]
    pub const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready)
    }

    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Ready | Self::Failed(_) | Self::Shutdown)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct WalletSyncToken {
    chain_id: u64,
    actor_id: u64,
    reset_generation: u64,
    job_id: u64,
}

impl WalletSyncToken {
    #[must_use]
    pub(crate) fn mint(
        authority: WalletActorTokenAuthority<'_>,
        reset_generation: u64,
        job_id: u64,
    ) -> Self {
        Self {
            chain_id: authority.chain_id(),
            actor_id: authority.actor_id(),
            reset_generation,
            job_id,
        }
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn for_test(
        chain_id: u64,
        actor_id: u64,
        reset_generation: u64,
        job_id: u64,
    ) -> Self {
        Self {
            chain_id,
            actor_id,
            reset_generation,
            job_id,
        }
    }

    #[must_use]
    pub(crate) const fn chain_id(self) -> u64 {
        self.chain_id
    }

    #[must_use]
    pub(crate) const fn actor_id(self) -> u64 {
        self.actor_id
    }

    #[must_use]
    pub(crate) const fn reset_generation(self) -> u64 {
        self.reset_generation
    }

    #[must_use]
    pub(crate) const fn job_id(self) -> u64 {
        self.job_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct WalletResetToken {
    chain_id: u64,
    actor_id: u64,
    intent_id: u64,
}

impl WalletResetToken {
    #[must_use]
    pub(crate) fn mint(authority: WalletActorTokenAuthority<'_>, intent_id: u64) -> Self {
        Self {
            chain_id: authority.chain_id(),
            actor_id: authority.actor_id(),
            intent_id,
        }
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn for_test(chain_id: u64, actor_id: u64, intent_id: u64) -> Self {
        Self {
            chain_id,
            actor_id,
            intent_id,
        }
    }

    #[must_use]
    pub(crate) const fn chain_id(self) -> u64 {
        self.chain_id
    }

    #[must_use]
    pub(crate) const fn actor_id(self) -> u64 {
        self.actor_id
    }

    #[must_use]
    pub(crate) const fn intent_id(self) -> u64 {
        self.intent_id
    }
}

#[derive(Debug, Clone)]
pub struct WalletBackfillLease {
    token: WalletSyncToken,
    sender: mpsc::Sender<BackfillEvent>,
}

impl PartialEq for WalletBackfillLease {
    fn eq(&self, other: &Self) -> bool {
        self.token == other.token
    }
}

impl Eq for WalletBackfillLease {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WalletResetReplayPlan {
    pub(crate) start_block: u64,
    pub(crate) target_block: u64,
    pub(crate) follow_safe_head: bool,
}

impl WalletResetReplayPlan {
    #[must_use]
    pub(crate) const fn new(start_block: u64, target_block: u64, follow_safe_head: bool) -> Self {
        Self {
            start_block,
            target_block,
            follow_safe_head,
        }
    }
}

impl WalletBackfillLease {
    pub(crate) fn from_token(token: WalletSyncToken, sender: mpsc::Sender<BackfillEvent>) -> Self {
        Self { token, sender }
    }

    pub(crate) const fn token(&self) -> WalletSyncToken {
        self.token
    }

    pub(crate) fn supersedes(&self, active: &Self) -> bool {
        let incoming = self.token();
        let active = active.token();
        (
            incoming.chain_id(),
            incoming.actor_id(),
            incoming.reset_generation(),
            incoming.job_id(),
        ) > (
            active.chain_id(),
            active.actor_id(),
            active.reset_generation(),
            active.job_id(),
        )
    }

    pub(crate) fn sender(&self) -> &mpsc::Sender<BackfillEvent> {
        &self.sender
    }

    pub(crate) async fn apply(
        &self,
        cache_key: &str,
        apply: WalletScanApply,
    ) -> WalletBackfillApplyResult {
        let requested_to = apply.to_block;
        let (response, result_rx) = oneshot::channel();
        if let Err(err) = self
            .sender
            .send(BackfillEvent::Apply {
                apply,
                token: self.token,
                response,
            })
            .await
        {
            warn!(?err, cache_key, "failed to send wallet scan batch");
            return WalletBackfillApplyResult::Rejected {
                committed_to: requested_to.saturating_sub(1),
                reason: WalletBackfillRejectReason::Shutdown,
            };
        }
        match result_rx.await {
            Ok(result) => result,
            Err(err) => {
                warn!(?err, cache_key, "wallet scan batch response dropped");
                WalletBackfillApplyResult::Rejected {
                    committed_to: requested_to.saturating_sub(1),
                    reason: WalletBackfillRejectReason::Shutdown,
                }
            }
        }
    }

    pub(crate) async fn finish(
        &self,
        cache_key: &str,
        target_block: u64,
    ) -> WalletBackfillFinishResult {
        let (response, result_rx) = oneshot::channel();
        if let Err(err) = self
            .sender
            .send(BackfillEvent::Target {
                target_block,
                token: self.token,
                sender: self.sender.clone(),
                response,
            })
            .await
        {
            warn!(
                ?err,
                cache_key, target_block, "failed to send wallet target update"
            );
            return WalletBackfillFinishResult::Rejected {
                committed_to: target_block.saturating_sub(1),
                reason: WalletBackfillRejectReason::Shutdown,
            };
        }
        match result_rx.await {
            Ok(result) => result,
            Err(err) => {
                warn!(
                    ?err,
                    cache_key, target_block, "wallet target response dropped"
                );
                WalletBackfillFinishResult::Rejected {
                    committed_to: target_block.saturating_sub(1),
                    reason: WalletBackfillRejectReason::Shutdown,
                }
            }
        }
    }

    pub(crate) async fn retire(&self, cache_key: &str) {
        if let Err(err) = self
            .sender
            .send(BackfillEvent::JobRetired { token: self.token })
            .await
        {
            warn!(?err, cache_key, "failed to send wallet job retirement");
        }
    }

    pub(crate) async fn fail(&self, cache_key: &str, reason: WalletReadinessError) {
        if let Err(err) = self
            .sender
            .send(BackfillEvent::JobFailed {
                token: self.token,
                reason,
            })
            .await
        {
            warn!(?err, cache_key, "failed to send wallet job failure");
        }
    }
}

#[derive(Debug)]
pub(crate) enum BackfillEvent {
    Apply {
        apply: WalletScanApply,
        token: WalletSyncToken,
        response: oneshot::Sender<WalletBackfillApplyResult>,
    },
    Target {
        target_block: u64,
        token: WalletSyncToken,
        sender: mpsc::Sender<BackfillEvent>,
        response: oneshot::Sender<WalletBackfillFinishResult>,
    },
    JobFailed {
        token: WalletSyncToken,
        reason: WalletReadinessError,
    },
    JobRetired {
        token: WalletSyncToken,
    },
    Reset {
        token: WalletResetToken,
        from_block: u64,
        replay_plan: WalletResetReplayPlan,
        response: oneshot::Sender<WalletBackfillResetResult>,
    },
}

#[derive(Debug)]
pub(crate) enum BackfillRequest {
    Add {
        cache_key: String,
        from_block: u64,
        to_block: u64,
        follow_safe_head: bool,
        progress_start_block: u64,
        lease: WalletBackfillLease,
    },
    Remove {
        cache_key: String,
    },
}

impl BackfillRequest {
    pub(crate) fn add(
        cache_key: impl Into<String>,
        from_block: u64,
        to_block: u64,
        follow_safe_head: bool,
        progress_start_block: u64,
        lease: WalletBackfillLease,
    ) -> Self {
        Self::Add {
            cache_key: cache_key.into(),
            from_block,
            to_block,
            follow_safe_head,
            progress_start_block,
            lease,
        }
    }
}
