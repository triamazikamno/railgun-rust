use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::primitives::{Address, FixedBytes, U256, address};
use alloy_rpc_types_eth::Log;
use broadcaster_core::query_rpc_pool::QueryRpcPool;
use broadcaster_core::transact::PreTxPoi;
use local_db::{
    DbError, DbStore, OpaqueWalletPrivateRow, OpaqueWalletPrivateRowMutation,
    OutputPoiRecoveryRecord, PendingOutputPoiContextRecord, PendingOutputPoiRole, WalletCacheKey,
    WalletMeta, WalletMetaMutation, WalletPrivateNamespaceId, WalletPrivateStateBatch,
    WalletPrivateV1MigrationBatch, WalletSyncActorStateRecord, WalletUtxoRowMutation,
};
use poi::SensitiveUrl;
use poi::cache::PoiCache;
use railgun_wallet::scan::{WalletScanError, WalletScanInputRows, WalletScanKeys};
use railgun_wallet::wallet_cache::{WalletCacheDbExt, WalletCacheError, serialize_wallet_utxo};
use railgun_wallet::{ProverService, WalletUtxo};
use tokio::sync::{
    OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock, RwLockReadGuard, RwLockWriteGuard, mpsc,
    oneshot, watch,
};
use tracing::warn;
use url::Url;

use crate::indexed_artifacts::{ChainScope, ChainType};
use crate::poi_artifacts::PoiCorpusAuthority;
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
    pub source: Option<PublicScanSource>,
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
            source: None,
            start_block,
            current_block,
            target_block,
        }
    }

    #[must_use]
    pub const fn with_source(mut self, source: PublicScanSource) -> Self {
        self.source = Some(source);
        self
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
    ResolvingManifest,
    VerifyingCatalog,
    Planning,
    DownloadingChunks,
    ReplayingRanges,
    Validating,
    Persisting,
    LiveTailing,
    Ready,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PoiArtifactCacheAttemptId(u64);

impl PoiArtifactCacheAttemptId {
    #[must_use]
    pub(crate) const fn new(value: u64) -> Self {
        assert!(value != 0, "POI artifact cache attempt IDs are nonzero");
        Self(value)
    }

    #[must_use]
    pub const fn from_u64(value: u64) -> Option<Self> {
        if value == 0 { None } else { Some(Self(value)) }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for PoiArtifactCacheAttemptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoiArtifactCacheListProgress {
    pub list_key: FixedBytes<32>,
    pub current_event_index: Option<u64>,
    pub target_event_index: Option<u64>,
    pub ready_for_wallet_checks: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PoiArtifactCacheGraphProgress {
    pub verified_chunks: usize,
    pub total_chunks: usize,
    pub verified_encoded_bytes: u64,
    pub total_authenticated_encoded_bytes: Option<u64>,
    pub replay_start_event_index: Option<u64>,
    pub replay_end_event_index: Option<u64>,
    pub replayed_event_count: u64,
    pub total_replay_event_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoiArtifactCacheFailureKind {
    RefreshDegraded,
    ServingCorpusUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoiArtifactCacheProgress {
    pub attempt_id: PoiArtifactCacheAttemptId,
    pub generation: u64,
    pub chain_id: u64,
    pub phase: PoiArtifactCachePhase,
    pub completed_lists: usize,
    pub total_lists: usize,
    pub current_list_key: Option<FixedBytes<32>>,
    pub current_event_index: Option<u64>,
    pub target_event_index: Option<u64>,
    pub list_progress: Vec<PoiArtifactCacheListProgress>,
    pub graph: PoiArtifactCacheGraphProgress,
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
                | PoiArtifactCachePhase::ResolvingManifest
                | PoiArtifactCachePhase::VerifyingCatalog
                | PoiArtifactCachePhase::Planning
                | PoiArtifactCachePhase::DownloadingChunks
                | PoiArtifactCachePhase::ReplayingRanges
                | PoiArtifactCachePhase::Validating
                | PoiArtifactCachePhase::Persisting
                | PoiArtifactCachePhase::LiveTailing
        )
    }

    #[must_use]
    pub const fn is_ready(&self) -> bool {
        matches!(self.phase, PoiArtifactCachePhase::Ready) && self.ready_for_wallet_checks
    }

    #[must_use]
    pub const fn is_error(&self) -> bool {
        matches!(self.phase, PoiArtifactCachePhase::Failed)
    }

    #[must_use]
    pub const fn failure_kind(&self) -> Option<PoiArtifactCacheFailureKind> {
        if self.last_error.is_none() {
            return None;
        }
        Some(if self.ready_for_wallet_checks {
            PoiArtifactCacheFailureKind::RefreshDegraded
        } else {
            PoiArtifactCacheFailureKind::ServingCorpusUnavailable
        })
    }
}

type LocalPoiCacheMap = BTreeMap<FixedBytes<32>, PoiCache>;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PoiCorpusRevision {
    pub(crate) revision: u64,
    pub(crate) blocked_shields_revision: u64,
}

#[derive(Debug)]
struct LocalPoiCachesInner {
    caches: RwLock<LocalPoiCacheMap>,
    authority: Arc<PoiCorpusAuthority>,
    installed_generation: AtomicU64,
    committed_revision_tx: watch::Sender<PoiCorpusRevision>,
}

pub(crate) struct LocalPoiCachesReadGuard<'a> {
    caches: RwLockReadGuard<'a, LocalPoiCacheMap>,
    _access: OwnedRwLockReadGuard<()>,
}

impl Deref for LocalPoiCachesReadGuard<'_> {
    type Target = LocalPoiCacheMap;

    fn deref(&self) -> &Self::Target {
        &self.caches
    }
}

pub(crate) struct LocalPoiCachesWriteGuard<'a> {
    caches: RwLockWriteGuard<'a, LocalPoiCacheMap>,
    _access: OwnedRwLockReadGuard<()>,
}

impl Deref for LocalPoiCachesWriteGuard<'_> {
    type Target = LocalPoiCacheMap;

    fn deref(&self) -> &Self::Target {
        &self.caches
    }
}

impl DerefMut for LocalPoiCachesWriteGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.caches
    }
}

/// A generation-fenced handle to chain-local POI caches.
///
/// Clones share the cache map, its installed generation, and a monotonic
/// revision published only after a committed corpus install. Every guard
/// acquisition clears the map before exposing it if the database generation
/// has advanced.
#[derive(Debug, Clone)]
pub(crate) struct LocalPoiCaches {
    inner: Arc<LocalPoiCachesInner>,
}

impl LocalPoiCaches {
    #[must_use]
    pub(crate) fn new(authority: Arc<PoiCorpusAuthority>) -> Self {
        let installed_generation = authority.generation().load(Ordering::Acquire);
        let (committed_revision_tx, _) = watch::channel(PoiCorpusRevision::default());
        Self {
            inner: Arc::new(LocalPoiCachesInner {
                caches: RwLock::new(BTreeMap::new()),
                authority,
                installed_generation: AtomicU64::new(installed_generation),
                committed_revision_tx,
            }),
        }
    }

    pub(crate) async fn read(&self) -> LocalPoiCachesReadGuard<'_> {
        let access = self.inner.authority.read_access().await;
        let guard = self.inner.caches.read().await;
        if self.installed_generation() == self.current_generation() {
            return LocalPoiCachesReadGuard {
                caches: guard,
                _access: access,
            };
        }
        drop(guard);

        let mut guard = self.inner.caches.write().await;
        self.synchronize_locked(&mut guard);
        LocalPoiCachesReadGuard {
            caches: RwLockWriteGuard::downgrade(guard),
            _access: access,
        }
    }

    pub(crate) async fn write(&self) -> LocalPoiCachesWriteGuard<'_> {
        let access = self.inner.authority.read_access().await;
        let mut guard = self.inner.caches.write().await;
        self.synchronize_locked(&mut guard);
        LocalPoiCachesWriteGuard {
            caches: guard,
            _access: access,
        }
    }

    pub(crate) async fn synchronize_generation(&self) -> bool {
        let _access = self.inner.authority.read_access().await;
        if self.installed_generation() == self.current_generation() {
            return false;
        }
        let mut guard = self.inner.caches.write().await;
        self.synchronize_locked(&mut guard)
    }

    pub(crate) fn shared_generation(&self) -> &AtomicU64 {
        self.inner.authority.generation()
    }

    pub(crate) fn current_generation(&self) -> u64 {
        self.inner.authority.generation().load(Ordering::Acquire)
    }

    pub(crate) fn installed_generation(&self) -> u64 {
        self.inner.installed_generation.load(Ordering::Acquire)
    }

    pub(crate) fn mark_installed_generation(&self, generation: u64) {
        self.inner
            .installed_generation
            .store(generation, Ordering::Release);
    }

    #[must_use]
    pub(crate) fn committed_revision_rx(&self) -> watch::Receiver<PoiCorpusRevision> {
        self.inner.committed_revision_tx.subscribe()
    }

    pub(crate) fn publish_committed_revision(&self, blocked_shields_changed: bool) {
        self.inner.committed_revision_tx.send_modify(|revision| {
            revision.revision = revision.revision.wrapping_add(1).max(1);
            if blocked_shields_changed {
                revision.blocked_shields_revision =
                    revision.blocked_shields_revision.wrapping_add(1).max(1);
            }
        });
    }

    pub(crate) async fn revision_read_fence(&self) -> OwnedRwLockReadGuard<()> {
        self.inner.authority.revision_read_access().await
    }

    pub(crate) async fn revision_write_fence(&self) -> OwnedRwLockWriteGuard<()> {
        self.inner.authority.revision_write_access().await
    }

    fn synchronize_locked(&self, caches: &mut LocalPoiCacheMap) -> bool {
        let current_generation = self.current_generation();
        if self.installed_generation() == current_generation {
            return false;
        }
        caches.clear();
        self.mark_installed_generation(current_generation);
        true
    }
}

pub(crate) type WalletLocalPoiCaches = LocalPoiCaches;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoiArtifactSourceConfig {
    pub trusted_publisher_pubkey: FixedBytes<32>,
    pub manifest_source: PoiArtifactManifestSource,
    pub gateway_urls: Vec<SensitiveUrl>,
    pub max_manifest_age: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoiArtifactManifestSource {
    Url(SensitiveUrl),
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
        rpc_url: SensitiveUrl,
        wallet_read_fallback: PoiProxyFallback,
    },
    PoiProxy {
        rpc_url: SensitiveUrl,
    },
}

impl GlobalPoiPolicy {
    #[must_use]
    pub const fn rpc_url(&self) -> &SensitiveUrl {
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

    pub(crate) const fn should_skip_merkle_artifact_catch_up(
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
    #[must_use]
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
                ])?,
                quick_sync_endpoint: Some(
                    Url::parse("https://rail-squid.squids.live/squid-railgun-ethereum-v2/graphql")
                        .ok()?,
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
                ])?,
                quick_sync_endpoint: Some(
                    Url::parse("https://rail-squid.squids.live/squid-railgun-bsc-v2/graphql")
                        .ok()?,
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
                ])?,
                quick_sync_endpoint: Some(
                    Url::parse("https://rail-squid.squids.live/squid-railgun-polygon-v2/graphql")
                        .ok()?,
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
                ])?,
                quick_sync_endpoint: Some(
                    Url::parse("https://rail-squid.squids.live/squid-railgun-arbitrum-v2/graphql")
                        .ok()?,
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

fn default_rpc_urls(urls: &[&str]) -> Option<Vec<Url>> {
    urls.iter().map(|url| Url::parse(url).ok()).collect()
}

#[derive(Debug, Clone, Copy)]
pub enum WalletUtxoMutation<'a> {
    Preserve,
    Replace(&'a [WalletUtxo]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletCheckpointMutation {
    Preserve,
    Set {
        last_scanned_block: u64,
        last_scanned_block_hash: Option<[u8; 32]>,
    },
}

pub struct WalletPrivateCommit<'a> {
    wallet_id: &'a WalletCacheKey,
    chain_id: u64,
    utxos: WalletUtxoMutation<'a>,
    checkpoint: WalletCheckpointMutation,
    sync_actor_state: Option<&'a WalletSyncActorStateRecord>,
    pending_output_context_updates: &'a [PendingOutputPoiContextRecord],
    pending_output_context_deletes: &'a [FixedBytes<32>],
    output_poi_recovery_updates: &'a [OutputPoiRecoveryRecord],
    output_poi_recovery_deletes: &'a [FixedBytes<32>],
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
        debug_assert_eq!(permit.wallet_id().as_str(), state.wallet_id.as_str());
        Self { state }
    }

    #[must_use]
    pub const fn state(&self) -> &WalletSyncActorStateRecord {
        self.state
    }
}

impl<'a> WalletPrivateCommit<'a> {
    pub(crate) const fn new(
        _token: &crate::wallet::WalletActorCommitToken<'_>,
        permit: &'a crate::wallet::WalletPrivateMutationPermit<'_>,
        utxos: WalletUtxoMutation<'a>,
        checkpoint: WalletCheckpointMutation,
    ) -> Self {
        Self {
            wallet_id: permit.wallet_id(),
            chain_id: permit.chain_id(),
            utxos,
            checkpoint,
            sync_actor_state: None,
            pending_output_context_updates: &[],
            pending_output_context_deletes: &[],
            output_poi_recovery_updates: &[],
            output_poi_recovery_deletes: &[],
        }
    }

    #[must_use]
    pub const fn wallet_id(&self) -> &WalletCacheKey {
        self.wallet_id
    }

    #[must_use]
    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }

    #[must_use]
    pub const fn utxo_mutation(&self) -> WalletUtxoMutation<'a> {
        self.utxos
    }

    #[must_use]
    pub const fn checkpoint_mutation(&self) -> WalletCheckpointMutation {
        self.checkpoint
    }

    #[must_use]
    pub const fn with_pending_output_context_updates(
        mut self,
        updates: &'a [PendingOutputPoiContextRecord],
    ) -> Self {
        self.pending_output_context_updates = updates;
        self
    }

    #[must_use]
    pub const fn with_pending_output_context_deletes(
        mut self,
        deletes: &'a [FixedBytes<32>],
    ) -> Self {
        self.pending_output_context_deletes = deletes;
        self
    }

    #[must_use]
    pub const fn with_output_poi_recovery_updates(
        mut self,
        updates: &'a [OutputPoiRecoveryRecord],
    ) -> Self {
        self.output_poi_recovery_updates = updates;
        self
    }

    #[must_use]
    pub const fn with_output_poi_recovery_deletes(mut self, deletes: &'a [FixedBytes<32>]) -> Self {
        self.output_poi_recovery_deletes = deletes;
        self
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

    #[must_use]
    pub const fn output_poi_recovery_deletes(&self) -> &[FixedBytes<32>] {
        self.output_poi_recovery_deletes
    }

    pub fn validate_namespace(&self) -> Result<(), WalletCacheError> {
        for (chain_id, wallet_id) in self
            .pending_output_context_updates
            .iter()
            .map(|record| (record.chain_id, record.wallet_id.as_str()))
            .chain(
                self.output_poi_recovery_updates
                    .iter()
                    .map(|record| (record.chain_id, record.wallet_id.as_str())),
            )
        {
            if chain_id != self.chain_id || wallet_id != self.wallet_id.as_str() {
                return Err(DbError::InvalidWalletPrivateCommitNamespace {
                    expected_chain_id: self.chain_id,
                    expected_wallet_id: self.wallet_id.to_string(),
                    actual_chain_id: chain_id,
                    actual_wallet_id: wallet_id.to_owned(),
                }
                .into());
            }
        }
        if let Some(state) = self.sync_actor_state
            && (state.chain_id != self.chain_id || state.wallet_id != self.wallet_id.as_str())
        {
            return Err(DbError::InvalidWalletPrivateCommitNamespace {
                expected_chain_id: self.chain_id,
                expected_wallet_id: self.wallet_id.to_string(),
                actual_chain_id: state.chain_id,
                actual_wallet_id: state.wallet_id.clone(),
            }
            .into());
        }
        Ok(())
    }
}

pub trait WalletCacheStore: Send + Sync {
    fn commit_wallet_private_state(
        &self,
        commit: WalletPrivateCommit<'_>,
    ) -> Result<(), WalletCacheError>;

    fn load_wallet_utxos(
        &self,
        wallet_id: &WalletCacheKey,
    ) -> Result<Vec<WalletUtxo>, WalletCacheError>;

    fn get_wallet_meta(
        &self,
        wallet_id: &WalletCacheKey,
    ) -> Result<Option<WalletMeta>, WalletCacheError>;

    fn get_wallet_sync_actor_state(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
    ) -> Result<Option<WalletSyncActorStateRecord>, WalletCacheError>;

    fn put_wallet_sync_actor_state(
        &self,
        commit: WalletSyncActorStateCommit<'_>,
    ) -> Result<(), WalletCacheError>;

    fn get_pending_output_poi_context(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
        output_commitment: &FixedBytes<32>,
    ) -> Result<Option<PendingOutputPoiContextRecord>, WalletCacheError>;

    fn list_pending_output_poi_contexts(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
    ) -> Result<Vec<PendingOutputPoiContextRecord>, WalletCacheError>;

    fn get_output_poi_recovery(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
        output_commitment: &FixedBytes<32>,
    ) -> Result<Option<OutputPoiRecoveryRecord>, WalletCacheError>;

    fn list_output_poi_recoveries(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
    ) -> Result<Vec<OutputPoiRecoveryRecord>, WalletCacheError>;
}

impl WalletCacheStore for DbStore {
    fn commit_wallet_private_state(
        &self,
        commit: WalletPrivateCommit<'_>,
    ) -> Result<(), WalletCacheError> {
        commit.validate_namespace()?;
        let utxo_entries = match commit.utxo_mutation() {
            WalletUtxoMutation::Preserve => None,
            WalletUtxoMutation::Replace(utxos) => Some(wallet_utxo_entries(utxos)?),
        };
        let meta = match commit.checkpoint_mutation() {
            WalletCheckpointMutation::Preserve => None,
            WalletCheckpointMutation::Set {
                last_scanned_block,
                last_scanned_block_hash,
            } => Some(WalletMeta {
                last_scanned_block,
                updated_at: wallet_cache_now_epoch_secs()?,
                last_scanned_block_hash,
            }),
        };
        let namespace =
            WalletPrivateNamespaceId::new(commit.chain_id(), commit.wallet_id().clone());
        migrate_db_store_wallet_private_v1_rows(self, &namespace)?;
        let pending_output_context_updates = commit
            .pending_output_context_updates()
            .iter()
            .map(pending_output_context_opaque_row)
            .collect::<Result<Vec<_>, WalletCacheError>>()?;
        let pending_output_context_deletes = commit
            .pending_output_context_deletes()
            .iter()
            .map(|commitment| commitment.to_vec())
            .collect::<Vec<_>>();
        let output_poi_recovery_updates = commit
            .output_poi_recovery_updates()
            .iter()
            .map(output_poi_recovery_opaque_row)
            .collect::<Result<Vec<_>, WalletCacheError>>()?;
        let output_poi_recovery_deletes = commit
            .output_poi_recovery_deletes()
            .iter()
            .map(|commitment| commitment.to_vec())
            .collect::<Vec<_>>();
        self.batch_commit_wallet_private_state(&WalletPrivateStateBatch {
            namespace: &namespace,
            utxos: utxo_entries.as_deref().map_or(
                WalletUtxoRowMutation::Preserve,
                WalletUtxoRowMutation::Replace,
            ),
            metadata: meta
                .as_ref()
                .map_or(WalletMetaMutation::Preserve, WalletMetaMutation::Set),
            sync_actor_state: commit.sync_actor_state(),
            pending_output_contexts: OpaqueWalletPrivateRowMutation {
                updates: &pending_output_context_updates,
                deletes: &pending_output_context_deletes,
            },
            output_poi_recoveries: OpaqueWalletPrivateRowMutation {
                updates: &output_poi_recovery_updates,
                deletes: &output_poi_recovery_deletes,
            },
        })?;
        Ok(())
    }

    fn load_wallet_utxos(
        &self,
        wallet_id: &WalletCacheKey,
    ) -> Result<Vec<WalletUtxo>, WalletCacheError> {
        WalletCacheDbExt::load_wallet_utxos(self, wallet_id)
    }

    fn get_wallet_meta(
        &self,
        wallet_id: &WalletCacheKey,
    ) -> Result<Option<WalletMeta>, WalletCacheError> {
        Ok(Self::get_wallet_meta(self, wallet_id)?)
    }

    fn get_wallet_sync_actor_state(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
    ) -> Result<Option<WalletSyncActorStateRecord>, WalletCacheError> {
        Ok(Self::get_wallet_sync_actor_state(
            self,
            chain_id,
            wallet_id.as_str(),
        )?)
    }

    fn put_wallet_sync_actor_state(
        &self,
        commit: WalletSyncActorStateCommit<'_>,
    ) -> Result<(), WalletCacheError> {
        Ok(Self::put_wallet_sync_actor_state(self, commit.state())?)
    }

    fn get_pending_output_poi_context(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
        output_commitment: &FixedBytes<32>,
    ) -> Result<Option<PendingOutputPoiContextRecord>, WalletCacheError> {
        Ok(Self::get_pending_output_poi_context(
            self,
            chain_id,
            wallet_id.as_str(),
            output_commitment,
        )?)
    }

    fn list_pending_output_poi_contexts(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
    ) -> Result<Vec<PendingOutputPoiContextRecord>, WalletCacheError> {
        Ok(Self::list_pending_output_poi_contexts(
            self,
            chain_id,
            wallet_id.as_str(),
        )?)
    }

    fn get_output_poi_recovery(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
        output_commitment: &FixedBytes<32>,
    ) -> Result<Option<OutputPoiRecoveryRecord>, WalletCacheError> {
        Ok(Self::get_output_poi_recovery(
            self,
            chain_id,
            wallet_id.as_str(),
            output_commitment,
        )?)
    }

    fn list_output_poi_recoveries(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
    ) -> Result<Vec<OutputPoiRecoveryRecord>, WalletCacheError> {
        Ok(Self::list_output_poi_recoveries(
            self,
            chain_id,
            wallet_id.as_str(),
        )?)
    }
}

fn pending_output_context_opaque_row(
    record: &PendingOutputPoiContextRecord,
) -> Result<OpaqueWalletPrivateRow, WalletCacheError> {
    Ok(OpaqueWalletPrivateRow {
        row_id: record.output_commitment.to_vec(),
        payload: rmp_serde::to_vec_named(record)?,
    })
}

fn migrate_db_store_wallet_private_v1_rows(
    db: &DbStore,
    namespace: &WalletPrivateNamespaceId,
) -> Result<(), WalletCacheError> {
    let sources = db.list_wallet_private_v1_rows(namespace)?;
    if sources.pending_output_contexts.is_empty() && sources.output_poi_recoveries.is_empty() {
        return Ok(());
    }
    let pending_output_context_destinations = sources
        .pending_output_contexts
        .iter()
        .map(|source| {
            let record: PendingOutputPoiContextRecord = rmp_serde::from_slice(&source.payload)?;
            if record.chain_id != namespace.chain_id
                || record.wallet_id != namespace.wallet_id.as_str()
            {
                return Err(WalletCacheError::Crypto);
            }
            pending_output_context_opaque_row(&record)
        })
        .collect::<Result<Vec<_>, WalletCacheError>>()?;
    let output_poi_recovery_destinations = sources
        .output_poi_recoveries
        .iter()
        .map(|source| {
            let record: OutputPoiRecoveryRecord = rmp_serde::from_slice(&source.payload)?;
            if record.chain_id != namespace.chain_id
                || record.wallet_id != namespace.wallet_id.as_str()
            {
                return Err(WalletCacheError::Crypto);
            }
            output_poi_recovery_opaque_row(&record)
        })
        .collect::<Result<Vec<_>, WalletCacheError>>()?;
    db.migrate_wallet_private_v1_rows(&WalletPrivateV1MigrationBatch {
        namespace,
        pending_output_context_sources: &sources.pending_output_contexts,
        pending_output_context_destinations: &pending_output_context_destinations,
        output_poi_recovery_sources: &sources.output_poi_recoveries,
        output_poi_recovery_destinations: &output_poi_recovery_destinations,
    })?;
    Ok(())
}

fn output_poi_recovery_opaque_row(
    record: &OutputPoiRecoveryRecord,
) -> Result<OpaqueWalletPrivateRow, WalletCacheError> {
    Ok(OpaqueWalletPrivateRow {
        row_id: record.output_commitment.to_vec(),
        payload: rmp_serde::to_vec_named(record)?,
    })
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
    pub cache_key: WalletCacheKey,
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

#[derive(Debug, Clone)]
pub struct PendingOutputPoiContextIntent {
    pub txid_version: String,
    pub output_commitment: FixedBytes<32>,
    pub output_npk: FixedBytes<32>,
    pub utxo_tree_in: u64,
    pub railgun_txid: U256,
    pub pre_transaction_pois_per_txid_leaf_per_list:
        BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PreTxPoi>>,
    pub required_poi_list_keys: Vec<FixedBytes<32>>,
    pub output_role: PendingOutputPoiRole,
}

impl PendingOutputPoiContextIntent {
    pub(crate) fn into_record(
        self,
        chain_id: u64,
        wallet_id: String,
        created_at: u64,
    ) -> PendingOutputPoiContextRecord {
        PendingOutputPoiContextRecord {
            chain_id,
            wallet_id,
            txid_version: self.txid_version,
            output_commitment: self.output_commitment,
            output_npk: self.output_npk,
            utxo_tree_in: self.utxo_tree_in,
            railgun_txid: self.railgun_txid,
            txid_merkleroot_index: None,
            pre_transaction_pois_per_txid_leaf_per_list: self
                .pre_transaction_pois_per_txid_leaf_per_list,
            required_poi_list_keys: self.required_poi_list_keys,
            output_role: self.output_role,
            created_at,
            source_operation_id: None,
            observation: None,
            submitted_poi_list_keys: Vec::new(),
            terminal_error: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WalletPrivateRequestError {
    #[error("wallet actor is inactive")]
    Inactive,
    #[error("wallet reset is pending")]
    ResetPending,
    #[error("wallet private request is stale")]
    StaleView,
    #[error("wallet private request persistence failed")]
    PersistenceFailed,
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

#[derive(Debug, Clone)]
pub(crate) enum WalletScanRowsPayload {
    Rows(Box<WalletScanInputRows>),
    EmptyCoverage,
    #[cfg(test)]
    IndexedDeltaForTest {
        delta: Box<railgun_wallet::scan::WalletLogDelta>,
    },
}

#[derive(Debug, Clone)]
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
    pub(crate) const fn covers(&self, from_block: u64, to_block: u64) -> bool {
        self.from_block == from_block
            && self.to_block == to_block
            && match &self.payload {
                WalletScanRowsPayload::Rows(_) | WalletScanRowsPayload::EmptyCoverage => true,
                #[cfg(test)]
                WalletScanRowsPayload::IndexedDeltaForTest { .. } => true,
            }
    }
}

#[derive(Debug, Clone)]
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
        batch: &SharedLogBatch,
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
    pub(crate) const fn empty_coverage(
        from_block: u64,
        to_block: u64,
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
                WalletScanRowsPayload::EmptyCoverage,
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

#[derive(Debug, PartialEq, Eq)]
pub enum WalletBackfillStartResult {
    Accepted {
        committed_to: u64,
        target_block: u64,
        grant: WalletBackfillGrant,
    },
    Rejected {
        committed_to: u64,
        reason: WalletBackfillRejectReason,
    },
}

impl WalletBackfillStartResult {
    #[must_use]
    pub const fn committed_to(&self) -> u64 {
        match self {
            Self::Accepted { committed_to, .. } | Self::Rejected { committed_to, .. } => {
                *committed_to
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletBackfillFinishResult {
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
            Self::Ready { committed_to } | Self::Rejected { committed_to, .. } => *committed_to,
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
    pub stable_identity: Option<Vec<u8>>,
    pub tx_hash: Option<FixedBytes<32>>,
    pub block_number: Option<u64>,
    pub block_timestamp: Option<u64>,
}

impl WalletPendingSpent {
    #[must_use]
    pub const fn key(&self) -> (u32, u64) {
        (self.tree, self.position)
    }

    #[must_use]
    pub const fn from_source(
        utxo: &railgun_wallet::Utxo,
        source: &railgun_wallet::UtxoSource,
    ) -> Self {
        Self {
            tree: utxo.tree,
            position: utxo.position,
            stable_identity: None,
            tx_hash: Some(source.tx_hash),
            block_number: Some(source.block_number),
            block_timestamp: Some(source.block_timestamp),
        }
    }

    #[must_use]
    pub(crate) fn submitted(
        utxo: &railgun_wallet::Utxo,
        tx_hash: Option<FixedBytes<32>>,
        now: u64,
    ) -> Self {
        let wallet_utxo = railgun_wallet::WalletUtxo::new(utxo.clone());
        Self {
            tree: utxo.tree,
            position: utxo.position,
            stable_identity: Some(railgun_wallet::wallet_cache::wallet_utxo_stable_identity(
                &wallet_utxo,
            )),
            tx_hash,
            block_number: None,
            block_timestamp: Some(now),
        }
    }

    #[must_use]
    pub fn matches_local_utxo(&self, utxo: &railgun_wallet::WalletUtxo) -> bool {
        self.key() == (utxo.utxo.tree, utxo.utxo.position)
            && self.stable_identity.as_ref()
                == Some(&railgun_wallet::wallet_cache::wallet_utxo_stable_identity(
                    utxo,
                ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletPendingSpentMarkOutcome {
    Marked,
    AlreadyProtected,
}

/// Coherent current private wallet projection (only valid when not reset-pending).
///
/// Includes confirmed UTXOs and pending tip overlay. Published atomically inside
/// [`WalletObservation`]; public observers must not read live mirrors.
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

/// Generation-scoped public progress taken from one [`WalletObservation`].
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletInactiveReason {
    Shutdown,
    Retired,
}

/// Private-view and terminal session state carried by [`WalletObservation`].
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
    Inactive {
        reason: WalletInactiveReason,
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
            (
                Self::Inactive {
                    reason: left_reason,
                    reset_generation: left_generation,
                },
                Self::Inactive {
                    reason: right_reason,
                    reset_generation: right_generation,
                },
            ) => left_reason == right_reason && left_generation == right_generation,
            _ => false,
        }
    }
}

impl Eq for WalletViewState {}

impl WalletViewState {
    #[must_use]
    pub const fn is_current(&self) -> bool {
        matches!(self, Self::Current(_))
    }

    #[must_use]
    pub const fn inactive_reason(&self) -> Option<WalletInactiveReason> {
        match self {
            Self::Inactive { reason, .. } => Some(*reason),
            Self::Current(_) | Self::ResetPending { .. } => None,
        }
    }

    #[must_use]
    pub fn current_snapshot(&self) -> Option<Arc<WalletCurrentSnapshot>> {
        match self {
            Self::Current(snapshot) => Some(Arc::clone(snapshot)),
            Self::ResetPending { .. } | Self::Inactive { .. } => None,
        }
    }

    #[must_use]
    pub fn last_scanned_current(&self) -> Option<u64> {
        match self {
            Self::Current(snapshot) => Some(snapshot.last_scanned),
            Self::ResetPending { .. } | Self::Inactive { .. } => None,
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
            Self::ResetPending { .. } | Self::Inactive { .. } => None,
        }
    }

    #[must_use]
    pub fn reset_generation(&self) -> u64 {
        match self {
            Self::Current(snapshot) => snapshot.reset_generation,
            Self::ResetPending {
                reset_generation, ..
            }
            | Self::Inactive {
                reset_generation, ..
            } => *reset_generation,
        }
    }
}

/// Status of the `CommitResetRewind` transition after `AcceptReset` has already succeeded
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
/// **Invariant:** once `AcceptReset` has durably succeeded, the result is always
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

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WalletReadinessError {
    #[error("wallet backfill is unavailable")]
    BackfillUnavailable,
    #[error("wallet sync target {target_block} was not reached")]
    TargetNotReached { target_block: u64 },
    #[error("wallet sync state could not be persisted")]
    PersistenceFailed,
    #[error("wallet sync update could not be applied")]
    ApplyFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WalletReadinessWaitError {
    #[error("wallet readiness failed: {0}")]
    Failed(#[source] WalletReadinessError),
    #[error("wallet sync shut down before becoming ready")]
    Shutdown,
    #[error("wallet observation channel closed before becoming ready")]
    ChannelClosed,
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

/// Privacy-safe aggregate of sender-created pending-output PPOI work.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WalletPpoiWorkflowStatus {
    pub awaiting_submission: u64,
    pub awaiting_validation: u64,
    pub needs_attention: u64,
    pub validation_revision: u64,
}

impl WalletPpoiWorkflowStatus {
    #[must_use]
    pub const fn has_outstanding(&self) -> bool {
        self.awaiting_submission > 0 || self.awaiting_validation > 0 || self.needs_attention > 0
    }

    #[must_use]
    pub const fn cleared(self) -> Self {
        Self {
            awaiting_submission: 0,
            awaiting_validation: 0,
            needs_attention: 0,
            validation_revision: self.validation_revision,
        }
    }
}

/// One authoritative public observation of a wallet actor's private projection and readiness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletObservation {
    view: WalletViewState,
    readiness: WalletReadiness,
    ppoi_workflow_status: WalletPpoiWorkflowStatus,
}

impl WalletObservation {
    pub(crate) fn new(view: WalletViewState, readiness: WalletReadiness) -> Self {
        Self::with_ppoi_workflow_status(view, readiness, WalletPpoiWorkflowStatus::default())
    }

    pub(crate) fn with_ppoi_workflow_status(
        view: WalletViewState,
        readiness: WalletReadiness,
        ppoi_workflow_status: WalletPpoiWorkflowStatus,
    ) -> Self {
        assert_eq!(
            matches!(&view, WalletViewState::Inactive { .. }),
            readiness == WalletReadiness::Shutdown
        );
        assert!(
            !matches!(&view, WalletViewState::ResetPending { .. })
                || readiness != WalletReadiness::Ready
        );
        Self {
            view,
            readiness,
            ppoi_workflow_status,
        }
    }

    #[must_use]
    pub const fn view(&self) -> &WalletViewState {
        &self.view
    }

    #[must_use]
    pub const fn readiness(&self) -> &WalletReadiness {
        &self.readiness
    }

    #[must_use]
    pub const fn ppoi_workflow_status(&self) -> &WalletPpoiWorkflowStatus {
        &self.ppoi_workflow_status
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
    pub(crate) const fn mint(
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
    pub(crate) const fn mint(authority: WalletActorTokenAuthority<'_>, intent_id: u64) -> Self {
        Self {
            chain_id: authority.chain_id(),
            actor_id: authority.actor_id(),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WalletBackfillOwnerDisposition {
    BenignRetirement,
    DriverLost,
}

#[derive(Debug)]
pub(crate) struct WalletBackfillOwnerSignal {
    pub(crate) disposition: WalletBackfillOwnerDisposition,
    pub(crate) acknowledgement: Option<oneshot::Sender<()>>,
}

#[derive(Debug)]
struct WalletBackfillOwner {
    token: WalletSyncToken,
    sender: mpsc::Sender<BackfillEvent>,
    liveness: oneshot::Sender<WalletBackfillOwnerSignal>,
}

impl WalletBackfillOwner {
    fn signal(
        self,
        disposition: WalletBackfillOwnerDisposition,
        acknowledgement: Option<oneshot::Sender<()>>,
    ) {
        let _ = self.liveness.send(WalletBackfillOwnerSignal {
            disposition,
            acknowledgement,
        });
    }
}

/// An actor-accepted backfill job that has not yet been activated by a driver.
/// Dropping a grant is benign cancellation.
#[derive(Debug)]
pub struct WalletBackfillGrant {
    inner: Option<WalletBackfillOwner>,
}

/// Actor-owned readiness target held across staged public-source work.
#[derive(Debug)]
pub(crate) struct WalletSyncTargetLease {
    owner: Option<WalletBackfillOwner>,
}

impl WalletSyncTargetLease {
    pub(crate) const fn for_actor_accepted_job(
        token: WalletSyncToken,
        sender: mpsc::Sender<BackfillEvent>,
        liveness: oneshot::Sender<WalletBackfillOwnerSignal>,
    ) -> Self {
        Self {
            owner: Some(WalletBackfillOwner {
                token,
                sender,
                liveness,
            }),
        }
    }
}

impl Drop for WalletSyncTargetLease {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.take() {
            owner.signal(WalletBackfillOwnerDisposition::BenignRetirement, None);
        }
    }
}

impl PartialEq for WalletBackfillGrant {
    fn eq(&self, other: &Self) -> bool {
        self.token() == other.token()
    }
}

impl Eq for WalletBackfillGrant {}

impl WalletBackfillGrant {
    pub(crate) const fn for_actor_accepted_job(
        token: WalletSyncToken,
        sender: mpsc::Sender<BackfillEvent>,
        liveness: oneshot::Sender<WalletBackfillOwnerSignal>,
    ) -> Self {
        Self {
            inner: Some(WalletBackfillOwner {
                token,
                sender,
                liveness,
            }),
        }
    }

    pub(crate) const fn token(&self) -> WalletSyncToken {
        self.inner
            .as_ref()
            .expect("backfill grant is present")
            .token
    }

    #[must_use]
    pub(crate) fn activate(mut self) -> WalletBackfillDriver {
        WalletBackfillDriver {
            inner: self.inner.take(),
        }
    }
}

impl Drop for WalletBackfillGrant {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            inner.signal(WalletBackfillOwnerDisposition::BenignRetirement, None);
        }
    }
}

/// Unique owner of an activated actor backfill job.
/// Dropping it without actor completion or explicit retirement reports driver loss.
#[derive(Debug)]
pub struct WalletBackfillDriver {
    inner: Option<WalletBackfillOwner>,
}

impl PartialEq for WalletBackfillDriver {
    fn eq(&self, other: &Self) -> bool {
        self.token() == other.token()
    }
}

impl Eq for WalletBackfillDriver {}

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

impl WalletBackfillDriver {
    const fn inner(&self) -> &WalletBackfillOwner {
        self.inner.as_ref().expect("backfill driver is present")
    }

    pub(crate) const fn token(&self) -> WalletSyncToken {
        self.inner().token
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

    pub(crate) const fn sender(&self) -> &mpsc::Sender<BackfillEvent> {
        &self.inner().sender
    }

    pub(crate) async fn apply(
        &self,
        cache_key: &str,
        apply: WalletScanApply,
    ) -> WalletBackfillApplyResult {
        let requested_to = apply.to_block;
        let (response, result_rx) = oneshot::channel();
        if let Err(err) = self
            .sender()
            .send(BackfillEvent::Apply {
                apply,
                token: self.token(),
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
            .sender()
            .send(BackfillEvent::Finish {
                target_block,
                token: self.token(),
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

    pub(crate) async fn retire(mut self, _cache_key: &str) {
        if let Some(inner) = self.inner.take() {
            let (acknowledgement, acknowledged) = oneshot::channel();
            inner.signal(
                WalletBackfillOwnerDisposition::BenignRetirement,
                Some(acknowledgement),
            );
            let _ = acknowledged.await;
        }
    }

    pub(crate) async fn fail(self, cache_key: &str, reason: WalletReadinessError) {
        let (response, result_rx) = oneshot::channel();
        if let Err(err) = self
            .sender()
            .send(BackfillEvent::JobFailed {
                token: self.token(),
                reason,
                response,
            })
            .await
        {
            warn!(?err, cache_key, "failed to send wallet job failure");
            return;
        }
        if let Err(err) = result_rx.await {
            warn!(?err, cache_key, "wallet job failure response dropped");
        }
    }
}

impl Drop for WalletBackfillDriver {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            inner.signal(WalletBackfillOwnerDisposition::DriverLost, None);
        }
    }
}

#[derive(Debug)]
pub(crate) enum BackfillEvent {
    #[cfg(test)]
    PanicForTest,
    ReserveTarget {
        target_block: u64,
        token: WalletSyncToken,
        response: oneshot::Sender<Result<WalletSyncTargetLease, WalletBackfillRejectReason>>,
    },
    Start {
        target_block: u64,
        token: WalletSyncToken,
        response: oneshot::Sender<WalletBackfillStartResult>,
    },
    Apply {
        apply: WalletScanApply,
        token: WalletSyncToken,
        response: oneshot::Sender<WalletBackfillApplyResult>,
    },
    Finish {
        target_block: u64,
        token: WalletSyncToken,
        response: oneshot::Sender<WalletBackfillFinishResult>,
    },
    JobFailed {
        token: WalletSyncToken,
        reason: WalletReadinessError,
        response: oneshot::Sender<()>,
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
        acquisition_range: Option<(u64, u64)>,
        driver: WalletBackfillDriver,
    },
    Remove {
        cache_key: String,
        actor_id: u64,
    },
}

impl BackfillRequest {
    pub(crate) fn add(
        cache_key: impl Into<String>,
        from_block: u64,
        to_block: u64,
        follow_safe_head: bool,
        progress_start_block: u64,
        driver: WalletBackfillDriver,
    ) -> Self {
        Self::Add {
            cache_key: cache_key.into(),
            from_block,
            to_block,
            follow_safe_head,
            progress_start_block,
            acquisition_range: None,
            driver,
        }
    }

    pub(crate) fn add_with_acquisition(
        cache_key: impl Into<String>,
        from_block: u64,
        to_block: u64,
        follow_safe_head: bool,
        progress_start_block: u64,
        acquisition_range: (u64, u64),
        driver: WalletBackfillDriver,
    ) -> Self {
        Self::Add {
            cache_key: cache_key.into(),
            from_block,
            to_block,
            follow_safe_head,
            progress_start_block,
            acquisition_range: Some(acquisition_range),
            driver,
        }
    }
}

#[cfg(test)]
impl LocalPoiCaches {
    #[must_use]
    pub(crate) fn new_for_test(caches: BTreeMap<FixedBytes<32>, PoiCache>) -> Self {
        let initial_revision = u64::from(!caches.is_empty());
        let initial_revision = PoiCorpusRevision {
            revision: initial_revision,
            blocked_shields_revision: initial_revision,
        };
        let (committed_revision_tx, _) = watch::channel(initial_revision);
        Self {
            inner: Arc::new(LocalPoiCachesInner {
                caches: RwLock::new(caches),
                authority: Arc::new(PoiCorpusAuthority::new(0)),
                installed_generation: AtomicU64::new(0),
                committed_revision_tx,
            }),
        }
    }

    pub(crate) fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

#[cfg(test)]
impl WalletScanApply {
    #[must_use]
    pub(crate) fn indexed_delta_for_test(
        from_block: u64,
        to_block: u64,
        delta: railgun_wallet::scan::WalletLogDelta,
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

#[cfg(test)]
impl WalletSyncToken {
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
}

#[cfg(test)]
impl WalletResetToken {
    #[must_use]
    pub(crate) const fn for_test(chain_id: u64, actor_id: u64, intent_id: u64) -> Self {
        Self {
            chain_id,
            actor_id,
            intent_id,
        }
    }
}

#[cfg(test)]
impl WalletSyncTargetLease {
    pub(crate) const fn token(&self) -> WalletSyncToken {
        self.owner.as_ref().expect("target lease is present").token
    }
}

#[cfg(test)]
impl WalletBackfillGrant {
    pub(crate) fn from_token(token: WalletSyncToken, sender: mpsc::Sender<BackfillEvent>) -> Self {
        let (liveness, _receiver) = oneshot::channel();
        Self::for_actor_accepted_job(token, sender, liveness)
    }
}

#[cfg(test)]
impl WalletBackfillDriver {
    pub(crate) fn from_token(token: WalletSyncToken, sender: mpsc::Sender<BackfillEvent>) -> Self {
        WalletBackfillGrant::from_token(token, sender).activate()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        ChainConfigDefaults, GlobalPoiPolicy, LocalPoiCaches, PoiArtifactCacheFailureKind,
        PoiArtifactCacheGraphProgress, PoiArtifactCachePhase, PoiArtifactCacheProgress,
        PoiArtifactManifestSource, PoiArtifactSourceConfig, PoiCorpusRevision, PoiProxyFallback,
        PublicScanSource, SyncProgressStage, SyncProgressUnit, SyncProgressUpdate,
    };
    use alloy::primitives::FixedBytes;
    use poi::SensitiveUrl;
    use url::Url;

    fn sentinel_url(label: &str) -> SensitiveUrl {
        Url::parse(&format!(
            "https://user-{label}:password-{label}@host-{label}.invalid/path-{label}?query={label}#fragment-{label}"
        ))
        .expect("sentinel URL")
        .into()
    }

    fn assert_no_endpoint_sentinels(formatted: &str) {
        for sentinel in ["rpc-sentinel", "manifest-sentinel", "gateway-sentinel"] {
            assert!(
                !formatted.contains(sentinel),
                "endpoint leaked {sentinel}: {formatted}"
            );
        }
    }

    #[test]
    fn poi_policy_and_nested_artifact_debug_are_endpoint_safe() {
        let artifact_source = PoiArtifactSourceConfig {
            trusted_publisher_pubkey: FixedBytes::from([0x42; 32]),
            manifest_source: PoiArtifactManifestSource::Url(sentinel_url("manifest-sentinel")),
            gateway_urls: vec![sentinel_url("gateway-sentinel")],
            max_manifest_age: Some(std::time::Duration::from_mins(1)),
        };
        let indexed = GlobalPoiPolicy::IndexedArtifacts {
            artifact_source: artifact_source.clone(),
            rpc_url: sentinel_url("rpc-sentinel"),
            wallet_read_fallback: PoiProxyFallback::OnCorpusUnavailable,
        };
        let proxy = GlobalPoiPolicy::PoiProxy {
            rpc_url: sentinel_url("rpc-sentinel"),
        };

        assert_no_endpoint_sentinels(&format!("{artifact_source:?}"));
        assert_no_endpoint_sentinels(&format!("{indexed:?}"));
        assert_no_endpoint_sentinels(&format!("{proxy:?}"));
        assert_eq!(
            indexed.rpc_url(),
            match &indexed {
                GlobalPoiPolicy::IndexedArtifacts { rpc_url, .. } => rpc_url,
                GlobalPoiPolicy::PoiProxy { .. } => unreachable!(),
            }
        );
    }

    #[tokio::test]
    async fn poi_corpus_revision_publication_waits_for_readiness_fence() {
        let caches = LocalPoiCaches::new_for_test(BTreeMap::new());
        let revision_rx = caches.committed_revision_rx();
        let readiness_fence = caches.revision_read_fence().await;
        let write_fence = caches.revision_write_fence();
        tokio::pin!(write_fence);

        tokio::select! {
            biased;
            _ = &mut write_fence => panic!("corpus writer crossed readiness fence"),
            () = tokio::task::yield_now() => {}
        }
        assert_eq!(*revision_rx.borrow(), PoiCorpusRevision::default());

        drop(readiness_fence);
        let _write_fence = write_fence.await;
        caches.publish_committed_revision(true);

        assert_eq!(
            *revision_rx.borrow(),
            PoiCorpusRevision {
                revision: 1,
                blocked_shields_revision: 1,
            }
        );
    }

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
        assert_eq!(progress.source, None);
        assert_eq!(
            progress.with_source(PublicScanSource::Rpc).source,
            Some(PublicScanSource::Rpc)
        );
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
            attempt_id: super::PoiArtifactCacheAttemptId::new(1),
            generation: 7,
            chain_id: 1,
            phase: PoiArtifactCachePhase::LoadingPersisted,
            completed_lists: 0,
            total_lists: 0,
            current_list_key: None,
            current_event_index: None,
            target_event_index: None,
            list_progress: Vec::new(),
            graph: PoiArtifactCacheGraphProgress::default(),
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
            attempt_id: super::PoiArtifactCacheAttemptId::new(2),
            generation: 8,
            chain_id: 1,
            phase: PoiArtifactCachePhase::Ready,
            completed_lists: 1,
            total_lists: 1,
            current_list_key: None,
            current_event_index: None,
            target_event_index: None,
            list_progress: Vec::new(),
            graph: PoiArtifactCacheGraphProgress::default(),
            ready_for_wallet_checks: true,
            last_error: None,
        };
        let error = PoiArtifactCacheProgress {
            phase: PoiArtifactCachePhase::Failed,
            ready_for_wallet_checks: false,
            last_error: Some("failed".to_string()),
            ..ready.clone()
        };

        assert_eq!(ready.percent(), 100);
        assert!(ready.is_ready());
        assert!(error.is_error());
        assert!(!error.is_active());
        assert_eq!(
            error.failure_kind(),
            Some(PoiArtifactCacheFailureKind::ServingCorpusUnavailable)
        );
    }
}
