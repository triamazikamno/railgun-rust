use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::{Address, FixedBytes, U256};
use broadcaster_core::query_rpc_pool::QueryRpcPool;
use local_db::WalletCacheKey;
use poi::SensitiveUrl;
use railgun_wallet::ProverService;
use railgun_wallet::scan::WalletScanKeys;
use trustless_artifacts::GatewayPool;
use url::Url;

use crate::indexed_artifacts::{ChainScope, ChainType, IndexedArtifactManifestReuse};
use crate::poi_submission::PoiSubmissionRouteProvider;

use super::{SyncProgressSender, WalletCacheStore};

pub const DEFAULT_INDEXED_WALLET_BLOCK_RANGE: u64 = 100_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoiArtifactSourceConfig {
    pub trusted_publisher_pubkey: FixedBytes<32>,
    pub manifest_source: PoiArtifactManifestSource,
    pub gateway_urls: Vec<SensitiveUrl>,
    pub gateway_pool: Option<GatewayPool>,
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
    pub fn with_optional_gateway_pool(self, gateway_pool: Option<GatewayPool>) -> Self {
        match gateway_pool {
            Some(pool) => self.with_gateway_pool(pool),
            None => self,
        }
    }

    #[must_use]
    pub fn with_gateway_pool(mut self, gateway_pool: GatewayPool) -> Self {
        if let Self::IndexedArtifacts {
            artifact_source, ..
        } = &mut self
        {
            artifact_source.gateway_pool = Some(gateway_pool);
        }
        self
    }

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
    pub gateway_pool: Option<GatewayPool>,
    /// Shared by clones, so consumers built from one session's config reuse verified manifests.
    /// Runtime cache state, excluded from configuration equality.
    pub manifest_reuse: IndexedArtifactManifestReuse,
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
    pub deployment: broadcaster_core::deployment::RailgunDeployment,
    pub sync: RailgunSyncOptions,
    pub rpcs: Arc<QueryRpcPool>,
    pub archive_rpc_url: Option<Url>,
    /// Transport for the archive endpoint. `None` uses the client the chain
    /// was added with, or `http_client`.
    pub archive_rpc_http_client: Option<reqwest::Client>,
    pub block_time: Duration,
    pub finality_depth: u64,
    /// Caller-configured transport for quick-sync and other internal HTTP requests.
    pub http_client: reqwest::Client,
    pub progress_tx: Option<SyncProgressSender>,
    /// Opens one isolated route per Railgun transaction for PPOI submissions,
    /// which the manager's submission scheduler then spaces. `None` sends them
    /// through `http_client` without spacing.
    pub poi_submission_routes: Option<Arc<dyn PoiSubmissionRouteProvider>>,
}

impl ChainConfig {
    pub(crate) const fn indexed_artifact_scope(&self) -> ChainScope {
        ChainScope {
            chain_type: ChainType::Evm,
            chain_id: self.deployment.chain_id,
            railgun_contract: self.deployment.contract,
        }
    }

    /// Whether the Merkle forest tail from `from_block` to `safe_head` is left
    /// to live RPC sync instead of indexed catch-up, whichever indexed sources
    /// are configured: it spans at most one `block_range` page, or is empty,
    /// including when no safe head is known.
    pub(crate) const fn should_skip_indexed_forest_catch_up(
        &self,
        from_block: u64,
        safe_head: u64,
    ) -> bool {
        from_block > safe_head
            || safe_head.saturating_sub(from_block).saturating_add(1) <= self.sync.block_range
    }
}

/// Resolved synchronization policy, independent of deployment identity and EVM defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RailgunSyncOptions {
    pub archive_until_block: u64,
    pub block_range: u64,
    pub indexed_wallet_block_range: u64,
    pub poll_interval: Duration,
    pub quick_sync_endpoint: Option<Url>,
    pub indexed_artifact_source: Option<IndexedArtifactSourceConfig>,
    pub anchor_interval: u64,
    pub anchor_retention: usize,
}

impl RailgunSyncOptions {
    /// Known sync sources and scan policy, with caller-supplied RPC batch size and polling.
    #[must_use]
    pub fn for_chain(chain_id: u64, block_range: u64, poll_interval: Duration) -> Option<Self> {
        match chain_id {
            1 => Some(Self {
                block_range,
                poll_interval,
                indexed_artifact_source: None,
                archive_until_block: 15_537_393,
                indexed_wallet_block_range: 300_000,
                quick_sync_endpoint: Some(
                    Url::parse("https://rail-squid.squids.live/squid-railgun-ethereum-v2/graphql")
                        .ok()?,
                ),
                anchor_interval: 1000,
                anchor_retention: 5,
            }),
            56 => Some(Self {
                block_range,
                poll_interval,
                indexed_artifact_source: None,
                archive_until_block: 0,
                indexed_wallet_block_range: 1_000_000,
                quick_sync_endpoint: Some(
                    Url::parse("https://rail-squid.squids.live/squid-railgun-bsc-v2/graphql")
                        .ok()?,
                ),
                anchor_interval: 1000,
                anchor_retention: 5,
            }),
            137 => Some(Self {
                block_range,
                poll_interval,
                indexed_artifact_source: None,
                archive_until_block: 0,
                indexed_wallet_block_range: 1_000_000,
                quick_sync_endpoint: Some(
                    Url::parse("https://rail-squid.squids.live/squid-railgun-polygon-v2/graphql")
                        .ok()?,
                ),
                anchor_interval: 1000,
                anchor_retention: 5,
            }),
            42161 => Some(Self {
                block_range,
                poll_interval,
                indexed_artifact_source: None,
                archive_until_block: 0,
                indexed_wallet_block_range: 5_000_000,
                quick_sync_endpoint: Some(
                    Url::parse("https://rail-squid.squids.live/squid-railgun-arbitrum-v2/graphql")
                        .ok()?,
                ),
                anchor_interval: 1000,
                anchor_retention: 5,
            }),
            8453 => Some(Self {
                block_range,
                poll_interval,
                indexed_artifact_source: None,
                archive_until_block: 0,
                indexed_wallet_block_range: 1_000_000,
                quick_sync_endpoint: None,
                anchor_interval: 1000,
                anchor_retention: 5,
            }),
            11_155_111 => Some(Self {
                block_range,
                poll_interval,
                indexed_artifact_source: None,
                archive_until_block: 0,
                indexed_wallet_block_range: 300_000,
                quick_sync_endpoint: Some(
                    Url::parse(
                        "https://rail-squid.squids.live/squid-railgun-eth-sepolia-v2/graphql",
                    )
                    .ok()?,
                ),
                anchor_interval: 1000,
                anchor_retention: 5,
            }),
            _ => None,
        }
    }
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
