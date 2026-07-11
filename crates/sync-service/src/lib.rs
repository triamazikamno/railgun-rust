//! Chain-owned POI corpus internals are intentionally not public construction APIs.
//!
//! ```compile_fail
//! use sync_service::PoiCacheService;
//! ```
//!
//! ```compile_fail
//! use sync_service::types::LocalPoiCaches;
//! ```

mod chain;
pub mod indexed_artifacts;
mod manager;
pub(crate) mod poi_artifacts;
mod poi_cache;
mod trustless_artifacts;
pub(crate) mod txid_cache;
pub mod types;
mod wallet;

pub use chain::{
    ChainError, ChainHandle, ChainService, PublicCoverageAnswer, PublicDataPlaneDiagnostic,
    PublicDataPlaneDiagnosticKind, PublicDataPlaneDiagnostics, PublicDataPlaneError,
    PublicDataPlaneHandle, PublicScanRange, PublicScanRows, PublicScanRowsAnswer,
    PublicSyncCacheReset,
};
pub use manager::{SyncManager, SyncManagerError};
pub use types::{
    ChainConfig, ChainConfigDefaults, ChainKey, DEFAULT_INDEXED_WALLET_BLOCK_RANGE,
    GlobalPoiPolicy, IndexedArtifactManifestSource, IndexedArtifactSourceConfig,
    PendingOutputPoiContextIntent, PoiArtifactCacheListProgress, PoiArtifactCachePhase,
    PoiArtifactCacheProgress, PoiArtifactManifestSource, PoiArtifactSourceConfig, PoiProxyFallback,
    PublicScanSource, SyncProgressSender, SyncProgressStage, SyncProgressUnit, SyncProgressUpdate,
    WalletCacheStore, WalletConfig, WalletCurrentSnapshot, WalletInactiveReason,
    WalletIndexedCatchUpSource, WalletIndexedCatchUpStatus, WalletPrivateRequestError,
    WalletSchedulableProgress, WalletViewState,
};
pub use wallet::{
    LocalPoiMerkleProofSource, WalletHandle, WalletPendingOverlay, WalletPendingSpent,
};
