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
pub mod poi_v4;
mod public_cache;
mod trustless_artifacts;
pub(crate) mod txid_cache;
pub mod types;
mod wallet;

pub use chain::{
    ChainError, ChainHandle, ChainPublicSyncCacheReset, ChainService, PoiArtifactCacheRetry,
    PublicCoverageAnswer, PublicDataPlaneDiagnostic, PublicDataPlaneDiagnosticKind,
    PublicDataPlaneDiagnostics, PublicDataPlaneError, PublicDataPlaneHandle, PublicScanRange,
    PublicScanRows, PublicScanRowsAnswer, PublicSyncCacheReset,
};
pub use manager::{
    ChainPublicSyncCacheResetResult, PublicSyncCachesResetReport, SyncManager, SyncManagerError,
};
pub use public_cache::{
    OfflinePoiCorpusReset, PersistedPublicSyncCacheKind, PersistedPublicSyncCacheResetError,
    PersistedPublicSyncCacheResetReport, reset_offline_poi_corpus,
    reset_persisted_public_sync_caches,
};
pub use types::{
    ChainConfig, ChainConfigDefaults, ChainKey, DEFAULT_INDEXED_WALLET_BLOCK_RANGE,
    GlobalPoiPolicy, IndexedArtifactManifestSource, IndexedArtifactSourceConfig,
    PendingOutputPoiContextIntent, PoiArtifactCacheAttemptId, PoiArtifactCacheFailureKind,
    PoiArtifactCacheGraphProgress, PoiArtifactCacheListProgress, PoiArtifactCachePhase,
    PoiArtifactCacheProgress, PoiArtifactManifestSource, PoiArtifactSourceConfig, PoiProxyFallback,
    PublicScanSource, SyncProgressSender, SyncProgressStage, SyncProgressUnit, SyncProgressUpdate,
    WalletCacheStore, WalletConfig, WalletCurrentSnapshot, WalletInactiveReason,
    WalletIndexedCatchUpSource, WalletIndexedCatchUpStatus, WalletObservation,
    WalletPendingSpentMarkOutcome, WalletPpoiWorkflowStatus, WalletPrivateRequestError,
    WalletReadiness, WalletReadinessError, WalletReadinessWaitError, WalletSchedulableProgress,
    WalletViewState,
};
pub use wallet::{
    LocalPoiMerkleProofSource, WalletHandle, WalletPendingOverlay, WalletPendingSpent,
};
