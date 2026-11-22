use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};

use local_db::DbStore;
use tokio::sync::{Mutex, OwnedMutexGuard, OwnedRwLockReadGuard, RwLock};

use crate::amount_statistics::clear_amount_statistics;
use crate::poi_artifacts::{
    POI_V4_RAW_CHUNK_BLOB_KIND, RawChunkCacheResetFailure, clear_poi_artifact_cache_for_reset,
    reset_raw_chunk_cache,
};
use crate::runtime_admission::{DbRuntimeLease, DbRuntimeOwnerKind};
use crate::txid_cache::reset_txid_public_cache;

pub(crate) const WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND: &str = "wallet_scan_artifact_chunks";

static PERSISTED_PUBLIC_SYNC_CACHE_RESET_LOCK: Mutex<()> = Mutex::const_new(());
static WALLET_SCAN_ARTIFACT_CACHE_AUTHORITIES: LazyLock<
    std::sync::Mutex<BTreeMap<PathBuf, Arc<WalletScanArtifactCacheAuthority>>>,
> = LazyLock::new(|| std::sync::Mutex::new(BTreeMap::new()));

struct WalletScanArtifactCacheAuthority {
    access: Arc<RwLock<()>>,
    transient_commit: Arc<Mutex<()>>,
    generation: AtomicU64,
}

impl WalletScanArtifactCacheAuthority {
    fn new() -> Self {
        Self {
            access: Arc::new(RwLock::new(())),
            transient_commit: Arc::new(Mutex::new(())),
            generation: AtomicU64::new(0),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistedPublicSyncCacheKind {
    Txid,
    WalletScanArtifactChunks,
    PoiArtifactCheckpointChunks,
    PoiCorpus,
    AmountStatistics,
}

impl fmt::Display for PersistedPublicSyncCacheKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Txid => "TXID public cache",
            Self::WalletScanArtifactChunks => "wallet-scan artifact chunk cache",
            Self::PoiArtifactCheckpointChunks => "POI artifact checkpoint chunk cache",
            Self::PoiCorpus => "POI corpus",
            Self::AmountStatistics => "amount statistics cache",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedPublicSyncCacheResetError {
    pub kind: PersistedPublicSyncCacheKind,
    pub reason: String,
    pub partial_report: PersistedPublicSyncCacheResetReport,
    pub poi_corpus_entries_removed: u64,
}

impl PersistedPublicSyncCacheResetError {
    fn new(
        kind: PersistedPublicSyncCacheKind,
        error: impl fmt::Display,
        partial_report: PersistedPublicSyncCacheResetReport,
    ) -> Self {
        Self {
            kind,
            reason: error.to_string(),
            partial_report,
            poi_corpus_entries_removed: 0,
        }
    }
}

impl fmt::Display for PersistedPublicSyncCacheResetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "failed to reset persisted {}", self.kind)?;
        let removed = self
            .partial_report
            .total_removed_entries()
            .saturating_add(self.poi_corpus_entries_removed);
        if removed > 0 {
            write!(f, " after removing {removed} cache entries")?;
        }
        write!(f, ": {}", self.reason)
    }
}

impl std::error::Error for PersistedPublicSyncCacheResetError {}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PersistedPublicSyncCacheResetReport {
    pub wallet_scan_artifact_chunk_entries_removed: u64,
    pub txid_blob_entries_removed: u64,
    pub poi_artifact_checkpoint_chunk_entries_removed: u64,
    pub amount_statistics_entries_removed: u64,
}

impl PersistedPublicSyncCacheResetReport {
    #[must_use]
    pub const fn total_removed_entries(self) -> u64 {
        self.wallet_scan_artifact_chunk_entries_removed
            .saturating_add(self.txid_blob_entries_removed)
            .saturating_add(self.poi_artifact_checkpoint_chunk_entries_removed)
            .saturating_add(self.amount_statistics_entries_removed)
    }

    const fn record_txid_reset(&mut self, reset: crate::txid_cache::TxidPublicCacheReset) {
        self.txid_blob_entries_removed = reset.blob_entries_removed;
    }

    const fn record_wallet_scan_reset(&mut self, reset: WalletScanArtifactChunkCacheReset) {
        self.wallet_scan_artifact_chunk_entries_removed = reset.blob_entries_removed;
    }
}

/// Clears only reconstructible persisted public synchronization caches.
///
/// This API is intended for maintenance while chain services are not active. The active manager
/// acquires every public-data-plane commit fence before using the same operation; a single data
/// plane acquires its own fence. Materialized POI serving corpora are deliberately excluded.
///
/// Amount-statistics refreshes run outside that fence. The reset removes the stored statistics
/// row but does not invalidate a running chain session's held snapshot, whose status still follows
/// the normal freshness rules, and an in-flight refresh or a newer manifest naming the held
/// snapshot may store that verified snapshot again. The row is also the statistics rollback floor,
/// so a session started after the reset accepts any correctly signed manifest, as a fresh install
/// does; the six-hour covered-block limit still applies.
pub async fn reset_persisted_public_sync_caches(
    db: &DbStore,
) -> Result<PersistedPublicSyncCacheResetReport, PersistedPublicSyncCacheResetError> {
    let _reset_guard = PERSISTED_PUBLIC_SYNC_CACHE_RESET_LOCK.lock().await;
    let mut report = PersistedPublicSyncCacheResetReport::default();
    match reset_txid_public_cache(db).await {
        Ok(reset) => report.record_txid_reset(reset),
        Err(failure) => {
            report.record_txid_reset(failure.reset);
            return Err(PersistedPublicSyncCacheResetError::new(
                PersistedPublicSyncCacheKind::Txid,
                failure,
                report,
            ));
        }
    }
    match reset_wallet_scan_artifact_chunk_cache(db).await {
        Ok(reset) => report.record_wallet_scan_reset(reset),
        Err(failure) => {
            report.record_wallet_scan_reset(failure.reset);
            return Err(PersistedPublicSyncCacheResetError::new(
                PersistedPublicSyncCacheKind::WalletScanArtifactChunks,
                failure,
                report,
            ));
        }
    }
    let poi_chunks = match reset_raw_chunk_cache(db).await {
        Ok(reset) => reset,
        Err(failure) => return Err(poi_chunk_reset_error(failure, report)),
    };
    report.poi_artifact_checkpoint_chunk_entries_removed = poi_chunks;
    report.amount_statistics_entries_removed = clear_amount_statistics(db).map_err(|error| {
        PersistedPublicSyncCacheResetError::new(
            PersistedPublicSyncCacheKind::AmountStatistics,
            error,
            report,
        )
    })?;
    Ok(report)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OfflinePoiCorpusReset {
    pub corpus_entries_removed: u64,
    pub raw_chunk_entries_removed: u64,
    pub generation: u64,
}

/// Destructively removes all persisted PPOI serving data and POI artifact raw chunks.
///
/// Every sync manager, chain service, public data plane, and PPOI cache service
/// using this database must be fully shut down before this offline operation is
/// called. Publisher anti-rollback state and wallet-private data are preserved.
/// If raw-chunk purge fails after serving data was removed, the returned error's
/// partial report records the completed removals.
pub async fn reset_offline_poi_corpus(
    db: &DbStore,
) -> Result<OfflinePoiCorpusReset, PersistedPublicSyncCacheResetError> {
    let _runtime_lease =
        DbRuntimeLease::acquire(db, DbRuntimeOwnerKind::OfflinePoiReset).map_err(|error| {
            PersistedPublicSyncCacheResetError::new(
                PersistedPublicSyncCacheKind::PoiCorpus,
                error,
                PersistedPublicSyncCacheResetReport::default(),
            )
        })?;
    db.ensure_blob_kind_purge_supported(POI_V4_RAW_CHUNK_BLOB_KIND)
        .map_err(|error| {
            PersistedPublicSyncCacheResetError::new(
                PersistedPublicSyncCacheKind::PoiArtifactCheckpointChunks,
                error,
                PersistedPublicSyncCacheResetReport::default(),
            )
        })?;
    let _reset_guard = PERSISTED_PUBLIC_SYNC_CACHE_RESET_LOCK.lock().await;
    let corpus = clear_poi_artifact_cache_for_reset(db).map_err(|error| {
        PersistedPublicSyncCacheResetError::new(
            PersistedPublicSyncCacheKind::PoiCorpus,
            error,
            PersistedPublicSyncCacheResetReport::default(),
        )
    })?;
    let raw = reset_raw_chunk_cache(db).await.map_err(|failure| {
        let mut error =
            poi_chunk_reset_error(failure, PersistedPublicSyncCacheResetReport::default());
        error.poi_corpus_entries_removed = corpus.removed;
        error
    })?;
    Ok(OfflinePoiCorpusReset {
        corpus_entries_removed: corpus.removed,
        raw_chunk_entries_removed: raw,
        generation: corpus.generation,
    })
}

fn poi_chunk_reset_error(
    failure: RawChunkCacheResetFailure,
    mut report: PersistedPublicSyncCacheResetReport,
) -> PersistedPublicSyncCacheResetError {
    report.poi_artifact_checkpoint_chunk_entries_removed = failure.entries_removed;
    PersistedPublicSyncCacheResetError::new(
        PersistedPublicSyncCacheKind::PoiArtifactCheckpointChunks,
        failure,
        report,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WalletScanArtifactChunkCacheReset {
    blob_entries_removed: u64,
}

#[derive(Debug, thiserror::Error)]
#[error("{error}")]
struct WalletScanArtifactChunkCacheResetFailure {
    reset: WalletScanArtifactChunkCacheReset,
    #[source]
    error: std::io::Error,
}

async fn reset_wallet_scan_artifact_chunk_cache(
    db: &DbStore,
) -> Result<WalletScanArtifactChunkCacheReset, WalletScanArtifactChunkCacheResetFailure> {
    let mut reset = WalletScanArtifactChunkCacheReset {
        blob_entries_removed: 0,
    };
    db.ensure_blob_kind_purge_supported(WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND)
        .map_err(|error| WalletScanArtifactChunkCacheResetFailure {
            reset,
            error: std::io::Error::other(error),
        })?;
    let authority = wallet_scan_artifact_cache_authority(db);
    let _access = Arc::clone(&authority.access).write_owned().await;
    authority.generation.fetch_add(1, Ordering::AcqRel);
    reset.blob_entries_removed = db
        .clear_blob_meta_kind(WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND)
        .map_err(|error| WalletScanArtifactChunkCacheResetFailure {
            reset,
            error: std::io::Error::other(error),
        })?;
    db.purge_blob_kind(WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND)
        .map_err(|error| WalletScanArtifactChunkCacheResetFailure {
            reset,
            error: std::io::Error::other(error),
        })?;
    Ok(reset)
}

fn wallet_scan_artifact_cache_authority(db: &DbStore) -> Arc<WalletScanArtifactCacheAuthority> {
    let mut authorities = WALLET_SCAN_ARTIFACT_CACHE_AUTHORITIES
        .lock()
        .expect("wallet-scan artifact cache authority lock poisoned");
    Arc::clone(
        authorities
            .entry(db.root_dir().to_path_buf())
            .or_insert_with(|| Arc::new(WalletScanArtifactCacheAuthority::new())),
    )
}

pub(crate) fn wallet_scan_artifact_cache_generation(db: &DbStore) -> u64 {
    wallet_scan_artifact_cache_authority(db)
        .generation
        .load(Ordering::Acquire)
}

pub(crate) async fn wallet_scan_artifact_cache_commit_access(
    db: &DbStore,
    expected_generation: u64,
) -> Option<OwnedRwLockReadGuard<()>> {
    let authority = wallet_scan_artifact_cache_authority(db);
    let access = Arc::clone(&authority.access).read_owned().await;
    (authority.generation.load(Ordering::Acquire) == expected_generation).then_some(access)
}

pub(crate) async fn wallet_scan_artifact_transient_commit_access(
    db: &DbStore,
) -> OwnedMutexGuard<()> {
    Arc::clone(&wallet_scan_artifact_cache_authority(db).transient_commit)
        .lock_owned()
        .await
}

#[cfg(test)]
mod tests;
