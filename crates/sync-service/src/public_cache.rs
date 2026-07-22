use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};

use local_db::DbStore;
use tokio::sync::{Mutex, OwnedMutexGuard, OwnedRwLockReadGuard, RwLock};

use crate::poi_artifacts::{
    POI_V4_RAW_CHUNK_BLOB_KIND, RawChunkCacheResetFailure, clear_poi_artifact_cache_for_reset,
    reset_raw_chunk_cache,
};
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
}

impl fmt::Display for PersistedPublicSyncCacheKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Txid => "TXID public cache",
            Self::WalletScanArtifactChunks => "wallet-scan artifact chunk cache",
            Self::PoiArtifactCheckpointChunks => "POI artifact checkpoint chunk cache",
            Self::PoiCorpus => "POI corpus",
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
}

impl PersistedPublicSyncCacheResetReport {
    #[must_use]
    pub const fn total_removed_entries(self) -> u64 {
        self.wallet_scan_artifact_chunk_entries_removed
            .saturating_add(self.txid_blob_entries_removed)
            .saturating_add(self.poi_artifact_checkpoint_chunk_entries_removed)
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
    db.ensure_blob_kind_purge_supported(POI_V4_RAW_CHUNK_BLOB_KIND)
        .map_err(|error| {
            PersistedPublicSyncCacheResetError::new(
                PersistedPublicSyncCacheKind::PoiArtifactCheckpointChunks,
                error,
                PersistedPublicSyncCacheResetReport::default(),
            )
        })?;
    let _reset_guard = PERSISTED_PUBLIC_SYNC_CACHE_RESET_LOCK.lock().await;
    let corpus = clear_poi_artifact_cache_for_reset(db)
        .await
        .map_err(|error| {
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
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use alloy::primitives::{Address, FixedBytes};
    use local_db::{
        BlobMeta, DbConfig, PoiArtifactCacheRecord, PoiArtifactDescriptorRecord,
        PoiCacheRecordSource, PoiCorpusValidationRecord, WalletCacheKey, WalletMeta,
    };

    use super::*;
    use crate::txid_cache::TXID_CACHE_BLOB_KIND;

    static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[tokio::test]
    async fn offline_reset_clears_public_caches_and_preserves_unrelated_data() {
        let root_dir = temp_db_root();
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open reset test db");
        seed_blob(&db, TXID_CACHE_BLOB_KIND, "txid-page", "page.bin");
        seed_blob(
            &db,
            WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND,
            "wallet-chunk",
            "chunk.bin",
        );
        seed_blob(
            &db,
            POI_V4_RAW_CHUNK_BLOB_KIND,
            "poi-v4-chunk",
            "poi-v4.bin",
        );
        seed_blob(&db, "unrelated-cache", "unrelated", "keep.bin");
        fs::remove_file(db.blob_path(TXID_CACHE_BLOB_KIND, "page.bin"))
            .expect("remove metadata-backed TXID file");
        for kind in [
            TXID_CACHE_BLOB_KIND,
            WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND,
            POI_V4_RAW_CHUNK_BLOB_KIND,
        ] {
            fs::write(db.blob_path(kind, "orphan.bin"), b"orphan").expect("write unindexed orphan");
        }
        #[cfg(unix)]
        let external_sentinel = {
            use std::os::unix::fs::symlink;
            let sentinel = root_dir.join("external-reset-sentinel");
            fs::write(&sentinel, b"sentinel").expect("write external reset sentinel");
            for kind in [
                TXID_CACHE_BLOB_KIND,
                WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND,
                POI_V4_RAW_CHUNK_BLOB_KIND,
            ] {
                symlink(&sentinel, db.blob_path(kind, "external-link"))
                    .expect("link external reset sentinel");
            }
            sentinel
        };

        let list_key = FixedBytes::from([0x44; 32]);
        db.put_poi_artifact_cache(&poi_record(list_key))
            .expect("seed POI corpus");
        let publisher = FixedBytes::from([0x55; 32]);
        db.advance_poi_publisher_manifest_watermark(publisher, 17)
            .expect("seed publisher watermark");
        db.put_app_settings_record("wallet-settings", b"settings")
            .expect("seed settings");
        let wallet_key = WalletCacheKey::new("wallet", 1, Address::from([0x66; 20]));
        db.put_wallet_meta(
            &wallet_key,
            &WalletMeta {
                last_scanned_block: 42,
                updated_at: 1,
                last_scanned_block_hash: Some([0x77; 32]),
            },
        )
        .expect("seed wallet-private metadata");
        db.put_wallet_utxo(&wallet_key, "balance-row", b"encrypted-balance")
            .expect("seed wallet-private balance row");
        db.put_desktop_wallet_vault_record("wallet-key", b"encrypted-key")
            .expect("seed wallet key record");

        let report = reset_persisted_public_sync_caches(&db)
            .await
            .expect("reset persisted public caches");

        assert_eq!(report.txid_blob_entries_removed, 1);
        assert_eq!(report.wallet_scan_artifact_chunk_entries_removed, 1);
        assert_eq!(report.poi_artifact_checkpoint_chunk_entries_removed, 1);
        assert_eq!(report.total_removed_entries(), 3);
        assert!(
            db.get_blob_meta(TXID_CACHE_BLOB_KIND, "txid-page")
                .expect("read TXID metadata")
                .is_none()
        );
        assert!(
            db.get_blob_meta(WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND, "wallet-chunk")
                .expect("read wallet-scan metadata")
                .is_none()
        );
        assert!(matches!(
            db.inspect_poi_artifact_cache(0, 1, "V3_PoseidonMerkle", &list_key)
                .expect("inspect POI corpus"),
            local_db::StoredRecord::Valid(_)
        ));
        assert!(db.blob_dir().join(TXID_CACHE_BLOB_KIND).is_dir());
        assert!(
            db.blob_dir()
                .join(WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND)
                .is_dir()
        );
        assert!(db.blob_dir().join(POI_V4_RAW_CHUNK_BLOB_KIND).is_dir());
        for kind in [
            TXID_CACHE_BLOB_KIND,
            WALLET_SCAN_ARTIFACT_CHUNK_BLOB_KIND,
            POI_V4_RAW_CHUNK_BLOB_KIND,
        ] {
            assert!(
                fs::read_dir(db.blob_dir().join(kind))
                    .expect("read purged cache kind")
                    .next()
                    .is_none(),
                "orphan entries must be purged without affecting reported metadata count"
            );
        }
        #[cfg(unix)]
        assert_eq!(
            fs::read(external_sentinel).expect("read external reset sentinel"),
            b"sentinel"
        );

        assert!(
            db.get_blob_meta("unrelated-cache", "unrelated")
                .expect("read unrelated metadata")
                .is_some()
        );
        assert!(db.blob_path("unrelated-cache", "keep.bin").is_file());
        assert_eq!(
            db.get_poi_publisher_manifest_watermark(&publisher)
                .expect("read publisher watermark")
                .expect("publisher watermark preserved")
                .accepted_sequence,
            17
        );
        assert_eq!(
            db.get_app_settings_record("wallet-settings")
                .expect("read settings")
                .expect("settings preserved"),
            b"settings"
        );
        assert_eq!(
            db.get_wallet_meta(&wallet_key)
                .expect("read wallet metadata")
                .expect("wallet metadata preserved")
                .last_scanned_block,
            42
        );
        assert_eq!(
            db.list_wallet_utxos(&wallet_key)
                .expect("read wallet-private balance rows")
                .len(),
            1
        );
        assert_eq!(
            db.get_desktop_wallet_vault_record("wallet-key")
                .expect("read wallet key record")
                .expect("wallet key record preserved"),
            b"encrypted-key"
        );

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove reset test db");
    }

    #[tokio::test]
    async fn destructive_poi_corpus_reset_removes_public_corpus_and_raw_chunks_only() {
        let root_dir = temp_db_root();
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open reset test db");
        let list_key = FixedBytes::from([0x81; 32]);
        db.put_poi_artifact_cache(&poi_record(list_key))
            .expect("seed POI corpus");
        seed_blob(
            &db,
            POI_V4_RAW_CHUNK_BLOB_KIND,
            "raw-chunk",
            "raw-chunk.bin",
        );
        let publisher = FixedBytes::from([0x82; 32]);
        db.advance_poi_publisher_manifest_watermark(publisher, 23)
            .expect("seed publisher watermark");
        let wallet_key = WalletCacheKey::new("wallet", 1, Address::from([0x83; 20]));
        db.put_wallet_utxo(&wallet_key, "private-row", b"encrypted")
            .expect("seed wallet-private row");
        db.put_desktop_wallet_vault_record("wallet-key", b"encrypted-key")
            .expect("seed vault row");

        let reset = reset_offline_poi_corpus(&db)
            .await
            .expect("destructively reset POI corpus");

        assert_eq!(reset.corpus_entries_removed, 1);
        assert_eq!(reset.raw_chunk_entries_removed, 1);
        assert_eq!(reset.generation, 1);
        assert!(
            db.get_poi_artifact_cache(0, 1, "V3_PoseidonMerkle", &list_key)
                .expect("read reset corpus")
                .is_none()
        );
        assert_eq!(
            db.get_poi_publisher_manifest_watermark(&publisher)
                .expect("read watermark")
                .expect("watermark retained")
                .accepted_sequence,
            23
        );
        assert_eq!(
            db.list_wallet_utxos(&wallet_key)
                .expect("read wallet-private rows")
                .len(),
            1
        );
        assert_eq!(
            db.get_desktop_wallet_vault_record("wallet-key")
                .expect("read vault")
                .expect("vault retained"),
            b"encrypted-key"
        );

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove reset test db");
    }

    #[cfg(not(any(unix, windows)))]
    #[tokio::test]
    async fn destructive_poi_reset_fails_before_corpus_or_raw_mutation_when_purge_is_unsupported() {
        let root_dir = temp_db_root();
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open reset test db");
        let list_key = FixedBytes::from([0x91; 32]);
        db.put_poi_artifact_cache(&poi_record(list_key))
            .expect("seed POI corpus");
        seed_blob(
            &db,
            POI_V4_RAW_CHUNK_BLOB_KIND,
            "raw-chunk",
            "raw-chunk.bin",
        );
        let generation = db
            .poi_artifact_cache_generation()
            .expect("read initial corpus generation");

        let error = reset_offline_poi_corpus(&db)
            .await
            .expect_err("unsupported purge fails closed");
        assert_eq!(
            error.kind,
            PersistedPublicSyncCacheKind::PoiArtifactCheckpointChunks
        );
        assert!(error.reason.contains("unsupported"));
        assert_eq!(
            db.poi_artifact_cache_generation()
                .expect("read retained corpus generation"),
            generation
        );
        assert!(
            db.get_poi_artifact_cache(0, 1, "V3_PoseidonMerkle", &list_key)
                .expect("read retained corpus")
                .is_some()
        );
        assert!(
            db.get_blob_meta(POI_V4_RAW_CHUNK_BLOB_KIND, "raw-chunk")
                .expect("read retained raw metadata")
                .is_some()
        );

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove reset test db");
    }

    #[test]
    fn reset_error_exposes_completed_deletions() {
        let partial_report = PersistedPublicSyncCacheResetReport {
            txid_blob_entries_removed: 2,
            ..PersistedPublicSyncCacheResetReport::default()
        };

        let error = PersistedPublicSyncCacheResetError::new(
            PersistedPublicSyncCacheKind::WalletScanArtifactChunks,
            "injected failure",
            partial_report,
        );

        assert_eq!(error.partial_report, partial_report);
        assert!(error.to_string().contains("after removing 2 cache entries"));
    }

    #[test]
    fn raw_chunk_reset_error_exposes_deleted_metadata() {
        let failure = RawChunkCacheResetFailure {
            entries_removed: 7,
            error: crate::poi_artifacts::RawChunkCacheError::Io(std::io::Error::other(
                "injected purge failure",
            )),
        };

        let error = poi_chunk_reset_error(failure, PersistedPublicSyncCacheResetReport::default());

        assert_eq!(
            error
                .partial_report
                .poi_artifact_checkpoint_chunk_entries_removed,
            7
        );
    }

    fn seed_blob(db: &DbStore, kind: &str, id: &str, name: &str) {
        db.ensure_blob_dir(kind).expect("create blob directory");
        fs::write(db.blob_path(kind, name), b"cache").expect("write blob file");
        db.put_blob_meta(
            kind,
            id,
            &BlobMeta {
                format_version: 1,
                relative_path: DbStore::relative_blob_path(kind, name),
                content_hash: [0x11; 32],
                source_hash: None,
                source_sequence: None,
                created_at: 1,
                updated_at: 1,
                last_accessed_at: 1,
                last_block: None,
            },
        )
        .expect("write blob metadata");
    }

    fn poi_record(list_key: FixedBytes<32>) -> PoiArtifactCacheRecord {
        let descriptor = PoiArtifactDescriptorRecord {
            cid: "bafytest".to_string(),
            sha256: "00".repeat(32),
            byte_size: 1,
        };
        PoiArtifactCacheRecord {
            chain_type: 0,
            chain_id: 1,
            txid_version: "V3_PoseidonMerkle".to_string(),
            list_key,
            cache_generation: 0,
            source: PoiCacheRecordSource::IndexedArtifacts,
            validation: PoiCorpusValidationRecord::Legacy,
            legacy_observed_manifest_sequence: 0,
            base_descriptor: descriptor.clone(),
            applied_delta_descriptors: Vec::new(),
            blocked_shields_descriptor: descriptor,
            artifact_tip_index: Some(0),
            artifact_tip_root: Some(FixedBytes::ZERO),
            current_tip_index: 0,
            current_tip_root: FixedBytes::ZERO,
            cache_payload: vec![0],
            legacy_last_successful_rpc_sync_at_ms: None,
            updated_at: 0,
        }
    }

    fn temp_db_root() -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let counter = TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "sync-service-public-cache-reset-{}-{unique}-{counter}",
            std::process::id()
        ))
    }
}
