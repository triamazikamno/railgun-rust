use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::{Address, FixedBytes};
use local_db::{
    AppTable, BlobMeta, DbConfig, PoiArtifactCacheRecord, PoiArtifactDescriptorRecord,
    PoiCacheRecordSource, PoiCorpusValidationRecord, WalletCacheKey, WalletMeta,
};

use super::*;
use crate::amount_statistics::AMOUNT_STATISTICS_TABLE;
use crate::manager::SyncManager;
use crate::txid_cache::TXID_CACHE_BLOB_KIND;
use crate::types::GlobalPoiPolicy;
use url::Url;

static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);
const APP_SETTINGS: AppTable = AppTable::new("app_settings_v1");
const DESKTOP_WALLET_VAULT: AppTable = AppTable::new("desktop_wallet_vault_v1");

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
    db.write_app_tables(|tables| {
        tables.insert(AMOUNT_STATISTICS_TABLE, "statistics-scope", b"statistics")?;
        tables.insert(APP_SETTINGS, "wallet-settings", b"settings")?;
        tables.insert(DESKTOP_WALLET_VAULT, "wallet-key", b"encrypted-key")
    })
    .expect("seed settings and wallet key record");

    let report = reset_persisted_public_sync_caches(&db)
        .await
        .expect("reset persisted public caches");

    assert_eq!(report.txid_blob_entries_removed, 1);
    assert_eq!(report.wallet_scan_artifact_chunk_entries_removed, 1);
    assert_eq!(report.poi_artifact_checkpoint_chunk_entries_removed, 1);
    assert_eq!(report.amount_statistics_entries_removed, 1);
    assert_eq!(report.total_removed_entries(), 4);
    assert!(
        db.read_app_tables(|tables| tables.get(AMOUNT_STATISTICS_TABLE, "statistics-scope"))
            .expect("read amount statistics")
            .is_none()
    );
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
        db.read_app_tables(|tables| tables.get(APP_SETTINGS, "wallet-settings"))
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
        db.read_app_tables(|tables| tables.get(DESKTOP_WALLET_VAULT, "wallet-key"))
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
    db.write_app_tables(|tables| {
        tables.insert(DESKTOP_WALLET_VAULT, "wallet-key", b"encrypted-key")
    })
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
        db.read_app_tables(|tables| tables.get(DESKTOP_WALLET_VAULT, "wallet-key"))
            .expect("read vault")
            .expect("vault retained"),
        b"encrypted-key"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove reset test db");
}

#[tokio::test]
async fn destructive_poi_reset_rejects_live_manager_and_succeeds_after_shutdown() {
    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open reset test db"),
    );
    let list_key = FixedBytes::from([0x89; 32]);
    db.put_poi_artifact_cache(&poi_record(list_key))
        .expect("seed POI corpus");
    let manager = SyncManager::new(
        Arc::clone(&db),
        GlobalPoiPolicy::PoiProxy {
            rpc_url: Url::parse("http://127.0.0.1:1").expect("proxy URL").into(),
        },
    )
    .expect("acquire manager");

    let error = reset_offline_poi_corpus(db.as_ref())
        .await
        .expect_err("live manager rejects destructive reset");
    assert_eq!(error.kind, PersistedPublicSyncCacheKind::PoiCorpus);
    assert!(error.reason.contains("active sync manager"));
    assert_eq!(error.poi_corpus_entries_removed, 0);
    assert!(
        db.get_poi_artifact_cache(0, 1, "V3_PoseidonMerkle", &list_key)
            .expect("read retained corpus")
            .is_some()
    );

    manager.shutdown().await;
    let reset = reset_offline_poi_corpus(db.as_ref())
        .await
        .expect("reset after manager shutdown");
    assert_eq!(reset.corpus_entries_removed, 1);
    let replacement = SyncManager::new(
        Arc::clone(&db),
        GlobalPoiPolicy::PoiProxy {
            rpc_url: Url::parse("http://127.0.0.1:1").expect("proxy URL").into(),
        },
    )
    .expect("manager admission released after reset");
    replacement.shutdown().await;

    drop(replacement);
    drop(manager);
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
