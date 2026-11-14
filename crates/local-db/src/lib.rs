use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use redb::{Database, ReadableDatabase, TableHandle, WriteTransaction};
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod app_tables;
mod blobs;
mod cache_key;
mod codec;
mod migrations;
mod output_poi;
mod poi_cache;
mod poi_corpus;
mod poi_corpus_records;
mod tables;
mod wallet_cache;
mod wallet_private;

pub use app_tables::{AppTable, AppTableReader, AppTableWriter};
pub use blobs::{BlobMeta, CanonicalBlobMetaIdentity, MerkleForestMeta, ZkeyMeta};
pub use cache_key::{WalletCacheKey, WalletCacheKeyError};
pub use output_poi::{
    OutputPoiRecoveryAction, OutputPoiRecoveryRecord, OutputPoiRecoveryStatus,
    PendingOutputPoiContextRecord, PendingOutputPoiObservation, PendingOutputPoiRole,
};
pub use poi_cache::{
    PoiArtifactCacheRecord, PoiArtifactCacheRecordScan, PoiArtifactDescriptorRecord,
    PoiCacheRecordSource, PoiCorpusRpcHealthRecord, PoiCorpusValidationRecord,
    PoiPublisherManifestObservation, PoiPublisherManifestWatermarkRecord,
    PoiV4CatalogIdentityRecord, StoredRecord,
};
pub use poi_corpus_records::{
    ExpectedPoiCorpusJournalState, POI_CORPUS_JOURNAL_FORMAT_VERSION,
    POI_CORPUS_JOURNAL_MAX_BLOCKED_PAYLOAD_BYTES, POI_CORPUS_JOURNAL_MAX_DELTA_COUNT,
    POI_CORPUS_JOURNAL_MAX_PAYLOAD_BYTES, POI_CORPUS_JOURNAL_SOFT_DELTA_COUNT,
    POI_CORPUS_JOURNAL_SOFT_PAYLOAD_BYTES, PoiCorpusBlockedSnapshotRecord, PoiCorpusJournalBundle,
    PoiCorpusJournalCommit, PoiCorpusJournalCommitCondition, PoiCorpusJournalCommitOutcome,
    PoiCorpusJournalCorruptionToken, PoiCorpusJournalDeltaRecord, PoiCorpusJournalHeadRecord,
    PoiCorpusJournalInspection,
};
pub use tables::{LOCAL_DB_TABLES, LocalDbTable, LocalDbTableDecodeKind, LocalDbTableInfo};
pub use wallet_cache::{
    WalletMeta, WalletPendingResetRecord, WalletSyncActorStateRecord, WalletUtxoRecord,
};
pub use wallet_private::{
    OpaqueWalletPrivateRow, OpaqueWalletPrivateRowMutation, WalletMetaMutation,
    WalletPrivateCanonicalizationBatch, WalletPrivateCanonicalizationKindBatch,
    WalletPrivateCanonicalizationReport, WalletPrivateNamespaceDeletionReport,
    WalletPrivateNamespaceId, WalletPrivateRecordKind, WalletPrivateStateBatch,
    WalletPrivateV1MigrationBatch, WalletPrivateV1MigrationReport, WalletPrivateV1Row,
    WalletPrivateV1Rows, WalletUtxoRowMutation,
};

use blobs::ensure_storage_directory;
use codec::{
    decode, encode, list_table_prefix, prefix_range_end, remove_table_prefix,
    remove_table_prefix_matching, table_prefix_has_rows,
};
use poi_cache::{
    POI_ARTIFACT_CACHE_GENERATION_KEY, POI_SIDECAR_KEY_PREFIX, poi_commit_context_conflict,
};
use poi_corpus_records::{
    POI_CORPUS_JOURNAL_MAX_HEAD_ROW_BYTES, decode_poi_corpus_blocked_snapshot_bounded,
    decode_poi_corpus_journal_delta_bounded,
};
use tables::{
    BLOB_INDEX_TABLE, ByteTableDefinition, MERKLE_FOREST_INDEX_TABLE, META_TABLE,
    OUTPUT_POI_RECOVERY_TABLE, OUTPUT_POI_RECOVERY_V2_TABLE, PENDING_OUTPUT_POI_CONTEXT_TABLE,
    PENDING_OUTPUT_POI_CONTEXT_V2_TABLE, POI_ARTIFACT_CACHE_TABLE, POI_CORPUS_JOURNAL_TABLE,
    POI_SIDECAR_STATE_TABLE, SENDER_TRANSACTION_CANDIDATE_V1_TABLE, WALLET_META_TABLE,
    WALLET_SYNC_ACTOR_STATE_TABLE, WALLET_UTXO_TABLE, ZKEY_INDEX_TABLE,
};
use wallet_cache::{wallet_utxo_key, wallet_utxo_prefix};
use wallet_private::opaque_wallet_private_row_key;

const LEGACY_DESKTOP_WALLET_CACHE_ROW_PREFIX: &str = "wallet-cache-row|";

const META_KEY: &str = "meta";
const WALLET_PRIVATE_COMPACTION_REQUESTED_KEY: &str = "wallet_private_compaction_requested_v1";
const RAILGUN_DIR: &str = "railgun";
const BLOBS_DIR: &str = "blobs";

pub const CURRENT_SCHEMA_VERSION: u32 = 12;

#[derive(Debug, Clone)]
pub struct DbConfig {
    pub root_dir: PathBuf,
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            root_dir: PathBuf::from("db"),
        }
    }
}

#[derive(Debug)]
pub struct DbStore {
    root_dir: PathBuf,
    db: Database,
    _lock_file: Arc<File>,
}

#[derive(Debug, Error)]
pub enum DbError {
    #[error(transparent)]
    InvalidWalletCacheKey(#[from] WalletCacheKeyError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("database is already in use at {}", path.display())]
    DatabaseInUse { path: PathBuf },
    #[error("db error: {0}")]
    Database(#[from] redb::DatabaseError),
    #[error("transaction error: {0}")]
    Transaction(#[from] redb::TransactionError),
    #[error("table error: {0}")]
    Table(#[from] redb::TableError),
    #[error("storage error: {0}")]
    Storage(#[from] redb::StorageError),
    #[error("commit error: {0}")]
    Commit(#[from] redb::CommitError),
    #[error("compaction error: {0}")]
    Compaction(#[from] redb::CompactionError),
    #[error("encode error: {0}")]
    Encode(#[from] rmp_serde::encode::Error),
    #[error("decode error: {0}")]
    Decode(#[from] rmp_serde::decode::Error),
    #[error("unsupported schema version {version}")]
    UnsupportedSchemaVersion { version: u32 },
    #[error(
        "invalid wallet-private commit namespace: expected chain {expected_chain_id} wallet {expected_wallet_id}, got chain {actual_chain_id} wallet {actual_wallet_id}"
    )]
    InvalidWalletPrivateCommitNamespace {
        expected_chain_id: u64,
        expected_wallet_id: String,
        actual_chain_id: u64,
        actual_wallet_id: String,
    },
    #[error("invalid legacy desktop wallet cache row key {key}")]
    InvalidLegacyDesktopWalletCacheRowKey { key: String },
    #[error("invalid schema-7 pending-output POI context row {key}")]
    InvalidSchemaSevenPendingOutputPoiContext { key: String },
    #[error("invalid legacy composite wallet row in {table}: {key}")]
    InvalidLegacyCompositeWalletRow { table: &'static str, key: String },
    #[error("schema migration destination already exists in {table}: {key}")]
    SchemaMigrationDestinationConflict { table: &'static str, key: String },
    #[error("opaque wallet-private row id must not be empty")]
    EmptyOpaqueWalletPrivateRowId,
    #[error("invalid opaque wallet-private row key {key}")]
    InvalidOpaqueWalletPrivateRowKey { key: String },
    #[error("wallet-private v1 migration source changed in {table}: {key}")]
    WalletPrivateV1MigrationSourceChanged { table: &'static str, key: String },
    #[error("wallet-private v1 migration must replace every source row for {kind}")]
    WalletPrivateV1MigrationRowCountMismatch { kind: &'static str },
    #[error("wallet-private canonicalization source changed in {table}: {key}")]
    WalletPrivateCanonicalizationSourceChanged { table: &'static str, key: String },
    #[error("wallet-private canonicalization source set changed for {kind}")]
    WalletPrivateCanonicalizationRowCountMismatch { kind: &'static str },
    #[error("invalid wallet-private canonicalization version marker")]
    InvalidWalletPrivateCanonicalizationVersion,
    #[error("wallet-private canonicalization namespaces must be distinct")]
    DuplicateWalletPrivateCanonicalizationNamespace,
    #[error("wallet-private {kind} row identity does not match key {key}")]
    WalletPrivateRecordIdentityMismatch { kind: &'static str, key: String },
    #[error("invalid {kind} PPOI sidecar record {key}")]
    InvalidPpoiSidecarRecord { kind: &'static str, key: String },
    #[error("invalid PPOI corpus record {key}")]
    InvalidPpoiCorpusRecord { key: String },
    #[error("invalid {kind} PPOI corpus journal record {key}")]
    InvalidPpoiCorpusJournalRecord { kind: &'static str, key: String },
    #[error("invalid schema-9 PPOI corpus record {key}")]
    InvalidSchemaNinePpoiCorpusRecord { key: String },
    #[error("invalid blob relative path for kind {kind}")]
    InvalidBlobRelativePath { kind: String },
    #[error("unsafe blob entry for kind {kind}")]
    UnsafeBlobEntry { kind: String },
    #[error("application table name is reserved by local-db: {table}")]
    ReservedTableName { table: &'static str },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub schema_version: u32,
    pub app_version: String,
    pub created_at: u64,
}

impl Meta {
    fn new() -> Result<Self, DbError> {
        Ok(Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            created_at: now_epoch_secs()?,
        })
    }
}

impl DbStore {
    pub fn open(config: DbConfig) -> Result<Self, DbError> {
        Self::open_inner(config, None)
    }

    pub fn open_with_cache_size_bytes(
        config: DbConfig,
        cache_size_bytes: usize,
    ) -> Result<Self, DbError> {
        Self::open_inner(config, Some(cache_size_bytes))
    }

    fn open_inner(config: DbConfig, cache_size_bytes: Option<usize>) -> Result<Self, DbError> {
        let root_dir = config.root_dir;
        let railgun_dir = railgun_dir(&root_dir);
        std::fs::create_dir_all(&root_dir)?;
        ensure_storage_directory(&railgun_dir, RAILGUN_DIR)?;
        let lock_path = db_lock_path(&root_dir);
        let lock_file = Arc::new(open_database_lock(&lock_path)?);
        match lock_file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(DbError::DatabaseInUse { path: lock_path });
            }
            Err(TryLockError::Error(error)) => return Err(error.into()),
        }
        ensure_storage_directory(&blobs_dir(&root_dir), BLOBS_DIR)?;
        let db_path = db_path(&root_dir);

        loop {
            validate_database_path(&db_path)?;
            let db = if let Some(cache_size_bytes) = cache_size_bytes {
                let mut builder = Database::builder();
                builder.set_cache_size(cache_size_bytes);
                if db_path.exists() {
                    builder.open(&db_path)?
                } else {
                    builder.create(&db_path)?
                }
            } else if db_path.exists() {
                Database::open(&db_path)?
            } else {
                Database::create(&db_path)?
            };

            let store = Self {
                root_dir: root_dir.clone(),
                db,
                _lock_file: Arc::clone(&lock_file),
            };

            if !store.has_meta_table()? {
                store.initialize_schema()?;
                let meta = Meta::new()?;
                store.write_meta(&meta)?;
                return store.finish_open();
            }

            match store.read_meta()? {
                None => {
                    store.initialize_schema()?;
                    let meta = Meta::new()?;
                    store.write_meta(&meta)?;
                    return store.finish_open();
                }
                Some(meta) if meta.schema_version > CURRENT_SCHEMA_VERSION => {
                    return Err(DbError::UnsupportedSchemaVersion {
                        version: meta.schema_version,
                    });
                }
                Some(meta) if meta.schema_version < CURRENT_SCHEMA_VERSION => {
                    if let Err(err) = store.run_migrations(&meta, CURRENT_SCHEMA_VERSION) {
                        if matches!(err, DbError::UnsupportedSchemaVersion { .. }) {
                            drop(store);
                            backup_db(&db_path)?;
                            continue;
                        }
                        return Err(err);
                    }
                    return store.finish_open();
                }
                Some(_) => {
                    store.initialize_schema()?;
                    return store.finish_open();
                }
            }
        }
    }

    #[must_use]
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    #[must_use]
    pub fn railgun_dir(&self) -> PathBuf {
        railgun_dir(&self.root_dir)
    }

    #[must_use]
    pub fn db_path(&self) -> PathBuf {
        db_path(&self.root_dir)
    }

    #[must_use]
    pub fn blob_dir(&self) -> PathBuf {
        blobs_dir(&self.root_dir)
    }

    fn finish_open(mut self) -> Result<Self, DbError> {
        if self.wallet_private_compaction_requested()? {
            while self.db.compact()? {}
            let txn = self.db.begin_write()?;
            {
                let mut table = txn.open_table(META_TABLE)?;
                table.remove(WALLET_PRIVATE_COMPACTION_REQUESTED_KEY)?;
            }
            txn.commit()?;
        }
        Ok(self)
    }

    fn wallet_private_compaction_requested(&self) -> Result<bool, DbError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(META_TABLE)?;
        Ok(table
            .get(WALLET_PRIVATE_COMPACTION_REQUESTED_KEY)?
            .is_some())
    }

    fn initialize_schema(&self) -> Result<(), DbError> {
        let txn = self.db.begin_write()?;
        Self::initialize_schema_tables(&txn)?;
        txn.commit()?;
        Ok(())
    }

    fn initialize_schema_tables(txn: &WriteTransaction) -> Result<(), DbError> {
        txn.open_table(META_TABLE)?;
        txn.open_table(BLOB_INDEX_TABLE)?;
        txn.open_table(MERKLE_FOREST_INDEX_TABLE)?;
        txn.open_table(ZKEY_INDEX_TABLE)?;
        txn.open_table(WALLET_UTXO_TABLE)?;
        txn.open_table(WALLET_META_TABLE)?;
        txn.open_table(WALLET_SYNC_ACTOR_STATE_TABLE)?;
        txn.open_table(PENDING_OUTPUT_POI_CONTEXT_TABLE)?;
        txn.open_table(OUTPUT_POI_RECOVERY_TABLE)?;
        txn.open_table(PENDING_OUTPUT_POI_CONTEXT_V2_TABLE)?;
        txn.open_table(OUTPUT_POI_RECOVERY_V2_TABLE)?;
        txn.open_table(SENDER_TRANSACTION_CANDIDATE_V1_TABLE)?;
        txn.open_table(POI_ARTIFACT_CACHE_TABLE)?;
        txn.open_table(POI_CORPUS_JOURNAL_TABLE)?;
        txn.open_table(POI_SIDECAR_STATE_TABLE)?;
        Ok(())
    }

    fn has_meta_table(&self) -> Result<bool, DbError> {
        let txn = self.db.begin_read()?;
        Ok(txn
            .list_tables()?
            .any(|table| table.name() == META_TABLE.name()))
    }

    fn read_meta(&self) -> Result<Option<Meta>, DbError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(META_TABLE)?;
        match table.get(META_KEY)? {
            Some(value) => Ok(Some(decode(value.value())?)),
            None => Ok(None),
        }
    }

    fn write_meta(&self, meta: &Meta) -> Result<(), DbError> {
        let data = encode(meta)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(META_TABLE)?;
            table.insert(META_KEY, data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    fn run_migrations(&self, meta: &Meta, to: u32) -> Result<(), DbError> {
        self.run_migrations_transaction(meta, to, || Ok(()))
    }

    fn run_migrations_transaction(
        &self,
        meta: &Meta,
        to: u32,
        before_commit: impl FnOnce() -> Result<(), DbError>,
    ) -> Result<(), DbError> {
        let migrate_schema_seven = match (meta.schema_version, to) {
            (7, 8..=12) => true,
            (8, 9..=12) | (9, 10..=12) | (10, 11..=12) | (11, 12) => false,
            _ => {
                return Err(DbError::UnsupportedSchemaVersion {
                    version: meta.schema_version,
                });
            }
        };
        if to > CURRENT_SCHEMA_VERSION {
            return Err(DbError::UnsupportedSchemaVersion {
                version: meta.schema_version,
            });
        }

        let migrated_meta = Meta {
            schema_version: to,
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            created_at: meta.created_at,
        };
        let migrated_meta = encode(&migrated_meta)?;
        let txn = self.db.begin_write()?;
        if migrate_schema_seven {
            migrations::migrate_schema_7_to_8(&txn)?;
        }
        if meta.schema_version <= 9 && to >= 10 {
            migrations::migrate_schema_9_to_10(&txn)?;
        }
        if meta.schema_version <= 11 && to >= 12 {
            migrations::migrate_schema_11_to_12(&txn)?;
        }
        Self::initialize_schema_tables(&txn)?;
        {
            let mut table = txn.open_table(META_TABLE)?;
            table.insert(META_KEY, migrated_meta.as_slice())?;
        }
        before_commit()?;
        txn.commit()?;
        Ok(())
    }

    pub fn migrate_legacy_composite_wallet_keys(&self) -> Result<(), DbError> {
        let txn = self.db.begin_write()?;
        migrations::migrate_legacy_composite_wallet_keys(&txn)?;
        txn.commit()?;
        Ok(())
    }
}

fn open_database_lock(path: &Path) -> Result<File, DbError> {
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = std::fs::symlink_metadata(path)?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "database lock path is not a regular file",
                )
                .into());
            }
            let file = OpenOptions::new().read(true).write(true).open(path)?;
            if !file.metadata()?.is_file() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "database lock path is not a regular file",
                )
                .into());
            }
            Ok(file)
        }
        Err(error) => Err(error.into()),
    }
}

fn validate_database_path(path: &Path) -> Result<(), DbError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "database path is not a regular file",
        )
        .into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn railgun_dir(root_dir: &Path) -> PathBuf {
    root_dir.join(RAILGUN_DIR)
}

fn db_lock_path(root_dir: &Path) -> PathBuf {
    railgun_dir(root_dir).join("db.lock")
}

fn db_path(root_dir: &Path) -> PathBuf {
    railgun_dir(root_dir).join("db.redb")
}

fn blobs_dir(root_dir: &Path) -> PathBuf {
    railgun_dir(root_dir).join(BLOBS_DIR)
}

fn backup_db(db_path: &Path) -> Result<(), DbError> {
    let ts = now_epoch_secs()?;
    let file_name = format!("db.redb.bak.{ts}");
    let backup_path = db_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(file_name);
    std::fs::rename(db_path, backup_path)?;
    Ok(())
}

fn now_epoch_secs() -> Result<u64, DbError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(std::io::Error::other)?;
    Ok(now.as_secs())
}

#[cfg(test)]
mod tests;
