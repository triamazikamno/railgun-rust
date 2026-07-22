use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fmt::{self, Display};
use std::fs::{File, OpenOptions, TryLockError};
use std::io::Write;
use std::ops::Deref;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::hex;
use alloy::primitives::{Address, FixedBytes, U256, keccak256};
use broadcaster_core::transact::{FeeNoteAssuranceContext, PreTxPoi, railgun_txid_leaf_hash};
use redb::{
    Database, ReadTransaction, ReadableDatabase, ReadableTable, ReadableTableMetadata, Table,
    TableDefinition, TableHandle, WriteTransaction,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

mod migrations;

type ByteTableDefinition = TableDefinition<'static, &'static str, &'static [u8]>;

const META_TABLE: ByteTableDefinition = TableDefinition::new("meta");
const BLOB_INDEX_TABLE: ByteTableDefinition = TableDefinition::new("blob_index");
const MERKLE_FOREST_INDEX_TABLE: ByteTableDefinition = TableDefinition::new("merkle_forest_index");
const ZKEY_INDEX_TABLE: ByteTableDefinition = TableDefinition::new("zkey_index");
const WALLET_UTXO_TABLE: ByteTableDefinition = TableDefinition::new("wallet_utxo");
const WALLET_META_TABLE: ByteTableDefinition = TableDefinition::new("wallet_meta");
const WALLET_SYNC_ACTOR_STATE_TABLE: ByteTableDefinition =
    TableDefinition::new("wallet_sync_actor_state_v1");
const PENDING_FEE_NOTE_ASSURANCE_TABLE: ByteTableDefinition =
    TableDefinition::new("fee_note_assurance_pending");
const TERMINAL_FEE_NOTE_ASSURANCE_TABLE: ByteTableDefinition =
    TableDefinition::new("fee_note_assurance_terminal");
const PENDING_OUTPUT_POI_CONTEXT_TABLE: ByteTableDefinition =
    TableDefinition::new("pending_output_poi_context");
const OUTPUT_POI_RECOVERY_TABLE: ByteTableDefinition = TableDefinition::new("output_poi_recovery");
const PENDING_OUTPUT_POI_CONTEXT_V2_TABLE: ByteTableDefinition =
    TableDefinition::new("pending_output_poi_context_v2");
const OUTPUT_POI_RECOVERY_V2_TABLE: ByteTableDefinition =
    TableDefinition::new("output_poi_recovery_v2");
const POI_ARTIFACT_CACHE_TABLE: ByteTableDefinition = TableDefinition::new("poi_artifact_cache");
const APP_SETTINGS_TABLE: ByteTableDefinition = TableDefinition::new("app_settings_v1");
const POI_ARTIFACT_CACHE_GENERATION_KEY: &str = "poi_artifact_cache_generation";
const POI_PUBLISHER_MANIFEST_WATERMARK_KEY_PREFIX: &str =
    "railgun:ppoi-sidecar:v1:publisher-manifest-watermark:";
const POI_CORPUS_RPC_HEALTH_KEY_PREFIX: &str = "railgun:ppoi-sidecar:v1:corpus-rpc-health:";
const DESKTOP_WALLET_VAULT_TABLE: ByteTableDefinition =
    TableDefinition::new("desktop_wallet_vault_v1");
const LEGACY_DESKTOP_WALLET_CACHE_ROW_PREFIX: &str = "wallet-cache-row|";
const WALLET_CACHE_KEY_DOMAIN: &[u8] = b"railgun-wallet-cache-key-v1";
const WALLET_PRIVATE_CANONICALIZATION_VERSION_KEY_PREFIX: &str =
    "wallet_private_canonicalization_version_v1:";
static BLOB_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalDbTable {
    Meta,
    BlobIndex,
    MerkleForestIndex,
    ZkeyIndex,
    WalletUtxo,
    WalletMeta,
    WalletSyncActorState,
    PendingFeeNoteAssurance,
    TerminalFeeNoteAssurance,
    PendingOutputPoiContextV1,
    OutputPoiRecoveryV1,
    PendingOutputPoiContextV2,
    OutputPoiRecoveryV2,
    PoiArtifactCache,
    AppSettings,
    DesktopWalletVault,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalDbTableDecodeKind {
    Meta,
    BlobMeta,
    MerkleForestMeta,
    ZkeyMeta,
    WalletUtxo,
    WalletMeta,
    WalletSyncActorState,
    PendingFeeNoteAssurance,
    TerminalFeeNoteAssurance,
    PendingOutputPoiContextV1,
    OutputPoiRecoveryV1,
    OpaqueBytes,
    PoiArtifactCache,
    AppSettings,
    DesktopWalletVault,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalDbTableInfo {
    pub table: LocalDbTable,
    pub name: &'static str,
    pub decode_kind: LocalDbTableDecodeKind,
}

pub const LOCAL_DB_TABLES: &[LocalDbTableInfo] = &[
    LocalDbTableInfo {
        table: LocalDbTable::Meta,
        name: "meta",
        decode_kind: LocalDbTableDecodeKind::Meta,
    },
    LocalDbTableInfo {
        table: LocalDbTable::BlobIndex,
        name: "blob_index",
        decode_kind: LocalDbTableDecodeKind::BlobMeta,
    },
    LocalDbTableInfo {
        table: LocalDbTable::MerkleForestIndex,
        name: "merkle_forest_index",
        decode_kind: LocalDbTableDecodeKind::MerkleForestMeta,
    },
    LocalDbTableInfo {
        table: LocalDbTable::ZkeyIndex,
        name: "zkey_index",
        decode_kind: LocalDbTableDecodeKind::ZkeyMeta,
    },
    LocalDbTableInfo {
        table: LocalDbTable::WalletUtxo,
        name: "wallet_utxo",
        decode_kind: LocalDbTableDecodeKind::WalletUtxo,
    },
    LocalDbTableInfo {
        table: LocalDbTable::WalletMeta,
        name: "wallet_meta",
        decode_kind: LocalDbTableDecodeKind::WalletMeta,
    },
    LocalDbTableInfo {
        table: LocalDbTable::WalletSyncActorState,
        name: "wallet_sync_actor_state_v1",
        decode_kind: LocalDbTableDecodeKind::WalletSyncActorState,
    },
    LocalDbTableInfo {
        table: LocalDbTable::PendingFeeNoteAssurance,
        name: "fee_note_assurance_pending",
        decode_kind: LocalDbTableDecodeKind::PendingFeeNoteAssurance,
    },
    LocalDbTableInfo {
        table: LocalDbTable::TerminalFeeNoteAssurance,
        name: "fee_note_assurance_terminal",
        decode_kind: LocalDbTableDecodeKind::TerminalFeeNoteAssurance,
    },
    LocalDbTableInfo {
        table: LocalDbTable::PendingOutputPoiContextV1,
        name: "pending_output_poi_context",
        decode_kind: LocalDbTableDecodeKind::PendingOutputPoiContextV1,
    },
    LocalDbTableInfo {
        table: LocalDbTable::OutputPoiRecoveryV1,
        name: "output_poi_recovery",
        decode_kind: LocalDbTableDecodeKind::OutputPoiRecoveryV1,
    },
    LocalDbTableInfo {
        table: LocalDbTable::PendingOutputPoiContextV2,
        name: "pending_output_poi_context_v2",
        decode_kind: LocalDbTableDecodeKind::OpaqueBytes,
    },
    LocalDbTableInfo {
        table: LocalDbTable::OutputPoiRecoveryV2,
        name: "output_poi_recovery_v2",
        decode_kind: LocalDbTableDecodeKind::OpaqueBytes,
    },
    LocalDbTableInfo {
        table: LocalDbTable::PoiArtifactCache,
        name: "poi_artifact_cache",
        decode_kind: LocalDbTableDecodeKind::PoiArtifactCache,
    },
    LocalDbTableInfo {
        table: LocalDbTable::AppSettings,
        name: "app_settings_v1",
        decode_kind: LocalDbTableDecodeKind::AppSettings,
    },
    LocalDbTableInfo {
        table: LocalDbTable::DesktopWalletVault,
        name: "desktop_wallet_vault_v1",
        decode_kind: LocalDbTableDecodeKind::DesktopWalletVault,
    },
];

impl LocalDbTable {
    #[must_use]
    pub const fn definition(self) -> TableDefinition<'static, &'static str, &'static [u8]> {
        match self {
            Self::Meta => META_TABLE,
            Self::BlobIndex => BLOB_INDEX_TABLE,
            Self::MerkleForestIndex => MERKLE_FOREST_INDEX_TABLE,
            Self::ZkeyIndex => ZKEY_INDEX_TABLE,
            Self::WalletUtxo => WALLET_UTXO_TABLE,
            Self::WalletMeta => WALLET_META_TABLE,
            Self::WalletSyncActorState => WALLET_SYNC_ACTOR_STATE_TABLE,
            Self::PendingFeeNoteAssurance => PENDING_FEE_NOTE_ASSURANCE_TABLE,
            Self::TerminalFeeNoteAssurance => TERMINAL_FEE_NOTE_ASSURANCE_TABLE,
            Self::PendingOutputPoiContextV1 => PENDING_OUTPUT_POI_CONTEXT_TABLE,
            Self::OutputPoiRecoveryV1 => OUTPUT_POI_RECOVERY_TABLE,
            Self::PendingOutputPoiContextV2 => PENDING_OUTPUT_POI_CONTEXT_V2_TABLE,
            Self::OutputPoiRecoveryV2 => OUTPUT_POI_RECOVERY_V2_TABLE,
            Self::PoiArtifactCache => POI_ARTIFACT_CACHE_TABLE,
            Self::AppSettings => APP_SETTINGS_TABLE,
            Self::DesktopWalletVault => DESKTOP_WALLET_VAULT_TABLE,
        }
    }
}

impl LocalDbTableInfo {
    #[must_use]
    pub fn by_name(name: &str) -> Option<Self> {
        LOCAL_DB_TABLES
            .iter()
            .copied()
            .find(|table| table.name == name)
    }
}

const META_KEY: &str = "meta";
const WALLET_PRIVATE_COMPACTION_REQUESTED_KEY: &str = "wallet_private_compaction_requested_v1";
const RAILGUN_DIR: &str = "railgun";
const BLOBS_DIR: &str = "blobs";

pub const CURRENT_SCHEMA_VERSION: u32 = 10;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WalletCacheKey(String);

impl WalletCacheKey {
    #[must_use]
    pub fn new(wallet_id: &str, chain_id: u64, contract: Address) -> Self {
        let wallet_id = wallet_id.as_bytes();
        let mut bytes = Vec::with_capacity(
            WALLET_CACHE_KEY_DOMAIN.len() + 8 + wallet_id.len() + 8 + contract.len(),
        );
        bytes.extend_from_slice(WALLET_CACHE_KEY_DOMAIN);
        bytes.extend_from_slice(&(wallet_id.len() as u64).to_be_bytes());
        bytes.extend_from_slice(wallet_id);
        bytes.extend_from_slice(&chain_id.to_be_bytes());
        bytes.extend_from_slice(contract.as_slice());
        Self(hex::encode(bytes))
    }

    #[must_use]
    pub fn from_opaque_id(id: [u8; 16]) -> Self {
        Self(hex::encode(id))
    }

    pub fn from_opaque_bytes(value: &[u8]) -> Result<Self, WalletCacheKeyError> {
        if value.is_empty() {
            return Err(WalletCacheKeyError);
        }
        Ok(Self(hex::encode(value)))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for WalletCacheKey {
    type Err = WalletCacheKeyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty()
            || !value.len().is_multiple_of(2)
            || value
                .bytes()
                .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            || hex::decode(value).is_err()
        {
            return Err(WalletCacheKeyError);
        }
        Ok(Self(value.to_owned()))
    }
}

impl AsRef<str> for WalletCacheKey {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Deref for WalletCacheKey {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl From<WalletCacheKey> for String {
    fn from(value: WalletCacheKey) -> Self {
        value.0
    }
}

impl Borrow<str> for WalletCacheKey {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl Display for WalletCacheKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for WalletCacheKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for WalletCacheKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
#[error("wallet cache key must be non-empty canonical lowercase hex")]
pub struct WalletCacheKeyError;

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
    #[error("invalid schema-9 PPOI corpus record {key}")]
    InvalidSchemaNinePpoiCorpusRecord { key: String },
    #[error("invalid blob relative path for kind {kind}")]
    InvalidBlobRelativePath { kind: String },
    #[error("unsafe blob entry for kind {kind}")]
    UnsafeBlobEntry { kind: String },
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobMeta {
    pub format_version: u32,
    pub relative_path: String,
    pub content_hash: [u8; 32],
    #[serde(default)]
    pub source_hash: Option<[u8; 32]>,
    #[serde(default)]
    pub source_sequence: Option<u64>,
    pub created_at: u64,
    pub updated_at: u64,
    #[serde(default)]
    pub last_accessed_at: u64,
    pub last_block: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct CanonicalBlobMetaIdentity {
    kind: String,
    leaf: String,
}

impl CanonicalBlobMetaIdentity {
    pub fn from_leaf(expected_kind: &str, leaf: &str) -> Result<Self, DbError> {
        validate_single_blob_component(expected_kind, expected_kind)?;
        validate_single_blob_component(leaf, expected_kind)?;
        Ok(Self {
            kind: expected_kind.to_string(),
            leaf: leaf.to_string(),
        })
    }

    #[must_use]
    pub fn relative_path(&self) -> String {
        Self::relative_path_for(&self.kind, &self.leaf)
    }

    fn relative_path_for(kind: &str, leaf: &str) -> String {
        format!("{BLOBS_DIR}/{kind}/{leaf}")
    }

    fn kind(&self) -> &str {
        &self.kind
    }

    fn leaf(&self) -> &str {
        &self.leaf
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleForestMeta {
    pub relative_path: String,
    pub last_block: u64,
    pub format_version: u32,
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkeyMeta {
    pub relative_path: String,
    pub zkey_hash: [u8; 32],
    #[serde(default)]
    pub cache_hash: Option<[u8; 32]>,
    pub format_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletUtxoRecord {
    pub utxo_id: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletMeta {
    pub last_scanned_block: u64,
    pub updated_at: u64,
    #[serde(default)]
    pub last_scanned_block_hash: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletPrivateNamespaceId {
    pub chain_id: u64,
    pub wallet_id: WalletCacheKey,
}

impl WalletPrivateNamespaceId {
    #[must_use]
    pub const fn new(chain_id: u64, wallet_id: WalletCacheKey) -> Self {
        Self {
            chain_id,
            wallet_id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletPrivateRecordKind {
    PendingOutputPoiContext,
    OutputPoiRecovery,
}

impl WalletPrivateRecordKind {
    const fn v1_table(self) -> ByteTableDefinition {
        match self {
            Self::PendingOutputPoiContext => PENDING_OUTPUT_POI_CONTEXT_TABLE,
            Self::OutputPoiRecovery => OUTPUT_POI_RECOVERY_TABLE,
        }
    }

    const fn v2_table(self) -> ByteTableDefinition {
        match self {
            Self::PendingOutputPoiContext => PENDING_OUTPUT_POI_CONTEXT_V2_TABLE,
            Self::OutputPoiRecovery => OUTPUT_POI_RECOVERY_V2_TABLE,
        }
    }

    const fn v1_table_name(self) -> &'static str {
        match self {
            Self::PendingOutputPoiContext => "pending_output_poi_context",
            Self::OutputPoiRecovery => "output_poi_recovery",
        }
    }

    const fn v2_table_name(self) -> &'static str {
        match self {
            Self::PendingOutputPoiContext => "pending_output_poi_context_v2",
            Self::OutputPoiRecovery => "output_poi_recovery_v2",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::PendingOutputPoiContext => "pending output POI context",
            Self::OutputPoiRecovery => "output POI recovery",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpaqueWalletPrivateRow {
    pub row_id: Vec<u8>,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OpaqueWalletPrivateRowMutation<'a> {
    pub updates: &'a [OpaqueWalletPrivateRow],
    pub deletes: &'a [Vec<u8>],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletPrivateV1Row {
    pub storage_key: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WalletPrivateV1Rows {
    pub pending_output_contexts: Vec<WalletPrivateV1Row>,
    pub output_poi_recoveries: Vec<WalletPrivateV1Row>,
}

pub struct WalletPrivateV1MigrationBatch<'a> {
    pub namespace: &'a WalletPrivateNamespaceId,
    pub pending_output_context_sources: &'a [WalletPrivateV1Row],
    pub output_poi_recovery_sources: &'a [WalletPrivateV1Row],
    pub pending_output_context_destinations: &'a [OpaqueWalletPrivateRow],
    pub output_poi_recovery_destinations: &'a [OpaqueWalletPrivateRow],
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WalletPrivateV1MigrationReport {
    pub pending_output_context_rows: u64,
    pub output_poi_recovery_rows: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct WalletPrivateCanonicalizationKindBatch<'a> {
    pub canonical_v1_sources: &'a [WalletPrivateV1Row],
    pub legacy_v1_sources: &'a [WalletPrivateV1Row],
    pub canonical_v2_sources: &'a [OpaqueWalletPrivateRow],
    pub legacy_v2_sources: &'a [OpaqueWalletPrivateRow],
    pub canonical_v2_destinations: &'a [OpaqueWalletPrivateRow],
}

pub struct WalletPrivateCanonicalizationBatch<'a> {
    pub canonical_namespace: &'a WalletPrivateNamespaceId,
    pub legacy_namespace: Option<&'a WalletPrivateNamespaceId>,
    pub target_version: u32,
    pub pending_output_contexts: WalletPrivateCanonicalizationKindBatch<'a>,
    pub output_poi_recoveries: WalletPrivateCanonicalizationKindBatch<'a>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WalletPrivateCanonicalizationReport {
    pub pending_output_context_rows: u64,
    pub output_poi_recovery_rows: u64,
    pub plaintext_rows_removed: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WalletPrivateNamespaceDeletionReport {
    pub wallet_utxo_rows: u64,
    pub wallet_meta_rows: u64,
    pub wallet_sync_actor_state_rows: u64,
    pub pending_output_poi_context_rows: u64,
    pub output_poi_recovery_rows: u64,
}

impl WalletPrivateNamespaceDeletionReport {
    const fn add_assign_saturating(&mut self, other: Self) {
        self.wallet_utxo_rows = self.wallet_utxo_rows.saturating_add(other.wallet_utxo_rows);
        self.wallet_meta_rows = self.wallet_meta_rows.saturating_add(other.wallet_meta_rows);
        self.wallet_sync_actor_state_rows = self
            .wallet_sync_actor_state_rows
            .saturating_add(other.wallet_sync_actor_state_rows);
        self.pending_output_poi_context_rows = self
            .pending_output_poi_context_rows
            .saturating_add(other.pending_output_poi_context_rows);
        self.output_poi_recovery_rows = self
            .output_poi_recovery_rows
            .saturating_add(other.output_poi_recovery_rows);
    }
}

/// Typed inputs for permanently deleting a wallet's private and vault state.
pub struct WalletDeletionBatch<'a> {
    pub private_namespaces: &'a [WalletPrivateNamespaceId],
    pub desktop_wallet_vault_delete_keys: &'a [String],
    pub desktop_wallet_vault_put_records: &'a [(String, Vec<u8>)],
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WalletDeletionReport {
    pub private_namespace_rows: WalletPrivateNamespaceDeletionReport,
    pub desktop_wallet_vault_rows_deleted: u64,
    pub desktop_wallet_vault_rows_put: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletPendingResetRecord {
    pub intent_id: u64,
    pub from_block: u64,
    #[serde(default)]
    pub replay_start_block: u64,
    #[serde(default)]
    pub replay_target_block: u64,
    #[serde(default)]
    pub follow_safe_head: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletSyncActorStateRecord {
    pub chain_id: u64,
    pub wallet_id: String,
    pub highest_accepted_reset_intent: u64,
    pub pending_reset: Option<WalletPendingResetRecord>,
    pub updated_at: u64,
}

impl WalletSyncActorStateRecord {
    #[must_use]
    pub fn key(&self) -> String {
        Self::key_for(self.chain_id, &self.wallet_id)
    }

    #[must_use]
    pub fn key_for(chain_id: u64, wallet_id: &str) -> String {
        format!("{chain_id}|{wallet_id}")
    }

    #[must_use]
    pub fn prefix_for_chain(chain_id: u64) -> String {
        format!("{chain_id}|")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PoiArtifactDescriptorRecord {
    pub cid: String,
    pub sha256: String,
    pub byte_size: u64,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum PoiCacheRecordSource {
    #[default]
    IndexedArtifacts,
    PublicRpc,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum PoiCorpusValidationRecord {
    #[default]
    Legacy,
    PublisherAttested {
        publisher_pubkey: FixedBytes<32>,
        manifest_sequence: u64,
        manifest_root: FixedBytes<32>,
        #[serde(default)]
        artifact_tip_index: u64,
    },
    ListSignedRanges {
        list_key: FixedBytes<32>,
        #[serde(default)]
        from_index: u64,
    },
    PublisherAndListSigned {
        publisher_pubkey: FixedBytes<32>,
        manifest_sequence: u64,
        manifest_root: FixedBytes<32>,
        artifact_tip_index: u64,
        list_key: FixedBytes<32>,
        list_signed_from_index: u64,
    },
    PublisherAttestedV4 {
        publisher_pubkey: FixedBytes<32>,
        manifest_sequence: u64,
        #[serde(default)]
        manifest_body_hash: Option<FixedBytes<32>>,
        manifest_root: FixedBytes<32>,
        artifact_tip_index: u64,
        format_version: u16,
        checkpoint_catalog: PoiV4CatalogIdentityRecord,
    },
    PublisherV4AndListSigned {
        publisher_pubkey: FixedBytes<32>,
        manifest_sequence: u64,
        #[serde(default)]
        manifest_body_hash: Option<FixedBytes<32>>,
        manifest_root: FixedBytes<32>,
        artifact_tip_index: u64,
        format_version: u16,
        checkpoint_catalog: PoiV4CatalogIdentityRecord,
        list_key: FixedBytes<32>,
        list_signed_from_index: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PoiV4CatalogIdentityRecord {
    pub cid: String,
    pub sha256: FixedBytes<32>,
    pub byte_size: u64,
    pub descriptor_hash: FixedBytes<32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PoiArtifactCacheRecord {
    pub chain_type: u8,
    pub chain_id: u64,
    pub txid_version: String,
    pub list_key: FixedBytes<32>,
    #[serde(default)]
    pub cache_generation: u64,
    #[serde(default)]
    pub source: PoiCacheRecordSource,
    #[serde(default)]
    pub validation: PoiCorpusValidationRecord,
    // Compatibility metadata only. The publisher watermark sidecar owns rollback protection.
    #[serde(default, rename = "last_accepted_manifest_sequence")]
    pub legacy_observed_manifest_sequence: u64,
    pub base_descriptor: PoiArtifactDescriptorRecord,
    pub applied_delta_descriptors: Vec<PoiArtifactDescriptorRecord>,
    pub blocked_shields_descriptor: PoiArtifactDescriptorRecord,
    #[serde(default)]
    pub artifact_tip_index: Option<u64>,
    #[serde(default)]
    pub artifact_tip_root: Option<FixedBytes<32>>,
    pub current_tip_index: u64,
    pub current_tip_root: FixedBytes<32>,
    pub cache_payload: Vec<u8>,
    // Compatibility metadata only. The RPC-health sidecar owns current source health.
    #[serde(default, rename = "last_successful_rpc_sync_at_ms")]
    pub legacy_last_successful_rpc_sync_at_ms: Option<u64>,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoiArtifactCacheCommitCondition {
    pub expected_generation: u64,
    pub expected_publisher: Option<(FixedBytes<32>, u64)>,
    pub expected_manifest_hash: Option<FixedBytes<32>>,
    pub expected_payload_hash: Option<FixedBytes<32>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoiArtifactCacheCommitOutcome {
    Applied,
    GenerationConflict { actual: u64 },
    PublisherSequenceConflict { actual: Option<u64> },
    PublisherManifestConflict { actual: Option<FixedBytes<32>> },
    CorpusConflict,
}

#[derive(Debug)]
pub struct PoiArtifactCacheRecordScan {
    pub records: Vec<PoiArtifactCacheRecord>,
    pub invalid_keys: Vec<String>,
}

#[derive(Debug)]
pub enum StoredRecord<T> {
    Missing,
    Valid(T),
    Corrupt { key: String },
}

impl PoiArtifactCacheRecord {
    #[must_use]
    pub fn key(&self) -> String {
        Self::key_for(
            self.chain_type,
            self.chain_id,
            &self.txid_version,
            &self.list_key,
        )
    }

    #[must_use]
    pub fn key_for(
        chain_type: u8,
        chain_id: u64,
        txid_version: &str,
        list_key: &FixedBytes<32>,
    ) -> String {
        format!(
            "{chain_type}|{chain_id}|{txid_version}|{}",
            hex::encode(list_key)
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PoiPublisherManifestWatermarkRecord {
    pub publisher_pubkey: FixedBytes<32>,
    pub accepted_sequence: u64,
    #[serde(default)]
    pub accepted_manifest_hash: Option<FixedBytes<32>>,
    pub updated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoiPublisherManifestObservation {
    Accepted {
        record: PoiPublisherManifestWatermarkRecord,
        changed: bool,
    },
    Rollback {
        record: PoiPublisherManifestWatermarkRecord,
    },
    Equivocation {
        record: PoiPublisherManifestWatermarkRecord,
    },
}

impl PoiPublisherManifestWatermarkRecord {
    #[must_use]
    pub fn key(&self) -> String {
        Self::key_for(&self.publisher_pubkey)
    }

    #[must_use]
    pub fn key_for(publisher_pubkey: &FixedBytes<32>) -> String {
        format!(
            "{POI_PUBLISHER_MANIFEST_WATERMARK_KEY_PREFIX}{}",
            hex::encode(publisher_pubkey)
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PoiCorpusRpcHealthRecord {
    pub chain_type: u8,
    pub chain_id: u64,
    pub txid_version: String,
    pub list_key: FixedBytes<32>,
    pub cache_generation: u64,
    pub last_successful_rpc_sync_at_ms: Option<u64>,
    pub updated_at: u64,
}

impl PoiCorpusRpcHealthRecord {
    #[must_use]
    pub fn key(&self) -> String {
        Self::key_for(
            self.chain_type,
            self.chain_id,
            &self.txid_version,
            &self.list_key,
        )
    }

    #[must_use]
    pub fn key_for(
        chain_type: u8,
        chain_id: u64,
        txid_version: &str,
        list_key: &FixedBytes<32>,
    ) -> String {
        format!(
            "{POI_CORPUS_RPC_HEALTH_KEY_PREFIX}{chain_type:02x}:{chain_id:016x}:{}:{}",
            hex::encode(txid_version.as_bytes()),
            hex::encode(list_key)
        )
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FeeNoteAssuranceTerminalOutcome {
    RevertedReceipt,
    CommitmentMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingFeeNoteAssuranceRecord {
    pub chain_id: u64,
    pub public_tx_hash: FixedBytes<32>,
    pub context: FeeNoteAssuranceContext,
}

impl PendingFeeNoteAssuranceRecord {
    #[must_use]
    pub fn key(&self) -> String {
        Self::key_for(self.chain_id, &self.public_tx_hash)
    }

    #[must_use]
    pub fn key_for(chain_id: u64, public_tx_hash: &FixedBytes<32>) -> String {
        format!("{chain_id}|{}", hex::encode(public_tx_hash))
    }

    #[must_use]
    pub fn prefix_for_chain(chain_id: u64) -> String {
        format!("{chain_id}|")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalFeeNoteAssuranceRecord {
    pub chain_id: u64,
    pub public_tx_hash: FixedBytes<32>,
    pub context: FeeNoteAssuranceContext,
    pub outcome: FeeNoteAssuranceTerminalOutcome,
}

impl TerminalFeeNoteAssuranceRecord {
    #[must_use]
    pub fn key(&self) -> String {
        PendingFeeNoteAssuranceRecord::key_for(self.chain_id, &self.public_tx_hash)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PendingOutputPoiRole {
    BroadcasterFee,
    Recipient,
    Change,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingOutputPoiObservation {
    pub output_tree: u64,
    pub output_position: u64,
    pub tx_hash: FixedBytes<32>,
    pub block_number: u64,
    pub block_timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingOutputPoiContextRecord {
    pub chain_id: u64,
    pub wallet_id: String,
    pub txid_version: String,
    pub output_commitment: FixedBytes<32>,
    pub output_npk: FixedBytes<32>,
    pub utxo_tree_in: u64,
    pub railgun_txid: U256,
    pub txid_merkleroot_index: Option<u64>,
    pub pre_transaction_pois_per_txid_leaf_per_list:
        BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PreTxPoi>>,
    pub required_poi_list_keys: Vec<FixedBytes<32>>,
    pub output_role: PendingOutputPoiRole,
    pub created_at: u64,
    pub source_operation_id: Option<String>,
    pub observation: Option<PendingOutputPoiObservation>,
    pub submitted_poi_list_keys: Vec<FixedBytes<32>>,
    pub terminal_error: Option<String>,
}

impl PendingOutputPoiContextRecord {
    #[must_use]
    pub fn key(&self) -> String {
        Self::key_for(self.chain_id, &self.wallet_id, &self.output_commitment)
    }

    #[must_use]
    pub fn key_for(chain_id: u64, wallet_id: &str, output_commitment: &FixedBytes<32>) -> String {
        format!("{chain_id}|{wallet_id}|{}", hex::encode(output_commitment))
    }

    #[must_use]
    pub fn prefix_for_wallet(chain_id: u64, wallet_id: &str) -> String {
        format!("{chain_id}|{wallet_id}|")
    }

    #[must_use]
    pub fn txid_leaf_hash(&self) -> Option<FixedBytes<32>> {
        if self.txid_merkleroot_index.is_none() {
            return Some(FixedBytes::from(
                railgun_txid_leaf_hash(self.railgun_txid, self.utxo_tree_in).to_be_bytes::<32>(),
            ));
        }

        let mut txid_leaf_hash = None;
        for per_leaf in self.pre_transaction_pois_per_txid_leaf_per_list.values() {
            for key in per_leaf.keys() {
                if txid_leaf_hash.is_some_and(|existing| existing != *key) {
                    return None;
                }
                txid_leaf_hash = Some(*key);
            }
        }
        txid_leaf_hash
    }

    #[must_use]
    pub fn list_keys(&self) -> Vec<FixedBytes<32>> {
        if self.required_poi_list_keys.is_empty() {
            self.pre_transaction_pois_per_txid_leaf_per_list
                .keys()
                .copied()
                .collect()
        } else {
            self.required_poi_list_keys.clone()
        }
    }

    #[must_use]
    pub fn missing_list_keys(&self) -> Vec<FixedBytes<32>> {
        self.list_keys()
            .into_iter()
            .filter(|list_key| !self.submitted_poi_list_keys.contains(list_key))
            .collect()
    }

    #[must_use]
    pub fn retain_poi_lists(
        &self,
        list_keys: &[FixedBytes<32>],
    ) -> BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PreTxPoi>> {
        list_keys
            .iter()
            .filter_map(|list_key| {
                self.pre_transaction_pois_per_txid_leaf_per_list
                    .get(list_key)
                    .cloned()
                    .map(|per_leaf| (*list_key, per_leaf))
            })
            .collect()
    }

    pub fn observe(&mut self, observation: PendingOutputPoiObservation) -> bool {
        if self.observation.as_ref() == Some(&observation) {
            return false;
        }
        self.observation = Some(observation);
        true
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum OutputPoiRecoveryStatus {
    Recoverable,
    Submitted,
    Valid,
    NotSelfOriginated,
    UnsupportedShape,
    MissingWalletInputs,
    MissingWalletOutputs,
    InputPoiNotValid,
    MissingMerkleProof,
    TxFetchFailed,
    DecodeFailed,
    ProofGenerationFailed,
    SubmitFailed,
}

impl OutputPoiRecoveryStatus {
    #[must_use]
    pub const fn is_permanent_skip(self) -> bool {
        matches!(
            self,
            Self::Valid
                | Self::NotSelfOriginated
                | Self::UnsupportedShape
                | Self::MissingWalletInputs
                | Self::MissingWalletOutputs
                | Self::DecodeFailed
        )
    }
}

#[derive(Debug, Clone)]
pub enum OutputPoiRecoveryAction {
    CacheTxInput {
        tx_input: Vec<u8>,
    },
    /// Add newly recoverable list material without changing submission/retry state.
    ExtendContext,
    Detected {
        status: OutputPoiRecoveryStatus,
        retry_after: Option<Duration>,
        last_error: Option<String>,
        increment_attempts: bool,
    },
    Submitted {
        retry_after: Duration,
    },
    SubmitFailed {
        error: String,
        retry_after: Duration,
    },
    Valid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputPoiRecoveryRecord {
    pub chain_id: u64,
    pub wallet_id: String,
    pub output_commitment: FixedBytes<32>,
    pub source_tx_hash: FixedBytes<32>,
    pub tx_input: Option<Vec<u8>>,
    pub status: OutputPoiRecoveryStatus,
    pub created_at: u64,
    pub updated_at: u64,
    pub last_detection_at: Option<u64>,
    pub last_submission_at: Option<u64>,
    pub next_retry_at: Option<u64>,
    pub attempt_count: u32,
    pub last_error: Option<String>,
}

impl OutputPoiRecoveryRecord {
    #[must_use]
    pub fn key(&self) -> String {
        Self::key_for(self.chain_id, &self.wallet_id, &self.output_commitment)
    }

    #[must_use]
    pub fn key_for(chain_id: u64, wallet_id: &str, output_commitment: &FixedBytes<32>) -> String {
        format!("{chain_id}|{wallet_id}|{}", hex::encode(output_commitment))
    }

    #[must_use]
    pub fn prefix_for_wallet(chain_id: u64, wallet_id: &str) -> String {
        format!("{chain_id}|{wallet_id}|")
    }

    #[must_use]
    pub fn retry_allowed(&self, now: u64, force_retry: bool) -> bool {
        if self.status == OutputPoiRecoveryStatus::Valid {
            return false;
        }
        if self.status.is_permanent_skip()
            && !(force_retry
                && matches!(
                    self.status,
                    OutputPoiRecoveryStatus::UnsupportedShape
                        | OutputPoiRecoveryStatus::MissingWalletOutputs
                ))
        {
            return false;
        }
        force_retry
            || self
                .next_retry_at
                .is_none_or(|next_retry_at| next_retry_at <= now)
    }

    #[must_use]
    pub fn submission_retry_allowed(&self, now: u64, force_retry: bool) -> bool {
        matches!(
            self.status,
            OutputPoiRecoveryStatus::Submitted
                | OutputPoiRecoveryStatus::SubmitFailed
                | OutputPoiRecoveryStatus::Recoverable
        ) && (force_retry
            || self
                .next_retry_at
                .is_some_and(|next_retry_at| next_retry_at <= now))
    }

    pub fn apply_action(&mut self, action: OutputPoiRecoveryAction, now: u64) {
        match action {
            OutputPoiRecoveryAction::CacheTxInput { tx_input } => {
                self.tx_input = Some(tx_input);
                self.updated_at = now;
                self.last_detection_at = Some(now);
            }
            OutputPoiRecoveryAction::ExtendContext => {}
            OutputPoiRecoveryAction::Detected {
                status,
                retry_after,
                last_error,
                increment_attempts,
            } => {
                self.status = status;
                self.updated_at = now;
                self.last_detection_at = Some(now);
                self.next_retry_at =
                    retry_after.map(|duration| now.saturating_add(duration.as_secs()));
                self.last_error = last_error;
                if increment_attempts {
                    self.attempt_count = self.attempt_count.saturating_add(1);
                }
            }
            OutputPoiRecoveryAction::Submitted { retry_after } => {
                self.status = OutputPoiRecoveryStatus::Submitted;
                self.updated_at = now;
                self.last_submission_at = Some(now);
                self.next_retry_at = Some(now.saturating_add(retry_after.as_secs()));
                self.last_error = None;
                self.attempt_count = self.attempt_count.saturating_add(1);
            }
            OutputPoiRecoveryAction::SubmitFailed { error, retry_after } => {
                self.status = OutputPoiRecoveryStatus::SubmitFailed;
                self.updated_at = now;
                self.next_retry_at = Some(now.saturating_add(retry_after.as_secs()));
                self.last_error = Some(error);
                self.attempt_count = self.attempt_count.saturating_add(1);
            }
            OutputPoiRecoveryAction::Valid => {
                self.status = OutputPoiRecoveryStatus::Valid;
                self.updated_at = now;
                self.next_retry_at = None;
                self.last_error = None;
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum WalletUtxoRowMutation<'a> {
    Preserve,
    Replace(&'a [(String, Vec<u8>)]),
}

#[derive(Debug, Clone, Copy)]
pub enum WalletMetaMutation<'a> {
    Preserve,
    Set(&'a WalletMeta),
}

pub struct WalletPrivateStateBatch<'a> {
    pub namespace: &'a WalletPrivateNamespaceId,
    pub utxos: WalletUtxoRowMutation<'a>,
    pub metadata: WalletMetaMutation<'a>,
    pub sync_actor_state: Option<&'a WalletSyncActorStateRecord>,
    pub pending_output_contexts: OpaqueWalletPrivateRowMutation<'a>,
    pub output_poi_recoveries: OpaqueWalletPrivateRowMutation<'a>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DesktopWalletVaultRecord {
    pub key: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppSettingsRecord {
    pub key: String,
    pub payload: Vec<u8>,
}

impl DbStore {
    pub fn open(config: DbConfig) -> Result<Self, DbError> {
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
            let db = if db_path.exists() {
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
                    drop(store);
                    backup_db(&db_path)?;
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

    pub fn ensure_blob_dir(&self, kind: &str) -> Result<PathBuf, DbError> {
        validate_single_blob_component(kind, kind)?;
        ensure_storage_directory(&self.blob_dir(), BLOBS_DIR)?;
        let dir = self.blob_dir().join(kind);
        ensure_storage_directory(&dir, kind)?;
        Ok(dir)
    }

    #[must_use]
    pub fn blob_path(&self, kind: &str, name: &str) -> PathBuf {
        self.blob_dir().join(kind).join(name)
    }

    #[must_use]
    pub fn resolve_path(&self, relative_path: &str) -> PathBuf {
        let path = PathBuf::from(relative_path);
        if path.is_absolute() {
            path
        } else {
            self.railgun_dir().join(path)
        }
    }

    #[must_use]
    pub fn relative_path(&self, path: &Path) -> String {
        if let Ok(relative) = path.strip_prefix(self.railgun_dir()) {
            relative.to_string_lossy().to_string()
        } else {
            path.to_string_lossy().to_string()
        }
    }

    #[must_use]
    pub fn relative_blob_path(kind: &str, name: &str) -> String {
        format!("{BLOBS_DIR}/{kind}/{name}")
    }

    pub fn open_blob_meta_file(
        &self,
        identity: &CanonicalBlobMetaIdentity,
    ) -> Result<Option<File>, DbError> {
        let kind_dir = self.blob_dir().join(identity.kind());
        if !validate_existing_blob_directory(&kind_dir, identity.kind())? {
            return Ok(None);
        }
        let path = kind_dir.join(identity.leaf());
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(DbError::UnsafeBlobEntry {
                kind: identity.kind().to_string(),
            });
        }
        let file = File::open(path)?;
        Ok(Some(file))
    }

    pub fn replace_blob_file_atomic(
        &self,
        kind: &str,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), DbError> {
        self.replace_blob_file_atomic_impl(kind, name, bytes, None)
    }

    pub fn purge_blob_kind(&self, kind: &str) -> Result<(), DbError> {
        self.ensure_blob_kind_purge_supported(kind)?;
        ensure_storage_directory(&self.blob_dir(), BLOBS_DIR)?;
        let kind_dir = self.blob_dir().join(kind);
        match std::fs::symlink_metadata(&kind_dir) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                std::fs::remove_dir_all(&kind_dir)?;
            }
            Ok(_metadata) => {
                #[cfg(windows)]
                {
                    use std::os::windows::fs::FileTypeExt;

                    if _metadata.file_type().is_symlink_dir() {
                        std::fs::remove_dir(&kind_dir)?;
                    } else {
                        std::fs::remove_file(&kind_dir)?;
                    }
                }
                #[cfg(not(windows))]
                std::fs::remove_file(&kind_dir)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        ensure_storage_directory(&kind_dir, kind)
    }

    pub fn ensure_blob_kind_purge_supported(&self, kind: &str) -> Result<(), DbError> {
        validate_single_blob_component(kind, kind)
    }

    fn replace_blob_file_atomic_impl(
        &self,
        kind: &str,
        name: &str,
        bytes: &[u8],
        forced_temp_name: Option<&str>,
    ) -> Result<(), DbError> {
        validate_single_blob_component(kind, kind)?;
        validate_single_blob_component(name, kind)?;
        if let Some(temp_name) = forced_temp_name {
            validate_single_blob_component(temp_name, kind)?;
        }
        let parent = self.ensure_blob_dir(kind)?;
        let (temp_path, mut temp_file) = loop {
            let temp_name = forced_temp_name.map_or_else(
                || {
                    let nonce = BLOB_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
                    format!(".railgun-blob-{}-{nonce}.tmp", std::process::id())
                },
                ToString::to_string,
            );
            let temp_path = parent.join(temp_name);
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)
            {
                Ok(file) => break (temp_path, file),
                Err(error)
                    if forced_temp_name.is_none()
                        && error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        };
        let mut guard = BlobTempGuard::new(temp_path);
        temp_file.write_all(bytes)?;
        drop(temp_file);
        let final_path = parent.join(name);
        validate_blob_replace_destination(&final_path, kind)?;
        std::fs::rename(guard.path(), final_path)?;
        guard.disarm();
        Ok(())
    }

    #[cfg(test)]
    fn replace_blob_file_atomic_with_test_temp_name(
        &self,
        kind: &str,
        name: &str,
        bytes: &[u8],
        temp_name: &str,
    ) -> Result<(), DbError> {
        self.replace_blob_file_atomic_impl(kind, name, bytes, Some(temp_name))
    }

    fn list_decoded_by_prefix<T>(
        &self,
        table_def: TableDefinition<'static, &str, &[u8]>,
        prefix: &str,
    ) -> Result<Vec<T>, DbError>
    where
        T: DeserializeOwned,
    {
        let range_end = prefix_range_end(prefix);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(table_def)?;
        let mut out = Vec::new();
        let entries = match range_end.as_deref() {
            Some(range_end) => table.range(prefix..range_end)?,
            None => table.range(prefix..)?,
        };
        for entry in entries {
            let (_, value) = entry?;
            out.push(decode(value.value())?);
        }
        Ok(out)
    }

    pub fn get_blob_meta(&self, kind: &str, id: &str) -> Result<Option<BlobMeta>, DbError> {
        let key = blob_index_key(kind, id);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(BLOB_INDEX_TABLE)?;
        match table.get(key.as_str())? {
            Some(value) => Ok(Some(decode(value.value())?)),
            None => Ok(None),
        }
    }

    pub fn put_blob_meta(&self, kind: &str, id: &str, meta: &BlobMeta) -> Result<(), DbError> {
        let key = blob_index_key(kind, id);
        let data = encode(meta)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(BLOB_INDEX_TABLE)?;
            table.insert(key.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn clear_blob_meta_kind(&self, kind: &str) -> Result<u64, DbError> {
        let prefix = format!("{kind}|");
        let range_end = prefix_range_end(&prefix);
        let txn = self.db.begin_write()?;
        let removed = {
            let mut table = txn.open_table(BLOB_INDEX_TABLE)?;
            let mut removed = 0_u64;
            let mut retain = |_: &str, _: &[u8]| {
                removed = removed.saturating_add(1);
                false
            };
            match range_end.as_deref() {
                Some(range_end) => {
                    table.retain_in(prefix.as_str()..range_end, &mut retain)?;
                }
                None => {
                    table.retain_in(prefix.as_str().., &mut retain)?;
                }
            }
            removed
        };
        txn.commit()?;
        Ok(removed)
    }

    pub fn get_merkle_forest_meta(
        &self,
        chain_id: u64,
        contract: &str,
    ) -> Result<Option<MerkleForestMeta>, DbError> {
        let key = merkle_forest_key(chain_id, contract);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(MERKLE_FOREST_INDEX_TABLE)?;
        match table.get(key.as_str())? {
            Some(value) => Ok(Some(decode(value.value())?)),
            None => Ok(None),
        }
    }

    pub fn put_merkle_forest_meta(
        &self,
        chain_id: u64,
        contract: &str,
        meta: &MerkleForestMeta,
    ) -> Result<(), DbError> {
        let key = merkle_forest_key(chain_id, contract);
        let data = encode(meta)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(MERKLE_FOREST_INDEX_TABLE)?;
            table.insert(key.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get_zkey_meta(&self, variant: &str) -> Result<Option<ZkeyMeta>, DbError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(ZKEY_INDEX_TABLE)?;
        match table.get(variant)? {
            Some(value) => Ok(Some(decode(value.value())?)),
            None => Ok(None),
        }
    }

    pub fn put_zkey_meta(&self, variant: &str, meta: &ZkeyMeta) -> Result<(), DbError> {
        let data = encode(meta)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(ZKEY_INDEX_TABLE)?;
            table.insert(variant, data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn put_wallet_utxo(
        &self,
        wallet_id: &WalletCacheKey,
        utxo_id: &str,
        payload: &[u8],
    ) -> Result<(), DbError> {
        let key = wallet_utxo_key(wallet_id, utxo_id);
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(WALLET_UTXO_TABLE)?;
            table.insert(key.as_str(), payload)?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn delete_wallet_utxo(
        &self,
        wallet_id: &WalletCacheKey,
        utxo_id: &str,
    ) -> Result<(), DbError> {
        let key = wallet_utxo_key(wallet_id, utxo_id);
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(WALLET_UTXO_TABLE)?;
            table.remove(key.as_str())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn clear_wallet_utxos(&self, wallet_id: &WalletCacheKey) -> Result<(), DbError> {
        let prefix = wallet_utxo_prefix(wallet_id);
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(WALLET_UTXO_TABLE)?;
            remove_table_prefix(&mut table, &prefix)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Atomically replace all UTXO entries for a wallet and update its
    /// metadata in a single transaction. This prevents partial state if the
    /// process is interrupted mid-write.
    pub fn batch_store_wallet_utxos(
        &self,
        wallet_id: &WalletCacheKey,
        utxos: &[(String, Vec<u8>)],
        meta: Option<&WalletMeta>,
    ) -> Result<(), DbError> {
        let prefix = wallet_utxo_prefix(wallet_id);
        let txn = self.db.begin_write()?;
        {
            let mut utxo_table = txn.open_table(WALLET_UTXO_TABLE)?;
            remove_table_prefix(&mut utxo_table, &prefix)?;
            for (utxo_id, payload) in utxos {
                let key = wallet_utxo_key(wallet_id, utxo_id);
                utxo_table.insert(key.as_str(), payload.as_slice())?;
            }
            if let Some(meta) = meta {
                let data = encode(meta)?;
                let mut meta_table = txn.open_table(WALLET_META_TABLE)?;
                meta_table.insert(wallet_id.as_str(), data.as_slice())?;
            }
        }
        txn.commit()?;
        Ok(())
    }

    pub fn batch_commit_wallet_private_state(
        &self,
        batch: &WalletPrivateStateBatch<'_>,
    ) -> Result<(), DbError> {
        self.batch_commit_wallet_private_state_with_vault_records(batch, &[])
    }

    pub fn batch_commit_wallet_private_state_with_vault_records(
        &self,
        batch: &WalletPrivateStateBatch<'_>,
        vault_records: &[DesktopWalletVaultRecord],
    ) -> Result<(), DbError> {
        self.batch_commit_wallet_private_state_with_vault_records_transaction(
            batch,
            vault_records,
            || Ok(()),
        )
    }

    fn batch_commit_wallet_private_state_with_vault_records_transaction(
        &self,
        batch: &WalletPrivateStateBatch<'_>,
        vault_records: &[DesktopWalletVaultRecord],
        before_commit: impl FnOnce() -> Result<(), DbError>,
    ) -> Result<(), DbError> {
        Self::validate_wallet_private_state_batch(batch)?;
        let txn = self.db.begin_write()?;
        Self::write_wallet_private_state_batch(&txn, batch)?;
        if !vault_records.is_empty() {
            let mut table = txn.open_table(DESKTOP_WALLET_VAULT_TABLE)?;
            for record in vault_records {
                table.insert(record.key.as_str(), record.payload.as_slice())?;
            }
        }
        before_commit()?;
        txn.commit()?;
        Ok(())
    }

    fn validate_wallet_private_state_batch(
        batch: &WalletPrivateStateBatch<'_>,
    ) -> Result<(), DbError> {
        let wallet_id = &batch.namespace.wallet_id;
        let chain_id = batch.namespace.chain_id;
        if let Some(state) = batch.sync_actor_state
            && (state.chain_id != chain_id || state.wallet_id != wallet_id.as_str())
        {
            return Err(DbError::InvalidWalletPrivateCommitNamespace {
                expected_chain_id: chain_id,
                expected_wallet_id: wallet_id.to_string(),
                actual_chain_id: state.chain_id,
                actual_wallet_id: state.wallet_id.clone(),
            });
        }
        validate_opaque_row_mutation(&batch.pending_output_contexts)?;
        validate_opaque_row_mutation(&batch.output_poi_recoveries)?;
        Ok(())
    }

    fn write_wallet_private_state_batch(
        txn: &WriteTransaction,
        batch: &WalletPrivateStateBatch<'_>,
    ) -> Result<(), DbError> {
        let wallet_id = &batch.namespace.wallet_id;
        let prefix = wallet_utxo_prefix(wallet_id);
        if let WalletUtxoRowMutation::Replace(utxos) = batch.utxos {
            let mut utxo_table = txn.open_table(WALLET_UTXO_TABLE)?;
            remove_table_prefix(&mut utxo_table, &prefix)?;
            for (utxo_id, payload) in utxos {
                let key = wallet_utxo_key(wallet_id, utxo_id);
                utxo_table.insert(key.as_str(), payload.as_slice())?;
            }
        }

        if let WalletMetaMutation::Set(meta) = batch.metadata {
            let data = encode(meta)?;
            let mut meta_table = txn.open_table(WALLET_META_TABLE)?;
            meta_table.insert(wallet_id.as_str(), data.as_slice())?;
        }

        if let Some(state) = batch.sync_actor_state {
            let key = state.key();
            let data = encode(state)?;
            let mut state_table = txn.open_table(WALLET_SYNC_ACTOR_STATE_TABLE)?;
            state_table.insert(key.as_str(), data.as_slice())?;
        }

        Self::write_opaque_wallet_private_rows(
            txn,
            batch.namespace,
            WalletPrivateRecordKind::PendingOutputPoiContext,
            batch.pending_output_contexts,
        )?;
        Self::write_opaque_wallet_private_rows(
            txn,
            batch.namespace,
            WalletPrivateRecordKind::OutputPoiRecovery,
            batch.output_poi_recoveries,
        )?;
        Ok(())
    }

    fn write_opaque_wallet_private_rows(
        txn: &WriteTransaction,
        namespace: &WalletPrivateNamespaceId,
        kind: WalletPrivateRecordKind,
        mutation: OpaqueWalletPrivateRowMutation<'_>,
    ) -> Result<(), DbError> {
        if mutation.updates.is_empty() && mutation.deletes.is_empty() {
            return Ok(());
        }
        let mut table = txn.open_table(kind.v2_table())?;
        for row in mutation.updates {
            let key = opaque_wallet_private_row_key(namespace, &row.row_id)?;
            table.insert(key.as_str(), row.payload.as_slice())?;
        }
        for row_id in mutation.deletes {
            let key = opaque_wallet_private_row_key(namespace, row_id)?;
            table.remove(key.as_str())?;
        }
        Ok(())
    }

    pub fn delete_wallet_private_namespace(
        &self,
        identity: &WalletPrivateNamespaceId,
    ) -> Result<WalletPrivateNamespaceDeletionReport, DbError> {
        self.delete_wallet_private_namespace_transaction(identity, || Ok(()))
    }

    fn delete_wallet_private_namespace_transaction(
        &self,
        identity: &WalletPrivateNamespaceId,
        before_commit: impl FnOnce() -> Result<(), DbError>,
    ) -> Result<WalletPrivateNamespaceDeletionReport, DbError> {
        let txn = self.db.begin_write()?;
        let report = Self::delete_wallet_private_namespace_in_transaction(&txn, identity)?;
        before_commit()?;
        txn.commit()?;
        Ok(report)
    }

    fn delete_wallet_private_namespace_in_transaction(
        txn: &WriteTransaction,
        identity: &WalletPrivateNamespaceId,
    ) -> Result<WalletPrivateNamespaceDeletionReport, DbError> {
        let wallet_utxo_prefix = wallet_utxo_prefix(&identity.wallet_id);
        let wallet_sync_actor_state_key =
            WalletSyncActorStateRecord::key_for(identity.chain_id, identity.wallet_id.as_str());
        let pending_output_poi_context_prefix = PendingOutputPoiContextRecord::prefix_for_wallet(
            identity.chain_id,
            identity.wallet_id.as_str(),
        );
        let chain_wallet_namespace = format!("{}|{}", identity.chain_id, identity.wallet_id);
        let output_poi_recovery_prefix = OutputPoiRecoveryRecord::prefix_for_wallet(
            identity.chain_id,
            identity.wallet_id.as_str(),
        );
        let opaque_prefix = opaque_wallet_private_row_prefix(identity);
        {
            let mut table = txn.open_table(META_TABLE)?;
            let marker_key = wallet_private_canonicalization_version_key(identity);
            table.remove(marker_key.as_str())?;
        }
        Ok({
            let wallet_utxo_rows = {
                let mut table = txn.open_table(WALLET_UTXO_TABLE)?;
                remove_table_prefix(&mut table, &wallet_utxo_prefix)?
            };
            let wallet_meta_rows = {
                let mut table = txn.open_table(WALLET_META_TABLE)?;
                u64::from(table.remove(identity.wallet_id.as_str())?.is_some())
            };
            let wallet_sync_actor_state_rows = {
                let mut table = txn.open_table(WALLET_SYNC_ACTOR_STATE_TABLE)?;
                u64::from(
                    table
                        .remove(wallet_sync_actor_state_key.as_str())?
                        .is_some(),
                )
            };
            let pending_output_poi_context_rows = {
                let mut table = txn.open_table(PENDING_OUTPUT_POI_CONTEXT_TABLE)?;
                let v1_rows = remove_table_prefix_matching(
                    &mut table,
                    &pending_output_poi_context_prefix,
                    |key| {
                        key.rsplit_once('|').is_some_and(|(namespace, _)| {
                            namespace == chain_wallet_namespace.as_str()
                        })
                    },
                )?;
                let mut table = txn.open_table(PENDING_OUTPUT_POI_CONTEXT_V2_TABLE)?;
                v1_rows.saturating_add(remove_table_prefix(&mut table, &opaque_prefix)?)
            };
            let output_poi_recovery_rows = {
                let mut table = txn.open_table(OUTPUT_POI_RECOVERY_TABLE)?;
                let v1_rows =
                    remove_table_prefix_matching(&mut table, &output_poi_recovery_prefix, |key| {
                        key.rsplit_once('|').is_some_and(|(namespace, _)| {
                            namespace == chain_wallet_namespace.as_str()
                        })
                    })?;
                let mut table = txn.open_table(OUTPUT_POI_RECOVERY_V2_TABLE)?;
                v1_rows.saturating_add(remove_table_prefix(&mut table, &opaque_prefix)?)
            };
            WalletPrivateNamespaceDeletionReport {
                wallet_utxo_rows,
                wallet_meta_rows,
                wallet_sync_actor_state_rows,
                pending_output_poi_context_rows,
                output_poi_recovery_rows,
            }
        })
    }

    /// Applies all namespace and desktop-vault mutations in one write transaction.
    pub fn delete_wallet(
        &self,
        batch: &WalletDeletionBatch<'_>,
    ) -> Result<WalletDeletionReport, DbError> {
        self.delete_wallet_transaction(batch, || Ok(()))
    }

    fn delete_wallet_transaction(
        &self,
        batch: &WalletDeletionBatch<'_>,
        before_commit: impl FnOnce() -> Result<(), DbError>,
    ) -> Result<WalletDeletionReport, DbError> {
        let txn = self.db.begin_write()?;
        let mut report = WalletDeletionReport::default();
        for identity in batch.private_namespaces {
            let namespace_report =
                Self::delete_wallet_private_namespace_in_transaction(&txn, identity)?;
            report
                .private_namespace_rows
                .add_assign_saturating(namespace_report);
        }
        {
            let mut table = txn.open_table(DESKTOP_WALLET_VAULT_TABLE)?;
            for key in batch.desktop_wallet_vault_delete_keys {
                if table.remove(key.as_str())?.is_some() {
                    report.desktop_wallet_vault_rows_deleted =
                        report.desktop_wallet_vault_rows_deleted.saturating_add(1);
                }
            }
            for (key, payload) in batch.desktop_wallet_vault_put_records {
                table.insert(key.as_str(), payload.as_slice())?;
                report.desktop_wallet_vault_rows_put =
                    report.desktop_wallet_vault_rows_put.saturating_add(1);
            }
        }
        before_commit()?;
        txn.commit()?;
        Ok(report)
    }

    pub fn list_wallet_utxos(
        &self,
        wallet_id: &WalletCacheKey,
    ) -> Result<Vec<WalletUtxoRecord>, DbError> {
        let prefix = wallet_utxo_prefix(wallet_id);
        let range_end = prefix_range_end(&prefix);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(WALLET_UTXO_TABLE)?;
        let mut out = Vec::new();
        let entries = match range_end.as_deref() {
            Some(range_end) => table.range(prefix.as_str()..range_end)?,
            None => table.range(prefix.as_str()..)?,
        };
        for entry in entries {
            let (key, value) = entry?;
            let key = key.value();
            let utxo_id = key.strip_prefix(&prefix).unwrap_or(key).to_string();
            out.push(WalletUtxoRecord {
                utxo_id,
                payload: value.value().to_vec(),
            });
        }
        Ok(out)
    }

    pub fn get_wallet_meta(
        &self,
        wallet_id: &WalletCacheKey,
    ) -> Result<Option<WalletMeta>, DbError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(WALLET_META_TABLE)?;
        match table.get(wallet_id.as_str())? {
            Some(value) => Ok(Some(decode(value.value())?)),
            None => Ok(None),
        }
    }

    pub fn put_wallet_meta(
        &self,
        wallet_id: &WalletCacheKey,
        meta: &WalletMeta,
    ) -> Result<(), DbError> {
        let data = encode(meta)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(WALLET_META_TABLE)?;
            table.insert(wallet_id.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn put_wallet_meta_if_absent(
        &self,
        wallet_id: &WalletCacheKey,
        meta: &WalletMeta,
    ) -> Result<bool, DbError> {
        let data = encode(meta)?;
        let txn = self.db.begin_write()?;
        let inserted = {
            let mut table = txn.open_table(WALLET_META_TABLE)?;
            if table.get(wallet_id.as_str())?.is_some() {
                false
            } else {
                table.insert(wallet_id.as_str(), data.as_slice())?;
                true
            }
        };
        txn.commit()?;
        Ok(inserted)
    }

    pub fn get_wallet_sync_actor_state(
        &self,
        chain_id: u64,
        wallet_id: &str,
    ) -> Result<Option<WalletSyncActorStateRecord>, DbError> {
        let key = WalletSyncActorStateRecord::key_for(chain_id, wallet_id);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(WALLET_SYNC_ACTOR_STATE_TABLE)?;
        match table.get(key.as_str())? {
            Some(value) => Ok(Some(decode(value.value())?)),
            None => Ok(None),
        }
    }

    pub fn put_wallet_sync_actor_state(
        &self,
        record: &WalletSyncActorStateRecord,
    ) -> Result<(), DbError> {
        record.wallet_id.parse::<WalletCacheKey>()?;
        let key = record.key();
        let data = encode(record)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(WALLET_SYNC_ACTOR_STATE_TABLE)?;
            table.insert(key.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn list_wallet_sync_actor_states_for_chain(
        &self,
        chain_id: u64,
    ) -> Result<Vec<WalletSyncActorStateRecord>, DbError> {
        let prefix = WalletSyncActorStateRecord::prefix_for_chain(chain_id);
        self.list_decoded_by_prefix(WALLET_SYNC_ACTOR_STATE_TABLE, &prefix)
    }

    pub fn get_poi_artifact_cache(
        &self,
        chain_type: u8,
        chain_id: u64,
        txid_version: &str,
        list_key: &FixedBytes<32>,
    ) -> Result<Option<PoiArtifactCacheRecord>, DbError> {
        match self.inspect_poi_artifact_cache(chain_type, chain_id, txid_version, list_key)? {
            StoredRecord::Missing => Ok(None),
            StoredRecord::Valid(record) => Ok(Some(record)),
            StoredRecord::Corrupt { key } => Err(DbError::InvalidPpoiCorpusRecord { key }),
        }
    }

    pub fn inspect_poi_artifact_cache(
        &self,
        chain_type: u8,
        chain_id: u64,
        txid_version: &str,
        list_key: &FixedBytes<32>,
    ) -> Result<StoredRecord<PoiArtifactCacheRecord>, DbError> {
        let key = PoiArtifactCacheRecord::key_for(chain_type, chain_id, txid_version, list_key);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(POI_ARTIFACT_CACHE_TABLE)?;
        let Some(value) = table.get(key.as_str())? else {
            return Ok(StoredRecord::Missing);
        };
        match decode::<PoiArtifactCacheRecord>(value.value()) {
            Ok(record) if record.key() == key => Ok(StoredRecord::Valid(record)),
            Ok(_) | Err(DbError::Decode(_)) => Ok(StoredRecord::Corrupt { key }),
            Err(error) => Err(error),
        }
    }

    pub fn put_poi_artifact_cache(&self, record: &PoiArtifactCacheRecord) -> Result<(), DbError> {
        let mut record = record.clone();
        record.updated_at = now_epoch_secs()?;
        let key = record.key();
        let data = encode(&record)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(POI_ARTIFACT_CACHE_TABLE)?;
            table.insert(key.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn commit_poi_artifact_cache_if_current(
        &self,
        record: &PoiArtifactCacheRecord,
        condition: PoiArtifactCacheCommitCondition,
    ) -> Result<PoiArtifactCacheCommitOutcome, DbError> {
        let mut record = record.clone();
        record.cache_generation = condition.expected_generation;
        record.updated_at = now_epoch_secs()?;
        let key = record.key();
        let data = encode(&record)?;
        let txn = self.db.begin_write()?;

        let generation = {
            let table = txn.open_table(APP_SETTINGS_TABLE)?;
            match table.get(POI_ARTIFACT_CACHE_GENERATION_KEY)? {
                Some(value) => decode(value.value())?,
                None => 0_u64,
            }
        };
        if generation != condition.expected_generation {
            return Ok(PoiArtifactCacheCommitOutcome::GenerationConflict { actual: generation });
        }

        if let Some((publisher_pubkey, expected_sequence)) = condition.expected_publisher {
            let watermark_key = PoiPublisherManifestWatermarkRecord::key_for(&publisher_pubkey);
            let actual = {
                let table = txn.open_table(APP_SETTINGS_TABLE)?;
                match table.get(watermark_key.as_str())? {
                    Some(value) => {
                        let watermark: PoiPublisherManifestWatermarkRecord = decode(value.value())?;
                        if watermark.publisher_pubkey != publisher_pubkey {
                            return Err(DbError::InvalidPpoiSidecarRecord {
                                kind: "publisher manifest watermark",
                                key: watermark_key,
                            });
                        }
                        Some((
                            watermark.accepted_sequence,
                            watermark.accepted_manifest_hash,
                        ))
                    }
                    None => None,
                }
            };
            if actual.map(|(sequence, _)| sequence) != Some(expected_sequence) {
                return Ok(PoiArtifactCacheCommitOutcome::PublisherSequenceConflict {
                    actual: actual.map(|(sequence, _)| sequence),
                });
            }
            if let Some(expected_hash) = condition.expected_manifest_hash
                && actual.and_then(|(_, hash)| hash) != Some(expected_hash)
            {
                return Ok(PoiArtifactCacheCommitOutcome::PublisherManifestConflict {
                    actual: actual.and_then(|(_, hash)| hash),
                });
            }
        }

        let observed_payload_hash = {
            let table = txn.open_table(POI_ARTIFACT_CACHE_TABLE)?;
            match table.get(key.as_str())? {
                None => None,
                Some(value) => match decode::<PoiArtifactCacheRecord>(value.value()) {
                    Ok(existing) if existing.key() == key => {
                        Some(keccak256(&existing.cache_payload))
                    }
                    Ok(_) | Err(DbError::Decode(_)) => None,
                    Err(error) => return Err(error),
                },
            }
        };
        if observed_payload_hash != condition.expected_payload_hash {
            return Ok(PoiArtifactCacheCommitOutcome::CorpusConflict);
        }

        {
            let mut table = txn.open_table(POI_ARTIFACT_CACHE_TABLE)?;
            table.insert(key.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(PoiArtifactCacheCommitOutcome::Applied)
    }

    pub fn scan_poi_artifact_caches(&self) -> Result<PoiArtifactCacheRecordScan, DbError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(POI_ARTIFACT_CACHE_TABLE)?;
        let mut records = Vec::new();
        let mut invalid_keys = Vec::new();
        for entry in table.range::<&str>(..)? {
            let (key, value) = entry?;
            let key = key.value().to_string();
            match decode::<PoiArtifactCacheRecord>(value.value()) {
                Ok(record) if record.key() == key => records.push(record),
                Ok(_) | Err(DbError::Decode(_)) => invalid_keys.push(key),
                Err(error) => return Err(error),
            }
        }
        Ok(PoiArtifactCacheRecordScan {
            records,
            invalid_keys,
        })
    }

    pub fn poi_artifact_cache_generation(&self) -> Result<u64, DbError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(APP_SETTINGS_TABLE)?;
        match table.get(POI_ARTIFACT_CACHE_GENERATION_KEY)? {
            Some(value) => decode(value.value()),
            None => Ok(0),
        }
    }

    pub fn clear_poi_artifact_cache(&self) -> Result<u64, DbError> {
        self.clear_poi_artifact_cache_with_generation()
            .map(|(removed, _)| removed)
    }

    pub fn clear_poi_artifact_cache_with_generation(&self) -> Result<(u64, u64), DbError> {
        let txn = self.db.begin_write()?;
        let generation = {
            let mut table = txn.open_table(APP_SETTINGS_TABLE)?;
            let current = match table.get(POI_ARTIFACT_CACHE_GENERATION_KEY)? {
                Some(value) => decode(value.value())?,
                None => 0_u64,
            };
            let generation = current
                .checked_add(1)
                .ok_or_else(|| std::io::Error::other("POI artifact cache generation overflow"))?;
            let encoded = encode(&generation)?;
            table.insert(POI_ARTIFACT_CACHE_GENERATION_KEY, encoded.as_slice())?;
            generation
        };
        let removed = {
            let mut table = txn.open_table(POI_ARTIFACT_CACHE_TABLE)?;
            let removed = table.len()?;
            table.retain(|_, _| false)?;
            removed
        };
        txn.commit()?;
        Ok((removed, generation))
    }

    pub fn get_poi_publisher_manifest_watermark(
        &self,
        publisher_pubkey: &FixedBytes<32>,
    ) -> Result<Option<PoiPublisherManifestWatermarkRecord>, DbError> {
        match self.inspect_poi_publisher_manifest_watermark(publisher_pubkey)? {
            StoredRecord::Missing => Ok(None),
            StoredRecord::Valid(record) => Ok(Some(record)),
            StoredRecord::Corrupt { key } => Err(DbError::InvalidPpoiSidecarRecord {
                kind: "publisher manifest watermark",
                key,
            }),
        }
    }

    pub fn inspect_poi_publisher_manifest_watermark(
        &self,
        publisher_pubkey: &FixedBytes<32>,
    ) -> Result<StoredRecord<PoiPublisherManifestWatermarkRecord>, DbError> {
        let key = PoiPublisherManifestWatermarkRecord::key_for(publisher_pubkey);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(APP_SETTINGS_TABLE)?;
        let Some(value) = table.get(key.as_str())? else {
            return Ok(StoredRecord::Missing);
        };
        match decode::<PoiPublisherManifestWatermarkRecord>(value.value()) {
            Ok(record) if record.publisher_pubkey == *publisher_pubkey => {
                Ok(StoredRecord::Valid(record))
            }
            Ok(_) | Err(DbError::Decode(_)) => Ok(StoredRecord::Corrupt { key }),
            Err(error) => Err(error),
        }
    }

    pub fn advance_poi_publisher_manifest_watermark(
        &self,
        publisher_pubkey: FixedBytes<32>,
        accepted_sequence: u64,
    ) -> Result<(PoiPublisherManifestWatermarkRecord, bool), DbError> {
        let key = PoiPublisherManifestWatermarkRecord::key_for(&publisher_pubkey);
        let txn = self.db.begin_write()?;
        let record = {
            let mut table = txn.open_table(APP_SETTINGS_TABLE)?;
            if let Some(value) = table.get(key.as_str())? {
                let record: PoiPublisherManifestWatermarkRecord = decode(value.value())?;
                if record.publisher_pubkey != publisher_pubkey {
                    return Err(DbError::InvalidPpoiSidecarRecord {
                        kind: "publisher manifest watermark",
                        key,
                    });
                }
                if record.accepted_sequence >= accepted_sequence {
                    return Ok((record, false));
                }
            }
            let record = PoiPublisherManifestWatermarkRecord {
                publisher_pubkey,
                accepted_sequence,
                accepted_manifest_hash: None,
                updated_at: now_epoch_secs()?,
            };
            let data = encode(&record)?;
            table.insert(key.as_str(), data.as_slice())?;
            record
        };
        txn.commit()?;
        Ok((record, true))
    }

    pub fn observe_poi_v4_publisher_manifest(
        &self,
        publisher_pubkey: FixedBytes<32>,
        accepted_sequence: u64,
        manifest_hash: FixedBytes<32>,
    ) -> Result<PoiPublisherManifestObservation, DbError> {
        let key = PoiPublisherManifestWatermarkRecord::key_for(&publisher_pubkey);
        let txn = self.db.begin_write()?;
        let observation = {
            let mut table = txn.open_table(APP_SETTINGS_TABLE)?;
            let existing = match table.get(key.as_str())? {
                Some(value) => {
                    let record: PoiPublisherManifestWatermarkRecord = decode(value.value())?;
                    if record.publisher_pubkey != publisher_pubkey {
                        return Err(DbError::InvalidPpoiSidecarRecord {
                            kind: "publisher manifest watermark",
                            key,
                        });
                    }
                    Some(record)
                }
                None => None,
            };
            if let Some(record) = existing {
                if accepted_sequence < record.accepted_sequence {
                    return Ok(PoiPublisherManifestObservation::Rollback { record });
                }
                if accepted_sequence == record.accepted_sequence
                    && let Some(accepted_hash) = record.accepted_manifest_hash
                {
                    return Ok(if accepted_hash == manifest_hash {
                        PoiPublisherManifestObservation::Accepted {
                            record,
                            changed: false,
                        }
                    } else {
                        PoiPublisherManifestObservation::Equivocation { record }
                    });
                }
            }
            let record = PoiPublisherManifestWatermarkRecord {
                publisher_pubkey,
                accepted_sequence,
                accepted_manifest_hash: Some(manifest_hash),
                updated_at: now_epoch_secs()?,
            };
            let data = encode(&record)?;
            table.insert(key.as_str(), data.as_slice())?;
            PoiPublisherManifestObservation::Accepted {
                record,
                changed: true,
            }
        };
        txn.commit()?;
        Ok(observation)
    }

    pub fn get_poi_corpus_rpc_health(
        &self,
        chain_type: u8,
        chain_id: u64,
        txid_version: &str,
        list_key: &FixedBytes<32>,
    ) -> Result<Option<PoiCorpusRpcHealthRecord>, DbError> {
        match self.inspect_poi_corpus_rpc_health(chain_type, chain_id, txid_version, list_key)? {
            StoredRecord::Missing => Ok(None),
            StoredRecord::Valid(record) => Ok(Some(record)),
            StoredRecord::Corrupt { key } => Err(DbError::InvalidPpoiSidecarRecord {
                kind: "corpus RPC health",
                key,
            }),
        }
    }

    pub fn inspect_poi_corpus_rpc_health(
        &self,
        chain_type: u8,
        chain_id: u64,
        txid_version: &str,
        list_key: &FixedBytes<32>,
    ) -> Result<StoredRecord<PoiCorpusRpcHealthRecord>, DbError> {
        let key = PoiCorpusRpcHealthRecord::key_for(chain_type, chain_id, txid_version, list_key);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(APP_SETTINGS_TABLE)?;
        let Some(value) = table.get(key.as_str())? else {
            return Ok(StoredRecord::Missing);
        };
        match decode::<PoiCorpusRpcHealthRecord>(value.value()) {
            Ok(record)
                if record.chain_type == chain_type
                    && record.chain_id == chain_id
                    && record.txid_version == txid_version
                    && record.list_key == *list_key =>
            {
                Ok(StoredRecord::Valid(record))
            }
            Ok(_) | Err(DbError::Decode(_)) => Ok(StoredRecord::Corrupt { key }),
            Err(error) => Err(error),
        }
    }

    pub fn put_poi_corpus_rpc_health(
        &self,
        record: &PoiCorpusRpcHealthRecord,
    ) -> Result<(), DbError> {
        let mut record = record.clone();
        record.updated_at = now_epoch_secs()?;
        let key = record.key();
        let data = encode(&record)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(APP_SETTINGS_TABLE)?;
            table.insert(key.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get_pending_fee_note_assurance(
        &self,
        chain_id: u64,
        public_tx_hash: &FixedBytes<32>,
    ) -> Result<Option<PendingFeeNoteAssuranceRecord>, DbError> {
        let key = PendingFeeNoteAssuranceRecord::key_for(chain_id, public_tx_hash);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(PENDING_FEE_NOTE_ASSURANCE_TABLE)?;
        match table.get(key.as_str())? {
            Some(value) => Ok(Some(decode(value.value())?)),
            None => Ok(None),
        }
    }

    pub fn put_pending_fee_note_assurance(
        &self,
        record: &PendingFeeNoteAssuranceRecord,
    ) -> Result<(), DbError> {
        let key = record.key();
        let data = encode(record)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(PENDING_FEE_NOTE_ASSURANCE_TABLE)?;
            table.insert(key.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn delete_pending_fee_note_assurance(
        &self,
        chain_id: u64,
        public_tx_hash: &FixedBytes<32>,
    ) -> Result<(), DbError> {
        let key = PendingFeeNoteAssuranceRecord::key_for(chain_id, public_tx_hash);
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(PENDING_FEE_NOTE_ASSURANCE_TABLE)?;
            table.remove(key.as_str())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn list_pending_fee_note_assurance(
        &self,
        chain_id: u64,
    ) -> Result<Vec<PendingFeeNoteAssuranceRecord>, DbError> {
        let prefix = PendingFeeNoteAssuranceRecord::prefix_for_chain(chain_id);
        self.list_decoded_by_prefix(PENDING_FEE_NOTE_ASSURANCE_TABLE, &prefix)
    }

    pub fn get_terminal_fee_note_assurance(
        &self,
        chain_id: u64,
        public_tx_hash: &FixedBytes<32>,
    ) -> Result<Option<TerminalFeeNoteAssuranceRecord>, DbError> {
        let key = PendingFeeNoteAssuranceRecord::key_for(chain_id, public_tx_hash);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(TERMINAL_FEE_NOTE_ASSURANCE_TABLE)?;
        match table.get(key.as_str())? {
            Some(value) => Ok(Some(decode(value.value())?)),
            None => Ok(None),
        }
    }

    pub fn list_terminal_fee_note_assurance(
        &self,
        chain_id: u64,
    ) -> Result<Vec<TerminalFeeNoteAssuranceRecord>, DbError> {
        let prefix = PendingFeeNoteAssuranceRecord::prefix_for_chain(chain_id);
        self.list_decoded_by_prefix(TERMINAL_FEE_NOTE_ASSURANCE_TABLE, &prefix)
    }

    pub fn mark_fee_note_assurance_terminal(
        &self,
        record: &PendingFeeNoteAssuranceRecord,
        outcome: FeeNoteAssuranceTerminalOutcome,
    ) -> Result<(), DbError> {
        let key = record.key();
        let terminal = TerminalFeeNoteAssuranceRecord {
            chain_id: record.chain_id,
            public_tx_hash: record.public_tx_hash,
            context: record.context.clone(),
            outcome,
        };
        let data = encode(&terminal)?;
        let txn = self.db.begin_write()?;
        {
            let mut pending_table = txn.open_table(PENDING_FEE_NOTE_ASSURANCE_TABLE)?;
            pending_table.remove(key.as_str())?;

            let mut terminal_table = txn.open_table(TERMINAL_FEE_NOTE_ASSURANCE_TABLE)?;
            terminal_table.insert(key.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get_opaque_wallet_private_row(
        &self,
        namespace: &WalletPrivateNamespaceId,
        kind: WalletPrivateRecordKind,
        row_id: &[u8],
    ) -> Result<Option<OpaqueWalletPrivateRow>, DbError> {
        let txn = self.db.begin_read()?;
        Self::get_opaque_wallet_private_row_in_transaction(&txn, namespace, kind, row_id)
    }

    fn get_opaque_wallet_private_row_in_transaction(
        txn: &ReadTransaction,
        namespace: &WalletPrivateNamespaceId,
        kind: WalletPrivateRecordKind,
        row_id: &[u8],
    ) -> Result<Option<OpaqueWalletPrivateRow>, DbError> {
        let key = opaque_wallet_private_row_key(namespace, row_id)?;
        let table = txn.open_table(kind.v2_table())?;
        match table.get(key.as_str())? {
            Some(value) => Ok(Some(OpaqueWalletPrivateRow {
                row_id: row_id.to_vec(),
                payload: value.value().to_vec(),
            })),
            None => Ok(None),
        }
    }

    pub fn list_opaque_wallet_private_rows(
        &self,
        namespace: &WalletPrivateNamespaceId,
        kind: WalletPrivateRecordKind,
    ) -> Result<Vec<OpaqueWalletPrivateRow>, DbError> {
        let txn = self.db.begin_read()?;
        Self::list_opaque_wallet_private_rows_in_transaction(&txn, namespace, kind)
    }

    fn list_opaque_wallet_private_rows_in_transaction(
        txn: &ReadTransaction,
        namespace: &WalletPrivateNamespaceId,
        kind: WalletPrivateRecordKind,
    ) -> Result<Vec<OpaqueWalletPrivateRow>, DbError> {
        let prefix = opaque_wallet_private_row_prefix(namespace);
        let range_end = prefix_range_end(&prefix);
        let table = txn.open_table(kind.v2_table())?;
        let entries = match range_end.as_deref() {
            Some(range_end) => table.range(prefix.as_str()..range_end)?,
            None => table.range(prefix.as_str()..)?,
        };
        let mut rows = Vec::new();
        for entry in entries {
            let (key, value) = entry?;
            rows.push(OpaqueWalletPrivateRow {
                row_id: opaque_wallet_private_row_id(&prefix, key.value())?,
                payload: value.value().to_vec(),
            });
        }
        Ok(rows)
    }

    pub fn put_opaque_wallet_private_row(
        &self,
        namespace: &WalletPrivateNamespaceId,
        kind: WalletPrivateRecordKind,
        row: &OpaqueWalletPrivateRow,
    ) -> Result<(), DbError> {
        validate_opaque_row(row)?;
        let txn = self.db.begin_write()?;
        Self::write_opaque_wallet_private_rows(
            &txn,
            namespace,
            kind,
            OpaqueWalletPrivateRowMutation {
                updates: std::slice::from_ref(row),
                deletes: &[],
            },
        )?;
        txn.commit()?;
        Ok(())
    }

    pub fn delete_opaque_wallet_private_row(
        &self,
        namespace: &WalletPrivateNamespaceId,
        kind: WalletPrivateRecordKind,
        row_id: &[u8],
    ) -> Result<(), DbError> {
        let key = opaque_wallet_private_row_key(namespace, row_id)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(kind.v2_table())?;
            table.remove(key.as_str())?;
        }
        txn.commit()?;
        Ok(())
    }

    fn put_typed_wallet_private_row(
        &self,
        namespace: &WalletPrivateNamespaceId,
        kind: WalletPrivateRecordKind,
        v1_key: &str,
        row: &OpaqueWalletPrivateRow,
    ) -> Result<(), DbError> {
        self.put_typed_wallet_private_row_transaction(namespace, kind, v1_key, row, || Ok(()))
    }

    fn put_typed_wallet_private_row_transaction<F>(
        &self,
        namespace: &WalletPrivateNamespaceId,
        kind: WalletPrivateRecordKind,
        v1_key: &str,
        row: &OpaqueWalletPrivateRow,
        before_commit: F,
    ) -> Result<(), DbError>
    where
        F: FnOnce() -> Result<(), DbError>,
    {
        validate_opaque_row(row)?;
        let v2_key = opaque_wallet_private_row_key(namespace, &row.row_id)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(kind.v2_table())?;
            table.insert(v2_key.as_str(), row.payload.as_slice())?;
        }
        let removed_v1 = {
            let mut table = txn.open_table(kind.v1_table())?;
            table.remove(v1_key)?.is_some()
        };
        if removed_v1 {
            let mut table = txn.open_table(META_TABLE)?;
            table.insert(WALLET_PRIVATE_COMPACTION_REQUESTED_KEY, &[1_u8][..])?;
        }
        before_commit()?;
        txn.commit()?;
        Ok(())
    }

    fn delete_typed_wallet_private_row(
        &self,
        namespace: &WalletPrivateNamespaceId,
        kind: WalletPrivateRecordKind,
        v1_key: &str,
        row_id: &[u8],
    ) -> Result<(), DbError> {
        self.delete_typed_wallet_private_row_transaction(namespace, kind, v1_key, row_id, || Ok(()))
    }

    fn delete_typed_wallet_private_row_transaction<F>(
        &self,
        namespace: &WalletPrivateNamespaceId,
        kind: WalletPrivateRecordKind,
        v1_key: &str,
        row_id: &[u8],
        before_commit: F,
    ) -> Result<(), DbError>
    where
        F: FnOnce() -> Result<(), DbError>,
    {
        let v2_key = opaque_wallet_private_row_key(namespace, row_id)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(kind.v2_table())?;
            table.remove(v2_key.as_str())?;
        }
        let removed_v1 = {
            let mut table = txn.open_table(kind.v1_table())?;
            table.remove(v1_key)?.is_some()
        };
        if removed_v1 {
            let mut table = txn.open_table(META_TABLE)?;
            table.insert(WALLET_PRIVATE_COMPACTION_REQUESTED_KEY, &[1_u8][..])?;
        }
        before_commit()?;
        txn.commit()?;
        Ok(())
    }

    fn get_wallet_private_v1_payload_in_transaction(
        txn: &ReadTransaction,
        kind: WalletPrivateRecordKind,
        key: &str,
    ) -> Result<Option<Vec<u8>>, DbError> {
        let table = txn.open_table(kind.v1_table())?;
        Ok(table.get(key)?.map(|value| value.value().to_vec()))
    }

    pub fn list_wallet_private_v1_rows(
        &self,
        namespace: &WalletPrivateNamespaceId,
    ) -> Result<WalletPrivateV1Rows, DbError> {
        let txn = self.db.begin_read()?;
        Ok(WalletPrivateV1Rows {
            pending_output_contexts: Self::list_wallet_private_v1_rows_for_kind_in_transaction(
                &txn,
                namespace,
                WalletPrivateRecordKind::PendingOutputPoiContext,
            )?,
            output_poi_recoveries: Self::list_wallet_private_v1_rows_for_kind_in_transaction(
                &txn,
                namespace,
                WalletPrivateRecordKind::OutputPoiRecovery,
            )?,
        })
    }

    fn list_wallet_private_v1_rows_for_kind_in_transaction(
        txn: &ReadTransaction,
        namespace: &WalletPrivateNamespaceId,
        kind: WalletPrivateRecordKind,
    ) -> Result<Vec<WalletPrivateV1Row>, DbError> {
        let prefix = legacy_wallet_private_row_prefix(namespace);
        let range_end = prefix_range_end(&prefix);
        let table = txn.open_table(kind.v1_table())?;
        let entries = match range_end.as_deref() {
            Some(range_end) => table.range(prefix.as_str()..range_end)?,
            None => table.range(prefix.as_str()..)?,
        };
        let mut rows = Vec::new();
        for entry in entries {
            let (key, value) = entry?;
            let row = WalletPrivateV1Row {
                storage_key: key.value().to_owned(),
                payload: value.value().to_vec(),
            };
            validate_wallet_private_v1_row(namespace, kind, &row)?;
            rows.push(row);
        }
        Ok(rows)
    }

    pub fn migrate_wallet_private_v1_rows(
        &self,
        batch: &WalletPrivateV1MigrationBatch<'_>,
    ) -> Result<WalletPrivateV1MigrationReport, DbError> {
        self.migrate_wallet_private_v1_rows_transaction(batch, || Ok(()))
    }

    fn migrate_wallet_private_v1_rows_transaction(
        &self,
        batch: &WalletPrivateV1MigrationBatch<'_>,
        before_commit: impl FnOnce() -> Result<(), DbError>,
    ) -> Result<WalletPrivateV1MigrationReport, DbError> {
        if batch.pending_output_context_sources.len()
            != batch.pending_output_context_destinations.len()
        {
            return Err(DbError::WalletPrivateV1MigrationRowCountMismatch {
                kind: "pending output POI context",
            });
        }
        if batch.output_poi_recovery_sources.len() != batch.output_poi_recovery_destinations.len() {
            return Err(DbError::WalletPrivateV1MigrationRowCountMismatch {
                kind: "output POI recovery",
            });
        }
        for row in batch.pending_output_context_destinations {
            validate_opaque_row(row)?;
        }
        for row in batch.output_poi_recovery_destinations {
            validate_opaque_row(row)?;
        }

        let txn = self.db.begin_write()?;
        Self::migrate_wallet_private_v1_kind(
            &txn,
            batch.namespace,
            WalletPrivateRecordKind::PendingOutputPoiContext,
            batch.pending_output_context_sources,
            batch.pending_output_context_destinations,
        )?;
        Self::migrate_wallet_private_v1_kind(
            &txn,
            batch.namespace,
            WalletPrivateRecordKind::OutputPoiRecovery,
            batch.output_poi_recovery_sources,
            batch.output_poi_recovery_destinations,
        )?;
        {
            let mut table = txn.open_table(META_TABLE)?;
            table.insert(WALLET_PRIVATE_COMPACTION_REQUESTED_KEY, &[1_u8][..])?;
        }
        before_commit()?;
        txn.commit()?;
        Ok(WalletPrivateV1MigrationReport {
            pending_output_context_rows: batch.pending_output_context_sources.len() as u64,
            output_poi_recovery_rows: batch.output_poi_recovery_sources.len() as u64,
        })
    }

    fn migrate_wallet_private_v1_kind(
        txn: &WriteTransaction,
        namespace: &WalletPrivateNamespaceId,
        kind: WalletPrivateRecordKind,
        sources: &[WalletPrivateV1Row],
        destinations: &[OpaqueWalletPrivateRow],
    ) -> Result<(), DbError> {
        for source in sources {
            validate_wallet_private_v1_row(namespace, kind, source)?;
        }
        {
            let source_table = txn.open_table(kind.v1_table())?;
            let prefix = legacy_wallet_private_row_prefix(namespace);
            let range_end = prefix_range_end(&prefix);
            let entries = match range_end.as_deref() {
                Some(range_end) => source_table.range(prefix.as_str()..range_end)?,
                None => source_table.range(prefix.as_str()..)?,
            };
            let mut current_source_count = 0_usize;
            for entry in entries {
                let (key, value) = entry?;
                current_source_count = current_source_count.saturating_add(1);
                if !sources.iter().any(|source| {
                    source.storage_key == key.value() && source.payload.as_slice() == value.value()
                }) {
                    return Err(DbError::WalletPrivateV1MigrationSourceChanged {
                        table: kind.v1_table_name(),
                        key: key.value().to_owned(),
                    });
                }
            }
            if current_source_count != sources.len() {
                return Err(DbError::WalletPrivateV1MigrationRowCountMismatch {
                    kind: kind.label(),
                });
            }
            for source in sources {
                let unchanged = source_table
                    .get(source.storage_key.as_str())?
                    .is_some_and(|value| value.value() == source.payload.as_slice());
                if !unchanged {
                    return Err(DbError::WalletPrivateV1MigrationSourceChanged {
                        table: kind.v1_table_name(),
                        key: source.storage_key.clone(),
                    });
                }
            }
        }
        {
            let mut destination_table = txn.open_table(kind.v2_table())?;
            for destination in destinations {
                let key = opaque_wallet_private_row_key(namespace, &destination.row_id)?;
                if destination_table.get(key.as_str())?.is_some() {
                    return Err(DbError::SchemaMigrationDestinationConflict {
                        table: kind.v2_table_name(),
                        key,
                    });
                }
                destination_table.insert(key.as_str(), destination.payload.as_slice())?;
            }
        }
        {
            let mut source_table = txn.open_table(kind.v1_table())?;
            for source in sources {
                source_table.remove(source.storage_key.as_str())?;
            }
        }
        Ok(())
    }

    pub fn wallet_private_canonicalization_version(
        &self,
        namespace: &WalletPrivateNamespaceId,
    ) -> Result<u32, DbError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(META_TABLE)?;
        let key = wallet_private_canonicalization_version_key(namespace);
        let Some(value) = table.get(key.as_str())? else {
            return Ok(0);
        };
        decode_wallet_private_canonicalization_version(value.value())
    }

    pub fn canonicalize_wallet_private_rows(
        &self,
        batch: &WalletPrivateCanonicalizationBatch<'_>,
    ) -> Result<WalletPrivateCanonicalizationReport, DbError> {
        self.canonicalize_wallet_private_rows_transaction(batch, || Ok(()))
    }

    fn canonicalize_wallet_private_rows_transaction(
        &self,
        batch: &WalletPrivateCanonicalizationBatch<'_>,
        before_commit: impl FnOnce() -> Result<(), DbError>,
    ) -> Result<WalletPrivateCanonicalizationReport, DbError> {
        if batch.target_version == 0 {
            return Err(DbError::InvalidWalletPrivateCanonicalizationVersion);
        }
        if batch
            .legacy_namespace
            .is_some_and(|legacy| legacy == batch.canonical_namespace)
        {
            return Err(DbError::DuplicateWalletPrivateCanonicalizationNamespace);
        }
        Self::validate_wallet_private_canonicalization_kind_batch(
            batch,
            WalletPrivateRecordKind::PendingOutputPoiContext,
            &batch.pending_output_contexts,
        )?;
        Self::validate_wallet_private_canonicalization_kind_batch(
            batch,
            WalletPrivateRecordKind::OutputPoiRecovery,
            &batch.output_poi_recoveries,
        )?;

        let txn = self.db.begin_write()?;
        let marker_key = wallet_private_canonicalization_version_key(batch.canonical_namespace);
        {
            let table = txn.open_table(META_TABLE)?;
            if let Some(value) = table.get(marker_key.as_str())?
                && decode_wallet_private_canonicalization_version(value.value())?
                    >= batch.target_version
            {
                return Ok(WalletPrivateCanonicalizationReport::default());
            }
        }
        Self::canonicalize_wallet_private_kind(
            &txn,
            batch,
            WalletPrivateRecordKind::PendingOutputPoiContext,
            &batch.pending_output_contexts,
        )?;
        Self::canonicalize_wallet_private_kind(
            &txn,
            batch,
            WalletPrivateRecordKind::OutputPoiRecovery,
            &batch.output_poi_recoveries,
        )?;

        let plaintext_rows_removed = batch
            .pending_output_contexts
            .canonical_v1_sources
            .len()
            .saturating_add(batch.pending_output_contexts.legacy_v1_sources.len())
            .saturating_add(batch.output_poi_recoveries.canonical_v1_sources.len())
            .saturating_add(batch.output_poi_recoveries.legacy_v1_sources.len());
        {
            let mut table = txn.open_table(META_TABLE)?;
            let version = batch.target_version.to_be_bytes();
            table.insert(marker_key.as_str(), version.as_slice())?;
            if plaintext_rows_removed > 0 {
                table.insert(WALLET_PRIVATE_COMPACTION_REQUESTED_KEY, &[1_u8][..])?;
            }
        }
        before_commit()?;
        txn.commit()?;
        Ok(WalletPrivateCanonicalizationReport {
            pending_output_context_rows: batch
                .pending_output_contexts
                .canonical_v2_destinations
                .len() as u64,
            output_poi_recovery_rows: batch.output_poi_recoveries.canonical_v2_destinations.len()
                as u64,
            plaintext_rows_removed: plaintext_rows_removed as u64,
        })
    }

    fn validate_wallet_private_canonicalization_kind_batch(
        batch: &WalletPrivateCanonicalizationBatch<'_>,
        kind: WalletPrivateRecordKind,
        rows: &WalletPrivateCanonicalizationKindBatch<'_>,
    ) -> Result<(), DbError> {
        if batch.legacy_namespace.is_none()
            && (!rows.legacy_v1_sources.is_empty() || !rows.legacy_v2_sources.is_empty())
        {
            return Err(DbError::WalletPrivateCanonicalizationRowCountMismatch {
                kind: kind.label(),
            });
        }
        let mut destination_keys = BTreeSet::new();
        for row in rows.canonical_v2_destinations {
            validate_opaque_row(row)?;
            let key = opaque_wallet_private_row_key(batch.canonical_namespace, &row.row_id)?;
            if !destination_keys.insert(key.clone()) {
                return Err(DbError::SchemaMigrationDestinationConflict {
                    table: kind.v2_table_name(),
                    key,
                });
            }
        }
        for row in rows
            .canonical_v2_sources
            .iter()
            .chain(rows.legacy_v2_sources)
        {
            validate_opaque_row(row)?;
        }
        Ok(())
    }

    fn canonicalize_wallet_private_kind(
        txn: &WriteTransaction,
        batch: &WalletPrivateCanonicalizationBatch<'_>,
        kind: WalletPrivateRecordKind,
        rows: &WalletPrivateCanonicalizationKindBatch<'_>,
    ) -> Result<(), DbError> {
        Self::validate_wallet_private_v1_snapshot(
            txn,
            batch.canonical_namespace,
            kind,
            rows.canonical_v1_sources,
        )?;
        Self::validate_wallet_private_v2_snapshot(
            txn,
            batch.canonical_namespace,
            kind,
            rows.canonical_v2_sources,
        )?;
        if let Some(legacy) = batch.legacy_namespace {
            Self::validate_wallet_private_v1_snapshot(txn, legacy, kind, rows.legacy_v1_sources)?;
            Self::validate_wallet_private_v2_snapshot(txn, legacy, kind, rows.legacy_v2_sources)?;
        }

        {
            let mut table = txn.open_table(kind.v1_table())?;
            remove_table_prefix(
                &mut table,
                &legacy_wallet_private_row_prefix(batch.canonical_namespace),
            )?;
            if let Some(legacy) = batch.legacy_namespace {
                remove_table_prefix(&mut table, &legacy_wallet_private_row_prefix(legacy))?;
            }
        }
        {
            let mut table = txn.open_table(kind.v2_table())?;
            remove_table_prefix(
                &mut table,
                &opaque_wallet_private_row_prefix(batch.canonical_namespace),
            )?;
            if let Some(legacy) = batch.legacy_namespace {
                remove_table_prefix(&mut table, &opaque_wallet_private_row_prefix(legacy))?;
            }
            for destination in rows.canonical_v2_destinations {
                let key =
                    opaque_wallet_private_row_key(batch.canonical_namespace, &destination.row_id)?;
                table.insert(key.as_str(), destination.payload.as_slice())?;
            }
        }
        Ok(())
    }

    fn validate_wallet_private_v1_snapshot(
        txn: &WriteTransaction,
        namespace: &WalletPrivateNamespaceId,
        kind: WalletPrivateRecordKind,
        expected: &[WalletPrivateV1Row],
    ) -> Result<(), DbError> {
        for row in expected {
            validate_wallet_private_v1_row(namespace, kind, row)?;
        }
        let prefix = legacy_wallet_private_row_prefix(namespace);
        let range_end = prefix_range_end(&prefix);
        let table = txn.open_table(kind.v1_table())?;
        let entries = match range_end.as_deref() {
            Some(range_end) => table.range(prefix.as_str()..range_end)?,
            None => table.range(prefix.as_str()..)?,
        };
        let mut count = 0_usize;
        for entry in entries {
            let (key, value) = entry?;
            count = count.saturating_add(1);
            if !expected.iter().any(|row| {
                row.storage_key == key.value() && row.payload.as_slice() == value.value()
            }) {
                return Err(DbError::WalletPrivateCanonicalizationSourceChanged {
                    table: kind.v1_table_name(),
                    key: key.value().to_owned(),
                });
            }
        }
        if count != expected.len() {
            return Err(DbError::WalletPrivateCanonicalizationRowCountMismatch {
                kind: kind.label(),
            });
        }
        Ok(())
    }

    fn validate_wallet_private_v2_snapshot(
        txn: &WriteTransaction,
        namespace: &WalletPrivateNamespaceId,
        kind: WalletPrivateRecordKind,
        expected: &[OpaqueWalletPrivateRow],
    ) -> Result<(), DbError> {
        let prefix = opaque_wallet_private_row_prefix(namespace);
        let range_end = prefix_range_end(&prefix);
        let table = txn.open_table(kind.v2_table())?;
        let entries = match range_end.as_deref() {
            Some(range_end) => table.range(prefix.as_str()..range_end)?,
            None => table.range(prefix.as_str()..)?,
        };
        let mut count = 0_usize;
        for entry in entries {
            let (key, value) = entry?;
            let row_id = opaque_wallet_private_row_id(&prefix, key.value())?;
            count = count.saturating_add(1);
            if !expected
                .iter()
                .any(|row| row.row_id == row_id && row.payload.as_slice() == value.value())
            {
                return Err(DbError::WalletPrivateCanonicalizationSourceChanged {
                    table: kind.v2_table_name(),
                    key: key.value().to_owned(),
                });
            }
        }
        if count != expected.len() {
            return Err(DbError::WalletPrivateCanonicalizationRowCountMismatch {
                kind: kind.label(),
            });
        }
        Ok(())
    }

    pub fn get_pending_output_poi_context(
        &self,
        chain_id: u64,
        wallet_id: &str,
        output_commitment: &FixedBytes<32>,
    ) -> Result<Option<PendingOutputPoiContextRecord>, DbError> {
        self.get_pending_output_poi_context_with_probe_hook(
            chain_id,
            wallet_id,
            output_commitment,
            || Ok(()),
        )
    }

    fn get_pending_output_poi_context_with_probe_hook<F>(
        &self,
        chain_id: u64,
        wallet_id: &str,
        output_commitment: &FixedBytes<32>,
        after_v2_miss: F,
    ) -> Result<Option<PendingOutputPoiContextRecord>, DbError>
    where
        F: FnOnce() -> Result<(), DbError>,
    {
        let namespace = wallet_private_namespace(chain_id, wallet_id)?;
        let v1_key = PendingOutputPoiContextRecord::key_for(chain_id, wallet_id, output_commitment);
        let txn = self.db.begin_read()?;
        if let Some(row) = Self::get_opaque_wallet_private_row_in_transaction(
            &txn,
            &namespace,
            WalletPrivateRecordKind::PendingOutputPoiContext,
            output_commitment.as_slice(),
        )? {
            let record: PendingOutputPoiContextRecord = decode(&row.payload)?;
            validate_pending_output_record_identity(
                &record,
                &namespace,
                output_commitment.as_slice(),
                &v1_key,
            )?;
            return Ok(Some(record));
        }
        after_v2_miss()?;
        let Some(payload) = Self::get_wallet_private_v1_payload_in_transaction(
            &txn,
            WalletPrivateRecordKind::PendingOutputPoiContext,
            &v1_key,
        )?
        else {
            return Ok(None);
        };
        let record: PendingOutputPoiContextRecord = decode(&payload)?;
        validate_pending_output_record_identity(
            &record,
            &namespace,
            output_commitment.as_slice(),
            &v1_key,
        )?;
        Ok(Some(record))
    }

    pub fn put_pending_output_poi_context(
        &self,
        record: &PendingOutputPoiContextRecord,
    ) -> Result<(), DbError> {
        let namespace = wallet_private_namespace(record.chain_id, &record.wallet_id)?;
        self.put_typed_wallet_private_row(
            &namespace,
            WalletPrivateRecordKind::PendingOutputPoiContext,
            &record.key(),
            &OpaqueWalletPrivateRow {
                row_id: record.output_commitment.to_vec(),
                payload: encode(record)?,
            },
        )
    }

    pub fn delete_pending_output_poi_context(
        &self,
        chain_id: u64,
        wallet_id: &str,
        output_commitment: &FixedBytes<32>,
    ) -> Result<(), DbError> {
        let namespace = wallet_private_namespace(chain_id, wallet_id)?;
        self.delete_typed_wallet_private_row(
            &namespace,
            WalletPrivateRecordKind::PendingOutputPoiContext,
            &PendingOutputPoiContextRecord::key_for(chain_id, wallet_id, output_commitment),
            output_commitment.as_slice(),
        )
    }

    pub fn list_pending_output_poi_contexts(
        &self,
        chain_id: u64,
        wallet_id: &str,
    ) -> Result<Vec<PendingOutputPoiContextRecord>, DbError> {
        self.list_pending_output_poi_contexts_with_probe_hook(chain_id, wallet_id, || Ok(()))
    }

    fn list_pending_output_poi_contexts_with_probe_hook<F>(
        &self,
        chain_id: u64,
        wallet_id: &str,
        after_v2_read: F,
    ) -> Result<Vec<PendingOutputPoiContextRecord>, DbError>
    where
        F: FnOnce() -> Result<(), DbError>,
    {
        let namespace = wallet_private_namespace(chain_id, wallet_id)?;
        let txn = self.db.begin_read()?;
        let records = Self::list_opaque_wallet_private_rows_in_transaction(
            &txn,
            &namespace,
            WalletPrivateRecordKind::PendingOutputPoiContext,
        )?
        .into_iter()
        .map(|row| {
            let record: PendingOutputPoiContextRecord = decode(&row.payload)?;
            validate_pending_output_record_identity(
                &record,
                &namespace,
                &row.row_id,
                &opaque_wallet_private_row_key(&namespace, &row.row_id)?,
            )?;
            Ok(record)
        })
        .collect::<Result<Vec<PendingOutputPoiContextRecord>, DbError>>()?;
        let mut records = records;
        after_v2_read()?;
        for row in Self::list_wallet_private_v1_rows_for_kind_in_transaction(
            &txn,
            &namespace,
            WalletPrivateRecordKind::PendingOutputPoiContext,
        )? {
            let record: PendingOutputPoiContextRecord = decode(&row.payload)?;
            validate_pending_output_record_identity(
                &record,
                &namespace,
                record.output_commitment.as_slice(),
                &row.storage_key,
            )?;
            if !records
                .iter()
                .any(|current| current.output_commitment == record.output_commitment)
            {
                records.push(record);
            }
        }
        Ok(records)
    }

    pub fn get_output_poi_recovery(
        &self,
        chain_id: u64,
        wallet_id: &str,
        output_commitment: &FixedBytes<32>,
    ) -> Result<Option<OutputPoiRecoveryRecord>, DbError> {
        let namespace = wallet_private_namespace(chain_id, wallet_id)?;
        let v1_key = OutputPoiRecoveryRecord::key_for(chain_id, wallet_id, output_commitment);
        let txn = self.db.begin_read()?;
        if let Some(row) = Self::get_opaque_wallet_private_row_in_transaction(
            &txn,
            &namespace,
            WalletPrivateRecordKind::OutputPoiRecovery,
            output_commitment.as_slice(),
        )? {
            let record: OutputPoiRecoveryRecord = decode(&row.payload)?;
            validate_output_recovery_record_identity(
                &record,
                &namespace,
                output_commitment.as_slice(),
                &v1_key,
            )?;
            return Ok(Some(record));
        }
        let Some(payload) = Self::get_wallet_private_v1_payload_in_transaction(
            &txn,
            WalletPrivateRecordKind::OutputPoiRecovery,
            &v1_key,
        )?
        else {
            return Ok(None);
        };
        let record: OutputPoiRecoveryRecord = decode(&payload)?;
        validate_output_recovery_record_identity(
            &record,
            &namespace,
            output_commitment.as_slice(),
            &v1_key,
        )?;
        Ok(Some(record))
    }

    pub fn put_output_poi_recovery(&self, record: &OutputPoiRecoveryRecord) -> Result<(), DbError> {
        let namespace = wallet_private_namespace(record.chain_id, &record.wallet_id)?;
        self.put_typed_wallet_private_row(
            &namespace,
            WalletPrivateRecordKind::OutputPoiRecovery,
            &record.key(),
            &OpaqueWalletPrivateRow {
                row_id: record.output_commitment.to_vec(),
                payload: encode(record)?,
            },
        )
    }

    pub fn delete_output_poi_recovery(
        &self,
        chain_id: u64,
        wallet_id: &str,
        output_commitment: &FixedBytes<32>,
    ) -> Result<(), DbError> {
        let namespace = wallet_private_namespace(chain_id, wallet_id)?;
        self.delete_typed_wallet_private_row(
            &namespace,
            WalletPrivateRecordKind::OutputPoiRecovery,
            &OutputPoiRecoveryRecord::key_for(chain_id, wallet_id, output_commitment),
            output_commitment.as_slice(),
        )
    }

    pub fn list_output_poi_recoveries(
        &self,
        chain_id: u64,
        wallet_id: &str,
    ) -> Result<Vec<OutputPoiRecoveryRecord>, DbError> {
        let namespace = wallet_private_namespace(chain_id, wallet_id)?;
        let txn = self.db.begin_read()?;
        let records = Self::list_opaque_wallet_private_rows_in_transaction(
            &txn,
            &namespace,
            WalletPrivateRecordKind::OutputPoiRecovery,
        )?
        .into_iter()
        .map(|row| {
            let record: OutputPoiRecoveryRecord = decode(&row.payload)?;
            validate_output_recovery_record_identity(
                &record,
                &namespace,
                &row.row_id,
                &opaque_wallet_private_row_key(&namespace, &row.row_id)?,
            )?;
            Ok(record)
        })
        .collect::<Result<Vec<OutputPoiRecoveryRecord>, DbError>>()?;
        let mut records = records;
        for row in Self::list_wallet_private_v1_rows_for_kind_in_transaction(
            &txn,
            &namespace,
            WalletPrivateRecordKind::OutputPoiRecovery,
        )? {
            let record: OutputPoiRecoveryRecord = decode(&row.payload)?;
            validate_output_recovery_record_identity(
                &record,
                &namespace,
                record.output_commitment.as_slice(),
                &row.storage_key,
            )?;
            if !records
                .iter()
                .any(|current| current.output_commitment == record.output_commitment)
            {
                records.push(record);
            }
        }
        Ok(records)
    }

    pub fn get_app_settings_record(&self, key: &str) -> Result<Option<Vec<u8>>, DbError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(APP_SETTINGS_TABLE)?;
        match table.get(key)? {
            Some(value) => Ok(Some(value.value().to_vec())),
            None => Ok(None),
        }
    }

    pub fn put_app_settings_record(&self, key: &str, payload: &[u8]) -> Result<(), DbError> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(APP_SETTINGS_TABLE)?;
            table.insert(key, payload)?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn delete_app_settings_record(&self, key: &str) -> Result<(), DbError> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(APP_SETTINGS_TABLE)?;
            table.remove(key)?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn list_app_settings_records(
        &self,
        prefix: &str,
    ) -> Result<Vec<AppSettingsRecord>, DbError> {
        let range_end = prefix_range_end(prefix);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(APP_SETTINGS_TABLE)?;
        let mut out = Vec::new();
        let entries = match range_end.as_deref() {
            Some(range_end) => table.range(prefix..range_end)?,
            None => table.range(prefix..)?,
        };
        for entry in entries {
            let (key, value) = entry?;
            out.push(AppSettingsRecord {
                key: key.value().to_string(),
                payload: value.value().to_vec(),
            });
        }
        Ok(out)
    }

    pub fn get_desktop_wallet_vault_record(&self, key: &str) -> Result<Option<Vec<u8>>, DbError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(DESKTOP_WALLET_VAULT_TABLE)?;
        match table.get(key)? {
            Some(value) => Ok(Some(value.value().to_vec())),
            None => Ok(None),
        }
    }

    pub fn put_desktop_wallet_vault_record(
        &self,
        key: &str,
        payload: &[u8],
    ) -> Result<(), DbError> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(DESKTOP_WALLET_VAULT_TABLE)?;
            table.insert(key, payload)?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn put_desktop_wallet_vault_record_if_absent(
        &self,
        key: &str,
        payload: &[u8],
    ) -> Result<bool, DbError> {
        let txn = self.db.begin_write()?;
        let inserted = {
            let mut table = txn.open_table(DESKTOP_WALLET_VAULT_TABLE)?;
            if table.get(key)?.is_some() {
                false
            } else {
                table.insert(key, payload)?;
                true
            }
        };
        txn.commit()?;
        Ok(inserted)
    }

    pub fn put_desktop_wallet_vault_records(
        &self,
        records: &[(String, Vec<u8>)],
    ) -> Result<(), DbError> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(DESKTOP_WALLET_VAULT_TABLE)?;
            for (key, payload) in records {
                table.insert(key.as_str(), payload.as_slice())?;
            }
        }
        txn.commit()?;
        Ok(())
    }

    pub fn update_desktop_wallet_vault_records(
        &self,
        delete_keys: &[String],
        put_records: &[(String, Vec<u8>)],
    ) -> Result<(), DbError> {
        self.update_desktop_wallet_vault_records_transaction(delete_keys, put_records, || Ok(()))
    }

    fn update_desktop_wallet_vault_records_transaction(
        &self,
        delete_keys: &[String],
        put_records: &[(String, Vec<u8>)],
        before_commit: impl FnOnce() -> Result<(), DbError>,
    ) -> Result<(), DbError> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(DESKTOP_WALLET_VAULT_TABLE)?;
            for key in delete_keys {
                table.remove(key.as_str())?;
            }
            for (key, payload) in put_records {
                table.insert(key.as_str(), payload.as_slice())?;
            }
        }
        before_commit()?;
        txn.commit()?;
        Ok(())
    }

    pub fn delete_desktop_wallet_vault_record(&self, key: &str) -> Result<(), DbError> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(DESKTOP_WALLET_VAULT_TABLE)?;
            table.remove(key)?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn replace_desktop_wallet_vault_prefix_with_records(
        &self,
        prefix: &str,
        records: &[(String, Vec<u8>)],
    ) -> Result<(), DbError> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(DESKTOP_WALLET_VAULT_TABLE)?;
            remove_table_prefix(&mut table, prefix)?;
            for (key, payload) in records {
                table.insert(key.as_str(), payload.as_slice())?;
            }
        }
        txn.commit()?;
        Ok(())
    }

    pub fn list_desktop_wallet_vault_records(
        &self,
        prefix: &str,
    ) -> Result<Vec<DesktopWalletVaultRecord>, DbError> {
        let range_end = prefix_range_end(prefix);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(DESKTOP_WALLET_VAULT_TABLE)?;
        let mut out = Vec::new();
        let entries = match range_end.as_deref() {
            Some(range_end) => table.range(prefix..range_end)?,
            None => table.range(prefix..)?,
        };
        for entry in entries {
            let (key, value) = entry?;
            out.push(DesktopWalletVaultRecord {
                key: key.value().to_string(),
                payload: value.value().to_vec(),
            });
        }
        Ok(out)
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
        txn.open_table(PENDING_FEE_NOTE_ASSURANCE_TABLE)?;
        txn.open_table(TERMINAL_FEE_NOTE_ASSURANCE_TABLE)?;
        txn.open_table(PENDING_OUTPUT_POI_CONTEXT_TABLE)?;
        txn.open_table(OUTPUT_POI_RECOVERY_TABLE)?;
        txn.open_table(PENDING_OUTPUT_POI_CONTEXT_V2_TABLE)?;
        txn.open_table(OUTPUT_POI_RECOVERY_V2_TABLE)?;
        txn.open_table(POI_ARTIFACT_CACHE_TABLE)?;
        txn.open_table(APP_SETTINGS_TABLE)?;
        txn.open_table(DESKTOP_WALLET_VAULT_TABLE)?;
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
            (7, 8..=10) => true,
            (8, 9..=10) | (9, 10) => false,
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
        if to == 10 {
            migrations::migrate_schema_9_to_10(&txn)?;
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

    pub fn update_merkle_forest_meta(
        &self,
        chain_id: u64,
        contract_address: &str,
        path: &Path,
        last_block: u64,
        format_version: u32,
        hash: [u8; 32],
    ) -> Result<(), DbError> {
        let meta = MerkleForestMeta {
            relative_path: self.relative_path(path),
            last_block,
            format_version,
            hash,
        };
        self.put_merkle_forest_meta(chain_id, contract_address, &meta)
    }
}

fn validate_single_blob_component(value: &str, kind: &str) -> Result<(), DbError> {
    let mut components = Path::new(value).components();
    if value.is_empty()
        || value.contains(['/', '\\', '\0', ':'])
        || !matches!(components.next(), Some(Component::Normal(component)) if component == OsStr::new(value))
        || components.next().is_some()
    {
        return Err(DbError::InvalidBlobRelativePath {
            kind: kind.to_string(),
        });
    }
    Ok(())
}

struct BlobTempGuard {
    path: PathBuf,
    armed: bool,
}

impl BlobTempGuard {
    const fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    const fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for BlobTempGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn ensure_storage_directory(path: &Path, kind: &str) -> Result<(), DbError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(DbError::InvalidBlobRelativePath {
            kind: kind.to_string(),
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match std::fs::create_dir(path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    ensure_storage_directory(path, kind)
                }
                Err(error) => Err(error.into()),
            }
        }
        Err(error) => Err(error.into()),
    }
}

fn validate_existing_blob_directory(path: &Path, kind: &str) -> Result<bool, DbError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(true),
        Ok(_) => Err(DbError::UnsafeBlobEntry {
            kind: kind.to_string(),
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn validate_blob_replace_destination(path: &Path, kind: &str) -> Result<(), DbError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(DbError::UnsafeBlobEntry {
            kind: kind.to_string(),
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
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

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, DbError> {
    Ok(rmp_serde::to_vec_named(value)?)
}

fn decode<T: DeserializeOwned>(data: &[u8]) -> Result<T, DbError> {
    Ok(rmp_serde::from_slice(data)?)
}

fn remove_table_prefix(table: &mut Table<'_, &str, &[u8]>, prefix: &str) -> Result<u64, DbError> {
    remove_table_prefix_matching(table, prefix, |_| true)
}

fn remove_table_prefix_matching(
    table: &mut Table<'_, &str, &[u8]>,
    prefix: &str,
    mut matches: impl FnMut(&str) -> bool,
) -> Result<u64, DbError> {
    let range_end = prefix_range_end(prefix);
    let mut removed = 0_u64;
    let mut retain = |key: &str, _: &[u8]| {
        let remove = matches(key);
        if remove {
            removed = removed.saturating_add(1);
        }
        !remove
    };
    match range_end.as_deref() {
        Some(range_end) => {
            table.retain_in(prefix..range_end, &mut retain)?;
        }
        None => {
            table.retain_in(prefix.., &mut retain)?;
        }
    }
    Ok(removed)
}

fn prefix_range_end(prefix: &str) -> Option<String> {
    let mut end = prefix.to_string();
    while let Some(last) = end.pop() {
        let mut next = u32::from(last).saturating_add(1);
        while next <= u32::from(char::MAX) {
            if let Some(next) = char::from_u32(next) {
                end.push(next);
                return Some(end);
            }
            next = next.saturating_add(1);
        }
    }
    None
}

fn blob_index_key(kind: &str, id: &str) -> String {
    format!("{kind}|{id}")
}

fn merkle_forest_key(chain_id: u64, contract: &str) -> String {
    format!("{chain_id}|{contract}")
}

fn wallet_utxo_key(wallet_id: &WalletCacheKey, utxo_id: &str) -> String {
    format!("{wallet_id}|{utxo_id}")
}

fn wallet_utxo_prefix(wallet_id: &WalletCacheKey) -> String {
    format!("{wallet_id}|")
}

fn wallet_private_namespace(
    chain_id: u64,
    wallet_id: &str,
) -> Result<WalletPrivateNamespaceId, DbError> {
    Ok(WalletPrivateNamespaceId::new(chain_id, wallet_id.parse()?))
}

fn validate_pending_output_record_identity(
    record: &PendingOutputPoiContextRecord,
    namespace: &WalletPrivateNamespaceId,
    row_id: &[u8],
    storage_key: &str,
) -> Result<(), DbError> {
    if record.chain_id != namespace.chain_id
        || record.wallet_id != namespace.wallet_id.as_str()
        || record.output_commitment.as_slice() != row_id
        || record.key() != storage_key
    {
        return Err(DbError::WalletPrivateRecordIdentityMismatch {
            kind: WalletPrivateRecordKind::PendingOutputPoiContext.label(),
            key: storage_key.to_owned(),
        });
    }
    Ok(())
}

fn validate_output_recovery_record_identity(
    record: &OutputPoiRecoveryRecord,
    namespace: &WalletPrivateNamespaceId,
    row_id: &[u8],
    storage_key: &str,
) -> Result<(), DbError> {
    if record.chain_id != namespace.chain_id
        || record.wallet_id != namespace.wallet_id.as_str()
        || record.output_commitment.as_slice() != row_id
        || record.key() != storage_key
    {
        return Err(DbError::WalletPrivateRecordIdentityMismatch {
            kind: WalletPrivateRecordKind::OutputPoiRecovery.label(),
            key: storage_key.to_owned(),
        });
    }
    Ok(())
}

fn legacy_wallet_private_row_prefix(namespace: &WalletPrivateNamespaceId) -> String {
    format!("{}|{}|", namespace.chain_id, namespace.wallet_id)
}

fn opaque_wallet_private_row_prefix(namespace: &WalletPrivateNamespaceId) -> String {
    legacy_wallet_private_row_prefix(namespace)
}

fn opaque_wallet_private_row_key(
    namespace: &WalletPrivateNamespaceId,
    row_id: &[u8],
) -> Result<String, DbError> {
    if row_id.is_empty() {
        return Err(DbError::EmptyOpaqueWalletPrivateRowId);
    }
    Ok(format!(
        "{}{}",
        opaque_wallet_private_row_prefix(namespace),
        hex::encode(row_id)
    ))
}

fn opaque_wallet_private_row_id(prefix: &str, key: &str) -> Result<Vec<u8>, DbError> {
    let encoded = key
        .strip_prefix(prefix)
        .filter(|encoded| !encoded.is_empty())
        .ok_or_else(|| DbError::InvalidOpaqueWalletPrivateRowKey {
            key: key.to_owned(),
        })?;
    hex::decode(encoded).map_err(|_| DbError::InvalidOpaqueWalletPrivateRowKey {
        key: key.to_owned(),
    })
}

fn wallet_private_canonicalization_version_key(namespace: &WalletPrivateNamespaceId) -> String {
    format!(
        "{WALLET_PRIVATE_CANONICALIZATION_VERSION_KEY_PREFIX}{}|{}",
        namespace.chain_id, namespace.wallet_id
    )
}

fn decode_wallet_private_canonicalization_version(value: &[u8]) -> Result<u32, DbError> {
    let bytes: [u8; 4] = value
        .try_into()
        .map_err(|_| DbError::InvalidWalletPrivateCanonicalizationVersion)?;
    Ok(u32::from_be_bytes(bytes))
}

const fn validate_opaque_row(row: &OpaqueWalletPrivateRow) -> Result<(), DbError> {
    if row.row_id.is_empty() {
        return Err(DbError::EmptyOpaqueWalletPrivateRowId);
    }
    Ok(())
}

fn validate_opaque_row_mutation(
    mutation: &OpaqueWalletPrivateRowMutation<'_>,
) -> Result<(), DbError> {
    for row in mutation.updates {
        validate_opaque_row(row)?;
    }
    if mutation.deletes.iter().any(Vec::is_empty) {
        return Err(DbError::EmptyOpaqueWalletPrivateRowId);
    }
    Ok(())
}

fn validate_wallet_private_v1_row(
    namespace: &WalletPrivateNamespaceId,
    kind: WalletPrivateRecordKind,
    row: &WalletPrivateV1Row,
) -> Result<(), DbError> {
    let valid = match kind {
        WalletPrivateRecordKind::PendingOutputPoiContext => {
            let record: PendingOutputPoiContextRecord = decode(&row.payload)?;
            record.chain_id == namespace.chain_id
                && record.wallet_id == namespace.wallet_id.as_str()
                && record.key() == row.storage_key
        }
        WalletPrivateRecordKind::OutputPoiRecovery => {
            let record: OutputPoiRecoveryRecord = decode(&row.payload)?;
            record.chain_id == namespace.chain_id
                && record.wallet_id == namespace.wallet_id.as_str()
                && record.key() == row.storage_key
        }
    };
    if valid {
        Ok(())
    } else {
        Err(DbError::WalletPrivateV1MigrationSourceChanged {
            table: kind.v1_table_name(),
            key: row.storage_key.clone(),
        })
    }
}

#[cfg(test)]
mod tests;
