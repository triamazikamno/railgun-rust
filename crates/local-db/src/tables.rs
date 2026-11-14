use redb::TableDefinition;

pub(crate) type ByteTableDefinition = TableDefinition<'static, &'static str, &'static [u8]>;

pub(crate) const META_TABLE: ByteTableDefinition = TableDefinition::new("meta");
pub(crate) const BLOB_INDEX_TABLE: ByteTableDefinition = TableDefinition::new("blob_index");
pub(crate) const MERKLE_FOREST_INDEX_TABLE: ByteTableDefinition =
    TableDefinition::new("merkle_forest_index");
pub(crate) const ZKEY_INDEX_TABLE: ByteTableDefinition = TableDefinition::new("zkey_index");
pub(crate) const WALLET_UTXO_TABLE: ByteTableDefinition = TableDefinition::new("wallet_utxo");
pub(crate) const WALLET_META_TABLE: ByteTableDefinition = TableDefinition::new("wallet_meta");
pub(crate) const WALLET_SYNC_ACTOR_STATE_TABLE: ByteTableDefinition =
    TableDefinition::new("wallet_sync_actor_state_v1");
pub(crate) const PENDING_OUTPUT_POI_CONTEXT_TABLE: ByteTableDefinition =
    TableDefinition::new("pending_output_poi_context");
pub(crate) const OUTPUT_POI_RECOVERY_TABLE: ByteTableDefinition =
    TableDefinition::new("output_poi_recovery");
pub(crate) const PENDING_OUTPUT_POI_CONTEXT_V2_TABLE: ByteTableDefinition =
    TableDefinition::new("pending_output_poi_context_v2");
pub(crate) const OUTPUT_POI_RECOVERY_V2_TABLE: ByteTableDefinition =
    TableDefinition::new("output_poi_recovery_v2");
pub(crate) const SENDER_TRANSACTION_CANDIDATE_V1_TABLE: ByteTableDefinition =
    TableDefinition::new("sender_transaction_candidate_v1");
pub(crate) const POI_ARTIFACT_CACHE_TABLE: ByteTableDefinition =
    TableDefinition::new("poi_artifact_cache");
pub(crate) const POI_CORPUS_JOURNAL_TABLE: ByteTableDefinition =
    TableDefinition::new("poi_corpus_journal_v1");
pub(crate) const POI_SIDECAR_STATE_TABLE: ByteTableDefinition =
    TableDefinition::new("poi_sidecar_state_v1");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalDbTable {
    Meta,
    BlobIndex,
    MerkleForestIndex,
    ZkeyIndex,
    WalletUtxo,
    WalletMeta,
    WalletSyncActorState,
    PendingOutputPoiContextV1,
    OutputPoiRecoveryV1,
    PendingOutputPoiContextV2,
    OutputPoiRecoveryV2,
    SenderTransactionCandidateV1,
    PoiArtifactCache,
    PoiCorpusJournal,
    PoiSidecarState,
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
    PendingOutputPoiContextV1,
    OutputPoiRecoveryV1,
    OpaqueBytes,
    PoiArtifactCache,
    PoiCorpusJournal,
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
        table: LocalDbTable::SenderTransactionCandidateV1,
        name: "sender_transaction_candidate_v1",
        decode_kind: LocalDbTableDecodeKind::OpaqueBytes,
    },
    LocalDbTableInfo {
        table: LocalDbTable::PoiArtifactCache,
        name: "poi_artifact_cache",
        decode_kind: LocalDbTableDecodeKind::PoiArtifactCache,
    },
    LocalDbTableInfo {
        table: LocalDbTable::PoiCorpusJournal,
        name: "poi_corpus_journal_v1",
        decode_kind: LocalDbTableDecodeKind::PoiCorpusJournal,
    },
    LocalDbTableInfo {
        table: LocalDbTable::PoiSidecarState,
        name: "poi_sidecar_state_v1",
        decode_kind: LocalDbTableDecodeKind::OpaqueBytes,
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
            Self::PendingOutputPoiContextV1 => PENDING_OUTPUT_POI_CONTEXT_TABLE,
            Self::OutputPoiRecoveryV1 => OUTPUT_POI_RECOVERY_TABLE,
            Self::PendingOutputPoiContextV2 => PENDING_OUTPUT_POI_CONTEXT_V2_TABLE,
            Self::OutputPoiRecoveryV2 => OUTPUT_POI_RECOVERY_V2_TABLE,
            Self::SenderTransactionCandidateV1 => SENDER_TRANSACTION_CANDIDATE_V1_TABLE,
            Self::PoiArtifactCache => POI_ARTIFACT_CACHE_TABLE,
            Self::PoiCorpusJournal => POI_CORPUS_JOURNAL_TABLE,
            Self::PoiSidecarState => POI_SIDECAR_STATE_TABLE,
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
