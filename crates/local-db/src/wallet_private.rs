use std::collections::BTreeSet;

use alloy::hex;
use redb::{ReadTransaction, ReadableDatabase, ReadableTable, WriteTransaction};

use super::{
    AppTableWriter, ByteTableDefinition, DbError, DbStore, META_TABLE, OUTPUT_POI_RECOVERY_TABLE,
    OUTPUT_POI_RECOVERY_V2_TABLE, OutputPoiRecoveryRecord, PENDING_OUTPUT_POI_CONTEXT_TABLE,
    PENDING_OUTPUT_POI_CONTEXT_V2_TABLE, PendingOutputPoiContextRecord,
    SENDER_TRANSACTION_CANDIDATE_V1_TABLE, WALLET_META_TABLE,
    WALLET_PRIVATE_COMPACTION_REQUESTED_KEY, WALLET_SYNC_ACTOR_STATE_TABLE, WALLET_UTXO_TABLE,
    WalletCacheKey, WalletMeta, WalletSyncActorStateRecord, decode, encode, prefix_range_end,
    remove_table_prefix, remove_table_prefix_matching, wallet_utxo_key, wallet_utxo_prefix,
};

const WALLET_PRIVATE_CANONICALIZATION_VERSION_KEY_PREFIX: &str =
    "wallet_private_canonicalization_version_v1:";

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
    SenderTransactionCandidate,
}

impl WalletPrivateRecordKind {
    const fn v1_table(self) -> ByteTableDefinition {
        match self {
            Self::PendingOutputPoiContext => PENDING_OUTPUT_POI_CONTEXT_TABLE,
            Self::OutputPoiRecovery => OUTPUT_POI_RECOVERY_TABLE,
            Self::SenderTransactionCandidate => {
                panic!("sender transaction candidates have no legacy table")
            }
        }
    }

    const fn v2_table(self) -> ByteTableDefinition {
        match self {
            Self::PendingOutputPoiContext => PENDING_OUTPUT_POI_CONTEXT_V2_TABLE,
            Self::OutputPoiRecovery => OUTPUT_POI_RECOVERY_V2_TABLE,
            Self::SenderTransactionCandidate => SENDER_TRANSACTION_CANDIDATE_V1_TABLE,
        }
    }

    const fn v1_table_name(self) -> &'static str {
        match self {
            Self::PendingOutputPoiContext => "pending_output_poi_context",
            Self::OutputPoiRecovery => "output_poi_recovery",
            Self::SenderTransactionCandidate => {
                panic!("sender transaction candidates have no legacy table")
            }
        }
    }

    const fn v2_table_name(self) -> &'static str {
        match self {
            Self::PendingOutputPoiContext => "pending_output_poi_context_v2",
            Self::OutputPoiRecovery => "output_poi_recovery_v2",
            Self::SenderTransactionCandidate => "sender_transaction_candidate_v1",
        }
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::PendingOutputPoiContext => "pending output POI context",
            Self::OutputPoiRecovery => "output POI recovery",
            Self::SenderTransactionCandidate => "sender transaction candidate",
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
    pub sender_transaction_candidate_rows: u64,
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
        self.sender_transaction_candidate_rows = self
            .sender_transaction_candidate_rows
            .saturating_add(other.sender_transaction_candidate_rows);
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
    pub sender_transaction_candidates: OpaqueWalletPrivateRowMutation<'a>,
}

impl DbStore {
    pub fn batch_commit_wallet_private_state(
        &self,
        batch: &WalletPrivateStateBatch<'_>,
    ) -> Result<(), DbError> {
        self.batch_commit_wallet_private_state_with(batch, |_| Ok(()))
    }

    /// Writes `batch` and runs `write` in the same write transaction, committing only when
    /// both succeed.
    pub fn batch_commit_wallet_private_state_with<T, E: From<DbError>>(
        &self,
        batch: &WalletPrivateStateBatch<'_>,
        write: impl FnOnce(&mut AppTableWriter<'_>) -> Result<T, E>,
    ) -> Result<T, E> {
        Self::validate_wallet_private_state_batch(batch)?;
        let txn = self.db.begin_write().map_err(DbError::from)?;
        Self::write_wallet_private_state_batch(&txn, batch)?;
        let value = AppTableWriter::run(&txn, write)?;
        txn.commit().map_err(DbError::from)?;
        Ok(value)
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
        validate_opaque_row_mutation(&batch.sender_transaction_candidates)?;
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
        Self::write_opaque_wallet_private_rows(
            txn,
            batch.namespace,
            WalletPrivateRecordKind::SenderTransactionCandidate,
            batch.sender_transaction_candidates,
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

    pub(crate) fn delete_wallet_private_namespace_transaction(
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
            let sender_transaction_candidate_rows = {
                let mut table = txn.open_table(SENDER_TRANSACTION_CANDIDATE_V1_TABLE)?;
                remove_table_prefix(&mut table, &opaque_prefix)?
            };
            WalletPrivateNamespaceDeletionReport {
                wallet_utxo_rows,
                wallet_meta_rows,
                wallet_sync_actor_state_rows,
                pending_output_poi_context_rows,
                output_poi_recovery_rows,
                sender_transaction_candidate_rows,
            }
        })
    }

    /// Deletes every namespace and runs `write` in the same write transaction, committing
    /// only when both succeed.
    pub fn delete_wallet_namespaces_with<T, E: From<DbError>>(
        &self,
        namespaces: &[WalletPrivateNamespaceId],
        write: impl FnOnce(&mut AppTableWriter<'_>) -> Result<T, E>,
    ) -> Result<(WalletPrivateNamespaceDeletionReport, T), E> {
        let txn = self.db.begin_write().map_err(DbError::from)?;
        let mut report = WalletPrivateNamespaceDeletionReport::default();
        for identity in namespaces {
            report.add_assign_saturating(Self::delete_wallet_private_namespace_in_transaction(
                &txn, identity,
            )?);
        }
        let value = AppTableWriter::run(&txn, write)?;
        txn.commit().map_err(DbError::from)?;
        Ok((report, value))
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

    pub(crate) fn get_opaque_wallet_private_row_in_transaction(
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

    pub(crate) fn list_opaque_wallet_private_rows_in_transaction(
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

    pub(crate) fn put_typed_wallet_private_row(
        &self,
        namespace: &WalletPrivateNamespaceId,
        kind: WalletPrivateRecordKind,
        v1_key: &str,
        row: &OpaqueWalletPrivateRow,
    ) -> Result<(), DbError> {
        self.put_typed_wallet_private_row_transaction(namespace, kind, v1_key, row, || Ok(()))
    }

    pub(crate) fn put_typed_wallet_private_row_transaction<F>(
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

    pub(crate) fn delete_typed_wallet_private_row(
        &self,
        namespace: &WalletPrivateNamespaceId,
        kind: WalletPrivateRecordKind,
        v1_key: &str,
        row_id: &[u8],
    ) -> Result<(), DbError> {
        self.delete_typed_wallet_private_row_transaction(namespace, kind, v1_key, row_id, || Ok(()))
    }

    pub(crate) fn delete_typed_wallet_private_row_transaction<F>(
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

    pub(crate) fn get_wallet_private_v1_payload_in_transaction(
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

    pub(crate) fn list_wallet_private_v1_rows_for_kind_in_transaction(
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

    pub(crate) fn migrate_wallet_private_v1_rows_transaction(
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

    pub(crate) fn canonicalize_wallet_private_rows_transaction(
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
}

fn legacy_wallet_private_row_prefix(namespace: &WalletPrivateNamespaceId) -> String {
    format!("{}|{}|", namespace.chain_id, namespace.wallet_id)
}

fn opaque_wallet_private_row_prefix(namespace: &WalletPrivateNamespaceId) -> String {
    legacy_wallet_private_row_prefix(namespace)
}

pub(crate) fn opaque_wallet_private_row_key(
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
        WalletPrivateRecordKind::SenderTransactionCandidate => false,
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
