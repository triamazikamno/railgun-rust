use std::collections::BTreeMap;
use std::time::Duration;

use alloy::hex;
use alloy::primitives::{FixedBytes, U256};
use broadcaster_core::transact::{PreTxPoi, railgun_txid_leaf_hash};
use redb::ReadableDatabase;
use serde::{Deserialize, Serialize};

use super::{
    DbError, DbStore, OpaqueWalletPrivateRow, WalletPrivateNamespaceId, WalletPrivateRecordKind,
    decode, encode, opaque_wallet_private_row_key,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PendingOutputPoiRole {
    BroadcasterFee,
    Recipient,
    Change,
    RecoveredOutgoing,
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

impl DbStore {
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

    pub(crate) fn get_pending_output_poi_context_with_probe_hook<F>(
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

    pub(crate) fn list_pending_output_poi_contexts_with_probe_hook<F>(
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
