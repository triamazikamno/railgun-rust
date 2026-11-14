use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::FixedBytes;
use local_db::{
    DbStore, OpaqueWalletPrivateRow, OpaqueWalletPrivateRowMutation, OutputPoiRecoveryRecord,
    PendingOutputPoiContextRecord, WalletCacheKey, WalletMeta, WalletMetaMutation,
    WalletPrivateNamespaceId, WalletPrivateRecordKind, WalletPrivateStateBatch,
    WalletPrivateV1MigrationBatch, WalletSyncActorStateRecord, WalletUtxoRowMutation,
};
use railgun_wallet::WalletUtxo;
use railgun_wallet::wallet_cache::{WalletCacheDbExt, WalletCacheError, serialize_wallet_utxo};

use crate::SenderTransactionCandidate;

use super::{
    WalletCheckpointMutation, WalletPrivateCommit, WalletSyncActorStateCommit, WalletUtxoMutation,
};

pub trait WalletCacheStore: Send + Sync {
    fn commit_wallet_private_state(
        &self,
        commit: WalletPrivateCommit<'_>,
    ) -> Result<(), WalletCacheError>;

    fn load_wallet_utxos(
        &self,
        wallet_id: &WalletCacheKey,
    ) -> Result<Vec<WalletUtxo>, WalletCacheError>;

    fn get_wallet_meta(
        &self,
        wallet_id: &WalletCacheKey,
    ) -> Result<Option<WalletMeta>, WalletCacheError>;

    fn get_wallet_sync_actor_state(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
    ) -> Result<Option<WalletSyncActorStateRecord>, WalletCacheError>;

    fn put_wallet_sync_actor_state(
        &self,
        commit: WalletSyncActorStateCommit<'_>,
    ) -> Result<(), WalletCacheError>;

    fn get_pending_output_poi_context(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
        output_commitment: &FixedBytes<32>,
    ) -> Result<Option<PendingOutputPoiContextRecord>, WalletCacheError>;

    fn list_pending_output_poi_contexts(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
    ) -> Result<Vec<PendingOutputPoiContextRecord>, WalletCacheError>;

    fn get_output_poi_recovery(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
        output_commitment: &FixedBytes<32>,
    ) -> Result<Option<OutputPoiRecoveryRecord>, WalletCacheError>;

    fn list_output_poi_recoveries(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
    ) -> Result<Vec<OutputPoiRecoveryRecord>, WalletCacheError>;

    fn get_sender_transaction_candidate(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
        outer_transaction_hash: &FixedBytes<32>,
    ) -> Result<Option<SenderTransactionCandidate>, WalletCacheError>;

    fn list_sender_transaction_candidates(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
    ) -> Result<Vec<SenderTransactionCandidate>, WalletCacheError>;
}

impl WalletCacheStore for DbStore {
    fn commit_wallet_private_state(
        &self,
        commit: WalletPrivateCommit<'_>,
    ) -> Result<(), WalletCacheError> {
        commit.validate_namespace()?;
        let utxo_entries = match commit.utxo_mutation() {
            WalletUtxoMutation::Preserve => None,
            WalletUtxoMutation::Replace(utxos) => Some(wallet_utxo_entries(utxos)?),
        };
        let meta = match commit.checkpoint_mutation() {
            WalletCheckpointMutation::Preserve => None,
            WalletCheckpointMutation::Set {
                last_scanned_block,
                last_scanned_block_hash,
            } => Some(WalletMeta {
                last_scanned_block,
                updated_at: wallet_cache_now_epoch_secs()?,
                last_scanned_block_hash,
            }),
        };
        let namespace =
            WalletPrivateNamespaceId::new(commit.chain_id(), commit.wallet_id().clone());
        migrate_db_store_wallet_private_v1_rows(self, &namespace)?;
        let pending_output_context_updates = commit
            .pending_output_context_updates()
            .iter()
            .map(pending_output_context_opaque_row)
            .collect::<Result<Vec<_>, WalletCacheError>>()?;
        let pending_output_context_deletes = commit
            .pending_output_context_deletes()
            .iter()
            .map(|commitment| commitment.to_vec())
            .collect::<Vec<_>>();
        let output_poi_recovery_updates = commit
            .output_poi_recovery_updates()
            .iter()
            .map(output_poi_recovery_opaque_row)
            .collect::<Result<Vec<_>, WalletCacheError>>()?;
        let output_poi_recovery_deletes = commit
            .output_poi_recovery_deletes()
            .iter()
            .map(|commitment| commitment.to_vec())
            .collect::<Vec<_>>();
        let sender_transaction_candidate_updates = commit
            .sender_transaction_candidate_updates()
            .iter()
            .map(sender_transaction_candidate_opaque_row)
            .collect::<Result<Vec<_>, WalletCacheError>>()?;
        let sender_transaction_candidate_deletes = commit
            .sender_transaction_candidate_deletes()
            .iter()
            .map(|transaction_hash| transaction_hash.to_vec())
            .collect::<Vec<_>>();
        self.batch_commit_wallet_private_state(&WalletPrivateStateBatch {
            namespace: &namespace,
            utxos: utxo_entries.as_deref().map_or(
                WalletUtxoRowMutation::Preserve,
                WalletUtxoRowMutation::Replace,
            ),
            metadata: meta
                .as_ref()
                .map_or(WalletMetaMutation::Preserve, WalletMetaMutation::Set),
            sync_actor_state: commit.sync_actor_state(),
            pending_output_contexts: OpaqueWalletPrivateRowMutation {
                updates: &pending_output_context_updates,
                deletes: &pending_output_context_deletes,
            },
            output_poi_recoveries: OpaqueWalletPrivateRowMutation {
                updates: &output_poi_recovery_updates,
                deletes: &output_poi_recovery_deletes,
            },
            sender_transaction_candidates: OpaqueWalletPrivateRowMutation {
                updates: &sender_transaction_candidate_updates,
                deletes: &sender_transaction_candidate_deletes,
            },
        })?;
        Ok(())
    }

    fn load_wallet_utxos(
        &self,
        wallet_id: &WalletCacheKey,
    ) -> Result<Vec<WalletUtxo>, WalletCacheError> {
        WalletCacheDbExt::load_wallet_utxos(self, wallet_id)
    }

    fn get_wallet_meta(
        &self,
        wallet_id: &WalletCacheKey,
    ) -> Result<Option<WalletMeta>, WalletCacheError> {
        Ok(Self::get_wallet_meta(self, wallet_id)?)
    }

    fn get_wallet_sync_actor_state(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
    ) -> Result<Option<WalletSyncActorStateRecord>, WalletCacheError> {
        Ok(Self::get_wallet_sync_actor_state(
            self,
            chain_id,
            wallet_id.as_str(),
        )?)
    }

    fn put_wallet_sync_actor_state(
        &self,
        commit: WalletSyncActorStateCommit<'_>,
    ) -> Result<(), WalletCacheError> {
        Ok(Self::put_wallet_sync_actor_state(self, commit.state())?)
    }

    fn get_pending_output_poi_context(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
        output_commitment: &FixedBytes<32>,
    ) -> Result<Option<PendingOutputPoiContextRecord>, WalletCacheError> {
        Ok(Self::get_pending_output_poi_context(
            self,
            chain_id,
            wallet_id.as_str(),
            output_commitment,
        )?)
    }

    fn list_pending_output_poi_contexts(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
    ) -> Result<Vec<PendingOutputPoiContextRecord>, WalletCacheError> {
        Ok(Self::list_pending_output_poi_contexts(
            self,
            chain_id,
            wallet_id.as_str(),
        )?)
    }

    fn get_output_poi_recovery(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
        output_commitment: &FixedBytes<32>,
    ) -> Result<Option<OutputPoiRecoveryRecord>, WalletCacheError> {
        Ok(Self::get_output_poi_recovery(
            self,
            chain_id,
            wallet_id.as_str(),
            output_commitment,
        )?)
    }

    fn list_output_poi_recoveries(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
    ) -> Result<Vec<OutputPoiRecoveryRecord>, WalletCacheError> {
        Ok(Self::list_output_poi_recoveries(
            self,
            chain_id,
            wallet_id.as_str(),
        )?)
    }

    fn get_sender_transaction_candidate(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
        outer_transaction_hash: &FixedBytes<32>,
    ) -> Result<Option<SenderTransactionCandidate>, WalletCacheError> {
        let namespace = WalletPrivateNamespaceId::new(chain_id, wallet_id.clone());
        self.get_opaque_wallet_private_row(
            &namespace,
            WalletPrivateRecordKind::SenderTransactionCandidate,
            outer_transaction_hash.as_slice(),
        )?
        .map(|row| sender_transaction_candidate_from_opaque_row(&namespace, &row))
        .transpose()
    }

    fn list_sender_transaction_candidates(
        &self,
        chain_id: u64,
        wallet_id: &WalletCacheKey,
    ) -> Result<Vec<SenderTransactionCandidate>, WalletCacheError> {
        let namespace = WalletPrivateNamespaceId::new(chain_id, wallet_id.clone());
        self.list_opaque_wallet_private_rows(
            &namespace,
            WalletPrivateRecordKind::SenderTransactionCandidate,
        )?
        .into_iter()
        .map(|row| sender_transaction_candidate_from_opaque_row(&namespace, &row))
        .collect()
    }
}

fn sender_transaction_candidate_opaque_row(
    record: &SenderTransactionCandidate,
) -> Result<OpaqueWalletPrivateRow, WalletCacheError> {
    Ok(OpaqueWalletPrivateRow {
        row_id: record.row_identity(),
        payload: record.encode().map_err(|_| WalletCacheError::Crypto)?,
    })
}

fn sender_transaction_candidate_from_opaque_row(
    namespace: &WalletPrivateNamespaceId,
    row: &OpaqueWalletPrivateRow,
) -> Result<SenderTransactionCandidate, WalletCacheError> {
    let record =
        SenderTransactionCandidate::decode(&row.payload).map_err(|_| WalletCacheError::Crypto)?;
    if record.chain_id != namespace.chain_id
        || record.wallet_id != namespace.wallet_id
        || record.row_identity() != row.row_id
    {
        return Err(WalletCacheError::Crypto);
    }
    Ok(record)
}

fn pending_output_context_opaque_row(
    record: &PendingOutputPoiContextRecord,
) -> Result<OpaqueWalletPrivateRow, WalletCacheError> {
    Ok(OpaqueWalletPrivateRow {
        row_id: record.output_commitment.to_vec(),
        payload: rmp_serde::to_vec_named(record)?,
    })
}

fn migrate_db_store_wallet_private_v1_rows(
    db: &DbStore,
    namespace: &WalletPrivateNamespaceId,
) -> Result<(), WalletCacheError> {
    let sources = db.list_wallet_private_v1_rows(namespace)?;
    if sources.pending_output_contexts.is_empty() && sources.output_poi_recoveries.is_empty() {
        return Ok(());
    }
    let pending_output_context_destinations = sources
        .pending_output_contexts
        .iter()
        .map(|source| {
            let record: PendingOutputPoiContextRecord = rmp_serde::from_slice(&source.payload)?;
            if record.chain_id != namespace.chain_id
                || record.wallet_id != namespace.wallet_id.as_str()
            {
                return Err(WalletCacheError::Crypto);
            }
            pending_output_context_opaque_row(&record)
        })
        .collect::<Result<Vec<_>, WalletCacheError>>()?;
    let output_poi_recovery_destinations = sources
        .output_poi_recoveries
        .iter()
        .map(|source| {
            let record: OutputPoiRecoveryRecord = rmp_serde::from_slice(&source.payload)?;
            if record.chain_id != namespace.chain_id
                || record.wallet_id != namespace.wallet_id.as_str()
            {
                return Err(WalletCacheError::Crypto);
            }
            output_poi_recovery_opaque_row(&record)
        })
        .collect::<Result<Vec<_>, WalletCacheError>>()?;
    db.migrate_wallet_private_v1_rows(&WalletPrivateV1MigrationBatch {
        namespace,
        pending_output_context_sources: &sources.pending_output_contexts,
        pending_output_context_destinations: &pending_output_context_destinations,
        output_poi_recovery_sources: &sources.output_poi_recoveries,
        output_poi_recovery_destinations: &output_poi_recovery_destinations,
    })?;
    Ok(())
}

fn output_poi_recovery_opaque_row(
    record: &OutputPoiRecoveryRecord,
) -> Result<OpaqueWalletPrivateRow, WalletCacheError> {
    Ok(OpaqueWalletPrivateRow {
        row_id: record.output_commitment.to_vec(),
        payload: rmp_serde::to_vec_named(record)?,
    })
}

fn wallet_utxo_entries(utxos: &[WalletUtxo]) -> Result<Vec<(String, Vec<u8>)>, WalletCacheError> {
    utxos
        .iter()
        .map(|utxo| {
            Ok((
                format!("{}:{}", utxo.utxo.tree, utxo.utxo.position),
                serialize_wallet_utxo(utxo)?,
            ))
        })
        .collect()
}

fn wallet_cache_now_epoch_secs() -> Result<u64, std::io::Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(std::io::Error::other)
}
