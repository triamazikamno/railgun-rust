use std::collections::BTreeMap;

use alloy::primitives::{FixedBytes, U256};
use broadcaster_core::transact::PreTxPoi;
use local_db::{
    DbError, OutputPoiRecoveryRecord, PendingOutputPoiContextRecord, PendingOutputPoiRole,
    WalletCacheKey, WalletSyncActorStateRecord,
};
use railgun_wallet::WalletUtxo;
use railgun_wallet::wallet_cache::WalletCacheError;

use crate::SenderTransactionCandidate;

#[derive(Debug, Clone, Copy)]
pub enum WalletUtxoMutation<'a> {
    Preserve,
    Replace(&'a [WalletUtxo]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletCheckpointMutation {
    Preserve,
    Set {
        last_scanned_block: u64,
        last_scanned_block_hash: Option<[u8; 32]>,
    },
}

pub struct WalletPrivateCommit<'a> {
    wallet_id: &'a WalletCacheKey,
    chain_id: u64,
    utxos: WalletUtxoMutation<'a>,
    checkpoint: WalletCheckpointMutation,
    sync_actor_state: Option<&'a WalletSyncActorStateRecord>,
    pending_output_context_updates: &'a [PendingOutputPoiContextRecord],
    pending_output_context_deletes: &'a [FixedBytes<32>],
    output_poi_recovery_updates: &'a [OutputPoiRecoveryRecord],
    output_poi_recovery_deletes: &'a [FixedBytes<32>],
    sender_transaction_candidate_updates: &'a [SenderTransactionCandidate],
    sender_transaction_candidate_deletes: &'a [FixedBytes<32>],
}

pub struct WalletSyncActorStateCommit<'a> {
    state: &'a WalletSyncActorStateRecord,
}

impl<'a> WalletSyncActorStateCommit<'a> {
    #[must_use]
    pub(crate) fn new(
        _token: &crate::wallet::WalletActorCommitToken<'_>,
        permit: &'a crate::wallet::WalletPrivateMutationPermit<'_>,
        state: &'a WalletSyncActorStateRecord,
    ) -> Self {
        debug_assert_eq!(permit.wallet_id().as_str(), state.wallet_id.as_str());
        Self { state }
    }

    #[must_use]
    pub const fn state(&self) -> &WalletSyncActorStateRecord {
        self.state
    }
}

impl<'a> WalletPrivateCommit<'a> {
    pub(crate) const fn new(
        _token: &crate::wallet::WalletActorCommitToken<'_>,
        permit: &'a crate::wallet::WalletPrivateMutationPermit<'_>,
        utxos: WalletUtxoMutation<'a>,
        checkpoint: WalletCheckpointMutation,
    ) -> Self {
        Self {
            wallet_id: permit.wallet_id(),
            chain_id: permit.chain_id(),
            utxos,
            checkpoint,
            sync_actor_state: None,
            pending_output_context_updates: &[],
            pending_output_context_deletes: &[],
            output_poi_recovery_updates: &[],
            output_poi_recovery_deletes: &[],
            sender_transaction_candidate_updates: &[],
            sender_transaction_candidate_deletes: &[],
        }
    }

    #[must_use]
    pub const fn wallet_id(&self) -> &WalletCacheKey {
        self.wallet_id
    }

    #[must_use]
    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }

    #[must_use]
    pub const fn utxo_mutation(&self) -> WalletUtxoMutation<'a> {
        self.utxos
    }

    #[must_use]
    pub const fn checkpoint_mutation(&self) -> WalletCheckpointMutation {
        self.checkpoint
    }

    #[must_use]
    pub const fn with_pending_output_context_updates(
        mut self,
        updates: &'a [PendingOutputPoiContextRecord],
    ) -> Self {
        self.pending_output_context_updates = updates;
        self
    }

    #[must_use]
    pub const fn with_pending_output_context_deletes(
        mut self,
        deletes: &'a [FixedBytes<32>],
    ) -> Self {
        self.pending_output_context_deletes = deletes;
        self
    }

    #[must_use]
    pub const fn with_output_poi_recovery_updates(
        mut self,
        updates: &'a [OutputPoiRecoveryRecord],
    ) -> Self {
        self.output_poi_recovery_updates = updates;
        self
    }

    #[must_use]
    pub const fn with_output_poi_recovery_deletes(mut self, deletes: &'a [FixedBytes<32>]) -> Self {
        self.output_poi_recovery_deletes = deletes;
        self
    }

    #[must_use]
    pub const fn with_sender_transaction_candidate_updates(
        mut self,
        updates: &'a [SenderTransactionCandidate],
    ) -> Self {
        self.sender_transaction_candidate_updates = updates;
        self
    }

    #[must_use]
    pub const fn with_sender_transaction_candidate_deletes(
        mut self,
        deletes: &'a [FixedBytes<32>],
    ) -> Self {
        self.sender_transaction_candidate_deletes = deletes;
        self
    }

    #[must_use]
    pub const fn with_sync_actor_state(
        mut self,
        sync_actor_state: &'a WalletSyncActorStateRecord,
    ) -> Self {
        self.sync_actor_state = Some(sync_actor_state);
        self
    }

    #[must_use]
    pub const fn sync_actor_state(&self) -> Option<&WalletSyncActorStateRecord> {
        self.sync_actor_state
    }

    #[must_use]
    pub const fn pending_output_context_updates(&self) -> &[PendingOutputPoiContextRecord] {
        self.pending_output_context_updates
    }

    #[must_use]
    pub const fn pending_output_context_deletes(&self) -> &[FixedBytes<32>] {
        self.pending_output_context_deletes
    }

    #[must_use]
    pub const fn output_poi_recovery_updates(&self) -> &[OutputPoiRecoveryRecord] {
        self.output_poi_recovery_updates
    }

    #[must_use]
    pub const fn output_poi_recovery_deletes(&self) -> &[FixedBytes<32>] {
        self.output_poi_recovery_deletes
    }

    #[must_use]
    pub const fn sender_transaction_candidate_updates(&self) -> &[SenderTransactionCandidate] {
        self.sender_transaction_candidate_updates
    }

    #[must_use]
    pub const fn sender_transaction_candidate_deletes(&self) -> &[FixedBytes<32>] {
        self.sender_transaction_candidate_deletes
    }

    pub fn validate_namespace(&self) -> Result<(), WalletCacheError> {
        for (chain_id, wallet_id) in self
            .pending_output_context_updates
            .iter()
            .map(|record| (record.chain_id, record.wallet_id.as_str()))
            .chain(
                self.output_poi_recovery_updates
                    .iter()
                    .map(|record| (record.chain_id, record.wallet_id.as_str())),
            )
            .chain(
                self.sender_transaction_candidate_updates
                    .iter()
                    .map(|record| (record.chain_id, record.wallet_id.as_str())),
            )
        {
            if chain_id != self.chain_id || wallet_id != self.wallet_id.as_str() {
                return Err(DbError::InvalidWalletPrivateCommitNamespace {
                    expected_chain_id: self.chain_id,
                    expected_wallet_id: self.wallet_id.to_string(),
                    actual_chain_id: chain_id,
                    actual_wallet_id: wallet_id.to_owned(),
                }
                .into());
            }
        }
        if let Some(state) = self.sync_actor_state
            && (state.chain_id != self.chain_id || state.wallet_id != self.wallet_id.as_str())
        {
            return Err(DbError::InvalidWalletPrivateCommitNamespace {
                expected_chain_id: self.chain_id,
                expected_wallet_id: self.wallet_id.to_string(),
                actual_chain_id: state.chain_id,
                actual_wallet_id: state.wallet_id.clone(),
            }
            .into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct PendingOutputPoiContextIntent {
    pub txid_version: String,
    pub output_commitment: FixedBytes<32>,
    pub output_npk: FixedBytes<32>,
    pub utxo_tree_in: u64,
    pub railgun_txid: U256,
    pub pre_transaction_pois_per_txid_leaf_per_list:
        BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PreTxPoi>>,
    pub required_poi_list_keys: Vec<FixedBytes<32>>,
    pub output_role: PendingOutputPoiRole,
}

impl PendingOutputPoiContextIntent {
    pub(crate) fn into_record(
        self,
        chain_id: u64,
        wallet_id: String,
        created_at: u64,
    ) -> PendingOutputPoiContextRecord {
        PendingOutputPoiContextRecord {
            chain_id,
            wallet_id,
            txid_version: self.txid_version,
            output_commitment: self.output_commitment,
            output_npk: self.output_npk,
            utxo_tree_in: self.utxo_tree_in,
            railgun_txid: self.railgun_txid,
            txid_merkleroot_index: None,
            pre_transaction_pois_per_txid_leaf_per_list: self
                .pre_transaction_pois_per_txid_leaf_per_list,
            required_poi_list_keys: self.required_poi_list_keys,
            output_role: self.output_role,
            created_at,
            source_operation_id: None,
            observation: None,
            submitted_poi_list_keys: Vec::new(),
            terminal_error: None,
        }
    }
}
