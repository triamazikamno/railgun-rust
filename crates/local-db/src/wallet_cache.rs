use redb::{ReadableDatabase, ReadableTable};
use serde::{Deserialize, Serialize};

use super::{
    DbError, DbStore, WALLET_META_TABLE, WALLET_SYNC_ACTOR_STATE_TABLE, WALLET_UTXO_TABLE,
    WalletCacheKey, decode, encode, prefix_range_end, remove_table_prefix,
};

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

impl DbStore {
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
}

pub(crate) fn wallet_utxo_key(wallet_id: &WalletCacheKey, utxo_id: &str) -> String {
    format!("{wallet_id}|{utxo_id}")
}

pub(crate) fn wallet_utxo_prefix(wallet_id: &WalletCacheKey) -> String {
    format!("{wallet_id}|")
}
