use std::collections::HashMap;
use std::sync::Arc;

use futures::future::join_all;
use tokio::sync::RwLock;

use local_db::DbStore;

use crate::chain::{
    ChainError, ChainHandle, ChainService, PublicDataPlaneError, PublicSyncCacheReset,
};
use crate::types::{ChainConfig, ChainKey, GlobalPoiPolicy, WalletConfig};
use crate::wallet::WalletHandle;

#[derive(Debug, thiserror::Error)]
pub enum SyncManagerError {
    #[error("chain not found")]
    ChainNotFound,
    #[error("wallet not found")]
    WalletNotFound,
    #[error("chain error: {0}")]
    Chain(#[from] ChainError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainPublicSyncCacheResetResult {
    pub chain: ChainKey,
    pub result: Result<PublicSyncCacheReset, PublicDataPlaneError>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PublicSyncCachesResetReport {
    pub chains: Vec<ChainPublicSyncCacheResetResult>,
    pub total_removed_entries: u64,
}

impl PublicSyncCachesResetReport {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.chains.is_empty()
    }

    #[must_use]
    pub fn failed_chain_count(&self) -> usize {
        self.chains
            .iter()
            .filter(|chain| chain.result.is_err())
            .count()
    }
}

pub struct SyncManager {
    db: Arc<DbStore>,
    poi_policy: GlobalPoiPolicy,
    chains: RwLock<HashMap<ChainKey, Arc<ChainService>>>,
}

impl SyncManager {
    #[must_use]
    pub fn new(db: Arc<DbStore>, poi_policy: GlobalPoiPolicy) -> Self {
        Self {
            db,
            poi_policy,
            chains: RwLock::new(HashMap::new()),
        }
    }

    pub async fn add_chain(&self, cfg: ChainConfig) -> Result<Arc<ChainService>, SyncManagerError> {
        let key = ChainKey {
            chain_id: cfg.chain_id,
            contract: cfg.contract,
        };
        if let Some(existing) = self.chains.read().await.get(&key) {
            return Ok(Arc::clone(existing));
        }

        let service =
            ChainService::start(Arc::clone(&self.db), cfg, self.poi_policy.clone()).await?;
        self.chains.write().await.insert(key, Arc::clone(&service));
        Ok(service)
    }

    pub async fn remove_chain(&self, key: &ChainKey) {
        let service = self
            .chains
            .write()
            .await
            .remove_entry(key)
            .map(|(_, service)| service);
        if let Some(service) = service {
            service.shutdown().await;
        }
    }

    pub async fn shutdown(&self) {
        let services = self
            .chains
            .write()
            .await
            .drain()
            .map(|(_, service)| service)
            .collect::<Vec<_>>();
        for service in services {
            service.shutdown().await;
        }
    }

    pub async fn add_wallet(&self, cfg: WalletConfig) -> Result<WalletHandle, SyncManagerError> {
        let chain = self
            .chains
            .read()
            .await
            .get(&cfg.chain)
            .cloned()
            .ok_or(SyncManagerError::ChainNotFound)?;
        Ok(chain.register_wallet(cfg).await?)
    }

    pub async fn chain_handle(&self, chain: &ChainKey) -> Option<ChainHandle> {
        self.chains
            .read()
            .await
            .get(chain)
            .map(|service| service.handle())
    }

    pub async fn wallet_handle(&self, chain: &ChainKey, cache_key: &str) -> Option<WalletHandle> {
        let chain = self.chains.read().await.get(chain).cloned()?;
        chain.wallet_handle(cache_key).await
    }

    pub async fn remove_wallet_session(
        &self,
        handle: &WalletHandle,
    ) -> Result<(), SyncManagerError> {
        let chain = self
            .chains
            .read()
            .await
            .get(handle.chain_key())
            .cloned()
            .ok_or(SyncManagerError::ChainNotFound)?;
        chain.unregister_wallet(handle).await;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) async fn insert_chain_for_test(&self, key: ChainKey, service: Arc<ChainService>) {
        self.chains.write().await.insert(key, service);
    }

    pub async fn remove_all_wallets(&self) {
        let chains = self
            .chains
            .read()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for chain in chains {
            chain.unregister_all_wallets().await;
        }
    }

    pub async fn reset_public_sync_caches(&self) -> PublicSyncCachesResetReport {
        let services = {
            let chains = self.chains.read().await;
            chains
                .iter()
                .map(|(chain, service)| (*chain, Arc::clone(service)))
                .collect::<Vec<_>>()
        };
        let chains = join_all(services.into_iter().map(|(chain, service)| async move {
            ChainPublicSyncCacheResetResult {
                chain,
                result: service.public_data_plane().reset_public_cache().await,
            }
        }))
        .await;
        let total_removed_entries = chains
            .iter()
            .filter_map(|chain| chain.result.as_ref().ok())
            .fold(0_u64, |total, reset| {
                total
                    .saturating_add(reset.poi_cache_entries_removed)
                    .saturating_add(reset.wallet_scan_artifact_chunk_entries_removed)
                    .saturating_add(reset.wallet_scan_artifact_chunk_files_removed)
                    .saturating_add(reset.txid_blob_entries_removed)
                    .saturating_add(reset.txid_files_removed)
                    .saturating_add(
                        u64::try_from(reset.coverage_entries_removed).unwrap_or(u64::MAX),
                    )
                    .saturating_add(u64::try_from(reset.diagnostics_removed).unwrap_or(u64::MAX))
            });
        PublicSyncCachesResetReport {
            chains,
            total_removed_entries,
        }
    }

    pub async fn reset_wallet(
        &self,
        cache_key: &str,
        from_block: Option<u64>,
    ) -> Result<(), SyncManagerError> {
        let chains = self.chains.read().await;
        for service in chains.values() {
            match service.reset_wallet(cache_key, from_block).await {
                Ok(()) => return Ok(()),
                Err(ChainError::WalletNotFound) => {}
                Err(err) => return Err(SyncManagerError::Chain(err)),
            }
        }
        Err(SyncManagerError::WalletNotFound)
    }
}
