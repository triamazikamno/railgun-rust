use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use local_db::DbStore;

use crate::chain::{
    ChainError, ChainHandle, ChainPublicSyncCacheReset, ChainService, PublicDataPlaneError,
};
use crate::public_cache::{
    PersistedPublicSyncCacheResetError, PersistedPublicSyncCacheResetReport,
    reset_persisted_public_sync_caches_with_generation,
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
    pub result: Result<ChainPublicSyncCacheReset, PublicDataPlaneError>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicSyncCachesResetReport {
    pub chains: Vec<ChainPublicSyncCacheResetResult>,
    pub persisted: Result<PersistedPublicSyncCacheResetReport, PersistedPublicSyncCacheResetError>,
    pub total_removed_entries: u64,
}

impl Default for PublicSyncCachesResetReport {
    fn default() -> Self {
        Self {
            chains: Vec::new(),
            persisted: Ok(PersistedPublicSyncCacheResetReport::default()),
            total_removed_entries: 0,
        }
    }
}

impl PublicSyncCachesResetReport {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.chains.is_empty()
            && self
                .persisted
                .as_ref()
                .is_ok_and(|persisted| persisted.total_removed_entries() == 0)
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
        let mut services = {
            let chains = self.chains.read().await;
            chains
                .iter()
                .map(|(chain, service)| (*chain, Arc::clone(service)))
                .collect::<Vec<_>>()
        };
        services.sort_by(|(left, _), (right, _)| {
            left.chain_id
                .cmp(&right.chain_id)
                .then_with(|| left.contract.as_slice().cmp(right.contract.as_slice()))
        });
        let mut permits = Vec::with_capacity(services.len());
        for (chain, service) in services {
            permits.push((
                chain,
                service
                    .public_data_plane()
                    .acquire_public_cache_reset_permit()
                    .await,
            ));
        }
        let persisted_reset =
            match reset_persisted_public_sync_caches_with_generation(&self.db).await {
                Ok(reset) => reset,
                Err(error) => {
                    let chain_error = PublicDataPlaneError::PublicCacheReset {
                        reason: error.to_string(),
                    };
                    let total_removed_entries = error.partial_report.total_removed_entries();
                    return PublicSyncCachesResetReport {
                        chains: permits
                            .into_iter()
                            .map(|(chain, _permit)| ChainPublicSyncCacheResetResult {
                                chain,
                                result: Err(chain_error.clone()),
                            })
                            .collect(),
                        persisted: Err(error),
                        total_removed_entries,
                    };
                }
            };
        let mut chains = Vec::with_capacity(permits.len());
        for (chain, permit) in permits {
            chains.push(ChainPublicSyncCacheResetResult {
                chain,
                result: permit.apply(&persisted_reset).await,
            });
        }
        let persisted = persisted_reset.report;
        let total_removed_entries = chains
            .iter()
            .filter_map(|chain| chain.result.as_ref().ok())
            .fold(persisted.total_removed_entries(), |total, reset| {
                total.saturating_add(reset.total_removed_entries())
            });
        PublicSyncCachesResetReport {
            chains,
            persisted: Ok(persisted),
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
