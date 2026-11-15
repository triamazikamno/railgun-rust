//! The public data plane handle that wallet and app code query.

use crate::types::PoiArtifactCacheProgress;
use crate::wallet::LocalPoiMerkleProofSource;
use alloy::primitives::FixedBytes;
use poi::cache::PoiCacheRootValidation;
use poi::poi::PoiStatus;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::watch;

use super::{
    ChainError, ChainService, EVM_CHAIN_TYPE, LocalPoiQueryUnavailable, LocalPoiRootValidation,
    LocalPoiStatusLookup, PoiArtifactCacheRetry, PoiArtifactPersistenceHandle,
    PublicCacheResetPermit, PublicCoverageAnswer, PublicDataPlaneDiagnostics, PublicDataPlaneError,
    PublicPoiCorpusKey, PublicScanRange, PublicScanRowsAnswer, PublicSyncCacheReset,
};

#[derive(Clone)]
pub struct PublicDataPlaneHandle {
    service: Arc<ChainService>,
}

impl PublicDataPlaneHandle {
    #[must_use]
    pub(crate) const fn new(service: Arc<ChainService>) -> Self {
        Self { service }
    }

    #[must_use]
    pub fn chain_id(&self) -> u64 {
        self.service.chain_id()
    }

    pub async fn public_scan_rows(
        &self,
        range: PublicScanRange,
    ) -> Result<PublicScanRowsAnswer, ChainError> {
        self.service.public_scan_rows(range).await
    }

    pub async fn public_scan_coverage(
        &self,
        range: PublicScanRange,
    ) -> Result<PublicCoverageAnswer, ChainError> {
        self.service.public_scan_coverage(range).await
    }

    pub async fn diagnostics(&self) -> PublicDataPlaneDiagnostics {
        self.service.public_data_plane.diagnostics().await
    }

    /// Returns a proof source derived from this data-plane lifetime.
    ///
    /// Like other handles from a chain service, the returned source must not be used after the
    /// owning sync manager or chain service has shut down.
    pub async fn local_poi_merkle_proof_source(
        &self,
        txid_version: impl Into<String>,
    ) -> Result<LocalPoiMerkleProofSource, PublicDataPlaneError> {
        let corpus = self
            .service
            .public_data_plane
            .ensure_poi_corpus(PublicPoiCorpusKey::new(
                EVM_CHAIN_TYPE,
                self.service.chain_id(),
                txid_version,
            ))
            .await?;
        Ok(corpus.merkle_proof_source())
    }

    pub async fn validate_local_poi_roots(
        &self,
        txid_version: impl Into<String>,
        list_key: FixedBytes<32>,
        submitted_roots: &[FixedBytes<32>],
    ) -> Result<LocalPoiRootValidation, PublicDataPlaneError> {
        if submitted_roots.is_empty() {
            return Ok(LocalPoiRootValidation::Unavailable(
                LocalPoiQueryUnavailable::SubmittedRootsEmpty,
            ));
        }
        let txid_version = txid_version.into();
        let corpus = self
            .service
            .public_data_plane
            .ensure_poi_corpus(PublicPoiCorpusKey::new(
                EVM_CHAIN_TYPE,
                self.service.chain_id(),
                txid_version.clone(),
            ))
            .await?;
        let caches = corpus.local_caches.read().await;
        let Some(cache) = caches.get(&list_key) else {
            return Ok(LocalPoiRootValidation::Unavailable(
                LocalPoiQueryUnavailable::ListUnavailable { list_key },
            ));
        };
        let identity = cache.identity();
        if identity.chain_type != EVM_CHAIN_TYPE
            || identity.chain_id != self.service.chain_id()
            || identity.txid_version != txid_version
            || identity.list_key != list_key
        {
            return Ok(LocalPoiRootValidation::Unavailable(
                LocalPoiQueryUnavailable::CacheIdentityMismatch { list_key },
            ));
        }
        let PoiCacheRootValidation::Validated { roots } = &cache.progress().root_validation else {
            return Ok(LocalPoiRootValidation::Unavailable(
                LocalPoiQueryUnavailable::AcceptedRootsUnavailable { list_key },
            ));
        };
        if roots.is_empty() {
            return Ok(LocalPoiRootValidation::Unavailable(
                LocalPoiQueryUnavailable::AcceptedRootsUnavailable { list_key },
            ));
        }
        if submitted_roots
            .iter()
            .all(|submitted| roots.values().any(|accepted| accepted == submitted))
        {
            Ok(LocalPoiRootValidation::Accepted)
        } else {
            Ok(LocalPoiRootValidation::Unavailable(
                LocalPoiQueryUnavailable::SubmittedRootAbsent { list_key },
            ))
        }
    }

    pub async fn local_poi_statuses(
        &self,
        txid_version: impl Into<String>,
        list_keys: &[FixedBytes<32>],
        blinded_commitment: &FixedBytes<32>,
    ) -> Result<LocalPoiStatusLookup, PublicDataPlaneError> {
        if list_keys.is_empty() {
            return Ok(LocalPoiStatusLookup::Unavailable(
                LocalPoiQueryUnavailable::RequiredListsEmpty,
            ));
        }
        let txid_version = txid_version.into();
        let corpus = self
            .service
            .public_data_plane
            .ensure_poi_corpus(PublicPoiCorpusKey::new(
                EVM_CHAIN_TYPE,
                self.service.chain_id(),
                txid_version.clone(),
            ))
            .await?;
        let caches = corpus.local_caches.read().await;
        let mut statuses = BTreeMap::new();
        for list_key in list_keys {
            let Some(cache) = caches.get(list_key) else {
                return Ok(LocalPoiStatusLookup::Unavailable(
                    LocalPoiQueryUnavailable::ListUnavailable {
                        list_key: *list_key,
                    },
                ));
            };
            let identity = cache.identity();
            if identity.chain_type != EVM_CHAIN_TYPE
                || identity.chain_id != self.service.chain_id()
                || identity.txid_version != txid_version
                || identity.list_key != *list_key
            {
                return Ok(LocalPoiStatusLookup::Unavailable(
                    LocalPoiQueryUnavailable::CacheIdentityMismatch {
                        list_key: *list_key,
                    },
                ));
            }
            let has_accepted_roots = matches!(
                &cache.progress().root_validation,
                PoiCacheRootValidation::Validated { roots } if !roots.is_empty()
            );
            if !has_accepted_roots || cache.status(blinded_commitment) != PoiStatus::Valid {
                return Ok(LocalPoiStatusLookup::Unavailable(
                    LocalPoiQueryUnavailable::StatusUnresolved {
                        list_key: *list_key,
                    },
                ));
            }
            statuses.insert(*list_key, PoiStatus::Valid);
        }
        Ok(LocalPoiStatusLookup::Valid(statuses))
    }

    #[must_use]
    pub fn poi_artifact_cache_progress_rx(
        &self,
    ) -> Option<watch::Receiver<BTreeMap<u64, PoiArtifactCacheProgress>>> {
        self.service
            .public_data_plane
            .poi_artifact_cache_progress_rx()
    }

    pub async fn retry_poi_artifact_cache(
        &self,
    ) -> Result<PoiArtifactCacheRetry, PublicDataPlaneError> {
        self.service
            .public_data_plane
            .retry_poi_artifact_cache(self.service.chain_id())
            .await
    }

    pub async fn reset_public_cache(&self) -> Result<PublicSyncCacheReset, PublicDataPlaneError> {
        self.service.public_data_plane.reset_public_cache().await
    }

    #[must_use]
    pub fn poi_artifact_persistence(&self) -> PoiArtifactPersistenceHandle {
        self.service.public_data_plane.poi_artifact_persistence()
    }

    pub(crate) async fn acquire_public_cache_reset_permit(&self) -> PublicCacheResetPermit {
        self.service
            .public_data_plane
            .acquire_public_cache_reset_permit()
            .await
    }
}
