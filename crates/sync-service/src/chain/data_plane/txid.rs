//! Public TXID cache reads, sync and proofs.

use crate::indexed_artifacts::{ChainScope, ChainType};
use crate::txid_cache::{
    TxidPublicCache, TxidPublicCacheError, TxidPublicCacheKey, TxidPublicCacheTransaction,
    TxidPublicCheckpointCandidate, TxidPublicLatestValidated, TxidPublicProof,
    artifact_bounded_transactions_for_outer_hash, txid_public_artifact_bounded_proof,
    txid_public_proof_for_recovered_output, txid_public_proof_for_recovered_output_at_index,
    validated_transactions_for_outer_hash,
};
use crate::types::IndexedArtifactSourceConfig;
use alloy::primitives::{FixedBytes, U256};
use std::sync::Arc;
use url::Url;

use super::{ChainPublicDataPlane, EVM_CHAIN_TYPE};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PublicTxidCacheKey {
    pub scope: ChainScope,
    pub txid_version: String,
}

impl PublicTxidCacheKey {
    pub(crate) fn new(scope: ChainScope, txid_version: impl Into<String>) -> Self {
        Self {
            scope,
            txid_version: txid_version.into(),
        }
    }

    fn as_cache_key(&self) -> TxidPublicCacheKey<'_> {
        TxidPublicCacheKey {
            chain_type: match self.scope.chain_type {
                ChainType::Evm => EVM_CHAIN_TYPE,
            },
            chain_id: self.scope.chain_id,
            railgun_contract: self.scope.railgun_contract,
            txid_version: &self.txid_version,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PublicTxidLatestValidated {
    pub txid_index: u64,
    pub merkleroot: Option<FixedBytes<32>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PublicTxidTransaction {
    pub txid_index: u64,
    pub transaction: TxidPublicCacheTransaction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublicTxidDataAuthority {
    LatestValidated,
    ArtifactBounded { txid_index: u64 },
}

impl From<TxidPublicLatestValidated> for PublicTxidLatestValidated {
    fn from(latest: TxidPublicLatestValidated) -> Self {
        Self {
            txid_index: latest.txid_index,
            merkleroot: latest.merkleroot,
        }
    }
}

impl From<PublicTxidLatestValidated> for TxidPublicLatestValidated {
    fn from(latest: PublicTxidLatestValidated) -> Self {
        Self {
            txid_index: latest.txid_index,
            merkleroot: latest.merkleroot,
        }
    }
}

pub(crate) struct PublicTxidSyncRequest<'a> {
    pub key: PublicTxidCacheKey,
    pub endpoint: Option<&'a Url>,
    pub http_client: Option<&'a reqwest::Client>,
    pub latest: PublicTxidLatestValidated,
    pub indexed_artifact_source: Option<&'a IndexedArtifactSourceConfig>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum PublicTxidProofTarget {
    KnownIndex {
        txid_index: u64,
        expected_leaf_hash: U256,
        output_start_global: u128,
    },
    UnknownIndex {
        expected_leaf_hash: U256,
        output_start_global: u128,
    },
}

impl PublicTxidProofTarget {
    pub(crate) const fn txid_index(self) -> Option<u64> {
        match self {
            Self::KnownIndex { txid_index, .. } => Some(txid_index),
            Self::UnknownIndex { .. } => None,
        }
    }

    const fn proof_inputs(self) -> (U256, u128) {
        match self {
            Self::KnownIndex {
                expected_leaf_hash,
                output_start_global,
                ..
            }
            | Self::UnknownIndex {
                expected_leaf_hash,
                output_start_global,
            } => (expected_leaf_hash, output_start_global),
        }
    }
}

pub(crate) struct PublicTxidProofRequest {
    pub key: PublicTxidCacheKey,
    pub target: PublicTxidProofTarget,
}

impl ChainPublicDataPlane {
    pub(crate) fn cached_txid_latest_validated(
        &self,
        key: &PublicTxidCacheKey,
    ) -> Result<Option<PublicTxidLatestValidated>, TxidPublicCacheError> {
        let cache = TxidPublicCache::new(self.db.as_ref(), key.as_cache_key());
        cache
            .cached_latest_validated()
            .map(|latest| latest.map(Into::into))
    }

    pub(crate) fn txid_transactions_for_outer_hash(
        &self,
        key: &PublicTxidCacheKey,
        transaction_hash: FixedBytes<32>,
    ) -> Result<Vec<PublicTxidTransaction>, TxidPublicCacheError> {
        validated_transactions_for_outer_hash(
            self.db.as_ref(),
            key.as_cache_key(),
            transaction_hash,
        )
        .map(|entries| {
            entries
                .into_iter()
                .map(|entry| PublicTxidTransaction {
                    txid_index: entry.txid_index,
                    transaction: entry.transaction,
                })
                .collect()
        })
    }

    pub(crate) fn txid_transactions_for_outer_hash_with_authority(
        &self,
        key: &PublicTxidCacheKey,
        transaction_hash: FixedBytes<32>,
    ) -> Result<(Vec<PublicTxidTransaction>, PublicTxidDataAuthority), TxidPublicCacheError> {
        match self.txid_transactions_for_outer_hash(key, transaction_hash) {
            Ok(rows) if !rows.is_empty() => Ok((rows, PublicTxidDataAuthority::LatestValidated)),
            Ok(_) | Err(TxidPublicCacheError::CacheNotReady { .. }) => {
                let entries = artifact_bounded_transactions_for_outer_hash(
                    self.db.as_ref(),
                    key.as_cache_key(),
                    transaction_hash,
                )?;
                let bound = TxidPublicCache::new(self.db.as_ref(), key.as_cache_key())
                    .cached_artifact_txid_index()?
                    .ok_or(TxidPublicCacheError::CacheNotReady {
                        next_index: 0,
                        required_index: 0,
                    })?;
                Ok((
                    entries
                        .into_iter()
                        .map(|entry| PublicTxidTransaction {
                            txid_index: entry.txid_index,
                            transaction: entry.transaction,
                        })
                        .collect(),
                    PublicTxidDataAuthority::ArtifactBounded { txid_index: bound },
                ))
            }
            Err(err) => Err(err),
        }
    }

    pub(crate) async fn sync_txid_public_cache(
        &self,
        request: PublicTxidSyncRequest<'_>,
    ) -> Result<(), TxidPublicCacheError> {
        let cache = TxidPublicCache::new(self.db.as_ref(), request.key.as_cache_key());
        cache
            .sync_with_artifact_source_maintained(
                request.endpoint,
                request.http_client,
                request.latest.into(),
                request.indexed_artifact_source,
                &self.indexed_artifact_maintenance,
                Arc::clone(&self.db),
            )
            .await
    }

    pub(crate) async fn txid_public_checkpoint_candidates(
        &self,
        key: &PublicTxidCacheKey,
        through_index: u64,
    ) -> Result<Vec<TxidPublicCheckpointCandidate>, TxidPublicCacheError> {
        TxidPublicCache::new(self.db.as_ref(), key.as_cache_key())
            .missing_checkpoint_candidates(through_index)
            .await
    }

    pub(crate) async fn commit_txid_public_checkpoint(
        &self,
        key: &PublicTxidCacheKey,
        candidate: TxidPublicCheckpointCandidate,
    ) -> Result<(), TxidPublicCacheError> {
        TxidPublicCache::new(self.db.as_ref(), key.as_cache_key())
            .commit_checkpoint(candidate)
            .await
    }

    pub(crate) fn txid_public_proof(
        &self,
        request: &PublicTxidProofRequest,
    ) -> Result<TxidPublicProof, TxidPublicCacheError> {
        let key = request.key.as_cache_key();
        let cache = TxidPublicCache::new(self.db.as_ref(), key);
        let latest =
            cache
                .cached_latest_validated()?
                .ok_or(TxidPublicCacheError::CacheNotReady {
                    next_index: 0,
                    required_index: request.target.txid_index().unwrap_or(0),
                })?;
        let (expected_leaf_hash, output_start_global) = request.target.proof_inputs();
        let proof = match request.target {
            PublicTxidProofTarget::KnownIndex { txid_index, .. } => {
                txid_public_proof_for_recovered_output_at_index(
                    self.db.as_ref(),
                    key,
                    txid_index,
                    expected_leaf_hash,
                    output_start_global,
                    latest.txid_index,
                    latest.merkleroot,
                )
            }
            PublicTxidProofTarget::UnknownIndex { .. } => txid_public_proof_for_recovered_output(
                self.db.as_ref(),
                key,
                expected_leaf_hash,
                output_start_global,
                latest.txid_index,
                latest.merkleroot,
            ),
        }?;
        if proof.target_txid_index > latest.txid_index || proof.root_txid_index > latest.txid_index
        {
            return Err(TxidPublicCacheError::MetadataMismatch(
                "TXID proof extends beyond its validated marker".to_string(),
            ));
        }
        Ok(proof)
    }

    pub(crate) fn txid_artifact_bounded_proof(
        &self,
        request: &PublicTxidProofRequest,
    ) -> Result<TxidPublicProof, TxidPublicCacheError> {
        let (expected_leaf_hash, output_start_global) = request.target.proof_inputs();
        txid_public_artifact_bounded_proof(
            self.db.as_ref(),
            request.key.as_cache_key(),
            request.target.txid_index(),
            expected_leaf_hash,
            output_start_global,
        )
    }
}
