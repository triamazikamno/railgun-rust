use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::{Address, FixedBytes, U256};
use broadcaster_core::tree::TREE_LEAF_COUNT;
use local_db::{BlobMeta, DbError, DbStore};
use merkletree::errors::SyncError;
use merkletree::quick::{IndexedRailgunTransaction, QuickSyncClient};
use merkletree::tree::{DenseMerkleTree, MerkleProof};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{debug, info, warn};
use url::Url;

use crate::types::IndexedArtifactSourceConfig;

mod artifact;
mod index;
mod lookup;
mod manifest;
mod paths;
mod proof;
mod sync;
mod types;

use index::{rebuild_index_for_manifest, update_index_for_page, write_blob_file};
use lookup::{find_target_row, read_tree_leaves};
use paths::{
    artifact_chunk_blob_id, artifact_chunk_file_name, cache_id, index_shard_file_name,
    manifest_file_name, now_epoch_secs, page_file_name, staged_page_file_name,
};
pub(crate) use types::TXID_CACHE_BLOB_KIND;
use types::{
    TXID_CACHE_FORMAT_VERSION, TXID_CACHE_PAGE_SIZE, TXID_CACHE_SYNC_LOCK, TXID_CACHE_TEMP_COUNTER,
    TxidPublicCacheIndexEntry, TxidPublicCacheIndexShard, TxidPublicCacheManifest,
    TxidPublicCachePage, TxidPublicCachePageRef, TxidPublicCacheReadScope, TxidPublicCacheRow,
    TxidPublicCacheSyncState, TxidPublicCacheWritePermit,
};

pub(crate) use lookup::artifact_bounded_transactions_for_outer_hash;
pub(crate) use lookup::validated_transactions_for_outer_hash;
pub(crate) use proof::{
    txid_public_artifact_bounded_proof, txid_public_proof_for_recovered_output,
    txid_public_proof_for_recovered_output_at_index,
};
pub(crate) use sync::reset_txid_public_cache;
pub(crate) use types::{
    TxidPublicCache, TxidPublicCacheEntry, TxidPublicCacheError, TxidPublicCacheKey,
    TxidPublicCacheReset, TxidPublicCacheTransaction, TxidPublicCheckpoint,
    TxidPublicCheckpointCandidate, TxidPublicCheckpointSource, TxidPublicLatestValidated,
    TxidPublicProof,
};

impl TxidPublicCache<'_> {
    pub(crate) fn cached_artifact_txid_index(&self) -> Result<Option<u64>, TxidPublicCacheError> {
        let Some(manifest) = self.load_manifest()? else {
            return Ok(None);
        };
        manifest.validate_for(self.key)?;
        Ok(manifest.artifact_cached_txid_index)
    }
}

#[cfg(test)]
pub(crate) async fn seed_verified_artifact_bound_for_test(
    db: &DbStore,
    key: TxidPublicCacheKey<'_>,
    transactions: Vec<IndexedRailgunTransaction>,
    expected_root: FixedBytes<32>,
) -> Result<(u64, FixedBytes<32>), TxidPublicCacheError> {
    let cache = TxidPublicCache::new(db, key);
    let permit = cache.begin_write().await;
    let mut manifest = permit.cache().load_or_new_manifest()?;
    let page = TxidPublicCachePage::from_indexed_transactions(key, 0, transactions);
    let root = DenseMerkleTree::from_ordered_leaves(
        page.rows
            .iter()
            .map(|row| U256::from_be_bytes(row.txid_leaf_hash.0))
            .collect::<Vec<_>>(),
        page.rows.len() as u64,
    )
    .root();
    let root = FixedBytes::from(root.to_be_bytes::<32>());
    if root != expected_root {
        return Err(TxidPublicCacheError::RootMismatch);
    }
    let bound_index = page.rows.last().map(|row| row.txid_index).ok_or_else(|| {
        TxidPublicCacheError::MetadataMismatch("empty test artifact bound".to_string())
    })?;
    manifest.append_page_after_prefix_validation(&permit, &page)?;
    update_index_for_page(&permit, &page)?;
    manifest.validated_cached_txid_index = Some(bound_index);
    manifest.artifact_cached_txid_index = Some(bound_index);
    manifest
        .insert_checkpoint(
            bound_index,
            root,
            types::TxidPublicCheckpointSource::IndexedArtifact,
        )
        .expect("insert test artifact checkpoint");
    manifest.write_to(&permit)?;
    Ok((bound_index, root))
}

#[cfg(test)]
mod tests;
