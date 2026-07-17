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

#[cfg(test)]
use index::{index_entries_for_hash, load_index_shard};
use index::{rebuild_index_for_manifest, update_index_for_page, write_blob_file};
use lookup::{find_target_row, read_tree_leaves};
#[cfg(test)]
use paths::safe_file_component;
use paths::{
    artifact_chunk_blob_id, artifact_chunk_file_name, cache_id, index_shard_file_name,
    manifest_file_name, now_epoch_secs, page_file_name, staged_artifact_page_file_name,
};
pub(crate) use types::TXID_CACHE_BLOB_KIND;
use types::{
    TXID_CACHE_FORMAT_VERSION, TXID_CACHE_PAGE_SIZE, TXID_CACHE_SYNC_LOCK, TXID_CACHE_TEMP_COUNTER,
    TxidPublicCacheIndexEntry, TxidPublicCacheIndexShard, TxidPublicCacheManifest,
    TxidPublicCachePage, TxidPublicCachePageRef, TxidPublicCacheReadScope, TxidPublicCacheRefresh,
    TxidPublicCacheRow, TxidPublicCacheSyncState, TxidPublicCacheTransaction,
    TxidPublicCacheWritePermit,
};

#[cfg(test)]
pub(crate) use proof::txid_public_transaction_for_recovered_output;
#[cfg(test)]
use proof::{
    find_public_recovery_transaction_in_manifest, find_target_row_in_page, row_for_txid_index,
    txid_root_index_for_target,
};
pub(crate) use proof::{
    txid_public_proof_for_recovered_output, txid_public_proof_for_recovered_output_at_index,
};
pub(crate) use sync::reset_txid_public_cache;
#[cfg(test)]
pub(crate) use types::TxidPublicCachedTransaction;
pub(crate) use types::{
    TxidPublicCache, TxidPublicCacheError, TxidPublicCacheKey, TxidPublicCacheReset,
    TxidPublicLatestValidated, TxidPublicProof,
};

#[cfg(test)]
mod tests;
