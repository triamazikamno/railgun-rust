use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::{FixedBytes, U256};
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

mod index;
mod lookup;
mod manifest;
mod paths;
mod proof;
mod sync;
mod types;

use index::*;
use lookup::*;
use manifest::*;
use paths::*;
use types::*;

#[cfg(test)]
use proof::{
    find_public_recovery_transaction_in_manifest, find_target_row_in_page, row_for_txid_index,
    txid_root_index_for_target,
};
#[cfg(test)]
use sync::{
    put_txid_public_latest_validated, sync_txid_public_cache_until_recovered_output_with_page_size,
};

#[cfg(test)]
pub(crate) use proof::txid_public_transaction_for_recovered_output;
pub(crate) use proof::{
    txid_public_proof_for_recovered_output, txid_public_proof_for_recovered_output_at_index,
};
pub(crate) use sync::{
    sync_txid_public_cache, sync_txid_public_cache_to_graph_tip,
    txid_public_cached_latest_validated,
};
#[cfg(test)]
pub(crate) use types::TxidPublicCachedTransaction;
pub(crate) use types::{
    TxidPublicCacheError, TxidPublicCacheKey, TxidPublicLatestValidated, TxidPublicProof,
};

#[cfg(test)]
mod tests;
