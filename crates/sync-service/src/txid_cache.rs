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

use index::*;
use lookup::*;
use paths::*;
use types::*;

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
