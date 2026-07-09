use super::*;

use crate::indexed_artifacts::{ChainScope, ChainType};

pub(crate) const TXID_CACHE_BLOB_KIND: &str = "txid_public_cache";
pub(super) const TXID_CACHE_FORMAT_VERSION: u32 = 2;
pub(super) const TXID_CACHE_PAGE_SIZE: NonZeroUsize =
    NonZeroUsize::new(10_000).expect("txid cache page size is non-zero");
pub(super) static TXID_CACHE_SYNC_LOCK: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));
pub(super) static TXID_CACHE_SYNC_STATE: LazyLock<std::sync::Mutex<TxidPublicCacheSyncState>> =
    LazyLock::new(|| std::sync::Mutex::new(TxidPublicCacheSyncState::default()));
pub(super) static TXID_CACHE_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Default)]
pub(super) struct TxidPublicCacheSyncState {
    generations: BTreeMap<PathBuf, u64>,
}

impl TxidPublicCacheSyncState {
    pub(super) fn lock() -> std::sync::MutexGuard<'static, Self> {
        TXID_CACHE_SYNC_STATE
            .lock()
            .expect("TXID public cache sync state lock poisoned")
    }

    pub(super) fn generation(&mut self, db: &DbStore) -> u64 {
        *self
            .generations
            .entry(db.root_dir().to_path_buf())
            .or_insert(0)
    }

    pub(super) fn bump_generation(&mut self, db: &DbStore) -> u64 {
        let generation = self
            .generations
            .entry(db.root_dir().to_path_buf())
            .or_insert(0);
        *generation = generation.saturating_add(1);
        *generation
    }
}

#[derive(Debug, Error)]
pub(crate) enum TxidPublicCacheError {
    #[error("db error: {0}")]
    Db(#[from] DbError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("encode error: {0}")]
    Encode(#[from] rmp_serde::encode::Error),
    #[error("decode error: {0}")]
    Decode(#[from] rmp_serde::decode::Error),
    #[error("quick-sync error: {0}")]
    Sync(#[from] SyncError),
    #[error("indexed artifact error: {0}")]
    Artifact(#[from] crate::indexed_artifacts::IndexedArtifactManifestError),
    #[error("TXID public cache is not ready: next index {next_index}, required {required_index}")]
    CacheNotReady {
        next_index: u64,
        required_index: u64,
    },
    #[error("recovered transaction is missing from local TXID public cache")]
    MissingTarget,
    #[error("multiple cached TXID rows match recovered transaction")]
    AmbiguousTarget,
    #[error("cached TXID page is missing leaf at index {index}")]
    MissingLeaf { index: u64 },
    #[error("cached TXID proof leaf does not match target row")]
    LeafMismatch,
    #[error("cached TXID root does not match latest validated root")]
    RootMismatch,
    #[error("TXID cache metadata mismatch: {0}")]
    MetadataMismatch(String),
    #[error("stale TXID public cache generation: expected {expected}, actual {actual}")]
    StalePublicCacheGeneration { expected: u64, actual: u64 },
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TxidPublicCacheKey<'a> {
    pub chain_type: u8,
    pub chain_id: u64,
    pub txid_version: &'a str,
}

impl TxidPublicCacheKey<'_> {
    pub(crate) fn artifact_scope(
        self,
        railgun_contract: &str,
    ) -> Result<ChainScope, TxidPublicCacheError> {
        let railgun_contract = railgun_contract.parse::<Address>().map_err(|err| {
            TxidPublicCacheError::MetadataMismatch(format!(
                "invalid railgun contract address: {err}"
            ))
        })?;
        Ok(ChainScope {
            chain_type: ChainType::Evm,
            chain_id: self.chain_id,
            railgun_contract,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TxidPublicCache<'a> {
    pub(crate) db: &'a DbStore,
    pub(crate) key: TxidPublicCacheKey<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TxidPublicCacheReadScope {
    generation: u64,
}

pub(super) struct TxidPublicCacheWritePermit<'a> {
    cache: TxidPublicCache<'a>,
    scope: TxidPublicCacheReadScope,
    _guard: tokio::sync::MutexGuard<'static, ()>,
}

impl<'a> TxidPublicCache<'a> {
    pub(crate) const fn new(db: &'a DbStore, key: TxidPublicCacheKey<'a>) -> Self {
        Self { db, key }
    }

    pub(super) async fn begin_write(&self) -> TxidPublicCacheWritePermit<'a> {
        let guard = TXID_CACHE_SYNC_LOCK.lock().await;
        let scope = TxidPublicCacheReadScope {
            generation: TxidPublicCacheSyncState::lock().generation(self.db),
        };
        TxidPublicCacheWritePermit {
            cache: *self,
            scope,
            _guard: guard,
        }
    }

    pub(super) async fn begin_write_for_scope(
        &self,
        scope: TxidPublicCacheReadScope,
    ) -> Result<TxidPublicCacheWritePermit<'a>, TxidPublicCacheError> {
        let guard = TXID_CACHE_SYNC_LOCK.lock().await;
        let current_generation = TxidPublicCacheSyncState::lock().generation(self.db);
        if scope.generation != current_generation {
            return Err(TxidPublicCacheError::StalePublicCacheGeneration {
                expected: current_generation,
                actual: scope.generation,
            });
        }
        Ok(TxidPublicCacheWritePermit {
            cache: *self,
            scope,
            _guard: guard,
        })
    }
}

impl<'a> TxidPublicCacheWritePermit<'a> {
    pub(super) const fn cache(&self) -> TxidPublicCache<'a> {
        self.cache
    }

    pub(super) const fn db(&self) -> &'a DbStore {
        self.cache.db
    }

    pub(super) const fn key(&self) -> TxidPublicCacheKey<'a> {
        self.cache.key
    }

    pub(super) const fn scope(&self) -> TxidPublicCacheReadScope {
        self.scope
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TxidPublicCacheReset {
    pub(crate) blob_entries_removed: u64,
    pub(crate) files_removed: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct TxidPublicProof {
    pub target_txid_index: u64,
    pub root_txid_index: u64,
    pub proof: MerkleProof,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TxidPublicLatestValidated {
    pub txid_index: u64,
    pub merkleroot: Option<FixedBytes<32>>,
}

#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct TxidPublicCachedTransaction {
    pub txid_index: u64,
    pub transaction: TxidPublicCacheTransaction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct TxidPublicCacheManifest {
    pub(super) format_version: u32,
    pub(super) chain_type: u8,
    pub(super) chain_id: u64,
    pub(super) txid_version: String,
    pub(super) page_size: usize,
    pub(super) next_txid_index: u64,
    pub(super) latest_validated_txid_index: Option<u64>,
    pub(super) latest_validated_merkleroot: Option<FixedBytes<32>>,
    #[serde(default)]
    pub(super) validated_cached_txid_index: Option<u64>,
    pub(super) pages: Vec<TxidPublicCachePageRef>,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct TxidPublicCacheRefresh {
    pub(super) fetched_rows: u64,
    pub(super) refreshed_to: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct TxidPublicCachePageRef {
    pub(super) start_index: u64,
    pub(super) row_count: u64,
    pub(super) relative_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct TxidPublicCachePage {
    pub(super) format_version: u32,
    pub(super) start_index: u64,
    pub(super) rows: Vec<TxidPublicCacheRow>,
}

impl TryFrom<Vec<TxidPublicCacheRow>> for TxidPublicCachePage {
    type Error = TxidPublicCacheError;

    fn try_from(rows: Vec<TxidPublicCacheRow>) -> Result<Self, Self::Error> {
        let Some(first) = rows.first() else {
            return Err(TxidPublicCacheError::MetadataMismatch(
                "TXID public cache page cannot be empty".to_string(),
            ));
        };
        Ok(Self {
            format_version: TXID_CACHE_FORMAT_VERSION,
            start_index: first.txid_index,
            rows,
        })
    }
}

impl TxidPublicCachePage {
    pub(super) fn from_indexed_transactions(
        start_index: u64,
        rows: Vec<IndexedRailgunTransaction>,
    ) -> Self {
        Self {
            format_version: TXID_CACHE_FORMAT_VERSION,
            start_index,
            rows: rows
                .into_iter()
                .enumerate()
                .map(|(offset, transaction)| {
                    let txid_index = start_index + offset as u64;
                    let txid_leaf_hash =
                        FixedBytes::from(transaction.txid_leaf_hash().to_be_bytes::<32>());
                    TxidPublicCacheRow {
                        txid_index,
                        txid_leaf_hash,
                        transaction: transaction.into(),
                    }
                })
                .collect(),
        }
    }

    pub(super) fn pages_from_rows(
        rows: Vec<TxidPublicCacheRow>,
    ) -> Result<Vec<Self>, TxidPublicCacheError> {
        let page_size = TXID_CACHE_PAGE_SIZE.get();
        let mut pages = Vec::with_capacity(rows.len().div_ceil(page_size));
        let mut page_rows = Vec::with_capacity(page_size);
        for row in rows {
            page_rows.push(row);
            if page_rows.len() == page_size {
                let full_page_rows =
                    std::mem::replace(&mut page_rows, Vec::with_capacity(page_size));
                pages.push(full_page_rows.try_into()?);
            }
        }
        if !page_rows.is_empty() {
            pages.push(page_rows.try_into()?);
        }
        Ok(pages)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct TxidPublicCacheIndexShard {
    pub(super) format_version: u32,
    pub(super) shard: u8,
    pub(super) entries: Vec<TxidPublicCacheIndexEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct TxidPublicCacheIndexEntry {
    pub(super) transaction_hash: FixedBytes<32>,
    pub(super) txid_index: u64,
    pub(super) page_start_index: u64,
    pub(super) row_offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct TxidPublicCacheRow {
    pub(super) txid_index: u64,
    pub(super) txid_leaf_hash: FixedBytes<32>,
    pub(super) transaction: TxidPublicCacheTransaction,
}

#[cfg(test)]
impl From<TxidPublicCacheRow> for TxidPublicCachedTransaction {
    fn from(row: TxidPublicCacheRow) -> Self {
        Self {
            txid_index: row.txid_index,
            transaction: row.transaction,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TxidPublicCacheTransaction {
    pub id: String,
    pub transaction_hash: FixedBytes<32>,
    pub block_number: u64,
    pub block_timestamp: u64,
    pub merkle_root: U256,
    pub nullifiers: Vec<U256>,
    pub commitments: Vec<U256>,
    pub bound_params_hash: U256,
    pub has_unshield: bool,
    pub utxo_tree_in: u64,
    pub utxo_tree_out: u64,
    pub utxo_batch_start_position_out: u64,
}

impl From<IndexedRailgunTransaction> for TxidPublicCacheTransaction {
    fn from(transaction: IndexedRailgunTransaction) -> Self {
        Self {
            id: transaction.id,
            transaction_hash: transaction.transaction_hash,
            block_number: transaction.block_number.to(),
            block_timestamp: transaction.block_timestamp.to(),
            merkle_root: U256::from_be_bytes(transaction.merkle_root.0),
            nullifiers: transaction.nullifiers,
            commitments: transaction.commitments,
            bound_params_hash: transaction.bound_params_hash,
            has_unshield: transaction.has_unshield,
            utxo_tree_in: transaction.utxo_tree_in.to(),
            utxo_tree_out: transaction.utxo_tree_out.to(),
            utxo_batch_start_position_out: transaction.utxo_batch_start_position_out.to(),
        }
    }
}

impl TxidPublicCacheTransaction {
    pub(crate) fn output_start_global(&self) -> u128 {
        u128::from(self.utxo_tree_out) * u128::from(TREE_LEAF_COUNT)
            + u128::from(self.utxo_batch_start_position_out)
    }

    #[cfg(test)]
    pub(crate) fn output_index(&self, output_commitment: FixedBytes<32>) -> Option<usize> {
        let output_commitment = U256::from_be_bytes(output_commitment.0);
        self.commitments
            .iter()
            .position(|commitment| *commitment == output_commitment)
    }
}
