use super::{
    BlobMeta, DbStore, Digest, ErrorKind, FixedBytes, IndexedArtifactSourceConfig, NonZeroUsize,
    Sha256, SystemTime, TREE_LEAF_COUNT, TXID_CACHE_BLOB_KIND, TXID_CACHE_FORMAT_VERSION,
    TXID_CACHE_PAGE_SIZE, TxidPublicCache, TxidPublicCacheError, TxidPublicCacheKey,
    TxidPublicCacheManifest, TxidPublicCachePage, TxidPublicCacheReadScope, TxidPublicCacheRow,
    TxidPublicCacheTransaction, TxidPublicCacheWritePermit, TxidPublicCheckpointSource, U256,
    artifact_chunk_blob_id, artifact_chunk_file_name, fs, now_epoch_secs, read_tree_leaves, warn,
    write_blob_file,
};

use crate::indexed_artifacts::{
    ChainScope, ChainType, IndexedArtifactDescriptor, IndexedArtifactManifestClient,
    IndexedArtifactRangeKind, IndexedArtifactStreamCatalog, IndexedArtifactStreamPartitionPolicy,
    IndexedArtifactStreamPlan, IndexedArtifactStreamPlanRequest, IndexedDatasetKind,
    VerifiedIndexedArtifactChunk, VerifiedIndexedArtifactChunkStager,
    decode_indexed_artifact_chunk, verify_chunk_bytes,
};

use alloy::sol_types::SolValue;
use broadcaster_core::contracts::railgun::CommitmentPreimage;
use broadcaster_core::transact::{
    DEFAULT_TXID_VERSION, compute_railgun_txid_parts, railgun_txid_leaf_hash_with_output_start,
};
use merkletree::tree::DenseMerkleTree;
use tracing::debug;

mod cache_access;
mod manifest_apply;
mod page_materialize;
mod source_fetch;
mod txid_cursor;

#[allow(clippy::wildcard_imports)]
use page_materialize::*;
#[allow(clippy::wildcard_imports)]
use txid_cursor::*;

/// Keeps the tracing target of the moved items at this module's path.
const LOG_TARGET: &str = module_path!();

// Section 1 held the earlier record layout with a spent-input Merkle root and is not read.
pub(super) const PUBLIC_TXID_RECORD_SECTION_ID: u16 = 3;
const PUBLIC_TXID_UNSHIELD_PREIMAGE_SECTION_ID: u16 = 2;

pub(crate) struct TxidPublicArtifactSource {
    client: IndexedArtifactManifestClient,
    scope: ChainScope,
    txid_version: String,
}

pub(super) struct TxidPublicArtifactChunkPlan {
    pub(super) required: Vec<VerifiedIndexedArtifactChunk>,
    pub(super) stable_current: Vec<VerifiedIndexedArtifactChunk>,
}

pub(super) struct TxidPublicArtifactMaintenance {
    stable_current: Vec<VerifiedIndexedArtifactChunk>,
    read_scope: TxidPublicCacheReadScope,
}

impl TxidPublicArtifactMaintenance {
    pub(super) const fn new(
        stable_current: Vec<VerifiedIndexedArtifactChunk>,
        read_scope: TxidPublicCacheReadScope,
    ) -> Self {
        Self {
            stable_current,
            read_scope,
        }
    }

    pub(super) fn take_stable_current(&mut self) -> Vec<VerifiedIndexedArtifactChunk> {
        std::mem::take(&mut self.stable_current)
    }

    #[must_use]
    pub(super) const fn read_scope(&self) -> TxidPublicCacheReadScope {
        self.read_scope
    }

    pub(super) async fn retain_stable_chunk(
        cache: &TxidPublicCache<'_>,
        chunk: VerifiedIndexedArtifactChunk,
        read_scope: TxidPublicCacheReadScope,
    ) {
        if cache.cached_artifact_chunk(&chunk.descriptor).is_some() {
            return;
        }
        match cache
            .begin_write_for_scope(read_scope)
            .await
            .and_then(|permit| {
                if cache.cached_artifact_chunk(&chunk.descriptor).is_some() {
                    Ok(0)
                } else {
                    permit.retain_artifact_chunks(std::slice::from_ref(&chunk))
                }
            }) {
            Ok(retained) => debug!(
                chain_id = cache.key.chain_id,
                txid_version = cache.key.txid_version,
                retained,
                "retained planner-stable current public TXID artifact chunk"
            ),
            Err(err) => warn!(
                ?err,
                chain_id = cache.key.chain_id,
                txid_version = cache.key.txid_version,
                "failed planner-stable current public TXID artifact retention"
            ),
        }
    }
}

struct PublicTxidCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

#[cfg(test)]
impl TxidPublicArtifactMaintenance {
    pub(super) async fn run(self, cache: &TxidPublicCache<'_>) {
        for chunk in self.stable_current {
            Self::retain_stable_chunk(cache, chunk, self.read_scope).await;
        }
    }
}

#[cfg(test)]
pub(super) mod test_support {
    use super::*;

    pub(in super::super) fn materialize_artifact_pages_with_page_size(
        chunk: &VerifiedIndexedArtifactChunk,
        page_size: NonZeroUsize,
    ) -> Result<Vec<TxidPublicCachePage>, TxidPublicCacheError> {
        materialize_artifact_pages(chunk, page_size)
    }
}
