//! POI history checkpoints: candidate roots for completed trees and the
//! requested index, and committing a validated candidate.

use super::{
    DenseMerkleTree, FixedBytes, TREE_LEAF_COUNT, TxidPublicCache, TxidPublicCacheError,
    TxidPublicCheckpointCandidate, TxidPublicCheckpointSource, read_tree_leaves,
};

impl TxidPublicCache<'_> {
    pub(crate) async fn missing_checkpoint_candidates(
        &self,
        through_index: u64,
    ) -> Result<Vec<TxidPublicCheckpointCandidate>, TxidPublicCacheError> {
        let permit = self.begin_write().await;
        let read_scope = permit.scope();
        let manifest =
            permit
                .cache()
                .load_manifest()?
                .ok_or(TxidPublicCacheError::CacheNotReady {
                    next_index: 0,
                    required_index: through_index,
                })?;
        manifest.validate_for(self.key)?;
        if manifest
            .validated_cached_txid_index
            .is_none_or(|index| index < through_index)
        {
            return Err(TxidPublicCacheError::CacheNotReady {
                next_index: manifest
                    .validated_cached_txid_index
                    .map_or(0, |index| index.saturating_add(1)),
                required_index: through_index,
            });
        }

        let mut candidates = Vec::new();
        let checkpoint_indexes = checkpoint_candidate_indexes(
            through_index,
            manifest.checkpoints.contains_key(&through_index),
        );
        for root_txid_index in checkpoint_indexes {
            if !manifest.checkpoints.contains_key(&root_txid_index) {
                let tree = root_txid_index / TREE_LEAF_COUNT;
                let index = root_txid_index % TREE_LEAF_COUNT;
                let leaf_count = index + 1;
                let leaves = read_tree_leaves(&manifest, permit.db(), tree, leaf_count)?;
                let root = DenseMerkleTree::from_ordered_leaves(leaves, leaf_count).root();
                candidates.push(TxidPublicCheckpointCandidate {
                    root_txid_index,
                    tree,
                    index,
                    merkleroot: FixedBytes::from(root.to_be_bytes::<32>()),
                    read_scope,
                });
            }
        }
        Ok(candidates)
    }

    pub(crate) async fn commit_checkpoint(
        &self,
        candidate: TxidPublicCheckpointCandidate,
    ) -> Result<(), TxidPublicCacheError> {
        let permit = self.begin_write_for_scope(candidate.read_scope).await?;
        let mut manifest = permit.cache().load_or_new_manifest()?;
        manifest.validate_for(self.key)?;
        if candidate.tree != candidate.root_txid_index / TREE_LEAF_COUNT
            || candidate.index != candidate.root_txid_index % TREE_LEAF_COUNT
        {
            return Err(TxidPublicCacheError::MetadataMismatch(
                "invalid TXID checkpoint candidate".to_string(),
            ));
        }
        manifest.validate_published_prefix(permit.db(), candidate.root_txid_index)?;
        let leaf_count = candidate.index + 1;
        let leaves = read_tree_leaves(&manifest, permit.db(), candidate.tree, leaf_count)?;
        let actual = DenseMerkleTree::from_ordered_leaves(leaves, leaf_count).root();
        if FixedBytes::from(actual.to_be_bytes::<32>()) != candidate.merkleroot {
            return Err(TxidPublicCacheError::RootMismatch);
        }
        manifest.insert_checkpoint(
            candidate.root_txid_index,
            candidate.merkleroot,
            TxidPublicCheckpointSource::PoiHistoryValidation,
        )?;
        manifest.write_to(&permit)
    }
}

pub(super) fn completed_tree_checkpoint_indexes(through_index: u64) -> Vec<u64> {
    let mut indexes = Vec::new();
    let mut root_txid_index = TREE_LEAF_COUNT - 1;
    while root_txid_index <= through_index {
        indexes.push(root_txid_index);
        let Some(next) = root_txid_index.checked_add(TREE_LEAF_COUNT) else {
            break;
        };
        root_txid_index = next;
    }
    indexes
}

pub(super) fn checkpoint_candidate_indexes(
    through_index: u64,
    through_checkpoint_exists: bool,
) -> Vec<u64> {
    let mut indexes = completed_tree_checkpoint_indexes(through_index);
    if !through_checkpoint_exists && !indexes.contains(&through_index) {
        indexes.push(through_index);
    }
    indexes
}
