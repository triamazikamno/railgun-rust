use super::*;

use std::collections::BTreeMap;
use std::time::SystemTime;

use alloy::primitives::U256;
use broadcaster_core::tree::{TREE_LEAF_COUNT, normalize_tree_position};
use merkletree::sync::SyncProgress;
use merkletree::tree::{DenseMerkleTree, MerkleTreeUpdate};
use tracing::{debug, warn};

use crate::indexed_artifacts::{
    ChainScope, ChainType, IndexedArtifactChainEntry, IndexedArtifactDescriptor,
    IndexedArtifactManifest, IndexedArtifactManifestClient, IndexedArtifactManifestError,
    IndexedArtifactRangeKind, IndexedDatasetKind, VerifiedIndexedArtifactChunk,
    decode_indexed_artifact_chunk,
};

const COMMITMENT_RECORD_SECTION_ID: u16 = 1;
const MERKLE_CHECKPOINT_SECTION_ID: u16 = 1;
const MERKLE_ARTIFACT_PROGRESS_TOTAL: u64 = 100;
const MERKLE_ARTIFACT_MANIFEST_START_PROGRESS: u64 = 5;
const MERKLE_ARTIFACT_MANIFEST_DONE_PROGRESS: u64 = 20;
const MERKLE_ARTIFACT_CHECKPOINT_DESCRIPTORS_DONE_PROGRESS: u64 = 30;
const MERKLE_ARTIFACT_CHECKPOINT_DECODE_DONE_PROGRESS: u64 = 50;
const MERKLE_ARTIFACT_COMMITMENT_DESCRIPTORS_DONE_PROGRESS: u64 = 60;
const MERKLE_ARTIFACT_COMMITMENT_CHUNKS_DONE_PROGRESS: u64 = 90;
const MERKLE_ARTIFACT_APPLY_START_PROGRESS: u64 = 95;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MerkleArtifactProbe {
    latest_commitment_block: u64,
    latest_commitment_block_hash: [u8; 32],
    commitment_catalog_count: usize,
    checkpoint_catalog_count: usize,
}

impl MerkleArtifactProbe {
    fn from_manifest(
        manifest: &IndexedArtifactManifest,
        scope: &ChainScope,
        from_block: u64,
        to_block: u64,
    ) -> Option<Self> {
        let chain = manifest.chains.iter().find(|entry| entry.scope == *scope)?;
        let latest_commitment = chain
            .latest_indexed
            .iter()
            .filter(|height| height.dataset_kind == IndexedDatasetKind::Commitments)
            .filter(|height| height.block_number <= to_block)
            .max_by_key(|height| height.block_number)?;
        if latest_commitment.block_number < from_block {
            return None;
        }

        let commitment_catalog_count = chain
            .catalogs
            .iter()
            .filter(|catalog| {
                catalog.matches(
                    IndexedDatasetKind::Commitments,
                    scope,
                    IndexedArtifactRangeKind::TreePosition,
                )
            })
            .count();
        let checkpoint_catalog_count = chain
            .catalogs
            .iter()
            .filter(|catalog| {
                catalog.matches(
                    IndexedDatasetKind::MerkleCheckpoint,
                    scope,
                    IndexedArtifactRangeKind::TreePosition,
                )
            })
            .count();
        Some(Self {
            latest_commitment_block: latest_commitment.block_number,
            latest_commitment_block_hash: latest_commitment.block_hash.into(),
            commitment_catalog_count,
            checkpoint_catalog_count,
        })
    }

    const fn catch_up_target(self) -> u64 {
        self.latest_commitment_block
    }
}

struct CommitmentArtifactPage {
    updates: Vec<MerkleTreeUpdate>,
    checkpoint_block: u64,
}

pub(super) struct MerkleArtifactCatchUp {
    pub(super) target_block: u64,
    pub(super) target_block_hash: [u8; 32],
    pub(super) progress: SyncProgress,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MerkleCheckpointArtifactPage {
    tree_number: u32,
    leaf_count: u64,
    last_indexed_block: u64,
    leaves: Vec<U256>,
}

pub(super) async fn run_merkle_artifact_catch_up_into(
    forest: &mut MerkleForest,
    chain: &ChainConfig,
    from_block: u64,
    to_block: u64,
    progress_tx: Option<&SyncProgressSender>,
) -> Result<Option<MerkleArtifactCatchUp>, SyncError> {
    let Some(session) =
        MerkleArtifactSession::prepare(chain, from_block, to_block, progress_tx).await?
    else {
        return Ok(None);
    };

    let progress = session.apply_into(forest)?;
    if progress.latest_commitment_block < session.target_block {
        return Ok(None);
    }
    Ok(Some(MerkleArtifactCatchUp {
        target_block: session.target_block,
        target_block_hash: session.target_block_hash,
        progress,
    }))
}

struct MerkleArtifactSession {
    target_block: u64,
    target_block_hash: [u8; 32],
    checkpoint_pages: Vec<MerkleCheckpointArtifactPage>,
    commitment_pages: Vec<CommitmentArtifactPage>,
}

impl MerkleArtifactSession {
    async fn prepare(
        chain: &ChainConfig,
        from_block: u64,
        to_block: u64,
        progress_tx: Option<&SyncProgressSender>,
    ) -> Result<Option<Self>, SyncError> {
        let Some(config) = chain.indexed_artifact_source.clone() else {
            return Ok(None);
        };
        let scope = chain.indexed_artifact_scope();
        let http_client = chain.http_client.clone().unwrap_or_default();
        let client = IndexedArtifactManifestClient::new(config, http_client);
        send_merkle_artifact_preparation_progress(
            progress_tx,
            MERKLE_ARTIFACT_MANIFEST_START_PROGRESS,
        );
        let manifest = client
            .fetch_manifest(&scope, None, SystemTime::now())
            .await
            .map_err(merkle_artifact_error)?;
        send_merkle_artifact_preparation_progress(
            progress_tx,
            MERKLE_ARTIFACT_MANIFEST_DONE_PROGRESS,
        );
        let Some(probe) =
            MerkleArtifactProbe::from_manifest(&manifest, &scope, from_block, to_block)
        else {
            return Ok(None);
        };
        let target_block = probe.catch_up_target();
        if target_block < from_block {
            return Ok(None);
        }
        let Some(chain_entry) = manifest.chains.iter().find(|entry| entry.scope == scope) else {
            return Ok(None);
        };

        let checkpoint_descriptors = match Self::fetch_checkpoint_descriptors(
            &client,
            chain_entry,
            &scope,
            from_block,
            target_block,
        )
        .await
        {
            Ok(descriptors) => descriptors,
            Err(err) => {
                warn!(
                    ?err,
                    chain_id = chain.chain_id,
                    from_block,
                    target_block,
                    "merkle checkpoint artifact descriptors unavailable; reconstructing from commitments"
                );
                Vec::new()
            }
        };
        send_merkle_artifact_preparation_progress(
            progress_tx,
            MERKLE_ARTIFACT_CHECKPOINT_DESCRIPTORS_DONE_PROGRESS,
        );
        debug!(
            chain_id = chain.chain_id,
            from_block,
            target_block,
            commitment_catalogs = probe.commitment_catalog_count,
            checkpoint_catalogs = probe.checkpoint_catalog_count,
            checkpoint_descriptors = checkpoint_descriptors.len(),
            "selected Merkle checkpoint artifact descriptors"
        );
        let checkpoint_pages = if checkpoint_descriptors.is_empty() {
            Vec::new()
        } else {
            match client.fetch_chunks_bounded(&checkpoint_descriptors).await {
                Ok(chunks) => Self::decode_checkpoint_pages_best_effort(
                    chain.chain_id,
                    from_block,
                    target_block,
                    chunks,
                ),
                Err(err) => {
                    warn!(
                        ?err,
                        chain_id = chain.chain_id,
                        from_block,
                        target_block,
                        checkpoint_descriptors = checkpoint_descriptors.len(),
                        "merkle checkpoint artifact chunks unavailable; reconstructing from commitments"
                    );
                    Vec::new()
                }
            }
        };
        send_merkle_artifact_preparation_progress(
            progress_tx,
            MERKLE_ARTIFACT_CHECKPOINT_DECODE_DONE_PROGRESS,
        );

        let commitment_descriptors = Self::fetch_commitment_descriptors(
            &client,
            chain_entry,
            &scope,
            from_block,
            target_block,
        )
        .await?;
        send_merkle_artifact_preparation_progress(
            progress_tx,
            MERKLE_ARTIFACT_COMMITMENT_DESCRIPTORS_DONE_PROGRESS,
        );
        debug!(
            chain_id = chain.chain_id,
            from_block,
            target_block,
            commitment_descriptors = commitment_descriptors.len(),
            "selected commitment artifact descriptors"
        );
        let completed_checkpoint_chunks = checkpoint_pages.len();
        let total_artifact_chunks =
            completed_checkpoint_chunks.saturating_add(commitment_descriptors.len());
        send_merkle_artifact_chunk_progress(
            progress_tx,
            completed_checkpoint_chunks,
            total_artifact_chunks,
            MERKLE_ARTIFACT_COMMITMENT_DESCRIPTORS_DONE_PROGRESS,
            MERKLE_ARTIFACT_COMMITMENT_CHUNKS_DONE_PROGRESS,
        );
        let commitment_chunks = client
            .fetch_chunks_bounded_with_progress(
                &commitment_descriptors,
                |completed_chunks, total_chunks| {
                    send_merkle_artifact_chunk_progress(
                        progress_tx,
                        completed_checkpoint_chunks.saturating_add(completed_chunks),
                        completed_checkpoint_chunks.saturating_add(total_chunks),
                        MERKLE_ARTIFACT_COMMITMENT_DESCRIPTORS_DONE_PROGRESS,
                        MERKLE_ARTIFACT_COMMITMENT_CHUNKS_DONE_PROGRESS,
                    );
                },
            )
            .await
            .map_err(merkle_artifact_error)?;
        let mut commitment_pages = Vec::with_capacity(commitment_chunks.len());
        for chunk in commitment_chunks {
            commitment_pages.push(CommitmentArtifactPage::try_from(&chunk)?);
        }
        send_merkle_artifact_preparation_progress(
            progress_tx,
            MERKLE_ARTIFACT_APPLY_START_PROGRESS,
        );
        if checkpoint_pages.is_empty() && commitment_pages.is_empty() {
            return Ok(None);
        }

        Ok(Some(Self {
            target_block,
            target_block_hash: probe.latest_commitment_block_hash,
            checkpoint_pages,
            commitment_pages,
        }))
    }

    async fn fetch_checkpoint_descriptors(
        client: &IndexedArtifactManifestClient,
        chain_entry: &IndexedArtifactChainEntry,
        scope: &ChainScope,
        from_block: u64,
        target_block: u64,
    ) -> Result<Vec<IndexedArtifactDescriptor>, SyncError> {
        let mut by_tree = BTreeMap::new();
        for catalog_descriptor in chain_entry.catalogs.iter().filter(|catalog| {
            catalog.matches(
                IndexedDatasetKind::MerkleCheckpoint,
                scope,
                IndexedArtifactRangeKind::TreePosition,
            ) && catalog
                .metadata
                .last_indexed_block
                .is_none_or(|block| block >= from_block)
        }) {
            let catalog = client
                .fetch_catalog(catalog_descriptor)
                .await
                .map_err(merkle_artifact_error)?;
            for chunk in catalog.chunks.into_iter().filter(|chunk| {
                chunk.matches(
                    IndexedDatasetKind::MerkleCheckpoint,
                    scope,
                    IndexedArtifactRangeKind::TreePosition,
                )
            }) {
                let tree_number = chunk.metadata.tree_number.ok_or_else(|| {
                    merkle_artifact_format("checkpoint tree_number metadata missing")
                })?;
                let last_indexed_block = chunk.metadata.last_indexed_block.ok_or_else(|| {
                    merkle_artifact_format("checkpoint last_indexed_block metadata missing")
                })?;
                if last_indexed_block < from_block || last_indexed_block > target_block {
                    continue;
                }
                let replace =
                    by_tree
                        .get(&tree_number)
                        .is_none_or(|current: &IndexedArtifactDescriptor| {
                            Self::checkpoint_descriptor_key(&chunk)
                                > Self::checkpoint_descriptor_key(current)
                        });
                if replace {
                    by_tree.insert(tree_number, chunk);
                }
            }
        }

        let mut descriptors = by_tree.into_values().collect::<Vec<_>>();
        descriptors.sort_by_key(Self::checkpoint_descriptor_key);
        Ok(descriptors)
    }

    async fn fetch_commitment_descriptors(
        client: &IndexedArtifactManifestClient,
        chain_entry: &IndexedArtifactChainEntry,
        scope: &ChainScope,
        from_block: u64,
        target_block: u64,
    ) -> Result<Vec<IndexedArtifactDescriptor>, SyncError> {
        let mut descriptors = Vec::new();
        for catalog_descriptor in chain_entry.catalogs.iter().filter(|catalog| {
            catalog.matches(
                IndexedDatasetKind::Commitments,
                scope,
                IndexedArtifactRangeKind::TreePosition,
            ) && catalog
                .metadata
                .end_block
                .is_none_or(|end_block| end_block >= from_block)
                && catalog
                    .metadata
                    .start_block
                    .is_none_or(|start_block| start_block <= target_block)
        }) {
            let catalog = client
                .fetch_catalog(catalog_descriptor)
                .await
                .map_err(merkle_artifact_error)?;
            for chunk in catalog.chunks.into_iter().filter(|chunk| {
                chunk.matches(
                    IndexedDatasetKind::Commitments,
                    scope,
                    IndexedArtifactRangeKind::TreePosition,
                )
            }) {
                if Self::commitment_chunk_in_block_range(&chunk, from_block, target_block)? {
                    descriptors.push(chunk);
                }
            }
        }
        descriptors.sort_by_key(|chunk| {
            (
                chunk.metadata.start_block.unwrap_or_default(),
                chunk.range.start,
                chunk.range.end,
            )
        });
        Ok(descriptors)
    }

    fn commitment_chunk_in_block_range(
        chunk: &IndexedArtifactDescriptor,
        from_block: u64,
        target_block: u64,
    ) -> Result<bool, SyncError> {
        let start_block = chunk
            .metadata
            .start_block
            .ok_or_else(|| merkle_artifact_format("commitment start_block metadata missing"))?;
        let end_block = chunk
            .metadata
            .end_block
            .ok_or_else(|| merkle_artifact_format("commitment end_block metadata missing"))?;
        if start_block > end_block {
            return Err(merkle_artifact_format(
                "commitment block coverage metadata is inverted",
            ));
        }
        Ok(end_block >= from_block && start_block <= target_block && end_block <= target_block)
    }

    fn checkpoint_descriptor_key(chunk: &IndexedArtifactDescriptor) -> (u16, u64, u64) {
        (
            chunk.metadata.tree_number.unwrap_or_default(),
            chunk.metadata.last_indexed_block.unwrap_or_default(),
            chunk.metadata.leaf_count.unwrap_or_default(),
        )
    }

    fn decode_checkpoint_pages_best_effort(
        chain_id: u64,
        from_block: u64,
        target_block: u64,
        chunks: Vec<VerifiedIndexedArtifactChunk>,
    ) -> Vec<MerkleCheckpointArtifactPage> {
        let mut checkpoint_pages = Vec::with_capacity(chunks.len());
        for chunk in chunks {
            match MerkleCheckpointArtifactPage::try_from(&chunk) {
                Ok(page) => checkpoint_pages.push(page),
                Err(err) => {
                    warn!(
                        ?err,
                        chain_id,
                        from_block,
                        target_block,
                        cid = %chunk.descriptor.cid,
                        range_start = chunk.descriptor.range.start,
                        range_end = chunk.descriptor.range.end,
                        "merkle checkpoint artifact chunk failed verification; reconstructing from commitments"
                    );
                }
            }
        }
        checkpoint_pages
    }

    fn apply_into(&self, forest: &mut MerkleForest) -> Result<SyncProgress, SyncError> {
        let mut latest_block = 0;
        let mut commitments = 0;

        let mut checkpoints = self.checkpoint_pages.iter().collect::<Vec<_>>();
        checkpoints.sort_by_key(|checkpoint| (checkpoint.tree_number, checkpoint.leaf_count));
        let checkpoint_page_count = checkpoints.len();
        for checkpoint in checkpoints {
            latest_block = latest_block.max(checkpoint.last_indexed_block);
            commitments += forest.replace_tree_ordered_leaves(
                checkpoint.tree_number,
                checkpoint.leaf_count,
                checkpoint.leaves.iter().copied(),
            )?;
        }
        debug!(
            checkpoint_pages = checkpoint_page_count,
            checkpoint_commitments = commitments,
            latest_block,
            "applied Merkle checkpoint artifact pages"
        );

        let mut updates = Vec::new();
        for page in &self.commitment_pages {
            latest_block = latest_block.max(page.checkpoint_block);
            for update in &page.updates {
                if let Some(checkpoint_leaf) = self.checkpoint_leaf_for_update(update)? {
                    if checkpoint_leaf != update.hash {
                        return Err(merkle_artifact_format(format!(
                            "commitment tree {} position {} conflicts with checkpoint leaf",
                            update.tree_number, update.tree_position
                        )));
                    }
                    continue;
                }
                updates.push(*update);
            }
        }
        updates.sort_by_key(|update| {
            global_tree_position(update.tree_number, update.tree_position).unwrap_or(u64::MAX)
        });
        let mut previous_global_position = None;
        let commitment_update_count = updates.len();
        for update in updates {
            let global_position = global_tree_position(update.tree_number, update.tree_position)?;
            if previous_global_position == Some(global_position) {
                return Err(merkle_artifact_format(format!(
                    "duplicate commitment global_position {global_position}"
                )));
            }
            previous_global_position = Some(global_position);
            forest.insert_leaf(update)?;
            commitments += 1;
        }
        forest.compute_roots();
        debug!(
            commitment_pages = self.commitment_pages.len(),
            commitment_updates = commitment_update_count,
            latest_block,
            total_commitments = commitments,
            "applied commitment artifact pages in deterministic order"
        );

        Ok(SyncProgress {
            latest_block,
            latest_commitment_block: latest_block,
            commitments,
            nullifiers: 0,
            unshields: 0,
        })
    }

    fn checkpoint_leaf_for_update(
        &self,
        update: &MerkleTreeUpdate,
    ) -> Result<Option<U256>, SyncError> {
        for checkpoint in &self.checkpoint_pages {
            if checkpoint.tree_number != update.tree_number
                || update.tree_position >= checkpoint.leaf_count
            {
                continue;
            }
            let position = usize::try_from(update.tree_position).map_err(|_| {
                merkle_artifact_format("checkpoint-covered commitment position overflow")
            })?;
            let leaf = checkpoint.leaves.get(position).copied().ok_or_else(|| {
                merkle_artifact_format("checkpoint leaf_count exceeds decoded leaves")
            })?;
            return Ok(Some(leaf));
        }
        Ok(None)
    }
}

fn send_merkle_artifact_preparation_progress(
    progress_tx: Option<&SyncProgressSender>,
    current_progress: u64,
) {
    send_sync_progress(
        progress_tx,
        SyncProgressUpdate::artifact_preparation(
            SyncProgressStage::SynchronizingCommitments,
            current_progress,
            MERKLE_ARTIFACT_PROGRESS_TOTAL,
        ),
    );
}

fn send_merkle_artifact_chunk_progress(
    progress_tx: Option<&SyncProgressSender>,
    completed_chunks: usize,
    total_chunks: usize,
    start_progress: u64,
    done_progress: u64,
) {
    let total = u64::try_from(total_chunks).unwrap_or(u64::MAX);
    let current_progress = artifact_chunk_progress(
        completed_chunks,
        total_chunks,
        start_progress,
        done_progress,
    );
    send_sync_progress(
        progress_tx,
        SyncProgressUpdate::artifact_chunk(
            SyncProgressStage::SynchronizingCommitments,
            current_progress,
            MERKLE_ARTIFACT_PROGRESS_TOTAL,
            u64::try_from(completed_chunks).unwrap_or(total).min(total),
            total,
        ),
    );
}

impl TryFrom<&VerifiedIndexedArtifactChunk> for CommitmentArtifactPage {
    type Error = SyncError;

    fn try_from(chunk: &VerifiedIndexedArtifactChunk) -> Result<Self, Self::Error> {
        let envelope = decode_indexed_artifact_chunk(chunk).map_err(merkle_artifact_error)?;
        if envelope.header.dataset_kind != IndexedDatasetKind::Commitments {
            return Err(merkle_artifact_format(
                "chunk is not a commitments artifact",
            ));
        }
        if envelope.header.scope.chain_type != ChainType::Evm {
            return Err(merkle_artifact_format("chunk is not an EVM chain artifact"));
        }
        if envelope.header.range.kind != IndexedArtifactRangeKind::TreePosition {
            return Err(merkle_artifact_format(
                "commitments range is not tree_position scoped",
            ));
        }
        let payload = envelope
            .section_payload(COMMITMENT_RECORD_SECTION_ID)
            .map_err(IndexedArtifactManifestError::from)
            .map_err(merkle_artifact_error)?;
        let mut cursor = MerkleArtifactCursor::new(payload);
        let count = cursor.read_count("commitment count")?;
        let mut previous_global = None;
        let mut updates = Vec::new();
        let start_block = chunk
            .descriptor
            .metadata
            .start_block
            .ok_or_else(|| merkle_artifact_format("commitment start_block metadata missing"))?;
        let end_block = chunk
            .descriptor
            .metadata
            .end_block
            .ok_or_else(|| merkle_artifact_format("commitment end_block metadata missing"))?;
        if start_block > end_block {
            return Err(merkle_artifact_format(
                "commitment block coverage metadata is inverted",
            ));
        }
        let mut decoded_start_block = None;
        let mut decoded_end_block = None;
        let mut checkpoint_block = chunk
            .descriptor
            .metadata
            .checkpoint_block
            .unwrap_or_default();

        for _ in 0..count {
            let global_position = cursor.read_u64("commitment global_position")?;
            if let Some(previous) = previous_global
                && global_position <= previous
            {
                return Err(merkle_artifact_format(format!(
                    "commitment global_position is not increasing: previous {previous}, got {global_position}"
                )));
            }
            previous_global = Some(global_position);
            if global_position < envelope.header.range.start
                || global_position > envelope.header.range.end
            {
                return Err(merkle_artifact_format(format!(
                    "commitment global_position {global_position} is outside descriptor range"
                )));
            }
            let block_number = cursor.read_source_block_number()?;
            if block_number < start_block || block_number > end_block {
                return Err(merkle_artifact_format(format!(
                    "commitment block_number {block_number} is outside descriptor block coverage"
                )));
            }
            decoded_start_block = Some(
                decoded_start_block.map_or(block_number, |block| u64::min(block, block_number)),
            );
            decoded_end_block =
                Some(decoded_end_block.map_or(block_number, |block| u64::max(block, block_number)));
            checkpoint_block = checkpoint_block.max(block_number);
            let _family = cursor.read_commitment_family()?;
            let tree_number = cursor.read_u32("commitment tree_number")?;
            let tree_position = cursor.read_u64("commitment tree_position")?;
            let hash = U256::from_be_bytes(cursor.read_fixed_32("commitment hash")?);
            let (tree_number, tree_position) = normalize_tree_position(tree_number, tree_position);
            let expected_global = global_tree_position(tree_number, tree_position)?;
            if expected_global != global_position {
                return Err(merkle_artifact_format(format!(
                    "commitment global_position mismatch: expected {expected_global}, got {global_position}"
                )));
            }
            updates.push(MerkleTreeUpdate {
                tree_number,
                tree_position,
                hash,
            });
        }
        cursor.expect_eof("commitment artifact section")?;
        if count as u64 != envelope.header.row_count {
            return Err(merkle_artifact_format(format!(
                "commitment row count mismatch: expected {}, got {count}",
                envelope.header.row_count
            )));
        }
        if decoded_start_block != Some(start_block) || decoded_end_block != Some(end_block) {
            return Err(merkle_artifact_format(
                "commitment block coverage metadata does not match decoded records",
            ));
        }
        Ok(Self {
            updates,
            checkpoint_block,
        })
    }
}

impl TryFrom<&VerifiedIndexedArtifactChunk> for MerkleCheckpointArtifactPage {
    type Error = SyncError;

    fn try_from(chunk: &VerifiedIndexedArtifactChunk) -> Result<Self, Self::Error> {
        let envelope = decode_indexed_artifact_chunk(chunk).map_err(merkle_artifact_error)?;
        if envelope.header.dataset_kind != IndexedDatasetKind::MerkleCheckpoint {
            return Err(merkle_artifact_format(
                "chunk is not a merkle_checkpoint artifact",
            ));
        }
        if envelope.header.scope.chain_type != ChainType::Evm {
            return Err(merkle_artifact_format("chunk is not an EVM chain artifact"));
        }
        if envelope.header.range.kind != IndexedArtifactRangeKind::TreePosition {
            return Err(merkle_artifact_format(
                "merkle checkpoint range is not tree_position scoped",
            ));
        }
        let payload = envelope
            .section_payload(MERKLE_CHECKPOINT_SECTION_ID)
            .map_err(IndexedArtifactManifestError::from)
            .map_err(merkle_artifact_error)?;
        let mut cursor = MerkleArtifactCursor::new(payload);
        let tree_number = cursor.read_u32("checkpoint tree_number")?;
        let leaf_count = cursor.read_u64("checkpoint leaf_count")?;
        let root = U256::from_be_bytes(cursor.read_fixed_32("checkpoint root")?);
        let last_indexed_block = cursor.read_u64("checkpoint last_indexed_block")?;
        if leaf_count > TREE_LEAF_COUNT {
            return Err(merkle_artifact_format(format!(
                "checkpoint leaf_count {leaf_count} exceeds tree capacity {TREE_LEAF_COUNT}"
            )));
        }
        let leaf_capacity = usize::try_from(leaf_count)
            .map_err(|_| merkle_artifact_format("checkpoint leaf_count overflows usize"))?;
        let mut leaves = Vec::with_capacity(leaf_capacity);
        for _ in 0..leaf_capacity {
            leaves.push(U256::from_be_bytes(
                cursor.read_fixed_32("checkpoint leaf")?,
            ));
        }
        cursor.expect_eof("merkle checkpoint artifact section")?;
        if envelope.header.row_count != leaf_count {
            return Err(merkle_artifact_format(format!(
                "checkpoint row count mismatch: expected {}, got {leaf_count}",
                envelope.header.row_count
            )));
        }
        if chunk.descriptor.metadata.tree_number.map(u32::from) != Some(tree_number) {
            return Err(merkle_artifact_format(
                "checkpoint tree_number metadata mismatch",
            ));
        }
        if chunk.descriptor.metadata.leaf_count != Some(leaf_count) {
            return Err(merkle_artifact_format(
                "checkpoint leaf_count metadata mismatch",
            ));
        }
        if chunk.descriptor.metadata.last_indexed_block != Some(last_indexed_block) {
            return Err(merkle_artifact_format(
                "checkpoint last_indexed_block metadata mismatch",
            ));
        }
        let range_start = u64::from(tree_number)
            .checked_mul(TREE_LEAF_COUNT)
            .ok_or_else(|| merkle_artifact_format("checkpoint range start overflow"))?;
        let range_end = range_start
            .checked_add(leaf_count.saturating_sub(1))
            .ok_or_else(|| merkle_artifact_format("checkpoint range end overflow"))?;
        if envelope.header.range.start != range_start || envelope.header.range.end != range_end {
            return Err(merkle_artifact_format("checkpoint range metadata mismatch"));
        }
        let computed_root =
            DenseMerkleTree::from_ordered_leaves(leaves.iter().copied(), leaf_count).root();
        if computed_root != root {
            return Err(merkle_artifact_format("checkpoint root mismatch"));
        }
        if let Some(expected_root) = chunk.descriptor.metadata.root.as_ref() {
            let expected_root = U256::from_be_slice(expected_root.as_slice());
            if expected_root != root {
                return Err(merkle_artifact_format(
                    "checkpoint descriptor root metadata mismatch",
                ));
            }
        } else {
            return Err(merkle_artifact_format("checkpoint root metadata missing"));
        }
        Ok(Self {
            tree_number,
            leaf_count,
            last_indexed_block,
            leaves,
        })
    }
}

fn global_tree_position(tree_number: u32, tree_position: u64) -> Result<u64, SyncError> {
    u64::from(tree_number)
        .checked_mul(TREE_LEAF_COUNT)
        .and_then(|base| base.checked_add(tree_position))
        .ok_or_else(|| merkle_artifact_format("commitment global_position overflow"))
}

struct MerkleArtifactCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> MerkleArtifactCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read_source_block_number(&mut self) -> Result<u64, SyncError> {
        self.read_u64("source block_number")
    }

    fn read_commitment_family(&mut self) -> Result<u8, SyncError> {
        let family = self.read_u8("commitment family")?;
        match family {
            0..=3 => Ok(family),
            other => Err(merkle_artifact_format(format!(
                "unknown commitment family id {other}"
            ))),
        }
    }

    fn read_count(&mut self, field: &'static str) -> Result<usize, SyncError> {
        usize::try_from(self.read_u64(field)?)
            .map_err(|_| merkle_artifact_format(format!("{field} overflows usize")))
    }

    fn read_u8(&mut self, field: &'static str) -> Result<u8, SyncError> {
        Ok(self.read_exact(1, field)?[0])
    }

    fn read_u32(&mut self, field: &'static str) -> Result<u32, SyncError> {
        let bytes = self.read_exact(4, field)?;
        Ok(u32::from_le_bytes(
            bytes.try_into().expect("u32 read length"),
        ))
    }

    fn read_u64(&mut self, field: &'static str) -> Result<u64, SyncError> {
        let bytes = self.read_exact(8, field)?;
        Ok(u64::from_le_bytes(
            bytes.try_into().expect("u64 read length"),
        ))
    }

    fn read_fixed_32(&mut self, field: &'static str) -> Result<[u8; 32], SyncError> {
        self.read_exact(32, field)?
            .try_into()
            .map_err(|_| merkle_artifact_format(format!("invalid fixed bytes in {field}")))
    }

    fn read_exact(&mut self, length: usize, field: &'static str) -> Result<&'a [u8], SyncError> {
        let end = self.position.checked_add(length).ok_or_else(|| {
            merkle_artifact_format(format!("merkle artifact overflow in {field}"))
        })?;
        let value = self.bytes.get(self.position..end).ok_or_else(|| {
            merkle_artifact_format(format!("merkle artifact ended while reading {field}"))
        })?;
        self.position = end;
        Ok(value)
    }

    fn expect_eof(&self, field: &'static str) -> Result<(), SyncError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(merkle_artifact_format(format!(
                "{field} has {} trailing bytes",
                self.bytes.len().saturating_sub(self.position)
            )))
        }
    }
}

fn merkle_artifact_error(err: IndexedArtifactManifestError) -> SyncError {
    merkle_artifact_format(err.to_string())
}

fn merkle_artifact_format(message: impl Into<String>) -> SyncError {
    SyncError::UnexpectedFormat(format!("merkle artifact: {}", message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::indexed_artifacts::{
        CompressionAlgorithm, DatasetDescriptorMetadata, INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION,
        INDEXED_ARTIFACT_CHUNK_MAGIC, IndexedArtifactChainEntry, IndexedArtifactDescriptor,
        IndexedArtifactRange, LatestIndexedHeight, PublisherIdentity,
    };
    use alloy::primitives::FixedBytes;
    use sha2::{Digest, Sha256};

    #[test]
    fn merkle_artifact_probe_accepts_commitment_latest_covering_start() {
        let scope = scope();
        let manifest = manifest_with_catalogs(scope.clone(), 200);

        let probe = MerkleArtifactProbe::from_manifest(&manifest, &scope, 120, 200)
            .expect("merkle artifacts available");

        assert_eq!(probe.latest_commitment_block, 200);
        assert_eq!(probe.latest_commitment_block_hash, [0x22; 32]);
        assert_eq!(probe.catch_up_target(), 200);
        assert_eq!(probe.commitment_catalog_count, 1);
        assert_eq!(probe.checkpoint_catalog_count, 1);
    }

    #[test]
    fn merkle_artifact_probe_requires_signed_latest_at_or_before_target() {
        let scope = scope();
        let manifest = manifest_with_catalogs(scope.clone(), 200);

        let probe = MerkleArtifactProbe::from_manifest(&manifest, &scope, 120, 180);

        assert_eq!(probe, None);
    }

    #[test]
    fn commitment_artifact_page_decodes_merkle_updates() {
        let chunk = commitment_chunk(scope(), vec![(TREE_LEAF_COUNT, 101, [0x11; 32])], 101);

        let page = CommitmentArtifactPage::try_from(&chunk).expect("commitment page");

        assert_eq!(page.checkpoint_block, 101);
        assert_eq!(page.updates[0].tree_number, 1);
        assert_eq!(page.updates[0].tree_position, 0);
        assert_eq!(page.updates[0].hash, U256::from_be_bytes([0x11; 32]));
    }

    #[test]
    fn commitment_artifact_page_rejects_mismatched_block_coverage() {
        let mut chunk = commitment_chunk(scope(), vec![(TREE_LEAF_COUNT, 101, [0x11; 32])], 101);
        chunk.descriptor.metadata.start_block = Some(100);
        chunk.descriptor.metadata.end_block = Some(101);

        let error = match CommitmentArtifactPage::try_from(&chunk) {
            Ok(_) => panic!("commitment block coverage mismatch"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("block coverage metadata does not match decoded records")
        );
    }

    #[test]
    fn commitment_artifact_page_accepts_sparse_tree_positions() {
        let chunk = commitment_chunk(
            scope(),
            vec![(0, 101, [0x11; 32]), (2, 101, [0x22; 32])],
            101,
        );

        let page = CommitmentArtifactPage::try_from(&chunk).expect("sparse commitment page");

        assert_eq!(page.updates.len(), 2);
        assert_eq!(page.updates[0].tree_position, 0);
        assert_eq!(page.updates[1].tree_position, 2);
    }

    #[test]
    fn commitment_artifact_page_rejects_extreme_count_without_allocation() {
        let mut payload = Vec::new();
        write_u64(&mut payload, u64::MAX);
        let chunk = chunk(
            scope(),
            IndexedDatasetKind::Commitments,
            0,
            0,
            payload,
            101,
            DatasetDescriptorMetadata {
                start_block: Some(101),
                end_block: Some(101),
                last_indexed_block: Some(101),
                ..Default::default()
            },
        );

        let error = match CommitmentArtifactPage::try_from(&chunk) {
            Ok(_) => panic!("extreme commitment count should fail as a format error"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("ended while reading commitment global_position")
        );
    }

    #[test]
    fn commitment_chunk_selection_requires_safe_block_coverage() {
        let mut descriptor =
            commitment_chunk(scope(), vec![(TREE_LEAF_COUNT, 101, [0x11; 32])], 101).descriptor;

        assert!(
            MerkleArtifactSession::commitment_chunk_in_block_range(&descriptor, 100, 101)
                .expect("coverage valid")
        );
        assert!(
            !MerkleArtifactSession::commitment_chunk_in_block_range(&descriptor, 100, 100)
                .expect("coverage valid")
        );

        descriptor.metadata.start_block = None;
        assert!(
            MerkleArtifactSession::commitment_chunk_in_block_range(&descriptor, 100, 101).is_err()
        );
    }

    #[test]
    fn merkle_checkpoint_artifact_page_verifies_root_and_metadata() {
        let leaves = vec![U256::from(1), U256::from(2)];
        let root = DenseMerkleTree::from_ordered_leaves(leaves.iter().copied(), 2).root();
        let chunk = checkpoint_chunk(scope(), 2, 2, root, 123, leaves.clone());

        let page = MerkleCheckpointArtifactPage::try_from(&chunk).expect("checkpoint page");

        assert_eq!(page.tree_number, 2);
        assert_eq!(page.leaf_count, 2);
        assert_eq!(page.last_indexed_block, 123);
        assert_eq!(page.leaves, leaves);
    }

    #[test]
    fn merkle_checkpoint_artifact_page_rejects_root_metadata_mismatch() {
        let leaves = vec![U256::from(1), U256::from(2)];
        let root = DenseMerkleTree::from_ordered_leaves(leaves.iter().copied(), 2).root();
        let mut chunk = checkpoint_chunk(scope(), 2, 2, root, 123, leaves);
        chunk.descriptor.metadata.root = Some(FixedBytes::from([0xee; 32]));

        let error = match MerkleCheckpointArtifactPage::try_from(&chunk) {
            Ok(_) => panic!("checkpoint root metadata mismatch"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("checkpoint descriptor root metadata mismatch")
        );
    }

    #[test]
    fn merkle_checkpoint_artifact_page_rejects_computed_root_mismatch() {
        let leaves = vec![U256::from(1), U256::from(2)];
        let wrong_root = U256::from(3);
        let chunk = checkpoint_chunk(scope(), 2, 2, wrong_root, 123, leaves);

        let error = match MerkleCheckpointArtifactPage::try_from(&chunk) {
            Ok(_) => panic!("checkpoint computed root mismatch"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("checkpoint root mismatch"));
    }

    #[test]
    fn merkle_checkpoint_artifact_page_rejects_extreme_leaf_count_without_allocation() {
        let root = U256::from(3);
        let mut payload = Vec::new();
        write_u32(&mut payload, 0);
        write_u64(&mut payload, u64::MAX);
        payload.extend_from_slice(&root.to_be_bytes::<32>());
        write_u64(&mut payload, 123);
        let chunk = chunk(
            scope(),
            IndexedDatasetKind::MerkleCheckpoint,
            0,
            0,
            payload,
            123,
            DatasetDescriptorMetadata {
                root: Some(FixedBytes::from(root.to_be_bytes::<32>())),
                tree_number: Some(0),
                leaf_count: Some(u64::MAX),
                last_indexed_block: Some(123),
                ..Default::default()
            },
        );

        let error = MerkleCheckpointArtifactPage::try_from(&chunk)
            .expect_err("extreme checkpoint leaf count should fail as a format error");

        assert!(error.to_string().contains("exceeds tree capacity"));
    }

    #[test]
    fn apply_merkle_artifact_pages_installs_checkpoints_then_sorted_commitments() {
        let mut forest = MerkleForest::new();
        let checkpoint_leaves = vec![U256::from(1), U256::from(2)];
        let checkpoint = MerkleCheckpointArtifactPage {
            tree_number: 0,
            leaf_count: 2,
            last_indexed_block: 100,
            leaves: checkpoint_leaves,
        };
        let commitments = CommitmentArtifactPage {
            updates: vec![
                MerkleTreeUpdate {
                    tree_number: 0,
                    tree_position: 3,
                    hash: U256::from(4),
                },
                MerkleTreeUpdate {
                    tree_number: 0,
                    tree_position: 2,
                    hash: U256::from(3),
                },
            ],
            checkpoint_block: 110,
        };

        let session = artifact_session(100, 110, vec![checkpoint], vec![commitments]);
        let progress = session.apply_into(&mut forest).expect("apply artifacts");

        assert_eq!(progress.latest_commitment_block, 110);
        assert_eq!(progress.commitments, 4);
        assert_eq!(forest.leaf_at(0, 0), Some(U256::from(1)));
        assert_eq!(forest.leaf_at(0, 1), Some(U256::from(2)));
        assert_eq!(forest.leaf_at(0, 2), Some(U256::from(3)));
        assert_eq!(forest.leaf_at(0, 3), Some(U256::from(4)));
    }

    #[test]
    fn apply_merkle_artifact_pages_replaces_stale_checkpoint_tree() {
        let mut forest = MerkleForest::new();
        forest
            .insert_leaf(MerkleTreeUpdate {
                tree_number: 0,
                tree_position: 5,
                hash: U256::from(99),
            })
            .expect("insert stale leaf");
        let checkpoint = MerkleCheckpointArtifactPage {
            tree_number: 0,
            leaf_count: 2,
            last_indexed_block: 100,
            leaves: vec![U256::from(1), U256::from(2)],
        };

        let session = artifact_session(50, 100, vec![checkpoint], Vec::new());
        let progress = session.apply_into(&mut forest).expect("apply checkpoint");

        let expected_root =
            DenseMerkleTree::from_ordered_leaves([U256::from(1), U256::from(2)], 2).root();
        assert_eq!(progress.latest_commitment_block, 100);
        assert_eq!(progress.commitments, 2);
        assert_eq!(forest.leaf_at(0, 0), Some(U256::from(1)));
        assert_eq!(forest.leaf_at(0, 1), Some(U256::from(2)));
        assert_eq!(forest.leaf_at(0, 5), None);
        assert_eq!(forest.roots().get(&0), Some(&expected_root));
    }

    #[test]
    fn apply_merkle_artifact_pages_keeps_same_block_commitment_in_other_tree_after_checkpoint() {
        let mut forest = MerkleForest::new();
        let checkpoint = MerkleCheckpointArtifactPage {
            tree_number: 0,
            leaf_count: 1,
            last_indexed_block: 100,
            leaves: vec![U256::from(1)],
        };
        let commitments = CommitmentArtifactPage {
            updates: vec![
                MerkleTreeUpdate {
                    tree_number: 0,
                    tree_position: 0,
                    hash: U256::from(1),
                },
                MerkleTreeUpdate {
                    tree_number: 1,
                    tree_position: 0,
                    hash: U256::from(2),
                },
            ],
            checkpoint_block: 100,
        };

        let session = artifact_session(50, 100, vec![checkpoint], vec![commitments]);
        let progress = session.apply_into(&mut forest).expect("apply artifacts");

        assert_eq!(progress.latest_commitment_block, 100);
        assert_eq!(progress.commitments, 2);
        assert_eq!(forest.leaf_at(0, 0), Some(U256::from(1)));
        assert_eq!(forest.leaf_at(1, 0), Some(U256::from(2)));
    }

    #[test]
    fn apply_merkle_artifact_pages_reconstructs_from_commitments_without_checkpoint() {
        let mut forest = MerkleForest::new();
        let commitments = CommitmentArtifactPage {
            updates: vec![
                MerkleTreeUpdate {
                    tree_number: 1,
                    tree_position: 1,
                    hash: U256::from(11),
                },
                MerkleTreeUpdate {
                    tree_number: 1,
                    tree_position: 0,
                    hash: U256::from(10),
                },
            ],
            checkpoint_block: 120,
        };

        let session = artifact_session(100, 120, Vec::new(), vec![commitments]);
        let progress = session.apply_into(&mut forest).expect("apply artifacts");

        assert_eq!(progress.latest_commitment_block, 120);
        assert_eq!(progress.commitments, 2);
        assert_eq!(forest.leaf_at(1, 0), Some(U256::from(10)));
        assert_eq!(forest.leaf_at(1, 1), Some(U256::from(11)));
    }

    #[test]
    fn merkle_checkpoint_failure_falls_back_to_commitment_replay() {
        let bad_checkpoint = checkpoint_chunk(
            scope(),
            0,
            2,
            U256::from(99),
            100,
            vec![U256::from(1), U256::from(2)],
        );
        let checkpoint_pages = MerkleArtifactSession::decode_checkpoint_pages_best_effort(
            1,
            50,
            120,
            vec![bad_checkpoint],
        );
        assert!(checkpoint_pages.is_empty());
        let commitment_chunk = commitment_chunk(
            scope(),
            vec![(0, 101, [0x11; 32]), (1, 102, [0x22; 32])],
            102,
        );
        let commitment_page =
            CommitmentArtifactPage::try_from(&commitment_chunk).expect("valid commitment page");
        let mut forest = MerkleForest::new();

        let session = artifact_session(50, 102, checkpoint_pages, vec![commitment_page]);
        let progress = session
            .apply_into(&mut forest)
            .expect("reconstruct from commitments");

        assert_eq!(progress.latest_commitment_block, 102);
        assert_eq!(progress.commitments, 2);
        assert_eq!(forest.leaf_at(0, 0), Some(U256::from_be_bytes([0x11; 32])));
        assert_eq!(forest.leaf_at(0, 1), Some(U256::from_be_bytes([0x22; 32])));
    }

    fn manifest_with_catalogs(scope: ChainScope, latest_block: u64) -> IndexedArtifactManifest {
        IndexedArtifactManifest::new(
            1_700_000_000_000,
            1,
            PublisherIdentity::ed25519(FixedBytes::from([0x11; 32])),
            vec![IndexedArtifactChainEntry {
                scope: scope.clone(),
                latest_indexed: vec![LatestIndexedHeight {
                    dataset_kind: IndexedDatasetKind::Commitments,
                    block_number: latest_block,
                    block_hash: FixedBytes::from([0x22; 32]),
                }],
                catalogs: vec![
                    catalog_descriptor(scope.clone(), IndexedDatasetKind::Commitments),
                    catalog_descriptor(scope, IndexedDatasetKind::MerkleCheckpoint),
                ],
            }],
        )
    }

    fn artifact_session(
        _from_block: u64,
        target_block: u64,
        checkpoint_pages: Vec<MerkleCheckpointArtifactPage>,
        commitment_pages: Vec<CommitmentArtifactPage>,
    ) -> MerkleArtifactSession {
        MerkleArtifactSession {
            target_block,
            target_block_hash: [0x22; 32],
            checkpoint_pages,
            commitment_pages,
        }
    }

    fn catalog_descriptor(
        scope: ChainScope,
        dataset_kind: IndexedDatasetKind,
    ) -> IndexedArtifactDescriptor {
        IndexedArtifactDescriptor {
            dataset_kind,
            scope,
            range: IndexedArtifactRange {
                kind: IndexedArtifactRangeKind::TreePosition,
                start: 0,
                end: TREE_LEAF_COUNT,
            },
            row_count: 1,
            cid: "bafymerkletest".to_string(),
            sha256: FixedBytes::from([0x33; 32]),
            byte_size: 1,
            encoding_version: INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION,
            compression: CompressionAlgorithm::None,
            metadata: DatasetDescriptorMetadata::default(),
        }
    }

    fn commitment_chunk(
        scope: ChainScope,
        rows: Vec<(u64, u64, [u8; 32])>,
        checkpoint_block: u64,
    ) -> VerifiedIndexedArtifactChunk {
        let start = rows.first().map_or(0, |row| row.0);
        let end = rows.last().map_or(0, |row| row.0);
        let start_block = rows.iter().map(|row| row.1).min();
        let end_block = rows.iter().map(|row| row.1).max();
        let mut payload = Vec::new();
        write_u64(&mut payload, rows.len() as u64);
        for (global_position, block_number, hash) in rows {
            write_u64(&mut payload, global_position);
            write_source(&mut payload, block_number);
            payload.push(0);
            write_u32(
                &mut payload,
                u32::try_from(global_position / TREE_LEAF_COUNT).expect("tree number"),
            );
            write_u64(&mut payload, global_position % TREE_LEAF_COUNT);
            payload.extend_from_slice(&hash);
        }
        chunk(
            scope,
            IndexedDatasetKind::Commitments,
            start,
            end,
            payload,
            checkpoint_block,
            DatasetDescriptorMetadata {
                checkpoint_block: Some(checkpoint_block),
                start_block,
                end_block,
                last_indexed_block: Some(checkpoint_block),
                ..Default::default()
            },
        )
    }

    fn checkpoint_chunk(
        scope: ChainScope,
        tree_number: u32,
        leaf_count: u64,
        root: U256,
        last_indexed_block: u64,
        leaves: Vec<U256>,
    ) -> VerifiedIndexedArtifactChunk {
        let mut payload = Vec::new();
        write_u32(&mut payload, tree_number);
        write_u64(&mut payload, leaf_count);
        payload.extend_from_slice(&root.to_be_bytes::<32>());
        write_u64(&mut payload, last_indexed_block);
        for leaf in &leaves {
            payload.extend_from_slice(&leaf.to_be_bytes::<32>());
        }
        let start = u64::from(tree_number) * TREE_LEAF_COUNT;
        let end = start + leaf_count - 1;
        chunk(
            scope,
            IndexedDatasetKind::MerkleCheckpoint,
            start,
            end,
            payload,
            last_indexed_block,
            DatasetDescriptorMetadata {
                root: Some(FixedBytes::from(root.to_be_bytes::<32>())),
                checkpoint_block: Some(last_indexed_block),
                tree_number: Some(u16::try_from(tree_number).expect("tree number metadata")),
                leaf_count: Some(leaf_count),
                start_block: None,
                end_block: None,
                last_indexed_block: Some(last_indexed_block),
                ..DatasetDescriptorMetadata::default()
            },
        )
    }

    fn chunk(
        scope: ChainScope,
        dataset_kind: IndexedDatasetKind,
        start: u64,
        end: u64,
        payload: Vec<u8>,
        checkpoint_block: u64,
        metadata: DatasetDescriptorMetadata,
    ) -> VerifiedIndexedArtifactChunk {
        let row_count = match dataset_kind {
            IndexedDatasetKind::Commitments => u64::from_le_bytes(
                payload[0..8]
                    .try_into()
                    .expect("commitment row count bytes"),
            ),
            IndexedDatasetKind::MerkleCheckpoint => metadata.leaf_count.expect("leaf count"),
            IndexedDatasetKind::WalletScan | IndexedDatasetKind::PublicTxid => 0,
        };
        let section_id = match dataset_kind {
            IndexedDatasetKind::Commitments => COMMITMENT_RECORD_SECTION_ID,
            IndexedDatasetKind::MerkleCheckpoint => MERKLE_CHECKPOINT_SECTION_ID,
            IndexedDatasetKind::WalletScan | IndexedDatasetKind::PublicTxid => 1,
        };
        let bytes = chunk_bytes(
            scope.clone(),
            dataset_kind,
            start,
            end,
            row_count,
            section_id,
            payload,
        );
        let descriptor = IndexedArtifactDescriptor {
            dataset_kind,
            scope,
            range: IndexedArtifactRange {
                kind: IndexedArtifactRangeKind::TreePosition,
                start,
                end,
            },
            row_count,
            cid: "bafymerklechunk".to_string(),
            sha256: prefixed_sha256(&bytes),
            byte_size: u64::try_from(bytes.len()).expect("chunk byte size"),
            encoding_version: INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION,
            compression: CompressionAlgorithm::None,
            metadata: DatasetDescriptorMetadata {
                checkpoint_block: Some(checkpoint_block),
                ..metadata
            },
        };
        VerifiedIndexedArtifactChunk { descriptor, bytes }
    }

    fn chunk_bytes(
        scope: ChainScope,
        dataset_kind: IndexedDatasetKind,
        start: u64,
        end: u64,
        row_count: u64,
        section_id: u16,
        payload: Vec<u8>,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(INDEXED_ARTIFACT_CHUNK_MAGIC);
        write_u16(&mut bytes, INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION);
        bytes.push(match dataset_kind {
            IndexedDatasetKind::WalletScan => 0,
            IndexedDatasetKind::Commitments => 1,
            IndexedDatasetKind::MerkleCheckpoint => 2,
            IndexedDatasetKind::PublicTxid => 3,
        });
        bytes.push(0);
        write_u64(&mut bytes, scope.chain_id);
        write_string(
            &mut bytes,
            &format!(
                "0x{}",
                alloy::hex::encode(scope.railgun_contract.as_slice())
            ),
        );
        bytes.push(2);
        write_u64(&mut bytes, start);
        write_u64(&mut bytes, end);
        write_u64(&mut bytes, row_count);
        write_u64(
            &mut bytes,
            u64::try_from(payload.len()).expect("payload len"),
        );
        write_u16(&mut bytes, 1);
        write_u16(&mut bytes, section_id);
        write_u64(&mut bytes, 0);
        write_u64(
            &mut bytes,
            u64::try_from(payload.len()).expect("payload len"),
        );
        bytes.extend(payload);
        bytes
    }

    fn write_source(bytes: &mut Vec<u8>, block_number: u64) {
        write_u64(bytes, block_number);
    }

    fn write_string(bytes: &mut Vec<u8>, value: &str) {
        write_u16(bytes, u16::try_from(value.len()).expect("string len"));
        bytes.extend_from_slice(value.as_bytes());
    }

    fn write_u16(bytes: &mut Vec<u8>, value: u16) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn write_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn write_u64(bytes: &mut Vec<u8>, value: u64) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn prefixed_sha256(bytes: &[u8]) -> FixedBytes<32> {
        FixedBytes::from_slice(&Sha256::digest(bytes))
    }

    fn scope() -> ChainScope {
        ChainScope {
            chain_type: ChainType::Evm,
            chain_id: 1,
            railgun_contract: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .parse()
                .expect("scope address"),
        }
    }
}
