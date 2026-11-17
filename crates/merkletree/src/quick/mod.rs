mod graphql;
mod types;

use tracing::info;

use types::Commitment;

use broadcaster_core::tree::{TREE_LEAF_COUNT, normalize_tree_position};

use crate::errors::SyncError;
use crate::sync::{SyncProgress, SyncResult};
use std::collections::{BTreeMap, HashSet};
use std::num::NonZeroUsize;
use url::Url;

use crate::tree::{MerkleForest, MerkleTreeUpdate};

pub use graphql::{
    DEFAULT_PAGE_SIZE, GraphPostError, GraphTimeoutPhase, QuickSyncClient, post_graphql_data,
};
pub use types::{
    IndexedLegacyEncryptedCommitment, IndexedLegacyGeneratedCommitment, IndexedNullifier,
    IndexedRailgunTransaction, IndexedShieldCommitment, IndexedTransactCommitment,
};

#[derive(Debug, Clone)]
pub struct QuickSyncConfig {
    pub endpoint: Url,
    pub start_block: u64,
    pub end_block: Option<u64>,
    pub page_size: NonZeroUsize,
    /// Optional pre-configured HTTP client (e.g. with proxy support).
    pub http_client: Option<reqwest::Client>,
}

impl Default for QuickSyncConfig {
    fn default() -> Self {
        Self {
            endpoint: Url::parse(
                "https://rail-squid.squids.live/squid-railgun-ethereum-v2/graphql",
            )
            .expect("valid quick sync endpoint"),
            start_block: 0,
            end_block: None,
            page_size: DEFAULT_PAGE_SIZE,
            http_client: None,
        }
    }
}

#[derive(Debug)]
pub struct QuickSyncResult {
    pub forest: MerkleForest,
    pub progress: SyncProgress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuickSyncPageProgress {
    pub start_block: u64,
    pub latest_block: u64,
    pub target_block: Option<u64>,
    pub commitments: usize,
}

pub async fn run_quick_sync(config: QuickSyncConfig) -> SyncResult<QuickSyncResult> {
    let mut forest = MerkleForest::new();
    let progress = run_quick_sync_into(&mut forest, config).await?;

    Ok(QuickSyncResult { forest, progress })
}

pub async fn run_quick_sync_into(
    forest: &mut MerkleForest,
    config: QuickSyncConfig,
) -> SyncResult<SyncProgress> {
    run_quick_sync_into_with_progress(forest, config, |_| {}).await
}

pub async fn run_quick_sync_into_with_progress<F>(
    forest: &mut MerkleForest,
    config: QuickSyncConfig,
    mut on_progress: F,
) -> SyncResult<SyncProgress>
where
    F: FnMut(QuickSyncPageProgress),
{
    let QuickSyncConfig {
        endpoint,
        start_block,
        end_block,
        page_size,
        http_client,
    } = config;
    let page_size_value = page_size.get();
    let client = match http_client {
        Some(c) => QuickSyncClient::with_http_client(endpoint, c),
        None => QuickSyncClient::new(endpoint),
    };

    let mut total_commitments = 0usize;
    let mut latest_block = start_block;
    let mut latest_commitment_block = start_block;
    let max_commitments = 16 * TREE_LEAF_COUNT as usize;
    let mut commitment_ids = HashSet::new();

    let mut commitment_cursor = start_block;
    loop {
        let commitments = client
            .fetch_list::<graphql::CommitmentsData>(
                graphql::COMMITMENTS_QUERY,
                commitment_cursor,
                page_size,
            )
            .await?;
        let commitment_count = commitments.len();
        if commitment_count == 0 {
            break;
        }

        let mut max_block_seen = commitment_cursor;
        for commitment in &commitments {
            let block_number: u64 = commitment.block_number.to();
            max_block_seen = max_block_seen.max(block_number);
        }
        let page_is_full = commitment_count >= page_size_value;
        let process_through_block = if page_is_full {
            if max_block_seen == commitment_cursor {
                return Err(SyncError::UnexpectedFormat(format!(
                    "commitment quick-sync page did not advance past block {commitment_cursor}; page size {page_size_value} may split one block"
                )));
            }
            max_block_seen.saturating_sub(1)
        } else {
            end_block.unwrap_or(u64::MAX)
        };
        let process_through_block = end_block.map_or(process_through_block, |end_block| {
            process_through_block.min(end_block)
        });
        let mut max_processed_block = None;
        let mut batch_map: BTreeMap<(u32, u64), Vec<Commitment>> = BTreeMap::new();
        for commitment in commitments {
            let block_number: u64 = commitment.block_number.to();
            if block_number > process_through_block {
                continue;
            }
            max_processed_block = Some(
                max_processed_block
                    .unwrap_or(block_number)
                    .max(block_number),
            );
            if !commitment_ids.insert(commitment.id) {
                continue;
            }
            let tree_number: u32 = commitment.tree_number.to();
            let batch_start_tree_position: u64 = commitment.batch_start_tree_position.to();
            let key = (tree_number, batch_start_tree_position);
            batch_map.entry(key).or_default().push(commitment);
        }

        for ((_tree_number, _start_position), batch) in batch_map {
            for commitment in batch {
                let tree_number: u32 = commitment.tree_number.to();
                let tree_position: u64 = commitment.tree_position.to();
                let (tree_number, tree_position) =
                    normalize_tree_position(tree_number, tree_position);
                let leaf = MerkleTreeUpdate {
                    tree_number,
                    tree_position,
                    hash: commitment.hash,
                };
                forest.insert_leaf(leaf)?;
                total_commitments += 1;
            }
        }

        if let Some(block) = max_processed_block {
            latest_commitment_block = latest_commitment_block.max(block);
            latest_block = latest_block.max(block);
        }
        info!(
            target: "quick-sync",
            "commitments page: count={}, latest_block={}",
            total_commitments,
            latest_block
        );
        on_progress(QuickSyncPageProgress {
            start_block,
            latest_block,
            target_block: end_block,
            commitments: total_commitments,
        });

        if !page_is_full {
            break;
        }
        if let Some(end_block) = end_block
            && max_block_seen > end_block
        {
            break;
        }
        if total_commitments >= max_commitments {
            break;
        }
        commitment_cursor = max_block_seen;
    }

    forest.compute_roots();
    if let Some(target_block) = end_block {
        latest_block = latest_block.max(target_block);
        latest_commitment_block = latest_commitment_block.max(target_block);
    }

    Ok(SyncProgress {
        latest_block,
        latest_commitment_block,
        commitments: total_commitments,
        nullifiers: 0,
        unshields: 0,
    })
}

#[cfg(test)]
mod tests;
