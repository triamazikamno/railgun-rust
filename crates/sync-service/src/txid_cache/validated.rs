//! The cache's validated-progress markers: reconciling them with the latest
//! validated TXID, and checking that local rows support a latest marker.

use super::{
    DbStore, DenseMerkleTree, ErrorKind, FixedBytes, TREE_LEAF_COUNT, TxidPublicCacheError,
    TxidPublicCacheManifest, TxidPublicCacheRow, TxidPublicCheckpointSource,
    TxidPublicLatestValidated, read_tree_leaves,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TxidPublicLocalLatestStatus {
    Satisfied,
    NeedsRows,
    NeedsValidatedRefresh,
}

impl TxidPublicCacheManifest {
    fn clear_all_validated_markers(&mut self) {
        self.validated_cached_txid_index = None;
        self.latest_validated_txid_index = None;
        self.latest_validated_merkleroot = None;
        self.artifact_cached_txid_index = None;
        self.checkpoints.clear();
    }

    pub(super) fn clear_validated_markers_for_latest(
        &mut self,
        latest: TxidPublicLatestValidated,
    ) -> bool {
        let before = (
            self.validated_cached_txid_index,
            self.latest_validated_txid_index,
            self.latest_validated_merkleroot,
            self.artifact_cached_txid_index,
        );
        if let Some(artifact_bound) = self.artifact_cached_txid_index {
            if artifact_bound == latest.txid_index {
                self.clear_all_validated_markers();
            } else {
                self.latest_validated_txid_index = None;
                self.latest_validated_merkleroot = None;
                self.validated_cached_txid_index = Some(artifact_bound.min(latest.txid_index));
            }
        } else {
            self.clear_all_validated_markers();
        }
        let changed = before
            != (
                self.validated_cached_txid_index,
                self.latest_validated_txid_index,
                self.latest_validated_merkleroot,
                self.artifact_cached_txid_index,
            );
        if changed {
            self.checkpoints.clear();
        }
        changed
    }

    pub(super) fn commit_latest_validated_if_supported(
        &mut self,
        db: &DbStore,
        latest: TxidPublicLatestValidated,
    ) -> Result<TxidPublicLocalLatestStatus, TxidPublicCacheError> {
        let status = self.local_latest_status(db, latest)?;
        if status == TxidPublicLocalLatestStatus::Satisfied {
            self.set_latest_validated(latest);
            if let Some(merkleroot) = latest.merkleroot {
                self.insert_checkpoint(
                    latest.txid_index,
                    merkleroot,
                    TxidPublicCheckpointSource::LatestValidated,
                )?;
            }
            if self
                .validated_cached_txid_index
                .is_none_or(|index| index < latest.txid_index)
            {
                self.validated_cached_txid_index = Some(latest.txid_index);
            }
        }
        Ok(status)
    }

    pub(super) const fn set_latest_validated(&mut self, latest: TxidPublicLatestValidated) {
        self.latest_validated_txid_index = Some(latest.txid_index);
        self.latest_validated_merkleroot = latest.merkleroot;
    }

    pub(super) fn unsupported_latest_error(
        &self,
        latest: TxidPublicLatestValidated,
        status: TxidPublicLocalLatestStatus,
        force_validated_refresh: bool,
    ) -> TxidPublicCacheError {
        match status {
            TxidPublicLocalLatestStatus::Satisfied => TxidPublicCacheError::MetadataMismatch(
                "supported latest marker unexpectedly rejected".to_string(),
            ),
            TxidPublicLocalLatestStatus::NeedsRows if !force_validated_refresh => {
                TxidPublicCacheError::CacheNotReady {
                    next_index: self
                        .validated_cached_txid_index
                        .map_or(0, |index| index.saturating_add(1)),
                    required_index: latest.txid_index,
                }
            }
            TxidPublicLocalLatestStatus::NeedsRows
            | TxidPublicLocalLatestStatus::NeedsValidatedRefresh => {
                TxidPublicCacheError::RootMismatch
            }
        }
    }

    pub(super) fn latest_validated_matches(&self, latest: TxidPublicLatestValidated) -> bool {
        self.latest_validated_txid_index == Some(latest.txid_index)
            && self.latest_validated_merkleroot == latest.merkleroot
    }

    pub(super) fn latest_checkpoint_matches(&self, latest: TxidPublicLatestValidated) -> bool {
        latest.merkleroot.is_none_or(|merkleroot| {
            self.checkpoints
                .get(&latest.txid_index)
                .is_some_and(|checkpoint| checkpoint.merkleroot == merkleroot)
        })
    }

    pub(super) fn artifact_covers_latest(&self, latest: TxidPublicLatestValidated) -> bool {
        self.artifact_cached_txid_index
            .is_some_and(|index| index >= latest.txid_index)
    }

    pub(super) fn reconcile_validated_progress_for_latest(
        &mut self,
        latest: TxidPublicLatestValidated,
    ) -> bool {
        let rollback_required = self
            .latest_validated_txid_index
            .is_some_and(|index| index > latest.txid_index)
            || self
                .validated_cached_txid_index
                .is_some_and(|index| index > latest.txid_index)
            || self.latest_root_conflicts(latest);
        if rollback_required {
            self.checkpoints.clear();
            if self.latest_root_conflicts(latest) {
                if let Some(artifact_bound) = self
                    .artifact_cached_txid_index
                    .filter(|bound| *bound < latest.txid_index)
                {
                    self.latest_validated_txid_index = None;
                    self.latest_validated_merkleroot = None;
                    self.validated_cached_txid_index = Some(artifact_bound);
                } else {
                    self.clear_all_validated_markers();
                }
                return true;
            }
            self.validated_cached_txid_index = self
                .validated_cached_txid_index
                .map(|index| index.min(latest.txid_index));
            return true;
        }
        false
    }

    /// The latest marker is at `latest`'s index but records a different root
    /// from the one `latest` supplies.
    fn latest_root_conflicts(&self, latest: TxidPublicLatestValidated) -> bool {
        self.latest_validated_txid_index == Some(latest.txid_index)
            && self.latest_validated_merkleroot != latest.merkleroot
            && latest.merkleroot.is_some()
    }

    pub(super) fn local_latest_status(
        &self,
        db: &DbStore,
        latest: TxidPublicLatestValidated,
    ) -> Result<TxidPublicLocalLatestStatus, TxidPublicCacheError> {
        if self
            .validated_cached_txid_index
            .is_none_or(|index| index < latest.txid_index)
        {
            return Ok(TxidPublicLocalLatestStatus::NeedsRows);
        }
        match self.validate_contiguous_rows_through(db, latest.txid_index) {
            Ok(()) => {}
            Err(
                TxidPublicCacheError::MissingLeaf { .. }
                | TxidPublicCacheError::MetadataMismatch(_)
                | TxidPublicCacheError::Decode(_),
            ) => {
                return Ok(TxidPublicLocalLatestStatus::NeedsValidatedRefresh);
            }
            Err(TxidPublicCacheError::Io(err)) if err.kind() == ErrorKind::NotFound => {
                return Ok(TxidPublicLocalLatestStatus::NeedsValidatedRefresh);
            }
            Err(err) => return Err(err),
        }
        let Some(expected_root) = latest.merkleroot else {
            return Ok(TxidPublicLocalLatestStatus::Satisfied);
        };
        let tree = latest.txid_index / TREE_LEAF_COUNT;
        let leaf_count = latest.txid_index % TREE_LEAF_COUNT + 1;
        let leaves = match read_tree_leaves(self, db, tree, leaf_count) {
            Ok(leaves) => leaves,
            Err(TxidPublicCacheError::MissingLeaf { .. }) => {
                return Ok(TxidPublicLocalLatestStatus::NeedsValidatedRefresh);
            }
            Err(err) => return Err(err),
        };
        let actual_root = DenseMerkleTree::from_ordered_leaves(leaves, leaf_count).root();
        if FixedBytes::from(actual_root.to_be_bytes::<32>()) == expected_root {
            Ok(TxidPublicLocalLatestStatus::Satisfied)
        } else {
            Ok(TxidPublicLocalLatestStatus::NeedsValidatedRefresh)
        }
    }

    fn validate_contiguous_rows_through(
        &self,
        db: &DbStore,
        txid_index: u64,
    ) -> Result<(), TxidPublicCacheError> {
        let mut expected_index = 0_u64;
        for page_ref in &self.pages {
            if expected_index > txid_index {
                return Ok(());
            }
            let page_ref_end = page_ref.start_index.saturating_add(page_ref.row_count);
            if page_ref_end <= expected_index {
                continue;
            }
            if page_ref.start_index > expected_index {
                return Err(TxidPublicCacheError::MissingLeaf {
                    index: expected_index,
                });
            }
            let page = page_ref.read(db, self.cache_key())?;
            if page.rows.len() as u64 != page_ref.row_count {
                return Err(TxidPublicCacheError::MetadataMismatch(
                    "page row count mismatch".to_string(),
                ));
            }
            match scan_contiguous_rows(page.rows, expected_index, txid_index)? {
                RowScan::ReachedTarget => return Ok(()),
                RowScan::Exhausted(next_index) => expected_index = next_index,
            }
        }
        Err(TxidPublicCacheError::MissingLeaf {
            index: expected_index,
        })
    }

    pub(super) fn artifact_fetch_start_index(
        &self,
        latest: TxidPublicLatestValidated,
        local_status: TxidPublicLocalLatestStatus,
    ) -> u64 {
        if self.checkpoints.is_empty() && self.artifact_cached_txid_index.is_some() {
            return 0;
        }
        if local_status == TxidPublicLocalLatestStatus::NeedsValidatedRefresh {
            return 0;
        }
        let validated_tip_conflicts = self
            .latest_validated_txid_index
            .is_some_and(|index| index > latest.txid_index)
            || (self.latest_validated_txid_index == Some(latest.txid_index)
                && self.latest_validated_merkleroot != latest.merkleroot);
        if validated_tip_conflicts {
            return 0;
        }
        self.artifact_cached_txid_index
            .map_or(0, |index| index.saturating_add(1))
    }
}

/// Where one page left the contiguity scan.
enum RowScan {
    /// A row at the target index was reached.
    ReachedTarget,
    /// The page ran out; the scan continues at this index.
    Exhausted(u64),
}

/// Checks that `rows` continue contiguously from `expected_index` towards
/// `target`, skipping rows an earlier page already covered.
fn scan_contiguous_rows(
    rows: Vec<TxidPublicCacheRow>,
    mut expected_index: u64,
    target: u64,
) -> Result<RowScan, TxidPublicCacheError> {
    for row in rows {
        if row.txid_index < expected_index {
            continue;
        }
        if row.txid_index != expected_index {
            return Err(TxidPublicCacheError::MissingLeaf {
                index: expected_index,
            });
        }
        if row.txid_index == target {
            return Ok(RowScan::ReachedTarget);
        }
        expected_index = expected_index.checked_add(1).ok_or_else(|| {
            TxidPublicCacheError::MetadataMismatch("txid index overflow".to_string())
        })?;
    }
    Ok(RowScan::Exhausted(expected_index))
}
