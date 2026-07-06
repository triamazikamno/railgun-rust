use super::*;

use crate::poi_artifacts::clear_poi_artifact_cache_for_reset;
use crate::txid_cache::reset_txid_public_cache;

const PUBLIC_DATA_PLANE_DIAGNOSTIC_LIMIT: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicScanRange {
    pub from_block: u64,
    pub to_block: u64,
}

impl PublicScanRange {
    #[must_use]
    pub const fn new(from_block: u64, to_block: u64) -> Self {
        Self {
            from_block,
            to_block,
        }
    }

    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.from_block <= self.to_block
    }

    #[must_use]
    pub const fn intersects_from(self, from_block: u64) -> bool {
        self.to_block >= from_block
    }

    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        self.from_block <= other.to_block && other.from_block <= self.to_block
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PublicScanCoverageWrite {
    pub range: PublicScanRange,
    pub source: PublicScanSource,
    pub row_count: usize,
    pub read_scope: PublicScanReadScope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicCoverageAnswer {
    ReplayableEmpty {
        range: PublicScanRange,
        source: PublicScanSource,
        epoch: PublicDataPlaneEpoch,
    },
    CoveredWithRows {
        range: PublicScanRange,
        source: PublicScanSource,
        epoch: PublicDataPlaneEpoch,
    },
    Missing {
        range: PublicScanRange,
        epoch: PublicDataPlaneEpoch,
    },
}

#[derive(Debug, Clone)]
pub struct PublicScanRows {
    pub range: PublicScanRange,
    pub source: PublicScanSource,
    pub to_block_hash: Option<[u8; 32]>,
    pub rows: WalletScanInputRows,
    pub epoch: PublicDataPlaneEpoch,
}

#[derive(Clone)]
pub struct PublicDataPlaneHandle {
    service: Arc<ChainService>,
}

impl PublicDataPlaneHandle {
    #[must_use]
    pub(crate) fn new(service: Arc<ChainService>) -> Self {
        Self { service }
    }

    pub async fn public_scan_rows(
        &self,
        range: PublicScanRange,
    ) -> Result<PublicScanRowsAnswer, ChainError> {
        self.service.public_scan_rows(range).await
    }

    pub async fn public_scan_coverage(
        &self,
        range: PublicScanRange,
    ) -> Result<PublicCoverageAnswer, ChainError> {
        self.service.public_scan_coverage(range).await
    }

    pub async fn diagnostics(&self) -> PublicDataPlaneDiagnostics {
        self.service.public_data_plane.diagnostics().await
    }

    pub async fn reset_public_cache(&self) -> Result<PublicSyncCacheReset, PublicDataPlaneError> {
        self.service.public_data_plane.reset_public_cache().await
    }
}

impl PublicScanRows {
    #[must_use]
    pub fn row_count(&self) -> usize {
        self.rows.row_count()
    }
}

#[derive(Debug, Clone)]
pub enum PublicScanRowsAnswer {
    Rows(PublicScanRows),
    CompleteCoverage {
        range: PublicScanRange,
        source: PublicScanSource,
        row_count: usize,
        epoch: PublicDataPlaneEpoch,
    },
    Missing {
        range: PublicScanRange,
        epoch: PublicDataPlaneEpoch,
    },
}

impl PublicScanRowsAnswer {
    pub(crate) fn from_wallet_scan_apply(apply: WalletScanApply) -> Self {
        let WalletScanApply {
            from_block,
            to_block,
            rows,
            read_scope,
        } = apply;
        let WalletScanRows {
            source,
            to_block_hash,
            payload,
            ..
        } = rows;
        let range = PublicScanRange::new(from_block, to_block);
        let epoch = read_scope.epoch();
        match payload {
            WalletScanRowsPayload::Rows(rows) => Self::Rows(PublicScanRows {
                range,
                source,
                to_block_hash,
                rows: *rows,
                epoch,
            }),
            WalletScanRowsPayload::EmptyCoverage => Self::CompleteCoverage {
                range,
                source,
                row_count: 0,
                epoch,
            },
            #[cfg(test)]
            WalletScanRowsPayload::IndexedDeltaForTest { .. } => Self::CompleteCoverage {
                range,
                source,
                row_count: 0,
                epoch,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicDataPlaneDiagnosticKind {
    SourceSelected,
    SourceFallback,
    CoverageRecorded,
    CoverageRejected,
    CoverageInvalidated,
    PublicCacheReset,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicDataPlaneDiagnostic {
    pub kind: PublicDataPlaneDiagnosticKind,
    pub source: Option<PublicScanSource>,
    pub range: Option<PublicScanRange>,
    pub reason: String,
    pub epoch: PublicDataPlaneEpoch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicDataPlaneDiagnostics {
    pub epoch: PublicDataPlaneEpoch,
    pub events: Vec<PublicDataPlaneDiagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicSyncCacheReset {
    pub previous_epoch: PublicDataPlaneEpoch,
    pub new_epoch: PublicDataPlaneEpoch,
    pub coverage_entries_removed: usize,
    pub diagnostics_removed: usize,
    pub txid_blob_entries_removed: u64,
    pub txid_files_removed: u64,
    pub poi_cache_entries_removed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PublicDataPlaneError {
    #[error("invalid public scan range {from_block}..={to_block}")]
    InvalidRange { from_block: u64, to_block: u64 },
    #[error("stale public data-plane epoch: expected {expected}, actual {actual}")]
    StaleEpoch { expected: u64, actual: u64 },
    #[error("public cache reset failed: {reason}")]
    PublicCacheReset { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PublicScanCoverageRecord {
    range: PublicScanRange,
    source: PublicScanSource,
    row_count: usize,
    epoch: PublicDataPlaneEpoch,
}

#[derive(Debug, Default)]
struct PublicCoverageStore {
    records: Vec<PublicScanCoverageRecord>,
}

impl PublicCoverageStore {
    fn len(&self) -> usize {
        self.records.len()
    }

    fn clear(&mut self) {
        self.records.clear();
    }

    fn retain_epoch(&mut self, epoch: PublicDataPlaneEpoch) {
        self.records.retain(|record| record.epoch == epoch);
    }

    fn insert_canonical(&mut self, record: PublicScanCoverageRecord) {
        self.retain_epoch(record.epoch);
        let mut records = Vec::with_capacity(self.records.len() + 2);
        for existing in self.records.drain(..) {
            if !existing.range.intersects(record.range) {
                records.push(existing);
                continue;
            }

            if existing.range.from_block < record.range.from_block {
                let mut left = existing.clone();
                left.range.to_block = record.range.from_block.saturating_sub(1);
                if left.range.is_valid() {
                    records.push(left);
                }
            }
            if existing.range.to_block > record.range.to_block {
                let mut right = existing;
                right.range.from_block = record.range.to_block.saturating_add(1);
                if right.range.is_valid() {
                    records.push(right);
                }
            }
        }
        records.push(record);
        records.sort_by_key(|coverage| (coverage.range.from_block, coverage.range.to_block));
        self.records = records;
    }

    fn invalidate_from(&mut self, from_block: u64) -> usize {
        let mut records = Vec::with_capacity(self.records.len());
        let mut affected = 0;
        for mut record in self.records.drain(..) {
            if !record.range.intersects_from(from_block) {
                records.push(record);
                continue;
            }

            affected += 1;
            if record.range.from_block < from_block {
                record.range.to_block = from_block.saturating_sub(1);
                if record.range.is_valid() {
                    records.push(record);
                }
            }
        }
        self.records = records;
        affected
    }

    fn restamp_epoch(&mut self, epoch: PublicDataPlaneEpoch) {
        for record in &mut self.records {
            record.epoch = epoch;
        }
    }

    fn coverage_for_range(
        &self,
        range: PublicScanRange,
        epoch: PublicDataPlaneEpoch,
    ) -> Option<CoverageForRange> {
        if !range.is_valid() {
            return None;
        }
        let mut next_block = range.from_block;
        let mut covered_to = None;
        let mut source = None;
        let mut has_rows = false;
        for record in &self.records {
            if record.epoch != epoch || record.range.to_block < next_block {
                continue;
            }
            if record.range.from_block > next_block {
                break;
            }
            let record_to = record.range.to_block.min(range.to_block);
            if record_to < next_block {
                continue;
            }
            covered_to = Some(record_to);
            source.get_or_insert(record.source);
            has_rows |= record.row_count > 0;
            if record_to >= range.to_block {
                break;
            }
            next_block = record_to.saturating_add(1);
        }
        covered_to.map(|covered_to| CoverageForRange {
            covered_to,
            source: source.unwrap_or(PublicScanSource::CachedCoverage),
            has_rows,
        })
    }

    fn empty_coverage_prefix_for_range(
        &self,
        range: PublicScanRange,
        epoch: PublicDataPlaneEpoch,
    ) -> Option<u64> {
        if !range.is_valid() {
            return None;
        }
        let mut next_block = range.from_block;
        let mut covered_to = None;
        for record in &self.records {
            if record.epoch != epoch || record.range.to_block < next_block {
                continue;
            }
            if record.range.from_block > next_block || record.row_count != 0 {
                break;
            }
            let record_to = record.range.to_block.min(range.to_block);
            if record_to < next_block {
                continue;
            }
            covered_to = Some(record_to);
            if record_to >= range.to_block {
                break;
            }
            next_block = record_to.saturating_add(1);
        }
        covered_to
    }

    #[cfg(test)]
    fn records(&self) -> &[PublicScanCoverageRecord] {
        &self.records
    }
}

#[derive(Debug, Default)]
struct ChainPublicDataPlaneState {
    coverage: PublicCoverageStore,
    diagnostics: Vec<PublicDataPlaneDiagnostic>,
}

impl ChainPublicDataPlaneState {
    fn insert_canonical_coverage(&mut self, record: PublicScanCoverageRecord) {
        self.coverage.insert_canonical(record);
    }

    fn coverage_for_range(
        &self,
        range: PublicScanRange,
        epoch: PublicDataPlaneEpoch,
    ) -> Option<CoverageForRange> {
        self.coverage.coverage_for_range(range, epoch)
    }

    fn empty_coverage_prefix_for_range(
        &self,
        range: PublicScanRange,
        epoch: PublicDataPlaneEpoch,
    ) -> Option<u64> {
        self.coverage.empty_coverage_prefix_for_range(range, epoch)
    }

    fn push_diagnostic(&mut self, diagnostic: PublicDataPlaneDiagnostic) {
        self.diagnostics.push(diagnostic);
        let overflow = self
            .diagnostics
            .len()
            .saturating_sub(PUBLIC_DATA_PLANE_DIAGNOSTIC_LIMIT);
        if overflow > 0 {
            self.diagnostics.drain(0..overflow);
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ChainPublicDataPlane {
    db: Arc<DbStore>,
    epoch: Arc<AtomicU64>,
    state: Arc<Mutex<ChainPublicDataPlaneState>>,
    commit_fence: Arc<Mutex<()>>,
}

impl ChainPublicDataPlane {
    #[must_use]
    pub(crate) fn new(db: Arc<DbStore>, epoch: Arc<AtomicU64>) -> Self {
        Self {
            db,
            epoch,
            state: Arc::new(Mutex::new(ChainPublicDataPlaneState::default())),
            commit_fence: Arc::new(Mutex::new(())),
        }
    }

    #[must_use]
    pub(crate) fn current_epoch(&self) -> PublicDataPlaneEpoch {
        PublicDataPlaneEpoch::new(self.epoch.load(Ordering::Acquire))
    }

    #[must_use]
    pub(crate) fn begin_public_scan_read(&self) -> PublicScanReadScope {
        PublicScanReadScope::new(self.current_epoch())
    }

    pub(crate) async fn cached_public_scan_coverage(
        &self,
        range: PublicScanRange,
    ) -> PublicCoverageAnswer {
        let state = self.state.lock().await;
        let epoch = self.current_epoch();
        state.coverage_for_range(range, epoch).map_or(
            PublicCoverageAnswer::Missing { range, epoch },
            |coverage| {
                let range = PublicScanRange::new(range.from_block, coverage.covered_to);
                if coverage.has_rows {
                    PublicCoverageAnswer::CoveredWithRows {
                        range,
                        source: coverage.source,
                        epoch,
                    }
                } else {
                    PublicCoverageAnswer::ReplayableEmpty {
                        range,
                        source: coverage.source,
                        epoch,
                    }
                }
            },
        )
    }

    pub(crate) async fn diagnostics(&self) -> PublicDataPlaneDiagnostics {
        let state = self.state.lock().await;
        PublicDataPlaneDiagnostics {
            epoch: self.current_epoch(),
            events: state.diagnostics.clone(),
        }
    }

    pub(crate) async fn reset_public_cache(
        &self,
    ) -> Result<PublicSyncCacheReset, PublicDataPlaneError> {
        let _commit_guard = self.commit_fence.lock().await;
        let (previous_epoch, new_epoch, coverage_entries_removed, diagnostics_removed) = {
            let mut state = self.state.lock().await;
            let previous_epoch = self.current_epoch();
            let coverage_entries_removed = state.coverage.len();
            let diagnostics_removed = state.diagnostics.len();
            state.coverage.clear();
            state.diagnostics.clear();
            let new_epoch = self.bump_epoch_locked(previous_epoch);
            state.push_diagnostic(PublicDataPlaneDiagnostic {
                kind: PublicDataPlaneDiagnosticKind::PublicCacheReset,
                source: None,
                range: None,
                reason: "public sync cache reset".to_string(),
                epoch: new_epoch,
            });
            (
                previous_epoch,
                new_epoch,
                coverage_entries_removed,
                diagnostics_removed,
            )
        };

        let txid_reset = reset_txid_public_cache(self.db.as_ref())
            .await
            .map_err(|err| PublicDataPlaneError::PublicCacheReset {
                reason: err.to_string(),
            })?;
        let poi_cache_entries_removed =
            clear_poi_artifact_cache_for_reset(&self.db).map_err(|err| {
                PublicDataPlaneError::PublicCacheReset {
                    reason: err.to_string(),
                }
            })?;
        Ok(PublicSyncCacheReset {
            previous_epoch,
            new_epoch,
            coverage_entries_removed,
            diagnostics_removed,
            txid_blob_entries_removed: txid_reset.blob_entries_removed,
            txid_files_removed: txid_reset.files_removed,
            poi_cache_entries_removed,
        })
    }

    pub(crate) async fn record_public_scan_coverage(
        &self,
        write: PublicScanCoverageWrite,
    ) -> Result<PublicDataPlaneEpoch, PublicDataPlaneError> {
        if !write.range.is_valid() {
            return Err(PublicDataPlaneError::InvalidRange {
                from_block: write.range.from_block,
                to_block: write.range.to_block,
            });
        }
        let mut state = self.state.lock().await;
        let current_epoch = self.current_epoch();
        let captured_epoch = write.read_scope.epoch();
        if current_epoch != captured_epoch {
            state.push_diagnostic(PublicDataPlaneDiagnostic {
                kind: PublicDataPlaneDiagnosticKind::CoverageRejected,
                source: Some(write.source),
                range: Some(write.range),
                reason: "stale coverage epoch".to_string(),
                epoch: current_epoch,
            });
            return Err(PublicDataPlaneError::StaleEpoch {
                expected: current_epoch.value,
                actual: captured_epoch.value,
            });
        }

        state.insert_canonical_coverage(PublicScanCoverageRecord {
            range: write.range,
            source: write.source,
            row_count: write.row_count,
            epoch: current_epoch,
        });
        state.push_diagnostic(PublicDataPlaneDiagnostic {
            kind: PublicDataPlaneDiagnosticKind::CoverageRecorded,
            source: Some(write.source),
            range: Some(write.range),
            reason: format!("recorded {} public rows", write.row_count),
            epoch: current_epoch,
        });
        Ok(current_epoch)
    }

    pub(crate) async fn record_source_decision(
        &self,
        kind: PublicDataPlaneDiagnosticKind,
        source: PublicScanSource,
        range: PublicScanRange,
        read_scope: PublicScanReadScope,
        reason: impl Into<String>,
    ) {
        let mut state = self.state.lock().await;
        state.push_diagnostic(PublicDataPlaneDiagnostic {
            kind,
            source: Some(source),
            range: Some(range),
            reason: reason.into(),
            epoch: read_scope.epoch(),
        });
    }

    #[cfg(test)]
    pub(crate) async fn validate_public_scan_read(
        &self,
        range: PublicScanRange,
        source: PublicScanSource,
        read_scope: PublicScanReadScope,
    ) -> Result<(), PublicDataPlaneError> {
        if !range.is_valid() {
            return Err(PublicDataPlaneError::InvalidRange {
                from_block: range.from_block,
                to_block: range.to_block,
            });
        }
        let mut state = self.state.lock().await;
        let current_epoch = self.current_epoch();
        Self::validate_public_scan_read_locked(&mut state, current_epoch, range, source, read_scope)
    }

    pub(crate) async fn with_valid_public_scan_read<T>(
        &self,
        range: PublicScanRange,
        source: PublicScanSource,
        read_scope: PublicScanReadScope,
        commit: impl FnOnce() -> T,
    ) -> Result<T, PublicDataPlaneError> {
        if !range.is_valid() {
            return Err(PublicDataPlaneError::InvalidRange {
                from_block: range.from_block,
                to_block: range.to_block,
            });
        }
        let _commit_guard = self.commit_fence.lock().await;
        {
            let mut state = self.state.lock().await;
            let current_epoch = self.current_epoch();
            Self::validate_public_scan_read_locked(
                &mut state,
                current_epoch,
                range,
                source,
                read_scope,
            )?;
        }
        Ok(commit())
    }

    pub(crate) async fn invalidate_public_scan_coverage_from(
        &self,
        from_block: u64,
    ) -> PublicDataPlaneEpoch {
        let _commit_guard = self.commit_fence.lock().await;
        let mut state = self.state.lock().await;
        let previous_epoch = self.current_epoch();
        let affected = state.coverage.invalidate_from(from_block);
        let new_epoch = self.bump_epoch_locked(previous_epoch);
        state.coverage.restamp_epoch(new_epoch);
        state.push_diagnostic(PublicDataPlaneDiagnostic {
            kind: PublicDataPlaneDiagnosticKind::CoverageInvalidated,
            source: None,
            range: Some(PublicScanRange::new(from_block, u64::MAX)),
            reason: format!("invalidated {affected} public coverage records"),
            epoch: new_epoch,
        });
        new_epoch
    }

    pub(crate) async fn cached_empty_wallet_scan_apply(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Option<WalletScanApply> {
        if from_block > to_block {
            return None;
        }
        let state = self.state.lock().await;
        let epoch = self.current_epoch();
        let read_scope = PublicScanReadScope::new(epoch);
        let range = PublicScanRange::new(from_block, to_block);
        let covered_to = state.empty_coverage_prefix_for_range(range, epoch)?;
        Some(WalletScanApply::empty_coverage(
            from_block,
            covered_to,
            read_scope,
            PublicScanSource::CachedCoverage,
        ))
    }

    fn bump_epoch_locked(&self, previous_epoch: PublicDataPlaneEpoch) -> PublicDataPlaneEpoch {
        let new_epoch = PublicDataPlaneEpoch::new(previous_epoch.value.saturating_add(1));
        self.epoch.store(new_epoch.value, Ordering::Release);
        new_epoch
    }

    fn validate_public_scan_read_locked(
        state: &mut ChainPublicDataPlaneState,
        current_epoch: PublicDataPlaneEpoch,
        range: PublicScanRange,
        source: PublicScanSource,
        read_scope: PublicScanReadScope,
    ) -> Result<(), PublicDataPlaneError> {
        let captured_epoch = read_scope.epoch();
        if current_epoch == captured_epoch {
            return Ok(());
        }
        state.push_diagnostic(PublicDataPlaneDiagnostic {
            kind: PublicDataPlaneDiagnosticKind::CoverageRejected,
            source: Some(source),
            range: Some(range),
            reason: "stale scan apply epoch".to_string(),
            epoch: current_epoch,
        });
        Err(PublicDataPlaneError::StaleEpoch {
            expected: current_epoch.value,
            actual: captured_epoch.value,
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct CoverageForRange {
    covered_to: u64,
    source: PublicScanSource,
    has_rows: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::path::PathBuf;
    use std::sync::mpsc as std_mpsc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use local_db::{BlobMeta, DbConfig, PoiArtifactCacheRecord, PoiArtifactDescriptorRecord};
    use sha2::{Digest, Sha256};

    #[tokio::test]
    async fn public_scan_coverage_rejects_stale_epoch_write() {
        let (_db, data_plane, root_dir) = test_data_plane("stale-coverage-write");
        data_plane.invalidate_public_scan_coverage_from(100).await;

        let error = data_plane
            .record_public_scan_coverage(PublicScanCoverageWrite {
                range: PublicScanRange::new(100, 110),
                source: PublicScanSource::Rpc,
                row_count: 0,
                read_scope: PublicScanReadScope::new(PublicDataPlaneEpoch::new(0)),
            })
            .await
            .expect_err("stale coverage must be rejected");

        assert_eq!(
            error,
            PublicDataPlaneError::StaleEpoch {
                expected: 1,
                actual: 0,
            }
        );
        assert!(matches!(
            data_plane
                .cached_public_scan_coverage(PublicScanRange::new(100, 110))
                .await,
            PublicCoverageAnswer::Missing { .. }
        ));
        drop(data_plane);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn cached_empty_wallet_scan_apply_reuses_only_empty_cached_coverage() {
        let (_db, data_plane, root_dir) = test_data_plane("cached-empty-coverage");
        data_plane
            .record_public_scan_coverage(PublicScanCoverageWrite {
                range: PublicScanRange::new(100, 110),
                source: PublicScanSource::IndexedArtifacts,
                row_count: 0,
                read_scope: data_plane.begin_public_scan_read(),
            })
            .await
            .expect("record empty coverage");
        data_plane
            .record_public_scan_coverage(PublicScanCoverageWrite {
                range: PublicScanRange::new(111, 120),
                source: PublicScanSource::Squid,
                row_count: 1,
                read_scope: data_plane.begin_public_scan_read(),
            })
            .await
            .expect("record non-empty coverage");

        let apply = data_plane
            .cached_empty_wallet_scan_apply(100, 120)
            .await
            .expect("empty prefix coverage is reusable");
        assert_eq!(apply.from_block, 100);
        assert_eq!(apply.to_block, 110);
        assert_eq!(apply.rows.source, PublicScanSource::CachedCoverage);
        assert!(
            data_plane
                .cached_empty_wallet_scan_apply(111, 120)
                .await
                .is_none(),
            "coverage with rows cannot be replayed without row data"
        );
        drop(data_plane);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn duplicate_public_coverage_writes_replace_canonical_coverage() {
        let (_db, data_plane, root_dir) = test_data_plane("duplicate-coverage-row-count");
        let range = PublicScanRange::new(100, 110);
        for _ in 0..2 {
            data_plane
                .record_public_scan_coverage(PublicScanCoverageWrite {
                    range,
                    source: PublicScanSource::Rpc,
                    row_count: 3,
                    read_scope: data_plane.begin_public_scan_read(),
                })
                .await
                .expect("record duplicate coverage");
        }

        let answer = data_plane.cached_public_scan_coverage(range).await;

        assert!(matches!(
            answer,
            PublicCoverageAnswer::CoveredWithRows {
                range: PublicScanRange {
                    from_block: 100,
                    to_block: 110
                },
                ..
            }
        ));
        assert_eq!(data_plane.state.lock().await.coverage.len(), 1);
        drop(data_plane);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn overlapping_public_coverage_writes_preserve_replayable_remainders() {
        let (_db, data_plane, root_dir) = test_data_plane("overlapping-coverage-remainders");
        data_plane
            .record_public_scan_coverage(PublicScanCoverageWrite {
                range: PublicScanRange::new(100, 200),
                source: PublicScanSource::Rpc,
                row_count: 0,
                read_scope: data_plane.begin_public_scan_read(),
            })
            .await
            .expect("record wide coverage");
        data_plane
            .record_public_scan_coverage(PublicScanCoverageWrite {
                range: PublicScanRange::new(150, 200),
                source: PublicScanSource::Rpc,
                row_count: 0,
                read_scope: data_plane.begin_public_scan_read(),
            })
            .await
            .expect("record overlapping suffix coverage");

        assert_eq!(data_plane.state.lock().await.coverage.len(), 2);
        assert_eq!(
            data_plane
                .cached_public_scan_coverage(PublicScanRange::new(100, 149))
                .await,
            PublicCoverageAnswer::ReplayableEmpty {
                range: PublicScanRange::new(100, 149),
                source: PublicScanSource::Rpc,
                epoch: PublicDataPlaneEpoch::new(0),
            }
        );
        let apply = data_plane
            .cached_empty_wallet_scan_apply(100, 200)
            .await
            .expect("overlapping empty coverage remains replayable");
        assert_eq!(apply.from_block, 100);
        assert_eq!(apply.to_block, 200);
        assert_eq!(apply.rows.source, PublicScanSource::CachedCoverage);

        drop(data_plane);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn row_bearing_cached_coverage_is_not_replayable_empty() {
        let (_db, data_plane, root_dir) = test_data_plane("partial-coverage-no-row-count");
        data_plane
            .record_public_scan_coverage(PublicScanCoverageWrite {
                range: PublicScanRange::new(100, 120),
                source: PublicScanSource::Rpc,
                row_count: 7,
                read_scope: data_plane.begin_public_scan_read(),
            })
            .await
            .expect("record aggregate coverage");

        let answer = data_plane
            .cached_public_scan_coverage(PublicScanRange::new(100, 110))
            .await;

        assert_eq!(
            answer,
            PublicCoverageAnswer::CoveredWithRows {
                range: PublicScanRange::new(100, 110),
                source: PublicScanSource::Rpc,
                epoch: PublicDataPlaneEpoch::new(0),
            }
        );
        assert_eq!(
            data_plane.state.lock().await.coverage.records()[0].row_count,
            7
        );
        assert!(
            data_plane
                .cached_empty_wallet_scan_apply(100, 110)
                .await
                .is_none(),
            "row-bearing coverage must not be replayed as empty coverage"
        );
        drop(data_plane);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn invalidation_removes_or_restamps_stale_coverage_records() {
        let (_db, data_plane, root_dir) = test_data_plane("coverage-invalidation-stale-cleanup");
        data_plane
            .record_public_scan_coverage(PublicScanCoverageWrite {
                range: PublicScanRange::new(1, 9),
                source: PublicScanSource::Rpc,
                row_count: 0,
                read_scope: data_plane.begin_public_scan_read(),
            })
            .await
            .expect("record retained coverage");
        data_plane
            .record_public_scan_coverage(PublicScanCoverageWrite {
                range: PublicScanRange::new(10, 20),
                source: PublicScanSource::Rpc,
                row_count: 0,
                read_scope: data_plane.begin_public_scan_read(),
            })
            .await
            .expect("record invalidated coverage");

        let new_epoch = data_plane.invalidate_public_scan_coverage_from(10).await;

        let state = data_plane.state.lock().await;
        assert_eq!(state.coverage.len(), 1);
        assert_eq!(
            state.coverage.records()[0].range,
            PublicScanRange::new(1, 9)
        );
        assert_eq!(state.coverage.records()[0].epoch, new_epoch);
        drop(state);
        assert!(matches!(
            data_plane
                .cached_public_scan_coverage(PublicScanRange::new(1, 9))
                .await,
            PublicCoverageAnswer::ReplayableEmpty { .. }
        ));
        assert!(matches!(
            data_plane
                .cached_public_scan_coverage(PublicScanRange::new(10, 20))
                .await,
            PublicCoverageAnswer::Missing { .. }
        ));
        drop(data_plane);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn invalidation_trims_spanning_coverage_record() {
        let (_db, data_plane, root_dir) = test_data_plane("coverage-invalidation-trim");
        data_plane
            .record_public_scan_coverage(PublicScanCoverageWrite {
                range: PublicScanRange::new(1, 20),
                source: PublicScanSource::Rpc,
                row_count: 0,
                read_scope: data_plane.begin_public_scan_read(),
            })
            .await
            .expect("record spanning coverage");

        let new_epoch = data_plane.invalidate_public_scan_coverage_from(10).await;

        let state = data_plane.state.lock().await;
        assert_eq!(state.coverage.len(), 1);
        assert_eq!(
            state.coverage.records()[0].range,
            PublicScanRange::new(1, 9)
        );
        assert_eq!(state.coverage.records()[0].epoch, new_epoch);
        drop(state);
        assert!(matches!(
            data_plane
                .cached_public_scan_coverage(PublicScanRange::new(1, 9))
                .await,
            PublicCoverageAnswer::ReplayableEmpty { .. }
        ));
        assert!(matches!(
            data_plane
                .cached_public_scan_coverage(PublicScanRange::new(10, 20))
                .await,
            PublicCoverageAnswer::Missing { .. }
        ));
        drop(data_plane);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn public_cache_reset_clears_coverage_and_advances_epoch() {
        let (_db, data_plane, root_dir) = test_data_plane("public-cache-reset-coverage");
        data_plane
            .record_public_scan_coverage(PublicScanCoverageWrite {
                range: PublicScanRange::new(1, 2),
                source: PublicScanSource::Rpc,
                row_count: 0,
                read_scope: data_plane.begin_public_scan_read(),
            })
            .await
            .expect("record coverage");
        data_plane
            .record_source_decision(
                PublicDataPlaneDiagnosticKind::SourceSelected,
                PublicScanSource::Rpc,
                PublicScanRange::new(1, 2),
                data_plane.begin_public_scan_read(),
                "test",
            )
            .await;

        let reset = data_plane
            .reset_public_cache()
            .await
            .expect("reset public cache");
        assert_eq!(reset.previous_epoch, PublicDataPlaneEpoch::new(0));
        assert_eq!(reset.new_epoch, PublicDataPlaneEpoch::new(1));
        assert_eq!(reset.coverage_entries_removed, 1);
        assert!(reset.diagnostics_removed >= 1);
        assert!(
            data_plane
                .cached_empty_wallet_scan_apply(1, 2)
                .await
                .is_none()
        );
        drop(data_plane);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn public_cache_reset_clears_durable_public_txid_and_poi_cache() {
        let (db, data_plane, root_dir) = test_data_plane("public-cache-reset-durable");
        let txid_kind = "txid_public_cache";
        let txid_name = "stale.msgpack";
        let txid_id = "stale-entry";
        let txid_path = db.blob_path(txid_kind, txid_name);
        db.ensure_blob_dir(txid_kind).expect("ensure txid blob dir");
        fs::write(&txid_path, b"stale txid cache").expect("write stale txid blob");
        db.put_blob_meta(
            txid_kind,
            txid_id,
            &BlobMeta {
                format_version: 1,
                relative_path: DbStore::relative_blob_path(txid_kind, txid_name),
                content_hash: Sha256::digest(b"stale txid cache").into(),
                source_hash: None,
                created_at: 1,
                updated_at: 1,
                last_block: None,
            },
        )
        .expect("put txid blob meta");
        let descriptor = PoiArtifactDescriptorRecord {
            cid: "cid".to_string(),
            sha256: "sha256".to_string(),
            byte_size: 1,
        };
        let list_key = FixedBytes::from([7_u8; 32]);
        db.put_poi_artifact_cache(&PoiArtifactCacheRecord {
            chain_type: 0,
            chain_id: 1,
            txid_version: "v2".to_string(),
            list_key,
            last_accepted_manifest_sequence: 1,
            base_descriptor: descriptor.clone(),
            applied_delta_descriptors: Vec::new(),
            blocked_shields_descriptor: descriptor,
            current_tip_index: 0,
            current_tip_root: FixedBytes::from([9_u8; 32]),
            cache_payload: vec![1, 2, 3],
            updated_at: 1,
        })
        .expect("put poi artifact cache");

        assert!(
            db.get_blob_meta(txid_kind, txid_id)
                .expect("get txid blob meta")
                .is_some()
        );
        assert!(
            db.get_poi_artifact_cache(0, 1, "v2", &list_key)
                .expect("get poi cache")
                .is_some()
        );

        let reset = data_plane
            .reset_public_cache()
            .await
            .expect("reset public cache");

        assert_eq!(reset.txid_blob_entries_removed, 1);
        assert!(reset.txid_files_removed >= 1);
        assert_eq!(reset.poi_cache_entries_removed, 1);
        assert!(
            db.get_blob_meta(txid_kind, txid_id)
                .expect("get txid blob meta after reset")
                .is_none()
        );
        assert!(!txid_path.exists());
        assert!(
            db.get_poi_artifact_cache(0, 1, "v2", &list_key)
                .expect("get poi cache after reset")
                .is_none()
        );

        drop(data_plane);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn public_data_plane_diagnostics_record_source_fallback() {
        let (_db, data_plane, root_dir) = test_data_plane("data-plane-diagnostics");
        let stale_scope = data_plane.begin_public_scan_read();
        data_plane.invalidate_public_scan_coverage_from(10).await;
        data_plane
            .record_source_decision(
                PublicDataPlaneDiagnosticKind::SourceSelected,
                PublicScanSource::IndexedArtifacts,
                PublicScanRange::new(10, 20),
                stale_scope,
                "artifact source selected",
            )
            .await;
        data_plane
            .record_source_decision(
                PublicDataPlaneDiagnosticKind::SourceFallback,
                PublicScanSource::Squid,
                PublicScanRange::new(10, 20),
                data_plane.begin_public_scan_read(),
                "artifact failed before checkpoint",
            )
            .await;

        let diagnostics = data_plane.diagnostics().await;
        assert_eq!(diagnostics.events.len(), 3);
        assert_eq!(
            diagnostics.events[1].kind,
            PublicDataPlaneDiagnosticKind::SourceSelected
        );
        assert_eq!(
            diagnostics.events[1].source,
            Some(PublicScanSource::IndexedArtifacts)
        );
        assert_eq!(diagnostics.events[1].epoch, stale_scope.epoch());
        assert_eq!(
            diagnostics.events[2].kind,
            PublicDataPlaneDiagnosticKind::SourceFallback
        );
        assert_eq!(diagnostics.events[2].source, Some(PublicScanSource::Squid));
        drop(data_plane);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test]
    async fn public_scan_epoch_validation_rejects_stale_apply_epoch() {
        let (_db, data_plane, root_dir) = test_data_plane("stale-apply-epoch");
        data_plane.invalidate_public_scan_coverage_from(10).await;

        let error = data_plane
            .validate_public_scan_read(
                PublicScanRange::new(10, 20),
                PublicScanSource::CachedCoverage,
                PublicScanReadScope::new(PublicDataPlaneEpoch::new(0)),
            )
            .await
            .expect_err("stale apply epoch must be rejected");

        assert_eq!(
            error,
            PublicDataPlaneError::StaleEpoch {
                expected: 1,
                actual: 0,
            }
        );
        drop(data_plane);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn validated_public_scan_commit_blocks_epoch_invalidation_until_commit_finishes() {
        let (_db, data_plane, root_dir) = test_data_plane("validated-commit-epoch-guard");
        let read_scope = data_plane.begin_public_scan_read();
        let range = PublicScanRange::new(10, 20);
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std_mpsc::channel();
        let commit_plane = data_plane.clone();
        let commit_task = tokio::spawn(async move {
            commit_plane
                .with_valid_public_scan_read(range, PublicScanSource::Rpc, read_scope, move || {
                    let _ = entered_tx.send(());
                    release_rx.recv().expect("release commit");
                })
                .await
                .expect("validated commit");
        });
        entered_rx.await.expect("commit closure entered");

        let invalidate_plane = data_plane.clone();
        let invalidate_task = tokio::spawn(async move {
            invalidate_plane
                .invalidate_public_scan_coverage_from(10)
                .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !invalidate_task.is_finished(),
            "epoch invalidation must wait for the guarded commit section"
        );

        release_tx.send(()).expect("release commit");
        commit_task.await.expect("commit task");
        assert_eq!(
            invalidate_task.await.expect("invalidate task"),
            PublicDataPlaneEpoch::new(1)
        );
        drop(data_plane);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    fn test_data_plane(name: &str) -> (Arc<DbStore>, ChainPublicDataPlane, PathBuf) {
        let root_dir = temp_db_root(name);
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let data_plane = ChainPublicDataPlane::new(Arc::clone(&db), Arc::new(AtomicU64::new(0)));
        (db, data_plane, root_dir)
    }

    fn temp_db_root(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!("sync-service-data-plane-{name}-{unique}"))
    }
}
