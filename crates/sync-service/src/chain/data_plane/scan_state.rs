//! In-memory public scan coverage and recent row pages.

use crate::types::LocalPoiCaches;
use std::collections::{BTreeMap, VecDeque};

use super::{
    PublicDataPlaneDiagnostic, PublicDataPlaneEpoch, PublicPoiCorpusKey, PublicScanRange,
    PublicScanReadScope, PublicScanRows, PublicScanSource, RECENT_PUBLIC_SCAN_ROW_PAGE_LIMIT,
    WalletScanApply,
};

const PUBLIC_DATA_PLANE_DIAGNOSTIC_LIMIT: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PublicScanCoverageRecord {
    pub(super) range: PublicScanRange,
    pub(super) source: PublicScanSource,
    pub(super) row_count: usize,
    pub(super) to_block_hash: Option<[u8; 32]>,
    pub(super) epoch: PublicDataPlaneEpoch,
}

#[derive(Debug, Clone, Default)]
pub(super) struct PublicCoverageStore {
    records: Vec<PublicScanCoverageRecord>,
}

impl PublicCoverageStore {
    pub(super) const fn len(&self) -> usize {
        self.records.len()
    }

    pub(super) fn clear(&mut self) {
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
                left.to_block_hash = None;
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

    pub(super) fn invalidate_from(&mut self, from_block: u64) -> usize {
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
                record.to_block_hash = None;
                if record.range.is_valid() {
                    records.push(record);
                }
            }
        }
        self.records = records;
        affected
    }

    pub(super) fn restamp_epoch(&mut self, epoch: PublicDataPlaneEpoch) {
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
    ) -> Option<EmptyCoverageForRange> {
        if !range.is_valid() {
            return None;
        }
        let mut next_block = range.from_block;
        let mut covered_to = None;
        let mut to_block_hash = None;
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
            to_block_hash = if record_to == record.range.to_block {
                record.to_block_hash
            } else {
                None
            };
            if record_to >= range.to_block {
                break;
            }
            next_block = record_to.saturating_add(1);
        }
        covered_to.map(|covered_to| EmptyCoverageForRange {
            covered_to,
            to_block_hash,
        })
    }

    fn mark_range_empty(&mut self, range: PublicScanRange, epoch: PublicDataPlaneEpoch) {
        if let Some(record) = self
            .records
            .iter_mut()
            .find(|record| record.epoch == epoch && record.range == range)
        {
            record.row_count = 0;
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct ChainPublicDataPlaneState {
    pub(super) coverage: PublicCoverageStore,
    pub(super) diagnostics: Vec<PublicDataPlaneDiagnostic>,
    pub(super) recent_scan_rows: VecDeque<PublicScanRows>,
    pub(super) poi_corpora: BTreeMap<PublicPoiCorpusKey, LocalPoiCaches>,
}

impl ChainPublicDataPlaneState {
    pub(super) fn transaction_snapshot(&self) -> Self {
        Self {
            coverage: self.coverage.clone(),
            recent_scan_rows: self.recent_scan_rows.clone(),
            ..Self::default()
        }
    }

    /// Publishes the coverage and row pages of a snapshot staged from
    /// [`Self::transaction_snapshot`]; diagnostics and POI corpora stay live.
    pub(super) fn commit_snapshot(&mut self, staged: Self) {
        self.coverage = staged.coverage;
        self.recent_scan_rows = staged.recent_scan_rows;
    }

    pub(super) fn insert_canonical_coverage(&mut self, record: PublicScanCoverageRecord) {
        self.coverage.insert_canonical(record);
    }

    pub(super) fn coverage_for_range(
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
    ) -> Option<EmptyCoverageForRange> {
        self.coverage.empty_coverage_prefix_for_range(range, epoch)
    }

    pub(super) fn push_diagnostic(&mut self, diagnostic: PublicDataPlaneDiagnostic) {
        self.diagnostics.push(diagnostic);
        let overflow = self
            .diagnostics
            .len()
            .saturating_sub(PUBLIC_DATA_PLANE_DIAGNOSTIC_LIMIT);
        if overflow > 0 {
            self.diagnostics.drain(0..overflow);
        }
    }

    pub(super) fn insert_recent_scan_rows_with_protection(
        &mut self,
        rows: PublicScanRows,
        protected_ranges: &[PublicScanRange],
    ) {
        let mut retained = VecDeque::new();
        while let Some(mut existing) = self.recent_scan_rows.pop_front() {
            if existing.epoch != rows.epoch {
                continue;
            }
            if !existing.range.intersects(rows.range) {
                retained.push_back(existing);
                continue;
            }
            if existing.range.from_block < rows.range.from_block {
                let mut prefix = existing.clone();
                prefix.range.to_block = rows.range.from_block - 1;
                prefix
                    .rows
                    .retain_block_range(prefix.range.from_block, prefix.range.to_block);
                prefix.to_block_hash = None;
                if prefix.row_count() == 0 {
                    self.coverage.mark_range_empty(prefix.range, prefix.epoch);
                } else {
                    retained.push_back(prefix);
                }
            }
            if existing.range.to_block > rows.range.to_block {
                existing.range.from_block = rows.range.to_block + 1;
                existing
                    .rows
                    .retain_block_range(existing.range.from_block, existing.range.to_block);
                if existing.row_count() == 0 {
                    self.coverage
                        .mark_range_empty(existing.range, existing.epoch);
                } else {
                    retained.push_back(existing);
                }
            }
        }
        self.recent_scan_rows = retained;
        if rows.row_count() > 0 {
            self.recent_scan_rows.push_back(rows);
        }
        while self.recent_scan_rows.len() > RECENT_PUBLIC_SCAN_ROW_PAGE_LIMIT {
            let Some(oldest_block_index) = self
                .recent_scan_rows
                .iter()
                .enumerate()
                .filter(|(_, rows)| {
                    !protected_ranges
                        .iter()
                        .any(|range| rows.range.intersects(*range))
                })
                .min_by_key(|(_, rows)| (rows.range.to_block, rows.range.from_block))
                .map(|(index, _)| index)
            else {
                break;
            };
            self.recent_scan_rows.remove(oldest_block_index);
        }
    }

    fn recent_scan_rows_for_range(
        &self,
        range: PublicScanRange,
        epoch: PublicDataPlaneEpoch,
    ) -> Option<PublicScanRows> {
        let rows = self.recent_scan_rows.iter().rev().find(|rows| {
            rows.epoch == epoch
                && rows.range.from_block <= range.from_block
                && rows.range.to_block >= range.from_block
        })?;
        let to_block = rows.range.to_block.min(range.to_block);
        let mut selected = rows.clone();
        selected.range = PublicScanRange::new(range.from_block, to_block);
        selected.rows.retain_block_range(range.from_block, to_block);
        if to_block < rows.range.to_block {
            selected.to_block_hash = None;
        }
        Some(selected)
    }

    pub(super) fn cached_wallet_scan_apply(
        &self,
        range: PublicScanRange,
        epoch: PublicDataPlaneEpoch,
    ) -> Option<WalletScanApply> {
        let read_scope = PublicScanReadScope::new(epoch);
        if let Some(rows) = self.recent_scan_rows_for_range(range, epoch) {
            return Some(WalletScanApply::rows(
                rows.range.from_block,
                rows.range.to_block,
                rows.rows,
                read_scope,
                PublicScanSource::CachedCoverage,
                rows.to_block_hash,
            ));
        }
        let coverage = self.empty_coverage_prefix_for_range(range, epoch)?;
        Some(WalletScanApply::empty_coverage(
            range.from_block,
            coverage.covered_to,
            read_scope,
            PublicScanSource::CachedCoverage,
            coverage.to_block_hash,
        ))
    }

    pub(super) fn cached_wallet_scan_suffix(
        &self,
        range: PublicScanRange,
        epoch: PublicDataPlaneEpoch,
    ) -> Option<Vec<WalletScanApply>> {
        let mut replayable_ranges = self
            .coverage
            .records
            .iter()
            .filter(|record| record.epoch == epoch && record.row_count == 0)
            .map(|record| record.range)
            .chain(
                self.recent_scan_rows
                    .iter()
                    .filter(|rows| rows.epoch == epoch)
                    .map(|rows| rows.range),
            )
            .collect::<Vec<_>>();
        replayable_ranges.sort_unstable_by_key(|range| (range.from_block, range.to_block));

        let mut suffix_start = None;
        let mut merged = None::<PublicScanRange>;
        for candidate in replayable_ranges {
            let Some(current) = merged.as_mut() else {
                merged = Some(candidate);
                continue;
            };
            if candidate.from_block <= current.to_block.saturating_add(1) {
                current.to_block = current.to_block.max(candidate.to_block);
                continue;
            }
            if (current.from_block..=current.to_block).contains(&range.to_block) {
                suffix_start = Some(current.from_block.max(range.from_block));
            }
            *current = candidate;
        }
        if let Some(current) = merged
            && (current.from_block..=current.to_block).contains(&range.to_block)
        {
            suffix_start = Some(current.from_block.max(range.from_block));
        }

        let mut from_block = suffix_start?;
        let mut applies = Vec::new();
        while from_block <= range.to_block {
            let apply = self.cached_wallet_scan_apply(
                PublicScanRange::new(from_block, range.to_block),
                epoch,
            )?;
            let applied_to = apply.to_block;
            applies.push(apply);
            if applied_to >= range.to_block {
                break;
            }
            from_block = applied_to.saturating_add(1);
        }
        Some(applies)
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct CoverageForRange {
    pub(super) covered_to: u64,
    pub(super) source: PublicScanSource,
    pub(super) has_rows: bool,
}

#[derive(Debug, Clone, Copy)]
struct EmptyCoverageForRange {
    covered_to: u64,
    to_block_hash: Option<[u8; 32]>,
}

#[cfg(test)]
impl PublicCoverageStore {
    pub(super) fn records(&self) -> &[PublicScanCoverageRecord] {
        &self.records
    }
}
