//! Recording, replaying and invalidating public scan coverage and rows.

use std::sync::Arc;
use std::sync::atomic::Ordering;

#[cfg(test)]
use super::PublicScanCoverageWrite;
use super::scan_state::{ChainPublicDataPlaneState, PublicScanCoverageRecord};
use super::{
    ChainPublicDataPlane, PublicCacheCommitPermit, PublicDataPlaneDiagnostic,
    PublicDataPlaneDiagnosticKind, PublicDataPlaneEpoch, PublicDataPlaneError,
    PublicScanCommitPermit, PublicScanRange, PublicScanReadScope, PublicScanRows, PublicScanSource,
    RECENT_PUBLIC_SCAN_ROW_PAGE_LIMIT, WalletScanAcquisitionCandidate,
    WalletScanAcquisitionOutcome, WalletScanApply, WalletScanInputRows, WalletScanRowsPayload,
};

impl ChainPublicDataPlane {
    #[cfg(test)]
    async fn record_public_scan_coverage_with_hash(
        &self,
        write: PublicScanCoverageWrite,
        to_block_hash: Option<[u8; 32]>,
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
                reason: "stale scan apply epoch".to_string(),
                epoch: current_epoch,
            });
            return Err(PublicDataPlaneError::StaleEpoch {
                expected: current_epoch.value,
                actual: captured_epoch.value,
            });
        }
        Self::validate_reusable_rpc_coverage(write.range, write.source, to_block_hash)?;

        state.insert_canonical_coverage(PublicScanCoverageRecord {
            range: write.range,
            source: write.source,
            row_count: write.row_count,
            to_block_hash,
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

    pub(crate) async fn record_public_scan_apply(
        &self,
        apply: &WalletScanApply,
    ) -> Result<PublicDataPlaneEpoch, PublicDataPlaneError> {
        self.record_public_scan_apply_with_acquisition(apply, None)
            .await
            .map(|(epoch, _)| epoch)
    }

    pub(crate) async fn record_public_scan_apply_with_acquisition(
        &self,
        apply: &WalletScanApply,
        candidate: Option<&WalletScanAcquisitionCandidate>,
    ) -> Result<(PublicDataPlaneEpoch, Option<WalletScanAcquisitionOutcome>), PublicDataPlaneError>
    {
        let mut state = self.state.lock().await;
        let current_epoch = self.current_epoch();
        let base = state.transaction_snapshot();
        let ordinary = Self::stage_ordinary_apply(&mut state, &base, current_epoch, apply)?;
        let (final_staged, outcome) = match candidate {
            Some(candidate) => {
                match Self::stage_retained_acquisition(&base, current_epoch, apply, candidate) {
                    Ok(trial) => (trial, Some(WalletScanAcquisitionOutcome::Retained)),
                    Err(error) => (ordinary, Some(rejected_acquisition_outcome(error))),
                }
            }
            None => (ordinary, None),
        };

        state.commit_snapshot(final_staged);
        state.push_diagnostic(PublicDataPlaneDiagnostic {
            kind: PublicDataPlaneDiagnosticKind::CoverageRecorded,
            source: Some(apply.rows.source),
            range: Some(PublicScanRange::new(apply.from_block, apply.to_block)),
            reason: format!(
                "recorded public scan apply with {} acquisition candidate",
                usize::from(candidate.is_some())
            ),
            epoch: current_epoch,
        });
        Ok((current_epoch, outcome))
    }

    /// Stages `apply` alone into a snapshot of `base`. A stale epoch is also
    /// reported on `live_state`, since diagnostics on the snapshot are dropped.
    fn stage_ordinary_apply(
        live_state: &mut ChainPublicDataPlaneState,
        base: &ChainPublicDataPlaneState,
        current_epoch: PublicDataPlaneEpoch,
        apply: &WalletScanApply,
    ) -> Result<ChainPublicDataPlaneState, PublicDataPlaneError> {
        let mut ordinary = base.transaction_snapshot();
        if let Err(error) = Self::stage_wallet_scan_apply(&mut ordinary, current_epoch, apply, &[])
        {
            if matches!(&error, PublicDataPlaneError::StaleEpoch { .. }) {
                Self::push_stale_coverage_diagnostic(
                    live_state,
                    current_epoch,
                    apply.rows.source,
                    PublicScanRange::new(apply.from_block, apply.to_block),
                );
            }
            return Err(error);
        }
        Self::ensure_recent_scan_row_page_limit(&ordinary)?;
        Ok(ordinary)
    }

    /// Stages `apply` into a snapshot of `base` that also keeps `candidate`
    /// exactly replayable, compacting the candidate's applies only when the
    /// apply alone does not.
    fn stage_retained_acquisition(
        base: &ChainPublicDataPlaneState,
        current_epoch: PublicDataPlaneEpoch,
        apply: &WalletScanApply,
        candidate: &WalletScanAcquisitionCandidate,
    ) -> Result<ChainPublicDataPlaneState, PublicDataPlaneError> {
        let proposed_ranges = [candidate.range];
        let mut trial = base.transaction_snapshot();
        Self::stage_wallet_scan_apply(&mut trial, current_epoch, apply, &proposed_ranges)?;
        if !Self::cached_wallet_scan_is_exact(&trial, candidate.range, current_epoch)
            || trial.recent_scan_rows.len() > RECENT_PUBLIC_SCAN_ROW_PAGE_LIMIT
        {
            let mut validation_state = base.transaction_snapshot();
            let compacted = Self::compact_completed_wallet_scan_acquisition(
                &mut validation_state,
                current_epoch,
                candidate.range,
                &candidate.applies,
            )?;
            Self::stage_compacted_wallet_scan_acquisition(
                &mut trial,
                current_epoch,
                &compacted,
                &proposed_ranges,
            )?;
        }
        Self::ensure_recent_scan_row_page_limit(&trial)?;
        if !Self::cached_wallet_scan_is_exact(&trial, candidate.range, current_epoch) {
            return Err(PublicDataPlaneError::InvalidCompletedAcquisition {
                reason: "accepted acquisition is not exactly replayable".to_string(),
            });
        }
        Ok(trial)
    }

    pub(crate) async fn commit_completed_wallet_scan_acquisition(
        &self,
        range: PublicScanRange,
        applies: &[WalletScanApply],
    ) -> Result<PublicDataPlaneEpoch, PublicDataPlaneError> {
        let mut state = self.state.lock().await;
        let current_epoch = self.current_epoch();
        let base = state.transaction_snapshot();
        let mut validation_state = base.transaction_snapshot();
        let compacted = match Self::compact_completed_wallet_scan_acquisition(
            &mut validation_state,
            current_epoch,
            range,
            applies,
        ) {
            Ok(compacted) => compacted,
            Err(error) => {
                if matches!(&error, PublicDataPlaneError::StaleEpoch { .. })
                    && let Some(stale_apply) = applies
                        .iter()
                        .find(|apply| apply.read_scope.epoch() != current_epoch)
                {
                    Self::push_stale_coverage_diagnostic(
                        &mut state,
                        current_epoch,
                        stale_apply.rows.source,
                        PublicScanRange::new(stale_apply.from_block, stale_apply.to_block),
                    );
                }
                return Err(error);
            }
        };
        let protected_ranges = [range];
        let mut staged = base.transaction_snapshot();
        if !Self::cached_wallet_scan_is_exact(&staged, range, current_epoch) {
            Self::stage_compacted_wallet_scan_acquisition(
                &mut staged,
                current_epoch,
                &compacted,
                &protected_ranges,
            )?;
        }
        Self::ensure_recent_scan_row_page_limit(&staged)?;
        if !Self::cached_wallet_scan_is_exact(&staged, range, current_epoch) {
            return Err(PublicDataPlaneError::InvalidCompletedAcquisition {
                reason: "compacted acquisition is not exactly replayable".to_string(),
            });
        }
        state.commit_snapshot(staged);
        state.push_diagnostic(PublicDataPlaneDiagnostic {
            kind: PublicDataPlaneDiagnosticKind::CoverageRecorded,
            source: None,
            range: Some(range),
            reason: "committed completed wallet scan acquisition".to_string(),
            epoch: current_epoch,
        });
        Ok(current_epoch)
    }

    #[cfg(test)]
    pub(crate) async fn record_recent_public_scan_rows(
        &self,
        rows: PublicScanRows,
    ) -> Result<PublicDataPlaneEpoch, PublicDataPlaneError> {
        if !rows.range.is_valid() {
            return Err(PublicDataPlaneError::InvalidRange {
                from_block: rows.range.from_block,
                to_block: rows.range.to_block,
            });
        }
        let mut state = self.state.lock().await;
        let current_epoch = self.current_epoch();
        if current_epoch != rows.epoch {
            state.push_diagnostic(PublicDataPlaneDiagnostic {
                kind: PublicDataPlaneDiagnosticKind::CoverageRejected,
                source: Some(rows.source),
                range: Some(rows.range),
                reason: "stale recent public rows epoch".to_string(),
                epoch: current_epoch,
            });
            return Err(PublicDataPlaneError::StaleEpoch {
                expected: current_epoch.value,
                actual: rows.epoch.value,
            });
        }
        Self::validate_reusable_rpc_coverage(rows.range, rows.source, rows.to_block_hash)?;

        let row_count = rows.row_count();
        state.insert_canonical_coverage(PublicScanCoverageRecord {
            range: rows.range,
            source: rows.source,
            row_count,
            to_block_hash: rows.to_block_hash,
            epoch: current_epoch,
        });
        state.insert_recent_scan_rows_with_protection(rows.clone(), &[]);
        state.push_diagnostic(PublicDataPlaneDiagnostic {
            kind: PublicDataPlaneDiagnosticKind::CoverageRecorded,
            source: Some(rows.source),
            range: Some(rows.range),
            reason: format!("recorded and buffered {row_count} public rows"),
            epoch: current_epoch,
        });
        Ok(current_epoch)
    }

    fn compact_completed_wallet_scan_acquisition(
        state: &mut ChainPublicDataPlaneState,
        current_epoch: PublicDataPlaneEpoch,
        range: PublicScanRange,
        applies: &[WalletScanApply],
    ) -> Result<Vec<PublicScanRows>, PublicDataPlaneError> {
        if !range.is_valid() {
            return Err(PublicDataPlaneError::InvalidRange {
                from_block: range.from_block,
                to_block: range.to_block,
            });
        }
        let mut compacted = Vec::<PublicScanRows>::new();
        let mut expected_from = range.from_block;
        for (index, apply) in applies.iter().enumerate() {
            let apply_range = PublicScanRange::new(apply.from_block, apply.to_block);
            if !apply_continues_acquisition(apply, expected_from, range) {
                return Err(PublicDataPlaneError::InvalidCompletedAcquisition {
                    reason: format!(
                        "apply {index} does not exactly continue {}..={}",
                        range.from_block, range.to_block
                    ),
                });
            }
            Self::validate_public_scan_read_locked(
                state,
                current_epoch,
                apply_range,
                apply.rows.source,
                apply.read_scope,
            )?;
            Self::validate_reusable_rpc_coverage(
                apply_range,
                apply.rows.source,
                apply.rows.to_block_hash,
            )?;
            let rows = match &apply.rows.payload {
                WalletScanRowsPayload::Rows(rows) => rows.as_ref().clone(),
                WalletScanRowsPayload::EmptyCoverage => WalletScanInputRows::default(),
                #[cfg(test)]
                WalletScanRowsPayload::IndexedDeltaForTest { .. } => {
                    return Err(PublicDataPlaneError::InvalidCompletedAcquisition {
                        reason: "indexed test deltas cannot be retained for replay".to_string(),
                    });
                }
            };
            push_compacted_run(&mut compacted, apply, apply_range, rows);
            if index + 1 < applies.len() {
                expected_from = apply.to_block.checked_add(1).ok_or_else(|| {
                    PublicDataPlaneError::InvalidCompletedAcquisition {
                        reason: "acquisition continues past the maximum block".to_string(),
                    }
                })?;
            } else if apply.to_block != range.to_block {
                return Err(PublicDataPlaneError::InvalidCompletedAcquisition {
                    reason: format!(
                        "acquisition ends at {}, expected {}",
                        apply.to_block, range.to_block
                    ),
                });
            }
        }
        if compacted.is_empty() {
            return Err(PublicDataPlaneError::InvalidCompletedAcquisition {
                reason: "acquisition contains no applies".to_string(),
            });
        }
        Ok(compacted)
    }

    fn stage_wallet_scan_apply(
        state: &mut ChainPublicDataPlaneState,
        current_epoch: PublicDataPlaneEpoch,
        apply: &WalletScanApply,
        protected_ranges: &[PublicScanRange],
    ) -> Result<(), PublicDataPlaneError> {
        let range = PublicScanRange::new(apply.from_block, apply.to_block);
        if !range.is_valid() {
            return Err(PublicDataPlaneError::InvalidRange {
                from_block: range.from_block,
                to_block: range.to_block,
            });
        }
        Self::validate_public_scan_read_locked(
            state,
            current_epoch,
            range,
            apply.rows.source,
            apply.read_scope,
        )?;
        Self::validate_reusable_rpc_coverage(range, apply.rows.source, apply.rows.to_block_hash)?;
        match &apply.rows.payload {
            WalletScanRowsPayload::Rows(rows) => {
                let rows = PublicScanRows {
                    range,
                    source: apply.rows.source,
                    to_block_hash: apply.rows.to_block_hash,
                    rows: rows.as_ref().clone(),
                    epoch: current_epoch,
                };
                Self::stage_public_scan_rows(state, current_epoch, rows, protected_ranges);
            }
            WalletScanRowsPayload::EmptyCoverage => {
                state.insert_canonical_coverage(PublicScanCoverageRecord {
                    range,
                    source: apply.rows.source,
                    row_count: 0,
                    to_block_hash: apply.rows.to_block_hash,
                    epoch: current_epoch,
                });
            }
            #[cfg(test)]
            WalletScanRowsPayload::IndexedDeltaForTest { .. } => {
                state.insert_canonical_coverage(PublicScanCoverageRecord {
                    range,
                    source: apply.rows.source,
                    row_count: 0,
                    to_block_hash: None,
                    epoch: current_epoch,
                });
            }
        }
        Ok(())
    }

    fn stage_compacted_wallet_scan_acquisition(
        state: &mut ChainPublicDataPlaneState,
        current_epoch: PublicDataPlaneEpoch,
        compacted: &[PublicScanRows],
        protected_ranges: &[PublicScanRange],
    ) -> Result<(), PublicDataPlaneError> {
        let row_pages = compacted.iter().filter(|run| run.row_count() > 0).count();
        if row_pages > RECENT_PUBLIC_SCAN_ROW_PAGE_LIMIT {
            return Err(PublicDataPlaneError::CompletedAcquisitionRowPageLimit {
                row_pages,
                limit: RECENT_PUBLIC_SCAN_ROW_PAGE_LIMIT,
            });
        }
        for run in compacted {
            Self::stage_public_scan_rows(state, current_epoch, run.clone(), protected_ranges);
        }
        Ok(())
    }

    fn stage_public_scan_rows(
        state: &mut ChainPublicDataPlaneState,
        current_epoch: PublicDataPlaneEpoch,
        rows: PublicScanRows,
        protected_ranges: &[PublicScanRange],
    ) {
        state.insert_canonical_coverage(PublicScanCoverageRecord {
            range: rows.range,
            source: rows.source,
            row_count: rows.row_count(),
            to_block_hash: rows.to_block_hash,
            epoch: current_epoch,
        });
        state.insert_recent_scan_rows_with_protection(rows, protected_ranges);
    }

    fn push_stale_coverage_diagnostic(
        state: &mut ChainPublicDataPlaneState,
        current_epoch: PublicDataPlaneEpoch,
        source: PublicScanSource,
        range: PublicScanRange,
    ) {
        state.push_diagnostic(PublicDataPlaneDiagnostic {
            kind: PublicDataPlaneDiagnosticKind::CoverageRejected,
            source: Some(source),
            range: Some(range),
            reason: "stale coverage epoch".to_string(),
            epoch: current_epoch,
        });
    }

    fn ensure_recent_scan_row_page_limit(
        state: &ChainPublicDataPlaneState,
    ) -> Result<(), PublicDataPlaneError> {
        if state.recent_scan_rows.len() > RECENT_PUBLIC_SCAN_ROW_PAGE_LIMIT {
            return Err(PublicDataPlaneError::CompletedAcquisitionRowPageLimit {
                row_pages: state.recent_scan_rows.len(),
                limit: RECENT_PUBLIC_SCAN_ROW_PAGE_LIMIT,
            });
        }
        Ok(())
    }

    fn cached_wallet_scan_is_exact(
        state: &ChainPublicDataPlaneState,
        range: PublicScanRange,
        epoch: PublicDataPlaneEpoch,
    ) -> bool {
        state
            .cached_wallet_scan_suffix(range, epoch)
            .is_some_and(|replay| wallet_scan_applies_exactly_cover(&replay, range))
    }

    const fn validate_reusable_rpc_coverage(
        range: PublicScanRange,
        source: PublicScanSource,
        to_block_hash: Option<[u8; 32]>,
    ) -> Result<(), PublicDataPlaneError> {
        if matches!(source, PublicScanSource::Rpc | PublicScanSource::ArchiveRpc)
            && to_block_hash.is_none()
        {
            return Err(PublicDataPlaneError::UnprovenRpcCoverage {
                from_block: range.from_block,
                to_block: range.to_block,
                scan_source: source,
            });
        }
        Ok(())
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

    pub(crate) async fn public_scan_commit_permit(
        &self,
        range: PublicScanRange,
        source: PublicScanSource,
        read_scope: PublicScanReadScope,
    ) -> Result<PublicScanCommitPermit, PublicDataPlaneError> {
        if !range.is_valid() {
            return Err(PublicDataPlaneError::InvalidRange {
                from_block: range.from_block,
                to_block: range.to_block,
            });
        }
        let commit_guard = Arc::clone(&self.commit_fence).lock_owned().await;
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
        Ok(PublicScanCommitPermit {
            _guard: commit_guard,
        })
    }

    pub(super) async fn public_cache_commit_permit(
        &self,
        read_scope: PublicScanReadScope,
        reason: impl Into<String>,
    ) -> Result<PublicCacheCommitPermit, PublicDataPlaneError> {
        let commit_guard = Arc::clone(&self.commit_fence).lock_owned().await;
        let mut state = self.state.lock().await;
        let current_epoch = self.current_epoch();
        if current_epoch != read_scope.epoch() {
            state.push_diagnostic(PublicDataPlaneDiagnostic {
                kind: PublicDataPlaneDiagnosticKind::CoverageRejected,
                source: None,
                range: None,
                reason: reason.into(),
                epoch: current_epoch,
            });
            return Err(PublicDataPlaneError::StaleEpoch {
                expected: current_epoch.value,
                actual: read_scope.epoch().value,
            });
        }
        Ok(PublicCacheCommitPermit {
            _guard: commit_guard,
        })
    }

    pub(crate) async fn invalidate_public_scan_coverage_from(
        &self,
        from_block: u64,
    ) -> PublicDataPlaneEpoch {
        let _commit_guard = self.commit_fence.lock().await;
        let mut state = self.state.lock().await;
        let previous_epoch = self.current_epoch();
        let affected = state.coverage.invalidate_from(from_block);
        state.recent_scan_rows.clear();
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

    pub(crate) async fn cached_wallet_scan_apply(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Option<WalletScanApply> {
        if from_block > to_block {
            return None;
        }
        let state = self.state.lock().await;
        let epoch = self.current_epoch();
        let range = PublicScanRange::new(from_block, to_block);
        state.cached_wallet_scan_apply(range, epoch)
    }

    pub(crate) async fn cached_wallet_scan_suffix(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Option<Vec<WalletScanApply>> {
        if from_block > to_block {
            return None;
        }
        let state = self.state.lock().await;
        let epoch = self.current_epoch();
        state.cached_wallet_scan_suffix(PublicScanRange::new(from_block, to_block), epoch)
    }

    pub(crate) async fn cached_wallet_scan_exact(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Option<Vec<WalletScanApply>> {
        if from_block > to_block {
            return None;
        }
        let state = self.state.lock().await;
        let epoch = self.current_epoch();
        let range = PublicScanRange::new(from_block, to_block);
        let applies = state.cached_wallet_scan_suffix(range, epoch)?;
        wallet_scan_applies_exactly_cover(&applies, range).then_some(applies)
    }

    pub(super) fn bump_epoch_locked(
        &self,
        previous_epoch: PublicDataPlaneEpoch,
    ) -> PublicDataPlaneEpoch {
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

/// A row-page overflow makes a candidate acquisition non-retainable; any
/// other staging failure rejects it.
const fn rejected_acquisition_outcome(error: PublicDataPlaneError) -> WalletScanAcquisitionOutcome {
    if matches!(
        &error,
        PublicDataPlaneError::CompletedAcquisitionRowPageLimit { .. }
    ) {
        WalletScanAcquisitionOutcome::NonRetainable(error)
    } else {
        WalletScanAcquisitionOutcome::Rejected(error)
    }
}

/// Whether `apply` is a valid range that starts at `expected_from`, ends
/// within `acquisition` and carries rows for all of its blocks.
const fn apply_continues_acquisition(
    apply: &WalletScanApply,
    expected_from: u64,
    acquisition: PublicScanRange,
) -> bool {
    PublicScanRange::new(apply.from_block, apply.to_block).is_valid()
        && apply.from_block == expected_from
        && apply.to_block <= acquisition.to_block
        && apply.rows.covers(apply.from_block, apply.to_block)
}

/// Extends the last run with `apply` when it has the same source and read
/// epoch, otherwise starts a new run.
fn push_compacted_run(
    compacted: &mut Vec<PublicScanRows>,
    apply: &WalletScanApply,
    apply_range: PublicScanRange,
    rows: WalletScanInputRows,
) {
    if let Some(run) = compacted.last_mut()
        && run.source == apply.rows.source
        && run.epoch == apply.read_scope.epoch()
    {
        run.range.to_block = apply.to_block;
        run.to_block_hash = apply.rows.to_block_hash;
        append_wallet_scan_input_rows(&mut run.rows, rows);
    } else {
        compacted.push(PublicScanRows {
            range: apply_range,
            source: apply.rows.source,
            to_block_hash: apply.rows.to_block_hash,
            rows,
            epoch: apply.read_scope.epoch(),
        });
    }
}

fn append_wallet_scan_input_rows(target: &mut WalletScanInputRows, mut rows: WalletScanInputRows) {
    target
        .transact_commitments
        .append(&mut rows.transact_commitments);
    target
        .shield_commitments
        .append(&mut rows.shield_commitments);
    target
        .legacy_encrypted_commitments
        .append(&mut rows.legacy_encrypted_commitments);
    target
        .legacy_generated_commitments
        .append(&mut rows.legacy_generated_commitments);
    target.nullifiers.append(&mut rows.nullifiers);
    target
        .commitment_observations
        .append(&mut rows.commitment_observations);
}

fn wallet_scan_applies_exactly_cover(applies: &[WalletScanApply], range: PublicScanRange) -> bool {
    let mut expected_from = range.from_block;
    for (index, apply) in applies.iter().enumerate() {
        if apply.from_block != expected_from || apply.to_block > range.to_block {
            return false;
        }
        if index + 1 == applies.len() {
            return apply.to_block == range.to_block;
        }
        let Some(next_block) = apply.to_block.checked_add(1) else {
            return false;
        };
        expected_from = next_block;
    }
    false
}

#[cfg(test)]
impl ChainPublicDataPlane {
    #[cfg(test)]
    pub(crate) async fn record_public_scan_coverage(
        &self,
        write: PublicScanCoverageWrite,
    ) -> Result<PublicDataPlaneEpoch, PublicDataPlaneError> {
        let to_block_hash = matches!(
            write.source,
            PublicScanSource::Rpc | PublicScanSource::ArchiveRpc
        )
        .then_some([0; 32]);
        self.record_public_scan_coverage_with_hash(write, to_block_hash)
            .await
    }

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
}
