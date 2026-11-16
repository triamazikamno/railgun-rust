use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::OnceLock;

use crate::chain::{ChainPublicDataPlaneCommitGuard, PublicTxidDataAuthority};
use crate::types::PublicDataPlaneEpoch;

use super::output_poi_recovery::{OutputPoiProofSourceResolution, WalletNullifierIndex};
#[allow(clippy::wildcard_imports)]
use super::*;

mod local_retirement;
mod materialization;
mod qualification;
mod unshield;

pub(super) use local_retirement::classify_sender_candidate_for_local_retirement;
use local_retirement::{
    SenderCandidateCoverage, locally_valid_sender_candidate, sender_candidate_coverage,
};
use materialization::{PreparedSenderCandidateMaterialization, SenderCandidateProver};
use qualification::{QualifiedSenderCandidate, qualify_sender_candidate_from_public_rows};
pub(super) use unshield::{
    SenderUnshieldAttempts, SenderUnshieldInputs, process_sender_candidate_unshields,
    sender_candidate_after_unshield_validation, sender_unshield_valid_txids,
};
use unshield::{
    corpus_shield_blocked_unshield_inputs, eligible_sender_unshield_txids,
    sender_candidate_unshield_txids, sender_candidate_with_unshield_work,
    unresolved_sender_unshield_txids,
};

pub(super) struct SenderCandidateRecoveryRequest<'a> {
    pub(super) output_recovery: OutputPoiRecoveryRequest<'a>,
    pub(super) candidates: Vec<SenderTransactionCandidate>,
    pub(super) unshield_attempts: &'a SenderUnshieldAttempts,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SenderCandidateRecoveryReport {
    pub(super) materialized: usize,
    pub(super) retired_locally_valid: usize,
    pub(super) awaiting_public_txid_data: u64,
    pub(super) awaiting_poi_data: u64,
    pub(super) retrying: u64,
    pub(super) needs_attention: u64,
    pub(super) covered_by_pending_contexts: u64,
    /// Materializations skipped because the POI corpus advanced after proof preparation.
    pub(super) stale_revision_skips: u64,
    /// Unshields this actor submitted that are not yet Valid, counted once each per pass.
    pub(super) unshield_awaiting_validation: u64,
    pub(super) unshields_validated: usize,
    pub(super) expected_candidates: BTreeMap<FixedBytes<32>, Vec<u8>>,
    pub(super) expected_pending_contexts: BTreeMap<FixedBytes<32>, Vec<u8>>,
    /// Predecessors satisfied by an exact, durable replacement in this recovery run.
    pub(super) satisfied_pending_contexts: BTreeSet<FixedBytes<32>>,
}

impl SenderCandidateRecoveryReport {
    pub(super) const fn completed(&self) -> usize {
        self.materialized
            .saturating_add(self.retired_locally_valid)
            .saturating_add(self.unshields_validated)
    }

    pub(super) fn matches_pending_contexts(
        &self,
        cache_store: &dyn WalletCacheStore,
        cfg: &WalletConfig,
    ) -> Result<bool, WalletCacheError> {
        for (commitment, expected) in &self.expected_pending_contexts {
            let current = cache_store.get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                commitment,
            )?;
            if current
                .as_ref()
                .and_then(pending_output_poi_context_fingerprint)
                .as_ref()
                != Some(expected)
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(super) fn merge_replay_report(&mut self, replay: Self) {
        self.awaiting_public_txid_data = self
            .awaiting_public_txid_data
            .saturating_add(replay.awaiting_public_txid_data);
        self.retrying = self.retrying.saturating_add(replay.retrying);
        self.needs_attention = self.needs_attention.saturating_add(replay.needs_attention);
        self.expected_pending_contexts
            .extend(replay.expected_pending_contexts);
        self.expected_pending_contexts
            .retain(|commitment, _| !self.satisfied_pending_contexts.contains(commitment));
    }

    pub(super) fn matches_candidates(&self, candidates: &[SenderTransactionCandidate]) -> bool {
        candidates
            .iter()
            .filter_map(|candidate| {
                candidate
                    .encode()
                    .ok()
                    .map(|encoded| (candidate.semantic_id(), encoded))
            })
            .collect::<BTreeMap<_, _>>()
            == self.expected_candidates
    }
}

#[derive(Clone)]
pub(crate) struct SenderCandidatePublicDataFence {
    public_data_plane: ChainPublicDataPlane,
    cache_key: PublicTxidCacheKey,
    epoch: PublicDataPlaneEpoch,
    rows: Vec<PublicTxidTransaction>,
    authority: PublicTxidDataAuthority,
}

impl fmt::Debug for SenderCandidatePublicDataFence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SenderCandidatePublicDataFence")
            .field("epoch", &self.epoch)
            .field("row_count", &self.rows.len())
            .field("authority", &self.authority)
            .finish_non_exhaustive()
    }
}

impl SenderCandidatePublicDataFence {
    pub(super) fn new(
        public_data_plane: &ChainPublicDataPlane,
        cache_key: PublicTxidCacheKey,
        epoch: PublicDataPlaneEpoch,
        rows: Vec<PublicTxidTransaction>,
        authority: PublicTxidDataAuthority,
    ) -> Self {
        Self {
            public_data_plane: public_data_plane.clone(),
            cache_key,
            epoch,
            rows,
            authority,
        }
    }

    pub(super) fn is_current(&self, outer_transaction_hash: FixedBytes<32>) -> bool {
        self.public_data_plane.current_epoch() == self.epoch
            && self
                .public_data_plane
                .txid_transactions_for_outer_hash_with_authority(
                    &self.cache_key,
                    outer_transaction_hash,
                )
                .is_ok_and(|(rows, authority)| rows == self.rows && authority == self.authority)
            && self.public_data_plane.current_epoch() == self.epoch
    }

    pub(super) async fn acquire_commit_guard(&self) -> ChainPublicDataPlaneCommitGuard {
        self.public_data_plane.acquire_commit_guard().await
    }
}

#[derive(Clone)]
pub(super) struct QualifiedSenderTransaction {
    txid_index: u64,
    public_row: PublicTxidTransaction,
    output_start_global: u128,
    outputs: Vec<Utxo>,
    output_notes: Vec<Note>,
}

pub(super) async fn materialize_sender_transaction_candidates(
    request: SenderCandidateRecoveryRequest<'_>,
) -> SenderCandidateRecoveryReport {
    let SenderCandidateRecoveryRequest {
        output_recovery,
        candidates,
        unshield_attempts,
    } = request;
    let output_request = &output_recovery;
    let report = SenderCandidateRecoveryReport {
        expected_candidates: candidates
            .iter()
            .filter_map(|candidate| {
                candidate
                    .encode()
                    .ok()
                    .map(|encoded| (candidate.semantic_id(), encoded))
            })
            .collect(),
        ..SenderCandidateRecoveryReport::default()
    };
    let live_unshields = candidates
        .iter()
        .flat_map(sender_candidate_unshield_txids)
        .collect::<BTreeSet<_>>();
    if candidates.is_empty() {
        unshield_attempts.retain(&live_unshields);
        return report;
    }
    debug!(
        chain_id = output_request.cfg.chain.chain_id,
        candidates = candidates.len(),
        force_retry = output_request.force_retry,
        "sender candidate recovery scan started"
    );
    let cache_key = PublicTxidCacheKey::new(
        ChainScope {
            chain_type: ChainType::Evm,
            chain_id: output_request.cfg.chain.chain_id,
            railgun_contract: output_request.cfg.chain.contract,
        },
        DEFAULT_TXID_VERSION,
    );
    // Built on first qualification: candidates still awaiting public data need no nullifiers.
    let wallet_nullifier_index = OnceLock::new();
    // Weighted by unshield count, so that with the per-candidate shuffle the
    // first unshield tried is uniform over every candidate's unshields.
    let candidates = output_request
        .private_poi
        .submission_order(candidates, |candidate| {
            sender_candidate_unshield_txids(candidate).len()
        });
    let mut scan = SenderCandidateScan {
        request: output_request,
        unshield_attempts,
        report,
        live_unshields,
        cache_key,
        public_txid_cache_refreshed: None,
        wallet_nullifier_index: &wallet_nullifier_index,
    };
    for candidate in candidates {
        scan.recover(candidate).await;
    }
    scan.finish()
}

/// One sender candidate recovery scan: the request, the report it builds and the caches its
/// candidates share.
struct SenderCandidateScan<'r, 'a> {
    request: &'r OutputPoiRecoveryRequest<'a>,
    unshield_attempts: &'r SenderUnshieldAttempts,
    report: SenderCandidateRecoveryReport,
    live_unshields: BTreeSet<FixedBytes<32>>,
    cache_key: PublicTxidCacheKey,
    public_txid_cache_refreshed: Option<bool>,
    /// Held by reference so candidate work can keep the index across scan mutations.
    wallet_nullifier_index: &'r OnceLock<WalletNullifierIndex<'a>>,
}

/// A qualified candidate's public data and unshield state, shared by its recovery paths.
struct QualifiedSenderRecovery<'w> {
    candidate_id: FixedBytes<32>,
    output_count: u64,
    qualified: &'w [QualifiedSenderTransaction],
    public_data_fence: &'w SenderCandidatePublicDataFence,
    data_epoch: PublicDataPlaneEpoch,
    proof_source_resolution: &'w OutputPoiProofSourceResolution,
    wallet_nullifiers: &'w WalletNullifierIndex<'w>,
    stored_unshields: BTreeSet<FixedBytes<32>>,
    eligible: BTreeSet<FixedBytes<32>>,
    valid: Option<BTreeSet<FixedBytes<32>>>,
    /// Unshield TXIDs a replacement candidate keeps.
    unresolved: BTreeSet<FixedBytes<32>>,
}

impl<'w> QualifiedSenderRecovery<'w> {
    fn into_unshield_inputs(
        self,
        candidate: SenderTransactionCandidate,
        cached_proofs: BTreeMap<FixedBytes<32>, (u64, PreTransactionPoiMap)>,
    ) -> SenderUnshieldInputs<'w> {
        SenderUnshieldInputs {
            candidate,
            eligible: self.eligible,
            valid: self.valid,
            qualified: self.qualified,
            wallet_nullifiers: self.wallet_nullifiers,
            public_data_fence: self.public_data_fence,
            proof_source_resolution: self.proof_source_resolution,
            cached_proofs,
        }
    }
}

impl<'r, 'a> SenderCandidateScan<'r, 'a> {
    fn wallet_nullifiers(&self) -> &'r WalletNullifierIndex<'a> {
        let request = self.request;
        let index: &'r OnceLock<_> = self.wallet_nullifier_index;
        index
            .get_or_init(|| WalletNullifierIndex::new(request.wallet_utxos, &request.cfg.scan_keys))
    }

    /// Qualify one candidate and run the recovery path its state selects.
    async fn recover(&mut self, candidate: SenderTransactionCandidate) {
        // Outputs already belong to pending-output maintenance; only unshield work remains.
        let handed_off = candidate
            .unshield
            .as_ref()
            .is_some_and(|unshield| unshield.outputs_handed_off);
        let pending_count = if handed_off {
            u64::try_from(sender_candidate_unshield_txids(&candidate).len()).unwrap_or(u64::MAX)
        } else {
            sender_candidate_output_count(&candidate)
        };
        let coverage = if handed_off {
            None
        } else {
            sender_candidate_coverage(self.request, &candidate).await
        };
        let Some((proof_source_resolution, qualified)) = self
            .qualify_or_wait(&candidate, coverage, pending_count)
            .await
        else {
            return;
        };
        let work = self
            .qualified_recovery(&candidate, &proof_source_resolution, &qualified)
            .await;
        if handed_off {
            self.process_unshields(work.into_unshield_inputs(candidate, BTreeMap::new()))
                .await;
        } else {
            self.recover_owned_outputs(candidate, coverage, work).await;
        }
    }

    /// Resolve the proof source and qualify the candidate from public rows. A candidate that
    /// cannot qualify yet is counted as covered or waiting.
    async fn qualify_or_wait(
        &mut self,
        candidate: &SenderTransactionCandidate,
        coverage: Option<SenderCandidateCoverage>,
        pending_count: u64,
    ) -> Option<(OutputPoiProofSourceResolution, QualifiedSenderCandidate)> {
        let request = self.request;
        if request.active_list_keys.is_empty() {
            self.record_coverage_or(coverage, |report| {
                report.awaiting_poi_data = report.awaiting_poi_data.saturating_add(pending_count);
            });
            return None;
        }
        let proof_source_resolution = request.resolve_proof_source(request.active_list_keys).await;
        if matches!(
            &proof_source_resolution,
            OutputPoiProofSourceResolution::Unavailable
        ) {
            self.record_coverage_or(coverage, |report| {
                log_local_poi_cache_unavailable(request.cfg, "sender_candidate_recovery");
                report.awaiting_poi_data = report.awaiting_poi_data.saturating_add(pending_count);
            });
            return None;
        }
        match qualify_sender_candidate_from_public_rows(
            request,
            candidate,
            &self.cache_key,
            &mut self.public_txid_cache_refreshed,
        )
        .await
        {
            Ok(qualified) => Some((proof_source_resolution, qualified)),
            Err(pending) => {
                self.record_coverage_or(coverage, |report| pending.record(report, pending_count));
                None
            }
        }
    }

    /// Count a covered candidate, or let `uncovered` count one that is still waiting.
    fn record_coverage_or(
        &mut self,
        coverage: Option<SenderCandidateCoverage>,
        uncovered: impl FnOnce(&mut SenderCandidateRecoveryReport),
    ) {
        if let Some(coverage) = coverage {
            record_covered_sender_candidate(&mut self.report, self.request.cfg, coverage);
        } else {
            uncovered(&mut self.report);
        }
    }

    /// The qualified candidate's unshield eligibility, with the inputs its recovery paths share.
    async fn qualified_recovery<'w>(
        &self,
        candidate: &SenderTransactionCandidate,
        proof_source_resolution: &'w OutputPoiProofSourceResolution,
        qualified: &'w QualifiedSenderCandidate,
    ) -> QualifiedSenderRecovery<'w>
    where
        'r: 'w,
    {
        let request = self.request;
        let wallet_nullifiers = self.wallet_nullifiers();
        let corpus_blocked = corpus_shield_blocked_unshield_inputs(
            request,
            proof_source_resolution,
            &qualified.qualified,
            wallet_nullifiers,
        )
        .await;
        let eligible = eligible_sender_unshield_txids(
            &qualified.qualified,
            wallet_nullifiers,
            request.active_list_keys,
            &corpus_blocked,
        );
        let valid = sender_unshield_valid_txids(request, proof_source_resolution, &eligible).await;
        let stored_unshields = sender_candidate_unshield_txids(candidate);
        let unresolved =
            unresolved_sender_unshield_txids(&eligible, &stored_unshields, valid.as_ref());
        QualifiedSenderRecovery {
            candidate_id: candidate.semantic_id(),
            output_count: sender_candidate_output_count(candidate),
            qualified: &qualified.qualified,
            public_data_fence: &qualified.public_data_fence,
            data_epoch: qualified.data_epoch,
            proof_source_resolution,
            wallet_nullifiers,
            stored_unshields,
            eligible,
            valid,
            unresolved,
        }
    }

    /// Recover a candidate that still owns its outputs: skip a covered one, otherwise retire,
    /// update or materialize it.
    async fn recover_owned_outputs(
        &mut self,
        candidate: SenderTransactionCandidate,
        coverage: Option<SenderCandidateCoverage>,
        work: QualifiedSenderRecovery<'_>,
    ) {
        if let Some(coverage) = coverage {
            record_covered_sender_candidate(&mut self.report, self.request.cfg, coverage);
            if !work.eligible.is_empty() || !work.stored_unshields.is_empty() {
                self.process_unshields(work.into_unshield_inputs(candidate, BTreeMap::new()))
                    .await;
            }
        } else if let Some(corpus) = locally_valid_sender_candidate(self.request, &candidate).await
        {
            self.retire_locally_valid(candidate, corpus, work).await;
        } else if work
            .qualified
            .iter()
            .all(|transaction| transaction.outputs.is_empty())
        {
            self.update_unshield_only(candidate, work).await;
        } else {
            self.materialize(candidate, work).await;
        }
    }

    /// Retire a candidate whose outputs are already Valid locally; a replacement keeps its
    /// unresolved unshield work.
    async fn retire_locally_valid(
        &mut self,
        candidate: SenderTransactionCandidate,
        corpus: PublicPoiCorpusHandle,
        work: QualifiedSenderRecovery<'_>,
    ) {
        // Retiring needs proof that no eligible unshield is unresolved.
        if !work.eligible.is_empty() && work.valid.is_none() {
            self.report.retrying = self.report.retrying.saturating_add(1);
            return;
        }
        let Ok(replacement) = sender_candidate_with_unshield_work(&candidate, &work.unresolved)
        else {
            self.report.needs_attention = self
                .report
                .needs_attention
                .saturating_add(work.output_count);
            return;
        };
        let apply_result = self
            .apply_delta(OwnedPoiPrivateDelta::SenderCandidateLocallyValid(
                SenderCandidateLocallyValidDelta {
                    expected_candidate: candidate,
                    corpus,
                    public_data_fence: work.public_data_fence.clone(),
                    unshield: replacement
                        .as_ref()
                        .and_then(|replacement| replacement.unshield.clone()),
                },
            ))
            .await;
        match apply_result {
            Ok(PoiPrivateApplyOutcome::Applied { .. }) => {
                if replacement.is_none() {
                    self.report.retired_locally_valid =
                        self.report.retired_locally_valid.saturating_add(1);
                }
                self.finish_applied(replacement, work, BTreeMap::new())
                    .await;
            }
            Ok(
                PoiPrivateApplyOutcome::Skipped
                | PoiPrivateApplyOutcome::SkippedStaleCorpusRevision,
            ) => {}
            Err(_) => {
                self.report.needs_attention = self
                    .report
                    .needs_attention
                    .saturating_add(work.output_count);
            }
        }
    }

    /// Update a candidate whose qualified transactions have no outputs left, so only its
    /// unshield work remains.
    async fn update_unshield_only(
        &mut self,
        candidate: SenderTransactionCandidate,
        work: QualifiedSenderRecovery<'_>,
    ) {
        let eligible_count = u64::try_from(work.eligible.len()).unwrap_or(u64::MAX);
        if !work.eligible.is_empty() && work.valid.is_none() {
            self.report.retrying = self.report.retrying.saturating_add(eligible_count);
            return;
        }
        // No replacement retires the candidate: a blocked refund or an already-valid unshield.
        let Ok(replacement) = sender_candidate_with_unshield_work(&candidate, &work.unresolved)
        else {
            self.report.needs_attention = self
                .report
                .needs_attention
                .saturating_add(work.output_count);
            return;
        };
        let apply_result = self
            .apply_delta(OwnedPoiPrivateDelta::SenderCandidateUnshieldUpdate(
                SenderCandidateUnshieldUpdateDelta {
                    expected_candidate: candidate,
                    public_data_fence: work.public_data_fence.clone(),
                    replacement: replacement.clone(),
                },
            ))
            .await;
        match apply_result {
            Ok(PoiPrivateApplyOutcome::Applied { .. }) => {
                self.finish_applied(replacement, work, BTreeMap::new())
                    .await;
            }
            Ok(
                PoiPrivateApplyOutcome::Skipped
                | PoiPrivateApplyOutcome::SkippedStaleCorpusRevision,
            ) => {}
            Err(_) => {
                self.report.needs_attention = self
                    .report
                    .needs_attention
                    .saturating_add(eligible_count.max(1));
            }
        }
    }

    /// Prove and persist the candidate's outputs, then continue any replacement's unshield work.
    async fn materialize(
        &mut self,
        candidate: SenderTransactionCandidate,
        work: QualifiedSenderRecovery<'_>,
    ) {
        let Some((replacement, prepared)) = self.prepare_materialization(&candidate, &work).await
        else {
            return;
        };
        if !self.still_current(&candidate, work.data_epoch).await {
            return;
        }
        let PreparedSenderCandidateMaterialization {
            pending_updates,
            recovery_updates,
            owned_substitutes,
            proof_outputs,
            expected_corpus,
            replacement_group,
            external_valid_substitutes,
            unshield_proofs,
        } = prepared;
        let satisfied_pending_contexts = replacement_group
            .iter()
            .map(|(context, _)| context.output_commitment)
            .collect::<Vec<_>>();
        let apply_result = self
            .apply_delta(OwnedPoiPrivateDelta::SenderCandidateMaterialization(
                SenderCandidateMaterializationDelta {
                    expected_candidate: candidate,
                    public_data_fence: work.public_data_fence.clone(),
                    active_list_keys: self.request.active_list_keys.to_vec(),
                    pending_updates,
                    recovery_updates,
                    owned_substitutes,
                    proof_outputs,
                    expected_corpus,
                    replacement_group,
                    external_valid_substitutes,
                    unshield: replacement
                        .as_ref()
                        .and_then(|replacement| replacement.unshield.clone()),
                },
            ))
            .await;
        match apply_result {
            Ok(PoiPrivateApplyOutcome::Applied { .. }) => {
                self.report.materialized = self.report.materialized.saturating_add(1);
                self.report
                    .satisfied_pending_contexts
                    .extend(satisfied_pending_contexts);
                self.finish_applied(replacement, work, unshield_proofs)
                    .await;
            }
            Ok(PoiPrivateApplyOutcome::SkippedStaleCorpusRevision) => {
                self.report.stale_revision_skips =
                    self.report.stale_revision_skips.saturating_add(1);
                self.report.retrying = self.report.retrying.saturating_add(work.output_count);
            }
            Ok(PoiPrivateApplyOutcome::Skipped) => {}
            Err(_) => {
                self.report.needs_attention = self
                    .report
                    .needs_attention
                    .saturating_add(work.output_count);
            }
        }
    }

    /// The replacement candidate and the prepared materialization, or `None` after counting a
    /// candidate that cannot be prepared now.
    async fn prepare_materialization(
        &mut self,
        candidate: &SenderTransactionCandidate,
        work: &QualifiedSenderRecovery<'_>,
    ) -> Option<(
        Option<SenderTransactionCandidate>,
        PreparedSenderCandidateMaterialization,
    )> {
        let request = self.request;
        let Some(spending_public_key) = request.cfg.spending_public_key else {
            self.report.retrying = self.report.retrying.saturating_add(work.output_count);
            return None;
        };
        let Some(prover) = request.cfg.poi_recovery_prover.as_ref() else {
            self.report.retrying = self.report.retrying.saturating_add(work.output_count);
            return None;
        };
        let Ok(replacement) = sender_candidate_with_unshield_work(candidate, &work.unresolved)
        else {
            self.report.needs_attention = self
                .report
                .needs_attention
                .saturating_add(work.output_count);
            return None;
        };
        let candidate_prover = SenderCandidateProver {
            request,
            candidate,
            wallet_nullifiers: work.wallet_nullifiers,
            spending_public_key,
            prover,
            proof_source_resolution: work.proof_source_resolution,
        };
        match candidate_prover
            .prepare_materialization(work.qualified, &work.unresolved)
            .await
        {
            Ok(Some(prepared)) => Some((replacement, prepared)),
            Ok(None) => None,
            Err(failure) => {
                warn!(
                    chain_id = request.cfg.chain.chain_id,
                    status = ?failure.status,
                    retryable = failure.retry_after.is_some(),
                    failure_category = failure.category,
                    "sender candidate recovery preparation failed"
                );
                if failure.retry_after.is_some() {
                    self.report.retrying = self.report.retrying.saturating_add(work.output_count);
                } else {
                    self.report.needs_attention = self
                        .report
                        .needs_attention
                        .saturating_add(work.output_count);
                }
                None
            }
        }
    }

    /// Whether the public data and the stored candidate are still the ones preparation used.
    async fn still_current(
        &self,
        candidate: &SenderTransactionCandidate,
        data_epoch: PublicDataPlaneEpoch,
    ) -> bool {
        let request = self.request;
        request.public_data_plane.current_epoch() == data_epoch
            && sender_candidate_still_current(
                request.authority,
                request.cache_store,
                request.cfg,
                candidate,
            )
            .await
    }

    async fn apply_delta(
        &self,
        delta: OwnedPoiPrivateDelta,
    ) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
        let request = self.request;
        apply_poi_private_delta(
            request.authority,
            request.db,
            request.cache_store,
            request.cfg,
            delta,
        )
        .await
    }

    async fn process_unshields(&mut self, inputs: SenderUnshieldInputs<'_>) {
        process_sender_candidate_unshields(
            self.request,
            &mut self.report,
            self.unshield_attempts,
            &mut self.live_unshields,
            inputs,
        )
        .await;
    }

    /// After an applied update, track the replacement and continue its unshield work, or drop
    /// the retired candidate from the expected set.
    async fn finish_applied(
        &mut self,
        replacement: Option<SenderTransactionCandidate>,
        work: QualifiedSenderRecovery<'_>,
        cached_proofs: BTreeMap<FixedBytes<32>, (u64, PreTransactionPoiMap)>,
    ) {
        if let Some(replacement) = replacement {
            track_sender_candidate(&mut self.report, &replacement);
            self.process_unshields(work.into_unshield_inputs(replacement, cached_proofs))
                .await;
        } else {
            self.report.expected_candidates.remove(&work.candidate_id);
        }
    }

    /// Drop attempts for unshields no candidate still carries, and return the report.
    fn finish(self) -> SenderCandidateRecoveryReport {
        let Self {
            request,
            unshield_attempts,
            report,
            live_unshields,
            ..
        } = self;
        unshield_attempts.retain(&live_unshields);
        debug!(
            chain_id = request.cfg.chain.chain_id,
            materialized = report.materialized,
            retired_locally_valid = report.retired_locally_valid,
            awaiting_public_txid_data = report.awaiting_public_txid_data,
            awaiting_poi_data = report.awaiting_poi_data,
            retrying = report.retrying,
            needs_attention = report.needs_attention,
            covered_by_pending_contexts = report.covered_by_pending_contexts,
            stale_revision_skips = report.stale_revision_skips,
            unshield_awaiting_validation = report.unshield_awaiting_validation,
            unshields_validated = report.unshields_validated,
            expected_candidates = report.expected_candidates.len(),
            "sender candidate recovery scan complete"
        );
        report
    }
}

/// The candidate's output count for report counters, at least one.
fn sender_candidate_output_count(candidate: &SenderTransactionCandidate) -> u64 {
    u64::try_from(candidate.outputs.len())
        .unwrap_or(u64::MAX)
        .max(1)
}

fn record_covered_sender_candidate(
    report: &mut SenderCandidateRecoveryReport,
    cfg: &WalletConfig,
    coverage: SenderCandidateCoverage,
) {
    report.covered_by_pending_contexts = report
        .covered_by_pending_contexts
        .saturating_add(coverage.pending_contexts);
    debug!(
        chain_id = cfg.chain.chain_id,
        covered_by_local_valid = coverage.local_valid,
        covered_by_pending_contexts = coverage.pending_contexts,
        "sender candidate recovery skipped covered candidate"
    );
}

/// Keep the report's expected candidate encoding in step with a durable candidate update.
fn track_sender_candidate(
    report: &mut SenderCandidateRecoveryReport,
    candidate: &SenderTransactionCandidate,
) {
    if let Ok(encoded) = candidate.encode() {
        report
            .expected_candidates
            .insert(candidate.semantic_id(), encoded);
    } else {
        report.expected_candidates.remove(&candidate.semantic_id());
    }
}

pub(super) async fn sender_candidate_still_current(
    authority: &WalletPrivateMutationAuthority<'_>,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    candidate: &SenderTransactionCandidate,
) -> bool {
    if authority.revalidate().is_err()
        || candidate.chain_id != cfg.chain.chain_id
        || candidate.wallet_id != cfg.cache_key
    {
        return false;
    }
    let Ok(snapshot) = authority.wallet_utxos().await else {
        return false;
    };
    if !sender_candidate_matches_wallet_snapshot(candidate, &snapshot) {
        return false;
    }
    let Ok(Some(current)) = cache_store.get_sender_transaction_candidate(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &candidate.semantic_id(),
    ) else {
        return false;
    };
    candidates_match(candidate, &current) && authority.revalidate().is_ok()
}

pub(super) fn sender_candidate_matches_wallet_snapshot(
    candidate: &SenderTransactionCandidate,
    wallet_utxos: &[WalletUtxo],
) -> bool {
    candidate.wallet_spends.iter().all(|spend| {
        let matches = wallet_utxos
            .iter()
            .filter(|wallet_utxo| {
                wallet_utxo.utxo.tree == spend.tree
                    && wallet_utxo.utxo.position == spend.position
                    && wallet_utxo.utxo.poi.commitment == spend.commitment
                    && wallet_utxo.spent.as_ref() == Some(&candidate.source)
            })
            .count();
        matches == 1
    })
}

pub(super) fn candidates_match(
    expected: &SenderTransactionCandidate,
    current: &SenderTransactionCandidate,
) -> bool {
    expected
        .encode()
        .ok()
        .zip(current.encode().ok())
        .is_some_and(|(expected, current)| expected == current)
}

#[cfg(test)]
mod tests;
