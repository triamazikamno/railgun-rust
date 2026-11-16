//! Reconciling, proving and submitting a sender candidate's unshield TXIDs.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::PoisonError;

use crate::SenderTransactionCandidateError;
use crate::wallet::output_poi_recovery::{
    OutputPoiProofSourceResolution, RecoveryFailure, WalletNullifierIndex,
    poi_shield_blocked_on_any_list,
};
use crate::wallet::saved_poi_compatibility::{
    corpus_valid_blinded_commitments, saved_poi_map_is_compatible,
};
use crate::wallet::{
    Arc, BlindedCommitmentData, DEFAULT_TXID_VERSION, Duration, EVM_CHAIN_TYPE, FixedBytes,
    Instant, OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER, OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
    OutputPoiRecoveryRequest, OutputPoiRecoveryStatus, OwnedPoiPrivateDelta,
    PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER, PoiPrivateApplyOutcome, PoiStatus, PoiStatusReader,
    PreTransactionPoiMap, SenderCandidateUnshieldUpdateDelta,
    SenderCandidateUnshieldValidatedDelta, SenderTransactionCandidate,
    SenderTransactionCandidateUnshield, TransactProofRoute, U256, WalletPrivateRemoteError,
    apply_poi_private_delta, blinded_commitment_type, debug, warn,
};

use super::materialization::SenderCandidateProver;
use super::{
    QualifiedSenderTransaction, SenderCandidatePublicDataFence, SenderCandidateRecoveryReport,
    sender_candidate_still_current, track_sender_candidate,
};

/// In-memory unshield submission pacing keyed by Railgun TXID, kept for the actor lifetime.
#[derive(Clone, Default)]
pub(crate) struct SenderUnshieldAttempts(
    Arc<std::sync::Mutex<BTreeMap<FixedBytes<32>, SenderUnshieldAttempt>>>,
);

impl fmt::Debug for SenderUnshieldAttempts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SenderUnshieldAttempts")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
struct SenderUnshieldAttempt {
    next_attempt_at: Instant,
    outcome: SenderUnshieldAttemptOutcome,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SenderUnshieldAttemptOutcome {
    Submitted,
    Retrying,
    NeedsAttention,
}

impl SenderUnshieldAttempts {
    fn waiting(
        &self,
        txid: FixedBytes<32>,
        now: Instant,
        force: bool,
    ) -> Option<SenderUnshieldAttemptOutcome> {
        if force {
            return None;
        }
        let attempts = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        attempts
            .get(&txid)
            .filter(|attempt| now < attempt.next_attempt_at)
            .map(|attempt| attempt.outcome)
    }

    fn record(
        &self,
        txid: FixedBytes<32>,
        outcome: SenderUnshieldAttemptOutcome,
        retry_after: Duration,
    ) {
        let attempt = SenderUnshieldAttempt {
            next_attempt_at: Instant::now() + retry_after,
            outcome,
        };
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(txid, attempt);
    }

    pub(super) fn retain(&self, live: &BTreeSet<FixedBytes<32>>) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|txid, _| live.contains(txid));
    }

    #[cfg(test)]
    pub(in crate::wallet) fn expire_all(&self) {
        let now = Instant::now();
        for attempt in self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values_mut()
        {
            attempt.next_attempt_at = now;
        }
    }
}

pub(super) fn sender_candidate_unshield_txids(
    candidate: &SenderTransactionCandidate,
) -> BTreeSet<FixedBytes<32>> {
    candidate
        .unshield
        .iter()
        .flat_map(|unshield| unshield.railgun_txids.iter().copied())
        .collect()
}

/// The candidate with only its unshield work left after its outputs are handed off, or `None`
/// when no unshield work remains.
pub(super) fn sender_candidate_with_unshield_work(
    candidate: &SenderTransactionCandidate,
    work: &BTreeSet<FixedBytes<32>>,
) -> Result<Option<SenderTransactionCandidate>, SenderTransactionCandidateError> {
    sender_candidate_with_remaining_unshield(candidate, work.iter().copied().collect(), true)
}

/// The candidate left after completing `validated` unshield TXIDs, or `None` when it retires.
pub(in crate::wallet) fn sender_candidate_after_unshield_validation(
    candidate: &SenderTransactionCandidate,
    unshield: &SenderTransactionCandidateUnshield,
    validated: &BTreeSet<FixedBytes<32>>,
) -> Result<Option<SenderTransactionCandidate>, SenderTransactionCandidateError> {
    let remaining = unshield
        .railgun_txids
        .iter()
        .copied()
        .filter(|txid| !validated.contains(txid))
        .collect();
    sender_candidate_with_remaining_unshield(candidate, remaining, unshield.outputs_handed_off)
}

/// The candidate keeping only `remaining` unshield TXIDs, or `None` when it retires because no
/// TXID remains and its outputs are handed off.
fn sender_candidate_with_remaining_unshield(
    candidate: &SenderTransactionCandidate,
    remaining: Vec<FixedBytes<32>>,
    outputs_handed_off: bool,
) -> Result<Option<SenderTransactionCandidate>, SenderTransactionCandidateError> {
    if remaining.is_empty() && outputs_handed_off {
        return Ok(None);
    }
    candidate
        .clone()
        .with_unshield(
            (!remaining.is_empty()).then_some(SenderTransactionCandidateUnshield {
                railgun_txids: remaining,
                outputs_handed_off,
            }),
        )
        .map(Some)
}

/// Eligible unshield TXIDs still to resolve: those already recorded plus those not Valid.
/// Unknown statuses (`valid` is `None`) keep every eligible TXID.
pub(super) fn unresolved_sender_unshield_txids(
    eligible: &BTreeSet<FixedBytes<32>>,
    stored: &BTreeSet<FixedBytes<32>>,
    valid: Option<&BTreeSet<FixedBytes<32>>>,
) -> BTreeSet<FixedBytes<32>> {
    eligible
        .iter()
        .copied()
        .filter(|txid| stored.contains(txid) || valid.is_none_or(|valid| !valid.contains(txid)))
        .collect()
}

pub(super) fn sender_unshield_railgun_txid(
    transaction: &QualifiedSenderTransaction,
) -> FixedBytes<32> {
    let transaction = &transaction.public_row.transaction;
    FixedBytes::from(
        broadcaster_core::transact::compute_railgun_txid_parts(
            &transaction.nullifiers,
            &transaction.commitments,
            transaction.bound_params_hash,
        )
        .to_be_bytes::<32>(),
    )
}

/// Railgun TXIDs of qualified inner unshields whose POI proof can be built.
///
/// A shield-blocked wallet input makes no proof possible; this is not a refund-authorization
/// decision. Qualification already resolved each row input to the unique wallet UTXO spent by
/// the row's transaction, so the nullifier index finds exactly those inputs. An input is blocked
/// when its stored statuses say so or its blinded commitment is in `corpus_blocked`.
pub(super) fn eligible_sender_unshield_txids(
    qualified: &[QualifiedSenderTransaction],
    wallet_nullifiers: &WalletNullifierIndex<'_>,
    active_list_keys: &[FixedBytes<32>],
    corpus_blocked: &BTreeSet<FixedBytes<32>>,
) -> BTreeSet<FixedBytes<32>> {
    qualified
        .iter()
        .filter(|transaction| {
            let row = &transaction.public_row.transaction;
            row.has_unshield
                && !row.nullifiers.iter().any(|nullifier| {
                    u32::try_from(row.utxo_tree_in)
                        .ok()
                        .and_then(|input_tree| {
                            wallet_nullifiers.input_for(
                                input_tree,
                                *nullifier,
                                row.transaction_hash,
                            )
                        })
                        .is_some_and(|wallet_utxo| {
                            poi_shield_blocked_on_any_list(&wallet_utxo.utxo.poi, active_list_keys)
                                || corpus_blocked.contains(&wallet_utxo.utxo.poi.blinded_commitment)
                        })
                })
        })
        .map(sender_unshield_railgun_txid)
        .collect()
}

/// Blinded commitments of qualified unshield inputs the local corpus marks Shield-blocked on an
/// active list. Stored statuses of spent inputs are never refreshed, so they can miss the block.
/// Empty when the corpus is not local or the read fails.
pub(super) async fn corpus_shield_blocked_unshield_inputs(
    request: &OutputPoiRecoveryRequest<'_>,
    proof_source_resolution: &OutputPoiProofSourceResolution,
    qualified: &[QualifiedSenderTransaction],
    wallet_nullifiers: &WalletNullifierIndex<'_>,
) -> BTreeSet<FixedBytes<32>> {
    let OutputPoiProofSourceResolution::Local { corpus, .. } = proof_source_resolution else {
        return BTreeSet::new();
    };
    let datas = qualified
        .iter()
        .map(|transaction| &transaction.public_row.transaction)
        .filter(|row| row.has_unshield)
        .flat_map(|row| {
            row.nullifiers.iter().filter_map(move |nullifier| {
                let input_tree = u32::try_from(row.utxo_tree_in).ok()?;
                wallet_nullifiers.input_for(input_tree, *nullifier, row.transaction_hash)
            })
        })
        .map(|wallet_utxo| {
            BlindedCommitmentData::new(
                wallet_utxo.utxo.poi.blinded_commitment,
                blinded_commitment_type(wallet_utxo.utxo.poi.commitment_kind),
            )
        })
        .collect::<Vec<_>>();
    if datas.is_empty() {
        return BTreeSet::new();
    }
    let _revision_fence = corpus.revision_read_fence().await;
    let Ok(statuses) = corpus
        .status_reader()
        .pois_per_list(
            DEFAULT_TXID_VERSION,
            EVM_CHAIN_TYPE,
            request.cfg.chain.chain_id,
            request.active_list_keys,
            &datas,
        )
        .await
    else {
        return BTreeSet::new();
    };
    statuses
        .into_iter()
        .filter(|(_, per_list)| {
            per_list
                .values()
                .any(|status| *status == PoiStatus::ShieldBlocked)
        })
        .map(|(blinded_commitment, _)| blinded_commitment)
        .collect()
}

/// Unshield TXIDs Valid on every active list in the local corpus; `None` when the read failed.
pub(in crate::wallet) async fn sender_unshield_valid_txids(
    request: &OutputPoiRecoveryRequest<'_>,
    proof_source_resolution: &OutputPoiProofSourceResolution,
    txids: &BTreeSet<FixedBytes<32>>,
) -> Option<BTreeSet<FixedBytes<32>>> {
    if txids.is_empty() {
        return Some(BTreeSet::new());
    }
    let OutputPoiProofSourceResolution::Local { corpus, .. } = proof_source_resolution else {
        return None;
    };
    let datas = txids
        .iter()
        .map(|txid| BlindedCommitmentData::unshield(*txid))
        .collect::<Vec<_>>();
    let _revision_fence = corpus.revision_read_fence().await;
    corpus_valid_blinded_commitments(
        corpus,
        request.cfg.chain.chain_id,
        request.active_list_keys,
        &datas,
    )
    .await
    .ok()
}

pub(in crate::wallet) struct SenderUnshieldInputs<'a> {
    pub(in crate::wallet) candidate: SenderTransactionCandidate,
    /// Eligible unshield TXIDs of the qualified rows.
    pub(in crate::wallet) eligible: BTreeSet<FixedBytes<32>>,
    /// Eligible TXIDs already Valid locally; `None` when the status read failed.
    pub(in crate::wallet) valid: Option<BTreeSet<FixedBytes<32>>>,
    pub(in crate::wallet) qualified: &'a [QualifiedSenderTransaction],
    /// Spent wallet UTXOs of this pass, indexed by input tree and nullifier.
    pub(in crate::wallet) wallet_nullifiers: &'a WalletNullifierIndex<'a>,
    pub(in crate::wallet) public_data_fence: &'a SenderCandidatePublicDataFence,
    pub(in crate::wallet) proof_source_resolution: &'a OutputPoiProofSourceResolution,
    /// Proofs built during materialization, keyed by TXID, with their TXID merkleroot index.
    pub(in crate::wallet) cached_proofs: BTreeMap<FixedBytes<32>, (u64, PreTransactionPoiMap)>,
}

/// Reconcile, complete, and submit a candidate's unshield work.
///
/// A submission acknowledgement never completes anything; only a later local Valid read does.
pub(in crate::wallet) async fn process_sender_candidate_unshields(
    request: &OutputPoiRecoveryRequest<'_>,
    report: &mut SenderCandidateRecoveryReport,
    attempts: &SenderUnshieldAttempts,
    live: &mut BTreeSet<FixedBytes<32>>,
    inputs: SenderUnshieldInputs<'_>,
) {
    let SenderUnshieldInputs {
        candidate,
        eligible,
        valid,
        qualified,
        wallet_nullifiers,
        public_data_fence,
        proof_source_resolution,
        mut cached_proofs,
    } = inputs;
    let stored = sender_candidate_unshield_txids(&candidate);
    let Some(valid) = valid else {
        let unknown = eligible.union(&stored).count();
        report.retrying = report
            .retrying
            .saturating_add(u64::try_from(unknown).unwrap_or(u64::MAX));
        return;
    };
    let target = unresolved_sender_unshield_txids(&eligible, &stored, Some(&valid));
    live.extend(target.iter().copied());
    let mut run = SenderUnshieldRun {
        request,
        report,
        attempts,
        qualified,
        wallet_nullifiers,
        public_data_fence,
        proof_source_resolution,
        candidate_id: candidate.semantic_id(),
        eligible_count: u64::try_from(eligible.len()).unwrap_or(u64::MAX),
        submitted: 0,
        waiting: 0,
    };
    let Some(candidate) = run.reconcile(candidate, &stored, &target).await else {
        return;
    };
    let completed = target
        .intersection(&valid)
        .copied()
        .collect::<BTreeSet<_>>();
    let Some(candidate) = run.complete(candidate, &completed).await else {
        return;
    };
    let unresolved = request.private_poi.submission_order(
        target.difference(&valid).copied().collect::<Vec<_>>(),
        |_| 1,
    );
    for txid in unresolved {
        run.submit(&candidate, &mut cached_proofs, txid).await;
    }
    debug!(
        chain_id = request.cfg.chain.chain_id,
        eligible = eligible.len(),
        unresolved = target.len(),
        validated = completed.len(),
        submitted = run.submitted,
        waiting = run.waiting,
        "sender candidate unshield work processed"
    );
}

fn record_sender_unshield_failure(
    report: &mut SenderCandidateRecoveryReport,
    attempts: &SenderUnshieldAttempts,
    txid: FixedBytes<32>,
    failure: &RecoveryFailure,
) {
    warn!(
        status = ?failure.status,
        retryable = failure.retry_after.is_some(),
        failure_category = failure.category,
        "sender candidate unshield proof submission failed"
    );
    if let Some(retry_after) = failure.retry_after {
        attempts.record(txid, SenderUnshieldAttemptOutcome::Retrying, retry_after);
        report.retrying = report.retrying.saturating_add(1);
    } else {
        attempts.record(
            txid,
            SenderUnshieldAttemptOutcome::NeedsAttention,
            OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
        );
        report.needs_attention = report.needs_attention.saturating_add(1);
    }
}

/// One candidate's unshield work: its shared inputs and the report it counts into.
struct SenderUnshieldRun<'r> {
    request: &'r OutputPoiRecoveryRequest<'r>,
    report: &'r mut SenderCandidateRecoveryReport,
    attempts: &'r SenderUnshieldAttempts,
    qualified: &'r [QualifiedSenderTransaction],
    wallet_nullifiers: &'r WalletNullifierIndex<'r>,
    public_data_fence: &'r SenderCandidatePublicDataFence,
    proof_source_resolution: &'r OutputPoiProofSourceResolution,
    /// The original candidate's id, which both retirement paths remove.
    candidate_id: FixedBytes<32>,
    eligible_count: u64,
    /// TXIDs submitted in this run.
    submitted: u64,
    /// TXIDs skipped because an earlier attempt still paces them.
    waiting: u64,
}

/// Where the proof of an unresolved unshield TXID comes from.
enum SenderUnshieldProofSource<'r> {
    /// Built during materialization, with its TXID merkleroot index.
    Cached((u64, PreTransactionPoiMap)),
    /// What proving the TXID needs.
    Prove {
        spending_public_key: [U256; 2],
        prover: &'r railgun_wallet::prover::ProverService,
        transaction: &'r QualifiedSenderTransaction,
    },
}

impl<'r> SenderUnshieldRun<'r> {
    /// Rewrites the stored unshield TXIDs to `target`. Returns the candidate to continue with, or
    /// `None` when the work stops.
    async fn reconcile(
        &mut self,
        candidate: SenderTransactionCandidate,
        stored: &BTreeSet<FixedBytes<32>>,
        target: &BTreeSet<FixedBytes<32>>,
    ) -> Option<SenderTransactionCandidate> {
        if target == stored {
            return Some(candidate);
        }
        let outputs_handed_off = candidate
            .unshield
            .as_ref()
            .is_some_and(|unshield| unshield.outputs_handed_off);
        let Ok(replacement) = sender_candidate_with_remaining_unshield(
            &candidate,
            target.iter().copied().collect(),
            outputs_handed_off,
        ) else {
            self.report.needs_attention = self
                .report
                .needs_attention
                .saturating_add(self.eligible_count);
            return None;
        };
        let delta = OwnedPoiPrivateDelta::SenderCandidateUnshieldUpdate(
            SenderCandidateUnshieldUpdateDelta {
                expected_candidate: candidate,
                public_data_fence: self.public_data_fence.clone(),
                replacement: replacement.clone(),
            },
        );
        self.apply_update(delta, replacement, 0).await
    }

    /// Completes the `completed` unshield TXIDs, which are Valid locally. Returns the candidate to
    /// continue with, or `None` when the work stops.
    async fn complete(
        &mut self,
        candidate: SenderTransactionCandidate,
        completed: &BTreeSet<FixedBytes<32>>,
    ) -> Option<SenderTransactionCandidate> {
        if completed.is_empty() {
            return Some(candidate);
        }
        // `valid` is nonempty only after a read from this local corpus.
        let OutputPoiProofSourceResolution::Local { corpus, .. } = self.proof_source_resolution
        else {
            return None;
        };
        let unshield = candidate.unshield.as_ref()?;
        let Ok(next) = sender_candidate_after_unshield_validation(&candidate, unshield, completed)
        else {
            self.report.needs_attention = self
                .report
                .needs_attention
                .saturating_add(self.eligible_count);
            return None;
        };
        let delta = OwnedPoiPrivateDelta::SenderCandidateUnshieldValidated(
            SenderCandidateUnshieldValidatedDelta {
                expected_candidate: candidate,
                validated_txids: completed.iter().copied().collect(),
                corpus: corpus.clone(),
            },
        );
        self.apply_update(delta, next, completed.len()).await
    }

    /// Applies a candidate update and adds `validated` to the report once it applies. Returns the
    /// candidate to continue with, or `None` when the update is skipped or fails or the candidate
    /// retires.
    async fn apply_update(
        &mut self,
        delta: OwnedPoiPrivateDelta,
        next: Option<SenderTransactionCandidate>,
        validated: usize,
    ) -> Option<SenderTransactionCandidate> {
        match apply_poi_private_delta(
            self.request.authority,
            self.request.db,
            self.request.cache_store,
            self.request.cfg,
            delta,
        )
        .await
        {
            Ok(PoiPrivateApplyOutcome::Applied { .. }) => {
                self.report.unshields_validated =
                    self.report.unshields_validated.saturating_add(validated);
            }
            Ok(
                PoiPrivateApplyOutcome::Skipped
                | PoiPrivateApplyOutcome::SkippedStaleCorpusRevision,
            ) => return None,
            Err(_) => {
                self.report.needs_attention = self
                    .report
                    .needs_attention
                    .saturating_add(self.eligible_count);
                return None;
            }
        }
        let Some(next) = next else {
            self.report.expected_candidates.remove(&self.candidate_id);
            return None;
        };
        track_sender_candidate(self.report, &next);
        Some(next)
    }

    /// Proves and submits one unresolved unshield TXID, unless an earlier attempt still paces it.
    async fn submit(
        &mut self,
        candidate: &SenderTransactionCandidate,
        cached_proofs: &mut BTreeMap<FixedBytes<32>, (u64, PreTransactionPoiMap)>,
        txid: FixedBytes<32>,
    ) {
        if self.attempt_waiting(txid) {
            return;
        }
        let Some(source) = self.proof_source(cached_proofs, txid) else {
            return;
        };
        // Reserve before proving, so that a deferral wastes no proof.
        let route = match self
            .request
            .private_poi
            .reserve_transact_route(
                self.request.cfg.chain.chain_id,
                U256::from_be_bytes(txid.0),
                None,
            )
            .await
        {
            Ok(route) => route,
            Err(deferred) => {
                self.attempts.record(
                    txid,
                    SenderUnshieldAttemptOutcome::Retrying,
                    deferred.retry_after(),
                );
                self.report.retrying = self.report.retrying.saturating_add(1);
                return;
            }
        };
        let Some(proof) = self.proof(candidate, txid, source).await else {
            return;
        };
        match self.submit_pois(&route, candidate, &proof).await {
            Ok(true) => {
                self.attempts.record(
                    txid,
                    SenderUnshieldAttemptOutcome::Submitted,
                    PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER,
                );
                self.report.unshield_awaiting_validation =
                    self.report.unshield_awaiting_validation.saturating_add(1);
                self.submitted = self.submitted.saturating_add(1);
            }
            Ok(false) => self.report.retrying = self.report.retrying.saturating_add(1),
            Err(failure) => {
                record_sender_unshield_failure(self.report, self.attempts, txid, &failure);
            }
        }
    }

    /// Counts `txid` by its last outcome and returns `true` when an earlier attempt still paces
    /// it.
    fn attempt_waiting(&mut self, txid: FixedBytes<32>) -> bool {
        let Some(outcome) = self
            .attempts
            .waiting(txid, Instant::now(), self.request.force_retry)
        else {
            return false;
        };
        self.waiting = self.waiting.saturating_add(1);
        match outcome {
            SenderUnshieldAttemptOutcome::Submitted => {
                self.report.unshield_awaiting_validation =
                    self.report.unshield_awaiting_validation.saturating_add(1);
            }
            SenderUnshieldAttemptOutcome::Retrying => {
                self.report.retrying = self.report.retrying.saturating_add(1);
            }
            SenderUnshieldAttemptOutcome::NeedsAttention => {
                self.report.needs_attention = self.report.needs_attention.saturating_add(1);
            }
        }
        true
    }

    /// The cached proof of `txid`, or what proving it needs. `None` after counting a TXID that
    /// cannot be proved yet.
    fn proof_source(
        &mut self,
        cached_proofs: &mut BTreeMap<FixedBytes<32>, (u64, PreTransactionPoiMap)>,
        txid: FixedBytes<32>,
    ) -> Option<SenderUnshieldProofSource<'r>> {
        if let Some(cached) = cached_proofs.remove(&txid) {
            return Some(SenderUnshieldProofSource::Cached(cached));
        }
        let (Some(spending_public_key), Some(prover)) = (
            self.request.cfg.spending_public_key,
            self.request.cfg.poi_recovery_prover.as_ref(),
        ) else {
            self.report.retrying = self.report.retrying.saturating_add(1);
            return None;
        };
        let Some(transaction) = self.qualified.iter().find(|transaction| {
            transaction.public_row.transaction.has_unshield
                && sender_unshield_railgun_txid(transaction) == txid
        }) else {
            self.report.awaiting_public_txid_data =
                self.report.awaiting_public_txid_data.saturating_add(1);
            return None;
        };
        Some(SenderUnshieldProofSource::Prove {
            spending_public_key,
            prover,
            transaction,
        })
    }

    /// The TXID merkleroot index and proofs to submit for `txid`, or `None` when proving went
    /// stale or failed.
    async fn proof(
        &mut self,
        candidate: &SenderTransactionCandidate,
        txid: FixedBytes<32>,
        source: SenderUnshieldProofSource<'_>,
    ) -> Option<(u64, PreTransactionPoiMap)> {
        match source {
            SenderUnshieldProofSource::Cached(cached) => Some(cached),
            SenderUnshieldProofSource::Prove {
                spending_public_key,
                prover,
                transaction,
            } => {
                let candidate_prover = SenderCandidateProver {
                    request: self.request,
                    candidate,
                    wallet_nullifiers: self.wallet_nullifiers,
                    spending_public_key,
                    prover,
                    proof_source_resolution: self.proof_source_resolution,
                };
                match candidate_prover.prove(transaction).await {
                    Ok(Some(proved)) => Some((
                        proved.txid_data.poi_data.txid_merkleroot_index,
                        proved.pre_transaction_pois,
                    )),
                    Ok(None) => None,
                    Err(failure) => {
                        record_sender_unshield_failure(self.report, self.attempts, txid, &failure);
                        None
                    }
                }
            }
        }
    }

    /// Submits the proof of one unshield TXID on every active list. `Ok(false)` when the proofs do
    /// not fit the active lists or the submission went stale.
    async fn submit_pois(
        &self,
        route: &TransactProofRoute,
        candidate: &SenderTransactionCandidate,
        proof: &(u64, PreTransactionPoiMap),
    ) -> Result<bool, RecoveryFailure> {
        let Self {
            request,
            public_data_fence,
            ..
        } = *self;
        let &(txid_merkleroot_index, ref pre_transaction_pois) = proof;
        if !saved_poi_map_is_compatible(pre_transaction_pois, request.active_list_keys) {
            return Ok(false);
        }
        for list_key in request.active_list_keys {
            let Some(per_leaf) = pre_transaction_pois.get(list_key) else {
                return Ok(false);
            };
            for poi in per_leaf.values() {
                match request
                    .private_poi
                    .submit_transact_proof(
                        route,
                        || async {
                            Ok::<bool, std::convert::Infallible>(
                                public_data_fence.is_current(candidate.source.tx_hash)
                                    && sender_candidate_still_current(
                                        request.authority,
                                        request.cache_store,
                                        request.cfg,
                                        candidate,
                                    )
                                    .await,
                            )
                        },
                        DEFAULT_TXID_VERSION,
                        EVM_CHAIN_TYPE,
                        request.cfg.chain.chain_id,
                        list_key,
                        txid_merkleroot_index,
                        poi,
                    )
                    .await
                {
                    Ok(()) => {}
                    Err(WalletPrivateRemoteError::Stale(_)) => return Ok(false),
                    Err(WalletPrivateRemoteError::Check(error)) => match error {},
                    Err(WalletPrivateRemoteError::Remote(_)) => {
                        return Err(RecoveryFailure::retryable(
                            OutputPoiRecoveryStatus::SubmitFailed,
                            "sender unshield POI submission failed",
                            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
                        ));
                    }
                }
            }
        }
        Ok(true)
    }
}
