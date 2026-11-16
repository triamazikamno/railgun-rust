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
        mut candidate,
        eligible,
        valid,
        qualified,
        wallet_nullifiers,
        public_data_fence,
        proof_source_resolution,
        mut cached_proofs,
    } = inputs;
    let candidate_id = candidate.semantic_id();
    let stored = sender_candidate_unshield_txids(&candidate);
    let eligible_count = u64::try_from(eligible.len()).unwrap_or(u64::MAX);
    let Some(valid) = valid else {
        let unknown = eligible.union(&stored).count();
        report.retrying = report
            .retrying
            .saturating_add(u64::try_from(unknown).unwrap_or(u64::MAX));
        return;
    };
    let target = unresolved_sender_unshield_txids(&eligible, &stored, Some(&valid));
    live.extend(target.iter().copied());
    if target != stored {
        let outputs_handed_off = candidate
            .unshield
            .as_ref()
            .is_some_and(|unshield| unshield.outputs_handed_off);
        let Ok(replacement) = sender_candidate_with_remaining_unshield(
            &candidate,
            target.iter().copied().collect(),
            outputs_handed_off,
        ) else {
            report.needs_attention = report.needs_attention.saturating_add(eligible_count);
            return;
        };
        match apply_poi_private_delta(
            request.authority,
            request.db,
            request.cache_store,
            request.cfg,
            OwnedPoiPrivateDelta::SenderCandidateUnshieldUpdate(
                SenderCandidateUnshieldUpdateDelta {
                    expected_candidate: candidate,
                    public_data_fence: public_data_fence.clone(),
                    replacement: replacement.clone(),
                },
            ),
        )
        .await
        {
            Ok(PoiPrivateApplyOutcome::Applied { .. }) => {}
            Ok(
                PoiPrivateApplyOutcome::Skipped
                | PoiPrivateApplyOutcome::SkippedStaleCorpusRevision,
            ) => return,
            Err(_) => {
                report.needs_attention = report.needs_attention.saturating_add(eligible_count);
                return;
            }
        }
        let Some(replacement) = replacement else {
            report.expected_candidates.remove(&candidate_id);
            return;
        };
        track_sender_candidate(report, &replacement);
        candidate = replacement;
    }

    let completed = target
        .intersection(&valid)
        .copied()
        .collect::<BTreeSet<_>>();
    if !completed.is_empty() {
        // `valid` is nonempty only after a read from this local corpus.
        let OutputPoiProofSourceResolution::Local { corpus, .. } = proof_source_resolution else {
            return;
        };
        let Some(unshield) = candidate.unshield.as_ref() else {
            return;
        };
        let Ok(next) = sender_candidate_after_unshield_validation(&candidate, unshield, &completed)
        else {
            report.needs_attention = report.needs_attention.saturating_add(eligible_count);
            return;
        };
        match apply_poi_private_delta(
            request.authority,
            request.db,
            request.cache_store,
            request.cfg,
            OwnedPoiPrivateDelta::SenderCandidateUnshieldValidated(
                SenderCandidateUnshieldValidatedDelta {
                    expected_candidate: candidate,
                    validated_txids: completed.iter().copied().collect(),
                    corpus: corpus.clone(),
                },
            ),
        )
        .await
        {
            Ok(PoiPrivateApplyOutcome::Applied { .. }) => {
                report.unshields_validated =
                    report.unshields_validated.saturating_add(completed.len());
            }
            Ok(
                PoiPrivateApplyOutcome::Skipped
                | PoiPrivateApplyOutcome::SkippedStaleCorpusRevision,
            ) => return,
            Err(_) => {
                report.needs_attention = report.needs_attention.saturating_add(eligible_count);
                return;
            }
        }
        let Some(next) = next else {
            report.expected_candidates.remove(&candidate_id);
            return;
        };
        track_sender_candidate(report, &next);
        candidate = next;
    }

    let mut submitted = 0_u64;
    let mut waiting = 0_u64;
    let unresolved = request.private_poi.submission_order(
        target.difference(&valid).copied().collect::<Vec<_>>(),
        |_| 1,
    );
    for txid in unresolved {
        if let Some(outcome) = attempts.waiting(txid, Instant::now(), request.force_retry) {
            waiting = waiting.saturating_add(1);
            match outcome {
                SenderUnshieldAttemptOutcome::Submitted => {
                    report.unshield_awaiting_validation =
                        report.unshield_awaiting_validation.saturating_add(1);
                }
                SenderUnshieldAttemptOutcome::Retrying => {
                    report.retrying = report.retrying.saturating_add(1);
                }
                SenderUnshieldAttemptOutcome::NeedsAttention => {
                    report.needs_attention = report.needs_attention.saturating_add(1);
                }
            }
            continue;
        }
        // A cached proof, or what proving this TXID needs.
        let proof = if let Some(cached) = cached_proofs.remove(&txid) {
            Ok(cached)
        } else {
            let (Some(spending_public_key), Some(prover)) = (
                request.cfg.spending_public_key,
                request.cfg.poi_recovery_prover.as_ref(),
            ) else {
                report.retrying = report.retrying.saturating_add(1);
                continue;
            };
            let Some(transaction) = qualified.iter().find(|transaction| {
                transaction.public_row.transaction.has_unshield
                    && sender_unshield_railgun_txid(transaction) == txid
            }) else {
                report.awaiting_public_txid_data =
                    report.awaiting_public_txid_data.saturating_add(1);
                continue;
            };
            Err((spending_public_key, prover, transaction))
        };
        // Reserve before proving, so that a deferral wastes no proof.
        let route = match request
            .private_poi
            .reserve_transact_route(
                request.cfg.chain.chain_id,
                U256::from_be_bytes(txid.0),
                None,
            )
            .await
        {
            Ok(route) => route,
            Err(deferred) => {
                attempts.record(
                    txid,
                    SenderUnshieldAttemptOutcome::Retrying,
                    deferred.retry_after(),
                );
                report.retrying = report.retrying.saturating_add(1);
                continue;
            }
        };
        let (txid_merkleroot_index, pre_transaction_pois) = match proof {
            Ok(cached) => cached,
            Err((spending_public_key, prover, transaction)) => {
                let candidate_prover = SenderCandidateProver {
                    request,
                    candidate: &candidate,
                    wallet_nullifiers,
                    spending_public_key,
                    prover,
                    proof_source_resolution,
                };
                match candidate_prover.prove(transaction).await {
                    Ok(Some(proved)) => (
                        proved.txid_data.poi_data.txid_merkleroot_index,
                        proved.pre_transaction_pois,
                    ),
                    Ok(None) => continue,
                    Err(failure) => {
                        record_sender_unshield_failure(report, attempts, txid, &failure);
                        continue;
                    }
                }
            }
        };
        match submit_sender_unshield_transaction_pois(
            request,
            &route,
            &candidate,
            public_data_fence,
            txid_merkleroot_index,
            &pre_transaction_pois,
        )
        .await
        {
            Ok(true) => {
                attempts.record(
                    txid,
                    SenderUnshieldAttemptOutcome::Submitted,
                    PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER,
                );
                report.unshield_awaiting_validation =
                    report.unshield_awaiting_validation.saturating_add(1);
                submitted = submitted.saturating_add(1);
            }
            Ok(false) => report.retrying = report.retrying.saturating_add(1),
            Err(failure) => record_sender_unshield_failure(report, attempts, txid, &failure),
        }
    }
    debug!(
        chain_id = request.cfg.chain.chain_id,
        eligible = eligible.len(),
        unresolved = target.len(),
        validated = completed.len(),
        submitted,
        waiting,
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

pub(super) async fn submit_sender_unshield_transaction_pois(
    request: &OutputPoiRecoveryRequest<'_>,
    route: &TransactProofRoute,
    candidate: &SenderTransactionCandidate,
    public_data_fence: &SenderCandidatePublicDataFence,
    txid_merkleroot_index: u64,
    pre_transaction_pois: &PreTransactionPoiMap,
) -> Result<bool, RecoveryFailure> {
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
