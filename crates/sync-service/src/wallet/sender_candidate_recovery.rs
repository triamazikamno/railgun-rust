use super::saved_poi_compatibility::{
    corpus_valid_blinded_commitments, saved_pending_context_is_compatible,
    saved_poi_map_is_compatible,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;
use std::sync::{OnceLock, PoisonError};

use crate::SenderTransactionCandidateError;
use crate::chain::{ChainPublicDataPlaneCommitGuard, PublicTxidDataAuthority};
use crate::types::PublicDataPlaneEpoch;

use super::output_poi_recovery::{
    OutputPoiProofSourceResolution, PublicCacheTxidRecoveryRequest, PublicCacheTxidRefreshRequest,
    RecoveredOutputTxidData, RecoveryChunk, RecoveryFailure, WalletNullifierIndex,
    build_recovery_chunk_for_public_transaction, new_output_poi_recovery_record_for_output,
    output_poi_recovery_proof_retry_after, pending_output_poi_context_from_output_recovery,
    poi_shield_blocked_on_any_list, preflight_local_recovery_chunk_input_proofs,
    recovered_output_txid_data_from_public_cache, refresh_public_txid_cache,
};
#[allow(clippy::wildcard_imports)]
use super::*;
pub(super) struct SenderCandidateRecoveryRequest<'a> {
    pub(super) output_recovery: OutputPoiRecoveryRequest<'a>,
    pub(super) candidates: Vec<SenderTransactionCandidate>,
    pub(super) unshield_attempts: &'a SenderUnshieldAttempts,
}

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

    fn retain(&self, live: &BTreeSet<FixedBytes<32>>) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|txid, _| live.contains(txid));
    }

    #[cfg(test)]
    pub(super) fn expire_all(&self) {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SenderRowQualification {
    Foreign,
    WalletAuthored,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SenderCandidateLocalClassification {
    pub(crate) external_outputs: Vec<BlindedCommitmentData>,
}

/// Classify a candidate without consulting public or remote state.
///
/// This is deliberately shared by the preflight and actor paths.  The actor repeats it from
/// its fresh wallet snapshot before allowing the candidate-only durable deletion.
///
/// Every output must be either exactly one wallet UTXO owned by the scan key or an external
/// output. An all-owned candidate classifies with no external outputs, which settles only its
/// private outputs, not its unshields. A candidate without outputs is `None`: it takes the
/// no-private-output unshield route instead.
pub(crate) fn classify_sender_candidate_for_local_retirement(
    candidate: &SenderTransactionCandidate,
    wallet_utxos: &[WalletUtxo],
    scan_keys: &railgun_wallet::scan::WalletScanKeys,
) -> Option<SenderCandidateLocalClassification> {
    candidate.validate().ok()?;
    if candidate.outputs.is_empty() {
        return None;
    }

    let expected_spends = candidate
        .wallet_spends
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if expected_spends.len() != candidate.wallet_spends.len() {
        return None;
    }
    let actual_spend_entries = wallet_utxos
        .iter()
        .filter(|wallet_utxo| wallet_utxo.spent.as_ref() == Some(&candidate.source))
        .map(|wallet_utxo| SenderTransactionCandidateSpend {
            tree: wallet_utxo.utxo.tree,
            position: wallet_utxo.utxo.position,
            commitment: wallet_utxo.utxo.poi.commitment,
        })
        .collect::<Vec<_>>();
    let actual_spends = actual_spend_entries
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if actual_spends.len() != actual_spend_entries.len() {
        return None;
    }
    if actual_spends != expected_spends {
        return None;
    }

    let mut external_outputs = Vec::new();
    let mut external_blinded_commitments = BTreeSet::new();
    for output in &candidate.outputs {
        let owned_by_scan_key = output.note.as_ref().is_some_and(|note| {
            note.npk == Note::npk_for(scan_keys.master_public_key, note.random)
        });
        let exact_wallet_matches = wallet_utxos
            .iter()
            .filter(|wallet_utxo| {
                let Some(note) = output.note.as_ref() else {
                    return wallet_utxo.utxo.source == candidate.source
                        && wallet_utxo.utxo.tree == output.tree
                        && wallet_utxo.utxo.position == output.position
                        && wallet_utxo.utxo.poi.commitment == output.commitment
                        && wallet_utxo.utxo.poi.commitment_kind == UtxoCommitmentKind::Transact
                        && wallet_utxo.utxo.poi.npk
                            == FixedBytes::from(
                                Note::npk_for(
                                    scan_keys.master_public_key,
                                    wallet_utxo.utxo.note.random,
                                )
                                .to_be_bytes::<32>(),
                            )
                        && sender_candidate_poi_identity_matches(
                            &wallet_utxo.utxo.poi,
                            &Utxo::new(
                                wallet_utxo.utxo.note.clone(),
                                output.tree,
                                output.position,
                                candidate.source.clone(),
                                UtxoCommitmentKind::Transact,
                            )
                            .poi,
                        );
                };
                let recomputed = Utxo::new(
                    note.clone(),
                    output.tree,
                    output.position,
                    candidate.source.clone(),
                    UtxoCommitmentKind::Transact,
                );
                wallet_utxo.utxo.source == candidate.source
                    && wallet_utxo.utxo.tree == output.tree
                    && wallet_utxo.utxo.position == output.position
                    && sender_candidate_poi_identity_matches(&wallet_utxo.utxo.poi, &recomputed.poi)
                    && wallet_utxo.utxo.note.npk
                        == Note::npk_for(scan_keys.master_public_key, note.random)
            })
            .count();

        if exact_wallet_matches > 1 {
            return None;
        }
        if owned_by_scan_key {
            if exact_wallet_matches != 1 {
                return None;
            }
            continue;
        }
        let note = output.note.as_ref()?;
        let recomputed = Utxo::new(
            note.clone(),
            output.tree,
            output.position,
            candidate.source.clone(),
            UtxoCommitmentKind::Transact,
        );
        if !external_blinded_commitments.insert(recomputed.poi.blinded_commitment) {
            return None;
        }
        external_outputs.push(BlindedCommitmentData::transact(
            recomputed.poi.blinded_commitment,
        ));
    }
    Some(SenderCandidateLocalClassification { external_outputs })
}

fn sender_candidate_poi_identity_matches(
    actual: &UtxoPoiMetadata,
    expected: &UtxoPoiMetadata,
) -> bool {
    actual.commitment_kind == expected.commitment_kind
        && actual.commitment == expected.commitment
        && actual.npk == expected.npk
        && actual.blinded_commitment == expected.blinded_commitment
}

async fn locally_valid_sender_candidate(
    request: &OutputPoiRecoveryRequest<'_>,
    candidate: &SenderTransactionCandidate,
) -> Option<PublicPoiCorpusHandle> {
    if !request.poi_runtime.is_indexed_artifacts() || request.active_list_keys.is_empty() {
        return None;
    }
    let classification = classify_sender_candidate_for_local_retirement(
        candidate,
        request.wallet_utxos,
        &request.cfg.scan_keys,
    )?;
    let key = PublicPoiCorpusKey::wallet_default(request.cfg.chain.chain_id);
    if !request
        .public_data_plane
        .poi_corpus_ready_for_lists(key.clone(), request.active_list_keys)
        .await
    {
        return None;
    }
    let corpus = request
        .public_data_plane
        .ensure_poi_corpus(key)
        .await
        .ok()?;
    let _revision_fence = corpus.revision_read_fence().await;
    let statuses = corpus
        .status_reader()
        .pois_per_list(
            DEFAULT_TXID_VERSION,
            EVM_CHAIN_TYPE,
            request.cfg.chain.chain_id,
            request.active_list_keys,
            &classification.external_outputs,
        )
        .await
        .ok()?;
    let all_valid = classification.external_outputs.iter().all(|data| {
        statuses
            .get(&data.blinded_commitment)
            .is_some_and(|per_list| {
                request
                    .active_list_keys
                    .iter()
                    .all(|list_key| per_list.get(list_key) == Some(&PoiStatus::Valid))
            })
    });
    all_valid.then_some(corpus)
}

async fn locally_valid_sender_candidate_outputs(
    request: &OutputPoiRecoveryRequest<'_>,
    candidate: &SenderTransactionCandidate,
) -> BTreeSet<FixedBytes<32>> {
    if !request.poi_runtime.is_indexed_artifacts()
        || request.active_list_keys.is_empty()
        || !request
            .public_data_plane
            .poi_corpus_ready_for_lists(
                PublicPoiCorpusKey::wallet_default(request.cfg.chain.chain_id),
                request.active_list_keys,
            )
            .await
    {
        return BTreeSet::new();
    }
    let Some(output_data) = candidate
        .outputs
        .iter()
        .map(|output| {
            let note = output.note.as_ref()?;
            let utxo = Utxo::new(
                note.clone(),
                output.tree,
                output.position,
                candidate.source.clone(),
                UtxoCommitmentKind::Transact,
            );
            (utxo.poi.commitment == output.commitment)
                .then_some(BlindedCommitmentData::transact(utxo.poi.blinded_commitment))
        })
        .collect::<Option<Vec<_>>>()
    else {
        return BTreeSet::new();
    };
    let Ok(corpus) = request
        .public_data_plane
        .ensure_poi_corpus(PublicPoiCorpusKey::wallet_default(
            request.cfg.chain.chain_id,
        ))
        .await
    else {
        return BTreeSet::new();
    };
    let _revision_fence = corpus.revision_read_fence().await;
    let Ok(statuses) = corpus
        .status_reader()
        .pois_per_list(
            DEFAULT_TXID_VERSION,
            EVM_CHAIN_TYPE,
            request.cfg.chain.chain_id,
            request.active_list_keys,
            &output_data,
        )
        .await
    else {
        return BTreeSet::new();
    };
    output_data
        .iter()
        .filter(|data| {
            statuses
                .get(&data.blinded_commitment)
                .is_some_and(|per_list| {
                    request
                        .active_list_keys
                        .iter()
                        .all(|list_key| per_list.get(list_key) == Some(&PoiStatus::Valid))
                })
        })
        .map(|data| data.blinded_commitment)
        .collect()
}

fn pending_context_covers_sender_output(
    chain_id: u64,
    wallet_id: &str,
    candidate: &SenderTransactionCandidate,
    output: &crate::SenderTransactionCandidateOutput,
    active_list_keys: &[FixedBytes<32>],
    context: &PendingOutputPoiContextRecord,
) -> bool {
    if !saved_pending_context_is_compatible(context, active_list_keys)
        || context.terminal_error.is_some()
        || context.chain_id != chain_id
        || context.wallet_id != wallet_id
        || context.output_commitment != output.commitment
    {
        return false;
    }
    let Some(note) = output.note.as_ref() else {
        return false;
    };
    if context.output_npk != FixedBytes::from(note.npk.to_be_bytes::<32>()) {
        return false;
    }
    let Some(observation) = context.observation.as_ref() else {
        return false;
    };
    observation.output_tree == u64::from(output.tree)
        && observation.output_position == output.position
        && observation.tx_hash == candidate.source.tx_hash
        && observation.block_number == candidate.source.block_number
        && observation.block_timestamp == candidate.source.block_timestamp
        && active_list_keys.iter().all(|list_key| {
            context.list_keys().contains(list_key)
                && context
                    .pre_transaction_pois_per_txid_leaf_per_list
                    .get(list_key)
                    .is_some_and(|pois| !pois.is_empty())
        })
}

#[derive(Debug, Default, Clone, Copy)]
struct SenderCandidateCoverage {
    local_valid: u64,
    pending_contexts: u64,
}

fn sender_candidate_coverage_from_routes(
    candidate: &SenderTransactionCandidate,
    local_valid_commitments: &BTreeSet<FixedBytes<32>>,
    pending_context_commitments: &BTreeSet<FixedBytes<32>>,
) -> Option<SenderCandidateCoverage> {
    let mut coverage = SenderCandidateCoverage::default();
    for output in &candidate.outputs {
        if local_valid_commitments.contains(&output.commitment) {
            coverage.local_valid = coverage.local_valid.saturating_add(1);
        } else if pending_context_commitments.contains(&output.commitment) {
            coverage.pending_contexts = coverage.pending_contexts.saturating_add(1);
        } else {
            return None;
        }
    }
    (coverage.pending_contexts > 0).then_some(coverage)
}

async fn sender_candidate_coverage(
    request: &OutputPoiRecoveryRequest<'_>,
    candidate: &SenderTransactionCandidate,
) -> Option<SenderCandidateCoverage> {
    if candidate.validate().is_err()
        || classify_sender_candidate_for_local_retirement(
            candidate,
            request.wallet_utxos,
            &request.cfg.scan_keys,
        )
        .is_none()
        || !sender_candidate_still_current(
            request.authority,
            request.cache_store,
            request.cfg,
            candidate,
        )
        .await
    {
        return None;
    }
    let local_valid = locally_valid_sender_candidate_outputs(request, candidate).await;
    let mut local_valid_commitments = BTreeSet::new();
    let mut pending_context_commitments = BTreeSet::new();
    for output in &candidate.outputs {
        let blinded_commitment = output.note.as_ref().and_then(|note| {
            let utxo = Utxo::new(
                note.clone(),
                output.tree,
                output.position,
                candidate.source.clone(),
                UtxoCommitmentKind::Transact,
            );
            (utxo.poi.commitment == output.commitment).then_some(utxo.poi.blinded_commitment)
        });
        if blinded_commitment.is_some_and(|blinded| local_valid.contains(&blinded)) {
            local_valid_commitments.insert(output.commitment);
            continue;
        }
        let pending = request
            .cache_store
            .get_pending_output_poi_context(
                request.cfg.chain.chain_id,
                &request.cfg.cache_key,
                &output.commitment,
            )
            .ok()
            .flatten()
            .is_some_and(|context| {
                pending_context_covers_sender_output(
                    request.cfg.chain.chain_id,
                    request.cfg.cache_key.as_str(),
                    candidate,
                    output,
                    request.active_list_keys,
                    &context,
                )
            });
        if pending {
            pending_context_commitments.insert(output.commitment);
        }
    }
    sender_candidate_coverage_from_routes(
        candidate,
        &local_valid_commitments,
        &pending_context_commitments,
    )
}

async fn refresh_sender_candidate_public_txid_cache(
    request: &OutputPoiRecoveryRequest<'_>,
    cache_key: &PublicTxidCacheKey,
    refreshed: &mut Option<bool>,
) -> bool {
    if let Some(refreshed) = *refreshed {
        refreshed
    } else {
        let result = refresh_public_txid_cache(PublicCacheTxidRefreshRequest {
            public_data_plane: request.public_data_plane,
            cfg: request.cfg,
            poi_client: request.poi_client,
            http_client: request.http_client,
            indexed_artifact_source: request.indexed_artifact_source,
            cache_key: cache_key.clone(),
        })
        .await
        .is_ok();
        *refreshed = Some(result);
        result
    }
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
        match prepare_sender_candidate_materialization(
            request,
            candidate,
            work.qualified,
            spending_public_key,
            prover,
            work.proof_source_resolution,
            &work.unresolved,
        )
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

fn sender_candidate_unshield_txids(
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
fn sender_candidate_with_unshield_work(
    candidate: &SenderTransactionCandidate,
    work: &BTreeSet<FixedBytes<32>>,
) -> Result<Option<SenderTransactionCandidate>, SenderTransactionCandidateError> {
    sender_candidate_with_remaining_unshield(candidate, work.iter().copied().collect(), true)
}

/// The candidate left after completing `validated` unshield TXIDs, or `None` when it retires.
pub(super) fn sender_candidate_after_unshield_validation(
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
fn unresolved_sender_unshield_txids(
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

fn sender_unshield_railgun_txid(transaction: &QualifiedSenderTransaction) -> FixedBytes<32> {
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
fn eligible_sender_unshield_txids(
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
async fn corpus_shield_blocked_unshield_inputs(
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
pub(super) async fn sender_unshield_valid_txids(
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

struct QualifiedSenderCandidate {
    qualified: Vec<QualifiedSenderTransaction>,
    public_data_fence: SenderCandidatePublicDataFence,
    data_epoch: PublicDataPlaneEpoch,
}

/// Why public rows do not yet qualify a candidate; each maps to one report category.
#[derive(Debug, Clone, Copy)]
enum SenderCandidateQualificationPending {
    AwaitingPublicTxidData,
    Retrying,
    NeedsAttention,
}

impl SenderCandidateQualificationPending {
    const fn record(self, report: &mut SenderCandidateRecoveryReport, count: u64) {
        let counter = match self {
            Self::AwaitingPublicTxidData => &mut report.awaiting_public_txid_data,
            Self::Retrying => &mut report.retrying,
            Self::NeedsAttention => &mut report.needs_attention,
        };
        *counter = counter.saturating_add(count);
    }
}

async fn qualify_sender_candidate_from_public_rows(
    request: &OutputPoiRecoveryRequest<'_>,
    candidate: &SenderTransactionCandidate,
    cache_key: &PublicTxidCacheKey,
    refreshed: &mut Option<bool>,
) -> Result<QualifiedSenderCandidate, SenderCandidateQualificationPending> {
    let mut data_epoch = request.public_data_plane.current_epoch();
    let mut rows = request
        .public_data_plane
        .txid_transactions_for_outer_hash_with_authority(cache_key, candidate.source.tx_hash);
    if matches!(&rows, Ok((rows, _)) if rows.is_empty())
        || matches!(&rows, Err(TxidPublicCacheError::CacheNotReady { .. }))
    {
        if !refresh_sender_candidate_public_txid_cache(request, cache_key, refreshed).await {
            return Err(SenderCandidateQualificationPending::Retrying);
        }
        data_epoch = request.public_data_plane.current_epoch();
        rows = request
            .public_data_plane
            .txid_transactions_for_outer_hash_with_authority(cache_key, candidate.source.tx_hash);
    }
    let (mut rows, mut authority) = match rows {
        Ok((rows, _authority)) if rows.is_empty() => {
            return Err(SenderCandidateQualificationPending::AwaitingPublicTxidData);
        }
        Ok((rows, authority)) => (rows, authority),
        Err(TxidPublicCacheError::CacheNotReady { .. }) => {
            return Err(SenderCandidateQualificationPending::AwaitingPublicTxidData);
        }
        Err(_) => return Err(SenderCandidateQualificationPending::Retrying),
    };
    let mut qualification = qualify_sender_candidate(
        candidate,
        request.wallet_utxos,
        &request.cfg.scan_keys,
        rows.clone(),
    );
    if matches!(qualification, Ok(None)) && refreshed.is_none() {
        if !refresh_sender_candidate_public_txid_cache(request, cache_key, refreshed).await {
            return Err(SenderCandidateQualificationPending::Retrying);
        }
        data_epoch = request.public_data_plane.current_epoch();
        (rows, authority) = match request
            .public_data_plane
            .txid_transactions_for_outer_hash_with_authority(cache_key, candidate.source.tx_hash)
        {
            Ok((rows, authority)) if !rows.is_empty() => (rows, authority),
            Ok(_) | Err(TxidPublicCacheError::CacheNotReady { .. }) => {
                return Err(SenderCandidateQualificationPending::AwaitingPublicTxidData);
            }
            Err(_) => return Err(SenderCandidateQualificationPending::Retrying),
        };
        qualification = qualify_sender_candidate(
            candidate,
            request.wallet_utxos,
            &request.cfg.scan_keys,
            rows.clone(),
        );
    }
    let qualified = match qualification {
        Ok(Some(qualified)) => qualified,
        Ok(None) => {
            debug!(
                chain_id = request.cfg.chain.chain_id,
                category = "public_rows_do_not_cover_candidate",
                "sender candidate recovery qualification incomplete"
            );
            return Err(SenderCandidateQualificationPending::AwaitingPublicTxidData);
        }
        Err(()) => {
            warn!(
                chain_id = request.cfg.chain.chain_id,
                category = "candidate_shape_or_wallet_association_mismatch",
                "sender candidate recovery qualification failed"
            );
            return Err(SenderCandidateQualificationPending::NeedsAttention);
        }
    };
    Ok(QualifiedSenderCandidate {
        qualified,
        public_data_fence: SenderCandidatePublicDataFence::new(
            request.public_data_plane,
            cache_key.clone(),
            data_epoch,
            rows,
            authority,
        ),
        data_epoch,
    })
}

pub(super) struct SenderUnshieldInputs<'a> {
    pub(super) candidate: SenderTransactionCandidate,
    /// Eligible unshield TXIDs of the qualified rows.
    pub(super) eligible: BTreeSet<FixedBytes<32>>,
    /// Eligible TXIDs already Valid locally; `None` when the status read failed.
    pub(super) valid: Option<BTreeSet<FixedBytes<32>>>,
    pub(super) qualified: &'a [QualifiedSenderTransaction],
    /// Spent wallet UTXOs of this pass, indexed by input tree and nullifier.
    pub(super) wallet_nullifiers: &'a WalletNullifierIndex<'a>,
    pub(super) public_data_fence: &'a SenderCandidatePublicDataFence,
    pub(super) proof_source_resolution: &'a OutputPoiProofSourceResolution,
    /// Proofs built during materialization, keyed by TXID, with their TXID merkleroot index.
    pub(super) cached_proofs: BTreeMap<FixedBytes<32>, (u64, PreTransactionPoiMap)>,
}

/// Reconcile, complete, and submit a candidate's unshield work.
///
/// A submission acknowledgement never completes anything; only a later local Valid read does.
pub(super) async fn process_sender_candidate_unshields(
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
                match prove_sender_transaction(
                    request,
                    &candidate,
                    transaction,
                    wallet_nullifiers,
                    spending_public_key,
                    prover,
                    proof_source_resolution,
                )
                .await
                {
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

struct PreparedSenderCandidateMaterialization {
    pending_updates: Vec<PendingOutputPoiContextRecord>,
    recovery_updates: Vec<OutputPoiRecoveryRecord>,
    owned_substitutes: Vec<ExpectedWalletOutput>,
    proof_outputs: Vec<FixedBytes<32>>,
    expected_corpus: ExpectedPoiCorpusRevision,
    replacement_group: Vec<(
        PendingOutputPoiContextRecord,
        Option<OutputPoiRecoveryRecord>,
    )>,
    external_valid_substitutes: Vec<Utxo>,
    /// Proofs of rows in the requested unshield work, reused for their unshield submission.
    unshield_proofs: BTreeMap<FixedBytes<32>, (u64, PreTransactionPoiMap)>,
}

struct ProvedSenderTransaction {
    recovery_chunk: RecoveryChunk,
    txid_data: RecoveredOutputTxidData,
    pre_transaction_pois: PreTransactionPoiMap,
}

/// Prove one qualified sender transaction from the local proof source.
///
/// `Ok(None)` means the candidate or proof source went stale and nothing was proved.
async fn prove_sender_transaction(
    request: &OutputPoiRecoveryRequest<'_>,
    candidate: &SenderTransactionCandidate,
    qualified: &QualifiedSenderTransaction,
    wallet_nullifiers: &WalletNullifierIndex<'_>,
    spending_public_key: [U256; 2],
    prover: &railgun_wallet::prover::ProverService,
    proof_source_resolution: &OutputPoiProofSourceResolution,
) -> Result<Option<ProvedSenderTransaction>, RecoveryFailure> {
    if !sender_candidate_still_current(
        request.authority,
        request.cache_store,
        request.cfg,
        candidate,
    )
    .await
    {
        return Ok(None);
    }
    let recovery_chunk = build_recovery_chunk_for_public_transaction(
        qualified.output_start_global,
        qualified.output_notes.clone(),
        candidate.source.tx_hash,
        wallet_nullifiers,
        &qualified.public_row.transaction,
        &request.forest,
        request.active_list_keys,
        spending_public_key,
        &request.cfg.scan_keys,
        Some(qualified.txid_index),
    )
    .await?;
    if !sender_candidate_still_current(
        request.authority,
        request.cache_store,
        request.cfg,
        candidate,
    )
    .await
    {
        return Ok(None);
    }
    let OutputPoiProofSourceResolution::Local { source, .. } = proof_source_resolution else {
        return Ok(None);
    };
    preflight_local_recovery_chunk_input_proofs(
        Some(source),
        request.cfg,
        &recovery_chunk,
        request.active_list_keys,
    )
    .await?;
    let txid_data = recovered_output_txid_data_from_public_cache(PublicCacheTxidRecoveryRequest {
        public_data_plane: request.public_data_plane,
        cfg: request.cfg,
        poi_client: request.poi_client,
        http_client: request.http_client,
        indexed_artifact_source: request.indexed_artifact_source,
        recovery_chunk: &recovery_chunk,
        started: Instant::now(),
    })
    .await?;
    debug!(
        chain_id = request.cfg.chain.chain_id,
        "sender candidate proof generation started"
    );
    let proof_generation_started = Instant::now();
    let pre_transaction_pois = generate_sender_candidate_post_transaction_pois(
        PostTransactionPoiGenerationRequest {
            chunk: &recovery_chunk.chunk,
            txid_data: &txid_data.poi_data,
            chain_type: EVM_CHAIN_TYPE,
            chain_id: request.cfg.chain.chain_id,
            txid_version: Some(DEFAULT_TXID_VERSION),
            required_poi_list_keys: request.active_list_keys,
            proof_source: source,
            prover,
            verify_proof: OUTPUT_POI_RECOVERY_VERIFY_PROOF,
        },
        SENDER_CANDIDATE_PROOF_GENERATION_TIMEOUT,
    )
    .await?;
    debug!(
        chain_id = request.cfg.chain.chain_id,
        elapsed_ms = proof_generation_started.elapsed().as_millis(),
        "sender candidate proof generation complete"
    );
    if pre_transaction_pois
        .values()
        .flat_map(|per_leaf| per_leaf.values())
        .any(|poi| {
            !super::saved_poi_compatibility::saved_poi_is_compatible(
                poi,
                Some((
                    qualified.public_row.transaction.nullifiers.len(),
                    qualified.public_row.transaction.commitments.len(),
                )),
            )
        })
    {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::ProofGenerationFailed,
            "generated proof does not match the current verifier",
            OUTPUT_POI_RECOVERY_PROOF_FAILURE_RETRY_AFTER,
        ));
    }
    Ok(Some(ProvedSenderTransaction {
        recovery_chunk,
        txid_data,
        pre_transaction_pois,
    }))
}

async fn prepare_sender_candidate_materialization(
    request: &OutputPoiRecoveryRequest<'_>,
    candidate: &SenderTransactionCandidate,
    qualified: &[QualifiedSenderTransaction],
    spending_public_key: [U256; 2],
    prover: &railgun_wallet::prover::ProverService,
    proof_source_resolution: &OutputPoiProofSourceResolution,
    unshield_work: &BTreeSet<FixedBytes<32>>,
) -> Result<Option<PreparedSenderCandidateMaterialization>, RecoveryFailure> {
    if !sender_candidate_still_current(
        request.authority,
        request.cache_store,
        request.cfg,
        candidate,
    )
    .await
    {
        return Ok(None);
    }
    if matches!(
        proof_source_resolution,
        OutputPoiProofSourceResolution::Unavailable
    ) {
        return Ok(None);
    }
    let wallet_nullifiers = WalletNullifierIndex::new(request.wallet_utxos, &request.cfg.scan_keys);
    let old_contexts = request
        .cache_store
        .list_pending_output_poi_contexts(request.cfg.chain.chain_id, &request.cfg.cache_key)
        .map_err(|_| {
            RecoveryFailure::retryable(
                OutputPoiRecoveryStatus::Recoverable,
                "pending proof evidence is unavailable",
                OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
            )
        })?;
    let source_contexts = old_contexts
        .into_iter()
        .filter(|context| {
            context.observation.as_ref().is_some_and(|observation| {
                observation.tx_hash == candidate.source.tx_hash
                    && observation.block_number == candidate.source.block_number
                    && observation.block_timestamp == candidate.source.block_timestamp
            })
        })
        .collect::<Vec<_>>();
    let replacing = source_contexts
        .iter()
        .any(|context| !saved_pending_context_is_compatible(context, &context.list_keys()));
    let replacement_group = if replacing {
        source_contexts
            .into_iter()
            .map(|context| {
                request
                    .cache_store
                    .get_output_poi_recovery(
                        request.cfg.chain.chain_id,
                        &request.cfg.cache_key,
                        &context.output_commitment,
                    )
                    .map(|recovery| (context, recovery))
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| {
                RecoveryFailure::retryable(
                    OutputPoiRecoveryStatus::Recoverable,
                    "pending recovery evidence is unavailable",
                    OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
                )
            })?
    } else {
        Vec::new()
    };
    let Some(expected_corpus) = proof_source_resolution.expected_corpus_revision() else {
        return Ok(None);
    };
    let candidate_blinded = qualified
        .iter()
        .flat_map(|transaction| {
            transaction
                .outputs
                .iter()
                .map(|output| output.poi.blinded_commitment)
        })
        .collect::<Vec<_>>();
    let Some(valid_by_list) = super::saved_poi_compatibility::corpus_valid_outputs_by_list(
        &expected_corpus.corpus,
        request.cfg.chain.chain_id,
        request.active_list_keys,
        &candidate_blinded,
    )
    .await
    else {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::Recoverable,
            "output POI status is unavailable",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    };
    let mut external_valid_substitutes = Vec::new();
    let now = now_epoch_secs();
    let mut pending_updates = Vec::new();
    let mut recovery_updates = Vec::new();
    let mut owned_substitutes = Vec::new();
    let mut proof_outputs = BTreeSet::new();
    let mut unshield_proofs = BTreeMap::new();
    for qualified in qualified {
        if qualified.outputs.is_empty() {
            continue;
        }
        let Some(ProvedSenderTransaction {
            recovery_chunk,
            txid_data,
            pre_transaction_pois,
        }) = prove_sender_transaction(
            request,
            candidate,
            qualified,
            &wallet_nullifiers,
            spending_public_key,
            prover,
            proof_source_resolution,
        )
        .await?
        else {
            return Ok(None);
        };
        let mut transaction_proof_outputs = None;
        for list_key in request.active_list_keys {
            let Some(per_leaf) = pre_transaction_pois.get(list_key) else {
                return Ok(None);
            };
            let outputs = per_leaf
                .values()
                .flat_map(|poi| poi.blinded_commitments_out.iter().copied())
                .collect::<BTreeSet<_>>();
            if outputs.len()
                != per_leaf
                    .values()
                    .map(|poi| poi.blinded_commitments_out.len())
                    .sum::<usize>()
                || transaction_proof_outputs
                    .as_ref()
                    .is_some_and(|expected| expected != &outputs)
            {
                return Ok(None);
            }
            transaction_proof_outputs = Some(outputs);
        }
        let Some(transaction_proof_outputs) = transaction_proof_outputs else {
            return Ok(None);
        };
        if transaction_proof_outputs
            .iter()
            .any(|output| !proof_outputs.insert(*output))
        {
            return Ok(None);
        }
        if qualified.public_row.transaction.has_unshield {
            let txid = sender_unshield_railgun_txid(qualified);
            if unshield_work.contains(&txid) {
                unshield_proofs.insert(
                    txid,
                    (
                        txid_data.poi_data.txid_merkleroot_index,
                        pre_transaction_pois.clone(),
                    ),
                );
            }
        }
        for output in &qualified.outputs {
            let expected = ExpectedWalletOutput::new(&WalletUtxo::new(output.clone()));
            let coordinate_matches = request
                .wallet_utxos
                .iter()
                .filter(|current| {
                    !current.is_spent()
                        && current.utxo.tree == output.tree
                        && current.utxo.position == output.position
                        && current.utxo.poi.commitment == output.poi.commitment
                        && current.utxo.source == candidate.source
                })
                .collect::<Vec<_>>();
            if coordinate_matches.len() > 1
                || coordinate_matches
                    .first()
                    .is_some_and(|current| !expected.matches(current))
            {
                return Ok(None);
            }
            if let Some(current) = coordinate_matches.first() {
                owned_substitutes.push(ExpectedWalletOutput::new(current));
                continue;
            }
            let target_lists = super::saved_poi_compatibility::unresolved_output_lists(
                request.active_list_keys,
                output.poi.blinded_commitment,
                &valid_by_list,
            );
            if target_lists.is_empty() {
                external_valid_substitutes.push(output.clone());
                continue;
            }
            let mut output_proofs = pre_transaction_pois.clone();
            output_proofs.retain(|list_key, _| target_lists.contains(list_key));
            pending_updates.push(pending_output_poi_context_from_output_recovery(
                request.cfg,
                output,
                &recovery_chunk,
                txid_data.poi_data.txid_merkleroot_index,
                output_proofs,
                &target_lists,
                PendingOutputPoiRole::RecoveredOutgoing,
                format!(
                    "recovered-sender-output-poi:{}:{}",
                    hex::encode(candidate.source.tx_hash),
                    qualified.txid_index
                ),
                now,
            ));
            let mut recovery = new_output_poi_recovery_record_for_output(
                request.cfg,
                output,
                OutputPoiRecoveryStatus::Recoverable,
                now,
            );
            recovery.apply_action(
                OutputPoiRecoveryAction::Detected {
                    status: OutputPoiRecoveryStatus::Recoverable,
                    retry_after: None,
                    last_error: None,
                    increment_attempts: false,
                },
                now,
            );
            recovery_updates.push(recovery);
        }
    }
    let Some(expected_corpus) = proof_source_resolution.expected_corpus_revision() else {
        return Ok(None);
    };
    Ok(Some(PreparedSenderCandidateMaterialization {
        pending_updates,
        recovery_updates,
        owned_substitutes,
        proof_outputs: proof_outputs.into_iter().collect(),
        expected_corpus,
        replacement_group,
        external_valid_substitutes,
        unshield_proofs,
    }))
}

const SENDER_CANDIDATE_PROOF_GENERATION_TIMEOUT: Duration = Duration::from_mins(2);

async fn generate_sender_candidate_post_transaction_pois(
    request: PostTransactionPoiGenerationRequest<'_>,
    timeout: Duration,
) -> Result<PreTransactionPoiMap, RecoveryFailure> {
    generate_sender_candidate_post_transaction_pois_with_timeout(
        generate_post_transaction_pois(request),
        timeout,
    )
    .await
}

async fn generate_sender_candidate_post_transaction_pois_with_timeout<F>(
    future: F,
    timeout: Duration,
) -> Result<PreTransactionPoiMap, RecoveryFailure>
where
    F: Future<Output = Result<PreTransactionPoiMap, PreTransactionPoiError>>,
{
    match tokio::time::timeout(timeout, future).await {
        Ok(Ok(pois)) => Ok(pois),
        Ok(Err(error)) => Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::ProofGenerationFailed,
            error.to_string(),
            output_poi_recovery_proof_retry_after(&error),
        )),
        Err(_) => Err(RecoveryFailure::retryable_category(
            OutputPoiRecoveryStatus::ProofGenerationFailed,
            "proof_generation_timeout",
            "post-transaction POI proof generation timed out",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        )),
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

fn qualify_sender_candidate(
    candidate: &SenderTransactionCandidate,
    wallet_utxos: &[WalletUtxo],
    scan_keys: &railgun_wallet::scan::WalletScanKeys,
    rows: Vec<PublicTxidTransaction>,
) -> Result<Option<Vec<QualifiedSenderTransaction>>, ()> {
    if candidate.validate().is_err() || rows.is_empty() {
        return Ok(None);
    }
    let mut qualified = Vec::new();
    let mut consumed_outputs = BTreeSet::new();
    let mut consumed_spends = BTreeSet::new();
    let mut qualified_nullifiers = BTreeSet::new();
    for row in rows {
        match qualify_sender_row_inputs(candidate, wallet_utxos, scan_keys, &row)? {
            SenderRowQualification::Foreign => continue,
            SenderRowQualification::WalletAuthored => {}
        }
        let transaction = &row.transaction;
        if transaction.transaction_hash != candidate.source.tx_hash
            || transaction.block_number != candidate.source.block_number
            || transaction.utxo_tree_in > u64::from(u32::MAX)
        {
            return Err(());
        }
        for nullifier in &transaction.nullifiers {
            if !qualified_nullifiers.insert(*nullifier) {
                return Err(());
            }
            let input = wallet_utxos
                .iter()
                .find(|wallet_utxo| {
                    u64::from(wallet_utxo.utxo.tree) == transaction.utxo_tree_in
                        && wallet_utxo.utxo.nullifier(scan_keys.nullifying_key) == *nullifier
                })
                .ok_or(())?;
            consumed_spends.insert(SenderTransactionCandidateSpend {
                tree: input.utxo.tree,
                position: input.utxo.position,
                commitment: input.utxo.poi.commitment,
            });
        }
        let private_output_count = transaction
            .commitments
            .len()
            .checked_sub(usize::from(transaction.has_unshield))
            .ok_or(())?;
        // A row with no private outputs qualifies only for its unshield.
        if private_output_count == 0 && !transaction.has_unshield {
            return Err(());
        }
        let output_start_global = transaction.output_start_global();
        let mut outputs = Vec::with_capacity(private_output_count);
        let mut output_notes = Vec::with_capacity(private_output_count);
        for (offset, commitment) in transaction
            .commitments
            .iter()
            .take(private_output_count)
            .enumerate()
        {
            let global = output_start_global
                .checked_add(u128::try_from(offset).map_err(|_| ())?)
                .ok_or(())?;
            let tree = u32::try_from(global / u128::from(TREE_LEAF_COUNT)).map_err(|_| ())?;
            let position = u64::try_from(global % u128::from(TREE_LEAF_COUNT)).map_err(|_| ())?;
            let commitment = FixedBytes::from(commitment.to_be_bytes::<32>());
            let output = candidate
                .outputs
                .iter()
                .find(|output| {
                    output.tree == tree
                        && output.position == position
                        && output.commitment == commitment
                })
                .ok_or(())?;
            let note = output.note.clone().ok_or(())?;
            if !consumed_outputs.insert((tree, position, commitment)) {
                return Err(());
            }
            outputs.push(Utxo::new(
                note.clone(),
                tree,
                position,
                candidate.source.clone(),
                UtxoCommitmentKind::Transact,
            ));
            output_notes.push(note);
        }
        qualified.push(QualifiedSenderTransaction {
            txid_index: row.txid_index,
            public_row: row,
            output_start_global,
            outputs,
            output_notes,
        });
    }
    if qualified.is_empty()
        || consumed_spends.len() != candidate.wallet_spends.len()
        || candidate
            .wallet_spends
            .iter()
            .any(|spend| !consumed_spends.contains(spend))
        || candidate.outputs.iter().any(|output| {
            output.note.is_some()
                && !consumed_outputs.contains(&(output.tree, output.position, output.commitment))
        })
    {
        return Ok(None);
    }
    Ok(Some(qualified))
}

fn qualify_sender_row_inputs(
    candidate: &SenderTransactionCandidate,
    wallet_utxos: &[WalletUtxo],
    scan_keys: &railgun_wallet::scan::WalletScanKeys,
    row: &PublicTxidTransaction,
) -> Result<SenderRowQualification, ()> {
    let input_tree = u32::try_from(row.transaction.utxo_tree_in).map_err(|_| ())?;
    let mut nullifiers = BTreeSet::new();
    let mut resolved = 0;
    for nullifier in &row.transaction.nullifiers {
        if !nullifiers.insert(*nullifier) {
            return Err(());
        }
        let matches = wallet_utxos
            .iter()
            .filter(|wallet_utxo| {
                wallet_utxo.utxo.tree == input_tree
                    && wallet_utxo.utxo.nullifier(scan_keys.nullifying_key) == *nullifier
            })
            .collect::<Vec<_>>();
        if matches.is_empty() {
            continue;
        }
        if matches.len() != 1 {
            return Err(());
        }
        let wallet_utxo = matches[0];
        if wallet_utxo.spent.as_ref() != Some(&candidate.source)
            || !candidate
                .wallet_spends
                .contains(&SenderTransactionCandidateSpend {
                    tree: wallet_utxo.utxo.tree,
                    position: wallet_utxo.utxo.position,
                    commitment: wallet_utxo.utxo.poi.commitment,
                })
        {
            return Err(());
        }
        resolved += 1;
    }
    if resolved == 0 {
        Ok(SenderRowQualification::Foreign)
    } else if resolved == row.transaction.nullifiers.len() && resolved > 0 {
        Ok(SenderRowQualification::WalletAuthored)
    } else {
        Err(())
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
