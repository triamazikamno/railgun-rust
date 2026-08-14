use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;

use crate::chain::{ChainPublicDataPlaneCommitGuard, PublicTxidDataAuthority};
use crate::types::PublicDataPlaneEpoch;
use railgun_wallet::tx::PoiMerkleProofSource;

use super::output_poi_recovery::{
    OutputPoiProofSourceResolution, PublicCacheTxidRecoveryRequest, PublicCacheTxidRefreshRequest,
    RecoveryFailure, WalletNullifierIndex, build_recovery_chunk_for_public_transaction,
    new_output_poi_recovery_record_for_output, output_poi_recovery_proof_retry_after,
    pending_output_poi_context_from_output_recovery, preflight_local_recovery_chunk_input_proofs,
    recovered_output_txid_data_from_public_cache, refresh_public_txid_cache,
};
#[allow(clippy::wildcard_imports)]
use super::*;
pub(super) struct SenderCandidateRecoveryRequest<'a> {
    pub(super) output_recovery: OutputPoiRecoveryRequest<'a>,
    pub(super) candidates: Vec<SenderTransactionCandidate>,
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
    pub(super) expected_candidates: BTreeMap<FixedBytes<32>, Vec<u8>>,
}

impl SenderCandidateRecoveryReport {
    pub(super) const fn completed(&self) -> usize {
        self.materialized.saturating_add(self.retired_locally_valid)
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
struct QualifiedSenderTransaction {
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
pub(crate) fn classify_sender_candidate_for_local_retirement(
    candidate: &SenderTransactionCandidate,
    wallet_utxos: &[WalletUtxo],
    scan_keys: &railgun_wallet::scan::WalletScanKeys,
) -> Option<SenderCandidateLocalClassification> {
    candidate.validate().ok()?;

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
    if external_outputs.is_empty() {
        return None;
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
    if context.terminal_error.is_some()
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
    } = request;
    let output_request = &output_recovery;
    let mut report = SenderCandidateRecoveryReport {
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
    if candidates.is_empty() {
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
    let mut public_txid_cache_refreshed = None;
    for candidate in candidates {
        let candidate_id = candidate.semantic_id();
        let output_count = u64::try_from(candidate.outputs.len())
            .unwrap_or(u64::MAX)
            .max(1);
        if let Some(coverage) = sender_candidate_coverage(output_request, &candidate).await {
            report.covered_by_pending_contexts = report
                .covered_by_pending_contexts
                .saturating_add(coverage.pending_contexts);
            debug!(
                chain_id = output_request.cfg.chain.chain_id,
                covered_by_local_valid = coverage.local_valid,
                covered_by_pending_contexts = coverage.pending_contexts,
                "sender candidate recovery skipped covered candidate"
            );
            continue;
        }
        if let Some(corpus) = locally_valid_sender_candidate(output_request, &candidate).await {
            let apply_result = apply_poi_private_delta(
                output_request.authority,
                output_request.db,
                output_request.cache_store,
                output_request.cfg,
                OwnedPoiPrivateDelta::SenderCandidateLocallyValid {
                    expected_candidate: candidate.clone(),
                    corpus,
                },
            )
            .await;
            match apply_result {
                Ok(PoiPrivateApplyOutcome::Applied { .. }) => {
                    report.retired_locally_valid = report.retired_locally_valid.saturating_add(1);
                    report.expected_candidates.remove(&candidate_id);
                }
                Ok(PoiPrivateApplyOutcome::Skipped) => {}
                Err(_) => {
                    report.needs_attention = report.needs_attention.saturating_add(output_count);
                }
            }
            continue;
        }
        if output_request.active_list_keys.is_empty() {
            report.awaiting_poi_data = report.awaiting_poi_data.saturating_add(output_count);
            continue;
        }
        let proof_source_resolution = output_request
            .resolve_proof_source(output_request.active_list_keys)
            .await;
        if matches!(
            &proof_source_resolution,
            OutputPoiProofSourceResolution::Unavailable
        ) {
            log_local_poi_cache_unavailable(output_request.cfg, "sender_candidate_recovery");
            report.awaiting_poi_data = report.awaiting_poi_data.saturating_add(output_count);
            continue;
        }
        let mut data_epoch = output_request.public_data_plane.current_epoch();
        let mut rows = output_request
            .public_data_plane
            .txid_transactions_for_outer_hash_with_authority(&cache_key, candidate.source.tx_hash);
        if matches!(&rows, Ok((rows, _)) if rows.is_empty())
            || matches!(&rows, Err(TxidPublicCacheError::CacheNotReady { .. }))
        {
            let refreshed = refresh_sender_candidate_public_txid_cache(
                output_request,
                &cache_key,
                &mut public_txid_cache_refreshed,
            )
            .await;
            if refreshed {
                data_epoch = output_request.public_data_plane.current_epoch();
                rows = output_request
                    .public_data_plane
                    .txid_transactions_for_outer_hash_with_authority(
                        &cache_key,
                        candidate.source.tx_hash,
                    );
            } else {
                report.retrying = report.retrying.saturating_add(output_count);
                continue;
            }
        }
        let (mut rows, fetched_authority) = match rows {
            Ok((rows, _authority)) if rows.is_empty() => {
                report.awaiting_public_txid_data = report
                    .awaiting_public_txid_data
                    .saturating_add(output_count);
                continue;
            }
            Ok((rows, authority)) => (rows, authority),
            Err(TxidPublicCacheError::CacheNotReady { .. }) => {
                report.awaiting_public_txid_data = report
                    .awaiting_public_txid_data
                    .saturating_add(output_count);
                continue;
            }
            Err(_) => {
                report.retrying = report.retrying.saturating_add(output_count);
                continue;
            }
        };
        let mut authority = fetched_authority;
        let mut qualification = qualify_sender_candidate(
            &candidate,
            output_request.wallet_utxos,
            &output_request.cfg.scan_keys,
            rows.clone(),
        );
        if matches!(qualification, Ok(None)) && public_txid_cache_refreshed.is_none() {
            if !refresh_sender_candidate_public_txid_cache(
                output_request,
                &cache_key,
                &mut public_txid_cache_refreshed,
            )
            .await
            {
                report.retrying = report.retrying.saturating_add(output_count);
                continue;
            }
            data_epoch = output_request.public_data_plane.current_epoch();
            (rows, authority) = match output_request
                .public_data_plane
                .txid_transactions_for_outer_hash_with_authority(
                    &cache_key,
                    candidate.source.tx_hash,
                ) {
                Ok((rows, authority)) if !rows.is_empty() => (rows, authority),
                Ok(_) | Err(TxidPublicCacheError::CacheNotReady { .. }) => {
                    report.awaiting_public_txid_data = report
                        .awaiting_public_txid_data
                        .saturating_add(output_count);
                    continue;
                }
                Err(_) => {
                    report.retrying = report.retrying.saturating_add(output_count);
                    continue;
                }
            };
            qualification = qualify_sender_candidate(
                &candidate,
                output_request.wallet_utxos,
                &output_request.cfg.scan_keys,
                rows.clone(),
            );
        }
        let qualified = match qualification {
            Ok(Some(qualified)) => qualified,
            Ok(None) => {
                debug!(
                    chain_id = output_request.cfg.chain.chain_id,
                    category = "public_rows_do_not_cover_candidate",
                    "sender candidate recovery qualification incomplete"
                );
                report.awaiting_public_txid_data = report
                    .awaiting_public_txid_data
                    .saturating_add(output_count);
                continue;
            }
            Err(()) => {
                warn!(
                    chain_id = output_request.cfg.chain.chain_id,
                    category = "candidate_shape_or_wallet_association_mismatch",
                    "sender candidate recovery qualification failed"
                );
                report.needs_attention = report.needs_attention.saturating_add(output_count);
                continue;
            }
        };
        let public_data_fence = SenderCandidatePublicDataFence::new(
            output_request.public_data_plane,
            cache_key.clone(),
            data_epoch,
            rows,
            authority,
        );
        let Some(spending_public_key) = output_request.cfg.spending_public_key else {
            report.retrying = report.retrying.saturating_add(output_count);
            continue;
        };
        let Some(prover) = output_request.cfg.poi_recovery_prover.as_ref() else {
            report.retrying = report.retrying.saturating_add(output_count);
            continue;
        };
        let prepared = match prepare_sender_candidate_materialization(
            output_request,
            &candidate,
            qualified,
            spending_public_key,
            prover,
            &public_data_fence,
            proof_source_resolution,
        )
        .await
        {
            Ok(Some(prepared)) => prepared,
            Ok(None) => continue,
            Err(failure) => {
                warn!(
                    chain_id = output_request.cfg.chain.chain_id,
                    status = ?failure.status,
                    retryable = failure.retry_after.is_some(),
                    failure_category = failure.category,
                    "sender candidate recovery preparation failed"
                );
                if failure.retry_after.is_some() {
                    report.retrying = report.retrying.saturating_add(output_count);
                } else {
                    report.needs_attention = report.needs_attention.saturating_add(output_count);
                }
                continue;
            }
        };
        if output_request.public_data_plane.current_epoch() != data_epoch
            || !sender_candidate_still_current(
                output_request.authority,
                output_request.cache_store,
                output_request.cfg,
                &candidate,
            )
            .await
        {
            continue;
        }
        let PreparedSenderCandidateMaterialization {
            pending_updates,
            recovery_updates,
            owned_substitutes,
            proof_outputs,
            poi_corpus_revision_fence,
        } = prepared;
        let apply_result = apply_poi_private_delta(
            output_request.authority,
            output_request.db,
            output_request.cache_store,
            output_request.cfg,
            OwnedPoiPrivateDelta::SenderCandidateMaterialization {
                expected_candidate: candidate,
                public_data_fence,
                active_list_keys: output_request.active_list_keys.to_vec(),
                pending_updates,
                recovery_updates,
                owned_substitutes,
                proof_outputs,
            },
        )
        .await;
        drop(poi_corpus_revision_fence);
        match apply_result {
            Ok(PoiPrivateApplyOutcome::Applied { .. }) => {
                report.materialized = report.materialized.saturating_add(1);
                report.expected_candidates.remove(&candidate_id);
            }
            Ok(PoiPrivateApplyOutcome::Skipped) => {}
            Err(_) => report.needs_attention = report.needs_attention.saturating_add(output_count),
        }
    }
    debug!(
        chain_id = output_request.cfg.chain.chain_id,
        materialized = report.materialized,
        retired_locally_valid = report.retired_locally_valid,
        awaiting_public_txid_data = report.awaiting_public_txid_data,
        awaiting_poi_data = report.awaiting_poi_data,
        retrying = report.retrying,
        needs_attention = report.needs_attention,
        covered_by_pending_contexts = report.covered_by_pending_contexts,
        expected_candidates = report.expected_candidates.len(),
        "sender candidate recovery scan complete"
    );
    report
}

struct PreparedSenderCandidateMaterialization {
    pending_updates: Vec<PendingOutputPoiContextRecord>,
    recovery_updates: Vec<OutputPoiRecoveryRecord>,
    owned_substitutes: Vec<ExpectedWalletOutput>,
    proof_outputs: Vec<FixedBytes<32>>,
    poi_corpus_revision_fence: Option<tokio::sync::OwnedRwLockReadGuard<()>>,
}

async fn prepare_sender_candidate_materialization(
    request: &OutputPoiRecoveryRequest<'_>,
    candidate: &SenderTransactionCandidate,
    qualified: Vec<QualifiedSenderTransaction>,
    spending_public_key: [U256; 2],
    prover: &railgun_wallet::prover::ProverService,
    public_data_fence: &SenderCandidatePublicDataFence,
    proof_source_resolution: OutputPoiProofSourceResolution,
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
    let proof_source: &dyn PoiMerkleProofSource = match &proof_source_resolution {
        OutputPoiProofSourceResolution::Local { source, .. } => source,
        OutputPoiProofSourceResolution::Unavailable => return Ok(None),
    };
    let wallet_nullifiers = WalletNullifierIndex::new(request.wallet_utxos, &request.cfg.scan_keys);
    let now = now_epoch_secs();
    let mut pending_updates = Vec::new();
    let mut recovery_updates = Vec::new();
    let mut owned_substitutes = Vec::new();
    let mut proof_outputs = BTreeSet::new();
    for qualified in qualified {
        if qualified.outputs.is_empty() {
            return Ok(None);
        }
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
            qualified.output_notes,
            candidate.source.tx_hash,
            &wallet_nullifiers,
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
        let OutputPoiProofSourceResolution::Local { source, .. } = &proof_source_resolution else {
            return Ok(None);
        };
        preflight_local_recovery_chunk_input_proofs(
            Some(source),
            request.cfg,
            &recovery_chunk,
            request.active_list_keys,
        )
        .await?;
        let txid_data =
            recovered_output_txid_data_from_public_cache(PublicCacheTxidRecoveryRequest {
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
                proof_source,
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
        if qualified.public_row.transaction.has_unshield
            && !submit_sender_unshield_transaction_pois(
                request,
                candidate,
                public_data_fence,
                txid_data.poi_data.txid_merkleroot_index,
                &pre_transaction_pois,
            )
            .await?
        {
            return Ok(None);
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
            pending_updates.push(pending_output_poi_context_from_output_recovery(
                request.cfg,
                output,
                &recovery_chunk,
                txid_data.poi_data.txid_merkleroot_index,
                pre_transaction_pois.clone(),
                request.active_list_keys,
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
    let poi_corpus_revision_fence = match proof_source_resolution {
        OutputPoiProofSourceResolution::Local { revision_fence, .. } => Some(revision_fence),
        OutputPoiProofSourceResolution::Unavailable => None,
    };
    Ok(Some(PreparedSenderCandidateMaterialization {
        pending_updates,
        recovery_updates,
        owned_substitutes,
        proof_outputs: proof_outputs.into_iter().collect(),
        poi_corpus_revision_fence,
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

async fn submit_sender_unshield_transaction_pois(
    request: &OutputPoiRecoveryRequest<'_>,
    candidate: &SenderTransactionCandidate,
    public_data_fence: &SenderCandidatePublicDataFence,
    txid_merkleroot_index: u64,
    pre_transaction_pois: &PreTransactionPoiMap,
) -> Result<bool, RecoveryFailure> {
    for list_key in request.active_list_keys {
        let Some(per_leaf) = pre_transaction_pois.get(list_key) else {
            return Ok(false);
        };
        for poi in per_leaf.values() {
            match request
                .private_poi
                .submit_transact_proof(
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
        if private_output_count == 0 {
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
mod tests {
    use super::*;
    use crate::sender_candidate::SenderTransactionCandidateOutput;
    use crate::txid_cache::TxidPublicCacheTransaction;
    use alloy::primitives::Address;
    use broadcaster_core::crypto::railgun::ViewingKeyData;
    use broadcaster_core::transact::{PreTxPoi, SnarkJsProof};
    use local_db::WalletCacheKey;

    fn sample_pre_tx_poi() -> PreTxPoi {
        PreTxPoi {
            snark_proof: SnarkJsProof::zero(),
            txid_merkleroot: FixedBytes::ZERO,
            poi_merkleroots: vec![FixedBytes::ZERO],
            blinded_commitments_out: vec![FixedBytes::ZERO],
            railgun_txid_if_has_unshield: alloy::primitives::Bytes::copy_from_slice(&[0_u8]),
        }
    }

    fn fixture() -> (
        ViewingKeyData,
        SenderTransactionCandidate,
        WalletUtxo,
        PublicTxidTransaction,
    ) {
        let keys =
            ViewingKeyData::from_spending_public_key([0x11; 32], [U256::from(2), U256::from(3)]);
        let input_note = Note::new_change(
            keys.master_public_key,
            Address::from([0x22; 20]),
            U256::from(10),
            [0x33; 16],
        );
        let input_source = UtxoSource {
            tx_hash: FixedBytes::from([0x44; 32]),
            block_number: 4,
            block_timestamp: 40,
        };
        let mut input = WalletUtxo {
            utxo: Utxo::new(input_note, 1, 7, input_source, UtxoCommitmentKind::Transact),
            spent: None,
        };
        let source = UtxoSource {
            tx_hash: FixedBytes::from([0x55; 32]),
            block_number: 5,
            block_timestamp: 50,
        };
        input.spent = Some(source.clone());
        let output_note = Note::new_change(
            U256::from(9),
            Address::from([0x22; 20]),
            U256::from(10),
            [0x66; 16],
        );
        let output_commitment = FixedBytes::from(output_note.commitment().to_be_bytes::<32>());
        let candidate = SenderTransactionCandidate::new(
            1,
            WalletCacheKey::from_opaque_bytes(b"sender-qualification").expect("wallet key"),
            source.clone(),
            vec![SenderTransactionCandidateSpend {
                tree: input.utxo.tree,
                position: input.utxo.position,
                commitment: input.utxo.poi.commitment,
            }],
            vec![SenderTransactionCandidateOutput {
                tree: 2,
                position: 3,
                commitment: output_commitment,
                note: Some(output_note),
            }],
        )
        .expect("candidate");
        let row = PublicTxidTransaction {
            txid_index: 8,
            transaction: TxidPublicCacheTransaction {
                id: "8".to_string(),
                transaction_hash: source.tx_hash,
                block_number: source.block_number,
                block_timestamp: source.block_timestamp,
                merkle_root: U256::from(1),
                nullifiers: vec![input.utxo.nullifier(keys.nullifying_key)],
                commitments: vec![U256::from_be_bytes(output_commitment.0)],
                bound_params_hash: U256::from(2),
                has_unshield: false,
                unshield_preimage: None,
                utxo_tree_in: 1,
                utxo_tree_out: 2,
                utxo_batch_start_position_out: 3,
            },
        };
        (keys, candidate, input, row)
    }

    #[test]
    fn exact_foreign_and_mixed_rows_qualify_fail_closed() {
        let (keys, candidate, input, row) = fixture();
        assert_eq!(
            qualify_sender_row_inputs(&candidate, std::slice::from_ref(&input), &keys, &row),
            Ok(SenderRowQualification::WalletAuthored)
        );

        let mut foreign = row.clone();
        foreign.transaction.nullifiers = vec![U256::from(999)];
        assert_eq!(
            qualify_sender_row_inputs(&candidate, std::slice::from_ref(&input), &keys, &foreign),
            Ok(SenderRowQualification::Foreign)
        );

        let mut mixed = row.clone();
        mixed.transaction.nullifiers.push(U256::from(999));
        assert!(
            qualify_sender_row_inputs(&candidate, std::slice::from_ref(&input), &keys, &mixed)
                .is_err()
        );

        let mut duplicate = row;
        duplicate
            .transaction
            .nullifiers
            .push(duplicate.transaction.nullifiers[0]);
        assert!(qualify_sender_row_inputs(&candidate, &[input], &keys, &duplicate).is_err());
    }

    #[test]
    fn complete_mixed_batch_qualifies_every_wallet_authored_chunk_in_order() {
        let (keys, candidate, first_input, first_row) = fixture();
        let source = candidate.source.clone();
        let second_input_note = Note::new_change(
            keys.master_public_key,
            Address::from([0x22; 20]),
            U256::from(11),
            [0x88; 16],
        );
        let mut second_input = WalletUtxo {
            utxo: Utxo::new(
                second_input_note,
                1,
                8,
                UtxoSource {
                    tx_hash: FixedBytes::from([0x89; 32]),
                    block_number: 4,
                    block_timestamp: 40,
                },
                UtxoCommitmentKind::Transact,
            ),
            spent: None,
        };
        second_input.spent = Some(source.clone());
        let second_output_note = Note::new_change(
            U256::from(10),
            Address::from([0x22; 20]),
            U256::from(11),
            [0x99; 16],
        );
        let second_output_commitment =
            FixedBytes::from(second_output_note.commitment().to_be_bytes::<32>());
        let candidate = SenderTransactionCandidate::new(
            candidate.chain_id,
            candidate.wallet_id.clone(),
            source,
            vec![
                SenderTransactionCandidateSpend {
                    tree: first_input.utxo.tree,
                    position: first_input.utxo.position,
                    commitment: first_input.utxo.poi.commitment,
                },
                SenderTransactionCandidateSpend {
                    tree: second_input.utxo.tree,
                    position: second_input.utxo.position,
                    commitment: second_input.utxo.poi.commitment,
                },
            ],
            vec![
                candidate.outputs[0].clone(),
                SenderTransactionCandidateOutput {
                    tree: 2,
                    position: 4,
                    commitment: second_output_commitment,
                    note: Some(second_output_note),
                },
            ],
        )
        .expect("complete candidate");
        let mut foreign_row = first_row.clone();
        foreign_row.txid_index = 9;
        foreign_row.transaction.id = "9".to_string();
        foreign_row.transaction.nullifiers = vec![U256::from(999)];
        let mut second_row = first_row.clone();
        second_row.txid_index = 10;
        second_row.transaction.id = "10".to_string();
        second_row.transaction.nullifiers = vec![second_input.utxo.nullifier(keys.nullifying_key)];
        second_row.transaction.commitments = vec![U256::from_be_bytes(second_output_commitment.0)];
        second_row.transaction.utxo_batch_start_position_out = 4;

        let qualified = qualify_sender_candidate(
            &candidate,
            &[first_input.clone(), second_input.clone()],
            &keys,
            vec![first_row, foreign_row, second_row],
        )
        .expect("complete rows are valid")
        .expect("all candidate evidence is covered");

        assert_eq!(
            qualified
                .iter()
                .map(|chunk| chunk.txid_index)
                .collect::<Vec<_>>(),
            vec![8, 10]
        );
        assert_eq!(
            qualified
                .iter()
                .flat_map(|chunk| chunk.outputs.iter())
                .map(|output| (output.tree, output.position, output.poi.commitment))
                .collect::<Vec<_>>(),
            candidate
                .outputs
                .iter()
                .map(|output| (output.tree, output.position, output.commitment))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            qualified
                .iter()
                .flat_map(|chunk| chunk.public_row.transaction.nullifiers.iter().copied())
                .collect::<BTreeSet<_>>(),
            [
                first_input.utxo.nullifier(keys.nullifying_key),
                second_input.utxo.nullifier(keys.nullifying_key),
            ]
            .into_iter()
            .collect()
        );
        assert!(!qualified.iter().any(|chunk| chunk.txid_index == 9));
    }

    #[test]
    fn missing_txid_or_output_data_keeps_candidate_unqualified() {
        let (keys, candidate, input, row) = fixture();
        assert!(
            qualify_sender_candidate(&candidate, std::slice::from_ref(&input), &keys, Vec::new())
                .expect("TXID lag is retryable")
                .is_none()
        );

        let mut wrong_output = row;
        wrong_output.transaction.commitments[0] = U256::from(123);
        assert!(qualify_sender_candidate(&candidate, &[input], &keys, vec![wrong_output]).is_err());
    }

    #[test]
    fn local_retirement_classifier_requires_exact_spends_and_classifies_owned_change() {
        let (keys, candidate, input, _) = fixture();
        let owned_note = Note::new_change(
            keys.master_public_key,
            Address::from([0x22; 20]),
            U256::from(3),
            [0x77; 16],
        );
        let owned_output = SenderTransactionCandidateOutput {
            tree: 2,
            position: 4,
            commitment: FixedBytes::from(owned_note.commitment().to_be_bytes::<32>()),
            note: Some(owned_note.clone()),
        };
        let mixed = SenderTransactionCandidate::new(
            candidate.chain_id,
            candidate.wallet_id.clone(),
            candidate.source.clone(),
            candidate.wallet_spends.clone(),
            vec![candidate.outputs[0].clone(), owned_output.clone()],
        )
        .expect("mixed candidate");
        let owned_utxo = WalletUtxo {
            utxo: Utxo::new(
                owned_note,
                owned_output.tree,
                owned_output.position,
                mixed.source.clone(),
                UtxoCommitmentKind::Transact,
            ),
            spent: None,
        };

        let classification = classify_sender_candidate_for_local_retirement(
            &mixed,
            &[input.clone(), owned_utxo],
            &keys,
        )
        .expect("exact mixed candidate classification");
        assert_eq!(classification.external_outputs.len(), 1);

        let mut extra_spend = input;
        extra_spend.utxo.position += 1;
        extra_spend.spent = Some(mixed.source.clone());
        assert!(
            classify_sender_candidate_for_local_retirement(&mixed, &[extra_spend], &keys,)
                .is_none()
        );
    }

    #[test]
    fn pending_context_coverage_requires_current_observation_and_retained_pois() {
        let (_keys, candidate, _input, _) = fixture();
        let list_key = FixedBytes::from([0x77; 32]);
        let output = &candidate.outputs[0];
        let note = output.note.as_ref().expect("fixture note");
        let mut context = PendingOutputPoiContextRecord {
            chain_id: candidate.chain_id,
            wallet_id: candidate.wallet_id.to_string(),
            txid_version: DEFAULT_TXID_VERSION.to_string(),
            output_commitment: output.commitment,
            output_npk: FixedBytes::from(note.npk.to_be_bytes::<32>()),
            utxo_tree_in: 1,
            railgun_txid: U256::ZERO,
            txid_merkleroot_index: None,
            pre_transaction_pois_per_txid_leaf_per_list: BTreeMap::from([(
                list_key,
                BTreeMap::from([(FixedBytes::from([0x88; 32]), sample_pre_tx_poi())]),
            )]),
            required_poi_list_keys: vec![list_key],
            output_role: PendingOutputPoiRole::Recipient,
            created_at: 1,
            source_operation_id: None,
            observation: Some(PendingOutputPoiObservation {
                output_tree: u64::from(output.tree),
                output_position: output.position,
                tx_hash: candidate.source.tx_hash,
                block_number: candidate.source.block_number,
                block_timestamp: candidate.source.block_timestamp,
            }),
            submitted_poi_list_keys: Vec::new(),
            terminal_error: None,
        };

        assert!(pending_context_covers_sender_output(
            candidate.chain_id,
            candidate.wallet_id.as_str(),
            &candidate,
            output,
            &[list_key],
            &context,
        ));
        context.observation.as_mut().expect("observation").tx_hash = FixedBytes::from([0xaa; 32]);
        assert!(!pending_context_covers_sender_output(
            candidate.chain_id,
            candidate.wallet_id.as_str(),
            &candidate,
            output,
            &[list_key],
            &context,
        ));
        context.observation.as_mut().expect("observation").tx_hash = candidate.source.tx_hash;
        context
            .observation
            .as_mut()
            .expect("observation")
            .block_number += 1;
        assert!(!pending_context_covers_sender_output(
            candidate.chain_id,
            candidate.wallet_id.as_str(),
            &candidate,
            output,
            &[list_key],
            &context,
        ));
        context
            .observation
            .as_mut()
            .expect("observation")
            .block_number = candidate.source.block_number;
        context.output_npk = FixedBytes::from([0x99; 32]);
        assert!(!pending_context_covers_sender_output(
            candidate.chain_id,
            candidate.wallet_id.as_str(),
            &candidate,
            output,
            &[list_key],
            &context,
        ));
        context.output_npk = FixedBytes::from(note.npk.to_be_bytes::<32>());
        context.observation = None;
        assert!(!pending_context_covers_sender_output(
            candidate.chain_id,
            candidate.wallet_id.as_str(),
            &candidate,
            output,
            &[list_key],
            &context,
        ));
        context.observation = Some(PendingOutputPoiObservation {
            output_tree: u64::from(output.tree),
            output_position: output.position,
            tx_hash: candidate.source.tx_hash,
            block_number: candidate.source.block_number,
            block_timestamp: candidate.source.block_timestamp,
        });
        context.pre_transaction_pois_per_txid_leaf_per_list.clear();
        assert!(!pending_context_covers_sender_output(
            candidate.chain_id,
            candidate.wallet_id.as_str(),
            &candidate,
            output,
            &[list_key],
            &context,
        ));
    }

    #[test]
    fn mixed_sender_candidate_coverage_uses_local_and_pending_routes_without_retiring() {
        let (_keys, mut candidate, _input, _) = fixture();
        let second_note = Note::new_change(
            U256::from(9),
            Address::from([0x22; 20]),
            U256::from(11),
            [0x67; 16],
        );
        let second_output = SenderTransactionCandidateOutput {
            tree: 2,
            position: 4,
            commitment: FixedBytes::from(second_note.commitment().to_be_bytes::<32>()),
            note: Some(second_note),
        };
        let third_note = Note::new_change(
            U256::from(9),
            Address::from([0x22; 20]),
            U256::from(12),
            [0x68; 16],
        );
        let third_output = SenderTransactionCandidateOutput {
            tree: 2,
            position: 5,
            commitment: FixedBytes::from(third_note.commitment().to_be_bytes::<32>()),
            note: Some(third_note),
        };
        candidate.outputs.extend([second_output, third_output]);
        candidate
            .outputs
            .sort_by_key(|output| (output.tree, output.position));

        let local = BTreeSet::from([candidate.outputs[0].commitment]);
        // These represent fresh pending contexts accepted by the predicate above.
        let fresh_pending_contexts = BTreeSet::from([
            candidate.outputs[1].commitment,
            candidate.outputs[2].commitment,
        ]);
        let coverage =
            sender_candidate_coverage_from_routes(&candidate, &local, &fresh_pending_contexts)
                .expect("mixed coverage should short-circuit");
        assert_eq!(coverage.local_valid, 1);
        assert_eq!(coverage.pending_contexts, 2);

        let all_local = candidate
            .outputs
            .iter()
            .map(|output| output.commitment)
            .collect();
        assert!(
            sender_candidate_coverage_from_routes(&candidate, &all_local, &BTreeSet::new())
                .is_none()
        );

        let missing = BTreeSet::from([candidate.outputs[1].commitment]);
        assert!(sender_candidate_coverage_from_routes(&candidate, &local, &missing).is_none());
    }

    #[tokio::test]
    async fn sender_candidate_proof_generation_timeout_is_retryable() {
        let failure = generate_sender_candidate_post_transaction_pois_with_timeout(
            std::future::pending(),
            Duration::from_millis(1),
        )
        .await
        .expect_err("hanging proof generation must time out");
        assert_eq!(failure.category, "proof_generation_timeout");
        assert!(failure.retry_after.is_some());
    }
}
