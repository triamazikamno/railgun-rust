use std::collections::BTreeSet;
use std::fmt;

use crate::chain::ChainPublicDataPlaneCommitGuard;
use crate::types::PublicDataPlaneEpoch;

use super::output_poi_recovery::{
    OutputPoiProofSourceResolution, PublicCacheTxidRecoveryRequest, PublicCacheTxidRefreshRequest,
    RecoveryFailure, WalletNullifierIndex, build_recovery_chunk_for_public_transaction,
    new_output_poi_recovery_record_for_output, pending_output_poi_context_from_output_recovery,
    preflight_local_recovery_chunk_input_proofs, recovered_output_txid_data_from_public_cache,
    refresh_public_txid_cache,
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
    pub(super) retired_already_valid: usize,
    pub(super) awaiting_public_txid_data: u64,
    pub(super) awaiting_poi_data: u64,
    pub(super) retrying: u64,
    pub(super) needs_attention: u64,
    pub(super) expected_candidates: BTreeMap<FixedBytes<32>, Vec<u8>>,
}

impl SenderCandidateRecoveryReport {
    pub(super) const fn completed(&self) -> usize {
        self.materialized.saturating_add(self.retired_already_valid)
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
}

impl fmt::Debug for SenderCandidatePublicDataFence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SenderCandidatePublicDataFence")
            .field("epoch", &self.epoch)
            .field("row_count", &self.rows.len())
            .finish_non_exhaustive()
    }
}

impl SenderCandidatePublicDataFence {
    pub(super) fn new(
        public_data_plane: &ChainPublicDataPlane,
        cache_key: PublicTxidCacheKey,
        epoch: PublicDataPlaneEpoch,
        rows: Vec<PublicTxidTransaction>,
    ) -> Self {
        Self {
            public_data_plane: public_data_plane.clone(),
            cache_key,
            epoch,
            rows,
        }
    }

    pub(super) fn is_current(&self, outer_transaction_hash: FixedBytes<32>) -> bool {
        self.public_data_plane.current_epoch() == self.epoch
            && self
                .public_data_plane
                .txid_transactions_for_outer_hash(&self.cache_key, outer_transaction_hash)
                .is_ok_and(|rows| rows == self.rows)
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

struct SenderRecoveryRemoteProofSource<'a> {
    request: &'a OutputPoiRecoveryRequest<'a>,
    candidate: &'a SenderTransactionCandidate,
}

#[async_trait]
impl PoiMerkleProofSource for SenderRecoveryRemoteProofSource<'_> {
    async fn poi_merkle_proofs(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_key: &FixedBytes<32>,
        blinded_commitments: &[FixedBytes<32>],
    ) -> Result<Vec<PoiMerkleProof>, PreTransactionPoiError> {
        if !self.request.active_list_keys.contains(list_key) {
            return Err(PreTransactionPoiError::ProofSource(format!(
                "sender output recovery rejected non-active listKey={}",
                hex::encode(list_key)
            )));
        }
        match self
            .request
            .private_poi
            .poi_merkle_proofs(
                || async {
                    Ok::<bool, std::convert::Infallible>(
                        sender_candidate_still_current(
                            self.request.authority,
                            self.request.cache_store,
                            self.request.cfg,
                            self.candidate,
                        )
                        .await,
                    )
                },
                txid_version,
                chain_type,
                chain_id,
                list_key,
                blinded_commitments,
            )
            .await
        {
            Ok(proofs) => Ok(proofs),
            Err(WalletPrivateRemoteError::Remote(error)) => Err(error),
            Err(WalletPrivateRemoteError::Check(error)) => match error {},
            Err(WalletPrivateRemoteError::Stale(reason)) => {
                Err(PreTransactionPoiError::ProofSource(format!(
                    "sender output recovery proof request rejected: {reason:?}"
                )))
            }
        }
    }
}

enum AlreadyValidCandidateOutcome {
    Retired,
    Continue,
    AwaitingPoiData,
    Retry,
    Stale,
}

fn external_candidate_status_data(
    cfg: &WalletConfig,
    candidate: &SenderTransactionCandidate,
) -> Vec<BlindedCommitmentData> {
    candidate
        .outputs
        .iter()
        .filter_map(|output| {
            let note = output.note.as_ref()?;
            if note.npk == Note::npk_for(cfg.scan_keys.master_public_key, note.random) {
                return None;
            }
            let output = Utxo::new(
                note.clone(),
                output.tree,
                output.position,
                candidate.source.clone(),
                UtxoCommitmentKind::Transact,
            );
            Some(BlindedCommitmentData::transact(
                output.poi.blinded_commitment,
            ))
        })
        .collect()
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

fn candidate_statuses_are_valid(
    request_data: &[BlindedCommitmentData],
    active_list_keys: &[FixedBytes<32>],
    statuses: &BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PoiStatus>>,
) -> bool {
    !request_data.is_empty()
        && request_data.iter().all(|data| {
            statuses
                .get(&data.blinded_commitment)
                .is_some_and(|per_list| {
                    active_list_keys
                        .iter()
                        .all(|list_key| per_list.get(list_key) == Some(&PoiStatus::Valid))
                })
        })
}

async fn apply_already_valid_candidate(
    request: &OutputPoiRecoveryRequest<'_>,
    candidate: &SenderTransactionCandidate,
) -> AlreadyValidCandidateOutcome {
    match apply_poi_private_delta(
        request.authority,
        request.db,
        request.cache_store,
        request.cfg,
        OwnedPoiPrivateDelta::SenderCandidateAlreadyValid {
            expected_candidate: candidate.clone(),
            active_list_keys: request.active_list_keys.to_vec(),
        },
    )
    .await
    {
        Ok(PoiPrivateApplyOutcome::Applied { .. }) => AlreadyValidCandidateOutcome::Retired,
        Ok(PoiPrivateApplyOutcome::Skipped) => AlreadyValidCandidateOutcome::Stale,
        Err(_) => AlreadyValidCandidateOutcome::Retry,
    }
}

async fn retire_candidate_if_already_valid(
    request: &OutputPoiRecoveryRequest<'_>,
    candidate: &SenderTransactionCandidate,
    request_data: &[BlindedCommitmentData],
) -> AlreadyValidCandidateOutcome {
    if request_data.is_empty() || request.active_list_keys.is_empty() {
        return AlreadyValidCandidateOutcome::Continue;
    }
    match request.poi_runtime {
        WalletPoiRuntime::IndexedArtifacts { .. } => {
            let key = PublicPoiCorpusKey::wallet_default(request.cfg.chain.chain_id);
            if request
                .public_data_plane
                .poi_corpus_ready_for_lists(key.clone(), request.active_list_keys)
                .await
            {
                let Ok(corpus) = request.public_data_plane.ensure_poi_corpus(key).await else {
                    return AlreadyValidCandidateOutcome::AwaitingPoiData;
                };
                let _revision_fence = corpus.revision_read_fence().await;
                let reader = corpus.status_reader();
                let Ok(statuses) = reader
                    .pois_per_list(
                        DEFAULT_TXID_VERSION,
                        EVM_CHAIN_TYPE,
                        request.cfg.chain.chain_id,
                        request.active_list_keys,
                        request_data,
                    )
                    .await
                else {
                    return AlreadyValidCandidateOutcome::Retry;
                };
                if !candidate_statuses_are_valid(request_data, request.active_list_keys, &statuses)
                {
                    return AlreadyValidCandidateOutcome::Continue;
                }
                apply_already_valid_candidate(request, candidate).await
            } else if request.poi_runtime.wallet_read_fallback_enabled() {
                retire_candidate_if_already_valid_remote(request, candidate, request_data).await
            } else {
                AlreadyValidCandidateOutcome::AwaitingPoiData
            }
        }
        WalletPoiRuntime::PoiProxy { .. } => {
            retire_candidate_if_already_valid_remote(request, candidate, request_data).await
        }
    }
}

async fn retire_candidate_if_already_valid_remote(
    request: &OutputPoiRecoveryRequest<'_>,
    candidate: &SenderTransactionCandidate,
    request_data: &[BlindedCommitmentData],
) -> AlreadyValidCandidateOutcome {
    let statuses = match request
        .private_poi
        .pois_per_list(
            || async {
                Ok::<bool, std::convert::Infallible>(
                    sender_candidate_still_current(
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
            request.active_list_keys,
            request_data,
        )
        .await
    {
        Ok(statuses) => statuses,
        Err(WalletPrivateRemoteError::Stale(_)) => return AlreadyValidCandidateOutcome::Stale,
        Err(WalletPrivateRemoteError::Check(error)) => match error {},
        Err(WalletPrivateRemoteError::Remote(_)) => return AlreadyValidCandidateOutcome::Retry,
    };
    if !candidate_statuses_are_valid(request_data, request.active_list_keys, &statuses) {
        return AlreadyValidCandidateOutcome::Continue;
    }
    apply_already_valid_candidate(request, candidate).await
}

#[cfg(test)]
pub(super) async fn sender_recovery_remote_proofs_for_test(
    request: &OutputPoiRecoveryRequest<'_>,
    candidate: &SenderTransactionCandidate,
    list_key: &FixedBytes<32>,
    blinded_commitments: &[FixedBytes<32>],
) -> Result<Vec<PoiMerkleProof>, PreTransactionPoiError> {
    SenderRecoveryRemoteProofSource { request, candidate }
        .poi_merkle_proofs(
            DEFAULT_TXID_VERSION,
            EVM_CHAIN_TYPE,
            request.cfg.chain.chain_id,
            list_key,
            blinded_commitments,
        )
        .await
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
        let external_status_data = external_candidate_status_data(output_request.cfg, &candidate);
        let has_unknown_output = candidate.outputs.iter().any(|output| output.note.is_none());
        let output_count = u64::try_from(external_status_data.len())
            .unwrap_or(u64::MAX)
            .saturating_add(u64::from(has_unknown_output));
        let already_valid = if has_unknown_output {
            AlreadyValidCandidateOutcome::Continue
        } else {
            retire_candidate_if_already_valid(output_request, &candidate, &external_status_data)
                .await
        };
        match already_valid {
            AlreadyValidCandidateOutcome::Retired => {
                report.retired_already_valid = report.retired_already_valid.saturating_add(1);
                report.expected_candidates.remove(&candidate_id);
                continue;
            }
            AlreadyValidCandidateOutcome::AwaitingPoiData => {
                report.awaiting_poi_data = report.awaiting_poi_data.saturating_add(output_count);
                continue;
            }
            AlreadyValidCandidateOutcome::Retry => {
                report.retrying = report.retrying.saturating_add(output_count);
                continue;
            }
            AlreadyValidCandidateOutcome::Stale => continue,
            AlreadyValidCandidateOutcome::Continue => {}
        }
        let Some(spending_public_key) = output_request.cfg.spending_public_key else {
            report.retrying = report.retrying.saturating_add(output_count);
            continue;
        };
        let Some(prover) = output_request.cfg.poi_recovery_prover.as_ref() else {
            report.retrying = report.retrying.saturating_add(output_count);
            continue;
        };
        if output_request.active_list_keys.is_empty() {
            report.awaiting_poi_data = report.awaiting_poi_data.saturating_add(output_count);
            continue;
        }
        let mut data_epoch = output_request.public_data_plane.current_epoch();
        let mut rows = output_request
            .public_data_plane
            .txid_transactions_for_outer_hash(&cache_key, candidate.source.tx_hash);
        if matches!(&rows, Ok(rows) if rows.is_empty())
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
                    .txid_transactions_for_outer_hash(&cache_key, candidate.source.tx_hash);
            } else {
                report.retrying = report.retrying.saturating_add(output_count);
                continue;
            }
        }
        let mut rows = match rows {
            Ok(rows) if rows.is_empty() => {
                report.awaiting_public_txid_data = report
                    .awaiting_public_txid_data
                    .saturating_add(output_count);
                continue;
            }
            Ok(rows) => rows,
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
            rows = match output_request
                .public_data_plane
                .txid_transactions_for_outer_hash(&cache_key, candidate.source.tx_hash)
            {
                Ok(rows) if !rows.is_empty() => rows,
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
                report.awaiting_public_txid_data = report
                    .awaiting_public_txid_data
                    .saturating_add(output_count);
                continue;
            }
            Err(()) => {
                report.needs_attention = report.needs_attention.saturating_add(output_count);
                continue;
            }
        };
        let public_data_fence = SenderCandidatePublicDataFence::new(
            output_request.public_data_plane,
            cache_key.clone(),
            data_epoch,
            rows,
        );
        let prepared = match prepare_sender_candidate_materialization(
            output_request,
            &candidate,
            qualified,
            spending_public_key,
            prover,
        )
        .await
        {
            Ok(Some(prepared)) => prepared,
            Ok(None) => continue,
            Err(failure) => {
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
    let proof_source_resolution = request.resolve_proof_source(request.active_list_keys).await;
    let remote_proof_source = SenderRecoveryRemoteProofSource { request, candidate };
    let proof_source: &dyn PoiMerkleProofSource = match &proof_source_resolution {
        OutputPoiProofSourceResolution::Local { source, .. } => source,
        OutputPoiProofSourceResolution::RemoteFallback => &remote_proof_source,
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
        let recovery_chunk = build_recovery_chunk_for_public_transaction(
            qualified.output_start_global,
            qualified.output_notes,
            candidate.source.tx_hash,
            &wallet_nullifiers,
            &qualified.public_row.transaction,
            request.forest,
            request.active_list_keys,
            spending_public_key,
            &request.cfg.scan_keys,
            Some(qualified.txid_index),
        )?;
        if let OutputPoiProofSourceResolution::Local { source, .. } = &proof_source_resolution {
            preflight_local_recovery_chunk_input_proofs(
                Some(source),
                request.cfg,
                &recovery_chunk,
                request.active_list_keys,
            )
            .await?;
        }
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
        let pre_transaction_pois =
            generate_post_transaction_pois(PostTransactionPoiGenerationRequest {
                chunk: &recovery_chunk.chunk,
                txid_data: &txid_data.poi_data,
                chain_type: EVM_CHAIN_TYPE,
                chain_id: request.cfg.chain.chain_id,
                txid_version: Some(DEFAULT_TXID_VERSION),
                required_poi_list_keys: request.active_list_keys,
                proof_source,
                prover,
                verify_proof: OUTPUT_POI_RECOVERY_VERIFY_PROOF,
            })
            .await
            .map_err(|err| {
                RecoveryFailure::retryable(
                    OutputPoiRecoveryStatus::ProofGenerationFailed,
                    err.to_string(),
                    output_poi_recovery::output_poi_recovery_proof_retry_after(&err),
                )
            })?;
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
        OutputPoiProofSourceResolution::RemoteFallback
        | OutputPoiProofSourceResolution::Unavailable => None,
    };
    Ok(Some(PreparedSenderCandidateMaterialization {
        pending_updates,
        recovery_updates,
        owned_substitutes,
        proof_outputs: proof_outputs.into_iter().collect(),
        poi_corpus_revision_fence,
    }))
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
    use local_db::WalletCacheKey;

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
}
