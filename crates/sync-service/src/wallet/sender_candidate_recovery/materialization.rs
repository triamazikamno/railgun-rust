//! Proving a sender candidate's transactions and preparing the records that materialize it.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;

use crate::wallet::output_poi_recovery::{
    OutputPoiProofSourceResolution, PublicCacheTxidRecoveryRequest, RecoveredOutputTxidData,
    RecoveryChunk, RecoveryFailure, WalletNullifierIndex,
    build_recovery_chunk_for_public_transaction, new_output_poi_recovery_record_for_output,
    output_poi_recovery_proof_retry_after, pending_output_poi_context_from_output_recovery,
    preflight_local_recovery_chunk_input_proofs, recovered_output_txid_data_from_public_cache,
};
use crate::wallet::saved_poi_compatibility::saved_pending_context_is_compatible;
use crate::wallet::{
    DEFAULT_TXID_VERSION, Duration, EVM_CHAIN_TYPE, ExpectedPoiCorpusRevision,
    ExpectedWalletOutput, FixedBytes, Instant, OUTPUT_POI_RECOVERY_PROOF_FAILURE_RETRY_AFTER,
    OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER, OUTPUT_POI_RECOVERY_VERIFY_PROOF,
    OutputPoiRecoveryAction, OutputPoiRecoveryRecord, OutputPoiRecoveryRequest,
    OutputPoiRecoveryStatus, PendingOutputPoiContextRecord, PendingOutputPoiRole,
    PostTransactionPoiGenerationRequest, PreTransactionPoiError, PreTransactionPoiMap,
    SenderTransactionCandidate, U256, Utxo, WalletUtxo, debug, generate_post_transaction_pois, hex,
    now_epoch_secs,
};

use super::unshield::sender_unshield_railgun_txid;
use super::{QualifiedSenderTransaction, sender_candidate_still_current};

pub(super) struct PreparedSenderCandidateMaterialization {
    pub(super) pending_updates: Vec<PendingOutputPoiContextRecord>,
    pub(super) recovery_updates: Vec<OutputPoiRecoveryRecord>,
    pub(super) owned_substitutes: Vec<ExpectedWalletOutput>,
    pub(super) proof_outputs: Vec<FixedBytes<32>>,
    pub(super) expected_corpus: ExpectedPoiCorpusRevision,
    pub(super) replacement_group: Vec<(
        PendingOutputPoiContextRecord,
        Option<OutputPoiRecoveryRecord>,
    )>,
    pub(super) external_valid_substitutes: Vec<Utxo>,
    /// Proofs of rows in the requested unshield work, reused for their unshield submission.
    pub(super) unshield_proofs: BTreeMap<FixedBytes<32>, (u64, PreTransactionPoiMap)>,
}

pub(super) struct ProvedSenderTransaction {
    recovery_chunk: RecoveryChunk,
    pub(super) txid_data: RecoveredOutputTxidData,
    pub(super) pre_transaction_pois: PreTransactionPoiMap,
}

/// What proving a sender candidate's transactions needs.
pub(super) struct SenderCandidateProver<'p> {
    pub(super) request: &'p OutputPoiRecoveryRequest<'p>,
    pub(super) candidate: &'p SenderTransactionCandidate,
    pub(super) wallet_nullifiers: &'p WalletNullifierIndex<'p>,
    pub(super) spending_public_key: [U256; 2],
    pub(super) prover: &'p railgun_wallet::prover::ProverService,
    pub(super) proof_source_resolution: &'p OutputPoiProofSourceResolution,
}

/// Output routing inputs and the records collected so far for one materialization.
#[derive(Default)]
struct SenderMaterializationRecords {
    valid_by_list: BTreeMap<FixedBytes<32>, BTreeSet<FixedBytes<32>>>,
    now: u64,
    pending_updates: Vec<PendingOutputPoiContextRecord>,
    recovery_updates: Vec<OutputPoiRecoveryRecord>,
    owned_substitutes: Vec<ExpectedWalletOutput>,
    proof_outputs: BTreeSet<FixedBytes<32>>,
    external_valid_substitutes: Vec<Utxo>,
    unshield_proofs: BTreeMap<FixedBytes<32>, (u64, PreTransactionPoiMap)>,
}

/// Where a qualified output goes when its candidate is materialized.
enum SenderOutputRoute {
    /// The wallet already holds the output.
    Owned(ExpectedWalletOutput),
    /// Every active list already has the output Valid.
    ExternallyValid,
    /// The active lists still missing the output's proof.
    Pending(Vec<FixedBytes<32>>),
}

impl SenderCandidateProver<'_> {
    /// Prove one qualified sender transaction from the local proof source.
    ///
    /// `Ok(None)` means the candidate or proof source went stale and nothing was proved.
    pub(super) async fn prove(
        &self,
        qualified: &QualifiedSenderTransaction,
    ) -> Result<Option<ProvedSenderTransaction>, RecoveryFailure> {
        let Self {
            request,
            candidate,
            wallet_nullifiers,
            spending_public_key,
            prover,
            proof_source_resolution,
        } = *self;
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

    /// Prove the candidate's transactions and collect the records that materialize its outputs.
    ///
    /// `Ok(None)` means the candidate, a proof or the proof source went stale or did not match.
    pub(super) async fn prepare_materialization(
        &self,
        qualified: &[QualifiedSenderTransaction],
        unshield_work: &BTreeSet<FixedBytes<32>>,
    ) -> Result<Option<PreparedSenderCandidateMaterialization>, RecoveryFailure> {
        let request = self.request;
        if !sender_candidate_still_current(
            request.authority,
            request.cache_store,
            request.cfg,
            self.candidate,
        )
        .await
        {
            return Ok(None);
        }
        if matches!(
            self.proof_source_resolution,
            OutputPoiProofSourceResolution::Unavailable
        ) {
            return Ok(None);
        }
        let replacement_group = sender_candidate_replacement_group(request, self.candidate)?;
        let Some(expected_corpus) = self.proof_source_resolution.expected_corpus_revision() else {
            return Ok(None);
        };
        let valid_by_list =
            valid_sender_outputs_by_list(request, qualified, &expected_corpus).await?;
        let mut records = SenderMaterializationRecords {
            valid_by_list,
            now: now_epoch_secs(),
            ..SenderMaterializationRecords::default()
        };
        for qualified in qualified {
            if qualified.outputs.is_empty() {
                continue;
            }
            if self
                .add_transaction(&mut records, qualified, unshield_work)
                .await?
                .is_none()
            {
                return Ok(None);
            }
        }
        let Some(expected_corpus) = self.proof_source_resolution.expected_corpus_revision() else {
            return Ok(None);
        };
        Ok(Some(PreparedSenderCandidateMaterialization {
            pending_updates: records.pending_updates,
            recovery_updates: records.recovery_updates,
            owned_substitutes: records.owned_substitutes,
            proof_outputs: records.proof_outputs.into_iter().collect(),
            expected_corpus,
            replacement_group,
            external_valid_substitutes: records.external_valid_substitutes,
            unshield_proofs: records.unshield_proofs,
        }))
    }

    /// Prove one transaction with outputs, then add its proof outputs, its unshield proof and
    /// its output records. `Ok(None)` means it went stale or its proofs did not match.
    async fn add_transaction(
        &self,
        records: &mut SenderMaterializationRecords,
        qualified: &QualifiedSenderTransaction,
        unshield_work: &BTreeSet<FixedBytes<32>>,
    ) -> Result<Option<()>, RecoveryFailure> {
        let Some(proved) = self.prove(qualified).await? else {
            return Ok(None);
        };
        let Some(transaction_proof_outputs) =
            transaction_proof_outputs(self.request.active_list_keys, &proved.pre_transaction_pois)
        else {
            return Ok(None);
        };
        if transaction_proof_outputs
            .iter()
            .any(|output| !records.proof_outputs.insert(*output))
        {
            return Ok(None);
        }
        if qualified.public_row.transaction.has_unshield {
            let txid = sender_unshield_railgun_txid(qualified);
            if unshield_work.contains(&txid) {
                records.unshield_proofs.insert(
                    txid,
                    (
                        proved.txid_data.poi_data.txid_merkleroot_index,
                        proved.pre_transaction_pois.clone(),
                    ),
                );
            }
        }
        Ok(self.record_outputs(records, qualified, &proved))
    }

    /// Route each output of a proved transaction and add its records. `None` means the wallet
    /// holds a conflicting output at one of its coordinates.
    fn record_outputs(
        &self,
        records: &mut SenderMaterializationRecords,
        qualified: &QualifiedSenderTransaction,
        proved: &ProvedSenderTransaction,
    ) -> Option<()> {
        let request = self.request;
        for output in &qualified.outputs {
            let target_lists =
                match route_sender_output(request, self.candidate, output, &records.valid_by_list)?
                {
                    SenderOutputRoute::Owned(expected) => {
                        records.owned_substitutes.push(expected);
                        continue;
                    }
                    SenderOutputRoute::ExternallyValid => {
                        records.external_valid_substitutes.push(output.clone());
                        continue;
                    }
                    SenderOutputRoute::Pending(target_lists) => target_lists,
                };
            let mut output_proofs = proved.pre_transaction_pois.clone();
            output_proofs.retain(|list_key, _| target_lists.contains(list_key));
            records
                .pending_updates
                .push(pending_output_poi_context_from_output_recovery(
                    request.cfg,
                    output,
                    &proved.recovery_chunk,
                    proved.txid_data.poi_data.txid_merkleroot_index,
                    output_proofs,
                    &target_lists,
                    PendingOutputPoiRole::RecoveredOutgoing,
                    format!(
                        "recovered-sender-output-poi:{}:{}",
                        hex::encode(self.candidate.source.tx_hash),
                        qualified.txid_index
                    ),
                    records.now,
                ));
            let mut recovery = new_output_poi_recovery_record_for_output(
                request.cfg,
                output,
                OutputPoiRecoveryStatus::Recoverable,
                records.now,
            );
            recovery.apply_action(
                OutputPoiRecoveryAction::Detected {
                    status: OutputPoiRecoveryStatus::Recoverable,
                    retry_after: None,
                    last_error: None,
                    increment_attempts: false,
                },
                records.now,
            );
            records.recovery_updates.push(recovery);
        }
        Some(())
    }
}

/// The candidate's pending proof contexts with their recovery records when any of them is
/// incompatible and must be replaced; otherwise empty.
fn sender_candidate_replacement_group(
    request: &OutputPoiRecoveryRequest<'_>,
    candidate: &SenderTransactionCandidate,
) -> Result<
    Vec<(
        PendingOutputPoiContextRecord,
        Option<OutputPoiRecoveryRecord>,
    )>,
    RecoveryFailure,
> {
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
    if replacing {
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
            })
    } else {
        Ok(Vec::new())
    }
}

/// Each active list's Valid outputs among the qualified transactions' blinded commitments.
async fn valid_sender_outputs_by_list(
    request: &OutputPoiRecoveryRequest<'_>,
    qualified: &[QualifiedSenderTransaction],
    expected_corpus: &ExpectedPoiCorpusRevision,
) -> Result<BTreeMap<FixedBytes<32>, BTreeSet<FixedBytes<32>>>, RecoveryFailure> {
    let candidate_blinded = qualified
        .iter()
        .flat_map(|transaction| {
            transaction
                .outputs
                .iter()
                .map(|output| output.poi.blinded_commitment)
        })
        .collect::<Vec<_>>();
    super::saved_poi_compatibility::corpus_valid_outputs_by_list(
        &expected_corpus.corpus,
        request.cfg.chain.chain_id,
        request.active_list_keys,
        &candidate_blinded,
    )
    .await
    .ok_or_else(|| {
        RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::Recoverable,
            "output POI status is unavailable",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        )
    })
}

/// The blinded outputs a transaction's proofs commit to, or `None` when a list's proofs are
/// missing, repeat an output or disagree with another list's.
fn transaction_proof_outputs(
    active_list_keys: &[FixedBytes<32>],
    pre_transaction_pois: &PreTransactionPoiMap,
) -> Option<BTreeSet<FixedBytes<32>>> {
    let mut transaction_proof_outputs = None;
    for list_key in active_list_keys {
        let per_leaf = pre_transaction_pois.get(list_key)?;
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
            return None;
        }
        transaction_proof_outputs = Some(outputs);
    }
    transaction_proof_outputs
}

/// Where a qualified output goes, or `None` when the wallet holds a conflicting output at its
/// coordinates.
fn route_sender_output(
    request: &OutputPoiRecoveryRequest<'_>,
    candidate: &SenderTransactionCandidate,
    output: &Utxo,
    valid_by_list: &BTreeMap<FixedBytes<32>, BTreeSet<FixedBytes<32>>>,
) -> Option<SenderOutputRoute> {
    let expected = ExpectedWalletOutput::new(&WalletUtxo::new(output.clone()));
    let coordinate_matches = request
        .wallet_utxos
        .iter()
        .filter(|current| {
            !current.is_spent()
                && (
                    current.utxo.tree,
                    current.utxo.position,
                    current.utxo.poi.commitment,
                ) == (output.tree, output.position, output.poi.commitment)
                && current.utxo.source == candidate.source
        })
        .collect::<Vec<_>>();
    if coordinate_matches.len() > 1
        || coordinate_matches
            .first()
            .is_some_and(|current| !expected.matches(current))
    {
        return None;
    }
    if let Some(current) = coordinate_matches.first() {
        return Some(SenderOutputRoute::Owned(ExpectedWalletOutput::new(current)));
    }
    let target_lists = super::saved_poi_compatibility::unresolved_output_lists(
        request.active_list_keys,
        output.poi.blinded_commitment,
        valid_by_list,
    );
    if target_lists.is_empty() {
        return Some(SenderOutputRoute::ExternallyValid);
    }
    Some(SenderOutputRoute::Pending(target_lists))
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

pub(super) async fn generate_sender_candidate_post_transaction_pois_with_timeout<F>(
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
