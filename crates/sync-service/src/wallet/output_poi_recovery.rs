use super::saved_poi_compatibility::saved_pending_context_is_compatible;
use railgun_wallet::tx::PoiMerkleProofSource;

use crate::types::PoiCorpusRevision;

use super::{
    Arc, ChainPublicDataPlane, ChainScope, ChainType, DEFAULT_TXID_VERSION, DbStore, Duration,
    EVM_CHAIN_TYPE, ExpectedPoiCorpusRevision, ExpectedPoiStatus, ExpectedWalletOutput, FixedBytes,
    HashMap, IndexedArtifactSourceConfig, InputWitness, Instant, LocalPoiMerkleProofSource,
    MerkleForest, Note, OUTPUT_POI_RECOVERY_PROOF_FAILURE_RETRY_AFTER,
    OUTPUT_POI_RECOVERY_SLOW_STEP_AFTER, OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
    OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER, OUTPUT_POI_RECOVERY_VERIFY_PROOF,
    OutputPoiRecoveryAction, OutputPoiRecoveryRecord, OutputPoiRecoveryStatus, OutputRecoveryDelta,
    OwnedPoiPrivateDelta, PendingOutputPoiContextRecord, PoiPrivateApplyOutcome, PoiRpcClient,
    PoiStatus, PostTransactionPoiData, PostTransactionPoiGenerationRequest, PreTransactionPoiError,
    PrivateInputs, ProverError, PublicInputs, PublicPoiCorpusHandle, PublicPoiCorpusKey,
    PublicTxidCacheKey, PublicTxidLatestValidated, PublicTxidProofRequest, PublicTxidProofTarget,
    PublicTxidSyncRequest, PublicTxidTransaction, RwLock, TREE_LEAF_COUNT, TransactionPlanChunk,
    TxidPublicCacheError, TxidPublicProof, U256, Utxo, UtxoCommitmentKind, UtxoPoiMetadata,
    ValidatedRailgunTxidStatus, WalletCacheStore, WalletConfig, WalletPoiRuntime,
    WalletPrivateMutationAuthority, WalletPrivatePoiClients, WalletUtxo, apply_poi_private_delta,
    debug, expected_pending_context_state, expected_recovery_state, generate_post_transaction_pois,
    hex, log_local_poi_cache_unavailable, now_epoch_secs,
    pending_output_poi_context_matches_wallet_utxo, railgun_txid_leaf_hash_with_output_start,
    submit_observed_pending_output_pois_inner, warn,
};
mod public_cache;

pub(super) use public_cache::{
    PublicCacheTxidRecoveryRequest, PublicCacheTxidRefreshRequest, RecoveredOutputTxidData,
    public_txid_rows_for_outer_hash, recovered_output_txid_data_from_public_cache,
    refresh_public_txid_cache,
};

mod chunk;
pub(super) use chunk::{
    PublicTxidRecoveryBuildRequest, build_output_poi_recovery_chunk_from_public_cache,
    build_recovery_chunk_for_public_transaction, preflight_local_recovery_chunk_input_proofs,
};
#[cfg(test)]
pub(super) use chunk::{
    RecoverySpendPublicKey, build_output_poi_recovery_chunk_from_public_rows,
    decode_railgun_transactions, output_start_global_position,
};

#[cfg(test)]
mod calldata_chunk;
#[cfg(test)]
pub(super) use calldata_chunk::{
    build_output_poi_recovery_chunk, preflight_local_output_poi_input_proofs,
};

mod force_resubmit;
pub(super) use force_resubmit::{
    force_resubmit_matching_pending_output_pois_authorized,
    force_resubmit_pending_output_poi_context,
};

mod records;
pub(super) use records::{
    extend_pending_output_poi_context, mark_valid_output_poi_recoveries,
    mark_valid_output_poi_recoveries_authorized, new_output_poi_recovery_record,
    new_output_poi_recovery_record_for_output, newly_recoverable_output_poi_list_keys,
    pending_output_poi_context_from_output_recovery,
};
use records::{
    log_forced_output_poi_recovery_regeneration, pending_output_poi_context_from_recovery,
    record_output_poi_recovery_failure,
};

pub(super) struct OutputPoiRecoveryRequest<'a> {
    pub(super) authority: &'a WalletPrivateMutationAuthority<'a>,
    pub(super) db: &'a DbStore,
    pub(super) cache_store: &'a dyn WalletCacheStore,
    pub(super) cfg: &'a WalletConfig,
    pub(super) public_data_plane: &'a ChainPublicDataPlane,
    pub(super) http_client: Option<&'a reqwest::Client>,
    pub(super) indexed_artifact_source: Option<&'a IndexedArtifactSourceConfig>,
    pub(super) forest: Arc<MerkleForest>,
    pub(super) poi_client: &'a PoiRpcClient,
    pub(super) private_poi: &'a WalletPrivatePoiClients,
    pub(super) poi_runtime: &'a WalletPoiRuntime,
    pub(super) active_list_keys: &'a [FixedBytes<32>],
    pub(super) wallet_utxos: &'a [WalletUtxo],
    pub(super) force_retry: bool,
}

pub(super) enum OutputPoiProofSourceResolution {
    /// A ready local proof source and the corpus revision it was read at. No corpus fence is
    /// held; a commit that consumes its proofs rechecks `revision` on the wallet actor.
    Local {
        source: LocalPoiMerkleProofSource,
        revision: PoiCorpusRevision,
        corpus: PublicPoiCorpusHandle,
    },
    Unavailable,
}

impl OutputPoiProofSourceResolution {
    pub(super) fn expected_corpus_revision(&self) -> Option<ExpectedPoiCorpusRevision> {
        match self {
            Self::Local {
                revision, corpus, ..
            } => Some(ExpectedPoiCorpusRevision {
                corpus: corpus.clone(),
                revision: *revision,
            }),
            Self::Unavailable => None,
        }
    }
}

impl OutputPoiRecoveryRequest<'_> {
    pub(super) async fn local_proof_source_if_ready(
        &self,
        required_poi_list_keys: &[FixedBytes<32>],
    ) -> Option<(
        LocalPoiMerkleProofSource,
        PoiCorpusRevision,
        PublicPoiCorpusHandle,
    )> {
        match self.poi_runtime {
            WalletPoiRuntime::IndexedArtifacts { .. } => {
                let corpus = self
                    .public_data_plane
                    .ensure_poi_corpus(PublicPoiCorpusKey::wallet_default(self.cfg.chain.chain_id))
                    .await
                    .ok()?;
                // Read the revision and check readiness against the same published corpus. The
                // fence is released before returning, so callers never hold it across proof
                // generation or a wallet actor round trip.
                let revision_fence = corpus.revision_read_fence().await;
                let revision = *corpus.committed_revision_rx().borrow();
                let source = corpus.merkle_proof_source();
                let ready = source
                    .available_for_lists(self.cfg.chain.chain_id, required_poi_list_keys)
                    .await;
                drop(revision_fence);
                ready.then_some((source, revision, corpus))
            }
            WalletPoiRuntime::PoiProxy { .. } => None,
        }
    }

    pub(super) async fn resolve_proof_source(
        &self,
        required_poi_list_keys: &[FixedBytes<32>],
    ) -> OutputPoiProofSourceResolution {
        if let Some((source, revision, corpus)) = self
            .local_proof_source_if_ready(required_poi_list_keys)
            .await
        {
            OutputPoiProofSourceResolution::Local {
                source,
                revision,
                corpus,
            }
        } else {
            OutputPoiProofSourceResolution::Unavailable
        }
    }
}

pub(super) struct WalletNullifierIndex<'a> {
    pub(super) wallet_utxos: &'a [WalletUtxo],
    pub(super) by_tree_nullifier: HashMap<(u32, U256), usize>,
}

impl OutputPoiRecoveryRequest<'_> {
    async fn candidate_still_current(
        &self,
        candidate: &WalletUtxo,
        required_poi_list_keys: &[FixedBytes<32>],
    ) -> bool {
        output_poi_recovery_candidate_still_current(
            self.authority,
            self.cache_store,
            self.cfg,
            candidate,
            required_poi_list_keys,
        )
        .await
    }
}

async fn output_poi_recovery_candidate_still_current(
    authority: &WalletPrivateMutationAuthority<'_>,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    candidate: &WalletUtxo,
    required_poi_list_keys: &[FixedBytes<32>],
) -> bool {
    if required_poi_list_keys.is_empty() {
        return false;
    }
    if authority.revalidate().is_err() {
        debug!(
            chain_id = cfg.chain.chain_id,
            "output POI recovery side effect rejected"
        );
        return false;
    }
    let Ok(snapshot) = authority.wallet_utxos().await else {
        debug!(
            chain_id = cfg.chain.chain_id,
            "output POI recovery side effect skipped before wallet state check"
        );
        return false;
    };
    if !snapshot.iter().any(|wallet_utxo| {
        !wallet_utxo.is_spent()
            && wallet_utxo.utxo.tree == candidate.utxo.tree
            && wallet_utxo.utxo.position == candidate.utxo.position
            && wallet_utxo.utxo.source.tx_hash == candidate.utxo.source.tx_hash
            && wallet_utxo.utxo.poi.commitment == candidate.utxo.poi.commitment
            && output_poi_statuses_are_recoverable_for_lists(
                &wallet_utxo.utxo.poi,
                required_poi_list_keys,
            )
    }) {
        debug!(
            chain_id = cfg.chain.chain_id,
            "output POI recovery side effect skipped; output no longer matches wallet state"
        );
        return false;
    }
    match cache_store.get_output_poi_recovery(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &candidate.utxo.poi.commitment,
    ) {
        Ok(record) if output_poi_recovery_source_matches_candidate(record.as_ref(), candidate) => {}
        Ok(_) => {
            debug!(
                chain_id = cfg.chain.chain_id,
                "output POI recovery side effect skipped; cached recovery source transaction is stale"
            );
            return false;
        }
        Err(_) => {
            debug!(
                chain_id = cfg.chain.chain_id,
                "output POI recovery side effect skipped; recovery source could not be checked"
            );
            return false;
        }
    }
    if authority.revalidate().is_err() {
        debug!(
            chain_id = cfg.chain.chain_id,
            "output POI recovery side effect rejected after wallet state check"
        );
        return false;
    }
    true
}

fn output_poi_statuses_are_recoverable_for_lists(
    poi: &UtxoPoiMetadata,
    list_keys: &[FixedBytes<32>],
) -> bool {
    list_keys.iter().all(|list_key| {
        poi.statuses
            .get(list_key)
            .is_none_or(|status| status.is_recoverable())
    })
}

pub(super) fn poi_shield_blocked_on_any_list(
    poi: &UtxoPoiMetadata,
    active_list_keys: &[FixedBytes<32>],
) -> bool {
    active_list_keys
        .iter()
        .any(|list_key| poi.statuses.get(list_key) == Some(&PoiStatus::ShieldBlocked))
}

pub(super) fn recoverable_output_poi_list_keys(
    poi: &UtxoPoiMetadata,
    active_list_keys: &[FixedBytes<32>],
) -> Vec<FixedBytes<32>> {
    active_list_keys
        .iter()
        .copied()
        .filter(|list_key| {
            poi.statuses
                .get(list_key)
                .is_none_or(|status| status.is_recoverable())
        })
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum MatchingPendingOutputPoiContextDisposition {
    Skip,
    Extend(Vec<FixedBytes<32>>),
    Regenerate,
}

pub(super) fn matching_pending_output_poi_context_disposition(
    context: &PendingOutputPoiContextRecord,
    recoverable_list_keys: &[FixedBytes<32>],
    force_retry: bool,
) -> MatchingPendingOutputPoiContextDisposition {
    if !saved_pending_context_is_compatible(context, &context.list_keys()) {
        return MatchingPendingOutputPoiContextDisposition::Regenerate;
    }
    if context.terminal_error.is_some() {
        return if force_retry {
            MatchingPendingOutputPoiContextDisposition::Regenerate
        } else {
            MatchingPendingOutputPoiContextDisposition::Skip
        };
    }
    let new_list_keys = newly_recoverable_output_poi_list_keys(context, recoverable_list_keys);
    if new_list_keys.is_empty() {
        MatchingPendingOutputPoiContextDisposition::Skip
    } else {
        MatchingPendingOutputPoiContextDisposition::Extend(new_list_keys)
    }
}

pub(super) fn output_poi_recovery_retry_allowed_for_lists(
    record: &OutputPoiRecoveryRecord,
    now: u64,
    force_retry: bool,
    recoverable_list_keys: &[FixedBytes<32>],
) -> bool {
    !recoverable_list_keys.is_empty()
        && (record.status == OutputPoiRecoveryStatus::Valid
            || record.retry_allowed(now, force_retry))
}

fn output_poi_recovery_source_matches_candidate(
    record: Option<&OutputPoiRecoveryRecord>,
    candidate: &WalletUtxo,
) -> bool {
    record.is_none_or(|record| record.source_tx_hash == candidate.utxo.source.tx_hash)
}

impl<'a> WalletNullifierIndex<'a> {
    pub(super) fn new(
        wallet_utxos: &'a [WalletUtxo],
        scan_keys: &railgun_wallet::scan::WalletScanKeys,
    ) -> Self {
        let mut by_tree_nullifier = HashMap::with_capacity(wallet_utxos.len());
        for (index, wallet_utxo) in wallet_utxos.iter().enumerate() {
            if wallet_utxo.spent.is_some() {
                by_tree_nullifier.insert(
                    (
                        wallet_utxo.utxo.tree,
                        wallet_utxo.utxo.nullifier(scan_keys.nullifying_key),
                    ),
                    index,
                );
            }
        }
        Self {
            wallet_utxos,
            by_tree_nullifier,
        }
    }

    pub(super) fn input_for(
        &self,
        input_tree: u32,
        nullifier: U256,
        source_tx_hash: FixedBytes<32>,
    ) -> Option<&'a WalletUtxo> {
        let index = self.by_tree_nullifier.get(&(input_tree, nullifier))?;
        let wallet_utxo = self.wallet_utxos.get(*index)?;
        wallet_utxo
            .spent
            .as_ref()
            .is_some_and(|spent| spent.tx_hash == source_tx_hash)
            .then_some(wallet_utxo)
    }
}

#[derive(Debug)]
pub(super) struct RecoveryChunk {
    pub(super) chunk: TransactionPlanChunk,
    pub(super) output_start_global: u128,
    pub(super) target_txid_index: Option<u64>,
    pub(super) replay_fence: Option<super::saved_poi_compatibility::SenderCandidateReplayFence>,
}

#[derive(Debug, Clone)]
pub(super) struct RecoveryFailure {
    pub(super) status: OutputPoiRecoveryStatus,
    pub(super) message: String,
    pub(super) retry_after: Option<Duration>,
    pub(super) category: &'static str,
}

impl RecoveryFailure {
    pub(super) fn permanent(status: OutputPoiRecoveryStatus, message: impl Into<String>) -> Self {
        Self::permanent_category(status, recovery_failure_category(status), message)
    }

    pub(super) fn permanent_category(
        status: OutputPoiRecoveryStatus,
        category: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            status,
            message: message.into(),
            retry_after: None,
            category,
        }
    }

    pub(super) fn retryable(
        status: OutputPoiRecoveryStatus,
        message: impl Into<String>,
        retry_after: Duration,
    ) -> Self {
        Self::retryable_category(
            status,
            recovery_failure_category(status),
            message,
            retry_after,
        )
    }

    pub(super) fn retryable_category(
        status: OutputPoiRecoveryStatus,
        category: &'static str,
        message: impl Into<String>,
        retry_after: Duration,
    ) -> Self {
        Self {
            status,
            message: message.into(),
            retry_after: Some(retry_after),
            category,
        }
    }

    const fn with_category(mut self, category: &'static str) -> Self {
        self.category = category;
        self
    }
}

const fn recovery_failure_category(status: OutputPoiRecoveryStatus) -> &'static str {
    match status {
        OutputPoiRecoveryStatus::MissingWalletOutputs => "missing_wallet_outputs",
        OutputPoiRecoveryStatus::MissingWalletInputs => "missing_wallet_inputs",
        OutputPoiRecoveryStatus::NotSelfOriginated => "not_self_originated",
        OutputPoiRecoveryStatus::MissingMerkleProof => "missing_merkle_proof",
        OutputPoiRecoveryStatus::UnsupportedShape => "unsupported_shape",
        OutputPoiRecoveryStatus::TxFetchFailed => "tx_fetch_failed",
        OutputPoiRecoveryStatus::Recoverable
        | OutputPoiRecoveryStatus::Submitted
        | OutputPoiRecoveryStatus::Valid
        | OutputPoiRecoveryStatus::InputPoiNotValid
        | OutputPoiRecoveryStatus::DecodeFailed
        | OutputPoiRecoveryStatus::ProofGenerationFailed
        | OutputPoiRecoveryStatus::SubmitFailed => "other",
    }
}

pub(super) async fn recover_missing_output_pois(request: OutputPoiRecoveryRequest<'_>) -> usize {
    let Some(spending_public_key) = request.cfg.spending_public_key else {
        return 0;
    };
    let Some(prover) = request.cfg.poi_recovery_prover.as_ref() else {
        return 0;
    };
    if request.active_list_keys.is_empty() {
        return 0;
    }

    let started = Instant::now();
    let now = now_epoch_secs();
    let mut recovered = 0usize;
    let mut stale_revision_skips = 0usize;
    let candidates = output_poi_recovery_candidates(request.wallet_utxos, request.active_list_keys);
    let wallet_nullifiers = WalletNullifierIndex::new(request.wallet_utxos, &request.cfg.scan_keys);
    debug!(
        chain_id = request.cfg.chain.chain_id,
        candidates = candidates.len(),
        force_retry = request.force_retry,
        "output POI recovery scan started"
    );

    for candidate in candidates {
        let candidate_started = Instant::now();
        let output_commitment = candidate.utxo.poi.commitment;
        let source_tx_hash = candidate.utxo.source.tx_hash;
        let mut recoverable_list_keys =
            recoverable_output_poi_list_keys(&candidate.utxo.poi, request.active_list_keys);
        if recoverable_list_keys.is_empty() {
            continue;
        }
        let Ok(existing_pending_context) = request.cache_store.get_pending_output_poi_context(
            request.cfg.chain.chain_id,
            &request.cfg.cache_key,
            &output_commitment,
        ) else {
            warn!(
                chain_id = request.cfg.chain.chain_id,
                "failed to load pending output POI recovery predecessor"
            );
            continue;
        };
        let Some(expected_pending_context) =
            expected_pending_context_state(existing_pending_context.as_ref())
        else {
            continue;
        };
        let mut pending_context_extension = None;
        if let Some(existing_pending_context) = existing_pending_context.as_ref() {
            if pending_output_poi_context_matches_wallet_utxo(
                request.cfg,
                candidate,
                existing_pending_context,
            ) {
                match matching_pending_output_poi_context_disposition(
                    existing_pending_context,
                    &recoverable_list_keys,
                    request.force_retry,
                ) {
                    MatchingPendingOutputPoiContextDisposition::Skip => {
                        debug!(
                            chain_id = request.cfg.chain.chain_id,
                            "output POI recovery skipped; matching pending context does not require recovery"
                        );
                        continue;
                    }
                    MatchingPendingOutputPoiContextDisposition::Extend(new_list_keys) => {
                        recoverable_list_keys = new_list_keys;
                        pending_context_extension = Some(existing_pending_context.clone());
                    }
                    MatchingPendingOutputPoiContextDisposition::Regenerate => {
                        log_forced_output_poi_recovery_regeneration(
                            request.cfg,
                            candidate,
                            existing_pending_context,
                        );
                    }
                }
            } else {
                if !request.force_retry {
                    continue;
                }
                log_forced_output_poi_recovery_regeneration(
                    request.cfg,
                    candidate,
                    existing_pending_context,
                );
            }
        }

        let Ok(existing_recovery) = request.cache_store.get_output_poi_recovery(
            request.cfg.chain.chain_id,
            &request.cfg.cache_key,
            &output_commitment,
        ) else {
            warn!(
                chain_id = request.cfg.chain.chain_id,
                "failed to load output POI recovery cache"
            );
            continue;
        };
        if existing_recovery
            .as_ref()
            .is_some_and(|record| record.source_tx_hash != source_tx_hash)
        {
            debug!(
                chain_id = request.cfg.chain.chain_id,
                "output POI recovery skipped; cached recovery source transaction is stale"
            );
            continue;
        }
        if let Some(record) = existing_recovery.as_ref()
            && !output_poi_recovery_retry_allowed_for_lists(
                record,
                now,
                request.force_retry,
                &recoverable_list_keys,
            )
            && !(pending_context_extension.is_some()
                && record.status == OutputPoiRecoveryStatus::Submitted)
        {
            debug!(
                chain_id = request.cfg.chain.chain_id,
                status = ?record.status,
                force_retry = request.force_retry,
                "output POI recovery skipped; cached recovery state is not retryable"
            );
            continue;
        }

        let build_chunk_started = Instant::now();
        let recovery_chunk = match build_output_poi_recovery_chunk_from_public_cache(
            PublicTxidRecoveryBuildRequest {
                request: &request,
                candidate,
                source_tx_hash,
                output_commitment,
                wallet_nullifiers: &wallet_nullifiers,
                required_poi_list_keys: &recoverable_list_keys,
                spending_public_key,
                candidate_started,
            },
        )
        .await
        {
            Ok(recovery_chunk) => recovery_chunk,
            Err(failure) => {
                warn!(
                    chain_id = request.cfg.chain.chain_id,
                    status = ?failure.status,
                    retryable = failure.retry_after.is_some(),
                    failure_category = failure.category,
                    "output POI recovery reconstruction failed"
                );
                if !request
                    .candidate_still_current(candidate, &recoverable_list_keys)
                    .await
                {
                    continue;
                }
                record_output_poi_recovery_failure(
                    request.authority,
                    request.db,
                    request.cache_store,
                    request.cfg,
                    candidate,
                    request.active_list_keys,
                    &recoverable_list_keys,
                    failure,
                    now,
                )
                .await;
                continue;
            }
        };
        let build_chunk_elapsed_ms = build_chunk_started.elapsed().as_millis();
        debug!(
            chain_id = request.cfg.chain.chain_id,
            inputs = recovery_chunk.chunk.inputs.len(),
            outputs = recovery_chunk.chunk.outputs.len(),
            build_chunk_elapsed_ms,
            candidate_elapsed_ms = candidate_started.elapsed().as_millis(),
            "output POI recovery chunk built"
        );

        let txid_data_started = Instant::now();
        let txid_data =
            match recovered_output_txid_data_from_public_cache(PublicCacheTxidRecoveryRequest {
                public_data_plane: request.public_data_plane,
                cfg: request.cfg,
                poi_client: request.poi_client,
                http_client: request.http_client,
                indexed_artifact_source: request.indexed_artifact_source,
                recovery_chunk: &recovery_chunk,
                started: Instant::now(),
            })
            .await
            {
                Ok(txid_data) => txid_data,
                Err(failure) => {
                    if !request
                        .candidate_still_current(candidate, &recoverable_list_keys)
                        .await
                    {
                        continue;
                    }
                    record_output_poi_recovery_failure(
                        request.authority,
                        request.db,
                        request.cache_store,
                        request.cfg,
                        candidate,
                        request.active_list_keys,
                        &recoverable_list_keys,
                        failure,
                        now,
                    )
                    .await;
                    continue;
                }
            };
        let txid_data_elapsed_ms = txid_data_started.elapsed().as_millis();
        debug!(
            chain_id = request.cfg.chain.chain_id,
            txid_data_elapsed_ms,
            candidate_elapsed_ms = candidate_started.elapsed().as_millis(),
            "output POI recovery TXID data recovered"
        );

        if !request
            .candidate_still_current(candidate, &recoverable_list_keys)
            .await
        {
            continue;
        }

        let proof_source_resolution = request.resolve_proof_source(&recoverable_list_keys).await;
        if !request
            .candidate_still_current(candidate, &recoverable_list_keys)
            .await
        {
            continue;
        }
        let proof_source: &dyn PoiMerkleProofSource = match &proof_source_resolution {
            OutputPoiProofSourceResolution::Local { source, .. } => source,
            OutputPoiProofSourceResolution::Unavailable => {
                if !request
                    .candidate_still_current(candidate, &recoverable_list_keys)
                    .await
                {
                    continue;
                }
                log_local_poi_cache_unavailable(
                    request.cfg,
                    "output_poi_recovery_proof_generation",
                );
                record_output_poi_recovery_failure(
                    request.authority,
                    request.db,
                    request.cache_store,
                    request.cfg,
                    candidate,
                    request.active_list_keys,
                    &recoverable_list_keys,
                    RecoveryFailure::retryable(
                        OutputPoiRecoveryStatus::ProofGenerationFailed,
                        "local POI proof source unavailable",
                        OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
                    ),
                    now,
                )
                .await;
                continue;
            }
        };
        let proof_generation_started = Instant::now();
        match generate_post_transaction_pois(PostTransactionPoiGenerationRequest {
            chunk: &recovery_chunk.chunk,
            txid_data: &txid_data.poi_data,
            chain_type: EVM_CHAIN_TYPE,
            chain_id: request.cfg.chain.chain_id,
            txid_version: Some(DEFAULT_TXID_VERSION),
            required_poi_list_keys: &recoverable_list_keys,
            proof_source,
            prover,
            verify_proof: OUTPUT_POI_RECOVERY_VERIFY_PROOF,
        })
        .await
        {
            Ok(pre_transaction_pois) => {
                if !request
                    .candidate_still_current(candidate, &recoverable_list_keys)
                    .await
                {
                    continue;
                }
                let proof_generation_elapsed_ms = proof_generation_started.elapsed().as_millis();
                let record = if let Some(existing) = pending_context_extension.as_ref() {
                    extend_pending_output_poi_context(
                        existing,
                        &recoverable_list_keys,
                        pre_transaction_pois,
                    )
                } else {
                    pending_output_poi_context_from_recovery(
                        request.cfg,
                        candidate,
                        &recovery_chunk,
                        txid_data.poi_data.txid_merkleroot_index,
                        pre_transaction_pois,
                        &recoverable_list_keys,
                        now,
                    )
                };
                let Ok(current_recovery) = request.cache_store.get_output_poi_recovery(
                    request.cfg.chain.chain_id,
                    &request.cfg.cache_key,
                    &output_commitment,
                ) else {
                    warn!(
                        chain_id = request.cfg.chain.chain_id,
                        "failed to load recovered output POI predecessor"
                    );
                    continue;
                };
                let Some(expected_recovery) = expected_recovery_state(current_recovery.as_ref())
                else {
                    continue;
                };
                let reset_valid_recovery = current_recovery
                    .as_ref()
                    .is_some_and(|record| record.status == OutputPoiRecoveryStatus::Valid);
                match apply_poi_private_delta(
                    request.authority,
                    request.db,
                    request.cache_store,
                    request.cfg,
                    OwnedPoiPrivateDelta::OutputRecovery(OutputRecoveryDelta {
                        expected_output: ExpectedWalletOutput::new(candidate),
                        active_list_keys: request.active_list_keys.to_vec(),
                        target_list_keys: recoverable_list_keys.clone(),
                        required_poi_status: ExpectedPoiStatus::Recoverable,
                        pending_update: Box::new(Some((expected_pending_context, record))),
                        expected_recovery,
                        action: if pending_context_extension.is_some() && !reset_valid_recovery {
                            OutputPoiRecoveryAction::ExtendContext
                        } else {
                            OutputPoiRecoveryAction::Detected {
                                status: OutputPoiRecoveryStatus::Recoverable,
                                retry_after: None,
                                last_error: None,
                                increment_attempts: false,
                            }
                        },
                        now,
                        expected_corpus: proof_source_resolution.expected_corpus_revision(),
                        replay_fence: recovery_chunk.replay_fence.clone(),
                    }),
                )
                .await
                {
                    Ok(PoiPrivateApplyOutcome::Applied { .. }) => {}
                    Ok(PoiPrivateApplyOutcome::SkippedStaleCorpusRevision) => {
                        stale_revision_skips += 1;
                        continue;
                    }
                    Ok(PoiPrivateApplyOutcome::Skipped) => continue,
                    Err(_) => {
                        warn!(
                            chain_id = request.cfg.chain.chain_id,
                            "failed to persist recovered output POI context"
                        );
                        continue;
                    }
                }
                debug!(
                    chain_id = request.cfg.chain.chain_id,
                    inputs = recovery_chunk.chunk.inputs.len(),
                    outputs = recovery_chunk.chunk.outputs.len(),
                    proof_generation_elapsed_ms,
                    candidate_elapsed_ms = candidate_started.elapsed().as_millis(),
                    "reconstructed output POI context"
                );
                recovered += 1;
            }
            Err(err) => {
                if !request
                    .candidate_still_current(candidate, &recoverable_list_keys)
                    .await
                {
                    continue;
                }
                let proof_generation_elapsed_ms = proof_generation_started.elapsed().as_millis();
                warn!(
                    chain_id = request.cfg.chain.chain_id,
                    proof_generation_elapsed_ms,
                    candidate_elapsed_ms = candidate_started.elapsed().as_millis(),
                    "output POI recovery proof generation failed"
                );
                let retry_after = output_poi_recovery_proof_retry_after(&err);
                record_output_poi_recovery_failure(
                    request.authority,
                    request.db,
                    request.cache_store,
                    request.cfg,
                    candidate,
                    request.active_list_keys,
                    &recoverable_list_keys,
                    RecoveryFailure::retryable(
                        OutputPoiRecoveryStatus::ProofGenerationFailed,
                        err.to_string(),
                        retry_after,
                    ),
                    now,
                )
                .await;
            }
        }
        let candidate_elapsed = candidate_started.elapsed();
        if candidate_elapsed >= OUTPUT_POI_RECOVERY_SLOW_STEP_AFTER {
            warn!(
                chain_id = request.cfg.chain.chain_id,
                elapsed_ms = candidate_elapsed.as_millis(),
                "slow output POI recovery candidate"
            );
        } else {
            debug!(
                chain_id = request.cfg.chain.chain_id,
                elapsed_ms = candidate_elapsed.as_millis(),
                "output POI recovery candidate complete"
            );
        }
    }

    if recovered > 0 {
        match submit_observed_pending_output_pois_inner(
            request.authority,
            request.public_data_plane,
            request.db,
            request.cache_store,
            request.cfg,
            request.active_list_keys,
            request.private_poi,
            false,
        )
        .await
        {
            Ok(submitted_contexts) => {
                debug!(
                    chain_id = request.cfg.chain.chain_id,
                    recovered,
                    submitted_contexts,
                    elapsed_ms = started.elapsed().as_millis(),
                    "recovered missing output POI contexts"
                );
            }
            Err(_) => {
                warn!(
                    chain_id = request.cfg.chain.chain_id,
                    recovered, "failed to submit recovered output POI contexts"
                );
            }
        }
    }

    debug!(
        chain_id = request.cfg.chain.chain_id,
        recovered,
        stale_revision_skips,
        elapsed_ms = started.elapsed().as_millis(),
        "output POI recovery scan complete"
    );

    recovered
}

pub(super) const fn output_poi_recovery_proof_retry_after(
    err: &PreTransactionPoiError,
) -> Duration {
    match err {
        PreTransactionPoiError::Prover(
            ProverError::WorkerPanic(_) | ProverError::WorkerDropped | ProverError::QueueClosed,
        ) => OUTPUT_POI_RECOVERY_PROOF_FAILURE_RETRY_AFTER,
        _ => OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
    }
}

pub(super) fn output_poi_recovery_candidates<'a>(
    wallet_utxos: &'a [WalletUtxo],
    active_list_keys: &[FixedBytes<32>],
) -> Vec<&'a WalletUtxo> {
    wallet_utxos
        .iter()
        .filter(|wallet_utxo| {
            !wallet_utxo.is_spent()
                && wallet_utxo.utxo.poi.commitment_kind == UtxoCommitmentKind::Transact
                && wallet_utxo
                    .utxo
                    .poi
                    .has_recoverable_status_for_lists(active_list_keys)
        })
        .collect()
}

#[cfg(test)]
pub(super) mod test_support;
