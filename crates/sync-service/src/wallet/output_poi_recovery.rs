use alloy::sol_types::{SolCall, SolValue};
use broadcaster_core::contracts::railgun::{
    CommitmentPreimage, Transaction, executeCall, relayCall, transactCall,
};

use crate::txid_cache::TxidPublicCacheTransaction;

use super::{
    Arc, ChainPublicDataPlane, ChainScope, ChainType, DEFAULT_TXID_VERSION, DbStore,
    DenseMerkleTree, Duration, EVM_CHAIN_TYPE, ExpectedPoiStatus, ExpectedWalletOutput, FixedBytes,
    HashMap, IndexedArtifactSourceConfig, InputWitness, Instant, LocalPoiMerkleProofSource,
    MerkleForest, Note, OUTPUT_POI_RECOVERY_PROOF_FAILURE_RETRY_AFTER,
    OUTPUT_POI_RECOVERY_SLOW_STEP_AFTER, OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
    OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER, OUTPUT_POI_RECOVERY_VERIFY_PROOF,
    OutputPoiRecoveryAction, OutputPoiRecoveryRecord, OutputPoiRecoveryStatus,
    OwnedPoiPrivateDelta, PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER, PendingOutputPoiContextRecord,
    PendingOutputPoiObservation, PendingOutputPoiPreflight, PendingOutputPoiRemoteAttempt,
    PendingOutputPoiRole, PendingOutputPoiSubmissionPlan, PoiMerkleProof, PoiMerkleProofSource,
    PoiPrivateApplyOutcome, PoiRpcClient, PoiStatus, PostTransactionPoiData,
    PostTransactionPoiGenerationRequest, PreTransactionPoiError, PreTransactionPoiMap,
    PrivateInputs, ProverError, PublicInputs, PublicPoiCorpusKey, PublicTxidCacheKey,
    PublicTxidLatestValidated, PublicTxidProofRequest, PublicTxidProofTarget,
    PublicTxidSyncRequest, PublicTxidTransaction, RailgunSpendSigner, RwLock,
    SenderTransactionCandidate, TREE_LEAF_COUNT, TransactionPlanChunk, TxidPublicCacheError, U256,
    Utxo, UtxoCommitmentKind, UtxoPoiMetadata, ValidatedRailgunTxidStatus, WalletCacheStore,
    WalletConfig, WalletPoiRuntime, WalletPrivateMutationAuthority, WalletPrivatePoiClients,
    WalletPrivateRemoteError, WalletUtxo, apply_poi_private_delta, async_trait,
    current_pending_output_poi_subject, debug, expected_pending_context_state,
    expected_recovery_state, generate_post_transaction_pois, hex, log_local_poi_cache_unavailable,
    now_epoch_secs, pending_output_poi_context_fingerprint,
    pending_output_poi_context_matches_wallet_utxo, pending_output_poi_submission_plan_current,
    preflight_and_remote_submit_pending_output_poi, railgun_txid_leaf_hash_with_output_start,
    submit_observed_pending_output_pois_inner, warn,
};
mod public_cache;

pub(super) use public_cache::{
    PublicCacheTxidRecoveryRequest, PublicCacheTxidRefreshRequest, public_txid_rows_for_outer_hash,
    recovered_output_txid_data_from_public_cache, refresh_public_txid_cache,
};

#[derive(Clone, Copy)]
pub(super) struct RecoverySpendPublicKey {
    pub(super) spending_public_key: [U256; 2],
}

impl RailgunSpendSigner for RecoverySpendPublicKey {
    fn spending_public_key(&self) -> [U256; 2] {
        self.spending_public_key
    }

    fn sign_spend_message(&self, _: U256) -> [U256; 3] {
        [U256::ZERO; 3]
    }
}

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
    Local {
        source: LocalPoiMerkleProofSource,
        revision_fence: tokio::sync::OwnedRwLockReadGuard<()>,
    },
    RemoteFallback,
    Unavailable,
}

/// Trait adapter that makes every remote proof read a separately authorized effect.
/// `generate_post_transaction_pois` may request multiple lists; each request revalidates.
pub(super) struct OutputRecoveryRemoteProofSource<'a> {
    pub(super) private_poi: &'a WalletPrivatePoiClients,
    pub(super) authority: &'a WalletPrivateMutationAuthority<'a>,
    pub(super) cache_store: &'a dyn WalletCacheStore,
    pub(super) cfg: &'a WalletConfig,
    pub(super) candidate: &'a WalletUtxo,
    pub(super) required_poi_list_keys: &'a [FixedBytes<32>],
}

#[async_trait]
impl PoiMerkleProofSource for OutputRecoveryRemoteProofSource<'_> {
    async fn poi_merkle_proofs(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_key: &FixedBytes<32>,
        blinded_commitments: &[FixedBytes<32>],
    ) -> Result<Vec<PoiMerkleProof>, PreTransactionPoiError> {
        if !self.required_poi_list_keys.contains(list_key) {
            return Err(PreTransactionPoiError::ProofSource(format!(
                "output POI recovery proof request rejected for non-recoverable listKey={}",
                hex::encode(list_key)
            )));
        }
        match self
            .private_poi
            .poi_merkle_proofs(
                || async {
                    Ok::<bool, std::convert::Infallible>(
                        output_poi_recovery_candidate_still_current(
                            self.authority,
                            self.cache_store,
                            self.cfg,
                            self.candidate,
                            self.required_poi_list_keys,
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
                    "wallet-private POI proof request rejected: {reason:?}"
                )))
            }
        }
    }
}

impl OutputPoiRecoveryRequest<'_> {
    pub(super) async fn local_proof_source_if_ready(
        &self,
        required_poi_list_keys: &[FixedBytes<32>],
    ) -> Option<(
        LocalPoiMerkleProofSource,
        tokio::sync::OwnedRwLockReadGuard<()>,
    )> {
        match self.poi_runtime {
            WalletPoiRuntime::IndexedArtifacts { .. } => {
                let corpus = self
                    .public_data_plane
                    .ensure_poi_corpus(PublicPoiCorpusKey::wallet_default(self.cfg.chain.chain_id))
                    .await
                    .ok()?;
                let revision_fence = corpus.revision_read_fence().await;
                let source = corpus.merkle_proof_source();
                source
                    .available_for_lists(self.cfg.chain.chain_id, required_poi_list_keys)
                    .await
                    .then_some((source, revision_fence))
            }
            WalletPoiRuntime::PoiProxy { .. } => None,
        }
    }

    pub(super) async fn resolve_proof_source(
        &self,
        required_poi_list_keys: &[FixedBytes<32>],
    ) -> OutputPoiProofSourceResolution {
        match self.poi_runtime {
            WalletPoiRuntime::IndexedArtifacts { .. } => {
                if let Some((source, revision_fence)) = self
                    .local_proof_source_if_ready(required_poi_list_keys)
                    .await
                {
                    OutputPoiProofSourceResolution::Local {
                        source,
                        revision_fence,
                    }
                } else if self.poi_runtime.wallet_read_fallback_enabled() {
                    OutputPoiProofSourceResolution::RemoteFallback
                } else {
                    OutputPoiProofSourceResolution::Unavailable
                }
            }
            WalletPoiRuntime::PoiProxy { .. } => OutputPoiProofSourceResolution::RemoteFallback,
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
}

#[derive(Debug, Clone)]
pub(super) struct RecoveryFailure {
    pub(super) status: OutputPoiRecoveryStatus,
    pub(super) message: String,
    pub(super) retry_after: Option<Duration>,
}

impl RecoveryFailure {
    pub(super) fn permanent(status: OutputPoiRecoveryStatus, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            retry_after: None,
        }
    }

    pub(super) fn retryable(
        status: OutputPoiRecoveryStatus,
        message: impl Into<String>,
        retry_after: Duration,
    ) -> Self {
        Self {
            status,
            message: message.into(),
            retry_after: Some(retry_after),
        }
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
        let remote_proof_source = OutputRecoveryRemoteProofSource {
            private_poi: request.private_poi,
            authority: request.authority,
            cache_store: request.cache_store,
            cfg: request.cfg,
            candidate,
            required_poi_list_keys: &recoverable_list_keys,
        };
        let proof_source: &dyn PoiMerkleProofSource = match &proof_source_resolution {
            OutputPoiProofSourceResolution::Local { source, .. } => source,
            OutputPoiProofSourceResolution::RemoteFallback => &remote_proof_source,
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
                    OwnedPoiPrivateDelta::OutputRecovery {
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
                    },
                )
                .await
                {
                    Ok(PoiPrivateApplyOutcome::Applied { .. }) => {}
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
        elapsed_ms = started.elapsed().as_millis(),
        "output POI recovery scan complete"
    );

    recovered
}

pub(super) async fn force_resubmit_matching_pending_output_pois_authorized(
    authority: &WalletPrivateMutationAuthority<'_>,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    _utxos: &Arc<RwLock<Vec<WalletUtxo>>>,
    active_list_keys: &[FixedBytes<32>],
    private_poi: &WalletPrivatePoiClients,
) -> usize {
    if authority.revalidate().is_err() {
        debug!(
            chain_id = cfg.chain.chain_id,
            "forced pending output POI resubmission skipped"
        );
        return 0;
    }
    force_resubmit_matching_pending_output_pois_impl(
        authority,
        db,
        cache_store,
        cfg,
        active_list_keys,
        private_poi,
    )
    .await
}

async fn force_resubmit_matching_pending_output_pois_impl(
    authority: &WalletPrivateMutationAuthority<'_>,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    private_poi: &WalletPrivatePoiClients,
) -> usize {
    if active_list_keys.is_empty() {
        return 0;
    }

    let now = now_epoch_secs();
    let mut attempted_contexts = 0usize;
    let Ok(records) =
        cache_store.list_pending_output_poi_contexts(cfg.chain.chain_id, &cfg.cache_key)
    else {
        warn!(
            chain_id = cfg.chain.chain_id,
            "failed to list pending output POI contexts for resubmission"
        );
        return 0;
    };
    for record in records {
        if record.terminal_error.is_some() {
            continue;
        }
        let output_commitment = record.output_commitment;
        let Some(observation) = record.observation.clone() else {
            continue;
        };
        let Some((subject, current_output)) =
            current_pending_output_poi_subject(authority, cfg, &record).await
        else {
            continue;
        };
        let Ok(current_recovery) = cache_store.get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &output_commitment,
        ) else {
            warn!(
                chain_id = cfg.chain.chain_id,
                "failed to load forced pending output POI recovery predecessor"
            );
            continue;
        };
        let Some(expected_recovery) = expected_recovery_state(current_recovery.as_ref()) else {
            continue;
        };
        let mut plan =
            PendingOutputPoiSubmissionPlan::force_matching(record.list_keys(), expected_recovery);
        plan.retain_current_recoverable(
            &record,
            active_list_keys,
            current_output.as_ref().map(|output| &output.utxo.poi),
        );
        if plan.list_keys().is_empty() {
            continue;
        }
        let Some(expected_context_fingerprint) = pending_output_poi_context_fingerprint(&record)
        else {
            continue;
        };
        debug!(
            chain_id = cfg.chain.chain_id,
            poi_lists = plan.list_keys().len(),
            "force-resubmitting matching pending output POI context"
        );
        let Ok(attempt) = preflight_and_remote_submit_pending_output_poi(
            authority,
            cache_store,
            cfg,
            active_list_keys,
            &record,
            &observation,
            &subject,
            &plan,
            private_poi,
        )
        .await
        else {
            warn!(
                chain_id = cfg.chain.chain_id,
                "forced pending output POI preflight/submit failed"
            );
            continue;
        };
        // Count only after preflight allowed remote work to start.
        match &attempt {
            PendingOutputPoiRemoteAttempt::Succeeded { .. }
            | PendingOutputPoiRemoteAttempt::Failed { .. } => {
                attempted_contexts += 1;
            }
            PendingOutputPoiRemoteAttempt::NotCurrent
            | PendingOutputPoiRemoteAttempt::AuthorityStale
            | PendingOutputPoiRemoteAttempt::MissingPreTransactionPois => {}
        }
        match attempt {
            PendingOutputPoiRemoteAttempt::NotCurrent => {}
            PendingOutputPoiRemoteAttempt::AuthorityStale => break,
            PendingOutputPoiRemoteAttempt::MissingPreTransactionPois => {
                if apply_poi_private_delta(
                    authority,
                    db,
                    cache_store,
                    cfg,
                    OwnedPoiPrivateDelta::PendingContextTerminal {
                        subject: subject.clone(),
                        expected_context_fingerprint,
                        expected_recovery: plan.expected_recovery(),
                        active_list_keys: active_list_keys.to_vec(),
                        target_list_keys: plan.list_keys().to_vec(),
                        error: "missing pre-transaction POI for pending output".to_string(),
                    },
                )
                .await
                .is_err()
                {
                    warn!(
                        chain_id = cfg.chain.chain_id,
                        "failed to mark pending output POI context terminal"
                    );
                }
            }
            PendingOutputPoiRemoteAttempt::Succeeded {
                submitted_list_keys,
            } => {
                if !matches!(
                    pending_output_poi_submission_plan_current(
                        authority,
                        cache_store,
                        cfg,
                        active_list_keys,
                        &record,
                        &subject,
                        &plan,
                    )
                    .await,
                    Ok(PendingOutputPoiPreflight::Ready)
                ) {
                    continue;
                }
                if apply_poi_private_delta(
                    authority,
                    db,
                    cache_store,
                    cfg,
                    OwnedPoiPrivateDelta::PendingSubmission {
                        subject: subject.clone(),
                        expected_context_fingerprint,
                        expected_recovery: plan.expected_recovery(),
                        active_list_keys: active_list_keys.to_vec(),
                        list_keys: submitted_list_keys,
                        predicate: plan.predicate(),
                        merge_submitted_list_keys: true,
                        action: OutputPoiRecoveryAction::Submitted {
                            retry_after: PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER,
                        },
                        now,
                    },
                )
                .await
                .is_err()
                {
                    warn!(
                        chain_id = cfg.chain.chain_id,
                        "failed to persist resubmitted pending output POI state"
                    );
                }
            }
            PendingOutputPoiRemoteAttempt::Failed { error: err, .. } => {
                if !matches!(
                    pending_output_poi_submission_plan_current(
                        authority,
                        cache_store,
                        cfg,
                        active_list_keys,
                        &record,
                        &subject,
                        &plan,
                    )
                    .await,
                    Ok(PendingOutputPoiPreflight::Ready)
                ) {
                    continue;
                }
                if apply_poi_private_delta(
                    authority,
                    db,
                    cache_store,
                    cfg,
                    OwnedPoiPrivateDelta::PendingSubmission {
                        subject: subject.clone(),
                        expected_context_fingerprint,
                        expected_recovery: plan.expected_recovery(),
                        active_list_keys: active_list_keys.to_vec(),
                        list_keys: plan.list_keys().to_vec(),
                        predicate: plan.predicate(),
                        merge_submitted_list_keys: false,
                        action: OutputPoiRecoveryAction::SubmitFailed {
                            error: err.to_string(),
                            retry_after: OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
                        },
                        now,
                    },
                )
                .await
                .is_err()
                {
                    warn!(
                        chain_id = cfg.chain.chain_id,
                        "failed to persist failed pending output POI resubmission state"
                    );
                }
                warn!(
                    chain_id = cfg.chain.chain_id,
                    "forced pending output POI resubmission failed"
                );
            }
        }
    }

    attempted_contexts
}

pub(super) struct PublicTxidRecoveryBuildRequest<'a> {
    pub(super) request: &'a OutputPoiRecoveryRequest<'a>,
    pub(super) candidate: &'a WalletUtxo,
    pub(super) source_tx_hash: FixedBytes<32>,
    pub(super) output_commitment: FixedBytes<32>,
    pub(super) wallet_nullifiers: &'a WalletNullifierIndex<'a>,
    pub(super) required_poi_list_keys: &'a [FixedBytes<32>],
    pub(super) spending_public_key: [U256; 2],
    pub(super) candidate_started: Instant,
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

pub(super) async fn build_output_poi_recovery_chunk_from_public_cache(
    input: PublicTxidRecoveryBuildRequest<'_>,
) -> Result<RecoveryChunk, RecoveryFailure> {
    let PublicTxidRecoveryBuildRequest {
        request,
        candidate,
        source_tx_hash,
        output_commitment,
        wallet_nullifiers,
        required_poi_list_keys,
        spending_public_key,
        candidate_started,
    } = input;
    let current_recovery = request
        .cache_store
        .get_output_poi_recovery(
            request.cfg.chain.chain_id,
            &request.cfg.cache_key,
            &output_commitment,
        )
        .map_err(|err| {
            RecoveryFailure::retryable(
                OutputPoiRecoveryStatus::TxFetchFailed,
                format!("load cached recovery state failed: {err}"),
                OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
            )
        })?;
    if !output_poi_recovery_source_matches_candidate(current_recovery.as_ref(), candidate) {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::TxFetchFailed,
            "cached recovery source transaction does not match current output",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    }
    let cache_key = PublicTxidCacheKey::new(
        ChainScope {
            chain_type: ChainType::Evm,
            chain_id: request.cfg.chain.chain_id,
            railgun_contract: request.cfg.chain.contract,
        },
        DEFAULT_TXID_VERSION,
    );
    let rows = public_txid_rows_for_outer_hash(
        PublicCacheTxidRefreshRequest {
            public_data_plane: request.public_data_plane,
            cfg: request.cfg,
            poi_client: request.poi_client,
            http_client: request.http_client,
            indexed_artifact_source: request.indexed_artifact_source,
            cache_key,
        },
        source_tx_hash,
    )
    .await?;
    let cached_transactions = current_recovery
        .as_ref()
        .and_then(|record| record.tx_input.as_deref())
        .and_then(|input| decode_railgun_transactions(input).ok())
        .unwrap_or_default();

    if !request
        .candidate_still_current(candidate, required_poi_list_keys)
        .await
    {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::TxFetchFailed,
            "output POI recovery candidate changed while resolving public TXID data",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    }
    let sender_candidate = request
        .cache_store
        .get_sender_transaction_candidate(
            request.cfg.chain.chain_id,
            &request.cfg.cache_key,
            &source_tx_hash,
        )
        .map_err(|err| {
            RecoveryFailure::retryable(
                OutputPoiRecoveryStatus::TxFetchFailed,
                format!("load sender output notes failed: {err}"),
                OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
            )
        })?;
    let recovery_chunk = build_output_poi_recovery_chunk_from_public_rows(
        candidate,
        wallet_nullifiers,
        &rows,
        sender_candidate.as_ref(),
        &cached_transactions,
        &request.forest,
        required_poi_list_keys,
        spending_public_key,
        &request.cfg.scan_keys,
    )
    .await?;
    if !request
        .candidate_still_current(candidate, required_poi_list_keys)
        .await
    {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::TxFetchFailed,
            "output POI recovery candidate changed while building recovery chunk",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    }
    if let Some((local_proof_source, _revision_fence)) = request
        .local_proof_source_if_ready(required_poi_list_keys)
        .await
    {
        let preflight_started = Instant::now();
        match preflight_local_recovery_chunk_input_proofs(
            Some(&local_proof_source),
            request.cfg,
            &recovery_chunk,
            required_poi_list_keys,
        )
        .await
        {
            Ok(()) => {
                debug!(
                    chain_id = request.cfg.chain.chain_id,
                    preflight_elapsed_ms = preflight_started.elapsed().as_millis(),
                    candidate_elapsed_ms = candidate_started.elapsed().as_millis(),
                    "output POI recovery local proof preflight complete"
                );
            }
            Err(failure) => {
                warn!(
                    chain_id = request.cfg.chain.chain_id,
                    preflight_elapsed_ms = preflight_started.elapsed().as_millis(),
                    candidate_elapsed_ms = candidate_started.elapsed().as_millis(),
                    "output POI recovery local proof preflight failed"
                );
                return Err(failure);
            }
        }
    }
    if !request
        .candidate_still_current(candidate, required_poi_list_keys)
        .await
    {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::TxFetchFailed,
            "output POI recovery candidate changed while resolving public TXID data",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    }

    debug!(
        chain_id = request.cfg.chain.chain_id,
        candidate_elapsed_ms = candidate_started.elapsed().as_millis(),
        "output POI recovery public TXID data resolved"
    );
    Ok(recovery_chunk)
}

pub(super) fn decode_railgun_transactions(
    calldata: &[u8],
) -> Result<Vec<Transaction>, RecoveryFailure> {
    if calldata.len() < 4 {
        return Err(RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::DecodeFailed,
            "transaction input too short",
        ));
    }
    if let Ok(call) = transactCall::abi_decode(calldata) {
        return Ok(call._transactions);
    }
    if let Ok(call) = relayCall::abi_decode(calldata) {
        if !call._actionData.calls.is_empty() {
            return Err(RecoveryFailure::permanent(
                OutputPoiRecoveryStatus::UnsupportedShape,
                "relay transaction with action data is not treated as consolidation recovery",
            ));
        }
        return Ok(call._transactions);
    }
    if let Ok(call) = executeCall::abi_decode(calldata) {
        return Ok(call._transactions);
    }
    Err(RecoveryFailure::permanent(
        OutputPoiRecoveryStatus::UnsupportedShape,
        "transaction is not a Railgun transact, relay, or 7702 execute call",
    ))
}

#[cfg(test)]
pub(super) async fn preflight_local_output_poi_input_proofs(
    proof_source: Option<&LocalPoiMerkleProofSource>,
    cfg: &WalletConfig,
    candidate: &WalletUtxo,
    wallet_utxos: &[WalletUtxo],
    wallet_nullifiers: &WalletNullifierIndex<'_>,
    transactions: &[Transaction],
    active_list_keys: &[FixedBytes<32>],
) -> Result<(), RecoveryFailure> {
    let Some(proof_source) = proof_source else {
        return Ok(());
    };
    let Some(blinded_commitments) = output_poi_recovery_input_blinded_commitments(
        candidate,
        wallet_utxos,
        wallet_nullifiers,
        transactions,
        &cfg.scan_keys,
        active_list_keys,
    ) else {
        return Ok(());
    };
    for list_key in active_list_keys {
        if let Err(err) = proof_source
            .check_commitments_available(
                DEFAULT_TXID_VERSION,
                EVM_CHAIN_TYPE,
                cfg.chain.chain_id,
                list_key,
                &blinded_commitments,
            )
            .await
        {
            return Err(RecoveryFailure::retryable(
                OutputPoiRecoveryStatus::ProofGenerationFailed,
                format!("local POI proof preflight failed: {err}"),
                output_poi_recovery_proof_retry_after(&err),
            ));
        }
    }
    Ok(())
}

pub(super) async fn preflight_local_recovery_chunk_input_proofs(
    proof_source: Option<&LocalPoiMerkleProofSource>,
    cfg: &WalletConfig,
    recovery_chunk: &RecoveryChunk,
    active_list_keys: &[FixedBytes<32>],
) -> Result<(), RecoveryFailure> {
    let Some(proof_source) = proof_source else {
        return Ok(());
    };
    if recovery_chunk.chunk.inputs.iter().any(|wallet_input| {
        active_list_keys.iter().any(|list_key| {
            wallet_input.utxo.poi.statuses.get(list_key) == Some(&PoiStatus::ShieldBlocked)
        })
    }) {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::InputPoiNotValid,
            "one or more transaction inputs are shield-blocked",
            OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
        ));
    }
    let blinded_commitments = recovery_chunk
        .chunk
        .inputs
        .iter()
        .map(|input| input.utxo.poi.blinded_commitment)
        .collect::<Vec<_>>();
    for list_key in active_list_keys {
        proof_source
            .check_commitments_available(
                DEFAULT_TXID_VERSION,
                EVM_CHAIN_TYPE,
                cfg.chain.chain_id,
                list_key,
                &blinded_commitments,
            )
            .await
            .map_err(|err| {
                RecoveryFailure::retryable(
                    OutputPoiRecoveryStatus::ProofGenerationFailed,
                    format!("local POI proof preflight failed: {err}"),
                    output_poi_recovery_proof_retry_after(&err),
                )
            })?;
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn output_poi_recovery_input_blinded_commitments(
    candidate: &WalletUtxo,
    wallet_utxos: &[WalletUtxo],
    wallet_nullifiers: &WalletNullifierIndex<'_>,
    transactions: &[Transaction],
    scan_keys: &railgun_wallet::scan::WalletScanKeys,
    active_list_keys: &[FixedBytes<32>],
) -> Option<Vec<FixedBytes<32>>> {
    if transactions.len() != 1 {
        return None;
    }
    let output_commitment = U256::from_be_bytes(candidate.utxo.poi.commitment.0);
    for transaction in transactions {
        let Some(output_index) = transaction
            .commitments
            .iter()
            .position(|commitment| U256::from_be_bytes(commitment.0) == output_commitment)
        else {
            continue;
        };
        let has_unshield = transaction.boundParams.unshield != 0;
        let private_output_count =
            private_output_count_for_commitments(transaction.commitments.len(), has_unshield)
                .ok()?;
        if output_index >= private_output_count {
            return None;
        }
        let Ok(output_start_global) = output_start_global_position(&candidate.utxo, output_index)
        else {
            return None;
        };
        let output_start_tree = (output_start_global / u128::from(TREE_LEAF_COUNT)) as u32;
        let input_tree = u32::from(transaction.boundParams.treeNumber);
        if input_tree > output_start_tree {
            return None;
        }
        if output_notes_for_transaction(candidate, wallet_utxos, transaction, scan_keys).is_err() {
            return None;
        }
        let inputs =
            wallet_inputs_for_transaction(candidate, wallet_nullifiers, transaction).ok()?;
        if inputs.iter().any(|wallet_utxo| {
            active_list_keys.iter().any(|list_key| {
                wallet_utxo.utxo.poi.statuses.get(list_key) == Some(&PoiStatus::ShieldBlocked)
            })
        }) {
            return None;
        }
        return Some(
            inputs
                .iter()
                .map(|wallet_utxo| wallet_utxo.utxo.poi.blinded_commitment)
                .collect(),
        );
    }
    None
}

#[cfg(test)]
pub(super) fn build_output_poi_recovery_chunk(
    candidate: &WalletUtxo,
    wallet_nullifiers: &WalletNullifierIndex<'_>,
    transactions: &[Transaction],
    forest: &MerkleForest,
    active_list_keys: &[FixedBytes<32>],
    spending_public_key: [U256; 2],
    scan_keys: &railgun_wallet::scan::WalletScanKeys,
) -> Result<RecoveryChunk, RecoveryFailure> {
    if transactions.len() != 1 {
        return Err(RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::UnsupportedShape,
            "batched transactions are not treated as consolidation recovery",
        ));
    }
    let output_commitment = U256::from_be_bytes(candidate.utxo.poi.commitment.0);
    for transaction in transactions {
        let Some(output_index) = transaction
            .commitments
            .iter()
            .position(|commitment| U256::from_be_bytes(commitment.0) == output_commitment)
        else {
            continue;
        };
        let has_unshield = transaction.boundParams.unshield != 0;
        let private_output_count =
            private_output_count_for_commitments(transaction.commitments.len(), has_unshield)?;
        if output_index >= private_output_count {
            return Err(RecoveryFailure::permanent(
                OutputPoiRecoveryStatus::UnsupportedShape,
                "matched output is the public unshield output",
            ));
        }
        let output_start_global = output_start_global_position(&candidate.utxo, output_index)?;
        let output_notes = output_notes_for_transaction(
            candidate,
            wallet_nullifiers.wallet_utxos,
            transaction,
            scan_keys,
        )?;
        return build_recovery_chunk_for_transaction(
            output_start_global,
            output_notes,
            candidate.utxo.source.tx_hash,
            wallet_nullifiers,
            transaction,
            forest,
            active_list_keys,
            spending_public_key,
            scan_keys,
            None,
        );
    }

    Err(RecoveryFailure::permanent(
        OutputPoiRecoveryStatus::NotSelfOriginated,
        "source transaction does not contain the wallet output commitment",
    ))
}

pub(super) async fn build_output_poi_recovery_chunk_from_public_rows(
    candidate: &WalletUtxo,
    wallet_nullifiers: &WalletNullifierIndex<'_>,
    rows: &[PublicTxidTransaction],
    sender_candidate: Option<&SenderTransactionCandidate>,
    cached_transactions: &[Transaction],
    forest: &Arc<MerkleForest>,
    active_list_keys: &[FixedBytes<32>],
    spending_public_key: [U256; 2],
    scan_keys: &railgun_wallet::scan::WalletScanKeys,
) -> Result<RecoveryChunk, RecoveryFailure> {
    let output_commitment = U256::from_be_bytes(candidate.utxo.poi.commitment.0);
    let matches = rows
        .iter()
        .filter_map(|row| {
            if row.transaction.transaction_hash != candidate.utxo.source.tx_hash
                || row.transaction.block_number != candidate.utxo.source.block_number
            {
                return None;
            }
            let output_index = row
                .transaction
                .commitments
                .iter()
                .position(|commitment| *commitment == output_commitment)?;
            let private_output_count = private_output_count_for_commitments(
                row.transaction.commitments.len(),
                row.transaction.has_unshield,
            )
            .ok()?;
            (output_index < private_output_count).then_some((row, output_index))
        })
        .collect::<Vec<_>>();
    let [(row, output_index)] = matches.as_slice() else {
        return Err(RecoveryFailure::permanent(
            if matches.is_empty() {
                OutputPoiRecoveryStatus::NotSelfOriginated
            } else {
                OutputPoiRecoveryStatus::UnsupportedShape
            },
            "validated public TXID rows do not uniquely contain the wallet output",
        ));
    };
    let observed_output_start = output_start_global_position(&candidate.utxo, *output_index)?;
    if observed_output_start != row.transaction.output_start_global() {
        return Err(RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::UnsupportedShape,
            "wallet output position does not match the public TXID output range",
        ));
    }
    let output_notes = output_notes_for_public_transaction(
        candidate,
        wallet_nullifiers.wallet_utxos,
        &row.transaction,
        sender_candidate,
        cached_transactions,
        scan_keys,
    )?;
    build_recovery_chunk_for_public_transaction(
        observed_output_start,
        output_notes,
        candidate.utxo.source.tx_hash,
        wallet_nullifiers,
        &row.transaction,
        forest,
        active_list_keys,
        spending_public_key,
        scan_keys,
        Some(row.txid_index),
    )
    .await
}

fn output_notes_for_public_transaction(
    candidate: &WalletUtxo,
    wallet_utxos: &[WalletUtxo],
    transaction: &TxidPublicCacheTransaction,
    sender_candidate: Option<&SenderTransactionCandidate>,
    cached_transactions: &[Transaction],
    scan_keys: &railgun_wallet::scan::WalletScanKeys,
) -> Result<Vec<Note>, RecoveryFailure> {
    let private_output_count = private_output_count_for_commitments(
        transaction.commitments.len(),
        transaction.has_unshield,
    )?;
    let sender_candidate = sender_candidate
        .filter(|sender| sender.source == candidate.utxo.source && sender.validate().is_ok());
    let matching_cached_transactions = cached_transactions
        .iter()
        .filter(|cached| cached_transaction_matches_public_row(cached, transaction))
        .collect::<Vec<_>>();
    let cached_transaction = match matching_cached_transactions.as_slice() {
        [cached] => Some(*cached),
        _ => None,
    };
    let mut notes = Vec::with_capacity(private_output_count);
    for (output_index, commitment) in transaction
        .commitments
        .iter()
        .take(private_output_count)
        .enumerate()
    {
        let commitment = FixedBytes::from(commitment.to_be_bytes::<32>());
        if let Some(output) = wallet_utxos.iter().find(|wallet_utxo| {
            wallet_utxo.utxo.source.tx_hash == candidate.utxo.source.tx_hash
                && wallet_utxo.utxo.poi.commitment_kind == UtxoCommitmentKind::Transact
                && wallet_utxo.utxo.poi.commitment == commitment
        }) {
            notes.push(output.utxo.note.clone());
            continue;
        }
        let global = transaction
            .output_start_global()
            .checked_add(output_index as u128)
            .ok_or_else(|| {
                RecoveryFailure::permanent(
                    OutputPoiRecoveryStatus::UnsupportedShape,
                    "public TXID output range overflow",
                )
            })?;
        let tree = u32::try_from(global / u128::from(TREE_LEAF_COUNT)).map_err(|_| {
            RecoveryFailure::permanent(
                OutputPoiRecoveryStatus::UnsupportedShape,
                "public TXID output tree is out of range",
            )
        })?;
        let position = (global % u128::from(TREE_LEAF_COUNT)) as u64;
        let note = sender_candidate.and_then(|sender| {
            sender.outputs.iter().find_map(|output| {
                (output.tree == tree
                    && output.position == position
                    && output.commitment == commitment)
                    .then(|| output.note.clone())
                    .flatten()
            })
        });
        let note = note.or_else(|| {
            cached_transaction.and_then(|cached| {
                decrypt_outgoing_transaction_output_note(
                    cached,
                    output_index,
                    commitment,
                    scan_keys,
                )
            })
        });
        let Some(note) = note else {
            return Err(RecoveryFailure::permanent(
                OutputPoiRecoveryStatus::MissingWalletOutputs,
                "selected public TXID row requires unavailable sender output notes",
            ));
        };
        notes.push(note);
    }
    if notes.is_empty() {
        return Err(RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::UnsupportedShape,
            "transaction has no private outputs",
        ));
    }
    Ok(notes)
}

fn cached_transaction_matches_public_row(
    transaction: &Transaction,
    public: &TxidPublicCacheTransaction,
) -> bool {
    transaction.merkleRoot == FixedBytes::from(public.merkle_root.to_be_bytes::<32>())
        && transaction
            .nullifiers
            .iter()
            .map(|nullifier| U256::from_be_bytes(nullifier.0))
            .eq(public.nullifiers.iter().copied())
        && transaction
            .commitments
            .iter()
            .map(|commitment| U256::from_be_bytes(commitment.0))
            .eq(public.commitments.iter().copied())
        && transaction.boundParams.hash() == public.bound_params_hash
        && (transaction.boundParams.unshield != 0) == public.has_unshield
        && u64::from(u32::from(transaction.boundParams.treeNumber)) == public.utxo_tree_in
}

pub(super) async fn build_recovery_chunk_for_public_transaction(
    output_start_global: u128,
    mut output_notes: Vec<Note>,
    source_tx_hash: FixedBytes<32>,
    wallet_nullifiers: &WalletNullifierIndex<'_>,
    transaction: &TxidPublicCacheTransaction,
    forest: &Arc<MerkleForest>,
    active_list_keys: &[FixedBytes<32>],
    spending_public_key: [U256; 2],
    scan_keys: &railgun_wallet::scan::WalletScanKeys,
    target_txid_index: Option<u64>,
) -> Result<RecoveryChunk, RecoveryFailure> {
    if transaction.transaction_hash != source_tx_hash
        || transaction.output_start_global() != output_start_global
    {
        return Err(RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::UnsupportedShape,
            "public TXID row does not match the recovery source or output range",
        ));
    }
    let private_output_count = private_output_count_for_commitments(
        transaction.commitments.len(),
        transaction.has_unshield,
    )?;
    if output_notes.len() != private_output_count
        || output_notes.iter().map(Note::commitment).ne(transaction
            .commitments
            .iter()
            .take(private_output_count)
            .copied())
    {
        return Err(RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::MissingWalletOutputs,
            "private output notes do not match the public TXID commitments",
        ));
    }
    let output_start_tree = u32::try_from(output_start_global / u128::from(TREE_LEAF_COUNT))
        .map_err(|_| {
            RecoveryFailure::permanent(
                OutputPoiRecoveryStatus::UnsupportedShape,
                "public TXID output tree is out of range",
            )
        })?;
    let output_start_position = (output_start_global % u128::from(TREE_LEAF_COUNT)) as u64;
    let input_tree = u32::from(u16::try_from(transaction.utxo_tree_in).map_err(|_| {
        RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::UnsupportedShape,
            "public TXID input tree is out of ABI range",
        )
    })?);
    let max_leaf_count = match input_tree.cmp(&output_start_tree) {
        std::cmp::Ordering::Equal => output_start_position,
        std::cmp::Ordering::Less => TREE_LEAF_COUNT,
        std::cmp::Ordering::Greater => {
            return Err(RecoveryFailure::retryable(
                OutputPoiRecoveryStatus::MissingMerkleProof,
                "transaction input tree is after output tree",
                OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
            ));
        }
    };
    let inputs = wallet_inputs_for_public_transaction(
        source_tx_hash,
        wallet_nullifiers,
        input_tree,
        &transaction.nullifiers,
    )?;
    if inputs.iter().any(|wallet_utxo| {
        active_list_keys.iter().any(|list_key| {
            wallet_utxo.utxo.poi.statuses.get(list_key) == Some(&PoiStatus::ShieldBlocked)
        })
    }) {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::InputPoiNotValid,
            "one or more transaction inputs are shield-blocked",
            OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
        ));
    }
    let first_input = inputs.first().ok_or_else(|| {
        RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::MissingWalletInputs,
            "transaction has no wallet-owned inputs",
        )
    })?;
    let input_merkle = recovery_input_merkle_tree_for_root_blocking(
        Arc::clone(forest),
        input_tree,
        (*first_input).clone(),
        max_leaf_count,
        transaction.merkle_root,
    )
    .await?;
    let mut input_witnesses = Vec::with_capacity(inputs.len());
    for input in inputs {
        let proof = input_merkle.tree.prove(input.utxo.position);
        if proof.root != transaction.merkle_root || proof.leaf != input.utxo.note.commitment() {
            return Err(RecoveryFailure::retryable(
                OutputPoiRecoveryStatus::MissingMerkleProof,
                "reconstructed Merkle proof does not match transaction root",
                OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
            ));
        }
        input_witnesses.push(InputWitness {
            utxo: input.utxo.clone(),
            merkle_proof: proof,
        });
    }
    if let Some(unshield_note) = unshield_note_from_public_transaction(transaction)? {
        output_notes.push(unshield_note);
    }
    let public_inputs = PublicInputs::from_parts(
        transaction.merkle_root,
        transaction.bound_params_hash,
        transaction.nullifiers.clone(),
        &output_notes,
    );
    if public_inputs.commitments_out != transaction.commitments {
        return Err(RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::UnsupportedShape,
            "reconstructed outputs do not match public TXID commitments",
        ));
    }
    let signer = RecoverySpendPublicKey {
        spending_public_key,
    };
    let private_inputs = PrivateInputs::from_inputs(
        input_witnesses[0].utxo.token_address(),
        &input_witnesses,
        &output_notes,
        scan_keys,
        &signer,
    );
    Ok(RecoveryChunk {
        chunk: TransactionPlanChunk {
            tree_number: input_tree,
            merkle_root: transaction.merkle_root,
            inputs: input_witnesses,
            outputs: output_notes,
            has_unshield: transaction.has_unshield,
            public_inputs,
            private_inputs,
            signature: [U256::ZERO; 3],
        },
        output_start_global,
        target_txid_index,
    })
}

fn unshield_note_from_public_transaction(
    transaction: &TxidPublicCacheTransaction,
) -> Result<Option<Note>, RecoveryFailure> {
    if !transaction.has_unshield {
        return Ok(None);
    }
    let encoded = transaction.unshield_preimage.as_deref().ok_or_else(|| {
        RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::UnsupportedShape,
            "selected public TXID source cannot provide the unshield preimage",
        )
    })?;
    let preimage = CommitmentPreimage::abi_decode(encoded).map_err(|err| {
        RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::UnsupportedShape,
            format!("public TXID unshield preimage is invalid: {err}"),
        )
    })?;
    let note = preimage.note_with_random([0_u8; 16]);
    if preimage.abi_encode() != encoded
        || transaction.commitments.last() != Some(&note.commitment())
    {
        return Err(RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::UnsupportedShape,
            "public TXID unshield preimage does not match its commitment",
        ));
    }
    Ok(Some(note))
}

fn wallet_inputs_for_public_transaction<'a>(
    source_tx_hash: FixedBytes<32>,
    wallet_nullifiers: &'a WalletNullifierIndex<'a>,
    input_tree: u32,
    nullifiers: &[U256],
) -> Result<Vec<&'a WalletUtxo>, RecoveryFailure> {
    let mut inputs = Vec::with_capacity(nullifiers.len());
    for nullifier in nullifiers {
        let Some(input) = wallet_nullifiers.input_for(input_tree, *nullifier, source_tx_hash)
        else {
            return Err(RecoveryFailure::permanent(
                OutputPoiRecoveryStatus::NotSelfOriginated,
                "transaction nullifiers do not resolve to wallet-spent inputs",
            ));
        };
        inputs.push(input);
    }
    if inputs.is_empty() {
        return Err(RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::MissingWalletInputs,
            "transaction has no wallet-owned inputs",
        ));
    }
    Ok(inputs)
}

#[cfg(test)]
fn build_recovery_chunk_for_transaction(
    output_start_global: u128,
    mut output_notes: Vec<Note>,
    source_tx_hash: FixedBytes<32>,
    wallet_nullifiers: &WalletNullifierIndex<'_>,
    transaction: &Transaction,
    forest: &MerkleForest,
    active_list_keys: &[FixedBytes<32>],
    spending_public_key: [U256; 2],
    scan_keys: &railgun_wallet::scan::WalletScanKeys,
    target_txid_index: Option<u64>,
) -> Result<RecoveryChunk, RecoveryFailure> {
    let has_unshield = transaction.boundParams.unshield != 0;
    if output_notes.len()
        != private_output_count_for_commitments(transaction.commitments.len(), has_unshield)?
    {
        return Err(RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::MissingWalletOutputs,
            "private output notes do not match the transaction output count",
        ));
    }
    let output_start_tree = (output_start_global / u128::from(TREE_LEAF_COUNT)) as u32;
    let output_start_position = (output_start_global % u128::from(TREE_LEAF_COUNT)) as u64;
    let input_tree = u32::from(transaction.boundParams.treeNumber);
    let max_leaf_count = match input_tree.cmp(&output_start_tree) {
        std::cmp::Ordering::Equal => output_start_position,
        std::cmp::Ordering::Less => TREE_LEAF_COUNT,
        std::cmp::Ordering::Greater => {
            return Err(RecoveryFailure::retryable(
                OutputPoiRecoveryStatus::MissingMerkleProof,
                "transaction input tree is after output tree",
                OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
            ));
        }
    };
    let inputs =
        wallet_inputs_for_source_transaction(source_tx_hash, wallet_nullifiers, transaction)?;
    if inputs.iter().any(|wallet_utxo| {
        active_list_keys.iter().any(|list_key| {
            wallet_utxo.utxo.poi.statuses.get(list_key) == Some(&PoiStatus::ShieldBlocked)
        })
    }) {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::InputPoiNotValid,
            "one or more transaction inputs are shield-blocked",
            OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
        ));
    }
    let merkle_root = U256::from_be_bytes(transaction.merkleRoot.0);
    let first_input = inputs.first().ok_or_else(|| {
        RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::MissingWalletInputs,
            "transaction has no wallet-owned inputs",
        )
    })?;
    let input_merkle = recovery_input_merkle_tree_for_root(
        forest,
        input_tree,
        first_input,
        max_leaf_count,
        merkle_root,
    )?;
    let mut input_witnesses = Vec::with_capacity(inputs.len());
    for input in inputs {
        let proof = input_merkle.tree.prove(input.utxo.position);
        if proof.root != merkle_root || proof.leaf != input.utxo.note.commitment() {
            return Err(RecoveryFailure::retryable(
                OutputPoiRecoveryStatus::MissingMerkleProof,
                "reconstructed Merkle proof does not match transaction root",
                OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
            ));
        }
        input_witnesses.push(InputWitness {
            utxo: input.utxo.clone(),
            merkle_proof: proof,
        });
    }
    if let Some(unshield_note) = unshield_note_from_transaction(transaction)? {
        output_notes.push(unshield_note);
    }
    let public_inputs = PublicInputs::from_transaction(merkle_root, transaction, &output_notes);
    let signer = RecoverySpendPublicKey {
        spending_public_key,
    };
    let private_inputs = PrivateInputs::from_inputs(
        input_witnesses[0].utxo.token_address(),
        &input_witnesses,
        &output_notes,
        scan_keys,
        &signer,
    );
    Ok(RecoveryChunk {
        chunk: TransactionPlanChunk {
            tree_number: input_tree,
            merkle_root,
            inputs: input_witnesses,
            outputs: output_notes,
            has_unshield,
            public_inputs,
            private_inputs,
            signature: [U256::ZERO; 3],
        },
        output_start_global,
        target_txid_index,
    })
}

pub(super) fn output_start_global_position(
    utxo: &Utxo,
    output_index: usize,
) -> Result<u128, RecoveryFailure> {
    let global = u128::from(utxo.tree) * u128::from(TREE_LEAF_COUNT) + u128::from(utxo.position);
    global.checked_sub(output_index as u128).ok_or_else(|| {
        RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::UnsupportedShape,
            "output index is before observed output position",
        )
    })
}

pub(super) fn private_output_count_for_commitments(
    commitment_count: usize,
    has_unshield: bool,
) -> Result<usize, RecoveryFailure> {
    if has_unshield {
        commitment_count.checked_sub(1).ok_or_else(|| {
            RecoveryFailure::permanent(
                OutputPoiRecoveryStatus::UnsupportedShape,
                "unshield transaction has no public output commitment",
            )
        })
    } else {
        Ok(commitment_count)
    }
}

#[cfg(test)]
pub(super) fn unshield_note_from_transaction(
    transaction: &Transaction,
) -> Result<Option<Note>, RecoveryFailure> {
    if transaction.boundParams.unshield == 0 {
        return Ok(None);
    }
    let note = transaction.unshieldPreimage.note_with_random([0_u8; 16]);
    let Some(expected_commitment) = transaction.commitments.last() else {
        return Err(RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::UnsupportedShape,
            "unshield transaction has no public output commitment",
        ));
    };
    if note.commitment() != U256::from_be_bytes(expected_commitment.0) {
        return Err(RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::UnsupportedShape,
            "unshield preimage does not match public output commitment",
        ));
    }
    Ok(Some(note))
}

pub(super) struct RecoveryInputMerkleTree {
    pub(super) tree: DenseMerkleTree,
}

pub(super) fn recovery_input_merkle_tree_for_root(
    forest: &MerkleForest,
    input_tree: u32,
    first_input: &WalletUtxo,
    max_leaf_count: u64,
    merkle_root: U256,
) -> Result<RecoveryInputMerkleTree, RecoveryFailure> {
    let min_leaf_count = first_input.utxo.position.saturating_add(1);
    let max_leaf_count = max_leaf_count.min(TREE_LEAF_COUNT);
    if max_leaf_count < min_leaf_count {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::MissingMerkleProof,
            "transaction root predates the first wallet input leaf",
            OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
        ));
    }
    if forest
        .leaf_at(input_tree, first_input.utxo.position)
        .is_none()
    {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::MissingMerkleProof,
            "input tree missing from local Merkle forest",
            OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
        ));
    }
    let mut tree = DenseMerkleTree::from_forest_prefix(forest, input_tree, max_leaf_count);
    for leaf_count in (min_leaf_count..=max_leaf_count).rev() {
        if tree.root() == merkle_root {
            let proof = tree.prove(first_input.utxo.position);
            if proof.leaf == first_input.utxo.note.commitment() && proof.root == merkle_root {
                return Ok(RecoveryInputMerkleTree { tree });
            }
        }
        if leaf_count > min_leaf_count {
            tree.remove_leaf(leaf_count - 1);
        }
    }
    Err(RecoveryFailure::retryable(
        OutputPoiRecoveryStatus::MissingMerkleProof,
        "reconstructed Merkle proof does not match transaction root in local Merkle history",
        OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
    ))
}

async fn recovery_input_merkle_tree_for_root_blocking(
    forest: Arc<MerkleForest>,
    input_tree: u32,
    first_input: WalletUtxo,
    max_leaf_count: u64,
    merkle_root: U256,
) -> Result<RecoveryInputMerkleTree, RecoveryFailure> {
    tokio::task::spawn_blocking(move || {
        recovery_input_merkle_tree_for_root(
            &forest,
            input_tree,
            &first_input,
            max_leaf_count,
            merkle_root,
        )
    })
    .await
    .map_err(|error| {
        RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::MissingMerkleProof,
            format!("historical Merkle proof search failed: {error}"),
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        )
    })?
}

#[cfg(test)]
pub(super) fn output_notes_for_transaction(
    candidate: &WalletUtxo,
    wallet_utxos: &[WalletUtxo],
    transaction: &Transaction,
    scan_keys: &railgun_wallet::scan::WalletScanKeys,
) -> Result<Vec<Note>, RecoveryFailure> {
    let private_output_count = private_output_count_for_commitments(
        transaction.commitments.len(),
        transaction.boundParams.unshield != 0,
    )?;
    let mut notes = Vec::with_capacity(private_output_count);
    let mut missing = Vec::new();
    for (output_index, commitment) in transaction
        .commitments
        .iter()
        .take(private_output_count)
        .enumerate()
    {
        let commitment = FixedBytes::from(commitment.0);
        if let Some(output) = wallet_utxos.iter().find(|wallet_utxo| {
            wallet_utxo.utxo.source.tx_hash == candidate.utxo.source.tx_hash
                && wallet_utxo.utxo.poi.commitment_kind == UtxoCommitmentKind::Transact
                && wallet_utxo.utxo.poi.commitment == commitment
        }) {
            notes.push(output.utxo.note.clone());
        } else if let Some(note) = decrypt_outgoing_transaction_output_note(
            transaction,
            output_index,
            commitment,
            scan_keys,
        ) {
            notes.push(note);
        } else {
            missing.push((output_index, commitment));
        }
    }
    if !missing.is_empty() {
        return Err(missing_wallet_outputs_failure(
            &missing,
            private_output_count,
        ));
    }
    if notes.is_empty() {
        return Err(RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::UnsupportedShape,
            "transaction has no private outputs",
        ));
    }
    Ok(notes)
}

fn decrypt_outgoing_transaction_output_note(
    transaction: &Transaction,
    output_index: usize,
    expected_commitment: FixedBytes<32>,
    scan_keys: &railgun_wallet::scan::WalletScanKeys,
) -> Option<Note> {
    let ciphertext = transaction
        .boundParams
        .commitmentCiphertext
        .get(output_index)?;
    let expected_commitment = U256::from_be_bytes(expected_commitment.0);
    railgun_wallet::decrypt_sender_note(ciphertext, expected_commitment, scan_keys)
}

#[cfg(test)]
fn missing_wallet_outputs_failure(
    missing: &[(usize, FixedBytes<32>)],
    private_output_count: usize,
) -> RecoveryFailure {
    let displayed = missing
        .iter()
        .take(8)
        .map(|(index, commitment)| format!("{index}:{}", hex::encode(commitment)))
        .collect::<Vec<_>>()
        .join(",");
    let truncated = missing
        .len()
        .checked_sub(8)
        .filter(|remaining| *remaining > 0)
        .map_or_else(String::new, |remaining| format!(";{remaining}_more"));
    RecoveryFailure::permanent(
        OutputPoiRecoveryStatus::MissingWalletOutputs,
        format!(
            "not all private transaction outputs are wallet-owned; missing_private_outputs={}/{} [{}{}]",
            missing.len(),
            private_output_count,
            displayed,
            truncated
        ),
    )
}

#[cfg(test)]
pub(super) fn wallet_inputs_for_transaction<'a>(
    candidate: &WalletUtxo,
    wallet_nullifiers: &'a WalletNullifierIndex<'a>,
    transaction: &Transaction,
) -> Result<Vec<&'a WalletUtxo>, RecoveryFailure> {
    wallet_inputs_for_source_transaction(
        candidate.utxo.source.tx_hash,
        wallet_nullifiers,
        transaction,
    )
}

#[cfg(test)]
pub(super) fn wallet_inputs_for_source_transaction<'a>(
    source_tx_hash: FixedBytes<32>,
    wallet_nullifiers: &'a WalletNullifierIndex<'a>,
    transaction: &Transaction,
) -> Result<Vec<&'a WalletUtxo>, RecoveryFailure> {
    let input_tree = u32::from(transaction.boundParams.treeNumber);
    let mut inputs = Vec::with_capacity(transaction.nullifiers.len());
    for nullifier in &transaction.nullifiers {
        let nullifier = U256::from_be_bytes(nullifier.0);
        let Some(input) = wallet_nullifiers.input_for(input_tree, nullifier, source_tx_hash) else {
            return Err(RecoveryFailure::permanent(
                OutputPoiRecoveryStatus::NotSelfOriginated,
                "transaction nullifiers do not resolve to wallet-spent inputs",
            ));
        };
        inputs.push(input);
    }
    if inputs.is_empty() {
        return Err(RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::MissingWalletInputs,
            "transaction has no wallet-owned inputs",
        ));
    }
    Ok(inputs)
}

pub(super) fn pending_output_poi_context_from_recovery(
    cfg: &WalletConfig,
    candidate: &WalletUtxo,
    recovery_chunk: &RecoveryChunk,
    txid_merkleroot_index: u64,
    pre_transaction_pois: PreTransactionPoiMap,
    active_list_keys: &[FixedBytes<32>],
    now: u64,
) -> PendingOutputPoiContextRecord {
    pending_output_poi_context_from_output_recovery(
        cfg,
        &candidate.utxo,
        recovery_chunk,
        txid_merkleroot_index,
        pre_transaction_pois,
        active_list_keys,
        PendingOutputPoiRole::Change,
        format!(
            "recovered-output-poi:{}",
            hex::encode(candidate.utxo.source.tx_hash)
        ),
        now,
    )
}

pub(super) fn pending_output_poi_context_from_output_recovery(
    cfg: &WalletConfig,
    output: &Utxo,
    recovery_chunk: &RecoveryChunk,
    txid_merkleroot_index: u64,
    pre_transaction_pois: PreTransactionPoiMap,
    active_list_keys: &[FixedBytes<32>],
    output_role: PendingOutputPoiRole,
    source_operation_id: String,
    now: u64,
) -> PendingOutputPoiContextRecord {
    PendingOutputPoiContextRecord {
        chain_id: cfg.chain.chain_id,
        wallet_id: cfg.cache_key.to_string(),
        txid_version: DEFAULT_TXID_VERSION.to_string(),
        output_commitment: output.poi.commitment,
        output_npk: output.poi.npk,
        utxo_tree_in: u64::from(recovery_chunk.chunk.tree_number),
        railgun_txid: recovery_chunk.chunk.railgun_txid(),
        txid_merkleroot_index: Some(txid_merkleroot_index),
        pre_transaction_pois_per_txid_leaf_per_list: pre_transaction_pois,
        required_poi_list_keys: active_list_keys.to_vec(),
        output_role,
        created_at: now,
        source_operation_id: Some(source_operation_id),
        observation: Some(PendingOutputPoiObservation {
            output_tree: u64::from(output.tree),
            output_position: output.position,
            tx_hash: output.source.tx_hash,
            block_number: output.source.block_number,
            block_timestamp: output.source.block_timestamp,
        }),
        submitted_poi_list_keys: Vec::new(),
        terminal_error: None,
    }
}

pub(super) fn newly_recoverable_output_poi_list_keys(
    context: &PendingOutputPoiContextRecord,
    recoverable_list_keys: &[FixedBytes<32>],
) -> Vec<FixedBytes<32>> {
    let represented_list_keys = context.list_keys();
    recoverable_list_keys
        .iter()
        .copied()
        .filter(|list_key| !represented_list_keys.contains(list_key))
        .collect()
}

pub(super) fn extend_pending_output_poi_context(
    context: &PendingOutputPoiContextRecord,
    new_list_keys: &[FixedBytes<32>],
    mut new_pre_transaction_pois: PreTransactionPoiMap,
) -> PendingOutputPoiContextRecord {
    let mut extended = context.clone();
    if extended.required_poi_list_keys.is_empty() {
        extended.required_poi_list_keys = extended.list_keys();
    }
    for list_key in new_list_keys {
        if let Some(per_leaf) = new_pre_transaction_pois.remove(list_key) {
            extended
                .pre_transaction_pois_per_txid_leaf_per_list
                .entry(*list_key)
                .or_insert(per_leaf);
        }
        if !extended.required_poi_list_keys.contains(list_key) {
            extended.required_poi_list_keys.push(*list_key);
        }
    }
    extended
}

pub(super) fn log_forced_output_poi_recovery_regeneration(
    cfg: &WalletConfig,
    _candidate: &WalletUtxo,
    _existing_pending_context: &PendingOutputPoiContextRecord,
) {
    debug!(
        chain_id = cfg.chain.chain_id,
        "force-regenerating recovered output POI context"
    );
}

pub(super) fn new_output_poi_recovery_record(
    cfg: &WalletConfig,
    candidate: &WalletUtxo,
    status: OutputPoiRecoveryStatus,
    now: u64,
) -> OutputPoiRecoveryRecord {
    new_output_poi_recovery_record_for_output(cfg, &candidate.utxo, status, now)
}

pub(super) fn new_output_poi_recovery_record_for_output(
    cfg: &WalletConfig,
    output: &Utxo,
    status: OutputPoiRecoveryStatus,
    now: u64,
) -> OutputPoiRecoveryRecord {
    OutputPoiRecoveryRecord {
        chain_id: cfg.chain.chain_id,
        wallet_id: cfg.cache_key.to_string(),
        output_commitment: output.poi.commitment,
        source_tx_hash: output.source.tx_hash,
        tx_input: None,
        status,
        created_at: now,
        updated_at: now,
        last_detection_at: None,
        last_submission_at: None,
        next_retry_at: None,
        attempt_count: 0,
        last_error: None,
    }
}

pub(super) async fn record_output_poi_recovery_failure(
    authority: &WalletPrivateMutationAuthority<'_>,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    candidate: &WalletUtxo,
    active_list_keys: &[FixedBytes<32>],
    target_list_keys: &[FixedBytes<32>],
    failure: RecoveryFailure,
    now: u64,
) {
    let status = failure.status;
    let message = failure.message;
    let Ok(current_recovery) = cache_store.get_output_poi_recovery(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &candidate.utxo.poi.commitment,
    ) else {
        warn!(
            chain_id = cfg.chain.chain_id,
            "failed to load output POI recovery failure predecessor"
        );
        return;
    };
    let Some(expected_recovery) = expected_recovery_state(current_recovery.as_ref()) else {
        return;
    };
    if apply_poi_private_delta(
        authority,
        db,
        cache_store,
        cfg,
        OwnedPoiPrivateDelta::OutputRecovery {
            expected_output: ExpectedWalletOutput::new(candidate),
            active_list_keys: active_list_keys.to_vec(),
            target_list_keys: target_list_keys.to_vec(),
            required_poi_status: ExpectedPoiStatus::Recoverable,
            pending_update: Box::new(None),
            expected_recovery,
            action: OutputPoiRecoveryAction::Detected {
                status,
                retry_after: failure.retry_after,
                last_error: Some(message.clone()),
                increment_attempts: true,
            },
            now,
        },
    )
    .await
    .is_err()
    {
        warn!(
            chain_id = cfg.chain.chain_id,
            "failed to persist output POI recovery failure state"
        );
    }
    debug!(
        chain_id = cfg.chain.chain_id,
        status = ?status,
        "output POI recovery skipped"
    );
}

pub(super) async fn mark_valid_output_poi_recoveries(
    authority: &WalletPrivateMutationAuthority<'_>,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    wallet_utxos: &[WalletUtxo],
    active_list_keys: &[FixedBytes<32>],
) {
    if active_list_keys.is_empty() {
        return;
    }
    let now = now_epoch_secs();
    for wallet_utxo in wallet_utxos.iter().filter(|wallet_utxo| {
        !wallet_utxo.is_spent()
            && wallet_utxo.utxo.poi.is_valid_for_lists(active_list_keys)
            && wallet_utxo.utxo.poi.commitment_kind == UtxoCommitmentKind::Transact
    }) {
        let Ok(Some(record)) = cache_store.get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &wallet_utxo.utxo.poi.commitment,
        ) else {
            continue;
        };
        if record.status == OutputPoiRecoveryStatus::Valid {
            continue;
        }
        let Some(expected_recovery) = expected_recovery_state(Some(&record)) else {
            continue;
        };
        if apply_poi_private_delta(
            authority,
            db,
            cache_store,
            cfg,
            OwnedPoiPrivateDelta::OutputRecovery {
                expected_output: ExpectedWalletOutput::new(wallet_utxo),
                active_list_keys: active_list_keys.to_vec(),
                target_list_keys: active_list_keys.to_vec(),
                required_poi_status: ExpectedPoiStatus::Valid,
                pending_update: Box::new(None),
                expected_recovery,
                action: OutputPoiRecoveryAction::Valid,
                now,
            },
        )
        .await
        .is_err()
        {
            warn!(
                chain_id = cfg.chain.chain_id,
                "failed to mark output POI recovery valid"
            );
        }
    }
}

pub(super) async fn mark_valid_output_poi_recoveries_authorized(
    authority: &WalletPrivateMutationAuthority<'_>,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    utxos: &Arc<RwLock<Vec<WalletUtxo>>>,
    active_list_keys: &[FixedBytes<32>],
) {
    if authority.revalidate().is_err() {
        debug!(
            chain_id = cfg.chain.chain_id,
            "mark output POI recoveries valid skipped"
        );
        return;
    }
    let snapshot = utxos.read().await.clone();
    mark_valid_output_poi_recoveries(authority, db, cache_store, cfg, &snapshot, active_list_keys)
        .await;
}

#[cfg(test)]
pub(super) mod test_support {
    use super::*;
    use crate::wallet::pending_output_poi::test_support::{
        pending_output_poi_context_still_current_unchecked, pending_output_poi_recovery_update,
        submit_pending_output_poi_context,
    };
    use crate::wallet::{PendingOutputPoiSubmitter, SingleCommitmentProofContext};
    pub(in crate::wallet) use public_cache::{
        PublicCacheTxidRecoveryRequest, recovered_output_txid_data_from_public_cache,
    };

    async fn force_resubmit_matching_pending_output_pois_unchecked(
        db: &DbStore,
        cfg: &WalletConfig,
        wallet_utxos: &[WalletUtxo],
        active_list_keys: &[FixedBytes<32>],
        submitter: &dyn PendingOutputPoiSubmitter,
    ) -> usize {
        if active_list_keys.is_empty() {
            return 0;
        }

        let now = now_epoch_secs();
        let mut attempted_contexts = 0usize;
        for candidate in output_poi_recovery_candidates(wallet_utxos, active_list_keys) {
            let output_commitment = candidate.utxo.poi.commitment;
            let mut record = match db.get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &output_commitment,
            ) {
                Ok(Some(record)) => record,
                Ok(None) => continue,
                Err(_) => {
                    warn!(
                        chain_id = cfg.chain.chain_id,
                        "failed to load matching pending output POI context"
                    );
                    continue;
                }
            };
            if record.terminal_error.is_some()
                || !pending_output_poi_context_matches_wallet_utxo(cfg, candidate, &record)
            {
                continue;
            }

            let mut submitted_list_keys = record.list_keys();
            submitted_list_keys.retain(|list_key| active_list_keys.contains(list_key));
            if submitted_list_keys.is_empty() {
                continue;
            }
            let pre_transaction_pois = record.retain_poi_lists(&submitted_list_keys);
            if pre_transaction_pois.len() != submitted_list_keys.len() {
                record.terminal_error =
                    Some("missing pre-transaction POI for pending output".to_string());
                if db.put_pending_output_poi_context(&record).is_err() {
                    warn!(
                        chain_id = cfg.chain.chain_id,
                        "failed to mark pending output POI context terminal"
                    );
                }
                continue;
            }
            let Some(observation) = record.observation.clone() else {
                continue;
            };
            let context = SingleCommitmentProofContext {
                txid_version: record.txid_version.clone(),
                railgun_txid: record.railgun_txid,
                utxo_tree_in: record.utxo_tree_in,
                commitment: record.output_commitment,
                npk: record.output_npk,
                pre_transaction_pois_per_txid_leaf_per_list: pre_transaction_pois,
            };
            attempted_contexts += 1;
            match submit_pending_output_poi_context(
                submitter,
                cfg.chain.chain_id,
                &record,
                &context,
                &observation,
                &submitted_list_keys,
            )
            .await
            {
                Ok(()) => {
                    match pending_output_poi_context_still_current_unchecked(
                        db,
                        cfg.chain.chain_id,
                        &cfg.cache_key,
                        &record,
                    ) {
                        Ok(true) => {}
                        Ok(false) => continue,
                        Err(_) => {
                            warn!(
                                chain_id = cfg.chain.chain_id,
                                "failed to revalidate resubmitted pending output POI context"
                            );
                            continue;
                        }
                    }
                    for list_key in &submitted_list_keys {
                        if !record.submitted_poi_list_keys.contains(list_key) {
                            record.submitted_poi_list_keys.push(*list_key);
                        }
                    }
                    let Ok(pending_recovery) = pending_output_poi_recovery_update(
                        db,
                        cfg.chain.chain_id,
                        &record,
                        &observation,
                        now,
                        OutputPoiRecoveryAction::Submitted {
                            retry_after: PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER,
                        },
                    ) else {
                        warn!(
                            chain_id = cfg.chain.chain_id,
                            "failed to prepare resubmitted pending output POI recovery state"
                        );
                        continue;
                    };
                    let mut recovery_updates = vec![pending_recovery];
                    if record.wallet_id != cfg.cache_key.as_str() {
                        recovery_updates.push(output_poi_recovery_record_update(
                            db,
                            cfg,
                            candidate,
                            now,
                            OutputPoiRecoveryAction::Submitted {
                                retry_after: OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
                            },
                        ));
                    }
                    if db.put_pending_output_poi_context(&record).is_err() {
                        warn!(
                            chain_id = cfg.chain.chain_id,
                            "failed to persist resubmitted pending output POI context"
                        );
                        continue;
                    }
                    for recovery in &recovery_updates {
                        if db.put_output_poi_recovery(recovery).is_err() {
                            warn!(
                                chain_id = cfg.chain.chain_id,
                                "failed to persist resubmitted pending output POI recovery state"
                            );
                        }
                    }
                }
                Err(err) => {
                    match pending_output_poi_context_still_current_unchecked(
                        db,
                        cfg.chain.chain_id,
                        &cfg.cache_key,
                        &record,
                    ) {
                        Ok(true) => {}
                        Ok(false) => continue,
                        Err(_) => {
                            warn!(
                                chain_id = cfg.chain.chain_id,
                                "failed to revalidate failed pending output POI resubmission"
                            );
                            continue;
                        }
                    }
                    let recovery = output_poi_recovery_record_update(
                        db,
                        cfg,
                        candidate,
                        now,
                        OutputPoiRecoveryAction::SubmitFailed {
                            error: err.to_string(),
                            retry_after: OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
                        },
                    );
                    if db.put_output_poi_recovery(&recovery).is_err() {
                        warn!(
                            chain_id = cfg.chain.chain_id,
                            "failed to persist failed pending output POI resubmission state"
                        );
                    }
                    warn!(
                        chain_id = cfg.chain.chain_id,
                        "forced pending output POI resubmission failed"
                    );
                }
            }
        }

        attempted_contexts
    }

    pub(in crate::wallet) async fn force_resubmit_matching_pending_output_pois(
        db: &DbStore,
        cfg: &WalletConfig,
        wallet_utxos: &[WalletUtxo],
        active_list_keys: &[FixedBytes<32>],
        submitter: &dyn PendingOutputPoiSubmitter,
    ) -> usize {
        force_resubmit_matching_pending_output_pois_unchecked(
            db,
            cfg,
            wallet_utxos,
            active_list_keys,
            submitter,
        )
        .await
    }

    pub(super) fn output_poi_recovery_record_update(
        db: &DbStore,
        cfg: &WalletConfig,
        candidate: &WalletUtxo,
        now: u64,
        action: OutputPoiRecoveryAction,
    ) -> OutputPoiRecoveryRecord {
        let existing = db
            .get_output_poi_recovery(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &candidate.utxo.poi.commitment,
            )
            .ok()
            .flatten();
        let default_status = match &action {
            OutputPoiRecoveryAction::Detected { status, .. } => *status,
            OutputPoiRecoveryAction::CacheTxInput { .. }
            | OutputPoiRecoveryAction::ExtendContext => OutputPoiRecoveryStatus::Recoverable,
            OutputPoiRecoveryAction::Submitted { .. } => OutputPoiRecoveryStatus::Submitted,
            OutputPoiRecoveryAction::SubmitFailed { .. } => OutputPoiRecoveryStatus::SubmitFailed,
            OutputPoiRecoveryAction::Valid => OutputPoiRecoveryStatus::Valid,
        };
        let mut record = existing
            .unwrap_or_else(|| new_output_poi_recovery_record(cfg, candidate, default_status, now));
        record.apply_action(action, now);
        record
    }
}
