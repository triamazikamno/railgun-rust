use super::*;
mod public_cache;

#[cfg(not(test))]
use public_cache::{PublicCacheTxidRecoveryRequest, recovered_output_txid_data_from_public_cache};
#[cfg(test)]
pub(super) use public_cache::{
    PublicCacheTxidRecoveryRequest, recovered_output_txid_data_from_public_cache,
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
    pub(super) rpcs: &'a QueryRpcPool,
    pub(super) http_client: Option<&'a reqwest::Client>,
    pub(super) indexed_artifact_source: Option<&'a IndexedArtifactSourceConfig>,
    pub(super) forest: &'a MerkleForest,
    pub(super) poi_client: &'a PoiRpcClient,
    pub(super) private_poi: &'a WalletPrivatePoiClients,
    pub(super) poi_runtime: &'a WalletPoiRuntime,
    pub(super) active_list_keys: &'a [FixedBytes<32>],
    pub(super) wallet_utxos: &'a [WalletUtxo],
    pub(super) force_retry: bool,
}

enum OutputPoiProofSourceResolution {
    Local(LocalPoiMerkleProofSource),
    RemoteFallback,
    Unavailable,
}

/// Trait adapter that makes every remote proof read a separately authorized effect.
/// `generate_post_transaction_pois` may request multiple lists; each request revalidates.
pub(super) struct OutputRecoveryRemoteProofSource<'a> {
    pub(super) private_poi: &'a WalletPrivatePoiClients,
    pub(super) authority: &'a WalletPrivateMutationAuthority<'a>,
    pub(super) db: &'a DbStore,
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
                            self.db,
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
    async fn local_proof_source_if_ready(
        &self,
        required_poi_list_keys: &[FixedBytes<32>],
    ) -> Option<LocalPoiMerkleProofSource> {
        match self.poi_runtime {
            WalletPoiRuntime::IndexedArtifacts { .. } => {
                let corpus = self
                    .public_data_plane
                    .ensure_poi_corpus(PublicPoiCorpusKey::wallet_default(self.cfg.chain.chain_id))
                    .await
                    .ok()?;
                let source = LocalPoiMerkleProofSource::new(corpus.local_caches());
                source
                    .available_for_lists(self.cfg.chain.chain_id, required_poi_list_keys)
                    .await
                    .then_some(source)
            }
            WalletPoiRuntime::PoiProxy { .. } => None,
        }
    }

    async fn resolve_proof_source(
        &self,
        required_poi_list_keys: &[FixedBytes<32>],
    ) -> OutputPoiProofSourceResolution {
        match self.poi_runtime {
            WalletPoiRuntime::IndexedArtifacts { .. } => {
                if let Some(source) = self
                    .local_proof_source_if_ready(required_poi_list_keys)
                    .await
                {
                    OutputPoiProofSourceResolution::Local(source)
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
            self.db,
            self.cfg,
            candidate,
            required_poi_list_keys,
        )
        .await
    }
}

async fn output_poi_recovery_candidate_still_current(
    authority: &WalletPrivateMutationAuthority<'_>,
    db: &DbStore,
    cfg: &WalletConfig,
    candidate: &WalletUtxo,
    required_poi_list_keys: &[FixedBytes<32>],
) -> bool {
    if required_poi_list_keys.is_empty() {
        return false;
    }
    if let Err(reason) = authority.revalidate() {
        debug!(
            ?reason,
            cache_key = %cfg.cache_key,
            commitment = %hex::encode(candidate.utxo.poi.commitment),
            "output POI recovery side effect rejected"
        );
        return false;
    }
    let snapshot = match authority.wallet_utxos().await {
        Ok(snapshot) => snapshot,
        Err(reason) => {
            debug!(
                ?reason,
                cache_key = %cfg.cache_key,
                commitment = %hex::encode(candidate.utxo.poi.commitment),
                "output POI recovery side effect skipped before wallet state check"
            );
            return false;
        }
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
            cache_key = %cfg.cache_key,
            commitment = %hex::encode(candidate.utxo.poi.commitment),
            "output POI recovery side effect skipped; output no longer matches wallet state"
        );
        return false;
    }
    match db.get_output_poi_recovery(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &candidate.utxo.poi.commitment,
    ) {
        Ok(record) if output_poi_recovery_source_matches_candidate(record.as_ref(), candidate) => {}
        Ok(_) => {
            debug!(
                cache_key = %cfg.cache_key,
                commitment = %hex::encode(candidate.utxo.poi.commitment),
                source_tx_hash = %hex::encode(candidate.utxo.source.tx_hash),
                "output POI recovery side effect skipped; cached recovery source transaction is stale"
            );
            return false;
        }
        Err(err) => {
            debug!(
                ?err,
                cache_key = %cfg.cache_key,
                commitment = %hex::encode(candidate.utxo.poi.commitment),
                "output POI recovery side effect skipped; recovery source could not be checked"
            );
            return false;
        }
    }
    if let Err(reason) = authority.revalidate() {
        debug!(
            ?reason,
            cache_key = %cfg.cache_key,
            commitment = %hex::encode(candidate.utxo.poi.commitment),
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
    pub(super) output: Utxo,
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

#[derive(Deserialize)]
pub(super) struct JsonRpcResponse<T> {
    pub(super) result: Option<T>,
    pub(super) error: Option<JsonRpcError>,
}

#[derive(Deserialize)]
pub(super) struct JsonRpcError {
    pub(super) message: String,
}

#[derive(Deserialize)]
pub(super) struct JsonRpcTransaction {
    pub(super) input: Option<String>,
    pub(super) data: Option<String>,
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
    let mut fetched_inputs: HashMap<FixedBytes<32>, Result<Bytes, RecoveryFailure>> =
        HashMap::new();
    let mut recovered = 0usize;
    let candidates = output_poi_recovery_candidates(request.wallet_utxos, request.active_list_keys);
    let wallet_nullifiers = WalletNullifierIndex::new(request.wallet_utxos, &request.cfg.scan_keys);
    debug!(
        cache_key = %request.cfg.cache_key,
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
        let existing_pending_context = match request.db.get_pending_output_poi_context(
            request.cfg.chain.chain_id,
            &request.cfg.cache_key,
            &output_commitment,
        ) {
            Ok(record) => record,
            Err(err) => {
                warn!(?err, cache_key = %request.cfg.cache_key, commitment = %hex::encode(output_commitment), "failed to load pending output POI recovery predecessor");
                continue;
            }
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
                            cache_key = %request.cfg.cache_key,
                            commitment = %hex::encode(output_commitment),
                            source_tx_hash = %hex::encode(source_tx_hash),
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

        let existing_recovery = match request.db.get_output_poi_recovery(
            request.cfg.chain.chain_id,
            &request.cfg.cache_key,
            &output_commitment,
        ) {
            Ok(record) => record,
            Err(err) => {
                warn!(
                    ?err,
                    cache_key = %request.cfg.cache_key,
                    commitment = %hex::encode(output_commitment),
                    "failed to load output POI recovery cache"
                );
                continue;
            }
        };
        if let Some(record) = existing_recovery
            .as_ref()
            .filter(|record| record.source_tx_hash != source_tx_hash)
        {
            debug!(
                cache_key = %request.cfg.cache_key,
                commitment = %hex::encode(output_commitment),
                source_tx_hash = %hex::encode(source_tx_hash),
                cached_source_tx_hash = %hex::encode(record.source_tx_hash),
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
                cache_key = %request.cfg.cache_key,
                commitment = %hex::encode(output_commitment),
                source_tx_hash = %hex::encode(source_tx_hash),
                status = ?record.status,
                force_retry = request.force_retry,
                last_error = ?record.last_error,
                "output POI recovery skipped; cached recovery state is not retryable"
            );
            continue;
        }

        let build_chunk_started = Instant::now();
        let recovery_chunk =
            match build_output_poi_recovery_chunk_from_calldata(CalldataRecoveryBuildRequest {
                request: &request,
                candidate,
                source_tx_hash,
                output_commitment,
                fetched_inputs: &mut fetched_inputs,
                wallet_nullifiers: &wallet_nullifiers,
                required_poi_list_keys: &recoverable_list_keys,
                spending_public_key,
                now,
                candidate_started,
            })
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
            cache_key = %request.cfg.cache_key,
            commitment = %hex::encode(output_commitment),
            source_tx_hash = %hex::encode(source_tx_hash),
            inputs = recovery_chunk.chunk.inputs.len(),
            outputs = recovery_chunk.chunk.outputs.len(),
            output_start_global = recovery_chunk.output_start_global,
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
                source_tx_hash,
                output_commitment,
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
            cache_key = %request.cfg.cache_key,
            commitment = %hex::encode(output_commitment),
            source_tx_hash = %hex::encode(source_tx_hash),
            target_txid_index = txid_data.target_txid_index,
            txid_merkleroot_index = txid_data.poi_data.txid_merkleroot_index,
            txid_data_elapsed_ms,
            candidate_elapsed_ms = candidate_started.elapsed().as_millis(),
            "output POI recovery TXID data recovered"
        );

        // Protocol A: last-moment fence after long TXID await, before any private-disclosing proof RPC.
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
            db: request.db,
            cfg: request.cfg,
            candidate,
            required_poi_list_keys: &recoverable_list_keys,
        };
        let proof_source: &dyn PoiMerkleProofSource = match &proof_source_resolution {
            OutputPoiProofSourceResolution::Local(source) => source,
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
                let current_recovery = match request.db.get_output_poi_recovery(
                    request.cfg.chain.chain_id,
                    &request.cfg.cache_key,
                    &output_commitment,
                ) {
                    Ok(record) => record,
                    Err(err) => {
                        warn!(?err, cache_key = %request.cfg.cache_key, commitment = %hex::encode(output_commitment), "failed to load recovered output POI predecessor");
                        continue;
                    }
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
                        active_list_keys: recoverable_list_keys.clone(),
                        required_poi_status: ExpectedPoiStatus::Recoverable,
                        pending_update: Some((expected_pending_context, record)),
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
                    Err(err) => {
                        warn!(
                            ?err,
                            cache_key = %request.cfg.cache_key,
                            commitment = %hex::encode(output_commitment),
                            "failed to persist recovered output POI context"
                        );
                        continue;
                    }
                }
                debug!(
                    cache_key = %request.cfg.cache_key,
                    commitment = %hex::encode(output_commitment),
                    wallet_blinded_commitment = %hex::encode(candidate.utxo.poi.blinded_commitment),
                    source_tx_hash = %hex::encode(source_tx_hash),
                    txid_merkleroot_index = txid_data.poi_data.txid_merkleroot_index,
                    target_txid_index = txid_data.target_txid_index,
                    inputs = recovery_chunk.chunk.inputs.len(),
                    outputs = recovery_chunk.chunk.outputs.len(),
                    input_tree = recovery_chunk.chunk.tree_number,
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
                    cache_key = %request.cfg.cache_key,
                    commitment = %hex::encode(output_commitment),
                    source_tx_hash = %hex::encode(source_tx_hash),
                    proof_generation_elapsed_ms,
                    candidate_elapsed_ms = candidate_started.elapsed().as_millis(),
                    error = %err,
                    "output POI recovery proof generation failed"
                );
                let retry_after = output_poi_recovery_proof_retry_after(&err);
                record_output_poi_recovery_failure(
                    request.authority,
                    request.db,
                    request.cache_store,
                    request.cfg,
                    candidate,
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
                cache_key = %request.cfg.cache_key,
                commitment = %hex::encode(output_commitment),
                source_tx_hash = %hex::encode(source_tx_hash),
                elapsed_ms = candidate_elapsed.as_millis(),
                "slow output POI recovery candidate"
            );
        } else {
            debug!(
                cache_key = %request.cfg.cache_key,
                commitment = %hex::encode(output_commitment),
                source_tx_hash = %hex::encode(source_tx_hash),
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
                    cache_key = %request.cfg.cache_key,
                    recovered,
                    submitted_contexts,
                    elapsed_ms = started.elapsed().as_millis(),
                    "recovered missing output POI contexts"
                );
            }
            Err(err) => {
                warn!(
                    ?err,
                    cache_key = %request.cfg.cache_key,
                    recovered,
                    "failed to submit recovered output POI contexts"
                );
            }
        }
    }

    debug!(
        cache_key = %request.cfg.cache_key,
        recovered,
        elapsed_ms = started.elapsed().as_millis(),
        "output POI recovery scan complete"
    );

    recovered
}

#[cfg(test)]
pub(super) async fn force_resubmit_matching_pending_output_pois(
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

pub(super) async fn force_resubmit_matching_pending_output_pois_authorized(
    authority: &WalletPrivateMutationAuthority<'_>,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    utxos: &Arc<RwLock<Vec<WalletUtxo>>>,
    active_list_keys: &[FixedBytes<32>],
    private_poi: &WalletPrivatePoiClients,
) -> usize {
    if let Err(reason) = authority.revalidate() {
        debug!(?reason, cache_key = %cfg.cache_key, "forced pending output POI resubmission skipped");
        return 0;
    }
    let snapshot = utxos.read().await.clone();
    force_resubmit_matching_pending_output_pois_impl(
        authority,
        db,
        cache_store,
        cfg,
        &snapshot,
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
    wallet_utxos: &[WalletUtxo],
    active_list_keys: &[FixedBytes<32>],
    private_poi: &WalletPrivatePoiClients,
) -> usize {
    if active_list_keys.is_empty() {
        return 0;
    }

    let now = now_epoch_secs();
    let mut attempted_contexts = 0usize;
    // Snapshot is discovery-only; liveness is revalidated per candidate via the shared choke point.
    for candidate in output_poi_recovery_candidates(wallet_utxos, active_list_keys) {
        let output_commitment = candidate.utxo.poi.commitment;
        let record = match db.get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &output_commitment,
        ) {
            Ok(Some(record)) => record,
            Ok(None) => continue,
            Err(err) => {
                warn!(
                    ?err,
                    cache_key = %cfg.cache_key,
                    commitment = %hex::encode(output_commitment),
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

        let Some(observation) = record.observation.clone() else {
            continue;
        };
        let current_recovery = match db.get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &output_commitment,
        ) {
            Ok(current) => current,
            Err(err) => {
                warn!(?err, cache_key = %cfg.cache_key, commitment = %hex::encode(output_commitment), "failed to load forced pending output POI recovery predecessor");
                continue;
            }
        };
        let Some(expected_recovery) = expected_recovery_state(current_recovery.as_ref()) else {
            continue;
        };
        let mut plan =
            PendingOutputPoiSubmissionPlan::force_matching(record.list_keys(), expected_recovery);
        plan.retain_current_recoverable(&record, active_list_keys, &candidate.utxo.poi);
        if plan.list_keys().is_empty() {
            continue;
        }
        let expected_output = ExpectedWalletOutput::new(candidate);
        let Some(expected_context_fingerprint) = pending_output_poi_context_fingerprint(&record)
        else {
            continue;
        };
        debug!(
            cache_key = %cfg.cache_key,
            commitment = %hex::encode(record.output_commitment),
            list_keys = ?plan.list_keys(),
            "force-resubmitting matching pending output POI context"
        );
        let attempt = match preflight_and_remote_submit_pending_output_poi(
            authority,
            db,
            cfg,
            active_list_keys,
            &record,
            &observation,
            &plan,
            private_poi,
        )
        .await
        {
            Ok(attempt) => attempt,
            Err(err) => {
                warn!(
                    ?err,
                    cache_key = %cfg.cache_key,
                    commitment = %hex::encode(output_commitment),
                    "forced pending output POI preflight/submit failed"
                );
                continue;
            }
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
            PendingOutputPoiRemoteAttempt::NotCurrent => continue,
            PendingOutputPoiRemoteAttempt::AuthorityStale => break,
            PendingOutputPoiRemoteAttempt::MissingPreTransactionPois => {
                if let Err(err) = apply_poi_private_delta(
                    authority,
                    db,
                    cache_store,
                    cfg,
                    OwnedPoiPrivateDelta::PendingContextTerminal {
                        expected_output,
                        expected_context_fingerprint,
                        active_list_keys: plan.list_keys().to_vec(),
                        error: "missing pre-transaction POI for pending output".to_string(),
                    },
                )
                .await
                {
                    warn!(
                        ?err,
                        cache_key = %cfg.cache_key,
                        commitment = %hex::encode(output_commitment),
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
                        db,
                        cfg,
                        active_list_keys,
                        &record,
                        &plan,
                    )
                    .await,
                    Ok(PendingOutputPoiPreflight::Ready)
                ) {
                    continue;
                }
                if let Err(err) = apply_poi_private_delta(
                    authority,
                    db,
                    cache_store,
                    cfg,
                    OwnedPoiPrivateDelta::PendingSubmission {
                        expected_output,
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
                {
                    warn!(
                        ?err,
                        cache_key = %cfg.cache_key,
                        commitment = %hex::encode(output_commitment),
                        "failed to persist resubmitted pending output POI state"
                    );
                }
            }
            PendingOutputPoiRemoteAttempt::Failed { error: err, .. } => {
                if !matches!(
                    pending_output_poi_submission_plan_current(
                        authority,
                        db,
                        cfg,
                        active_list_keys,
                        &record,
                        &plan,
                    )
                    .await,
                    Ok(PendingOutputPoiPreflight::Ready)
                ) {
                    continue;
                }
                if let Err(cache_err) = apply_poi_private_delta(
                    authority,
                    db,
                    cache_store,
                    cfg,
                    OwnedPoiPrivateDelta::PendingSubmission {
                        expected_output,
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
                {
                    warn!(
                        ?cache_err,
                        cache_key = %cfg.cache_key,
                        commitment = %hex::encode(output_commitment),
                        "failed to persist failed pending output POI resubmission state"
                    );
                }
                warn!(
                    ?err,
                    cache_key = %cfg.cache_key,
                    commitment = %hex::encode(output_commitment),
                    "forced pending output POI resubmission failed"
                );
            }
        }
    }

    attempted_contexts
}

#[cfg(test)]
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
            Err(err) => {
                warn!(?err, cache_key = %cfg.cache_key, commitment = %hex::encode(output_commitment), "failed to load matching pending output POI context");
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
            if let Err(err) = db.put_pending_output_poi_context(&record) {
                warn!(?err, cache_key = %cfg.cache_key, commitment = %hex::encode(output_commitment), "failed to mark pending output POI context terminal");
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
                    Err(err) => {
                        warn!(?err, cache_key = %cfg.cache_key, commitment = %hex::encode(output_commitment), "failed to revalidate resubmitted pending output POI context");
                        continue;
                    }
                }
                for list_key in &submitted_list_keys {
                    if !record.submitted_poi_list_keys.contains(list_key) {
                        record.submitted_poi_list_keys.push(*list_key);
                    }
                }
                let pending_recovery = match pending_output_poi_recovery_update(
                    db,
                    cfg.chain.chain_id,
                    &record,
                    &observation,
                    now,
                    OutputPoiRecoveryAction::Submitted {
                        retry_after: PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER,
                    },
                ) {
                    Ok(record) => record,
                    Err(err) => {
                        warn!(?err, cache_key = %cfg.cache_key, commitment = %hex::encode(output_commitment), "failed to prepare resubmitted pending output POI recovery state");
                        continue;
                    }
                };
                let mut recovery_updates = vec![pending_recovery];
                if record.wallet_id != cfg.cache_key {
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
                if let Err(err) = db.put_pending_output_poi_context(&record) {
                    warn!(?err, cache_key = %cfg.cache_key, commitment = %hex::encode(output_commitment), "failed to persist resubmitted pending output POI context");
                    continue;
                }
                for recovery in &recovery_updates {
                    if let Err(err) = db.put_output_poi_recovery(recovery) {
                        warn!(?err, cache_key = %cfg.cache_key, commitment = %hex::encode(output_commitment), "failed to persist resubmitted pending output POI recovery state");
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
                    Err(db_err) => {
                        warn!(?db_err, cache_key = %cfg.cache_key, commitment = %hex::encode(output_commitment), "failed to revalidate failed pending output POI resubmission");
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
                if let Err(cache_err) = db.put_output_poi_recovery(&recovery) {
                    warn!(?cache_err, cache_key = %cfg.cache_key, commitment = %hex::encode(output_commitment), "failed to persist failed pending output POI resubmission state");
                }
                warn!(?err, cache_key = %cfg.cache_key, commitment = %hex::encode(output_commitment), "forced pending output POI resubmission failed");
            }
        }
    }

    attempted_contexts
}

pub(super) struct CalldataRecoveryBuildRequest<'a> {
    pub(super) request: &'a OutputPoiRecoveryRequest<'a>,
    pub(super) candidate: &'a WalletUtxo,
    pub(super) source_tx_hash: FixedBytes<32>,
    pub(super) output_commitment: FixedBytes<32>,
    pub(super) fetched_inputs: &'a mut HashMap<FixedBytes<32>, Result<Bytes, RecoveryFailure>>,
    pub(super) wallet_nullifiers: &'a WalletNullifierIndex<'a>,
    pub(super) required_poi_list_keys: &'a [FixedBytes<32>],
    pub(super) spending_public_key: [U256; 2],
    pub(super) now: u64,
    pub(super) candidate_started: Instant,
}

pub(super) fn output_poi_recovery_proof_retry_after(err: &PreTransactionPoiError) -> Duration {
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

pub(super) async fn build_output_poi_recovery_chunk_from_calldata(
    input: CalldataRecoveryBuildRequest<'_>,
) -> Result<RecoveryChunk, RecoveryFailure> {
    let CalldataRecoveryBuildRequest {
        request,
        candidate,
        source_tx_hash,
        output_commitment,
        fetched_inputs,
        wallet_nullifiers,
        required_poi_list_keys,
        spending_public_key,
        now,
        candidate_started,
    } = input;
    let current_recovery = request
        .db
        .get_output_poi_recovery(
            request.cfg.chain.chain_id,
            &request.cfg.cache_key,
            &output_commitment,
        )
        .map_err(|err| {
            RecoveryFailure::retryable(
                OutputPoiRecoveryStatus::TxFetchFailed,
                format!("load cached recovery transaction input failed: {err}"),
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
    let tx_input_started = Instant::now();
    let (tx_input, tx_input_source) = if let Some(cached) = fetched_inputs.get(&source_tx_hash) {
        (cached.clone(), "memory_cache")
    } else if let Some(tx_input) = current_recovery
        .as_ref()
        .and_then(|record| record.tx_input.clone())
    {
        (Ok(Bytes::from(tx_input)), "db_cache")
    } else {
        let remote_effects = request.private_poi.remote_effects();
        let fetched = match remote_effects
            .run(
                || async {
                    Ok::<bool, std::convert::Infallible>(
                        request
                            .candidate_still_current(candidate, required_poi_list_keys)
                            .await,
                    )
                },
                || {
                    fetch_transaction_input(
                        request.rpcs,
                        request.http_client,
                        request.cfg.chain.chain_id,
                        source_tx_hash,
                    )
                },
            )
            .await
        {
            Ok(tx_input) => Ok(tx_input),
            Err(WalletPrivateRemoteError::Remote(failure)) => Err(failure),
            Err(WalletPrivateRemoteError::Stale(reason)) => {
                return Err(RecoveryFailure::retryable(
                    OutputPoiRecoveryStatus::TxFetchFailed,
                    format!("wallet-associated transaction fetch rejected: {reason:?}"),
                    OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
                ));
            }
            Err(WalletPrivateRemoteError::Check(error)) => match error {},
        };
        fetched_inputs.insert(source_tx_hash, fetched.clone());
        if let Ok(tx_input) = &fetched
            && request
                .candidate_still_current(candidate, required_poi_list_keys)
                .await
            && let Some(expected_recovery) = expected_recovery_state(current_recovery.as_ref())
            && let Err(err) = apply_poi_private_delta(
                request.authority,
                request.db,
                request.cache_store,
                request.cfg,
                OwnedPoiPrivateDelta::OutputRecovery {
                    expected_output: ExpectedWalletOutput::new(candidate),
                    active_list_keys: required_poi_list_keys.to_vec(),
                    required_poi_status: ExpectedPoiStatus::Recoverable,
                    pending_update: None,
                    expected_recovery,
                    action: OutputPoiRecoveryAction::CacheTxInput {
                        tx_input: tx_input.to_vec(),
                    },
                    now,
                },
            )
            .await
        {
            warn!(
                ?err,
                cache_key = %request.cfg.cache_key,
                commitment = %hex::encode(candidate.utxo.poi.commitment),
                "failed to persist output POI recovery transaction input"
            );
        }
        (fetched, "rpc")
    };
    let tx_input_elapsed_ms = tx_input_started.elapsed().as_millis();
    debug!(
        cache_key = %request.cfg.cache_key,
        commitment = %hex::encode(output_commitment),
        source_tx_hash = %hex::encode(source_tx_hash),
        tx_input_source,
        tx_input_elapsed_ms,
        candidate_elapsed_ms = candidate_started.elapsed().as_millis(),
        "output POI recovery transaction input resolved"
    );

    let tx_input = tx_input?;
    let decode_started = Instant::now();
    let decoded = decode_railgun_transactions(&tx_input)?;
    let decode_elapsed_ms = decode_started.elapsed().as_millis();
    debug!(
        cache_key = %request.cfg.cache_key,
        commitment = %hex::encode(output_commitment),
        source_tx_hash = %hex::encode(source_tx_hash),
        transactions = decoded.len(),
        decode_elapsed_ms,
        candidate_elapsed_ms = candidate_started.elapsed().as_millis(),
        "output POI recovery transaction input decoded"
    );

    if !request
        .candidate_still_current(candidate, required_poi_list_keys)
        .await
    {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::TxFetchFailed,
            "output POI recovery candidate changed while resolving transaction input",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    }
    if let Some(local_proof_source) = request
        .local_proof_source_if_ready(required_poi_list_keys)
        .await
    {
        let preflight_started = Instant::now();
        match preflight_local_output_poi_input_proofs(
            Some(&local_proof_source),
            request.cfg,
            candidate,
            request.wallet_utxos,
            wallet_nullifiers,
            &decoded,
            required_poi_list_keys,
        )
        .await
        {
            Ok(()) => {
                debug!(
                    cache_key = %request.cfg.cache_key,
                    commitment = %hex::encode(output_commitment),
                    source_tx_hash = %hex::encode(source_tx_hash),
                    preflight_elapsed_ms = preflight_started.elapsed().as_millis(),
                    candidate_elapsed_ms = candidate_started.elapsed().as_millis(),
                    "output POI recovery local proof preflight complete"
                );
            }
            Err(failure) => {
                warn!(
                    cache_key = %request.cfg.cache_key,
                    commitment = %hex::encode(output_commitment),
                    source_tx_hash = %hex::encode(source_tx_hash),
                    preflight_elapsed_ms = preflight_started.elapsed().as_millis(),
                    candidate_elapsed_ms = candidate_started.elapsed().as_millis(),
                    error = %failure.message,
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
            "output POI recovery candidate changed while resolving transaction input",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    }

    build_output_poi_recovery_chunk(
        candidate,
        wallet_nullifiers,
        &decoded,
        request.forest,
        required_poi_list_keys,
        spending_public_key,
        &request.cfg.scan_keys,
    )
}

pub(super) async fn fetch_transaction_input(
    rpcs: &QueryRpcPool,
    http_client: Option<&reqwest::Client>,
    chain_id: u64,
    tx_hash: FixedBytes<32>,
) -> Result<Bytes, RecoveryFailure> {
    let Some(provider) = rpcs.random_provider() else {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::TxFetchFailed,
            "no healthy RPC available",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    };
    let client = http_client.cloned().unwrap_or_else(reqwest::Client::new);
    let tx_hash_hex = hex::encode_prefixed(tx_hash);
    let response = client
        .post(provider.url.clone())
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_getTransactionByHash",
            "params": [tx_hash_hex],
        }))
        .send()
        .await
        .map_err(|err| {
            rpcs.mark_bad_provider(&provider);
            RecoveryFailure::retryable(
                OutputPoiRecoveryStatus::TxFetchFailed,
                format!("fetch transaction RPC failed: {err}"),
                OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
            )
        })?;
    let status = response.status();
    if !status.is_success() {
        rpcs.mark_bad_provider(&provider);
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::TxFetchFailed,
            format!("fetch transaction RPC returned HTTP {status}"),
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    }
    let response: JsonRpcResponse<JsonRpcTransaction> = response.json().await.map_err(|err| {
        rpcs.mark_bad_provider(&provider);
        RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::TxFetchFailed,
            format!("decode transaction RPC response failed: {err}"),
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        )
    })?;
    if let Some(error) = response.error {
        rpcs.mark_bad_provider(&provider);
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::TxFetchFailed,
            format!(
                "fetch transaction RPC error on chain {chain_id}: {}",
                error.message
            ),
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    }
    let Some(tx) = response.result else {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::TxFetchFailed,
            "transaction not found",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    };
    let input = tx.input.or(tx.data).ok_or_else(|| {
        RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::DecodeFailed,
            "transaction has no input",
        )
    })?;
    let input = input.strip_prefix("0x").unwrap_or(&input);
    let bytes = hex::decode(input).map_err(|err| {
        RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::DecodeFailed,
            format!("transaction input is not hex: {err}"),
        )
    })?;
    Ok(Bytes::from(bytes))
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
        let unshield_note = unshield_note_from_transaction(transaction)?;

        let output_start_global = output_start_global_position(&candidate.utxo, output_index)?;
        let output_start_tree = (output_start_global / u128::from(TREE_LEAF_COUNT)) as u32;
        let output_start_position = (output_start_global % u128::from(TREE_LEAF_COUNT)) as u64;
        let input_tree = u32::from(transaction.boundParams.treeNumber);
        let max_leaf_count = if input_tree == output_start_tree {
            output_start_position
        } else if input_tree < output_start_tree {
            TREE_LEAF_COUNT
        } else {
            return Err(RecoveryFailure::retryable(
                OutputPoiRecoveryStatus::MissingMerkleProof,
                "transaction input tree is after output tree",
                OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
            ));
        };

        let mut output_notes = output_notes_for_transaction(
            candidate,
            wallet_nullifiers.wallet_utxos,
            transaction,
            scan_keys,
        )?;
        let inputs = wallet_inputs_for_transaction(candidate, wallet_nullifiers, transaction)?;
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

        if let Some(unshield_note) = unshield_note {
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
        return Ok(RecoveryChunk {
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
            output: candidate.utxo.clone(),
            output_start_global,
            target_txid_index: None,
        });
    }

    Err(RecoveryFailure::permanent(
        OutputPoiRecoveryStatus::NotSelfOriginated,
        "source transaction does not contain the wallet output commitment",
    ))
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
    if max_leaf_count < min_leaf_count {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::MissingMerkleProof,
            "transaction root predates the first wallet input leaf",
            OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
        ));
    }
    let lower_bound = max_leaf_count
        .saturating_sub(OUTPUT_POI_RECOVERY_ROOT_SEARCH_LEAVES)
        .max(min_leaf_count);
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
    for leaf_count in (lower_bound..=max_leaf_count).rev() {
        let proof = tree.prove(first_input.utxo.position);
        if proof.leaf == first_input.utxo.note.commitment() && proof.root == merkle_root {
            return Ok(RecoveryInputMerkleTree { tree });
        }
        if leaf_count > lower_bound {
            tree.remove_leaf(leaf_count - 1);
        }
    }
    Err(RecoveryFailure::retryable(
        OutputPoiRecoveryStatus::MissingMerkleProof,
        "reconstructed Merkle proof does not match transaction root within recovery search window",
        OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
    ))
}

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
    decrypt_outgoing_note_ciphertext(ciphertext, expected_commitment, scan_keys)
}

fn decrypt_outgoing_note_ciphertext(
    ciphertext: &CommitmentCiphertext,
    expected_commitment: U256,
    scan_keys: &railgun_wallet::scan::WalletScanKeys,
) -> Option<Note> {
    if ciphertext.blindedReceiverViewingKey == FixedBytes::ZERO {
        return None;
    }
    let shared_key = shared_symmetric_key(
        &scan_keys.viewing_private_key,
        &ciphertext.blindedReceiverViewingKey.0,
    )
    .ok()?;
    let (iv, tag) = split_iv_tag(ciphertext.ciphertext[0].0);
    let mut plaintext = Vec::with_capacity(96 + ciphertext.memo.len());
    plaintext.extend_from_slice(&ciphertext.ciphertext[1].0);
    plaintext.extend_from_slice(&ciphertext.ciphertext[2].0);
    plaintext.extend_from_slice(&ciphertext.ciphertext[3].0);
    plaintext.extend_from_slice(ciphertext.memo.as_ref());
    decrypt_in_place_16b_iv(&shared_key, &iv, &tag, &mut plaintext).ok()?;
    if plaintext.len() < 96 {
        return None;
    }

    let encoded_mpk = U256::from_be_slice(&plaintext[0..32]);
    let token_hash = U256::from_be_slice(&plaintext[32..64]);
    let mut random = [0u8; 16];
    random.copy_from_slice(&plaintext[64..80]);
    let value = U256::from_be_slice(&plaintext[80..96]);
    let receiver_mpk_candidates = [encoded_mpk ^ scan_keys.master_public_key, encoded_mpk];
    for receiver_mpk in receiver_mpk_candidates {
        let note = Note {
            token_hash,
            value,
            random,
            npk: Note::npk_for(receiver_mpk, random),
        };
        if note.commitment() == expected_commitment {
            return Some(note);
        }
    }
    None
}

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

pub(super) fn wallet_inputs_for_transaction<'a>(
    candidate: &WalletUtxo,
    wallet_nullifiers: &'a WalletNullifierIndex<'a>,
    transaction: &Transaction,
) -> Result<Vec<&'a WalletUtxo>, RecoveryFailure> {
    let input_tree = u32::from(transaction.boundParams.treeNumber);
    let mut inputs = Vec::with_capacity(transaction.nullifiers.len());
    for nullifier in &transaction.nullifiers {
        let nullifier = U256::from_be_bytes(nullifier.0);
        let Some(input) =
            wallet_nullifiers.input_for(input_tree, nullifier, candidate.utxo.source.tx_hash)
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

pub(super) fn pending_output_poi_context_from_recovery(
    cfg: &WalletConfig,
    candidate: &WalletUtxo,
    recovery_chunk: &RecoveryChunk,
    txid_merkleroot_index: u64,
    pre_transaction_pois: PreTransactionPoiMap,
    active_list_keys: &[FixedBytes<32>],
    now: u64,
) -> PendingOutputPoiContextRecord {
    PendingOutputPoiContextRecord {
        chain_id: cfg.chain.chain_id,
        wallet_id: cfg.cache_key.clone(),
        txid_version: DEFAULT_TXID_VERSION.to_string(),
        output_commitment: recovery_chunk.output.poi.commitment,
        output_npk: recovery_chunk.output.poi.npk,
        utxo_tree_in: u64::from(recovery_chunk.chunk.tree_number),
        railgun_txid: recovery_chunk.chunk.railgun_txid(),
        txid_merkleroot_index: Some(txid_merkleroot_index),
        pre_transaction_pois_per_txid_leaf_per_list: pre_transaction_pois,
        required_poi_list_keys: active_list_keys.to_vec(),
        output_role: PendingOutputPoiRole::Change,
        created_at: now,
        source_operation_id: Some(format!(
            "recovered-output-poi:{}",
            hex::encode(candidate.utxo.source.tx_hash)
        )),
        observation: Some(PendingOutputPoiObservation {
            output_tree: u64::from(candidate.utxo.tree),
            output_position: candidate.utxo.position,
            tx_hash: candidate.utxo.source.tx_hash,
            block_number: candidate.utxo.source.block_number,
            block_timestamp: candidate.utxo.source.block_timestamp,
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
    candidate: &WalletUtxo,
    existing_pending_context: &PendingOutputPoiContextRecord,
) {
    let stored_derived_blinded_commitment = existing_pending_context
        .observation
        .as_ref()
        .and_then(|observation| {
            pending_output_poi_submit_identity(existing_pending_context, observation)
                .map(|identity| identity.derived_blinded_commitment)
        })
        .map_or_else(|| "none".to_string(), hex::encode);
    let stored_source_tx_hash = existing_pending_context.observation.as_ref().map_or_else(
        || "none".to_string(),
        |observation| hex::encode(observation.tx_hash),
    );
    debug!(
        cache_key = %cfg.cache_key,
        commitment = %hex::encode(candidate.utxo.poi.commitment),
        wallet_blinded_commitment = %hex::encode(candidate.utxo.poi.blinded_commitment),
        stored_derived_blinded_commitment = %stored_derived_blinded_commitment,
        stored_source_tx_hash = %stored_source_tx_hash,
        source_tx_hash = %hex::encode(candidate.utxo.source.tx_hash),
        "force-regenerating recovered output POI context"
    );
}

pub(super) fn new_output_poi_recovery_record(
    cfg: &WalletConfig,
    candidate: &WalletUtxo,
    status: OutputPoiRecoveryStatus,
    now: u64,
) -> OutputPoiRecoveryRecord {
    OutputPoiRecoveryRecord {
        chain_id: cfg.chain.chain_id,
        wallet_id: cfg.cache_key.clone(),
        output_commitment: candidate.utxo.poi.commitment,
        source_tx_hash: candidate.utxo.source.tx_hash,
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

#[cfg(test)]
fn output_poi_recovery_record_update(
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
        OutputPoiRecoveryAction::CacheTxInput { .. } | OutputPoiRecoveryAction::ExtendContext => {
            OutputPoiRecoveryStatus::Recoverable
        }
        OutputPoiRecoveryAction::Submitted { .. } => OutputPoiRecoveryStatus::Submitted,
        OutputPoiRecoveryAction::SubmitFailed { .. } => OutputPoiRecoveryStatus::SubmitFailed,
        OutputPoiRecoveryAction::Valid => OutputPoiRecoveryStatus::Valid,
    };
    let mut record = existing
        .unwrap_or_else(|| new_output_poi_recovery_record(cfg, candidate, default_status, now));
    record.apply_action(action, now);
    record
}

pub(super) async fn record_output_poi_recovery_failure(
    authority: &WalletPrivateMutationAuthority<'_>,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    candidate: &WalletUtxo,
    active_list_keys: &[FixedBytes<32>],
    failure: RecoveryFailure,
    now: u64,
) {
    let status = failure.status;
    let message = failure.message;
    let current_recovery = match db.get_output_poi_recovery(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &candidate.utxo.poi.commitment,
    ) {
        Ok(record) => record,
        Err(err) => {
            warn!(?err, cache_key = %cfg.cache_key, commitment = %hex::encode(candidate.utxo.poi.commitment), "failed to load output POI recovery failure predecessor");
            return;
        }
    };
    let Some(expected_recovery) = expected_recovery_state(current_recovery.as_ref()) else {
        return;
    };
    if let Err(err) = apply_poi_private_delta(
        authority,
        db,
        cache_store,
        cfg,
        OwnedPoiPrivateDelta::OutputRecovery {
            expected_output: ExpectedWalletOutput::new(candidate),
            active_list_keys: active_list_keys.to_vec(),
            required_poi_status: ExpectedPoiStatus::Recoverable,
            pending_update: None,
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
    {
        warn!(
            ?err,
            cache_key = %cfg.cache_key,
            commitment = %hex::encode(candidate.utxo.poi.commitment),
            "failed to persist output POI recovery failure state"
        );
    }
    debug!(
        cache_key = %cfg.cache_key,
        status = ?status,
        commitment = %hex::encode(candidate.utxo.poi.commitment),
        source_tx_hash = %hex::encode(candidate.utxo.source.tx_hash),
        error = %message,
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
        let Ok(Some(record)) = db.get_output_poi_recovery(
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
        if let Err(err) = apply_poi_private_delta(
            authority,
            db,
            cache_store,
            cfg,
            OwnedPoiPrivateDelta::OutputRecovery {
                expected_output: ExpectedWalletOutput::new(wallet_utxo),
                active_list_keys: active_list_keys.to_vec(),
                required_poi_status: ExpectedPoiStatus::Valid,
                pending_update: None,
                expected_recovery,
                action: OutputPoiRecoveryAction::Valid,
                now,
            },
        )
        .await
        {
            warn!(?err, cache_key = %cfg.cache_key, "failed to mark output POI recovery valid");
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
    if let Err(reason) = authority.revalidate() {
        debug!(?reason, cache_key = %cfg.cache_key, "mark output POI recoveries valid skipped");
        return;
    }
    let snapshot = utxos.read().await.clone();
    mark_valid_output_poi_recoveries(authority, db, cache_store, cfg, &snapshot, active_list_keys)
        .await;
}
