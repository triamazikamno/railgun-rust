//! Rebuilds a wallet output's recovery transaction chunk from validated public TXID rows.

use alloy::sol_types::{SolCall, SolValue};
use broadcaster_core::contracts::railgun::{
    CommitmentPreimage, Transaction, executeCall, relayCall, transactCall,
};

use crate::txid_cache::TxidPublicCacheTransaction;
use crate::wallet::{DenseMerkleTree, RailgunSpendSigner, SenderTransactionCandidate};

use super::{
    Arc, ChainScope, ChainType, DEFAULT_TXID_VERSION, EVM_CHAIN_TYPE, FixedBytes, InputWitness,
    Instant, LocalPoiMerkleProofSource, MerkleForest, Note,
    OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER, OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
    OutputPoiRecoveryRequest, OutputPoiRecoveryStatus, PrivateInputs,
    PublicCacheTxidRefreshRequest, PublicInputs, PublicTxidCacheKey, PublicTxidTransaction,
    RecoveryChunk, RecoveryFailure, TREE_LEAF_COUNT, TransactionPlanChunk, U256, Utxo,
    UtxoCommitmentKind, WalletConfig, WalletNullifierIndex, WalletUtxo, debug,
    output_poi_recovery_proof_retry_after, output_poi_recovery_source_matches_candidate,
    poi_shield_blocked_on_any_list, public_txid_rows_for_outer_hash, warn,
};

#[derive(Clone, Copy)]
pub(in crate::wallet) struct RecoverySpendPublicKey {
    pub(in crate::wallet) spending_public_key: [U256; 2],
}

impl RailgunSpendSigner for RecoverySpendPublicKey {
    fn spending_public_key(&self) -> [U256; 2] {
        self.spending_public_key
    }

    fn sign_spend_message(&self, _: U256) -> [U256; 3] {
        [U256::ZERO; 3]
    }
}

pub(in crate::wallet) struct PublicTxidRecoveryBuildRequest<'a> {
    pub(in crate::wallet) request: &'a OutputPoiRecoveryRequest<'a>,
    pub(in crate::wallet) candidate: &'a WalletUtxo,
    pub(in crate::wallet) source_tx_hash: FixedBytes<32>,
    pub(in crate::wallet) output_commitment: FixedBytes<32>,
    pub(in crate::wallet) wallet_nullifiers: &'a WalletNullifierIndex<'a>,
    pub(in crate::wallet) required_poi_list_keys: &'a [FixedBytes<32>],
    pub(in crate::wallet) spending_public_key: [U256; 2],
    pub(in crate::wallet) candidate_started: Instant,
}

pub(in crate::wallet) async fn build_output_poi_recovery_chunk_from_public_cache(
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
    let public_epoch = request.public_data_plane.current_epoch();
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
    .await;
    let recovery_chunk = match recovery_chunk {
        Err(failure)
            if failure.category == "sender_output_notes_unavailable"
                && wallet_nullifiers
                    .wallet_utxos
                    .iter()
                    .any(|input| input.spent.as_ref() == Some(&candidate.utxo.source)) =>
        {
            let replay_failure = |category, message| {
                RecoveryFailure::retryable_category(
                    OutputPoiRecoveryStatus::TxFetchFailed,
                    category,
                    message,
                    OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
                )
            };
            let source_rows = match request
                .public_data_plane
                .output_poi_source_block_rows(candidate.utxo.source.block_number)
                .await
            {
                Ok(crate::chain::PublicScanRowsAnswer::Rows(rows)) => rows,
                Ok(_) => {
                    return Err(replay_failure(
                        "sender_source_rows_unavailable",
                        "sender output source block is not available in public artifacts",
                    ));
                }
                Err(_) => {
                    return Err(replay_failure(
                        "sender_source_rows_fetch_failed",
                        "sender output source block could not be loaded from public artifacts",
                    ));
                }
            };
            if request.authority.revalidate().is_err()
                || source_rows.range.from_block > candidate.utxo.source.block_number
                || source_rows.range.to_block < candidate.utxo.source.block_number
                || source_rows.epoch != public_epoch
                || request.public_data_plane.current_epoch() != public_epoch
            {
                return Err(replay_failure(
                    "sender_source_rows_stale",
                    "sender output source block changed while reconstructing recovery notes",
                ));
            }
            let delta =
                crate::wallet::WalletLogDelta::from_rows(&source_rows.rows, &request.cfg.scan_keys);
            let nullifiers = delta
                .nullifiers
                .into_iter()
                .map(|spent| ((spent.tree, spent.nullifier), spent.source))
                .collect();
            let candidates = crate::wallet::delta::sender_scan_candidate_inputs(
                wallet_nullifiers.wallet_utxos,
                request.cfg.scan_keys.nullifying_key,
                &nullifiers,
                delta.sender_scan_outputs,
                &request.cfg.scan_keys,
            );
            let mut candidates = candidates
                .into_iter()
                .filter(|sender| sender.source == candidate.utxo.source);
            let Some(sender) = candidates.next() else {
                return Err(failure);
            };
            if candidates.next().is_some() {
                return Err(failure);
            }
            let sender = sender
                .into_record(request.cfg.chain.chain_id, request.cfg.cache_key.clone())
                .map_err(|_| failure)?;
            let mut chunk = build_output_poi_recovery_chunk_from_public_rows(
                candidate,
                wallet_nullifiers,
                &rows,
                Some(&sender),
                &cached_transactions,
                &request.forest,
                required_poi_list_keys,
                spending_public_key,
                &request.cfg.scan_keys,
            )
            .await?;
            chunk.replay_fence = Some(
                crate::wallet::saved_poi_compatibility::SenderCandidateReplayFence {
                    public_data_plane: request.public_data_plane.clone(),
                    epoch: public_epoch,
                },
            );
            chunk
        }
        result => result?,
    };
    if recovery_chunk
        .replay_fence
        .as_ref()
        .is_some_and(|fence| fence.public_data_plane.current_epoch() != fence.epoch)
    {
        return Err(RecoveryFailure::retryable_category(
            OutputPoiRecoveryStatus::TxFetchFailed,
            "sender_source_rows_stale",
            "sender output source block changed while building recovery chunk",
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        ));
    }
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
    if let Some((local_proof_source, ..)) = request
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

pub(in crate::wallet) fn decode_railgun_transactions(
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

pub(in crate::wallet) async fn preflight_local_recovery_chunk_input_proofs(
    proof_source: Option<&LocalPoiMerkleProofSource>,
    cfg: &WalletConfig,
    recovery_chunk: &RecoveryChunk,
    active_list_keys: &[FixedBytes<32>],
) -> Result<(), RecoveryFailure> {
    let Some(proof_source) = proof_source else {
        return Ok(());
    };
    if recovery_chunk.chunk.inputs.iter().any(|wallet_input| {
        poi_shield_blocked_on_any_list(&wallet_input.utxo.poi, active_list_keys)
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

pub(in crate::wallet) async fn build_output_poi_recovery_chunk_from_public_rows(
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
        return Err(RecoveryFailure::permanent_category(
            if matches.is_empty() {
                OutputPoiRecoveryStatus::NotSelfOriginated
            } else {
                OutputPoiRecoveryStatus::UnsupportedShape
            },
            "public_row_not_unique_or_missing",
            "validated public TXID rows do not uniquely contain the wallet output",
        ));
    };
    let observed_output_start = output_start_global_position(&candidate.utxo, *output_index)
        .map_err(|failure| failure.with_category("output_position_mismatch"))?;
    if observed_output_start != row.transaction.output_start_global() {
        return Err(RecoveryFailure::permanent_category(
            OutputPoiRecoveryStatus::UnsupportedShape,
            "output_position_mismatch",
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
    )
    .map_err(|failure| failure.with_category("unsupported_transaction_shape"))?;
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
                RecoveryFailure::permanent_category(
                    OutputPoiRecoveryStatus::UnsupportedShape,
                    "unsupported_transaction_shape",
                    "public TXID output range overflow",
                )
            })?;
        let tree = u32::try_from(global / u128::from(TREE_LEAF_COUNT)).map_err(|_| {
            RecoveryFailure::permanent_category(
                OutputPoiRecoveryStatus::UnsupportedShape,
                "unsupported_transaction_shape",
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
            return Err(RecoveryFailure::permanent_category(
                OutputPoiRecoveryStatus::MissingWalletOutputs,
                "sender_output_notes_unavailable",
                "selected public TXID row requires unavailable sender output notes",
            ));
        };
        notes.push(note);
    }
    if notes.is_empty() {
        return Err(RecoveryFailure::permanent_category(
            OutputPoiRecoveryStatus::UnsupportedShape,
            "unsupported_transaction_shape",
            "transaction has no private outputs",
        ));
    }
    Ok(notes)
}

fn cached_transaction_matches_public_row(
    transaction: &Transaction,
    public: &TxidPublicCacheTransaction,
) -> bool {
    transaction
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

pub(in crate::wallet) async fn build_recovery_chunk_for_public_transaction(
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
        return Err(RecoveryFailure::permanent_category(
            OutputPoiRecoveryStatus::UnsupportedShape,
            "unsupported_transaction_shape",
            "public TXID row does not match the recovery source or output range",
        ));
    }
    let private_output_count = private_output_count_for_commitments(
        transaction.commitments.len(),
        transaction.has_unshield,
    )
    .map_err(|failure| failure.with_category("unsupported_transaction_shape"))?;
    if output_notes.len() != private_output_count
        || output_notes.iter().map(Note::commitment).ne(transaction
            .commitments
            .iter()
            .take(private_output_count)
            .copied())
    {
        return Err(RecoveryFailure::permanent_category(
            OutputPoiRecoveryStatus::MissingWalletOutputs,
            "private_output_notes_mismatch",
            "private output notes do not match the public TXID commitments",
        ));
    }
    let output_start_tree = u32::try_from(output_start_global / u128::from(TREE_LEAF_COUNT))
        .map_err(|_| {
            RecoveryFailure::permanent_category(
                OutputPoiRecoveryStatus::UnsupportedShape,
                "unsupported_transaction_shape",
                "public TXID output tree is out of range",
            )
        })?;
    let output_start_position = (output_start_global % u128::from(TREE_LEAF_COUNT)) as u64;
    let input_tree = u32::from(u16::try_from(transaction.utxo_tree_in).map_err(|_| {
        RecoveryFailure::permanent_category(
            OutputPoiRecoveryStatus::UnsupportedShape,
            "unsupported_transaction_shape",
            "public TXID input tree is out of ABI range",
        )
    })?);
    let max_leaf_count = match input_tree.cmp(&output_start_tree) {
        std::cmp::Ordering::Equal => output_start_position,
        std::cmp::Ordering::Less => TREE_LEAF_COUNT,
        std::cmp::Ordering::Greater => {
            return Err(RecoveryFailure::retryable_category(
                OutputPoiRecoveryStatus::MissingMerkleProof,
                "input_merkle_proof_unavailable",
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
    if inputs
        .iter()
        .any(|wallet_utxo| poi_shield_blocked_on_any_list(&wallet_utxo.utxo.poi, active_list_keys))
    {
        return Err(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::InputPoiNotValid,
            "one or more transaction inputs are shield-blocked",
            OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
        ));
    }
    let first_input = inputs.first().ok_or_else(|| {
        RecoveryFailure::permanent_category(
            OutputPoiRecoveryStatus::MissingWalletInputs,
            "wallet_inputs_missing",
            "transaction has no wallet-owned inputs",
        )
    })?;
    let input_merkle = recovery_input_merkle_tree_blocking(
        Arc::clone(forest),
        input_tree,
        (*first_input).clone(),
        max_leaf_count,
    )
    .await?;
    let merkle_root = input_merkle.root();
    let mut input_witnesses = Vec::with_capacity(inputs.len());
    for input in inputs {
        let proof = input_merkle.prove(input.utxo.position);
        if proof.leaf != input.utxo.note.commitment() {
            return Err(RecoveryFailure::retryable_category(
                OutputPoiRecoveryStatus::MissingMerkleProof,
                "input_merkle_proof_unavailable",
                "reconstructed Merkle proof does not match wallet input commitment",
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
        merkle_root,
        transaction.bound_params_hash,
        transaction.nullifiers.clone(),
        &output_notes,
    );
    if public_inputs.commitments_out != transaction.commitments {
        return Err(RecoveryFailure::permanent_category(
            OutputPoiRecoveryStatus::UnsupportedShape,
            "unsupported_transaction_shape",
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
            merkle_root,
            inputs: input_witnesses,
            outputs: output_notes,
            has_unshield: transaction.has_unshield,
            public_inputs,
            private_inputs,
            signature: [U256::ZERO; 3],
        },
        output_start_global,
        target_txid_index,
        replay_fence: None,
    })
}

fn unshield_note_from_public_transaction(
    transaction: &TxidPublicCacheTransaction,
) -> Result<Option<Note>, RecoveryFailure> {
    if !transaction.has_unshield {
        return Ok(None);
    }
    let encoded = transaction.unshield_preimage.as_deref().ok_or_else(|| {
        RecoveryFailure::permanent_category(
            OutputPoiRecoveryStatus::UnsupportedShape,
            "unshield_preimage_unavailable_or_invalid",
            "selected public TXID source cannot provide the unshield preimage",
        )
    })?;
    let preimage = CommitmentPreimage::abi_decode(encoded).map_err(|err| {
        RecoveryFailure::permanent_category(
            OutputPoiRecoveryStatus::UnsupportedShape,
            "unshield_preimage_unavailable_or_invalid",
            format!("public TXID unshield preimage is invalid: {err}"),
        )
    })?;
    let note = preimage.note_with_random([0_u8; 16]);
    if preimage.abi_encode() != encoded
        || transaction.commitments.last() != Some(&note.commitment())
    {
        return Err(RecoveryFailure::permanent_category(
            OutputPoiRecoveryStatus::UnsupportedShape,
            "unshield_preimage_unavailable_or_invalid",
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
            return Err(RecoveryFailure::permanent_category(
                OutputPoiRecoveryStatus::NotSelfOriginated,
                "wallet_inputs_unresolved",
                "transaction nullifiers do not resolve to wallet-spent inputs",
            ));
        };
        inputs.push(input);
    }
    if inputs.is_empty() {
        return Err(RecoveryFailure::permanent_category(
            OutputPoiRecoveryStatus::MissingWalletInputs,
            "wallet_inputs_missing",
            "transaction has no wallet-owned inputs",
        ));
    }
    Ok(inputs)
}

pub(in crate::wallet) fn output_start_global_position(
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

pub(in crate::wallet) fn private_output_count_for_commitments(
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

pub(super) fn recovery_input_merkle_tree(
    forest: &MerkleForest,
    input_tree: u32,
    first_input: &WalletUtxo,
    max_leaf_count: u64,
) -> Result<DenseMerkleTree, RecoveryFailure> {
    let max_leaf_count = max_leaf_count.min(TREE_LEAF_COUNT);
    if max_leaf_count < first_input.utxo.position.saturating_add(1) {
        return Err(RecoveryFailure::retryable_category(
            OutputPoiRecoveryStatus::MissingMerkleProof,
            "input_merkle_proof_unavailable",
            "transaction outputs precede the first wallet input leaf",
            OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
        ));
    }
    if forest
        .leaf_at(input_tree, first_input.utxo.position)
        .is_none()
    {
        return Err(RecoveryFailure::retryable_category(
            OutputPoiRecoveryStatus::MissingMerkleProof,
            "input_merkle_proof_unavailable",
            "input tree missing from local Merkle forest",
            OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER,
        ));
    }
    Ok(DenseMerkleTree::from_forest_prefix(
        forest,
        input_tree,
        max_leaf_count,
    ))
}

async fn recovery_input_merkle_tree_blocking(
    forest: Arc<MerkleForest>,
    input_tree: u32,
    first_input: WalletUtxo,
    max_leaf_count: u64,
) -> Result<DenseMerkleTree, RecoveryFailure> {
    tokio::task::spawn_blocking(move || {
        recovery_input_merkle_tree(&forest, input_tree, &first_input, max_leaf_count)
    })
    .await
    .map_err(|error| {
        RecoveryFailure::retryable_category(
            OutputPoiRecoveryStatus::MissingMerkleProof,
            "input_merkle_proof_unavailable",
            format!("input Merkle tree build failed: {error}"),
            OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
        )
    })?
}

pub(super) fn decrypt_outgoing_transaction_output_note(
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
