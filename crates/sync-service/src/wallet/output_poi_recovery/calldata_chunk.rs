//! Calldata-based recovery chunk reconstruction, used only by tests.

use broadcaster_core::contracts::railgun::Transaction;

use super::chunk::{
    RecoverySpendPublicKey, decrypt_outgoing_transaction_output_note, output_start_global_position,
    private_output_count_for_commitments, recovery_input_merkle_tree,
};

use super::{
    DEFAULT_TXID_VERSION, EVM_CHAIN_TYPE, FixedBytes, InputWitness, LocalPoiMerkleProofSource,
    MerkleForest, Note, OUTPUT_POI_RECOVERY_SUBMITTED_RETRY_AFTER, OutputPoiRecoveryStatus,
    PrivateInputs, PublicInputs, RecoveryChunk, RecoveryFailure, TREE_LEAF_COUNT,
    TransactionPlanChunk, U256, UtxoCommitmentKind, WalletConfig, WalletNullifierIndex, WalletUtxo,
    hex, output_poi_recovery_proof_retry_after, poi_shield_blocked_on_any_list,
};

pub(in crate::wallet) async fn preflight_local_output_poi_input_proofs(
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

pub(in crate::wallet) fn output_poi_recovery_input_blinded_commitments(
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
            poi_shield_blocked_on_any_list(&wallet_utxo.utxo.poi, active_list_keys)
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

pub(in crate::wallet) fn build_output_poi_recovery_chunk(
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
        RecoveryFailure::permanent(
            OutputPoiRecoveryStatus::MissingWalletInputs,
            "transaction has no wallet-owned inputs",
        )
    })?;
    let input_merkle = recovery_input_merkle_tree(forest, input_tree, first_input, max_leaf_count)?;
    let merkle_root = input_merkle.root();
    let mut input_witnesses = Vec::with_capacity(inputs.len());
    for input in inputs {
        let proof = input_merkle.prove(input.utxo.position);
        if proof.leaf != input.utxo.note.commitment() {
            return Err(RecoveryFailure::retryable(
                OutputPoiRecoveryStatus::MissingMerkleProof,
                "reconstructed Merkle proof does not match wallet input commitment",
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
        replay_fence: None,
    })
}

pub(in crate::wallet) fn unshield_note_from_transaction(
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

pub(in crate::wallet) fn output_notes_for_transaction(
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

pub(in crate::wallet) fn wallet_inputs_for_transaction<'a>(
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

pub(in crate::wallet) fn wallet_inputs_for_source_transaction<'a>(
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
