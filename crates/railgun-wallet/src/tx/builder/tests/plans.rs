use super::*;

fn note_parts(note: &Note) -> (U256, U256) {
    (note.token_hash, note.value)
}

fn token_parts(token: Address, value: u64) -> (U256, U256) {
    (U256::from_be_slice(token.as_slice()), U256::from(value))
}

fn test_fee(token: Address, amount: u64) -> BroadcasterFeeOutput {
    BroadcasterFeeOutput {
        recipient: sample_address_data(0x7f).address_data(),
        token_address: token,
        amount: U256::from(amount),
    }
}

fn plain_unshield_request(token: Address, fee: Option<BroadcasterFeeOutput>) -> UnshieldRequest {
    UnshieldRequest {
        token_address: token,
        amount: uint!(10_U256),
        recipient: Address::from([0x73; 20]),
        verify_proof: false,
        spend_up_to: false,
        broadcaster_fee: fee,
        min_gas_price: 0,
    }
}

fn plain_send_request(token: Address, fee: Option<BroadcasterFeeOutput>) -> SendRequest {
    SendRequest {
        token_address: token,
        amount: uint!(10_U256),
        recipient: sample_address_data(0x76).address_data(),
        verify_proof: false,
        spend_up_to: false,
        broadcaster_fee: fee,
        min_gas_price: 0,
    }
}

/// Calldata transaction `i` must be chunk `i`, so the calldata keeps the plan's order.
fn assert_calldata_follows_chunks(call: &TransactionCall, chunks: &[TransactionPlanChunk]) {
    assert_eq!(call.to, test_transaction_builder().railgun_contract);
    let decoded = transactCall::abi_decode(&call.data).expect("decode transact call");
    let calldata = decoded
        ._transactions
        .iter()
        .map(|transaction| {
            (
                u32::from(transaction.boundParams.treeNumber),
                U256::from_be_slice(transaction.merkleRoot.as_slice()),
                transaction
                    .nullifiers
                    .iter()
                    .map(|nullifier| U256::from_be_slice(nullifier.as_slice()))
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    let expected = chunks
        .iter()
        .map(|chunk| {
            (
                chunk.tree_number,
                chunk.merkle_root,
                chunk.public_inputs.nullifiers.clone(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(calldata, expected);
}

/// The fields a plain plan copies from its first chunk.
fn first_chunk_fields(chunk: &TransactionPlanChunk) -> (u32, U256, String, String, [U256; 3]) {
    (
        chunk.tree_number,
        chunk.merkle_root,
        format!("{:?}", chunk.public_inputs),
        format!("{:?}", chunk.private_inputs),
        chunk.signature,
    )
}

async fn plain_unshield_plan(
    wallet: &WalletKeys,
    utxos: &[Utxo],
    request: UnshieldRequest,
) -> UnshieldPlan {
    let forest = forest_for_utxos(utxos);
    let plan = test_transaction_builder()
        .build_unshield_plan_inner(
            &wallet.viewing,
            wallet,
            &forest,
            utxos,
            request,
            &MockTransactionProver,
        )
        .await
        .expect("unshield plan");
    assert_calldata_follows_chunks(&plan.call, &plan.chunks);
    let plan_fields = (
        plan.tree_number,
        plan.merkle_root,
        format!("{:?}", plan.public_inputs),
        format!("{:?}", plan.private_inputs),
        plan.signature,
    );
    assert_eq!(plan_fields, first_chunk_fields(&plan.chunks[0]));
    plan
}

async fn plain_send_plan(wallet: &WalletKeys, utxos: &[Utxo], request: &SendRequest) -> SendPlan {
    let forest = forest_for_utxos(utxos);
    let plan = test_transaction_builder()
        .build_send_plan_inner(
            &wallet.viewing,
            wallet,
            &forest,
            utxos,
            request,
            &MockTransactionProver,
        )
        .await
        .expect("send plan");
    assert_calldata_follows_chunks(&plan.call, &plan.chunks);
    let plan_fields = (
        plan.tree_number,
        plan.merkle_root,
        format!("{:?}", plan.public_inputs),
        format!("{:?}", plan.private_inputs),
        plan.signature,
    );
    assert_eq!(plan_fields, first_chunk_fields(&plan.chunks[0]));
    plan
}

#[tokio::test]
async fn unshield_plan_with_separate_token_fee_puts_fee_transaction_first() {
    let wallet = test_wallet();
    let token = Address::from([0x71; 20]);
    let fee_token = Address::from([0x72; 20]);
    // The fee input sits in another tree and position, so tree numbers, roots and
    // nullifiers show which transaction came first.
    let utxos = vec![
        wallet_test_utxo(&wallet, token, 12, 0, 0),
        wallet_test_utxo(&wallet, fee_token, 5, 1, 1),
    ];

    let plan = plain_unshield_plan(
        &wallet,
        &utxos,
        plain_unshield_request(token, Some(test_fee(fee_token, 2))),
    )
    .await;

    assert_eq!(plan.chunks.len(), 2);
    assert!(!plan.chunks[0].has_unshield);
    assert!(plan.chunks[1].has_unshield);
    assert_eq!(plan.tree_number, 1);
    assert_eq!(
        plan.broadcaster_fee_note.as_ref().map(note_parts),
        Some(token_parts(fee_token, 2))
    );
    assert_eq!(plan.unshield_notes.len(), 1);
    assert_eq!(note_parts(&plan.unshield_note), token_parts(token, 10));
    // The action's change replaces the fee transaction's change of 3.
    assert_eq!(
        plan.change_note.as_ref().map(note_parts),
        Some(token_parts(token, 2))
    );
}

#[tokio::test]
async fn send_plan_with_separate_token_fee_keeps_fee_change_without_action_change() {
    let wallet = test_wallet();
    let token = Address::from([0x74; 20]);
    let fee_token = Address::from([0x75; 20]);
    let utxos = vec![
        wallet_test_utxo(&wallet, token, 10, 0, 0),
        wallet_test_utxo(&wallet, fee_token, 5, 1, 1),
    ];

    let plan = plain_send_plan(
        &wallet,
        &utxos,
        &plain_send_request(token, Some(test_fee(fee_token, 2))),
    )
    .await;

    assert_eq!(plan.chunks.len(), 2);
    assert_eq!(plan.tree_number, 1);
    assert_eq!(plan.chunks[0].outputs.len(), 2);
    assert_eq!(plan.chunks[1].outputs.len(), 1);
    assert_eq!(
        plan.broadcaster_fee_note.as_ref().map(note_parts),
        Some(token_parts(fee_token, 2))
    );
    assert_eq!(plan.recipient_notes.len(), 1);
    assert_eq!(note_parts(&plan.recipient_note), token_parts(token, 10));
    assert_eq!(
        plan.change_note.as_ref().map(note_parts),
        Some(token_parts(fee_token, 3))
    );
}

#[tokio::test]
async fn unshield_plan_with_same_token_fee_spans_trees() {
    let wallet = test_wallet();
    let token = Address::from([0x77; 20]);
    let utxos = vec![
        wallet_test_utxo(&wallet, token, 6, 0, 0),
        wallet_test_utxo(&wallet, token, 6, 1, 1),
    ];

    let plan = plain_unshield_plan(
        &wallet,
        &utxos,
        plain_unshield_request(token, Some(test_fee(token, 1))),
    )
    .await;

    assert_eq!(plan.chunks.len(), 2);
    assert!(plan.chunks.iter().all(|chunk| chunk.has_unshield));
    // The first chunk pays the fee (outputs: fee, unshield); the last returns the
    // change (outputs: change, unshield).
    assert_eq!(
        plan.broadcaster_fee_note.as_ref().map(note_parts),
        Some(token_parts(token, 1))
    );
    assert_eq!(
        plan.broadcaster_fee_note.as_ref().map(Note::commitment),
        Some(plan.chunks[0].outputs[0].commitment())
    );
    assert_eq!(
        plan.change_note.as_ref().map(note_parts),
        Some(token_parts(token, 1))
    );
    assert_eq!(
        plan.change_note.as_ref().map(Note::commitment),
        Some(plan.chunks[1].outputs[0].commitment())
    );
    assert_eq!(
        plan.unshield_notes
            .iter()
            .map(note_parts)
            .collect::<Vec<_>>(),
        vec![token_parts(token, 5), token_parts(token, 5)]
    );
    assert_eq!(note_parts(&plan.unshield_note), token_parts(token, 5));
}

#[tokio::test]
async fn send_plan_with_same_token_fee_spans_trees() {
    let wallet = test_wallet();
    let token = Address::from([0x79; 20]);
    let utxos = vec![
        wallet_test_utxo(&wallet, token, 6, 0, 0),
        wallet_test_utxo(&wallet, token, 6, 1, 1),
    ];

    let plan = plain_send_plan(
        &wallet,
        &utxos,
        &plain_send_request(token, Some(test_fee(token, 1))),
    )
    .await;

    assert_eq!(plan.chunks.len(), 2);
    // The first chunk pays the fee (outputs: fee, recipient); the last returns the
    // change (outputs: recipient, change).
    assert_eq!(
        plan.broadcaster_fee_note.as_ref().map(note_parts),
        Some(token_parts(token, 1))
    );
    assert_eq!(
        plan.broadcaster_fee_note.as_ref().map(Note::commitment),
        Some(plan.chunks[0].outputs[0].commitment())
    );
    assert_eq!(
        plan.change_note.as_ref().map(note_parts),
        Some(token_parts(token, 1))
    );
    assert_eq!(
        plan.change_note.as_ref().map(Note::commitment),
        Some(plan.chunks[1].outputs[1].commitment())
    );
    assert_eq!(
        plan.recipient_notes
            .iter()
            .map(note_parts)
            .collect::<Vec<_>>(),
        vec![token_parts(token, 5), token_parts(token, 5)]
    );
    assert_eq!(note_parts(&plan.recipient_note), token_parts(token, 5));
}
