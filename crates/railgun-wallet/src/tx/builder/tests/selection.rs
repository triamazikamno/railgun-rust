use super::*;

fn selected_positions(selection: &[Utxo]) -> Vec<u64> {
    selection.iter().map(|utxo| utxo.position).collect()
}

#[test]
fn single_token_unshield_selection_behavior_is_unchanged() {
    let token = Address::from([0x91; 20]);
    let utxos = vec![test_utxo(token, 10, 0, 0)];

    let info = unshield_selection_info(&utxos, token, uint!(7_U256), false)
        .expect("single-token unshield selection");

    assert_eq!(info.total, uint!(10_U256));
    assert_eq!(info.input_count, 1);
    assert_eq!(info.transaction_count, 1);
    assert_eq!(info.private_output_count, 1);
    assert_eq!(info.public_output_count, 1);
}

#[test]
fn unshield_selection_prefers_fewest_inputs() {
    let token = Address::from([1_u8; 20]);
    let utxos = vec![
        test_utxo(token, 40, 0, 1),
        test_utxo(token, 30, 0, 2),
        test_utxo(token, 5, 0, 3),
    ];

    let (selected, total) = select_utxos(&utxos, token, uint!(35_U256), false, 1).unwrap();

    assert_eq!(total, uint!(40_U256));
    assert_eq!(selected_positions(&selected), vec![1]);
}

#[test]
fn unshield_selection_prefers_exact_match_with_same_input_count() {
    let token = Address::from([2_u8; 20]);
    let utxos = vec![
        test_utxo(token, 12, 0, 1),
        test_utxo(token, 10, 0, 2),
        test_utxo(token, 6, 0, 3),
        test_utxo(token, 5, 0, 4),
    ];

    let (selected, total) = select_utxos(&utxos, token, uint!(16_U256), false, 1).unwrap();

    assert_eq!(total, uint!(16_U256));
    assert_eq!(selected_positions(&selected), vec![2, 3]);
}

#[test]
fn unshield_selection_minimizes_change_with_same_input_count() {
    let token = Address::from([3_u8; 20]);
    let utxos = vec![
        test_utxo(token, 10, 0, 1),
        test_utxo(token, 7, 0, 2),
        test_utxo(token, 6, 0, 3),
    ];

    let (selected, total) = select_utxos(&utxos, token, uint!(12_U256), false, 1).unwrap();

    assert_eq!(total, uint!(13_U256));
    assert_eq!(selected_positions(&selected), vec![2, 3]);
}

#[test]
fn partial_unshield_uses_at_most_twelve_inputs_when_change_is_needed() {
    let token = Address::from([4_u8; 20]);
    let utxos = (0..13)
        .map(|position| test_utxo(token, 2, 0, position))
        .collect::<Vec<_>>();

    let (selected, total) = select_utxos(&utxos, token, uint!(23_U256), false, 1).unwrap();

    assert_eq!(selected.len(), 12);
    assert_eq!(total, uint!(24_U256));
}

#[test]
fn exact_unshield_can_use_thirteen_inputs() {
    let token = Address::from([5_u8; 20]);
    let utxos = (0..13)
        .map(|position| test_utxo(token, 2, 0, position))
        .collect::<Vec<_>>();

    let (selected, total) = select_utxos(&utxos, token, uint!(26_U256), false, 1).unwrap();

    assert_eq!(selected.len(), 13);
    assert_eq!(total, uint!(26_U256));
}

#[test]
fn max_unshield_spendable_uses_eight_batched_chunks() {
    let token = Address::from([6_u8; 20]);
    let mut utxos = (0..20)
        .map(|position| test_utxo(token, 1, 0, position))
        .collect::<Vec<_>>();
    utxos.extend((0..5).map(|position| test_utxo(token, 3, 1, position)));

    assert_eq!(max_unshield_spendable(&utxos, token), uint!(35_U256));
}

#[test]
fn unshield_selection_error_reports_max_single_transaction_amount() {
    let token = Address::from([7_u8; 20]);
    let utxos = (0..13)
        .map(|position| test_utxo(token, 1, 0, position))
        .collect::<Vec<_>>();

    let error = select_utxos(&utxos, token, uint!(14_U256), false, 1).unwrap_err();

    assert!(matches!(error, BuildError::InsufficientBalance(max) if max == uint!(13_U256)));
}

#[test]
fn send_outputs_create_recipient_and_change_notes() {
    let token = Address::from([8_u8; 20]);
    let sender_viewing = sample_address_data(10);
    let sender = sender_viewing.address_data();
    let recipient = sample_address_data(20).address_data();

    let outputs = build_send_outputs(
        token,
        uint!(7_U256),
        uint!(3_U256),
        &sender,
        &recipient,
        None,
        &sender_viewing.viewing_private_key,
    )
    .expect("send outputs");

    assert_eq!(outputs.outputs.len(), 2);
    assert_eq!(outputs.recipient_note.value, uint!(7_U256));
    assert_eq!(
        outputs.recipient_note.npk,
        Note::npk_for(recipient.master_public_key, outputs.recipient_note.random)
    );
    let change_note = outputs.change_note.expect("change note");
    assert_eq!(change_note.value, uint!(3_U256));
    assert_eq!(
        change_note.npk,
        Note::npk_for(sender.master_public_key, change_note.random)
    );
}

#[test]
fn send_outputs_omit_change_for_exact_send() {
    let token = Address::from([9_u8; 20]);
    let sender_viewing = sample_address_data(11);
    let sender = sender_viewing.address_data();
    let recipient = sample_address_data(21).address_data();

    let outputs = build_send_outputs(
        token,
        uint!(7_U256),
        U256::ZERO,
        &sender,
        &recipient,
        None,
        &sender_viewing.viewing_private_key,
    )
    .expect("send outputs");

    assert_eq!(outputs.outputs.len(), 1);
    assert!(outputs.change_note.is_none());
}

#[test]
fn send_outputs_put_broadcaster_fee_note_first() {
    let token = Address::from([14_u8; 20]);
    let sender_viewing = sample_address_data(12);
    let sender = sender_viewing.address_data();
    let recipient = sample_address_data(22).address_data();
    let broadcaster = sample_address_data(32).address_data();

    let outputs = build_send_outputs(
        token,
        uint!(7_U256),
        uint!(3_U256),
        &sender,
        &recipient,
        Some(BroadcasterFeeOutput {
            recipient: broadcaster,
            token_address: token,
            amount: uint!(2_U256),
        }),
        &sender_viewing.viewing_private_key,
    )
    .expect("send outputs");

    assert_eq!(outputs.outputs.len(), 3);
    let fee_note = outputs.broadcaster_fee_note.expect("fee note");
    assert_eq!(outputs.outputs[0].value, uint!(2_U256));
    assert_eq!(fee_note.value, uint!(2_U256));
    assert_eq!(
        outputs.outputs[0].npk,
        Note::npk_for(broadcaster.master_public_key, outputs.outputs[0].random)
    );
    assert_eq!(outputs.outputs[1].value, uint!(7_U256));
    assert_eq!(outputs.outputs[2].value, uint!(3_U256));
}

#[test]
fn unshield_outputs_put_broadcaster_fee_note_first() {
    let token = Address::from([15_u8; 20]);
    let receiver_viewing = sample_address_data(13);
    let receiver = receiver_viewing.address_data();
    let broadcaster = sample_address_data(33).address_data();
    let unshield_to = Address::from([16_u8; 20]);

    let outputs = build_unshield_outputs(
        token,
        uint!(7_U256),
        unshield_to,
        uint!(3_U256),
        &receiver,
        Some(BroadcasterFeeOutput {
            recipient: broadcaster,
            token_address: token,
            amount: uint!(2_U256),
        }),
        &receiver_viewing.viewing_private_key,
    )
    .expect("unshield outputs");

    assert_eq!(outputs.outputs.len(), 3);
    assert_eq!(outputs.unshield_output_index, 2);
    assert_eq!(outputs.commitment_ciphertext.len(), 2);
    let fee_note = outputs.broadcaster_fee_note.expect("fee note");
    assert_eq!(outputs.outputs[0].value, uint!(2_U256));
    assert_eq!(fee_note.value, uint!(2_U256));
    assert_eq!(outputs.outputs[1].value, uint!(3_U256));
    assert_eq!(outputs.outputs[2].value, uint!(7_U256));
    assert_eq!(
        outputs.unshield_note.npk,
        U256::from_be_slice(unshield_to.as_slice())
    );
}

#[test]
fn send_selection_prefers_fewest_inputs() {
    let token = Address::from([10_u8; 20]);
    let utxos = vec![
        test_utxo(token, 40, 0, 1),
        test_utxo(token, 30, 0, 2),
        test_utxo(token, 5, 0, 3),
    ];

    let (selected, total) = select_utxos(&utxos, token, uint!(35_U256), false, 1).unwrap();

    assert_eq!(total, uint!(40_U256));
    assert_eq!(selected_positions(&selected), vec![1]);
}

#[test]
fn partial_send_uses_at_most_twelve_inputs_when_change_is_needed() {
    let token = Address::from([11_u8; 20]);
    let utxos = (0..13)
        .map(|position| test_utxo(token, 2, 0, position))
        .collect::<Vec<_>>();

    let info = send_selection_info(&utxos, token, uint!(23_U256), false).unwrap();

    assert_eq!(info.input_count, 12);
    assert_eq!(info.total, uint!(24_U256));
}

#[test]
fn exact_send_can_use_thirteen_inputs() {
    let token = Address::from([12_u8; 20]);
    let utxos = (0..13)
        .map(|position| test_utxo(token, 2, 0, position))
        .collect::<Vec<_>>();

    let info = send_selection_info(&utxos, token, uint!(26_U256), false).unwrap();

    assert_eq!(info.input_count, 13);
    assert_eq!(info.total, uint!(26_U256));
}

#[test]
fn broadcaster_fee_selection_batches_when_fee_output_reduces_first_chunk() {
    let token = Address::from([17_u8; 20]);
    let utxos = (0..13)
        .map(|position| test_utxo(token, 2, 0, position))
        .collect::<Vec<_>>();

    let info = send_selection_info_with_broadcaster_fee(
        &utxos,
        token,
        uint!(23_U256),
        uint!(3_U256),
        false,
    )
    .unwrap();

    assert_eq!(info.total, uint!(26_U256));
    assert_eq!(info.input_count, 13);
    assert_eq!(info.transaction_count, 2);
    assert_eq!(info.private_output_count, 3);
    assert_eq!(info.public_output_count, 0);
    assert_eq!(info.max_spendable, uint!(23_U256));
}

#[test]
fn same_token_fee_token_selection_preserves_existing_shape() {
    let token = Address::from([23_u8; 20]);
    let utxos = (0..13)
        .map(|position| test_utxo(token, 2, 0, position))
        .collect::<Vec<_>>();

    let existing = send_selection_info_with_broadcaster_fee(
        &utxos,
        token,
        uint!(23_U256),
        uint!(3_U256),
        false,
    )
    .expect("same-token existing selection");
    let selected_fee_token = send_selection_info_with_broadcaster_fee_token(
        &utxos,
        token,
        token,
        uint!(23_U256),
        uint!(3_U256),
        false,
    )
    .expect("same-token fee-token selection");

    assert_eq!(selected_fee_token, existing);
}

#[test]
fn different_token_fee_shape_includes_fee_transaction_first() {
    let action_token = Address::from([24_u8; 20]);
    let fee_token = Address::from([25_u8; 20]);
    let utxos = vec![
        test_utxo(fee_token, 5, 0, 0),
        test_utxo(action_token, 10, 0, 1),
    ];

    let info = send_selection_info_with_broadcaster_fee_token(
        &utxos,
        action_token,
        fee_token,
        uint!(7_U256),
        uint!(3_U256),
        false,
    )
    .expect("different-token selection");

    assert_eq!(info.transaction_count, 2);
    assert_eq!(info.input_count, 2);
    assert_eq!(info.private_output_count, 4);
    assert_eq!(info.public_output_count, 0);
    assert_eq!(info.total, uint!(10_U256));
}

#[test]
fn fee_only_outputs_use_fee_token_and_private_change() {
    let fee_token = Address::from([26_u8; 20]);
    let sender_viewing = sample_address_data(14);
    let sender = sender_viewing.address_data();
    let broadcaster = sample_address_data(34).address_data();

    let outputs = build_fee_only_outputs(
        BroadcasterFeeOutput {
            recipient: broadcaster,
            token_address: fee_token,
            amount: uint!(3_U256),
        },
        uint!(2_U256),
        &sender,
        &sender_viewing.viewing_private_key,
    )
    .expect("fee-only outputs");

    assert_eq!(outputs.outputs.len(), 2);
    assert_eq!(outputs.outputs[0].value, uint!(3_U256));
    assert_eq!(
        outputs.outputs[0].token_hash,
        U256::from_be_slice(fee_token.as_slice())
    );
    assert_eq!(
        outputs.outputs[0].npk,
        Note::npk_for(broadcaster.master_public_key, outputs.outputs[0].random)
    );
    let change = outputs.change_note.expect("fee-token change");
    assert_eq!(outputs.outputs[1].value, uint!(2_U256));
    assert_eq!(
        outputs.outputs[1].token_hash,
        U256::from_be_slice(fee_token.as_slice())
    );
    assert_eq!(change.value, uint!(2_U256));
}

#[test]
fn different_token_fee_selection_reports_fee_token_balance() {
    let action_token = Address::from([27_u8; 20]);
    let fee_token = Address::from([28_u8; 20]);
    let utxos = vec![test_utxo(action_token, 10, 0, 1)];

    let error = send_selection_info_with_broadcaster_fee_token(
        &utxos,
        action_token,
        fee_token,
        uint!(7_U256),
        uint!(3_U256),
        false,
    )
    .expect_err("missing fee token should fail");

    assert!(matches!(error, BuildError::InsufficientFeeTokenBalance(max) if max == U256::ZERO));
}

#[test]
fn fee_token_max_spendable_matches_single_fee_transaction_limit() {
    let fee_token = Address::from([31_u8; 20]);
    let utxos: Vec<_> = (0..20)
        .map(|position| test_utxo(fee_token, 1, 0, position))
        .collect();

    assert_eq!(
        max_broadcaster_fee_token_spendable(&utxos, fee_token),
        U256::from(MAX_CIRCUIT_INPUTS)
    );
}

#[test]
fn separate_fee_seed_selection_reserves_fee_transaction_without_fee_amount() {
    let action_token = Address::from([32_u8; 20]);
    let fee_token = Address::from([33_u8; 20]);
    let utxos = vec![
        test_utxo(fee_token, 1, 0, 100),
        test_utxo(action_token, 10, 0, 1),
    ];

    let info = send_selection_info_with_separate_broadcaster_fee_seed(
        &utxos,
        action_token,
        fee_token,
        uint!(7_U256),
        false,
    )
    .expect("seed selection");

    assert_eq!(info.transaction_count, 2);
    assert_eq!(info.input_count, 2);
    assert_eq!(info.private_output_count, 4);
    assert_eq!(info.max_spendable, uint!(10_U256));
}

#[test]
fn different_token_fee_selection_reserves_one_batch_slot() {
    let action_token = Address::from([29_u8; 20]);
    let fee_token = Address::from([30_u8; 20]);
    let mut utxos = vec![test_utxo(fee_token, 1, 0, 100)];
    utxos.extend(
        (0..8).flat_map(|tree| {
            (0..13).map(move |position| test_utxo(action_token, 1, tree, position))
        }),
    );

    let error = send_selection_info_with_broadcaster_fee_token(
        &utxos,
        action_token,
        fee_token,
        uint!(92_U256),
        uint!(1_U256),
        false,
    )
    .expect_err("fee transaction should reduce action batch capacity");

    assert!(matches!(error, BuildError::InsufficientBalance(max) if max == uint!(91_U256)));
}

#[test]
fn batched_selection_can_use_smaller_first_chunk_for_satisfiable_remainder() {
    let token = Address::from([19_u8; 20]);
    let mut utxos = (0..13)
        .map(|position| test_utxo(token, 2, 0, position))
        .collect::<Vec<_>>();
    utxos.push(test_utxo(token, 1, 1, 0));

    let info = send_selection_info(&utxos, token, uint!(25_U256), false).unwrap();

    assert_eq!(info.total, uint!(25_U256));
    assert_eq!(info.input_count, 13);
    assert_eq!(info.transaction_count, 2);
    assert_eq!(info.private_output_count, 2);
    assert_eq!(info.public_output_count, 0);
}

#[test]
fn max_send_spendable_uses_eight_batched_chunks() {
    let token = Address::from([13_u8; 20]);
    let mut utxos = (0..20)
        .map(|position| test_utxo(token, 1, 0, position))
        .collect::<Vec<_>>();
    utxos.extend((0..5).map(|position| test_utxo(token, 3, 1, position)));

    assert_eq!(max_send_spendable(&utxos, token), uint!(35_U256));
}

#[test]
fn batched_selection_reports_eight_chunk_cap() {
    let token = Address::from([18_u8; 20]);
    let utxos = (0..9)
        .flat_map(|tree| (0..13).map(move |position| test_utxo(token, 1, tree, position)))
        .collect::<Vec<_>>();

    let error = send_selection_info(&utxos, token, uint!(105_U256), false).unwrap_err();

    assert!(matches!(error, BuildError::InsufficientBalance(max) if max == uint!(104_U256)));
}

#[tokio::test]
async fn equal_value_notes_select_without_exhaustive_search() {
    let wallet = test_wallet();
    let builder = test_transaction_builder();
    let token = Address::from([0xd1; 20]);
    let unshield = |amount| MixedPrivateActionRequest {
        executor_calls: Vec::new(),
        adapter: None,
        private_sends: Vec::new(),
        public_unshields: vec![CompositeUnshieldLeg {
            token_address: token,
            amount,
            recipient: CompositeUnshieldRecipient::Public(Address::from([0xd2; 20])),
            role: CompositeUnshieldLegRole::Primary,
        }],
        relay_actions: None,
        min_gas_price: 0,
        verify_proof: false,
        spend_up_to: false,
        rebuild: None,
    };
    let assert_bounded_shape = |preview: &crate::tx::MixedPrivateActionPreview, inputs: usize| {
        assert_eq!(preview.selected_inputs.len(), inputs);
        assert!(preview.transactions.len() <= MAX_BATCH_TRANSACTIONS);
        assert!(
            preview
                .transactions
                .iter()
                .all(|transaction| transaction.input_count <= MAX_CIRCUIT_INPUTS)
        );
    };

    // Eight trees of thirteen: only whole-tree chunk sequences cover the
    // amount, so most multi-transaction branches add no candidate.
    let utxos = (0..8)
        .flat_map(|tree| (0..13).map(move |position| (tree, position)))
        .map(|(tree, position)| wallet_test_utxo(&wallet, token, 1, tree, position))
        .collect::<Vec<_>>();
    let preview = builder
        .preview_mixed_private_action_plan(&utxos, &unshield(uint!(104_U256)))
        .unwrap();
    assert_bounded_shape(&preview, 104);

    // Sixty in one tree: ties never prune the partial-selection searches.
    let utxos = (0..60)
        .map(|position| wallet_test_utxo(&wallet, token, 1, 0, position))
        .collect::<Vec<_>>();

    let info = unshield_selection_info(&utxos, token, uint!(10_U256), false).unwrap();
    assert_eq!(info.total, uint!(10_U256));
    assert_eq!(info.input_count, 10);
    assert_eq!(info.transaction_count, 1);

    let forest = forest_for_utxos(&utxos);
    let request = unshield(uint!(60_U256));
    let preview = builder
        .preview_mixed_private_action_plan(&utxos, &request)
        .unwrap();
    assert_bounded_shape(&preview, 60);

    let plan = builder
        .build_mixed_private_action_plan_inner(
            &wallet.viewing,
            &wallet,
            &forest,
            &utxos,
            request,
            &MockTransactionProver,
        )
        .await
        .unwrap();
    assert_eq!(plan.selected_inputs, preview.selected_inputs);
    assert_eq!(plan.shape, preview.shape);
}

#[test]
fn exact_only_selection_finds_repeated_value_match_within_budget() {
    // Thirteen inputs leave no change slot, so only an exact total fits one
    // transaction. Repeated values must not exhaust the search budget first.
    let token = Address::from([0xd3; 20]);
    let values = [
        106, 109, 103, 105, 110, 100, 104, 109, 110, 102, 105, 108, 109, 109, 101, 110, 103, 110,
    ];
    let utxos = (0_u64..)
        .zip(values)
        .map(|(position, value)| test_utxo(token, value, 0, position))
        .collect::<Vec<_>>();

    let info = unshield_selection_info(&utxos, token, uint!(1364_U256), false).unwrap();
    assert_eq!(info.transaction_count, 1);
    assert_eq!(info.input_count, 13);
}
