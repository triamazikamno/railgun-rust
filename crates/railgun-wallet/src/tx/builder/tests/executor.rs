use super::*;

#[tokio::test]
async fn executor_recovery_calls_bind_private_fee_proofs_and_exact_shield_actions() {
    use alloy::sol_types::SolValue;
    use broadcaster_core::contracts::railgun::{Call, TokenData, shieldCall};
    use broadcaster_core::contracts::shield::build_shield_request;

    use crate::keys::note_blinding_keys;
    use crate::notes::{ANNOTATION_DATA_LEN, decrypt_annotation_data};

    let wallet = test_wallet();
    let builder = test_transaction_builder();
    let signer = PrivateKeySigner::from_bytes(&FixedBytes::from([0x47; 32])).unwrap();
    let context = ExecutorContext {
        chain_id: builder.chain_id,
        executor: signer.address(),
        delegate: Address::repeat_byte(0x48),
        execution_nonce: U256::from(3),
    };
    let fee_token = Address::repeat_byte(0x49);
    let recovered_token = Address::repeat_byte(0x4a);
    let broadcaster = sample_address_data(0x4b).address_data();
    let utxos = vec![wallet_test_utxo(&wallet, fee_token, 90, 0, 0)];
    let forest = forest_for_utxos(&utxos);
    let prover = RecordingTransactionProver::default();
    let shield = build_shield_request(
        wallet.viewing.master_public_key,
        &wallet.viewing.viewing_public_key,
        TokenData::erc20(recovered_token),
        Uint::from(25),
        &[0x11; 32],
    )
    .unwrap();
    let calls = vec![Call {
        to: context.executor,
        value: U256::ZERO,
        data: shieldCall {
            _shieldRequests: vec![shield],
        }
        .abi_encode()
        .into(),
    }];
    let request = MixedPrivateActionRequest {
        adapter: Some(CompositeAdapter::Executor(context)),
        executor_calls: calls.clone(),
        private_sends: vec![MixedPrivateSend {
            token_address: fee_token,
            amount: U256::from(10),
            recipient: broadcaster,
            role: MixedPrivateSendRole::BroadcasterFee,
        }],
        public_unshields: Vec::new(),
        relay_actions: None,
        min_gas_price: 0,
        verify_proof: false,
        spend_up_to: false,
        rebuild: None,
    };
    let preview = builder
        .preview_mixed_private_action_plan(&utxos, &request)
        .unwrap();
    let plan = builder
        .build_mixed_private_action_plan_inner(
            &wallet.viewing,
            &wallet,
            &forest,
            &utxos,
            request.clone(),
            &prover,
        )
        .await
        .unwrap();
    assert_eq!(plan.shape, preview.shape);
    assert_eq!(plan.shape.relay_call_count, 1);
    assert_eq!(plan.private_outputs[0].amount, U256::from(10));
    assert_eq!(plan.private_outputs[0].token_address, fee_token);
    assert_eq!(
        plan.private_outputs[0].role,
        MixedPrivateOutputRole::Recipient(MixedPrivateSendRole::BroadcasterFee)
    );
    assert_eq!(plan.private_outputs[1].amount, U256::from(80));
    assert_eq!(plan.private_outputs[1].role, MixedPrivateOutputRole::Change);
    let digest = context.signing_hash(&plan.call).unwrap();
    let signed = context
        .authorize_call(&plan.call, signer.sign_hash_sync(&digest).unwrap())
        .unwrap();
    let decoded = RelayAdapt7702::executeCall::abi_decode(&signed.data).unwrap();
    assert!(decoded._actionData.requireSuccess);
    assert_eq!(decoded._actionData.calls.abi_encode(), calls.abi_encode());
    assert_eq!(
        decoded._transactions[0].boundParams.adaptContract,
        context.executor
    );
    assert_eq!(
        decoded._transactions[0].boundParams.adaptParams,
        UNRELAYED_ADAPT_PARAMS
    );
    assert_eq!(
        prover.bound_params_hashes(),
        vec![decoded._transactions[0].boundParams.hash()]
    );
    let sender = wallet.viewing.address_data();
    for (index, receiver, output_type) in [
        (0, &broadcaster, NoteOutputType::BroadcasterFee),
        (1, &sender, NoteOutputType::Change),
    ] {
        let ciphertext = &decoded._transactions[0].boundParams.commitmentCiphertext[index];
        assert_eq!(ciphertext.annotationData.len(), ANNOTATION_DATA_LEN);
        let (annotated_type, sender_random) = decrypt_annotation_data(
            &wallet.viewing.viewing_private_key,
            &ciphertext.annotationData,
        );
        assert_eq!(annotated_type, output_type as u8);
        let (blinded_sender, blinded_receiver) = note_blinding_keys(
            &sender.viewing_public_key,
            &receiver.viewing_public_key,
            plan.private_outputs[index].note.random,
            sender_random,
        )
        .unwrap();
        assert_eq!(ciphertext.blindedSenderViewingKey.0, blinded_sender);
        assert_eq!(ciphertext.blindedReceiverViewingKey.0, blinded_receiver);
    }

    // Setup: no executor calls, only the private fee.
    let mut setup = request.clone();
    setup.executor_calls.clear();
    let setup_preview = builder
        .preview_mixed_private_action_plan(&utxos, &setup)
        .unwrap();
    let setup_plan = builder
        .build_mixed_private_action_plan_inner(
            &wallet.viewing,
            &wallet,
            &forest,
            &utxos,
            setup.clone(),
            &prover,
        )
        .await
        .unwrap();
    assert_eq!(setup_plan.shape, setup_preview.shape);
    assert_eq!(
        setup_plan.shape.execution,
        CompositeExecution::Executor(context)
    );
    assert_eq!(setup_plan.shape.relay_call_count, 0);
    let digest = context.signing_hash(&setup_plan.call).unwrap();
    let signed = context
        .authorize_call(&setup_plan.call, signer.sign_hash_sync(&digest).unwrap())
        .unwrap();
    let signed = RelayAdapt7702::executeCall::abi_decode(&signed.data).unwrap();
    assert!(signed._actionData.calls.is_empty());
    let mut wrong_chain = setup.clone();
    wrong_chain.adapter = Some(CompositeAdapter::Executor(ExecutorContext {
        chain_id: context.chain_id + 1,
        ..context
    }));
    assert!(matches!(
        builder.preview_mixed_private_action_plan(&utxos, &wrong_chain),
        Err(BuildError::InvalidExecutorContext)
    ));
    let mut direct = setup;
    direct.adapter = None;
    let direct = builder
        .preview_mixed_private_action_plan(&utxos, &direct)
        .unwrap();
    assert_eq!(
        direct.shape.execution,
        CompositeExecution::Direct(builder.railgun_contract)
    );
    assert!(!direct.shape.uses_relay_adapt);

    let mut no_executor = request.clone();
    no_executor.adapter = None;
    assert!(matches!(
        builder.preview_mixed_private_action_plan(&utxos, &no_executor),
        Err(BuildError::InvalidExecutorContext)
    ));
    let mut ambiguous = request;
    ambiguous.relay_actions = Some(CompositeRelayActions {
        min_gas_limit: U256::ZERO,
        calls: vec![CompositeRelayAction::UnwrapBase { amount: U256::ONE }],
    });
    assert!(matches!(
        builder.preview_mixed_private_action_plan(&utxos, &ambiguous),
        Err(BuildError::ConflictingExecutorActions)
    ));
}

#[tokio::test]
async fn executor_fee_less_unshield_plan_sends_exact_amount_to_executor() {
    use alloy::sol_types::SolValue;
    use broadcaster_core::contracts::railgun::Call;

    let wallet = test_wallet();
    let builder = test_transaction_builder();
    let context = ExecutorContext {
        chain_id: builder.chain_id,
        executor: Address::repeat_byte(0x50),
        delegate: Address::repeat_byte(0x51),
        execution_nonce: U256::from(5),
    };
    let sell_token = Address::repeat_byte(0x52);
    let utxos = (0_u32..3)
        .map(|tree| wallet_test_utxo(&wallet, sell_token, 5, tree, u64::from(tree)))
        .collect::<Vec<_>>();
    let forest = forest_for_utxos(&utxos);
    let prover = RecordingTransactionProver::default();
    let calls = vec![
        Call {
            to: Address::repeat_byte(0x53),
            value: U256::ZERO,
            data: Bytes::from(vec![0x01, 0x02]),
        },
        Call {
            to: sell_token,
            value: U256::ZERO,
            data: Bytes::from(vec![0x03]),
        },
    ];
    let request = MixedPrivateActionRequest {
        adapter: Some(CompositeAdapter::Executor(context)),
        executor_calls: calls.clone(),
        private_sends: Vec::new(),
        public_unshields: vec![CompositeUnshieldLeg {
            token_address: sell_token,
            amount: U256::from(12),
            recipient: CompositeUnshieldRecipient::RelayAdapt,
            role: CompositeUnshieldLegRole::Primary,
        }],
        relay_actions: None,
        min_gas_price: 0,
        verify_proof: false,
        spend_up_to: false,
        rebuild: None,
    };
    let preview = builder
        .preview_mixed_private_action_plan(&utxos, &request)
        .unwrap();
    let plan = builder
        .build_mixed_private_action_plan_inner(
            &wallet.viewing,
            &wallet,
            &forest,
            &utxos,
            request,
            &prover,
        )
        .await
        .unwrap();

    assert_eq!(plan.selected_inputs, preview.selected_inputs);
    assert_eq!(plan.shape, preview.shape);
    assert_eq!(plan.shape.execution, CompositeExecution::Executor(context));
    assert_eq!(plan.shape.transaction_count, 3);
    assert!(plan.shape.transaction_count <= MAX_BATCH_TRANSACTIONS);
    assert_eq!(plan.shape.relay_call_count, 2);
    assert_eq!(
        plan.public_outputs
            .iter()
            .map(|output| output.amount)
            .sum::<U256>(),
        U256::from(12)
    );
    assert!(plan.public_outputs.iter().all(|output| {
        output.token_address == sell_token
            && output.recipient == CompositeUnshieldRecipient::RelayAdapt
    }));
    assert!(
        plan.private_outputs
            .iter()
            .all(|output| output.role == MixedPrivateOutputRole::Change)
    );
    assert_eq!(
        plan.private_outputs
            .iter()
            .map(|output| output.amount)
            .sum::<U256>(),
        U256::from(3)
    );

    let decoded = decode_adapter_plan(&plan.call, Some(context));
    assert_eq!(plan.call.to, context.executor);
    assert!(decoded._actionData.requireSuccess);
    assert_eq!(decoded._actionData.calls.abi_encode(), calls.abi_encode());
    assert_eq!(decoded._transactions.len(), 3);
    assert!(decoded._transactions.iter().all(|transaction| {
        transaction.nullifiers.len() <= MAX_CIRCUIT_INPUTS
            && transaction.unshieldPreimage.npk == context.executor.into_word()
            && transaction.boundParams.adaptContract == context.executor
            && transaction.boundParams.adaptParams == UNRELAYED_ADAPT_PARAMS
    }));
    let mut proven_bound_params = prover.bound_params_hashes();
    proven_bound_params.sort_unstable();
    let mut final_bound_params = decoded
        ._transactions
        .iter()
        .map(|transaction| transaction.boundParams.hash())
        .collect::<Vec<_>>();
    final_bound_params.sort_unstable();
    assert_eq!(proven_bound_params, final_bound_params);
    context.signing_hash(&plan.call).unwrap();
}
