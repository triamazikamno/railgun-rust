use super::*;

#[tokio::test]
async fn mixed_send_and_public_unshield_bind_relay_and_preserve_output_roles() {
    let wallet = test_wallet();
    let builder = test_transaction_builder();
    for use_executor in [false, true] {
        let executor_signer = PrivateKeySigner::from_bytes(&FixedBytes::from([0x42; 32])).unwrap();
        let executor = use_executor.then_some(ExecutorContext {
            chain_id: builder.chain_id,
            executor: executor_signer.address(),
            delegate: Address::from([0x43; 20]),
            execution_nonce: U256::from(9),
        });
        let execution_account = executor.map_or(TEST_RELAY_ADAPT, |context| context.executor);
        let adapter = Some(executor.map_or(
            CompositeAdapter::RelayAdapt(TEST_RELAY_ADAPT),
            CompositeAdapter::Executor,
        ));
        let send_token = Address::from([0xa1; 20]);
        let wrapped_native = Address::from([0xa2; 20]);
        let private_recipient = sample_address_data(0xa3).address_data();
        let payer = Address::from([0xa4; 20]);
        let utxos = vec![
            wallet_test_utxo(&wallet, send_token, 12, 0, 0),
            wallet_test_utxo(&wallet, wrapped_native, 8, 0, 1),
        ];
        let forest = forest_for_utxos(&utxos);
        let prover = RecordingTransactionProver::default();
        let request = MixedPrivateActionRequest {
            executor_calls: Vec::new(),
            adapter,
            private_sends: vec![MixedPrivateSend {
                token_address: send_token,
                amount: uint!(10_U256),
                recipient: private_recipient,
                role: MixedPrivateSendRole::Primary,
            }],
            public_unshields: vec![CompositeUnshieldLeg {
                token_address: wrapped_native,
                amount: uint!(8_U256),
                recipient: CompositeUnshieldRecipient::RelayAdapt,
                role: CompositeUnshieldLegRole::Other,
            }],
            relay_actions: Some(CompositeRelayActions {
                min_gas_limit: uint!(123_U256),
                calls: vec![
                    CompositeRelayAction::UnwrapBase {
                        amount: uint!(8_U256),
                    },
                    CompositeRelayAction::Transfer {
                        token: CompositeRelayActionToken::BaseNative,
                        recipient: payer,
                        amount: uint!(8_U256),
                    },
                ],
            }),
            min_gas_price: 0,
            verify_proof: false,
            spend_up_to: false,
            rebuild: None,
        };
        let preview = builder
            .preview_mixed_private_action_plan(&utxos, &request)
            .expect("mixed preview");

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
            .expect("mixed plan");
        let decoded = decode_adapter_plan(&plan.call, executor);

        assert_eq!(plan.call.to, execution_account);
        assert_eq!(preview.selected_inputs, plan.selected_inputs);
        assert_eq!(preview.shape, plan.shape);
        assert_eq!(plan.shape.transaction_count, 2);
        assert_eq!(plan.shape.input_count, 2);
        assert_eq!(plan.shape.private_output_count, 2);
        assert_eq!(plan.shape.public_output_count, 1);
        assert_eq!(plan.shape.relay_call_count, 2);
        assert!(plan.shape.uses_relay_adapt);
        assert!(decoded._actionData.requireSuccess);
        assert_eq!(decoded._transactions.len(), 2);
        assert!(decoded._transactions.iter().all(|transaction| {
            transaction.boundParams.adaptContract == execution_account
                && (transaction.boundParams.adaptParams == UNRELAYED_ADAPT_PARAMS)
                    == executor.is_some()
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
        assert_eq!(plan.private_outputs.len(), 2);
        assert_eq!(
            plan.private_outputs[0].source,
            MixedPrivateOutputSource::Send(0)
        );
        assert_eq!(
            plan.private_outputs[0].role,
            MixedPrivateOutputRole::Recipient(MixedPrivateSendRole::Primary)
        );
        assert_eq!(plan.private_outputs[0].amount, uint!(10_U256));
        assert_eq!(plan.private_outputs[1].role, MixedPrivateOutputRole::Change);
        assert_eq!(plan.public_outputs.len(), 1);
        assert_eq!(plan.public_outputs[0].role, CompositeUnshieldLegRole::Other);
    }
}

#[tokio::test]
async fn mixed_plan_pinned_rebuild_rejects_input_and_shape_changes() {
    let wallet = test_wallet();
    let builder = test_transaction_builder();
    let send_token = Address::from([0xb1; 20]);
    let wrapped_native = Address::from([0xb2; 20]);
    let payer = Address::from([0xb3; 20]);
    let utxos = vec![
        wallet_test_utxo(&wallet, send_token, 12, 0, 0),
        wallet_test_utxo(&wallet, wrapped_native, 8, 0, 1),
        wallet_test_utxo(&wallet, send_token, 20, 0, 2),
    ];
    let forest = forest_for_utxos(&utxos);
    let request = MixedPrivateActionRequest {
        executor_calls: Vec::new(),
        adapter: Some(CompositeAdapter::RelayAdapt(TEST_RELAY_ADAPT)),
        private_sends: vec![MixedPrivateSend {
            token_address: send_token,
            amount: uint!(10_U256),
            recipient: sample_address_data(0xb4).address_data(),
            role: MixedPrivateSendRole::Primary,
        }],
        public_unshields: vec![CompositeUnshieldLeg {
            token_address: wrapped_native,
            amount: uint!(8_U256),
            recipient: CompositeUnshieldRecipient::RelayAdapt,
            role: CompositeUnshieldLegRole::Other,
        }],
        relay_actions: Some(CompositeRelayActions {
            min_gas_limit: U256::ZERO,
            calls: vec![
                CompositeRelayAction::UnwrapBase {
                    amount: uint!(8_U256),
                },
                CompositeRelayAction::Transfer {
                    token: CompositeRelayActionToken::BaseNative,
                    recipient: payer,
                    amount: uint!(8_U256),
                },
            ],
        }),
        min_gas_price: 0,
        verify_proof: false,
        spend_up_to: false,
        rebuild: None,
    };
    let first = builder
        .build_mixed_private_action_plan_inner(
            &wallet.viewing,
            &wallet,
            &forest,
            &utxos,
            request.clone(),
            &MockTransactionProver,
        )
        .await
        .expect("first mixed plan");
    let constraint = MixedPrivateActionRebuildConstraint {
        selected_inputs: first.selected_inputs.clone(),
        expected_shape: first.shape,
    };
    let mut stable_request = request.clone();
    stable_request.rebuild = Some(constraint.clone());

    let stable = builder
        .build_mixed_private_action_plan_inner(
            &wallet.viewing,
            &wallet,
            &forest,
            &utxos,
            stable_request,
            &MockTransactionProver,
        )
        .await
        .expect("stable pinned rebuild");
    assert_eq!(stable.selected_inputs, first.selected_inputs);
    assert_eq!(stable.shape, first.shape);

    let mut unavailable_request = request.clone();
    unavailable_request.rebuild = Some(MixedPrivateActionRebuildConstraint {
        selected_inputs: vec![SelectedInputIdentity {
            tree: 0,
            position: 99,
        }],
        expected_shape: first.shape,
    });
    let unavailable = builder
        .build_mixed_private_action_plan_inner(
            &wallet.viewing,
            &wallet,
            &forest,
            &utxos,
            unavailable_request,
            &MockTransactionProver,
        )
        .await
        .expect_err("unavailable pinned input must fail");
    assert!(matches!(
        unavailable,
        BuildError::PinnedInputUnavailable {
            tree: 0,
            position: 99
        }
    ));

    let mut insufficient_request = request.clone();
    insufficient_request.public_unshields[0].amount = uint!(9_U256);
    insufficient_request.rebuild = Some(constraint.clone());
    let insufficient = builder
        .build_mixed_private_action_plan_inner(
            &wallet.viewing,
            &wallet,
            &forest,
            &utxos,
            insufficient_request,
            &MockTransactionProver,
        )
        .await
        .expect_err("insufficient pinned inputs must fail");
    assert!(matches!(
        insufficient,
        BuildError::PinnedInputsInsufficient(max) if max == uint!(8_U256)
    ));

    let mut changed_inputs_request = request.clone();
    let mut changed_inputs = constraint.selected_inputs.clone();
    changed_inputs.push(SelectedInputIdentity {
        tree: 0,
        position: 2,
    });
    changed_inputs_request.rebuild = Some(MixedPrivateActionRebuildConstraint {
        selected_inputs: changed_inputs,
        expected_shape: first.shape,
    });
    let changed_inputs = builder
        .build_mixed_private_action_plan_inner(
            &wallet.viewing,
            &wallet,
            &forest,
            &utxos,
            changed_inputs_request,
            &MockTransactionProver,
        )
        .await
        .expect_err("changed pinned input set must fail");
    assert!(matches!(
        changed_inputs,
        BuildError::PinnedInputsChanged { .. }
    ));

    let mut changed_shape_request = request;
    changed_shape_request.private_sends[0].amount = uint!(12_U256);
    changed_shape_request.rebuild = Some(constraint);
    let changed_shape = builder
        .build_mixed_private_action_plan_inner(
            &wallet.viewing,
            &wallet,
            &forest,
            &utxos,
            changed_shape_request,
            &MockTransactionProver,
        )
        .await
        .expect_err("changed pinned shape must fail");
    assert!(matches!(
        changed_shape,
        BuildError::CompositePlanShapeChanged { expected, actual }
            if *expected == first.shape && actual != expected
    ));
}

#[tokio::test]
async fn mixed_max_spend_reserves_exact_public_output() {
    let wallet = test_wallet();
    let builder = test_transaction_builder();
    let token = Address::from([0xc2; 20]);
    let payer = Address::from([0xc3; 20]);
    let utxos = vec![
        wallet_test_utxo(&wallet, token, 80, 0, 0),
        wallet_test_utxo(&wallet, token, 20, 0, 1),
    ];
    let forest = forest_for_utxos(&utxos);
    let request = MixedPrivateActionRequest {
        executor_calls: Vec::new(),
        adapter: Some(CompositeAdapter::RelayAdapt(TEST_RELAY_ADAPT)),
        private_sends: vec![MixedPrivateSend {
            token_address: token,
            amount: uint!(81_U256),
            recipient: sample_address_data(0xc4).address_data(),
            role: MixedPrivateSendRole::Primary,
        }],
        public_unshields: vec![CompositeUnshieldLeg {
            token_address: token,
            amount: uint!(20_U256),
            recipient: CompositeUnshieldRecipient::RelayAdapt,
            role: CompositeUnshieldLegRole::Other,
        }],
        relay_actions: Some(CompositeRelayActions {
            min_gas_limit: U256::ZERO,
            calls: vec![
                CompositeRelayAction::UnwrapBase {
                    amount: uint!(20_U256),
                },
                CompositeRelayAction::Transfer {
                    token: CompositeRelayActionToken::BaseNative,
                    recipient: payer,
                    amount: uint!(20_U256),
                },
            ],
        }),
        min_gas_price: 0,
        verify_proof: false,
        spend_up_to: true,
        rebuild: None,
    };
    let preview = builder
        .preview_mixed_private_action_plan(&utxos, &request)
        .expect("mixed max-spend preview");

    let plan = builder
        .build_mixed_private_action_plan_inner(
            &wallet.viewing,
            &wallet,
            &forest,
            &utxos,
            request.clone(),
            &MockTransactionProver,
        )
        .await
        .expect("mixed max-spend plan");
    assert_eq!(preview.selected_inputs, plan.selected_inputs);
    assert_eq!(preview.shape, plan.shape);
    assert_eq!(plan.private_outputs[0].amount, uint!(80_U256));
    assert_eq!(plan.public_outputs[0].amount, uint!(20_U256));

    let mut exact_request = request;
    exact_request.spend_up_to = false;
    let error = builder
        .build_mixed_private_action_plan_inner(
            &wallet.viewing,
            &wallet,
            &forest,
            &utxos,
            exact_request,
            &MockTransactionProver,
        )
        .await
        .expect_err("exact send above sponsored maximum must fail");
    assert!(matches!(
        error,
        BuildError::InsufficientBalance(max) if max == uint!(80_U256)
    ));
}

#[tokio::test]
async fn mixed_max_spend_does_not_reduce_underfunded_public_output() {
    let wallet = test_wallet();
    let builder = test_transaction_builder();
    let send_token = Address::from([0xc5; 20]);
    let public_token = Address::from([0xc6; 20]);
    let utxos = vec![
        wallet_test_utxo(&wallet, send_token, 10, 0, 0),
        wallet_test_utxo(&wallet, public_token, 8, 0, 1),
    ];
    let forest = forest_for_utxos(&utxos);
    let request = MixedPrivateActionRequest {
        executor_calls: Vec::new(),
        adapter: Some(CompositeAdapter::RelayAdapt(TEST_RELAY_ADAPT)),
        private_sends: vec![MixedPrivateSend {
            token_address: send_token,
            amount: uint!(10_U256),
            recipient: sample_address_data(0xc7).address_data(),
            role: MixedPrivateSendRole::Primary,
        }],
        public_unshields: vec![CompositeUnshieldLeg {
            token_address: public_token,
            amount: uint!(10_U256),
            recipient: CompositeUnshieldRecipient::RelayAdapt,
            role: CompositeUnshieldLegRole::Other,
        }],
        relay_actions: Some(CompositeRelayActions {
            min_gas_limit: U256::ZERO,
            calls: vec![CompositeRelayAction::UnwrapBase {
                amount: uint!(10_U256),
            }],
        }),
        min_gas_price: 0,
        verify_proof: false,
        spend_up_to: true,
        rebuild: None,
    };

    let error = builder
        .build_mixed_private_action_plan_inner(
            &wallet.viewing,
            &wallet,
            &forest,
            &utxos,
            request,
            &MockTransactionProver,
        )
        .await
        .expect_err("underfunded public output must not be reduced");
    assert!(matches!(
        error,
        BuildError::InsufficientBalance(max) if max == uint!(8_U256)
    ));
}

#[tokio::test]
async fn mixed_fragmented_ninth_transaction_reports_shape_limit() {
    let wallet = test_wallet();
    let builder = test_transaction_builder();
    let send_token = Address::from([0xc8; 20]);
    let public_token = Address::from([0xc9; 20]);
    let mut utxos = (0_u32..7)
        .map(|tree| wallet_test_utxo(&wallet, send_token, 1, tree, 0))
        .collect::<Vec<_>>();
    utxos.push(wallet_test_utxo(&wallet, public_token, 1, 7, 0));
    utxos.push(wallet_test_utxo(&wallet, public_token, 1, 8, 0));
    let forest = forest_for_utxos(&utxos);
    let request = MixedPrivateActionRequest {
        executor_calls: Vec::new(),
        adapter: None,
        private_sends: vec![MixedPrivateSend {
            token_address: send_token,
            amount: uint!(7_U256),
            recipient: sample_address_data(0xca).address_data(),
            role: MixedPrivateSendRole::Primary,
        }],
        public_unshields: vec![CompositeUnshieldLeg {
            token_address: public_token,
            amount: uint!(2_U256),
            recipient: CompositeUnshieldRecipient::Public(Address::from([0xcb; 20])),
            role: CompositeUnshieldLegRole::Other,
        }],
        relay_actions: None,
        min_gas_price: 0,
        verify_proof: false,
        spend_up_to: false,
        rebuild: None,
    };

    let error = builder
        .build_mixed_private_action_plan_inner(
            &wallet.viewing,
            &wallet,
            &forest,
            &utxos,
            request,
            &MockTransactionProver,
        )
        .await
        .expect_err("fragmented ninth transaction must fail as a shape limit");
    assert!(matches!(
        error,
        BuildError::TooManyBatchTransactions {
            requested: 9,
            max: 8
        }
    ));
}
