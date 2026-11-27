use super::*;

#[tokio::test]
async fn direct_composite_unshield_uses_transact_and_preserves_fee_output_role() {
    let wallet = test_wallet();
    let builder = test_transaction_builder();
    let token_a = Address::from([0x61; 20]);
    let token_b = Address::from([0x62; 20]);
    let recipient = Address::from([0x63; 20]);
    let broadcaster = sample_address_data(0x64).address_data();
    let utxos = vec![
        wallet_test_utxo(&wallet, token_a, 12, 0, 0),
        wallet_test_utxo(&wallet, token_b, 7, 0, 1),
    ];
    let forest = forest_for_utxos(&utxos);
    let request = CompositeUnshieldRequest {
        adapter: None,
        legs: vec![
            CompositeUnshieldLeg {
                token_address: token_a,
                amount: uint!(10_U256),
                recipient: CompositeUnshieldRecipient::Public(recipient),
                role: CompositeUnshieldLegRole::Primary,
            },
            CompositeUnshieldLeg {
                token_address: token_b,
                amount: uint!(7_U256),
                recipient: CompositeUnshieldRecipient::Public(recipient),
                role: CompositeUnshieldLegRole::Other,
            },
        ],
        relay_actions: None,
        broadcaster_fee: Some(BroadcasterFeeOutput {
            recipient: broadcaster,
            token_address: token_a,
            amount: uint!(2_U256),
        }),
        min_gas_price: 0,
        verify_proof: false,
        spend_up_to: false,
    };

    let plan = builder
        .build_composite_unshield_plan_inner(
            &wallet.viewing,
            &wallet,
            &forest,
            &utxos,
            request,
            &MockTransactionProver,
        )
        .await
        .expect("direct composite plan");
    let decoded = transactCall::abi_decode(&plan.call.data).expect("decode transact call");

    assert_eq!(plan.call.to, builder.railgun_contract);
    assert_eq!(decoded._transactions.len(), 2);
    assert_eq!(plan.shape.transaction_count, 2);
    assert_eq!(plan.shape.input_count, 2);
    assert_eq!(plan.shape.private_output_count, 1);
    assert_eq!(plan.shape.public_output_count, 2);
    assert_eq!(plan.shape.relay_call_count, 0);
    assert!(!plan.shape.uses_relay_adapt);
    assert_eq!(plan.private_output_roles.len(), 1);
    assert_eq!(plan.private_output_roles[0].chunk_index, 0);
    assert_eq!(plan.private_output_roles[0].output_index, 0);
    assert_eq!(
        plan.private_output_roles[0].role,
        CompositePrivateOutputRoleKind::BroadcasterFee
    );
    assert_eq!(plan.private_output_roles[0].token_address, token_a);
    assert_eq!(
        decoded._transactions[0].boundParams.adaptContract,
        Address::ZERO
    );
    assert_eq!(
        decoded._transactions[0].boundParams.adaptParams,
        UNRELAYED_ADAPT_PARAMS
    );
}

#[tokio::test]
async fn relay_composite_binds_action_data_and_uses_exact_actions() {
    let wallet = test_wallet();
    let builder = test_transaction_builder();
    let executor_signer = PrivateKeySigner::from_bytes(&FixedBytes::from([0x42; 32])).unwrap();
    let context = ExecutorContext {
        chain_id: builder.chain_id,
        executor: executor_signer.address(),
        delegate: Address::from([0x43; 20]),
        execution_nonce: U256::from(9),
    };
    let execution_account = context.executor;
    let primary_token = Address::from([0x71; 20]);
    let wrapped_native = Address::from([0x72; 20]);
    let recipient = Address::from([0x73; 20]);
    let utxos = vec![
        wallet_test_utxo(&wallet, primary_token, 10, 0, 0),
        wallet_test_utxo(&wallet, wrapped_native, 8, 0, 1),
    ];
    let forest = forest_for_utxos(&utxos);
    let request = CompositeUnshieldRequest {
        adapter: Some(CompositeAdapter::Executor(context)),
        legs: vec![
            CompositeUnshieldLeg {
                token_address: primary_token,
                amount: uint!(10_U256),
                recipient: CompositeUnshieldRecipient::Public(recipient),
                role: CompositeUnshieldLegRole::Primary,
            },
            CompositeUnshieldLeg {
                token_address: wrapped_native,
                amount: uint!(8_U256),
                recipient: CompositeUnshieldRecipient::RelayAdapt,
                role: CompositeUnshieldLegRole::NativeTopUp,
            },
        ],
        relay_actions: Some(CompositeRelayActions {
            min_gas_limit: uint!(123_U256),
            calls: vec![
                CompositeRelayAction::UnwrapBase {
                    amount: uint!(3_U256),
                },
                CompositeRelayAction::Transfer {
                    token: CompositeRelayActionToken::BaseNative,
                    recipient,
                    amount: uint!(3_U256),
                },
                CompositeRelayAction::Transfer {
                    token: CompositeRelayActionToken::Erc20(wrapped_native),
                    recipient,
                    amount: uint!(5_U256),
                },
            ],
        }),
        broadcaster_fee: None,
        min_gas_price: 0,
        verify_proof: false,
        spend_up_to: false,
    };

    let prover = RecordingTransactionProver::default();
    let plan = builder
        .build_composite_unshield_plan_inner(
            &wallet.viewing,
            &wallet,
            &forest,
            &utxos,
            request,
            &prover,
        )
        .await
        .expect("relay composite plan");
    let decoded = decode_adapter_plan(&plan.call, context);
    let action_data = plan.action_data.as_ref().expect("action data");

    assert_eq!(plan.call.to, execution_account);
    assert_eq!(plan.shape.transaction_count, 2);
    assert_eq!(plan.shape.relay_call_count, 3);
    assert!(plan.shape.uses_relay_adapt);
    assert!(decoded._actionData.requireSuccess);
    assert!(action_data.requireSuccess);
    assert_eq!(decoded._actionData.minGasLimit, uint!(123_U256));
    assert_eq!(decoded._actionData.calls.len(), 3);
    assert_eq!(
        decoded._actionData.calls[0].data,
        ActionData::unwrap_base_call(execution_account, uint!(3_U256)).data
    );
    assert_eq!(
        decoded._actionData.calls[1].data,
        ActionData::transfer_call(
            execution_account,
            vec![TokenTransfer::base_native(recipient, uint!(3_U256))],
        )
        .data
    );
    assert_eq!(
        decoded._actionData.calls[2].data,
        ActionData::transfer_call(
            execution_account,
            vec![TokenTransfer::erc20(
                wrapped_native,
                recipient,
                uint!(5_U256)
            )],
        )
        .data
    );
    for transaction in &decoded._transactions {
        assert_eq!(transaction.boundParams.adaptContract, execution_account);
        assert_eq!(transaction.boundParams.adaptParams, UNRELAYED_ADAPT_PARAMS);
    }

    let mut recorded = prover.bound_params_hashes();
    recorded.sort_unstable();
    let mut encoded = decoded
        ._transactions
        .iter()
        .map(|tx| tx.boundParams.hash())
        .collect::<Vec<_>>();
    encoded.sort_unstable();
    assert_eq!(recorded, encoded);
    assert!(
        decoded
            ._actionData
            .calls
            .iter()
            .all(|call| call.to == execution_account)
    );
    assert_eq!(
        decoded._transactions[1].unshieldPreimage.npk,
        context.executor.into_word()
    );
    let digest = context
        .signing_hash(&plan.call)
        .expect("prepared execution digest");
    let signature = executor_signer
        .sign_hash_sync(&digest)
        .expect("public test signature");
    let signed = context
        .authorize_call(&plan.call, signature)
        .expect("authorized executor call");
    let signed = RelayAdapt7702::executeCall::abi_decode(&signed.data).unwrap();
    assert!(!signed._signature.is_empty());
    let mut stale = context;
    stale.execution_nonce += U256::ONE;
    assert!(stale.signing_hash(&plan.call).is_err());
    let mut changed = RelayAdapt7702::executeCall::abi_decode(&plan.call.data).unwrap();
    changed._actionData.calls[0].value += U256::ONE;
    let changed = TransactionCall {
        to: context.executor,
        data: changed.abi_encode().into(),
    };
    assert!(matches!(
        context.authorize_call(&changed, signature),
        Err(BuildError::InvalidExecutorSignature)
    ));
}

#[tokio::test]
async fn relay_composite_with_later_fee_leg_keeps_fee_transaction_first() {
    let wallet = test_wallet();
    let builder = test_transaction_builder();
    let primary_token = Address::from([0x79; 20]);
    let wrapped_native = Address::from([0x7a; 20]);
    let recipient = Address::from([0x7b; 20]);
    let broadcaster = sample_address_data(0x7c);
    let utxos = vec![
        wallet_test_utxo(&wallet, primary_token, 12, 0, 0),
        wallet_test_utxo(&wallet, wrapped_native, 10, 0, 1),
    ];
    let forest = forest_for_utxos(&utxos);
    let request = CompositeUnshieldRequest {
        adapter: Some(CompositeAdapter::Executor(TEST_EXECUTOR_CONTEXT)),
        legs: vec![
            CompositeUnshieldLeg {
                token_address: primary_token,
                amount: uint!(10_U256),
                recipient: CompositeUnshieldRecipient::Public(recipient),
                role: CompositeUnshieldLegRole::Primary,
            },
            CompositeUnshieldLeg {
                token_address: wrapped_native,
                amount: uint!(8_U256),
                recipient: CompositeUnshieldRecipient::RelayAdapt,
                role: CompositeUnshieldLegRole::NativeTopUp,
            },
        ],
        relay_actions: Some(CompositeRelayActions {
            min_gas_limit: U256::ZERO,
            calls: vec![
                CompositeRelayAction::UnwrapBase {
                    amount: uint!(3_U256),
                },
                CompositeRelayAction::Transfer {
                    token: CompositeRelayActionToken::BaseNative,
                    recipient,
                    amount: uint!(3_U256),
                },
            ],
        }),
        broadcaster_fee: Some(BroadcasterFeeOutput {
            recipient: broadcaster.address_data(),
            token_address: wrapped_native,
            amount: uint!(2_U256),
        }),
        min_gas_price: 0,
        verify_proof: false,
        spend_up_to: false,
    };

    let plan = builder
        .build_composite_unshield_plan_inner(
            &wallet.viewing,
            &wallet,
            &forest,
            &utxos,
            request,
            &MockTransactionProver,
        )
        .await
        .expect("relay composite plan");
    let decoded = decode_adapter_plan(&plan.call, TEST_EXECUTOR_CONTEXT);
    let fee_role = plan
        .private_output_roles
        .iter()
        .find(|role| role.role == CompositePrivateOutputRoleKind::BroadcasterFee)
        .expect("broadcaster fee role");
    let parsed = parse_transact_calldata(
        plan.call.data.as_ref(),
        &broadcaster.viewing_private_key,
        broadcaster.master_public_key,
        None,
    )
    .expect("broadcaster parses fee note from transaction zero");

    assert_eq!(decoded._transactions.len(), 2);
    assert_eq!(plan.leg_metadata[1].transaction_indices, vec![0]);
    assert_eq!(plan.leg_metadata[0].transaction_indices, vec![1]);
    assert_eq!(fee_role.chunk_index, 0);
    assert_eq!(fee_role.output_index, 0);
    assert_eq!(fee_role.token_address, wrapped_native);
    assert_eq!(parsed.fee_token, wrapped_native);
    assert_eq!(parsed.fee_amount, uint!(2_U256));
    assert!(parsed.action_data.is_some());
}

#[tokio::test]
async fn composite_fee_placement_backtracks_after_current_leg_exceeds_remaining_slots() {
    let wallet = test_wallet();
    let builder = test_transaction_builder();
    let shared_token = Address::from([0xb0; 20]);
    let recipient = Address::from([0xb1; 20]);
    let broadcaster = sample_address_data(0xb2).address_data();
    let mut utxos = (0_u8..6)
        .map(|index| {
            wallet_test_utxo(
                &wallet,
                Address::from([0xa0 + index; 20]),
                1,
                u32::from(index),
                0,
            )
        })
        .collect::<Vec<_>>();
    utxos.extend(
        (0_u64..12).map(|position| wallet_test_utxo(&wallet, shared_token, 10, 6, position)),
    );
    utxos.push(wallet_test_utxo(&wallet, shared_token, 2, 6, 12));
    utxos.push(wallet_test_utxo(&wallet, shared_token, 11, 7, 0));
    let forest = forest_for_utxos(&utxos);
    let mut legs = (0_u8..6)
        .map(|index| CompositeUnshieldLeg {
            token_address: Address::from([0xa0 + index; 20]),
            amount: uint!(1_U256),
            recipient: CompositeUnshieldRecipient::Public(recipient),
            role: CompositeUnshieldLegRole::Other,
        })
        .collect::<Vec<_>>();
    legs.push(CompositeUnshieldLeg {
        token_address: shared_token,
        amount: uint!(122_U256),
        recipient: CompositeUnshieldRecipient::Public(recipient),
        role: CompositeUnshieldLegRole::Primary,
    });
    legs.push(CompositeUnshieldLeg {
        token_address: shared_token,
        amount: uint!(1_U256),
        recipient: CompositeUnshieldRecipient::Public(recipient),
        role: CompositeUnshieldLegRole::Other,
    });
    let request = CompositeUnshieldRequest {
        adapter: None,
        legs,
        relay_actions: None,
        broadcaster_fee: Some(BroadcasterFeeOutput {
            recipient: broadcaster,
            token_address: shared_token,
            amount: uint!(10_U256),
        }),
        min_gas_price: 0,
        verify_proof: false,
        spend_up_to: false,
    };

    let plan = builder
        .build_composite_unshield_plan_inner(
            &wallet.viewing,
            &wallet,
            &forest,
            &utxos,
            request,
            &MockTransactionProver,
        )
        .await
        .expect("later fee placement fits the composite batch");
    let fee_role = plan
        .private_output_roles
        .iter()
        .find(|role| role.role == CompositePrivateOutputRoleKind::BroadcasterFee)
        .expect("broadcaster fee role");

    assert_eq!(plan.shape.transaction_count, MAX_BATCH_TRANSACTIONS);
    assert_eq!(plan.leg_metadata[7].transaction_indices, vec![0]);
    assert_eq!(plan.leg_metadata[6].transaction_indices, vec![7]);
    assert_eq!(fee_role.chunk_index, 0);
    assert_eq!(fee_role.output_index, 0);
    assert_eq!(fee_role.token_address, shared_token);
}

#[test]
fn composite_same_token_selection_retries_when_greedy_choice_starves_later_leg() {
    let wallet = test_wallet();
    let token = Address::from([0x85; 20]);
    let recipient = Address::from([0x86; 20]);
    let utxos = vec![
        wallet_test_utxo(&wallet, token, 9, 0, 0),
        wallet_test_utxo(&wallet, token, 4, 0, 1),
        wallet_test_utxo(&wallet, token, 4, 0, 2),
    ];
    let legs = vec![
        CompositeUnshieldLeg {
            token_address: token,
            amount: uint!(8_U256),
            recipient: CompositeUnshieldRecipient::Public(recipient),
            role: CompositeUnshieldLegRole::Primary,
        },
        CompositeUnshieldLeg {
            token_address: token,
            amount: uint!(9_U256),
            recipient: CompositeUnshieldRecipient::Public(recipient),
            role: CompositeUnshieldLegRole::Other,
        },
    ];

    let (selections, _) = select_composite_leg_selections(&utxos, &legs, None, false, 0)
        .expect("same-token composite selection");

    assert_eq!(
        selections
            .iter()
            .map(|selection| selection.chunks.len())
            .sum::<usize>(),
        2
    );
    assert_eq!(selections[0].chunks[0].utxos.len(), 2);
    assert_eq!(selections[1].chunks[0].utxos.len(), 1);
    assert_eq!(
        selections[0].chunks[0]
            .utxos
            .iter()
            .map(|utxo| utxo.note.value)
            .collect::<Vec<_>>(),
        vec![uint!(4_U256), uint!(4_U256)]
    );
    assert_eq!(selections[1].chunks[0].utxos[0].note.value, uint!(9_U256));
}

#[test]
fn composite_same_token_selection_retries_multi_transaction_alternates() {
    let wallet = test_wallet();
    let token = Address::from([0x87; 20]);
    let recipient = Address::from([0x88; 20]);
    let utxos = vec![
        wallet_test_utxo(&wallet, token, 12, 0, 0),
        wallet_test_utxo(&wallet, token, 8, 1, 1),
        wallet_test_utxo(&wallet, token, 7, 2, 2),
    ];
    let legs = vec![
        CompositeUnshieldLeg {
            token_address: token,
            amount: uint!(15_U256),
            recipient: CompositeUnshieldRecipient::Public(recipient),
            role: CompositeUnshieldLegRole::Primary,
        },
        CompositeUnshieldLeg {
            token_address: token,
            amount: uint!(12_U256),
            recipient: CompositeUnshieldRecipient::Public(recipient),
            role: CompositeUnshieldLegRole::Other,
        },
    ];

    let (selections, _) = select_composite_leg_selections(&utxos, &legs, None, false, 0)
        .expect("same-token composite selection");

    assert_eq!(
        selections
            .iter()
            .map(|selection| selection.chunks.len())
            .sum::<usize>(),
        3
    );
    assert_eq!(selections[0].chunks[0].utxos[0].note.value, uint!(8_U256));
    assert_eq!(selections[0].chunks[1].utxos[0].note.value, uint!(7_U256));
    assert_eq!(selections[1].chunks[0].utxos[0].note.value, uint!(12_U256));
}

#[test]
fn composite_same_token_selection_retries_smaller_partial_tree_chunks() {
    let wallet = test_wallet();
    let token = Address::from([0x89; 20]);
    let recipient = Address::from([0x8a; 20]);
    let utxos = vec![
        wallet_test_utxo(&wallet, token, 13, 3, 30),
        wallet_test_utxo(&wallet, token, 12, 3, 31),
        wallet_test_utxo(&wallet, token, 8, 3, 32),
        wallet_test_utxo(&wallet, token, 8, 0, 0),
        wallet_test_utxo(&wallet, token, 14, 0, 1),
        wallet_test_utxo(&wallet, token, 5, 0, 2),
        wallet_test_utxo(&wallet, token, 5, 2, 20),
        wallet_test_utxo(&wallet, token, 12, 2, 21),
    ];
    let legs = vec![
        CompositeUnshieldLeg {
            token_address: token,
            amount: uint!(49_U256),
            recipient: CompositeUnshieldRecipient::Public(recipient),
            role: CompositeUnshieldLegRole::Primary,
        },
        CompositeUnshieldLeg {
            token_address: token,
            amount: uint!(28_U256),
            recipient: CompositeUnshieldRecipient::Public(recipient),
            role: CompositeUnshieldLegRole::Other,
        },
    ];

    let (selections, _) = select_composite_leg_selections(&utxos, &legs, None, false, 0)
        .expect("same-token composite selection");

    assert_eq!(
        selections
            .iter()
            .map(|selection| selection.chunks.len())
            .sum::<usize>(),
        6
    );
    assert_eq!(
        selections
            .iter()
            .map(|selection| selection.total)
            .collect::<Vec<_>>(),
        vec![uint!(49_U256), uint!(28_U256)]
    );
}

#[test]
fn composite_same_size_alternate_tree_candidate_keeps_plan_under_batch_limit() {
    let wallet = test_wallet();
    let token = Address::from([0x8b; 20]);
    let recipient = Address::from([0x8c; 20]);
    let mut utxos = vec![
        wallet_test_utxo(&wallet, token, 10, 0, 0),
        wallet_test_utxo(&wallet, token, 5, 0, 1),
        wallet_test_utxo(&wallet, token, 10, 1, 0),
    ];
    let mut legs = vec![
        CompositeUnshieldLeg {
            token_address: token,
            amount: uint!(10_U256),
            recipient: CompositeUnshieldRecipient::Public(recipient),
            role: CompositeUnshieldLegRole::Primary,
        },
        CompositeUnshieldLeg {
            token_address: token,
            amount: uint!(15_U256),
            recipient: CompositeUnshieldRecipient::Public(recipient),
            role: CompositeUnshieldLegRole::Other,
        },
    ];
    for index in 0..6 {
        let leg_token = Address::from([0x90 + u8::try_from(index).expect("test index"); 20]);
        utxos.push(wallet_test_utxo(
            &wallet,
            leg_token,
            1,
            2 + u32::try_from(index).expect("test index"),
            u64::try_from(index).expect("test index"),
        ));
        legs.push(CompositeUnshieldLeg {
            token_address: leg_token,
            amount: uint!(1_U256),
            recipient: CompositeUnshieldRecipient::Public(recipient),
            role: CompositeUnshieldLegRole::Other,
        });
    }
    let (selections, _) = select_composite_leg_selections(&utxos, &legs, None, false, 0)
        .expect("same-size alternate tree candidate selection");
    let second_leg_inputs = selections[1].chunks[0]
        .utxos
        .iter()
        .map(|utxo| (utxo.tree, utxo.note.value))
        .collect::<Vec<_>>();

    assert_eq!(
        selections
            .iter()
            .map(|selection| selection.chunks.len())
            .sum::<usize>(),
        MAX_BATCH_TRANSACTIONS
    );
    assert_eq!(selections[0].chunks[0].utxos[0].tree, 1);
    assert_eq!(
        second_leg_inputs,
        vec![(0, uint!(10_U256)), (0, uint!(5_U256))]
    );
}

#[tokio::test]
async fn composite_fee_matching_later_leg_emits_fee_transaction_first() {
    let wallet = test_wallet();
    let builder = test_transaction_builder();
    let token_a = Address::from([0x8d; 20]);
    let token_b = Address::from([0x8e; 20]);
    let recipient = Address::from([0x8f; 20]);
    let broadcaster = sample_address_data(0x90).address_data();
    let utxos = vec![
        wallet_test_utxo(&wallet, token_a, 10, 0, 0),
        wallet_test_utxo(&wallet, token_b, 12, 1, 0),
    ];
    let forest = forest_for_utxos(&utxos);
    let request = CompositeUnshieldRequest {
        adapter: None,
        legs: vec![
            CompositeUnshieldLeg {
                token_address: token_a,
                amount: uint!(10_U256),
                recipient: CompositeUnshieldRecipient::Public(recipient),
                role: CompositeUnshieldLegRole::Primary,
            },
            CompositeUnshieldLeg {
                token_address: token_b,
                amount: uint!(10_U256),
                recipient: CompositeUnshieldRecipient::Public(recipient),
                role: CompositeUnshieldLegRole::Other,
            },
        ],
        relay_actions: None,
        broadcaster_fee: Some(BroadcasterFeeOutput {
            recipient: broadcaster,
            token_address: token_b,
            amount: uint!(2_U256),
        }),
        min_gas_price: 0,
        verify_proof: false,
        spend_up_to: false,
    };

    let plan = builder
        .build_composite_unshield_plan_inner(
            &wallet.viewing,
            &wallet,
            &forest,
            &utxos,
            request,
            &MockTransactionProver,
        )
        .await
        .expect("later-leg fee composite plan");

    assert_eq!(plan.shape.transaction_count, 2);
    assert_eq!(plan.shape.input_count, 2);
    assert_eq!(plan.shape.private_output_count, 1);
    assert_eq!(plan.shape.public_output_count, 2);
    assert_eq!(plan.leg_metadata[1].transaction_indices, vec![0]);
    assert_eq!(plan.leg_metadata[0].transaction_indices, vec![1]);
    assert_eq!(plan.private_output_roles.len(), 1);
    assert_eq!(plan.private_output_roles[0].chunk_index, 0);
    assert_eq!(plan.private_output_roles[0].output_index, 0);
    assert_eq!(
        plan.private_output_roles[0].role,
        CompositePrivateOutputRoleKind::BroadcasterFee
    );
    assert_eq!(plan.private_output_roles[0].token_address, token_b);
    assert!(plan.broadcaster_fee_note.is_some());
}

#[tokio::test]
async fn composite_same_token_later_fee_emits_fee_transaction_first() {
    let wallet = test_wallet();
    let builder = test_transaction_builder();
    let token = Address::from([0x91; 20]);
    let recipient = Address::from([0x92; 20]);
    let broadcaster = sample_address_data(0x93).address_data();
    let utxos = vec![
        wallet_test_utxo(&wallet, token, 10, 0, 0),
        wallet_test_utxo(&wallet, token, 10, 0, 1),
    ];
    let forest = forest_for_utxos(&utxos);
    let request = CompositeUnshieldRequest {
        adapter: None,
        legs: vec![
            CompositeUnshieldLeg {
                token_address: token,
                amount: uint!(10_U256),
                recipient: CompositeUnshieldRecipient::Public(recipient),
                role: CompositeUnshieldLegRole::Primary,
            },
            CompositeUnshieldLeg {
                token_address: token,
                amount: uint!(5_U256),
                recipient: CompositeUnshieldRecipient::Public(recipient),
                role: CompositeUnshieldLegRole::Other,
            },
        ],
        relay_actions: None,
        broadcaster_fee: Some(BroadcasterFeeOutput {
            recipient: broadcaster,
            token_address: token,
            amount: uint!(5_U256),
        }),
        min_gas_price: 0,
        verify_proof: false,
        spend_up_to: false,
    };

    let plan = builder
        .build_composite_unshield_plan_inner(
            &wallet.viewing,
            &wallet,
            &forest,
            &utxos,
            request,
            &MockTransactionProver,
        )
        .await
        .expect("same-token later fee composite plan");

    assert_eq!(plan.shape.transaction_count, 2);
    assert_eq!(plan.shape.input_count, 2);
    assert_eq!(plan.shape.private_output_count, 1);
    assert_eq!(plan.shape.public_output_count, 2);
    assert_eq!(plan.leg_metadata[1].transaction_indices, vec![0]);
    assert_eq!(plan.leg_metadata[0].transaction_indices, vec![1]);
    assert_eq!(plan.private_output_roles.len(), 1);
    assert_eq!(plan.private_output_roles[0].chunk_index, 0);
    assert_eq!(plan.private_output_roles[0].output_index, 0);
    assert_eq!(
        plan.private_output_roles[0].role,
        CompositePrivateOutputRoleKind::BroadcasterFee
    );
    assert_eq!(plan.private_output_roles[0].token_address, token);
    assert!(plan.broadcaster_fee_note.is_some());
}
