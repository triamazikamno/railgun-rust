use super::*;

fn swap_pre_hook_request(
    context: ExecutorContext,
    calls: Vec<broadcaster_core::contracts::railgun::Call>,
    sell_token: Address,
    amount: u64,
) -> MixedPrivateActionRequest {
    MixedPrivateActionRequest {
        adapter: Some(CompositeAdapter::Executor(context)),
        executor_calls: calls,
        private_sends: Vec::new(),
        public_unshields: vec![CompositeUnshieldLeg {
            token_address: sell_token,
            amount: U256::from(amount),
            recipient: CompositeUnshieldRecipient::RelayAdapt,
            role: CompositeUnshieldLegRole::Primary,
        }],
        relay_actions: None,
        min_gas_price: 0,
        verify_proof: false,
        spend_up_to: false,
        rebuild: None,
    }
}

#[tokio::test]
async fn swap_app_data_estimate_matches_signed_hook_documents() {
    use broadcaster_core::contracts::cow::{AppData, AppDataHook, OrderUid};
    use broadcaster_core::contracts::executor::{
        ExecutorAction, guarded_shield_calls, post_hook_signing_hash, signed_post_hook_calldata,
    };
    use broadcaster_core::contracts::railgun::{
        CommitmentPreimage, ShieldCiphertext, ShieldRequest, TokenData,
    };

    use crate::tx::{
        SwapAmountCheck, SwapAppDataTemplate, SwapPostHookTemplate, estimate_swap_app_data_len,
    };

    let wallet = test_wallet();
    let builder = test_transaction_builder();
    let signer = PrivateKeySigner::from_bytes(&FixedBytes::from([0x61; 32])).unwrap();
    let context = ExecutorContext {
        chain_id: builder.chain_id,
        executor: signer.address(),
        delegate: Address::repeat_byte(0x62),
        execution_nonce: U256::from(7),
    };
    let sell_token = Address::repeat_byte(0x63);
    let buy_token = Address::repeat_byte(0x64);
    let post_hook_calls = guarded_shield_calls(
        context.executor,
        buy_token,
        U256::from(1_000_000),
        ShieldRequest {
            preimage: CommitmentPreimage {
                npk: FixedBytes::repeat_byte(0x65),
                token: TokenData::erc20(buy_token),
                value: Uint::ZERO,
            },
            ciphertext: ShieldCiphertext {
                encryptedBundle: [FixedBytes::repeat_byte(0x66); 3],
                shieldKey: FixedBytes::repeat_byte(0x67),
            },
        },
    )
    .unwrap();
    let post_nonce = context.execution_nonce + U256::ONE;
    let post_signature = signer
        .sign_hash_sync(&post_hook_signing_hash(
            &post_hook_calls,
            post_nonce,
            context.chain_id,
            context.executor,
        ))
        .unwrap();
    let post_hook = signed_post_hook_calldata(
        post_hook_calls.clone(),
        post_nonce,
        context.chain_id,
        context.executor,
        &post_signature,
    )
    .unwrap();
    let template = SwapAppDataTemplate {
        app_code: "railgun".to_owned(),
        pre_hook_gas_limit: 1_500_000,
        post_hook: Some(SwapPostHookTemplate {
            calls: post_hook_calls,
            gas_limit: 400_000,
        }),
    };
    let pre_hook_only = SwapAppDataTemplate {
        post_hook: None,
        ..template.clone()
    };

    // Notes of 5 per tree, the sell amount, whether a retry invalidates an
    // earlier order, and the expected transaction count. Each case leaves
    // change in its last transaction.
    let cases: [(&[u64], u64, bool, usize); 3] = [
        (&[3], 11, false, 1),
        (&[2, 3, 1], 28, true, 3),
        (&[1, 2, 1, 3, 1, 2, 1, 2], 63, true, MAX_BATCH_TRANSACTIONS),
    ];
    for (notes_per_tree, amount, invalidate, transaction_count) in cases {
        let mut utxos = Vec::new();
        for (tree, count) in (0_u32..).zip(notes_per_tree) {
            for _ in 0..*count {
                let position = utxos.len() as u64;
                utxos.push(wallet_test_utxo(&wallet, sell_token, 5, tree, position));
            }
        }
        let forest = forest_for_utxos(&utxos);
        let mut calls = vec![
            ExecutorAction::Deadline {
                target: Address::repeat_byte(0x68),
                deadline: 1_900_000_000,
            }
            .call(context.executor)
            .unwrap(),
            ExecutorAction::Approve {
                token: sell_token,
                spender: Address::repeat_byte(0x69),
                amount: U256::from(amount),
            }
            .call(context.executor)
            .unwrap(),
        ];
        if invalidate {
            calls.push(
                ExecutorAction::InvalidateOrder {
                    settlement: Address::repeat_byte(0x6a),
                    order_uid: OrderUid::new(
                        FixedBytes::repeat_byte(0x6b),
                        context.executor,
                        u32::MAX,
                    ),
                }
                .call(context.executor)
                .unwrap(),
            );
        }
        let request = swap_pre_hook_request(context, calls, sell_token, amount);
        let pre_hook_calls = request.executor_calls.clone();

        let SwapAmountCheck::Fits(size) = builder
            .check_swap_pre_hook(&utxos, &request, &template, usize::MAX)
            .unwrap()
        else {
            panic!("an unbounded budget fits");
        };
        assert_eq!(size.preview.transactions.len(), transaction_count);
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
        assert_eq!(plan.selected_inputs, size.preview.selected_inputs);
        let digest = context.signing_hash(&plan.call).unwrap();
        let pre_hook = context
            .authorize_call(&plan.call, signer.sign_hash_sync(&digest).unwrap())
            .unwrap();
        let pre_hooks = vec![AppDataHook {
            call_data: pre_hook.data,
            gas_limit: template.pre_hook_gas_limit,
            target: context.executor,
        }];
        let document = AppData::hooks(
            template.app_code.clone(),
            pre_hooks.clone(),
            vec![AppDataHook {
                call_data: post_hook.clone(),
                gas_limit: 400_000,
                target: context.executor,
            }],
        )
        .encode()
        .unwrap()
        .document;
        assert_eq!(
            size.app_data_len,
            document.len(),
            "{transaction_count} transactions"
        );

        let pre_hook_only_document = AppData::hooks(template.app_code.clone(), pre_hooks, vec![])
            .encode()
            .unwrap()
            .document;
        assert_eq!(
            estimate_swap_app_data_len(
                &pre_hook_only,
                context.executor,
                &pre_hook_calls,
                &size.preview.transactions,
            )
            .unwrap(),
            pre_hook_only_document.len(),
            "{transaction_count} transactions without a post-hook"
        );
    }
}

#[test]
fn swap_max_amount_is_capped_by_app_data_budget_and_batch_limit() {
    use broadcaster_core::contracts::railgun::Call;

    use crate::tx::{
        SwapAmountCheck, SwapAppDataTemplate, SwapPostHookTemplate, TransactionShape,
        estimate_swap_app_data_len,
    };

    let wallet = test_wallet();
    let builder = test_transaction_builder();
    let context = ExecutorContext {
        chain_id: builder.chain_id,
        executor: Address::repeat_byte(0x70),
        delegate: Address::repeat_byte(0x71),
        execution_nonce: U256::ZERO,
    };
    let sell_token = Address::repeat_byte(0x72);
    let calls = vec![Call {
        to: Address::repeat_byte(0x73),
        value: U256::ZERO,
        data: Bytes::from(vec![0x01; 100]),
    }];
    let template = SwapAppDataTemplate {
        app_code: "railgun".to_owned(),
        pre_hook_gas_limit: 1_000_000,
        post_hook: Some(SwapPostHookTemplate {
            calls: vec![Call {
                to: context.executor,
                value: U256::ZERO,
                data: Bytes::from(vec![0x02; 300]),
            }],
            gas_limit: 300_000,
        }),
    };
    let request = |amount| swap_pre_hook_request(context, calls.clone(), sell_token, amount);
    let shape = |input_count| TransactionShape {
        input_count,
        output_count: 1,
        has_unshield: true,
    };

    // Three trees of four notes of 10. The budget fits a whole first
    // transaction and two inputs of a second one.
    let mut utxos = Vec::new();
    for tree in 0_u32..3 {
        for index in 0..4 {
            utxos.push(wallet_test_utxo(
                &wallet,
                sell_token,
                10,
                tree,
                u64::from(tree * 4 + index),
            ));
        }
    }
    let budget =
        estimate_swap_app_data_len(&template, context.executor, &calls, &[shape(4), shape(2)])
            .unwrap();
    let max = builder
        .max_swap_pre_hook(&utxos, &request(1), &template, budget)
        .unwrap();
    assert_eq!(max.amount, U256::from(60));
    assert_eq!(max.preview.transactions, vec![shape(4), shape(2)]);
    assert_eq!(max.app_data_len, budget);
    assert_eq!(
        builder
            .check_swap_pre_hook(&utxos, &request(60), &template, budget)
            .unwrap(),
        SwapAmountCheck::Fits(max.clone())
    );
    // One more unit needs a third input in the second transaction.
    assert_eq!(
        builder
            .check_swap_pre_hook(&utxos, &request(61), &template, budget)
            .unwrap(),
        SwapAmountCheck::TooLarge { largest: max }
    );
    // The offer stays below the entered amount: 59 would otherwise offer 60.
    let SwapAmountCheck::TooLarge { largest } = builder
        .check_swap_pre_hook(&utxos, &request(59), &template, budget)
        .unwrap()
    else {
        panic!("59 needs a change output over the budget");
    };
    assert_eq!(largest.amount, U256::from(50));
    assert_eq!(largest.preview.transactions, vec![shape(4), shape(1)]);
    assert!(largest.app_data_len <= budget);
    // A whole transaction that fits the budget but not the entered amount
    // falls back to fewer of its inputs.
    let one_transaction =
        estimate_swap_app_data_len(&template, context.executor, &calls, &[shape(4)]).unwrap();
    let SwapAmountCheck::TooLarge { largest } = builder
        .check_swap_pre_hook(&utxos, &request(35), &template, one_transaction)
        .unwrap()
    else {
        panic!("35 needs a change output over the budget");
    };
    assert_eq!(largest.amount, U256::from(30));
    assert_eq!(largest.preview.transactions, vec![shape(3)]);
    let one_input =
        estimate_swap_app_data_len(&template, context.executor, &calls, &[shape(1)]).unwrap();
    assert!(matches!(
        builder.check_swap_pre_hook(&utxos, &request(61), &template, one_input - 1),
        Err(BuildError::SwapAppDataTooLarge { len, budget })
            if len == one_input && budget == one_input - 1
    ));

    // Nine single-note trees under an unbounded budget stop at eight transactions.
    let utxos = (0_u32..9)
        .map(|tree| wallet_test_utxo(&wallet, sell_token, 10, tree, u64::from(tree)))
        .collect::<Vec<_>>();
    let SwapAmountCheck::TooLarge { largest } = builder
        .check_swap_pre_hook(&utxos, &request(90), &template, usize::MAX)
        .unwrap()
    else {
        panic!("nine transactions exceed the batch limit");
    };
    assert_eq!(largest.amount, U256::from(80));
    assert_eq!(
        largest.preview.transactions,
        vec![shape(1); MAX_BATCH_TRANSACTIONS]
    );

    // 7125 is below the 7130 balance but unselectable: after seven 1000
    // notes, 125 needs all 13 notes of 10 plus change. The offer stays below
    // the entered amount instead of offering the full 7130.
    let mut utxos = (0..13)
        .map(|position| wallet_test_utxo(&wallet, sell_token, 10, 0, position))
        .collect::<Vec<_>>();
    utxos.extend(
        (1_u32..8)
            .map(|tree| wallet_test_utxo(&wallet, sell_token, 1000, tree, u64::from(tree) + 12)),
    );
    let SwapAmountCheck::TooLarge { largest } = builder
        .check_swap_pre_hook(&utxos, &request(7125), &template, usize::MAX)
        .unwrap()
    else {
        panic!("7125 is not selectable");
    };
    assert_eq!(largest.amount, U256::from(7120));
    assert_eq!(largest.preview.transactions.len(), MAX_BATCH_TRANSACTIONS);

    // Thirteen of sixty equal notes in one tree still yield an offer. The
    // budget fits one transaction of twelve inputs.
    let utxos = (0..60)
        .map(|position| wallet_test_utxo(&wallet, sell_token, 1, 0, position))
        .collect::<Vec<_>>();
    let twelve_inputs =
        estimate_swap_app_data_len(&template, context.executor, &calls, &[shape(12)]).unwrap();
    let SwapAmountCheck::TooLarge { largest } = builder
        .check_swap_pre_hook(&utxos, &request(13), &template, twelve_inputs)
        .unwrap()
    else {
        panic!("thirteen inputs exceed a twelve-input budget");
    };
    assert_eq!(largest.amount, U256::from(12));
    assert_eq!(largest.preview.transactions, vec![shape(12)]);
}
