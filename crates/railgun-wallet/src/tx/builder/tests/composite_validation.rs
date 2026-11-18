use super::*;

#[tokio::test]
async fn composite_unshield_rejects_empty_requests() {
    let wallet = test_wallet();
    let builder = test_transaction_builder();
    let request = CompositeUnshieldRequest {
        adapter: None,
        legs: Vec::new(),
        relay_actions: None,
        broadcaster_fee: None,
        min_gas_price: 0,
        verify_proof: false,
        spend_up_to: false,
    };

    let error = builder
        .build_composite_unshield_plan_inner(
            &wallet.viewing,
            &wallet,
            &MerkleForest::new(),
            &[],
            request,
            &MockTransactionProver,
        )
        .await
        .expect_err("empty composite request should fail");

    assert!(matches!(error, BuildError::EmptyCompositeUnshieldRequest));
}

#[tokio::test]
async fn composite_unshield_rejects_relay_adapt_leg_without_actions() {
    let wallet = test_wallet();
    let builder = test_transaction_builder();
    let request = CompositeUnshieldRequest {
        adapter: Some(CompositeAdapter::RelayAdapt(TEST_RELAY_ADAPT)),
        legs: vec![CompositeUnshieldLeg {
            token_address: Address::from([0x83; 20]),
            amount: uint!(1_U256),
            recipient: CompositeUnshieldRecipient::RelayAdapt,
            role: CompositeUnshieldLegRole::NativeTopUp,
        }],
        relay_actions: None,
        broadcaster_fee: None,
        min_gas_price: 0,
        verify_proof: false,
        spend_up_to: false,
    };

    let error = builder
        .build_composite_unshield_plan_inner(
            &wallet.viewing,
            &wallet,
            &MerkleForest::new(),
            &[],
            request,
            &MockTransactionProver,
        )
        .await
        .expect_err("missing RelayAdapt actions should fail");

    assert!(matches!(error, BuildError::MissingCompositeRelayActions));
}

#[tokio::test]
async fn composite_and_mixed_reject_mismatched_adapter_before_signing() {
    let wallet = test_wallet();
    let builder = test_transaction_builder();
    let token = Address::from([0x84; 20]);
    let recipient = Address::from([0x85; 20]);
    let utxos = vec![wallet_test_utxo(&wallet, token, 10, 0, 0)];
    let forest = forest_for_utxos(&utxos);
    let signer = MockSpendSigner {
        signed_msg: Cell::new(None),
    };
    let prover = RecordingTransactionProver::default();
    let relay_leg = CompositeUnshieldLeg {
        token_address: token,
        amount: uint!(5_U256),
        recipient: CompositeUnshieldRecipient::RelayAdapt,
        role: CompositeUnshieldLegRole::NativeTopUp,
    };
    let direct_leg = CompositeUnshieldLeg {
        recipient: CompositeUnshieldRecipient::Public(recipient),
        role: CompositeUnshieldLegRole::Primary,
        ..relay_leg
    };
    let relay_actions = CompositeRelayActions {
        min_gas_limit: U256::ZERO,
        calls: vec![CompositeRelayAction::Transfer {
            token: CompositeRelayActionToken::Erc20(token),
            recipient,
            amount: uint!(5_U256),
        }],
    };
    let relay_adapt = Some(CompositeAdapter::RelayAdapt(TEST_RELAY_ADAPT));

    for (leg, adapter) in [(relay_leg, None), (direct_leg, relay_adapt)] {
        let uses_relay = leg.recipient.uses_relay_adapt();
        let actions = uses_relay.then(|| relay_actions.clone());
        let composite = CompositeUnshieldRequest {
            adapter,
            legs: vec![leg],
            relay_actions: actions.clone(),
            broadcaster_fee: None,
            min_gas_price: 0,
            verify_proof: false,
            spend_up_to: false,
        };
        let mixed = MixedPrivateActionRequest {
            adapter,
            executor_calls: Vec::new(),
            private_sends: Vec::new(),
            public_unshields: vec![leg],
            relay_actions: actions,
            min_gas_price: 0,
            verify_proof: false,
            spend_up_to: false,
            rebuild: None,
        };
        let composite_error = builder
            .build_composite_unshield_plan_inner(
                &wallet.viewing,
                &signer,
                &forest,
                &utxos,
                composite,
                &prover,
            )
            .await
            .expect_err("mismatched composite adapter");
        let mixed_error = builder
            .build_mixed_private_action_plan_inner(
                &wallet.viewing,
                &signer,
                &forest,
                &utxos,
                mixed,
                &prover,
            )
            .await
            .expect_err("mismatched mixed adapter");
        for error in [composite_error, mixed_error] {
            assert!(matches!(
                (uses_relay, error),
                (true, BuildError::MissingCompositeAdapter) | (false, BuildError::UnusedRelayAdapt)
            ));
        }
    }
    assert!(signer.signed_msg.get().is_none());
    assert_eq!(prover.bound_params_hashes(), [] as [U256; 0]);
}

#[tokio::test]
async fn composite_unshield_rejects_relay_adapt_leg_with_empty_actions() {
    let wallet = test_wallet();
    let builder = test_transaction_builder();
    let request = CompositeUnshieldRequest {
        adapter: Some(CompositeAdapter::RelayAdapt(TEST_RELAY_ADAPT)),
        legs: vec![CompositeUnshieldLeg {
            token_address: Address::from([0x84; 20]),
            amount: uint!(1_U256),
            recipient: CompositeUnshieldRecipient::RelayAdapt,
            role: CompositeUnshieldLegRole::NativeTopUp,
        }],
        relay_actions: Some(CompositeRelayActions {
            min_gas_limit: U256::ZERO,
            calls: Vec::new(),
        }),
        broadcaster_fee: None,
        min_gas_price: 0,
        verify_proof: false,
        spend_up_to: false,
    };

    let error = builder
        .build_composite_unshield_plan_inner(
            &wallet.viewing,
            &wallet,
            &MerkleForest::new(),
            &[],
            request,
            &MockTransactionProver,
        )
        .await
        .expect_err("empty RelayAdapt actions should fail");

    assert!(matches!(error, BuildError::MissingCompositeRelayActions));
}

#[tokio::test]
async fn composite_unshield_rejects_zero_amount_relay_actions() {
    let wallet = test_wallet();
    let builder = test_transaction_builder();
    let token = Address::from([0x81; 20]);
    let utxos = vec![wallet_test_utxo(&wallet, token, 1, 0, 0)];
    let forest = forest_for_utxos(&utxos);
    let request = CompositeUnshieldRequest {
        adapter: Some(CompositeAdapter::RelayAdapt(TEST_RELAY_ADAPT)),
        legs: vec![CompositeUnshieldLeg {
            token_address: token,
            amount: uint!(1_U256),
            recipient: CompositeUnshieldRecipient::RelayAdapt,
            role: CompositeUnshieldLegRole::NativeTopUp,
        }],
        relay_actions: Some(CompositeRelayActions {
            min_gas_limit: U256::ZERO,
            calls: vec![CompositeRelayAction::UnwrapBase { amount: U256::ZERO }],
        }),
        broadcaster_fee: None,
        min_gas_price: 0,
        verify_proof: false,
        spend_up_to: false,
    };

    let error = builder
        .build_composite_unshield_plan_inner(
            &wallet.viewing,
            &wallet,
            &forest,
            &utxos,
            request,
            &MockTransactionProver,
        )
        .await
        .expect_err("zero-amount action should fail");

    assert!(matches!(error, BuildError::InvalidRelayAdaptActionAmount));
}

#[tokio::test]
async fn composite_unshield_enforces_eight_transaction_batch_limit() {
    let wallet = test_wallet();
    let builder = test_transaction_builder();
    let utxos = (0..9)
        .map(|index| {
            wallet_test_utxo(
                &wallet,
                Address::from([u8::try_from(index).expect("test index") + 1; 20]),
                1,
                0,
                index,
            )
        })
        .collect::<Vec<_>>();
    let forest = forest_for_utxos(&utxos);
    let request = CompositeUnshieldRequest {
        adapter: None,
        legs: (0_u8..9)
            .map(|index| CompositeUnshieldLeg {
                token_address: Address::from([index + 1; 20]),
                amount: uint!(1_U256),
                recipient: CompositeUnshieldRecipient::Public(Address::from([0x82; 20])),
                role: CompositeUnshieldLegRole::Other,
            })
            .collect(),
        relay_actions: None,
        broadcaster_fee: None,
        min_gas_price: 0,
        verify_proof: false,
        spend_up_to: false,
    };

    let error = builder
        .build_composite_unshield_plan_inner(
            &wallet.viewing,
            &wallet,
            &forest,
            &utxos,
            request,
            &MockTransactionProver,
        )
        .await
        .expect_err("ninth transaction should fail");

    assert!(matches!(
        error,
        BuildError::TooManyBatchTransactions {
            requested: 9,
            max: 8
        }
    ));
}
