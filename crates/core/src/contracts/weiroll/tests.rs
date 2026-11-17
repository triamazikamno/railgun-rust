use super::*;
use alloy::hex;

fn deposit() -> BalanceDeposit {
    BalanceDeposit {
        proxy: Address::repeat_byte(0x5e),
        math: Address::repeat_byte(0x3a),
        spoke_pool: Address::repeat_byte(0x5b),
        buy_amount: U256::from(10_000),
        destination_min: U256::from(9_900),
        depositor: Address::repeat_byte(0xb0),
        input_token: Address::repeat_byte(0x70),
        output_token: Address::repeat_byte(0x71),
        destination_chain_id: 42_161,
        exclusive_relayer: Address::repeat_byte(0xe7),
        quote_timestamp: 1_700_000_000,
        fill_deadline: 1_700_003_600,
        exclusivity_parameter: 30,
        delivery: AcrossPrivateDelivery {
            handler: Address::repeat_byte(0x7e),
            destination_executor: Address::repeat_byte(0xe1),
            shield_multicall: Bytes::from_static(&[0xab; 37]),
            fallback: Some(Address::repeat_byte(0xfb)),
        },
    }
}

fn script(deposit: &BalanceDeposit) -> WeirollExecutor::executeCall {
    WeirollExecutor::executeCall::abi_decode(&deposit.encode().unwrap()).unwrap()
}

/// Decode the script of `deposit()` after `edit` changed it.
fn decode_edited(
    edit: impl FnOnce(&mut WeirollExecutor::executeCall),
) -> Result<BalanceDeposit, WeirollError> {
    let mut script = script(&deposit());
    edit(&mut script);
    BalanceDeposit::decode(&script.abi_encode())
}

#[test]
fn script_reads_the_balance_scales_it_approves_and_deposits() {
    let deposit = deposit();
    let calldata = deposit.encode().unwrap();
    assert_eq!(BalanceDeposit::decode(&calldata).unwrap(), deposit);
    let without_fallback = BalanceDeposit {
        delivery: AcrossPrivateDelivery {
            fallback: None,
            ..deposit.delivery.clone()
        },
        ..deposit
    };
    assert_eq!(
        BalanceDeposit::decode(&without_fallback.encode().unwrap()).unwrap(),
        without_fallback
    );

    // Read the command words by the VM's layout, not through `commands`.
    let WeirollExecutor::executeCall { commands, state } = script(&deposit);
    let selector = |command: usize| &commands[command][..4];
    let flags = |command: usize| commands[command][4];
    let inputs = |command: usize| &commands[command][5..11];
    let output = |command: usize| commands[command][11];
    let target = |command: usize| Address::from_slice(&commands[command][12..]);
    let slot = |index: u8| &state[usize::from(index)][..];
    let address_word = |address: Address| address.into_word().0;
    let uint_word = |value: u64| U256::from(value).to_be_bytes::<32>();

    assert_eq!(commands.len(), 5);
    assert_eq!(state.len(), 16);

    // balance = input_token.balanceOf(proxy)
    assert_eq!(selector(0), hex!("70a08231"));
    assert_eq!(flags(0), 0x02);
    assert_eq!(target(0), deposit.input_token);
    assert_eq!(slot(inputs(0)[0]), address_word(deposit.proxy));
    assert_eq!(inputs(0)[1..], [0xff_u8; 5]);
    let balance = output(0);
    assert_eq!(slot(balance), [] as [u8; 0]);

    // output = math.scale(balance, destination_min, buy_amount)
    assert_eq!(selector(1), hex!("ca939f26"));
    assert_eq!(flags(1), 0x01);
    assert_eq!(target(1), deposit.math);
    assert_eq!(inputs(1)[0], balance);
    assert_eq!(slot(inputs(1)[1]), uint_word(9_900));
    assert_eq!(slot(inputs(1)[2]), uint_word(10_000));
    assert_eq!(inputs(1)[3..], [0xff_u8; 3]);
    let scaled = output(1);
    assert_ne!(scaled, balance);
    assert_eq!(slot(scaled), [] as [u8; 0]);

    // input_token.approve(spoke_pool, balance)
    assert_eq!(selector(2), hex!("095ea7b3"));
    assert_eq!(flags(2), 0x01);
    assert_eq!(target(2), deposit.input_token);
    assert_eq!(slot(inputs(2)[0]), address_word(deposit.spoke_pool));
    assert_eq!(inputs(2)[1], balance);
    assert_eq!(inputs(2)[2..], [0xff_u8; 4]);
    assert_eq!(output(2), 0xff);

    // spoke_pool.depositV3(...), extended: its indices are the next word.
    assert_eq!(selector(3), hex!("7b939232"));
    assert_eq!(flags(3), 0x01 | 0x40);
    assert_eq!(target(3), deposit.spoke_pool);
    assert_eq!(inputs(3), [0_u8; 6]);
    assert_eq!(output(3), 0xff);
    let indices = commands[4].0;
    assert_eq!(indices[12..], [0xff_u8; 20]);
    let static_arguments = [
        (0, address_word(deposit.depositor)),
        (1, address_word(deposit.delivery.handler)),
        (2, address_word(deposit.input_token)),
        (3, address_word(deposit.output_token)),
        (6, uint_word(42_161)),
        (7, address_word(deposit.exclusive_relayer)),
        (8, uint_word(1_700_000_000)),
        (9, uint_word(1_700_003_600)),
        (10, uint_word(30)),
    ];
    for (argument, word) in static_arguments {
        assert_eq!(slot(indices[argument]), word, "argument {argument}");
    }
    assert_eq!((indices[4], indices[5]), (balance, scaled));
    assert_eq!(indices[11] & 0x80, 0x80);
    let message = private_delivery_message(
        deposit.delivery.handler,
        deposit.output_token,
        deposit.delivery.destination_executor,
        deposit.delivery.shield_multicall.clone(),
        deposit.delivery.fallback,
    );
    let element = slot(indices[11] & 0x7f);
    assert_eq!(element[..32], U256::from(message.len()).to_be_bytes::<32>());
    assert_eq!(element[32..32 + message.len()], message[..]);
    assert_eq!(element.len() % 32, 0);
    assert!(element.len() - 32 - message.len() < 32);
    assert!(element[32 + message.len()..].iter().all(|byte| *byte == 0));
}

#[test]
fn decode_rejects_scripts_encode_would_not_emit() {
    assert_eq!(
        decode_edited(|script| script.commands.push(B256::ZERO)),
        Err(WeirollError::CommandCount(6))
    );
    // `approve` on another token.
    assert_eq!(
        decode_edited(|script| {
            script.commands[2].0[12..].copy_from_slice(&[0x99; 20]);
        }),
        Err(WeirollError::Command(2))
    );
    // The deposit names a recipient the message does not drain from.
    assert_eq!(
        decode_edited(|script| {
            script.state[usize::from(HANDLER)] = address_element(Address::repeat_byte(0x99));
        }),
        Err(WeirollError::NotPrivateDeliveryMessage)
    );
    assert_eq!(
        decode_edited(|script| {
            let message = bytes_element_data(&script.state[usize::from(MESSAGE)]).unwrap();
            let mut instructions = MulticallHandler::Instructions::abi_decode(message).unwrap();
            instructions.calls.push(MulticallHandler::Call {
                target: Address::repeat_byte(0x99),
                callData: Bytes::new(),
                value: U256::ZERO,
            });
            script.state[usize::from(MESSAGE)] = bytes_element(&instructions.abi_encode());
        }),
        Err(WeirollError::NotPrivateDeliveryMessage)
    );
    for index in [BALANCE, OUTPUT] {
        assert_eq!(
            decode_edited(|script| {
                script.state[usize::from(index)] = uint_element(U256::ONE);
            }),
            Err(WeirollError::StateElement(usize::from(index)))
        );
    }
}

#[test]
fn encode_rejects_a_zero_buy_amount() {
    let deposit = BalanceDeposit {
        buy_amount: U256::ZERO,
        ..deposit()
    };
    assert_eq!(deposit.encode(), Err(WeirollError::ZeroBuyAmount));
}
