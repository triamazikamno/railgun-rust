use super::*;
use crate::contracts::executor::AcrossPrivateDelivery;
use crate::contracts::weiroll::WeirollExecutor;
use alloy::primitives::{address, b256};
use alloy::signers::SignerSync;
use alloy::signers::local::PrivateKeySigner;

// cow-shed v2.1.0, the same on Ethereum, BNB Chain, Polygon, and Arbitrum
// One. Checked on 2026-10-06.
const FACTORY: Address = address!("0x0a654985c5856Ab562237286f36d55c0FF637213");
const IMPLEMENTATION: Address = address!("0xF0D586aB0017fDfE2ACf4AB008B3Ddb2CF50bB09");
const WEIROLL: Address = Address::repeat_byte(0x3e);
const OWNER: Address = Address::repeat_byte(0xb0);
const TOKEN: Address = Address::repeat_byte(0x70);

fn deposit() -> BalanceDeposit {
    BalanceDeposit {
        proxy: Address::repeat_byte(0x5e),
        math: Address::repeat_byte(0x3a),
        spoke_pool: Address::repeat_byte(0x5b),
        buy_amount: U256::from(10_000),
        destination_min: U256::from(9_900),
        depositor: OWNER,
        input_token: TOKEN,
        output_token: Address::repeat_byte(0x71),
        destination_chain_id: 42_161,
        exclusive_relayer: Address::ZERO,
        quote_timestamp: 1_700_000_000,
        fill_deadline: 1_700_003_600,
        exclusivity_parameter: 0,
        delivery: AcrossPrivateDelivery {
            handler: Address::repeat_byte(0x7e),
            destination_executor: Address::repeat_byte(0xe1),
            shield_multicall: Bytes::from_static(&[0xab; 37]),
            fallback: None,
        },
    }
}

/// The deposit hook batch of `deposit()` after `edit` changed it.
fn decode_edited(edit: impl FnOnce(&mut Vec<Call>)) -> Result<DepositHook, CowShedError> {
    let mut calls = deposit_hook_calls(WEIROLL, &deposit()).unwrap();
    edit(&mut calls);
    decode_deposit_hook_calls(&calls)
}

/// Rewrite the weiroll state of the script call in `calls`.
fn edit_script_state(calls: &mut [Call], edit: impl FnOnce(&mut Vec<Bytes>)) {
    let mut script = WeirollExecutor::executeCall::abi_decode(&calls[1].callData).unwrap();
    edit(&mut script.state);
    calls[1].callData = script.abi_encode().into();
}

#[test]
fn bindings_match_cow_shed_v2_1_0() {
    let call = transfer_call(TOKEN, OWNER, U256::ONE);
    assert_eq!(
        call.eip712_type_hash(),
        keccak256(
            "Call(address target,uint256 value,bytes callData,bool allowFailure,bool isDelegateCall)"
        )
    );
    let hooks = ExecuteHooks {
        calls: vec![call],
        nonce: B256::ZERO,
        deadline: U256::ZERO,
    };
    assert_eq!(
        hooks.eip712_type_hash(),
        keccak256(
            "ExecuteHooks(Call[] calls,bytes32 nonce,uint256 deadline)Call(address target,uint256 value,bytes callData,bool allowFailure,bool isDelegateCall)"
        )
    );
    assert_eq!(
        COWShedFactory::executeHooksCall::SELECTOR,
        keccak256(
            "executeHooks((address,uint256,bytes,bool,bool)[],bytes32,uint256,address,bytes)"
        )[..4]
    );
    assert_eq!(IERC20::transferCall::SELECTOR, hex!("a9059cbb"));

    // `keccak256(COWShedFactory.PROXY_CREATION_CODE())` and `proxyOf` of
    // the deployed factory.
    assert_eq!(
        keccak256(PROXY_CREATION_CODE),
        b256!("0x41b0551a89c786348707850c2b84a0c34dc75a24a17e98f2677250411bc037a2")
    );
    assert_eq!(
        proxy_address(
            FACTORY,
            IMPLEMENTATION,
            address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
        ),
        address!("0x38152bF904eb4865eb339159411C8A79D833e289")
    );
}

#[test]
fn deposit_hook_guards_the_balance_then_delegates_to_the_script() {
    let deposit = deposit();
    let calls = deposit_hook_calls(WEIROLL, &deposit).unwrap();
    let [guard, script] = calls.as_slice() else {
        panic!("expected two calls");
    };
    assert_eq!((guard.target, guard.value), (TOKEN, U256::ZERO));
    assert!(!guard.allowFailure && !guard.isDelegateCall);
    let transfer = IERC20::transferCall::abi_decode(&guard.callData).unwrap();
    assert_eq!(
        (transfer.to, transfer.amount),
        (deposit.proxy, deposit.buy_amount)
    );
    assert_eq!((script.target, script.value), (WEIROLL, U256::ZERO));
    assert!(!script.allowFailure && script.isDelegateCall);
    assert_eq!(script.callData, deposit.encode().unwrap());

    assert_eq!(
        decode_deposit_hook_calls(&calls).unwrap(),
        DepositHook {
            weiroll: WEIROLL,
            deposit,
        }
    );
}

#[test]
fn decode_deposit_hook_rejects_batches_that_could_move_funds_elsewhere() {
    // A guard below the script's buy amount lets a short fill through.
    assert!(matches!(
        decode_edited(|calls| {
            calls[0] = transfer_call(TOKEN, deposit().proxy, U256::from(9_999));
        }),
        Err(CowShedError::NotDepositHook(_))
    ));
    assert!(matches!(
        decode_edited(|calls| calls[1].isDelegateCall = false),
        Err(CowShedError::NotDepositHook(_))
    ));
    for call in [0, 1] {
        assert!(matches!(
            decode_edited(|calls| calls[call].allowFailure = true),
            Err(CowShedError::NotDepositHook(_))
        ));
    }
    // State element 13 is the message and 5 the deposit recipient.
    assert!(matches!(
        decode_edited(|calls| {
            edit_script_state(calls, |state| {
                // A 64-byte `bytes` value of zeros.
                let mut message = U256::from(64).to_be_bytes::<32>().to_vec();
                message.extend_from_slice(&[0; 64]);
                state[13] = message.into();
            });
        }),
        Err(CowShedError::Weiroll(
            WeirollError::NotPrivateDeliveryMessage
        ))
    ));
    assert!(matches!(
        decode_edited(|calls| {
            edit_script_state(calls, |state| {
                state[5] = Address::repeat_byte(0x99).into_word().to_vec().into();
            });
        }),
        Err(CowShedError::Weiroll(
            WeirollError::NotPrivateDeliveryMessage
        ))
    ));
}

#[test]
fn withdrawal_pays_only_the_owner() {
    let amount = U256::from(1_234);
    let calls = withdrawal_calls(TOKEN, OWNER, amount).unwrap();
    let [call] = calls.as_slice() else {
        panic!("expected one call");
    };
    assert_eq!((call.target, call.value), (TOKEN, U256::ZERO));
    assert!(!call.allowFailure && !call.isDelegateCall);
    let transfer = IERC20::transferCall::abi_decode(&call.callData).unwrap();
    assert_eq!((transfer.to, transfer.amount), (OWNER, amount));

    assert_eq!(
        decode_withdrawal_calls(&calls, OWNER).unwrap(),
        (TOKEN, amount)
    );
    assert!(matches!(
        decode_withdrawal_calls(&calls, Address::repeat_byte(0x99)),
        Err(CowShedError::NotWithdrawal)
    ));
    assert!(matches!(
        withdrawal_calls(TOKEN, OWNER, U256::ZERO),
        Err(CowShedError::ZeroAmount)
    ));
}

#[test]
fn execute_hooks_calldata_requires_the_owner_signature() {
    let signer = PrivateKeySigner::random();
    let owner = signer.address();
    let hooks = ExecuteHooks {
        calls: withdrawal_calls(TOKEN, owner, U256::from(1_234)).unwrap(),
        nonce: B256::repeat_byte(0x11),
        deadline: U256::from(1_700_003_600),
    };
    let proxy = proxy_address(FACTORY, IMPLEMENTATION, owner);
    let digest = execute_hooks_digest(&hooks, 1, proxy);
    let signature = signer.sign_hash_sync(&digest).unwrap();

    let calldata =
        execute_hooks_calldata(hooks.clone(), owner, &signature, 1, FACTORY, IMPLEMENTATION)
            .unwrap();
    let call = COWShedFactory::executeHooksCall::abi_decode(&calldata).unwrap();
    assert_eq!(call.calls, hooks.calls);
    assert_eq!((call.nonce, call.deadline), (hooks.nonce, hooks.deadline));
    assert_eq!(call.user, owner);
    assert_eq!(call.signature.len(), 65);
    assert!(matches!(call.signature[64], 27 | 28));
    assert_eq!(call.signature[..], signature.as_bytes());

    let other = PrivateKeySigner::random().sign_hash_sync(&digest).unwrap();
    assert!(matches!(
        execute_hooks_calldata(hooks.clone(), owner, &other, 1, FACTORY, IMPLEMENTATION),
        Err(CowShedError::SignerNotOwner)
    ));
    // A signature for another chain's proxy domain does not carry over.
    assert!(matches!(
        execute_hooks_calldata(hooks, owner, &signature, 137, FACTORY, IMPLEMENTATION),
        Err(CowShedError::SignerNotOwner)
    ));
}
