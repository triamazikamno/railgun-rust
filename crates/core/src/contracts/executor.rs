//! `RelayAdapt7702` owner authorization for the nonce-bearing execution profile.
//!
//! The EIP-712 verifying contract is the executing EOA, not its code delegate.
//! Execution and multicall consume the same contract storage nonce. Ethereum
//! account nonces and delegation authorizations are separate from this nonce.

use alloy::primitives::{Address, B256, Bytes, Signature, U256, keccak256};
use alloy::sol;
use alloy::sol_types::{Eip712Domain, SolCall, SolStruct, SolValue, eip712_domain};
use thiserror::Error;

use super::across::{SpokePool, private_delivery_message};
use super::cow::{GPv2Settlement, OrderUid};
use super::railgun::{
    Call, RelayAdapt7702, RelayAdapt7702ActionData, ShieldRequest, TokenTransfer, Transaction,
    approveCall, shieldCall, transferCall,
};

/// Storage layout of the nonce-bearing profile at contract revision
/// `1ea5e472867df1a14975a1ee5bf43dac21b89bde`: `nonce` is its first mutable field.
/// Read this slot at the executing EOA to retain nonce state after revocation.
/// It does not describe arbitrary replacement delegates or their storage layouts.
///
/// Wallet-side recovery relies on the following behavior of that revision under
/// EIP-7702. It was checked once on a local Prague chain and is not re-tested
/// here, since the contract is accepted as is and not maintained in this repository.
///
/// - `execute` and `multicall` consume the same storage nonce, so a signed
///   multicall at nonce N invalidates any issued `execute` payload at nonce N.
/// - Delegation installs even when the execution in the same transaction
///   reverts. The account nonce advances, the storage nonce does not.
/// - An authorization with a stale account nonce is skipped silently. The
///   transaction succeeds, no code is installed, and nothing executes.
/// - Revoking the delegation and reinstalling this delegate leaves the storage
///   nonce in place, so consumed payloads never become replayable.
/// - Ordinary value transfers to or from the delegated account do not touch
///   the storage nonce.
pub const EXECUTION_NONCE_STORAGE_SLOT: U256 = U256::ZERO;

sol! {
    struct Execute { bytes32 payloadHash; }
    struct Multicall { bytes32 payloadHash; }

    // Uniswap `SwapRouter02` reverts this call once `block.timestamp > deadline`.
    interface DeadlineMulticall {
        function multicall(uint256 deadline, bytes[] data) payable returns (bytes[] results);
    }
}

/// Railgun `TokenType.ERC20`.
const ERC20_TOKEN_TYPE: u8 = 0;

const fn domain(chain_id: u64, executor: Address) -> Eip712Domain {
    eip712_domain! {
        name: "RelayAdapt7702",
        version: "1",
        chain_id: chain_id,
        verifying_contract: executor,
    }
}

#[must_use]
pub fn execute_payload_hash(
    transactions: &[Transaction],
    action_data: &RelayAdapt7702ActionData,
    nonce: U256,
) -> B256 {
    keccak256((transactions, action_data.clone(), nonce).abi_encode_params())
}

#[must_use]
pub fn execute_signing_hash(
    transactions: &[Transaction],
    action_data: &RelayAdapt7702ActionData,
    nonce: U256,
    chain_id: u64,
    executor: Address,
) -> B256 {
    Execute {
        payloadHash: execute_payload_hash(transactions, action_data, nonce),
    }
    .eip712_signing_hash(&domain(chain_id, executor))
}

#[must_use]
pub fn multicall_payload_hash(require_success: bool, calls: &[Call], nonce: U256) -> B256 {
    keccak256((require_success, calls, nonce).abi_encode_params())
}

#[must_use]
pub fn multicall_signing_hash(
    require_success: bool,
    calls: &[Call],
    nonce: U256,
    chain_id: u64,
    executor: Address,
) -> B256 {
    Multicall {
        payloadHash: multicall_payload_hash(require_success, calls, nonce),
    }
    .eip712_signing_hash(&domain(chain_id, executor))
}

/// Check an execution or multicall signature against its expected EOA owner.
#[must_use]
pub fn is_executor_signature(
    signature: &Signature,
    signing_hash: &B256,
    executor: Address,
) -> bool {
    // Match OpenZeppelin ECDSA's low-s requirement in the accepted contract.
    signature.normalize_s().is_none()
        && signature
            .recover_address_from_prehash(signing_hash)
            .is_ok_and(|recovered| recovered == executor)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ExecutorActionError {
    #[error("self-called transfer amount must be nonzero; the helper treats 0 as the full balance")]
    ZeroTransferAmount,
    #[error("full-balance shield request must have preimage value 0")]
    NonZeroShieldValue,
    #[error("full-balance shield request must be for an ERC-20 token")]
    NonErc20Shield,
    #[error("full-balance shield token does not match the guarded token")]
    ShieldTokenMismatch,
    #[error("bridge deposit depositor must be the executor")]
    DepositorNotExecutor,
    #[error("bridge deposit message must be empty")]
    NonEmptyDepositMessage,
    #[error("private bridge deposit recipient must be the handler")]
    RecipientNotHandler,
    #[error("signature does not authorize this multicall for the executor")]
    InvalidSignature,
}

/// What the Across handler does with a private-delivery fill on the destination chain.
#[derive(Clone)]
pub struct AcrossPrivateDelivery {
    /// The Across `MulticallHandler` on the destination chain.
    pub handler: Address,
    /// The executor on the destination chain that receives and shields the fill.
    pub destination_executor: Address,
    /// Signed `RelayAdapt7702.multicall` calldata for `destination_executor`.
    pub shield_multicall: Bytes,
    /// Where the handler sends the fill when a call fails. `None` reverts the fill.
    pub fallback: Option<Address>,
}

/// One call made by the executor inside a signed `execute` or `multicall`.
///
/// Targets other than the executor itself are chain profile data supplied by callers.
#[derive(Clone)]
pub enum ExecutorAction {
    /// `token.approve(spender, amount)` for an exact amount.
    Approve {
        token: Address,
        spender: Address,
        amount: U256,
    },
    /// `spoke_pool.depositV3(..)` on an Across V3 `SpokePool`, which pulls
    /// `inputAmount` of `inputToken` from the executor. Across refunds an
    /// expired deposit to its depositor, so the depositor must be the executor.
    /// The message must be empty, so the fill is a plain transfer to the recipient.
    /// Use [`Self::AcrossPrivateDeposit`] for a fill the handler shields.
    AcrossDeposit {
        spoke_pool: Address,
        deposit: SpokePool::depositV3Call,
    },
    /// `spoke_pool.depositV3(..)` whose fill goes to the Across `MulticallHandler`
    /// with the [`private_delivery_message`] built from `delivery` for
    /// `deposit.outputToken`. The depositor must be the executor, the recipient
    /// must be `delivery.handler`, and `deposit.message` must be empty because
    /// this action builds the message.
    AcrossPrivateDeposit {
        spoke_pool: Address,
        deposit: SpokePool::depositV3Call,
        delivery: AcrossPrivateDelivery,
    },
    /// `target.multicall(deadline, [])` on a contract, such as Uniswap
    /// `SwapRouter02`, that reverts once `block.timestamp > deadline`.
    Deadline { target: Address, deadline: u64 },
    /// `settlement.invalidateOrder(orderUid)` on `GPv2Settlement`.
    InvalidateOrder {
        settlement: Address,
        order_uid: OrderUid,
    },
    /// The executor's own `transfer` helper for an exact ERC-20 amount. It uses
    /// `SafeERC20`, so a `false` return or a short balance reverts. The helper
    /// treats 0 as the full balance, so 0 is rejected.
    Transfer {
        token: Address,
        to: Address,
        amount: U256,
    },
    /// The executor's own `shield` helper for a request with preimage value 0,
    /// which shields the executor's full ERC-20 balance of the request token.
    ShieldFullBalance(ShieldRequest),
}

impl ExecutorAction {
    /// Encode this action as a value-0 call made by `executor`.
    pub fn call(&self, executor: Address) -> Result<Call, ExecutorActionError> {
        let (to, data) = match self {
            Self::Approve {
                token,
                spender,
                amount,
            } => (
                *token,
                approveCall {
                    spender: *spender,
                    amount: *amount,
                }
                .abi_encode(),
            ),
            Self::AcrossDeposit {
                spoke_pool,
                deposit,
            } => {
                if deposit.depositor != executor {
                    return Err(ExecutorActionError::DepositorNotExecutor);
                }
                if !deposit.message.is_empty() {
                    return Err(ExecutorActionError::NonEmptyDepositMessage);
                }
                (*spoke_pool, deposit.abi_encode())
            }
            Self::AcrossPrivateDeposit {
                spoke_pool,
                deposit,
                delivery,
            } => {
                if deposit.depositor != executor {
                    return Err(ExecutorActionError::DepositorNotExecutor);
                }
                if !deposit.message.is_empty() {
                    return Err(ExecutorActionError::NonEmptyDepositMessage);
                }
                if deposit.recipient != delivery.handler {
                    return Err(ExecutorActionError::RecipientNotHandler);
                }
                (
                    *spoke_pool,
                    SpokePool::depositV3Call {
                        message: private_delivery_message(
                            delivery.handler,
                            deposit.outputToken,
                            delivery.destination_executor,
                            delivery.shield_multicall.clone(),
                            delivery.fallback,
                        ),
                        ..deposit.clone()
                    }
                    .abi_encode(),
                )
            }
            Self::Deadline { target, deadline } => (
                *target,
                DeadlineMulticall::multicallCall {
                    deadline: U256::from(*deadline),
                    data: Vec::new(),
                }
                .abi_encode(),
            ),
            Self::InvalidateOrder {
                settlement,
                order_uid,
            } => (
                *settlement,
                GPv2Settlement::invalidateOrderCall {
                    orderUid: order_uid.0.into(),
                }
                .abi_encode(),
            ),
            Self::Transfer { token, to, amount } => {
                if amount.is_zero() {
                    return Err(ExecutorActionError::ZeroTransferAmount);
                }
                (
                    executor,
                    transferCall {
                        _transfers: vec![TokenTransfer::erc20(*token, *to, *amount)],
                    }
                    .abi_encode(),
                )
            }
            Self::ShieldFullBalance(request) => {
                if request.preimage.token.tokenType != ERC20_TOKEN_TYPE {
                    return Err(ExecutorActionError::NonErc20Shield);
                }
                if !request.preimage.value.is_zero() {
                    return Err(ExecutorActionError::NonZeroShieldValue);
                }
                (
                    executor,
                    shieldCall {
                        _shieldRequests: vec![request.clone()],
                    }
                    .abi_encode(),
                )
            }
        };
        Ok(Call {
            to,
            data: data.into(),
            value: U256::ZERO,
        })
    }
}

/// Post-hook calls that shield `token` only if the executor holds at least `amount`.
///
/// The first call self-transfers exactly `amount` from the executor to itself. It
/// moves nothing and exists only as a balance assertion: `SafeERC20` reverts on a
/// short balance, and `requireSuccess = true` then reverts the whole post-hook.
/// The second call shields the full balance under `shield`, which must be a
/// value-0 ERC-20 request for `token`. Sign them with [`post_hook_signing_hash`]
/// for a `multicall` with `requireSuccess = true`.
///
/// The guard is needed because the contract's full-balance shield returns without
/// reverting when the balance is 0, so an unguarded post-hook could consume its
/// nonce and shield nothing. `multicall` ignores return data, so a `balanceOf`
/// call cannot serve as the check.
///
/// A self-transfer does not leave every token balance unchanged. Fee-on-transfer
/// tokens lose the fee, rebasing tokens can lose a few wei to rounding, and some
/// tokens reject self-transfers. Railgun's shield already rejects the first two,
/// because it requires the received amount to equal the note value. For the
/// rest, the post-hook reverts and the tokens stay with the executor.
///
/// Shielding exactly `amount` and then sweeping the remainder with a value-0
/// shield would avoid the self-transfer. It would also create a second note
/// whenever the balance exceeds `amount`, which is the usual outcome of a swap
/// filled above its limit.
pub fn guarded_shield_calls(
    executor: Address,
    token: Address,
    amount: U256,
    shield: ShieldRequest,
) -> Result<Vec<Call>, ExecutorActionError> {
    if shield.preimage.token.tokenAddress != token {
        return Err(ExecutorActionError::ShieldTokenMismatch);
    }
    Ok(vec![
        ExecutorAction::Transfer {
            token,
            to: executor,
            amount,
        }
        .call(executor)?,
        ExecutorAction::ShieldFullBalance(shield).call(executor)?,
    ])
}

/// Post-hook calls that bridge `deposit.inputAmount` of `deposit.inputToken`
/// through the Across `SpokePool` at `spoke_pool`.
///
/// The calls are, in order: the self-transfer guard of [`guarded_shield_calls`]
/// for exactly `inputAmount`, which reverts when the executor holds less; an
/// approval of exactly `inputAmount` to `spoke_pool`; and the value-0
/// `depositV3` call, which must name the executor as depositor and carry an
/// empty message. When `surplus_shield` is given, a final value-0 full-balance
/// shield of `inputToken` sweeps whatever the executor still holds after the
/// deposit. Sign them with [`post_hook_signing_hash`] for a `multicall` with
/// `requireSuccess = true`, so a failed deposit reverts the whole post-hook and
/// leaves its nonce unused.
pub fn bridge_deposit_calls(
    executor: Address,
    spoke_pool: Address,
    deposit: SpokePool::depositV3Call,
    surplus_shield: Option<ShieldRequest>,
) -> Result<Vec<Call>, ExecutorActionError> {
    deposit_calls(
        executor,
        spoke_pool,
        deposit.inputToken,
        deposit.inputAmount,
        &ExecutorAction::AcrossDeposit {
            spoke_pool,
            deposit,
        },
        surplus_shield,
    )
}

/// Post-hook calls that bridge like [`bridge_deposit_calls`] and have the
/// Across handler on the destination chain shield the fill.
///
/// The calls and their order are the same. The `depositV3` call must name the
/// executor as depositor and `delivery.handler` as recipient, and must carry an
/// empty message, which is replaced by the [`private_delivery_message`] for
/// `delivery` and `deposit.outputToken`.
pub fn private_bridge_deposit_calls(
    executor: Address,
    spoke_pool: Address,
    deposit: SpokePool::depositV3Call,
    delivery: AcrossPrivateDelivery,
    surplus_shield: Option<ShieldRequest>,
) -> Result<Vec<Call>, ExecutorActionError> {
    deposit_calls(
        executor,
        spoke_pool,
        deposit.inputToken,
        deposit.inputAmount,
        &ExecutorAction::AcrossPrivateDeposit {
            spoke_pool,
            deposit,
            delivery,
        },
        surplus_shield,
    )
}

/// Guard, approval of `amount` of `token` to `spoke_pool`, the `deposit` action,
/// and an optional full-balance shield of what is left.
fn deposit_calls(
    executor: Address,
    spoke_pool: Address,
    token: Address,
    amount: U256,
    deposit: &ExecutorAction,
    surplus_shield: Option<ShieldRequest>,
) -> Result<Vec<Call>, ExecutorActionError> {
    if surplus_shield
        .as_ref()
        .is_some_and(|shield| shield.preimage.token.tokenAddress != token)
    {
        return Err(ExecutorActionError::ShieldTokenMismatch);
    }
    let mut calls = vec![
        ExecutorAction::Transfer {
            token,
            to: executor,
            amount,
        }
        .call(executor)?,
        ExecutorAction::Approve {
            token,
            spender: spoke_pool,
            amount,
        }
        .call(executor)?,
        deposit.call(executor)?,
    ];
    if let Some(shield) = surplus_shield {
        calls.push(ExecutorAction::ShieldFullBalance(shield).call(executor)?);
    }
    Ok(calls)
}

/// Signing hash of a post-hook `multicall` with `requireSuccess = true`.
#[must_use]
pub fn post_hook_signing_hash(
    calls: &[Call],
    nonce: U256,
    chain_id: u64,
    executor: Address,
) -> B256 {
    multicall_signing_hash(true, calls, nonce, chain_id, executor)
}

/// Encode `RelayAdapt7702.multicall` calldata for a post-hook, to be called on
/// `executor`, after checking that `signature` authorizes it.
pub fn signed_post_hook_calldata(
    calls: Vec<Call>,
    nonce: U256,
    chain_id: u64,
    executor: Address,
    signature: &Signature,
) -> Result<Bytes, ExecutorActionError> {
    let signing_hash = post_hook_signing_hash(&calls, nonce, chain_id, executor);
    if !is_executor_signature(signature, &signing_hash, executor) {
        return Err(ExecutorActionError::InvalidSignature);
    }
    Ok(RelayAdapt7702::multicallCall {
        _requireSuccess: true,
        _calls: calls,
        _nonce: nonce,
        _signature: signature.as_bytes().into(),
    }
    .abi_encode()
    .into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::railgun::{CommitmentPreimage, ShieldCiphertext, TokenData};
    use alloy::primitives::Uint;
    use alloy::signers::SignerSync;
    use alloy::signers::local::PrivateKeySigner;

    const EXECUTOR: Address = Address::repeat_byte(0xe0);
    const TOKEN: Address = Address::repeat_byte(0x70);

    fn shield_request(token: TokenData, value: u64) -> ShieldRequest {
        ShieldRequest {
            preimage: CommitmentPreimage {
                npk: B256::with_last_byte(1),
                token,
                value: Uint::from(value),
            },
            ciphertext: ShieldCiphertext {
                encryptedBundle: [B256::ZERO; 3],
                shieldKey: B256::ZERO,
            },
        }
    }

    #[test]
    fn external_actions_encode_value_zero_calls_to_their_targets() {
        let spender = Address::repeat_byte(0x5e);
        let call = ExecutorAction::Approve {
            token: TOKEN,
            spender,
            amount: U256::from(7),
        }
        .call(EXECUTOR)
        .unwrap();
        assert_eq!((call.to, call.value), (TOKEN, U256::ZERO));
        let approve = approveCall::abi_decode(&call.data).unwrap();
        assert_eq!((approve.spender, approve.amount), (spender, U256::from(7)));

        let guard = Address::repeat_byte(0x68);
        let call = ExecutorAction::Deadline {
            target: guard,
            deadline: 1_700_000_000,
        }
        .call(EXECUTOR)
        .unwrap();
        assert_eq!((call.to, call.value), (guard, U256::ZERO));
        let deadline = DeadlineMulticall::multicallCall::abi_decode(&call.data).unwrap();
        assert_eq!(deadline.deadline, U256::from(1_700_000_000_u64));
        assert!(deadline.data.is_empty());

        let settlement = Address::repeat_byte(0x90);
        let order_uid = OrderUid::new(B256::repeat_byte(0xaa), EXECUTOR, 0x0102_0304);
        let call = ExecutorAction::InvalidateOrder {
            settlement,
            order_uid,
        }
        .call(EXECUTOR)
        .unwrap();
        assert_eq!((call.to, call.value), (settlement, U256::ZERO));
        let invalidate = GPv2Settlement::invalidateOrderCall::abi_decode(&call.data).unwrap();
        assert_eq!(invalidate.orderUid.as_ref(), order_uid.0.as_slice());
    }

    #[test]
    fn guarded_post_hook_self_transfers_exact_amount_then_shields_full_balance() {
        let amount = U256::from(9_999);
        let calls = guarded_shield_calls(
            EXECUTOR,
            TOKEN,
            amount,
            shield_request(TokenData::erc20(TOKEN), 0),
        )
        .unwrap();
        assert_eq!(calls.len(), 2);
        assert!(
            calls
                .iter()
                .all(|call| call.to == EXECUTOR && call.value.is_zero())
        );

        let transfer = transferCall::abi_decode(&calls[0].data).unwrap();
        let [TokenTransfer { token, to, value }] = transfer._transfers.as_slice() else {
            panic!("expected one transfer");
        };
        assert_eq!(
            (token.tokenType, token.tokenAddress, token.tokenSubID),
            (ERC20_TOKEN_TYPE, TOKEN, U256::ZERO)
        );
        assert_eq!((*to, *value), (EXECUTOR, amount));

        let shield = shieldCall::abi_decode(&calls[1].data).unwrap();
        let [request] = shield._shieldRequests.as_slice() else {
            panic!("expected one shield request");
        };
        assert_eq!(request.preimage.token.tokenType, ERC20_TOKEN_TYPE);
        assert_eq!(request.preimage.token.tokenAddress, TOKEN);
        assert!(request.preimage.value.is_zero());
    }

    #[test]
    fn self_helper_actions_reject_amounts_the_helpers_reinterpret() {
        let erc20 = TokenData::erc20(TOKEN);
        assert_eq!(
            ExecutorAction::Transfer {
                token: TOKEN,
                to: EXECUTOR,
                amount: U256::ZERO,
            }
            .call(EXECUTOR)
            .unwrap_err(),
            ExecutorActionError::ZeroTransferAmount
        );
        assert_eq!(
            ExecutorAction::ShieldFullBalance(shield_request(erc20.clone(), 1))
                .call(EXECUTOR)
                .unwrap_err(),
            ExecutorActionError::NonZeroShieldValue
        );
        let nft = TokenData {
            tokenType: 1,
            tokenAddress: TOKEN,
            tokenSubID: U256::from(1),
        };
        assert_eq!(
            ExecutorAction::ShieldFullBalance(shield_request(nft, 0))
                .call(EXECUTOR)
                .unwrap_err(),
            ExecutorActionError::NonErc20Shield
        );
        assert_eq!(
            guarded_shield_calls(EXECUTOR, TOKEN, U256::ZERO, shield_request(erc20, 0))
                .unwrap_err(),
            ExecutorActionError::ZeroTransferAmount
        );
        assert_eq!(
            guarded_shield_calls(
                EXECUTOR,
                TOKEN,
                U256::ONE,
                shield_request(TokenData::erc20(Address::repeat_byte(0x71)), 0),
            )
            .unwrap_err(),
            ExecutorActionError::ShieldTokenMismatch
        );
    }

    fn across_deposit(depositor: Address) -> SpokePool::depositV3Call {
        SpokePool::depositV3Call {
            depositor,
            recipient: Address::repeat_byte(0x7e),
            inputToken: TOKEN,
            outputToken: Address::repeat_byte(0x71),
            inputAmount: U256::from(10_000),
            outputAmount: U256::from(9_900),
            destinationChainId: U256::from(42_161),
            exclusiveRelayer: Address::ZERO,
            quoteTimestamp: 1_700_000_000,
            fillDeadline: 1_700_003_600,
            exclusivityParameter: 0,
            message: Bytes::new(),
        }
    }

    #[test]
    fn bridge_deposit_guards_approves_and_deposits_the_exact_amount() {
        let spoke_pool = Address::repeat_byte(0x5b);
        let deposit = across_deposit(EXECUTOR);
        let calls = bridge_deposit_calls(EXECUTOR, spoke_pool, deposit.clone(), None).unwrap();
        assert_eq!(
            calls.iter().map(|call| call.to).collect::<Vec<_>>(),
            [EXECUTOR, TOKEN, spoke_pool]
        );
        assert!(calls.iter().all(|call| call.value.is_zero()));

        let transfer = transferCall::abi_decode(&calls[0].data).unwrap();
        let [TokenTransfer { token, to, value }] = transfer._transfers.as_slice() else {
            panic!("expected one transfer");
        };
        assert_eq!(
            (token.tokenAddress, *to, *value),
            (TOKEN, EXECUTOR, deposit.inputAmount)
        );

        let approve = approveCall::abi_decode(&calls[1].data).unwrap();
        assert_eq!(
            (approve.spender, approve.amount),
            (spoke_pool, deposit.inputAmount)
        );

        let encoded = SpokePool::depositV3Call::abi_decode(&calls[2].data).unwrap();
        assert_eq!(
            (encoded.depositor, encoded.recipient),
            (EXECUTOR, deposit.recipient)
        );
        assert_eq!(
            (encoded.inputToken, encoded.outputToken),
            (TOKEN, deposit.outputToken)
        );
        assert_eq!(
            (encoded.inputAmount, encoded.outputAmount),
            (deposit.inputAmount, deposit.outputAmount)
        );
        assert_eq!(encoded.destinationChainId, deposit.destinationChainId);
        assert!(encoded.message.is_empty());

        let with_shield = bridge_deposit_calls(
            EXECUTOR,
            spoke_pool,
            deposit,
            Some(shield_request(TokenData::erc20(TOKEN), 0)),
        )
        .unwrap();
        assert_eq!(with_shield.len(), 4);
        assert_eq!(with_shield[..3].to_vec().abi_encode(), calls.abi_encode());
        assert_eq!(
            (with_shield[3].to, with_shield[3].value),
            (EXECUTOR, U256::ZERO)
        );
        let shield = shieldCall::abi_decode(&with_shield[3].data).unwrap();
        let [request] = shield._shieldRequests.as_slice() else {
            panic!("expected one shield request");
        };
        assert_eq!(request.preimage.token.tokenAddress, TOKEN);
        assert!(request.preimage.value.is_zero());
    }

    #[test]
    fn bridge_deposit_rejects_deposits_it_cannot_guard_or_refund() {
        let reject = |deposit: SpokePool::depositV3Call, shield: Option<ShieldRequest>| {
            bridge_deposit_calls(EXECUTOR, Address::repeat_byte(0x5b), deposit, shield).unwrap_err()
        };
        assert_eq!(
            reject(across_deposit(Address::repeat_byte(0x99)), None),
            ExecutorActionError::DepositorNotExecutor
        );
        assert_eq!(
            reject(
                SpokePool::depositV3Call {
                    message: Bytes::from_static(&[0x01]),
                    ..across_deposit(EXECUTOR)
                },
                None
            ),
            ExecutorActionError::NonEmptyDepositMessage
        );
        assert_eq!(
            reject(
                SpokePool::depositV3Call {
                    inputAmount: U256::ZERO,
                    ..across_deposit(EXECUTOR)
                },
                None
            ),
            ExecutorActionError::ZeroTransferAmount
        );
        assert_eq!(
            reject(
                across_deposit(EXECUTOR),
                Some(shield_request(
                    TokenData::erc20(Address::repeat_byte(0x71)),
                    0
                ))
            ),
            ExecutorActionError::ShieldTokenMismatch
        );
    }

    const HANDLER: Address = Address::repeat_byte(0x7e);

    fn private_delivery(fallback: Option<Address>) -> AcrossPrivateDelivery {
        AcrossPrivateDelivery {
            handler: HANDLER,
            destination_executor: Address::repeat_byte(0xe1),
            shield_multicall: Bytes::from_static(&[0xab; 37]),
            fallback,
        }
    }

    #[test]
    fn private_bridge_deposit_sends_the_fill_to_the_handler_with_the_delivery_message() {
        let spoke_pool = Address::repeat_byte(0x5b);
        let deposit = across_deposit(EXECUTOR);
        let delivery = private_delivery(Some(Address::repeat_byte(0xfb)));
        let plain = bridge_deposit_calls(EXECUTOR, spoke_pool, deposit.clone(), None).unwrap();
        let calls = private_bridge_deposit_calls(
            EXECUTOR,
            spoke_pool,
            deposit.clone(),
            delivery.clone(),
            None,
        )
        .unwrap();
        assert_eq!(
            calls.iter().map(|call| call.to).collect::<Vec<_>>(),
            [EXECUTOR, TOKEN, spoke_pool]
        );
        assert!(calls.iter().all(|call| call.value.is_zero()));
        assert_eq!(
            calls[..2].to_vec().abi_encode(),
            plain[..2].to_vec().abi_encode()
        );

        let encoded = SpokePool::depositV3Call::abi_decode(&calls[2].data).unwrap();
        assert_eq!((encoded.depositor, encoded.recipient), (EXECUTOR, HANDLER));
        assert_eq!(
            encoded.message,
            private_delivery_message(
                HANDLER,
                deposit.outputToken,
                delivery.destination_executor,
                delivery.shield_multicall.clone(),
                delivery.fallback,
            )
        );
        // Everything but the message is the caller's deposit.
        assert_eq!(
            SpokePool::depositV3Call {
                message: Bytes::new(),
                ..encoded
            }
            .abi_encode(),
            deposit.abi_encode()
        );

        let with_shield = private_bridge_deposit_calls(
            EXECUTOR,
            spoke_pool,
            deposit,
            delivery,
            Some(shield_request(TokenData::erc20(TOKEN), 0)),
        )
        .unwrap();
        assert_eq!(with_shield.len(), 4);
        assert_eq!(with_shield[..3].to_vec().abi_encode(), calls.abi_encode());
        assert_eq!(with_shield[3].to, EXECUTOR);
    }

    #[test]
    fn private_bridge_deposit_rejects_deposits_the_handler_would_not_deliver() {
        let reject = |deposit: SpokePool::depositV3Call| {
            private_bridge_deposit_calls(
                EXECUTOR,
                Address::repeat_byte(0x5b),
                deposit,
                private_delivery(None),
                None,
            )
            .unwrap_err()
        };
        assert_eq!(
            reject(across_deposit(Address::repeat_byte(0x99))),
            ExecutorActionError::DepositorNotExecutor
        );
        assert_eq!(
            reject(SpokePool::depositV3Call {
                message: Bytes::from_static(&[0x01]),
                ..across_deposit(EXECUTOR)
            }),
            ExecutorActionError::NonEmptyDepositMessage
        );
        assert_eq!(
            reject(SpokePool::depositV3Call {
                recipient: Address::repeat_byte(0x7f),
                ..across_deposit(EXECUTOR)
            }),
            ExecutorActionError::RecipientNotHandler
        );
    }

    #[test]
    fn signed_post_hook_calldata_requires_the_executor_signature() {
        let signer = PrivateKeySigner::random();
        let executor = signer.address();
        let calls = guarded_shield_calls(
            executor,
            TOKEN,
            U256::ONE,
            shield_request(TokenData::erc20(TOKEN), 0),
        )
        .unwrap();
        let nonce = U256::from(4);
        let signing_hash = post_hook_signing_hash(&calls, nonce, 1, executor);
        let signature = signer.sign_hash_sync(&signing_hash).unwrap();

        let other = PrivateKeySigner::random()
            .sign_hash_sync(&signing_hash)
            .unwrap();
        assert_eq!(
            signed_post_hook_calldata(calls.clone(), nonce, 1, executor, &other).unwrap_err(),
            ExecutorActionError::InvalidSignature
        );
        assert_eq!(
            signed_post_hook_calldata(calls.clone(), nonce + U256::ONE, 1, executor, &signature)
                .unwrap_err(),
            ExecutorActionError::InvalidSignature
        );

        let calldata =
            signed_post_hook_calldata(calls.clone(), nonce, 1, executor, &signature).unwrap();
        let decoded = RelayAdapt7702::multicallCall::abi_decode(&calldata).unwrap();
        assert!(decoded._requireSuccess);
        assert_eq!(decoded._nonce, nonce);
        assert_eq!(decoded._calls.abi_encode(), calls.abi_encode());
        assert_eq!(decoded._signature.as_ref(), signature.as_bytes().as_slice());
    }
}
