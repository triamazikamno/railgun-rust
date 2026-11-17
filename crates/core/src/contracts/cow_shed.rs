//! `CoW` cow-shed v2.1.0 hook batches: proxy addresses, batch signing, and the
//! deposit and withdrawal batches a proxy's owner signs.
//!
//! Every account has one cow-shed proxy at a `CREATE2` address. The proxy runs
//! a batch of calls that its owner signed, whoever submits it. Factory,
//! implementation, and weiroll executor addresses are chain profile data
//! supplied by callers.

use alloy::hex;
use alloy::primitives::{Address, B256, Bytes, Signature, U256, keccak256};
use alloy::sol;
use alloy::sol_types::{Eip712Domain, SolCall, SolStruct, SolValue, eip712_domain};
use thiserror::Error;

use super::weiroll::{BalanceDeposit, WeirollError};

sol! {
    /// One call of a cow-shed hook batch. Field names and types form the
    /// EIP-712 type hash.
    #[derive(Debug, PartialEq, Eq)]
    struct Call {
        address target;
        uint256 value;
        bytes callData;
        bool allowFailure;
        bool isDelegateCall;
    }

    /// The batch a proxy's owner signs. Field names and types form the EIP-712
    /// type hash.
    #[derive(Debug, PartialEq, Eq)]
    struct ExecuteHooks {
        Call[] calls;
        bytes32 nonce;
        uint256 deadline;
    }

    interface COWShedFactory {
        function executeHooks(Call[] calls, bytes32 nonce, uint256 deadline, address user, bytes signature);
        function proxyOf(address who) view returns (address);
        function implementation() view returns (address);
    }

    interface COWShed {
        function nonces(bytes32 nonce) view returns (bool);
        function domainSeparator() view returns (bytes32);
    }

    interface IERC20 {
        function transfer(address to, uint256 amount) returns (bool);
    }
}

/// `COWShedFactory.PROXY_CREATION_CODE` of cow-shed v2.1.0, without the
/// constructor arguments.
pub const PROXY_CREATION_CODE: &[u8] = &hex!(
    "60a03461009557601f61033d38819003918201601f19168301916001600160401b0383118484101761009957808492604094855283398101031261009557610052602061004b836100ad565b92016100ad565b6080527f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc5560405161027b90816100c28239608051818181608b01526101750152f35b5f80fd5b634e487b7160e01b5f52604160045260245ffd5b51906001600160a01b03821682036100955756fe60806040526004361015610018575b3661019757610197565b5f3560e01c8063025b22bc146100375763f851a4400361000e57610116565b346101125760207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126101125760043573ffffffffffffffffffffffffffffffffffffffff81169081810361011257337f000000000000000000000000000000000000000000000000000000000000000073ffffffffffffffffffffffffffffffffffffffff160361010d577f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc557fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b5f80a2005b61023d565b5f80fd5b34610112575f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36011261011257602061014e61016c565b73ffffffffffffffffffffffffffffffffffffffff60405191168152f35b33300361010d577f000000000000000000000000000000000000000000000000000000000000000090565b60ff7f68df44b1011761f481358c0f49a711192727fb02c377d697bcb0ea8ff8393ac0541615806101f0575b1561023d577ff92ee8a9000000000000000000000000000000000000000000000000000000005f5260045ffd5b507fc4d66de8000000000000000000000000000000000000000000000000000000007fffffffff000000000000000000000000000000000000000000000000000000005f351614156101c3565b5f807f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc54368280378136915af43d5f803e15610277573d5ff35b3d5ffd"
);

#[derive(Debug, Error)]
pub enum CowShedError {
    #[error("hook batch signature does not recover the proxy owner")]
    SignerNotOwner,
    #[error("hook batch signature v must be 27 or 28, got {0}")]
    InvalidSignatureV(u8),
    #[error("not a deposit hook batch: {0}")]
    NotDepositHook(&'static str),
    #[error("not a withdrawal batch to the proxy owner")]
    NotWithdrawal,
    #[error("withdrawal amount must be nonzero")]
    ZeroAmount,
    #[error(transparent)]
    Weiroll(#[from] WeirollError),
}

/// EIP-712 domain of an account's cow-shed proxy.
#[must_use]
pub const fn proxy_domain(chain_id: u64, proxy: Address) -> Eip712Domain {
    eip712_domain! {
        name: "COWShed",
        version: "2.1.0",
        chain_id: chain_id,
        verifying_contract: proxy,
    }
}

/// The cow-shed proxy of `owner`, as `COWShedFactory.proxyOf` computes it. The
/// address has code only after the factory deployed the proxy.
#[must_use]
pub fn proxy_address(factory: Address, implementation: Address, owner: Address) -> Address {
    let init_code = [
        PROXY_CREATION_CODE,
        (implementation, owner).abi_encode_params().as_slice(),
    ]
    .concat();
    factory.create2(owner.into_word(), keccak256(init_code))
}

/// EIP-712 digest the proxy's owner signs for a batch.
#[must_use]
pub fn execute_hooks_digest(hooks: &ExecuteHooks, chain_id: u64, proxy: Address) -> B256 {
    hooks.eip712_signing_hash(&proxy_domain(chain_id, proxy))
}

/// `COWShedFactory.executeHooks` calldata for a batch `owner` signed, after
/// checking that `signature` recovers `owner` over the batch's digest in the
/// domain of `proxy_address(factory, implementation, owner)`.
///
/// The signature is encoded as `r || s || v` with `v` in {27, 28}, which is
/// what cow-shed's `decodeEOASignature` reads.
pub fn execute_hooks_calldata(
    hooks: ExecuteHooks,
    owner: Address,
    signature: &Signature,
    chain_id: u64,
    factory: Address,
    implementation: Address,
) -> Result<Bytes, CowShedError> {
    let proxy = proxy_address(factory, implementation, owner);
    let digest = execute_hooks_digest(&hooks, chain_id, proxy);
    if !signature
        .recover_address_from_prehash(&digest)
        .is_ok_and(|recovered| recovered == owner)
    {
        return Err(CowShedError::SignerNotOwner);
    }
    let signature = signature.as_bytes();
    let v = signature[64];
    if !matches!(v, 27 | 28) {
        return Err(CowShedError::InvalidSignatureV(v));
    }
    Ok(COWShedFactory::executeHooksCall {
        calls: hooks.calls,
        nonce: hooks.nonce,
        deadline: hooks.deadline,
        user: owner,
        signature: signature.into(),
    }
    .abi_encode()
    .into())
}

/// The two calls of the deposit hook batch, both `allowFailure = false`:
///
/// 1. `input_token.transfer(proxy, buy_amount)`, a plain value-0 call from the
///    proxy to the token. It is a self-transfer that moves nothing and reverts
///    when the proxy holds less than `buy_amount`, which makes it the guard.
/// 2. a delegatecall (`isDelegateCall = true`, value 0) to `weiroll` with
///    `deposit.encode()`.
///
/// `proxy`, `input_token` and `buy_amount` come from `deposit`.
pub fn deposit_hook_calls(
    weiroll: Address,
    deposit: &BalanceDeposit,
) -> Result<Vec<Call>, CowShedError> {
    Ok(vec![
        transfer_call(deposit.input_token, deposit.proxy, deposit.buy_amount),
        Call {
            target: weiroll,
            value: U256::ZERO,
            callData: deposit.encode()?,
            allowFailure: false,
            isDelegateCall: true,
        },
    ])
}

/// What a deposit hook batch does, read back from its calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositHook {
    pub weiroll: Address,
    pub deposit: BalanceDeposit,
}

/// Decode `calls`, rejecting anything that [`deposit_hook_calls`] would not
/// emit.
///
/// A deposit hook batch has exactly two calls, both value 0 and
/// `allowFailure = false`. The first is a non-delegate `transfer(to, amount)`
/// on the script's input token with `to == deposit.proxy` and
/// `amount == deposit.buy_amount`. The second is a delegatecall whose calldata
/// [`BalanceDeposit::decode`] accepts.
pub fn decode_deposit_hook_calls(calls: &[Call]) -> Result<DepositHook, CowShedError> {
    let [guard, script] = calls else {
        return Err(CowShedError::NotDepositHook("expected two calls"));
    };
    if !script.isDelegateCall {
        return Err(CowShedError::NotDepositHook(
            "the script call must be a delegatecall",
        ));
    }
    if script.allowFailure || !script.value.is_zero() {
        return Err(CowShedError::NotDepositHook(
            "the script call must not allow failure or carry value",
        ));
    }
    let deposit = BalanceDeposit::decode(&script.callData)?;
    if *guard != transfer_call(deposit.input_token, deposit.proxy, deposit.buy_amount) {
        return Err(CowShedError::NotDepositHook(
            "the guard must be `transfer(proxy, buy_amount)` on the input token",
        ));
    }
    if script.callData != deposit.encode()? {
        return Err(CowShedError::NotDepositHook(
            "the script calldata is not what the encoder emits",
        ));
    }
    Ok(DepositHook {
        weiroll: script.target,
        deposit,
    })
}

/// The one call of a withdrawal batch: `token.transfer(owner, amount)`, value
/// 0, `allowFailure = false`, not a delegatecall.
///
/// Rejects a zero amount. The recipient is always the proxy's owner: there is
/// no parameter for another one.
pub fn withdrawal_calls(
    token: Address,
    owner: Address,
    amount: U256,
) -> Result<Vec<Call>, CowShedError> {
    if amount.is_zero() {
        return Err(CowShedError::ZeroAmount);
    }
    Ok(vec![transfer_call(token, owner, amount)])
}

/// `(token, amount)` if `calls` is exactly the withdrawal batch
/// `withdrawal_calls(token, owner, amount)` emits for `owner`; an error for any
/// other recipient or shape.
pub fn decode_withdrawal_calls(
    calls: &[Call],
    owner: Address,
) -> Result<(Address, U256), CowShedError> {
    let [call] = calls else {
        return Err(CowShedError::NotWithdrawal);
    };
    let amount = IERC20::transferCall::abi_decode(&call.callData)
        .map_err(|_| CowShedError::NotWithdrawal)?
        .amount;
    if withdrawal_calls(call.target, owner, amount)? != calls {
        return Err(CowShedError::NotWithdrawal);
    }
    Ok((call.target, amount))
}

/// A plain, value-0 `token.transfer(to, amount)` that must succeed.
fn transfer_call(token: Address, to: Address, amount: U256) -> Call {
    Call {
        target: token,
        value: U256::ZERO,
        callData: IERC20::transferCall { to, amount }.abi_encode().into(),
        allowFailure: false,
        isDelegateCall: false,
    }
}

#[cfg(test)]
mod tests;
