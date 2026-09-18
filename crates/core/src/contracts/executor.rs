//! `RelayAdapt7702` owner authorization for the nonce-bearing execution profile.
//!
//! The EIP-712 verifying contract is the executing EOA, not its code delegate.
//! Execution and multicall consume the same contract storage nonce. Ethereum
//! account nonces and delegation authorizations are separate from this nonce.

use alloy::primitives::{Address, B256, Signature, U256, keccak256};
use alloy::sol;
use alloy::sol_types::{Eip712Domain, SolStruct, SolValue, eip712_domain};

use super::railgun::{Call, RelayAdapt7702ActionData, Transaction};

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
}

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
