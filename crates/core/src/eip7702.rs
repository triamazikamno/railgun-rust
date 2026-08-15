//! EIP-7702 nonce domains are deliberately non-interchangeable.
//! `RelayAdapt`'s execution nonce is shared by `execute` and `multicall`.

use std::fmt;

use alloy::eips::eip7702::{Authorization, SignedAuthorization, constants::SECP256K1N_HALF};
use alloy::primitives::{Address, B256, Bytes, FixedBytes, Signature, U256};
use alloy::sol;
use alloy::sol_types::{Eip712Domain, SolCall, SolStruct, SolValue};
use thiserror::Error;

use crate::contracts::railgun::{
    RelayAdapt7702ActionData, RelayAdapt7702Current, RelayAdapt7702Legacy, Transaction,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Eip7702AuthorizationNonce(u64);

impl Eip7702AuthorizationNonce {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

impl From<u64> for Eip7702AuthorizationNonce {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl From<Eip7702AuthorizationNonce> for u64 {
    fn from(value: Eip7702AuthorizationNonce) -> Self {
        value.value()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RelayAdapt7702ExecutionNonce(U256);

impl RelayAdapt7702ExecutionNonce {
    #[must_use]
    pub const fn new(value: U256) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn value(self) -> U256 {
        self.0
    }
}

impl From<U256> for RelayAdapt7702ExecutionNonce {
    fn from(value: U256) -> Self {
        Self::new(value)
    }
}

impl From<RelayAdapt7702ExecutionNonce> for U256 {
    fn from(value: RelayAdapt7702ExecutionNonce) -> Self {
        value.value()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Eip7702OuterTransactionNonce(u64);

impl Eip7702OuterTransactionNonce {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

impl From<u64> for Eip7702OuterTransactionNonce {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl From<Eip7702OuterTransactionNonce> for u64 {
    fn from(value: Eip7702OuterTransactionNonce) -> Self {
        value.value()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Eip7702NonceError {
    #[error("EIP-7702 authorization nonce exceeds u64")]
    AuthorizationNonceOverflow,
    #[error("EIP-7702 outer transaction nonce exceeds u64")]
    OuterTransactionNonceOverflow,
}

fn try_u64(value: U256, error: Eip7702NonceError) -> Result<u64, Eip7702NonceError> {
    if value > U256::from(u64::MAX) {
        return Err(error);
    }
    Ok(value.to::<u64>())
}

impl TryFrom<U256> for Eip7702AuthorizationNonce {
    type Error = Eip7702NonceError;

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        try_u64(value, Eip7702NonceError::AuthorizationNonceOverflow).map(Self::new)
    }
}

impl TryFrom<U256> for Eip7702OuterTransactionNonce {
    type Error = Eip7702NonceError;

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        try_u64(value, Eip7702NonceError::OuterTransactionNonceOverflow).map(Self::new)
    }
}

/// Closed ABI versions fix the `execute` selector and nonce shape.
///
/// The current nonce is shared `RelayAdapt` execution-domain state, despite the
/// ABI naming it `_executeNonce`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelayAdapt7702ExecutionVersion {
    LegacyPreExecuteNonce,
    CurrentNonceAware { nonce: RelayAdapt7702ExecutionNonce },
}

impl RelayAdapt7702ExecutionVersion {
    #[must_use]
    pub fn execute_payload_hash(
        &self,
        transactions: &[Transaction],
        action_data: &RelayAdapt7702ActionData,
    ) -> FixedBytes<32> {
        match self {
            Self::LegacyPreExecuteNonce => alloy::primitives::keccak256(
                (transactions.to_vec(), action_data.clone()).abi_encode_params(),
            ),
            Self::CurrentNonceAware { nonce } => alloy::primitives::keccak256(
                (transactions.to_vec(), action_data.clone(), nonce.value()).abi_encode_params(),
            ),
        }
    }

    #[must_use]
    pub fn encode_execute(
        &self,
        transactions: Vec<Transaction>,
        action_data: RelayAdapt7702ActionData,
        signature: Bytes,
    ) -> Bytes {
        match self {
            Self::LegacyPreExecuteNonce => RelayAdapt7702Legacy::executeCall {
                _transactions: transactions,
                _actionData: action_data,
                _signature: signature,
            }
            .abi_encode()
            .into(),
            Self::CurrentNonceAware { nonce } => RelayAdapt7702Current::executeCall {
                _transactions: transactions,
                _actionData: action_data,
                _executeNonce: nonce.value(),
                _signature: signature,
            }
            .abi_encode()
            .into(),
        }
    }
}

sol! {
    struct Execute {
        bytes32 payloadHash;
    }
}

/// Owned EIP-712 data for the `RelayAdapt7702` `Execute` message.
#[derive(Clone)]
pub struct RelayAdapt7702ExecutionTypedData {
    domain: Eip712Domain,
    message: Execute,
    signing_hash: B256,
}

impl RelayAdapt7702ExecutionTypedData {
    fn new(domain: Eip712Domain, message: Execute) -> Self {
        let signing_hash = message.eip712_signing_hash(&domain);
        Self {
            domain,
            message,
            signing_hash,
        }
    }

    #[must_use]
    pub const fn domain(&self) -> &Eip712Domain {
        &self.domain
    }

    #[must_use]
    pub const fn message(&self) -> &Execute {
        &self.message
    }

    #[must_use]
    pub const fn payload_hash(&self) -> B256 {
        self.message.payloadHash
    }

    #[must_use]
    pub const fn signing_hash(&self) -> B256 {
        self.signing_hash
    }
}

impl fmt::Debug for RelayAdapt7702ExecutionTypedData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayAdapt7702ExecutionTypedData")
            .field("chain_id", &self.domain.chain_id)
            .field("message_type", &Execute::NAME)
            .field("category", &"relay-adapt-7702-execution")
            .finish_non_exhaustive()
    }
}

/// Privacy-safe failures from EIP-7702 authorization signature finalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Eip7702AuthorizationFinalizationError {
    #[error("EIP-7702 authorization signature has high s")]
    HighS,
    #[error("EIP-7702 authorization signature is invalid")]
    InvalidSignature,
    #[error("EIP-7702 authorization authority does not match the prepared authority")]
    AuthorityMismatch,
}

/// Privacy-safe failures from `RelayAdapt7702` execution signature finalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Eip7702ExecutionFinalizationError {
    #[error("RelayAdapt7702 execution signature has high s")]
    HighS,
    #[error("RelayAdapt7702 execution signature is invalid")]
    InvalidSignature,
    #[error("RelayAdapt7702 execution authority does not match the prepared authority")]
    AuthorityMismatch,
}

/// Value-free failures from aggregate EIP-7702 signature finalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Eip7702FinalizationError {
    #[error("EIP-7702 authorization finalization failed: {0}")]
    Authorization(#[from] Eip7702AuthorizationFinalizationError),
    #[error("RelayAdapt7702 execution finalization failed: {0}")]
    Execution(#[from] Eip7702ExecutionFinalizationError),
}

/// A verified `RelayAdapt7702` execution signature and its exact calldata bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct FinalizedRelayAdapt7702ExecutionSignature {
    signature: Signature,
    calldata: Bytes,
}

impl FinalizedRelayAdapt7702ExecutionSignature {
    #[must_use]
    pub const fn signature(&self) -> &Signature {
        &self.signature
    }

    #[must_use]
    pub const fn calldata(&self) -> &Bytes {
        &self.calldata
    }
}

/// The authority-owned portion of a finalized `RelayAdapt7702` call.
#[derive(Clone, PartialEq, Eq)]
pub struct FinalizedRelayAdapt7702Call {
    to: Address,
    data: Bytes,
    value: U256,
    authorization: SignedAuthorization,
    execution_signature: Signature,
}

impl FinalizedRelayAdapt7702Call {
    #[must_use]
    pub const fn to(&self) -> Address {
        self.to
    }

    #[must_use]
    pub const fn data(&self) -> &Bytes {
        &self.data
    }

    #[must_use]
    pub const fn value(&self) -> U256 {
        self.value
    }

    #[must_use]
    pub const fn authorization(&self) -> &SignedAuthorization {
        &self.authorization
    }

    #[must_use]
    pub const fn execution_signature(&self) -> &Signature {
        &self.execution_signature
    }
}

impl fmt::Debug for FinalizedRelayAdapt7702Call {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FinalizedRelayAdapt7702Call")
            .field("category", &"relay-adapt-7702-finalized-call")
            .field("calldata_len", &self.data.len())
            .field("outer_value_nonzero", &(!self.value.is_zero()))
            .field("authorization_present", &true)
            .field("execution_signature_present", &true)
            .finish_non_exhaustive()
    }
}

/// Payer-owned fields applied after authority-side finalization.
#[derive(Clone, PartialEq, Eq)]
pub struct RelayAdapt7702OuterTransactionFields {
    nonce: Eip7702OuterTransactionNonce,
    gas_limit: u64,
    max_fee_per_gas: U256,
    max_priority_fee_per_gas: U256,
}

impl RelayAdapt7702OuterTransactionFields {
    #[must_use]
    pub const fn new(
        nonce: Eip7702OuterTransactionNonce,
        gas_limit: u64,
        max_fee_per_gas: U256,
        max_priority_fee_per_gas: U256,
    ) -> Self {
        Self {
            nonce,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        }
    }

    #[must_use]
    pub const fn nonce(&self) -> Eip7702OuterTransactionNonce {
        self.nonce
    }

    #[must_use]
    pub const fn gas_limit(&self) -> u64 {
        self.gas_limit
    }

    #[must_use]
    pub const fn max_fee_per_gas(&self) -> U256 {
        self.max_fee_per_gas
    }

    #[must_use]
    pub const fn max_priority_fee_per_gas(&self) -> U256 {
        self.max_priority_fee_per_gas
    }
}

impl fmt::Debug for RelayAdapt7702OuterTransactionFields {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayAdapt7702OuterTransactionFields")
            .field("category", &"relay-adapt-7702-outer-payer-fields")
            .field("nonce_present", &true)
            .field("gas_limit_present", &true)
            .field("max_fee_per_gas_present", &true)
            .field("max_priority_fee_per_gas_present", &true)
            .finish()
    }
}

impl fmt::Debug for FinalizedRelayAdapt7702ExecutionSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FinalizedRelayAdapt7702ExecutionSignature")
            .field("category", &"relay-adapt-7702-execution-signature")
            .field("encoded_len", &self.calldata.len())
            .finish_non_exhaustive()
    }
}

fn canonical_authorization(
    chain_id: u64,
    delegate: Address,
    authorization_nonce: Eip7702AuthorizationNonce,
) -> Authorization {
    Authorization {
        chain_id: U256::from(chain_id),
        address: delegate,
        nonce: authorization_nonce.value(),
    }
}

fn canonical_execution_typed_data(
    chain_id: u64,
    authority: Address,
    payload_hash: B256,
) -> RelayAdapt7702ExecutionTypedData {
    RelayAdapt7702ExecutionTypedData::new(
        Eip712Domain {
            name: Some("RelayAdapt7702".into()),
            version: Some("1".into()),
            chain_id: Some(U256::from(chain_id)),
            verifying_contract: Some(authority),
            salt: None,
        },
        Execute {
            payloadHash: payload_hash,
        },
    )
}

/// Immutable, signer- and provider-neutral `RelayAdapt7702` execution material.
#[derive(Clone)]
pub struct PreparedRelayAdapt7702Execution {
    chain_id: u64,
    authority: Address,
    delegate: Address,
    authorization_nonce: Eip7702AuthorizationNonce,
    execution_version: RelayAdapt7702ExecutionVersion,
    transactions: Vec<Transaction>,
    action_data: RelayAdapt7702ActionData,
    outer_value: U256,
    payload_hash: B256,
    authorization: Authorization,
    authorization_signing_hash: B256,
    execution_typed_data: RelayAdapt7702ExecutionTypedData,
    execution_signing_hash: B256,
}

impl PreparedRelayAdapt7702Execution {
    #[must_use]
    pub fn prepare(
        chain_id: u64,
        authority: Address,
        delegate: Address,
        authorization_nonce: Eip7702AuthorizationNonce,
        execution_version: RelayAdapt7702ExecutionVersion,
        transactions: Vec<Transaction>,
        action_data: RelayAdapt7702ActionData,
        outer_value: U256,
    ) -> Self {
        let payload_hash = execution_version.execute_payload_hash(&transactions, &action_data);
        let authorization = canonical_authorization(chain_id, delegate, authorization_nonce);
        let authorization_signing_hash = authorization.signature_hash();
        let execution_typed_data =
            canonical_execution_typed_data(chain_id, authority, payload_hash);
        let execution_signing_hash = execution_typed_data.signing_hash();

        Self {
            chain_id,
            authority,
            delegate,
            authorization_nonce,
            execution_version,
            transactions,
            action_data,
            outer_value,
            payload_hash,
            authorization,
            authorization_signing_hash,
            execution_typed_data,
            execution_signing_hash,
        }
    }

    #[must_use]
    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }

    #[must_use]
    pub const fn authority(&self) -> Address {
        self.authority
    }

    #[must_use]
    pub const fn delegate(&self) -> Address {
        self.delegate
    }

    #[must_use]
    pub const fn authorization_nonce(&self) -> Eip7702AuthorizationNonce {
        self.authorization_nonce
    }

    #[must_use]
    pub const fn execution_version(&self) -> RelayAdapt7702ExecutionVersion {
        self.execution_version
    }

    #[must_use]
    pub fn transactions(&self) -> &[Transaction] {
        &self.transactions
    }

    #[must_use]
    pub const fn action_data(&self) -> &RelayAdapt7702ActionData {
        &self.action_data
    }

    #[must_use]
    pub const fn outer_value(&self) -> U256 {
        self.outer_value
    }

    #[must_use]
    pub const fn payload_hash(&self) -> B256 {
        self.payload_hash
    }

    #[must_use]
    pub const fn authorization(&self) -> &Authorization {
        &self.authorization
    }

    #[must_use]
    pub const fn authorization_signing_hash(&self) -> B256 {
        self.authorization_signing_hash
    }

    #[must_use]
    pub const fn execution_typed_data(&self) -> &RelayAdapt7702ExecutionTypedData {
        &self.execution_typed_data
    }

    #[must_use]
    pub const fn execution_signing_hash(&self) -> B256 {
        self.execution_signing_hash
    }

    /// Finalize the canonical authorization with one externally produced signature.
    pub fn finalize_authorization_signature(
        &self,
        signature: Signature,
    ) -> Result<SignedAuthorization, Eip7702AuthorizationFinalizationError> {
        if signature.s() > SECP256K1N_HALF {
            return Err(Eip7702AuthorizationFinalizationError::HighS);
        }

        let authorization =
            canonical_authorization(self.chain_id, self.delegate, self.authorization_nonce);
        let signed_authorization = authorization.into_signed(signature);
        let signed_signature = signed_authorization
            .signature()
            .map_err(|_| Eip7702AuthorizationFinalizationError::InvalidSignature)?;
        let recovered_authority = signed_signature
            .recover_address_from_prehash(&signed_authorization.inner().signature_hash())
            .map_err(|_| Eip7702AuthorizationFinalizationError::InvalidSignature)?;
        if recovered_authority != self.authority {
            return Err(Eip7702AuthorizationFinalizationError::AuthorityMismatch);
        }

        Ok(signed_authorization)
    }

    /// Verify and encode the canonical `RelayAdapt7702` execution signature.
    pub fn finalize_execution_signature(
        &self,
        signature: Signature,
    ) -> Result<FinalizedRelayAdapt7702ExecutionSignature, Eip7702ExecutionFinalizationError> {
        if signature.s() > SECP256K1N_HALF {
            return Err(Eip7702ExecutionFinalizationError::HighS);
        }

        let payload_hash = self
            .execution_version
            .execute_payload_hash(&self.transactions, &self.action_data);
        let execution_typed_data =
            canonical_execution_typed_data(self.chain_id, self.authority, payload_hash);
        let recovered_authority = signature
            .recover_address_from_prehash(&execution_typed_data.signing_hash())
            .map_err(|_| Eip7702ExecutionFinalizationError::InvalidSignature)?;
        if recovered_authority != self.authority {
            return Err(Eip7702ExecutionFinalizationError::AuthorityMismatch);
        }

        let encoded_signature: [u8; 65] = signature.as_bytes();
        debug_assert_eq!(encoded_signature.len(), 65);
        Ok(FinalizedRelayAdapt7702ExecutionSignature {
            signature,
            calldata: Bytes::from(encoded_signature),
        })
    }

    /// Finalize exactly one authorization and one execution signature.
    pub fn finalize(
        &self,
        authorization_signature: Signature,
        execution_signature: Signature,
    ) -> Result<FinalizedRelayAdapt7702Call, Eip7702FinalizationError> {
        let authorization = self
            .finalize_authorization_signature(authorization_signature)
            .map_err(Eip7702FinalizationError::Authorization)?;
        let execution = self
            .finalize_execution_signature(execution_signature)
            .map_err(Eip7702FinalizationError::Execution)?;
        let data = self.execution_version.encode_execute(
            self.transactions.clone(),
            self.action_data.clone(),
            execution.calldata().clone(),
        );

        Ok(FinalizedRelayAdapt7702Call {
            to: self.authority,
            data,
            value: self.outer_value,
            authorization,
            execution_signature: *execution.signature(),
        })
    }
}

impl fmt::Debug for PreparedRelayAdapt7702Execution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let execution_version = match self.execution_version {
            RelayAdapt7702ExecutionVersion::LegacyPreExecuteNonce => "legacy",
            RelayAdapt7702ExecutionVersion::CurrentNonceAware { .. } => "current",
        };
        formatter
            .debug_struct("PreparedRelayAdapt7702Execution")
            .field("chain_id", &self.chain_id)
            .field("execution_version", &execution_version)
            .field("transaction_count", &self.transactions.len())
            .field("action_call_count", &self.action_data.calls.len())
            .field("outer_value_nonzero", &(!self.outer_value.is_zero()))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use alloy::eips::eip7702::Authorization;
    use alloy::primitives::{
        Address, B256, Bytes, FixedBytes, Signature, U256, address, keccak256,
    };
    use alloy::signers::{SignerSync, local::PrivateKeySigner};
    use alloy::sol;
    use alloy::sol_types::{SolCall, SolStruct, SolValue};
    use serde_json::Value;
    use std::str::FromStr;

    sol! {
        struct Multicall {
            bytes32 payloadHash;
        }
    }

    use crate::contracts::railgun::{
        BoundParams, Call, CommitmentCiphertext, CommitmentPreimage, G1Point, G2Point,
        RelayAdapt7702ActionData, RelayAdapt7702Current, RelayAdapt7702Legacy, SnarkProof,
        TokenData, Transaction,
    };

    use super::{
        Eip7702AuthorizationFinalizationError, Eip7702AuthorizationNonce,
        Eip7702ExecutionFinalizationError, Eip7702FinalizationError, Eip7702NonceError,
        Eip7702OuterTransactionNonce, Execute, FinalizedRelayAdapt7702Call,
        PreparedRelayAdapt7702Execution, RelayAdapt7702ExecutionNonce,
        RelayAdapt7702ExecutionVersion, RelayAdapt7702OuterTransactionFields,
    };

    const AUTHORIZATION_TEST_KEY: [u8; 32] = [0x77; 32];
    const OTHER_AUTHORIZATION_TEST_KEY: [u8; 32] = [0x88; 32];

    const INPUTS_FIXTURE: &str = include_str!("../resources/fixtures/eip-7702/inputs.json");
    const VECTORS_FIXTURE: &str =
        include_str!("../resources/fixtures/eip-7702/expected-vectors.json");

    fn fixture_json(source: &str) -> Value {
        serde_json::from_str(source).expect("valid static EIP-7702 fixture JSON")
    }

    fn fixture_u256(value: &Value) -> U256 {
        U256::from_str(value.as_str().expect("decimal fixture value")).expect("valid U256")
    }

    fn fixture_fixed32(value: &Value) -> FixedBytes<32> {
        let bytes = alloy::hex::decode(value.as_str().expect("bytes32 fixture value"))
            .expect("valid bytes32 fixture value");
        FixedBytes::from_slice(&bytes)
    }

    fn fixture_bytes(value: &Value) -> Bytes {
        value
            .as_str()
            .expect("hex fixture value")
            .parse()
            .expect("valid hex fixture value")
    }

    fn fixture_transaction(value: &Value) -> Transaction {
        let proof = &value["proof"];
        let bound_params = &value["boundParams"];
        let unshield_preimage = &value["unshieldPreimage"];
        let ciphertext = bound_params["commitmentCiphertext"]
            .as_array()
            .expect("ciphertext array")
            .iter()
            .map(|value| CommitmentCiphertext {
                ciphertext: value["ciphertext"]
                    .as_array()
                    .expect("ciphertext words")
                    .iter()
                    .map(fixture_fixed32)
                    .collect::<Vec<_>>()
                    .try_into()
                    .expect("four ciphertext words"),
                blindedSenderViewingKey: fixture_fixed32(&value["blindedSenderViewingKey"]),
                blindedReceiverViewingKey: fixture_fixed32(&value["blindedReceiverViewingKey"]),
                annotationData: fixture_bytes(&value["annotationData"]),
                memo: fixture_bytes(&value["memo"]),
            })
            .collect();

        Transaction {
            proof: SnarkProof {
                a: G1Point {
                    x: fixture_u256(&proof["a"]["x"]),
                    y: fixture_u256(&proof["a"]["y"]),
                },
                b: G2Point {
                    x: proof["b"]["x"]
                        .as_array()
                        .expect("G2 x")
                        .iter()
                        .map(fixture_u256)
                        .collect::<Vec<_>>()
                        .try_into()
                        .expect("two G2 x coordinates"),
                    y: proof["b"]["y"]
                        .as_array()
                        .expect("G2 y")
                        .iter()
                        .map(fixture_u256)
                        .collect::<Vec<_>>()
                        .try_into()
                        .expect("two G2 y coordinates"),
                },
                c: G1Point {
                    x: fixture_u256(&proof["c"]["x"]),
                    y: fixture_u256(&proof["c"]["y"]),
                },
            },
            merkleRoot: fixture_fixed32(&value["merkleRoot"]),
            nullifiers: value["nullifiers"]
                .as_array()
                .expect("nullifier array")
                .iter()
                .map(fixture_fixed32)
                .collect(),
            commitments: value["commitments"]
                .as_array()
                .expect("commitment array")
                .iter()
                .map(fixture_fixed32)
                .collect(),
            boundParams: BoundParams {
                treeNumber: fixture_u256(&bound_params["treeNumber"]).to::<u16>(),
                minGasPrice: alloy::primitives::Uint::<72, 2>::from(
                    fixture_u256(&bound_params["minGasPrice"]).to::<u128>(),
                ),
                unshield: fixture_u256(&bound_params["unshield"]).to::<u8>(),
                chainID: fixture_u256(&bound_params["chainID"]).to::<u64>(),
                adaptContract: Address::from_str(
                    bound_params["adaptContract"]
                        .as_str()
                        .expect("adapt contract"),
                )
                .expect("valid adapt contract"),
                adaptParams: fixture_fixed32(&bound_params["adaptParams"]),
                commitmentCiphertext: ciphertext,
            },
            unshieldPreimage: CommitmentPreimage {
                npk: fixture_fixed32(&unshield_preimage["npk"]),
                token: TokenData {
                    tokenType: fixture_u256(&unshield_preimage["token"]["tokenType"]).to::<u8>(),
                    tokenAddress: Address::from_str(
                        unshield_preimage["token"]["tokenAddress"]
                            .as_str()
                            .expect("token address"),
                    )
                    .expect("valid token address"),
                    tokenSubID: fixture_u256(&unshield_preimage["token"]["tokenSubID"]),
                },
                value: alloy::primitives::Uint::<120, 2>::from(fixture_u256(
                    &unshield_preimage["value"],
                )),
            },
        }
    }

    fn fixture_action_data(value: &Value) -> RelayAdapt7702ActionData {
        RelayAdapt7702ActionData {
            requireSuccess: value["requireSuccess"]
                .as_bool()
                .expect("action requireSuccess"),
            minGasLimit: fixture_u256(&value["minGasLimit"]),
            calls: value["calls"]
                .as_array()
                .expect("action calls")
                .iter()
                .map(|value| Call {
                    to: Address::from_str(value["to"].as_str().expect("call address"))
                        .expect("valid call address"),
                    data: fixture_bytes(&value["data"]),
                    value: fixture_u256(&value["value"]),
                })
                .collect(),
        }
    }

    fn fixture_signature(value: &Value) -> Signature {
        Signature::new(
            fixture_u256(&value["r"]),
            fixture_u256(&value["s"]),
            value["yParity"].as_u64().expect("signature parity") == 1,
        )
    }

    fn assert_fixture_hex(actual: impl AsRef<[u8]>, expected: &str) {
        assert_eq!(format!("0x{}", alloy::hex::encode(actual)), expected);
    }

    // Exactly one signature from each domain is required; malformed counts are unrepresentable.
    const _: fn(
        &PreparedRelayAdapt7702Execution,
        Signature,
        Signature,
    ) -> Result<FinalizedRelayAdapt7702Call, Eip7702FinalizationError> =
        PreparedRelayAdapt7702Execution::finalize;

    fn action_data() -> RelayAdapt7702ActionData {
        RelayAdapt7702ActionData {
            requireSuccess: true,
            minGasLimit: U256::ZERO,
            calls: vec![Call {
                to: address!("0x3333333333333333333333333333333333333333"),
                data: Bytes::from(vec![0xaa, 0xbb, 0xcc]),
                value: U256::from(7_u64),
            }],
        }
    }

    fn transaction() -> Transaction {
        Transaction {
            proof: SnarkProof::default(),
            merkleRoot: FixedBytes::from([0x44; 32]),
            nullifiers: vec![FixedBytes::from([0x45; 32])],
            commitments: vec![FixedBytes::from([0x46; 32])],
            boundParams: BoundParams::new_transact(
                9,
                0,
                1,
                Vec::new(),
                Address::ZERO,
                FixedBytes::ZERO,
            ),
            unshieldPreimage: CommitmentPreimage::empty(),
        }
    }

    fn current_version() -> RelayAdapt7702ExecutionVersion {
        RelayAdapt7702ExecutionVersion::CurrentNonceAware {
            nonce: RelayAdapt7702ExecutionNonce::new(U256::from(29_u64)),
        }
    }

    fn prepared(outer_value: U256) -> PreparedRelayAdapt7702Execution {
        prepared_for_authority(
            address!("0x1111111111111111111111111111111111111111"),
            outer_value,
        )
    }

    fn prepared_for_authority(
        authority: Address,
        outer_value: U256,
    ) -> PreparedRelayAdapt7702Execution {
        PreparedRelayAdapt7702Execution::prepare(
            1_337,
            authority,
            address!("0x2222222222222222222222222222222222222222"),
            Eip7702AuthorizationNonce::new(0xdead_beef),
            current_version(),
            Vec::new(),
            action_data(),
            outer_value,
        )
    }

    fn authorization_test_signer() -> PrivateKeySigner {
        PrivateKeySigner::from_slice(&AUTHORIZATION_TEST_KEY).expect("valid test signer key")
    }

    fn other_authorization_test_signer() -> PrivateKeySigner {
        PrivateKeySigner::from_slice(&OTHER_AUTHORIZATION_TEST_KEY)
            .expect("valid other test signer key")
    }

    #[test]
    fn u64_nonce_domains_check_u256_boundaries() {
        let max = U256::from(u64::MAX);
        assert_eq!(
            Eip7702AuthorizationNonce::try_from(max)
                .expect("u64::MAX fits authorization nonce")
                .value(),
            u64::MAX
        );
        assert_eq!(
            Eip7702OuterTransactionNonce::try_from(max)
                .expect("u64::MAX fits outer transaction nonce")
                .value(),
            u64::MAX
        );

        let above_max = max + U256::from(1_u64);
        assert!(matches!(
            Eip7702AuthorizationNonce::try_from(above_max),
            Err(Eip7702NonceError::AuthorizationNonceOverflow)
        ));
        assert!(matches!(
            Eip7702OuterTransactionNonce::try_from(above_max),
            Err(Eip7702NonceError::OuterTransactionNonceOverflow)
        ));
    }

    #[test]
    fn execute_payload_hash_matches_namespaced_binding_arguments() {
        let transactions = Vec::<Transaction>::new();
        let action_data = RelayAdapt7702ActionData {
            requireSuccess: true,
            minGasLimit: U256::from(0x1234_u64),
            calls: vec![Call {
                to: address!("0x1111111111111111111111111111111111111111"),
                data: Bytes::from(vec![0xaa, 0xbb, 0xcc]),
                value: U256::from(7_u64),
            }],
        };
        let nonce = U256::from(29_u64);
        let current = RelayAdapt7702ExecutionVersion::CurrentNonceAware {
            nonce: RelayAdapt7702ExecutionNonce::new(nonce),
        };
        let legacy = RelayAdapt7702ExecutionVersion::LegacyPreExecuteNonce;

        let current_expected = keccak256(
            &RelayAdapt7702Current::getExecutePayloadHashCall {
                _transactions: transactions.clone(),
                _actionData: action_data.clone(),
                _executeNonce: nonce,
            }
            .abi_encode()[4..],
        );
        let legacy_expected = keccak256(
            &RelayAdapt7702Legacy::getExecutePayloadHashCall {
                _transactions: transactions.clone(),
                _actionData: action_data.clone(),
            }
            .abi_encode()[4..],
        );
        let current_hash = current.execute_payload_hash(&transactions, &action_data);
        let legacy_hash = legacy.execute_payload_hash(&transactions, &action_data);

        assert_eq!(current_hash, current_expected);
        assert_eq!(legacy_hash, legacy_expected);
        assert_ne!(current_hash, legacy_hash);
    }

    #[test]
    fn execute_encoding_is_version_exact_without_fallback() {
        let transactions = Vec::<Transaction>::new();
        let action_data = RelayAdapt7702ActionData {
            requireSuccess: false,
            minGasLimit: U256::from(0x5678_u64),
            calls: vec![Call {
                to: Address::from([0x22; 20]),
                data: Bytes::from(vec![0x01, 0x02]),
                value: U256::from(11_u64),
            }],
        };
        let current_nonce = U256::from(41_u64);
        let current_signature = Bytes::from(vec![0xa1, 0xa2, 0xa3]);
        let legacy_signature = Bytes::from(vec![0xb1, 0xb2, 0xb3]);
        let current = RelayAdapt7702ExecutionVersion::CurrentNonceAware {
            nonce: RelayAdapt7702ExecutionNonce::new(current_nonce),
        };
        let legacy = RelayAdapt7702ExecutionVersion::LegacyPreExecuteNonce;

        let current_encoded = current.encode_execute(
            transactions.clone(),
            action_data.clone(),
            current_signature.clone(),
        );
        assert_eq!(
            &current_encoded[..4],
            &RelayAdapt7702Current::executeCall::SELECTOR
        );
        let current_call = RelayAdapt7702Current::executeCall::abi_decode(&current_encoded)
            .expect("decode current execute call");
        assert!(current_call._transactions.is_empty());
        assert_eq!(
            current_call._actionData.requireSuccess,
            action_data.requireSuccess
        );
        assert_eq!(
            current_call._actionData.minGasLimit,
            action_data.minGasLimit
        );
        assert_eq!(
            current_call._actionData.calls.len(),
            action_data.calls.len()
        );
        assert_eq!(
            current_call._actionData.calls[0].to,
            action_data.calls[0].to
        );
        assert_eq!(
            current_call._actionData.calls[0].data,
            action_data.calls[0].data
        );
        assert_eq!(
            current_call._actionData.calls[0].value,
            action_data.calls[0].value
        );
        assert_eq!(current_call._executeNonce, current_nonce);
        assert_eq!(current_call._signature, current_signature);

        let legacy_encoded =
            legacy.encode_execute(transactions, action_data, legacy_signature.clone());
        assert_eq!(
            &legacy_encoded[..4],
            &RelayAdapt7702Legacy::executeCall::SELECTOR
        );
        let legacy_call = RelayAdapt7702Legacy::executeCall::abi_decode(&legacy_encoded)
            .expect("decode legacy execute call");
        assert!(legacy_call._transactions.is_empty());
        assert_eq!(
            legacy_call._actionData.abi_encode(),
            current_call._actionData.abi_encode()
        );
        assert_eq!(legacy_call._signature, legacy_signature);

        assert!(RelayAdapt7702Legacy::executeCall::abi_decode(&current_encoded).is_err());
        assert!(RelayAdapt7702Current::executeCall::abi_decode(&legacy_encoded).is_err());
    }

    #[test]
    fn preparation_derives_authorization_and_execution_typed_data() {
        let prepared = prepared(U256::ZERO);
        let expected_authorization = Authorization {
            chain_id: U256::from(1_337_u64),
            address: address!("0x2222222222222222222222222222222222222222"),
            nonce: 0xdead_beef,
        };

        assert_eq!(prepared.authorization(), &expected_authorization);
        assert_eq!(
            prepared.authorization_signing_hash(),
            expected_authorization.signature_hash()
        );

        let typed_data = prepared.execution_typed_data();
        assert_eq!(typed_data.domain().name.as_deref(), Some("RelayAdapt7702"));
        assert_eq!(typed_data.domain().version.as_deref(), Some("1"));
        assert_eq!(typed_data.domain().chain_id, Some(U256::from(1_337_u64)));
        assert_eq!(
            typed_data.domain().verifying_contract,
            Some(address!("0x1111111111111111111111111111111111111111"))
        );
        assert_eq!(typed_data.message().payloadHash, prepared.payload_hash());
        assert_eq!(
            typed_data.signing_hash(),
            typed_data
                .message()
                .eip712_signing_hash(typed_data.domain())
        );
        assert_eq!(prepared.execution_signing_hash(), typed_data.signing_hash());
    }

    #[test]
    fn preparation_uses_each_exact_execution_version_payload_path() {
        let transactions = Vec::new();
        let action_data = action_data();
        let current = PreparedRelayAdapt7702Execution::prepare(
            1_337,
            Address::ZERO,
            Address::ZERO,
            Eip7702AuthorizationNonce::new(1),
            current_version(),
            transactions.clone(),
            action_data.clone(),
            U256::ZERO,
        );
        let legacy = PreparedRelayAdapt7702Execution::prepare(
            1_337,
            Address::ZERO,
            Address::ZERO,
            Eip7702AuthorizationNonce::new(1),
            RelayAdapt7702ExecutionVersion::LegacyPreExecuteNonce,
            transactions.clone(),
            action_data.clone(),
            U256::ZERO,
        );

        assert_eq!(
            current.payload_hash(),
            current_version().execute_payload_hash(&transactions, &action_data)
        );
        assert_eq!(
            legacy.payload_hash(),
            RelayAdapt7702ExecutionVersion::LegacyPreExecuteNonce
                .execute_payload_hash(&transactions, &action_data)
        );
        assert_ne!(current.payload_hash(), legacy.payload_hash());
    }

    #[test]
    fn authorization_finalization_preserves_signed_tuple_and_recovers_authority() {
        let signer = authorization_test_signer();
        let prepared = prepared_for_authority(signer.address(), U256::ZERO);
        let signature = signer
            .sign_hash_sync(&prepared.authorization_signing_hash())
            .expect("sign authorization hash");

        let signed = prepared
            .finalize_authorization_signature(signature)
            .expect("finalize authorization signature");

        assert_eq!(signed.inner().chain_id, U256::from(1_337_u64));
        assert_eq!(signed.inner().address, prepared.delegate());
        assert_eq!(signed.inner().nonce, prepared.authorization_nonce().value());
        assert!(signed.y_parity() <= 1);
        assert_eq!(signed.r(), signature.r());
        assert_eq!(signed.s(), signature.s());
        let signed_signature = signed.signature().expect("recover signed tuple");
        assert_eq!(
            signed_signature
                .recover_address_from_prehash(&signed.inner().signature_hash())
                .expect("recover authority"),
            prepared.authority()
        );
    }

    #[test]
    fn signature_parity_conversions_preserve_r_and_s_at_each_boundary() {
        let authorization = Authorization {
            chain_id: U256::from(1_337_u64),
            address: address!("0x2222222222222222222222222222222222222222"),
            nonce: 7,
        };
        let r = U256::from(0x1234_u64);
        let s = U256::from(0x5678_u64);
        let r_bytes = r.to_be_bytes::<32>();
        let s_bytes = s.to_be_bytes::<32>();

        for parity in [false, true] {
            let signature = Signature::new(r, s, parity);
            let signed_authorization = authorization.clone().into_signed(signature);
            assert_eq!(signed_authorization.y_parity(), u8::from(parity));
            assert_eq!(signed_authorization.r(), r);
            assert_eq!(signed_authorization.s(), s);

            let electrum = signature.as_bytes();
            assert_eq!(&electrum[..32], r_bytes.as_slice());
            assert_eq!(&electrum[32..64], s_bytes.as_slice());
            assert_eq!(electrum[64], 27 + u8::from(parity));
        }
    }

    #[test]
    fn authorization_finalization_rejects_a_different_authority() {
        let signer = authorization_test_signer();
        let other_signer = other_authorization_test_signer();
        let prepared = prepared_for_authority(signer.address(), U256::ZERO);
        let signature = other_signer
            .sign_hash_sync(&prepared.authorization_signing_hash())
            .expect("sign authorization hash");

        assert_eq!(
            prepared.finalize_authorization_signature(signature),
            Err(Eip7702AuthorizationFinalizationError::AuthorityMismatch)
        );
    }

    #[test]
    fn authorization_finalization_rejects_high_s_before_recovery() {
        let signer = authorization_test_signer();
        let prepared = prepared_for_authority(signer.address(), U256::ZERO);
        let signature = signer
            .sign_hash_sync(&prepared.authorization_signing_hash())
            .expect("sign authorization hash");
        let high_s = Signature::new(
            signature.r(),
            super::SECP256K1N_HALF + U256::from(1_u64),
            signature.v(),
        );

        assert_eq!(
            prepared.finalize_authorization_signature(high_s),
            Err(Eip7702AuthorizationFinalizationError::HighS)
        );
    }

    #[test]
    fn authorization_finalization_maps_recovery_failure_without_output() {
        let prepared = prepared(U256::ZERO);
        let signature = Signature::new(U256::ZERO, U256::ZERO, false);

        assert_eq!(
            prepared.finalize_authorization_signature(signature),
            Err(Eip7702AuthorizationFinalizationError::InvalidSignature)
        );
    }

    #[test]
    fn authorization_finalization_errors_are_value_free() {
        let prohibited = [
            "1111111111111111111111111111111111111111",
            "2222222222222222222222222222222222222222",
            "deadbeef",
        ];
        let errors = [
            Eip7702AuthorizationFinalizationError::HighS,
            Eip7702AuthorizationFinalizationError::InvalidSignature,
            Eip7702AuthorizationFinalizationError::AuthorityMismatch,
        ];

        for error in errors {
            let rendered = format!("{error:?} {error}");
            for value in prohibited {
                assert!(!rendered.contains(value));
            }
        }
    }

    #[test]
    fn execution_finalization_preserves_signature_and_emits_electrum_calldata() {
        let signer = authorization_test_signer();
        let prepared = prepared_for_authority(signer.address(), U256::ZERO);
        let signature = signer
            .sign_hash_sync(&prepared.execution_signing_hash())
            .expect("sign execution hash");

        let finalized = prepared
            .finalize_execution_signature(signature)
            .expect("finalize execution signature");

        assert_eq!(finalized.signature(), &signature);
        assert_eq!(finalized.calldata().len(), 65);
        assert_eq!(
            finalized.calldata().as_ref(),
            signature.as_bytes().as_slice()
        );
        assert!(matches!(finalized.calldata()[64], 27 | 28));
        assert_eq!(finalized.calldata()[64], 27 + u8::from(signature.v()));
        assert_eq!(
            finalized
                .signature()
                .recover_address_from_prehash(&prepared.execution_signing_hash())
                .expect("recover execution authority"),
            prepared.authority()
        );
        assert_eq!(
            Signature::from_raw(finalized.calldata().as_ref()).expect("roundtrip raw signature"),
            signature
        );
        assert_eq!(
            Signature::try_from(finalized.calldata().as_ref())
                .expect("roundtrip TryFrom raw signature"),
            signature
        );
    }

    #[test]
    fn execution_finalization_rejects_a_different_authority() {
        let signer = authorization_test_signer();
        let other_signer = other_authorization_test_signer();
        let prepared = prepared_for_authority(signer.address(), U256::ZERO);
        let signature = other_signer
            .sign_hash_sync(&prepared.execution_signing_hash())
            .expect("sign execution hash");

        assert_eq!(
            prepared.finalize_execution_signature(signature),
            Err(Eip7702ExecutionFinalizationError::AuthorityMismatch)
        );
    }

    #[test]
    fn execution_finalization_rejects_high_s_before_recovery() {
        let signer = authorization_test_signer();
        let prepared = prepared_for_authority(signer.address(), U256::ZERO);
        let signature = signer
            .sign_hash_sync(&prepared.execution_signing_hash())
            .expect("sign execution hash");
        let high_s = Signature::new(
            signature.r(),
            super::SECP256K1N_HALF + U256::from(1_u64),
            signature.v(),
        );

        assert_eq!(
            prepared.finalize_execution_signature(high_s),
            Err(Eip7702ExecutionFinalizationError::HighS)
        );
    }

    #[test]
    fn execution_finalization_maps_recovery_failure_without_output() {
        let prepared = prepared(U256::ZERO);
        let signature = Signature::new(U256::ZERO, U256::ZERO, false);

        assert_eq!(
            prepared.finalize_execution_signature(signature),
            Err(Eip7702ExecutionFinalizationError::InvalidSignature)
        );
    }

    #[test]
    fn current_aggregate_finalization_emits_exact_namespaced_execute_call() {
        let signer = authorization_test_signer();
        let authority = signer.address();
        let delegate = address!("0x2222222222222222222222222222222222222222");
        let authorization_nonce = Eip7702AuthorizationNonce::new(0xdead_beef);
        let execution_version = current_version();
        let transactions = vec![transaction()];
        let action_data = action_data();
        let outer_value = U256::from(0xfeed_c0ffee_u64);
        let prepared = PreparedRelayAdapt7702Execution::prepare(
            1_337,
            authority,
            delegate,
            authorization_nonce,
            execution_version,
            transactions.clone(),
            action_data.clone(),
            outer_value,
        );
        let authorization_signature = signer
            .sign_hash_sync(&prepared.authorization_signing_hash())
            .expect("sign authorization hash");
        let execution_signature = signer
            .sign_hash_sync(&prepared.execution_signing_hash())
            .expect("sign execution hash");

        let finalized: FinalizedRelayAdapt7702Call = prepared
            .finalize(authorization_signature, execution_signature)
            .expect("finalize aggregate signatures");

        assert_eq!(finalized.to(), authority);
        assert_eq!(finalized.value(), outer_value);
        assert_eq!(
            finalized.authorization().inner().chain_id,
            U256::from(1_337_u64)
        );
        assert_eq!(finalized.authorization().inner().address, delegate);
        assert_eq!(
            finalized.authorization().inner().nonce,
            authorization_nonce.value()
        );

        let execution_calldata = Bytes::from(execution_signature.as_bytes());
        let expected_data = execution_version.encode_execute(
            transactions.clone(),
            action_data.clone(),
            execution_calldata.clone(),
        );
        assert_eq!(finalized.data(), &expected_data);

        let call = RelayAdapt7702Current::executeCall::abi_decode(finalized.data())
            .expect("decode current execute call");
        assert_eq!(call._transactions.len(), 1);
        assert_eq!(
            call._transactions[0].abi_encode(),
            transactions[0].abi_encode()
        );
        assert_eq!(call._actionData.abi_encode(), action_data.abi_encode());
        assert_eq!(call._executeNonce, U256::from(29_u64));
        assert_eq!(call._signature, execution_calldata);
    }

    #[test]
    fn legacy_aggregate_finalization_emits_legacy_call_without_fallback() {
        let signer = authorization_test_signer();
        let execution_version = RelayAdapt7702ExecutionVersion::LegacyPreExecuteNonce;
        let transactions = vec![transaction()];
        let action_data = action_data();
        let prepared = PreparedRelayAdapt7702Execution::prepare(
            1_337,
            signer.address(),
            address!("0x2222222222222222222222222222222222222222"),
            Eip7702AuthorizationNonce::new(0xdead_beef),
            execution_version,
            transactions.clone(),
            action_data.clone(),
            U256::ZERO,
        );
        let authorization_signature = signer
            .sign_hash_sync(&prepared.authorization_signing_hash())
            .expect("sign authorization hash");
        let execution_signature = signer
            .sign_hash_sync(&prepared.execution_signing_hash())
            .expect("sign execution hash");
        let finalized = prepared
            .finalize(authorization_signature, execution_signature)
            .expect("finalize legacy aggregate signatures");

        assert_eq!(
            &finalized.data()[..4],
            &RelayAdapt7702Legacy::executeCall::SELECTOR
        );
        let call = RelayAdapt7702Legacy::executeCall::abi_decode(finalized.data())
            .expect("decode legacy execute call");
        assert_eq!(call._transactions.len(), 1);
        assert_eq!(
            call._transactions[0].abi_encode(),
            transactions[0].abi_encode()
        );
        assert_eq!(call._actionData.abi_encode(), action_data.abi_encode());
        assert_eq!(
            call._signature,
            Bytes::from(finalized.execution_signature().as_bytes())
        );
        assert!(RelayAdapt7702Current::executeCall::abi_decode(finalized.data()).is_err());
    }

    #[test]
    fn aggregate_finalization_rejects_either_wrong_signature_without_output() {
        let signer = authorization_test_signer();
        let other_signer = other_authorization_test_signer();
        let prepared = prepared_for_authority(signer.address(), U256::ZERO);
        let authorization_signature = signer
            .sign_hash_sync(&prepared.authorization_signing_hash())
            .expect("sign authorization hash");
        let execution_signature = signer
            .sign_hash_sync(&prepared.execution_signing_hash())
            .expect("sign execution hash");
        let wrong_authorization_signature = other_signer
            .sign_hash_sync(&prepared.authorization_signing_hash())
            .expect("sign wrong authorization hash");
        let wrong_execution_signature = other_signer
            .sign_hash_sync(&prepared.execution_signing_hash())
            .expect("sign wrong execution hash");

        assert_eq!(
            prepared.finalize(wrong_authorization_signature, execution_signature),
            Err(Eip7702FinalizationError::Authorization(
                Eip7702AuthorizationFinalizationError::AuthorityMismatch
            ))
        );
        assert_eq!(
            prepared.finalize(authorization_signature, wrong_execution_signature),
            Err(Eip7702FinalizationError::Execution(
                Eip7702ExecutionFinalizationError::AuthorityMismatch
            ))
        );
    }

    #[test]
    fn aggregate_finalization_recomputes_canonical_values_not_cached_views() {
        let signer = authorization_test_signer();
        let mut prepared = prepared_for_authority(signer.address(), U256::ZERO);
        let authorization_signature = signer
            .sign_hash_sync(&prepared.authorization_signing_hash())
            .expect("sign authorization hash");
        let execution_signature = signer
            .sign_hash_sync(&prepared.execution_signing_hash())
            .expect("sign execution hash");

        prepared.payload_hash = B256::from([0xa1; 32]);
        prepared.authorization = Authorization {
            chain_id: U256::from(9_999_u64),
            address: Address::ZERO,
            nonce: 1,
        };
        prepared.authorization_signing_hash = B256::from([0xa2; 32]);
        prepared.execution_typed_data =
            super::canonical_execution_typed_data(9_999, Address::ZERO, B256::from([0xa3; 32]));
        prepared.execution_signing_hash = B256::from([0xa4; 32]);

        let finalized = prepared
            .finalize(authorization_signature, execution_signature)
            .expect("finalize from canonical private values");

        assert_eq!(finalized.to(), signer.address());
        assert_eq!(
            finalized.authorization().inner().chain_id,
            U256::from(1_337_u64)
        );
        assert_eq!(
            finalized.authorization().inner().address,
            prepared.delegate()
        );
        assert_eq!(
            finalized.authorization().inner().nonce,
            prepared.authorization_nonce().value()
        );
    }

    #[test]
    fn outer_fields_are_typed_and_do_not_change_reusable_authority_material() {
        let signer = authorization_test_signer();
        let prepared = prepared_for_authority(signer.address(), U256::ZERO);
        let authorization_signature = signer
            .sign_hash_sync(&prepared.authorization_signing_hash())
            .expect("sign authorization hash");
        let execution_signature = signer
            .sign_hash_sync(&prepared.execution_signing_hash())
            .expect("sign execution hash");
        let first_outer = RelayAdapt7702OuterTransactionFields::new(
            Eip7702OuterTransactionNonce::new(7),
            21_000,
            U256::from(100_u64),
            U256::from(2_u64),
        );
        let second_outer = RelayAdapt7702OuterTransactionFields::new(
            Eip7702OuterTransactionNonce::new(8),
            42_000,
            U256::from(200_u64),
            U256::from(3_u64),
        );

        let first_nonce: Eip7702OuterTransactionNonce = first_outer.nonce();
        assert_eq!(first_nonce.value(), 7);
        assert_eq!(first_outer.gas_limit(), 21_000);
        assert_eq!(first_outer.max_fee_per_gas(), U256::from(100_u64));
        assert_eq!(first_outer.max_priority_fee_per_gas(), U256::from(2_u64));
        assert_ne!(first_outer.nonce(), second_outer.nonce());
        assert_ne!(first_outer.gas_limit(), second_outer.gas_limit());
        assert_ne!(
            first_outer.max_fee_per_gas(),
            second_outer.max_fee_per_gas()
        );
        assert_ne!(
            first_outer.max_priority_fee_per_gas(),
            second_outer.max_priority_fee_per_gas()
        );
        assert_ne!(first_outer, second_outer);

        let first_call = prepared
            .finalize(authorization_signature, execution_signature)
            .expect("finalize first outer attempt");
        let second_call = prepared
            .finalize(authorization_signature, execution_signature)
            .expect("finalize second outer attempt");
        assert_eq!(first_call, second_call);
        assert_eq!(first_call.data(), second_call.data());
        assert_eq!(first_call.authorization(), second_call.authorization());
        let equivalent_prepared = prepared_for_authority(signer.address(), U256::ZERO);
        assert_eq!(
            prepared.authorization_signing_hash(),
            equivalent_prepared.authorization_signing_hash()
        );
        assert_eq!(
            prepared.execution_signing_hash(),
            equivalent_prepared.execution_signing_hash()
        );
        assert_eq!(prepared.payload_hash(), equivalent_prepared.payload_hash());
    }

    #[test]
    fn authorization_and_execution_nonce_domains_do_not_substitute() {
        let authority = address!("0x1111111111111111111111111111111111111111");
        let delegate = address!("0x2222222222222222222222222222222222222222");
        let prepare = |authorization_nonce: Eip7702AuthorizationNonce,
                       execution_nonce: RelayAdapt7702ExecutionNonce| {
            PreparedRelayAdapt7702Execution::prepare(
                1_337,
                authority,
                delegate,
                authorization_nonce,
                RelayAdapt7702ExecutionVersion::CurrentNonceAware {
                    nonce: execution_nonce,
                },
                Vec::new(),
                action_data(),
                U256::ZERO,
            )
        };

        let baseline = prepare(
            Eip7702AuthorizationNonce::new(7),
            RelayAdapt7702ExecutionNonce::new(U256::from(29_u64)),
        );
        let changed_authorization_nonce = prepare(
            Eip7702AuthorizationNonce::new(8),
            RelayAdapt7702ExecutionNonce::new(U256::from(29_u64)),
        );
        let changed_execution_nonce = prepare(
            Eip7702AuthorizationNonce::new(7),
            RelayAdapt7702ExecutionNonce::new(U256::from(30_u64)),
        );

        assert_ne!(
            baseline.authorization_signing_hash(),
            changed_authorization_nonce.authorization_signing_hash()
        );
        assert_eq!(
            baseline.payload_hash(),
            changed_authorization_nonce.payload_hash()
        );
        assert_eq!(
            baseline.execution_signing_hash(),
            changed_authorization_nonce.execution_signing_hash()
        );

        assert_eq!(
            baseline.authorization_signing_hash(),
            changed_execution_nonce.authorization_signing_hash()
        );
        assert_ne!(
            baseline.payload_hash(),
            changed_execution_nonce.payload_hash()
        );
        assert_ne!(
            baseline.execution_signing_hash(),
            changed_execution_nonce.execution_signing_hash()
        );
    }

    #[test]
    fn finalized_outer_and_aggregate_diagnostics_are_value_free() {
        let signer = authorization_test_signer();
        let prepared = prepared_for_authority(signer.address(), U256::from(0xfeed_c0ffee_u64));
        let authorization_signature = signer
            .sign_hash_sync(&prepared.authorization_signing_hash())
            .expect("sign authorization hash");
        let execution_signature = signer
            .sign_hash_sync(&prepared.execution_signing_hash())
            .expect("sign execution hash");
        let finalized = prepared
            .finalize(authorization_signature, execution_signature)
            .expect("finalize aggregate signatures");
        let outer = RelayAdapt7702OuterTransactionFields::new(
            Eip7702OuterTransactionNonce::new(0xcafe),
            0xbeef,
            U256::from(0x1234_u64),
            U256::from(0x5678_u64),
        );
        let finalized_debug = format!("{finalized:?}");
        let outer_debug = format!("{outer:?}");
        let prohibited = [
            format!("{:?}", finalized.to()),
            alloy::hex::encode(finalized.data()),
            alloy::hex::encode(authorization_signature.as_bytes()),
            alloy::hex::encode(execution_signature.as_bytes()),
            format!("{:?}", prepared.payload_hash()),
            format!("{:?}", finalized.value()),
            format!("{:?}", outer.nonce().value()),
            format!("{:?}", outer.gas_limit()),
            format!("{:?}", outer.max_fee_per_gas()),
            format!("{:?}", outer.max_priority_fee_per_gas()),
        ];

        assert!(finalized_debug.contains("calldata_len"));
        assert!(outer_debug.contains("outer-payer-fields"));
        assert!(!outer_debug.contains("signature"));
        for value in &prohibited {
            assert!(!finalized_debug.contains(value.as_str()));
            assert!(!outer_debug.contains(value.as_str()));
        }

        for error in [
            Eip7702FinalizationError::Authorization(
                Eip7702AuthorizationFinalizationError::AuthorityMismatch,
            ),
            Eip7702FinalizationError::Execution(
                Eip7702ExecutionFinalizationError::AuthorityMismatch,
            ),
        ] {
            let rendered = format!("{error:?} {error}");
            for value in &prohibited {
                assert!(!rendered.contains(value.as_str()));
            }
        }
    }

    #[test]
    fn finalized_execution_signature_debug_and_error_are_value_free() {
        let signer = authorization_test_signer();
        let prepared = prepared_for_authority(signer.address(), U256::ZERO);
        let signature = signer
            .sign_hash_sync(&prepared.execution_signing_hash())
            .expect("sign execution hash");
        let finalized = prepared
            .finalize_execution_signature(signature)
            .expect("finalize execution signature");
        let debug = format!("{finalized:?}");
        let prohibited = [
            alloy::hex::encode(signature.as_bytes()),
            format!("{:?}", prepared.execution_signing_hash()),
            format!("{:?}", prepared.authority()),
        ];

        assert!(debug.contains("category"));
        assert!(debug.contains("encoded_len"));
        for value in prohibited {
            assert!(!debug.contains(value.as_str()));
        }

        for error in [
            Eip7702ExecutionFinalizationError::HighS,
            Eip7702ExecutionFinalizationError::InvalidSignature,
            Eip7702ExecutionFinalizationError::AuthorityMismatch,
        ] {
            let rendered = format!("{error:?} {error}");
            assert!(!rendered.contains("1111111111111111111111111111111111111111"));
            assert!(!rendered.contains("deadbeef"));
        }
    }

    #[test]
    fn current_execute_and_multicall_signatures_are_type_isolated() {
        let signer = authorization_test_signer();
        let prepared = prepared_for_authority(signer.address(), U256::ZERO);
        let shared_nonce = match prepared.execution_version() {
            RelayAdapt7702ExecutionVersion::CurrentNonceAware { nonce } => nonce.value(),
            RelayAdapt7702ExecutionVersion::LegacyPreExecuteNonce => {
                panic!("current execution version required")
            }
        };
        let action_data = prepared.action_data().clone();
        let execute_payload_encoding = (
            prepared.transactions().to_vec(),
            action_data.clone(),
            shared_nonce,
        )
            .abi_encode_params();
        let multicall_payload_encoding =
            (action_data.requireSuccess, action_data.calls, shared_nonce).abi_encode_params();
        assert_ne!(execute_payload_encoding, multicall_payload_encoding);
        let execute_payload_hash = keccak256(execute_payload_encoding);
        let multicall_payload_hash = keccak256(multicall_payload_encoding);
        let execute = Execute {
            payloadHash: execute_payload_hash,
        };
        let multicall = Multicall {
            payloadHash: multicall_payload_hash,
        };
        let domain = prepared.execution_typed_data().domain();
        let execute_digest = execute.eip712_signing_hash(domain);
        let multicall_digest = multicall.eip712_signing_hash(domain);

        assert_eq!(Execute::eip712_root_type(), "Execute(bytes32 payloadHash)");
        assert_eq!(
            Multicall::eip712_root_type(),
            "Multicall(bytes32 payloadHash)"
        );
        assert_ne!(execute.eip712_type_hash(), multicall.eip712_type_hash());
        assert_ne!(execute_payload_hash, multicall_payload_hash);
        assert_ne!(execute_digest, multicall_digest);
        assert_eq!(execute_payload_hash, prepared.payload_hash());
        assert_eq!(execute_digest, prepared.execution_signing_hash());

        let execute_signature = signer
            .sign_hash_sync(&execute_digest)
            .expect("sign Execute digest");
        let multicall_signature = signer
            .sign_hash_sync(&multicall_digest)
            .expect("sign Multicall digest");

        assert_eq!(
            execute_signature
                .recover_address_from_prehash(&execute_digest)
                .expect("recover Execute authority"),
            signer.address()
        );
        assert_eq!(
            multicall_signature
                .recover_address_from_prehash(&multicall_digest)
                .expect("recover Multicall authority"),
            signer.address()
        );
        assert_ne!(
            execute_signature
                .recover_address_from_prehash(&multicall_digest)
                .ok(),
            Some(signer.address())
        );
        assert_ne!(
            multicall_signature
                .recover_address_from_prehash(&execute_digest)
                .ok(),
            Some(signer.address())
        );
    }

    #[test]
    fn outer_value_is_not_part_of_any_prepared_signable_hash() {
        let zero_value = prepared(U256::ZERO);
        let nonzero_value = prepared(U256::from(0xfeed_c0ffee_u64));

        assert_eq!(zero_value.outer_value(), U256::ZERO);
        assert_eq!(nonzero_value.outer_value(), U256::from(0xfeed_c0ffee_u64));
        assert_eq!(zero_value.payload_hash(), nonzero_value.payload_hash());
        assert_eq!(
            zero_value.authorization_signing_hash(),
            nonzero_value.authorization_signing_hash()
        );
        assert_eq!(
            zero_value.execution_signing_hash(),
            nonzero_value.execution_signing_hash()
        );
    }

    #[test]
    fn prepared_and_typed_data_debug_are_privacy_safe() {
        let prepared = prepared(U256::from(0xfeed_c0ffee_u64));
        let prepared_debug = format!("{prepared:?}");
        let typed_data_debug = format!("{:?}", prepared.execution_typed_data());
        let payload_debug = format!("{:?}", prepared.payload_hash());
        let authorization_hash_debug = format!("{:?}", prepared.authorization_signing_hash());
        let execution_hash_debug = format!("{:?}", prepared.execution_signing_hash());
        let outer_value_debug = format!("{:?}", prepared.outer_value());

        assert!(prepared_debug.contains("chain_id"));
        assert!(prepared_debug.contains("current"));
        assert!(prepared_debug.contains("transaction_count"));
        assert!(prepared_debug.contains("action_call_count"));
        assert!(typed_data_debug.contains("RelayAdapt7702"));
        assert!(typed_data_debug.contains("Execute"));
        assert!(!prepared_debug.contains("1111111111111111111111111111111111111111"));
        assert!(!prepared_debug.contains("2222222222222222222222222222222222222222"));
        assert!(!typed_data_debug.contains("1111111111111111111111111111111111111111"));
        assert!(!typed_data_debug.contains("2222222222222222222222222222222222222222"));
        assert!(!prepared_debug.contains("deadbeef"));
        assert!(!prepared_debug.contains("aabbcc"));
        assert!(!prepared_debug.contains(payload_debug.trim_start_matches("0x")));
        assert!(!prepared_debug.contains(authorization_hash_debug.trim_start_matches("0x")));
        assert!(!prepared_debug.contains(execution_hash_debug.trim_start_matches("0x")));
        assert!(!prepared_debug.contains(outer_value_debug.trim_start_matches("0x")));
        assert!(!typed_data_debug.contains(payload_debug.trim_start_matches("0x")));
        assert!(!typed_data_debug.contains(execution_hash_debug.trim_start_matches("0x")));
    }

    #[test]
    fn static_mit_vectors_match_rust_abi_hash_signature_and_recovery_paths() {
        let inputs = fixture_json(INPUTS_FIXTURE);
        let vectors = fixture_json(VECTORS_FIXTURE);
        let authority = PrivateKeySigner::from_slice(&[0x11; 32]).expect("valid vector signer");
        let authority_address = authority.address();
        let delegate = Address::from_str(
            vectors["inputs"]["delegate"]
                .as_str()
                .expect("delegate vector"),
        )
        .expect("valid delegate");
        let chain_id = vectors["inputs"]["chainId"]
            .as_str()
            .expect("chain id vector")
            .parse::<u64>()
            .expect("valid chain id");
        let authorization_nonce = vectors["inputs"]["authorizationNonce"]
            .as_str()
            .expect("authorization nonce vector")
            .parse::<u64>()
            .expect("valid authorization nonce");
        let execute_nonce = fixture_u256(&vectors["inputs"]["executeNonce"]);
        let transaction = fixture_transaction(&inputs["transactionAbiEncodingOnly"]["transaction"]);
        let action_data = fixture_action_data(&inputs["authorityActionData"]);
        let empty_action_data = fixture_action_data(&inputs["emptyBatch"]["actionData"]);
        let current = PreparedRelayAdapt7702Execution::prepare(
            chain_id,
            authority_address,
            delegate,
            Eip7702AuthorizationNonce::new(authorization_nonce),
            RelayAdapt7702ExecutionVersion::CurrentNonceAware {
                nonce: RelayAdapt7702ExecutionNonce::new(execute_nonce),
            },
            vec![transaction.clone()],
            action_data.clone(),
            fixture_u256(&inputs["protocol"]["outerValue"]),
        );
        let legacy = PreparedRelayAdapt7702Execution::prepare(
            chain_id,
            authority_address,
            delegate,
            Eip7702AuthorizationNonce::new(authorization_nonce),
            RelayAdapt7702ExecutionVersion::LegacyPreExecuteNonce,
            vec![transaction],
            action_data,
            U256::ZERO,
        );

        let authorization_vector = &vectors["authorization"];
        assert_eq!(
            current.authorization_signing_hash(),
            fixture_fixed32(&authorization_vector["signingHash"])
        );
        let authorization_signature = fixture_signature(&authorization_vector["signature"]);
        assert_fixture_hex(
            authorization_signature.as_bytes(),
            authorization_vector["signature"]["serialized"]
                .as_str()
                .expect("serialized authorization signature"),
        );
        assert!(matches!(
            authorization_vector["signature"]["yParity"].as_u64(),
            Some(0 | 1)
        ));
        let signed_authorization = current
            .finalize_authorization_signature(authorization_signature)
            .expect("finalize static authorization vector");
        assert_eq!(signed_authorization.inner().chain_id, U256::from(chain_id));
        assert_eq!(signed_authorization.inner().address, delegate);
        assert_eq!(signed_authorization.inner().nonce, authorization_nonce);
        assert_eq!(
            signed_authorization.r(),
            fixture_u256(&authorization_vector["signedTuple"]["r"])
        );
        assert_eq!(
            signed_authorization.s(),
            fixture_u256(&authorization_vector["signedTuple"]["s"])
        );
        assert_eq!(
            signed_authorization.y_parity(),
            authorization_vector["signedTuple"]["yParity"]
                .as_u64()
                .expect("authorization tuple parity") as u8
        );
        assert_eq!(
            27 + u64::from(signed_authorization.y_parity()),
            authorization_vector["signedTuple"]["electrumV"]
                .as_u64()
                .expect("authorization Electrum v")
        );
        let recovered_authority = signed_authorization
            .signature()
            .expect("recover authorization vector")
            .recover_address_from_prehash(&current.authorization_signing_hash())
            .expect("recover authorization authority");
        assert_eq!(recovered_authority, authority_address);
        assert_eq!(
            recovered_authority,
            Address::from_str(
                authorization_vector["signedTuple"]["recoveredAuthority"]
                    .as_str()
                    .expect("recovered authority vector"),
            )
            .expect("valid recovered authority vector")
        );

        let execute_type = Execute {
            payloadHash: current.payload_hash(),
        };
        assert_eq!(
            execute_type.eip712_type_hash(),
            fixture_fixed32(&vectors["execute"]["typehash"])
        );
        for (prepared, version_name) in [(&current, "current"), (&legacy, "legacy")] {
            let expected = &vectors["execute"][version_name];
            assert_eq!(
                prepared.payload_hash(),
                fixture_fixed32(&expected["payloadHash"])
            );
            assert_eq!(
                prepared.execution_signing_hash(),
                fixture_fixed32(&expected["digest"])
            );
            let selector_calldata = prepared.execution_version().encode_execute(
                prepared.transactions().to_vec(),
                prepared.action_data().clone(),
                Bytes::new(),
            );
            assert_fixture_hex(
                &selector_calldata[..4],
                expected["selector"].as_str().expect("execution selector"),
            );
            let signature = fixture_signature(&expected["signature"]);
            assert!(matches!(expected["signature"]["v"].as_u64(), Some(27 | 28)));
            let finalized = prepared
                .finalize_execution_signature(signature)
                .expect("finalize static Execute vector");
            assert_fixture_hex(
                finalized.calldata().as_ref(),
                expected["signature"]["serialized"]
                    .as_str()
                    .expect("serialized execution signature"),
            );
            let encoded = prepared.execution_version().encode_execute(
                prepared.transactions().to_vec(),
                prepared.action_data().clone(),
                finalized.calldata().clone(),
            );
            assert_fixture_hex(
                encoded.as_ref(),
                expected["calldata"].as_str().expect("execution calldata"),
            );
            assert_eq!(
                signature
                    .recover_address_from_prehash(&prepared.execution_signing_hash())
                    .expect("recover Execute authority"),
                authority_address
            );
        }

        let empty_current = PreparedRelayAdapt7702Execution::prepare(
            chain_id,
            authority_address,
            delegate,
            Eip7702AuthorizationNonce::new(authorization_nonce),
            RelayAdapt7702ExecutionVersion::CurrentNonceAware {
                nonce: RelayAdapt7702ExecutionNonce::new(execute_nonce),
            },
            Vec::new(),
            empty_action_data.clone(),
            U256::ZERO,
        );
        let empty_legacy = PreparedRelayAdapt7702Execution::prepare(
            chain_id,
            authority_address,
            delegate,
            Eip7702AuthorizationNonce::new(authorization_nonce),
            RelayAdapt7702ExecutionVersion::LegacyPreExecuteNonce,
            Vec::new(),
            empty_action_data.clone(),
            U256::ZERO,
        );
        for (prepared, version_name) in [(&empty_current, "current"), (&empty_legacy, "legacy")] {
            let expected = &vectors["emptyBatch"][version_name];
            assert_eq!(
                prepared.payload_hash(),
                fixture_fixed32(&expected["payloadHash"])
            );
            assert_eq!(
                prepared.execution_signing_hash(),
                fixture_fixed32(&expected["digest"])
            );
            let signature = fixture_signature(&expected["signature"]);
            let finalized = prepared
                .finalize_execution_signature(signature)
                .expect("finalize empty-batch Execute vector");
            let encoded = prepared.execution_version().encode_execute(
                Vec::new(),
                prepared.action_data().clone(),
                finalized.calldata().clone(),
            );
            assert_fixture_hex(
                encoded.as_ref(),
                expected["calldata"].as_str().expect("empty calldata"),
            );
        }

        let multicall_payload_hash = keccak256(
            (
                empty_action_data.requireSuccess,
                empty_action_data.calls,
                execute_nonce,
            )
                .abi_encode_params(),
        );
        let multicall_vector = &vectors["multicallTestOnly"];
        let multicall_type = Multicall {
            payloadHash: multicall_payload_hash,
        };
        assert_eq!(
            multicall_type.eip712_type_hash(),
            fixture_fixed32(&multicall_vector["typehash"])
        );
        assert_eq!(
            multicall_payload_hash,
            fixture_fixed32(&multicall_vector["payloadHash"])
        );
        let multicall_digest =
            multicall_type.eip712_signing_hash(current.execution_typed_data().domain());
        assert_eq!(
            multicall_digest,
            fixture_fixed32(&multicall_vector["digest"])
        );
        let multicall_signature = fixture_signature(&multicall_vector["signature"]);
        assert_fixture_hex(
            multicall_signature.as_bytes(),
            multicall_vector["signature"]["serialized"]
                .as_str()
                .expect("serialized Multicall signature"),
        );
        assert_eq!(
            multicall_signature
                .recover_address_from_prehash(&multicall_digest)
                .expect("recover Multicall authority"),
            authority_address
        );
        assert_ne!(
            fixture_signature(&vectors["execute"]["current"]["signature"])
                .recover_address_from_prehash(&multicall_digest)
                .expect("cross-type Execute recovery"),
            authority_address
        );
        assert_ne!(
            multicall_signature
                .recover_address_from_prehash(&current.execution_signing_hash())
                .expect("cross-type Multicall recovery"),
            authority_address
        );
        assert_eq!(
            fixture_signature(&vectors["execute"]["current"]["signature"])
                .recover_address_from_prehash(&multicall_digest)
                .expect("cross-type Execute recovery vector"),
            Address::from_str(
                multicall_vector["crossTypeRecovery"]["executeSignatureUnderMulticallDigest"]
                    .as_str()
                    .expect("cross-type Execute recovery vector"),
            )
            .expect("valid cross-type Execute recovery"),
        );
        assert_eq!(
            multicall_signature
                .recover_address_from_prehash(&current.execution_signing_hash())
                .expect("cross-type Multicall recovery vector"),
            Address::from_str(
                multicall_vector["crossTypeRecovery"]["multicallSignatureUnderExecuteDigest"]
                    .as_str()
                    .expect("cross-type Multicall recovery vector"),
            )
            .expect("valid cross-type Multicall recovery"),
        );

        assert_ne!(
            vectors["nonceSeparation"]["authorizationNonce"],
            vectors["nonceSeparation"]["executeNonce"]
        );
        assert_ne!(
            vectors["nonceSeparation"]["executeNonce"],
            vectors["nonceSeparation"]["outerPayerNonce"]
        );
        assert!(
            RelayAdapt7702Legacy::executeCall::abi_decode(&fixture_bytes(
                &vectors["execute"]["current"]["calldata"]
            ))
            .is_err()
        );
        assert!(
            RelayAdapt7702Current::executeCall::abi_decode(&fixture_bytes(
                &vectors["execute"]["legacy"]["calldata"]
            ))
            .is_err()
        );
    }
}
