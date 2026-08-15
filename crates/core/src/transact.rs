use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use alloy::eips::eip7702::SignedAuthorization;
use alloy::hex;
use alloy::primitives::{Address, Bytes, FixedBytes, U256};
use alloy::sol_types::{SolCall, SolValue};
use ruint::uint;

use crate::contracts::railgun::{
    ActionData, RelayAdapt7702ActionData, RelayAdapt7702Current, RelayAdapt7702Legacy, Transaction,
    relayCall, transactCall,
};
use crate::crypto::aes_gcm::{
    AesGcmError, decrypt_in_place_16b_iv, encrypt_in_place_16b_iv, split_iv_tag,
};
use crate::crypto::poseidon::poseidon;
use crate::crypto::shared_key::{ed25519_private_scalar_bytes, shared_symmetric_key};
use crate::eip7702::{
    FinalizedRelayAdapt7702Call, PreparedRelayAdapt7702Execution, RelayAdapt7702ExecutionNonce,
    RelayAdapt7702ExecutionVersion,
};
use crate::notes::Note;
use crate::tree::{TREE_DEPTH, TREE_LEAF_COUNT_U256};

#[derive(Debug, Error)]
pub enum TransactError {
    #[error("invalid ed25519 pubkey")]
    InvalidEd25519Pubkey,
    #[error("shared key error")]
    SharedKey,
    #[error("random generation failed")]
    Random,
    #[error(transparent)]
    AesGcm(#[from] AesGcmError),
    #[error("ivtag must be 32 bytes, got {len}")]
    InvalidIvTag { len: usize },
    #[error("calldata too short: {len}")]
    CalldataTooShort { len: usize },
    #[error("unknown function call: {selector}")]
    UnknownFunctionCall { selector: String },
    #[error("no transactions")]
    MissingTransactions,
    #[error("no commitment")]
    MissingCommitment,
    #[error("no commitment ciphertext")]
    MissingCommitmentCiphertext,
    #[error("plaintext too short: {len}")]
    PlaintextTooShort { len: usize },
    #[error("token hash invalid")]
    InvalidTokenHash,
    #[error("json parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("abi decode error: {0}")]
    AbiDecode(#[from] alloy::sol_types::Error),
    #[error("missing pre-transaction POI for required list key")]
    MissingPreTransactionPoiForAssurance,
    #[error("unsupported txid version: {txid_version}")]
    UnsupportedTxidVersion { txid_version: String },
}

#[non_exhaustive]
#[derive(Debug, Error)]
pub enum Transact7702Error {
    #[error(transparent)]
    Transact(#[from] TransactError),
    #[error("transact JSON serialization failed")]
    JsonSerialize,
    #[error("transact JSON deserialization failed")]
    JsonDeserialize,
    #[error("invalid EIP-7702 authorization parity")]
    InvalidAuthorizationParity,
    #[error("canonical EIP-7702 operation mismatch")]
    CanonicalOperationMismatch,
    #[error("strict TX7702 broadcaster policy rejected")]
    StrictBroadcasterPolicy,
}

/// Ed25519 pubkey (compressed Edwards Y) -> Montgomery u
fn ed25519_pub_to_montgomery_u(ed_pub: &[u8; 32]) -> Result<[u8; 32], TransactError> {
    let comp = CompressedEdwardsY(*ed_pub);
    let point = comp
        .decompress()
        .ok_or(TransactError::InvalidEd25519Pubkey)?;
    Ok(point.to_montgomery().to_bytes())
}

fn shared_key_32(
    viewing_priv_seed: &[u8; 32],
    client_ed_pub: &[u8; 32],
) -> Result<[u8; 32], TransactError> {
    let scalar = ed25519_private_scalar_bytes(viewing_priv_seed);
    let mont_u = ed25519_pub_to_montgomery_u(client_ed_pub)?;
    let secret = StaticSecret::from(scalar);
    let peer = X25519PublicKey::from(mont_u);
    Ok(secret.diffie_hellman(&peer).to_bytes())
}

fn shared_key_for_broadcaster(
    client_viewing_priv_seed: &[u8; 32],
    broadcaster_ed_pub: &[u8; 32],
) -> Result<[u8; 32], TransactError> {
    let scalar = ed25519_private_scalar_bytes(client_viewing_priv_seed);
    let mont_u = ed25519_pub_to_montgomery_u(broadcaster_ed_pub)?;
    let secret = StaticSecret::from(scalar);
    let peer = X25519PublicKey::from(mont_u);
    Ok(secret.diffie_hellman(&peer).to_bytes())
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BroadcasterRawParamsTransact {
    pub chain_type: u64,
    #[serde(rename = "chainID")]
    pub chain_id: u64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub transact_type: Option<BroadcasterTransactRequestType>,

    pub min_gas_price: Option<U256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_fee_per_gas: Option<U256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_priority_fee_per_gas: Option<U256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<BroadcasterAuthorization>,

    #[serde(rename = "feesID")]
    pub fees_id: Option<String>,
    pub to: Address,
    pub data: Bytes,
    pub broadcaster_viewing_key: FixedBytes<32>,

    // pub use_relay_adapt: bool,

    // pub min_version: Option<String>,
    // pub max_version: Option<String>,
    pub txid_version: Option<String>,

    #[serde(default)]
    #[serde(rename = "preTransactionPOIsPerTxidLeafPerList")]
    pub pre_transaction_pois_per_txid_leaf_per_list:
        BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PreTxPoi>>,
    // pub dev_log: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum BroadcasterTransactRequestType {
    #[serde(rename = "COMMON")]
    Common,
    #[serde(rename = "TX7702")]
    Tx7702,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BroadcasterAuthorization {
    pub address: Address,
    pub nonce: U256,
    pub chain_id: U256,
    pub signature: BroadcasterAuthorizationSignature,
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct BroadcasterAuthorizationSignature {
    pub v: u64,
    pub r: U256,
    pub s: U256,
}

const fn broadcaster_transact_type_category(
    transact_type: Option<BroadcasterTransactRequestType>,
) -> &'static str {
    match transact_type {
        None => "absent",
        Some(BroadcasterTransactRequestType::Common) => "common",
        Some(BroadcasterTransactRequestType::Tx7702) => "tx7702",
    }
}

impl fmt::Debug for BroadcasterRawParamsTransact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let poi_entry_count = self
            .pre_transaction_pois_per_txid_leaf_per_list
            .values()
            .map(BTreeMap::len)
            .sum::<usize>();

        formatter
            .debug_struct("BroadcasterRawParamsTransact")
            .field("chain_id", &self.chain_id)
            .field(
                "envelope_kind",
                &broadcaster_transact_type_category(self.transact_type),
            )
            .field("calldata_len", &self.data.len())
            .field(
                "poi_list_count",
                &self.pre_transaction_pois_per_txid_leaf_per_list.len(),
            )
            .field("poi_entry_count", &poi_entry_count)
            .field("min_gas_price_present", &self.min_gas_price.is_some())
            .field("max_fee_per_gas_present", &self.max_fee_per_gas.is_some())
            .field(
                "max_priority_fee_per_gas_present",
                &self.max_priority_fee_per_gas.is_some(),
            )
            .field("fees_id_present", &self.fees_id.is_some())
            .field("authorization_present", &self.authorization.is_some())
            .field("broadcaster_viewing_key_present", &true)
            .field("txid_version_present", &self.txid_version.is_some())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for BroadcasterAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BroadcasterAuthorization")
            .field("category", &"eip7702-authorization")
            .field("address_present", &true)
            .field("nonce_present", &true)
            .field("chain_id_present", &true)
            .field("signature_present", &true)
            .finish()
    }
}

impl fmt::Debug for BroadcasterAuthorizationSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BroadcasterAuthorizationSignature")
            .field("category", &"authorization-signature")
            .field("v_present", &true)
            .field("r_present", &true)
            .field("s_present", &true)
            .finish()
    }
}

const INVALID_DECIMAL_QUANTITY: &str = "invalid decimal quantity";

fn is_canonical_decimal(value: &str) -> bool {
    !value.is_empty()
        && (value == "0" || !value.starts_with('0'))
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn parse_strict_decimal<T>(value: &str) -> Result<T, ()>
where
    T: FromStr,
{
    if !is_canonical_decimal(value) {
        return Err(());
    }
    value.parse().map_err(|_| ())
}

struct StrictDecimalVisitor<T>(PhantomData<fn() -> T>);

impl<T> serde::de::Visitor<'_> for StrictDecimalVisitor<T>
where
    T: FromStr,
{
    type Value = T;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a canonical base-10 decimal string")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        parse_strict_decimal(value).map_err(|()| E::custom(INVALID_DECIMAL_QUANTITY))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(&value)
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Err(E::custom(INVALID_DECIMAL_QUANTITY))
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Err(E::custom(INVALID_DECIMAL_QUANTITY))
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Err(E::custom(INVALID_DECIMAL_QUANTITY))
    }

    fn visit_i128<E>(self, _value: i128) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Err(E::custom(INVALID_DECIMAL_QUANTITY))
    }

    fn visit_u128<E>(self, _value: u128) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Err(E::custom(INVALID_DECIMAL_QUANTITY))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Err(E::custom(INVALID_DECIMAL_QUANTITY))
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn serialize_u64_decimal<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&value.to_string())
}

fn deserialize_u64_decimal<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserializer.deserialize_any(StrictDecimalVisitor(PhantomData))
}

fn serialize_u256_decimal<S>(value: &U256, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&value.to_string())
}

fn deserialize_u256_decimal<'de, D>(deserializer: D) -> Result<U256, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserializer.deserialize_any(StrictDecimalVisitor(PhantomData))
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn serialize_electrum_v<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if matches!(*value, 27 | 28) {
        serializer.serialize_u64(*value)
    } else {
        Err(serde::ser::Error::custom(
            "EIP-7702 authorization v must be 27 or 28",
        ))
    }
}

struct ElectrumVVisitor;

impl serde::de::Visitor<'_> for ElectrumVVisitor {
    type Value = u64;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the numeric EIP-7702 authorization v value 27 or 28")
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if matches!(value, 27 | 28) {
            Ok(value)
        } else {
            Err(E::custom("EIP-7702 authorization v must be 27 or 28"))
        }
    }
}

fn deserialize_electrum_v<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserializer.deserialize_any(ElectrumVVisitor)
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum BroadcasterRawParamsTransact7702Type {
    #[serde(rename = "TX7702")]
    Tx7702,
}

impl fmt::Debug for BroadcasterRawParamsTransact7702Type {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("BroadcasterRawParamsTransact7702Type")
            .field(&"TX7702")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum BroadcasterRawParamsTransact7702SignatureType {
    #[serde(rename = "signature")]
    Signature,
}

impl fmt::Debug for BroadcasterRawParamsTransact7702SignatureType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("BroadcasterRawParamsTransact7702SignatureType")
            .field(&"signature")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BroadcasterRawParamsTransact7702AuthorizationSignature {
    #[serde(rename = "_type")]
    pub signature_type: BroadcasterRawParamsTransact7702SignatureType,
    #[serde(rename = "networkV")]
    pub network_v: (),
    pub r: FixedBytes<32>,
    pub s: FixedBytes<32>,
    #[serde(
        serialize_with = "serialize_electrum_v",
        deserialize_with = "deserialize_electrum_v"
    )]
    pub v: u64,
}

impl fmt::Debug for BroadcasterRawParamsTransact7702AuthorizationSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BroadcasterRawParamsTransact7702AuthorizationSignature")
            .field("category", &"ethers-signature")
            .field("type_present", &true)
            .field("network_v_present", &true)
            .field("r_present", &true)
            .field("s_present", &true)
            .field("v_present", &true)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BroadcasterRawParamsTransact7702Authorization {
    #[serde(with = "crate::serde_helpers::checksum_address")]
    pub address: Address,
    #[serde(
        serialize_with = "serialize_u256_decimal",
        deserialize_with = "deserialize_u256_decimal"
    )]
    pub chain_id: U256,
    #[serde(
        serialize_with = "serialize_u64_decimal",
        deserialize_with = "deserialize_u64_decimal"
    )]
    pub nonce: u64,
    pub signature: BroadcasterRawParamsTransact7702AuthorizationSignature,
}

impl TryFrom<&SignedAuthorization> for BroadcasterRawParamsTransact7702Authorization {
    type Error = Transact7702Error;

    fn try_from(value: &SignedAuthorization) -> Result<Self, Self::Error> {
        let v = match value.signature() {
            Ok(_) => 27 + u64::from(value.y_parity()),
            Err(_) => return Err(Transact7702Error::InvalidAuthorizationParity),
        };

        Ok(Self {
            address: value.inner().address,
            chain_id: value.inner().chain_id,
            nonce: value.inner().nonce,
            signature: BroadcasterRawParamsTransact7702AuthorizationSignature {
                signature_type: BroadcasterRawParamsTransact7702SignatureType::Signature,
                network_v: (),
                r: FixedBytes::from(value.r().to_be_bytes::<32>()),
                s: FixedBytes::from(value.s().to_be_bytes::<32>()),
                v,
            },
        })
    }
}

impl fmt::Debug for BroadcasterRawParamsTransact7702Authorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BroadcasterRawParamsTransact7702Authorization")
            .field("category", &"eip7702-authorization")
            .field("address_present", &true)
            .field("chain_id_present", &true)
            .field("nonce_present", &true)
            .field("signature_present", &true)
            .finish()
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BroadcasterRawParamsTransact7702 {
    pub transact_type: BroadcasterRawParamsTransact7702Type,
    pub txid_version: String,
    #[serde(with = "crate::serde_helpers::checksum_address")]
    pub to: Address,
    pub data: Bytes,
    pub broadcaster_viewing_key: FixedBytes<32>,
    #[serde(rename = "chainID")]
    pub chain_id: u64,
    pub chain_type: u64,
    #[serde(rename = "feesID")]
    pub fees_id: String,
    pub use_relay_adapt: bool,
    pub dev_log: bool,
    pub min_version: String,
    pub max_version: String,
    #[serde(rename = "preTransactionPOIsPerTxidLeafPerList")]
    pub pre_transaction_pois_per_txid_leaf_per_list:
        BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PreTxPoi>>,
    #[serde(
        serialize_with = "serialize_u64_decimal",
        deserialize_with = "deserialize_u64_decimal"
    )]
    pub gas_limit: u64,
    #[serde(
        serialize_with = "serialize_u256_decimal",
        deserialize_with = "deserialize_u256_decimal"
    )]
    pub max_fee_per_gas: U256,
    #[serde(
        serialize_with = "serialize_u256_decimal",
        deserialize_with = "deserialize_u256_decimal"
    )]
    pub max_priority_fee_per_gas: U256,
    pub authorization: BroadcasterRawParamsTransact7702Authorization,
}

impl fmt::Debug for BroadcasterRawParamsTransact7702 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let poi_entry_count = self
            .pre_transaction_pois_per_txid_leaf_per_list
            .values()
            .map(BTreeMap::len)
            .sum::<usize>();

        formatter
            .debug_struct("BroadcasterRawParamsTransact7702")
            .field("chain_id", &self.chain_id)
            .field("envelope_kind", &"tx7702")
            .field("calldata_len", &self.data.len())
            .field(
                "poi_list_count",
                &self.pre_transaction_pois_per_txid_leaf_per_list.len(),
            )
            .field("poi_entry_count", &poi_entry_count)
            .field("txid_version_present", &true)
            .field("fees_id_present", &true)
            .field("broadcaster_viewing_key_present", &true)
            .field("gas_limit_present", &true)
            .field("max_fee_per_gas_present", &true)
            .field("max_priority_fee_per_gas_present", &true)
            .field("authorization_present", &true)
            .finish_non_exhaustive()
    }
}

impl BroadcasterRawParamsTransact7702 {
    pub fn validate_finalized_operation(
        &self,
        prepared: &PreparedRelayAdapt7702Execution,
        finalized: &FinalizedRelayAdapt7702Call,
    ) -> Result<(), Transact7702Error> {
        if self.to != prepared.authority()
            || finalized.to() != prepared.authority()
            || self.to != finalized.to()
            || finalized.value() != prepared.outer_value()
        {
            return Err(Transact7702Error::CanonicalOperationMismatch);
        }

        let authorization = finalized.authorization().inner();
        if authorization.chain_id != U256::from(prepared.chain_id())
            || authorization.address != prepared.delegate()
            || authorization.nonce != prepared.authorization_nonce().value()
        {
            return Err(Transact7702Error::CanonicalOperationMismatch);
        }

        let expected_authorization =
            BroadcasterRawParamsTransact7702Authorization::try_from(finalized.authorization())
                .map_err(|_| Transact7702Error::CanonicalOperationMismatch)?;
        if self.authorization != expected_authorization {
            return Err(Transact7702Error::CanonicalOperationMismatch);
        }

        if self.data != finalized.data().clone() {
            return Err(Transact7702Error::CanonicalOperationMismatch);
        }

        let ParsedTransactEnvelope::RelayAdapt7702 {
            version,
            transactions,
            action_data,
            execution_signature: parsed_signature,
        } = parse_transact_envelope(&self.data)
            .map_err(|_| Transact7702Error::CanonicalOperationMismatch)?
        else {
            return Err(Transact7702Error::CanonicalOperationMismatch);
        };

        let execution_signature = Bytes::from(finalized.execution_signature().as_bytes());
        if version != prepared.execution_version() || parsed_signature != execution_signature {
            return Err(Transact7702Error::CanonicalOperationMismatch);
        }

        let expected_data = prepared.execution_version().encode_execute(
            prepared.transactions().to_vec(),
            prepared.action_data().clone(),
            execution_signature,
        );
        if finalized.data() != &expected_data {
            return Err(Transact7702Error::CanonicalOperationMismatch);
        }

        let prepared_values = (
            prepared.transactions().to_vec(),
            prepared.action_data().clone(),
        )
            .abi_encode_params();
        let parsed_values = (transactions, action_data).abi_encode_params();
        if parsed_values != prepared_values {
            return Err(Transact7702Error::CanonicalOperationMismatch);
        }

        Ok(())
    }

    pub fn validate_broadcaster_request(
        &self,
        prepared: &PreparedRelayAdapt7702Execution,
        finalized: &FinalizedRelayAdapt7702Call,
        viewing_privkey: &[u8; 32],
        receiver_master_public_key: U256,
        required_poi_list_keys: &[FixedBytes<32>],
    ) -> Result<ParsedTransactCalldata, Transact7702Error> {
        let chain_type = u8::try_from(self.chain_type)
            .map_err(|_| Transact7702Error::StrictBroadcasterPolicy)?;
        self.validate_finalized_operation(prepared, finalized)?;

        if !matches!(
            self.transact_type,
            BroadcasterRawParamsTransact7702Type::Tx7702
        ) || self.chain_id != prepared.chain_id()
            || self.authorization.chain_id != U256::from(self.chain_id)
            || finalized.value() != U256::ZERO
            || self.fees_id.is_empty()
            || self.gas_limit == 0
            || self.max_fee_per_gas.is_zero()
            || self.max_priority_fee_per_gas > self.max_fee_per_gas
        {
            return Err(Transact7702Error::StrictBroadcasterPolicy);
        }

        let mut parsed = parse_transact_calldata(
            &self.data,
            viewing_privkey,
            receiver_master_public_key,
            Some(&self.txid_version),
        )
        .map_err(|_| Transact7702Error::StrictBroadcasterPolicy)?;

        if required_poi_list_keys.is_empty() {
            parsed.fee_note_assurance = None;
        } else {
            let mut transaction_leaves = Vec::with_capacity(parsed.transactions.len());
            for transaction in &parsed.transactions {
                let leaf =
                    railgun_txid_leaf_hash(transaction.railgun_txid, transaction.utxo_tree_in);
                transaction_leaves.push((
                    FixedBytes::from(leaf.to_be_bytes::<32>()),
                    FixedBytes::from(dummy_txid_root(leaf).to_be_bytes::<32>()),
                ));
            }

            if !required_poi_list_keys.iter().all(|list_key| {
                self.pre_transaction_pois_per_txid_leaf_per_list
                    .get(list_key)
                    .is_some_and(|per_leaf| {
                        transaction_leaves.iter().all(|(leaf, expected_root)| {
                            per_leaf
                                .get(leaf)
                                .is_some_and(|poi| poi.txid_merkleroot == *expected_root)
                        })
                    })
            }) {
                return Err(Transact7702Error::StrictBroadcasterPolicy);
            }

            let txid_version = supported_txid_version(Some(&self.txid_version))
                .map_err(|_| Transact7702Error::StrictBroadcasterPolicy)?;
            parsed.fee_note_assurance = Some(FeeNoteAssuranceContext {
                chain_type,
                txid_version: txid_version.to_string(),
                railgun_txid: parsed.railgun_txid,
                utxo_tree_in: parsed.utxo_tree_in,
                fee_commitment: parsed.fee_commitment,
                fee_note_npk: parsed.fee_note_npk,
                pre_transaction_pois_per_txid_leaf_per_list: self
                    .pre_transaction_pois_per_txid_leaf_per_list
                    .clone(),
                required_poi_list_keys: required_poi_list_keys.to_vec(),
            });
        }

        Ok(parsed)
    }
}

#[derive(Clone)]
pub struct EncryptedTransactRequest {
    pub pubkey: [u8; 32],
    pub encrypted_data: [Bytes; 2],
    pub shared_key: [u8; 32],
}

fn encrypt_params_with_seed<T: Serialize>(
    broadcaster_viewing_pubkey: [u8; 32],
    params: &T,
    client_seed: [u8; 32],
) -> Result<EncryptedTransactRequest, TransactError> {
    let pubkey = SigningKey::from_bytes(&client_seed)
        .verifying_key()
        .to_bytes();
    let shared_key = shared_key_for_broadcaster(&client_seed, &broadcaster_viewing_pubkey)
        .map_err(|_| TransactError::SharedKey)?;
    let mut plaintext = serde_json::to_vec(params)
        .map_err(|_| TransactError::Json(legacy_json_serialize_error()))?;
    let iv_tag = encrypt_in_place_16b_iv(&shared_key, &mut plaintext)?;
    Ok(EncryptedTransactRequest {
        pubkey,
        encrypted_data: [Bytes::copy_from_slice(&iv_tag), Bytes::from(plaintext)],
        shared_key,
    })
}

fn encrypt_params_with_seed_7702<T: Serialize>(
    broadcaster_viewing_pubkey: [u8; 32],
    params: &T,
    client_seed: [u8; 32],
) -> Result<EncryptedTransactRequest, Transact7702Error> {
    let pubkey = SigningKey::from_bytes(&client_seed)
        .verifying_key()
        .to_bytes();
    let shared_key = shared_key_for_broadcaster(&client_seed, &broadcaster_viewing_pubkey)
        .map_err(Transact7702Error::from)?;
    let mut plaintext = serde_json::to_vec(params).map_err(|_| Transact7702Error::JsonSerialize)?;
    let iv_tag =
        encrypt_in_place_16b_iv(&shared_key, &mut plaintext).map_err(TransactError::from)?;
    Ok(EncryptedTransactRequest {
        pubkey,
        encrypted_data: [Bytes::copy_from_slice(&iv_tag), Bytes::from(plaintext)],
        shared_key,
    })
}

fn legacy_json_serialize_error() -> serde_json::Error {
    <serde_json::Error as serde::ser::Error>::custom("transact JSON serialization failed")
}

fn legacy_json_deserialize_error() -> serde_json::Error {
    <serde_json::Error as serde::de::Error>::custom("transact JSON deserialization failed")
}

impl EncryptedTransactRequest {
    pub fn encrypt(
        broadcaster_viewing_pubkey: [u8; 32],
        params: &BroadcasterRawParamsTransact,
    ) -> Result<Self, TransactError> {
        let mut client_seed = [0u8; 32];
        getrandom::fill(&mut client_seed).map_err(|_| TransactError::Random)?;
        Self::encrypt_with_seed(broadcaster_viewing_pubkey, params, client_seed)
    }

    pub fn encrypt_7702(
        broadcaster_viewing_pubkey: [u8; 32],
        params: &BroadcasterRawParamsTransact7702,
        prepared: &PreparedRelayAdapt7702Execution,
        finalized: &FinalizedRelayAdapt7702Call,
        viewing_privkey: &[u8; 32],
        receiver_master_public_key: U256,
        required_poi_list_keys: &[FixedBytes<32>],
    ) -> Result<Self, Transact7702Error> {
        params.validate_broadcaster_request(
            prepared,
            finalized,
            viewing_privkey,
            receiver_master_public_key,
            required_poi_list_keys,
        )?;
        let mut client_seed = [0u8; 32];
        getrandom::fill(&mut client_seed)
            .map_err(|_| Transact7702Error::from(TransactError::Random))?;
        encrypt_params_with_seed_7702(broadcaster_viewing_pubkey, params, client_seed)
    }

    pub fn encrypt_with_seed(
        broadcaster_viewing_pubkey: [u8; 32],
        params: &BroadcasterRawParamsTransact,
        client_seed: [u8; 32],
    ) -> Result<Self, TransactError> {
        encrypt_params_with_seed(broadcaster_viewing_pubkey, params, client_seed)
    }

    pub fn to_transact_payload(&self) -> Result<Vec<u8>, serde_json::Error> {
        let envelope = TransactEnvelope {
            method: "transact",
            params: TransactEnvelopeParams {
                pubkey: FixedBytes::from(self.pubkey),
                encrypted_data: &self.encrypted_data,
            },
        };
        serde_json::to_vec(&envelope)
    }
}

#[derive(Serialize)]
struct TransactEnvelope<'a> {
    method: &'static str,
    params: TransactEnvelopeParams<'a>,
}

#[derive(Serialize)]
struct TransactEnvelopeParams<'a> {
    pubkey: FixedBytes<32>,
    #[serde(rename = "encryptedData")]
    encrypted_data: &'a [Bytes; 2],
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreTxPoi {
    pub snark_proof: SnarkJsProof,
    pub txid_merkleroot: FixedBytes<32>,
    pub poi_merkleroots: Vec<FixedBytes<32>>,
    pub blinded_commitments_out: Vec<FixedBytes<32>>,
    pub railgun_txid_if_has_unshield: Bytes,
}

impl fmt::Debug for PreTxPoi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreTxPoi")
            .field("category", &"pre-transaction-poi")
            .field("snark_proof_present", &true)
            .field("txid_merkleroot_present", &true)
            .field("poi_merkleroot_count", &self.poi_merkleroots.len())
            .field(
                "blinded_commitment_count",
                &self.blinded_commitments_out.len(),
            )
            .field(
                "unshield_present",
                &!self.railgun_txid_if_has_unshield.is_empty(),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct SnarkJsProof {
    pub pi_a: [U256; 2],
    pub pi_b: [[U256; 2]; 2],
    pub pi_c: [U256; 2],
}

impl fmt::Debug for SnarkJsProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SnarkJsProof")
            .field("category", &"snark-js-proof")
            .finish()
    }
}

impl SnarkJsProof {
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            pi_a: [U256::ZERO; 2],
            pi_b: [[U256::ZERO; 2]; 2],
            pi_c: [U256::ZERO; 2],
        }
    }
}

pub struct DecryptedTransact {
    pub shared_key: [u8; 32],
    pub params: BroadcasterRawParamsTransact,
}

impl fmt::Debug for DecryptedTransact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecryptedTransact")
            .field("shared_key", &"<redacted>")
            .field("params", &self.params)
            .finish()
    }
}

pub struct DecryptedTransact7702 {
    pub shared_key: [u8; 32],
    pub params: BroadcasterRawParamsTransact7702,
}

impl fmt::Debug for DecryptedTransact7702 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecryptedTransact7702")
            .field("shared_key", &"<redacted>")
            .field("params", &self.params)
            .finish()
    }
}

pub enum DecryptedTransactRequest {
    Legacy(DecryptedTransact),
    Tx7702(DecryptedTransact7702),
}

impl fmt::Debug for DecryptedTransactRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Legacy(request) => formatter.debug_tuple("Legacy").field(request).finish(),
            Self::Tx7702(request) => formatter.debug_tuple("Tx7702").field(request).finish(),
        }
    }
}

pub fn try_decrypt_transact_request(
    viewing_priv_seed: &[u8; 32],
    pubkey: [u8; 32],
    encrypted_data: &[Bytes; 2],
) -> Result<Option<DecryptedTransact>, TransactError> {
    let Some((shared, params)) =
        decrypt_request::<BroadcasterRawParamsTransact>(viewing_priv_seed, pubkey, encrypted_data)?
    else {
        return Ok(None);
    };

    trace_decrypted_request(
        encrypted_data,
        broadcaster_transact_type_category(params.transact_type),
    );
    Ok(Some(DecryptedTransact {
        shared_key: shared,
        params,
    }))
}

pub fn try_decrypt_transact_request_7702(
    viewing_priv_seed: &[u8; 32],
    pubkey: [u8; 32],
    encrypted_data: &[Bytes; 2],
) -> Result<Option<DecryptedTransact7702>, Transact7702Error> {
    let Some((shared, params)) = decrypt_request_7702(viewing_priv_seed, pubkey, encrypted_data)?
    else {
        return Ok(None);
    };

    trace_decrypted_request(encrypted_data, "tx7702");
    Ok(Some(DecryptedTransact7702 {
        shared_key: shared,
        params,
    }))
}

pub fn try_decrypt_transact_request_dispatched(
    viewing_priv_seed: &[u8; 32],
    pubkey: [u8; 32],
    encrypted_data: &[Bytes; 2],
) -> Result<Option<DecryptedTransactRequest>, Transact7702Error> {
    let shared = shared_key_32(viewing_priv_seed, &pubkey).map_err(Transact7702Error::from)?;
    let Some(plaintext) =
        decrypt_authenticated_plaintext(&shared, &encrypted_data[0], encrypted_data[1].to_vec())?
    else {
        return Ok(None);
    };

    let request = match transact_dispatch_kind(&plaintext)? {
        TransactDispatchKind::Legacy => DecryptedTransactRequest::Legacy(DecryptedTransact {
            shared_key: shared,
            params: deserialize_transact_plaintext_7702(&plaintext)?,
        }),
        TransactDispatchKind::Tx7702 => DecryptedTransactRequest::Tx7702(DecryptedTransact7702 {
            shared_key: shared,
            params: deserialize_transact_plaintext_7702(&plaintext)?,
        }),
    };
    let envelope_kind = match &request {
        DecryptedTransactRequest::Legacy(decrypted) => {
            broadcaster_transact_type_category(decrypted.params.transact_type)
        }
        DecryptedTransactRequest::Tx7702(_) => "tx7702",
    };
    trace_decrypted_request(encrypted_data, envelope_kind);
    Ok(Some(request))
}

fn decrypt<T: serde::de::DeserializeOwned>(
    shared_key: &[u8; 32],
    ivtag: &[u8],
    ct: Vec<u8>,
) -> Result<Option<T>, TransactError> {
    let Some(plaintext) = decrypt_authenticated_plaintext(shared_key, ivtag, ct)? else {
        return Ok(None);
    };

    Ok(Some(deserialize_transact_plaintext(&plaintext)?))
}

fn decrypt_request<T: serde::de::DeserializeOwned>(
    viewing_priv_seed: &[u8; 32],
    pubkey: [u8; 32],
    encrypted_data: &[Bytes; 2],
) -> Result<Option<([u8; 32], T)>, TransactError> {
    let shared = shared_key_32(viewing_priv_seed, &pubkey).map_err(|_| TransactError::SharedKey)?;
    let params = decrypt::<T>(&shared, &encrypted_data[0], encrypted_data[1].to_vec())?;
    Ok(params.map(|params| (shared, params)))
}

fn decrypt_request_7702(
    viewing_priv_seed: &[u8; 32],
    pubkey: [u8; 32],
    encrypted_data: &[Bytes; 2],
) -> Result<Option<([u8; 32], BroadcasterRawParamsTransact7702)>, Transact7702Error> {
    let shared = shared_key_32(viewing_priv_seed, &pubkey).map_err(Transact7702Error::from)?;
    let params = decrypt_7702(&shared, &encrypted_data[0], encrypted_data[1].to_vec())?;
    Ok(params.map(|params| (shared, params)))
}

fn decrypt_7702(
    shared_key: &[u8; 32],
    ivtag: &[u8],
    ct: Vec<u8>,
) -> Result<Option<BroadcasterRawParamsTransact7702>, Transact7702Error> {
    let Some(plaintext) = decrypt_authenticated_plaintext(shared_key, ivtag, ct)? else {
        return Ok(None);
    };

    Ok(Some(deserialize_transact_plaintext_7702(&plaintext)?))
}

fn trace_decrypted_request(encrypted_data: &[Bytes; 2], envelope_kind: &'static str) {
    let encrypted_total_len = encrypted_data
        .iter()
        .map(|bytes| bytes.len())
        .sum::<usize>();
    tracing::debug!(
        envelope_kind = envelope_kind,
        encrypted_part_count = encrypted_data.len(),
        encrypted_total_len,
        "decrypting transact request"
    );
}

fn decrypt_authenticated_plaintext(
    shared_key: &[u8; 32],
    ivtag: &[u8],
    ct: Vec<u8>,
) -> Result<Option<Vec<u8>>, TransactError> {
    let mut ct = ct;
    if ivtag.len() != 32 {
        return Err(TransactError::InvalidIvTag { len: ivtag.len() });
    }
    let iv = ivtag[..16]
        .try_into()
        .map_err(|_| TransactError::InvalidIvTag { len: ivtag.len() })?;
    let tag = ivtag[16..]
        .try_into()
        .map_err(|_| TransactError::InvalidIvTag { len: ivtag.len() })?;

    match decrypt_in_place_16b_iv(shared_key, &iv, &tag, &mut ct) {
        Ok(()) => {}
        Err(AesGcmError::DecryptFailed) => return Ok(None),
        Err(err) => return Err(err.into()),
    }

    tracing::debug!(
        plaintext_category = "broadcaster-transact-params",
        plaintext_len = ct.len(),
        "deserializing transact plaintext"
    );
    Ok(Some(ct))
}

fn deserialize_transact_plaintext<T: serde::de::DeserializeOwned>(
    plaintext: &[u8],
) -> Result<T, TransactError> {
    serde_json::from_slice(plaintext)
        .map_err(|_| TransactError::Json(legacy_json_deserialize_error()))
}

fn deserialize_transact_plaintext_7702<T: serde::de::DeserializeOwned>(
    plaintext: &[u8],
) -> Result<T, Transact7702Error> {
    serde_json::from_slice(plaintext).map_err(|_| Transact7702Error::JsonDeserialize)
}

enum TransactDispatchKind {
    Legacy,
    Tx7702,
}

fn data_starts_with_selector(data: &str, selector: [u8; 4]) -> bool {
    let data = data
        .strip_prefix("0x")
        .or_else(|| data.strip_prefix("0X"))
        .unwrap_or(data);
    data.get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(&hex::encode(selector)))
}

fn transact_dispatch_kind(plaintext: &[u8]) -> Result<TransactDispatchKind, Transact7702Error> {
    let object: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(plaintext).map_err(|_| Transact7702Error::JsonDeserialize)?;
    let has_strict_only_marker = object.contains_key("gasLimit")
        || object
            .get("data")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|data| {
                data_starts_with_selector(data, RelayAdapt7702Current::executeCall::SELECTOR)
                    || data_starts_with_selector(data, RelayAdapt7702Legacy::executeCall::SELECTOR)
            });
    let Some(value) = object.get("transactType") else {
        if has_strict_only_marker {
            return Err(Transact7702Error::JsonDeserialize);
        }
        return Ok(TransactDispatchKind::Legacy);
    };
    let transact_type: BroadcasterTransactRequestType =
        serde_json::from_value(value.clone()).map_err(|_| Transact7702Error::JsonDeserialize)?;
    match transact_type {
        BroadcasterTransactRequestType::Common => {
            if has_strict_only_marker {
                Err(Transact7702Error::JsonDeserialize)
            } else {
                Ok(TransactDispatchKind::Legacy)
            }
        }
        BroadcasterTransactRequestType::Tx7702 => Ok(TransactDispatchKind::Tx7702),
    }
}

pub const MERKLE_ZERO_VALUE: U256 =
    uint!(2051258411002736885948763699317990061539314419500486054347250703186609807356_U256);

pub const DEFAULT_TXID_VERSION: &str = "V2_PoseidonMerkle";
pub const RAILGUN_TXID_PARTS_WIDTH: usize = 13;
pub const PRE_TRANSACTION_POI_TREE: U256 = uint!(199_999_U256);
pub const PRE_TRANSACTION_POI_POSITION: U256 = uint!(199_999_U256);

#[must_use]
pub fn pad_with_merkle_zero(mut v: Vec<U256>, target: usize) -> Vec<U256> {
    while v.len() < target {
        v.push(MERKLE_ZERO_VALUE);
    }
    v.truncate(target);
    v
}

fn compute_railgun_txid_poseidon(tx0: &Transaction) -> U256 {
    let nullifiers: Vec<U256> = tx0
        .nullifiers
        .iter()
        .map(|b| U256::from_be_bytes(b.0))
        .collect();

    let commitments: Vec<U256> = tx0
        .commitments
        .iter()
        .map(|b| U256::from_be_bytes(b.0))
        .collect();

    compute_railgun_txid_parts(&nullifiers, &commitments, tx0.boundParams.hash())
}

#[must_use]
pub fn compute_railgun_txid_parts(
    nullifiers: &[U256],
    commitments: &[U256],
    bound_params_hash: U256,
) -> U256 {
    let nullifiers_hash = poseidon(pad_with_merkle_zero(
        nullifiers.to_vec(),
        RAILGUN_TXID_PARTS_WIDTH,
    ));
    let commitments_hash = poseidon(pad_with_merkle_zero(
        commitments.to_vec(),
        RAILGUN_TXID_PARTS_WIDTH,
    ));

    poseidon(vec![nullifiers_hash, commitments_hash, bound_params_hash])
}

#[must_use]
pub fn txid_version_or_default(txid_version: Option<&str>) -> &str {
    txid_version.unwrap_or(DEFAULT_TXID_VERSION)
}

pub fn supported_txid_version(txid_version: Option<&str>) -> Result<&str, TransactError> {
    let txid_version = txid_version_or_default(txid_version);
    if txid_version == DEFAULT_TXID_VERSION {
        Ok(txid_version)
    } else {
        Err(TransactError::UnsupportedTxidVersion {
            txid_version: txid_version.to_string(),
        })
    }
}

pub fn compute_railgun_txid(
    tx0: &Transaction,
    txid_version: Option<&str>,
) -> Result<U256, TransactError> {
    let _txid_version = supported_txid_version(txid_version)?;
    Ok(compute_railgun_txid_poseidon(tx0))
}

#[must_use]
pub fn railgun_txid_leaf_hash(railgun_txid: U256, utxo_tree_in: u64) -> U256 {
    railgun_txid_leaf_hash_with_output_start(
        railgun_txid,
        utxo_tree_in,
        pre_transaction_output_global_position(),
    )
}

#[must_use]
pub fn railgun_txid_leaf_hash_with_output_start(
    railgun_txid: U256,
    utxo_tree_in: u64,
    output_start_global: U256,
) -> U256 {
    poseidon(vec![
        railgun_txid,
        U256::from(utxo_tree_in),
        output_start_global,
    ])
}

#[must_use]
pub fn pre_transaction_output_global_position() -> U256 {
    PRE_TRANSACTION_POI_TREE * TREE_LEAF_COUNT_U256 + PRE_TRANSACTION_POI_POSITION
}

#[must_use]
pub fn dummy_txid_root(leaf: U256) -> U256 {
    let mut acc = leaf;
    for _ in 0..TREE_DEPTH {
        acc = poseidon(vec![acc, U256::ZERO]);
    }
    acc
}

#[derive(Clone, Serialize, Deserialize)]
pub struct FeeNoteAssuranceContext {
    pub chain_type: u8,
    pub txid_version: String,
    pub railgun_txid: U256,
    pub utxo_tree_in: u64,
    pub fee_commitment: FixedBytes<32>,
    pub fee_note_npk: FixedBytes<32>,
    pub pre_transaction_pois_per_txid_leaf_per_list:
        BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PreTxPoi>>,
    pub required_poi_list_keys: Vec<FixedBytes<32>>,
}

impl fmt::Debug for FeeNoteAssuranceContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FeeNoteAssuranceContext")
            .field("category", &"fee-note-assurance")
            .field("chain_type", &self.chain_type)
            .field("txid_version_category", &self.txid_version)
            .field(
                "poi_list_count",
                &self.pre_transaction_pois_per_txid_leaf_per_list.len(),
            )
            .field(
                "required_poi_list_count",
                &self.required_poi_list_keys.len(),
            )
            .finish_non_exhaustive()
    }
}

pub struct ParsedTransactTransaction {
    pub railgun_txid: U256,
    pub utxo_tree_in: u64,
    pub tx_nullifiers_len: usize,
    pub tx_commitments_out_len: usize,
    pub has_unshield: bool,
}

impl fmt::Debug for ParsedTransactTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParsedTransactTransaction")
            .field("tx_nullifier_count", &self.tx_nullifiers_len)
            .field("tx_commitment_output_count", &self.tx_commitments_out_len)
            .field("has_unshield", &self.has_unshield)
            .finish_non_exhaustive()
    }
}

pub struct ParsedTransactCalldata {
    pub fee_token: Address,
    pub fee_amount: U256,
    pub railgun_txid: U256,
    pub utxo_tree_in: u64,
    pub fee_commitment: FixedBytes<32>,
    pub fee_note_npk: FixedBytes<32>,
    pub tx_nullifiers_len: usize,
    pub tx_commitments_out_len: usize,
    pub transactions: Vec<ParsedTransactTransaction>,
    pub action_data: Option<ActionData>,
    pub fee_note_assurance: Option<FeeNoteAssuranceContext>,
}

impl fmt::Debug for ParsedTransactCalldata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParsedTransactCalldata")
            .field("transaction_count", &self.transactions.len())
            .field("tx_nullifier_count", &self.tx_nullifiers_len)
            .field("tx_commitment_output_count", &self.tx_commitments_out_len)
            .field("action_data_present", &self.action_data.is_some())
            .field(
                "fee_note_assurance_present",
                &self.fee_note_assurance.is_some(),
            )
            .finish_non_exhaustive()
    }
}

impl ParsedTransactCalldata {
    pub fn attach_fee_note_assurance_context(
        &mut self,
        params: &BroadcasterRawParamsTransact,
        required_poi_list_keys: &[FixedBytes<32>],
    ) -> Result<(), TransactError> {
        if required_poi_list_keys.is_empty() {
            self.fee_note_assurance = None;
            return Ok(());
        }

        let txid_version = supported_txid_version(params.txid_version.as_deref())?;

        let leaf = railgun_txid_leaf_hash(self.railgun_txid, self.utxo_tree_in);
        let leaf_hex: FixedBytes<32> = leaf.into();

        if !required_poi_list_keys.iter().all(|list_key| {
            params
                .pre_transaction_pois_per_txid_leaf_per_list
                .get(list_key)
                .is_some_and(|per_list| per_list.contains_key(&leaf_hex))
        }) {
            return Err(TransactError::MissingPreTransactionPoiForAssurance);
        }

        self.fee_note_assurance = Some(FeeNoteAssuranceContext {
            chain_type: params.chain_type as u8,
            txid_version: txid_version.to_string(),
            railgun_txid: self.railgun_txid,
            utxo_tree_in: self.utxo_tree_in,
            fee_commitment: self.fee_commitment,
            fee_note_npk: self.fee_note_npk,
            pre_transaction_pois_per_txid_leaf_per_list: params
                .pre_transaction_pois_per_txid_leaf_per_list
                .clone(),
            required_poi_list_keys: required_poi_list_keys.to_vec(),
        });

        Ok(())
    }
}

impl ParsedTransactTransaction {
    fn from_transaction(
        transaction: &Transaction,
        txid_version: Option<&str>,
    ) -> Result<Self, TransactError> {
        let railgun_txid = compute_railgun_txid(transaction, txid_version)?;
        Ok(Self {
            railgun_txid,
            utxo_tree_in: transaction.boundParams.treeNumber.into(),
            tx_nullifiers_len: transaction.nullifiers.len(),
            tx_commitments_out_len: transaction.commitments.len(),
            has_unshield: transaction.boundParams.unshield != 0,
        })
    }
}

#[derive(Clone)]
pub enum ParsedTransactEnvelope {
    Direct {
        transactions: Vec<Transaction>,
    },
    LegacyRelay {
        transactions: Vec<Transaction>,
        action_data: ActionData,
    },
    RelayAdapt7702 {
        version: RelayAdapt7702ExecutionVersion,
        transactions: Vec<Transaction>,
        action_data: RelayAdapt7702ActionData,
        execution_signature: Bytes,
    },
}

impl fmt::Debug for ParsedTransactEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, transaction_count, action_call_count, execution_nonce_present, signature_len) =
            match self {
                Self::Direct { transactions } => ("direct", transactions.len(), 0, false, None),
                Self::LegacyRelay {
                    transactions,
                    action_data,
                } => (
                    "legacy-relay",
                    transactions.len(),
                    action_data.calls.len(),
                    false,
                    None,
                ),
                Self::RelayAdapt7702 {
                    version,
                    transactions,
                    action_data,
                    execution_signature,
                } => (
                    "relay-adapt-7702",
                    transactions.len(),
                    action_data.calls.len(),
                    matches!(
                        version,
                        RelayAdapt7702ExecutionVersion::CurrentNonceAware { .. }
                    ),
                    Some(execution_signature.len()),
                ),
            };

        formatter
            .debug_struct("ParsedTransactEnvelope")
            .field("kind", &kind)
            .field("transaction_count", &transaction_count)
            .field("action_call_count", &action_call_count)
            .field("execution_nonce_present", &execution_nonce_present)
            .field("execution_signature_present", &signature_len.is_some())
            .field("execution_signature_encoded_len", &signature_len)
            .finish()
    }
}

/// Parses calldata into its recognized transaction envelope.
///
/// # Panics
///
/// Panics if the four-byte selector cannot be converted into an array after
/// the calldata length check, indicating that an internal length invariant was
/// violated.
pub fn parse_transact_envelope(calldata: &[u8]) -> Result<ParsedTransactEnvelope, TransactError> {
    if calldata.len() < 4 {
        return Err(TransactError::CalldataTooShort {
            len: calldata.len(),
        });
    }

    let selector: [u8; 4] = calldata[..4]
        .try_into()
        .expect("calldata length checked above");
    match selector {
        transactCall::SELECTOR => Ok(ParsedTransactEnvelope::Direct {
            transactions: transactCall::abi_decode(calldata)?._transactions,
        }),
        relayCall::SELECTOR => {
            let call = relayCall::abi_decode(calldata)?;
            Ok(ParsedTransactEnvelope::LegacyRelay {
                transactions: call._transactions,
                action_data: call._actionData,
            })
        }
        RelayAdapt7702Current::executeCall::SELECTOR => {
            let call = RelayAdapt7702Current::executeCall::abi_decode(calldata)?;
            Ok(ParsedTransactEnvelope::RelayAdapt7702 {
                version: RelayAdapt7702ExecutionVersion::CurrentNonceAware {
                    nonce: RelayAdapt7702ExecutionNonce::new(call._executeNonce),
                },
                transactions: call._transactions,
                action_data: call._actionData,
                execution_signature: call._signature,
            })
        }
        RelayAdapt7702Legacy::executeCall::SELECTOR => {
            let call = RelayAdapt7702Legacy::executeCall::abi_decode(calldata)?;
            Ok(ParsedTransactEnvelope::RelayAdapt7702 {
                version: RelayAdapt7702ExecutionVersion::LegacyPreExecuteNonce,
                transactions: call._transactions,
                action_data: call._actionData,
                execution_signature: call._signature,
            })
        }
        _ => Err(TransactError::UnknownFunctionCall {
            selector: hex::encode(selector),
        }),
    }
}

pub fn parse_transact_calldata(
    calldata: &[u8],
    viewing_privkey: &[u8; 32],
    receiver_master_public_key: U256,
    txid_version: Option<&str>,
) -> Result<ParsedTransactCalldata, TransactError> {
    if calldata.len() < 4 {
        return Err(TransactError::CalldataTooShort {
            len: calldata.len(),
        });
    }
    let (transactions, action_data) = match parse_transact_envelope(calldata)? {
        ParsedTransactEnvelope::Direct { transactions } => (transactions, None),
        ParsedTransactEnvelope::LegacyRelay {
            transactions,
            action_data,
        } => (transactions, Some(action_data)),
        ParsedTransactEnvelope::RelayAdapt7702 {
            transactions,
            action_data,
            ..
        } => (
            transactions,
            Some(ActionData {
                random: FixedBytes::ZERO,
                requireSuccess: action_data.requireSuccess,
                minGasLimit: action_data.minGasLimit,
                calls: action_data.calls,
            }),
        ),
    };

    let tx0 = transactions
        .first()
        .ok_or(TransactError::MissingTransactions)?;
    let parsed_transactions = transactions
        .iter()
        .map(|transaction| ParsedTransactTransaction::from_transaction(transaction, txid_version))
        .collect::<Result<Vec<_>, _>>()?;

    let Some(tx0_metadata) = parsed_transactions.first() else {
        return Err(TransactError::MissingTransactions);
    };
    let railgun_txid = tx0_metadata.railgun_txid;
    let utxo_tree_in = tx0_metadata.utxo_tree_in;
    let fee_commitment = tx0
        .commitments
        .first()
        .copied()
        .ok_or(TransactError::MissingCommitment)?;

    let cc0 = tx0
        .boundParams
        .commitmentCiphertext
        .first()
        .ok_or(TransactError::MissingCommitmentCiphertext)?;

    let (iv, tag) = split_iv_tag(cc0.ciphertext[0].0);

    let mut ct = Vec::with_capacity(32 * 3 + cc0.memo.len());
    ct.extend_from_slice(&cc0.ciphertext[1].0);
    ct.extend_from_slice(&cc0.ciphertext[2].0);
    ct.extend_from_slice(&cc0.ciphertext[3].0);
    ct.extend_from_slice(&cc0.memo);

    let blinded_sender = cc0.blindedSenderViewingKey.0;
    let key = shared_symmetric_key(viewing_privkey, &blinded_sender)
        .map_err(|_| TransactError::InvalidEd25519Pubkey)?;

    decrypt_in_place_16b_iv(&key, &iv, &tag, &mut ct)?;

    if ct.len() < 96 {
        return Err(TransactError::PlaintextTooShort { len: ct.len() });
    }

    let mut token_hash = [0u8; 32];
    token_hash.copy_from_slice(&ct[32..64]);
    let mut random = [0u8; 16];
    random.copy_from_slice(&ct[64..80]);
    let mut value_bytes = [0u8; 16];
    value_bytes.copy_from_slice(&ct[80..96]);

    if token_hash[..12] != [0u8; 12] {
        return Err(TransactError::InvalidTokenHash);
    }
    let fee_token = Address::from_slice(&token_hash[12..32]);
    let fee_amount = U256::from_be_slice(&value_bytes);
    let fee_note_npk: FixedBytes<32> = Note::npk_for(receiver_master_public_key, random).into();

    Ok(ParsedTransactCalldata {
        fee_token,
        fee_amount,
        railgun_txid,
        utxo_tree_in,
        fee_commitment,
        fee_note_npk,
        tx_nullifiers_len: tx0_metadata.tx_nullifiers_len,
        tx_commitments_out_len: tx0_metadata.tx_commitments_out_len,
        transactions: parsed_transactions,
        action_data,
        fee_note_assurance: None,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        BroadcasterAuthorization, BroadcasterAuthorizationSignature, BroadcasterRawParamsTransact,
        BroadcasterRawParamsTransact7702, BroadcasterRawParamsTransact7702Authorization,
        BroadcasterRawParamsTransact7702AuthorizationSignature,
        BroadcasterRawParamsTransact7702SignatureType, BroadcasterRawParamsTransact7702Type,
        BroadcasterTransactRequestType, DEFAULT_TXID_VERSION, DecryptedTransact,
        DecryptedTransactRequest, EncryptedTransactRequest, FeeNoteAssuranceContext,
        ParsedTransactCalldata, ParsedTransactEnvelope, ParsedTransactTransaction, PreTxPoi,
        SnarkJsProof, Transact7702Error, TransactError, compute_railgun_txid, decrypt,
        decrypt_authenticated_plaintext, dummy_txid_root, encrypt_params_with_seed,
        encrypt_params_with_seed_7702, parse_transact_calldata, parse_transact_envelope,
        railgun_txid_leaf_hash, try_decrypt_transact_request, try_decrypt_transact_request_7702,
        try_decrypt_transact_request_dispatched,
    };
    use crate::contracts::railgun::{
        ActionData, BoundParams, Call, CommitmentCiphertext, CommitmentPreimage,
        RelayAdapt7702ActionData, RelayAdapt7702Current, RelayAdapt7702Legacy, SnarkProof,
        TokenData, Transaction, executeCall, relayCall, transactCall,
    };
    use crate::crypto::aes_gcm::encrypt_in_place_16b_iv;
    use crate::crypto::railgun::{ViewingKeyData, derive_viewing_public_key};
    use crate::crypto::shared_key::shared_symmetric_key;
    use crate::eip7702::{
        Eip7702AuthorizationNonce, FinalizedRelayAdapt7702Call, PreparedRelayAdapt7702Execution,
        RelayAdapt7702ExecutionNonce, RelayAdapt7702ExecutionVersion,
    };
    use crate::notes::Note;
    use alloy::eips::eip7702::{Authorization, SignedAuthorization};
    use alloy::primitives::{Address, Bytes, FixedBytes, Signature, U256};
    use alloy::signers::{SignerSync, local::PrivateKeySigner};
    use alloy::sol_types::{SolCall, SolValue};
    use ed25519_dalek::SigningKey;
    use ruint::uint;
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::subscriber::{Interest, with_default};
    use tracing::{Event, Metadata, Subscriber};

    static DECRYPT_TRACE_TEST_LOCK: Mutex<()> = Mutex::new(());

    type ParamsMutation = (&'static str, fn(&mut BroadcasterRawParamsTransact7702));

    const TX7702_WIRE_FIXTURE: &str = include_str!("../resources/fixtures/eip-7702/wire.json");
    const TX7702_WIRE_CASES_FIXTURE: &str =
        include_str!("../resources/fixtures/eip-7702/wire-cases.json");
    const TX7702_ENCRYPTED_FIXTURE: &str =
        include_str!("../resources/fixtures/eip-7702/encrypted-envelope.json");
    const TX7702_ENCRYPTED_FIXTURE_BYTES: &[u8] =
        include_bytes!("../resources/fixtures/eip-7702/encrypted-envelope.json");

    fn set_fixture_path(value: &mut Value, path: &str, replacement: Value) {
        let mut parts = path.split('.').peekable();
        let mut current = value;
        while let Some(part) = parts.next() {
            if parts.peek().is_none() {
                current[part] = replacement;
                return;
            }
            current = current.get_mut(part).expect("fixture mutation path exists");
        }
    }

    fn apply_wire_case(base: &Value, case: &Value) -> Value {
        let mut value = base.clone();
        if let Some(paths) = case["remove"].as_array() {
            for path in paths {
                value
                    .as_object_mut()
                    .expect("wire fixture object")
                    .remove(path.as_str().expect("wire removal path"));
            }
        }
        if let Some(replacements) = case["set"].as_object() {
            for (path, replacement) in replacements {
                set_fixture_path(&mut value, path, replacement.clone());
            }
        }
        value
    }

    fn wire_fixture_bytes(value: &Value) -> Bytes {
        value
            .as_str()
            .expect("wire fixture bytes")
            .parse()
            .expect("valid wire fixture hex")
    }

    struct CapturedEvent {
        fields: Vec<String>,
    }

    struct EventCapture {
        events: Arc<Mutex<Vec<CapturedEvent>>>,
    }

    struct EventFieldVisitor {
        fields: Vec<String>,
    }

    impl Visit for EventFieldVisitor {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.fields.push(format!("{}={value:?}", field.name()));
        }
    }

    impl Subscriber for EventCapture {
        fn register_callsite(&self, _metadata: &'static Metadata<'static>) -> Interest {
            Interest::always()
        }

        fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _span: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }

        fn record(&self, _span: &Id, _values: &Record<'_>) {}

        fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

        fn event(&self, event: &Event<'_>) {
            let mut visitor = EventFieldVisitor { fields: Vec::new() };
            event.record(&mut visitor);
            self.events
                .lock()
                .expect("trace capture lock")
                .push(CapturedEvent {
                    fields: visitor.fields,
                });
        }

        fn enter(&self, _span: &Id) {}

        fn exit(&self, _span: &Id) {}
    }

    fn sample_viewing_key_data() -> ViewingKeyData {
        ViewingKeyData::from_spending_public_key([7u8; 32], [uint!(3_U256), uint!(9_U256)])
    }

    fn sample_ciphertext(
        viewing_key_data: &ViewingKeyData,
        token: Address,
        value: U256,
        random: [u8; 16],
        encoded_mpk: U256,
    ) -> CommitmentCiphertext {
        let sender_viewing_private_key = [11u8; 32];
        let blinded_sender = derive_viewing_public_key(&sender_viewing_private_key);
        let shared_key =
            shared_symmetric_key(&viewing_key_data.viewing_private_key, &blinded_sender)
                .expect("shared key");

        let mut plaintext = Vec::with_capacity(96);
        plaintext.extend_from_slice(&encoded_mpk.to_be_bytes::<32>());
        plaintext.extend_from_slice(&U256::from_be_slice(token.as_slice()).to_be_bytes::<32>());
        plaintext.extend_from_slice(&random);
        let value_bytes = value.to_be_bytes::<32>();
        plaintext.extend_from_slice(&value_bytes[16..]);
        let iv_tag = encrypt_in_place_16b_iv(&shared_key, &mut plaintext).expect("encrypt note");

        let mut ciphertext_words = [[0u8; 32]; 4];
        ciphertext_words[0].copy_from_slice(&iv_tag);
        ciphertext_words[1].copy_from_slice(&plaintext[..32]);
        ciphertext_words[2].copy_from_slice(&plaintext[32..64]);
        ciphertext_words[3].copy_from_slice(&plaintext[64..96]);

        CommitmentCiphertext {
            ciphertext: ciphertext_words.map(FixedBytes::from),
            blindedSenderViewingKey: FixedBytes::from(blinded_sender),
            blindedReceiverViewingKey: FixedBytes::ZERO,
            annotationData: Bytes::new(),
            memo: Bytes::new(),
        }
    }

    fn sample_transaction_and_params_with_encoded_mpk(
        txid_version: Option<&str>,
        encoded_mpk: U256,
    ) -> (
        Vec<u8>,
        Transaction,
        BroadcasterRawParamsTransact,
        FixedBytes<32>,
        FixedBytes<32>,
    ) {
        let viewing_key_data = sample_viewing_key_data();
        let fee_token = Address::from([0x22; 20]);
        let fee_value = uint!(42_U256);
        let random = [0x55; 16];
        let npk = Note::npk_for(viewing_key_data.master_public_key, random);
        let fee_commitment = Note {
            token_hash: U256::from_be_slice(fee_token.as_slice()),
            value: fee_value,
            random,
            npk,
        }
        .commitment();
        let transaction = Transaction {
            proof: SnarkProof::default(),
            merkleRoot: FixedBytes::ZERO,
            nullifiers: vec![FixedBytes::from([1u8; 32])],
            commitments: vec![fee_commitment.into()],
            boundParams: BoundParams::new_transact(
                9,
                0,
                1,
                vec![sample_ciphertext(
                    &viewing_key_data,
                    fee_token,
                    fee_value,
                    random,
                    encoded_mpk,
                )],
                Address::ZERO,
                FixedBytes::ZERO,
            ),
            unshieldPreimage: CommitmentPreimage {
                npk: FixedBytes::ZERO,
                token: TokenData {
                    tokenType: 0,
                    tokenAddress: Address::ZERO,
                    tokenSubID: U256::ZERO,
                },
                value: alloy::primitives::Uint::<120, 2>::ZERO,
            },
        };

        let railgun_txid = compute_railgun_txid(&transaction, txid_version).expect("txid");
        let leaf: FixedBytes<32> = railgun_txid_leaf_hash(railgun_txid, 9).into();
        let required_list_key = FixedBytes::from([0x88; 32]);
        let pre_tx_poi = PreTxPoi {
            snark_proof: SnarkJsProof::zero(),
            txid_merkleroot: FixedBytes::ZERO,
            poi_merkleroots: vec![FixedBytes::ZERO],
            blinded_commitments_out: vec![FixedBytes::from([0x77; 32])],
            railgun_txid_if_has_unshield: Bytes::new(),
        };

        let mut per_leaf = BTreeMap::new();
        per_leaf.insert(leaf, pre_tx_poi);
        let mut per_list = BTreeMap::new();
        per_list.insert(required_list_key, per_leaf);

        let params = BroadcasterRawParamsTransact {
            chain_type: 0,
            chain_id: 1,
            transact_type: None,
            min_gas_price: None,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            authorization: None,
            fees_id: None,
            to: Address::ZERO,
            data: transactCall {
                _transactions: vec![transaction.clone()],
            }
            .abi_encode()
            .into(),
            broadcaster_viewing_key: FixedBytes::ZERO,
            txid_version: txid_version.map(str::to_string),
            pre_transaction_pois_per_txid_leaf_per_list: per_list,
        };

        (
            transactCall {
                _transactions: vec![transaction.clone()],
            }
            .abi_encode(),
            transaction,
            params,
            fee_commitment.into(),
            FixedBytes::from([0x77; 32]),
        )
    }

    fn sample_transaction_and_params(
        txid_version: Option<&str>,
    ) -> (
        Vec<u8>,
        Transaction,
        BroadcasterRawParamsTransact,
        FixedBytes<32>,
        FixedBytes<32>,
    ) {
        let viewing_key_data = sample_viewing_key_data();
        sample_transaction_and_params_with_encoded_mpk(
            txid_version,
            viewing_key_data.master_public_key,
        )
    }

    fn sample_strict_tx7702_params() -> BroadcasterRawParamsTransact7702 {
        BroadcasterRawParamsTransact7702 {
            transact_type: BroadcasterRawParamsTransact7702Type::Tx7702,
            txid_version: DEFAULT_TXID_VERSION.to_string(),
            to: Address::from([0x11; 20]),
            data: Bytes::from(vec![0xab, 0xcd, 0xef]),
            broadcaster_viewing_key: FixedBytes::from([0x33; 32]),
            chain_id: 31_337,
            chain_type: 0,
            fees_id: "SENTINEL-FEE-ID".to_string(),
            use_relay_adapt: true,
            dev_log: false,
            min_version: "10.10.0-rc.1".to_string(),
            max_version: "10.10.0-rc.1".to_string(),
            pre_transaction_pois_per_txid_leaf_per_list: BTreeMap::new(),
            gas_limit: 987_654,
            max_fee_per_gas: U256::from(42_000_000_000_u64),
            max_priority_fee_per_gas: U256::from(1_700_000_000_u64),
            authorization: BroadcasterRawParamsTransact7702Authorization {
                address: Address::from([0x44; 20]),
                chain_id: U256::from(31_337_u64),
                nonce: 42,
                signature: BroadcasterRawParamsTransact7702AuthorizationSignature {
                    signature_type: BroadcasterRawParamsTransact7702SignatureType::Signature,
                    network_v: (),
                    r: FixedBytes::from([0xab; 32]),
                    s: FixedBytes::from([0xcd; 32]),
                    v: 27,
                },
            },
        }
    }

    const VALIDATION_SIGNER_KEY: [u8; 32] = [0x91; 32];
    const OTHER_VALIDATION_SIGNER_KEY: [u8; 32] = [0x92; 32];

    fn validation_transaction(seed: u8) -> Transaction {
        Transaction {
            proof: SnarkProof::default(),
            merkleRoot: FixedBytes::from([seed; 32]),
            nullifiers: vec![FixedBytes::from([seed.wrapping_add(1); 32])],
            commitments: vec![FixedBytes::from([seed.wrapping_add(2); 32])],
            boundParams: BoundParams::new_transact(
                u32::from(seed),
                0,
                1_337,
                Vec::new(),
                Address::ZERO,
                FixedBytes::ZERO,
            ),
            unshieldPreimage: CommitmentPreimage::empty(),
        }
    }

    fn validation_action_data(seed: u8) -> RelayAdapt7702ActionData {
        RelayAdapt7702ActionData {
            requireSuccess: true,
            minGasLimit: U256::from(17_u64 + u64::from(seed)),
            calls: vec![
                Call {
                    to: Address::from([0x31_u8.wrapping_add(seed); 20]),
                    data: Bytes::from(vec![seed, 0xa1]),
                    value: U256::from(seed),
                },
                Call {
                    to: Address::from([0x41_u8.wrapping_add(seed); 20]),
                    data: Bytes::from(vec![seed, 0xb2, 0xc3]),
                    value: U256::from(seed + 1),
                },
            ],
        }
    }

    fn validation_operation(
        signer_key: [u8; 32],
        chain_id: u64,
        delegate: Address,
        authorization_nonce: u64,
        execution_version: RelayAdapt7702ExecutionVersion,
        transactions: Vec<Transaction>,
        action_data: RelayAdapt7702ActionData,
        outer_value: U256,
    ) -> (PreparedRelayAdapt7702Execution, FinalizedRelayAdapt7702Call) {
        let signer = PrivateKeySigner::from_slice(&signer_key).expect("valid validation signer");
        let prepared = PreparedRelayAdapt7702Execution::prepare(
            chain_id,
            signer.address(),
            delegate,
            Eip7702AuthorizationNonce::new(authorization_nonce),
            execution_version,
            transactions,
            action_data,
            outer_value,
        );
        let authorization_signature = signer
            .sign_hash_sync(&prepared.authorization_signing_hash())
            .expect("sign validation authorization");
        let execution_signature = signer
            .sign_hash_sync(&prepared.execution_signing_hash())
            .expect("sign validation execution");
        let finalized = prepared
            .finalize(authorization_signature, execution_signature)
            .expect("finalize validation operation");
        (prepared, finalized)
    }

    fn strict_params_for_finalized(
        finalized: &FinalizedRelayAdapt7702Call,
    ) -> BroadcasterRawParamsTransact7702 {
        BroadcasterRawParamsTransact7702 {
            transact_type: BroadcasterRawParamsTransact7702Type::Tx7702,
            txid_version: DEFAULT_TXID_VERSION.to_string(),
            to: finalized.to(),
            data: finalized.data().clone(),
            broadcaster_viewing_key: FixedBytes::ZERO,
            chain_id: 1_337,
            chain_type: 0,
            fees_id: "validation-fees".to_string(),
            use_relay_adapt: true,
            dev_log: false,
            min_version: "validation".to_string(),
            max_version: "validation".to_string(),
            pre_transaction_pois_per_txid_leaf_per_list: BTreeMap::new(),
            gas_limit: 21_000,
            max_fee_per_gas: U256::from(100_u64),
            max_priority_fee_per_gas: U256::from(2_u64),
            authorization: BroadcasterRawParamsTransact7702Authorization::try_from(
                finalized.authorization(),
            )
            .expect("convert validation authorization"),
        }
    }

    fn strict_fee_validation_fixture(
        outer_value: U256,
    ) -> (
        BroadcasterRawParamsTransact7702,
        PreparedRelayAdapt7702Execution,
        FinalizedRelayAdapt7702Call,
        ViewingKeyData,
        FixedBytes<32>,
    ) {
        let viewing_key_data = sample_viewing_key_data();
        let (_, first_transaction, _, _, _) = sample_transaction_and_params(None);
        let transactions = vec![first_transaction, validation_transaction(2)];
        let action_data = validation_action_data(1);
        let (prepared, finalized) = validation_operation(
            VALIDATION_SIGNER_KEY,
            1_337,
            Address::from([0x12; 20]),
            0x100,
            RelayAdapt7702ExecutionVersion::CurrentNonceAware {
                nonce: RelayAdapt7702ExecutionNonce::new(U256::from(77_u64)),
            },
            transactions,
            action_data,
            outer_value,
        );

        let required_list_key = FixedBytes::from([0x88; 32]);
        let mut per_leaf = BTreeMap::new();
        for transaction in prepared.transactions() {
            let railgun_txid = compute_railgun_txid(transaction, Some(DEFAULT_TXID_VERSION))
                .expect("fixture txid");
            let utxo_tree_in = transaction.boundParams.treeNumber.into();
            let leaf = railgun_txid_leaf_hash(railgun_txid, utxo_tree_in);
            let leaf_key = FixedBytes::from(leaf.to_be_bytes::<32>());
            let poi = PreTxPoi {
                snark_proof: SnarkJsProof::zero(),
                txid_merkleroot: FixedBytes::from(dummy_txid_root(leaf).to_be_bytes::<32>()),
                poi_merkleroots: vec![FixedBytes::ZERO],
                blinded_commitments_out: vec![FixedBytes::from([0x77; 32])],
                railgun_txid_if_has_unshield: Bytes::new(),
            };
            per_leaf.insert(leaf_key, poi);
        }

        let mut params = strict_params_for_finalized(&finalized);
        params.pre_transaction_pois_per_txid_leaf_per_list =
            BTreeMap::from([(required_list_key, per_leaf)]);

        (
            params,
            prepared,
            finalized,
            viewing_key_data,
            required_list_key,
        )
    }

    fn assert_strict_validation_rejected(
        label: &str,
        params: &BroadcasterRawParamsTransact7702,
        prepared: &PreparedRelayAdapt7702Execution,
        finalized: &FinalizedRelayAdapt7702Call,
        viewing_key_data: &ViewingKeyData,
        required_poi_list_keys: &[FixedBytes<32>],
    ) {
        let error = params
            .validate_broadcaster_request(
                prepared,
                finalized,
                &viewing_key_data.viewing_private_key,
                viewing_key_data.master_public_key,
                required_poi_list_keys,
            )
            .expect_err(label);
        assert!(
            matches!(
                error,
                Transact7702Error::CanonicalOperationMismatch
                    | Transact7702Error::StrictBroadcasterPolicy
            ),
            "{label}: unexpected error {error:?}"
        );

        let rendered = format!("{error:?} {error}");
        for sentinel in [
            format!("{:?}", prepared.authority()),
            alloy::hex::encode(finalized.data()),
            alloy::hex::encode(finalized.execution_signature().as_bytes()),
            alloy::hex::encode(finalized.authorization().r().to_be_bytes::<32>()),
            alloy::hex::encode(finalized.authorization().s().to_be_bytes::<32>()),
        ] {
            assert!(!rendered.contains(&sentinel), "{label} leaked {sentinel}");
        }
        assert!(!rendered.contains("COMMON"), "{label} downgraded to COMMON");
        assert!(
            !rendered.contains("MissingTransactions"),
            "{label} exposed parser error"
        );
    }

    fn assert_validation_rejected(
        label: &str,
        params: &BroadcasterRawParamsTransact7702,
        prepared: &PreparedRelayAdapt7702Execution,
        finalized: &FinalizedRelayAdapt7702Call,
    ) {
        let error = params
            .validate_finalized_operation(prepared, finalized)
            .expect_err(label);
        assert!(matches!(
            error,
            Transact7702Error::CanonicalOperationMismatch
        ));

        let rendered = format!("{error:?} {error}");
        for sentinel in [
            format!("{:?}", prepared.authority()),
            format!("{:?}", finalized.to()),
            alloy::hex::encode(finalized.data()),
            alloy::hex::encode(finalized.execution_signature().as_bytes()),
            alloy::hex::encode(finalized.authorization().r().to_be_bytes::<32>()),
            alloy::hex::encode(finalized.authorization().s().to_be_bytes::<32>()),
        ] {
            assert!(!rendered.contains(&sentinel), "{label} leaked {sentinel}");
        }
    }

    #[test]
    fn strict_tx7702_validation_accepts_canonical_current_and_legacy_operations() {
        let transactions = vec![validation_transaction(1), validation_transaction(2)];
        let action_data = validation_action_data(1);
        let delegate = Address::from([0x12; 20]);

        let (current_prepared, current_finalized) = validation_operation(
            VALIDATION_SIGNER_KEY,
            1_337,
            delegate,
            0x100,
            RelayAdapt7702ExecutionVersion::CurrentNonceAware {
                nonce: RelayAdapt7702ExecutionNonce::new(U256::from(77_u64)),
            },
            transactions.clone(),
            action_data.clone(),
            U256::from(5_u64),
        );
        let current_params = strict_params_for_finalized(&current_finalized);
        current_params
            .validate_finalized_operation(&current_prepared, &current_finalized)
            .expect("canonical current operation");

        let (legacy_prepared, legacy_finalized) = validation_operation(
            VALIDATION_SIGNER_KEY,
            1_337,
            delegate,
            0x100,
            RelayAdapt7702ExecutionVersion::LegacyPreExecuteNonce,
            transactions,
            action_data,
            U256::from(5_u64),
        );
        let legacy_params = strict_params_for_finalized(&legacy_finalized);
        legacy_params
            .validate_finalized_operation(&legacy_prepared, &legacy_finalized)
            .expect("canonical legacy operation");
    }

    #[test]
    fn strict_tx7702_validation_rejects_semantically_unrelated_operations() {
        let base_transactions = vec![validation_transaction(1), validation_transaction(2)];
        let base_action_data = validation_action_data(1);
        let delegate = Address::from([0x12; 20]);
        let current_version = RelayAdapt7702ExecutionVersion::CurrentNonceAware {
            nonce: RelayAdapt7702ExecutionNonce::new(U256::from(77_u64)),
        };
        let (base_prepared, base_finalized) = validation_operation(
            VALIDATION_SIGNER_KEY,
            1_337,
            delegate,
            0x100,
            current_version,
            base_transactions.clone(),
            base_action_data.clone(),
            U256::from(5_u64),
        );
        let base_params = strict_params_for_finalized(&base_finalized);

        let mut request_authority = base_params.clone();
        request_authority.to = Address::from([0xe1; 20]);
        assert_validation_rejected(
            "request authority destination mismatch",
            &request_authority,
            &base_prepared,
            &base_finalized,
        );

        let (_, other_authority_finalized) = validation_operation(
            OTHER_VALIDATION_SIGNER_KEY,
            1_337,
            delegate,
            0x100,
            current_version,
            base_transactions.clone(),
            base_action_data.clone(),
            U256::from(5_u64),
        );
        assert_validation_rejected(
            "finalized authority destination mismatch",
            &base_params,
            &base_prepared,
            &other_authority_finalized,
        );

        let mut unrelated_request = base_params.clone();
        unrelated_request.data = other_authority_finalized.data().clone();
        assert_validation_rejected(
            "structurally valid unrelated calldata",
            &unrelated_request,
            &base_prepared,
            &base_finalized,
        );

        let (_, legacy_finalized) = validation_operation(
            VALIDATION_SIGNER_KEY,
            1_337,
            delegate,
            0x100,
            RelayAdapt7702ExecutionVersion::LegacyPreExecuteNonce,
            base_transactions.clone(),
            base_action_data.clone(),
            U256::from(5_u64),
        );
        assert_validation_rejected(
            "current and legacy selector/version substitution",
            &base_params,
            &base_prepared,
            &legacy_finalized,
        );

        let (_, changed_nonce_finalized) = validation_operation(
            VALIDATION_SIGNER_KEY,
            1_337,
            delegate,
            0x100,
            RelayAdapt7702ExecutionVersion::CurrentNonceAware {
                nonce: RelayAdapt7702ExecutionNonce::new(U256::from(78_u64)),
            },
            base_transactions.clone(),
            base_action_data.clone(),
            U256::from(5_u64),
        );
        assert_validation_rejected(
            "execute nonce mutation",
            &base_params,
            &base_prepared,
            &changed_nonce_finalized,
        );

        let (_, changed_transaction_finalized) = validation_operation(
            VALIDATION_SIGNER_KEY,
            1_337,
            delegate,
            0x100,
            current_version,
            vec![validation_transaction(3), validation_transaction(2)],
            base_action_data.clone(),
            U256::from(5_u64),
        );
        assert_validation_rejected(
            "transaction content mutation",
            &base_params,
            &base_prepared,
            &changed_transaction_finalized,
        );

        let (_, reordered_transaction_finalized) = validation_operation(
            VALIDATION_SIGNER_KEY,
            1_337,
            delegate,
            0x100,
            current_version,
            vec![validation_transaction(2), validation_transaction(1)],
            base_action_data.clone(),
            U256::from(5_u64),
        );
        assert_validation_rejected(
            "transaction ordering mutation",
            &base_params,
            &base_prepared,
            &reordered_transaction_finalized,
        );

        let (_, changed_action_finalized) = validation_operation(
            VALIDATION_SIGNER_KEY,
            1_337,
            delegate,
            0x100,
            current_version,
            base_transactions.clone(),
            validation_action_data(2),
            U256::from(5_u64),
        );
        assert_validation_rejected(
            "action field and call content mutation",
            &base_params,
            &base_prepared,
            &changed_action_finalized,
        );

        let mut reordered_action = base_action_data.clone();
        reordered_action.calls.reverse();
        let (_, reordered_action_finalized) = validation_operation(
            VALIDATION_SIGNER_KEY,
            1_337,
            delegate,
            0x100,
            current_version,
            base_transactions.clone(),
            reordered_action,
            U256::from(5_u64),
        );
        assert_validation_rejected(
            "action call ordering mutation",
            &base_params,
            &base_prepared,
            &reordered_action_finalized,
        );

        let mut calldata_mismatch = base_params.clone();
        calldata_mismatch.data = changed_action_finalized.data().clone();
        assert_validation_rejected(
            "request and finalized calldata mismatch",
            &calldata_mismatch,
            &base_prepared,
            &base_finalized,
        );

        let (_, changed_outer_value_finalized) = validation_operation(
            VALIDATION_SIGNER_KEY,
            1_337,
            delegate,
            0x100,
            current_version,
            base_transactions.clone(),
            base_action_data.clone(),
            U256::from(6_u64),
        );
        assert_validation_rejected(
            "prepared and finalized outer value mismatch",
            &base_params,
            &base_prepared,
            &changed_outer_value_finalized,
        );

        let (_, changed_execution_signature_finalized) = validation_operation(
            VALIDATION_SIGNER_KEY,
            1_338,
            delegate,
            0x100,
            current_version,
            base_transactions.clone(),
            base_action_data.clone(),
            U256::from(5_u64),
        );
        assert_validation_rejected(
            "execution signature mutation",
            &base_params,
            &base_prepared,
            &changed_execution_signature_finalized,
        );

        let (_, changed_authorization_finalized) = validation_operation(
            VALIDATION_SIGNER_KEY,
            1_337,
            Address::from([0x13; 20]),
            0x101,
            current_version,
            base_transactions,
            base_action_data,
            U256::from(5_u64),
        );
        assert_validation_rejected(
            "finalized authorization delegate and nonce mismatch",
            &base_params,
            &base_prepared,
            &changed_authorization_finalized,
        );

        let mutations: [ParamsMutation; 4] = [
            (
                "request authorization delegate mismatch",
                |params: &mut BroadcasterRawParamsTransact7702| {
                    params.authorization.address = Address::from([0xe2; 20]);
                },
            ),
            (
                "request authorization chain mismatch",
                |params: &mut BroadcasterRawParamsTransact7702| {
                    params.authorization.chain_id = U256::from(1_338_u64);
                },
            ),
            (
                "request authorization nonce mismatch",
                |params: &mut BroadcasterRawParamsTransact7702| {
                    params.authorization.nonce += 1;
                },
            ),
            (
                "request authorization signature mismatch",
                |params: &mut BroadcasterRawParamsTransact7702| {
                    params.authorization.signature.r = FixedBytes::from([0xe3; 32]);
                },
            ),
        ];
        for (label, mutate) in mutations {
            let mut mutated = base_params.clone();
            mutate(&mut mutated);
            assert_validation_rejected(label, &mutated, &base_prepared, &base_finalized);
        }
    }

    #[test]
    fn strict_tx7702_broadcaster_validation_accepts_fee_note_and_aligned_poi() {
        let (mut params, prepared, finalized, viewing_key_data, required_list_key) =
            strict_fee_validation_fixture(U256::ZERO);
        params.max_priority_fee_per_gas = U256::ZERO;

        let parsed = params
            .validate_broadcaster_request(
                &prepared,
                &finalized,
                &viewing_key_data.viewing_private_key,
                viewing_key_data.master_public_key,
                &[required_list_key],
            )
            .expect("strict TX7702 broadcaster validation");

        assert_eq!(parsed.fee_token, Address::from([0x22; 20]));
        assert_eq!(parsed.fee_amount, U256::from(42_u64));
        assert_eq!(parsed.transactions.len(), 2);

        let assurance = parsed
            .fee_note_assurance
            .expect("fee note assurance context");
        assert_eq!(
            assurance.chain_type,
            u8::try_from(params.chain_type).expect("fixture chain type")
        );
        assert_eq!(assurance.txid_version, DEFAULT_TXID_VERSION);
        assert_eq!(assurance.railgun_txid, parsed.railgun_txid);
        assert_eq!(assurance.utxo_tree_in, parsed.utxo_tree_in);
        assert_eq!(assurance.fee_commitment, parsed.fee_commitment);
        assert_eq!(assurance.fee_note_npk, parsed.fee_note_npk);
        assert_eq!(assurance.required_poi_list_keys, vec![required_list_key]);
        assert_eq!(
            assurance.pre_transaction_pois_per_txid_leaf_per_list.len(),
            1
        );
        assert_eq!(
            assurance
                .pre_transaction_pois_per_txid_leaf_per_list
                .get(&required_list_key)
                .expect("required POI list")
                .len(),
            parsed.transactions.len()
        );

        let parsed_without_assurance = params
            .validate_broadcaster_request(
                &prepared,
                &finalized,
                &viewing_key_data.viewing_private_key,
                viewing_key_data.master_public_key,
                &[],
            )
            .expect("strict validation without required POI lists");
        assert!(parsed_without_assurance.fee_note_assurance.is_none());
    }

    #[test]
    fn strict_tx7702_chain_type_overflow_rejects_before_encryption() {
        let (mut params, prepared, finalized, viewing_key_data, _) =
            strict_fee_validation_fixture(U256::ZERO);
        params.chain_type = 256;

        assert!(matches!(
            params.validate_broadcaster_request(
                &prepared,
                &finalized,
                &viewing_key_data.viewing_private_key,
                viewing_key_data.master_public_key,
                &[],
            ),
            Err(Transact7702Error::StrictBroadcasterPolicy)
        ));

        let broadcaster_viewing_private_seed = [0x79; 32];
        let broadcaster_viewing_pubkey = SigningKey::from_bytes(&broadcaster_viewing_private_seed)
            .verifying_key()
            .to_bytes();
        assert!(matches!(
            EncryptedTransactRequest::encrypt_7702(
                broadcaster_viewing_pubkey,
                &params,
                &prepared,
                &finalized,
                &viewing_key_data.viewing_private_key,
                viewing_key_data.master_public_key,
                &[],
            ),
            Err(Transact7702Error::StrictBroadcasterPolicy)
        ));
    }

    #[test]
    fn strict_tx7702_broadcaster_validation_rejects_policy_mismatches_without_downgrade() {
        let (base_params, prepared, finalized, viewing_key_data, required_list_key) =
            strict_fee_validation_fixture(U256::ZERO);

        let mutations: [ParamsMutation; 6] = [
            (
                "request chain mismatch",
                |params: &mut BroadcasterRawParamsTransact7702| {
                    params.chain_id += 1;
                },
            ),
            (
                "empty fees id",
                |params: &mut BroadcasterRawParamsTransact7702| {
                    params.fees_id.clear();
                },
            ),
            (
                "zero gas limit",
                |params: &mut BroadcasterRawParamsTransact7702| {
                    params.gas_limit = 0;
                },
            ),
            (
                "zero max fee",
                |params: &mut BroadcasterRawParamsTransact7702| {
                    params.max_fee_per_gas = U256::ZERO;
                },
            ),
            (
                "priority fee above max fee",
                |params: &mut BroadcasterRawParamsTransact7702| {
                    params.max_priority_fee_per_gas = params.max_fee_per_gas + U256::from(1);
                },
            ),
            (
                "authorization chain mismatch",
                |params: &mut BroadcasterRawParamsTransact7702| {
                    params.authorization.chain_id = U256::from(params.chain_id + 1);
                },
            ),
        ];

        for (label, mutate) in mutations {
            let mut params = base_params.clone();
            mutate(&mut params);
            assert_strict_validation_rejected(
                label,
                &params,
                &prepared,
                &finalized,
                &viewing_key_data,
                &[required_list_key],
            );
        }

        let (outer_params, outer_prepared, outer_finalized, outer_viewing_key_data, outer_list_key) =
            strict_fee_validation_fixture(U256::from(1_u64));
        assert_strict_validation_rejected(
            "nonzero broadcaster outer value",
            &outer_params,
            &outer_prepared,
            &outer_finalized,
            &outer_viewing_key_data,
            &[outer_list_key],
        );
    }

    #[test]
    fn strict_tx7702_broadcaster_validation_requires_fee_note_and_complete_poi() {
        let (base_params, prepared, finalized, viewing_key_data, required_list_key) =
            strict_fee_validation_fixture(U256::ZERO);

        let missing_required_list = FixedBytes::from([0x99; 32]);
        assert_strict_validation_rejected(
            "missing required POI list",
            &base_params,
            &prepared,
            &finalized,
            &viewing_key_data,
            &[missing_required_list],
        );

        let mut missing_transaction_leaf = base_params.clone();
        let leaves = missing_transaction_leaf
            .pre_transaction_pois_per_txid_leaf_per_list
            .get(&required_list_key)
            .expect("fixture POI list")
            .keys()
            .copied()
            .collect::<Vec<_>>();
        missing_transaction_leaf
            .pre_transaction_pois_per_txid_leaf_per_list
            .get_mut(&required_list_key)
            .expect("fixture POI list")
            .remove(&leaves[1]);
        assert_strict_validation_rejected(
            "missing second transaction leaf",
            &missing_transaction_leaf,
            &prepared,
            &finalized,
            &viewing_key_data,
            &[required_list_key],
        );

        let mut misaligned_txid_root = base_params.clone();
        misaligned_txid_root
            .pre_transaction_pois_per_txid_leaf_per_list
            .get_mut(&required_list_key)
            .expect("fixture POI list")
            .values_mut()
            .next()
            .expect("fixture POI entry")
            .txid_merkleroot = FixedBytes::from([0xff; 32]);
        assert_strict_validation_rejected(
            "misaligned transaction root",
            &misaligned_txid_root,
            &prepared,
            &finalized,
            &viewing_key_data,
            &[required_list_key],
        );

        let mut undecodable = base_params;
        undecodable.data = Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]);
        assert_strict_validation_rejected(
            "undecodable calldata",
            &undecodable,
            &prepared,
            &finalized,
            &viewing_key_data,
            &[required_list_key],
        );

        let empty_action_data = RelayAdapt7702ActionData {
            requireSuccess: true,
            minGasLimit: U256::ZERO,
            calls: Vec::new(),
        };
        let (empty_prepared, empty_finalized) = validation_operation(
            VALIDATION_SIGNER_KEY,
            1_337,
            Address::from([0x12; 20]),
            0x100,
            RelayAdapt7702ExecutionVersion::CurrentNonceAware {
                nonce: RelayAdapt7702ExecutionNonce::new(U256::from(77_u64)),
            },
            Vec::new(),
            empty_action_data,
            U256::ZERO,
        );
        let empty_params = strict_params_for_finalized(&empty_finalized);
        assert_strict_validation_rejected(
            "empty transactions",
            &empty_params,
            &empty_prepared,
            &empty_finalized,
            &viewing_key_data,
            &[],
        );

        let (missing_note_prepared, missing_note_finalized) = validation_operation(
            VALIDATION_SIGNER_KEY,
            1_337,
            Address::from([0x12; 20]),
            0x100,
            RelayAdapt7702ExecutionVersion::CurrentNonceAware {
                nonce: RelayAdapt7702ExecutionNonce::new(U256::from(77_u64)),
            },
            vec![validation_transaction(3)],
            validation_action_data(1),
            U256::ZERO,
        );
        let missing_note_params = strict_params_for_finalized(&missing_note_finalized);
        assert_strict_validation_rejected(
            "missing broadcaster fee note",
            &missing_note_params,
            &missing_note_prepared,
            &missing_note_finalized,
            &viewing_key_data,
            &[],
        );
    }

    fn set_strict_quantity(
        value: &mut serde_json::Value,
        field: &str,
        replacement: serde_json::Value,
    ) {
        if let Some(field) = field.strip_prefix("authorization.") {
            value["authorization"][field] = replacement;
        } else {
            value[field] = replacement;
        }
    }

    #[test]
    fn strict_tx7702_serializes_exact_wire_shape_and_roundtrips() {
        let params = sample_strict_tx7702_params();
        let value = serde_json::to_value(&params).expect("serialize strict TX7702 params");
        let object = value.as_object().expect("strict params object");
        let expected_keys = BTreeSet::from([
            "authorization",
            "broadcasterViewingKey",
            "chainID",
            "chainType",
            "data",
            "devLog",
            "feesID",
            "gasLimit",
            "maxFeePerGas",
            "maxPriorityFeePerGas",
            "maxVersion",
            "minVersion",
            "preTransactionPOIsPerTxidLeafPerList",
            "to",
            "transactType",
            "txidVersion",
            "useRelayAdapt",
        ]);
        assert_eq!(
            object.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            expected_keys
        );
        assert_eq!(value["transactType"], "TX7702");
        assert_eq!(value["gasLimit"], "987654");
        assert_eq!(value["maxFeePerGas"], "42000000000");
        assert_eq!(value["maxPriorityFeePerGas"], "1700000000");
        assert!(!object.contains_key("minGasPrice"));

        let authorization = value["authorization"]
            .as_object()
            .expect("authorization object");
        assert_eq!(
            authorization
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["address", "chainId", "nonce", "signature"])
        );
        assert_eq!(value["authorization"]["chainId"], "31337");
        assert_eq!(value["authorization"]["nonce"], "42");
        assert!(!authorization.contains_key("yParity"));
        assert!(!authorization.contains_key("r"));
        assert!(!authorization.contains_key("s"));

        let signature = authorization["signature"]
            .as_object()
            .expect("signature object");
        assert_eq!(
            signature
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["_type", "networkV", "r", "s", "v"])
        );
        assert_eq!(signature["_type"], "signature");
        assert!(signature["networkV"].is_null());
        assert_eq!(value["data"], "0xabcdef");
        assert_eq!(signature["r"], format!("0x{}", "ab".repeat(32)));
        assert_eq!(signature["s"], format!("0x{}", "cd".repeat(32)));
        assert_eq!(signature["v"], 27);

        let roundtrip: BroadcasterRawParamsTransact7702 =
            serde_json::from_value(value.clone()).expect("deserialize strict TX7702 params");
        assert_eq!(
            serde_json::to_value(&roundtrip).expect("re-serialize params"),
            value
        );
        assert_eq!(roundtrip.transact_type, params.transact_type);
        assert_eq!(roundtrip.txid_version, params.txid_version);
        assert_eq!(roundtrip.to, params.to);
        assert_eq!(roundtrip.data, params.data);
        assert_eq!(
            roundtrip.broadcaster_viewing_key,
            params.broadcaster_viewing_key
        );
        assert_eq!(roundtrip.chain_id, params.chain_id);
        assert_eq!(roundtrip.chain_type, params.chain_type);
        assert_eq!(roundtrip.fees_id, params.fees_id);
        assert_eq!(roundtrip.gas_limit, params.gas_limit);
        assert_eq!(roundtrip.max_fee_per_gas, params.max_fee_per_gas);
        assert_eq!(
            roundtrip.max_priority_fee_per_gas,
            params.max_priority_fee_per_gas
        );
        assert_eq!(roundtrip.authorization, params.authorization);
    }

    #[test]
    fn strict_tx7702_authorization_conversion_maps_parity_and_preserves_signature() {
        let authorization = Authorization {
            chain_id: U256::from(31_337_u64),
            address: Address::from([0x44; 20]),
            nonce: 42,
        };
        let r = U256::from_be_bytes([0xab; 32]);
        let s = U256::from_be_bytes([0xcd; 32]);

        for parity in [false, true] {
            let signed = authorization
                .clone()
                .into_signed(Signature::new(r, s, parity));
            let converted = BroadcasterRawParamsTransact7702Authorization::try_from(&signed)
                .expect("convert signed authorization");

            assert_eq!(converted.address, authorization.address);
            assert_eq!(converted.chain_id, authorization.chain_id);
            assert_eq!(converted.nonce, authorization.nonce);
            assert_eq!(
                converted.signature.signature_type,
                BroadcasterRawParamsTransact7702SignatureType::Signature
            );
            assert_eq!(converted.signature.network_v, ());
            assert_eq!(
                converted.signature.r,
                FixedBytes::from(r.to_be_bytes::<32>())
            );
            assert_eq!(
                converted.signature.s,
                FixedBytes::from(s.to_be_bytes::<32>())
            );
            assert_eq!(converted.signature.v, 27 + u64::from(parity));
        }

        let invalid = SignedAuthorization::new_unchecked(authorization, 2, r, s);
        assert!(matches!(
            BroadcasterRawParamsTransact7702Authorization::try_from(&invalid),
            Err(Transact7702Error::InvalidAuthorizationParity)
        ));
    }

    #[test]
    fn strict_tx7702_normalizes_checksum_addresses_and_rejects_invalid_electrum_v() {
        let mut value =
            serde_json::to_value(sample_strict_tx7702_params()).expect("strict params JSON");
        value["to"] = serde_json::json!("0x52908400098527886e0f7030069857d2e4169ee7");
        value["authorization"]["address"] =
            serde_json::json!("0x8617e340b3d01fa5f11f306f4090fd50e238070d");

        let normalized: BroadcasterRawParamsTransact7702 =
            serde_json::from_value(value).expect("deserialize lowercase addresses");
        let normalized = serde_json::to_value(normalized).expect("serialize checksummed addresses");
        assert_eq!(
            normalized["to"],
            "0x52908400098527886E0F7030069857D2E4169EE7"
        );
        assert_eq!(
            normalized["authorization"]["address"],
            "0x8617E340B3D01FA5F11F306F4090FD50E238070D"
        );
        assert_eq!(normalized["data"], "0xabcdef");
        assert_eq!(
            normalized["authorization"]["signature"]["r"],
            format!("0x{}", "ab".repeat(32))
        );
        assert_eq!(
            normalized["authorization"]["signature"]["s"],
            format!("0x{}", "cd".repeat(32))
        );

        for valid_v in [27, 28] {
            let mut valid = normalized.clone();
            valid["authorization"]["signature"]["v"] = serde_json::json!(valid_v);
            assert!(
                serde_json::from_value::<BroadcasterRawParamsTransact7702>(valid).is_ok(),
                "valid numeric v should deserialize: {valid_v}"
            );
        }

        for invalid_v in [
            serde_json::json!(26),
            serde_json::json!(29),
            serde_json::json!("27"),
            serde_json::json!(true),
            serde_json::json!(27.5),
        ] {
            let mut invalid = normalized.clone();
            invalid["authorization"]["signature"]["v"] = invalid_v;
            assert!(
                serde_json::from_value::<BroadcasterRawParamsTransact7702>(invalid).is_err(),
                "invalid v should reject"
            );
        }

        let mut invalid_for_serialization = sample_strict_tx7702_params();
        invalid_for_serialization.authorization.signature.v = 26;
        assert!(serde_json::to_value(invalid_for_serialization).is_err());
    }

    #[test]
    fn strict_tx7702_deserialization_rejects_omissions_and_unknown_shapes() {
        let base = serde_json::to_value(sample_strict_tx7702_params()).expect("strict params JSON");
        let required_fields = [
            "transactType",
            "txidVersion",
            "to",
            "data",
            "broadcasterViewingKey",
            "chainID",
            "chainType",
            "feesID",
            "useRelayAdapt",
            "devLog",
            "minVersion",
            "maxVersion",
            "preTransactionPOIsPerTxidLeafPerList",
            "gasLimit",
            "maxFeePerGas",
            "maxPriorityFeePerGas",
            "authorization",
        ];
        for field in required_fields {
            let mut value = base.clone();
            assert!(
                value
                    .as_object_mut()
                    .expect("params object")
                    .remove(field)
                    .is_some()
            );
            assert!(
                serde_json::from_value::<BroadcasterRawParamsTransact7702>(value).is_err(),
                "omitted required field should reject: {field}"
            );
        }

        for field in ["address", "chainId", "nonce", "signature"] {
            let mut value = base.clone();
            assert!(
                value["authorization"]
                    .as_object_mut()
                    .expect("authorization object")
                    .remove(field)
                    .is_some()
            );
            assert!(
                serde_json::from_value::<BroadcasterRawParamsTransact7702>(value).is_err(),
                "omitted required authorization field should reject: {field}"
            );
        }

        for field in ["_type", "networkV", "r", "s", "v"] {
            let mut value = base.clone();
            assert!(
                value["authorization"]["signature"]
                    .as_object_mut()
                    .expect("signature object")
                    .remove(field)
                    .is_some()
            );
            assert!(
                serde_json::from_value::<BroadcasterRawParamsTransact7702>(value).is_err(),
                "omitted required signature field should reject: {field}"
            );
        }

        let mut wrong_type = base.clone();
        wrong_type["transactType"] = serde_json::json!("COMMON");
        let mut missing_type = base.clone();
        missing_type
            .as_object_mut()
            .expect("params object")
            .remove("transactType");
        for (label, value) in [
            ("wrong transactType", wrong_type),
            ("missing transactType", missing_type),
        ] {
            assert!(
                serde_json::from_value::<BroadcasterRawParamsTransact7702>(value).is_err(),
                "{label} should reject"
            );
        }

        let quantity_fields = [
            "gasLimit",
            "maxFeePerGas",
            "maxPriorityFeePerGas",
            "authorization.chainId",
            "authorization.nonce",
        ];
        for field in quantity_fields {
            let mut value = base.clone();
            set_strict_quantity(&mut value, field, serde_json::json!(123));
            assert!(
                serde_json::from_value::<BroadcasterRawParamsTransact7702>(value).is_err(),
                "numeric quantity should reject: {field}"
            );

            for malformed in ["", "01", "+1", "-1", " 1", "1 ", "0x1", "not-a-number"] {
                let mut value = base.clone();
                set_strict_quantity(&mut value, field, serde_json::json!(malformed));
                assert!(
                    serde_json::from_value::<BroadcasterRawParamsTransact7702>(value).is_err(),
                    "malformed quantity should reject: {field}={malformed:?}"
                );
            }

            let overflow = if field == "gasLimit" || field == "authorization.nonce" {
                "18446744073709551616".to_string()
            } else {
                format!("{}0", U256::MAX)
            };
            let mut value = base.clone();
            set_strict_quantity(&mut value, field, serde_json::json!(overflow));
            assert!(
                serde_json::from_value::<BroadcasterRawParamsTransact7702>(value).is_err(),
                "overflow quantity should reject: {field}"
            );
        }

        let mut missing_authorization = base.clone();
        missing_authorization["authorization"] = serde_json::Value::Null;
        assert!(
            serde_json::from_value::<BroadcasterRawParamsTransact7702>(missing_authorization)
                .is_err()
        );

        let mut non_null_network_v = base.clone();
        non_null_network_v["authorization"]["signature"]["networkV"] = serde_json::json!(0);
        assert!(
            serde_json::from_value::<BroadcasterRawParamsTransact7702>(non_null_network_v).is_err()
        );

        let mut wrong_signature_type = base.clone();
        wrong_signature_type["authorization"]["signature"]["_type"] =
            serde_json::json!("not-signature");
        assert!(
            serde_json::from_value::<BroadcasterRawParamsTransact7702>(wrong_signature_type)
                .is_err()
        );

        let mut min_gas_price = base.clone();
        min_gas_price["minGasPrice"] = serde_json::json!("1");
        assert!(serde_json::from_value::<BroadcasterRawParamsTransact7702>(min_gas_price).is_err());

        for field in ["yParity", "r", "s"] {
            let mut flattened = base.clone();
            flattened["authorization"][field] = serde_json::json!(0);
            assert!(
                serde_json::from_value::<BroadcasterRawParamsTransact7702>(flattened).is_err(),
                "flattened authorization field should reject: {field}"
            );
        }

        let mut unknown = base;
        unknown["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<BroadcasterRawParamsTransact7702>(unknown).is_err());
    }

    #[test]
    fn strict_tx7702_debug_summaries_redact_all_wire_values() {
        let mut params = sample_strict_tx7702_params();
        params.to = Address::from([0xa1; 20]);
        params.data = Bytes::from(vec![0xa2; 7]);
        params.broadcaster_viewing_key = FixedBytes::from([0xa3; 32]);
        params.gas_limit = u64::from_be_bytes([0xaf; 8]);
        params.max_fee_per_gas = U256::from_be_bytes([0xad; 32]);
        params.max_priority_fee_per_gas = U256::from_be_bytes([0xae; 32]);
        params.authorization.address = Address::from([0xa4; 20]);
        params.authorization.signature.r = FixedBytes::from([0xa5; 32]);
        params.authorization.signature.s = FixedBytes::from([0xa6; 32]);

        let poi = PreTxPoi {
            snark_proof: SnarkJsProof::zero(),
            txid_merkleroot: FixedBytes::from([0xa7; 32]),
            poi_merkleroots: vec![FixedBytes::from([0xa8; 32])],
            blinded_commitments_out: vec![FixedBytes::from([0xa9; 32])],
            railgun_txid_if_has_unshield: Bytes::from(vec![0xaa; 32]),
        };
        let mut per_leaf = BTreeMap::new();
        per_leaf.insert(FixedBytes::from([0xab; 32]), poi);
        let mut per_list = BTreeMap::new();
        per_list.insert(FixedBytes::from([0xac; 32]), per_leaf);
        params.pre_transaction_pois_per_txid_leaf_per_list = per_list;

        let authorization = &params.authorization;
        let signature = &authorization.signature;
        let rendered = format!(
            "{:?}\n{:?}\n{:?}\n{:?}\n{:?}",
            params, authorization, signature, signature.signature_type, params.transact_type
        );
        for sentinel in [
            format!("0x{}", "a1".repeat(20)),
            "a2".repeat(7),
            "a3".repeat(32),
            u64::from_be_bytes([0xaf; 8]).to_string(),
            U256::from_be_bytes([0xad; 32]).to_string(),
            U256::from_be_bytes([0xae; 32]).to_string(),
            format!("0x{}", "a4".repeat(20)),
            "a5".repeat(32),
            "a6".repeat(32),
            "a7".repeat(32),
            "a8".repeat(32),
            "a9".repeat(32),
            "aa".repeat(32),
            "ab".repeat(32),
            "ac".repeat(32),
            "SENTINEL-FEE-ID".to_string(),
        ] {
            assert!(
                !rendered.contains(&sentinel),
                "leaked strict DTO sentinel: {sentinel}"
            );
        }
        assert!(rendered.contains("chain_id: 31337"));
        assert!(rendered.contains("envelope_kind: \"tx7702\""));
        assert!(rendered.contains("calldata_len: 7"));
        assert!(rendered.contains("poi_list_count: 1"));
        assert!(rendered.contains("poi_entry_count: 1"));
        assert!(rendered.contains("address_present: true"));
        assert!(rendered.contains("r_present: true"));
        assert!(rendered.contains("s_present: true"));
    }

    #[test]
    fn strict_tx7702_public_encryption_roundtrips_validated_plaintext_and_dispatches_strictly() {
        let _decrypt_trace_test_guard = DECRYPT_TRACE_TEST_LOCK
            .lock()
            .expect("decrypt trace test lock poisoned");
        let (params, prepared, finalized, viewing_key_data, required_list_key) =
            strict_fee_validation_fixture(U256::ZERO);
        let broadcaster_viewing_private_seed = [0x79; 32];
        let broadcaster_viewing_pubkey = SigningKey::from_bytes(&broadcaster_viewing_private_seed)
            .verifying_key()
            .to_bytes();
        let encrypted = EncryptedTransactRequest::encrypt_7702(
            broadcaster_viewing_pubkey,
            &params,
            &prepared,
            &finalized,
            &viewing_key_data.viewing_private_key,
            viewing_key_data.master_public_key,
            &[required_list_key],
        )
        .expect("encrypt validated strict TX7702 request");

        assert_eq!(
            decrypt_authenticated_plaintext(
                &encrypted.shared_key,
                &encrypted.encrypted_data[0],
                encrypted.encrypted_data[1].to_vec(),
            )
            .expect("decrypt strict plaintext"),
            Some(serde_json::to_vec(&params).expect("serialize strict params"))
        );

        let payload: serde_json::Value = serde_json::from_slice(
            &encrypted
                .to_transact_payload()
                .expect("serialize transact envelope"),
        )
        .expect("parse transact envelope");
        assert_eq!(payload["method"], "transact");
        assert_eq!(
            payload["params"]["pubkey"],
            serde_json::to_value(FixedBytes::from(encrypted.pubkey)).expect("serialize pubkey")
        );
        assert_eq!(
            payload["params"]["encryptedData"],
            serde_json::to_value(encrypted.encrypted_data.clone())
                .expect("serialize encrypted data")
        );

        let explicit = try_decrypt_transact_request_7702(
            &broadcaster_viewing_private_seed,
            encrypted.pubkey,
            &encrypted.encrypted_data,
        )
        .expect("explicit strict decrypt")
        .expect("strict request");
        assert_eq!(explicit.shared_key, encrypted.shared_key);
        let expected_params_json =
            serde_json::to_value(&params).expect("serialize expected strict params");
        assert_eq!(
            serde_json::to_value(&explicit.params).expect("serialize explicit strict params"),
            expected_params_json
        );

        let dispatched = try_decrypt_transact_request_dispatched(
            &broadcaster_viewing_private_seed,
            encrypted.pubkey,
            &encrypted.encrypted_data,
        )
        .expect("dispatch strict decrypt")
        .expect("dispatched request");
        let dispatched_debug = format!("{dispatched:?}");
        let DecryptedTransactRequest::Tx7702(request) = dispatched else {
            panic!("expected strict dispatched request");
        };
        assert_eq!(request.shared_key, encrypted.shared_key);
        assert_eq!(
            serde_json::to_value(&request.params).expect("serialize dispatched strict params"),
            expected_params_json
        );
        assert!(dispatched_debug.contains("Tx7702"));
        assert!(dispatched_debug.contains("shared_key: \"<redacted>\""));
        assert!(!dispatched_debug.contains("SENTINEL-FEE-ID"));
    }

    #[test]
    fn strict_tx7702_public_encryption_rejects_mutation_before_ciphertext() {
        let (mut params, prepared, finalized, viewing_key_data, required_list_key) =
            strict_fee_validation_fixture(U256::ZERO);
        params.authorization.nonce += 1;
        let broadcaster_viewing_private_seed = [0x79; 32];
        let broadcaster_viewing_pubkey = SigningKey::from_bytes(&broadcaster_viewing_private_seed)
            .verifying_key()
            .to_bytes();

        let result = EncryptedTransactRequest::encrypt_7702(
            broadcaster_viewing_pubkey,
            &params,
            &prepared,
            &finalized,
            &viewing_key_data.viewing_private_key,
            viewing_key_data.master_public_key,
            &[required_list_key],
        );

        assert!(matches!(
            result,
            Err(Transact7702Error::CanonicalOperationMismatch)
        ));
    }

    #[test]
    fn legacy_absent_and_common_requests_keep_legacy_decrypt_and_dispatch_behavior() {
        let _decrypt_trace_test_guard = DECRYPT_TRACE_TEST_LOCK
            .lock()
            .expect("decrypt trace test lock poisoned");
        let broadcaster_viewing_private_seed = [0x79; 32];
        let broadcaster_viewing_pubkey = SigningKey::from_bytes(&broadcaster_viewing_private_seed)
            .verifying_key()
            .to_bytes();
        let client_seed = [0x7a; 32];

        let (_, transaction, direct_params, _, _) = sample_transaction_and_params(None);
        let direct_data = direct_params.data;
        let legacy_relay_data: Bytes = relayCall {
            _transactions: vec![transaction],
            _actionData: ActionData {
                random: FixedBytes::from([0x01; 31]),
                requireSuccess: true,
                minGasLimit: U256::ZERO,
                calls: Vec::new(),
            },
        }
        .abi_encode()
        .into();

        for data in [direct_data, legacy_relay_data] {
            for transact_type in [None, Some(BroadcasterTransactRequestType::Common)] {
                let (_, _, mut params, _, _) = sample_transaction_and_params(None);
                params.data = data.clone();
                params.transact_type = transact_type;
                let encrypted = EncryptedTransactRequest::encrypt_with_seed(
                    broadcaster_viewing_pubkey,
                    &params,
                    client_seed,
                )
                .expect("encrypt legacy request");

                let legacy = try_decrypt_transact_request(
                    &broadcaster_viewing_private_seed,
                    encrypted.pubkey,
                    &encrypted.encrypted_data,
                )
                .expect("legacy decrypt")
                .expect("legacy request");
                assert_eq!(legacy.shared_key, encrypted.shared_key);
                assert_eq!(legacy.params.transact_type, transact_type);
                assert_eq!(legacy.params.data, params.data);

                if matches!(transact_type, Some(BroadcasterTransactRequestType::Common)) {
                    assert!(matches!(
                        try_decrypt_transact_request_7702(
                            &broadcaster_viewing_private_seed,
                            encrypted.pubkey,
                            &encrypted.encrypted_data,
                        ),
                        Err(Transact7702Error::JsonDeserialize)
                    ));
                }

                let dispatched = try_decrypt_transact_request_dispatched(
                    &broadcaster_viewing_private_seed,
                    encrypted.pubkey,
                    &encrypted.encrypted_data,
                )
                .expect("legacy dispatch")
                .expect("dispatched legacy request");
                assert!(matches!(
                    dispatched,
                    DecryptedTransactRequest::Legacy(request)
                        if request.shared_key == encrypted.shared_key
                            && request.params.transact_type == transact_type
                            && request.params.data == params.data
                ));
            }
        }

        let (_, _, base_params, _, _) = sample_transaction_and_params(None);
        let mut legacy_value = serde_json::to_value(base_params).expect("serialize legacy DTO");
        legacy_value["legacyExtension"] = serde_json::json!("historical-compatible");
        let encrypted =
            encrypt_params_with_seed(broadcaster_viewing_pubkey, &legacy_value, client_seed)
                .expect("encrypt legacy extension request");
        assert!(matches!(
            try_decrypt_transact_request_dispatched(
                &broadcaster_viewing_private_seed,
                encrypted.pubkey,
                &encrypted.encrypted_data,
            ),
            Ok(Some(DecryptedTransactRequest::Legacy(_)))
        ));
    }

    #[test]
    fn strict_tx7702_encrypted_boundary_rejects_malformed_and_downgraded_inputs() {
        let _decrypt_trace_test_guard = DECRYPT_TRACE_TEST_LOCK
            .lock()
            .expect("decrypt trace test lock poisoned");
        let base = serde_json::to_value(sample_strict_tx7702_params()).expect("strict params JSON");
        let broadcaster_viewing_private_seed = [0x79; 32];
        let broadcaster_viewing_pubkey = SigningKey::from_bytes(&broadcaster_viewing_private_seed)
            .verifying_key()
            .to_bytes();
        let client_seed = [0x7a; 32];

        let valid = encrypt_params_with_seed(broadcaster_viewing_pubkey, &base, client_seed)
            .expect("encrypt strict boundary fixture");
        assert!(matches!(
            try_decrypt_transact_request_dispatched(
                &[0x7b; 32],
                valid.pubkey,
                &valid.encrypted_data,
            ),
            Ok(None)
        ));

        let mut tampered_data = valid.encrypted_data.clone();
        let mut tampered_ciphertext = tampered_data[1].to_vec();
        tampered_ciphertext[0] ^= 1;
        tampered_data[1] = Bytes::from(tampered_ciphertext);
        assert!(matches!(
            try_decrypt_transact_request_dispatched(
                &broadcaster_viewing_private_seed,
                valid.pubkey,
                &tampered_data,
            ),
            Ok(None)
        ));

        let malformed_data = [Bytes::from(vec![0u8; 31]), valid.encrypted_data[1].clone()];
        let error = try_decrypt_transact_request_dispatched(
            &broadcaster_viewing_private_seed,
            valid.pubkey,
            &malformed_data,
        )
        .expect_err("malformed IV/tag length should fail");
        assert!(matches!(
            &error,
            Transact7702Error::Transact(TransactError::InvalidIvTag { len: 31 })
        ));
        assert!(!format!("{error:?} {error}").contains("SENTINEL-FEE-ID"));

        for label in [
            "missing transactType",
            "COMMON transactType",
            "missing transactType and gasLimit with current selector",
            "missing transactType and gasLimit with legacy selector",
            "COMMON transactType and gasLimit absent with current selector",
            "COMMON transactType and gasLimit absent with legacy selector",
            "missing gasLimit",
            "missing authorization",
            "malformed decimal fee",
            "invalid nested Electrum v",
        ] {
            let mut value = base.clone();
            match label {
                "missing transactType" => {
                    value
                        .as_object_mut()
                        .expect("strict params object")
                        .remove("transactType");
                }
                "COMMON transactType" => value["transactType"] = serde_json::json!("COMMON"),
                "missing transactType and gasLimit with current selector" => {
                    let object = value.as_object_mut().expect("strict params object");
                    object.remove("transactType");
                    object.remove("gasLimit");
                    value["data"] = serde_json::json!(format!(
                        "0x{}deadbeef",
                        alloy::hex::encode(RelayAdapt7702Current::executeCall::SELECTOR)
                    ));
                }
                "missing transactType and gasLimit with legacy selector" => {
                    let object = value.as_object_mut().expect("strict params object");
                    object.remove("transactType");
                    object.remove("gasLimit");
                    value["data"] = serde_json::json!(format!(
                        "0x{}deadbeef",
                        alloy::hex::encode(RelayAdapt7702Legacy::executeCall::SELECTOR)
                    ));
                }
                "COMMON transactType and gasLimit absent with current selector" => {
                    value["transactType"] = serde_json::json!("COMMON");
                    value
                        .as_object_mut()
                        .expect("strict params object")
                        .remove("gasLimit");
                    value["data"] = serde_json::json!(format!(
                        "0x{}deadbeef",
                        alloy::hex::encode(RelayAdapt7702Current::executeCall::SELECTOR)
                    ));
                }
                "COMMON transactType and gasLimit absent with legacy selector" => {
                    value["transactType"] = serde_json::json!("COMMON");
                    value
                        .as_object_mut()
                        .expect("strict params object")
                        .remove("gasLimit");
                    value["data"] = serde_json::json!(format!(
                        "0x{}deadbeef",
                        alloy::hex::encode(RelayAdapt7702Legacy::executeCall::SELECTOR)
                    ));
                }
                "missing gasLimit" => {
                    value
                        .as_object_mut()
                        .expect("strict params object")
                        .remove("gasLimit");
                }
                "missing authorization" => {
                    value
                        .as_object_mut()
                        .expect("strict params object")
                        .remove("authorization");
                }
                "malformed decimal fee" => {
                    value["maxFeePerGas"] = serde_json::json!("not-a-number");
                }
                "invalid nested Electrum v" => {
                    value["authorization"]["signature"]["v"] = serde_json::json!(26);
                }
                _ => unreachable!("listed strict boundary case"),
            }

            let raw_json = serde_json::to_string(&value).expect("serialize malformed fixture");
            let encrypted =
                encrypt_params_with_seed(broadcaster_viewing_pubkey, &value, client_seed)
                    .expect("encrypt malformed strict boundary fixture");
            let error = try_decrypt_transact_request_dispatched(
                &broadcaster_viewing_private_seed,
                encrypted.pubkey,
                &encrypted.encrypted_data,
            )
            .expect_err(label);
            assert!(
                matches!(&error, Transact7702Error::JsonDeserialize),
                "{label}: {error:?}"
            );

            let rendered = format!("{error:?} {error}");
            assert!(!rendered.contains(&raw_json), "{label} leaked raw JSON");
            for sentinel in [
                "SENTINEL-FEE-ID",
                "0x1111111111111111111111111111111111111111",
                "abcdef",
                "3333333333333333333333333333333333333333333333333333333333333333",
                "4444444444444444444444444444444444444444",
                "abababababababababababababababababababababababababababababababab",
                "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
                "987654",
                "42000000000",
                "1700000000",
                "31337",
                "42",
                "not-a-number",
            ] {
                assert!(!rendered.contains(sentinel), "{label} leaked {sentinel}");
            }
        }
    }

    #[test]
    fn tx7702_dispatch_does_not_fallback_to_the_legacy_dto() {
        let _decrypt_trace_test_guard = DECRYPT_TRACE_TEST_LOCK
            .lock()
            .expect("decrypt trace test lock poisoned");
        let (_, _, mut params, _, _) = sample_transaction_and_params(None);
        params.transact_type = Some(BroadcasterTransactRequestType::Tx7702);
        let broadcaster_viewing_private_seed = [0x79; 32];
        let broadcaster_viewing_pubkey = SigningKey::from_bytes(&broadcaster_viewing_private_seed)
            .verifying_key()
            .to_bytes();
        let encrypted = EncryptedTransactRequest::encrypt_with_seed(
            broadcaster_viewing_pubkey,
            &params,
            [0x7a; 32],
        )
        .expect("encrypt legacy-shaped TX7702 request");

        assert!(matches!(
            try_decrypt_transact_request_dispatched(
                &broadcaster_viewing_private_seed,
                encrypted.pubkey,
                &encrypted.encrypted_data,
            ),
            Err(Transact7702Error::JsonDeserialize)
        ));
    }

    #[test]
    fn parse_transact_envelope_classifies_empty_batches_by_selector() {
        let legacy_action_data = ActionData {
            random: FixedBytes::from([0x01; 31]),
            requireSuccess: true,
            minGasLimit: U256::ZERO,
            calls: Vec::new(),
        };
        let relay_calldata = relayCall {
            _transactions: Vec::new(),
            _actionData: legacy_action_data,
        }
        .abi_encode();
        assert!(matches!(
            parse_transact_envelope(&relay_calldata).expect("empty legacy relay calldata"),
            ParsedTransactEnvelope::LegacyRelay { transactions, .. }
                if transactions.is_empty()
        ));

        let direct_calldata = transactCall {
            _transactions: Vec::new(),
        }
        .abi_encode();
        assert!(matches!(
            parse_transact_envelope(&direct_calldata).expect("empty direct calldata"),
            ParsedTransactEnvelope::Direct { transactions } if transactions.is_empty()
        ));

        let action_data = RelayAdapt7702ActionData {
            requireSuccess: true,
            minGasLimit: U256::ZERO,
            calls: Vec::new(),
        };
        let current_calldata = RelayAdapt7702Current::executeCall {
            _transactions: Vec::new(),
            _actionData: action_data.clone(),
            _executeNonce: U256::from(7_u64),
            _signature: Bytes::from(vec![0xaa, 0xbb]),
        }
        .abi_encode();
        assert!(matches!(
            parse_transact_envelope(&current_calldata).expect("empty current 7702 calldata"),
            ParsedTransactEnvelope::RelayAdapt7702 { transactions, .. }
                if transactions.is_empty()
        ));

        let legacy_calldata = RelayAdapt7702Legacy::executeCall {
            _transactions: Vec::new(),
            _actionData: action_data,
            _signature: Bytes::from(vec![0xcc, 0xdd]),
        }
        .abi_encode();
        assert!(matches!(
            parse_transact_envelope(&legacy_calldata).expect("empty legacy 7702 calldata"),
            ParsedTransactEnvelope::RelayAdapt7702 { transactions, .. }
                if transactions.is_empty()
        ));
        assert_eq!(
            executeCall::SELECTOR,
            RelayAdapt7702Legacy::executeCall::SELECTOR
        );
    }

    #[test]
    fn parse_transact_envelope_preserves_7702_version_data_without_fallback() {
        let action_data = RelayAdapt7702ActionData {
            requireSuccess: false,
            minGasLimit: U256::from(123_u64),
            calls: vec![Call {
                to: Address::from([0x11; 20]),
                data: Bytes::from(vec![0x22, 0x33]),
                value: U256::from(44_u64),
            }],
        };
        let execute_nonce = U256::from(0x1234_u64);
        let current_signature = Bytes::from(vec![0xde, 0xad, 0xbe]);
        let current_calldata = RelayAdapt7702Current::executeCall {
            _transactions: Vec::new(),
            _actionData: action_data.clone(),
            _executeNonce: execute_nonce,
            _signature: current_signature.clone(),
        }
        .abi_encode();

        let ParsedTransactEnvelope::RelayAdapt7702 {
            version,
            transactions,
            action_data: parsed_action_data,
            execution_signature,
        } = parse_transact_envelope(&current_calldata).expect("current 7702 calldata")
        else {
            panic!("expected current 7702 envelope");
        };
        assert!(transactions.is_empty());
        assert!(matches!(
            version,
            RelayAdapt7702ExecutionVersion::CurrentNonceAware { nonce }
                if nonce.value() == execute_nonce
        ));
        assert_eq!(parsed_action_data.abi_encode(), action_data.abi_encode());
        assert_eq!(execution_signature, current_signature);

        let legacy_signature = Bytes::from(vec![0xfa, 0xce]);
        let legacy_calldata = RelayAdapt7702Legacy::executeCall {
            _transactions: Vec::new(),
            _actionData: action_data.clone(),
            _signature: legacy_signature.clone(),
        }
        .abi_encode();
        let ParsedTransactEnvelope::RelayAdapt7702 {
            version,
            transactions,
            action_data: parsed_action_data,
            execution_signature,
        } = parse_transact_envelope(&legacy_calldata).expect("legacy 7702 calldata")
        else {
            panic!("expected legacy 7702 envelope");
        };
        assert!(transactions.is_empty());
        assert!(matches!(
            version,
            RelayAdapt7702ExecutionVersion::LegacyPreExecuteNonce
        ));
        assert_eq!(parsed_action_data.abi_encode(), action_data.abi_encode());
        assert_eq!(execution_signature, legacy_signature);
        assert!(RelayAdapt7702Current::executeCall::abi_decode(&legacy_calldata).is_err());
    }

    #[test]
    fn parse_transact_envelope_does_not_fallback_after_recognized_selector() {
        let selectors = [
            transactCall::SELECTOR,
            relayCall::SELECTOR,
            RelayAdapt7702Current::executeCall::SELECTOR,
            RelayAdapt7702Legacy::executeCall::SELECTOR,
        ];

        for selector in selectors {
            assert!(matches!(
                parse_transact_envelope(&selector),
                Err(TransactError::AbiDecode(_))
            ));
        }
    }

    #[test]
    fn parse_transact_envelope_preserves_typed_short_and_unknown_errors() {
        assert!(matches!(
            parse_transact_envelope(&[0xde, 0xad, 0xbe, 0xef]),
            Err(TransactError::UnknownFunctionCall { selector })
                if selector == "deadbeef"
        ));
        assert!(matches!(
            parse_transact_envelope(&[0xde, 0xad, 0xbe]),
            Err(TransactError::CalldataTooShort { len: 3 })
        ));
    }

    #[test]
    fn parsed_transact_envelope_debug_redacts_decoded_values() {
        let (_, mut transaction, _, _, _) = sample_transaction_and_params(None);
        transaction.nullifiers = vec![FixedBytes::from([0x44; 32])];
        let calldata = RelayAdapt7702Current::executeCall {
            _transactions: vec![transaction],
            _actionData: RelayAdapt7702ActionData {
                requireSuccess: true,
                minGasLimit: U256::ZERO,
                calls: vec![Call {
                    to: Address::from([0x11; 20]),
                    data: Bytes::from(vec![0x22, 0x22]),
                    value: U256::ZERO,
                }],
            },
            _executeNonce: U256::from(9_u64),
            _signature: Bytes::from(vec![0x33; 65]),
        }
        .abi_encode();
        let envelope = parse_transact_envelope(&calldata).expect("current 7702 calldata");
        let rendered = format!("{envelope:?}");

        assert!(!rendered.contains(&"11".repeat(20)));
        assert!(!rendered.contains(&"22".repeat(2)));
        assert!(!rendered.contains(&"33".repeat(65)));
        assert!(!rendered.contains(&"44".repeat(32)));
    }

    #[test]
    fn transact_debug_summaries_redact_request_and_parsed_material() {
        let proof = SnarkJsProof {
            pi_a: [U256::from_be_bytes([0xc5; 32]); 2],
            pi_b: [[U256::from_be_bytes([0xc5; 32]); 2]; 2],
            pi_c: [U256::from_be_bytes([0xc5; 32]); 2],
        };
        let poi = PreTxPoi {
            snark_proof: proof.clone(),
            txid_merkleroot: FixedBytes::from([0xc1; 32]),
            poi_merkleroots: vec![FixedBytes::from([0xc2; 32]); 2],
            blinded_commitments_out: vec![FixedBytes::from([0xc3; 32])],
            railgun_txid_if_has_unshield: Bytes::from(vec![0xc4; 32]),
        };
        let mut poi_per_leaf = BTreeMap::new();
        poi_per_leaf.insert(FixedBytes::from([0xca; 32]), poi.clone());
        let mut poi_per_list = BTreeMap::new();
        poi_per_list.insert(FixedBytes::from([0xcb; 32]), poi_per_leaf);
        let fee_assurance = FeeNoteAssuranceContext {
            chain_type: 0,
            txid_version: DEFAULT_TXID_VERSION.to_string(),
            railgun_txid: U256::from_be_bytes([0xc6; 32]),
            utxo_tree_in: 0xc7,
            fee_commitment: FixedBytes::from([0xc8; 32]),
            fee_note_npk: FixedBytes::from([0xc9; 32]),
            pre_transaction_pois_per_txid_leaf_per_list: poi_per_list.clone(),
            required_poi_list_keys: vec![FixedBytes::from([0xcc; 32])],
        };
        let signature = BroadcasterAuthorizationSignature {
            v: 27,
            r: U256::from_be_bytes([0xa7; 32]),
            s: U256::from_be_bytes([0xa8; 32]),
        };
        let authorization = BroadcasterAuthorization {
            address: Address::from([0xa4; 20]),
            nonce: U256::from_be_bytes([0xa5; 32]),
            chain_id: U256::from_be_bytes([0xa6; 32]),
            signature,
        };
        let (_, _, mut raw_params, _, _) = sample_transaction_and_params(None);
        raw_params.transact_type = Some(BroadcasterTransactRequestType::Tx7702);
        raw_params.to = Address::from([0xa1; 20]);
        raw_params.data = Bytes::from(vec![0xa2; 7]);
        raw_params.broadcaster_viewing_key = FixedBytes::from([0xa3; 32]);
        raw_params.fees_id = Some("SENTINEL-FEE-ID".to_string());
        raw_params.authorization = Some(authorization.clone());
        raw_params.pre_transaction_pois_per_txid_leaf_per_list = poi_per_list;

        let raw_debug = format!("{raw_params:?}");
        let authorization_debug = format!("{authorization:?}");
        let signature_debug = format!("{signature:?}");
        let decrypted_debug = format!(
            "{:?}",
            DecryptedTransact {
                shared_key: [0xab; 32],
                params: raw_params,
            }
        );
        let fee_assurance_debug = format!("{fee_assurance:?}");
        let poi_debug = format!("{poi:?}");
        let proof_debug = format!("{proof:?}");

        let parsed_transaction = ParsedTransactTransaction {
            railgun_txid: U256::from_be_bytes([0xd1; 32]),
            utxo_tree_in: 0xd2,
            tx_nullifiers_len: 2,
            tx_commitments_out_len: 3,
            has_unshield: true,
        };
        let parsed_calldata = ParsedTransactCalldata {
            fee_token: Address::from([0xd3; 20]),
            fee_amount: U256::from_be_bytes([0xd4; 32]),
            railgun_txid: U256::from_be_bytes([0xd5; 32]),
            utxo_tree_in: 0xd6,
            fee_commitment: FixedBytes::from([0xd7; 32]),
            fee_note_npk: FixedBytes::from([0xd8; 32]),
            tx_nullifiers_len: 2,
            tx_commitments_out_len: 3,
            transactions: vec![parsed_transaction],
            action_data: Some(ActionData {
                random: FixedBytes::from([0xd9; 31]),
                requireSuccess: true,
                minGasLimit: U256::from_be_bytes([0xda; 32]),
                calls: vec![Call {
                    to: Address::from([0xdb; 20]),
                    data: Bytes::from(vec![0xdc; 4]),
                    value: U256::from_be_bytes([0xdd; 32]),
                }],
            }),
            fee_note_assurance: Some(fee_assurance),
        };
        let parsed_calldata_debug = format!("{parsed_calldata:?}");
        let parsed_transaction_debug = format!("{:?}", parsed_calldata.transactions[0]);
        let parsed_assurance_debug = format!("{:?}", parsed_calldata.fee_note_assurance.as_ref());

        let rendered_diagnostics = [
            &raw_debug,
            &authorization_debug,
            &signature_debug,
            &decrypted_debug,
            &fee_assurance_debug,
            &poi_debug,
            &proof_debug,
            &parsed_calldata_debug,
            &parsed_transaction_debug,
            &parsed_assurance_debug,
        ];
        for rendered in rendered_diagnostics {
            assert!(!rendered.contains("SENTINEL-FEE-ID"));
            for sentinel in [
                "a1".repeat(20),
                "a2".repeat(7),
                "a3".repeat(32),
                "a4".repeat(20),
                "a5".repeat(32),
                "a6".repeat(32),
                "a7".repeat(32),
                "a8".repeat(32),
                "ab".repeat(32),
                "c1".repeat(32),
                "c2".repeat(32),
                "c3".repeat(32),
                "c4".repeat(32),
                "c5".repeat(32),
                "c6".repeat(32),
                "c7".to_string(),
                "c8".repeat(32),
                "c9".repeat(32),
                "ca".repeat(32),
                "cb".repeat(32),
                "cc".repeat(32),
                "d1".repeat(32),
                "d2".to_string(),
                "d3".repeat(20),
                "d4".repeat(32),
                "d5".repeat(32),
                "d6".to_string(),
                "d7".repeat(32),
                "d8".repeat(32),
                "d9".repeat(31),
                "da".repeat(32),
                "db".repeat(20),
                "dc".repeat(4),
                "dd".repeat(32),
            ] {
                assert!(
                    !rendered.contains(&sentinel),
                    "leaked sentinel in {rendered}"
                );
            }
        }

        assert!(raw_debug.contains("chain_id: 1"));
        assert!(raw_debug.contains("envelope_kind: \"tx7702\""));
        assert!(raw_debug.contains("calldata_len: 7"));
        assert!(raw_debug.contains("poi_list_count: 1"));
        assert!(authorization_debug.contains("address_present: true"));
        assert!(signature_debug.contains("category: \"authorization-signature\""));
        assert!(decrypted_debug.contains("shared_key: \"<redacted>\""));
        assert!(fee_assurance_debug.contains("required_poi_list_count: 1"));
        assert!(poi_debug.contains("poi_merkleroot_count: 2"));
        assert!(poi_debug.contains("unshield_present: true"));
        assert!(proof_debug.contains("category: \"snark-js-proof\""));
        assert!(parsed_calldata_debug.contains("action_data_present: true"));
        assert!(parsed_calldata_debug.contains("fee_note_assurance_present: true"));
        assert!(parsed_calldata_debug.contains("transaction_count: 1"));
        assert!(parsed_calldata_debug.contains("tx_nullifier_count: 2"));
        assert!(parsed_transaction_debug.contains("tx_commitment_output_count: 3"));
        assert!(parsed_transaction_debug.contains("has_unshield: true"));
    }

    #[test]
    fn malformed_transact_json_error_is_value_free() {
        let _decrypt_trace_test_guard = DECRYPT_TRACE_TEST_LOCK
            .lock()
            .expect("decrypt trace test lock poisoned");
        let key = [0x11; 32];
        let mut plaintext = br#"{"sentinel":"MALFORMED-PLAINTEXT""#.to_vec();
        let iv_tag = encrypt_in_place_16b_iv(&key, &mut plaintext).expect("encrypt malformed JSON");
        let error = decrypt::<BroadcasterRawParamsTransact>(&key, &iv_tag, plaintext)
            .expect_err("malformed JSON should fail");

        assert!(matches!(&error, TransactError::Json(_)));
        let debug = format!("{error:?}");
        let display = error.to_string();
        assert!(debug.contains("transact JSON deserialization failed"));
        assert_eq!(
            display,
            "json parse error: transact JSON deserialization failed"
        );
        let mut source_chain = String::new();
        let mut source = std::error::Error::source(&error);
        while let Some(current) = source {
            source_chain.push_str(&current.to_string());
            source = current.source();
        }
        assert!(source_chain.contains("transact JSON deserialization failed"));
        for rendered in [&debug, &display, &source_chain] {
            assert!(
                !rendered.contains("MALFORMED-PLAINTEXT"),
                "leaked malformed JSON: {rendered}"
            );
            assert!(
                !rendered.contains("sentinel"),
                "leaked custom JSON detail: {rendered}"
            );
        }
    }

    #[test]
    fn transact_json_error_preserves_public_source_compatibility() {
        let json_error = serde_json::from_str::<Value>("{")
            .expect_err("malformed JSON should produce a serde_json error");
        let error: TransactError = json_error.into();

        assert!(matches!(&error, TransactError::Json(_)));
        assert!(std::error::Error::source(&error).is_some());
    }

    #[test]
    fn legacy_and_strict_json_serialization_errors_keep_their_boundaries() {
        struct SerializationSentinel;

        impl serde::Serialize for SerializationSentinel {
            fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                Err(serde::ser::Error::custom("SERIALIZATION-SENTINEL"))
            }
        }

        let broadcaster_viewing_private_seed = [0x79; 32];
        let broadcaster_viewing_pubkey = SigningKey::from_bytes(&broadcaster_viewing_private_seed)
            .verifying_key()
            .to_bytes();
        let serialization_sentinel = SerializationSentinel;

        let Err(legacy) = encrypt_params_with_seed(
            broadcaster_viewing_pubkey,
            &serialization_sentinel,
            [0x7a; 32],
        ) else {
            panic!("sentinel serializer must fail legacy serialization");
        };
        assert!(matches!(legacy, TransactError::Json(_)));
        let legacy_debug = format!("{legacy:?}");
        let legacy_display = legacy.to_string();
        let mut legacy_source_chain = String::new();
        let mut source = std::error::Error::source(&legacy);
        while let Some(current) = source {
            legacy_source_chain.push_str(&current.to_string());
            source = current.source();
        }
        for rendered in [&legacy_debug, &legacy_display, &legacy_source_chain] {
            assert!(!rendered.contains("SERIALIZATION-SENTINEL"));
            assert!(rendered.contains("transact JSON serialization failed"));
        }
        assert_eq!(
            legacy_display,
            "json parse error: transact JSON serialization failed"
        );

        let Err(strict) = encrypt_params_with_seed_7702(
            broadcaster_viewing_pubkey,
            &serialization_sentinel,
            [0x7a; 32],
        ) else {
            panic!("sentinel serializer must fail strict serialization");
        };
        assert!(matches!(strict, Transact7702Error::JsonSerialize));
        let strict_debug = format!("{strict:?}");
        let strict_display = strict.to_string();
        assert!(!strict_debug.contains("SERIALIZATION-SENTINEL"));
        assert!(!strict_display.contains("SERIALIZATION-SENTINEL"));
    }

    #[test]
    fn try_decrypt_transact_request_tracing_redacts_all_request_material() {
        let _decrypt_trace_test_guard = DECRYPT_TRACE_TEST_LOCK
            .lock()
            .expect("decrypt trace test lock poisoned");
        let (_, mut transaction, mut params, _, _) = sample_transaction_and_params(None);

        let mut snark_proof = SnarkProof::default();
        snark_proof.a.x = U256::from_be_bytes([0x5d; 32]);
        snark_proof.a.y = U256::from_be_bytes([0x5d; 32]);
        snark_proof.b.x = [U256::from_be_bytes([0x5d; 32]); 2];
        snark_proof.b.y = [U256::from_be_bytes([0x5d; 32]); 2];
        snark_proof.c.x = U256::from_be_bytes([0x5d; 32]);
        snark_proof.c.y = U256::from_be_bytes([0x5d; 32]);
        transaction.proof = snark_proof;
        transaction.merkleRoot = FixedBytes::from([0x64; 32]);
        transaction.nullifiers = vec![FixedBytes::from([0x62; 32])];
        transaction.commitments = vec![FixedBytes::from([0x63; 32])];
        transaction.boundParams.commitmentCiphertext = vec![CommitmentCiphertext {
            ciphertext: [
                FixedBytes::from([0x65; 32]),
                FixedBytes::from([0x66; 32]),
                FixedBytes::from([0x67; 32]),
                FixedBytes::from([0x68; 32]),
            ],
            blindedSenderViewingKey: FixedBytes::from([0x69; 32]),
            blindedReceiverViewingKey: FixedBytes::from([0x6a; 32]),
            annotationData: Bytes::from(vec![0x6b; 7]),
            memo: Bytes::from(vec![0x6c; 11]),
        }];
        transaction.unshieldPreimage = CommitmentPreimage {
            npk: FixedBytes::from([0x6d; 32]),
            token: TokenData {
                tokenType: 0,
                tokenAddress: Address::from([0x6e; 20]),
                tokenSubID: U256::from_be_bytes([0x6f; 32]),
            },
            value: alloy::primitives::Uint::<120, 2>::from(0x7070_7070_7070_7070_u64),
        };

        let authorization_nonce = U256::from_be_bytes([0x55; 32]);
        let authorization_chain_id = U256::from_be_bytes([0x56; 32]);
        let authorization_r = U256::from_be_bytes([0x57; 32]);
        let authorization_s = U256::from_be_bytes([0x58; 32]);
        let authorization_v = u64::from_be_bytes([0x59; 8]);
        params.transact_type = Some(BroadcasterTransactRequestType::Tx7702);
        params.to = Address::from([0x11; 20]);
        params.broadcaster_viewing_key = FixedBytes::from([0x33; 32]);
        params.min_gas_price = Some(U256::from_be_bytes([0x75; 32]));
        params.max_fee_per_gas = Some(U256::from_be_bytes([0x76; 32]));
        params.max_priority_fee_per_gas = Some(U256::from_be_bytes([0x77; 32]));
        params.fees_id = Some(format!("0x{}", "5a".repeat(32)));
        params.authorization = Some(BroadcasterAuthorization {
            address: Address::from([0x44; 20]),
            nonce: authorization_nonce,
            chain_id: authorization_chain_id,
            signature: BroadcasterAuthorizationSignature {
                v: authorization_v,
                r: authorization_r,
                s: authorization_s,
            },
        });

        let poi = PreTxPoi {
            snark_proof: SnarkJsProof {
                pi_a: [U256::from_be_bytes([0x5d; 32]); 2],
                pi_b: [[U256::from_be_bytes([0x5d; 32]); 2]; 2],
                pi_c: [U256::from_be_bytes([0x5d; 32]); 2],
            },
            txid_merkleroot: FixedBytes::from([0x5e; 32]),
            poi_merkleroots: vec![FixedBytes::from([0x5f; 32])],
            blinded_commitments_out: vec![FixedBytes::from([0x60; 32])],
            railgun_txid_if_has_unshield: Bytes::from(vec![0x61; 32]),
        };
        let poi_list_key = FixedBytes::from([0x5b; 32]);
        let poi_leaf = FixedBytes::from([0x5c; 32]);
        let mut poi_by_leaf = BTreeMap::new();
        poi_by_leaf.insert(poi_leaf, poi);
        let mut poi_by_list = BTreeMap::new();
        poi_by_list.insert(poi_list_key, poi_by_leaf);
        params.pre_transaction_pois_per_txid_leaf_per_list = poi_by_list;

        params.data = RelayAdapt7702Current::executeCall {
            _transactions: vec![transaction],
            _actionData: RelayAdapt7702ActionData {
                requireSuccess: true,
                minGasLimit: U256::from_be_bytes([0x78; 32]),
                calls: vec![Call {
                    to: Address::from([0x71; 20]),
                    data: Bytes::from(vec![0x22; 17]),
                    value: U256::from_be_bytes([0x72; 32]),
                }],
            },
            _executeNonce: U256::from_be_bytes([0x73; 32]),
            _signature: Bytes::from(vec![0x74; 65]),
        }
        .abi_encode()
        .into();

        let broadcaster_viewing_private_seed = [0x79; 32];
        let client_seed = [0x7a; 32];
        let broadcaster_viewing_pubkey = SigningKey::from_bytes(&broadcaster_viewing_private_seed)
            .verifying_key()
            .to_bytes();
        let encrypted = EncryptedTransactRequest::encrypt_with_seed(
            broadcaster_viewing_pubkey,
            &params,
            client_seed,
        )
        .expect("encrypt deterministic transact request");

        let events = Arc::new(Mutex::new(Vec::new()));
        let encrypted_pubkey = encrypted.pubkey;
        let encrypted_data = encrypted.encrypted_data.clone();
        let decrypted = std::thread::spawn({
            let events = Arc::clone(&events);
            move || {
                with_default(EventCapture { events }, || {
                    tracing::callsite::rebuild_interest_cache();
                    try_decrypt_transact_request(
                        &broadcaster_viewing_private_seed,
                        encrypted_pubkey,
                        &encrypted_data,
                    )
                })
            }
        })
        .join()
        .expect("tracing capture thread panicked")
        .expect("decrypt deterministic transact request");
        assert!(decrypted.is_some());

        let events = events.lock().expect("trace capture lock");
        assert_eq!(
            events.len(),
            2,
            "only the actual decrypt events are captured"
        );
        let rendered = events
            .iter()
            .flat_map(|event| event.fields.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");

        assert!(rendered.contains("plaintext_category=\"broadcaster-transact-params\""));
        assert!(rendered.contains("plaintext_len="));
        assert!(rendered.contains("envelope_kind=\"tx7702\""));
        assert!(rendered.contains("encrypted_part_count=2"));
        assert!(rendered.contains("encrypted_total_len="));
        assert!(rendered.contains("message="));

        let authorization_v_hex = format!("{authorization_v:x}");
        let prohibited_sentinels = [
            format!("0x{}", "11".repeat(20)),
            "22".repeat(17),
            "33".repeat(32),
            format!("0x{}", "44".repeat(20)),
            format!("0x{}", "55".repeat(32)),
            format!("0x{}", "56".repeat(32)),
            format!("0x{}", "57".repeat(32)),
            format!("0x{}", "58".repeat(32)),
            authorization_v.to_string(),
            authorization_v_hex,
            format!("0x{}", "5a".repeat(32)),
            "5b".repeat(32),
            "5c".repeat(32),
            "5d".repeat(32),
            "5e".repeat(32),
            "5f".repeat(32),
            "60".repeat(32),
            "61".repeat(32),
            "62".repeat(32),
            "63".repeat(32),
            "64".repeat(32),
            "65".repeat(32),
            "66".repeat(32),
            "67".repeat(32),
            "68".repeat(32),
            "69".repeat(32),
            "6a".repeat(32),
            "6b".repeat(7),
            "6c".repeat(11),
            "6d".repeat(32),
            format!("0x{}", "6e".repeat(20)),
            "6f".repeat(32),
            format!("0x{}", "70".repeat(16)),
            "71".repeat(20),
            "72".repeat(32),
            "73".repeat(32),
            "74".repeat(65),
            "75".repeat(32),
            "76".repeat(32),
            "77".repeat(32),
            "78".repeat(32),
            alloy::hex::encode(encrypted.pubkey),
            format!("0x{}", alloy::hex::encode(encrypted.pubkey)),
            alloy::hex::encode(broadcaster_viewing_pubkey),
            format!("0x{}", alloy::hex::encode(broadcaster_viewing_pubkey)),
            alloy::hex::encode(encrypted.shared_key),
            format!("0x{}", alloy::hex::encode(encrypted.shared_key)),
            format!("{broadcaster_viewing_private_seed:?}"),
            format!("{client_seed:?}"),
            format!("{:?}", encrypted.shared_key),
        ];
        for sentinel in prohibited_sentinels {
            assert!(
                !rendered.contains(&sentinel),
                "leaked tracing sentinel: {sentinel}"
            );
        }

        for json_field in [
            "\"chainType\"",
            "\"chainID\"",
            "\"transactType\"",
            "\"maxFeePerGas\"",
            "\"maxPriorityFeePerGas\"",
            "\"feesID\"",
            "\"to\"",
            "\"data\"",
            "\"broadcasterViewingKey\"",
            "\"preTransactionPOIsPerTxidLeafPerList\"",
            "\"authorization\"",
            "\"address\"",
            "\"nonce\"",
            "\"chainId\"",
            "\"signature\"",
            "\"v\"",
            "\"r\"",
            "\"s\"",
            "\"nullifiers\"",
            "\"commitments\"",
            "\"commitmentCiphertext\"",
            "\"unshieldPreimage\"",
        ] {
            assert!(
                !rendered.contains(json_field),
                "leaked JSON field: {json_field}"
            );
        }
    }

    #[test]
    fn parse_transact_extracts_fee_note_context_fields() {
        let viewing_key_data = sample_viewing_key_data();
        let (calldata, _, _, fee_commitment, _) = sample_transaction_and_params(None);
        let parsed = parse_transact_calldata(
            &calldata,
            &viewing_key_data.viewing_private_key,
            viewing_key_data.master_public_key,
            None,
        )
        .expect("parse calldata");

        assert_eq!(parsed.utxo_tree_in, 9);
        assert_eq!(parsed.fee_commitment, fee_commitment);
        assert!(parsed.fee_note_assurance.is_none());
    }

    #[test]
    fn parse_transact_extracts_all_inner_transaction_metadata() {
        let viewing_key_data = sample_viewing_key_data();
        let (_, tx0, _, _, _) = sample_transaction_and_params(None);
        let mut tx1 = tx0.clone();
        tx1.boundParams.treeNumber = 10;
        tx1.nullifiers = vec![FixedBytes::from([2u8; 32]), FixedBytes::from([3u8; 32])];
        tx1.commitments.push(FixedBytes::from([4u8; 32]));
        let calldata = transactCall {
            _transactions: vec![tx0, tx1],
        }
        .abi_encode();

        let parsed = parse_transact_calldata(
            &calldata,
            &viewing_key_data.viewing_private_key,
            viewing_key_data.master_public_key,
            None,
        )
        .expect("parse calldata");

        assert_eq!(parsed.transactions.len(), 2);
        assert_eq!(parsed.transactions[0].utxo_tree_in, 9);
        assert_eq!(parsed.transactions[0].tx_nullifiers_len, 1);
        assert_eq!(parsed.transactions[0].tx_commitments_out_len, 1);
        assert!(!parsed.transactions[0].has_unshield);
        assert_eq!(parsed.transactions[1].utxo_tree_in, 10);
        assert_eq!(parsed.transactions[1].tx_nullifiers_len, 2);
        assert_eq!(parsed.transactions[1].tx_commitments_out_len, 2);
        assert_eq!(parsed.railgun_txid, parsed.transactions[0].railgun_txid);
    }

    #[test]
    fn parse_transact_decodes_relay_adapt_7702_execute_wrapper() {
        let viewing_key_data = sample_viewing_key_data();
        let (_, transaction, _, fee_commitment, _) = sample_transaction_and_params(None);
        let relay_action_data = RelayAdapt7702ActionData {
            requireSuccess: true,
            minGasLimit: uint!(123_U256),
            calls: vec![Call {
                to: Address::from([0x33; 20]),
                data: Bytes::from(vec![0x44, 0x55]),
                value: uint!(6_U256),
            }],
        };
        let calldata = executeCall {
            _transactions: vec![transaction],
            _actionData: relay_action_data.clone(),
            _signature: Bytes::from(vec![0x12, 0x34]),
        }
        .abi_encode();

        assert_eq!(&calldata[..4], &[0xc6, 0x1e, 0x6b, 0x9d]);

        let parsed = parse_transact_calldata(
            &calldata,
            &viewing_key_data.viewing_private_key,
            viewing_key_data.master_public_key,
            None,
        )
        .expect("parse 7702 execute calldata");

        let action_data = parsed.action_data.expect("action data");
        let expected_action_data = ActionData {
            random: FixedBytes::ZERO,
            requireSuccess: relay_action_data.requireSuccess,
            minGasLimit: relay_action_data.minGasLimit,
            calls: relay_action_data.calls,
        };
        assert_eq!(parsed.fee_commitment, fee_commitment);
        assert_eq!(action_data.abi_encode(), expected_action_data.abi_encode());
    }

    #[test]
    fn parse_transact_decodes_current_relay_adapt_7702_execute_wrapper() {
        let viewing_key_data = sample_viewing_key_data();
        let (_, transaction, _, fee_commitment, _) = sample_transaction_and_params(None);
        let relay_action_data = RelayAdapt7702ActionData {
            requireSuccess: false,
            minGasLimit: uint!(456_U256),
            calls: vec![Call {
                to: Address::from([0x66; 20]),
                data: Bytes::from(vec![0x77, 0x88, 0x99]),
                value: uint!(10_U256),
            }],
        };
        let calldata = RelayAdapt7702Current::executeCall {
            _transactions: vec![transaction],
            _actionData: relay_action_data.clone(),
            _executeNonce: uint!(7_U256),
            _signature: Bytes::from(vec![0xaa, 0xbb]),
        }
        .abi_encode();

        let parsed = parse_transact_calldata(
            &calldata,
            &viewing_key_data.viewing_private_key,
            viewing_key_data.master_public_key,
            None,
        )
        .expect("parse current 7702 execute calldata");

        let action_data = parsed.action_data.expect("action data");
        let expected_action_data = ActionData {
            random: FixedBytes::ZERO,
            requireSuccess: relay_action_data.requireSuccess,
            minGasLimit: relay_action_data.minGasLimit,
            calls: relay_action_data.calls,
        };
        assert_eq!(parsed.fee_commitment, fee_commitment);
        assert_eq!(action_data.abi_encode(), expected_action_data.abi_encode());
    }

    #[test]
    fn parse_transact_returns_missing_transactions_for_empty_batches() {
        let action_data = RelayAdapt7702ActionData {
            requireSuccess: true,
            minGasLimit: U256::ZERO,
            calls: Vec::new(),
        };
        let calldata_cases = vec![
            transactCall {
                _transactions: Vec::new(),
            }
            .abi_encode(),
            relayCall {
                _transactions: Vec::new(),
                _actionData: ActionData {
                    random: FixedBytes::from([0x01; 31]),
                    requireSuccess: true,
                    minGasLimit: U256::ZERO,
                    calls: Vec::new(),
                },
            }
            .abi_encode(),
            RelayAdapt7702Current::executeCall {
                _transactions: Vec::new(),
                _actionData: action_data.clone(),
                _executeNonce: uint!(7_U256),
                _signature: Bytes::from(vec![0xaa, 0xbb]),
            }
            .abi_encode(),
            RelayAdapt7702Legacy::executeCall {
                _transactions: Vec::new(),
                _actionData: action_data,
                _signature: Bytes::from(vec![0xcc, 0xdd]),
            }
            .abi_encode(),
        ];

        for calldata in calldata_cases {
            assert!(matches!(
                parse_transact_calldata(&calldata, &[0u8; 32], U256::ZERO, None),
                Err(TransactError::MissingTransactions)
            ));
        }
    }

    #[test]
    fn raw_params_deserializes_tx7702_fields() {
        let params: BroadcasterRawParamsTransact = serde_json::from_value(serde_json::json!({
            "chainType": 0,
            "chainID": 1,
            "transactType": "TX7702",
            "maxFeePerGas": "134943801",
            "maxPriorityFeePerGas": "10329316",
            "feesID": null,
            "to": "0x56daCb58fD9C6f654047908B573FcCd51652a33C",
            "data": "0x",
            "broadcasterViewingKey": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "txidVersion": null,
            "preTransactionPOIsPerTxidLeafPerList": {},
            "authorization": {
                "address": "0x2df3D82C06339387A4532C685daaF39A218Cf56E",
                "nonce": "0",
                "chainId": "1",
                "signature": {
                    "v": 27,
                    "r": "0x1111111111111111111111111111111111111111111111111111111111111111",
                    "s": "0x2222222222222222222222222222222222222222222222222222222222222222"
                }
            }
        }))
        .expect("deserialize tx7702 params");

        assert_eq!(
            params.transact_type,
            Some(BroadcasterTransactRequestType::Tx7702)
        );
        assert_eq!(params.max_fee_per_gas, Some(uint!(134943801_U256)));
        assert_eq!(params.max_priority_fee_per_gas, Some(uint!(10329316_U256)));
        let authorization = params.authorization.expect("authorization");
        assert_eq!(authorization.nonce, U256::ZERO);
        assert_eq!(authorization.chain_id, U256::from(1));
        assert_eq!(authorization.signature.v, 27);
    }

    #[test]
    fn parse_transact_uses_receiver_master_public_key_for_visible_sender_note() {
        let viewing_key_data = sample_viewing_key_data();
        let sender_master_public_key = uint!(0x1234_U256);
        let encoded_mpk = viewing_key_data.master_public_key ^ sender_master_public_key;
        let (calldata, _, _, fee_commitment, _) =
            sample_transaction_and_params_with_encoded_mpk(None, encoded_mpk);

        let parsed = parse_transact_calldata(
            &calldata,
            &viewing_key_data.viewing_private_key,
            viewing_key_data.master_public_key,
            None,
        )
        .expect("parse calldata");

        assert_eq!(parsed.fee_commitment, fee_commitment);
        let expected_npk: FixedBytes<32> =
            Note::npk_for(viewing_key_data.master_public_key, [0x55; 16]).into();
        assert_eq!(parsed.fee_note_npk, expected_npk);
    }

    #[test]
    fn parse_transact_rejects_unsupported_txid_version() {
        let viewing_key_data = sample_viewing_key_data();
        let (calldata, _, _, _, _) = sample_transaction_and_params(None);

        let error = parse_transact_calldata(
            &calldata,
            &viewing_key_data.viewing_private_key,
            viewing_key_data.master_public_key,
            Some("V3_PoseidonMerkle"),
        )
        .expect_err("unsupported txid version should fail");

        assert!(matches!(
            error,
            TransactError::UnsupportedTxidVersion { txid_version }
            if txid_version == "V3_PoseidonMerkle"
        ));
    }

    #[test]
    fn attach_fee_note_assurance_context_rejects_unsupported_txid_version() {
        let viewing_key_data = sample_viewing_key_data();
        let (calldata, _, mut params, _, _) = sample_transaction_and_params(None);
        params.txid_version = Some("V3_PoseidonMerkle".to_string());
        let mut parsed = parse_transact_calldata(
            &calldata,
            &viewing_key_data.viewing_private_key,
            viewing_key_data.master_public_key,
            None,
        )
        .expect("parse calldata");

        let error = parsed
            .attach_fee_note_assurance_context(&params, &[FixedBytes::from([0x88; 32])])
            .expect_err("unsupported txid version should fail");

        assert!(matches!(
            error,
            TransactError::UnsupportedTxidVersion { txid_version }
            if txid_version == "V3_PoseidonMerkle"
        ));
    }

    #[test]
    fn default_txid_version_is_v2_poseidon_merkle() {
        let viewing_key_data = sample_viewing_key_data();
        let (calldata, transaction, _, _, _) = sample_transaction_and_params(None);
        let parsed = parse_transact_calldata(
            &calldata,
            &viewing_key_data.viewing_private_key,
            viewing_key_data.master_public_key,
            None,
        )
        .expect("parse calldata");

        assert_eq!(
            parsed.railgun_txid,
            compute_railgun_txid(&transaction, Some(DEFAULT_TXID_VERSION)).expect("txid")
        );
    }

    #[test]
    fn encrypted_tx7702_fixture_provenance_matches_exact_bytes() {
        let encrypted_fixture_digest =
            alloy::hex::encode(Sha256::digest(TX7702_ENCRYPTED_FIXTURE_BYTES));
        let provenance = include_str!("../resources/fixtures/eip-7702/PROVENANCE.md");
        assert!(
            provenance.contains(&encrypted_fixture_digest),
            "fixture provenance is missing encrypted-envelope SHA-256 {encrypted_fixture_digest}"
        );
    }

    #[test]
    fn static_tx7702_wire_and_encryption_fixtures_match_rust_boundaries() {
        let wire: Value = serde_json::from_str(TX7702_WIRE_FIXTURE).expect("wire fixture JSON");
        let params: BroadcasterRawParamsTransact7702 =
            serde_json::from_value(wire.clone()).expect("valid TX7702 wire fixture");
        let serialized = serde_json::to_value(&params).expect("serialize TX7702 wire fixture");
        assert_eq!(
            serialized, wire,
            "Rust wire serialization must preserve the reviewed shape"
        );

        assert_eq!(
            params.transact_type,
            BroadcasterRawParamsTransact7702Type::Tx7702
        );
        assert_eq!(params.chain_id, 31_337);
        assert_eq!(params.gas_limit, 987_654);
        assert_eq!(params.max_fee_per_gas, U256::from(42_000_000_000_u64));
        assert_eq!(
            params.max_priority_fee_per_gas,
            U256::from(1_700_000_000_u64)
        );
        assert_eq!(serialized["to"], wire["to"]);
        assert_eq!(
            serialized["authorization"]["address"],
            wire["authorization"]["address"]
        );
        assert_eq!(
            serialized["authorization"]["signature"]["_type"],
            "signature"
        );
        assert_eq!(
            serialized["authorization"]["signature"]["networkV"],
            Value::Null
        );
        assert!(wire.get("minGasPrice").is_none());
        assert!(wire["authorization"].get("r").is_none());
        assert!(wire["authorization"].get("s").is_none());
        assert!(wire["authorization"].get("v").is_none());

        let signer = PrivateKeySigner::from_slice(&[0x11; 32]).expect("valid wire signer");
        let call = RelayAdapt7702Current::executeCall::abi_decode(&params.data)
            .expect("decode current wire calldata");
        let execution_signature =
            Signature::try_from(call._signature.as_ref()).expect("wire execution signature");
        let prepared = PreparedRelayAdapt7702Execution::prepare(
            params.chain_id,
            signer.address(),
            params.authorization.address,
            Eip7702AuthorizationNonce::new(params.authorization.nonce),
            RelayAdapt7702ExecutionVersion::CurrentNonceAware {
                nonce: RelayAdapt7702ExecutionNonce::new(call._executeNonce),
            },
            call._transactions,
            call._actionData,
            U256::ZERO,
        );
        let authorization_signature = Signature::new(
            U256::from_be_bytes(params.authorization.signature.r.0),
            U256::from_be_bytes(params.authorization.signature.s.0),
            params.authorization.signature.v == 28,
        );
        let finalized = prepared
            .finalize(authorization_signature, execution_signature)
            .expect("finalize valid wire operation");
        params
            .validate_finalized_operation(&prepared, &finalized)
            .expect("wire operation matches canonical Rust operation");

        let cases: Value =
            serde_json::from_str(TX7702_WIRE_CASES_FIXTURE).expect("wire cases fixture JSON");
        for case in cases["cases"].as_array().expect("wire cases array") {
            let name = case["name"].as_str().expect("wire case name");
            let mutated = apply_wire_case(&wire, case);
            if case["kind"].as_str() == Some("parse") {
                assert!(
                    serde_json::from_value::<BroadcasterRawParamsTransact7702>(mutated).is_err(),
                    "malformed wire case should fail: {name}"
                );
            } else {
                let mutated_params: BroadcasterRawParamsTransact7702 =
                    serde_json::from_value(mutated).expect("semantic case remains well-shaped");
                assert!(
                    mutated_params
                        .validate_finalized_operation(&prepared, &finalized)
                        .is_err(),
                    "semantic wire case should fail: {name}"
                );
            }
        }

        let encrypted: Value =
            serde_json::from_str(TX7702_ENCRYPTED_FIXTURE).expect("encrypted fixture JSON");
        let key_bytes = alloy::hex::decode(
            encrypted["sharedKey"]
                .as_str()
                .expect("encrypted fixture shared key"),
        )
        .expect("encrypted fixture key hex");
        let key: [u8; 32] = key_bytes.try_into().expect("32-byte fixture key");
        let encrypted_data = [
            wire_fixture_bytes(&encrypted["encryptedData"][0]),
            wire_fixture_bytes(&encrypted["encryptedData"][1]),
        ];
        let plaintext =
            decrypt_authenticated_plaintext(&key, &encrypted_data[0], encrypted_data[1].to_vec())
                .expect("decrypt static package envelope")
                .expect("static package envelope authenticates");
        assert_eq!(
            plaintext,
            encrypted["expectedPlaintextUtf8"]
                .as_str()
                .expect("expected plaintext UTF-8")
                .as_bytes()
        );
        let decrypted_json: Value = serde_json::from_slice(&plaintext).expect("decrypted JSON");
        assert_eq!(decrypted_json, encrypted["expectedPlaintext"]);
    }
}
