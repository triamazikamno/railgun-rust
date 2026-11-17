use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use alloy::eips::eip7702::{Authorization, SignedAuthorization};
use alloy::hex;
use alloy::primitives::{Address, Bytes, FixedBytes, Signature, U256};
use alloy::serde::{OtherFields, WithOtherFields};
use alloy::sol_types::SolCall;
use ruint::uint;

use crate::contracts::railgun::{
    ActionData, RelayAdapt7702, Transaction, executeCall, relayCall, transactCall,
};
use crate::crypto::aes_gcm::{
    AesGcmError, decrypt_in_place_16b_iv, encrypt_in_place_16b_iv, split_iv_tag,
};
use crate::crypto::poseidon::poseidon;
use crate::crypto::shared_key::{ed25519_private_scalar_bytes, shared_symmetric_key};
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
    #[error("authorization nonce exceeds the Ethereum account nonce range")]
    AuthorizationNonceOutOfRange,
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

#[derive(Debug, Deserialize, Serialize)]
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
    // SDK receivers compare this to unprefixed ByteUtils.hexlify output.
    #[serde(serialize_with = "serialize_broadcaster_viewing_key")]
    pub broadcaster_viewing_key: FixedBytes<32>,

    // pub use_relay_adapt: bool,

    // pub min_version: Option<String>,
    // pub max_version: Option<String>,
    pub txid_version: Option<String>,

    #[serde(default)]
    #[serde(rename = "preTransactionPOIsPerTxidLeafPerList")]
    #[serde(serialize_with = "serialize_broadcaster_pois")]
    pub pre_transaction_pois_per_txid_leaf_per_list:
        BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PreTxPoi>>,
    #[serde(flatten)]
    pub other: OtherFields,
    // pub dev_log: Option<serde_json::Value>,
}

fn serialize_broadcaster_viewing_key<S: serde::Serializer>(
    key: &FixedBytes<32>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    crate::serde_helpers::hex_string::serialize(key.as_slice(), serializer)
}

// Alloy's FixedBytes serializer adds 0x, but SDK POI validation uses exact
// unprefixed list/leaf lookups, dummy-root equality, and POI-root lookups. Adapt
// this request only: canonical PreTxPoi serialization is also used by stored records.
// Derive the proof object from that serializer to preserve every other field.
fn serialize_broadcaster_pois<S: serde::Serializer>(
    pois: &BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PreTxPoi>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeMap;

    let mut lists = serializer.serialize_map(Some(pois.len()))?;
    for (list_key, per_leaf) in pois {
        let leaves = per_leaf
            .iter()
            .map(|(leaf, poi)| {
                let mut value = serde_json::to_value(poi).map_err(serde::ser::Error::custom)?;
                value["txidMerkleroot"] = hex::encode(poi.txid_merkleroot).into();
                value["poiMerkleroots"] = poi
                    .poi_merkleroots
                    .iter()
                    .map(hex::encode)
                    .collect::<Vec<_>>()
                    .into();
                Ok((hex::encode(leaf), value))
            })
            .collect::<Result<BTreeMap<_, _>, S::Error>>()?;
        lists.serialize_entry(&hex::encode(list_key), &leaves)?;
    }
    lists.end()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum BroadcasterTransactRequestType {
    #[serde(rename = "COMMON")]
    Common,
    #[serde(rename = "TX7702")]
    Tx7702,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BroadcasterAuthorization {
    pub address: Address,
    pub nonce: U256,
    pub chain_id: U256,
    #[serde(serialize_with = "serialize_broadcaster_authorization_signature")]
    pub signature: BroadcasterAuthorizationSignature,
    #[serde(flatten)]
    pub other: OtherFields,
}

/// Alloy accepts SDK `yParity` and normalizes historical `v` encodings.
pub type BroadcasterAuthorizationSignature = WithOtherFields<Signature>;

// Alloy 2's Signature serializer emits RPC hex quantities for v/yParity, but
// released broadcasters and ethers' Signature.toJSON use a numeric v. Keep
// Alloy's input parsing and adapt only this nested broadcaster output format.
fn serialize_broadcaster_authorization_signature<S: serde::Serializer>(
    signature: &BroadcasterAuthorizationSignature,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeMap;

    let mut map = serializer.serialize_map(Some(3 + signature.other.len()))?;
    map.serialize_entry("r", &signature.r())?;
    map.serialize_entry("s", &signature.s())?;
    map.serialize_entry("v", &(27 + u64::from(signature.v())))?;
    for (key, value) in &signature.other {
        map.serialize_entry(key, value)?;
    }
    map.end()
}

impl BroadcasterAuthorization {
    /// Adapt the existing nested broadcaster wire format to Alloy's flat tuple.
    ///
    /// The wire nonce remains U256 for historical request compatibility. Alloy
    /// requires a u64 account nonce when constructing the transaction envelope.
    pub fn signed_authorization(&self) -> Result<SignedAuthorization, TransactError> {
        let nonce = self
            .nonce
            .try_into()
            .map_err(|_| TransactError::AuthorizationNonceOutOfRange)?;
        Ok(Authorization {
            chain_id: self.chain_id,
            address: self.address,
            nonce,
        }
        .into_signed(self.signature.inner))
    }
}

#[derive(Clone)]
pub struct EncryptedTransactRequest {
    pub pubkey: [u8; 32],
    pub encrypted_data: [Bytes; 2],
    pub shared_key: [u8; 32],
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

    pub fn encrypt_with_seed(
        broadcaster_viewing_pubkey: [u8; 32],
        params: &BroadcasterRawParamsTransact,
        client_seed: [u8; 32],
    ) -> Result<Self, TransactError> {
        let pubkey = SigningKey::from_bytes(&client_seed)
            .verifying_key()
            .to_bytes();
        let shared_key = shared_key_for_broadcaster(&client_seed, &broadcaster_viewing_pubkey)
            .map_err(|_| TransactError::SharedKey)?;
        let mut plaintext = serde_json::to_vec(params)?;
        let iv_tag = encrypt_in_place_16b_iv(&shared_key, &mut plaintext)?;
        Ok(Self {
            pubkey,
            encrypted_data: [Bytes::copy_from_slice(&iv_tag), Bytes::from(plaintext)],
            shared_key,
        })
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

#[derive(Debug, Serialize)]
struct TransactEnvelope<'a> {
    method: &'static str,
    params: TransactEnvelopeParams<'a>,
}

#[derive(Debug, Serialize)]
struct TransactEnvelopeParams<'a> {
    // Noble's Ed25519 decoder rejects 0x on this outer key.
    #[serde(serialize_with = "serialize_broadcaster_viewing_key")]
    pubkey: FixedBytes<32>,
    #[serde(rename = "encryptedData")]
    encrypted_data: &'a [Bytes; 2],
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreTxPoi {
    pub snark_proof: SnarkJsProof,
    pub txid_merkleroot: FixedBytes<32>,
    pub poi_merkleroots: Vec<FixedBytes<32>>,
    pub blinded_commitments_out: Vec<FixedBytes<32>>,
    pub railgun_txid_if_has_unshield: Bytes,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SnarkJsProof {
    pub pi_a: [U256; 2],
    pub pi_b: [[U256; 2]; 2],
    pub pi_c: [U256; 2],
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

pub fn try_decrypt_transact_request(
    viewing_priv_seed: &[u8; 32],
    pubkey: [u8; 32],
    encrypted_data: &[Bytes; 2],
) -> Result<Option<DecryptedTransact>, TransactError> {
    let shared = shared_key_32(viewing_priv_seed, &pubkey).map_err(|_| TransactError::SharedKey)?;

    if let Some(params) = decrypt::<BroadcasterRawParamsTransact>(
        &shared,
        &encrypted_data[0],
        encrypted_data[1].to_vec(),
    )? {
        tracing::debug!(
            pubkey = hex::encode(pubkey),
            ?encrypted_data,
            "decrypting transact request"
        );
        Ok(Some(DecryptedTransact {
            shared_key: shared,
            params,
        }))
    } else {
        Ok(None)
    }
}

fn decrypt<T: serde::de::DeserializeOwned>(
    shared_key: &[u8; 32],
    ivtag: &[u8],
    ct: Vec<u8>,
) -> Result<Option<T>, TransactError> {
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

    let params: T = serde_json::from_slice(&ct)?;

    Ok(Some(params))
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug)]
pub struct ParsedTransactTransaction {
    pub railgun_txid: U256,
    pub utxo_tree_in: u64,
    pub tx_nullifiers_len: usize,
    pub tx_commitments_out_len: usize,
    pub has_unshield: bool,
}

#[derive(Debug)]
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
    let (transactions, action_data) = if let Ok(call) = transactCall::abi_decode(calldata) {
        (call._transactions, None)
    } else if let Ok(call) = relayCall::abi_decode(calldata) {
        (call._transactions, Some(call._actionData))
    } else if let Ok((transactions, action_data)) =
        RelayAdapt7702::executeCall::abi_decode(calldata)
            .map(|call| (call._transactions, call._actionData))
            .or_else(|_| {
                executeCall::abi_decode(calldata).map(|call| (call._transactions, call._actionData))
            })
    {
        let action_data = ActionData {
            random: FixedBytes::ZERO,
            requireSuccess: action_data.requireSuccess,
            minGasLimit: action_data.minGasLimit,
            calls: action_data.calls,
        };
        (transactions, Some(action_data))
    } else {
        return Err(TransactError::UnknownFunctionCall {
            selector: hex::encode(&calldata[..4]),
        });
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
mod tests;
