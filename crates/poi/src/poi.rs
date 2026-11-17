use crate::error::{PoiError, PoiRpcError, PoiRpcTransportPhase};
use crate::sensitive_url::SensitiveUrl;
use alloy::hex;
use alloy::primitives::{FixedBytes, U256};
use broadcaster_core::crypto::snark_proof::Prover;
use broadcaster_core::transact::{
    BroadcasterRawParamsTransact, FeeNoteAssuranceContext, ParsedTransactCalldata,
    ParsedTransactTransaction, PreTxPoi, SnarkJsProof, dummy_txid_root, railgun_txid_leaf_hash,
    txid_version_or_default,
};
pub use broadcaster_core::utxo::PoiStatus;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::debug;

pub const DEFAULT_WALLET_POI_RPC_URL: &str = "https://ppoi.fdi.network";
pub const DEFAULT_ACTIVE_POI_LIST_KEY_HEX: &str =
    "efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88";

const DEFAULT_ACTIVE_POI_LIST_KEY_BYTES: [u8; 32] = [
    0xef, 0xc6, 0xdd, 0xb5, 0x9c, 0x09, 0x8a, 0x13, 0xfb, 0x2b, 0x61, 0x8f, 0xda, 0xe9, 0x4c, 0x1c,
    0x3a, 0x80, 0x7a, 0xbc, 0x8f, 0xb1, 0x83, 0x7c, 0x93, 0x62, 0x0c, 0x91, 0x43, 0xee, 0x9e, 0x88,
];

#[must_use]
pub fn default_active_poi_list_key() -> FixedBytes<32> {
    FixedBytes::from(DEFAULT_ACTIVE_POI_LIST_KEY_BYTES)
}

#[must_use]
pub fn default_active_poi_list_keys() -> Vec<FixedBytes<32>> {
    vec![default_active_poi_list_key()]
}

pub struct Poi {
    rpc_client: PoiRpcClient,
    snark_prover: Arc<Prover>,
    required_poi_list: Vec<FixedBytes<32>>,
}

impl Poi {
    pub const fn new(
        rpc_client: PoiRpcClient,
        snark_prover: Arc<Prover>,
        required_poi_list: Vec<FixedBytes<32>>,
    ) -> Self {
        Self {
            rpc_client,
            snark_prover,
            required_poi_list,
        }
    }

    pub async fn validate_all(
        &self,
        parsed_calldata: &ParsedTransactCalldata,
        params: &BroadcasterRawParamsTransact,
    ) -> Result<(), PoiError> {
        for list_key in &self.required_poi_list {
            for transaction in &parsed_calldata.transactions {
                self.validate_transaction(transaction, params, list_key)
                    .await
                    .map_err(|source| PoiError::ValidateList {
                        list_key: *list_key,
                        source: Box::new(source),
                    })?;
            }
        }
        Ok(())
    }

    async fn validate_transaction(
        &self,
        transaction: &ParsedTransactTransaction,
        params: &BroadcasterRawParamsTransact,
        required_list_key: &FixedBytes<32>,
    ) -> Result<(), PoiError> {
        let leaf = railgun_txid_leaf_hash(transaction.railgun_txid, transaction.utxo_tree_in);
        let leaf_hex: FixedBytes<32> = leaf.into();

        let per_list = params
            .pre_transaction_pois_per_txid_leaf_per_list
            .get(required_list_key)
            .ok_or(PoiError::MissingListKey)?;

        let poi = per_list
            .get(&leaf_hex)
            .ok_or(PoiError::MissingProof { leaf_hex })?;

        let expected_root = FixedBytes::from(dummy_txid_root(leaf).to_be_bytes::<32>());
        if expected_root != poi.txid_merkleroot {
            return Err(PoiError::TxidMerklerootMismatch {
                expected: expected_root,
                actual: poi.txid_merkleroot,
            });
        }
        let txid_version = txid_version_or_default(params.txid_version.as_deref());
        let ok = self
            .rpc_client
            .validate_poi_merkleroots(
                txid_version,
                params.chain_type as u8,
                params.chain_id,
                required_list_key,
                &poi.poi_merkleroots
                    .iter()
                    .map(hex::encode)
                    .collect::<Vec<_>>(),
            )
            .await?;

        if !ok {
            return Err(PoiError::MerkleRootsRejected);
        }

        let snark_ok = self.snark_prover.verify(
            transaction.tx_nullifiers_len,
            transaction.tx_commitments_out_len,
            poi,
        )?;

        if !snark_ok {
            return Err(PoiError::InvalidSnarkProof);
        }

        Ok(())
    }

    pub async fn submit_fee_note_single_commitment(
        &self,
        chain_type: u8,
        chain_id: u64,
        context: &FeeNoteAssuranceContext,
        utxo_tree_out: u64,
        utxo_position_out: u64,
    ) -> Result<(), PoiError> {
        debug!(
            method = POI_SUBMIT_SINGLE_COMMITMENT_PROOFS_METHOD,
            chain_type,
            chain_id,
            txid_version = %context.txid_version,
            fee_commitment = %hex::encode_prefixed(context.fee_commitment),
            fee_note_npk = %hex::encode_prefixed(context.fee_note_npk),
            railgun_txid = %encode_u256(context.railgun_txid),
            utxo_tree_in = context.utxo_tree_in,
            utxo_tree_out,
            utxo_position_out,
            required_poi_list_keys = ?context
                .required_poi_list_keys
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
            poi_list_keys = ?context
                .pre_transaction_pois_per_txid_leaf_per_list
                .keys()
                .map(hex::encode)
                .collect::<Vec<_>>(),
            "submit fee-note single-commitment poi"
        );
        let single_commitment_context = SingleCommitmentProofContext::from(context);
        self.rpc_client
            .submit_single_commitment_proofs(
                &context.txid_version,
                chain_type,
                chain_id,
                &single_commitment_context,
                utxo_tree_out,
                utxo_position_out,
            )
            .await?;
        Ok(())
    }

    pub async fn submit_single_commitment(
        &self,
        chain_type: u8,
        chain_id: u64,
        context: &SingleCommitmentProofContext,
        utxo_tree_out: u64,
        utxo_position_out: u64,
    ) -> Result<(), PoiError> {
        debug!(
            method = POI_SUBMIT_SINGLE_COMMITMENT_PROOFS_METHOD,
            chain_type,
            chain_id,
            txid_version = %context.txid_version,
            commitment = %hex::encode_prefixed(context.commitment),
            npk = %hex::encode_prefixed(context.npk),
            railgun_txid = %encode_u256(context.railgun_txid),
            utxo_tree_in = context.utxo_tree_in,
            utxo_tree_out,
            utxo_position_out,
            poi_list_keys = ?context
                .pre_transaction_pois_per_txid_leaf_per_list
                .keys()
                .map(hex::encode)
                .collect::<Vec<_>>(),
            "submit single-commitment poi"
        );
        self.rpc_client
            .submit_single_commitment_proofs(
                &context.txid_version,
                chain_type,
                chain_id,
                context,
                utxo_tree_out,
                utxo_position_out,
            )
            .await?;
        Ok(())
    }

    pub async fn fee_note_statuses_for_blinded_commitment(
        &self,
        chain_type: u8,
        chain_id: u64,
        txid_version: &str,
        required_poi_list_keys: &[FixedBytes<32>],
        blinded_commitment: &FixedBytes<32>,
    ) -> Result<BTreeMap<FixedBytes<32>, PoiStatus>, PoiError> {
        debug!(
            method = POI_POIS_PER_LIST_METHOD,
            chain_type,
            chain_id,
            txid_version,
            fee_blinded_commitment = %hex::encode_prefixed(blinded_commitment),
            required_poi_list_keys = ?required_poi_list_keys.iter().map(hex::encode).collect::<Vec<_>>(),
            "query fee-note poi statuses for candidate commitment"
        );
        let statuses = self
            .rpc_client
            .pois_per_list(
                txid_version,
                chain_type,
                chain_id,
                required_poi_list_keys,
                &[BlindedCommitmentData::transact(*blinded_commitment)],
            )
            .await?;

        Ok(statuses
            .get(blinded_commitment)
            .cloned()
            .unwrap_or_else(|| {
                required_poi_list_keys
                    .iter()
                    .copied()
                    .map(|list_key| (list_key, PoiStatus::Missing))
                    .collect()
            }))
    }
}

const POI_VALIDATE_MERKLEROOTS_METHOD: &str = "ppoi_validate_poi_merkleroots";
const POI_VALIDATE_TXID_MERKLEROOT_METHOD: &str = "ppoi_validate_txid_merkleroot";
const POI_VALIDATED_TXID_METHOD: &str = "ppoi_validated_txid";
const POI_SUBMIT_TRANSACT_PROOF_METHOD: &str = "ppoi_submit_transact_proof";
const POI_SUBMIT_SINGLE_COMMITMENT_PROOFS_METHOD: &str = "ppoi_submit_single_commitment_proofs";
const POI_POIS_PER_LIST_METHOD: &str = "ppoi_pois_per_list";
const POI_MERKLE_PROOFS_METHOD: &str = "ppoi_merkle_proofs";
const POI_EVENTS_METHOD: &str = "ppoi_poi_events";
const POI_MERKLETREE_LEAVES_METHOD: &str = "ppoi_poi_merkletree_leaves";
const POI_BLOCKED_SHIELDS_METHOD: &str = "ppoi_blocked_shields";

#[derive(Debug, Serialize)]
struct JsonRpcReq<T> {
    jsonrpc: &'static str,
    id: u64,
    method: &'static str,
    params: T,
}

#[derive(Debug, Deserialize)]
struct JsonRpcResp<T> {
    result: Option<T>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
    data: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ChainParams {
    chain_type: String,
    #[serde(rename = "chainID")]
    chain_id: String,
    txid_version: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ValidatePOIMerklerootsParams {
    #[serde(flatten)]
    chain: ChainParams,
    list_key: String,
    poi_merkleroots: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SubmitSingleCommitmentProofsParams {
    #[serde(flatten)]
    chain: ChainParams,
    single_commitment_proofs_data: SingleCommitmentProofsData,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SubmitTransactProofParams {
    #[serde(flatten)]
    chain: ChainParams,
    list_key: String,
    transact_proof_data: SubmitTransactProofData,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SubmitTransactProofData {
    #[serde(flatten)]
    proof: SubmitPoiProofData,
    txid_merkleroot_index: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GetLatestValidatedRailgunTxidParams {
    #[serde(flatten)]
    chain: ChainParams,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ValidatedRailgunTxidStatus {
    pub validated_txid_index: Option<u64>,
    #[serde(rename = "validatedTxidMerkleroot", alias = "validatedMerkleroot")]
    pub validated_merkleroot: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ValidateTxidMerklerootParams {
    #[serde(flatten)]
    chain: ChainParams,
    tree: u64,
    index: u64,
    merkleroot: String,
}

#[derive(Debug, Clone)]
pub struct SingleCommitmentProofContext {
    pub txid_version: String,
    pub railgun_txid: U256,
    pub utxo_tree_in: u64,
    pub commitment: FixedBytes<32>,
    pub npk: FixedBytes<32>,
    pub pre_transaction_pois_per_txid_leaf_per_list:
        BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PreTxPoi>>,
}

impl From<&FeeNoteAssuranceContext> for SingleCommitmentProofContext {
    fn from(context: &FeeNoteAssuranceContext) -> Self {
        Self {
            txid_version: context.txid_version.clone(),
            railgun_txid: context.railgun_txid,
            utxo_tree_in: context.utxo_tree_in,
            commitment: context.fee_commitment,
            npk: context.fee_note_npk,
            pre_transaction_pois_per_txid_leaf_per_list: context
                .pre_transaction_pois_per_txid_leaf_per_list
                .clone(),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SingleCommitmentProofsData {
    commitment: String,
    npk: String,
    utxo_tree_in: u64,
    utxo_tree_out: u64,
    utxo_position_out: u64,
    railgun_txid: String,
    pois: BTreeMap<String, BTreeMap<String, SubmitPoiProofData>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SubmitPoiProofData {
    snark_proof: SubmitSnarkJsProof,
    txid_merkleroot: String,
    poi_merkleroots: Vec<String>,
    blinded_commitments_out: Vec<String>,
    railgun_txid_if_has_unshield: String,
}

#[derive(Debug, Serialize)]
struct SubmitSnarkJsProof {
    pi_a: [String; 2],
    pi_b: [[String; 2]; 2],
    pi_c: [String; 2],
}

impl From<&PreTxPoi> for SubmitPoiProofData {
    fn from(poi: &PreTxPoi) -> Self {
        Self {
            snark_proof: SubmitSnarkJsProof::from(&poi.snark_proof),
            txid_merkleroot: hex::encode(poi.txid_merkleroot),
            poi_merkleroots: poi.poi_merkleroots.iter().map(hex::encode).collect(),
            blinded_commitments_out: poi
                .blinded_commitments_out
                .iter()
                .map(hex::encode_prefixed)
                .collect(),
            railgun_txid_if_has_unshield: if poi.railgun_txid_if_has_unshield.is_empty() {
                "0x00".to_string()
            } else {
                hex::encode_prefixed(&poi.railgun_txid_if_has_unshield)
            },
        }
    }
}

impl From<&SnarkJsProof> for SubmitSnarkJsProof {
    fn from(proof: &SnarkJsProof) -> Self {
        Self {
            pi_a: proof.pi_a.map(|value| value.to_string()),
            pi_b: proof.pi_b.map(|row| row.map(|value| value.to_string())),
            pi_c: proof.pi_c.map(|value| value.to_string()),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GetPoisPerListParams {
    #[serde(flatten)]
    chain: ChainParams,
    list_keys: Vec<String>,
    blinded_commitment_datas: Vec<BlindedCommitmentDataParam>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BlindedCommitmentDataParam {
    blinded_commitment: String,
    #[serde(rename = "type")]
    commitment_type: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GetMerkleProofsParams {
    #[serde(flatten)]
    chain: ChainParams,
    list_key: String,
    blinded_commitments: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GetPoiListEventRangeParams {
    #[serde(flatten)]
    chain: ChainParams,
    list_key: String,
    start_index: u64,
    end_index: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GetPoiMerkletreeLeavesParams {
    #[serde(flatten)]
    chain: ChainParams,
    list_key: String,
    start_index: u64,
    end_index: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GetFilteredBlockedShieldsParams<'a> {
    #[serde(flatten)]
    chain: ChainParams,
    list_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    bloom_filter_serialized: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoiMerkleProof {
    #[serde(with = "u256_hex_full")]
    pub leaf: U256,
    #[serde(with = "u256_hex_full_vec")]
    pub elements: Vec<U256>,
    #[serde(with = "u256_hex_full")]
    pub indices: U256,
    #[serde(with = "u256_hex_full")]
    pub root: U256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
struct PoiMerkletreeLeavesResponse {
    #[serde(with = "u256_hex_32_vec")]
    leaves: Vec<U256>,
}

mod fixed_bytes32_hex {
    use super::{FixedBytes, hex, u256_hex_full};
    use serde::{Deserialize, Deserializer, Serializer, de};

    pub(super) fn serialize<S>(value: &FixedBytes<32>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode_prefixed(value.as_slice()))
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<FixedBytes<32>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        // Upstream event commitments are numeric hex and may omit leading zeros;
        // Alloy FixedBytes parsing requires the full byte width.
        u256_hex_full::parse_u256_hex(&value)
            .map(|value| FixedBytes::from(value.to_be_bytes::<32>()))
            .map_err(de::Error::custom)
    }

    pub(super) fn decode(value: &str) -> Result<FixedBytes<32>, String> {
        let value_without_prefix = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
            .unwrap_or(value);
        let bytes = hex::decode(value_without_prefix).map_err(|err| err.to_string())?;
        if bytes.len() != 32 {
            return Err(format!("hex string has {} bytes, expected 32", bytes.len()));
        }
        Ok(FixedBytes::from_slice(&bytes))
    }
}

mod u256_hex_full {
    use super::U256;
    use serde::{Deserialize, Deserializer, Serializer, de};

    pub(super) fn serialize<S>(value: &U256, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{value:064x}"))
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<U256, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        parse_u256_hex(&value).map_err(de::Error::custom)
    }

    pub(super) fn parse_u256_hex(value: &str) -> Result<U256, String> {
        let value_without_prefix = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
            .unwrap_or(value);
        if value_without_prefix.len() > 64 {
            return Err(format!(
                "hex string has {} nibbles, expected at most 64",
                value_without_prefix.len()
            ));
        }
        if value_without_prefix.is_empty() {
            return Ok(U256::ZERO);
        }
        U256::from_str_radix(value_without_prefix, 16).map_err(|err| err.to_string())
    }
}

mod u256_hex_full_vec {
    use super::{U256, u256_hex_full};
    use serde::{Deserialize, Deserializer, Serializer, de, ser::SerializeSeq};

    pub(super) fn serialize<S>(values: &[U256], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(values.len()))?;
        for value in values {
            seq.serialize_element(&format!("0x{value:064x}"))?;
        }
        seq.end()
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<U256>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<String>::deserialize(deserializer)?
            .into_iter()
            .map(|value| u256_hex_full::parse_u256_hex(&value).map_err(de::Error::custom))
            .collect()
    }
}

mod u256_hex_32_vec {
    use super::{U256, fixed_bytes32_hex};
    use serde::{Deserialize, Deserializer, Serializer, de, ser::SerializeSeq};

    pub(super) fn serialize<S>(values: &[U256], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(values.len()))?;
        for value in values {
            seq.serialize_element(&format!("0x{value:064x}"))?;
        }
        seq.end()
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<U256>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<String>::deserialize(deserializer)?
            .into_iter()
            .map(|value| {
                fixed_bytes32_hex::decode(&value)
                    .map(|bytes| U256::from_be_bytes(bytes.0))
                    .map_err(de::Error::custom)
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PoiEventType {
    Shield,
    Transact,
    Unshield,
    LegacyTransact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedPoiEvent {
    pub index: u64,
    #[serde(with = "fixed_bytes32_hex")]
    pub blinded_commitment: FixedBytes<32>,
    pub signature: String,
    #[serde(rename = "type")]
    pub event_type: PoiEventType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PoiSyncedListEvent {
    #[serde(rename = "signedPOIEvent")]
    pub signed_poi_event: SignedPoiEvent,
    pub validated_merkleroot: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockedShield {
    pub commitment_hash: String,
    pub blinded_commitment: String,
    pub block_reason: Option<String>,
    pub signature: String,
}

pub type SignedBlockedShield = BlockedShield;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlindedCommitmentType {
    Shield,
    Transact,
    Unshield,
}

impl BlindedCommitmentType {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Shield => "Shield",
            Self::Transact => "Transact",
            Self::Unshield => "Unshield",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlindedCommitmentData {
    pub blinded_commitment: FixedBytes<32>,
    pub commitment_type: BlindedCommitmentType,
}

impl BlindedCommitmentData {
    #[must_use]
    pub const fn new(
        blinded_commitment: FixedBytes<32>,
        commitment_type: BlindedCommitmentType,
    ) -> Self {
        Self {
            blinded_commitment,
            commitment_type,
        }
    }

    #[must_use]
    pub const fn shield(blinded_commitment: FixedBytes<32>) -> Self {
        Self::new(blinded_commitment, BlindedCommitmentType::Shield)
    }

    #[must_use]
    pub const fn transact(blinded_commitment: FixedBytes<32>) -> Self {
        Self::new(blinded_commitment, BlindedCommitmentType::Transact)
    }

    #[must_use]
    pub const fn unshield(blinded_commitment: FixedBytes<32>) -> Self {
        Self::new(blinded_commitment, BlindedCommitmentType::Unshield)
    }
}

pub type PoisPerListMap = BTreeMap<String, BTreeMap<String, PoiStatus>>;
pub type PoisPerListStatusMap = BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PoiStatus>>;

pub struct PoiRpcClient {
    base_url: SensitiveUrl,
    http: reqwest::Client,
    next_id: std::sync::atomic::AtomicU64,
    request_timeout: Duration,
}

impl Clone for PoiRpcClient {
    fn clone(&self) -> Self {
        Self {
            base_url: self.base_url.clone(),
            http: self.http.clone(),
            next_id: std::sync::atomic::AtomicU64::new(1),
            request_timeout: self.request_timeout,
        }
    }
}

impl PoiRpcClient {
    #[must_use]
    pub fn new(base_url: impl Into<SensitiveUrl>) -> Self {
        Self {
            base_url: base_url.into(),
            http: reqwest::Client::new(),
            next_id: std::sync::atomic::AtomicU64::new(1),
            request_timeout: Duration::from_mins(2),
        }
    }

    /// Creates a client that routes all traffic through the given
    /// pre-configured [`reqwest::Client`] (e.g. one with a SOCKS proxy).
    #[must_use]
    pub fn with_http_client(base_url: impl Into<SensitiveUrl>, http: reqwest::Client) -> Self {
        Self {
            base_url: base_url.into(),
            http,
            next_id: std::sync::atomic::AtomicU64::new(1),
            request_timeout: Duration::from_mins(2),
        }
    }

    #[must_use]
    pub const fn with_request_timeout(mut self, request_timeout: Duration) -> Self {
        self.request_timeout = request_timeout;
        self
    }

    fn next_id(&self) -> u64 {
        self.next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    fn chain_params(txid_version: &str, chain_type: u8, chain_id: u64) -> ChainParams {
        ChainParams {
            chain_type: chain_type.to_string(),
            chain_id: chain_id.to_string(),
            txid_version: txid_version.to_string(),
        }
    }

    async fn send_request<P, R>(&self, method: &'static str, params: P) -> Result<R, PoiRpcError>
    where
        P: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        let body = self.send_raw_json_rpc(method, params).await?;
        decode_json_rpc_response(&body)
    }

    async fn send_request_allow_missing_result<P>(
        &self,
        method: &'static str,
        params: P,
    ) -> Result<(), PoiRpcError>
    where
        P: Serialize,
    {
        let body = self.send_raw_json_rpc(method, params).await?;
        decode_json_rpc_ack_response(method, &body)
    }

    async fn send_raw_json_rpc<P>(
        &self,
        method: &'static str,
        params: P,
    ) -> Result<String, PoiRpcError>
    where
        P: Serialize,
    {
        let started = Instant::now();
        let req = JsonRpcReq {
            jsonrpc: "2.0",
            id: self.next_id(),
            method,
            params,
        };

        let resp = self
            .http
            .post(self.base_url.expose_url().clone())
            .timeout(self.request_timeout)
            .json(&req)
            .send()
            .await
            .map_err(|source| PoiRpcError::Post {
                phase: PoiRpcTransportPhase::Send,
                source: source.without_url(),
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.map_err(|source| PoiRpcError::Post {
                phase: PoiRpcTransportPhase::ResponseBody,
                source: source.without_url(),
            })?;
            debug!(
                method,
                %status,
                response_bytes = body.len(),
                elapsed_ms = started.elapsed().as_millis(),
                "POI RPC request failed"
            );
            return Err(PoiRpcError::HttpStatus { status });
        }

        let body = resp.text().await.map_err(|source| PoiRpcError::Post {
            phase: PoiRpcTransportPhase::ResponseBody,
            source: source.without_url(),
        })?;
        debug!(
            method,
            response_bytes = body.len(),
            elapsed_ms = started.elapsed().as_millis(),
            "POI RPC request complete"
        );
        Ok(body)
    }

    fn submit_single_commitment_pois(
        context: &SingleCommitmentProofContext,
    ) -> BTreeMap<String, BTreeMap<String, SubmitPoiProofData>> {
        context
            .pre_transaction_pois_per_txid_leaf_per_list
            .iter()
            .map(|(list_key, per_leaf)| {
                (
                    hex::encode(list_key),
                    per_leaf
                        .iter()
                        .map(|(leaf, poi)| (hex::encode(leaf), poi.into()))
                        .collect(),
                )
            })
            .collect()
    }

    fn validate_poi_merkleroots_params(
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_key: &FixedBytes<32>,
        poi_merkleroots: &[String],
    ) -> ValidatePOIMerklerootsParams {
        ValidatePOIMerklerootsParams {
            chain: Self::chain_params(txid_version, chain_type, chain_id),
            list_key: hex::encode(list_key),
            poi_merkleroots: poi_merkleroots.to_vec(),
        }
    }

    fn validate_txid_merkleroot_params(
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        tree: u64,
        index: u64,
        merkleroot: &FixedBytes<32>,
    ) -> ValidateTxidMerklerootParams {
        ValidateTxidMerklerootParams {
            chain: Self::chain_params(txid_version, chain_type, chain_id),
            tree,
            index,
            merkleroot: hex::encode(merkleroot),
        }
    }

    fn latest_validated_txid_params(
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
    ) -> GetLatestValidatedRailgunTxidParams {
        GetLatestValidatedRailgunTxidParams {
            chain: Self::chain_params(txid_version, chain_type, chain_id),
        }
    }

    fn submit_single_commitment_proofs_params(
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        context: &SingleCommitmentProofContext,
        utxo_tree_out: u64,
        utxo_position_out: u64,
    ) -> SubmitSingleCommitmentProofsParams {
        SubmitSingleCommitmentProofsParams {
            chain: Self::chain_params(txid_version, chain_type, chain_id),
            single_commitment_proofs_data: SingleCommitmentProofsData {
                commitment: hex::encode_prefixed(context.commitment),
                npk: hex::encode_prefixed(context.npk),
                utxo_tree_in: context.utxo_tree_in,
                utxo_tree_out,
                utxo_position_out,
                railgun_txid: encode_u256_bare(context.railgun_txid),
                pois: Self::submit_single_commitment_pois(context),
            },
        }
    }

    fn submit_transact_proof_params(
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_key: &FixedBytes<32>,
        txid_merkleroot_index: u64,
        poi: &PreTxPoi,
    ) -> SubmitTransactProofParams {
        SubmitTransactProofParams {
            chain: Self::chain_params(txid_version, chain_type, chain_id),
            list_key: hex::encode(list_key),
            transact_proof_data: SubmitTransactProofData {
                proof: poi.into(),
                txid_merkleroot_index,
            },
        }
    }

    fn pois_per_list_params(
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_keys: &[FixedBytes<32>],
        blinded_commitment_datas: &[BlindedCommitmentData],
    ) -> GetPoisPerListParams {
        GetPoisPerListParams {
            chain: Self::chain_params(txid_version, chain_type, chain_id),
            list_keys: list_keys.iter().map(hex::encode).collect(),
            blinded_commitment_datas: blinded_commitment_datas
                .iter()
                .map(|data| BlindedCommitmentDataParam {
                    blinded_commitment: hex::encode_prefixed(data.blinded_commitment),
                    commitment_type: data.commitment_type.as_str(),
                })
                .collect(),
        }
    }

    fn poi_merkle_proofs_params(
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_key: &FixedBytes<32>,
        blinded_commitments: &[FixedBytes<32>],
    ) -> GetMerkleProofsParams {
        GetMerkleProofsParams {
            chain: Self::chain_params(txid_version, chain_type, chain_id),
            list_key: hex::encode(list_key),
            blinded_commitments: blinded_commitments
                .iter()
                .map(hex::encode_prefixed)
                .collect(),
        }
    }

    fn poi_events_params(
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_key: &FixedBytes<32>,
        start_index: u64,
        end_index: u64,
    ) -> GetPoiListEventRangeParams {
        GetPoiListEventRangeParams {
            chain: Self::chain_params(txid_version, chain_type, chain_id),
            list_key: hex::encode(list_key),
            start_index,
            end_index,
        }
    }

    fn poi_merkletree_leaves_params(
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_key: &FixedBytes<32>,
        start_index: u64,
        end_index: u64,
    ) -> GetPoiMerkletreeLeavesParams {
        GetPoiMerkletreeLeavesParams {
            chain: Self::chain_params(txid_version, chain_type, chain_id),
            list_key: hex::encode(list_key),
            start_index,
            end_index,
        }
    }

    fn blocked_shields_params(
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_key: &FixedBytes<32>,
        start_index: u64,
        end_index: u64,
    ) -> GetPoiListEventRangeParams {
        GetPoiListEventRangeParams {
            chain: Self::chain_params(txid_version, chain_type, chain_id),
            list_key: hex::encode(list_key),
            start_index,
            end_index,
        }
    }

    fn filtered_blocked_shields_params<'a>(
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_key: &FixedBytes<32>,
        bloom_filter_serialized: Option<&'a str>,
    ) -> GetFilteredBlockedShieldsParams<'a> {
        GetFilteredBlockedShieldsParams {
            chain: Self::chain_params(txid_version, chain_type, chain_id),
            list_key: hex::encode(list_key),
            bloom_filter_serialized,
        }
    }

    pub async fn validate_poi_merkleroots(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_key: &FixedBytes<32>,
        poi_merkleroots: &[String],
    ) -> Result<bool, PoiRpcError> {
        self.send_request(
            POI_VALIDATE_MERKLEROOTS_METHOD,
            Self::validate_poi_merkleroots_params(
                txid_version,
                chain_type,
                chain_id,
                list_key,
                poi_merkleroots,
            ),
        )
        .await
    }

    pub async fn validate_txid_merkleroot(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        tree: u64,
        index: u64,
        merkleroot: &FixedBytes<32>,
    ) -> Result<bool, PoiRpcError> {
        self.send_request(
            POI_VALIDATE_TXID_MERKLEROOT_METHOD,
            Self::validate_txid_merkleroot_params(
                txid_version,
                chain_type,
                chain_id,
                tree,
                index,
                merkleroot,
            ),
        )
        .await
    }

    pub async fn latest_validated_railgun_txid(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
    ) -> Result<ValidatedRailgunTxidStatus, PoiRpcError> {
        self.send_request(
            POI_VALIDATED_TXID_METHOD,
            Self::latest_validated_txid_params(txid_version, chain_type, chain_id),
        )
        .await
    }

    pub async fn submit_single_commitment_proofs(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        context: &SingleCommitmentProofContext,
        utxo_tree_out: u64,
        utxo_position_out: u64,
    ) -> Result<(), PoiRpcError> {
        self.send_request_allow_missing_result(
            POI_SUBMIT_SINGLE_COMMITMENT_PROOFS_METHOD,
            Self::submit_single_commitment_proofs_params(
                txid_version,
                chain_type,
                chain_id,
                context,
                utxo_tree_out,
                utxo_position_out,
            ),
        )
        .await
    }

    pub async fn submit_transact_proof(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_key: &FixedBytes<32>,
        txid_merkleroot_index: u64,
        poi: &PreTxPoi,
    ) -> Result<(), PoiRpcError> {
        self.send_request_allow_missing_result(
            POI_SUBMIT_TRANSACT_PROOF_METHOD,
            Self::submit_transact_proof_params(
                txid_version,
                chain_type,
                chain_id,
                list_key,
                txid_merkleroot_index,
                poi,
            ),
        )
        .await
    }

    pub async fn pois_per_list(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_keys: &[FixedBytes<32>],
        blinded_commitment_datas: &[BlindedCommitmentData],
    ) -> Result<PoisPerListStatusMap, PoiError> {
        let response: PoisPerListMap = self
            .send_request(
                POI_POIS_PER_LIST_METHOD,
                Self::pois_per_list_params(
                    txid_version,
                    chain_type,
                    chain_id,
                    list_keys,
                    blinded_commitment_datas,
                ),
            )
            .await?;

        Ok(blinded_commitment_datas
            .iter()
            .map(|data| {
                let blinded_commitment_hex = hex::encode_prefixed(data.blinded_commitment);
                let per_list = response
                    .get(&blinded_commitment_hex)
                    .cloned()
                    .unwrap_or_default();
                let statuses = list_keys
                    .iter()
                    .copied()
                    .map(|list_key| {
                        let status = per_list
                            .get(&hex::encode(list_key))
                            .copied()
                            .unwrap_or(PoiStatus::Missing);
                        (list_key, status)
                    })
                    .collect();
                (data.blinded_commitment, statuses)
            })
            .collect())
    }

    pub async fn poi_merkle_proofs(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_key: &FixedBytes<32>,
        blinded_commitments: &[FixedBytes<32>],
    ) -> Result<Vec<PoiMerkleProof>, PoiRpcError> {
        self.send_request(
            POI_MERKLE_PROOFS_METHOD,
            Self::poi_merkle_proofs_params(
                txid_version,
                chain_type,
                chain_id,
                list_key,
                blinded_commitments,
            ),
        )
        .await
    }

    pub async fn poi_events(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_key: &FixedBytes<32>,
        start_index: u64,
        end_index: u64,
    ) -> Result<Vec<PoiSyncedListEvent>, PoiRpcError> {
        self.send_request(
            POI_EVENTS_METHOD,
            Self::poi_events_params(
                txid_version,
                chain_type,
                chain_id,
                list_key,
                start_index,
                end_index,
            ),
        )
        .await
    }

    pub async fn poi_merkletree_leaves(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_key: &FixedBytes<32>,
        start_index: u64,
        end_index: u64,
    ) -> Result<Vec<U256>, PoiRpcError> {
        let response: PoiMerkletreeLeavesResponse = self
            .send_request(
                POI_MERKLETREE_LEAVES_METHOD,
                Self::poi_merkletree_leaves_params(
                    txid_version,
                    chain_type,
                    chain_id,
                    list_key,
                    start_index,
                    end_index,
                ),
            )
            .await?;
        Ok(response.leaves)
    }

    pub async fn blocked_shields(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_key: &FixedBytes<32>,
        start_index: u64,
        end_index: u64,
    ) -> Result<Vec<SignedBlockedShield>, PoiRpcError> {
        self.send_request(
            POI_BLOCKED_SHIELDS_METHOD,
            Self::blocked_shields_params(
                txid_version,
                chain_type,
                chain_id,
                list_key,
                start_index,
                end_index,
            ),
        )
        .await
    }

    pub async fn filtered_blocked_shields(
        &self,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_key: &FixedBytes<32>,
        bloom_filter_serialized: Option<&str>,
    ) -> Result<Vec<BlockedShield>, PoiRpcError> {
        self.send_request(
            POI_BLOCKED_SHIELDS_METHOD,
            Self::filtered_blocked_shields_params(
                txid_version,
                chain_type,
                chain_id,
                list_key,
                bloom_filter_serialized,
            ),
        )
        .await
    }
}

fn decode_json_rpc_response<R>(body: &str) -> Result<R, PoiRpcError>
where
    R: for<'de> Deserialize<'de>,
{
    let parsed: JsonRpcResp<R> = serde_json::from_str(body).map_err(PoiRpcError::JsonDecode)?;
    if let Some(error) = parsed.error {
        return Err(PoiRpcError::JsonRpc {
            code: error.code,
            message: error.message,
            data: error.data,
        });
    }
    parsed.result.ok_or(PoiRpcError::MissingResult)
}

fn decode_json_rpc_ack_response(method: &'static str, body: &str) -> Result<(), PoiRpcError> {
    let parsed: JsonRpcResp<serde_json::Value> =
        serde_json::from_str(body).map_err(PoiRpcError::JsonDecode)?;
    if let Some(error) = parsed.error {
        return Err(PoiRpcError::JsonRpc {
            code: error.code,
            message: error.message,
            data: error.data,
        });
    }
    if parsed.result.is_some_and(|result| !result.is_null()) {
        debug!(method, "POI RPC ack response contained a result");
    }
    Ok(())
}

fn encode_u256(value: U256) -> String {
    format!("0x{value:064x}")
}

fn encode_u256_bare(value: U256) -> String {
    format!("{value:064x}")
}

#[cfg(test)]
mod tests;
