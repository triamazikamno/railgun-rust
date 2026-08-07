use std::fmt;

use alloy::primitives::{Address, Bytes, FixedBytes, U64, U256, Uint};
use alloy::sol_types::SolValue;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use broadcaster_core::contracts::railgun::{
    CommitmentPreimage, LegacyCommitmentPreimage, ShieldCiphertext, TokenData,
};
use broadcaster_core::transact::{
    compute_railgun_txid_parts, railgun_txid_leaf_hash_with_output_start,
};
use broadcaster_core::tree::TREE_LEAF_COUNT;

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Commitment {
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_64")]
    pub id: FixedBytes<64>,
    #[serde(rename = "treeNumber")]
    pub tree_number: U256,
    #[serde(rename = "treePosition")]
    pub tree_position: U256,
    #[serde(rename = "batchStartTreePosition")]
    pub batch_start_tree_position: U256,
    #[serde(rename = "blockNumber")]
    pub block_number: U256,
    pub hash: U256,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IndexedTransactCommitment {
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_64")]
    pub id: FixedBytes<64>,
    #[serde(rename = "transactionHash")]
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_32")]
    pub transaction_hash: FixedBytes<32>,
    #[serde(rename = "blockNumber")]
    pub block_number: U256,
    #[serde(rename = "blockTimestamp")]
    pub block_timestamp: U256,
    #[serde(rename = "treeNumber")]
    pub tree_number: U256,
    #[serde(rename = "treePosition")]
    pub tree_position: U256,
    pub hash: U256,
    pub ciphertext: IndexedCommitmentCiphertext,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IndexedLegacyEncryptedCommitment {
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_64")]
    pub id: FixedBytes<64>,
    #[serde(rename = "transactionHash")]
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_32")]
    pub transaction_hash: FixedBytes<32>,
    #[serde(rename = "blockNumber")]
    pub block_number: U256,
    #[serde(rename = "blockTimestamp")]
    pub block_timestamp: U256,
    #[serde(rename = "treeNumber")]
    pub tree_number: U256,
    #[serde(rename = "treePosition")]
    pub tree_position: U256,
    pub hash: U256,
    pub ciphertext: IndexedLegacyCommitmentCiphertext,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IndexedLegacyCommitmentCiphertext {
    #[serde(deserialize_with = "deserialize_commitment_ciphertext")]
    pub ciphertext: [FixedBytes<32>; 4],
    #[serde(
        rename = "ephemeralKeys",
        deserialize_with = "deserialize_indexed_fixed_bytes_array_32_2"
    )]
    pub ephemeral_keys: [FixedBytes<32>; 2],
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_vec_32")]
    pub memo: Vec<FixedBytes<32>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IndexedLegacyGeneratedCommitment {
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_64")]
    pub id: FixedBytes<64>,
    #[serde(rename = "transactionHash")]
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_32")]
    pub transaction_hash: FixedBytes<32>,
    #[serde(rename = "blockNumber")]
    pub block_number: U256,
    #[serde(rename = "blockTimestamp")]
    pub block_timestamp: U256,
    #[serde(rename = "treeNumber")]
    pub tree_number: U256,
    #[serde(rename = "treePosition")]
    pub tree_position: U256,
    pub hash: U256,
    pub preimage: IndexedLegacyCommitmentPreimage,
    #[serde(
        rename = "encryptedRandom",
        deserialize_with = "deserialize_indexed_encrypted_random"
    )]
    pub encrypted_random: (FixedBytes<32>, FixedBytes<16>),
}

#[derive(Debug, Clone, Deserialize)]
pub struct IndexedCommitmentCiphertext {
    #[serde(deserialize_with = "deserialize_commitment_ciphertext")]
    pub ciphertext: [FixedBytes<32>; 4],
    #[serde(rename = "blindedSenderViewingKey")]
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_32")]
    pub blinded_sender_viewing_key: FixedBytes<32>,
    #[serde(rename = "blindedReceiverViewingKey")]
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_32")]
    pub blinded_receiver_viewing_key: FixedBytes<32>,
    #[serde(rename = "annotationData")]
    #[serde(default)]
    pub annotation_data: Bytes,
    pub memo: Bytes,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IndexedShieldCommitment {
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_64")]
    pub id: FixedBytes<64>,
    #[serde(rename = "transactionHash")]
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_32")]
    pub transaction_hash: FixedBytes<32>,
    #[serde(rename = "blockNumber")]
    pub block_number: U256,
    #[serde(rename = "blockTimestamp")]
    pub block_timestamp: U256,
    #[serde(rename = "treeNumber")]
    pub tree_number: U256,
    #[serde(rename = "treePosition")]
    pub tree_position: U256,
    pub preimage: IndexedCommitmentPreimage,
    #[serde(rename = "shieldKey")]
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_32")]
    pub shield_key: FixedBytes<32>,
    #[serde(rename = "encryptedBundle")]
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_array_32_3")]
    pub encrypted_bundle: [FixedBytes<32>; 3],
}

impl IndexedShieldCommitment {
    #[must_use]
    pub fn preimage(&self) -> CommitmentPreimage {
        self.preimage.clone().into()
    }

    #[must_use]
    pub const fn shield_ciphertext(&self) -> ShieldCiphertext {
        ShieldCiphertext {
            encryptedBundle: self.encrypted_bundle,
            shieldKey: self.shield_key,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct IndexedCommitmentPreimage {
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_32")]
    pub npk: FixedBytes<32>,
    pub token: IndexedTokenData,
    pub value: U256,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IndexedLegacyCommitmentPreimage {
    pub npk: U256,
    pub token: IndexedTokenData,
    pub value: U256,
}

impl From<IndexedLegacyCommitmentPreimage> for LegacyCommitmentPreimage {
    fn from(value: IndexedLegacyCommitmentPreimage) -> Self {
        Self {
            npk: value.npk,
            token: value.token.into(),
            value: Uint::<120, 2>::from(value.value.to::<u128>()),
        }
    }
}

impl From<IndexedCommitmentPreimage> for CommitmentPreimage {
    fn from(value: IndexedCommitmentPreimage) -> Self {
        Self {
            npk: value.npk,
            token: value.token.into(),
            value: Uint::<120, 2>::from(value.value.to::<u128>()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndexedTokenData {
    #[serde(rename = "tokenType", deserialize_with = "deserialize_token_type")]
    pub token_type: u8,
    #[serde(rename = "tokenAddress")]
    pub token_address: Address,
    #[serde(rename = "tokenSubID")]
    pub token_sub_id: U256,
}

#[derive(Debug, Deserialize)]
struct IndexedCiphertextPayload {
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_16")]
    iv: FixedBytes<16>,
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_16")]
    tag: FixedBytes<16>,
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_vec_32")]
    data: Vec<FixedBytes<32>>,
}

#[derive(Debug, Deserialize)]
struct IndexedEncryptedRandom(
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_32")] FixedBytes<32>,
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_16")] FixedBytes<16>,
);

#[derive(Debug, Deserialize)]
struct IndexedFixedBytes<const N: usize>(
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes")] FixedBytes<N>,
);

fn deserialize_indexed_fixed_bytes_16<'de, D>(deserializer: D) -> Result<FixedBytes<16>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_indexed_fixed_bytes(deserializer)
}

fn deserialize_indexed_fixed_bytes_32<'de, D>(deserializer: D) -> Result<FixedBytes<32>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_indexed_fixed_bytes(deserializer)
}

fn deserialize_optional_indexed_fixed_bytes_32<'de, D>(
    deserializer: D,
) -> Result<Option<FixedBytes<32>>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)?
        .map(|value| parse_left_padded_hex(&value))
        .transpose()
}

fn deserialize_indexed_fixed_bytes_64<'de, D>(deserializer: D) -> Result<FixedBytes<64>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_indexed_fixed_bytes(deserializer)
}

fn deserialize_indexed_fixed_bytes<'de, D, const N: usize>(
    deserializer: D,
) -> Result<FixedBytes<N>, D::Error>
where
    D: Deserializer<'de>,
{
    struct IndexedFixedBytesVisitor<const N: usize>;

    impl<const N: usize> Visitor<'_> for IndexedFixedBytesVisitor<N> {
        type Value = FixedBytes<N>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "0x-prefixed hex string up to {N} bytes")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            parse_left_padded_hex(value)
        }
    }

    deserializer.deserialize_str(IndexedFixedBytesVisitor::<N>)
}

fn parse_left_padded_hex<E, const N: usize>(value: &str) -> Result<FixedBytes<N>, E>
where
    E: de::Error,
{
    let hex = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .ok_or_else(|| E::custom("expected 0x-prefixed hex string"))?;
    let byte_len = hex.len().div_ceil(2);
    if byte_len > N {
        return Err(E::custom(format!(
            "expected at most {N} bytes, got {byte_len} bytes"
        )));
    }

    let mut bytes = [0_u8; N];
    let mut index = N - byte_len;
    let hex_bytes = hex.as_bytes();
    let offset = if hex_bytes.len() % 2 == 1 {
        bytes[index] = decode_hex_nibble(hex_bytes[0])?;
        index += 1;
        1
    } else {
        0
    };
    for pair in hex_bytes[offset..].chunks_exact(2) {
        let high = decode_hex_nibble(pair[0])?;
        let low = decode_hex_nibble(pair[1])?;
        bytes[index] = (high << 4) | low;
        index += 1;
    }

    Ok(FixedBytes::from(bytes))
}

fn decode_hex_nibble<E>(value: u8) -> Result<u8, E>
where
    E: de::Error,
{
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(E::custom(format!(
            "invalid hex character: {}",
            char::from(value)
        ))),
    }
}

fn deserialize_indexed_fixed_bytes_array<'de, D, const N: usize, const LEN: usize>(
    deserializer: D,
) -> Result<[FixedBytes<N>; LEN], D::Error>
where
    D: Deserializer<'de>,
{
    let values = Vec::<IndexedFixedBytes<N>>::deserialize(deserializer)?;
    let values = values.into_iter().map(|value| value.0).collect::<Vec<_>>();
    values.try_into().map_err(|values: Vec<_>| {
        de::Error::custom(format!(
            "expected {LEN} fixed byte values, got {}",
            values.len()
        ))
    })
}

fn deserialize_indexed_fixed_bytes_array_32_2<'de, D>(
    deserializer: D,
) -> Result<[FixedBytes<32>; 2], D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_indexed_fixed_bytes_array(deserializer)
}

fn deserialize_indexed_fixed_bytes_array_32_3<'de, D>(
    deserializer: D,
) -> Result<[FixedBytes<32>; 3], D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_indexed_fixed_bytes_array(deserializer)
}

fn deserialize_indexed_fixed_bytes_vec_32<'de, D>(
    deserializer: D,
) -> Result<Vec<FixedBytes<32>>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = Vec::<IndexedFixedBytes<32>>::deserialize(deserializer)?;
    Ok(values.into_iter().map(|value| value.0).collect())
}

fn deserialize_indexed_encrypted_random<'de, D>(
    deserializer: D,
) -> Result<(FixedBytes<32>, FixedBytes<16>), D::Error>
where
    D: Deserializer<'de>,
{
    let encrypted_random = IndexedEncryptedRandom::deserialize(deserializer)?;
    Ok((encrypted_random.0, encrypted_random.1))
}

fn deserialize_commitment_ciphertext<'de, D>(
    deserializer: D,
) -> Result<[FixedBytes<32>; 4], D::Error>
where
    D: Deserializer<'de>,
{
    let payload = IndexedCiphertextPayload::deserialize(deserializer)?;
    let [first, second, third]: [FixedBytes<32>; 3] =
        payload.data.try_into().map_err(|data: Vec<_>| {
            de::Error::custom(format!(
                "expected 3 ciphertext data blocks, got {}",
                data.len()
            ))
        })?;
    let mut iv_tag = [0u8; 32];
    iv_tag[..16].copy_from_slice(&payload.iv.0);
    iv_tag[16..].copy_from_slice(&payload.tag.0);
    Ok([FixedBytes::from(iv_tag), first, second, third])
}

fn deserialize_token_type<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: Deserializer<'de>,
{
    struct TokenTypeVisitor;

    impl Visitor<'_> for TokenTypeVisitor {
        type Value = u8;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("RAILGUN token type enum or numeric token type")
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            u8::try_from(value).map_err(|_| E::custom(format!("token type out of range: {value}")))
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            match value {
                "ERC20" => Ok(0),
                "ERC721" => Ok(1),
                "ERC1155" => Ok(2),
                other => other
                    .parse::<u8>()
                    .map_err(|_| E::custom(format!("unsupported indexed token type: {other}"))),
            }
        }
    }

    deserializer.deserialize_any(TokenTypeVisitor)
}

impl From<IndexedTokenData> for TokenData {
    fn from(value: IndexedTokenData) -> Self {
        Self {
            tokenType: value.token_type,
            tokenAddress: value.token_address,
            tokenSubID: value.token_sub_id,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct IndexedNullifier {
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_64")]
    pub id: FixedBytes<64>,
    #[serde(rename = "transactionHash")]
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_32")]
    pub transaction_hash: FixedBytes<32>,
    #[serde(rename = "blockNumber")]
    pub block_number: U256,
    #[serde(rename = "blockTimestamp")]
    pub block_timestamp: U256,
    #[serde(rename = "treeNumber")]
    pub tree_number: U256,
    pub nullifier: U256,
}

#[derive(Debug, Clone, serde::Serialize, Deserialize, PartialEq, Eq)]
pub struct IndexedRailgunTransaction {
    pub id: String,
    #[serde(rename = "blockNumber")]
    pub block_number: U256,
    #[serde(rename = "blockTimestamp")]
    pub block_timestamp: U256,
    #[serde(rename = "transactionHash")]
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_32")]
    pub transaction_hash: FixedBytes<32>,
    #[serde(rename = "merkleRoot")]
    #[serde(deserialize_with = "deserialize_indexed_fixed_bytes_32")]
    pub merkle_root: FixedBytes<32>,
    pub nullifiers: Vec<U256>,
    pub commitments: Vec<U256>,
    #[serde(rename = "boundParamsHash")]
    pub bound_params_hash: U256,
    #[serde(rename = "hasUnshield")]
    pub has_unshield: bool,
    #[serde(rename = "unshieldToken", default)]
    pub unshield_token: Option<IndexedTokenData>,
    #[serde(
        rename = "unshieldToAddress",
        default,
        deserialize_with = "deserialize_optional_indexed_fixed_bytes_32"
    )]
    pub unshield_to_address: Option<FixedBytes<32>>,
    #[serde(rename = "unshieldValue", default)]
    pub unshield_value: Option<U256>,
    #[serde(rename = "utxoTreeIn")]
    pub utxo_tree_in: U64,
    #[serde(rename = "utxoTreeOut")]
    pub utxo_tree_out: U64,
    #[serde(rename = "utxoBatchStartPositionOut")]
    pub utxo_batch_start_position_out: U64,
}

impl IndexedRailgunTransaction {
    #[must_use]
    pub fn verified_unshield_preimage(&self) -> Option<Vec<u8>> {
        if !self.has_unshield {
            return None;
        }
        let value = self.unshield_value?;
        if value > U256::from((1_u128 << 120) - 1) {
            return None;
        }
        let preimage = CommitmentPreimage {
            npk: self.unshield_to_address?,
            token: self.unshield_token.clone()?.into(),
            value: Uint::<120, 2>::from(value.to::<u128>()),
        };
        (self.commitments.last() == Some(&preimage.hash())).then(|| preimage.abi_encode())
    }

    #[must_use]
    pub fn railgun_txid(&self) -> U256 {
        compute_railgun_txid_parts(&self.nullifiers, &self.commitments, self.bound_params_hash)
    }

    #[must_use]
    pub fn txid_leaf_hash(&self) -> U256 {
        railgun_txid_leaf_hash_with_output_start(
            self.railgun_txid(),
            self.utxo_tree_in.to(),
            U256::from(self.output_start_global()),
        )
    }

    #[must_use]
    pub fn output_start_global(&self) -> u128 {
        let output_tree = self.utxo_tree_out.to::<u128>();
        let output_position = self.utxo_batch_start_position_out.to::<u128>();
        output_tree * u128::from(TREE_LEAF_COUNT) + output_position
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{Address, Bytes, FixedBytes, U256, Uint};
    use alloy::sol_types::SolValue;
    use alloy::uint;
    use serde_json::json;

    use broadcaster_core::contracts::railgun::{CommitmentPreimage, TokenData};

    use super::{IndexedNullifier, IndexedRailgunTransaction, IndexedTransactCommitment};

    #[test]
    fn indexed_unshield_fields_normalize_only_when_commitment_verifies() {
        let destination = Address::from([0x11; 20]);
        let mut npk = [0_u8; 32];
        npk[12..].copy_from_slice(destination.as_slice());
        let preimage = CommitmentPreimage {
            npk: FixedBytes::from(npk),
            token: TokenData {
                tokenType: 0,
                tokenAddress: Address::from([0x22; 20]),
                tokenSubID: U256::ZERO,
            },
            value: Uint::<120, 2>::from(42_u64),
        };
        let mut item: IndexedRailgunTransaction = serde_json::from_value(json!({
            "id": "1",
            "blockNumber": "123",
            "blockTimestamp": "1700000123",
            "transactionHash": format!("0x{}", "33".repeat(32)),
            "merkleRoot": format!("0x{}", "44".repeat(32)),
            "nullifiers": ["0x01"],
            "commitments": [format!("0x{:064x}", preimage.hash())],
            "boundParamsHash": "0x02",
            "hasUnshield": true,
            "unshieldToken": {
                "tokenType": "ERC20",
                "tokenAddress": preimage.token.tokenAddress,
                "tokenSubID": "0",
            },
            "unshieldToAddress": destination,
            "unshieldValue": "42",
            "utxoTreeIn": "0",
            "utxoTreeOut": "1",
            "utxoBatchStartPositionOut": "2",
        }))
        .expect("deserialize Squid unshield row");

        assert_eq!(item.unshield_to_address, Some(preimage.npk));
        assert_eq!(
            item.verified_unshield_preimage(),
            Some(preimage.abi_encode())
        );

        item.commitments[0] = U256::from(7);
        assert_eq!(item.verified_unshield_preimage(), None);

        let full_npk_preimage = CommitmentPreimage {
            npk: FixedBytes::from([0x77; 32]),
            ..preimage
        };
        item.commitments[0] = full_npk_preimage.hash();
        assert_eq!(item.verified_unshield_preimage(), None);
    }

    #[test]
    fn indexed_transact_commitment_preserves_complete_ciphertext() {
        let item: IndexedTransactCommitment = serde_json::from_value(json!({
            "id": format!("0x{}", "11".repeat(64)),
            "transactionHash": format!("0x{}", "22".repeat(32)),
            "blockNumber": "123",
            "blockTimestamp": "1700000123",
            "treeNumber": "4",
            "treePosition": "5",
            "hash": "0x06",
            "ciphertext": {
                "ciphertext": {
                    "iv": format!("0x{}", "01".repeat(16)),
                    "tag": format!("0x{}", "02".repeat(16)),
                    "data": [
                        format!("0x{}", "03".repeat(32)),
                        format!("0x{}", "04".repeat(32)),
                        format!("0x{}", "05".repeat(32)),
                    ],
                },
                "blindedSenderViewingKey": format!("0x{}", "06".repeat(32)),
                "blindedReceiverViewingKey": format!("0x{}", "07".repeat(32)),
                "annotationData": "0x0809",
                "memo": "0x0a0b",
            },
        }))
        .expect("deserialize complete indexed transact commitment");

        assert_eq!(item.ciphertext.ciphertext[0].0[..16], [1; 16]);
        assert_eq!(item.ciphertext.ciphertext[0].0[16..], [2; 16]);
        assert_eq!(
            item.ciphertext.blinded_sender_viewing_key,
            FixedBytes::from([6; 32])
        );
        assert_eq!(
            item.ciphertext.blinded_receiver_viewing_key,
            FixedBytes::from([7; 32])
        );
        assert_eq!(item.ciphertext.annotation_data, Bytes::from(vec![8, 9]));
        assert_eq!(item.ciphertext.memo, Bytes::from(vec![10, 11]));
    }

    #[test]
    fn indexed_nullifier_deserializes_block_timestamp() {
        let item: IndexedNullifier = serde_json::from_value(json!({
            "id": "0x01",
            "transactionHash": "0x02",
            "blockNumber": "123",
            "blockTimestamp": "1700000123",
            "treeNumber": "4",
            "nullifier": "0x05",
        }))
        .expect("deserialize indexed nullifier");

        assert_eq!(item.block_number, uint!(123_U256));
        assert_eq!(item.block_timestamp, uint!(1_700_000_123_U256));
    }
}
