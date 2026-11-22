use alloy_primitives::{Address, FixedBytes, U256, hex};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    ChainScope, ChunkError, CompressionAlgorithm, PublisherIdentity, compress_bytes,
    decompress_bytes_with_limit,
};

pub const AMOUNT_STATISTICS_SNAPSHOT_ENCODING_VERSION: u16 = 1;
pub const AMOUNT_STATISTICS_MANIFEST_FORMAT_VERSION: u16 = 1;
pub const AMOUNT_STATISTICS_MAX_COMPRESSED_BYTES: u64 = 4 * 1024 * 1024;
pub const AMOUNT_STATISTICS_MAX_DECODED_BYTES: u64 = 32 * 1024 * 1024;

/// Envelope signed with [`AMOUNT_STATISTICS_FIXTURE_SIGNING_KEY_SEED`], shared by
/// the indexer's signing test and the wallet's verification test.
pub const AMOUNT_STATISTICS_MANIFEST_ENVELOPE_FIXTURE: &str =
    include_str!("../fixtures/amount_statistics_manifest_envelope.json");
pub const AMOUNT_STATISTICS_FIXTURE_SIGNING_KEY_SEED: [u8; 32] = [7; 32];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmountStatisticsCoveredBlock {
    pub number: u64,
    pub hash: FixedBytes<32>,
    /// Unix seconds.
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmountStatisticsSnapshot {
    pub encoding_version: u16,
    pub scope: ChainScope,
    pub covered_block: AmountStatisticsCoveredBlock,
    pub tokens: Vec<TokenAmountStatistics>,
}

impl AmountStatisticsSnapshot {
    #[must_use]
    pub fn token(&self, token: Address) -> Option<&TokenAmountStatistics> {
        self.tokens.iter().find(|entry| entry.token == token)
    }

    fn canonicalize(&mut self) {
        self.tokens.sort_by_key(|token| token.token);
        for token in &mut self.tokens {
            token
                .repeated_shield_amounts
                .sort_by_key(|amount| amount.value);
            for amount in &mut token.repeated_shield_amounts {
                amount.trees.sort_by_key(|tree| tree.tree);
            }
            token.shield_value_buckets.sort_by_key(|tree| tree.tree);
            for tree in &mut token.shield_value_buckets {
                tree.buckets.sort_by_key(|bucket| bucket.bit_length);
            }
            token
                .repeated_unshield_amounts
                .sort_by_key(|amount| amount.value);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenAmountStatistics {
    pub token: Address,
    pub pool_balance: U256,
    pub shields_last_24h: u64,
    pub shields_last_30d: u64,
    pub unshields_last_24h: u64,
    pub unshields_last_30d: u64,
    pub repeated_shield_amounts: Vec<RepeatedShieldAmount>,
    pub shield_value_buckets: Vec<TreeShieldValueBuckets>,
    pub repeated_unshield_amounts: Vec<RepeatedUnshieldAmount>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepeatedShieldAmount {
    pub value: U256,
    pub trees: Vec<TreeShieldAmountCount>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeShieldAmountCount {
    pub tree: u32,
    pub all_time: u64,
    pub last_30d: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeShieldValueBuckets {
    pub tree: u32,
    /// Non-empty buckets only.
    pub buckets: Vec<ShieldValueBucketCount>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldValueBucketCount {
    pub bit_length: u16,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepeatedUnshieldAmount {
    pub value: U256,
    pub last_30d: u64,
}

/// The power-of-two bucket of a note value: its bit length.
#[must_use]
pub const fn amount_value_bucket(value: U256) -> u16 {
    value.bit_len() as u16
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedAmountStatisticsSnapshot {
    pub bytes: Vec<u8>,
    pub decoded_byte_size: u64,
}

/// Encodes collections in canonical order, so equal statistics always produce
/// identical bytes and an unchanged snapshot keeps its CID.
pub fn encode_amount_statistics_snapshot(
    snapshot: &AmountStatisticsSnapshot,
) -> Result<EncodedAmountStatisticsSnapshot, AmountStatisticsError> {
    ensure_supported_encoding_version(snapshot.encoding_version)?;
    let mut canonical = snapshot.clone();
    canonical.canonicalize();
    let decoded = serde_json::to_vec(&canonical)?;
    let decoded_byte_size = decoded.len() as u64;
    if decoded_byte_size > AMOUNT_STATISTICS_MAX_DECODED_BYTES {
        return Err(AmountStatisticsError::DecodedTooLarge {
            actual: decoded_byte_size,
            maximum: AMOUNT_STATISTICS_MAX_DECODED_BYTES,
        });
    }
    let bytes = compress_bytes(&decoded, CompressionAlgorithm::Zstd)?;
    ensure_compressed_size(&bytes)?;
    Ok(EncodedAmountStatisticsSnapshot {
        bytes,
        decoded_byte_size,
    })
}

pub fn decode_amount_statistics_snapshot(
    bytes: &[u8],
) -> Result<AmountStatisticsSnapshot, AmountStatisticsError> {
    ensure_compressed_size(bytes)?;
    let decoded = decompress_bytes_with_limit(
        bytes,
        CompressionAlgorithm::Zstd,
        AMOUNT_STATISTICS_MAX_DECODED_BYTES,
    )
    .map_err(|error| match error {
        ChunkError::DecodedEnvelopeTooLarge { actual, maximum } => {
            AmountStatisticsError::DecodedTooLarge { actual, maximum }
        }
        other => AmountStatisticsError::Compression(other),
    })?;
    let probe: EncodingVersionProbe = serde_json::from_slice(&decoded)?;
    ensure_supported_encoding_version(probe.encoding_version)?;
    Ok(serde_json::from_slice(&decoded)?)
}

#[derive(Deserialize)]
struct EncodingVersionProbe {
    encoding_version: u16,
}

const fn ensure_supported_encoding_version(version: u16) -> Result<(), AmountStatisticsError> {
    if version == AMOUNT_STATISTICS_SNAPSHOT_ENCODING_VERSION {
        Ok(())
    } else {
        Err(AmountStatisticsError::UnsupportedEncodingVersion(version))
    }
}

const fn ensure_compressed_size(bytes: &[u8]) -> Result<(), AmountStatisticsError> {
    let actual = bytes.len() as u64;
    if actual > AMOUNT_STATISTICS_MAX_COMPRESSED_BYTES {
        return Err(AmountStatisticsError::CompressedTooLarge {
            actual,
            maximum: AMOUNT_STATISTICS_MAX_COMPRESSED_BYTES,
        });
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmountStatisticsManifest {
    pub format_version: u16,
    pub issued_at_ms: u64,
    pub sequence: u64,
    pub publisher: PublisherIdentity,
    pub chains: Vec<AmountStatisticsChainEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmountStatisticsChainEntry {
    pub scope: ChainScope,
    pub covered_block: AmountStatisticsCoveredBlock,
    pub snapshot: AmountStatisticsSnapshotDescriptor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmountStatisticsSnapshotDescriptor {
    pub cid: String,
    pub sha256: FixedBytes<32>,
    pub byte_size: u64,
    pub encoding_version: u16,
    pub compression: CompressionAlgorithm,
}

/// The signing message is exactly the UTF-8 bytes of `body`. Neither side
/// re-serialises the body, so fields added by a newer publisher keep verifying.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmountStatisticsManifestEnvelope {
    pub body: String,
    pub publisher: PublisherIdentity,
    pub signature: FixedBytes<64>,
}

impl AmountStatisticsManifestEnvelope {
    pub fn sign(
        manifest: &AmountStatisticsManifest,
        signing_key: &SigningKey,
    ) -> Result<Self, AmountStatisticsError> {
        let publisher =
            PublisherIdentity::ed25519(FixedBytes::from(signing_key.verifying_key().to_bytes()));
        let mut manifest = manifest.clone();
        manifest.publisher = publisher.clone();
        let body = serde_json::to_string(&manifest)?;
        let signature = FixedBytes::from(signing_key.sign(body.as_bytes()).to_bytes());
        Ok(Self {
            body,
            publisher,
            signature,
        })
    }

    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, AmountStatisticsError> {
        Ok(serde_json::from_slice(bytes)?)
    }

    pub fn verify_trusted(
        &self,
        trusted_publisher_pubkey: &[u8; 32],
    ) -> Result<AmountStatisticsManifest, AmountStatisticsError> {
        if self.publisher.public_key.as_slice() != trusted_publisher_pubkey.as_slice() {
            return Err(publisher_key_mismatch(
                trusted_publisher_pubkey,
                &self.publisher,
            ));
        }
        let verifying_key = VerifyingKey::from_bytes(trusted_publisher_pubkey)
            .map_err(AmountStatisticsError::PublicKey)?;
        verifying_key
            .verify(
                self.body.as_bytes(),
                &Signature::from_bytes(&self.signature.0),
            )
            .map_err(AmountStatisticsError::Signature)?;

        let manifest: AmountStatisticsManifest = serde_json::from_str(&self.body)?;
        if manifest.format_version != AMOUNT_STATISTICS_MANIFEST_FORMAT_VERSION {
            return Err(AmountStatisticsError::UnsupportedManifestFormatVersion(
                manifest.format_version,
            ));
        }
        if manifest.publisher != self.publisher {
            return Err(publisher_key_mismatch(
                &self.publisher.public_key.0,
                &manifest.publisher,
            ));
        }
        Ok(manifest)
    }
}

fn publisher_key_mismatch(
    expected: &[u8; 32],
    actual: &PublisherIdentity,
) -> AmountStatisticsError {
    AmountStatisticsError::PublisherKeyMismatch {
        expected: hex::encode_prefixed(expected),
        actual: hex::encode_prefixed(actual.public_key.as_slice()),
    }
}

#[derive(Debug, Error)]
pub enum AmountStatisticsError {
    #[error("amount statistics JSON could not be encoded or decoded")]
    Json(#[from] serde_json::Error),
    #[error("amount statistics snapshot compressed size {actual} exceeds maximum {maximum}")]
    CompressedTooLarge { actual: u64, maximum: u64 },
    #[error("amount statistics snapshot decoded size {actual} exceeds maximum {maximum}")]
    DecodedTooLarge { actual: u64, maximum: u64 },
    #[error("unsupported amount statistics snapshot encoding version {0}")]
    UnsupportedEncodingVersion(u16),
    #[error("unsupported amount statistics manifest format version {0}")]
    UnsupportedManifestFormatVersion(u16),
    #[error("amount statistics snapshot compression failed")]
    Compression(#[from] ChunkError),
    #[error("amount statistics publisher public key mismatch: expected {expected}, got {actual}")]
    PublisherKeyMismatch { expected: String, actual: String },
    #[error("invalid amount statistics publisher public key")]
    PublicKey(#[source] ed25519_dalek::SignatureError),
    #[error("amount statistics manifest signature verification failed")]
    Signature(#[source] ed25519_dalek::SignatureError),
}

#[cfg(test)]
mod tests;
