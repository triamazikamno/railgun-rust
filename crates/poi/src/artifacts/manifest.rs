use std::fs;
use std::path::Path;

use alloy::hex;
use alloy::primitives::FixedBytes;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const PUBLISHER_SIGNING_KEY_FIELD: &str = "publisher signing key";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactDescriptor {
    pub cid: String,
    pub sha256: FixedBytes<32>,
    pub byte_size: u64,
}

impl ArtifactDescriptor {
    #[must_use]
    pub fn from_bytes(cid: impl Into<String>, bytes: &[u8]) -> Self {
        Self {
            cid: cid.into(),
            sha256: FixedBytes::from(content_hash(bytes)),
            byte_size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        }
    }

    pub fn verify_bytes(&self, bytes: &[u8]) -> Result<(), ManifestError> {
        let actual_size =
            u64::try_from(bytes.len()).map_err(|_| ManifestError::ByteSizeOverflow)?;
        if actual_size != self.byte_size {
            return Err(ManifestError::ArtifactByteSizeMismatch {
                cid: self.cid.clone(),
                expected: self.byte_size,
                actual: actual_size,
            });
        }

        let expected = self.sha256;
        let actual = FixedBytes::from(content_hash(bytes));
        if actual != expected {
            return Err(ManifestError::ArtifactHashMismatch {
                cid: self.cid.clone(),
                expected: hex::encode_prefixed(expected.as_slice()),
                actual: hex::encode_prefixed(actual.as_slice()),
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetainedDeltaDescriptor {
    #[serde(flatten)]
    pub artifact: ArtifactDescriptor,
    pub start_index: u64,
    pub end_index: u64,
    pub tip_merkleroot: FixedBytes<32>,
}

impl RetainedDeltaDescriptor {
    #[must_use]
    pub const fn new(
        artifact: ArtifactDescriptor,
        start_index: u64,
        end_index: u64,
        tip_merkleroot: FixedBytes<32>,
    ) -> Self {
        Self {
            artifact,
            start_index,
            end_index,
            tip_merkleroot,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub format_version: u16,
    pub issued_at_ms: u64,
    pub sequence: u64,
    pub publisher_pubkey: FixedBytes<32>,
    pub entries: Vec<ManifestEntry>,
    pub publisher_signature: Option<FixedBytes<64>>,
}

impl Manifest {
    #[must_use]
    pub const fn new(
        format_version: u16,
        issued_at_ms: u64,
        sequence: u64,
        publisher_pubkey: FixedBytes<32>,
        entries: Vec<ManifestEntry>,
    ) -> Self {
        Self {
            format_version,
            issued_at_ms,
            sequence,
            publisher_pubkey,
            entries,
            publisher_signature: None,
        }
    }

    pub fn deterministic_body_bytes(&self) -> Result<Vec<u8>, ManifestError> {
        let mut entries = self.entries.clone();
        entries.sort_by(|left, right| {
            left.list_key
                .cmp(&right.list_key)
                .then_with(|| left.chain_id.cmp(&right.chain_id))
        });

        let body = ManifestBody {
            format_version: self.format_version,
            issued_at_ms: self.issued_at_ms,
            sequence: self.sequence,
            publisher_pubkey: self.publisher_pubkey,
            entries,
        };
        serde_json::to_vec(&body).map_err(ManifestError::Json)
    }

    #[must_use]
    pub fn sign(body_bytes: &[u8], signing_key: &SigningKey) -> [u8; 64] {
        signing_key.sign(body_bytes).to_bytes()
    }

    pub fn sign_manifest(&mut self, signing_key: &SigningKey) -> Result<(), ManifestError> {
        self.publisher_pubkey = FixedBytes::from(signing_key.verifying_key().to_bytes());
        let body_bytes = self.deterministic_body_bytes()?;
        self.publisher_signature = Some(FixedBytes::from(Self::sign(&body_bytes, signing_key)));
        Ok(())
    }

    pub fn verify_signature(&self) -> Result<(), ManifestError> {
        self.verify_signature_with_key(&self.publisher_pubkey.0)
    }

    pub fn verify_trusted_signature(
        &self,
        trusted_publisher_pubkey: &[u8; 32],
    ) -> Result<(), ManifestError> {
        if self.publisher_pubkey.as_slice() != trusted_publisher_pubkey.as_slice() {
            return Err(ManifestError::PublisherKeyMismatch {
                expected: hex::encode_prefixed(trusted_publisher_pubkey),
                actual: hex::encode_prefixed(self.publisher_pubkey.as_slice()),
            });
        }

        self.verify_signature_with_key(trusted_publisher_pubkey)
    }

    fn verify_signature_with_key(&self, pubkey_bytes: &[u8; 32]) -> Result<(), ManifestError> {
        let signature_bytes = self
            .publisher_signature
            .as_ref()
            .ok_or(ManifestError::MissingPublisherSignature)?;
        let verifying_key =
            VerifyingKey::from_bytes(pubkey_bytes).map_err(ManifestError::PublicKey)?;
        let signature = Signature::from_bytes(&signature_bytes.0);
        verifying_key
            .verify(&self.deterministic_body_bytes()?, &signature)
            .map_err(ManifestError::Signature)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub list_key: FixedBytes<32>,
    pub chain_id: u64,
    pub base: ArtifactDescriptor,
    pub deltas: Vec<ArtifactDescriptor>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retained_deltas: Vec<RetainedDeltaDescriptor>,
    pub blocked_shields: ArtifactDescriptor,
    pub current_tip_index: u64,
    pub current_tip_merkleroot: FixedBytes<32>,
}

#[derive(Serialize)]
struct ManifestBody {
    format_version: u16,
    issued_at_ms: u64,
    sequence: u64,
    publisher_pubkey: FixedBytes<32>,
    entries: Vec<ManifestEntry>,
}

pub fn load_publisher_signing_key(path: impl AsRef<Path>) -> Result<SigningKey, ManifestError> {
    let data = fs::read(path).map_err(ManifestError::KeyRead)?;
    if data.len() == 32 {
        let bytes = fixed_slice::<32>(PUBLISHER_SIGNING_KEY_FIELD, &data)?;
        return Ok(SigningKey::from_bytes(&bytes));
    }

    let text = std::str::from_utf8(&data).map_err(ManifestError::KeyUtf8)?;
    let bytes = decode_fixed_hex::<32>(PUBLISHER_SIGNING_KEY_FIELD, text.trim())?;
    Ok(SigningKey::from_bytes(&bytes))
}

#[must_use]
pub fn content_hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("manifest JSON serialization failed")]
    Json(#[source] serde_json::Error),
    #[error("failed to read publisher signing key")]
    KeyRead(#[source] std::io::Error),
    #[error("publisher signing key file is neither 32 raw bytes nor hex text")]
    KeyUtf8(#[source] std::str::Utf8Error),
    #[error("invalid hex in {field}")]
    Hex {
        field: &'static str,
        #[source]
        source: hex::FromHexError,
    },
    #[error("{field} has {actual} bytes, expected {expected}")]
    InvalidByteLen {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("invalid manifest publisher public key")]
    PublicKey(#[source] ed25519_dalek::SignatureError),
    #[error("manifest publisher public key mismatch: expected {expected}, got {actual}")]
    PublisherKeyMismatch { expected: String, actual: String },
    #[error("manifest publisher signature is missing")]
    MissingPublisherSignature,
    #[error("manifest signature verification failed")]
    Signature(#[source] ed25519_dalek::SignatureError),
    #[error("artifact byte size overflows u64")]
    ByteSizeOverflow,
    #[error("artifact {cid} byte size mismatch: expected {expected}, got {actual}")]
    ArtifactByteSizeMismatch {
        cid: String,
        expected: u64,
        actual: u64,
    },
    #[error("artifact {cid} sha256 mismatch: expected {expected}, got {actual}")]
    ArtifactHashMismatch {
        cid: String,
        expected: String,
        actual: String,
    },
}

fn decode_fixed_hex<const N: usize>(
    field: &'static str,
    value: &str,
) -> Result<[u8; N], ManifestError> {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|source| ManifestError::Hex { field, source })?;
    fixed_slice(field, &bytes)
}

fn fixed_slice<const N: usize>(
    field: &'static str,
    value: &[u8],
) -> Result<[u8; N], ManifestError> {
    value.try_into().map_err(|_| ManifestError::InvalidByteLen {
        field,
        expected: N,
        actual: value.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn descriptor_verifies_matching_bytes() {
        let bytes = b"artifact bytes";
        let descriptor = ArtifactDescriptor::from_bytes("bafyartifact", bytes);

        descriptor.verify_bytes(bytes).expect("matching bytes");
    }

    #[test]
    fn descriptor_rejects_size_and_hash_mismatch() {
        let descriptor = ArtifactDescriptor::from_bytes("bafyartifact", b"artifact bytes");
        let mut wrong_size = descriptor.clone();
        wrong_size.byte_size += 1;
        assert!(matches!(
            wrong_size.verify_bytes(b"artifact bytes"),
            Err(ManifestError::ArtifactByteSizeMismatch { .. })
        ));

        assert!(matches!(
            descriptor.verify_bytes(b"artifact bytex"),
            Err(ManifestError::ArtifactHashMismatch { .. })
        ));
    }

    #[test]
    fn manifest_body_bytes_are_deterministic() {
        let mut first = manifest(vec![entry(2, 2), entry(1, 1)]);
        let mut second = manifest(vec![entry(1, 1), entry(2, 2)]);
        first.publisher_signature = Some(FixedBytes::from([1_u8; 64]));
        second.publisher_signature = Some(FixedBytes::from([2_u8; 64]));

        assert_eq!(
            first.deterministic_body_bytes().expect("first body"),
            second.deterministic_body_bytes().expect("second body")
        );
    }

    #[test]
    fn manifest_signature_verifies_with_publisher_pubkey() {
        let signing_key = SigningKey::from_bytes(&[12_u8; 32]);
        let mut manifest = manifest(vec![entry(1, 1)]);

        manifest.sign_manifest(&signing_key).expect("sign manifest");

        manifest.verify_signature().expect("valid signature");
        manifest
            .verify_trusted_signature(signing_key.verifying_key().as_bytes())
            .expect("trusted publisher signature");
    }

    #[test]
    fn manifest_signature_rejects_untrusted_publisher_pubkey() {
        let signing_key = SigningKey::from_bytes(&[12_u8; 32]);
        let mut manifest = manifest(vec![entry(1, 1)]);
        manifest.sign_manifest(&signing_key).expect("sign manifest");

        assert!(matches!(
            manifest.verify_trusted_signature(&[13_u8; 32]),
            Err(ManifestError::PublisherKeyMismatch { .. })
        ));
    }

    #[test]
    fn manifest_signature_covers_sequence_and_issued_at_ms() {
        let signing_key = SigningKey::from_bytes(&[12_u8; 32]);
        let mut manifest = manifest(vec![entry(1, 1)]);
        manifest.sign_manifest(&signing_key).expect("sign manifest");

        manifest.sequence += 1;
        assert!(manifest.verify_signature().is_err());

        manifest.sequence -= 1;
        manifest.issued_at_ms += 1;
        assert!(manifest.verify_signature().is_err());
    }

    #[test]
    fn manifest_signature_covers_artifact_descriptor_fields() {
        let signing_key = SigningKey::from_bytes(&[12_u8; 32]);
        for mutate in [mutate_cid, mutate_sha256, mutate_byte_size] {
            let mut manifest = manifest(vec![entry(1, 1)]);
            manifest.sign_manifest(&signing_key).expect("sign manifest");

            mutate(&mut manifest.entries[0].base);

            assert!(manifest.verify_signature().is_err());
        }
    }

    #[test]
    fn manifest_signature_covers_blocked_shields_descriptor() {
        let signing_key = SigningKey::from_bytes(&[12_u8; 32]);
        let mut manifest = manifest(vec![entry(1, 1)]);
        manifest.sign_manifest(&signing_key).expect("sign manifest");

        manifest.entries[0].blocked_shields.sha256 = FixedBytes::from([9_u8; 32]);

        assert!(manifest.verify_signature().is_err());
    }

    #[test]
    fn manifest_signature_covers_retained_delta_descriptor() {
        let signing_key = SigningKey::from_bytes(&[12_u8; 32]);
        let mut manifest = manifest(vec![entry(1, 1)]);
        manifest.entries[0].retained_deltas = vec![RetainedDeltaDescriptor::new(
            descriptor("retained", 1),
            10,
            19,
            FixedBytes::from([8_u8; 32]),
        )];
        manifest.sign_manifest(&signing_key).expect("sign manifest");

        manifest.entries[0].retained_deltas[0].end_index += 1;

        assert!(manifest.verify_signature().is_err());
    }

    #[test]
    fn manifest_entry_defaults_missing_retained_deltas() {
        let json = r#"{
            "list_key":"0x0101010101010101010101010101010101010101010101010101010101010101",
            "chain_id":1,
            "base":{"cid":"bafybase","sha256":"0x0000000000000000000000000000000000000000000000000000000000000000","byte_size":0},
            "deltas":[],
            "blocked_shields":{"cid":"bafyblocked","sha256":"0x0000000000000000000000000000000000000000000000000000000000000000","byte_size":0},
            "current_tip_index":0,
            "current_tip_merkleroot":"0x0000000000000000000000000000000000000000000000000000000000000000"
        }"#;

        let entry: ManifestEntry = serde_json::from_str(json).expect("entry decodes");

        assert!(entry.retained_deltas.is_empty());
    }

    #[test]
    fn loads_publisher_signing_key_from_hex_file() {
        let path = std::env::temp_dir().join(format!("poi-test-key-{}", std::process::id()));
        fs::write(&path, hex::encode([42_u8; 32])).expect("write key");

        let signing_key = load_publisher_signing_key(&path).expect("load key");

        assert_eq!(signing_key.to_bytes(), [42_u8; 32]);
        fs::remove_file(path).expect("remove key");
    }

    fn manifest(entries: Vec<ManifestEntry>) -> Manifest {
        Manifest::new(
            2,
            1_767_225_600_000,
            1_767_225_600_000,
            FixedBytes::ZERO,
            entries,
        )
    }

    fn entry(list_key_byte: u8, chain_id: u64) -> ManifestEntry {
        ManifestEntry {
            list_key: FixedBytes::from([list_key_byte; 32]),
            chain_id,
            base: descriptor("base", chain_id),
            deltas: vec![descriptor("delta", chain_id)],
            retained_deltas: Vec::new(),
            blocked_shields: descriptor("blocked", chain_id),
            current_tip_index: chain_id * 10,
            current_tip_merkleroot: fixed_from_u64(chain_id),
        }
    }

    fn descriptor(kind: &str, chain_id: u64) -> ArtifactDescriptor {
        ArtifactDescriptor {
            cid: format!("bafy{kind}{chain_id}"),
            sha256: fixed_from_u64(chain_id),
            byte_size: chain_id * 100,
        }
    }

    fn fixed_from_u64(value: u64) -> FixedBytes<32> {
        let mut bytes = [0_u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        FixedBytes::from(bytes)
    }

    fn mutate_cid(descriptor: &mut ArtifactDescriptor) {
        descriptor.cid.push_str("changed");
    }

    fn mutate_sha256(descriptor: &mut ArtifactDescriptor) {
        descriptor.sha256 = FixedBytes::from([7_u8; 32]);
    }

    fn mutate_byte_size(descriptor: &mut ArtifactDescriptor) {
        descriptor.byte_size += 1;
    }
}
