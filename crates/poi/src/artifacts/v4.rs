use std::collections::BTreeSet;
use std::io::{self, Write};

use alloy::hex;
use alloy::primitives::FixedBytes;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256 as Sha256Digest};
use thiserror::Error;

use super::blocked::BlockedShieldArtifactRecord;
use super::manifest::{ArtifactDescriptor, ManifestError};
use super::snapshot::SnapshotEvent;
use super::verify::{VerifyError, verify_blocked_shield, verify_poi_event};
use crate::poi::{PoiEventType, SignedBlockedShield, SignedPoiEvent};

pub const FORMAT_VERSION: u16 = 4;
pub const MANIFEST_SIGNATURE_DOMAIN: &[u8] = b"railgun-poi-manifest-v4\0";
pub const MANIFEST_MAX_BYTES: u64 = 2 * 1024 * 1024;
pub const CHECKPOINT_EVENT_SPAN: u64 = 32_768;
pub const EVENT_ARTIFACT_MAX_BYTES: u64 = 4 * 1024 * 1024;
pub const BLOCKED_SHIELDS_ARTIFACT_MAX_BYTES: u64 = 4 * 1024 * 1024;
pub const CATALOG_MAX_DESCRIPTORS: u64 = 4_096;
pub const CATALOG_MAX_BYTES: u64 = 2 * 1024 * 1024;
pub const MAX_RETAINED_BRIDGES: usize = 7;
pub const ARTIFACT_CAR_MAX_BLOCKS: u64 = 16_384;
pub const IPNS_KDF_SALT: &[u8] = b"railgun-indexer/ipns-key-derivation/v1";
pub const IPNS_KDF_INFO: &[u8] = b"poi-artifact/chunked-manifest/v4";

const EVENT_MAGIC: &[u8; 8] = b"POIEVT4\0";
const EVENT_HEADER_FIXED_BYTES: usize = 147;
const EVENT_RECORD_BYTES: usize = 97;
const EVENT_RECORD_BYTES_U64: u64 = 97;
const CAR_MIN_OVERHEAD_BYTES: u64 = 1024 * 1024;
const CAR_FIXED_OVERHEAD_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub list_key: FixedBytes<32>,
    pub chain_type: u8,
    pub chain_id: u64,
    pub txid_version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationId {
    pub publisher_pubkey: FixedBytes<32>,
    pub sequence: u64,
    pub manifest_body_hash: FixedBytes<32>,
}

impl Scope {
    #[must_use]
    pub fn new(
        list_key: FixedBytes<32>,
        chain_type: u8,
        chain_id: u64,
        txid_version: impl Into<String>,
    ) -> Self {
        Self {
            list_key,
            chain_type,
            chain_id,
            txid_version: txid_version.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventRange {
    pub start_index: u64,
    pub end_index: u64,
}

impl EventRange {
    pub fn new(start_index: u64, end_index: u64) -> Result<Self, Error> {
        let range = Self {
            start_index,
            end_index,
        };
        range.row_count()?;
        Ok(range)
    }

    pub fn row_count(self) -> Result<u64, Error> {
        self.end_index
            .checked_sub(self.start_index)
            .and_then(|difference| difference.checked_add(1))
            .ok_or(Error::InvalidRange {
                start_index: self.start_index,
                end_index: self.end_index,
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactEncoding {
    CanonicalJson,
    PoiEventBinary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Compression {
    Identity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventArtifactKind {
    Checkpoint,
    CurrentTail,
    Bridge,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventArtifactDescriptor {
    pub artifact: ArtifactDescriptor,
    pub format_version: u16,
    pub scope: Scope,
    pub kind: EventArtifactKind,
    pub range: EventRange,
    pub row_count: u64,
    pub encoding: ArtifactEncoding,
    pub compression: Compression,
    pub start_root: Option<FixedBytes<32>>,
    pub end_root: FixedBytes<32>,
}

impl EventArtifactDescriptor {
    pub fn validate(&self) -> Result<(), Error> {
        require_format_version(self.format_version)?;
        if self.encoding != ArtifactEncoding::PoiEventBinary {
            return Err(Error::UnsupportedEncoding);
        }
        if self.compression != Compression::Identity {
            return Err(Error::UnsupportedCompression);
        }
        let range_count = self.range.row_count()?;
        if self.row_count == 0 || self.row_count != range_count {
            return Err(Error::RowCountMismatch {
                expected: range_count,
                actual: self.row_count,
            });
        }
        require_start_root(self.range.start_index, self.start_root)?;
        require_event_artifact_size(self.artifact.byte_size)?;
        let expected_byte_size = expected_event_artifact_size(&self.scope, self.row_count)?;
        if self.artifact.byte_size != expected_byte_size {
            return Err(Error::EventDescriptorByteSizeMismatch {
                expected: expected_byte_size,
                actual: self.artifact.byte_size,
            });
        }
        if self.kind == EventArtifactKind::Checkpoint {
            validate_checkpoint_range(self.range, self.row_count)?;
        }
        Ok(())
    }

    pub fn verify_bytes(&self, bytes: &[u8]) -> Result<EventArtifact, Error> {
        self.validate()?;
        self.artifact.verify_bytes(bytes)?;
        let decoded = EventArtifact::read(bytes)?;
        let decoded_row_count = usize_to_u64(decoded.events.len())?;
        if decoded.format_version != self.format_version
            || decoded.scope != self.scope
            || decoded.kind != self.kind
            || decoded.range != self.range
            || decoded_row_count != self.row_count
            || decoded.encoding != self.encoding
            || decoded.compression != self.compression
            || decoded.start_root != self.start_root
            || decoded.end_root != self.end_root
        {
            return Err(Error::DescriptorBodyMismatch);
        }
        Ok(decoded)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointCatalogDescriptor {
    pub artifact: ArtifactDescriptor,
    pub format_version: u16,
    pub scope: Scope,
    pub range: Option<EventRange>,
    pub row_count: u64,
    pub chunk_count: u64,
    pub encoding: ArtifactEncoding,
    pub compression: Compression,
    pub checkpoint_root: Option<FixedBytes<32>>,
}

impl CheckpointCatalogDescriptor {
    pub fn validate(&self) -> Result<(), Error> {
        require_format_version(self.format_version)?;
        if self.encoding != ArtifactEncoding::CanonicalJson {
            return Err(Error::UnsupportedEncoding);
        }
        if self.compression != Compression::Identity {
            return Err(Error::UnsupportedCompression);
        }
        validate_catalog_limits(
            self.artifact.byte_size,
            self.artifact.byte_size,
            self.chunk_count,
        )?;
        validate_aggregate(self.range, self.row_count, self.checkpoint_root)?;
        let expected = expected_checkpoint_chunk_count(self.row_count)?;
        if self.chunk_count != expected {
            return Err(Error::CheckpointChunkCountMismatch {
                expected,
                actual: self.chunk_count,
            });
        }
        Ok(())
    }

    pub fn verify_bytes(&self, bytes: &[u8]) -> Result<CheckpointCatalog, Error> {
        self.validate()?;
        self.artifact.verify_bytes(bytes)?;
        let catalog = CheckpointCatalog::read(bytes)?;
        let decoded_chunk_count = usize_to_u64(catalog.chunks.len())?;
        if catalog.format_version != self.format_version
            || catalog.scope != self.scope
            || catalog.range != self.range
            || catalog.row_count != self.row_count
            || decoded_chunk_count != self.chunk_count
            || catalog.checkpoint_root != self.checkpoint_root
        {
            return Err(Error::DescriptorBodyMismatch);
        }
        Ok(catalog)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockedShieldsDescriptor {
    pub artifact: ArtifactDescriptor,
    pub format_version: u16,
    pub scope: Scope,
    pub row_count: u64,
    pub encoding: ArtifactEncoding,
    pub compression: Compression,
}

impl BlockedShieldsDescriptor {
    pub fn validate(&self) -> Result<(), Error> {
        require_format_version(self.format_version)?;
        if self.encoding != ArtifactEncoding::CanonicalJson {
            return Err(Error::UnsupportedEncoding);
        }
        if self.compression != Compression::Identity {
            return Err(Error::UnsupportedCompression);
        }
        require_blocked_shields_artifact_size(self.artifact.byte_size)?;
        Ok(())
    }

    pub fn verify_bytes(&self, bytes: &[u8]) -> Result<BlockedShieldsArtifact, Error> {
        self.validate()?;
        self.artifact.verify_bytes(bytes)?;
        let artifact = BlockedShieldsArtifact::read(bytes)?;
        let row_count = usize_to_u64(artifact.blocked_shields.len())?;
        if artifact.format_version != self.format_version
            || artifact.scope != self.scope
            || row_count != self.row_count
        {
            return Err(Error::DescriptorBodyMismatch);
        }
        artifact.verify_signatures()?;
        Ok(artifact)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockedShieldsArtifact {
    pub format_version: u16,
    pub scope: Scope,
    pub blocked_shields: Vec<BlockedShieldArtifactRecord>,
}

impl BlockedShieldsArtifact {
    #[must_use]
    pub fn from_signed_records(scope: Scope, records: &[SignedBlockedShield]) -> Self {
        let mut blocked_shields = records
            .iter()
            .map(BlockedShieldArtifactRecord::from)
            .collect::<Vec<_>>();
        blocked_shields.sort_by(|left, right| {
            left.blinded_commitment
                .cmp(&right.blinded_commitment)
                .then_with(|| left.commitment_hash.cmp(&right.commitment_hash))
        });
        Self {
            format_version: FORMAT_VERSION,
            scope,
            blocked_shields,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate_order()?;
        let byte_size = canonical_json_size(self)?;
        require_blocked_shields_artifact_size(byte_size)?;
        serde_json::to_vec(self).map_err(Error::Json)
    }

    pub fn read(bytes: &[u8]) -> Result<Self, Error> {
        require_blocked_shields_artifact_size(usize_to_u64(bytes.len())?)?;
        let artifact: Self = serde_json::from_slice(bytes).map_err(Error::Json)?;
        artifact.validate_order()?;
        if artifact.to_bytes()? != bytes {
            return Err(Error::NonCanonicalBytes);
        }
        Ok(artifact)
    }

    pub fn into_signed_records(self) -> Vec<SignedBlockedShield> {
        self.blocked_shields
            .into_iter()
            .map(BlockedShieldArtifactRecord::into_signed_blocked_shield)
            .collect()
    }

    fn verify_signatures(&self) -> Result<(), Error> {
        for record in &self.blocked_shields {
            verify_blocked_shield(
                &SignedBlockedShield {
                    commitment_hash: record.commitment_hash.clone(),
                    blinded_commitment: record.blinded_commitment.clone(),
                    block_reason: record.block_reason.clone(),
                    signature: record.signature.clone(),
                },
                &self.scope.list_key.0,
            )?;
        }
        Ok(())
    }

    fn validate_order(&self) -> Result<(), Error> {
        require_format_version(self.format_version)?;
        for pair in self.blocked_shields.windows(2) {
            let left = (&pair[0].blinded_commitment, &pair[0].commitment_hash);
            let right = (&pair[1].blinded_commitment, &pair[1].commitment_hash);
            if left >= right {
                return Err(Error::NonCanonicalBytes);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEntry {
    pub scope: Scope,
    pub event_count: u64,
    pub current_tip_index: Option<u64>,
    pub current_root: Option<FixedBytes<32>>,
    pub checkpoint_catalog: CheckpointCatalogDescriptor,
    pub current_tail: Option<EventArtifactDescriptor>,
    pub retained_bridges: Vec<EventArtifactDescriptor>,
    pub blocked_shields: BlockedShieldsDescriptor,
}

impl ManifestEntry {
    pub fn validate(&self) -> Result<(), Error> {
        self.checkpoint_catalog.validate()?;
        self.blocked_shields.validate()?;
        require_scope(&self.scope, &self.checkpoint_catalog.scope)?;
        require_scope(&self.scope, &self.blocked_shields.scope)?;

        if self.retained_bridges.len() > MAX_RETAINED_BRIDGES {
            return Err(Error::TooManyRetainedBridges {
                count: self.retained_bridges.len(),
            });
        }

        if self.event_count == 0 {
            if self.current_tip_index.is_some()
                || self.current_root.is_some()
                || self.checkpoint_catalog.row_count != 0
                || self.checkpoint_catalog.range.is_some()
                || self.checkpoint_catalog.checkpoint_root.is_some()
                || self.current_tail.is_some()
                || !self.retained_bridges.is_empty()
            {
                return Err(Error::InvalidEmptyGraph);
            }
            return Ok(());
        }

        let expected_tip = self
            .event_count
            .checked_sub(1)
            .ok_or(Error::ArithmeticOverflow)?;
        if self.current_tip_index != Some(expected_tip) || self.current_root.is_none() {
            return Err(Error::InvalidNonemptyGraph);
        }
        if self.checkpoint_catalog.row_count > self.event_count {
            return Err(Error::CheckpointBeyondCurrentTip);
        }

        let checkpoint_count = self.checkpoint_catalog.row_count;
        let current_root = self.current_root.ok_or(Error::InvalidNonemptyGraph)?;
        match checkpoint_count {
            0 => {
                if self.checkpoint_catalog.range.is_some()
                    || self.checkpoint_catalog.checkpoint_root.is_some()
                    || !self.retained_bridges.is_empty()
                {
                    return Err(Error::InvalidEmptyCheckpoint);
                }
            }
            count => {
                let expected_end = count.checked_sub(1).ok_or(Error::ArithmeticOverflow)?;
                if self.checkpoint_catalog.range
                    != Some(EventRange {
                        start_index: 0,
                        end_index: expected_end,
                    })
                    || self.checkpoint_catalog.checkpoint_root.is_none()
                {
                    return Err(Error::InvalidCheckpointAggregate);
                }
                self.validate_bridge_chain()?;
            }
        }

        if checkpoint_count == self.event_count {
            if self.current_tail.is_some()
                || self.checkpoint_catalog.checkpoint_root != Some(current_root)
            {
                return Err(Error::InvalidCurrentTail);
            }
        } else {
            let tail = self
                .current_tail
                .as_ref()
                .ok_or(Error::InvalidCurrentTail)?;
            tail.validate()?;
            require_scope(&self.scope, &tail.scope)?;
            if tail.kind != EventArtifactKind::CurrentTail
                || tail.range.start_index != checkpoint_count
                || tail.range.end_index != expected_tip
                || tail.end_root != current_root
                || tail.start_root != self.checkpoint_catalog.checkpoint_root
            {
                return Err(Error::InvalidCurrentTail);
            }
        }
        Ok(())
    }

    fn validate_bridge_chain(&self) -> Result<(), Error> {
        if self.retained_bridges.is_empty() {
            return Ok(());
        }
        let checkpoint_count = self.checkpoint_catalog.row_count;
        let mut previous: Option<&EventArtifactDescriptor> = None;
        for bridge in &self.retained_bridges {
            bridge.validate()?;
            require_scope(&self.scope, &bridge.scope)?;
            if bridge.kind != EventArtifactKind::Bridge
                || bridge.range.end_index >= checkpoint_count
            {
                return Err(Error::InvalidBridgeChain);
            }
            if let Some(prior) = previous {
                require_contiguous(prior, bridge)?;
            }
            previous = Some(bridge);
        }
        let last = previous.ok_or(Error::InvalidBridgeChain)?;
        let expected_end = checkpoint_count
            .checked_sub(1)
            .ok_or(Error::ArithmeticOverflow)?;
        if last.range.end_index != expected_end
            || Some(last.end_root) != self.checkpoint_catalog.checkpoint_root
        {
            return Err(Error::InvalidBridgeChain);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
        issued_at_ms: u64,
        sequence: u64,
        publisher_pubkey: FixedBytes<32>,
        entries: Vec<ManifestEntry>,
    ) -> Self {
        Self {
            format_version: FORMAT_VERSION,
            issued_at_ms,
            sequence,
            publisher_pubkey,
            entries,
            publisher_signature: None,
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
        require_format_version(self.format_version)?;
        let mut scopes = BTreeSet::new();
        for entry in &self.entries {
            if !scopes.insert(entry.scope.clone()) {
                return Err(Error::DuplicateScope);
            }
            entry.validate()?;
        }
        Ok(())
    }

    pub fn canonical_body_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        self.canonical_body_bytes_envelope()
    }

    fn canonical_body_bytes_envelope(&self) -> Result<Vec<u8>, Error> {
        require_format_version(self.format_version)?;
        let mut entries = self.entries.clone();
        entries.sort_by(|left, right| left.scope.cmp(&right.scope));
        let bytes = serde_json::to_vec(&ManifestBody {
            format_version: self.format_version,
            issued_at_ms: self.issued_at_ms,
            sequence: self.sequence,
            publisher_pubkey: self.publisher_pubkey,
            entries,
        })
        .map_err(Error::Json)?;
        require_manifest_size(usize_to_u64(bytes.len())?)?;
        Ok(bytes)
    }

    pub fn signing_message(&self) -> Result<Vec<u8>, Error> {
        let body = self.canonical_body_bytes()?;
        signing_message_from_body(&body)
    }

    fn signing_message_envelope(&self) -> Result<Vec<u8>, Error> {
        signing_message_from_body(&self.canonical_body_bytes_envelope()?)
    }

    pub fn publication_id_envelope(&self) -> Result<PublicationId, Error> {
        let body = self.canonical_body_bytes_envelope()?;
        let manifest_body_hash: [u8; 32] = Sha256Digest::digest(body).into();
        Ok(PublicationId {
            publisher_pubkey: self.publisher_pubkey,
            sequence: self.sequence,
            manifest_body_hash: FixedBytes::from(manifest_body_hash),
        })
    }

    pub fn verify_trusted_signature_envelope(
        &self,
        trusted_publisher_pubkey: &[u8; 32],
    ) -> Result<(), Error> {
        if self.publisher_pubkey.as_slice() != trusted_publisher_pubkey.as_slice() {
            return Err(Error::PublisherKeyMismatch {
                expected: hex::encode_prefixed(trusted_publisher_pubkey),
                actual: hex::encode_prefixed(self.publisher_pubkey.as_slice()),
            });
        }
        let signature = self
            .publisher_signature
            .as_ref()
            .ok_or(Error::MissingPublisherSignature)?;
        let verifying_key =
            VerifyingKey::from_bytes(trusted_publisher_pubkey).map_err(Error::PublicKey)?;
        verifying_key
            .verify(
                &self.signing_message_envelope()?,
                &Signature::from_bytes(&signature.0),
            )
            .map_err(Error::Signature)
    }

    pub fn read_envelope(bytes: &[u8]) -> Result<Self, Error> {
        let byte_size = usize_to_u64(bytes.len())?;
        require_manifest_size(byte_size)?;
        let manifest: Self = serde_json::from_slice(bytes).map_err(Error::Json)?;
        if manifest.to_bytes_envelope()? != bytes {
            return Err(Error::NonCanonicalBytes);
        }
        Ok(manifest)
    }

    fn to_bytes_envelope(&self) -> Result<Vec<u8>, Error> {
        require_format_version(self.format_version)?;
        let mut entries = self.entries.clone();
        entries.sort_by(|left, right| left.scope.cmp(&right.scope));
        let bytes = serde_json::to_vec(&ManifestWire {
            format_version: self.format_version,
            issued_at_ms: self.issued_at_ms,
            sequence: self.sequence,
            publisher_pubkey: self.publisher_pubkey,
            entries,
            publisher_signature: self.publisher_signature,
        })
        .map_err(Error::Json)?;
        require_manifest_size(usize_to_u64(bytes.len())?)?;
        Ok(bytes)
    }

    pub fn publication_id(&self) -> Result<PublicationId, Error> {
        self.validate()?;
        self.publication_id_envelope()
    }

    pub fn sign_manifest(&mut self, signing_key: &SigningKey) -> Result<(), Error> {
        self.publisher_pubkey = FixedBytes::from(signing_key.verifying_key().to_bytes());
        let signature = signing_key.sign(&self.signing_message()?).to_bytes();
        self.publisher_signature = Some(FixedBytes::from(signature));
        drop(self.to_bytes()?);
        Ok(())
    }

    pub fn verify_signature(&self) -> Result<(), Error> {
        self.verify_signature_with_key(&self.publisher_pubkey.0)
    }

    pub fn verify_trusted_signature(
        &self,
        trusted_publisher_pubkey: &[u8; 32],
    ) -> Result<(), Error> {
        self.validate()?;
        self.verify_trusted_signature_envelope(trusted_publisher_pubkey)
    }

    fn verify_signature_with_key(&self, pubkey: &[u8; 32]) -> Result<(), Error> {
        self.validate()?;
        self.verify_trusted_signature_envelope(pubkey)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        self.to_bytes_envelope()
    }

    pub fn read(bytes: &[u8]) -> Result<Self, Error> {
        let manifest = Self::read_envelope(bytes)?;
        manifest.validate()?;
        Ok(manifest)
    }
}

fn signing_message_from_body(body: &[u8]) -> Result<Vec<u8>, Error> {
    let capacity = MANIFEST_SIGNATURE_DOMAIN
        .len()
        .checked_add(body.len())
        .ok_or(Error::ArithmeticOverflow)?;
    let mut message = Vec::with_capacity(capacity);
    message.extend_from_slice(MANIFEST_SIGNATURE_DOMAIN);
    message.extend_from_slice(body);
    Ok(message)
}

#[derive(Serialize)]
struct ManifestBody {
    format_version: u16,
    issued_at_ms: u64,
    sequence: u64,
    publisher_pubkey: FixedBytes<32>,
    entries: Vec<ManifestEntry>,
}

#[derive(Serialize)]
struct ManifestWire {
    format_version: u16,
    issued_at_ms: u64,
    sequence: u64,
    publisher_pubkey: FixedBytes<32>,
    entries: Vec<ManifestEntry>,
    publisher_signature: Option<FixedBytes<64>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointCatalog {
    pub format_version: u16,
    pub scope: Scope,
    pub range: Option<EventRange>,
    pub row_count: u64,
    pub checkpoint_root: Option<FixedBytes<32>>,
    pub chunks: Vec<EventArtifactDescriptor>,
}

impl CheckpointCatalog {
    pub fn new(scope: Scope, chunks: Vec<EventArtifactDescriptor>) -> Result<Self, Error> {
        let row_count = checked_sum(chunks.iter().map(|chunk| chunk.row_count))?;
        let range = chunks.last().map(|last| EventRange {
            start_index: 0,
            end_index: last.range.end_index,
        });
        let checkpoint_root = chunks.last().map(|chunk| chunk.end_root);
        let catalog = Self {
            format_version: FORMAT_VERSION,
            scope,
            range,
            row_count,
            checkpoint_root,
            chunks,
        };
        catalog.validate()?;
        Ok(catalog)
    }

    pub fn validate(&self) -> Result<(), Error> {
        require_format_version(self.format_version)?;
        validate_catalog_limits(0, 0, usize_to_u64(self.chunks.len())?)?;
        if self.chunks.is_empty() {
            if self.row_count != 0 || self.range.is_some() || self.checkpoint_root.is_some() {
                return Err(Error::InvalidCheckpointAggregate);
            }
            return Ok(());
        }
        if self.row_count == 0 {
            return Err(Error::InvalidCheckpointAggregate);
        }

        let mut total_rows = 0_u64;
        let mut previous: Option<&EventArtifactDescriptor> = None;
        for (index, chunk) in self.chunks.iter().enumerate() {
            chunk.validate()?;
            require_scope(&self.scope, &chunk.scope)?;
            if chunk.kind != EventArtifactKind::Checkpoint {
                return Err(Error::InvalidCheckpointChunk);
            }
            if index == 0 && chunk.range.start_index != 0 {
                return Err(Error::RangeGapOrOverlap);
            }
            if let Some(prior) = previous {
                require_contiguous(prior, chunk)?;
            }
            if index + 1 != self.chunks.len() && chunk.row_count != CHECKPOINT_EVENT_SPAN {
                return Err(Error::PartialCheckpointNotFinal);
            }
            total_rows = total_rows
                .checked_add(chunk.row_count)
                .ok_or(Error::ArithmeticOverflow)?;
            previous = Some(chunk);
        }
        let last = previous.ok_or(Error::InvalidCheckpointAggregate)?;
        validate_aggregate(self.range, self.row_count, self.checkpoint_root)?;
        if total_rows != self.row_count
            || self.range
                != Some(EventRange {
                    start_index: 0,
                    end_index: last.range.end_index,
                })
            || self.checkpoint_root != Some(last.end_root)
        {
            return Err(Error::InvalidCheckpointAggregate);
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(Error::Json)?;
        let byte_size = usize_to_u64(bytes.len())?;
        validate_catalog_limits(byte_size, byte_size, usize_to_u64(self.chunks.len())?)?;
        Ok(bytes)
    }

    pub fn read(bytes: &[u8]) -> Result<Self, Error> {
        let byte_size = usize_to_u64(bytes.len())?;
        validate_catalog_limits(byte_size, byte_size, 0)?;
        let catalog: Self = serde_json::from_slice(bytes).map_err(Error::Json)?;
        catalog.validate()?;
        if catalog.to_bytes()? != bytes {
            return Err(Error::NonCanonicalBytes);
        }
        Ok(catalog)
    }

    pub fn descriptor(&self, cid: impl Into<String>) -> Result<CheckpointCatalogDescriptor, Error> {
        let bytes = self.to_bytes()?;
        Ok(CheckpointCatalogDescriptor {
            artifact: ArtifactDescriptor::from_bytes(cid, &bytes),
            format_version: self.format_version,
            scope: self.scope.clone(),
            range: self.range,
            row_count: self.row_count,
            chunk_count: usize_to_u64(self.chunks.len())?,
            encoding: ArtifactEncoding::CanonicalJson,
            compression: Compression::Identity,
            checkpoint_root: self.checkpoint_root,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventArtifact {
    pub format_version: u16,
    pub scope: Scope,
    pub kind: EventArtifactKind,
    pub range: EventRange,
    pub encoding: ArtifactEncoding,
    pub compression: Compression,
    pub start_root: Option<FixedBytes<32>>,
    pub end_root: FixedBytes<32>,
    pub events: Vec<SnapshotEvent>,
}

impl EventArtifact {
    pub fn new(
        scope: Scope,
        kind: EventArtifactKind,
        start_root: Option<FixedBytes<32>>,
        end_root: FixedBytes<32>,
        events: Vec<SnapshotEvent>,
    ) -> Result<Self, Error> {
        let first = events.first().ok_or(Error::EmptyEventArtifact)?;
        let last = events.last().ok_or(Error::EmptyEventArtifact)?;
        let artifact = Self {
            format_version: FORMAT_VERSION,
            scope,
            kind,
            range: EventRange::new(first.event_index, last.event_index)?,
            encoding: ArtifactEncoding::PoiEventBinary,
            compression: Compression::Identity,
            start_root,
            end_root,
            events,
        };
        artifact.validate()?;
        Ok(artifact)
    }

    pub fn validate(&self) -> Result<(), Error> {
        require_format_version(self.format_version)?;
        if self.encoding != ArtifactEncoding::PoiEventBinary {
            return Err(Error::UnsupportedEncoding);
        }
        if self.compression != Compression::Identity {
            return Err(Error::UnsupportedCompression);
        }
        let row_count = u64::try_from(self.events.len()).map_err(|_| Error::ArithmeticOverflow)?;
        if row_count == 0 || self.range.row_count()? != row_count {
            return Err(Error::RowCountMismatch {
                expected: self.range.row_count()?,
                actual: row_count,
            });
        }
        require_start_root(self.range.start_index, self.start_root)?;
        if self.kind == EventArtifactKind::Checkpoint {
            validate_checkpoint_range(self.range, row_count)?;
        }
        for (offset, event) in self.events.iter().enumerate() {
            let offset = usize_to_u64(offset)?;
            let expected = self
                .range
                .start_index
                .checked_add(offset)
                .ok_or(Error::ArithmeticOverflow)?;
            if event.event_index != expected {
                return Err(Error::NonContiguousEvent {
                    expected,
                    actual: event.event_index,
                });
            }
        }
        Ok(())
    }

    pub fn verify_signatures(&self) -> Result<(), Error> {
        for event in &self.events {
            verify_poi_event(
                &SignedPoiEvent {
                    index: event.event_index,
                    blinded_commitment: FixedBytes::from(event.blinded_commitment),
                    signature: hex::encode_prefixed(event.signature),
                    event_type: event.event_type,
                },
                &self.scope.list_key.0,
            )
            .map_err(|source| Error::EventVerify {
                event_index: event.event_index,
                source,
            })?;
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let txid_version = self.scope.txid_version.as_bytes();
        let txid_len = u16::try_from(txid_version.len()).map_err(|_| Error::TxidVersionTooLong)?;
        let header_len = EVENT_HEADER_FIXED_BYTES
            .checked_add(txid_version.len())
            .ok_or(Error::ArithmeticOverflow)?;
        let header_len_u16 = u16::try_from(header_len).map_err(|_| Error::TxidVersionTooLong)?;
        let records_len = self
            .events
            .len()
            .checked_mul(EVENT_RECORD_BYTES)
            .ok_or(Error::ArithmeticOverflow)?;
        let total_len = header_len
            .checked_add(records_len)
            .ok_or(Error::ArithmeticOverflow)?;
        require_event_artifact_size(usize_to_u64(total_len)?)?;

        let mut bytes = vec![0_u8; header_len];
        bytes[0..8].copy_from_slice(EVENT_MAGIC);
        bytes[8..10].copy_from_slice(&self.format_version.to_le_bytes());
        bytes[10..12].copy_from_slice(&header_len_u16.to_le_bytes());
        bytes[12] = self.scope.chain_type;
        bytes[13] = event_kind_discriminant(self.kind);
        bytes[14] = encoding_discriminant(self.encoding);
        bytes[15] = compression_discriminant(self.compression);
        bytes[16..48].copy_from_slice(self.scope.list_key.as_slice());
        bytes[48..56].copy_from_slice(&self.scope.chain_id.to_le_bytes());
        bytes[56..58].copy_from_slice(&txid_len.to_le_bytes());
        bytes[58..66].copy_from_slice(&self.range.start_index.to_le_bytes());
        bytes[66..74].copy_from_slice(&self.range.end_index.to_le_bytes());
        bytes[74..82].copy_from_slice(&usize_to_u64(self.events.len())?.to_le_bytes());
        if let Some(start_root) = self.start_root {
            bytes[82] = 1;
            bytes[83..115].copy_from_slice(start_root.as_slice());
        }
        bytes[115..147].copy_from_slice(self.end_root.as_slice());
        bytes[147..header_len].copy_from_slice(txid_version);

        for event in &self.events {
            bytes.extend_from_slice(&event.blinded_commitment);
            bytes.extend_from_slice(&event.signature);
            bytes.push(event_type_discriminant(event.event_type));
        }
        Ok(bytes)
    }

    pub fn read(bytes: &[u8]) -> Result<Self, Error> {
        let actual_byte_size = usize_to_u64(bytes.len())?;
        require_event_artifact_size(actual_byte_size)?;
        ensure_len(bytes, EVENT_HEADER_FIXED_BYTES)?;
        if &bytes[0..8] != EVENT_MAGIC {
            return Err(Error::InvalidEventMagic);
        }
        let format_version = read_u16(bytes, 8)?;
        require_format_version(format_version)?;
        let header_len = usize::from(read_u16(bytes, 10)?);
        ensure_len(bytes, header_len)?;
        let txid_len = usize::from(read_u16(bytes, 56)?);
        let expected_header_len = EVENT_HEADER_FIXED_BYTES
            .checked_add(txid_len)
            .ok_or(Error::ArithmeticOverflow)?;
        if header_len != expected_header_len {
            return Err(Error::InvalidEventHeaderLength);
        }
        let kind = event_kind_from_discriminant(bytes[13])?;
        let encoding = encoding_from_discriminant(bytes[14])?;
        let compression = compression_from_discriminant(bytes[15])?;
        let start_index = read_u64(bytes, 58)?;
        let end_index = read_u64(bytes, 66)?;
        let row_count = read_u64(bytes, 74)?;
        let start_root = match bytes[82] {
            0 if bytes[83..115].iter().all(|byte| *byte == 0) => None,
            1 => Some(FixedBytes::from(read_bytes::<32>(bytes, 83)?)),
            _ => return Err(Error::InvalidOptionalRoot),
        };
        let records_len = row_count
            .checked_mul(EVENT_RECORD_BYTES_U64)
            .ok_or(Error::ArithmeticOverflow)?;
        let expected_len = u64::try_from(header_len)
            .map_err(|_| Error::ArithmeticOverflow)?
            .checked_add(records_len)
            .ok_or(Error::ArithmeticOverflow)?;
        if expected_len != actual_byte_size {
            return Err(Error::EventByteLengthMismatch {
                expected: expected_len,
                actual: actual_byte_size,
            });
        }
        let event_capacity = usize::try_from(row_count).map_err(|_| Error::ArithmeticOverflow)?;
        let mut events = Vec::with_capacity(event_capacity);
        for offset in 0..row_count {
            let offset_usize = usize::try_from(offset).map_err(|_| Error::ArithmeticOverflow)?;
            let record_offset = header_len
                .checked_add(
                    offset_usize
                        .checked_mul(EVENT_RECORD_BYTES)
                        .ok_or(Error::ArithmeticOverflow)?,
                )
                .ok_or(Error::ArithmeticOverflow)?;
            events.push(SnapshotEvent {
                event_index: start_index
                    .checked_add(offset)
                    .ok_or(Error::ArithmeticOverflow)?,
                blinded_commitment: read_bytes(bytes, record_offset)?,
                signature: read_bytes(bytes, record_offset + 32)?,
                event_type: event_type_from_discriminant(bytes[record_offset + 96])?,
            });
        }
        let txid_version = std::str::from_utf8(&bytes[147..header_len])
            .map_err(Error::TxidVersionUtf8)?
            .to_string();
        let artifact = Self {
            format_version,
            scope: Scope {
                list_key: FixedBytes::from(read_bytes(bytes, 16)?),
                chain_type: bytes[12],
                chain_id: read_u64(bytes, 48)?,
                txid_version,
            },
            kind,
            range: EventRange::new(start_index, end_index)?,
            encoding,
            compression,
            start_root,
            end_root: FixedBytes::from(read_bytes(bytes, 115)?),
            events,
        };
        artifact.validate()?;
        Ok(artifact)
    }

    pub fn descriptor(&self, cid: impl Into<String>) -> Result<EventArtifactDescriptor, Error> {
        let bytes = self.to_bytes()?;
        Ok(EventArtifactDescriptor {
            artifact: ArtifactDescriptor::from_bytes(cid, &bytes),
            format_version: self.format_version,
            scope: self.scope.clone(),
            kind: self.kind,
            range: self.range,
            row_count: usize_to_u64(self.events.len())?,
            encoding: self.encoding,
            compression: self.compression,
            start_root: self.start_root,
            end_root: self.end_root,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetrievalLimits {
    pub response_bytes: u64,
    pub car_block_count: u64,
    pub reconstructed_bytes: u64,
    pub decoded_bytes: u64,
    pub record_count: u64,
}

impl RetrievalLimits {
    pub fn for_event(descriptor: &EventArtifactDescriptor) -> Result<Self, Error> {
        descriptor.validate()?;
        Ok(Self {
            response_bytes: checked_car_response_limit(descriptor.artifact.byte_size)?,
            car_block_count: ARTIFACT_CAR_MAX_BLOCKS,
            reconstructed_bytes: descriptor.artifact.byte_size,
            decoded_bytes: descriptor.artifact.byte_size,
            record_count: descriptor.row_count,
        })
    }

    pub fn for_catalog(descriptor: &CheckpointCatalogDescriptor) -> Result<Self, Error> {
        descriptor.validate()?;
        Ok(Self {
            response_bytes: checked_car_response_limit(descriptor.artifact.byte_size)?,
            car_block_count: ARTIFACT_CAR_MAX_BLOCKS,
            reconstructed_bytes: descriptor.artifact.byte_size,
            decoded_bytes: descriptor.artifact.byte_size,
            record_count: descriptor.chunk_count,
        })
    }

    pub fn checked_usize(self) -> Result<RetrievalLimitsUsize, Error> {
        Ok(RetrievalLimitsUsize {
            response_bytes: usize::try_from(self.response_bytes)
                .map_err(|_| Error::ArithmeticOverflow)?,
            car_block_count: usize::try_from(self.car_block_count)
                .map_err(|_| Error::ArithmeticOverflow)?,
            reconstructed_bytes: usize::try_from(self.reconstructed_bytes)
                .map_err(|_| Error::ArithmeticOverflow)?,
            decoded_bytes: usize::try_from(self.decoded_bytes)
                .map_err(|_| Error::ArithmeticOverflow)?,
            record_count: usize::try_from(self.record_count)
                .map_err(|_| Error::ArithmeticOverflow)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetrievalLimitsUsize {
    pub response_bytes: usize,
    pub car_block_count: usize,
    pub reconstructed_bytes: usize,
    pub decoded_bytes: usize,
    pub record_count: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PlanLimits {
    pub descriptor_count: u64,
    pub encoded_bytes: u64,
    pub response_bytes: u64,
    pub reconstructed_bytes: u64,
    pub decoded_bytes: u64,
    pub record_count: u64,
    pub car_block_count: u64,
}

pub fn checked_event_plan_limits<'a>(
    descriptors: impl IntoIterator<Item = &'a EventArtifactDescriptor>,
) -> Result<PlanLimits, Error> {
    let mut total = PlanLimits::default();
    for descriptor in descriptors {
        let limits = RetrievalLimits::for_event(descriptor)?;
        total.descriptor_count = checked_add(total.descriptor_count, 1)?;
        total.encoded_bytes = checked_add(total.encoded_bytes, descriptor.artifact.byte_size)?;
        total.response_bytes = checked_add(total.response_bytes, limits.response_bytes)?;
        total.reconstructed_bytes =
            checked_add(total.reconstructed_bytes, limits.reconstructed_bytes)?;
        total.decoded_bytes = checked_add(total.decoded_bytes, limits.decoded_bytes)?;
        total.record_count = checked_add(total.record_count, limits.record_count)?;
        total.car_block_count = checked_add(total.car_block_count, limits.car_block_count)?;
    }
    Ok(total)
}

pub const fn validate_catalog_limits(
    encoded_bytes: u64,
    decoded_bytes: u64,
    descriptor_count: u64,
) -> Result<(), Error> {
    if descriptor_count > CATALOG_MAX_DESCRIPTORS {
        return Err(Error::CatalogDescriptorLimitExceeded { descriptor_count });
    }
    if encoded_bytes > CATALOG_MAX_BYTES || decoded_bytes > CATALOG_MAX_BYTES {
        return Err(Error::CatalogByteLimitExceeded {
            encoded_bytes,
            decoded_bytes,
        });
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("POI v4 JSON encoding failed")]
    Json(#[source] serde_json::Error),
    #[error("POI v4 artifact descriptor verification failed")]
    Artifact(#[from] ManifestError),
    #[error("POI v4 list signature verification failed")]
    Verify(#[from] VerifyError),
    #[error("POI v4 event signature verification failed at event index {event_index}")]
    EventVerify {
        event_index: u64,
        #[source]
        source: VerifyError,
    },
    #[error("unsupported POI v4 format version {version}")]
    WrongFormat { version: u16 },
    #[error("duplicate exact POI v4 scope")]
    DuplicateScope,
    #[error("POI v4 scope mismatch")]
    ScopeMismatch,
    #[error("unsupported POI v4 encoding")]
    UnsupportedEncoding,
    #[error("unsupported POI v4 compression")]
    UnsupportedCompression,
    #[error("invalid event range {start_index}..={end_index}")]
    InvalidRange { start_index: u64, end_index: u64 },
    #[error("row count mismatch: expected {expected}, got {actual}")]
    RowCountMismatch { expected: u64, actual: u64 },
    #[error("checked POI v4 arithmetic overflow")]
    ArithmeticOverflow,
    #[error("event artifact byte size {byte_size} exceeds the 4 MiB limit")]
    EventArtifactByteLimitExceeded { byte_size: u64 },
    #[error("blocked-shields artifact byte size {byte_size} exceeds the 4 MiB limit")]
    BlockedShieldsArtifactByteLimitExceeded { byte_size: u64 },
    #[error("event descriptor byte size mismatch: expected {expected}, got {actual}")]
    EventDescriptorByteSizeMismatch { expected: u64, actual: u64 },
    #[error("catalog descriptor count {descriptor_count} exceeds 4,096")]
    CatalogDescriptorLimitExceeded { descriptor_count: u64 },
    #[error("checkpoint chunk count mismatch: expected {expected}, got {actual}")]
    CheckpointChunkCountMismatch { expected: u64, actual: u64 },
    #[error("catalog exceeds the 2 MiB limit: encoded {encoded_bytes}, decoded {decoded_bytes}")]
    CatalogByteLimitExceeded {
        encoded_bytes: u64,
        decoded_bytes: u64,
    },
    #[error("POI v4 manifest byte size {byte_size} exceeds the 2 MiB limit")]
    ManifestByteLimitExceeded { byte_size: u64 },
    #[error("invalid explicit zero-event graph")]
    InvalidEmptyGraph,
    #[error("invalid nonempty POI v4 graph")]
    InvalidNonemptyGraph,
    #[error("checkpoint event count exceeds current event count")]
    CheckpointBeyondCurrentTip,
    #[error("invalid empty checkpoint state")]
    InvalidEmptyCheckpoint,
    #[error("invalid checkpoint aggregate metadata")]
    InvalidCheckpointAggregate,
    #[error("invalid current-tail descriptor")]
    InvalidCurrentTail,
    #[error("invalid retained bridge chain")]
    InvalidBridgeChain,
    #[error("too many retained bridges: {count}")]
    TooManyRetainedBridges { count: usize },
    #[error("range gap, overlap, or root discontinuity")]
    RangeGapOrOverlap,
    #[error("invalid checkpoint chunk range")]
    InvalidCheckpointChunk,
    #[error("only the final checkpoint chunk may be partial")]
    PartialCheckpointNotFinal,
    #[error("descriptor metadata does not match the canonical artifact body")]
    DescriptorBodyMismatch,
    #[error("noncanonical POI v4 bytes")]
    NonCanonicalBytes,
    #[error("POI v4 manifest has no publisher signature")]
    MissingPublisherSignature,
    #[error("POI v4 publisher public key mismatch: expected {expected}, got {actual}")]
    PublisherKeyMismatch { expected: String, actual: String },
    #[error("invalid POI v4 publisher public key")]
    PublicKey(#[source] ed25519_dalek::SignatureError),
    #[error("invalid POI v4 publisher signature")]
    Signature(#[source] ed25519_dalek::SignatureError),
    #[error("event artifact must contain at least one event")]
    EmptyEventArtifact,
    #[error("event artifact TXID version is too long")]
    TxidVersionTooLong,
    #[error("event artifact TXID version is not UTF-8")]
    TxidVersionUtf8(#[source] std::str::Utf8Error),
    #[error("invalid POI v4 event artifact magic")]
    InvalidEventMagic,
    #[error("invalid POI v4 event header length")]
    InvalidEventHeaderLength,
    #[error("invalid optional start-root encoding")]
    InvalidOptionalRoot,
    #[error("unsupported event artifact kind")]
    UnsupportedEventKind,
    #[error("unsupported event type")]
    UnsupportedEventType,
    #[error("buffer too short: need {needed} bytes, got {actual}")]
    BufferTooShort { needed: usize, actual: usize },
    #[error("event byte length mismatch: expected {expected}, got {actual}")]
    EventByteLengthMismatch { expected: u64, actual: u64 },
    #[error("event index is not contiguous: expected {expected}, got {actual}")]
    NonContiguousEvent { expected: u64, actual: u64 },
    #[error("event range start-root option is inconsistent with its start index")]
    InvalidStartRoot,
}

const fn require_format_version(version: u16) -> Result<(), Error> {
    if version != FORMAT_VERSION {
        return Err(Error::WrongFormat { version });
    }
    Ok(())
}

fn require_scope(expected: &Scope, actual: &Scope) -> Result<(), Error> {
    if expected != actual {
        return Err(Error::ScopeMismatch);
    }
    Ok(())
}

const fn require_start_root(
    start_index: u64,
    start_root: Option<FixedBytes<32>>,
) -> Result<(), Error> {
    if (start_index == 0) != start_root.is_none() {
        return Err(Error::InvalidStartRoot);
    }
    Ok(())
}

fn validate_aggregate(
    range: Option<EventRange>,
    row_count: u64,
    root: Option<FixedBytes<32>>,
) -> Result<(), Error> {
    if row_count == 0 {
        if range.is_some() || root.is_some() {
            return Err(Error::InvalidCheckpointAggregate);
        }
        return Ok(());
    }
    let aggregate = range.ok_or(Error::InvalidCheckpointAggregate)?;
    if aggregate.start_index != 0 || aggregate.row_count()? != row_count || root.is_none() {
        return Err(Error::InvalidCheckpointAggregate);
    }
    Ok(())
}

fn expected_checkpoint_chunk_count(row_count: u64) -> Result<u64, Error> {
    if row_count == 0 {
        return Ok(0);
    }
    row_count
        .checked_sub(1)
        .and_then(|last_index| last_index.checked_div(CHECKPOINT_EVENT_SPAN))
        .and_then(|last_chunk_index| last_chunk_index.checked_add(1))
        .ok_or(Error::ArithmeticOverflow)
}

const fn validate_checkpoint_range(range: EventRange, row_count: u64) -> Result<(), Error> {
    if !range.start_index.is_multiple_of(CHECKPOINT_EVENT_SPAN) || row_count > CHECKPOINT_EVENT_SPAN
    {
        return Err(Error::InvalidCheckpointChunk);
    }
    Ok(())
}

fn require_contiguous(
    left: &EventArtifactDescriptor,
    right: &EventArtifactDescriptor,
) -> Result<(), Error> {
    let next = left
        .range
        .end_index
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow)?;
    if right.range.start_index != next || right.start_root != Some(left.end_root) {
        return Err(Error::RangeGapOrOverlap);
    }
    Ok(())
}

const fn require_event_artifact_size(byte_size: u64) -> Result<(), Error> {
    if byte_size > EVENT_ARTIFACT_MAX_BYTES {
        return Err(Error::EventArtifactByteLimitExceeded { byte_size });
    }
    Ok(())
}

const fn require_blocked_shields_artifact_size(byte_size: u64) -> Result<(), Error> {
    if byte_size > BLOCKED_SHIELDS_ARTIFACT_MAX_BYTES {
        return Err(Error::BlockedShieldsArtifactByteLimitExceeded { byte_size });
    }
    Ok(())
}

fn canonical_json_size(value: &impl Serialize) -> Result<u64, Error> {
    let mut writer = JsonSizeWriter::default();
    serde_json::to_writer(&mut writer, value).map_err(Error::Json)?;
    Ok(writer.byte_size)
}

#[derive(Default)]
struct JsonSizeWriter {
    byte_size: u64,
}

impl Write for JsonSizeWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let byte_size = u64::try_from(bytes.len())
            .map_err(|_| io::Error::other("canonical JSON size overflow"))?;
        self.byte_size = self
            .byte_size
            .checked_add(byte_size)
            .ok_or_else(|| io::Error::other("canonical JSON size overflow"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

const fn require_manifest_size(byte_size: u64) -> Result<(), Error> {
    if byte_size > MANIFEST_MAX_BYTES {
        return Err(Error::ManifestByteLimitExceeded { byte_size });
    }
    Ok(())
}

fn expected_event_artifact_size(scope: &Scope, row_count: u64) -> Result<u64, Error> {
    let txid_len =
        u64::try_from(scope.txid_version.len()).map_err(|_| Error::TxidVersionTooLong)?;
    let header_len = u64::try_from(EVENT_HEADER_FIXED_BYTES)
        .map_err(|_| Error::ArithmeticOverflow)?
        .checked_add(txid_len)
        .ok_or(Error::ArithmeticOverflow)?;
    if txid_len > u64::from(u16::MAX) || header_len > u64::from(u16::MAX) {
        return Err(Error::TxidVersionTooLong);
    }
    let records_len = row_count
        .checked_mul(EVENT_RECORD_BYTES_U64)
        .ok_or(Error::ArithmeticOverflow)?;
    let byte_size = header_len
        .checked_add(records_len)
        .ok_or(Error::ArithmeticOverflow)?;
    require_event_artifact_size(byte_size)?;
    Ok(byte_size)
}

fn checked_car_response_limit(reconstructed_bytes: u64) -> Result<u64, Error> {
    let overhead = (reconstructed_bytes / 8)
        .max(CAR_MIN_OVERHEAD_BYTES)
        .checked_add(CAR_FIXED_OVERHEAD_BYTES)
        .ok_or(Error::ArithmeticOverflow)?;
    reconstructed_bytes
        .checked_add(overhead)
        .ok_or(Error::ArithmeticOverflow)
}

fn checked_add(left: u64, right: u64) -> Result<u64, Error> {
    left.checked_add(right).ok_or(Error::ArithmeticOverflow)
}

fn usize_to_u64(value: usize) -> Result<u64, Error> {
    u64::try_from(value).map_err(|_| Error::ArithmeticOverflow)
}

fn checked_sum(values: impl IntoIterator<Item = u64>) -> Result<u64, Error> {
    values.into_iter().try_fold(0_u64, checked_add)
}

const fn event_kind_discriminant(kind: EventArtifactKind) -> u8 {
    match kind {
        EventArtifactKind::Checkpoint => 0,
        EventArtifactKind::CurrentTail => 1,
        EventArtifactKind::Bridge => 2,
    }
}

const fn event_kind_from_discriminant(value: u8) -> Result<EventArtifactKind, Error> {
    match value {
        0 => Ok(EventArtifactKind::Checkpoint),
        1 => Ok(EventArtifactKind::CurrentTail),
        2 => Ok(EventArtifactKind::Bridge),
        _ => Err(Error::UnsupportedEventKind),
    }
}

const fn encoding_discriminant(encoding: ArtifactEncoding) -> u8 {
    match encoding {
        ArtifactEncoding::CanonicalJson => 0,
        ArtifactEncoding::PoiEventBinary => 1,
    }
}

const fn encoding_from_discriminant(value: u8) -> Result<ArtifactEncoding, Error> {
    match value {
        0 => Ok(ArtifactEncoding::CanonicalJson),
        1 => Ok(ArtifactEncoding::PoiEventBinary),
        _ => Err(Error::UnsupportedEncoding),
    }
}

const fn compression_discriminant(compression: Compression) -> u8 {
    match compression {
        Compression::Identity => 0,
    }
}

const fn compression_from_discriminant(value: u8) -> Result<Compression, Error> {
    match value {
        0 => Ok(Compression::Identity),
        _ => Err(Error::UnsupportedCompression),
    }
}

const fn event_type_discriminant(event_type: PoiEventType) -> u8 {
    match event_type {
        PoiEventType::Shield => 0,
        PoiEventType::Transact => 1,
        PoiEventType::Unshield => 2,
        PoiEventType::LegacyTransact => 3,
    }
}

const fn event_type_from_discriminant(value: u8) -> Result<PoiEventType, Error> {
    match value {
        0 => Ok(PoiEventType::Shield),
        1 => Ok(PoiEventType::Transact),
        2 => Ok(PoiEventType::Unshield),
        3 => Ok(PoiEventType::LegacyTransact),
        _ => Err(Error::UnsupportedEventType),
    }
}

const fn ensure_len(bytes: &[u8], needed: usize) -> Result<(), Error> {
    if bytes.len() < needed {
        return Err(Error::BufferTooShort {
            needed,
            actual: bytes.len(),
        });
    }
    Ok(())
}

fn read_bytes<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], Error> {
    let needed = offset.checked_add(N).ok_or(Error::ArithmeticOverflow)?;
    ensure_len(bytes, needed)?;
    bytes[offset..needed]
        .try_into()
        .map_err(|_| Error::BufferTooShort {
            needed,
            actual: bytes.len(),
        })
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    Ok(u16::from_le_bytes(read_bytes(bytes, offset)?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, Error> {
    Ok(u64::from_le_bytes(read_bytes(bytes, offset)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, KeyInit, Mac};
    use multibase::Base;
    use sha2::Sha256;

    const GOLDEN_BODY_HASHES: [&str; 6] = [
        "30535cbb6ce23b841d21df5eed9efa1ef644c1cb24da46d40d63cab1dc90f59c",
        "487956c9329cd53153cb43fcfd70d2d5bbf85f3d540b208849c0a3be4eb0eec7",
        "93e6e21cf06524b7b1dad99f4d06bfbd3d01411e6ed0b987b56c8822aa4f62fc",
        "e0edb1cd85ab8b33fe5d43cc676d4b275c60736e4028240052e41bea1659485c",
        "78769462650f91068703148ba86411955aad42abce3fe88c5e58023edacbafbb",
        "503cd8d3715c34549fc0d3ecfa8bb098dbe7f44e2b71c35ed9e1e703bb3c3cdd",
    ];
    const IPNS_TEST_ROOT_SEED: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const IPNS_TEST_CHILD_PUBLIC_KEY: [u8; 32] = [
        0x56, 0xf6, 0xdf, 0x31, 0x02, 0xdf, 0x04, 0x67, 0xda, 0x6a, 0x5a, 0xdc, 0x7e, 0xf6, 0xff,
        0x57, 0x7f, 0xab, 0xf2, 0x94, 0x4f, 0xd1, 0xbd, 0x60, 0x6f, 0x6a, 0x47, 0x46, 0x4f, 0x22,
        0xab, 0xc9,
    ];
    const IPNS_TEST_PEER_ID: &str = "12D3KooWFfqZkgZyH41hEVExsTkwAEVk9bTmHdLTP99uD1uwWo52";
    const IPNS_TEST_NAME: &str = "k51qzi5uqu5dicmabkge4lkunc4bkd198u9xicp5espmw5zdzbafkez7hyh5ft";
    const MANIFEST_SIGNATURE_TEST_SEED: [u8; 32] = [7; 32];
    const GOLDEN_SIGNED_BODY_HASH: &str =
        "b69109db5c1b989d9ae3ade3a5b06ec9e3eefd379405a7a4e4d373f1bf2b3c48";
    const GOLDEN_SIGNATURE_HASH: &str =
        "e8427b380f033519b42a40cd0a37d11d7920a7c4bda42e78f674500b618e15de";

    #[test]
    fn v4_ipns_derivation_vector_binds_domains_and_public_identity() {
        assert_eq!(IPNS_KDF_SALT, b"railgun-indexer/ipns-key-derivation/v1");
        assert_eq!(IPNS_KDF_INFO, b"poi-artifact/chunked-manifest/v4");

        let mut extract = Hmac::<Sha256>::new_from_slice(IPNS_KDF_SALT)
            .expect("HMAC accepts an arbitrary salt length");
        extract.update(&IPNS_TEST_ROOT_SEED);
        let pseudorandom_key = extract.finalize().into_bytes();
        let mut expand = Hmac::<Sha256>::new_from_slice(&pseudorandom_key)
            .expect("SHA-256 pseudorandom key has a valid HMAC length");
        expand.update(IPNS_KDF_INFO);
        expand.update(&[1]);
        let mut child_seed: [u8; 32] = expand.finalize().into_bytes().into();
        let keypair = libp2p_identity::Keypair::ed25519_from_bytes(&mut child_seed)
            .expect("vector child seed is a valid ed25519 seed");
        child_seed.fill(0);
        let public_key = keypair
            .public()
            .try_into_ed25519()
            .expect("vector key is ed25519")
            .to_bytes();
        let peer_id = keypair.public().to_peer_id();
        let ipns_name = cid::Cid::new_v1(0x72, *peer_id.as_ref())
            .to_string_of_base(Base::Base36Lower)
            .expect("peer ID is a valid libp2p-key CID");

        assert_eq!(public_key, IPNS_TEST_CHILD_PUBLIC_KEY);
        assert_eq!(peer_id.to_base58(), IPNS_TEST_PEER_ID);
        assert_eq!(ipns_name, IPNS_TEST_NAME);
    }

    #[test]
    fn event_artifact_roundtrip_has_deterministic_timestamp_free_bytes() {
        let artifact = EventArtifact::new(
            scope(),
            EventArtifactKind::Checkpoint,
            None,
            root(1),
            vec![event(0, 1)],
        )
        .expect("event artifact");
        let bytes = artifact.to_bytes().expect("event bytes");
        let decoded = EventArtifact::read(&bytes).expect("decode event bytes");
        let descriptor = artifact.descriptor("bafyevent").expect("descriptor");

        assert_eq!(decoded, artifact);
        assert_eq!(
            descriptor.verify_bytes(&bytes).expect("verify bytes"),
            artifact
        );
        let mut wrong_size = descriptor;
        wrong_size.artifact.byte_size -= 1;
        assert!(matches!(
            wrong_size.validate(),
            Err(Error::EventDescriptorByteSizeMismatch { .. })
        ));
        assert_eq!(&bytes[0..8], EVENT_MAGIC);
        assert_eq!(
            bytes.len(),
            EVENT_HEADER_FIXED_BYTES + 17 + EVENT_RECORD_BYTES
        );
        assert!(!bytes.windows(9).any(|window| window == b"timestamp"));
    }

    #[test]
    fn event_semantic_verification_rejects_invalid_list_signature() {
        let signing_key = SigningKey::from_bytes(&[0x31; 32]);
        let scope = Scope::new(
            FixedBytes::from(signing_key.verifying_key().to_bytes()),
            0,
            1,
            "V2_PoseidonMerkle",
        );
        let artifact = EventArtifact::new(
            scope,
            EventArtifactKind::Checkpoint,
            None,
            root(2),
            vec![
                signed_event(&signing_key, 0, 0x32),
                signed_event(&signing_key, 1, 0x33),
            ],
        )
        .expect("event artifact");
        artifact.verify_signatures().expect("valid event signature");

        let mut invalid = artifact;
        invalid.events[1].event_type = PoiEventType::Transact;
        invalid.events[1].signature = [0_u8; 64];
        match invalid
            .verify_signatures()
            .expect_err("invalid event signature")
        {
            Error::EventVerify {
                event_index,
                source,
            } => {
                assert_eq!(event_index, 1);
                assert!(matches!(source, VerifyError::Signature(_)));
            }
            other => panic!("unexpected verification error: {other:?}"),
        }
    }

    #[test]
    fn event_semantic_verification_accepts_historical_unsigned_shield() {
        let signing_key = SigningKey::from_bytes(&[0x31; 32]);
        let scope = Scope::new(
            FixedBytes::from(signing_key.verifying_key().to_bytes()),
            0,
            1,
            "V2_PoseidonMerkle",
        );
        let mut event = signed_event(&signing_key, 0, 0x32);
        event.signature = [0; 64];
        let artifact = EventArtifact::new(
            scope,
            EventArtifactKind::Checkpoint,
            None,
            root(2),
            vec![event],
        )
        .expect("event artifact");

        artifact
            .verify_signatures()
            .expect("historical unsigned Shield event");
    }

    #[test]
    fn blocked_artifact_verification_binds_scope_count_and_signatures() {
        let signing_key = SigningKey::from_bytes(&[0x41; 32]);
        let scope = Scope::new(
            FixedBytes::from(signing_key.verifying_key().to_bytes()),
            0,
            1,
            "V2_PoseidonMerkle",
        );
        let record = signed_blocked_shield(&signing_key, 0x42);
        let artifact = BlockedShieldsArtifact::from_signed_records(
            scope.clone(),
            std::slice::from_ref(&record),
        );
        let bytes = artifact.to_bytes().expect("blocked bytes");
        let descriptor = BlockedShieldsDescriptor {
            artifact: ArtifactDescriptor::from_bytes("bafyblocked", &bytes),
            format_version: FORMAT_VERSION,
            scope: scope.clone(),
            row_count: 1,
            encoding: ArtifactEncoding::CanonicalJson,
            compression: Compression::Identity,
        };
        descriptor
            .verify_bytes(&bytes)
            .expect("valid blocked artifact");

        let mut wrong_count = descriptor.clone();
        wrong_count.row_count = 2;
        assert!(matches!(
            wrong_count.verify_bytes(&bytes),
            Err(Error::DescriptorBodyMismatch)
        ));
        let mut wrong_scope = descriptor.clone();
        wrong_scope.scope.txid_version.push_str("-other");
        assert!(matches!(
            wrong_scope.verify_bytes(&bytes),
            Err(Error::DescriptorBodyMismatch)
        ));

        let mut invalid_record = record;
        invalid_record.signature = "00".repeat(64);
        let invalid_artifact =
            BlockedShieldsArtifact::from_signed_records(scope, &[invalid_record]);
        let invalid_bytes = invalid_artifact.to_bytes().expect("invalid blocked bytes");
        let invalid_descriptor = BlockedShieldsDescriptor {
            artifact: ArtifactDescriptor::from_bytes("bafyinvalidblocked", &invalid_bytes),
            ..descriptor
        };
        assert!(matches!(
            invalid_descriptor.verify_bytes(&invalid_bytes),
            Err(Error::Verify(_))
        ));
    }

    #[test]
    fn blocked_artifact_byte_limit_is_shared_by_descriptor_writer_and_reader() {
        let mut descriptor = BlockedShieldsDescriptor {
            artifact: fake_artifact("bafyblocked", BLOCKED_SHIELDS_ARTIFACT_MAX_BYTES, 0x42),
            format_version: FORMAT_VERSION,
            scope: scope(),
            row_count: 0,
            encoding: ArtifactEncoding::CanonicalJson,
            compression: Compression::Identity,
        };
        descriptor
            .validate()
            .expect("exact blocked artifact byte limit");
        descriptor.artifact.byte_size += 1;
        assert!(matches!(
            descriptor.validate(),
            Err(Error::BlockedShieldsArtifactByteLimitExceeded { byte_size })
                if byte_size == BLOCKED_SHIELDS_ARTIFACT_MAX_BYTES + 1
        ));

        let oversized_bytes = vec![
            b' ';
            usize::try_from(BLOCKED_SHIELDS_ARTIFACT_MAX_BYTES + 1)
                .expect("blocked artifact limit fits usize")
        ];
        assert!(matches!(
            BlockedShieldsArtifact::read(&oversized_bytes),
            Err(Error::BlockedShieldsArtifactByteLimitExceeded { .. })
        ));

        let oversized_record = SignedBlockedShield {
            commitment_hash: "00".repeat(32),
            blinded_commitment: "11".repeat(32),
            signature: "22".repeat(64),
            block_reason: Some(
                "x".repeat(
                    usize::try_from(BLOCKED_SHIELDS_ARTIFACT_MAX_BYTES)
                        .expect("blocked artifact limit fits usize"),
                ),
            ),
        };
        let oversized_artifact =
            BlockedShieldsArtifact::from_signed_records(scope(), &[oversized_record]);
        assert!(matches!(
            oversized_artifact.to_bytes(),
            Err(Error::BlockedShieldsArtifactByteLimitExceeded { .. })
        ));
    }

    #[test]
    fn event_artifact_rejects_malformed_unsupported_and_oversized_bytes() {
        let artifact = EventArtifact::new(
            scope(),
            EventArtifactKind::Checkpoint,
            None,
            root(1),
            vec![event(0, 1)],
        )
        .expect("event artifact");
        let mut bytes = artifact.to_bytes().expect("event bytes");

        bytes.push(0);
        assert!(matches!(
            EventArtifact::read(&bytes),
            Err(Error::EventByteLengthMismatch { .. })
        ));
        bytes.pop();
        bytes[14] = u8::MAX;
        assert!(matches!(
            EventArtifact::read(&bytes),
            Err(Error::UnsupportedEncoding)
        ));
        bytes[14] = encoding_discriminant(ArtifactEncoding::PoiEventBinary);
        bytes[15] = u8::MAX;
        assert!(matches!(
            EventArtifact::read(&bytes),
            Err(Error::UnsupportedCompression)
        ));
        require_event_artifact_size(EVENT_ARTIFACT_MAX_BYTES).expect("exact event byte limit");
        assert!(matches!(
            EventArtifact::read(&vec![0; 4 * 1024 * 1024 + 1]),
            Err(Error::EventArtifactByteLimitExceeded { .. })
        ));
    }

    #[test]
    fn checkpoint_catalog_rejects_gap_overlap_root_mismatch_and_nonfinal_partial() {
        let first = chunk(0, CHECKPOINT_EVENT_SPAN, None, root(1), 1);
        let second = chunk(CHECKPOINT_EVENT_SPAN, 2, Some(root(1)), root(2), 2);
        CheckpointCatalog::new(scope(), vec![first.clone(), second.clone()])
            .expect("valid catalog");

        let gap = chunk(CHECKPOINT_EVENT_SPAN * 2, 2, Some(root(1)), root(2), 2);
        assert!(matches!(
            CheckpointCatalog::new(scope(), vec![first.clone(), gap]),
            Err(Error::RangeGapOrOverlap)
        ));

        let overlap = chunk(0, CHECKPOINT_EVENT_SPAN, None, root(2), 2);
        assert!(matches!(
            CheckpointCatalog::new(scope(), vec![first.clone(), overlap]),
            Err(Error::RangeGapOrOverlap)
        ));

        let mut wrong_root = second.clone();
        wrong_root.start_root = Some(root(9));
        assert!(matches!(
            CheckpointCatalog::new(scope(), vec![first.clone(), wrong_root]),
            Err(Error::RangeGapOrOverlap)
        ));

        let mut wrong_scope = second;
        wrong_scope.scope.chain_id += 1;
        assert!(matches!(
            CheckpointCatalog::new(scope(), vec![first, wrong_scope]),
            Err(Error::ScopeMismatch)
        ));

        let partial = chunk(0, 2, None, root(1), 1);
        let after_partial = chunk(2, 2, Some(root(1)), root(2), 2);
        assert!(matches!(
            CheckpointCatalog::new(scope(), vec![partial, after_partial]),
            Err(Error::PartialCheckpointNotFinal)
        ));
    }

    #[test]
    fn checkpoint_catalog_requires_empty_chunks_and_aggregate_together() {
        let nonempty_aggregate = CheckpointCatalog {
            format_version: FORMAT_VERSION,
            scope: scope(),
            range: Some(EventRange {
                start_index: 0,
                end_index: 1,
            }),
            row_count: 2,
            checkpoint_root: Some(root(1)),
            chunks: vec![],
        };
        assert!(matches!(
            nonempty_aggregate.validate(),
            Err(Error::InvalidCheckpointAggregate)
        ));

        let zero_aggregate_with_chunk = CheckpointCatalog {
            format_version: FORMAT_VERSION,
            scope: scope(),
            range: None,
            row_count: 0,
            checkpoint_root: None,
            chunks: vec![chunk(0, 2, None, root(1), 1)],
        };
        assert!(matches!(
            zero_aggregate_with_chunk.validate(),
            Err(Error::InvalidCheckpointAggregate)
        ));
    }

    #[test]
    fn checkpoint_catalog_descriptor_requires_exact_chunk_count() {
        let empty_catalog = CheckpointCatalog::new(scope(), vec![]).expect("empty catalog");
        let mut empty_descriptor = empty_catalog
            .descriptor("bafyemptycatalog")
            .expect("empty descriptor");
        empty_descriptor.chunk_count = 1;
        assert!(matches!(
            empty_descriptor.validate(),
            Err(Error::CheckpointChunkCountMismatch {
                expected: 0,
                actual: 1
            })
        ));

        let catalog = CheckpointCatalog::new(
            scope(),
            vec![
                chunk(0, CHECKPOINT_EVENT_SPAN, None, root(1), 1),
                chunk(CHECKPOINT_EVENT_SPAN, 2, Some(root(1)), root(2), 2),
            ],
        )
        .expect("two-chunk catalog");
        let mut descriptor = catalog.descriptor("bafycatalog").expect("descriptor");
        descriptor.chunk_count = 1;
        assert!(matches!(
            descriptor.validate(),
            Err(Error::CheckpointChunkCountMismatch {
                expected: 2,
                actual: 1
            })
        ));
    }

    #[test]
    fn catalog_decode_requires_canonical_bytes_and_exact_descriptor_binding() {
        let catalog =
            CheckpointCatalog::new(scope(), vec![chunk(0, 2, None, root(1), 1)]).expect("catalog");
        let bytes = catalog.to_bytes().expect("catalog bytes");
        let descriptor = catalog.descriptor("bafycatalog").expect("descriptor");
        assert_eq!(descriptor.verify_bytes(&bytes).expect("verify"), catalog);

        let mut whitespace = vec![b' '];
        whitespace.extend_from_slice(&bytes);
        assert!(matches!(
            CheckpointCatalog::read(&whitespace),
            Err(Error::NonCanonicalBytes)
        ));

        let mut mutated = descriptor;
        mutated.row_count += 1;
        assert!(matches!(
            mutated.verify_bytes(&bytes),
            Err(Error::InvalidCheckpointAggregate | Error::DescriptorBodyMismatch)
        ));

        let unsupported = String::from_utf8(bytes)
            .expect("JSON")
            .replace("\"poi_event_binary\"", "\"future_encoding\"");
        assert!(matches!(
            CheckpointCatalog::read(unsupported.as_bytes()),
            Err(Error::Json(_))
        ));
        let bytes = catalog.to_bytes().expect("catalog bytes");
        let unsupported = String::from_utf8(bytes).expect("JSON").replacen(
            "\"identity\"",
            "\"future_compression\"",
            1,
        );
        assert!(matches!(
            CheckpointCatalog::read(unsupported.as_bytes()),
            Err(Error::Json(_))
        ));
    }

    #[test]
    fn manifest_signature_is_domain_separated_and_descriptor_bound() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let mut manifest = publication_graph(GraphKind::Partial).0;
        manifest.sign_manifest(&signing_key).expect("sign");
        manifest.verify_signature().expect("verify");

        let mut wrong_domain = manifest.clone();
        wrong_domain.publisher_signature = Some(FixedBytes::from(
            signing_key
                .sign(&wrong_domain.canonical_body_bytes().expect("body"))
                .to_bytes(),
        ));
        assert!(matches!(
            wrong_domain.verify_signature(),
            Err(Error::Signature(_))
        ));

        let mut mutated = manifest;
        mutated.entries[0]
            .checkpoint_catalog
            .artifact
            .cid
            .push_str("-mutated");
        assert!(matches!(
            mutated.verify_signature(),
            Err(Error::Signature(_))
        ));
    }

    #[test]
    fn canonical_manifest_signature_matches_golden_vector() {
        let signing_key = SigningKey::from_bytes(&MANIFEST_SIGNATURE_TEST_SEED);
        let mut manifest = publication_graph(GraphKind::Partial).0;
        manifest.sign_manifest(&signing_key).expect("sign manifest");

        assert_eq!(MANIFEST_SIGNATURE_DOMAIN, b"railgun-poi-manifest-v4\0");
        let body = manifest.canonical_body_bytes().expect("canonical body");
        assert_eq!(
            hex::encode(super::super::manifest::content_hash(&body)),
            GOLDEN_SIGNED_BODY_HASH
        );
        let signature = manifest
            .publisher_signature
            .as_ref()
            .expect("publisher signature");
        assert_eq!(
            hex::encode(super::super::manifest::content_hash(signature.as_slice())),
            GOLDEN_SIGNATURE_HASH
        );
        manifest
            .verify_trusted_signature(&signing_key.verifying_key().to_bytes())
            .expect("golden signature verifies");
    }

    #[test]
    fn manifest_rejects_wrong_format_duplicate_scope_and_noncanonical_bytes() {
        let mut wrong_format = publication_graph(GraphKind::Zero).0;
        wrong_format.format_version = 3;
        assert!(matches!(
            wrong_format.validate(),
            Err(Error::WrongFormat { version: 3 })
        ));

        let mut duplicate = publication_graph(GraphKind::Partial).0;
        duplicate.entries.push(duplicate.entries[0].clone());
        assert!(matches!(duplicate.validate(), Err(Error::DuplicateScope)));

        let manifest = publication_graph(GraphKind::Zero).0;
        let bytes = manifest.to_bytes().expect("manifest bytes");
        let mut whitespace = bytes.clone();
        whitespace.push(b'\n');
        assert!(matches!(
            Manifest::read(&whitespace),
            Err(Error::NonCanonicalBytes)
        ));
        let unknown =
            String::from_utf8(bytes)
                .expect("JSON")
                .replacen('{', "{\"unknown\":true,", 1);
        assert!(matches!(
            Manifest::read(unknown.as_bytes()),
            Err(Error::Json(_))
        ));
    }

    #[test]
    fn manifest_size_limit_is_shared_by_producer_and_consumer_paths() {
        require_manifest_size(MANIFEST_MAX_BYTES).expect("exact manifest byte limit");
        assert!(matches!(
            require_manifest_size(MANIFEST_MAX_BYTES + 1),
            Err(Error::ManifestByteLimitExceeded { .. })
        ));

        let mut body_boundary = publication_graph(GraphKind::Zero).0;
        let base_body_size = usize_to_u64(
            body_boundary
                .canonical_body_bytes()
                .expect("base body")
                .len(),
        )
        .expect("base body size");
        body_boundary.entries[0]
            .blocked_shields
            .artifact
            .cid
            .push_str(
                &"v".repeat(
                    usize::try_from(MANIFEST_MAX_BYTES - base_body_size)
                        .expect("body padding fits usize"),
                ),
            );
        assert_eq!(
            usize_to_u64(
                body_boundary
                    .canonical_body_bytes()
                    .expect("exact-limit body")
                    .len()
            )
            .expect("exact body size"),
            MANIFEST_MAX_BYTES
        );
        body_boundary.entries[0]
            .blocked_shields
            .artifact
            .cid
            .push('v');

        assert!(matches!(
            body_boundary.canonical_body_bytes(),
            Err(Error::ManifestByteLimitExceeded { .. })
        ));
        assert!(matches!(
            body_boundary.to_bytes(),
            Err(Error::ManifestByteLimitExceeded { .. })
        ));
        assert!(matches!(
            body_boundary.sign_manifest(&SigningKey::from_bytes(&[7; 32])),
            Err(Error::ManifestByteLimitExceeded { .. })
        ));
        body_boundary.publisher_signature = Some(FixedBytes::ZERO);
        assert!(matches!(
            body_boundary.verify_signature(),
            Err(Error::ManifestByteLimitExceeded { .. })
        ));

        let mut full_boundary = publication_graph(GraphKind::Zero).0;
        full_boundary.publisher_signature = Some(FixedBytes::ZERO);
        let base_full_size = usize_to_u64(full_boundary.to_bytes().expect("base manifest").len())
            .expect("base manifest size");
        full_boundary.entries[0]
            .blocked_shields
            .artifact
            .cid
            .push_str(
                &"v".repeat(
                    usize::try_from(MANIFEST_MAX_BYTES - base_full_size)
                        .expect("manifest padding fits usize"),
                ),
            );
        let exact_limit_bytes = full_boundary.to_bytes().expect("exact-limit manifest");
        assert_eq!(
            usize_to_u64(exact_limit_bytes.len()).expect("exact manifest size"),
            MANIFEST_MAX_BYTES
        );
        assert_eq!(
            Manifest::read(&exact_limit_bytes).expect("read exact-limit manifest"),
            full_boundary
        );

        full_boundary.entries[0]
            .blocked_shields
            .artifact
            .cid
            .push('v');
        assert!(matches!(
            full_boundary.to_bytes(),
            Err(Error::ManifestByteLimitExceeded { .. })
        ));
        let oversized_wire = serde_json::to_vec(&full_boundary).expect("oversized fixture bytes");
        assert_eq!(
            usize_to_u64(oversized_wire.len()).expect("oversized manifest size"),
            MANIFEST_MAX_BYTES + 1
        );
        assert!(matches!(
            Manifest::read(&oversized_wire),
            Err(Error::ManifestByteLimitExceeded { .. })
        ));
    }

    #[test]
    fn entry_validation_covers_zero_tail_bridge_and_root_rules() {
        for kind in [
            GraphKind::Zero,
            GraphKind::Partial,
            GraphKind::OneChunk,
            GraphKind::MultiChunk,
            GraphKind::EmptyCheckpointTail,
            GraphKind::RetainedBridges,
        ] {
            publication_graph(kind).0.validate().expect("valid graph");
        }

        let mut missing_tail = publication_graph(GraphKind::EmptyCheckpointTail).0;
        missing_tail.entries[0].current_tail = None;
        assert!(matches!(
            missing_tail.validate(),
            Err(Error::InvalidCurrentTail)
        ));

        let mut root_mismatch = publication_graph(GraphKind::RetainedBridges).0;
        root_mismatch.entries[0].retained_bridges[1].start_root = Some(root(99));
        assert!(matches!(
            root_mismatch.validate(),
            Err(Error::RangeGapOrOverlap)
        ));

        let mut too_many = publication_graph(GraphKind::RetainedBridges).0;
        too_many.entries[0].retained_bridges =
            vec![too_many.entries[0].retained_bridges[0].clone(); 8];
        assert!(matches!(
            too_many.validate(),
            Err(Error::TooManyRetainedBridges { count: 8 })
        ));
    }

    #[test]
    fn resource_limits_accept_boundaries_and_reject_oversize_or_overflow() {
        assert_eq!(expected_checkpoint_chunk_count(0).expect("empty"), 0);
        assert_eq!(expected_checkpoint_chunk_count(1).expect("partial"), 1);
        assert_eq!(
            expected_checkpoint_chunk_count(CHECKPOINT_EVENT_SPAN).expect("full"),
            1
        );
        assert_eq!(
            expected_checkpoint_chunk_count(CHECKPOINT_EVENT_SPAN + 1).expect("full and partial"),
            2
        );
        validate_catalog_limits(
            CATALOG_MAX_BYTES,
            CATALOG_MAX_BYTES,
            CATALOG_MAX_DESCRIPTORS,
        )
        .expect("exact catalog limits");
        assert!(matches!(
            validate_catalog_limits(
                CATALOG_MAX_BYTES + 1,
                CATALOG_MAX_BYTES,
                CATALOG_MAX_DESCRIPTORS,
            ),
            Err(Error::CatalogByteLimitExceeded { .. })
        ));
        assert!(matches!(
            validate_catalog_limits(0, 0, CATALOG_MAX_DESCRIPTORS + 1),
            Err(Error::CatalogDescriptorLimitExceeded { .. })
        ));
        assert!(matches!(
            EventRange::new(0, u64::MAX),
            Err(Error::InvalidRange { .. })
        ));
        assert!(matches!(
            checked_car_response_limit(u64::MAX),
            Err(Error::ArithmeticOverflow)
        ));

        let descriptors = publication_graph(GraphKind::MultiChunk)
            .1
            .into_iter()
            .flat_map(|catalog| catalog.chunks)
            .collect::<Vec<_>>();
        let limits = checked_event_plan_limits(&descriptors).expect("checked plan limits");
        assert_eq!(limits.descriptor_count, 2);
        assert_eq!(limits.record_count, CHECKPOINT_EVENT_SPAN + 2);
        RetrievalLimits::for_event(&descriptors[0])
            .expect("event limits")
            .checked_usize()
            .expect("usize limits");
    }

    #[test]
    fn six_publication_graphs_match_producer_consumer_golden_hashes() {
        let kinds = [
            GraphKind::Zero,
            GraphKind::Partial,
            GraphKind::OneChunk,
            GraphKind::MultiChunk,
            GraphKind::EmptyCheckpointTail,
            GraphKind::RetainedBridges,
        ];
        for (index, kind) in kinds.into_iter().enumerate() {
            let (manifest, catalogs) = publication_graph(kind);
            let body = manifest.canonical_body_bytes().expect("producer body");
            assert_eq!(
                hex::encode(super::super::manifest::content_hash(&body)),
                GOLDEN_BODY_HASHES[index]
            );

            let manifest_bytes = manifest.to_bytes().expect("producer manifest");
            let consumed = Manifest::read(&manifest_bytes).expect("consumer manifest");
            assert_eq!(
                consumed.canonical_body_bytes().expect("consumer body"),
                body
            );
            for catalog in catalogs {
                let catalog_bytes = catalog.to_bytes().expect("producer catalog");
                let descriptor = catalog
                    .descriptor("bafygolden")
                    .expect("catalog descriptor");
                assert_eq!(
                    descriptor
                        .verify_bytes(&catalog_bytes)
                        .expect("consumer catalog"),
                    catalog
                );
            }
        }
    }

    #[derive(Clone, Copy)]
    enum GraphKind {
        Zero,
        Partial,
        OneChunk,
        MultiChunk,
        EmptyCheckpointTail,
        RetainedBridges,
    }

    fn publication_graph(kind: GraphKind) -> (Manifest, Vec<CheckpointCatalog>) {
        let scope = scope();
        let (catalog, event_count, current_root, current_tail, retained_bridges) = match kind {
            GraphKind::Zero => (
                CheckpointCatalog::new(scope.clone(), vec![]).expect("empty catalog"),
                0,
                None,
                None,
                vec![],
            ),
            GraphKind::Partial => (
                CheckpointCatalog::new(scope.clone(), vec![chunk(0, 3, None, root(3), 1)])
                    .expect("partial catalog"),
                3,
                Some(root(3)),
                None,
                vec![],
            ),
            GraphKind::OneChunk => (
                CheckpointCatalog::new(
                    scope.clone(),
                    vec![chunk(0, CHECKPOINT_EVENT_SPAN, None, root(1), 1)],
                )
                .expect("one chunk catalog"),
                CHECKPOINT_EVENT_SPAN,
                Some(root(1)),
                None,
                vec![],
            ),
            GraphKind::MultiChunk => (
                CheckpointCatalog::new(
                    scope.clone(),
                    vec![
                        chunk(0, CHECKPOINT_EVENT_SPAN, None, root(1), 1),
                        chunk(CHECKPOINT_EVENT_SPAN, 2, Some(root(1)), root(2), 2),
                    ],
                )
                .expect("multi chunk catalog"),
                CHECKPOINT_EVENT_SPAN + 2,
                Some(root(2)),
                None,
                vec![],
            ),
            GraphKind::EmptyCheckpointTail => (
                CheckpointCatalog::new(scope.clone(), vec![]).expect("empty catalog"),
                3,
                Some(root(3)),
                Some(event_descriptor(
                    EventArtifactKind::CurrentTail,
                    0,
                    3,
                    None,
                    root(3),
                    3,
                )),
                vec![],
            ),
            GraphKind::RetainedBridges => (
                CheckpointCatalog::new(scope.clone(), vec![chunk(0, 10, None, root(10), 1)])
                    .expect("bridge catalog"),
                12,
                Some(root(12)),
                Some(event_descriptor(
                    EventArtifactKind::CurrentTail,
                    10,
                    2,
                    Some(root(10)),
                    root(12),
                    4,
                )),
                vec![
                    event_descriptor(EventArtifactKind::Bridge, 4, 3, Some(root(4)), root(7), 2),
                    event_descriptor(EventArtifactKind::Bridge, 7, 3, Some(root(7)), root(10), 3),
                ],
            ),
        };
        let catalog_descriptor = catalog
            .descriptor("bafycatalog")
            .expect("catalog descriptor");
        let entry = ManifestEntry {
            scope: scope.clone(),
            event_count,
            current_tip_index: event_count.checked_sub(1),
            current_root,
            checkpoint_catalog: catalog_descriptor,
            current_tail,
            retained_bridges,
            blocked_shields: BlockedShieldsDescriptor {
                artifact: fake_artifact("bafyblocked", 64, 90),
                format_version: FORMAT_VERSION,
                scope,
                row_count: 0,
                encoding: ArtifactEncoding::CanonicalJson,
                compression: Compression::Identity,
            },
        };
        (
            Manifest::new(
                1_700_000_000_000,
                42,
                FixedBytes::from([9; 32]),
                vec![entry],
            ),
            vec![catalog],
        )
    }

    fn scope() -> Scope {
        Scope::new(FixedBytes::from([1; 32]), 0, 1, "V3_PoseidonMerkle")
    }

    fn chunk(
        start_index: u64,
        row_count: u64,
        start_root: Option<FixedBytes<32>>,
        end_root: FixedBytes<32>,
        marker: u8,
    ) -> EventArtifactDescriptor {
        event_descriptor(
            EventArtifactKind::Checkpoint,
            start_index,
            row_count,
            start_root,
            end_root,
            marker,
        )
    }

    fn event_descriptor(
        kind: EventArtifactKind,
        start_index: u64,
        row_count: u64,
        start_root: Option<FixedBytes<32>>,
        end_root: FixedBytes<32>,
        marker: u8,
    ) -> EventArtifactDescriptor {
        let end_index = start_index
            .checked_add(row_count - 1)
            .expect("fixture range");
        EventArtifactDescriptor {
            artifact: fake_artifact(
                &format!("bafyevent{marker}"),
                expected_event_artifact_size(&scope(), row_count).expect("fixture size"),
                marker,
            ),
            format_version: FORMAT_VERSION,
            scope: scope(),
            kind,
            range: EventRange {
                start_index,
                end_index,
            },
            row_count,
            encoding: ArtifactEncoding::PoiEventBinary,
            compression: Compression::Identity,
            start_root,
            end_root,
        }
    }

    fn fake_artifact(cid: &str, byte_size: u64, marker: u8) -> ArtifactDescriptor {
        ArtifactDescriptor {
            cid: cid.to_string(),
            sha256: FixedBytes::from([marker; 32]),
            byte_size,
        }
    }

    fn root(marker: u8) -> FixedBytes<32> {
        FixedBytes::from([marker; 32])
    }

    fn event(event_index: u64, marker: u8) -> SnapshotEvent {
        SnapshotEvent {
            event_index,
            blinded_commitment: [marker; 32],
            signature: [marker + 1; 64],
            event_type: PoiEventType::Shield,
        }
    }

    fn signed_event(signing_key: &SigningKey, event_index: u64, marker: u8) -> SnapshotEvent {
        let mut event = SignedPoiEvent {
            index: event_index,
            blinded_commitment: FixedBytes::from([marker; 32]),
            signature: String::new(),
            event_type: PoiEventType::Shield,
        };
        let signature = signing_key
            .sign(&super::super::verify::canonical_poi_event_message(&event))
            .to_bytes();
        event.signature = hex::encode_prefixed(signature);
        SnapshotEvent {
            event_index,
            blinded_commitment: event.blinded_commitment.0,
            signature,
            event_type: event.event_type,
        }
    }

    fn signed_blocked_shield(signing_key: &SigningKey, marker: u8) -> SignedBlockedShield {
        let mut record = SignedBlockedShield {
            commitment_hash: hex::encode_prefixed([marker + 1; 32]),
            blinded_commitment: hex::encode_prefixed([marker; 32]),
            block_reason: Some("blocked".to_string()),
            signature: String::new(),
        };
        record.signature = hex::encode_prefixed(
            signing_key
                .sign(&super::super::verify::canonical_blocked_shield_message(
                    &record,
                ))
                .to_bytes(),
        );
        record
    }
}
