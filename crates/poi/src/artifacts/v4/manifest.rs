//! The signed v4 manifest and its per-scope entries.

use std::collections::BTreeSet;

use alloy::hex;
use alloy::primitives::FixedBytes;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256 as Sha256Digest};

use super::event::require_contiguous;
use super::limits::require_manifest_size;
use super::{
    BlockedShieldsDescriptor, CheckpointCatalogDescriptor, Error, EventArtifactDescriptor,
    EventArtifactKind, EventRange, FORMAT_VERSION, MANIFEST_SIGNATURE_DOMAIN, MAX_RETAINED_BRIDGES,
    PublicationId, Scope, require_format_version, require_scope, usize_to_u64,
};

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
            return self.validate_empty_graph();
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
        self.validate_checkpoint_state(checkpoint_count)?;
        self.validate_current_tail(checkpoint_count, expected_tip, current_root)
    }

    /// An entry without events carries no tip, checkpoint, tail or bridges.
    const fn validate_empty_graph(&self) -> Result<(), Error> {
        let has_graph_state = self.current_tip_index.is_some()
            || self.current_root.is_some()
            || self.checkpoint_catalog.row_count != 0
            || self.checkpoint_catalog.range.is_some()
            || self.checkpoint_catalog.checkpoint_root.is_some()
            || self.current_tail.is_some()
            || !self.retained_bridges.is_empty();
        if has_graph_state {
            return Err(Error::InvalidEmptyGraph);
        }
        Ok(())
    }

    /// Checkpoints cover events `0..checkpoint_count`, and the retained bridges
    /// end at the checkpoint root.
    fn validate_checkpoint_state(&self, checkpoint_count: u64) -> Result<(), Error> {
        match checkpoint_count {
            0 => {
                let has_checkpoint_state = self.checkpoint_catalog.range.is_some()
                    || self.checkpoint_catalog.checkpoint_root.is_some()
                    || !self.retained_bridges.is_empty();
                if has_checkpoint_state {
                    return Err(Error::InvalidEmptyCheckpoint);
                }
            }
            count => {
                let expected_end = count.checked_sub(1).ok_or(Error::ArithmeticOverflow)?;
                let aggregate_matches = self.checkpoint_catalog.range
                    == Some(EventRange {
                        start_index: 0,
                        end_index: expected_end,
                    })
                    && self.checkpoint_catalog.checkpoint_root.is_some();
                if !aggregate_matches {
                    return Err(Error::InvalidCheckpointAggregate);
                }
                self.validate_bridge_chain()?;
            }
        }
        Ok(())
    }

    /// Events past the checkpoints form the current tail, which runs from the
    /// checkpoint root to the current root.
    fn validate_current_tail(
        &self,
        checkpoint_count: u64,
        expected_tip: u64,
        current_root: FixedBytes<32>,
    ) -> Result<(), Error> {
        if checkpoint_count == self.event_count {
            if self.current_tail.is_some()
                || self.checkpoint_catalog.checkpoint_root != Some(current_root)
            {
                return Err(Error::InvalidCurrentTail);
            }
            return Ok(());
        }
        let tail = self
            .current_tail
            .as_ref()
            .ok_or(Error::InvalidCurrentTail)?;
        tail.validate()?;
        require_scope(&self.scope, &tail.scope)?;
        let tail_matches = tail.kind == EventArtifactKind::CurrentTail
            && tail.range.start_index == checkpoint_count
            && tail.range.end_index == expected_tip
            && tail.end_root == current_root
            && tail.start_root == self.checkpoint_catalog.checkpoint_root;
        if !tail_matches {
            return Err(Error::InvalidCurrentTail);
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
        serialize_manifest(&ManifestBody {
            format_version: self.format_version,
            issued_at_ms: self.issued_at_ms,
            sequence: self.sequence,
            publisher_pubkey: self.publisher_pubkey,
            entries: self.sorted_entries(),
        })
    }

    /// The entries in canonical order: by scope, keeping equal scopes in place.
    fn sorted_entries(&self) -> Vec<ManifestEntry> {
        let mut entries = self.entries.clone();
        entries.sort_by(|left, right| left.scope.cmp(&right.scope));
        entries
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
        serialize_manifest(&ManifestWire {
            format_version: self.format_version,
            issued_at_ms: self.issued_at_ms,
            sequence: self.sequence,
            publisher_pubkey: self.publisher_pubkey,
            entries: self.sorted_entries(),
            publisher_signature: self.publisher_signature,
        })
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

/// Serializes a manifest representation and enforces the manifest byte limit.
fn serialize_manifest(value: &impl Serialize) -> Result<Vec<u8>, Error> {
    let bytes = serde_json::to_vec(value).map_err(Error::Json)?;
    require_manifest_size(usize_to_u64(bytes.len())?)?;
    Ok(bytes)
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
