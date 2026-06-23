use std::cmp::Ordering;

use alloy_primitives::{Address, FixedBytes};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const INDEXED_ARTIFACT_MANIFEST_FORMAT_VERSION: u16 = 1;
pub const INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION: u16 = 1;
pub const INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION: u16 = 2;
pub const INDEXED_ARTIFACT_MAX_COMPRESSED_CHUNK_BYTES: u64 = 32 * 1024 * 1024;

pub const CHUNK_FORMAT_VERSION: u16 = INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION;
pub const TARGET_COMPRESSED_CHUNK_BYTES: u64 = 8 * 1024 * 1024;
pub const SOFT_MIN_COMPRESSED_CHUNK_BYTES: u64 = 4 * 1024 * 1024;
pub const SOFT_MAX_COMPRESSED_CHUNK_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_COMPRESSED_CHUNK_BYTES: u64 = INDEXED_ARTIFACT_MAX_COMPRESSED_CHUNK_BYTES;

pub const INDEXED_ARTIFACT_CHUNK_MAGIC: &[u8; 8] = b"RGIDXCH\0";
const ZSTD_LEVEL: i32 = 3;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedArtifactManifest {
    pub format_version: u16,
    pub issued_at_ms: u64,
    pub sequence: u64,
    pub publisher: PublisherIdentity,
    pub chains: Vec<IndexedArtifactChainEntry>,
    pub publisher_signature: Option<String>,
}

impl IndexedArtifactManifest {
    #[must_use]
    pub const fn new(
        issued_at_ms: u64,
        sequence: u64,
        publisher: PublisherIdentity,
        chains: Vec<IndexedArtifactChainEntry>,
    ) -> Self {
        Self {
            format_version: INDEXED_ARTIFACT_MANIFEST_FORMAT_VERSION,
            issued_at_ms,
            sequence,
            publisher,
            chains,
            publisher_signature: None,
        }
    }

    pub fn deterministic_body_bytes(&self) -> Result<Vec<u8>, IndexedArtifactError> {
        let mut chains = self.chains.clone();
        for chain in &mut chains {
            chain.latest_indexed.sort_by(cmp_latest_indexed_height);
            chain.catalogs.sort_by(cmp_descriptor);
        }
        chains.sort_by(cmp_chain_entry);

        let body = IndexedArtifactManifestBody {
            format_version: self.format_version,
            issued_at_ms: self.issued_at_ms,
            sequence: self.sequence,
            publisher: &self.publisher,
            chains,
        };
        serde_json::to_vec(&body).map_err(IndexedArtifactError::Json)
    }

    pub fn sign_manifest(&mut self, signing_key: &SigningKey) -> Result<(), IndexedArtifactError> {
        self.publisher =
            PublisherIdentity::ed25519(hex::encode(signing_key.verifying_key().to_bytes()));
        let body_bytes = self.deterministic_body_bytes()?;
        self.publisher_signature = Some(hex::encode(signing_key.sign(&body_bytes).to_bytes()));
        Ok(())
    }

    pub fn verify_signature(&self) -> Result<(), IndexedArtifactError> {
        match self.publisher.key_algorithm {
            PublisherKeyAlgorithm::Ed25519 => {
                let pubkey_bytes: [u8; 32] = self
                    .publisher
                    .public_key
                    .parse::<FixedBytes<32>>()
                    .map_err(|err| IndexedArtifactError::Hex(err.to_string()))?
                    .into();
                self.verify_signature_with_key(&pubkey_bytes)
            }
        }
    }

    pub fn verify_trusted_signature(
        &self,
        trusted_publisher_pubkey: &[u8; 32],
    ) -> Result<(), IndexedArtifactError> {
        let pubkey = self
            .publisher
            .public_key
            .parse::<FixedBytes<32>>()
            .map_err(|err| IndexedArtifactError::Hex(err.to_string()))?;
        if pubkey.as_slice() != trusted_publisher_pubkey.as_slice() {
            return Err(IndexedArtifactError::PublisherKeyMismatch {
                expected: prefixed_hex(trusted_publisher_pubkey),
                actual: prefixed_hex(pubkey.as_slice()),
            });
        }

        self.verify_signature_with_key(trusted_publisher_pubkey)
    }

    fn verify_signature_with_key(
        &self,
        pubkey_bytes: &[u8; 32],
    ) -> Result<(), IndexedArtifactError> {
        let signature_bytes: [u8; 64] = self
            .publisher_signature
            .as_deref()
            .ok_or(IndexedArtifactError::MissingPublisherSignature)?
            .parse::<FixedBytes<64>>()
            .map_err(|err| IndexedArtifactError::Hex(err.to_string()))?
            .into();
        let verifying_key =
            VerifyingKey::from_bytes(pubkey_bytes).map_err(IndexedArtifactError::PublicKey)?;
        let signature = Signature::from_bytes(&signature_bytes);
        verifying_key
            .verify(&self.deterministic_body_bytes()?, &signature)
            .map_err(IndexedArtifactError::Signature)
    }
}

#[derive(Serialize)]
struct IndexedArtifactManifestBody<'a> {
    format_version: u16,
    issued_at_ms: u64,
    sequence: u64,
    publisher: &'a PublisherIdentity,
    chains: Vec<IndexedArtifactChainEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublisherIdentity {
    pub key_algorithm: PublisherKeyAlgorithm,
    pub public_key: String,
}

impl PublisherIdentity {
    #[must_use]
    pub fn ed25519(public_key: impl Into<String>) -> Self {
        Self {
            key_algorithm: PublisherKeyAlgorithm::Ed25519,
            public_key: public_key.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublisherKeyAlgorithm {
    Ed25519,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedArtifactChainEntry {
    pub scope: ChainScope,
    pub latest_indexed: Vec<LatestIndexedHeight>,
    pub catalogs: Vec<IndexedArtifactDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainScope {
    pub chain_type: ChainType,
    pub chain_id: u64,
    pub railgun_contract: Address,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainType {
    Evm,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatestIndexedHeight {
    pub dataset_kind: IndexedDatasetKind,
    pub block_number: u64,
    pub block_hash: FixedBytes<32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexedDatasetKind {
    WalletScan,
    Commitments,
    MerkleCheckpoint,
    PublicTxid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedArtifactDescriptor {
    pub dataset_kind: IndexedDatasetKind,
    pub scope: ChainScope,
    pub range: IndexedArtifactRange,
    pub row_count: u64,
    pub cid: String,
    pub sha256: FixedBytes<32>,
    pub byte_size: u64,
    pub encoding_version: u16,
    pub compression: CompressionAlgorithm,
    pub metadata: DatasetDescriptorMetadata,
}

impl IndexedArtifactDescriptor {
    #[must_use]
    pub fn matches(
        &self,
        dataset_kind: IndexedDatasetKind,
        scope: &ChainScope,
        range_kind: IndexedArtifactRangeKind,
    ) -> bool {
        self.dataset_kind == dataset_kind && self.scope == *scope && self.range.kind == range_kind
    }

    #[must_use]
    pub fn matches_range(
        &self,
        dataset_kind: IndexedDatasetKind,
        scope: &ChainScope,
        range_kind: IndexedArtifactRangeKind,
        start: u64,
        end: u64,
    ) -> bool {
        self.matches(dataset_kind, scope, range_kind) && self.range.intersects(start, end)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedArtifactCatalog {
    pub format_version: u16,
    pub dataset_kind: IndexedDatasetKind,
    pub scope: ChainScope,
    pub chunks: Vec<IndexedArtifactDescriptor>,
}

impl IndexedArtifactCatalog {
    #[must_use]
    pub const fn new(
        dataset_kind: IndexedDatasetKind,
        scope: ChainScope,
        chunks: Vec<IndexedArtifactDescriptor>,
    ) -> Self {
        Self {
            format_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
            dataset_kind,
            scope,
            chunks,
        }
    }

    pub fn deterministic_body_bytes(&self) -> Result<Vec<u8>, IndexedArtifactError> {
        let mut chunks = self.chunks.clone();
        chunks.sort_by(cmp_descriptor);
        let body = IndexedArtifactCatalogBody {
            format_version: self.format_version,
            dataset_kind: self.dataset_kind,
            scope: &self.scope,
            chunks,
        };
        serde_json::to_vec(&body).map_err(IndexedArtifactError::Json)
    }
}

#[derive(Serialize)]
struct IndexedArtifactCatalogBody<'a> {
    format_version: u16,
    dataset_kind: IndexedDatasetKind,
    scope: &'a ChainScope,
    chunks: Vec<IndexedArtifactDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedArtifactRange {
    pub kind: IndexedArtifactRangeKind,
    pub start: u64,
    pub end: u64,
}

impl IndexedArtifactRange {
    #[must_use]
    pub const fn intersects(&self, start: u64, end: u64) -> bool {
        self.start <= self.end && start <= end && self.start <= end && start <= self.end
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexedArtifactRangeKind {
    Block,
    TxidIndex,
    TreePosition,
    PoiEventIndex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionAlgorithm {
    None,
    Zstd,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatasetDescriptorMetadata {
    pub root: Option<FixedBytes<32>>,
    pub checkpoint_block: Option<u64>,
    pub tree_number: Option<u16>,
    pub leaf_count: Option<u64>,
    pub start_block: Option<u64>,
    pub end_block: Option<u64>,
    pub last_indexed_block: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkEnvelope {
    pub header: ChunkEnvelopeHeader,
    pub payload: Vec<u8>,
}

impl ChunkEnvelope {
    #[must_use]
    pub const fn new(header: ChunkEnvelopeHeader, payload: Vec<u8>) -> Self {
        Self { header, payload }
    }

    pub fn section_payload(&self, section_id: u16) -> Result<&[u8], ChunkError> {
        let section = self
            .header
            .sections
            .iter()
            .find(|section| section.section_id == section_id)
            .ok_or(ChunkError::SectionMissing { section_id })?;
        let start =
            usize::try_from(section.offset).map_err(|_| ChunkError::SectionOutOfBounds {
                section_id,
                offset: section.offset,
                byte_length: section.byte_length,
                payload_len: u64::try_from(self.payload.len()).unwrap_or(u64::MAX),
            })?;
        let length =
            usize::try_from(section.byte_length).map_err(|_| ChunkError::SectionOutOfBounds {
                section_id,
                offset: section.offset,
                byte_length: section.byte_length,
                payload_len: u64::try_from(self.payload.len()).unwrap_or(u64::MAX),
            })?;
        let end = start
            .checked_add(length)
            .ok_or_else(|| ChunkError::SectionOutOfBounds {
                section_id,
                offset: section.offset,
                byte_length: section.byte_length,
                payload_len: u64::try_from(self.payload.len()).unwrap_or(u64::MAX),
            })?;
        self.payload
            .get(start..end)
            .ok_or_else(|| ChunkError::SectionOutOfBounds {
                section_id,
                offset: section.offset,
                byte_length: section.byte_length,
                payload_len: u64::try_from(self.payload.len()).unwrap_or(u64::MAX),
            })
    }

    pub fn encode(&self) -> Result<Vec<u8>, ChunkError> {
        self.header.validate_for_payload(&self.payload)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(INDEXED_ARTIFACT_CHUNK_MAGIC);
        write_u16(&mut bytes, self.header.format_version);
        bytes.push(dataset_kind_id(self.header.dataset_kind));
        bytes.push(chain_type_id(self.header.scope.chain_type));
        write_u64(&mut bytes, self.header.scope.chain_id);
        write_string(
            &mut bytes,
            "railgun_contract",
            &prefixed_hex(self.header.scope.railgun_contract.as_slice()),
        )?;
        bytes.push(range_kind_id(self.header.range.kind));
        write_u64(&mut bytes, self.header.range.start);
        write_u64(&mut bytes, self.header.range.end);
        write_u64(&mut bytes, self.header.row_count);
        write_u64(&mut bytes, self.header.uncompressed_length);
        write_u16(
            &mut bytes,
            u16::try_from(self.header.sections.len()).map_err(|_| ChunkError::TooManySections {
                count: self.header.sections.len(),
            })?,
        );
        for section in &self.header.sections {
            write_u16(&mut bytes, section.section_id);
            write_u64(&mut bytes, section.offset);
            write_u64(&mut bytes, section.byte_length);
        }
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ChunkError> {
        let mut cursor = Cursor::new(bytes);
        let magic = cursor.read_exact(INDEXED_ARTIFACT_CHUNK_MAGIC.len(), "magic")?;
        if magic != INDEXED_ARTIFACT_CHUNK_MAGIC {
            return Err(ChunkError::WrongMagic);
        }

        let format_version = cursor.read_u16("format_version")?;
        if format_version != CHUNK_FORMAT_VERSION {
            return Err(ChunkError::UnsupportedFormatVersion(format_version));
        }
        let dataset_kind = parse_dataset_kind(cursor.read_u8("dataset_kind")?)?;
        let chain_type = parse_chain_type(cursor.read_u8("chain_type")?)?;
        let chain_id = cursor.read_u64("chain_id")?;
        let railgun_contract = cursor
            .read_string("railgun_contract")?
            .parse::<Address>()
            .map_err(|err| ChunkError::Hex(err.to_string()))?;
        let range = IndexedArtifactRange {
            kind: parse_range_kind(cursor.read_u8("range_kind")?)?,
            start: cursor.read_u64("range_start")?,
            end: cursor.read_u64("range_end")?,
        };
        let row_count = cursor.read_u64("row_count")?;
        let uncompressed_length = cursor.read_u64("uncompressed_length")?;
        let section_count = cursor.read_u16("section_count")?;
        let mut sections = Vec::with_capacity(section_count as usize);
        for _ in 0..section_count {
            sections.push(ChunkSection {
                section_id: cursor.read_u16("section_id")?,
                offset: cursor.read_u64("section_offset")?,
                byte_length: cursor.read_u64("section_byte_length")?,
            });
        }
        let payload = bytes[cursor.position..].to_vec();
        let header = ChunkEnvelopeHeader {
            format_version,
            dataset_kind,
            scope: ChainScope {
                chain_type,
                chain_id,
                railgun_contract,
            },
            range,
            row_count,
            uncompressed_length,
            sections,
        };
        header.validate_for_payload(&payload)?;

        Ok(Self { header, payload })
    }
}

pub type IndexedArtifactChunkEnvelope = ChunkEnvelope;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkEnvelopeHeader {
    pub format_version: u16,
    pub dataset_kind: IndexedDatasetKind,
    pub scope: ChainScope,
    pub range: IndexedArtifactRange,
    pub row_count: u64,
    pub uncompressed_length: u64,
    pub sections: Vec<ChunkSection>,
}

impl ChunkEnvelopeHeader {
    #[must_use]
    pub const fn new(
        dataset_kind: IndexedDatasetKind,
        scope: ChainScope,
        range: IndexedArtifactRange,
        row_count: u64,
        uncompressed_length: u64,
        sections: Vec<ChunkSection>,
    ) -> Self {
        Self {
            format_version: CHUNK_FORMAT_VERSION,
            dataset_kind,
            scope,
            range,
            row_count,
            uncompressed_length,
            sections,
        }
    }

    fn validate_for_payload(&self, payload: &[u8]) -> Result<(), ChunkError> {
        let payload_len = u64::try_from(payload.len()).map_err(|_| ChunkError::PayloadTooLarge)?;
        if self.uncompressed_length != payload_len {
            return Err(ChunkError::UncompressedLengthMismatch {
                expected: self.uncompressed_length,
                actual: payload_len,
            });
        }
        for section in &self.sections {
            let end = section.offset.checked_add(section.byte_length).ok_or(
                ChunkError::SectionRangeOverflow {
                    section_id: section.section_id,
                },
            )?;
            if end > payload_len {
                return Err(ChunkError::SectionOutOfBounds {
                    section_id: section.section_id,
                    offset: section.offset,
                    byte_length: section.byte_length,
                    payload_len,
                });
            }
        }
        Ok(())
    }
}

pub type IndexedArtifactChunkEnvelopeHeader = ChunkEnvelopeHeader;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkSection {
    pub section_id: u16,
    pub offset: u64,
    pub byte_length: u64,
}

pub type IndexedArtifactChunkSection = ChunkSection;

pub fn encode_chunk_bytes(
    envelope: &ChunkEnvelope,
    compression: CompressionAlgorithm,
) -> Result<Vec<u8>, ChunkError> {
    compress_bytes(&envelope.encode()?, compression)
}

pub fn decode_chunk_bytes(
    descriptor: &IndexedArtifactDescriptor,
    bytes: &[u8],
) -> Result<ChunkEnvelope, ChunkError> {
    if descriptor.byte_size > MAX_COMPRESSED_CHUNK_BYTES {
        return Err(ChunkError::ChunkTooLarge {
            actual: descriptor.byte_size,
            maximum: MAX_COMPRESSED_CHUNK_BYTES,
        });
    }
    let actual = u64::try_from(bytes.len()).map_err(|_| ChunkError::PayloadTooLarge)?;
    if actual > MAX_COMPRESSED_CHUNK_BYTES {
        return Err(ChunkError::ChunkTooLarge {
            actual,
            maximum: MAX_COMPRESSED_CHUNK_BYTES,
        });
    }
    if actual != descriptor.byte_size {
        return Err(ChunkError::DescriptorByteSizeMismatch {
            expected: descriptor.byte_size,
            actual,
        });
    }
    let uncompressed = decompress_bytes(bytes, descriptor.compression)?;
    let envelope = ChunkEnvelope::decode(&uncompressed)?;
    validate_descriptor_matches_header(descriptor, &envelope.header)?;
    Ok(envelope)
}

pub fn compress_bytes(
    bytes: &[u8],
    compression: CompressionAlgorithm,
) -> Result<Vec<u8>, ChunkError> {
    match compression {
        CompressionAlgorithm::None => Ok(bytes.to_vec()),
        CompressionAlgorithm::Zstd => {
            zstd::stream::encode_all(std::io::Cursor::new(bytes), ZSTD_LEVEL)
                .map_err(ChunkError::Compression)
        }
    }
}

pub fn decompress_bytes(
    bytes: &[u8],
    compression: CompressionAlgorithm,
) -> Result<Vec<u8>, ChunkError> {
    match compression {
        CompressionAlgorithm::None => Ok(bytes.to_vec()),
        CompressionAlgorithm::Zstd => {
            zstd::stream::decode_all(std::io::Cursor::new(bytes)).map_err(ChunkError::Compression)
        }
    }
}

pub fn plan_chunks(
    items: &[ChunkPlanItem],
    config: ChunkPlanningConfig,
) -> Result<Vec<PlannedChunk>, ChunkError> {
    config.validate()?;
    let mut planner = ChunkPlanner::new(config);
    for item in items {
        planner.push(item)?;
    }
    Ok(planner.finish())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkPlanningConfig {
    pub target_compressed_bytes: u64,
    pub soft_min_compressed_bytes: u64,
    pub soft_max_compressed_bytes: u64,
    pub hard_max_compressed_bytes: u64,
}

impl Default for ChunkPlanningConfig {
    fn default() -> Self {
        Self {
            target_compressed_bytes: TARGET_COMPRESSED_CHUNK_BYTES,
            soft_min_compressed_bytes: SOFT_MIN_COMPRESSED_CHUNK_BYTES,
            soft_max_compressed_bytes: SOFT_MAX_COMPRESSED_CHUNK_BYTES,
            hard_max_compressed_bytes: MAX_COMPRESSED_CHUNK_BYTES,
        }
    }
}

impl ChunkPlanningConfig {
    const fn validate(self) -> Result<(), ChunkError> {
        if self.soft_min_compressed_bytes > self.target_compressed_bytes
            || self.target_compressed_bytes > self.soft_max_compressed_bytes
            || self.soft_max_compressed_bytes > self.hard_max_compressed_bytes
        {
            return Err(ChunkError::InvalidChunkPlanningConfig {
                soft_min: self.soft_min_compressed_bytes,
                target: self.target_compressed_bytes,
                soft_max: self.soft_max_compressed_bytes,
                hard_max: self.hard_max_compressed_bytes,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkPlanItem {
    pub range: IndexedArtifactRange,
    pub row_count: u64,
    pub compressed_byte_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedChunk {
    pub range: IndexedArtifactRange,
    pub row_count: u64,
    pub compressed_byte_size: u64,
    pub item_count: usize,
}

struct ChunkPlanner {
    config: ChunkPlanningConfig,
    current: Option<PlannedChunk>,
    planned: Vec<PlannedChunk>,
}

impl ChunkPlanner {
    const fn new(config: ChunkPlanningConfig) -> Self {
        Self {
            config,
            current: None,
            planned: Vec::new(),
        }
    }

    fn push(&mut self, item: &ChunkPlanItem) -> Result<(), ChunkError> {
        if item.range.start > item.range.end {
            return Err(ChunkError::InvalidChunkPlanRange {
                start: item.range.start,
                end: item.range.end,
            });
        }
        if item.compressed_byte_size > self.config.hard_max_compressed_bytes {
            return Err(ChunkError::ChunkPlanItemTooLarge {
                actual: item.compressed_byte_size,
                maximum: self.config.hard_max_compressed_bytes,
            });
        }

        if self.should_flush_before(item)? {
            self.flush_current();
        }

        match &mut self.current {
            Some(current) => {
                if current.range.kind != item.range.kind {
                    self.flush_current();
                    self.current = Some(PlannedChunk::from_item(item));
                    return Ok(());
                }
                current.range.end = current.range.end.max(item.range.end);
                current.row_count = current
                    .row_count
                    .checked_add(item.row_count)
                    .ok_or(ChunkError::ChunkPlanningOverflow)?;
                current.compressed_byte_size = current
                    .compressed_byte_size
                    .checked_add(item.compressed_byte_size)
                    .ok_or(ChunkError::ChunkPlanningOverflow)?;
                current.item_count = current
                    .item_count
                    .checked_add(1)
                    .ok_or(ChunkError::ChunkPlanningOverflow)?;
            }
            None => self.current = Some(PlannedChunk::from_item(item)),
        }
        Ok(())
    }

    fn should_flush_before(&self, item: &ChunkPlanItem) -> Result<bool, ChunkError> {
        let Some(current) = &self.current else {
            return Ok(false);
        };
        if current.range.kind != item.range.kind {
            return Ok(true);
        }
        let next_size = current
            .compressed_byte_size
            .checked_add(item.compressed_byte_size)
            .ok_or(ChunkError::ChunkPlanningOverflow)?;
        Ok(next_size > self.config.hard_max_compressed_bytes
            || next_size > self.config.soft_max_compressed_bytes
            || (current.compressed_byte_size >= self.config.target_compressed_bytes
                && next_size > self.config.target_compressed_bytes))
    }

    fn flush_current(&mut self) {
        if let Some(current) = self.current.take() {
            self.planned.push(current);
        }
    }

    fn finish(mut self) -> Vec<PlannedChunk> {
        self.flush_current();
        self.planned
    }
}

impl PlannedChunk {
    fn from_item(item: &ChunkPlanItem) -> Self {
        Self {
            range: item.range.clone(),
            row_count: item.row_count,
            compressed_byte_size: item.compressed_byte_size,
            item_count: 1,
        }
    }
}

#[derive(Debug, Error)]
pub enum IndexedArtifactError {
    #[error("indexed artifact JSON encoding failed")]
    Json(#[from] serde_json::Error),
    #[error("indexed artifact publisher public key mismatch: expected {expected}, got {actual}")]
    PublisherKeyMismatch { expected: String, actual: String },
    #[error("indexed artifact manifest publisher signature is missing")]
    MissingPublisherSignature,
    #[error("invalid indexed artifact publisher public key")]
    PublicKey(#[source] ed25519_dalek::SignatureError),
    #[error("indexed artifact manifest signature verification failed")]
    Signature(#[source] ed25519_dalek::SignatureError),
    #[error("invalid indexed artifact hex: {0}")]
    Hex(String),
}

#[derive(Debug, Error)]
pub enum ChunkError {
    #[error("chunk has wrong magic bytes")]
    WrongMagic,
    #[error("unsupported chunk format version {0}")]
    UnsupportedFormatVersion(u16),
    #[error("unknown dataset kind id {0}")]
    UnknownDatasetKind(u8),
    #[error("unknown chain type id {0}")]
    UnknownChainType(u8),
    #[error("unknown range kind id {0}")]
    UnknownRangeKind(u8),
    #[error("chunk ended while reading {field}")]
    UnexpectedEof { field: &'static str },
    #[error("invalid chunk hex: {0}")]
    Hex(String),
    #[error("string field {field} length {length} exceeds u16")]
    StringTooLong { field: &'static str, length: usize },
    #[error("string field {field} is not utf8")]
    InvalidUtf8 {
        field: &'static str,
        #[source]
        source: std::str::Utf8Error,
    },
    #[error("chunk payload length overflows u64")]
    PayloadTooLarge,
    #[error("chunk byte size {actual} exceeds maximum {maximum}")]
    ChunkTooLarge { actual: u64, maximum: u64 },
    #[error(
        "invalid chunk planning config: soft_min={soft_min}, target={target}, soft_max={soft_max}, hard_max={hard_max}"
    )]
    InvalidChunkPlanningConfig {
        soft_min: u64,
        target: u64,
        soft_max: u64,
        hard_max: u64,
    },
    #[error("chunk plan item range start {start} exceeds end {end}")]
    InvalidChunkPlanRange { start: u64, end: u64 },
    #[error("chunk plan item compressed byte size {actual} exceeds maximum {maximum}")]
    ChunkPlanItemTooLarge { actual: u64, maximum: u64 },
    #[error("chunk planning byte count overflowed")]
    ChunkPlanningOverflow,
    #[error("chunk descriptor byte size mismatch: expected {expected}, got {actual}")]
    DescriptorByteSizeMismatch { expected: u64, actual: u64 },
    #[error("chunk descriptor encoding version mismatch: expected {expected}, got {actual}")]
    DescriptorEncodingVersionMismatch { expected: u16, actual: u16 },
    #[error("chunk descriptor dataset mismatch: expected {expected:?}, got {actual:?}")]
    DescriptorDatasetKindMismatch {
        expected: IndexedDatasetKind,
        actual: IndexedDatasetKind,
    },
    #[error("chunk descriptor scope mismatch: expected {expected}, got {actual}")]
    DescriptorScopeMismatch { expected: String, actual: String },
    #[error(
        "chunk descriptor range mismatch: expected {expected_start}-{expected_end}, got {actual_start}-{actual_end}"
    )]
    DescriptorRangeMismatch {
        expected_start: u64,
        expected_end: u64,
        actual_start: u64,
        actual_end: u64,
    },
    #[error("chunk descriptor row count mismatch: expected {expected}, got {actual}")]
    DescriptorRowCountMismatch { expected: u64, actual: u64 },
    #[error("chunk compression failed")]
    Compression(#[source] std::io::Error),
    #[error("chunk has {count} sections, exceeding u16")]
    TooManySections { count: usize },
    #[error("chunk uncompressed length mismatch: expected {expected}, got {actual}")]
    UncompressedLengthMismatch { expected: u64, actual: u64 },
    #[error("chunk section {section_id} range overflows u64")]
    SectionRangeOverflow { section_id: u16 },
    #[error(
        "chunk section {section_id} is out of bounds: offset {offset}, length {byte_length}, payload length {payload_len}"
    )]
    SectionOutOfBounds {
        section_id: u16,
        offset: u64,
        byte_length: u64,
        payload_len: u64,
    },
    #[error("chunk section {section_id} is missing")]
    SectionMissing { section_id: u16 },
}

fn validate_descriptor_matches_header(
    descriptor: &IndexedArtifactDescriptor,
    header: &ChunkEnvelopeHeader,
) -> Result<(), ChunkError> {
    if descriptor.encoding_version != header.format_version {
        return Err(ChunkError::DescriptorEncodingVersionMismatch {
            expected: descriptor.encoding_version,
            actual: header.format_version,
        });
    }
    if descriptor.dataset_kind != header.dataset_kind {
        return Err(ChunkError::DescriptorDatasetKindMismatch {
            expected: descriptor.dataset_kind,
            actual: header.dataset_kind,
        });
    }
    if descriptor.scope != header.scope {
        return Err(ChunkError::DescriptorScopeMismatch {
            expected: format_scope(&descriptor.scope),
            actual: format_scope(&header.scope),
        });
    }
    if descriptor.range != header.range {
        return Err(ChunkError::DescriptorRangeMismatch {
            expected_start: descriptor.range.start,
            expected_end: descriptor.range.end,
            actual_start: header.range.start,
            actual_end: header.range.end,
        });
    }
    if descriptor.row_count != header.row_count {
        return Err(ChunkError::DescriptorRowCountMismatch {
            expected: descriptor.row_count,
            actual: header.row_count,
        });
    }
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read_exact(&mut self, length: usize, field: &'static str) -> Result<&'a [u8], ChunkError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(ChunkError::UnexpectedEof { field })?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(ChunkError::UnexpectedEof { field })?;
        self.position = end;
        Ok(value)
    }

    fn read_u8(&mut self, field: &'static str) -> Result<u8, ChunkError> {
        Ok(self.read_exact(1, field)?[0])
    }

    fn read_u16(&mut self, field: &'static str) -> Result<u16, ChunkError> {
        let bytes = self.read_exact(2, field)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u64(&mut self, field: &'static str) -> Result<u64, ChunkError> {
        let bytes = self.read_exact(8, field)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_string(&mut self, field: &'static str) -> Result<String, ChunkError> {
        let length = self.read_u16(field)? as usize;
        let bytes = self.read_exact(length, field)?;
        std::str::from_utf8(bytes)
            .map(str::to_string)
            .map_err(|source| ChunkError::InvalidUtf8 { field, source })
    }
}

fn write_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn write_string(bytes: &mut Vec<u8>, field: &'static str, value: &str) -> Result<(), ChunkError> {
    write_u16(
        bytes,
        u16::try_from(value.len()).map_err(|_| ChunkError::StringTooLong {
            field,
            length: value.len(),
        })?,
    );
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

const fn dataset_kind_id(value: IndexedDatasetKind) -> u8 {
    match value {
        IndexedDatasetKind::WalletScan => 0,
        IndexedDatasetKind::Commitments => 1,
        IndexedDatasetKind::MerkleCheckpoint => 2,
        IndexedDatasetKind::PublicTxid => 3,
    }
}

const fn parse_dataset_kind(value: u8) -> Result<IndexedDatasetKind, ChunkError> {
    match value {
        0 => Ok(IndexedDatasetKind::WalletScan),
        1 => Ok(IndexedDatasetKind::Commitments),
        2 => Ok(IndexedDatasetKind::MerkleCheckpoint),
        3 => Ok(IndexedDatasetKind::PublicTxid),
        other => Err(ChunkError::UnknownDatasetKind(other)),
    }
}

const fn chain_type_id(value: ChainType) -> u8 {
    match value {
        ChainType::Evm => 0,
    }
}

const fn parse_chain_type(value: u8) -> Result<ChainType, ChunkError> {
    match value {
        0 => Ok(ChainType::Evm),
        other => Err(ChunkError::UnknownChainType(other)),
    }
}

const fn range_kind_id(value: IndexedArtifactRangeKind) -> u8 {
    match value {
        IndexedArtifactRangeKind::Block => 0,
        IndexedArtifactRangeKind::TxidIndex => 1,
        IndexedArtifactRangeKind::TreePosition => 2,
        IndexedArtifactRangeKind::PoiEventIndex => 3,
    }
}

const fn parse_range_kind(value: u8) -> Result<IndexedArtifactRangeKind, ChunkError> {
    match value {
        0 => Ok(IndexedArtifactRangeKind::Block),
        1 => Ok(IndexedArtifactRangeKind::TxidIndex),
        2 => Ok(IndexedArtifactRangeKind::TreePosition),
        3 => Ok(IndexedArtifactRangeKind::PoiEventIndex),
        other => Err(ChunkError::UnknownRangeKind(other)),
    }
}

fn cmp_chain_entry(
    left: &IndexedArtifactChainEntry,
    right: &IndexedArtifactChainEntry,
) -> Ordering {
    cmp_chain_scope(&left.scope, &right.scope)
}

fn cmp_chain_scope(left: &ChainScope, right: &ChainScope) -> Ordering {
    chain_type_order(left.chain_type)
        .cmp(&chain_type_order(right.chain_type))
        .then_with(|| left.chain_id.cmp(&right.chain_id))
        .then_with(|| {
            left.railgun_contract
                .as_slice()
                .cmp(right.railgun_contract.as_slice())
        })
}

fn cmp_latest_indexed_height(left: &LatestIndexedHeight, right: &LatestIndexedHeight) -> Ordering {
    dataset_kind_order(left.dataset_kind)
        .cmp(&dataset_kind_order(right.dataset_kind))
        .then_with(|| left.block_number.cmp(&right.block_number))
        .then_with(|| left.block_hash.as_slice().cmp(right.block_hash.as_slice()))
}

fn cmp_descriptor(left: &IndexedArtifactDescriptor, right: &IndexedArtifactDescriptor) -> Ordering {
    cmp_descriptor_parts(
        left.dataset_kind,
        &left.scope,
        &left.range,
        left.row_count,
        &left.cid,
        right.dataset_kind,
        &right.scope,
        &right.range,
        right.row_count,
        &right.cid,
    )
}

#[allow(clippy::too_many_arguments)]
fn cmp_descriptor_parts(
    left_dataset_kind: IndexedDatasetKind,
    left_scope: &ChainScope,
    left_range: &IndexedArtifactRange,
    left_row_count: u64,
    left_cid: &str,
    right_dataset_kind: IndexedDatasetKind,
    right_scope: &ChainScope,
    right_range: &IndexedArtifactRange,
    right_row_count: u64,
    right_cid: &str,
) -> Ordering {
    dataset_kind_order(left_dataset_kind)
        .cmp(&dataset_kind_order(right_dataset_kind))
        .then_with(|| cmp_chain_scope(left_scope, right_scope))
        .then_with(|| cmp_range(left_range, right_range))
        .then_with(|| left_row_count.cmp(&right_row_count))
        .then_with(|| left_cid.cmp(right_cid))
}

fn cmp_range(left: &IndexedArtifactRange, right: &IndexedArtifactRange) -> Ordering {
    range_kind_order(left.kind)
        .cmp(&range_kind_order(right.kind))
        .then_with(|| left.start.cmp(&right.start))
        .then_with(|| left.end.cmp(&right.end))
}

const fn chain_type_order(value: ChainType) -> u8 {
    match value {
        ChainType::Evm => 0,
    }
}

const fn dataset_kind_order(value: IndexedDatasetKind) -> u8 {
    match value {
        IndexedDatasetKind::WalletScan => 0,
        IndexedDatasetKind::Commitments => 1,
        IndexedDatasetKind::MerkleCheckpoint => 2,
        IndexedDatasetKind::PublicTxid => 3,
    }
}

const fn range_kind_order(value: IndexedArtifactRangeKind) -> u8 {
    match value {
        IndexedArtifactRangeKind::Block => 0,
        IndexedArtifactRangeKind::TxidIndex => 1,
        IndexedArtifactRangeKind::TreePosition => 2,
        IndexedArtifactRangeKind::PoiEventIndex => 3,
    }
}

#[must_use]
pub fn prefixed_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

#[must_use]
pub fn format_scope(scope: &ChainScope) -> String {
    format!(
        "{:?}:{}:{}",
        scope.chain_type,
        scope.chain_id,
        prefixed_hex(scope.railgun_contract.as_slice())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_signature_verifies_with_typed_scope() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let mut manifest = IndexedArtifactManifest::new(
            42,
            7,
            PublisherIdentity::ed25519(""),
            vec![IndexedArtifactChainEntry {
                scope: scope(),
                latest_indexed: vec![LatestIndexedHeight {
                    dataset_kind: IndexedDatasetKind::PublicTxid,
                    block_number: 20,
                    block_hash: FixedBytes::from([0xcc; 32]),
                }],
                catalogs: Vec::new(),
            }],
        );

        manifest.sign_manifest(&signing_key).expect("sign manifest");

        manifest
            .verify_trusted_signature(&signing_key.verifying_key().to_bytes())
            .expect("manifest verifies");
    }

    #[test]
    fn typed_fields_serialize_as_lowercase_prefixed_hex() {
        let descriptor = IndexedArtifactDescriptor {
            dataset_kind: IndexedDatasetKind::PublicTxid,
            scope: scope(),
            range: IndexedArtifactRange {
                kind: IndexedArtifactRangeKind::TxidIndex,
                start: 1,
                end: 2,
            },
            row_count: 2,
            cid: "bafy".to_string(),
            sha256: FixedBytes::from([0xab; 32]),
            byte_size: 10,
            encoding_version: CHUNK_FORMAT_VERSION,
            compression: CompressionAlgorithm::Zstd,
            metadata: DatasetDescriptorMetadata {
                root: Some(FixedBytes::from([0xcd; 32])),
                ..Default::default()
            },
        };

        let json = serde_json::to_string(&descriptor).expect("serialize descriptor");

        assert!(
            json.contains("\"railgun_contract\":\"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"")
        );
        assert!(json.contains(
            "\"sha256\":\"0xabababababababababababababababababababababababababababababababab\""
        ));
        assert!(json.contains(
            "\"root\":\"0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\""
        ));
    }

    #[test]
    fn range_intersection_is_inclusive() {
        let range = range(IndexedArtifactRangeKind::Block, 10, 20);

        assert!(range.intersects(0, 10));
        assert!(range.intersects(20, 30));
        assert!(range.intersects(12, 18));
        assert!(!range.intersects(0, 9));
        assert!(!range.intersects(21, 30));
    }

    #[test]
    fn range_intersection_rejects_inverted_ranges() {
        assert!(!range(IndexedArtifactRangeKind::Block, 10, 20).intersects(21, 20));
        assert!(!range(IndexedArtifactRangeKind::Block, 20, 10).intersects(0, 30));
    }

    #[test]
    fn descriptor_matches_dataset_scope_and_range_kind() {
        let scope = scope();
        let mut other_scope = scope.clone();
        other_scope.chain_id = 2;
        let descriptor = descriptor(
            IndexedDatasetKind::PublicTxid,
            scope.clone(),
            IndexedArtifactRangeKind::TxidIndex,
            10,
            20,
        );

        assert!(descriptor.matches(
            IndexedDatasetKind::PublicTxid,
            &scope,
            IndexedArtifactRangeKind::TxidIndex,
        ));
        assert!(!descriptor.matches(
            IndexedDatasetKind::WalletScan,
            &scope,
            IndexedArtifactRangeKind::TxidIndex,
        ));
        assert!(!descriptor.matches(
            IndexedDatasetKind::PublicTxid,
            &scope,
            IndexedArtifactRangeKind::Block,
        ));
        assert!(!descriptor.matches(
            IndexedDatasetKind::PublicTxid,
            &other_scope,
            IndexedArtifactRangeKind::TxidIndex,
        ));
    }

    #[test]
    fn descriptor_matches_range_requires_identity_and_intersection() {
        let scope = scope();
        let descriptor = descriptor(
            IndexedDatasetKind::WalletScan,
            scope.clone(),
            IndexedArtifactRangeKind::Block,
            10,
            20,
        );

        assert!(descriptor.matches_range(
            IndexedDatasetKind::WalletScan,
            &scope,
            IndexedArtifactRangeKind::Block,
            20,
            30,
        ));
        assert!(!descriptor.matches_range(
            IndexedDatasetKind::WalletScan,
            &scope,
            IndexedArtifactRangeKind::Block,
            21,
            30,
        ));
        assert!(!descriptor.matches_range(
            IndexedDatasetKind::WalletScan,
            &scope,
            IndexedArtifactRangeKind::TxidIndex,
            10,
            20,
        ));
    }

    #[test]
    fn chunk_envelope_round_trips_header_and_payload() {
        let envelope = ChunkEnvelope::new(
            ChunkEnvelopeHeader::new(
                IndexedDatasetKind::PublicTxid,
                scope(),
                IndexedArtifactRange {
                    kind: IndexedArtifactRangeKind::TxidIndex,
                    start: 0,
                    end: 2,
                },
                3,
                6,
                vec![ChunkSection {
                    section_id: 1,
                    offset: 1,
                    byte_length: 3,
                }],
            ),
            b"abcdef".to_vec(),
        );

        let encoded = envelope.encode().expect("encode envelope");
        let decoded = ChunkEnvelope::decode(&encoded).expect("decode envelope");

        assert_eq!(decoded, envelope);
        assert_eq!(decoded.section_payload(1).expect("section"), b"bcd");
    }

    #[test]
    fn chunk_planner_groups_by_size_and_range_kind() {
        let items = [
            ChunkPlanItem {
                range: range(IndexedArtifactRangeKind::Block, 0, 9),
                row_count: 10,
                compressed_byte_size: 4,
            },
            ChunkPlanItem {
                range: range(IndexedArtifactRangeKind::Block, 10, 19),
                row_count: 10,
                compressed_byte_size: 4,
            },
            ChunkPlanItem {
                range: range(IndexedArtifactRangeKind::TxidIndex, 20, 29),
                row_count: 10,
                compressed_byte_size: 4,
            },
        ];
        let planned = plan_chunks(
            &items,
            ChunkPlanningConfig {
                target_compressed_bytes: 8,
                soft_min_compressed_bytes: 4,
                soft_max_compressed_bytes: 8,
                hard_max_compressed_bytes: 16,
            },
        )
        .expect("plan chunks");

        assert_eq!(planned.len(), 2);
        assert_eq!(
            planned[0].range,
            range(IndexedArtifactRangeKind::Block, 0, 19)
        );
        assert_eq!(planned[0].item_count, 2);
        assert_eq!(
            planned[1].range,
            range(IndexedArtifactRangeKind::TxidIndex, 20, 29)
        );
    }

    fn scope() -> ChainScope {
        ChainScope {
            chain_type: ChainType::Evm,
            chain_id: 1,
            railgun_contract: Address::from([0xbb; 20]),
        }
    }

    fn range(kind: IndexedArtifactRangeKind, start: u64, end: u64) -> IndexedArtifactRange {
        IndexedArtifactRange { kind, start, end }
    }

    fn descriptor(
        dataset_kind: IndexedDatasetKind,
        scope: ChainScope,
        range_kind: IndexedArtifactRangeKind,
        start: u64,
        end: u64,
    ) -> IndexedArtifactDescriptor {
        IndexedArtifactDescriptor {
            dataset_kind,
            scope,
            range: range(range_kind, start, end),
            row_count: end.saturating_sub(start).saturating_add(1),
            cid: "bafy".to_string(),
            sha256: FixedBytes::from([0xab; 32]),
            byte_size: 10,
            encoding_version: CHUNK_FORMAT_VERSION,
            compression: CompressionAlgorithm::Zstd,
            metadata: DatasetDescriptorMetadata::default(),
        }
    }
}
