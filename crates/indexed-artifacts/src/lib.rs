use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
};

use alloy_primitives::{Address, FixedBytes, hex};
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
    pub publisher_signature: Option<FixedBytes<64>>,
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
            PublisherIdentity::ed25519(FixedBytes::from(signing_key.verifying_key().to_bytes()));
        let body_bytes = self.deterministic_body_bytes()?;
        self.publisher_signature = Some(FixedBytes::from(signing_key.sign(&body_bytes).to_bytes()));
        Ok(())
    }

    pub fn verify_signature(&self) -> Result<(), IndexedArtifactError> {
        match self.publisher.key_algorithm {
            PublisherKeyAlgorithm::Ed25519 => {
                self.verify_signature_with_key(&self.publisher.public_key.0)
            }
        }
    }

    pub fn verify_trusted_signature(
        &self,
        trusted_publisher_pubkey: &[u8; 32],
    ) -> Result<(), IndexedArtifactError> {
        if self.publisher.public_key.as_slice() != trusted_publisher_pubkey.as_slice() {
            return Err(IndexedArtifactError::PublisherKeyMismatch {
                expected: hex::encode_prefixed(trusted_publisher_pubkey),
                actual: hex::encode_prefixed(self.publisher.public_key.as_slice()),
            });
        }

        self.verify_signature_with_key(trusted_publisher_pubkey)
    }

    fn verify_signature_with_key(
        &self,
        pubkey_bytes: &[u8; 32],
    ) -> Result<(), IndexedArtifactError> {
        let signature_bytes = self
            .publisher_signature
            .as_ref()
            .ok_or(IndexedArtifactError::MissingPublisherSignature)?;
        let verifying_key =
            VerifyingKey::from_bytes(pubkey_bytes).map_err(IndexedArtifactError::PublicKey)?;
        let signature = Signature::from_bytes(&signature_bytes.0);
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
    pub public_key: FixedBytes<32>,
}

impl PublisherIdentity {
    #[must_use]
    pub fn ed25519(public_key: FixedBytes<32>) -> Self {
        Self {
            key_algorithm: PublisherKeyAlgorithm::Ed25519,
            public_key,
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

    #[must_use]
    pub fn with_inherited_catalog_generation(mut self, catalog: &Self) -> Self {
        self.metadata.catalog_generation = catalog.metadata.catalog_generation;
        self
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

impl CompressionAlgorithm {
    const fn sort_key(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Zstd => 1,
        }
    }
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
    #[serde(default)]
    pub catalog_generation: Option<u64>,
    #[serde(default)]
    pub stream_partition: Option<String>,
    #[serde(default)]
    pub stream_complete: bool,
    #[serde(default)]
    pub chunk_sealed: bool,
}

impl DatasetDescriptorMetadata {
    fn cmp_for_descriptor(&self, other: &Self) -> Ordering {
        self.root
            .as_ref()
            .map(FixedBytes::as_slice)
            .cmp(&other.root.as_ref().map(FixedBytes::as_slice))
            .then_with(|| self.checkpoint_block.cmp(&other.checkpoint_block))
            .then_with(|| self.tree_number.cmp(&other.tree_number))
            .then_with(|| self.leaf_count.cmp(&other.leaf_count))
            .then_with(|| self.start_block.cmp(&other.start_block))
            .then_with(|| self.end_block.cmp(&other.end_block))
            .then_with(|| self.last_indexed_block.cmp(&other.last_indexed_block))
            .then_with(|| self.catalog_generation.cmp(&other.catalog_generation))
            .then_with(|| self.stream_partition.cmp(&other.stream_partition))
            .then_with(|| self.stream_complete.cmp(&other.stream_complete))
            .then_with(|| self.chunk_sealed.cmp(&other.chunk_sealed))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexedArtifactStreamPartitionPolicy {
    Ignore,
    Exact(String),
    Unpartitioned,
}

impl IndexedArtifactStreamPartitionPolicy {
    fn matches_descriptor(&self, descriptor: &IndexedArtifactDescriptor) -> bool {
        self.matches_partition(descriptor.stream_partition_for_identity())
    }

    fn matches_partition(&self, partition: Option<&str>) -> bool {
        match self {
            Self::Ignore => true,
            Self::Exact(expected) => partition == Some(expected.as_str()),
            Self::Unpartitioned => partition.is_none(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedArtifactStreamPlanRequest {
    pub dataset_kind: IndexedDatasetKind,
    pub scope: ChainScope,
    pub range_kind: IndexedArtifactRangeKind,
    pub start: u64,
    pub end: u64,
    pub partition_policy: IndexedArtifactStreamPartitionPolicy,
}

impl IndexedArtifactStreamPlanRequest {
    #[must_use]
    pub fn new(
        dataset_kind: IndexedDatasetKind,
        scope: ChainScope,
        range_kind: IndexedArtifactRangeKind,
        start: u64,
        end: u64,
        partition_policy: IndexedArtifactStreamPartitionPolicy,
    ) -> Self {
        Self {
            dataset_kind,
            scope,
            range_kind,
            start,
            end,
            partition_policy,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedArtifactStreamCatalog {
    pub descriptor: IndexedArtifactDescriptor,
    pub chunks: Vec<IndexedArtifactDescriptor>,
}

impl IndexedArtifactStreamCatalog {
    #[must_use]
    pub fn new(
        descriptor: IndexedArtifactDescriptor,
        chunks: Vec<IndexedArtifactDescriptor>,
    ) -> Self {
        Self { descriptor, chunks }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IndexedArtifactStreamPlan {
    pub required_current_chunks: Vec<IndexedArtifactDescriptor>,
    pub required_current_coverage: Vec<IndexedArtifactDescriptor>,
    pub optional_prior_tail_retention: Vec<IndexedArtifactDescriptor>,
}

impl IndexedArtifactStreamPlan {
    pub fn plan(
        catalogs: &[IndexedArtifactStreamCatalog],
        request: &IndexedArtifactStreamPlanRequest,
    ) -> Result<Self, IndexedArtifactStreamPlanError> {
        if request.start > request.end {
            return Err(IndexedArtifactStreamPlanError::InvalidRequestRange {
                start: request.start,
                end: request.end,
            });
        }

        let mut streams: BTreeMap<ArtifactStreamKey, StreamPlanInput> = BTreeMap::new();
        for catalog in catalogs.iter().filter(|catalog| {
            catalog
                .descriptor
                .matches(request.dataset_kind, &request.scope, request.range_kind)
        }) {
            let descriptor = &catalog.descriptor;
            if descriptor.range.start > descriptor.range.end {
                return Err(IndexedArtifactStreamPlanError::InvalidDescriptorRange {
                    cid: descriptor.cid.clone(),
                    start: descriptor.range.start,
                    end: descriptor.range.end,
                });
            }
            let generation = descriptor.metadata.catalog_generation.ok_or_else(|| {
                IndexedArtifactStreamPlanError::MissingCatalogGeneration {
                    cid: descriptor.cid.clone(),
                }
            })?;
            if request.partition_policy.matches_descriptor(descriptor) {
                let catalog_stream_key = ArtifactStreamKey::from_descriptor(descriptor);
                streams
                    .entry(catalog_stream_key.clone())
                    .or_default()
                    .coverage
                    .push(StreamCoverageEntry::new(
                        descriptor.clone(),
                        generation,
                        catalog_stream_key,
                    ));
            }
            for chunk in catalog.chunks.iter().filter(|chunk| {
                chunk.matches(request.dataset_kind, &request.scope, request.range_kind)
                    && request.partition_policy.matches_descriptor(chunk)
            }) {
                if chunk.range.start > chunk.range.end {
                    return Err(IndexedArtifactStreamPlanError::InvalidDescriptorRange {
                        cid: chunk.cid.clone(),
                        start: chunk.range.start,
                        end: chunk.range.end,
                    });
                }
                let stream_key = ArtifactStreamKey::from_descriptor(chunk);
                streams
                    .entry(stream_key.clone())
                    .or_default()
                    .entries
                    .push(StreamPlanEntry::new(
                        chunk.clone().with_inherited_catalog_generation(descriptor),
                        generation,
                        stream_key,
                    ));
            }
        }

        let mut required_current_chunks = Vec::new();
        let mut required_current_coverage = Vec::new();
        let mut optional_prior_tail_retention = Vec::new();
        for (stream_key, input) in streams {
            let stream_plan = ArtifactStreamPlanner::plan(stream_key, input, request)?;
            required_current_chunks.extend(stream_plan.required_current_chunks);
            required_current_coverage.extend(stream_plan.required_current_coverage);
            optional_prior_tail_retention.extend(stream_plan.optional_prior_tail_retention);
        }

        required_current_chunks.sort_by(cmp_descriptor);
        required_current_coverage.sort_by(cmp_descriptor);
        optional_prior_tail_retention.sort_by(cmp_descriptor);
        Ok(Self {
            required_current_chunks,
            required_current_coverage,
            optional_prior_tail_retention,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ArtifactStreamKey {
    dataset_kind: IndexedDatasetKind,
    chain_type: ChainType,
    chain_id: u64,
    railgun_contract: Address,
    range_kind: IndexedArtifactRangeKind,
    partition: Option<String>,
}

impl ArtifactStreamKey {
    fn from_descriptor(descriptor: &IndexedArtifactDescriptor) -> Self {
        Self {
            dataset_kind: descriptor.dataset_kind,
            chain_type: descriptor.scope.chain_type,
            chain_id: descriptor.scope.chain_id,
            railgun_contract: descriptor.scope.railgun_contract,
            range_kind: descriptor.range.kind,
            partition: descriptor
                .stream_partition_for_identity()
                .map(str::to_string),
        }
    }

    fn validate_generation_ranges(
        &self,
        generation: u64,
        entries: &[StreamPlanEntry],
    ) -> Result<(), IndexedArtifactStreamPlanError> {
        for window in entries.windows(2) {
            let left = &window[0].descriptor;
            let right = &window[1].descriptor;
            if left.range.intersects(right.range.start, right.range.end) {
                return Err(IndexedArtifactStreamPlanError::SameGenerationOverlap {
                    generation,
                    partition: self.partition.clone(),
                    left_start: left.range.start,
                    left_end: left.range.end,
                    right_start: right.range.start,
                    right_end: right.range.end,
                });
            }
        }
        Ok(())
    }

    fn validate_generation_coverage_ranges(
        &self,
        generation: u64,
        entries: &[StreamCoverageEntry],
    ) -> Result<(), IndexedArtifactStreamPlanError> {
        for window in entries.windows(2) {
            let left = &window[0].descriptor;
            let right = &window[1].descriptor;
            if left.range.intersects(right.range.start, right.range.end) {
                return Err(IndexedArtifactStreamPlanError::SameGenerationOverlap {
                    generation,
                    partition: self.partition.clone(),
                    left_start: left.range.start,
                    left_end: left.range.end,
                    right_start: right.range.start,
                    right_end: right.range.end,
                });
            }
        }
        Ok(())
    }
}

impl Ord for ArtifactStreamKey {
    fn cmp(&self, other: &Self) -> Ordering {
        dataset_kind_order(self.dataset_kind)
            .cmp(&dataset_kind_order(other.dataset_kind))
            .then_with(|| {
                chain_type_order(self.chain_type).cmp(&chain_type_order(other.chain_type))
            })
            .then_with(|| self.chain_id.cmp(&other.chain_id))
            .then_with(|| {
                self.railgun_contract
                    .as_slice()
                    .cmp(other.railgun_contract.as_slice())
            })
            .then_with(|| {
                range_kind_order(self.range_kind).cmp(&range_kind_order(other.range_kind))
            })
            .then_with(|| self.partition.cmp(&other.partition))
    }
}

impl PartialOrd for ArtifactStreamKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StreamPlanEntry {
    descriptor: IndexedArtifactDescriptor,
    generation: u64,
    stream_key: ArtifactStreamKey,
    final_in_generation: bool,
}

impl StreamPlanEntry {
    fn new(
        descriptor: IndexedArtifactDescriptor,
        generation: u64,
        stream_key: ArtifactStreamKey,
    ) -> Self {
        Self {
            descriptor,
            generation,
            stream_key,
            final_in_generation: false,
        }
    }

    fn mark_final(entries: &mut [Self]) {
        if let Some(final_entry) = entries.last_mut() {
            final_entry.final_in_generation = true;
        }
    }

    fn cmp_for_plan(left: &Self, right: &Self) -> Ordering {
        left.stream_key
            .cmp(&right.stream_key)
            .then_with(|| cmp_range(&left.descriptor.range, &right.descriptor.range))
            .then_with(|| left.generation.cmp(&right.generation))
            .then_with(|| left.descriptor.cid.cmp(&right.descriptor.cid))
    }

    const fn is_replaceable_final(&self) -> bool {
        self.final_in_generation
            && !self.descriptor.metadata.chunk_sealed
            && !self.descriptor.metadata.stream_complete
    }

    const fn is_complete_tail(&self) -> bool {
        self.final_in_generation && self.descriptor.metadata.stream_complete
    }

    const fn is_explicitly_stable(&self) -> bool {
        !self.final_in_generation
            || self.descriptor.metadata.chunk_sealed
            || self.descriptor.metadata.stream_complete
    }

    fn is_currently_replaceable(&self, current: &[Self]) -> bool {
        self.is_replaceable_final() && !self.is_followed_by_current_chunk(current)
    }

    fn is_currently_stable(&self, current: &[Self]) -> bool {
        self.is_explicitly_stable() || self.is_followed_by_current_chunk(current)
    }

    fn is_followed_by_current_chunk(&self, current: &[Self]) -> bool {
        current.iter().any(|other| {
            other.stream_key == self.stream_key
                && other.descriptor.range.start > self.descriptor.range.end
        })
    }

    fn requested_overlap(
        &self,
        request: &IndexedArtifactStreamPlanRequest,
    ) -> Option<SupersededRequestedRange> {
        if self.descriptor.range.intersects(request.start, request.end) {
            Some(SupersededRequestedRange {
                stream_key: self.stream_key.clone(),
                start: self.descriptor.range.start.max(request.start),
                end: self.descriptor.range.end.min(request.end),
            })
        } else {
            None
        }
    }

    fn is_retainable_prior_tail(&self, current: &[Self]) -> bool {
        self.is_explicitly_stable()
            || current.iter().any(|other| {
                other.stream_key == self.stream_key
                    && other.generation > self.generation
                    && other.descriptor.range.start > self.descriptor.range.end
            })
    }
}

#[derive(Default)]
struct StreamPlanInput {
    entries: Vec<StreamPlanEntry>,
    coverage: Vec<StreamCoverageEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StreamCoverageEntry {
    descriptor: IndexedArtifactDescriptor,
    generation: u64,
    stream_key: ArtifactStreamKey,
}

impl StreamCoverageEntry {
    fn new(
        descriptor: IndexedArtifactDescriptor,
        generation: u64,
        stream_key: ArtifactStreamKey,
    ) -> Self {
        Self {
            descriptor,
            generation,
            stream_key,
        }
    }

    fn cmp_for_plan(left: &Self, right: &Self) -> Ordering {
        left.stream_key
            .cmp(&right.stream_key)
            .then_with(|| cmp_range(&left.descriptor.range, &right.descriptor.range))
            .then_with(|| left.generation.cmp(&right.generation))
            .then_with(|| left.descriptor.cid.cmp(&right.descriptor.cid))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SupersededRequestedRange {
    stream_key: ArtifactStreamKey,
    start: u64,
    end: u64,
}

impl SupersededRequestedRange {
    fn is_covered_by(&self, entries: &[StreamPlanEntry], coverage: &[StreamCoverageEntry]) -> bool {
        let mut ranges = entries
            .iter()
            .filter(|entry| entry.stream_key == self.stream_key)
            .map(|entry| (entry.descriptor.range.start, entry.descriptor.range.end))
            .chain(
                coverage
                    .iter()
                    .filter(|entry| entry.stream_key == self.stream_key)
                    .map(|entry| (entry.descriptor.range.start, entry.descriptor.range.end)),
            )
            .filter(|(start, end)| *start <= self.end && self.start <= *end)
            .collect::<Vec<_>>();
        ranges.sort_unstable();

        let mut cursor = self.start;
        for (start, end) in ranges {
            if start > cursor {
                return false;
            }
            if end >= self.end {
                return true;
            }
            cursor = end.saturating_add(1);
        }
        false
    }
}

struct ArtifactStreamPlanner<'a> {
    request: &'a IndexedArtifactStreamPlanRequest,
    stream_key: ArtifactStreamKey,
    current: Vec<StreamPlanEntry>,
    current_coverage: Vec<StreamCoverageEntry>,
    complete_tail_end: Option<u64>,
    superseded_requested_ranges: Vec<SupersededRequestedRange>,
}

impl<'a> ArtifactStreamPlanner<'a> {
    fn plan(
        stream_key: ArtifactStreamKey,
        input: StreamPlanInput,
        request: &'a IndexedArtifactStreamPlanRequest,
    ) -> Result<IndexedArtifactStreamPlan, IndexedArtifactStreamPlanError> {
        let mut planner = Self {
            request,
            stream_key,
            current: Vec::new(),
            current_coverage: Vec::new(),
            complete_tail_end: None,
            superseded_requested_ranges: Vec::new(),
        };

        let mut by_generation: BTreeMap<u64, Vec<StreamPlanEntry>> = BTreeMap::new();
        for entry in input.entries {
            by_generation
                .entry(entry.generation)
                .or_default()
                .push(entry);
        }
        let mut coverage_by_generation: BTreeMap<u64, Vec<StreamCoverageEntry>> = BTreeMap::new();
        for coverage in input.coverage {
            coverage_by_generation
                .entry(coverage.generation)
                .or_default()
                .push(coverage);
        }
        for generation in coverage_by_generation.keys() {
            by_generation.entry(*generation).or_default();
        }

        for (generation, mut generation_entries) in by_generation {
            let mut generation_coverage = coverage_by_generation
                .remove(&generation)
                .unwrap_or_default();
            generation_entries
                .sort_by(|left, right| cmp_descriptor(&left.descriptor, &right.descriptor));
            generation_coverage.sort_by(StreamCoverageEntry::cmp_for_plan);
            planner
                .stream_key
                .validate_generation_ranges(generation, &generation_entries)?;
            planner
                .stream_key
                .validate_generation_coverage_ranges(generation, &generation_coverage)?;
            StreamPlanEntry::mark_final(&mut generation_entries);

            for entry in generation_entries {
                planner.apply_entry(entry)?;
            }
            for coverage in generation_coverage {
                planner.apply_coverage(coverage)?;
            }
        }

        planner.finish()
    }

    fn apply_coverage(
        &mut self,
        coverage: StreamCoverageEntry,
    ) -> Result<(), IndexedArtifactStreamPlanError> {
        self.reject_if_extends_complete_tail(coverage.descriptor.range.end)?;
        if let Some(complete_tail) = self
            .current
            .iter()
            .find(|current| current.is_complete_tail())
            && coverage.descriptor.range.end > complete_tail.descriptor.range.end
        {
            return Err(IndexedArtifactStreamPlanError::StreamCompleteExtended {
                complete_end: complete_tail.descriptor.range.end,
                attempted_end: coverage.descriptor.range.end,
            });
        }

        let mut remove_indexes = Vec::new();
        for (index, existing) in self.current.iter().enumerate() {
            if !existing.descriptor.range.intersects(
                coverage.descriptor.range.start,
                coverage.descriptor.range.end,
            ) {
                continue;
            }

            if existing.is_currently_replaceable(&self.current)
                && coverage.generation > existing.generation
            {
                if let Some(superseded) = existing.requested_overlap(self.request) {
                    self.superseded_requested_ranges.push(superseded);
                }
                remove_indexes.push(index);
            }
        }

        for index in remove_indexes.into_iter().rev() {
            self.current.remove(index);
        }

        self.current_coverage.retain(|existing| {
            !existing.descriptor.range.intersects(
                coverage.descriptor.range.start,
                coverage.descriptor.range.end,
            ) || existing.generation >= coverage.generation
        });
        if self.current_coverage.iter().all(|existing| {
            existing.generation != coverage.generation
                || !existing.descriptor.range.intersects(
                    coverage.descriptor.range.start,
                    coverage.descriptor.range.end,
                )
        }) {
            if coverage.descriptor.metadata.stream_complete {
                self.mark_complete_tail(coverage.descriptor.range.end);
            }
            self.current_coverage.push(coverage);
        }
        Ok(())
    }

    fn apply_entry(
        &mut self,
        entry: StreamPlanEntry,
    ) -> Result<(), IndexedArtifactStreamPlanError> {
        self.reject_if_extends_complete_tail(entry.descriptor.range.end)?;
        if let Some(complete_tail) = self
            .current
            .iter()
            .find(|current| current.is_complete_tail())
            && entry.descriptor.range.end > complete_tail.descriptor.range.end
        {
            return Err(IndexedArtifactStreamPlanError::StreamCompleteExtended {
                complete_end: complete_tail.descriptor.range.end,
                attempted_end: entry.descriptor.range.end,
            });
        }

        let mut remove_indexes = Vec::new();
        let mut skip_entry = false;
        for (index, existing) in self.current.iter().enumerate() {
            if !existing
                .descriptor
                .range
                .intersects(entry.descriptor.range.start, entry.descriptor.range.end)
            {
                continue;
            }

            if existing.is_currently_replaceable(&self.current)
                && entry.generation > existing.generation
            {
                if let Some(superseded) = existing.requested_overlap(self.request) {
                    self.superseded_requested_ranges.push(superseded);
                }
                remove_indexes.push(index);
                continue;
            }

            if existing.is_currently_stable(&self.current)
                && existing
                    .descriptor
                    .has_same_stream_content(&entry.descriptor)
            {
                skip_entry = true;
                break;
            }

            return Err(IndexedArtifactStreamPlanError::StableChunkConflict {
                existing_start: existing.descriptor.range.start,
                existing_end: existing.descriptor.range.end,
                attempted_start: entry.descriptor.range.start,
                attempted_end: entry.descriptor.range.end,
            });
        }

        for index in remove_indexes.into_iter().rev() {
            self.current.remove(index);
        }
        if !skip_entry {
            if entry.descriptor.metadata.stream_complete {
                self.mark_complete_tail(entry.descriptor.range.end);
            }
            self.current.push(entry);
        }
        Ok(())
    }

    fn reject_if_extends_complete_tail(
        &self,
        attempted_end: u64,
    ) -> Result<(), IndexedArtifactStreamPlanError> {
        if let Some(complete_end) = self.complete_tail_end
            && attempted_end > complete_end
        {
            return Err(IndexedArtifactStreamPlanError::StreamCompleteExtended {
                complete_end,
                attempted_end,
            });
        }
        Ok(())
    }

    fn mark_complete_tail(&mut self, complete_end: u64) {
        self.complete_tail_end = Some(
            self.complete_tail_end
                .map_or(complete_end, |existing| existing.min(complete_end)),
        );
    }

    fn finish(mut self) -> Result<IndexedArtifactStreamPlan, IndexedArtifactStreamPlanError> {
        self.current.sort_by(StreamPlanEntry::cmp_for_plan);
        self.current_coverage
            .sort_by(StreamCoverageEntry::cmp_for_plan);
        for superseded in self.superseded_requested_ranges {
            if !superseded.is_covered_by(&self.current, &self.current_coverage) {
                return Err(
                    IndexedArtifactStreamPlanError::SupersededRequestedRangeGap {
                        start: superseded.start,
                        end: superseded.end,
                    },
                );
            }
        }

        let mut required_current_chunks = Vec::new();
        let mut required_current_coverage = Vec::new();
        let mut optional_prior_tail_retention = Vec::new();
        for entry in &self.current {
            if entry
                .descriptor
                .range
                .intersects(self.request.start, self.request.end)
            {
                required_current_chunks.push(entry.descriptor.clone());
                required_current_coverage.push(entry.descriptor.clone());
            } else if entry.descriptor.range.end < self.request.start
                && entry.is_retainable_prior_tail(&self.current)
            {
                optional_prior_tail_retention.push(entry.descriptor.clone());
            }
        }
        required_current_coverage.extend(
            self.current_coverage
                .into_iter()
                .filter(|entry| {
                    entry
                        .descriptor
                        .range
                        .intersects(self.request.start, self.request.end)
                })
                .map(|entry| entry.descriptor),
        );

        Ok(IndexedArtifactStreamPlan {
            required_current_chunks,
            required_current_coverage,
            optional_prior_tail_retention,
        })
    }
}

impl IndexedArtifactDescriptor {
    fn stream_partition_for_identity(&self) -> Option<&str> {
        if self.dataset_kind == IndexedDatasetKind::WalletScan
            && self.range.kind == IndexedArtifactRangeKind::Block
        {
            None
        } else {
            self.metadata.stream_partition.as_deref()
        }
    }

    fn has_same_stream_content(&self, other: &Self) -> bool {
        self.dataset_kind == other.dataset_kind
            && self.scope == other.scope
            && self.range == other.range
            && self.row_count == other.row_count
            && self.cid == other.cid
            && self.sha256 == other.sha256
            && self.byte_size == other.byte_size
            && self.encoding_version == other.encoding_version
            && self.compression == other.compression
            && self.metadata.root == other.metadata.root
            && self.metadata.checkpoint_block == other.metadata.checkpoint_block
            && self.metadata.tree_number == other.metadata.tree_number
            && self.metadata.leaf_count == other.metadata.leaf_count
            && self.metadata.start_block == other.metadata.start_block
            && self.metadata.end_block == other.metadata.end_block
            && self.metadata.last_indexed_block == other.metadata.last_indexed_block
            && self.stream_partition_for_identity() == other.stream_partition_for_identity()
            && self.metadata.stream_complete == other.metadata.stream_complete
            && self.metadata.chunk_sealed == other.metadata.chunk_sealed
    }
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
            &hex::encode_prefixed(self.header.scope.railgun_contract.as_slice()),
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
        let mut section_ids = BTreeSet::new();
        let mut section_ranges = Vec::with_capacity(self.sections.len());
        if self.uncompressed_length != payload_len {
            return Err(ChunkError::UncompressedLengthMismatch {
                expected: self.uncompressed_length,
                actual: payload_len,
            });
        }
        for section in &self.sections {
            if !section_ids.insert(section.section_id) {
                return Err(ChunkError::DuplicateSection {
                    section_id: section.section_id,
                });
            }
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
            if section.byte_length > 0 {
                section_ranges.push((section.offset, end, section.section_id));
            }
        }
        section_ranges.sort_unstable_by_key(|range| (range.0, range.1, range.2));
        for window in section_ranges.windows(2) {
            let previous = window[0];
            let current = window[1];
            if current.0 < previous.1 {
                return Err(ChunkError::OverlappingSections {
                    first_section_id: previous.2,
                    first_start: previous.0,
                    first_end: previous.1,
                    second_section_id: current.2,
                    second_start: current.0,
                    second_end: current.1,
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
pub enum IndexedArtifactStreamPlanError {
    #[error("artifact stream plan request range start {start} exceeds end {end}")]
    InvalidRequestRange { start: u64, end: u64 },
    #[error("artifact stream descriptor {cid} range start {start} exceeds end {end}")]
    InvalidDescriptorRange { cid: String, start: u64, end: u64 },
    #[error("artifact stream descriptor {cid} is missing catalog generation")]
    MissingCatalogGeneration { cid: String },
    #[error(
        "artifact stream generation {generation} has overlapping chunks for partition {partition:?}: {left_start}-{left_end} overlaps {right_start}-{right_end}"
    )]
    SameGenerationOverlap {
        generation: u64,
        partition: Option<String>,
        left_start: u64,
        left_end: u64,
        right_start: u64,
        right_end: u64,
    },
    #[error(
        "artifact stream stable chunk {existing_start}-{existing_end} conflicts with attempted chunk {attempted_start}-{attempted_end}"
    )]
    StableChunkConflict {
        existing_start: u64,
        existing_end: u64,
        attempted_start: u64,
        attempted_end: u64,
    },
    #[error(
        "artifact stream complete tail ending at {complete_end} was extended to {attempted_end}"
    )]
    StreamCompleteExtended {
        complete_end: u64,
        attempted_end: u64,
    },
    #[error("artifact stream superseded requested range {start}-{end} is not covered")]
    SupersededRequestedRangeGap { start: u64, end: u64 },
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
    #[error("chunk section {section_id} appears more than once")]
    DuplicateSection { section_id: u16 },
    #[error(
        "chunk section {second_section_id} byte range [{second_start}, {second_end}) overlaps section {first_section_id} byte range [{first_start}, {first_end})"
    )]
    OverlappingSections {
        first_section_id: u16,
        first_start: u64,
        first_end: u64,
        second_section_id: u16,
        second_start: u64,
        second_end: u64,
    },
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
    .then_with(|| left.metadata.cmp_for_descriptor(&right.metadata))
    .then_with(|| left.sha256.as_slice().cmp(right.sha256.as_slice()))
    .then_with(|| left.byte_size.cmp(&right.byte_size))
    .then_with(|| left.encoding_version.cmp(&right.encoding_version))
    .then_with(|| {
        left.compression
            .sort_key()
            .cmp(&right.compression.sort_key())
    })
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
pub fn format_scope(scope: &ChainScope) -> String {
    format!(
        "{:?}:{}:{}",
        scope.chain_type,
        scope.chain_id,
        hex::encode_prefixed(scope.railgun_contract.as_slice())
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
            PublisherIdentity::ed25519(FixedBytes::ZERO),
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
                catalog_generation: Some(9),
                stream_partition: Some("txid-v3:list-a".to_string()),
                stream_complete: true,
                chunk_sealed: true,
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
        assert!(json.contains("\"catalog_generation\":9"));
        assert!(json.contains("\"stream_partition\":\"txid-v3:list-a\""));
        assert!(json.contains("\"stream_complete\":true"));
        assert!(json.contains("\"chunk_sealed\":true"));
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
    fn chunk_envelope_rejects_duplicate_section_ids() {
        let header = ChunkEnvelopeHeader::new(
            IndexedDatasetKind::PublicTxid,
            scope(),
            IndexedArtifactRange {
                kind: IndexedArtifactRangeKind::TxidIndex,
                start: 0,
                end: 1,
            },
            2,
            2,
            vec![
                ChunkSection {
                    section_id: 1,
                    offset: 0,
                    byte_length: 1,
                },
                ChunkSection {
                    section_id: 1,
                    offset: 1,
                    byte_length: 1,
                },
            ],
        );

        let error = header
            .validate_for_payload(b"ab")
            .expect_err("duplicate section id should fail validation");

        assert!(matches!(
            error,
            ChunkError::DuplicateSection { section_id: 1 }
        ));
    }

    #[test]
    fn chunk_envelope_rejects_overlapping_section_ranges() {
        let header = ChunkEnvelopeHeader::new(
            IndexedDatasetKind::WalletScan,
            scope(),
            IndexedArtifactRange {
                kind: IndexedArtifactRangeKind::Block,
                start: 0,
                end: 1,
            },
            2,
            6,
            vec![
                ChunkSection {
                    section_id: 1,
                    offset: 0,
                    byte_length: 4,
                },
                ChunkSection {
                    section_id: 2,
                    offset: 3,
                    byte_length: 2,
                },
            ],
        );

        let error = header
            .validate_for_payload(b"abcdef")
            .expect_err("overlapping section ranges should fail validation");

        assert!(matches!(
            error,
            ChunkError::OverlappingSections {
                first_section_id: 1,
                first_start: 0,
                first_end: 4,
                second_section_id: 2,
                second_start: 3,
                second_end: 5,
            }
        ));
    }

    #[test]
    fn chunk_envelope_accepts_adjacent_section_ranges() {
        let envelope = ChunkEnvelope::new(
            ChunkEnvelopeHeader::new(
                IndexedDatasetKind::WalletScan,
                scope(),
                IndexedArtifactRange {
                    kind: IndexedArtifactRangeKind::Block,
                    start: 0,
                    end: 1,
                },
                2,
                6,
                vec![
                    ChunkSection {
                        section_id: 1,
                        offset: 0,
                        byte_length: 3,
                    },
                    ChunkSection {
                        section_id: 2,
                        offset: 3,
                        byte_length: 3,
                    },
                ],
            ),
            b"abcdef".to_vec(),
        );

        let decoded = ChunkEnvelope::decode(&envelope.encode().expect("encode envelope"))
            .expect("decode adjacent sections");

        assert_eq!(decoded.section_payload(1).expect("first section"), b"abc");
        assert_eq!(decoded.section_payload(2).expect("second section"), b"def");
    }

    #[test]
    fn chunk_envelope_accepts_unsorted_non_overlapping_section_ranges() {
        let envelope = ChunkEnvelope::new(
            ChunkEnvelopeHeader::new(
                IndexedDatasetKind::WalletScan,
                scope(),
                IndexedArtifactRange {
                    kind: IndexedArtifactRangeKind::Block,
                    start: 0,
                    end: 1,
                },
                2,
                6,
                vec![
                    ChunkSection {
                        section_id: 2,
                        offset: 3,
                        byte_length: 3,
                    },
                    ChunkSection {
                        section_id: 1,
                        offset: 0,
                        byte_length: 3,
                    },
                ],
            ),
            b"abcdef".to_vec(),
        );

        let decoded = ChunkEnvelope::decode(&envelope.encode().expect("encode envelope"))
            .expect("decode unsorted sections");

        assert_eq!(decoded.section_payload(1).expect("first section"), b"abc");
        assert_eq!(decoded.section_payload(2).expect("second section"), b"def");
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

    #[test]
    fn stream_planner_replaces_extends_and_consolidates_superseded_final_tails() {
        for (old_start, old_end, new_start, new_end) in
            [(10, 19, 10, 19), (10, 19, 10, 24), (10, 19, 0, 24)]
        {
            let old = StreamFixture::descriptor(
                IndexedDatasetKind::WalletScan,
                IndexedArtifactRangeKind::Block,
                old_start,
                old_end,
                1,
            );
            let new = StreamFixture::descriptor(
                IndexedDatasetKind::WalletScan,
                IndexedArtifactRangeKind::Block,
                new_start,
                new_end,
                2,
            );
            let request = StreamFixture::request(
                IndexedDatasetKind::WalletScan,
                IndexedArtifactRangeKind::Block,
                new_start,
                new_end,
            );

            let plan = plan_from_descriptors(&[old.clone(), new.clone()], &request)
                .expect("plan canonical stream");
            let reversed_plan = plan_from_descriptors(&[new.clone(), old.clone()], &request)
                .expect("plan canonical stream from reversed input");

            assert_eq!(required_cids(&plan), vec![new.cid.clone()]);
            assert_eq!(plan, reversed_plan);
            assert_non_overlapping(&plan.required_current_chunks);
        }
    }

    #[test]
    fn stream_planner_empty_catalog_replaces_superseded_final_tail() {
        let old_tail = StreamFixture::descriptor(
            IndexedDatasetKind::WalletScan,
            IndexedArtifactRangeKind::Block,
            100,
            110,
            1,
        );
        let empty_replacement = empty_catalog(
            IndexedDatasetKind::WalletScan,
            IndexedArtifactRangeKind::Block,
            100,
            110,
            2,
        );

        let plan = IndexedArtifactStreamPlan::plan(
            &[
                catalog_for_descriptors(Some(1), vec![old_tail]),
                empty_replacement,
            ],
            &StreamFixture::request(
                IndexedDatasetKind::WalletScan,
                IndexedArtifactRangeKind::Block,
                100,
                110,
            ),
        )
        .expect("empty replacement catalog covers superseded tail");

        assert!(plan.required_current_chunks.is_empty());
        assert_eq!(coverage_ranges(&plan), vec![(100, 110)]);
    }

    #[test]
    fn stream_planner_empty_catalog_does_not_suppress_stable_chunks() {
        let sealed_tail = StreamFixture::descriptor(
            IndexedDatasetKind::WalletScan,
            IndexedArtifactRangeKind::Block,
            100,
            110,
            1,
        )
        .sealed();
        let empty_replacement = empty_catalog(
            IndexedDatasetKind::WalletScan,
            IndexedArtifactRangeKind::Block,
            100,
            110,
            2,
        );

        let plan = IndexedArtifactStreamPlan::plan(
            &[
                catalog_for_descriptors(Some(1), vec![sealed_tail.clone()]),
                empty_replacement,
            ],
            &StreamFixture::request(
                IndexedDatasetKind::WalletScan,
                IndexedArtifactRangeKind::Block,
                100,
                110,
            ),
        )
        .expect("empty coverage does not replace sealed chunks");

        assert_eq!(required_cids(&plan), vec![sealed_tail.cid]);
    }

    #[test]
    fn stream_planner_empty_catalog_rejects_partial_superseded_tail_coverage() {
        let old_tail = StreamFixture::descriptor(
            IndexedDatasetKind::WalletScan,
            IndexedArtifactRangeKind::Block,
            100,
            110,
            1,
        );
        let partial_empty_replacement = empty_catalog(
            IndexedDatasetKind::WalletScan,
            IndexedArtifactRangeKind::Block,
            105,
            110,
            2,
        );

        assert!(matches!(
            IndexedArtifactStreamPlan::plan(
                &[
                    catalog_for_descriptors(Some(1), vec![old_tail]),
                    partial_empty_replacement,
                ],
                &StreamFixture::request(
                    IndexedDatasetKind::WalletScan,
                    IndexedArtifactRangeKind::Block,
                    100,
                    110,
                ),
            ),
            Err(
                IndexedArtifactStreamPlanError::SupersededRequestedRangeGap {
                    start: 100,
                    end: 110
                }
            )
        ));
    }

    #[test]
    fn stream_planner_retains_prior_tail_only_after_later_chunk_seals_it() {
        let old_tail = StreamFixture::descriptor(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            0,
            9,
            1,
        );
        let request = StreamFixture::request(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            10,
            19,
        );

        let plan_without_later = plan_from_descriptors(std::slice::from_ref(&old_tail), &request)
            .expect("plan without later chunk");

        assert!(plan_without_later.required_current_chunks.is_empty());
        assert!(plan_without_later.optional_prior_tail_retention.is_empty());

        let current_tail = StreamFixture::descriptor(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            10,
            19,
            2,
        );
        let plan = plan_from_descriptors(&[current_tail.clone(), old_tail.clone()], &request)
            .expect("plan with later chunk");

        assert_eq!(required_cids(&plan), vec![current_tail.cid.clone()]);
        assert_eq!(optional_cids(&plan), vec![old_tail.cid.clone()]);
    }

    #[test]
    fn stream_planner_rejects_repack_after_prior_tail_becomes_non_final() {
        let old_tail = StreamFixture::descriptor(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            0,
            9,
            1,
        );
        let later_chunk = StreamFixture::descriptor(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            10,
            19,
            2,
        );
        let illegal_repack = StreamFixture::descriptor(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            5,
            14,
            3,
        );

        assert!(matches!(
            plan_from_descriptors(
                &[old_tail, later_chunk, illegal_repack],
                &StreamFixture::request(
                    IndexedDatasetKind::PublicTxid,
                    IndexedArtifactRangeKind::TxidIndex,
                    5,
                    14,
                ),
            ),
            Err(IndexedArtifactStreamPlanError::StableChunkConflict {
                existing_start: 0,
                existing_end: 9,
                attempted_start: 5,
                attempted_end: 14,
            })
        ));
    }

    #[test]
    fn stream_planner_rejects_missing_generation_and_superseded_requested_range_gaps() {
        let missing_generation = descriptor(
            IndexedDatasetKind::PublicTxid,
            scope(),
            IndexedArtifactRangeKind::TxidIndex,
            0,
            9,
        );
        let request = StreamFixture::request(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            0,
            9,
        );

        assert!(matches!(
            plan_from_descriptors(&[missing_generation], &request),
            Err(IndexedArtifactStreamPlanError::MissingCatalogGeneration { .. })
        ));

        let old_tail = StreamFixture::descriptor(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            0,
            19,
            1,
        );
        let partial_replacement = StreamFixture::descriptor(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            10,
            19,
            2,
        );
        let requested_gap = StreamFixture::request(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            0,
            19,
        );

        assert!(matches!(
            plan_from_descriptors(&[old_tail, partial_replacement], &requested_gap),
            Err(IndexedArtifactStreamPlanError::SupersededRequestedRangeGap { start: 0, end: 19 })
        ));
    }

    #[test]
    fn stream_planner_keeps_sealed_tails_and_enforces_complete_terminal_tails() {
        let sealed_tail = StreamFixture::descriptor(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            0,
            9,
            1,
        )
        .sealed();
        let next_tail = StreamFixture::descriptor(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            10,
            19,
            2,
        );
        let sealed_request = StreamFixture::request(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            0,
            9,
        );

        let plan = plan_from_descriptors(&[next_tail, sealed_tail.clone()], &sealed_request)
            .expect("sealed tail remains current");

        assert_eq!(required_cids(&plan), vec![sealed_tail.cid.clone()]);

        let conflicting_replacement = StreamFixture::descriptor(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            0,
            9,
            2,
        );
        assert!(matches!(
            plan_from_descriptors(&[sealed_tail, conflicting_replacement], &sealed_request),
            Err(IndexedArtifactStreamPlanError::StableChunkConflict { .. })
        ));

        let complete_tail = StreamFixture::descriptor(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            0,
            9,
            1,
        )
        .complete();
        let mut repeated_complete = complete_tail.clone();
        repeated_complete.metadata.catalog_generation = Some(2);

        plan_from_descriptors(
            &[complete_tail.clone(), repeated_complete],
            &StreamFixture::request(
                IndexedDatasetKind::PublicTxid,
                IndexedArtifactRangeKind::TxidIndex,
                0,
                9,
            ),
        )
        .expect("identical complete tail may repeat");

        let extension_after_complete = StreamFixture::descriptor(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            10,
            19,
            2,
        );
        assert!(matches!(
            plan_from_descriptors(
                &[complete_tail, extension_after_complete],
                &StreamFixture::request(
                    IndexedDatasetKind::PublicTxid,
                    IndexedArtifactRangeKind::TxidIndex,
                    10,
                    19,
                ),
            ),
            Err(IndexedArtifactStreamPlanError::StreamCompleteExtended {
                complete_end: 9,
                attempted_end: 19
            })
        ));
    }

    #[test]
    fn stream_planner_rejects_empty_coverage_after_complete_tail() {
        let complete_tail = StreamFixture::descriptor(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            0,
            9,
            1,
        )
        .complete();
        let catalogs = vec![
            catalog_for_descriptors(Some(1), vec![complete_tail]),
            empty_catalog(
                IndexedDatasetKind::PublicTxid,
                IndexedArtifactRangeKind::TxidIndex,
                10,
                19,
                2,
            ),
        ];

        assert!(matches!(
            IndexedArtifactStreamPlan::plan(
                &catalogs,
                &StreamFixture::request(
                    IndexedDatasetKind::PublicTxid,
                    IndexedArtifactRangeKind::TxidIndex,
                    10,
                    19,
                ),
            ),
            Err(IndexedArtifactStreamPlanError::StreamCompleteExtended {
                complete_end: 9,
                attempted_end: 19
            })
        ));
    }

    #[test]
    fn stream_planner_rejects_complete_metadata_on_non_final_chunks() {
        let first_chunk = StreamFixture::descriptor(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            0,
            9,
            1,
        )
        .complete();
        let final_chunk = StreamFixture::descriptor(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            10,
            19,
            1,
        )
        .complete();

        assert!(matches!(
            plan_from_descriptors(
                &[first_chunk.clone(), final_chunk.clone()],
                &StreamFixture::request(
                    IndexedDatasetKind::PublicTxid,
                    IndexedArtifactRangeKind::TxidIndex,
                    0,
                    19,
                ),
            ),
            Err(IndexedArtifactStreamPlanError::StreamCompleteExtended {
                complete_end: 9,
                attempted_end: 19
            })
        ));

        let extension_after_complete = StreamFixture::descriptor(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            20,
            29,
            2,
        );
        assert!(matches!(
            plan_from_descriptors(
                &[first_chunk, final_chunk, extension_after_complete],
                &StreamFixture::request(
                    IndexedDatasetKind::PublicTxid,
                    IndexedArtifactRangeKind::TxidIndex,
                    20,
                    29,
                ),
            ),
            Err(IndexedArtifactStreamPlanError::StreamCompleteExtended {
                complete_end: 9,
                attempted_end: 19
            })
        ));
    }

    #[test]
    fn stream_planner_rejects_complete_coverage_followed_by_extension() {
        let mut complete_coverage = empty_catalog(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            0,
            9,
            1,
        );
        complete_coverage.descriptor.metadata.stream_complete = true;
        let extension = StreamFixture::descriptor(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            10,
            19,
            1,
        );

        assert!(matches!(
            IndexedArtifactStreamPlan::plan(
                &[
                    complete_coverage,
                    catalog_for_descriptors(Some(1), vec![extension]),
                ],
                &StreamFixture::request(
                    IndexedDatasetKind::PublicTxid,
                    IndexedArtifactRangeKind::TxidIndex,
                    0,
                    19,
                ),
            ),
            Err(IndexedArtifactStreamPlanError::StreamCompleteExtended {
                complete_end: 9,
                attempted_end: 19
            })
        ));
    }

    #[test]
    fn stream_planner_allows_repeated_complete_tail() {
        let first_chunk = StreamFixture::descriptor(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            0,
            9,
            1,
        )
        .complete();
        let mut repeated = first_chunk.clone();
        repeated.metadata.catalog_generation = Some(2);

        let plan = plan_from_descriptors(
            &[first_chunk.clone(), repeated.clone()],
            &StreamFixture::request(
                IndexedDatasetKind::PublicTxid,
                IndexedArtifactRangeKind::TxidIndex,
                0,
                9,
            ),
        )
        .expect("identical complete tail may repeat");

        assert_eq!(required_cids(&plan), vec![first_chunk.cid]);
    }

    #[test]
    fn stream_planner_wallet_scan_ignores_partitions_but_partitioned_datasets_are_independent() {
        let wallet_tree_a = StreamFixture::descriptor(
            IndexedDatasetKind::WalletScan,
            IndexedArtifactRangeKind::Block,
            0,
            9,
            1,
        )
        .partition("tree-a");
        let wallet_tree_b = StreamFixture::descriptor(
            IndexedDatasetKind::WalletScan,
            IndexedArtifactRangeKind::Block,
            5,
            14,
            1,
        )
        .partition("tree-b");

        assert!(matches!(
            plan_from_descriptors(
                &[wallet_tree_a, wallet_tree_b],
                &StreamFixture::request(
                    IndexedDatasetKind::WalletScan,
                    IndexedArtifactRangeKind::Block,
                    0,
                    14,
                ),
            ),
            Err(IndexedArtifactStreamPlanError::SameGenerationOverlap {
                partition: None,
                ..
            })
        ));

        let txid_partition_a = StreamFixture::descriptor(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            0,
            9,
            1,
        )
        .partition("list-a");
        let txid_partition_b = StreamFixture::descriptor(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            0,
            9,
            1,
        )
        .partition("list-b");

        let plan = plan_from_descriptors(
            &[txid_partition_b.clone(), txid_partition_a.clone()],
            &StreamFixture::partitioned_request(
                IndexedDatasetKind::PublicTxid,
                IndexedArtifactRangeKind::TxidIndex,
                0,
                9,
                "list-a",
            ),
        )
        .expect("partitioned TXID stream remains independently plannable");

        assert_eq!(required_cids(&plan), vec![txid_partition_a.cid.clone()]);
        assert_non_overlapping_by_partition(&plan.required_current_chunks);

        let plan = plan_from_descriptors(
            &[txid_partition_b.clone(), txid_partition_a.clone()],
            &StreamFixture::partitioned_request(
                IndexedDatasetKind::PublicTxid,
                IndexedArtifactRangeKind::TxidIndex,
                0,
                9,
                "list-b",
            ),
        )
        .expect("second partition remains independently plannable");

        assert_eq!(required_cids(&plan), vec![txid_partition_b.cid.clone()]);
    }

    #[test]
    fn stream_planner_exact_partition_rejects_unpartitioned_and_other_partitions() {
        let unpartitioned = StreamFixture::descriptor(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            0,
            9,
            1,
        );
        let other_partition = StreamFixture::descriptor(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            0,
            9,
            1,
        )
        .partition("list-b");

        let plan = plan_from_descriptors(
            &[unpartitioned, other_partition],
            &StreamFixture::partitioned_request(
                IndexedDatasetKind::PublicTxid,
                IndexedArtifactRangeKind::TxidIndex,
                0,
                9,
                "list-a",
            ),
        )
        .expect("irrelevant partitions are ignored");

        assert!(plan.required_current_chunks.is_empty());
        assert!(plan.required_current_coverage.is_empty());
    }

    #[test]
    fn stream_planner_deduplicates_wallet_scan_block_repeats_with_ignored_partitions() {
        let sealed_tree_a = StreamFixture::descriptor(
            IndexedDatasetKind::WalletScan,
            IndexedArtifactRangeKind::Block,
            0,
            9,
            1,
        )
        .partition("tree-a")
        .sealed();
        let mut repeated_tree_b = sealed_tree_a.clone();
        repeated_tree_b.metadata.catalog_generation = Some(2);
        repeated_tree_b.metadata.stream_partition = Some("tree-b".to_string());

        let plan = plan_from_descriptors(
            &[sealed_tree_a.clone(), repeated_tree_b],
            &StreamFixture::request(
                IndexedDatasetKind::WalletScan,
                IndexedArtifactRangeKind::Block,
                0,
                9,
            ),
        )
        .expect("ignored wallet-scan partition metadata does not conflict on identical content");

        assert_eq!(required_cids(&plan), vec![sealed_tree_a.cid.clone()]);
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

    struct StreamFixture;

    impl StreamFixture {
        fn request(
            dataset_kind: IndexedDatasetKind,
            range_kind: IndexedArtifactRangeKind,
            start: u64,
            end: u64,
        ) -> IndexedArtifactStreamPlanRequest {
            IndexedArtifactStreamPlanRequest::new(
                dataset_kind,
                scope(),
                range_kind,
                start,
                end,
                default_partition_policy(dataset_kind, range_kind),
            )
        }

        fn partitioned_request(
            dataset_kind: IndexedDatasetKind,
            range_kind: IndexedArtifactRangeKind,
            start: u64,
            end: u64,
            partition: &str,
        ) -> IndexedArtifactStreamPlanRequest {
            IndexedArtifactStreamPlanRequest::new(
                dataset_kind,
                scope(),
                range_kind,
                start,
                end,
                IndexedArtifactStreamPartitionPolicy::Exact(partition.to_string()),
            )
        }

        fn descriptor(
            dataset_kind: IndexedDatasetKind,
            range_kind: IndexedArtifactRangeKind,
            start: u64,
            end: u64,
            generation: u64,
        ) -> IndexedArtifactDescriptor {
            let mut descriptor = descriptor(dataset_kind, scope(), range_kind, start, end);
            descriptor.cid =
                format!("bafy-{dataset_kind:?}-{range_kind:?}-{generation}-{start}-{end}");
            descriptor.metadata.catalog_generation = Some(generation);
            descriptor
        }
    }

    trait StreamDescriptorTestExt {
        fn partition(self, partition: &str) -> IndexedArtifactDescriptor;
        fn sealed(self) -> IndexedArtifactDescriptor;
        fn complete(self) -> IndexedArtifactDescriptor;
    }

    impl StreamDescriptorTestExt for IndexedArtifactDescriptor {
        fn partition(mut self, partition: &str) -> IndexedArtifactDescriptor {
            self.metadata.stream_partition = Some(partition.to_string());
            self.cid = format!("{}-{partition}", self.cid);
            self
        }

        fn sealed(mut self) -> IndexedArtifactDescriptor {
            self.metadata.chunk_sealed = true;
            self
        }

        fn complete(mut self) -> IndexedArtifactDescriptor {
            self.metadata.stream_complete = true;
            self
        }
    }

    fn plan_from_descriptors(
        descriptors: &[IndexedArtifactDescriptor],
        request: &IndexedArtifactStreamPlanRequest,
    ) -> Result<IndexedArtifactStreamPlan, IndexedArtifactStreamPlanError> {
        IndexedArtifactStreamPlan::plan(&catalogs_for_descriptors(descriptors), request)
    }

    fn default_partition_policy(
        dataset_kind: IndexedDatasetKind,
        range_kind: IndexedArtifactRangeKind,
    ) -> IndexedArtifactStreamPartitionPolicy {
        if dataset_kind == IndexedDatasetKind::WalletScan
            && range_kind == IndexedArtifactRangeKind::Block
        {
            IndexedArtifactStreamPartitionPolicy::Ignore
        } else {
            IndexedArtifactStreamPartitionPolicy::Unpartitioned
        }
    }

    fn catalogs_for_descriptors(
        descriptors: &[IndexedArtifactDescriptor],
    ) -> Vec<IndexedArtifactStreamCatalog> {
        let mut by_generation: BTreeMap<Option<u64>, Vec<IndexedArtifactDescriptor>> =
            BTreeMap::new();
        for descriptor in descriptors {
            by_generation
                .entry(descriptor.metadata.catalog_generation)
                .or_default()
                .push(descriptor.clone());
        }

        by_generation
            .into_iter()
            .map(|(generation, chunks)| catalog_for_descriptors(generation, chunks))
            .collect()
    }

    fn catalog_for_descriptors(
        generation: Option<u64>,
        chunks: Vec<IndexedArtifactDescriptor>,
    ) -> IndexedArtifactStreamCatalog {
        let first = chunks.first().expect("test catalog has chunks");
        let range_start = chunks
            .iter()
            .map(|chunk| chunk.range.start)
            .min()
            .expect("catalog range start");
        let range_end = chunks
            .iter()
            .map(|chunk| chunk.range.end)
            .max()
            .expect("catalog range end");
        let row_count = chunks
            .iter()
            .map(|chunk| chunk.row_count)
            .fold(0_u64, u64::saturating_add);
        let mut descriptor = first.clone();
        descriptor.range.start = range_start;
        descriptor.range.end = range_end;
        descriptor.row_count = row_count;
        descriptor.cid = format!(
            "bafy-catalog-{}-{range_start}-{range_end}",
            generation.unwrap_or(0)
        );
        descriptor.metadata.catalog_generation = generation;
        IndexedArtifactStreamCatalog::new(descriptor, chunks)
    }

    fn empty_catalog(
        dataset_kind: IndexedDatasetKind,
        range_kind: IndexedArtifactRangeKind,
        start: u64,
        end: u64,
        generation: u64,
    ) -> IndexedArtifactStreamCatalog {
        let mut descriptor = descriptor(dataset_kind, scope(), range_kind, start, end);
        descriptor.row_count = 0;
        descriptor.cid = format!("bafy-empty-catalog-{generation}-{start}-{end}");
        descriptor.metadata.catalog_generation = Some(generation);
        IndexedArtifactStreamCatalog::new(descriptor, Vec::new())
    }

    fn required_cids(plan: &IndexedArtifactStreamPlan) -> Vec<String> {
        plan.required_current_chunks
            .iter()
            .map(|descriptor| descriptor.cid.clone())
            .collect()
    }

    fn coverage_ranges(plan: &IndexedArtifactStreamPlan) -> Vec<(u64, u64)> {
        plan.required_current_coverage
            .iter()
            .map(|descriptor| (descriptor.range.start, descriptor.range.end))
            .collect()
    }

    fn optional_cids(plan: &IndexedArtifactStreamPlan) -> Vec<String> {
        plan.optional_prior_tail_retention
            .iter()
            .map(|descriptor| descriptor.cid.clone())
            .collect()
    }

    fn assert_non_overlapping(descriptors: &[IndexedArtifactDescriptor]) {
        for window in descriptors.windows(2) {
            assert!(
                !window[0]
                    .range
                    .intersects(window[1].range.start, window[1].range.end),
                "required current chunks overlap: {:?} and {:?}",
                window[0].range,
                window[1].range
            );
        }
    }

    fn assert_non_overlapping_by_partition(descriptors: &[IndexedArtifactDescriptor]) {
        for (index, left) in descriptors.iter().enumerate() {
            for right in descriptors.iter().skip(index + 1) {
                if left.metadata.stream_partition == right.metadata.stream_partition {
                    assert!(
                        !left.range.intersects(right.range.start, right.range.end),
                        "same partition required current chunks overlap: {:?} and {:?}",
                        left.range,
                        right.range
                    );
                }
            }
        }
    }
}
