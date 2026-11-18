//! The error type for indexed artifact retrieval and verification.

#[allow(clippy::wildcard_imports)]
use super::*;

#[derive(Debug, Error)]
pub enum IndexedArtifactManifestError {
    #[error("indexed artifact JSON decode failed")]
    Json(#[from] serde_json::Error),
    #[error("indexed artifact trustless retrieval failed: {message}")]
    Trustless { message: String },
    #[error("unsupported indexed artifact manifest version {version}")]
    UnsupportedManifestVersion { version: u16 },
    #[error("unsupported indexed artifact catalog version {version}")]
    UnsupportedCatalogVersion { version: u16 },
    #[error("indexed artifact publisher public key mismatch: expected {expected}, got {actual}")]
    PublisherKeyMismatch { expected: String, actual: String },
    #[error("indexed artifact manifest publisher signature is missing")]
    MissingPublisherSignature,
    #[error("invalid indexed artifact publisher public key")]
    PublicKey {
        source: ed25519_dalek::SignatureError,
    },
    #[error("indexed artifact manifest signature verification failed")]
    Signature {
        source: ed25519_dalek::SignatureError,
    },
    #[error("invalid indexed artifact hex: {message}")]
    Hex { message: String },
    #[error(
        "indexed artifact manifest sequence rollback: previous={previous}, received={received}"
    )]
    ManifestSequenceRollback { previous: u64, received: u64 },
    #[error("indexed artifact manifest is stale: age={age:?}, max={max:?}")]
    ManifestStale { age: Duration, max: Duration },
    #[error("indexed artifact manifest issued_at_ms is in the future")]
    ManifestIssuedInFuture,
    #[error("indexed artifact manifest has no valid candidate")]
    NoValidManifest,
    #[error(
        "indexed artifact manifest does not contain chain scope chain_id={chain_id} contract={railgun_contract}"
    )]
    MissingChainScope {
        chain_id: u64,
        railgun_contract: String,
    },
    #[error("indexed artifact catalog scope mismatch: expected {expected}, got {actual}")]
    CatalogScopeMismatch { expected: String, actual: String },
    #[error("indexed artifact catalog dataset mismatch: expected {expected:?}, got {actual:?}")]
    CatalogDatasetMismatch {
        expected: IndexedDatasetKind,
        actual: IndexedDatasetKind,
    },
    #[error(
        "indexed artifact catalog chunk dataset mismatch: expected {expected:?}, got {actual:?}"
    )]
    CatalogChunkDatasetMismatch {
        expected: IndexedDatasetKind,
        actual: IndexedDatasetKind,
    },
    #[error(
        "indexed artifact catalog chunk range {chunk_start}-{chunk_end} is outside catalog range {catalog_start}-{catalog_end}"
    )]
    CatalogChunkRangeMismatch {
        catalog_start: u64,
        catalog_end: u64,
        chunk_start: u64,
        chunk_end: u64,
    },
    #[error("indexed artifact catalog {cid} range start {start} exceeds end {end}")]
    CatalogDescriptorInvalidRange { cid: String, start: u64, end: u64 },
    #[error("indexed artifact catalog chunk {cid} range start {start} exceeds end {end}")]
    CatalogChunkInvalidRange { cid: String, start: u64, end: u64 },
    #[error(
        "indexed artifact catalog aggregate range mismatch: expected {expected_start}-{expected_end}, got {actual_start}-{actual_end}"
    )]
    CatalogAggregateRangeMismatch {
        expected_start: u64,
        expected_end: u64,
        actual_start: u64,
        actual_end: u64,
    },
    #[error(
        "indexed artifact catalog aggregate row count mismatch: expected {expected}, got {actual}"
    )]
    CatalogAggregateRowCountMismatch { expected: u64, actual: u64 },
    #[error("indexed artifact catalog aggregate row count overflowed for catalog {cid}")]
    CatalogAggregateRowCountOverflow { cid: String },
    #[error("empty indexed artifact catalog {cid} has non-zero row count {row_count}")]
    EmptyCatalogRowCountMismatch { cid: String, row_count: u64 },
    #[error("indexed artifact byte size overflows u64")]
    ByteSizeOverflow,
    #[error("indexed artifact {cid} byte size mismatch: expected {expected}, got {actual}")]
    ArtifactByteSizeMismatch {
        cid: String,
        expected: u64,
        actual: u64,
    },
    #[error("indexed artifact {cid} sha256 mismatch: expected {expected}, got {actual}")]
    ArtifactHashMismatch {
        cid: String,
        expected: String,
        actual: String,
    },
    #[error("indexed artifact chunk byte size {actual} exceeds maximum {maximum}")]
    ChunkTooLarge { actual: u64, maximum: u64 },
    #[error("indexed artifact decoded chunk envelope byte size {actual} exceeds maximum {maximum}")]
    ChunkDecodedEnvelopeTooLarge { actual: u64, maximum: u64 },
    #[error("indexed artifact chunk decompression failed")]
    ChunkDecompression { source: std::io::Error },
    #[error("indexed artifact chunk has wrong magic bytes")]
    WrongChunkMagic,
    #[error("unsupported indexed artifact chunk version {version}")]
    UnsupportedChunkVersion { version: u16 },
    #[error("unknown indexed artifact chunk dataset kind id {value}")]
    UnknownChunkDatasetKind { value: u8 },
    #[error("unknown indexed artifact chunk chain type id {value}")]
    UnknownChunkChainType { value: u8 },
    #[error("unknown indexed artifact chunk range kind id {value}")]
    UnknownChunkRangeKind { value: u8 },
    #[error("indexed artifact chunk ended while reading {field}")]
    ChunkUnexpectedEof { field: &'static str },
    #[error("indexed artifact chunk field {field} is not utf8")]
    ChunkInvalidUtf8 {
        field: &'static str,
        #[source]
        source: std::str::Utf8Error,
    },
    #[error(
        "indexed artifact chunk uncompressed length mismatch: expected {expected}, got {actual}"
    )]
    ChunkUncompressedLengthMismatch { expected: u64, actual: u64 },
    #[error("indexed artifact chunk section {section_id} range overflows u64")]
    ChunkSectionRangeOverflow { section_id: u16 },
    #[error("indexed artifact chunk section {section_id} appears more than once")]
    ChunkDuplicateSection { section_id: u16 },
    #[error(
        "indexed artifact chunk section {second_section_id} byte range [{second_start}, {second_end}) overlaps section {first_section_id} byte range [{first_start}, {first_end})"
    )]
    ChunkOverlappingSections {
        first_section_id: u16,
        first_start: u64,
        first_end: u64,
        second_section_id: u16,
        second_start: u64,
        second_end: u64,
    },
    #[error(
        "indexed artifact chunk section {section_id} is out of bounds: offset {offset}, length {byte_length}, payload length {payload_len}"
    )]
    ChunkSectionOutOfBounds {
        section_id: u16,
        offset: u64,
        byte_length: u64,
        payload_len: u64,
    },
    #[error("indexed artifact chunk section {section_id} is missing")]
    ChunkSectionMissing { section_id: u16 },
    #[error(
        "indexed artifact chunk descriptor encoding version mismatch: expected {expected}, got {actual}"
    )]
    ChunkDescriptorEncodingVersionMismatch { expected: u16, actual: u16 },
    #[error(
        "indexed artifact chunk descriptor dataset mismatch: expected {expected:?}, got {actual:?}"
    )]
    ChunkDescriptorDatasetMismatch {
        expected: IndexedDatasetKind,
        actual: IndexedDatasetKind,
    },
    #[error("indexed artifact chunk descriptor scope mismatch: expected {expected}, got {actual}")]
    ChunkDescriptorScopeMismatch { expected: String, actual: String },
    #[error(
        "indexed artifact chunk descriptor range mismatch: expected {expected_start}-{expected_end}, got {actual_start}-{actual_end}"
    )]
    ChunkDescriptorRangeMismatch {
        expected_start: u64,
        expected_end: u64,
        actual_start: u64,
        actual_end: u64,
    },
    #[error(
        "indexed artifact chunk descriptor row count mismatch: expected {expected}, got {actual}"
    )]
    ChunkDescriptorRowCountMismatch { expected: u64, actual: u64 },
    #[error(
        "indexed artifact chunk descriptor byte size mismatch: expected {expected}, got {actual}"
    )]
    ChunkDescriptorByteSizeMismatch { expected: u64, actual: u64 },
    #[error(
        "indexed artifact chunk descriptor decoded envelope byte size mismatch: expected {expected}, got {actual}"
    )]
    ChunkDescriptorDecodedEnvelopeByteSizeMismatch { expected: u64, actual: u64 },
    #[error("indexed artifact chunk format failed: {message}")]
    ChunkFormat { message: String },
    #[error("indexed artifact chunk concurrency must be greater than zero")]
    InvalidChunkConcurrency,
    #[error(
        "indexed artifact chunk {cid} resource charge {byte_size} exceeds in-flight byte budget {max_in_flight_bytes}"
    )]
    ChunkExceedsInFlightBudget {
        cid: String,
        byte_size: u64,
        max_in_flight_bytes: u64,
    },
    #[error(
        "indexed artifact staged chunk dataset mismatch: expected {expected:?}, got {actual:?}"
    )]
    StagedChunkDatasetMismatch {
        expected: IndexedDatasetKind,
        actual: IndexedDatasetKind,
    },
    #[error("indexed artifact staged chunk scope mismatch: expected {expected}, got {actual}")]
    StagedChunkScopeMismatch { expected: String, actual: String },
    #[error(
        "indexed artifact staged chunk range kind mismatch: expected {expected:?}, got {actual:?}"
    )]
    StagedChunkRangeKindMismatch {
        expected: IndexedArtifactRangeKind,
        actual: IndexedArtifactRangeKind,
    },
    #[error("indexed artifact staged chunk range start {start} exceeds end {end}")]
    StagedChunkInvalidRange { start: u64, end: u64 },
    #[error(
        "indexed artifact staged chunk range {chunk_start}-{chunk_end} is before next required start {next_range_start}"
    )]
    StagedChunkBeforeProgress {
        next_range_start: u64,
        chunk_start: u64,
        chunk_end: u64,
    },
    #[error("indexed artifact staged chunk range start {start} is already staged")]
    StagedChunkDuplicateRangeStart { start: u64 },
    #[error(
        "indexed artifact staged chunk range {chunk_start}-{chunk_end} overlaps staged range {existing_start}-{existing_end}"
    )]
    StagedChunkRangeOverlap {
        existing_start: u64,
        existing_end: u64,
        chunk_start: u64,
        chunk_end: u64,
    },
    #[error("indexed artifact staged chunk range end {end} cannot advance next range start")]
    StagedChunkRangeEndOverflow { end: u64 },
}

impl From<TrustlessArtifactError> for IndexedArtifactManifestError {
    fn from(source: TrustlessArtifactError) -> Self {
        Self::Trustless {
            message: source.to_string(),
        }
    }
}

impl From<IndexedArtifactError> for IndexedArtifactManifestError {
    fn from(source: IndexedArtifactError) -> Self {
        match source {
            IndexedArtifactError::Json(source) => Self::Json(source),
            IndexedArtifactError::PublisherKeyMismatch { expected, actual } => {
                Self::PublisherKeyMismatch { expected, actual }
            }
            IndexedArtifactError::MissingPublisherSignature => Self::MissingPublisherSignature,
            IndexedArtifactError::PublicKey(source) => Self::PublicKey { source },
            IndexedArtifactError::Signature(source) => Self::Signature { source },
            IndexedArtifactError::Hex(message) => Self::Hex { message },
        }
    }
}

impl From<IndexedArtifactChunkError> for IndexedArtifactManifestError {
    fn from(source: IndexedArtifactChunkError) -> Self {
        match source {
            IndexedArtifactChunkError::WrongMagic => Self::WrongChunkMagic,
            IndexedArtifactChunkError::UnsupportedFormatVersion(version) => {
                Self::UnsupportedChunkVersion { version }
            }
            IndexedArtifactChunkError::UnknownDatasetKind(value) => {
                Self::UnknownChunkDatasetKind { value }
            }
            IndexedArtifactChunkError::UnknownChainType(value) => {
                Self::UnknownChunkChainType { value }
            }
            IndexedArtifactChunkError::UnknownRangeKind(value) => {
                Self::UnknownChunkRangeKind { value }
            }
            IndexedArtifactChunkError::UnexpectedEof { field } => {
                Self::ChunkUnexpectedEof { field }
            }
            IndexedArtifactChunkError::Hex(message) => Self::Hex { message },
            IndexedArtifactChunkError::StringTooLong { field, length } => Self::ChunkFormat {
                message: format!("string field {field} length {length} exceeds u16"),
            },
            IndexedArtifactChunkError::InvalidUtf8 { field, source } => {
                Self::ChunkInvalidUtf8 { field, source }
            }
            IndexedArtifactChunkError::PayloadTooLarge => Self::ByteSizeOverflow,
            IndexedArtifactChunkError::ChunkTooLarge { actual, maximum } => {
                Self::ChunkTooLarge { actual, maximum }
            }
            IndexedArtifactChunkError::DecodedEnvelopeTooLarge { actual, maximum } => {
                Self::ChunkDecodedEnvelopeTooLarge { actual, maximum }
            }
            IndexedArtifactChunkError::InvalidChunkPlanningConfig {
                soft_min,
                target,
                soft_max,
                hard_max,
            } => Self::ChunkFormat {
                message: format!(
                    "invalid chunk planning config: soft_min={soft_min}, target={target}, soft_max={soft_max}, hard_max={hard_max}"
                ),
            },
            IndexedArtifactChunkError::InvalidChunkPlanRange { start, end } => Self::ChunkFormat {
                message: format!("chunk plan item range start {start} exceeds end {end}"),
            },
            IndexedArtifactChunkError::ChunkPlanItemTooLarge { actual, maximum } => {
                Self::ChunkFormat {
                    message: format!(
                        "chunk plan item compressed byte size {actual} exceeds maximum {maximum}"
                    ),
                }
            }
            IndexedArtifactChunkError::ChunkPlanningOverflow => Self::ChunkFormat {
                message: "chunk planning byte count overflowed".to_string(),
            },
            IndexedArtifactChunkError::DescriptorByteSizeMismatch { expected, actual } => {
                Self::ChunkDescriptorByteSizeMismatch { expected, actual }
            }
            IndexedArtifactChunkError::DescriptorDecodedEnvelopeByteSizeMismatch {
                expected,
                actual,
            } => Self::ChunkDescriptorDecodedEnvelopeByteSizeMismatch { expected, actual },
            IndexedArtifactChunkError::DescriptorEncodingVersionMismatch { expected, actual } => {
                Self::ChunkDescriptorEncodingVersionMismatch { expected, actual }
            }
            IndexedArtifactChunkError::DescriptorDatasetKindMismatch { expected, actual } => {
                Self::ChunkDescriptorDatasetMismatch { expected, actual }
            }
            IndexedArtifactChunkError::DescriptorScopeMismatch { expected, actual } => {
                Self::ChunkDescriptorScopeMismatch { expected, actual }
            }
            IndexedArtifactChunkError::DescriptorRangeMismatch {
                expected_start,
                expected_end,
                actual_start,
                actual_end,
            } => Self::ChunkDescriptorRangeMismatch {
                expected_start,
                expected_end,
                actual_start,
                actual_end,
            },
            IndexedArtifactChunkError::DescriptorRowCountMismatch { expected, actual } => {
                Self::ChunkDescriptorRowCountMismatch { expected, actual }
            }
            IndexedArtifactChunkError::Compression(source) => Self::ChunkDecompression { source },
            IndexedArtifactChunkError::TooManySections { count } => Self::ChunkFormat {
                message: format!("chunk has {count} sections, exceeding u16"),
            },
            IndexedArtifactChunkError::DuplicateSection { section_id } => {
                Self::ChunkDuplicateSection { section_id }
            }
            IndexedArtifactChunkError::OverlappingSections {
                first_section_id,
                first_start,
                first_end,
                second_section_id,
                second_start,
                second_end,
            } => Self::ChunkOverlappingSections {
                first_section_id,
                first_start,
                first_end,
                second_section_id,
                second_start,
                second_end,
            },
            IndexedArtifactChunkError::UncompressedLengthMismatch { expected, actual } => {
                Self::ChunkUncompressedLengthMismatch { expected, actual }
            }
            IndexedArtifactChunkError::SectionRangeOverflow { section_id } => {
                Self::ChunkSectionRangeOverflow { section_id }
            }
            IndexedArtifactChunkError::SectionOutOfBounds {
                section_id,
                offset,
                byte_length,
                payload_len,
            } => Self::ChunkSectionOutOfBounds {
                section_id,
                offset,
                byte_length,
                payload_len,
            },
            IndexedArtifactChunkError::SectionMissing { section_id } => {
                Self::ChunkSectionMissing { section_id }
            }
        }
    }
}
