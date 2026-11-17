//! The POI v4 artifact format error.

use thiserror::Error;

use crate::artifacts::manifest::ManifestError;
use crate::artifacts::verify::VerifyError;

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
