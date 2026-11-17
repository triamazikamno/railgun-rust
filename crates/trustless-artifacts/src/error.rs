//! Errors of trustless artifact retrieval and the HTTP sources and phases they name.

use chrono::Utc;
use cid::Cid;
use libp2p_identity::PeerId;
use thiserror::Error;

use crate::car::UnixFsDataType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustlessHttpSource {
    ExplicitManifest,
    Gateway { index: usize, count: usize },
}

impl std::fmt::Display for TrustlessHttpSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExplicitManifest => formatter.write_str("explicit manifest"),
            Self::Gateway { index, count } => {
                write!(formatter, "gateway {index} of {count}")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustlessHttpPhase {
    ResponseHeaders,
    ResponseBody,
}

impl std::fmt::Display for TrustlessHttpPhase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ResponseHeaders => formatter.write_str("response headers"),
            Self::ResponseBody => formatter.write_str("response body"),
        }
    }
}

#[derive(Debug, Error)]
pub enum TrustlessArtifactError {
    #[error("POI artifact source has no gateway URLs configured")]
    NoGateways,
    #[error("invalid CID")]
    InvalidCid {
        #[source]
        source: cid::Error,
    },
    #[error("POI artifact HTTP {origin} failed during {phase}")]
    Http {
        origin: TrustlessHttpSource,
        phase: TrustlessHttpPhase,
        #[source]
        error: reqwest::Error,
    },
    #[error("POI artifact HTTP {origin} timed out waiting for {phase}")]
    HttpTimeout {
        origin: TrustlessHttpSource,
        phase: TrustlessHttpPhase,
    },
    #[error("POI artifact HTTP {origin} exceeded the total attempt deadline")]
    HttpAttemptDeadline { origin: TrustlessHttpSource },
    #[error("POI artifact HTTP {origin} returned {status}")]
    HttpStatus {
        origin: TrustlessHttpSource,
        status: reqwest::StatusCode,
    },
    #[error("POI artifact response from {origin} exceeds {limit} bytes")]
    ResponseTooLarge {
        origin: TrustlessHttpSource,
        limit: usize,
    },
    #[error("POI artifact CAR decode failed")]
    Car(#[from] rs_car::CarDecodeError),
    #[error("POI artifact CAR is malformed: {0}")]
    MalformedCar(String),
    #[error("POI artifact CAR block CID decode failed")]
    InvalidCarCid {
        #[source]
        source: cid::Error,
    },
    #[error("POI artifact CAR roots do not include requested CID {requested}")]
    CarRootMissing { requested: Cid },
    #[error("POI artifact CAR exceeds {limit} blocks")]
    TooManyCarBlocks { limit: usize },
    #[error("POI artifact CAR is missing block {cid}")]
    MissingBlock { cid: Cid },
    #[error("POI artifact CID {cid} uses unsupported codec {codec:#x}")]
    UnsupportedCodec { cid: Cid, codec: u64 },
    #[error("CID {cid} uses unsupported multihash code {code:#x}")]
    UnsupportedMultihash { cid: Cid, code: u64 },
    #[error("raw CID {cid} bytes failed multihash verification")]
    RawCidDigestMismatch { cid: Cid },
    #[error("POI artifact DAG-PB decode failed")]
    DagPb(#[from] ipld_dagpb::Error),
    #[error("POI artifact UnixFS Data decode failed")]
    UnixFsData(#[from] quick_protobuf::Error),
    #[error("unsupported UnixFS node type {data_type:?}")]
    UnsupportedUnixFsType { data_type: UnixFsDataType },
    #[error("malformed UnixFS file layout: {0}")]
    MalformedUnixFsFile(&'static str),
    #[error("cycle detected while reconstructing UnixFS CID {cid}")]
    Cycle { cid: Cid },
    #[error("UnixFS reconstruction exceeds depth limit {limit}")]
    UnixFsDepthLimitExceeded { limit: usize },
    #[error("UnixFS reconstruction exceeds followed-link limit {limit}")]
    UnixFsLinkVisitLimitExceeded { limit: usize },
    #[error("reconstructed POI artifact bytes exceed {limit} bytes")]
    ReconstructedTooLarge { limit: usize },
    #[error("artifact descriptor byte_size {byte_size} is too large for this platform")]
    DescriptorByteSizeTooLarge { byte_size: u64 },
    #[error("artifact retrieval limits overflowed")]
    RetrievalLimitOverflow,
    #[error("IPNS record exceeds {limit} bytes")]
    IpnsRecordTooLarge { limit: usize },
    #[error("invalid IPNS record")]
    InvalidIpnsRecord {
        #[source]
        source: std::io::Error,
    },
    #[error("invalid IPNS record signature")]
    InvalidIpnsSignature {
        #[source]
        source: rust_ipns::Error,
    },
    #[error("IPNS record uses unsupported validity type")]
    UnsupportedIpnsValidity,
    #[error("IPNS record expired at {eol}")]
    ExpiredIpnsRecord { eol: chrono::DateTime<Utc> },
    #[error("unsupported IPNS record value: {0}")]
    UnsupportedIpnsValue(&'static str),
    #[error("unsupported IPNS name {name}")]
    UnsupportedIpnsName { name: String },
    #[error("invalid IPNS peer ID")]
    InvalidIpnsPeerId {
        #[source]
        source: libp2p_identity::ParseError,
    },
    #[error("invalid IPNS record public key")]
    InvalidIpnsPublicKey {
        #[source]
        source: libp2p_identity::DecodingError,
    },
    #[error("IPNS record public key peer ID {actual} does not match configured name {expected}")]
    IpnsPublicKeyMismatch {
        expected: Box<PeerId>,
        actual: Box<PeerId>,
    },
    #[error("no valid IPNS records were returned by configured gateways")]
    NoValidIpnsRecords,
}

#[derive(Debug, Error)]
#[error("verified CID fetch failed")]
pub struct VerifiedCidError {
    #[source]
    source: TrustlessArtifactError,
}

impl From<TrustlessArtifactError> for VerifiedCidError {
    fn from(source: TrustlessArtifactError) -> Self {
        Self { source }
    }
}
