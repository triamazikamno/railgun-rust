use std::time::Duration;

use reqwest::header::HeaderValue;

mod car;
mod error;
mod fetcher;
mod http;
mod pool;

pub use car::UnixFsDataType;
pub use error::{
    TrustlessArtifactError, TrustlessHttpPhase, TrustlessHttpSource, VerifiedCidError,
};
pub use fetcher::ipns::IpnsManifestCandidate;
pub use fetcher::{
    TrustlessArtifactFetchResult, TrustlessArtifactFetcher, fetch_manifest_url, fetch_verified_cid,
    fetch_verified_cid_with_pool,
};
pub use pool::{GatewayAttempt, GatewayCapability, GatewayPool};

/// Public canonical defaults for artifact gateway consumers.
pub const DEFAULT_GATEWAYS: &[&str] = &[
    "https://dweb.link",
    "https://ipfs.filebase.io",
    "https://ipfs.io",
    "https://gateway.pinata.cloud",
];

const RAW_CODEC: u64 = 0x55;
const DAG_PB_CODEC: u64 = 0x70;
const LIBP2P_KEY_CODEC: u64 = 0x72;

const CAR_ACCEPT: HeaderValue = HeaderValue::from_static("application/vnd.ipld.car");
const RAW_ACCEPT: HeaderValue = HeaderValue::from_static("application/vnd.ipld.raw");
const IPNS_RECORD_ACCEPT: HeaderValue =
    HeaderValue::from_static("application/vnd.ipfs.ipns-record");

const MANIFEST_CAR_MAX_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MANIFEST_JSON_MAX_BYTES: usize = 2 * 1024 * 1024;
const IPNS_RECORD_MAX_BYTES: usize = 10 * 1024;
const MANIFEST_CAR_MAX_BLOCKS: usize = 1_024;
const ARTIFACT_CAR_MAX_BLOCKS: usize = 16_384;
const ARTIFACT_CAR_MIN_OVERHEAD_BYTES: usize = 1024 * 1024;
const ARTIFACT_CAR_FIXED_OVERHEAD_BYTES: usize = 64 * 1024;
/// Time allowed for a gateway to return response headers. It is shorter than
/// the idle timeout so an unreachable gateway fails fast, and leaves room for a
/// request through built-in Tor.
const ARTIFACT_HTTP_HEADERS_TIMEOUT: Duration = Duration::from_secs(15);
const ARTIFACT_HTTP_IDLE_TIMEOUT: Duration = Duration::from_mins(2);
const ARTIFACT_HTTP_TOTAL_TIMEOUT: Duration = Duration::from_mins(5);
const MAX_CONCURRENT_IPNS_GATEWAY_REQUESTS: usize = 8;
const MANIFEST_CID_HEDGE_DELAY: Duration = Duration::from_millis(750);
/// Time after the first qualifying IPNS record arrives during which other
/// gateways may still answer before the resolution phase closes.
const IPNS_EARLY_CLOSE_GRACE: Duration = Duration::from_secs(2);
/// Time without response headers after which an indexed-artifact chunk
/// attempt gets a concurrent attempt on another gateway.
const CHUNK_HEDGE_DELAY: Duration = Duration::from_secs(5);
/// Time without response headers from any running attempt after which a
/// catalog fetch starts an attempt on another gateway.
const CATALOG_HEDGE_DELAY: Duration = Duration::from_secs(2);
const GATEWAY_FAILURE_COOLDOWN: Duration = Duration::from_mins(5);
const GATEWAY_FAILURE_COOLDOWN_CAP: Duration = Duration::from_mins(15);
const CARV2_PRAGMA: [u8; 11] = [
    0x0a, 0xa1, 0x67, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x02,
];
const CARV2_HEADER_SIZE: usize = 40;
const CARV2_DATA_OFFSET_OFFSET: usize = 16;
const CARV2_DATA_SIZE_OFFSET: usize = 24;
const CARV2_PRAGMA_AND_HEADER_SIZE: usize = CARV2_PRAGMA.len() + CARV2_HEADER_SIZE;
const CAR_HEADER_MAX_BYTES: u64 = 1024 * 1024;
const CAR_BLOCK_MAX_BYTES: u64 = 1024 * 1024 * 1024;

#[cfg(test)]
mod tests;
