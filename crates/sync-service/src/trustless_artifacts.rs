use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::str;
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use chrono::Utc;
use cid::{Cid, Version};
use futures::{StreamExt, io::Cursor, stream::FuturesUnordered};
use ipld_core::{codec::Codec, ipld::Ipld};
use ipld_dagpb::{PbLink, PbNode};
use libp2p_identity::{PeerId, PublicKey};
use poi::SensitiveUrl;
use quick_protobuf::BytesReader;
use reqwest::header::{ACCEPT, HeaderValue};
use serde_ipld_dagcbor::codec::DagCborCodec;
use thiserror::Error;
use tracing::debug;
use url::Url;

const RAW_CODEC: u64 = 0x55;
const DAG_PB_CODEC: u64 = 0x70;
const LIBP2P_KEY_CODEC: u64 = 0x72;

const CAR_ACCEPT: HeaderValue = HeaderValue::from_static("application/vnd.ipld.car");
const IPNS_RECORD_ACCEPT: HeaderValue =
    HeaderValue::from_static("application/vnd.ipfs.ipns-record");

const MANIFEST_CAR_MAX_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MANIFEST_JSON_MAX_BYTES: usize = 2 * 1024 * 1024;
const IPNS_RECORD_MAX_BYTES: usize = 10 * 1024;
const MANIFEST_CAR_MAX_BLOCKS: usize = 1_024;
const ARTIFACT_CAR_MAX_BLOCKS: usize = 16_384;
const ARTIFACT_CAR_MIN_OVERHEAD_BYTES: usize = 1024 * 1024;
const ARTIFACT_CAR_FIXED_OVERHEAD_BYTES: usize = 64 * 1024;
const ARTIFACT_HTTP_IDLE_TIMEOUT: Duration = Duration::from_mins(2);
const ARTIFACT_HTTP_TOTAL_TIMEOUT: Duration = Duration::from_mins(10);
const MAX_CONCURRENT_IPNS_GATEWAY_REQUESTS: usize = 8;
const CARV2_PRAGMA: [u8; 11] = [
    0x0a, 0xa1, 0x67, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x02,
];
const CARV2_HEADER_SIZE: usize = 40;
const CARV2_DATA_OFFSET_OFFSET: usize = 16;
const CARV2_DATA_SIZE_OFFSET: usize = 24;
const CARV2_PRAGMA_AND_HEADER_SIZE: usize = CARV2_PRAGMA.len() + CARV2_HEADER_SIZE;
const CAR_HEADER_MAX_BYTES: u64 = 1024 * 1024;
const CAR_BLOCK_MAX_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IpnsManifestCandidate {
    pub(crate) sequence: u64,
    pub(crate) cid: Cid,
    eol: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone, Copy)]
struct RetrievalLimits {
    response_bytes: usize,
    block_count: usize,
    reconstructed_bytes: usize,
    unixfs_max_depth: usize,
    unixfs_max_link_visits: usize,
}

#[derive(Debug, Clone, Copy)]
struct HttpAttemptTimeouts {
    idle: Duration,
    total: Duration,
}

impl HttpAttemptTimeouts {
    const PRODUCTION: Self = Self {
        idle: ARTIFACT_HTTP_IDLE_TIMEOUT,
        total: ARTIFACT_HTTP_TOTAL_TIMEOUT,
    };
}

impl RetrievalLimits {
    const fn manifest() -> Self {
        Self {
            response_bytes: MANIFEST_CAR_MAX_BYTES,
            block_count: MANIFEST_CAR_MAX_BLOCKS,
            reconstructed_bytes: MANIFEST_JSON_MAX_BYTES,
            unixfs_max_depth: MANIFEST_CAR_MAX_BLOCKS,
            unixfs_max_link_visits: MANIFEST_CAR_MAX_BLOCKS,
        }
    }

    fn artifact(byte_size: u64) -> Result<Self, TrustlessArtifactError> {
        let reconstructed_bytes = usize::try_from(byte_size)
            .map_err(|_| TrustlessArtifactError::DescriptorByteSizeTooLarge { byte_size })?;
        let proportional_overhead = reconstructed_bytes / 8;
        let overhead = proportional_overhead
            .max(ARTIFACT_CAR_MIN_OVERHEAD_BYTES)
            .checked_add(ARTIFACT_CAR_FIXED_OVERHEAD_BYTES)
            .ok_or(TrustlessArtifactError::RetrievalLimitOverflow)?;
        let response_bytes = reconstructed_bytes
            .checked_add(overhead)
            .ok_or(TrustlessArtifactError::RetrievalLimitOverflow)?;
        Ok(Self {
            response_bytes,
            block_count: ARTIFACT_CAR_MAX_BLOCKS,
            reconstructed_bytes,
            unixfs_max_depth: ARTIFACT_CAR_MAX_BLOCKS,
            unixfs_max_link_visits: ARTIFACT_CAR_MAX_BLOCKS,
        })
    }
}

pub(crate) struct TrustlessArtifactFetcher<'a> {
    client: &'a reqwest::Client,
    gateways: GatewayUrls<'a>,
    timeouts: HttpAttemptTimeouts,
}

enum GatewayUrls<'a> {
    Public(&'a [Url]),
    Poi(&'a [SensitiveUrl]),
}

impl GatewayUrls<'_> {
    const fn len(&self) -> usize {
        match self {
            Self::Public(gateways) => gateways.len(),
            Self::Poi(gateways) => gateways.len(),
        }
    }

    const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn expose(&self, index: usize) -> &Url {
        match self {
            Self::Public(gateways) => &gateways[index],
            Self::Poi(gateways) => gateways[index].expose_url(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct TrustlessArtifactFetchResult {
    verified_cid: String,
    bytes: Vec<u8>,
    gateway_index: usize,
    gateway_count: usize,
}

impl TrustlessArtifactFetchResult {
    pub(crate) fn verified_cid(&self) -> &str {
        &self.verified_cid
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) const fn gateway_index(&self) -> usize {
        self.gateway_index
    }

    pub(crate) const fn gateway_count(&self) -> usize {
        self.gateway_count
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl<'a> TrustlessArtifactFetcher<'a> {
    pub(crate) const fn new(client: &'a reqwest::Client, gateways: &'a [Url]) -> Self {
        Self {
            client,
            gateways: GatewayUrls::Public(gateways),
            timeouts: HttpAttemptTimeouts::PRODUCTION,
        }
    }

    pub(crate) const fn new_poi(client: &'a reqwest::Client, gateways: &'a [SensitiveUrl]) -> Self {
        Self {
            client,
            gateways: GatewayUrls::Poi(gateways),
            timeouts: HttpAttemptTimeouts::PRODUCTION,
        }
    }

    pub(crate) async fn fetch_manifest_cid(
        &self,
        cid: &str,
    ) -> Result<Vec<u8>, TrustlessArtifactError> {
        let cid = parse_cid(cid)?;
        self.fetch_cid_bytes(cid, RetrievalLimits::manifest(), "manifest")
            .await
            .map(TrustlessArtifactFetchResult::into_bytes)
    }

    pub(crate) async fn fetch_artifact_cid(
        &self,
        cid: &str,
        byte_size: u64,
    ) -> Result<Vec<u8>, TrustlessArtifactError> {
        let cid = parse_cid(cid)?;
        self.fetch_cid_bytes(cid, RetrievalLimits::artifact(byte_size)?, "artifact")
            .await
            .map(TrustlessArtifactFetchResult::into_bytes)
    }

    pub(crate) async fn fetch_artifact_cid_with_metadata_from_gateway(
        &self,
        cid: &str,
        byte_size: u64,
        preferred_gateway_index: usize,
    ) -> Result<TrustlessArtifactFetchResult, TrustlessArtifactError> {
        self.fetch_artifact_cid_with_metadata_from_gateway_bounded(
            cid,
            byte_size,
            preferred_gateway_index,
            self.gateways.len(),
        )
        .await
    }

    pub(crate) async fn fetch_artifact_cid_with_metadata_from_gateway_bounded(
        &self,
        cid: &str,
        byte_size: u64,
        preferred_gateway_index: usize,
        max_gateway_attempts: usize,
    ) -> Result<TrustlessArtifactFetchResult, TrustlessArtifactError> {
        let cid = parse_cid(cid)?;
        self.fetch_cid_bytes_from_gateway(
            cid,
            RetrievalLimits::artifact(byte_size)?,
            "artifact",
            preferred_gateway_index,
            max_gateway_attempts,
        )
        .await
    }

    pub(crate) async fn resolve_ipns_manifest_candidates(
        &self,
        name: &str,
    ) -> Result<Vec<IpnsManifestCandidate>, TrustlessArtifactError> {
        self.resolve_ipns_manifest_candidates_with_clock(name, &SystemTime::now)
            .await
    }

    pub(crate) async fn resolve_ipns_manifest_candidates_with_clock<F>(
        &self,
        name: &str,
        acceptance_time: &F,
    ) -> Result<Vec<IpnsManifestCandidate>, TrustlessArtifactError>
    where
        F: Fn() -> SystemTime + Sync + ?Sized,
    {
        if self.gateways.is_empty() {
            return Err(TrustlessArtifactError::NoGateways);
        }

        let peer_id = expected_ipns_peer_id(name)?;
        let mut candidates = Vec::new();
        let mut errors = Vec::new();
        let gateway_count = self.gateways.len();
        let mut requests = FuturesUnordered::new();
        let mut next_gateway_index = 0;
        while next_gateway_index < gateway_count || !requests.is_empty() {
            while next_gateway_index < gateway_count
                && requests.len() < MAX_CONCURRENT_IPNS_GATEWAY_REQUESTS
            {
                let gateway_index = next_gateway_index;
                next_gateway_index += 1;
                let gateway = self.gateways.expose(gateway_index);
                let url = ipns_record_gateway_url(gateway, name);
                let source = TrustlessHttpSource::Gateway {
                    index: gateway_index,
                    count: gateway_count,
                };
                requests.push(async move {
                    let attempt_started = Instant::now();
                    let result = self
                        .fetch_ipns_record_candidate(&url, source, peer_id)
                        .await;
                    (gateway_index, attempt_started.elapsed().as_millis(), result)
                });
            }
            let Some((gateway_index, elapsed_ms, result)) = requests.next().await else {
                continue;
            };
            match result {
                Ok(candidate) => {
                    debug!(
                        gateway_index,
                        gateway_count,
                        ipns_name = name,
                        cid = %candidate.cid,
                        ipns_sequence = candidate.sequence,
                        elapsed_ms,
                        "POI artifact IPNS gateway returned verified record"
                    );
                    candidates.push((gateway_index, candidate));
                }
                Err(err) => {
                    debug!(
                        ?err,
                        gateway_index,
                        gateway_count,
                        ipns_name = name,
                        elapsed_ms,
                        "POI artifact IPNS gateway failed"
                    );
                    errors.push((gateway_index, err));
                }
            }
        }

        // This single post-settlement sample is authoritative; keep filtering and return synchronous.
        let accepted_at = chrono::DateTime::<Utc>::from(acceptance_time());
        candidates.retain(|(gateway_index, candidate)| {
            if candidate.eol <= accepted_at {
                debug!(
                    gateway_index,
                    gateway_count,
                    ipns_name = name,
                    ipns_sequence = candidate.sequence,
                    eol = %candidate.eol,
                    "POI artifact IPNS gateway record expired before aggregate acceptance"
                );
                errors.push((
                    *gateway_index,
                    TrustlessArtifactError::ExpiredIpnsRecord { eol: candidate.eol },
                ));
                false
            } else {
                true
            }
        });
        if candidates.is_empty() {
            return Err(errors
                .into_iter()
                .max_by_key(|(gateway_index, _)| *gateway_index)
                .map_or(TrustlessArtifactError::NoValidIpnsRecords, |(_, err)| err));
        }

        candidates.sort_by_key(|(gateway_index, candidate)| {
            (Reverse(candidate.sequence), *gateway_index)
        });
        let mut unique_candidates = Vec::with_capacity(candidates.len());
        let mut seen_candidates = HashSet::with_capacity(candidates.len());
        for (_, candidate) in candidates {
            if seen_candidates.insert((candidate.sequence, candidate.cid)) {
                unique_candidates.push(candidate);
            }
        }
        Ok(unique_candidates)
    }

    async fn fetch_cid_bytes(
        &self,
        cid: Cid,
        limits: RetrievalLimits,
        resource: &'static str,
    ) -> Result<TrustlessArtifactFetchResult, TrustlessArtifactError> {
        self.fetch_cid_bytes_from_gateway(cid, limits, resource, 0, self.gateways.len())
            .await
    }

    async fn fetch_cid_bytes_from_gateway(
        &self,
        cid: Cid,
        limits: RetrievalLimits,
        resource: &'static str,
        preferred_gateway_index: usize,
        max_gateway_attempts: usize,
    ) -> Result<TrustlessArtifactFetchResult, TrustlessArtifactError> {
        if self.gateways.is_empty() {
            return Err(TrustlessArtifactError::NoGateways);
        }

        let mut last_error = None;
        let gateway_count = self.gateways.len();
        let preferred_gateway_index = preferred_gateway_index % gateway_count;
        for attempt in 0..gateway_count.min(max_gateway_attempts.max(1)) {
            let gateway_index = (preferred_gateway_index + attempt) % gateway_count;
            let gateway = self.gateways.expose(gateway_index);
            let attempt_started = Instant::now();
            let url = car_gateway_url(gateway, &cid);
            let source = TrustlessHttpSource::Gateway {
                index: gateway_index,
                count: gateway_count,
            };
            match self
                .fetch_cid_bytes_from_url(cid, &url, source, limits)
                .await
            {
                Ok(bytes) => {
                    if attempt > 0 {
                        debug!(
                            gateway_index,
                            gateway_count,
                            preferred_gateway_index,
                            resource,
                            cid = %cid,
                            bytes = bytes.len(),
                            elapsed_ms = attempt_started.elapsed().as_millis(),
                            "POI artifact CID gateway fetch succeeded after fallback"
                        );
                    }
                    return Ok(TrustlessArtifactFetchResult {
                        verified_cid: cid.to_string(),
                        bytes,
                        gateway_index,
                        gateway_count,
                    });
                }
                Err(err) => {
                    debug!(
                        ?err,
                        gateway_index,
                        gateway_count,
                        resource,
                        cid = %cid,
                        elapsed_ms = attempt_started.elapsed().as_millis(),
                        "POI artifact CID gateway fetch failed"
                    );
                    last_error = Some(err);
                }
            }
        }

        Err(last_error.unwrap_or(TrustlessArtifactError::NoGateways))
    }

    async fn fetch_cid_bytes_from_url(
        &self,
        cid: Cid,
        url: &Url,
        source: TrustlessHttpSource,
        limits: RetrievalLimits,
    ) -> Result<Vec<u8>, TrustlessArtifactError> {
        let car_bytes = fetch_response_bytes_with_timeouts(
            self.client,
            url,
            source,
            Some(CAR_ACCEPT),
            limits.response_bytes,
            self.timeouts,
        )
        .await?;
        let blocks = decode_car_blocks(&car_bytes, cid, limits.block_count).await?;
        reconstruct_file(cid, &blocks, limits)
    }

    async fn fetch_ipns_record_candidate(
        &self,
        url: &Url,
        source: TrustlessHttpSource,
        peer_id: PeerId,
    ) -> Result<IpnsManifestCandidate, TrustlessArtifactError> {
        let bytes = fetch_response_bytes_with_timeouts(
            self.client,
            url,
            source,
            Some(IPNS_RECORD_ACCEPT),
            IPNS_RECORD_MAX_BYTES,
            self.timeouts,
        )
        .await?;
        verify_ipns_record_candidate(&bytes, peer_id)
    }
}

pub(crate) async fn fetch_manifest_url(
    client: &reqwest::Client,
    url: &Url,
) -> Result<Vec<u8>, TrustlessArtifactError> {
    fetch_response_bytes(
        client,
        url,
        TrustlessHttpSource::ExplicitManifest,
        None,
        MANIFEST_JSON_MAX_BYTES,
    )
    .await
}

async fn fetch_response_bytes(
    client: &reqwest::Client,
    url: &Url,
    source: TrustlessHttpSource,
    accept: Option<HeaderValue>,
    limit: usize,
) -> Result<Vec<u8>, TrustlessArtifactError> {
    fetch_response_bytes_with_timeouts(
        client,
        url,
        source,
        accept,
        limit,
        HttpAttemptTimeouts::PRODUCTION,
    )
    .await
}

async fn fetch_response_bytes_with_timeouts(
    client: &reqwest::Client,
    url: &Url,
    source: TrustlessHttpSource,
    accept: Option<HeaderValue>,
    limit: usize,
    timeouts: HttpAttemptTimeouts,
) -> Result<Vec<u8>, TrustlessArtifactError> {
    let deadline = tokio::time::Instant::now() + timeouts.total;
    tokio::time::timeout_at(
        deadline,
        fetch_response_bytes_with_idle_timeout(client, url, source, accept, limit, timeouts.idle),
    )
    .await
    .map_err(|_| TrustlessArtifactError::HttpAttemptDeadline { origin: source })?
}

async fn fetch_response_bytes_with_idle_timeout(
    client: &reqwest::Client,
    url: &Url,
    source: TrustlessHttpSource,
    accept: Option<HeaderValue>,
    limit: usize,
    idle_timeout: Duration,
) -> Result<Vec<u8>, TrustlessArtifactError> {
    let mut request = client.get(url.clone());
    if let Some(accept) = accept {
        request = request.header(ACCEPT, accept);
    }
    let mut response = tokio::time::timeout(idle_timeout, request.send())
        .await
        .map_err(|_| TrustlessArtifactError::HttpTimeout {
            origin: source,
            phase: TrustlessHttpPhase::ResponseHeaders,
        })?
        .map_err(|error| TrustlessArtifactError::Http {
            origin: source,
            phase: TrustlessHttpPhase::ResponseHeaders,
            error: error.without_url(),
        })?;
    let status = response.status();
    if !status.is_success() {
        return Err(TrustlessArtifactError::HttpStatus {
            origin: source,
            status,
        });
    }

    let mut bytes = Vec::new();
    while let Some(chunk) = tokio::time::timeout(idle_timeout, response.chunk())
        .await
        .map_err(|_| TrustlessArtifactError::HttpTimeout {
            origin: source,
            phase: TrustlessHttpPhase::ResponseBody,
        })?
        .map_err(|error| TrustlessArtifactError::Http {
            origin: source,
            phase: TrustlessHttpPhase::ResponseBody,
            error: error.without_url(),
        })?
    {
        let next_len = bytes.len().checked_add(chunk.len()).ok_or(
            TrustlessArtifactError::ResponseTooLarge {
                origin: source,
                limit,
            },
        )?;
        if next_len > limit {
            return Err(TrustlessArtifactError::ResponseTooLarge {
                origin: source,
                limit,
            });
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn decode_car_blocks(
    bytes: &[u8],
    requested: Cid,
    block_limit: usize,
) -> Result<HashMap<Cid, Vec<u8>>, TrustlessArtifactError> {
    let mut reader = Cursor::new(bytes);
    prevalidate_car_block_cids(bytes, block_limit)?;
    let mut car_reader = rs_car::CarReader::new(&mut reader, true).await?;
    if !car_reader.header.roots.contains(&requested) {
        return Err(TrustlessArtifactError::CarRootMissing { requested });
    }

    let mut blocks = HashMap::new();
    let mut total_blocks = 0_usize;
    while let Some(item) = car_reader.next().await {
        if total_blocks >= block_limit {
            return Err(TrustlessArtifactError::TooManyCarBlocks { limit: block_limit });
        }
        total_blocks += 1;
        let (cid, block) = item?;
        blocks.insert(cid, block);
    }
    Ok(blocks)
}

fn reconstruct_file(
    root: Cid,
    blocks: &HashMap<Cid, Vec<u8>>,
    limits: RetrievalLimits,
) -> Result<Vec<u8>, TrustlessArtifactError> {
    let mut out = Vec::new();
    let mut active_ancestry = HashSet::new();
    let mut frames = Vec::<UnixFsFrame>::new();
    let mut next = Some((root, 1_usize));
    let mut link_visits = 0_usize;
    loop {
        if let Some((cid, depth)) = next.take() {
            if depth > limits.unixfs_max_depth {
                return Err(TrustlessArtifactError::UnixFsDepthLimitExceeded {
                    limit: limits.unixfs_max_depth,
                });
            }
            let block = blocks
                .get(&cid)
                .ok_or(TrustlessArtifactError::MissingBlock { cid })?;
            match cid.codec() {
                RAW_CODEC => {
                    append_bytes(&mut out, block, limits.reconstructed_bytes)?;
                    validate_completed_child(&mut frames, out.len(), limits.reconstructed_bytes)?;
                    if frames.is_empty() {
                        return Ok(out);
                    }
                }
                DAG_PB_CODEC => {
                    if !active_ancestry.insert(cid) {
                        return Err(TrustlessArtifactError::Cycle { cid });
                    }
                    let node = PbNode::from_bytes(Bytes::copy_from_slice(block))?;
                    let data =
                        node.data
                            .as_deref()
                            .ok_or(TrustlessArtifactError::MalformedUnixFsFile(
                                "missing UnixFS Data",
                            ))?;
                    let unixfs = UnixFsData::decode(data)?;
                    match unixfs.data_type {
                        UnixFsDataType::Raw => {
                            if !node.links.is_empty() || !unixfs.blocksizes.is_empty() {
                                return Err(TrustlessArtifactError::MalformedUnixFsFile(
                                    "raw UnixFS node must not contain links or block sizes",
                                ));
                            }
                            let start = out.len();
                            if let Some(data) = unixfs.data {
                                append_bytes(&mut out, data, limits.reconstructed_bytes)?;
                            }
                            if let Some(filesize) = unixfs.filesize {
                                validate_unixfs_size(
                                    out.len() - start,
                                    filesize,
                                    limits.reconstructed_bytes,
                                )?;
                            }
                            active_ancestry.remove(&cid);
                            validate_completed_child(
                                &mut frames,
                                out.len(),
                                limits.reconstructed_bytes,
                            )?;
                            if frames.is_empty() {
                                return Ok(out);
                            }
                        }
                        UnixFsDataType::File => {
                            if !unixfs.blocksizes.is_empty()
                                && unixfs.blocksizes.len() != node.links.len()
                            {
                                return Err(TrustlessArtifactError::MalformedUnixFsFile(
                                    "UnixFS block sizes must match link count",
                                ));
                            }
                            let output_start = out.len();
                            if let Some(data) = unixfs.data {
                                append_bytes(&mut out, data, limits.reconstructed_bytes)?;
                            }
                            frames.push(UnixFsFrame {
                                cid,
                                depth,
                                output_start,
                                links: node.links,
                                blocksizes: unixfs.blocksizes,
                                filesize: unixfs.filesize,
                                next_link: 0,
                                pending_child: None,
                            });
                        }
                        other => {
                            return Err(TrustlessArtifactError::UnsupportedUnixFsType {
                                data_type: other,
                            });
                        }
                    }
                }
                codec => return Err(TrustlessArtifactError::UnsupportedCodec { cid, codec }),
            }
            continue;
        }

        let frame = frames
            .last_mut()
            .expect("UnixFS traversal has active frame");
        if frame.next_link < frame.links.len() {
            link_visits = link_visits.checked_add(1).ok_or(
                TrustlessArtifactError::UnixFsLinkVisitLimitExceeded {
                    limit: limits.unixfs_max_link_visits,
                },
            )?;
            if link_visits > limits.unixfs_max_link_visits {
                return Err(TrustlessArtifactError::UnixFsLinkVisitLimitExceeded {
                    limit: limits.unixfs_max_link_visits,
                });
            }
            let link_index = frame.next_link;
            let child = frame.links[link_index].cid;
            let child_depth = frame.depth.checked_add(1).ok_or(
                TrustlessArtifactError::UnixFsDepthLimitExceeded {
                    limit: limits.unixfs_max_depth,
                },
            )?;
            frame.next_link += 1;
            frame.pending_child = Some((out.len(), frame.blocksizes.get(link_index).copied()));
            next = Some((child, child_depth));
            continue;
        }

        let frame = frames.pop().expect("UnixFS traversal frame exists");
        let appended = out.len() - frame.output_start;
        if let Some(filesize) = frame.filesize {
            validate_unixfs_size(appended, filesize, limits.reconstructed_bytes)?;
        }
        active_ancestry.remove(&frame.cid);
        validate_completed_child(&mut frames, out.len(), limits.reconstructed_bytes)?;
        if frames.is_empty() {
            return Ok(out);
        }
    }
}

struct UnixFsFrame {
    cid: Cid,
    depth: usize,
    output_start: usize,
    links: Vec<PbLink>,
    blocksizes: Vec<u64>,
    filesize: Option<u64>,
    next_link: usize,
    pending_child: Option<(usize, Option<u64>)>,
}

fn validate_completed_child(
    frames: &mut [UnixFsFrame],
    output_len: usize,
    limit: usize,
) -> Result<(), TrustlessArtifactError> {
    let Some(parent) = frames.last_mut() else {
        return Ok(());
    };
    let (child_start, expected) = parent
        .pending_child
        .take()
        .expect("completed UnixFS child belongs to parent frame");
    if let Some(expected) = expected {
        let actual = u64::try_from(output_len - child_start)
            .map_err(|_| TrustlessArtifactError::ReconstructedTooLarge { limit })?;
        if actual != expected {
            return Err(TrustlessArtifactError::MalformedUnixFsFile(
                "UnixFS child size does not match declared block size",
            ));
        }
    }
    Ok(())
}

fn validate_unixfs_size(
    actual: usize,
    expected: u64,
    limit: usize,
) -> Result<(), TrustlessArtifactError> {
    let actual = u64::try_from(actual)
        .map_err(|_| TrustlessArtifactError::ReconstructedTooLarge { limit })?;
    if actual != expected {
        return Err(TrustlessArtifactError::MalformedUnixFsFile(
            "UnixFS file size does not match reconstructed bytes",
        ));
    }
    Ok(())
}

fn append_bytes(
    out: &mut Vec<u8>,
    bytes: &[u8],
    limit: usize,
) -> Result<usize, TrustlessArtifactError> {
    let next_len = out
        .len()
        .checked_add(bytes.len())
        .ok_or(TrustlessArtifactError::ReconstructedTooLarge { limit })?;
    if next_len > limit {
        return Err(TrustlessArtifactError::ReconstructedTooLarge { limit });
    }
    out.extend_from_slice(bytes);
    Ok(bytes.len())
}

fn prevalidate_car_block_cids(
    bytes: &[u8],
    block_limit: usize,
) -> Result<(), TrustlessArtifactError> {
    let (header_len, header_varint_len) = read_car_varint(bytes, 0)?;
    if header_len > CAR_HEADER_MAX_BYTES {
        return Err(TrustlessArtifactError::MalformedCar(format!(
            "header exceeds {CAR_HEADER_MAX_BYTES} bytes"
        )));
    }
    let header_len = usize::try_from(header_len)
        .map_err(|_| TrustlessArtifactError::MalformedCar("header length overflow".to_string()))?;
    let header_end = header_varint_len.checked_add(header_len).ok_or_else(|| {
        TrustlessArtifactError::MalformedCar("header length overflow".to_string())
    })?;
    if header_end > bytes.len() {
        return Err(TrustlessArtifactError::MalformedCar(
            "header extends past response".to_string(),
        ));
    }

    let header = &bytes[header_varint_len..header_end];
    let header_version = car_header_version(header)?;
    let (blocks_start, blocks_end) = if header_version == 2 {
        if !bytes.starts_with(&CARV2_PRAGMA) {
            return Err(TrustlessArtifactError::MalformedCar(
                "CARv2 header must use canonical pragma".to_string(),
            ));
        }
        car_v2_block_bounds(bytes)?
    } else {
        (header_end, bytes.len())
    };
    prevalidate_car_blocks(bytes, blocks_start, blocks_end, block_limit)
}

fn car_header_version(header: &[u8]) -> Result<u64, TrustlessArtifactError> {
    let header: Ipld = DagCborCodec::decode(header).map_err(|source| {
        TrustlessArtifactError::MalformedCar(format!("header CBOR decode failed: {source:?}"))
    })?;
    let Ipld::Map(map) = header else {
        return Err(TrustlessArtifactError::MalformedCar(
            "header must be a CBOR map".to_string(),
        ));
    };
    match map.get("version") {
        Some(Ipld::Integer(version)) => u64::try_from(*version).map_err(|_| {
            TrustlessArtifactError::MalformedCar("header version is out of range".to_string())
        }),
        Some(_) => Err(TrustlessArtifactError::MalformedCar(
            "header version must be an integer".to_string(),
        )),
        None => Err(TrustlessArtifactError::MalformedCar(
            "header missing version".to_string(),
        )),
    }
}

fn car_v2_block_bounds(bytes: &[u8]) -> Result<(usize, usize), TrustlessArtifactError> {
    if bytes.len() < CARV2_PRAGMA_AND_HEADER_SIZE {
        return Err(TrustlessArtifactError::MalformedCar(
            "CARv2 header is truncated".to_string(),
        ));
    }
    let header = &bytes[CARV2_PRAGMA.len()..CARV2_PRAGMA_AND_HEADER_SIZE];
    let data_offset = u64::from_le_bytes(
        header[CARV2_DATA_OFFSET_OFFSET..CARV2_DATA_OFFSET_OFFSET + 8]
            .try_into()
            .expect("fixed CARv2 data offset slice"),
    );
    let data_size = u64::from_le_bytes(
        header[CARV2_DATA_SIZE_OFFSET..CARV2_DATA_SIZE_OFFSET + 8]
            .try_into()
            .expect("fixed CARv2 data size slice"),
    );
    let data_start = usize::try_from(data_offset).map_err(|_| {
        TrustlessArtifactError::MalformedCar("CARv2 data offset overflow".to_string())
    })?;
    let data_size = usize::try_from(data_size).map_err(|_| {
        TrustlessArtifactError::MalformedCar("CARv2 data size overflow".to_string())
    })?;
    let data_end = data_start.checked_add(data_size).ok_or_else(|| {
        TrustlessArtifactError::MalformedCar("CARv2 data range overflow".to_string())
    })?;
    if data_start < CARV2_PRAGMA_AND_HEADER_SIZE || data_end > bytes.len() {
        return Err(TrustlessArtifactError::MalformedCar(
            "CARv2 data range is outside response".to_string(),
        ));
    }

    let (inner_header_len, inner_header_varint_len) = read_car_varint(bytes, data_start)?;
    if inner_header_len > CAR_HEADER_MAX_BYTES {
        return Err(TrustlessArtifactError::MalformedCar(format!(
            "inner header exceeds {CAR_HEADER_MAX_BYTES} bytes"
        )));
    }
    let inner_header_len = usize::try_from(inner_header_len).map_err(|_| {
        TrustlessArtifactError::MalformedCar("inner header length overflow".to_string())
    })?;
    let blocks_start = data_start
        .checked_add(inner_header_varint_len)
        .and_then(|start| start.checked_add(inner_header_len))
        .ok_or_else(|| {
            TrustlessArtifactError::MalformedCar("inner header range overflow".to_string())
        })?;
    if blocks_start > data_end {
        return Err(TrustlessArtifactError::MalformedCar(
            "inner header extends past CARv2 data".to_string(),
        ));
    }
    Ok((blocks_start, data_end))
}

fn prevalidate_car_blocks(
    bytes: &[u8],
    mut offset: usize,
    end: usize,
    block_limit: usize,
) -> Result<(), TrustlessArtifactError> {
    let mut total_blocks = 0_usize;
    while offset < end {
        if total_blocks >= block_limit {
            return Err(TrustlessArtifactError::TooManyCarBlocks { limit: block_limit });
        }
        let (block_len, block_len_varint_len) = read_car_varint(bytes, offset)?;
        if block_len == 0 {
            return Err(TrustlessArtifactError::MalformedCar(
                "zero-length CAR block".to_string(),
            ));
        }
        if block_len > CAR_BLOCK_MAX_BYTES {
            return Err(TrustlessArtifactError::MalformedCar(format!(
                "block exceeds {CAR_BLOCK_MAX_BYTES} bytes"
            )));
        }
        let block_len = usize::try_from(block_len).map_err(|_| {
            TrustlessArtifactError::MalformedCar("block length overflow".to_string())
        })?;
        let block_start = offset.checked_add(block_len_varint_len).ok_or_else(|| {
            TrustlessArtifactError::MalformedCar("block range overflow".to_string())
        })?;
        let block_end = block_start.checked_add(block_len).ok_or_else(|| {
            TrustlessArtifactError::MalformedCar("block range overflow".to_string())
        })?;
        if block_end > end {
            return Err(TrustlessArtifactError::MalformedCar(
                "block extends past CAR data".to_string(),
            ));
        }
        prevalidate_car_block_cid(&bytes[block_start..block_end])?;
        total_blocks += 1;
        offset = block_end;
    }
    Ok(())
}

fn prevalidate_car_block_cid(block: &[u8]) -> Result<(), TrustlessArtifactError> {
    let mut cursor = std::io::Cursor::new(block);
    let cid = Cid::read_bytes(&mut cursor)
        .map_err(|source| TrustlessArtifactError::InvalidCarCid { source })?;
    let cid_len = usize::try_from(cursor.position())
        .map_err(|_| TrustlessArtifactError::MalformedCar("CID length overflow".to_string()))?;
    if cid_len == 0 || cid_len > block.len() {
        return Err(TrustlessArtifactError::MalformedCar(
            "invalid CAR block CID length".to_string(),
        ));
    }
    if cid.to_bytes() != block[..cid_len] {
        return Err(TrustlessArtifactError::MalformedCar(
            "non-canonical CAR block CID".to_string(),
        ));
    }
    Ok(())
}

fn read_car_varint(bytes: &[u8], offset: usize) -> Result<(u64, usize), TrustlessArtifactError> {
    let mut result = 0_u64;
    for index in 0..10 {
        let byte = *bytes
            .get(offset + index)
            .ok_or_else(|| TrustlessArtifactError::MalformedCar("truncated varint".to_string()))?;
        if index == 9 && (byte & 0b0111_1110) != 0 {
            return Err(TrustlessArtifactError::MalformedCar(
                "varint exceeds u64".to_string(),
            ));
        }
        result |= u64::from(byte & 0b0111_1111) << (index * 7);
        if byte & 0b1000_0000 == 0 {
            return Ok((result, index + 1));
        }
    }
    Err(TrustlessArtifactError::MalformedCar(
        "unterminated varint".to_string(),
    ))
}

fn verify_ipns_record_candidate(
    bytes: &[u8],
    peer_id: PeerId,
) -> Result<IpnsManifestCandidate, TrustlessArtifactError> {
    if bytes.len() > IPNS_RECORD_MAX_BYTES {
        return Err(TrustlessArtifactError::IpnsRecordTooLarge {
            limit: IPNS_RECORD_MAX_BYTES,
        });
    }

    let record = rust_ipns::Record::decode(bytes)
        .map_err(|source| TrustlessArtifactError::InvalidIpnsRecord { source })?;
    record
        .verify(peer_id)
        .map_err(|source| TrustlessArtifactError::InvalidIpnsSignature { source })?;
    verify_ipns_public_key_binding(bytes, peer_id)?;
    if record.validity_type() != rust_ipns::ValidityType::EOL {
        return Err(TrustlessArtifactError::UnsupportedIpnsValidity);
    }
    let eol = record
        .validity()
        .map_err(|source| TrustlessArtifactError::InvalidIpnsRecord { source })?
        .with_timezone(&Utc);
    let data = record
        .data()
        .map_err(|source| TrustlessArtifactError::InvalidIpnsRecord { source })?;
    let cid = parse_ipns_value(data.value())?;
    Ok(IpnsManifestCandidate {
        sequence: data.sequence(),
        cid,
        eol,
    })
}

fn parse_ipns_value(value: &[u8]) -> Result<Cid, TrustlessArtifactError> {
    let value = str::from_utf8(value)
        .map_err(|_| TrustlessArtifactError::UnsupportedIpnsValue("non-UTF8 value"))?;
    let cid = if let Some(cid) = value.strip_prefix("/ipfs/") {
        if cid.is_empty() || cid.contains('/') {
            return Err(TrustlessArtifactError::UnsupportedIpnsValue(
                "IPNS value must be /ipfs/{cid} without a path suffix",
            ));
        }
        cid
    } else if value.starts_with('/') {
        return Err(TrustlessArtifactError::UnsupportedIpnsValue(
            "IPNS value must be /ipfs/{cid} or a bare CID",
        ));
    } else {
        value
    };
    parse_cid(cid)
}

fn expected_ipns_peer_id(name: &str) -> Result<PeerId, TrustlessArtifactError> {
    let cid = parse_cid(name)?;
    if cid.version() != Version::V1 || cid.codec() != LIBP2P_KEY_CODEC {
        return Err(TrustlessArtifactError::UnsupportedIpnsName {
            name: name.to_string(),
        });
    }
    PeerId::from_bytes(&cid.hash().to_bytes())
        .map_err(|source| TrustlessArtifactError::InvalidIpnsPeerId { source })
}

fn verify_ipns_public_key_binding(
    bytes: &[u8],
    expected_peer_id: PeerId,
) -> Result<(), TrustlessArtifactError> {
    let Some(public_key_bytes) = ipns_record_public_key(bytes)? else {
        return Ok(());
    };
    let public_key = PublicKey::try_decode_protobuf(public_key_bytes)
        .map_err(|source| TrustlessArtifactError::InvalidIpnsPublicKey { source })?;
    let actual_peer_id = public_key.to_peer_id();
    if actual_peer_id != expected_peer_id {
        return Err(TrustlessArtifactError::IpnsPublicKeyMismatch {
            expected: Box::new(expected_peer_id),
            actual: Box::new(actual_peer_id),
        });
    }
    Ok(())
}

fn ipns_record_public_key(bytes: &[u8]) -> Result<Option<&[u8]>, TrustlessArtifactError> {
    let mut reader = BytesReader::from_bytes(bytes);
    let mut public_key = None;
    while !reader.is_eof() {
        match reader
            .next_tag(bytes)
            .map_err(|source| invalid_ipns_record_error(&source))?
        {
            58 => {
                let value = reader
                    .read_bytes(bytes)
                    .map_err(|source| invalid_ipns_record_error(&source))?;
                if value.is_empty() {
                    public_key = None;
                } else {
                    public_key = Some(value);
                }
            }
            tag => reader
                .read_unknown(bytes, tag)
                .map_err(|source| invalid_ipns_record_error(&source))?,
        }
    }
    Ok(public_key)
}

fn invalid_ipns_record_error(source: &quick_protobuf::Error) -> TrustlessArtifactError {
    TrustlessArtifactError::InvalidIpnsRecord {
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, source.to_string()),
    }
}

fn parse_cid(value: &str) -> Result<Cid, TrustlessArtifactError> {
    Cid::try_from(value).map_err(|source| TrustlessArtifactError::InvalidCid { source })
}

fn car_gateway_url(gateway: &Url, cid: &Cid) -> Url {
    let mut url = gateway_resource_url(gateway, "ipfs", &cid.to_string());
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("format", "car");
        query.append_pair("dag-scope", "entity");
    }
    url
}

fn ipns_record_gateway_url(gateway: &Url, name: &str) -> Url {
    let mut url = gateway_resource_url(gateway, "ipns", name);
    url.query_pairs_mut().append_pair("format", "ipns-record");
    url
}

fn gateway_resource_url(gateway: &Url, namespace: &'static str, value: &str) -> Url {
    let mut url = gateway.clone();
    let path = gateway.path().trim_end_matches('/');
    let namespace_suffix = format!("/{namespace}");
    let new_path = if path.ends_with(&namespace_suffix) {
        format!("{path}/{value}")
    } else if path.is_empty() {
        format!("/{namespace}/{value}")
    } else {
        format!("{path}/{namespace}/{value}")
    };
    url.set_path(&new_path);
    url
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnixFsDataType {
    Raw,
    Directory,
    File,
    Metadata,
    Symlink,
    HamtShard,
    Unknown(i32),
}

impl From<i32> for UnixFsDataType {
    fn from(value: i32) -> Self {
        match value {
            0 => Self::Raw,
            1 => Self::Directory,
            2 => Self::File,
            3 => Self::Metadata,
            4 => Self::Symlink,
            5 => Self::HamtShard,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug)]
struct UnixFsData<'a> {
    data_type: UnixFsDataType,
    data: Option<&'a [u8]>,
    filesize: Option<u64>,
    blocksizes: Vec<u64>,
}

impl<'a> UnixFsData<'a> {
    fn decode(bytes: &'a [u8]) -> Result<Self, TrustlessArtifactError> {
        let mut reader = BytesReader::from_bytes(bytes);
        let mut data = Self {
            data_type: UnixFsDataType::Raw,
            data: None,
            filesize: None,
            blocksizes: Vec::new(),
        };
        while !reader.is_eof() {
            match reader.next_tag(bytes)? {
                8 => data.data_type = reader.read_enum(bytes)?,
                18 => data.data = Some(reader.read_bytes(bytes)?),
                24 => data.filesize = Some(reader.read_uint64(bytes)?),
                32 => data.blocksizes.push(reader.read_uint64(bytes)?),
                tag => reader.read_unknown(bytes, tag)?,
            }
        }
        Ok(data)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrustlessHttpSource {
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
pub(crate) enum TrustlessHttpPhase {
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
pub(crate) enum TrustlessArtifactError {
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
        source: std::io::Error,
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

#[cfg(test)]
impl TrustlessArtifactFetchResult {
    pub(crate) fn verified_for_test(cid: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            verified_cid: cid.into(),
            bytes,
            gateway_index: 0,
            gateway_count: 1,
        }
    }
}

#[cfg(test)]
impl TrustlessArtifactFetcher<'_> {
    const fn with_http_timeouts_for_test(mut self, idle: Duration, total: Duration) -> Self {
        self.timeouts = HttpAttemptTimeouts { idle, total };
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::error::Error as StdError;
    use std::time::{Duration, UNIX_EPOCH};

    use ipld_dagpb::{PbLink, PbNode};
    use libp2p_identity::Keypair;
    use multihash_codetable::{Code, MultihashDigest};
    use quick_protobuf::Writer;

    fn sensitive_server_url(mut url: Url) -> SensitiveUrl {
        url.set_path("/endpoint-sentinel");
        url.set_query(Some("secret=endpoint-sentinel"));
        url.set_fragment(Some("endpoint-sentinel"));
        url.into()
    }

    fn spawn_stalled_server() -> SensitiveUrl {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind stalled server");
        let url = Url::parse(&format!(
            "http://{}",
            listener.local_addr().expect("stalled server address")
        ))
        .expect("stalled server URL");
        std::thread::spawn(move || {
            let (_stream, _) = listener.accept().expect("accept stalled request");
            std::thread::sleep(Duration::from_secs(1));
        });
        sensitive_server_url(url)
    }

    fn formatted_error_chain(error: &(dyn StdError + 'static)) -> String {
        let mut formatted = String::new();
        let mut current = Some(error);
        while let Some(error) = current {
            std::fmt::Write::write_fmt(&mut formatted, format_args!("{error} {error:?}\n"))
                .expect("write error chain");
            current = error.source();
        }
        formatted
    }

    fn assert_artifact_error_safe(error: &TrustlessArtifactError) {
        let formatted = formatted_error_chain(error);
        assert!(
            !formatted.contains("endpoint-sentinel"),
            "artifact error leaked endpoint: {formatted}"
        );
        assert!(
            !formatted.contains("body-sentinel"),
            "artifact error leaked response body: {formatted}"
        );
    }

    #[tokio::test]
    async fn sensitive_gateway_errors_are_url_free() {
        let oversized_server = spawn_once_server(200, b"oversized".to_vec());
        let oversized_url = sensitive_server_url(oversized_server.url.clone());
        let oversized_error = fetch_response_bytes(
            &reqwest::Client::new(),
            oversized_url.expose_url(),
            TrustlessHttpSource::Gateway { index: 0, count: 1 },
            None,
            1,
        )
        .await
        .expect_err("oversized manifest response");
        assert!(matches!(
            &oversized_error,
            TrustlessArtifactError::ResponseTooLarge {
                origin: TrustlessHttpSource::Gateway { index: 0, count: 1 },
                limit,
            } if *limit == 1
        ));
        assert_artifact_error_safe(&oversized_error);

        let stalled_url = spawn_stalled_server();
        let timeout_error = fetch_response_bytes_with_timeouts(
            &reqwest::Client::new(),
            stalled_url.expose_url(),
            TrustlessHttpSource::Gateway { index: 1, count: 2 },
            None,
            1024,
            HttpAttemptTimeouts {
                idle: Duration::from_millis(20),
                total: Duration::from_secs(1),
            },
        )
        .await
        .expect_err("gateway timeout");
        assert!(matches!(
            &timeout_error,
            TrustlessArtifactError::HttpTimeout {
                origin: TrustlessHttpSource::Gateway { index: 1, count: 2 },
                phase: TrustlessHttpPhase::ResponseHeaders,
            }
        ));
        assert_artifact_error_safe(&timeout_error);

        let artifact_bytes = b"verified fallback artifact".to_vec();
        let cid = raw_cid(&artifact_bytes);
        let gateway_status_server = spawn_once_server(503, b"body-sentinel".to_vec());
        let gateway_status_urls = [sensitive_server_url(gateway_status_server.url.clone())];
        let client = reqwest::Client::new();
        let gateway_status_error = TrustlessArtifactFetcher::new_poi(&client, &gateway_status_urls)
            .fetch_artifact_cid(&cid.to_string(), artifact_bytes.len() as u64)
            .await
            .expect_err("gateway status error");
        assert!(matches!(
            &gateway_status_error,
            TrustlessArtifactError::HttpStatus {
                origin: TrustlessHttpSource::Gateway { index: 0, count: 1 },
                status,
            } if *status == reqwest::StatusCode::SERVICE_UNAVAILABLE
        ));
        assert_artifact_error_safe(&gateway_status_error);

        let failing = spawn_once_server(503, Vec::new());
        let valid = spawn_once_server(200, car_bytes(cid, &[(cid, artifact_bytes.clone())]));
        let gateways = [
            sensitive_server_url(failing.url.clone()),
            sensitive_server_url(valid.url.clone()),
        ];
        let fetched = TrustlessArtifactFetcher::new_poi(&client, &gateways)
            .fetch_artifact_cid(&cid.to_string(), artifact_bytes.len() as u64)
            .await
            .expect("fallback to second sensitive gateway");
        assert_eq!(fetched, artifact_bytes);
        assert_eq!(
            valid.request_path(),
            format!(
                "/endpoint-sentinel/ipfs/{cid}?secret=endpoint-sentinel&format=car&dag-scope=entity"
            )
        );
    }

    #[tokio::test(start_paused = true)]
    async fn slow_drip_hits_total_deadline_despite_remaining_under_idle_timeout() {
        let server = spawn_controlled_chunk_server();
        let url = sensitive_server_url(server.url.clone());
        let started = tokio::time::Instant::now();
        let task = tokio::spawn(async move {
            let client = reqwest::Client::new();
            fetch_response_bytes_with_timeouts(
                &client,
                url.expose_url(),
                TrustlessHttpSource::Gateway { index: 1, count: 3 },
                None,
                1024,
                HttpAttemptTimeouts {
                    idle: Duration::from_secs(5),
                    total: Duration::from_secs(12),
                },
            )
            .await
        });
        server.wait_for_request().await;
        server.send_headers(200);
        server.send_chunk(b"body-sentinel-0".to_vec());
        tokio::task::yield_now().await;
        for chunk in [b"body-sentinel-1".as_slice(), b"body-sentinel-2".as_slice()] {
            tokio::time::advance(Duration::from_secs(4)).await;
            server.send_chunk(chunk.to_vec());
            tokio::task::yield_now().await;
        }
        tokio::time::advance(Duration::from_secs(4)).await;

        let error = task
            .await
            .expect("join slow-drip request")
            .expect_err("absolute deadline expires");
        assert_eq!(started.elapsed(), Duration::from_secs(12));
        assert!(matches!(
            &error,
            TrustlessArtifactError::HttpAttemptDeadline {
                origin: TrustlessHttpSource::Gateway { index: 1, count: 3 }
            }
        ));
        assert_artifact_error_safe(&error);
    }

    #[tokio::test(start_paused = true)]
    async fn response_body_idle_stall_keeps_phase_specific_timeout() {
        let server = spawn_controlled_chunk_server();
        let url = server.url.clone();
        let task = tokio::spawn(async move {
            let client = reqwest::Client::new();
            fetch_response_bytes_with_timeouts(
                &client,
                &url,
                TrustlessHttpSource::ExplicitManifest,
                None,
                1024,
                HttpAttemptTimeouts {
                    idle: Duration::from_secs(3),
                    total: Duration::from_secs(20),
                },
            )
            .await
        });
        server.wait_for_request().await;
        server.send_headers(200);
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(3)).await;

        assert!(matches!(
            task.await.expect("join idle-stall request"),
            Err(TrustlessArtifactError::HttpTimeout {
                origin: TrustlessHttpSource::ExplicitManifest,
                phase: TrustlessHttpPhase::ResponseBody,
            })
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn response_header_idle_stall_keeps_phase_specific_timeout() {
        let server = spawn_controlled_chunk_server();
        let url = server.url.clone();
        let task = tokio::spawn(async move {
            let client = reqwest::Client::new();
            fetch_response_bytes_with_timeouts(
                &client,
                &url,
                TrustlessHttpSource::ExplicitManifest,
                None,
                1024,
                HttpAttemptTimeouts {
                    idle: Duration::from_secs(3),
                    total: Duration::from_secs(20),
                },
            )
            .await
        });
        server.wait_for_request().await;
        tokio::time::advance(Duration::from_secs(3)).await;

        assert!(matches!(
            task.await.expect("join header-stall request"),
            Err(TrustlessArtifactError::HttpTimeout {
                origin: TrustlessHttpSource::ExplicitManifest,
                phase: TrustlessHttpPhase::ResponseHeaders,
            })
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn response_completed_before_total_deadline_succeeds() {
        let server = spawn_controlled_chunk_server();
        let url = server.url.clone();
        let task = tokio::spawn(async move {
            let client = reqwest::Client::new();
            fetch_response_bytes_with_timeouts(
                &client,
                &url,
                TrustlessHttpSource::ExplicitManifest,
                None,
                1024,
                HttpAttemptTimeouts {
                    idle: Duration::from_secs(5),
                    total: Duration::from_secs(20),
                },
            )
            .await
        });
        server.wait_for_request().await;
        server.send_headers(200);
        server.send_chunk(b"complete".to_vec());
        server.finish();

        assert_eq!(
            task.await
                .expect("join completed request")
                .expect("completed response"),
            b"complete"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn slow_first_gateway_deadline_falls_back_to_healthy_gateway() {
        let artifact_bytes = b"deadline fallback artifact".to_vec();
        let cid = raw_cid(&artifact_bytes);
        let slow = spawn_controlled_chunk_server();
        let healthy = spawn_controlled_chunk_server();
        let healthy_body = car_bytes(cid, &[(cid, artifact_bytes.clone())]);
        let gateways = vec![
            sensitive_server_url(slow.url.clone()),
            sensitive_server_url(healthy.url.clone()),
        ];
        let expected = artifact_bytes.clone();
        let task = tokio::spawn(async move {
            let client = reqwest::Client::new();
            TrustlessArtifactFetcher::new_poi(&client, &gateways)
                .with_http_timeouts_for_test(Duration::from_secs(5), Duration::from_secs(12))
                .fetch_artifact_cid(&cid.to_string(), expected.len() as u64)
                .await
        });
        slow.wait_for_request().await;
        slow.send_headers(200);
        slow.send_chunk(b"slow-0".to_vec());
        tokio::task::yield_now().await;
        for chunk in [b"slow-1".as_slice(), b"slow-2".as_slice()] {
            tokio::time::advance(Duration::from_secs(4)).await;
            slow.send_chunk(chunk.to_vec());
            tokio::task::yield_now().await;
        }
        tokio::time::advance(Duration::from_secs(4)).await;
        let healthy_path = healthy.wait_for_request().await;
        healthy.send_headers(200);
        healthy.send_chunk(healthy_body);
        healthy.finish();

        assert_eq!(
            task.await
                .expect("join fallback request")
                .expect("healthy fallback succeeds"),
            artifact_bytes
        );
        assert!(healthy_path.contains(&cid.to_string()));
    }

    #[tokio::test(start_paused = true)]
    async fn bounded_gateway_fetch_uses_three_deadline_windows_and_never_contacts_fourth() {
        let artifact_bytes = b"three-attempt artifact".to_vec();
        let cid = raw_cid(&artifact_bytes);
        let servers = (0..4)
            .map(|_| spawn_controlled_chunk_server())
            .collect::<Vec<_>>();
        let gateways = servers
            .iter()
            .map(|server| sensitive_server_url(server.url.clone()))
            .collect::<Vec<_>>();
        let started = tokio::time::Instant::now();
        let task = tokio::spawn(async move {
            let client = reqwest::Client::new();
            TrustlessArtifactFetcher::new_poi(&client, &gateways)
                .with_http_timeouts_for_test(Duration::from_secs(10), Duration::from_secs(5))
                .fetch_artifact_cid_with_metadata_from_gateway_bounded(
                    &cid.to_string(),
                    artifact_bytes.len() as u64,
                    0,
                    3,
                )
                .await
        });
        for server in &servers[..3] {
            server.wait_for_request().await;
            server.send_headers(200);
            tokio::task::yield_now().await;
            tokio::time::advance(Duration::from_secs(5)).await;
        }

        let error = task
            .await
            .expect("join bounded gateway request")
            .expect_err("three deadlines exhaust bounded attempts");
        assert_eq!(started.elapsed(), Duration::from_secs(15));
        assert!(matches!(
            error,
            TrustlessArtifactError::HttpAttemptDeadline {
                origin: TrustlessHttpSource::Gateway { index: 2, count: 4 }
            }
        ));
        servers[3].assert_no_request();
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_ipns_slow_peer_consumes_only_one_deadline_window() {
        let keypair = test_ipns_keypair();
        let name = ipns_name(&keypair);
        let cid = raw_cid(b"concurrent IPNS candidate");
        let record = ipns_record(&keypair, format!("/ipfs/{cid}"), 7);
        let slow = spawn_controlled_chunk_server();
        let healthy = spawn_controlled_chunk_server();
        let gateways = vec![
            sensitive_server_url(slow.url.clone()),
            sensitive_server_url(healthy.url.clone()),
        ];
        let started = tokio::time::Instant::now();
        let task = tokio::spawn(async move {
            let client = reqwest::Client::new();
            TrustlessArtifactFetcher::new_poi(&client, &gateways)
                .with_http_timeouts_for_test(Duration::from_secs(10), Duration::from_secs(5))
                .resolve_ipns_manifest_candidates(&name)
                .await
        });
        slow.wait_for_request().await;
        healthy.wait_for_request().await;
        healthy.send_headers(200);
        healthy.send_chunk(record);
        healthy.finish();
        slow.send_headers(200);
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(5)).await;

        let candidates = task
            .await
            .expect("join concurrent IPNS request")
            .expect("healthy IPNS candidate survives slow peer");
        assert_eq!(started.elapsed(), Duration::from_secs(5));
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].sequence, 7);
        assert_eq!(candidates[0].cid, cid);
    }

    #[test]
    fn car_gateway_url_adds_trustless_query_parameters() {
        let gateway = Url::parse("https://gateway.example/base/ipfs?existing=1").expect("URL");
        let cid = raw_cid(b"hello");

        let url = car_gateway_url(&gateway, &cid);

        assert_eq!(url.path(), format!("/base/ipfs/{cid}"));
        assert_eq!(url.query(), Some("existing=1&format=car&dag-scope=entity"));
    }

    #[test]
    fn ipns_gateway_url_adds_record_query_parameter() {
        let gateway = Url::parse("https://gateway.example/root").expect("URL");

        let url = ipns_record_gateway_url(&gateway, "k51name");

        assert_eq!(url.path(), "/root/ipns/k51name");
        assert_eq!(url.query(), Some("format=ipns-record"));
    }

    #[tokio::test]
    async fn raw_root_car_reconstructs_root_block() {
        let root = raw_cid(b"hello raw");
        let car = car_bytes(root, &[(root, b"hello raw".to_vec())]);

        let blocks = decode_car_blocks(&car, root, 8).await.expect("CAR blocks");
        let bytes = reconstruct_for_test(root, &blocks, 1024, 8, 8).expect("raw root");

        assert_eq!(bytes, b"hello raw");
    }

    #[tokio::test]
    async fn car_duplicate_blocks_continue_to_count_toward_car_block_limit() {
        let root = raw_cid(b"duplicate raw");
        let car = car_bytes(
            root,
            &[
                (root, b"duplicate raw".to_vec()),
                (root, b"duplicate raw".to_vec()),
                (root, b"duplicate raw".to_vec()),
            ],
        );

        let error = decode_car_blocks(&car, root, 2)
            .await
            .expect_err("duplicate blocks exceed total block limit");

        assert!(matches!(
            error,
            TrustlessArtifactError::TooManyCarBlocks { limit: 2 }
        ));
    }

    #[tokio::test]
    async fn dag_pb_single_file_reconstructs_inline_data() {
        let block = dag_pb_file_node(b"inline", &[], Some(6));
        let root = dag_pb_cid(&block);
        let car = car_bytes(root, &[(root, block)]);

        let blocks = decode_car_blocks(&car, root, 8).await.expect("CAR blocks");
        let bytes = reconstruct_for_test(root, &blocks, 1024, 8, 8).expect("DAG-PB file");

        assert_eq!(bytes, b"inline");
    }

    #[tokio::test]
    async fn dag_pb_file_with_raw_leaves_reconstructs_declared_order() {
        let left = raw_cid(b"left");
        let right = raw_cid(b"right");
        let root_block = dag_pb_file_node(
            b"root-",
            &[(left, "left", 4), (right, "right", 5)],
            Some(14),
        );
        let root = dag_pb_cid(&root_block);
        let car = car_bytes(
            root,
            &[
                (root, root_block),
                (right, b"right".to_vec()),
                (left, b"left".to_vec()),
            ],
        );

        let blocks = decode_car_blocks(&car, root, 8).await.expect("CAR blocks");
        let bytes = reconstruct_for_test(root, &blocks, 1024, 8, 8).expect("DAG-PB leaves");

        assert_eq!(bytes, b"root-leftright");
    }

    #[tokio::test]
    async fn missing_block_is_rejected() {
        let child = raw_cid(b"child");
        let root_block = dag_pb_file_node(b"", &[(child, "child", 5)], Some(5));
        let root = dag_pb_cid(&root_block);
        let car = car_bytes(root, &[(root, root_block)]);

        let blocks = decode_car_blocks(&car, root, 8).await.expect("CAR blocks");
        let error =
            reconstruct_for_test(root, &blocks, 1024, 8, 8).expect_err("missing child block");

        assert!(matches!(error, TrustlessArtifactError::MissingBlock { cid } if cid == child));
    }

    #[tokio::test]
    async fn wrong_block_hash_is_rejected() {
        let root = raw_cid(b"expected");
        let car = car_bytes(root, &[(root, b"tampered".to_vec())]);

        let error = decode_car_blocks(&car, root, 8)
            .await
            .expect_err("wrong block hash");

        assert!(matches!(error, TrustlessArtifactError::Car(_)));
    }

    #[tokio::test]
    async fn malformed_car_block_cid_falls_back_to_next_gateway() {
        let artifact_bytes = b"verified artifact bytes".to_vec();
        let cid = raw_cid(&artifact_bytes);
        let malformed = spawn_once_server(200, car_with_invalid_block_cid(cid));
        let valid = spawn_once_server(200, car_bytes(cid, &[(cid, artifact_bytes.clone())]));
        let client = reqwest::Client::new();
        let gateways = [malformed.url.clone(), valid.url.clone()];
        let fetcher = TrustlessArtifactFetcher::new(&client, &gateways);

        let fetched = fetcher
            .fetch_artifact_cid(&cid.to_string(), artifact_bytes.len() as u64)
            .await
            .expect("fallback to valid CAR");

        assert_eq!(fetched, artifact_bytes);
        assert_eq!(
            malformed.request_path(),
            format!("/ipfs/{cid}?format=car&dag-scope=entity")
        );
        assert_eq!(
            valid.request_path(),
            format!("/ipfs/{cid}?format=car&dag-scope=entity")
        );
    }

    #[tokio::test]
    async fn noncanonical_car_v2_header_falls_back_to_next_gateway() {
        let artifact_bytes = b"verified artifact bytes".to_vec();
        let cid = raw_cid(&artifact_bytes);
        let malformed = spawn_once_server(200, car_with_noncanonical_v2_header());
        let valid = spawn_once_server(200, car_bytes(cid, &[(cid, artifact_bytes.clone())]));
        let client = reqwest::Client::new();
        let gateways = [malformed.url.clone(), valid.url.clone()];
        let fetcher = TrustlessArtifactFetcher::new(&client, &gateways);

        let fetched = fetcher
            .fetch_artifact_cid(&cid.to_string(), artifact_bytes.len() as u64)
            .await
            .expect("fallback to valid CAR");

        assert_eq!(fetched, artifact_bytes);
        assert_eq!(
            malformed.request_path(),
            format!("/ipfs/{cid}?format=car&dag-scope=entity")
        );
        assert_eq!(
            valid.request_path(),
            format!("/ipfs/{cid}?format=car&dag-scope=entity")
        );
    }

    #[tokio::test]
    async fn unsupported_unixfs_node_type_is_rejected() {
        let block = dag_pb_node(
            Some(unixfs_data(UnixFsDataType::Directory, b"", &[], None)),
            &[],
        );
        let root = dag_pb_cid(&block);
        let car = car_bytes(root, &[(root, block)]);

        let blocks = decode_car_blocks(&car, root, 8).await.expect("CAR blocks");
        let error =
            reconstruct_for_test(root, &blocks, 1024, 8, 8).expect_err("directory rejected");

        assert!(matches!(
            error,
            TrustlessArtifactError::UnsupportedUnixFsType {
                data_type: UnixFsDataType::Directory
            }
        ));
    }

    #[tokio::test]
    async fn reconstructed_limit_is_enforced() {
        let root = raw_cid(b"too large");
        let car = car_bytes(root, &[(root, b"too large".to_vec())]);

        let blocks = decode_car_blocks(&car, root, 8).await.expect("CAR blocks");
        let error = reconstruct_for_test(root, &blocks, 3, 8, 8).expect_err("limit exceeded");

        assert!(matches!(
            error,
            TrustlessArtifactError::ReconstructedTooLarge { limit: 3 }
        ));
    }

    #[test]
    fn unixfs_depth_accepts_exact_limit() {
        let (root, blocks) = unixfs_chain(8);
        assert_eq!(
            reconstruct_for_test(root, &blocks, 1, 8, 7).expect("exact depth accepted"),
            b"x"
        );
    }

    #[test]
    fn unixfs_budgets_are_derived_from_applicable_car_block_caps() {
        let manifest = RetrievalLimits::manifest();
        assert_eq!(manifest.unixfs_max_depth, MANIFEST_CAR_MAX_BLOCKS);
        assert_eq!(manifest.unixfs_max_link_visits, MANIFEST_CAR_MAX_BLOCKS);
        let artifact = RetrievalLimits::artifact(1).expect("artifact limits");
        assert_eq!(artifact.unixfs_max_depth, ARTIFACT_CAR_MAX_BLOCKS);
        assert_eq!(artifact.unixfs_max_link_visits, ARTIFACT_CAR_MAX_BLOCKS);
    }

    #[test]
    fn unixfs_depth_rejects_limit_plus_one() {
        let (root, blocks) = unixfs_chain(9);
        assert!(matches!(
            reconstruct_for_test(root, &blocks, 1, 8, 8),
            Err(TrustlessArtifactError::UnixFsDepthLimitExceeded { limit: 8 })
        ));
    }

    #[test]
    fn unixfs_link_visits_accept_exact_limit() {
        let (root, blocks) = repeated_link_graph(8);
        assert_eq!(
            reconstruct_for_test(root, &blocks, 8, 2, 8).expect("exact visits accepted"),
            vec![b'x'; 8]
        );
    }

    #[test]
    fn unixfs_link_visits_reject_limit_plus_one() {
        let (root, blocks) = repeated_link_graph(9);
        assert!(matches!(
            reconstruct_for_test(root, &blocks, 9, 2, 8),
            Err(TrustlessArtifactError::UnixFsLinkVisitLimitExceeded { limit: 8 })
        ));
    }

    #[test]
    fn unixfs_repeated_link_visits_are_charged_individually() {
        let (root, blocks) = repeated_link_graph(3);
        assert!(matches!(
            reconstruct_for_test(root, &blocks, 3, 2, 2),
            Err(TrustlessArtifactError::UnixFsLinkVisitLimitExceeded { limit: 2 })
        ));
    }

    #[test]
    fn unixfs_diamond_dag_emits_shared_child_for_each_reference() {
        let shared = raw_cid(b"x");
        let left_block = dag_pb_file_node(b"", &[(shared, "left-shared", 1)], Some(1));
        let left = dag_pb_cid(&left_block);
        let right_block = dag_pb_file_node(b"", &[(shared, "right-shared", 1)], Some(1));
        let right = dag_pb_cid(&right_block);
        let root_block = dag_pb_file_node(b"", &[(left, "left", 1), (right, "right", 1)], Some(2));
        let root = dag_pb_cid(&root_block);
        let blocks = HashMap::from([
            (root, root_block),
            (left, left_block),
            (right, right_block),
            (shared, b"x".to_vec()),
        ]);

        assert_eq!(
            reconstruct_for_test(root, &blocks, 2, 3, 4).expect("diamond DAG"),
            b"xx"
        );
    }

    #[test]
    fn unixfs_active_path_cycle_is_still_rejected() {
        let root = dag_pb_cid(b"cycle-key");
        let root_block = dag_pb_file_node(b"", &[(root, "cycle", 0)], Some(0));
        let blocks = HashMap::from([(root, root_block)]);

        assert!(matches!(
            reconstruct_for_test(root, &blocks, 1, 2, 1),
            Err(TrustlessArtifactError::Cycle { cid }) if cid == root
        ));
    }

    #[test]
    fn unixfs_deep_chain_is_iterative_and_does_not_use_call_stack() {
        let (root, blocks) = unixfs_chain(2_048);
        assert_eq!(
            reconstruct_for_test(root, &blocks, 1, 2_048, 2_047).expect("deep iterative chain"),
            b"x"
        );
    }

    #[test]
    fn unixfs_output_limit_remains_independent() {
        let (root, blocks) = repeated_link_graph(2);
        assert!(matches!(
            reconstruct_for_test(root, &blocks, 1, 2, 2),
            Err(TrustlessArtifactError::ReconstructedTooLarge { limit: 1 })
        ));
    }

    #[test]
    fn descriptor_size_overflow_is_rejected() {
        let error = RetrievalLimits::artifact(u64::MAX).expect_err("overflowing descriptor size");

        assert!(matches!(
            error,
            TrustlessArtifactError::DescriptorByteSizeTooLarge { .. }
                | TrustlessArtifactError::RetrievalLimitOverflow
        ));
    }

    #[test]
    fn ipns_record_accepts_bare_and_prefixed_cids() {
        let keypair = test_ipns_keypair();
        let peer_id = keypair.public().to_peer_id();
        let manifest_cid = raw_cid(b"manifest");
        let prefixed = ipns_record(&keypair, format!("/ipfs/{manifest_cid}"), 3);
        let bare = ipns_record(&keypair, manifest_cid.to_string(), 2);

        let prefixed = verify_ipns_record_candidate(&prefixed, peer_id).expect("prefixed");
        let bare = verify_ipns_record_candidate(&bare, peer_id).expect("bare");

        assert_eq!(prefixed.sequence, 3);
        assert_eq!(prefixed.cid, manifest_cid);
        assert_eq!(bare.sequence, 2);
        assert_eq!(bare.cid, manifest_cid);
    }

    #[test]
    fn invalid_ipns_signature_is_rejected() {
        let good_keypair = test_ipns_keypair();
        let bad_keypair = Keypair::ed25519_from_bytes([8_u8; 32]).expect("bad keypair");
        let peer_id = good_keypair.public().to_peer_id();
        let record = ipns_record(&bad_keypair, raw_cid(b"manifest").to_string(), 1);

        let error = verify_ipns_record_candidate(&record, peer_id).expect_err("invalid signature");

        assert!(matches!(
            error,
            TrustlessArtifactError::InvalidIpnsSignature { .. }
        ));
    }

    #[test]
    fn ipns_record_embedded_public_key_must_match_name() {
        let good_keypair = test_ipns_keypair();
        let bad_keypair = Keypair::ed25519_from_bytes([8_u8; 32]).expect("bad keypair");
        let peer_id = good_keypair.public().to_peer_id();
        let record =
            ipns_record_with_embedded_public_key(&bad_keypair, raw_cid(b"manifest").to_string(), 1);

        let error =
            verify_ipns_record_candidate(&record, peer_id).expect_err("wrong embedded public key");

        assert!(matches!(
            error,
            TrustlessArtifactError::IpnsPublicKeyMismatch { .. }
        ));
    }

    #[test]
    fn authenticated_ipns_record_retains_mandatory_eol() {
        let keypair = test_ipns_keypair();
        let peer_id = keypair.public().to_peer_id();
        let record = ipns_record(&keypair, raw_cid(b"manifest").to_string(), 1);

        let candidate = verify_ipns_record_candidate(&record, peer_id).expect("authenticated EOL");

        assert!(candidate.eol > chrono::DateTime::<Utc>::from(UNIX_EPOCH));
    }

    #[test]
    fn unsupported_ipns_value_is_rejected() {
        let keypair = test_ipns_keypair();
        let peer_id = keypair.public().to_peer_id();
        let record = ipns_record(&keypair, "/ipns/not-supported".to_string(), 1);

        let error = verify_ipns_record_candidate(&record, peer_id).expect_err("unsupported value");

        assert!(matches!(
            error,
            TrustlessArtifactError::UnsupportedIpnsValue(_)
        ));
    }

    #[test]
    fn oversized_ipns_record_is_rejected() {
        let keypair = test_ipns_keypair();
        let peer_id = keypair.public().to_peer_id();
        let bytes = vec![0_u8; IPNS_RECORD_MAX_BYTES + 1];

        let error = verify_ipns_record_candidate(&bytes, peer_id).expect_err("oversized");

        assert!(matches!(
            error,
            TrustlessArtifactError::IpnsRecordTooLarge { .. }
        ));
    }

    #[tokio::test]
    async fn ipns_candidates_are_sorted_and_exact_pairs_are_deduplicated() {
        let keypair = test_ipns_keypair();
        let name = ipns_name(&keypair);
        let high_cid = raw_cid(b"high");
        let low = spawn_once_server(200, ipns_record(&keypair, raw_cid(b"low").to_string(), 1));
        let high = spawn_once_server(200, ipns_record(&keypair, high_cid.to_string(), 5));
        let duplicate_high = spawn_once_server(200, ipns_record(&keypair, high_cid.to_string(), 5));
        let client = reqwest::Client::new();
        let gateways = [
            low.url.clone(),
            high.url.clone(),
            duplicate_high.url.clone(),
        ];
        let fetcher = TrustlessArtifactFetcher::new(&client, &gateways);

        let candidates = fetcher
            .resolve_ipns_manifest_candidates(&name)
            .await
            .expect("IPNS candidates");

        assert_eq!(
            candidates
                .iter()
                .map(|candidate| candidate.sequence)
                .collect::<Vec<_>>(),
            vec![5, 1]
        );
        assert_eq!(
            low.request_path(),
            format!("/ipns/{name}?format=ipns-record")
        );
        assert_eq!(
            high.request_path(),
            format!("/ipns/{name}?format=ipns-record")
        );
        assert_eq!(
            duplicate_high.request_path(),
            format!("/ipns/{name}?format=ipns-record")
        );
    }

    #[tokio::test]
    async fn ipns_gateways_are_queried_concurrently() {
        let keypair = test_ipns_keypair();
        let name = ipns_name(&keypair);
        let blocked_cid = raw_cid(b"blocked");
        let fast_cid = raw_cid(b"fast");
        let (blocked, release) =
            spawn_blocked_once_server(200, ipns_record(&keypair, blocked_cid.to_string(), 2));
        let fast = spawn_once_server(200, ipns_record(&keypair, fast_cid.to_string(), 2));
        let blocked_url = blocked.url.clone();
        let fast_url = fast.url.clone();
        let fast_requests = fast.requests;
        let resolve = tokio::spawn(async move {
            let client = reqwest::Client::new();
            let gateways = [blocked_url, fast_url];
            TrustlessArtifactFetcher::new(&client, &gateways)
                .resolve_ipns_manifest_candidates(&name)
                .await
        });

        let fast_request =
            tokio::task::spawn_blocking(move || fast_requests.recv_timeout(Duration::from_secs(1)))
                .await
                .expect("fast gateway request wait");
        release.send(()).expect("release blocked gateway");
        assert!(
            fast_request.is_ok(),
            "second gateway was not queried while the first was blocked"
        );
        let candidates = resolve
            .await
            .expect("IPNS resolution task")
            .expect("IPNS candidates");
        assert_eq!(
            candidates
                .iter()
                .map(|candidate| candidate.cid)
                .collect::<Vec<_>>(),
            vec![blocked_cid, fast_cid]
        );
    }

    #[tokio::test]
    async fn delayed_ipns_response_crossing_eol_is_rejected_at_acceptance() {
        let keypair = test_ipns_keypair();
        let name = ipns_name(&keypair);
        let record = ipns_record_with_validity(
            &keypair,
            raw_cid(b"delayed expired IPNS").to_string(),
            3,
            chrono::Duration::seconds(1),
        );
        let (server, release) = spawn_blocked_once_server(200, record);
        let MockServer { url, requests } = server;
        let acceptance_time = std::sync::Arc::new(std::sync::Mutex::new(SystemTime::now()));
        let task_clock = std::sync::Arc::clone(&acceptance_time);
        let task = tokio::spawn(async move {
            let client = reqwest::Client::new();
            let gateways = [url];
            let now = || *task_clock.lock().expect("acceptance clock lock");
            TrustlessArtifactFetcher::new(&client, &gateways)
                .resolve_ipns_manifest_candidates_with_clock(&name, &now)
                .await
        });
        tokio::task::spawn_blocking(move || requests.recv_timeout(Duration::from_secs(1)))
            .await
            .expect("join delayed IPNS request wait")
            .expect("delayed IPNS request");
        *acceptance_time.lock().expect("acceptance clock lock") =
            SystemTime::now() + Duration::from_mins(1);
        release.send(()).expect("release delayed IPNS response");

        assert!(matches!(
            task.await.expect("join delayed IPNS resolution"),
            Err(TrustlessArtifactError::ExpiredIpnsRecord { .. })
        ));
    }

    #[tokio::test]
    async fn early_ipns_candidate_expiring_while_delayed_peer_settles_is_filtered() {
        let keypair = test_ipns_keypair();
        let name = ipns_name(&keypair);
        let expired_cid = raw_cid(b"early expiring IPNS candidate");
        let current_cid = raw_cid(b"delayed current IPNS candidate");
        let early = spawn_once_server(
            200,
            ipns_record_with_validity(
                &keypair,
                expired_cid.to_string(),
                9,
                chrono::Duration::seconds(1),
            ),
        );
        let (delayed, release) = spawn_blocked_once_server(
            200,
            ipns_record_with_validity(
                &keypair,
                current_cid.to_string(),
                7,
                chrono::Duration::seconds(60 * 60 * 24 * 365),
            ),
        );
        let MockServer {
            url: early_url,
            requests: early_requests,
        } = early;
        let MockServer {
            url: delayed_url,
            requests: delayed_requests,
        } = delayed;
        let acceptance_time = std::sync::Arc::new(std::sync::Mutex::new(SystemTime::now()));
        let task_clock = std::sync::Arc::clone(&acceptance_time);
        let task = tokio::spawn(async move {
            let client = reqwest::Client::new();
            let gateways = [early_url, delayed_url];
            let now = || *task_clock.lock().expect("acceptance clock lock");
            TrustlessArtifactFetcher::new(&client, &gateways)
                .resolve_ipns_manifest_candidates_with_clock(&name, &now)
                .await
        });
        tokio::task::spawn_blocking(move || {
            early_requests.recv_timeout(Duration::from_secs(1))?;
            delayed_requests.recv_timeout(Duration::from_secs(1))?;
            Ok::<_, std::sync::mpsc::RecvTimeoutError>(())
        })
        .await
        .expect("join IPNS peer request wait")
        .expect("both IPNS peers received requests");
        *acceptance_time.lock().expect("acceptance clock lock") =
            SystemTime::now() + Duration::from_mins(1);
        release.send(()).expect("release delayed IPNS peer");

        let candidates = task
            .await
            .expect("join aggregate IPNS resolution")
            .expect("delayed current candidate survives");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].sequence, 7);
        assert_eq!(candidates[0].cid, current_cid);
    }

    #[tokio::test]
    async fn all_expired_ipns_candidates_return_redacted_expiry() {
        let keypair = test_ipns_keypair();
        let name = ipns_name(&keypair);
        let first = spawn_once_server(
            200,
            ipns_record_with_validity(
                &keypair,
                raw_cid(b"expired first").to_string(),
                5,
                chrono::Duration::seconds(1),
            ),
        );
        let second = spawn_once_server(
            200,
            ipns_record_with_validity(
                &keypair,
                raw_cid(b"expired second").to_string(),
                6,
                chrono::Duration::seconds(1),
            ),
        );
        let gateways = [
            sensitive_server_url(first.url.clone()),
            sensitive_server_url(second.url.clone()),
        ];
        let client = reqwest::Client::new();
        let accepted_at = SystemTime::now() + Duration::from_mins(1);

        let error = TrustlessArtifactFetcher::new_poi(&client, &gateways)
            .resolve_ipns_manifest_candidates_with_clock(&name, &|| accepted_at)
            .await
            .expect_err("all authenticated candidates expired before acceptance");

        assert!(matches!(
            &error,
            TrustlessArtifactError::ExpiredIpnsRecord { .. }
        ));
        assert_artifact_error_safe(&error);
    }

    #[tokio::test]
    async fn mixed_expired_and_current_ipns_candidates_keep_only_current_records() {
        let keypair = test_ipns_keypair();
        let name = ipns_name(&keypair);
        let expired_cid = raw_cid(b"expired high-sequence candidate");
        let current_cid = raw_cid(b"current lower-sequence candidate");
        let expired = spawn_once_server(
            200,
            ipns_record_with_validity(
                &keypair,
                expired_cid.to_string(),
                20,
                chrono::Duration::seconds(1),
            ),
        );
        let current = spawn_once_server(
            200,
            ipns_record_with_validity(
                &keypair,
                current_cid.to_string(),
                10,
                chrono::Duration::seconds(60 * 60 * 24 * 365),
            ),
        );
        let gateways = [expired.url.clone(), current.url.clone()];
        let client = reqwest::Client::new();
        let accepted_at = SystemTime::now() + Duration::from_mins(1);
        let samples = std::sync::atomic::AtomicUsize::new(0);

        let candidates = TrustlessArtifactFetcher::new(&client, &gateways)
            .resolve_ipns_manifest_candidates_with_clock(&name, &|| {
                samples.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                accepted_at
            })
            .await
            .expect("current candidate remains after aggregate expiry filtering");

        assert_eq!(samples.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].sequence, 10);
        assert_eq!(candidates[0].cid, current_cid);
    }

    #[tokio::test]
    async fn ipns_resolution_uses_valid_gateway_when_one_fails() {
        let keypair = test_ipns_keypair();
        let name = ipns_name(&keypair);
        let failing = spawn_once_server(500, Vec::new());
        let valid = spawn_once_server(200, ipns_record(&keypair, raw_cid(b"ok").to_string(), 2));
        let client = reqwest::Client::new();
        let gateways = [failing.url.clone(), valid.url.clone()];
        let fetcher = TrustlessArtifactFetcher::new(&client, &gateways);

        let candidates = fetcher
            .resolve_ipns_manifest_candidates(&name)
            .await
            .expect("valid second gateway");

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].sequence, 2);
    }

    #[tokio::test]
    async fn artifact_fetch_starts_from_preferred_gateway() {
        let artifact_bytes = b"preferred gateway artifact".to_vec();
        let cid = raw_cid(&artifact_bytes);
        let skipped = spawn_once_server(503, Vec::new());
        let preferred = spawn_once_server(200, car_bytes(cid, &[(cid, artifact_bytes.clone())]));
        let client = reqwest::Client::new();
        let gateways = [skipped.url.clone(), preferred.url.clone()];

        let fetched = TrustlessArtifactFetcher::new(&client, &gateways)
            .fetch_artifact_cid_with_metadata_from_gateway(
                &cid.to_string(),
                artifact_bytes.len() as u64,
                1,
            )
            .await
            .expect("fetch from preferred gateway");

        assert_eq!(fetched.bytes, artifact_bytes);
        assert_eq!(fetched.gateway_index, 1);
        assert_eq!(fetched.gateway_count, 2);
        assert_eq!(
            preferred.request_path(),
            format!("/ipfs/{cid}?format=car&dag-scope=entity")
        );
        assert!(
            skipped
                .requests
                .recv_timeout(Duration::from_millis(100))
                .is_err(),
            "earlier gateway should not be contacted before preferred gateway succeeds"
        );
    }

    #[tokio::test]
    async fn artifact_gateway_fallback_honors_bounded_attempt_count() {
        let cid = raw_cid(b"bounded gateway artifact");
        let skipped_before = spawn_once_server(503, Vec::new());
        let first = spawn_once_server(503, Vec::new());
        let second = spawn_once_server(503, Vec::new());
        let skipped_after = spawn_once_server(503, Vec::new());
        let client = reqwest::Client::new();
        let gateways = [
            skipped_before.url.clone(),
            first.url.clone(),
            second.url.clone(),
            skipped_after.url.clone(),
        ];

        TrustlessArtifactFetcher::new(&client, &gateways)
            .fetch_artifact_cid_with_metadata_from_gateway_bounded(&cid.to_string(), 24, 1, 2)
            .await
            .expect_err("two failed attempts exhaust the bound");

        let expected = format!("/ipfs/{cid}?format=car&dag-scope=entity");
        assert_eq!(first.request_path(), expected);
        assert_eq!(second.request_path(), expected);
        assert!(
            skipped_before
                .requests
                .recv_timeout(Duration::from_millis(100))
                .is_err()
        );
        assert!(
            skipped_after
                .requests
                .recv_timeout(Duration::from_millis(100))
                .is_err()
        );
    }

    #[tokio::test]
    async fn no_valid_ipns_records_is_reported() {
        let keypair = test_ipns_keypair();
        let name = ipns_name(&keypair);
        let failing = spawn_once_server(500, Vec::new());
        let client = reqwest::Client::new();
        let gateways = [failing.url.clone()];
        let fetcher = TrustlessArtifactFetcher::new(&client, &gateways);

        let error = fetcher
            .resolve_ipns_manifest_candidates(&name)
            .await
            .expect_err("no valid records");

        assert!(matches!(error, TrustlessArtifactError::HttpStatus { .. }));
    }

    fn raw_cid(bytes: &[u8]) -> Cid {
        Cid::new_v1(RAW_CODEC, Code::Sha2_256.digest(bytes))
    }

    fn reconstruct_for_test(
        root: Cid,
        blocks: &HashMap<Cid, Vec<u8>>,
        reconstructed_bytes: usize,
        unixfs_max_depth: usize,
        unixfs_max_link_visits: usize,
    ) -> Result<Vec<u8>, TrustlessArtifactError> {
        reconstruct_file(
            root,
            blocks,
            RetrievalLimits {
                response_bytes: usize::MAX,
                block_count: usize::MAX,
                reconstructed_bytes,
                unixfs_max_depth,
                unixfs_max_link_visits,
            },
        )
    }

    fn unixfs_chain(depth: usize) -> (Cid, HashMap<Cid, Vec<u8>>) {
        assert!(depth > 0);
        let mut blocks = HashMap::new();
        let mut root = raw_cid(b"x");
        blocks.insert(root, b"x".to_vec());
        for index in 1..depth {
            let name = format!("depth-{index}");
            let block = dag_pb_file_node(b"", &[(root, name.as_str(), 1)], Some(1));
            root = dag_pb_cid(&block);
            blocks.insert(root, block);
        }
        (root, blocks)
    }

    fn repeated_link_graph(count: usize) -> (Cid, HashMap<Cid, Vec<u8>>) {
        let child = raw_cid(b"x");
        let links = vec![(child, "repeated", 1); count];
        let root_block = dag_pb_file_node(b"", &links, Some(count as u64));
        let root = dag_pb_cid(&root_block);
        (
            root,
            HashMap::from([(root, root_block), (child, b"x".to_vec())]),
        )
    }

    fn dag_pb_cid(bytes: &[u8]) -> Cid {
        Cid::new_v1(DAG_PB_CODEC, Code::Sha2_256.digest(bytes))
    }

    fn dag_pb_file_node(data: &[u8], links: &[(Cid, &str, u64)], filesize: Option<u64>) -> Vec<u8> {
        dag_pb_node(
            Some(unixfs_data(
                UnixFsDataType::File,
                data,
                &links.iter().map(|(_, _, size)| *size).collect::<Vec<_>>(),
                filesize,
            )),
            links,
        )
    }

    fn dag_pb_node(data: Option<Vec<u8>>, links: &[(Cid, &str, u64)]) -> Vec<u8> {
        PbNode {
            links: links
                .iter()
                .map(|(cid, name, size)| PbLink {
                    cid: *cid,
                    name: Some((*name).to_string()),
                    size: Some(*size),
                })
                .collect(),
            data: data.map(Bytes::from),
        }
        .into_bytes()
    }

    fn unixfs_data(
        data_type: UnixFsDataType,
        data: &[u8],
        block_sizes: &[u64],
        filesize: Option<u64>,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut writer = Writer::new(&mut bytes);
        writer
            .write_with_tag(8, |writer| {
                writer.write_enum(unixfs_data_type_code(data_type))
            })
            .expect("type");
        if !data.is_empty() {
            writer
                .write_with_tag(18, |writer| writer.write_bytes(data))
                .expect("data");
        }
        if let Some(filesize) = filesize {
            writer
                .write_with_tag(24, |writer| writer.write_uint64(filesize))
                .expect("filesize");
        }
        for size in block_sizes {
            writer
                .write_with_tag(32, |writer| writer.write_uint64(*size))
                .expect("block size");
        }
        bytes
    }

    fn unixfs_data_type_code(data_type: UnixFsDataType) -> i32 {
        match data_type {
            UnixFsDataType::Raw => 0,
            UnixFsDataType::Directory => 1,
            UnixFsDataType::File => 2,
            UnixFsDataType::Metadata => 3,
            UnixFsDataType::Symlink => 4,
            UnixFsDataType::HamtShard => 5,
            UnixFsDataType::Unknown(value) => value,
        }
    }

    fn car_bytes(root: Cid, blocks: &[(Cid, Vec<u8>)]) -> Vec<u8> {
        let header = car_header(root);
        let mut car = Vec::new();
        write_varint(header.len(), &mut car);
        car.extend_from_slice(&header);
        for (cid, block) in blocks {
            let cid_bytes = cid.to_bytes();
            write_varint(cid_bytes.len() + block.len(), &mut car);
            car.extend_from_slice(&cid_bytes);
            car.extend_from_slice(block);
        }
        car
    }

    fn car_with_invalid_block_cid(root: Cid) -> Vec<u8> {
        let header = car_header(root);
        let mut car = Vec::new();
        write_varint(header.len(), &mut car);
        car.extend_from_slice(&header);

        let mut invalid_cid = Vec::new();
        invalid_cid.push(0x02); // Invalid CID version; rs-car 0.5.0 panics here without prevalidation.
        invalid_cid.push(u8::try_from(RAW_CODEC).expect("raw codec byte"));
        invalid_cid.extend_from_slice(&[0x12, 0x20]);
        invalid_cid.extend_from_slice(&[0_u8; 32]);
        let block = b"malformed";
        write_varint(invalid_cid.len() + block.len(), &mut car);
        car.extend_from_slice(&invalid_cid);
        car.extend_from_slice(block);
        car
    }

    fn car_with_noncanonical_v2_header() -> Vec<u8> {
        let mut car = Vec::new();
        let mut header = Vec::new();
        header.push(0xa1);
        write_cbor_text("version", &mut header);
        header.extend_from_slice(&[0x18, 0x02]);
        write_varint(header.len(), &mut car);
        car.extend_from_slice(&header);

        let mut v2_header = [0_u8; CARV2_HEADER_SIZE];
        let mut cid_bytes = vec![
            0x01,
            u8::try_from(RAW_CODEC).expect("raw codec byte"),
            0x12,
            0x20,
        ];
        cid_bytes.extend_from_slice(&[0_u8; 32]);
        v2_header[0] = u8::try_from(cid_bytes.len() + 3).expect("block length byte");
        v2_header[1..=cid_bytes.len()].copy_from_slice(&cid_bytes);
        car.extend_from_slice(&v2_header);
        car
    }

    fn car_header(root: Cid) -> Vec<u8> {
        let mut header = Vec::new();
        header.push(0xa2);
        write_cbor_text("roots", &mut header);
        header.push(0x81);
        header.extend_from_slice(&[0xd8, 0x2a]);
        let mut cid_link = vec![0_u8];
        cid_link.extend_from_slice(&root.to_bytes());
        write_cbor_bytes(&cid_link, &mut header);
        write_cbor_text("version", &mut header);
        header.push(0x01);
        header
    }

    fn write_cbor_text(value: &str, out: &mut Vec<u8>) {
        write_cbor_len(0x60, value.len(), out);
        out.extend_from_slice(value.as_bytes());
    }

    fn write_cbor_bytes(value: &[u8], out: &mut Vec<u8>) {
        write_cbor_len(0x40, value.len(), out);
        out.extend_from_slice(value);
    }

    fn write_cbor_len(major: u8, len: usize, out: &mut Vec<u8>) {
        match len {
            0..=23 => out.push(major | u8::try_from(len).expect("small len")),
            24..=0xff => {
                out.extend_from_slice(&[major | 0x18, u8::try_from(len).expect("u8 len")]);
            }
            0x100..=0xffff => {
                out.push(major | 0x19);
                out.extend_from_slice(&u16::try_from(len).expect("u16 len").to_be_bytes());
            }
            _ => panic!("fixture length too large"),
        }
    }

    fn write_varint(mut value: usize, out: &mut Vec<u8>) {
        while value >= 0x80 {
            out.push((u8::try_from(value & 0x7f).expect("varint byte")) | 0x80);
            value >>= 7;
        }
        out.push(u8::try_from(value).expect("varint final byte"));
    }

    fn test_ipns_keypair() -> Keypair {
        Keypair::ed25519_from_bytes([7_u8; 32]).expect("test keypair")
    }

    fn ipns_name(keypair: &Keypair) -> String {
        let peer_id = keypair.public().to_peer_id();
        Cid::new_v1(LIBP2P_KEY_CODEC, *peer_id.as_ref()).to_string()
    }

    fn ipns_record(keypair: &Keypair, value: String, sequence: u64) -> Vec<u8> {
        ipns_record_with_validity(
            keypair,
            value,
            sequence,
            chrono::Duration::seconds(60 * 60 * 24 * 365),
        )
    }

    fn ipns_record_with_validity(
        keypair: &Keypair,
        value: String,
        sequence: u64,
        validity: chrono::Duration,
    ) -> Vec<u8> {
        rust_ipns::Record::new(keypair, value, validity, sequence, 60)
            .expect("IPNS record")
            .encode()
            .expect("encoded IPNS record")
    }

    fn ipns_record_with_embedded_public_key(
        keypair: &Keypair,
        value: String,
        sequence: u64,
    ) -> Vec<u8> {
        let mut record = ipns_record(keypair, value, sequence);
        let public_key = keypair.public().encode_protobuf();
        Writer::new(&mut record)
            .write_with_tag(58, |writer| writer.write_bytes(&public_key))
            .expect("embedded public key");
        record
    }

    enum ControlledResponseCommand {
        Headers(u16),
        Chunk(Vec<u8>),
        Finish,
    }

    struct ControlledChunkServer {
        url: Url,
        requests: std::sync::mpsc::Receiver<String>,
        commands: std::sync::mpsc::Sender<(ControlledResponseCommand, std::sync::mpsc::Sender<()>)>,
    }

    impl ControlledChunkServer {
        async fn wait_for_request(&self) -> String {
            loop {
                match self.requests.try_recv() {
                    Ok(path) => return path,
                    Err(std::sync::mpsc::TryRecvError::Empty) => tokio::task::yield_now().await,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        panic!("controlled server stopped before receiving request")
                    }
                }
            }
        }

        fn send(&self, command: ControlledResponseCommand) {
            let (acknowledge, acknowledged) = std::sync::mpsc::channel();
            self.commands
                .send((command, acknowledge))
                .expect("send controlled response command");
            acknowledged
                .recv_timeout(Duration::from_secs(2))
                .expect("controlled response command acknowledged");
        }

        fn send_headers(&self, status: u16) {
            self.send(ControlledResponseCommand::Headers(status));
        }

        fn send_chunk(&self, chunk: impl Into<Vec<u8>>) {
            self.send(ControlledResponseCommand::Chunk(chunk.into()));
        }

        fn finish(&self) {
            self.send(ControlledResponseCommand::Finish);
        }

        fn assert_no_request(&self) {
            assert!(matches!(
                self.requests.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            ));
        }
    }

    fn spawn_controlled_chunk_server() -> ControlledChunkServer {
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind controlled chunk server");
        let url = Url::parse(&format!(
            "http://{}",
            listener.local_addr().expect("controlled server address")
        ))
        .expect("controlled server URL");
        let (request_tx, requests) = std::sync::mpsc::channel();
        let (commands, command_rx) =
            std::sync::mpsc::channel::<(ControlledResponseCommand, std::sync::mpsc::Sender<()>)>();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept controlled request");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let read =
                    std::io::Read::read(&mut stream, &mut buffer).expect("read controlled request");
                if read == 0 {
                    return;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request_text = String::from_utf8_lossy(&request);
            let path = request_text
                .split_whitespace()
                .nth(1)
                .expect("controlled request path")
                .to_string();
            request_tx.send(path).expect("record controlled request");

            while let Ok((command, acknowledge)) = command_rx.recv() {
                let finish = matches!(&command, ControlledResponseCommand::Finish);
                let write_result = match command {
                    ControlledResponseCommand::Headers(status) => {
                        let reason = if status == 200 { "OK" } else { "ERROR" };
                        let headers = format!(
                            "HTTP/1.1 {status} {reason}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                        );
                        std::io::Write::write_all(&mut stream, headers.as_bytes())
                    }
                    ControlledResponseCommand::Chunk(chunk) => {
                        let frame = format!("{:x}\r\n", chunk.len());
                        std::io::Write::write_all(&mut stream, frame.as_bytes())
                            .and_then(|()| std::io::Write::write_all(&mut stream, &chunk))
                            .and_then(|()| std::io::Write::write_all(&mut stream, b"\r\n"))
                    }
                    ControlledResponseCommand::Finish => {
                        std::io::Write::write_all(&mut stream, b"0\r\n\r\n")
                    }
                };
                let _ = acknowledge.send(());
                if write_result.is_err() || finish {
                    break;
                }
            }
        });
        ControlledChunkServer {
            url,
            requests,
            commands,
        }
    }

    struct MockServer {
        url: Url,
        requests: std::sync::mpsc::Receiver<String>,
    }

    impl MockServer {
        fn request_path(&self) -> String {
            self.requests
                .recv_timeout(Duration::from_secs(2))
                .expect("request path")
        }
    }

    fn spawn_once_server(status: u16, body: Vec<u8>) -> MockServer {
        spawn_once_server_controlled(status, body, None)
    }

    fn spawn_blocked_once_server(
        status: u16,
        body: Vec<u8>,
    ) -> (MockServer, std::sync::mpsc::Sender<()>) {
        let (release, release_rx) = std::sync::mpsc::channel();
        (
            spawn_once_server_controlled(status, body, Some(release_rx)),
            release,
        )
    }

    fn spawn_once_server_controlled(
        status: u16,
        body: Vec<u8>,
        release: Option<std::sync::mpsc::Receiver<()>>,
    ) -> MockServer {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind server");
        let url = Url::parse(&format!(
            "http://{}",
            listener.local_addr().expect("local addr")
        ))
        .expect("server URL");
        let (tx, requests) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let mut request = Vec::new();
            let mut buf = [0_u8; 1024];
            loop {
                let read = std::io::Read::read(&mut stream, &mut buf).expect("read request");
                assert!(read > 0, "client closed before request headers");
                request.extend_from_slice(&buf[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request_text = String::from_utf8_lossy(&request);
            let path = request_text
                .split_whitespace()
                .nth(1)
                .expect("request path")
                .to_string();
            tx.send(path).expect("record request path");
            if let Some(release) = release {
                release.recv().expect("release response");
            }

            let reason = if status == 200 { "OK" } else { "ERROR" };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            std::io::Write::write_all(&mut stream, response.as_bytes()).expect("headers");
            std::io::Write::write_all(&mut stream, &body).expect("body");
        });

        MockServer { url, requests }
    }
}
