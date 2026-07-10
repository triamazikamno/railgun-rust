use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::str;
use std::time::{Instant, SystemTime};

use bytes::Bytes;
use chrono::Utc;
use cid::{Cid, Version};
use futures::{StreamExt, io::Cursor};
use ipld_core::{codec::Codec, ipld::Ipld};
use ipld_dagpb::PbNode;
use libp2p_identity::{PeerId, PublicKey};
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
}

#[derive(Debug, Clone, Copy)]
struct RetrievalLimits {
    response_bytes: usize,
    block_count: usize,
    reconstructed_bytes: usize,
}

impl RetrievalLimits {
    const fn manifest() -> Self {
        Self {
            response_bytes: MANIFEST_CAR_MAX_BYTES,
            block_count: MANIFEST_CAR_MAX_BLOCKS,
            reconstructed_bytes: MANIFEST_JSON_MAX_BYTES,
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
        })
    }
}

pub(crate) struct TrustlessArtifactFetcher<'a> {
    client: &'a reqwest::Client,
    gateways: &'a [Url],
}

pub(crate) struct TrustlessArtifactFetchResult {
    pub(crate) bytes: Vec<u8>,
    pub(crate) gateway_host: String,
    pub(crate) gateway_index: usize,
    pub(crate) gateway_count: usize,
}

impl<'a> TrustlessArtifactFetcher<'a> {
    pub(crate) const fn new(client: &'a reqwest::Client, gateways: &'a [Url]) -> Self {
        Self { client, gateways }
    }

    pub(crate) async fn fetch_manifest_cid(
        &self,
        cid: &str,
    ) -> Result<Vec<u8>, TrustlessArtifactError> {
        let cid = parse_cid(cid)?;
        self.fetch_cid_bytes(cid, RetrievalLimits::manifest(), "manifest")
            .await
            .map(|result| result.bytes)
    }

    pub(crate) async fn fetch_artifact_cid(
        &self,
        cid: &str,
        byte_size: u64,
    ) -> Result<Vec<u8>, TrustlessArtifactError> {
        let cid = parse_cid(cid)?;
        self.fetch_cid_bytes(cid, RetrievalLimits::artifact(byte_size)?, "artifact")
            .await
            .map(|result| result.bytes)
    }

    pub(crate) async fn fetch_artifact_cid_with_metadata(
        &self,
        cid: &str,
        byte_size: u64,
    ) -> Result<TrustlessArtifactFetchResult, TrustlessArtifactError> {
        let cid = parse_cid(cid)?;
        self.fetch_cid_bytes(cid, RetrievalLimits::artifact(byte_size)?, "artifact")
            .await
    }

    pub(crate) async fn resolve_ipns_manifest_candidates(
        &self,
        name: &str,
        now: SystemTime,
    ) -> Result<Vec<IpnsManifestCandidate>, TrustlessArtifactError> {
        if self.gateways.is_empty() {
            return Err(TrustlessArtifactError::NoGateways);
        }

        let peer_id = expected_ipns_peer_id(name)?;
        let mut candidates = Vec::new();
        let mut last_error = None;
        let gateway_count = self.gateways.len();

        for (gateway_index, gateway) in self.gateways.iter().enumerate() {
            let gateway_host = gateway_host(gateway);
            let attempt_started = Instant::now();
            let url = ipns_record_gateway_url(gateway, name);
            match self.fetch_ipns_record_candidate(&url, peer_id, now).await {
                Ok(candidate) => {
                    debug!(
                        gateway_host,
                        gateway_index,
                        gateway_count,
                        ipns_name = name,
                        cid = %candidate.cid,
                        ipns_sequence = candidate.sequence,
                        elapsed_ms = attempt_started.elapsed().as_millis(),
                        "POI artifact IPNS gateway returned verified record"
                    );
                    candidates.push(candidate);
                }
                Err(err) => {
                    debug!(
                        ?err,
                        gateway_host,
                        gateway_index,
                        gateway_count,
                        ipns_name = name,
                        elapsed_ms = attempt_started.elapsed().as_millis(),
                        "POI artifact IPNS gateway failed"
                    );
                    last_error = Some(err);
                }
            }
        }

        if candidates.is_empty() {
            return Err(last_error.unwrap_or(TrustlessArtifactError::NoValidIpnsRecords));
        }

        candidates.sort_by_key(|candidate| Reverse(candidate.sequence));
        candidates.dedup_by(|left, right| left.sequence == right.sequence && left.cid == right.cid);
        Ok(candidates)
    }

    async fn fetch_cid_bytes(
        &self,
        cid: Cid,
        limits: RetrievalLimits,
        resource: &'static str,
    ) -> Result<TrustlessArtifactFetchResult, TrustlessArtifactError> {
        if self.gateways.is_empty() {
            return Err(TrustlessArtifactError::NoGateways);
        }

        let mut last_error = None;
        let gateway_count = self.gateways.len();
        for (gateway_index, gateway) in self.gateways.iter().enumerate() {
            let gateway_host = gateway_host(gateway);
            let attempt_started = Instant::now();
            let url = car_gateway_url(gateway, &cid);
            match self.fetch_cid_bytes_from_url(cid, &url, limits).await {
                Ok(bytes) => {
                    if gateway_index > 0 {
                        debug!(
                            gateway_host,
                            gateway_index,
                            gateway_count,
                            resource,
                            cid = %cid,
                            bytes = bytes.len(),
                            elapsed_ms = attempt_started.elapsed().as_millis(),
                            "POI artifact CID gateway fetch succeeded after fallback"
                        );
                    }
                    return Ok(TrustlessArtifactFetchResult {
                        bytes,
                        gateway_host: gateway_host.to_string(),
                        gateway_index,
                        gateway_count,
                    });
                }
                Err(err) => {
                    debug!(
                        ?err,
                        gateway_host,
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
        limits: RetrievalLimits,
    ) -> Result<Vec<u8>, TrustlessArtifactError> {
        let car_bytes =
            fetch_response_bytes(self.client, url, Some(CAR_ACCEPT), limits.response_bytes).await?;
        let blocks = decode_car_blocks(&car_bytes, cid, limits.block_count).await?;
        reconstruct_file(cid, &blocks, limits.reconstructed_bytes)
    }

    async fn fetch_ipns_record_candidate(
        &self,
        url: &Url,
        peer_id: PeerId,
        now: SystemTime,
    ) -> Result<IpnsManifestCandidate, TrustlessArtifactError> {
        let bytes = fetch_response_bytes(
            self.client,
            url,
            Some(IPNS_RECORD_ACCEPT),
            IPNS_RECORD_MAX_BYTES,
        )
        .await?;
        verify_ipns_record_candidate(&bytes, peer_id, now)
    }
}

pub(crate) async fn fetch_manifest_url(
    client: &reqwest::Client,
    url: &Url,
) -> Result<Vec<u8>, TrustlessArtifactError> {
    fetch_response_bytes(client, url, None, MANIFEST_JSON_MAX_BYTES).await
}

async fn fetch_response_bytes(
    client: &reqwest::Client,
    url: &Url,
    accept: Option<HeaderValue>,
    limit: usize,
) -> Result<Vec<u8>, TrustlessArtifactError> {
    let mut request = client.get(url.clone());
    if let Some(accept) = accept {
        request = request.header(ACCEPT, accept);
    }
    let mut response = request.send().await?;
    let status = response.status();
    if !status.is_success() {
        return Err(TrustlessArtifactError::HttpStatus {
            url: url.clone(),
            status,
        });
    }

    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        let next_len = bytes.len().checked_add(chunk.len()).ok_or(
            TrustlessArtifactError::ResponseTooLarge {
                url: url.clone(),
                limit,
            },
        )?;
        if next_len > limit {
            return Err(TrustlessArtifactError::ResponseTooLarge {
                url: url.clone(),
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
    limit: usize,
) -> Result<Vec<u8>, TrustlessArtifactError> {
    let mut out = Vec::new();
    let mut visiting = HashSet::new();
    append_cid(root, blocks, limit, &mut visiting, &mut out)?;
    Ok(out)
}

fn append_cid(
    cid: Cid,
    blocks: &HashMap<Cid, Vec<u8>>,
    limit: usize,
    visiting: &mut HashSet<Cid>,
    out: &mut Vec<u8>,
) -> Result<usize, TrustlessArtifactError> {
    let block = blocks
        .get(&cid)
        .ok_or(TrustlessArtifactError::MissingBlock { cid })?;
    match cid.codec() {
        RAW_CODEC => append_bytes(out, block, limit),
        DAG_PB_CODEC => append_dag_pb(cid, block, blocks, limit, visiting, out),
        codec => Err(TrustlessArtifactError::UnsupportedCodec { cid, codec }),
    }
}

fn append_dag_pb(
    cid: Cid,
    block: &[u8],
    blocks: &HashMap<Cid, Vec<u8>>,
    limit: usize,
    visiting: &mut HashSet<Cid>,
    out: &mut Vec<u8>,
) -> Result<usize, TrustlessArtifactError> {
    if !visiting.insert(cid) {
        return Err(TrustlessArtifactError::Cycle { cid });
    }

    let result = append_dag_pb_inner(block, blocks, limit, visiting, out);
    visiting.remove(&cid);
    result
}

fn append_dag_pb_inner(
    block: &[u8],
    blocks: &HashMap<Cid, Vec<u8>>,
    limit: usize,
    visiting: &mut HashSet<Cid>,
    out: &mut Vec<u8>,
) -> Result<usize, TrustlessArtifactError> {
    let start_len = out.len();
    let node = PbNode::from_bytes(Bytes::copy_from_slice(block))?;
    let data = node
        .data
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
            if let Some(data) = unixfs.data {
                append_bytes(out, data, limit)?;
            }
        }
        UnixFsDataType::File => {
            if !unixfs.blocksizes.is_empty() && unixfs.blocksizes.len() != node.links.len() {
                return Err(TrustlessArtifactError::MalformedUnixFsFile(
                    "UnixFS block sizes must match link count",
                ));
            }
            if let Some(data) = unixfs.data {
                append_bytes(out, data, limit)?;
            }
            for (index, link) in node.links.iter().enumerate() {
                let before_child = out.len();
                append_cid(link.cid, blocks, limit, visiting, out)?;
                if let Some(expected) = unixfs.blocksizes.get(index) {
                    let actual = u64::try_from(out.len() - before_child)
                        .map_err(|_| TrustlessArtifactError::ReconstructedTooLarge { limit })?;
                    if actual != *expected {
                        return Err(TrustlessArtifactError::MalformedUnixFsFile(
                            "UnixFS child size does not match declared block size",
                        ));
                    }
                }
            }
        }
        other => return Err(TrustlessArtifactError::UnsupportedUnixFsType { data_type: other }),
    }

    let appended = out.len() - start_len;
    if let Some(filesize) = unixfs.filesize {
        let actual = u64::try_from(appended)
            .map_err(|_| TrustlessArtifactError::ReconstructedTooLarge { limit })?;
        if actual != filesize {
            return Err(TrustlessArtifactError::MalformedUnixFsFile(
                "UnixFS file size does not match reconstructed bytes",
            ));
        }
    }
    Ok(appended)
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
    now: SystemTime,
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
    let now = chrono::DateTime::<Utc>::from(now);
    if eol <= now {
        return Err(TrustlessArtifactError::ExpiredIpnsRecord { eol });
    }
    let data = record
        .data()
        .map_err(|source| TrustlessArtifactError::InvalidIpnsRecord { source })?;
    let cid = parse_ipns_value(data.value())?;
    Ok(IpnsManifestCandidate {
        sequence: data.sequence(),
        cid,
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
    Cid::try_from(value).map_err(|source| TrustlessArtifactError::InvalidCid {
        value: value.to_string(),
        source,
    })
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

fn gateway_host(gateway: &Url) -> &str {
    gateway.host_str().unwrap_or("<unknown>")
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

#[derive(Debug, Error)]
pub(crate) enum TrustlessArtifactError {
    #[error("POI artifact source has no gateway URLs configured")]
    NoGateways,
    #[error("invalid CID {value}")]
    InvalidCid {
        value: String,
        #[source]
        source: cid::Error,
    },
    #[error("POI artifact HTTP request failed")]
    Http(#[from] reqwest::Error),
    #[error("POI artifact HTTP request to {url} returned {status}")]
    HttpStatus {
        url: Url,
        status: reqwest::StatusCode,
    },
    #[error("POI artifact response from {url} exceeds {limit} bytes")]
    ResponseTooLarge { url: Url, limit: usize },
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
mod tests {
    use super::*;

    use std::time::{Duration, UNIX_EPOCH};

    use ipld_dagpb::{PbLink, PbNode};
    use libp2p_identity::Keypair;
    use multihash_codetable::{Code, MultihashDigest};
    use quick_protobuf::Writer;

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
        let bytes = reconstruct_file(root, &blocks, 1024).expect("raw root");

        assert_eq!(bytes, b"hello raw");
    }

    #[tokio::test]
    async fn duplicate_car_blocks_count_toward_limit() {
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
        let bytes = reconstruct_file(root, &blocks, 1024).expect("DAG-PB file");

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
        let bytes = reconstruct_file(root, &blocks, 1024).expect("DAG-PB leaves");

        assert_eq!(bytes, b"root-leftright");
    }

    #[tokio::test]
    async fn missing_block_is_rejected() {
        let child = raw_cid(b"child");
        let root_block = dag_pb_file_node(b"", &[(child, "child", 5)], Some(5));
        let root = dag_pb_cid(&root_block);
        let car = car_bytes(root, &[(root, root_block)]);

        let blocks = decode_car_blocks(&car, root, 8).await.expect("CAR blocks");
        let error = reconstruct_file(root, &blocks, 1024).expect_err("missing child block");

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
        let error = reconstruct_file(root, &blocks, 1024).expect_err("directory rejected");

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
        let error = reconstruct_file(root, &blocks, 3).expect_err("limit exceeded");

        assert!(matches!(
            error,
            TrustlessArtifactError::ReconstructedTooLarge { limit: 3 }
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
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let prefixed = ipns_record(&keypair, format!("/ipfs/{manifest_cid}"), 3);
        let bare = ipns_record(&keypair, manifest_cid.to_string(), 2);

        let prefixed = verify_ipns_record_candidate(&prefixed, peer_id, now).expect("prefixed");
        let bare = verify_ipns_record_candidate(&bare, peer_id, now).expect("bare");

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

        let error = verify_ipns_record_candidate(
            &record,
            peer_id,
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        )
        .expect_err("invalid signature");

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

        let error = verify_ipns_record_candidate(
            &record,
            peer_id,
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        )
        .expect_err("wrong embedded public key");

        assert!(matches!(
            error,
            TrustlessArtifactError::IpnsPublicKeyMismatch { .. }
        ));
    }

    #[test]
    fn expired_ipns_record_is_rejected() {
        let keypair = test_ipns_keypair();
        let peer_id = keypair.public().to_peer_id();
        let record = ipns_record(&keypair, raw_cid(b"manifest").to_string(), 1);

        let error = verify_ipns_record_candidate(
            &record,
            peer_id,
            UNIX_EPOCH + Duration::from_secs(4_000_000_000),
        )
        .expect_err("expired");

        assert!(matches!(
            error,
            TrustlessArtifactError::ExpiredIpnsRecord { .. }
        ));
    }

    #[test]
    fn unsupported_ipns_value_is_rejected() {
        let keypair = test_ipns_keypair();
        let peer_id = keypair.public().to_peer_id();
        let record = ipns_record(&keypair, "/ipns/not-supported".to_string(), 1);

        let error = verify_ipns_record_candidate(
            &record,
            peer_id,
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        )
        .expect_err("unsupported value");

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

        let error = verify_ipns_record_candidate(
            &bytes,
            peer_id,
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        )
        .expect_err("oversized");

        assert!(matches!(
            error,
            TrustlessArtifactError::IpnsRecordTooLarge { .. }
        ));
    }

    #[tokio::test]
    async fn ipns_candidates_are_sorted_by_descending_sequence() {
        let keypair = test_ipns_keypair();
        let name = ipns_name(&keypair);
        let low = spawn_once_server(200, ipns_record(&keypair, raw_cid(b"low").to_string(), 1));
        let high = spawn_once_server(200, ipns_record(&keypair, raw_cid(b"high").to_string(), 5));
        let client = reqwest::Client::new();
        let gateways = [low.url.clone(), high.url.clone()];
        let fetcher = TrustlessArtifactFetcher::new(&client, &gateways);

        let candidates = fetcher
            .resolve_ipns_manifest_candidates(
                &name,
                UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            )
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
            .resolve_ipns_manifest_candidates(
                &name,
                UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            )
            .await
            .expect("valid second gateway");

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].sequence, 2);
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
            .resolve_ipns_manifest_candidates(
                &name,
                UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            )
            .await
            .expect_err("no valid records");

        assert!(matches!(error, TrustlessArtifactError::HttpStatus { .. }));
    }

    fn raw_cid(bytes: &[u8]) -> Cid {
        Cid::new_v1(RAW_CODEC, Code::Sha2_256.digest(bytes))
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
        rust_ipns::Record::new(
            keypair,
            value,
            chrono::Duration::seconds(60 * 60 * 24 * 365),
            sequence,
            60,
        )
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
