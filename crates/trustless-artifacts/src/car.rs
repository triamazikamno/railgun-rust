//! CAR decoding and validation, `UnixFS` file reconstruction and the limits they enforce.

use std::collections::{HashMap, HashSet};

use bytes::Bytes;
use cid::Cid;
use futures::{StreamExt, io::Cursor};
use ipld_core::{codec::Codec, ipld::Ipld};
use ipld_dagpb::{PbLink, PbNode};
use quick_protobuf::BytesReader;
use serde_ipld_dagcbor::codec::DagCborCodec;

use crate::error::TrustlessArtifactError;
use crate::{
    ARTIFACT_CAR_FIXED_OVERHEAD_BYTES, ARTIFACT_CAR_MAX_BLOCKS, ARTIFACT_CAR_MIN_OVERHEAD_BYTES,
    CAR_BLOCK_MAX_BYTES, CAR_HEADER_MAX_BYTES, CARV2_DATA_OFFSET_OFFSET, CARV2_DATA_SIZE_OFFSET,
    CARV2_PRAGMA, CARV2_PRAGMA_AND_HEADER_SIZE, DAG_PB_CODEC, MANIFEST_CAR_MAX_BLOCKS,
    MANIFEST_CAR_MAX_BYTES, MANIFEST_JSON_MAX_BYTES, RAW_CODEC,
};

#[derive(Debug, Clone, Copy)]
pub(crate) struct RetrievalLimits {
    pub(crate) response_bytes: usize,
    pub(crate) block_count: usize,
    pub(crate) reconstructed_bytes: usize,
    pub(crate) unixfs_max_depth: usize,
    pub(crate) unixfs_max_link_visits: usize,
}

impl RetrievalLimits {
    pub(crate) const fn manifest() -> Self {
        Self {
            response_bytes: MANIFEST_CAR_MAX_BYTES,
            block_count: MANIFEST_CAR_MAX_BLOCKS,
            reconstructed_bytes: MANIFEST_JSON_MAX_BYTES,
            unixfs_max_depth: MANIFEST_CAR_MAX_BLOCKS,
            unixfs_max_link_visits: MANIFEST_CAR_MAX_BLOCKS,
        }
    }

    pub(crate) fn artifact(byte_size: u64) -> Result<Self, TrustlessArtifactError> {
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

pub(crate) async fn decode_car_blocks(
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

pub(crate) fn reconstruct_file(
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnixFsDataType {
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
