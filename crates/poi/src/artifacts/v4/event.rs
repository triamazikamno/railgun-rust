//! The binary event artifact: its descriptor, the `POIEVT4` codec, and the
//! range and continuity rules for checkpoint, tail and bridge artifacts.

use alloy::hex;
use alloy::primitives::FixedBytes;
use serde::{Deserialize, Serialize};

use crate::artifacts::manifest::ArtifactDescriptor;
use crate::artifacts::snapshot::SnapshotEvent;
use crate::artifacts::verify::verify_poi_event;
use crate::poi::{PoiEventType, SignedPoiEvent};

use super::limits::require_event_artifact_size;
use super::{
    ArtifactEncoding, CHECKPOINT_EVENT_SPAN, Compression, Error, EventArtifactKind, EventRange,
    FORMAT_VERSION, Scope, require_format_version, require_start_root, usize_to_u64,
};

pub(super) const EVENT_MAGIC: &[u8; 8] = b"POIEVT4\0";
pub(super) const EVENT_HEADER_FIXED_BYTES: usize = 147;
pub(super) const EVENT_RECORD_BYTES: usize = 97;
const EVENT_RECORD_BYTES_U64: u64 = 97;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventArtifactDescriptor {
    pub artifact: ArtifactDescriptor,
    pub format_version: u16,
    pub scope: Scope,
    pub kind: EventArtifactKind,
    pub range: EventRange,
    pub row_count: u64,
    pub encoding: ArtifactEncoding,
    pub compression: Compression,
    pub start_root: Option<FixedBytes<32>>,
    pub end_root: FixedBytes<32>,
}

impl EventArtifactDescriptor {
    pub fn validate(&self) -> Result<(), Error> {
        require_format_version(self.format_version)?;
        if self.encoding != ArtifactEncoding::PoiEventBinary {
            return Err(Error::UnsupportedEncoding);
        }
        if self.compression != Compression::Identity {
            return Err(Error::UnsupportedCompression);
        }
        let range_count = self.range.row_count()?;
        if self.row_count == 0 || self.row_count != range_count {
            return Err(Error::RowCountMismatch {
                expected: range_count,
                actual: self.row_count,
            });
        }
        require_start_root(self.range.start_index, self.start_root)?;
        require_event_artifact_size(self.artifact.byte_size)?;
        let expected_byte_size = expected_event_artifact_size(&self.scope, self.row_count)?;
        if self.artifact.byte_size != expected_byte_size {
            return Err(Error::EventDescriptorByteSizeMismatch {
                expected: expected_byte_size,
                actual: self.artifact.byte_size,
            });
        }
        if self.kind == EventArtifactKind::Checkpoint {
            validate_checkpoint_range(self.range, self.row_count)?;
        }
        Ok(())
    }

    pub fn verify_bytes(&self, bytes: &[u8]) -> Result<EventArtifact, Error> {
        self.validate()?;
        self.artifact.verify_bytes(bytes)?;
        let decoded = EventArtifact::read(bytes)?;
        let decoded_row_count = usize_to_u64(decoded.events.len())?;
        if decoded.format_version != self.format_version
            || decoded.scope != self.scope
            || decoded.kind != self.kind
            || decoded.range != self.range
            || decoded_row_count != self.row_count
            || decoded.encoding != self.encoding
            || decoded.compression != self.compression
            || decoded.start_root != self.start_root
            || decoded.end_root != self.end_root
        {
            return Err(Error::DescriptorBodyMismatch);
        }
        Ok(decoded)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventArtifact {
    pub format_version: u16,
    pub scope: Scope,
    pub kind: EventArtifactKind,
    pub range: EventRange,
    pub encoding: ArtifactEncoding,
    pub compression: Compression,
    pub start_root: Option<FixedBytes<32>>,
    pub end_root: FixedBytes<32>,
    pub events: Vec<SnapshotEvent>,
}

impl EventArtifact {
    pub fn new(
        scope: Scope,
        kind: EventArtifactKind,
        start_root: Option<FixedBytes<32>>,
        end_root: FixedBytes<32>,
        events: Vec<SnapshotEvent>,
    ) -> Result<Self, Error> {
        let first = events.first().ok_or(Error::EmptyEventArtifact)?;
        let last = events.last().ok_or(Error::EmptyEventArtifact)?;
        let artifact = Self {
            format_version: FORMAT_VERSION,
            scope,
            kind,
            range: EventRange::new(first.event_index, last.event_index)?,
            encoding: ArtifactEncoding::PoiEventBinary,
            compression: Compression::Identity,
            start_root,
            end_root,
            events,
        };
        artifact.validate()?;
        Ok(artifact)
    }

    pub fn validate(&self) -> Result<(), Error> {
        require_format_version(self.format_version)?;
        if self.encoding != ArtifactEncoding::PoiEventBinary {
            return Err(Error::UnsupportedEncoding);
        }
        if self.compression != Compression::Identity {
            return Err(Error::UnsupportedCompression);
        }
        let row_count = u64::try_from(self.events.len()).map_err(|_| Error::ArithmeticOverflow)?;
        if row_count == 0 || self.range.row_count()? != row_count {
            return Err(Error::RowCountMismatch {
                expected: self.range.row_count()?,
                actual: row_count,
            });
        }
        require_start_root(self.range.start_index, self.start_root)?;
        if self.kind == EventArtifactKind::Checkpoint {
            validate_checkpoint_range(self.range, row_count)?;
        }
        for (offset, event) in self.events.iter().enumerate() {
            let offset = usize_to_u64(offset)?;
            let expected = self
                .range
                .start_index
                .checked_add(offset)
                .ok_or(Error::ArithmeticOverflow)?;
            if event.event_index != expected {
                return Err(Error::NonContiguousEvent {
                    expected,
                    actual: event.event_index,
                });
            }
        }
        Ok(())
    }

    pub fn verify_signatures(&self) -> Result<(), Error> {
        for event in &self.events {
            verify_poi_event(
                &SignedPoiEvent {
                    index: event.event_index,
                    blinded_commitment: FixedBytes::from(event.blinded_commitment),
                    signature: hex::encode_prefixed(event.signature),
                    event_type: event.event_type,
                },
                &self.scope.list_key.0,
            )
            .map_err(|source| Error::EventVerify {
                event_index: event.event_index,
                source,
            })?;
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let txid_version = self.scope.txid_version.as_bytes();
        let txid_len = u16::try_from(txid_version.len()).map_err(|_| Error::TxidVersionTooLong)?;
        let header_len = EVENT_HEADER_FIXED_BYTES
            .checked_add(txid_version.len())
            .ok_or(Error::ArithmeticOverflow)?;
        let header_len_u16 = u16::try_from(header_len).map_err(|_| Error::TxidVersionTooLong)?;
        let records_len = self
            .events
            .len()
            .checked_mul(EVENT_RECORD_BYTES)
            .ok_or(Error::ArithmeticOverflow)?;
        let total_len = header_len
            .checked_add(records_len)
            .ok_or(Error::ArithmeticOverflow)?;
        require_event_artifact_size(usize_to_u64(total_len)?)?;

        let mut bytes = vec![0_u8; header_len];
        bytes[0..8].copy_from_slice(EVENT_MAGIC);
        bytes[8..10].copy_from_slice(&self.format_version.to_le_bytes());
        bytes[10..12].copy_from_slice(&header_len_u16.to_le_bytes());
        bytes[12] = self.scope.chain_type;
        bytes[13] = event_kind_discriminant(self.kind);
        bytes[14] = encoding_discriminant(self.encoding);
        bytes[15] = compression_discriminant(self.compression);
        bytes[16..48].copy_from_slice(self.scope.list_key.as_slice());
        bytes[48..56].copy_from_slice(&self.scope.chain_id.to_le_bytes());
        bytes[56..58].copy_from_slice(&txid_len.to_le_bytes());
        bytes[58..66].copy_from_slice(&self.range.start_index.to_le_bytes());
        bytes[66..74].copy_from_slice(&self.range.end_index.to_le_bytes());
        bytes[74..82].copy_from_slice(&usize_to_u64(self.events.len())?.to_le_bytes());
        if let Some(start_root) = self.start_root {
            bytes[82] = 1;
            bytes[83..115].copy_from_slice(start_root.as_slice());
        }
        bytes[115..147].copy_from_slice(self.end_root.as_slice());
        bytes[147..header_len].copy_from_slice(txid_version);

        for event in &self.events {
            bytes.extend_from_slice(&event.blinded_commitment);
            bytes.extend_from_slice(&event.signature);
            bytes.push(event_type_discriminant(event.event_type));
        }
        Ok(bytes)
    }

    pub fn read(bytes: &[u8]) -> Result<Self, Error> {
        let actual_byte_size = usize_to_u64(bytes.len())?;
        require_event_artifact_size(actual_byte_size)?;
        ensure_len(bytes, EVENT_HEADER_FIXED_BYTES)?;
        if &bytes[0..8] != EVENT_MAGIC {
            return Err(Error::InvalidEventMagic);
        }
        let format_version = read_u16(bytes, 8)?;
        require_format_version(format_version)?;
        let header_len = usize::from(read_u16(bytes, 10)?);
        ensure_len(bytes, header_len)?;
        let txid_len = usize::from(read_u16(bytes, 56)?);
        let expected_header_len = EVENT_HEADER_FIXED_BYTES
            .checked_add(txid_len)
            .ok_or(Error::ArithmeticOverflow)?;
        if header_len != expected_header_len {
            return Err(Error::InvalidEventHeaderLength);
        }
        let kind = event_kind_from_discriminant(bytes[13])?;
        let encoding = encoding_from_discriminant(bytes[14])?;
        let compression = compression_from_discriminant(bytes[15])?;
        let start_index = read_u64(bytes, 58)?;
        let end_index = read_u64(bytes, 66)?;
        let row_count = read_u64(bytes, 74)?;
        let start_root = match bytes[82] {
            0 if bytes[83..115].iter().all(|byte| *byte == 0) => None,
            1 => Some(FixedBytes::from(read_bytes::<32>(bytes, 83)?)),
            _ => return Err(Error::InvalidOptionalRoot),
        };
        let records_len = row_count
            .checked_mul(EVENT_RECORD_BYTES_U64)
            .ok_or(Error::ArithmeticOverflow)?;
        let expected_len = u64::try_from(header_len)
            .map_err(|_| Error::ArithmeticOverflow)?
            .checked_add(records_len)
            .ok_or(Error::ArithmeticOverflow)?;
        if expected_len != actual_byte_size {
            return Err(Error::EventByteLengthMismatch {
                expected: expected_len,
                actual: actual_byte_size,
            });
        }
        let event_capacity = usize::try_from(row_count).map_err(|_| Error::ArithmeticOverflow)?;
        let mut events = Vec::with_capacity(event_capacity);
        for offset in 0..row_count {
            let offset_usize = usize::try_from(offset).map_err(|_| Error::ArithmeticOverflow)?;
            let record_offset = header_len
                .checked_add(
                    offset_usize
                        .checked_mul(EVENT_RECORD_BYTES)
                        .ok_or(Error::ArithmeticOverflow)?,
                )
                .ok_or(Error::ArithmeticOverflow)?;
            events.push(SnapshotEvent {
                event_index: start_index
                    .checked_add(offset)
                    .ok_or(Error::ArithmeticOverflow)?,
                blinded_commitment: read_bytes(bytes, record_offset)?,
                signature: read_bytes(bytes, record_offset + 32)?,
                event_type: event_type_from_discriminant(bytes[record_offset + 96])?,
            });
        }
        let txid_version = std::str::from_utf8(&bytes[147..header_len])
            .map_err(Error::TxidVersionUtf8)?
            .to_string();
        let artifact = Self {
            format_version,
            scope: Scope {
                list_key: FixedBytes::from(read_bytes(bytes, 16)?),
                chain_type: bytes[12],
                chain_id: read_u64(bytes, 48)?,
                txid_version,
            },
            kind,
            range: EventRange::new(start_index, end_index)?,
            encoding,
            compression,
            start_root,
            end_root: FixedBytes::from(read_bytes(bytes, 115)?),
            events,
        };
        artifact.validate()?;
        Ok(artifact)
    }

    pub fn descriptor(&self, cid: impl Into<String>) -> Result<EventArtifactDescriptor, Error> {
        let bytes = self.to_bytes()?;
        Ok(EventArtifactDescriptor {
            artifact: ArtifactDescriptor::from_bytes(cid, &bytes),
            format_version: self.format_version,
            scope: self.scope.clone(),
            kind: self.kind,
            range: self.range,
            row_count: usize_to_u64(self.events.len())?,
            encoding: self.encoding,
            compression: self.compression,
            start_root: self.start_root,
            end_root: self.end_root,
        })
    }
}

const fn validate_checkpoint_range(range: EventRange, row_count: u64) -> Result<(), Error> {
    if !range.start_index.is_multiple_of(CHECKPOINT_EVENT_SPAN) || row_count > CHECKPOINT_EVENT_SPAN
    {
        return Err(Error::InvalidCheckpointChunk);
    }
    Ok(())
}

pub(super) fn require_contiguous(
    left: &EventArtifactDescriptor,
    right: &EventArtifactDescriptor,
) -> Result<(), Error> {
    let next = left
        .range
        .end_index
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow)?;
    if right.range.start_index != next || right.start_root != Some(left.end_root) {
        return Err(Error::RangeGapOrOverlap);
    }
    Ok(())
}

pub(super) fn expected_event_artifact_size(scope: &Scope, row_count: u64) -> Result<u64, Error> {
    let txid_len =
        u64::try_from(scope.txid_version.len()).map_err(|_| Error::TxidVersionTooLong)?;
    let header_len = u64::try_from(EVENT_HEADER_FIXED_BYTES)
        .map_err(|_| Error::ArithmeticOverflow)?
        .checked_add(txid_len)
        .ok_or(Error::ArithmeticOverflow)?;
    if txid_len > u64::from(u16::MAX) || header_len > u64::from(u16::MAX) {
        return Err(Error::TxidVersionTooLong);
    }
    let records_len = row_count
        .checked_mul(EVENT_RECORD_BYTES_U64)
        .ok_or(Error::ArithmeticOverflow)?;
    let byte_size = header_len
        .checked_add(records_len)
        .ok_or(Error::ArithmeticOverflow)?;
    require_event_artifact_size(byte_size)?;
    Ok(byte_size)
}

const fn event_kind_discriminant(kind: EventArtifactKind) -> u8 {
    match kind {
        EventArtifactKind::Checkpoint => 0,
        EventArtifactKind::CurrentTail => 1,
        EventArtifactKind::Bridge => 2,
    }
}

const fn event_kind_from_discriminant(value: u8) -> Result<EventArtifactKind, Error> {
    match value {
        0 => Ok(EventArtifactKind::Checkpoint),
        1 => Ok(EventArtifactKind::CurrentTail),
        2 => Ok(EventArtifactKind::Bridge),
        _ => Err(Error::UnsupportedEventKind),
    }
}

pub(super) const fn encoding_discriminant(encoding: ArtifactEncoding) -> u8 {
    match encoding {
        ArtifactEncoding::CanonicalJson => 0,
        ArtifactEncoding::PoiEventBinary => 1,
    }
}

const fn encoding_from_discriminant(value: u8) -> Result<ArtifactEncoding, Error> {
    match value {
        0 => Ok(ArtifactEncoding::CanonicalJson),
        1 => Ok(ArtifactEncoding::PoiEventBinary),
        _ => Err(Error::UnsupportedEncoding),
    }
}

const fn compression_discriminant(compression: Compression) -> u8 {
    match compression {
        Compression::Identity => 0,
    }
}

const fn compression_from_discriminant(value: u8) -> Result<Compression, Error> {
    match value {
        0 => Ok(Compression::Identity),
        _ => Err(Error::UnsupportedCompression),
    }
}

const fn event_type_discriminant(event_type: PoiEventType) -> u8 {
    match event_type {
        PoiEventType::Shield => 0,
        PoiEventType::Transact => 1,
        PoiEventType::Unshield => 2,
        PoiEventType::LegacyTransact => 3,
    }
}

const fn event_type_from_discriminant(value: u8) -> Result<PoiEventType, Error> {
    match value {
        0 => Ok(PoiEventType::Shield),
        1 => Ok(PoiEventType::Transact),
        2 => Ok(PoiEventType::Unshield),
        3 => Ok(PoiEventType::LegacyTransact),
        _ => Err(Error::UnsupportedEventType),
    }
}

const fn ensure_len(bytes: &[u8], needed: usize) -> Result<(), Error> {
    if bytes.len() < needed {
        return Err(Error::BufferTooShort {
            needed,
            actual: bytes.len(),
        });
    }
    Ok(())
}

fn read_bytes<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], Error> {
    let needed = offset.checked_add(N).ok_or(Error::ArithmeticOverflow)?;
    ensure_len(bytes, needed)?;
    bytes[offset..needed]
        .try_into()
        .map_err(|_| Error::BufferTooShort {
            needed,
            actual: bytes.len(),
        })
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    Ok(u16::from_le_bytes(read_bytes(bytes, offset)?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, Error> {
    Ok(u64::from_le_bytes(read_bytes(bytes, offset)?))
}
