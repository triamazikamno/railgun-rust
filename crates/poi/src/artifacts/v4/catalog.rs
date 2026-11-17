//! The checkpoint catalog, which lists the full checkpoint chunks, and its
//! descriptor.

use alloy::primitives::FixedBytes;
use serde::{Deserialize, Serialize};

use crate::artifacts::manifest::ArtifactDescriptor;

use super::event::require_contiguous;
use super::{
    ArtifactEncoding, CHECKPOINT_EVENT_SPAN, Compression, Error, EventArtifactDescriptor,
    EventArtifactKind, EventRange, FORMAT_VERSION, Scope, checked_sum, require_format_version,
    require_scope, usize_to_u64, validate_catalog_limits,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointCatalogDescriptor {
    pub artifact: ArtifactDescriptor,
    pub format_version: u16,
    pub scope: Scope,
    pub range: Option<EventRange>,
    pub row_count: u64,
    pub chunk_count: u64,
    pub encoding: ArtifactEncoding,
    pub compression: Compression,
    pub checkpoint_root: Option<FixedBytes<32>>,
}

impl CheckpointCatalogDescriptor {
    pub fn validate(&self) -> Result<(), Error> {
        require_format_version(self.format_version)?;
        if self.encoding != ArtifactEncoding::CanonicalJson {
            return Err(Error::UnsupportedEncoding);
        }
        if self.compression != Compression::Identity {
            return Err(Error::UnsupportedCompression);
        }
        validate_catalog_limits(
            self.artifact.byte_size,
            self.artifact.byte_size,
            self.chunk_count,
        )?;
        validate_aggregate(self.range, self.row_count, self.checkpoint_root)?;
        let expected = expected_checkpoint_chunk_count(self.row_count)?;
        if self.chunk_count != expected {
            return Err(Error::CheckpointChunkCountMismatch {
                expected,
                actual: self.chunk_count,
            });
        }
        Ok(())
    }

    pub fn verify_bytes(&self, bytes: &[u8]) -> Result<CheckpointCatalog, Error> {
        self.validate()?;
        self.artifact.verify_bytes(bytes)?;
        let catalog = CheckpointCatalog::read(bytes)?;
        let decoded_chunk_count = usize_to_u64(catalog.chunks.len())?;
        if catalog.format_version != self.format_version
            || catalog.scope != self.scope
            || catalog.range != self.range
            || catalog.row_count != self.row_count
            || decoded_chunk_count != self.chunk_count
            || catalog.checkpoint_root != self.checkpoint_root
        {
            return Err(Error::DescriptorBodyMismatch);
        }
        Ok(catalog)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointCatalog {
    pub format_version: u16,
    pub scope: Scope,
    pub range: Option<EventRange>,
    pub row_count: u64,
    pub checkpoint_root: Option<FixedBytes<32>>,
    pub chunks: Vec<EventArtifactDescriptor>,
}

impl CheckpointCatalog {
    pub fn new(scope: Scope, chunks: Vec<EventArtifactDescriptor>) -> Result<Self, Error> {
        let row_count = checked_sum(chunks.iter().map(|chunk| chunk.row_count))?;
        let range = chunks.last().map(|last| EventRange {
            start_index: 0,
            end_index: last.range.end_index,
        });
        let checkpoint_root = chunks.last().map(|chunk| chunk.end_root);
        let catalog = Self {
            format_version: FORMAT_VERSION,
            scope,
            range,
            row_count,
            checkpoint_root,
            chunks,
        };
        catalog.validate()?;
        Ok(catalog)
    }

    pub fn validate(&self) -> Result<(), Error> {
        require_format_version(self.format_version)?;
        validate_catalog_limits(0, 0, usize_to_u64(self.chunks.len())?)?;
        if self.chunks.is_empty() {
            let has_aggregate =
                self.row_count != 0 || self.range.is_some() || self.checkpoint_root.is_some();
            if has_aggregate {
                return Err(Error::InvalidCheckpointAggregate);
            }
            return Ok(());
        }
        if self.row_count == 0 {
            return Err(Error::InvalidCheckpointAggregate);
        }

        let (total_rows, last) = self.validate_chunks()?;
        validate_aggregate(self.range, self.row_count, self.checkpoint_root)?;
        let aggregate_matches = total_rows == self.row_count
            && self.range
                == Some(EventRange {
                    start_index: 0,
                    end_index: last.range.end_index,
                })
            && self.checkpoint_root == Some(last.end_root);
        if !aggregate_matches {
            return Err(Error::InvalidCheckpointAggregate);
        }
        Ok(())
    }

    /// Checks every chunk and the chain between them. Returns the summed row
    /// count and the last chunk.
    fn validate_chunks(&self) -> Result<(u64, &EventArtifactDescriptor), Error> {
        let mut total_rows = 0_u64;
        let mut previous: Option<&EventArtifactDescriptor> = None;
        for (index, chunk) in self.chunks.iter().enumerate() {
            chunk.validate()?;
            require_scope(&self.scope, &chunk.scope)?;
            if chunk.kind != EventArtifactKind::Checkpoint {
                return Err(Error::InvalidCheckpointChunk);
            }
            if index == 0 && chunk.range.start_index != 0 {
                return Err(Error::RangeGapOrOverlap);
            }
            if let Some(prior) = previous {
                require_contiguous(prior, chunk)?;
            }
            if index + 1 != self.chunks.len() && chunk.row_count != CHECKPOINT_EVENT_SPAN {
                return Err(Error::PartialCheckpointNotFinal);
            }
            total_rows = total_rows
                .checked_add(chunk.row_count)
                .ok_or(Error::ArithmeticOverflow)?;
            previous = Some(chunk);
        }
        let last = previous.ok_or(Error::InvalidCheckpointAggregate)?;
        Ok((total_rows, last))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(Error::Json)?;
        let byte_size = usize_to_u64(bytes.len())?;
        validate_catalog_limits(byte_size, byte_size, usize_to_u64(self.chunks.len())?)?;
        Ok(bytes)
    }

    pub fn read(bytes: &[u8]) -> Result<Self, Error> {
        let byte_size = usize_to_u64(bytes.len())?;
        validate_catalog_limits(byte_size, byte_size, 0)?;
        let catalog: Self = serde_json::from_slice(bytes).map_err(Error::Json)?;
        catalog.validate()?;
        if catalog.to_bytes()? != bytes {
            return Err(Error::NonCanonicalBytes);
        }
        Ok(catalog)
    }

    pub fn descriptor(&self, cid: impl Into<String>) -> Result<CheckpointCatalogDescriptor, Error> {
        let bytes = self.to_bytes()?;
        Ok(CheckpointCatalogDescriptor {
            artifact: ArtifactDescriptor::from_bytes(cid, &bytes),
            format_version: self.format_version,
            scope: self.scope.clone(),
            range: self.range,
            row_count: self.row_count,
            chunk_count: usize_to_u64(self.chunks.len())?,
            encoding: ArtifactEncoding::CanonicalJson,
            compression: Compression::Identity,
            checkpoint_root: self.checkpoint_root,
        })
    }
}

fn validate_aggregate(
    range: Option<EventRange>,
    row_count: u64,
    root: Option<FixedBytes<32>>,
) -> Result<(), Error> {
    if row_count == 0 {
        if range.is_some() || root.is_some() {
            return Err(Error::InvalidCheckpointAggregate);
        }
        return Ok(());
    }
    let aggregate = range.ok_or(Error::InvalidCheckpointAggregate)?;
    if aggregate.start_index != 0 {
        return Err(Error::InvalidCheckpointAggregate);
    }
    if aggregate.row_count()? != row_count || root.is_none() {
        return Err(Error::InvalidCheckpointAggregate);
    }
    Ok(())
}

pub(super) fn expected_checkpoint_chunk_count(row_count: u64) -> Result<u64, Error> {
    if row_count == 0 {
        return Ok(0);
    }
    row_count
        .checked_sub(1)
        .and_then(|last_index| last_index.checked_div(CHECKPOINT_EVENT_SPAN))
        .and_then(|last_chunk_index| last_chunk_index.checked_add(1))
        .ok_or(Error::ArithmeticOverflow)
}
