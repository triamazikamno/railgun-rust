//! Resource limits: artifact and manifest byte limits, and the retrieval
//! budgets for fetching artifacts over CAR.

use super::{
    ARTIFACT_CAR_MAX_BLOCKS, BLOCKED_SHIELDS_ARTIFACT_MAX_BYTES, CATALOG_MAX_BYTES,
    CATALOG_MAX_DESCRIPTORS, CheckpointCatalogDescriptor, EVENT_ARTIFACT_MAX_BYTES, Error,
    EventArtifactDescriptor, MANIFEST_MAX_BYTES, checked_add,
};

const CAR_MIN_OVERHEAD_BYTES: u64 = 1024 * 1024;
const CAR_FIXED_OVERHEAD_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetrievalLimits {
    pub response_bytes: u64,
    pub car_block_count: u64,
    pub reconstructed_bytes: u64,
    pub decoded_bytes: u64,
    pub record_count: u64,
}

impl RetrievalLimits {
    pub fn for_event(descriptor: &EventArtifactDescriptor) -> Result<Self, Error> {
        descriptor.validate()?;
        Ok(Self {
            response_bytes: checked_car_response_limit(descriptor.artifact.byte_size)?,
            car_block_count: ARTIFACT_CAR_MAX_BLOCKS,
            reconstructed_bytes: descriptor.artifact.byte_size,
            decoded_bytes: descriptor.artifact.byte_size,
            record_count: descriptor.row_count,
        })
    }

    pub fn for_catalog(descriptor: &CheckpointCatalogDescriptor) -> Result<Self, Error> {
        descriptor.validate()?;
        Ok(Self {
            response_bytes: checked_car_response_limit(descriptor.artifact.byte_size)?,
            car_block_count: ARTIFACT_CAR_MAX_BLOCKS,
            reconstructed_bytes: descriptor.artifact.byte_size,
            decoded_bytes: descriptor.artifact.byte_size,
            record_count: descriptor.chunk_count,
        })
    }

    pub fn checked_usize(self) -> Result<RetrievalLimitsUsize, Error> {
        Ok(RetrievalLimitsUsize {
            response_bytes: usize::try_from(self.response_bytes)
                .map_err(|_| Error::ArithmeticOverflow)?,
            car_block_count: usize::try_from(self.car_block_count)
                .map_err(|_| Error::ArithmeticOverflow)?,
            reconstructed_bytes: usize::try_from(self.reconstructed_bytes)
                .map_err(|_| Error::ArithmeticOverflow)?,
            decoded_bytes: usize::try_from(self.decoded_bytes)
                .map_err(|_| Error::ArithmeticOverflow)?,
            record_count: usize::try_from(self.record_count)
                .map_err(|_| Error::ArithmeticOverflow)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetrievalLimitsUsize {
    pub response_bytes: usize,
    pub car_block_count: usize,
    pub reconstructed_bytes: usize,
    pub decoded_bytes: usize,
    pub record_count: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PlanLimits {
    pub descriptor_count: u64,
    pub encoded_bytes: u64,
    pub response_bytes: u64,
    pub reconstructed_bytes: u64,
    pub decoded_bytes: u64,
    pub record_count: u64,
    pub car_block_count: u64,
}

pub fn checked_event_plan_limits<'a>(
    descriptors: impl IntoIterator<Item = &'a EventArtifactDescriptor>,
) -> Result<PlanLimits, Error> {
    let mut total = PlanLimits::default();
    for descriptor in descriptors {
        let limits = RetrievalLimits::for_event(descriptor)?;
        total.descriptor_count = checked_add(total.descriptor_count, 1)?;
        total.encoded_bytes = checked_add(total.encoded_bytes, descriptor.artifact.byte_size)?;
        total.response_bytes = checked_add(total.response_bytes, limits.response_bytes)?;
        total.reconstructed_bytes =
            checked_add(total.reconstructed_bytes, limits.reconstructed_bytes)?;
        total.decoded_bytes = checked_add(total.decoded_bytes, limits.decoded_bytes)?;
        total.record_count = checked_add(total.record_count, limits.record_count)?;
        total.car_block_count = checked_add(total.car_block_count, limits.car_block_count)?;
    }
    Ok(total)
}

pub const fn validate_catalog_limits(
    encoded_bytes: u64,
    decoded_bytes: u64,
    descriptor_count: u64,
) -> Result<(), Error> {
    if descriptor_count > CATALOG_MAX_DESCRIPTORS {
        return Err(Error::CatalogDescriptorLimitExceeded { descriptor_count });
    }
    if encoded_bytes > CATALOG_MAX_BYTES || decoded_bytes > CATALOG_MAX_BYTES {
        return Err(Error::CatalogByteLimitExceeded {
            encoded_bytes,
            decoded_bytes,
        });
    }
    Ok(())
}

pub(super) const fn require_event_artifact_size(byte_size: u64) -> Result<(), Error> {
    if byte_size > EVENT_ARTIFACT_MAX_BYTES {
        return Err(Error::EventArtifactByteLimitExceeded { byte_size });
    }
    Ok(())
}

pub(super) const fn require_blocked_shields_artifact_size(byte_size: u64) -> Result<(), Error> {
    if byte_size > BLOCKED_SHIELDS_ARTIFACT_MAX_BYTES {
        return Err(Error::BlockedShieldsArtifactByteLimitExceeded { byte_size });
    }
    Ok(())
}

pub(super) const fn require_manifest_size(byte_size: u64) -> Result<(), Error> {
    if byte_size > MANIFEST_MAX_BYTES {
        return Err(Error::ManifestByteLimitExceeded { byte_size });
    }
    Ok(())
}

pub(super) fn checked_car_response_limit(reconstructed_bytes: u64) -> Result<u64, Error> {
    let overhead = (reconstructed_bytes / 8)
        .max(CAR_MIN_OVERHEAD_BYTES)
        .checked_add(CAR_FIXED_OVERHEAD_BYTES)
        .ok_or(Error::ArithmeticOverflow)?;
    reconstructed_bytes
        .checked_add(overhead)
        .ok_or(Error::ArithmeticOverflow)
}
