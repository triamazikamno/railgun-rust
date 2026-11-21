//! The blocked-shields artifact and its descriptor.

use std::io::{self, Write};

use serde::{Deserialize, Serialize};

use crate::artifacts::blocked::BlockedShieldArtifactRecord;
use crate::artifacts::manifest::ArtifactDescriptor;
use crate::artifacts::verify::verify_blocked_shield;
use crate::poi::SignedBlockedShield;

use super::limits::require_blocked_shields_artifact_size;
use super::{
    ArtifactEncoding, Compression, Error, FORMAT_VERSION, Scope, require_format_version,
    usize_to_u64,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockedShieldsDescriptor {
    pub artifact: ArtifactDescriptor,
    pub format_version: u16,
    pub scope: Scope,
    pub row_count: u64,
    pub encoding: ArtifactEncoding,
    pub compression: Compression,
}

impl BlockedShieldsDescriptor {
    pub fn validate(&self) -> Result<(), Error> {
        require_format_version(self.format_version)?;
        if self.encoding != ArtifactEncoding::CanonicalJson {
            return Err(Error::UnsupportedEncoding);
        }
        if self.compression != Compression::Identity {
            return Err(Error::UnsupportedCompression);
        }
        require_blocked_shields_artifact_size(self.artifact.byte_size)?;
        Ok(())
    }

    pub fn verify_bytes(&self, bytes: &[u8]) -> Result<BlockedShieldsArtifact, Error> {
        self.validate()?;
        self.artifact.verify_bytes(bytes)?;
        let artifact = BlockedShieldsArtifact::read(bytes)?;
        let row_count = usize_to_u64(artifact.blocked_shields.len())?;
        let body_mismatch = artifact.format_version != self.format_version
            || artifact.scope != self.scope
            || row_count != self.row_count;
        if body_mismatch {
            return Err(Error::DescriptorBodyMismatch);
        }
        artifact.verify_signatures()?;
        Ok(artifact)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockedShieldsArtifact {
    pub format_version: u16,
    pub scope: Scope,
    pub blocked_shields: Vec<BlockedShieldArtifactRecord>,
}

impl BlockedShieldsArtifact {
    #[must_use]
    pub fn from_signed_records(scope: Scope, records: &[SignedBlockedShield]) -> Self {
        let mut blocked_shields = records
            .iter()
            .map(BlockedShieldArtifactRecord::from)
            .collect::<Vec<_>>();
        blocked_shields.sort_by(|left, right| {
            left.blinded_commitment
                .cmp(&right.blinded_commitment)
                .then_with(|| left.commitment_hash.cmp(&right.commitment_hash))
        });
        Self {
            format_version: FORMAT_VERSION,
            scope,
            blocked_shields,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate_order()?;
        let byte_size = canonical_json_size(self)?;
        require_blocked_shields_artifact_size(byte_size)?;
        serde_json::to_vec(self).map_err(Error::Json)
    }

    pub fn read(bytes: &[u8]) -> Result<Self, Error> {
        require_blocked_shields_artifact_size(usize_to_u64(bytes.len())?)?;
        let artifact: Self = serde_json::from_slice(bytes).map_err(Error::Json)?;
        artifact.validate_order()?;
        if artifact.to_bytes()? != bytes {
            return Err(Error::NonCanonicalBytes);
        }
        Ok(artifact)
    }

    pub fn into_signed_records(self) -> Vec<SignedBlockedShield> {
        self.blocked_shields
            .into_iter()
            .map(BlockedShieldArtifactRecord::into_signed_blocked_shield)
            .collect()
    }

    fn verify_signatures(&self) -> Result<(), Error> {
        for record in &self.blocked_shields {
            verify_blocked_shield(
                &SignedBlockedShield {
                    commitment_hash: record.commitment_hash.clone(),
                    blinded_commitment: record.blinded_commitment.clone(),
                    block_reason: record.block_reason.clone(),
                    signature: record.signature.clone(),
                },
                &self.scope.list_key.0,
            )?;
        }
        Ok(())
    }

    fn validate_order(&self) -> Result<(), Error> {
        require_format_version(self.format_version)?;
        for pair in self.blocked_shields.windows(2) {
            let left = (&pair[0].blinded_commitment, &pair[0].commitment_hash);
            let right = (&pair[1].blinded_commitment, &pair[1].commitment_hash);
            if left >= right {
                return Err(Error::NonCanonicalBytes);
            }
        }
        Ok(())
    }
}

fn canonical_json_size(value: &impl Serialize) -> Result<u64, Error> {
    let mut writer = JsonSizeWriter::default();
    serde_json::to_writer(&mut writer, value).map_err(Error::Json)?;
    Ok(writer.byte_size)
}

#[derive(Default)]
struct JsonSizeWriter {
    byte_size: u64,
}

impl Write for JsonSizeWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let byte_size = u64::try_from(bytes.len())
            .map_err(|_| io::Error::other("canonical JSON size overflow"))?;
        self.byte_size = self
            .byte_size
            .checked_add(byte_size)
            .ok_or_else(|| io::Error::other("canonical JSON size overflow"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
