use alloy::primitives::FixedBytes;
use serde::{Deserialize, Serialize};

mod blocked;
mod catalog;
mod error;
mod event;
mod limits;
mod manifest;
#[cfg(test)]
mod tests;

pub use blocked::{BlockedShieldsArtifact, BlockedShieldsDescriptor};
pub use catalog::{CheckpointCatalog, CheckpointCatalogDescriptor};
pub use error::Error;
pub use event::{EventArtifact, EventArtifactDescriptor};
pub use limits::{
    PlanLimits, RetrievalLimits, RetrievalLimitsUsize, checked_event_plan_limits,
    validate_catalog_limits,
};
pub use manifest::{Manifest, ManifestEntry};

pub const FORMAT_VERSION: u16 = 4;
pub const MANIFEST_SIGNATURE_DOMAIN: &[u8] = b"railgun-poi-manifest-v4\0";
pub const MANIFEST_MAX_BYTES: u64 = 2 * 1024 * 1024;
pub const CHECKPOINT_EVENT_SPAN: u64 = 32_768;
pub const EVENT_ARTIFACT_MAX_BYTES: u64 = 4 * 1024 * 1024;
pub const BLOCKED_SHIELDS_ARTIFACT_MAX_BYTES: u64 = 4 * 1024 * 1024;
pub const CATALOG_MAX_DESCRIPTORS: u64 = 4_096;
pub const CATALOG_MAX_BYTES: u64 = 2 * 1024 * 1024;
pub const MAX_RETAINED_BRIDGES: usize = 7;
pub const ARTIFACT_CAR_MAX_BLOCKS: u64 = 16_384;
pub const IPNS_KDF_SALT: &[u8] = b"railgun-indexer/ipns-key-derivation/v1";
pub const IPNS_KDF_INFO: &[u8] = b"poi-artifact/chunked-manifest/v4";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub list_key: FixedBytes<32>,
    pub chain_type: u8,
    pub chain_id: u64,
    pub txid_version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationId {
    pub publisher_pubkey: FixedBytes<32>,
    pub sequence: u64,
    pub manifest_body_hash: FixedBytes<32>,
}

impl Scope {
    #[must_use]
    pub fn new(
        list_key: FixedBytes<32>,
        chain_type: u8,
        chain_id: u64,
        txid_version: impl Into<String>,
    ) -> Self {
        Self {
            list_key,
            chain_type,
            chain_id,
            txid_version: txid_version.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventRange {
    pub start_index: u64,
    pub end_index: u64,
}

impl EventRange {
    pub fn new(start_index: u64, end_index: u64) -> Result<Self, Error> {
        let range = Self {
            start_index,
            end_index,
        };
        range.row_count()?;
        Ok(range)
    }

    pub fn row_count(self) -> Result<u64, Error> {
        self.end_index
            .checked_sub(self.start_index)
            .and_then(|difference| difference.checked_add(1))
            .ok_or(Error::InvalidRange {
                start_index: self.start_index,
                end_index: self.end_index,
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactEncoding {
    CanonicalJson,
    PoiEventBinary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Compression {
    Identity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventArtifactKind {
    Checkpoint,
    CurrentTail,
    Bridge,
}

const fn require_format_version(version: u16) -> Result<(), Error> {
    if version != FORMAT_VERSION {
        return Err(Error::WrongFormat { version });
    }
    Ok(())
}

fn require_scope(expected: &Scope, actual: &Scope) -> Result<(), Error> {
    if expected != actual {
        return Err(Error::ScopeMismatch);
    }
    Ok(())
}

const fn require_start_root(
    start_index: u64,
    start_root: Option<FixedBytes<32>>,
) -> Result<(), Error> {
    if (start_index == 0) != start_root.is_none() {
        return Err(Error::InvalidStartRoot);
    }
    Ok(())
}

fn checked_add(left: u64, right: u64) -> Result<u64, Error> {
    left.checked_add(right).ok_or(Error::ArithmeticOverflow)
}

fn usize_to_u64(value: usize) -> Result<u64, Error> {
    u64::try_from(value).map_err(|_| Error::ArithmeticOverflow)
}

fn checked_sum(values: impl IntoIterator<Item = u64>) -> Result<u64, Error> {
    values.into_iter().try_fold(0_u64, checked_add)
}
