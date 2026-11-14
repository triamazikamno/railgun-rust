use std::fmt;

use alloy::primitives::FixedBytes;
use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};

use super::{DbError, PoiArtifactCacheRecord, decode};

pub const POI_CORPUS_JOURNAL_FORMAT_VERSION: u16 = 1;
pub const POI_CORPUS_JOURNAL_SOFT_DELTA_COUNT: u32 = 128;
pub const POI_CORPUS_JOURNAL_SOFT_PAYLOAD_BYTES: u64 = 8 * 1024 * 1024;
pub const POI_CORPUS_JOURNAL_MAX_DELTA_COUNT: u32 = 512;
pub const POI_CORPUS_JOURNAL_MAX_PAYLOAD_BYTES: u64 = 32 * 1024 * 1024;
pub const POI_CORPUS_JOURNAL_MAX_BLOCKED_PAYLOAD_BYTES: u64 = 4 * 1024 * 1024;
pub(crate) const POI_CORPUS_JOURNAL_MAX_HEAD_ROW_BYTES: usize = 1024 * 1024;
const POI_CORPUS_JOURNAL_ROW_OVERHEAD_BYTES: usize = 64 * 1024;
const POI_CORPUS_JOURNAL_MAX_DELTA_ROW_BYTES: usize =
    POI_CORPUS_JOURNAL_MAX_PAYLOAD_BYTES as usize + POI_CORPUS_JOURNAL_ROW_OVERHEAD_BYTES;
const POI_CORPUS_JOURNAL_MAX_BLOCKED_ROW_BYTES: usize =
    POI_CORPUS_JOURNAL_MAX_BLOCKED_PAYLOAD_BYTES as usize + POI_CORPUS_JOURNAL_ROW_OVERHEAD_BYTES;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PoiCorpusJournalHeadRecord {
    pub format_version: u16,
    pub revision: u64,
    pub base_revision: u64,
    pub base_payload_hash: FixedBytes<32>,
    pub event_cursor: u64,
    pub leaf_cursor: u64,
    pub blocked_revision: Option<u64>,
    pub blocked_payload_hash: Option<FixedBytes<32>>,
    pub delta_count: u32,
    pub delta_payload_bytes: u64,
    /// Current corpus metadata. `cache_payload` is always empty in a journal head.
    pub corpus: PoiArtifactCacheRecord,
}

impl PoiCorpusJournalHeadRecord {
    #[must_use]
    pub fn key(&self) -> String {
        Self::key_for(
            self.corpus.chain_type,
            self.corpus.chain_id,
            &self.corpus.txid_version,
            &self.corpus.list_key,
        )
    }

    #[must_use]
    pub fn key_for(
        chain_type: u8,
        chain_id: u64,
        txid_version: &str,
        list_key: &FixedBytes<32>,
    ) -> String {
        format!(
            "{}|head",
            PoiArtifactCacheRecord::key_for(chain_type, chain_id, txid_version, list_key)
        )
    }

    #[must_use]
    pub fn identity_prefix_for(
        chain_type: u8,
        chain_id: u64,
        txid_version: &str,
        list_key: &FixedBytes<32>,
    ) -> String {
        format!(
            "{}|",
            PoiArtifactCacheRecord::key_for(chain_type, chain_id, txid_version, list_key)
        )
    }

    #[must_use]
    pub fn delta_prefix_for(
        chain_type: u8,
        chain_id: u64,
        txid_version: &str,
        list_key: &FixedBytes<32>,
    ) -> String {
        format!(
            "{}delta|",
            Self::identity_prefix_for(chain_type, chain_id, txid_version, list_key)
        )
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PoiCorpusJournalDeltaRecord {
    pub format_version: u16,
    pub chain_type: u8,
    pub chain_id: u64,
    pub txid_version: String,
    pub list_key: FixedBytes<32>,
    pub cache_generation: u64,
    pub revision: u64,
    pub previous_revision: u64,
    pub base_revision: u64,
    pub event_start_cursor: u64,
    pub event_end_cursor: u64,
    pub leaf_start_cursor: u64,
    pub leaf_end_cursor: u64,
    pub start_tip_root: FixedBytes<32>,
    pub end_tip_root: FixedBytes<32>,
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
    pub updated_at: u64,
}

impl fmt::Debug for PoiCorpusJournalDeltaRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PoiCorpusJournalDeltaRecord")
            .field("key", &self.key())
            .field("cache_generation", &self.cache_generation)
            .field("revision", &self.revision)
            .field("previous_revision", &self.previous_revision)
            .field("base_revision", &self.base_revision)
            .field("event_start_cursor", &self.event_start_cursor)
            .field("event_end_cursor", &self.event_end_cursor)
            .field("leaf_start_cursor", &self.leaf_start_cursor)
            .field("leaf_end_cursor", &self.leaf_end_cursor)
            .field("payload_bytes", &self.payload.len())
            .field("updated_at", &self.updated_at)
            .finish_non_exhaustive()
    }
}

impl PoiCorpusJournalDeltaRecord {
    #[must_use]
    pub fn key(&self) -> String {
        Self::key_for(
            self.chain_type,
            self.chain_id,
            &self.txid_version,
            &self.list_key,
            self.revision,
        )
    }

    #[must_use]
    pub fn key_for(
        chain_type: u8,
        chain_id: u64,
        txid_version: &str,
        list_key: &FixedBytes<32>,
        revision: u64,
    ) -> String {
        format!(
            "{}{revision:020}",
            PoiCorpusJournalHeadRecord::delta_prefix_for(
                chain_type,
                chain_id,
                txid_version,
                list_key
            )
        )
    }
}

#[derive(Deserialize)]
struct PoiCorpusJournalDeltaRecordWire<'a> {
    format_version: u16,
    chain_type: u8,
    chain_id: u64,
    #[serde(borrow)]
    txid_version: &'a str,
    list_key: FixedBytes<32>,
    cache_generation: u64,
    revision: u64,
    previous_revision: u64,
    base_revision: u64,
    event_start_cursor: u64,
    event_end_cursor: u64,
    leaf_start_cursor: u64,
    leaf_end_cursor: u64,
    start_tip_root: FixedBytes<32>,
    end_tip_root: FixedBytes<32>,
    #[serde(borrow, with = "serde_bytes")]
    payload: &'a [u8],
    updated_at: u64,
}

impl PoiCorpusJournalDeltaRecordWire<'_> {
    fn into_owned(self) -> PoiCorpusJournalDeltaRecord {
        PoiCorpusJournalDeltaRecord {
            format_version: self.format_version,
            chain_type: self.chain_type,
            chain_id: self.chain_id,
            txid_version: self.txid_version.to_owned(),
            list_key: self.list_key,
            cache_generation: self.cache_generation,
            revision: self.revision,
            previous_revision: self.previous_revision,
            base_revision: self.base_revision,
            event_start_cursor: self.event_start_cursor,
            event_end_cursor: self.event_end_cursor,
            leaf_start_cursor: self.leaf_start_cursor,
            leaf_end_cursor: self.leaf_end_cursor,
            start_tip_root: self.start_tip_root,
            end_tip_root: self.end_tip_root,
            payload: self.payload.to_vec(),
            updated_at: self.updated_at,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PoiCorpusBlockedSnapshotRecord {
    pub format_version: u16,
    pub chain_type: u8,
    pub chain_id: u64,
    pub txid_version: String,
    pub list_key: FixedBytes<32>,
    pub cache_generation: u64,
    pub revision: u64,
    pub payload_hash: FixedBytes<32>,
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
    pub updated_at: u64,
}

impl fmt::Debug for PoiCorpusBlockedSnapshotRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PoiCorpusBlockedSnapshotRecord")
            .field("key", &self.key())
            .field("cache_generation", &self.cache_generation)
            .field("revision", &self.revision)
            .field("payload_bytes", &self.payload.len())
            .field("updated_at", &self.updated_at)
            .finish_non_exhaustive()
    }
}

impl PoiCorpusBlockedSnapshotRecord {
    #[must_use]
    pub fn key(&self) -> String {
        Self::key_for(
            self.chain_type,
            self.chain_id,
            &self.txid_version,
            &self.list_key,
        )
    }

    #[must_use]
    pub fn key_for(
        chain_type: u8,
        chain_id: u64,
        txid_version: &str,
        list_key: &FixedBytes<32>,
    ) -> String {
        format!(
            "{}blocked",
            PoiCorpusJournalHeadRecord::identity_prefix_for(
                chain_type,
                chain_id,
                txid_version,
                list_key
            )
        )
    }
}

#[derive(Deserialize)]
struct PoiCorpusBlockedSnapshotRecordWire<'a> {
    format_version: u16,
    chain_type: u8,
    chain_id: u64,
    #[serde(borrow)]
    txid_version: &'a str,
    list_key: FixedBytes<32>,
    cache_generation: u64,
    revision: u64,
    payload_hash: FixedBytes<32>,
    #[serde(borrow, with = "serde_bytes")]
    payload: &'a [u8],
    updated_at: u64,
}

impl PoiCorpusBlockedSnapshotRecordWire<'_> {
    fn into_owned(self) -> PoiCorpusBlockedSnapshotRecord {
        PoiCorpusBlockedSnapshotRecord {
            format_version: self.format_version,
            chain_type: self.chain_type,
            chain_id: self.chain_id,
            txid_version: self.txid_version.to_owned(),
            list_key: self.list_key,
            cache_generation: self.cache_generation,
            revision: self.revision,
            payload_hash: self.payload_hash,
            payload: self.payload.to_vec(),
            updated_at: self.updated_at,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoiCorpusJournalBundle {
    pub base: PoiArtifactCacheRecord,
    pub head: Option<PoiCorpusJournalHeadRecord>,
    pub deltas: Vec<PoiCorpusJournalDeltaRecord>,
    pub blocked: Option<PoiCorpusBlockedSnapshotRecord>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PoiCorpusJournalCorruptionToken {
    pub(crate) fingerprint: FixedBytes<32>,
    pub(crate) replacement_revision: u64,
    pub(crate) retired_delta_count: u32,
    pub(crate) retired_delta_payload_bytes: u64,
}

impl fmt::Debug for PoiCorpusJournalCorruptionToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PoiCorpusJournalCorruptionToken")
            .field("replacement_revision", &self.replacement_revision)
            .field("retired_delta_count", &self.retired_delta_count)
            .field(
                "retired_delta_payload_bytes",
                &self.retired_delta_payload_bytes,
            )
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum PoiCorpusJournalInspection {
    Missing,
    Valid {
        bundle: Box<PoiCorpusJournalBundle>,
        replacement_token: PoiCorpusJournalCorruptionToken,
    },
    Corrupt {
        key: String,
        replacement_token: PoiCorpusJournalCorruptionToken,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedPoiCorpusJournalState {
    NoValidBase,
    ImplicitBase {
        base_payload_hash: FixedBytes<32>,
        event_cursor: u64,
        leaf_cursor: u64,
        current_tip_root: FixedBytes<32>,
    },
    Head {
        revision: u64,
        base_revision: u64,
        base_payload_hash: FixedBytes<32>,
        event_cursor: u64,
        leaf_cursor: u64,
        current_tip_root: FixedBytes<32>,
    },
    Corrupt {
        replacement_token: PoiCorpusJournalCorruptionToken,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoiCorpusJournalCommitCondition {
    pub expected_generation: u64,
    pub expected_publisher: Option<(FixedBytes<32>, u64)>,
    pub expected_manifest_hash: Option<FixedBytes<32>>,
    pub expected_state: ExpectedPoiCorpusJournalState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoiCorpusJournalCommit {
    pub head: PoiCorpusJournalHeadRecord,
    pub delta: Option<PoiCorpusJournalDeltaRecord>,
    pub blocked: Option<PoiCorpusBlockedSnapshotRecord>,
    pub base: Option<Box<PoiArtifactCacheRecord>>,
    pub retired_delta_count: u32,
    pub retired_delta_payload_bytes: u64,
    pub compaction_recommended: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoiCorpusJournalCommitOutcome {
    Applied(Box<PoiCorpusJournalCommit>),
    GenerationConflict { actual: u64 },
    PublisherSequenceConflict { actual: Option<u64> },
    PublisherManifestConflict { actual: Option<FixedBytes<32>> },
    CorpusConflict,
    CompactionRequired,
}

pub(crate) fn decode_poi_corpus_journal_delta_bounded(
    data: &[u8],
    remaining_payload_bytes: u64,
) -> Result<Option<PoiCorpusJournalDeltaRecord>, DbError> {
    if data.len() > POI_CORPUS_JOURNAL_MAX_DELTA_ROW_BYTES {
        return Ok(None);
    }
    let _: IgnoredAny = decode(data)?;
    let wire: PoiCorpusJournalDeltaRecordWire<'_> = rmp_serde::from_slice(data)?;
    let payload_bytes = u64::try_from(wire.payload.len()).unwrap_or(u64::MAX);
    if payload_bytes > remaining_payload_bytes
        || payload_bytes > POI_CORPUS_JOURNAL_MAX_PAYLOAD_BYTES
    {
        return Ok(None);
    }
    Ok(Some(wire.into_owned()))
}

pub(crate) fn decode_poi_corpus_blocked_snapshot_bounded(
    data: &[u8],
) -> Result<Option<PoiCorpusBlockedSnapshotRecord>, DbError> {
    if data.len() > POI_CORPUS_JOURNAL_MAX_BLOCKED_ROW_BYTES {
        return Ok(None);
    }
    let _: IgnoredAny = decode(data)?;
    let wire: PoiCorpusBlockedSnapshotRecordWire<'_> = rmp_serde::from_slice(data)?;
    if u64::try_from(wire.payload.len()).unwrap_or(u64::MAX)
        > POI_CORPUS_JOURNAL_MAX_BLOCKED_PAYLOAD_BYTES
    {
        return Ok(None);
    }
    Ok(Some(wire.into_owned()))
}
