use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, ErrorKind};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use alloy::hex;
use alloy::primitives::{FixedBytes, U256};
use broadcaster_core::tree::{TREE_LEAF_COUNT, normalize_tree_position};
use merkletree::tree::{DenseMerkleTree, MerkleForest, MerkleProof, MerkleTreeUpdate};
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use tracing::debug;

use crate::artifacts::SnapshotEvent;
use crate::artifacts::verify::{VerifyError, verify_blocked_shield, verify_poi_event};
use crate::error::PoiRpcError;
use crate::poi::{
    BlindedCommitmentData, BlockedShield, PoiMerkleProof, PoiRpcClient, PoiStatus,
    PoiSyncedListEvent,
};

pub const POI_CACHE_SNAPSHOT_VERSION: u32 = 1;
pub const POI_EVENTS_PAGE_SIZE: u64 = 500;
pub const POI_MERKLETREE_LEAVES_PAGE_SIZE: u64 = 100;
const POI_BLOCKED_SHIELDS_PAGE_SIZE: u64 = 500;
const POI_BLOCKED_SHIELDS_LIMIT: usize = 100_000;
const DENSE_POI_PROOF_MIN_COMMITMENTS_PER_TREE: usize = 1;

#[derive(Clone, Copy, PartialEq, Eq)]
enum PoiCacheSyncScope {
    Full,
    Events,
    BlockedShields,
}

impl PoiCacheSyncScope {
    const fn sync_events(self) -> bool {
        matches!(self, Self::Full | Self::Events)
    }

    const fn sync_blocked_shields(self) -> bool {
        matches!(self, Self::Full | Self::BlockedShields)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoiCacheIdentity {
    pub chain_type: u8,
    pub chain_id: u64,
    pub txid_version: String,
    pub list_key: FixedBytes<32>,
}

impl PoiCacheIdentity {
    #[must_use]
    pub fn new(
        chain_type: u8,
        chain_id: u64,
        txid_version: impl Into<String>,
        list_key: FixedBytes<32>,
    ) -> Self {
        Self {
            chain_type,
            chain_id,
            txid_version: txid_version.into(),
            list_key,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoiCachePosition {
    pub global_index: u64,
    pub tree_number: u32,
    pub tree_position: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum PoiCacheRootValidation {
    #[default]
    Pending,
    Validated {
        roots: BTreeMap<u32, FixedBytes<32>>,
    },
    Invalid {
        roots: BTreeMap<u32, FixedBytes<32>>,
    },
}

impl PoiCacheRootValidation {
    fn accepts(&self, roots: &BTreeMap<u32, FixedBytes<32>>) -> bool {
        matches!(self, Self::Validated { roots: validated } if validated == roots)
    }

    fn rejects(&self, roots: &BTreeMap<u32, FixedBytes<32>>) -> bool {
        matches!(self, Self::Invalid { roots: invalid } if invalid == roots)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoiCacheSyncProgress {
    pub next_event_index: u64,
    pub next_leaf_index: u64,
    pub blocked_shields_synced: bool,
    pub root_validation: PoiCacheRootValidation,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PoiCacheSyncOutcome {
    pub events: usize,
    pub leaves: usize,
    pub blocked_shields: usize,
    pub event_page_budget_exhausted: bool,
    pub changed: bool,
}

pub const POI_CACHE_JOURNAL_DELTA_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct PoiCacheJournalEvent {
    pub event_index: u64,
    pub blinded_commitment: FixedBytes<32>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PoiCacheJournalDelta {
    pub version: u16,
    pub identity: PoiCacheIdentity,
    pub event_start_cursor: u64,
    pub event_end_cursor: u64,
    pub leaf_start_cursor: u64,
    pub leaf_end_cursor: u64,
    pub events: Vec<PoiCacheJournalEvent>,
    pub leaves: Vec<FixedBytes<32>>,
}

impl std::fmt::Debug for PoiCacheJournalDelta {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PoiCacheJournalDelta")
            .field("version", &self.version)
            .field("identity", &self.identity)
            .field("event_start_cursor", &self.event_start_cursor)
            .field("event_end_cursor", &self.event_end_cursor)
            .field("leaf_start_cursor", &self.leaf_start_cursor)
            .field("leaf_end_cursor", &self.leaf_end_cursor)
            .field("event_count", &self.events.len())
            .field("leaf_count", &self.leaves.len())
            .finish()
    }
}

impl PoiCacheJournalDelta {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.events.is_empty() && self.leaves.is_empty()
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, PoiCacheError> {
        Ok(rmp_serde::to_vec_named(self)?)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PoiCacheError> {
        let mut deserializer = rmp_serde::Deserializer::new(Cursor::new(bytes));
        let delta = Self::deserialize(&mut deserializer)?;
        require_exact_messagepack_consumption(deserializer.get_ref().position(), bytes.len())?;
        Self::validate_version(delta)
    }

    pub fn from_bytes_bounded(
        bytes: &[u8],
        max_events: usize,
        max_leaves: usize,
    ) -> Result<Self, PoiCacheError> {
        let mut deserializer = rmp_serde::Deserializer::new(Cursor::new(bytes));
        let delta = PoiCacheJournalDeltaSeed {
            max_events,
            max_leaves,
        }
        .deserialize(&mut deserializer)?;
        require_exact_messagepack_consumption(deserializer.get_ref().position(), bytes.len())?;
        Self::validate_version(delta)
    }

    fn validate_version(delta: Self) -> Result<Self, PoiCacheError> {
        if delta.version != POI_CACHE_JOURNAL_DELTA_VERSION {
            return Err(PoiCacheError::UnsupportedJournalDeltaVersion {
                version: delta.version,
            });
        }
        Ok(delta)
    }
}

struct BoundedVecSeed<T> {
    limit: usize,
    field: &'static str,
    marker: PhantomData<T>,
}

impl<T> BoundedVecSeed<T> {
    const fn new(limit: usize, field: &'static str) -> Self {
        Self {
            limit,
            field,
            marker: PhantomData,
        }
    }
}

impl<'de, T> DeserializeSeed<'de> for BoundedVecSeed<T>
where
    T: Deserialize<'de>,
{
    type Value = Vec<T>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(BoundedVecVisitor {
            limit: self.limit,
            field: self.field,
            marker: PhantomData,
        })
    }
}

struct BoundedVecVisitor<T> {
    limit: usize,
    field: &'static str,
    marker: PhantomData<T>,
}

impl<'de, T> Visitor<'de> for BoundedVecVisitor<T>
where
    T: Deserialize<'de>,
{
    type Value = Vec<T>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "at most {} {} entries", self.limit, self.field)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if sequence
            .size_hint()
            .is_some_and(|length| length > self.limit)
        {
            return Err(de::Error::custom(format_args!(
                "{} entry count exceeds limit {}",
                self.field, self.limit
            )));
        }
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(self.limit));
        while values.len() < self.limit {
            let Some(value) = sequence.next_element()? else {
                return Ok(values);
            };
            values.push(value);
        }
        if sequence.next_element::<IgnoredAny>()?.is_some() {
            return Err(de::Error::custom(format_args!(
                "{} entry count exceeds limit {}",
                self.field, self.limit
            )));
        }
        Ok(values)
    }
}

struct PoiCacheJournalDeltaSeed {
    max_events: usize,
    max_leaves: usize,
}

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "snake_case")]
enum PoiCacheJournalDeltaField {
    Version,
    Identity,
    EventStartCursor,
    EventEndCursor,
    LeafStartCursor,
    LeafEndCursor,
    Events,
    Leaves,
}

impl<'de> DeserializeSeed<'de> for PoiCacheJournalDeltaSeed {
    type Value = PoiCacheJournalDelta;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        const FIELDS: &[&str] = &[
            "version",
            "identity",
            "event_start_cursor",
            "event_end_cursor",
            "leaf_start_cursor",
            "leaf_end_cursor",
            "events",
            "leaves",
        ];
        deserializer.deserialize_struct(
            "PoiCacheJournalDelta",
            FIELDS,
            PoiCacheJournalDeltaVisitor {
                max_events: self.max_events,
                max_leaves: self.max_leaves,
            },
        )
    }
}

struct PoiCacheJournalDeltaVisitor {
    max_events: usize,
    max_leaves: usize,
}

impl<'de> Visitor<'de> for PoiCacheJournalDeltaVisitor {
    type Value = PoiCacheJournalDelta;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a named POI cache journal delta")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut version = None;
        let mut identity = None;
        let mut event_start_cursor = None;
        let mut event_end_cursor = None;
        let mut leaf_start_cursor = None;
        let mut leaf_end_cursor = None;
        let mut events = None;
        let mut leaves = None;
        while let Some(field) = map.next_key()? {
            match field {
                PoiCacheJournalDeltaField::Version => {
                    if version.replace(map.next_value()?).is_some() {
                        return Err(de::Error::duplicate_field("version"));
                    }
                }
                PoiCacheJournalDeltaField::Identity => {
                    if identity.replace(map.next_value()?).is_some() {
                        return Err(de::Error::duplicate_field("identity"));
                    }
                }
                PoiCacheJournalDeltaField::EventStartCursor => {
                    if event_start_cursor.replace(map.next_value()?).is_some() {
                        return Err(de::Error::duplicate_field("event_start_cursor"));
                    }
                }
                PoiCacheJournalDeltaField::EventEndCursor => {
                    if event_end_cursor.replace(map.next_value()?).is_some() {
                        return Err(de::Error::duplicate_field("event_end_cursor"));
                    }
                }
                PoiCacheJournalDeltaField::LeafStartCursor => {
                    if leaf_start_cursor.replace(map.next_value()?).is_some() {
                        return Err(de::Error::duplicate_field("leaf_start_cursor"));
                    }
                }
                PoiCacheJournalDeltaField::LeafEndCursor => {
                    if leaf_end_cursor.replace(map.next_value()?).is_some() {
                        return Err(de::Error::duplicate_field("leaf_end_cursor"));
                    }
                }
                PoiCacheJournalDeltaField::Events => {
                    if events.is_some() {
                        return Err(de::Error::duplicate_field("events"));
                    }
                    events = Some(
                        map.next_value_seed(BoundedVecSeed::new(self.max_events, "journal event"))?,
                    );
                }
                PoiCacheJournalDeltaField::Leaves => {
                    if leaves.is_some() {
                        return Err(de::Error::duplicate_field("leaves"));
                    }
                    leaves = Some(
                        map.next_value_seed(BoundedVecSeed::new(self.max_leaves, "journal leaf"))?,
                    );
                }
            }
        }
        Ok(PoiCacheJournalDelta {
            version: version.ok_or_else(|| de::Error::missing_field("version"))?,
            identity: identity.ok_or_else(|| de::Error::missing_field("identity"))?,
            event_start_cursor: event_start_cursor
                .ok_or_else(|| de::Error::missing_field("event_start_cursor"))?,
            event_end_cursor: event_end_cursor
                .ok_or_else(|| de::Error::missing_field("event_end_cursor"))?,
            leaf_start_cursor: leaf_start_cursor
                .ok_or_else(|| de::Error::missing_field("leaf_start_cursor"))?,
            leaf_end_cursor: leaf_end_cursor
                .ok_or_else(|| de::Error::missing_field("leaf_end_cursor"))?,
            events: events.ok_or_else(|| de::Error::missing_field("events"))?,
            leaves: leaves.ok_or_else(|| de::Error::missing_field("leaves"))?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoiCacheJournalSyncResult {
    pub outcome: PoiCacheSyncOutcome,
    pub delta: PoiCacheJournalDelta,
    pub blocked_shields: Option<Vec<BlockedShield>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PoiCacheSnapshot {
    version: u32,
    identity: PoiCacheIdentity,
    progress: PoiCacheSyncProgress,
    forest: MerkleForest,
    status_by_blinded_commitment: BTreeMap<FixedBytes<32>, PoiStatus>,
    position_by_blinded_commitment: BTreeMap<FixedBytes<32>, PoiCachePosition>,
    blocked_shields_by_blinded_commitment: BTreeMap<FixedBytes<32>, BlockedShield>,
}

#[derive(Debug, Clone)]
pub struct PoiCache {
    snapshot: PoiCacheSnapshot,
}

pub struct PoiCacheJournalReplay {
    cache: PoiCache,
    current_tree: Option<(u32, DenseMerkleTree)>,
}

#[derive(Debug, Error)]
pub enum PoiCacheError {
    #[error("POI cache io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("POI cache decode error: {0}")]
    Decode(#[from] rmp_serde::decode::Error),
    #[error("POI cache encode error: {0}")]
    Encode(#[from] rmp_serde::encode::Error),
    #[error("POI cache RPC error: {0}")]
    Rpc(#[from] PoiRpcError),
    #[error("POI cache merkle error: {0}")]
    Merkle(#[from] merkletree::errors::SyncError),
    #[error("POI cache list signature verification failed: {0}")]
    Verify(#[from] VerifyError),
    #[error("POI cache snapshot version unsupported: {version}")]
    UnsupportedVersion { version: u32 },
    #[error("POI cache journal delta version unsupported: {version}")]
    UnsupportedJournalDeltaVersion { version: u16 },
    #[error("POI cache metadata mismatch: {reason}")]
    MetadataMismatch { reason: String },
    #[error("invalid POI cache hex field {field}: {value}")]
    InvalidHex { field: &'static str, value: String },
    #[error("POI cache page size must be non-zero")]
    InvalidPageSize,
    #[error("POI cache sync range overflow")]
    RangeOverflow,
    #[error(
        "POI cache sync cursors differ: next event index {next_event_index}, next leaf index {next_leaf_index}"
    )]
    SyncCursorMismatch {
        next_event_index: u64,
        next_leaf_index: u64,
    },
    #[error(
        "POI cache event response exceeds requested page {start_index}..={end_index}: requested at most {requested}, got {actual}"
    )]
    EventPageTooLarge {
        start_index: u64,
        end_index: u64,
        requested: u64,
        actual: usize,
    },
    #[error(
        "POI cache blocked Shield response exceeds requested page {start_index}..{end_index}: requested at most {requested}, got {actual}"
    )]
    BlockedShieldPageTooLarge {
        start_index: u64,
        end_index: u64,
        requested: u64,
        actual: usize,
    },
    #[error("POI cache blocked Shield snapshot exceeds record limit {limit}")]
    BlockedShieldLimitExceeded { limit: usize },
    #[error("POI cache event index is not contiguous: expected {expected}, got {actual}")]
    NonContiguousEvent { expected: u64, actual: u64 },
    #[error(
        "POI cache leaf response does not cover requested range {start_index}..{end_index}: expected {expected}, got {actual}"
    )]
    LeafPageSizeMismatch {
        start_index: u64,
        end_index: u64,
        expected: u64,
        actual: usize,
    },
    #[error("POI cache merkle leaf at index {index} has no fetched signed event")]
    LeafWithoutEvent { index: u64 },
    #[error("POI cache event/leaf mismatch at index {index}")]
    EventLeafMismatch { index: u64 },
    #[error("POI cache event at index {index} has no corresponding merkle leaf")]
    MissingEventLeaf { index: u64 },
    #[error("POI cache journal delta identity does not match the target cache")]
    JournalDeltaIdentityMismatch,
    #[error(
        "POI cache journal delta starts at event/leaf cursors {event_start_cursor}/{leaf_start_cursor}, current cursors are {next_event_index}/{next_leaf_index}"
    )]
    JournalDeltaCursorMismatch {
        event_start_cursor: u64,
        leaf_start_cursor: u64,
        next_event_index: u64,
        next_leaf_index: u64,
    },
    #[error(
        "POI cache journal delta ends at event/leaf cursors {event_end_cursor}/{leaf_end_cursor}, replay reached {next_event_index}/{next_leaf_index}"
    )]
    JournalDeltaEndCursorMismatch {
        event_end_cursor: u64,
        leaf_end_cursor: u64,
        next_event_index: u64,
        next_leaf_index: u64,
    },
    #[error("POI cache root validation required before proof generation")]
    RootValidationRequired,
    #[error("POI cache roots were rejected by the POI node")]
    InvalidRoots,
    #[error("missing POI cache proof data for blinded commitment {blinded_commitment}")]
    MissingCommitment { blinded_commitment: FixedBytes<32> },
    #[error("missing POI cache journal replay root for tree {tree_number}")]
    MissingJournalReplayRoot { tree_number: u32 },
    #[error(
        "POI cache proof leaf mismatch for blinded commitment {blinded_commitment}: got {leaf}"
    )]
    LeafMismatch {
        blinded_commitment: FixedBytes<32>,
        leaf: FixedBytes<32>,
    },
}

impl PoiCache {
    #[must_use]
    pub fn new(identity: PoiCacheIdentity) -> Self {
        Self {
            snapshot: PoiCacheSnapshot {
                version: POI_CACHE_SNAPSHOT_VERSION,
                identity,
                progress: PoiCacheSyncProgress::default(),
                forest: MerkleForest::new(),
                status_by_blinded_commitment: BTreeMap::new(),
                position_by_blinded_commitment: BTreeMap::new(),
                blocked_shields_by_blinded_commitment: BTreeMap::new(),
            },
        }
    }

    pub fn load(path: &Path, identity: &PoiCacheIdentity) -> Result<Option<Self>, PoiCacheError> {
        let data = match fs::read(path) {
            Ok(data) => data,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        Self::from_bytes(&data, identity).map(Some)
    }

    pub fn write(&self, path: &Path) -> Result<(), PoiCacheError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let data = self.to_bytes()?;
        let temp_path = temp_path(path);
        fs::write(&temp_path, data)?;
        fs::rename(temp_path, path)?;
        Ok(())
    }

    pub fn from_bytes(bytes: &[u8], identity: &PoiCacheIdentity) -> Result<Self, PoiCacheError> {
        let mut deserializer = rmp_serde::Deserializer::new(Cursor::new(bytes));
        let mut snapshot = PoiCacheSnapshot::deserialize(&mut deserializer)?;
        require_exact_messagepack_consumption(deserializer.get_ref().position(), bytes.len())?;
        if snapshot.version != POI_CACHE_SNAPSHOT_VERSION {
            return Err(PoiCacheError::UnsupportedVersion {
                version: snapshot.version,
            });
        }
        if &snapshot.identity != identity {
            return Err(PoiCacheError::MetadataMismatch {
                reason: "cache identity mismatch".to_string(),
            });
        }
        snapshot.forest.compute_roots();
        Ok(Self { snapshot })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, PoiCacheError> {
        Ok(rmp_serde::to_vec_named(&self.snapshot)?)
    }

    #[must_use]
    pub const fn into_journal_replay(self) -> PoiCacheJournalReplay {
        PoiCacheJournalReplay {
            cache: self,
            current_tree: None,
        }
    }

    #[must_use]
    pub const fn identity(&self) -> &PoiCacheIdentity {
        &self.snapshot.identity
    }

    #[must_use]
    pub const fn progress(&self) -> &PoiCacheSyncProgress {
        &self.snapshot.progress
    }

    #[must_use]
    pub fn leaf_count(&self) -> usize {
        self.snapshot.forest.leaf_count()
    }

    #[must_use]
    pub fn position(&self, blinded_commitment: &FixedBytes<32>) -> Option<PoiCachePosition> {
        self.snapshot
            .position_by_blinded_commitment
            .get(blinded_commitment)
            .copied()
    }

    #[must_use]
    pub fn positions_for_blinded_commitments(
        &self,
        blinded_commitments: &[FixedBytes<32>],
    ) -> Vec<Option<PoiCachePosition>> {
        blinded_commitments
            .iter()
            .map(|commitment| self.position(commitment))
            .collect()
    }

    #[must_use]
    pub fn commitment_at_global_index(&self, global_index: u64) -> Option<FixedBytes<32>> {
        let (tree_number, tree_position) = normalize_tree_position(0, global_index);
        self.snapshot
            .forest
            .leaf_at(tree_number, tree_position)
            .map(|leaf| FixedBytes::from(leaf.to_be_bytes::<32>()))
    }

    #[must_use]
    pub fn status(&self, blinded_commitment: &FixedBytes<32>) -> PoiStatus {
        self.snapshot
            .status_by_blinded_commitment
            .get(blinded_commitment)
            .copied()
            .unwrap_or(PoiStatus::Missing)
    }

    #[must_use]
    pub fn status_for_data(&self, data: &BlindedCommitmentData) -> PoiStatus {
        self.status(&data.blinded_commitment)
    }

    pub fn current_roots(&mut self) -> BTreeMap<u32, FixedBytes<32>> {
        self.snapshot.forest.compute_roots();
        fixed_roots(self.snapshot.forest.roots())
    }

    /// Returns current roots without updating cached roots.
    ///
    /// Existing cached roots are reused, but dirty roots are computed on demand and remain
    /// uncached. Prefer [`Self::current_roots`] when mutable access is available and subsequent
    /// calls should reuse the computed roots or benefit from mutable cross-tree computation.
    #[must_use]
    pub fn current_roots_readonly(&self) -> BTreeMap<u32, FixedBytes<32>> {
        fixed_roots(self.snapshot.forest.computed_roots())
    }

    /// Returns the roots accepted for the current forest state, if any.
    ///
    /// Every method that may mutate the forest must invalidate `root_validation`
    /// before its first possible insertion, including when the mutation later fails.
    #[must_use]
    pub const fn validated_roots(&self) -> Option<&BTreeMap<u32, FixedBytes<32>>> {
        match &self.snapshot.progress.root_validation {
            PoiCacheRootValidation::Validated { roots } => Some(roots),
            PoiCacheRootValidation::Pending | PoiCacheRootValidation::Invalid { .. } => None,
        }
    }

    fn insert_leaf(&mut self, update: MerkleTreeUpdate) -> Result<(), PoiCacheError> {
        self.snapshot.progress.root_validation = PoiCacheRootValidation::Pending;
        self.snapshot.forest.insert_leaf(update)?;
        Ok(())
    }

    #[must_use]
    pub fn root_at_global_index(&self, global_index: u64) -> Option<FixedBytes<32>> {
        let (tree_number, tree_position) = normalize_tree_position(0, global_index);
        if !self.snapshot.forest.contains_tree(tree_number) {
            return None;
        }
        let leaf_count = tree_position.checked_add(1)?;
        let root =
            DenseMerkleTree::from_forest_prefix(&self.snapshot.forest, tree_number, leaf_count)
                .root();
        Some(FixedBytes::from(root.to_be_bytes::<32>()))
    }

    #[must_use]
    pub fn blocked_shields_match(&self, other: &Self) -> bool {
        self.snapshot.blocked_shields_by_blinded_commitment
            == other.snapshot.blocked_shields_by_blinded_commitment
            && self.snapshot.progress.blocked_shields_synced
                == other.snapshot.progress.blocked_shields_synced
    }

    #[must_use]
    pub fn blocked_shields_snapshot(&self) -> Vec<BlockedShield> {
        self.snapshot
            .blocked_shields_by_blinded_commitment
            .values()
            .cloned()
            .collect()
    }

    pub fn apply_poi_events(
        &mut self,
        events: &[PoiSyncedListEvent],
    ) -> Result<usize, PoiCacheError> {
        for event in events {
            self.apply_event_commitment(
                event.signed_poi_event.index,
                event.signed_poi_event.blinded_commitment,
            )?;
        }
        Ok(events.len())
    }

    fn apply_event_commitment(
        &mut self,
        event_index: u64,
        blinded_commitment: FixedBytes<32>,
    ) -> Result<(), PoiCacheError> {
        self.snapshot
            .status_by_blinded_commitment
            .insert(blinded_commitment, PoiStatus::Valid);
        self.snapshot.progress.next_event_index = self
            .snapshot
            .progress
            .next_event_index
            .max(next_index(event_index)?);
        Ok(())
    }

    pub fn apply_poi_leaves(
        &mut self,
        start_index: u64,
        leaves: &[U256],
    ) -> Result<usize, PoiCacheError> {
        let mut inserted = 0usize;
        for (offset, leaf) in leaves.iter().enumerate() {
            let global_index = start_index
                .checked_add(offset as u64)
                .ok_or(PoiCacheError::RangeOverflow)?;
            if *leaf != U256::ZERO {
                let (tree_number, tree_position) = normalize_tree_position(0, global_index);
                self.insert_leaf(MerkleTreeUpdate {
                    tree_number,
                    tree_position,
                    hash: *leaf,
                })?;
                let blinded_commitment = FixedBytes::from(leaf.to_be_bytes::<32>());
                self.snapshot.position_by_blinded_commitment.insert(
                    blinded_commitment,
                    PoiCachePosition {
                        global_index,
                        tree_number,
                        tree_position,
                    },
                );
                self.snapshot
                    .status_by_blinded_commitment
                    .insert(blinded_commitment, PoiStatus::Valid);
                inserted += 1;
            }
            self.snapshot.progress.next_leaf_index = self
                .snapshot
                .progress
                .next_leaf_index
                .max(next_index(global_index)?);
        }
        Ok(inserted)
    }

    pub fn apply_journal_delta(
        &mut self,
        delta: &PoiCacheJournalDelta,
    ) -> Result<(), PoiCacheError> {
        if delta.version != POI_CACHE_JOURNAL_DELTA_VERSION {
            return Err(PoiCacheError::UnsupportedJournalDeltaVersion {
                version: delta.version,
            });
        }
        if delta.identity != self.snapshot.identity {
            return Err(PoiCacheError::JournalDeltaIdentityMismatch);
        }
        if delta.event_start_cursor != self.snapshot.progress.next_event_index
            || delta.leaf_start_cursor != self.snapshot.progress.next_leaf_index
        {
            return Err(PoiCacheError::JournalDeltaCursorMismatch {
                event_start_cursor: delta.event_start_cursor,
                leaf_start_cursor: delta.leaf_start_cursor,
                next_event_index: self.snapshot.progress.next_event_index,
                next_leaf_index: self.snapshot.progress.next_leaf_index,
            });
        }
        let expected_event_end = delta
            .event_start_cursor
            .checked_add(delta.events.len() as u64)
            .ok_or(PoiCacheError::RangeOverflow)?;
        let expected_leaf_end = delta
            .leaf_start_cursor
            .checked_add(delta.leaves.len() as u64)
            .ok_or(PoiCacheError::RangeOverflow)?;
        if expected_event_end != delta.event_end_cursor
            || expected_leaf_end != delta.leaf_end_cursor
        {
            return Err(PoiCacheError::JournalDeltaEndCursorMismatch {
                event_end_cursor: delta.event_end_cursor,
                leaf_end_cursor: delta.leaf_end_cursor,
                next_event_index: expected_event_end,
                next_leaf_index: expected_leaf_end,
            });
        }

        let mut event_commitments = BTreeMap::new();
        let mut expected_index = delta.event_start_cursor;
        for event in &delta.events {
            if event.event_index != expected_index {
                return Err(PoiCacheError::NonContiguousEvent {
                    expected: expected_index,
                    actual: event.event_index,
                });
            }
            event_commitments.insert(event.event_index, event.blinded_commitment);
            expected_index = next_index(expected_index)?;
        }
        for (offset, leaf) in delta.leaves.iter().enumerate() {
            let index = delta
                .leaf_start_cursor
                .checked_add(offset as u64)
                .ok_or(PoiCacheError::RangeOverflow)?;
            let expected = event_commitments
                .remove(&index)
                .ok_or(PoiCacheError::LeafWithoutEvent { index })?;
            if *leaf != expected {
                return Err(PoiCacheError::EventLeafMismatch { index });
            }
        }
        if let Some(index) = event_commitments.keys().next().copied() {
            return Err(PoiCacheError::MissingEventLeaf { index });
        }

        for event in &delta.events {
            self.apply_event_commitment(event.event_index, event.blinded_commitment)?;
        }
        let leaves = delta
            .leaves
            .iter()
            .map(|leaf| U256::from_be_bytes(leaf.0))
            .collect::<Vec<_>>();
        self.apply_poi_leaves(delta.leaf_start_cursor, &leaves)?;
        if self.snapshot.progress.next_event_index != delta.event_end_cursor
            || self.snapshot.progress.next_leaf_index != delta.leaf_end_cursor
        {
            return Err(PoiCacheError::JournalDeltaEndCursorMismatch {
                event_end_cursor: delta.event_end_cursor,
                leaf_end_cursor: delta.leaf_end_cursor,
                next_event_index: self.snapshot.progress.next_event_index,
                next_leaf_index: self.snapshot.progress.next_leaf_index,
            });
        }
        Ok(())
    }

    pub fn apply_blocked_shields(
        &mut self,
        blocked_shields: &[BlockedShield],
    ) -> Result<usize, PoiCacheError> {
        for blocked_shield in blocked_shields {
            let blinded_commitment = parse_fixed_hex(
                &blocked_shield.blinded_commitment,
                "blockedShield.blindedCommitment",
            )?;
            self.snapshot
                .blocked_shields_by_blinded_commitment
                .insert(blinded_commitment, blocked_shield.clone());
            if self.status(&blinded_commitment) != PoiStatus::Valid {
                self.snapshot
                    .status_by_blinded_commitment
                    .insert(blinded_commitment, PoiStatus::ShieldBlocked);
            }
        }
        self.snapshot.progress.blocked_shields_synced = true;
        Ok(blocked_shields.len())
    }

    pub fn replace_blocked_shields(
        &mut self,
        blocked_shields: &[BlockedShield],
    ) -> Result<usize, PoiCacheError> {
        let previous = self
            .snapshot
            .blocked_shields_by_blinded_commitment
            .keys()
            .copied()
            .collect::<Vec<_>>();
        self.snapshot.blocked_shields_by_blinded_commitment.clear();
        for blinded_commitment in previous {
            if self.status(&blinded_commitment) == PoiStatus::ShieldBlocked {
                self.snapshot
                    .status_by_blinded_commitment
                    .remove(&blinded_commitment);
            }
        }
        self.apply_blocked_shields(blocked_shields)
    }

    pub fn apply_verified_artifact_events(
        &mut self,
        events: &[SnapshotEvent],
    ) -> Result<usize, PoiCacheError> {
        let mut inserted = 0usize;
        for event in events {
            let global_index = event.event_index;
            let leaf = U256::from_be_bytes(event.blinded_commitment);
            let (tree_number, tree_position) = normalize_tree_position(0, global_index);
            self.insert_leaf(MerkleTreeUpdate {
                tree_number,
                tree_position,
                hash: leaf,
            })?;
            let blinded_commitment = FixedBytes::from(leaf.to_be_bytes::<32>());
            self.snapshot.position_by_blinded_commitment.insert(
                blinded_commitment,
                PoiCachePosition {
                    global_index,
                    tree_number,
                    tree_position,
                },
            );
            self.snapshot
                .status_by_blinded_commitment
                .insert(blinded_commitment, PoiStatus::Valid);
            self.snapshot.progress.next_event_index = self
                .snapshot
                .progress
                .next_event_index
                .max(next_index(global_index)?);
            self.snapshot.progress.next_leaf_index = self
                .snapshot
                .progress
                .next_leaf_index
                .max(next_index(global_index)?);
            inserted += 1;
        }
        Ok(inserted)
    }

    pub fn accept_current_roots(&mut self) -> BTreeMap<u32, FixedBytes<32>> {
        let roots = self.current_roots();
        self.snapshot.progress.root_validation = PoiCacheRootValidation::Validated {
            roots: roots.clone(),
        };
        roots
    }

    pub async fn sync(
        &mut self,
        client: &PoiRpcClient,
    ) -> Result<PoiCacheSyncOutcome, PoiCacheError> {
        self.sync_with_page_sizes(
            client,
            POI_EVENTS_PAGE_SIZE,
            POI_MERKLETREE_LEAVES_PAGE_SIZE,
        )
        .await
    }

    pub async fn sync_with_page_sizes(
        &mut self,
        client: &PoiRpcClient,
        event_page_size: u64,
        leaf_page_size: u64,
    ) -> Result<PoiCacheSyncOutcome, PoiCacheError> {
        self.sync_bounded(client, event_page_size, leaf_page_size, usize::MAX)
            .await
    }

    pub async fn sync_bounded(
        &mut self,
        client: &PoiRpcClient,
        event_page_size: u64,
        leaf_page_size: u64,
        max_event_pages: usize,
    ) -> Result<PoiCacheSyncOutcome, PoiCacheError> {
        let mut candidate = self.clone();
        let result = candidate
            .sync_bounded_candidate(
                client,
                event_page_size,
                leaf_page_size,
                max_event_pages,
                PoiCacheSyncScope::Full,
            )
            .await?;
        *self = candidate;
        Ok(result.outcome)
    }

    pub async fn sync_bounded_with_journal(
        mut self,
        client: &PoiRpcClient,
        event_page_size: u64,
        leaf_page_size: u64,
        max_event_pages: usize,
    ) -> Result<(Self, PoiCacheJournalSyncResult), PoiCacheError> {
        let result = self
            .sync_bounded_candidate(
                client,
                event_page_size,
                leaf_page_size,
                max_event_pages,
                PoiCacheSyncScope::Full,
            )
            .await?;
        Ok((self, result))
    }

    pub async fn sync_events_bounded_with_journal(
        mut self,
        client: &PoiRpcClient,
        event_page_size: u64,
        leaf_page_size: u64,
        max_event_pages: usize,
    ) -> Result<(Self, PoiCacheJournalSyncResult), PoiCacheError> {
        let result = self
            .sync_bounded_candidate(
                client,
                event_page_size,
                leaf_page_size,
                max_event_pages,
                PoiCacheSyncScope::Events,
            )
            .await?;
        Ok((self, result))
    }

    pub async fn sync_blocked_shields_with_journal(
        mut self,
        client: &PoiRpcClient,
    ) -> Result<(Self, PoiCacheJournalSyncResult), PoiCacheError> {
        let result = self
            .sync_bounded_candidate(
                client,
                POI_EVENTS_PAGE_SIZE,
                POI_MERKLETREE_LEAVES_PAGE_SIZE,
                usize::MAX,
                PoiCacheSyncScope::BlockedShields,
            )
            .await?;
        Ok((self, result))
    }

    async fn sync_bounded_candidate(
        &mut self,
        client: &PoiRpcClient,
        event_page_size: u64,
        leaf_page_size: u64,
        max_event_pages: usize,
        scope: PoiCacheSyncScope,
    ) -> Result<PoiCacheJournalSyncResult, PoiCacheError> {
        if scope.sync_events()
            && (event_page_size == 0 || leaf_page_size == 0 || max_event_pages == 0)
        {
            return Err(PoiCacheError::InvalidPageSize);
        }
        if scope.sync_events()
            && self.snapshot.progress.next_event_index != self.snapshot.progress.next_leaf_index
        {
            return Err(PoiCacheError::SyncCursorMismatch {
                next_event_index: self.snapshot.progress.next_event_index,
                next_leaf_index: self.snapshot.progress.next_leaf_index,
            });
        }

        let sync_started = Instant::now();
        let event_start_cursor = self.snapshot.progress.next_event_index;
        let leaf_start_cursor = self.snapshot.progress.next_leaf_index;
        debug!(
            chain_type = self.snapshot.identity.chain_type,
            chain_id = self.snapshot.identity.chain_id,
            txid_version = %self.snapshot.identity.txid_version,
            list_key = %hex::encode(self.snapshot.identity.list_key),
            next_event_index = self.snapshot.progress.next_event_index,
            next_leaf_index = self.snapshot.progress.next_leaf_index,
            blocked_shields_synced = self.snapshot.progress.blocked_shields_synced,
            event_page_size,
            leaf_page_size,
            "local POI cache sync started"
        );

        let mut outcome = PoiCacheSyncOutcome::default();
        let mut event_commitments = BTreeMap::new();
        let mut journal_events = Vec::new();
        let mut journal_leaves = Vec::new();
        let mut event_pages = 0_usize;
        while scope.sync_events() {
            let start_index = self.snapshot.progress.next_event_index;
            let end_index = start_index
                .checked_add(event_page_size - 1)
                .ok_or(PoiCacheError::RangeOverflow)?;
            let page_started = Instant::now();
            let events = client
                .poi_events(
                    &self.snapshot.identity.txid_version,
                    self.snapshot.identity.chain_type,
                    self.snapshot.identity.chain_id,
                    &self.snapshot.identity.list_key,
                    start_index,
                    end_index,
                )
                .await?;
            let requested_event_count = usize::try_from(event_page_size).unwrap_or(usize::MAX);
            if events.len() > requested_event_count {
                return Err(PoiCacheError::EventPageTooLarge {
                    start_index,
                    end_index,
                    requested: event_page_size,
                    actual: events.len(),
                });
            }
            if events.is_empty() {
                debug!(
                    chain_id = self.snapshot.identity.chain_id,
                    list_key = %hex::encode(self.snapshot.identity.list_key),
                    start_index,
                    end_index,
                    elapsed_ms = page_started.elapsed().as_millis(),
                    "local POI events sync reached empty page"
                );
                break;
            }
            let mut expected_index = start_index;
            for event in &events {
                if event.signed_poi_event.index != expected_index {
                    return Err(PoiCacheError::NonContiguousEvent {
                        expected: expected_index,
                        actual: event.signed_poi_event.index,
                    });
                }
                verify_poi_event(&event.signed_poi_event, &self.snapshot.identity.list_key.0)?;
                event_commitments.insert(expected_index, event.signed_poi_event.blinded_commitment);
                journal_events.push(PoiCacheJournalEvent {
                    event_index: expected_index,
                    blinded_commitment: event.signed_poi_event.blinded_commitment,
                });
                expected_index = expected_index
                    .checked_add(1)
                    .ok_or(PoiCacheError::RangeOverflow)?;
            }
            let returned = events.len();
            let applied = self.apply_poi_events(&events)?;
            outcome.events += applied;
            event_pages = event_pages.saturating_add(1);
            debug!(
                chain_id = self.snapshot.identity.chain_id,
                list_key = %hex::encode(self.snapshot.identity.list_key),
                start_index,
                end_index,
                returned,
                applied,
                next_event_index = self.snapshot.progress.next_event_index,
                elapsed_ms = page_started.elapsed().as_millis(),
                events_per_sec = rate_per_sec(returned, page_started.elapsed()),
                "local POI events page synced"
            );
            if events.len() < requested_event_count {
                break;
            }
            if event_pages >= max_event_pages {
                outcome.event_page_budget_exhausted = true;
                break;
            }
        }

        while scope.sync_events()
            && self.snapshot.progress.next_leaf_index < self.snapshot.progress.next_event_index
        {
            let start_index = self.snapshot.progress.next_leaf_index;
            let remaining = self.snapshot.progress.next_event_index - start_index;
            let page_size = leaf_page_size.min(remaining);
            let end_index = start_index
                .checked_add(page_size)
                .ok_or(PoiCacheError::RangeOverflow)?;
            let page_started = Instant::now();
            let leaves = client
                .poi_merkletree_leaves(
                    &self.snapshot.identity.txid_version,
                    self.snapshot.identity.chain_type,
                    self.snapshot.identity.chain_id,
                    &self.snapshot.identity.list_key,
                    start_index,
                    end_index,
                )
                .await?;
            if u64::try_from(leaves.len()) != Ok(page_size) {
                return Err(PoiCacheError::LeafPageSizeMismatch {
                    start_index,
                    end_index,
                    expected: page_size,
                    actual: leaves.len(),
                });
            }
            for (offset, leaf) in leaves.iter().enumerate() {
                let index = start_index
                    .checked_add(offset as u64)
                    .ok_or(PoiCacheError::RangeOverflow)?;
                let expected = event_commitments
                    .get(&index)
                    .ok_or(PoiCacheError::LeafWithoutEvent { index })?;
                if FixedBytes::from(leaf.to_be_bytes::<32>()) != *expected {
                    return Err(PoiCacheError::EventLeafMismatch { index });
                }
            }
            for offset in 0..leaves.len() {
                let index = start_index
                    .checked_add(offset as u64)
                    .ok_or(PoiCacheError::RangeOverflow)?;
                event_commitments.remove(&index);
            }
            journal_leaves.extend(
                leaves
                    .iter()
                    .map(|leaf| FixedBytes::from(leaf.to_be_bytes::<32>())),
            );
            let returned = leaves.len();
            let applied = self.apply_poi_leaves(start_index, &leaves)?;
            outcome.leaves += applied;
            debug!(
                chain_id = self.snapshot.identity.chain_id,
                list_key = %hex::encode(self.snapshot.identity.list_key),
                start_index,
                end_index,
                returned,
                applied,
                next_leaf_index = self.snapshot.progress.next_leaf_index,
                elapsed_ms = page_started.elapsed().as_millis(),
                leaves_per_sec = rate_per_sec(returned, page_started.elapsed()),
                "local POI leaves page synced"
            );
        }

        if scope.sync_events()
            && let Some(index) = event_commitments.keys().next().copied()
        {
            return Err(PoiCacheError::MissingEventLeaf { index });
        }

        let (blocked_shields, blocked_shields_changed) = if scope.sync_blocked_shields() {
            let blocked_started = Instant::now();
            let previous_blocked_shields_synced = self.snapshot.progress.blocked_shields_synced;
            let previous_blocked_shields =
                self.snapshot.blocked_shields_by_blinded_commitment.clone();
            let requested_blocked_shield_count =
                usize::try_from(POI_BLOCKED_SHIELDS_PAGE_SIZE).unwrap_or(usize::MAX);
            let mut blocked_shields = Vec::new();
            let mut blocked_start_index = 0_u64;
            loop {
                let blocked_end_index = blocked_start_index
                    .checked_add(POI_BLOCKED_SHIELDS_PAGE_SIZE)
                    .ok_or(PoiCacheError::RangeOverflow)?;
                let page = client
                    .blocked_shields(
                        &self.snapshot.identity.txid_version,
                        self.snapshot.identity.chain_type,
                        self.snapshot.identity.chain_id,
                        &self.snapshot.identity.list_key,
                        blocked_start_index,
                        blocked_end_index,
                    )
                    .await?;
                if page.len() > requested_blocked_shield_count {
                    return Err(PoiCacheError::BlockedShieldPageTooLarge {
                        start_index: blocked_start_index,
                        end_index: blocked_end_index,
                        requested: POI_BLOCKED_SHIELDS_PAGE_SIZE,
                        actual: page.len(),
                    });
                }
                if blocked_shields.len().saturating_add(page.len()) > POI_BLOCKED_SHIELDS_LIMIT {
                    return Err(PoiCacheError::BlockedShieldLimitExceeded {
                        limit: POI_BLOCKED_SHIELDS_LIMIT,
                    });
                }
                for blocked_shield in &page {
                    verify_blocked_shield(blocked_shield, &self.snapshot.identity.list_key.0)?;
                }
                let returned = page.len();
                blocked_shields.extend(page);
                if returned < requested_blocked_shield_count {
                    break;
                }
                blocked_start_index = blocked_end_index;
            }
            outcome.blocked_shields = self.replace_blocked_shields(&blocked_shields)?;
            let changed = (!previous_blocked_shields_synced
                && (scope == PoiCacheSyncScope::BlockedShields
                    || self.snapshot.progress.next_event_index > 0))
                || self.snapshot.blocked_shields_by_blinded_commitment != previous_blocked_shields;
            debug!(
                chain_id = self.snapshot.identity.chain_id,
                list_key = %hex::encode(self.snapshot.identity.list_key),
                returned = blocked_shields.len(),
                applied = outcome.blocked_shields,
                elapsed_ms = blocked_started.elapsed().as_millis(),
                "local POI blocked shields synced"
            );
            (Some(blocked_shields), changed)
        } else {
            (None, false)
        };
        outcome.changed = outcome.events > 0 || outcome.leaves > 0 || blocked_shields_changed;

        debug!(
            chain_id = self.snapshot.identity.chain_id,
            list_key = %hex::encode(self.snapshot.identity.list_key),
            events = outcome.events,
            leaves = outcome.leaves,
            blocked_shields = outcome.blocked_shields,
            leaf_count = self.leaf_count(),
            elapsed_ms = sync_started.elapsed().as_millis(),
            "local POI cache sync finished"
        );

        Ok(PoiCacheJournalSyncResult {
            outcome,
            delta: PoiCacheJournalDelta {
                version: POI_CACHE_JOURNAL_DELTA_VERSION,
                identity: self.snapshot.identity.clone(),
                event_start_cursor,
                event_end_cursor: self.snapshot.progress.next_event_index,
                leaf_start_cursor,
                leaf_end_cursor: self.snapshot.progress.next_leaf_index,
                events: journal_events,
                leaves: journal_leaves,
            },
            blocked_shields: blocked_shields.filter(|_| blocked_shields_changed),
        })
    }

    pub async fn validate_roots(&mut self, client: &PoiRpcClient) -> Result<bool, PoiCacheError> {
        let roots = self.current_roots();
        let root_hexes = roots.values().map(hex::encode).collect::<Vec<_>>();
        let accepted = !root_hexes.is_empty()
            && client
                .validate_poi_merkleroots(
                    &self.snapshot.identity.txid_version,
                    self.snapshot.identity.chain_type,
                    self.snapshot.identity.chain_id,
                    &self.snapshot.identity.list_key,
                    &root_hexes,
                )
                .await?;
        self.snapshot.progress.root_validation = if accepted {
            PoiCacheRootValidation::Validated { roots }
        } else {
            PoiCacheRootValidation::Invalid { roots }
        };
        Ok(accepted)
    }

    pub fn poi_merkle_proofs(
        &self,
        blinded_commitments: &[FixedBytes<32>],
    ) -> Result<Vec<PoiMerkleProof>, PoiCacheError> {
        self.ensure_roots_validated()?;
        let positions = blinded_commitments
            .iter()
            .map(|blinded_commitment| {
                self.position_for_blinded_commitment(blinded_commitment)
                    .map(|position| (*blinded_commitment, position))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let dense_tree_counts = dense_tree_counts(&positions);
        let mut dense_trees = BTreeMap::new();
        positions
            .into_iter()
            .map(|(blinded_commitment, position)| {
                self.poi_merkle_proof_at_position(
                    &blinded_commitment,
                    position,
                    &dense_tree_counts,
                    &mut dense_trees,
                )
            })
            .collect()
    }

    fn ensure_roots_validated(&self) -> Result<(), PoiCacheError> {
        let roots = self.current_roots_readonly();
        if self.snapshot.progress.root_validation.accepts(&roots) {
            Ok(())
        } else if self.snapshot.progress.root_validation.rejects(&roots) {
            Err(PoiCacheError::InvalidRoots)
        } else {
            Err(PoiCacheError::RootValidationRequired)
        }
    }

    fn poi_merkle_proof_at_position(
        &self,
        blinded_commitment: &FixedBytes<32>,
        position: PoiCachePosition,
        dense_tree_counts: &BTreeMap<u32, usize>,
        dense_trees: &mut BTreeMap<u32, DenseMerkleTree>,
    ) -> Result<PoiMerkleProof, PoiCacheError> {
        let proof = if dense_tree_counts
            .get(&position.tree_number)
            .is_some_and(|count| *count >= DENSE_POI_PROOF_MIN_COMMITMENTS_PER_TREE)
        {
            let dense_tree = dense_trees.entry(position.tree_number).or_insert_with(|| {
                DenseMerkleTree::from_forest_prefix(
                    &self.snapshot.forest,
                    position.tree_number,
                    TREE_LEAF_COUNT,
                )
            });
            dense_tree.prove(position.tree_position)
        } else {
            self.sparse_poi_merkle_proof(position, blinded_commitment)?
        };
        validate_poi_merkle_proof_leaf(&proof, blinded_commitment)?;
        Ok(poi_merkle_proof_from_cache(&proof))
    }

    fn position_for_blinded_commitment(
        &self,
        blinded_commitment: &FixedBytes<32>,
    ) -> Result<PoiCachePosition, PoiCacheError> {
        self.snapshot
            .position_by_blinded_commitment
            .get(blinded_commitment)
            .copied()
            .ok_or(PoiCacheError::MissingCommitment {
                blinded_commitment: *blinded_commitment,
            })
    }

    fn sparse_poi_merkle_proof(
        &self,
        position: PoiCachePosition,
        blinded_commitment: &FixedBytes<32>,
    ) -> Result<MerkleProof, PoiCacheError> {
        self.snapshot
            .forest
            .prove(position.tree_number, position.tree_position)
            .ok_or(PoiCacheError::MissingCommitment {
                blinded_commitment: *blinded_commitment,
            })
    }
}

fn require_exact_messagepack_consumption(
    position: u64,
    input_len: usize,
) -> Result<(), PoiCacheError> {
    if position != u64::try_from(input_len).unwrap_or(u64::MAX) {
        return Err(rmp_serde::decode::Error::Syntax(
            "trailing bytes after MessagePack value".to_string(),
        )
        .into());
    }
    Ok(())
}

fn validate_poi_merkle_proof_leaf(
    proof: &MerkleProof,
    blinded_commitment: &FixedBytes<32>,
) -> Result<(), PoiCacheError> {
    let leaf = FixedBytes::from(proof.leaf.to_be_bytes::<32>());
    if leaf != *blinded_commitment {
        return Err(PoiCacheError::LeafMismatch {
            blinded_commitment: *blinded_commitment,
            leaf,
        });
    }
    Ok(())
}

fn dense_tree_counts(positions: &[(FixedBytes<32>, PoiCachePosition)]) -> BTreeMap<u32, usize> {
    let mut counts = BTreeMap::new();
    for (_, position) in positions {
        *counts.entry(position.tree_number).or_default() += 1;
    }
    counts
}

fn poi_merkle_proof_from_cache(proof: &MerkleProof) -> PoiMerkleProof {
    PoiMerkleProof {
        leaf: proof.leaf,
        elements: proof.path_elements.to_vec(),
        indices: U256::from(proof.leaf_index),
        root: proof.root,
    }
}

impl PoiCacheJournalReplay {
    pub fn apply_delta(
        &mut self,
        delta: &PoiCacheJournalDelta,
    ) -> Result<FixedBytes<32>, PoiCacheError> {
        let tip_index = delta.event_end_cursor.checked_sub(1).ok_or(
            PoiCacheError::JournalDeltaEndCursorMismatch {
                event_end_cursor: delta.event_end_cursor,
                leaf_end_cursor: delta.leaf_end_cursor,
                next_event_index: self.cache.progress().next_event_index,
                next_leaf_index: self.cache.progress().next_leaf_index,
            },
        )?;
        let (tree_number, tree_position) = normalize_tree_position(0, tip_index);
        let increment_current_tree = !delta.leaves.is_empty()
            && self
                .current_tree
                .as_ref()
                .is_some_and(|(current, _)| *current == tree_number)
            && normalize_tree_position(0, delta.leaf_start_cursor).0 == tree_number;

        self.cache.apply_journal_delta(delta)?;

        if increment_current_tree {
            let Some((_, dense)) = self.current_tree.as_mut() else {
                return Err(PoiCacheError::MissingJournalReplayRoot { tree_number });
            };
            for (offset, leaf) in delta.leaves.iter().enumerate() {
                if *leaf == FixedBytes::ZERO {
                    continue;
                }
                let global_index = delta
                    .leaf_start_cursor
                    .checked_add(offset as u64)
                    .ok_or(PoiCacheError::RangeOverflow)?;
                let (leaf_tree, leaf_position) = normalize_tree_position(0, global_index);
                debug_assert_eq!(leaf_tree, tree_number);
                dense.set_leaf(leaf_position, U256::from_be_bytes(leaf.0));
            }
        } else if !delta.leaves.is_empty() {
            self.current_tree = Some((
                tree_number,
                DenseMerkleTree::from_forest_prefix(
                    &self.cache.snapshot.forest,
                    tree_number,
                    tree_position + 1,
                ),
            ));
        }

        if let Some((current, dense)) = self.current_tree.as_ref()
            && *current == tree_number
        {
            return Ok(FixedBytes::from(dense.root().to_be_bytes::<32>()));
        }
        self.cache
            .current_roots_readonly()
            .get(&tree_number)
            .copied()
            .ok_or(PoiCacheError::MissingJournalReplayRoot { tree_number })
    }

    #[must_use]
    pub fn finish(mut self) -> PoiCache {
        self.cache.accept_current_roots();
        self.cache
    }
}

fn fixed_roots(roots: BTreeMap<u32, U256>) -> BTreeMap<u32, FixedBytes<32>> {
    roots
        .into_iter()
        .map(|(tree, root)| (tree, FixedBytes::from(root.to_be_bytes::<32>())))
        .collect()
}

fn parse_fixed_hex(value: &str, field: &'static str) -> Result<FixedBytes<32>, PoiCacheError> {
    parse_u256_hex(value, field).map(|value| FixedBytes::from(value.to_be_bytes::<32>()))
}

fn parse_u256_hex(value: &str, field: &'static str) -> Result<U256, PoiCacheError> {
    let value_without_prefix = value.strip_prefix("0x").unwrap_or(value);
    if value_without_prefix.len() > 64 {
        return Err(PoiCacheError::InvalidHex {
            field,
            value: value.to_string(),
        });
    }
    if value_without_prefix.is_empty() {
        return Ok(U256::ZERO);
    }
    U256::from_str_radix(value_without_prefix, 16).map_err(|_| PoiCacheError::InvalidHex {
        field,
        value: value.to_string(),
    })
}

fn next_index(index: u64) -> Result<u64, PoiCacheError> {
    index.checked_add(1).ok_or(PoiCacheError::RangeOverflow)
}

fn temp_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("poi-cache.msgpack");
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let temp_name = format!("{file_name}.tmp.{pid}.{nanos}");
    let mut temp_path = path.to_path_buf();
    temp_path.set_file_name(temp_name);
    temp_path
}

fn rate_per_sec(count: usize, elapsed: Duration) -> f64 {
    let secs = elapsed.as_secs_f64();
    if secs == 0.0 {
        0.0
    } else {
        let count = u32::try_from(count).unwrap_or(u32::MAX);
        f64::from(count) / secs
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc::{self, Receiver};
    use std::time::Duration;

    use serde_json::{Value, json};

    use super::*;
    use crate::artifacts::verify::{canonical_blocked_shield_message, canonical_poi_event_message};
    use crate::poi::{PoiEventType, SignedPoiEvent};

    struct MockJsonRpc {
        url: reqwest::Url,
        requests: Receiver<String>,
    }

    fn identity() -> PoiCacheIdentity {
        PoiCacheIdentity::new(
            0,
            1,
            "V2_PoseidonMerkle",
            FixedBytes::from(signing_key().verifying_key().to_bytes()),
        )
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x11; 32])
    }

    fn temp_cache_path() -> PathBuf {
        let dir = std::env::temp_dir().join("railgun-broadcaster-tests");
        fs::create_dir_all(&dir).expect("create temp cache dir");
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        dir.join(format!("poi-cache-{pid}-{nanos}.msgpack"))
    }

    fn event(index: u64, blinded_commitment: FixedBytes<32>) -> PoiSyncedListEvent {
        let mut signed_poi_event = SignedPoiEvent {
            index,
            blinded_commitment,
            signature: String::new(),
            event_type: PoiEventType::Shield,
        };
        signed_poi_event.signature = hex::encode(
            signing_key()
                .sign(&canonical_poi_event_message(&signed_poi_event))
                .to_bytes(),
        );
        PoiSyncedListEvent {
            signed_poi_event,
            validated_merkleroot: hex::encode(FixedBytes::from([0x44; 32])),
        }
    }

    fn blocked(blinded_commitment: FixedBytes<32>) -> BlockedShield {
        let mut blocked = BlockedShield {
            commitment_hash: hex::encode_prefixed(FixedBytes::from([0x99; 32])),
            blinded_commitment: hex::encode_prefixed(blinded_commitment),
            block_reason: Some("blocked".to_string()),
            signature: String::new(),
        };
        blocked.signature = hex::encode(
            signing_key()
                .sign(&canonical_blocked_shield_message(&blocked))
                .to_bytes(),
        );
        blocked
    }

    fn spawn_json_rpc(responses: Vec<String>) -> MockJsonRpc {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let url = reqwest::Url::parse(&format!("http://{}", listener.local_addr().unwrap()))
            .expect("mock url");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().expect("accept request");
                let body = read_http_body(&mut stream);
                tx.send(body).expect("send request body");
                let reply = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    response.len(),
                    response
                );
                stream.write_all(reply.as_bytes()).expect("write response");
            }
        });
        MockJsonRpc { url, requests: rx }
    }

    fn read_http_body(stream: &mut std::net::TcpStream) -> String {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let read = stream.read(&mut chunk).expect("read request");
            assert!(read > 0, "connection closed before request body");
            buffer.extend_from_slice(&chunk[..read]);
            if let Some((body_start, content_length)) = request_body_bounds(&buffer)
                && buffer.len() >= body_start + content_length
            {
                return String::from_utf8_lossy(&buffer[body_start..body_start + content_length])
                    .to_string();
            }
        }
    }

    fn request_body_bounds(buffer: &[u8]) -> Option<(usize, usize)> {
        let header_end = buffer.windows(4).position(|window| window == b"\r\n\r\n")?;
        let body_start = header_end + 4;
        let headers = String::from_utf8_lossy(&buffer[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("content-length") {
                    value.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0);
        Some((body_start, content_length))
    }

    fn json_rpc_result(result: &Value) -> String {
        json!({ "jsonrpc": "2.0", "id": 1, "result": result }).to_string()
    }

    fn request_json(mock: &MockJsonRpc) -> Value {
        let body = mock
            .requests
            .recv_timeout(Duration::from_secs(2))
            .expect("receive request");
        serde_json::from_str(&body).expect("request json")
    }

    #[test]
    fn cache_snapshot_roundtrip_preserves_indexes_and_progress() {
        let path = temp_cache_path();
        let mut cache = PoiCache::new(identity());
        let valid_commitment = FixedBytes::from([0x22; 32]);
        let blocked_commitment = FixedBytes::from([0x33; 32]);
        let leaves = vec![U256::from_be_bytes(valid_commitment.0)];

        cache
            .apply_poi_events(&[event(0, valid_commitment)])
            .unwrap();
        cache.apply_poi_leaves(0, &leaves).unwrap();
        cache
            .apply_blocked_shields(&[blocked(blocked_commitment)])
            .unwrap();
        cache.write(&path).unwrap();

        let loaded = PoiCache::load(&path, &identity()).unwrap().unwrap();

        assert_eq!(loaded.progress().next_event_index, 1);
        assert_eq!(loaded.progress().next_leaf_index, 1);
        assert_eq!(loaded.leaf_count(), 1);
        assert_eq!(loaded.status(&valid_commitment), PoiStatus::Valid);
        assert_eq!(loaded.status(&blocked_commitment), PoiStatus::ShieldBlocked);
        assert_eq!(loaded.position(&valid_commitment).unwrap().global_index, 0);

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn cache_snapshot_requires_exact_messagepack_input_and_accepts_legacy_sequence_encoding() {
        let cache = PoiCache::new(identity());
        let named = cache.to_bytes().expect("encode named cache snapshot");
        let legacy_sequence =
            rmp_serde::to_vec(&cache.snapshot).expect("encode legacy sequence cache snapshot");

        PoiCache::from_bytes(&named, &identity()).expect("decode named cache snapshot");
        PoiCache::from_bytes(&legacy_sequence, &identity())
            .expect("decode legacy sequence cache snapshot");
        for suffix in [&[0xc0_u8][..], &[0xc1_u8][..]] {
            let mut tainted = named.clone();
            tainted.extend_from_slice(suffix);
            assert!(PoiCache::from_bytes(&tainted, &identity()).is_err());
        }
    }

    #[test]
    fn cache_derives_roots_at_historical_global_indexes() {
        let mut prefix = PoiCache::new(identity());
        prefix
            .apply_verified_artifact_events(&[SnapshotEvent {
                event_index: 0,
                blinded_commitment: [0x21; 32],
                signature: [0; 64],
                event_type: PoiEventType::Transact,
            }])
            .expect("apply prefix event");
        let prefix_root = prefix.current_roots().remove(&0).expect("prefix root");

        let mut extended = prefix;
        extended
            .apply_verified_artifact_events(&[SnapshotEvent {
                event_index: 1,
                blinded_commitment: [0x22; 32],
                signature: [0; 64],
                event_type: PoiEventType::Transact,
            }])
            .expect("apply extension event");
        let current_root = extended.current_roots().remove(&0).expect("extended root");

        assert_eq!(extended.root_at_global_index(0), Some(prefix_root));
        assert_eq!(extended.root_at_global_index(1), Some(current_root));
        assert_eq!(extended.root_at_global_index(TREE_LEAF_COUNT), None);
    }

    #[test]
    fn replacing_blocked_shields_removes_omitted_blocked_only_statuses() {
        let mut cache = PoiCache::new(identity());
        let removed = FixedBytes::from([0x22; 32]);
        let retained = FixedBytes::from([0x33; 32]);
        cache
            .apply_blocked_shields(&[blocked(removed), blocked(retained)])
            .expect("apply blocked shields");

        cache
            .replace_blocked_shields(&[blocked(retained)])
            .expect("replace blocked shields");

        assert_eq!(cache.status(&removed), PoiStatus::Missing);
        assert_eq!(cache.status(&retained), PoiStatus::ShieldBlocked);
    }

    #[test]
    fn proof_generation_fails_closed_until_roots_are_validated() {
        let mut cache = PoiCache::new(identity());
        let blinded_commitment = FixedBytes::from([0x22; 32]);
        let leaves = vec![U256::from_be_bytes(blinded_commitment.0)];
        cache.apply_poi_leaves(0, &leaves).unwrap();

        let missing_validation = cache
            .poi_merkle_proofs(&[blinded_commitment])
            .expect_err("root validation should be required");
        assert!(matches!(
            missing_validation,
            PoiCacheError::RootValidationRequired
        ));

        let roots = cache.current_roots();
        cache.snapshot.progress.root_validation = PoiCacheRootValidation::Validated { roots };
        let proofs = cache.poi_merkle_proofs(&[blinded_commitment]).unwrap();
        assert_eq!(proofs.len(), 1);
        assert_eq!(proofs[0].leaf, U256::from_be_bytes(blinded_commitment.0));
        assert_eq!(proofs[0].elements.len(), broadcaster_core::tree::TREE_DEPTH);
        assert_eq!(proofs[0].indices, U256::ZERO);

        let roots = cache.current_roots();
        cache.snapshot.progress.root_validation = PoiCacheRootValidation::Invalid { roots };
        let invalid_roots = cache
            .poi_merkle_proofs(&[blinded_commitment])
            .expect_err("rejected roots should fail closed");
        assert!(matches!(invalid_roots, PoiCacheError::InvalidRoots));
    }

    #[test]
    fn poi_leaf_error_after_possible_insertion_invalidates_validated_roots() {
        let mut cache = PoiCache::new(identity());
        cache
            .apply_poi_leaves(0, &[U256::from(1)])
            .expect("seed POI leaf");
        cache.accept_current_roots();
        assert!(cache.validated_roots().is_some());

        let error = cache
            .apply_poi_leaves(u64::MAX, &[U256::from(2)])
            .expect_err("overflowing POI leaf must fail");

        assert!(matches!(error, PoiCacheError::RangeOverflow));
        assert!(cache.validated_roots().is_none());
    }

    #[test]
    fn artifact_event_error_after_possible_insertion_invalidates_validated_roots() {
        let mut cache = PoiCache::new(identity());
        cache
            .apply_verified_artifact_events(&[SnapshotEvent {
                event_index: 0,
                blinded_commitment: [0x21; 32],
                signature: [0; 64],
                event_type: PoiEventType::Transact,
            }])
            .expect("seed artifact event");
        cache.accept_current_roots();
        assert!(cache.validated_roots().is_some());

        let error = cache
            .apply_verified_artifact_events(&[SnapshotEvent {
                event_index: u64::MAX,
                blinded_commitment: [0x22; 32],
                signature: [0; 64],
                event_type: PoiEventType::Transact,
            }])
            .expect_err("overflowing artifact event must fail");

        assert!(matches!(error, PoiCacheError::RangeOverflow));
        assert!(cache.validated_roots().is_none());
    }

    #[test]
    fn local_proofs_match_merkle_forest_for_representative_leaves() {
        let mut cache = PoiCache::new(identity());
        let commitments = [
            FixedBytes::from([0x22; 32]),
            FixedBytes::from([0x33; 32]),
            FixedBytes::from([0x44; 32]),
            FixedBytes::from([0x55; 32]),
        ];
        let leaves = commitments
            .iter()
            .copied()
            .map(|commitment| U256::from_be_bytes(commitment.0))
            .collect::<Vec<_>>();
        cache.apply_poi_leaves(0, &leaves).unwrap();
        let roots = cache.current_roots();
        cache.snapshot.progress.root_validation = PoiCacheRootValidation::Validated { roots };

        let mut expected_forest = MerkleForest::new();
        for (index, commitment) in commitments.iter().enumerate() {
            expected_forest
                .insert_leaf(MerkleTreeUpdate {
                    tree_number: 0,
                    tree_position: index as u64,
                    hash: U256::from_be_bytes(commitment.0),
                })
                .expect("insert expected leaf");
        }
        let expected = [
            commitments[0],
            commitments[1],
            commitments[2],
            commitments[3],
        ]
        .iter()
        .map(|commitment| {
            let position = cache.position(commitment).expect("position");
            let proof = expected_forest
                .prove(position.tree_number, position.tree_position)
                .expect("expected proof");
            poi_merkle_proof_from_cache(&proof)
        })
        .collect::<Vec<_>>();

        let actual = cache
            .poi_merkle_proofs(&[
                commitments[0],
                commitments[1],
                commitments[2],
                commitments[3],
            ])
            .unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn missing_local_proof_data_fails_closed() {
        let mut cache = PoiCache::new(identity());
        let present = FixedBytes::from([0x22; 32]);
        let missing = FixedBytes::from([0x33; 32]);
        cache
            .apply_poi_leaves(0, &[U256::from_be_bytes(present.0)])
            .unwrap();
        let roots = cache.current_roots();
        cache.snapshot.progress.root_validation = PoiCacheRootValidation::Validated { roots };

        let err = cache
            .poi_merkle_proofs(&[missing])
            .expect_err("missing proof data should fail closed");

        assert!(matches!(
            err,
            PoiCacheError::MissingCommitment {
                blinded_commitment
            } if blinded_commitment == missing
        ));
    }

    #[tokio::test]
    async fn sync_uses_paginated_bulk_methods_without_wallet_scoped_reads() {
        let commitment_0 = FixedBytes::from([0x22; 32]);
        let commitment_1 = FixedBytes::from([0x33; 32]);
        let mock = spawn_json_rpc(vec![
            json_rpc_result(&json!([event(0, commitment_0), event(1, commitment_1)])),
            json_rpc_result(&json!([])),
            json_rpc_result(&json!([
                hex::encode_prefixed(commitment_0),
                hex::encode_prefixed(commitment_1),
            ])),
            json_rpc_result(&json!([])),
        ]);
        let client = PoiRpcClient::new(mock.url.clone());
        let mut cache = PoiCache::new(identity());

        let outcome = cache.sync_with_page_sizes(&client, 2, 2).await.unwrap();

        assert_eq!(outcome.events, 2);
        assert_eq!(outcome.leaves, 2);
        assert_eq!(outcome.blocked_shields, 0);
        assert!(outcome.changed);
        assert_eq!(cache.status(&commitment_0), PoiStatus::Valid);
        assert_eq!(cache.status(&commitment_1), PoiStatus::Valid);

        let requests = [
            request_json(&mock),
            request_json(&mock),
            request_json(&mock),
            request_json(&mock),
        ];
        let methods = requests
            .iter()
            .map(|request| request["method"].as_str().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(
            methods,
            vec![
                "ppoi_poi_events",
                "ppoi_poi_events",
                "ppoi_poi_merkletree_leaves",
                "ppoi_blocked_shields",
            ]
        );
        assert!(!methods.contains(&"ppoi_pois_per_list"));
        assert!(!methods.contains(&"ppoi_merkle_proofs"));
        assert_eq!(requests[0]["params"]["startIndex"], 0);
        assert_eq!(requests[0]["params"]["endIndex"], 1);
        assert_eq!(requests[1]["params"]["startIndex"], 2);
        assert_eq!(requests[1]["params"]["endIndex"], 3);
        assert_eq!(requests[2]["params"]["startIndex"], 0);
        assert_eq!(requests[2]["params"]["endIndex"], 2);
        assert!(requests[3]["params"].get("bloomFilterSerialized").is_none());
        assert_eq!(requests[3]["params"]["startIndex"], 0);
        assert_eq!(requests[3]["params"]["endIndex"], 500);
    }

    #[tokio::test]
    async fn scoped_event_sync_skips_blocked_shield_snapshot() {
        let commitment = FixedBytes::from([0x42; 32]);
        let mock = spawn_json_rpc(vec![
            json_rpc_result(&json!([event(0, commitment)])),
            json_rpc_result(&json!([hex::encode_prefixed(commitment)])),
        ]);
        let (cache, result) = PoiCache::new(identity())
            .sync_events_bounded_with_journal(&PoiRpcClient::new(mock.url.clone()), 2, 2, 4)
            .await
            .expect("event-only sync");

        assert_eq!(result.outcome.events, 1);
        assert!(result.blocked_shields.is_none());
        assert_eq!(cache.progress().next_event_index, 1);
        assert_eq!(
            [request_json(&mock), request_json(&mock)]
                .iter()
                .map(|request| request["method"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["ppoi_poi_events", "ppoi_poi_merkletree_leaves"]
        );
    }

    #[tokio::test]
    async fn scoped_blocked_shield_sync_skips_events_and_leaves() {
        let mock = spawn_json_rpc(vec![json_rpc_result(&json!([]))]);
        let (cache, result) = PoiCache::new(identity())
            .sync_blocked_shields_with_journal(&PoiRpcClient::new(mock.url.clone()))
            .await
            .expect("blocked-shield-only sync");

        assert!(result.delta.is_empty());
        assert!(result.blocked_shields.is_some());
        assert!(cache.progress().blocked_shields_synced);
        let request = request_json(&mock);
        assert_eq!(request["method"], "ppoi_blocked_shields");
        assert!(mock.requests.try_recv().is_err());
    }

    #[tokio::test]
    async fn sync_collects_complete_paginated_blocked_shield_snapshot() {
        let valid_commitment = FixedBytes::from([0x22; 32]);
        let blocked_shields = (1_u64..=501)
            .map(|index| blocked(FixedBytes::from(U256::from(index).to_be_bytes::<32>())))
            .collect::<Vec<_>>();
        let target = FixedBytes::from(U256::from(501).to_be_bytes::<32>());
        let mock = spawn_json_rpc(vec![
            json_rpc_result(&json!([event(0, valid_commitment)])),
            json_rpc_result(&json!([hex::encode_prefixed(valid_commitment)])),
            json_rpc_result(&json!(&blocked_shields[..500])),
            json_rpc_result(&json!(&blocked_shields[500..])),
        ]);
        let mut cache = PoiCache::new(identity());

        let outcome = cache
            .sync_with_page_sizes(&PoiRpcClient::new(mock.url.clone()), 2, 2)
            .await
            .expect("sync paginated blocked Shield snapshot");

        assert_eq!(outcome.blocked_shields, 501);
        assert_eq!(cache.status(&valid_commitment), PoiStatus::Valid);
        assert_eq!(cache.status(&target), PoiStatus::ShieldBlocked);

        let requests = [
            request_json(&mock),
            request_json(&mock),
            request_json(&mock),
            request_json(&mock),
        ];
        assert_eq!(requests[2]["method"], "ppoi_blocked_shields");
        assert_eq!(requests[2]["params"]["startIndex"], 0);
        assert_eq!(requests[2]["params"]["endIndex"], 500);
        assert_eq!(requests[3]["method"], "ppoi_blocked_shields");
        assert_eq!(requests[3]["params"]["startIndex"], 500);
        assert_eq!(requests[3]["params"]["endIndex"], 1000);
    }

    #[tokio::test]
    async fn captured_journal_delta_replays_to_the_public_rpc_candidate() {
        let commitment_0 = FixedBytes::from([0x24; 32]);
        let commitment_1 = FixedBytes::from([0x35; 32]);
        let mock = spawn_json_rpc(vec![
            json_rpc_result(&json!([event(0, commitment_0), event(1, commitment_1)])),
            json_rpc_result(&json!([])),
            json_rpc_result(&json!([
                hex::encode_prefixed(commitment_0),
                hex::encode_prefixed(commitment_1),
            ])),
            json_rpc_result(&json!([])),
        ]);
        let base = PoiCache::new(identity());

        let (mut candidate, result) = base
            .clone()
            .sync_bounded_with_journal(&PoiRpcClient::new(mock.url), 2, 2, usize::MAX)
            .await
            .expect("sync candidate with journal capture");
        let encoded = result.delta.to_bytes().expect("encode journal delta");
        let decoded = PoiCacheJournalDelta::from_bytes(&encoded).expect("decode journal delta");
        assert_eq!(decoded, result.delta);
        assert_eq!(
            PoiCacheJournalDelta::from_bytes_bounded(&encoded, 2, 2)
                .expect("decode bounded journal delta"),
            result.delta
        );
        assert!(PoiCacheJournalDelta::from_bytes_bounded(&encoded, 1, 2).is_err());
        assert!(PoiCacheJournalDelta::from_bytes_bounded(&encoded, 2, 1).is_err());
        for suffix in [&[0xc0_u8][..], &[0xc1_u8][..]] {
            let mut tainted = encoded.clone();
            tainted.extend_from_slice(suffix);
            assert!(PoiCacheJournalDelta::from_bytes(&tainted).is_err());
            assert!(PoiCacheJournalDelta::from_bytes_bounded(&tainted, 2, 2).is_err());
        }
        assert_eq!(decoded.events.len(), 2);
        assert_eq!(decoded.leaves.len(), 2);
        assert_eq!(result.blocked_shields, Some(Vec::new()));

        let mut replayed = base;
        replayed
            .apply_journal_delta(&decoded)
            .expect("replay captured delta");
        replayed
            .replace_blocked_shields(
                result
                    .blocked_shields
                    .as_deref()
                    .expect("captured blocked snapshot"),
            )
            .expect("replay blocked snapshot");
        replayed.accept_current_roots();
        candidate.accept_current_roots();

        assert_eq!(
            replayed.to_bytes().expect("serialize replayed cache"),
            candidate.to_bytes().expect("serialize direct candidate")
        );
        assert_eq!(replayed.status(&commitment_0), PoiStatus::Valid);
        assert_eq!(
            replayed
                .position(&commitment_1)
                .expect("replayed commitment position")
                .global_index,
            1
        );
    }

    #[test]
    fn incremental_journal_replay_matches_each_committed_root_with_zero_leaf() {
        let identity = identity();
        let base = PoiCache::new(identity.clone());
        let mut direct = base.clone();
        let mut replay = base.into_journal_replay();

        for event_index in 0..4 {
            let commitment = if event_index == 1 {
                FixedBytes::ZERO
            } else {
                FixedBytes::from([0x60 + event_index as u8; 32])
            };
            let delta = PoiCacheJournalDelta {
                version: POI_CACHE_JOURNAL_DELTA_VERSION,
                identity: identity.clone(),
                event_start_cursor: event_index,
                event_end_cursor: event_index + 1,
                leaf_start_cursor: event_index,
                leaf_end_cursor: event_index + 1,
                events: vec![PoiCacheJournalEvent {
                    event_index,
                    blinded_commitment: commitment,
                }],
                leaves: vec![commitment],
            };
            direct
                .apply_journal_delta(&delta)
                .expect("apply direct journal delta");
            let expected_root = direct
                .current_roots()
                .get(&0)
                .copied()
                .expect("direct replay root");
            assert_eq!(
                replay
                    .apply_delta(&delta)
                    .expect("apply incremental journal delta"),
                expected_root
            );
        }

        direct.accept_current_roots();
        let replayed = replay.finish();
        assert_eq!(
            replayed.to_bytes().expect("serialize incremental replay"),
            direct.to_bytes().expect("serialize direct replay")
        );
    }

    #[test]
    fn journal_delta_rejects_cursor_and_leaf_conflicts_before_mutation() {
        let commitment = FixedBytes::from([0x46; 32]);
        let base = PoiCache::new(identity());
        let delta = PoiCacheJournalDelta {
            version: POI_CACHE_JOURNAL_DELTA_VERSION,
            identity: identity(),
            event_start_cursor: 0,
            event_end_cursor: 1,
            leaf_start_cursor: 0,
            leaf_end_cursor: 1,
            events: vec![PoiCacheJournalEvent {
                event_index: 0,
                blinded_commitment: commitment,
            }],
            leaves: vec![FixedBytes::from([0x47; 32])],
        };
        let mut mismatched_leaf = base.clone();
        assert!(matches!(
            mismatched_leaf.apply_journal_delta(&delta),
            Err(PoiCacheError::EventLeafMismatch { index: 0 })
        ));
        assert_eq!(mismatched_leaf.progress().next_event_index, 0);
        assert_eq!(mismatched_leaf.progress().next_leaf_index, 0);

        let mut wrong_cursor = base;
        let mut delta = delta;
        delta.leaves[0] = commitment;
        delta.event_start_cursor = 1;
        assert!(matches!(
            wrong_cursor.apply_journal_delta(&delta),
            Err(PoiCacheError::JournalDeltaCursorMismatch { .. })
        ));
        assert_eq!(wrong_cursor.progress().next_event_index, 0);
        assert_eq!(wrong_cursor.progress().next_leaf_index, 0);
    }

    #[tokio::test]
    async fn empty_public_range_sync_reports_no_corpus_change() {
        let mock = spawn_json_rpc(vec![
            json_rpc_result(&json!([])),
            json_rpc_result(&json!([])),
        ]);
        let client = PoiRpcClient::new(mock.url);
        let mut cache = PoiCache::new(identity());

        let outcome = cache.sync_with_page_sizes(&client, 2, 2).await.unwrap();

        assert!(!outcome.changed);
        assert_eq!(outcome.events, 0);
        assert_eq!(outcome.leaves, 0);
        assert_eq!(outcome.blocked_shields, 0);
    }

    #[tokio::test]
    async fn public_range_sync_rejects_mismatched_cursors_before_requesting() {
        let commitment = FixedBytes::from([0x65; 32]);
        let mock = spawn_json_rpc(vec![]);
        let mut cache = PoiCache::new(identity());
        cache.apply_poi_events(&[event(0, commitment)]).unwrap();

        let error = cache
            .sync_with_page_sizes(&PoiRpcClient::new(mock.url), 2, 2)
            .await
            .expect_err("mismatched cursors must fail");

        assert!(matches!(
            error,
            PoiCacheError::SyncCursorMismatch {
                next_event_index: 1,
                next_leaf_index: 0
            }
        ));
        assert_eq!(cache.progress().next_leaf_index, 0);
    }

    #[tokio::test]
    async fn public_range_sync_rejects_invalid_event_signature() {
        let commitment = FixedBytes::from([0x66; 32]);
        let mut invalid = event(0, commitment);
        invalid.signed_poi_event.event_type = PoiEventType::Transact;
        invalid.signed_poi_event.signature = "00".repeat(64);
        let mock = spawn_json_rpc(vec![json_rpc_result(&json!([invalid]))]);
        let mut cache = PoiCache::new(identity());

        let error = cache
            .sync_with_page_sizes(&PoiRpcClient::new(mock.url), 2, 2)
            .await
            .expect_err("invalid list signature must fail");

        assert!(matches!(error, PoiCacheError::Verify(_)));
    }

    #[tokio::test]
    async fn public_range_sync_rejects_non_contiguous_event_index() {
        let mock = spawn_json_rpc(vec![json_rpc_result(&json!([event(
            1,
            FixedBytes::from([0x67; 32])
        )]))]);
        let mut cache = PoiCache::new(identity());

        let error = cache
            .sync_with_page_sizes(&PoiRpcClient::new(mock.url), 2, 2)
            .await
            .expect_err("non-contiguous range must fail");

        assert!(matches!(
            error,
            PoiCacheError::NonContiguousEvent {
                expected: 0,
                actual: 1
            }
        ));
    }

    #[tokio::test]
    async fn public_range_sync_rejects_event_response_larger_than_requested_page() {
        let mock = spawn_json_rpc(vec![json_rpc_result(&json!([
            event(0, FixedBytes::from([0x67; 32])),
            event(1, FixedBytes::from([0x68; 32])),
        ]))]);
        let mut cache = PoiCache::new(identity());

        let error = cache
            .sync_with_page_sizes(&PoiRpcClient::new(mock.url), 1, 2)
            .await
            .expect_err("oversized event page must fail");

        assert!(matches!(
            error,
            PoiCacheError::EventPageTooLarge {
                start_index: 0,
                end_index: 0,
                requested: 1,
                actual: 2
            }
        ));
        assert_eq!(cache.progress().next_event_index, 0);
        assert_eq!(cache.progress().next_leaf_index, 0);
    }

    #[tokio::test]
    async fn public_range_sync_rejects_event_leaf_mismatch() {
        let event_commitment = FixedBytes::from([0x68; 32]);
        let leaf_commitment = FixedBytes::from([0x69; 32]);
        let mock = spawn_json_rpc(vec![
            json_rpc_result(&json!([event(0, event_commitment)])),
            json_rpc_result(&json!([hex::encode_prefixed(leaf_commitment)])),
        ]);
        let mut cache = PoiCache::new(identity());

        let error = cache
            .sync_with_page_sizes(&PoiRpcClient::new(mock.url), 2, 2)
            .await
            .expect_err("event/leaf mismatch must fail");

        assert!(matches!(
            error,
            PoiCacheError::EventLeafMismatch { index: 0 }
        ));
        assert_eq!(cache.progress().next_event_index, 0);
        assert_eq!(cache.progress().next_leaf_index, 0);
        assert_eq!(cache.leaf_count(), 0);
    }

    #[tokio::test]
    async fn public_range_sync_rejects_short_leaf_response_without_advancing_leaf_state() {
        let commitment = FixedBytes::from([0x6a; 32]);
        let mock = spawn_json_rpc(vec![
            json_rpc_result(&json!([event(0, commitment)])),
            json_rpc_result(&json!([])),
        ]);
        let mut cache = PoiCache::new(identity());

        let error = cache
            .sync_with_page_sizes(&PoiRpcClient::new(mock.url), 2, 2)
            .await
            .expect_err("short leaf page must fail");

        assert!(matches!(
            error,
            PoiCacheError::LeafPageSizeMismatch {
                start_index: 0,
                end_index: 1,
                expected: 1,
                actual: 0
            }
        ));
        assert_eq!(cache.progress().next_event_index, 0);
        assert_eq!(cache.progress().next_leaf_index, 0);
        assert_eq!(cache.leaf_count(), 0);
    }

    #[tokio::test]
    async fn public_range_sync_rejects_extra_leaf_response_without_advancing_leaf_state() {
        let commitment = FixedBytes::from([0x6b; 32]);
        let extra = FixedBytes::from([0x6c; 32]);
        let mock = spawn_json_rpc(vec![
            json_rpc_result(&json!([event(0, commitment)])),
            json_rpc_result(&json!([
                hex::encode_prefixed(commitment),
                hex::encode_prefixed(extra),
            ])),
        ]);
        let mut cache = PoiCache::new(identity());

        let error = cache
            .sync_with_page_sizes(&PoiRpcClient::new(mock.url), 2, 2)
            .await
            .expect_err("extra leaf page must fail");

        assert!(matches!(
            error,
            PoiCacheError::LeafPageSizeMismatch {
                start_index: 0,
                end_index: 1,
                expected: 1,
                actual: 2
            }
        ));
        assert_eq!(cache.progress().next_event_index, 0);
        assert_eq!(cache.progress().next_leaf_index, 0);
        assert_eq!(cache.leaf_count(), 0);
    }

    #[tokio::test]
    async fn public_range_sync_rejects_invalid_blocked_shield_signature() {
        let commitment = FixedBytes::from([0x70; 32]);
        let mut invalid_blocked = blocked(FixedBytes::from([0x71; 32]));
        invalid_blocked.signature = "00".repeat(64);
        let mock = spawn_json_rpc(vec![
            json_rpc_result(&json!([event(0, commitment)])),
            json_rpc_result(&json!([hex::encode_prefixed(commitment)])),
            json_rpc_result(&json!([invalid_blocked])),
        ]);
        let mut cache = PoiCache::new(identity());

        let error = cache
            .sync_with_page_sizes(&PoiRpcClient::new(mock.url), 2, 2)
            .await
            .expect_err("invalid blocked-shield signature must fail");

        assert!(matches!(error, PoiCacheError::Verify(_)));
    }

    #[tokio::test]
    async fn bounded_public_range_sync_reports_large_backlog() {
        let commitment = FixedBytes::from([0x72; 32]);
        let mock = spawn_json_rpc(vec![
            json_rpc_result(&json!([event(0, commitment)])),
            json_rpc_result(&json!([hex::encode_prefixed(commitment)])),
            json_rpc_result(&json!([])),
        ]);
        let mut cache = PoiCache::new(identity());

        let outcome = cache
            .sync_bounded(&PoiRpcClient::new(mock.url), 1, 1, 1)
            .await
            .expect("bounded public range sync");

        assert!(outcome.event_page_budget_exhausted);
        assert_eq!(outcome.events, 1);
        assert_eq!(outcome.leaves, 1);
    }

    #[tokio::test]
    async fn public_range_request_timeout_bounds_stalled_endpoint() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stalled POI RPC");
        let url = reqwest::Url::parse(&format!(
            "http://{}",
            listener.local_addr().expect("stalled RPC address")
        ))
        .expect("stalled RPC URL");
        std::thread::spawn(move || {
            let (_stream, _) = listener.accept().expect("accept stalled request");
            std::thread::sleep(Duration::from_secs(1));
        });
        let client = PoiRpcClient::new(url).with_request_timeout(Duration::from_millis(50));
        let mut cache = PoiCache::new(identity());

        let error = cache
            .sync(&client)
            .await
            .expect_err("stalled RPC times out");

        assert!(matches!(
            error,
            PoiCacheError::Rpc(PoiRpcError::Post { source, .. }) if source.is_timeout()
        ));
    }
}
