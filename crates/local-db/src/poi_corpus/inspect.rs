use alloy::primitives::{FixedBytes, keccak256};
use redb::{ReadOnlyTable, ReadableDatabase};

use super::{
    JournalKeys, decode_valid_journal_head, poi_corpus_journal_replacement_token,
    poi_journal_blocked_identity_matches, poi_journal_delta_identity_matches,
};
use crate::{
    DbError, DbStore, POI_ARTIFACT_CACHE_TABLE, POI_CORPUS_JOURNAL_FORMAT_VERSION,
    POI_CORPUS_JOURNAL_MAX_DELTA_COUNT, POI_CORPUS_JOURNAL_TABLE, PoiArtifactCacheRecord,
    PoiCorpusBlockedSnapshotRecord, PoiCorpusJournalBundle, PoiCorpusJournalDeltaRecord,
    PoiCorpusJournalHeadRecord, PoiCorpusJournalInspection, StoredRecord, decode,
    decode_poi_corpus_blocked_snapshot_bounded, decode_poi_corpus_journal_delta_bounded,
    prefix_range_end, table_prefix_has_rows,
};

type ReadTable = ReadOnlyTable<&'static str, &'static [u8]>;

impl DbStore {
    pub fn inspect_poi_corpus_journal(
        &self,
        chain_type: u8,
        chain_id: u64,
        txid_version: &str,
        list_key: &FixedBytes<32>,
    ) -> Result<StoredRecord<PoiCorpusJournalBundle>, DbError> {
        match self.inspect_poi_corpus_journal_detailed(
            chain_type,
            chain_id,
            txid_version,
            list_key,
        )? {
            PoiCorpusJournalInspection::Missing => Ok(StoredRecord::Missing),
            PoiCorpusJournalInspection::Valid { bundle, .. } => Ok(StoredRecord::Valid(*bundle)),
            PoiCorpusJournalInspection::Corrupt { key, .. } => Ok(StoredRecord::Corrupt { key }),
        }
    }

    pub fn inspect_poi_corpus_journal_head(
        &self,
        chain_type: u8,
        chain_id: u64,
        txid_version: &str,
        list_key: &FixedBytes<32>,
    ) -> Result<StoredRecord<PoiCorpusJournalHeadRecord>, DbError> {
        let head_key =
            PoiCorpusJournalHeadRecord::key_for(chain_type, chain_id, txid_version, list_key);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(POI_CORPUS_JOURNAL_TABLE)?;
        let Some(value) = table.get(head_key.as_str())? else {
            return Ok(StoredRecord::Missing);
        };
        match decode_valid_journal_head(value.value(), &head_key)? {
            Some(head) => Ok(StoredRecord::Valid(head)),
            None => Ok(StoredRecord::Corrupt { key: head_key }),
        }
    }

    pub fn inspect_poi_corpus_journal_detailed(
        &self,
        chain_type: u8,
        chain_id: u64,
        txid_version: &str,
        list_key: &FixedBytes<32>,
    ) -> Result<PoiCorpusJournalInspection, DbError> {
        let keys = JournalKeys::for_identity(chain_type, chain_id, txid_version, list_key);
        let blocked_key =
            PoiCorpusBlockedSnapshotRecord::key_for(chain_type, chain_id, txid_version, list_key);
        let txn = self.db.begin_read()?;
        let base_table = txn.open_table(POI_ARTIFACT_CACHE_TABLE)?;
        let journal_table = txn.open_table(POI_CORPUS_JOURNAL_TABLE)?;
        let replacement_token =
            poi_corpus_journal_replacement_token(&base_table, &journal_table, &keys)?;
        match inspect_journal_rows(&base_table, &journal_table, &keys, &blocked_key) {
            Ok(None) => Ok(PoiCorpusJournalInspection::Missing),
            Ok(Some(bundle)) => Ok(PoiCorpusJournalInspection::Valid {
                bundle: Box::new(bundle),
                replacement_token,
            }),
            Err(InspectFailure::Corrupt(key)) => Ok(PoiCorpusJournalInspection::Corrupt {
                key,
                replacement_token,
            }),
            Err(InspectFailure::Db(error)) => Err(error),
        }
    }
}

/// Why an inspection stopped: a corrupt row, named by its key, or a
/// database error.
enum InspectFailure {
    Corrupt(String),
    Db(DbError),
}

impl From<DbError> for InspectFailure {
    fn from(error: DbError) -> Self {
        Self::Db(error)
    }
}

impl From<redb::StorageError> for InspectFailure {
    fn from(error: redb::StorageError) -> Self {
        Self::Db(error.into())
    }
}

/// Reads and cross-checks every stored row of one journal identity.
/// Returns `None` when neither a base nor any journal row exists.
fn inspect_journal_rows(
    base_table: &ReadTable,
    journal_table: &ReadTable,
    keys: &JournalKeys,
    blocked_key: &str,
) -> Result<Option<PoiCorpusJournalBundle>, InspectFailure> {
    let base = read_journal_base(base_table, &keys.base)?;
    let head = read_journal_head(journal_table, &keys.head, base.as_ref())?;
    let Some(base) = base else {
        require_no_journal_rows(journal_table, &keys.identity_prefix)?;
        return Ok(None);
    };
    let Some(head) = head else {
        require_no_journal_rows(journal_table, &keys.identity_prefix)?;
        return Ok(Some(PoiCorpusJournalBundle {
            base,
            head: None,
            deltas: Vec::new(),
            blocked: None,
        }));
    };
    let deltas = read_journal_deltas(journal_table, keys, &base, &head)?;
    let blocked = read_blocked_snapshot(journal_table, blocked_key, &keys.head, &head)?;
    Ok(Some(PoiCorpusJournalBundle {
        base,
        head: Some(head),
        deltas,
        blocked,
    }))
}

fn read_journal_base(
    table: &ReadTable,
    base_key: &str,
) -> Result<Option<PoiArtifactCacheRecord>, InspectFailure> {
    let Some(value) = table.get(base_key)? else {
        return Ok(None);
    };
    match decode::<PoiArtifactCacheRecord>(value.value()) {
        Ok(record) if record.key() == base_key => Ok(Some(record)),
        Ok(_) | Err(DbError::Decode(_)) => Err(InspectFailure::Corrupt(base_key.to_owned())),
        Err(error) => Err(error.into()),
    }
}

fn read_journal_head(
    table: &ReadTable,
    head_key: &str,
    base: Option<&PoiArtifactCacheRecord>,
) -> Result<Option<PoiCorpusJournalHeadRecord>, InspectFailure> {
    let Some(value) = table.get(head_key)? else {
        return Ok(None);
    };
    match decode_valid_journal_head(value.value(), head_key)? {
        Some(head) if head_matches_base(&head, base) => Ok(Some(head)),
        _ => Err(InspectFailure::Corrupt(head_key.to_owned())),
    }
}

/// Whether `head` was journaled on top of the stored base row.
fn head_matches_base(
    head: &PoiCorpusJournalHeadRecord,
    base: Option<&PoiArtifactCacheRecord>,
) -> bool {
    base.is_some_and(|base| {
        base.cache_generation == head.corpus.cache_generation
            && keccak256(&base.cache_payload) == head.base_payload_hash
    })
}

/// Journal rows without a valid base and head are orphans, so the identity
/// prefix is reported as corrupt.
fn require_no_journal_rows(table: &ReadTable, identity_prefix: &str) -> Result<(), InspectFailure> {
    if table_prefix_has_rows(table, identity_prefix)? {
        return Err(InspectFailure::Corrupt(identity_prefix.to_owned()));
    }
    Ok(())
}

fn read_journal_deltas(
    table: &ReadTable,
    keys: &JournalKeys,
    base: &PoiArtifactCacheRecord,
    head: &PoiCorpusJournalHeadRecord,
) -> Result<Vec<PoiCorpusJournalDeltaRecord>, InspectFailure> {
    let mut chain = DeltaChain::new(base, head);
    let delta_range_end = prefix_range_end(&keys.delta_prefix);
    let mut range = match delta_range_end.as_deref() {
        Some(end) => table.range(keys.delta_prefix.as_str()..end)?,
        None => table.range(keys.delta_prefix.as_str()..)?,
    };
    for entry in &mut range {
        let (key, value) = entry?;
        let key = key.value().to_string();
        let Some(delta) = chain.decode_next(value.value())? else {
            return Err(InspectFailure::Corrupt(key));
        };
        if !chain.try_push(&key, delta) {
            return Err(InspectFailure::Corrupt(key));
        }
    }
    drop(range);
    if !chain.completes_head() {
        return Err(InspectFailure::Corrupt(keys.head.clone()));
    }
    Ok(chain.deltas)
}

/// Delta rows of one journal head, walked in key order. Each row must
/// continue where the previous one ended, and the rows after the head's
/// blocked snapshot (or base) must cover every revision up to the head.
struct DeltaChain<'a> {
    head: &'a PoiCorpusJournalHeadRecord,
    deltas: Vec<PoiCorpusJournalDeltaRecord>,
    delta_payload_bytes: u64,
    previous_revision: Option<u64>,
    event_cursor: u64,
    /// Unknown until the first delta, since the base row does not record it.
    leaf_cursor: Option<u64>,
    tip_root: FixedBytes<32>,
    coverage_after_revision: u64,
    last_required_revision: Option<u64>,
}

impl<'a> DeltaChain<'a> {
    fn new(base: &PoiArtifactCacheRecord, head: &'a PoiCorpusJournalHeadRecord) -> Self {
        Self {
            head,
            deltas: Vec::new(),
            delta_payload_bytes: 0,
            previous_revision: None,
            event_cursor: base.current_tip_index.saturating_add(1),
            leaf_cursor: None,
            tip_root: base.current_tip_root,
            coverage_after_revision: head.blocked_revision.unwrap_or(head.base_revision),
            last_required_revision: None,
        }
    }

    /// Decodes the next delta row within the head's remaining count and byte
    /// budget. `None` means the row is corrupt.
    fn decode_next(&self, data: &[u8]) -> Result<Option<PoiCorpusJournalDeltaRecord>, DbError> {
        if self.deltas.len() >= self.head.delta_count as usize
            || self.deltas.len() >= POI_CORPUS_JOURNAL_MAX_DELTA_COUNT as usize
        {
            return Ok(None);
        }
        let Some(remaining_payload_bytes) = self
            .head
            .delta_payload_bytes
            .checked_sub(self.delta_payload_bytes)
        else {
            return Ok(None);
        };
        match decode_poi_corpus_journal_delta_bounded(data, remaining_payload_bytes) {
            Ok(delta) => Ok(delta),
            Err(DbError::Decode(_)) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Appends `delta`, stored under `key`, when it is valid for the head and
    /// continues the chain. Returns false otherwise, after which the chain
    /// must be discarded.
    fn try_push(&mut self, key: &str, delta: PoiCorpusJournalDeltaRecord) -> bool {
        if delta.key() != key || !valid_poi_corpus_journal_delta(&delta, self.head) {
            return false;
        }
        if !self.continues_with(&delta) || !self.record_required_coverage(delta.revision) {
            return false;
        }
        let Some(payload_bytes) = self
            .delta_payload_bytes
            .checked_add(u64::try_from(delta.payload.len()).unwrap_or(u64::MAX))
        else {
            return false;
        };
        self.delta_payload_bytes = payload_bytes;
        self.previous_revision = Some(delta.revision);
        self.event_cursor = delta.event_end_cursor;
        self.leaf_cursor = Some(delta.leaf_end_cursor);
        self.tip_root = delta.end_tip_root;
        self.deltas.push(delta);
        true
    }

    /// Whether `delta` follows the previous row in revision order and starts
    /// where it ended.
    fn continues_with(&self, delta: &PoiCorpusJournalDeltaRecord) -> bool {
        self.previous_revision
            .is_none_or(|previous| delta.revision > previous)
            && delta.event_start_cursor == self.event_cursor
            && self
                .leaf_cursor
                .is_none_or(|cursor| delta.leaf_start_cursor == cursor)
            && delta.start_tip_root == self.tip_root
    }

    /// Records `revision` as the next required delta when it lies after the
    /// coverage boundary. Returns false when it skips a required revision.
    fn record_required_coverage(&mut self, revision: u64) -> bool {
        if revision <= self.coverage_after_revision {
            return true;
        }
        let expected_revision = self.last_required_revision.map_or_else(
            || self.coverage_after_revision.checked_add(1),
            |previous| previous.checked_add(1),
        );
        if expected_revision != Some(revision) {
            return false;
        }
        self.last_required_revision = Some(revision);
        true
    }

    /// Whether the walked rows account for every delta, byte and cursor the
    /// head records.
    fn completes_head(&self) -> bool {
        let head = self.head;
        let required_suffix_complete = head.revision == self.coverage_after_revision
            || self.last_required_revision == Some(head.revision);
        required_suffix_complete
            && self.deltas.len() == head.delta_count as usize
            && self.delta_payload_bytes == head.delta_payload_bytes
            && self.event_cursor == head.event_cursor
            && self
                .leaf_cursor
                .is_none_or(|cursor| cursor == head.leaf_cursor)
            && self.tip_root == head.corpus.current_tip_root
    }
}

fn read_blocked_snapshot(
    table: &ReadTable,
    blocked_key: &str,
    head_key: &str,
    head: &PoiCorpusJournalHeadRecord,
) -> Result<Option<PoiCorpusBlockedSnapshotRecord>, InspectFailure> {
    let corrupt_blocked = || InspectFailure::Corrupt(blocked_key.to_owned());
    match (head.blocked_revision, head.blocked_payload_hash) {
        (Some(_), Some(_)) => {
            let Some(value) = table.get(blocked_key)? else {
                return Err(corrupt_blocked());
            };
            match decode_poi_corpus_blocked_snapshot_bounded(value.value()) {
                Ok(Some(blocked)) if blocked_snapshot_matches_head(&blocked, blocked_key, head) => {
                    Ok(Some(blocked))
                }
                Ok(_) | Err(DbError::Decode(_)) => Err(corrupt_blocked()),
                Err(error) => Err(error.into()),
            }
        }
        (None, None) => {
            if table.get(blocked_key)?.is_some() {
                return Err(corrupt_blocked());
            }
            Ok(None)
        }
        _ => Err(InspectFailure::Corrupt(head_key.to_owned())),
    }
}

/// Whether `blocked` is the snapshot the head points at.
fn blocked_snapshot_matches_head(
    blocked: &PoiCorpusBlockedSnapshotRecord,
    blocked_key: &str,
    head: &PoiCorpusJournalHeadRecord,
) -> bool {
    blocked.key() == blocked_key
        && valid_poi_corpus_blocked_snapshot(blocked, head)
        && head.blocked_revision == Some(blocked.revision)
        && head.blocked_payload_hash == Some(blocked.payload_hash)
}

fn valid_poi_corpus_journal_delta(
    delta: &PoiCorpusJournalDeltaRecord,
    head: &PoiCorpusJournalHeadRecord,
) -> bool {
    delta.format_version == POI_CORPUS_JOURNAL_FORMAT_VERSION
        && poi_journal_delta_identity_matches(delta, &head.corpus)
        && delta.cache_generation == head.corpus.cache_generation
        && delta.base_revision == head.base_revision
        && delta.revision > head.base_revision
        && delta.revision <= head.revision
        && delta.previous_revision.checked_add(1) == Some(delta.revision)
        && delta.event_start_cursor <= delta.event_end_cursor
        && delta.leaf_start_cursor <= delta.leaf_end_cursor
}

fn valid_poi_corpus_blocked_snapshot(
    blocked: &PoiCorpusBlockedSnapshotRecord,
    head: &PoiCorpusJournalHeadRecord,
) -> bool {
    blocked.format_version == POI_CORPUS_JOURNAL_FORMAT_VERSION
        && poi_journal_blocked_identity_matches(blocked, &head.corpus)
        && blocked.cache_generation == head.corpus.cache_generation
        && blocked.revision > head.base_revision
        && blocked.revision <= head.revision
        && blocked.payload_hash == keccak256(&blocked.payload)
}
