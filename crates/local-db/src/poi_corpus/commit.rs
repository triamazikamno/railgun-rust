use alloy::primitives::{FixedBytes, keccak256};
use redb::{ReadableTable, WriteTransaction};

use super::{
    JournalKeys, decode_valid_journal_head, poi_corpus_journal_replacement_token,
    poi_journal_blocked_identity_matches, poi_journal_delta_identity_matches,
};
use crate::{
    DbError, DbStore, ExpectedPoiCorpusJournalState, POI_ARTIFACT_CACHE_TABLE,
    POI_CORPUS_JOURNAL_FORMAT_VERSION, POI_CORPUS_JOURNAL_MAX_BLOCKED_PAYLOAD_BYTES,
    POI_CORPUS_JOURNAL_MAX_DELTA_COUNT, POI_CORPUS_JOURNAL_MAX_PAYLOAD_BYTES,
    POI_CORPUS_JOURNAL_SOFT_DELTA_COUNT, POI_CORPUS_JOURNAL_SOFT_PAYLOAD_BYTES,
    POI_CORPUS_JOURNAL_TABLE, PoiArtifactCacheRecord, PoiCorpusBlockedSnapshotRecord,
    PoiCorpusJournalCommit, PoiCorpusJournalCommitCondition, PoiCorpusJournalCommitOutcome,
    PoiCorpusJournalCorruptionToken, PoiCorpusJournalDeltaRecord, PoiCorpusJournalHeadRecord,
    decode, encode, now_epoch_secs, poi_commit_context_conflict, remove_table_prefix,
    table_prefix_has_rows,
};

impl DbStore {
    pub fn append_poi_corpus_journal_if_current(
        &self,
        mut head: PoiCorpusJournalHeadRecord,
        mut delta: Option<PoiCorpusJournalDeltaRecord>,
        mut blocked: Option<PoiCorpusBlockedSnapshotRecord>,
        condition: PoiCorpusJournalCommitCondition,
    ) -> Result<PoiCorpusJournalCommitOutcome, DbError> {
        let key = head.corpus.key();
        let head_key = head.key();
        if !head.corpus.cache_payload.is_empty() {
            return Err(invalid_journal_head(&head_key));
        }
        if matches!(
            condition.expected_state,
            ExpectedPoiCorpusJournalState::Corrupt { .. }
        ) {
            return Ok(PoiCorpusJournalCommitOutcome::CorpusConflict);
        }
        let txn = self.db.begin_write()?;
        let observed = match admit_journal_write(&txn, &key, &head_key, condition)? {
            JournalAdmission::Observed(observed) => observed,
            JournalAdmission::Rejected(outcome) => return Ok(outcome),
        };
        if matches!(
            condition.expected_state,
            ExpectedPoiCorpusJournalState::NoValidBase
        ) {
            return Ok(PoiCorpusJournalCommitOutcome::CorpusConflict);
        }

        let stamp = JournalStamp::new(observed, condition.expected_generation)?;
        stamp.stamp_head(&mut head);
        let Some((delta_count, delta_payload_bytes)) = stamp.next_totals(delta.as_ref())? else {
            return Ok(PoiCorpusJournalCommitOutcome::CompactionRequired);
        };
        head.delta_count = delta_count;
        head.delta_payload_bytes = delta_payload_bytes;
        match delta.as_mut() {
            Some(delta) => stamp.stamp_delta(delta, &head)?,
            None => stamp.check_head_unmoved(&head, &head_key)?,
        }
        check_head_tip_index(&head, &head_key)?;
        stamp.stamp_blocked(blocked.as_mut(), &mut head)?;

        if let Some(conflict) = write_journal_append(&txn, &head, delta.as_ref(), blocked.as_ref())?
        {
            return Ok(conflict);
        }
        txn.commit()?;
        Ok(applied_append(head, delta, blocked))
    }

    pub fn rebase_poi_corpus_journal_if_current(
        &self,
        mut base: PoiArtifactCacheRecord,
        event_cursor: u64,
        leaf_cursor: u64,
        condition: PoiCorpusJournalCommitCondition,
    ) -> Result<PoiCorpusJournalCommitOutcome, DbError> {
        let key = base.key();
        let head_key = PoiCorpusJournalHeadRecord::key_for(
            base.chain_type,
            base.chain_id,
            &base.txid_version,
            &base.list_key,
        );
        if event_cursor == 0 || base.current_tip_index != event_cursor.saturating_sub(1) {
            return Err(DbError::InvalidPpoiCorpusRecord { key });
        }
        let txn = self.db.begin_write()?;
        let observed = match admit_journal_write(&txn, &key, &head_key, condition)? {
            JournalAdmission::Observed(observed) => observed,
            JournalAdmission::Rejected(outcome) => return Ok(outcome),
        };
        let stamp = JournalStamp::new(observed, condition.expected_generation)?;
        base.cache_generation = stamp.generation;
        base.updated_at = stamp.now;
        let head = fresh_journal_head(&base, stamp.revision, event_cursor, leaf_cursor);
        let base_data = encode(&base)?;
        let head_data = encode(&head)?;
        let identity_prefix = PoiCorpusJournalHeadRecord::identity_prefix_for(
            base.chain_type,
            base.chain_id,
            &base.txid_version,
            &base.list_key,
        );
        {
            let mut base_table = txn.open_table(POI_ARTIFACT_CACHE_TABLE)?;
            base_table.insert(key.as_str(), base_data.as_slice())?;
        }
        {
            let mut journal_table = txn.open_table(POI_CORPUS_JOURNAL_TABLE)?;
            remove_table_prefix(&mut journal_table, &identity_prefix)?;
            journal_table.insert(head_key.as_str(), head_data.as_slice())?;
        }
        txn.commit()?;
        Ok(PoiCorpusJournalCommitOutcome::Applied(Box::new(
            PoiCorpusJournalCommit {
                head,
                delta: None,
                blocked: None,
                base: Some(Box::new(base)),
                retired_delta_count: observed.delta_count,
                retired_delta_payload_bytes: observed.delta_payload_bytes,
                compaction_recommended: false,
            },
        )))
    }
}

/// Event cursor, leaf cursor and tip root of a journal position.
type JournalPosition = (u64, u64, FixedBytes<32>);

const fn head_position(head: &PoiCorpusJournalHeadRecord) -> JournalPosition {
    (
        head.event_cursor,
        head.leaf_cursor,
        head.corpus.current_tip_root,
    )
}

/// The `Head` expectation that `head` satisfies.
const fn head_expectation(head: &PoiCorpusJournalHeadRecord) -> ExpectedPoiCorpusJournalState {
    ExpectedPoiCorpusJournalState::Head {
        revision: head.revision,
        base_revision: head.base_revision,
        base_payload_hash: head.base_payload_hash,
        event_cursor: head.event_cursor,
        leaf_cursor: head.leaf_cursor,
        current_tip_root: head.corpus.current_tip_root,
    }
}

/// The head's tip index must sit just before its event cursor.
fn check_head_tip_index(head: &PoiCorpusJournalHeadRecord, head_key: &str) -> Result<(), DbError> {
    if head.event_cursor == 0
        || head.corpus.current_tip_index != head.event_cursor.saturating_sub(1)
    {
        return Err(invalid_journal_head(head_key));
    }
    Ok(())
}

fn invalid_journal_head(head_key: &str) -> DbError {
    DbError::InvalidPpoiCorpusJournalRecord {
        kind: "head",
        key: head_key.to_string(),
    }
}

fn journal_identity_prefix(head_key: &str) -> Result<&str, DbError> {
    head_key
        .strip_suffix("head")
        .ok_or_else(|| invalid_journal_head(head_key))
}

/// Result of the checks every conditional journal write runs first.
enum JournalAdmission {
    Observed(ObservedPoiJournalState),
    Rejected(PoiCorpusJournalCommitOutcome),
}

/// Checks the commit context, then the expected journal state, inside `txn`.
fn admit_journal_write(
    txn: &WriteTransaction,
    base_key: &str,
    head_key: &str,
    condition: PoiCorpusJournalCommitCondition,
) -> Result<JournalAdmission, DbError> {
    if let Some(conflict) = poi_commit_context_conflict(
        txn,
        condition.expected_generation,
        condition.expected_publisher,
        condition.expected_manifest_hash,
    )? {
        return Ok(JournalAdmission::Rejected(conflict.into_journal_outcome()));
    }
    let Some(observed) =
        observe_expected_poi_journal_state(txn, base_key, head_key, condition.expected_state)?
    else {
        return Ok(JournalAdmission::Rejected(
            PoiCorpusJournalCommitOutcome::CorpusConflict,
        ));
    };
    Ok(JournalAdmission::Observed(observed))
}

#[derive(Debug, Clone, Copy)]
struct ObservedPoiJournalState {
    revision: u64,
    base_revision: u64,
    base_payload_hash: FixedBytes<32>,
    event_cursor: u64,
    leaf_cursor: u64,
    current_tip_root: FixedBytes<32>,
    blocked_revision: Option<u64>,
    blocked_payload_hash: Option<FixedBytes<32>>,
    delta_count: u32,
    delta_payload_bytes: u64,
}

impl ObservedPoiJournalState {
    /// A journal with no base or journal rows.
    const fn empty() -> Self {
        Self::without_head(FixedBytes::ZERO, 0, 0, FixedBytes::ZERO)
    }

    /// A journal with no head row: revision 0 on top of the given base.
    const fn without_head(
        base_payload_hash: FixedBytes<32>,
        event_cursor: u64,
        leaf_cursor: u64,
        current_tip_root: FixedBytes<32>,
    ) -> Self {
        Self {
            revision: 0,
            base_revision: 0,
            base_payload_hash,
            event_cursor,
            leaf_cursor,
            current_tip_root,
            blocked_revision: None,
            blocked_payload_hash: None,
            delta_count: 0,
            delta_payload_bytes: 0,
        }
    }

    /// A corrupt journal about to be replaced, retiring the rows `token` counted.
    const fn replacement(token: PoiCorpusJournalCorruptionToken) -> Self {
        Self {
            revision: token.replacement_revision,
            base_revision: token.replacement_revision,
            base_payload_hash: FixedBytes::ZERO,
            event_cursor: 0,
            leaf_cursor: 0,
            current_tip_root: FixedBytes::ZERO,
            blocked_revision: None,
            blocked_payload_hash: None,
            delta_count: token.retired_delta_count,
            delta_payload_bytes: token.retired_delta_payload_bytes,
        }
    }

    const fn from_head(head: &PoiCorpusJournalHeadRecord) -> Self {
        Self {
            revision: head.revision,
            base_revision: head.base_revision,
            base_payload_hash: head.base_payload_hash,
            event_cursor: head.event_cursor,
            leaf_cursor: head.leaf_cursor,
            current_tip_root: head.corpus.current_tip_root,
            blocked_revision: head.blocked_revision,
            blocked_payload_hash: head.blocked_payload_hash,
            delta_count: head.delta_count,
            delta_payload_bytes: head.delta_payload_bytes,
        }
    }

    const fn position(&self) -> JournalPosition {
        (self.event_cursor, self.leaf_cursor, self.current_tip_root)
    }
}

fn observe_expected_poi_journal_state(
    txn: &WriteTransaction,
    base_key: &str,
    head_key: &str,
    expected: ExpectedPoiCorpusJournalState,
) -> Result<Option<ObservedPoiJournalState>, DbError> {
    if let ExpectedPoiCorpusJournalState::Corrupt { replacement_token } = expected {
        return observe_replacement(txn, base_key, head_key, replacement_token);
    }
    let head = read_observed_head(txn, head_key)?;
    match expected {
        ExpectedPoiCorpusJournalState::NoValidBase => {
            if head.is_some() || journal_identity_has_rows(txn, base_key, head_key)? {
                return Ok(None);
            }
            Ok(Some(ObservedPoiJournalState::empty()))
        }
        ExpectedPoiCorpusJournalState::ImplicitBase {
            base_payload_hash,
            event_cursor,
            leaf_cursor,
            current_tip_root,
        } => {
            if head.is_some() || read_base_payload_hash(txn, base_key)? != Some(base_payload_hash) {
                return Ok(None);
            }
            Ok(Some(ObservedPoiJournalState::without_head(
                base_payload_hash,
                event_cursor,
                leaf_cursor,
                current_tip_root,
            )))
        }
        ExpectedPoiCorpusJournalState::Head { .. } => Ok(head
            .filter(|head| head_expectation(head) == expected)
            .map(|head| ObservedPoiJournalState::from_head(&head))),
        ExpectedPoiCorpusJournalState::Corrupt { .. } => {
            unreachable!("corrupt expected state handled before head decoding")
        }
    }
}

/// Accepts a corrupt journal for replacement only while its rows still hash
/// to `token`.
fn observe_replacement(
    txn: &WriteTransaction,
    base_key: &str,
    head_key: &str,
    token: PoiCorpusJournalCorruptionToken,
) -> Result<Option<ObservedPoiJournalState>, DbError> {
    let identity_prefix = journal_identity_prefix(head_key)?;
    let keys = JournalKeys {
        base: base_key.to_owned(),
        head: head_key.to_owned(),
        identity_prefix: identity_prefix.to_owned(),
        delta_prefix: format!("{identity_prefix}delta|"),
    };
    let base_table = txn.open_table(POI_ARTIFACT_CACHE_TABLE)?;
    let journal_table = txn.open_table(POI_CORPUS_JOURNAL_TABLE)?;
    let observed = poi_corpus_journal_replacement_token(&base_table, &journal_table, &keys)?;
    if observed != token {
        return Ok(None);
    }
    Ok(Some(ObservedPoiJournalState::replacement(token)))
}

/// Reads the stored head, treating any invalid head row as an error.
fn read_observed_head(
    txn: &WriteTransaction,
    head_key: &str,
) -> Result<Option<PoiCorpusJournalHeadRecord>, DbError> {
    let table = txn.open_table(POI_CORPUS_JOURNAL_TABLE)?;
    let Some(value) = table.get(head_key)? else {
        return Ok(None);
    };
    match decode_valid_journal_head(value.value(), head_key)? {
        Some(head) => Ok(Some(head)),
        None => Err(invalid_journal_head(head_key)),
    }
}

/// Whether a base row or any journal row exists for this identity. Both are
/// read before either is checked.
fn journal_identity_has_rows(
    txn: &WriteTransaction,
    base_key: &str,
    head_key: &str,
) -> Result<bool, DbError> {
    let base_exists = {
        let table = txn.open_table(POI_ARTIFACT_CACHE_TABLE)?;
        table.get(base_key)?.is_some()
    };
    let identity_prefix = journal_identity_prefix(head_key)?;
    let journal_rows_exist = {
        let table = txn.open_table(POI_CORPUS_JOURNAL_TABLE)?;
        table_prefix_has_rows(&table, identity_prefix)?
    };
    Ok(base_exists || journal_rows_exist)
}

/// Payload hash of the stored base row, or `None` when the row is missing,
/// undecodable or stored under another key.
fn read_base_payload_hash(
    txn: &WriteTransaction,
    base_key: &str,
) -> Result<Option<FixedBytes<32>>, DbError> {
    let table = txn.open_table(POI_ARTIFACT_CACHE_TABLE)?;
    let Some(value) = table.get(base_key)? else {
        return Ok(None);
    };
    match decode::<PoiArtifactCacheRecord>(value.value()) {
        Ok(record) if record.key() == base_key => Ok(Some(keccak256(&record.cache_payload))),
        Ok(_) | Err(DbError::Decode(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Revision, generation and time stamped onto every row of one journal write.
struct JournalStamp {
    observed: ObservedPoiJournalState,
    revision: u64,
    generation: u64,
    now: u64,
}

impl JournalStamp {
    fn new(observed: ObservedPoiJournalState, generation: u64) -> Result<Self, DbError> {
        let revision = observed
            .revision
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("POI corpus journal revision overflow"))?;
        let now = now_epoch_secs()?;
        Ok(Self {
            observed,
            revision,
            generation,
            now,
        })
    }

    const fn stamp_head(&self, head: &mut PoiCorpusJournalHeadRecord) {
        head.format_version = POI_CORPUS_JOURNAL_FORMAT_VERSION;
        head.revision = self.revision;
        head.base_revision = self.observed.base_revision;
        head.base_payload_hash = self.observed.base_payload_hash;
        head.corpus.cache_generation = self.generation;
        head.corpus.updated_at = self.now;
    }

    /// Delta count and payload bytes after appending `delta`, or `None` when
    /// they exceed the journal's hard limits and the journal must be compacted.
    fn next_totals(
        &self,
        delta: Option<&PoiCorpusJournalDeltaRecord>,
    ) -> Result<Option<(u32, u64)>, DbError> {
        let delta_payload_bytes = delta.map_or(0_u64, |delta| {
            u64::try_from(delta.payload.len()).unwrap_or(u64::MAX)
        });
        let delta_count = self
            .observed
            .delta_count
            .checked_add(u32::from(delta.is_some()))
            .ok_or_else(|| std::io::Error::other("POI corpus journal delta count overflow"))?;
        let delta_payload_bytes = self
            .observed
            .delta_payload_bytes
            .checked_add(delta_payload_bytes)
            .ok_or_else(|| std::io::Error::other("POI corpus journal byte count overflow"))?;
        if delta_count > POI_CORPUS_JOURNAL_MAX_DELTA_COUNT
            || delta_payload_bytes > POI_CORPUS_JOURNAL_MAX_PAYLOAD_BYTES
        {
            return Ok(None);
        }
        Ok(Some((delta_count, delta_payload_bytes)))
    }

    /// Checks that `delta` spans from the observed position to `head`'s, then
    /// stamps it.
    fn stamp_delta(
        &self,
        delta: &mut PoiCorpusJournalDeltaRecord,
        head: &PoiCorpusJournalHeadRecord,
    ) -> Result<(), DbError> {
        let start = (
            delta.event_start_cursor,
            delta.leaf_start_cursor,
            delta.start_tip_root,
        );
        let end = (
            delta.event_end_cursor,
            delta.leaf_end_cursor,
            delta.end_tip_root,
        );
        let spans_observed_to_head =
            start == self.observed.position() && end == head_position(head);
        if !poi_journal_delta_identity_matches(delta, &head.corpus) || !spans_observed_to_head {
            return Err(DbError::InvalidPpoiCorpusJournalRecord {
                kind: "delta",
                key: delta.key(),
            });
        }
        delta.format_version = POI_CORPUS_JOURNAL_FORMAT_VERSION;
        delta.cache_generation = self.generation;
        delta.revision = self.revision;
        delta.previous_revision = self.observed.revision;
        delta.base_revision = self.observed.base_revision;
        delta.updated_at = self.now;
        Ok(())
    }

    /// Without a delta, the head must stay at the observed position.
    fn check_head_unmoved(
        &self,
        head: &PoiCorpusJournalHeadRecord,
        head_key: &str,
    ) -> Result<(), DbError> {
        if head_position(head) != self.observed.position() {
            return Err(invalid_journal_head(head_key));
        }
        Ok(())
    }

    /// Stamps a replacement blocked snapshot and points the head at it, or
    /// keeps the observed snapshot when there is no replacement.
    fn stamp_blocked(
        &self,
        blocked: Option<&mut PoiCorpusBlockedSnapshotRecord>,
        head: &mut PoiCorpusJournalHeadRecord,
    ) -> Result<(), DbError> {
        let Some(blocked) = blocked else {
            head.blocked_revision = self.observed.blocked_revision;
            head.blocked_payload_hash = self.observed.blocked_payload_hash;
            return Ok(());
        };
        if !poi_journal_blocked_identity_matches(blocked, &head.corpus)
            || u64::try_from(blocked.payload.len()).unwrap_or(u64::MAX)
                > POI_CORPUS_JOURNAL_MAX_BLOCKED_PAYLOAD_BYTES
        {
            return Err(DbError::InvalidPpoiCorpusJournalRecord {
                kind: "blocked snapshot",
                key: blocked.key(),
            });
        }
        blocked.format_version = POI_CORPUS_JOURNAL_FORMAT_VERSION;
        blocked.cache_generation = self.generation;
        blocked.revision = self.revision;
        blocked.payload_hash = keccak256(&blocked.payload);
        blocked.updated_at = self.now;
        head.blocked_revision = Some(self.revision);
        head.blocked_payload_hash = Some(blocked.payload_hash);
        Ok(())
    }
}

/// Encodes the append's rows, then writes the delta, the blocked snapshot and
/// the head. Returns a conflict, writing nothing, when the delta row already
/// exists.
fn write_journal_append(
    txn: &WriteTransaction,
    head: &PoiCorpusJournalHeadRecord,
    delta: Option<&PoiCorpusJournalDeltaRecord>,
    blocked: Option<&PoiCorpusBlockedSnapshotRecord>,
) -> Result<Option<PoiCorpusJournalCommitOutcome>, DbError> {
    let head_data = encode(head)?;
    let delta_data = delta.map(encode).transpose()?;
    let blocked_data = blocked.map(encode).transpose()?;
    let mut table = txn.open_table(POI_CORPUS_JOURNAL_TABLE)?;
    if let (Some(delta), Some(data)) = (delta, delta_data.as_ref()) {
        let delta_key = delta.key();
        if table.get(delta_key.as_str())?.is_some() {
            return Ok(Some(PoiCorpusJournalCommitOutcome::CorpusConflict));
        }
        table.insert(delta_key.as_str(), data.as_slice())?;
    }
    if let (Some(blocked), Some(data)) = (blocked, blocked_data.as_ref()) {
        table.insert(blocked.key().as_str(), data.as_slice())?;
    }
    table.insert(head.key().as_str(), head_data.as_slice())?;
    Ok(None)
}

fn applied_append(
    head: PoiCorpusJournalHeadRecord,
    delta: Option<PoiCorpusJournalDeltaRecord>,
    blocked: Option<PoiCorpusBlockedSnapshotRecord>,
) -> PoiCorpusJournalCommitOutcome {
    let compaction_recommended = head.delta_count >= POI_CORPUS_JOURNAL_SOFT_DELTA_COUNT
        || head.delta_payload_bytes >= POI_CORPUS_JOURNAL_SOFT_PAYLOAD_BYTES;
    PoiCorpusJournalCommitOutcome::Applied(Box::new(PoiCorpusJournalCommit {
        head,
        delta,
        blocked,
        base: None,
        retired_delta_count: 0,
        retired_delta_payload_bytes: 0,
        compaction_recommended,
    }))
}

/// Head of a journal rebased onto `base`, with no deltas or blocked snapshot.
fn fresh_journal_head(
    base: &PoiArtifactCacheRecord,
    revision: u64,
    event_cursor: u64,
    leaf_cursor: u64,
) -> PoiCorpusJournalHeadRecord {
    let base_payload_hash = keccak256(&base.cache_payload);
    let mut corpus = base.clone();
    corpus.cache_payload.clear();
    PoiCorpusJournalHeadRecord {
        format_version: POI_CORPUS_JOURNAL_FORMAT_VERSION,
        revision,
        base_revision: revision,
        base_payload_hash,
        event_cursor,
        leaf_cursor,
        blocked_revision: None,
        blocked_payload_hash: None,
        delta_count: 0,
        delta_payload_bytes: 0,
        corpus,
    }
}
