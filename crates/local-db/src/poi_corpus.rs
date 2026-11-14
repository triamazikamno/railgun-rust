use alloy::primitives::{FixedBytes, keccak256};
use redb::{ReadableDatabase, ReadableTable, WriteTransaction};
use sha2::{Digest, Sha256};

use super::{
    DbError, DbStore, ExpectedPoiCorpusJournalState, POI_ARTIFACT_CACHE_TABLE,
    POI_CORPUS_JOURNAL_FORMAT_VERSION, POI_CORPUS_JOURNAL_MAX_BLOCKED_PAYLOAD_BYTES,
    POI_CORPUS_JOURNAL_MAX_DELTA_COUNT, POI_CORPUS_JOURNAL_MAX_HEAD_ROW_BYTES,
    POI_CORPUS_JOURNAL_MAX_PAYLOAD_BYTES, POI_CORPUS_JOURNAL_SOFT_DELTA_COUNT,
    POI_CORPUS_JOURNAL_SOFT_PAYLOAD_BYTES, POI_CORPUS_JOURNAL_TABLE, PoiArtifactCacheRecord,
    PoiCorpusBlockedSnapshotRecord, PoiCorpusJournalBundle, PoiCorpusJournalCommit,
    PoiCorpusJournalCommitCondition, PoiCorpusJournalCommitOutcome,
    PoiCorpusJournalCorruptionToken, PoiCorpusJournalDeltaRecord, PoiCorpusJournalHeadRecord,
    PoiCorpusJournalInspection, StoredRecord, decode, decode_poi_corpus_blocked_snapshot_bounded,
    decode_poi_corpus_journal_delta_bounded, encode, now_epoch_secs, poi_commit_context_conflict,
    prefix_range_end, remove_table_prefix, table_prefix_has_rows,
};

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
        let data = value.value();
        if data.len() > POI_CORPUS_JOURNAL_MAX_HEAD_ROW_BYTES {
            return Ok(StoredRecord::Corrupt { key: head_key });
        }
        match decode::<PoiCorpusJournalHeadRecord>(data) {
            Ok(head) if head.key() == head_key && valid_poi_corpus_journal_head(&head) => {
                Ok(StoredRecord::Valid(head))
            }
            Ok(_) | Err(DbError::Decode(_)) => Ok(StoredRecord::Corrupt { key: head_key }),
            Err(error) => Err(error),
        }
    }

    pub fn inspect_poi_corpus_journal_detailed(
        &self,
        chain_type: u8,
        chain_id: u64,
        txid_version: &str,
        list_key: &FixedBytes<32>,
    ) -> Result<PoiCorpusJournalInspection, DbError> {
        let base_key =
            PoiArtifactCacheRecord::key_for(chain_type, chain_id, txid_version, list_key);
        let head_key =
            PoiCorpusJournalHeadRecord::key_for(chain_type, chain_id, txid_version, list_key);
        let blocked_key =
            PoiCorpusBlockedSnapshotRecord::key_for(chain_type, chain_id, txid_version, list_key);
        let identity_prefix = PoiCorpusJournalHeadRecord::identity_prefix_for(
            chain_type,
            chain_id,
            txid_version,
            list_key,
        );
        let delta_prefix = PoiCorpusJournalHeadRecord::delta_prefix_for(
            chain_type,
            chain_id,
            txid_version,
            list_key,
        );
        let txn = self.db.begin_read()?;
        let base_table = txn.open_table(POI_ARTIFACT_CACHE_TABLE)?;
        let journal_table = txn.open_table(POI_CORPUS_JOURNAL_TABLE)?;
        let replacement_token = poi_corpus_journal_replacement_token(
            &base_table,
            &journal_table,
            &base_key,
            &head_key,
            &identity_prefix,
            &delta_prefix,
        )?;

        let base = match base_table.get(base_key.as_str())? {
            Some(value) => match decode::<PoiArtifactCacheRecord>(value.value()) {
                Ok(record) if record.key() == base_key => Some(record),
                Ok(_) | Err(DbError::Decode(_)) => {
                    return Ok(PoiCorpusJournalInspection::Corrupt {
                        key: base_key,
                        replacement_token,
                    });
                }
                Err(error) => return Err(error),
            },
            None => None,
        };
        let head = match journal_table.get(head_key.as_str())? {
            Some(value) => {
                let data = value.value();
                if data.len() > POI_CORPUS_JOURNAL_MAX_HEAD_ROW_BYTES {
                    return Ok(PoiCorpusJournalInspection::Corrupt {
                        key: head_key,
                        replacement_token,
                    });
                }
                match decode::<PoiCorpusJournalHeadRecord>(data) {
                    Ok(head)
                        if head.key() == head_key
                            && valid_poi_corpus_journal_head(&head)
                            && base.as_ref().is_some_and(|base| {
                                base.cache_generation == head.corpus.cache_generation
                                    && keccak256(&base.cache_payload) == head.base_payload_hash
                            }) =>
                    {
                        Some(head)
                    }
                    Ok(_) | Err(DbError::Decode(_)) => {
                        return Ok(PoiCorpusJournalInspection::Corrupt {
                            key: head_key,
                            replacement_token,
                        });
                    }
                    Err(error) => return Err(error),
                }
            }
            None => None,
        };

        let Some(base) = base else {
            let has_journal_rows = table_prefix_has_rows(&journal_table, identity_prefix.as_str())?;
            if has_journal_rows {
                return Ok(PoiCorpusJournalInspection::Corrupt {
                    key: identity_prefix,
                    replacement_token,
                });
            }
            return Ok(PoiCorpusJournalInspection::Missing);
        };
        let Some(head) = head else {
            let has_journal_rows = table_prefix_has_rows(&journal_table, identity_prefix.as_str())?;
            if has_journal_rows {
                return Ok(PoiCorpusJournalInspection::Corrupt {
                    key: identity_prefix,
                    replacement_token,
                });
            }
            return Ok(PoiCorpusJournalInspection::Valid {
                bundle: Box::new(PoiCorpusJournalBundle {
                    base,
                    head: None,
                    deltas: Vec::new(),
                    blocked: None,
                }),
                replacement_token,
            });
        };

        let mut deltas = Vec::new();
        let mut delta_payload_bytes = 0_u64;
        let mut previous_delta_revision = None;
        let mut expected_event_cursor = base.current_tip_index.saturating_add(1);
        let mut expected_leaf_cursor = None;
        let mut expected_tip_root = base.current_tip_root;
        let coverage_after_revision = head.blocked_revision.unwrap_or(head.base_revision);
        let mut last_required_delta_revision = None;
        let delta_range_end = prefix_range_end(&delta_prefix);
        let mut range = match delta_range_end.as_deref() {
            Some(end) => journal_table.range(delta_prefix.as_str()..end)?,
            None => journal_table.range(delta_prefix.as_str()..)?,
        };
        for entry in &mut range {
            let (key, value) = entry?;
            let key = key.value().to_string();
            if deltas.len() >= head.delta_count as usize
                || deltas.len() >= POI_CORPUS_JOURNAL_MAX_DELTA_COUNT as usize
            {
                return Ok(PoiCorpusJournalInspection::Corrupt {
                    key,
                    replacement_token,
                });
            }
            let data = value.value();
            let Some(remaining_payload_bytes) =
                head.delta_payload_bytes.checked_sub(delta_payload_bytes)
            else {
                return Ok(PoiCorpusJournalInspection::Corrupt {
                    key,
                    replacement_token,
                });
            };
            let delta = match decode_poi_corpus_journal_delta_bounded(data, remaining_payload_bytes)
            {
                Ok(Some(delta)) => delta,
                Ok(None) | Err(DbError::Decode(_)) => {
                    return Ok(PoiCorpusJournalInspection::Corrupt {
                        key,
                        replacement_token,
                    });
                }
                Err(error) => return Err(error),
            };
            let valid_revision_order =
                previous_delta_revision.is_none_or(|previous| delta.revision > previous);
            let valid_required_coverage = if delta.revision > coverage_after_revision {
                let expected_revision = last_required_delta_revision.map_or_else(
                    || coverage_after_revision.checked_add(1),
                    |previous: u64| previous.checked_add(1),
                );
                if expected_revision == Some(delta.revision) {
                    last_required_delta_revision = Some(delta.revision);
                    true
                } else {
                    false
                }
            } else {
                true
            };
            if delta.key() != key
                || !valid_poi_corpus_journal_delta(&delta, &head)
                || !valid_revision_order
                || !valid_required_coverage
                || delta.event_start_cursor != expected_event_cursor
                || expected_leaf_cursor.is_some_and(|cursor| delta.leaf_start_cursor != cursor)
                || delta.start_tip_root != expected_tip_root
            {
                return Ok(PoiCorpusJournalInspection::Corrupt {
                    key,
                    replacement_token,
                });
            }
            previous_delta_revision = Some(delta.revision);
            expected_event_cursor = delta.event_end_cursor;
            expected_leaf_cursor = Some(delta.leaf_end_cursor);
            expected_tip_root = delta.end_tip_root;
            let Some(next_delta_payload_bytes) = delta_payload_bytes
                .checked_add(u64::try_from(delta.payload.len()).unwrap_or(u64::MAX))
            else {
                return Ok(PoiCorpusJournalInspection::Corrupt {
                    key,
                    replacement_token,
                });
            };
            delta_payload_bytes = next_delta_payload_bytes;
            deltas.push(delta);
        }
        drop(range);
        let required_suffix_complete = head.revision == coverage_after_revision
            || last_required_delta_revision == Some(head.revision);
        if !required_suffix_complete
            || deltas.len() != head.delta_count as usize
            || delta_payload_bytes != head.delta_payload_bytes
            || expected_event_cursor != head.event_cursor
            || expected_leaf_cursor.is_some_and(|cursor| cursor != head.leaf_cursor)
            || expected_tip_root != head.corpus.current_tip_root
        {
            return Ok(PoiCorpusJournalInspection::Corrupt {
                key: head_key,
                replacement_token,
            });
        }

        let blocked = match (head.blocked_revision, head.blocked_payload_hash) {
            (Some(expected_revision), Some(expected_hash)) => {
                match journal_table.get(blocked_key.as_str())? {
                    Some(value) => {
                        match decode_poi_corpus_blocked_snapshot_bounded(value.value()) {
                            Ok(Some(blocked))
                                if blocked.key() == blocked_key
                                    && valid_poi_corpus_blocked_snapshot(&blocked, &head)
                                    && blocked.revision == expected_revision
                                    && blocked.payload_hash == expected_hash =>
                            {
                                Some(blocked)
                            }
                            Ok(_) | Err(DbError::Decode(_)) => {
                                return Ok(PoiCorpusJournalInspection::Corrupt {
                                    key: blocked_key,
                                    replacement_token,
                                });
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    None => {
                        return Ok(PoiCorpusJournalInspection::Corrupt {
                            key: blocked_key,
                            replacement_token,
                        });
                    }
                }
            }
            (None, None) => {
                if journal_table.get(blocked_key.as_str())?.is_some() {
                    return Ok(PoiCorpusJournalInspection::Corrupt {
                        key: blocked_key,
                        replacement_token,
                    });
                }
                None
            }
            _ => {
                return Ok(PoiCorpusJournalInspection::Corrupt {
                    key: head_key,
                    replacement_token,
                });
            }
        };

        Ok(PoiCorpusJournalInspection::Valid {
            bundle: Box::new(PoiCorpusJournalBundle {
                base,
                head: Some(head),
                deltas,
                blocked,
            }),
            replacement_token,
        })
    }

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
            return Err(DbError::InvalidPpoiCorpusJournalRecord {
                kind: "head",
                key: head_key,
            });
        }
        if matches!(
            condition.expected_state,
            ExpectedPoiCorpusJournalState::Corrupt { .. }
        ) {
            return Ok(PoiCorpusJournalCommitOutcome::CorpusConflict);
        }
        let txn = self.db.begin_write()?;
        if let Some(conflict) = poi_commit_context_conflict(
            &txn,
            condition.expected_generation,
            condition.expected_publisher,
            condition.expected_manifest_hash,
        )? {
            return Ok(conflict.into_journal_outcome());
        }
        let Some(observed) =
            observe_expected_poi_journal_state(&txn, &key, &head_key, condition.expected_state)?
        else {
            return Ok(PoiCorpusJournalCommitOutcome::CorpusConflict);
        };
        if matches!(
            condition.expected_state,
            ExpectedPoiCorpusJournalState::NoValidBase
        ) {
            return Ok(PoiCorpusJournalCommitOutcome::CorpusConflict);
        }

        let revision = observed
            .revision
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("POI corpus journal revision overflow"))?;
        let now = now_epoch_secs()?;
        head.format_version = POI_CORPUS_JOURNAL_FORMAT_VERSION;
        head.revision = revision;
        head.base_revision = observed.base_revision;
        head.base_payload_hash = observed.base_payload_hash;
        head.corpus.cache_generation = condition.expected_generation;
        head.corpus.updated_at = now;

        let delta_payload_bytes = delta.as_ref().map_or(0_u64, |delta| {
            u64::try_from(delta.payload.len()).unwrap_or(u64::MAX)
        });
        let new_delta_count = observed
            .delta_count
            .checked_add(u32::from(delta.is_some()))
            .ok_or_else(|| std::io::Error::other("POI corpus journal delta count overflow"))?;
        let new_delta_payload_bytes = observed
            .delta_payload_bytes
            .checked_add(delta_payload_bytes)
            .ok_or_else(|| std::io::Error::other("POI corpus journal byte count overflow"))?;
        if new_delta_count > POI_CORPUS_JOURNAL_MAX_DELTA_COUNT
            || new_delta_payload_bytes > POI_CORPUS_JOURNAL_MAX_PAYLOAD_BYTES
        {
            return Ok(PoiCorpusJournalCommitOutcome::CompactionRequired);
        }
        head.delta_count = new_delta_count;
        head.delta_payload_bytes = new_delta_payload_bytes;

        if let Some(delta) = delta.as_mut() {
            if !poi_journal_delta_identity_matches(delta, &head.corpus)
                || delta.event_start_cursor != observed.event_cursor
                || delta.leaf_start_cursor != observed.leaf_cursor
                || delta.start_tip_root != observed.current_tip_root
                || delta.event_end_cursor != head.event_cursor
                || delta.leaf_end_cursor != head.leaf_cursor
                || delta.end_tip_root != head.corpus.current_tip_root
            {
                return Err(DbError::InvalidPpoiCorpusJournalRecord {
                    kind: "delta",
                    key: delta.key(),
                });
            }
            delta.format_version = POI_CORPUS_JOURNAL_FORMAT_VERSION;
            delta.cache_generation = condition.expected_generation;
            delta.revision = revision;
            delta.previous_revision = observed.revision;
            delta.base_revision = observed.base_revision;
            delta.updated_at = now;
        } else if head.event_cursor != observed.event_cursor
            || head.leaf_cursor != observed.leaf_cursor
            || head.corpus.current_tip_root != observed.current_tip_root
        {
            return Err(DbError::InvalidPpoiCorpusJournalRecord {
                kind: "head",
                key: head_key,
            });
        }

        if head.event_cursor == 0
            || head.corpus.current_tip_index != head.event_cursor.saturating_sub(1)
        {
            return Err(DbError::InvalidPpoiCorpusJournalRecord {
                kind: "head",
                key: head_key,
            });
        }

        if let Some(blocked) = blocked.as_mut() {
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
            blocked.cache_generation = condition.expected_generation;
            blocked.revision = revision;
            blocked.payload_hash = keccak256(&blocked.payload);
            blocked.updated_at = now;
            head.blocked_revision = Some(revision);
            head.blocked_payload_hash = Some(blocked.payload_hash);
        } else {
            head.blocked_revision = observed.blocked_revision;
            head.blocked_payload_hash = observed.blocked_payload_hash;
        }

        let head_data = encode(&head)?;
        let delta_data = delta.as_ref().map(encode).transpose()?;
        let blocked_data = blocked.as_ref().map(encode).transpose()?;
        {
            let mut table = txn.open_table(POI_CORPUS_JOURNAL_TABLE)?;
            if let (Some(delta), Some(data)) = (delta.as_ref(), delta_data.as_ref()) {
                let delta_key = delta.key();
                if table.get(delta_key.as_str())?.is_some() {
                    return Ok(PoiCorpusJournalCommitOutcome::CorpusConflict);
                }
                table.insert(delta_key.as_str(), data.as_slice())?;
            }
            if let (Some(blocked), Some(data)) = (blocked.as_ref(), blocked_data.as_ref()) {
                table.insert(blocked.key().as_str(), data.as_slice())?;
            }
            table.insert(head_key.as_str(), head_data.as_slice())?;
        }
        txn.commit()?;
        let compaction_recommended = new_delta_count >= POI_CORPUS_JOURNAL_SOFT_DELTA_COUNT
            || new_delta_payload_bytes >= POI_CORPUS_JOURNAL_SOFT_PAYLOAD_BYTES;
        Ok(PoiCorpusJournalCommitOutcome::Applied(Box::new(
            PoiCorpusJournalCommit {
                head,
                delta,
                blocked,
                base: None,
                retired_delta_count: 0,
                retired_delta_payload_bytes: 0,
                compaction_recommended,
            },
        )))
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
        if let Some(conflict) = poi_commit_context_conflict(
            &txn,
            condition.expected_generation,
            condition.expected_publisher,
            condition.expected_manifest_hash,
        )? {
            return Ok(conflict.into_journal_outcome());
        }
        let Some(observed) =
            observe_expected_poi_journal_state(&txn, &key, &head_key, condition.expected_state)?
        else {
            return Ok(PoiCorpusJournalCommitOutcome::CorpusConflict);
        };
        let revision = observed
            .revision
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("POI corpus journal revision overflow"))?;
        let now = now_epoch_secs()?;
        base.cache_generation = condition.expected_generation;
        base.updated_at = now;
        let base_payload_hash = keccak256(&base.cache_payload);
        let mut head_corpus = base.clone();
        head_corpus.cache_payload.clear();
        let head = PoiCorpusJournalHeadRecord {
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
            corpus: head_corpus,
        };
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

fn observe_expected_poi_journal_state(
    txn: &WriteTransaction,
    base_key: &str,
    head_key: &str,
    expected: ExpectedPoiCorpusJournalState,
) -> Result<Option<ObservedPoiJournalState>, DbError> {
    if let ExpectedPoiCorpusJournalState::Corrupt { replacement_token } = expected {
        let identity_prefix = head_key.strip_suffix("head").ok_or_else(|| {
            DbError::InvalidPpoiCorpusJournalRecord {
                kind: "head",
                key: head_key.to_string(),
            }
        })?;
        let delta_prefix = format!("{identity_prefix}delta|");
        let base_table = txn.open_table(POI_ARTIFACT_CACHE_TABLE)?;
        let journal_table = txn.open_table(POI_CORPUS_JOURNAL_TABLE)?;
        let observed = poi_corpus_journal_replacement_token(
            &base_table,
            &journal_table,
            base_key,
            head_key,
            identity_prefix,
            &delta_prefix,
        )?;
        if observed != replacement_token {
            return Ok(None);
        }
        return Ok(Some(ObservedPoiJournalState {
            revision: replacement_token.replacement_revision,
            base_revision: replacement_token.replacement_revision,
            base_payload_hash: FixedBytes::ZERO,
            event_cursor: 0,
            leaf_cursor: 0,
            current_tip_root: FixedBytes::ZERO,
            blocked_revision: None,
            blocked_payload_hash: None,
            delta_count: replacement_token.retired_delta_count,
            delta_payload_bytes: replacement_token.retired_delta_payload_bytes,
        }));
    }
    let head = {
        let table = txn.open_table(POI_CORPUS_JOURNAL_TABLE)?;
        match table.get(head_key)? {
            Some(value) => {
                let data = value.value();
                if data.len() > POI_CORPUS_JOURNAL_MAX_HEAD_ROW_BYTES {
                    return Err(DbError::InvalidPpoiCorpusJournalRecord {
                        kind: "head",
                        key: head_key.to_string(),
                    });
                }
                let head: PoiCorpusJournalHeadRecord = decode(data).map_err(|error| {
                    if matches!(error, DbError::Decode(_)) {
                        DbError::InvalidPpoiCorpusJournalRecord {
                            kind: "head",
                            key: head_key.to_string(),
                        }
                    } else {
                        error
                    }
                })?;
                if head.key() != head_key || !valid_poi_corpus_journal_head(&head) {
                    return Err(DbError::InvalidPpoiCorpusJournalRecord {
                        kind: "head",
                        key: head_key.to_string(),
                    });
                }
                Some(head)
            }
            None => None,
        }
    };
    match expected {
        ExpectedPoiCorpusJournalState::NoValidBase => {
            if head.is_some() {
                return Ok(None);
            }
            let base_exists = {
                let table = txn.open_table(POI_ARTIFACT_CACHE_TABLE)?;
                table.get(base_key)?.is_some()
            };
            let identity_prefix = head_key.strip_suffix("head").ok_or_else(|| {
                DbError::InvalidPpoiCorpusJournalRecord {
                    kind: "head",
                    key: head_key.to_string(),
                }
            })?;
            let journal_rows_exist = {
                let table = txn.open_table(POI_CORPUS_JOURNAL_TABLE)?;
                table_prefix_has_rows(&table, identity_prefix)?
            };
            if base_exists || journal_rows_exist {
                return Ok(None);
            }
            Ok(Some(ObservedPoiJournalState {
                revision: 0,
                base_revision: 0,
                base_payload_hash: FixedBytes::ZERO,
                event_cursor: 0,
                leaf_cursor: 0,
                current_tip_root: FixedBytes::ZERO,
                blocked_revision: None,
                blocked_payload_hash: None,
                delta_count: 0,
                delta_payload_bytes: 0,
            }))
        }
        ExpectedPoiCorpusJournalState::ImplicitBase {
            base_payload_hash,
            event_cursor,
            leaf_cursor,
            current_tip_root,
        } => {
            if head.is_some() {
                return Ok(None);
            }
            let observed_hash = {
                let table = txn.open_table(POI_ARTIFACT_CACHE_TABLE)?;
                match table.get(base_key)? {
                    Some(value) => match decode::<PoiArtifactCacheRecord>(value.value()) {
                        Ok(record) if record.key() == base_key => {
                            Some(keccak256(&record.cache_payload))
                        }
                        Ok(_) | Err(DbError::Decode(_)) => None,
                        Err(error) => return Err(error),
                    },
                    None => None,
                }
            };
            if observed_hash != Some(base_payload_hash) {
                return Ok(None);
            }
            Ok(Some(ObservedPoiJournalState {
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
            }))
        }
        ExpectedPoiCorpusJournalState::Head {
            revision,
            base_revision,
            base_payload_hash,
            event_cursor,
            leaf_cursor,
            current_tip_root,
        } => {
            let Some(head) = head else {
                return Ok(None);
            };
            if head.revision != revision
                || head.base_revision != base_revision
                || head.base_payload_hash != base_payload_hash
                || head.event_cursor != event_cursor
                || head.leaf_cursor != leaf_cursor
                || head.corpus.current_tip_root != current_tip_root
            {
                return Ok(None);
            }
            Ok(Some(ObservedPoiJournalState {
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
            }))
        }
        ExpectedPoiCorpusJournalState::Corrupt { .. } => {
            unreachable!("corrupt expected state handled before head decoding")
        }
    }
}

fn poi_corpus_journal_replacement_token<BaseTable, JournalTable>(
    base_table: &BaseTable,
    journal_table: &JournalTable,
    base_key: &str,
    head_key: &str,
    identity_prefix: &str,
    delta_prefix: &str,
) -> Result<PoiCorpusJournalCorruptionToken, DbError>
where
    BaseTable: ReadableTable<&'static str, &'static [u8]>,
    JournalTable: ReadableTable<&'static str, &'static [u8]>,
{
    let mut hasher = Sha256::new();
    hasher.update(b"railgun-poi-corpus-journal-replacement-token-v1");
    hasher.update((base_key.len() as u64).to_be_bytes());
    hasher.update(base_key.as_bytes());
    match base_table.get(base_key)? {
        Some(value) => {
            hasher.update([1]);
            hasher.update((value.value().len() as u64).to_be_bytes());
            hasher.update(value.value());
        }
        None => hasher.update([0]),
    }

    let mut replacement_revision = 0_u64;
    let mut retired_delta_count = 0_u32;
    let mut retired_delta_payload_bytes = 0_u64;
    if let Some(value) = journal_table.get(head_key)? {
        let data = value.value();
        if data.len() <= POI_CORPUS_JOURNAL_MAX_HEAD_ROW_BYTES
            && let Ok(head) = decode::<PoiCorpusJournalHeadRecord>(data)
            && head.key() == head_key
            && valid_poi_corpus_journal_head(&head)
        {
            replacement_revision = head.revision;
            retired_delta_count = head.delta_count;
            retired_delta_payload_bytes = head.delta_payload_bytes;
        }
    }

    let mut journal_row_count = 0_u64;
    let journal_range_end = prefix_range_end(identity_prefix);
    let mut range = match journal_range_end.as_deref() {
        Some(end) => journal_table.range(identity_prefix..end)?,
        None => journal_table.range(identity_prefix..)?,
    };
    for entry in &mut range {
        let (key, value) = entry?;
        let key = key.value();
        let value = value.value();
        hasher.update([2]);
        hasher.update((key.len() as u64).to_be_bytes());
        hasher.update(key.as_bytes());
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
        journal_row_count = journal_row_count
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("POI corpus journal row count overflow"))?;
    }
    drop(range);
    hasher.update([3]);
    hasher.update(journal_row_count.to_be_bytes());
    hasher.update((delta_prefix.len() as u64).to_be_bytes());
    hasher.update(delta_prefix.as_bytes());

    Ok(PoiCorpusJournalCorruptionToken {
        fingerprint: FixedBytes::from(<[u8; 32]>::from(hasher.finalize())),
        replacement_revision,
        retired_delta_count,
        retired_delta_payload_bytes,
    })
}

fn valid_poi_corpus_journal_head(head: &PoiCorpusJournalHeadRecord) -> bool {
    head.format_version == POI_CORPUS_JOURNAL_FORMAT_VERSION
        && head.corpus.cache_payload.is_empty()
        && head.base_revision <= head.revision
        && head.event_cursor > 0
        && head.corpus.current_tip_index == head.event_cursor.saturating_sub(1)
        && head.delta_count <= POI_CORPUS_JOURNAL_MAX_DELTA_COUNT
        && head.delta_payload_bytes <= POI_CORPUS_JOURNAL_MAX_PAYLOAD_BYTES
        && head.blocked_revision.is_some() == head.blocked_payload_hash.is_some()
        && head
            .blocked_revision
            .is_none_or(|revision| revision > head.base_revision && revision <= head.revision)
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

fn poi_journal_delta_identity_matches(
    delta: &PoiCorpusJournalDeltaRecord,
    corpus: &PoiArtifactCacheRecord,
) -> bool {
    delta.chain_type == corpus.chain_type
        && delta.chain_id == corpus.chain_id
        && delta.txid_version == corpus.txid_version
        && delta.list_key == corpus.list_key
}

fn poi_journal_blocked_identity_matches(
    blocked: &PoiCorpusBlockedSnapshotRecord,
    corpus: &PoiArtifactCacheRecord,
) -> bool {
    blocked.chain_type == corpus.chain_type
        && blocked.chain_id == corpus.chain_id
        && blocked.txid_version == corpus.txid_version
        && blocked.list_key == corpus.list_key
}
