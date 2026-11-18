use alloy::primitives::FixedBytes;
use redb::ReadableTable;
use sha2::{Digest, Sha256};

use super::{
    DbError, POI_CORPUS_JOURNAL_FORMAT_VERSION, POI_CORPUS_JOURNAL_MAX_DELTA_COUNT,
    POI_CORPUS_JOURNAL_MAX_HEAD_ROW_BYTES, POI_CORPUS_JOURNAL_MAX_PAYLOAD_BYTES,
    PoiArtifactCacheRecord, PoiCorpusBlockedSnapshotRecord, PoiCorpusJournalCorruptionToken,
    PoiCorpusJournalDeltaRecord, PoiCorpusJournalHeadRecord, decode, prefix_range_end,
};

mod commit;
mod inspect;

/// Row keys of one corpus journal identity, as the replacement token hashes them.
struct JournalKeys {
    base: String,
    head: String,
    identity_prefix: String,
    delta_prefix: String,
}

impl JournalKeys {
    fn for_identity(
        chain_type: u8,
        chain_id: u64,
        txid_version: &str,
        list_key: &FixedBytes<32>,
    ) -> Self {
        Self {
            base: PoiArtifactCacheRecord::key_for(chain_type, chain_id, txid_version, list_key),
            head: PoiCorpusJournalHeadRecord::key_for(chain_type, chain_id, txid_version, list_key),
            identity_prefix: PoiCorpusJournalHeadRecord::identity_prefix_for(
                chain_type,
                chain_id,
                txid_version,
                list_key,
            ),
            delta_prefix: PoiCorpusJournalHeadRecord::delta_prefix_for(
                chain_type,
                chain_id,
                txid_version,
                list_key,
            ),
        }
    }
}

/// Decodes a journal head row. Returns `None` when the row is oversized,
/// undecodable, stored under another key or breaks the head invariants.
fn decode_valid_journal_head(
    data: &[u8],
    head_key: &str,
) -> Result<Option<PoiCorpusJournalHeadRecord>, DbError> {
    if data.len() > POI_CORPUS_JOURNAL_MAX_HEAD_ROW_BYTES {
        return Ok(None);
    }
    match decode::<PoiCorpusJournalHeadRecord>(data) {
        Ok(head) if head.key() == head_key && valid_poi_corpus_journal_head(&head) => {
            Ok(Some(head))
        }
        Ok(_) | Err(DbError::Decode(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

fn poi_corpus_journal_replacement_token<BaseTable, JournalTable>(
    base_table: &BaseTable,
    journal_table: &JournalTable,
    keys: &JournalKeys,
) -> Result<PoiCorpusJournalCorruptionToken, DbError>
where
    BaseTable: ReadableTable<&'static str, &'static [u8]>,
    JournalTable: ReadableTable<&'static str, &'static [u8]>,
{
    let mut hasher = Sha256::new();
    hasher.update(b"railgun-poi-corpus-journal-replacement-token-v1");
    hasher.update((keys.base.len() as u64).to_be_bytes());
    hasher.update(keys.base.as_bytes());
    match base_table.get(keys.base.as_str())? {
        Some(value) => {
            hasher.update([1]);
            hasher.update((value.value().len() as u64).to_be_bytes());
            hasher.update(value.value());
        }
        None => hasher.update([0]),
    }

    let retired_head = journal_table.get(keys.head.as_str())?.and_then(|value| {
        decode_valid_journal_head(value.value(), &keys.head)
            .ok()
            .flatten()
    });
    let (replacement_revision, retired_delta_count, retired_delta_payload_bytes) = retired_head
        .map_or((0, 0, 0), |head| {
            (head.revision, head.delta_count, head.delta_payload_bytes)
        });

    let mut journal_row_count = 0_u64;
    let journal_range_end = prefix_range_end(&keys.identity_prefix);
    let mut range = match journal_range_end.as_deref() {
        Some(end) => journal_table.range(keys.identity_prefix.as_str()..end)?,
        None => journal_table.range(keys.identity_prefix.as_str()..)?,
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
    hasher.update((keys.delta_prefix.len() as u64).to_be_bytes());
    hasher.update(keys.delta_prefix.as_bytes());

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
