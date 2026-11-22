//! The public cache record of a chain's last accepted amount-statistics snapshot.

use alloy::primitives::{Bytes, FixedBytes};
use local_db::{AppTable, DbError, DbStore};
use serde::{Deserialize, Serialize};

use super::AmountStatisticsRefreshError;
use crate::indexed_artifacts::{ChainScope, format_scope};

/// One row per chain scope, outside the wallet vault. Each write replaces a whole row in one
/// transaction, so a reader sees the old record or the new one.
pub(crate) const AMOUNT_STATISTICS_TABLE: AppTable = AppTable::new("sync_amount_statistics_v1");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AmountStatisticsSourceIdentity {
    pub(crate) ipns_name: String,
    pub(crate) publisher_key: FixedBytes<32>,
}

/// Public data only: where the snapshot came from, its manifest sequence and descriptor, and
/// its bytes. Nothing in it identifies a wallet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StoredAmountStatistics {
    pub(crate) source: AmountStatisticsSourceIdentity,
    /// The last accepted manifest sequence, below which no manifest from this source is used.
    pub(crate) sequence: u64,
    pub(crate) cid: String,
    pub(crate) sha256: FixedBytes<32>,
    /// The compressed snapshot exactly as fetched.
    pub(crate) snapshot: Bytes,
}

/// The stored record for `scope` from `source`. A record from another source, or one that no
/// longer decodes, is deleted.
pub(crate) fn load_amount_statistics(
    db: &DbStore,
    scope: &ChainScope,
    source: &AmountStatisticsSourceIdentity,
) -> Result<Option<StoredAmountStatistics>, DbError> {
    let key = format_scope(scope);
    db.write_app_tables(|tables| {
        let Some(bytes) = tables.get(AMOUNT_STATISTICS_TABLE, &key)? else {
            return Ok(None);
        };
        match decode_record(&bytes) {
            Some(record) if record.source == *source => Ok(Some(record)),
            _ => {
                tables.remove(AMOUNT_STATISTICS_TABLE, &key)?;
                Ok(None)
            }
        }
    })
}

/// Replaces the record for `scope` unless the stored one is from the same source with a
/// higher sequence. Returns whether `record` was stored.
pub(crate) fn replace_amount_statistics(
    db: &DbStore,
    scope: &ChainScope,
    record: &StoredAmountStatistics,
) -> Result<bool, AmountStatisticsRefreshError> {
    let key = format_scope(scope);
    let encoded = rmp_serde::to_vec_named(record)?;
    db.write_app_tables(|tables| {
        let newer_stored = tables
            .get(AMOUNT_STATISTICS_TABLE, &key)?
            .and_then(|bytes| decode_record(&bytes))
            .is_some_and(|stored| {
                stored.source == record.source && stored.sequence > record.sequence
            });
        if newer_stored {
            return Ok(false);
        }
        tables.insert(AMOUNT_STATISTICS_TABLE, &key, &encoded)?;
        Ok(true)
    })
}

/// Deletes every stored record and returns how many there were.
pub(crate) fn clear_amount_statistics(db: &DbStore) -> Result<u64, DbError> {
    db.write_app_tables(|tables| {
        let rows = tables.list_prefix(AMOUNT_STATISTICS_TABLE, "")?;
        for (key, _) in &rows {
            tables.remove(AMOUNT_STATISTICS_TABLE, key)?;
        }
        Ok(rows.len() as u64)
    })
}

fn decode_record(bytes: &[u8]) -> Option<StoredAmountStatistics> {
    rmp_serde::from_slice(bytes).ok()
}
