use alloy::hex;
use redb::{ReadableTable, WriteTransaction};

use super::{
    APP_SETTINGS_TABLE, DESKTOP_WALLET_VAULT_TABLE, DbError,
    LEGACY_DESKTOP_WALLET_CACHE_ROW_PREFIX, PENDING_OUTPUT_POI_CONTEXT_TABLE,
    POI_ARTIFACT_CACHE_GENERATION_KEY, POI_ARTIFACT_CACHE_TABLE, PendingOutputPoiContextRecord,
    PoiArtifactCacheRecord, WALLET_UTXO_TABLE, WalletCacheKey, decode, encode, prefix_range_end,
    wallet_utxo_key,
};

struct SchemaSevenWalletUtxoRow {
    source_key: String,
    wallet_id: WalletCacheKey,
    utxo_id: String,
    payload: Vec<u8>,
}

struct SchemaSevenPendingOutputPoiContextRow {
    source_key: String,
    destination_key: String,
    payload: Vec<u8>,
}

pub(super) fn migrate_schema_7_to_8(txn: &WriteTransaction) -> Result<(), DbError> {
    let wallet_utxos = schema_seven_wallet_utxo_rows(txn)?;
    let pending_contexts = schema_seven_pending_output_poi_context_rows(txn)?;

    {
        let mut table = txn.open_table(WALLET_UTXO_TABLE)?;
        for row in &wallet_utxos {
            let key = wallet_utxo_key(&row.wallet_id, &row.utxo_id);
            if table.get(key.as_str())?.is_some() {
                return Err(DbError::SchemaMigrationDestinationConflict {
                    table: "wallet_utxo",
                    key,
                });
            }
            table.insert(key.as_str(), row.payload.as_slice())?;
        }
    }
    {
        let mut table = txn.open_table(PENDING_OUTPUT_POI_CONTEXT_TABLE)?;
        for row in &pending_contexts {
            table.insert(row.destination_key.as_str(), row.payload.as_slice())?;
        }
        for row in &pending_contexts {
            table.remove(row.source_key.as_str())?;
        }
    }
    {
        let mut table = txn.open_table(DESKTOP_WALLET_VAULT_TABLE)?;
        for row in &wallet_utxos {
            table.remove(row.source_key.as_str())?;
        }
    }
    Ok(())
}

pub(super) fn migrate_schema_9_to_10(txn: &WriteTransaction) -> Result<(), DbError> {
    let generation = {
        let table = txn.open_table(APP_SETTINGS_TABLE)?;
        match table.get(POI_ARTIFACT_CACHE_GENERATION_KEY)? {
            Some(value) => decode(value.value())?,
            None => 0_u64,
        }
    };
    let records = {
        let table = txn.open_table(POI_ARTIFACT_CACHE_TABLE)?;
        let mut records = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            let key = key.value().to_string();
            let mut record = decode::<PoiArtifactCacheRecord>(value.value())
                .map_err(|_| DbError::InvalidSchemaNinePpoiCorpusRecord { key: key.clone() })?;
            if record.key() != key {
                return Err(DbError::InvalidSchemaNinePpoiCorpusRecord { key });
            }
            record.cache_generation = generation;
            records.push((key, encode(&record)?));
        }
        records
    };
    let mut table = txn.open_table(POI_ARTIFACT_CACHE_TABLE)?;
    for (key, payload) in records {
        table.insert(key.as_str(), payload.as_slice())?;
    }
    Ok(())
}

fn schema_seven_wallet_utxo_rows(
    txn: &WriteTransaction,
) -> Result<Vec<SchemaSevenWalletUtxoRow>, DbError> {
    let range_end = prefix_range_end(LEGACY_DESKTOP_WALLET_CACHE_ROW_PREFIX);
    let table = txn.open_table(DESKTOP_WALLET_VAULT_TABLE)?;
    let entries = match range_end.as_deref() {
        Some(range_end) => table.range(LEGACY_DESKTOP_WALLET_CACHE_ROW_PREFIX..range_end)?,
        None => table.range(LEGACY_DESKTOP_WALLET_CACHE_ROW_PREFIX..)?,
    };
    let mut rows = Vec::new();
    for entry in entries {
        let (key, value) = entry?;
        let key = key.value();
        let (wallet_id, utxo_id) = parse_schema_seven_wallet_utxo_key(key)?;
        rows.push(SchemaSevenWalletUtxoRow {
            source_key: key.to_owned(),
            wallet_id,
            utxo_id,
            payload: value.value().to_vec(),
        });
    }
    Ok(rows)
}

fn schema_seven_pending_output_poi_context_rows(
    txn: &WriteTransaction,
) -> Result<Vec<SchemaSevenPendingOutputPoiContextRow>, DbError> {
    let table = txn.open_table(PENDING_OUTPUT_POI_CONTEXT_TABLE)?;
    let mut rows = Vec::new();
    for entry in table.iter()? {
        let (key, value) = entry?;
        let source_key = key.value();
        let payload = value.value();
        let record = decode::<PendingOutputPoiContextRecord>(payload)
            .map_err(|_| invalid_pending_context(source_key))?;
        let wallet_id = record
            .wallet_id
            .parse::<WalletCacheKey>()
            .map_err(|_| invalid_pending_context(source_key))?;
        let expected_source_key = format!(
            "{}|{}",
            record.chain_id,
            hex::encode(record.output_commitment)
        );
        if source_key != expected_source_key {
            return Err(invalid_pending_context(source_key));
        }
        let destination_key = PendingOutputPoiContextRecord::key_for(
            record.chain_id,
            wallet_id.as_str(),
            &record.output_commitment,
        );
        if table.get(destination_key.as_str())?.is_some() {
            return Err(DbError::SchemaMigrationDestinationConflict {
                table: "pending_output_poi_context",
                key: destination_key,
            });
        }
        rows.push(SchemaSevenPendingOutputPoiContextRow {
            source_key: source_key.to_owned(),
            destination_key,
            payload: payload.to_vec(),
        });
    }
    Ok(rows)
}

fn parse_schema_seven_wallet_utxo_key(key: &str) -> Result<(WalletCacheKey, String), DbError> {
    let invalid = || DbError::InvalidLegacyDesktopWalletCacheRowKey {
        key: key.to_owned(),
    };
    let suffix = key
        .strip_prefix(LEGACY_DESKTOP_WALLET_CACHE_ROW_PREFIX)
        .ok_or_else(invalid)?;
    let (wallet_id, utxo_id) = suffix.split_once('|').ok_or_else(invalid)?;
    if wallet_id.len() != 32
        || utxo_id.len() != 64
        || utxo_id
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(invalid());
    }
    Ok((
        wallet_id.parse().map_err(|_| invalid())?,
        utxo_id.to_owned(),
    ))
}

fn invalid_pending_context(key: &str) -> DbError {
    DbError::InvalidSchemaSevenPendingOutputPoiContext {
        key: key.to_owned(),
    }
}
