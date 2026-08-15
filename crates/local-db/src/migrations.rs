use alloy::hex;
use alloy::primitives::Address;
use redb::{ReadableTable, WriteTransaction};
use std::collections::BTreeSet;

use super::{
    APP_SETTINGS_TABLE, DESKTOP_WALLET_VAULT_TABLE, DbError,
    LEGACY_DESKTOP_WALLET_CACHE_ROW_PREFIX, OUTPUT_POI_RECOVERY_TABLE, OutputPoiRecoveryRecord,
    PENDING_OUTPUT_POI_CONTEXT_TABLE, POI_ARTIFACT_CACHE_GENERATION_KEY, POI_ARTIFACT_CACHE_TABLE,
    PendingOutputPoiContextRecord, PoiArtifactCacheRecord, WALLET_META_TABLE, WALLET_UTXO_TABLE,
    WalletCacheKey, decode, encode, prefix_range_end, wallet_utxo_key,
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

struct LegacyCompositeWalletRow {
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
        let mut record = decode::<PendingOutputPoiContextRecord>(payload)
            .map_err(|_| invalid_pending_context(source_key))?;
        let (wallet_id, is_legacy) =
            parse_wallet_cache_key_with_legacy_composite_support(&record.wallet_id)
                .map_err(|()| invalid_pending_context(source_key))?;
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
        let payload = if is_legacy {
            record.wallet_id = wallet_id.to_string();
            encode(&record)?
        } else {
            payload.to_vec()
        };
        rows.push(SchemaSevenPendingOutputPoiContextRow {
            source_key: source_key.to_owned(),
            destination_key,
            payload,
        });
    }
    Ok(rows)
}

pub(super) fn migrate_legacy_composite_wallet_keys(txn: &WriteTransaction) -> Result<(), DbError> {
    let wallet_meta_rows = legacy_composite_wallet_meta_rows(txn)?;
    let wallet_utxo_rows = legacy_composite_wallet_utxo_rows(txn)?;
    let pending_context_rows = legacy_composite_pending_output_poi_context_rows(txn)?;
    let output_recovery_rows = legacy_composite_output_poi_recovery_rows(txn)?;

    preflight_legacy_composite_wallet_rows(
        txn,
        WALLET_META_TABLE,
        "wallet_meta",
        &wallet_meta_rows,
    )?;
    preflight_legacy_composite_wallet_rows(
        txn,
        WALLET_UTXO_TABLE,
        "wallet_utxo",
        &wallet_utxo_rows,
    )?;
    preflight_legacy_composite_wallet_rows(
        txn,
        PENDING_OUTPUT_POI_CONTEXT_TABLE,
        "pending_output_poi_context",
        &pending_context_rows,
    )?;
    preflight_legacy_composite_wallet_rows(
        txn,
        OUTPUT_POI_RECOVERY_TABLE,
        "output_poi_recovery",
        &output_recovery_rows,
    )?;

    apply_legacy_composite_wallet_rows(txn, WALLET_META_TABLE, &wallet_meta_rows)?;
    apply_legacy_composite_wallet_rows(txn, WALLET_UTXO_TABLE, &wallet_utxo_rows)?;
    apply_legacy_composite_wallet_rows(
        txn,
        PENDING_OUTPUT_POI_CONTEXT_TABLE,
        &pending_context_rows,
    )?;
    apply_legacy_composite_wallet_rows(txn, OUTPUT_POI_RECOVERY_TABLE, &output_recovery_rows)?;
    Ok(())
}

fn legacy_composite_wallet_meta_rows(
    txn: &WriteTransaction,
) -> Result<Vec<LegacyCompositeWalletRow>, DbError> {
    let table = txn.open_table(WALLET_META_TABLE)?;
    let mut rows = Vec::new();
    for entry in table.iter()? {
        let (key, value) = entry?;
        let source_key = key.value();
        if !source_key.contains('|') {
            continue;
        }
        let wallet_id = parse_legacy_composite_wallet_key(source_key)
            .map_err(|()| invalid_legacy_composite_wallet_row("wallet_meta", source_key))?;
        rows.push(LegacyCompositeWalletRow {
            source_key: source_key.to_owned(),
            destination_key: wallet_id.to_string(),
            payload: value.value().to_vec(),
        });
    }
    Ok(rows)
}

fn legacy_composite_wallet_utxo_rows(
    txn: &WriteTransaction,
) -> Result<Vec<LegacyCompositeWalletRow>, DbError> {
    let table = txn.open_table(WALLET_UTXO_TABLE)?;
    let mut rows = Vec::new();
    for entry in table.iter()? {
        let (key, value) = entry?;
        let source_key = key.value();
        let Some((legacy_wallet_key, utxo_id)) = source_key.rsplit_once('|') else {
            continue;
        };
        if !legacy_wallet_key.contains('|') {
            continue;
        }
        let wallet_id = parse_legacy_composite_wallet_key(legacy_wallet_key)
            .map_err(|()| invalid_legacy_composite_wallet_row("wallet_utxo", source_key))?;
        rows.push(LegacyCompositeWalletRow {
            source_key: source_key.to_owned(),
            destination_key: wallet_utxo_key(&wallet_id, utxo_id),
            payload: value.value().to_vec(),
        });
    }
    Ok(rows)
}

fn legacy_composite_pending_output_poi_context_rows(
    txn: &WriteTransaction,
) -> Result<Vec<LegacyCompositeWalletRow>, DbError> {
    let table = txn.open_table(PENDING_OUTPUT_POI_CONTEXT_TABLE)?;
    let mut rows = Vec::new();
    for entry in table.iter()? {
        let (key, value) = entry?;
        let source_key = key.value();
        let mut record: PendingOutputPoiContextRecord = decode(value.value()).map_err(|_| {
            invalid_legacy_composite_wallet_row("pending_output_poi_context", source_key)
        })?;
        if !record.wallet_id.contains('|') {
            continue;
        }
        let wallet_id = parse_legacy_composite_wallet_key(&record.wallet_id).map_err(|()| {
            invalid_legacy_composite_wallet_row("pending_output_poi_context", source_key)
        })?;
        let expected_legacy_key = record.key();
        let expected_schema_seven_key = format!(
            "{}|{}",
            record.chain_id,
            hex::encode(record.output_commitment)
        );
        if source_key != expected_legacy_key && source_key != expected_schema_seven_key {
            return Err(invalid_legacy_composite_wallet_row(
                "pending_output_poi_context",
                source_key,
            ));
        }
        record.wallet_id = wallet_id.to_string();
        rows.push(LegacyCompositeWalletRow {
            source_key: source_key.to_owned(),
            destination_key: record.key(),
            payload: encode(&record)?,
        });
    }
    Ok(rows)
}

fn legacy_composite_output_poi_recovery_rows(
    txn: &WriteTransaction,
) -> Result<Vec<LegacyCompositeWalletRow>, DbError> {
    let table = txn.open_table(OUTPUT_POI_RECOVERY_TABLE)?;
    let mut rows = Vec::new();
    for entry in table.iter()? {
        let (key, value) = entry?;
        let source_key = key.value();
        let mut record: OutputPoiRecoveryRecord = decode(value.value())
            .map_err(|_| invalid_legacy_composite_wallet_row("output_poi_recovery", source_key))?;
        if !record.wallet_id.contains('|') {
            continue;
        }
        let wallet_id = parse_legacy_composite_wallet_key(&record.wallet_id)
            .map_err(|()| invalid_legacy_composite_wallet_row("output_poi_recovery", source_key))?;
        if source_key != record.key() {
            return Err(invalid_legacy_composite_wallet_row(
                "output_poi_recovery",
                source_key,
            ));
        }
        record.wallet_id = wallet_id.to_string();
        rows.push(LegacyCompositeWalletRow {
            source_key: source_key.to_owned(),
            destination_key: record.key(),
            payload: encode(&record)?,
        });
    }
    Ok(rows)
}

fn preflight_legacy_composite_wallet_rows(
    txn: &WriteTransaction,
    table_definition: super::ByteTableDefinition,
    table_name: &'static str,
    rows: &[LegacyCompositeWalletRow],
) -> Result<(), DbError> {
    let table = txn.open_table(table_definition)?;
    let mut destinations = BTreeSet::new();
    for row in rows {
        if !destinations.insert(row.destination_key.clone())
            || table.get(row.destination_key.as_str())?.is_some()
        {
            return Err(DbError::SchemaMigrationDestinationConflict {
                table: table_name,
                key: row.destination_key.clone(),
            });
        }
    }
    Ok(())
}

fn apply_legacy_composite_wallet_rows(
    txn: &WriteTransaction,
    table_definition: super::ByteTableDefinition,
    rows: &[LegacyCompositeWalletRow],
) -> Result<(), DbError> {
    let mut table = txn.open_table(table_definition)?;
    for row in rows {
        table.insert(row.destination_key.as_str(), row.payload.as_slice())?;
    }
    for row in rows {
        table.remove(row.source_key.as_str())?;
    }
    Ok(())
}

fn parse_wallet_cache_key_with_legacy_composite_support(
    value: &str,
) -> Result<(WalletCacheKey, bool), ()> {
    if value.contains('|') {
        parse_legacy_composite_wallet_key(value).map(|key| (key, true))
    } else {
        value.parse().map(|key| (key, false)).map_err(|_| ())
    }
}

// Historical wallet namespace keys used `{wallet_id}|{chain_id}|{contract_address}`.
fn parse_legacy_composite_wallet_key(value: &str) -> Result<WalletCacheKey, ()> {
    let mut parts = value.rsplitn(3, '|');
    let contract = parts.next().ok_or(())?;
    let chain_id = parts.next().ok_or(())?.parse::<u64>().map_err(|_| ())?;
    let wallet_id = parts.next().ok_or(())?;
    if wallet_id.is_empty() {
        return Err(());
    }
    let contract = contract.parse::<Address>().map_err(|_| ())?;
    Ok(WalletCacheKey::new(wallet_id, chain_id, contract))
}

fn invalid_legacy_composite_wallet_row(table: &'static str, key: &str) -> DbError {
    DbError::InvalidLegacyCompositeWalletRow {
        table,
        key: key.to_owned(),
    }
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
