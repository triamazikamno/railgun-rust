use std::io::Cursor;

use redb::{ReadableDatabase, ReadableTable, Table, TableDefinition};
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::{DbError, DbStore};

impl DbStore {
    pub(crate) fn list_decoded_by_prefix<T>(
        &self,
        table_def: TableDefinition<'static, &str, &[u8]>,
        prefix: &str,
    ) -> Result<Vec<T>, DbError>
    where
        T: DeserializeOwned,
    {
        let range_end = prefix_range_end(prefix);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(table_def)?;
        let mut out = Vec::new();
        let entries = match range_end.as_deref() {
            Some(range_end) => table.range(prefix..range_end)?,
            None => table.range(prefix..)?,
        };
        for entry in entries {
            let (_, value) = entry?;
            out.push(decode(value.value())?);
        }
        Ok(out)
    }
}

pub(crate) fn table_prefix_has_rows<TableType>(
    table: &TableType,
    prefix: &str,
) -> Result<bool, DbError>
where
    TableType: ReadableTable<&'static str, &'static [u8]>,
{
    let range_end = prefix_range_end(prefix);
    let mut range = match range_end.as_deref() {
        Some(end) => table.range(prefix..end)?,
        None => table.range(prefix..)?,
    };
    Ok(range.next().transpose()?.is_some())
}

pub(crate) fn list_table_prefix<TableType>(
    table: &TableType,
    prefix: &str,
) -> Result<Vec<(String, Vec<u8>)>, DbError>
where
    TableType: ReadableTable<&'static str, &'static [u8]>,
{
    let range_end = prefix_range_end(prefix);
    let entries = match range_end.as_deref() {
        Some(end) => table.range(prefix..end)?,
        None => table.range(prefix..)?,
    };
    let mut out = Vec::new();
    for entry in entries {
        let (key, value) = entry?;
        out.push((key.value().to_string(), value.value().to_vec()));
    }
    Ok(out)
}

pub(crate) fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, DbError> {
    Ok(rmp_serde::to_vec_named(value)?)
}

pub(crate) fn decode<T: DeserializeOwned>(data: &[u8]) -> Result<T, DbError> {
    let mut deserializer = rmp_serde::Deserializer::new(Cursor::new(data));
    let value = T::deserialize(&mut deserializer)?;
    if deserializer.get_ref().position() != u64::try_from(data.len()).unwrap_or(u64::MAX) {
        return Err(rmp_serde::decode::Error::Syntax(
            "trailing bytes after MessagePack value".to_string(),
        )
        .into());
    }
    Ok(value)
}

pub(crate) fn remove_table_prefix(
    table: &mut Table<'_, &str, &[u8]>,
    prefix: &str,
) -> Result<u64, DbError> {
    remove_table_prefix_matching(table, prefix, |_| true)
}

pub(crate) fn remove_table_prefix_matching(
    table: &mut Table<'_, &str, &[u8]>,
    prefix: &str,
    mut matches: impl FnMut(&str) -> bool,
) -> Result<u64, DbError> {
    let range_end = prefix_range_end(prefix);
    let mut removed = 0_u64;
    let mut retain = |key: &str, _: &[u8]| {
        let remove = matches(key);
        if remove {
            removed = removed.saturating_add(1);
        }
        !remove
    };
    match range_end.as_deref() {
        Some(range_end) => {
            table.retain_in(prefix..range_end, &mut retain)?;
        }
        None => {
            table.retain_in(prefix.., &mut retain)?;
        }
    }
    Ok(removed)
}

pub(crate) fn prefix_range_end(prefix: &str) -> Option<String> {
    let mut end = prefix.to_string();
    while let Some(last) = end.pop() {
        let mut next = u32::from(last).saturating_add(1);
        while next <= u32::from(char::MAX) {
            if let Some(next) = char::from_u32(next) {
                end.push(next);
                return Some(end);
            }
            next = next.saturating_add(1);
        }
    }
    None
}
