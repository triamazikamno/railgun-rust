use std::cell::Cell;

use redb::{
    ReadOnlyTable, ReadTransaction, ReadableDatabase, ReadableTable, Table, TableDefinition,
    WriteTransaction,
};

use super::{ByteTableDefinition, DbError, DbStore, LOCAL_DB_TABLES, list_table_prefix};

/// A byte table owned by an application rather than by `local-db`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AppTable(&'static str);

impl AppTable {
    #[must_use]
    pub const fn new(name: &'static str) -> Self {
        Self(name)
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        self.0
    }

    fn definition(self) -> Result<ByteTableDefinition, DbError> {
        if LOCAL_DB_TABLES.iter().any(|info| info.name == self.0) {
            return Err(DbError::ReservedTableName { table: self.0 });
        }
        Ok(TableDefinition::new(self.0))
    }
}

/// Reads application tables inside one `local-db` read transaction.
pub struct AppTableReader<'txn> {
    txn: &'txn ReadTransaction,
}

impl AppTableReader<'_> {
    pub fn get(&self, table: AppTable, key: &str) -> Result<Option<Vec<u8>>, DbError> {
        match self.open(table)? {
            Some(table) => Ok(table.get(key)?.map(|value| value.value().to_vec())),
            None => Ok(None),
        }
    }

    /// Lists the rows whose key starts with `prefix`, in key order.
    pub fn list_prefix(
        &self,
        table: AppTable,
        prefix: &str,
    ) -> Result<Vec<(String, Vec<u8>)>, DbError> {
        match self.open(table)? {
            Some(table) => list_table_prefix(&table, prefix),
            None => Ok(Vec::new()),
        }
    }

    fn open(
        &self,
        table: AppTable,
    ) -> Result<Option<ReadOnlyTable<&'static str, &'static [u8]>>, DbError> {
        match self.txn.open_table(table.definition()?) {
            Ok(table) => Ok(Some(table)),
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}

/// Reads and writes application tables inside one `local-db` write transaction.
pub struct AppTableWriter<'txn> {
    txn: &'txn WriteTransaction,
    rejected: Cell<Option<AppTable>>,
}

impl<'txn> AppTableWriter<'txn> {
    pub fn get(&self, table: AppTable, key: &str) -> Result<Option<Vec<u8>>, DbError> {
        let table = self.open(table)?;
        Ok(table.get(key)?.map(|value| value.value().to_vec()))
    }

    /// Lists the rows whose key starts with `prefix`, in key order.
    pub fn list_prefix(
        &self,
        table: AppTable,
        prefix: &str,
    ) -> Result<Vec<(String, Vec<u8>)>, DbError> {
        list_table_prefix(&self.open(table)?, prefix)
    }

    pub fn insert(&mut self, table: AppTable, key: &str, value: &[u8]) -> Result<(), DbError> {
        self.open(table)?.insert(key, value)?;
        Ok(())
    }

    /// Removes `key` and returns whether the row existed.
    pub fn remove(&mut self, table: AppTable, key: &str) -> Result<bool, DbError> {
        let mut table = self.open(table)?;
        Ok(table.remove(key)?.is_some())
    }

    fn open(&self, table: AppTable) -> Result<Table<'txn, &'static str, &'static [u8]>, DbError> {
        let definition = table.definition().inspect_err(|_| {
            self.rejected.set(self.rejected.get().or(Some(table)));
        })?;
        Ok(self.txn.open_table(definition)?)
    }

    /// Runs `write`, then fails if it touched a reserved name even when it swallowed that
    /// error, so the caller never commits such a transaction.
    pub(crate) fn run<T, E: From<DbError>>(
        txn: &'txn WriteTransaction,
        write: impl FnOnce(&mut AppTableWriter<'_>) -> Result<T, E>,
    ) -> Result<T, E> {
        let mut writer = Self {
            txn,
            rejected: Cell::new(None),
        };
        let value = write(&mut writer)?;
        match writer.rejected.get() {
            Some(table) => Err(DbError::ReservedTableName {
                table: table.name(),
            }
            .into()),
            None => Ok(value),
        }
    }
}

impl DbStore {
    /// Runs `read` against application tables in one read transaction.
    pub fn read_app_tables<T, E: From<DbError>>(
        &self,
        read: impl FnOnce(&AppTableReader<'_>) -> Result<T, E>,
    ) -> Result<T, E> {
        let txn = self.db.begin_read().map_err(DbError::from)?;
        read(&AppTableReader { txn: &txn })
    }

    /// Runs `write` against application tables in one write transaction and commits only
    /// when it returns `Ok`.
    pub fn write_app_tables<T, E: From<DbError>>(
        &self,
        write: impl FnOnce(&mut AppTableWriter<'_>) -> Result<T, E>,
    ) -> Result<T, E> {
        let txn = self.db.begin_write().map_err(DbError::from)?;
        let value = AppTableWriter::run(&txn, write)?;
        txn.commit().map_err(DbError::from)?;
        Ok(value)
    }
}
