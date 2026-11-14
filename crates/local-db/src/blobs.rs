use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use redb::ReadableDatabase;
use serde::{Deserialize, Serialize};

use super::{
    BLOB_INDEX_TABLE, BLOBS_DIR, DbError, DbStore, MERKLE_FOREST_INDEX_TABLE, ZKEY_INDEX_TABLE,
    decode, encode, prefix_range_end,
};

static BLOB_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobMeta {
    pub format_version: u32,
    pub relative_path: String,
    pub content_hash: [u8; 32],
    #[serde(default)]
    pub source_hash: Option<[u8; 32]>,
    #[serde(default)]
    pub source_sequence: Option<u64>,
    pub created_at: u64,
    pub updated_at: u64,
    #[serde(default)]
    pub last_accessed_at: u64,
    pub last_block: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct CanonicalBlobMetaIdentity {
    kind: String,
    leaf: String,
}

impl CanonicalBlobMetaIdentity {
    pub fn from_leaf(expected_kind: &str, leaf: &str) -> Result<Self, DbError> {
        validate_single_blob_component(expected_kind, expected_kind)?;
        validate_single_blob_component(leaf, expected_kind)?;
        Ok(Self {
            kind: expected_kind.to_string(),
            leaf: leaf.to_string(),
        })
    }

    #[must_use]
    pub fn relative_path(&self) -> String {
        Self::relative_path_for(&self.kind, &self.leaf)
    }

    fn relative_path_for(kind: &str, leaf: &str) -> String {
        format!("{BLOBS_DIR}/{kind}/{leaf}")
    }

    fn kind(&self) -> &str {
        &self.kind
    }

    fn leaf(&self) -> &str {
        &self.leaf
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleForestMeta {
    pub relative_path: String,
    pub last_block: u64,
    pub format_version: u32,
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkeyMeta {
    pub relative_path: String,
    pub zkey_hash: [u8; 32],
    #[serde(default)]
    pub cache_hash: Option<[u8; 32]>,
    pub format_version: u32,
}

impl DbStore {
    pub fn ensure_blob_dir(&self, kind: &str) -> Result<PathBuf, DbError> {
        validate_single_blob_component(kind, kind)?;
        ensure_storage_directory(&self.blob_dir(), BLOBS_DIR)?;
        let dir = self.blob_dir().join(kind);
        ensure_storage_directory(&dir, kind)?;
        Ok(dir)
    }

    #[must_use]
    pub fn blob_path(&self, kind: &str, name: &str) -> PathBuf {
        self.blob_dir().join(kind).join(name)
    }

    #[must_use]
    pub fn resolve_path(&self, relative_path: &str) -> PathBuf {
        let path = PathBuf::from(relative_path);
        if path.is_absolute() {
            path
        } else {
            self.railgun_dir().join(path)
        }
    }

    #[must_use]
    pub fn relative_path(&self, path: &Path) -> String {
        if let Ok(relative) = path.strip_prefix(self.railgun_dir()) {
            relative.to_string_lossy().to_string()
        } else {
            path.to_string_lossy().to_string()
        }
    }

    #[must_use]
    pub fn relative_blob_path(kind: &str, name: &str) -> String {
        format!("{BLOBS_DIR}/{kind}/{name}")
    }

    pub fn open_blob_meta_file(
        &self,
        identity: &CanonicalBlobMetaIdentity,
    ) -> Result<Option<File>, DbError> {
        let kind_dir = self.blob_dir().join(identity.kind());
        if !validate_existing_blob_directory(&kind_dir, identity.kind())? {
            return Ok(None);
        }
        let path = kind_dir.join(identity.leaf());
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(DbError::UnsafeBlobEntry {
                kind: identity.kind().to_string(),
            });
        }
        let file = File::open(path)?;
        Ok(Some(file))
    }

    pub fn replace_blob_file_atomic(
        &self,
        kind: &str,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), DbError> {
        self.replace_blob_file_atomic_impl(kind, name, bytes, None)
    }

    pub fn purge_blob_kind(&self, kind: &str) -> Result<(), DbError> {
        self.ensure_blob_kind_purge_supported(kind)?;
        ensure_storage_directory(&self.blob_dir(), BLOBS_DIR)?;
        let kind_dir = self.blob_dir().join(kind);
        match std::fs::symlink_metadata(&kind_dir) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                std::fs::remove_dir_all(&kind_dir)?;
            }
            Ok(_metadata) => {
                #[cfg(windows)]
                {
                    use std::os::windows::fs::FileTypeExt;

                    if _metadata.file_type().is_symlink_dir() {
                        std::fs::remove_dir(&kind_dir)?;
                    } else {
                        std::fs::remove_file(&kind_dir)?;
                    }
                }
                #[cfg(not(windows))]
                std::fs::remove_file(&kind_dir)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        ensure_storage_directory(&kind_dir, kind)
    }

    pub fn ensure_blob_kind_purge_supported(&self, kind: &str) -> Result<(), DbError> {
        validate_single_blob_component(kind, kind)
    }

    fn replace_blob_file_atomic_impl(
        &self,
        kind: &str,
        name: &str,
        bytes: &[u8],
        forced_temp_name: Option<&str>,
    ) -> Result<(), DbError> {
        validate_single_blob_component(kind, kind)?;
        validate_single_blob_component(name, kind)?;
        if let Some(temp_name) = forced_temp_name {
            validate_single_blob_component(temp_name, kind)?;
        }
        let parent = self.ensure_blob_dir(kind)?;
        let (temp_path, mut temp_file) = loop {
            let temp_name = forced_temp_name.map_or_else(
                || {
                    let nonce = BLOB_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
                    format!(".railgun-blob-{}-{nonce}.tmp", std::process::id())
                },
                ToString::to_string,
            );
            let temp_path = parent.join(temp_name);
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)
            {
                Ok(file) => break (temp_path, file),
                Err(error)
                    if forced_temp_name.is_none()
                        && error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        };
        let mut guard = BlobTempGuard::new(temp_path);
        temp_file.write_all(bytes)?;
        drop(temp_file);
        let final_path = parent.join(name);
        validate_blob_replace_destination(&final_path, kind)?;
        std::fs::rename(guard.path(), final_path)?;
        guard.disarm();
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn replace_blob_file_atomic_with_test_temp_name(
        &self,
        kind: &str,
        name: &str,
        bytes: &[u8],
        temp_name: &str,
    ) -> Result<(), DbError> {
        self.replace_blob_file_atomic_impl(kind, name, bytes, Some(temp_name))
    }

    pub fn get_blob_meta(&self, kind: &str, id: &str) -> Result<Option<BlobMeta>, DbError> {
        let key = blob_index_key(kind, id);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(BLOB_INDEX_TABLE)?;
        match table.get(key.as_str())? {
            Some(value) => Ok(Some(decode(value.value())?)),
            None => Ok(None),
        }
    }

    pub fn put_blob_meta(&self, kind: &str, id: &str, meta: &BlobMeta) -> Result<(), DbError> {
        let key = blob_index_key(kind, id);
        let data = encode(meta)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(BLOB_INDEX_TABLE)?;
            table.insert(key.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn clear_blob_meta_kind(&self, kind: &str) -> Result<u64, DbError> {
        let prefix = format!("{kind}|");
        let range_end = prefix_range_end(&prefix);
        let txn = self.db.begin_write()?;
        let removed = {
            let mut table = txn.open_table(BLOB_INDEX_TABLE)?;
            let mut removed = 0_u64;
            let mut retain = |_: &str, _: &[u8]| {
                removed = removed.saturating_add(1);
                false
            };
            match range_end.as_deref() {
                Some(range_end) => {
                    table.retain_in(prefix.as_str()..range_end, &mut retain)?;
                }
                None => {
                    table.retain_in(prefix.as_str().., &mut retain)?;
                }
            }
            removed
        };
        txn.commit()?;
        Ok(removed)
    }

    pub fn get_merkle_forest_meta(
        &self,
        chain_id: u64,
        contract: &str,
    ) -> Result<Option<MerkleForestMeta>, DbError> {
        let key = merkle_forest_key(chain_id, contract);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(MERKLE_FOREST_INDEX_TABLE)?;
        match table.get(key.as_str())? {
            Some(value) => Ok(Some(decode(value.value())?)),
            None => Ok(None),
        }
    }

    pub fn put_merkle_forest_meta(
        &self,
        chain_id: u64,
        contract: &str,
        meta: &MerkleForestMeta,
    ) -> Result<(), DbError> {
        let key = merkle_forest_key(chain_id, contract);
        let data = encode(meta)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(MERKLE_FOREST_INDEX_TABLE)?;
            table.insert(key.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get_zkey_meta(&self, variant: &str) -> Result<Option<ZkeyMeta>, DbError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(ZKEY_INDEX_TABLE)?;
        match table.get(variant)? {
            Some(value) => Ok(Some(decode(value.value())?)),
            None => Ok(None),
        }
    }

    pub fn put_zkey_meta(&self, variant: &str, meta: &ZkeyMeta) -> Result<(), DbError> {
        let data = encode(meta)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(ZKEY_INDEX_TABLE)?;
            table.insert(variant, data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn update_merkle_forest_meta(
        &self,
        chain_id: u64,
        contract_address: &str,
        path: &Path,
        last_block: u64,
        format_version: u32,
        hash: [u8; 32],
    ) -> Result<(), DbError> {
        let meta = MerkleForestMeta {
            relative_path: self.relative_path(path),
            last_block,
            format_version,
            hash,
        };
        self.put_merkle_forest_meta(chain_id, contract_address, &meta)
    }
}

fn validate_single_blob_component(value: &str, kind: &str) -> Result<(), DbError> {
    let mut components = Path::new(value).components();
    if value.is_empty()
        || value.contains(['/', '\\', '\0', ':'])
        || !matches!(components.next(), Some(Component::Normal(component)) if component == OsStr::new(value))
        || components.next().is_some()
    {
        return Err(DbError::InvalidBlobRelativePath {
            kind: kind.to_string(),
        });
    }
    Ok(())
}

struct BlobTempGuard {
    path: PathBuf,
    armed: bool,
}

impl BlobTempGuard {
    const fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    const fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for BlobTempGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

pub(crate) fn ensure_storage_directory(path: &Path, kind: &str) -> Result<(), DbError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(DbError::InvalidBlobRelativePath {
            kind: kind.to_string(),
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match std::fs::create_dir(path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    ensure_storage_directory(path, kind)
                }
                Err(error) => Err(error.into()),
            }
        }
        Err(error) => Err(error.into()),
    }
}

fn validate_existing_blob_directory(path: &Path, kind: &str) -> Result<bool, DbError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(true),
        Ok(_) => Err(DbError::UnsafeBlobEntry {
            kind: kind.to_string(),
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn validate_blob_replace_destination(path: &Path, kind: &str) -> Result<(), DbError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(DbError::UnsafeBlobEntry {
            kind: kind.to_string(),
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn blob_index_key(kind: &str, id: &str) -> String {
    format!("{kind}|{id}")
}

fn merkle_forest_key(chain_id: u64, contract: &str) -> String {
    format!("{chain_id}|{contract}")
}
