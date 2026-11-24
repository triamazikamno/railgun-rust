use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use local_db::{BlobMeta, DbError, DbStore};
use sha2::{Digest, Sha256};
use thiserror::Error;
use wasmer::{Module, Store};
use zeroize::Zeroizing;

const WASM_MODULE_CACHE_KIND: &str = "wasm-module";
const WASM_MODULE_CACHE_MAGIC: &[u8; 8] = b"RWMODCCH";
const WASM_MODULE_CACHE_FILE_VERSION: u32 = 1;
const WASM_MODULE_CACHE_FORMAT_VERSION: u32 = 3;
const WASM_MODULE_CACHE_ENGINE_VERSION: &str = "wasmer-6.1.0";
const WASM_MODULE_CACHE_TAG_DOMAIN: &[u8] = b"railgun-wallet/wasm-module-cache-tag/v1";

type HmacSha256 = Hmac<Sha256>;

/// Secret key that authenticates compiled wasm module cache entries before they are loaded
/// as native code.
///
/// The key must not be stored in, or derivable from, anything a cache writer can modify, such
/// as the profile directory. Otherwise the cache becomes a way to load attacker-supplied native
/// code.
pub struct WasmModuleCacheKey(Zeroizing<[u8; 32]>);

impl WasmModuleCacheKey {
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

impl fmt::Debug for WasmModuleCacheKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WasmModuleCacheKey(<redacted>)")
    }
}

#[derive(Debug, Error)]
pub(crate) enum WasmModuleCacheError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("db error: {0}")]
    Db(#[from] DbError),
    #[error("cache format mismatch")]
    FormatMismatch,
    #[error("cache version mismatch")]
    VersionMismatch,
    #[error("module compile failed: {0}")]
    Compile(String),
    #[error("module serialize failed: {0}")]
    Serialize(String),
    #[error("module deserialize failed: {0}")]
    Deserialize(String),
}

pub(crate) struct CachedWasmModule {
    pub(crate) module: Module,
    pub(crate) cache_hit: bool,
}

pub(crate) fn load_or_compile_wasm_module(
    db: Option<&DbStore>,
    cache_key: Option<&WasmModuleCacheKey>,
    store: &Store,
    variant: &str,
    compiler: &str,
    wasm: &[u8],
) -> Result<CachedWasmModule, WasmModuleCacheError> {
    let wasm_hash: [u8; 32] = Sha256::digest(wasm).into();
    let cache_id = module_cache_id(variant, compiler);
    // Without a key the native module cache is never read or written.
    let cache = db.zip(cache_key);
    if let Some((db, cache_key)) = cache {
        match load_wasm_module_cache(db, cache_key, store, &cache_id, wasm_hash) {
            Ok(Some(module)) => {
                return Ok(CachedWasmModule {
                    module,
                    cache_hit: true,
                });
            }
            Ok(None) => {}
            Err(err) => tracing::warn!(
                ?err,
                variant,
                compiler,
                "failed to load compiled wasm module cache"
            ),
        }
    }

    let module =
        Module::new(store, wasm).map_err(|err| WasmModuleCacheError::Compile(err.to_string()))?;
    if let Some((db, cache_key)) = cache
        && let Err(err) = write_wasm_module_cache(db, cache_key, &cache_id, wasm_hash, &module)
    {
        tracing::warn!(
            ?err,
            variant,
            compiler,
            "failed to write compiled wasm module cache"
        );
    }

    Ok(CachedWasmModule {
        module,
        cache_hit: false,
    })
}

pub(crate) fn wasm_module_cache_exists(
    db: &DbStore,
    cache_key: Option<&WasmModuleCacheKey>,
    variant: &str,
    compiler: &str,
    wasm: &[u8],
) -> Result<bool, WasmModuleCacheError> {
    let Some(cache_key) = cache_key else {
        return Ok(false);
    };
    let wasm_hash: [u8; 32] = Sha256::digest(wasm).into();
    let cache_id = module_cache_id(variant, compiler);
    Ok(read_authenticated_cache(db, cache_key, &cache_id, wasm_hash)?.is_some())
}

/// Returns the cache file bytes only when their tag verifies under `cache_key`.
fn read_authenticated_cache(
    db: &DbStore,
    cache_key: &WasmModuleCacheKey,
    cache_id: &str,
    wasm_hash: [u8; 32],
) -> Result<Option<Vec<u8>>, WasmModuleCacheError> {
    let Some(meta) = db.get_blob_meta(WASM_MODULE_CACHE_KIND, cache_id)? else {
        return Ok(None);
    };
    if !wasm_module_meta_matches(&meta, wasm_hash) {
        return Ok(None);
    }

    let path = db.resolve_path(&meta.relative_path);
    if !path.exists() {
        return Ok(None);
    }

    let cache_bytes = std::fs::read(path)?;
    if cache_tag_mac(cache_key, cache_id, wasm_hash, &cache_bytes)
        .verify_slice(&meta.content_hash)
        .is_err()
    {
        return Ok(None);
    }
    Ok(Some(cache_bytes))
}

fn cache_tag_mac(
    cache_key: &WasmModuleCacheKey,
    cache_id: &str,
    wasm_hash: [u8; 32],
    cache_bytes: &[u8],
) -> HmacSha256 {
    let Ok(mut mac) = HmacSha256::new_from_slice(cache_key.0.as_slice()) else {
        unreachable!("HMAC accepts any key length");
    };
    mac.update(WASM_MODULE_CACHE_TAG_DOMAIN);
    mac.update(&(cache_id.len() as u64).to_le_bytes());
    mac.update(cache_id.as_bytes());
    mac.update(&wasm_hash);
    mac.update(cache_bytes);
    mac
}

fn load_wasm_module_cache(
    db: &DbStore,
    cache_key: &WasmModuleCacheKey,
    store: &Store,
    cache_id: &str,
    wasm_hash: [u8; 32],
) -> Result<Option<Module>, WasmModuleCacheError> {
    let Some(cache_bytes) = read_authenticated_cache(db, cache_key, cache_id, wasm_hash)? else {
        return Ok(None);
    };

    let mut file = std::io::Cursor::new(cache_bytes);
    let mut magic = [0_u8; 8];
    file.read_exact(&mut magic)?;
    if &magic != WASM_MODULE_CACHE_MAGIC {
        return Err(WasmModuleCacheError::FormatMismatch);
    }
    let mut version_bytes = [0_u8; 4];
    file.read_exact(&mut version_bytes)?;
    if u32::from_le_bytes(version_bytes) != WASM_MODULE_CACHE_FILE_VERSION {
        return Err(WasmModuleCacheError::VersionMismatch);
    }
    let mut serialized = Vec::new();
    file.read_to_end(&mut serialized)?;

    // SAFETY: these bytes were authenticated with the caller's secret, vault-derived key over
    // the cache id (compiler, OS/arch, Wasmer version), the wasm hash and the whole cache
    // file, and tags are only computed over output freshly serialized by this wallet's compiler.
    let module = unsafe { Module::deserialize(store, serialized) }
        .map_err(|err| WasmModuleCacheError::Deserialize(err.to_string()))?;
    Ok(Some(module))
}

fn write_wasm_module_cache(
    db: &DbStore,
    cache_key: &WasmModuleCacheKey,
    cache_id: &str,
    wasm_hash: [u8; 32],
    module: &Module,
) -> Result<(), WasmModuleCacheError> {
    db.ensure_blob_dir(WASM_MODULE_CACHE_KIND)?;
    let file_name = format!("{cache_id}.wasmer");
    let relative = DbStore::relative_blob_path(WASM_MODULE_CACHE_KIND, &file_name);
    let path = db.resolve_path(&relative);
    let tmp_path = path.with_file_name(format!("{file_name}.{}.tmp", std::process::id()));
    let serialized = module
        .serialize()
        .map_err(|err| WasmModuleCacheError::Serialize(err.to_string()))?;
    let mut cache_bytes = Vec::with_capacity(WASM_MODULE_CACHE_MAGIC.len() + 4 + serialized.len());
    cache_bytes.write_all(WASM_MODULE_CACHE_MAGIC)?;
    cache_bytes.write_all(&WASM_MODULE_CACHE_FILE_VERSION.to_le_bytes())?;
    cache_bytes.write_all(serialized.as_ref())?;
    let cache_tag: [u8; 32] = cache_tag_mac(cache_key, cache_id, wasm_hash, &cache_bytes)
        .finalize()
        .into_bytes()
        .into();

    {
        let mut file = File::create(&tmp_path)?;
        file.write_all(&cache_bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp_path, &path)?;

    let now = now_epoch_secs();
    let created_at = db
        .get_blob_meta(WASM_MODULE_CACHE_KIND, cache_id)?
        .map_or(now, |meta| meta.created_at);
    db.put_blob_meta(
        WASM_MODULE_CACHE_KIND,
        cache_id,
        &BlobMeta {
            format_version: WASM_MODULE_CACHE_FORMAT_VERSION,
            relative_path: relative,
            content_hash: cache_tag,
            source_hash: Some(wasm_hash),
            source_sequence: None,
            created_at,
            updated_at: now,
            last_accessed_at: now,
            last_block: None,
        },
    )?;
    Ok(())
}

fn wasm_module_meta_matches(meta: &BlobMeta, wasm_hash: [u8; 32]) -> bool {
    meta.format_version == WASM_MODULE_CACHE_FORMAT_VERSION && meta.source_hash == Some(wasm_hash)
}

fn module_cache_id(variant: &str, compiler: &str) -> String {
    format!(
        "{}-{}-{}-{}-{}",
        safe_component(variant),
        safe_component(compiler),
        safe_component(std::env::consts::OS),
        safe_component(std::env::consts::ARCH),
        WASM_MODULE_CACHE_ENGINE_VERSION
    )
}

fn safe_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use local_db::{DbConfig, DbStore};
    use wasmer::Store;

    use super::{
        WASM_MODULE_CACHE_KIND, WasmModuleCacheKey, load_or_compile_wasm_module, module_cache_id,
        wasm_module_cache_exists,
    };

    static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_db_root() -> PathBuf {
        let dir = std::env::temp_dir().join("railgun-wallet-wasm-module-cache-tests");
        fs::create_dir_all(&dir).expect("create temp db dir");
        let pid = std::process::id();
        let counter = TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
        dir.join(format!("{pid}-{counter}"))
    }

    #[test]
    fn compiled_wasm_module_cache_roundtrip() {
        let root_dir = temp_db_root();
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        let store = Store::default();
        let wasm = b"\0asm\x01\0\0\0";
        let cache_key = WasmModuleCacheKey::new([1; 32]);
        let key = Some(&cache_key);

        let first =
            load_or_compile_wasm_module(Some(&db), key, &store, "test/variant", "default", wasm)
                .expect("compile module");
        assert!(!first.cache_hit);
        drop(first);

        let meta = db
            .get_blob_meta(
                WASM_MODULE_CACHE_KIND,
                &module_cache_id("test/variant", "default"),
            )
            .expect("read blob meta")
            .expect("blob meta present");
        assert!(db.resolve_path(&meta.relative_path).exists());

        let second =
            load_or_compile_wasm_module(Some(&db), key, &store, "test/variant", "default", wasm)
                .expect("load cached module");
        assert!(second.cache_hit);

        load_or_compile_wasm_module(Some(&db), key, &store, "01x01", "default", wasm)
            .expect("compile ordinary module");
        // A valid custom section changes the source bytes without requiring a larger fixture.
        let changed_wasm = b"\0asm\x01\0\0\0\0\x02\x01x";
        assert!(
            !wasm_module_cache_exists(&db, key, "test/variant", "default", changed_wasm)
                .expect("changed source misses")
        );
        let replacement = load_or_compile_wasm_module(
            Some(&db),
            key,
            &store,
            "test/variant",
            "default",
            changed_wasm,
        )
        .expect("compile changed module");
        assert!(!replacement.cache_hit);
        let reused = load_or_compile_wasm_module(
            Some(&db),
            key,
            &store,
            "test/variant",
            "default",
            changed_wasm,
        )
        .expect("reuse changed module");
        assert!(reused.cache_hit);
        assert!(
            !wasm_module_cache_exists(&db, key, "test/variant", "default", wasm)
                .expect("old source misses after replacement")
        );
        let ordinary =
            load_or_compile_wasm_module(Some(&db), key, &store, "01x01", "default", wasm)
                .expect("reuse ordinary module");
        assert!(ordinary.cache_hit);

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn tampered_compiled_wasm_module_cache_is_regenerated() {
        let root_dir = temp_db_root();
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        let store = Store::default();
        let wasm = b"\0asm\x01\0\0\0";
        let cache_key = WasmModuleCacheKey::new([1; 32]);
        let key = Some(&cache_key);

        let first = load_or_compile_wasm_module(Some(&db), key, &store, "tamper", "default", wasm)
            .expect("compile module");
        assert!(!first.cache_hit);
        drop(first);

        let meta = db
            .get_blob_meta(
                WASM_MODULE_CACHE_KIND,
                &module_cache_id("tamper", "default"),
            )
            .expect("read blob meta")
            .expect("blob meta present");
        let path = db.resolve_path(&meta.relative_path);
        let mut bytes = fs::read(&path).expect("read cache bytes");
        let last = bytes.last_mut().expect("cache bytes not empty");
        *last ^= 0xff;
        fs::write(&path, bytes).expect("tamper cache bytes");

        let second = load_or_compile_wasm_module(Some(&db), key, &store, "tamper", "default", wasm)
            .expect("regenerate module");
        assert!(!second.cache_hit);

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn compiled_wasm_module_cache_from_another_key_is_recompiled() {
        let root_dir = temp_db_root();
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        let store = Store::default();
        let wasm = b"\0asm\x01\0\0\0";
        let key_a = WasmModuleCacheKey::new([1; 32]);
        let key_b = WasmModuleCacheKey::new([2; 32]);

        let written =
            load_or_compile_wasm_module(Some(&db), Some(&key_a), &store, "rekey", "default", wasm)
                .expect("compile module under key A");
        assert!(!written.cache_hit);
        assert!(
            wasm_module_cache_exists(&db, Some(&key_a), "rekey", "default", wasm)
                .expect("probe under key A")
        );

        assert!(
            !wasm_module_cache_exists(&db, Some(&key_b), "rekey", "default", wasm)
                .expect("probe under key B")
        );
        let recompiled =
            load_or_compile_wasm_module(Some(&db), Some(&key_b), &store, "rekey", "default", wasm)
                .expect("recompile module under key B");
        assert!(!recompiled.cache_hit);
        let reused =
            load_or_compile_wasm_module(Some(&db), Some(&key_b), &store, "rekey", "default", wasm)
                .expect("reuse module under key B");
        assert!(reused.cache_hit);

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }
}
