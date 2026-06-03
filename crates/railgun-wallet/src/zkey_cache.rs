use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use ark_bn254::{Bn254, Fr};
use ark_circom::{index::NPIndex, read_zkey};
use ark_groth16::ProvingKey;
use ark_relations::utils::matrix::Matrix;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use local_db::{DbError, DbStore, ZkeyMeta};
use sha2::{Digest, Sha256};
use thiserror::Error;

const ZKEY_CACHE_MAGIC: &[u8; 8] = b"RZKCACHE";
const ZKEY_CACHE_VERSION: u32 = 1;
const ZKEY_CACHE_FORMAT_VERSION: u32 = 3;

#[derive(Debug, Error)]
pub enum ZkeyCacheError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] SerializationError),
    #[error("db error: {0}")]
    Db(#[from] DbError),
    #[error("cache format mismatch")]
    FormatMismatch,
    #[error("cache version mismatch")]
    VersionMismatch,
}

type ZkeyCachePayload = (ProvingKey<Bn254>, NPIndex<Fr>);
type ZkeyCacheLoadResult = Result<Option<ZkeyCachePayload>, ZkeyCacheError>;

pub trait ZkeyCacheDbExt {
    fn load_zkey_cache(&self, variant: &str, expected_hash: [u8; 32]) -> ZkeyCacheLoadResult;
    fn write_zkey_cache(
        &self,
        variant: &str,
        expected_hash: [u8; 32],
        proving_key: &ProvingKey<Bn254>,
        matrices: &NPIndex<Fr>,
    ) -> Result<(), ZkeyCacheError>;
}

impl ZkeyCacheDbExt for DbStore {
    fn load_zkey_cache(&self, variant: &str, expected_hash: [u8; 32]) -> ZkeyCacheLoadResult {
        let Some(meta) = self.get_zkey_meta(variant)? else {
            return Ok(None);
        };

        if meta.format_version != ZKEY_CACHE_FORMAT_VERSION {
            return Ok(None);
        }

        if meta.zkey_hash != expected_hash {
            return Ok(None);
        }
        let Some(expected_cache_hash) = meta.cache_hash else {
            return Ok(None);
        };

        let path = self.resolve_path(&meta.relative_path);
        if !path.exists() {
            return Ok(None);
        }

        let mut file = File::open(path)?;
        let cache_hash = reader_sha256(&mut file)?;
        if cache_hash != expected_cache_hash {
            return Ok(None);
        }
        file.seek(SeekFrom::Start(0))?;

        let mut magic = [0u8; 8];
        file.read_exact(&mut magic)?;
        if &magic != ZKEY_CACHE_MAGIC {
            return Err(ZkeyCacheError::FormatMismatch);
        }

        let version = file.read_u32::<LittleEndian>()?;
        if version != ZKEY_CACHE_VERSION {
            return Err(ZkeyCacheError::VersionMismatch);
        }

        let proving_key = ProvingKey::<Bn254>::deserialize_uncompressed(&mut file)?;
        let matrices = read_matrices(&mut file)?;
        Ok(Some((proving_key, matrices)))
    }

    fn write_zkey_cache(
        &self,
        variant: &str,
        expected_hash: [u8; 32],
        proving_key: &ProvingKey<Bn254>,
        matrices: &NPIndex<Fr>,
    ) -> Result<(), ZkeyCacheError> {
        self.ensure_blob_dir("zkey")?;
        let file_name = format!("{variant}.ark");
        let relative = DbStore::relative_blob_path("zkey", &file_name);
        let path = self.resolve_path(&relative);
        let tmp_path = path.with_extension("tmp");

        {
            let mut file = File::create(&tmp_path)?;
            file.write_all(ZKEY_CACHE_MAGIC)?;
            file.write_u32::<LittleEndian>(ZKEY_CACHE_VERSION)?;
            proving_key.serialize_uncompressed(&mut file)?;
            write_matrices(&mut file, matrices)?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp_path, &path)?;
        let mut file = File::open(&path)?;
        let cache_hash = reader_sha256(&mut file)?;

        let meta = ZkeyMeta {
            relative_path: relative,
            zkey_hash: expected_hash,
            cache_hash: Some(cache_hash),
            format_version: ZKEY_CACHE_FORMAT_VERSION,
        };
        self.put_zkey_meta(variant, &meta)?;
        Ok(())
    }
}

pub fn load_or_parse_zkey(
    db: Option<&DbStore>,
    variant: &str,
    expected_hash: [u8; 32],
    zkey_path: &Path,
) -> Result<ZkeyCachePayload, ZkeyCacheError> {
    if let Some(db) = db {
        match db.load_zkey_cache(variant, expected_hash) {
            Ok(Some(result)) => return Ok(result),
            Ok(None) => {}
            Err(err) => {
                tracing::warn!(?err, "failed to load zkey cache");
            }
        }
    }

    let zkey_bytes = std::fs::read(zkey_path)?;
    let mut cursor = std::io::Cursor::new(zkey_bytes);
    let (proving_key, matrices) = read_zkey(&mut cursor)?;

    if let Some(db) = db
        && let Err(err) = db.write_zkey_cache(variant, expected_hash, &proving_key, &matrices)
    {
        tracing::warn!(?err, "failed to write zkey cache");
    }

    Ok((proving_key, matrices))
}

pub fn zkey_cache_exists(
    db: &DbStore,
    variant: &str,
    expected_hash: [u8; 32],
) -> Result<bool, ZkeyCacheError> {
    let Some(meta) = db.get_zkey_meta(variant)? else {
        return Ok(false);
    };
    if meta.format_version != ZKEY_CACHE_FORMAT_VERSION || meta.zkey_hash != expected_hash {
        return Ok(false);
    }
    let Some(expected_cache_hash) = meta.cache_hash else {
        return Ok(false);
    };
    let path = db.resolve_path(&meta.relative_path);
    if !path.exists() {
        return Ok(false);
    }
    let mut file = File::open(path)?;
    Ok(reader_sha256(&mut file)? == expected_cache_hash)
}

fn reader_sha256<R: Read>(reader: &mut R) -> Result<[u8; 32], ZkeyCacheError> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

fn write_matrices<W: Write>(writer: &mut W, matrices: &NPIndex<Fr>) -> Result<(), ZkeyCacheError> {
    writer.write_u64::<LittleEndian>(matrices.num_instance_variables as u64)?;
    writer.write_u64::<LittleEndian>(matrices.num_witness_variables as u64)?;
    writer.write_u64::<LittleEndian>(matrices.num_constraints as u64)?;
    writer.write_u64::<LittleEndian>(matrices.a_num_non_zero as u64)?;
    writer.write_u64::<LittleEndian>(matrices.b_num_non_zero as u64)?;
    writer.write_u64::<LittleEndian>(matrices.c_num_non_zero as u64)?;

    write_matrix(writer, &matrices.a)?;
    write_matrix(writer, &matrices.b)?;
    write_matrix(writer, &matrices.c)?;
    Ok(())
}

fn write_matrix<W: Write>(writer: &mut W, matrix: &Matrix<Fr>) -> Result<(), ZkeyCacheError> {
    writer.write_u64::<LittleEndian>(matrix.len() as u64)?;
    for row in matrix {
        writer.write_u64::<LittleEndian>(row.len() as u64)?;
        for (coeff, idx) in row {
            coeff.serialize_uncompressed(&mut *writer)?;
            writer.write_u64::<LittleEndian>(*idx as u64)?;
        }
    }
    Ok(())
}

fn read_matrices<R: Read>(reader: &mut R) -> Result<NPIndex<Fr>, ZkeyCacheError> {
    let num_instance_variables = reader.read_u64::<LittleEndian>()?;
    let num_witness_variables = reader.read_u64::<LittleEndian>()?;
    let num_constraints = reader.read_u64::<LittleEndian>()?;
    let a_num_non_zero = reader.read_u64::<LittleEndian>()?;
    let b_num_non_zero = reader.read_u64::<LittleEndian>()?;
    let c_num_non_zero = reader.read_u64::<LittleEndian>()?;

    let a = read_matrix(reader)?;
    let b = read_matrix(reader)?;
    let c = read_matrix(reader)?;

    Ok(NPIndex {
        num_instance_variables: num_instance_variables as usize,
        num_witness_variables: num_witness_variables as usize,
        num_constraints: num_constraints as usize,
        a_num_non_zero: a_num_non_zero as usize,
        b_num_non_zero: b_num_non_zero as usize,
        c_num_non_zero: c_num_non_zero as usize,
        a,
        b,
        c,
    })
}

fn read_matrix<R: Read>(reader: &mut R) -> Result<Matrix<Fr>, ZkeyCacheError> {
    let row_count = reader.read_u64::<LittleEndian>()?;
    let mut matrix = Vec::with_capacity(row_count as usize);
    for _ in 0..row_count {
        let entry_count = reader.read_u64::<LittleEndian>()?;
        let mut row = Vec::with_capacity(entry_count as usize);
        for _ in 0..entry_count {
            let coeff = Fr::deserialize_uncompressed(&mut *reader)?;
            let idx = reader.read_u64::<LittleEndian>()?;
            row.push((coeff, idx as usize));
        }
        matrix.push(row);
    }
    Ok(matrix)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use local_db::{DbConfig, DbStore};

    use super::{ZKEY_CACHE_FORMAT_VERSION, ZkeyCacheDbExt};

    static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_db_root() -> PathBuf {
        let dir = std::env::temp_dir().join("railgun-wallet-zkey-cache-tests");
        fs::create_dir_all(&dir).expect("create temp db dir");
        let pid = std::process::id();
        let counter = TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
        dir.join(format!("{pid}-{counter}"))
    }

    #[test]
    fn zkey_cache_exists_rejects_tampered_cache_file() {
        let root_dir = temp_db_root();
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        db.ensure_blob_dir("zkey").expect("create zkey blob dir");
        let relative = DbStore::relative_blob_path("zkey", "tampered.ark");
        let path = db.resolve_path(&relative);
        fs::write(&path, b"tampered-cache").expect("write cache file");
        let mut expected_hash = [0u8; 32];
        expected_hash[0] = 42;

        db.put_zkey_meta(
            "tampered",
            &local_db::ZkeyMeta {
                relative_path: relative,
                zkey_hash: expected_hash,
                cache_hash: Some([7u8; 32]),
                format_version: ZKEY_CACHE_FORMAT_VERSION,
            },
        )
        .expect("write zkey meta");

        assert!(
            !super::zkey_cache_exists(&db, "tampered", expected_hash).expect("check zkey cache")
        );
        assert!(
            db.load_zkey_cache("tampered", expected_hash)
                .expect("load zkey cache")
                .is_none()
        );

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }

    #[test]
    fn zkey_cache_load_rejects_legacy_meta_without_cache_hash() {
        let root_dir = temp_db_root();
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        db.ensure_blob_dir("zkey").expect("create zkey blob dir");
        let relative = DbStore::relative_blob_path("zkey", "legacy.ark");
        let path = db.resolve_path(&relative);
        fs::write(&path, b"legacy-cache").expect("write cache file");
        let mut expected_hash = [0u8; 32];
        expected_hash[0] = 7;

        db.put_zkey_meta(
            "legacy",
            &local_db::ZkeyMeta {
                relative_path: relative,
                zkey_hash: expected_hash,
                cache_hash: None,
                format_version: ZKEY_CACHE_FORMAT_VERSION,
            },
        )
        .expect("write zkey meta");

        assert!(
            db.load_zkey_cache("legacy", expected_hash)
                .expect("load zkey cache")
                .is_none()
        );

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }
}
