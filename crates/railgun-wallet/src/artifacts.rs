use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use alloy::hex;
use alloy::primitives::FixedBytes;
use brotli::Decompressor;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use trustless_artifacts::{
    DEFAULT_GATEWAYS, GatewayPool, TrustlessArtifactError, TrustlessArtifactFetcher,
};
use url::Url;

const ARTIFACTS_DIR: &str = "db/railgun/blobs/artifacts";
const ARTIFACTS_LIST_FILE: &str = "artifacts.json";
const ARTIFACTS_HASHES_FILE: &str = "artifact-v2-hashes.json";
const ARTIFACT_CIDS_FILE: &str = "artifact-cids.json";
const POI_ARTIFACT_PREFIX: &str = "POI_";
const POI_ARTIFACT_CACHE_DIR: &str = "artifacts-v2.1/poi-nov-2-23";

const ARTIFACTS_LIST_EMBED: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/resources/metadata/artifacts.json"
));
const ARTIFACTS_HASHES_EMBED: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/resources/metadata/artifact-v2-hashes.json"
));
const ARTIFACT_CIDS_EMBED: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/resources/metadata/artifact-cids.json"
));

#[derive(Debug, Error)]
pub enum ArtifactError {
    #[error("unsupported artifact variant {nullifiers}x{commitments}")]
    UnsupportedVariant {
        nullifiers: usize,
        commitments: usize,
    },
    #[error("unsupported POI artifact variant {variant}")]
    UnsupportedPoiVariant { variant: String },
    #[error("read artifact list: {0}")]
    ArtifactList(#[source] serde_json::Error),
    #[error("read artifact file {path}: {source}")]
    ArtifactFile {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("read artifact hashes: {0}")]
    ArtifactHashes(#[source] std::io::Error),
    #[error("parse artifact hashes: {0}")]
    HashesParse(#[source] serde_json::Error),
    #[error("read artifact CIDs {path}: {source}")]
    ArtifactCids {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("parse artifact CIDs: {0}")]
    CidsParse(#[source] serde_json::Error),
    #[error("missing artifact hash for {variant}")]
    MissingHash { variant: String },
    #[error("missing artifact CID entry for variant {variant}")]
    MissingCid { variant: String },
    #[error("trustless artifact fetch failed: {0}")]
    Trustless(#[source] TrustlessArtifactError),
    #[error("artifact materialization task failed: {0}")]
    MaterializationTask(#[source] tokio::task::JoinError),
    #[error("brotli decompress failed: {0}")]
    Decompress(#[source] std::io::Error),
    #[error("hash mismatch for {label}: got {actual}, expected {expected}")]
    HashMismatch {
        label: String,
        actual: String,
        expected: String,
    },
}

#[derive(Debug, Deserialize)]
struct ArtifactSpec {
    nullifiers: usize,
    commitments: usize,
}

#[derive(Debug, Deserialize)]
struct ArtifactHashes {
    zkey: FixedBytes<32>,
    wasm: FixedBytes<32>,
    #[serde(default)]
    #[allow(dead_code)]
    dat: Option<FixedBytes<32>>,
}

#[derive(Debug, Deserialize)]
struct ArtifactCid {
    cid: String,
    br_bytes: u64,
}

#[derive(Debug, Deserialize)]
struct ArtifactCidSet {
    zkey: ArtifactCid,
    wasm: ArtifactCid,
}

#[derive(Debug)]
pub struct Artifacts {
    pub zkey: Vec<u8>,
    pub wasm: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ArtifactSource {
    pub gateways: Vec<Url>,
    pub client: Option<reqwest::Client>,
    pub gateway_pool: GatewayPool,
    pub out_dir: PathBuf,
    pub metadata_dir: Option<PathBuf>,
}

impl Default for ArtifactSource {
    fn default() -> Self {
        let gateways = DEFAULT_GATEWAYS
            .iter()
            .map(|gateway| Url::parse(gateway).expect("valid gateway url"))
            .collect::<Vec<_>>();
        Self {
            gateway_pool: GatewayPool::new(),
            gateways,
            client: None,
            out_dir: PathBuf::from(ARTIFACTS_DIR),
            metadata_dir: None,
        }
    }
}

impl ArtifactSource {
    #[must_use]
    pub fn new(gateways: Vec<Url>, out_dir: PathBuf) -> Self {
        Self {
            gateways,
            client: None,
            gateway_pool: GatewayPool::new(),
            out_dir,
            metadata_dir: None,
        }
    }

    #[must_use]
    pub fn with_cache_dir(mut self, path: PathBuf) -> Self {
        self.out_dir = path;
        self
    }

    #[must_use]
    pub fn with_gateways(mut self, gateways: Vec<Url>) -> Self {
        self.gateways = gateways;
        self
    }

    #[must_use]
    pub fn with_gateway_pool(mut self, gateway_pool: GatewayPool) -> Self {
        self.gateway_pool = gateway_pool;
        self
    }

    #[must_use]
    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        self.client = Some(client);
        self
    }

    pub fn with_metadata_dir(mut self, path: PathBuf) -> Result<Self, ArtifactError> {
        validate_metadata_dir(&path)?;
        self.metadata_dir = Some(path);
        Ok(self)
    }

    pub fn list_variants(&self) -> Result<Vec<String>, ArtifactError> {
        let specs = self.artifact_specs()?;
        let mut variants: Vec<String> = specs
            .iter()
            .map(|spec| variant_name(spec.nullifiers, spec.commitments))
            .collect();
        variants.sort();
        Ok(variants)
    }

    pub(crate) fn list_variants_with_max_commitments(
        &self,
        max_commitments: usize,
    ) -> Result<Vec<String>, ArtifactError> {
        let specs = self.artifact_specs()?;
        let mut variants: Vec<String> = specs
            .into_iter()
            .filter(|spec| spec.commitments <= max_commitments)
            .map(|spec| variant_name(spec.nullifiers, spec.commitments))
            .collect();
        variants.sort();
        Ok(variants)
    }

    #[must_use]
    pub fn artifact_paths(&self, variant: &str) -> ArtifactPaths {
        let base = if is_poi_variant(variant) {
            self.out_dir.join(POI_ARTIFACT_CACHE_DIR).join(variant)
        } else {
            self.out_dir.join(variant)
        };
        ArtifactPaths {
            zkey: base.join("zkey"),
            wasm: base.join("wasm"),
        }
    }

    pub async fn ensure_artifacts(
        &self,
        nullifiers: usize,
        commitments: usize,
    ) -> Result<ArtifactPaths, ArtifactError> {
        self.assert_variant_exists(nullifiers, commitments)?;
        let variant = variant_name(nullifiers, commitments);
        let paths = self.artifact_paths(&variant);
        if paths.zkey.exists() && paths.wasm.exists() {
            return Ok(paths);
        }
        self.download_variant(&variant, false).await
    }

    pub async fn ensure_poi_artifacts(
        &self,
        max_inputs: usize,
        max_outputs: usize,
    ) -> Result<ArtifactPaths, ArtifactError> {
        let variant = poi_variant_name(max_inputs, max_outputs);
        assert_supported_poi_variant(&variant)?;
        let paths = self.artifact_paths(&variant);
        if paths.zkey.exists() && paths.wasm.exists() {
            return Ok(paths);
        }
        self.download_variant(&variant, false).await
    }

    pub async fn download_variants(
        &self,
        variants: &[String],
        force: bool,
    ) -> Result<Vec<ArtifactPaths>, ArtifactError> {
        let mut out = Vec::with_capacity(variants.len());
        for variant in variants {
            out.push(self.download_variant(variant, force).await?);
        }
        Ok(out)
    }

    pub async fn download_variant(
        &self,
        variant: &str,
        force: bool,
    ) -> Result<ArtifactPaths, ArtifactError> {
        let paths = self.artifact_paths(variant);
        if !force && paths.zkey.exists() && paths.wasm.exists() {
            return Ok(paths);
        }

        let expected =
            self.load_hashes()?
                .remove(variant)
                .ok_or_else(|| ArtifactError::MissingHash {
                    variant: variant.to_string(),
                })?;
        let cids = self
            .load_cids()?
            .remove(variant)
            .ok_or_else(|| ArtifactError::MissingCid {
                variant: variant.to_string(),
            })?;

        let zkey_br = self.fetch_artifact(&cids.zkey).await?;
        let wasm_br = self.fetch_artifact(&cids.wasm).await?;

        tokio::task::spawn_blocking(move || {
            materialize_artifacts(&zkey_br, &wasm_br, &expected, paths, force)
        })
        .await
        .map_err(ArtifactError::MaterializationTask)?
    }

    async fn fetch_artifact(&self, artifact: &ArtifactCid) -> Result<Vec<u8>, ArtifactError> {
        let client = self.client.clone().unwrap_or_default();
        TrustlessArtifactFetcher::new_with_pool(&client, &self.gateways, self.gateway_pool.clone())
            .fetch_artifact_cid(&artifact.cid, artifact.br_bytes)
            .await
            .map_err(ArtifactError::Trustless)
    }

    pub fn load_artifacts(
        &self,
        nullifiers: usize,
        commitments: usize,
    ) -> Result<Artifacts, ArtifactError> {
        self.assert_variant_exists(nullifiers, commitments)?;
        let variant = variant_name(nullifiers, commitments);
        let paths = self.artifact_paths(&variant);

        let zkey = fs::read(&paths.zkey).map_err(|source| ArtifactError::ArtifactFile {
            path: paths.zkey.clone(),
            source,
        })?;
        let wasm = fs::read(&paths.wasm).map_err(|source| ArtifactError::ArtifactFile {
            path: paths.wasm.clone(),
            source,
        })?;

        Ok(Artifacts { zkey, wasm })
    }

    pub fn expected_zkey_hash(&self, variant: &str) -> Result<FixedBytes<32>, ArtifactError> {
        let hashes = self.load_hashes()?;
        let expected = hashes
            .get(variant)
            .ok_or_else(|| ArtifactError::MissingHash {
                variant: variant.to_string(),
            })?;
        Ok(expected.zkey)
    }

    fn assert_variant_exists(
        &self,
        nullifiers: usize,
        commitments: usize,
    ) -> Result<(), ArtifactError> {
        let specs = self.artifact_specs()?;
        let exists = specs
            .iter()
            .any(|spec| spec.nullifiers == nullifiers && spec.commitments == commitments);
        if exists {
            Ok(())
        } else {
            Err(ArtifactError::UnsupportedVariant {
                nullifiers,
                commitments,
            })
        }
    }

    fn artifact_specs(&self) -> Result<Vec<ArtifactSpec>, ArtifactError> {
        if let Some(dir) = self.metadata_dir.as_ref() {
            let path = dir.join(ARTIFACTS_LIST_FILE);
            let data =
                fs::read(&path).map_err(|source| ArtifactError::ArtifactFile { path, source })?;
            serde_json::from_slice(&data).map_err(ArtifactError::ArtifactList)
        } else {
            serde_json::from_slice(ARTIFACTS_LIST_EMBED).map_err(ArtifactError::ArtifactList)
        }
    }

    fn load_hashes(&self) -> Result<HashMap<String, ArtifactHashes>, ArtifactError> {
        if let Some(dir) = self.metadata_dir.as_ref() {
            let path = dir.join(ARTIFACTS_HASHES_FILE);
            let data = fs::read(&path).map_err(ArtifactError::ArtifactHashes)?;
            serde_json::from_slice(&data).map_err(ArtifactError::HashesParse)
        } else {
            serde_json::from_slice(ARTIFACTS_HASHES_EMBED).map_err(ArtifactError::HashesParse)
        }
    }

    fn load_cids(&self) -> Result<HashMap<String, ArtifactCidSet>, ArtifactError> {
        if let Some(dir) = self.metadata_dir.as_ref() {
            let path = dir.join(ARTIFACT_CIDS_FILE);
            let data = fs::read(&path).map_err(|source| ArtifactError::ArtifactCids {
                path: path.clone(),
                source,
            })?;
            serde_json::from_slice(&data).map_err(ArtifactError::CidsParse)
        } else {
            serde_json::from_slice(ARTIFACT_CIDS_EMBED).map_err(ArtifactError::CidsParse)
        }
    }
}

#[derive(Debug, Clone)]
pub struct ArtifactPaths {
    pub zkey: PathBuf,
    pub wasm: PathBuf,
}

#[must_use]
pub fn variant_name(nullifiers: usize, commitments: usize) -> String {
    format!("{nullifiers:02}x{commitments:02}")
}

#[must_use]
pub fn poi_variant_name(max_inputs: usize, max_outputs: usize) -> String {
    format!("{POI_ARTIFACT_PREFIX}{max_inputs}x{max_outputs}")
}

fn validate_metadata_dir(path: &Path) -> Result<(), ArtifactError> {
    let list_path = path.join(ARTIFACTS_LIST_FILE);
    let hashes_path = path.join(ARTIFACTS_HASHES_FILE);
    let cids_path = path.join(ARTIFACT_CIDS_FILE);
    fs::read(&list_path).map_err(|source| ArtifactError::ArtifactFile {
        path: list_path,
        source,
    })?;
    fs::read(&hashes_path).map_err(ArtifactError::ArtifactHashes)?;
    fs::read(&cids_path).map_err(|source| ArtifactError::ArtifactCids {
        path: cids_path,
        source,
    })?;
    Ok(())
}

pub fn load_artifacts(nullifiers: usize, commitments: usize) -> Result<Artifacts, ArtifactError> {
    let source = ArtifactSource::default();
    source.load_artifacts(nullifiers, commitments)
}

fn is_poi_variant(variant: &str) -> bool {
    variant.starts_with(POI_ARTIFACT_PREFIX)
}

fn assert_supported_poi_variant(variant: &str) -> Result<(), ArtifactError> {
    if variant == poi_variant_name(3, 3) || variant == poi_variant_name(13, 13) {
        Ok(())
    } else {
        Err(ArtifactError::UnsupportedPoiVariant {
            variant: variant.to_string(),
        })
    }
}

fn brotli_decompress(data: &[u8]) -> Result<Vec<u8>, ArtifactError> {
    let mut out = Vec::new();
    let mut reader = Decompressor::new(data, 4096);
    reader
        .read_to_end(&mut out)
        .map_err(ArtifactError::Decompress)?;
    Ok(out)
}

fn validate_hash(label: &str, data: &[u8], expected: &[u8]) -> Result<(), ArtifactError> {
    let digest = Sha256::digest(data);
    if digest.as_slice() != expected {
        let actual = hex::encode(digest);
        let expected = hex::encode(expected);
        return Err(ArtifactError::HashMismatch {
            label: label.to_string(),
            actual,
            expected,
        });
    }
    Ok(())
}

fn materialize_artifacts(
    zkey_br: &[u8],
    wasm_br: &[u8],
    expected: &ArtifactHashes,
    paths: ArtifactPaths,
    force: bool,
) -> Result<ArtifactPaths, ArtifactError> {
    let zkey = brotli_decompress(zkey_br)?;
    let wasm = brotli_decompress(wasm_br)?;
    validate_hash("zkey", &zkey, expected.zkey.as_slice())?;
    validate_hash("wasm", &wasm, expected.wasm.as_slice())?;

    let zkey_parent = paths
        .zkey
        .parent()
        .ok_or_else(|| ArtifactError::ArtifactFile {
            path: paths.zkey.clone(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "zkey path missing parent",
            ),
        })?;
    fs::create_dir_all(zkey_parent).map_err(|source| ArtifactError::ArtifactFile {
        path: paths.zkey.clone(),
        source,
    })?;
    write_if_needed(&paths.zkey, &zkey, force)?;
    write_if_needed(&paths.wasm, &wasm, force)?;
    Ok(paths)
}

fn write_if_needed(path: &Path, data: &[u8], force: bool) -> Result<(), ArtifactError> {
    if path.exists() && !force {
        return Ok(());
    }
    fs::write(path, data).map_err(|source| ArtifactError::ArtifactFile {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;

    use alloy::primitives::FixedBytes;
    use sha2::{Digest, Sha256};

    use super::{
        ARTIFACT_CIDS_FILE, ARTIFACTS_HASHES_EMBED, ARTIFACTS_HASHES_FILE, ARTIFACTS_LIST_EMBED,
        ARTIFACTS_LIST_FILE, ArtifactError, ArtifactHashes, ArtifactPaths, ArtifactSource,
        materialize_artifacts, poi_variant_name,
    };

    #[test]
    fn poi_variant_name_matches_expected_shape() {
        assert_eq!(poi_variant_name(3, 3), "POI_3x3");
        assert_eq!(poi_variant_name(13, 13), "POI_13x13");
    }

    #[test]
    fn embedded_artifact_list_includes_deployed_high_input_variants() {
        let variants = ArtifactSource::default()
            .list_variants()
            .expect("embedded variants should parse");

        for variant in ["11x02", "11x03", "12x02"] {
            assert!(
                variants.iter().any(|candidate| candidate == variant),
                "missing deployed verifier variant {variant}"
            );
        }
    }

    #[test]
    fn embedded_cid_table_includes_known_variant() {
        let cids = ArtifactSource::default()
            .load_cids()
            .expect("embedded CIDs should parse");
        let variant = cids.get("01x01").expect("known variant");
        assert_eq!(variant.zkey.br_bytes, 3_447_484);
        assert_eq!(variant.wasm.br_bytes, 895_378);
    }

    #[tokio::test]
    async fn missing_cid_variant_fails_before_network() {
        let dir = std::env::temp_dir().join(format!(
            "railgun-missing-artifact-cid-{}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create metadata dir");
        fs::write(dir.join(ARTIFACTS_LIST_FILE), ARTIFACTS_LIST_EMBED).expect("write list");
        fs::write(dir.join(ARTIFACTS_HASHES_FILE), ARTIFACTS_HASHES_EMBED).expect("write hashes");
        fs::write(dir.join(ARTIFACT_CIDS_FILE), b"{}").expect("write CIDs");
        let source = ArtifactSource::default()
            .with_gateways(Vec::new())
            .with_metadata_dir(dir.clone())
            .expect("metadata override");
        let error = source
            .download_variant("01x01", true)
            .await
            .expect_err("missing CID should fail");
        assert!(matches!(error, ArtifactError::MissingCid { ref variant } if variant == "01x01"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn metadata_directory_override_reads_cid_table() {
        let dir =
            std::env::temp_dir().join(format!("railgun-artifact-cids-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("create metadata dir");
        fs::write(dir.join(ARTIFACTS_LIST_FILE), b"[]").expect("write list");
        fs::write(dir.join(ARTIFACTS_HASHES_FILE), b"{}").expect("write hashes");
        fs::write(
            dir.join(ARTIFACT_CIDS_FILE),
            br#"{"custom":{"zkey":{"cid":"Qmfoo","br_bytes":1},"wasm":{"cid":"Qmbar","br_bytes":2}}}"#,
        )
        .expect("write CIDs");
        let source = ArtifactSource::default()
            .with_metadata_dir(dir.clone())
            .expect("metadata override");
        assert_eq!(
            source
                .load_cids()
                .expect("override CIDs")
                .get("custom")
                .expect("custom variant")
                .zkey
                .cid,
            "Qmfoo"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn poi_artifact_paths_use_poi_cache_dir() {
        let source = ArtifactSource::default().with_cache_dir(PathBuf::from("cache"));

        let paths = source.artifact_paths("POI_3x3");

        assert_eq!(
            paths.zkey,
            PathBuf::from("cache/artifacts-v2.1/poi-nov-2-23/POI_3x3/zkey")
        );
        assert_eq!(
            paths.wasm,
            PathBuf::from("cache/artifacts-v2.1/poi-nov-2-23/POI_3x3/wasm")
        );
    }

    #[tokio::test]
    async fn unsupported_poi_variant_is_rejected_before_download() {
        let source = ArtifactSource::default();

        let error = source
            .ensure_poi_artifacts(4, 4)
            .await
            .expect_err("unsupported poi variant should fail");

        assert!(error.to_string().contains("POI_4x4"));
    }

    fn brotli_compress(data: &[u8]) -> Vec<u8> {
        let mut compressed = Vec::new();
        {
            let mut writer = brotli::CompressorWriter::new(&mut compressed, 4096, 5, 22);
            writer.write_all(data).expect("compress test data");
        }
        compressed
    }

    #[test]
    fn materialization_validates_both_artifacts_before_writes() {
        let dir = std::env::temp_dir().join(format!(
            "railgun-artifact-materialization-{}",
            std::process::id()
        ));
        let paths = ArtifactPaths {
            zkey: dir.join("nested/zkey"),
            wasm: dir.join("nested/wasm"),
        };
        let zkey = b"valid zkey";
        let wasm = b"valid wasm";
        let zkey_hash: [u8; 32] = Sha256::digest(zkey).into();
        let wasm_hash: [u8; 32] = Sha256::digest(wasm).into();
        let expected = ArtifactHashes {
            zkey: FixedBytes::from(zkey_hash),
            wasm: FixedBytes::from(wasm_hash),
            dat: None,
        };
        materialize_artifacts(
            &brotli_compress(zkey),
            &brotli_compress(wasm),
            &expected,
            paths.clone(),
            false,
        )
        .expect("valid artifacts should materialize");
        assert_eq!(fs::read(&paths.zkey).expect("zkey output"), zkey);
        assert_eq!(fs::read(&paths.wasm).expect("wasm output"), wasm);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn materialization_hash_mismatch_leaves_both_outputs_absent() {
        let dir = std::env::temp_dir().join(format!(
            "railgun-artifact-materialization-mismatch-{}",
            std::process::id()
        ));
        let paths = ArtifactPaths {
            zkey: dir.join("nested/zkey"),
            wasm: dir.join("nested/wasm"),
        };
        let zkey_hash: [u8; 32] = Sha256::digest(b"valid zkey").into();
        let wasm_hash: [u8; 32] = Sha256::digest(b"wrong wasm").into();
        let expected = ArtifactHashes {
            zkey: FixedBytes::from(zkey_hash),
            wasm: FixedBytes::from(wasm_hash),
            dat: None,
        };
        let error = materialize_artifacts(
            &brotli_compress(b"valid zkey"),
            &brotli_compress(b"valid wasm"),
            &expected,
            paths.clone(),
            false,
        )
        .expect_err("wasm mismatch should fail");
        assert!(matches!(error, ArtifactError::HashMismatch { ref label, .. } if label == "wasm"));
        assert!(!paths.zkey.exists());
        assert!(!paths.wasm.exists());
        assert!(!dir.exists());
    }
}
