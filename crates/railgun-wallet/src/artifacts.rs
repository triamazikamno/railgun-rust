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
const POI_ARTIFACT_CACHE_DIR: &str =
    "artifacts-v2.1/QmZ2MyM6TKxffkv6stuo2hFwmUfs3q4xgMYN164Sje8new";

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
mod tests;
