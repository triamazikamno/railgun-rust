use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use alloy::hex;
use futures::{FutureExt, StreamExt, future::Shared, stream::FuturesUnordered};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

pub use railgun_indexed_artifacts::{
    ChainScope, ChainType, ChunkError as IndexedArtifactChunkError, CompressionAlgorithm,
    DatasetDescriptorMetadata, INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
    INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION, INDEXED_ARTIFACT_CHUNK_MAGIC,
    INDEXED_ARTIFACT_COMMITMENTS_MAX_DECODED_ENVELOPE_BYTES,
    INDEXED_ARTIFACT_MANIFEST_FORMAT_VERSION, INDEXED_ARTIFACT_MAX_COMPRESSED_CHUNK_BYTES,
    INDEXED_ARTIFACT_MAX_DECODED_ENVELOPE_BYTES,
    INDEXED_ARTIFACT_MERKLE_CHECKPOINT_MAX_DECODED_ENVELOPE_BYTES,
    INDEXED_ARTIFACT_PUBLIC_TXID_MAX_DECODED_ENVELOPE_BYTES,
    INDEXED_ARTIFACT_WALLET_SCAN_MAX_DECODED_ENVELOPE_BYTES, IndexedArtifactCatalog,
    IndexedArtifactChainEntry, IndexedArtifactChunkEnvelope, IndexedArtifactChunkEnvelopeHeader,
    IndexedArtifactChunkSection, IndexedArtifactDescriptor, IndexedArtifactError,
    IndexedArtifactManifest, IndexedArtifactPlannedChunk, IndexedArtifactPlannedChunkPlacement,
    IndexedArtifactRange, IndexedArtifactRangeKind, IndexedArtifactStreamCatalog,
    IndexedArtifactStreamCoverage, IndexedArtifactStreamIdentity,
    IndexedArtifactStreamPartitionPolicy, IndexedArtifactStreamPlan,
    IndexedArtifactStreamPlanError, IndexedArtifactStreamPlanRequest, IndexedDatasetKind,
    LatestIndexedHeight, PublisherIdentity, PublisherKeyAlgorithm, format_scope,
};

use crate::trustless_artifacts::{
    TrustlessArtifactError, TrustlessArtifactFetchResult, TrustlessArtifactFetcher,
};
use crate::types::{IndexedArtifactManifestSource, IndexedArtifactSourceConfig};
use trustless_artifacts::GatewayPool;

/// How long consumers of one source config reuse a verified manifest instead of fetching it again.
const MANIFEST_REUSE_WINDOW: Duration = Duration::from_mins(2);

/// The tracing target these submodules log under, as before they were split out.
const LOG_TARGET: &str = module_path!();

mod chunk_fetch;
mod error;
mod maintenance;
mod stager;
mod validation;

#[cfg(test)]
use chunk_fetch::preferred_artifact_gateway_index;
pub(crate) use chunk_fetch::{IndexedArtifactChunkFetchBatch, IndexedArtifactChunkFetchMetrics};
pub use error::IndexedArtifactManifestError;
pub(crate) use maintenance::{
    IndexedArtifactMaintenanceAdmission, IndexedArtifactMaintenanceKey,
    IndexedArtifactMaintenanceScheduler,
};
pub use stager::VerifiedIndexedArtifactChunkStager;
use validation::validate_catalog_descriptor_for_expansion;
pub use validation::{
    decode_indexed_artifact_chunk, validate_manifest, verify_catalog_bytes, verify_chunk_bytes,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIndexedArtifactChunk {
    pub descriptor: IndexedArtifactDescriptor,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIndexedArtifactCatalog {
    pub descriptor: IndexedArtifactDescriptor,
    pub catalog: IndexedArtifactCatalog,
}

#[derive(Debug, Clone)]
pub(crate) struct IndexedArtifactManifestFetchResult {
    pub(crate) manifest: IndexedArtifactManifest,
    pub(crate) preferred_gateway_index: Option<usize>,
}

/// Verified manifests shared by every consumer built from clones of one
/// `IndexedArtifactSourceConfig`. Clones share the stored manifests for as
/// long as the configuration lives. The handle is runtime cache state, so it
/// is excluded from configuration equality: any two handles compare equal.
#[derive(Clone, Default)]
pub struct IndexedArtifactManifestReuse {
    slots: std::sync::Arc<std::sync::Mutex<Vec<ManifestReuseSlot>>>,
}

type ManifestReuseEntry = std::sync::Arc<tokio::sync::Mutex<Option<StoredManifest>>>;

struct ManifestReuseSlot {
    manifest_source: IndexedArtifactManifestSource,
    scope: ChainScope,
    entry: ManifestReuseEntry,
}

struct StoredManifest {
    result: IndexedArtifactManifestFetchResult,
    verified_at: tokio::time::Instant,
}

impl IndexedArtifactManifestReuse {
    fn entry(
        &self,
        manifest_source: &IndexedArtifactManifestSource,
        scope: &ChainScope,
    ) -> ManifestReuseEntry {
        let mut slots = self
            .slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(slot) = slots
            .iter()
            .find(|slot| slot.manifest_source == *manifest_source && slot.scope == *scope)
        {
            return std::sync::Arc::clone(&slot.entry);
        }
        let entry = ManifestReuseEntry::default();
        slots.push(ManifestReuseSlot {
            manifest_source: manifest_source.clone(),
            scope: scope.clone(),
            entry: std::sync::Arc::clone(&entry),
        });
        entry
    }
}

impl PartialEq for IndexedArtifactManifestReuse {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for IndexedArtifactManifestReuse {}

impl std::fmt::Debug for IndexedArtifactManifestReuse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IndexedArtifactManifestReuse")
            .finish_non_exhaustive()
    }
}

impl VerifiedIndexedArtifactCatalog {
    #[must_use]
    pub fn into_catalog(self) -> IndexedArtifactCatalog {
        self.catalog
    }
}

impl From<VerifiedIndexedArtifactCatalog> for IndexedArtifactStreamCatalog {
    fn from(verified: VerifiedIndexedArtifactCatalog) -> Self {
        let mut descriptor = verified.descriptor;
        descriptor.metadata.catalog_generation = None;
        descriptor.metadata.stream_partition = None;
        descriptor.metadata.stream_complete = false;
        descriptor.metadata.chunk_sealed = false;
        let chunks = verified
            .catalog
            .chunks
            .into_iter()
            .map(|mut chunk| {
                chunk.metadata.catalog_generation = None;
                chunk.metadata.stream_partition = None;
                chunk.metadata.stream_complete = false;
                chunk.metadata.chunk_sealed = false;
                chunk
            })
            .collect();
        Self::new(descriptor, chunks)
    }
}

#[derive(Clone)]
pub struct IndexedArtifactManifestClient {
    config: IndexedArtifactSourceConfig,
    client: reqwest::Client,
    gateway_pool: GatewayPool,
}

impl IndexedArtifactManifestClient {
    #[must_use]
    pub fn new(config: IndexedArtifactSourceConfig, client: reqwest::Client) -> Self {
        let gateway_pool = config.gateway_pool.clone().unwrap_or_default();
        Self {
            config,
            client,
            gateway_pool,
        }
    }

    fn fetcher(&self) -> TrustlessArtifactFetcher<'_> {
        TrustlessArtifactFetcher::new_with_pool(
            &self.client,
            &self.config.gateway_urls,
            self.gateway_pool.clone(),
        )
    }

    pub async fn fetch_manifest(
        &self,
        expected_scope: &ChainScope,
        last_accepted_sequence: Option<u64>,
        now: SystemTime,
    ) -> Result<IndexedArtifactManifest, IndexedArtifactManifestError> {
        self.fetch_manifest_with_metadata(expected_scope, last_accepted_sequence, now)
            .await
            .map(|result| result.manifest)
    }

    /// Returns a manifest verified for this source and scope less than
    /// `MANIFEST_REUSE_WINDOW` ago if it still validates for this caller;
    /// otherwise fetches and verifies one. The entry lock is held across the
    /// fetch so concurrent callers share it; dropping the future releases it.
    pub(crate) async fn fetch_manifest_with_metadata(
        &self,
        expected_scope: &ChainScope,
        last_accepted_sequence: Option<u64>,
        now: SystemTime,
    ) -> Result<IndexedArtifactManifestFetchResult, IndexedArtifactManifestError> {
        let entry = self
            .config
            .manifest_reuse
            .entry(&self.config.manifest_source, expected_scope);
        let mut reuse = entry.lock().await;
        if let Some(stored) = reuse.as_ref() {
            let age = stored.verified_at.elapsed();
            if age < MANIFEST_REUSE_WINDOW
                && validate_manifest(
                    &stored.result.manifest,
                    &self.config,
                    expected_scope,
                    last_accepted_sequence,
                    now,
                )
                .is_ok()
            {
                debug!(
                    manifest_sequence = stored.result.manifest.sequence,
                    age_ms = age.as_millis(),
                    "reused verified indexed artifact manifest"
                );
                return Ok(stored.result.clone());
            }
        }
        let result = self
            .fetch_verified_manifest(expected_scope, last_accepted_sequence, now)
            .await?;
        *reuse = Some(StoredManifest {
            result: result.clone(),
            verified_at: tokio::time::Instant::now(),
        });
        Ok(result)
    }

    async fn fetch_verified_manifest(
        &self,
        expected_scope: &ChainScope,
        last_accepted_sequence: Option<u64>,
        now: SystemTime,
    ) -> Result<IndexedArtifactManifestFetchResult, IndexedArtifactManifestError> {
        match &self.config.manifest_source {
            IndexedArtifactManifestSource::Url(url) => {
                let started = Instant::now();
                let bytes =
                    match crate::trustless_artifacts::fetch_manifest_url(&self.client, url).await {
                        Ok(bytes) => bytes,
                        Err(err) => {
                            debug!(
                                ?err,
                                elapsed_ms = started.elapsed().as_millis(),
                                "indexed artifact manifest URL fetch failed"
                            );
                            return Err(err.into());
                        }
                    };
                let manifest = match self.verify_manifest_bytes(
                    &bytes,
                    expected_scope,
                    last_accepted_sequence,
                    now,
                ) {
                    Ok(manifest) => manifest,
                    Err(err) => {
                        debug!(
                            ?err,
                            bytes = bytes.len(),
                            elapsed_ms = started.elapsed().as_millis(),
                            "indexed artifact manifest URL verification failed"
                        );
                        return Err(err);
                    }
                };
                debug!(
                    bytes = bytes.len(),
                    manifest_sequence = manifest.sequence,
                    elapsed_ms = started.elapsed().as_millis(),
                    "fetched indexed artifact manifest from explicit URL"
                );
                Ok(IndexedArtifactManifestFetchResult {
                    manifest,
                    preferred_gateway_index: None,
                })
            }
            IndexedArtifactManifestSource::Cid(cid) => {
                self.fetch_manifest_from_cid(cid, expected_scope, last_accepted_sequence, now)
                    .await
            }
            IndexedArtifactManifestSource::IpnsName(name) => {
                self.fetch_manifest_from_ipns_name(
                    name,
                    expected_scope,
                    last_accepted_sequence,
                    now,
                )
                .await
            }
        }
    }

    pub async fn fetch_catalog(
        &self,
        descriptor: &IndexedArtifactDescriptor,
    ) -> Result<VerifiedIndexedArtifactCatalog, IndexedArtifactManifestError> {
        self.fetch_catalog_with_preferred_gateway(descriptor, None)
            .await
    }

    pub(crate) async fn fetch_catalog_with_preferred_gateway(
        &self,
        descriptor: &IndexedArtifactDescriptor,
        preferred_gateway_index: Option<usize>,
    ) -> Result<VerifiedIndexedArtifactCatalog, IndexedArtifactManifestError> {
        validate_catalog_descriptor_for_expansion(descriptor)?;
        let started = Instant::now();
        let fetcher = self.fetcher();
        let bytes = match match preferred_gateway_index {
            Some(preferred_gateway_index) => fetcher
                .fetch_artifact_cid_with_metadata_from_gateway(
                    &descriptor.cid,
                    descriptor.byte_size,
                    preferred_gateway_index,
                )
                .await
                .map(TrustlessArtifactFetchResult::into_bytes),
            None => {
                fetcher
                    .fetch_artifact_cid(&descriptor.cid, descriptor.byte_size)
                    .await
            }
        } {
            Ok(bytes) => bytes,
            Err(err) => {
                debug!(
                    ?err,
                    cid = %descriptor.cid,
                    dataset_kind = ?descriptor.dataset_kind,
                    range_start = descriptor.range.start,
                    range_end = descriptor.range.end,
                    byte_size = descriptor.byte_size,
                    row_count = descriptor.row_count,
                    elapsed_ms = started.elapsed().as_millis(),
                    "indexed artifact catalog fetch failed"
                );
                return Err(err.into());
            }
        };
        let catalog = match verify_catalog_bytes(descriptor, &bytes) {
            Ok(catalog) => catalog,
            Err(err) => {
                debug!(
                    ?err,
                    cid = %descriptor.cid,
                    dataset_kind = ?descriptor.dataset_kind,
                    range_start = descriptor.range.start,
                    range_end = descriptor.range.end,
                    byte_size = descriptor.byte_size,
                    row_count = descriptor.row_count,
                    elapsed_ms = started.elapsed().as_millis(),
                    "indexed artifact catalog verification failed"
                );
                return Err(err);
            }
        };
        debug!(
            cid = %descriptor.cid,
            dataset_kind = ?descriptor.dataset_kind,
            bytes = bytes.len(),
            chunks = catalog.chunks.len(),
            elapsed_ms = started.elapsed().as_millis(),
            "fetched verified indexed artifact catalog"
        );
        Ok(VerifiedIndexedArtifactCatalog {
            descriptor: descriptor.clone(),
            catalog,
        })
    }

    async fn fetch_manifest_from_cid(
        &self,
        cid: &str,
        expected_scope: &ChainScope,
        last_accepted_sequence: Option<u64>,
        now: SystemTime,
    ) -> Result<IndexedArtifactManifestFetchResult, IndexedArtifactManifestError> {
        let started = Instant::now();
        let fetched = match self.fetcher().fetch_manifest_cid_with_metadata(cid).await {
            Ok(bytes) => bytes,
            Err(err) => {
                debug!(
                    ?err,
                    cid,
                    elapsed_ms = started.elapsed().as_millis(),
                    "indexed artifact manifest CID fetch failed"
                );
                return Err(err.into());
            }
        };
        let manifest = match self.verify_manifest_bytes(
            fetched.bytes(),
            expected_scope,
            last_accepted_sequence,
            now,
        ) {
            Ok(manifest) => manifest,
            Err(err) => {
                debug!(
                    ?err,
                    cid,
                    bytes = fetched.bytes().len(),
                    elapsed_ms = started.elapsed().as_millis(),
                    "indexed artifact manifest CID verification failed"
                );
                return Err(err);
            }
        };
        debug!(
            cid,
            bytes = fetched.bytes().len(),
            manifest_sequence = manifest.sequence,
            elapsed_ms = started.elapsed().as_millis(),
            "fetched trustless indexed artifact manifest CID"
        );
        Ok(IndexedArtifactManifestFetchResult {
            manifest,
            preferred_gateway_index: Some(fetched.gateway_index()),
        })
    }

    async fn fetch_manifest_from_ipns_name(
        &self,
        name: &str,
        expected_scope: &ChainScope,
        last_accepted_sequence: Option<u64>,
        now: SystemTime,
    ) -> Result<IndexedArtifactManifestFetchResult, IndexedArtifactManifestError> {
        let started = Instant::now();
        let fetcher = self.fetcher();
        let candidates = fetcher
            .resolve_ipns_manifest_candidates(name, last_accepted_sequence)
            .await?;
        let candidate_count = candidates.len();
        let mut last_error = None;
        for (candidate_index, candidate) in candidates.into_iter().enumerate() {
            match fetcher
                .fetch_manifest_cid_with_metadata_from_gateway(
                    &candidate.cid.to_string(),
                    Some(candidate.gateway_index()),
                )
                .await
            {
                Ok(fetched) => match self.verify_manifest_bytes(
                    fetched.bytes(),
                    expected_scope,
                    last_accepted_sequence,
                    now,
                ) {
                    Ok(manifest) => {
                        debug!(
                            ipns_name = name,
                            cid = %candidate.cid,
                            ipns_sequence = candidate.sequence,
                            candidate_index,
                            candidate_count,
                            manifest_sequence = manifest.sequence,
                            elapsed_ms = started.elapsed().as_millis(),
                            "fetched trustless indexed artifact manifest through verified IPNS"
                        );
                        return Ok(IndexedArtifactManifestFetchResult {
                            manifest,
                            preferred_gateway_index: Some(fetched.gateway_index()),
                        });
                    }
                    Err(err) => {
                        debug!(
                            ?err,
                            ipns_name = name,
                            cid = %candidate.cid,
                            ipns_sequence = candidate.sequence,
                            candidate_index,
                            candidate_count,
                            elapsed_ms = started.elapsed().as_millis(),
                            "verified indexed artifact IPNS candidate failed manifest acceptance"
                        );
                        last_error = Some(err);
                    }
                },
                Err(err) => {
                    debug!(
                        ?err,
                        ipns_name = name,
                        cid = %candidate.cid,
                        ipns_sequence = candidate.sequence,
                        candidate_index,
                        candidate_count,
                        elapsed_ms = started.elapsed().as_millis(),
                        "verified indexed artifact IPNS manifest CID fetch failed"
                    );
                    last_error = Some(IndexedArtifactManifestError::from(err));
                }
            }
        }
        Err(last_error.unwrap_or(IndexedArtifactManifestError::NoValidManifest))
    }

    fn verify_manifest_bytes(
        &self,
        bytes: &[u8],
        expected_scope: &ChainScope,
        last_accepted_sequence: Option<u64>,
        now: SystemTime,
    ) -> Result<IndexedArtifactManifest, IndexedArtifactManifestError> {
        let manifest: IndexedArtifactManifest = serde_json::from_slice(bytes)?;
        validate_manifest(
            &manifest,
            &self.config,
            expected_scope,
            last_accepted_sequence,
            now,
        )?;
        Ok(manifest)
    }
}

#[cfg(test)]
mod tests;
