use std::collections::BTreeMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use alloy::hex;
use futures::{StreamExt, stream::FuturesUnordered};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::debug;

pub use railgun_indexed_artifacts::{
    ChainScope, ChainType, ChunkError as IndexedArtifactChunkError, CompressionAlgorithm,
    DatasetDescriptorMetadata, INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
    INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION, INDEXED_ARTIFACT_CHUNK_MAGIC,
    INDEXED_ARTIFACT_MANIFEST_FORMAT_VERSION, INDEXED_ARTIFACT_MAX_COMPRESSED_CHUNK_BYTES,
    IndexedArtifactCatalog, IndexedArtifactChainEntry, IndexedArtifactChunkEnvelope,
    IndexedArtifactChunkEnvelopeHeader, IndexedArtifactChunkSection, IndexedArtifactDescriptor,
    IndexedArtifactError, IndexedArtifactManifest, IndexedArtifactRange, IndexedArtifactRangeKind,
    IndexedDatasetKind, LatestIndexedHeight, PublisherIdentity, PublisherKeyAlgorithm,
    format_scope,
};

use crate::trustless_artifacts::{TrustlessArtifactError, TrustlessArtifactFetcher};
use crate::types::{IndexedArtifactManifestSource, IndexedArtifactSourceConfig};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIndexedArtifactChunk {
    pub descriptor: IndexedArtifactDescriptor,
    pub bytes: Vec<u8>,
}

struct FetchedIndexedArtifactChunk {
    index: usize,
    byte_size: u64,
    chunk: VerifiedIndexedArtifactChunk,
    gateway_host: String,
    gateway_index: usize,
    gateway_count: usize,
    elapsed_ms: u128,
}

#[derive(Debug, Clone)]
pub struct VerifiedIndexedArtifactChunkStager {
    dataset_kind: IndexedDatasetKind,
    scope: ChainScope,
    range_kind: IndexedArtifactRangeKind,
    next_range_start: u64,
    staged: BTreeMap<u64, VerifiedIndexedArtifactChunk>,
}

impl VerifiedIndexedArtifactChunkStager {
    #[must_use]
    pub fn new(
        dataset_kind: IndexedDatasetKind,
        scope: ChainScope,
        range_kind: IndexedArtifactRangeKind,
        next_range_start: u64,
    ) -> Self {
        Self {
            dataset_kind,
            scope,
            range_kind,
            next_range_start,
            staged: BTreeMap::new(),
        }
    }

    #[must_use]
    pub const fn next_range_start(&self) -> u64 {
        self.next_range_start
    }

    #[must_use]
    pub fn staged_len(&self) -> usize {
        self.staged.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.staged.is_empty()
    }

    pub fn stage(
        &mut self,
        chunk: VerifiedIndexedArtifactChunk,
    ) -> Result<(), IndexedArtifactManifestError> {
        self.validate_stage_descriptor(&chunk.descriptor)?;
        self.staged.insert(chunk.descriptor.range.start, chunk);
        Ok(())
    }

    pub fn stage_many(
        &mut self,
        chunks: impl IntoIterator<Item = VerifiedIndexedArtifactChunk>,
    ) -> Result<(), IndexedArtifactManifestError> {
        for chunk in chunks {
            self.stage(chunk)?;
        }
        Ok(())
    }

    pub fn drain_contiguous(
        &mut self,
    ) -> Result<Vec<VerifiedIndexedArtifactChunk>, IndexedArtifactManifestError> {
        let mut ready = Vec::new();
        while let Some(chunk) = self.staged.get(&self.next_range_start) {
            let next_range_start = chunk.descriptor.range.end.checked_add(1).ok_or(
                IndexedArtifactManifestError::StagedChunkRangeEndOverflow {
                    end: chunk.descriptor.range.end,
                },
            )?;
            let chunk = self
                .staged
                .remove(&self.next_range_start)
                .expect("chunk was present for next range start");
            self.next_range_start = next_range_start;
            ready.push(chunk);
        }
        Ok(ready)
    }

    fn validate_stage_descriptor(
        &self,
        descriptor: &IndexedArtifactDescriptor,
    ) -> Result<(), IndexedArtifactManifestError> {
        if descriptor.dataset_kind != self.dataset_kind {
            return Err(IndexedArtifactManifestError::StagedChunkDatasetMismatch {
                expected: self.dataset_kind,
                actual: descriptor.dataset_kind,
            });
        }
        if descriptor.scope != self.scope {
            return Err(IndexedArtifactManifestError::StagedChunkScopeMismatch {
                expected: format_scope(&self.scope),
                actual: format_scope(&descriptor.scope),
            });
        }
        if descriptor.range.kind != self.range_kind {
            return Err(IndexedArtifactManifestError::StagedChunkRangeKindMismatch {
                expected: self.range_kind,
                actual: descriptor.range.kind,
            });
        }
        if descriptor.range.start > descriptor.range.end {
            return Err(IndexedArtifactManifestError::StagedChunkInvalidRange {
                start: descriptor.range.start,
                end: descriptor.range.end,
            });
        }
        if descriptor.range.start < self.next_range_start {
            return Err(IndexedArtifactManifestError::StagedChunkBeforeProgress {
                next_range_start: self.next_range_start,
                chunk_start: descriptor.range.start,
                chunk_end: descriptor.range.end,
            });
        }
        if self.staged.contains_key(&descriptor.range.start) {
            return Err(
                IndexedArtifactManifestError::StagedChunkDuplicateRangeStart {
                    start: descriptor.range.start,
                },
            );
        }
        if let Some(existing) = self
            .staged
            .range(..=descriptor.range.end)
            .next_back()
            .map(|(_, chunk)| &chunk.descriptor.range)
            && existing.end >= descriptor.range.start
        {
            return Err(IndexedArtifactManifestError::StagedChunkRangeOverlap {
                existing_start: existing.start,
                existing_end: existing.end,
                chunk_start: descriptor.range.start,
                chunk_end: descriptor.range.end,
            });
        }
        if let Some(existing) = self
            .staged
            .range(descriptor.range.start..)
            .next()
            .map(|(_, chunk)| &chunk.descriptor.range)
            && existing.start <= descriptor.range.end
        {
            return Err(IndexedArtifactManifestError::StagedChunkRangeOverlap {
                existing_start: existing.start,
                existing_end: existing.end,
                chunk_start: descriptor.range.start,
                chunk_end: descriptor.range.end,
            });
        }
        Ok(())
    }
}

pub struct IndexedArtifactManifestClient {
    config: IndexedArtifactSourceConfig,
    client: reqwest::Client,
}

impl IndexedArtifactManifestClient {
    #[must_use]
    pub const fn new(config: IndexedArtifactSourceConfig, client: reqwest::Client) -> Self {
        Self { config, client }
    }

    pub async fn fetch_manifest(
        &self,
        expected_scope: &ChainScope,
        last_accepted_sequence: Option<u64>,
        now: SystemTime,
    ) -> Result<IndexedArtifactManifest, IndexedArtifactManifestError> {
        match &self.config.manifest_source {
            IndexedArtifactManifestSource::Url(url) => {
                let started = Instant::now();
                let bytes =
                    match crate::trustless_artifacts::fetch_manifest_url(&self.client, url).await {
                        Ok(bytes) => bytes,
                        Err(err) => {
                            debug!(
                                ?err,
                                url = %url,
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
                            url = %url,
                            bytes = bytes.len(),
                            elapsed_ms = started.elapsed().as_millis(),
                            "indexed artifact manifest URL verification failed"
                        );
                        return Err(err);
                    }
                };
                debug!(
                    url = %url,
                    bytes = bytes.len(),
                    manifest_sequence = manifest.sequence,
                    elapsed_ms = started.elapsed().as_millis(),
                    "fetched indexed artifact manifest from explicit URL"
                );
                Ok(manifest)
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
    ) -> Result<IndexedArtifactCatalog, IndexedArtifactManifestError> {
        validate_catalog_descriptor_for_expansion(descriptor)?;
        let started = Instant::now();
        let bytes = match TrustlessArtifactFetcher::new(&self.client, &self.config.gateway_urls)
            .fetch_artifact_cid(&descriptor.cid, descriptor.byte_size)
            .await
        {
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
        Ok(catalog)
    }

    pub async fn fetch_chunks_bounded(
        &self,
        descriptors: &[IndexedArtifactDescriptor],
    ) -> Result<Vec<VerifiedIndexedArtifactChunk>, IndexedArtifactManifestError> {
        self.fetch_chunks_bounded_with_progress(descriptors, |_, _| {})
            .await
    }

    pub async fn fetch_chunks_bounded_with_progress<F>(
        &self,
        descriptors: &[IndexedArtifactDescriptor],
        mut on_chunk_verified: F,
    ) -> Result<Vec<VerifiedIndexedArtifactChunk>, IndexedArtifactManifestError>
    where
        F: FnMut(usize, usize),
    {
        let total_chunks = descriptors.len();
        let concurrency = self.config.concurrency;
        if concurrency == 0 {
            return Err(IndexedArtifactManifestError::InvalidChunkConcurrency);
        }
        let batch_started = Instant::now();
        let max_in_flight_bytes = self.config.max_in_flight_bytes;
        let fetcher = TrustlessArtifactFetcher::new(&self.client, &self.config.gateway_urls);
        let mut results = vec![None; descriptors.len()];
        let mut next_index = 0;
        let mut completed_chunks = 0;
        let mut in_flight_bytes = 0_u64;
        let mut max_observed_in_flight_chunks = 0_usize;
        let mut max_observed_in_flight_bytes = 0_u64;
        let mut byte_budget_waits = 0_u64;
        let mut in_flight = FuturesUnordered::new();

        while next_index < descriptors.len() || !in_flight.is_empty() {
            while next_index < descriptors.len() && in_flight.len() < concurrency {
                let descriptor = descriptors[next_index].clone();
                if descriptor.byte_size > max_in_flight_bytes {
                    return Err(IndexedArtifactManifestError::ChunkExceedsInFlightBudget {
                        cid: descriptor.cid,
                        byte_size: descriptor.byte_size,
                        max_in_flight_bytes,
                    });
                }
                let next_in_flight_bytes = in_flight_bytes.saturating_add(descriptor.byte_size);
                if next_in_flight_bytes > max_in_flight_bytes {
                    byte_budget_waits = byte_budget_waits.saturating_add(1);
                    debug!(
                        dataset_kind = ?descriptor.dataset_kind,
                        range_start = descriptor.range.start,
                        range_end = descriptor.range.end,
                        next_index,
                        next_byte_size = descriptor.byte_size,
                        in_flight_chunks = in_flight.len(),
                        in_flight_bytes,
                        max_in_flight_bytes,
                        configured_concurrency = concurrency,
                        "indexed artifact chunk in-flight byte budget saturated"
                    );
                    break;
                }
                let index = next_index;
                let byte_size = descriptor.byte_size;
                let cid = descriptor.cid.clone();
                let dataset_kind = descriptor.dataset_kind;
                let range_start = descriptor.range.start;
                let range_end = descriptor.range.end;
                in_flight_bytes = next_in_flight_bytes;
                next_index += 1;
                let fetcher = &fetcher;
                in_flight.push(async move {
                    let started = Instant::now();
                    let fetched = match fetcher
                        .fetch_artifact_cid_with_metadata(&descriptor.cid, descriptor.byte_size)
                        .await
                    {
                        Ok(fetched) => fetched,
                        Err(err) => {
                            debug!(
                                ?err,
                                cid = %cid,
                                dataset_kind = ?dataset_kind,
                                range_start,
                                range_end,
                                byte_size,
                                index,
                                elapsed_ms = started.elapsed().as_millis(),
                                "indexed artifact chunk fetch failed"
                            );
                            return Err(err.into());
                        }
                    };
                    let gateway_host = fetched.gateway_host;
                    let gateway_index = fetched.gateway_index;
                    let gateway_count = fetched.gateway_count;
                    let chunk = match verify_chunk_bytes(descriptor, fetched.bytes) {
                        Ok(chunk) => chunk,
                        Err(err) => {
                            debug!(
                                ?err,
                                cid = %cid,
                                dataset_kind = ?dataset_kind,
                                range_start,
                                range_end,
                                byte_size,
                                index,
                                gateway_host,
                                gateway_index,
                                gateway_count,
                                elapsed_ms = started.elapsed().as_millis(),
                                "indexed artifact chunk verification failed"
                            );
                            return Err(err);
                        }
                    };
                    Ok::<_, IndexedArtifactManifestError>(FetchedIndexedArtifactChunk {
                        index,
                        byte_size,
                        chunk,
                        gateway_host,
                        gateway_index,
                        gateway_count,
                        elapsed_ms: started.elapsed().as_millis(),
                    })
                });
                max_observed_in_flight_chunks = max_observed_in_flight_chunks.max(in_flight.len());
                max_observed_in_flight_bytes = max_observed_in_flight_bytes.max(in_flight_bytes);
            }

            let Some(completed) = in_flight.next().await else {
                continue;
            };
            let fetched = completed?;
            in_flight_bytes = in_flight_bytes.saturating_sub(fetched.byte_size);
            completed_chunks += 1;
            on_chunk_verified(completed_chunks, total_chunks);
            debug!(
                cid = %fetched.chunk.descriptor.cid,
                dataset_kind = ?fetched.chunk.descriptor.dataset_kind,
                range_start = fetched.chunk.descriptor.range.start,
                range_end = fetched.chunk.descriptor.range.end,
                byte_size = fetched.byte_size,
                index = fetched.index,
                completed_chunks,
                total_chunks,
                gateway_host = fetched.gateway_host,
                gateway_index = fetched.gateway_index,
                gateway_count = fetched.gateway_count,
                elapsed_ms = fetched.elapsed_ms,
                "indexed artifact chunk fetch verified"
            );
            results[fetched.index] = Some(fetched.chunk);
        }

        debug!(
            total_chunks,
            configured_concurrency = concurrency,
            max_observed_in_flight_chunks,
            max_observed_in_flight_bytes,
            max_in_flight_bytes,
            byte_budget_waits,
            elapsed_ms = batch_started.elapsed().as_millis(),
            "indexed artifact chunk fetch batch complete"
        );

        Ok(results
            .into_iter()
            .map(|chunk| chunk.expect("all scheduled chunks completed"))
            .collect())
    }

    async fn fetch_manifest_from_cid(
        &self,
        cid: &str,
        expected_scope: &ChainScope,
        last_accepted_sequence: Option<u64>,
        now: SystemTime,
    ) -> Result<IndexedArtifactManifest, IndexedArtifactManifestError> {
        let started = Instant::now();
        let bytes = match TrustlessArtifactFetcher::new(&self.client, &self.config.gateway_urls)
            .fetch_manifest_cid(cid)
            .await
        {
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
        let manifest =
            match self.verify_manifest_bytes(&bytes, expected_scope, last_accepted_sequence, now) {
                Ok(manifest) => manifest,
                Err(err) => {
                    debug!(
                        ?err,
                        cid,
                        bytes = bytes.len(),
                        elapsed_ms = started.elapsed().as_millis(),
                        "indexed artifact manifest CID verification failed"
                    );
                    return Err(err);
                }
            };
        debug!(
            cid,
            bytes = bytes.len(),
            manifest_sequence = manifest.sequence,
            elapsed_ms = started.elapsed().as_millis(),
            "fetched trustless indexed artifact manifest CID"
        );
        Ok(manifest)
    }

    async fn fetch_manifest_from_ipns_name(
        &self,
        name: &str,
        expected_scope: &ChainScope,
        last_accepted_sequence: Option<u64>,
        now: SystemTime,
    ) -> Result<IndexedArtifactManifest, IndexedArtifactManifestError> {
        let started = Instant::now();
        let fetcher = TrustlessArtifactFetcher::new(&self.client, &self.config.gateway_urls);
        let candidates = fetcher.resolve_ipns_manifest_candidates(name, now).await?;
        let candidate_count = candidates.len();
        let mut last_error = None;
        for (candidate_index, candidate) in candidates.into_iter().enumerate() {
            match fetcher.fetch_manifest_cid(&candidate.cid.to_string()).await {
                Ok(bytes) => match self.verify_manifest_bytes(
                    &bytes,
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
                        return Ok(manifest);
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

pub fn validate_manifest(
    manifest: &IndexedArtifactManifest,
    config: &IndexedArtifactSourceConfig,
    expected_scope: &ChainScope,
    last_accepted_sequence: Option<u64>,
    now: SystemTime,
) -> Result<(), IndexedArtifactManifestError> {
    if manifest.format_version != INDEXED_ARTIFACT_MANIFEST_FORMAT_VERSION {
        return Err(IndexedArtifactManifestError::UnsupportedManifestVersion {
            version: manifest.format_version,
        });
    }
    manifest.verify_trusted_signature(&config.trusted_publisher_pubkey.0)?;
    validate_manifest_sequence(manifest.sequence, last_accepted_sequence)?;
    validate_manifest_freshness(
        manifest.sequence,
        manifest.issued_at_ms,
        last_accepted_sequence,
        config.max_manifest_age,
        now,
    )?;
    validate_manifest_scope(manifest, expected_scope)
}

pub fn verify_catalog_bytes(
    descriptor: &IndexedArtifactDescriptor,
    bytes: &[u8],
) -> Result<IndexedArtifactCatalog, IndexedArtifactManifestError> {
    validate_catalog_descriptor_for_expansion(descriptor)?;
    let actual_size =
        u64::try_from(bytes.len()).map_err(|_| IndexedArtifactManifestError::ByteSizeOverflow)?;
    if actual_size != descriptor.byte_size {
        return Err(IndexedArtifactManifestError::ArtifactByteSizeMismatch {
            cid: descriptor.cid.clone(),
            expected: descriptor.byte_size,
            actual: actual_size,
        });
    }
    let actual_hash = Sha256::digest(bytes);
    if actual_hash.as_slice() != descriptor.sha256.as_slice() {
        return Err(IndexedArtifactManifestError::ArtifactHashMismatch {
            cid: descriptor.cid.clone(),
            expected: hex::encode_prefixed(descriptor.sha256.as_slice()),
            actual: hex::encode_prefixed(actual_hash),
        });
    }

    let mut catalog: IndexedArtifactCatalog = serde_json::from_slice(bytes)?;
    if catalog.format_version != INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION {
        return Err(IndexedArtifactManifestError::UnsupportedCatalogVersion {
            version: catalog.format_version,
        });
    }
    if catalog.dataset_kind != descriptor.dataset_kind {
        return Err(IndexedArtifactManifestError::CatalogDatasetMismatch {
            expected: descriptor.dataset_kind,
            actual: catalog.dataset_kind,
        });
    }
    if catalog.scope != descriptor.scope {
        return Err(IndexedArtifactManifestError::CatalogScopeMismatch {
            expected: format_scope(&descriptor.scope),
            actual: format_scope(&catalog.scope),
        });
    }
    for chunk in &catalog.chunks {
        validate_chunk_descriptor_scope(descriptor, chunk)?;
    }
    validate_catalog_descriptor_aggregate(descriptor, &catalog.chunks)?;
    catalog.chunks = catalog
        .chunks
        .into_iter()
        .map(|chunk| chunk.with_inherited_catalog_generation(descriptor))
        .collect();
    Ok(catalog)
}

pub fn verify_chunk_bytes(
    descriptor: IndexedArtifactDescriptor,
    bytes: Vec<u8>,
) -> Result<VerifiedIndexedArtifactChunk, IndexedArtifactManifestError> {
    let actual_size =
        u64::try_from(bytes.len()).map_err(|_| IndexedArtifactManifestError::ByteSizeOverflow)?;
    if actual_size != descriptor.byte_size {
        return Err(IndexedArtifactManifestError::ArtifactByteSizeMismatch {
            cid: descriptor.cid,
            expected: descriptor.byte_size,
            actual: actual_size,
        });
    }
    let actual_hash = Sha256::digest(&bytes);
    if actual_hash.as_slice() != descriptor.sha256.as_slice() {
        return Err(IndexedArtifactManifestError::ArtifactHashMismatch {
            cid: descriptor.cid,
            expected: hex::encode_prefixed(descriptor.sha256.as_slice()),
            actual: hex::encode_prefixed(actual_hash),
        });
    }
    Ok(VerifiedIndexedArtifactChunk { descriptor, bytes })
}

pub fn decode_indexed_artifact_chunk(
    chunk: &VerifiedIndexedArtifactChunk,
) -> Result<IndexedArtifactChunkEnvelope, IndexedArtifactManifestError> {
    railgun_indexed_artifacts::decode_chunk_bytes(&chunk.descriptor, &chunk.bytes)
        .map_err(Into::into)
}

fn validate_chunk_descriptor_scope(
    catalog: &IndexedArtifactDescriptor,
    chunk: &IndexedArtifactDescriptor,
) -> Result<(), IndexedArtifactManifestError> {
    if chunk.dataset_kind != catalog.dataset_kind {
        return Err(IndexedArtifactManifestError::CatalogChunkDatasetMismatch {
            expected: catalog.dataset_kind,
            actual: chunk.dataset_kind,
        });
    }
    if chunk.scope != catalog.scope {
        return Err(IndexedArtifactManifestError::CatalogScopeMismatch {
            expected: format_scope(&catalog.scope),
            actual: format_scope(&chunk.scope),
        });
    }
    if chunk.range.kind != catalog.range.kind
        || chunk.range.start < catalog.range.start
        || chunk.range.end > catalog.range.end
    {
        return Err(IndexedArtifactManifestError::CatalogChunkRangeMismatch {
            catalog_start: catalog.range.start,
            catalog_end: catalog.range.end,
            chunk_start: chunk.range.start,
            chunk_end: chunk.range.end,
        });
    }
    Ok(())
}

fn validate_catalog_descriptor_for_expansion(
    descriptor: &IndexedArtifactDescriptor,
) -> Result<(), IndexedArtifactManifestError> {
    if descriptor.metadata.catalog_generation.is_none() {
        return Err(IndexedArtifactManifestError::CatalogMissingGeneration {
            cid: descriptor.cid.clone(),
        });
    }
    if descriptor.range.start > descriptor.range.end {
        return Err(
            IndexedArtifactManifestError::CatalogDescriptorInvalidRange {
                cid: descriptor.cid.clone(),
                start: descriptor.range.start,
                end: descriptor.range.end,
            },
        );
    }
    Ok(())
}

fn validate_catalog_descriptor_aggregate(
    descriptor: &IndexedArtifactDescriptor,
    chunks: &[IndexedArtifactDescriptor],
) -> Result<(), IndexedArtifactManifestError> {
    if chunks.is_empty() {
        if descriptor.row_count != 0 {
            return Err(IndexedArtifactManifestError::EmptyCatalogRowCountMismatch {
                cid: descriptor.cid.clone(),
                row_count: descriptor.row_count,
            });
        }
        return Ok(());
    }

    let mut aggregate_start = u64::MAX;
    let mut aggregate_end = 0_u64;
    let mut aggregate_row_count = 0_u64;
    for chunk in chunks {
        if chunk.range.start > chunk.range.end {
            return Err(IndexedArtifactManifestError::CatalogChunkInvalidRange {
                cid: chunk.cid.clone(),
                start: chunk.range.start,
                end: chunk.range.end,
            });
        }
        aggregate_start = aggregate_start.min(chunk.range.start);
        aggregate_end = aggregate_end.max(chunk.range.end);
        aggregate_row_count = aggregate_row_count
            .checked_add(chunk.row_count)
            .ok_or_else(
                || IndexedArtifactManifestError::CatalogAggregateRowCountOverflow {
                    cid: descriptor.cid.clone(),
                },
            )?;
    }

    if descriptor.range.start != aggregate_start || descriptor.range.end != aggregate_end {
        return Err(
            IndexedArtifactManifestError::CatalogAggregateRangeMismatch {
                expected_start: descriptor.range.start,
                expected_end: descriptor.range.end,
                actual_start: aggregate_start,
                actual_end: aggregate_end,
            },
        );
    }
    if descriptor.row_count != aggregate_row_count {
        return Err(
            IndexedArtifactManifestError::CatalogAggregateRowCountMismatch {
                expected: descriptor.row_count,
                actual: aggregate_row_count,
            },
        );
    }
    Ok(())
}

fn validate_manifest_sequence(
    sequence: u64,
    last_accepted_sequence: Option<u64>,
) -> Result<(), IndexedArtifactManifestError> {
    if let Some(previous) = last_accepted_sequence
        && sequence < previous
    {
        return Err(IndexedArtifactManifestError::ManifestSequenceRollback {
            previous,
            received: sequence,
        });
    }
    Ok(())
}

fn validate_manifest_freshness(
    sequence: u64,
    issued_at_ms: u64,
    last_accepted_sequence: Option<u64>,
    max_age: Option<Duration>,
    now: SystemTime,
) -> Result<(), IndexedArtifactManifestError> {
    if last_accepted_sequence.is_some_and(|previous| sequence <= previous) {
        return Ok(());
    }
    let Some(max_age) = max_age else {
        return Ok(());
    };
    let issued_at = UNIX_EPOCH + Duration::from_millis(issued_at_ms);
    let age = now
        .duration_since(issued_at)
        .map_err(|_| IndexedArtifactManifestError::ManifestIssuedInFuture)?;
    if age > max_age {
        return Err(IndexedArtifactManifestError::ManifestStale { age, max: max_age });
    }
    Ok(())
}

fn validate_manifest_scope(
    manifest: &IndexedArtifactManifest,
    expected_scope: &ChainScope,
) -> Result<(), IndexedArtifactManifestError> {
    let chain = manifest
        .chains
        .iter()
        .find(|entry| entry.scope == *expected_scope)
        .ok_or_else(|| IndexedArtifactManifestError::MissingChainScope {
            chain_id: expected_scope.chain_id,
            railgun_contract: hex::encode_prefixed(expected_scope.railgun_contract.as_slice()),
        })?;
    for catalog in &chain.catalogs {
        if catalog.scope != chain.scope {
            return Err(IndexedArtifactManifestError::CatalogScopeMismatch {
                expected: format_scope(&chain.scope),
                actual: format_scope(&catalog.scope),
            });
        }
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum IndexedArtifactManifestError {
    #[error("indexed artifact JSON decode failed")]
    Json(#[from] serde_json::Error),
    #[error("indexed artifact trustless retrieval failed: {message}")]
    Trustless { message: String },
    #[error("unsupported indexed artifact manifest version {version}")]
    UnsupportedManifestVersion { version: u16 },
    #[error("unsupported indexed artifact catalog version {version}")]
    UnsupportedCatalogVersion { version: u16 },
    #[error("indexed artifact publisher public key mismatch: expected {expected}, got {actual}")]
    PublisherKeyMismatch { expected: String, actual: String },
    #[error("indexed artifact manifest publisher signature is missing")]
    MissingPublisherSignature,
    #[error("invalid indexed artifact publisher public key")]
    PublicKey {
        source: ed25519_dalek::SignatureError,
    },
    #[error("indexed artifact manifest signature verification failed")]
    Signature {
        source: ed25519_dalek::SignatureError,
    },
    #[error("invalid indexed artifact hex: {message}")]
    Hex { message: String },
    #[error(
        "indexed artifact manifest sequence rollback: previous={previous}, received={received}"
    )]
    ManifestSequenceRollback { previous: u64, received: u64 },
    #[error("indexed artifact manifest is stale: age={age:?}, max={max:?}")]
    ManifestStale { age: Duration, max: Duration },
    #[error("indexed artifact manifest issued_at_ms is in the future")]
    ManifestIssuedInFuture,
    #[error("indexed artifact manifest has no valid candidate")]
    NoValidManifest,
    #[error(
        "indexed artifact manifest does not contain chain scope chain_id={chain_id} contract={railgun_contract}"
    )]
    MissingChainScope {
        chain_id: u64,
        railgun_contract: String,
    },
    #[error("indexed artifact catalog scope mismatch: expected {expected}, got {actual}")]
    CatalogScopeMismatch { expected: String, actual: String },
    #[error("indexed artifact catalog dataset mismatch: expected {expected:?}, got {actual:?}")]
    CatalogDatasetMismatch {
        expected: IndexedDatasetKind,
        actual: IndexedDatasetKind,
    },
    #[error(
        "indexed artifact catalog chunk dataset mismatch: expected {expected:?}, got {actual:?}"
    )]
    CatalogChunkDatasetMismatch {
        expected: IndexedDatasetKind,
        actual: IndexedDatasetKind,
    },
    #[error(
        "indexed artifact catalog chunk range {chunk_start}-{chunk_end} is outside catalog range {catalog_start}-{catalog_end}"
    )]
    CatalogChunkRangeMismatch {
        catalog_start: u64,
        catalog_end: u64,
        chunk_start: u64,
        chunk_end: u64,
    },
    #[error("indexed artifact catalog {cid} missing catalog generation metadata")]
    CatalogMissingGeneration { cid: String },
    #[error("indexed artifact catalog {cid} range start {start} exceeds end {end}")]
    CatalogDescriptorInvalidRange { cid: String, start: u64, end: u64 },
    #[error("indexed artifact catalog chunk {cid} range start {start} exceeds end {end}")]
    CatalogChunkInvalidRange { cid: String, start: u64, end: u64 },
    #[error(
        "indexed artifact catalog aggregate range mismatch: expected {expected_start}-{expected_end}, got {actual_start}-{actual_end}"
    )]
    CatalogAggregateRangeMismatch {
        expected_start: u64,
        expected_end: u64,
        actual_start: u64,
        actual_end: u64,
    },
    #[error(
        "indexed artifact catalog aggregate row count mismatch: expected {expected}, got {actual}"
    )]
    CatalogAggregateRowCountMismatch { expected: u64, actual: u64 },
    #[error("indexed artifact catalog aggregate row count overflowed for catalog {cid}")]
    CatalogAggregateRowCountOverflow { cid: String },
    #[error("empty indexed artifact catalog {cid} has non-zero row count {row_count}")]
    EmptyCatalogRowCountMismatch { cid: String, row_count: u64 },
    #[error("indexed artifact byte size overflows u64")]
    ByteSizeOverflow,
    #[error("indexed artifact {cid} byte size mismatch: expected {expected}, got {actual}")]
    ArtifactByteSizeMismatch {
        cid: String,
        expected: u64,
        actual: u64,
    },
    #[error("indexed artifact {cid} sha256 mismatch: expected {expected}, got {actual}")]
    ArtifactHashMismatch {
        cid: String,
        expected: String,
        actual: String,
    },
    #[error("indexed artifact chunk byte size {actual} exceeds maximum {maximum}")]
    ChunkTooLarge { actual: u64, maximum: u64 },
    #[error("indexed artifact chunk decompression failed")]
    ChunkDecompression { source: std::io::Error },
    #[error("indexed artifact chunk has wrong magic bytes")]
    WrongChunkMagic,
    #[error("unsupported indexed artifact chunk version {version}")]
    UnsupportedChunkVersion { version: u16 },
    #[error("unknown indexed artifact chunk dataset kind id {value}")]
    UnknownChunkDatasetKind { value: u8 },
    #[error("unknown indexed artifact chunk chain type id {value}")]
    UnknownChunkChainType { value: u8 },
    #[error("unknown indexed artifact chunk range kind id {value}")]
    UnknownChunkRangeKind { value: u8 },
    #[error("indexed artifact chunk ended while reading {field}")]
    ChunkUnexpectedEof { field: &'static str },
    #[error("indexed artifact chunk field {field} is not utf8")]
    ChunkInvalidUtf8 {
        field: &'static str,
        #[source]
        source: std::str::Utf8Error,
    },
    #[error(
        "indexed artifact chunk uncompressed length mismatch: expected {expected}, got {actual}"
    )]
    ChunkUncompressedLengthMismatch { expected: u64, actual: u64 },
    #[error("indexed artifact chunk section {section_id} range overflows u64")]
    ChunkSectionRangeOverflow { section_id: u16 },
    #[error(
        "indexed artifact chunk section {section_id} is out of bounds: offset {offset}, length {byte_length}, payload length {payload_len}"
    )]
    ChunkSectionOutOfBounds {
        section_id: u16,
        offset: u64,
        byte_length: u64,
        payload_len: u64,
    },
    #[error("indexed artifact chunk section {section_id} is missing")]
    ChunkSectionMissing { section_id: u16 },
    #[error(
        "indexed artifact chunk descriptor encoding version mismatch: expected {expected}, got {actual}"
    )]
    ChunkDescriptorEncodingVersionMismatch { expected: u16, actual: u16 },
    #[error(
        "indexed artifact chunk descriptor dataset mismatch: expected {expected:?}, got {actual:?}"
    )]
    ChunkDescriptorDatasetMismatch {
        expected: IndexedDatasetKind,
        actual: IndexedDatasetKind,
    },
    #[error("indexed artifact chunk descriptor scope mismatch: expected {expected}, got {actual}")]
    ChunkDescriptorScopeMismatch { expected: String, actual: String },
    #[error(
        "indexed artifact chunk descriptor range mismatch: expected {expected_start}-{expected_end}, got {actual_start}-{actual_end}"
    )]
    ChunkDescriptorRangeMismatch {
        expected_start: u64,
        expected_end: u64,
        actual_start: u64,
        actual_end: u64,
    },
    #[error(
        "indexed artifact chunk descriptor row count mismatch: expected {expected}, got {actual}"
    )]
    ChunkDescriptorRowCountMismatch { expected: u64, actual: u64 },
    #[error(
        "indexed artifact chunk descriptor byte size mismatch: expected {expected}, got {actual}"
    )]
    ChunkDescriptorByteSizeMismatch { expected: u64, actual: u64 },
    #[error("indexed artifact chunk format failed: {message}")]
    ChunkFormat { message: String },
    #[error("indexed artifact chunk concurrency must be greater than zero")]
    InvalidChunkConcurrency,
    #[error(
        "indexed artifact chunk {cid} byte size {byte_size} exceeds in-flight byte budget {max_in_flight_bytes}"
    )]
    ChunkExceedsInFlightBudget {
        cid: String,
        byte_size: u64,
        max_in_flight_bytes: u64,
    },
    #[error(
        "indexed artifact staged chunk dataset mismatch: expected {expected:?}, got {actual:?}"
    )]
    StagedChunkDatasetMismatch {
        expected: IndexedDatasetKind,
        actual: IndexedDatasetKind,
    },
    #[error("indexed artifact staged chunk scope mismatch: expected {expected}, got {actual}")]
    StagedChunkScopeMismatch { expected: String, actual: String },
    #[error(
        "indexed artifact staged chunk range kind mismatch: expected {expected:?}, got {actual:?}"
    )]
    StagedChunkRangeKindMismatch {
        expected: IndexedArtifactRangeKind,
        actual: IndexedArtifactRangeKind,
    },
    #[error("indexed artifact staged chunk range start {start} exceeds end {end}")]
    StagedChunkInvalidRange { start: u64, end: u64 },
    #[error(
        "indexed artifact staged chunk range {chunk_start}-{chunk_end} is before next required start {next_range_start}"
    )]
    StagedChunkBeforeProgress {
        next_range_start: u64,
        chunk_start: u64,
        chunk_end: u64,
    },
    #[error("indexed artifact staged chunk range start {start} is already staged")]
    StagedChunkDuplicateRangeStart { start: u64 },
    #[error(
        "indexed artifact staged chunk range {chunk_start}-{chunk_end} overlaps staged range {existing_start}-{existing_end}"
    )]
    StagedChunkRangeOverlap {
        existing_start: u64,
        existing_end: u64,
        chunk_start: u64,
        chunk_end: u64,
    },
    #[error("indexed artifact staged chunk range end {end} cannot advance next range start")]
    StagedChunkRangeEndOverflow { end: u64 },
}

impl From<TrustlessArtifactError> for IndexedArtifactManifestError {
    fn from(source: TrustlessArtifactError) -> Self {
        Self::Trustless {
            message: source.to_string(),
        }
    }
}

impl From<IndexedArtifactError> for IndexedArtifactManifestError {
    fn from(source: IndexedArtifactError) -> Self {
        match source {
            IndexedArtifactError::Json(source) => Self::Json(source),
            IndexedArtifactError::PublisherKeyMismatch { expected, actual } => {
                Self::PublisherKeyMismatch { expected, actual }
            }
            IndexedArtifactError::MissingPublisherSignature => Self::MissingPublisherSignature,
            IndexedArtifactError::PublicKey(source) => Self::PublicKey { source },
            IndexedArtifactError::Signature(source) => Self::Signature { source },
            IndexedArtifactError::Hex(message) => Self::Hex { message },
        }
    }
}

impl From<IndexedArtifactChunkError> for IndexedArtifactManifestError {
    fn from(source: IndexedArtifactChunkError) -> Self {
        match source {
            IndexedArtifactChunkError::WrongMagic => Self::WrongChunkMagic,
            IndexedArtifactChunkError::UnsupportedFormatVersion(version) => {
                Self::UnsupportedChunkVersion { version }
            }
            IndexedArtifactChunkError::UnknownDatasetKind(value) => {
                Self::UnknownChunkDatasetKind { value }
            }
            IndexedArtifactChunkError::UnknownChainType(value) => {
                Self::UnknownChunkChainType { value }
            }
            IndexedArtifactChunkError::UnknownRangeKind(value) => {
                Self::UnknownChunkRangeKind { value }
            }
            IndexedArtifactChunkError::UnexpectedEof { field } => {
                Self::ChunkUnexpectedEof { field }
            }
            IndexedArtifactChunkError::Hex(message) => Self::Hex { message },
            IndexedArtifactChunkError::StringTooLong { field, length } => Self::ChunkFormat {
                message: format!("string field {field} length {length} exceeds u16"),
            },
            IndexedArtifactChunkError::InvalidUtf8 { field, source } => {
                Self::ChunkInvalidUtf8 { field, source }
            }
            IndexedArtifactChunkError::PayloadTooLarge => Self::ByteSizeOverflow,
            IndexedArtifactChunkError::ChunkTooLarge { actual, maximum } => {
                Self::ChunkTooLarge { actual, maximum }
            }
            IndexedArtifactChunkError::InvalidChunkPlanningConfig {
                soft_min,
                target,
                soft_max,
                hard_max,
            } => Self::ChunkFormat {
                message: format!(
                    "invalid chunk planning config: soft_min={soft_min}, target={target}, soft_max={soft_max}, hard_max={hard_max}"
                ),
            },
            IndexedArtifactChunkError::InvalidChunkPlanRange { start, end } => Self::ChunkFormat {
                message: format!("chunk plan item range start {start} exceeds end {end}"),
            },
            IndexedArtifactChunkError::ChunkPlanItemTooLarge { actual, maximum } => {
                Self::ChunkFormat {
                    message: format!(
                        "chunk plan item compressed byte size {actual} exceeds maximum {maximum}"
                    ),
                }
            }
            IndexedArtifactChunkError::ChunkPlanningOverflow => Self::ChunkFormat {
                message: "chunk planning byte count overflowed".to_string(),
            },
            IndexedArtifactChunkError::DescriptorByteSizeMismatch { expected, actual } => {
                Self::ChunkDescriptorByteSizeMismatch { expected, actual }
            }
            IndexedArtifactChunkError::DescriptorEncodingVersionMismatch { expected, actual } => {
                Self::ChunkDescriptorEncodingVersionMismatch { expected, actual }
            }
            IndexedArtifactChunkError::DescriptorDatasetKindMismatch { expected, actual } => {
                Self::ChunkDescriptorDatasetMismatch { expected, actual }
            }
            IndexedArtifactChunkError::DescriptorScopeMismatch { expected, actual } => {
                Self::ChunkDescriptorScopeMismatch { expected, actual }
            }
            IndexedArtifactChunkError::DescriptorRangeMismatch {
                expected_start,
                expected_end,
                actual_start,
                actual_end,
            } => Self::ChunkDescriptorRangeMismatch {
                expected_start,
                expected_end,
                actual_start,
                actual_end,
            },
            IndexedArtifactChunkError::DescriptorRowCountMismatch { expected, actual } => {
                Self::ChunkDescriptorRowCountMismatch { expected, actual }
            }
            IndexedArtifactChunkError::Compression(source) => Self::ChunkDecompression { source },
            IndexedArtifactChunkError::TooManySections { count } => Self::ChunkFormat {
                message: format!("chunk has {count} sections, exceeding u16"),
            },
            IndexedArtifactChunkError::UncompressedLengthMismatch { expected, actual } => {
                Self::ChunkUncompressedLengthMismatch { expected, actual }
            }
            IndexedArtifactChunkError::SectionRangeOverflow { section_id } => {
                Self::ChunkSectionRangeOverflow { section_id }
            }
            IndexedArtifactChunkError::SectionOutOfBounds {
                section_id,
                offset,
                byte_length,
                payload_len,
            } => Self::ChunkSectionOutOfBounds {
                section_id,
                offset,
                byte_length,
                payload_len,
            },
            IndexedArtifactChunkError::SectionMissing { section_id } => {
                Self::ChunkSectionMissing { section_id }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering as AtomicOrdering},
    };
    use std::time::Duration;

    use alloy::primitives::FixedBytes;
    use cid::Cid;
    use ed25519_dalek::SigningKey;
    use libp2p_identity::Keypair;
    use multihash_codetable::{Code, MultihashDigest};
    use railgun_indexed_artifacts::{IndexedArtifactStreamPlan, IndexedArtifactStreamPlanRequest};
    use url::Url;

    const LIBP2P_KEY_CODEC: u64 = 0x72;
    const RAW_CODEC: u64 = 0x55;

    #[test]
    fn manifest_validation_accepts_signature_sequence_freshness_and_scope() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let scope = scope();
        let mut manifest = manifest_for_scope(scope.clone(), now_ms());
        manifest.sign_manifest(&signing_key).expect("sign manifest");
        let config = config(
            signing_key.verifying_key().to_bytes(),
            Some(Duration::from_secs(60)),
        );

        validate_manifest(
            &manifest,
            &config,
            &scope,
            Some(manifest.sequence),
            UNIX_EPOCH + Duration::from_millis(now_ms()),
        )
        .expect("manifest validates");
    }

    #[test]
    fn manifest_validation_rejects_untrusted_publisher() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let scope = scope();
        let mut manifest = manifest_for_scope(scope.clone(), now_ms());
        manifest.sign_manifest(&signing_key).expect("sign manifest");
        let config = config([8_u8; 32], None);

        let err = validate_manifest(
            &manifest,
            &config,
            &scope,
            None,
            UNIX_EPOCH + Duration::from_millis(now_ms()),
        )
        .expect_err("publisher mismatch rejected");

        assert!(matches!(
            err,
            IndexedArtifactManifestError::PublisherKeyMismatch { .. }
        ));
    }

    #[test]
    fn manifest_validation_rejects_missing_scope_and_catalog_scope_mismatch() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let scope = scope();
        let other_scope = ChainScope {
            chain_id: 56,
            ..scope.clone()
        };
        let mut manifest = manifest_for_scope(scope.clone(), now_ms());
        manifest.sign_manifest(&signing_key).expect("sign manifest");
        let config = config(signing_key.verifying_key().to_bytes(), None);

        let missing = validate_manifest(
            &manifest,
            &config,
            &other_scope,
            None,
            UNIX_EPOCH + Duration::from_millis(now_ms()),
        )
        .expect_err("missing scope rejected");
        assert!(matches!(
            missing,
            IndexedArtifactManifestError::MissingChainScope { .. }
        ));

        manifest.chains[0].catalogs[0].scope = other_scope;
        manifest
            .sign_manifest(&signing_key)
            .expect("resign manifest");
        let mismatch = validate_manifest(
            &manifest,
            &config,
            &scope,
            None,
            UNIX_EPOCH + Duration::from_millis(now_ms()),
        )
        .expect_err("catalog mismatch rejected");
        assert!(matches!(
            mismatch,
            IndexedArtifactManifestError::CatalogScopeMismatch { .. }
        ));
    }

    #[test]
    fn manifest_validation_rejects_rollback_and_stale_first_manifest() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let scope = scope();
        let mut manifest = manifest_for_scope(scope.clone(), now_ms());
        manifest.sign_manifest(&signing_key).expect("sign manifest");
        let config = config(
            signing_key.verifying_key().to_bytes(),
            Some(Duration::from_secs(1)),
        );

        let rollback = validate_manifest(
            &manifest,
            &config,
            &scope,
            Some(manifest.sequence + 1),
            UNIX_EPOCH + Duration::from_millis(now_ms()),
        )
        .expect_err("rollback rejected");
        assert!(matches!(
            rollback,
            IndexedArtifactManifestError::ManifestSequenceRollback { .. }
        ));

        let stale = validate_manifest(
            &manifest,
            &config,
            &scope,
            None,
            UNIX_EPOCH + Duration::from_millis(now_ms() + 2_000),
        )
        .expect_err("stale manifest rejected");
        assert!(matches!(
            stale,
            IndexedArtifactManifestError::ManifestStale { .. }
        ));
    }

    #[test]
    fn manifest_validation_rejects_stale_advanced_manifest() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let scope = scope();
        let mut manifest = manifest_for_scope(scope.clone(), now_ms());
        manifest.sequence = 11;
        manifest.sign_manifest(&signing_key).expect("sign manifest");
        let config = config(
            signing_key.verifying_key().to_bytes(),
            Some(Duration::from_secs(1)),
        );

        let stale = validate_manifest(
            &manifest,
            &config,
            &scope,
            Some(10),
            UNIX_EPOCH + Duration::from_millis(now_ms() + 2_000),
        )
        .expect_err("stale advanced manifest rejected");

        assert!(matches!(
            stale,
            IndexedArtifactManifestError::ManifestStale { .. }
        ));
    }

    #[tokio::test]
    async fn ipns_manifest_fetch_falls_back_to_next_valid_candidate() {
        let ipns_keypair = test_ipns_keypair();
        let ipns_name = ipns_name(&ipns_keypair);
        let scope = scope();
        let trusted_signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let bad_signing_key = SigningKey::from_bytes(&[8_u8; 32]);

        let mut valid_manifest = manifest_for_scope(scope.clone(), now_ms());
        valid_manifest.sequence = 10;
        valid_manifest
            .sign_manifest(&trusted_signing_key)
            .expect("sign valid manifest");
        let valid_manifest_bytes = serde_json::to_vec(&valid_manifest).expect("valid JSON");
        let valid_manifest_cid = raw_cid(&valid_manifest_bytes);

        let mut invalid_manifest = manifest_for_scope(scope.clone(), now_ms());
        invalid_manifest.sequence = 11;
        invalid_manifest
            .sign_manifest(&bad_signing_key)
            .expect("sign invalid manifest");
        let invalid_manifest_bytes = serde_json::to_vec(&invalid_manifest).expect("invalid JSON");
        let invalid_manifest_cid = raw_cid(&invalid_manifest_bytes);

        let ipns_path = format!("/ipns/{ipns_name}?format=ipns-record");
        let invalid_manifest_path =
            format!("/ipfs/{invalid_manifest_cid}?format=car&dag-scope=entity");
        let valid_manifest_path = format!("/ipfs/{valid_manifest_cid}?format=car&dag-scope=entity");
        let high_gateway = PathServer::spawn(
            HashMap::from([
                (
                    ipns_path.clone(),
                    ipns_record(&ipns_keypair, format!("/ipfs/{invalid_manifest_cid}"), 2),
                ),
                (
                    invalid_manifest_path,
                    car_bytes(
                        invalid_manifest_cid,
                        &[(invalid_manifest_cid, invalid_manifest_bytes)],
                    ),
                ),
            ]),
            3,
        );
        let low_gateway = PathServer::spawn(
            HashMap::from([
                (
                    ipns_path,
                    ipns_record(&ipns_keypair, format!("/ipfs/{valid_manifest_cid}"), 1),
                ),
                (
                    valid_manifest_path,
                    car_bytes(
                        valid_manifest_cid,
                        &[(valid_manifest_cid, valid_manifest_bytes)],
                    ),
                ),
            ]),
            2,
        );
        let mut config = config(trusted_signing_key.verifying_key().to_bytes(), None);
        config.manifest_source = IndexedArtifactManifestSource::IpnsName(ipns_name);
        config.gateway_urls = vec![high_gateway.url.clone(), low_gateway.url.clone()];
        let client = IndexedArtifactManifestClient::new(config, reqwest::Client::new());

        let fetched = client
            .fetch_manifest(&scope, None, SystemTime::now())
            .await
            .expect("fallback manifest accepted");

        assert_eq!(fetched.sequence, valid_manifest.sequence);
    }

    #[test]
    fn catalog_verification_checks_descriptor_hash_scope_and_chunks() {
        let scope = scope();
        let catalog = IndexedArtifactCatalog {
            format_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
            dataset_kind: IndexedDatasetKind::WalletScan,
            scope: scope.clone(),
            chunks: vec![chunk_descriptor(scope.clone(), 0, 50)],
        };
        let bytes = serde_json::to_vec(&catalog).expect("catalog json");
        let descriptor = catalog_descriptor(scope, 0, 50, &bytes);

        let verified = verify_catalog_bytes(&descriptor, &bytes).expect("catalog verifies");

        assert_eq!(verified.chunks.len(), 1);

        let mut wrong_hash = descriptor.clone();
        wrong_hash.sha256 = FixedBytes::from([99_u8; 32]);
        assert!(matches!(
            verify_catalog_bytes(&wrong_hash, &bytes),
            Err(IndexedArtifactManifestError::ArtifactHashMismatch { .. })
        ));

        let mut wrong_chunk = catalog;
        wrong_chunk.chunks[0].range.end = 101;
        let wrong_chunk_bytes = serde_json::to_vec(&wrong_chunk).expect("catalog json");
        let wrong_chunk_descriptor =
            catalog_descriptor(wrong_chunk.scope.clone(), 0, 100, &wrong_chunk_bytes);
        assert!(matches!(
            verify_catalog_bytes(&wrong_chunk_descriptor, &wrong_chunk_bytes),
            Err(IndexedArtifactManifestError::CatalogChunkRangeMismatch { .. })
        ));
    }

    #[test]
    fn catalog_verification_rejects_missing_generation() {
        let scope = scope();
        let catalog = IndexedArtifactCatalog {
            format_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
            dataset_kind: IndexedDatasetKind::WalletScan,
            scope: scope.clone(),
            chunks: vec![chunk_descriptor(scope.clone(), 0, 50)],
        };
        let bytes = serde_json::to_vec(&catalog).expect("catalog json");
        let mut descriptor = catalog_descriptor(scope, 0, 50, &bytes);
        descriptor.metadata.catalog_generation = None;

        let err = verify_catalog_bytes(&descriptor, &bytes).expect_err("generation required");

        assert!(matches!(
            err,
            IndexedArtifactManifestError::CatalogMissingGeneration { .. }
        ));
    }

    #[test]
    fn catalog_verification_rejects_missing_generation_on_empty_matching_catalog() {
        let scope = scope();
        let catalog = IndexedArtifactCatalog {
            format_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
            dataset_kind: IndexedDatasetKind::WalletScan,
            scope: scope.clone(),
            chunks: Vec::new(),
        };
        let bytes = serde_json::to_vec(&catalog).expect("catalog json");
        let mut descriptor = catalog_descriptor_with_metadata(
            scope,
            0,
            50,
            0,
            &bytes,
            DatasetDescriptorMetadata::default(),
        );
        descriptor.metadata.catalog_generation = None;

        let err = verify_catalog_bytes(&descriptor, &bytes).expect_err("generation required");

        assert!(matches!(
            err,
            IndexedArtifactManifestError::CatalogMissingGeneration { .. }
        ));
    }

    #[test]
    fn catalog_verification_rejects_aggregate_range_mismatch() {
        let scope = scope();
        let catalog = IndexedArtifactCatalog {
            format_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
            dataset_kind: IndexedDatasetKind::WalletScan,
            scope: scope.clone(),
            chunks: vec![chunk_descriptor(scope.clone(), 0, 50)],
        };
        let bytes = serde_json::to_vec(&catalog).expect("catalog json");
        let descriptor = catalog_descriptor(scope, 0, 100, &bytes);

        let err = verify_catalog_bytes(&descriptor, &bytes).expect_err("aggregate range rejected");

        assert!(matches!(
            err,
            IndexedArtifactManifestError::CatalogAggregateRangeMismatch { .. }
        ));
    }

    #[test]
    fn catalog_verification_rejects_aggregate_row_count_mismatch() {
        let scope = scope();
        let catalog = IndexedArtifactCatalog {
            format_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
            dataset_kind: IndexedDatasetKind::WalletScan,
            scope: scope.clone(),
            chunks: vec![chunk_descriptor(scope.clone(), 0, 50)],
        };
        let bytes = serde_json::to_vec(&catalog).expect("catalog json");
        let descriptor =
            catalog_descriptor_with_metadata(scope, 0, 50, 6, &bytes, catalog_metadata(1));

        let err = verify_catalog_bytes(&descriptor, &bytes).expect_err("row count rejected");

        assert!(matches!(
            err,
            IndexedArtifactManifestError::CatalogAggregateRowCountMismatch { .. }
        ));
    }

    #[test]
    fn catalog_verification_rejects_empty_catalog_with_nonzero_row_count() {
        let scope = scope();
        let catalog = IndexedArtifactCatalog {
            format_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
            dataset_kind: IndexedDatasetKind::WalletScan,
            scope: scope.clone(),
            chunks: Vec::new(),
        };
        let bytes = serde_json::to_vec(&catalog).expect("catalog json");
        let descriptor =
            catalog_descriptor_with_metadata(scope, 0, 50, 1, &bytes, catalog_metadata(1));

        let err = verify_catalog_bytes(&descriptor, &bytes).expect_err("empty row count rejected");

        assert!(matches!(
            err,
            IndexedArtifactManifestError::EmptyCatalogRowCountMismatch { .. }
        ));
    }

    #[test]
    fn catalog_verification_inherits_generation_and_preserves_chunk_stream_metadata() {
        let scope = scope();
        let catalog_metadata = DatasetDescriptorMetadata {
            catalog_generation: Some(42),
            stream_partition: Some("catalog-partition".to_string()),
            stream_complete: true,
            chunk_sealed: true,
            ..DatasetDescriptorMetadata::default()
        };
        let mut list_a = chunk_descriptor_for_dataset(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            scope.clone(),
            0,
            9,
        );
        list_a.cid = "bafytxid-list-a".to_string();
        list_a.metadata.stream_partition = Some("list-a".to_string());
        list_a.metadata.stream_complete = false;
        list_a.metadata.chunk_sealed = false;
        let mut list_b = chunk_descriptor_for_dataset(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            scope.clone(),
            0,
            9,
        );
        list_b.cid = "bafytxid-list-b".to_string();
        list_b.metadata.stream_partition = Some("list-b".to_string());
        list_b.metadata.stream_complete = false;
        list_b.metadata.chunk_sealed = false;
        let catalog_row_count = list_a.row_count + list_b.row_count;
        let catalog = IndexedArtifactCatalog {
            format_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
            dataset_kind: IndexedDatasetKind::PublicTxid,
            scope: scope.clone(),
            chunks: vec![list_a, list_b],
        };
        let bytes = serde_json::to_vec(&catalog).expect("catalog json");
        let descriptor = catalog_descriptor_for_dataset_with_metadata(
            IndexedDatasetKind::PublicTxid,
            IndexedArtifactRangeKind::TxidIndex,
            scope.clone(),
            0,
            9,
            catalog_row_count,
            &bytes,
            catalog_metadata,
        );

        let verified = verify_catalog_bytes(&descriptor, &bytes).expect("catalog verifies");

        let list_a_metadata = &verified.chunks[0].metadata;
        assert_eq!(list_a_metadata.catalog_generation, Some(42));
        assert_eq!(list_a_metadata.stream_partition.as_deref(), Some("list-a"));
        assert!(!list_a_metadata.stream_complete);
        assert!(!list_a_metadata.chunk_sealed);
        let list_b_metadata = &verified.chunks[1].metadata;
        assert_eq!(list_b_metadata.catalog_generation, Some(42));
        assert_eq!(list_b_metadata.stream_partition.as_deref(), Some("list-b"));
        assert!(!list_b_metadata.stream_complete);
        assert!(!list_b_metadata.chunk_sealed);

        let plan = IndexedArtifactStreamPlan::plan(
            &verified.chunks,
            &IndexedArtifactStreamPlanRequest::new(
                IndexedDatasetKind::PublicTxid,
                scope,
                IndexedArtifactRangeKind::TxidIndex,
                0,
                9,
            ),
        )
        .expect("verified catalog partitions remain independently plannable");

        assert_eq!(plan.required_current.len(), 2);
        assert_eq!(
            plan.required_current
                .iter()
                .map(|chunk| chunk.metadata.stream_partition.as_deref())
                .collect::<Vec<_>>(),
            vec![Some("list-a"), Some("list-b")]
        );
    }

    #[test]
    fn catalog_verification_replaces_chunk_generation_with_authenticated_catalog_generation() {
        let scope = scope();
        let mut chunk = chunk_descriptor(scope.clone(), 0, 50);
        chunk.metadata.catalog_generation = Some(7);
        let catalog = IndexedArtifactCatalog {
            format_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
            dataset_kind: IndexedDatasetKind::WalletScan,
            scope: scope.clone(),
            chunks: vec![chunk],
        };
        let bytes = serde_json::to_vec(&catalog).expect("catalog json");
        let descriptor =
            catalog_descriptor_with_metadata(scope, 0, 50, 5, &bytes, catalog_metadata(42));

        let verified = verify_catalog_bytes(&descriptor, &bytes).expect("catalog verifies");

        let metadata = &verified.chunks[0].metadata;
        assert_eq!(metadata.catalog_generation, Some(42));
    }

    #[tokio::test]
    async fn fetch_catalog_rejects_missing_generation_before_gateway_request() {
        let scope = scope();
        let catalog = IndexedArtifactCatalog {
            format_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
            dataset_kind: IndexedDatasetKind::WalletScan,
            scope: scope.clone(),
            chunks: Vec::new(),
        };
        let bytes = serde_json::to_vec(&catalog).expect("catalog json");
        let cid = raw_cid(&bytes);
        let mut descriptor = catalog_descriptor_with_metadata(
            scope,
            0,
            50,
            0,
            &bytes,
            DatasetDescriptorMetadata::default(),
        );
        descriptor.cid = cid.to_string();
        descriptor.metadata.catalog_generation = None;
        let server = ChunkServer::spawn(HashMap::from([(
            descriptor.cid.clone(),
            ChunkResponse::new(&bytes, Duration::ZERO),
        )]));
        let mut source_config = config([7_u8; 32], None);
        source_config.gateway_urls = vec![server.url.clone()];
        let client = IndexedArtifactManifestClient::new(source_config, reqwest::Client::new());

        let err = client
            .fetch_catalog(&descriptor)
            .await
            .expect_err("missing generation rejected before fetch");

        assert!(matches!(
            err,
            IndexedArtifactManifestError::CatalogMissingGeneration { .. }
        ));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(server.max_active(), 0, "gateway should not be touched");
    }

    #[test]
    fn chunk_verification_checks_descriptor_hash_and_size() {
        let bytes = b"verified chunk".to_vec();
        let descriptor = chunk_descriptor_for_bytes(scope(), 0, 10, raw_cid(&bytes), &bytes);

        let verified =
            verify_chunk_bytes(descriptor.clone(), bytes.clone()).expect("chunk verifies");

        assert_eq!(verified.bytes, bytes);

        let mut wrong_size = descriptor.clone();
        wrong_size.byte_size += 1;
        assert!(matches!(
            verify_chunk_bytes(wrong_size, bytes.clone()),
            Err(IndexedArtifactManifestError::ArtifactByteSizeMismatch { .. })
        ));

        let mut wrong_hash = descriptor;
        wrong_hash.sha256 = FixedBytes::from([7_u8; 32]);
        assert!(matches!(
            verify_chunk_bytes(wrong_hash, bytes),
            Err(IndexedArtifactManifestError::ArtifactHashMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn bounded_chunk_fetch_preserves_order_when_responses_complete_out_of_order() {
        let scope = scope();
        let chunk_bytes = vec![
            b"first chunk".to_vec(),
            b"second chunk".to_vec(),
            b"third chunk".to_vec(),
        ];
        let descriptors = descriptors_for_bytes(scope, &chunk_bytes);
        let server = ChunkServer::spawn(
            descriptors
                .iter()
                .zip(chunk_bytes.iter())
                .map(|(descriptor, bytes)| {
                    let delay = if descriptor.range.start == 0 {
                        Duration::from_millis(150)
                    } else {
                        Duration::from_millis(20)
                    };
                    (descriptor.cid.clone(), ChunkResponse::new(bytes, delay))
                })
                .collect(),
        );
        let mut config = config([7_u8; 32], None);
        config.gateway_urls = vec![server.url.clone()];
        config.concurrency = 3;
        config.max_in_flight_bytes = 1024;
        let client = IndexedArtifactManifestClient::new(config, reqwest::Client::new());

        let fetched = client
            .fetch_chunks_bounded(&descriptors)
            .await
            .expect("chunks fetch");

        assert_eq!(
            fetched
                .iter()
                .map(|chunk| chunk.bytes.as_slice())
                .collect::<Vec<_>>(),
            chunk_bytes.iter().map(Vec::as_slice).collect::<Vec<_>>()
        );
        assert!(server.max_active() > 1, "chunks should fetch in parallel");
    }

    #[tokio::test]
    async fn bounded_chunk_fetch_uses_configured_concurrency() {
        let scope = scope();
        let chunk_bytes = vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()];
        let descriptors = descriptors_for_bytes(scope, &chunk_bytes);
        let server = ChunkServer::spawn(responses_for_descriptors(
            &descriptors,
            &chunk_bytes,
            Duration::from_millis(40),
        ));
        let mut config = config([7_u8; 32], None);
        config.gateway_urls = vec![server.url.clone()];
        config.concurrency = 1;
        config.max_in_flight_bytes = 1024;
        let client = IndexedArtifactManifestClient::new(config, reqwest::Client::new());

        client
            .fetch_chunks_bounded(&descriptors)
            .await
            .expect("chunks fetch");

        assert_eq!(server.max_active(), 1);
    }

    #[tokio::test]
    async fn bounded_chunk_fetch_enforces_in_flight_byte_budget() {
        let scope = scope();
        let chunk_bytes = vec![b"aaaaa".to_vec(), b"bbbbb".to_vec(), b"ccccc".to_vec()];
        let descriptors = descriptors_for_bytes(scope, &chunk_bytes);
        let server = ChunkServer::spawn(responses_for_descriptors(
            &descriptors,
            &chunk_bytes,
            Duration::from_millis(75),
        ));
        let mut config = config([7_u8; 32], None);
        config.gateway_urls = vec![server.url.clone()];
        config.concurrency = 3;
        config.max_in_flight_bytes = 10;
        let client = IndexedArtifactManifestClient::new(config, reqwest::Client::new());

        let fetched = client
            .fetch_chunks_bounded(&descriptors)
            .await
            .expect("chunks fetch");

        assert_eq!(fetched.len(), descriptors.len());
        assert!(
            server.max_active() <= 2,
            "byte budget should cap active 5-byte chunks at two"
        );
    }

    #[tokio::test]
    async fn bounded_chunk_fetch_rejects_invalid_limits_before_network() {
        let scope = scope();
        let bytes = b"oversized".to_vec();
        let descriptor = chunk_descriptor_for_bytes(scope, 0, 1, raw_cid(&bytes), &bytes);
        let mut source_config = config([7_u8; 32], None);
        source_config.concurrency = 0;
        let client = IndexedArtifactManifestClient::new(source_config, reqwest::Client::new());

        let zero_concurrency = client
            .fetch_chunks_bounded(std::slice::from_ref(&descriptor))
            .await
            .expect_err("zero concurrency rejected");
        assert!(matches!(
            zero_concurrency,
            IndexedArtifactManifestError::InvalidChunkConcurrency
        ));

        let mut source_config = config([7_u8; 32], None);
        source_config.max_in_flight_bytes = 1;
        let client = IndexedArtifactManifestClient::new(source_config, reqwest::Client::new());
        let oversized = client
            .fetch_chunks_bounded(&[descriptor])
            .await
            .expect_err("oversized chunk rejected");
        assert!(matches!(
            oversized,
            IndexedArtifactManifestError::ChunkExceedsInFlightBudget { .. }
        ));
    }

    #[test]
    fn stager_holds_later_chunks_until_gap_is_filled() {
        let scope = scope();
        let mut stager = VerifiedIndexedArtifactChunkStager::new(
            IndexedDatasetKind::PublicTxid,
            scope.clone(),
            IndexedArtifactRangeKind::TxidIndex,
            0,
        );

        stager
            .stage(verified_chunk(
                chunk_descriptor_for_dataset(
                    IndexedDatasetKind::PublicTxid,
                    IndexedArtifactRangeKind::TxidIndex,
                    scope.clone(),
                    10,
                    19,
                ),
                b"later".to_vec(),
            ))
            .expect("stage later chunk");

        assert!(stager.drain_contiguous().expect("drain").is_empty());
        assert_eq!(stager.next_range_start(), 0);
        assert_eq!(stager.staged_len(), 1);

        stager
            .stage(verified_chunk(
                chunk_descriptor_for_dataset(
                    IndexedDatasetKind::PublicTxid,
                    IndexedArtifactRangeKind::TxidIndex,
                    scope,
                    0,
                    9,
                ),
                b"first".to_vec(),
            ))
            .expect("stage first chunk");

        let ready = stager.drain_contiguous().expect("drain ready chunks");

        assert_eq!(
            ready
                .iter()
                .map(|chunk| (chunk.descriptor.range.start, chunk.descriptor.range.end))
                .collect::<Vec<_>>(),
            vec![(0, 9), (10, 19)]
        );
        assert_eq!(stager.next_range_start(), 20);
        assert!(stager.is_empty());
    }

    #[test]
    fn stager_rejects_mismatched_and_overlapping_chunks() {
        let scope = scope();
        let mut stager = VerifiedIndexedArtifactChunkStager::new(
            IndexedDatasetKind::WalletScan,
            scope.clone(),
            IndexedArtifactRangeKind::Block,
            10,
        );

        let before_progress = stager
            .stage(verified_chunk(
                chunk_descriptor_for_dataset(
                    IndexedDatasetKind::WalletScan,
                    IndexedArtifactRangeKind::Block,
                    scope.clone(),
                    0,
                    9,
                ),
                Vec::new(),
            ))
            .expect_err("past progress rejected");
        assert!(matches!(
            before_progress,
            IndexedArtifactManifestError::StagedChunkBeforeProgress { .. }
        ));

        let wrong_dataset = stager
            .stage(verified_chunk(
                chunk_descriptor_for_dataset(
                    IndexedDatasetKind::PublicTxid,
                    IndexedArtifactRangeKind::Block,
                    scope.clone(),
                    10,
                    19,
                ),
                Vec::new(),
            ))
            .expect_err("wrong dataset rejected");
        assert!(matches!(
            wrong_dataset,
            IndexedArtifactManifestError::StagedChunkDatasetMismatch { .. }
        ));

        stager
            .stage(verified_chunk(
                chunk_descriptor_for_dataset(
                    IndexedDatasetKind::WalletScan,
                    IndexedArtifactRangeKind::Block,
                    scope.clone(),
                    10,
                    20,
                ),
                Vec::new(),
            ))
            .expect("stage first chunk");

        let overlap = stager
            .stage(verified_chunk(
                chunk_descriptor_for_dataset(
                    IndexedDatasetKind::WalletScan,
                    IndexedArtifactRangeKind::Block,
                    scope,
                    20,
                    30,
                ),
                Vec::new(),
            ))
            .expect_err("overlap rejected");
        assert!(matches!(
            overlap,
            IndexedArtifactManifestError::StagedChunkRangeOverlap { .. }
        ));
    }

    #[test]
    fn stager_rejects_partial_stale_chunk_without_blocking_progress() {
        let scope = scope();
        let mut stager = VerifiedIndexedArtifactChunkStager::new(
            IndexedDatasetKind::WalletScan,
            scope.clone(),
            IndexedArtifactRangeKind::Block,
            10,
        );

        let partial_stale = stager
            .stage(verified_chunk(
                chunk_descriptor_for_dataset(
                    IndexedDatasetKind::WalletScan,
                    IndexedArtifactRangeKind::Block,
                    scope.clone(),
                    5,
                    15,
                ),
                Vec::new(),
            ))
            .expect_err("partially stale chunk rejected");
        assert!(matches!(
            partial_stale,
            IndexedArtifactManifestError::StagedChunkBeforeProgress { .. }
        ));
        assert_eq!(stager.staged_len(), 0);

        stager
            .stage(verified_chunk(
                chunk_descriptor_for_dataset(
                    IndexedDatasetKind::WalletScan,
                    IndexedArtifactRangeKind::Block,
                    scope,
                    10,
                    15,
                ),
                Vec::new(),
            ))
            .expect("exact next chunk stages");

        let ready = stager.drain_contiguous().expect("drain exact chunk");

        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].descriptor.range.start, 10);
        assert_eq!(ready[0].descriptor.range.end, 15);
        assert_eq!(stager.next_range_start(), 16);
        assert!(stager.is_empty());
    }

    fn manifest_for_scope(scope: ChainScope, issued_at_ms: u64) -> IndexedArtifactManifest {
        IndexedArtifactManifest::new(
            issued_at_ms,
            10,
            PublisherIdentity::ed25519(FixedBytes::ZERO),
            vec![IndexedArtifactChainEntry {
                latest_indexed: vec![LatestIndexedHeight {
                    dataset_kind: IndexedDatasetKind::WalletScan,
                    block_number: 100,
                    block_hash: FixedBytes::from([9_u8; 32]),
                }],
                catalogs: vec![IndexedArtifactDescriptor {
                    dataset_kind: IndexedDatasetKind::WalletScan,
                    scope: scope.clone(),
                    range: IndexedArtifactRange {
                        kind: IndexedArtifactRangeKind::Block,
                        start: 0,
                        end: 100,
                    },
                    row_count: 5,
                    cid: "bafycatalog".to_string(),
                    sha256: FixedBytes::from([4_u8; 32]),
                    byte_size: 256,
                    encoding_version: INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION,
                    compression: CompressionAlgorithm::Zstd,
                    metadata: DatasetDescriptorMetadata::default(),
                }],
                scope,
            }],
        )
    }

    fn catalog_descriptor(
        scope: ChainScope,
        start: u64,
        end: u64,
        bytes: &[u8],
    ) -> IndexedArtifactDescriptor {
        catalog_descriptor_with_metadata(scope, start, end, 5, bytes, catalog_metadata(1))
    }

    fn catalog_descriptor_with_metadata(
        scope: ChainScope,
        start: u64,
        end: u64,
        row_count: u64,
        bytes: &[u8],
        metadata: DatasetDescriptorMetadata,
    ) -> IndexedArtifactDescriptor {
        catalog_descriptor_for_dataset_with_metadata(
            IndexedDatasetKind::WalletScan,
            IndexedArtifactRangeKind::Block,
            scope,
            start,
            end,
            row_count,
            bytes,
            metadata,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn catalog_descriptor_for_dataset_with_metadata(
        dataset_kind: IndexedDatasetKind,
        range_kind: IndexedArtifactRangeKind,
        scope: ChainScope,
        start: u64,
        end: u64,
        row_count: u64,
        bytes: &[u8],
        metadata: DatasetDescriptorMetadata,
    ) -> IndexedArtifactDescriptor {
        IndexedArtifactDescriptor {
            dataset_kind,
            scope,
            range: IndexedArtifactRange {
                kind: range_kind,
                start,
                end,
            },
            row_count,
            cid: "bafycatalog".to_string(),
            sha256: FixedBytes::from_slice(&Sha256::digest(bytes)),
            byte_size: u64::try_from(bytes.len()).expect("catalog size"),
            encoding_version: INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION,
            compression: CompressionAlgorithm::Zstd,
            metadata,
        }
    }

    fn catalog_metadata(generation: u64) -> DatasetDescriptorMetadata {
        DatasetDescriptorMetadata {
            catalog_generation: Some(generation),
            ..DatasetDescriptorMetadata::default()
        }
    }

    fn chunk_descriptor(scope: ChainScope, start: u64, end: u64) -> IndexedArtifactDescriptor {
        IndexedArtifactDescriptor {
            dataset_kind: IndexedDatasetKind::WalletScan,
            scope,
            range: IndexedArtifactRange {
                kind: IndexedArtifactRangeKind::Block,
                start,
                end,
            },
            row_count: 5,
            cid: "bafychunk".to_string(),
            sha256: FixedBytes::from([5_u8; 32]),
            byte_size: 128,
            encoding_version: INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION,
            compression: CompressionAlgorithm::Zstd,
            metadata: DatasetDescriptorMetadata::default(),
        }
    }

    fn descriptors_for_bytes(
        scope: ChainScope,
        chunks: &[Vec<u8>],
    ) -> Vec<IndexedArtifactDescriptor> {
        chunks
            .iter()
            .enumerate()
            .map(|(index, bytes)| {
                let start = u64::try_from(index).expect("index fits") * 10;
                chunk_descriptor_for_bytes(scope.clone(), start, start + 10, raw_cid(bytes), bytes)
            })
            .collect()
    }

    fn chunk_descriptor_for_bytes(
        scope: ChainScope,
        start: u64,
        end: u64,
        cid: Cid,
        bytes: &[u8],
    ) -> IndexedArtifactDescriptor {
        IndexedArtifactDescriptor {
            dataset_kind: IndexedDatasetKind::WalletScan,
            scope,
            range: IndexedArtifactRange {
                kind: IndexedArtifactRangeKind::Block,
                start,
                end,
            },
            row_count: 5,
            cid: cid.to_string(),
            sha256: FixedBytes::from_slice(&Sha256::digest(bytes)),
            byte_size: u64::try_from(bytes.len()).expect("chunk size"),
            encoding_version: INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION,
            compression: CompressionAlgorithm::Zstd,
            metadata: DatasetDescriptorMetadata::default(),
        }
    }

    fn chunk_descriptor_for_dataset(
        dataset_kind: IndexedDatasetKind,
        range_kind: IndexedArtifactRangeKind,
        scope: ChainScope,
        start: u64,
        end: u64,
    ) -> IndexedArtifactDescriptor {
        IndexedArtifactDescriptor {
            dataset_kind,
            scope,
            range: IndexedArtifactRange {
                kind: range_kind,
                start,
                end,
            },
            row_count: end.saturating_sub(start).saturating_add(1),
            cid: format!("bafychunk{start}"),
            sha256: FixedBytes::from([5_u8; 32]),
            byte_size: 0,
            encoding_version: INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION,
            compression: CompressionAlgorithm::Zstd,
            metadata: DatasetDescriptorMetadata::default(),
        }
    }

    fn verified_chunk(
        descriptor: IndexedArtifactDescriptor,
        bytes: Vec<u8>,
    ) -> VerifiedIndexedArtifactChunk {
        VerifiedIndexedArtifactChunk { descriptor, bytes }
    }

    fn responses_for_descriptors(
        descriptors: &[IndexedArtifactDescriptor],
        chunks: &[Vec<u8>],
        delay: Duration,
    ) -> HashMap<String, ChunkResponse> {
        descriptors
            .iter()
            .zip(chunks.iter())
            .map(|(descriptor, bytes)| (descriptor.cid.clone(), ChunkResponse::new(bytes, delay)))
            .collect()
    }

    fn raw_cid(bytes: &[u8]) -> Cid {
        Cid::new_v1(RAW_CODEC, Code::Sha2_256.digest(bytes))
    }

    fn car_bytes(root: Cid, blocks: &[(Cid, Vec<u8>)]) -> Vec<u8> {
        let header = car_header(root);
        let mut car = Vec::new();
        write_varint(header.len(), &mut car);
        car.extend_from_slice(&header);
        for (cid, block) in blocks {
            let cid_bytes = cid.to_bytes();
            write_varint(cid_bytes.len() + block.len(), &mut car);
            car.extend_from_slice(&cid_bytes);
            car.extend_from_slice(block);
        }
        car
    }

    fn car_header(root: Cid) -> Vec<u8> {
        let mut header = Vec::new();
        header.push(0xa2);
        write_cbor_text("roots", &mut header);
        header.push(0x81);
        header.extend_from_slice(&[0xd8, 0x2a]);
        let mut cid_link = vec![0_u8];
        cid_link.extend_from_slice(&root.to_bytes());
        write_cbor_bytes(&cid_link, &mut header);
        write_cbor_text("version", &mut header);
        header.push(0x01);
        header
    }

    fn write_cbor_text(value: &str, out: &mut Vec<u8>) {
        write_cbor_len(0x60, value.len(), out);
        out.extend_from_slice(value.as_bytes());
    }

    fn write_cbor_bytes(value: &[u8], out: &mut Vec<u8>) {
        write_cbor_len(0x40, value.len(), out);
        out.extend_from_slice(value);
    }

    fn write_cbor_len(major: u8, len: usize, out: &mut Vec<u8>) {
        match len {
            0..=23 => out.push(major | u8::try_from(len).expect("small len")),
            24..=0xff => out.extend_from_slice(&[major | 24, u8::try_from(len).expect("u8 len")]),
            0x100..=0xffff => {
                out.push(major | 25);
                out.extend_from_slice(&u16::try_from(len).expect("u16 len").to_be_bytes());
            }
            _ => panic!("fixture length too large"),
        }
    }

    fn write_varint(mut value: usize, out: &mut Vec<u8>) {
        while value >= 0x80 {
            out.push((u8::try_from(value & 0x7f).expect("varint byte")) | 0x80);
            value >>= 7;
        }
        out.push(u8::try_from(value).expect("varint final byte"));
    }

    #[derive(Clone)]
    struct ChunkResponse {
        body: Vec<u8>,
        delay: Duration,
    }

    impl ChunkResponse {
        fn new(bytes: &[u8], delay: Duration) -> Self {
            let cid = raw_cid(bytes);
            Self {
                body: car_bytes(cid, &[(cid, bytes.to_vec())]),
                delay,
            }
        }
    }

    struct ChunkServer {
        url: Url,
        max_active: Arc<AtomicUsize>,
    }

    impl ChunkServer {
        fn spawn(responses: HashMap<String, ChunkResponse>) -> Self {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind server");
            let url = Url::parse(&format!(
                "http://{}",
                listener.local_addr().expect("local addr")
            ))
            .expect("server URL");
            let responses = Arc::new(responses);
            let active = Arc::new(AtomicUsize::new(0));
            let max_active = Arc::new(AtomicUsize::new(0));
            let requests = Arc::new(Mutex::new(Vec::new()));
            let request_count = responses.len();
            std::thread::spawn({
                let responses = Arc::clone(&responses);
                let active = Arc::clone(&active);
                let max_active = Arc::clone(&max_active);
                let requests = Arc::clone(&requests);
                move || {
                    for _ in 0..request_count {
                        let (stream, _) = listener.accept().expect("accept request");
                        let responses = Arc::clone(&responses);
                        let active = Arc::clone(&active);
                        let max_active = Arc::clone(&max_active);
                        let requests = Arc::clone(&requests);
                        std::thread::spawn(move || {
                            handle_chunk_request(stream, responses, active, max_active, requests);
                        });
                    }
                }
            });

            Self { url, max_active }
        }

        fn max_active(&self) -> usize {
            self.max_active.load(AtomicOrdering::SeqCst)
        }
    }

    struct PathServer {
        url: Url,
    }

    impl PathServer {
        fn spawn(routes: HashMap<String, Vec<u8>>, request_count: usize) -> Self {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind server");
            let url = Url::parse(&format!(
                "http://{}",
                listener.local_addr().expect("local addr")
            ))
            .expect("server URL");
            let routes = Arc::new(routes);
            std::thread::spawn({
                let routes = Arc::clone(&routes);
                move || {
                    for _ in 0..request_count {
                        let (stream, _) = listener.accept().expect("accept request");
                        let routes = Arc::clone(&routes);
                        std::thread::spawn(move || handle_path_request(stream, routes));
                    }
                }
            });

            Self { url }
        }
    }

    fn handle_chunk_request(
        mut stream: std::net::TcpStream,
        responses: Arc<HashMap<String, ChunkResponse>>,
        active: Arc<AtomicUsize>,
        max_active: Arc<AtomicUsize>,
        requests: Arc<Mutex<Vec<String>>>,
    ) {
        let mut request = Vec::new();
        let mut buf = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buf).expect("read request");
            assert!(read > 0, "client closed before request headers");
            request.extend_from_slice(&buf[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let request_text = String::from_utf8_lossy(&request);
        let path = request_text
            .split_whitespace()
            .nth(1)
            .expect("request path")
            .to_string();
        requests.lock().expect("requests lock").push(path.clone());
        let cid = path
            .strip_prefix("/ipfs/")
            .and_then(|path| path.split('?').next())
            .expect("CID path");
        let response = responses.get(cid).expect("registered response");
        let current = active.fetch_add(1, AtomicOrdering::SeqCst) + 1;
        max_active.fetch_max(current, AtomicOrdering::SeqCst);
        std::thread::sleep(response.delay);

        let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response.body.len()
        );
        stream.write_all(headers.as_bytes()).expect("headers");
        stream.write_all(&response.body).expect("body");
        active.fetch_sub(1, AtomicOrdering::SeqCst);
    }

    fn handle_path_request(mut stream: std::net::TcpStream, routes: Arc<HashMap<String, Vec<u8>>>) {
        let path = read_request_path(&mut stream);
        let (status, reason, body) = routes
            .get(&path)
            .map_or((404_u16, "NOT FOUND", Vec::new()), |body| {
                (200_u16, "OK", body.clone())
            });
        let headers = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(headers.as_bytes()).expect("headers");
        stream.write_all(&body).expect("body");
    }

    fn read_request_path(stream: &mut std::net::TcpStream) -> String {
        let mut request = Vec::new();
        let mut buf = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buf).expect("read request");
            assert!(read > 0, "client closed before request headers");
            request.extend_from_slice(&buf[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let request_text = String::from_utf8_lossy(&request);
        request_text
            .split_whitespace()
            .nth(1)
            .expect("request path")
            .to_string()
    }

    fn test_ipns_keypair() -> Keypair {
        Keypair::ed25519_from_bytes([9_u8; 32]).expect("test keypair")
    }

    fn ipns_name(keypair: &Keypair) -> String {
        let peer_id = keypair.public().to_peer_id();
        Cid::new_v1(LIBP2P_KEY_CODEC, *peer_id.as_ref()).to_string()
    }

    fn ipns_record(keypair: &Keypair, value: String, sequence: u64) -> Vec<u8> {
        rust_ipns::Record::new(
            keypair,
            value,
            chrono::Duration::seconds(60 * 60 * 24 * 365),
            sequence,
            60,
        )
        .expect("IPNS record")
        .encode()
        .expect("encoded IPNS record")
    }

    fn scope() -> ChainScope {
        ChainScope {
            chain_type: ChainType::Evm,
            chain_id: 1,
            railgun_contract: "0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"
                .parse()
                .expect("scope address"),
        }
    }

    fn config(pubkey: [u8; 32], max_manifest_age: Option<Duration>) -> IndexedArtifactSourceConfig {
        IndexedArtifactSourceConfig {
            trusted_publisher_pubkey: FixedBytes::from(pubkey),
            manifest_source: IndexedArtifactManifestSource::Cid("bafymanifest".to_string()),
            gateway_urls: Vec::new(),
            max_manifest_age,
            concurrency: 6,
            max_in_flight_bytes: 64 * 1024 * 1024,
        }
    }

    const fn now_ms() -> u64 {
        1_700_000_000_000
    }
}
