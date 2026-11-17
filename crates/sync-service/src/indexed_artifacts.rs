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

const INDEXED_ARTIFACT_MAINTENANCE_CAPACITY: usize = 8;
const INDEXED_ARTIFACT_MAINTENANCE_MAX_RETAINED_PAYLOAD_BYTES: u64 =
    INDEXED_ARTIFACT_MAX_DECODED_ENVELOPE_BYTES;
const SLOW_INDEXED_ARTIFACT_CHUNK_FETCH: Duration = Duration::from_secs(3);
/// How long consumers of one source config reuse a verified manifest instead of fetching it again.
const MANIFEST_REUSE_WINDOW: Duration = Duration::from_mins(2);
type IndexedArtifactMaintenanceJob = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
type IndexedArtifactMaintenanceWorker = Shared<IndexedArtifactMaintenanceJob>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IndexedArtifactMaintenanceKey {
    WalletChunk {
        epoch: u64,
        descriptor: Box<IndexedArtifactDescriptor>,
    },
    TxidChunk {
        scope: ChainScope,
        txid_version: String,
        generation: u64,
        cid: String,
        sha256: alloy::primitives::FixedBytes<32>,
    },
    #[cfg(test)]
    Test(u64),
}

impl IndexedArtifactMaintenanceKey {
    #[must_use]
    pub(crate) fn wallet_chunk(descriptor: &IndexedArtifactDescriptor, epoch: u64) -> Self {
        Self::WalletChunk {
            epoch,
            descriptor: Box::new(descriptor.clone()),
        }
    }

    #[must_use]
    pub(crate) fn txid_chunk(
        descriptor: &IndexedArtifactDescriptor,
        txid_version: &str,
        generation: u64,
    ) -> Self {
        Self::TxidChunk {
            scope: descriptor.scope.clone(),
            txid_version: txid_version.to_string(),
            generation,
            cid: descriptor.cid.clone(),
            sha256: descriptor.sha256,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IndexedArtifactMaintenanceAdmission {
    Admitted,
    Duplicate,
    Full,
    PayloadFull,
    Shutdown,
}

#[derive(Clone)]
pub(crate) struct IndexedArtifactMaintenanceScheduler {
    inner: std::sync::Arc<IndexedArtifactMaintenanceSchedulerInner>,
}

struct IndexedArtifactMaintenanceSchedulerInner {
    sender: mpsc::Sender<IndexedArtifactMaintenanceJob>,
    worker: std::sync::Mutex<IndexedArtifactMaintenanceWorkerState>,
    admission: std::sync::Mutex<IndexedArtifactMaintenanceAdmissionState>,
    cancel: CancellationToken,
}

struct IndexedArtifactMaintenanceWorkerState {
    receiver: Option<mpsc::Receiver<IndexedArtifactMaintenanceJob>>,
    worker: Option<IndexedArtifactMaintenanceWorker>,
}

struct IndexedArtifactMaintenanceAdmissionState {
    retained_payload_bytes: u64,
    max_retained_payload_bytes: u64,
    keys: Vec<IndexedArtifactMaintenanceKey>,
}

struct IndexedArtifactMaintenanceReservation {
    inner: std::sync::Weak<IndexedArtifactMaintenanceSchedulerInner>,
    key: Option<IndexedArtifactMaintenanceKey>,
    retained_payload_bytes: u64,
}

impl Drop for IndexedArtifactMaintenanceReservation {
    fn drop(&mut self) {
        let Some(inner) = self.inner.upgrade() else {
            return;
        };
        let mut admission = inner
            .admission
            .lock()
            .expect("indexed artifact maintenance admission lock poisoned");
        admission.retained_payload_bytes = admission
            .retained_payload_bytes
            .saturating_sub(self.retained_payload_bytes);
        if let Some(key) = self.key.take()
            && let Some(index) = admission.keys.iter().position(|reserved| *reserved == key)
        {
            admission.keys.swap_remove(index);
        }
    }
}

impl Drop for IndexedArtifactMaintenanceSchedulerInner {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl IndexedArtifactMaintenanceScheduler {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::with_limits(
            INDEXED_ARTIFACT_MAINTENANCE_CAPACITY,
            INDEXED_ARTIFACT_MAINTENANCE_MAX_RETAINED_PAYLOAD_BYTES,
        )
    }

    fn with_limits(capacity: usize, max_retained_payload_bytes: u64) -> Self {
        let (sender, receiver) = mpsc::channel(capacity.max(1));
        Self {
            inner: std::sync::Arc::new(IndexedArtifactMaintenanceSchedulerInner {
                sender,
                worker: std::sync::Mutex::new(IndexedArtifactMaintenanceWorkerState {
                    receiver: Some(receiver),
                    worker: None,
                }),
                admission: std::sync::Mutex::new(IndexedArtifactMaintenanceAdmissionState {
                    retained_payload_bytes: 0,
                    max_retained_payload_bytes,
                    keys: Vec::new(),
                }),
                cancel: CancellationToken::new(),
            }),
        }
    }

    pub(crate) fn try_schedule<F>(
        &self,
        key: IndexedArtifactMaintenanceKey,
        retained_payload_bytes: u64,
        job: F,
    ) -> IndexedArtifactMaintenanceAdmission
    where
        F: Future<Output = ()> + Send + 'static,
    {
        if self.inner.cancel.is_cancelled() {
            return IndexedArtifactMaintenanceAdmission::Shutdown;
        }

        let reservation = {
            let mut admission = self
                .inner
                .admission
                .lock()
                .expect("indexed artifact maintenance admission lock poisoned");
            if admission.keys.contains(&key) {
                return IndexedArtifactMaintenanceAdmission::Duplicate;
            }
            if retained_payload_bytes
                > admission
                    .max_retained_payload_bytes
                    .saturating_sub(admission.retained_payload_bytes)
            {
                return IndexedArtifactMaintenanceAdmission::PayloadFull;
            }
            admission.retained_payload_bytes = admission
                .retained_payload_bytes
                .saturating_add(retained_payload_bytes);
            admission.keys.push(key.clone());
            IndexedArtifactMaintenanceReservation {
                inner: std::sync::Arc::downgrade(&self.inner),
                key: Some(key),
                retained_payload_bytes,
            }
        };

        let mut worker = self
            .inner
            .worker
            .lock()
            .expect("indexed artifact maintenance worker lock poisoned");
        if self.inner.cancel.is_cancelled() {
            return IndexedArtifactMaintenanceAdmission::Shutdown;
        }
        Self::ensure_worker(&mut worker, &self.inner.cancel);
        let reserved_job = async move {
            let _reservation = reservation;
            job.await;
        };
        match self.inner.sender.try_send(Box::pin(reserved_job)) {
            Ok(()) => IndexedArtifactMaintenanceAdmission::Admitted,
            Err(mpsc::error::TrySendError::Full(_)) => IndexedArtifactMaintenanceAdmission::Full,
            Err(mpsc::error::TrySendError::Closed(_)) => {
                IndexedArtifactMaintenanceAdmission::Shutdown
            }
        }
    }

    pub(crate) async fn shutdown(&self) {
        let worker = {
            let worker = self
                .inner
                .worker
                .lock()
                .expect("indexed artifact maintenance worker lock poisoned");
            self.inner.cancel.cancel();
            worker.worker.clone()
        };
        if let Some(worker) = worker {
            worker.await;
        }
    }

    pub(crate) fn begin_shutdown(&self) {
        self.inner.cancel.cancel();
    }

    fn ensure_worker(
        state: &mut IndexedArtifactMaintenanceWorkerState,
        cancel: &CancellationToken,
    ) {
        let Some(mut receiver) = state.receiver.take() else {
            return;
        };
        let worker_cancel = cancel.clone();
        let handle = tokio::spawn(async move {
            loop {
                let job = tokio::select! {
                    biased;
                    () = worker_cancel.cancelled() => break,
                    job = receiver.recv() => job,
                };
                let Some(job) = job else {
                    break;
                };
                tokio::select! {
                    biased;
                    () = worker_cancel.cancelled() => break,
                    () = job => {}
                }
            }
        });
        state.worker = Some(
            async move {
                let _ = handle.await;
            }
            .boxed()
            .shared(),
        );
    }
}

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

struct FetchedIndexedArtifactChunk {
    index: usize,
    in_flight_byte_charge: u64,
    chunk: VerifiedIndexedArtifactChunk,
    /// The batch preference this chunk was dispatched under.
    batch_preferred_gateway_index: Option<usize>,
    preferred_gateway_index: usize,
    gateway_index: usize,
    gateway_count: usize,
    hedged: bool,
    elapsed_ms: u128,
}

/// Compressed gateway bytes in flight for one chunk batch. First attempts and
/// hedge attempts draw from the same budget.
struct ChunkByteBudget {
    max_in_flight_bytes: u64,
    state: std::sync::Mutex<ChunkByteBudgetState>,
}

#[derive(Default)]
struct ChunkByteBudgetState {
    in_flight_bytes: u64,
    max_observed_in_flight_bytes: u64,
}

impl ChunkByteBudget {
    fn new(max_in_flight_bytes: u64) -> Self {
        Self {
            max_in_flight_bytes,
            state: std::sync::Mutex::default(),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, ChunkByteBudgetState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Charges `bytes` if they fit under the budget now.
    fn try_charge(&self, bytes: u64) -> bool {
        let mut state = self.state();
        let next_in_flight_bytes = state.in_flight_bytes.saturating_add(bytes);
        if next_in_flight_bytes > self.max_in_flight_bytes {
            return false;
        }
        state.in_flight_bytes = next_in_flight_bytes;
        state.max_observed_in_flight_bytes =
            state.max_observed_in_flight_bytes.max(next_in_flight_bytes);
        true
    }

    fn release(&self, bytes: u64) {
        let mut state = self.state();
        state.in_flight_bytes = state.in_flight_bytes.saturating_sub(bytes);
    }

    /// Charges a hedge attempt's `bytes` if they fit now. The charge lasts as
    /// long as the returned guard.
    fn try_charge_hedge(&self, bytes: u64) -> Option<HedgeByteCharge<'_>> {
        if !self.try_charge(bytes) {
            return None;
        }
        Some(HedgeByteCharge {
            budget: self,
            bytes,
        })
    }

    fn in_flight_bytes(&self) -> u64 {
        self.state().in_flight_bytes
    }

    fn max_observed_in_flight_bytes(&self) -> u64 {
        self.state().max_observed_in_flight_bytes
    }
}

/// Releases a hedge attempt's byte charge when the attempt ends.
struct HedgeByteCharge<'a> {
    budget: &'a ChunkByteBudget,
    bytes: u64,
}

impl Drop for HedgeByteCharge<'_> {
    fn drop(&mut self) {
        self.budget.release(self.bytes);
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct IndexedArtifactChunkFetchMetrics {
    pub(crate) slowest_chunk_elapsed_ms: u128,
    pub(crate) byte_budget_waits: u64,
    pub(crate) max_observed_in_flight_chunks: usize,
    pub(crate) max_observed_in_flight_bytes: u64,
}

pub(crate) struct IndexedArtifactChunkFetchBatch {
    pub(crate) chunks: Vec<VerifiedIndexedArtifactChunk>,
    pub(crate) metrics: IndexedArtifactChunkFetchMetrics,
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
    pub const fn new(
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
            let Some(chunk) = self.staged.remove(&self.next_range_start) else {
                break;
            };
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

    pub async fn fetch_chunks_bounded(
        &self,
        descriptors: &[IndexedArtifactDescriptor],
    ) -> Result<Vec<VerifiedIndexedArtifactChunk>, IndexedArtifactManifestError> {
        self.fetch_chunks_bounded_with_preferred_gateway(descriptors, None)
            .await
    }

    pub(crate) async fn fetch_chunks_bounded_with_preferred_gateway(
        &self,
        descriptors: &[IndexedArtifactDescriptor],
        preferred_gateway_index: Option<usize>,
    ) -> Result<Vec<VerifiedIndexedArtifactChunk>, IndexedArtifactManifestError> {
        self.fetch_chunks_bounded_with_verified_progress(
            descriptors,
            preferred_gateway_index,
            |_, _, _| {},
        )
        .await
        .map(|batch| batch.chunks)
    }

    pub async fn fetch_chunks_bounded_with_progress<F>(
        &self,
        descriptors: &[IndexedArtifactDescriptor],
        preferred_gateway_index: Option<usize>,
        mut on_chunk_verified: F,
    ) -> Result<Vec<VerifiedIndexedArtifactChunk>, IndexedArtifactManifestError>
    where
        F: FnMut(usize, usize),
    {
        self.fetch_chunks_bounded_with_verified_progress(
            descriptors,
            preferred_gateway_index,
            |_, completed_chunks, total_chunks| {
                on_chunk_verified(completed_chunks, total_chunks);
            },
        )
        .await
        .map(|batch| batch.chunks)
    }

    pub(crate) async fn fetch_chunks_bounded_with_verified_progress<F>(
        &self,
        descriptors: &[IndexedArtifactDescriptor],
        preferred_gateway_index: Option<usize>,
        mut on_chunk_verified: F,
    ) -> Result<IndexedArtifactChunkFetchBatch, IndexedArtifactManifestError>
    where
        F: FnMut(&VerifiedIndexedArtifactChunk, usize, usize),
    {
        let total_chunks = descriptors.len();
        let concurrency = self.config.concurrency;
        if concurrency == 0 {
            return Err(IndexedArtifactManifestError::InvalidChunkConcurrency);
        }
        let batch_started = Instant::now();
        let max_in_flight_bytes = self.config.max_in_flight_bytes;
        for descriptor in descriptors {
            descriptor.decoded_envelope_byte_size_charge()?;
        }
        // Retrieval and decoded-resident memory are separate resources. This budget limits
        // compressed gateway bytes; decode_chunk_bytes enforces the dataset output limit.
        let in_flight_byte_charges = descriptors
            .iter()
            .map(|descriptor| descriptor.byte_size)
            .collect::<Vec<_>>();
        let fetcher = self.fetcher();
        let byte_budget = ChunkByteBudget::new(max_in_flight_bytes);
        let mut results = Vec::with_capacity(descriptors.len());
        let mut next_index = 0;
        let mut completed_chunks = 0;
        let mut max_observed_in_flight_chunks = 0_usize;
        let mut byte_budget_waits = 0_u64;
        let mut slowest_chunk_elapsed_ms = 0_u128;
        let mut in_flight = FuturesUnordered::new();
        let mut batch_preferred_gateway_index = preferred_gateway_index;

        while next_index < descriptors.len() || !in_flight.is_empty() {
            while next_index < descriptors.len() && in_flight.len() < concurrency {
                let descriptor = descriptors[next_index].clone();
                let in_flight_byte_charge = in_flight_byte_charges[next_index];
                if in_flight_byte_charge > max_in_flight_bytes {
                    return Err(IndexedArtifactManifestError::ChunkExceedsInFlightBudget {
                        cid: descriptor.cid,
                        byte_size: in_flight_byte_charge,
                        max_in_flight_bytes,
                    });
                }
                if !byte_budget.try_charge(in_flight_byte_charge) {
                    byte_budget_waits = byte_budget_waits.saturating_add(1);
                    debug!(
                        dataset_kind = ?descriptor.dataset_kind,
                        range_start = descriptor.range.start,
                        range_end = descriptor.range.end,
                        next_index,
                        next_byte_size = descriptor.byte_size,
                        next_in_flight_byte_charge = in_flight_byte_charge,
                        in_flight_chunks = in_flight.len(),
                        in_flight_bytes = byte_budget.in_flight_bytes(),
                        max_in_flight_bytes,
                        configured_concurrency = concurrency,
                        "indexed artifact chunk in-flight byte budget saturated"
                    );
                    break;
                }
                let index = next_index;
                let byte_size = descriptor.byte_size;
                let cid = descriptor.cid.clone();
                // Without a batch preference, e.g. the gateway that served the manifest,
                // chunks spread across gateways by content hash.
                let dispatch_batch_preferred_gateway_index = batch_preferred_gateway_index;
                let preferred_gateway_index = dispatch_batch_preferred_gateway_index
                    .unwrap_or_else(|| preferred_artifact_gateway_index(&descriptor));
                let dataset_kind = descriptor.dataset_kind;
                let range_start = descriptor.range.start;
                let range_end = descriptor.range.end;
                next_index += 1;
                let fetcher = &fetcher;
                let byte_budget = &byte_budget;
                in_flight.push(async move {
                    let started = Instant::now();
                    let mut hedged = false;
                    let result = fetcher
                        .fetch_artifact_cid_with_metadata_hedged(
                            &descriptor.cid,
                            descriptor.byte_size,
                            preferred_gateway_index,
                            || {
                                // A hedge starts only if its bytes fit the batch budget now;
                                // otherwise the first attempt continues alone.
                                let charge = byte_budget.try_charge_hedge(in_flight_byte_charge);
                                hedged = charge.is_some();
                                charge
                            },
                        )
                        .await;
                    let fetched = match result {
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
                                preferred_gateway_index,
                                hedged,
                                elapsed_ms = started.elapsed().as_millis(),
                                "indexed artifact chunk fetch failed"
                            );
                            return Err(err.into());
                        }
                    };
                    let gateway_index = fetched.gateway_index();
                    let gateway_count = fetched.gateway_count();
                    let chunk = match verify_chunk_bytes(descriptor, fetched.into_bytes()) {
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
                        in_flight_byte_charge,
                        chunk,
                        batch_preferred_gateway_index: dispatch_batch_preferred_gateway_index,
                        preferred_gateway_index,
                        gateway_index,
                        gateway_count,
                        hedged,
                        elapsed_ms: started.elapsed().as_millis(),
                    })
                });
                max_observed_in_flight_chunks = max_observed_in_flight_chunks.max(in_flight.len());
            }

            let Some(completed) = in_flight.next().await else {
                continue;
            };
            let fetched = completed?;
            byte_budget.release(fetched.in_flight_byte_charge);
            completed_chunks += 1;
            on_chunk_verified(&fetched.chunk, completed_chunks, total_chunks);
            slowest_chunk_elapsed_ms = slowest_chunk_elapsed_ms.max(fetched.elapsed_ms);
            if fetched.elapsed_ms >= SLOW_INDEXED_ARTIFACT_CHUNK_FETCH.as_millis() {
                info!(
                    dataset_kind = ?fetched.chunk.descriptor.dataset_kind,
                    range_start = fetched.chunk.descriptor.range.start,
                    range_end = fetched.chunk.descriptor.range.end,
                    byte_size = fetched.chunk.descriptor.byte_size,
                    index = fetched.index,
                    preferred_gateway_index = fetched.preferred_gateway_index,
                    completed_chunks,
                    total_chunks,
                    gateway_index = fetched.gateway_index,
                    gateway_count = fetched.gateway_count,
                    hedged = fetched.hedged,
                    elapsed_ms = fetched.elapsed_ms,
                    "slow indexed artifact chunk fetch verified"
                );
            } else {
                debug!(
                    cid = %fetched.chunk.descriptor.cid,
                    dataset_kind = ?fetched.chunk.descriptor.dataset_kind,
                    range_start = fetched.chunk.descriptor.range.start,
                    range_end = fetched.chunk.descriptor.range.end,
                    byte_size = fetched.chunk.descriptor.byte_size,
                    in_flight_byte_charge = fetched.in_flight_byte_charge,
                    index = fetched.index,
                    preferred_gateway_index = fetched.preferred_gateway_index,
                    completed_chunks,
                    total_chunks,
                    gateway_index = fetched.gateway_index,
                    gateway_count = fetched.gateway_count,
                    hedged = fetched.hedged,
                    elapsed_ms = fetched.elapsed_ms,
                    "indexed artifact chunk fetch verified"
                );
            }
            // Later chunks follow the gateway that won a chunk dispatched under this preference.
            if let Some(previous_gateway_index) = batch_preferred_gateway_index
                && fetched.batch_preferred_gateway_index == batch_preferred_gateway_index
                && fetched.gateway_index != previous_gateway_index % fetched.gateway_count
            {
                debug!(
                    dataset_kind = ?fetched.chunk.descriptor.dataset_kind,
                    range_start = fetched.chunk.descriptor.range.start,
                    range_end = fetched.chunk.descriptor.range.end,
                    previous_gateway_index,
                    gateway_index = fetched.gateway_index,
                    gateway_count = fetched.gateway_count,
                    "indexed artifact chunk batch moved preferred gateway"
                );
                batch_preferred_gateway_index = Some(fetched.gateway_index);
            }
            results.push((fetched.index, fetched.chunk));
        }

        let max_observed_in_flight_bytes = byte_budget.max_observed_in_flight_bytes();
        debug!(
            total_chunks,
            configured_concurrency = concurrency,
            max_observed_in_flight_chunks,
            max_observed_in_flight_bytes,
            max_in_flight_bytes,
            byte_budget_waits,
            slowest_chunk_elapsed_ms,
            elapsed_ms = batch_started.elapsed().as_millis(),
            "indexed artifact chunk fetch batch complete"
        );

        results.sort_unstable_by_key(|(index, _)| *index);
        Ok(IndexedArtifactChunkFetchBatch {
            chunks: results.into_iter().map(|(_, chunk)| chunk).collect(),
            metrics: IndexedArtifactChunkFetchMetrics {
                slowest_chunk_elapsed_ms,
                byte_budget_waits,
                max_observed_in_flight_chunks,
                max_observed_in_flight_bytes,
            },
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

fn preferred_artifact_gateway_index(descriptor: &IndexedArtifactDescriptor) -> usize {
    usize::from(descriptor.sha256[0])
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

    let catalog: IndexedArtifactCatalog = serde_json::from_slice(bytes)?;
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
    chunk.decoded_envelope_byte_size_charge()?;
    Ok(())
}

fn validate_catalog_descriptor_for_expansion(
    descriptor: &IndexedArtifactDescriptor,
) -> Result<(), IndexedArtifactManifestError> {
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

    let allows_sparse_chunks = descriptor.dataset_kind == IndexedDatasetKind::WalletScan
        && descriptor.range.kind == IndexedArtifactRangeKind::Block;
    if !allows_sparse_chunks
        && (descriptor.range.start != aggregate_start || descriptor.range.end != aggregate_end)
    {
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

const fn validate_manifest_sequence(
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
    #[error("indexed artifact decoded chunk envelope byte size {actual} exceeds maximum {maximum}")]
    ChunkDecodedEnvelopeTooLarge { actual: u64, maximum: u64 },
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
    #[error("indexed artifact chunk section {section_id} appears more than once")]
    ChunkDuplicateSection { section_id: u16 },
    #[error(
        "indexed artifact chunk section {second_section_id} byte range [{second_start}, {second_end}) overlaps section {first_section_id} byte range [{first_start}, {first_end})"
    )]
    ChunkOverlappingSections {
        first_section_id: u16,
        first_start: u64,
        first_end: u64,
        second_section_id: u16,
        second_start: u64,
        second_end: u64,
    },
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
    #[error(
        "indexed artifact chunk descriptor decoded envelope byte size mismatch: expected {expected}, got {actual}"
    )]
    ChunkDescriptorDecodedEnvelopeByteSizeMismatch { expected: u64, actual: u64 },
    #[error("indexed artifact chunk format failed: {message}")]
    ChunkFormat { message: String },
    #[error("indexed artifact chunk concurrency must be greater than zero")]
    InvalidChunkConcurrency,
    #[error(
        "indexed artifact chunk {cid} resource charge {byte_size} exceeds in-flight byte budget {max_in_flight_bytes}"
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
            IndexedArtifactChunkError::DecodedEnvelopeTooLarge { actual, maximum } => {
                Self::ChunkDecodedEnvelopeTooLarge { actual, maximum }
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
            IndexedArtifactChunkError::DescriptorDecodedEnvelopeByteSizeMismatch {
                expected,
                actual,
            } => Self::ChunkDescriptorDecodedEnvelopeByteSizeMismatch { expected, actual },
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
            IndexedArtifactChunkError::DuplicateSection { section_id } => {
                Self::ChunkDuplicateSection { section_id }
            }
            IndexedArtifactChunkError::OverlappingSections {
                first_section_id,
                first_start,
                first_end,
                second_section_id,
                second_start,
                second_end,
            } => Self::ChunkOverlappingSections {
                first_section_id,
                first_start,
                first_end,
                second_section_id,
                second_start,
                second_end,
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
impl IndexedArtifactMaintenanceScheduler {
    fn with_capacity(capacity: usize) -> Self {
        Self::with_limits(
            capacity,
            INDEXED_ARTIFACT_MAINTENANCE_MAX_RETAINED_PAYLOAD_BYTES,
        )
    }
}

#[cfg(test)]
mod tests;
