//! Prepared indexed-artifact sessions: manifest, descriptor and chunk
//! acquisition, and the per-range page reads over the prepared chunks.

use super::coverage::{
    WalletScanArtifactCoverage, WalletScanChunkBounds, WalletScanCoverageStatus,
    wallet_scan_artifact_target_block,
};
use super::page::IndexedWalletPage;
use super::{
    ChainConfig, ChainPublicDataPlane, Instant, PublicScanReadScope, PublicScanSource, SyncError,
    SyncProgressSender, SyncProgressStage, SyncProgressUpdate, artifact_chunk_progress, debug,
    info, send_sync_progress, wallet_artifact_error, wallet_artifact_format,
};

use crate::indexed_artifacts::{
    ChainScope, IndexedArtifactChainEntry, IndexedArtifactChunkFetchBatch,
    IndexedArtifactChunkFetchMetrics, IndexedArtifactDescriptor,
    IndexedArtifactMaintenanceAdmission, IndexedArtifactMaintenanceKey, IndexedArtifactManifest,
    IndexedArtifactManifestClient, IndexedArtifactPlannedChunk,
    IndexedArtifactPlannedChunkPlacement, IndexedArtifactRange, IndexedArtifactRangeKind,
    IndexedArtifactStreamCatalog, IndexedArtifactStreamPartitionPolicy, IndexedArtifactStreamPlan,
    IndexedArtifactStreamPlanRequest, IndexedDatasetKind, VerifiedIndexedArtifactChunk,
};
use std::collections::HashSet;
use std::time::SystemTime;

const WALLET_ARTIFACT_PROGRESS_TOTAL: u64 = 100;
const WALLET_ARTIFACT_MANIFEST_START_PROGRESS: u64 = 5;
const WALLET_ARTIFACT_MANIFEST_DONE_PROGRESS: u64 = 20;
const WALLET_ARTIFACT_DESCRIPTORS_DONE_PROGRESS: u64 = 35;
const WALLET_ARTIFACT_CHUNKS_DONE_PROGRESS: u64 = 90;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::chain) struct IndexedWalletArtifactProbe {
    pub(in crate::chain) latest_indexed_block: u64,
    pub(in crate::chain) catalog_count: usize,
}

impl IndexedWalletArtifactProbe {
    pub(in crate::chain) fn from_manifest(
        manifest: &IndexedArtifactManifest,
        scope: &ChainScope,
        from_block: u64,
        to_block: u64,
    ) -> Option<Self> {
        let chain = manifest.chains.iter().find(|entry| entry.scope == *scope)?;
        let latest_indexed_block = chain
            .latest_indexed
            .iter()
            .filter(|height| height.dataset_kind == IndexedDatasetKind::WalletScan)
            .map(|height| height.block_number)
            .max()?;
        if latest_indexed_block < from_block {
            return None;
        }

        let target_block = to_block.min(latest_indexed_block);
        if target_block < from_block {
            return None;
        }

        let catalog_count = chain
            .catalogs
            .iter()
            .filter(|catalog| {
                catalog.matches_range(
                    IndexedDatasetKind::WalletScan,
                    scope,
                    IndexedArtifactRangeKind::Block,
                    from_block,
                    target_block,
                )
            })
            .count();
        if catalog_count == 0 {
            return None;
        }

        Some(Self {
            latest_indexed_block,
            catalog_count,
        })
    }
}

pub(in crate::chain) struct IndexedWalletArtifactSession {
    pub(super) probe: IndexedWalletArtifactProbe,
    pub(super) target_block: u64,
    pub(super) chunk_descriptors: Vec<IndexedArtifactDescriptor>,
    pub(super) chunks: Vec<IndexedWalletArtifactChunk>,
    pub(super) coverage: WalletScanArtifactCoverage,
    pub(super) read_scope: PublicScanReadScope,
}

pub(in crate::chain) enum IndexedWalletArtifactPageOutcome {
    Page(IndexedWalletPage),
    Exhausted { checkpoint_block: u64 },
}

impl IndexedWalletArtifactSession {
    pub(in crate::chain) async fn prepare(
        chain: &ChainConfig,
        from_block: u64,
        to_block: u64,
        read_scope: PublicScanReadScope,
        public_data_plane: &ChainPublicDataPlane,
        progress_tx: Option<&SyncProgressSender>,
    ) -> Result<Option<Self>, SyncError> {
        let Some(config) = chain.sync.indexed_artifact_source.clone() else {
            return Ok(None);
        };
        let chain_scope = chain.indexed_artifact_scope();
        let http_client = chain.http_client.clone();
        let mut preparation = WalletArtifactPreparation {
            client: IndexedArtifactManifestClient::new(config, http_client),
            chain_scope,
            public_data_plane,
            read_scope,
            progress_tx,
            preferred_gateway_index: None,
        };
        let started = Instant::now();
        let (manifest, manifest_elapsed_ms) = preparation.fetch_manifest().await?;
        let Some(probe) = IndexedWalletArtifactProbe::from_manifest(
            &manifest,
            &preparation.chain_scope,
            from_block,
            to_block,
        ) else {
            return Ok(None);
        };
        let advertised_target_block = to_block.min(probe.latest_indexed_block);
        let Some(chain_entry) = manifest
            .chains
            .iter()
            .find(|entry| entry.scope == preparation.chain_scope)
        else {
            return Ok(None);
        };
        let descriptor_started = Instant::now();
        let Some(plan) = preparation
            .plan_chunks(chain_entry, from_block, advertised_target_block)
            .await?
        else {
            return Ok(None);
        };
        let descriptor_elapsed_ms = descriptor_started.elapsed().as_millis();
        preparation.send_preparation_progress(WALLET_ARTIFACT_DESCRIPTORS_DONE_PROGRESS);
        debug!(
            from_block,
            to_block,
            target_block = plan.target_block,
            advertised_target_block,
            latest_indexed_block = probe.latest_indexed_block,
            catalog_count = probe.catalog_count,
            chunk_count = plan.chunk_descriptors.len(),
            manifest_elapsed_ms,
            descriptor_elapsed_ms,
            elapsed_ms = started.elapsed().as_millis(),
            "indexed wallet artifact descriptors prepared"
        );
        let chunks = preparation.fetch_chunks(&plan, manifest.sequence).await?;
        preparation.schedule_chunk_maintenance(&plan.required_current_chunks, &chunks.chunks);
        info!(
            from_block,
            to_block,
            target_block = plan.target_block,
            advertised_target_block,
            latest_indexed_block = probe.latest_indexed_block,
            catalog_count = probe.catalog_count,
            chunk_count = plan.chunk_descriptors.len(),
            cache_hits = chunks.cache_hits,
            fetched_chunks = chunks.fetched_chunks,
            fetched_bytes = chunks.fetched_bytes,
            manifest_elapsed_ms,
            descriptor_elapsed_ms,
            chunk_fetch_verify_elapsed_ms = chunks.fetch_verify_elapsed_ms,
            slowest_chunk_elapsed_ms = chunks.slowest_chunk_elapsed_ms,
            chunk_byte_budget_waits = chunks.byte_budget_waits,
            max_in_flight_chunks = chunks.max_observed_in_flight_chunks,
            max_in_flight_bytes = chunks.max_observed_in_flight_bytes,
            elapsed_ms = started.elapsed().as_millis(),
            "indexed wallet artifact preparation complete"
        );
        Ok(Some(Self {
            probe,
            target_block: plan.target_block,
            chunk_descriptors: plan.chunk_descriptors,
            chunks: chunks.chunks,
            coverage: plan.coverage,
            read_scope,
        }))
    }

    pub(in crate::chain) const fn latest_indexed_block(&self) -> u64 {
        self.probe.latest_indexed_block
    }

    pub(in crate::chain) const fn target_block(&self) -> u64 {
        self.target_block
    }

    pub(in crate::chain) const fn catalog_count(&self) -> usize {
        self.probe.catalog_count
    }

    pub(in crate::chain) const fn chunk_count(&self) -> usize {
        self.chunk_descriptors.len()
    }

    pub(in crate::chain) const fn read_scope(&self) -> PublicScanReadScope {
        self.read_scope
    }

    pub(in crate::chain) fn page_for_block_range(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Result<IndexedWalletArtifactPageOutcome, SyncError> {
        let target_block = to_block.min(self.target_block);
        if target_block < from_block {
            return Ok(IndexedWalletArtifactPageOutcome::Exhausted {
                checkpoint_block: self.target_block,
            });
        }
        let started = Instant::now();
        let page_checkpoint = match self
            .coverage
            .checkpoint_for_range(from_block, target_block)?
        {
            WalletScanCoverageStatus::Available { checkpoint_block } => checkpoint_block,
            WalletScanCoverageStatus::Exhausted { checkpoint_block } => {
                debug!(
                    from_block,
                    to_block,
                    target_block,
                    checkpoint_block,
                    "indexed wallet artifact coverage exhausted before requested range"
                );
                return Ok(IndexedWalletArtifactPageOutcome::Exhausted { checkpoint_block });
            }
        };
        let page_chunks = self.page_chunks(from_block, target_block)?;
        let page_checkpoint = page_chunks.lower_checkpoint(from_block, page_checkpoint)?;
        if page_checkpoint < from_block {
            debug!(
                from_block,
                to_block,
                target_block,
                page_checkpoint,
                "indexed wallet artifact source has no proven data after checkpoint"
            );
            return Ok(IndexedWalletArtifactPageOutcome::Exhausted {
                checkpoint_block: page_checkpoint,
            });
        }

        let decode_started = Instant::now();
        let page = page_chunks.decode(from_block, page_checkpoint)?;
        debug!(
            from_block,
            to_block,
            target_block,
            page_checkpoint,
            needed_chunks = page_chunks.needed,
            cached_chunks = page_chunks.cached,
            fetched_chunks = 0,
            session_cached_chunks = self.chunks.len(),
            chunk_fetch_verify_elapsed_ms = 0,
            chunk_decode_elapsed_ms = decode_started.elapsed().as_millis(),
            elapsed_ms = started.elapsed().as_millis(),
            "indexed wallet artifact page chunks ready"
        );
        Ok(IndexedWalletArtifactPageOutcome::Page(page))
    }

    /// The prepared chunks whose descriptors intersect
    /// `from_block..=target_block`. Errors when preparation did not keep one.
    fn page_chunks(&self, from_block: u64, target_block: u64) -> Result<PageChunks<'_>, SyncError> {
        let needed_indices: Vec<_> = self
            .chunk_descriptors
            .iter()
            .enumerate()
            .filter(|(_, chunk)| chunk.range.intersects(from_block, target_block))
            .map(|(index, _)| index)
            .collect();
        let cached_chunks = needed_indices
            .iter()
            .filter(|needed_index| {
                self.chunks
                    .iter()
                    .any(|chunk| chunk.descriptor_index == **needed_index)
            })
            .count();
        if cached_chunks != needed_indices.len() {
            return Err(wallet_artifact_format(
                "prepared wallet_scan artifact chunk missing",
            ));
        }

        let chunks = self
            .chunks
            .iter()
            .filter(|chunk| needed_indices.contains(&chunk.descriptor_index))
            .collect();
        Ok(PageChunks {
            chunks,
            needed: needed_indices.len(),
            cached: cached_chunks,
        })
    }

    pub(super) fn select_current_stream_plan(
        catalogs: &[IndexedArtifactStreamCatalog],
        scope: &ChainScope,
        from_block: u64,
        target_block: u64,
    ) -> Result<IndexedArtifactStreamPlan, SyncError> {
        IndexedArtifactStreamPlan::plan(
            catalogs,
            &IndexedArtifactStreamPlanRequest::new(
                IndexedDatasetKind::WalletScan,
                scope.clone(),
                IndexedArtifactRangeKind::Block,
                from_block,
                target_block,
                IndexedArtifactStreamPartitionPolicy::Ignore,
            ),
        )
        .map_err(|err| wallet_artifact_format(err.to_string()))
    }
}

/// The prepared chunks one page read needs, with the counts its log reports.
struct PageChunks<'a> {
    chunks: Vec<&'a IndexedWalletArtifactChunk>,
    needed: usize,
    cached: usize,
}

impl PageChunks<'_> {
    /// Lowers `page_checkpoint` to the checkpoint of each intersecting chunk
    /// that is proven only part way through its range.
    fn lower_checkpoint(
        &self,
        from_block: u64,
        mut page_checkpoint: u64,
    ) -> Result<u64, SyncError> {
        for chunk in &self.chunks {
            if !chunk.range.intersects(from_block, page_checkpoint) {
                continue;
            }
            let chunk_bounds = WalletScanChunkBounds::try_from(&chunk.chunk.descriptor)?;
            if chunk_bounds.checkpoint_block() < chunk.range.end {
                page_checkpoint = page_checkpoint.min(chunk_bounds.checkpoint_block());
            }
        }
        Ok(page_checkpoint)
    }

    fn decode(
        &self,
        from_block: u64,
        page_checkpoint: u64,
    ) -> Result<IndexedWalletPage, SyncError> {
        let mut page = IndexedWalletPage::empty(page_checkpoint);
        for chunk in &self.chunks {
            if !chunk.range.intersects(from_block, page_checkpoint) {
                continue;
            }
            let chunk_page = IndexedWalletPage::from_chunk_for_block_range(
                &chunk.chunk,
                from_block,
                page_checkpoint,
            )?;
            page.extend_filtered_from(&chunk_page, from_block, page_checkpoint);
        }
        page.refresh_row_counts();
        Ok(page)
    }
}

/// One preparation attempt: the manifest client and the epoch-gated
/// progress sink its stages share.
struct WalletArtifactPreparation<'a> {
    client: IndexedArtifactManifestClient,
    chain_scope: ChainScope,
    public_data_plane: &'a ChainPublicDataPlane,
    read_scope: PublicScanReadScope,
    progress_tx: Option<&'a SyncProgressSender>,
    /// The gateway that served the manifest; catalog and chunk fetches
    /// prefer it.
    preferred_gateway_index: Option<usize>,
}

/// The current wallet-scan chunks a preparation needs, trimmed to its
/// target block.
struct WalletArtifactChunkPlan {
    target_block: u64,
    required_current_chunks: Vec<IndexedArtifactPlannedChunk>,
    chunk_descriptors: Vec<IndexedArtifactDescriptor>,
    coverage: WalletScanArtifactCoverage,
}

impl WalletArtifactPreparation<'_> {
    fn is_current_epoch(&self) -> bool {
        self.public_data_plane.current_epoch() == self.read_scope.epoch()
    }

    fn send_preparation_progress(&self, current_progress: u64) {
        if !self.is_current_epoch() {
            return;
        }
        send_sync_progress(
            self.progress_tx,
            SyncProgressUpdate::artifact_preparation(
                SyncProgressStage::PreparingUtxoIndex,
                current_progress,
                WALLET_ARTIFACT_PROGRESS_TOTAL,
            )
            .with_source(PublicScanSource::IndexedArtifacts),
        );
    }

    fn send_chunk_progress(&self, completed_chunks: usize, total_chunks: usize) {
        if !self.is_current_epoch() {
            return;
        }
        send_sync_progress(
            self.progress_tx,
            SyncProgressUpdate::artifact_chunk(
                SyncProgressStage::PreparingUtxoIndex,
                artifact_chunk_progress(
                    completed_chunks,
                    total_chunks,
                    WALLET_ARTIFACT_DESCRIPTORS_DONE_PROGRESS,
                    WALLET_ARTIFACT_CHUNKS_DONE_PROGRESS,
                ),
                WALLET_ARTIFACT_PROGRESS_TOTAL,
                u64::try_from(completed_chunks).unwrap_or(u64::MAX),
                u64::try_from(total_chunks).unwrap_or(u64::MAX),
            )
            .with_source(PublicScanSource::IndexedArtifacts),
        );
    }

    /// Fetches the manifest and remembers the gateway that served it.
    /// Returns the manifest and the fetch's elapsed milliseconds.
    async fn fetch_manifest(&mut self) -> Result<(IndexedArtifactManifest, u128), SyncError> {
        let manifest_started = Instant::now();
        self.send_preparation_progress(WALLET_ARTIFACT_MANIFEST_START_PROGRESS);
        let manifest_fetch = self
            .client
            .fetch_manifest_with_metadata(&self.chain_scope, None, SystemTime::now())
            .await
            .map_err(|err| wallet_artifact_error(&err))?;
        self.preferred_gateway_index = manifest_fetch.preferred_gateway_index;
        let manifest_elapsed_ms = manifest_started.elapsed().as_millis();
        self.send_preparation_progress(WALLET_ARTIFACT_MANIFEST_DONE_PROGRESS);
        Ok((manifest_fetch.manifest, manifest_elapsed_ms))
    }

    /// Plans the current chunks from `from_block` towards the advertised
    /// target, trimmed to the block that coverage and chunk checkpoints
    /// prove. None when nothing from `from_block` on is proven.
    async fn plan_chunks(
        &self,
        chain_entry: &IndexedArtifactChainEntry,
        from_block: u64,
        advertised_target_block: u64,
    ) -> Result<Option<WalletArtifactChunkPlan>, SyncError> {
        let IndexedWalletArtifactDescriptorFetchResult {
            mut required_current_chunks,
            coverage,
        } = self
            .fetch_descriptors(chain_entry, from_block, advertised_target_block)
            .await?;
        let all_chunk_descriptors = required_current_chunks
            .iter()
            .map(|entry| entry.descriptor.clone())
            .collect::<Vec<_>>();
        let Some(target_block) = wallet_scan_artifact_target_block(
            &coverage,
            &all_chunk_descriptors,
            from_block,
            advertised_target_block,
        )?
        else {
            return Ok(None);
        };
        required_current_chunks
            .retain(|entry| entry.descriptor.range.intersects(from_block, target_block));
        let chunk_descriptors = required_current_chunks
            .iter()
            .map(|entry| entry.descriptor.clone())
            .collect::<Vec<_>>();
        Ok(Some(WalletArtifactChunkPlan {
            target_block,
            required_current_chunks,
            chunk_descriptors,
            coverage,
        }))
    }

    async fn fetch_descriptors(
        &self,
        chain_entry: &IndexedArtifactChainEntry,
        from_block: u64,
        target_block: u64,
    ) -> Result<IndexedWalletArtifactDescriptorFetchResult, SyncError> {
        let mut candidate_catalogs = Vec::new();
        for catalog_descriptor in chain_entry.catalogs.iter().filter(|catalog| {
            catalog.matches_range(
                IndexedDatasetKind::WalletScan,
                &self.chain_scope,
                IndexedArtifactRangeKind::Block,
                from_block,
                target_block,
            )
        }) {
            let catalog = self
                .client
                .fetch_catalog_with_preferred_gateway(
                    catalog_descriptor,
                    self.preferred_gateway_index,
                )
                .await
                .map_err(|err| wallet_artifact_error(&err))?;
            candidate_catalogs.push(IndexedArtifactStreamCatalog::from(catalog));
        }
        let plan = IndexedWalletArtifactSession::select_current_stream_plan(
            &candidate_catalogs,
            &self.chain_scope,
            from_block,
            target_block,
        )?;
        let coverage = WalletScanArtifactCoverage::from_coverage(&plan.required_current_coverage)?;
        Ok(IndexedWalletArtifactDescriptorFetchResult {
            required_current_chunks: plan.required_current_chunks,
            coverage,
        })
    }

    /// Resolves every planned chunk through the public cache, fetching and
    /// verifying the ones it lacks.
    async fn fetch_chunks(
        &self,
        plan: &WalletArtifactChunkPlan,
        manifest_sequence: u64,
    ) -> Result<IndexedWalletArtifactChunkFetchResult, SyncError> {
        let fetch_started = Instant::now();
        let ChunkCachePartition {
            cached: mut indexed_chunks,
            missing,
        } = self.partition_cached(plan);
        let missing_descriptors: Vec<_> = missing
            .iter()
            .map(|(_, descriptor)| descriptor.clone())
            .collect();
        let counts = ChunkFetchCounts::new(plan.chunk_descriptors.len(), &missing_descriptors);
        let ChunkFetchCounts {
            requested_chunks,
            cache_hits,
            fetched_chunks,
            fetched_bytes,
        } = counts;
        let cids = PlannedChunkCids::new(&plan.required_current_chunks);
        let mut fetch_metrics = IndexedArtifactChunkFetchMetrics::default();
        info!(
            requested_chunks,
            cache_hits, fetched_chunks, fetched_bytes, "wallet-scan artifact chunk fetch starting"
        );
        self.send_chunk_progress(cache_hits, requested_chunks);
        if !missing_descriptors.is_empty() {
            let fetched_batch = self
                .fetch_missing(&missing_descriptors, &cids.stable, counts)
                .await?;
            fetch_metrics = fetched_batch.metrics;
            self.retain_transient(&fetched_batch.chunks, &cids.transient, manifest_sequence)
                .await;
            indexed_chunks.extend(
                missing
                    .into_iter()
                    .zip(fetched_batch.chunks)
                    .map(|((descriptor_index, _), chunk)| (descriptor_index, chunk)),
            );
        }
        let fetch_verify_elapsed_ms = fetch_started.elapsed().as_millis();
        debug!(
            requested_chunks,
            cache_hits,
            fetched_chunks,
            fetched_bytes,
            slowest_chunk_elapsed_ms = fetch_metrics.slowest_chunk_elapsed_ms,
            byte_budget_waits = fetch_metrics.byte_budget_waits,
            "wallet-scan artifact chunks resolved through public cache"
        );
        Ok(IndexedWalletArtifactChunkFetchResult {
            chunks: into_session_chunks(indexed_chunks),
            fetch_verify_elapsed_ms,
            cache_hits,
            fetched_chunks,
            fetched_bytes,
            slowest_chunk_elapsed_ms: fetch_metrics.slowest_chunk_elapsed_ms,
            byte_budget_waits: fetch_metrics.byte_budget_waits,
            max_observed_in_flight_chunks: fetch_metrics.max_observed_in_flight_chunks,
            max_observed_in_flight_bytes: fetch_metrics.max_observed_in_flight_bytes,
        })
    }

    /// Looks each planned chunk up in the cache its placement selects: the
    /// transient cache for a current transient chunk, the stable cache
    /// otherwise.
    fn partition_cached(&self, plan: &WalletArtifactChunkPlan) -> ChunkCachePartition {
        let mut cached = Vec::with_capacity(plan.chunk_descriptors.len());
        let mut missing = Vec::new();
        for (descriptor_index, descriptor) in plan.chunk_descriptors.iter().enumerate() {
            let chunk = match wallet_artifact_cache_class(&plan.required_current_chunks, descriptor)
            {
                Some(WalletArtifactCacheClass::Transient) => self
                    .public_data_plane
                    .cached_wallet_scan_transient_artifact_chunk(descriptor),
                Some(WalletArtifactCacheClass::Stable) | None => self
                    .public_data_plane
                    .cached_wallet_scan_artifact_chunk(descriptor),
            };
            if let Some(chunk) = chunk {
                cached.push((descriptor_index, chunk));
            } else {
                missing.push((descriptor_index, descriptor.clone()));
            }
        }
        ChunkCachePartition { cached, missing }
    }

    /// Fetches and verifies the missing chunks. Each verified stable chunk
    /// is scheduled for retention before its progress is reported.
    async fn fetch_missing(
        &self,
        missing_descriptors: &[IndexedArtifactDescriptor],
        stable_chunk_cids: &HashSet<String>,
        counts: ChunkFetchCounts,
    ) -> Result<IndexedArtifactChunkFetchBatch, SyncError> {
        self.client
            .fetch_chunks_bounded_with_verified_progress(
                missing_descriptors,
                self.preferred_gateway_index,
                |chunk, completed_chunks, _| {
                    if stable_chunk_cids.contains(&chunk.descriptor.cid) {
                        self.schedule_verified_chunk_maintenance(chunk.clone());
                    }
                    self.send_chunk_progress(
                        counts.cache_hits.saturating_add(completed_chunks),
                        counts.requested_chunks,
                    );
                },
            )
            .await
            .map_err(|err| wallet_artifact_error(&err))
    }

    async fn retain_transient(
        &self,
        chunks: &[VerifiedIndexedArtifactChunk],
        transient_chunk_cids: &HashSet<String>,
        manifest_sequence: u64,
    ) {
        for chunk in chunks {
            if transient_chunk_cids.contains(&chunk.descriptor.cid) {
                let retained = self
                    .public_data_plane
                    .retain_wallet_scan_transient_artifact_chunk_for_generation(
                        chunk,
                        self.read_scope,
                        self.public_data_plane
                            .wallet_scan_artifact_cache_generation(),
                        manifest_sequence,
                    )
                    .await;
                debug!(retained, "retained wallet-scan transient artifact chunk");
            }
        }
    }

    fn schedule_verified_chunk_maintenance(&self, chunk: VerifiedIndexedArtifactChunk) {
        if self
            .public_data_plane
            .cached_wallet_scan_artifact_chunk(&chunk.descriptor)
            .is_some()
        {
            return;
        }
        let read_scope = self.read_scope;
        let cache_generation = self
            .public_data_plane
            .wallet_scan_artifact_cache_generation();
        let key = IndexedArtifactMaintenanceKey::wallet_chunk(
            &chunk.descriptor,
            read_scope.epoch().value,
        );
        let retained_payload_bytes = chunk.bytes.len() as u64;
        let descriptor = chunk.descriptor.clone();
        let cid = descriptor.cid.clone();
        let maintenance_plane = (*self.public_data_plane).clone();
        let admission = self
            .public_data_plane
            .schedule_indexed_artifact_maintenance(key, retained_payload_bytes, async move {
                if maintenance_plane
                    .cached_wallet_scan_artifact_chunk(&descriptor)
                    .is_some()
                {
                    return;
                }
                let retained = maintenance_plane
                    .retain_wallet_scan_artifact_chunks_for_generation(
                        std::slice::from_ref(&chunk),
                        read_scope,
                        cache_generation,
                    )
                    .await;
                debug!(retained, "retained stable wallet-scan artifact chunk");
            });
        if admission != IndexedArtifactMaintenanceAdmission::Admitted {
            debug!(
                ?admission,
                cid = %cid,
                "stable wallet-scan artifact maintenance was not admitted"
            );
        }
    }

    fn schedule_chunk_maintenance(
        &self,
        required_entries: &[IndexedArtifactPlannedChunk],
        current_chunks: &[IndexedWalletArtifactChunk],
    ) {
        for chunk in current_chunks {
            if wallet_artifact_cache_class(required_entries, &chunk.chunk.descriptor)
                == Some(WalletArtifactCacheClass::Stable)
            {
                self.schedule_verified_chunk_maintenance(chunk.chunk.clone());
            }
        }
    }
}

/// A plan's chunks split by whether the public cache already holds them,
/// each with its index in the plan's descriptors.
struct ChunkCachePartition {
    cached: Vec<(usize, VerifiedIndexedArtifactChunk)>,
    missing: Vec<(usize, IndexedArtifactDescriptor)>,
}

/// How a plan's chunks split between cache hits and fetches.
#[derive(Clone, Copy)]
struct ChunkFetchCounts {
    requested_chunks: usize,
    cache_hits: usize,
    fetched_chunks: usize,
    fetched_bytes: u64,
}

impl ChunkFetchCounts {
    fn new(requested_chunks: usize, missing_descriptors: &[IndexedArtifactDescriptor]) -> Self {
        Self {
            requested_chunks,
            cache_hits: requested_chunks.saturating_sub(missing_descriptors.len()),
            fetched_chunks: missing_descriptors.len(),
            fetched_bytes: missing_descriptors.iter().fold(0_u64, |total, descriptor| {
                total.saturating_add(descriptor.byte_size)
            }),
        }
    }
}

/// The CIDs of the plan's current stable and current transient chunks.
struct PlannedChunkCids {
    stable: HashSet<String>,
    transient: HashSet<String>,
}

impl PlannedChunkCids {
    fn new(required_entries: &[IndexedArtifactPlannedChunk]) -> Self {
        Self {
            stable: required_entries
                .iter()
                .filter(|entry| entry.is_stable_current())
                .map(|entry| entry.descriptor.cid.clone())
                .collect(),
            transient: required_entries
                .iter()
                .filter(|entry| {
                    entry.placement == IndexedArtifactPlannedChunkPlacement::CurrentTransient
                })
                .map(|entry| entry.descriptor.cid.clone())
                .collect(),
        }
    }
}

/// Session chunks in block order.
fn into_session_chunks(
    indexed_chunks: Vec<(usize, VerifiedIndexedArtifactChunk)>,
) -> Vec<IndexedWalletArtifactChunk> {
    let mut chunks: Vec<_> = indexed_chunks
        .into_iter()
        .map(|(descriptor_index, chunk)| {
            let range = chunk.descriptor.range.clone();
            IndexedWalletArtifactChunk {
                descriptor_index,
                range,
                chunk,
            }
        })
        .collect();
    chunks.sort_by_key(|chunk| (chunk.range.start, chunk.range.end));
    chunks
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WalletArtifactCacheClass {
    Stable,
    Transient,
}

fn wallet_artifact_cache_class(
    required_entries: &[IndexedArtifactPlannedChunk],
    descriptor: &IndexedArtifactDescriptor,
) -> Option<WalletArtifactCacheClass> {
    required_entries
        .iter()
        .find(|entry| entry.descriptor == *descriptor)
        .and_then(|entry| match entry.placement {
            IndexedArtifactPlannedChunkPlacement::CurrentStable => {
                Some(WalletArtifactCacheClass::Stable)
            }
            IndexedArtifactPlannedChunkPlacement::CurrentTransient => {
                Some(WalletArtifactCacheClass::Transient)
            }
            IndexedArtifactPlannedChunkPlacement::OptionalPriorTail => None,
        })
}

pub(super) struct IndexedWalletArtifactChunk {
    pub(super) descriptor_index: usize,
    pub(super) range: IndexedArtifactRange,
    pub(super) chunk: VerifiedIndexedArtifactChunk,
}

struct IndexedWalletArtifactChunkFetchResult {
    chunks: Vec<IndexedWalletArtifactChunk>,
    fetch_verify_elapsed_ms: u128,
    cache_hits: usize,
    fetched_chunks: usize,
    fetched_bytes: u64,
    slowest_chunk_elapsed_ms: u128,
    byte_budget_waits: u64,
    max_observed_in_flight_chunks: usize,
    max_observed_in_flight_bytes: u64,
}

struct IndexedWalletArtifactDescriptorFetchResult {
    required_current_chunks: Vec<IndexedArtifactPlannedChunk>,
    coverage: WalletScanArtifactCoverage,
}

#[cfg(test)]
impl IndexedWalletArtifactPageOutcome {
    pub(super) fn expect(self, message: &str) -> IndexedWalletPage {
        match self {
            Self::Page(page) => page,
            Self::Exhausted { .. } => panic!("{message}"),
        }
    }
}
