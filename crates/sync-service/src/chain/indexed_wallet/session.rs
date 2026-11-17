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
    ChainScope, IndexedArtifactChainEntry, IndexedArtifactDescriptor,
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
        let scope = chain.indexed_artifact_scope();
        let http_client = chain.http_client.clone();
        let client = IndexedArtifactManifestClient::new(config, http_client);
        let started = Instant::now();
        let manifest_started = Instant::now();
        if public_data_plane.current_epoch() == read_scope.epoch() {
            send_wallet_artifact_preparation_progress(
                progress_tx,
                WALLET_ARTIFACT_MANIFEST_START_PROGRESS,
            );
        }
        let manifest_fetch = client
            .fetch_manifest_with_metadata(&scope, None, SystemTime::now())
            .await
            .map_err(|err| wallet_artifact_error(&err))?;
        let manifest = manifest_fetch.manifest;
        let preferred_gateway_index = manifest_fetch.preferred_gateway_index;
        let manifest_elapsed_ms = manifest_started.elapsed().as_millis();
        if public_data_plane.current_epoch() == read_scope.epoch() {
            send_wallet_artifact_preparation_progress(
                progress_tx,
                WALLET_ARTIFACT_MANIFEST_DONE_PROGRESS,
            );
        }
        let Some(probe) =
            IndexedWalletArtifactProbe::from_manifest(&manifest, &scope, from_block, to_block)
        else {
            return Ok(None);
        };
        let advertised_target_block = to_block.min(probe.latest_indexed_block);
        let Some(chain_entry) = manifest.chains.iter().find(|entry| entry.scope == scope) else {
            return Ok(None);
        };
        let descriptor_started = Instant::now();
        let descriptors = Self::fetch_descriptors(
            &client,
            chain_entry,
            &scope,
            from_block,
            advertised_target_block,
            preferred_gateway_index,
        )
        .await?;
        let IndexedWalletArtifactDescriptorFetchResult {
            mut required_current_chunks,
            coverage,
        } = descriptors;
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
        let descriptor_elapsed_ms = descriptor_started.elapsed().as_millis();
        if public_data_plane.current_epoch() == read_scope.epoch() {
            send_wallet_artifact_preparation_progress(
                progress_tx,
                WALLET_ARTIFACT_DESCRIPTORS_DONE_PROGRESS,
            );
        }
        debug!(
            from_block,
            to_block,
            target_block,
            advertised_target_block,
            latest_indexed_block = probe.latest_indexed_block,
            catalog_count = probe.catalog_count,
            chunk_count = chunk_descriptors.len(),
            manifest_elapsed_ms,
            descriptor_elapsed_ms,
            elapsed_ms = started.elapsed().as_millis(),
            "indexed wallet artifact descriptors prepared"
        );
        let indexed_chunk_descriptors: Vec<_> =
            chunk_descriptors.iter().cloned().enumerate().collect();
        let chunks = Self::fetch_chunks(
            &client,
            &indexed_chunk_descriptors,
            &required_current_chunks,
            manifest.sequence,
            preferred_gateway_index,
            public_data_plane,
            read_scope,
            progress_tx,
        )
        .await?;
        Self::schedule_chunk_maintenance(
            &required_current_chunks,
            &chunks.chunks,
            public_data_plane,
            read_scope,
        );
        info!(
            from_block,
            to_block,
            target_block,
            advertised_target_block,
            latest_indexed_block = probe.latest_indexed_block,
            catalog_count = probe.catalog_count,
            chunk_count = chunk_descriptors.len(),
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
            target_block,
            chunk_descriptors,
            chunks: chunks.chunks,
            coverage,
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
        let mut page_checkpoint = match self
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

        let needed_chunks: Vec<_> = self
            .chunks
            .iter()
            .filter(|chunk| needed_indices.contains(&chunk.descriptor_index))
            .collect();
        for chunk in &needed_chunks {
            if !chunk.range.intersects(from_block, page_checkpoint) {
                continue;
            }
            let chunk_bounds = WalletScanChunkBounds::try_from(&chunk.chunk.descriptor)?;
            if chunk_bounds.checkpoint_block() < chunk.range.end {
                page_checkpoint = page_checkpoint.min(chunk_bounds.checkpoint_block());
            }
        }
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
        let mut page = IndexedWalletPage::empty(page_checkpoint);
        for chunk in needed_chunks {
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
        debug!(
            from_block,
            to_block,
            target_block,
            page_checkpoint,
            needed_chunks = needed_indices.len(),
            cached_chunks,
            fetched_chunks = 0,
            session_cached_chunks = self.chunks.len(),
            chunk_fetch_verify_elapsed_ms = 0,
            chunk_decode_elapsed_ms = decode_started.elapsed().as_millis(),
            elapsed_ms = started.elapsed().as_millis(),
            "indexed wallet artifact page chunks ready"
        );
        Ok(IndexedWalletArtifactPageOutcome::Page(page))
    }

    async fn fetch_descriptors(
        client: &IndexedArtifactManifestClient,
        chain_entry: &IndexedArtifactChainEntry,
        scope: &ChainScope,
        from_block: u64,
        target_block: u64,
        preferred_gateway_index: Option<usize>,
    ) -> Result<IndexedWalletArtifactDescriptorFetchResult, SyncError> {
        let mut candidate_catalogs = Vec::new();
        for catalog_descriptor in chain_entry.catalogs.iter().filter(|catalog| {
            catalog.matches_range(
                IndexedDatasetKind::WalletScan,
                scope,
                IndexedArtifactRangeKind::Block,
                from_block,
                target_block,
            )
        }) {
            let catalog = client
                .fetch_catalog_with_preferred_gateway(catalog_descriptor, preferred_gateway_index)
                .await
                .map_err(|err| wallet_artifact_error(&err))?;
            candidate_catalogs.push(IndexedArtifactStreamCatalog::from(catalog));
        }
        let plan =
            Self::select_current_stream_plan(&candidate_catalogs, scope, from_block, target_block)?;
        let coverage = WalletScanArtifactCoverage::from_coverage(&plan.required_current_coverage)?;
        Ok(IndexedWalletArtifactDescriptorFetchResult {
            required_current_chunks: plan.required_current_chunks,
            coverage,
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

    async fn fetch_chunks(
        client: &IndexedArtifactManifestClient,
        chunk_descriptors: &[(usize, IndexedArtifactDescriptor)],
        required_entries: &[IndexedArtifactPlannedChunk],
        manifest_sequence: u64,
        preferred_gateway_index: Option<usize>,
        public_data_plane: &ChainPublicDataPlane,
        read_scope: PublicScanReadScope,
        progress_tx: Option<&SyncProgressSender>,
    ) -> Result<IndexedWalletArtifactChunkFetchResult, SyncError> {
        let descriptors: Vec<_> = chunk_descriptors
            .iter()
            .map(|(_, descriptor)| descriptor.clone())
            .collect();
        let fetch_started = Instant::now();
        let mut indexed_chunks = Vec::with_capacity(chunk_descriptors.len());
        let mut missing = Vec::new();
        for (descriptor_index, descriptor) in chunk_descriptors {
            let cached = match wallet_artifact_cache_class(required_entries, descriptor) {
                Some(WalletArtifactCacheClass::Transient) => {
                    public_data_plane.cached_wallet_scan_transient_artifact_chunk(descriptor)
                }
                Some(WalletArtifactCacheClass::Stable) | None => {
                    public_data_plane.cached_wallet_scan_artifact_chunk(descriptor)
                }
            };
            if let Some(chunk) = cached {
                indexed_chunks.push((*descriptor_index, chunk));
            } else {
                missing.push((*descriptor_index, descriptor.clone()));
            }
        }

        let missing_descriptors: Vec<_> = missing
            .iter()
            .map(|(_, descriptor)| descriptor.clone())
            .collect();
        let cache_hits = descriptors.len().saturating_sub(missing_descriptors.len());
        let fetched_chunks = missing_descriptors.len();
        let fetched_bytes = missing_descriptors.iter().fold(0_u64, |total, descriptor| {
            total.saturating_add(descriptor.byte_size)
        });
        let stable_chunk_cids = required_entries
            .iter()
            .filter(|entry| entry.is_stable_current())
            .map(|entry| entry.descriptor.cid.clone())
            .collect::<HashSet<_>>();
        let transient_chunk_cids = required_entries
            .iter()
            .filter(|entry| {
                entry.placement == IndexedArtifactPlannedChunkPlacement::CurrentTransient
            })
            .map(|entry| entry.descriptor.cid.clone())
            .collect::<HashSet<_>>();
        let mut fetch_metrics =
            crate::indexed_artifacts::IndexedArtifactChunkFetchMetrics::default();
        info!(
            requested_chunks = descriptors.len(),
            cache_hits, fetched_chunks, fetched_bytes, "wallet-scan artifact chunk fetch starting"
        );
        if public_data_plane.current_epoch() == read_scope.epoch() {
            send_wallet_artifact_chunk_progress(progress_tx, cache_hits, descriptors.len());
        }
        if !missing_descriptors.is_empty() {
            let fetched_batch = client
                .fetch_chunks_bounded_with_verified_progress(
                    &missing_descriptors,
                    preferred_gateway_index,
                    |chunk, completed_chunks, _| {
                        if stable_chunk_cids.contains(&chunk.descriptor.cid) {
                            Self::schedule_verified_chunk_maintenance(
                                chunk.clone(),
                                public_data_plane,
                                read_scope,
                            );
                        }
                        if public_data_plane.current_epoch() == read_scope.epoch() {
                            send_wallet_artifact_chunk_progress(
                                progress_tx,
                                cache_hits.saturating_add(completed_chunks),
                                descriptors.len(),
                            );
                        }
                    },
                )
                .await
                .map_err(|err| wallet_artifact_error(&err))?;
            fetch_metrics = fetched_batch.metrics;
            for chunk in &fetched_batch.chunks {
                if transient_chunk_cids.contains(&chunk.descriptor.cid) {
                    let retained = public_data_plane
                        .retain_wallet_scan_transient_artifact_chunk_for_generation(
                            chunk,
                            read_scope,
                            public_data_plane.wallet_scan_artifact_cache_generation(),
                            manifest_sequence,
                        )
                        .await;
                    debug!(retained, "retained wallet-scan transient artifact chunk");
                }
            }
            for ((descriptor_index, _), chunk) in missing.into_iter().zip(fetched_batch.chunks) {
                indexed_chunks.push((descriptor_index, chunk));
            }
        }
        let fetch_verify_elapsed_ms = fetch_started.elapsed().as_millis();
        debug!(
            requested_chunks = descriptors.len(),
            cache_hits,
            fetched_chunks,
            fetched_bytes,
            slowest_chunk_elapsed_ms = fetch_metrics.slowest_chunk_elapsed_ms,
            byte_budget_waits = fetch_metrics.byte_budget_waits,
            "wallet-scan artifact chunks resolved through public cache"
        );
        let mut indexed_chunks: Vec<_> = indexed_chunks
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
        indexed_chunks.sort_by_key(|chunk| (chunk.range.start, chunk.range.end));
        Ok(IndexedWalletArtifactChunkFetchResult {
            chunks: indexed_chunks,
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

    fn schedule_verified_chunk_maintenance(
        chunk: VerifiedIndexedArtifactChunk,
        public_data_plane: &ChainPublicDataPlane,
        read_scope: PublicScanReadScope,
    ) {
        if public_data_plane
            .cached_wallet_scan_artifact_chunk(&chunk.descriptor)
            .is_some()
        {
            return;
        }
        let cache_generation = public_data_plane.wallet_scan_artifact_cache_generation();
        let key = IndexedArtifactMaintenanceKey::wallet_chunk(
            &chunk.descriptor,
            read_scope.epoch().value,
        );
        let retained_payload_bytes = chunk.bytes.len() as u64;
        let descriptor = chunk.descriptor.clone();
        let cid = descriptor.cid.clone();
        let maintenance_plane = (*public_data_plane).clone();
        let admission = public_data_plane.schedule_indexed_artifact_maintenance(
            key,
            retained_payload_bytes,
            async move {
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
            },
        );
        if admission != IndexedArtifactMaintenanceAdmission::Admitted {
            debug!(
                ?admission,
                cid = %cid,
                "stable wallet-scan artifact maintenance was not admitted"
            );
        }
    }

    fn schedule_chunk_maintenance(
        required_entries: &[IndexedArtifactPlannedChunk],
        current_chunks: &[IndexedWalletArtifactChunk],
        public_data_plane: &ChainPublicDataPlane,
        read_scope: PublicScanReadScope,
    ) {
        for chunk in current_chunks {
            if wallet_artifact_cache_class(required_entries, &chunk.chunk.descriptor)
                == Some(WalletArtifactCacheClass::Stable)
            {
                Self::schedule_verified_chunk_maintenance(
                    chunk.chunk.clone(),
                    public_data_plane,
                    read_scope,
                );
            }
        }
    }
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

fn send_wallet_artifact_preparation_progress(
    progress_tx: Option<&SyncProgressSender>,
    current_progress: u64,
) {
    send_sync_progress(
        progress_tx,
        SyncProgressUpdate::artifact_preparation(
            SyncProgressStage::PreparingUtxoIndex,
            current_progress,
            WALLET_ARTIFACT_PROGRESS_TOTAL,
        )
        .with_source(PublicScanSource::IndexedArtifacts),
    );
}

fn send_wallet_artifact_chunk_progress(
    progress_tx: Option<&SyncProgressSender>,
    completed_chunks: usize,
    total_chunks: usize,
) {
    send_sync_progress(
        progress_tx,
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
