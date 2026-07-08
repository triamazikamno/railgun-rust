use super::*;

use crate::chain::service::{send_wallet_job_retired, send_wallet_scan_apply, send_wallet_target};

use std::time::SystemTime;

use alloy::primitives::{FixedBytes as AlloyFixedBytes, U256};
use alloy::sol_types::SolValue;
use broadcaster_core::contracts::railgun::{
    CommitmentCiphertext, CommitmentPreimage, LegacyCommitmentCiphertext, LegacyCommitmentPreimage,
    ShieldCiphertext,
};

use crate::indexed_artifacts::{
    ChainScope, ChainType, IndexedArtifactChainEntry, IndexedArtifactDescriptor,
    IndexedArtifactManifest, IndexedArtifactManifestClient, IndexedArtifactManifestError,
    IndexedArtifactRange, IndexedArtifactRangeKind, IndexedArtifactStreamCatalog,
    IndexedArtifactStreamPartitionPolicy, IndexedArtifactStreamPlan,
    IndexedArtifactStreamPlanRequest, IndexedDatasetKind, VerifiedIndexedArtifactChunk,
    decode_indexed_artifact_chunk,
};

const WALLET_TRANSACT_SECTION_ID: u16 = 1;
const WALLET_SHIELD_SECTION_ID: u16 = 2;
const WALLET_NULLIFIER_SECTION_ID: u16 = 3;
const WALLET_LEGACY_ENCRYPTED_SECTION_ID: u16 = 4;
const WALLET_LEGACY_GENERATED_SECTION_ID: u16 = 5;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct IndexedWalletArtifactProbe {
    pub(super) latest_indexed_block: u64,
    pub(super) catalog_count: usize,
}

impl IndexedWalletArtifactProbe {
    pub(super) fn from_manifest(
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

    pub(super) fn catch_up_target(self, safe_head: u64) -> u64 {
        self.latest_indexed_block.min(safe_head)
    }
}

pub(super) struct IndexedWalletPage {
    pub(super) transact_commitments: Vec<IndexedTransactCommitmentInput>,
    pub(super) shield_commitments: Vec<IndexedShieldCommitmentInput>,
    pub(super) legacy_encrypted_commitments: Vec<IndexedLegacyEncryptedCommitmentInput>,
    pub(super) legacy_generated_commitments: Vec<IndexedLegacyGeneratedCommitmentInput>,
    pub(super) nullifiers: Vec<IndexedNullifierInput>,
    pub(super) checkpoint_block: u64,
    pub(super) transact_rows: usize,
    pub(super) shield_rows: usize,
    pub(super) legacy_encrypted_rows: usize,
    pub(super) legacy_generated_rows: usize,
    pub(super) nullifier_rows: usize,
}

impl IndexedWalletPage {
    pub(super) fn into_scan_rows(self) -> WalletScanInputRows {
        WalletScanInputRows {
            transact_commitments: self.transact_commitments,
            shield_commitments: self.shield_commitments,
            legacy_encrypted_commitments: self.legacy_encrypted_commitments,
            legacy_generated_commitments: self.legacy_generated_commitments,
            nullifiers: self.nullifiers,
            commitment_observations: Vec::new(),
        }
    }

    async fn fetch_modern(
        client: &QuickSyncClient,
        from_block: u64,
        to_block: u64,
    ) -> Result<Self, SyncError> {
        let page = client
            .fetch_indexed_wallet_page(from_block, to_block, DEFAULT_PAGE_SIZE)
            .await?;
        let transact = page.transact_commitments;
        let shields = page.shield_commitments;
        let nullifiers = page.nullifiers;
        let page_size = DEFAULT_PAGE_SIZE.get();
        let transact_checkpoint = complete_stream_checkpoint(
            transact.len(),
            page_size,
            to_block,
            transact.iter().map(|item| item.block_number.to()),
        );
        let shield_checkpoint = complete_stream_checkpoint(
            shields.len(),
            page_size,
            to_block,
            shields.iter().map(|item| item.block_number.to()),
        );
        let nullifier_checkpoint = complete_stream_checkpoint(
            nullifiers.len(),
            page_size,
            to_block,
            nullifiers.iter().map(|item| item.block_number.to()),
        );
        let checkpoint_block = transact_checkpoint
            .min(shield_checkpoint)
            .min(nullifier_checkpoint);
        if checkpoint_block < from_block {
            return Err(SyncError::UnexpectedFormat(format!(
                "indexed wallet page is incomplete at block {from_block}; reduce page range or increase page size"
            )));
        }

        let transact_rows = transact.len();
        let shield_rows = shields.len();
        let nullifier_rows = nullifiers.len();
        let transact_commitments = transact
            .into_iter()
            .filter(|item| item.block_number.to::<u64>() <= checkpoint_block)
            .map(Into::into)
            .collect();
        let shield_commitments = shields
            .into_iter()
            .filter(|item| item.block_number.to::<u64>() <= checkpoint_block)
            .map(Into::into)
            .collect();
        let nullifiers = nullifiers
            .into_iter()
            .filter(|item| item.block_number.to::<u64>() <= checkpoint_block)
            .map(Into::into)
            .collect();

        Ok(Self {
            transact_commitments,
            shield_commitments,
            legacy_encrypted_commitments: Vec::new(),
            legacy_generated_commitments: Vec::new(),
            nullifiers,
            checkpoint_block,
            transact_rows,
            shield_rows,
            legacy_encrypted_rows: 0,
            legacy_generated_rows: 0,
            nullifier_rows,
        })
    }

    async fn fetch_legacy(
        client: &QuickSyncClient,
        from_block: u64,
        to_block: u64,
    ) -> Result<Self, SyncError> {
        let page = client
            .fetch_indexed_legacy_wallet_page(from_block, to_block, DEFAULT_PAGE_SIZE)
            .await?;
        let legacy_encrypted = page.legacy_encrypted_commitments;
        let legacy_generated = page.legacy_generated_commitments;
        let nullifiers = page.nullifiers;
        let page_size = DEFAULT_PAGE_SIZE.get();
        let encrypted_checkpoint = complete_stream_checkpoint(
            legacy_encrypted.len(),
            page_size,
            to_block,
            legacy_encrypted.iter().map(|item| item.block_number.to()),
        );
        let generated_checkpoint = complete_stream_checkpoint(
            legacy_generated.len(),
            page_size,
            to_block,
            legacy_generated.iter().map(|item| item.block_number.to()),
        );
        let nullifier_checkpoint = complete_stream_checkpoint(
            nullifiers.len(),
            page_size,
            to_block,
            nullifiers.iter().map(|item| item.block_number.to()),
        );
        let checkpoint_block = encrypted_checkpoint
            .min(generated_checkpoint)
            .min(nullifier_checkpoint);
        if checkpoint_block < from_block {
            return Err(SyncError::UnexpectedFormat(format!(
                "indexed legacy wallet page is incomplete at block {from_block}; reduce page range or increase page size"
            )));
        }

        let legacy_encrypted_rows = legacy_encrypted.len();
        let legacy_generated_rows = legacy_generated.len();
        let nullifier_rows = nullifiers.len();
        let legacy_encrypted_commitments = legacy_encrypted
            .into_iter()
            .filter(|item| item.block_number.to::<u64>() <= checkpoint_block)
            .map(Into::into)
            .collect();
        let legacy_generated_commitments = legacy_generated
            .into_iter()
            .filter(|item| item.block_number.to::<u64>() <= checkpoint_block)
            .map(Into::into)
            .collect();
        let nullifiers = nullifiers
            .into_iter()
            .filter(|item| item.block_number.to::<u64>() <= checkpoint_block)
            .map(Into::into)
            .collect();

        Ok(Self {
            transact_commitments: Vec::new(),
            shield_commitments: Vec::new(),
            legacy_encrypted_commitments,
            legacy_generated_commitments,
            nullifiers,
            checkpoint_block,
            transact_rows: 0,
            shield_rows: 0,
            legacy_encrypted_rows,
            legacy_generated_rows,
            nullifier_rows,
        })
    }

    pub(super) async fn fetch(
        client: &QuickSyncClient,
        page_kind: IndexedWalletPageKind,
        from_block: u64,
        to_block: u64,
    ) -> Result<Self, SyncError> {
        match page_kind {
            IndexedWalletPageKind::Legacy => Self::fetch_legacy(client, from_block, to_block).await,
            IndexedWalletPageKind::Modern => Self::fetch_modern(client, from_block, to_block).await,
        }
    }

    fn empty(checkpoint_block: u64) -> Self {
        Self {
            transact_commitments: Vec::new(),
            shield_commitments: Vec::new(),
            legacy_encrypted_commitments: Vec::new(),
            legacy_generated_commitments: Vec::new(),
            nullifiers: Vec::new(),
            checkpoint_block,
            transact_rows: 0,
            shield_rows: 0,
            legacy_encrypted_rows: 0,
            legacy_generated_rows: 0,
            nullifier_rows: 0,
        }
    }

    fn extend_filtered_from(&mut self, source: &Self, from_block: u64, to_block: u64) {
        self.transact_commitments.extend(
            source
                .transact_commitments
                .iter()
                .filter(|row| Self::source_in_range(&row.source, from_block, to_block))
                .cloned(),
        );
        self.shield_commitments.extend(
            source
                .shield_commitments
                .iter()
                .filter(|row| Self::source_in_range(&row.source, from_block, to_block))
                .cloned(),
        );
        self.legacy_encrypted_commitments.extend(
            source
                .legacy_encrypted_commitments
                .iter()
                .filter(|row| Self::source_in_range(&row.source, from_block, to_block))
                .cloned(),
        );
        self.legacy_generated_commitments.extend(
            source
                .legacy_generated_commitments
                .iter()
                .filter(|row| Self::source_in_range(&row.source, from_block, to_block))
                .cloned(),
        );
        self.nullifiers.extend(
            source
                .nullifiers
                .iter()
                .filter(|row| Self::source_in_range(&row.source, from_block, to_block))
                .cloned(),
        );
    }

    fn refresh_row_counts(&mut self) {
        self.transact_rows = self.transact_commitments.len();
        self.shield_rows = self.shield_commitments.len();
        self.legacy_encrypted_rows = self.legacy_encrypted_commitments.len();
        self.legacy_generated_rows = self.legacy_generated_commitments.len();
        self.nullifier_rows = self.nullifiers.len();
    }

    const fn source_in_range(source: &UtxoSource, from_block: u64, to_block: u64) -> bool {
        source.block_number >= from_block && source.block_number <= to_block
    }
}

pub(super) struct IndexedWalletArtifactSession {
    probe: IndexedWalletArtifactProbe,
    chunk_descriptors: Vec<IndexedArtifactDescriptor>,
    chunks: Vec<IndexedWalletArtifactChunk>,
    coverage: WalletScanArtifactCoverage,
    read_scope: PublicScanReadScope,
}

pub(super) enum IndexedWalletArtifactPageOutcome {
    Page(IndexedWalletPage),
    Exhausted { checkpoint_block: u64 },
}

#[cfg(test)]
impl IndexedWalletArtifactPageOutcome {
    fn expect(self, message: &str) -> IndexedWalletPage {
        match self {
            Self::Page(page) => page,
            Self::Exhausted { .. } => panic!("{message}"),
        }
    }
}

impl IndexedWalletArtifactSession {
    pub(super) async fn prepare(
        chain: &ChainConfig,
        from_block: u64,
        to_block: u64,
        read_scope: PublicScanReadScope,
        public_data_plane: &ChainPublicDataPlane,
    ) -> Result<Option<Self>, SyncError> {
        let Some(config) = chain.indexed_artifact_source.clone() else {
            return Ok(None);
        };
        let scope = chain.indexed_artifact_scope();
        let http_client = chain.http_client.clone().unwrap_or_default();
        let client = IndexedArtifactManifestClient::new(config, http_client);
        let started = Instant::now();
        let manifest_started = Instant::now();
        let manifest = client
            .fetch_manifest(&scope, None, SystemTime::now())
            .await
            .map_err(wallet_artifact_error)?;
        let manifest_elapsed_ms = manifest_started.elapsed().as_millis();
        let Some(probe) =
            IndexedWalletArtifactProbe::from_manifest(&manifest, &scope, from_block, to_block)
        else {
            return Ok(None);
        };
        let target_block = to_block.min(probe.latest_indexed_block);
        let Some(chain_entry) = manifest.chains.iter().find(|entry| entry.scope == scope) else {
            return Ok(None);
        };
        let descriptor_started = Instant::now();
        let descriptors =
            Self::fetch_descriptors(&client, chain_entry, &scope, from_block, target_block).await?;
        let IndexedWalletArtifactDescriptorFetchResult {
            chunk_descriptors,
            chunk_retention_descriptors,
            optional_prior_tail_retention,
            coverage,
        } = descriptors;
        let descriptor_elapsed_ms = descriptor_started.elapsed().as_millis();
        debug!(
            from_block,
            to_block,
            target_block,
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
            &chunk_retention_descriptors,
            public_data_plane,
        )
        .await?;
        Self::retain_optional_prior_tail_chunks(
            &client,
            &optional_prior_tail_retention,
            &chunk_retention_descriptors,
            public_data_plane,
        )
        .await;
        debug!(
            from_block,
            to_block,
            target_block,
            latest_indexed_block = probe.latest_indexed_block,
            catalog_count = probe.catalog_count,
            chunk_count = chunk_descriptors.len(),
            chunk_fetch_verify_elapsed_ms = chunks.fetch_verify_elapsed_ms,
            elapsed_ms = started.elapsed().as_millis(),
            "indexed wallet artifact chunks prepared"
        );
        Ok(Some(Self {
            probe,
            chunk_descriptors,
            chunks: chunks.chunks,
            coverage,
            read_scope,
        }))
    }

    pub(super) const fn probe(&self) -> IndexedWalletArtifactProbe {
        self.probe
    }

    pub(super) const fn latest_indexed_block(&self) -> u64 {
        self.probe.latest_indexed_block
    }

    pub(super) const fn catalog_count(&self) -> usize {
        self.probe.catalog_count
    }

    pub(super) fn chunk_count(&self) -> usize {
        self.chunk_descriptors.len()
    }

    pub(super) const fn read_scope(&self) -> PublicScanReadScope {
        self.read_scope
    }

    pub(super) fn page_for_block_range(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Result<IndexedWalletArtifactPageOutcome, SyncError> {
        let target_block = to_block.min(self.probe.latest_indexed_block);
        if target_block < from_block {
            return Ok(IndexedWalletArtifactPageOutcome::Exhausted {
                checkpoint_block: self.probe.latest_indexed_block,
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
            let chunk_bounds = WalletScanChunkBounds::from_descriptor(&chunk.chunk.descriptor)?;
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
                .fetch_catalog(catalog_descriptor)
                .await
                .map_err(wallet_artifact_error)?;
            candidate_catalogs.push(catalog.into_stream_catalog());
        }
        let plan =
            Self::select_current_stream_plan(&candidate_catalogs, scope, from_block, target_block)?;
        let coverage =
            WalletScanArtifactCoverage::from_descriptors(&plan.required_current_coverage)?;
        let mut chunk_retention_descriptors = plan.required_current_coverage.clone();
        chunk_retention_descriptors.extend_from_slice(&plan.optional_prior_tail_retention);
        Ok(IndexedWalletArtifactDescriptorFetchResult {
            chunk_descriptors: plan.required_current_chunks,
            chunk_retention_descriptors,
            optional_prior_tail_retention: plan.optional_prior_tail_retention,
            coverage,
        })
    }

    fn select_current_stream_plan(
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
        chunk_retention_descriptors: &[IndexedArtifactDescriptor],
        public_data_plane: &ChainPublicDataPlane,
    ) -> Result<IndexedWalletArtifactChunkFetchResult, SyncError> {
        let descriptors: Vec<_> = chunk_descriptors
            .iter()
            .map(|(_, descriptor)| descriptor.clone())
            .collect();
        let fetch_started = Instant::now();
        let mut indexed_chunks = Vec::with_capacity(chunk_descriptors.len());
        let mut missing = Vec::new();
        for (descriptor_index, descriptor) in chunk_descriptors {
            if let Some(chunk) = public_data_plane.cached_wallet_scan_artifact_chunk(descriptor) {
                indexed_chunks.push((*descriptor_index, chunk));
            } else {
                missing.push((*descriptor_index, descriptor.clone()));
            }
        }

        let missing_descriptors: Vec<_> = missing
            .iter()
            .map(|(_, descriptor)| descriptor.clone())
            .collect();
        if !missing_descriptors.is_empty() {
            let fetched_chunks = client
                .fetch_chunks_bounded(&missing_descriptors)
                .await
                .map_err(wallet_artifact_error)?;
            for ((descriptor_index, _), chunk) in missing.into_iter().zip(fetched_chunks) {
                indexed_chunks.push((descriptor_index, chunk));
            }
        }
        let fetch_verify_elapsed_ms = fetch_started.elapsed().as_millis();
        let all_chunks: Vec<_> = indexed_chunks
            .iter()
            .map(|(_, chunk)| chunk.clone())
            .collect();
        let retained_chunks = public_data_plane
            .retain_wallet_scan_artifact_chunks(&all_chunks, chunk_retention_descriptors);
        debug!(
            requested_chunks = descriptors.len(),
            cache_hits = descriptors.len().saturating_sub(missing_descriptors.len()),
            fetched_chunks = missing_descriptors.len(),
            retained_chunks,
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
        })
    }

    async fn retain_optional_prior_tail_chunks(
        client: &IndexedArtifactManifestClient,
        optional_descriptors: &[IndexedArtifactDescriptor],
        chunk_retention_descriptors: &[IndexedArtifactDescriptor],
        public_data_plane: &ChainPublicDataPlane,
    ) {
        if optional_descriptors.is_empty() {
            return;
        }
        match client.fetch_chunks_bounded(optional_descriptors).await {
            Ok(chunks) => {
                let retained = public_data_plane
                    .retain_wallet_scan_artifact_chunks(&chunks, chunk_retention_descriptors);
                debug!(
                    requested = optional_descriptors.len(),
                    retained, "retained optional wallet-scan prior-tail artifact chunks"
                );
            }
            Err(err) => warn!(
                ?err,
                requested = optional_descriptors.len(),
                "failed best-effort wallet-scan prior-tail artifact retention"
            ),
        }
    }
}

struct IndexedWalletArtifactChunk {
    descriptor_index: usize,
    range: IndexedArtifactRange,
    chunk: VerifiedIndexedArtifactChunk,
}

struct IndexedWalletArtifactChunkFetchResult {
    chunks: Vec<IndexedWalletArtifactChunk>,
    fetch_verify_elapsed_ms: u128,
}

struct IndexedWalletArtifactDescriptorFetchResult {
    chunk_descriptors: Vec<IndexedArtifactDescriptor>,
    chunk_retention_descriptors: Vec<IndexedArtifactDescriptor>,
    optional_prior_tail_retention: Vec<IndexedArtifactDescriptor>,
    coverage: WalletScanArtifactCoverage,
}

#[derive(Default)]
struct WalletScanArtifactCoverage {
    ranges: Vec<WalletScanCoverageRange>,
}

impl WalletScanArtifactCoverage {
    fn from_descriptors(descriptors: &[IndexedArtifactDescriptor]) -> Result<Self, SyncError> {
        let mut coverage = Self::default();
        for descriptor in descriptors {
            coverage.add_descriptor(descriptor)?;
        }
        Ok(coverage)
    }

    fn add_descriptor(&mut self, descriptor: &IndexedArtifactDescriptor) -> Result<(), SyncError> {
        self.ranges
            .push(WalletScanCoverageRange::from_descriptor(descriptor)?);
        self.ranges.sort_by_key(|range| (range.start, range.end));
        Ok(())
    }

    fn checkpoint_for_range(
        &self,
        from_block: u64,
        target_block: u64,
    ) -> Result<WalletScanCoverageStatus, SyncError> {
        let mut next_start = from_block;
        let mut checkpoint = None;
        for range in &self.ranges {
            if range.end < next_start {
                continue;
            }
            if range.start > next_start {
                break;
            }
            let range_end = range.end.min(target_block);
            if range.checkpoint_block < next_start {
                return Ok(WalletScanCoverageStatus::Exhausted {
                    checkpoint_block: checkpoint.map_or(range.checkpoint_block, |current: u64| {
                        current.max(range.checkpoint_block)
                    }),
                });
            }
            let range_checkpoint = range.checkpoint_block.min(range_end);
            checkpoint = Some(checkpoint.map_or(range_checkpoint, |current: u64| {
                current.max(range_checkpoint)
            }));
            if range_checkpoint < range_end {
                return Ok(WalletScanCoverageStatus::Available {
                    checkpoint_block: range_checkpoint,
                });
            }
            if range_end >= target_block {
                return Ok(WalletScanCoverageStatus::Available {
                    checkpoint_block: target_block,
                });
            }
            next_start = range_end.saturating_add(1);
        }

        checkpoint.map_or_else(
            || {
                Err(wallet_artifact_format(format!(
                    "wallet_scan artifact coverage does not include requested block {from_block}"
                )))
            },
            |checkpoint_block| Ok(WalletScanCoverageStatus::Available { checkpoint_block }),
        )
    }
}

#[derive(Clone, Copy)]
enum WalletScanCoverageStatus {
    Available { checkpoint_block: u64 },
    Exhausted { checkpoint_block: u64 },
}

#[derive(Clone, Copy)]
struct WalletScanCoverageRange {
    start: u64,
    end: u64,
    checkpoint_block: u64,
}

impl WalletScanCoverageRange {
    fn from_descriptor(descriptor: &IndexedArtifactDescriptor) -> Result<Self, SyncError> {
        let checkpoint_block = wallet_scan_descriptor_checkpoint_block(descriptor, "coverage")?;
        Ok(Self {
            start: descriptor.range.start,
            end: descriptor.range.end,
            checkpoint_block,
        })
    }
}

#[derive(Clone, Copy)]
struct WalletScanChunkBounds {
    range_start: u64,
    range_end: u64,
    checkpoint_block: u64,
}

impl WalletScanChunkBounds {
    fn from_descriptor(descriptor: &IndexedArtifactDescriptor) -> Result<Self, SyncError> {
        let checkpoint_block = wallet_scan_descriptor_checkpoint_block(descriptor, "chunk")?;
        Ok(Self {
            range_start: descriptor.range.start,
            range_end: descriptor.range.end,
            checkpoint_block,
        })
    }

    const fn checkpoint_block(self) -> u64 {
        self.checkpoint_block
    }

    fn validate_source(self, source: &UtxoSource) -> Result<(), SyncError> {
        if !IndexedWalletPage::source_in_range(source, self.range_start, self.range_end) {
            return Err(wallet_artifact_format(format!(
                "wallet_scan row source block {} is outside chunk block range {}-{}",
                source.block_number, self.range_start, self.range_end
            )));
        }
        if source.block_number > self.checkpoint_block {
            return Err(wallet_artifact_format(format!(
                "wallet_scan row source block {} exceeds checkpoint block {}",
                source.block_number, self.checkpoint_block
            )));
        }
        Ok(())
    }
}

fn wallet_scan_descriptor_checkpoint_block(
    descriptor: &IndexedArtifactDescriptor,
    descriptor_kind: &str,
) -> Result<u64, SyncError> {
    let checkpoint_block = descriptor
        .metadata
        .checkpoint_block
        .unwrap_or(descriptor.range.end);
    if checkpoint_block > descriptor.range.end {
        return Err(wallet_artifact_format(format!(
            "wallet_scan {descriptor_kind} checkpoint block {checkpoint_block} exceeds range end {}",
            descriptor.range.end
        )));
    }
    if checkpoint_block < descriptor.range.start {
        return Err(wallet_artifact_format(format!(
            "wallet_scan {descriptor_kind} checkpoint block {checkpoint_block} is before range start {}",
            descriptor.range.start
        )));
    }
    Ok(checkpoint_block)
}

#[derive(Clone, Copy)]
struct WalletScanRowBounds {
    from_block: u64,
    to_block: u64,
}

impl WalletScanRowBounds {
    const fn contains(self, source: &UtxoSource) -> bool {
        source.block_number >= self.from_block && source.block_number <= self.to_block
    }
}

impl IndexedWalletPage {
    fn from_chunk_for_block_range(
        chunk: &VerifiedIndexedArtifactChunk,
        from_block: u64,
        to_block: u64,
    ) -> Result<Self, SyncError> {
        Self::decode_from_chunk(
            chunk,
            Some(WalletScanRowBounds {
                from_block,
                to_block,
            }),
        )
    }

    fn decode_from_chunk(
        chunk: &VerifiedIndexedArtifactChunk,
        bounds: Option<WalletScanRowBounds>,
    ) -> Result<Self, SyncError> {
        let envelope = decode_indexed_artifact_chunk(chunk).map_err(wallet_artifact_error)?;
        if envelope.header.dataset_kind != IndexedDatasetKind::WalletScan {
            return Err(wallet_artifact_format(
                "chunk is not a wallet_scan artifact",
            ));
        }
        if envelope.header.scope.chain_type != ChainType::Evm {
            return Err(wallet_artifact_format("chunk is not an EVM chain artifact"));
        }
        if envelope.header.range.kind != IndexedArtifactRangeKind::Block {
            return Err(wallet_artifact_format(
                "wallet_scan range is not block scoped",
            ));
        }

        let chunk_bounds = WalletScanChunkBounds::from_descriptor(&chunk.descriptor)?;
        let checkpoint_block = chunk_bounds.checkpoint_block();
        let mut page = Self {
            transact_commitments: Vec::new(),
            shield_commitments: Vec::new(),
            legacy_encrypted_commitments: Vec::new(),
            legacy_generated_commitments: Vec::new(),
            nullifiers: Vec::new(),
            checkpoint_block,
            transact_rows: 0,
            shield_rows: 0,
            legacy_encrypted_rows: 0,
            legacy_generated_rows: 0,
            nullifier_rows: 0,
        };

        let mut row_count = 0_usize;
        for section in &envelope.header.sections {
            let payload = envelope
                .section_payload(section.section_id)
                .map_err(IndexedArtifactManifestError::from)
                .map_err(wallet_artifact_error)?;
            let mut cursor = WalletScanArtifactCursor::new(payload);
            match section.section_id {
                WALLET_TRANSACT_SECTION_ID => {
                    let (rows, decoded_rows) = cursor.read_transact_rows(chunk_bounds, bounds)?;
                    page.transact_rows = rows.len();
                    page.transact_commitments = rows;
                    row_count = row_count.saturating_add(decoded_rows);
                }
                WALLET_SHIELD_SECTION_ID => {
                    let (rows, decoded_rows) = cursor.read_shield_rows(chunk_bounds, bounds)?;
                    page.shield_rows = rows.len();
                    page.shield_commitments = rows;
                    row_count = row_count.saturating_add(decoded_rows);
                }
                WALLET_NULLIFIER_SECTION_ID => {
                    let (rows, decoded_rows) = cursor.read_nullifier_rows(chunk_bounds, bounds)?;
                    page.nullifier_rows = rows.len();
                    page.nullifiers = rows;
                    row_count = row_count.saturating_add(decoded_rows);
                }
                WALLET_LEGACY_ENCRYPTED_SECTION_ID => {
                    let (rows, decoded_rows) =
                        cursor.read_legacy_encrypted_rows(chunk_bounds, bounds)?;
                    page.legacy_encrypted_rows = rows.len();
                    page.legacy_encrypted_commitments = rows;
                    row_count = row_count.saturating_add(decoded_rows);
                }
                WALLET_LEGACY_GENERATED_SECTION_ID => {
                    let (rows, decoded_rows) =
                        cursor.read_legacy_generated_rows(chunk_bounds, bounds)?;
                    page.legacy_generated_rows = rows.len();
                    page.legacy_generated_commitments = rows;
                    row_count = row_count.saturating_add(decoded_rows);
                }
                other => {
                    return Err(wallet_artifact_format(format!(
                        "unknown wallet_scan section id {other}"
                    )));
                }
            }
            cursor.expect_eof("wallet_scan section")?;
        }

        if row_count as u64 != envelope.header.row_count {
            return Err(wallet_artifact_format(format!(
                "wallet_scan row count mismatch: expected {}, got {row_count}",
                envelope.header.row_count
            )));
        }
        Ok(page)
    }
}

impl TryFrom<&VerifiedIndexedArtifactChunk> for IndexedWalletPage {
    type Error = SyncError;

    fn try_from(chunk: &VerifiedIndexedArtifactChunk) -> Result<Self, Self::Error> {
        Self::decode_from_chunk(chunk, None)
    }
}

pub(super) const fn artifact_failure_can_fallback_to_squid(
    using_artifact: bool,
    checkpoint: u64,
    last_scanned: u64,
) -> bool {
    using_artifact && checkpoint == last_scanned
}

struct WalletScanArtifactCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> WalletScanArtifactCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read_transact_rows(
        &mut self,
        chunk_bounds: WalletScanChunkBounds,
        bounds: Option<WalletScanRowBounds>,
    ) -> Result<(Vec<IndexedTransactCommitmentInput>, usize), SyncError> {
        let count = self.read_count("transact count")?;
        let mut rows = Vec::new();
        for _ in 0..count {
            let source = self.read_source()?;
            let tree_number = self.read_u32("transact tree_number")?;
            let tree_position = self.read_u64("transact tree_position")?;
            let hash = U256::from_be_bytes(self.read_fixed_32("transact hash")?);
            let ciphertext =
                CommitmentCiphertext::abi_decode(&self.read_bytes("transact ciphertext")?)
                    .map_err(|err| {
                        wallet_artifact_format(format!("decode transact ciphertext: {err}"))
                    })?;
            chunk_bounds.validate_source(&source)?;
            if bounds.is_none_or(|bounds| bounds.contains(&source)) {
                rows.push(IndexedTransactCommitmentInput {
                    tree_number,
                    tree_position,
                    hash,
                    ciphertext: ciphertext.ciphertext,
                    blinded_sender_viewing_key: ciphertext.blindedSenderViewingKey,
                    memo: ciphertext.memo,
                    source,
                });
            }
        }
        Ok((rows, count))
    }

    fn read_shield_rows(
        &mut self,
        chunk_bounds: WalletScanChunkBounds,
        bounds: Option<WalletScanRowBounds>,
    ) -> Result<(Vec<IndexedShieldCommitmentInput>, usize), SyncError> {
        let count = self.read_count("shield count")?;
        let mut rows = Vec::new();
        for _ in 0..count {
            let source = self.read_source()?;
            let tree_number = self.read_u32("shield tree_number")?;
            let tree_position = self.read_u64("shield tree_position")?;
            let _hash = self.read_fixed_32("shield hash")?;
            let preimage = CommitmentPreimage::abi_decode(&self.read_bytes("shield preimage")?)
                .map_err(|err| wallet_artifact_format(format!("decode shield preimage: {err}")))?;
            let shield_ciphertext = ShieldCiphertext::abi_decode(
                &self.read_bytes("shield ciphertext")?,
            )
            .map_err(|err| wallet_artifact_format(format!("decode shield ciphertext: {err}")))?;
            chunk_bounds.validate_source(&source)?;
            if bounds.is_none_or(|bounds| bounds.contains(&source)) {
                rows.push(IndexedShieldCommitmentInput {
                    tree_number,
                    tree_position,
                    preimage,
                    shield_ciphertext,
                    source,
                });
            }
        }
        Ok((rows, count))
    }

    fn read_nullifier_rows(
        &mut self,
        chunk_bounds: WalletScanChunkBounds,
        bounds: Option<WalletScanRowBounds>,
    ) -> Result<(Vec<IndexedNullifierInput>, usize), SyncError> {
        let count = self.read_count("nullifier count")?;
        let mut rows = Vec::new();
        for _ in 0..count {
            let source = self.read_source()?;
            let tree_number = self.read_u32("nullifier tree_number")?;
            let nullifier = U256::from_be_bytes(self.read_fixed_32("nullifier")?);
            chunk_bounds.validate_source(&source)?;
            if bounds.is_none_or(|bounds| bounds.contains(&source)) {
                rows.push(IndexedNullifierInput {
                    tree_number,
                    nullifier,
                    source,
                });
            }
        }
        Ok((rows, count))
    }

    fn read_legacy_encrypted_rows(
        &mut self,
        chunk_bounds: WalletScanChunkBounds,
        bounds: Option<WalletScanRowBounds>,
    ) -> Result<(Vec<IndexedLegacyEncryptedCommitmentInput>, usize), SyncError> {
        let count = self.read_count("legacy encrypted count")?;
        let mut rows = Vec::new();
        for _ in 0..count {
            let source = self.read_source()?;
            let tree_number = self.read_u32("legacy encrypted tree_number")?;
            let tree_position = self.read_u64("legacy encrypted tree_position")?;
            let hash = U256::from_be_bytes(self.read_fixed_32("legacy encrypted hash")?);
            let ciphertext = LegacyCommitmentCiphertext::abi_decode(
                &self.read_bytes("legacy encrypted ciphertext")?,
            )
            .map_err(|err| {
                wallet_artifact_format(format!("decode legacy encrypted ciphertext: {err}"))
            })?;
            chunk_bounds.validate_source(&source)?;
            if bounds.is_none_or(|bounds| bounds.contains(&source)) {
                rows.push(IndexedLegacyEncryptedCommitmentInput {
                    tree_number,
                    tree_position,
                    hash,
                    ciphertext: ciphertext
                        .ciphertext
                        .map(|value| AlloyFixedBytes::from(value.to_be_bytes::<32>())),
                    ephemeral_keys: ciphertext
                        .ephemeralKeys
                        .map(|value| AlloyFixedBytes::from(value.to_be_bytes::<32>())),
                    memo: ciphertext
                        .memo
                        .into_iter()
                        .map(|value| AlloyFixedBytes::from(value.to_be_bytes::<32>()))
                        .collect(),
                    source,
                });
            }
        }
        Ok((rows, count))
    }

    fn read_legacy_generated_rows(
        &mut self,
        chunk_bounds: WalletScanChunkBounds,
        bounds: Option<WalletScanRowBounds>,
    ) -> Result<(Vec<IndexedLegacyGeneratedCommitmentInput>, usize), SyncError> {
        let count = self.read_count("legacy generated count")?;
        let mut rows = Vec::new();
        for _ in 0..count {
            let source = self.read_source()?;
            let tree_number = self.read_u32("legacy generated tree_number")?;
            let tree_position = self.read_u64("legacy generated tree_position")?;
            let _hash = self.read_fixed_32("legacy generated hash")?;
            let preimage = LegacyCommitmentPreimage::abi_decode(
                &self.read_bytes("legacy generated preimage")?,
            )
            .map_err(|err| {
                wallet_artifact_format(format!("decode legacy generated preimage: {err}"))
            })?;
            let encrypted_random = self.read_fixed_64("legacy generated encrypted_random")?;
            let encrypted_random_iv_tag: [u8; 32] = encrypted_random[..32]
                .try_into()
                .expect("encrypted random iv/tag slice length");
            let encrypted_random_data: [u8; 16] = encrypted_random[48..64]
                .try_into()
                .expect("encrypted random data slice length");
            chunk_bounds.validate_source(&source)?;
            if bounds.is_none_or(|bounds| bounds.contains(&source)) {
                rows.push(IndexedLegacyGeneratedCommitmentInput {
                    tree_number,
                    tree_position,
                    preimage,
                    encrypted_random: (
                        AlloyFixedBytes::from(encrypted_random_iv_tag),
                        AlloyFixedBytes::from(encrypted_random_data),
                    ),
                    source,
                });
            }
        }
        Ok((rows, count))
    }

    fn read_source(&mut self) -> Result<UtxoSource, SyncError> {
        let block_number = self.read_u64("source block_number")?;
        let block_timestamp = self.read_u64("source block_timestamp")?;
        let transaction_hash =
            AlloyFixedBytes::from(self.read_fixed_32("source transaction_hash")?);
        Ok(UtxoSource {
            tx_hash: transaction_hash,
            block_number,
            block_timestamp,
        })
    }

    fn read_count(&mut self, field: &'static str) -> Result<usize, SyncError> {
        usize::try_from(self.read_u64(field)?)
            .map_err(|_| wallet_artifact_format(format!("{field} overflows usize")))
    }

    fn read_u32(&mut self, field: &'static str) -> Result<u32, SyncError> {
        let bytes = self.read_exact(4, field)?;
        Ok(u32::from_le_bytes(
            bytes.try_into().expect("u32 read length"),
        ))
    }

    fn read_u64(&mut self, field: &'static str) -> Result<u64, SyncError> {
        let bytes = self.read_exact(8, field)?;
        Ok(u64::from_le_bytes(
            bytes.try_into().expect("u64 read length"),
        ))
    }

    fn read_bytes(&mut self, field: &'static str) -> Result<Vec<u8>, SyncError> {
        let length = usize::try_from(self.read_u32(field)?)
            .map_err(|_| wallet_artifact_format(format!("{field} length overflows usize")))?;
        Ok(self.read_exact(length, field)?.to_vec())
    }

    fn read_fixed_32(&mut self, field: &'static str) -> Result<[u8; 32], SyncError> {
        self.read_exact(32, field)?
            .try_into()
            .map_err(|_| wallet_artifact_format(format!("invalid fixed bytes in {field}")))
    }

    fn read_fixed_64(&mut self, field: &'static str) -> Result<[u8; 64], SyncError> {
        self.read_exact(64, field)?
            .try_into()
            .map_err(|_| wallet_artifact_format(format!("invalid fixed bytes in {field}")))
    }

    fn read_exact(&mut self, length: usize, field: &'static str) -> Result<&'a [u8], SyncError> {
        let end = self.position.checked_add(length).ok_or_else(|| {
            wallet_artifact_format(format!("wallet_scan artifact overflow in {field}"))
        })?;
        let value = self.bytes.get(self.position..end).ok_or_else(|| {
            wallet_artifact_format(format!("wallet_scan artifact ended while reading {field}"))
        })?;
        self.position = end;
        Ok(value)
    }

    fn expect_eof(&self, field: &'static str) -> Result<(), SyncError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(wallet_artifact_format(format!(
                "{field} has {} trailing bytes",
                self.bytes.len().saturating_sub(self.position)
            )))
        }
    }
}

fn wallet_artifact_error(err: IndexedArtifactManifestError) -> SyncError {
    wallet_artifact_format(err.to_string())
}

fn wallet_artifact_format(message: impl Into<String>) -> SyncError {
    SyncError::UnexpectedFormat(format!("indexed wallet artifact: {}", message.into()))
}

pub(super) fn complete_stream_checkpoint<I>(
    row_count: usize,
    page_size: usize,
    target_block: u64,
    block_numbers: I,
) -> u64
where
    I: Iterator<Item = u64>,
{
    if row_count < page_size {
        return target_block;
    }
    block_numbers
        .max()
        .unwrap_or(target_block)
        .saturating_sub(1)
}

pub(super) fn wallet_backfill_from_block(last_scanned: u64, start_block: u64) -> u64 {
    last_scanned.saturating_add(1).max(start_block)
}

pub(super) fn wallet_reorg_backfill_from_block(reset_from_block: u64, start_block: u64) -> u64 {
    reset_from_block.max(start_block)
}

pub(super) fn wallet_sync_target(safe_head: u64, sync_to_block: Option<u64>) -> u64 {
    match sync_to_block {
        Some(sync_to_block) if safe_head == 0 => sync_to_block,
        Some(sync_to_block) => sync_to_block.min(safe_head),
        None => safe_head,
    }
}

pub(super) const fn squid_tail_target_after_artifact(
    from_block: u64,
    artifact_target: u64,
    safe_head: u64,
    squid_height: u64,
) -> Option<u64> {
    if artifact_target >= safe_head {
        return None;
    }
    let target = if squid_height < safe_head {
        squid_height
    } else {
        safe_head
    };
    if from_block <= target {
        Some(target)
    } else {
        None
    }
}

pub(super) fn wallet_startup_hedge_block_count(
    last_scanned: u64,
    start_block: u64,
    sync_target: u64,
) -> Option<u64> {
    if sync_target == 0 {
        return None;
    }
    let from_block = wallet_backfill_from_block(last_scanned, start_block);
    if from_block > sync_target {
        return None;
    }
    Some(sync_target.saturating_sub(from_block).saturating_add(1))
}

pub(super) fn should_hedge_wallet_startup(
    last_scanned: u64,
    start_block: u64,
    sync_target: u64,
    block_range: u64,
    indexed_artifact_source_configured: bool,
) -> bool {
    !indexed_artifact_source_configured
        && block_range > 0
        && wallet_startup_hedge_block_count(last_scanned, start_block, sync_target)
            .is_some_and(|block_count| block_count <= block_range)
}

pub(super) async fn wait_or_cancel<T>(
    cancel: &CancellationToken,
    future: impl Future<Output = T>,
) -> Result<T, WalletStartupSyncError> {
    tokio::select! {
        result = future => Ok(result),
        _ = cancel.cancelled() => Err(WalletStartupSyncError::Cancelled),
    }
}

pub(super) async fn send_wallet_startup_events(
    cache_key: &str,
    applies: Vec<WalletScanApply>,
    done_block: Option<u64>,
    reset_generation: u64,
    sender: &mpsc::Sender<BackfillEvent>,
    handle: &WalletHandle,
) -> bool {
    let token = handle.mint_sync_token(reset_generation);
    let target_block =
        done_block.unwrap_or_else(|| applies.last().map_or(0, |apply| apply.to_block));
    if target_block > 0 {
        let target_result = send_wallet_target(cache_key, sender, target_block, token).await;
        if matches!(target_result, WalletBackfillFinishResult::Ready { .. }) {
            return true;
        }
        if !matches!(target_result, WalletBackfillFinishResult::Accepted { .. }) {
            send_wallet_job_retired(cache_key, sender, token).await;
            return false;
        }
    }
    for apply in applies {
        let result = send_wallet_scan_apply(cache_key, sender, apply, token).await;
        match result {
            WalletBackfillApplyResult::Committed { .. }
            | WalletBackfillApplyResult::AlreadyCovered { .. } => {}
            WalletBackfillApplyResult::Rejected { reason, .. } => {
                debug!(?reason, cache_key, "wallet startup scan batch rejected");
                send_wallet_job_retired(cache_key, sender, token).await;
                return false;
            }
        }
    }
    if let Some(last_block) = done_block
        && !matches!(
            send_wallet_target(cache_key, sender, last_block, token).await,
            WalletBackfillFinishResult::Ready { .. }
        )
    {
        debug!(cache_key, last_block, "wallet startup finish rejected");
        send_wallet_job_retired(cache_key, sender, token).await;
        return false;
    }
    if done_block.is_none() && target_block > 0 {
        send_wallet_job_retired(cache_key, sender, token).await;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    use crate::indexed_artifacts::{
        CompressionAlgorithm, DatasetDescriptorMetadata, INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION,
        INDEXED_ARTIFACT_CHUNK_MAGIC, IndexedArtifactChainEntry, IndexedArtifactDescriptor,
        LatestIndexedHeight, PublisherIdentity,
    };
    use alloy::primitives::{Address, FixedBytes, Uint};
    use alloy::sol_types::SolValue;
    use broadcaster_core::contracts::railgun::TokenData;
    use broadcaster_core::crypto::railgun::ViewingKeyData;
    use sha2::{Digest, Sha256};

    #[test]
    fn indexed_wallet_artifact_probe_accepts_latest_covering_range() {
        let scope = scope();
        let manifest = manifest_with_latest_and_catalog(
            scope.clone(),
            200,
            Some(IndexedArtifactRange {
                kind: IndexedArtifactRangeKind::Block,
                start: 100,
                end: 150,
            }),
        );

        let probe = IndexedWalletArtifactProbe::from_manifest(&manifest, &scope, 120, 180)
            .expect("wallet scan artifacts available");

        assert_eq!(probe.latest_indexed_block, 200);
        assert_eq!(probe.catalog_count, 1);
    }

    #[test]
    fn indexed_wallet_artifact_probe_accepts_latest_below_safe_head() {
        let scope = scope();
        let manifest = manifest_with_latest_and_catalog(
            scope.clone(),
            149,
            Some(IndexedArtifactRange {
                kind: IndexedArtifactRangeKind::Block,
                start: 100,
                end: 149,
            }),
        );

        let probe = IndexedWalletArtifactProbe::from_manifest(&manifest, &scope, 120, 180)
            .expect("partial wallet scan artifacts available");

        assert_eq!(probe.latest_indexed_block, 149);
        assert_eq!(probe.catalog_count, 1);
    }

    #[test]
    fn indexed_wallet_artifact_probe_rejects_latest_without_matching_catalog() {
        let scope = scope();
        let manifest = manifest_with_latest_and_catalog(scope.clone(), 149, None);

        let probe = IndexedWalletArtifactProbe::from_manifest(&manifest, &scope, 120, 180);

        assert_eq!(probe, None);
    }

    #[test]
    fn indexed_wallet_artifact_probe_rejects_latest_below_start() {
        let scope = scope();
        let manifest = manifest_with_latest_and_catalog(scope.clone(), 119, None);

        let probe = IndexedWalletArtifactProbe::from_manifest(&manifest, &scope, 120, 180);

        assert_eq!(probe, None);
    }

    #[test]
    fn indexed_wallet_artifact_probe_rejects_missing_scope() {
        let manifest = manifest_with_latest_and_catalog(scope(), 200, None);
        let missing_scope = ChainScope {
            chain_type: ChainType::Evm,
            chain_id: 137,
            railgun_contract: Address::from([0xcc; 20]),
        };

        let probe = IndexedWalletArtifactProbe::from_manifest(&manifest, &missing_scope, 120, 180);

        assert_eq!(probe, None);
    }

    #[test]
    fn indexed_wallet_artifact_page_decodes_rows_for_existing_scan_path() {
        let scope = scope();
        let nullifier = [0x42; 32];
        let legacy_random = std::array::from_fn(|index| index as u8);
        let chunk = wallet_scan_chunk(
            scope,
            100,
            110,
            vec![
                (
                    WALLET_NULLIFIER_SECTION_ID,
                    nullifier_section(105, 7, nullifier),
                ),
                (
                    WALLET_LEGACY_GENERATED_SECTION_ID,
                    legacy_generated_section(106, 3, 9, legacy_random),
                ),
            ],
            2,
        );

        let page = IndexedWalletPage::try_from(&chunk).expect("decode page");

        assert_eq!(page.checkpoint_block, 110);
        assert_eq!(page.nullifier_rows, 1);
        assert_eq!(page.legacy_generated_rows, 1);
        assert_eq!(page.nullifiers[0].tree_number, 7);
        assert_eq!(page.nullifiers[0].nullifier, U256::from_be_bytes(nullifier));
        assert_eq!(page.nullifiers[0].source.block_number, 105);
        assert_eq!(page.legacy_generated_commitments[0].tree_number, 3);
        assert_eq!(page.legacy_generated_commitments[0].tree_position, 9);
        assert_eq!(
            page.legacy_generated_commitments[0].encrypted_random.0,
            AlloyFixedBytes::from(<[u8; 32]>::try_from(&legacy_random[..32]).expect("first word"))
        );
        assert_eq!(
            page.legacy_generated_commitments[0].encrypted_random.1,
            AlloyFixedBytes::from(
                <[u8; 16]>::try_from(&legacy_random[48..64]).expect("second word suffix")
            )
        );

        let keys = ViewingKeyData::from_spending_public_key([1; 32], [U256::ZERO; 2]);
        let delta = parse_indexed_wallet_delta(
            &page.transact_commitments,
            &page.shield_commitments,
            &page.legacy_encrypted_commitments,
            &page.legacy_generated_commitments,
            &page.nullifiers,
            &keys,
        );

        assert_eq!(delta.nullifiers.len(), 1);
        assert_eq!(delta.nullifiers[0].tree, 7);
        assert_eq!(
            delta.nullifiers[0].nullifier,
            U256::from_be_bytes(nullifier)
        );
        assert_eq!(delta.commitment_observations.len(), 1);
        assert_eq!(delta.commitment_observations[0].tree, 3);
        assert_eq!(delta.commitment_observations[0].position, 9);
    }

    #[test]
    fn indexed_wallet_artifact_page_rejects_row_count_mismatch() {
        let chunk = wallet_scan_chunk(
            scope(),
            100,
            110,
            vec![(
                WALLET_NULLIFIER_SECTION_ID,
                nullifier_section(105, 7, [0x42; 32]),
            )],
            2,
        );

        let Err(error) = IndexedWalletPage::try_from(&chunk) else {
            panic!("row count mismatch should fail");
        };

        assert!(
            matches!(error, SyncError::UnexpectedFormat(message) if message.contains("row count mismatch"))
        );
    }

    #[test]
    fn indexed_wallet_artifact_page_rejects_duplicate_section_id() {
        let chunk = wallet_scan_chunk(
            scope(),
            100,
            110,
            vec![
                (
                    WALLET_NULLIFIER_SECTION_ID,
                    nullifier_section(105, 7, [0x42; 32]),
                ),
                (
                    WALLET_NULLIFIER_SECTION_ID,
                    nullifier_section(106, 8, [0x43; 32]),
                ),
            ],
            2,
        );

        let Err(error) = IndexedWalletPage::try_from(&chunk) else {
            panic!("duplicate wallet_scan section id should fail");
        };

        assert!(
            matches!(error, SyncError::UnexpectedFormat(message) if message.contains("appears more than once"))
        );
    }

    #[test]
    fn indexed_wallet_artifact_page_rejects_out_of_range_source_block() {
        let chunk = wallet_scan_chunk(
            scope(),
            100,
            110,
            vec![(
                WALLET_NULLIFIER_SECTION_ID,
                nullifier_section(111, 7, [0x42; 32]),
            )],
            1,
        );

        let error = match IndexedWalletPage::try_from(&chunk) {
            Ok(_) => panic!("out-of-range wallet_scan source should fail"),
            Err(error) => error,
        };

        assert!(
            matches!(error, SyncError::UnexpectedFormat(message) if message.contains("outside chunk block range"))
        );
    }

    #[test]
    fn indexed_wallet_artifact_page_rejects_extreme_section_count_without_allocation() {
        let mut section = Vec::new();
        write_u64(&mut section, u64::MAX);
        let chunk = wallet_scan_chunk(
            scope(),
            100,
            110,
            vec![(WALLET_NULLIFIER_SECTION_ID, section)],
            u64::MAX,
        );

        let error = match IndexedWalletPage::try_from(&chunk) {
            Ok(_) => panic!("extreme section row count should fail as a format error"),
            Err(error) => error,
        };

        assert!(
            matches!(error, SyncError::UnexpectedFormat(message) if message.contains("ended while reading source block_number"))
        );
    }

    #[test]
    fn indexed_wallet_artifact_page_accepts_fully_sparse_requested_range() {
        let session = artifact_session_with_coverage(200, Vec::new(), &[(100, 200)]);

        let page = session
            .page_for_block_range(100, 200)
            .expect("fully sparse range should decode")
            .expect("latest indexed block covers range");

        assert_eq!(page.checkpoint_block, 200);
        assert_eq!(page.transact_rows, 0);
        assert_eq!(page.shield_rows, 0);
        assert_eq!(page.legacy_encrypted_rows, 0);
        assert_eq!(page.legacy_generated_rows, 0);
        assert_eq!(page.nullifier_rows, 0);
    }

    #[test]
    fn indexed_wallet_artifact_page_rejects_unproven_empty_requested_range() {
        let session = artifact_session(200, Vec::new());

        let error = match session.page_for_block_range(100, 200) {
            Ok(_) => panic!("unproven empty artifact coverage should fail"),
            Err(error) => error,
        };

        assert!(
            matches!(error, SyncError::UnexpectedFormat(message) if message.contains("coverage does not include"))
        );
    }

    #[test]
    fn indexed_wallet_artifact_page_accepts_sparse_requested_prefix_and_suffix() {
        let chunk = wallet_scan_chunk(
            scope(),
            150,
            180,
            vec![(
                WALLET_NULLIFIER_SECTION_ID,
                nullifier_section(175, 7, [0x42; 32]),
            )],
            1,
        );
        let session = artifact_session_with_coverage(200, vec![chunk], &[(100, 200)]);

        let page = session
            .page_for_block_range(100, 200)
            .expect("sparse prefix and suffix should decode")
            .expect("latest indexed block covers range");

        assert_eq!(page.checkpoint_block, 200);
        assert_eq!(page.nullifier_rows, 1);
        assert_eq!(page.nullifiers[0].source.block_number, 175);
    }

    #[test]
    fn indexed_wallet_artifact_page_accepts_sparse_gap_between_chunks() {
        let first_chunk = wallet_scan_chunk(
            scope(),
            100,
            110,
            vec![(
                WALLET_NULLIFIER_SECTION_ID,
                nullifier_section(105, 7, [0x11; 32]),
            )],
            1,
        );
        let second_chunk = wallet_scan_chunk(
            scope(),
            150,
            160,
            vec![(
                WALLET_NULLIFIER_SECTION_ID,
                nullifier_section(155, 7, [0x22; 32]),
            )],
            1,
        );
        let session =
            artifact_session_with_coverage(160, vec![first_chunk, second_chunk], &[(100, 160)]);

        let page = session
            .page_for_block_range(100, 160)
            .expect("sparse gap should decode")
            .expect("latest indexed block covers range");

        assert_eq!(page.checkpoint_block, 160);
        assert_eq!(page.nullifier_rows, 2);
        assert_eq!(page.nullifiers[0].source.block_number, 105);
        assert_eq!(page.nullifiers[1].source.block_number, 155);
    }

    #[test]
    fn indexed_wallet_artifact_page_stops_before_unproven_sparse_gap() {
        let first_chunk = wallet_scan_chunk(
            scope(),
            100,
            110,
            vec![(
                WALLET_NULLIFIER_SECTION_ID,
                nullifier_section(105, 7, [0x11; 32]),
            )],
            1,
        );
        let second_chunk = wallet_scan_chunk(
            scope(),
            150,
            160,
            vec![(
                WALLET_NULLIFIER_SECTION_ID,
                nullifier_section(155, 7, [0x22; 32]),
            )],
            1,
        );
        let session = artifact_session(160, vec![first_chunk, second_chunk]);

        let page = session
            .page_for_block_range(100, 160)
            .expect("page should stop before unproven coverage gap")
            .expect("latest indexed block covers range");

        assert_eq!(page.checkpoint_block, 110);
        assert_eq!(page.nullifier_rows, 1);
        assert_eq!(page.nullifiers[0].source.block_number, 105);
    }

    #[test]
    fn indexed_wallet_artifact_selection_uses_current_replacement_tail() {
        let scope = scope();
        let old_tail = with_catalog_generation(
            wallet_scan_chunk(
                scope.clone(),
                100,
                110,
                vec![(
                    WALLET_NULLIFIER_SECTION_ID,
                    nullifier_section(105, 7, [0x11; 32]),
                )],
                1,
            ),
            1,
        );
        let current_tail = with_catalog_generation(
            wallet_scan_chunk(
                scope,
                100,
                120,
                vec![(
                    WALLET_NULLIFIER_SECTION_ID,
                    nullifier_section(115, 7, [0x22; 32]),
                )],
                1,
            ),
            2,
        );

        let selected = selected_wallet_scan_chunks(&[old_tail, current_tail], 100, 120)
            .expect("select required current chunks");
        let session = artifact_session(120, selected);
        let page = session
            .page_for_block_range(100, 120)
            .expect("current tail page should decode")
            .expect("latest indexed block covers range");

        assert_eq!(page.nullifier_rows, 1);
        assert_eq!(page.nullifiers[0].source.block_number, 115);
        assert_eq!(
            page.nullifiers[0].nullifier,
            U256::from_be_bytes([0x22; 32])
        );
    }

    #[test]
    fn indexed_wallet_artifact_empty_catalog_suppresses_stale_replacement_tail() {
        let scope = scope();
        let old_tail = with_catalog_generation(
            wallet_scan_chunk(
                scope.clone(),
                100,
                110,
                vec![(
                    WALLET_NULLIFIER_SECTION_ID,
                    nullifier_section(105, 7, [0x11; 32]),
                )],
                1,
            ),
            1,
        );
        let catalogs = vec![
            wallet_scan_catalog(1, vec![old_tail.descriptor.clone()]),
            empty_wallet_scan_catalog(scope.clone(), 2, 100, 110),
        ];

        let plan =
            IndexedWalletArtifactSession::select_current_stream_plan(&catalogs, &scope, 100, 110)
                .expect("empty replacement catalog should plan");
        assert!(plan.required_current_chunks.is_empty());

        let session = IndexedWalletArtifactSession {
            probe: IndexedWalletArtifactProbe {
                latest_indexed_block: 110,
                catalog_count: catalogs.len(),
            },
            chunk_descriptors: plan.required_current_chunks,
            chunks: Vec::new(),
            coverage: WalletScanArtifactCoverage::from_descriptors(&plan.required_current_coverage)
                .expect("planner coverage"),
            read_scope: test_public_scan_read_scope(),
        };
        let page = session
            .page_for_block_range(100, 110)
            .expect("empty current page should decode")
            .expect("latest indexed block covers range");

        assert_eq!(page.checkpoint_block, 110);
        assert_eq!(page.nullifier_rows, 0);
        assert!(page.nullifiers.is_empty());
    }

    #[test]
    fn indexed_wallet_artifact_selection_rejects_stable_consolidation() {
        let scope = scope();
        let sealed_prefix = with_catalog_generation(
            wallet_scan_chunk(
                scope.clone(),
                100,
                110,
                vec![(
                    WALLET_NULLIFIER_SECTION_ID,
                    nullifier_section(105, 7, [0x11; 32]),
                )],
                1,
            ),
            1,
        );
        let generation_tail = with_catalog_generation(
            wallet_scan_chunk(
                scope.clone(),
                111,
                120,
                vec![(
                    WALLET_NULLIFIER_SECTION_ID,
                    nullifier_section(115, 7, [0x22; 32]),
                )],
                1,
            ),
            1,
        );
        let consolidated = with_catalog_generation(
            wallet_scan_chunk(
                scope,
                100,
                120,
                vec![(
                    WALLET_NULLIFIER_SECTION_ID,
                    nullifier_section(115, 7, [0x33; 32]),
                )],
                1,
            ),
            2,
        );

        let error =
            selected_wallet_scan_chunks(&[sealed_prefix, generation_tail, consolidated], 100, 120)
                .expect_err("stable consolidation should fail");

        assert!(
            matches!(error, SyncError::UnexpectedFormat(message) if message.contains("stable chunk"))
        );
    }

    #[test]
    fn indexed_wallet_artifact_selection_rejects_sealed_tail_replacement() {
        let scope = scope();
        let sealed_tail = with_chunk_sealed(with_catalog_generation(
            wallet_scan_chunk(
                scope.clone(),
                100,
                110,
                vec![(
                    WALLET_NULLIFIER_SECTION_ID,
                    nullifier_section(105, 7, [0x11; 32]),
                )],
                1,
            ),
            1,
        ));
        let replacement = with_catalog_generation(
            wallet_scan_chunk(
                scope,
                100,
                120,
                vec![(
                    WALLET_NULLIFIER_SECTION_ID,
                    nullifier_section(115, 7, [0x22; 32]),
                )],
                1,
            ),
            2,
        );

        let error = selected_wallet_scan_chunks(&[sealed_tail, replacement], 100, 120)
            .expect_err("sealed tail replacement should fail");

        assert!(
            matches!(error, SyncError::UnexpectedFormat(message) if message.contains("stable chunk"))
        );
    }

    #[test]
    fn indexed_wallet_artifact_selection_rejects_complete_stream_extension() {
        let scope = scope();
        let complete_tail = with_stream_complete(with_catalog_generation(
            wallet_scan_chunk(
                scope.clone(),
                100,
                110,
                vec![(
                    WALLET_NULLIFIER_SECTION_ID,
                    nullifier_section(105, 7, [0x11; 32]),
                )],
                1,
            ),
            1,
        ));
        let extension = with_catalog_generation(
            wallet_scan_chunk(
                scope,
                111,
                120,
                vec![(
                    WALLET_NULLIFIER_SECTION_ID,
                    nullifier_section(115, 7, [0x22; 32]),
                )],
                1,
            ),
            2,
        );

        let error = selected_wallet_scan_chunks(&[complete_tail, extension], 100, 120)
            .expect_err("complete stream extension should fail");

        assert!(
            matches!(error, SyncError::UnexpectedFormat(message) if message.contains("complete tail"))
        );
    }

    #[test]
    fn indexed_wallet_artifact_page_rejects_source_after_checkpoint() {
        let chunk = with_checkpoint_block(
            wallet_scan_chunk(
                scope(),
                100,
                110,
                vec![(
                    WALLET_NULLIFIER_SECTION_ID,
                    nullifier_section(106, 7, [0x42; 32]),
                )],
                1,
            ),
            105,
        );

        let error = match IndexedWalletPage::try_from(&chunk) {
            Ok(_) => panic!("post-checkpoint wallet_scan source should fail"),
            Err(error) => error,
        };

        assert!(
            matches!(error, SyncError::UnexpectedFormat(message) if message.contains("exceeds checkpoint"))
        );
    }

    #[test]
    fn indexed_wallet_artifact_page_stops_at_checkpointed_chunk() {
        let chunk = with_checkpoint_block(
            wallet_scan_chunk(
                scope(),
                100,
                110,
                vec![(
                    WALLET_NULLIFIER_SECTION_ID,
                    nullifier_section(104, 7, [0x42; 32]),
                )],
                1,
            ),
            105,
        );
        let session = artifact_session(110, vec![chunk]);

        let page = session
            .page_for_block_range(100, 110)
            .expect("checkpointed page should decode")
            .expect("latest indexed block covers range");

        assert_eq!(page.checkpoint_block, 105);
        assert_eq!(page.nullifier_rows, 1);
        assert_eq!(page.nullifiers[0].source.block_number, 104);
    }

    #[test]
    fn indexed_wallet_artifact_page_returns_exhaustion_after_open_tail_checkpoint() {
        let chunk = with_checkpoint_block(
            wallet_scan_chunk(
                scope(),
                100,
                200,
                vec![(
                    WALLET_NULLIFIER_SECTION_ID,
                    nullifier_section(140, 7, [0x42; 32]),
                )],
                1,
            ),
            150,
        );
        let session = artifact_session(200, vec![chunk]);

        let first_page = session
            .page_for_block_range(100, 200)
            .expect("checkpointed page should decode")
            .expect("latest indexed block covers range");
        assert_eq!(first_page.checkpoint_block, 150);

        let next_page = session
            .page_for_block_range(151, 200)
            .expect("open tail after checkpoint should not be a format error");
        assert!(matches!(
            next_page,
            IndexedWalletArtifactPageOutcome::Exhausted {
                checkpoint_block: 150,
            }
        ));
    }

    #[test]
    fn indexed_wallet_artifact_page_rejects_checkpoint_before_chunk_range() {
        let chunk = with_checkpoint_block(
            wallet_scan_chunk(
                scope(),
                100,
                110,
                vec![(
                    WALLET_NULLIFIER_SECTION_ID,
                    nullifier_section(105, 7, [0x42; 32]),
                )],
                1,
            ),
            90,
        );

        let error = match IndexedWalletPage::try_from(&chunk) {
            Ok(_) => panic!("pre-range checkpoint should fail"),
            Err(error) => error,
        };

        assert!(
            matches!(error, SyncError::UnexpectedFormat(message) if message.contains("before range start"))
        );
    }

    #[test]
    fn indexed_wallet_artifact_page_decodes_only_requested_chunk_range() {
        let valid_chunk = wallet_scan_chunk(
            scope(),
            100,
            110,
            vec![(
                WALLET_NULLIFIER_SECTION_ID,
                nullifier_section(105, 7, [0x11; 32]),
            )],
            1,
        );
        let invalid_later_chunk = wallet_scan_chunk(
            scope(),
            150,
            160,
            vec![(
                WALLET_NULLIFIER_SECTION_ID,
                nullifier_section(161, 7, [0x22; 32]),
            )],
            1,
        );
        let session = artifact_session(160, vec![valid_chunk, invalid_later_chunk]);

        let page = session
            .page_for_block_range(100, 110)
            .expect("first page should not decode later chunk")
            .expect("latest indexed block covers range");

        assert_eq!(page.checkpoint_block, 110);
        assert_eq!(page.nullifier_rows, 1);
        assert_eq!(page.nullifiers[0].source.block_number, 105);
    }

    fn manifest_with_latest_and_catalog(
        scope: ChainScope,
        latest_block: u64,
        catalog_range: Option<IndexedArtifactRange>,
    ) -> IndexedArtifactManifest {
        let catalogs = catalog_range
            .map(|range| {
                let range_end = range.end;
                vec![IndexedArtifactDescriptor {
                    dataset_kind: IndexedDatasetKind::WalletScan,
                    scope: scope.clone(),
                    range,
                    row_count: 42,
                    cid: "bafywalletscan".to_string(),
                    sha256: FixedBytes::from([0x11; 32]),
                    byte_size: 1234,
                    encoding_version: INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION,
                    compression: CompressionAlgorithm::Zstd,
                    metadata: DatasetDescriptorMetadata {
                        catalog_generation: Some(1),
                        checkpoint_block: Some(range_end),
                        ..Default::default()
                    },
                }]
            })
            .unwrap_or_default();
        IndexedArtifactManifest::new(
            1_700_000_000_000,
            1,
            PublisherIdentity::ed25519(FixedBytes::from([0x11; 32])),
            vec![IndexedArtifactChainEntry {
                scope,
                latest_indexed: vec![LatestIndexedHeight {
                    dataset_kind: IndexedDatasetKind::WalletScan,
                    block_number: latest_block,
                    block_hash: FixedBytes::from([0x22; 32]),
                }],
                catalogs,
            }],
        )
    }

    fn scope() -> ChainScope {
        ChainScope {
            chain_type: ChainType::Evm,
            chain_id: 1,
            railgun_contract: Address::from([0xbb; 20]),
        }
    }

    fn wallet_scan_chunk(
        scope: ChainScope,
        start: u64,
        end: u64,
        sections: Vec<(u16, Vec<u8>)>,
        row_count: u64,
    ) -> VerifiedIndexedArtifactChunk {
        let mut payload = Vec::new();
        let mut section_headers = Vec::new();
        for (section_id, section_payload) in sections {
            let offset = u64::try_from(payload.len()).expect("section offset");
            payload.extend(section_payload);
            let byte_length = u64::try_from(payload.len()).expect("section end") - offset;
            section_headers.push((section_id, offset, byte_length));
        }

        let mut bytes = Vec::new();
        bytes.extend_from_slice(INDEXED_ARTIFACT_CHUNK_MAGIC);
        write_u16(&mut bytes, INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION);
        bytes.push(0);
        bytes.push(0);
        write_u64(&mut bytes, scope.chain_id);
        write_string(
            &mut bytes,
            &format!(
                "0x{}",
                alloy::hex::encode(scope.railgun_contract.as_slice())
            ),
        );
        bytes.push(0);
        write_u64(&mut bytes, start);
        write_u64(&mut bytes, end);
        write_u64(&mut bytes, row_count);
        write_u64(
            &mut bytes,
            u64::try_from(payload.len()).expect("payload len"),
        );
        write_u16(
            &mut bytes,
            u16::try_from(section_headers.len()).expect("section count"),
        );
        for (section_id, offset, byte_length) in section_headers {
            write_u16(&mut bytes, section_id);
            write_u64(&mut bytes, offset);
            write_u64(&mut bytes, byte_length);
        }
        bytes.extend(payload);

        let descriptor = IndexedArtifactDescriptor {
            dataset_kind: IndexedDatasetKind::WalletScan,
            scope,
            range: IndexedArtifactRange {
                kind: IndexedArtifactRangeKind::Block,
                start,
                end,
            },
            row_count,
            cid: "bafywalletchunk".to_string(),
            sha256: prefixed_sha256(&bytes),
            byte_size: u64::try_from(bytes.len()).expect("chunk byte size"),
            encoding_version: INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION,
            compression: CompressionAlgorithm::None,
            metadata: DatasetDescriptorMetadata {
                catalog_generation: Some(1),
                checkpoint_block: Some(end),
                ..Default::default()
            },
        };
        VerifiedIndexedArtifactChunk { descriptor, bytes }
    }

    fn artifact_session(
        latest_indexed_block: u64,
        chunks: Vec<VerifiedIndexedArtifactChunk>,
    ) -> IndexedWalletArtifactSession {
        let mut chunk_descriptors = Vec::new();
        let mut indexed_chunks = Vec::new();
        let mut coverage = WalletScanArtifactCoverage::default();
        for (index, chunk) in chunks.into_iter().enumerate() {
            let descriptor = chunk.descriptor.clone();
            let range = descriptor.range.clone();
            coverage
                .add_descriptor(&descriptor)
                .expect("wallet scan test chunk coverage");
            chunk_descriptors.push(descriptor);
            indexed_chunks.push(IndexedWalletArtifactChunk {
                descriptor_index: index,
                range,
                chunk,
            });
        }
        IndexedWalletArtifactSession {
            probe: IndexedWalletArtifactProbe {
                latest_indexed_block,
                catalog_count: chunk_descriptors.len(),
            },
            chunk_descriptors,
            chunks: indexed_chunks,
            coverage,
            read_scope: test_public_scan_read_scope(),
        }
    }

    fn artifact_session_with_coverage(
        latest_indexed_block: u64,
        chunks: Vec<VerifiedIndexedArtifactChunk>,
        ranges: &[(u64, u64)],
    ) -> IndexedWalletArtifactSession {
        let mut session = artifact_session(latest_indexed_block, chunks);
        session.probe.catalog_count = ranges.len();
        session.coverage = coverage_from_ranges(ranges);
        session
    }

    const fn test_public_scan_read_scope() -> PublicScanReadScope {
        PublicScanReadScope::new(PublicDataPlaneEpoch::new(0))
    }

    fn coverage_from_ranges(ranges: &[(u64, u64)]) -> WalletScanArtifactCoverage {
        let mut coverage = WalletScanArtifactCoverage::default();
        coverage
            .ranges
            .extend(ranges.iter().map(|(start, end)| WalletScanCoverageRange {
                start: *start,
                end: *end,
                checkpoint_block: *end,
            }));
        coverage
            .ranges
            .sort_by_key(|range| (range.start, range.end));
        coverage
    }

    fn selected_wallet_scan_chunks(
        chunks: &[VerifiedIndexedArtifactChunk],
        from_block: u64,
        target_block: u64,
    ) -> Result<Vec<VerifiedIndexedArtifactChunk>, SyncError> {
        let scope = chunks
            .first()
            .expect("at least one wallet scan chunk")
            .descriptor
            .scope
            .clone();
        let catalogs = stream_catalogs_for_chunks(chunks);
        let selected = IndexedWalletArtifactSession::select_current_stream_plan(
            &catalogs,
            &scope,
            from_block,
            target_block,
        )?
        .required_current_chunks;
        Ok(selected
            .into_iter()
            .map(|descriptor| {
                chunks
                    .iter()
                    .find(|chunk| chunk.descriptor == descriptor)
                    .expect("selected descriptor has chunk bytes")
                    .clone()
            })
            .collect())
    }

    fn stream_catalogs_for_chunks(
        chunks: &[VerifiedIndexedArtifactChunk],
    ) -> Vec<IndexedArtifactStreamCatalog> {
        let mut by_generation = BTreeMap::<u64, Vec<IndexedArtifactDescriptor>>::new();
        for chunk in chunks {
            let generation = chunk
                .descriptor
                .metadata
                .catalog_generation
                .expect("test chunk generation");
            by_generation
                .entry(generation)
                .or_default()
                .push(chunk.descriptor.clone());
        }
        by_generation
            .into_iter()
            .map(|(generation, chunks)| wallet_scan_catalog(generation, chunks))
            .collect()
    }

    fn wallet_scan_catalog(
        generation: u64,
        chunks: Vec<IndexedArtifactDescriptor>,
    ) -> IndexedArtifactStreamCatalog {
        let first = chunks.first().expect("wallet scan test catalog chunk");
        let start = chunks
            .iter()
            .map(|chunk| chunk.range.start)
            .min()
            .expect("catalog start");
        let end = chunks
            .iter()
            .map(|chunk| chunk.range.end)
            .max()
            .expect("catalog end");
        let row_count = chunks
            .iter()
            .map(|chunk| chunk.row_count)
            .fold(0_u64, u64::saturating_add);
        let mut descriptor = first.clone();
        descriptor.range.start = start;
        descriptor.range.end = end;
        descriptor.row_count = row_count;
        descriptor.cid = format!("bafywalletcatalog-{generation}-{start}-{end}");
        descriptor.metadata.catalog_generation = Some(generation);
        descriptor.metadata.checkpoint_block = Some(end);
        IndexedArtifactStreamCatalog::new(descriptor, chunks)
    }

    fn empty_wallet_scan_catalog(
        scope: ChainScope,
        generation: u64,
        start: u64,
        end: u64,
    ) -> IndexedArtifactStreamCatalog {
        let descriptor = IndexedArtifactDescriptor {
            dataset_kind: IndexedDatasetKind::WalletScan,
            scope,
            range: IndexedArtifactRange {
                kind: IndexedArtifactRangeKind::Block,
                start,
                end,
            },
            row_count: 0,
            cid: format!("bafywalletcatalog-empty-{generation}-{start}-{end}"),
            sha256: FixedBytes::from([0xee; 32]),
            byte_size: 0,
            encoding_version: INDEXED_ARTIFACT_CHUNK_FORMAT_VERSION,
            compression: CompressionAlgorithm::Zstd,
            metadata: DatasetDescriptorMetadata {
                catalog_generation: Some(generation),
                checkpoint_block: Some(end),
                ..Default::default()
            },
        };
        IndexedArtifactStreamCatalog::new(descriptor, Vec::new())
    }

    fn with_catalog_generation(
        mut chunk: VerifiedIndexedArtifactChunk,
        generation: u64,
    ) -> VerifiedIndexedArtifactChunk {
        chunk.descriptor.metadata.catalog_generation = Some(generation);
        chunk
    }

    fn with_checkpoint_block(
        mut chunk: VerifiedIndexedArtifactChunk,
        checkpoint_block: u64,
    ) -> VerifiedIndexedArtifactChunk {
        chunk.descriptor.metadata.checkpoint_block = Some(checkpoint_block);
        chunk
    }

    fn with_chunk_sealed(mut chunk: VerifiedIndexedArtifactChunk) -> VerifiedIndexedArtifactChunk {
        chunk.descriptor.metadata.chunk_sealed = true;
        chunk
    }

    fn with_stream_complete(
        mut chunk: VerifiedIndexedArtifactChunk,
    ) -> VerifiedIndexedArtifactChunk {
        chunk.descriptor.metadata.stream_complete = true;
        chunk
    }

    fn nullifier_section(block_number: u64, tree_number: u32, nullifier: [u8; 32]) -> Vec<u8> {
        let mut bytes = Vec::new();
        write_u64(&mut bytes, 1);
        write_source(&mut bytes, block_number, 1);
        write_u32(&mut bytes, tree_number);
        bytes.extend_from_slice(&nullifier);
        bytes
    }

    fn legacy_generated_section(
        block_number: u64,
        tree_number: u32,
        tree_position: u64,
        encrypted_random: [u8; 64],
    ) -> Vec<u8> {
        let preimage = LegacyCommitmentPreimage {
            npk: U256::from(1),
            token: TokenData {
                tokenType: 0,
                tokenAddress: Address::ZERO,
                tokenSubID: U256::ZERO,
            },
            value: Uint::<120, 2>::from(1),
        };
        let mut bytes = Vec::new();
        write_u64(&mut bytes, 1);
        write_source(&mut bytes, block_number, 2);
        write_u32(&mut bytes, tree_number);
        write_u64(&mut bytes, tree_position);
        bytes.extend_from_slice(&[0x33; 32]);
        write_bytes(&mut bytes, &preimage.abi_encode());
        bytes.extend_from_slice(&encrypted_random);
        bytes
    }

    fn write_source(bytes: &mut Vec<u8>, block_number: u64, log_index: u64) {
        write_u64(bytes, block_number);
        write_u64(bytes, block_number + 1_700_000_000);
        bytes.extend_from_slice(&[log_index as u8; 32]);
    }

    fn write_bytes(bytes: &mut Vec<u8>, value: &[u8]) {
        write_u32(bytes, u32::try_from(value.len()).expect("byte vec len"));
        bytes.extend_from_slice(value);
    }

    fn write_string(bytes: &mut Vec<u8>, value: &str) {
        write_u16(bytes, u16::try_from(value.len()).expect("string len"));
        bytes.extend_from_slice(value.as_bytes());
    }

    fn write_u16(bytes: &mut Vec<u8>, value: u16) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn write_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn write_u64(bytes: &mut Vec<u8>, value: u64) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn prefixed_sha256(bytes: &[u8]) -> FixedBytes<32> {
        FixedBytes::from_slice(&Sha256::digest(bytes))
    }
}
