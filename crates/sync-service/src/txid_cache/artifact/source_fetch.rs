#[allow(clippy::wildcard_imports)]
use super::*;

impl TxidPublicArtifactSource {
    pub(crate) fn new(
        config: &IndexedArtifactSourceConfig,
        http_client: Option<&reqwest::Client>,
        scope: ChainScope,
        txid_version: &str,
    ) -> Self {
        Self {
            client: IndexedArtifactManifestClient::new(
                config.clone(),
                http_client.cloned().unwrap_or_default(),
            ),
            scope,
            txid_version: txid_version.to_string(),
        }
    }

    pub(crate) async fn fetch_current_chunks(
        &self,
        cache: &TxidPublicCache<'_>,
        from_index: u64,
        to_index: Option<u64>,
    ) -> Result<TxidPublicArtifactChunkPlan, TxidPublicCacheError> {
        if self.txid_version != DEFAULT_TXID_VERSION {
            return Ok(TxidPublicArtifactChunkPlan {
                required: Vec::new(),
                stable_current: Vec::new(),
            });
        }
        let manifest_fetch = self
            .client
            .fetch_manifest_with_metadata(&self.scope, None, SystemTime::now())
            .await?;
        let manifest = manifest_fetch.manifest;
        let preferred_gateway_index = manifest_fetch.preferred_gateway_index;
        let Some(chain_entry) = manifest
            .chains
            .iter()
            .find(|entry| entry.scope == self.scope)
        else {
            return Ok(TxidPublicArtifactChunkPlan {
                required: Vec::new(),
                stable_current: Vec::new(),
            });
        };
        let range_end = to_index.unwrap_or(u64::MAX);

        let mut catalogs = Vec::new();
        for catalog_descriptor in chain_entry.catalogs.iter().filter(|catalog| {
            self.catalog_may_contain_txid_partition(catalog)
                && catalog.range.intersects(from_index, range_end)
        }) {
            catalogs.push(
                self.fetch_stream_catalog(catalog_descriptor, preferred_gateway_index)
                    .await?,
            );
        }
        if let Some(context_start) =
            self.required_prior_context_start(&catalogs, from_index, range_end)
        {
            let context_end = from_index.saturating_sub(1);
            for catalog_descriptor in chain_entry.catalogs.iter().filter(|catalog| {
                self.catalog_may_contain_txid_partition(catalog)
                    && !catalog.range.intersects(from_index, range_end)
                    && catalog.range.intersects(context_start, context_end)
            }) {
                catalogs.push(
                    self.fetch_stream_catalog(catalog_descriptor, preferred_gateway_index)
                        .await?,
                );
            }
        }
        let plan = IndexedArtifactStreamPlan::plan(
            &catalogs,
            &IndexedArtifactStreamPlanRequest::new(
                IndexedDatasetKind::PublicTxid,
                self.scope.clone(),
                IndexedArtifactRangeKind::TxidIndex,
                from_index,
                range_end,
                IndexedArtifactStreamPartitionPolicy::Unpartitioned,
            ),
        )
        .map_err(|err| TxidPublicCacheError::MetadataMismatch(err.to_string()))?;
        let mut chunks = Vec::with_capacity(plan.required_current_chunks.len());
        let mut missing = Vec::new();
        for entry in &plan.required_current_chunks {
            let descriptor = &entry.descriptor;
            if let Some(chunk) = cache.cached_artifact_chunk(descriptor) {
                chunks.push(chunk);
            } else {
                missing.push(descriptor.clone());
            }
        }
        if !missing.is_empty() {
            chunks.extend(
                self.client
                    .fetch_chunks_bounded_with_preferred_gateway(&missing, preferred_gateway_index)
                    .await
                    .map_err(TxidPublicCacheError::from)?,
            );
        }
        let stable_current = chunks
            .iter()
            .filter(|chunk| {
                plan.required_current_chunks
                    .iter()
                    .any(|entry| entry.is_stable_current() && entry.descriptor == chunk.descriptor)
                    && cache.cached_artifact_chunk(&chunk.descriptor).is_none()
            })
            .cloned()
            .collect();
        Ok(TxidPublicArtifactChunkPlan {
            required: chunks,
            stable_current,
        })
    }

    fn catalog_may_contain_txid_partition(&self, descriptor: &IndexedArtifactDescriptor) -> bool {
        descriptor.matches(
            IndexedDatasetKind::PublicTxid,
            &self.scope,
            IndexedArtifactRangeKind::TxidIndex,
        ) && descriptor.metadata.stream_partition.is_none()
    }

    fn txid_chunk_matches_partition(&self, descriptor: &IndexedArtifactDescriptor) -> bool {
        descriptor.matches(
            IndexedDatasetKind::PublicTxid,
            &self.scope,
            IndexedArtifactRangeKind::TxidIndex,
        ) && descriptor.metadata.stream_partition.is_none()
    }

    fn required_prior_context_start(
        &self,
        catalogs: &[IndexedArtifactStreamCatalog],
        from_index: u64,
        range_end: u64,
    ) -> Option<u64> {
        catalogs
            .iter()
            .flat_map(|catalog| catalog.chunks.iter())
            .filter(|chunk| {
                self.txid_chunk_matches_partition(chunk)
                    && chunk.range.start < from_index
                    && chunk.range.intersects(from_index, range_end)
            })
            .map(|chunk| chunk.range.start)
            .min()
    }

    async fn fetch_stream_catalog(
        &self,
        descriptor: &IndexedArtifactDescriptor,
        preferred_gateway_index: Option<usize>,
    ) -> Result<IndexedArtifactStreamCatalog, TxidPublicCacheError> {
        Ok(IndexedArtifactStreamCatalog::from(
            self.client
                .fetch_catalog_with_preferred_gateway(descriptor, preferred_gateway_index)
                .await?,
        ))
    }
}
