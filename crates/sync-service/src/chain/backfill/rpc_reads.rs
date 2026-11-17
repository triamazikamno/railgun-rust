//! Chain RPC reads: archive routing, block hashes and timestamps, and log ranges.

#[allow(clippy::wildcard_imports)]
use super::*;
/// The live forest's lag behind the safe head, from
/// [`ChainConfig::live_forest_lag`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::chain) struct ForestLag {
    pub(in crate::chain) estimated_requests: u64,
    pub(in crate::chain) far_behind: bool,
}

impl ChainConfig {
    pub(in crate::chain) const fn archive_boundary_crossed_by(
        &self,
        from_block: u64,
        to_block: u64,
    ) -> Option<u64> {
        let boundary = self.sync.archive_until_block;
        if boundary == 0 || from_block > boundary {
            return None;
        }
        if to_block > boundary {
            Some(boundary)
        } else {
            None
        }
    }

    /// Builds the configured archive provider over `archive_rpc_http_client`,
    /// else `fallback_client`, else `http_client`.
    pub(in crate::chain) async fn build_archive_provider(
        &self,
        fallback_client: Option<&reqwest::Client>,
    ) -> Result<Option<DynProvider>, ChainError> {
        let Some(url) = self.archive_rpc_url.as_ref() else {
            return Ok(None);
        };
        let client = self
            .archive_rpc_http_client
            .as_ref()
            .or(fallback_client)
            .unwrap_or(&self.http_client);
        build_provider_with_http_client(url, Some(client))
            .await
            .map(Some)
            .map_err(ChainError::ProviderBuild)
    }

    /// Returns the archive provider that serves reads at or below
    /// `archive_until_block`, or `None` when no archive endpoint is configured
    /// and the regular provider serves them. A configured archive endpoint the
    /// pool has not admitted fails the read without contacting any endpoint.
    fn admitted_archive_provider<'a>(
        &self,
        archive_provider: Option<&'a DynProvider>,
    ) -> Result<Option<&'a DynProvider>, ChainError> {
        match archive_provider {
            Some(_) if !self.rpcs.archive_admitted() => Err(ChainError::ArchiveRpcUnverified),
            archive_provider => Ok(archive_provider),
        }
    }

    /// Checks the forest metadata `(meta_last_block, stored_hash)` against the
    /// hash of `last_processed`. Reads the hash only when the forest is past
    /// deployment and the metadata records a hash for `last_processed`. One
    /// read returning the stored hash is a match; a different hash must be
    /// confirmed by the next read before it counts as a mismatch.
    /// Shared by the reorg check and the startup catch-up gate.
    pub(in crate::chain) async fn check_forest_meta(
        &self,
        provider: &DynProvider,
        archive_provider: Option<&DynProvider>,
        meta_last_block: u64,
        stored_hash: [u8; 32],
        last_processed: u64,
    ) -> Result<ForestMetaCheck, ChainError> {
        if last_processed < self.deployment.deployment_block || stored_hash == [0u8; 32] {
            return Ok(ForestMetaCheck::Unchecked);
        }
        if meta_last_block != last_processed {
            return Ok(ForestMetaCheck::StaleMeta);
        }
        let current_hash = match self
            .fetch_block_hash(provider, archive_provider, last_processed)
            .await?
        {
            Some(first_hash) if first_hash == stored_hash => return Ok(ForestMetaCheck::Match),
            Some(first_hash) => {
                self.confirm_block_hash(provider, archive_provider, last_processed, first_hash)
                    .await?
            }
            None => None,
        };
        let decision = ForestReorgDecision::from_confirmed_hash(
            last_processed,
            meta_last_block,
            stored_hash,
            current_hash,
        );
        Ok(match decision {
            ForestReorgDecision::Skip => ForestMetaCheck::Unconfirmed,
            ForestReorgDecision::Match => ForestMetaCheck::Match,
            ForestReorgDecision::Mismatch => ForestMetaCheck::Mismatch {
                current_hash: current_hash.expect("mismatch requires confirmed hash"),
            },
        })
    }

    pub(in crate::chain) async fn fetch_confirmed_block_hash(
        &self,
        provider: &DynProvider,
        archive_provider: Option<&DynProvider>,
        block_number: u64,
    ) -> Result<Option<[u8; 32]>, ChainError> {
        let Some(first_hash) = self
            .fetch_block_hash(provider, archive_provider, block_number)
            .await?
        else {
            return Ok(None);
        };
        self.confirm_block_hash(provider, archive_provider, block_number, first_hash)
            .await
    }

    /// Makes a second read of `block_number` and returns `first_hash` only
    /// when it agrees.
    async fn confirm_block_hash(
        &self,
        provider: &DynProvider,
        archive_provider: Option<&DynProvider>,
        block_number: u64,
        first_hash: [u8; 32],
    ) -> Result<Option<[u8; 32]>, ChainError> {
        let Some(second_hash) = self
            .fetch_block_hash(provider, archive_provider, block_number)
            .await?
        else {
            debug!(target: LOG_TARGET,
                block_number,
                "block hash confirmation read returned no block"
            );
            return Ok(None);
        };

        if second_hash != first_hash {
            debug!(target: LOG_TARGET,
                block_number,
                first_hash = %FixedBytes::<32>::from(first_hash),
                second_hash = %FixedBytes::<32>::from(second_hash),
                "block hash changed between confirmation reads"
            );
            return Ok(None);
        }

        Ok(Some(first_hash))
    }

    pub(in crate::chain) async fn fetch_block_hash(
        &self,
        provider: &DynProvider,
        archive_provider: Option<&DynProvider>,
        block_number: u64,
    ) -> Result<Option<[u8; 32]>, ChainError> {
        let block = self
            .block_read_provider(provider, archive_provider, block_number)?
            .get_block_by_number(BlockNumberOrTag::Number(block_number))
            .await?;
        Ok(block.map(|block| block.header.hash.0))
    }

    /// The provider that serves reads of `block_number`: the admitted archive provider at or
    /// below `archive_until_block` when one is configured, else `provider`.
    fn block_read_provider<'a>(
        &self,
        provider: &'a DynProvider,
        archive_provider: Option<&'a DynProvider>,
        block_number: u64,
    ) -> Result<&'a DynProvider, ChainError> {
        if self.sync.archive_until_block > 0 && block_number <= self.sync.archive_until_block {
            Ok(self
                .admitted_archive_provider(archive_provider)?
                .unwrap_or(provider))
        } else {
            Ok(provider)
        }
    }

    pub(in crate::chain) async fn fetch_block_timestamp(
        &self,
        provider: &DynProvider,
        archive_provider: Option<&DynProvider>,
        block_number: u64,
    ) -> Result<Option<u64>, ChainError> {
        let block = self
            .block_read_provider(provider, archive_provider, block_number)?
            .get_block_by_number(BlockNumberOrTag::Number(block_number))
            .await?;
        Ok(block.map(|block| block.header.timestamp))
    }

    /// Maps each log block to its timestamp, preferring nonzero timestamps supplied
    /// with the logs and requesting headers only for blocks without one.
    pub(in crate::chain) async fn fetch_log_block_timestamps(
        &self,
        provider: &DynProvider,
        archive_provider: Option<&DynProvider>,
        logs: &[Log],
    ) -> Result<HashMap<u64, u64>, ChainError> {
        let started = Instant::now();
        let mut timestamps = HashMap::new();
        for log in logs {
            // A zero log timestamp is missing metadata, not the note's creation time.
            if let (Some(block_number), Some(timestamp)) = (log.block_number, log.block_timestamp)
                && timestamp != 0
            {
                timestamps.entry(block_number).or_insert(timestamp);
            }
        }
        let blocks_from_logs = timestamps.len();

        let mut missing_blocks = logs
            .iter()
            .filter_map(|log| log.block_number)
            .filter(|block_number| !timestamps.contains_key(block_number))
            .collect::<Vec<_>>();
        missing_blocks.sort_unstable();
        missing_blocks.dedup();
        let headers_requested = missing_blocks.len();

        for block_number in missing_blocks {
            if let Some(timestamp) = self
                .fetch_block_timestamp(provider, archive_provider, block_number)
                .await?
            {
                timestamps.insert(block_number, timestamp);
            }
        }
        debug!(target: LOG_TARGET,
            logs = logs.len(),
            blocks_from_logs,
            headers_requested,
            elapsed_ms = started.elapsed().as_millis(),
            "log block timestamp coverage"
        );
        Ok(timestamps)
    }

    /// Fetches the logical range `from_block..=to_block` from `rpc`, and from
    /// the archive provider for blocks at or below `archive_until_block`.
    ///
    /// Physical `eth_getLogs` requests adapt to each endpoint's range limits;
    /// the returned log set is that of the whole logical range.
    pub(in crate::chain) async fn fetch_logs_for_range(
        &self,
        rpc: &ProviderHandle,
        archive_provider: Option<&DynProvider>,
        from_block: u64,
        to_block: u64,
        cancel: &CancellationToken,
    ) -> Result<Vec<Log>, ChainError> {
        let started = Instant::now();
        let mut fetch = LogRangeFetch {
            spans: self.rpcs.as_ref(),
            max_span: self.sync.block_range,
            cancel,
            logical_from: from_block,
            logical_to: to_block,
            get_logs_requests: 0,
            budget: None,
        };
        let result = self
            .fetch_logs_for_logical_range(&mut fetch, rpc, archive_provider)
            .await;
        debug!(target: LOG_TARGET,
            from_block,
            to_block,
            rpc_index = rpc.index,
            get_logs_requests = fetch.get_logs_requests,
            logs = result.as_ref().map_or(0, Vec::len),
            ok = result.is_ok(),
            elapsed_ms = started.elapsed().as_millis(),
            "logical log range fetch finished"
        );
        result
    }

    pub(super) async fn fetch_logs_for_logical_range(
        &self,
        fetch: &mut LogRangeFetch<'_>,
        rpc: &ProviderHandle,
        archive_provider: Option<&DynProvider>,
    ) -> Result<Vec<Log>, ChainError> {
        let (from_block, to_block) = (fetch.logical_from, fetch.logical_to);
        let rpc_endpoint = LogSpanEndpoint::Provider(rpc.index);
        let mut logs = Vec::new();
        let archive_until_block = self.sync.archive_until_block;

        if archive_until_block > 0 && from_block <= archive_until_block {
            let archive_end = to_block.min(archive_until_block);
            let (archive_provider, archive_endpoint) = self
                .admitted_archive_provider(archive_provider)?
                .map_or((&rpc.provider, rpc_endpoint), |provider| {
                    (provider, LogSpanEndpoint::Archive)
                });
            let archive_logs = fetch_logs_for_range_with_provider(
                fetch,
                archive_provider,
                archive_endpoint,
                self.deployment.contract,
                from_block,
                archive_end,
                self.deployment.v2_start_block,
                self.deployment.legacy_shield_block,
            )
            .await?;
            logs.extend(archive_logs);
        }

        if to_block > archive_until_block {
            let standard_start = if archive_until_block > 0 {
                from_block.max(archive_until_block + 1)
            } else {
                from_block
            };
            let standard_logs = fetch_logs_for_range_with_provider(
                fetch,
                &rpc.provider,
                rpc_endpoint,
                self.deployment.contract,
                standard_start,
                to_block,
                self.deployment.v2_start_block,
                self.deployment.legacy_shield_block,
            )
            .await?;
            logs.extend(standard_logs);
        }

        Ok(logs)
    }

    /// Estimates the physical `eth_getLogs` requests needed for
    /// `from_block..=to_block` without issuing any request: one request per
    /// span and filter, using the widest span learned for any available
    /// provider, capped at `block_range`.
    pub(in crate::chain) fn estimate_log_requests(&self, from_block: u64, to_block: u64) -> u64 {
        if from_block > to_block {
            return 0;
        }
        let span = self
            .rpcs
            .available_providers()
            .iter()
            .map(|rpc| {
                self.rpcs
                    .log_span(LogSpanEndpoint::Provider(rpc.index), self.sync.block_range)
            })
            .max()
            .unwrap_or_else(|| self.sync.block_range.max(1));
        let filters = log_filter_count_for_range(
            from_block,
            to_block,
            self.deployment.v2_start_block,
            self.deployment.legacy_shield_block,
        );
        ((to_block - from_block) / span + 1).saturating_mul(filters)
    }

    /// Measures the live forest's lag from `forest_block` to `safe_head` in
    /// estimated `eth_getLogs` requests. The lag is far behind when the
    /// estimate exceeds the forest RPC request budget.
    pub(in crate::chain) fn live_forest_lag(&self, forest_block: u64, safe_head: u64) -> ForestLag {
        let estimated_requests =
            self.estimate_log_requests(forest_block.saturating_add(1), safe_head);
        ForestLag {
            estimated_requests,
            far_behind: estimated_requests > FOREST_RPC_REQUEST_BUDGET,
        }
    }
}
