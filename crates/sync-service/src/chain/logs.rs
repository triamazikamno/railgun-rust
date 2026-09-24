use super::{
    Address, AtomicU64, CancellationToken, ChainError, CommitmentBatch, Duration, DynProvider,
    Filter, FixedBytes, GeneratedCommitmentBatch, Log, LogRangeLimit, LogSpanEndpoint, Nullified,
    Nullifiers, Ordering, Provider, QueryRpcPool, RailgunLegacyShieldEvents, Shield, SolEvent,
    Transact, TransportError, debug,
};

/// Providers that fetch forest catch-up pages concurrently.
pub(super) const FOREST_RPC_PARALLELISM: usize = 4;
/// Physical `eth_getLogs` requests one forest catch-up acquisition may issue.
pub(super) const FOREST_RPC_REQUEST_BUDGET: u64 = 64;

/// Physical `eth_getLogs` request budget shared by every provider of one
/// acquisition.
pub(super) struct LogRequestBudget {
    limit: u64,
    issued: AtomicU64,
}

impl LogRequestBudget {
    pub(super) const fn new(limit: u64) -> Self {
        Self {
            limit,
            issued: AtomicU64::new(0),
        }
    }

    /// Reserves one request, or fails once `limit` requests were reserved.
    fn reserve(&self) -> Result<(), ChainError> {
        self.issued
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |issued| {
                (issued < self.limit).then_some(issued + 1)
            })
            .map(|_| ())
            .map_err(|_| ChainError::LogRequestBudgetExceeded(self.limit))
    }

    /// Requests reserved so far. A reservation is made just before its
    /// request is sent, so a fetch aborted in between leaves one reserved
    /// request unsent.
    pub(super) fn issued(&self) -> u64 {
        self.issued.load(Ordering::Relaxed)
    }

    pub(super) const fn limit(&self) -> u64 {
        self.limit
    }
}

/// One logical page of a parallel log acquisition. Its logs are in provider
/// order; `sort_logs` orders them by block and log index.
pub(super) struct LogPage {
    pub(super) to_block: u64,
    pub(super) logs: Vec<Log>,
}

/// Counters of one parallel log acquisition.
#[derive(Debug, Default)]
pub(super) struct ParallelLogStats {
    /// Logical pages in the range.
    pub(super) pages: u64,
    pub(super) delivered_pages: u64,
    /// Providers whose head covered the range end.
    pub(super) eligible_providers: usize,
    /// Requests reserved on the budget. At most one per in-flight task
    /// aborted when the acquisition ended may not have been sent.
    pub(super) get_logs_requests: u64,
    /// Pages put back on the queue after a provider failed them.
    pub(super) retries: u64,
    /// Per-provider counts, covering completed page tasks only.
    pub(super) providers: Vec<ProviderLogStats>,
    pub(super) elapsed: Duration,
}

/// Pages fetched and physical requests issued by one provider.
#[derive(Debug, Clone, Copy)]
pub(super) struct ProviderLogStats {
    pub(super) rpc_index: usize,
    pub(super) pages: u64,
    pub(super) get_logs_requests: u64,
}

/// Adapts the physical `eth_getLogs` requests covering one logical range to
/// each endpoint's block-span and result-size limits.
pub(super) struct LogRangeFetch<'a> {
    pub(super) spans: &'a QueryRpcPool,
    pub(super) max_span: u64,
    pub(super) cancel: &'a CancellationToken,
    pub(super) logical_from: u64,
    pub(super) logical_to: u64,
    pub(super) get_logs_requests: u64,
    /// Request budget shared with other fetches, if any.
    pub(super) budget: Option<&'a LogRequestBudget>,
}

impl LogRangeFetch<'_> {
    /// Fetches `filter` over `from_block..=to_block` in contiguous requests of
    /// at most the endpoint's learned span.
    ///
    /// A block-span rejection narrows the endpoint's learned span and retries
    /// the uncovered part. A result-size rejection splits only the rejected
    /// request. A rejected single-block request, or any other error, is
    /// returned unchanged. A request beyond the shared budget fails with
    /// `ChainError::LogRequestBudgetExceeded` without being issued.
    async fn get_logs(
        &mut self,
        provider: &DynProvider,
        endpoint: LogSpanEndpoint,
        filter: &Filter,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<Log>, ChainError> {
        if from_block > to_block {
            return Ok(Vec::new());
        }
        let mut logs = Vec::new();
        // Uncovered segments, popped in ascending block order. A segment's cap
        // limits its request width after a result-size split.
        let mut pending: Vec<(u64, u64, Option<u64>)> = vec![(from_block, to_block, None)];
        while let Some((start, end, cap)) = pending.pop() {
            let learned = self.spans.log_span(endpoint, self.max_span);
            let span = cap.map_or(learned, |cap| cap.min(learned));
            let request_end = start.saturating_add(span - 1).min(end);
            if request_end < end {
                pending.push((request_end + 1, end, cap));
            }

            if self.cancel.is_cancelled() {
                return Err(ChainError::LogFetchCancelled);
            }
            if let Some(budget) = self.budget {
                budget.reserve()?;
            }
            self.get_logs_requests += 1;
            let request = filter.clone().select(start..=request_end);
            let result = tokio::select! {
                () = self.cancel.cancelled() => return Err(ChainError::LogFetchCancelled),
                result = provider.get_logs(&request) => result,
            };
            let err = match result {
                Ok(batch) => {
                    logs.extend(batch);
                    continue;
                }
                Err(err) => ChainError::from(err),
            };

            let rejected_span = request_end - start + 1;
            let Some(limit) = err.log_range_limit() else {
                if let ChainError::Rpc(TransportError::ErrorResp(resp)) = &err {
                    debug!(
                        code = resp.code,
                        endpoint = %endpoint,
                        from_block = start,
                        to_block = request_end,
                        "eth_getLogs error is not a recognized range limit"
                    );
                }
                return Err(err);
            };
            if rejected_span == 1 {
                return Err(err);
            }
            let (kind, next_span) = match limit {
                LogRangeLimit::BlockSpan { max_blocks } => {
                    let next_span = max_blocks
                        .filter(|max_blocks| (1..rejected_span).contains(max_blocks))
                        .unwrap_or(rejected_span / 2);
                    self.spans.narrow_log_span(endpoint, next_span);
                    pending.push((start, request_end, cap));
                    ("block_span", next_span)
                }
                LogRangeLimit::ResultSize => {
                    let first_span = rejected_span / 2;
                    let first_end = start + first_span - 1;
                    pending.push((first_end + 1, request_end, Some(rejected_span - first_span)));
                    pending.push((start, first_end, Some(first_span)));
                    ("result_size", first_span)
                }
            };
            debug!(
                logical_from = self.logical_from,
                logical_to = self.logical_to,
                rejected_from = start,
                rejected_to = request_end,
                rejected_span,
                next_span,
                endpoint = %endpoint,
                kind,
                "narrowed eth_getLogs request after provider range limit"
            );
        }
        Ok(logs)
    }
}

pub(super) async fn fetch_logs_for_range_with_provider(
    fetch: &mut LogRangeFetch<'_>,
    provider: &DynProvider,
    endpoint: LogSpanEndpoint,
    contract: Address,
    from_block: u64,
    to_block: u64,
    v2_start_block: u64,
    legacy_shield_block: u64,
) -> Result<Vec<Log>, ChainError> {
    if from_block > to_block {
        return Ok(Vec::new());
    }

    if let Some(event_signatures) = combined_log_event_signatures_for_range(
        from_block,
        to_block,
        v2_start_block,
        legacy_shield_block,
    ) {
        let filter = Filter::new()
            .address(contract)
            .event_signature(event_signatures);
        return fetch
            .get_logs(provider, endpoint, &filter, from_block, to_block)
            .await;
    }

    let mut logs = Vec::new();

    if from_block <= v2_start_block {
        let legacy_end = to_block.min(v2_start_block);
        let legacy_filter = Filter::new().address(contract).event_signature(vec![
            CommitmentBatch::SIGNATURE_HASH,
            GeneratedCommitmentBatch::SIGNATURE_HASH,
        ]);
        let legacy_logs = fetch
            .get_logs(provider, endpoint, &legacy_filter, from_block, legacy_end)
            .await?;
        logs.extend(legacy_logs);
    }

    if to_block >= v2_start_block {
        let v2_start = from_block.max(v2_start_block);
        let transact_filter = Filter::new()
            .address(contract)
            .event_signature(Transact::SIGNATURE_HASH);
        let transact_logs = fetch
            .get_logs(provider, endpoint, &transact_filter, v2_start, to_block)
            .await?;
        logs.extend(transact_logs);

        if v2_start <= legacy_shield_block {
            let legacy_shield_end = to_block.min(legacy_shield_block);
            let legacy_shield_filter = Filter::new()
                .address(contract)
                .event_signature(RailgunLegacyShieldEvents::Shield::SIGNATURE_HASH);
            let legacy_shield_logs = fetch
                .get_logs(
                    provider,
                    endpoint,
                    &legacy_shield_filter,
                    v2_start,
                    legacy_shield_end,
                )
                .await?;
            logs.extend(legacy_shield_logs);
        }

        if to_block > legacy_shield_block {
            let modern_start = v2_start.max(legacy_shield_block.saturating_add(1));
            let modern_shield_filter = Filter::new()
                .address(contract)
                .event_signature(Shield::SIGNATURE_HASH);
            let modern_shield_logs = fetch
                .get_logs(
                    provider,
                    endpoint,
                    &modern_shield_filter,
                    modern_start,
                    to_block,
                )
                .await?;
            logs.extend(modern_shield_logs);
        }
    }

    let nullifier_filter = Filter::new()
        .address(contract)
        .event_signature(vec![Nullifiers::SIGNATURE_HASH, Nullified::SIGNATURE_HASH]);
    let nullifier_logs = fetch
        .get_logs(provider, endpoint, &nullifier_filter, from_block, to_block)
        .await?;
    logs.extend(nullifier_logs);

    Ok(logs)
}

/// Number of `eth_getLogs` filters `fetch_logs_for_range_with_provider`
/// issues for `from_block..=to_block`.
pub(super) fn log_filter_count_for_range(
    from_block: u64,
    to_block: u64,
    v2_start_block: u64,
    legacy_shield_block: u64,
) -> u64 {
    if from_block > to_block {
        return 0;
    }
    if combined_log_event_signatures_for_range(
        from_block,
        to_block,
        v2_start_block,
        legacy_shield_block,
    )
    .is_some()
    {
        return 1;
    }

    // Nullifiers, then legacy commitments, transact, legacy and modern shields.
    let mut filters = 1;
    if from_block <= v2_start_block {
        filters += 1;
    }
    if to_block >= v2_start_block {
        filters += 1;
        let v2_start = from_block.max(v2_start_block);
        if v2_start <= legacy_shield_block {
            filters += 1;
        }
        if to_block > legacy_shield_block {
            filters += 1;
        }
    }
    filters
}

pub(super) fn combined_log_event_signatures_for_range(
    from_block: u64,
    to_block: u64,
    v2_start_block: u64,
    legacy_shield_block: u64,
) -> Option<Vec<FixedBytes<32>>> {
    if v2_start_block > 0 && to_block < v2_start_block {
        return Some(vec![
            CommitmentBatch::SIGNATURE_HASH,
            GeneratedCommitmentBatch::SIGNATURE_HASH,
            Nullifiers::SIGNATURE_HASH,
            Nullified::SIGNATURE_HASH,
        ]);
    }

    if from_block < v2_start_block {
        return None;
    }

    if to_block <= legacy_shield_block {
        return Some(vec![
            Transact::SIGNATURE_HASH,
            RailgunLegacyShieldEvents::Shield::SIGNATURE_HASH,
            Nullifiers::SIGNATURE_HASH,
            Nullified::SIGNATURE_HASH,
        ]);
    }

    if from_block > legacy_shield_block {
        return Some(vec![
            Transact::SIGNATURE_HASH,
            Shield::SIGNATURE_HASH,
            Nullifiers::SIGNATURE_HASH,
            Nullified::SIGNATURE_HASH,
        ]);
    }

    None
}

pub(super) fn sort_logs(logs: &mut [Log]) {
    logs.sort_by_key(|log| {
        (
            log.block_number.unwrap_or_default(),
            log.log_index.unwrap_or_default(),
        )
    });
}

pub(super) fn anchor_file_name(chain_id: u64, contract: Address, block: u64) -> String {
    format!("forest-{chain_id}-{contract}-anchor-{block}.msgpack")
}

pub(super) fn parse_anchor_block(chain_id: u64, contract: Address, name: &str) -> Option<u64> {
    let prefix = format!("forest-{chain_id}-{contract}-anchor-");
    let suffix = ".msgpack";
    if !name.starts_with(&prefix) || !name.ends_with(suffix) {
        return None;
    }
    let start = prefix.len();
    let end = name.len().saturating_sub(suffix.len());
    name.get(start..end)?.parse::<u64>().ok()
}
