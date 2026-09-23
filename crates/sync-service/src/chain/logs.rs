use super::{
    Address, CancellationToken, ChainError, CommitmentBatch, DynProvider, Filter, FixedBytes,
    GeneratedCommitmentBatch, Log, LogRangeLimit, LogSpanEndpoint, Nullified, Nullifiers, Provider,
    QueryRpcPool, RailgunLegacyShieldEvents, Shield, SolEvent, Transact, TransportError, debug,
};

/// Adapts the physical `eth_getLogs` requests covering one logical range to
/// each endpoint's block-span and result-size limits.
pub(super) struct LogRangeFetch<'a> {
    pub(super) spans: &'a QueryRpcPool,
    pub(super) max_span: u64,
    pub(super) cancel: &'a CancellationToken,
    pub(super) logical_from: u64,
    pub(super) logical_to: u64,
    pub(super) get_logs_requests: u64,
}

impl LogRangeFetch<'_> {
    /// Fetches `filter` over `from_block..=to_block` in contiguous requests of
    /// at most the endpoint's learned span.
    ///
    /// A block-span rejection narrows the endpoint's learned span and retries
    /// the uncovered part. A result-size rejection splits only the rejected
    /// request. A rejected single-block request, or any other error, is
    /// returned unchanged.
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
