use crate::chain::workers::untried_provider;
use crate::chain::{LogBatch, sort_logs};
use std::collections::BTreeSet;

use super::{
    Arc, CancellationToken, ChainError, ChainService, Instant, Provider, ProviderHandle,
    PublicScanReadScope, WalletScanApply, WalletStartupSyncError, debug, wait_or_cancel,
};

pub(super) struct WalletRpcBackfillEvents {
    pub(super) acquisition_applies: Vec<WalletScanApply>,
    pub(super) delivery_applies: Vec<WalletScanApply>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RpcTargetPolicy {
    RequireRequestedTarget,
    AllowFinalizedPrefix,
}

/// Distinct providers one wallet RPC backfill read tries above the archive
/// boundary before it reports failure.
const WALLET_RPC_READ_MAX_PROVIDERS: usize = 3;

impl ChainService {
    pub(super) async fn fetch_wallet_rpc_backfill_events(
        &self,
        fetch_from_block: u64,
        deliver_from_block: u64,
        to_block: u64,
        target_policy: RpcTargetPolicy,
        cancel: &CancellationToken,
        read_scope: PublicScanReadScope,
    ) -> Result<WalletRpcBackfillEvents, WalletStartupSyncError> {
        if fetch_from_block > to_block {
            return Ok(WalletRpcBackfillEvents {
                acquisition_applies: Vec::new(),
                delivery_applies: Vec::new(),
            });
        }
        // Reads at or below the archive boundary go to the archive endpoint
        // whichever regular provider is chosen, so another regular provider
        // would repeat the same failing request.
        let archive_until_block = self.chain.sync.archive_until_block;
        let max_providers = if archive_until_block > 0 && fetch_from_block <= archive_until_block {
            1
        } else {
            WALLET_RPC_READ_MAX_PROVIDERS
        };
        let mut rpc = self
            .chain
            .rpcs
            .random_provider()
            .ok_or(ChainError::NoHealthyRpc)?;
        let mut tried = BTreeSet::new();
        let started = Instant::now();
        let batch = loop {
            tried.insert(rpc.index);
            let err = match self
                .fetch_wallet_rpc_log_batch(
                    &rpc,
                    fetch_from_block,
                    deliver_from_block,
                    to_block,
                    target_policy,
                    cancel,
                    read_scope,
                )
                .await
            {
                Ok(batch) => break batch,
                Err(err) => err,
            };
            let next = if matches!(err, WalletStartupSyncError::Cancelled)
                || tried.len() >= max_providers
            {
                None
            } else {
                untried_provider(&self.chain.rpcs, &tried)
            };
            let Some(next) = next else {
                return Err(err);
            };
            debug!(
                rpc_index = rpc.index,
                next_rpc_index = next.index,
                fetch_from_block,
                to_block,
                err = %err.without_url(),
                "wallet RPC read failed; trying another provider"
            );
            rpc = next;
        };
        let Some(batch) = batch else {
            return Ok(WalletRpcBackfillEvents {
                acquisition_applies: Vec::new(),
                delivery_applies: Vec::new(),
            });
        };
        let to_block = batch.to_block;
        let batch = Arc::new(batch);
        debug!(
            fetch_from_block,
            deliver_from_block,
            to_block,
            elapsed_ms = started.elapsed().as_millis(),
            "hedged wallet RPC backfill candidate complete"
        );
        let source = self.rpc_scan_source_for_range(fetch_from_block);
        let fetched_apply =
            WalletScanApply::rows_from_log_batch(fetch_from_block, to_block, &batch, source)
                .map_err(ChainError::from)?;
        let delivery_applies = if deliver_from_block > to_block {
            Vec::new()
        } else {
            vec![
                WalletScanApply::rows_from_log_batch(deliver_from_block, to_block, &batch, source)
                    .map_err(ChainError::from)?,
            ]
        };
        Ok(WalletRpcBackfillEvents {
            acquisition_applies: vec![fetched_apply],
            delivery_applies,
        })
    }

    /// Reads `fetch_from_block..=to_block` from `rpc` for a wallet RPC
    /// backfill read, as far as the provider's finalized head proves it.
    /// Returns `None` when a prefix read has no proven coverage.
    async fn fetch_wallet_rpc_log_batch(
        &self,
        rpc: &ProviderHandle,
        fetch_from_block: u64,
        deliver_from_block: u64,
        to_block: u64,
        target_policy: RpcTargetPolicy,
        cancel: &CancellationToken,
        read_scope: PublicScanReadScope,
    ) -> Result<Option<LogBatch>, WalletStartupSyncError> {
        let provider_head = match wait_or_cancel(cancel, rpc.provider.get_block_number()).await? {
            Ok(provider_head) => provider_head,
            Err(err) => {
                let err = ChainError::from(err);
                if err.should_mark_rpc_unhealthy() {
                    self.chain.rpcs.mark_bad_provider(rpc);
                }
                return Err(err.into());
            }
        };
        let proven_to_block = provider_head.saturating_sub(self.chain.finality_depth);
        if target_policy == RpcTargetPolicy::RequireRequestedTarget && proven_to_block < to_block {
            debug!(
                fetch_from_block,
                deliver_from_block,
                requested_to_block = to_block,
                provider_head,
                proven_to_block,
                finality_depth = self.chain.finality_depth,
                "RPC wallet startup source does not cover the required target"
            );
            return Err(WalletStartupSyncError::IncompleteRpcCoverage {
                requested_to: to_block,
                proven_to: proven_to_block,
            });
        }
        if fetch_from_block > proven_to_block {
            debug!(
                fetch_from_block,
                deliver_from_block,
                requested_to_block = to_block,
                provider_head,
                proven_to_block,
                finality_depth = self.chain.finality_depth,
                "RPC wallet scan source has no proven coverage for requested range"
            );
            return Ok(None);
        }
        let to_block = to_block.min(proven_to_block);
        let fetch_logs_started = Instant::now();
        let mut logs = match wait_or_cancel(
            cancel,
            self.chain.fetch_logs_for_range(
                rpc,
                self.archive_provider.as_ref(),
                fetch_from_block,
                to_block,
                cancel,
            ),
        )
        .await?
        {
            Ok(logs) => logs,
            Err(err) => {
                if err.should_mark_rpc_unhealthy() {
                    self.chain.rpcs.mark_bad_provider(rpc);
                }
                return Err(err.into());
            }
        };
        debug!(
            fetch_from_block,
            deliver_from_block,
            to_block,
            num_logs = logs.len(),
            elapsed_ms = fetch_logs_started.elapsed().as_millis(),
            "fetched hedged wallet RPC logs"
        );
        sort_logs(&mut logs);

        let timestamps_started = Instant::now();
        let block_timestamps = match wait_or_cancel(
            cancel,
            self.chain.fetch_log_block_timestamps(
                &rpc.provider,
                self.archive_provider.as_ref(),
                &logs,
            ),
        )
        .await?
        {
            Ok(block_timestamps) => block_timestamps,
            Err(err) => {
                if err.should_mark_rpc_unhealthy() {
                    self.chain.rpcs.mark_bad_provider(rpc);
                }
                return Err(err.into());
            }
        };
        debug!(
            fetch_from_block,
            deliver_from_block,
            to_block,
            num_logs = logs.len(),
            elapsed_ms = timestamps_started.elapsed().as_millis(),
            "fetched hedged wallet RPC log block timestamps"
        );

        if let Some(archive_endpoint) = self
            .chain
            .archive_boundary_crossed_by(fetch_from_block, to_block)
        {
            let archive_hash = wait_or_cancel(
                cancel,
                self.chain.fetch_block_hash(
                    &rpc.provider,
                    self.archive_provider.as_ref(),
                    archive_endpoint,
                ),
            )
            .await??;
            if archive_hash.is_none() {
                return Err(WalletStartupSyncError::UnprovenRpcEndpoint {
                    block_number: archive_endpoint,
                });
            }
        }

        let block_hash_started = Instant::now();
        let to_block_hash = match wait_or_cancel(
            cancel,
            self.chain
                .fetch_block_hash(&rpc.provider, self.archive_provider.as_ref(), to_block),
        )
        .await?
        {
            Ok(hash) => {
                if hash.is_none() {
                    return Err(WalletStartupSyncError::UnprovenRpcEndpoint {
                        block_number: to_block,
                    });
                }
                hash
            }
            Err(err) => return Err(err.into()),
        };
        debug!(
            to_block,
            elapsed_ms = block_hash_started.elapsed().as_millis(),
            "fetched hedged wallet RPC block hash"
        );

        Ok(Some(LogBatch {
            from_block: fetch_from_block,
            to_block,
            logs,
            block_timestamps,
            to_block_hash,
            read_scope,
        }))
    }
}
