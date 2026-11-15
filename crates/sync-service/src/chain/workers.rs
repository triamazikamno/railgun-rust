use super::{
    Arc, BackfillRequest, CancellationToken, ChainError, ChainService, DEFAULT_TXID_VERSION,
    Duration, DynProvider, EVM_CHAIN_TYPE, Instant, Instrument, JoinHandle, LogBatch, Provider,
    ProviderHandle, PublicScanSource, QueryRpcPool, TXID_PUBLIC_CACHE_SYNC_INTERVAL,
    TxidPublicCache, TxidPublicCacheKey, WalletScanApply, WalletScanRows, WalletScanRowsPayload,
    await_wallet_cancellation, debug, info, min, mpsc, sort_logs, wallet_backfill_lag_blocks, warn,
    watch,
};

mod head;
#[cfg(test)]
pub(super) use head::{HEAD_READ_STAGGER, INITIAL_HEAD_DEADLINE};
pub(super) use head::{read_head_bounded, spawn_head_poller, untried_provider};

mod pending_tip;
pub(super) use pending_tip::spawn_pending_tip_loop;
#[cfg(test)]
pub(super) use pending_tip::{pending_tip_from_block, pending_tip_provider_covers_target};

mod lag_fallback;
pub(super) use lag_fallback::spawn_wallet_lag_fallback_loop;
#[cfg(test)]
pub(super) use lag_fallback::wallet_lag_fallback_state_for_test;

mod live_logs;
pub(super) use live_logs::spawn_live_log_loop;
#[cfg(test)]
pub(super) use live_logs::{ForestStallTracker, IndexedForestSources, IndexedForestTrigger};

mod backfill;
#[cfg(test)]
pub(super) use backfill::{
    WalletBackfillSlot, drain_pending_backfill_requests, reconcile_retained_acquisition,
};
pub(super) use backfill::{
    spawn_backfill_loop, wallet_finish_result_removes_cursor, wallet_finish_retry_request,
};

const INDEXED_TAIL_FALLBACK_MIN_STALL: Duration = Duration::from_secs(15);
/// Cooldown between wallet indexed tail fallbacks, also used between
/// far-behind live forest attempts.
pub(super) const INDEXED_TAIL_FALLBACK_COOLDOWN: Duration = Duration::from_mins(1);

pub(super) fn spawn_txid_public_cache_loop(
    service: Arc<ChainService>,
    cancel: CancellationToken,
) -> Option<JoinHandle<()>> {
    let endpoint = service.chain.sync.quick_sync_endpoint.clone();
    let indexed_artifact_source = service.chain.sync.indexed_artifact_source.clone();
    if endpoint.is_none() && indexed_artifact_source.is_none() {
        return None;
    }
    let chain_id = service.chain.deployment.chain_id;
    let railgun_contract = service.chain.deployment.contract;
    let http_client = Some(service.chain.http_client.clone());
    let db = service.db.clone();
    Some(tokio::spawn(
        async move {
            loop {
                let key = TxidPublicCacheKey {
                    chain_type: EVM_CHAIN_TYPE,
                    chain_id,
                    railgun_contract,
                    txid_version: DEFAULT_TXID_VERSION,
                };
                let cache = TxidPublicCache::new(&db, key);
                let maintenance = service.public_data_plane.indexed_artifact_maintenance();
                // Cache writes are synchronous between awaits, so dropping the
                // sync on cancel stops between complete writes.
                let result = tokio::select! {
                    biased;
                    () = cancel.cancelled() => break,
                    result = cache.sync_to_indexed_tip_maintained(
                        endpoint.as_ref(),
                        http_client.as_ref(),
                        indexed_artifact_source.as_ref(),
                        &maintenance,
                        Arc::clone(&db),
                    ) => result,
                };
                if let Err(err) = result {
                    warn!(err = %err.without_url(), chain_id, "TXID public cache background sync failed");
                }
                tokio::select! {
                    () = cancel.cancelled() => break,
                    () = tokio::time::sleep(TXID_PUBLIC_CACHE_SYNC_INTERVAL) => {}
                }
            }
        }
        .instrument(tracing::info_span!("txid_public_cache", chain_id)),
    ))
}
