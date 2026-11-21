//! Safe-head reads and the head poller.

use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::BTreeSet;

use super::{
    Arc, ChainError, ChainService, Duration, Instrument, Provider, ProviderHandle, QueryRpcPool,
    debug, warn,
};

/// Providers whose head is read at once while no safe head is known.
pub(in crate::chain) const INITIAL_HEAD_PARALLELISM: usize = 3;

/// Interval after which a bounded head read also starts the next untried
/// provider, so hung providers can't hold every slot.
pub(in crate::chain) const HEAD_READ_STAGGER: Duration = Duration::from_millis(1500);

/// Bound on a head read while no safe head is known.
pub(in crate::chain) const INITIAL_HEAD_DEADLINE: Duration = Duration::from_secs(10);

/// Returns an available provider that `tried` does not contain, chosen at
/// random when possible.
pub(in crate::chain) fn untried_provider(
    rpcs: &QueryRpcPool,
    tried: &BTreeSet<usize>,
) -> Option<ProviderHandle> {
    rpcs.random_provider()
        .filter(|rpc| !tried.contains(&rpc.index))
        .or_else(|| {
            rpcs.available_providers()
                .into_iter()
                .find(|rpc| !tried.contains(&rpc.index))
        })
}

/// Reads the chain head from the first of several distinct providers to
/// answer. Starts `INITIAL_HEAD_PARALLELISM` reads, then another untried
/// provider every `HEAD_READ_STAGGER` and whenever a read fails. Returns
/// `None` once `INITIAL_HEAD_DEADLINE` passes or every provider tried has
/// failed. The reads are futures of this call, so dropping it cancels them.
pub(in crate::chain) async fn read_head_bounded(
    rpcs: &QueryRpcPool,
) -> Option<(ProviderHandle, u64)> {
    let started = tokio::time::Instant::now();
    let deadline = tokio::time::sleep(INITIAL_HEAD_DEADLINE);
    tokio::pin!(deadline);
    let mut next_stagger = started + HEAD_READ_STAGGER;
    let mut tried = BTreeSet::new();
    let mut in_flight = BTreeSet::new();
    let mut reads = FuturesUnordered::new();
    let mut starts = INITIAL_HEAD_PARALLELISM;
    loop {
        for _ in 0..starts {
            let Some(rpc) = untried_provider(rpcs, &tried) else {
                break;
            };
            tried.insert(rpc.index);
            in_flight.insert(rpc.index);
            reads.push(async move {
                let result = rpc.provider.get_block_number().await;
                (rpc, result)
            });
        }
        if reads.is_empty() {
            debug!(
                providers_tried = tried.len(),
                elapsed_ms = started.elapsed().as_millis(),
                "head read ran out of providers"
            );
            return None;
        }
        tokio::select! {
            () = &mut deadline => {
                debug!(
                    providers_tried = tried.len(),
                    unanswered = ?in_flight,
                    elapsed_ms = started.elapsed().as_millis(),
                    "head read deadline passed"
                );
                return None;
            }
            () = tokio::time::sleep_until(next_stagger) => {
                next_stagger += HEAD_READ_STAGGER;
                starts = 1;
            }
            Some((rpc, result)) = reads.next() => match result {
                Ok(head) => {
                    debug!(
                        rpc_index = rpc.index,
                        head,
                        providers_tried = tried.len(),
                        elapsed_ms = started.elapsed().as_millis(),
                        "head read answered"
                    );
                    return Some((rpc, head));
                }
                Err(err) => {
                    in_flight.remove(&rpc.index);
                    let err = ChainError::from(err);
                    let marked_bad = err.should_mark_rpc_unhealthy();
                    if marked_bad {
                        rpcs.mark_bad_provider(&rpc);
                    }
                    debug!(
                        rpc_index = rpc.index,
                        marked_bad,
                        err = %err.without_url(),
                        elapsed_ms = started.elapsed().as_millis(),
                        "head read failed on provider"
                    );
                    starts = 1;
                }
            },
        }
    }
}

pub(in crate::chain) fn spawn_head_poller(service: Arc<ChainService>, rpcs: Arc<QueryRpcPool>) {
    let cancel = service.cancel.clone();
    let chain_id = service.chain.deployment.chain_id;
    tokio::spawn(
        async move {
            loop {
                // Poll first, then sleep.  This ensures the very first poll
                // happens immediately instead of after a full poll_interval
                // delay, which is critical for fast safe_head availability.
                let head = if *service.safe_head_tx.borrow() == 0 {
                    // Until a safe head exists, hung providers must not delay
                    // it by a request timeout each.
                    let read = tokio::select! {
                        () = cancel.cancelled() => break,
                        read = read_head_bounded(&rpcs) => read,
                    };
                    if read.is_none() {
                        warn!("no rpc provider returned the latest block");
                    }
                    read.map(|(_, head)| head)
                } else {
                    let Some(rpc) = rpcs.random_provider() else {
                        warn!("no healthy rpc providers available");
                        tokio::select! {
                            () = cancel.cancelled() => break,
                            () = tokio::time::sleep(service.chain.sync.poll_interval) => { continue; }
                        }
                    };
                    match rpc.provider.get_block_number().await {
                        Ok(head) => Some(head),
                        Err(err) => {
                            warn!(
                                err = %ChainError::from(err).without_url(),
                                rpc_index = rpc.index,
                                "failed to fetch latest block"
                            );
                            rpcs.mark_bad_provider(&rpc);
                            None
                        }
                    }
                };
                if let Some(head) = head {
                    let safe_head = head
                        .saturating_sub(service.chain.finality_depth)
                        .max(service.chain.deployment.deployment_block);
                    if service.head_tx.receiver_count() > 0 {
                        let _ = service.head_tx.send(head);
                    }
                    if let Err(err) = service.safe_head_tx.send(safe_head) {
                        debug!(?err, safe_head, "failed to send safe head update");
                    }
                }
                tokio::select! {
                    () = cancel.cancelled() => break,
                    () = tokio::time::sleep(service.chain.sync.poll_interval) => {}
                }
            }
        }
        .instrument(tracing::error_span!("sync_head", chain_id)),
    );
}
