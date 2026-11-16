//! POI artifact cache progress records and the cache readiness views they report.

use std::collections::BTreeMap;

use alloy::primitives::FixedBytes;
use broadcaster_core::transact::DEFAULT_TXID_VERSION;
use poi::cache::PoiCache;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::types::{
    LocalPoiCaches, PoiArtifactCacheAttemptId, PoiArtifactCacheGraphProgress,
    PoiArtifactCacheListProgress, PoiArtifactCachePhase, PoiArtifactCacheProgress,
};

use super::{
    ChainPoiCacheCoordinator, EVM_CHAIN_TYPE, PoiCacheServiceError, PoiCacheServiceRuntime,
};

#[allow(clippy::too_many_arguments)]
pub(super) const fn new_poi_artifact_cache_progress(
    attempt_id: PoiArtifactCacheAttemptId,
    generation: u64,
    chain_id: u64,
    phase: PoiArtifactCachePhase,
    completed_lists: usize,
    total_lists: usize,
    current_list_key: Option<FixedBytes<32>>,
    current_event_index: Option<u64>,
    target_event_index: Option<u64>,
    list_progress: Vec<PoiArtifactCacheListProgress>,
    graph: PoiArtifactCacheGraphProgress,
    ready_for_wallet_checks: bool,
    last_error: Option<String>,
) -> PoiArtifactCacheProgress {
    PoiArtifactCacheProgress {
        attempt_id,
        generation,
        chain_id,
        phase,
        completed_lists,
        total_lists,
        current_list_key,
        current_event_index,
        target_event_index,
        list_progress,
        graph,
        ready_for_wallet_checks,
        last_error,
    }
}

pub(super) fn send_poi_artifact_cache_progress(
    progress_tx: &watch::Sender<BTreeMap<u64, PoiArtifactCacheProgress>>,
    progress: PoiArtifactCacheProgress,
) {
    progress_tx.send_modify(|chains| {
        if chains.get(&progress.chain_id).is_some_and(|current| {
            current.attempt_id > progress.attempt_id
                || (current.attempt_id == progress.attempt_id
                    && current.generation != progress.generation)
        }) {
            return;
        }
        chains.insert(progress.chain_id, progress);
    });
}

pub(super) fn send_poi_artifact_cache_progress_for_generation(
    progress_tx: &watch::Sender<BTreeMap<u64, PoiArtifactCacheProgress>>,
    generation: u64,
    progress: PoiArtifactCacheProgress,
) -> Result<(), PoiCacheServiceError> {
    if progress.generation != generation {
        return Err(PoiCacheServiceError::Refresh {
            reason: format!(
                "POI cache progress generation {} does not match service generation {generation}",
                progress.generation
            ),
        });
    }
    send_poi_artifact_cache_progress(progress_tx, progress);
    Ok(())
}

pub(super) fn poi_cache_list_progress_for_keys(
    active_list_keys: &[FixedBytes<32>],
) -> Vec<PoiArtifactCacheListProgress> {
    active_list_keys
        .iter()
        .map(|list_key| PoiArtifactCacheListProgress {
            list_key: *list_key,
            current_event_index: None,
            target_event_index: None,
            ready_for_wallet_checks: false,
        })
        .collect()
}

pub(super) const fn single_list_event_index(
    list_progress: &[PoiArtifactCacheListProgress],
) -> (Option<u64>, Option<u64>) {
    if let [progress] = list_progress {
        (progress.current_event_index, progress.target_event_index)
    } else {
        (None, None)
    }
}

pub(super) fn list_progress_with_active_event(
    active_list_keys: &[FixedBytes<32>],
    baseline: &[PoiArtifactCacheListProgress],
    active_list_key: FixedBytes<32>,
    current_event_index: Option<u64>,
    target_event_index: Option<u64>,
) -> Vec<PoiArtifactCacheListProgress> {
    active_list_keys
        .iter()
        .map(|list_key| {
            let mut progress = baseline
                .iter()
                .find(|progress| progress.list_key == *list_key)
                .cloned()
                .unwrap_or(PoiArtifactCacheListProgress {
                    list_key: *list_key,
                    current_event_index: None,
                    target_event_index: None,
                    ready_for_wallet_checks: false,
                });
            if *list_key == active_list_key {
                progress.current_event_index = current_event_index;
                progress.target_event_index = target_event_index;
            }
            progress
        })
        .collect()
}

async fn emit_chain_poi_cache_ready_progress(
    progress_tx: &watch::Sender<BTreeMap<u64, PoiArtifactCacheProgress>>,
    chain_id: u64,
    local_caches: &LocalPoiCaches,
    active_list_keys: &[FixedBytes<32>],
    attempt_id: PoiArtifactCacheAttemptId,
    generation: u64,
    runtime: &PoiCacheServiceRuntime,
    cancel: &CancellationToken,
    initialized_tx: Option<&watch::Sender<bool>>,
) -> Result<(), PoiCacheServiceError> {
    let ready =
        chain_poi_caches_available_for_lists(chain_id, local_caches, active_list_keys).await;
    let completed = installed_chain_poi_cache_count(chain_id, local_caches, active_list_keys).await;
    let list_progress =
        chain_poi_cache_list_progress(chain_id, local_caches, active_list_keys).await;
    let (current_event_index, target_event_index) = single_list_event_index(&list_progress);
    let publication = runtime
        .publication_fence
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if publication.shutdown || cancel.is_cancelled() {
        return Err(PoiCacheServiceError::Shutdown { attempt_id });
    }
    send_poi_artifact_cache_progress_for_generation(
        progress_tx,
        generation,
        new_poi_artifact_cache_progress(
            attempt_id,
            generation,
            chain_id,
            PoiArtifactCachePhase::Ready,
            completed,
            active_list_keys.len(),
            None,
            current_event_index,
            target_event_index,
            list_progress,
            PoiArtifactCacheGraphProgress::default(),
            ready,
            None,
        ),
    )?;
    if let Some(initialized_tx) = initialized_tx {
        let _ = initialized_tx.send(true);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn publish_chain_poi_cache_ready_and_acknowledge_initialization(
    progress_tx: &watch::Sender<BTreeMap<u64, PoiArtifactCacheProgress>>,
    chain_id: u64,
    local_caches: &LocalPoiCaches,
    active_list_keys: &[FixedBytes<32>],
    attempt_id: PoiArtifactCacheAttemptId,
    generation: u64,
    runtime: &PoiCacheServiceRuntime,
    cancel: &CancellationToken,
    initialized_tx: watch::Sender<bool>,
) -> Result<(), PoiCacheServiceError> {
    emit_chain_poi_cache_ready_progress(
        progress_tx,
        chain_id,
        local_caches,
        active_list_keys,
        attempt_id,
        generation,
        runtime,
        cancel,
        Some(&initialized_tx),
    )
    .await?;
    Ok(())
}

pub(super) fn publish_current_attempt_phase(
    task: &ChainPoiCacheCoordinator,
    attempt_id: PoiArtifactCacheAttemptId,
    generation: u64,
    phase: PoiArtifactCachePhase,
) {
    let publication = task
        .runtime
        .publication_fence
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if publication.shutdown || task.cancel.is_cancelled() {
        return;
    }
    let Some(mut progress) = task.progress_tx.borrow().get(&task.chain_id).cloned() else {
        return;
    };
    if progress.attempt_id != attempt_id || progress.generation != generation {
        return;
    }
    progress.phase = phase;
    let _ =
        send_poi_artifact_cache_progress_for_generation(&task.progress_tx, generation, progress);
}

pub(super) fn completion_progress_from_caches(
    attempt_id: PoiArtifactCacheAttemptId,
    generation: u64,
    chain_id: u64,
    caches: &BTreeMap<FixedBytes<32>, PoiCache>,
    active_list_keys: &[FixedBytes<32>],
    graph: PoiArtifactCacheGraphProgress,
    last_error: Option<String>,
) -> PoiArtifactCacheProgress {
    let ready = cache_map_available_for_lists(chain_id, caches, active_list_keys);
    let completed = active_list_keys
        .iter()
        .filter(|list_key| cache_map_available_for_list(chain_id, caches, **list_key))
        .count();
    let list_progress = cache_map_list_progress(chain_id, caches, active_list_keys);
    let (current_event_index, target_event_index) = single_list_event_index(&list_progress);
    new_poi_artifact_cache_progress(
        attempt_id,
        generation,
        chain_id,
        if last_error.is_some() {
            PoiArtifactCachePhase::Failed
        } else {
            PoiArtifactCachePhase::Ready
        },
        completed,
        active_list_keys.len(),
        None,
        current_event_index,
        target_event_index,
        list_progress,
        graph,
        ready,
        last_error,
    )
}

pub(super) fn cache_map_available_for_list(
    chain_id: u64,
    caches: &BTreeMap<FixedBytes<32>, PoiCache>,
    list_key: FixedBytes<32>,
) -> bool {
    caches.get(&list_key).is_some_and(|cache| {
        cache.identity().chain_type == EVM_CHAIN_TYPE
            && cache.identity().chain_id == chain_id
            && cache.identity().txid_version == DEFAULT_TXID_VERSION
            && cache.progress().next_event_index > 0
    })
}

pub(super) fn cache_map_available_for_lists(
    chain_id: u64,
    caches: &BTreeMap<FixedBytes<32>, PoiCache>,
    active_list_keys: &[FixedBytes<32>],
) -> bool {
    active_list_keys
        .iter()
        .all(|list_key| cache_map_available_for_list(chain_id, caches, *list_key))
}

pub(super) fn cache_map_list_progress(
    chain_id: u64,
    caches: &BTreeMap<FixedBytes<32>, PoiCache>,
    active_list_keys: &[FixedBytes<32>],
) -> Vec<PoiArtifactCacheListProgress> {
    active_list_keys
        .iter()
        .map(|list_key| {
            let event_index = caches.get(list_key).and_then(|cache| {
                (cache.identity().chain_type == EVM_CHAIN_TYPE
                    && cache.identity().chain_id == chain_id
                    && cache.identity().txid_version == DEFAULT_TXID_VERSION)
                    .then(|| cache.progress().next_event_index.checked_sub(1))
                    .flatten()
            });
            PoiArtifactCacheListProgress {
                list_key: *list_key,
                current_event_index: event_index,
                target_event_index: event_index,
                ready_for_wallet_checks: event_index.is_some(),
            }
        })
        .collect()
}

async fn chain_poi_caches_available_for_lists(
    chain_id: u64,
    local_caches: &LocalPoiCaches,
    active_list_keys: &[FixedBytes<32>],
) -> bool {
    if active_list_keys.is_empty() {
        return true;
    }
    let caches = local_caches.read().await;
    active_list_keys.iter().all(|list_key| {
        caches.get(list_key).is_some_and(|cache| {
            cache.identity().chain_type == EVM_CHAIN_TYPE
                && cache.identity().chain_id == chain_id
                && cache.identity().txid_version == DEFAULT_TXID_VERSION
                && cache.progress().next_event_index > 0
        })
    })
}

async fn installed_chain_poi_cache_count(
    chain_id: u64,
    local_caches: &LocalPoiCaches,
    active_list_keys: &[FixedBytes<32>],
) -> usize {
    let caches = local_caches.read().await;
    active_list_keys
        .iter()
        .filter(|list_key| {
            caches.get(*list_key).is_some_and(|cache| {
                cache.identity().chain_type == EVM_CHAIN_TYPE
                    && cache.identity().chain_id == chain_id
                    && cache.identity().txid_version == DEFAULT_TXID_VERSION
                    && cache.progress().next_event_index > 0
            })
        })
        .count()
}

pub(super) async fn chain_poi_cache_list_progress(
    chain_id: u64,
    local_caches: &LocalPoiCaches,
    active_list_keys: &[FixedBytes<32>],
) -> Vec<PoiArtifactCacheListProgress> {
    let caches = local_caches.read().await;
    active_list_keys
        .iter()
        .map(|list_key| {
            let event_index = caches.get(list_key).and_then(|cache| {
                if cache.identity().chain_type == EVM_CHAIN_TYPE
                    && cache.identity().chain_id == chain_id
                    && cache.identity().txid_version == DEFAULT_TXID_VERSION
                {
                    cache.progress().next_event_index.checked_sub(1)
                } else {
                    None
                }
            });
            PoiArtifactCacheListProgress {
                list_key: *list_key,
                current_event_index: event_index,
                target_event_index: event_index,
                ready_for_wallet_checks: event_index.is_some(),
            }
        })
        .collect()
}
