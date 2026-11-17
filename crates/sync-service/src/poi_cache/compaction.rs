//! Background soft compaction of installed POI corpora.

use std::collections::BTreeMap;

use alloy::primitives::FixedBytes;
use futures::FutureExt;
use futures::future::BoxFuture;
use poi::cache::PoiCacheIdentity;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::poi_artifacts::{ExpectedPoiCorpusBase, PoiCorpusCompactionResult};

use super::{ChainPoiCacheCoordinator, acquire_corpus_write_fence};

#[derive(Default)]
pub(super) struct PoiCorpusCompactionLane {
    pub(super) pending: BTreeMap<FixedBytes<32>, PoiCorpusCompactionRequest>,
    pub(super) active: Option<ActivePoiCorpusCompaction>,
}

pub(super) struct ActivePoiCorpusCompaction {
    pub(super) cancel: CancellationToken,
    pub(super) job: BoxFuture<'static, PoiCorpusCompactionCompletion>,
}

pub(super) struct PoiCorpusCompactionCompletion {
    pub(super) list_key: FixedBytes<32>,
    pub(super) expected_base: ExpectedPoiCorpusBase,
    pub(super) result: Result<Option<PoiCorpusCompactionResult>, String>,
}

pub(super) fn enqueue_poi_corpus_compactions(
    lane: &mut PoiCorpusCompactionLane,
    compactions: Vec<PoiCorpusCompactionRequest>,
) {
    for compaction in compactions {
        lane.pending
            .insert(compaction.identity.list_key, compaction);
    }
}

pub(super) fn start_next_poi_corpus_compaction(
    task: &ChainPoiCacheCoordinator,
    lane: &mut PoiCorpusCompactionLane,
    generation: u64,
) {
    if lane.active.is_some() || task.cancel.is_cancelled() {
        return;
    }
    let Some((_, compaction)) = lane.pending.pop_first() else {
        return;
    };
    let list_key = compaction.identity.list_key;
    let expected_base = compaction.expected_base;
    let persistence = task.poi_artifact_persistence.clone();
    let publisher_pubkey = task.artifact_config.trusted_publisher_pubkey;
    let cancel = task.cancel.child_token();
    let job_cancel = cancel.clone();
    let job = async move {
        let result = persistence
            .compact_poi_corpus_for_attempt(
                compaction.identity,
                generation,
                publisher_pubkey,
                expected_base,
                &job_cancel,
            )
            .await
            .map_err(|error| error.to_string());
        PoiCorpusCompactionCompletion {
            list_key,
            expected_base,
            result,
        }
    }
    .boxed();
    lane.active = Some(ActivePoiCorpusCompaction { cancel, job });
}

pub(super) async fn wait_for_active_poi_corpus_compaction(
    lane: &mut PoiCorpusCompactionLane,
) -> PoiCorpusCompactionCompletion {
    match lane.active.as_mut() {
        Some(active) => (&mut active.job).await,
        None => std::future::pending().await,
    }
}

pub(super) fn cancel_poi_corpus_compaction_lane(lane: &mut PoiCorpusCompactionLane) {
    lane.pending.clear();
    if let Some(active) = lane.active.take() {
        active.cancel.cancel();
        drop(active.job);
    }
}

pub(super) async fn finish_background_poi_corpus_compaction(
    task: &ChainPoiCacheCoordinator,
    generation: u64,
    completion: PoiCorpusCompactionCompletion,
) {
    match completion.result {
        Ok(Some(result)) => {
            reconcile_background_compaction_anchor(
                task,
                generation,
                completion.list_key,
                completion.expected_base,
                &result,
            )
            .await;
        }
        Ok(None) => {}
        Err(error) => {
            warn!(%error, "PPOI corpus journal compaction deferred after failure");
        }
    }
}

#[cfg(test)]
pub(super) async fn run_background_poi_corpus_compaction(
    task: &ChainPoiCacheCoordinator,
    generation: u64,
    compaction: PoiCorpusCompactionRequest,
) -> bool {
    let mut lane = PoiCorpusCompactionLane::default();
    enqueue_poi_corpus_compactions(&mut lane, vec![compaction]);
    start_next_poi_corpus_compaction(task, &mut lane, generation);
    if lane.active.is_none() {
        return false;
    }
    let completion = wait_for_active_poi_corpus_compaction(&mut lane).await;
    lane.active.take();
    finish_background_poi_corpus_compaction(task, generation, completion).await;
    !task.cancel.is_cancelled()
}

async fn reconcile_background_compaction_anchor(
    task: &ChainPoiCacheCoordinator,
    generation: u64,
    list_key: FixedBytes<32>,
    expected_base: ExpectedPoiCorpusBase,
    result: &PoiCorpusCompactionResult,
) -> bool {
    let PoiCorpusCompactionResult::Applied(persisted) = result else {
        return false;
    };
    let Some(compacted_head) = persisted.journal_head.as_ref() else {
        return false;
    };
    if persisted.cache_generation != generation || persisted.cache.identity().list_key != list_key {
        return false;
    }

    let _revision_fence = acquire_corpus_write_fence(task).await;
    let publication = task
        .runtime
        .publication_fence
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if publication.shutdown || task.cancel.is_cancelled() {
        return false;
    }
    let mut anchors = task
        .installed_head_anchors
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(installed) = anchors.get_mut(&list_key) else {
        return false;
    };
    if ExpectedPoiCorpusBase::from_journal_head(installed) != expected_base {
        return false;
    }
    *installed = compacted_head.clone();
    drop(publication);
    true
}

pub(super) struct PoiCorpusCompactionRequest {
    pub(super) identity: PoiCacheIdentity,
    pub(super) expected_base: ExpectedPoiCorpusBase,
}
