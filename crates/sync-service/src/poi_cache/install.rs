//! Staging and installing POI cache candidates, and loading persisted corpora.

use std::collections::BTreeMap;
use std::time::Instant;

use alloy::hex;
use alloy::primitives::FixedBytes;
use broadcaster_core::transact::DEFAULT_TXID_VERSION;
use local_db::{DbStore, PoiCorpusJournalHeadRecord};
use poi::cache::{PoiCache, PoiCacheIdentity};
use tracing::{info, warn};

use crate::poi_artifacts::{
    PersistedPoiArtifactCache, PreparedIngestion, load_persisted_cache_for_publisher,
    record_poi_rpc_success,
};
use crate::types::{
    PoiArtifactCacheAttemptId, PoiArtifactCacheGraphProgress, PoiArtifactCachePhase,
};

use super::candidates::{
    PreparedPoiCacheBatch, PreparedPoiCacheCandidate, PreparedPoiCachePersistence,
    PreparedPublicRpcPersistence,
};
use super::compaction::PoiCorpusCompactionRequest;
use super::progress::{
    completion_progress_from_caches, publish_current_attempt_phase,
    send_poi_artifact_cache_progress,
};
use super::source_health::PoiRpcAttemptOutcome;
use super::{
    ChainPoiCacheCoordinator, EVM_CHAIN_TYPE, PoiCacheServiceError, acquire_corpus_write_fence,
};

pub(super) struct FinishedPoiCacheAttempt {
    pub(super) result: Result<(), PoiCacheServiceError>,
    pub(super) compactions: Vec<PoiCorpusCompactionRequest>,
}

pub(super) async fn finish_chain_poi_cache_attempt(
    task: &ChainPoiCacheCoordinator,
    attempt_id: PoiArtifactCacheAttemptId,
    generation: u64,
    batch: PreparedPoiCacheBatch,
) -> FinishedPoiCacheAttempt {
    let PreparedPoiCacheBatch {
        candidates,
        source_outcomes,
        result: network_result,
        ..
    } = batch;
    let mut commit_result = validate_artifact_manifest_sequences(
        candidates
            .iter()
            .filter_map(|candidate| candidate.persistence.artifact_manifest_sequence()),
    );
    let candidates_valid = commit_result.is_ok();
    if candidates_valid && !candidates.is_empty() {
        publish_current_attempt_phase(
            task,
            attempt_id,
            generation,
            PoiArtifactCachePhase::Persisting,
        );
    }
    if candidates_valid {
        for outcome in &source_outcomes {
            if task.cancel.is_cancelled() {
                return FinishedPoiCacheAttempt {
                    result: Err(PoiCacheServiceError::Shutdown { attempt_id }),
                    compactions: Vec::new(),
                };
            }
            if !matches!(outcome.rpc, Some(PoiRpcAttemptOutcome::Succeeded { .. })) {
                continue;
            }
            let identity = PoiCacheIdentity::new(
                EVM_CHAIN_TYPE,
                task.chain_id,
                DEFAULT_TXID_VERSION,
                outcome.list_key,
            );
            if let Err(error) = record_poi_rpc_success(task.db.as_ref(), &identity, generation) {
                commit_result = Err(PoiCacheServiceError::Refresh {
                    reason: error.to_string(),
                });
                break;
            }
        }
    }
    let mut staged = Vec::new();
    if candidates_valid {
        for candidate in candidates {
            if task.cancel.is_cancelled() {
                return FinishedPoiCacheAttempt {
                    result: Err(PoiCacheServiceError::Shutdown { attempt_id }),
                    compactions: Vec::new(),
                };
            }
            match stage_poi_cache_candidate(task, attempt_id, generation, candidate).await {
                Ok(Some(candidate)) => staged.push(candidate),
                Ok(None) => {}
                Err(error) => {
                    commit_result = Err(error);
                    break;
                }
            }
        }
    }
    let result = commit_result
        .and_then(|()| network_result.map_err(|reason| PoiCacheServiceError::Refresh { reason }));
    let compactions =
        match apply_staged_poi_cache_batch(task, attempt_id, generation, staged, &result).await {
            Ok(compactions) => compactions,
            Err(error) => {
                return FinishedPoiCacheAttempt {
                    result: Err(error),
                    compactions: Vec::new(),
                };
            }
        };
    FinishedPoiCacheAttempt {
        result,
        compactions,
    }
}

pub(super) fn validate_artifact_manifest_sequences(
    sequences: impl Iterator<Item = u64>,
) -> Result<(), PoiCacheServiceError> {
    let sequence_range = sequences.fold(None, |range, sequence| {
        Some(
            range.map_or((sequence, sequence), |(min, max): (u64, u64)| {
                (min.min(sequence), max.max(sequence))
            }),
        )
    });
    match sequence_range {
        Some((min, max)) if min != max => Err(PoiCacheServiceError::Refresh {
            reason: format!(
                "artifact candidates used inconsistent global manifest sequences {min} and {max}"
            ),
        }),
        _ => Ok(()),
    }
}

pub(super) async fn stage_poi_cache_candidate(
    task: &ChainPoiCacheCoordinator,
    attempt_id: PoiArtifactCacheAttemptId,
    generation: u64,
    candidate: PreparedPoiCacheCandidate,
) -> Result<Option<StagedPoiCacheCandidate>, PoiCacheServiceError> {
    let PreparedPoiCacheCandidate {
        list_key,
        cache,
        persistence,
    } = candidate;
    let persisted = match persistence {
        PreparedPoiCachePersistence::Artifact { prepared } => {
            let PreparedIngestion { candidate } = *prepared;
            let Some(persisted) = task
                .poi_artifact_persistence
                .commit_candidate_for_attempt(candidate, &task.cancel)
                .await
                .map_err(|err| PoiCacheServiceError::Refresh {
                    reason: err.to_string(),
                })?
            else {
                return Ok(None);
            };
            persisted
        }
        PreparedPoiCachePersistence::PublicRpc { prepared } => {
            let PreparedPublicRpcPersistence {
                range_start_index,
                expected_base,
                starting_record,
                starting_head,
                delta,
                blocked_shields,
            } = *prepared;
            let Some(persisted) = task
                .poi_artifact_persistence
                .commit_public_rpc_for_attempt(
                    cache.expect("public RPC candidate has a cache"),
                    generation,
                    task.artifact_config.trusted_publisher_pubkey,
                    range_start_index,
                    expected_base,
                    starting_record,
                    starting_head,
                    delta,
                    blocked_shields,
                    &task.cancel,
                )
                .await
                .map_err(|err| PoiCacheServiceError::Refresh {
                    reason: err.to_string(),
                })?
            else {
                return Ok(None);
            };
            persisted
        }
    };
    if task.cancel.is_cancelled() {
        return Err(PoiCacheServiceError::Shutdown { attempt_id });
    }
    let compaction = persisted
        .compaction_recommended
        .then(|| PoiCorpusCompactionRequest {
            identity: persisted.cache.identity().clone(),
            expected_base: persisted.expected_base(),
        });
    Ok(Some(StagedPoiCacheCandidate {
        list_key,
        cache: persisted.cache,
        journal_head: persisted.journal_head,
        compaction,
    }))
}

pub(super) struct StagedPoiCacheCandidate {
    pub(super) list_key: FixedBytes<32>,
    pub(super) cache: PoiCache,
    pub(super) journal_head: Option<PoiCorpusJournalHeadRecord>,
    pub(super) compaction: Option<PoiCorpusCompactionRequest>,
}

pub(super) async fn apply_staged_poi_cache_batch(
    task: &ChainPoiCacheCoordinator,
    attempt_id: PoiArtifactCacheAttemptId,
    generation: u64,
    staged: Vec<StagedPoiCacheCandidate>,
    result: &Result<(), PoiCacheServiceError>,
) -> Result<Vec<PoiCorpusCompactionRequest>, PoiCacheServiceError> {
    let _revision_fence = acquire_corpus_write_fence(task).await;
    let mut caches = task.local_caches.write().await;
    let publication = task
        .runtime
        .publication_fence
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if publication.shutdown || task.cancel.is_cancelled() {
        return Err(PoiCacheServiceError::Shutdown { attempt_id });
    }
    let mut installed_head_anchors = task
        .installed_head_anchors
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut installed_any = false;
    let mut blocked_shields_changed = false;
    let mut compactions = Vec::new();
    for candidate in staged {
        let changed = caches.get(&candidate.list_key).is_none_or(|current| {
            current.progress() != candidate.cache.progress()
                || !current.blocked_shields_match(&candidate.cache)
        });
        if let Some(compaction) = candidate.compaction {
            compactions.push(compaction);
        }
        if !changed {
            if let Some(head) = candidate.journal_head {
                installed_head_anchors.insert(candidate.list_key, head);
            }
            continue;
        }
        let blocked_changed = caches
            .get(&candidate.list_key)
            .is_none_or(|current| !current.blocked_shields_match(&candidate.cache));
        if install_cache_if_not_behind(&mut caches, candidate.list_key, candidate.cache) {
            if let Some(head) = candidate.journal_head {
                installed_head_anchors.insert(candidate.list_key, head);
            }
            installed_any = true;
            blocked_shields_changed |= blocked_changed;
        }
    }
    if installed_any {
        task.local_caches
            .publish_committed_revision(blocked_shields_changed);
    }
    let graph_progress = task
        .progress_tx
        .borrow()
        .get(&task.chain_id)
        .filter(|progress| progress.attempt_id == attempt_id && progress.generation == generation)
        .map_or_else(PoiArtifactCacheGraphProgress::default, |progress| {
            progress.graph
        });
    let progress = completion_progress_from_caches(
        attempt_id,
        generation,
        task.chain_id,
        &caches,
        &task.active_list_keys,
        graph_progress,
        result.as_ref().err().map(ToString::to_string),
    );
    send_poi_artifact_cache_progress(&task.progress_tx, progress);
    drop(publication);
    Ok(compactions)
}

pub(super) fn install_cache_if_not_behind(
    caches: &mut BTreeMap<FixedBytes<32>, PoiCache>,
    list_key: FixedBytes<32>,
    cache: PoiCache,
) -> bool {
    if caches.get(&list_key).is_some_and(|current| {
        current.progress().next_event_index > cache.progress().next_event_index
    }) {
        return false;
    }
    caches.insert(list_key, cache);
    true
}

pub(super) fn load_persisted_chain_poi_caches(
    db: &DbStore,
    chain_id: u64,
    active_list_keys: &[FixedBytes<32>],
    publisher_pubkey: FixedBytes<32>,
) -> BTreeMap<FixedBytes<32>, PersistedPoiArtifactCache> {
    let mut loaded = BTreeMap::new();
    for list_key in active_list_keys {
        let identity =
            PoiCacheIdentity::new(EVM_CHAIN_TYPE, chain_id, DEFAULT_TXID_VERSION, *list_key);
        match load_persisted_cache_for_publisher(db, &identity, publisher_pubkey) {
            Ok(Some(persisted)) => {
                loaded.insert(*list_key, persisted);
            }
            Ok(None) => {}
            Err(err) => warn!(
                ?err,
                chain_id,
                list_key = %hex::encode(list_key),
                "failed to load persisted artifact POI cache"
            ),
        }
    }

    loaded
}

pub(super) async fn apply_loaded_persisted_chain_poi_caches(
    task: &ChainPoiCacheCoordinator,
    mut loaded: BTreeMap<FixedBytes<32>, PersistedPoiArtifactCache>,
    started: Instant,
    attempt_id: PoiArtifactCacheAttemptId,
) -> BTreeMap<FixedBytes<32>, PersistedPoiArtifactCache> {
    let loaded_count = loaded.len();
    if loaded_count == 0 {
        return loaded;
    }
    let _revision_fence = acquire_corpus_write_fence(task).await;
    let lock_started = Instant::now();
    let mut caches = task.local_caches.write().await;
    let lock_wait_elapsed_ms = lock_started.elapsed().as_millis();
    let publication = task
        .runtime
        .publication_fence
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if publication.shutdown || task.cancel.is_cancelled() {
        return BTreeMap::new();
    }
    loaded.retain(|list_key, persisted| {
        if task.cache_generation != persisted.cache_generation {
            return false;
        }
        caches.insert(*list_key, persisted.cache.clone());
        true
    });
    let installed_count = loaded.len();
    if installed_count > 0 {
        task.local_caches.publish_committed_revision(true);
    }
    info!(
        chain_id = task.chain_id,
        %attempt_id,
        loaded_count,
        installed_count,
        lock_wait_elapsed_ms,
        elapsed_ms = started.elapsed().as_millis(),
        "installed persisted chain-scoped artifact POI cache"
    );
    loaded
}
