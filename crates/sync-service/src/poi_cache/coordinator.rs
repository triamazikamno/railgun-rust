//! The chain POI cache coordinator loop and its attempt lifecycle.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use alloy::primitives::FixedBytes;
use futures::FutureExt;
use futures::future::BoxFuture;
use tokio::sync::{oneshot, watch};
use tokio::time::Instant as TokioInstant;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, info};

use crate::types::{
    PoiArtifactCacheAttemptId, PoiArtifactCacheGraphProgress, PoiArtifactCachePhase,
};

use super::candidates::{
    PoiCacheCandidateJob, PreparedPoiCacheBatch, produce_chain_poi_cache_candidates,
};
use super::compaction::{
    PoiCorpusCompactionLane, cancel_poi_corpus_compaction_lane, enqueue_poi_corpus_compactions,
    finish_background_poi_corpus_compaction, start_next_poi_corpus_compaction,
    wait_for_active_poi_corpus_compaction,
};
use super::install::{
    FinishedPoiCacheAttempt, apply_loaded_persisted_chain_poi_caches,
    finish_chain_poi_cache_attempt, load_persisted_chain_poi_caches,
};
use super::progress::{
    cache_map_available_for_list, cache_map_available_for_lists, cache_map_list_progress,
    new_poi_artifact_cache_progress, poi_cache_list_progress_for_keys,
    publish_chain_poi_cache_ready_and_acknowledge_initialization,
    send_poi_artifact_cache_progress_for_generation, single_list_event_index,
};
use super::schedule::{
    PoiCacheMaintenanceSchedule, PoiCacheSyncScope, apply_poi_cache_demand_update,
    effective_poi_cache_scope,
};
use super::source_health::{
    PoiListAttemptPlan, PoiSourceHealth, record_list_source_outcomes, source_health_for_lists,
};
use super::{
    ChainPoiCacheCommand, ChainPoiCacheCoordinator, ChainPoiCacheJobEvent, PoiCacheRetryHandle,
    PoiCacheServiceError,
};

pub(super) fn replacement_poi_cache_scope(
    requested: PoiCacheSyncScope,
    active: Option<&ActivePoiCacheAttempt>,
) -> PoiCacheSyncScope {
    requested.union(active.map_or(
        PoiCacheSyncScope {
            events: false,
            blocked_shields: false,
        },
        |attempt| attempt.scope,
    ))
}

pub(super) struct ActivePoiCacheAttempt {
    pub(super) id: PoiArtifactCacheAttemptId,
    pub(super) generation: u64,
    pub(super) scope: PoiCacheSyncScope,
    pub(super) cancel: CancellationToken,
    pub(super) job: BoxFuture<'static, PreparedPoiCacheBatch>,
    pub(super) retry_completion: Option<oneshot::Sender<Result<(), PoiCacheServiceError>>>,
}

pub(super) fn spawn_chain_poi_cache_coordinator(
    task: ChainPoiCacheCoordinator,
    initialized_tx: watch::Sender<bool>,
    stopped_tx: watch::Sender<bool>,
) {
    let chain_id = task.chain_id;
    tokio::spawn(
        async move {
            run_chain_poi_cache_coordinator(task, initialized_tx).await;
            let _ = stopped_tx.send(true);
        }
        .instrument(tracing::error_span!("poi_artifact_cache", chain_id)),
    );
}

async fn run_chain_poi_cache_coordinator(
    mut task: ChainPoiCacheCoordinator,
    initialized_tx: watch::Sender<bool>,
) {
    let chain_id = task.chain_id;
    let generation = task.cache_generation;
    let startup_attempt_id = task.runtime.next_attempt_id();
    if !publish_persisted_cache_loading(&task, startup_attempt_id) {
        return;
    }
    preload_persisted_chain_poi_caches(&mut task, startup_attempt_id).await;
    if publish_chain_poi_cache_ready_and_acknowledge_initialization(
        &task.progress_tx,
        chain_id,
        &task.local_caches,
        &task.active_list_keys,
        startup_attempt_id,
        generation,
        task.runtime.as_ref(),
        &task.cancel,
        initialized_tx,
    )
    .await
    .is_err()
    {
        return;
    }
    let health = source_health_for_lists(
        task.db.as_ref(),
        chain_id,
        generation,
        &task.active_list_keys,
        &task.preloaded_caches,
    );
    let mut coordinator = ChainPoiCacheCoordinatorLoop {
        generation,
        health,
        active: None,
        public_cache_reset: None,
        compaction_lane: PoiCorpusCompactionLane::default(),
        maintenance: PoiCacheMaintenanceSchedule::new(TokioInstant::now()),
        task,
    };
    info!(
        chain_id,
        list_count = coordinator.task.active_list_keys.len(),
        "starting chain-owned POI cache coordinator"
    );
    coordinator.start_full_sync().await;
    coordinator.run().await;
    info!(chain_id, "chain-owned POI cache coordinator stopped");
}

/// Publishes the startup `LoadingPersisted` progress under the publication
/// fence; false once shutdown has begun or the coordinator is cancelled.
fn publish_persisted_cache_loading(
    task: &ChainPoiCacheCoordinator,
    attempt_id: PoiArtifactCacheAttemptId,
) -> bool {
    let publication = task
        .runtime
        .publication_fence
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if publication.shutdown || task.cancel.is_cancelled() {
        return false;
    }
    let _ = send_poi_artifact_cache_progress_for_generation(
        &task.progress_tx,
        task.cache_generation,
        new_poi_artifact_cache_progress(
            attempt_id,
            task.cache_generation,
            task.chain_id,
            PoiArtifactCachePhase::LoadingPersisted,
            0,
            task.active_list_keys.len(),
            None,
            None,
            None,
            poi_cache_list_progress_for_keys(&task.active_list_keys),
            PoiArtifactCacheGraphProgress::default(),
            false,
            None,
        ),
    );
    true
}

/// Loads the persisted caches into the coordinator and installs their journal
/// heads as the installed head anchors.
async fn preload_persisted_chain_poi_caches(
    task: &mut ChainPoiCacheCoordinator,
    startup_attempt_id: PoiArtifactCacheAttemptId,
) {
    let preload_started = Instant::now();
    let loaded = load_persisted_chain_poi_caches(
        task.db.as_ref(),
        task.chain_id,
        &task.active_list_keys,
        task.artifact_config.trusted_publisher_pubkey,
    );
    task.preloaded_caches =
        apply_loaded_persisted_chain_poi_caches(task, loaded, preload_started, startup_attempt_id)
            .await;
    let mut anchors = task
        .installed_head_anchors
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *anchors = task
        .preloaded_caches
        .iter()
        .filter_map(|(list_key, persisted)| {
            persisted.journal_head.clone().map(|head| (*list_key, head))
        })
        .collect();
}

/// A running chain POI cache coordinator and the state its loop carries between turns.
pub(super) struct ChainPoiCacheCoordinatorLoop {
    pub(super) generation: u64,
    pub(super) health: BTreeMap<FixedBytes<32>, PoiSourceHealth>,
    pub(super) active: Option<ActivePoiCacheAttempt>,
    pub(super) public_cache_reset: Option<CancellationToken>,
    pub(super) compaction_lane: PoiCorpusCompactionLane,
    pub(super) maintenance: PoiCacheMaintenanceSchedule,
    // Declared last so that the loop state, including any compaction job, drops first.
    pub(super) task: ChainPoiCacheCoordinator,
}

impl ChainPoiCacheCoordinatorLoop {
    /// Serves commands, attempt and compaction completions, maintenance and
    /// reset releases until cancelled or the command channel closes.
    async fn run(&mut self) {
        loop {
            tokio::select! {
                biased;
                () = self.task.cancel.cancelled() => {
                    cancel_active_attempt(&mut self.active, |attempt_id| {
                        PoiCacheServiceError::Shutdown { attempt_id }
                    });
                    cancel_poi_corpus_compaction_lane(&mut self.compaction_lane);
                    break;
                }
                command = self.task.command_rx.recv() => {
                    let Some(command) = command else {
                        cancel_active_attempt(&mut self.active, |attempt_id| {
                            PoiCacheServiceError::Shutdown { attempt_id }
                        });
                        break;
                    };
                    self.handle_command(command).await;
                }
                event = self.task.job_rx.recv() => {
                    let Some(event) = event else { continue };
                    publish_active_attempt_progress(&self.task, self.active.as_ref(), event);
                }
                completion = wait_for_active_attempt(&mut self.active) => {
                    self.finish_active_attempt(completion).await;
                }
                completion = wait_for_active_poi_corpus_compaction(&mut self.compaction_lane) => {
                    self.compaction_lane.active.take();
                    finish_background_poi_corpus_compaction(&self.task, self.generation, completion)
                        .await;
                    start_next_poi_corpus_compaction(
                        &self.task,
                        &mut self.compaction_lane,
                        self.generation,
                    );
                }
                () = tokio::time::sleep_until(self.maintenance.next_deadline()),
                    if self.active.is_none() && self.public_cache_reset.is_none() => {
                    self.start_due_maintenance().await;
                }
                () = wait_for_public_cache_reset_release(&mut self.public_cache_reset),
                    if self.active.is_none() => {
                    self.public_cache_reset = None;
                    self.start_full_sync().await;
                }
            }
        }
    }

    async fn start_attempt(
        &mut self,
        scope: PoiCacheSyncScope,
        retry_completion: Option<oneshot::Sender<Result<(), PoiCacheServiceError>>>,
    ) -> Result<PoiArtifactCacheAttemptId, PoiCacheServiceError> {
        start_chain_poi_cache_attempt(
            &mut self.task,
            &mut self.active,
            self.generation,
            &self.health,
            scope,
            retry_completion,
        )
        .await
    }

    /// Starts a full sync, recording a failure to start it.
    async fn start_full_sync(&mut self) {
        if self
            .start_attempt(PoiCacheSyncScope::FULL, None)
            .await
            .is_err()
        {
            self.maintenance
                .record_failure(PoiCacheSyncScope::FULL, TokioInstant::now());
        }
    }

    /// Starts the maintenance attempt that is due, recording a failure to start it.
    async fn start_due_maintenance(&mut self) {
        let now = TokioInstant::now();
        if let Some(scope) = self.maintenance.due_scope(now)
            && self.start_attempt(scope, None).await.is_err()
        {
            self.maintenance.record_failure(scope, now);
        }
    }

    async fn handle_command(&mut self, command: ChainPoiCacheCommand) {
        match command {
            ChainPoiCacheCommand::UpdateDemand { actor_id, demand } => {
                let _ = apply_poi_cache_demand_update(
                    &mut self.maintenance,
                    actor_id,
                    demand,
                    TokioInstant::now(),
                );
            }
            ChainPoiCacheCommand::Retry { scope, admission } => {
                self.admit_retry(scope, admission).await;
            }
            ChainPoiCacheCommand::QuiesceForPublicCacheReset { lease, response } => {
                self.public_cache_reset = Some(lease);
                cancel_active_attempt(&mut self.active, |attempt_id| {
                    PoiCacheServiceError::StaleAttempt { attempt_id }
                });
                cancel_poi_corpus_compaction_lane(&mut self.compaction_lane);
                let _ = response.send(());
            }
        }
    }

    /// Replaces the active attempt with a retry over `scope` and answers its admission.
    async fn admit_retry(
        &mut self,
        scope: PoiCacheSyncScope,
        admission: oneshot::Sender<Result<PoiCacheRetryHandle, PoiCacheServiceError>>,
    ) {
        clear_released_public_cache_reset(&mut self.public_cache_reset);
        if self.public_cache_reset.is_some()
            || self
                .task
                .runtime
                .public_cache_reset_gate
                .try_read()
                .is_err()
        {
            let _ = admission.send(Err(PoiCacheServiceError::CorpusResetInProgress));
            return;
        }
        let replacement_scope = replacement_poi_cache_scope(scope, self.active.as_ref());
        cancel_active_attempt(&mut self.active, |attempt_id| {
            PoiCacheServiceError::AttemptSuperseded { attempt_id }
        });
        let (completion, completed) = oneshot::channel();
        match self
            .start_attempt(replacement_scope, Some(completion))
            .await
        {
            Ok(attempt_id) => {
                let publication = self
                    .task
                    .runtime
                    .publication_fence
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if publication.shutdown || self.task.cancel.is_cancelled() {
                    drop(publication);
                    cancel_active_attempt(&mut self.active, |attempt_id| {
                        PoiCacheServiceError::Shutdown { attempt_id }
                    });
                    let _ = admission.send(Err(PoiCacheServiceError::Shutdown { attempt_id }));
                } else {
                    let _ = admission.send(Ok(PoiCacheRetryHandle {
                        attempt_id,
                        completion: completed,
                    }));
                }
            }
            Err(error) => {
                self.maintenance
                    .record_failure(replacement_scope, TokioInstant::now());
                let _ = admission.send(Err(error));
            }
        }
    }

    /// Installs the completed attempt's batch, records its source health and
    /// maintenance outcome, answers its retry, and queues its compactions.
    async fn finish_active_attempt(&mut self, completion: PreparedPoiCacheBatch) {
        let finished = self
            .active
            .take()
            .expect("completed POI cache attempt is active");
        let attempt_id = finished.id;
        let attempt_generation = finished.generation;
        let attempt_scope = finished.scope;
        let actual_scope = completion.actual_scope;
        let source_outcomes = completion.source_outcomes.clone();
        let FinishedPoiCacheAttempt {
            result: attempt_result,
            compactions,
        } = finish_chain_poi_cache_attempt(&self.task, attempt_id, attempt_generation, completion)
            .await;
        if !matches!(&attempt_result, Err(PoiCacheServiceError::Shutdown { .. })) {
            record_list_source_outcomes(&mut self.health, &source_outcomes);
        }
        if attempt_result.is_ok() {
            self.maintenance
                .record_success(actual_scope, TokioInstant::now());
        } else {
            self.maintenance
                .record_failure(attempt_scope, TokioInstant::now());
        }
        if let Some(response) = drop_completed_attempt(finished) {
            let publication = self
                .task
                .runtime
                .publication_fence
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let attempt_result = if publication.shutdown || self.task.cancel.is_cancelled() {
                Err(PoiCacheServiceError::Shutdown { attempt_id })
            } else {
                attempt_result
            };
            let _ = response.send(attempt_result);
        }
        enqueue_poi_corpus_compactions(&mut self.compaction_lane, compactions);
        start_next_poi_corpus_compaction(&self.task, &mut self.compaction_lane, self.generation);
    }
}

fn clear_released_public_cache_reset(reset: &mut Option<CancellationToken>) {
    if reset.as_ref().is_some_and(CancellationToken::is_cancelled) {
        *reset = None;
    }
}

async fn wait_for_public_cache_reset_release(reset: &mut Option<CancellationToken>) {
    match reset {
        Some(reset) => reset.cancelled().await,
        None => std::future::pending().await,
    }
}

pub(super) fn publish_active_attempt_progress(
    task: &ChainPoiCacheCoordinator,
    active: Option<&ActivePoiCacheAttempt>,
    event: ChainPoiCacheJobEvent,
) {
    let progress = event.progress;
    let attempt_id = progress.attempt_id;
    let generation = progress.generation;
    if !active.is_some_and(|attempt| attempt.id == attempt_id && attempt.generation == generation) {
        return;
    }
    let publication = task
        .runtime
        .publication_fence
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !publication.shutdown && !task.cancel.is_cancelled() {
        let _ = send_poi_artifact_cache_progress_for_generation(
            &task.progress_tx,
            generation,
            progress,
        );
    }
}

pub(super) fn cancel_active_attempt(
    active: &mut Option<ActivePoiCacheAttempt>,
    error: impl FnOnce(PoiArtifactCacheAttemptId) -> PoiCacheServiceError,
) {
    let Some(attempt) = active.take() else {
        return;
    };
    let ActivePoiCacheAttempt {
        id,
        generation: _,
        scope: _,
        cancel,
        job,
        retry_completion,
    } = attempt;
    cancel.cancel();
    drop(job);
    if let Some(response) = retry_completion {
        let _ = response.send(Err(error(id)));
    }
}

pub(super) fn drop_completed_attempt(
    mut attempt: ActivePoiCacheAttempt,
) -> Option<oneshot::Sender<Result<(), PoiCacheServiceError>>> {
    let retry_completion = attempt.retry_completion.take();
    attempt.cancel.cancel();
    drop(attempt);
    retry_completion
}

async fn wait_for_active_attempt(
    active: &mut Option<ActivePoiCacheAttempt>,
) -> PreparedPoiCacheBatch {
    match active {
        Some(attempt) => (&mut attempt.job).await,
        None => std::future::pending().await,
    }
}

async fn start_chain_poi_cache_attempt(
    task: &mut ChainPoiCacheCoordinator,
    active: &mut Option<ActivePoiCacheAttempt>,
    generation: u64,
    health: &BTreeMap<FixedBytes<32>, PoiSourceHealth>,
    scope: PoiCacheSyncScope,
    retry_completion: Option<oneshot::Sender<Result<(), PoiCacheServiceError>>>,
) -> Result<PoiArtifactCacheAttemptId, PoiCacheServiceError> {
    let Ok(_public_cache_reset_admission) = task.runtime.public_cache_reset_gate.try_read() else {
        return Err(PoiCacheServiceError::CorpusResetInProgress);
    };
    let attempt_id = task.runtime.next_attempt_id();
    let baseline = task.local_caches.read().await.clone();
    let scope = effective_poi_cache_scope(scope, &baseline, &task.active_list_keys);
    let ready = cache_map_available_for_lists(task.chain_id, &baseline, &task.active_list_keys);
    let completed = task
        .active_list_keys
        .iter()
        .filter(|list_key| cache_map_available_for_list(task.chain_id, &baseline, **list_key))
        .count();
    let source_plans = task
        .active_list_keys
        .iter()
        .map(|list_key| {
            let corpus_ready = cache_map_available_for_list(task.chain_id, &baseline, *list_key);
            let plan = health.get(list_key).map_or_else(
                || PoiSourceHealth::new(None).attempt_plan(corpus_ready),
                |health| health.attempt_plan(corpus_ready),
            );
            let plan = if scope.events {
                plan
            } else {
                PoiListAttemptPlan {
                    use_artifact: false,
                    artifact_after_rpc_failure: false,
                }
            };
            (*list_key, plan)
        })
        .collect::<BTreeMap<_, _>>();
    let use_artifact = scope.events && source_plans.values().any(|plan| plan.use_artifact);
    let baseline_list_progress =
        cache_map_list_progress(task.chain_id, &baseline, &task.active_list_keys);
    let (current_event_index, target_event_index) =
        single_list_event_index(&baseline_list_progress);
    let start_progress = new_poi_artifact_cache_progress(
        attempt_id,
        generation,
        task.chain_id,
        if use_artifact {
            PoiArtifactCachePhase::ResolvingManifest
        } else {
            PoiArtifactCachePhase::LiveTailing
        },
        completed,
        task.active_list_keys.len(),
        None,
        current_event_index,
        target_event_index,
        baseline_list_progress,
        PoiArtifactCacheGraphProgress::default(),
        ready,
        None,
    );

    let attempt_cancel = task.cancel.child_token();
    let job = PoiCacheCandidateJob {
        db: Arc::clone(&task.db),
        http_client: task.http_client.clone(),
        poi_rpc_url: task.poi_rpc_url.clone(),
        artifact_config: task.artifact_config.clone(),
        chain_id: task.chain_id,
        active_list_keys: task.active_list_keys.clone(),
        baseline,
        installed_head_anchors: task
            .installed_head_anchors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone(),
        preloaded_caches: std::mem::take(&mut task.preloaded_caches),
        attempt_id,
        generation,
        ready,
        source_plans,
        scope,
        event_tx: task.job_tx.clone(),
        cancel: attempt_cancel.clone(),
        poi_artifact_persistence: task.poi_artifact_persistence.clone(),
    };
    let job = produce_chain_poi_cache_candidates(job)
        .instrument(tracing::info_span!(
            "poi_cache_candidate",
            %attempt_id,
            generation
        ))
        .boxed();
    *active = Some(ActivePoiCacheAttempt {
        id: attempt_id,
        generation,
        scope,
        cancel: attempt_cancel,
        job,
        retry_completion,
    });
    let publication = task
        .runtime
        .publication_fence
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if publication.shutdown || task.cancel.is_cancelled() {
        drop(publication);
        cancel_active_attempt(active, |attempt_id| PoiCacheServiceError::Shutdown {
            attempt_id,
        });
        return Err(PoiCacheServiceError::Shutdown { attempt_id });
    }
    if let Err(error) = send_poi_artifact_cache_progress_for_generation(
        &task.progress_tx,
        generation,
        start_progress,
    ) {
        drop(publication);
        cancel_active_attempt(active, |attempt_id| PoiCacheServiceError::StaleAttempt {
            attempt_id,
        });
        return Err(error);
    }
    drop(publication);
    Ok(attempt_id)
}
