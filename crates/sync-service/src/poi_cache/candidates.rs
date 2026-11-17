//! POI cache candidate jobs: artifact and public-range candidates for each active list.

use std::collections::BTreeMap;
use std::ops::ControlFlow;
use std::sync::Arc;

use alloy::hex;
use alloy::primitives::FixedBytes;
use broadcaster_core::transact::DEFAULT_TXID_VERSION;
use local_db::{DbStore, PoiArtifactCacheRecord, PoiCorpusJournalHeadRecord};
use poi::SensitiveUrl;
use poi::cache::{
    POI_EVENTS_PAGE_SIZE, POI_MERKLETREE_LEAVES_PAGE_SIZE, PoiCache, PoiCacheError,
    PoiCacheIdentity, PoiCacheJournalDelta, PoiCacheSyncOutcome,
};
use poi::poi::{BlockedShield, PoiRpcClient};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::chain::PoiArtifactPersistenceHandle;
use crate::poi_artifacts::{
    ExpectedPoiCorpusBase, ObservedManifest, PersistedPoiArtifactCache, PoiArtifactError,
    PoiArtifactIngestor, PreparedIngestion, load_persisted_cache_candidate_for_publisher,
};
use crate::types::{
    PoiArtifactCacheAttemptId, PoiArtifactCacheGraphProgress, PoiArtifactCachePhase,
    PoiArtifactSourceConfig,
};
use crate::wallet::wallet_poi_status_client;

use super::progress::{
    cache_map_list_progress, list_progress_with_active_event, new_poi_artifact_cache_progress,
};
use super::schedule::PoiCacheSyncScope;
use super::source_health::{PoiListAttemptPlan, PoiListSourceOutcome, PoiRpcAttemptOutcome};
use super::{ChainPoiCacheJobEvent, EVM_CHAIN_TYPE};

pub(super) struct PoiRpcSyncResult {
    pub(super) outcome: PoiCacheSyncOutcome,
    pub(super) candidate: Option<PoiRpcCandidate>,
}

pub(super) struct PoiRpcCandidate {
    pub(super) cache: PoiCache,
    pub(super) delta: PoiCacheJournalDelta,
    pub(super) blocked_shields: Option<Vec<BlockedShield>>,
}

pub(super) enum PreparedPoiCachePersistence {
    Artifact {
        prepared: Box<PreparedIngestion>,
    },
    PublicRpc {
        prepared: Box<PreparedPublicRpcPersistence>,
    },
}

pub(super) struct PreparedPublicRpcPersistence {
    pub(super) range_start_index: u64,
    pub(super) expected_base: ExpectedPoiCorpusBase,
    pub(super) starting_record: Option<PoiArtifactCacheRecord>,
    pub(super) starting_head: Option<PoiCorpusJournalHeadRecord>,
    pub(super) delta: PoiCacheJournalDelta,
    pub(super) blocked_shields: Option<Vec<BlockedShield>>,
}

impl PreparedPoiCachePersistence {
    pub(super) const fn artifact_manifest_sequence(&self) -> Option<u64> {
        match self {
            Self::Artifact { prepared } => Some(prepared.candidate.manifest_sequence()),
            Self::PublicRpc { .. } => None,
        }
    }
}

pub(super) struct PreparedPoiCacheCandidate {
    pub(super) list_key: FixedBytes<32>,
    pub(super) cache: Option<PoiCache>,
    pub(super) persistence: PreparedPoiCachePersistence,
}

pub(super) struct PreparedPoiCacheBatch {
    pub(super) candidates: Vec<PreparedPoiCacheCandidate>,
    pub(super) source_outcomes: Vec<PoiListSourceOutcome>,
    pub(super) actual_scope: PoiCacheSyncScope,
    pub(super) result: Result<(), String>,
}

pub(super) struct PoiCacheCandidateJob {
    pub(super) db: Arc<DbStore>,
    pub(super) http_client: Option<reqwest::Client>,
    pub(super) poi_rpc_url: SensitiveUrl,
    pub(super) artifact_config: PoiArtifactSourceConfig,
    pub(super) chain_id: u64,
    pub(super) active_list_keys: Vec<FixedBytes<32>>,
    pub(super) baseline: BTreeMap<FixedBytes<32>, PoiCache>,
    pub(super) installed_head_anchors: BTreeMap<FixedBytes<32>, PoiCorpusJournalHeadRecord>,
    pub(super) preloaded_caches: BTreeMap<FixedBytes<32>, PersistedPoiArtifactCache>,
    pub(super) attempt_id: PoiArtifactCacheAttemptId,
    pub(super) generation: u64,
    pub(super) ready: bool,
    pub(super) source_plans: BTreeMap<FixedBytes<32>, PoiListAttemptPlan>,
    pub(super) scope: PoiCacheSyncScope,
    pub(super) event_tx: mpsc::UnboundedSender<ChainPoiCacheJobEvent>,
    pub(super) cancel: CancellationToken,
    pub(super) poi_artifact_persistence: PoiArtifactPersistenceHandle,
}

impl PoiCacheCandidateJob {
    /// Takes the list's installed and preloaded caches out of the job and
    /// returns its persisted cache with the corpus base it expects, loading
    /// the stored candidate when none was preloaded.
    fn take_persisted_cache(
        &mut self,
        list_key: FixedBytes<32>,
        identity: &PoiCacheIdentity,
    ) -> Result<(Option<PersistedPoiArtifactCache>, ExpectedPoiCorpusBase), PoiArtifactError> {
        let installed_cache = self.baseline.remove(&list_key);
        match self.preloaded_caches.remove(&list_key) {
            Some(persisted) => {
                let expected = persisted.expected_base();
                Ok((Some(persisted), expected))
            }
            None => load_persisted_cache_candidate_for_publisher(
                self.db.as_ref(),
                identity,
                self.artifact_config.trusted_publisher_pubkey,
                installed_cache,
                self.installed_head_anchors.get(&list_key),
            ),
        }
    }
}

pub(super) async fn produce_chain_poi_cache_candidates(
    job: PoiCacheCandidateJob,
) -> PreparedPoiCacheBatch {
    let mut producer = PoiCacheCandidateProducer::new(job);
    let list_keys = producer.job.active_list_keys.clone();
    for (list_index, list_key) in list_keys.into_iter().enumerate() {
        let Some((plan, artifact, public_range)) = producer.list_start(list_index, list_key) else {
            continue;
        };
        let step = if producer.job.scope.events && plan.use_artifact {
            producer.artifact_first(artifact, public_range).await
        } else {
            producer.range_first(plan, artifact, public_range).await
        };
        if step.is_break() {
            break;
        }
    }
    producer.finish()
}

/// One list's artifact candidate inputs, with the list's position in the attempt.
pub(super) struct ArtifactCandidateRequest {
    pub(super) list_index: usize,
    pub(super) list_key: FixedBytes<32>,
    pub(super) identity: PoiCacheIdentity,
    pub(super) persisted: Option<PersistedPoiArtifactCache>,
    pub(super) expected_base: ExpectedPoiCorpusBase,
}

/// The cache one list's public-range catch-up starts from, and what its
/// candidate persists against.
pub(super) struct PublicRangeStart {
    pub(super) cache: PoiCache,
    pub(super) range_start_index: u64,
    pub(super) expected_base: ExpectedPoiCorpusBase,
    pub(super) starting_record: Option<PoiArtifactCacheRecord>,
    pub(super) starting_head: Option<PoiCorpusJournalHeadRecord>,
}

/// A candidate job in progress: its clients and the batch built so far.
pub(super) struct PoiCacheCandidateProducer {
    pub(super) job: PoiCacheCandidateJob,
    pub(super) client: reqwest::Client,
    pub(super) rpc_client: PoiRpcClient,
    pub(super) candidates: Vec<PreparedPoiCacheCandidate>,
    pub(super) source_outcomes: Vec<PoiListSourceOutcome>,
    pub(super) errors: Vec<String>,
    pub(super) observed_manifest: Option<ObservedManifest>,
    pub(super) actual_scope: PoiCacheSyncScope,
}

impl PoiCacheCandidateProducer {
    pub(super) fn new(job: PoiCacheCandidateJob) -> Self {
        let client = job.http_client.clone().unwrap_or_default();
        let rpc_client = wallet_poi_status_client(&job.poi_rpc_url, job.http_client.as_ref());
        Self {
            client,
            rpc_client,
            candidates: Vec::with_capacity(job.active_list_keys.len()),
            source_outcomes: Vec::with_capacity(job.active_list_keys.len()),
            errors: Vec::new(),
            observed_manifest: None,
            actual_scope: job.scope,
            job,
        }
    }

    /// The list's source plan and starting points, taking its installed and
    /// preloaded caches out of the job. `None`, with the error recorded, when
    /// its persisted cache fails to load.
    fn list_start(
        &mut self,
        list_index: usize,
        list_key: FixedBytes<32>,
    ) -> Option<(
        PoiListAttemptPlan,
        ArtifactCandidateRequest,
        PublicRangeStart,
    )> {
        let plan = self
            .job
            .source_plans
            .get(&list_key)
            .copied()
            .expect("active POI list has a source plan");
        let identity = PoiCacheIdentity::new(
            EVM_CHAIN_TYPE,
            self.job.chain_id,
            DEFAULT_TXID_VERSION,
            list_key,
        );
        let (persisted, expected_base) = match self.job.take_persisted_cache(list_key, &identity) {
            Ok(persisted) => persisted,
            Err(err) => {
                self.errors.push(err.to_string());
                return None;
            }
        };
        let starting_record = persisted
            .as_ref()
            .map(PersistedPoiArtifactCache::metadata_only);
        let starting_head = persisted
            .as_ref()
            .and_then(|persisted| persisted.journal_head.clone());
        let (artifact_starting, baseline_cache) =
            if plan.use_artifact || plan.artifact_after_rpc_failure {
                let baseline_cache = persisted.as_ref().map_or_else(
                    || PoiCache::new(identity.clone()),
                    |persisted| persisted.cache.clone(),
                );
                (persisted, baseline_cache)
            } else {
                (
                    None,
                    persisted.map_or_else(
                        || PoiCache::new(identity.clone()),
                        |persisted| persisted.cache,
                    ),
                )
            };
        let public_range = PublicRangeStart {
            range_start_index: baseline_cache.progress().next_event_index,
            cache: baseline_cache,
            expected_base,
            starting_record,
            starting_head,
        };
        let artifact = ArtifactCandidateRequest {
            list_index,
            list_key,
            identity,
            persisted: artifact_starting,
            expected_base,
        };
        Some((plan, artifact, public_range))
    }

    /// Prepares the list from the artifact, falling back to the public range
    /// when the artifact fails for a reason other than cancellation.
    async fn artifact_first(
        &mut self,
        artifact: ArtifactCandidateRequest,
        public_range: PublicRangeStart,
    ) -> ControlFlow<()> {
        let list_key = artifact.list_key;
        match Box::pin(prepare_artifact_candidate(
            &self.job,
            &self.client,
            artifact,
            &mut self.observed_manifest,
        ))
        .await
        {
            Ok(candidate) => self.record_artifact(list_key, candidate, None),
            Err(artifact_error) if self.artifact_cancelled(&artifact_error) => {
                self.errors.push(artifact_error.to_string());
                return ControlFlow::Break(());
            }
            Err(artifact_error) => {
                warn!(chain_id = self.job.chain_id, list_key = %hex::encode(list_key), %artifact_error, "artifact candidate failed; trying public range fallback");
                if let Err(rpc_error) = self.catch_up_public_range(list_key, public_range).await {
                    let rpc_error = poi_cache_error_diagnostic(&rpc_error);
                    self.record_sources_failed(
                        list_key,
                        format!(
                            "artifact refresh failed: {artifact_error}; public range catch-up failed: {rpc_error}"
                        ),
                    );
                }
            }
        }
        ControlFlow::Continue(())
    }

    /// Catches the list up over the public range, falling back to the
    /// artifact when the range fails and the plan allows it.
    async fn range_first(
        &mut self,
        plan: PoiListAttemptPlan,
        artifact: ArtifactCandidateRequest,
        public_range: PublicRangeStart,
    ) -> ControlFlow<()> {
        let list_key = artifact.list_key;
        emit_candidate_progress(
            &self.job,
            artifact.list_index,
            list_key,
            PoiArtifactCachePhase::LiveTailing,
            public_range
                .cache
                .progress()
                .next_event_index
                .checked_sub(1),
            None,
        );
        let Err(rpc_error) = self.catch_up_public_range(list_key, public_range).await else {
            return ControlFlow::Continue(());
        };
        let rpc_error = poi_cache_error_diagnostic(&rpc_error);
        if !plan.artifact_after_rpc_failure {
            self.record_sources_failed(
                list_key,
                format!("public range catch-up failed: {rpc_error}"),
            );
            return ControlFlow::Continue(());
        }
        match Box::pin(prepare_artifact_candidate(
            &self.job,
            &self.client,
            artifact,
            &mut self.observed_manifest,
        ))
        .await
        {
            Ok(candidate) => {
                self.record_artifact(list_key, candidate, Some(PoiRpcAttemptOutcome::Failed));
            }
            Err(artifact_error) if self.artifact_cancelled(&artifact_error) => {
                self.errors.push(artifact_error.to_string());
                return ControlFlow::Break(());
            }
            Err(artifact_error) => self.record_sources_failed(
                list_key,
                format!(
                    "public range catch-up failed: {rpc_error}; artifact refresh failed: {artifact_error}"
                ),
            ),
        }
        ControlFlow::Continue(())
    }

    /// Runs the list's public-range catch-up and records its success; a
    /// failure is returned unrecorded.
    async fn catch_up_public_range(
        &mut self,
        list_key: FixedBytes<32>,
        start: PublicRangeStart,
    ) -> Result<(), PoiCacheError> {
        let result =
            public_rpc_candidate_cache(&self.rpc_client, start.cache, self.job.scope).await?;
        self.source_outcomes.push(PoiListSourceOutcome {
            list_key,
            rpc: Some(PoiRpcAttemptOutcome::Succeeded {
                backlog_large: result.outcome.event_page_budget_exhausted,
            }),
            artifact_succeeded: false,
        });
        if let Some(candidate) = result.candidate {
            self.candidates.push(PreparedPoiCacheCandidate {
                list_key,
                cache: Some(candidate.cache),
                persistence: PreparedPoiCachePersistence::PublicRpc {
                    prepared: Box::new(PreparedPublicRpcPersistence {
                        range_start_index: start.range_start_index,
                        expected_base: start.expected_base,
                        starting_record: start.starting_record,
                        starting_head: start.starting_head,
                        delta: candidate.delta,
                        blocked_shields: candidate.blocked_shields,
                    }),
                },
            });
        }
        Ok(())
    }

    /// Records an artifact success after `rpc`, the public-range outcome that preceded it.
    fn record_artifact(
        &mut self,
        list_key: FixedBytes<32>,
        candidate: Option<PreparedPoiCacheCandidate>,
        rpc: Option<PoiRpcAttemptOutcome>,
    ) {
        self.actual_scope = self.actual_scope.union(PoiCacheSyncScope::FULL);
        if let Some(candidate) = candidate {
            self.candidates.push(candidate);
        }
        self.source_outcomes.push(PoiListSourceOutcome {
            list_key,
            rpc,
            artifact_succeeded: true,
        });
    }

    /// Records that every source tried for the list failed.
    fn record_sources_failed(&mut self, list_key: FixedBytes<32>, error: String) {
        self.source_outcomes.push(PoiListSourceOutcome {
            list_key,
            rpc: Some(PoiRpcAttemptOutcome::Failed),
            artifact_succeeded: false,
        });
        self.errors.push(error);
    }

    fn artifact_cancelled(&self, error: &PoiArtifactError) -> bool {
        matches!(error, PoiArtifactError::Cancelled) || self.job.cancel.is_cancelled()
    }

    fn finish(self) -> PreparedPoiCacheBatch {
        let result = if self.errors.is_empty() {
            Ok(())
        } else {
            Err(self.errors.join("; "))
        };
        PreparedPoiCacheBatch {
            candidates: self.candidates,
            source_outcomes: self.source_outcomes,
            actual_scope: self.actual_scope,
            result,
        }
    }
}

async fn prepare_artifact_candidate(
    job: &PoiCacheCandidateJob,
    client: &reqwest::Client,
    request: ArtifactCandidateRequest,
    observed_manifest: &mut Option<ObservedManifest>,
) -> Result<Option<PreparedPoiCacheCandidate>, PoiArtifactError> {
    let ingestor = PoiArtifactIngestor::new(job.artifact_config.clone(), client.clone())
        .with_progress_observer({
            let event_tx = job.event_tx.clone();
            let active_list_keys = job.active_list_keys.clone();
            let baseline = cache_map_list_progress(job.chain_id, &job.baseline, &active_list_keys);
            let attempt_id = job.attempt_id;
            let generation = job.generation;
            let chain_id = job.chain_id;
            let ready = job.ready;
            move |event| {
                let list_progress = list_progress_with_active_event(
                    &active_list_keys,
                    &baseline,
                    request.list_key,
                    event.current_event_index,
                    event.target_event_index,
                );
                let _ = event_tx.send(ChainPoiCacheJobEvent {
                    progress: new_poi_artifact_cache_progress(
                        attempt_id,
                        generation,
                        chain_id,
                        event.phase,
                        request.list_index,
                        active_list_keys.len(),
                        Some(request.list_key),
                        event.current_event_index,
                        event.target_event_index,
                        list_progress,
                        event.graph,
                        ready,
                        None,
                    ),
                });
            }
        });
    if observed_manifest.is_none() {
        *observed_manifest = Some(
            ingestor
                .fetch_observed_manifest(&job.poi_artifact_persistence, &job.cancel)
                .await?,
        );
    }
    let prepared = ingestor
        .prepare_cache_with_observed_manifest(
            &job.poi_artifact_persistence,
            request.identity,
            observed_manifest
                .as_ref()
                .expect("observed manifest initialized"),
            request.persisted,
            request.expected_base,
            job.generation,
            &job.cancel,
        )
        .await?;
    Ok(prepared.map(|prepared| PreparedPoiCacheCandidate {
        list_key: request.list_key,
        cache: None,
        persistence: PreparedPoiCachePersistence::Artifact {
            prepared: Box::new(prepared),
        },
    }))
}

fn emit_candidate_progress(
    job: &PoiCacheCandidateJob,
    list_index: usize,
    list_key: FixedBytes<32>,
    phase: PoiArtifactCachePhase,
    current_event_index: Option<u64>,
    target_event_index: Option<u64>,
) {
    let baseline = cache_map_list_progress(job.chain_id, &job.baseline, &job.active_list_keys);
    let list_progress = list_progress_with_active_event(
        &job.active_list_keys,
        &baseline,
        list_key,
        current_event_index,
        target_event_index,
    );
    let _ = job.event_tx.send(ChainPoiCacheJobEvent {
        progress: new_poi_artifact_cache_progress(
            job.attempt_id,
            job.generation,
            job.chain_id,
            phase,
            list_index,
            job.active_list_keys.len(),
            Some(list_key),
            current_event_index,
            target_event_index,
            list_progress,
            PoiArtifactCacheGraphProgress::default(),
            job.ready,
            None,
        ),
    });
}

pub(super) fn poi_cache_error_diagnostic(error: &PoiCacheError) -> String {
    let PoiCacheError::Rpc(error) = error else {
        return error.to_string();
    };
    if let Some(code) = error.json_rpc_code() {
        return format!("POI cache RPC JSON-RPC error {code}");
    }
    if let Some(status) = error.status() {
        return format!("POI cache RPC HTTP {status}");
    }
    if let Some(phase) = error.transport_phase() {
        return format!("POI cache RPC failed during {phase}");
    }
    "POI cache RPC failed".to_string()
}

pub(super) async fn public_rpc_candidate_cache(
    client: &PoiRpcClient,
    cache: PoiCache,
    scope: PoiCacheSyncScope,
) -> Result<PoiRpcSyncResult, PoiCacheError> {
    let (mut cache, result) = match scope {
        PoiCacheSyncScope {
            events: true,
            blocked_shields: true,
        } => {
            cache
                .sync_bounded_with_journal(
                    client,
                    POI_EVENTS_PAGE_SIZE,
                    POI_MERKLETREE_LEAVES_PAGE_SIZE,
                    crate::poi_limits::POI_RPC_EVENT_PAGE_LIMIT,
                )
                .await?
        }
        PoiCacheSyncScope {
            events: true,
            blocked_shields: false,
        } => {
            cache
                .sync_events_bounded_with_journal(
                    client,
                    POI_EVENTS_PAGE_SIZE,
                    POI_MERKLETREE_LEAVES_PAGE_SIZE,
                    crate::poi_limits::POI_RPC_EVENT_PAGE_LIMIT,
                )
                .await?
        }
        PoiCacheSyncScope {
            events: false,
            blocked_shields: true,
        } => cache.sync_blocked_shields_with_journal(client).await?,
        PoiCacheSyncScope {
            events: false,
            blocked_shields: false,
        } => unreachable!("empty POI cache synchronization scope"),
    };
    if cache.progress().next_event_index == 0 {
        return Ok(PoiRpcSyncResult {
            outcome: result.outcome,
            candidate: None,
        });
    }
    if cache.progress().next_event_index > 0
        && cache.validated_roots().is_none()
        && !cache.validate_roots(client).await?
    {
        return Err(PoiCacheError::InvalidRoots);
    }
    let candidate = result.outcome.changed.then_some(PoiRpcCandidate {
        cache,
        delta: result.delta,
        blocked_shields: result.blocked_shields,
    });
    Ok(PoiRpcSyncResult {
        outcome: result.outcome,
        candidate,
    })
}
