use std::collections::BTreeMap;
use std::time::SystemTime;

use futures::{StreamExt, stream};
use poi::artifacts::v4::{
    EventArtifactDescriptor, Manifest, ManifestEntry, Scope, checked_event_plan_limits,
};
use poi::cache::PoiCacheIdentity;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use super::{
    CandidateError, CorpusCandidate, ExpectedPoiCorpusBase, FetchedArtifact, ObservedManifest,
    PersistedPoiArtifactCache, PoiArtifactError, PoiArtifactIngestor, VerifiedCatalog,
    VerifiedCorpusCandidate,
};
use crate::chain::PoiArtifactPersistenceHandle;
use crate::types::{
    PoiArtifactCacheGraphProgress, PoiArtifactCachePhase, PoiArtifactManifestSource,
};

const FETCH_CONCURRENCY: usize = 6;
const MAX_GATEWAY_ATTEMPTS: usize = 3;
const MAX_INFLIGHT_ENCODED_BYTES: u64 =
    FETCH_CONCURRENCY as u64 * poi::artifacts::v4::EVENT_ARTIFACT_MAX_BYTES;
pub(crate) struct PreparedIngestion {
    pub(crate) candidate: VerifiedCorpusCandidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum AcquisitionRank {
    CurrentTail,
    RetainedBridge,
    CheckpointRange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct PlanCost {
    network_rounds: u64,
    authenticated_encoded_bytes: u64,
    network_request_count: u64,
    replay_event_count: u64,
    acquisition_rank: AcquisitionRank,
}

#[derive(Debug, Clone)]
struct AcquisitionRoute {
    replay_start: u64,
    replay_end: u64,
    restart_from_genesis: bool,
    descriptors: Vec<EventArtifactDescriptor>,
    acquisition_rank: AcquisitionRank,
}

#[derive(Debug, Clone)]
struct RefreshPlan {
    route: AcquisitionRoute,
    cache_hits: Vec<EventArtifactDescriptor>,
    cost: PlanCost,
}

impl PoiArtifactIngestor {
    pub(crate) async fn fetch_observed_manifest(
        &self,
        persistence: &PoiArtifactPersistenceHandle,
        cancel: &CancellationToken,
    ) -> Result<ObservedManifest, PoiArtifactError> {
        self.fetch_observed_manifest_with_clock(persistence, cancel, &SystemTime::now)
            .await
    }

    async fn fetch_observed_manifest_with_clock<F>(
        &self,
        persistence: &PoiArtifactPersistenceHandle,
        cancel: &CancellationToken,
        acceptance_time: &F,
    ) -> Result<ObservedManifest, PoiArtifactError>
    where
        F: Fn() -> SystemTime + Sync + ?Sized,
    {
        let name = ipns_name(&self.config.manifest_source)?;
        // A record below the durable sequence would fail as rollback, so it
        // must not close IPNS resolution early.
        let sequence_floor = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(PoiArtifactError::Cancelled),
            result = persistence.publisher_manifest_sequence(self.config.trusted_publisher_pubkey) => {
                result.map_err(persistence_error)?
            }
        };
        let fetcher = self.fetcher();
        let candidates = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(PoiArtifactError::Cancelled),
            result = fetcher.resolve_ipns_manifest_candidates_with_clock(
                name,
                sequence_floor,
                acceptance_time,
            ) => result?,
        };
        let mut last_error = None;
        for candidate in candidates {
            let candidate_cid = candidate.cid.to_string();
            let fetched = tokio::select! {
                biased;
                () = cancel.cancelled() => return Err(PoiArtifactError::Cancelled),
                result = fetcher.fetch_manifest_cid_with_metadata_from_gateway(
                    &candidate_cid,
                    Some(candidate.gateway_index()),
                ) => {
                    match result {
                        Ok(fetched) => fetched,
                        Err(error) => {
                            last_error = Some(PoiArtifactError::Trustless(error));
                            continue;
                        }
                    }
                }
            };
            let manifest = match Manifest::read_envelope(fetched.bytes()) {
                Ok(manifest) => manifest,
                Err(error) => {
                    last_error = Some(PoiArtifactError::Format(error));
                    continue;
                }
            };
            let observation = tokio::select! {
                biased;
                () = cancel.cancelled() => return Err(PoiArtifactError::Cancelled),
                result = persistence.observe_manifest_with_clock(
                    self.config.trusted_publisher_pubkey,
                    manifest,
                    self.config.max_manifest_age,
                    acceptance_time,
                ) => result,
            };
            match observation {
                Ok(mut observed) => {
                    observed.set_serving_gateway_index(fetched.gateway_index());
                    return Ok(observed);
                }
                Err(error) => last_error = Some(persistence_error(error)),
            }
        }
        Err(last_error.unwrap_or(PoiArtifactError::NoGateways))
    }

    pub(crate) async fn prepare_cache_with_observed_manifest(
        &self,
        persistence: &PoiArtifactPersistenceHandle,
        identity: PoiCacheIdentity,
        observed: &ObservedManifest,
        persisted: Option<PersistedPoiArtifactCache>,
        expected_base: ExpectedPoiCorpusBase,
        expected_generation: u64,
        cancel: &CancellationToken,
    ) -> Result<Option<PreparedIngestion>, PoiArtifactError> {
        ensure_not_cancelled(cancel)?;
        let scope = Scope::new(
            identity.list_key,
            identity.chain_type,
            identity.chain_id,
            identity.txid_version.clone(),
        );
        let entry = observed.entry(&scope)?.clone();
        self.report_progress(
            PoiArtifactCachePhase::VerifyingCatalog,
            None,
            entry.current_tip_index,
            PoiArtifactCacheGraphProgress::default(),
        );
        let catalog_fetched = self
            .fetch_catalog(
                &entry.checkpoint_catalog.artifact.cid,
                entry.checkpoint_catalog.artifact.byte_size,
                observed.serving_gateway_index(),
                cancel,
            )
            .await?;
        let catalog = persistence
            .verify_checkpoint_catalog(observed, &scope, catalog_fetched)
            .map_err(persistence_error)?;
        if entry.event_count == 0 {
            return Ok(None);
        }

        self.report_progress(
            PoiArtifactCachePhase::Planning,
            None,
            entry.current_tip_index,
            PoiArtifactCacheGraphProgress::default(),
        );
        let mut candidate = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(PoiArtifactError::Cancelled),
            result = persistence.begin_candidate_from_starting(
                observed,
                &catalog,
                persisted,
                expected_base,
                expected_generation,
            ) => {
                result.map_err(persistence_error)?
            }
        };
        let plan = if candidate.next_event_index() > entry.event_count {
            if candidate.root_at(entry.event_count - 1) != entry.current_root {
                return Err(PoiArtifactError::CorpusTipRootConflict {
                    tip_index: entry.event_count - 1,
                });
            }
            candidate.preserve_ahead_events();
            ahead_no_replay_plan(&entry, candidate.next_event_index())
        } else {
            select_refresh_plan(persistence, observed, &catalog, &candidate, cancel).await?
        };
        if plan.route.restart_from_genesis {
            candidate.restart_from_genesis();
        }
        let (candidate, graph_progress) = self
            .execute_event_plan(
                persistence,
                observed,
                &catalog,
                &scope,
                &plan,
                candidate,
                cancel,
            )
            .await?;

        ensure_not_cancelled(cancel)?;
        self.report_progress(
            PoiArtifactCachePhase::DownloadingChunks,
            candidate.next_event_index().checked_sub(1),
            entry.current_tip_index,
            graph_progress,
        );
        let blocked = self
            .fetch_artifact(
                &entry.blocked_shields.artifact.cid,
                entry.blocked_shields.artifact.byte_size,
                observed
                    .serving_gateway_index()
                    .unwrap_or(plan.route.descriptors.len()),
                cancel,
            )
            .await?;
        let blocked = persistence
            .verify_blocked_shields(observed, &scope, blocked)
            .map_err(persistence_error)?;
        let candidate = candidate.install_blocked_shields(&blocked)?;
        self.report_progress(
            PoiArtifactCachePhase::Validating,
            candidate.next_event_index().checked_sub(1),
            entry.current_tip_index,
            graph_progress,
        );
        let candidate = candidate.finish()?;
        Ok(Some(PreparedIngestion { candidate }))
    }

    async fn execute_event_plan(
        &self,
        persistence: &PoiArtifactPersistenceHandle,
        observed: &ObservedManifest,
        catalog: &VerifiedCatalog,
        scope: &Scope,
        plan: &RefreshPlan,
        mut candidate: CorpusCandidate,
        cancel: &CancellationToken,
    ) -> Result<(CorpusCandidate, PoiArtifactCacheGraphProgress), PoiArtifactError> {
        let replay_origin = candidate.next_event_index();
        let mut progress = graph_progress_for_plan(plan)?;
        self.report_progress(
            PoiArtifactCachePhase::DownloadingChunks,
            candidate.next_event_index().checked_sub(1),
            catalog.entry().current_tip_index,
            progress,
        );
        let mut cursor = 0_usize;
        while cursor < plan.route.descriptors.len() {
            ensure_not_cancelled(cancel)?;
            let descriptor = &plan.route.descriptors[cursor];
            if plan.cache_hits.contains(descriptor) {
                let current = persistence
                    .current_graph_chunk(observed, scope, Some(catalog), descriptor)
                    .map_err(persistence_error)?;
                let chunk = tokio::select! {
                    biased;
                    () = cancel.cancelled() => return Err(PoiArtifactError::Cancelled),
                    result = persistence.cached_chunk(&current) => {
                        result.map_err(persistence_error)?
                    }
                }
                .ok_or(PoiArtifactError::NoReplayRoute {
                    start_index: candidate.next_event_index(),
                })?;
                record_verified_chunk(&mut progress, descriptor)?;
                self.report_progress(
                    PoiArtifactCachePhase::DownloadingChunks,
                    candidate.next_event_index().checked_sub(1),
                    catalog.entry().current_tip_index,
                    progress,
                );
                candidate = candidate.replay_chunk(&chunk)?;
                progress.replayed_event_count = candidate
                    .next_event_index()
                    .saturating_sub(replay_origin)
                    .min(progress.total_replay_event_count);
                self.report_progress(
                    PoiArtifactCachePhase::ReplayingRanges,
                    candidate.next_event_index().checked_sub(1),
                    catalog.entry().current_tip_index,
                    progress,
                );
                cursor += 1;
                continue;
            }

            let mut window = Vec::new();
            let mut encoded_bytes = 0_u64;
            for (index, descriptor) in plan.route.descriptors[cursor..].iter().enumerate() {
                if plan.cache_hits.contains(descriptor) {
                    break;
                }
                encoded_bytes = encoded_bytes
                    .checked_add(descriptor.artifact.byte_size)
                    .ok_or(PoiArtifactError::PlanOverflow)?;
                if encoded_bytes > MAX_INFLIGHT_ENCODED_BYTES {
                    return Err(PoiArtifactError::InflightByteLimit);
                }
                let current = persistence
                    .current_graph_chunk(observed, scope, Some(catalog), descriptor)
                    .map_err(persistence_error)?;
                window.push((cursor + index, current));
                if window.len() == FETCH_CONCURRENCY {
                    break;
                }
            }
            let fetches = stream::iter(window.into_iter().map(|(index, current)| async move {
                let descriptor = current.descriptor();
                let fetched = self
                    .fetch_artifact(
                        &descriptor.artifact.cid,
                        descriptor.artifact.byte_size,
                        observed.serving_gateway_index().unwrap_or(index),
                        cancel,
                    )
                    .await?;
                let chunk = persistence
                    .verify_fetched_chunk(current, fetched)
                    .and_then(|chunk| persistence.verify_event_signatures(chunk))
                    .map_err(persistence_error)?;
                Ok::<_, PoiArtifactError>((index, chunk))
            }))
            .buffer_unordered(FETCH_CONCURRENCY);
            tokio::pin!(fetches);
            let mut buffered = BTreeMap::new();
            while let Some(result) = fetches.next().await {
                let (index, chunk) = result?;
                ensure_not_cancelled(cancel)?;
                if catalog.chunks().contains(&plan.route.descriptors[index]) {
                    let retained = tokio::select! {
                        biased;
                        () = cancel.cancelled() => return Err(PoiArtifactError::Cancelled),
                        result = persistence.retain_chunk_for_attempt(&chunk, cancel) => {
                            result.map_err(persistence_error)?
                        }
                    };
                    if retained.is_none() {
                        return Err(PoiArtifactError::Cancelled);
                    }
                }
                record_verified_chunk(&mut progress, &plan.route.descriptors[index])?;
                self.report_progress(
                    PoiArtifactCachePhase::DownloadingChunks,
                    candidate.next_event_index().checked_sub(1),
                    catalog.entry().current_tip_index,
                    progress,
                );
                buffered.insert(index, chunk);
            }
            while cursor < plan.route.descriptors.len() {
                if let Some(chunk) = buffered.remove(&cursor) {
                    candidate = candidate.replay_chunk(&chunk)?;
                    progress.replayed_event_count = candidate
                        .next_event_index()
                        .saturating_sub(replay_origin)
                        .min(progress.total_replay_event_count);
                    self.report_progress(
                        PoiArtifactCachePhase::ReplayingRanges,
                        candidate.next_event_index().checked_sub(1),
                        catalog.entry().current_tip_index,
                        progress,
                    );
                    cursor += 1;
                    continue;
                }
                if plan.cache_hits.contains(&plan.route.descriptors[cursor]) {
                    break;
                }
                break;
            }
        }
        Ok((candidate, progress))
    }

    async fn fetch_artifact(
        &self,
        cid: &str,
        byte_size: u64,
        preferred_gateway_index: usize,
        cancel: &CancellationToken,
    ) -> Result<FetchedArtifact, PoiArtifactError> {
        let fetcher = self.fetcher();
        let fetched = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(PoiArtifactError::Cancelled),
            result = fetcher.fetch_artifact_cid_with_metadata_from_gateway_bounded(
                cid,
                byte_size,
                preferred_gateway_index,
                MAX_GATEWAY_ATTEMPTS,
            ) => result?,
        };
        Ok(FetchedArtifact::from_trustless(fetched))
    }

    /// Fetches a checkpoint catalog, starting at the gateway that served the
    /// manifest and hedging gateways that stall before responding.
    async fn fetch_catalog(
        &self,
        cid: &str,
        byte_size: u64,
        preferred_gateway_index: Option<usize>,
        cancel: &CancellationToken,
    ) -> Result<FetchedArtifact, PoiArtifactError> {
        let fetcher = self.fetcher();
        let fetched = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(PoiArtifactError::Cancelled),
            result = fetcher.fetch_catalog_cid_with_metadata_hedged(
                cid,
                byte_size,
                preferred_gateway_index,
                MAX_GATEWAY_ATTEMPTS,
            ) => result?,
        };
        Ok(FetchedArtifact::from_trustless(fetched))
    }
}

fn graph_progress_for_plan(
    plan: &RefreshPlan,
) -> Result<PoiArtifactCacheGraphProgress, PoiArtifactError> {
    let total_authenticated_encoded_bytes =
        plan.route
            .descriptors
            .iter()
            .try_fold(0_u64, |total, descriptor| {
                total
                    .checked_add(descriptor.artifact.byte_size)
                    .ok_or(PoiArtifactError::PlanOverflow)
            })?;
    let has_replay = plan.cost.replay_event_count > 0;
    Ok(PoiArtifactCacheGraphProgress {
        verified_chunks: 0,
        total_chunks: plan.route.descriptors.len(),
        verified_encoded_bytes: 0,
        total_authenticated_encoded_bytes: Some(total_authenticated_encoded_bytes),
        replay_start_event_index: has_replay.then_some(plan.route.replay_start),
        replay_end_event_index: has_replay.then_some(plan.route.replay_end),
        replayed_event_count: 0,
        total_replay_event_count: plan.cost.replay_event_count,
    })
}

fn record_verified_chunk(
    progress: &mut PoiArtifactCacheGraphProgress,
    descriptor: &EventArtifactDescriptor,
) -> Result<(), PoiArtifactError> {
    progress.verified_chunks = progress
        .verified_chunks
        .checked_add(1)
        .ok_or(PoiArtifactError::PlanOverflow)?;
    progress.verified_encoded_bytes = progress
        .verified_encoded_bytes
        .checked_add(descriptor.artifact.byte_size)
        .ok_or(PoiArtifactError::PlanOverflow)?;
    Ok(())
}

async fn select_refresh_plan(
    persistence: &PoiArtifactPersistenceHandle,
    observed: &ObservedManifest,
    catalog: &VerifiedCatalog,
    candidate: &CorpusCandidate,
    cancel: &CancellationToken,
) -> Result<RefreshPlan, PoiArtifactError> {
    let entry = catalog.entry();
    let start = candidate.next_event_index();
    let current_root = candidate.current_root();
    if let Some(plan) = no_replay_plan(
        entry,
        start,
        current_root,
        start == entry.event_count && candidate.validate_canonical_boundaries().is_ok(),
    ) {
        return Ok(plan);
    }

    let mut routes = suffix_routes(entry, catalog, candidate);
    routes.push(complete_route(entry, catalog)?);
    let mut unique = Vec::<AcquisitionRoute>::new();
    for route in routes {
        if !unique.iter().any(|existing| {
            existing.replay_start == route.replay_start
                && existing.restart_from_genesis == route.restart_from_genesis
                && existing.descriptors == route.descriptors
        }) {
            unique.push(route);
        }
    }

    let mut cache_hits = Vec::new();
    for descriptor in catalog.chunks() {
        let current = persistence
            .current_graph_chunk(observed, &entry.scope, Some(catalog), descriptor)
            .map_err(persistence_error)?;
        let cached = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(PoiArtifactError::Cancelled),
            result = persistence.cached_chunk(&current) => {
                result.map_err(persistence_error)?
            }
        };
        if cached.is_some() {
            cache_hits.push(descriptor.clone());
        }
    }

    let selected = select_lowest_cost_plan(unique, entry.event_count, &cache_hits, start)?;
    debug!(
        replay_start = selected.route.replay_start,
        replay_end = selected.route.replay_end,
        requests = selected.cost.network_request_count,
        encoded_bytes = selected.cost.authenticated_encoded_bytes,
        replay_events = selected.cost.replay_event_count,
        "selected authenticated POI artifact refresh plan"
    );
    Ok(selected)
}

fn select_lowest_cost_plan(
    routes: Vec<AcquisitionRoute>,
    event_count: u64,
    cache_hits: &[EventArtifactDescriptor],
    start: u64,
) -> Result<RefreshPlan, PoiArtifactError> {
    routes
        .into_iter()
        .map(|route| {
            let cost = route_cost(&route, event_count, cache_hits)?;
            Ok(RefreshPlan {
                cache_hits: route
                    .descriptors
                    .iter()
                    .filter(|descriptor| cache_hits.contains(descriptor))
                    .cloned()
                    .collect(),
                route,
                cost,
            })
        })
        .collect::<Result<Vec<_>, PoiArtifactError>>()?
        .into_iter()
        .min_by_key(|plan| plan.cost)
        .ok_or(PoiArtifactError::NoReplayRoute { start_index: start })
}

fn no_replay_plan(
    entry: &ManifestEntry,
    start: u64,
    current_root: Option<alloy::primitives::FixedBytes<32>>,
    canonical_boundaries_match: bool,
) -> Option<RefreshPlan> {
    if start != entry.event_count {
        return None;
    }
    if current_root != entry.current_root || !canonical_boundaries_match {
        return None;
    }
    Some(RefreshPlan {
        route: AcquisitionRoute {
            replay_start: start,
            replay_end: start.saturating_sub(1),
            restart_from_genesis: false,
            descriptors: Vec::new(),
            acquisition_rank: AcquisitionRank::CurrentTail,
        },
        cache_hits: Vec::new(),
        cost: PlanCost {
            network_rounds: 0,
            authenticated_encoded_bytes: 0,
            network_request_count: 0,
            replay_event_count: 0,
            acquisition_rank: AcquisitionRank::CurrentTail,
        },
    })
}

const fn ahead_no_replay_plan(entry: &ManifestEntry, start: u64) -> RefreshPlan {
    RefreshPlan {
        route: AcquisitionRoute {
            replay_start: start,
            replay_end: entry.event_count.saturating_sub(1),
            restart_from_genesis: false,
            descriptors: Vec::new(),
            acquisition_rank: AcquisitionRank::CurrentTail,
        },
        cache_hits: Vec::new(),
        cost: PlanCost {
            network_rounds: 0,
            authenticated_encoded_bytes: 0,
            network_request_count: 0,
            replay_event_count: 0,
            acquisition_rank: AcquisitionRank::CurrentTail,
        },
    }
}

fn suffix_routes(
    entry: &ManifestEntry,
    catalog: &VerifiedCatalog,
    candidate: &CorpusCandidate,
) -> Vec<AcquisitionRoute> {
    suffix_routes_from_chunks(
        entry,
        catalog.chunks(),
        candidate.next_event_index(),
        |range_start| candidate.expected_descriptor_start_root(range_start),
    )
}

fn suffix_routes_from_chunks<F>(
    entry: &ManifestEntry,
    checkpoint_chunks: &[EventArtifactDescriptor],
    start: u64,
    expected_start_root: F,
) -> Vec<AcquisitionRoute>
where
    F: Fn(u64) -> Result<Option<alloy::primitives::FixedBytes<32>>, CandidateError>,
{
    if start == 0 || start >= entry.event_count {
        return Vec::new();
    }
    let mut routes = Vec::new();
    if let Some(tail) = entry.current_tail.as_ref()
        && descriptor_covers_start(tail, start, &expected_start_root)
    {
        routes.push(route(
            start,
            entry.event_count - 1,
            false,
            vec![tail.clone()],
            AcquisitionRank::CurrentTail,
        ));
    }
    if let Some(first) = entry
        .retained_bridges
        .iter()
        .position(|descriptor| descriptor_covers_start(descriptor, start, &expected_start_root))
    {
        let mut descriptors = entry.retained_bridges[first..].to_vec();
        if let Some(tail) = entry.current_tail.as_ref() {
            descriptors.push(tail.clone());
        }
        routes.push(route(
            start,
            entry.event_count - 1,
            false,
            descriptors,
            AcquisitionRank::RetainedBridge,
        ));
    }
    if let Some(first) = checkpoint_chunks
        .iter()
        .position(|descriptor| descriptor_covers_start(descriptor, start, &expected_start_root))
    {
        let mut descriptors = checkpoint_chunks[first..].to_vec();
        if let Some(tail) = entry.current_tail.as_ref() {
            descriptors.push(tail.clone());
        }
        routes.push(route(
            start,
            entry.event_count - 1,
            false,
            descriptors,
            AcquisitionRank::CheckpointRange,
        ));
    }
    routes
}

fn complete_route(
    entry: &ManifestEntry,
    catalog: &VerifiedCatalog,
) -> Result<AcquisitionRoute, PoiArtifactError> {
    complete_route_from_chunks(entry, catalog.chunks())
}

fn complete_route_from_chunks(
    entry: &ManifestEntry,
    checkpoint_chunks: &[EventArtifactDescriptor],
) -> Result<AcquisitionRoute, PoiArtifactError> {
    let mut descriptors = checkpoint_chunks.to_vec();
    if let Some(tail) = entry.current_tail.as_ref() {
        descriptors.push(tail.clone());
    }
    if descriptors.is_empty() {
        return Err(PoiArtifactError::NoReplayRoute { start_index: 0 });
    }
    Ok(route(
        0,
        entry.event_count - 1,
        true,
        descriptors,
        if checkpoint_chunks.is_empty() {
            AcquisitionRank::CurrentTail
        } else {
            AcquisitionRank::CheckpointRange
        },
    ))
}

const fn route(
    replay_start: u64,
    replay_end: u64,
    restart_from_genesis: bool,
    descriptors: Vec<EventArtifactDescriptor>,
    acquisition_rank: AcquisitionRank,
) -> AcquisitionRoute {
    AcquisitionRoute {
        replay_start,
        replay_end,
        restart_from_genesis,
        descriptors,
        acquisition_rank,
    }
}

fn descriptor_covers_start<F>(
    descriptor: &EventArtifactDescriptor,
    start: u64,
    expected_start_root: &F,
) -> bool
where
    F: Fn(u64) -> Result<Option<alloy::primitives::FixedBytes<32>>, CandidateError>,
{
    descriptor.range.start_index <= start
        && start <= descriptor.range.end_index
        && expected_start_root(descriptor.range.start_index)
            .is_ok_and(|expected| descriptor.start_root == expected)
}

fn route_cost(
    route: &AcquisitionRoute,
    event_count: u64,
    cache_hits: &[EventArtifactDescriptor],
) -> Result<PlanCost, PoiArtifactError> {
    let missing = route
        .descriptors
        .iter()
        .filter(|descriptor| !cache_hits.contains(descriptor))
        .collect::<Vec<_>>();
    let limits = checked_event_plan_limits(missing.iter().copied())?;
    let requests = u64::try_from(missing.len()).map_err(|_| PoiArtifactError::PlanOverflow)?;
    let rounds = requests
        .checked_add((FETCH_CONCURRENCY - 1) as u64)
        .ok_or(PoiArtifactError::PlanOverflow)?
        / FETCH_CONCURRENCY as u64;
    Ok(PlanCost {
        network_rounds: rounds,
        authenticated_encoded_bytes: limits.encoded_bytes,
        network_request_count: requests,
        replay_event_count: event_count
            .checked_sub(route.replay_start)
            .ok_or(PoiArtifactError::PlanOverflow)?,
        acquisition_rank: route.acquisition_rank,
    })
}

fn ipns_name(source: &PoiArtifactManifestSource) -> Result<&str, PoiArtifactError> {
    match source {
        PoiArtifactManifestSource::IpnsName(name) => Ok(name),
        PoiArtifactManifestSource::Url(_) | PoiArtifactManifestSource::Cid(_) => {
            Err(PoiArtifactError::RequiresIpnsSource)
        }
    }
}

fn ensure_not_cancelled(cancel: &CancellationToken) -> Result<(), PoiArtifactError> {
    if cancel.is_cancelled() {
        Err(PoiArtifactError::Cancelled)
    } else {
        Ok(())
    }
}

#[allow(clippy::needless_pass_by_value)]
fn persistence_error(error: impl std::fmt::Display) -> PoiArtifactError {
    PoiArtifactError::Persistence {
        reason: error.to_string(),
    }
}

#[cfg(test)]
mod tests;
