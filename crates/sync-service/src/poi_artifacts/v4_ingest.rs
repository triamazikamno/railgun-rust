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
    CandidateError, CorpusCandidate, FetchedArtifact, ObservedManifest, PoiArtifactError,
    PoiArtifactIngestor, VerifiedCatalog, VerifiedCorpusCandidate,
};
use crate::chain::PoiArtifactPersistenceHandle;
use crate::trustless_artifacts::TrustlessArtifactFetcher;
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
        let fetcher = TrustlessArtifactFetcher::new_poi(&self.client, &self.config.gateway_urls);
        let candidates = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(PoiArtifactError::Cancelled),
            result = fetcher.resolve_ipns_manifest_candidates_with_clock(name, acceptance_time) => result?,
        };
        let mut last_error = None;
        for candidate in candidates {
            let candidate_cid = candidate.cid.to_string();
            let bytes = tokio::select! {
                biased;
                () = cancel.cancelled() => return Err(PoiArtifactError::Cancelled),
                result = fetcher.fetch_manifest_cid(&candidate_cid) => {
                    match result {
                        Ok(bytes) => bytes,
                        Err(error) => {
                            last_error = Some(PoiArtifactError::Trustless(error));
                            continue;
                        }
                    }
                }
            };
            let manifest = match Manifest::read_envelope(&bytes) {
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
                Ok(observed) => return Ok(observed),
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
            .fetch_artifact(
                &entry.checkpoint_catalog.artifact.cid,
                entry.checkpoint_catalog.artifact.byte_size,
                0,
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
            result = persistence.begin_candidate(observed, &catalog) => {
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
                plan.route.descriptors.len(),
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
                        index,
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
        let fetcher = TrustlessArtifactFetcher::new_poi(&self.client, &self.config.gateway_urls);
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
mod tests {
    use super::*;
    use alloy::primitives::FixedBytes;
    use cid::Cid;
    use ed25519_dalek::SigningKey;
    use libp2p_identity::Keypair;
    use local_db::{DbConfig, DbStore};
    use multihash_codetable::{Code, MultihashDigest};
    use poi::artifacts::ArtifactDescriptor;
    use poi::artifacts::v4::{
        ArtifactEncoding, BlockedShieldsDescriptor, CheckpointCatalogDescriptor, Compression,
        EventArtifactKind, EventRange, FORMAT_VERSION,
    };
    use std::fs;
    use std::io::ErrorKind;
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::time::{Duration, UNIX_EPOCH};
    use url::Url;

    static TEMP_DB_COUNTER: AtomicUsize = AtomicUsize::new(0);

    #[tokio::test]
    async fn delayed_stale_first_manifest_does_not_create_watermark() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create delayed stale-first DB root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open delayed stale-first DB"),
        );
        let signing_key = SigningKey::from_bytes(&[0xa1; 32]);
        let publisher = FixedBytes::from(signing_key.verifying_key().to_bytes());
        let manifest = signed_empty_manifest(&signing_key, 9_500, 10);

        let result = fetch_delayed_manifest(Arc::clone(&db), manifest, 10_000, 12_000).await;

        let Err(error) = result else {
            panic!("manifest made stale during response delay must fail");
        };
        assert!(error.to_string().contains("stale"));
        assert!(
            db.get_poi_publisher_manifest_watermark(&publisher)
                .expect("read absent stale-first watermark")
                .is_none()
        );
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove delayed stale-first DB root");
    }

    #[tokio::test]
    async fn delayed_stale_higher_manifest_retains_existing_watermark() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create delayed stale-higher DB root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open delayed stale-higher DB"),
        );
        let signing_key = SigningKey::from_bytes(&[0xa2; 32]);
        let publisher = FixedBytes::from(signing_key.verifying_key().to_bytes());
        let accepted = signed_empty_manifest(&signing_key, 9_500, 10);
        crate::poi_artifacts::test_support::observe_manifest(
            db.as_ref(),
            publisher,
            accepted,
            Some(Duration::from_secs(1)),
            UNIX_EPOCH + Duration::from_secs(10),
        )
        .expect("seed accepted manifest watermark");
        let retained = db
            .get_poi_publisher_manifest_watermark(&publisher)
            .expect("read seeded watermark")
            .expect("seeded watermark");
        let higher = signed_empty_manifest(&signing_key, 10_500, 11);

        let result = fetch_delayed_manifest(Arc::clone(&db), higher, 11_000, 13_000).await;

        let Err(error) = result else {
            panic!("higher manifest made stale during response delay must fail");
        };
        assert!(error.to_string().contains("stale"));
        assert_eq!(
            db.get_poi_publisher_manifest_watermark(&publisher)
                .expect("read retained watermark")
                .expect("retained watermark"),
            retained
        );
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove delayed stale-higher DB root");
    }

    #[tokio::test]
    async fn delayed_aged_exact_manifest_replay_remains_accepted() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create delayed exact-replay DB root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open delayed exact-replay DB"),
        );
        let signing_key = SigningKey::from_bytes(&[0xa3; 32]);
        let publisher = FixedBytes::from(signing_key.verifying_key().to_bytes());
        let manifest = signed_empty_manifest(&signing_key, 9_500, 10);
        crate::poi_artifacts::test_support::observe_manifest(
            db.as_ref(),
            publisher,
            manifest.clone(),
            Some(Duration::from_secs(1)),
            UNIX_EPOCH + Duration::from_secs(10),
        )
        .expect("seed exact manifest watermark");
        let retained = db
            .get_poi_publisher_manifest_watermark(&publisher)
            .expect("read exact replay watermark")
            .expect("exact replay watermark");

        fetch_delayed_manifest(Arc::clone(&db), manifest, 10_000, 12_000)
            .await
            .expect("aged exact sequence and hash replay remains accepted");
        assert_eq!(
            db.get_poi_publisher_manifest_watermark(&publisher)
                .expect("read watermark after exact replay")
                .expect("watermark after exact replay"),
            retained
        );
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove delayed exact-replay DB root");
    }

    #[tokio::test]
    async fn all_expired_ipns_stops_before_manifest_fetch_or_watermark_observation() {
        let root_dir = temp_db_root();
        fs::create_dir_all(&root_dir).expect("create all-expired IPNS DB root");
        let db = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open all-expired IPNS DB"),
        );
        let signing_key = SigningKey::from_bytes(&[0xa4; 32]);
        let publisher = FixedBytes::from(signing_key.verifying_key().to_bytes());
        let ipns_keypair =
            Keypair::ed25519_from_bytes([0xb2; 32]).expect("all-expired IPNS keypair");
        let peer_id = ipns_keypair.public().to_peer_id();
        let ipns_name = Cid::new_v1(0x72, *peer_id.as_ref()).to_string();
        let manifest_cid = delayed_raw_cid(b"manifest must not be fetched");
        let ipns_record = rust_ipns::Record::new(
            &ipns_keypair,
            manifest_cid.to_string(),
            chrono::Duration::seconds(1),
            12,
            60,
        )
        .expect("all-expired IPNS record")
        .encode()
        .expect("encode all-expired IPNS record");
        let (mut gateway, requests) = spawn_ipns_request_sentinel_gateway(ipns_record);
        gateway.set_path("/endpoint-sentinel");
        gateway.set_query(Some("secret=endpoint-sentinel"));
        let ingestor = PoiArtifactIngestor::new(
            crate::types::PoiArtifactSourceConfig {
                trusted_publisher_pubkey: publisher,
                manifest_source: PoiArtifactManifestSource::IpnsName(ipns_name),
                gateway_urls: vec![gateway.into()],
                max_manifest_age: Some(Duration::from_secs(1)),
            },
            reqwest::Client::new(),
        );
        let persistence = PoiArtifactPersistenceHandle::new(
            Arc::clone(&db),
            Arc::new(tokio::sync::Mutex::new(())),
        );
        let accepted_at = SystemTime::now() + Duration::from_mins(1);
        let cancel = CancellationToken::new();
        let result = ingestor
            .fetch_observed_manifest_with_clock(&persistence, &cancel, &|| accepted_at)
            .await;
        let Err(error) = result else {
            panic!("expired IPNS authority must stop POI artifact ingestion");
        };

        assert!(matches!(
            &error,
            PoiArtifactError::Trustless(
                crate::trustless_artifacts::TrustlessArtifactError::ExpiredIpnsRecord { .. }
            )
        ));
        let formatted = format!("{error} {error:?}");
        assert!(!formatted.contains("endpoint-sentinel"));
        let first_path = requests
            .recv_timeout(Duration::from_secs(1))
            .expect("IPNS request path");
        assert!(first_path.contains("/ipns/"));
        assert!(
            requests.recv_timeout(Duration::from_millis(100)).is_err(),
            "expired IPNS candidates must not trigger a manifest CID request"
        );
        assert!(
            db.get_poi_publisher_manifest_watermark(&publisher)
                .expect("read absent all-expired watermark")
                .is_none()
        );
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove all-expired IPNS DB root");
    }

    #[test]
    fn cancellation_is_fail_closed() {
        let cancel = CancellationToken::new();
        assert!(ensure_not_cancelled(&cancel).is_ok());
        cancel.cancel();
        assert!(matches!(
            ensure_not_cancelled(&cancel),
            Err(PoiArtifactError::Cancelled)
        ));
    }

    #[tokio::test]
    async fn biased_cancellation_wins_simultaneous_total_deadline() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let outcome: Result<(), PoiArtifactError> = tokio::select! {
            biased;
            () = cancel.cancelled() => Err(PoiArtifactError::Cancelled),
            result = std::future::ready(Err(PoiArtifactError::Trustless(
                crate::trustless_artifacts::TrustlessArtifactError::HttpAttemptDeadline {
                    origin: crate::trustless_artifacts::TrustlessHttpSource::Gateway {
                        index: 0,
                        count: 1,
                    },
                },
            ))) => result,
        };
        assert!(matches!(outcome, Err(PoiArtifactError::Cancelled)));
    }

    #[test]
    fn diagnostics_do_not_include_sensitive_urls_or_response_bodies() {
        let gateway = Url::parse(
            "https://userinfo-sentinel:password-sentinel@host-sentinel.invalid/path-sentinel?query=query-sentinel#fragment-sentinel",
        )
        .expect("sensitive gateway URL");
        let configured = poi::SensitiveUrl::from(gateway);
        let error = PoiArtifactError::Trustless(
            crate::trustless_artifacts::TrustlessArtifactError::HttpStatus {
                origin: crate::trustless_artifacts::TrustlessHttpSource::Gateway {
                    index: 0,
                    count: 1,
                },
                status: reqwest::StatusCode::BAD_GATEWAY,
            },
        );
        let diagnostic = format!("{error}; gateway={configured:?}");
        for sentinel in [
            "userinfo-sentinel",
            "password-sentinel",
            "host-sentinel",
            "path-sentinel",
            "query-sentinel",
            "fragment-sentinel",
            "raw-response-body-sentinel",
        ] {
            assert!(!diagnostic.contains(sentinel), "leaked {sentinel}");
        }
        assert!(diagnostic.contains("trustless retrieval failed"));
    }

    #[test]
    fn graph_progress_counts_verified_chunks_bytes_and_replay_range() {
        let first = descriptor(0, 9, None, EventArtifactKind::Bridge);
        let second = descriptor(10, 19, Some(first.end_root), EventArtifactKind::Bridge);
        let route = route(
            0,
            19,
            true,
            vec![first.clone(), second.clone()],
            AcquisitionRank::CheckpointRange,
        );
        let plan = RefreshPlan {
            cost: route_cost(&route, 20, &[]).expect("route cost"),
            route,
            cache_hits: Vec::new(),
        };

        let mut progress = graph_progress_for_plan(&plan).expect("progress plan");
        assert_eq!(progress.verified_chunks, 0);
        assert_eq!(progress.total_chunks, 2);
        assert_eq!(
            progress.total_authenticated_encoded_bytes,
            Some(first.artifact.byte_size + second.artifact.byte_size)
        );
        assert_eq!(progress.replay_start_event_index, Some(0));
        assert_eq!(progress.replay_end_event_index, Some(19));
        assert_eq!(progress.total_replay_event_count, 20);

        record_verified_chunk(&mut progress, &second).expect("second verified");
        record_verified_chunk(&mut progress, &first).expect("first verified");
        assert_eq!(progress.verified_chunks, 2);
        assert_eq!(
            progress.verified_encoded_bytes,
            first.artifact.byte_size + second.artifact.byte_size
        );
    }

    #[test]
    fn range_coverage_rejects_forward_gap_and_wrong_boundary_root() {
        let descriptor = descriptor(10, 19, Some(root(0x11)), EventArtifactKind::Bridge);
        assert!(!descriptor_covers_start(&descriptor, 9, &|_| {
            Ok(Some(root(0x11)))
        }));
        assert!(!descriptor_covers_start(&descriptor, 10, &|_| {
            Ok(Some(root(0x12)))
        }));
        assert!(descriptor_covers_start(&descriptor, 15, &|_| {
            Ok(Some(root(0x11)))
        }));
        assert!(!descriptor_covers_start(&descriptor, 15, &|_| {
            Err(CandidateError::MissingRoot { event_index: 9 })
        }));
    }

    #[test]
    fn official_v4_source_rejects_url_and_cid_without_legacy_fallback() {
        let url = PoiArtifactManifestSource::Url(
            Url::parse("https://user:password@example.invalid/legacy?token=secret")
                .expect("URL")
                .into(),
        );
        assert!(matches!(
            ipns_name(&url),
            Err(PoiArtifactError::RequiresIpnsSource)
        ));
        assert!(matches!(
            ipns_name(&PoiArtifactManifestSource::Cid("legacy-cid".into())),
            Err(PoiArtifactError::RequiresIpnsSource)
        ));
        assert_eq!(
            ipns_name(&PoiArtifactManifestSource::IpnsName(
                "derived-v4-name".into()
            ))
            .expect("v4 IPNS"),
            "derived-v4-name"
        );
    }

    #[test]
    fn planner_enumerates_tail_bridge_checkpoint_overlap_and_complete_routes() {
        let checkpoint = descriptor(0, 9, None, EventArtifactKind::Checkpoint);
        let bridge = descriptor(10, 19, Some(root(9)), EventArtifactKind::Bridge);
        let tail = descriptor(
            20,
            29,
            Some(bridge.end_root),
            EventArtifactKind::CurrentTail,
        );
        let entry = entry(30, 20, Some(tail.clone()), vec![bridge.clone()]);

        let bridge_routes = suffix_routes_from_chunks(
            &entry,
            std::slice::from_ref(&checkpoint),
            15,
            |range_start| {
                Ok(if range_start == 0 {
                    None
                } else {
                    Some(root(9))
                })
            },
        );
        assert_eq!(bridge_routes.len(), 1);
        assert_eq!(
            bridge_routes[0].acquisition_rank,
            AcquisitionRank::RetainedBridge
        );
        assert_eq!(bridge_routes[0].descriptors, vec![bridge, tail]);

        let checkpoint_routes =
            suffix_routes_from_chunks(&entry, std::slice::from_ref(&checkpoint), 5, |_| Ok(None));
        assert_eq!(checkpoint_routes.len(), 1);
        assert_eq!(
            checkpoint_routes[0].acquisition_rank,
            AcquisitionRank::CheckpointRange
        );
        assert_eq!(checkpoint_routes[0].replay_start, 5);

        let complete = complete_route_from_chunks(&entry, &[checkpoint]).expect("complete route");
        assert!(complete.restart_from_genesis);
        assert_eq!(complete.descriptors.len(), 2);
    }

    #[test]
    fn planner_excludes_incompatible_tail_bridge_and_checkpoint_suffixes() {
        let tail = descriptor(20, 29, Some(root(0x20)), EventArtifactKind::CurrentTail);
        let tail_entry = entry(30, 20, Some(tail), Vec::new());
        assert!(
            suffix_routes_from_chunks(&tail_entry, &[], 25, |_| Ok(Some(root(0xff)))).is_empty()
        );

        let bridge = descriptor(10, 19, Some(root(0x10)), EventArtifactKind::Bridge);
        let bridge_entry = entry(20, 10, None, vec![bridge]);
        assert!(
            suffix_routes_from_chunks(&bridge_entry, &[], 15, |_| Ok(Some(root(0xff)))).is_empty()
        );

        let checkpoint = descriptor(
            32_768,
            65_535,
            Some(root(0x40)),
            EventArtifactKind::Checkpoint,
        );
        let checkpoint_entry = entry(65_536, 65_536, None, Vec::new());
        assert!(
            suffix_routes_from_chunks(
                &checkpoint_entry,
                std::slice::from_ref(&checkpoint),
                50_000,
                |_| Ok(Some(root(0xff))),
            )
            .is_empty()
        );
        assert!(
            suffix_routes_from_chunks(
                &checkpoint_entry,
                std::slice::from_ref(&checkpoint),
                50_000,
                |_| {
                    Err(CandidateError::MissingRoot {
                        event_index: 32_767,
                    })
                },
            )
            .is_empty()
        );
    }

    #[test]
    fn incompatible_suffix_selects_complete_restart_route() {
        let first_checkpoint = descriptor(0, 32_767, None, EventArtifactKind::Checkpoint);
        let second_checkpoint = descriptor(
            32_768,
            65_535,
            Some(first_checkpoint.end_root),
            EventArtifactKind::Checkpoint,
        );
        let tail = descriptor(
            65_536,
            65_545,
            Some(second_checkpoint.end_root),
            EventArtifactKind::CurrentTail,
        );
        let entry = entry(65_546, 65_536, Some(tail), Vec::new());
        let checkpoints = vec![first_checkpoint, second_checkpoint];
        let mut routes =
            suffix_routes_from_chunks(&entry, &checkpoints, 50_000, |_| Ok(Some(root(0xff))));
        assert!(routes.is_empty());
        routes.push(
            complete_route_from_chunks(&entry, &checkpoints).expect("complete restart route"),
        );

        let selected = select_lowest_cost_plan(routes, entry.event_count, &[], 50_000)
            .expect("select complete restart fallback");
        assert!(selected.route.restart_from_genesis);
        assert_eq!(selected.route.replay_start, 0);
    }

    #[test]
    fn current_tip_and_root_select_no_event_fetch() {
        let tail = descriptor(10, 19, Some(root(9)), EventArtifactKind::CurrentTail);
        let entry = entry(20, 10, Some(tail), Vec::new());
        let plan = no_replay_plan(&entry, 20, entry.current_root, true).expect("no-replay plan");
        assert!(plan.route.descriptors.is_empty());
        assert_eq!(plan.cost.network_request_count, 0);
        assert_eq!(plan.cost.replay_event_count, 0);
        assert!(no_replay_plan(&entry, 20, Some(root(0xff)), true).is_none());
        assert!(no_replay_plan(&entry, 20, entry.current_root, false).is_none());
    }

    #[test]
    fn equal_tip_canonical_boundary_mismatch_selects_complete_restart() {
        let checkpoint = descriptor(0, 9, None, EventArtifactKind::Checkpoint);
        let entry = entry(10, 10, None, Vec::new());
        assert!(no_replay_plan(&entry, 10, entry.current_root, false).is_none());
        let complete = complete_route_from_chunks(&entry, std::slice::from_ref(&checkpoint))
            .expect("complete equal-tip restart");
        let selected = select_lowest_cost_plan(vec![complete], entry.event_count, &[], 10)
            .expect("select complete equal-tip restart");
        assert!(selected.route.restart_from_genesis);
        assert_eq!(selected.route.replay_start, 0);
        assert_eq!(selected.route.replay_end, 9);
    }

    #[test]
    fn expired_bridge_has_no_suffix_route_and_falls_back_to_complete_replay() {
        let checkpoint = descriptor(0, 9, None, EventArtifactKind::Checkpoint);
        let bridge = descriptor(10, 19, Some(root(9)), EventArtifactKind::Bridge);
        let tail = descriptor(
            20,
            29,
            Some(bridge.end_root),
            EventArtifactKind::CurrentTail,
        );
        let entry = entry(30, 20, Some(tail), vec![bridge]);
        assert!(suffix_routes_from_chunks(&entry, &[], 5, |_| Ok(None)).is_empty());
        assert!(complete_route_from_chunks(&entry, &[checkpoint]).is_ok());
    }

    #[test]
    fn current_tail_suffix_is_preferred_for_cursor_inside_tail() {
        let tail = descriptor(10, 19, Some(root(9)), EventArtifactKind::CurrentTail);
        let entry = entry(20, 10, Some(tail.clone()), Vec::new());
        let routes = suffix_routes_from_chunks(&entry, &[], 15, |_| Ok(Some(root(9))));
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].acquisition_rank, AcquisitionRank::CurrentTail);
        assert_eq!(routes[0].descriptors, vec![tail]);
    }

    #[test]
    fn exact_cache_hits_are_costed_after_replay_route_selection() {
        let first = descriptor(0, 9, None, EventArtifactKind::Bridge);
        let second = descriptor(10, 19, Some(first.end_root), EventArtifactKind::Bridge);
        let route = route(
            0,
            19,
            true,
            vec![first.clone(), second.clone()],
            AcquisitionRank::CheckpointRange,
        );
        let missing = route_cost(&route, 20, &[]).expect("missing cost");
        let partial = route_cost(&route, 20, std::slice::from_ref(&first)).expect("partial cost");
        let exact = route_cost(&route, 20, &[first, second]).expect("exact cost");
        assert_eq!(missing.network_request_count, 2);
        assert_eq!(partial.network_request_count, 1);
        assert_eq!(exact.network_request_count, 0);
        assert_eq!(missing.replay_event_count, exact.replay_event_count);
    }

    #[test]
    fn cached_checkpoint_route_beats_uncached_bridge_for_same_suffix() {
        let checkpoint = descriptor(0, 9, None, EventArtifactKind::Bridge);
        let mut bridge = descriptor(0, 9, None, EventArtifactKind::Bridge);
        bridge.artifact.cid = "bafy-bridge-route".into();
        let checkpoint_route = route(
            5,
            9,
            false,
            vec![checkpoint.clone()],
            AcquisitionRank::CheckpointRange,
        );
        let bridge_route = route(5, 9, false, vec![bridge], AcquisitionRank::RetainedBridge);
        assert!(
            route_cost(&checkpoint_route, 10, &[checkpoint]).expect("checkpoint cost")
                < route_cost(&bridge_route, 10, &[]).expect("bridge cost")
        );
    }

    #[test]
    fn out_of_order_fetch_results_are_buffered_by_authenticated_position() {
        let mut buffered = BTreeMap::new();
        buffered.insert(2, "third");
        buffered.insert(0, "first");
        buffered.insert(1, "second");
        assert_eq!(
            buffered.into_values().collect::<Vec<_>>(),
            ["first", "second", "third"]
        );
    }

    #[test]
    fn failed_window_does_not_produce_a_partial_ordered_result() {
        let results: [Result<(usize, &str), &str>; 3] =
            [Ok((2, "third")), Err("failed chunk"), Ok((0, "first"))];
        let mut buffered = BTreeMap::new();
        let outcome = results.into_iter().try_for_each(|result| {
            let (index, value) = result?;
            buffered.insert(index, value);
            Ok::<_, &str>(())
        });
        assert_eq!(outcome, Err("failed chunk"));
        assert!(!buffered.contains_key(&1));
    }

    async fn fetch_delayed_manifest(
        db: Arc<DbStore>,
        manifest: Manifest,
        request_started_at_ms: u64,
        accepted_at_ms: u64,
    ) -> Result<ObservedManifest, PoiArtifactError> {
        let publisher = manifest.publisher_pubkey;
        let manifest_bytes = manifest.to_bytes().expect("encode delayed manifest");
        let manifest_cid = delayed_raw_cid(&manifest_bytes);
        let ipns_keypair =
            Keypair::ed25519_from_bytes([0xb1; 32]).expect("delayed manifest IPNS keypair");
        let peer_id = ipns_keypair.public().to_peer_id();
        let ipns_name = Cid::new_v1(0x72, *peer_id.as_ref()).to_string();
        let ipns_record = rust_ipns::Record::new(
            &ipns_keypair,
            manifest_cid.to_string(),
            chrono::Duration::seconds(60 * 60 * 24 * 365),
            manifest.sequence,
            60,
        )
        .expect("delayed manifest IPNS record")
        .encode()
        .expect("encode delayed manifest IPNS record");
        let manifest_car = delayed_raw_car(manifest_cid, &manifest_bytes);
        let (gateway, manifest_request_started, release_manifest) =
            spawn_delayed_manifest_gateway(ipns_record, manifest_car);
        let persistence =
            PoiArtifactPersistenceHandle::new(db, Arc::new(tokio::sync::Mutex::new(())));
        let ingestor = PoiArtifactIngestor::new(
            crate::types::PoiArtifactSourceConfig {
                trusted_publisher_pubkey: publisher,
                manifest_source: PoiArtifactManifestSource::IpnsName(ipns_name),
                gateway_urls: vec![gateway.into()],
                max_manifest_age: Some(Duration::from_secs(1)),
            },
            reqwest::Client::new(),
        );
        let clock = Arc::new(AtomicU64::new(request_started_at_ms));
        let acceptance_time = || UNIX_EPOCH + Duration::from_millis(clock.load(Ordering::SeqCst));
        let cancel = CancellationToken::new();
        let fetch =
            ingestor.fetch_observed_manifest_with_clock(&persistence, &cancel, &acceptance_time);
        let release_clock = Arc::clone(&clock);
        let release = async move {
            tokio::task::spawn_blocking(move || {
                manifest_request_started.recv_timeout(Duration::from_secs(2))
            })
            .await
            .expect("join delayed manifest request wait")
            .expect("delayed manifest request");
            release_clock.store(accepted_at_ms, Ordering::SeqCst);
            release_manifest
                .send(())
                .expect("release delayed manifest response");
        };
        let (result, ()) = tokio::join!(fetch, release);
        result
    }

    fn signed_empty_manifest(
        signing_key: &SigningKey,
        issued_at_ms: u64,
        sequence: u64,
    ) -> Manifest {
        let publisher = FixedBytes::from(signing_key.verifying_key().to_bytes());
        let mut manifest = Manifest::new(issued_at_ms, sequence, publisher, Vec::new());
        manifest
            .sign_manifest(signing_key)
            .expect("sign delayed manifest");
        manifest
    }

    fn delayed_raw_cid(bytes: &[u8]) -> Cid {
        Cid::new_v1(0x55, Code::Sha2_256.digest(bytes))
    }

    fn delayed_raw_car(root: Cid, block: &[u8]) -> Vec<u8> {
        let header = delayed_car_header(root);
        let cid_bytes = root.to_bytes();
        let mut car = Vec::new();
        delayed_write_varint(header.len(), &mut car);
        car.extend_from_slice(&header);
        delayed_write_varint(cid_bytes.len() + block.len(), &mut car);
        car.extend_from_slice(&cid_bytes);
        car.extend_from_slice(block);
        car
    }

    fn delayed_car_header(root: Cid) -> Vec<u8> {
        let mut header = Vec::new();
        header.push(0xa2);
        delayed_write_cbor_text("roots", &mut header);
        header.push(0x81);
        header.extend_from_slice(&[0xd8, 0x2a]);
        let mut cid_link = vec![0_u8];
        cid_link.extend_from_slice(&root.to_bytes());
        delayed_write_cbor_bytes(&cid_link, &mut header);
        delayed_write_cbor_text("version", &mut header);
        header.push(0x01);
        header
    }

    fn delayed_write_cbor_text(value: &str, out: &mut Vec<u8>) {
        delayed_write_cbor_len(0x60, value.len(), out);
        out.extend_from_slice(value.as_bytes());
    }

    fn delayed_write_cbor_bytes(value: &[u8], out: &mut Vec<u8>) {
        delayed_write_cbor_len(0x40, value.len(), out);
        out.extend_from_slice(value);
    }

    fn delayed_write_cbor_len(major: u8, len: usize, out: &mut Vec<u8>) {
        match len {
            0..=23 => out.push(major | u8::try_from(len).expect("small delayed CBOR length")),
            24..=0xff => out.extend_from_slice(&[
                major | 0x18,
                u8::try_from(len).expect("u8 delayed CBOR length"),
            ]),
            0x100..=0xffff => {
                out.push(major | 0x19);
                out.extend_from_slice(
                    &u16::try_from(len)
                        .expect("u16 delayed CBOR length")
                        .to_be_bytes(),
                );
            }
            _ => panic!("delayed CAR fixture length is too large"),
        }
    }

    fn delayed_write_varint(mut value: usize, out: &mut Vec<u8>) {
        while value >= 0x80 {
            out.push((u8::try_from(value & 0x7f).expect("delayed varint byte")) | 0x80);
            value >>= 7;
        }
        out.push(u8::try_from(value).expect("delayed final varint byte"));
    }

    fn spawn_ipns_request_sentinel_gateway(
        ipns_record: Vec<u8>,
    ) -> (Url, std::sync::mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind IPNS request sentinel");
        let url = Url::parse(&format!(
            "http://{}",
            listener.local_addr().expect("IPNS sentinel address")
        ))
        .expect("IPNS sentinel URL");
        let (request_tx, requests) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept IPNS sentinel request");
            let path = read_test_request_path(&mut stream);
            request_tx.send(path).expect("record IPNS request path");
            write_test_response(&mut stream, 200, &ipns_record);

            listener
                .set_nonblocking(true)
                .expect("set IPNS sentinel nonblocking");
            let deadline = std::time::Instant::now() + Duration::from_millis(500);
            while std::time::Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let path = read_test_request_path(&mut stream);
                        request_tx
                            .send(path)
                            .expect("record unexpected manifest request path");
                        write_test_response(&mut stream, 500, &[]);
                        break;
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("accept IPNS sentinel follow-up request: {error}"),
                }
            }
        });
        (url, requests)
    }

    fn read_test_request_path(stream: &mut std::net::TcpStream) -> String {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let read = std::io::Read::read(stream, &mut buffer).expect("read test HTTP request");
            assert!(read > 0, "client closed test HTTP request");
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        String::from_utf8_lossy(&request)
            .split_whitespace()
            .nth(1)
            .expect("test HTTP request path")
            .to_string()
    }

    fn write_test_response(stream: &mut std::net::TcpStream, status: u16, body: &[u8]) {
        let reason = if status == 200 { "OK" } else { "ERROR" };
        let headers = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        std::io::Write::write_all(stream, headers.as_bytes()).expect("write test HTTP headers");
        std::io::Write::write_all(stream, body).expect("write test HTTP body");
    }

    fn spawn_delayed_manifest_gateway(
        ipns_record: Vec<u8>,
        manifest_car: Vec<u8>,
    ) -> (
        Url,
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind delayed manifest gateway");
        let url = Url::parse(&format!(
            "http://{}",
            listener
                .local_addr()
                .expect("delayed manifest gateway address")
        ))
        .expect("delayed manifest gateway URL");
        let (manifest_request_tx, manifest_request_started) = std::sync::mpsc::channel();
        let (release_manifest, release_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for (index, body) in [ipns_record, manifest_car].into_iter().enumerate() {
                let (mut stream, _) = listener.accept().expect("accept delayed gateway request");
                let mut request = Vec::new();
                let mut buffer = [0_u8; 1024];
                loop {
                    let read = std::io::Read::read(&mut stream, &mut buffer)
                        .expect("read delayed gateway request");
                    assert!(read > 0, "client closed delayed gateway request");
                    request.extend_from_slice(&buffer[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                if index == 1 {
                    manifest_request_tx
                        .send(())
                        .expect("record delayed manifest request");
                    release_rx.recv().expect("release delayed manifest body");
                }
                let headers = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                std::io::Write::write_all(&mut stream, headers.as_bytes())
                    .expect("write delayed gateway headers");
                std::io::Write::write_all(&mut stream, &body).expect("write delayed gateway body");
            }
        });
        (url, manifest_request_started, release_manifest)
    }

    fn descriptor(
        start_index: u64,
        end_index: u64,
        start_root: Option<alloy::primitives::FixedBytes<32>>,
        kind: EventArtifactKind,
    ) -> EventArtifactDescriptor {
        let row_count = end_index - start_index + 1;
        let txid_version = "V2_PoseidonMerkle";
        let byte_size = 147 + txid_version.len() as u64 + row_count * 97;

        EventArtifactDescriptor {
            artifact: ArtifactDescriptor {
                cid: format!("bafy-{start_index}-{end_index}"),
                sha256: [0x22; 32].into(),
                byte_size,
            },
            format_version: FORMAT_VERSION,
            scope: scope(),
            kind,
            range: EventRange {
                start_index,
                end_index,
            },
            row_count,
            encoding: ArtifactEncoding::PoiEventBinary,
            compression: Compression::Identity,
            start_root,
            end_root: [0x44; 32].into(),
        }
    }

    fn entry(
        event_count: u64,
        checkpoint_count: u64,
        current_tail: Option<EventArtifactDescriptor>,
        retained_bridges: Vec<EventArtifactDescriptor>,
    ) -> ManifestEntry {
        let checkpoint_root = (checkpoint_count != 0).then(|| root(0x55));
        ManifestEntry {
            scope: scope(),
            event_count,
            current_tip_index: Some(event_count - 1),
            current_root: current_tail
                .as_ref()
                .map_or(checkpoint_root, |tail| Some(tail.end_root)),
            checkpoint_catalog: CheckpointCatalogDescriptor {
                artifact: ArtifactDescriptor {
                    cid: "bafy-catalog".into(),
                    sha256: root(0x66),
                    byte_size: 1,
                },
                format_version: FORMAT_VERSION,
                scope: scope(),
                range: (checkpoint_count != 0).then(|| EventRange {
                    start_index: 0,
                    end_index: checkpoint_count - 1,
                }),
                row_count: checkpoint_count,
                chunk_count: u64::from(checkpoint_count != 0),
                encoding: ArtifactEncoding::CanonicalJson,
                compression: Compression::Identity,
                checkpoint_root,
            },
            current_tail,
            retained_bridges,
            blocked_shields: BlockedShieldsDescriptor {
                artifact: ArtifactDescriptor {
                    cid: "bafy-blocked".into(),
                    sha256: root(0x77),
                    byte_size: 1,
                },
                format_version: FORMAT_VERSION,
                scope: scope(),
                row_count: 0,
                encoding: ArtifactEncoding::CanonicalJson,
                compression: Compression::Identity,
            },
        }
    }

    fn temp_db_root() -> PathBuf {
        let unique = TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "sync-service-poi-v4-ingest-{}-{unique}",
            std::process::id()
        ))
    }

    fn scope() -> Scope {
        Scope::new(root(0x33), 0, 1, "V2_PoseidonMerkle")
    }

    fn root(byte: u8) -> FixedBytes<32> {
        [byte; 32].into()
    }
}
