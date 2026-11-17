//! Per-list POI source health and the attempt plans it chooses.

use std::collections::BTreeMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use alloy::hex;
use alloy::primitives::FixedBytes;
use broadcaster_core::transact::DEFAULT_TXID_VERSION;
use local_db::DbStore;
use poi::cache::PoiCacheIdentity;
use tracing::warn;

use crate::poi_artifacts::{PersistedPoiArtifactCache, load_poi_rpc_health};

use super::EVM_CHAIN_TYPE;

const POI_ARTIFACT_RPC_FAILURE_THRESHOLD: u32 = 3;

const POI_ARTIFACT_RPC_STALE_AFTER: Duration = Duration::from_mins(5);

pub(super) struct PoiSourceHealth {
    pub(super) consecutive_rpc_failures: u32,
    pub(super) rpc_stale_at: Option<Instant>,
    pub(super) observed_since: Instant,
    pub(super) artifact_acceleration_needed: bool,
    pub(super) force_rpc_probe: bool,
}

impl PoiSourceHealth {
    pub(super) fn new(rpc_stale_at: Option<Instant>) -> Self {
        Self {
            consecutive_rpc_failures: 0,
            rpc_stale_at,
            observed_since: Instant::now(),
            artifact_acceleration_needed: false,
            force_rpc_probe: false,
        }
    }

    pub(super) fn artifact_eligible(&self) -> bool {
        self.consecutive_rpc_failures >= POI_ARTIFACT_RPC_FAILURE_THRESHOLD
            || self.artifact_acceleration_needed
            || self.rpc_stale_at.map_or_else(
                || self.observed_since.elapsed() >= POI_ARTIFACT_RPC_STALE_AFTER,
                |stale_at| Instant::now() >= stale_at,
            )
    }

    fn rpc_recently_healthy(&self) -> bool {
        self.rpc_stale_at
            .is_some_and(|stale_at| Instant::now() < stale_at)
    }

    pub(super) fn attempt_plan(&self, corpus_ready: bool) -> PoiListAttemptPlan {
        if !corpus_ready && !self.force_rpc_probe && !self.rpc_recently_healthy() {
            return PoiListAttemptPlan {
                use_artifact: true,
                artifact_after_rpc_failure: false,
            };
        }
        let force_rpc_probe = self.force_rpc_probe;
        PoiListAttemptPlan {
            use_artifact: !force_rpc_probe && self.artifact_eligible(),
            artifact_after_rpc_failure: !force_rpc_probe
                && self.consecutive_rpc_failures.saturating_add(1)
                    >= POI_ARTIFACT_RPC_FAILURE_THRESHOLD,
        }
    }

    pub(super) fn record(&mut self, outcome: &PoiListSourceOutcome) {
        if let Some(rpc) = outcome.rpc {
            self.force_rpc_probe = false;
            match rpc {
                PoiRpcAttemptOutcome::Succeeded { backlog_large } => {
                    self.artifact_acceleration_needed = backlog_large;
                    self.consecutive_rpc_failures = 0;
                    let now = Instant::now();
                    self.rpc_stale_at = now.checked_add(POI_ARTIFACT_RPC_STALE_AFTER).or(Some(now));
                }
                PoiRpcAttemptOutcome::Failed => {
                    self.artifact_acceleration_needed = false;
                    self.consecutive_rpc_failures = self.consecutive_rpc_failures.saturating_add(1);
                }
            }
        }
        if outcome.artifact_succeeded {
            self.artifact_acceleration_needed = false;
            self.force_rpc_probe = true;
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct PoiListAttemptPlan {
    pub(super) use_artifact: bool,
    pub(super) artifact_after_rpc_failure: bool,
}

#[derive(Clone, Copy)]
pub(super) enum PoiRpcAttemptOutcome {
    Succeeded { backlog_large: bool },
    Failed,
}

#[derive(Clone, Copy)]
pub(super) struct PoiListSourceOutcome {
    pub(super) list_key: FixedBytes<32>,
    pub(super) rpc: Option<PoiRpcAttemptOutcome>,
    pub(super) artifact_succeeded: bool,
}

pub(super) fn source_health_for_lists(
    db: &DbStore,
    chain_id: u64,
    generation: u64,
    active_list_keys: &[FixedBytes<32>],
    preloaded: &BTreeMap<FixedBytes<32>, PersistedPoiArtifactCache>,
) -> BTreeMap<FixedBytes<32>, PoiSourceHealth> {
    active_list_keys
        .iter()
        .map(|list_key| {
            let identity =
                PoiCacheIdentity::new(EVM_CHAIN_TYPE, chain_id, DEFAULT_TXID_VERSION, *list_key);
            let legacy_timestamp = preloaded
                .get(list_key)
                .and_then(|persisted| persisted.record.legacy_last_successful_rpc_sync_at_ms);
            let timestamp = match load_poi_rpc_health(db, &identity, generation, legacy_timestamp) {
                Ok(timestamp) => timestamp,
                Err(err) => {
                    warn!(
                        ?err,
                        chain_id,
                        list_key = %hex::encode(list_key),
                        "failed to load advisory PPOI RPC health"
                    );
                    None
                }
            };
            let rpc_stale_at = persisted_rpc_stale_at(timestamp);
            (*list_key, PoiSourceHealth::new(rpc_stale_at))
        })
        .collect()
}

fn persisted_rpc_stale_at(timestamp_ms: Option<u64>) -> Option<Instant> {
    let timestamp_ms = timestamp_ms?;
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())?;
    let age = Duration::from_millis(now_ms.saturating_sub(timestamp_ms));
    let remaining = POI_ARTIFACT_RPC_STALE_AFTER.saturating_sub(age);
    let now = Instant::now();
    now.checked_add(remaining).or(Some(now))
}

pub(super) fn record_list_source_outcomes(
    health: &mut BTreeMap<FixedBytes<32>, PoiSourceHealth>,
    outcomes: &[PoiListSourceOutcome],
) {
    for outcome in outcomes {
        health
            .entry(outcome.list_key)
            .or_insert_with(|| PoiSourceHealth::new(None))
            .record(outcome);
    }
}
