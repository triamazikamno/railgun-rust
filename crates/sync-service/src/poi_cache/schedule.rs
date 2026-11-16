//! POI cache demand and the maintenance schedule it drives.

use std::collections::BTreeMap;
use std::time::Duration;

use alloy::primitives::FixedBytes;
use poi::cache::PoiCache;
use railgun_wallet::UtxoCommitmentKind;
use tokio::time::Instant as TokioInstant;

use crate::types::{WalletObservation, WalletReadiness};

pub(super) const POI_CACHE_EVENT_ACTIVE_INTERVAL: Duration = Duration::from_secs(15);

pub(super) const POI_CACHE_EVENT_IDLE_INTERVAL: Duration = Duration::from_mins(5);

pub(super) const POI_CACHE_BLOCKED_ACTIVE_INTERVAL: Duration = Duration::from_mins(1);

pub(super) const POI_CACHE_BLOCKED_IDLE_INTERVAL: Duration = Duration::from_mins(30);

pub(super) const POI_CACHE_FAILURE_RETRY_INTERVAL: Duration = Duration::from_mins(1);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct PoiCacheDemand {
    pub(super) events: bool,
    pub(super) blocked_shields: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PoiCacheSyncScope {
    pub(super) events: bool,
    pub(super) blocked_shields: bool,
}

impl PoiCacheSyncScope {
    pub(super) const FULL: Self = Self {
        events: true,
        blocked_shields: true,
    };

    pub(super) const EVENTS: Self = Self {
        events: true,
        blocked_shields: false,
    };

    pub(super) const BLOCKED_SHIELDS: Self = Self {
        events: false,
        blocked_shields: true,
    };

    pub(super) const fn union(self, other: Self) -> Self {
        Self {
            events: self.events || other.events,
            blocked_shields: self.blocked_shields || other.blocked_shields,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct PoiCacheMaintenanceSchedule {
    pub(super) demand_actor_id: Option<u64>,
    pub(super) demand: PoiCacheDemand,
    pub(super) event_deadline: TokioInstant,
    pub(super) blocked_shields_deadline: TokioInstant,
    pub(super) event_last_success: Option<TokioInstant>,
    pub(super) blocked_shields_last_success: Option<TokioInstant>,
}

impl PoiCacheMaintenanceSchedule {
    pub(super) fn new(now: TokioInstant) -> Self {
        Self {
            demand_actor_id: None,
            demand: PoiCacheDemand::default(),
            event_deadline: now,
            blocked_shields_deadline: now,
            event_last_success: None,
            blocked_shields_last_success: None,
        }
    }

    pub(super) fn update_demand(&mut self, demand: PoiCacheDemand, now: TokioInstant) {
        if !self.demand.events && demand.events {
            self.event_deadline = now;
        } else if self.demand.events && !demand.events {
            self.event_deadline = self
                .event_last_success
                .map_or(now, |last| last + POI_CACHE_EVENT_IDLE_INTERVAL);
        }
        if !self.demand.blocked_shields && demand.blocked_shields {
            self.blocked_shields_deadline = now;
        } else if self.demand.blocked_shields && !demand.blocked_shields {
            self.blocked_shields_deadline = self
                .blocked_shields_last_success
                .map_or(now, |last| last + POI_CACHE_BLOCKED_IDLE_INTERVAL);
        }
        self.demand = demand;
    }

    pub(super) fn due_scope(&self, now: TokioInstant) -> Option<PoiCacheSyncScope> {
        let events = now >= self.event_deadline;
        let blocked_shields = now >= self.blocked_shields_deadline;
        let scope = match (events, blocked_shields) {
            (true, true) => PoiCacheSyncScope::FULL,
            (true, false) => PoiCacheSyncScope::EVENTS,
            (false, true) => PoiCacheSyncScope::BLOCKED_SHIELDS,
            (false, false) => return None,
        };
        Some(scope)
    }

    pub(super) fn next_deadline(&self) -> TokioInstant {
        self.event_deadline.min(self.blocked_shields_deadline)
    }

    pub(super) fn record_success(&mut self, scope: PoiCacheSyncScope, completed_at: TokioInstant) {
        if scope.events {
            self.event_last_success = Some(completed_at);
            self.event_deadline = completed_at
                + if self.demand.events {
                    POI_CACHE_EVENT_ACTIVE_INTERVAL
                } else {
                    POI_CACHE_EVENT_IDLE_INTERVAL
                };
        }
        if scope.blocked_shields {
            self.blocked_shields_last_success = Some(completed_at);
            self.blocked_shields_deadline = completed_at
                + if self.demand.blocked_shields {
                    POI_CACHE_BLOCKED_ACTIVE_INTERVAL
                } else {
                    POI_CACHE_BLOCKED_IDLE_INTERVAL
                };
        }
    }

    pub(super) fn record_failure(&mut self, scope: PoiCacheSyncScope, now: TokioInstant) {
        if scope.events {
            self.event_deadline = now + POI_CACHE_FAILURE_RETRY_INTERVAL;
        }
        if scope.blocked_shields {
            self.blocked_shields_deadline = now + POI_CACHE_FAILURE_RETRY_INTERVAL;
        }
    }
}

pub(super) fn apply_poi_cache_demand_update(
    schedule: &mut PoiCacheMaintenanceSchedule,
    actor_id: u64,
    demand: PoiCacheDemand,
    now: TokioInstant,
) -> bool {
    if schedule
        .demand_actor_id
        .is_some_and(|current| actor_id < current)
    {
        return false;
    }
    schedule.demand_actor_id = Some(actor_id);
    schedule.update_demand(demand, now);
    true
}

pub(super) fn effective_poi_cache_scope(
    scope: PoiCacheSyncScope,
    baseline: &BTreeMap<FixedBytes<32>, PoiCache>,
    active_list_keys: &[FixedBytes<32>],
) -> PoiCacheSyncScope {
    if scope.events
        && active_list_keys.iter().any(|list_key| {
            baseline
                .get(list_key)
                .is_none_or(|cache| !cache.progress().blocked_shields_synced)
        })
    {
        PoiCacheSyncScope::FULL
    } else {
        scope
    }
}

pub(super) fn poi_cache_demand(
    observation: &WalletObservation,
    active_list_keys: &[FixedBytes<32>],
) -> PoiCacheDemand {
    let (WalletReadiness::Syncing | WalletReadiness::Ready) = observation.readiness() else {
        return PoiCacheDemand::default();
    };
    let Some(snapshot) = observation.view().current_snapshot() else {
        return PoiCacheDemand::default();
    };
    let mut demand = PoiCacheDemand::default();
    for wallet_utxo in snapshot
        .utxos
        .iter()
        .chain(snapshot.pending_overlay.new_utxos.iter())
        .filter(|wallet_utxo| !wallet_utxo.is_spent())
    {
        let unresolved = active_list_keys.iter().any(|list_key| {
            wallet_utxo
                .utxo
                .poi
                .statuses
                .get(list_key)
                .is_none_or(|status| status.is_recoverable())
        });
        if unresolved {
            demand.events = true;
            demand.blocked_shields |=
                wallet_utxo.utxo.poi.commitment_kind == UtxoCommitmentKind::Shield;
        }
    }
    let workflow = observation.ppoi_workflow_status();
    demand.events |= workflow.awaiting_validation > 0 || workflow.awaiting_poi_data > 0;
    demand
}
