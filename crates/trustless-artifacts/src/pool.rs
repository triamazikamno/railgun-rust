//! Session-scoped gateway selection, health tracking and attempt reservations.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Instant, SystemTime};

use sha2::{Digest, Sha256};
use tracing::debug;
use url::Url;

use crate::error::{TrustlessArtifactError, TrustlessHttpPhase};
use crate::{GATEWAY_FAILURE_COOLDOWN, GATEWAY_FAILURE_COOLDOWN_CAP};

/// The independently health-tracked resource class requested from a gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GatewayCapability {
    ArtifactCar,
    ManifestCid,
    IpnsRecord,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GatewaySelectionPolicy {
    HealthyOnly,
    AllowCoolingFallback,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GatewayHealth {
    pub(crate) failures: u32,
    pub(crate) cooldown_until: Option<Instant>,
    pub(crate) in_flight: usize,
    pub(crate) half_open: bool,
}

impl GatewayHealth {
    const fn new() -> Self {
        Self {
            failures: 0,
            cooldown_until: None,
            in_flight: 0,
            half_open: false,
        }
    }

    fn is_cooling(&self, now: Instant) -> bool {
        self.cooldown_until.is_some_and(|until| until > now) || self.half_open
    }

    fn remaining_cooldown_ms(&self, now: Instant) -> u128 {
        self.cooldown_until
            .map_or(0, |until| until.saturating_duration_since(now).as_millis())
    }

    /// Whether a reservation now owns the half-open probe after an expired
    /// cooldown.
    fn takes_half_open_probe(&self, now: Instant) -> bool {
        self.cooldown_until.is_some_and(|until| until <= now) && !self.half_open
    }

    /// Records one more consecutive failure and returns the failure count and
    /// cooldown duration in milliseconds.
    fn record_failure(&mut self, now: Instant) -> (u32, u128) {
        self.failures = self.failures.saturating_add(1);
        let exponent = self.failures.saturating_sub(1).min(4);
        let multiplier = 1_u32 << exponent;
        let cooldown = GATEWAY_FAILURE_COOLDOWN
            .checked_mul(multiplier)
            .unwrap_or(GATEWAY_FAILURE_COOLDOWN_CAP)
            .min(GATEWAY_FAILURE_COOLDOWN_CAP);
        self.cooldown_until = Some(now + cooldown);
        (self.failures, cooldown.as_millis())
    }

    /// Clears failures and cooldown, and reports whether any were recorded.
    const fn clear_failures(&mut self) -> bool {
        let recorded = self.failures != 0 || self.cooldown_until.is_some();
        self.failures = 0;
        self.cooldown_until = None;
        recorded
    }
}

#[derive(Debug)]
pub(crate) struct GatewayPoolState {
    pub(crate) health: HashMap<(u64, GatewayCapability), GatewayHealth>,
    /// Gateway-wide health keyed by opaque identity. Only failures, cooldown
    /// and the half-open probe are tracked here; in-flight reservations stay
    /// on the capability entry.
    pub(crate) gateway_health: HashMap<u64, GatewayHealth>,
    seed: u64,
    generation: u64,
}

/// Which health entries an outcome or selection involves, for diagnostics.
const fn health_scope(capability: bool, gateway: bool) -> &'static str {
    match (capability, gateway) {
        (true, true) => "capability_and_gateway",
        (false, true) => "gateway",
        _ => "capability",
    }
}

/// Whether a failure shows that the gateway itself is unreachable, so it cools
/// the gateway for every capability. Content-specific failures, including
/// HTTP 502 and 504, stay on the requested capability.
const fn is_gateway_wide_failure(error: &TrustlessArtifactError) -> bool {
    match error {
        TrustlessArtifactError::HttpTimeout {
            phase: TrustlessHttpPhase::ResponseHeaders,
            ..
        }
        | TrustlessArtifactError::Http {
            phase: TrustlessHttpPhase::ResponseHeaders,
            ..
        } => true,
        TrustlessArtifactError::HttpStatus { status, .. } => {
            matches!(status.as_u16(), 521..=523)
        }
        _ => false,
    }
}

/// Session-scoped gateway selection and health state.
///
/// The pool deliberately stores no configured gateway vector. Callers retain
/// their URL vectors and supply opaque identities for each selection.
#[derive(Clone)]
pub struct GatewayPool {
    pub(crate) state: Arc<Mutex<GatewayPoolState>>,
}

impl PartialEq for GatewayPool {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
    }
}

impl Eq for GatewayPool {}

impl std::fmt::Debug for GatewayPool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayPool")
            .finish_non_exhaustive()
    }
}

impl Default for GatewayPool {
    fn default() -> Self {
        Self::new()
    }
}

/// A reserved gateway attempt. Dropping it releases the in-flight reservation.
pub struct GatewayAttempt {
    pool: GatewayPool,
    pub(crate) identity: u64,
    capability: GatewayCapability,
    generation: u64,
    owns_half_open: bool,
    owns_gateway_half_open: bool,
    pub index: usize,
    completed: bool,
}

impl std::fmt::Debug for GatewayAttempt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayAttempt")
            .field("capability", &self.capability)
            .field("index", &self.index)
            .field("completed", &self.completed)
            .finish_non_exhaustive()
    }
}

impl GatewayPool {
    #[must_use]
    pub fn new() -> Self {
        let seed = next_pool_seed();
        Self {
            state: Arc::new(Mutex::new(GatewayPoolState {
                health: HashMap::new(),
                gateway_health: HashMap::new(),
                seed,
                generation: 0,
            })),
        }
    }

    /// Clears health and cooldown state and reseeds this session's ranking.
    pub fn reset(&self) {
        let (generation, cleared_entries) = {
            let mut state = recover_mutex(&self.state);
            state.generation = state.generation.wrapping_add(1);
            state.seed = next_pool_seed();
            let cleared_entries = state.health.len() + state.gateway_health.len();
            state.health.clear();
            state.gateway_health.clear();
            (state.generation, cleared_entries)
        };
        debug!(
            generation,
            cleared_health_entries = cleared_entries,
            "gateway pool health reset"
        );
    }

    #[cfg(test)]
    pub(crate) fn with_seed_for_test(seed: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(GatewayPoolState {
                health: HashMap::new(),
                gateway_health: HashMap::new(),
                seed,
                generation: 0,
            })),
        }
    }

    /// Reserve a gateway according to the session ranking and current health.
    #[must_use]
    pub fn select(
        &self,
        gateway_ids: &[u64],
        capability: GatewayCapability,
        preferred_gateway_index: Option<usize>,
    ) -> Option<GatewayAttempt> {
        self.select_excluding(
            gateway_ids,
            capability,
            preferred_gateway_index,
            &HashSet::new(),
        )
    }

    pub(crate) fn select_excluding(
        &self,
        gateway_ids: &[u64],
        capability: GatewayCapability,
        preferred_gateway_index: Option<usize>,
        excluded_identities: &HashSet<u64>,
    ) -> Option<GatewayAttempt> {
        self.select_excluding_with_policy(
            gateway_ids,
            capability,
            preferred_gateway_index,
            excluded_identities,
            GatewaySelectionPolicy::AllowCoolingFallback,
        )
    }

    pub(crate) fn select_excluding_with_policy(
        &self,
        gateway_ids: &[u64],
        capability: GatewayCapability,
        preferred_gateway_index: Option<usize>,
        excluded_identities: &HashSet<u64>,
        policy: GatewaySelectionPolicy,
    ) -> Option<GatewayAttempt> {
        let now = Instant::now();
        let (attempt, probe, fallback) = {
            let mut guard = recover_mutex(&self.state);
            let state = &mut *guard;
            let mut candidates = Vec::with_capacity(gateway_ids.len());
            for (index, &identity) in gateway_ids.iter().enumerate() {
                if excluded_identities.contains(&identity) {
                    continue;
                }
                let health = state
                    .health
                    .get(&(identity, capability))
                    .copied()
                    .unwrap_or_else(GatewayHealth::new);
                let gateway_health = state
                    .gateway_health
                    .get(&identity)
                    .copied()
                    .unwrap_or_else(GatewayHealth::new);
                candidates.push(SelectionCandidate {
                    index,
                    identity,
                    rank: rank_for(state.seed, identity),
                    in_flight: health.in_flight,
                    cooldown_ms: health
                        .remaining_cooldown_ms(now)
                        .max(gateway_health.remaining_cooldown_ms(now)),
                    half_open: health.half_open || gateway_health.half_open,
                    capability_cooling: health.is_cooling(now),
                    gateway_cooling: gateway_health.is_cooling(now),
                });
            }
            let healthy = candidates
                .iter()
                .filter(|candidate| !candidate.cooling())
                .min_by_key(|candidate| {
                    (
                        u8::from(preferred_gateway_index != Some(candidate.index)),
                        candidate.in_flight,
                        candidate.rank,
                    )
                });
            let chosen = healthy.or_else(|| {
                if policy == GatewaySelectionPolicy::HealthyOnly {
                    return None;
                }
                // The least-bad cooling gateway is the one whose longer
                // remaining cooldown, capability or gateway-wide, ends first.
                candidates
                    .iter()
                    .filter(|candidate| candidate.in_flight == 0)
                    .min_by_key(|candidate| {
                        (candidate.cooldown_ms, candidate.in_flight, candidate.rank)
                    })
                    .or_else(|| {
                        candidates
                            .iter()
                            .min_by_key(|candidate| (candidate.in_flight, candidate.rank))
                    })
            })?;
            let chosen = *chosen;
            let generation = state.generation;
            let health = state
                .health
                .entry((chosen.identity, capability))
                .or_insert_with(GatewayHealth::new);
            let owns_half_open = health.takes_half_open_probe(now);
            health.in_flight = health.in_flight.saturating_add(1);
            if owns_half_open {
                health.half_open = true;
            }
            let owns_gateway_half_open = state
                .gateway_health
                .get_mut(&chosen.identity)
                .is_some_and(|gateway_health| {
                    let owns = gateway_health.takes_half_open_probe(now);
                    if owns {
                        gateway_health.half_open = true;
                    }
                    owns
                });
            let fallback = chosen.cooling().then_some((
                chosen.index,
                chosen.cooldown_ms,
                chosen.in_flight,
                chosen.half_open,
                health_scope(chosen.capability_cooling, chosen.gateway_cooling),
            ));
            (
                GatewayAttempt {
                    pool: self.clone(),
                    identity: chosen.identity,
                    capability,
                    generation,
                    owns_half_open,
                    owns_gateway_half_open,
                    index: chosen.index,
                    completed: false,
                },
                (owns_half_open || owns_gateway_half_open).then_some((
                    chosen.index,
                    health_scope(owns_half_open, owns_gateway_half_open),
                )),
                fallback,
            )
        };
        if let Some((gateway_index, scope)) = probe {
            debug!(
                gateway_index,
                ?capability,
                scope,
                "gateway cooldown expired; reserved owning half-open probe"
            );
        }
        if let Some((gateway_index, cooldown_ms, in_flight, half_open, scope)) = fallback {
            debug!(
                gateway_index,
                ?capability,
                scope,
                cooldown_ms,
                in_flight,
                half_open,
                "gateway pool selected cooling gateway as last-resort fallback"
            );
        }
        Some(attempt)
    }

    fn release(
        &self,
        identity: u64,
        capability: GatewayCapability,
        generation: u64,
        owns_half_open: bool,
        owns_gateway_half_open: bool,
        gateway_index: usize,
    ) {
        let stale_generation = {
            let mut guard = recover_mutex(&self.state);
            let state = &mut *guard;
            if state.generation == generation {
                let health = state
                    .health
                    .entry((identity, capability))
                    .or_insert_with(GatewayHealth::new);
                health.in_flight = health.in_flight.saturating_sub(1);
                if owns_half_open {
                    health.half_open = false;
                }
                if owns_gateway_half_open
                    && let Some(gateway_health) = state.gateway_health.get_mut(&identity)
                {
                    gateway_health.half_open = false;
                }
                None
            } else {
                Some(state.generation)
            }
        };
        if let Some(current_generation) = stale_generation {
            debug!(
                gateway_index,
                ?capability,
                attempt_generation = generation,
                current_generation,
                outcome = "cancellation",
                "stale gateway attempt cancellation ignored after pool reset"
            );
            return;
        }
        if owns_half_open || owns_gateway_half_open {
            debug!(
                gateway_index,
                ?capability,
                scope = health_scope(owns_half_open, owns_gateway_half_open),
                "owning half-open gateway attempt cancelled"
            );
        }
    }

    /// Settles a reserved attempt. A success clears this capability's entry
    /// and the gateway-wide entry. A gateway-wide failure cools the gateway
    /// for every capability and leaves the capability entry's failures
    /// unchanged; any other failure cools only this capability.
    fn finish(
        &self,
        identity: u64,
        capability: GatewayCapability,
        generation: u64,
        owns_half_open: bool,
        owns_gateway_half_open: bool,
        gateway_index: usize,
        success: bool,
        gateway_wide_failure: bool,
    ) {
        let transition = {
            let mut guard = recover_mutex(&self.state);
            let state = &mut *guard;
            if state.generation == generation {
                let health = state
                    .health
                    .entry((identity, capability))
                    .or_insert_with(GatewayHealth::new);
                health.in_flight = health.in_flight.saturating_sub(1);
                if owns_half_open {
                    health.half_open = false;
                }
                let mut gateway_health = state.gateway_health.get_mut(&identity);
                if owns_gateway_half_open && let Some(gateway_health) = gateway_health.as_mut() {
                    gateway_health.half_open = false;
                }
                if success {
                    let capability_recovered = health.clear_failures() || owns_half_open;
                    let gateway_recovered = gateway_health
                        .is_some_and(GatewayHealth::clear_failures)
                        || owns_gateway_half_open;
                    Ok((
                        (capability_recovered || gateway_recovered)
                            .then_some(health_scope(capability_recovered, gateway_recovered)),
                        None,
                    ))
                } else if gateway_wide_failure {
                    let (failure_count, cooldown_ms) = state
                        .gateway_health
                        .entry(identity)
                        .or_insert_with(GatewayHealth::new)
                        .record_failure(Instant::now());
                    Ok((None, Some((failure_count, cooldown_ms, "gateway"))))
                } else {
                    let (failure_count, cooldown_ms) = health.record_failure(Instant::now());
                    Ok((None, Some((failure_count, cooldown_ms, "capability"))))
                }
            } else {
                Err(state.generation)
            }
        };
        match transition {
            Err(current_generation) => {
                debug!(
                    gateway_index,
                    ?capability,
                    attempt_generation = generation,
                    current_generation,
                    outcome = if success { "success" } else { "failure" },
                    "stale gateway attempt outcome ignored after pool reset"
                );
            }
            Ok((Some(scope), _)) => {
                debug!(
                    gateway_index,
                    ?capability,
                    scope,
                    "gateway recovered after successful attempt"
                );
            }
            Ok((None, Some((failure_count, cooldown_ms, scope)))) => {
                debug!(
                    gateway_index,
                    ?capability,
                    scope,
                    failure_count,
                    cooldown_ms,
                    "gateway entered cooldown after failure"
                );
            }
            Ok((None, None)) => {}
        }
    }
}

/// A selectable gateway with the health that decides its ranking.
#[derive(Debug, Clone, Copy)]
struct SelectionCandidate {
    index: usize,
    identity: u64,
    rank: u64,
    in_flight: usize,
    /// The longer remaining cooldown of the capability and gateway-wide entries.
    cooldown_ms: u128,
    half_open: bool,
    capability_cooling: bool,
    gateway_cooling: bool,
}

impl SelectionCandidate {
    const fn cooling(&self) -> bool {
        self.capability_cooling || self.gateway_cooling
    }
}

impl GatewayAttempt {
    pub fn success(mut self) {
        self.pool.finish(
            self.identity,
            self.capability,
            self.generation,
            self.owns_half_open,
            self.owns_gateway_half_open,
            self.index,
            true,
            false,
        );
        self.completed = true;
    }

    /// Records a failed attempt. A failure showing that the gateway is
    /// unreachable cools it for every capability; any other failure cools
    /// only this attempt's capability.
    pub fn failure(mut self, error: &TrustlessArtifactError) {
        self.pool.finish(
            self.identity,
            self.capability,
            self.generation,
            self.owns_half_open,
            self.owns_gateway_half_open,
            self.index,
            false,
            is_gateway_wide_failure(error),
        );
        self.completed = true;
    }
}

impl Drop for GatewayAttempt {
    fn drop(&mut self) {
        if !self.completed {
            self.pool.release(
                self.identity,
                self.capability,
                self.generation,
                self.owns_half_open,
                self.owns_gateway_half_open,
                self.index,
            );
        }
    }
}

pub(crate) fn recover_mutex<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

pub(crate) fn opaque_gateway_id(url: &Url) -> u64 {
    let digest = Sha256::digest(url.as_str().as_bytes());
    u64::from_be_bytes(digest[..8].try_into().expect("gateway digest prefix"))
}

pub(crate) const fn rank_for(seed: u64, identity: u64) -> u64 {
    let mut value = seed ^ identity.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn next_pool_seed() -> u64 {
    static COUNTER: OnceLock<Mutex<u64>> = OnceLock::new();
    let counter = COUNTER.get_or_init(|| Mutex::new(0));
    let mut value = recover_mutex(counter);
    *value = value.wrapping_add(1);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos() as u64);
    nanos ^ value.wrapping_mul(0x9e37_79b9_7f4a_7c15)
}
