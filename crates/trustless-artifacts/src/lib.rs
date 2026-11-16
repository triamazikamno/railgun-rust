use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::str;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use blake2b_simd::Params;
use chrono::Utc;
use cid::{Cid, Version};
use futures::{StreamExt, future::BoxFuture, stream::FuturesUnordered};
use libp2p_identity::{PeerId, PublicKey};
use poi::SensitiveUrl;
use quick_protobuf::BytesReader;
use reqwest::header::HeaderValue;
use sha2::{Digest, Sha256};
use tracing::debug;
use url::Url;

mod car;
mod error;
mod http;

pub use car::UnixFsDataType;
use car::{RetrievalLimits, decode_car_blocks, reconstruct_file};
pub use error::{
    TrustlessArtifactError, TrustlessHttpPhase, TrustlessHttpSource, VerifiedCidError,
};
use http::{
    HttpAttemptTimeouts, car_gateway_url, fetch_response_bytes,
    fetch_response_bytes_reporting_headers, fetch_response_bytes_with_timeouts,
    ipns_record_gateway_url, raw_gateway_url,
};

/// Public canonical defaults for artifact gateway consumers.
pub const DEFAULT_GATEWAYS: &[&str] = &[
    "https://dweb.link",
    "https://ipfs.filebase.io",
    "https://ipfs.io",
    "https://gateway.pinata.cloud",
];

const RAW_CODEC: u64 = 0x55;
const DAG_PB_CODEC: u64 = 0x70;
const LIBP2P_KEY_CODEC: u64 = 0x72;

const CAR_ACCEPT: HeaderValue = HeaderValue::from_static("application/vnd.ipld.car");
const RAW_ACCEPT: HeaderValue = HeaderValue::from_static("application/vnd.ipld.raw");
const IPNS_RECORD_ACCEPT: HeaderValue =
    HeaderValue::from_static("application/vnd.ipfs.ipns-record");

const MANIFEST_CAR_MAX_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MANIFEST_JSON_MAX_BYTES: usize = 2 * 1024 * 1024;
const IPNS_RECORD_MAX_BYTES: usize = 10 * 1024;
const MANIFEST_CAR_MAX_BLOCKS: usize = 1_024;
const ARTIFACT_CAR_MAX_BLOCKS: usize = 16_384;
const ARTIFACT_CAR_MIN_OVERHEAD_BYTES: usize = 1024 * 1024;
const ARTIFACT_CAR_FIXED_OVERHEAD_BYTES: usize = 64 * 1024;
/// Time allowed for a gateway to return response headers. It is shorter than
/// the idle timeout so an unreachable gateway fails fast, and leaves room for a
/// request through built-in Tor.
const ARTIFACT_HTTP_HEADERS_TIMEOUT: Duration = Duration::from_secs(15);
const ARTIFACT_HTTP_IDLE_TIMEOUT: Duration = Duration::from_mins(2);
const ARTIFACT_HTTP_TOTAL_TIMEOUT: Duration = Duration::from_mins(5);
const MAX_CONCURRENT_IPNS_GATEWAY_REQUESTS: usize = 8;
const MANIFEST_CID_HEDGE_DELAY: Duration = Duration::from_millis(750);
/// Time after the first qualifying IPNS record arrives during which other
/// gateways may still answer before the resolution phase closes.
const IPNS_EARLY_CLOSE_GRACE: Duration = Duration::from_secs(2);
/// Time without response headers after which an indexed-artifact chunk
/// attempt gets a concurrent attempt on another gateway.
const CHUNK_HEDGE_DELAY: Duration = Duration::from_secs(5);
/// Time without response headers from any running attempt after which a
/// catalog fetch starts an attempt on another gateway.
const CATALOG_HEDGE_DELAY: Duration = Duration::from_secs(2);
const GATEWAY_FAILURE_COOLDOWN: Duration = Duration::from_mins(5);
const GATEWAY_FAILURE_COOLDOWN_CAP: Duration = Duration::from_mins(15);
const CARV2_PRAGMA: [u8; 11] = [
    0x0a, 0xa1, 0x67, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x02,
];
const CARV2_HEADER_SIZE: usize = 40;
const CARV2_DATA_OFFSET_OFFSET: usize = 16;
const CARV2_DATA_SIZE_OFFSET: usize = 24;
const CARV2_PRAGMA_AND_HEADER_SIZE: usize = CARV2_PRAGMA.len() + CARV2_HEADER_SIZE;
const CAR_HEADER_MAX_BYTES: u64 = 1024 * 1024;
const CAR_BLOCK_MAX_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpnsManifestCandidate {
    pub sequence: u64,
    pub cid: Cid,
    eol: chrono::DateTime<Utc>,
    gateway_index: usize,
}

impl IpnsManifestCandidate {
    /// The configured index of the first gateway whose record with this
    /// sequence and CID arrived.
    #[must_use]
    pub const fn gateway_index(&self) -> usize {
        self.gateway_index
    }
}

type ManifestCidRequestResult = (usize, usize, u128, Result<Vec<u8>, TrustlessArtifactError>);
type ManifestCidRequest<'a> = BoxFuture<'a, ManifestCidRequestResult>;
/// An IPNS request outcome with its unsettled gateway attempt. The attempt is
/// settled when the phase results are collected, after the acceptance sample.
type IpnsRecordRequestResult = (
    GatewayAttempt,
    u128,
    Result<IpnsManifestCandidate, TrustlessArtifactError>,
);

/// The independently health-tracked resource class requested from a gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GatewayCapability {
    ArtifactCar,
    ManifestCid,
    IpnsRecord,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GatewaySelectionPolicy {
    HealthyOnly,
    AllowCoolingFallback,
}

#[derive(Debug, Clone, Copy)]
struct GatewayHealth {
    failures: u32,
    cooldown_until: Option<Instant>,
    in_flight: usize,
    half_open: bool,
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
struct GatewayPoolState {
    health: HashMap<(u64, GatewayCapability), GatewayHealth>,
    /// Gateway-wide health keyed by opaque identity. Only failures, cooldown
    /// and the half-open probe are tracked here; in-flight reservations stay
    /// on the capability entry.
    gateway_health: HashMap<u64, GatewayHealth>,
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
    state: Arc<Mutex<GatewayPoolState>>,
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
    identity: u64,
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
    fn with_seed_for_test(seed: u64) -> Self {
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

    fn select_excluding(
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

    fn select_excluding_with_policy(
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

const fn manifest_attempt_role(ordinal: usize) -> &'static str {
    if ordinal == 0 {
        "initial"
    } else {
        "hedged_or_fallback"
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

fn recover_mutex<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn opaque_gateway_id(url: &Url) -> u64 {
    let digest = Sha256::digest(url.as_str().as_bytes());
    u64::from_be_bytes(digest[..8].try_into().expect("gateway digest prefix"))
}

const fn rank_for(seed: u64, identity: u64) -> u64 {
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

pub struct TrustlessArtifactFetcher<'a> {
    client: &'a reqwest::Client,
    gateways: GatewayUrls<'a>,
    gateway_ids: Vec<u64>,
    pool: GatewayPool,
    timeouts: HttpAttemptTimeouts,
}

enum GatewayUrls<'a> {
    Public(&'a [Url]),
    Poi(&'a [SensitiveUrl]),
}

impl GatewayUrls<'_> {
    const fn len(&self) -> usize {
        match self {
            Self::Public(gateways) => gateways.len(),
            Self::Poi(gateways) => gateways.len(),
        }
    }

    const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    const fn expose(&self, index: usize) -> &Url {
        match self {
            Self::Public(gateways) => &gateways[index],
            Self::Poi(gateways) => gateways[index].expose_url(),
        }
    }
}

#[derive(Debug)]
pub struct TrustlessArtifactFetchResult {
    verified_cid: String,
    bytes: Vec<u8>,
    gateway_index: usize,
    gateway_count: usize,
}

impl TrustlessArtifactFetchResult {
    #[must_use]
    pub fn verified_cid(&self) -> &str {
        &self.verified_cid
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn gateway_index(&self) -> usize {
        self.gateway_index
    }

    #[must_use]
    pub const fn gateway_count(&self) -> usize {
        self.gateway_count
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    #[doc(hidden)]
    #[cfg(any(test, feature = "test-utils"))]
    pub fn verified_for_test(cid: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            verified_cid: cid.into(),
            bytes,
            gateway_index: 0,
            gateway_count: 1,
        }
    }
}

impl<'a> TrustlessArtifactFetcher<'a> {
    #[must_use]
    pub fn new(client: &'a reqwest::Client, gateways: &'a [Url]) -> Self {
        Self {
            client,
            gateways: GatewayUrls::Public(gateways),
            gateway_ids: gateways.iter().map(opaque_gateway_id).collect(),
            pool: GatewayPool::new(),
            timeouts: HttpAttemptTimeouts::PRODUCTION,
        }
    }

    #[must_use]
    pub fn new_poi(client: &'a reqwest::Client, gateways: &'a [SensitiveUrl]) -> Self {
        Self {
            client,
            gateways: GatewayUrls::Poi(gateways),
            gateway_ids: gateways
                .iter()
                .map(|gateway| opaque_gateway_id(gateway.expose_url()))
                .collect(),
            pool: GatewayPool::new(),
            timeouts: HttpAttemptTimeouts::PRODUCTION,
        }
    }

    #[must_use]
    pub fn new_with_pool(
        client: &'a reqwest::Client,
        gateways: &'a [Url],
        pool: GatewayPool,
    ) -> Self {
        Self {
            client,
            gateways: GatewayUrls::Public(gateways),
            gateway_ids: gateways.iter().map(opaque_gateway_id).collect(),
            pool,
            timeouts: HttpAttemptTimeouts::PRODUCTION,
        }
    }

    #[must_use]
    pub fn new_poi_with_pool(
        client: &'a reqwest::Client,
        gateways: &'a [SensitiveUrl],
        pool: GatewayPool,
    ) -> Self {
        Self {
            client,
            gateways: GatewayUrls::Poi(gateways),
            gateway_ids: gateways
                .iter()
                .map(|gateway| opaque_gateway_id(gateway.expose_url()))
                .collect(),
            pool,
            timeouts: HttpAttemptTimeouts::PRODUCTION,
        }
    }

    pub async fn fetch_manifest_cid(&self, cid: &str) -> Result<Vec<u8>, TrustlessArtifactError> {
        self.fetch_manifest_cid_with_metadata(cid)
            .await
            .map(TrustlessArtifactFetchResult::into_bytes)
    }

    pub async fn fetch_manifest_cid_with_metadata(
        &self,
        cid: &str,
    ) -> Result<TrustlessArtifactFetchResult, TrustlessArtifactError> {
        self.fetch_manifest_cid_with_metadata_from_gateway(cid, None)
            .await
    }

    /// Like [`Self::fetch_manifest_cid_with_metadata`], preferring
    /// `preferred_gateway_index` for the first attempt only. Hedged attempts
    /// are chosen by the pool.
    pub async fn fetch_manifest_cid_with_metadata_from_gateway(
        &self,
        cid: &str,
        preferred_gateway_index: Option<usize>,
    ) -> Result<TrustlessArtifactFetchResult, TrustlessArtifactError> {
        let cid = parse_cid(cid)?;
        self.fetch_verified_manifest_cid(cid, preferred_gateway_index)
            .await
    }

    pub async fn fetch_artifact_cid(
        &self,
        cid: &str,
        byte_size: u64,
    ) -> Result<Vec<u8>, TrustlessArtifactError> {
        let cid = parse_cid(cid)?;
        self.fetch_cid_bytes(cid, RetrievalLimits::artifact(byte_size)?, "artifact")
            .await
            .map(TrustlessArtifactFetchResult::into_bytes)
    }

    pub async fn fetch_artifact_cid_with_metadata_from_gateway(
        &self,
        cid: &str,
        byte_size: u64,
        preferred_gateway_index: usize,
    ) -> Result<TrustlessArtifactFetchResult, TrustlessArtifactError> {
        self.fetch_artifact_cid_with_metadata_from_gateway_bounded(
            cid,
            byte_size,
            preferred_gateway_index,
            self.gateways.len(),
        )
        .await
    }

    pub async fn fetch_artifact_cid_with_metadata_from_gateway_bounded(
        &self,
        cid: &str,
        byte_size: u64,
        preferred_gateway_index: usize,
        max_gateway_attempts: usize,
    ) -> Result<TrustlessArtifactFetchResult, TrustlessArtifactError> {
        let cid = parse_cid(cid)?;
        self.fetch_cid_bytes_from_gateway(
            cid,
            RetrievalLimits::artifact(byte_size)?,
            "artifact",
            Some(preferred_gateway_index),
            max_gateway_attempts,
        )
        .await
    }

    /// Fetches an indexed-artifact chunk, hedging a gateway that stalls before
    /// responding.
    ///
    /// Attempts fall back sequentially across the same gateways as
    /// [`Self::fetch_artifact_cid_with_metadata_from_gateway`], except that when
    /// the sole running attempt has not received response headers within
    /// `CHUNK_HEDGE_DELAY`, one concurrent attempt starts on another gateway.
    /// At most one hedge starts per chunk, so at most two attempts run at once.
    /// The first body that verifies against `cid` wins; the other attempt is
    /// cancelled and its gateway released without a recorded failure.
    ///
    /// `admit_hedge` is called at most once, after a hedge gateway has been
    /// reserved and immediately before the hedge starts. Returning `None`
    /// vetoes the hedge and the running attempt continues alone. A returned
    /// guard is held for the hedge attempt's lifetime and dropped when that
    /// attempt succeeds, fails or is cancelled, so a caller can charge the
    /// hedge to a byte budget.
    pub async fn fetch_artifact_cid_with_metadata_hedged<G>(
        &self,
        cid: &str,
        byte_size: u64,
        preferred_gateway_index: usize,
        admit_hedge: impl FnOnce() -> Option<G>,
    ) -> Result<TrustlessArtifactFetchResult, TrustlessArtifactError> {
        let cid = parse_cid(cid)?;
        let limits = RetrievalLimits::artifact(byte_size)?;
        if self.gateways.is_empty() {
            return Err(TrustlessArtifactError::NoGateways);
        }

        let gateway_count = self.gateways.len();
        let preferred_gateway_index = preferred_gateway_index % gateway_count;
        let started = tokio::time::Instant::now();
        let mut admit_hedge = Some(admit_hedge);
        let mut reserved_identities = HashSet::with_capacity(gateway_count);
        let mut attempts = FuturesUnordered::new();
        // Hedge deadline, gateway index and headers flag of the sole running
        // attempt, armed while the hedge is unused.
        let mut hedge_watch: Option<(tokio::time::Instant, usize, Arc<AtomicBool>)> = None;
        let mut hedged_gateways = None;
        let mut last_error = None;
        loop {
            if attempts.is_empty() {
                let Some(gateway_attempt) = self.pool.select_excluding(
                    &self.gateway_ids,
                    GatewayCapability::ArtifactCar,
                    reserved_identities
                        .is_empty()
                        .then_some(preferred_gateway_index),
                    &reserved_identities,
                ) else {
                    break;
                };
                reserved_identities.insert(gateway_attempt.identity);
                let headers_received = Arc::new(AtomicBool::new(false));
                if admit_hedge.is_some() {
                    hedge_watch = Some((
                        tokio::time::Instant::now() + CHUNK_HEDGE_DELAY,
                        gateway_attempt.index,
                        Arc::clone(&headers_received),
                    ));
                }
                attempts.push(self.chunk_attempt(
                    cid,
                    limits,
                    gateway_attempt,
                    headers_received,
                    None::<G>,
                ));
            }

            let hedge_at = hedge_watch.as_ref().map(|(hedge_at, _, _)| *hedge_at);
            tokio::select! {
                biased;
                result = attempts.next() => {
                    let Some((gateway_index, result)) = result else { continue };
                    match result {
                        Ok(bytes) => {
                            if let Some((first_gateway_index, hedge_gateway_index)) = hedged_gateways {
                                debug!(
                                    cid = %cid,
                                    first_gateway_index,
                                    hedge_gateway_index,
                                    winner_gateway_index = gateway_index,
                                    gateway_count,
                                    elapsed_ms = started.elapsed().as_millis(),
                                    "hedged artifact chunk fetch completed"
                                );
                            }
                            return Ok(TrustlessArtifactFetchResult {
                                verified_cid: cid.to_string(),
                                bytes,
                                gateway_index,
                                gateway_count,
                            });
                        }
                        // Any other running attempt continues; once none is
                        // left, the loop falls back to the next gateway.
                        Err(error) => last_error = Some(error),
                    }
                }
                () = tokio::time::sleep_until(hedge_at.unwrap_or(started)), if hedge_at.is_some() => {
                    let Some((_, first_gateway_index, headers_received)) = hedge_watch.take() else {
                        continue;
                    };
                    // An attempt that has received headers is progressing and is
                    // never duplicated.
                    if headers_received.load(Ordering::Relaxed) {
                        continue;
                    }
                    let Some(gateway_attempt) = self.pool.select_excluding(
                        &self.gateway_ids,
                        GatewayCapability::ArtifactCar,
                        None,
                        &reserved_identities,
                    ) else {
                        continue;
                    };
                    // A vetoed hedge drops its reservation without a recorded failure.
                    let Some(hedge_guard) = admit_hedge.take().and_then(|admit_hedge| admit_hedge())
                    else {
                        continue;
                    };
                    reserved_identities.insert(gateway_attempt.identity);
                    let hedge_gateway_index = gateway_attempt.index;
                    debug!(
                        cid = %cid,
                        first_gateway_index,
                        hedge_gateway_index,
                        gateway_count,
                        elapsed_ms = started.elapsed().as_millis(),
                        "artifact chunk hedge started"
                    );
                    hedged_gateways = Some((first_gateway_index, hedge_gateway_index));
                    attempts.push(self.chunk_attempt(
                        cid,
                        limits,
                        gateway_attempt,
                        Arc::new(AtomicBool::new(false)),
                        Some(hedge_guard),
                    ));
                }
            }
        }

        Err(last_error.unwrap_or(TrustlessArtifactError::NoGateways))
    }

    /// Fetches a catalog-sized artifact, hedging gateways that stall before
    /// responding.
    ///
    /// The first attempt starts on `preferred_gateway_index` unless the pool
    /// finds that gateway cooling. Every `CATALOG_HEDGE_DELAY` while no running
    /// attempt has received response headers, another attempt starts on the
    /// next eligible gateway. When every running attempt has failed, the next
    /// gateway starts immediately. At most `max_gateway_attempts` attempts start,
    /// bounded by the gateway count. The first body that verifies against `cid`
    /// wins; the other attempts are cancelled and their gateways released
    /// without a recorded failure. A body that fails verification counts as
    /// that gateway's failure while other attempts continue.
    pub async fn fetch_catalog_cid_with_metadata_hedged(
        &self,
        cid: &str,
        byte_size: u64,
        preferred_gateway_index: Option<usize>,
        max_gateway_attempts: usize,
    ) -> Result<TrustlessArtifactFetchResult, TrustlessArtifactError> {
        let cid = parse_cid(cid)?;
        let limits = RetrievalLimits::artifact(byte_size)?;
        if self.gateways.is_empty() {
            return Err(TrustlessArtifactError::NoGateways);
        }

        let gateway_count = self.gateways.len();
        let preferred_gateway_index = preferred_gateway_index.map(|index| index % gateway_count);
        let max_attempts = gateway_count.min(max_gateway_attempts.max(1));
        let started = tokio::time::Instant::now();
        let mut reserved_identities = HashSet::with_capacity(max_attempts);
        let mut attempts = FuturesUnordered::new();
        // Gateway index and headers flag of each running attempt.
        let mut running: Vec<(usize, Arc<AtomicBool>)> = Vec::with_capacity(max_attempts);
        let mut started_gateways = Vec::with_capacity(max_attempts);
        let mut hedge_at: Option<tokio::time::Instant> = None;
        let mut hedge_due = false;
        let mut hedged = false;
        let mut last_error = None;
        loop {
            if (hedge_due || attempts.is_empty()) && started_gateways.len() < max_attempts {
                let gateway_attempt = self.pool.select_excluding(
                    &self.gateway_ids,
                    GatewayCapability::ArtifactCar,
                    if started_gateways.is_empty() {
                        preferred_gateway_index
                    } else {
                        None
                    },
                    &reserved_identities,
                );
                if let Some(gateway_attempt) = gateway_attempt {
                    reserved_identities.insert(gateway_attempt.identity);
                    let gateway_index = gateway_attempt.index;
                    if hedge_due {
                        hedged = true;
                        debug!(
                            cid = %cid,
                            hedge_gateway_index = gateway_index,
                            attempt = started_gateways.len(),
                            gateway_count,
                            elapsed_ms = started.elapsed().as_millis(),
                            "artifact catalog hedge started"
                        );
                    }
                    started_gateways.push(gateway_index);
                    let headers_received = Arc::new(AtomicBool::new(false));
                    running.push((gateway_index, Arc::clone(&headers_received)));
                    attempts.push(self.chunk_attempt(
                        cid,
                        limits,
                        gateway_attempt,
                        headers_received,
                        None::<()>,
                    ));
                    hedge_at = (started_gateways.len() < max_attempts)
                        .then(|| tokio::time::Instant::now() + CATALOG_HEDGE_DELAY);
                }
            }
            hedge_due = false;
            if attempts.is_empty() {
                break;
            }

            tokio::select! {
                biased;
                result = attempts.next() => {
                    let Some((gateway_index, result)) = result else { continue };
                    match result {
                        Ok(bytes) => {
                            if hedged {
                                debug!(
                                    cid = %cid,
                                    ?started_gateways,
                                    winner_gateway_index = gateway_index,
                                    gateway_count,
                                    elapsed_ms = started.elapsed().as_millis(),
                                    "hedged artifact catalog fetch completed"
                                );
                            }
                            return Ok(TrustlessArtifactFetchResult {
                                verified_cid: cid.to_string(),
                                bytes,
                                gateway_index,
                                gateway_count,
                            });
                        }
                        // Other running attempts continue; once none is left,
                        // the loop starts the next gateway immediately.
                        Err(error) => {
                            running.retain(|(index, _)| *index != gateway_index);
                            last_error = Some(error);
                        }
                    }
                }
                () = tokio::time::sleep_until(hedge_at.unwrap_or(started)), if hedge_at.is_some() => {
                    // An attempt that has received headers is progressing and is
                    // never duplicated; the timer re-arms while below the cap.
                    if running
                        .iter()
                        .any(|(_, headers_received)| headers_received.load(Ordering::Relaxed))
                    {
                        hedge_at = Some(tokio::time::Instant::now() + CATALOG_HEDGE_DELAY);
                    } else {
                        hedge_at = None;
                        hedge_due = true;
                    }
                }
            }
        }

        Err(last_error.unwrap_or(TrustlessArtifactError::NoGateways))
    }

    /// Resolves an IPNS name to verified manifest CID candidates, highest
    /// sequence first.
    ///
    /// A resolution phase closes `IPNS_EARLY_CLOSE_GRACE` after the first
    /// qualifying record arrives, or when every attempt has settled. A record
    /// qualifies when it is verified, unexpired on arrival, and at or above
    /// `sequence_floor` when one is supplied, so a lagging gateway cannot close
    /// resolution early.
    pub async fn resolve_ipns_manifest_candidates(
        &self,
        name: &str,
        sequence_floor: Option<u64>,
    ) -> Result<Vec<IpnsManifestCandidate>, TrustlessArtifactError> {
        self.resolve_ipns_manifest_candidates_with_clock(name, sequence_floor, &SystemTime::now)
            .await
    }

    /// Like [`Self::resolve_ipns_manifest_candidates`], reading time from
    /// `acceptance_time`. Arrival reads only decide when a phase stops
    /// waiting; one acceptance sample after the phase closes decides which
    /// candidates are returned.
    pub async fn resolve_ipns_manifest_candidates_with_clock<F>(
        &self,
        name: &str,
        sequence_floor: Option<u64>,
        acceptance_time: &F,
    ) -> Result<Vec<IpnsManifestCandidate>, TrustlessArtifactError>
    where
        F: Fn() -> SystemTime + Sync + ?Sized,
    {
        if self.gateways.is_empty() {
            return Err(TrustlessArtifactError::NoGateways);
        }

        let peer_id = expected_ipns_peer_id(name)?;
        let mut errors = Vec::new();
        let gateway_count = self.gateways.len();
        let mut reserved_identities = HashSet::with_capacity(gateway_count);
        let phase_one = self
            .fetch_ipns_phase(
                name,
                peer_id,
                GatewaySelectionPolicy::HealthyOnly,
                &mut reserved_identities,
                sequence_floor,
                acceptance_time,
            )
            .await;
        let mut candidates = Vec::new();
        self.collect_ipns_phase_results(
            name,
            phase_one,
            chrono::DateTime::<Utc>::from(acceptance_time()),
            &mut candidates,
            &mut errors,
        );
        if !candidates.is_empty() {
            return finalize_ipns_candidates(candidates, errors);
        }

        let phase_two = self
            .fetch_ipns_phase(
                name,
                peer_id,
                GatewaySelectionPolicy::AllowCoolingFallback,
                &mut reserved_identities,
                sequence_floor,
                acceptance_time,
            )
            .await;
        self.collect_ipns_phase_results(
            name,
            phase_two,
            chrono::DateTime::<Utc>::from(acceptance_time()),
            &mut candidates,
            &mut errors,
        );
        finalize_ipns_candidates(candidates, errors)
    }

    /// Queries gateways concurrently until every attempt settles, or until
    /// `IPNS_EARLY_CLOSE_GRACE` after the first qualifying record. Attempts
    /// still pending at close are dropped, which releases their reservations
    /// without a recorded failure.
    async fn fetch_ipns_phase<F>(
        &self,
        name: &str,
        peer_id: PeerId,
        policy: GatewaySelectionPolicy,
        reserved_identities: &mut HashSet<u64>,
        sequence_floor: Option<u64>,
        acceptance_time: &F,
    ) -> Vec<IpnsRecordRequestResult>
    where
        F: Fn() -> SystemTime + Sync + ?Sized,
    {
        let gateway_count = self.gateways.len();
        let mut requests = FuturesUnordered::new();
        let mut results = Vec::with_capacity(gateway_count);
        let mut close_at: Option<tokio::time::Instant> = None;
        loop {
            // Free slots keep filling until the grace deadline, which cancels
            // whatever is still pending.
            while requests.len() < MAX_CONCURRENT_IPNS_GATEWAY_REQUESTS {
                let Some(gateway_attempt) = self.pool.select_excluding_with_policy(
                    &self.gateway_ids,
                    GatewayCapability::IpnsRecord,
                    None,
                    reserved_identities,
                    policy,
                ) else {
                    break;
                };
                reserved_identities.insert(gateway_attempt.identity);
                let gateway_index = gateway_attempt.index;
                let gateway = self.gateways.expose(gateway_index);
                let url = ipns_record_gateway_url(gateway, name);
                let source = TrustlessHttpSource::Gateway {
                    index: gateway_index,
                    count: gateway_count,
                };
                requests.push(async move {
                    let attempt_started = Instant::now();
                    let result = self
                        .fetch_ipns_record_candidate(&url, source, peer_id)
                        .await;
                    (
                        gateway_attempt,
                        attempt_started.elapsed().as_millis(),
                        result,
                    )
                });
            }
            let result = if let Some(close_at) = close_at {
                tokio::select! {
                    biased;
                    () = tokio::time::sleep_until(close_at) => {
                        debug!(
                            gateway_count,
                            ipns_name = name,
                            received = results.len(),
                            cancelled = requests.len(),
                            "POI artifact IPNS phase closed after grace window"
                        );
                        break;
                    }
                    result = requests.next() => result,
                }
            } else {
                requests.next().await
            };
            let Some(result) = result else {
                break;
            };
            // The arrival-time clock read only decides when to stop waiting.
            let qualifies = result.2.as_ref().is_ok_and(|candidate| {
                candidate.eol > chrono::DateTime::<Utc>::from(acceptance_time())
                    && sequence_floor.is_none_or(|floor| candidate.sequence >= floor)
            });
            if qualifies && close_at.is_none() {
                close_at = Some(tokio::time::Instant::now() + IPNS_EARLY_CLOSE_GRACE);
            }
            results.push(result);
        }
        results
    }

    /// Records each phase result against the single acceptance sample and
    /// settles its gateway attempt: a current verified record is a success, an
    /// expired one is a capability-scoped failure.
    fn collect_ipns_phase_results(
        &self,
        name: &str,
        results: Vec<IpnsRecordRequestResult>,
        accepted_at: chrono::DateTime<Utc>,
        candidates: &mut Vec<(usize, IpnsManifestCandidate)>,
        errors: &mut Vec<(usize, TrustlessArtifactError)>,
    ) {
        let gateway_count = self.gateways.len();
        for (gateway_attempt, elapsed_ms, result) in results {
            let gateway_index = gateway_attempt.index;
            match result {
                Ok(mut candidate) => {
                    candidate.gateway_index = gateway_index;
                    debug!(
                        gateway_index,
                        gateway_count,
                        ipns_name = name,
                        cid = %candidate.cid,
                        ipns_sequence = candidate.sequence,
                        elapsed_ms,
                        "POI artifact IPNS gateway returned verified record"
                    );
                    if candidate.eol <= accepted_at {
                        debug!(
                            gateway_index,
                            gateway_count,
                            ipns_name = name,
                            ipns_sequence = candidate.sequence,
                            eol = %candidate.eol,
                            "POI artifact IPNS gateway record expired before aggregate acceptance"
                        );
                        let error =
                            TrustlessArtifactError::ExpiredIpnsRecord { eol: candidate.eol };
                        gateway_attempt.failure(&error);
                        errors.push((gateway_index, error));
                    } else {
                        gateway_attempt.success();
                        candidates.push((gateway_index, candidate));
                    }
                }
                Err(err) => {
                    debug!(
                        ?err,
                        gateway_index,
                        gateway_count,
                        ipns_name = name,
                        elapsed_ms,
                        "POI artifact IPNS gateway failed"
                    );
                    gateway_attempt.failure(&err);
                    errors.push((gateway_index, err));
                }
            }
        }
    }

    async fn fetch_cid_bytes(
        &self,
        cid: Cid,
        limits: RetrievalLimits,
        resource: &'static str,
    ) -> Result<TrustlessArtifactFetchResult, TrustlessArtifactError> {
        self.fetch_cid_bytes_from_gateway(cid, limits, resource, None, self.gateways.len())
            .await
    }

    async fn fetch_cid_bytes_from_gateway(
        &self,
        cid: Cid,
        limits: RetrievalLimits,
        resource: &'static str,
        preferred_gateway_index: Option<usize>,
        max_gateway_attempts: usize,
    ) -> Result<TrustlessArtifactFetchResult, TrustlessArtifactError> {
        if self.gateways.is_empty() {
            return Err(TrustlessArtifactError::NoGateways);
        }

        let mut last_error = None;
        let gateway_count = self.gateways.len();
        let preferred_gateway_index = preferred_gateway_index.map(|index| index % gateway_count);
        let max_attempts = gateway_count.min(max_gateway_attempts.max(1));
        let mut reserved_identities = HashSet::with_capacity(max_attempts);
        let mut launched_attempts = 0;
        while launched_attempts < max_attempts {
            let Some(gateway_attempt) = self.pool.select_excluding(
                &self.gateway_ids,
                GatewayCapability::ArtifactCar,
                if launched_attempts == 0 {
                    preferred_gateway_index
                } else {
                    None
                },
                &reserved_identities,
            ) else {
                break;
            };
            reserved_identities.insert(gateway_attempt.identity);
            let attempt = launched_attempts;
            launched_attempts += 1;
            let gateway_index = gateway_attempt.index;
            let gateway = self.gateways.expose(gateway_index);
            let attempt_started = Instant::now();
            let url = car_gateway_url(gateway, &cid);
            let source = TrustlessHttpSource::Gateway {
                index: gateway_index,
                count: gateway_count,
            };
            match self
                .fetch_cid_bytes_from_url(cid, &url, source, limits, None)
                .await
            {
                Ok(bytes) => {
                    if attempt > 0 {
                        debug!(
                            gateway_index,
                            gateway_count,
                            preferred_gateway_index,
                            resource,
                            cid = %cid,
                            bytes = bytes.len(),
                            elapsed_ms = attempt_started.elapsed().as_millis(),
                            "POI artifact CID gateway fetch succeeded after fallback"
                        );
                    }
                    gateway_attempt.success();
                    return Ok(TrustlessArtifactFetchResult {
                        verified_cid: cid.to_string(),
                        bytes,
                        gateway_index,
                        gateway_count,
                    });
                }
                Err(err) => {
                    debug!(
                        ?err,
                        gateway_index,
                        gateway_count,
                        resource,
                        cid = %cid,
                        elapsed_ms = attempt_started.elapsed().as_millis(),
                        "POI artifact CID gateway fetch failed"
                    );
                    gateway_attempt.failure(&err);
                    last_error = Some(err);
                }
            }
        }

        Err(last_error.unwrap_or(TrustlessArtifactError::NoGateways))
    }

    /// Runs one hedged artifact attempt, for an indexed-artifact chunk or a POI
    /// checkpoint catalog, and records its gateway outcome. `_hedge_guard` is
    /// held until the attempt completes or is cancelled.
    async fn chunk_attempt<G>(
        &self,
        cid: Cid,
        limits: RetrievalLimits,
        gateway_attempt: GatewayAttempt,
        headers_received: Arc<AtomicBool>,
        _hedge_guard: Option<G>,
    ) -> (usize, Result<Vec<u8>, TrustlessArtifactError>) {
        let gateway_index = gateway_attempt.index;
        let gateway_count = self.gateways.len();
        let url = car_gateway_url(self.gateways.expose(gateway_index), &cid);
        let source = TrustlessHttpSource::Gateway {
            index: gateway_index,
            count: gateway_count,
        };
        let attempt_started = Instant::now();
        let result = self
            .fetch_cid_bytes_from_url(cid, &url, source, limits, Some(&headers_received))
            .await;
        match &result {
            Ok(_) => gateway_attempt.success(),
            Err(err) => {
                debug!(
                    ?err,
                    gateway_index,
                    gateway_count,
                    resource = "artifact",
                    cid = %cid,
                    elapsed_ms = attempt_started.elapsed().as_millis(),
                    "POI artifact CID gateway fetch failed"
                );
                gateway_attempt.failure(err);
            }
        }
        (gateway_index, result)
    }

    async fn fetch_cid_bytes_from_url(
        &self,
        cid: Cid,
        url: &Url,
        source: TrustlessHttpSource,
        limits: RetrievalLimits,
        headers_received: Option<&AtomicBool>,
    ) -> Result<Vec<u8>, TrustlessArtifactError> {
        let car_bytes = fetch_response_bytes_reporting_headers(
            self.client,
            url,
            source,
            Some(CAR_ACCEPT),
            limits.response_bytes,
            self.timeouts,
            headers_received,
        )
        .await?;
        let blocks = decode_car_blocks(&car_bytes, cid, limits.block_count).await?;
        reconstruct_file(cid, &blocks, limits)
    }

    async fn fetch_verified_manifest_cid(
        &self,
        cid: Cid,
        preferred_gateway_index: Option<usize>,
    ) -> Result<TrustlessArtifactFetchResult, TrustlessArtifactError> {
        if self.gateways.is_empty() {
            return Err(TrustlessArtifactError::NoGateways);
        }
        if cid.codec() == RAW_CODEC {
            raw_multihash_policy(cid)?;
        }

        let gateway_count = self.gateways.len();
        let preferred_gateway_index = preferred_gateway_index.map(|index| index % gateway_count);
        let mut next_gateway_index = 0;
        let mut reserved_identities = HashSet::with_capacity(gateway_count);
        let mut requests: FuturesUnordered<ManifestCidRequest<'_>> = FuturesUnordered::new();
        let mut last_error = None;

        let Some(gateway_attempt) = self.pool.select_excluding(
            &self.gateway_ids,
            GatewayCapability::ManifestCid,
            preferred_gateway_index,
            &reserved_identities,
        ) else {
            return Err(TrustlessArtifactError::NoGateways);
        };
        reserved_identities.insert(gateway_attempt.identity);
        let gateway_index = gateway_attempt.index;
        let gateway = self.gateways.expose(gateway_index);
        let url = if cid.codec() == RAW_CODEC {
            raw_gateway_url(gateway, &cid)
        } else {
            car_gateway_url(gateway, &cid)
        };
        let source = TrustlessHttpSource::Gateway {
            index: gateway_index,
            count: gateway_count,
        };
        requests.push(self.manifest_cid_request(
            cid,
            gateway_index,
            0,
            url,
            source,
            gateway_attempt,
        ));
        next_gateway_index += 1;
        let mut next_launch_at = tokio::time::Instant::now() + MANIFEST_CID_HEDGE_DELAY;

        while next_gateway_index < gateway_count || !requests.is_empty() {
            if requests.is_empty() {
                let Some(gateway_attempt) = self.pool.select_excluding(
                    &self.gateway_ids,
                    GatewayCapability::ManifestCid,
                    None,
                    &reserved_identities,
                ) else {
                    break;
                };
                reserved_identities.insert(gateway_attempt.identity);
                let gateway_index = gateway_attempt.index;
                let gateway = self.gateways.expose(gateway_index);
                let url = if cid.codec() == RAW_CODEC {
                    raw_gateway_url(gateway, &cid)
                } else {
                    car_gateway_url(gateway, &cid)
                };
                let source = TrustlessHttpSource::Gateway {
                    index: gateway_index,
                    count: gateway_count,
                };
                let ordinal = next_gateway_index;
                requests.push(self.manifest_cid_request(
                    cid,
                    gateway_index,
                    ordinal,
                    url,
                    source,
                    gateway_attempt,
                ));
                next_gateway_index += 1;
                next_launch_at = tokio::time::Instant::now() + MANIFEST_CID_HEDGE_DELAY;
                continue;
            }

            // Every eligible gateway may start an attempt, one hedge delay apart,
            // while earlier attempts are still pending.
            if next_gateway_index < gateway_count {
                tokio::select! {
                    biased;
                    result = requests.next() => {
                        let Some((gateway_index, ordinal, elapsed_ms, result)) = result else { continue };
                        match result {
                            Ok(bytes) => {
                                debug!(
                                    gateway_index,
                                    gateway_count,
                                    cid = %cid,
                                    bytes = bytes.len(),
                                    elapsed_ms,
                                    attempt = manifest_attempt_role(ordinal),
                                    representation = if cid.codec() == RAW_CODEC { "raw" } else { "car" },
                                    "verified CID gateway fetch succeeded"
                                );
                                return Ok(TrustlessArtifactFetchResult {
                                    verified_cid: cid.to_string(),
                                    bytes,
                                    gateway_index,
                                    gateway_count,
                                });
                            }
                            Err(error) => {
                                debug!(
                                    ?error,
                                    gateway_index,
                                    gateway_count,
                                    cid = %cid,
                                    elapsed_ms,
                                    attempt = manifest_attempt_role(ordinal),
                                    representation = if cid.codec() == RAW_CODEC { "raw" } else { "car" },
                                    "verified CID gateway fetch failed"
                                );
                                last_error = Some(error);
                                // A failed request launches the next gateway immediately; do not wait for the hedge timer.
                                next_launch_at = tokio::time::Instant::now();
                            }
                        }
                    }
                    () = tokio::time::sleep_until(next_launch_at) => {
                        let Some(gateway_attempt) = self.pool.select_excluding(
                            &self.gateway_ids,
                            GatewayCapability::ManifestCid,
                            None,
                            &reserved_identities,
                        )
                        else {
                            next_gateway_index = gateway_count;
                            continue;
                        };
                        reserved_identities.insert(gateway_attempt.identity);
                        let gateway_index = gateway_attempt.index;
                        let gateway = self.gateways.expose(gateway_index);
                        let url = if cid.codec() == RAW_CODEC {
                            raw_gateway_url(gateway, &cid)
                        } else {
                            car_gateway_url(gateway, &cid)
                        };
                        let source = TrustlessHttpSource::Gateway {
                            index: gateway_index,
                            count: gateway_count,
                        };
                        let ordinal = next_gateway_index;
                        requests.push(self.manifest_cid_request(
                            cid,
                            gateway_index,
                            ordinal,
                            url,
                            source,
                            gateway_attempt,
                        ));
                        next_gateway_index += 1;
                        next_launch_at = tokio::time::Instant::now() + MANIFEST_CID_HEDGE_DELAY;
                    }
                }
            } else if let Some((gateway_index, ordinal, elapsed_ms, result)) = requests.next().await
            {
                match result {
                    Ok(bytes) => {
                        debug!(
                            gateway_index,
                            gateway_count,
                            cid = %cid,
                            bytes = bytes.len(),
                            elapsed_ms,
                            attempt = manifest_attempt_role(ordinal),
                            representation = if cid.codec() == RAW_CODEC { "raw" } else { "car" },
                            "verified CID gateway fetch succeeded"
                        );
                        return Ok(TrustlessArtifactFetchResult {
                            verified_cid: cid.to_string(),
                            bytes,
                            gateway_index,
                            gateway_count,
                        });
                    }
                    Err(error) => {
                        debug!(
                            ?error,
                            gateway_index,
                            gateway_count,
                            cid = %cid,
                            elapsed_ms,
                            attempt = manifest_attempt_role(ordinal),
                            representation = if cid.codec() == RAW_CODEC { "raw" } else { "car" },
                            "verified CID gateway fetch failed"
                        );
                        last_error = Some(error);
                        next_launch_at = tokio::time::Instant::now();
                    }
                }
            }
        }

        Err(last_error.unwrap_or(TrustlessArtifactError::NoGateways))
    }

    fn manifest_cid_request(
        &self,
        cid: Cid,
        gateway_index: usize,
        ordinal: usize,
        url: Url,
        source: TrustlessHttpSource,
        gateway_attempt: GatewayAttempt,
    ) -> ManifestCidRequest<'_> {
        Box::pin(async move {
            let attempt_started = Instant::now();
            let result = self.fetch_verified_cid_from_url(cid, &url, source).await;
            match &result {
                Ok(_) => gateway_attempt.success(),
                Err(error) => gateway_attempt.failure(error),
            }
            (
                gateway_index,
                ordinal,
                attempt_started.elapsed().as_millis(),
                result,
            )
        })
    }

    async fn fetch_verified_cid_from_url(
        &self,
        cid: Cid,
        url: &Url,
        source: TrustlessHttpSource,
    ) -> Result<Vec<u8>, TrustlessArtifactError> {
        let limits = RetrievalLimits::manifest();
        if cid.codec() == RAW_CODEC {
            let bytes = fetch_response_bytes_with_timeouts(
                self.client,
                url,
                source,
                Some(RAW_ACCEPT),
                limits.reconstructed_bytes,
                self.timeouts,
            )
            .await?;
            verify_raw_cid_bytes(cid, &bytes)?;
            Ok(bytes)
        } else {
            self.fetch_cid_bytes_from_url(cid, url, source, limits, None)
                .await
        }
    }

    async fn fetch_ipns_record_candidate(
        &self,
        url: &Url,
        source: TrustlessHttpSource,
        peer_id: PeerId,
    ) -> Result<IpnsManifestCandidate, TrustlessArtifactError> {
        let bytes = fetch_response_bytes_with_timeouts(
            self.client,
            url,
            source,
            Some(IPNS_RECORD_ACCEPT),
            IPNS_RECORD_MAX_BYTES,
            self.timeouts,
        )
        .await?;
        verify_ipns_record_candidate(&bytes, peer_id)
    }
}

fn finalize_ipns_candidates(
    mut candidates: Vec<(usize, IpnsManifestCandidate)>,
    errors: Vec<(usize, TrustlessArtifactError)>,
) -> Result<Vec<IpnsManifestCandidate>, TrustlessArtifactError> {
    if candidates.is_empty() {
        return Err(errors
            .into_iter()
            .max_by_key(|(gateway_index, _)| *gateway_index)
            .map_or(TrustlessArtifactError::NoValidIpnsRecords, |(_, err)| err));
    }
    // Candidates are in arrival order, so the first occurrence of each pair
    // names the gateway whose record arrived first.
    let mut first_gateway_indices = HashMap::with_capacity(candidates.len());
    for (gateway_index, candidate) in &candidates {
        first_gateway_indices
            .entry((candidate.sequence, candidate.cid))
            .or_insert(*gateway_index);
    }
    candidates
        .sort_by_key(|(gateway_index, candidate)| (Reverse(candidate.sequence), *gateway_index));
    let mut unique_candidates = Vec::with_capacity(first_gateway_indices.len());
    for (_, mut candidate) in candidates {
        if let Some(gateway_index) =
            first_gateway_indices.remove(&(candidate.sequence, candidate.cid))
        {
            candidate.gateway_index = gateway_index;
            unique_candidates.push(candidate);
        }
    }
    Ok(unique_candidates)
}

/// Fetches and verifies a manifest-sized artifact from the configured gateways.
pub async fn fetch_verified_cid(
    client: &reqwest::Client,
    gateways: &[Url],
    cid: &str,
) -> Result<Vec<u8>, VerifiedCidError> {
    let cid = parse_cid(cid).map_err(VerifiedCidError::from)?;
    TrustlessArtifactFetcher::new(client, gateways)
        .fetch_verified_manifest_cid(cid, None)
        .await
        .map(TrustlessArtifactFetchResult::into_bytes)
        .map_err(VerifiedCidError::from)
}

pub async fn fetch_verified_cid_with_pool(
    client: &reqwest::Client,
    gateways: &[Url],
    cid: &str,
    pool: GatewayPool,
) -> Result<Vec<u8>, VerifiedCidError> {
    let cid = parse_cid(cid).map_err(VerifiedCidError::from)?;
    TrustlessArtifactFetcher::new_with_pool(client, gateways, pool)
        .fetch_verified_manifest_cid(cid, None)
        .await
        .map(TrustlessArtifactFetchResult::into_bytes)
        .map_err(VerifiedCidError::from)
}

pub async fn fetch_manifest_url(
    client: &reqwest::Client,
    url: &Url,
) -> Result<Vec<u8>, TrustlessArtifactError> {
    fetch_response_bytes(
        client,
        url,
        TrustlessHttpSource::ExplicitManifest,
        None,
        MANIFEST_JSON_MAX_BYTES,
    )
    .await
}

fn verify_ipns_record_candidate(
    bytes: &[u8],
    peer_id: PeerId,
) -> Result<IpnsManifestCandidate, TrustlessArtifactError> {
    if bytes.len() > IPNS_RECORD_MAX_BYTES {
        return Err(TrustlessArtifactError::IpnsRecordTooLarge {
            limit: IPNS_RECORD_MAX_BYTES,
        });
    }

    let record = rust_ipns::Record::decode(bytes).map_err(|source| {
        TrustlessArtifactError::InvalidIpnsRecord {
            source: source.into(),
        }
    })?;
    verify_ipns_public_key_binding(bytes, peer_id)?;
    record
        .verify_signature(peer_id)
        .map_err(|source| TrustlessArtifactError::InvalidIpnsSignature { source })?;
    if record.validity_type() != rust_ipns::ValidityType::EOL {
        return Err(TrustlessArtifactError::UnsupportedIpnsValidity);
    }
    let eol = record
        .validity()
        .map_err(|source| TrustlessArtifactError::InvalidIpnsRecord {
            source: source.into(),
        })?
        .with_timezone(&Utc);
    let data = record
        .data()
        .map_err(|source| TrustlessArtifactError::InvalidIpnsRecord {
            source: source.into(),
        })?;
    let cid = parse_ipns_value(data.value())?;
    Ok(IpnsManifestCandidate {
        sequence: data.sequence(),
        cid,
        eol,
        // The IPNS phase collector sets the gateway that returned the record.
        gateway_index: 0,
    })
}

fn parse_ipns_value(value: &[u8]) -> Result<Cid, TrustlessArtifactError> {
    let value = str::from_utf8(value)
        .map_err(|_| TrustlessArtifactError::UnsupportedIpnsValue("non-UTF8 value"))?;
    let cid = if let Some(cid) = value.strip_prefix("/ipfs/") {
        if cid.is_empty() || cid.contains('/') {
            return Err(TrustlessArtifactError::UnsupportedIpnsValue(
                "IPNS value must be /ipfs/{cid} without a path suffix",
            ));
        }
        cid
    } else if value.starts_with('/') {
        return Err(TrustlessArtifactError::UnsupportedIpnsValue(
            "IPNS value must be /ipfs/{cid} or a bare CID",
        ));
    } else {
        value
    };
    parse_cid(cid)
}

fn expected_ipns_peer_id(name: &str) -> Result<PeerId, TrustlessArtifactError> {
    let cid = parse_cid(name)?;
    if cid.version() != Version::V1 || cid.codec() != LIBP2P_KEY_CODEC {
        return Err(TrustlessArtifactError::UnsupportedIpnsName {
            name: name.to_string(),
        });
    }
    PeerId::from_bytes(&cid.hash().to_bytes())
        .map_err(|source| TrustlessArtifactError::InvalidIpnsPeerId { source })
}

fn verify_ipns_public_key_binding(
    bytes: &[u8],
    expected_peer_id: PeerId,
) -> Result<(), TrustlessArtifactError> {
    let Some(public_key_bytes) = ipns_record_public_key(bytes)? else {
        return Ok(());
    };
    let public_key = PublicKey::try_decode_protobuf(public_key_bytes)
        .map_err(|source| TrustlessArtifactError::InvalidIpnsPublicKey { source })?;
    let actual_peer_id = public_key.to_peer_id();
    if actual_peer_id != expected_peer_id {
        return Err(TrustlessArtifactError::IpnsPublicKeyMismatch {
            expected: Box::new(expected_peer_id),
            actual: Box::new(actual_peer_id),
        });
    }
    Ok(())
}

fn ipns_record_public_key(bytes: &[u8]) -> Result<Option<&[u8]>, TrustlessArtifactError> {
    let mut reader = BytesReader::from_bytes(bytes);
    let mut public_key = None;
    while !reader.is_eof() {
        match reader
            .next_tag(bytes)
            .map_err(|source| invalid_ipns_record_error(&source))?
        {
            58 => {
                let value = reader
                    .read_bytes(bytes)
                    .map_err(|source| invalid_ipns_record_error(&source))?;
                if value.is_empty() {
                    public_key = None;
                } else {
                    public_key = Some(value);
                }
            }
            tag => reader
                .read_unknown(bytes, tag)
                .map_err(|source| invalid_ipns_record_error(&source))?,
        }
    }
    Ok(public_key)
}

fn invalid_ipns_record_error(source: &quick_protobuf::Error) -> TrustlessArtifactError {
    TrustlessArtifactError::InvalidIpnsRecord {
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, source.to_string()),
    }
}

fn parse_cid(value: &str) -> Result<Cid, TrustlessArtifactError> {
    Cid::try_from(value).map_err(|source| TrustlessArtifactError::InvalidCid { source })
}

#[derive(Debug, Clone, Copy)]
enum RawMultihash {
    Identity,
    Sha2_256,
    Blake2b256,
}

const fn raw_multihash_policy(cid: Cid) -> Result<RawMultihash, TrustlessArtifactError> {
    match cid.hash().code() {
        0x00 => Ok(RawMultihash::Identity),
        0x12 => Ok(RawMultihash::Sha2_256),
        0xb220 => Ok(RawMultihash::Blake2b256),
        code => Err(TrustlessArtifactError::UnsupportedMultihash { cid, code }),
    }
}

fn verify_raw_cid_bytes(cid: Cid, bytes: &[u8]) -> Result<(), TrustlessArtifactError> {
    let multihash = raw_multihash_policy(cid)?;
    let matches = match multihash {
        RawMultihash::Identity => cid.hash().digest() == bytes,
        RawMultihash::Sha2_256 => {
            let digest = Sha256::digest(bytes);
            cid.hash().digest() == &digest[..]
        }
        RawMultihash::Blake2b256 => {
            let digest = Params::new()
                .hash_length(32)
                .to_state()
                .update(bytes)
                .finalize();
            cid.hash().digest() == digest.as_bytes()
        }
    };
    if !matches {
        return Err(TrustlessArtifactError::RawCidDigestMismatch { cid });
    }
    Ok(())
}

#[cfg(test)]
impl TrustlessArtifactFetcher<'_> {
    const fn with_http_timeouts_for_test(
        mut self,
        headers: Duration,
        idle: Duration,
        total: Duration,
    ) -> Self {
        self.timeouts = HttpAttemptTimeouts {
            headers,
            idle,
            total,
        };
        self
    }
}

#[cfg(test)]
mod tests;
