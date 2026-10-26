use crate::address_policy::{retain_tor_safe_addrs, with_peer_id, without_trailing_peer_id};
use crate::config::{NodeConfig, WakuTransportProfile};
use crate::discovery;
use crate::discovery::DiscoveryConfig;
use crate::error::WakuError;
use crate::proto;
use crate::proto::HashKey;
use crate::protocols;
use crate::transport::{FilterPushEvent, ReqId, TransportCmd, TransportEvent};
use crate::types::OpId;
use libp2p::request_response::OutboundFailure;
use libp2p::swarm::DialError;
use libp2p::{Multiaddr, PeerId};
use lru::LruCache;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::{Mutex, Notify, broadcast, mpsc, oneshot, watch};
use tokio::time::Instant;
use tracing::{debug, error, trace, warn};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerStats {
    /// Currently connected peer IDs.
    pub connected_peers: Vec<PeerId>,
    /// Total number of known peers (connected or not).
    pub known_peers: usize,
    /// Number of peers currently being dialed.
    pub dialing_count: usize,
    /// Number of connected peers that support `LightPush` v3.
    pub lightpush_capable: usize,
    /// Number of connected peers that support Peer Exchange.
    pub peer_exchange_capable: usize,
}

/// A read-only snapshot of a single peer's state suitable for UI rendering.
///
/// Intentionally flat and additive; do not expose mutation or coordinator control
/// surfaces through this type.
#[derive(Debug, Clone)]
pub struct PeerSnapshot {
    pub peer_id: PeerId,
    pub addrs: Vec<Multiaddr>,
    pub connected: bool,
    pub dialing: bool,
    pub supports_lightpush_v3: bool,
    pub supports_peer_exchange: bool,
    pub supports_filter: bool,
    pub dial_failures: u32,
}

#[derive(Debug)]
pub struct LightPushResult {
    pub peer_id: PeerId,
    pub status_code: Option<u32>,
    pub status_desc: Option<String>,
    pub relay_peer_count: Option<u32>,
    pub error: Option<OutboundFailure>,
}

impl LightPushResult {
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.error.is_none() && self.status_code == Some(200)
    }
}

#[derive(Debug, Clone)]
pub struct StoreQueryOptions {
    pub pubsub_topic: String,
    pub content_topics: Vec<String>,
    pub time_start: Option<i64>,
    pub time_end: Option<i64>,
    pub pagination_limit: Option<u64>,
}

impl StoreQueryOptions {
    pub fn validate(&self) -> Result<(), WakuError> {
        if self.pubsub_topic.is_empty() {
            return Err(WakuError::InvalidArgument(
                "pubsub_topic cannot be empty".to_string(),
            ));
        }
        if self.content_topics.is_empty() {
            return Err(WakuError::InvalidArgument(
                "content_topics cannot be empty".to_string(),
            ));
        }
        Ok(())
    }

    fn to_request(&self, pagination_cursor: Option<Vec<u8>>) -> proto::store::StoreQueryRequest {
        proto::store::StoreQueryRequest {
            request_id: uuid::Uuid::new_v4().to_string(),
            include_data: true,
            pubsub_topic: Some(self.pubsub_topic.clone()),
            content_topics: self.content_topics.clone(),
            time_start: self.time_start,
            time_end: self.time_end,
            message_hashes: Vec::new(),
            pagination_cursor,
            pagination_forward: true,
            pagination_limit: self.pagination_limit,
        }
    }
}

const MAX_LEARNED_PEERS: usize = 256;
const MAX_ADDRS_PER_PEER: usize = 16;

/// Where a peer book entry came from, weakest first.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum PeerSource {
    #[default]
    Learned,
    Dns {
        last_round: u64,
    },
    Configured,
}

impl PeerSource {
    const fn upgraded(self, incoming: Self) -> Self {
        match (self, incoming) {
            (_, Self::Configured) | (Self::Learned, Self::Dns { .. }) => incoming,
            (Self::Dns { last_round: old }, Self::Dns { last_round: new }) => Self::Dns {
                last_round: if new > old { new } else { old },
            },
            (current, _) => current,
        }
    }
}

#[derive(Debug, Default)]
struct PeerState {
    source: PeerSource,
    addrs: Vec<Multiaddr>,
    connected: bool,
    supports_lightpush_v3: bool,
    supports_peer_exchange: bool,
    supports_filter: bool,
    supports_store: bool,
    dial_failures: u32,
    next_dial_at: Option<Instant>,
    last_peer_exchange_at: Option<Instant>,
}

#[derive(Debug, Default)]
pub struct PeerBook {
    peers: HashMap<PeerId, PeerState>,
    connected: HashSet<PeerId>,
    dialing: HashSet<PeerId>,
}

impl PeerBook {
    /// Get statistics about the current peer state.
    #[must_use]
    pub fn get_stats(&self) -> PeerStats {
        let connected_peers: Vec<PeerId> = self.connected.iter().copied().collect();
        let lightpush_capable = self
            .connected
            .iter()
            .filter(|p| self.peers.get(p).is_some_and(|s| s.supports_lightpush_v3))
            .count();
        let peer_exchange_capable = self
            .connected
            .iter()
            .filter(|p| self.peers.get(p).is_some_and(|s| s.supports_peer_exchange))
            .count();

        PeerStats {
            connected_peers,
            known_peers: self.peers.len(),
            dialing_count: self.dialing.len(),
            lightpush_capable,
            peer_exchange_capable,
        }
    }

    /// Get the list of currently connected peers.
    #[must_use]
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.connected.iter().copied().collect()
    }

    #[must_use]
    pub fn num_connections(&self) -> usize {
        self.connected.len() + self.dialing.len()
    }

    /// Build a read-only snapshot of every known peer's state.
    #[must_use]
    pub fn peer_snapshots(&self) -> Vec<PeerSnapshot> {
        self.peers
            .iter()
            .map(|(peer_id, state)| PeerSnapshot {
                peer_id: *peer_id,
                addrs: state.addrs.clone(),
                connected: self.connected.contains(peer_id),
                dialing: self.dialing.contains(peer_id),
                supports_lightpush_v3: state.supports_lightpush_v3,
                supports_peer_exchange: state.supports_peer_exchange,
                supports_filter: state.supports_filter,
                dial_failures: state.dial_failures,
            })
            .collect()
    }
}

fn record_dial_failure(state: &mut PeerState, now: Instant) {
    state.dial_failures = state.dial_failures.saturating_add(1);
    let pow = state.dial_failures.min(8);
    let backoff = Duration::from_secs(1 << pow);
    state.next_dial_at = Some(now + backoff);
}

fn apply_addr_policy(tor: bool, addrs: &mut Vec<Multiaddr>) {
    if tor {
        retain_tor_safe_addrs(addrs);
    } else {
        addrs.sort();
    }
}

/// Keeps the most recently announced addresses, then sorts them by the address policy.
fn merge_addrs(addrs: &mut Vec<Multiaddr>, announced: Vec<Multiaddr>, tor: bool) {
    let mut merged = Vec::with_capacity(MAX_ADDRS_PER_PEER);
    for addr in announced.into_iter().chain(std::mem::take(addrs)) {
        if merged.len() == MAX_ADDRS_PER_PEER {
            break;
        }
        if !merged.contains(&addr) {
            merged.push(addr);
        }
    }
    apply_addr_policy(tor, &mut merged);
    *addrs = merged;
}

fn is_idle(book: &PeerBook, peer_id: &PeerId) -> bool {
    !book.connected.contains(peer_id) && !book.dialing.contains(peer_id)
}

/// Evicts idle learned peers without addresses, then those with the most dial failures, until
/// fewer than `MAX_LEARNED_PEERS` remain or nothing is eligible. Returns the learned count.
fn evict_idle_learned_peers(book: &mut PeerBook) -> usize {
    let mut learned = book
        .peers
        .values()
        .filter(|state| state.source == PeerSource::Learned)
        .count();
    while learned >= MAX_LEARNED_PEERS {
        let victim = book
            .peers
            .iter()
            .filter(|(peer_id, state)| {
                state.source == PeerSource::Learned && is_idle(book, peer_id)
            })
            .max_by_key(|(_, state)| (state.addrs.is_empty(), state.dial_failures))
            .filter(|(_, state)| state.addrs.is_empty() || state.dial_failures > 0)
            .map(|(peer_id, _)| *peer_id);
        let Some(victim) = victim else { break };
        book.peers.remove(&victim);
        learned -= 1;
    }
    learned
}

/// Adds or updates a peer. A new learned peer needs a free learned slot. Returns whether the
/// peer is in the book afterwards.
fn insert_peer(
    book: &mut PeerBook,
    peer_id: PeerId,
    addrs: Vec<Multiaddr>,
    source: PeerSource,
    tor: bool,
) -> bool {
    if let Some(state) = book.peers.get_mut(&peer_id) {
        state.source = state.source.upgraded(source);
        merge_addrs(&mut state.addrs, addrs, tor);
        return true;
    }
    if source == PeerSource::Learned && evict_idle_learned_peers(book) >= MAX_LEARNED_PEERS {
        debug!(%peer_id, "learned peer limit reached, dropping peer");
        return false;
    }
    let mut state = PeerState {
        source,
        ..PeerState::default()
    };
    merge_addrs(&mut state.addrs, addrs, tor);
    book.peers.insert(peer_id, state);
    true
}

/// Removes the least recently discovered idle DNS peers until at most `bound` remain.
fn retain_dns_peers(book: &mut PeerBook, bound: usize) {
    let dns = book
        .peers
        .values()
        .filter(|state| matches!(state.source, PeerSource::Dns { .. }))
        .count();
    if dns <= bound {
        return;
    }
    let mut idle = book
        .peers
        .iter()
        .filter_map(|(peer_id, state)| match state.source {
            PeerSource::Dns { last_round } if is_idle(book, peer_id) => {
                Some((last_round, *peer_id))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    idle.sort_unstable_by_key(|(last_round, _)| *last_round);
    for (_, peer_id) in idle.into_iter().take(dns - bound) {
        book.peers.remove(&peer_id);
    }
}

fn remap_wrong_peer_id(
    book: &mut PeerBook,
    expected_peer_id: PeerId,
    obtained_peer_id: PeerId,
    address: &Multiaddr,
    now: Instant,
    tor: bool,
) {
    let dialed_addr = without_trailing_peer_id(address);
    let expected_exhausted = book.peers.get_mut(&expected_peer_id).is_some_and(|state| {
        state
            .addrs
            .retain(|addr| without_trailing_peer_id(addr) != dialed_addr);
        record_dial_failure(state, now);
        state.source == PeerSource::Learned && state.addrs.is_empty()
    });
    if expected_exhausted && is_idle(book, &expected_peer_id) {
        book.peers.remove(&expected_peer_id);
    }

    let remapped_addr = with_peer_id(address, obtained_peer_id);
    if let Some(state) = book.peers.get_mut(&obtained_peer_id) {
        state
            .addrs
            .retain(|addr| without_trailing_peer_id(addr) != dialed_addr);
        merge_addrs(&mut state.addrs, vec![remapped_addr], tor);
    } else {
        insert_peer(
            book,
            obtained_peer_id,
            vec![remapped_addr],
            PeerSource::Learned,
            tor,
        );
    }
}

#[derive(Debug)]
struct ResponseBatch<T> {
    expected: usize,
    finished: usize,
    results: Vec<T>,
    deadline: Instant,
}

#[derive(Debug, Default)]
struct LightPushState {
    pending: HashMap<ReqId, (OpId, PeerId)>,
    ops: HashMap<OpId, ResponseBatch<LightPushResult>>,
    waiters: HashMap<OpId, oneshot::Sender<Result<Vec<LightPushResult>, WakuError>>>,
}

fn remove_lightpush_operation(
    state: &mut LightPushState,
    op_id: OpId,
) -> Option<oneshot::Sender<Result<Vec<LightPushResult>, WakuError>>> {
    state.ops.remove(&op_id);
    state
        .pending
        .retain(|_, (pending_op_id, _)| *pending_op_id != op_id);
    state.waiters.remove(&op_id)
}

fn record_lightpush_result(
    batch: &mut ResponseBatch<LightPushResult>,
    result: LightPushResult,
) -> bool {
    batch.finished += 1;
    let accepted = result.is_success();
    batch.results.push(result);
    accepted || batch.finished >= batch.expected
}

#[derive(Debug)]
struct PeerExchangeOp {
    remaining_rounds: usize,
    current_batch: Option<usize>,
    deadline: Instant,
}

#[derive(Debug, Default)]
struct PeerExchangeState {
    pending: HashMap<ReqId, usize>,
    ops: HashMap<usize, ResponseBatch<Vec<u8>>>,
    next_batch_id: usize,
    round_ops: HashMap<OpId, PeerExchangeOp>,
    waiters: HashMap<OpId, oneshot::Sender<()>>,
}

/// Unique identifier for a filter subscription.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct SubId(u64);

impl SubId {
    fn next(counter: &AtomicU64) -> Self {
        Self(counter.fetch_add(1, Ordering::Relaxed))
    }
}

/// A single filter subscription.
#[derive(Debug)]
struct Subscription {
    pubsub_topic: String,
    content_topics: Vec<String>,
    sender: mpsc::Sender<proto::WakuMessage>,
    dropped_since_log: u64,
    last_drop_log: Option<Instant>,
}

#[derive(Debug)]
enum FilterOp {
    Subscribe { sub_id: SubId },
    Unsubscribe { sub_id: SubId, batch_id: u64 },
    UnsubscribeAll { pubsub_topic: String, batch_id: u64 },
    SubscribeOnPeer { sub_id: SubId },
}

#[derive(Debug)]
struct FilterBatch {
    expected: usize,
    finished: usize,
    succeeded: bool,
    waiter: oneshot::Sender<Result<(), WakuError>>,
    last_error: Option<WakuError>,
}

#[derive(Debug)]
struct FilterState {
    /// Active subscriptions by ID.
    subscriptions: HashMap<SubId, Subscription>,
    /// Pending outbound requests.
    pending: HashMap<ReqId, FilterOp>,
    /// Dedup cache: hash of (`content_topic`, `payload`).
    dedup_cache: LruCache<u64, ()>,
    /// Next subscription ID counter.
    next_sub_id: AtomicU64,
    /// Next batch ID counter.
    next_batch_id: AtomicU64,
    /// Pending unsubscribe batches.
    batches: HashMap<u64, FilterBatch>,
}

impl Default for FilterState {
    fn default() -> Self {
        Self {
            subscriptions: HashMap::default(),
            pending: HashMap::default(),
            dedup_cache: LruCache::new(NonZeroUsize::new(DEDUP_CACHE_SIZE).unwrap()),
            next_sub_id: AtomicU64::default(),
            next_batch_id: AtomicU64::default(),
            batches: HashMap::default(),
        }
    }
}

#[derive(Debug)]
struct StorePending {
    waiter: oneshot::Sender<Result<protocols::store::StoreQueryPage, WakuError>>,
    deadline: Instant,
}

#[derive(Debug, Default)]
struct StoreState {
    pending: HashMap<ReqId, StorePending>,
}

struct OpTracker {
    next_req_id: AtomicU64,
    lightpush: Mutex<LightPushState>,
    peer_exchange: Mutex<PeerExchangeState>,
    filter: Mutex<FilterState>,
    store: Mutex<StoreState>,
}

const DEDUP_CACHE_SIZE: usize = 500;
const STORE_PEER_EVENT_CAPACITY: usize = 64;

impl OpTracker {
    fn new() -> Self {
        Self {
            next_req_id: AtomicU64::new(1),
            lightpush: Mutex::new(LightPushState::default()),
            peer_exchange: Mutex::new(PeerExchangeState::default()),
            filter: Mutex::new(FilterState::default()),
            store: Mutex::new(StoreState::default()),
        }
    }

    fn next_req_id(&self) -> ReqId {
        self.next_req_id.fetch_add(1, Ordering::Relaxed)
    }
}

fn build_filter_request(
    filter_type: proto::filter::filter_subscribe_request::FilterSubscribeType,
    pubsub_topic: String,
    content_topics: Vec<String>,
) -> proto::filter::FilterSubscribeRequest {
    proto::filter::FilterSubscribeRequest {
        request_id: uuid::Uuid::new_v4().to_string(),
        filter_subscribe_type: filter_type as i32,
        pubsub_topic: Some(pubsub_topic),
        content_topics,
    }
}

fn store_status_ok(response: &proto::store::StoreQueryResponse) -> bool {
    response
        .status_code
        .is_none_or(|status_code| (200..300).contains(&status_code))
}

const fn tor_discovery_retry_delay(failures: u32) -> Duration {
    match failures {
        0 => Duration::from_secs(10),
        1 => Duration::from_secs(30),
        2 => Duration::from_mins(1),
        _ => Duration::from_mins(5),
    }
}

async fn shutdown_changed_or_requested(shutdown: &mut watch::Receiver<bool>) -> bool {
    if *shutdown.borrow() {
        return true;
    }
    shutdown.changed().await.is_err() || *shutdown.borrow()
}

async fn sleep_or_shutdown(duration: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(duration) => false,
        should_shutdown = shutdown_changed_or_requested(shutdown) => should_shutdown,
    }
}

struct NodeInner {
    config: NodeConfig,
    discovery_config: DiscoveryConfig,
    network_profile: WakuTransportProfile,
    peer_book: Arc<RwLock<PeerBook>>,
    session_refresh_disconnects: RwLock<HashSet<PeerId>>,
    discovery_wake: Notify,
    ops: OpTracker,
    transport_tx: mpsc::Sender<TransportCmd>,
    dial_tx: mpsc::Sender<PeerId>,
    metadata_response: proto::metadata::WakuMetadataResponse,
    peer_exchange_cooldown: Duration,
    op_counter: AtomicU64,
    dns_round: AtomicU64,
    store_peer_tx: broadcast::Sender<PeerId>,
    shutdown_tx: watch::Sender<bool>,
}

impl NodeInner {
    fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
        self.discovery_wake.notify_waiters();
    }

    fn is_shutdown(&self) -> bool {
        *self.shutdown_tx.borrow()
    }

    const fn uses_tor_profile(&self) -> bool {
        matches!(self.network_profile, WakuTransportProfile::Tor)
    }

    fn apply_addr_policy(&self, addrs: &mut Vec<Multiaddr>) {
        apply_addr_policy(self.uses_tor_profile(), addrs);
    }

    fn maybe_dial(&self) {
        let book = self.peer_book.read();

        if self.uses_tor_profile() && !self.session_refresh_disconnects.read().is_empty() {
            trace!("waiting for Waku session refresh disconnects before dialing");
            return;
        }

        if book.num_connections() >= self.config.connection_cap {
            trace!(
                connections = book.num_connections(),
                "connection cap reached, not dialing any more peers"
            );
            return;
        }

        let now = Instant::now();
        let mut in_flight = 0;

        for (peer_id, state) in &book.peers {
            if book.num_connections() + in_flight >= self.config.connection_cap
                || state.connected
                || book.dialing.contains(peer_id)
                || state.next_dial_at.is_some_and(|next| next > now)
                || state.addrs.is_empty()
                || in_flight >= self.config.dial_concurrency
            {
                continue;
            }

            if let Err(error) = self.dial_tx.try_send(*peer_id) {
                debug!(%peer_id, %error, "dial queue full, dropping request");
                continue;
            }

            in_flight += 1;
        }
    }

    async fn discover(&self) -> Result<usize, discovery::DiscoveryError> {
        let peers = self.discovery_config.discover_all().await?;
        let round = self.dns_round.fetch_add(1, Ordering::Relaxed) + 1;
        Ok(self.apply_discovered_peers(peers, PeerSource::Dns { last_round: round }))
    }

    async fn peer_exchange_rounds(&self, rounds: usize) -> Result<(), WakuError> {
        if rounds == 0 {
            return Ok(());
        }

        let op_id = OpId::next(&self.op_counter);
        let (tx, rx) = oneshot::channel();

        {
            let mut px = self.ops.peer_exchange.lock().await;
            px.waiters.insert(op_id, tx);

            let op = PeerExchangeOp {
                remaining_rounds: rounds,
                current_batch: None,
                deadline: Instant::now() + self.config.request_timeout,
            };
            px.round_ops.insert(op_id, op);
        }

        self.start_peer_exchange_round(op_id).await;
        rx.await.map_err(|_| WakuError::Cancelled)
    }

    fn apply_discovered_peers(
        &self,
        peers: Vec<discovery::DiscoveredPeer>,
        source: PeerSource,
    ) -> usize {
        let discovered = peers.len();
        let tor = self.uses_tor_profile();
        let peers = peers
            .into_iter()
            .filter_map(|mut peer| {
                self.apply_addr_policy(&mut peer.addrs);
                (!peer.addrs.is_empty()).then_some(peer)
            })
            .collect::<Vec<_>>();
        let usable = peers.len();

        let known = {
            let mut book = self.peer_book.write();
            for peer in peers {
                insert_peer(&mut book, peer.peer_id, peer.addrs, source, tor);
            }
            if matches!(source, PeerSource::Dns { .. }) {
                let bound = self
                    .discovery_config
                    .max_enrs_per_tree
                    .saturating_mul(self.discovery_config.enr_trees.len());
                retain_dns_peers(&mut book, bound);
            }
            book.peers.len()
        };

        debug!(discovered, usable, known, "applied discovered peers");
        self.maybe_dial();
        usable
    }

    async fn run_discovery_loop(self: Arc<Self>) {
        let mut tor_zero_peer_failures = 0_u32;
        let mut shutdown = self.shutdown_tx.subscribe();
        loop {
            let discover = self.discover();
            let result = tokio::select! {
                result = discover => result,
                should_shutdown = shutdown_changed_or_requested(&mut shutdown) => {
                    if should_shutdown {
                        debug!("discovery loop shutting down");
                        break;
                    }
                    continue;
                }
            };
            match result {
                Ok(usable) if usable > 0 => tor_zero_peer_failures = 0,
                Ok(_) => {
                    if self.uses_tor_profile() {
                        tor_zero_peer_failures = tor_zero_peer_failures.saturating_add(1);
                    }
                }
                Err(error) => {
                    warn!(?error, "dns discovery failed");
                    if self.uses_tor_profile() {
                        tor_zero_peer_failures = tor_zero_peer_failures.saturating_add(1);
                    }
                }
            }

            let connected = self.peer_book.read().connected.len();
            let sleep_for = if self.uses_tor_profile() && connected == 0 {
                tor_discovery_retry_delay(tor_zero_peer_failures.saturating_sub(1))
            } else {
                self.discovery_config.dns_discovery_interval
            };
            tokio::select! {
                () = tokio::time::sleep(sleep_for) => {}
                () = self.discovery_wake.notified() => {}
                should_shutdown = shutdown_changed_or_requested(&mut shutdown) => {
                    if should_shutdown {
                        debug!("discovery loop shutting down");
                        break;
                    }
                }
            }
        }
    }

    fn refresh_network_session(&self) {
        let connected_peers = {
            let book = self.peer_book.read();
            book.connected.iter().copied().collect::<Vec<_>>()
        };

        {
            let mut book = self.peer_book.write();
            self.session_refresh_disconnects
                .write()
                .extend(connected_peers.iter().copied());
            book.connected.clear();
            book.dialing.clear();
            for state in book.peers.values_mut() {
                state.connected = false;
                state.dial_failures = 0;
                state.next_dial_at = None;
            }
        }

        if let Err(error) = self.transport_tx.try_send(TransportCmd::DisconnectPeers {
            peers: connected_peers.clone(),
        }) {
            warn!(%error, "failed to request Waku peer disconnect after network session refresh");
            self.session_refresh_disconnects.write().clear();
        }
        self.discovery_wake.notify_one();
        if connected_peers.is_empty() {
            self.maybe_dial();
        }
    }

    async fn run_peer_exchange_loop(self: Arc<Self>) {
        let mut shutdown = self.shutdown_tx.subscribe();
        loop {
            let connected = self.peer_book.read().connected.len();
            let interval = if connected < self.discovery_config.peer_exchange_bootstrap_peers {
                self.discovery_config.peer_exchange_bootstrap_interval
            } else {
                self.discovery_config.peer_exchange_interval
            };

            if connected == 0 {
                debug!("skipping peer exchange: no connected peers");
                if sleep_or_shutdown(interval, &mut shutdown).await {
                    debug!("peer exchange loop shutting down");
                    break;
                }
                continue;
            }

            if connected >= self.config.connection_cap {
                debug!("skipping peer exchange: connection cap reached");
                if sleep_or_shutdown(interval, &mut shutdown).await {
                    debug!("peer exchange loop shutting down");
                    break;
                }
                continue;
            }

            debug!(connected, "performing peer exchange");
            let result = tokio::select! {
                result = self.peer_exchange_rounds(self.discovery_config.peer_exchange_rounds) => result,
                should_shutdown = shutdown_changed_or_requested(&mut shutdown) => {
                    if should_shutdown {
                        debug!("peer exchange loop shutting down");
                        break;
                    }
                    continue;
                }
            };
            match result {
                Ok(()) => {}
                Err(WakuError::Cancelled) => warn!("peer exchange cancelled"),
                Err(error) => {
                    error!(?error, "peer exchange failed, stopping loop");
                    break;
                }
            }

            if sleep_or_shutdown(interval, &mut shutdown).await {
                debug!("peer exchange loop shutting down");
                break;
            }
        }
    }

    async fn run_dialer(self: Arc<Self>, mut dial_rx: mpsc::Receiver<PeerId>) {
        let mut shutdown = self.shutdown_tx.subscribe();
        loop {
            let peer_id = tokio::select! {
                peer_id = dial_rx.recv() => peer_id,
                should_shutdown = shutdown_changed_or_requested(&mut shutdown) => {
                    if should_shutdown {
                        debug!("dialer loop shutting down");
                        break;
                    }
                    continue;
                }
            };
            let Some(peer_id) = peer_id else { break };
            let addrs = {
                let mut book = self.peer_book.write();

                if book.num_connections() >= self.config.connection_cap {
                    debug!(%peer_id, "connection cap reached, dropping dial request");
                    continue;
                }

                if book.connected.contains(&peer_id) || book.dialing.contains(&peer_id) {
                    debug!(%peer_id, "peer already connected or dialing, dropping request");
                    continue;
                }

                let Some(state) = book.peers.get(&peer_id) else {
                    debug!(%peer_id, "missing peer state, dropping request");
                    continue;
                };

                if state.addrs.is_empty() {
                    debug!(%peer_id, "peer has no addrs, dropping request");
                    continue;
                }

                let mut addrs = state.addrs.clone();
                self.apply_addr_policy(&mut addrs);
                if addrs.is_empty() {
                    debug!(%peer_id, "peer has no Tor-safe addrs, dropping dial request");
                    continue;
                }
                book.dialing.insert(peer_id);
                addrs
            };

            if let Err(error) = self
                .transport_tx
                .try_send(TransportCmd::Dial { peer_id, addrs })
            {
                debug!(%peer_id, %error, "failed to send dial command, rolling back");
                let mut book = self.peer_book.write();
                book.dialing.remove(&peer_id);
            }
        }
    }

    async fn run_event_loop(
        self: Arc<Self>,
        mut transport_rx: mpsc::Receiver<TransportEvent>,
        mut filter_push_rx: mpsc::Receiver<FilterPushEvent>,
    ) {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        let mut shutdown = self.shutdown_tx.subscribe();

        loop {
            tokio::select! {
                should_shutdown = shutdown_changed_or_requested(&mut shutdown) => {
                    if should_shutdown {
                        debug!("event loop shutting down");
                        break;
                    }
                }
                _ = tick.tick() => {
                    self.handle_tick(Instant::now()).await;
                }
                ev = transport_rx.recv() => {
                    let Some(ev) = ev else { break };
                    self.handle_transport_event(ev).await;
                }
                push = filter_push_rx.recv() => {
                    let Some(push) = push else { break };
                    self.handle_filter_push(push.peer_id, *push.push).await;
                }
            }
        }
    }

    async fn handle_tick(&self, now: Instant) {
        // LightPush timeouts
        {
            let mut lp = self.ops.lightpush.lock().await;
            let expired = lp
                .ops
                .iter()
                .filter_map(|(op_id, op)| (op.deadline <= now).then_some(*op_id))
                .collect::<Vec<_>>();

            for op_id in expired {
                if let Some(tx) = remove_lightpush_operation(&mut lp, op_id)
                    && tx.send(Err(WakuError::RequestTimeout)).is_err()
                {
                    debug!(?op_id, "lightpush results receiver dropped");
                }
            }
        }

        // PeerExchange timeouts
        let expired_batches = {
            let mut px = self.ops.peer_exchange.lock().await;
            px.ops
                .extract_if(|_, batch| batch.deadline <= now)
                .map(|(batch_id, batch)| (batch_id, batch.results))
                .collect::<Vec<_>>()
        };

        for (batch_id, enrs) in expired_batches {
            self.finish_peer_exchange_batch(batch_id, enrs).await;
        }

        // Store query timeouts
        let expired_store_queries = {
            let mut store = self.ops.store.lock().await;
            store
                .pending
                .extract_if(|_, pending| pending.deadline <= now)
                .collect::<Vec<_>>()
        };

        for (req_id, pending) in expired_store_queries {
            if let Err(error) = pending.waiter.send(Err(WakuError::StoreRequestFailed)) {
                debug!(?req_id, ?error, "store query receiver dropped");
            }
        }

        {
            let mut filter = self.ops.filter.lock().await;
            for (sub_id, subscription) in &mut filter.subscriptions {
                if subscription.dropped_since_log == 0
                    || subscription
                        .last_drop_log
                        .is_none_or(|last| now.duration_since(last) < Duration::from_secs(30))
                {
                    continue;
                }
                debug!(
                    ?sub_id,
                    pubsub_topic = subscription.pubsub_topic,
                    content_topics = ?subscription.content_topics,
                    dropped = subscription.dropped_since_log,
                    "filter subscription dropped messages since last capacity warning"
                );
                subscription.dropped_since_log = 0;
                subscription.last_drop_log = Some(now);
            }
        }

        self.maybe_dial();
    }

    async fn handle_transport_event(&self, ev: TransportEvent) {
        match ev {
            TransportEvent::ConnectionEstablished { peer_id } => {
                debug!(%peer_id, "connected");
                let supports_store = {
                    let mut book = self.peer_book.write();
                    book.connected.insert(peer_id);
                    book.dialing.remove(&peer_id);
                    let state = book.peers.entry(peer_id).or_default();
                    state.connected = true;
                    if state.dial_failures > 5
                        && state.next_dial_at.is_some_and(|t| t <= Instant::now())
                    {
                        state.dial_failures = state.dial_failures.saturating_sub(1);
                    }
                    state.supports_store
                };
                if supports_store {
                    debug!(%peer_id, "connected peer supports store");
                    let _ = self.store_peer_tx.send(peer_id);
                }
                self.maybe_dial();
            }
            TransportEvent::ConnectionClosed { peer_id } => {
                debug!(%peer_id, "disconnected");
                let suppress_backoff = self.session_refresh_disconnects.write().remove(&peer_id);
                {
                    let mut book = self.peer_book.write();
                    book.connected.remove(&peer_id);
                    if !suppress_backoff {
                        book.dialing.remove(&peer_id);
                    }
                    if let Some(state) = book.peers.get_mut(&peer_id) {
                        state.connected = false;
                        if suppress_backoff {
                            state.next_dial_at = None;
                        } else {
                            record_dial_failure(state, Instant::now());
                        }
                    }
                }
                self.maybe_dial();
            }
            TransportEvent::DialError { peer_id, error } => {
                debug!(%peer_id, ?error, "dial error");
                let now = Instant::now();
                let mut book = self.peer_book.write();
                book.dialing.remove(&peer_id);
                if let DialError::WrongPeerId { obtained, address } = error {
                    debug!(
                        expected_peer_id=%peer_id,
                        obtained_peer_id=%obtained,
                        %address,
                        "remapping stale peer address to authenticated peer id"
                    );
                    remap_wrong_peer_id(
                        &mut book,
                        peer_id,
                        obtained,
                        &address,
                        now,
                        self.uses_tor_profile(),
                    );
                } else if let Some(state) = book.peers.get_mut(&peer_id) {
                    record_dial_failure(state, now);
                }
            }
            TransportEvent::IdentifyReceived {
                peer_id,
                protocols,
                mut addrs,
            } => {
                trace!(%peer_id, ?addrs, ?protocols, "received identify");
                self.apply_addr_policy(&mut addrs);
                let supports_lightpush = protocols
                    .iter()
                    .any(|p| p == protocols::lightpush::LIGHTPUSH_V3_CODEC);
                let supports_px = protocols
                    .iter()
                    .any(|p| p == protocols::peer_exchange::PEER_EXCHANGE_CODEC);
                let supports_filter = protocols
                    .iter()
                    .any(|p| p == protocols::filter::FILTER_SUBSCRIBE_CODEC);
                let supports_store = protocols
                    .iter()
                    .any(|p| p == protocols::store::STORE_QUERY_CODEC);

                let became_store_capable = {
                    let mut book = self.peer_book.write();
                    let entry = book.peers.entry(peer_id).or_default();
                    let became_store_capable =
                        supports_store && entry.connected && !entry.supports_store;
                    entry.supports_lightpush_v3 = supports_lightpush;
                    entry.supports_peer_exchange = supports_px;
                    entry.supports_filter = supports_filter;
                    entry.supports_store = supports_store;
                    merge_addrs(&mut entry.addrs, addrs, self.uses_tor_profile());
                    became_store_capable
                };

                if became_store_capable {
                    debug!(%peer_id, "peer supports store");
                    let _ = self.store_peer_tx.send(peer_id);
                }

                // Resubscribe to filter on reconnect if peer supports filter
                if supports_filter {
                    self.subscribe_on_peer(peer_id).await;
                }
            }
            TransportEvent::MetadataRequest { peer_id, channel } => {
                debug!(%peer_id, "received metadata request");
                let response = self.metadata_response.clone();
                if let Err(error) = self
                    .transport_tx
                    .try_send(TransportCmd::SendMetadataResponse { channel, response })
                {
                    error!(%error, "failed to send metadata response command");
                }
            }
            TransportEvent::LightPushResponse {
                req_id,
                peer_id,
                result,
            } => {
                self.handle_lightpush_response(req_id, peer_id, result)
                    .await;
            }
            TransportEvent::PeerExchangeResponse { req_id, result } => {
                self.handle_peer_exchange_response(req_id, result).await;
            }
            TransportEvent::FilterSubscribeResponse {
                req_id,
                peer_id,
                result,
            } => {
                self.handle_filter_subscribe_response(req_id, peer_id, result)
                    .await;
            }
            TransportEvent::StoreQueryResponse { req_id, result } => {
                self.handle_store_query_response(req_id, result).await;
            }
        }
    }

    async fn handle_lightpush_response(
        &self,
        req_id: ReqId,
        peer_id: PeerId,
        result: Result<proto::light_push::LightPushResponseV3, OutboundFailure>,
    ) {
        let mut lp = self.ops.lightpush.lock().await;
        let Some((op_id, _)) = lp.pending.remove(&req_id) else {
            return;
        };
        let result = match result {
            Ok(response) => LightPushResult {
                peer_id,
                status_code: Some(response.status_code),
                status_desc: response.status_desc,
                relay_peer_count: response.relay_peer_count,
                error: None,
            },
            Err(error) => LightPushResult {
                peer_id,
                status_code: None,
                status_desc: None,
                relay_peer_count: None,
                error: Some(error),
            },
        };
        let Some(op) = lp.ops.get_mut(&op_id) else {
            return;
        };
        let should_finish = record_lightpush_result(op, result);

        if should_finish {
            let results = lp
                .ops
                .remove(&op_id)
                .map(|finished_op| finished_op.results)
                .unwrap_or_default();
            lp.pending
                .retain(|_, (pending_op_id, _)| *pending_op_id != op_id);
            if let Some(tx) = lp.waiters.remove(&op_id)
                && tx.send(Ok(results)).is_err()
            {
                debug!(?op_id, "lightpush response receiver dropped");
            }
        }
    }

    async fn start_peer_exchange_round(&self, op_id: OpId) {
        {
            let mut px = self.ops.peer_exchange.lock().await;
            let Some(op) = px.round_ops.get_mut(&op_id) else {
                return;
            };

            if op.remaining_rounds == 0 {
                px.round_ops.remove(&op_id);
                if let Some(tx) = px.waiters.remove(&op_id)
                    && tx.send(()).is_err()
                {
                    debug!(?op_id, "peer exchange receiver dropped");
                }
                return;
            }
        }

        let now = Instant::now();
        let peers: Vec<PeerId> = {
            let book = self.peer_book.read();
            book.connected
                .iter()
                .filter_map(|peer_id| {
                    let state = book.peers.get(peer_id)?;
                    if !state.supports_peer_exchange {
                        return None;
                    }
                    if state
                        .last_peer_exchange_at
                        .is_some_and(|last| now.duration_since(last) < self.peer_exchange_cooldown)
                    {
                        return None;
                    }
                    Some(*peer_id)
                })
                .collect()
        };

        let mut sent_peers = Vec::new();
        {
            let mut px = self.ops.peer_exchange.lock().await;
            {
                let Some(op) = px.round_ops.get_mut(&op_id) else {
                    return;
                };

                if peers.is_empty() {
                    op.remaining_rounds = 0;
                    px.round_ops.remove(&op_id);
                    if let Some(tx) = px.waiters.remove(&op_id)
                        && tx.send(()).is_err()
                    {
                        debug!(?op_id, "peer exchange receiver dropped");
                    }
                    return;
                }
            }

            let batch_id = px.next_batch_id;
            px.next_batch_id += 1;

            let Some(op) = px.round_ops.get_mut(&op_id) else {
                return;
            };
            op.current_batch = Some(batch_id);
            op.deadline = Instant::now() + self.config.request_timeout;

            let mut expected = 0;
            for peer in peers {
                let req_id = self.ops.next_req_id();
                let request = proto::peer_exchange::PeerExchangeRpc {
                    query: Some(proto::peer_exchange::PeerExchangeQuery {
                        num_peers: Some(self.config.peer_exchange_peers_per_query),
                    }),
                    response: None,
                };

                let cmd = TransportCmd::SendPeerExchange {
                    req_id,
                    peer_id: peer,
                    request,
                };
                if self.transport_tx.try_send(cmd).is_ok() {
                    px.pending.insert(req_id, batch_id);
                    expected += 1;
                    sent_peers.push(peer);
                }
            }

            let batch = ResponseBatch {
                expected,
                finished: 0,
                results: Vec::new(),
                deadline: Instant::now() + self.config.request_timeout,
            };
            px.ops.insert(batch_id, batch);
        }

        if !sent_peers.is_empty() {
            let mut book = self.peer_book.write();
            for peer_id in sent_peers {
                if let Some(state) = book.peers.get_mut(&peer_id) {
                    state.last_peer_exchange_at = Some(now);
                }
            }
        }
    }

    async fn handle_peer_exchange_response(
        &self,
        req_id: ReqId,
        result: Result<proto::peer_exchange::PeerExchangeRpc, OutboundFailure>,
    ) {
        let (batch_id, enrs) = {
            let mut px = self.ops.peer_exchange.lock().await;
            let Some(batch_id) = px.pending.remove(&req_id) else {
                return;
            };
            let Some(batch) = px.ops.get_mut(&batch_id) else {
                return;
            };

            batch.finished += 1;
            if let Ok(response) = result
                && let Some(resp) = response.response
            {
                let records = resp.peer_infos.len();
                if u64::try_from(records)
                    .is_ok_and(|records| records <= self.config.peer_exchange_peers_per_query)
                {
                    batch
                        .results
                        .extend(resp.peer_infos.into_iter().filter_map(|p| p.enr));
                } else {
                    debug!(
                        records,
                        "discarding peer exchange response with too many records"
                    );
                }
            }

            if batch.finished < batch.expected {
                return;
            }

            let Some(batch) = px.ops.remove(&batch_id) else {
                return;
            };
            (batch_id, batch.results)
        };

        self.finish_peer_exchange_batch(batch_id, enrs).await;
    }

    async fn finish_peer_exchange_batch(&self, batch_id: usize, enrs: Vec<Vec<u8>>) {
        let peers = enrs
            .into_iter()
            .filter_map(|enr| discovery::enr::decode_enr_rlp(&enr).ok())
            .collect();
        self.apply_discovered_peers(peers, PeerSource::Learned);

        let op_id = {
            let mut px = self.ops.peer_exchange.lock().await;
            let op_id = px
                .round_ops
                .iter()
                .find_map(|(op_id, op)| (op.current_batch == Some(batch_id)).then_some(*op_id));

            let Some(op_id) = op_id else { return };

            if let Some(op) = px.round_ops.get_mut(&op_id) {
                op.remaining_rounds = op.remaining_rounds.saturating_sub(1);
                op.current_batch = None;
            }

            op_id
        };

        self.start_peer_exchange_round(op_id).await;
    }

    async fn send_filter_request(
        &self,
        req_id: ReqId,
        peer_id: PeerId,
        request: proto::filter::FilterSubscribeRequest,
        op: FilterOp,
    ) -> Result<(), WakuError> {
        let cmd = TransportCmd::SendFilterSubscribe {
            req_id,
            peer_id,
            request,
        };
        if self.transport_tx.try_send(cmd).is_err() {
            return Err(WakuError::ChannelFull);
        }

        let mut filter = self.ops.filter.lock().await;
        filter.pending.insert(req_id, op);
        Ok(())
    }

    fn update_filter_batch<F>(
        filter: &mut FilterState,
        batch_id: u64,
        result_status: Result<(), WakuError>,
        on_success: F,
    ) where
        F: FnOnce(&mut FilterState),
    {
        let mut finalize_success = false;
        let mut finalize_failure = false;

        if let Some(batch) = filter.batches.get_mut(&batch_id) {
            batch.finished += 1;
            match result_status {
                Ok(()) => {
                    if !batch.succeeded {
                        batch.succeeded = true;
                        finalize_success = true;
                    }
                }
                Err(error) => {
                    batch.last_error = Some(error);
                    if batch.finished >= batch.expected && !batch.succeeded {
                        finalize_failure = true;
                    }
                }
            }

            if batch.finished >= batch.expected && !batch.succeeded {
                finalize_failure = true;
            }
        }

        if (finalize_success || finalize_failure)
            && let Some(batch) = filter.batches.remove(&batch_id)
        {
            let outcome = if finalize_success {
                on_success(filter);
                Ok(())
            } else {
                Err(batch.last_error.unwrap_or(WakuError::FilterRequestFailed))
            };
            if let Err(err) = batch.waiter.send(outcome) {
                debug!(?err, batch_id = %batch_id, "failed to send filter batch outcome");
            }
        }
    }

    async fn handle_filter_subscribe_response(
        &self,
        req_id: ReqId,
        peer_id: PeerId,
        result: Result<proto::filter::FilterSubscribeResponse, OutboundFailure>,
    ) {
        let mut filter = self.ops.filter.lock().await;
        let Some(op) = filter.pending.remove(&req_id) else {
            return;
        };

        let result_status = match &result {
            Ok(response) if response.status_code == 200 => Ok(()),
            Ok(response) => Err(WakuError::FilterSubscribeFailed {
                status_code: response.status_code,
                status_desc: response.status_desc.clone(),
            }),
            Err(error) => {
                debug!(%peer_id, ?error, "filter subscribe failed");
                Err(WakuError::FilterRequestFailed)
            }
        };

        match op {
            FilterOp::Subscribe { sub_id } => match result_status {
                Ok(()) => {
                    debug!(%peer_id, ?sub_id, "filter subscribe succeeded");
                }
                Err(error) => {
                    warn!(%peer_id, ?sub_id, ?error, "filter subscribe failed");
                }
            },
            FilterOp::Unsubscribe { sub_id, batch_id } => {
                Self::update_filter_batch(&mut filter, batch_id, result_status, |filter| {
                    filter.subscriptions.remove(&sub_id);
                });
            }
            FilterOp::UnsubscribeAll {
                pubsub_topic,
                batch_id,
            } => {
                Self::update_filter_batch(&mut filter, batch_id, result_status, |filter| {
                    filter
                        .subscriptions
                        .retain(|_, sub| sub.pubsub_topic != pubsub_topic);
                });
            }
            FilterOp::SubscribeOnPeer { sub_id } => match result_status {
                Ok(()) => {
                    debug!(%peer_id, ?sub_id, "filter subscribe (peer) succeeded");
                }
                Err(error) => {
                    debug!(%peer_id, ?sub_id, ?error, "filter subscribe (peer) failed");
                }
            },
        }
    }

    async fn handle_filter_push(&self, peer_id: PeerId, push: proto::filter::MessagePush) {
        let Some(message) = push.waku_message else {
            debug!(%peer_id, "received filter push without message");
            return;
        };

        let hash = message.hash_key();

        let mut filter = self.ops.filter.lock().await;

        if filter.dedup_cache.contains(&hash) {
            trace!(%peer_id, "duplicate filter push, ignoring");
            return;
        }
        filter.dedup_cache.put(hash, ());

        // Route to matching subscriptions
        let Some(pubsub_topic) = push.pubsub_topic.as_deref() else {
            debug!(%peer_id, "received filter push without pubsub topic");
            return;
        };
        let content_topic = &message.content_topic;

        let mut closed = Vec::new();
        for (sub_id, sub) in &mut filter.subscriptions {
            if sub.pubsub_topic != pubsub_topic {
                continue;
            }

            if !sub.content_topics.iter().any(|ct| ct == content_topic) {
                continue;
            }

            match sub.sender.try_send(message.clone()) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    sub.dropped_since_log = sub.dropped_since_log.saturating_add(1);
                    let now = Instant::now();
                    if sub
                        .last_drop_log
                        .is_none_or(|last| now.duration_since(last) >= Duration::from_secs(30))
                    {
                        debug!(
                            %peer_id,
                            ?sub_id,
                            pubsub_topic,
                            content_topic,
                            dropped = sub.dropped_since_log,
                            "filter subscription capacity exhausted; dropping messages"
                        );
                        sub.dropped_since_log = 0;
                        sub.last_drop_log = Some(now);
                    }
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    closed.push(*sub_id);
                }
            }
        }
        for sub_id in closed {
            filter.subscriptions.remove(&sub_id);
            debug!(?sub_id, "removed closed filter subscription");
        }
    }

    async fn handle_store_query_response(
        &self,
        req_id: ReqId,
        result: Result<protocols::store::StoreQueryPage, OutboundFailure>,
    ) {
        let mut store = self.ops.store.lock().await;
        let Some(pending) = store.pending.remove(&req_id) else {
            return;
        };

        let result = result.map_err(|error| {
            debug!(?req_id, ?error, "store request failed");
            WakuError::StoreRequestFailed
        });
        if let Err(error) = pending.waiter.send(result) {
            debug!(?req_id, ?error, "store query receiver dropped");
        }
    }

    async fn send_subscribe_request(
        &self,
        peer_id: PeerId,
        sub_id: SubId,
        pubsub_topic: String,
        content_topics: Vec<String>,
    ) {
        let req_id = self.ops.next_req_id();
        let request = build_filter_request(
            proto::filter::filter_subscribe_request::FilterSubscribeType::Subscribe,
            pubsub_topic,
            content_topics,
        );

        if let Err(error) = self
            .send_filter_request(
                req_id,
                peer_id,
                request,
                FilterOp::SubscribeOnPeer { sub_id },
            )
            .await
        {
            warn!(%peer_id, ?sub_id, ?error, "failed to send filter subscribe request");
        }
    }

    async fn subscribe_on_peer(&self, peer_id: PeerId) {
        let subs_to_send: Vec<(SubId, String, Vec<String>)> = {
            let filter = self.ops.filter.lock().await;
            filter
                .subscriptions
                .iter()
                .map(|(id, sub)| (*id, sub.pubsub_topic.clone(), sub.content_topics.clone()))
                .collect()
        };

        if subs_to_send.is_empty() {
            return;
        }

        debug!(%peer_id, count = subs_to_send.len(), "subscribing filter subscriptions on peer");

        for (sub_id, pubsub_topic, content_topics) in subs_to_send {
            self.send_subscribe_request(peer_id, sub_id, pubsub_topic, content_topics)
                .await;
        }
    }
}

#[derive(Clone)]
pub struct WakuNode {
    inner: Arc<NodeInner>,
}

mod api;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WakuConfig;
    use libp2p::request_response::OutboundFailure;

    fn addr(value: &str) -> Multiaddr {
        value.parse().expect("valid multiaddr")
    }

    #[test]
    fn tor_discovery_retry_delay_backs_off_and_caps() {
        assert_eq!(tor_discovery_retry_delay(0), Duration::from_secs(10));
        assert_eq!(tor_discovery_retry_delay(1), Duration::from_secs(30));
        assert_eq!(tor_discovery_retry_delay(2), Duration::from_mins(1));
        assert_eq!(tor_discovery_retry_delay(3), Duration::from_mins(5));
        assert_eq!(tor_discovery_retry_delay(u32::MAX), Duration::from_mins(5));
    }

    #[test]
    fn lightpush_result_requires_success_status_without_transport_error() {
        let peer_id = PeerId::random();
        let accepted = LightPushResult {
            peer_id,
            status_code: Some(200),
            status_desc: None,
            relay_peer_count: Some(1),
            error: None,
        };
        assert!(accepted.is_success());

        let rejected = LightPushResult {
            status_code: Some(503),
            ..accepted
        };
        assert!(!rejected.is_success());

        let undefined_success = LightPushResult {
            status_code: Some(201),
            ..rejected
        };
        assert!(!undefined_success.is_success());

        let failed = LightPushResult {
            status_code: None,
            error: Some(OutboundFailure::Timeout),
            ..undefined_success
        };
        assert!(!failed.is_success());
    }

    #[test]
    fn lightpush_batch_finishes_on_first_accepted_response() {
        let mut batch = ResponseBatch {
            expected: 3,
            finished: 0,
            results: Vec::new(),
            deadline: Instant::now() + Duration::from_secs(10),
        };

        assert!(record_lightpush_result(
            &mut batch,
            LightPushResult {
                peer_id: PeerId::random(),
                status_code: Some(200),
                status_desc: None,
                relay_peer_count: Some(1),
                error: None,
            },
        ));
        assert_eq!(batch.finished, 1);
    }

    #[test]
    fn lightpush_batch_waits_for_all_rejected_responses() {
        let mut batch = ResponseBatch {
            expected: 2,
            finished: 0,
            results: Vec::new(),
            deadline: Instant::now() + Duration::from_secs(10),
        };
        let rejected = || LightPushResult {
            peer_id: PeerId::random(),
            status_code: Some(503),
            status_desc: None,
            relay_peer_count: None,
            error: None,
        };

        assert!(!record_lightpush_result(&mut batch, rejected()));
        assert!(record_lightpush_result(&mut batch, rejected()));
        assert_eq!(batch.finished, 2);
    }

    #[test]
    fn wrong_peer_id_remaps_address_to_authenticated_peer() {
        let advertised_peer = PeerId::random();
        let authenticated_peer = PeerId::random();
        let stale_addr = addr(&format!(
            "/ip4/45.76.230.253/tcp/30304/p2p/{advertised_peer}"
        ));
        let corrected_addr = addr(&format!(
            "/ip4/45.76.230.253/tcp/30304/p2p/{authenticated_peer}"
        ));
        let dialed_addr = addr("/ip4/45.76.230.253/tcp/30304");
        let mut book = PeerBook::default();

        let advertised = book.peers.entry(advertised_peer).or_default();
        advertised.addrs = vec![stale_addr.clone()];
        advertised.source = PeerSource::Dns { last_round: 1 };

        remap_wrong_peer_id(
            &mut book,
            advertised_peer,
            authenticated_peer,
            &stale_addr,
            Instant::now(),
            false,
        );

        let advertised_state = book.peers.get(&advertised_peer).expect("advertised peer");
        assert!(
            advertised_state
                .addrs
                .iter()
                .all(|addr| without_trailing_peer_id(addr) != dialed_addr)
        );
        assert_eq!(advertised_state.dial_failures, 1);
        assert!(advertised_state.next_dial_at.is_some());

        let authenticated_state = book
            .peers
            .get(&authenticated_peer)
            .expect("authenticated peer");
        assert_eq!(authenticated_state.addrs, vec![corrected_addr]);
    }

    #[tokio::test]
    async fn node_shutdown_marks_node_and_wakes_workers() {
        let mut config = WakuConfig::default();
        config.discovery.enr_trees.clear();

        let node = WakuNode::spawn(config).expect("spawn Waku node");
        assert!(!node.is_shutdown());

        node.shutdown();

        assert!(node.is_shutdown());
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    fn test_node(discovery_config: DiscoveryConfig) -> NodeInner {
        let (transport_tx, _) = mpsc::channel(64);
        let (dial_tx, _) = mpsc::channel(64);
        let (store_peer_tx, _) = broadcast::channel(STORE_PEER_EVENT_CAPACITY);
        let (shutdown_tx, _) = watch::channel(false);
        NodeInner {
            config: NodeConfig::default(),
            discovery_config,
            network_profile: WakuTransportProfile::Direct,
            peer_book: Arc::new(RwLock::new(PeerBook::default())),
            session_refresh_disconnects: RwLock::new(HashSet::new()),
            discovery_wake: Notify::new(),
            ops: OpTracker::new(),
            transport_tx,
            dial_tx,
            metadata_response: proto::metadata::WakuMetadataResponse::default(),
            peer_exchange_cooldown: Duration::from_mins(1),
            op_counter: AtomicU64::new(1),
            dns_round: AtomicU64::new(0),
            store_peer_tx,
            shutdown_tx,
        }
    }

    fn test_enr_rlp(seed: u32) -> Vec<u8> {
        use enr::k256::ecdsa::SigningKey;
        let mut secret = [0_u8; 32];
        secret[28..].copy_from_slice(&(seed + 1).to_be_bytes());
        let key = SigningKey::from_slice(&secret).expect("test ENR key");
        let enr = enr::Enr::<SigningKey>::builder()
            .ip4(std::net::Ipv4Addr::from(0x0a00_0000 + seed))
            .tcp4(60000)
            .add_value("waku2", &[1_u8].as_slice())
            .build(&key)
            .expect("test ENR");
        alloy_rlp::encode(&enr)
    }

    fn peer_addr(n: usize) -> Multiaddr {
        addr(&format!("/ip4/10.0.{}.{}/tcp/60000", n / 256, n % 256))
    }

    fn learned_count(book: &PeerBook) -> usize {
        book.peers
            .values()
            .filter(|state| state.source == PeerSource::Learned)
            .count()
    }

    fn offer_learned(book: &mut PeerBook) -> (PeerId, bool) {
        let peer_id = PeerId::random();
        let inserted = insert_peer(
            book,
            peer_id,
            vec![peer_addr(1_000)],
            PeerSource::Learned,
            false,
        );
        (peer_id, inserted)
    }

    /// Fills the book with healthy learned peers; peer `n` has `peer_addr(n)`.
    fn fill_learned(book: &mut PeerBook) -> Vec<PeerId> {
        (0..MAX_LEARNED_PEERS)
            .map(|n| {
                let peer_id = PeerId::random();
                assert!(insert_peer(
                    book,
                    peer_id,
                    vec![peer_addr(n)],
                    PeerSource::Learned,
                    false
                ));
                peer_id
            })
            .collect()
    }

    fn state_mut(book: &mut PeerBook, peer_id: PeerId) -> &mut PeerState {
        book.peers.get_mut(&peer_id).expect("peer state")
    }

    #[tokio::test]
    async fn peer_exchange_response_above_requested_count_is_discarded() {
        let node = test_node(DiscoveryConfig::default());
        for (records, added) in [(61, 0), (60, 60)] {
            let req_id = node.ops.next_req_id();
            {
                let mut px = node.ops.peer_exchange.lock().await;
                px.pending.insert(req_id, 0);
                px.ops.insert(
                    0,
                    ResponseBatch {
                        expected: 1,
                        finished: 0,
                        results: Vec::new(),
                        deadline: Instant::now() + Duration::from_secs(10),
                    },
                );
            }
            let peer_infos = (0..records)
                .map(|seed| proto::peer_exchange::PeerInfo {
                    enr: Some(test_enr_rlp(seed)),
                })
                .collect();
            let rpc = proto::peer_exchange::PeerExchangeRpc {
                query: None,
                response: Some(proto::peer_exchange::PeerExchangeResponse { peer_infos }),
            };
            node.handle_peer_exchange_response(req_id, Ok(rpc)).await;
            assert_eq!(
                node.peer_book.read().peers.len(),
                added,
                "{records} records"
            );
        }
    }

    #[test]
    fn learned_flood_keeps_configured_and_dns_peers() {
        let mut book = PeerBook::default();
        let configured = PeerId::random();
        let dns = PeerId::random();
        insert_peer(
            &mut book,
            configured,
            vec![peer_addr(0)],
            PeerSource::Configured,
            false,
        );
        insert_peer(
            &mut book,
            dns,
            vec![peer_addr(1)],
            PeerSource::Dns { last_round: 1 },
            false,
        );
        for peer_id in [configured, dns] {
            state_mut(&mut book, peer_id).dial_failures = 9;
        }

        for n in 0..1_000 {
            let peer_id = PeerId::random();
            if insert_peer(
                &mut book,
                peer_id,
                vec![peer_addr(n + 2)],
                PeerSource::Learned,
                false,
            ) {
                state_mut(&mut book, peer_id).dial_failures = 1;
            }
        }

        assert_eq!(learned_count(&book), MAX_LEARNED_PEERS);
        assert_eq!(book.peers[&configured].source, PeerSource::Configured);
        assert_eq!(book.peers[&configured].addrs, vec![peer_addr(0)]);
        assert_eq!(book.peers[&dns].source, PeerSource::Dns { last_round: 1 });
        assert_eq!(book.peers[&dns].addrs, vec![peer_addr(1)]);
    }

    #[test]
    fn full_learned_book_evicts_idle_empty_then_most_failed_else_drops_newcomer() {
        let mut book = PeerBook::default();
        let peers = fill_learned(&mut book);
        let (empty, failing, worse) = (peers[0], peers[1], peers[2]);
        state_mut(&mut book, empty).addrs.clear();
        state_mut(&mut book, failing).dial_failures = 1;
        state_mut(&mut book, worse).dial_failures = 3;

        assert!(offer_learned(&mut book).1);
        assert!(!book.peers.contains_key(&empty));
        assert!(book.peers.contains_key(&worse));
        assert!(offer_learned(&mut book).1);
        assert!(!book.peers.contains_key(&worse));
        assert!(offer_learned(&mut book).1);
        assert!(!book.peers.contains_key(&failing));

        let (dropped, inserted) = offer_learned(&mut book);
        assert!(!inserted);
        assert!(!book.peers.contains_key(&dropped));
        assert_eq!(learned_count(&book), MAX_LEARNED_PEERS);
    }

    #[test]
    fn connected_or_dialing_learned_peers_are_not_evicted() {
        for dialing in [false, true] {
            let mut book = PeerBook::default();
            let peers = fill_learned(&mut book);
            let (busy, failing) = (peers[0], peers[1]);
            state_mut(&mut book, busy).dial_failures = 9;
            state_mut(&mut book, failing).dial_failures = 1;
            if dialing {
                book.dialing.insert(busy);
            } else {
                book.connected.insert(busy);
            }

            assert!(offer_learned(&mut book).1);
            assert!(!book.peers.contains_key(&failing));
            assert!(!offer_learned(&mut book).1);
            assert!(book.peers.contains_key(&busy));
        }
    }

    #[test]
    fn connection_path_overshoot_is_reclaimed_at_next_learned_insertion() {
        let mut book = PeerBook::default();
        let failing = fill_learned(&mut book)[0];
        state_mut(&mut book, failing).dial_failures = 1;
        let extra = (0..3).map(|_| PeerId::random()).collect::<Vec<_>>();
        for peer_id in &extra {
            book.connected.insert(*peer_id);
            book.peers.entry(*peer_id).or_default().connected = true;
        }
        assert_eq!(learned_count(&book), MAX_LEARNED_PEERS + extra.len());

        for peer_id in &extra {
            book.connected.remove(peer_id);
            let state = state_mut(&mut book, *peer_id);
            state.connected = false;
            state.dial_failures = 1;
        }
        assert!(offer_learned(&mut book).1);
        assert_eq!(learned_count(&book), MAX_LEARNED_PEERS);
        assert!(
            extra
                .iter()
                .all(|peer_id| !book.peers.contains_key(peer_id))
        );
    }

    #[test]
    fn wrong_identity_endpoint_keeps_learned_peers_at_cap() {
        let mut book = PeerBook::default();
        let peers = fill_learned(&mut book);
        let endpoint = peer_addr(0);
        let mut expected = peers[0];
        for _ in 0..100 {
            let obtained = PeerId::random();
            remap_wrong_peer_id(
                &mut book,
                expected,
                obtained,
                &with_peer_id(&endpoint, expected),
                Instant::now(),
                false,
            );
            assert!(!book.peers.contains_key(&expected));
            assert_eq!(
                book.peers[&obtained].addrs,
                vec![with_peer_id(&endpoint, obtained)]
            );
            assert_eq!(learned_count(&book), MAX_LEARNED_PEERS);
            expected = obtained;
        }
    }

    #[test]
    fn dns_retention_keeps_most_recently_seen_within_quota() {
        let node = test_node(DiscoveryConfig {
            max_enrs_per_tree: 4,
            ..DiscoveryConfig::default()
        });
        assert_eq!(node.discovery_config.enr_trees.len(), 1);
        let mut next_addr = 0;
        let mut batch = |reseen: &[PeerId], fresh: usize| {
            let mut peers = reseen.to_vec();
            peers.extend((0..fresh).map(|_| PeerId::random()));
            let discovered = peers
                .iter()
                .map(|peer_id| {
                    next_addr += 1;
                    discovery::DiscoveredPeer {
                        peer_id: *peer_id,
                        addrs: vec![peer_addr(next_addr)],
                    }
                })
                .collect::<Vec<_>>();
            (peers, discovered)
        };

        let (first, discovered) = batch(&[], 2);
        node.apply_discovered_peers(discovered, PeerSource::Dns { last_round: 1 });
        let (_, discovered) = batch(&[], 2);
        node.apply_discovered_peers(discovered, PeerSource::Dns { last_round: 2 });
        // Re-seeing a round-1 peer keeps it over the round-2 peers.
        let (latest, discovered) = batch(&first[..1], 3);
        node.apply_discovered_peers(discovered, PeerSource::Dns { last_round: 3 });
        let retained = node
            .peer_book
            .read()
            .peers
            .keys()
            .copied()
            .collect::<HashSet<_>>();
        assert_eq!(retained, latest.into_iter().collect());

        let (newest, discovered) = batch(&[], 4);
        node.apply_discovered_peers(discovered, PeerSource::Dns { last_round: 4 });
        let book = node.peer_book.read();
        assert_eq!(book.peers.len(), 4);
        assert!(
            newest
                .iter()
                .all(|peer_id| book.peers.contains_key(peer_id))
        );
    }

    #[test]
    fn stronger_sources_upgrade_and_weaker_never_downgrade() {
        let mut book = PeerBook::default();
        let peer_id = PeerId::random();
        let mut offer = |source| {
            insert_peer(&mut book, peer_id, vec![peer_addr(0)], source, false);
            book.peers[&peer_id].source
        };
        let dns = PeerSource::Dns { last_round: 2 };

        assert_eq!(offer(PeerSource::Learned), PeerSource::Learned);
        assert_eq!(offer(dns), dns);
        assert_eq!(offer(PeerSource::Learned), dns);
        assert_eq!(offer(PeerSource::Configured), PeerSource::Configured);
        assert_eq!(offer(PeerSource::Learned), PeerSource::Configured);
        assert_eq!(offer(dns), PeerSource::Configured);
    }

    #[test]
    fn address_merge_dedups_and_keeps_newest_sixteen() {
        let (first, second) = (peer_addr(1), peer_addr(2));
        let mut addrs = Vec::new();
        for _ in 0..10 {
            merge_addrs(&mut addrs, vec![first.clone()], false);
            merge_addrs(&mut addrs, vec![second.clone()], false);
        }
        assert_eq!(addrs, vec![first, second]);

        let mut addrs = (0..MAX_ADDRS_PER_PEER).map(peer_addr).collect::<Vec<_>>();
        let newest = addr("/ip4/10.255.0.1/tcp/60000");
        merge_addrs(&mut addrs, vec![newest.clone()], false);
        assert_eq!(addrs.len(), MAX_ADDRS_PER_PEER);
        assert_eq!(addrs.last(), Some(&newest));
    }

    #[tokio::test]
    #[ignore = "runs peer exchange against the live Waku fleet"]
    async fn live_peer_exchange_responses_fit_request_and_frame() {
        let transport = crate::transport::Transport::new(
            &NodeConfig::default(),
            &crate::config::WakuNetworkConfig::direct(),
        )
        .expect("transport");
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        let (event_tx, mut event_rx) = mpsc::channel(64);
        let (filter_push_tx, _filter_push_rx) = mpsc::channel(64);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        tokio::spawn(transport.run(cmd_rx, event_tx, filter_push_tx, shutdown_rx));

        let peers = DiscoveryConfig::default()
            .discover_all()
            .await
            .expect("live discovery");
        let dialed = peers.len().min(8);
        for peer in peers.into_iter().take(dialed) {
            cmd_tx
                .send(TransportCmd::Dial {
                    peer_id: peer.peer_id,
                    addrs: peer.addrs,
                })
                .await
                .expect("dial command");
        }

        let mut asked = HashSet::new();
        let mut failed_dials = HashSet::new();
        let mut pending = 0_usize;
        let mut next_req_id = 0;
        let mut responses = Vec::new();
        let deadline = Instant::now() + Duration::from_mins(1);
        while let Ok(Some(event)) = tokio::time::timeout_at(deadline, event_rx.recv()).await {
            match event {
                TransportEvent::IdentifyReceived {
                    peer_id,
                    protocols: supported,
                    ..
                } if supported
                    .iter()
                    .any(|p| p == protocols::peer_exchange::PEER_EXCHANGE_CODEC)
                    && asked.insert(peer_id) =>
                {
                    next_req_id += 1;
                    let request = proto::peer_exchange::PeerExchangeRpc {
                        query: Some(proto::peer_exchange::PeerExchangeQuery {
                            num_peers: Some(60),
                        }),
                        response: None,
                    };
                    cmd_tx
                        .send(TransportCmd::SendPeerExchange {
                            req_id: next_req_id,
                            peer_id,
                            request,
                        })
                        .await
                        .expect("peer exchange command");
                    pending += 1;
                }
                TransportEvent::MetadataRequest { channel, .. } => {
                    // The Railgun fleet (waku-relay's defaults) drops peers outside cluster 5.
                    let response = proto::metadata::WakuMetadataResponse {
                        cluster_id: Some(5),
                        shards: vec![1],
                    };
                    cmd_tx
                        .send(TransportCmd::SendMetadataResponse { channel, response })
                        .await
                        .expect("metadata response command");
                }
                TransportEvent::DialError { peer_id, .. } => {
                    failed_dials.insert(peer_id);
                }
                TransportEvent::PeerExchangeResponse { result, .. } => {
                    pending -= 1;
                    match result {
                        Ok(rpc) => {
                            let records = rpc.response.as_ref().map_or(0, |r| r.peer_infos.len());
                            let bytes = prost::Message::encoded_len(&rpc);
                            eprintln!("peer exchange response: {records} records, {bytes} bytes");
                            responses.push((records, bytes));
                        }
                        Err(error) => eprintln!("peer exchange failed: {error}"),
                    }
                }
                _ => {}
            }
            if pending == 0 && asked.len() + failed_dials.len() >= dialed {
                break;
            }
        }
        let _ = shutdown_tx.send(true);

        assert!(
            !responses.is_empty(),
            "no successful peer exchange response"
        );
        for (records, bytes) in responses {
            assert!(records <= 60);
            assert!(bytes <= protocols::peer_exchange::PEER_EXCHANGE_RESPONSE_MAX_BYTES);
        }
    }
}
