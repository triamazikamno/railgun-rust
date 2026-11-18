use crate::address_policy::{retain_tor_safe_addrs, with_peer_id, without_trailing_peer_id};
use crate::config::{NodeConfig, WakuTransportProfile};
use crate::discovery;
use crate::discovery::DiscoveryConfig;
use crate::error::WakuError;
use crate::proto;
use crate::proto::HashKey;
use crate::protocols;
use crate::tasks::TaskWaiter;
use crate::transport::{FilterPushEvent, ReqId, TransportCmd, TransportEvent};
use crate::types::OpId;
use libp2p::request_response::{OutboundFailure, ResponseChannel};
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

const LOG_TARGET: &str = module_path!();

mod filter;
mod peer_book;
mod peer_exchange;

pub use filter::SubId;
use filter::{FilterBatch, FilterOp, FilterState, Subscription, build_filter_request};
pub use peer_book::PeerBook;
#[cfg(test)]
use peer_book::{MAX_ADDRS_PER_PEER, MAX_LEARNED_PEERS, PeerState};
use peer_book::{
    PeerSource, apply_addr_policy, insert_peer, merge_addrs, record_dial_failure,
    remap_wrong_peer_id, retain_dns_peers,
};
use peer_exchange::PeerExchangeState;

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
    /// Latest successful DNS round's records after the address policy, kept apart from the
    /// peer book so peer-exchange peers and Identify addresses never enter it.
    dns_records: RwLock<Vec<discovery::DiscoveredPeer>>,
    /// Notified when a peer connects, disconnects or reports its protocols, and at shutdown.
    peer_capabilities_changed: Notify,
    local_peer_id: PeerId,
    /// Completes once every task the node spawned has ended; see `WakuNode::shutdown_and_wait`.
    tasks: Mutex<TaskWaiter>,
    store_peer_tx: broadcast::Sender<PeerId>,
    shutdown_tx: watch::Sender<bool>,
}

impl NodeInner {
    fn shutdown(&self) {
        // `send` would not record the value once every receiver has gone.
        self.shutdown_tx.send_replace(true);
        self.discovery_wake.notify_waiters();
        self.peer_capabilities_changed.notify_waiters();
    }

    async fn wait_ready(&self, bound: Duration) -> Result<(), WakuError> {
        let deadline = Instant::now() + bound;
        loop {
            let changed = self.peer_capabilities_changed.notified();
            tokio::pin!(changed);
            // Register before checking so a change between the check and the await still wakes us.
            changed.as_mut().enable();
            if self.is_shutdown() {
                return Err(WakuError::Cancelled);
            }
            if self.peer_book.read().ready() {
                return Ok(());
            }
            if tokio::time::timeout_at(deadline, changed).await.is_err() {
                return Err(WakuError::NoPeersAvailable);
            }
        }
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
            if book.num_connections() + in_flight >= self.config.connection_cap {
                continue;
            }
            if state.connected {
                continue;
            }
            if book.dialing.contains(peer_id) {
                continue;
            }
            if state.next_dial_at.is_some_and(|next| next > now) {
                continue;
            }
            if state.addrs.is_empty() {
                continue;
            }
            if in_flight >= self.config.dial_concurrency {
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
        Ok(self.record_dns_round(peers))
    }

    /// Replace the DNS record snapshot with a successful round, then add it to the peer book.
    fn record_dns_round(&self, peers: Vec<discovery::DiscoveredPeer>) -> usize {
        let round = self.dns_round.fetch_add(1, Ordering::Relaxed) + 1;
        let records = peers
            .iter()
            .cloned()
            .filter_map(|mut peer| {
                self.apply_addr_policy(&mut peer.addrs);
                (!peer.addrs.is_empty()).then_some(peer)
            })
            .collect();
        *self.dns_records.write() = records;
        self.apply_discovered_peers(peers, PeerSource::Dns { last_round: round })
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
                self.handle_connection_established(peer_id);
            }
            TransportEvent::ConnectionClosed { peer_id } => {
                self.handle_connection_closed(peer_id);
            }
            TransportEvent::DialError { peer_id, error } => {
                self.handle_dial_error(peer_id, error);
            }
            TransportEvent::IdentifyReceived {
                peer_id,
                protocols,
                addrs,
            } => {
                self.handle_identify_received(peer_id, &protocols, addrs)
                    .await;
            }
            TransportEvent::MetadataRequest { peer_id, channel } => {
                self.handle_metadata_request(peer_id, channel);
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

    fn handle_connection_established(&self, peer_id: PeerId) {
        debug!(%peer_id, "connected");
        let supports_store = {
            let mut book = self.peer_book.write();
            book.connected.insert(peer_id);
            book.dialing.remove(&peer_id);
            let state = book.peers.entry(peer_id).or_default();
            state.connected = true;
            if state.dial_failures > 5 && state.next_dial_at.is_some_and(|t| t <= Instant::now()) {
                state.dial_failures = state.dial_failures.saturating_sub(1);
            }
            state.supports_store
        };
        self.peer_capabilities_changed.notify_waiters();
        if supports_store {
            debug!(%peer_id, "connected peer supports store");
            let _ = self.store_peer_tx.send(peer_id);
        }
        self.maybe_dial();
    }

    fn handle_connection_closed(&self, peer_id: PeerId) {
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
        self.peer_capabilities_changed.notify_waiters();
        self.maybe_dial();
    }

    fn handle_dial_error(&self, peer_id: PeerId, error: DialError) {
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

    async fn handle_identify_received(
        &self,
        peer_id: PeerId,
        protocols: &[String],
        mut addrs: Vec<Multiaddr>,
    ) {
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
            let became_store_capable = supports_store && entry.connected && !entry.supports_store;
            entry.supports_lightpush_v3 = supports_lightpush;
            entry.supports_peer_exchange = supports_px;
            entry.supports_filter = supports_filter;
            entry.supports_store = supports_store;
            merge_addrs(&mut entry.addrs, addrs, self.uses_tor_profile());
            became_store_capable
        };
        self.peer_capabilities_changed.notify_waiters();

        if became_store_capable {
            debug!(%peer_id, "peer supports store");
            let _ = self.store_peer_tx.send(peer_id);
        }

        // Resubscribe to filter on reconnect if peer supports filter
        if supports_filter {
            self.subscribe_on_peer(peer_id).await;
        }
    }

    fn handle_metadata_request(
        &self,
        peer_id: PeerId,
        channel: ResponseChannel<proto::metadata::WakuMetadataResponse>,
    ) {
        debug!(%peer_id, "received metadata request");
        let response = self.metadata_response.clone();
        if let Err(error) = self
            .transport_tx
            .try_send(TransportCmd::SendMetadataResponse { channel, response })
        {
            error!(%error, "failed to send metadata response command");
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
}

#[derive(Clone)]
pub struct WakuNode {
    inner: Arc<NodeInner>,
}

mod api;

#[cfg(test)]
mod tests;
