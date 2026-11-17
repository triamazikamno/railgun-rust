use crate::error::ClientError;
use crate::msg::{ContentTopic, Message};
use base64::Engine;
use base64::engine::general_purpose;
use lru::LruCache;
use std::collections::{HashSet, VecDeque};
use std::num::NonZeroUsize;
use std::ops::ControlFlow;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, broadcast, mpsc};
use tokio::task::JoinHandle;
use waku::proto::{HashKey, WakuMessage};
use waku::{
    DEFAULT_CLEARNET_DOH_ENDPOINT, DiscoveredPeer, PeerId, PeerSnapshot, PeerStats,
    StoreQueryOptions, WakuConfig, WakuError, WakuNetworkConfig, WakuNode, WakuTorClientProvider,
    parse_multiaddr, parse_peer_id, read_limited_body,
};

pub const DEFAULT_CLUSTER_ID: u32 = 5;
pub const DEFAULT_SHARD_ID: u32 = 1;
const FEE_HISTORY_LOOKBACK: Duration = Duration::from_mins(2);
const FEE_HISTORY_PAGE_LIMIT: u64 = 100;
const DEFAULT_NWAKU_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const NWAKU_MAX_POLL_BYTES: usize = 16 * 1024 * 1024;
const BACKUP_PEER_DELAY: Duration = Duration::from_mins(1);
const CACHE_SIZE: NonZeroUsize = match NonZeroUsize::new(500) {
    Some(n) => n,
    None => panic!("cache size must be non-zero"),
};

#[derive(Debug, Clone, Default)]
pub struct ClientConfig {
    pub nwaku_url: Option<String>,
    pub shard_id: Option<u32>,
    pub direct_peers: Vec<AdditionalPeer>,
    pub backup_peers: Vec<AdditionalPeer>,
    pub dns_enr_trees: Option<Vec<String>>,
    pub doh_endpoint: Option<String>,
    pub doh_fallback_endpoints: Option<Vec<String>>,
    pub cluster_id: Option<u32>,
    pub max_peers: Option<usize>,
    pub peer_connection_timeout: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdditionalPeer {
    pub peer_id: String,
    pub addrs: Vec<String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RelayNetworkMode {
    Direct,
    Tor,
    Proxy,
}

#[derive(Clone)]
pub struct RelayNetworkConfig {
    pub mode: RelayNetworkMode,
    pub http_client: Option<reqwest::Client>,
    pub tor_client: Option<WakuTorClientProvider>,
}

impl RelayNetworkConfig {
    #[must_use]
    pub const fn direct() -> Self {
        Self {
            mode: RelayNetworkMode::Direct,
            http_client: None,
            tor_client: None,
        }
    }

    #[must_use]
    pub fn tor_with_client_provider(
        tor_client: WakuTorClientProvider,
        http_client: reqwest::Client,
    ) -> Self {
        Self {
            mode: RelayNetworkMode::Tor,
            http_client: Some(http_client),
            tor_client: Some(tor_client),
        }
    }

    #[must_use]
    pub const fn proxy(http_client: reqwest::Client) -> Self {
        Self {
            mode: RelayNetworkMode::Proxy,
            http_client: Some(http_client),
            tor_client: None,
        }
    }
}

impl Default for RelayNetworkConfig {
    fn default() -> Self {
        Self::direct()
    }
}

impl std::fmt::Debug for RelayNetworkConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayNetworkConfig")
            .field("mode", &self.mode)
            .field("http_client", &self.http_client.is_some())
            .field("tor_client", &self.tor_client.is_some())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayMessageOutcome {
    Delivered,
    Duplicate,
    Dropped,
    SinkClosed,
}

fn handle_relay_message(
    cache: &mut LruCache<u64, ()>,
    sink_tx: &mpsc::Sender<WakuMessage>,
    message: WakuMessage,
) -> RelayMessageOutcome {
    let hash = message.hash_key();

    if cache.contains(&hash) {
        tracing::trace!(hash, "duplicate message, ignoring");
        return RelayMessageOutcome::Duplicate;
    }
    cache.put(hash, ());
    match sink_tx.try_send(message) {
        Ok(()) => RelayMessageOutcome::Delivered,
        Err(mpsc::error::TrySendError::Full(_)) => {
            tracing::warn!("failed to send message to sink: channel full");
            RelayMessageOutcome::Dropped
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            tracing::debug!("message sink closed; stopping relay subscription task");
            RelayMessageOutcome::SinkClosed
        }
    }
}

fn relay_sink_is_closed(sink_tx: &mpsc::Sender<WakuMessage>) -> bool {
    if sink_tx.is_closed() {
        tracing::debug!("message sink closed; stopping relay subscription task");
        return true;
    }
    false
}

async fn wait_for_relay_sink_closed(sink_tx: &mpsc::Sender<WakuMessage>) {
    sink_tx.closed().await;
    tracing::debug!("message sink closed; stopping relay subscription task");
}

fn nwaku_request(request: reqwest::RequestBuilder, timeout: Duration) -> reqwest::RequestBuilder {
    request.timeout(timeout)
}

fn parse_peers(peers: &[AdditionalPeer]) -> Result<Vec<DiscoveredPeer>, ClientError> {
    peers
        .iter()
        .map(|peer| {
            Ok(DiscoveredPeer {
                peer_id: parse_peer_id(&peer.peer_id).map_err(|_| ClientError::ParsePeerId)?,
                addrs: peer
                    .addrs
                    .iter()
                    .map(|addr| parse_multiaddr(addr).map_err(|_| ClientError::ParseMultiaddr))
                    .collect::<Result<Vec<_>, ClientError>>()?,
            })
        })
        .collect()
}

fn backup_peers_due(
    disconnected_since: &mut Option<Instant>,
    now: Instant,
    connected: bool,
) -> bool {
    if connected {
        *disconnected_since = None;
        return false;
    }
    now.duration_since(*disconnected_since.get_or_insert(now)) >= BACKUP_PEER_DELAY
}

async fn observe_backup_peers(node: Arc<WakuNode>, peers: Vec<DiscoveredPeer>) {
    let mut disconnected_since = None;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        if node.is_shutdown() {
            return;
        }
        if backup_peers_due(
            &mut disconnected_since,
            Instant::now(),
            !node.connected_peers().is_empty(),
        ) {
            // A connection observed at the deadline starts a fresh grace period.
            if !node.connected_peers().is_empty() {
                disconnected_since = None;
                continue;
            }
            if !node.is_shutdown() {
                node.add_additional_peers(peers);
            }
            return;
        }
    }
}

type HistoryFuture =
    Pin<Box<dyn Future<Output = (PeerId, Result<Vec<WakuMessage>, WakuError>)> + Send>>;

/// Store history inputs for [`RelayForwarder`].
struct StoreHistory {
    lookback: Duration,
    peer_rx: Option<broadcast::Receiver<PeerId>>,
    list_peers: Box<dyn Fn() -> Vec<PeerId> + Send>,
    query: Box<dyn FnMut(PeerId) -> HistoryFuture + Send>,
}

impl StoreHistory {
    /// Queries each of the fleet's Store peers for the last `lookback` of messages on
    /// `content_topics`.
    fn for_fleet(
        waku_fleet: &Arc<WakuNode>,
        pubsub_path: &str,
        content_topics: &[String],
        lookback: Duration,
    ) -> Self {
        let peer_rx = waku_fleet.subscribe_store_peers();
        let list_fleet = Arc::clone(waku_fleet);
        let query_fleet = Arc::clone(waku_fleet);
        let pubsub_path = pubsub_path.to_owned();
        let content_topics = content_topics.to_vec();
        Self {
            lookback,
            peer_rx: Some(peer_rx),
            list_peers: Box::new(move || list_fleet.store_peers()),
            query: Box::new(move |peer_id: PeerId| -> HistoryFuture {
                let end = now_nanos();
                let start = end.saturating_sub(duration_nanos(lookback));
                let query = StoreQueryOptions {
                    pubsub_topic: pubsub_path.clone(),
                    content_topics: content_topics.clone(),
                    time_start: Some(start),
                    time_end: Some(end),
                    pagination_limit: Some(FEE_HISTORY_PAGE_LIMIT),
                };
                let fleet = Arc::clone(&query_fleet);
                Box::pin(async move { (peer_id, fleet.store_query_peer(peer_id, query).await) })
            }),
        }
    }
}

/// Queues `peer_id` unless it is already queued, in flight or queried.
///
/// A notification for the in-flight peer is recorded in its flag so a failed query can be retried.
fn queue_store_peer(
    pending: &mut VecDeque<PeerId>,
    in_flight: &mut Option<(PeerId, bool)>,
    queried: &HashSet<PeerId>,
    peer_id: PeerId,
) -> bool {
    if let Some((in_flight_peer, notified)) = in_flight
        && *in_flight_peer == peer_id
    {
        *notified = true;
        return false;
    }
    if pending.contains(&peer_id) || queried.contains(&peer_id) {
        return false;
    }
    pending.push_back(peer_id);
    true
}

/// nwaku's REST endpoint for the subscription's relayed messages.
struct NwakuMessagesPoll {
    url: String,
    http: reqwest::Client,
    request_timeout: Duration,
}

/// Polls nwaku once; returns `false` once the sink is closed.
async fn poll_nwaku_messages(
    nwaku: &NwakuMessagesPoll,
    content_topics: &[String],
    cache: &mut LruCache<u64, ()>,
    sink_tx: &mpsc::Sender<WakuMessage>,
) -> bool {
    let response = tokio::select! {
        () = wait_for_relay_sink_closed(sink_tx) => return false,
        response = nwaku_request(nwaku.http.get(nwaku.url.as_str()), nwaku.request_timeout).send() => response.and_then(reqwest::Response::error_for_status),
    };
    match response {
        Ok(resp) => {
            let body = tokio::select! {
                () = wait_for_relay_sink_closed(sink_tx) => return false,
                body = read_limited_body(resp, NWAKU_MAX_POLL_BYTES) => body,
            };
            let body = match body {
                Ok(body) => body,
                Err(error) => {
                    tracing::warn!(%error, "failed to read messages from nwaku");
                    return true;
                }
            };
            match serde_json::from_slice::<Vec<Message>>(&body) {
                Ok(messages) => {
                    for msg in messages {
                        if !content_topics.contains(&msg.content_topic) {
                            continue;
                        }
                        match general_purpose::STANDARD.decode(msg.payload.as_bytes()) {
                            Ok(payload) => {
                                let msg = WakuMessage {
                                    content_topic: msg.content_topic,
                                    payload,
                                    ..Default::default()
                                };
                                tracing::trace!(
                                    msg.content_topic,
                                    hash = msg.hash_key(),
                                    "received message from nwaku"
                                );
                                if matches!(
                                    handle_relay_message(cache, sink_tx, msg),
                                    RelayMessageOutcome::SinkClosed
                                ) {
                                    return false;
                                }
                            }
                            Err(error) => {
                                tracing::warn!(%error, "failed to decode message payload");
                            }
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "failed to decode messages from nwaku");
                }
            }
        }
        Err(error) => {
            tracing::warn!(error = %error.without_url(), "failed to poll messages from nwaku");
        }
    }
    true
}

/// The running Store query's result; pending forever when no query runs.
async fn running_store_query(
    history: &mut Option<HistoryFuture>,
) -> (PeerId, Result<Vec<WakuMessage>, WakuError>) {
    match history.as_mut() {
        Some(query) => query.await,
        None => std::future::pending().await,
    }
}

/// The next Store peer notification; pending forever without a notification channel.
async fn next_store_peer_notification(
    store: &mut Option<StoreHistory>,
) -> Result<PeerId, broadcast::error::RecvError> {
    match store.as_mut().and_then(|store| store.peer_rx.as_mut()) {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// Forwards fleet, nwaku and Store history messages into `sink_tx` through one dedup cache.
///
/// Store peers are queried one at a time, and live messages keep flowing while a query runs.
struct RelayForwarder {
    sink_tx: mpsc::Sender<WakuMessage>,
    content_topics: Vec<String>,
    nwaku: Option<NwakuMessagesPoll>,
    store: Option<StoreHistory>,
    cache: LruCache<u64, ()>,
    pending_store_peers: VecDeque<PeerId>,
    successfully_queried_store_peers: HashSet<PeerId>,
    history: Option<HistoryFuture>,
    in_flight: Option<(PeerId, bool)>,
}

impl RelayForwarder {
    fn new(
        sink_tx: mpsc::Sender<WakuMessage>,
        content_topics: Vec<String>,
        nwaku: Option<NwakuMessagesPoll>,
        store: Option<StoreHistory>,
    ) -> Self {
        Self {
            sink_tx,
            content_topics,
            nwaku,
            store,
            cache: LruCache::new(CACHE_SIZE),
            pending_store_peers: VecDeque::new(),
            successfully_queried_store_peers: HashSet::new(),
            history: None,
            in_flight: None,
        }
    }

    /// Forwards until the sink or the fleet subscription closes. The Store peers known at
    /// start are listed here, in the forwarding task.
    async fn run(mut self, mut fleet_rx: mpsc::Receiver<WakuMessage>) {
        let mut tick = tokio::time::interval(Duration::from_secs(2));
        self.pending_store_peers = self
            .store
            .as_ref()
            .map(|store| (store.list_peers)().into())
            .unwrap_or_default();
        loop {
            if relay_sink_is_closed(&self.sink_tx) {
                tracing::debug!("relay sink is closed, breaking...");
                return;
            }
            self.start_next_store_query();

            let sink_tx = &self.sink_tx;
            let history = &mut self.history;
            let store = &mut self.store;
            let flow = tokio::select! {
                () = wait_for_relay_sink_closed(sink_tx) => return,
                _ = tick.tick(), if self.nwaku.is_some() => self.poll_nwaku().await,
                msg = fleet_rx.recv() => self.forward_fleet_message(msg),
                (peer_id, result) = running_store_query(history), if history.is_some() => self.finish_store_query(peer_id, result),
                notification = next_store_peer_notification(store), if store.as_ref().is_some_and(|store| store.peer_rx.is_some()) => {
                    self.queue_notified_store_peers(&notification);
                    ControlFlow::Continue(())
                }
            };
            if flow.is_break() {
                return;
            }
        }
    }

    /// Starts a query of the next pending Store peer not yet queried, unless one is running.
    fn start_next_store_query(&mut self) {
        if self.history.is_some() {
            return;
        }
        let Some(store) = self.store.as_mut() else {
            return;
        };
        while let Some(peer_id) = self.pending_store_peers.pop_front() {
            if !self.successfully_queried_store_peers.contains(&peer_id) {
                self.history = Some((store.query)(peer_id));
                self.in_flight = Some((peer_id, false));
                break;
            }
        }
    }

    async fn poll_nwaku(&mut self) -> ControlFlow<()> {
        let Some(nwaku) = &self.nwaku else {
            return ControlFlow::Continue(());
        };
        if poll_nwaku_messages(nwaku, &self.content_topics, &mut self.cache, &self.sink_tx).await {
            ControlFlow::Continue(())
        } else {
            ControlFlow::Break(())
        }
    }

    fn forward_fleet_message(&mut self, msg: Option<WakuMessage>) -> ControlFlow<()> {
        let Some(msg) = msg else {
            tracing::warn!("fleet subscription channel closed");
            return ControlFlow::Break(());
        };
        tracing::trace!(
            msg.content_topic,
            hash = msg.hash_key(),
            "received message from fleet"
        );
        if matches!(
            handle_relay_message(&mut self.cache, &self.sink_tx, msg),
            RelayMessageOutcome::SinkClosed
        ) {
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    }

    /// Records a finished Store query: forwards its history, or re-queues a failed peer that
    /// was notified while its query ran.
    fn finish_store_query(
        &mut self,
        peer_id: PeerId,
        result: Result<Vec<WakuMessage>, WakuError>,
    ) -> ControlFlow<()> {
        self.history = None;
        let notified = self.in_flight.take().is_some_and(|(_, notified)| notified);
        match result {
            Ok(messages) => {
                self.successfully_queried_store_peers.insert(peer_id);
                if !self.forward_store_messages(peer_id, messages) {
                    return ControlFlow::Break(());
                }
            }
            Err(error) => {
                tracing::warn!(%peer_id, %error, "failed to query historical fee messages from store peer");
                if notified
                    && queue_store_peer(
                        &mut self.pending_store_peers,
                        &mut None,
                        &self.successfully_queried_store_peers,
                        peer_id,
                    )
                {
                    tracing::debug!(%peer_id, "re-queueing store peer notified during its failed query");
                }
            }
        }
        ControlFlow::Continue(())
    }

    /// Forwards one Store peer's history; returns `false` once the sink is closed.
    fn forward_store_messages(&mut self, peer_id: PeerId, messages: Vec<WakuMessage>) -> bool {
        let lookback = self
            .store
            .as_ref()
            .map_or(Duration::ZERO, |store| store.lookback);
        let returned = messages.len();
        let mut matching_topics = 0usize;
        let mut delivered = 0usize;
        let mut deduped = 0usize;
        let mut dropped = 0usize;
        for msg in messages {
            if !self.content_topics.contains(&msg.content_topic) {
                continue;
            }
            matching_topics += 1;
            tracing::debug!(
                %peer_id,
                msg.content_topic,
                hash = msg.hash_key(),
                "received historical message from store peer"
            );
            match handle_relay_message(&mut self.cache, &self.sink_tx, msg) {
                RelayMessageOutcome::Delivered => delivered += 1,
                RelayMessageOutcome::Duplicate => deduped += 1,
                RelayMessageOutcome::Dropped => dropped += 1,
                RelayMessageOutcome::SinkClosed => return false,
            }
        }
        tracing::debug!(
            %peer_id,
            returned,
            matching_topics,
            delivered,
            deduped,
            dropped,
            lookback_secs = lookback.as_secs(),
            "queried historical fee messages from store peer"
        );
        true
    }

    /// Queues a notified Store peer, or every listed peer after missed notifications.
    fn queue_notified_store_peers(
        &mut self,
        notification: &Result<PeerId, broadcast::error::RecvError>,
    ) {
        let Some(store) = self.store.as_mut() else {
            return;
        };
        match *notification {
            Ok(peer_id) => {
                if queue_store_peer(
                    &mut self.pending_store_peers,
                    &mut self.in_flight,
                    &self.successfully_queried_store_peers,
                    peer_id,
                ) {
                    tracing::debug!(%peer_id, "queueing store peer for fee history query");
                }
            }
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                tracing::warn!(skipped, "missed store peer notifications");
                for peer_id in (store.list_peers)() {
                    queue_store_peer(
                        &mut self.pending_store_peers,
                        &mut self.in_flight,
                        &self.successfully_queried_store_peers,
                        peer_id,
                    );
                }
            }
            Err(broadcast::error::RecvError::Closed) => {
                tracing::warn!("store peer notification channel closed");
                store.peer_rx = None;
            }
        }
    }
}

pub struct Client {
    http_client: reqwest::Client,
    nwaku_request_timeout: Duration,
    nwaku_url: Option<String>,
    pubsub_path: String,
    waku_fleet: Option<Arc<WakuNode>>,
    /// Parsed configured direct peers, kept for [`Client::seed_peers`].
    direct_peers: Vec<DiscoveredPeer>,
    /// The backup-peer observer, if any, and every message-forwarding task.
    tasks: Mutex<Vec<JoinHandle<()>>>,
    network_mode: RelayNetworkMode,
    disabled_reason: Option<Arc<str>>,
}

impl Drop for Client {
    fn drop(&mut self) {
        for task in self.tasks.get_mut() {
            task.abort();
        }
        if let Some(waku_fleet) = self.waku_fleet.as_ref() {
            waku_fleet.shutdown();
        }
    }
}

impl Client {
    pub fn new(cfg: &ClientConfig) -> Result<Self, ClientError> {
        Self::new_with_network(cfg, RelayNetworkConfig::direct())
    }

    pub fn new_with_network(
        cfg: &ClientConfig,
        network: RelayNetworkConfig,
    ) -> Result<Self, ClientError> {
        let RelayNetworkConfig {
            mode,
            http_client,
            tor_client,
        } = network;
        let cluster_id = configured_cluster_id(cfg);
        let shard_id = configured_shard_id(cfg);
        let http_client = http_client.unwrap_or_default();
        let disabled_reason = (mode == RelayNetworkMode::Proxy)
            .then(|| Arc::<str>::from("proxy mode does not support Waku libp2p transports"));
        let mut tasks = Vec::new();
        let mut direct_peers = Vec::new();
        let waku = if let Some(reason) = disabled_reason.as_ref() {
            tracing::warn!(%reason, "Waku disabled by network policy");
            None
        } else {
            let mut config = Self::build_waku_config(cfg);
            if mode == RelayNetworkMode::Tor {
                let tor_client = tor_client.ok_or_else(|| {
                    ClientError::Disabled("Tor Waku profile requires an Arti client".to_string())
                })?;
                add_tor_doh_fallback(&mut config, cfg.doh_fallback_endpoints.is_some());
                config.network =
                    WakuNetworkConfig::tor_with_client_provider(tor_client, http_client.clone());
            }
            direct_peers = parse_peers(&cfg.direct_peers)?;
            let backup_peers = parse_peers(&cfg.backup_peers)?;
            let waku = Arc::new(WakuNode::spawn(config).map_err(ClientError::SpawnNode)?);
            waku.add_additional_peers(direct_peers.clone());
            if !backup_peers.is_empty() {
                tasks.push(tokio::spawn(observe_backup_peers(
                    Arc::clone(&waku),
                    backup_peers,
                )));
            }
            Some(waku)
        };
        Ok(Self {
            http_client,
            nwaku_request_timeout: DEFAULT_NWAKU_REQUEST_TIMEOUT,
            nwaku_url: cfg.nwaku_url.clone(),
            pubsub_path: relay_shard_pubsub_path(cluster_id, shard_id),
            waku_fleet: waku,
            direct_peers,
            tasks: Mutex::new(tasks),
            network_mode: mode,
            disabled_reason,
        })
    }

    fn build_waku_config(cfg: &ClientConfig) -> WakuConfig {
        let mut config = WakuConfig::default();
        if let Some(dns_enr_trees) = &cfg.dns_enr_trees {
            config.discovery.enr_trees.clone_from(dns_enr_trees);
        }
        if let Some(doh_endpoint) = &cfg.doh_endpoint {
            config.discovery.doh_endpoint.clone_from(doh_endpoint);
        }
        if let Some(doh_fallback_endpoints) = &cfg.doh_fallback_endpoints {
            config
                .discovery
                .doh_fallback_endpoints
                .clone_from(doh_fallback_endpoints);
        }
        config.cluster_id = configured_cluster_id(cfg);
        config.shard_id = configured_shard_id(cfg);
        if let Some(max_peers) = cfg.max_peers {
            config.node.connection_cap = max_peers;
        }
        if let Some(request_timeout) = cfg.peer_connection_timeout {
            config.node.request_timeout = request_timeout;
        }
        config
    }

    #[must_use]
    pub fn pubsub_path(&self) -> &str {
        &self.pubsub_path
    }

    #[must_use]
    pub const fn network_mode(&self) -> RelayNetworkMode {
        self.network_mode
    }

    #[must_use]
    pub const fn network_status_label(&self) -> &'static str {
        if self.disabled_reason.is_some() {
            return "Waku disabled";
        }
        match self.network_mode {
            RelayNetworkMode::Tor => "Tor-safe Waku",
            RelayNetworkMode::Proxy => "Waku disabled",
            RelayNetworkMode::Direct => "Direct Waku",
        }
    }

    #[must_use]
    pub fn disabled_reason(&self) -> Option<&str> {
        self.disabled_reason.as_deref()
    }

    #[must_use]
    pub fn refresh_network_session(&self) -> bool {
        if self.network_mode != RelayNetworkMode::Tor {
            return false;
        }
        let Some(waku_fleet) = self.waku_fleet.as_ref() else {
            return false;
        };
        waku_fleet.refresh_network_session();
        true
    }

    /// Current aggregate peer statistics from the underlying Waku node.
    #[must_use]
    pub fn peer_stats(&self) -> PeerStats {
        self.waku_fleet
            .as_ref()
            .map_or_else(PeerStats::default, |waku| waku.get_stats())
    }

    /// Read-only per-peer snapshot rows from the underlying Waku node.
    #[must_use]
    pub fn peer_snapshots(&self) -> Vec<PeerSnapshot> {
        self.waku_fleet
            .as_ref()
            .map_or_else(Vec::new, |waku| waku.peer_snapshots())
    }

    /// This client's Waku peer ID, or `None` when Waku is disabled.
    #[must_use]
    pub fn local_peer_id(&self) -> Option<PeerId> {
        self.waku_fleet.as_ref().map(|waku| waku.local_peer_id())
    }

    /// Peers another Waku node can bootstrap from: the latest verified ENR-tree DNS records
    /// and the configured direct peers, deduplicated by peer ID with configured peers first.
    ///
    /// Contains only ENR-tree record addresses and configured addresses, never peers learned
    /// through peer exchange or addresses reported by Identify. Backup peers are excluded.
    /// Empty when Waku is disabled.
    #[must_use]
    pub fn seed_peers(&self) -> Vec<AdditionalPeer> {
        let Some(waku_fleet) = self.waku_fleet.as_ref() else {
            return Vec::new();
        };
        let mut seen = HashSet::new();
        self.direct_peers
            .iter()
            .cloned()
            .chain(waku_fleet.dns_peer_records())
            .filter(|peer| seen.insert(peer.peer_id))
            .map(|peer| AdditionalPeer {
                peer_id: peer.peer_id.to_string(),
                addrs: peer.addrs.iter().map(ToString::to_string).collect(),
            })
            .collect()
    }

    /// The embedded node, unless Waku is disabled or the node was shut down.
    fn active_fleet(&self) -> Result<&Arc<WakuNode>, ClientError> {
        let Some(waku_fleet) = self.waku_fleet.as_ref() else {
            let reason = self
                .disabled_reason
                .as_deref()
                .unwrap_or("Waku is unavailable for the selected network mode");
            return Err(ClientError::Disabled(reason.to_string()));
        };
        if waku_fleet.is_shutdown() {
            return Err(ClientError::Disabled("Waku node was shut down".to_string()));
        }
        Ok(waku_fleet)
    }

    /// Wait up to `bound` until connected Waku peers support both `LightPush` and Filter.
    pub async fn wait_ready(&self, bound: Duration) -> Result<(), ClientError> {
        let waku_fleet = self.active_fleet()?;
        waku_fleet
            .wait_ready(bound)
            .await
            .map_err(ClientError::NotReady)
    }

    /// Stop background work and wait up to `bound` for the embedded Waku node to terminate.
    ///
    /// Signals the node to stop, so no new subscription registers a forwarding task, then
    /// aborts and awaits the backup-peer observer and every message-forwarding task (which
    /// stops nwaku polling), then waits on [`WakuNode::shutdown_and_wait`]. Subscription
    /// receivers stop receiving messages. Returns `Ok` when Waku is disabled, and is safe to
    /// call more than once.
    ///
    /// `bound` limits only the embedded-node wait, not acquiring the task list or joining the
    /// tasks. Concurrent calls serialize. A cancelled call leaves the tasks it has not yet
    /// seen end in the list, so a later call still waits for them.
    pub async fn shutdown(&self, bound: Duration) -> Result<(), ClientError> {
        if let Some(waku_fleet) = self.waku_fleet.as_ref() {
            waku_fleet.shutdown();
        }
        {
            let mut tasks = self.tasks.lock().await;
            tasks.iter().for_each(JoinHandle::abort);
            // Pop only after the await completes, so a cancelled call keeps the handle.
            while let Some(task) = tasks.last_mut() {
                // A cancelled or panicked task has ended too.
                let _ = task.await;
                tasks.pop();
            }
        }
        if let Some(waku_fleet) = self.waku_fleet.as_ref() {
            waku_fleet
                .shutdown_and_wait(bound)
                .await
                .map_err(ClientError::Shutdown)?;
        }
        Ok(())
    }

    pub async fn subscribe(
        &self,
        content_topics: Vec<String>,
    ) -> Result<mpsc::Receiver<WakuMessage>, ClientError> {
        self.subscribe_internal(content_topics, None).await
    }

    pub async fn subscribe_with_fee_history(
        &self,
        content_topics: Vec<String>,
    ) -> Result<mpsc::Receiver<WakuMessage>, ClientError> {
        let history_lookback = content_topics
            .iter()
            .all(|topic| is_fee_content_topic(topic))
            .then_some(FEE_HISTORY_LOOKBACK);
        if history_lookback.is_none() {
            tracing::warn!(
                pubsub_path = %self.pubsub_path,
                topics = ?content_topics,
                "fee history requested for non-fee topics; using live-only subscription"
            );
        }

        self.subscribe_internal(content_topics, history_lookback)
            .await
    }

    async fn subscribe_internal(
        &self,
        content_topics: Vec<String>,
        history_lookback: Option<Duration>,
    ) -> Result<mpsc::Receiver<WakuMessage>, ClientError> {
        let waku_fleet = self.active_fleet()?;
        let mut rx = waku_fleet
            .filter_subscribe(self.pubsub_path.clone(), content_topics.clone())
            .await
            .map_err(ClientError::FleetSubscribe)?;
        if let Some(nwaku_url) = &self.nwaku_url {
            let url = format!("{nwaku_url}/relay/v1/subscriptions");
            if let Err(error) =
                nwaku_request(self.http_client.post(url), self.nwaku_request_timeout)
                    .json(&[self.pubsub_path.as_str()])
                    .send()
                    .await
                    .and_then(reqwest::Response::error_for_status)
            {
                tracing::warn!(error = %error.without_url(), "failed to subscribe on nwaku");
            }
        }

        if self.nwaku_url.is_some() || history_lookback.is_some() {
            let (sink_tx, sink_rx) = mpsc::channel(1024);
            let nwaku = self.nwaku_url.as_ref().map(|nwaku_url| {
                let encoded_pubsub_path = urlencoding::encode(&self.pubsub_path);
                NwakuMessagesPoll {
                    url: format!("{nwaku_url}/relay/v1/messages/{encoded_pubsub_path}"),
                    http: self.http_client.clone(),
                    request_timeout: self.nwaku_request_timeout,
                }
            });
            let store = history_lookback.map(|lookback| {
                StoreHistory::for_fleet(waku_fleet, &self.pubsub_path, &content_topics, lookback)
            });
            let mut tasks = self.tasks.lock().await;
            // `shutdown` signals before taking this lock, so a task registered here is joined.
            if waku_fleet.is_shutdown() {
                return Err(ClientError::Disabled("Waku node was shut down".to_string()));
            }
            tasks.retain(|task| !task.is_finished());
            tasks.push(tokio::spawn(
                RelayForwarder::new(sink_tx, content_topics, nwaku, store).run(rx),
            ));
            drop(tasks);
            rx = sink_rx;
        }

        Ok(rx)
    }

    async fn publish_to_nwaku(
        &self,
        content_topic: &str,
        json_payload_utf8: &[u8],
    ) -> Result<(), ClientError> {
        #[derive(Debug, serde::Serialize)]
        struct PublishBody<'a> {
            payload: &'a str,
            timestamp: u64,
            version: u32,
            #[serde(rename = "contentTopic")]
            content_topic: &'a str,
        }
        let Some(nwaku_url) = &self.nwaku_url else {
            return Ok(());
        };
        let pubsub_path = urlencoding::encode(&self.pubsub_path);

        let payload_b64 = general_purpose::STANDARD.encode(json_payload_utf8);
        let body = PublishBody {
            payload: &payload_b64,
            timestamp: now_micros() * 1000,
            version: 0,
            content_topic,
        };
        let url = format!("{nwaku_url}/relay/v1/messages/{pubsub_path}");
        tracing::debug!(
            content_topic,
            payload_len = json_payload_utf8.len(),
            "publishing Waku message to nwaku"
        );
        let res = nwaku_request(self.http_client.post(url), self.nwaku_request_timeout)
            .json(&body)
            .send()
            .await
            .map_err(reqwest::Error::without_url)?;
        let status = res.status();
        if status != reqwest::StatusCode::OK {
            let body = res.text().await.map_err(reqwest::Error::without_url)?;
            tracing::warn!(
                %status,
                body_len = body.len(),
                content_topic,
                "nwaku publish returned non-OK status"
            );
            return Err(ClientError::NwakuStatus { body });
        }
        tracing::debug!(%status, content_topic, "published Waku message to nwaku");
        Ok(())
    }

    pub async fn publish(
        &self,
        content_topic: &str,
        json_payload_utf8: &[u8],
    ) -> Result<(), ClientError> {
        let pubsub_path = self.pubsub_path.as_str();
        tracing::debug!(
            pubsub_path,
            content_topic,
            payload_len = json_payload_utf8.len(),
            nwaku_configured = self.nwaku_url.is_some(),
            "publishing Waku message"
        );
        tracing::debug!(
            pubsub_path,
            content_topic,
            "publishing Waku message to fleet"
        );
        let waku_fleet = self.active_fleet()?;
        match waku_fleet
            .lightpush_all(
                self.pubsub_path.clone(),
                content_topic.to_string(),
                json_payload_utf8.to_vec(),
            )
            .await
        {
            Ok(results) => {
                let accepted = results.iter().filter(|result| result.is_success()).count();
                if accepted == 0 {
                    tracing::warn!(
                        pubsub_path,
                        content_topic,
                        responses = results.len(),
                        "no Waku fleet peer accepted published message"
                    );
                } else {
                    tracing::debug!(
                        pubsub_path,
                        content_topic,
                        accepted,
                        responses = results.len(),
                        "published Waku message to fleet"
                    );
                }
            }
            Err(error) => {
                tracing::warn!(%error, pubsub_path, content_topic, "failed to publish message to waku fleet");
            }
        }
        if self.nwaku_url.is_some() {
            self.publish_to_nwaku(content_topic, json_payload_utf8)
                .await?;
        } else {
            tracing::debug!(
                pubsub_path,
                content_topic,
                "nwaku publish skipped because nwaku_url is not configured"
            );
        }
        Ok(())
    }
}

#[must_use]
pub fn relay_shard_pubsub_path(cluster_id: u32, shard_id: u32) -> String {
    format!("/waku/2/rs/{cluster_id}/{shard_id}")
}

fn now_micros() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_micros() as u64,
        Err(error) => {
            tracing::warn!(?error, "system time before unix epoch");
            0
        }
    }
}

fn now_nanos() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX),
        Err(error) => {
            tracing::warn!(?error, "system time before unix epoch");
            0
        }
    }
}

fn duration_nanos(duration: Duration) -> i64 {
    i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX)
}

fn is_fee_content_topic(topic: &str) -> bool {
    matches!(ContentTopic::parse(topic), ContentTopic::Fees(_))
}

fn configured_cluster_id(cfg: &ClientConfig) -> u32 {
    cfg.cluster_id.unwrap_or(DEFAULT_CLUSTER_ID)
}

fn configured_shard_id(cfg: &ClientConfig) -> u32 {
    cfg.shard_id.unwrap_or(DEFAULT_SHARD_ID)
}

fn add_tor_doh_fallback(config: &mut WakuConfig, fallback_endpoints_configured: bool) {
    if fallback_endpoints_configured
        || config.discovery.doh_endpoint == DEFAULT_CLEARNET_DOH_ENDPOINT
    {
        return;
    }
    let fallbacks = &mut config.discovery.doh_fallback_endpoints;
    if !fallbacks
        .iter()
        .any(|endpoint| endpoint == DEFAULT_CLEARNET_DOH_ENDPOINT)
    {
        fallbacks.push(DEFAULT_CLEARNET_DOH_ENDPOINT.to_string());
    }
}

#[cfg(test)]
mod tests;
