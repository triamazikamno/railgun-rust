use crate::error::ClientError;
use crate::msg::{ContentTopic, Message};
use base64::Engine;
use base64::engine::general_purpose;
use lru::LruCache;
use std::collections::{HashSet, VecDeque};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, mpsc};
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

/// Store history inputs for [`forward_messages`].
struct StoreHistory {
    lookback: Duration,
    peer_rx: Option<broadcast::Receiver<PeerId>>,
    list_peers: Box<dyn Fn() -> Vec<PeerId> + Send>,
    query: Box<dyn FnMut(PeerId) -> HistoryFuture + Send>,
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

/// Forwards one Store peer's history; returns `false` once the sink is closed.
fn forward_store_messages(
    cache: &mut LruCache<u64, ()>,
    sink_tx: &mpsc::Sender<WakuMessage>,
    content_topics: &[String],
    peer_id: PeerId,
    messages: Vec<WakuMessage>,
    lookback: Duration,
) -> bool {
    let returned = messages.len();
    let mut matching_topics = 0usize;
    let mut delivered = 0usize;
    let mut deduped = 0usize;
    let mut dropped = 0usize;
    for msg in messages {
        if !content_topics.contains(&msg.content_topic) {
            continue;
        }
        matching_topics += 1;
        tracing::debug!(
            %peer_id,
            msg.content_topic,
            hash = msg.hash_key(),
            "received historical message from store peer"
        );
        match handle_relay_message(cache, sink_tx, msg) {
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

/// Polls nwaku once; returns `false` once the sink is closed.
async fn poll_nwaku_messages(
    http: &reqwest::Client,
    url: &str,
    nwaku_request_timeout: Duration,
    content_topics: &[String],
    cache: &mut LruCache<u64, ()>,
    sink_tx: &mpsc::Sender<WakuMessage>,
) -> bool {
    let response = tokio::select! {
        () = wait_for_relay_sink_closed(sink_tx) => return false,
        response = nwaku_request(http.get(url), nwaku_request_timeout).send() => response.and_then(reqwest::Response::error_for_status),
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

/// Forwards fleet, nwaku and Store history messages into `sink_tx` through one dedup cache.
///
/// Store peers are queried one at a time, and live messages keep flowing while a query runs.
async fn forward_messages(
    mut fleet_rx: mpsc::Receiver<WakuMessage>,
    sink_tx: mpsc::Sender<WakuMessage>,
    content_topics: Vec<String>,
    nwaku_messages_url: Option<String>,
    http: reqwest::Client,
    nwaku_request_timeout: Duration,
    mut store: Option<StoreHistory>,
) {
    let mut cache = LruCache::new(CACHE_SIZE);
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    let mut pending_store_peers: VecDeque<PeerId> = store
        .as_ref()
        .map(|store| (store.list_peers)().into())
        .unwrap_or_default();
    let mut successfully_queried_store_peers = HashSet::new();
    let mut history: Option<HistoryFuture> = None;
    let mut in_flight = None;
    loop {
        if relay_sink_is_closed(&sink_tx) {
            tracing::debug!("relay sink is closed, breaking...");
            return;
        }

        if history.is_none()
            && let Some(store) = store.as_mut()
        {
            while let Some(peer_id) = pending_store_peers.pop_front() {
                if !successfully_queried_store_peers.contains(&peer_id) {
                    history = Some((store.query)(peer_id));
                    in_flight = Some((peer_id, false));
                    break;
                }
            }
        }

        tokio::select! {
            () = wait_for_relay_sink_closed(&sink_tx) => return,
            _ = tick.tick(), if nwaku_messages_url.is_some() => {
                let Some(url) = &nwaku_messages_url else { continue };
                if !poll_nwaku_messages(&http, url, nwaku_request_timeout, &content_topics, &mut cache, &sink_tx).await {
                    return;
                }
            }
            msg = fleet_rx.recv() => {
                if let Some(msg) = msg {
                    tracing::trace!(msg.content_topic, hash=msg.hash_key(), "received message from fleet");
                    if matches!(handle_relay_message(&mut cache, &sink_tx, msg), RelayMessageOutcome::SinkClosed) {
                        return;
                    }
                } else {
                    tracing::warn!("fleet subscription channel closed");
                    break;
                }
            }
            (peer_id, result) = async {
                match history.as_mut() {
                    Some(query) => query.await,
                    None => std::future::pending().await,
                }
            }, if history.is_some() => {
                history = None;
                let notified = in_flight.take().is_some_and(|(_, notified)| notified);
                match result {
                    Ok(messages) => {
                        successfully_queried_store_peers.insert(peer_id);
                        let lookback = store.as_ref().map_or(Duration::ZERO, |store| store.lookback);
                        if !forward_store_messages(&mut cache, &sink_tx, &content_topics, peer_id, messages, lookback) {
                            return;
                        }
                    }
                    Err(error) => {
                        tracing::warn!(%peer_id, %error, "failed to query historical fee messages from store peer");
                        if notified && queue_store_peer(&mut pending_store_peers, &mut None, &successfully_queried_store_peers, peer_id) {
                            tracing::debug!(%peer_id, "re-queueing store peer notified during its failed query");
                        }
                    }
                }
            }
            notification = async {
                match store.as_mut().and_then(|store| store.peer_rx.as_mut()) {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            }, if store.as_ref().is_some_and(|store| store.peer_rx.is_some()) => {
                let Some(store) = store.as_mut() else { continue };
                match notification {
                    Ok(peer_id) => {
                        if queue_store_peer(&mut pending_store_peers, &mut in_flight, &successfully_queried_store_peers, peer_id) {
                            tracing::debug!(%peer_id, "queueing store peer for fee history query");
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::warn!(skipped, "missed store peer notifications");
                        for peer_id in (store.list_peers)() {
                            queue_store_peer(&mut pending_store_peers, &mut in_flight, &successfully_queried_store_peers, peer_id);
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        tracing::warn!("store peer notification channel closed");
                        store.peer_rx = None;
                    }
                }
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
    backup_peer_task: Option<JoinHandle<()>>,
    network_mode: RelayNetworkMode,
    disabled_reason: Option<Arc<str>>,
}

impl Drop for Client {
    fn drop(&mut self) {
        if let Some(task) = self.backup_peer_task.as_ref() {
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
        let mut backup_peer_task = None;
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
            let direct_peers = parse_peers(&cfg.direct_peers)?;
            let backup_peers = parse_peers(&cfg.backup_peers)?;
            let waku = Arc::new(WakuNode::spawn(config).map_err(ClientError::SpawnNode)?);
            waku.add_additional_peers(direct_peers);
            if !backup_peers.is_empty() {
                backup_peer_task = Some(tokio::spawn(observe_backup_peers(
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
            backup_peer_task,
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
        let Some(waku_fleet) = self.waku_fleet.as_ref() else {
            let reason = self
                .disabled_reason
                .as_deref()
                .unwrap_or("Waku is unavailable for the selected network mode");
            return Err(ClientError::Disabled(reason.to_string()));
        };
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
            let nwaku_messages_url = self.nwaku_url.as_ref().map(|nwaku_url| {
                let encoded_pubsub_path = urlencoding::encode(&self.pubsub_path);
                format!("{nwaku_url}/relay/v1/messages/{encoded_pubsub_path}")
            });
            let store = history_lookback.map(|lookback| {
                let peer_rx = waku_fleet.subscribe_store_peers();
                let list_fleet = Arc::clone(waku_fleet);
                let query_fleet = Arc::clone(waku_fleet);
                let pubsub_path = self.pubsub_path.clone();
                let content_topics = content_topics.clone();
                StoreHistory {
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
                        Box::pin(
                            async move { (peer_id, fleet.store_query_peer(peer_id, query).await) },
                        )
                    }),
                }
            });
            tokio::spawn(forward_messages(
                rx,
                sink_tx,
                content_topics,
                nwaku_messages_url,
                self.http_client.clone(),
                self.nwaku_request_timeout,
                store,
            ));
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
        let Some(waku_fleet) = self.waku_fleet.as_ref() else {
            let reason = self
                .disabled_reason
                .as_deref()
                .unwrap_or("Waku is unavailable for the selected network mode");
            return Err(ClientError::Disabled(reason.to_string()));
        };
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
    if !fallback_endpoints_configured
        && config.discovery.doh_endpoint != DEFAULT_CLEARNET_DOH_ENDPOINT
        && !config
            .discovery
            .doh_fallback_endpoints
            .iter()
            .any(|endpoint| endpoint == DEFAULT_CLEARNET_DOH_ENDPOINT)
    {
        config
            .discovery
            .doh_fallback_endpoints
            .push(DEFAULT_CLEARNET_DOH_ENDPOINT.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CACHE_SIZE, Client, ClientConfig, ClientError, DEFAULT_CLUSTER_ID, DEFAULT_SHARD_ID,
        HistoryFuture, NWAKU_MAX_POLL_BYTES, RelayMessageOutcome, StoreHistory,
        add_tor_doh_fallback, forward_messages, handle_relay_message, is_fee_content_topic,
        poll_nwaku_messages, relay_shard_pubsub_path, relay_sink_is_closed,
        wait_for_relay_sink_closed,
    };
    use lru::LruCache;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::mpsc as std_mpsc;
    use std::thread;
    use std::time::{Duration, Instant};
    use tokio::sync::{broadcast, mpsc, oneshot};
    use tokio::time::timeout;
    use waku::proto::WakuMessage;
    use waku::{DEFAULT_CLEARNET_DOH_ENDPOINT, DEFAULT_TOR_DOH_ENDPOINT, PeerId, WakuError};

    const FEE_TOPIC: &str = "/railgun/v2/0-1-fees/json";

    fn fee_message(payload: u8) -> WakuMessage {
        WakuMessage {
            content_topic: FEE_TOPIC.to_string(),
            payload: vec![payload],
            ..Default::default()
        }
    }

    fn spawn_forwarding(
        fleet_rx: mpsc::Receiver<WakuMessage>,
        sink_tx: mpsc::Sender<WakuMessage>,
        store: StoreHistory,
    ) {
        tokio::spawn(forward_messages(
            fleet_rx,
            sink_tx,
            vec![FEE_TOPIC.to_string()],
            None,
            reqwest::Client::new(),
            Duration::from_secs(1),
            Some(store),
        ));
    }

    #[tokio::test]
    async fn live_messages_forward_while_store_history_is_pending() {
        let peer = PeerId::random();
        let (fleet_tx, fleet_rx) = mpsc::channel(8);
        let (sink_tx, mut sink_rx) = mpsc::channel(8);
        let (peer_tx, peer_rx) = broadcast::channel(8);
        let (history_tx, history_rx) = oneshot::channel();
        let mut history_rx = Some(history_rx);
        spawn_forwarding(
            fleet_rx,
            sink_tx,
            StoreHistory {
                lookback: Duration::from_mins(2),
                peer_rx: Some(peer_rx),
                list_peers: Box::new(move || vec![peer]),
                query: Box::new(move |peer_id: PeerId| -> HistoryFuture {
                    let rx = history_rx.take().expect("one history query");
                    Box::pin(async move { (peer_id, rx.await.expect("history result")) })
                }),
            },
        );
        let (m1, m2) = (fee_message(1), fee_message(2));

        fleet_tx.send(m1.clone()).await.expect("loop reads fleet");
        let live = timeout(Duration::from_secs(1), sink_rx.recv()).await;
        assert_eq!(
            live.expect("live message while history pending"),
            Some(m1.clone())
        );

        // A second query panics the loop and closes the sink, failing the final assertion,
        // so this notification during a successful query must not re-query the peer.
        peer_tx.send(peer).expect("loop subscribed");
        timeout(Duration::from_secs(1), async {
            while !peer_tx.is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("loop consumes store peer notification");

        history_tx
            .send(Ok(vec![m1, m2.clone()]))
            .expect("history pending");
        let history = timeout(Duration::from_secs(1), sink_rx.recv()).await;
        assert_eq!(history.expect("new history message"), Some(m2));
        assert!(
            timeout(Duration::from_millis(100), sink_rx.recv())
                .await
                .is_err(),
            "history copy of the live message must be deduplicated"
        );
    }

    #[tokio::test]
    async fn failing_store_peer_does_not_delay_another() {
        type Call = (PeerId, oneshot::Sender<Result<Vec<WakuMessage>, WakuError>>);
        let (a, b) = (PeerId::random(), PeerId::random());
        let (_fleet_tx, fleet_rx) = mpsc::channel(1);
        let (sink_tx, _sink_rx) = mpsc::channel(8);
        let (peer_tx, peer_rx) = broadcast::channel(64);
        let (calls_tx, mut calls_rx) = mpsc::unbounded_channel::<Call>();
        spawn_forwarding(
            fleet_rx,
            sink_tx,
            StoreHistory {
                lookback: Duration::from_mins(2),
                peer_rx: Some(peer_rx),
                list_peers: Box::new(move || vec![a]),
                query: Box::new(move |peer_id: PeerId| -> HistoryFuture {
                    let (result_tx, result_rx) = oneshot::channel();
                    calls_tx
                        .send((peer_id, result_tx))
                        .expect("test reads history calls");
                    Box::pin(async move {
                        (
                            peer_id,
                            result_rx.await.unwrap_or(Err(WakuError::Cancelled)),
                        )
                    })
                }),
            },
        );
        let next_call = async |calls_rx: &mut mpsc::UnboundedReceiver<Call>| {
            timeout(Duration::from_secs(1), calls_rx.recv())
                .await
                .expect("history query started")
                .expect("query closure alive")
        };

        let (first, fail_a) = next_call(&mut calls_rx).await;
        assert_eq!(first, a);
        for _ in 0..32 {
            peer_tx.send(a).expect("loop subscribed");
        }
        peer_tx.send(b).expect("loop subscribed");
        timeout(Duration::from_secs(1), async {
            while !peer_tx.is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("loop consumes store peer notifications");

        fail_a
            .send(Err(WakuError::StoreRequestFailed))
            .expect("A pending");
        let (second, done_b) = next_call(&mut calls_rx).await;
        assert_eq!(second, b, "B is queried right after A fails");
        done_b.send(Ok(Vec::new())).expect("B pending");

        let mut a_requeries = 0;
        while let Ok(Some((peer_id, result_tx))) =
            timeout(Duration::from_millis(100), calls_rx.recv()).await
        {
            assert_eq!(peer_id, a);
            a_requeries += 1;
            let _ = result_tx.send(Err(WakuError::StoreRequestFailed));
        }
        assert_eq!(
            a_requeries, 1,
            "A notified during its failed query is retried exactly once"
        );
    }

    #[test]
    fn relay_shard_pubsub_path_uses_static_sharding_format() {
        assert_eq!(relay_shard_pubsub_path(5, 1), "/waku/2/rs/5/1");
        assert_eq!(relay_shard_pubsub_path(7, 2), "/waku/2/rs/7/2");
    }

    #[test]
    fn fee_history_topic_detection_only_matches_fees() {
        assert!(is_fee_content_topic("/railgun/v2/0-1-fees/json"));
        assert!(is_fee_content_topic("/railgun/v2/0-42161-fees/json"));
        assert!(!is_fee_content_topic("/railgun/v2/0-1-transact/json"));
        assert!(!is_fee_content_topic(
            "/railgun/v2/0-1-transact-response/json"
        ));
        assert!(!is_fee_content_topic("/other/v2/0-1-fees/json"));
    }

    #[test]
    fn relay_message_delivery_reports_closed_sink() {
        let (sink_tx, sink_rx) = mpsc::channel(1);
        drop(sink_rx);
        let mut cache = LruCache::new(CACHE_SIZE);
        let msg = WakuMessage {
            content_topic: "/railgun/v2/0-1-fees/json".to_string(),
            payload: vec![1, 2, 3],
            ..Default::default()
        };

        assert_eq!(
            handle_relay_message(&mut cache, &sink_tx, msg),
            RelayMessageOutcome::SinkClosed
        );
    }

    #[tokio::test]
    async fn relay_sink_closed_wait_completes_without_messages() {
        let (sink_tx, sink_rx) = mpsc::channel::<WakuMessage>(1);
        assert!(!relay_sink_is_closed(&sink_tx));

        drop(sink_rx);

        tokio::time::timeout(
            Duration::from_millis(100),
            wait_for_relay_sink_closed(&sink_tx),
        )
        .await
        .expect("closed sink should wake relay task promptly");
        assert!(relay_sink_is_closed(&sink_tx));
    }

    #[test]
    fn waku_client_config_applies_schema_fields() {
        let cfg = ClientConfig {
            nwaku_url: None,
            shard_id: Some(3),
            direct_peers: Vec::new(),
            backup_peers: Vec::new(),
            dns_enr_trees: Some(vec!["enrtree://example".to_string()]),
            doh_endpoint: Some("https://example.invalid/dns-query".to_string()),
            doh_fallback_endpoints: Some(vec![
                "https://fallback.example.invalid/dns-query".to_string(),
            ]),
            cluster_id: Some(7),
            max_peers: Some(42),
            peer_connection_timeout: Some(Duration::from_secs(7)),
        };

        let waku = super::Client::build_waku_config(&cfg);

        assert_eq!(waku.cluster_id, 7);
        assert_eq!(waku.shard_id, 3);
        assert_eq!(waku.discovery.enr_trees, vec!["enrtree://example"]);
        assert_eq!(
            waku.discovery.doh_endpoint,
            "https://example.invalid/dns-query"
        );
        assert_eq!(
            waku.discovery.doh_fallback_endpoints,
            vec!["https://fallback.example.invalid/dns-query".to_string()]
        );
        assert_eq!(waku.node.connection_cap, 42);
        assert_eq!(waku.node.request_timeout, Duration::from_secs(7));
    }

    #[test]
    fn waku_client_config_uses_relay_defaults() {
        let cfg = ClientConfig {
            nwaku_url: None,
            shard_id: None,
            direct_peers: Vec::new(),
            backup_peers: Vec::new(),
            dns_enr_trees: None,
            doh_endpoint: None,
            doh_fallback_endpoints: None,
            cluster_id: None,
            max_peers: None,
            peer_connection_timeout: None,
        };

        let waku = super::Client::build_waku_config(&cfg);

        assert_eq!(waku.cluster_id, DEFAULT_CLUSTER_ID);
        assert_eq!(waku.shard_id, DEFAULT_SHARD_ID);
    }

    #[test]
    fn tor_doh_fallback_adds_clearnet_endpoint() {
        let mut waku = waku::WakuConfig::default();
        waku.discovery.doh_endpoint = DEFAULT_TOR_DOH_ENDPOINT.to_string();

        add_tor_doh_fallback(&mut waku, false);

        assert_eq!(waku.discovery.doh_endpoint, DEFAULT_TOR_DOH_ENDPOINT);
        assert_eq!(
            waku.discovery.doh_fallback_endpoints,
            vec![DEFAULT_CLEARNET_DOH_ENDPOINT.to_string()]
        );
    }

    #[test]
    fn tor_doh_fallback_respects_explicit_empty_list() {
        let mut waku = waku::WakuConfig::default();
        waku.discovery.doh_endpoint = DEFAULT_TOR_DOH_ENDPOINT.to_string();

        add_tor_doh_fallback(&mut waku, true);

        assert!(waku.discovery.doh_fallback_endpoints.is_empty());
    }

    #[tokio::test]
    async fn client_drop_shuts_down_embedded_waku_node() {
        let direct = super::AdditionalPeer {
            peer_id: "12D3KooWPZAXp2aXSq7hh5iy8pxziTv1bxU8cg4pc4YEgkFiiixv".to_string(),
            addrs: vec!["/ip4/127.0.0.1/tcp/1".to_string()],
        };
        let backup = super::AdditionalPeer {
            peer_id: "12D3KooWPZAXp2aXSq7hh5iy8pxziTv1bxU8cg4pc4YEgkFiiixw".to_string(),
            addrs: vec!["/ip4/127.0.0.1/tcp/2".to_string()],
        };
        for backup_peers in [Vec::new(), vec![backup]] {
            let cfg = ClientConfig {
                direct_peers: vec![direct.clone()],
                backup_peers,
                dns_enr_trees: Some(Vec::new()),
                max_peers: Some(0),
                ..Default::default()
            };
            let client = Client::new(&cfg).expect("client starts");
            let node = Arc::clone(client.waku_fleet.as_ref().expect("Waku node enabled"));
            tokio::task::yield_now().await;
            assert!(!node.is_shutdown());
            let peers = node.peer_snapshots();
            assert_eq!(
                peers.len(),
                1,
                "only immediate peers enter the initial pool"
            );
            assert_eq!(peers[0].peer_id.to_string(), direct.peer_id);
            let observer = client
                .backup_peer_task
                .as_ref()
                .map(tokio::task::JoinHandle::abort_handle);
            assert_eq!(observer.is_none(), cfg.backup_peers.is_empty());

            drop(client);

            assert!(node.is_shutdown());
            if let Some(observer) = observer {
                tokio::time::timeout(Duration::from_secs(1), async {
                    while !observer.is_finished() {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("client drop must retire backup observation");
            }
            assert_eq!(node.peer_snapshots().len(), 1);
        }
    }

    #[test]
    fn backup_delay_restarts_after_an_observed_connection() {
        let start = Instant::now();
        let mut since = None;
        for seconds in [0, 1, 30, 59] {
            assert!(!super::backup_peers_due(
                &mut since,
                start + Duration::from_secs(seconds),
                false
            ));
        }
        assert!(super::backup_peers_due(
            &mut since,
            start + Duration::from_mins(1),
            false
        ));
        assert!(!super::backup_peers_due(
            &mut since,
            start + Duration::from_secs(61),
            true
        ));
        assert!(!super::backup_peers_due(
            &mut since,
            start + Duration::from_mins(2),
            true
        ));
        for seconds in [121, 150, 180] {
            assert!(!super::backup_peers_due(
                &mut since,
                start + Duration::from_secs(seconds),
                false
            ));
        }
        assert!(super::backup_peers_due(
            &mut since,
            start + Duration::from_secs(181),
            false
        ));
    }

    #[tokio::test]
    async fn nwaku_publication_times_out_when_server_stalls() {
        let nwaku_request_timeout = Duration::from_millis(100);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stalled HTTP endpoint");
        let address = listener.local_addr().expect("read listener address");
        let (accepted_tx, accepted_rx) = std_mpsc::channel();
        let (release_tx, release_rx) = std_mpsc::channel();
        let server = thread::spawn(move || {
            let (_stream, _) = listener.accept().expect("accept nwaku request");
            accepted_tx.send(()).expect("notify request accepted");
            release_rx.recv().expect("wait for test cleanup");
        });
        let client = Client {
            http_client: reqwest::Client::new(),
            nwaku_request_timeout,
            nwaku_url: Some(format!("http://{address}/private-endpoint-token")),
            pubsub_path: relay_shard_pubsub_path(DEFAULT_CLUSTER_ID, DEFAULT_SHARD_ID),
            waku_fleet: None,
            backup_peer_task: None,
            network_mode: super::RelayNetworkMode::Direct,
            disabled_reason: None,
        };

        let result = tokio::time::timeout(
            nwaku_request_timeout + Duration::from_secs(1),
            client.publish_to_nwaku("/railgun/v2/0-1-fees/json", br"{}"),
        )
        .await
        .expect("publication should not outlive its request timeout");
        accepted_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("stalled endpoint should receive the publication request");
        release_tx.send(()).expect("release stalled endpoint");
        server.join().expect("stalled endpoint thread exits");

        let Err(ClientError::Http(error)) = result else {
            panic!("stalled publication should fail with an HTTP timeout");
        };
        assert!(error.is_timeout());
        assert!(
            error.url().is_none(),
            "endpoint credentials must not escape in errors"
        );
    }

    #[tokio::test]
    async fn oversized_nwaku_poll_is_rejected_and_next_poll_succeeds() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind nwaku endpoint");
        let url = format!(
            "http://{}/relay/v1/auto/messages",
            listener.local_addr().expect("read listener address")
        );
        let server = thread::spawn(move || {
            let mut buf = [0_u8; 1024];
            let (mut stream, _) = listener.accept().expect("accept oversized poll");
            let _ = stream.read(&mut buf);
            let mut response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n[{{\"contentTopic\":\"{FEE_TOPIC}\",\"payload\":\"AQ==\"}}]"
            )
            .into_bytes();
            // Trailing whitespace keeps the body valid JSON if it were read in full.
            response.resize(response.len() + NWAKU_MAX_POLL_BYTES + 1, b' ');
            let _ = stream.write_all(&response);
            drop(stream);

            let (mut stream, _) = listener.accept().expect("accept next poll");
            let _ = stream.read(&mut buf);
            let body = format!("[{{\"contentTopic\":\"{FEE_TOPIC}\",\"payload\":\"Ag==\"}}]");
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        });
        let http = reqwest::Client::new();
        let topics = [FEE_TOPIC.to_string()];
        let mut cache = LruCache::new(CACHE_SIZE);
        let (sink_tx, mut sink_rx) = mpsc::channel(8);

        assert!(
            poll_nwaku_messages(
                &http,
                &url,
                Duration::from_secs(10),
                &topics,
                &mut cache,
                &sink_tx
            )
            .await
        );
        assert!(sink_rx.try_recv().is_err());

        assert!(
            poll_nwaku_messages(
                &http,
                &url,
                Duration::from_secs(10),
                &topics,
                &mut cache,
                &sink_tx
            )
            .await
        );
        assert_eq!(sink_rx.try_recv(), Ok(fee_message(2)));
        server.join().expect("nwaku endpoint thread exits");
    }
}
