use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use libp2p::PeerId;
use parking_lot::RwLock;
use tokio::sync::{Mutex, Notify, broadcast, mpsc, oneshot, watch};
use tokio::time::{Instant, timeout};
use tracing::{debug, warn};

use crate::config::{WakuConfig, WakuTransportProfile};
use crate::discovery;
use crate::error::WakuError;
use crate::proto;
use crate::protocols::store::StoreQueryPage;
use crate::tasks::task_tracker;
use crate::transport::{ReqId, Transport, TransportCmd};
use crate::types::OpId;

use super::{
    FilterBatch, FilterOp, FilterState, LightPushResult, NodeInner, OpTracker, PeerBook,
    PeerSnapshot, PeerSource, PeerStats, ResponseBatch, STORE_PEER_EVENT_CAPACITY, StorePending,
    StoreQueryOptions, SubId, Subscription, WakuNode, build_filter_request,
    remove_lightpush_operation, store_status_ok,
};

impl WakuNode {
    /// Spawn the node and transport tasks.
    pub fn spawn(config: WakuConfig) -> Result<Self, WakuError> {
        let (tasks, task_waiter) = task_tracker();
        let transport = Transport::new(&config.node, &config.network, tasks.clone())?;
        let local_peer_id = transport.local_peer_id();
        let (transport_tx, transport_cmd_rx) = mpsc::channel(64);
        let (transport_event_tx, transport_event_rx) = mpsc::channel(64);
        let (filter_push_tx, filter_push_rx) = mpsc::channel(64);
        let (dial_tx, dial_rx) = mpsc::channel(64);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        tasks.spawn(transport.run(
            transport_cmd_rx,
            transport_event_tx,
            filter_push_tx,
            shutdown_rx,
        ));

        let metadata_response = proto::metadata::WakuMetadataResponse {
            cluster_id: Some(config.cluster_id),
            shards: vec![config.shard_id],
        };

        let (store_peer_tx, _) = broadcast::channel(STORE_PEER_EVENT_CAPACITY);

        let mut discovery_config = config.discovery;
        if config.network.transport_profile == WakuTransportProfile::Tor {
            discovery_config
                .http_client
                .clone_from(&config.network.http_client);
            discovery_config.allow_system_dns = false;
        }

        let inner = Arc::new(NodeInner {
            config: config.node,
            discovery_config,
            network_profile: config.network.transport_profile,
            peer_book: Arc::new(RwLock::new(PeerBook::default())),
            session_refresh_disconnects: RwLock::new(HashSet::new()),
            discovery_wake: Notify::new(),
            ops: OpTracker::new(),
            transport_tx,
            dial_tx,
            metadata_response,
            peer_exchange_cooldown: config.peer_exchange_cooldown,
            op_counter: AtomicU64::new(1),
            dns_round: AtomicU64::new(0),
            dns_records: RwLock::new(Vec::new()),
            peer_capabilities_changed: Notify::new(),
            local_peer_id,
            tasks: Mutex::new(task_waiter),
            store_peer_tx,
            shutdown_tx,
        });

        {
            let inner = inner.clone();
            tasks.spawn(async move {
                inner
                    .run_event_loop(transport_event_rx, filter_push_rx)
                    .await;
            });
        }

        {
            let inner = inner.clone();
            tasks.spawn(async move {
                inner.run_dialer(dial_rx).await;
            });
        }

        {
            let inner = inner.clone();
            tasks.spawn(async move {
                inner.run_discovery_loop().await;
            });
        }

        {
            let inner = inner.clone();
            tasks.spawn(async move {
                inner.run_peer_exchange_loop().await;
            });
        }

        Ok(Self { inner })
    }

    /// Signal shutdown without waiting; see [`Self::shutdown_and_wait`].
    pub fn shutdown(&self) {
        self.inner.shutdown();
    }

    /// Signal shutdown and wait up to `bound` for the node to terminate.
    ///
    /// `Ok` guarantees that every task the node spawned has ended: the transport loop, event
    /// loop, dialer, DNS discovery loop, peer-exchange loop and filter-push stream handlers, plus
    /// every libp2p connection and pending-dial task spawned through the swarm executor. The
    /// swarm and its transport, including the Tor client provider, have been dropped, so no
    /// dial, DNS discovery or peer exchange can start again.
    ///
    /// Limit: in the Direct profile, QUIC endpoint driver tasks are spawned inside quinn, are
    /// not tracked, and end when their sockets close. The Tor profile has no QUIC.
    ///
    /// Returns [`WakuError::ShutdownIncomplete`] if `bound` elapses first; the node stays shut
    /// down and a later call may wait again. Concurrent calls serialize, and calls after
    /// termination was observed return `Ok` immediately.
    pub async fn shutdown_and_wait(&self, bound: Duration) -> Result<(), WakuError> {
        self.shutdown();
        timeout(bound, async { self.inner.tasks.lock().await.wait().await })
            .await
            .map_err(|_| WakuError::ShutdownIncomplete)
    }

    /// Wait up to `bound` until a connected peer supports `LightPush` v3 and a connected peer,
    /// possibly another one, supports Filter.
    ///
    /// Returns [`WakuError::NoPeersAvailable`] when `bound` elapses and
    /// [`WakuError::Cancelled`] once the node is shut down.
    pub async fn wait_ready(&self, bound: Duration) -> Result<(), WakuError> {
        self.inner.wait_ready(bound).await
    }

    /// This node's libp2p peer ID, generated fresh for each spawned node.
    #[must_use]
    pub fn local_peer_id(&self) -> PeerId {
        self.inner.local_peer_id
    }

    /// Records from the latest successful DNS discovery round, after the address policy.
    ///
    /// Only ENR-tree record addresses appear here; peer-exchange peers and Identify-reported
    /// addresses never do. A failed round keeps the previous records.
    #[must_use]
    pub fn dns_peer_records(&self) -> Vec<discovery::DiscoveredPeer> {
        self.inner.dns_records.read().clone()
    }

    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.inner.is_shutdown()
    }

    pub fn add_additional_peers(&self, peers: Vec<discovery::DiscoveredPeer>) {
        self.inner
            .apply_discovered_peers(peers, PeerSource::Configured);
    }

    /// Refresh peer dialing after the underlying network session changes.
    ///
    /// Existing connections are closed, dial backoff is cleared, known peers are
    /// retried immediately, and DNS discovery is re-run without waiting for the
    /// normal discovery interval.
    pub fn refresh_network_session(&self) {
        self.inner.refresh_network_session();
    }

    /// Get peer statistics
    #[must_use]
    pub fn get_stats(&self) -> PeerStats {
        self.inner.peer_book.read().get_stats()
    }

    /// Get the list of currently connected peers.
    #[must_use]
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.inner.peer_book.read().connected_peers()
    }

    /// Read-only peer snapshot for monitor-style consumers.
    #[must_use]
    pub fn peer_snapshots(&self) -> Vec<PeerSnapshot> {
        self.inner.peer_book.read().peer_snapshots()
    }

    /// Dial known peers until the configured connection cap is reached.
    pub fn connect_until_cap(&self) {
        self.inner.maybe_dial();
    }

    /// `LightPush` a message to all currently connected peers supporting `LightPush` v3.
    /// Returns when one peer accepts the message or every attempted peer responds.
    pub async fn lightpush_all(
        &self,
        pubsub_topic: String,
        content_topic: String,
        payload: Vec<u8>,
    ) -> Result<Vec<LightPushResult>, WakuError> {
        let op_id = OpId::next(&self.inner.op_counter);
        let (tx, rx) = oneshot::channel();

        {
            let mut lp = self.inner.ops.lightpush.lock().await;
            lp.waiters.insert(op_id, tx);

            let candidates: Vec<PeerId> = {
                let book = self.inner.peer_book.read();
                book.connected
                    .iter()
                    .filter(|p| book.peers.get(p).is_some_and(|s| s.supports_lightpush_v3))
                    .copied()
                    .collect()
            };

            if candidates.is_empty() {
                lp.waiters.remove(&op_id);
                return Err(WakuError::NoPeersAvailable);
            }

            let mut expected = 0;
            let now_ns = i64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos(),
            )
            .unwrap_or(i64::MAX);

            for peer_id in candidates {
                let req_id = self.inner.ops.next_req_id();
                let request = proto::light_push::LightPushRequestV3 {
                    request_id: uuid::Uuid::new_v4().to_string(),
                    pubsub_topic: Some(pubsub_topic.clone()),
                    message: Some(proto::message::WakuMessage {
                        payload: payload.clone(),
                        content_topic: content_topic.clone(),
                        version: None,
                        timestamp: Some(now_ns),
                        meta: None,
                        rate_limit_proof: None,
                        ephemeral: None,
                    }),
                };

                let cmd = TransportCmd::SendLightPush {
                    req_id,
                    peer_id,
                    request,
                };
                if self.inner.transport_tx.try_send(cmd).is_ok() {
                    lp.pending.insert(req_id, (op_id, peer_id));
                    expected += 1;
                }
            }

            if expected == 0 {
                lp.waiters.remove(&op_id);
                return Err(WakuError::ChannelFull);
            }

            let op = ResponseBatch {
                expected,
                finished: 0,
                results: Vec::new(),
                deadline: Instant::now() + self.inner.config.request_timeout,
            };
            lp.ops.insert(op_id, op);
        }

        if let Ok(result) = timeout(self.inner.config.request_timeout, rx).await {
            return result.map_err(|_| WakuError::Cancelled)?;
        }
        let mut lp = self.inner.ops.lightpush.lock().await;
        remove_lightpush_operation(&mut lp, op_id);
        Err(WakuError::RequestTimeout)
    }

    #[must_use]
    pub fn store_peers(&self) -> Vec<PeerId> {
        let book = self.inner.peer_book.read();
        book.connected
            .iter()
            .filter(|p| book.peers.get(p).is_some_and(|s| s.supports_store))
            .copied()
            .collect()
    }

    #[must_use]
    pub fn subscribe_store_peers(&self) -> broadcast::Receiver<PeerId> {
        self.inner.store_peer_tx.subscribe()
    }

    pub async fn store_query_peer(
        &self,
        peer_id: PeerId,
        options: StoreQueryOptions,
    ) -> Result<Vec<proto::WakuMessage>, WakuError> {
        options.validate()?;
        store_query_peer_pages(peer_id, &options, move |request| {
            self.store_query_peer_page(peer_id, request)
        })
        .await
    }

    async fn store_query_peer_page(
        &self,
        peer_id: PeerId,
        request: proto::store::StoreQueryRequest,
    ) -> Result<StoreQueryPage, WakuError> {
        let req_id = self.inner.ops.next_req_id();
        let (waiter, rx) = oneshot::channel();

        {
            let mut store = self.inner.ops.store.lock().await;
            store.pending.insert(
                req_id,
                StorePending {
                    waiter,
                    deadline: Instant::now() + self.inner.config.request_timeout,
                },
            );
        }

        let cmd = TransportCmd::SendStoreQuery {
            req_id,
            peer_id,
            request,
        };
        if self.inner.transport_tx.try_send(cmd).is_err() {
            self.inner.ops.store.lock().await.pending.remove(&req_id);
            return Err(WakuError::ChannelFull);
        }

        rx.await.map_err(|_| WakuError::Cancelled)?
    }

    fn filter_peers(&self) -> Vec<PeerId> {
        let book = self.inner.peer_book.read();
        book.connected
            .iter()
            .filter(|p| book.peers.get(p).is_some_and(|s| s.supports_filter))
            .copied()
            .collect()
    }

    async fn await_filter_result<T, F>(
        &self,
        waiter_rx: oneshot::Receiver<Result<T, WakuError>>,
        cleanup: F,
    ) -> Result<T, WakuError>
    where
        F: FnOnce(&mut FilterState) + Send,
    {
        if let Ok(result) = waiter_rx.await {
            result
        } else {
            let mut filter = self.inner.ops.filter.lock().await;
            cleanup(&mut filter);
            Err(WakuError::Cancelled)
        }
    }

    async fn run_filter_batch<F>(
        &self,
        peers: Vec<PeerId>,
        make_request: F,
    ) -> Result<(), WakuError>
    where
        F: Fn(PeerId, ReqId, u64) -> (proto::filter::FilterSubscribeRequest, FilterOp),
    {
        let (waiter_tx, waiter_rx) = oneshot::channel();
        let batch_id = {
            let mut filter = self.inner.ops.filter.lock().await;
            let batch_id = filter.next_batch_id.fetch_add(1, Ordering::Relaxed);
            let batch = FilterBatch {
                expected: peers.len(),
                finished: 0,
                succeeded: false,
                waiter: waiter_tx,
                last_error: None,
            };
            filter.batches.insert(batch_id, batch);
            batch_id
        };

        for peer_id in peers {
            let req_id = self.inner.ops.next_req_id();
            let (request, op) = make_request(peer_id, req_id, batch_id);

            if let Err(error) = self
                .inner
                .send_filter_request(req_id, peer_id, request, op)
                .await
            {
                let mut filter = self.inner.ops.filter.lock().await;
                if let Some(batch) = filter.batches.get_mut(&batch_id) {
                    batch.expected = batch.expected.saturating_sub(1);
                    batch.last_error.get_or_insert(error);
                }
            }
        }

        let empty_batch = {
            let mut filter = self.inner.ops.filter.lock().await;
            if let Some(batch) = filter.batches.get(&batch_id)
                && batch.expected == 0
            {
                filter.batches.remove(&batch_id)
            } else {
                None
            }
        };

        if let Some(batch) = empty_batch {
            return Err(batch.last_error.unwrap_or(WakuError::ChannelFull));
        }

        self.await_filter_result(waiter_rx, |filter| {
            filter.batches.remove(&batch_id);
        })
        .await
    }

    /// Subscribe to filter messages matching the given criteria.
    /// Returns a receiver that will receive matching `WakuMessage`s.
    pub async fn filter_subscribe(
        &self,
        pubsub_topic: String,
        content_topics: Vec<String>,
    ) -> Result<mpsc::Receiver<proto::WakuMessage>, WakuError> {
        if content_topics.is_empty() {
            return Err(WakuError::InvalidArgument(
                "content_topics cannot be empty".to_string(),
            ));
        }

        let (msg_tx, msg_rx) = mpsc::channel(64);
        let sub_content_topics = content_topics.clone();
        let sub_pubsub_topic = pubsub_topic.clone();

        let sub_id = {
            let mut filter = self.inner.ops.filter.lock().await;
            let sub_id = SubId::next(&filter.next_sub_id);

            let subscription = Subscription {
                pubsub_topic: sub_pubsub_topic,
                content_topics: sub_content_topics,
                sender: msg_tx,
                dropped_since_log: 0,
                last_drop_log: None,
            };
            filter.subscriptions.insert(sub_id, subscription);
            sub_id
        };

        let peers = self.filter_peers();
        if peers.is_empty() {
            debug!(
                ?sub_id,
                "no filter peers available; subscription will activate on connect"
            );
            return Ok(msg_rx);
        }

        for peer_id in peers {
            let req_id = self.inner.ops.next_req_id();
            let request = build_filter_request(
                proto::filter::filter_subscribe_request::FilterSubscribeType::Subscribe,
                pubsub_topic.clone(),
                content_topics.clone(),
            );

            if let Err(error) = self
                .inner
                .send_filter_request(req_id, peer_id, request, FilterOp::Subscribe { sub_id })
                .await
            {
                warn!(%peer_id, ?sub_id, ?error, "failed to send filter subscribe request");
            }
        }

        Ok(msg_rx)
    }

    /// Unsubscribe from specific content topics.
    pub async fn filter_unsubscribe(
        &self,
        pubsub_topic: String,
        content_topics: Vec<String>,
    ) -> Result<(), WakuError> {
        if content_topics.is_empty() {
            return Err(WakuError::InvalidArgument(
                "content_topics cannot be empty".to_string(),
            ));
        }

        let peers = self.filter_peers();
        if peers.is_empty() {
            return Err(WakuError::NoPeersAvailable);
        }

        // Find matching subscription
        let sub_id = {
            let filter = self.inner.ops.filter.lock().await;
            filter.subscriptions.iter().find_map(|(id, sub)| {
                if sub.pubsub_topic == pubsub_topic && sub.content_topics == content_topics {
                    Some(*id)
                } else {
                    None
                }
            })
        };

        let Some(sub_id) = sub_id else {
            return Err(WakuError::SubscriptionNotFound);
        };

        let pubsub_topic = pubsub_topic.clone();
        let content_topics = content_topics.clone();

        self.run_filter_batch(peers, move |_peer_id, _req_id, batch_id| {
            let request = build_filter_request(
                proto::filter::filter_subscribe_request::FilterSubscribeType::Unsubscribe,
                pubsub_topic.clone(),
                content_topics.clone(),
            );
            (request, FilterOp::Unsubscribe { sub_id, batch_id })
        })
        .await
    }

    /// Unsubscribe from all content topics for the given pubsub topic.
    pub async fn filter_unsubscribe_all(&self, pubsub_topic: String) -> Result<(), WakuError> {
        let peers = self.filter_peers();
        if peers.is_empty() {
            return Err(WakuError::NoPeersAvailable);
        }

        let pubsub_topic = pubsub_topic.clone();

        self.run_filter_batch(peers, move |_peer_id, _req_id, batch_id| {
            let request = build_filter_request(
                proto::filter::filter_subscribe_request::FilterSubscribeType::UnsubscribeAll,
                pubsub_topic.clone(),
                Vec::new(),
            );
            (
                request,
                FilterOp::UnsubscribeAll {
                    pubsub_topic: pubsub_topic.clone(),
                    batch_id,
                },
            )
        })
        .await
    }
}

// Bound one peer's history query so a Store peer cannot keep it paging or growing.
const MAX_STORE_QUERY_PAGES: usize = 8;
const MAX_STORE_QUERY_BYTES: usize = 16 * 1024 * 1024;

/// Page through one peer's Store history until its cursor ends or a limit is reached.
///
/// Response frame lengths, not decoded sizes, count toward `MAX_STORE_QUERY_BYTES`, since
/// decoded messages can retain more capacity than they encode to.
async fn store_query_peer_pages<F, Fut>(
    peer_id: PeerId,
    options: &StoreQueryOptions,
    mut fetch_page: F,
) -> Result<Vec<proto::WakuMessage>, WakuError>
where
    F: FnMut(proto::store::StoreQueryRequest) -> Fut,
    Fut: Future<Output = Result<StoreQueryPage, WakuError>>,
{
    let mut cursor = None;
    let mut messages = Vec::new();
    let mut pages = 0usize;
    let mut bytes = 0usize;

    loop {
        let StoreQueryPage {
            response,
            frame_len,
        } = fetch_page(options.to_request(cursor.take())).await?;
        pages += 1;
        bytes += frame_len;

        if !store_status_ok(&response) {
            return Err(WakuError::StoreQueryFailed {
                status_code: response.status_code,
                status_desc: response.status_desc,
            });
        }

        messages.extend(
            response
                .messages
                .into_iter()
                .filter_map(|entry| entry.message),
        );

        let Some(next_cursor) = response.pagination_cursor.filter(|c| !c.is_empty()) else {
            debug!(%peer_id, pages, bytes, messages = messages.len(), "store query complete");
            break;
        };
        if pages >= MAX_STORE_QUERY_PAGES || bytes >= MAX_STORE_QUERY_BYTES {
            let limit = if pages >= MAX_STORE_QUERY_PAGES {
                "pages"
            } else {
                "bytes"
            };
            warn!(%peer_id, limit, pages, bytes, "store query stopped at history limit");
            break;
        }
        cursor = Some(next_cursor);
    }

    Ok(messages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::store::decode_store_query_page;
    use prost::Message;

    fn options() -> StoreQueryOptions {
        StoreQueryOptions {
            pubsub_topic: "/waku/2/rs/1/0".to_string(),
            content_topics: vec!["/railgun/v2/0-1-fees/json".to_string()],
            time_start: None,
            time_end: None,
            pagination_limit: Some(100),
        }
    }

    /// A page with one message per payload byte.
    fn page(cursor: Option<Vec<u8>>, payloads: &[u8]) -> StoreQueryPage {
        let response = proto::store::StoreQueryResponse {
            messages: payloads
                .iter()
                .map(|&payload| proto::store::WakuMessageKeyValue {
                    message: Some(proto::WakuMessage {
                        payload: vec![payload],
                        ..Default::default()
                    }),
                    ..Default::default()
                })
                .collect(),
            pagination_cursor: cursor,
            ..Default::default()
        };
        StoreQueryPage {
            frame_len: response.encoded_len(),
            response,
        }
    }

    /// Run the paging loop over `page_for(call_number)`, returning each request's cursor and
    /// the payload byte of every message returned.
    async fn query(
        mut page_for: impl FnMut(u8) -> StoreQueryPage,
    ) -> (Vec<Option<Vec<u8>>>, Vec<u8>) {
        let mut cursors = Vec::new();
        let messages = store_query_peer_pages(PeerId::random(), &options(), |request| {
            cursors.push(request.pagination_cursor);
            let page = page_for(cursors.len() as u8);
            async move { Ok::<_, WakuError>(page) }
        })
        .await
        .expect("store query");
        let payloads = messages
            .iter()
            .map(|message| message.payload.first().copied().unwrap_or_default())
            .collect();
        (cursors, payloads)
    }

    #[tokio::test]
    async fn fresh_cursors_stop_at_page_limit() {
        let (cursors, payloads) = query(|n| page(Some(vec![n]), &[n])).await;
        assert_eq!(cursors.len(), MAX_STORE_QUERY_PAGES);
        assert_eq!(payloads, (1..=8).collect::<Vec<u8>>());
    }

    #[tokio::test]
    async fn repeated_cursor_stops_at_page_limit() {
        let (cursors, _) = query(|_| page(Some(vec![7]), &[])).await;
        assert_eq!(cursors.len(), MAX_STORE_QUERY_PAGES);
    }

    #[tokio::test]
    async fn large_cursors_stop_at_byte_limit() {
        // Each frame is just over 5 MiB, so the fourth crosses 16 MiB.
        let (cursors, _) = query(|n| page(Some(vec![n; 5 * 1024 * 1024]), &[])).await;
        assert_eq!(cursors.len(), 4);
    }

    #[tokio::test]
    async fn byte_limit_counts_frame_length_not_decoded_size() {
        // A ~9 MiB payload followed by an empty duplicate decodes to an empty payload.
        let page_for = |n: u8| {
            let mut message = proto::WakuMessage {
                payload: vec![n; 9 * 1024 * 1024],
                content_topic: "t".to_string(),
                ..Default::default()
            }
            .encode_to_vec();
            prost::encoding::bytes::encode(1, &Vec::<u8>::new(), &mut message);
            let mut entry = Vec::new();
            prost::encoding::bytes::encode(2, &message, &mut entry);
            let mut frame = proto::store::StoreQueryResponse {
                pagination_cursor: Some(vec![n]),
                ..Default::default()
            }
            .encode_to_vec();
            prost::encoding::bytes::encode(20, &entry, &mut frame);

            let page = decode_store_query_page(&frame).expect("decode page");
            assert!(page.response.encoded_len() * 1000 < page.frame_len);
            page
        };

        let (cursors, _) = query(page_for).await;
        assert_eq!(cursors.len(), 2);
    }

    #[tokio::test]
    async fn ended_cursor_returns_all_pages() {
        let (cursors, payloads) = query(|n| page((n < 3).then(|| vec![n]), &[n])).await;
        assert_eq!(cursors, vec![None, Some(vec![1]), Some(vec![2])]);
        assert_eq!(payloads, vec![1, 2, 3]);
    }
}
