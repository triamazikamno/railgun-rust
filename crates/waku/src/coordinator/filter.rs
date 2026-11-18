#[allow(clippy::wildcard_imports)]
use super::*;

const DEDUP_CACHE_SIZE: usize = 500;

/// Unique identifier for a filter subscription.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct SubId(u64);

impl SubId {
    pub(super) fn next(counter: &AtomicU64) -> Self {
        Self(counter.fetch_add(1, Ordering::Relaxed))
    }
}

/// A single filter subscription.
#[derive(Debug)]
pub(super) struct Subscription {
    pub(super) pubsub_topic: String,
    pub(super) content_topics: Vec<String>,
    pub(super) sender: mpsc::Sender<proto::WakuMessage>,
    pub(super) dropped_since_log: u64,
    pub(super) last_drop_log: Option<Instant>,
}

#[derive(Debug)]
pub(super) enum FilterOp {
    Subscribe { sub_id: SubId },
    Unsubscribe { sub_id: SubId, batch_id: u64 },
    UnsubscribeAll { pubsub_topic: String, batch_id: u64 },
    SubscribeOnPeer { sub_id: SubId },
}

#[derive(Debug)]
pub(super) struct FilterBatch {
    pub(super) expected: usize,
    pub(super) finished: usize,
    pub(super) succeeded: bool,
    pub(super) waiter: oneshot::Sender<Result<(), WakuError>>,
    pub(super) last_error: Option<WakuError>,
}

#[derive(Debug)]
pub(super) struct FilterState {
    /// Active subscriptions by ID.
    pub(super) subscriptions: HashMap<SubId, Subscription>,
    /// Pending outbound requests.
    pending: HashMap<ReqId, FilterOp>,
    /// Dedup cache: hash of (`content_topic`, `payload`).
    dedup_cache: LruCache<u64, ()>,
    /// Next subscription ID counter.
    pub(super) next_sub_id: AtomicU64,
    /// Next batch ID counter.
    pub(super) next_batch_id: AtomicU64,
    /// Pending unsubscribe batches.
    pub(super) batches: HashMap<u64, FilterBatch>,
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

pub(super) fn build_filter_request(
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

impl NodeInner {
    pub(super) async fn send_filter_request(
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

        if !finalize_success && !finalize_failure {
            return;
        }
        let Some(batch) = filter.batches.remove(&batch_id) else {
            return;
        };
        let outcome = if finalize_success {
            on_success(filter);
            Ok(())
        } else {
            Err(batch.last_error.unwrap_or(WakuError::FilterRequestFailed))
        };
        if let Err(err) = batch.waiter.send(outcome) {
            debug!(target: LOG_TARGET, ?err, batch_id = %batch_id, "failed to send filter batch outcome");
        }
    }

    pub(super) async fn handle_filter_subscribe_response(
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
                debug!(target: LOG_TARGET, %peer_id, ?error, "filter subscribe failed");
                Err(WakuError::FilterRequestFailed)
            }
        };

        match op {
            FilterOp::Subscribe { sub_id } => match result_status {
                Ok(()) => {
                    debug!(target: LOG_TARGET, %peer_id, ?sub_id, "filter subscribe succeeded");
                }
                Err(error) => {
                    warn!(target: LOG_TARGET, %peer_id, ?sub_id, ?error, "filter subscribe failed");
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
                    debug!(target: LOG_TARGET, %peer_id, ?sub_id, "filter subscribe (peer) succeeded");
                }
                Err(error) => {
                    debug!(target: LOG_TARGET, %peer_id, ?sub_id, ?error, "filter subscribe (peer) failed");
                }
            },
        }
    }

    pub(super) async fn handle_filter_push(
        &self,
        peer_id: PeerId,
        push: proto::filter::MessagePush,
    ) {
        let Some(message) = push.waku_message else {
            debug!(target: LOG_TARGET, %peer_id, "received filter push without message");
            return;
        };

        let hash = message.hash_key();

        let mut filter = self.ops.filter.lock().await;

        if filter.dedup_cache.contains(&hash) {
            trace!(target: LOG_TARGET, %peer_id, "duplicate filter push, ignoring");
            return;
        }
        filter.dedup_cache.put(hash, ());

        // Route to matching subscriptions
        let Some(pubsub_topic) = push.pubsub_topic.as_deref() else {
            debug!(target: LOG_TARGET, %peer_id, "received filter push without pubsub topic");
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
                        debug!(target: LOG_TARGET,
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
            debug!(target: LOG_TARGET, ?sub_id, "removed closed filter subscription");
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
            warn!(target: LOG_TARGET, %peer_id, ?sub_id, ?error, "failed to send filter subscribe request");
        }
    }

    pub(super) async fn subscribe_on_peer(&self, peer_id: PeerId) {
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

        debug!(target: LOG_TARGET, %peer_id, count = subs_to_send.len(), "subscribing filter subscriptions on peer");

        for (sub_id, pubsub_topic, content_topics) in subs_to_send {
            self.send_subscribe_request(peer_id, sub_id, pubsub_topic, content_topics)
                .await;
        }
    }
}
