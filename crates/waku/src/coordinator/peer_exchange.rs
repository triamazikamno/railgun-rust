#[allow(clippy::wildcard_imports)]
use super::*;

#[derive(Debug)]
struct PeerExchangeOp {
    remaining_rounds: usize,
    current_batch: Option<usize>,
    deadline: Instant,
}

#[derive(Debug, Default)]
pub(super) struct PeerExchangeState {
    pub(super) pending: HashMap<ReqId, usize>,
    pub(super) ops: HashMap<usize, ResponseBatch<Vec<u8>>>,
    next_batch_id: usize,
    round_ops: HashMap<OpId, PeerExchangeOp>,
    waiters: HashMap<OpId, oneshot::Sender<()>>,
}

/// Ends the whole operation and wakes its waiter.
fn finish_peer_exchange_op(px: &mut PeerExchangeState, op_id: OpId) {
    px.round_ops.remove(&op_id);
    if let Some(tx) = px.waiters.remove(&op_id)
        && tx.send(()).is_err()
    {
        debug!(target: LOG_TARGET, ?op_id, "peer exchange receiver dropped");
    }
}

/// Connected peers that support peer exchange and are past their cooldown.
fn eligible_peer_exchange_peers(book: &PeerBook, now: Instant, cooldown: Duration) -> Vec<PeerId> {
    book.connected
        .iter()
        .filter_map(|peer_id| {
            let state = book.peers.get(peer_id)?;
            if !state.supports_peer_exchange {
                return None;
            }
            if state
                .last_peer_exchange_at
                .is_some_and(|last| now.duration_since(last) < cooldown)
            {
                return None;
            }
            Some(*peer_id)
        })
        .collect()
}

impl NodeInner {
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

    pub(super) async fn run_peer_exchange_loop(self: Arc<Self>) {
        let mut shutdown = self.shutdown_tx.subscribe();
        loop {
            let connected = self.peer_book.read().connected.len();
            let interval = if connected < self.discovery_config.peer_exchange_bootstrap_peers {
                self.discovery_config.peer_exchange_bootstrap_interval
            } else {
                self.discovery_config.peer_exchange_interval
            };

            if connected == 0 {
                debug!(target: LOG_TARGET, "skipping peer exchange: no connected peers");
                if sleep_or_shutdown(interval, &mut shutdown).await {
                    debug!(target: LOG_TARGET, "peer exchange loop shutting down");
                    break;
                }
                continue;
            }

            if connected >= self.config.connection_cap {
                debug!(target: LOG_TARGET, "skipping peer exchange: connection cap reached");
                if sleep_or_shutdown(interval, &mut shutdown).await {
                    debug!(target: LOG_TARGET, "peer exchange loop shutting down");
                    break;
                }
                continue;
            }

            debug!(target: LOG_TARGET, connected, "performing peer exchange");
            let result = tokio::select! {
                result = self.peer_exchange_rounds(self.discovery_config.peer_exchange_rounds) => result,
                should_shutdown = shutdown_changed_or_requested(&mut shutdown) => {
                    if should_shutdown {
                        debug!(target: LOG_TARGET, "peer exchange loop shutting down");
                        break;
                    }
                    continue;
                }
            };
            match result {
                Ok(()) => {}
                Err(WakuError::Cancelled) => warn!(target: LOG_TARGET, "peer exchange cancelled"),
                Err(error) => {
                    error!(target: LOG_TARGET, ?error, "peer exchange failed, stopping loop");
                    break;
                }
            }

            if sleep_or_shutdown(interval, &mut shutdown).await {
                debug!(target: LOG_TARGET, "peer exchange loop shutting down");
                break;
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
                finish_peer_exchange_op(&mut px, op_id);
                return;
            }
        }

        let now = Instant::now();
        let peers: Vec<PeerId> = {
            let book = self.peer_book.read();
            eligible_peer_exchange_peers(&book, now, self.peer_exchange_cooldown)
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
                    finish_peer_exchange_op(&mut px, op_id);
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

    pub(super) async fn handle_peer_exchange_response(
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
                    debug!(target: LOG_TARGET,
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

    pub(super) async fn finish_peer_exchange_batch(&self, batch_id: usize, enrs: Vec<Vec<u8>>) {
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
}
