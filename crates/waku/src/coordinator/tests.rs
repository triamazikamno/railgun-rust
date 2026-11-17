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
        dns_records: RwLock::new(Vec::new()),
        peer_capabilities_changed: Notify::new(),
        local_peer_id: PeerId::random(),
        tasks: Mutex::new(crate::tasks::task_tracker().1),
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
async fn dns_records_exclude_peer_exchange_peers_and_identify_addrs() {
    let node = test_node(DiscoveryConfig::default());
    let (tree_peer, learned_peer) = (PeerId::random(), PeerId::random());
    let peer = |peer_id, n| discovery::DiscoveredPeer {
        peer_id,
        addrs: vec![peer_addr(n)],
    };

    node.record_dns_round(vec![peer(tree_peer, 1)]);
    node.apply_discovered_peers(vec![peer(learned_peer, 2)], PeerSource::Learned);
    node.handle_transport_event(TransportEvent::ConnectionEstablished { peer_id: tree_peer })
        .await;
    node.handle_transport_event(TransportEvent::IdentifyReceived {
        peer_id: tree_peer,
        protocols: Vec::new(),
        addrs: vec![peer_addr(3)],
    })
    .await;

    {
        let book = node.peer_book.read();
        assert!(book.peers.contains_key(&learned_peer));
        assert!(book.peers[&tree_peer].addrs.contains(&peer_addr(3)));
    }
    let records = node.dns_records.read();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].peer_id, tree_peer);
    assert_eq!(records[0].addrs, vec![peer_addr(1)]);
}

#[tokio::test]
async fn wait_ready_needs_lightpush_and_filter_peers() {
    let node = test_node(DiscoveryConfig::default());
    let (lightpush_peer, filter_peer) = (PeerId::random(), PeerId::random());
    let identify = |peer_id, codec: &str| TransportEvent::IdentifyReceived {
        peer_id,
        protocols: vec![codec.to_string()],
        addrs: Vec::new(),
    };
    for peer_id in [lightpush_peer, filter_peer] {
        node.handle_transport_event(TransportEvent::ConnectionEstablished { peer_id })
            .await;
    }
    node.handle_transport_event(identify(
        lightpush_peer,
        protocols::lightpush::LIGHTPUSH_V3_CODEC,
    ))
    .await;

    assert!(matches!(
        node.wait_ready(Duration::from_millis(200)).await,
        Err(WakuError::NoPeersAvailable)
    ));

    // `join!` polls the wait first, so it is already waiting when Identify arrives.
    let (ready, ()) = tokio::join!(
        node.wait_ready(Duration::from_secs(5)),
        node.handle_transport_event(identify(
            filter_peer,
            protocols::filter::FILTER_SUBSCRIBE_CODEC,
        )),
    );
    assert!(ready.is_ok(), "{ready:?}");

    node.shutdown();
    assert!(matches!(
        node.wait_ready(Duration::from_secs(5)).await,
        Err(WakuError::Cancelled)
    ));
}

fn quiet_config() -> WakuConfig {
    let mut config = WakuConfig::default();
    config.discovery.enr_trees.clear();
    config
}

#[tokio::test]
async fn nodes_have_distinct_peer_ids_and_own_tor_providers() {
    use std::sync::atomic::AtomicUsize;

    let tor_node = |dials: Arc<AtomicUsize>| {
        let provider: crate::config::WakuTorClientProvider = Arc::new(move || {
            dials.fetch_add(1, Ordering::SeqCst);
            None::<crate::config::WakuTorClient>
        });
        let mut config = quiet_config();
        config.network = crate::config::WakuNetworkConfig::tor_with_client_provider(
            provider,
            reqwest::Client::new(),
        );
        WakuNode::spawn(config).expect("spawn Tor Waku node")
    };
    let (a_dials, b_dials) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let a = tor_node(Arc::clone(&a_dials));
    let b = tor_node(Arc::clone(&b_dials));

    a.add_additional_peers(vec![discovery::DiscoveredPeer {
        peer_id: PeerId::random(),
        addrs: vec![addr("/ip4/127.0.0.1/tcp/9")],
    }]);
    tokio::time::timeout(Duration::from_secs(5), async {
        while a_dials.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("node A dials through its own Tor provider");

    assert_eq!(b_dials.load(Ordering::SeqCst), 0);
    assert_ne!(a.local_peer_id(), b.local_peer_id());
    for node in [a, b] {
        node.shutdown_and_wait(Duration::from_secs(5))
            .await
            .expect("node shuts down");
    }
}

#[tokio::test]
async fn shutdown_and_wait_ends_pending_dial() {
    use std::io::{ErrorKind, Read};
    use std::net::{TcpListener, TcpStream};

    async fn accept(
        listener: &TcpListener,
        bound: Duration,
    ) -> Result<TcpStream, tokio::time::error::Elapsed> {
        tokio::time::timeout(bound, async {
            loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(error) => panic!("accept failed: {error}"),
                }
            }
        })
        .await
    }

    // The listener accepts and stays silent, so the dial waits in its handshake.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let port = listener.local_addr().expect("listener address").port();

    let node = WakuNode::spawn(quiet_config()).expect("spawn Waku node");
    node.add_additional_peers(vec![discovery::DiscoveredPeer {
        peer_id: PeerId::random(),
        addrs: vec![addr(&format!("/ip4/127.0.0.1/tcp/{port}"))],
    }]);
    let mut socket = accept(&listener, Duration::from_secs(5))
        .await
        .expect("node dials the listener");

    node.shutdown_and_wait(Duration::from_secs(5))
        .await
        .expect("shutdown completes");

    // The dialer's handshake bytes may precede EOF; a timeout means the dial is still open.
    socket.set_nonblocking(false).expect("blocking socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("read timeout");
    let mut buf = [0_u8; 256];
    loop {
        match socket.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) => {
                assert!(
                    !matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut),
                    "pending dial outlived shutdown"
                );
                break;
            }
        }
    }
    assert!(
        accept(&listener, Duration::from_millis(500)).await.is_err(),
        "no dial starts after shutdown"
    );
    tokio::time::timeout(
        Duration::from_millis(100),
        node.shutdown_and_wait(Duration::from_secs(5)),
    )
    .await
    .expect("repeated shutdown returns immediately")
    .expect("repeated shutdown succeeds");
}

#[tokio::test]
#[ignore = "runs peer exchange against the live Waku fleet"]
async fn live_peer_exchange_responses_fit_request_and_frame() {
    let transport = crate::transport::Transport::new(
        &NodeConfig::default(),
        &crate::config::WakuNetworkConfig::direct(),
        crate::tasks::task_tracker().0,
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
