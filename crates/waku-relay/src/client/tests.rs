use super::{
    CACHE_SIZE, Client, ClientConfig, ClientError, DEFAULT_CLUSTER_ID, DEFAULT_SHARD_ID,
    HistoryFuture, NWAKU_MAX_POLL_BYTES, NwakuMessagesPoll, RelayForwarder, RelayMessageOutcome,
    StoreHistory, add_tor_doh_fallback, handle_relay_message, is_fee_content_topic,
    poll_nwaku_messages, relay_shard_pubsub_path, relay_sink_is_closed, wait_for_relay_sink_closed,
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
    tokio::spawn(
        RelayForwarder::new(sink_tx, vec![FEE_TOPIC.to_string()], None, Some(store)).run(fleet_rx),
    );
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

    assert_eq!(waku.discovery.doh_fallback_endpoints, [] as [String; 0]);
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
            .tasks
            .try_lock()
            .expect("no shutdown in progress")
            .first()
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

#[tokio::test]
async fn client_shutdown_stops_nwaku_polling() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n[]";

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind nwaku endpoint");
    let address = listener.local_addr().expect("read listener address");
    let requests = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    // Every subscription request after the first is handed to the test unanswered.
    let (held_tx, held_rx) = std_mpsc::channel();
    let server = thread::spawn({
        let (requests, stop) = (Arc::clone(&requests), Arc::clone(&stop));
        move || {
            let mut subscriptions = 0;
            for stream in listener.incoming() {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(mut stream) = stream else { continue };
                requests.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0_u8; 4096];
                let len = stream.read(&mut buf).unwrap_or(0);
                if buf[..len].starts_with(b"POST /relay/v1/subscriptions") {
                    subscriptions += 1;
                    if subscriptions > 1 {
                        let _ = held_tx.send(stream);
                        continue;
                    }
                }
                let _ = stream.write_all(RESPONSE);
            }
        }
    });
    let cfg = ClientConfig {
        nwaku_url: Some(format!("http://{address}")),
        dns_enr_trees: Some(Vec::new()),
        max_peers: Some(0),
        ..Default::default()
    };
    let client = Arc::new(Client::new(&cfg).expect("client starts"));
    let _messages = client
        .subscribe(vec!["/railgun/v2/0-1-transact/json".to_string()])
        .await
        .expect("subscribe");

    // The subscription request plus the first poll.
    timeout(Duration::from_secs(5), async {
        while requests.load(Ordering::SeqCst) < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("client polls nwaku");

    // A subscription whose nwaku request is in flight when shutdown runs.
    let late = tokio::spawn({
        let client = Arc::clone(&client);
        async move {
            client
                .subscribe(vec!["/railgun/v2/0-1-fees/json".to_string()])
                .await
        }
    });
    let mut held = timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(stream) = held_rx.try_recv() {
                break stream;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("late subscription reaches nwaku");

    client
        .shutdown(Duration::from_secs(5))
        .await
        .expect("client shuts down");
    let _ = held.write_all(RESPONSE);
    drop(held);
    let late = timeout(Duration::from_secs(5), late)
        .await
        .expect("late subscription finishes")
        .expect("late subscription does not panic");
    assert!(
        late.is_err(),
        "a subscription finishing after shutdown starts no forwarding"
    );
    let after_shutdown = requests.load(Ordering::SeqCst);
    // Longer than the 2 s poll interval, with the receiver still alive.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(requests.load(Ordering::SeqCst), after_shutdown);
    assert!(
        client
            .subscribe(vec!["/railgun/v2/0-1-transact/json".to_string()])
            .await
            .is_err(),
        "a shut-down client starts no new subscription"
    );
    client
        .shutdown(Duration::from_secs(5))
        .await
        .expect("repeated shutdown succeeds");

    stop.store(true, Ordering::SeqCst);
    drop(std::net::TcpStream::connect(address));
    server.join().expect("nwaku endpoint thread exits");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_waits_for_tasks_despite_cancelled_and_overlapping_calls() {
    let client = Client {
        http_client: reqwest::Client::new(),
        nwaku_request_timeout: Duration::from_secs(1),
        nwaku_url: None,
        pubsub_path: relay_shard_pubsub_path(DEFAULT_CLUSTER_ID, DEFAULT_SHARD_ID),
        waku_fleet: None,
        direct_peers: Vec::new(),
        tasks: tokio::sync::Mutex::new(Vec::new()),
        network_mode: super::RelayNetworkMode::Direct,
        disabled_reason: None,
    };
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = std_mpsc::channel::<()>();
    // Blocks its worker without an await point, so abort cannot end it until released.
    client.tasks.lock().await.push(tokio::spawn(async move {
        let _ = started_tx.send(());
        let _ = release_rx.recv();
    }));
    started_rx.await.expect("worker started");
    let wait = Duration::from_millis(200);

    // Boxed so that dropping it cancels the call.
    let mut first = Box::pin(client.shutdown(Duration::from_secs(1)));
    assert!(
        timeout(wait, &mut first).await.is_err(),
        "worker still runs"
    );
    assert!(
        timeout(wait, client.shutdown(Duration::from_secs(1)))
            .await
            .is_err(),
        "an overlapping call must not return before the worker ends"
    );
    // Cancel the first call while the worker still runs.
    drop(first);
    let mut last = Box::pin(client.shutdown(Duration::from_secs(1)));
    assert!(
        timeout(wait, &mut last).await.is_err(),
        "a call after cancelled ones must still wait for the worker"
    );

    release_tx.send(()).expect("worker waits for release");
    timeout(Duration::from_secs(2), last)
        .await
        .expect("shutdown completes once the worker ends")
        .expect("shutdown succeeds");
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
        direct_peers: Vec::new(),
        tasks: tokio::sync::Mutex::new(Vec::new()),
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
    let nwaku = NwakuMessagesPoll {
        url,
        http: reqwest::Client::new(),
        request_timeout: Duration::from_secs(10),
    };
    let topics = [FEE_TOPIC.to_string()];
    let mut cache = LruCache::new(CACHE_SIZE);
    let (sink_tx, mut sink_rx) = mpsc::channel(8);

    assert!(poll_nwaku_messages(&nwaku, &topics, &mut cache, &sink_tx).await);
    assert!(sink_rx.try_recv().is_err());

    assert!(poll_nwaku_messages(&nwaku, &topics, &mut cache, &sink_tx).await);
    assert_eq!(sink_rx.try_recv(), Ok(fee_message(2)));
    server.join().expect("nwaku endpoint thread exits");
}
