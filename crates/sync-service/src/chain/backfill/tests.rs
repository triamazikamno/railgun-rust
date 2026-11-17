use super::*;

use super::super::{Address, Arc, QueryRpcPool};
use broadcaster_core::query_rpc_pool::RpcAdmission;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use super::super::logs::{FOREST_RPC_PARALLELISM, FOREST_RPC_REQUEST_BUDGET, sort_logs};
use serde_json::json;
use url::Url;

struct MockJsonRpc {
    url: Url,
    requests: Arc<AtomicUsize>,
}

#[tokio::test]
async fn archive_range_log_fetch_uses_regular_rpc_when_archive_provider_missing() {
    let mock = spawn_json_rpc_server(1);
    let mut chain = chain_config(mock.url.clone());
    chain.deployment.deployment_block = 100;
    chain.sync.archive_until_block = 150;
    chain.deployment.v2_start_block = 200;
    chain.deployment.legacy_shield_block = 250;

    let rpc = chain.rpcs.random_provider().expect("rpc provider");

    let logs = chain
        .fetch_logs_for_range(&rpc, None, 100, 120, &CancellationToken::new())
        .await
        .expect("regular RPC should be used for archive range");

    assert_eq!(logs, [] as [Log; 0]);
    assert_eq!(mock.requests.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn archive_range_reads_wait_for_archive_admission_without_fallback() {
    let regular = spawn_json_rpc_server(1);
    let archive_mock = spawn_json_rpc_server(3);
    let mut chain = chain_config(regular.url.clone());
    chain.rpcs = Arc::new(
        QueryRpcPool::new(vec![regular.url.clone()], Duration::from_secs(1)).with_pending_archive(),
    );
    chain.deployment.deployment_block = 100;
    chain.sync.archive_until_block = 150;
    chain.deployment.v2_start_block = 200;
    chain.deployment.legacy_shield_block = 250;

    let rpc = chain.rpcs.random_provider().expect("rpc provider");
    chain.archive_rpc_url = Some(archive_mock.url.clone());
    chain.archive_rpc_http_client = Some(reqwest::Client::new());
    // The add-chain client cannot reach anything, so served archive reads
    // prove the archive client carries them.
    let unreachable = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all("http://127.0.0.1:1").expect("proxy"))
        .build()
        .expect("unreachable client");
    let archive = chain
        .build_archive_provider(Some(&unreachable))
        .await
        .expect("archive provider")
        .expect("configured archive provider");
    let cancel = CancellationToken::new();

    let logs = chain
        .fetch_logs_for_range(&rpc, Some(&archive), 100, 120, &cancel)
        .await;
    assert!(
        matches!(logs, Err(ChainError::ArchiveRpcUnverified)),
        "{logs:?}"
    );
    let hash = chain
        .fetch_block_hash(&rpc.provider, Some(&archive), 120)
        .await;
    assert!(
        matches!(hash, Err(ChainError::ArchiveRpcUnverified)),
        "{hash:?}"
    );
    let timestamp = chain
        .fetch_block_timestamp(&rpc.provider, Some(&archive), 120)
        .await;
    assert!(
        matches!(timestamp, Err(ChainError::ArchiveRpcUnverified)),
        "{timestamp:?}"
    );
    assert_eq!(archive_mock.requests.load(Ordering::SeqCst), 0);
    assert_eq!(regular.requests.load(Ordering::SeqCst), 0);

    chain.rpcs.set_archive_admission(RpcAdmission::Admitted);
    let logs = chain
        .fetch_logs_for_range(&rpc, Some(&archive), 100, 120, &cancel)
        .await
        .expect("admitted archive serves archive-range logs");
    assert_eq!(logs, [] as [Log; 0]);
    let hash = chain
        .fetch_block_hash(&rpc.provider, Some(&archive), 120)
        .await
        .expect("admitted archive serves archive-range block hash");
    assert_eq!(hash, None);
    let timestamp = chain
        .fetch_block_timestamp(&rpc.provider, Some(&archive), 120)
        .await
        .expect("admitted archive serves archive-range block timestamp");
    assert_eq!(timestamp, None);
    assert_eq!(archive_mock.requests.load(Ordering::SeqCst), 3);
    assert_eq!(regular.requests.load(Ordering::SeqCst), 0);
}

fn chain_config(rpc_url: Url) -> ChainConfig {
    ChainConfig {
        deployment: broadcaster_core::deployment::RailgunDeployment {
            chain_id: 1,
            contract: Address::ZERO,
            deployment_block: 1,
            v2_start_block: 1,
            legacy_shield_block: 1,
            relay_adapt_contract: None,
            relay_adapt_7702_contract: Address::ZERO,
            relay_adapt_7702_delegates: &[],
            relay_adapt_history: &[],
        },
        sync: crate::RailgunSyncOptions {
            archive_until_block: 0,
            block_range: 100,
            indexed_wallet_block_range: 100,
            poll_interval: Duration::from_secs(1),
            quick_sync_endpoint: None,
            indexed_artifact_source: None,
            anchor_interval: 100,
            anchor_retention: 2,
        },
        rpcs: Arc::new(QueryRpcPool::new(vec![rpc_url], Duration::from_secs(1))),
        archive_rpc_url: None,
        archive_rpc_http_client: None,
        block_time: Duration::from_secs(12),
        finality_depth: 1,
        http_client: reqwest::Client::new(),
        progress_tx: None,
        poi_submission_routes: None,
    }
}

fn spawn_json_rpc_server(expected_requests: usize) -> MockJsonRpc {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock RPC");
    let url = Url::parse(&format!(
        "http://{}",
        listener.local_addr().expect("local addr")
    ))
    .expect("mock RPC URL");
    let requests = Arc::new(AtomicUsize::new(0));
    let server_requests = Arc::clone(&requests);
    thread::spawn(move || {
        for stream in listener.incoming().take(expected_requests) {
            let mut stream = stream.expect("accept mock RPC request");
            let mut buffer = [0_u8; 8192];
            let read = stream.read(&mut buffer).expect("read mock RPC request");
            assert!(read > 0, "mock RPC connection closed before request");
            server_requests.fetch_add(1, Ordering::SeqCst);

            let request = String::from_utf8_lossy(&buffer[..read]);
            let body_start = request.find("\r\n\r\n").map_or(read, |index| index + 4);
            let request_body = &request[body_start..];
            let parsed = serde_json::from_str::<serde_json::Value>(request_body).ok();
            let id = parsed
                .as_ref()
                .and_then(|value| value.get("id").cloned())
                .unwrap_or_else(|| json!(1));
            let method = parsed
                .as_ref()
                .and_then(|value| value.get("method"))
                .and_then(serde_json::Value::as_str);
            // An unknown block reads as `null`; every other call gets no logs.
            let result = if method == Some("eth_getBlockByNumber") {
                serde_json::Value::Null
            } else {
                json!([])
            };
            let body = json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": result,
            })
            .to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body,
            );
            stream
                .write_all(response.as_bytes())
                .expect("write mock RPC response");
        }
    });

    MockJsonRpc { url, requests }
}

#[test]
fn log_request_estimate_uses_widest_learned_span_without_requests() {
    let servers = [
        spawn_rpc_handler(log_rpc_handler(2000, Vec::new(), |_, _| None)),
        spawn_rpc_handler(log_rpc_handler(2000, Vec::new(), |_, _| None)),
    ];
    let mut chain = pool_chain_config(servers.iter().map(|server| server.url.clone()));

    assert_eq!(
        chain.estimate_log_requests(1001, 1400),
        4,
        "unlimited providers use block_range"
    );
    chain.rpcs.narrow_log_span(LogSpanEndpoint::Provider(0), 25);
    assert_eq!(
        chain.estimate_log_requests(1001, 1400),
        4,
        "the wider provider's span counts"
    );
    chain.rpcs.narrow_log_span(LogSpanEndpoint::Provider(1), 25);
    assert_eq!(chain.estimate_log_requests(1001, 1400), 16);

    // Legacy commitments, transact, legacy shield, modern shield and
    // nullifiers each need their own filter.
    chain.deployment.v2_start_block = 1100;
    chain.deployment.legacy_shield_block = 1200;
    let estimate = chain.estimate_log_requests(1001, 1400);
    assert_eq!(estimate, 16 * 5);
    assert!(estimate > FOREST_RPC_REQUEST_BUDGET);
    for server in &servers {
        assert!(server.bodies().is_empty(), "estimation issues no request");
    }
}

#[tokio::test]
async fn parallel_log_fetch_matches_one_provider_in_order_and_skips_lagging_provider() {
    let log_blocks = vec![1001, 1050, 1100, 1101, 1234, 1333, 1480, 1555, 1600];
    let serving = (0..3)
        .map(|_| {
            spawn_rpc_handler(delayed(
                "eth_getLogs",
                Duration::from_millis(25),
                log_rpc_handler(2000, log_blocks.clone(), |_, _| None),
            ))
        })
        .collect::<Vec<_>>();
    // Head 1600 less finality depth 1 does not cover block 1600.
    let lagging = spawn_rpc_handler(log_rpc_handler(1600, log_blocks.clone(), |_, _| None));
    let chain = pool_chain_config(
        serving
            .iter()
            .chain([&lagging])
            .map(|server| server.url.clone()),
    );

    let mut pages = Vec::new();
    let (result, stats) = chain
        .fetch_logs_in_parallel(
            1001,
            1600,
            FOREST_RPC_PARALLELISM,
            &LogRequestBudget::new(FOREST_RPC_REQUEST_BUDGET),
            &CancellationToken::new(),
            |page| {
                pages.push(page);
                Ok(())
            },
        )
        .await;
    result.expect("parallel fetch succeeds");

    assert_eq!(
        pages.iter().map(|page| page.to_block).collect::<Vec<_>>(),
        (0..6).map(|page| 1100 + page * 100).collect::<Vec<_>>(),
        "pages arrive contiguous and in block order"
    );
    assert!(
        serving
            .iter()
            .filter(|server| server.count("eth_getLogs") > 0)
            .count()
            > 1,
        "pages are spread across providers"
    );
    assert_eq!(lagging.count("eth_blockNumber"), 1);
    assert_eq!(
        lagging.count("eth_getLogs"),
        0,
        "lagging provider fetches no page"
    );
    assert_eq!(stats.eligible_providers, 3);

    // With one slot, the lagging provider listed first hands its slot to
    // the next provider.
    let lagging_first = pool_chain_config(
        std::iter::once(&lagging)
            .chain(&serving)
            .map(|server| server.url.clone()),
    );
    let mut lagging_first_pages = 0;
    let (result, _) = lagging_first
        .fetch_logs_in_parallel(
            1001,
            1600,
            1,
            &LogRequestBudget::new(FOREST_RPC_REQUEST_BUDGET),
            &CancellationToken::new(),
            |_| {
                lagging_first_pages += 1;
                Ok(())
            },
        )
        .await;
    result.expect("a later provider fetches every page");
    assert_eq!(lagging_first_pages, 6);
    assert_eq!(lagging.count("eth_blockNumber"), 2);
    assert_eq!(
        lagging.count("eth_getLogs"),
        0,
        "lagging provider fetches no page"
    );

    let parallel_logs = pages
        .into_iter()
        .flat_map(|page| {
            let mut logs = page.logs;
            sort_logs(&mut logs);
            logs
        })
        .collect::<Vec<_>>();
    let single = pool_chain_config([serving[0].url.clone()]);
    let rpc = single.rpcs.random_provider().expect("rpc provider");
    let mut single_logs = single
        .fetch_logs_for_range(&rpc, None, 1001, 1600, &CancellationToken::new())
        .await
        .expect("single-provider fetch succeeds");
    sort_logs(&mut single_logs);
    assert_eq!(single_logs.len(), log_blocks.len());
    assert_eq!(parallel_logs, single_logs);
}

#[tokio::test]
async fn failed_log_page_is_retried_elsewhere_and_diagnostics_hide_endpoints() {
    let events = CapturedEvents::default();
    let _guard = events.capture();
    let log_blocks = vec![1010, 1150, 1290];
    let refused_port = TcpListener::bind("127.0.0.1:0")
        .expect("bind refused port")
        .local_addr()
        .expect("local addr")
        .port();
    let failing = spawn_rpc_handler(log_rpc_handler(2000, log_blocks.clone(), |_, _| {
        Some(json!({ "code": -32000, "message": "header not found" }))
    }));
    // The slow head lets the failing provider take the first page.
    let working = spawn_rpc_handler(delayed(
        "eth_blockNumber",
        Duration::from_millis(200),
        log_rpc_handler(2000, log_blocks.clone(), |_, _| None),
    ));
    let chain = pool_chain_config([
        credential_url(refused_port),
        failing.url.clone(),
        working.url.clone(),
    ]);

    let mut pages = Vec::new();
    let (result, stats) = chain
        .fetch_logs_in_parallel(
            1001,
            1300,
            FOREST_RPC_PARALLELISM,
            &LogRequestBudget::new(FOREST_RPC_REQUEST_BUDGET),
            &CancellationToken::new(),
            |page| {
                pages.push((page.to_block, page.logs.len()));
                Ok(())
            },
        )
        .await;
    result.expect("working provider fetches every page");

    assert_eq!(pages, vec![(1100, 1), (1200, 1), (1300, 1)]);
    assert_eq!(failing.count("eth_getLogs"), 1);
    assert_eq!(stats.retries, 1, "the failed page is retried");
    assert_eq!(
        stats
            .providers
            .iter()
            .map(|provider| (provider.rpc_index, provider.pages))
            .collect::<Vec<_>>(),
        vec![(0, 0), (1, 0), (2, 3)]
    );
    assert_eq!(
        chain
            .rpcs
            .available_providers()
            .iter()
            .map(|rpc| rpc.index)
            .collect::<Vec<_>>(),
        vec![2],
        "failing providers cool down"
    );

    let finished = events.find("parallel log range fetch finished");
    assert_eq!(
        finished.get("outcome").map(String::as_str),
        Some("complete")
    );
    assert_eq!(finished.get("retries").map(String::as_str), Some("1"));
    assert!(finished.contains_key("providers"));
    events.find("parallel log fetch provider failed; its page returns to the queue");
    for event in events.events() {
        for value in event.values() {
            assert!(
                ["secret", "user", "apikey", "127.0.0.1"]
                    .iter()
                    .all(|needle| !value.contains(needle)),
                "log value {value:?} exposes an endpoint"
            );
        }
    }

    let only_failing = pool_chain_config([failing.url.clone()]);
    let mut delivered = 0;
    let (result, _) = only_failing
        .fetch_logs_in_parallel(
            1001,
            1300,
            FOREST_RPC_PARALLELISM,
            &LogRequestBudget::new(FOREST_RPC_REQUEST_BUDGET),
            &CancellationToken::new(),
            |_| {
                delivered += 1;
                Ok(())
            },
        )
        .await;
    assert!(
        matches!(result, Err(ChainError::NoHealthyRpc)),
        "{result:?}"
    );
    assert_eq!(delivered, 0);
}

#[tokio::test]
async fn parallel_log_fetch_stops_when_narrowing_exceeds_request_budget() {
    let server = spawn_rpc_handler(log_rpc_handler(2000, Vec::new(), |from, to| {
        (to - from + 1 > 25).then(
            || json!({ "code": -32000, "message": "log query range must not exceed 25 blocks" }),
        )
    }));
    let chain = pool_chain_config([server.url.clone()]);
    assert_eq!(chain.estimate_log_requests(1001, 1200), 2);

    let budget = LogRequestBudget::new(4);
    let (result, stats) = chain
        .fetch_logs_in_parallel(
            1001,
            1200,
            4,
            &budget,
            &CancellationToken::new(),
            |_| Ok(()),
        )
        .await;

    assert!(
        matches!(result, Err(ChainError::LogRequestBudgetExceeded(4))),
        "{result:?}"
    );
    assert_eq!(server.count("eth_getLogs"), 4);
    assert_eq!(stats.get_logs_requests, 4);
    assert_eq!(
        chain.rpcs.available_providers().len(),
        1,
        "exceeding the budget is not a provider failure"
    );
}

#[tokio::test]
async fn cancelled_parallel_log_fetch_issues_no_further_requests() {
    let (started_tx, mut started) = tokio::sync::mpsc::unbounded_channel();
    let (release_first, first_gate) = std::sync::mpsc::channel::<()>();
    let (release_second, second_gate) = std::sync::mpsc::channel::<()>();
    let servers = [
        spawn_rpc_handler(gated_get_logs(started_tx.clone(), first_gate)),
        spawn_rpc_handler(gated_get_logs(started_tx, second_gate)),
    ];
    let chain = pool_chain_config(servers.iter().map(|server| server.url.clone()));
    let cancel = CancellationToken::new();
    let budget = LogRequestBudget::new(FOREST_RPC_REQUEST_BUDGET);

    let fetch =
        chain.fetch_logs_in_parallel(1001, 1600, FOREST_RPC_PARALLELISM, &budget, &cancel, |_| {
            Ok(())
        });
    let cancel_once_both_fetch = async {
        for _ in 0..2 {
            started.recv().await.expect("page request started");
        }
        cancel.cancel();
    };
    let ((result, _), ()) = tokio::join!(fetch, cancel_once_both_fetch);
    assert!(
        matches!(result, Err(ChainError::LogFetchCancelled)),
        "{result:?}"
    );

    // Released servers answer anything queued behind the held requests.
    drop((release_first, release_second));
    tokio::time::sleep(Duration::from_millis(100)).await;
    for server in &servers {
        assert_eq!(server.count("eth_blockNumber"), 1);
        assert_eq!(
            server.count("eth_getLogs"),
            1,
            "no request after cancellation"
        );
    }
    assert_eq!(
        chain.rpcs.available_providers().len(),
        2,
        "cancellation marks no provider bad"
    );
}

fn pool_chain_config(urls: impl IntoIterator<Item = Url>) -> ChainConfig {
    let urls = urls.into_iter().collect::<Vec<_>>();
    let mut chain = chain_config(urls[0].clone());
    chain.rpcs = Arc::new(QueryRpcPool::new(urls, Duration::from_mins(1)));
    chain
}

fn credential_url(port: u16) -> Url {
    Url::parse(&format!(
        "http://user:secret@127.0.0.1:{port}/?apikey=secret"
    ))
    .expect("mock RPC URL")
}

struct HandlerRpc {
    url: Url,
    bodies: Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
}

impl HandlerRpc {
    fn bodies(&self) -> Vec<serde_json::Value> {
        self.bodies.lock().expect("request bodies lock").clone()
    }

    fn count(&self, method: &str) -> usize {
        self.bodies()
            .iter()
            .filter(|body| body["method"] == method)
            .count()
    }
}

/// Serves every request, one connection at a time, with `handler`, which
/// maps the request body to the response's `result` or `error` member.
/// The URL carries credentials in its userinfo and query.
fn spawn_rpc_handler(
    handler: impl Fn(&serde_json::Value) -> serde_json::Value + Send + 'static,
) -> HandlerRpc {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock RPC");
    let url = credential_url(listener.local_addr().expect("local addr").port());
    let bodies = Arc::new(std::sync::Mutex::new(Vec::new()));
    let server_bodies = Arc::clone(&bodies);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let Some(body) = read_json_rpc_body(&mut stream) else {
                continue;
            };
            server_bodies
                .lock()
                .expect("request bodies lock")
                .push(body.clone());
            let mut response = handler(&body);
            response["jsonrpc"] = json!("2.0");
            response["id"] = body["id"].clone();
            let response = response.to_string();
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                response.len(),
            );
        }
    });
    HandlerRpc { url, bodies }
}

fn read_json_rpc_body(stream: &mut std::net::TcpStream) -> Option<serde_json::Value> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = stream.read(&mut buffer).ok().filter(|read| *read > 0)?;
        request.extend_from_slice(&buffer[..read]);
        let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
            continue;
        };
        let body_start = header_end + 4;
        let content_length = String::from_utf8_lossy(&request[..header_end])
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);
        if request.len() >= body_start + content_length {
            return serde_json::from_slice(&request[body_start..body_start + content_length]).ok();
        }
    }
}

fn hex_quantity(value: &serde_json::Value) -> u64 {
    let hex = value.as_str().expect("hex quantity");
    u64::from_str_radix(hex.trim_start_matches("0x"), 16).expect("hex quantity")
}

/// Answers `eth_blockNumber` with `head`, and `eth_getLogs` with one log
/// per listed block in the requested range unless `reject` returns an
/// error for that range.
fn log_rpc_handler(
    head: u64,
    log_blocks: Vec<u64>,
    reject: impl Fn(u64, u64) -> Option<serde_json::Value> + Send + 'static,
) -> impl Fn(&serde_json::Value) -> serde_json::Value + Send + 'static {
    move |request: &serde_json::Value| match request["method"].as_str() {
        Some("eth_blockNumber") => json!({ "result": format!("{head:#x}") }),
        Some("eth_getLogs") => {
            let from_block = hex_quantity(&request["params"][0]["fromBlock"]);
            let to_block = hex_quantity(&request["params"][0]["toBlock"]);
            reject(from_block, to_block).map_or_else(
                || {
                    let logs = log_blocks
                        .iter()
                        .filter(|block| (from_block..=to_block).contains(block))
                        .map(|block| {
                            json!({
                                "address": format!("{:#x}", Address::ZERO),
                                "topics": [],
                                "data": "0x",
                                "blockHash": format!("{:#x}", FixedBytes::<32>::from([0x11; 32])),
                                "blockNumber": format!("{block:#x}"),
                                "transactionHash": format!("{:#x}", FixedBytes::<32>::from([0x33; 32])),
                                "transactionIndex": "0x0",
                                "logIndex": "0x0",
                                "removed": false,
                            })
                        })
                        .collect::<Vec<_>>();
                    json!({ "result": logs })
                },
                |error| json!({ "error": error }),
            )
        }
        _ => json!({ "error": { "code": -32601, "message": "method not found" } }),
    }
}

/// Delays every `method` request by `delay` before `serve` answers it.
fn delayed(
    method: &'static str,
    delay: Duration,
    serve: impl Fn(&serde_json::Value) -> serde_json::Value + Send + 'static,
) -> impl Fn(&serde_json::Value) -> serde_json::Value + Send + 'static {
    move |request: &serde_json::Value| {
        if request["method"] == method {
            thread::sleep(delay);
        }
        serve(request)
    }
}

/// Reports each `eth_getLogs` request on `started` and holds it until
/// `release` yields or disconnects.
fn gated_get_logs(
    started: tokio::sync::mpsc::UnboundedSender<()>,
    release: std::sync::mpsc::Receiver<()>,
) -> impl Fn(&serde_json::Value) -> serde_json::Value + Send + 'static {
    let serve = log_rpc_handler(2000, Vec::new(), |_, _| None);
    move |request: &serde_json::Value| {
        if request["method"] == "eth_getLogs" {
            let _ = started.send(());
            let _ = release.recv();
        }
        serve(request)
    }
}

/// Records `sync_service` tracing events as field-name to value maps.
#[derive(Clone, Default)]
struct CapturedEvents(Arc<std::sync::Mutex<Vec<BTreeMap<String, String>>>>);

impl CapturedEvents {
    fn capture(&self) -> CaptureGuard {
        // With one registered dispatcher, tracing-core resolves a callsite
        // first hit on another test thread against that thread's empty
        // default and caches it as disabled. A second live dispatcher keeps
        // interest computed across every registered dispatcher.
        let registered = tracing::Dispatch::new(CaptureSubscriber(self.clone()));
        CaptureGuard {
            _default: tracing::subscriber::set_default(CaptureSubscriber(self.clone())),
            _registered: registered,
        }
    }

    fn events(&self) -> Vec<BTreeMap<String, String>> {
        self.0.lock().expect("captured events lock").clone()
    }

    fn find(&self, message: &str) -> BTreeMap<String, String> {
        self.events()
            .into_iter()
            .find(|event| event.get("message").is_some_and(|value| value == message))
            .unwrap_or_else(|| panic!("missing {message:?} event"))
    }
}

struct CaptureGuard {
    _default: tracing::subscriber::DefaultGuard,
    _registered: tracing::Dispatch,
}

struct CaptureSubscriber(CapturedEvents);

struct CapturedFields<'a>(&'a mut BTreeMap<String, String>);

impl tracing::field::Visit for CapturedFields<'_> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.insert(field.name().to_owned(), value.to_owned());
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }
}

impl tracing::Subscriber for CaptureSubscriber {
    fn register_callsite(
        &self,
        _metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }

    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target().starts_with("sync_service")
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = BTreeMap::new();
        event.record(&mut CapturedFields(&mut fields));
        self.0.0.lock().expect("captured events lock").push(fields);
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}
