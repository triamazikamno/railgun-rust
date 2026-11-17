use super::*;

#[test]
fn log_range_limit_classifies_only_observed_provider_rejections() {
    let block_span = |max_blocks| Some(LogRangeLimit::BlockSpan { max_blocks });
    for (code, message, expected) in [
        (
            -32001,
            "Block range too large: maximum allowed is 50 blocks",
            block_span(Some(50)),
        ),
        (
            -32000,
            "log query range must not exceed 25 blocks",
            block_span(Some(25)),
        ),
        (
            -32000,
            "eth_getLogs is limited to 0 - 50 blocks range",
            block_span(Some(50)),
        ),
        (
            35,
            "ranges over 10000 blocks are not supported on freemium",
            block_span(Some(10_000)),
        ),
        (
            -32600,
            "You can make eth_getLogs requests with up to a 10 block range. Based on your parameters, this block range should work: [0x1e4a1c8e, 0x1e4a1c97]",
            block_span(Some(10)),
        ),
        (
            -32005,
            "query returned more than 10000 results",
            Some(LogRangeLimit::ResultSize),
        ),
        (
            -32005,
            "Query returned more than 10000 results. Try with this block range [0x1, 0x2].",
            Some(LogRangeLimit::ResultSize),
        ),
        (
            -32000,
            "log query range must not exceed the plan's blocks",
            block_span(None),
        ),
        (-32000, "header not found", None),
    ] {
        assert_eq!(
            rpc_error_response(code, message).log_range_limit(),
            expected,
            "{message}"
        );
    }

    // A cancelled log fetch is not an endpoint failure.
    assert!(!ChainError::LogFetchCancelled.should_mark_rpc_unhealthy());
    assert!(matches!(
        WalletStartupSyncError::from(ChainError::LogFetchCancelled),
        WalletStartupSyncError::Cancelled
    ));
    // An unverified archive endpoint says nothing about the regular endpoint.
    assert!(!ChainError::ArchiveRpcUnverified.should_mark_rpc_unhealthy());
}

#[tokio::test]
async fn startup_and_chain_errors_without_url_remove_endpoint_from_display() {
    use alloy_provider::Provider as _;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind unused port");
    let port = listener.local_addr().expect("listener addr").port();
    drop(listener);
    let url = Url::parse(&format!("http://127.0.0.1:{port}/key-abc")).expect("rpc url");
    let squid_err = reqwest::Client::new()
        .get(url.as_str())
        .send()
        .await
        .expect_err("closed port refuses the request");
    let err = WalletStartupSyncError::Indexed(merkletree::errors::SyncError::Request(squid_err));

    let unredacted = err.to_string();
    assert!(unredacted.contains("key-abc"), "{unredacted}");
    let redacted = err.without_url().to_string();
    assert!(
        !redacted.contains("key-abc") && !redacted.contains("127.0.0.1"),
        "{redacted}"
    );

    let rpcs = QueryRpcPool::new(vec![url], Duration::from_secs(1));
    let rpc = rpcs.random_provider().expect("rpc provider");
    let err = ChainError::from(
        rpc.provider
            .get_block_number()
            .await
            .expect_err("closed port refuses the request"),
    );

    let unredacted = err.to_string();
    assert!(unredacted.contains("key-abc"), "{unredacted}");
    let redacted = err.without_url().to_string();
    assert!(
        !redacted.contains("key-abc") && !redacted.contains("127.0.0.1"),
        "{redacted}"
    );
}

#[tokio::test]
async fn log_fetch_narrows_to_endpoint_span_limit_and_reuses_it() {
    let scope = test_scope();
    let logs = [1003, 1100, 1250, 1499, 1520]
        .into_iter()
        .map(|block| rpc_nullifiers_log(scope.railgun_contract, block))
        .collect::<Vec<_>>();
    let unlimited =
        JsonRpcServer::spawn_handler(log_range_rpc_handler(logs.clone(), 1600, |_, _, _| None));
    let limited =
        JsonRpcServer::spawn_handler(log_range_rpc_handler(logs, 1600, reject_spans_over_25));
    let mut unlimited_chain = log_fetch_chain(&scope, unlimited.url.clone(), 500);
    let limited_chain = log_fetch_chain(&scope, limited.url.clone(), 500);

    let expected = fetch_sorted_logs(&unlimited_chain, 1001, 1500)
        .await
        .expect("unlimited endpoint logs");
    let fetched = fetch_sorted_logs(&limited_chain, 1001, 1500)
        .await
        .expect("span-limited endpoint completes the logical range");

    assert_eq!(expected.len(), 4);
    assert_eq!(fetched, expected);
    let expected_ranges = std::iter::once((1001, 1500))
        .chain((0..20).map(|chunk| (1001 + chunk * 25, 1025 + chunk * 25)))
        .collect::<Vec<(u64, u64)>>();
    assert_eq!(
        get_logs_ranges(&limited.drain_request_bodies()),
        expected_ranges,
        "one rejected request, then contiguous spans of the parsed limit"
    );

    let second = fetch_sorted_logs(&limited_chain, 1501, 1550)
        .await
        .expect("second range on the same pool");
    assert_eq!(second.len(), 1);
    assert_eq!(
        get_logs_ranges(&limited.drain_request_bodies()),
        vec![(1501, 1525), (1526, 1550)],
        "later ranges reuse the learned span without a wide request"
    );

    // Through an archive provider, the archive learns its own span while the
    // regular provider's slot keeps the full range.
    unlimited_chain.sync.archive_until_block = 1250;
    let archive = broadcaster_core::provider::build_provider(&limited.url)
        .await
        .expect("archive provider");
    let rpc = unlimited_chain
        .rpcs
        .random_provider()
        .expect("rpc provider");
    let mut through_archive = unlimited_chain
        .fetch_logs_for_range(&rpc, Some(&archive), 1001, 1500, &CancellationToken::new())
        .await
        .expect("archive and regular providers complete the logical range");
    sort_logs(&mut through_archive);
    assert_eq!(through_archive, expected);
    assert_eq!(
        get_logs_ranges(&limited.drain_request_bodies()),
        std::iter::once((1001, 1250))
            .chain((0..10).map(|chunk| (1001 + chunk * 25, 1025 + chunk * 25)))
            .collect::<Vec<(u64, u64)>>(),
        "the archive range narrows on the archive's own rejection"
    );
    assert_eq!(
        unlimited_chain.rpcs.log_span(LogSpanEndpoint::Archive, 500),
        25
    );
    assert_eq!(
        unlimited_chain
            .rpcs
            .log_span(LogSpanEndpoint::Provider(0), 500),
        500
    );
}

#[tokio::test]
async fn log_fetch_splits_result_size_rejection_without_narrowing_span() {
    let scope = test_scope();
    let logs = [1003, 1100, 1250, 1499]
        .into_iter()
        .map(|block| rpc_nullifiers_log(scope.railgun_contract, block))
        .collect::<Vec<_>>();
    let server =
        JsonRpcServer::spawn_handler(log_range_rpc_handler(logs, 1600, |_, _, log_count| {
            (log_count > 3).then(|| rpc_error(-32005, "query returned more than 10000 results"))
        }));
    let chain = log_fetch_chain(&scope, server.url.clone(), 500);

    let fetched = fetch_sorted_logs(&chain, 1001, 1500)
        .await
        .expect("result-size rejection is split");

    assert_eq!(fetched.len(), 4);
    assert_eq!(
        get_logs_ranges(&server.drain_request_bodies()),
        vec![(1001, 1500), (1001, 1250), (1251, 1500)],
        "only the rejected request is split"
    );
    assert_eq!(
        chain.rpcs.log_span(LogSpanEndpoint::Provider(0), 500),
        500,
        "result-size rejections leave the learned span unchanged"
    );
}

#[tokio::test]
async fn log_fetch_returns_unrecognized_and_single_block_rejections() {
    let scope = test_scope();
    let events = CapturedEvents::default();
    let _guard = events.capture();
    let unrecognized =
        JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 1600, |_, _, _| {
            Some(rpc_error(-32000, "header not found"))
        }));
    let chain = log_fetch_chain(&scope, unrecognized.url.clone(), 500);

    let err = fetch_sorted_logs(&chain, 1001, 1500)
        .await
        .expect_err("unrecognized error is returned");

    assert!(matches!(err, ChainError::Rpc(_)) && err.log_range_limit().is_none());
    assert_eq!(
        get_logs_ranges(&unrecognized.drain_request_bodies()),
        vec![(1001, 1500)],
        "unrecognized errors are not retried"
    );
    assert_eq!(chain.rpcs.log_span(LogSpanEndpoint::Provider(0), 500), 500);
    let unmatched = events.find("eth_getLogs error is not a recognized range limit");
    assert_eq!(unmatched.get("code").map(String::as_str), Some("-32000"));

    let saturated =
        JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 1600, |_, _, _| {
            Some(rpc_error(-32005, "query returned more than 10000 results"))
        }));
    let chain = log_fetch_chain(&scope, saturated.url.clone(), 500);

    let err = fetch_sorted_logs(&chain, 1001, 1004)
        .await
        .expect_err("single-block rejection is an endpoint failure");

    assert_eq!(err.log_range_limit(), Some(LogRangeLimit::ResultSize));
    assert!(err.should_mark_rpc_unhealthy());
    assert_eq!(
        get_logs_ranges(&saturated.drain_request_bodies()),
        vec![(1001, 1004), (1001, 1002), (1001, 1001)]
    );
}

#[tokio::test]
async fn log_block_timestamps_request_headers_only_for_blocks_without_log_timestamps() {
    let scope = test_scope();
    let contract = scope.railgun_contract;
    let server =
        JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 1600, |_, _, _| None));
    let chain = log_fetch_chain(&scope, server.url.clone(), 100);
    let rpc = chain.rpcs.random_provider().expect("rpc provider");
    let log = |block_number, timestamp| {
        let mut log = serde_json::from_value::<Log>(rpc_nullifiers_log(contract, block_number))
            .expect("RPC log");
        log.block_timestamp = timestamp;
        log
    };
    let partial = [
        log(1003, Some(test_block_timestamp(1003))),
        log(1050, None),
        log(1060, Some(0)),
        log(1060, None),
        log(1070, Some(0)),
        log(1070, Some(test_block_timestamp(1070))),
        log(1070, None),
    ];
    let without_timestamps = [
        log(1003, None),
        log(1050, None),
        log(1060, None),
        log(1070, None),
    ];

    let from_logs = chain
        .fetch_log_block_timestamps(&rpc.provider, None, &partial)
        .await
        .expect("partial log timestamps");
    assert_eq!(
        header_blocks(&server.drain_request_bodies()),
        vec![1050, 1060],
        "missing or zero log timestamps need one header per block; a nonzero log timestamp suffices"
    );
    let from_headers = chain
        .fetch_log_block_timestamps(&rpc.provider, None, &without_timestamps)
        .await
        .expect("header timestamps");
    assert_eq!(
        header_blocks(&server.drain_request_bodies()),
        vec![1003, 1050, 1060, 1070]
    );

    assert_eq!(from_logs, from_headers);
}

#[tokio::test]
async fn wallet_startup_rpc_candidate_completes_on_span_limited_endpoint() {
    let root_dir = temp_db_root("wallet-startup-span-limited-rpc");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc = JsonRpcServer::spawn_handler(log_range_rpc_handler(
        vec![rpc_nullifiers_log_with_timestamp(
            scope.railgun_contract,
            190,
        )],
        200,
        reject_spans_over_25,
    ));
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, Arc::clone(&rpcs), None);
    chain.sync.block_range = 100;
    chain.finality_depth = 0;
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
    let mut cfg = test_wallet_config(&scope, rpc.url.clone());
    cfg.start_block = Some(1);

    let candidate = Arc::clone(&service)
        .wallet_startup_rpc_candidate(
            &cfg,
            WalletShortStartupPlan::new(1, 150, 200, 100).expect("short startup plan"),
            CancellationToken::new(),
        )
        .await
        .expect("RPC startup candidate completes through narrower requests");

    assert_eq!(candidate.applies.len(), 1);
    let WalletScanRowsPayload::Rows(rows) = &candidate.applies[0].rows.payload else {
        panic!("RPC delivery rows expected");
    };
    assert_eq!(rows.nullifiers.len(), 1);
    assert_eq!(
        rows.nullifiers[0].source.block_timestamp,
        test_block_timestamp(190)
    );
    let bodies = rpc.drain_request_bodies();
    assert_eq!(
        get_logs_ranges(&bodies),
        vec![(151, 200), (151, 175), (176, 200)],
        "the delivery range after the cursor completes through narrower requests"
    );
    assert_eq!(
        header_blocks(&bodies),
        vec![200],
        "log timestamps replace header reads; the endpoint confirmation read still runs"
    );
    assert_eq!(
        rpcs.available_providers().len(),
        1,
        "a range-limited endpoint stays eligible"
    );

    service.shutdown().await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn log_fetch_diagnostics_record_adaptation_without_endpoint_url() {
    let scope = test_scope();
    let server = JsonRpcServer::spawn_handler(log_range_rpc_handler(
        vec![
            rpc_nullifiers_log_with_timestamp(scope.railgun_contract, 1003),
            rpc_nullifiers_log(scope.railgun_contract, 1050),
        ],
        1600,
        reject_spans_over_25,
    ));
    let port = server.url.port().expect("mock RPC port");
    let credential_url = Url::parse(&format!("http://user:secret@127.0.0.1:{port}/key-abc"))
        .expect("credential-bearing RPC URL");
    let chain = log_fetch_chain(&scope, credential_url.clone(), 100);
    let rpc = chain.rpcs.random_provider().expect("rpc provider");
    let events = CapturedEvents::default();
    let guard = events.capture();

    let logs = chain
        .fetch_logs_for_range(&rpc, None, 1001, 1100, &CancellationToken::new())
        .await
        .expect("span-limited logs");
    let timestamps = chain
        .fetch_log_block_timestamps(&rpc.provider, None, &logs)
        .await
        .expect("log block timestamps");
    drop(guard);
    assert_eq!(timestamps.len(), 2);

    let field = |event: &BTreeMap<String, String>, name: &str| {
        event
            .get(name)
            .cloned()
            .unwrap_or_else(|| panic!("missing {name} field"))
    };
    let adaptation = events.find("narrowed eth_getLogs request after provider range limit");
    for (name, value) in [
        ("logical_from", "1001"),
        ("logical_to", "1100"),
        ("rejected_span", "100"),
        ("next_span", "25"),
        ("endpoint", "0"),
        ("kind", "block_span"),
    ] {
        assert_eq!(field(&adaptation, name), value, "{name}");
    }
    let range = events.find("logical log range fetch finished");
    assert_eq!(field(&range, "get_logs_requests"), "5");
    assert_eq!(field(&range, "rpc_index"), "0");
    let coverage = events.find("log block timestamp coverage");
    assert_eq!(field(&coverage, "blocks_from_logs"), "1");
    assert_eq!(field(&coverage, "headers_requested"), "1");
    assert!(coverage.contains_key("elapsed_ms"));

    let forbidden = [
        credential_url.as_str(),
        "127.0.0.1",
        "user",
        "secret",
        "key-abc",
    ];
    for event in events.events() {
        for value in event.values() {
            assert!(
                forbidden.iter().all(|needle| !value.contains(needle)),
                "diagnostic value {value:?} exposes the endpoint"
            );
        }
    }
}

#[tokio::test]
async fn wallet_startup_hedge_failure_logs_omit_endpoint_url() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind refused RPC port");
    let port = listener.local_addr().expect("refused RPC addr").port();
    drop(listener);
    let credential_url = Url::parse(&format!("http://user:secret@127.0.0.1:{port}/key-abc"))
        .expect("credential-bearing RPC URL");
    let root_dir = temp_db_root("wallet-startup-hedge-url-redaction");
    let events = CapturedEvents::default();
    let guard = events.capture();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![credential_url],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    chain.sync.block_range = 10;
    chain.sync.indexed_wallet_block_range = 10;
    chain.finality_depth = 0;
    let public_data_plane = ChainPublicDataPlane::new(Arc::clone(&db), Arc::new(AtomicU64::new(0)));
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
    service.safe_head_tx.send_replace(110);

    // Only the RPC candidate runs, and its head read is refused.
    let mut cfg = test_wallet_config(
        &scope,
        Url::parse("http://127.0.0.1:1").expect("unused Squid URL"),
    );
    cfg.cache_key = test_cache_key("hedge-url-redaction");
    cfg.start_block = Some(101);
    cfg.sync_to_block = Some(110);
    cfg.use_indexed_wallet_catch_up = false;
    db.put_wallet_meta(
        &cfg.cache_key,
        &WalletMeta {
            last_scanned_block: 105,
            updated_at: 1,
            last_scanned_block_hash: None,
        },
    )
    .expect("seed wallet cursor");
    let _handle = service.register_wallet(cfg).await.expect("register wallet");
    let hedge_failed = |event: &BTreeMap<String, String>| {
        event
            .get("message")
            .is_some_and(|message| message == "wallet startup hedge candidate failed")
    };
    yield_until("failed wallet startup hedge candidate", || {
        events.events().iter().any(hedge_failed)
    })
    .await;

    service.unregister_all_wallets().await;
    service.shutdown().await;
    drop(guard);

    let failure = events.find("wallet startup hedge candidate failed");
    let err = failure.get("err").expect("hedge failure err field");
    assert!(
        err.starts_with("rpc error"),
        "the candidate failed on the transport error: {err:?}"
    );
    let endpoint = format!("127.0.0.1:{port}");
    let forbidden = ["secret", "user:", "key-abc", endpoint.as_str()];
    for event in events.events() {
        for value in event.values() {
            assert!(
                forbidden.iter().all(|needle| !value.contains(needle)),
                "log value {value:?} exposes the endpoint"
            );
        }
    }

    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn chain_rpc_failure_logs_omit_endpoint_url() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind refused RPC port");
    let port = listener.local_addr().expect("refused RPC addr").port();
    drop(listener);
    let events = CapturedEvents::default();
    let guard = events.capture();
    let fixture = LiveForestFixture::spawn(
        "chain-rpc-failure-url-redaction",
        vec![credential_url(port)],
        Url::parse("http://127.0.0.1:1").expect("unused Squid URL"),
        50,
        200,
    )
    .await;
    let service = &fixture.service;
    let chain = &service.chain;
    // A recorded hash for the forest block makes the live loop read it back.
    service
        .db
        .update_merkle_forest_meta(
            chain.deployment.chain_id,
            &chain.deployment.contract.to_string(),
            &service.db.resolve_path(&DbStore::relative_blob_path(
                "merkle_forest",
                "live-forest.msgpack",
            )),
            50,
            merkletree::persist::SNAPSHOT_VERSION,
            [0xaa; 32],
        )
        .expect("persist forest meta for block 50");
    service.safe_head_tx.send(200).expect("wake live loop");
    yield_until("failed reorg check", || {
        events.events().iter().any(|event| {
            event
                .get("message")
                .is_some_and(|m| m == "reorg check failed")
        })
    })
    .await;

    // A separate pool keeps the live loop's cooldown from hiding the head read.
    spawn_head_poller(
        Arc::clone(service),
        Arc::new(QueryRpcPool::new(
            vec![credential_url(port)],
            Duration::from_secs(1),
        )),
    );
    yield_until("failed head read", || {
        events.events().iter().any(|event| {
            event
                .get("message")
                .is_some_and(|m| m == "failed to fetch latest block")
        })
    })
    .await;
    fixture.stop().await;
    drop(guard);

    for message in ["reorg check failed", "failed to fetch latest block"] {
        let event = events.find(message);
        assert_eq!(
            event.get("rpc_index").map(String::as_str),
            Some("0"),
            "{message}"
        );
        let err = event.get("err").expect("err field");
        assert!(
            err.starts_with("rpc error"),
            "{message} logs the transport error: {err:?}"
        );
    }
    let endpoint = format!("127.0.0.1:{port}");
    let forbidden = ["secret", "user:", "key-abc", endpoint.as_str()];
    for event in events.events() {
        for value in event.values() {
            assert!(
                forbidden.iter().all(|needle| !value.contains(needle)),
                "log value {value:?} exposes the endpoint"
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn bounded_head_read_uses_answering_provider_beside_hung_one() {
    let (_hung, hung_port) = silent_server();
    let answering =
        JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 200, |_, _, _| None));
    let rpcs = QueryRpcPool::new(
        vec![
            Url::parse(&format!("http://127.0.0.1:{hung_port}")).expect("hung RPC URL"),
            answering.url.clone(),
        ],
        Duration::from_mins(1),
    );
    let started = tokio::time::Instant::now();
    let read = tokio::spawn(async move {
        read_head_bounded(&rpcs)
            .await
            .map(|(rpc, head)| (rpc.index, head))
    });
    // Busy-yielding keeps the paused clock still while the answer arrives.
    yield_until("head read", || read.is_finished()).await;

    assert_eq!(read.await.expect("head read task"), Some((1, 200)));
    assert_eq!(
        started.elapsed(),
        Duration::ZERO,
        "no stagger or deadline wait"
    );
}

#[tokio::test(start_paused = true)]
async fn bounded_head_read_gives_up_at_deadline_when_every_provider_hangs() {
    let hung = (0..4).map(|_| silent_server()).collect::<Vec<_>>();
    // Per-request timeouts as in production, longer than the deadline.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("RPC client");
    let rpcs = QueryRpcPool::with_http_client(
        hung.iter()
            .map(|(_, port)| Url::parse(&format!("http://127.0.0.1:{port}")).expect("hung RPC URL"))
            .collect(),
        Duration::from_mins(1),
        client,
    );
    let started = tokio::time::Instant::now();

    // Nothing answers, so the paused clock runs forward through the read's
    // timers.
    assert!(read_head_bounded(&rpcs).await.is_none());
    let elapsed = started.elapsed();
    assert!(
        (INITIAL_HEAD_DEADLINE..INITIAL_HEAD_DEADLINE + Duration::from_secs(1)).contains(&elapsed),
        "the read ends at its deadline, got {elapsed:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn bounded_head_read_staggers_past_hung_providers() {
    let (servers, head_reads, release) = head_servers_with_hung_first_reads(4, 3, 300);
    let rpcs = QueryRpcPool::new(
        servers.iter().map(|server| server.url.clone()).collect(),
        Duration::from_mins(1),
    );
    let started = tokio::time::Instant::now();
    let read = tokio::spawn(async move { read_head_bounded(&rpcs).await.map(|(_, head)| head) });

    // Busy-yielding keeps the paused clock still between the steps.
    yield_until("three hung head reads", || {
        head_reads.load(Ordering::Acquire) >= 3
    })
    .await;
    tokio::time::advance(HEAD_READ_STAGGER).await;
    yield_until("staggered head read", || read.is_finished()).await;

    assert_eq!(read.await.expect("head read task"), Some(300));
    assert_eq!(
        head_reads.load(Ordering::Acquire),
        4,
        "the fourth provider starts at the stagger"
    );
    assert!(started.elapsed() < INITIAL_HEAD_DEADLINE);
    release.store(true, Ordering::Release);
}

#[tokio::test(start_paused = true)]
async fn head_poller_publishes_first_safe_head_past_hung_providers() {
    let (servers, head_reads, release) = head_servers_with_hung_first_reads(4, 3, 300);
    let (root_dir, db) = open_forest_db("head-poller-hung-providers");
    let rpcs = Arc::new(QueryRpcPool::new(
        servers.iter().map(|server| server.url.clone()).collect(),
        Duration::from_mins(1),
    ));
    let chain = test_chain_config(&test_scope(), Arc::clone(&rpcs), None);
    let public_data_plane = ChainPublicDataPlane::new(Arc::clone(&db), Arc::new(AtomicU64::new(0)));
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
    let safe_head_rx = service.safe_head_tx.subscribe();
    let started = tokio::time::Instant::now();

    // A headless start: no safe head is known yet.
    spawn_head_poller(Arc::clone(&service), rpcs);
    yield_until("three hung head reads", || {
        head_reads.load(Ordering::Acquire) >= 3
    })
    .await;
    tokio::time::advance(HEAD_READ_STAGGER).await;
    yield_until("first safe head", || *safe_head_rx.borrow() == 300).await;
    assert!(
        started.elapsed() < INITIAL_HEAD_DEADLINE,
        "no hung provider's request is waited out"
    );

    service.cancel.cancel();
    release.store(true, Ordering::Release);
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

fn rpc_error_response(code: i64, message: &str) -> ChainError {
    let payload = serde_json::json!({ "code": code, "message": message }).to_string();
    ChainError::Rpc(TransportError::ErrorResp(
        serde_json::from_str(&payload).expect("JSON-RPC error payload"),
    ))
}

async fn fetch_sorted_logs(
    chain: &ChainConfig,
    from_block: u64,
    to_block: u64,
) -> Result<Vec<Log>, ChainError> {
    let rpc = chain.rpcs.random_provider().expect("rpc provider");
    let mut logs = chain
        .fetch_logs_for_range(&rpc, None, from_block, to_block, &CancellationToken::new())
        .await?;
    sort_logs(&mut logs);
    Ok(logs)
}

/// Starts `count` JSON-RPC endpoints with head `head`. The first `hung`
/// block-number reads, counted across all of them, get no answer until the
/// returned release flag is set.
fn head_servers_with_hung_first_reads(
    count: usize,
    hung: u64,
    head: u64,
) -> (
    Vec<JsonRpcServer>,
    Arc<AtomicU64>,
    Arc<std::sync::atomic::AtomicBool>,
) {
    let head_reads = Arc::new(AtomicU64::new(0));
    let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let servers = (0..count)
        .map(|_| {
            let head_reads = Arc::clone(&head_reads);
            let release = Arc::clone(&release);
            let serve = log_range_rpc_handler(Vec::new(), head, |_, _, _| None);
            JsonRpcServer::spawn_handler(move |request| {
                if request["method"] == "eth_blockNumber"
                    && head_reads.fetch_add(1, Ordering::AcqRel) < hung
                {
                    while !release.load(Ordering::Acquire) {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
                serve(request)
            })
        })
        .collect();
    (servers, head_reads, release)
}
