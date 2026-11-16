use super::*;

/// A content-specific failure that cools only the requested capability.
const fn capability_failure() -> TrustlessArtifactError {
    TrustlessArtifactError::HttpStatus {
        origin: TrustlessHttpSource::Gateway { index: 0, count: 1 },
        status: reqwest::StatusCode::NOT_FOUND,
    }
}

/// A failure showing that the gateway is unreachable.
const fn unreachable_failure() -> TrustlessArtifactError {
    TrustlessArtifactError::HttpTimeout {
        origin: TrustlessHttpSource::Gateway { index: 0, count: 1 },
        phase: TrustlessHttpPhase::ResponseHeaders,
    }
}

#[test]
fn gateway_failure_cooldown_skips_failed_gateway() {
    let gateways = [
        Url::parse("https://one.example").expect("gateway"),
        Url::parse("https://two.example").expect("gateway"),
    ];
    let ids = gateways.iter().map(opaque_gateway_id).collect::<Vec<_>>();
    let pool = GatewayPool::new();
    let attempt = pool
        .select(&ids, GatewayCapability::ArtifactCar, Some(0))
        .expect("first gateway");
    assert_eq!(attempt.index, 0);
    attempt.failure(&capability_failure());
    let fallback = pool
        .select(&ids, GatewayCapability::ArtifactCar, Some(0))
        .expect("healthy fallback");
    assert_eq!(fallback.index, 1);
}

#[test]
fn gateway_health_isolated_by_capability_and_reset() {
    let gateways = [
        Url::parse("https://one.example").expect("gateway"),
        Url::parse("https://two.example").expect("gateway"),
    ];
    let ids = gateways.iter().map(opaque_gateway_id).collect::<Vec<_>>();
    let pool = GatewayPool::new();
    pool.select(&ids, GatewayCapability::IpnsRecord, Some(0))
        .expect("IPNS gateway")
        .failure(&capability_failure());
    assert_eq!(
        pool.select(&ids, GatewayCapability::ArtifactCar, Some(0))
            .expect("artifact gateway")
            .index,
        0
    );
    pool.select(&ids, GatewayCapability::ArtifactCar, Some(0))
        .expect("artifact gateway")
        .failure(&capability_failure());
    pool.reset();
    assert_eq!(
        pool.select(&ids, GatewayCapability::ArtifactCar, Some(0))
            .expect("reset gateway")
            .index,
        0
    );
}

#[test]
fn gateway_wide_failure_cools_every_capability_until_any_success() {
    let ids = [11_u64, 22];
    let pool = GatewayPool::with_seed_for_test(10);
    let unreachable = pool
        .select(&ids, GatewayCapability::ManifestCid, Some(0))
        .expect("manifest gateway");
    assert_eq!(unreachable.index, 0);
    unreachable.failure(&unreachable_failure());
    assert!(
        recover_mutex(&pool.state)
            .health
            .get(&(ids[0], GatewayCapability::ManifestCid))
            .is_some_and(|health| health.failures == 0 && health.cooldown_until.is_none()),
        "a gateway-wide failure leaves the capability entry unchanged"
    );
    for capability in [
        GatewayCapability::ArtifactCar,
        GatewayCapability::IpnsRecord,
    ] {
        assert_eq!(
            pool.select(&ids, capability, Some(0))
                .expect("healthy alternative")
                .index,
            1,
            "{capability:?} selection skips the unreachable gateway"
        );
    }

    let only_unreachable = HashSet::from([ids[1]]);
    let ipns = pool
        .select_excluding(
            &ids,
            GatewayCapability::IpnsRecord,
            Some(0),
            &only_unreachable,
        )
        .expect("cooling IPNS fallback");
    assert_eq!(ipns.index, 0);
    ipns.failure(&capability_failure());
    pool.select_excluding(
        &ids,
        GatewayCapability::ArtifactCar,
        Some(0),
        &only_unreachable,
    )
    .expect("cooling artifact fallback")
    .success();

    for capability in [
        GatewayCapability::ArtifactCar,
        GatewayCapability::ManifestCid,
    ] {
        assert_eq!(
            pool.select(&ids, capability, Some(0))
                .expect("restored gateway")
                .index,
            0,
            "a success on any capability restores {capability:?} selection"
        );
    }
    assert_eq!(
        pool.select(&ids, GatewayCapability::IpnsRecord, Some(0))
            .expect("IPNS alternative")
            .index,
        1,
        "the content-specific IPNS cooldown remains"
    );

    pool.select(&ids, GatewayCapability::ManifestCid, Some(0))
        .expect("manifest gateway")
        .failure(&unreachable_failure());
    pool.reset();
    assert!(recover_mutex(&pool.state).gateway_health.is_empty());
}

fn pool_for_gateway_order(gateways: &[Url], order: &[usize]) -> GatewayPool {
    assert_eq!(gateways.len(), order.len());
    let ids = gateways.iter().map(opaque_gateway_id).collect::<Vec<_>>();
    let seed = (0_u64..1_000_000)
        .find(|seed| {
            order
                .windows(2)
                .all(|pair| rank_for(*seed, ids[pair[0]]) < rank_for(*seed, ids[pair[1]]))
        })
        .expect("find deterministic gateway ranking within test seed range");
    GatewayPool::with_seed_for_test(seed)
}

fn pool_for_sensitive_gateway_order(gateways: &[SensitiveUrl], order: &[usize]) -> GatewayPool {
    assert_eq!(gateways.len(), order.len());
    let ids = gateways
        .iter()
        .map(|gateway| opaque_gateway_id(gateway.expose_url()))
        .collect::<Vec<_>>();
    let seed = (0_u64..1_000_000)
        .find(|seed| {
            order
                .windows(2)
                .all(|pair| rank_for(*seed, ids[pair[0]]) < rank_for(*seed, ids[pair[1]]))
        })
        .expect("find deterministic sensitive gateway ranking within test seed range");
    GatewayPool::with_seed_for_test(seed)
}

#[test]
fn shared_pool_keeps_indices_local_to_each_gateway_vector() {
    let first = [
        Url::parse("https://one.example").expect("gateway"),
        Url::parse("https://two.example").expect("gateway"),
    ];
    let second = [
        Url::parse("https://two.example").expect("gateway"),
        Url::parse("https://three.example").expect("gateway"),
        Url::parse("https://one.example").expect("gateway"),
    ];
    let first_ids = first.iter().map(opaque_gateway_id).collect::<Vec<_>>();
    let second_ids = second.iter().map(opaque_gateway_id).collect::<Vec<_>>();
    let pool = GatewayPool::new();
    pool.select(&first_ids, GatewayCapability::ArtifactCar, Some(0))
        .expect("first vector attempt")
        .failure(&capability_failure());
    let second_attempt = pool
        .select(&second_ids, GatewayCapability::ArtifactCar, Some(0))
        .expect("second vector attempt");
    assert!(second_attempt.index < second.len());
    assert_ne!(second[second_attempt.index], first[0]);
    second_attempt.failure(&capability_failure());
    let first_attempt = pool
        .select(&first_ids, GatewayCapability::ArtifactCar, Some(0))
        .expect("first vector fallback");
    assert!(first_attempt.index < first.len());
}

#[test]
fn operation_exclusions_exhaust_cooling_gateways_once() {
    let ids = [11_u64, 22, 33, 44];
    let pool = GatewayPool::with_seed_for_test(7);
    let mut pre_cooling = HashSet::new();
    for _ in 0..3 {
        let attempt = pool
            .select_excluding(&ids, GatewayCapability::ArtifactCar, None, &pre_cooling)
            .expect("pre-cool gateway");
        pre_cooling.insert(ids[attempt.index]);
        attempt.failure(&capability_failure());
    }

    let mut operation_exclusions = HashSet::new();
    for _ in 0..4 {
        let attempt = pool
            .select_excluding(
                &ids,
                GatewayCapability::ArtifactCar,
                None,
                &operation_exclusions,
            )
            .expect("each cooling gateway is reserved once");
        assert!(operation_exclusions.insert(ids[attempt.index]));
        attempt.failure(&capability_failure());
    }
    assert!(
        pool.select_excluding(
            &ids,
            GatewayCapability::ArtifactCar,
            None,
            &operation_exclusions,
        )
        .is_none()
    );
}

#[test]
fn stale_attempt_outcomes_do_not_recreate_reset_state() {
    let ids = [11_u64];
    let pool = GatewayPool::with_seed_for_test(8);

    let stale_success = pool
        .select(&ids, GatewayCapability::ArtifactCar, None)
        .expect("stale success attempt");
    pool.reset();
    stale_success.success();

    let stale_failure = pool
        .select(&ids, GatewayCapability::ArtifactCar, None)
        .expect("stale failure attempt");
    pool.reset();
    stale_failure.failure(&capability_failure());

    let stale_drop = pool
        .select(&ids, GatewayCapability::ArtifactCar, None)
        .expect("stale drop attempt");
    pool.reset();
    drop(stale_drop);

    assert!(recover_mutex(&pool.state).health.is_empty());
}

#[test]
fn half_open_probe_ownership_controls_cancellation() {
    let ids = [11_u64];
    let pool = GatewayPool::with_seed_for_test(9);
    {
        let mut state = recover_mutex(&pool.state);
        state.health.insert(
            (ids[0], GatewayCapability::ArtifactCar),
            GatewayHealth {
                failures: 1,
                cooldown_until: Some(
                    Instant::now()
                        .checked_sub(Duration::from_secs(1))
                        .expect("current instant supports one-second test subtraction"),
                ),
                in_flight: 0,
                half_open: false,
            },
        );
    }

    let owner = pool
        .select(&ids, GatewayCapability::ArtifactCar, None)
        .expect("expired cooldown probe");
    let non_owner = pool
        .select(&ids, GatewayCapability::ArtifactCar, None)
        .expect("least-bad concurrent probe");
    drop(non_owner);
    assert!(
        recover_mutex(&pool.state)
            .health
            .get(&(ids[0], GatewayCapability::ArtifactCar))
            .is_some_and(|health| health.half_open && health.in_flight == 1)
    );
    drop(owner);
    assert!(
        recover_mutex(&pool.state)
            .health
            .get(&(ids[0], GatewayCapability::ArtifactCar))
            .is_some_and(|health| !health.half_open && health.in_flight == 0)
    );

    let stale_owner = pool
        .select(&ids, GatewayCapability::ArtifactCar, None)
        .expect("new probe");
    pool.reset();
    let current = pool
        .select(&ids, GatewayCapability::ArtifactCar, None)
        .expect("post-reset attempt");
    drop(stale_owner);
    assert!(
        recover_mutex(&pool.state)
            .health
            .get(&(ids[0], GatewayCapability::ArtifactCar))
            .is_some_and(|health| !health.half_open && health.in_flight == 1)
    );
    drop(current);
}

use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;
use ipld_dagpb::{PbLink, PbNode};
use libp2p_identity::Keypair;
use multihash_codetable::{Code, MultihashDigest};
use quick_protobuf::Writer;

fn sensitive_server_url(mut url: Url) -> SensitiveUrl {
    url.set_path("/endpoint-sentinel");
    url.set_query(Some("secret=endpoint-sentinel"));
    url.set_fragment(Some("endpoint-sentinel"));
    url.into()
}

fn spawn_stalled_server() -> SensitiveUrl {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind stalled server");
    let url = Url::parse(&format!(
        "http://{}",
        listener.local_addr().expect("stalled server address")
    ))
    .expect("stalled server URL");
    std::thread::spawn(move || {
        let (_stream, _) = listener.accept().expect("accept stalled request");
        std::thread::sleep(Duration::from_secs(1));
    });
    sensitive_server_url(url)
}

fn formatted_error_chain(error: &(dyn StdError + 'static)) -> String {
    let mut formatted = String::new();
    let mut current = Some(error);
    while let Some(error) = current {
        std::fmt::Write::write_fmt(&mut formatted, format_args!("{error} {error:?}\n"))
            .expect("write error chain");
        current = error.source();
    }
    formatted
}

fn assert_artifact_error_safe(error: &TrustlessArtifactError) {
    let formatted = formatted_error_chain(error);
    assert!(
        !formatted.contains("endpoint-sentinel"),
        "artifact error leaked endpoint: {formatted}"
    );
    assert!(
        !formatted.contains("body-sentinel"),
        "artifact error leaked response body: {formatted}"
    );
}

#[tokio::test]
async fn sensitive_gateway_errors_are_url_free() {
    let oversized_server = spawn_once_server(200, b"oversized".to_vec());
    let oversized_url = sensitive_server_url(oversized_server.url.clone());
    let oversized_error = fetch_response_bytes(
        &reqwest::Client::new(),
        oversized_url.expose_url(),
        TrustlessHttpSource::Gateway { index: 0, count: 1 },
        None,
        1,
    )
    .await
    .expect_err("oversized manifest response");
    assert!(matches!(
        &oversized_error,
        TrustlessArtifactError::ResponseTooLarge {
            origin: TrustlessHttpSource::Gateway { index: 0, count: 1 },
            limit,
        } if *limit == 1
    ));
    assert_artifact_error_safe(&oversized_error);

    let stalled_url = spawn_stalled_server();
    let timeout_error = fetch_response_bytes_with_timeouts(
        &reqwest::Client::new(),
        stalled_url.expose_url(),
        TrustlessHttpSource::Gateway { index: 1, count: 2 },
        None,
        1024,
        HttpAttemptTimeouts {
            headers: Duration::from_millis(20),
            idle: Duration::from_secs(1),
            total: Duration::from_secs(1),
        },
    )
    .await
    .expect_err("gateway timeout");
    assert!(matches!(
        &timeout_error,
        TrustlessArtifactError::HttpTimeout {
            origin: TrustlessHttpSource::Gateway { index: 1, count: 2 },
            phase: TrustlessHttpPhase::ResponseHeaders,
        }
    ));
    assert_artifact_error_safe(&timeout_error);

    let artifact_bytes = b"verified fallback artifact".to_vec();
    let cid = raw_cid(&artifact_bytes);
    let gateway_status_server = spawn_once_server(503, b"body-sentinel".to_vec());
    let gateway_status_urls = [sensitive_server_url(gateway_status_server.url.clone())];
    let client = reqwest::Client::new();
    let gateway_status_error = TrustlessArtifactFetcher::new_poi(&client, &gateway_status_urls)
        .fetch_artifact_cid(&cid.to_string(), artifact_bytes.len() as u64)
        .await
        .expect_err("gateway status error");
    assert!(matches!(
        &gateway_status_error,
        TrustlessArtifactError::HttpStatus {
            origin: TrustlessHttpSource::Gateway { index: 0, count: 1 },
            status,
        } if *status == reqwest::StatusCode::SERVICE_UNAVAILABLE
    ));
    assert_artifact_error_safe(&gateway_status_error);

    let failing = spawn_once_server(503, Vec::new());
    let valid = spawn_once_server(200, car_bytes(cid, &[(cid, artifact_bytes.clone())]));
    let gateways = [
        sensitive_server_url(failing.url.clone()),
        sensitive_server_url(valid.url.clone()),
    ];
    let fetched = TrustlessArtifactFetcher::new_poi(&client, &gateways)
        .fetch_artifact_cid(&cid.to_string(), artifact_bytes.len() as u64)
        .await
        .expect("fallback to second sensitive gateway");
    assert_eq!(fetched, artifact_bytes);
    assert_eq!(
        valid.request_path(),
        format!(
            "/endpoint-sentinel/ipfs/{cid}?secret=endpoint-sentinel&format=car&dag-scope=entity"
        )
    );
}

#[tokio::test]
async fn unreachable_gateway_failures_cool_every_capability() {
    let cid = raw_cid(b"failure scope artifact");
    let refused_listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("bind refused gateway");
    let refused = Url::parse(&format!(
        "http://{}",
        refused_listener
            .local_addr()
            .expect("refused gateway address")
    ))
    .expect("refused gateway URL");
    drop(refused_listener);
    let stalled = spawn_stalled_server();
    let status_servers =
        [521_u16, 522, 523, 403, 504].map(|status| (status, spawn_once_server(status, Vec::new())));
    let mut cases = vec![
        ("connection error".to_owned(), refused, true),
        (
            "header timeout".to_owned(),
            stalled.expose_url().clone(),
            true,
        ),
    ];
    cases.extend(status_servers.iter().map(|(status, server)| {
        (
            format!("HTTP {status}"),
            server.url.clone(),
            (521..=523).contains(status),
        )
    }));
    let client = reqwest::Client::new();

    for (case, gateway, gateway_wide) in cases {
        let pool = GatewayPool::new();
        let gateways = [gateway];
        let error = TrustlessArtifactFetcher::new_with_pool(&client, &gateways, pool.clone())
            .with_http_timeouts_for_test(
                Duration::from_millis(250),
                Duration::from_secs(1),
                Duration::from_secs(2),
            )
            .fetch_artifact_cid(&cid.to_string(), 24)
            .await
            .expect_err("the only gateway fails");
        let recorded = (
            gateway_wide_failures(&pool, &gateways[0]),
            gateway_health(&pool, &gateways[0], GatewayCapability::ArtifactCar).0,
        );
        let expected = if gateway_wide { (1, 0) } else { (0, 1) };
        assert_eq!(recorded, expected, "{case}: {error}");
    }
}

#[tokio::test(start_paused = true)]
async fn slow_drip_hits_total_deadline_despite_remaining_under_idle_timeout() {
    let server = spawn_controlled_chunk_server();
    let url = sensitive_server_url(server.url.clone());
    let started = tokio::time::Instant::now();
    let task = tokio::spawn(async move {
        let client = reqwest::Client::new();
        fetch_response_bytes_with_timeouts(
            &client,
            url.expose_url(),
            TrustlessHttpSource::Gateway { index: 1, count: 3 },
            None,
            1024,
            HttpAttemptTimeouts {
                headers: Duration::from_secs(5),
                idle: Duration::from_secs(5),
                total: Duration::from_secs(12),
            },
        )
        .await
    });
    server.wait_for_request().await;
    server.send_headers(200);
    server.send_chunk(b"body-sentinel-0".to_vec());
    tokio::task::yield_now().await;
    for chunk in [b"body-sentinel-1".as_slice(), b"body-sentinel-2".as_slice()] {
        tokio::time::advance(Duration::from_secs(4)).await;
        server.send_chunk(chunk.to_vec());
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_secs(4)).await;

    let error = task
        .await
        .expect("join slow-drip request")
        .expect_err("absolute deadline expires");
    assert_eq!(started.elapsed(), Duration::from_secs(12));
    assert!(matches!(
        &error,
        TrustlessArtifactError::HttpAttemptDeadline {
            origin: TrustlessHttpSource::Gateway { index: 1, count: 3 }
        }
    ));
    assert_artifact_error_safe(&error);
}

#[tokio::test(start_paused = true)]
async fn response_body_idle_stall_keeps_phase_specific_timeout() {
    let server = spawn_controlled_chunk_server();
    let url = server.url.clone();
    let headers_received = Arc::new(AtomicBool::new(false));
    let task_headers_received = Arc::clone(&headers_received);
    let task = tokio::spawn(async move {
        let client = reqwest::Client::new();
        fetch_response_bytes_reporting_headers(
            &client,
            &url,
            TrustlessHttpSource::ExplicitManifest,
            None,
            1024,
            HttpAttemptTimeouts {
                headers: Duration::from_secs(1),
                idle: Duration::from_secs(3),
                total: Duration::from_secs(20),
            },
            Some(&task_headers_received),
        )
        .await
    });
    server.wait_for_request().await;
    server.send_headers(200);
    yield_until("response headers are read", || {
        headers_received.load(Ordering::SeqCst)
    })
    .await;
    // The header limit no longer applies once headers have arrived.
    tokio::time::advance(Duration::from_secs(2)).await;
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    assert!(!task.is_finished(), "body stall outlived the header limit");
    tokio::time::advance(Duration::from_secs(1)).await;

    assert!(matches!(
        task.await.expect("join idle-stall request"),
        Err(TrustlessArtifactError::HttpTimeout {
            origin: TrustlessHttpSource::ExplicitManifest,
            phase: TrustlessHttpPhase::ResponseBody,
        })
    ));
}

#[tokio::test(start_paused = true)]
async fn response_header_stall_fails_at_header_limit_without_url() {
    let server = spawn_controlled_chunk_server();
    let url = sensitive_server_url(server.url.clone());
    let started = tokio::time::Instant::now();
    let task = tokio::spawn(async move {
        let client = reqwest::Client::new();
        fetch_response_bytes_with_timeouts(
            &client,
            url.expose_url(),
            TrustlessHttpSource::Gateway { index: 1, count: 2 },
            None,
            1024,
            HttpAttemptTimeouts {
                headers: Duration::from_secs(3),
                idle: Duration::from_secs(10),
                total: Duration::from_secs(20),
            },
        )
        .await
    });
    server.wait_for_request().await;
    tokio::time::advance(Duration::from_secs(3)).await;

    let error = task
        .await
        .expect("join header-stall request")
        .expect_err("header limit expires");
    assert_eq!(started.elapsed(), Duration::from_secs(3));
    assert!(matches!(
        &error,
        TrustlessArtifactError::HttpTimeout {
            origin: TrustlessHttpSource::Gateway { index: 1, count: 2 },
            phase: TrustlessHttpPhase::ResponseHeaders,
        }
    ));
    assert_artifact_error_safe(&error);
}

#[tokio::test(start_paused = true)]
async fn response_completed_before_total_deadline_succeeds() {
    let server = spawn_controlled_chunk_server();
    let url = server.url.clone();
    let task = tokio::spawn(async move {
        let client = reqwest::Client::new();
        fetch_response_bytes_with_timeouts(
            &client,
            &url,
            TrustlessHttpSource::ExplicitManifest,
            None,
            1024,
            HttpAttemptTimeouts {
                headers: Duration::from_secs(5),
                idle: Duration::from_secs(5),
                total: Duration::from_secs(20),
            },
        )
        .await
    });
    server.wait_for_request().await;
    server.send_headers(200);
    server.send_chunk(b"complete".to_vec());
    server.finish();

    assert_eq!(
        task.await
            .expect("join completed request")
            .expect("completed response"),
        b"complete"
    );
}

#[tokio::test(start_paused = true)]
async fn slow_first_gateway_deadline_falls_back_to_healthy_gateway() {
    let artifact_bytes = b"deadline fallback artifact".to_vec();
    let cid = raw_cid(&artifact_bytes);
    let slow = spawn_controlled_chunk_server();
    let healthy = spawn_controlled_chunk_server();
    let healthy_body = car_bytes(cid, &[(cid, artifact_bytes.clone())]);
    let gateways = vec![
        sensitive_server_url(slow.url.clone()),
        sensitive_server_url(healthy.url.clone()),
    ];
    let expected = artifact_bytes.clone();
    let task = tokio::spawn(async move {
        let client = reqwest::Client::new();
        TrustlessArtifactFetcher::new_poi(&client, &gateways)
            .with_http_timeouts_for_test(
                Duration::from_secs(5),
                Duration::from_secs(5),
                Duration::from_secs(12),
            )
            .fetch_artifact_cid_with_metadata_from_gateway(
                &cid.to_string(),
                expected.len() as u64,
                0,
            )
            .await
            .map(TrustlessArtifactFetchResult::into_bytes)
    });
    slow.wait_for_request().await;
    slow.send_headers(200);
    slow.send_chunk(b"slow-0".to_vec());
    tokio::task::yield_now().await;
    for chunk in [b"slow-1".as_slice(), b"slow-2".as_slice()] {
        tokio::time::advance(Duration::from_secs(4)).await;
        slow.send_chunk(chunk.to_vec());
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_secs(4)).await;
    let healthy_path = healthy.wait_for_request().await;
    healthy.send_headers(200);
    healthy.send_chunk(healthy_body);
    healthy.finish();

    assert_eq!(
        task.await
            .expect("join fallback request")
            .expect("healthy fallback succeeds"),
        artifact_bytes
    );
    assert!(healthy_path.contains(&cid.to_string()));
}

#[tokio::test(start_paused = true)]
async fn bounded_gateway_fetch_uses_three_deadline_windows_and_never_contacts_fourth() {
    let artifact_bytes = b"three-attempt artifact".to_vec();
    let cid = raw_cid(&artifact_bytes);
    let servers = (0..4)
        .map(|_| spawn_controlled_chunk_server())
        .collect::<Vec<_>>();
    let gateways = servers
        .iter()
        .map(|server| sensitive_server_url(server.url.clone()))
        .collect::<Vec<_>>();
    let pool = pool_for_sensitive_gateway_order(&gateways, &[0, 1, 2, 3]);
    let started = tokio::time::Instant::now();
    let task = tokio::spawn(async move {
        let client = reqwest::Client::new();
        TrustlessArtifactFetcher::new_poi_with_pool(&client, &gateways, pool)
            .with_http_timeouts_for_test(
                Duration::from_secs(10),
                Duration::from_secs(10),
                Duration::from_secs(5),
            )
            .fetch_artifact_cid_with_metadata_from_gateway_bounded(
                &cid.to_string(),
                artifact_bytes.len() as u64,
                0,
                3,
            )
            .await
    });
    for server in &servers[..3] {
        server.wait_for_request().await;
        server.send_headers(200);
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(5)).await;
    }

    let error = task
        .await
        .expect("join bounded gateway request")
        .expect_err("three deadlines exhaust bounded attempts");
    assert_eq!(started.elapsed(), Duration::from_secs(15));
    assert!(matches!(
        error,
        TrustlessArtifactError::HttpAttemptDeadline {
            origin: TrustlessHttpSource::Gateway { index: 2, count: 4 }
        }
    ));
    servers[3].assert_no_request();
}

#[tokio::test(start_paused = true)]
async fn concurrent_ipns_slow_peer_consumes_only_one_deadline_window() {
    let keypair = test_ipns_keypair();
    let name = ipns_name(&keypair);
    let cid = raw_cid(b"concurrent IPNS candidate");
    let record = ipns_record(&keypair, format!("/ipfs/{cid}"), 7);
    let slow = spawn_controlled_chunk_server();
    let healthy = spawn_controlled_chunk_server();
    let gateways = vec![
        sensitive_server_url(slow.url.clone()),
        sensitive_server_url(healthy.url.clone()),
    ];
    let started = tokio::time::Instant::now();
    let task = tokio::spawn(async move {
        let client = reqwest::Client::new();
        TrustlessArtifactFetcher::new_poi(&client, &gateways)
            .with_http_timeouts_for_test(
                Duration::from_secs(10),
                Duration::from_secs(10),
                Duration::from_secs(5),
            )
            .resolve_ipns_manifest_candidates(&name, None)
            .await
    });
    slow.wait_for_request().await;
    healthy.wait_for_request().await;
    healthy.send_headers(200);
    healthy.send_chunk(record);
    healthy.finish();
    slow.send_headers(200);
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(5)).await;

    let candidates = task
        .await
        .expect("join concurrent IPNS request")
        .expect("healthy IPNS candidate survives slow peer");
    assert_eq!(started.elapsed(), Duration::from_secs(5));
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].sequence, 7);
    assert_eq!(candidates[0].cid, cid);
}

#[test]
fn car_gateway_url_adds_trustless_query_parameters() {
    let gateway = Url::parse("https://gateway.example/base/ipfs?existing=1").expect("URL");
    let cid = raw_cid(b"hello");

    let url = car_gateway_url(&gateway, &cid);

    assert_eq!(url.path(), format!("/base/ipfs/{cid}"));
    assert_eq!(url.query(), Some("existing=1&format=car&dag-scope=entity"));
}

#[test]
fn ipns_gateway_url_adds_record_query_parameter() {
    let gateway = Url::parse("https://gateway.example/root").expect("URL");

    let url = ipns_record_gateway_url(&gateway, "k51name");

    assert_eq!(url.path(), "/root/ipns/k51name");
    assert_eq!(url.query(), Some("format=ipns-record"));
}

#[tokio::test]
async fn raw_root_car_reconstructs_root_block() {
    let root = raw_cid(b"hello raw");
    let car = car_bytes(root, &[(root, b"hello raw".to_vec())]);

    let blocks = decode_car_blocks(&car, root, 8).await.expect("CAR blocks");
    let bytes = reconstruct_for_test(root, &blocks, 1024, 8, 8).expect("raw root");

    assert_eq!(bytes, b"hello raw");
}

#[tokio::test]
async fn car_duplicate_blocks_continue_to_count_toward_car_block_limit() {
    let root = raw_cid(b"duplicate raw");
    let car = car_bytes(
        root,
        &[
            (root, b"duplicate raw".to_vec()),
            (root, b"duplicate raw".to_vec()),
            (root, b"duplicate raw".to_vec()),
        ],
    );

    let error = decode_car_blocks(&car, root, 2)
        .await
        .expect_err("duplicate blocks exceed total block limit");

    assert!(matches!(
        error,
        TrustlessArtifactError::TooManyCarBlocks { limit: 2 }
    ));
}

#[tokio::test]
async fn dag_pb_single_file_reconstructs_inline_data() {
    let block = dag_pb_file_node(b"inline", &[], Some(6));
    let root = dag_pb_cid(&block);
    let car = car_bytes(root, &[(root, block)]);

    let blocks = decode_car_blocks(&car, root, 8).await.expect("CAR blocks");
    let bytes = reconstruct_for_test(root, &blocks, 1024, 8, 8).expect("DAG-PB file");

    assert_eq!(bytes, b"inline");
}

#[tokio::test]
async fn dag_pb_file_with_raw_leaves_reconstructs_declared_order() {
    let left = raw_cid(b"left");
    let right = raw_cid(b"right");
    let root_block = dag_pb_file_node(
        b"root-",
        &[(left, "left", 4), (right, "right", 5)],
        Some(14),
    );
    let root = dag_pb_cid(&root_block);
    let car = car_bytes(
        root,
        &[
            (root, root_block),
            (right, b"right".to_vec()),
            (left, b"left".to_vec()),
        ],
    );

    let blocks = decode_car_blocks(&car, root, 8).await.expect("CAR blocks");
    let bytes = reconstruct_for_test(root, &blocks, 1024, 8, 8).expect("DAG-PB leaves");

    assert_eq!(bytes, b"root-leftright");
}

#[tokio::test]
async fn missing_block_is_rejected() {
    let child = raw_cid(b"child");
    let root_block = dag_pb_file_node(b"", &[(child, "child", 5)], Some(5));
    let root = dag_pb_cid(&root_block);
    let car = car_bytes(root, &[(root, root_block)]);

    let blocks = decode_car_blocks(&car, root, 8).await.expect("CAR blocks");
    let error = reconstruct_for_test(root, &blocks, 1024, 8, 8).expect_err("missing child block");

    assert!(matches!(error, TrustlessArtifactError::MissingBlock { cid } if cid == child));
}

#[tokio::test]
async fn wrong_block_hash_is_rejected() {
    let root = raw_cid(b"expected");
    let car = car_bytes(root, &[(root, b"tampered".to_vec())]);

    let error = decode_car_blocks(&car, root, 8)
        .await
        .expect_err("wrong block hash");

    assert!(matches!(error, TrustlessArtifactError::Car(_)));
}

#[tokio::test]
async fn malformed_car_block_cid_falls_back_to_next_gateway() {
    let artifact_bytes = b"verified artifact bytes".to_vec();
    let cid = raw_cid(&artifact_bytes);
    let malformed = spawn_once_server(200, car_with_invalid_block_cid(cid));
    let valid = spawn_once_server(200, car_bytes(cid, &[(cid, artifact_bytes.clone())]));
    let client = reqwest::Client::new();
    let gateways = [malformed.url.clone(), valid.url.clone()];
    let fetcher = TrustlessArtifactFetcher::new(&client, &gateways);

    let fetched = fetcher
        .fetch_artifact_cid_with_metadata_from_gateway(
            &cid.to_string(),
            artifact_bytes.len() as u64,
            0,
        )
        .await
        .expect("fallback to valid CAR");

    assert_eq!(fetched.bytes, artifact_bytes);
    assert_eq!(
        malformed.request_path(),
        format!("/ipfs/{cid}?format=car&dag-scope=entity")
    );
    assert_eq!(
        valid.request_path(),
        format!("/ipfs/{cid}?format=car&dag-scope=entity")
    );
}

#[tokio::test]
async fn noncanonical_car_v2_header_falls_back_to_next_gateway() {
    let artifact_bytes = b"verified artifact bytes".to_vec();
    let cid = raw_cid(&artifact_bytes);
    let malformed = spawn_once_server(200, car_with_noncanonical_v2_header());
    let valid = spawn_once_server(200, car_bytes(cid, &[(cid, artifact_bytes.clone())]));
    let client = reqwest::Client::new();
    let gateways = [malformed.url.clone(), valid.url.clone()];
    let fetcher = TrustlessArtifactFetcher::new(&client, &gateways);

    let fetched = fetcher
        .fetch_artifact_cid_with_metadata_from_gateway(
            &cid.to_string(),
            artifact_bytes.len() as u64,
            0,
        )
        .await
        .expect("fallback to valid CAR");

    assert_eq!(fetched.bytes, artifact_bytes);
    assert_eq!(
        malformed.request_path(),
        format!("/ipfs/{cid}?format=car&dag-scope=entity")
    );
    assert_eq!(
        valid.request_path(),
        format!("/ipfs/{cid}?format=car&dag-scope=entity")
    );
}

#[tokio::test]
async fn unsupported_unixfs_node_type_is_rejected() {
    let block = dag_pb_node(
        Some(unixfs_data(UnixFsDataType::Directory, b"", &[], None)),
        &[],
    );
    let root = dag_pb_cid(&block);
    let car = car_bytes(root, &[(root, block)]);

    let blocks = decode_car_blocks(&car, root, 8).await.expect("CAR blocks");
    let error = reconstruct_for_test(root, &blocks, 1024, 8, 8).expect_err("directory rejected");

    assert!(matches!(
        error,
        TrustlessArtifactError::UnsupportedUnixFsType {
            data_type: UnixFsDataType::Directory
        }
    ));
}

#[tokio::test]
async fn reconstructed_limit_is_enforced() {
    let root = raw_cid(b"too large");
    let car = car_bytes(root, &[(root, b"too large".to_vec())]);

    let blocks = decode_car_blocks(&car, root, 8).await.expect("CAR blocks");
    let error = reconstruct_for_test(root, &blocks, 3, 8, 8).expect_err("limit exceeded");

    assert!(matches!(
        error,
        TrustlessArtifactError::ReconstructedTooLarge { limit: 3 }
    ));
}

#[test]
fn unixfs_depth_accepts_exact_limit() {
    let (root, blocks) = unixfs_chain(8);
    assert_eq!(
        reconstruct_for_test(root, &blocks, 1, 8, 7).expect("exact depth accepted"),
        b"x"
    );
}

#[test]
fn unixfs_budgets_are_derived_from_applicable_car_block_caps() {
    let manifest = RetrievalLimits::manifest();
    assert_eq!(manifest.unixfs_max_depth, MANIFEST_CAR_MAX_BLOCKS);
    assert_eq!(manifest.unixfs_max_link_visits, MANIFEST_CAR_MAX_BLOCKS);
    let artifact = RetrievalLimits::artifact(1).expect("artifact limits");
    assert_eq!(artifact.unixfs_max_depth, ARTIFACT_CAR_MAX_BLOCKS);
    assert_eq!(artifact.unixfs_max_link_visits, ARTIFACT_CAR_MAX_BLOCKS);
}

#[test]
fn unixfs_depth_rejects_limit_plus_one() {
    let (root, blocks) = unixfs_chain(9);
    assert!(matches!(
        reconstruct_for_test(root, &blocks, 1, 8, 8),
        Err(TrustlessArtifactError::UnixFsDepthLimitExceeded { limit: 8 })
    ));
}

#[test]
fn unixfs_link_visits_accept_exact_limit() {
    let (root, blocks) = repeated_link_graph(8);
    assert_eq!(
        reconstruct_for_test(root, &blocks, 8, 2, 8).expect("exact visits accepted"),
        vec![b'x'; 8]
    );
}

#[test]
fn unixfs_link_visits_reject_limit_plus_one() {
    let (root, blocks) = repeated_link_graph(9);
    assert!(matches!(
        reconstruct_for_test(root, &blocks, 9, 2, 8),
        Err(TrustlessArtifactError::UnixFsLinkVisitLimitExceeded { limit: 8 })
    ));
}

#[test]
fn unixfs_repeated_link_visits_are_charged_individually() {
    let (root, blocks) = repeated_link_graph(3);
    assert!(matches!(
        reconstruct_for_test(root, &blocks, 3, 2, 2),
        Err(TrustlessArtifactError::UnixFsLinkVisitLimitExceeded { limit: 2 })
    ));
}

#[test]
fn unixfs_diamond_dag_emits_shared_child_for_each_reference() {
    let shared = raw_cid(b"x");
    let left_block = dag_pb_file_node(b"", &[(shared, "left-shared", 1)], Some(1));
    let left = dag_pb_cid(&left_block);
    let right_block = dag_pb_file_node(b"", &[(shared, "right-shared", 1)], Some(1));
    let right = dag_pb_cid(&right_block);
    let root_block = dag_pb_file_node(b"", &[(left, "left", 1), (right, "right", 1)], Some(2));
    let root = dag_pb_cid(&root_block);
    let blocks = HashMap::from([
        (root, root_block),
        (left, left_block),
        (right, right_block),
        (shared, b"x".to_vec()),
    ]);

    assert_eq!(
        reconstruct_for_test(root, &blocks, 2, 3, 4).expect("diamond DAG"),
        b"xx"
    );
}

#[test]
fn unixfs_active_path_cycle_is_still_rejected() {
    let root = dag_pb_cid(b"cycle-key");
    let root_block = dag_pb_file_node(b"", &[(root, "cycle", 0)], Some(0));
    let blocks = HashMap::from([(root, root_block)]);

    assert!(matches!(
        reconstruct_for_test(root, &blocks, 1, 2, 1),
        Err(TrustlessArtifactError::Cycle { cid }) if cid == root
    ));
}

#[test]
fn unixfs_deep_chain_is_iterative_and_does_not_use_call_stack() {
    let (root, blocks) = unixfs_chain(2_048);
    assert_eq!(
        reconstruct_for_test(root, &blocks, 1, 2_048, 2_047).expect("deep iterative chain"),
        b"x"
    );
}

#[test]
fn unixfs_output_limit_remains_independent() {
    let (root, blocks) = repeated_link_graph(2);
    assert!(matches!(
        reconstruct_for_test(root, &blocks, 1, 2, 2),
        Err(TrustlessArtifactError::ReconstructedTooLarge { limit: 1 })
    ));
}

#[test]
fn descriptor_size_overflow_is_rejected() {
    let error = RetrievalLimits::artifact(u64::MAX).expect_err("overflowing descriptor size");

    assert!(matches!(
        error,
        TrustlessArtifactError::DescriptorByteSizeTooLarge { .. }
            | TrustlessArtifactError::RetrievalLimitOverflow
    ));
}

#[test]
fn ipns_record_accepts_bare_and_prefixed_cids() {
    let keypair = test_ipns_keypair();
    let peer_id = keypair.public().to_peer_id();
    let manifest_cid = raw_cid(b"manifest");
    let prefixed = ipns_record(&keypair, format!("/ipfs/{manifest_cid}"), 3);
    let bare = ipns_record(&keypair, manifest_cid.to_string(), 2);

    let prefixed = verify_ipns_record_candidate(&prefixed, peer_id).expect("prefixed");
    let bare = verify_ipns_record_candidate(&bare, peer_id).expect("bare");

    assert_eq!(prefixed.sequence, 3);
    assert_eq!(prefixed.cid, manifest_cid);
    assert_eq!(bare.sequence, 2);
    assert_eq!(bare.cid, manifest_cid);
}

#[test]
fn invalid_ipns_signature_is_rejected() {
    let good_keypair = test_ipns_keypair();
    let bad_keypair = Keypair::ed25519_from_bytes([8_u8; 32]).expect("bad keypair");
    let peer_id = good_keypair.public().to_peer_id();
    let record = ipns_record(&bad_keypair, raw_cid(b"manifest").to_string(), 1);

    let error = verify_ipns_record_candidate(&record, peer_id).expect_err("invalid signature");

    assert!(matches!(
        error,
        TrustlessArtifactError::InvalidIpnsSignature { .. }
    ));
}

#[test]
fn ipns_record_embedded_public_key_must_match_name() {
    let good_keypair = test_ipns_keypair();
    let bad_keypair = Keypair::ed25519_from_bytes([8_u8; 32]).expect("bad keypair");
    let peer_id = good_keypair.public().to_peer_id();
    let record =
        ipns_record_with_embedded_public_key(&bad_keypair, raw_cid(b"manifest").to_string(), 1);

    let error =
        verify_ipns_record_candidate(&record, peer_id).expect_err("wrong embedded public key");

    assert!(matches!(
        error,
        TrustlessArtifactError::IpnsPublicKeyMismatch { .. }
    ));
}

#[test]
fn authenticated_ipns_record_retains_mandatory_eol() {
    let keypair = test_ipns_keypair();
    let peer_id = keypair.public().to_peer_id();
    let record = ipns_record(&keypair, raw_cid(b"manifest").to_string(), 1);

    let candidate = verify_ipns_record_candidate(&record, peer_id).expect("authenticated EOL");

    assert!(candidate.eol > chrono::DateTime::<Utc>::from(UNIX_EPOCH));
}

#[test]
fn unsupported_ipns_value_is_rejected() {
    let keypair = test_ipns_keypair();
    let peer_id = keypair.public().to_peer_id();
    let record = ipns_record(&keypair, "/ipns/not-supported".to_string(), 1);

    let error = verify_ipns_record_candidate(&record, peer_id).expect_err("unsupported value");

    assert!(matches!(
        error,
        TrustlessArtifactError::UnsupportedIpnsValue(_)
    ));
}

#[test]
fn oversized_ipns_record_is_rejected() {
    let keypair = test_ipns_keypair();
    let peer_id = keypair.public().to_peer_id();
    let bytes = vec![0_u8; IPNS_RECORD_MAX_BYTES + 1];

    let error = verify_ipns_record_candidate(&bytes, peer_id).expect_err("oversized");

    assert!(matches!(
        error,
        TrustlessArtifactError::IpnsRecordTooLarge { .. }
    ));
}

#[tokio::test]
async fn ipns_candidates_are_sorted_and_exact_pairs_are_deduplicated() {
    let keypair = test_ipns_keypair();
    let name = ipns_name(&keypair);
    let high_cid = raw_cid(b"high");
    let low = spawn_once_server(200, ipns_record(&keypair, raw_cid(b"low").to_string(), 1));
    let high = spawn_once_server(200, ipns_record(&keypair, high_cid.to_string(), 5));
    let duplicate_high = spawn_once_server(200, ipns_record(&keypair, high_cid.to_string(), 5));
    let client = reqwest::Client::new();
    let gateways = [
        low.url.clone(),
        high.url.clone(),
        duplicate_high.url.clone(),
    ];
    let fetcher = TrustlessArtifactFetcher::new(&client, &gateways);

    let candidates = fetcher
        .resolve_ipns_manifest_candidates(&name, None)
        .await
        .expect("IPNS candidates");

    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.sequence)
            .collect::<Vec<_>>(),
        vec![5, 1]
    );
    assert_eq!(
        low.request_path(),
        format!("/ipns/{name}?format=ipns-record")
    );
    assert_eq!(
        high.request_path(),
        format!("/ipns/{name}?format=ipns-record")
    );
    assert_eq!(
        duplicate_high.request_path(),
        format!("/ipns/{name}?format=ipns-record")
    );
}

#[tokio::test]
async fn ipns_gateways_are_queried_concurrently() {
    let keypair = test_ipns_keypair();
    let name = ipns_name(&keypair);
    let blocked_cid = raw_cid(b"blocked");
    let fast_cid = raw_cid(b"fast");
    let (blocked, release) =
        spawn_blocked_once_server(200, ipns_record(&keypair, blocked_cid.to_string(), 2));
    let fast = spawn_once_server(200, ipns_record(&keypair, fast_cid.to_string(), 2));
    let blocked_url = blocked.url.clone();
    let fast_url = fast.url.clone();
    let fast_requests = fast.requests;
    let resolve = tokio::spawn(async move {
        let client = reqwest::Client::new();
        let gateways = [blocked_url, fast_url];
        TrustlessArtifactFetcher::new(&client, &gateways)
            .resolve_ipns_manifest_candidates(&name, None)
            .await
    });

    let fast_request =
        tokio::task::spawn_blocking(move || fast_requests.recv_timeout(Duration::from_secs(1)))
            .await
            .expect("fast gateway request wait");
    release.send(()).expect("release blocked gateway");
    assert!(
        fast_request.is_ok(),
        "second gateway was not queried while the first was blocked"
    );
    let candidates = resolve
        .await
        .expect("IPNS resolution task")
        .expect("IPNS candidates");
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.cid)
            .collect::<Vec<_>>(),
        vec![blocked_cid, fast_cid]
    );
}

#[tokio::test]
async fn delayed_ipns_response_crossing_eol_is_rejected_at_acceptance() {
    let keypair = test_ipns_keypair();
    let name = ipns_name(&keypair);
    let record = ipns_record_with_validity(
        &keypair,
        raw_cid(b"delayed expired IPNS").to_string(),
        3,
        chrono::Duration::seconds(1),
    );
    let (server, release) = spawn_blocked_once_server(200, record);
    let MockServer { url, requests } = server;
    let acceptance_time = std::sync::Arc::new(std::sync::Mutex::new(SystemTime::now()));
    let task_clock = std::sync::Arc::clone(&acceptance_time);
    let task = tokio::spawn(async move {
        let client = reqwest::Client::new();
        let gateways = [url];
        let now = || *task_clock.lock().expect("acceptance clock lock");
        TrustlessArtifactFetcher::new(&client, &gateways)
            .resolve_ipns_manifest_candidates_with_clock(&name, None, &now)
            .await
    });
    tokio::task::spawn_blocking(move || requests.recv_timeout(Duration::from_secs(1)))
        .await
        .expect("join delayed IPNS request wait")
        .expect("delayed IPNS request");
    *acceptance_time.lock().expect("acceptance clock lock") =
        SystemTime::now() + Duration::from_mins(1);
    release.send(()).expect("release delayed IPNS response");

    assert!(matches!(
        task.await.expect("join delayed IPNS resolution"),
        Err(TrustlessArtifactError::ExpiredIpnsRecord { .. })
    ));
}

#[tokio::test]
async fn early_ipns_candidate_expiring_while_delayed_peer_settles_is_filtered() {
    let keypair = test_ipns_keypair();
    let name = ipns_name(&keypair);
    let expired_cid = raw_cid(b"early expiring IPNS candidate");
    let current_cid = raw_cid(b"delayed current IPNS candidate");
    let early = spawn_once_server(
        200,
        ipns_record_with_validity(
            &keypair,
            expired_cid.to_string(),
            9,
            chrono::Duration::seconds(1),
        ),
    );
    let (delayed, release) = spawn_blocked_once_server(
        200,
        ipns_record_with_validity(
            &keypair,
            current_cid.to_string(),
            7,
            chrono::Duration::seconds(60 * 60 * 24 * 365),
        ),
    );
    let MockServer {
        url: early_url,
        requests: early_requests,
    } = early;
    let MockServer {
        url: delayed_url,
        requests: delayed_requests,
    } = delayed;
    let acceptance_time = std::sync::Arc::new(std::sync::Mutex::new(SystemTime::now()));
    let task_clock = std::sync::Arc::clone(&acceptance_time);
    let task = tokio::spawn(async move {
        let client = reqwest::Client::new();
        let gateways = [early_url, delayed_url];
        let now = || *task_clock.lock().expect("acceptance clock lock");
        TrustlessArtifactFetcher::new(&client, &gateways)
            .resolve_ipns_manifest_candidates_with_clock(&name, None, &now)
            .await
    });
    tokio::task::spawn_blocking(move || {
        early_requests.recv_timeout(Duration::from_secs(1))?;
        delayed_requests.recv_timeout(Duration::from_secs(1))?;
        Ok::<_, std::sync::mpsc::RecvTimeoutError>(())
    })
    .await
    .expect("join IPNS peer request wait")
    .expect("both IPNS peers received requests");
    *acceptance_time.lock().expect("acceptance clock lock") =
        SystemTime::now() + Duration::from_mins(1);
    release.send(()).expect("release delayed IPNS peer");

    let candidates = task
        .await
        .expect("join aggregate IPNS resolution")
        .expect("delayed current candidate survives");
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].sequence, 7);
    assert_eq!(candidates[0].cid, current_cid);
}

#[tokio::test]
async fn all_expired_ipns_candidates_return_redacted_expiry() {
    let keypair = test_ipns_keypair();
    let name = ipns_name(&keypair);
    let first = spawn_once_server(
        200,
        ipns_record_with_validity(
            &keypair,
            raw_cid(b"expired first").to_string(),
            5,
            chrono::Duration::seconds(-1),
        ),
    );
    let second = spawn_once_server(
        200,
        ipns_record_with_validity(
            &keypair,
            raw_cid(b"expired second").to_string(),
            6,
            chrono::Duration::seconds(-1),
        ),
    );
    let gateways = [
        sensitive_server_url(first.url.clone()),
        sensitive_server_url(second.url.clone()),
    ];
    let client = reqwest::Client::new();
    let accepted_at = SystemTime::now() + Duration::from_mins(1);
    let pool = GatewayPool::new();

    let error = TrustlessArtifactFetcher::new_poi_with_pool(&client, &gateways, pool.clone())
        .resolve_ipns_manifest_candidates_with_clock(&name, None, &|| accepted_at)
        .await
        .expect_err("all authenticated candidates expired before acceptance");

    assert!(matches!(
        &error,
        TrustlessArtifactError::ExpiredIpnsRecord { .. }
    ));
    assert_artifact_error_safe(&error);
    let ids = gateways
        .iter()
        .map(|gateway| opaque_gateway_id(gateway.expose_url()))
        .collect::<Vec<_>>();
    for (index, gateway) in gateways.iter().enumerate() {
        assert_eq!(
            gateway_health(&pool, gateway.expose_url(), GatewayCapability::IpnsRecord),
            (1, 0),
            "an expired record is an IPNS failure"
        );
        assert_eq!(gateway_wide_failures(&pool, gateway.expose_url()), 0);
        assert_eq!(
            pool.select(&ids, GatewayCapability::ArtifactCar, Some(index))
                .expect("artifact gateway")
                .index,
            index,
            "the gateway stays eligible for artifacts"
        );
    }
}

#[tokio::test]
async fn mixed_expired_and_current_ipns_candidates_keep_only_current_records() {
    let keypair = test_ipns_keypair();
    let name = ipns_name(&keypair);
    let expired_cid = raw_cid(b"expired high-sequence candidate");
    let current_cid = raw_cid(b"current lower-sequence candidate");
    let expired = spawn_once_server(
        200,
        ipns_record_with_validity(
            &keypair,
            expired_cid.to_string(),
            20,
            chrono::Duration::seconds(1),
        ),
    );
    let current = spawn_once_server(
        200,
        ipns_record_with_validity(
            &keypair,
            current_cid.to_string(),
            10,
            chrono::Duration::seconds(60 * 60 * 24 * 365),
        ),
    );
    let gateways = [expired.url.clone(), current.url.clone()];
    let client = reqwest::Client::new();
    let accepted_at = SystemTime::now() + Duration::from_mins(1);
    let samples = std::sync::atomic::AtomicUsize::new(0);

    let candidates = TrustlessArtifactFetcher::new(&client, &gateways)
        .resolve_ipns_manifest_candidates_with_clock(&name, None, &|| {
            samples.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            accepted_at
        })
        .await
        .expect("current candidate remains after aggregate expiry filtering");

    // One arrival read per verified record decides when to stop waiting,
    // then exactly one acceptance sample filters the closed phase.
    assert_eq!(samples.load(std::sync::atomic::Ordering::SeqCst), 3);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].sequence, 10);
    assert_eq!(candidates[0].cid, current_cid);
}

#[tokio::test]
async fn ipns_resolution_uses_valid_gateway_when_one_fails() {
    let keypair = test_ipns_keypair();
    let name = ipns_name(&keypair);
    let failing = spawn_once_server(500, Vec::new());
    let valid = spawn_once_server(200, ipns_record(&keypair, raw_cid(b"ok").to_string(), 2));
    let client = reqwest::Client::new();
    let gateways = [failing.url.clone(), valid.url.clone()];
    let fetcher = TrustlessArtifactFetcher::new(&client, &gateways);

    let candidates = fetcher
        .resolve_ipns_manifest_candidates(&name, None)
        .await
        .expect("valid second gateway");

    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].sequence, 2);
}

#[tokio::test]
async fn ipns_healthy_phase_skips_precooled_gateway_when_current_record_exists() {
    let keypair = test_ipns_keypair();
    let name = ipns_name(&keypair);
    let cid = raw_cid(b"healthy IPNS phase");
    let pre_cooled = spawn_controlled_chunk_server();
    let healthy = spawn_controlled_chunk_server();
    let gateways = [pre_cooled.url.clone(), healthy.url.clone()];
    let ids = gateways.iter().map(opaque_gateway_id).collect::<Vec<_>>();
    let pool = GatewayPool::new();
    pool.select(&ids, GatewayCapability::IpnsRecord, Some(0))
        .expect("pre-cool gateway")
        .failure(&capability_failure());
    let task = tokio::spawn(async move {
        TrustlessArtifactFetcher::new_with_pool(&reqwest::Client::new(), &gateways, pool)
            .resolve_ipns_manifest_candidates(&name, None)
            .await
    });

    healthy.wait_for_request().await;
    healthy.send_headers(200);
    healthy.send_chunk(ipns_record(&keypair, format!("/ipfs/{cid}"), 4));
    healthy.finish();

    let candidates = task
        .await
        .expect("join healthy IPNS phase")
        .expect("current healthy record");
    assert_eq!(candidates[0].cid, cid);
    pre_cooled.assert_no_request();
}

#[tokio::test]
async fn ipns_fallback_phase_queries_precooled_gateway_after_healthy_failure() {
    let keypair = test_ipns_keypair();
    let name = ipns_name(&keypair);
    let cid = raw_cid(b"fallback IPNS phase");
    let pre_cooled = spawn_controlled_chunk_server();
    let failing = spawn_controlled_chunk_server();
    let gateways = [pre_cooled.url.clone(), failing.url.clone()];
    let ids = gateways.iter().map(opaque_gateway_id).collect::<Vec<_>>();
    let pool = GatewayPool::new();
    pool.select(&ids, GatewayCapability::IpnsRecord, Some(0))
        .expect("pre-cool gateway")
        .failure(&capability_failure());
    let task = tokio::spawn(async move {
        TrustlessArtifactFetcher::new_with_pool(&reqwest::Client::new(), &gateways, pool)
            .resolve_ipns_manifest_candidates(&name, None)
            .await
    });

    failing.wait_for_request().await;
    failing.send_headers(503);
    failing.finish();
    pre_cooled.wait_for_request().await;
    pre_cooled.send_headers(200);
    pre_cooled.send_chunk(ipns_record(&keypair, format!("/ipfs/{cid}"), 9));
    pre_cooled.finish();

    let candidates = task
        .await
        .expect("join fallback IPNS phase")
        .expect("current fallback record");
    assert_eq!(candidates[0].cid, cid);
    assert_eq!(candidates[0].sequence, 9);
}

#[tokio::test(start_paused = true)]
async fn ipns_phase_closes_after_grace_window_without_failing_stalled_gateways() {
    let keypair = test_ipns_keypair();
    let name = ipns_name(&keypair);
    let cid = raw_cid(b"early-close IPNS candidate");
    let servers = (0..3)
        .map(|_| spawn_controlled_chunk_server())
        .collect::<Vec<_>>();
    let gateways = servers
        .iter()
        .map(|server| server.url.clone())
        .collect::<Vec<_>>();
    let pool = GatewayPool::new();
    let (task, clock_reads) = spawn_ipns_resolution(gateways.clone(), pool.clone(), name, None);

    for server in &servers {
        server.wait_for_request().await;
    }
    servers[0].send_headers(200);
    servers[0].send_chunk(ipns_record(&keypair, format!("/ipfs/{cid}"), 4));
    servers[0].finish();
    yield_until("the fast record arrives", || {
        clock_reads.load(Ordering::SeqCst) == 1
    })
    .await;
    tokio::time::advance(
        IPNS_EARLY_CLOSE_GRACE
            .checked_sub(Duration::from_millis(1))
            .expect("grace window exceeds one millisecond"),
    )
    .await;
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    assert!(!task.is_finished(), "the phase waits for the grace window");
    tokio::time::advance(Duration::from_millis(1)).await;

    let candidates = join_without_auto_advance(task)
        .await
        .expect("fast record is returned");
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].cid, cid);
    for gateway in &gateways[1..] {
        assert_eq!(
            gateway_health(&pool, gateway, GatewayCapability::IpnsRecord),
            (0, 0),
            "a cancelled attempt is released without a recorded failure"
        );
        assert_eq!(gateway_wide_failures(&pool, gateway), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn ipns_higher_sequence_inside_grace_window_is_ordered_first() {
    let keypair = test_ipns_keypair();
    let name = ipns_name(&keypair);
    let low_cid = raw_cid(b"first IPNS candidate");
    let high_cid = raw_cid(b"higher IPNS candidate");
    let servers = (0..=MAX_CONCURRENT_IPNS_GATEWAY_REQUESTS)
        .map(|_| spawn_controlled_chunk_server())
        .collect::<Vec<_>>();
    let gateways = servers
        .iter()
        .map(|server| server.url.clone())
        .collect::<Vec<_>>();
    let (task, clock_reads) = spawn_ipns_resolution(gateways, GatewayPool::new(), name, None);

    // The first batch fills every concurrent slot. Pool selection, not
    // configured order, decides which gateway waits for a free slot.
    let mut requested = vec![false; servers.len()];
    yield_until("every concurrent slot holds a request", || {
        for (server, seen) in servers.iter().zip(&mut requested) {
            *seen |= server.requests.try_recv().is_ok();
        }
        requested.iter().filter(|seen| **seen).count() == MAX_CONCURRENT_IPNS_GATEWAY_REQUESTS
    })
    .await;
    let late = requested
        .iter()
        .position(|seen| !seen)
        .expect("one gateway waits for a free slot");
    for (_, server) in servers
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != late)
    {
        server.send_headers(200);
        server.send_chunk(ipns_record(&keypair, format!("/ipfs/{low_cid}"), 4));
        server.finish();
    }
    // Paused time has not moved since the first record armed the grace
    // deadline, so the freed slot must be refilled before it.
    yield_until(
        "the waiting gateway is queried inside the grace window",
        || servers[late].requests.try_recv().is_ok(),
    )
    .await;
    yield_until("every first-batch record arrives", || {
        clock_reads.load(Ordering::SeqCst) == MAX_CONCURRENT_IPNS_GATEWAY_REQUESTS
    })
    .await;
    assert!(!task.is_finished(), "the phase waits for the late gateway");
    tokio::time::advance(IPNS_EARLY_CLOSE_GRACE / 2).await;
    servers[late].send_headers(200);
    servers[late].send_chunk(ipns_record(&keypair, format!("/ipfs/{high_cid}"), 5));
    servers[late].finish();

    let candidates = join_without_auto_advance(task)
        .await
        .expect("both records are returned");
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| (candidate.sequence, candidate.cid))
            .collect::<Vec<_>>(),
        vec![(5, high_cid), (4, low_cid)]
    );
}

#[tokio::test(start_paused = true)]
async fn ipns_record_below_sequence_floor_does_not_close_phase() {
    let keypair = test_ipns_keypair();
    let name = ipns_name(&keypair);
    let lagging = spawn_controlled_chunk_server();
    let slower = spawn_controlled_chunk_server();
    let gateways = vec![lagging.url.clone(), slower.url.clone()];
    let (task, clock_reads) = spawn_ipns_resolution(gateways, GatewayPool::new(), name, Some(5));

    lagging.wait_for_request().await;
    slower.wait_for_request().await;
    lagging.send_headers(200);
    lagging.send_chunk(ipns_record(
        &keypair,
        format!("/ipfs/{}", raw_cid(b"lagging IPNS candidate")),
        3,
    ));
    lagging.finish();
    yield_until("the lagging record arrives", || {
        clock_reads.load(Ordering::SeqCst) == 1
    })
    .await;
    tokio::time::advance(IPNS_EARLY_CLOSE_GRACE * 2).await;
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    assert!(
        !task.is_finished(),
        "a record below the floor does not close the phase"
    );
    slower.send_headers(200);
    slower.send_chunk(ipns_record(
        &keypair,
        format!("/ipfs/{}", raw_cid(b"slower IPNS candidate")),
        4,
    ));
    slower.finish();

    let candidates = join_without_auto_advance(task)
        .await
        .expect("settled records are returned");
    assert_eq!(
        candidates
            .iter()
            .map(|candidate| candidate.sequence)
            .collect::<Vec<_>>(),
        vec![4, 3]
    );
}

#[tokio::test(start_paused = true)]
async fn manifest_fetch_starts_at_gateway_whose_ipns_record_arrived_first() {
    let keypair = test_ipns_keypair();
    let name = ipns_name(&keypair);
    let bytes = b"manifest from the IPNS record gateway".to_vec();
    let cid = raw_cid(&bytes);
    let listeners = (0..2)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").expect("bind gateway"))
        .collect::<Vec<_>>();
    let ipns_servers = listeners
        .iter()
        .map(|listener| {
            spawn_controlled_chunk_server_on(listener.try_clone().expect("clone listener"))
        })
        .collect::<Vec<_>>();
    let gateways = ipns_servers
        .iter()
        .map(|server| server.url.clone())
        .collect::<Vec<_>>();
    // The pool ranks gateway 0 first for every capability.
    let pool = pool_for_gateway_order(&gateways, &[0, 1]);
    let (task, clock_reads) = spawn_ipns_resolution(gateways.clone(), pool.clone(), name, None);

    for server in &ipns_servers {
        server.wait_for_request().await;
    }
    // Gateway 1's record arrives first; gateway 0 later returns the same
    // record, which sorts ahead of it by gateway index.
    for (server, arrivals) in ipns_servers.iter().rev().zip(1..) {
        server.send_headers(200);
        server.send_chunk(ipns_record(&keypair, format!("/ipfs/{cid}"), 4));
        server.finish();
        yield_until("the record arrives", || {
            clock_reads.load(Ordering::SeqCst) >= arrivals
        })
        .await;
    }
    let candidates = join_without_auto_advance(task)
        .await
        .expect("IPNS candidates");
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].gateway_index(), 1);

    let manifest_servers = listeners
        .into_iter()
        .map(spawn_controlled_chunk_server_on)
        .collect::<Vec<_>>();
    let preferred_gateway_index = candidates[0].gateway_index();
    let task = tokio::spawn(async move {
        TrustlessArtifactFetcher::new_with_pool(&reqwest::Client::new(), &gateways, pool)
            .fetch_manifest_cid_with_metadata_from_gateway(
                &cid.to_string(),
                Some(preferred_gateway_index),
            )
            .await
    });

    let mut first_request = None;
    yield_until("a gateway receives the manifest request", || {
        first_request = manifest_servers
            .iter()
            .enumerate()
            .find_map(|(index, server)| server.requests.try_recv().ok().map(|path| (index, path)));
        first_request.is_some()
    })
    .await;
    assert_eq!(first_request, Some((1, format!("/ipfs/{cid}?format=raw"))));
    manifest_servers[1].send_headers(200);
    manifest_servers[1].send_chunk(bytes.clone());
    manifest_servers[1].finish();
    let fetched = join_without_auto_advance(task)
        .await
        .expect("manifest from the record's gateway");
    assert_eq!(fetched.bytes(), bytes);
    assert_eq!(fetched.gateway_index(), 1);
    manifest_servers[0].assert_no_request();
}

fn spawn_ipns_resolution(
    gateways: Vec<Url>,
    pool: GatewayPool,
    name: String,
    sequence_floor: Option<u64>,
) -> (
    tokio::task::JoinHandle<Result<Vec<IpnsManifestCandidate>, TrustlessArtifactError>>,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    let clock_reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let task_clock_reads = Arc::clone(&clock_reads);
    let task = tokio::spawn(async move {
        let now = move || {
            task_clock_reads.fetch_add(1, Ordering::SeqCst);
            SystemTime::now()
        };
        TrustlessArtifactFetcher::new_with_pool(&reqwest::Client::new(), &gateways, pool)
            .resolve_ipns_manifest_candidates_with_clock(&name, sequence_floor, &now)
            .await
    });
    (task, clock_reads)
}

#[tokio::test]
async fn artifact_fetch_starts_from_preferred_gateway() {
    let artifact_bytes = b"preferred gateway artifact".to_vec();
    let cid = raw_cid(&artifact_bytes);
    let skipped = spawn_once_server(503, Vec::new());
    let preferred = spawn_once_server(200, car_bytes(cid, &[(cid, artifact_bytes.clone())]));
    let client = reqwest::Client::new();
    let gateways = [skipped.url.clone(), preferred.url.clone()];

    let fetched = TrustlessArtifactFetcher::new(&client, &gateways)
        .fetch_artifact_cid_with_metadata_from_gateway(
            &cid.to_string(),
            artifact_bytes.len() as u64,
            3,
        )
        .await
        .expect("fetch from preferred gateway");

    assert_eq!(fetched.bytes, artifact_bytes);
    assert_eq!(fetched.gateway_index, 1);
    assert_eq!(fetched.gateway_count, 2);
    assert_eq!(
        preferred.request_path(),
        format!("/ipfs/{cid}?format=car&dag-scope=entity")
    );
    assert!(
        skipped
            .requests
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "earlier gateway should not be contacted before preferred gateway succeeds"
    );
}

#[tokio::test]
async fn artifact_gateway_fallback_honors_bounded_attempt_count() {
    let cid = raw_cid(b"bounded gateway artifact");
    let skipped_before = spawn_once_server(503, Vec::new());
    let first = spawn_once_server(503, Vec::new());
    let second = spawn_once_server(503, Vec::new());
    let skipped_after = spawn_once_server(503, Vec::new());
    let client = reqwest::Client::new();
    let gateways = [
        skipped_before.url.clone(),
        first.url.clone(),
        second.url.clone(),
        skipped_after.url.clone(),
    ];

    TrustlessArtifactFetcher::new(&client, &gateways)
        .fetch_artifact_cid_with_metadata_from_gateway_bounded(&cid.to_string(), 24, 1, 2)
        .await
        .expect_err("two failed attempts exhaust the bound");

    let expected = format!("/ipfs/{cid}?format=car&dag-scope=entity");
    assert_eq!(first.request_path(), expected);
    let fallback_attempts = [&skipped_before, &second, &skipped_after]
        .into_iter()
        .filter(|server| {
            server
                .requests
                .recv_timeout(Duration::from_millis(100))
                .is_ok()
        })
        .count();
    assert_eq!(
        fallback_attempts, 1,
        "the bounded fetch made one fallback attempt"
    );
}

#[tokio::test]
async fn public_verified_cid_fetch_accepts_matching_bytes_and_rejects_tampering() {
    let bytes = b"verified manifest bytes".to_vec();
    let cid = raw_cid(&bytes);
    let valid = spawn_once_server(200, bytes.clone());
    let client = reqwest::Client::new();
    let gateways = [valid.url.clone()];

    assert_eq!(
        fetch_verified_cid(&client, &gateways, &cid.to_string())
            .await
            .expect("matching CID bytes pass"),
        bytes
    );
    assert_eq!(valid.request_path(), format!("/ipfs/{cid}?format=raw"));

    let tampered = spawn_once_server(200, b"tampered".to_vec());
    let error = fetch_verified_cid(
        &client,
        std::slice::from_ref(&tampered.url),
        &cid.to_string(),
    )
    .await
    .expect_err("tampered bytes are rejected");
    assert_eq!(error.to_string(), "verified CID fetch failed");
    assert!(error.source().is_some());
}

#[tokio::test]
async fn public_verified_cid_fetch_supports_blake2b_256_raw_bytes() {
    let bytes = b"blake2b raw bytes".to_vec();
    let cid = blake2b_256_cid(&bytes);
    let valid = spawn_once_server(200, bytes.clone());
    let client = reqwest::Client::new();

    assert_eq!(
        fetch_verified_cid(&client, std::slice::from_ref(&valid.url), &cid.to_string())
            .await
            .expect("matching BLAKE2b-256 CID bytes pass"),
        bytes
    );
    assert_eq!(valid.request_path(), format!("/ipfs/{cid}?format=raw"));

    let tampered = spawn_once_server(200, b"tampered".to_vec());
    let error = fetch_verified_cid(
        &client,
        std::slice::from_ref(&tampered.url),
        &cid.to_string(),
    )
    .await
    .expect_err("tampered BLAKE2b-256 bytes are rejected");
    assert!(matches!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<TrustlessArtifactError>()),
        Some(TrustlessArtifactError::RawCidDigestMismatch { cid: actual })
            if actual == &cid
    ));
}

#[tokio::test]
async fn public_verified_cid_fetch_supports_identity_raw_bytes() {
    let bytes = b"identity raw bytes".to_vec();
    let cid = identity_cid(&bytes);
    let valid = spawn_once_server(200, bytes.clone());
    let client = reqwest::Client::new();

    assert_eq!(
        fetch_verified_cid(&client, std::slice::from_ref(&valid.url), &cid.to_string())
            .await
            .expect("matching identity CID bytes pass"),
        bytes
    );
    assert_eq!(valid.request_path(), format!("/ipfs/{cid}?format=raw"));

    let tampered = spawn_once_server(200, b"tampered".to_vec());
    let error = fetch_verified_cid(
        &client,
        std::slice::from_ref(&tampered.url),
        &cid.to_string(),
    )
    .await
    .expect_err("tampered identity bytes are rejected");
    assert!(matches!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<TrustlessArtifactError>()),
        Some(TrustlessArtifactError::RawCidDigestMismatch { cid: actual })
            if actual == &cid
    ));
}

#[tokio::test]
async fn public_verified_cid_fetch_rejects_unsupported_raw_multihash_before_request() {
    let gateway = spawn_controlled_chunk_server();
    let cid = cid_with_digest(0x13, &[0; 64]);
    let error = fetch_verified_cid(
        &reqwest::Client::new(),
        std::slice::from_ref(&gateway.url),
        &cid.to_string(),
    )
    .await
    .expect_err("unsupported raw multihash is rejected");

    assert!(matches!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<TrustlessArtifactError>()),
        Some(TrustlessArtifactError::UnsupportedMultihash { code: 0x13, .. })
    ));
    gateway.assert_no_request();
}

#[tokio::test]
async fn public_verified_cid_fetch_reconstructs_dag_pb_from_car() {
    let leaf = raw_cid(b"dag-pb payload");
    let root_block = dag_pb_file_node(b"", &[(leaf, "payload", 14)], Some(14));
    let root = dag_pb_cid(&root_block);
    let gateway = spawn_once_server(
        200,
        car_bytes(
            root,
            &[(root, root_block), (leaf, b"dag-pb payload".to_vec())],
        ),
    );
    let client = reqwest::Client::new();

    assert_eq!(
        fetch_verified_cid(
            &client,
            std::slice::from_ref(&gateway.url),
            &root.to_string()
        )
        .await
        .expect("DAG-PB CAR reconstructs"),
        b"dag-pb payload"
    );
    assert_eq!(
        gateway.request_path(),
        format!("/ipfs/{root}?format=car&dag-scope=entity")
    );
}

#[tokio::test(start_paused = true)]
async fn manifest_cid_fetch_hedges_slow_first_gateway_and_reports_winner() {
    let bytes = b"hedged verified bytes".to_vec();
    let cid = raw_cid(&bytes);
    let slow = spawn_controlled_chunk_server();
    let healthy = spawn_controlled_chunk_server();
    let gateways = [slow.url.clone(), healthy.url.clone()];
    let pool = pool_for_gateway_order(&gateways, &[0, 1]);
    let task = tokio::spawn(async move {
        TrustlessArtifactFetcher::new_with_pool(&reqwest::Client::new(), &gateways, pool)
            .fetch_manifest_cid_with_metadata(&cid.to_string())
            .await
    });

    assert_eq!(
        slow.wait_for_request().await,
        format!("/ipfs/{cid}?format=raw")
    );
    tokio::time::advance(MANIFEST_CID_HEDGE_DELAY).await;
    assert_eq!(
        healthy.wait_for_request().await,
        format!("/ipfs/{cid}?format=raw")
    );
    healthy.send_headers(200);
    healthy.send_chunk(bytes.clone());
    healthy.finish();

    let fetched = task
        .await
        .expect("join hedged fetch")
        .expect("healthy gateway");
    assert_eq!(fetched.bytes(), bytes);
    assert_eq!(fetched.gateway_index(), 1);
    assert_eq!(fetched.gateway_count(), 2);

    // Release the stalled server thread after the successful request cancels its future.
    slow.send_headers(500);
}

#[tokio::test(start_paused = true)]
async fn public_verified_cid_fetch_launches_fallback_immediately_after_full_pool_failure() {
    let bytes = b"fallback verified bytes".to_vec();
    let cid = raw_cid(&bytes);
    let servers = (0..4)
        .map(|_| spawn_controlled_chunk_server())
        .collect::<Vec<_>>();
    let gateways = servers
        .iter()
        .map(|server| server.url.clone())
        .collect::<Vec<_>>();
    let pool = pool_for_gateway_order(&gateways, &[0, 1, 2, 3]);
    let cid_string = cid.to_string();
    let task = tokio::spawn(async move {
        TrustlessArtifactFetcher::new_with_pool(&reqwest::Client::new(), &gateways, pool)
            .fetch_manifest_cid(&cid_string)
            .await
    });

    let expected_path = format!("/ipfs/{cid}?format=raw");
    assert_eq!(servers[0].wait_for_request().await, expected_path);
    tokio::time::advance(MANIFEST_CID_HEDGE_DELAY).await;
    assert_eq!(servers[1].wait_for_request().await, expected_path);
    tokio::time::advance(MANIFEST_CID_HEDGE_DELAY).await;
    assert_eq!(servers[2].wait_for_request().await, expected_path);
    servers[3].assert_no_request();

    let failure_at = tokio::time::Instant::now();
    servers[2].send_headers(500);
    servers[2].finish();
    assert_eq!(servers[3].wait_for_request().await, expected_path);
    assert_eq!(tokio::time::Instant::now(), failure_at);

    servers[3].send_headers(200);
    servers[3].send_chunk(bytes);
    servers[3].finish();
    assert_eq!(
        task.await
            .expect("join fallback fetch")
            .expect("fallback gateway succeeds"),
        b"fallback verified bytes"
    );

    // Release the stalled server threads after the successful request cancels their futures.
    servers[0].send_headers(500);
    servers[1].send_headers(500);
}

#[tokio::test(start_paused = true)]
async fn manifest_cid_fetch_starts_every_gateway_while_earlier_attempts_stall() {
    let bytes = b"fourth gateway manifest".to_vec();
    let cid = raw_cid(&bytes);
    let servers = (0..4)
        .map(|_| spawn_controlled_chunk_server())
        .collect::<Vec<_>>();
    let gateways = servers
        .iter()
        .map(|server| server.url.clone())
        .collect::<Vec<_>>();
    let pool = pool_for_gateway_order(&gateways, &[0, 1, 2, 3]);
    let task = {
        let gateways = gateways.clone();
        let pool = pool.clone();
        tokio::spawn(async move {
            TrustlessArtifactFetcher::new_with_pool(&reqwest::Client::new(), &gateways, pool)
                .fetch_manifest_cid_with_metadata(&cid.to_string())
                .await
        })
    };

    let expected_path = format!("/ipfs/{cid}?format=raw");
    assert_eq!(servers[0].wait_for_request().await, expected_path);
    tokio::time::advance(MANIFEST_CID_HEDGE_DELAY).await;
    assert_eq!(servers[1].wait_for_request().await, expected_path);
    tokio::time::advance(MANIFEST_CID_HEDGE_DELAY).await;
    assert_eq!(servers[2].wait_for_request().await, expected_path);
    servers[3].assert_no_request();
    tokio::time::advance(MANIFEST_CID_HEDGE_DELAY).await;
    assert_eq!(servers[3].wait_for_request().await, expected_path);
    servers[3].send_headers(200);
    servers[3].send_chunk(bytes.clone());
    servers[3].finish();

    let fetched = join_without_auto_advance(task)
        .await
        .expect("fourth gateway succeeds");
    assert_eq!(fetched.bytes(), bytes);
    assert_eq!(fetched.gateway_index(), 3);
    for gateway in &gateways {
        assert_eq!(
            gateway_health(&pool, gateway, GatewayCapability::ManifestCid),
            (0, 0),
            "attempts are released without recorded failures"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn chunk_fetch_hedges_stalled_gateway_and_logs_indices_only() {
    let events = CapturedEvents::default();
    let _capture = events.capture();
    let artifact_bytes = b"hedged chunk artifact".to_vec();
    let cid = raw_cid(&artifact_bytes);
    let stalled = spawn_controlled_chunk_server();
    let hedge = spawn_controlled_chunk_server();
    let gateways = vec![
        sensitive_server_url(stalled.url.clone()),
        sensitive_server_url(hedge.url.clone()),
    ];
    let pool = GatewayPool::new();
    let budget = Arc::new(());
    let task = spawn_hedged_chunk_fetch(gateways.clone(), pool.clone(), &artifact_bytes, {
        let budget = Arc::clone(&budget);
        move || Some(budget)
    });

    stalled.wait_for_request().await;
    tokio::time::advance(CHUNK_HEDGE_DELAY).await;
    hedge.wait_for_request().await;
    hedge.send_headers(200);
    hedge.send_chunk(car_bytes(cid, &[(cid, artifact_bytes.clone())]));
    hedge.finish();

    let fetched = join_without_auto_advance(task)
        .await
        .expect("hedged gateway succeeds");
    assert_eq!(fetched.bytes(), artifact_bytes);
    assert_eq!(fetched.gateway_index(), 1);
    assert_eq!(Arc::strong_count(&budget), 1, "hedge guard is released");
    assert_eq!(
        gateway_health(
            &pool,
            gateways[0].expose_url(),
            GatewayCapability::ArtifactCar
        ),
        (0, 0),
        "the cancelled attempt is released without a recorded failure"
    );

    let started = events.find("artifact chunk hedge started");
    assert_eq!(started["cid"], cid.to_string());
    assert_eq!(started["first_gateway_index"], "0");
    assert_eq!(started["hedge_gateway_index"], "1");
    assert_eq!(
        started["elapsed_ms"],
        CHUNK_HEDGE_DELAY.as_millis().to_string()
    );
    let completed = events.find("hedged artifact chunk fetch completed");
    assert_eq!(completed["cid"], cid.to_string());
    assert_eq!(completed["first_gateway_index"], "0");
    assert_eq!(completed["hedge_gateway_index"], "1");
    assert_eq!(completed["winner_gateway_index"], "1");
    assert!(completed.contains_key("elapsed_ms"));
    let mut forbidden = vec!["endpoint-sentinel".to_owned()];
    for gateway in &gateways {
        let url = gateway.expose_url();
        forbidden.push(format!("127.0.0.1:{}", url.port().expect("server port")));
        forbidden.push(opaque_gateway_id(url).to_string());
    }
    for event in events.events() {
        for value in event.values() {
            assert!(
                forbidden
                    .iter()
                    .all(|needle| !value.contains(needle.as_str())),
                "log value {value:?} exposes a gateway"
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn chunk_fetch_does_not_hedge_gateway_that_sent_headers() {
    let artifact_bytes = b"slow but progressing chunk".to_vec();
    let cid = raw_cid(&artifact_bytes);
    let body = car_bytes(cid, &[(cid, artifact_bytes.clone())]);
    let (body_head, body_tail) = body.split_at(body.len() / 2);
    let prompt = spawn_controlled_chunk_server();
    let spare = spawn_controlled_chunk_server();
    let gateways = vec![
        sensitive_server_url(prompt.url.clone()),
        sensitive_server_url(spare.url.clone()),
    ];
    let task = spawn_hedged_chunk_fetch(
        gateways,
        GatewayPool::new(),
        &artifact_bytes,
        || -> Option<()> { panic!("a gateway that sent headers must not be hedged") },
    );

    prompt.wait_for_request().await;
    prompt.send_headers(200);
    prompt.send_chunk(body_head.to_vec());
    // Let the client read the headers before the hedge delay elapses.
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(CHUNK_HEDGE_DELAY * 2).await;
    prompt.send_chunk(body_tail.to_vec());
    prompt.finish();

    let fetched = join_without_auto_advance(task)
        .await
        .expect("prompt gateway succeeds");
    assert_eq!(fetched.bytes(), artifact_bytes);
    assert_eq!(fetched.gateway_index(), 0);
    spare.assert_no_request();
}

#[tokio::test(start_paused = true)]
async fn chunk_fetch_falls_back_immediately_after_early_failure() {
    let artifact_bytes = b"early fallback chunk".to_vec();
    let cid = raw_cid(&artifact_bytes);
    let failing = spawn_controlled_chunk_server();
    let healthy = spawn_controlled_chunk_server();
    let gateways = vec![
        sensitive_server_url(failing.url.clone()),
        sensitive_server_url(healthy.url.clone()),
    ];
    let pool = GatewayPool::new();
    let task =
        spawn_hedged_chunk_fetch(gateways.clone(), pool.clone(), &artifact_bytes, || Some(()));

    failing.wait_for_request().await;
    let failure_at = tokio::time::Instant::now();
    failing.send_headers(503);
    failing.finish();
    healthy.wait_for_request().await;
    assert_eq!(tokio::time::Instant::now(), failure_at);
    healthy.send_headers(200);
    healthy.send_chunk(car_bytes(cid, &[(cid, artifact_bytes.clone())]));
    healthy.finish();

    let fetched = join_without_auto_advance(task)
        .await
        .expect("fallback gateway succeeds");
    assert_eq!(fetched.gateway_index(), 1);
    assert_eq!(
        gateway_health(
            &pool,
            gateways[0].expose_url(),
            GatewayCapability::ArtifactCar
        ),
        (1, 0),
        "the early failure updates gateway health"
    );
}

#[tokio::test(start_paused = true)]
async fn chunk_fetch_rejects_mismatched_hedge_body_as_gateway_failure() {
    let artifact_bytes = b"verified chunk".to_vec();
    let cid = raw_cid(&artifact_bytes);
    let slow = spawn_controlled_chunk_server();
    let tampered = spawn_controlled_chunk_server();
    let gateways = vec![
        sensitive_server_url(slow.url.clone()),
        sensitive_server_url(tampered.url.clone()),
    ];
    let pool = GatewayPool::new();
    let task =
        spawn_hedged_chunk_fetch(gateways.clone(), pool.clone(), &artifact_bytes, || Some(()));

    slow.wait_for_request().await;
    tokio::time::advance(CHUNK_HEDGE_DELAY).await;
    tampered.wait_for_request().await;
    tampered.send_headers(200);
    tampered.send_chunk(car_bytes(cid, &[(cid, b"tampered".to_vec())]));
    tampered.finish();
    yield_until("hedge failure is recorded", || {
        gateway_health(
            &pool,
            gateways[1].expose_url(),
            GatewayCapability::ArtifactCar,
        )
        .0 == 1
    })
    .await;
    slow.send_headers(200);
    slow.send_chunk(car_bytes(cid, &[(cid, artifact_bytes.clone())]));
    slow.finish();

    let fetched = join_without_auto_advance(task)
        .await
        .expect("first gateway still succeeds");
    assert_eq!(fetched.bytes(), artifact_bytes);
    assert_eq!(fetched.gateway_index(), 0);
    assert_eq!(
        gateway_health(
            &pool,
            gateways[1].expose_url(),
            GatewayCapability::ArtifactCar
        ),
        (1, 0)
    );
    assert_eq!(
        gateway_health(
            &pool,
            gateways[0].expose_url(),
            GatewayCapability::ArtifactCar
        ),
        (0, 0)
    );
}

#[tokio::test(start_paused = true)]
async fn chunk_fetch_vetoed_hedge_starts_no_attempt() {
    let artifact_bytes = b"vetoed hedge chunk".to_vec();
    let cid = raw_cid(&artifact_bytes);
    let slow = spawn_controlled_chunk_server();
    let spare = spawn_controlled_chunk_server();
    let gateways = vec![
        sensitive_server_url(slow.url.clone()),
        sensitive_server_url(spare.url.clone()),
    ];
    let pool = GatewayPool::new();
    let admissions = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let task = spawn_hedged_chunk_fetch(gateways.clone(), pool.clone(), &artifact_bytes, {
        let admissions = Arc::clone(&admissions);
        move || {
            admissions.fetch_add(1, Ordering::SeqCst);
            None::<()>
        }
    });

    slow.wait_for_request().await;
    tokio::time::advance(CHUNK_HEDGE_DELAY).await;
    yield_until("hedge admission is requested", || {
        admissions.load(Ordering::SeqCst) == 1
    })
    .await;
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
    spare.assert_no_request();
    slow.send_headers(200);
    slow.send_chunk(car_bytes(cid, &[(cid, artifact_bytes.clone())]));
    slow.finish();

    let fetched = join_without_auto_advance(task)
        .await
        .expect("first gateway continues after veto");
    assert_eq!(fetched.gateway_index(), 0);
    assert_eq!(admissions.load(Ordering::SeqCst), 1);
    assert_eq!(
        gateway_health(
            &pool,
            gateways[1].expose_url(),
            GatewayCapability::ArtifactCar
        ),
        (0, 0),
        "the vetoed hedge reservation is released"
    );
}

#[tokio::test(start_paused = true)]
async fn catalog_fetch_hedges_stalled_gateways_and_logs_indices_only() {
    let events = CapturedEvents::default();
    let _capture = events.capture();
    let artifact_bytes = b"hedged catalog artifact".to_vec();
    let cid = raw_cid(&artifact_bytes);
    let servers = (0..3)
        .map(|_| spawn_controlled_chunk_server())
        .collect::<Vec<_>>();
    let gateways = servers
        .iter()
        .map(|server| sensitive_server_url(server.url.clone()))
        .collect::<Vec<_>>();
    let pool = pool_for_sensitive_gateway_order(&gateways, &[0, 1, 2]);
    let started = tokio::time::Instant::now();
    let task = spawn_catalog_fetch(gateways.clone(), pool.clone(), &artifact_bytes, 3);

    servers[0].wait_for_request().await;
    tokio::time::advance(CATALOG_HEDGE_DELAY).await;
    servers[1].wait_for_request().await;
    tokio::time::advance(CATALOG_HEDGE_DELAY).await;
    servers[2].wait_for_request().await;
    servers[2].send_headers(200);
    servers[2].send_chunk(car_bytes(cid, &[(cid, artifact_bytes.clone())]));
    servers[2].finish();

    let fetched = join_without_auto_advance(task)
        .await
        .expect("third gateway succeeds");
    assert_eq!(started.elapsed(), CATALOG_HEDGE_DELAY * 2);
    assert_eq!(fetched.bytes(), artifact_bytes);
    assert_eq!(fetched.gateway_index(), 2);
    for gateway in &gateways[..2] {
        assert_eq!(
            gateway_health(&pool, gateway.expose_url(), GatewayCapability::ArtifactCar),
            (0, 0),
            "stalled attempts are released without recorded failures"
        );
    }

    let hedges = events
        .events()
        .into_iter()
        .filter(|event| {
            event
                .get("message")
                .is_some_and(|message| message == "artifact catalog hedge started")
        })
        .map(|event| {
            (
                event["hedge_gateway_index"].clone(),
                event["elapsed_ms"].clone(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        hedges,
        vec![
            ("1".to_owned(), CATALOG_HEDGE_DELAY.as_millis().to_string()),
            (
                "2".to_owned(),
                (CATALOG_HEDGE_DELAY * 2).as_millis().to_string()
            ),
        ]
    );
    let completed = events.find("hedged artifact catalog fetch completed");
    assert_eq!(completed["cid"], cid.to_string());
    assert_eq!(completed["started_gateways"], "[0, 1, 2]");
    assert_eq!(completed["winner_gateway_index"], "2");
    let mut forbidden = vec!["endpoint-sentinel".to_owned()];
    for gateway in &gateways {
        let url = gateway.expose_url();
        forbidden.push(format!("127.0.0.1:{}", url.port().expect("server port")));
        forbidden.push(opaque_gateway_id(url).to_string());
    }
    for event in events.events() {
        for value in event.values() {
            assert!(
                forbidden
                    .iter()
                    .all(|needle| !value.contains(needle.as_str())),
                "log value {value:?} exposes a gateway"
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn catalog_fetch_does_not_hedge_gateway_that_sent_headers() {
    let artifact_bytes = b"prompt catalog artifact".to_vec();
    let cid = raw_cid(&artifact_bytes);
    let body = car_bytes(cid, &[(cid, artifact_bytes.clone())]);
    let (body_head, body_tail) = body.split_at(body.len() / 2);
    let prompt = spawn_controlled_chunk_server();
    let spare = spawn_controlled_chunk_server();
    let gateways = vec![
        sensitive_server_url(prompt.url.clone()),
        sensitive_server_url(spare.url.clone()),
    ];
    let task = spawn_catalog_fetch(gateways, GatewayPool::new(), &artifact_bytes, 3);

    prompt.wait_for_request().await;
    prompt.send_headers(200);
    prompt.send_chunk(body_head.to_vec());
    // Let the client read the headers before the hedge delay elapses.
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(CATALOG_HEDGE_DELAY * 2).await;
    prompt.send_chunk(body_tail.to_vec());
    prompt.finish();

    let fetched = join_without_auto_advance(task)
        .await
        .expect("prompt gateway succeeds");
    assert_eq!(fetched.bytes(), artifact_bytes);
    assert_eq!(fetched.gateway_index(), 0);
    spare.assert_no_request();
}

#[tokio::test(start_paused = true)]
async fn catalog_fetch_attempt_cap_never_contacts_fourth_gateway() {
    let artifact_bytes = b"capped catalog artifact".to_vec();
    let servers = (0..4)
        .map(|_| spawn_controlled_chunk_server())
        .collect::<Vec<_>>();
    let gateways = servers
        .iter()
        .map(|server| sensitive_server_url(server.url.clone()))
        .collect::<Vec<_>>();
    let pool = pool_for_sensitive_gateway_order(&gateways, &[0, 1, 2, 3]);
    let task = spawn_catalog_fetch(gateways, pool, &artifact_bytes, 3);

    servers[0].wait_for_request().await;
    tokio::time::advance(CATALOG_HEDGE_DELAY).await;
    servers[1].wait_for_request().await;
    tokio::time::advance(CATALOG_HEDGE_DELAY).await;
    servers[2].wait_for_request().await;
    tokio::time::advance(CATALOG_HEDGE_DELAY * 2).await;
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
    servers[3].assert_no_request();
    for server in &servers[..3] {
        server.send_headers(503);
        server.finish();
    }

    let error = join_without_auto_advance(task)
        .await
        .expect_err("every started attempt failed");
    assert!(matches!(error, TrustlessArtifactError::HttpStatus { .. }));
    servers[3].assert_no_request();
}

#[tokio::test(start_paused = true)]
async fn catalog_fetch_rejects_mismatched_hedge_body_as_gateway_failure() {
    let artifact_bytes = b"verified catalog".to_vec();
    let cid = raw_cid(&artifact_bytes);
    let slow = spawn_controlled_chunk_server();
    let tampered = spawn_controlled_chunk_server();
    let gateways = vec![
        sensitive_server_url(slow.url.clone()),
        sensitive_server_url(tampered.url.clone()),
    ];
    let pool = GatewayPool::new();
    let task = spawn_catalog_fetch(gateways.clone(), pool.clone(), &artifact_bytes, 3);

    slow.wait_for_request().await;
    tokio::time::advance(CATALOG_HEDGE_DELAY).await;
    tampered.wait_for_request().await;
    tampered.send_headers(200);
    tampered.send_chunk(car_bytes(cid, &[(cid, b"tampered".to_vec())]));
    tampered.finish();
    yield_until("hedge failure is recorded", || {
        gateway_health(
            &pool,
            gateways[1].expose_url(),
            GatewayCapability::ArtifactCar,
        )
        .0 == 1
    })
    .await;
    slow.send_headers(200);
    slow.send_chunk(car_bytes(cid, &[(cid, artifact_bytes.clone())]));
    slow.finish();

    let fetched = join_without_auto_advance(task)
        .await
        .expect("first gateway still succeeds");
    assert_eq!(fetched.bytes(), artifact_bytes);
    assert_eq!(fetched.gateway_index(), 0);
    assert_eq!(
        gateway_health(
            &pool,
            gateways[0].expose_url(),
            GatewayCapability::ArtifactCar
        ),
        (0, 0)
    );
}

fn spawn_catalog_fetch(
    gateways: Vec<SensitiveUrl>,
    pool: GatewayPool,
    artifact_bytes: &[u8],
    max_gateway_attempts: usize,
) -> tokio::task::JoinHandle<Result<TrustlessArtifactFetchResult, TrustlessArtifactError>> {
    let cid = raw_cid(artifact_bytes).to_string();
    let byte_size = artifact_bytes.len() as u64;
    tokio::spawn(async move {
        TrustlessArtifactFetcher::new_poi_with_pool(&reqwest::Client::new(), &gateways, pool)
            .fetch_catalog_cid_with_metadata_hedged(&cid, byte_size, Some(0), max_gateway_attempts)
            .await
    })
}

fn spawn_hedged_chunk_fetch<G: Send + 'static>(
    gateways: Vec<SensitiveUrl>,
    pool: GatewayPool,
    artifact_bytes: &[u8],
    admit_hedge: impl FnOnce() -> Option<G> + Send + 'static,
) -> tokio::task::JoinHandle<Result<TrustlessArtifactFetchResult, TrustlessArtifactError>> {
    let cid = raw_cid(artifact_bytes).to_string();
    let byte_size = artifact_bytes.len() as u64;
    tokio::spawn(async move {
        TrustlessArtifactFetcher::new_poi_with_pool(&reqwest::Client::new(), &gateways, pool)
            .fetch_artifact_cid_with_metadata_hedged(&cid, byte_size, 0, admit_hedge)
            .await
    })
}

/// Joins by yielding instead of parking: a parked paused-time runtime
/// auto-advances to the next timer, which would expire stalled attempts'
/// idle timeouts before a ready body is read.
async fn join_without_auto_advance<T>(task: tokio::task::JoinHandle<T>) -> T {
    yield_until("fetch task finishes", || task.is_finished()).await;
    task.await.expect("join fetch task")
}

/// Yields until `condition` holds, without letting paused time advance.
async fn yield_until(what: &str, mut condition: impl FnMut() -> bool) {
    for _ in 0..100_000 {
        if condition() {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("timed out waiting until {what}");
}

/// Returns the recorded failure count and in-flight reservations.
fn gateway_health(
    pool: &GatewayPool,
    gateway: &Url,
    capability: GatewayCapability,
) -> (u32, usize) {
    recover_mutex(&pool.state)
        .health
        .get(&(opaque_gateway_id(gateway), capability))
        .map_or((0, 0), |health| (health.failures, health.in_flight))
}

/// Returns the gateway-wide failure count recorded for `gateway`.
fn gateway_wide_failures(pool: &GatewayPool, gateway: &Url) -> u32 {
    recover_mutex(&pool.state)
        .gateway_health
        .get(&opaque_gateway_id(gateway))
        .map_or(0, |health| health.failures)
}

/// Records `trustless_artifacts` tracing events as field-name to value maps.
#[derive(Clone, Default)]
struct CapturedEvents(Arc<Mutex<Vec<BTreeMap<String, String>>>>);

impl CapturedEvents {
    fn capture(&self) -> CaptureGuard {
        // With one registered dispatcher, tracing-core resolves a callsite first
        // hit on another test thread against that thread's empty default and
        // caches it as disabled. A second live dispatcher keeps interest computed
        // across every registered dispatcher, including this thread's capture.
        let registered = tracing::Dispatch::new(CaptureSubscriber(self.clone()));
        CaptureGuard {
            _default: tracing::subscriber::set_default(CaptureSubscriber(self.clone())),
            _registered: registered,
        }
    }

    fn events(&self) -> Vec<BTreeMap<String, String>> {
        recover_mutex(&self.0).clone()
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
        metadata.target().starts_with("trustless_artifacts")
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = BTreeMap::new();
        event.record(&mut CapturedFields(&mut fields));
        recover_mutex(&self.0.0).push(fields);
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

#[tokio::test]
async fn no_valid_ipns_records_is_reported() {
    let keypair = test_ipns_keypair();
    let name = ipns_name(&keypair);
    let failing = spawn_once_server(500, Vec::new());
    let client = reqwest::Client::new();
    let gateways = [failing.url.clone()];
    let fetcher = TrustlessArtifactFetcher::new(&client, &gateways);

    let error = fetcher
        .resolve_ipns_manifest_candidates(&name, None)
        .await
        .expect_err("no valid records");

    assert!(matches!(error, TrustlessArtifactError::HttpStatus { .. }));
}

fn raw_cid(bytes: &[u8]) -> Cid {
    Cid::new_v1(RAW_CODEC, Code::Sha2_256.digest(bytes))
}

fn cid_with_digest(code: u64, digest: &[u8]) -> Cid {
    Cid::new_v1(
        RAW_CODEC,
        cid::multihash::Multihash::wrap(code, digest).expect("valid test multihash"),
    )
}

fn blake2b_256_cid(bytes: &[u8]) -> Cid {
    let digest = Params::new()
        .hash_length(32)
        .to_state()
        .update(bytes)
        .finalize();
    cid_with_digest(0xb220, digest.as_bytes())
}

fn identity_cid(bytes: &[u8]) -> Cid {
    cid_with_digest(0x00, bytes)
}

fn reconstruct_for_test(
    root: Cid,
    blocks: &HashMap<Cid, Vec<u8>>,
    reconstructed_bytes: usize,
    unixfs_max_depth: usize,
    unixfs_max_link_visits: usize,
) -> Result<Vec<u8>, TrustlessArtifactError> {
    reconstruct_file(
        root,
        blocks,
        RetrievalLimits {
            response_bytes: usize::MAX,
            block_count: usize::MAX,
            reconstructed_bytes,
            unixfs_max_depth,
            unixfs_max_link_visits,
        },
    )
}

fn unixfs_chain(depth: usize) -> (Cid, HashMap<Cid, Vec<u8>>) {
    assert!(depth > 0);
    let mut blocks = HashMap::new();
    let mut root = raw_cid(b"x");
    blocks.insert(root, b"x".to_vec());
    for index in 1..depth {
        let name = format!("depth-{index}");
        let block = dag_pb_file_node(b"", &[(root, name.as_str(), 1)], Some(1));
        root = dag_pb_cid(&block);
        blocks.insert(root, block);
    }
    (root, blocks)
}

fn repeated_link_graph(count: usize) -> (Cid, HashMap<Cid, Vec<u8>>) {
    let child = raw_cid(b"x");
    let links = vec![(child, "repeated", 1); count];
    let root_block = dag_pb_file_node(b"", &links, Some(count as u64));
    let root = dag_pb_cid(&root_block);
    (
        root,
        HashMap::from([(root, root_block), (child, b"x".to_vec())]),
    )
}

fn dag_pb_cid(bytes: &[u8]) -> Cid {
    Cid::new_v1(DAG_PB_CODEC, Code::Sha2_256.digest(bytes))
}

fn dag_pb_file_node(data: &[u8], links: &[(Cid, &str, u64)], filesize: Option<u64>) -> Vec<u8> {
    dag_pb_node(
        Some(unixfs_data(
            UnixFsDataType::File,
            data,
            &links.iter().map(|(_, _, size)| *size).collect::<Vec<_>>(),
            filesize,
        )),
        links,
    )
}

fn dag_pb_node(data: Option<Vec<u8>>, links: &[(Cid, &str, u64)]) -> Vec<u8> {
    PbNode {
        links: links
            .iter()
            .map(|(cid, name, size)| PbLink {
                cid: *cid,
                name: Some((*name).to_string()),
                size: Some(*size),
            })
            .collect(),
        data: data.map(Bytes::from),
    }
    .into_bytes()
}

fn unixfs_data(
    data_type: UnixFsDataType,
    data: &[u8],
    block_sizes: &[u64],
    filesize: Option<u64>,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut writer = Writer::new(&mut bytes);
    writer
        .write_with_tag(8, |writer| {
            writer.write_enum(unixfs_data_type_code(data_type))
        })
        .expect("type");
    if !data.is_empty() {
        writer
            .write_with_tag(18, |writer| writer.write_bytes(data))
            .expect("data");
    }
    if let Some(filesize) = filesize {
        writer
            .write_with_tag(24, |writer| writer.write_uint64(filesize))
            .expect("filesize");
    }
    for size in block_sizes {
        writer
            .write_with_tag(32, |writer| writer.write_uint64(*size))
            .expect("block size");
    }
    bytes
}

fn unixfs_data_type_code(data_type: UnixFsDataType) -> i32 {
    match data_type {
        UnixFsDataType::Raw => 0,
        UnixFsDataType::Directory => 1,
        UnixFsDataType::File => 2,
        UnixFsDataType::Metadata => 3,
        UnixFsDataType::Symlink => 4,
        UnixFsDataType::HamtShard => 5,
        UnixFsDataType::Unknown(value) => value,
    }
}

fn car_bytes(root: Cid, blocks: &[(Cid, Vec<u8>)]) -> Vec<u8> {
    let header = car_header(root);
    let mut car = Vec::new();
    write_varint(header.len(), &mut car);
    car.extend_from_slice(&header);
    for (cid, block) in blocks {
        let cid_bytes = cid.to_bytes();
        write_varint(cid_bytes.len() + block.len(), &mut car);
        car.extend_from_slice(&cid_bytes);
        car.extend_from_slice(block);
    }
    car
}

fn car_with_invalid_block_cid(root: Cid) -> Vec<u8> {
    let header = car_header(root);
    let mut car = Vec::new();
    write_varint(header.len(), &mut car);
    car.extend_from_slice(&header);

    let mut invalid_cid = Vec::new();
    invalid_cid.push(0x02); // Invalid CID version; rs-car 0.5.0 panics here without prevalidation.
    invalid_cid.push(u8::try_from(RAW_CODEC).expect("raw codec byte"));
    invalid_cid.extend_from_slice(&[0x12, 0x20]);
    invalid_cid.extend_from_slice(&[0_u8; 32]);
    let block = b"malformed";
    write_varint(invalid_cid.len() + block.len(), &mut car);
    car.extend_from_slice(&invalid_cid);
    car.extend_from_slice(block);
    car
}

fn car_with_noncanonical_v2_header() -> Vec<u8> {
    let mut car = Vec::new();
    let mut header = Vec::new();
    header.push(0xa1);
    write_cbor_text("version", &mut header);
    header.extend_from_slice(&[0x18, 0x02]);
    write_varint(header.len(), &mut car);
    car.extend_from_slice(&header);

    let mut v2_header = [0_u8; CARV2_HEADER_SIZE];
    let mut cid_bytes = vec![
        0x01,
        u8::try_from(RAW_CODEC).expect("raw codec byte"),
        0x12,
        0x20,
    ];
    cid_bytes.extend_from_slice(&[0_u8; 32]);
    v2_header[0] = u8::try_from(cid_bytes.len() + 3).expect("block length byte");
    v2_header[1..=cid_bytes.len()].copy_from_slice(&cid_bytes);
    car.extend_from_slice(&v2_header);
    car
}

fn car_header(root: Cid) -> Vec<u8> {
    let mut header = Vec::new();
    header.push(0xa2);
    write_cbor_text("roots", &mut header);
    header.push(0x81);
    header.extend_from_slice(&[0xd8, 0x2a]);
    let mut cid_link = vec![0_u8];
    cid_link.extend_from_slice(&root.to_bytes());
    write_cbor_bytes(&cid_link, &mut header);
    write_cbor_text("version", &mut header);
    header.push(0x01);
    header
}

fn write_cbor_text(value: &str, out: &mut Vec<u8>) {
    write_cbor_len(0x60, value.len(), out);
    out.extend_from_slice(value.as_bytes());
}

fn write_cbor_bytes(value: &[u8], out: &mut Vec<u8>) {
    write_cbor_len(0x40, value.len(), out);
    out.extend_from_slice(value);
}

fn write_cbor_len(major: u8, len: usize, out: &mut Vec<u8>) {
    match len {
        0..=23 => out.push(major | u8::try_from(len).expect("small len")),
        24..=0xff => {
            out.extend_from_slice(&[major | 0x18, u8::try_from(len).expect("u8 len")]);
        }
        0x100..=0xffff => {
            out.push(major | 0x19);
            out.extend_from_slice(&u16::try_from(len).expect("u16 len").to_be_bytes());
        }
        _ => panic!("fixture length too large"),
    }
}

fn write_varint(mut value: usize, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((u8::try_from(value & 0x7f).expect("varint byte")) | 0x80);
        value >>= 7;
    }
    out.push(u8::try_from(value).expect("varint final byte"));
}

fn test_ipns_keypair() -> Keypair {
    Keypair::ed25519_from_bytes([7_u8; 32]).expect("test keypair")
}

fn ipns_name(keypair: &Keypair) -> String {
    let peer_id = keypair.public().to_peer_id();
    Cid::new_v1(LIBP2P_KEY_CODEC, *peer_id.as_ref()).to_string()
}

fn ipns_record(keypair: &Keypair, value: String, sequence: u64) -> Vec<u8> {
    ipns_record_with_validity(
        keypair,
        value,
        sequence,
        chrono::Duration::seconds(60 * 60 * 24 * 365),
    )
}

fn ipns_record_with_validity(
    keypair: &Keypair,
    value: String,
    sequence: u64,
    validity: chrono::Duration,
) -> Vec<u8> {
    rust_ipns::Record::new(
        keypair,
        value,
        Utc::now() + validity,
        sequence,
        Duration::from_nanos(60),
    )
    .expect("IPNS record")
    .encode()
    .expect("encoded IPNS record")
}

fn ipns_record_with_embedded_public_key(
    keypair: &Keypair,
    value: String,
    sequence: u64,
) -> Vec<u8> {
    let mut record = ipns_record(keypair, value, sequence);
    let public_key = keypair.public().encode_protobuf();
    Writer::new(&mut record)
        .write_with_tag(58, |writer| writer.write_bytes(&public_key))
        .expect("embedded public key");
    record
}

enum ControlledResponseCommand {
    Headers(u16),
    Chunk(Vec<u8>),
    Finish,
}

struct ControlledChunkServer {
    url: Url,
    requests: std::sync::mpsc::Receiver<String>,
    commands: std::sync::mpsc::Sender<(ControlledResponseCommand, std::sync::mpsc::Sender<()>)>,
}

impl ControlledChunkServer {
    async fn wait_for_request(&self) -> String {
        loop {
            match self.requests.try_recv() {
                Ok(path) => return path,
                Err(std::sync::mpsc::TryRecvError::Empty) => tokio::task::yield_now().await,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    panic!("controlled server stopped before receiving request")
                }
            }
        }
    }

    fn send(&self, command: ControlledResponseCommand) {
        let (acknowledge, acknowledged) = std::sync::mpsc::channel();
        self.commands
            .send((command, acknowledge))
            .expect("send controlled response command");
        acknowledged
            .recv_timeout(Duration::from_secs(2))
            .expect("controlled response command acknowledged");
    }

    fn send_headers(&self, status: u16) {
        self.send(ControlledResponseCommand::Headers(status));
    }

    fn send_chunk(&self, chunk: impl Into<Vec<u8>>) {
        self.send(ControlledResponseCommand::Chunk(chunk.into()));
    }

    fn finish(&self) {
        self.send(ControlledResponseCommand::Finish);
    }

    fn assert_no_request(&self) {
        assert!(matches!(
            self.requests.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
    }
}

fn spawn_controlled_chunk_server() -> ControlledChunkServer {
    spawn_controlled_chunk_server_on(
        std::net::TcpListener::bind("127.0.0.1:0").expect("bind controlled chunk server"),
    )
}

/// Serves the next connection accepted on `listener`, so a later server on
/// a clone of the same listener answers a second request to the same URL.
fn spawn_controlled_chunk_server_on(listener: std::net::TcpListener) -> ControlledChunkServer {
    let url = Url::parse(&format!(
        "http://{}",
        listener.local_addr().expect("controlled server address")
    ))
    .expect("controlled server URL");
    let (request_tx, requests) = std::sync::mpsc::channel();
    let (commands, command_rx) =
        std::sync::mpsc::channel::<(ControlledResponseCommand, std::sync::mpsc::Sender<()>)>();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept controlled request");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let read =
                std::io::Read::read(&mut stream, &mut buffer).expect("read controlled request");
            if read == 0 {
                return;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let request_text = String::from_utf8_lossy(&request);
        let path = request_text
            .split_whitespace()
            .nth(1)
            .expect("controlled request path")
            .to_string();
        request_tx.send(path).expect("record controlled request");

        while let Ok((command, acknowledge)) = command_rx.recv() {
            let finish = matches!(&command, ControlledResponseCommand::Finish);
            let write_result = match command {
                ControlledResponseCommand::Headers(status) => {
                    let reason = if status == 200 { "OK" } else { "ERROR" };
                    let headers = format!(
                        "HTTP/1.1 {status} {reason}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                    );
                    std::io::Write::write_all(&mut stream, headers.as_bytes())
                }
                ControlledResponseCommand::Chunk(chunk) => {
                    let frame = format!("{:x}\r\n", chunk.len());
                    std::io::Write::write_all(&mut stream, frame.as_bytes())
                        .and_then(|()| std::io::Write::write_all(&mut stream, &chunk))
                        .and_then(|()| std::io::Write::write_all(&mut stream, b"\r\n"))
                }
                ControlledResponseCommand::Finish => {
                    std::io::Write::write_all(&mut stream, b"0\r\n\r\n")
                }
            };
            let _ = acknowledge.send(());
            if write_result.is_err() || finish {
                break;
            }
        }
    });
    ControlledChunkServer {
        url,
        requests,
        commands,
    }
}

struct MockServer {
    url: Url,
    requests: std::sync::mpsc::Receiver<String>,
}

impl MockServer {
    fn request_path(&self) -> String {
        self.requests
            .recv_timeout(Duration::from_secs(2))
            .expect("request path")
    }
}

fn spawn_once_server(status: u16, body: Vec<u8>) -> MockServer {
    spawn_once_server_controlled(status, body, None)
}

fn spawn_blocked_once_server(
    status: u16,
    body: Vec<u8>,
) -> (MockServer, std::sync::mpsc::Sender<()>) {
    let (release, release_rx) = std::sync::mpsc::channel();
    (
        spawn_once_server_controlled(status, body, Some(release_rx)),
        release,
    )
}

fn spawn_once_server_controlled(
    status: u16,
    body: Vec<u8>,
    release: Option<std::sync::mpsc::Receiver<()>>,
) -> MockServer {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind server");
    let url = Url::parse(&format!(
        "http://{}",
        listener.local_addr().expect("local addr")
    ))
    .expect("server URL");
    let (tx, requests) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept request");
        let mut request = Vec::new();
        let mut buf = [0_u8; 1024];
        loop {
            let read = std::io::Read::read(&mut stream, &mut buf).expect("read request");
            assert!(read > 0, "client closed before request headers");
            request.extend_from_slice(&buf[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let request_text = String::from_utf8_lossy(&request);
        let path = request_text
            .split_whitespace()
            .nth(1)
            .expect("request path")
            .to_string();
        tx.send(path).expect("record request path");
        if let Some(release) = release {
            release.recv().expect("release response");
        }

        let reason = if status == 200 { "OK" } else { "ERROR" };
        let response = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        std::io::Write::write_all(&mut stream, response.as_bytes()).expect("headers");
        std::io::Write::write_all(&mut stream, &body).expect("body");
    });

    MockServer { url, requests }
}
