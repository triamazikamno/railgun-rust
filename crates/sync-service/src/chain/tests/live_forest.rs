use super::*;

#[tokio::test]
async fn chain_shutdown_waits_for_live_log_worker() {
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        let _ = release_rx.await;
    });
    let live_log_task = Arc::new(std::sync::Mutex::new(Some(task)));
    let waiter_task = tokio::spawn({
        let live_log_task = Arc::clone(&live_log_task);
        async move {
            await_live_log_task_shutdown(live_log_task.as_ref(), 1).await;
        }
    });

    tokio::task::yield_now().await;
    assert!(!waiter_task.is_finished());

    release_tx.send(()).expect("release live log worker");
    tokio::time::timeout(std::time::Duration::from_secs(1), waiter_task)
        .await
        .expect("shutdown wait completed")
        .expect("shutdown task completed");
    assert!(
        live_log_task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_none()
    );
}

#[tokio::test(start_paused = true)]
async fn stalled_live_forest_catches_up_from_squid_when_rpc_pages_fail() {
    let scope = test_scope();
    // The one indexed commitment is a prepared output at tree 0, position 1.
    let squid = GraphqlServer::spawn(vec![
        r#"{"data":{"squidStatus":{"height":"150"}}}"#,
        r#"{"data":{"commitments":[{"id":"0x11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111","treeNumber":"0","treePosition":"1","batchStartTreePosition":"1","blockNumber":"100","hash":"77"}]}}"#,
    ]);
    let prepared = FixedBytes::from(U256::from(77).to_be_bytes::<32>());
    let list = FixedBytes::from([0x1a; 32]);
    // Confirms the Squid target; getLogs fails so RPC cannot advance.
    let rpc = JsonRpcServer::spawn_handler(|request| match request["method"].as_str() {
        Some("eth_getBlockByNumber") => {
            let block_number = hex_quantity(&request["params"][0]);
            serde_json::json!({
                "result": rpc_block(block_number, test_block_timestamp(block_number), 0x11),
            })
        }
        _ => serde_json::json!({ "error": rpc_error(-32000, "unavailable") }),
    });
    let transport = Arc::new(RecordingPoiTransport::default());
    let submitter_cancel = CancellationToken::new();
    let (poi_submitter, submitter_task) = ChainPoiSubmitterHandle::spawn_for_test(
        scope.chain_id,
        Arc::clone(&transport) as Arc<dyn crate::wallet::PendingOutputPoiSubmitter>,
        submitter_cancel.clone(),
    );
    poi_submitter
        .prepare(vec![poi::poi::SingleCommitmentProofContext {
            txid_version: DEFAULT_TXID_VERSION.to_string(),
            railgun_txid: U256::from(7),
            utxo_tree_in: 0,
            commitment: prepared,
            npk: FixedBytes::from([0x22; 32]),
            pre_transaction_pois_per_txid_leaf_per_list: BTreeMap::from([(list, BTreeMap::new())]),
        }])
        .await
        .expect("prepare output context");
    let events = CapturedEvents::default();
    let _guard = events.capture();
    let squid_url = squid.url.clone();
    let fixture = LiveForestFixture::spawn_with(
        "live-forest-stall-squid",
        Arc::new(QueryRpcPool::new(
            vec![rpc.url.clone()],
            Duration::from_secs(1),
        )),
        50,
        200,
        poi_submitter,
        move |chain| {
            chain.sync.quick_sync_endpoint = Some(squid_url);
        },
    )
    .await;
    let stall = fixture.stall_period();

    tokio::time::advance(stall.saturating_sub(Duration::from_secs(1))).await;
    assert_eq!(
        squid.requests.try_iter().count(),
        0,
        "no Squid request before the stall period"
    );

    tokio::time::advance(Duration::from_secs(1)).await;
    yield_until("Squid stall fallback", || {
        *fixture.forest_rx.borrow() == 150
    })
    .await;
    assert_eq!(
        squid.requests.try_iter().count(),
        2,
        "Squid height and commitments"
    );
    let chain = &fixture.service.chain;
    let meta = fixture
        .service
        .db
        .get_merkle_forest_meta(
            chain.deployment.chain_id,
            &chain.deployment.contract.to_string(),
        )
        .expect("read forest meta")
        .expect("forest meta persisted");
    assert_eq!(meta.last_block, 150);
    let records = events.with_message("live forest progress");
    assert_eq!(
        records.len(),
        1,
        "one record per published block: {records:?}"
    );
    assert_eq!(
        (
            records[0].get("cause").map(String::as_str),
            records[0].get("forest_block").map(String::as_str),
        ),
        (Some("stall_install"), Some("150"))
    );
    yield_until("PPOI send", || !transport.sends().is_empty()).await;
    assert_eq!(
        transport.sends(),
        vec![RecordedSend {
            commitment: prepared,
            tree: 0,
            position: 1,
            lists: vec![list],
        }]
    );

    fixture.stop().await;
    submitter_cancel.cancel();
    submitter_task.await.expect("submitter exits");
}

#[tokio::test(start_paused = true)]
async fn advancing_live_forest_issues_no_squid_requests() {
    let squid = GraphqlServer::spawn(vec![r#"{"data":{"squidStatus":{"height":"400"}}}"#]);
    let (release_page, page_gate) = std_mpsc::channel::<()>();
    let serve = log_range_rpc_handler(Vec::new(), 400, |_, _, _| None);
    let rpc = JsonRpcServer::spawn_handler(move |request| {
        if request["method"] == "eth_getLogs" {
            // Hold each page until the test has advanced the paused clock.
            let _ = page_gate.recv();
        }
        serve(request)
    });
    let fixture = LiveForestFixture::spawn(
        "live-forest-advancing",
        vec![rpc.url.clone()],
        squid.url.clone(),
        0,
        400,
    )
    .await;
    let stall = fixture.stall_period();
    fixture
        .service
        .safe_head_tx
        .send(400)
        .expect("wake live loop");

    // Each page lands within the stall period; together they span more than it.
    for page in 1..=3_u64 {
        tokio::time::advance(stall.saturating_sub(Duration::from_secs(20))).await;
        release_page.send(()).expect("release live page");
        yield_until("live forest page", || {
            *fixture.forest_rx.borrow() == page * 100
        })
        .await;
    }
    assert_eq!(squid.requests.try_iter().count(), 0);

    fixture.stop().await;
}

#[tokio::test(start_paused = true)]
async fn live_batch_sends_prepared_output_ppoi_proofs() {
    let scope = test_scope();
    let prepared = FixedBytes::from([0xc2; 32]);
    let list = FixedBytes::from([0x1a; 32]);
    let log = rpc_transact_outputs_log(
        scope.railgun_contract,
        50,
        vec![FixedBytes::from([0xc1; 32]), prepared],
    );
    let rpc = JsonRpcServer::spawn_handler(log_range_rpc_handler(vec![log], 100, |_, _, _| None));
    let transport = Arc::new(RecordingPoiTransport::default());
    let submitter_cancel = CancellationToken::new();
    let (poi_submitter, submitter_task) = ChainPoiSubmitterHandle::spawn_for_test(
        scope.chain_id,
        Arc::clone(&transport) as Arc<dyn crate::wallet::PendingOutputPoiSubmitter>,
        submitter_cancel.clone(),
    );
    poi_submitter
        .prepare(vec![poi::poi::SingleCommitmentProofContext {
            txid_version: DEFAULT_TXID_VERSION.to_string(),
            railgun_txid: U256::from(7),
            utxo_tree_in: 0,
            commitment: prepared,
            npk: FixedBytes::from([0x22; 32]),
            pre_transaction_pois_per_txid_leaf_per_list: BTreeMap::from([(list, BTreeMap::new())]),
        }])
        .await
        .expect("prepare output context");
    let fixture = LiveForestFixture::spawn_with(
        "live-forest-ppoi-submit",
        Arc::new(QueryRpcPool::new(
            vec![rpc.url.clone()],
            Duration::from_secs(1),
        )),
        0,
        100,
        poi_submitter,
        |_| {},
    )
    .await;
    fixture
        .service
        .safe_head_tx
        .send(100)
        .expect("wake live loop");

    yield_until("live batch applied", || *fixture.forest_rx.borrow() == 100).await;
    yield_until("PPOI send", || !transport.sends().is_empty()).await;
    assert_eq!(
        transport.sends(),
        vec![RecordedSend {
            commitment: prepared,
            tree: 0,
            position: 1,
            lists: vec![list],
        }]
    );

    fixture.stop().await;
    submitter_cancel.cancel();
    submitter_task.await.expect("submitter exits");
}

/// Reported bug: switching away from the sender wallet before its transaction
/// finalizes left the outputs' PPOI proofs unsent.
#[tokio::test(start_paused = true)]
async fn created_output_ppoi_context_is_sent_after_sender_wallet_retires() {
    #[derive(serde::Deserialize)]
    struct ProofFixture {
        pre_tx_poi: broadcaster_core::transact::PreTxPoi,
        public_context: ProofPublicContext,
    }

    #[derive(serde::Deserialize)]
    struct ProofPublicContext {
        commitments_out: Vec<U256>,
        output_npks: Vec<U256>,
        input_tree: u64,
        railgun_txid: U256,
        txid_leaf_hash: U256,
    }

    let proof_fixture: ProofFixture = serde_json::from_slice(include_bytes!(
        "../../../../core/tests/fixtures/ppoi_3x3_two_outputs.json"
    ))
    .expect("current two-output PPOI fixture");
    let public_context = proof_fixture.public_context;
    let scope = test_scope();
    let output = FixedBytes::from(public_context.commitments_out[1].to_be_bytes::<32>());
    let output_npk = FixedBytes::from(public_context.output_npks[1].to_be_bytes::<32>());
    let txid_leaf_hash = FixedBytes::from(public_context.txid_leaf_hash.to_be_bytes::<32>());
    let list = poi::poi::default_active_poi_list_keys()[0];
    let log = rpc_transact_outputs_log(
        scope.railgun_contract,
        50,
        public_context
            .commitments_out
            .iter()
            .map(|commitment| FixedBytes::from(commitment.to_be_bytes::<32>()))
            .collect(),
    );
    let rpc = JsonRpcServer::spawn_handler(log_range_rpc_handler(vec![log], 100, |_, _, _| None));
    let transport = Arc::new(RecordingPoiTransport::default());
    let submitter_cancel = CancellationToken::new();
    let (poi_submitter, driver) = ChainPoiSubmitterDriver::unspawned_for_test(
        scope.chain_id,
        Arc::clone(&transport) as Arc<dyn crate::wallet::PendingOutputPoiSubmitter>,
    );
    let fixture = LiveForestFixture::spawn_with(
        "live-forest-ppoi-sender-retired",
        Arc::new(QueryRpcPool::new(
            vec![rpc.url.clone()],
            Duration::from_secs(1),
        )),
        0,
        100,
        poi_submitter.clone(),
        |_| {},
    )
    .await;
    let mut cfg = test_wallet_config(
        &scope,
        Url::parse("http://127.0.0.1:1").expect("unused quick-sync url"),
    );
    cfg.cache_key = test_cache_key("ppoi-sender");
    cfg.quick_sync_endpoint = None;
    // No startup scan: the sender never observes its own output, so only the
    // chain's live rows can place it.
    cfg.sync_to_block = Some(0);
    cfg.use_indexed_wallet_catch_up = false;
    let sender = fixture
        .service
        .register_wallet(cfg)
        .await
        .expect("register sender wallet");

    let create_sender = sender.clone();
    let create = tokio::spawn(async move {
        create_sender
            .create_pending_output_poi_contexts(vec![crate::types::PendingOutputPoiContextIntent {
                txid_version: DEFAULT_TXID_VERSION.to_string(),
                output_commitment: output,
                output_npk,
                utxo_tree_in: public_context.input_tree,
                railgun_txid: public_context.railgun_txid,
                pre_transaction_pois_per_txid_leaf_per_list: BTreeMap::from([(
                    list,
                    BTreeMap::from([(txid_leaf_hash, proof_fixture.pre_tx_poi)]),
                )]),
                required_poi_list_keys: vec![list],
                output_role: local_db::PendingOutputPoiRole::Recipient,
            }])
            .await
    });
    // Nothing else enqueues while no context is pending, so the one queued
    // command is the create's prepare.
    yield_until("prepare queued", || driver.queued_commands_for_test() == 1).await;
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    assert!(
        !create.is_finished(),
        "the create reply waits for the chain to hold the context"
    );
    let submitter_task = driver.spawn(submitter_cancel.clone());
    assert_eq!(create.await.expect("create task"), Ok(1));

    fixture.service.unregister_wallet(&sender).await;
    assert!(fixture.service.wallet.read().await.is_none());
    fixture
        .service
        .safe_head_tx
        .send(100)
        .expect("wake live loop");

    yield_until("live batch applied", || *fixture.forest_rx.borrow() == 100).await;
    yield_until("PPOI send", || !transport.sends().is_empty()).await;
    assert_eq!(
        transport.sends(),
        vec![RecordedSend {
            commitment: output,
            tree: 0,
            position: 1,
            lists: vec![list],
        }]
    );

    fixture.stop().await;
    submitter_cancel.cancel();
    submitter_task.await.expect("submitter exits");
}

#[tokio::test(start_paused = true)]
async fn failed_live_squid_fallback_waits_for_cooldown() {
    let failure = r#"{"errors":[{"message":"indexer unavailable"}]}"#;
    let squid = GraphqlServer::spawn(vec![failure, failure]);
    let events = CapturedEvents::default();
    let _guard = events.capture();
    // The stall fallback needs an available provider to confirm a target;
    // Squid fails first, so this one is never contacted.
    let fixture = LiveForestFixture::spawn(
        "live-forest-squid-cooldown",
        vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
        squid.url.clone(),
        50,
        200,
    )
    .await;
    let stall = fixture.stall_period();
    let attempts = || {
        events
            .events()
            .iter()
            .filter(|event| {
                event.get("message").is_some_and(|message| {
                    message == "live merkle forest stall fallback to Squid finished"
                })
            })
            .count()
    };

    tokio::time::advance(stall).await;
    yield_until("first Squid attempt", || attempts() == 1).await;
    assert_eq!(squid.requests.try_iter().count(), 1);

    tokio::time::advance(stall.saturating_sub(Duration::from_secs(1))).await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert_eq!(attempts(), 1, "no retry before the cooldown elapses");
    assert_eq!(squid.requests.try_iter().count(), 0);

    tokio::time::advance(Duration::from_secs(1)).await;
    yield_until("second Squid attempt", || attempts() == 2).await;
    assert_eq!(squid.requests.try_iter().count(), 1);
    assert_eq!(*fixture.forest_rx.borrow(), 50);

    fixture.stop().await;
}

#[tokio::test(start_paused = true)]
async fn stalled_live_forest_checks_reorg_before_squid_fallback() {
    let (squid, commitments) = GraphqlServer::spawn_with_blocked_response(
        vec![
            r#"{"data":{"squidStatus":{"height":"150"}}}"#,
            SQUID_EMPTY_COMMITMENTS,
        ],
        1,
    );
    // Block headers carry hash 0xbb, except that block 50 has none until
    // `block_50_unconfirmed` clears; getLogs fails so RPC cannot advance.
    let block_50_unconfirmed = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let rpc = JsonRpcServer::spawn_handler({
        let block_50_unconfirmed = Arc::clone(&block_50_unconfirmed);
        move |request| match request["method"].as_str() {
            Some("eth_getBlockByNumber") => {
                let block_number = hex_quantity(&request["params"][0]);
                if block_number == 50 && block_50_unconfirmed.load(Ordering::Acquire) {
                    return serde_json::json!({ "result": null });
                }
                serde_json::json!({
                    "result": rpc_block(block_number, test_block_timestamp(block_number), 0xbb),
                })
            }
            _ => serde_json::json!({ "error": rpc_error(-32000, "unavailable") }),
        }
    });
    let events = CapturedEvents::default();
    let _guard = events.capture();
    let fixture = LiveForestFixture::spawn(
        "live-forest-stall-reorg",
        vec![rpc.url.clone()],
        squid.url.clone(),
        50,
        200,
    )
    .await;
    let service = &fixture.service;
    let chain = &service.chain;
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

    // Without a confirmed hash for block 50, the stall fallback waits for
    // another stall period.
    tokio::time::advance(fixture.stall_period()).await;
    yield_until("deferred stall fallback", || {
        !events
            .with_message(
                "live merkle forest stall fallback deferred after an inconclusive reorg check",
            )
            .is_empty()
    })
    .await;
    assert_eq!(squid.requests.try_iter().count(), 0);
    assert_eq!(*fixture.forest_rx.borrow(), 50);
    assert_eq!(fixture.meta(), Some((50, [0xaa; 32])));
    // The live page after the deferral fails and cools the only provider down.
    yield_until("failed live RPC page", || {
        !events
            .with_message("failed to fetch logs, retrying...")
            .is_empty()
    })
    .await;
    yield_until("provider cooldown", || {
        !chain.rpcs.available_providers().is_empty()
    })
    .await;

    block_50_unconfirmed.store(false, Ordering::Release);
    tokio::time::advance(fixture.stall_period()).await;
    yield_until("Squid commitments request", || {
        commitments.request_started.try_recv().is_ok()
    })
    .await;
    assert_eq!(
        *fixture.forest_rx.borrow(),
        0,
        "the reorged forest resets before the Squid catch-up"
    );
    let requests = squid.requests.try_iter().collect::<Vec<_>>();
    assert_eq!(requests.len(), 2, "Squid height and commitments");
    assert_eq!(
        json_rpc_request_body(&requests[1])["variables"]["blockNumber"],
        "1",
        "Squid catches up from the reset block"
    );

    commitments
        .release
        .send(())
        .expect("release Squid commitments");
    yield_until("Squid stall fallback", || {
        *fixture.forest_rx.borrow() == 150
    })
    .await;

    fixture.stop().await;
}

#[tokio::test(start_paused = true)]
async fn hung_squid_stall_fallback_times_out_and_live_rpc_resumes() {
    let (squid, squid_port) = silent_server();
    let recovered = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let serve = log_range_rpc_handler(Vec::new(), 200, |_, _, _| None);
    let rpc = JsonRpcServer::spawn_handler({
        let recovered = Arc::clone(&recovered);
        move |request| {
            if request["method"] == "eth_getLogs" && !recovered.load(Ordering::Acquire) {
                return serde_json::json!({ "error": rpc_error(-32000, "unavailable") });
            }
            serve(request)
        }
    });
    let events = CapturedEvents::default();
    let _guard = events.capture();
    let fixture = LiveForestFixture::spawn(
        "live-forest-hung-squid",
        vec![rpc.url.clone()],
        Url::parse(&format!("http://127.0.0.1:{squid_port}")).expect("squid url"),
        50,
        200,
    )
    .await;
    let rpcs = Arc::clone(&fixture.service.chain.rpcs);
    let finished = || {
        events
            .events()
            .into_iter()
            .filter(|event| {
                event.get("message").is_some_and(|message| {
                    message == "live merkle forest stall fallback to Squid finished"
                })
            })
            .collect::<Vec<_>>()
    };

    // A live page fails and the only provider cools down.
    fixture
        .service
        .safe_head_tx
        .send(200)
        .expect("wake live loop");
    yield_until("failed live RPC page", || {
        rpcs.available_providers().is_empty()
    })
    .await;
    // The stall fallback starts only with a provider to confirm its target.
    yield_until("provider cooldown", || {
        !rpcs.available_providers().is_empty()
    })
    .await;

    tokio::time::advance(fixture.stall_period()).await;
    // Only the silent Squid's timers are pending during the fallback, so the
    // paused clock may run through its header timeouts and retry delays.
    let fallback_started = tokio::time::Instant::now();
    while finished().is_empty() {
        assert!(
            fallback_started.elapsed() < Duration::from_mins(10),
            "the Squid stall fallback never finished"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let elapsed = fallback_started.elapsed();
    assert!(
        (Duration::from_secs(127)..=Duration::from_secs(129)).contains(&elapsed),
        "four 30 s header timeouts and 1, 2 and 4 s retry delays, got {elapsed:?}"
    );
    assert_eq!(
        finished()[0].get("outcome").map(String::as_str),
        Some("not_applied")
    );
    assert_eq!(*fixture.forest_rx.borrow(), 50);
    drain_backlog_connections(&squid);

    // Once the provider recovers, the live loop pages from RPC within the
    // Squid cooldown.
    recovered.store(true, Ordering::Release);
    yield_until("provider cooldown", || {
        !rpcs.available_providers().is_empty()
    })
    .await;
    fixture
        .service
        .safe_head_tx
        .send(200)
        .expect("wake live loop");
    yield_until("live RPC pages", || *fixture.forest_rx.borrow() == 200).await;
    assert_eq!(finished().len(), 1, "no Squid retry within the cooldown");
    assert_eq!(drain_backlog_connections(&squid), 0);

    fixture.stop().await;
}

#[test]
fn forest_stall_tracker_starts_far_behind_attempts_at_once() {
    let squid = IndexedForestSources {
        artifacts: false,
        squid: true,
    };
    let artifacts = IndexedForestSources {
        artifacts: true,
        squid: false,
    };
    let stall_period = Duration::from_mins(2);
    let start = tokio::time::Instant::now();

    // An advancing forest whose lag exceeds the budget is due at once, from
    // either indexed source, but only with a provider to confirm a target.
    let mut tracker = ForestStallTracker::new(stall_period);
    tracker.observe(100, 10_000, test_forest_lag(true), start);
    let advanced = start + Duration::from_secs(1);
    tracker.observe(110, 10_000, test_forest_lag(true), advanced);
    assert_eq!(
        tracker.due(advanced, squid, true),
        Some(IndexedForestTrigger::FarBehind)
    );
    assert_eq!(
        tracker.due(advanced, artifacts, true),
        Some(IndexedForestTrigger::FarBehind)
    );
    assert_eq!(tracker.due(advanced, squid, false), None);

    // A finished attempt defers the next one by the cooldown from its finish.
    let finished = advanced + Duration::from_secs(30);
    tracker.finish_far_behind_attempt(finished);
    let retry = finished + INDEXED_TAIL_FALLBACK_COOLDOWN;
    assert_eq!(tracker.deadline(squid), Some(retry));
    let before_retry =
        finished + INDEXED_TAIL_FALLBACK_COOLDOWN.saturating_sub(Duration::from_millis(1));
    assert_eq!(tracker.due(before_retry, squid, true), None);
    assert_eq!(
        tracker.due(retry, squid, true),
        Some(IndexedForestTrigger::FarBehind)
    );

    // A lag within the budget stays on the Squid-only stall rule.
    let mut tracker = ForestStallTracker::new(stall_period);
    tracker.observe(100, 200, test_forest_lag(false), start);
    let before_stall = start + stall_period.saturating_sub(Duration::from_millis(1));
    assert_eq!(tracker.due(before_stall, squid, true), None);
    let stalled = start + stall_period;
    assert_eq!(
        tracker.due(stalled, squid, true),
        Some(IndexedForestTrigger::Stall)
    );
    assert_eq!(tracker.due(stalled, squid, false), None);
    assert_eq!(tracker.deadline(artifacts), None);
    assert_eq!(tracker.due(stalled, artifacts, true), None);
}

#[test]
fn short_lag_is_far_behind_with_restricted_log_spans() {
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
        Duration::from_secs(1),
    ));
    let chain = test_chain_config(&test_scope(), Arc::clone(&rpcs), None);
    assert_eq!(
        chain.live_forest_lag(0, 200),
        ForestLag {
            estimated_requests: 2,
            far_behind: false,
        },
        "two pages at the configured range"
    );

    rpcs.narrow_log_span(LogSpanEndpoint::Provider(0), 2);
    assert_eq!(
        chain.live_forest_lag(0, 200),
        ForestLag {
            estimated_requests: 100,
            far_behind: true,
        }
    );
}

#[tokio::test(start_paused = true)]
async fn far_behind_live_forest_keeps_paging_through_hung_squid_attempts() {
    let (squid, squid_port) = silent_server();
    let (release_page, page_gate) = std_mpsc::channel::<()>();
    let serve = log_range_rpc_handler(Vec::new(), 10_000, |_, _, _| None);
    let rpc = JsonRpcServer::spawn_handler(move |request| {
        if request["method"] == "eth_getLogs" {
            // Hold each page until the test has advanced the paused clock.
            let _ = page_gate.recv();
        }
        serve(request)
    });
    let events = CapturedEvents::default();
    let _guard = events.capture();
    let started = tokio::time::Instant::now();
    let fixture = LiveForestFixture::spawn_far_behind(
        "live-forest-far-behind-hung-squid",
        rpc.url.clone(),
        Url::parse(&format!("http://127.0.0.1:{squid_port}")).expect("squid url"),
        0,
        10_000,
        None,
    )
    .await;
    let triggered = || {
        events
            .with_message("far-behind live forest catch-up triggered")
            .len()
    };
    let finished = || events.with_message("far-behind live forest catch-up finished");
    let step = Duration::from_secs(5);
    // The attempt starts without waiting for a stall.
    yield_until("far-behind attempt", || triggered() == 1).await;

    // Pages keep applying while Squid's requests time out and retry.
    let mut pages = 0;
    while finished().is_empty() {
        assert!(pages < 60, "the hung attempt never finished");
        advance_and_apply_live_page(&fixture, &release_page, step).await;
        pages += 1;
    }
    let attempt = finished().remove(0);
    assert_eq!(
        attempt.get("outcome").map(String::as_str),
        Some("no_result")
    );
    assert!(pages >= 20, "live pages during the attempt: {pages}");
    let elapsed_ms = attempt["elapsed_ms"].parse().expect("attempt elapsed ms");
    let retry_at = started + Duration::from_millis(elapsed_ms) + INDEXED_TAIL_FALLBACK_COOLDOWN;

    // The repeated attempt waits for the cooldown, and pages keep applying.
    while triggered() == 1 {
        let now = tokio::time::Instant::now();
        assert!(now < retry_at + 2 * step, "no attempt after the cooldown");
        advance_and_apply_live_page(&fixture, &release_page, step).await;
        if tokio::time::Instant::now() < retry_at {
            assert_eq!(triggered(), 1, "no attempt within the cooldown");
        }
    }
    for _ in 0..3 {
        advance_and_apply_live_page(&fixture, &release_page, step).await;
    }
    assert_eq!(triggered(), 2);
    assert_eq!(finished().len(), 1, "the repeated attempt is still running");

    fixture.stop().await;
    drain_backlog_connections(&squid);
}

#[tokio::test(start_paused = true)]
async fn far_behind_attempt_is_installed_when_it_finishes() {
    let squid = GraphqlServer::spawn(vec![
        r#"{"data":{"squidStatus":{"height":"10000"}}}"#,
        r#"{"errors":[{"message":"indexer unavailable"}]}"#,
        r#"{"data":{"squidStatus":{"height":"10000"}}}"#,
        SQUID_EMPTY_COMMITMENTS,
    ]);
    // Live pages fail, so only indexed attempts advance the forest.
    let get_logs = Arc::new(AtomicU64::new(0));
    let rpc = JsonRpcServer::spawn_handler(live_pages_then_fail(
        0,
        Arc::clone(&get_logs),
        log_range_rpc_handler(Vec::new(), 10_000, |_, _, _| None),
    ));
    let (progress_tx, progress_rx) = watch::channel(None);
    let events = CapturedEvents::default();
    let _guard = events.capture();
    let fixture = LiveForestFixture::spawn_far_behind(
        "live-forest-far-behind-install",
        rpc.url.clone(),
        squid.url.clone(),
        0,
        10_000,
        Some(progress_tx),
    )
    .await;
    let triggered = || {
        events
            .with_message("far-behind live forest catch-up triggered")
            .len()
    };

    // The first attempt fails after Squid reports its height, past the point
    // where a reporting catch-up publishes progress.
    yield_until("failed attempt and a live page after it", || {
        !events
            .with_message("far-behind live forest catch-up finished")
            .is_empty()
            && get_logs.load(Ordering::Acquire) >= 2
    })
    .await;
    assert_eq!(squid.requests.try_iter().count(), 2);
    assert_eq!(
        *progress_rx.borrow(),
        None,
        "a failed attempt publishes no progress"
    );

    tokio::time::advance(INDEXED_TAIL_FALLBACK_COOLDOWN.saturating_sub(Duration::from_secs(1)))
        .await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert_eq!(triggered(), 1, "no retry before the cooldown");
    assert_eq!(squid.requests.try_iter().count(), 0);

    // From here the clock and the safe head stay put: the finished attempt
    // alone wakes the loop to install it.
    tokio::time::advance(Duration::from_secs(1)).await;
    yield_until("indexed install", || *fixture.forest_rx.borrow() == 10_000).await;
    assert_eq!(triggered(), 2);
    assert_eq!(fixture.meta(), Some((10_000, [0x11; 32])));
    let completion = progress_rx.borrow().expect("completion progress");
    assert_eq!(
        (completion.current_block, completion.target_block),
        (10_000, 10_000)
    );

    fixture.stop().await;
}

#[tokio::test(start_paused = true)]
async fn far_behind_candidate_waits_for_a_conclusive_reorg_check() {
    // Squid holds its commitments until the forest metadata is seeded, so no
    // candidate exists before then.
    let (squid, commitments) = GraphqlServer::spawn_with_blocked_response(
        vec![
            r#"{"data":{"squidStatus":{"height":"10000"}}}"#,
            SQUID_EMPTY_COMMITMENTS,
        ],
        1,
    );
    // Live pages fail, and block 50 has no header until
    // `block_50_unconfirmed` clears.
    let block_50_unconfirmed = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let serve = live_pages_then_fail(
        0,
        Arc::new(AtomicU64::new(0)),
        log_range_rpc_handler(Vec::new(), 10_000, |_, _, _| None),
    );
    let rpc = JsonRpcServer::spawn_handler({
        let block_50_unconfirmed = Arc::clone(&block_50_unconfirmed);
        move |request| {
            if request["method"] == "eth_getBlockByNumber"
                && hex_quantity(&request["params"][0]) == 50
                && block_50_unconfirmed.load(Ordering::Acquire)
            {
                return serde_json::json!({ "result": null });
            }
            serve(request)
        }
    });
    let (progress_tx, progress_rx) = watch::channel(None);
    let events = CapturedEvents::default();
    let _guard = events.capture();
    let fixture = LiveForestFixture::spawn_far_behind(
        "live-forest-far-behind-unconfirmed-reorg-check",
        rpc.url.clone(),
        squid.url.clone(),
        50,
        10_000,
        Some(progress_tx),
    )
    .await;
    let results = || {
        events
            .with_message("far-behind live forest catch-up result")
            .into_iter()
            .filter_map(|record| record.get("outcome").cloned())
            .collect::<Vec<_>>()
    };

    yield_until("Squid commitments request", || {
        commitments.request_started.try_recv().is_ok()
    })
    .await;
    let chain = &fixture.service.chain;
    fixture
        .service
        .db
        .update_merkle_forest_meta(
            chain.deployment.chain_id,
            &chain.deployment.contract.to_string(),
            &fixture.snapshot_path,
            50,
            merkletree::persist::SNAPSHOT_VERSION,
            [0x11; 32],
        )
        .expect("persist forest meta for block 50");
    commitments
        .release
        .send(())
        .expect("release Squid commitments");

    // The attempt finishes with a candidate, and the loop runs a reorg check
    // and a failed live page after it.
    yield_until("finished attempt and a live page after it", || {
        events
            .with_message("far-behind live forest catch-up finished")
            .iter()
            .any(|record| record.get("target").map(String::as_str) == Some("10000"))
            && events
                .with_message("failed to fetch logs, retrying...")
                .len()
                >= 2
    })
    .await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        *fixture.forest_rx.borrow(),
        50,
        "an unconfirmed forest block hash holds the candidate"
    );
    assert_eq!(fixture.meta(), Some((50, [0x11; 32])));
    assert_eq!(fixture.snapshot_block(), None);
    assert!(
        !events
            .with_message("live forest progress")
            .iter()
            .any(|record| record.get("cause").map(String::as_str) == Some("indexed_install"))
    );
    assert!(
        results().is_empty(),
        "no install outcome yet: {:?}",
        results()
    );
    assert_eq!(*progress_rx.borrow(), None);

    // Once block 50 confirms the stored hash, the next check installs the
    // held candidate.
    block_50_unconfirmed.store(false, Ordering::Release);
    fixture
        .service
        .safe_head_tx
        .send(10_000)
        .expect("wake live loop");
    yield_until("indexed install", || *fixture.forest_rx.borrow() == 10_000).await;
    assert_eq!(fixture.meta(), Some((10_000, [0x11; 32])));
    assert_eq!(fixture.snapshot_block(), Some(10_000));
    let completion = progress_rx.borrow().expect("completion progress");
    assert_eq!(
        (completion.current_block, completion.target_block),
        (10_000, 10_000)
    );
    // The first attempt's candidate installs, within its cooldown.
    assert_eq!(results(), vec!["installed".to_owned()]);
    assert_eq!(
        events
            .with_message("far-behind live forest catch-up triggered")
            .len(),
        1
    );

    fixture.stop().await;
}

#[tokio::test(start_paused = true)]
async fn live_forest_progress_records_each_published_block() {
    // Squid holds its height answer until the test releases it.
    let (squid, squid_height) = GraphqlServer::spawn_with_blocked_response(
        vec![
            r#"{"data":{"squidStatus":{"height":"10000"}}}"#,
            SQUID_EMPTY_COMMITMENTS,
        ],
        0,
    );
    // Two live pages succeed and later ones fail. The first read of block 10
    // returns no block, so the first page fails its endpoint confirmation.
    let get_logs = Arc::new(AtomicU64::new(0));
    let serve = live_pages_then_fail(
        2,
        Arc::clone(&get_logs),
        log_range_rpc_handler(Vec::new(), 10_000, |_, _, _| None),
    );
    let endpoint_unproven = std::sync::atomic::AtomicBool::new(true);
    let rpc = JsonRpcServer::spawn_handler(move |request| {
        if request["method"] == "eth_getBlockByNumber"
            && hex_quantity(&request["params"][0]) == 10
            && endpoint_unproven.swap(false, Ordering::AcqRel)
        {
            return serde_json::json!({ "result": null });
        }
        serve(request)
    });
    let events = CapturedEvents::default();
    let _guard = events.capture();
    let fixture = LiveForestFixture::spawn_far_behind(
        "live-forest-progress-records",
        rpc.url.clone(),
        squid.url.clone(),
        0,
        10_000,
        None,
    )
    .await;
    let records = || events.with_message("live forest progress");

    yield_until("unproven live page", || {
        !events
            .with_message("live RPC range does not prove its endpoint")
            .is_empty()
    })
    .await;
    assert!(records().is_empty(), "an unapplied page has no record");

    fixture
        .service
        .safe_head_tx
        .send(10_000)
        .expect("wake live loop");
    yield_until("applied live page and a failed one", || {
        *fixture.forest_rx.borrow() == 10 && get_logs.load(Ordering::Acquire) == 3
    })
    .await;
    squid_height.release.send(()).expect("release Squid height");
    yield_until("indexed install", || *fixture.forest_rx.borrow() == 10_000).await;

    assert_eq!(
        records(),
        vec![
            progress_record("rpc_apply", 10, 10_000, 999, true),
            progress_record("indexed_install", 10_000, 10_000, 0, false),
        ]
    );

    fixture.stop().await;
}

#[tokio::test(start_paused = true)]
async fn far_behind_result_is_dropped_once_live_rpc_passes_its_target() {
    let (squid, commitments) = GraphqlServer::spawn_with_blocked_response(
        vec![
            r#"{"data":{"squidStatus":{"height":"30"}}}"#,
            SQUID_EMPTY_COMMITMENTS,
        ],
        1,
    );
    // Four live pages apply, through block 40; later pages fail.
    let get_logs = Arc::new(AtomicU64::new(0));
    let rpc = JsonRpcServer::spawn_handler(live_pages_then_fail(
        4,
        Arc::clone(&get_logs),
        log_range_rpc_handler(Vec::new(), 10_000, |_, _, _| None),
    ));
    let (progress_tx, progress_rx) = watch::channel(None);
    let events = CapturedEvents::default();
    let _guard = events.capture();
    let fixture = LiveForestFixture::spawn_far_behind(
        "live-forest-far-behind-passed",
        rpc.url.clone(),
        squid.url.clone(),
        0,
        10_000,
        Some(progress_tx),
    )
    .await;

    let mut attempt_running = false;
    yield_until("live pages past the attempt's target", || {
        attempt_running |= commitments.request_started.try_recv().is_ok();
        attempt_running
            && *fixture.forest_rx.borrow() == 40
            && get_logs.load(Ordering::Acquire) >= 5
    })
    .await;
    commitments
        .release
        .send(())
        .expect("release Squid commitments");
    yield_until("far-behind result", || {
        !events
            .with_message("far-behind live forest catch-up result")
            .is_empty()
    })
    .await;

    let result = events.find("far-behind live forest catch-up result");
    assert_eq!(
        (
            result.get("target").map(String::as_str),
            result.get("outcome").map(String::as_str),
        ),
        (Some("30"), Some("forest_at_target"))
    );
    assert_eq!(*fixture.forest_rx.borrow(), 40);
    assert_eq!(fixture.meta(), Some((40, [0x11; 32])));
    assert_eq!(fixture.snapshot_block(), Some(40));
    assert_eq!(*progress_rx.borrow(), None, "no completion progress");

    fixture.stop().await;
}

#[tokio::test(start_paused = true)]
async fn reorg_during_far_behind_attempt_aborts_it() {
    let (squid, commitments) = GraphqlServer::spawn_with_blocked_response(
        vec![
            r#"{"data":{"squidStatus":{"height":"10000"}}}"#,
            SQUID_EMPTY_COMMITMENTS,
        ],
        1,
    );
    // The first live page waits until the attempt is running. Block 60 proves
    // that page with hash 0x11, then reorgs to 0xbb for the reorg check.
    let (release_page, page_gate) = std_mpsc::channel::<()>();
    let block_60_reads = AtomicU64::new(0);
    let serve = live_pages_then_fail(
        1,
        Arc::new(AtomicU64::new(0)),
        log_range_rpc_handler(Vec::new(), 10_000, |_, _, _| None),
    );
    let rpc = JsonRpcServer::spawn_handler(move |request| {
        if request["method"] == "eth_getLogs" {
            let _ = page_gate.recv();
        }
        if request["method"] == "eth_getBlockByNumber"
            && hex_quantity(&request["params"][0]) == 60
            && block_60_reads.fetch_add(1, Ordering::AcqRel) > 0
        {
            return serde_json::json!({
                "result": rpc_block(60, test_block_timestamp(60), 0xbb),
            });
        }
        serve(request)
    });
    let events = CapturedEvents::default();
    let _guard = events.capture();
    let fixture = LiveForestFixture::spawn_far_behind(
        "live-forest-far-behind-reorg",
        rpc.url.clone(),
        squid.url.clone(),
        50,
        10_000,
        None,
    )
    .await;

    yield_until("Squid commitments request", || {
        commitments.request_started.try_recv().is_ok()
    })
    .await;
    drop(release_page);
    yield_until("aborted attempt", || {
        !events
            .with_message("far-behind live forest catch-up aborted by a reorg rewind")
            .is_empty()
    })
    .await;
    assert_eq!(
        Arc::strong_count(&fixture.service),
        2,
        "the aborted attempt dropped its service handle"
    );

    // The held Squid answer now reaches no attempt.
    commitments
        .release
        .send(())
        .expect("release Squid commitments");
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert_eq!(*fixture.forest_rx.borrow(), 0);
    assert_eq!(fixture.meta(), Some((0, [0; 32])));
    assert_eq!(
        events.with_message("far-behind live forest catch-up finished"),
        [] as [BTreeMap<String, String>; 0]
    );
    assert_eq!(
        events.with_message("live forest progress"),
        vec![
            progress_record("rpc_apply", 60, 10_000, 994, true),
            progress_record("reorg_reset", 0, 10_000, 1000, true),
        ]
    );

    fixture.stop().await;
}

#[tokio::test(start_paused = true)]
async fn far_behind_attempt_blocks_the_stall_trigger_and_ends_with_shutdown() {
    let (squid, commitments) = GraphqlServer::spawn_with_blocked_response(
        vec![
            r#"{"data":{"squidStatus":{"height":"600"}}}"#,
            SQUID_EMPTY_COMMITMENTS,
        ],
        1,
    );
    // One live page brings the lag within the request budget; later pages fail.
    let get_logs = Arc::new(AtomicU64::new(0));
    let rpc = JsonRpcServer::spawn_handler(live_pages_then_fail(
        1,
        Arc::clone(&get_logs),
        log_range_rpc_handler(Vec::new(), 650, |_, _, _| None),
    ));
    let events = CapturedEvents::default();
    let _guard = events.capture();
    let fixture = LiveForestFixture::spawn_far_behind(
        "live-forest-far-behind-stall-shutdown",
        rpc.url.clone(),
        squid.url.clone(),
        0,
        650,
        None,
    )
    .await;

    let mut attempt_running = false;
    yield_until("far-behind attempt and live pages", || {
        attempt_running |= commitments.request_started.try_recv().is_ok();
        attempt_running
            && *fixture.forest_rx.borrow() == 10
            && get_logs.load(Ordering::Acquire) == 2
    })
    .await;

    // The forest has stalled within the budget, so the stall trigger is due.
    // A stall fallback would hang behind the held Squid answer; the loop pages
    // instead.
    tokio::time::advance(fixture.stall_period()).await;
    fixture
        .service
        .safe_head_tx
        .send(650)
        .expect("wake live loop");
    yield_until("live page after the stall period", || {
        get_logs.load(Ordering::Acquire) == 3
    })
    .await;
    assert_eq!(
        events.with_message("live merkle forest stall fallback to Squid finished"),
        [] as [BTreeMap<String, String>; 0]
    );
    assert_eq!(
        Arc::strong_count(&fixture.service),
        3,
        "the fixture, the loop and the attempt hold the service"
    );

    // Shutdown during the attempt: `ChainService::shutdown` awaits this task.
    let LiveForestFixture {
        root_dir,
        service,
        task,
        ..
    } = fixture;
    service.cancel.cancel();
    task.await.expect("live forest loop exits");
    assert_eq!(
        Arc::strong_count(&service),
        1,
        "the attempt's service handle"
    );
    assert_eq!(
        Arc::strong_count(&service.chain.rpcs),
        1,
        "the loop's and the attempt's pool handles"
    );
    assert_eq!(*service.forest_last_tx.borrow(), 10);
    assert_eq!(
        forest_meta(&service.db, &service.chain),
        Some((10, [0x11; 32])),
        "only the live page persisted"
    );

    drop(commitments);
    drop(service);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn chain_shutdown_awaits_stalled_txid_public_cache_sync() {
    let scope = test_scope();
    let (squid, squid_block) = GraphqlServer::spawn_with_blocked_response(vec!["{}"], 0);
    let (root_dir, db) = open_forest_db("txid-public-cache-shutdown");
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    chain.sync.quick_sync_endpoint = Some(squid.url.clone());
    let public_data_plane = ChainPublicDataPlane::new(Arc::clone(&db), Arc::new(AtomicU64::new(0)));
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);

    service.spawn_txid_public_cache_loop_once();
    wait_for_std_signal(
        squid_block.request_started,
        "TXID public cache page request started",
    )
    .await;

    // The held page would stall the sync for minutes of header timeouts and retries.
    tokio::time::timeout(Duration::from_secs(2), service.shutdown())
        .await
        .expect("shutdown must not wait for the stalled TXID public cache sync");
    assert_eq!(
        Arc::strong_count(&service),
        1,
        "the TXID public cache loop released its service handle"
    );

    squid_block
        .release
        .send(())
        .expect("release stalled TXID page");
    drop(squid);
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

/// A `Transact` log whose commitments, from position 0 of tree 0, carry
/// ciphertext, so wallet scan rows decode them.
fn rpc_transact_outputs_log(
    contract: Address,
    block_number: u64,
    hashes: Vec<FixedBytes<32>>,
) -> serde_json::Value {
    let ciphertext = merkletree::slow::types::CommitmentCiphertext {
        ciphertext: [FixedBytes::ZERO; 4],
        blindedSenderViewingKey: FixedBytes::ZERO,
        blindedReceiverViewingKey: FixedBytes::ZERO,
        annotationData: alloy::primitives::Bytes::new(),
        memo: alloy::primitives::Bytes::new(),
    };
    rpc_event_log(
        contract,
        block_number,
        &Transact {
            treeNumber: U256::ZERO,
            startPosition: U256::ZERO,
            ciphertext: vec![ciphertext; hashes.len()],
            hash: hashes,
        }
        .encode_log_data(),
    )
}

/// Advances the paused clock by `step`, then releases one held live page and
/// waits until the loop applies it.
async fn advance_and_apply_live_page(
    fixture: &LiveForestFixture,
    release_page: &std_mpsc::Sender<()>,
    step: Duration,
) {
    let before = *fixture.forest_rx.borrow();
    tokio::time::advance(step).await;
    release_page.send(()).expect("release live page");
    yield_until("live page", || *fixture.forest_rx.borrow() > before).await;
}

/// Serves `serve`, but fails every `eth_getLogs` after the first `pages`.
/// `get_logs` counts the `eth_getLogs` requests.
fn live_pages_then_fail(
    pages: u64,
    get_logs: Arc<AtomicU64>,
    serve: impl Fn(&serde_json::Value) -> serde_json::Value + Send + 'static,
) -> impl Fn(&serde_json::Value) -> serde_json::Value + Send + 'static {
    move |request: &serde_json::Value| {
        if request["method"] == "eth_getLogs" && get_logs.fetch_add(1, Ordering::AcqRel) >= pages {
            return serde_json::json!({ "error": rpc_error(-32000, "unavailable") });
        }
        serve(request)
    }
}

fn progress_record(
    cause: &str,
    forest_block: u64,
    safe_head: u64,
    estimated_requests: u64,
    far_behind: bool,
) -> BTreeMap<String, String> {
    [
        ("message", "live forest progress".to_owned()),
        ("chain_id", "1".to_owned()),
        ("cause", cause.to_owned()),
        ("forest_block", forest_block.to_string()),
        ("safe_head", safe_head.to_string()),
        ("estimated_requests", estimated_requests.to_string()),
        ("far_behind", far_behind.to_string()),
    ]
    .into_iter()
    .map(|(field, value)| (field.to_owned(), value))
    .collect()
}
