use super::*;

#[tokio::test]
async fn merkle_artifact_catch_up_targets_indexed_height_past_last_commitment() {
    let scope = test_scope();
    let indexed_through_hash = [0x44; 32];
    let leaves = [(0, U256::from(11)), (1, U256::from(12))];
    // Commitments are indexed through block 120, but the newest commitment is at block 110.
    let artifact_source =
        commitment_artifact_source(&scope, 120, indexed_through_hash, 110, &leaves);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
        Duration::from_secs(1),
    ));
    let chain = test_chain_config(&scope, rpcs, Some(artifact_source.config.clone()));

    let mut forest = MerkleForest::new();
    let catch_up = run_merkle_artifact_catch_up_into(&mut forest, &chain, 100, 150, None)
        .await
        .expect("merkle artifact catch-up")
        .expect("commitment artifacts are complete through the indexed height");

    assert_eq!(catch_up.target_block, 120);
    assert_eq!(catch_up.target_block_hash, indexed_through_hash);
    let mut expected = MerkleForest::new();
    for (tree_position, hash) in leaves {
        expected
            .insert_leaf(MerkleTreeUpdate {
                tree_number: 0,
                tree_position,
                hash,
            })
            .expect("insert expected leaf");
    }
    expected.compute_roots();
    assert_eq!(forest.roots(), expected.roots());
}

#[tokio::test]
async fn startup_forest_catch_up_skips_indexed_sources_only_for_short_tails() {
    // From block 1, safe head 100 leaves a tail of exactly `block_range` blocks.
    let (forest_block, artifact_requests, squid_requests) =
        load_startup_forest_with_indexed_sources("startup-forest-short-tail", 100).await;
    assert_eq!(forest_block, 0, "live RPC sync owns the short tail");
    assert_eq!(artifact_requests, 0, "no artifact request for a short tail");
    assert_eq!(squid_requests, 0, "no Squid request for a short tail");

    let (forest_block, artifact_requests, squid_requests) =
        load_startup_forest_with_indexed_sources("startup-forest-long-tail", 500).await;
    assert!(artifact_requests > 0, "artifact catch-up is tried first");
    assert_eq!(squid_requests, 2, "Squid height and commitments");
    assert_eq!(forest_block, 300, "Squid catches up to its indexed height");
}

#[tokio::test]
async fn startup_rpc_forest_candidate_matches_sequential_log_application() {
    let scope = test_scope();
    // A 963-block tail from block 1, ten pages of 100 blocks.
    let logs = [
        (1, 0),
        (99, 1),
        (100, 2),
        (101, 3),
        (250, 4),
        (512, 5),
        (963, 6),
    ]
    .into_iter()
    .map(|(block_number, tree_position)| {
        rpc_transact_log(scope.railgun_contract, block_number, tree_position)
    })
    .collect::<Vec<_>>();
    let servers = (0..3)
        .map(|_| {
            JsonRpcServer::spawn_handler(log_range_rpc_handler(logs.clone(), 963, |_, _, _| None))
        })
        .collect::<Vec<_>>();
    let (root_dir, db) = open_forest_db("startup-rpc-forest-candidate");
    let rpcs = Arc::new(QueryRpcPool::new(
        servers.iter().map(|server| server.url.clone()).collect(),
        Duration::from_secs(1),
    ));
    let chain = test_chain_config(&scope, rpcs, None);

    let (forest, forest_block, snapshot_path, _) = db
        .load_or_initialize_forest(&chain, 963, None, None)
        .await
        .expect("load startup forest");

    let mut expected = MerkleForest::new();
    expected
        .apply_commitment_updates_from_logs(
            &logs
                .iter()
                .map(|log| serde_json::from_value::<Log>(log.clone()).expect("rpc log"))
                .collect::<Vec<_>>(),
        )
        .expect("apply logs in order");
    expected.compute_roots();
    assert_eq!(forest_block, 963, "the RPC candidate reaches the safe head");
    assert_eq!(forest.read().await.roots(), expected.roots());
    assert_eq!(
        forest_meta(&db, &chain),
        Some((963, [0x11; 32])),
        "the winner's target and confirmed hash are persisted"
    );
    let snapshot = merkletree::persist::MerkleForestSnapshot::load(
        &snapshot_path,
        chain.deployment.chain_id,
        chain.deployment.contract,
    )
    .expect("load snapshot")
    .expect("snapshot present");
    assert_eq!(snapshot.last_processed_block, 963);
    assert_eq!(snapshot.forest.roots(), expected.roots());

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn startup_forest_race_starts_no_rpc_candidate_over_budget_or_archive_boundary() {
    for (name, archive_until_block, learned_span) in
        [("over-budget", 0, Some(5)), ("archive-boundary", 10, None)]
    {
        let scope = test_scope();
        let rpc =
            JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 500, |_, _, _| None));
        let squid = GraphqlServer::spawn(vec![
            r#"{"data":{"squidStatus":{"height":"300"}}}"#,
            SQUID_EMPTY_COMMITMENTS,
        ]);
        let (root_dir, db) = open_forest_db(&format!("startup-forest-race-{name}"));
        let rpcs = Arc::new(QueryRpcPool::new(
            vec![rpc.url.clone()],
            Duration::from_secs(1),
        ));
        if let Some(span) = learned_span {
            // 500 blocks in 5-block requests is over the 64-request budget.
            rpcs.narrow_log_span(LogSpanEndpoint::Provider(0), span);
        }
        let mut chain = test_chain_config(&scope, rpcs, None);
        chain.sync.archive_until_block = archive_until_block;
        chain.sync.quick_sync_endpoint = Some(squid.url.clone());
        let events = CapturedEvents::default();
        let guard = events.capture();

        let (_, forest_block, _, _) = db
            .load_or_initialize_forest(&chain, 500, None, None)
            .await
            .expect("load startup forest");
        drop(guard);

        assert_eq!(
            forest_block, 300,
            "{name}: Squid catch-up applies as before"
        );
        assert_eq!(squid.requests.try_iter().count(), 2, "{name}");
        // The provider still confirms the Squid target.
        assert!(
            get_logs_ranges(&rpc.drain_request_bodies()).is_empty(),
            "{name}: no RPC forest candidate request"
        );
        let started = events.find("merkle forest catch-up race started");
        assert_eq!(
            started.get("candidates").map(String::as_str),
            Some("indexed"),
            "{name}"
        );
        assert!(race_finished_events(&events, "rpc").is_empty(), "{name}");

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }
}

#[tokio::test]
async fn stalled_artifact_gateway_lets_rpc_forest_candidate_win() {
    let scope = test_scope();
    let (gateway, gateway_port) = silent_server();
    let (squid, squid_port) = silent_server();
    let rpc = JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 500, |_, _, _| None));
    let rpc_port = rpc.url.port().expect("rpc port");
    let mut artifact_config = checkpointed_wallet_artifact_source(&scope, 1, 50, 50).config;
    let gateway_url = Url::parse(&format!("http://127.0.0.1:{gateway_port}")).expect("gateway url");
    artifact_config.manifest_source =
        IndexedArtifactManifestSource::Url(gateway_url.join("/manifest.json").expect("url"));
    artifact_config.gateway_urls = vec![gateway_url];
    let (root_dir, db) = open_forest_db("startup-forest-stalled-artifacts");
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![credential_url(rpc_port)],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, Some(artifact_config));
    chain.sync.quick_sync_endpoint = Some(credential_url(squid_port));
    let events = CapturedEvents::default();
    let guard = events.capture();

    let (_, forest_block, _, _) = db
        .load_or_initialize_forest(&chain, 500, None, None)
        .await
        .expect("load startup forest");
    // Give a request from the dropped indexed candidate time to arrive.
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(guard);

    assert_eq!(forest_block, 500, "the RPC candidate wins at the safe head");
    assert_eq!(forest_meta(&db, &chain), Some((500, [0x11; 32])));
    assert_eq!(
        drain_backlog_connections(&gateway),
        1,
        "only the stalled manifest request reaches the gateway"
    );
    assert_eq!(drain_backlog_connections(&squid), 0, "Squid is never asked");

    let started = events.find("merkle forest catch-up race started");
    for (field, value) in [
        ("tail_blocks", "500"),
        ("candidates", "indexed,rpc"),
        ("estimated_rpc_requests", "5"),
        ("rpc_request_budget", "64"),
    ] {
        assert_eq!(
            started.get(field).map(String::as_str),
            Some(value),
            "{field}"
        );
    }
    let rpc_end = race_finished_events(&events, "rpc");
    assert_eq!(rpc_end.len(), 1);
    for (field, value) in [
        ("outcome", "confirmed"),
        ("source", "rpc"),
        ("target", "500"),
        ("get_logs_requests", "5"),
    ] {
        assert_eq!(
            rpc_end[0].get(field).map(String::as_str),
            Some(value),
            "{field}"
        );
    }
    assert!(rpc_end[0].contains_key("elapsed_ms"));
    let indexed_end = race_finished_events(&events, "indexed");
    assert_eq!(indexed_end.len(), 1);
    assert_eq!(
        indexed_end[0].get("outcome").map(String::as_str),
        Some("cancelled")
    );
    let winner = events.find("merkle forest catch-up race won");
    assert_eq!(winner.get("source").map(String::as_str), Some("rpc"));
    assert_eq!(winner.get("target").map(String::as_str), Some("500"));
    assert!(winner.contains_key("elapsed_ms"));
    let endpoints = [rpc_port, squid_port, gateway_port].map(|port| format!("127.0.0.1:{port}"));
    for event in events.events() {
        for value in event.values() {
            assert!(
                ["secret", "user:", "key-abc"]
                    .into_iter()
                    .chain(endpoints.iter().map(String::as_str))
                    .all(|needle| !value.contains(needle)),
                "log value {value:?} exposes an endpoint"
            );
        }
    }

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn startup_forest_progress_stays_with_leading_rpc_candidate() {
    let scope = test_scope();
    let (artifact_source, manifest_block) =
        checkpointed_wallet_artifact_source_with_blocked_manifest(&scope, 1, 50, 50);
    let (release_last_page, last_page_gate) = std_mpsc::channel();
    let rpc = JsonRpcServer::spawn_handler(gated_get_logs_handler(
        log_range_rpc_handler(Vec::new(), 500, |_, _, _| None),
        vec![((401, 500), last_page_gate)],
    ));
    let (root_dir, db) = open_forest_db("startup-forest-monotonic-progress");
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, Some(artifact_source.config.clone()));
    let (progress_tx, progress_rx) = watch::channel(None);
    chain.progress_tx = Some(progress_tx);
    let events = CapturedEvents::default();
    let _guard = events.capture();
    let load = tokio::spawn({
        let db = Arc::clone(&db);
        async move {
            db.load_or_initialize_forest(&chain, 500, None, None)
                .await
                .map(|(_, forest_block, _, _)| forest_block)
        }
    });

    wait_for_std_signal(manifest_block.request_started, "artifact manifest request").await;
    yield_until("RPC pages before the gated one", || {
        progress_rx.borrow().is_some_and(|update| {
            update.unit == SyncProgressUnit::Block && update.current_block == 400
        })
    })
    .await;
    let leading = *progress_rx.borrow();
    // The lagging artifact candidate reports manifest progress, then yields nothing.
    manifest_block
        .release
        .send(())
        .expect("release artifact manifest");
    yield_until("indexed candidate end", || {
        !race_finished_events(&events, "indexed").is_empty()
    })
    .await;
    assert_eq!(
        *progress_rx.borrow(),
        leading,
        "artifact progress must not replace the leading block progress"
    );

    release_last_page.send(()).expect("release last RPC page");
    let forest_block = load
        .await
        .expect("startup forest task")
        .expect("load startup forest");
    assert_eq!(forest_block, 500);
    let last = progress_rx.borrow().expect("final progress");
    assert_eq!(
        (last.unit, last.current_block),
        (SyncProgressUnit::Block, 500)
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn startup_forest_relays_artifact_preparation_progress() {
    let scope = test_scope();
    let (artifact_source, manifest_block) =
        checkpointed_wallet_artifact_source_with_blocked_manifest(&scope, 1, 50, 50);
    let rpc = JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 500, |_, _, _| None));
    let (root_dir, db) = open_forest_db("startup-forest-artifact-preparation");
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, Some(artifact_source.config.clone()));
    // The tail starts below the archive boundary, so no RPC candidate
    // publishes block progress over the artifact preparation.
    chain.sync.archive_until_block = 10;
    let (progress_tx, progress_rx) = watch::channel(None);
    chain.progress_tx = Some(progress_tx);
    let load = tokio::spawn({
        let db = Arc::clone(&db);
        async move {
            db.load_or_initialize_forest(&chain, 500, None, None)
                .await
                .map(|_| ())
        }
    });

    wait_for_std_signal(manifest_block.request_started, "artifact manifest request").await;
    yield_until("manifest start progress", || {
        progress_rx.borrow().is_some_and(|update| {
            update.unit == SyncProgressUnit::ArtifactPreparation && update.current_block == 5
        })
    })
    .await;

    manifest_block
        .release
        .send(())
        .expect("release artifact manifest");
    load.await
        .expect("startup forest task")
        .expect("load startup forest");

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn fast_artifact_forest_candidate_wins_and_stops_rpc_candidate() {
    let scope = test_scope();
    let leaves = [(0, U256::from(11)), (1, U256::from(12))];
    // Indexed through block 120 with the hash the confirming provider serves.
    // Confirmation waits until the RPC candidate has published its first page.
    let artifact_source = commitment_artifact_source(&scope, 120, [0x11; 32], 110, &leaves);
    let (release_confirmation, confirmation_gate) = std_mpsc::channel::<()>();
    let serve_confirmer = log_range_rpc_handler(Vec::new(), 500, |_, _, _| None);
    let confirmer = JsonRpcServer::spawn_handler(move |request: &serde_json::Value| {
        if request["method"] == "eth_getBlockByNumber" {
            let _ = confirmation_gate.recv();
        }
        serve_confirmer(request)
    });
    let (second_page_started_tx, second_page_started) = std_mpsc::channel();
    let (release_second_page, second_page_gate) = std_mpsc::channel();
    let serve_pool = gated_get_logs_handler(
        log_range_rpc_handler(Vec::new(), 500, |_, _, _| None),
        vec![((101, 200), second_page_gate)],
    );
    let pool_rpc = JsonRpcServer::spawn_handler(move |request: &serde_json::Value| {
        if request["method"] == "eth_getLogs"
            && hex_quantity(&request["params"][0]["fromBlock"]) == 101
        {
            let _ = second_page_started_tx.send(());
        }
        serve_pool(request)
    });
    let (root_dir, db) = open_forest_db("startup-forest-fast-artifacts");
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![pool_rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, Some(artifact_source.config.clone()));
    let (progress_tx, progress_rx) = watch::channel(None);
    chain.progress_tx = Some(progress_tx);
    let provider = QueryRpcPool::new(vec![confirmer.url.clone()], Duration::from_secs(1))
        .random_provider()
        .expect("confirming provider");
    let events = CapturedEvents::default();
    let _guard = events.capture();

    // The second page's request follows delivery of the first page.
    let confirm_after_first_page = async move {
        wait_for_std_signal(second_page_started, "second RPC page request").await;
        drop(release_confirmation);
    };
    let (loaded, ()) = tokio::join!(
        db.load_or_initialize_forest(&chain, 500, Some(&provider), None),
        confirm_after_first_page
    );
    let (forest, forest_block, _, _) = loaded.expect("load startup forest");

    assert_eq!(
        forest_block, 120,
        "the artifact candidate wins at its target"
    );
    assert_eq!(forest_meta(&db, &chain), Some((120, [0x11; 32])));
    let mut expected = MerkleForest::new();
    for (tree_position, hash) in leaves {
        expected
            .insert_leaf(MerkleTreeUpdate {
                tree_number: 0,
                tree_position,
                hash,
            })
            .expect("insert expected leaf");
    }
    expected.compute_roots();
    assert_eq!(forest.read().await.roots(), expected.roots());
    let last = progress_rx.borrow().expect("final progress");
    assert_eq!(
        last.unit,
        SyncProgressUnit::ArtifactApplied,
        "the winner's completion follows the loser's block progress"
    );
    let rpc_end = race_finished_events(&events, "rpc");
    assert_eq!(rpc_end.len(), 1);
    assert_eq!(
        rpc_end[0].get("outcome").map(String::as_str),
        Some("cancelled")
    );
    assert_eq!(
        rpc_end[0].get("get_logs_requests").map(String::as_str),
        Some("2"),
        "the held second page counts"
    );
    // The held page arrived before the win; free it.
    pool_rpc.drain_request_bodies();
    release_second_page
        .send(())
        .expect("release second RPC page");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        pool_rpc.drain_request_bodies().is_empty(),
        "the cancelled RPC candidate sends no further request"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn failed_forest_race_keeps_loaded_forest_and_writes_nothing() {
    let scope = test_scope();
    let leaves = [(0, U256::from(11)), (1, U256::from(12))];
    // The confirming provider serves hash 0x11 for the artifact target.
    let artifact_source = commitment_artifact_source(&scope, 120, [0x44; 32], 110, &leaves);
    let confirmer =
        JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 500, |_, _, _| None));
    let failing =
        JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 500, |_, _, _| {
            Some(rpc_error(-32000, "unavailable"))
        }));
    let (root_dir, db) = open_forest_db("startup-forest-race-fails");
    // Without a cooldown, the failed provider's index stays available, so the
    // artifact target is still confirmed on the passed-in provider.
    let rpcs = Arc::new(QueryRpcPool::new(vec![failing.url.clone()], Duration::ZERO));
    let chain = test_chain_config(&scope, rpcs, Some(artifact_source.config.clone()));
    let provider = QueryRpcPool::new(vec![confirmer.url.clone()], Duration::from_secs(1))
        .random_provider()
        .expect("confirming provider");
    // The loaded block's hash is canonical, so the race runs.
    let (loaded, snapshot_path, snapshot_bytes) = seed_loaded_forest(&db, &chain, 10, [0x11; 32]);
    let events = CapturedEvents::default();
    let guard = events.capture();

    let (forest, forest_block, _, _) = db
        .load_or_initialize_forest(&chain, 500, Some(&provider), None)
        .await
        .expect("load startup forest");
    drop(guard);

    events.find(
        "artifact-backed merkle forest target hash mismatch; falling back to configured indexed sources",
    );
    assert!(
        !get_logs_ranges(&failing.drain_request_bodies()).is_empty(),
        "the RPC candidate ran and failed"
    );
    assert_eq!(forest_block, 10, "startup keeps the loaded forest");
    assert_eq!(forest.read().await.roots(), loaded.roots());
    assert_eq!(forest_meta(&db, &chain), Some((10, [0x11; 32])));
    assert_eq!(
        fs::read(&snapshot_path).expect("read snapshot"),
        snapshot_bytes,
        "no candidate writes the snapshot"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn reorged_loaded_forest_skips_startup_catch_up() {
    let scope = test_scope();
    let leaves = [(0, U256::from(11)), (1, U256::from(12))];
    // Would win the race: indexed through block 120 with the served hash.
    let artifact_source = commitment_artifact_source(&scope, 120, [0x11; 32], 110, &leaves);
    // Serves hash 0x11 for every block, so the loaded block 10 has reorged.
    let rpc = JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 500, |_, _, _| None));
    let (root_dir, db) = open_forest_db("startup-forest-reorged");
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let chain = test_chain_config(&scope, rpcs, Some(artifact_source.config.clone()));
    let provider = QueryRpcPool::new(vec![rpc.url.clone()], Duration::from_secs(1))
        .random_provider()
        .expect("provider");
    let (loaded, snapshot_path, snapshot_bytes) = seed_loaded_forest(&db, &chain, 10, [0x10; 32]);

    let (forest, forest_block, _, _) = db
        .load_or_initialize_forest(&chain, 500, Some(&provider), None)
        .await
        .expect("load startup forest");

    assert_eq!(forest_block, 10, "the live reorg check owns the rewind");
    assert_eq!(forest.read().await.roots(), loaded.roots());
    assert_eq!(
        forest_meta(&db, &chain),
        Some((10, [0x10; 32])),
        "the metadata that shows the reorg is kept"
    );
    assert_eq!(
        fs::read(&snapshot_path).expect("read snapshot"),
        snapshot_bytes
    );
    assert!(
        get_logs_ranges(&rpc.drain_request_bodies()).is_empty(),
        "no RPC candidate"
    );
    assert_eq!(
        artifact_source.server.request_count(),
        0,
        "no artifact candidate"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test(start_paused = true)]
async fn headless_chain_start_skips_forest_catch_up_and_live_loop_rewinds_first() {
    let scope = test_scope();
    let (squid, squid_port) = silent_server();
    let (gateway, gateway_port) = silent_server();
    let gateway_url = Url::parse(&format!("http://127.0.0.1:{gateway_port}")).expect("gateway URL");
    // Every provider hangs until `recovered`. It then serves hash 0x11 for
    // every block and holds range reads until `logs_released`.
    let recovered = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let logs_released = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hung_reads = Arc::new(AtomicU64::new(0));
    let rpc_servers = (0..3)
        .map(|_| {
            let recovered = Arc::clone(&recovered);
            let logs_released = Arc::clone(&logs_released);
            let hung_reads = Arc::clone(&hung_reads);
            let serve = log_range_rpc_handler(Vec::new(), 200, |_, _, _| None);
            JsonRpcServer::spawn_handler(move |request| {
                if !recovered.load(Ordering::Acquire) {
                    hung_reads.fetch_add(1, Ordering::AcqRel);
                    while !recovered.load(Ordering::Acquire) {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
                if request["method"] == "eth_getLogs" {
                    while !logs_released.load(Ordering::Acquire) {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
                serve(request)
            })
        })
        .collect::<Vec<_>>();
    let (root_dir, db) = open_forest_db("headless-chain-start");
    let rpcs = Arc::new(QueryRpcPool::new(
        rpc_servers
            .iter()
            .map(|server| server.url.clone())
            .collect(),
        Duration::from_mins(1),
    ));
    let mut chain = test_chain_config(
        &scope,
        rpcs,
        Some(IndexedArtifactSourceConfig {
            trusted_publisher_pubkey: FixedBytes::ZERO,
            manifest_source: IndexedArtifactManifestSource::Url(
                gateway_url.join("/manifest.json").expect("manifest URL"),
            ),
            gateway_urls: vec![gateway_url],
            gateway_pool: None,
            manifest_reuse: crate::IndexedArtifactManifestReuse::default(),
            max_manifest_age: None,
            concurrency: 1,
            max_in_flight_bytes: 1024 * 1024,
        }),
    );
    chain.sync.quick_sync_endpoint =
        Some(Url::parse(&format!("http://127.0.0.1:{squid_port}")).expect("Squid URL"));
    seed_loaded_forest(&db, &chain, 50, [0xaa; 32]);
    let lease = crate::runtime_admission::DbRuntimeLease::acquire(
        &db,
        crate::runtime_admission::DbRuntimeOwnerKind::SyncManager,
    )
    .expect("runtime lease");

    let started = tokio::time::Instant::now();
    let prepare = tokio::spawn(ChainService::prepare(
        Arc::clone(&db),
        chain,
        test_proxy_poi_policy(),
        lease,
        None,
        crate::poi_submission::test_support::seeded_scheduler(0),
    ));
    // Busy-yielding keeps the paused clock still until every provider holds
    // a head read. Each provider then stays blocked, so chain start could
    // not finish if it sent any provider another request.
    yield_until("hung head reads", || {
        hung_reads.load(Ordering::Acquire) == 3
    })
    .await;
    tokio::time::advance(INITIAL_HEAD_DEADLINE).await;
    yield_until("chain start", || prepare.is_finished()).await;
    let prepared = prepare
        .await
        .expect("chain start task")
        .expect("chain start without a safe head");

    assert_eq!(
        started.elapsed(),
        INITIAL_HEAD_DEADLINE,
        "chain start waits only for the head deadline"
    );
    assert_eq!(drain_backlog_connections(&squid), 0, "no Squid request");
    assert_eq!(drain_backlog_connections(&gateway), 0, "no gateway request");

    // The providers recover and report a different hash for the loaded block.
    let service = prepared.activate();
    let forest_rx = service.forest_last_tx.subscribe();
    assert_eq!(*forest_rx.borrow(), 50);
    recovered.store(true, Ordering::Release);
    // Range reads are held, so no log can apply before the rewind.
    yield_until("reorg rewind", || *forest_rx.borrow() == 0).await;
    assert_eq!(*service.safe_head_tx.borrow(), 200);

    logs_released.store(true, Ordering::Release);
    service.shutdown().await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn unconfirmed_artifact_forest_candidate_keeps_loaded_forest() {
    let scope = test_scope();
    // Carries its own hash for block 120, but no provider can confirm it.
    let artifact_source =
        commitment_artifact_source(&scope, 120, [0x11; 32], 110, &artifact_forest_leaves());
    let (root_dir, db) = open_forest_db("startup-forest-unconfirmed-artifacts");
    let rpcs = Arc::new(QueryRpcPool::new(Vec::new(), Duration::from_secs(1)));
    let chain = test_chain_config(&scope, rpcs, Some(artifact_source.config.clone()));
    let (loaded, snapshot_path, snapshot_bytes) = seed_loaded_forest(&db, &chain, 10, [0x10; 32]);
    let events = CapturedEvents::default();
    let guard = events.capture();

    let (forest, forest_block, _, _) = db
        .load_or_initialize_forest(&chain, 500, None, None)
        .await
        .expect("load startup forest");
    drop(guard);

    let unconfirmed =
        events.find("no provider available to confirm the indexed merkle forest target");
    assert_eq!(
        unconfirmed.get("source").map(String::as_str),
        Some("indexed_artifacts")
    );
    assert_eq!(unconfirmed.get("target").map(String::as_str), Some("120"));
    assert_eq!(forest_block, 10, "startup keeps the loaded forest");
    assert_eq!(forest.read().await.roots(), loaded.roots());
    assert_eq!(forest_meta(&db, &chain), Some((10, [0x10; 32])));
    assert_eq!(
        fs::read(&snapshot_path).expect("read snapshot"),
        snapshot_bytes,
        "the unconfirmed artifact forest is not persisted"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn artifact_forest_squid_step_follows_tail_length_and_confirmation() {
    // Artifacts confirm at block 120; Squid is indexed through 300.
    for (name, safe_head, squid_target_confirmed, forest_target, squid_requests) in [
        ("one-page-tail", 200, true, 120, 0),
        ("long-tail", 500, true, 300, 2),
        ("long-tail-unconfirmed-squid", 500, false, 120, 2),
    ] {
        let scope = test_scope();
        let artifact_source =
            commitment_artifact_source(&scope, 120, [0x11; 32], 110, &artifact_forest_leaves());
        let squid = GraphqlServer::spawn(vec![SQUID_HEIGHT_300, SQUID_EMPTY_COMMITMENTS]);
        let serve = log_range_rpc_handler(Vec::new(), 500, |_, _, _| None);
        let confirmer = JsonRpcServer::spawn_handler(move |request: &serde_json::Value| {
            if !squid_target_confirmed
                && request["method"] == "eth_getBlockByNumber"
                && hex_quantity(&request["params"][0]) == 300
            {
                return serde_json::json!({ "result": null });
            }
            serve(request)
        });
        let (root_dir, db) = open_forest_db(&format!("startup-forest-squid-step-{name}"));
        let chain = indexed_forest_chain(
            artifact_source.config.clone(),
            squid.url.clone(),
            &confirmer.url,
        );
        let events = CapturedEvents::default();
        let guard = events.capture();

        let (_, forest_block, _, _) = db
            .load_or_initialize_forest(&chain, safe_head, None, None)
            .await
            .expect("load startup forest");
        drop(guard);

        assert_eq!(forest_block, forest_target, "{name}");
        assert_eq!(
            forest_meta(&db, &chain),
            Some((forest_target, [0x11; 32])),
            "{name}"
        );
        let requests = squid.requests.try_iter().collect::<Vec<_>>();
        assert_eq!(requests.len(), squid_requests, "{name}");
        if let Some(commitments) = requests.get(1) {
            assert_eq!(
                json_rpc_request_body(commitments)["variables"]["blockNumber"],
                "121",
                "{name}: Squid runs on top of the artifact forest"
            );
        } else {
            // Nor does a Squid hedge start while artifacts finish in time.
            let skipped = events.find("Squid step skipped for one-page tail");
            assert_eq!(skipped.get("tail_blocks").map(String::as_str), Some("80"));
        }

        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }
}

#[tokio::test(start_paused = true)]
async fn artifact_forest_at_safe_head_does_not_wait_on_hung_squid() {
    let scope = test_scope();
    let artifact_source =
        commitment_artifact_source(&scope, 120, [0x11; 32], 110, &artifact_forest_leaves());
    let (squid, squid_port) = silent_server();
    let confirmer =
        JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 500, |_, _, _| None));
    let (root_dir, db) = open_forest_db("startup-forest-artifacts-at-safe-head");
    let chain = indexed_forest_chain(
        artifact_source.config.clone(),
        Url::parse(&format!("http://127.0.0.1:{squid_port}")).expect("squid url"),
        &confirmer.url,
    );

    // A 120-block tail from block 1 that artifacts close exactly.
    let load = spawn_forest_load(&db, &chain, 120);
    // The paused clock stands still, so the load cannot wait on Squid or a timer.
    yield_until("artifact forest installed", || load.is_finished()).await;

    assert_eq!(load.await.expect("startup forest task"), 120);
    assert_eq!(forest_meta(&db, &chain), Some((120, [0x11; 32])));
    assert_eq!(drain_backlog_connections(&squid), 0, "Squid is never asked");

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test(start_paused = true)]
async fn hung_squid_step_returns_artifact_forest_at_deadline() {
    let scope = test_scope();
    let artifact_source =
        commitment_artifact_source(&scope, 120, [0x11; 32], 110, &artifact_forest_leaves());
    let (squid, squid_status) =
        GraphqlServer::spawn_with_blocked_response(vec![SQUID_HEIGHT_300], 0);
    let confirmer =
        JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 500, |_, _, _| None));
    let (root_dir, db) = open_forest_db("startup-forest-hung-squid-step");
    let chain = indexed_forest_chain(
        artifact_source.config.clone(),
        squid.url.clone(),
        &confirmer.url,
    );
    let events = CapturedEvents::default();
    let _guard = events.capture();

    let load = spawn_forest_load(&db, &chain, 500);
    yield_until("Squid status request", || {
        squid_status.request_started.try_recv().is_ok()
    })
    .await;
    tokio::time::advance(
        super::super::logs::INDEXED_SQUID_STEP_DEADLINE.saturating_sub(Duration::from_secs(1)),
    )
    .await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert!(
        !load.is_finished(),
        "the Squid step runs until its deadline"
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    yield_until("artifact forest installed", || load.is_finished()).await;

    assert_eq!(load.await.expect("startup forest task"), 120);
    assert_eq!(forest_meta(&db, &chain), Some((120, [0x11; 32])));
    let passed = events.find("Squid step deadline passed");
    assert_eq!(passed.get("tail_blocks").map(String::as_str), Some("380"));
    assert!(passed.contains_key("elapsed_ms"));
    squid_status.release.send(()).expect("release Squid status");

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test(start_paused = true)]
async fn hung_artifacts_start_squid_hedge_after_delay() {
    let hedge_delay = super::super::forest_db::FOREST_SQUID_HEDGE_DELAY;
    let scope = test_scope();
    let (artifact_source, manifest_block) = commitment_artifact_source_with_blocked_manifest(
        &scope,
        120,
        [0x11; 32],
        110,
        &artifact_forest_leaves(),
    );
    let squid = GraphqlServer::spawn(vec![SQUID_HEIGHT_300, SQUID_EMPTY_COMMITMENTS]);
    let confirmer =
        JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 500, |_, _, _| None));
    let (root_dir, db) = open_forest_db("startup-forest-hung-artifacts");
    let chain = indexed_forest_chain(
        artifact_source.config.clone(),
        squid.url.clone(),
        &confirmer.url,
    );
    let events = CapturedEvents::default();
    let _guard = events.capture();

    let load = spawn_forest_load(&db, &chain, 500);
    yield_until("artifact manifest request", || {
        manifest_block.request_started.try_recv().is_ok()
    })
    .await;
    tokio::time::advance(hedge_delay.saturating_sub(Duration::from_secs(1))).await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        squid.requests.try_iter().count(),
        0,
        "no Squid request before the hedge delay"
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    yield_until("Squid forest installed", || load.is_finished()).await;

    assert_eq!(load.await.expect("startup forest task"), 300);
    assert_eq!(forest_meta(&db, &chain), Some((300, [0x11; 32])));
    let requests = squid.requests.try_iter().collect::<Vec<_>>();
    assert_eq!(requests.len(), 2, "Squid height and commitments");
    assert_eq!(
        json_rpc_request_body(&requests[1])["variables"]["blockNumber"],
        "1",
        "Squid catches up from the loaded forest"
    );
    assert_eq!(
        artifact_source.server.request_count(),
        1,
        "the dropped artifact candidate sends nothing after the held manifest"
    );
    let hedge = events.find("artifact forest hedge started");
    assert_eq!(
        hedge.get("trigger").map(String::as_str),
        Some("hedge_delay")
    );
    assert!(hedge.contains_key("elapsed_ms"));
    manifest_block
        .release
        .send(())
        .expect("release artifact manifest");

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test(start_paused = true)]
async fn failed_artifacts_start_squid_hedge_without_delay() {
    let scope = test_scope();
    // Wallet-scan artifacts only, so forest artifact catch-up yields nothing.
    let artifact_source = checkpointed_wallet_artifact_source(&scope, 1, 50, 50);
    let squid = GraphqlServer::spawn(vec![SQUID_HEIGHT_300, SQUID_EMPTY_COMMITMENTS]);
    let confirmer =
        JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 500, |_, _, _| None));
    let (root_dir, db) = open_forest_db("startup-forest-failed-artifacts");
    let chain = indexed_forest_chain(
        artifact_source.config.clone(),
        squid.url.clone(),
        &confirmer.url,
    );

    let load = spawn_forest_load(&db, &chain, 500);
    // The paused clock stands still, so the hedge delay never elapses.
    yield_until("Squid forest installed", || load.is_finished()).await;

    assert_eq!(load.await.expect("startup forest task"), 300);
    assert!(
        artifact_source.server.request_count() > 0,
        "artifacts ran first"
    );
    assert_eq!(squid.requests.try_iter().count(), 2);
    assert_eq!(forest_meta(&db, &chain), Some((300, [0x11; 32])));

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test(start_paused = true)]
async fn unconfirmed_squid_hedge_leaves_artifact_candidate_running() {
    let scope = test_scope();
    let (artifact_source, manifest_block) = commitment_artifact_source_with_blocked_manifest(
        &scope,
        120,
        [0x11; 32],
        110,
        &artifact_forest_leaves(),
    );
    // The hedge from the loaded forest, then the step on top of artifacts.
    let squid = GraphqlServer::spawn(vec![
        SQUID_HEIGHT_300,
        SQUID_EMPTY_COMMITMENTS,
        SQUID_HEIGHT_300,
        SQUID_EMPTY_COMMITMENTS,
    ]);
    // Returns no block for the Squid target.
    let serve = log_range_rpc_handler(Vec::new(), 500, |_, _, _| None);
    let confirmer = JsonRpcServer::spawn_handler(move |request: &serde_json::Value| {
        if request["method"] == "eth_getBlockByNumber" && hex_quantity(&request["params"][0]) == 300
        {
            return serde_json::json!({ "result": null });
        }
        serve(request)
    });
    let (root_dir, db) = open_forest_db("startup-forest-unconfirmed-squid-hedge");
    let chain = indexed_forest_chain(
        artifact_source.config.clone(),
        squid.url.clone(),
        &confirmer.url,
    );
    let events = CapturedEvents::default();
    let _guard = events.capture();
    let squid_unconfirmed = || {
        events.events().iter().any(|event| {
            event.get("message").is_some_and(|message| {
                message == "indexed merkle forest target block hash unconfirmed"
            }) && event.get("source").is_some_and(|source| source == "squid")
        })
    };

    let load = spawn_forest_load(&db, &chain, 500);
    yield_until("artifact manifest request", || {
        manifest_block.request_started.try_recv().is_ok()
    })
    .await;
    tokio::time::advance(super::super::forest_db::FOREST_SQUID_HEDGE_DELAY).await;
    yield_until("unconfirmed Squid hedge", squid_unconfirmed).await;
    manifest_block
        .release
        .send(())
        .expect("release artifact manifest");
    yield_until("artifact forest installed", || load.is_finished()).await;

    assert_eq!(load.await.expect("startup forest task"), 120);
    assert_eq!(
        forest_meta(&db, &chain),
        Some((120, [0x11; 32])),
        "only the confirmed artifact forest is persisted"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

/// Serves a signed manifest with one Commitments catalog holding one chunk. Every leaf is in
/// tree 0 and sits at `commitment_block`; the manifest reports Commitments indexed through
/// `indexed_through_block`. The server answers one full catch-up (manifest, catalog, chunk).
fn commitment_artifact_source(
    scope: &ChainScope,
    indexed_through_block: u64,
    indexed_through_hash: [u8; 32],
    commitment_block: u64,
    leaves: &[(u64, U256)],
) -> TestArtifactSource {
    commitment_artifact_source_controlled(
        scope,
        indexed_through_block,
        indexed_through_hash,
        commitment_block,
        leaves,
        false,
    )
    .0
}

/// Like [`commitment_artifact_source`], but holds the manifest request until released.
fn commitment_artifact_source_with_blocked_manifest(
    scope: &ChainScope,
    indexed_through_block: u64,
    indexed_through_hash: [u8; 32],
    commitment_block: u64,
    leaves: &[(u64, U256)],
) -> (TestArtifactSource, PathServerBlockControl) {
    let (source, block) = commitment_artifact_source_controlled(
        scope,
        indexed_through_block,
        indexed_through_hash,
        commitment_block,
        leaves,
        true,
    );
    (source, block.expect("blocked manifest control"))
}

fn commitment_artifact_source_controlled(
    scope: &ChainScope,
    indexed_through_block: u64,
    indexed_through_hash: [u8; 32],
    commitment_block: u64,
    leaves: &[(u64, U256)],
    block_manifest: bool,
) -> (TestArtifactSource, Option<PathServerBlockControl>) {
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let start = leaves.first().map_or(0, |leaf| leaf.0);
    let end = leaves.last().map_or(0, |leaf| leaf.0);
    let row_count = u64::try_from(leaves.len()).expect("commitment row count");
    let range = IndexedArtifactRange {
        kind: IndexedArtifactRangeKind::TreePosition,
        start,
        end,
    };
    let mut payload = Vec::new();
    write_u64(&mut payload, row_count);
    for (tree_position, hash) in leaves {
        write_u64(&mut payload, *tree_position);
        write_u64(&mut payload, commitment_block);
        payload.push(0);
        payload.extend_from_slice(&0_u32.to_le_bytes());
        write_u64(&mut payload, *tree_position);
        payload.extend_from_slice(&hash.to_be_bytes::<32>());
    }
    let payload_len = u64::try_from(payload.len()).expect("commitment payload len");
    let chunk_bytes = IndexedArtifactChunkEnvelope::new(
        IndexedArtifactChunkEnvelopeHeader::new(
            IndexedDatasetKind::Commitments,
            scope.clone(),
            range.clone(),
            row_count,
            payload_len,
            vec![IndexedArtifactChunkSection {
                section_id: 1,
                offset: 0,
                byte_length: payload_len,
            }],
        ),
        payload,
    )
    .encode()
    .expect("encode commitment chunk");
    let chunk_cid = raw_cid(&chunk_bytes);
    let chunk_descriptor = IndexedArtifactDescriptor {
        dataset_kind: IndexedDatasetKind::Commitments,
        range: range.clone(),
        ..wallet_artifact_descriptor(
            scope.clone(),
            start,
            end,
            row_count,
            chunk_cid,
            &chunk_bytes,
            DatasetDescriptorMetadata {
                checkpoint_block: Some(commitment_block),
                start_block: Some(commitment_block),
                end_block: Some(commitment_block),
                ..Default::default()
            },
            CompressionAlgorithm::None,
        )
    };
    let catalog = IndexedArtifactCatalog {
        format_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
        dataset_kind: IndexedDatasetKind::Commitments,
        scope: scope.clone(),
        chunks: vec![chunk_descriptor.clone()],
    };
    let catalog_bytes = serde_json::to_vec(&catalog).expect("catalog json");
    let catalog_cid = raw_cid(&catalog_bytes);
    let catalog_descriptor = IndexedArtifactDescriptor {
        dataset_kind: IndexedDatasetKind::Commitments,
        range,
        ..wallet_artifact_descriptor(
            scope.clone(),
            start,
            end,
            row_count,
            catalog_cid,
            &catalog_bytes,
            DatasetDescriptorMetadata::default(),
            CompressionAlgorithm::None,
        )
    };
    let mut manifest = IndexedArtifactManifest::new(
        1_700_000_000_000,
        1,
        PublisherIdentity::ed25519(FixedBytes::from(signing_key.verifying_key().to_bytes())),
        vec![IndexedArtifactChainEntry {
            scope: scope.clone(),
            latest_indexed: vec![LatestIndexedHeight {
                dataset_kind: IndexedDatasetKind::Commitments,
                block_number: indexed_through_block,
                block_hash: FixedBytes::from(indexed_through_hash),
            }],
            catalogs: vec![catalog_descriptor],
        }],
    );
    manifest.sign_manifest(&signing_key).expect("sign manifest");
    let manifest_bytes = serde_json::to_vec(&manifest).expect("manifest json");
    let routes = HashMap::from([
        ("/manifest.json".to_string(), manifest_bytes),
        (
            format!("/ipfs/{catalog_cid}?format=car&dag-scope=entity"),
            car_bytes(catalog_cid, &[(catalog_cid, catalog_bytes)]),
        ),
        (
            format!("/ipfs/{chunk_cid}?format=car&dag-scope=entity"),
            car_bytes(chunk_cid, &[(chunk_cid, chunk_bytes)]),
        ),
    ]);
    let (server, block) = if block_manifest {
        let (server, block) =
            PathServer::spawn_with_blocked_path(routes, 3, "/manifest.json".to_string());
        (server, Some(block))
    } else {
        (PathServer::spawn(routes, 3), None)
    };
    let config = IndexedArtifactSourceConfig {
        trusted_publisher_pubkey: FixedBytes::from(signing_key.verifying_key().to_bytes()),
        manifest_source: IndexedArtifactManifestSource::Url(
            server.url.join("/manifest.json").expect("manifest url"),
        ),
        gateway_urls: vec![server.url.clone()],
        gateway_pool: None,
        manifest_reuse: crate::IndexedArtifactManifestReuse::default(),
        max_manifest_age: None,
        concurrency: 1,
        max_in_flight_bytes: 1024 * 1024,
    };
    (
        TestArtifactSource {
            config,
            server,
            chunk_descriptors: vec![chunk_descriptor],
        },
        block,
    )
}

/// Loads the startup forest from block 1 with an artifact source and a Squid
/// endpoint (height 300) configured, and returns the forest block plus the
/// artifact and Squid request counts.
async fn load_startup_forest_with_indexed_sources(name: &str, safe_head: u64) -> (u64, u64, usize) {
    let scope = test_scope();
    let artifact_source = checkpointed_wallet_artifact_source(&scope, 1, 50, 50);
    let squid = GraphqlServer::spawn(vec![
        r#"{"data":{"squidStatus":{"height":"300"}}}"#,
        SQUID_EMPTY_COMMITMENTS,
    ]);
    let root_dir = temp_db_root(name);
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let confirmer =
        JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 500, |_, _, _| None));
    let rpcs = confirming_pool_without_rpc_candidate(&confirmer.url);
    let mut chain = test_chain_config(&scope, rpcs, Some(artifact_source.config.clone()));
    chain.sync.quick_sync_endpoint = Some(squid.url.clone());

    let (_, forest_block, _, _) = db
        .load_or_initialize_forest(&chain, safe_head, None, None)
        .await
        .expect("load startup forest");

    let requests = (
        forest_block,
        artifact_source.server.request_count(),
        squid.requests.try_iter().count(),
    );
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
    requests
}

/// A `Transact` log that adds one commitment at `tree_position` of tree 0.
fn rpc_transact_log(contract: Address, block_number: u64, tree_position: u64) -> serde_json::Value {
    rpc_event_log(
        contract,
        block_number,
        &Transact {
            treeNumber: U256::ZERO,
            startPosition: U256::from(tree_position),
            hash: vec![FixedBytes::from(
                U256::from(tree_position + 1_000).to_be_bytes::<32>(),
            )],
            ciphertext: Vec::new(),
        }
        .encode_log_data(),
    )
}

/// Writes a one-leaf forest snapshot at `block`, with `hash` in its forest
/// metadata, and returns the forest, the snapshot path, and its bytes.
fn seed_loaded_forest(
    db: &DbStore,
    chain: &ChainConfig,
    block: u64,
    hash: [u8; 32],
) -> (MerkleForest, PathBuf, Vec<u8>) {
    db.ensure_blob_dir("merkle_forest")
        .expect("create merkle forest blob dir");
    let snapshot_path = db.resolve_path(&DbStore::relative_blob_path(
        "merkle_forest",
        &format!(
            "forest-{}-{}.msgpack",
            chain.deployment.chain_id, chain.deployment.contract
        ),
    ));
    let mut loaded = MerkleForest::new();
    loaded
        .insert_leaf(MerkleTreeUpdate {
            tree_number: 1,
            tree_position: 0,
            hash: U256::from(5),
        })
        .expect("insert loaded leaf");
    loaded.compute_roots();
    merkletree::persist::MerkleForestSnapshot::write(
        &snapshot_path,
        chain.deployment.chain_id,
        chain.deployment.contract,
        block,
        &loaded,
    )
    .expect("seed loaded snapshot");
    db.update_merkle_forest_meta(
        chain.deployment.chain_id,
        &chain.deployment.contract.to_string(),
        &snapshot_path,
        block,
        merkletree::persist::SNAPSHOT_VERSION,
        hash,
    )
    .expect("seed loaded forest meta");
    let snapshot_bytes = fs::read(&snapshot_path).expect("read seeded snapshot");
    (loaded, snapshot_path, snapshot_bytes)
}

/// A pool whose one provider, at `url`, confirms indexed forest targets, while
/// its learned one-block log span puts every tail longer than one page over
/// the RPC forest request budget, so no RPC forest candidate starts.
fn confirming_pool_without_rpc_candidate(url: &Url) -> Arc<QueryRpcPool> {
    let rpcs = Arc::new(QueryRpcPool::new(vec![url.clone()], Duration::from_secs(1)));
    rpcs.narrow_log_span(LogSpanEndpoint::Provider(0), 1);
    rpcs
}

fn race_finished_events(events: &CapturedEvents, candidate: &str) -> Vec<BTreeMap<String, String>> {
    events
        .events()
        .into_iter()
        .filter(|event| {
            event
                .get("message")
                .is_some_and(|message| message == "merkle forest catch-up candidate finished")
                && event
                    .get("candidate")
                    .is_some_and(|value| value == candidate)
        })
        .collect()
}

/// Two tree-0 leaves at block 110, served by the commitment artifact fixtures.
fn artifact_forest_leaves() -> [(u64, U256); 2] {
    [(0, U256::from(11)), (1, U256::from(12))]
}

/// Chain config with the artifact source and Squid endpoint configured, and a
/// pool that confirms indexed targets through `confirmer` but starts no RPC
/// forest candidate.
fn indexed_forest_chain(
    artifact_config: IndexedArtifactSourceConfig,
    squid_url: Url,
    confirmer: &Url,
) -> ChainConfig {
    let mut chain = test_chain_config(
        &test_scope(),
        confirming_pool_without_rpc_candidate(confirmer),
        Some(artifact_config),
    );
    chain.sync.quick_sync_endpoint = Some(squid_url);
    chain
}

/// Loads the startup forest on a separate task, returning the forest block.
fn spawn_forest_load(
    db: &Arc<DbStore>,
    chain: &ChainConfig,
    safe_head: u64,
) -> tokio::task::JoinHandle<u64> {
    let db = Arc::clone(db);
    let chain = chain.clone();
    tokio::spawn(async move {
        db.load_or_initialize_forest(&chain, safe_head, None, None)
            .await
            .map(|(_, forest_block, _, _)| forest_block)
            .expect("load startup forest")
    })
}
