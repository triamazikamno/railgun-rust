use super::startup_forest::seed_loaded_forest;
use super::*;
use crate::amount_statistics::AmountStatisticsStatus;
use crate::indexed_artifacts::tests::{
    ManifestGateway, config as indexed_artifact_test_config, ipns_name, test_ipns_keypair,
};

#[tokio::test]
async fn wallet_startup_reuses_recent_rows_before_short_tail_hedge() {
    let root_dir = temp_db_root("wallet-startup-recent-rows");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc_url = Url::parse("http://127.0.0.1:1").expect("rpc url");
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc_url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    chain.sync.quick_sync_endpoint = Some(rpc_url.clone());
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    public_data_plane
        .record_recent_public_scan_rows(crate::chain::PublicScanRows {
            range: PublicScanRange::new(101, 110),
            source: PublicScanSource::Rpc,
            to_block_hash: Some([0x11; 32]),
            rows: WalletScanInputRows {
                nullifiers: vec![IndexedNullifierInput {
                    tree_number: 1,
                    nullifier: U256::from(1),
                    source: UtxoSource {
                        tx_hash: FixedBytes::from([0x22; 32]),
                        block_number: 105,
                        block_timestamp: 1_700_000_105,
                    },
                }],
                ..WalletScanInputRows::default()
            },
            epoch: public_data_plane.current_epoch(),
        })
        .await
        .expect("record recent public rows");
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
    service.safe_head_tx.send_replace(110);
    let mut cfg = test_wallet_config(&scope, rpc_url);
    cfg.start_block = Some(101);
    cfg.sync_to_block = Some(110);

    let mut handle = service.register_wallet(cfg).await.expect("register wallet");
    tokio::time::timeout(Duration::from_secs(1), handle.wait_until_ready())
        .await
        .expect("cached recent rows made wallet ready")
        .expect("wallet readiness succeeded");

    assert_eq!(handle.last_scanned(), Some(110));
    service.unregister_all_wallets().await;
    service.shutdown().await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_startup_replays_empty_coverage_endpoint_hash_to_checkpoint() {
    let root_dir = temp_db_root("wallet-startup-empty-coverage-hash");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc_url = Url::parse("http://127.0.0.1:1").expect("rpc url");
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc_url.clone()],
        Duration::from_secs(1),
    ));
    let chain = test_chain_config(&scope, rpcs, None);
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    public_data_plane
        .record_recent_public_scan_rows(PublicScanRows {
            range: PublicScanRange::new(101, 110),
            source: PublicScanSource::Rpc,
            to_block_hash: Some([0x44; 32]),
            rows: WalletScanInputRows::default(),
            epoch: public_data_plane.current_epoch(),
        })
        .await
        .expect("record empty public coverage");
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
    service.safe_head_tx.send_replace(110);
    let mut cfg = test_wallet_config(&scope, rpc_url);
    cfg.start_block = Some(101);
    cfg.sync_to_block = Some(110);
    let cache_key = cfg.cache_key.clone();

    let mut handle = service.register_wallet(cfg).await.expect("register wallet");
    tokio::time::timeout(Duration::from_secs(1), handle.wait_until_ready())
        .await
        .expect("cached empty coverage made wallet ready")
        .expect("wallet readiness succeeded");

    let checkpoint = db
        .get_wallet_meta(&cache_key)
        .expect("read wallet checkpoint")
        .expect("wallet checkpoint present");
    assert_eq!(checkpoint.last_scanned_block, 110);
    assert_eq!(checkpoint.last_scanned_block_hash, Some([0x44; 32]));

    service.unregister_all_wallets().await;
    service.shutdown().await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn stalled_amount_statistics_refresh_leaves_wallet_readiness_unchanged() {
    let scope = test_scope();
    let rpc = JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 110, |_, _, _| None));
    // Knows no path. It holds its first request, the chain's statistics IPNS resolution, past
    // the readiness deadline below, and answers any later request with 404.
    let gateway = ManifestGateway::spawn(HashMap::new(), 1);
    let statistics_name = ipns_name(&test_ipns_keypair());
    let mut artifacts = indexed_artifact_test_config([7; 32], None);
    artifacts.gateway_urls = vec![gateway.url.clone()];
    artifacts.amount_statistics_ipns_name = Some(statistics_name.clone());
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, Some(artifacts));
    // Keeps the chain loops idle after their first pass.
    chain.sync.poll_interval = Duration::from_mins(1);
    let (root_dir, db) = open_forest_db("wallet-startup-stalled-amount-statistics");
    // A forest at the safe head, so chain start runs no forest catch-up.
    seed_loaded_forest(&db, &chain, 110, [0x11; 32]);
    let lease = crate::runtime_admission::DbRuntimeLease::acquire(
        &db,
        crate::runtime_admission::DbRuntimeOwnerKind::SyncManager,
    )
    .expect("runtime lease");
    let service = ChainService::prepare(
        Arc::clone(&db),
        chain,
        test_proxy_poi_policy(),
        lease,
        None,
        crate::poi_submission::test_support::seeded_scheduler(0),
    )
    .await
    .expect("chain start")
    .activate();
    tokio::time::timeout(Duration::from_secs(5), gateway.wait_for_requests(1))
        .await
        .expect("statistics refresh starts with the chain");
    assert_eq!(
        gateway.request_paths()[0],
        format!("/ipns/{statistics_name}?format=ipns-record")
    );
    service
        .public_data_plane
        .record_recent_public_scan_rows(PublicScanRows {
            range: PublicScanRange::new(101, 110),
            source: PublicScanSource::Rpc,
            to_block_hash: Some([0x11; 32]),
            rows: WalletScanInputRows::default(),
            epoch: service.public_data_plane.current_epoch(),
        })
        .await
        .expect("record empty public coverage");
    let mut cfg = test_wallet_config(&scope, rpc.url.clone());
    cfg.start_block = Some(101);
    cfg.sync_to_block = Some(110);

    let mut handle = service.register_wallet(cfg).await.expect("register wallet");
    tokio::time::timeout(Duration::from_secs(1), handle.wait_until_ready())
        .await
        .expect("wallet ready while statistics stall")
        .expect("wallet readiness succeeded");

    assert_eq!(handle.last_scanned(), Some(110));
    assert_eq!(
        service.amount_statistics_status(SystemTime::now()),
        AmountStatisticsStatus::NotYetAvailable
    );
    service.unregister_all_wallets().await;
    service.shutdown().await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn indexed_disabled_short_startup_warms_and_reuses_full_rpc_window() {
    let root_dir = temp_db_root("wallet-switch-rpc-rows");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let target_block = 110;
    let (release_warm, warm_gate) = std_mpsc::channel();
    let rpc = JsonRpcServer::spawn_handler(gated_get_logs_handler(
        log_range_rpc_handler(
            vec![rpc_nullifiers_log_with_timestamp(
                scope.railgun_contract,
                105,
            )],
            target_block,
            |_, _, _| None,
        ),
        vec![((101, 105), warm_gate)],
    ));
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    chain.sync.block_range = 10;
    chain.finality_depth = 0;
    chain.sync.quick_sync_endpoint = None;
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
    service.safe_head_tx.send_replace(target_block);

    let mut first_cfg = test_wallet_config(&scope, rpc.url.clone());
    first_cfg.cache_key = test_cache_key("wallet-a");
    first_cfg.start_block = Some(101);
    first_cfg.sync_to_block = Some(target_block);
    first_cfg.use_indexed_wallet_catch_up = false;
    let first_cache_key = first_cfg.cache_key.clone();
    db.put_wallet_meta(
        &first_cfg.cache_key,
        &WalletMeta {
            last_scanned_block: 105,
            updated_at: 1,
            last_scanned_block_hash: None,
        },
    )
    .expect("seed first wallet cursor");
    let mut first = service
        .register_wallet(first_cfg)
        .await
        .expect("register first wallet");
    tokio::time::timeout(Duration::from_secs(2), first.wait_until_ready())
        .await
        .expect("first wallet RPC startup completed")
        .expect("wallet readiness succeeded");
    assert_eq!(first.last_scanned(), Some(target_block));

    // The warm request for the pre-cursor blocks is still held by the mock,
    // so readiness did not wait for it.
    let mut bodies = Vec::new();
    yield_until("held background warm request", || {
        bodies.extend(rpc.drain_request_bodies());
        get_logs_ranges(&bodies).contains(&(101, 105))
    })
    .await;
    assert!(service.public_data_plane.public_window_warm_running());
    service
        .start_public_scan_window_warm(PublicScanRange::new(101, 105))
        .await;

    release_warm.send(()).expect("release warm request");
    yield_until("background warm finished", || {
        !service.public_data_plane.public_window_warm_running()
    })
    .await;
    bodies.extend(rpc.drain_request_bodies());
    assert_eq!(
        get_logs_ranges(&bodies),
        vec![(106, 110), (101, 105)],
        "delivery fetches only blocks after the cursor; one warm task fetches the rest"
    );
    assert!(
        service
            .public_data_plane
            .cached_wallet_scan_exact(101, target_block)
            .await
            .is_some(),
        "warming makes the whole window reusable"
    );
    assert_eq!(first.last_scanned(), Some(target_block));
    assert_eq!(
        db.get_wallet_meta(&first_cache_key)
            .expect("read first wallet cursor")
            .expect("first wallet cursor present")
            .last_scanned_block,
        target_block,
        "warming does not move the wallet cursor"
    );

    service.unregister_all_wallets().await;

    let mut second_cfg = test_wallet_config(&scope, rpc.url.clone());
    second_cfg.cache_key = test_cache_key("wallet-b");
    second_cfg.start_block = Some(101);
    second_cfg.sync_to_block = Some(target_block);
    second_cfg.use_indexed_wallet_catch_up = false;
    db.put_wallet_meta(
        &second_cfg.cache_key,
        &WalletMeta {
            last_scanned_block: 104,
            updated_at: 1,
            last_scanned_block_hash: None,
        },
    )
    .expect("seed replacement wallet cursor");
    let mut second = service
        .register_wallet(second_cfg)
        .await
        .expect("register replacement wallet");
    tokio::time::timeout(Duration::from_secs(1), second.wait_until_ready())
        .await
        .expect("replacement wallet reused RPC rows")
        .expect("wallet readiness succeeded");

    assert_eq!(second.last_scanned(), Some(target_block));
    assert!(
        rpc.drain_request_bodies().is_empty(),
        "replacement wallet must not issue another RPC request"
    );
    service.unregister_all_wallets().await;
    service.shutdown().await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_startup_reuses_sliding_cached_prefix_and_retains_new_tail() {
    let root_dir = temp_db_root("wallet-switch-sliding-rpc-window");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc = JsonRpcServer::spawn(vec![
        serde_json::json!("0x6e"),
        serde_json::json!([]),
        rpc_block(110, 1_700_000_110, 0x11),
        serde_json::json!("0x6e"),
        serde_json::json!([]),
        rpc_block(105, 1_700_000_105, 0x33),
        serde_json::json!("0x6f"),
        serde_json::json!([]),
        rpc_block(111, 1_700_000_111, 0x22),
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    chain.sync.block_range = 10;
    chain.finality_depth = 0;
    chain.sync.quick_sync_endpoint = None;
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
    service.safe_head_tx.send_replace(110);

    let mut first_cfg = test_wallet_config(&scope, rpc.url.clone());
    first_cfg.cache_key = test_cache_key("sliding-wallet-a");
    first_cfg.start_block = Some(101);
    first_cfg.sync_to_block = Some(110);
    first_cfg.use_indexed_wallet_catch_up = false;
    db.put_wallet_meta(
        &first_cfg.cache_key,
        &WalletMeta {
            last_scanned_block: 105,
            updated_at: 1,
            last_scanned_block_hash: None,
        },
    )
    .expect("seed first wallet cursor");
    let mut first = service
        .register_wallet(first_cfg)
        .await
        .expect("register first wallet");
    tokio::time::timeout(Duration::from_secs(2), first.wait_until_ready())
        .await
        .expect("first wallet RPC startup completed")
        .expect("first wallet readiness succeeded");
    assert_eq!(first.last_scanned(), Some(110));

    let mut first_bodies = Vec::new();
    yield_until("first wallet delivery and window warm", || {
        first_bodies.extend(rpc.drain_request_bodies());
        first_bodies.len() == 6 && !service.public_data_plane.public_window_warm_running()
    })
    .await;
    assert_eq!(
        get_logs_ranges(&first_bodies),
        vec![(106, 110), (101, 105)],
        "delivery precedes warming of the pre-cursor blocks"
    );

    service.unregister_all_wallets().await;
    service.safe_head_tx.send_replace(111);

    let mut second_cfg = test_wallet_config(&scope, rpc.url.clone());
    second_cfg.cache_key = test_cache_key("sliding-wallet-b");
    second_cfg.start_block = Some(101);
    second_cfg.sync_to_block = Some(111);
    second_cfg.use_indexed_wallet_catch_up = false;
    db.put_wallet_meta(
        &second_cfg.cache_key,
        &WalletMeta {
            last_scanned_block: 110,
            updated_at: 1,
            last_scanned_block_hash: None,
        },
    )
    .expect("seed replacement wallet cursor");
    let mut second = service
        .register_wallet(second_cfg)
        .await
        .expect("register replacement wallet");
    tokio::time::timeout(Duration::from_secs(2), second.wait_until_ready())
        .await
        .expect("replacement wallet RPC startup completed")
        .expect("replacement wallet readiness succeeded");
    assert_eq!(second.last_scanned(), Some(111));

    let second_requests = (0..3)
        .map(|_| {
            rpc.requests
                .recv_timeout(Duration::from_secs(1))
                .expect("replacement wallet RPC request")
        })
        .collect::<Vec<_>>();
    let second_get_logs = second_requests
        .iter()
        .find(|request| request.contains("eth_getLogs"))
        .expect("replacement wallet eth_getLogs request");
    assert!(second_get_logs.contains(r#""fromBlock":"0x6f""#));
    assert!(second_get_logs.contains(r#""toBlock":"0x6f""#));

    service.unregister_all_wallets().await;

    let mut third_cfg = test_wallet_config(&scope, rpc.url.clone());
    third_cfg.cache_key = test_cache_key("sliding-wallet-a");
    third_cfg.start_block = Some(101);
    third_cfg.sync_to_block = Some(111);
    third_cfg.use_indexed_wallet_catch_up = false;
    let mut third = service
        .register_wallet(third_cfg)
        .await
        .expect("register first wallet again");
    tokio::time::timeout(Duration::from_secs(1), third.wait_until_ready())
        .await
        .expect("first wallet reused retained new tail")
        .expect("first wallet readiness succeeded after switch back");
    assert_eq!(third.last_scanned(), Some(111));
    assert!(
        rpc.requests.try_recv().is_err(),
        "switching back at the same target must not issue another RPC request"
    );

    service.unregister_all_wallets().await;
    service.shutdown().await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_startup_fetches_cursor_gap_before_cached_suffix_then_warms_prefix() {
    let root_dir = temp_db_root("wallet-startup-leading-gap");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let gap_block = 105;
    let target_block = 110;
    let rpc = JsonRpcServer::spawn(vec![
        serde_json::json!(format!("{target_block:#x}")),
        serde_json::json!([rpc_nullifiers_log(scope.railgun_contract, gap_block)]),
        rpc_block(gap_block, 1_700_000_105, 0x11),
        rpc_block(gap_block, 1_700_000_105, 0x11),
        serde_json::json!(format!("{target_block:#x}")),
        serde_json::json!([]),
        rpc_block(104, 1_700_000_104, 0x44),
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    chain.sync.block_range = 10;
    chain.finality_depth = 0;
    chain.sync.quick_sync_endpoint = None;
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    public_data_plane
        .record_recent_public_scan_rows(PublicScanRows {
            range: PublicScanRange::new(106, target_block),
            source: PublicScanSource::Rpc,
            to_block_hash: Some([0x22; 32]),
            rows: WalletScanInputRows {
                nullifiers: vec![IndexedNullifierInput {
                    tree_number: 1,
                    nullifier: U256::from(7),
                    source: UtxoSource {
                        tx_hash: FixedBytes::from([0x22; 32]),
                        block_number: 106,
                        block_timestamp: 1_700_000_106,
                    },
                }],
                ..WalletScanInputRows::default()
            },
            epoch: public_data_plane.current_epoch(),
        })
        .await
        .expect("seed cached suffix");
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
    service.safe_head_tx.send_replace(target_block);

    let mut cfg = test_wallet_config(&scope, rpc.url.clone());
    cfg.cache_key = test_cache_key("wallet-leading-gap");
    cfg.start_block = Some(101);
    cfg.sync_to_block = Some(target_block);
    db.put_wallet_meta(
        &cfg.cache_key,
        &WalletMeta {
            last_scanned_block: 104,
            updated_at: 1,
            last_scanned_block_hash: None,
        },
    )
    .expect("seed wallet cursor");

    let mut handle = service.register_wallet(cfg).await.expect("register wallet");
    tokio::time::timeout(Duration::from_secs(2), handle.wait_until_ready())
        .await
        .expect("gap plus cached suffix completed")
        .expect("wallet readiness succeeded");
    assert_eq!(handle.last_scanned(), Some(target_block));

    let mut bodies = Vec::new();
    yield_until("gap delivery and window warm", || {
        bodies.extend(rpc.drain_request_bodies());
        bodies.len() == 7 && !service.public_data_plane.public_window_warm_running()
    })
    .await;
    assert_eq!(
        get_logs_ranges(&bodies),
        vec![(105, 105), (101, 104)],
        "only the gap after the cursor is fetched before delivery"
    );
    assert!(
        service
            .public_data_plane
            .cached_wallet_scan_exact(101, target_block)
            .await
            .is_some()
    );

    service.unregister_all_wallets().await;
    service.shutdown().await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn historical_catch_up_delivers_captured_suffix_after_cache_eviction() {
    let root_dir = temp_db_root("wallet-historical-captured-suffix");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let (artifact_source, manifest_block) =
        checkpointed_wallet_artifact_source_with_blocked_manifest(&scope, 101, 150, 150);
    let PathServerBlockControl {
        request_started,
        release,
    } = manifest_block;
    let rpc = JsonRpcServer::spawn(vec![serde_json::json!([])]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, Some(artifact_source.config.clone()));
    chain.sync.block_range = 10;
    chain.finality_depth = 0;
    chain.sync.quick_sync_endpoint = None;
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    public_data_plane
        .record_recent_public_scan_rows(PublicScanRows {
            range: PublicScanRange::new(151, 200),
            source: PublicScanSource::Rpc,
            to_block_hash: Some([0x22; 32]),
            rows: WalletScanInputRows {
                nullifiers: vec![IndexedNullifierInput {
                    tree_number: 1,
                    nullifier: U256::from(151),
                    source: UtxoSource {
                        tx_hash: FixedBytes::from([0x22; 32]),
                        block_number: 151,
                        block_timestamp: 1_700_000_151,
                    },
                }],
                ..WalletScanInputRows::default()
            },
            epoch: public_data_plane.current_epoch(),
        })
        .await
        .expect("seed captured suffix");
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane.clone());
    service.safe_head_tx.send_replace(200);
    let mut cfg = test_wallet_config(&scope, rpc.url.clone());
    cfg.cache_key = test_cache_key("captured-suffix-wallet");
    cfg.start_block = Some(101);
    cfg.sync_to_block = Some(200);
    db.put_wallet_meta(
        &cfg.cache_key,
        &WalletMeta {
            last_scanned_block: 100,
            updated_at: 1,
            last_scanned_block_hash: None,
        },
    )
    .expect("seed wallet cursor");

    let mut handle = service.register_wallet(cfg).await.expect("register wallet");
    wait_for_std_signal(request_started, "artifact manifest request started").await;
    for block_number in 201..=205 {
        public_data_plane
            .record_recent_public_scan_rows(PublicScanRows {
                range: PublicScanRange::new(block_number, block_number),
                source: PublicScanSource::Rpc,
                to_block_hash: Some([0x33; 32]),
                rows: WalletScanInputRows {
                    nullifiers: vec![IndexedNullifierInput {
                        tree_number: 1,
                        nullifier: U256::from(block_number),
                        source: UtxoSource {
                            tx_hash: FixedBytes::from([0x33; 32]),
                            block_number,
                            block_timestamp: block_number.saturating_add(1_700_000_000),
                        },
                    }],
                    ..WalletScanInputRows::default()
                },
                epoch: public_data_plane.current_epoch(),
            })
            .await
            .expect("record newer pending-tip page");
    }
    assert!(
        public_data_plane
            .cached_wallet_scan_apply(151, 200)
            .await
            .is_none(),
        "test must evict the original suffix from the shared cache"
    );
    release.send(()).expect("release artifact manifest");

    tokio::time::timeout(Duration::from_secs(2), handle.wait_until_ready())
        .await
        .expect("captured suffix startup completed")
        .expect("wallet readiness succeeded");
    assert_eq!(handle.last_scanned(), Some(200));
    assert!(
        rpc.requests.try_recv().is_err(),
        "captured suffix delivery must not refetch the evicted range through RPC"
    );

    service.unregister_all_wallets().await;
    service.shutdown().await;
    drop(service);
    drop(public_data_plane);
    drop(artifact_source.server);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_startup_rpc_candidate_skips_pre_cursor_blocks_when_delivery_is_cached() {
    let root_dir = temp_db_root("wallet-startup-exact-delivery-boundary");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc = JsonRpcServer::spawn_handler(
        |_| serde_json::json!({ "error": rpc_error(-32601, "unexpected request") }),
    );
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    chain.sync.block_range = 10;
    chain.finality_depth = 0;
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    public_data_plane
        .record_recent_public_scan_rows(PublicScanRows {
            range: PublicScanRange::new(106, 110),
            source: PublicScanSource::Rpc,
            to_block_hash: Some([0x22; 32]),
            rows: WalletScanInputRows::default(),
            epoch: public_data_plane.current_epoch(),
        })
        .await
        .expect("seed exact-boundary cached suffix");
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
    let mut cfg = test_wallet_config(&scope, rpc.url.clone());
    cfg.start_block = Some(101);

    let candidate = Arc::clone(&service)
        .wallet_startup_rpc_candidate(
            &cfg,
            WalletShortStartupPlan::new(101, 105, 110, 10).expect("short startup plan"),
            CancellationToken::new(),
        )
        .await
        .expect("RPC startup candidate");

    assert_eq!(
        candidate
            .applies
            .iter()
            .map(|apply| (apply.from_block, apply.to_block))
            .collect::<Vec<_>>(),
        vec![(106, 110)],
        "only the delivery suffix is returned to the wallet",
    );
    assert_eq!(
        candidate
            .acquisition_applies
            .first()
            .map(|apply| apply.from_block),
        Some(106),
        "the candidate holds no blocks at or before the cursor",
    );
    assert!(
        rpc.requests.try_recv().is_err(),
        "a cached delivery range needs no RPC request before delivery"
    );

    service.shutdown().await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_startup_rpc_candidate_rejects_zero_provider_coverage() {
    // Every head is below the target. A lagging head doesn't mark a provider
    // unhealthy, so only the read's tried set keeps it from asking one twice.
    let servers = (0..4)
        .map(|_| {
            JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 100, |_, _, _| None))
        })
        .collect::<Vec<_>>();

    let (result, _) = run_wallet_startup_rpc_candidate(
        "wallet-startup-zero-rpc-coverage",
        servers.iter().map(|server| server.url.clone()).collect(),
    )
    .await;

    assert!(matches!(
        result,
        Err(WalletStartupSyncError::IncompleteRpcCoverage {
            requested_to: 110,
            proven_to: 100,
        })
    ));
    let mut head_reads = servers
        .iter()
        .map(|server| {
            let bodies = server.drain_request_bodies();
            assert!(
                bodies
                    .iter()
                    .all(|body| body["method"] == "eth_blockNumber"),
                "only head reads: {bodies:?}"
            );
            bodies.len()
        })
        .collect::<Vec<_>>();
    head_reads.sort_unstable();
    assert_eq!(
        head_reads,
        vec![0, 1, 1, 1],
        "the read stops after three distinct providers"
    );
}

#[tokio::test]
async fn wallet_startup_rpc_candidate_fails_over_after_provider_error() {
    let scope = test_scope();
    // The first range read, on whichever provider is picked first, gets HTTP 503.
    let get_logs_reads = Arc::new(AtomicU64::new(0));
    let servers = (0..2)
        .map(|_| {
            let get_logs_reads = Arc::clone(&get_logs_reads);
            let serve = log_range_rpc_handler(
                vec![rpc_nullifiers_log_with_timestamp(
                    scope.railgun_contract,
                    108,
                )],
                110,
                |_, _, _| None,
            );
            JsonRpcServer::spawn_handler_with_status(move |request| {
                if request["method"] == "eth_getLogs"
                    && get_logs_reads.fetch_add(1, Ordering::AcqRel) == 0
                {
                    return Err(503);
                }
                Ok(serve(request))
            })
        })
        .collect::<Vec<_>>();

    let (result, rpcs) = run_wallet_startup_rpc_candidate(
        "wallet-startup-rpc-failover-after-error",
        servers.iter().map(|server| server.url.clone()).collect(),
    )
    .await;

    let applies = result.expect("the second provider completes the read");
    assert_eq!(applies.len(), 1);
    let WalletScanRowsPayload::Rows(rows) = &applies[0].rows.payload else {
        panic!("RPC delivery rows expected");
    };
    assert_eq!(rows.nullifiers.len(), 1);
    for server in &servers {
        assert_eq!(
            get_logs_ranges(&server.drain_request_bodies()),
            vec![(106, 110)],
            "each provider is asked for the range once"
        );
    }
    assert_eq!(
        rpcs.available_providers().len(),
        1,
        "the failed provider cools down"
    );
}

#[tokio::test]
async fn wallet_startup_rpc_candidate_fails_over_when_provider_head_is_behind() {
    // The first head read, on whichever provider is picked first, is below
    // the required target 110.
    let head_reads = Arc::new(AtomicU64::new(0));
    let servers = (0..2)
        .map(|_| {
            let head_reads = Arc::clone(&head_reads);
            let serve = log_range_rpc_handler(Vec::new(), 110, |_, _, _| None);
            JsonRpcServer::spawn_handler(move |request| {
                if request["method"] == "eth_blockNumber"
                    && head_reads.fetch_add(1, Ordering::AcqRel) == 0
                {
                    return serde_json::json!({ "result": "0x64" });
                }
                serve(request)
            })
        })
        .collect::<Vec<_>>();

    let (result, rpcs) = run_wallet_startup_rpc_candidate(
        "wallet-startup-rpc-failover-behind-head",
        servers.iter().map(|server| server.url.clone()).collect(),
    )
    .await;

    let applies = result.expect("the provider whose head covers the target completes the read");
    assert_eq!(
        applies
            .iter()
            .map(|apply| (apply.from_block, apply.to_block))
            .collect::<Vec<_>>(),
        vec![(106, 110)]
    );
    let mut ranges = servers
        .iter()
        .map(|server| get_logs_ranges(&server.drain_request_bodies()))
        .collect::<Vec<_>>();
    ranges.sort();
    assert_eq!(
        ranges,
        vec![Vec::new(), vec![(106, 110)]],
        "only the provider that covers the target reads the range"
    );
    assert_eq!(
        rpcs.available_providers().len(),
        2,
        "a lagging head doesn't mark the provider unhealthy"
    );
}

#[tokio::test]
async fn wallet_startup_rpc_candidate_rejects_missing_endpoint_block() {
    let root_dir = temp_db_root("wallet-startup-missing-rpc-endpoint");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc = JsonRpcServer::spawn(vec![
        serde_json::json!("0x6e"),
        serde_json::json!([]),
        serde_json::Value::Null,
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    chain.sync.block_range = 10;
    chain.finality_depth = 0;
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
    let mut cfg = test_wallet_config(&scope, rpc.url.clone());
    cfg.start_block = Some(101);

    let result = Arc::clone(&service)
        .wallet_startup_rpc_candidate(
            &cfg,
            WalletShortStartupPlan::new(101, 105, 110, 10).expect("short startup plan"),
            CancellationToken::new(),
        )
        .await;

    assert!(matches!(
        result,
        Err(WalletStartupSyncError::UnprovenRpcEndpoint { block_number: 110 })
    ));
    assert!(
        service
            .public_data_plane
            .cached_wallet_scan_suffix(101, 110)
            .await
            .is_none()
    );
    service.shutdown().await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_startup_rpc_candidate_requires_archive_boundary_proof() {
    let root_dir = temp_db_root("wallet-startup-missing-archive-endpoint");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    // Either provider fails the same way; the read must not try the other.
    let rpc_servers = (0..2)
        .map(|_| {
            JsonRpcServer::spawn(vec![
                serde_json::json!("0x6e"),
                serde_json::json!([]),
                serde_json::json!([]),
                serde_json::Value::Null,
            ])
        })
        .collect::<Vec<_>>();
    let rpcs = Arc::new(QueryRpcPool::new(
        rpc_servers
            .iter()
            .map(|server| server.url.clone())
            .collect(),
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    // The delivery range 106..=110 crosses this archive boundary.
    chain.sync.archive_until_block = 107;
    chain.sync.block_range = 10;
    chain.finality_depth = 0;
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
    let mut cfg = test_wallet_config(&scope, rpc_servers[0].url.clone());
    cfg.start_block = Some(101);

    let result = Arc::clone(&service)
        .wallet_startup_rpc_candidate(
            &cfg,
            WalletShortStartupPlan::new(101, 105, 110, 10).expect("short startup plan"),
            CancellationToken::new(),
        )
        .await;

    assert!(matches!(
        result,
        Err(WalletStartupSyncError::UnprovenRpcEndpoint { block_number: 107 })
    ));
    let mut request_counts = rpc_servers
        .iter()
        .map(|server| server.requests.try_iter().count())
        .collect::<Vec<_>>();
    request_counts.sort_unstable();
    assert_eq!(
        request_counts,
        vec![0, 4],
        "a read that reaches the archive range stays on one provider"
    );
    assert!(
        service
            .public_data_plane
            .cached_wallet_scan_suffix(101, 110)
            .await
            .is_none()
    );
    service.shutdown().await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn multi_page_squid_winner_aborts_blocked_rpc_loser_before_publication() {
    let root_dir = temp_db_root("wallet-startup-hedge-isolation");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let replacement_wallet_utxo = WalletUtxo::new(Utxo::new(
        Note {
            token_hash: U256::from(1),
            value: U256::from(10),
            random: [0x33; 16],
            npk: U256::from(2),
        },
        1,
        9,
        UtxoSource {
            tx_hash: FixedBytes::from([0x55; 32]),
            block_number: 100,
            block_timestamp: 1_700_000_100,
        },
        UtxoCommitmentKind::Transact,
    ));
    let replacement_nullifier = replacement_wallet_utxo.utxo.nullifier(U256::ZERO);
    let (rpc, rpc_block) = JsonRpcServer::spawn_with_blocked_response(
        vec![
            serde_json::json!("0x6a"),
            serde_json::json!([rpc_nullifiers_log_with_value(
                scope.railgun_contract,
                101,
                replacement_nullifier,
            )]),
            rpc_block(101, 1_700_000_101, 0x11),
            rpc_block(106, 1_700_000_106, 0x22),
        ],
        1,
    );
    let mut squid_responses = vec![
        r#"{"data":{"squidStatus":{"height":"106"},"transactCommitments":[],"shieldCommitments":[],"nullifiers":[],"legacyEncryptedCommitments":[],"legacyGeneratedCommitments":[]}}"#
            .to_string(),
    ];
    squid_responses.extend((101..=106).map(|block_number| {
        let nullifier = if block_number == 101 {
            replacement_nullifier
        } else {
            U256::from(block_number)
        };
        indexed_wallet_nullifier_page(block_number, nullifier)
    }));
    let (squid, squid_block) = GraphqlServer::spawn_owned_with_blocked_response(squid_responses, 0);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    chain.sync.block_range = 6;
    chain.sync.indexed_wallet_block_range = 1;
    chain.finality_depth = 0;
    chain.sync.quick_sync_endpoint = Some(squid.url.clone());
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane.clone());
    service.safe_head_tx.send_replace(106);

    let mut first_cfg = test_wallet_config(&scope, squid.url.clone());
    first_cfg.cache_key = test_cache_key("hedge-isolation-wallet-a");
    first_cfg.start_block = Some(101);
    first_cfg.sync_to_block = Some(106);
    db.put_wallet_meta(
        &first_cfg.cache_key,
        &WalletMeta {
            last_scanned_block: 100,
            updated_at: 1,
            last_scanned_block_hash: None,
        },
    )
    .expect("seed first wallet cursor");
    let mut first = service
        .register_wallet(first_cfg)
        .await
        .expect("register first wallet");

    let PathServerBlockControl {
        request_started: squid_request_started,
        release: squid_release,
    } = squid_block;
    let PathServerBlockControl {
        request_started: rpc_request_started,
        release: rpc_release,
    } = rpc_block;
    wait_for_std_signal(squid_request_started, "Squid candidate reached its request").await;
    wait_for_std_signal(rpc_request_started, "RPC loser reached its log request").await;
    squid_release
        .send(())
        .expect("release Squid candidate after RPC loser is blocked");
    tokio::time::timeout(Duration::from_secs(2), first.wait_until_ready())
        .await
        .expect("Squid winner delivered while RPC response remained blocked")
        .expect("wallet readiness succeeded");
    assert_eq!(first.last_scanned(), Some(106));
    rpc_release
        .send(())
        .expect("release terminated RPC request for fixture cleanup");

    let replay = public_data_plane
        .cached_wallet_scan_suffix(101, 106)
        .await
        .expect("complete Squid acquisition remains replayable");
    assert_eq!(
        replay.len(),
        1,
        "six Squid pages should compact into one run"
    );
    let WalletScanRowsPayload::Rows(rows) = &replay[0].rows.payload else {
        panic!("Squid winner rows expected");
    };
    assert_eq!(rows.nullifiers.len(), 6);
    assert_eq!(rows.nullifiers[0].source.block_number, 101);
    assert_eq!(rows.nullifiers[0].nullifier, replacement_nullifier);
    let first_rpc_requests = (0..2)
        .map(|_| {
            rpc.requests
                .recv_timeout(Duration::from_secs(1))
                .expect("RPC loser request")
        })
        .collect::<Vec<_>>();
    assert!(
        first_rpc_requests
            .iter()
            .any(|request| request.contains("eth_getLogs"))
    );
    let squid_requests = (0..7)
        .map(|_| {
            squid
                .requests
                .recv_timeout(Duration::from_secs(1))
                .expect("Squid winner request")
        })
        .collect::<Vec<_>>();
    for block_number in 101..=106 {
        assert!(squid_requests.iter().any(|request| {
            request.contains(&format!("\"fromBlock\":\"{block_number}\""))
                && request.contains(&format!("\"toBlock\":\"{block_number}\""))
        }));
    }

    service.unregister_all_wallets().await;
    let mut second_cfg = test_wallet_config(&scope, squid.url.clone());
    second_cfg.cache_key = test_cache_key("hedge-isolation-wallet-b");
    second_cfg.start_block = Some(101);
    second_cfg.sync_to_block = Some(106);
    db.put_wallet_meta(
        &second_cfg.cache_key,
        &WalletMeta {
            last_scanned_block: 100,
            updated_at: 1,
            last_scanned_block_hash: None,
        },
    )
    .expect("seed replacement wallet cursor");
    db.put_wallet_utxo(
        &second_cfg.cache_key,
        "1:9",
        &serialize_wallet_utxo(&replacement_wallet_utxo).expect("serialize replacement UTXO"),
    )
    .expect("seed replacement wallet UTXO");
    let mut second = service
        .register_wallet(second_cfg)
        .await
        .expect("register replacement wallet");
    tokio::time::timeout(Duration::from_secs(1), second.wait_until_ready())
        .await
        .expect("replacement wallet replayed Squid winner acquisition")
        .expect("wallet readiness succeeded");
    assert_eq!(second.last_scanned(), Some(106));
    let replacement_snapshot = second
        .utxos_snapshot()
        .expect("replacement wallet snapshot");
    assert_eq!(
        replacement_snapshot[0]
            .spent
            .as_ref()
            .expect("leading Squid nullifier marks UTXO spent")
            .block_number,
        101,
    );
    assert!(rpc.requests.try_recv().is_err());
    assert!(squid.requests.try_recv().is_err());

    service.unregister_all_wallets().await;
    service.shutdown().await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn failed_short_startup_hedge_uses_artifact_chunk_spanning_cursor_and_reuses_it() {
    let root_dir = temp_db_root("wallet-startup-artifact-fallback-window");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    // One chunk covers 101..=110, across the first wallet's cursor at 105.
    let artifact_source = checkpointed_wallet_artifact_source(&scope, 101, 110, 110);
    let squid = GraphqlServer::spawn(vec![
        r#"{"errors":[{"message":"indexed source unavailable"}]}"#,
    ]);
    // The RPC head stays below every requested target, so the standalone
    // candidate and the background warm both fail before any data request.
    let rpc = JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 100, |_, _, _| None));
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, Some(artifact_source.config.clone()));
    chain.sync.block_range = 10;
    chain.sync.indexed_wallet_block_range = 10;
    chain.finality_depth = 0;
    chain.sync.quick_sync_endpoint = Some(squid.url.clone());
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
    service.safe_head_tx.send_replace(110);

    let mut first_cfg = test_wallet_config(&scope, squid.url.clone());
    first_cfg.cache_key = test_cache_key("artifact-fallback-wallet-a");
    first_cfg.start_block = Some(101);
    first_cfg.sync_to_block = Some(110);
    db.put_wallet_meta(
        &first_cfg.cache_key,
        &WalletMeta {
            last_scanned_block: 105,
            updated_at: 1,
            last_scanned_block_hash: None,
        },
    )
    .expect("seed first wallet cursor");
    let mut first = service
        .register_wallet(first_cfg)
        .await
        .expect("register first wallet");
    tokio::time::timeout(Duration::from_secs(2), first.wait_until_ready())
        .await
        .expect("artifact fallback startup completed")
        .expect("wallet readiness succeeded");
    assert_eq!(first.last_scanned(), Some(110));
    assert_eq!(
        artifact_source.server.request_count(),
        3,
        "manifest, catalog, and the whole chunk spanning the cursor"
    );
    assert!(
        squid
            .requests
            .recv_timeout(Duration::from_secs(1))
            .expect("failed Squid hedge request")
            .contains("query WalletProbe")
    );

    let mut bodies = Vec::new();
    yield_until("failed hedge RPC and background warm head reads", || {
        bodies.extend(rpc.drain_request_bodies());
        bodies.len() == 2 && !service.public_data_plane.public_window_warm_running()
    })
    .await;
    assert!(
        bodies
            .iter()
            .all(|body| body["method"] == "eth_blockNumber"),
        "neither RPC path issued a data request"
    );
    assert_eq!(
        service
            .public_data_plane
            .cached_wallet_scan_suffix(101, 110)
            .await
            .and_then(|applies| applies.first().map(|apply| apply.from_block)),
        Some(106),
        "chunk rows before the cursor are neither delivered nor recorded"
    );

    service.unregister_all_wallets().await;

    let mut second_cfg = test_wallet_config(&scope, squid.url.clone());
    second_cfg.cache_key = test_cache_key("artifact-fallback-wallet-b");
    second_cfg.start_block = Some(101);
    second_cfg.sync_to_block = Some(110);
    db.put_wallet_meta(
        &second_cfg.cache_key,
        &WalletMeta {
            last_scanned_block: 105,
            updated_at: 1,
            last_scanned_block_hash: None,
        },
    )
    .expect("seed replacement wallet cursor");
    let mut second = service
        .register_wallet(second_cfg)
        .await
        .expect("register replacement wallet");
    tokio::time::timeout(Duration::from_secs(1), second.wait_until_ready())
        .await
        .expect("replacement wallet reused artifact rows")
        .expect("wallet readiness succeeded");
    assert_eq!(second.last_scanned(), Some(110));
    assert_eq!(
        artifact_source.server.request_count(),
        3,
        "replacement wallet should reuse the cached delivery range without HTTP"
    );
    assert_eq!(rpc.drain_request_bodies(), [] as [serde_json::Value; 0]);
    assert!(squid.requests.try_recv().is_err());

    service.unregister_all_wallets().await;
    service.shutdown().await;
    drop(service);
    drop(db);
    drop(artifact_source.server);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn artifact_poi_corpus_survives_wallet_scope_replacement() {
    let root_dir = temp_db_root("artifact-poi-corpus-reregister");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::ZERO,
    };
    let rpc_url = Url::parse("http://127.0.0.1:1").expect("rpc url");
    let chain = test_chain_config(
        &scope,
        Arc::new(QueryRpcPool::new(
            vec![rpc_url.clone()],
            Duration::from_secs(1),
        )),
        None,
    );
    let poi_policy = test_indexed_poi_policy();
    let public_data_plane = if let GlobalPoiPolicy::IndexedArtifacts {
        artifact_source,
        rpc_url,
        ..
    } = &poi_policy
    {
        ChainPublicDataPlane::new(
            Arc::clone(&db),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        )
        .with_poi_cache_service(Arc::new(
            crate::poi_cache::PoiCacheService::new(Arc::clone(&db), artifact_source.clone(), None)
                .expect("initialize POI cache generation")
                .with_poi_rpc_url(rpc_url.clone()),
        ))
    } else {
        unreachable!("test policy is artifact-backed")
    };
    let service = test_chain_service_with_policy(
        Arc::clone(&db),
        chain,
        public_data_plane.clone(),
        poi_policy,
    );
    let list_key = FixedBytes::from([0x31; 32]);
    let blinded_commitment = FixedBytes::from([0x32; 32]);
    let mut cache = PoiCache::new(PoiCacheIdentity::new(
        0,
        scope.chain_id,
        DEFAULT_TXID_VERSION,
        list_key,
    ));
    cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: *blinded_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("seed public POI corpus event");
    cache.accept_current_roots();
    let accepted_root = match &cache.progress().root_validation {
        poi::cache::PoiCacheRootValidation::Validated { roots } => {
            roots.values().next().copied().expect("accepted POI root")
        }
        other => panic!("expected accepted POI roots, got {other:?}"),
    };
    public_data_plane
        .ensure_poi_corpus(PublicPoiCorpusKey::new(
            0,
            scope.chain_id,
            DEFAULT_TXID_VERSION,
        ))
        .await
        .expect("public POI corpus")
        .local_caches()
        .write()
        .await
        .insert(list_key, cache);
    let data_plane_handle = service.public_data_plane();
    assert_eq!(
        data_plane_handle
            .validate_local_poi_roots(DEFAULT_TXID_VERSION, list_key, &[accepted_root])
            .await
            .expect("validate accepted local POI root"),
        LocalPoiRootValidation::Accepted
    );
    assert_eq!(
        data_plane_handle
            .validate_local_poi_roots(
                DEFAULT_TXID_VERSION,
                list_key,
                &[FixedBytes::from([0xff; 32])],
            )
            .await
            .expect("validate absent local POI root"),
        LocalPoiRootValidation::Unavailable(LocalPoiQueryUnavailable::SubmittedRootAbsent {
            list_key,
        })
    );
    assert_eq!(
        data_plane_handle
            .local_poi_statuses(DEFAULT_TXID_VERSION, &[list_key], &blinded_commitment,)
            .await
            .expect("query local POI status"),
        LocalPoiStatusLookup::Valid(BTreeMap::from([(list_key, PoiStatus::Valid)]))
    );
    assert_eq!(
        data_plane_handle
            .local_poi_statuses(
                DEFAULT_TXID_VERSION,
                &[list_key],
                &FixedBytes::from([0xfe; 32]),
            )
            .await
            .expect("query unresolved local POI status"),
        LocalPoiStatusLookup::Unavailable(LocalPoiQueryUnavailable::StatusUnresolved { list_key })
    );
    let proof_source = service
        .public_data_plane()
        .local_poi_merkle_proof_source(DEFAULT_TXID_VERSION)
        .await
        .expect("chain-owned local POI proof source");
    let proofs = proof_source
        .poi_merkle_proofs(
            DEFAULT_TXID_VERSION,
            0,
            scope.chain_id,
            &list_key,
            &[blinded_commitment],
        )
        .await
        .expect("proof from chain-owned local corpus");
    assert_eq!(proofs.len(), 1);
    assert_eq!(proofs[0].leaf, U256::from_be_bytes(blinded_commitment.0));
    let mut cfg = test_wallet_config(&scope, rpc_url);
    cfg.sync_to_block = Some(0);
    cfg.use_indexed_wallet_catch_up = false;
    let corpus_key = PublicPoiCorpusKey::new(0, scope.chain_id, DEFAULT_TXID_VERSION);

    let first = service
        .register_wallet(cfg.clone())
        .await
        .expect("register artifact wallet");
    let first_corpus = public_data_plane
        .ensure_poi_corpus(corpus_key.clone())
        .await
        .expect("first POI corpus")
        .local_caches();
    service.unregister_all_wallets().await;

    let second = service
        .register_wallet(cfg.clone())
        .await
        .expect("re-register artifact wallet");
    let second_corpus = public_data_plane
        .ensure_poi_corpus(corpus_key)
        .await
        .expect("second POI corpus")
        .local_caches();
    service.unregister_wallet(&first).await;

    assert_ne!(first.actor_id(), second.actor_id());
    assert!(first_corpus.ptr_eq(&second_corpus));
    assert_eq!(
        service
            .wallet_handle(&cfg.cache_key)
            .await
            .expect("replacement actor remains registered")
            .actor_id(),
        second.actor_id()
    );
    service.unregister_all_wallets().await;
    service.shutdown().await;
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_startup_events_send_target_before_follow_safe_head_backfill_runs() {
    let root_dir = temp_db_root("wallet-startup-events-token");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cancel = CancellationToken::new();
    let (_live_tx, live_rx) = broadcast::channel(1);
    let (worker_tx, worker_rx) = mpsc::channel(1);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(1);
    let scope = test_scope();
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),
            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: worker_tx,
            public_data_plane: ChainPublicDataPlane::new(
                Arc::clone(&db),
                Arc::new(std::sync::atomic::AtomicU64::new(0)),
            ),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        test_wallet_config(
            &scope,
            Url::parse("http://127.0.0.1:1").expect("quick sync url"),
        ),
        1,
        live_rx,
        worker_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");
    let (sender, mut receiver) = mpsc::channel(4);
    let batch = Arc::new(LogBatch {
        from_block: 101,
        to_block: 105,
        logs: Vec::new(),
        block_timestamps: HashMap::new(),
        to_block_hash: None,
        read_scope: PublicScanReadScope::new(PublicDataPlaneEpoch::new(0)),
    });

    let sender_clone = sender.clone();
    let send_task = tokio::spawn(async move {
        send_wallet_startup_events(
            "test",
            vec![
                WalletScanApply::rows_from_log_batch(101, 105, &batch, PublicScanSource::Rpc)
                    .expect("normalize empty log payload"),
            ],
            Some(105),
            crate::types::WalletSchedulableProgress {
                last_scanned: 100,
                reset_generation: 0,
            },
            &sender_clone,
            &handle,
        )
        .await
    });

    let Some(BackfillEvent::Start {
        target_block,
        token,
        response,
    }) = receiver.recv().await
    else {
        panic!("startup target should accept the token first");
    };
    assert_eq!(target_block, 105);
    assert_eq!(token.reset_generation(), 0);
    response
        .send(WalletBackfillStartResult::Accepted {
            committed_to: 100,
            target_block,
            grant: WalletBackfillGrant::from_token(token, sender.clone()),
        })
        .expect("send initial target result");

    let Some(BackfillEvent::Apply {
        apply,
        token: apply_token,
        response,
    }) = receiver.recv().await
    else {
        panic!("startup logs should be sent first");
    };
    assert_eq!(apply.from_block, 101);
    assert_eq!(apply.to_block, 105);
    let WalletScanRowsPayload::Rows(rows) = apply.rows.payload else {
        panic!("startup apply should contain normalized rows");
    };
    assert_eq!(rows.row_count(), 0);
    assert_eq!(apply_token, token);
    response
        .send(WalletBackfillApplyResult::Committed { committed_to: 105 })
        .expect("send apply result");
    let Some(BackfillEvent::Finish {
        target_block,
        token: finish_token,
        response,
    }) = receiver.recv().await
    else {
        panic!("startup target should be sent after logs");
    };
    assert_eq!(target_block, 105);
    assert_eq!(finish_token, token);
    response
        .send(WalletBackfillFinishResult::Ready { committed_to: 105 })
        .expect("send target result");
    assert!(send_task.await.expect("send task completed"));
    assert!(receiver.try_recv().is_err());
    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_startup_events_treat_leading_ready_as_success() {
    let root_dir = temp_db_root("wallet-startup-events-leading-ready");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cancel = CancellationToken::new();
    let (_live_tx, live_rx) = broadcast::channel(1);
    let (worker_tx, worker_rx) = mpsc::channel(1);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(1);
    let scope = test_scope();
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),
            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: worker_tx,
            public_data_plane: ChainPublicDataPlane::new(
                Arc::clone(&db),
                Arc::new(std::sync::atomic::AtomicU64::new(0)),
            ),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        test_wallet_config(
            &scope,
            Url::parse("http://127.0.0.1:1").expect("quick sync url"),
        ),
        1,
        live_rx,
        worker_rx,
        cancel.clone(),
        Vec::new(),
        105,
    )
    .await
    .expect("spawn wallet worker");
    let (sender, mut receiver) = mpsc::channel(4);
    let batch = Arc::new(LogBatch {
        from_block: 101,
        to_block: 105,
        logs: Vec::new(),
        block_timestamps: HashMap::new(),
        to_block_hash: None,
        read_scope: PublicScanReadScope::new(PublicDataPlaneEpoch::new(0)),
    });

    let sender_clone = sender.clone();
    let send_task = tokio::spawn(async move {
        send_wallet_startup_events(
            "test",
            vec![
                WalletScanApply::rows_from_log_batch(101, 105, &batch, PublicScanSource::Rpc)
                    .expect("normalize empty log payload"),
            ],
            Some(105),
            crate::types::WalletSchedulableProgress {
                last_scanned: 0,
                reset_generation: 0,
            },
            &sender_clone,
            &handle,
        )
        .await
    });

    let Some(BackfillEvent::Start {
        target_block,
        token,
        response,
    }) = receiver.recv().await
    else {
        panic!("startup target should be sent");
    };
    assert_eq!(target_block, 105);
    response
        .send(WalletBackfillStartResult::Accepted {
            committed_to: 105,
            target_block,
            grant: WalletBackfillGrant::from_token(token, sender.clone()),
        })
        .expect("send accepted start result");
    let Some(BackfillEvent::Apply { response, .. }) = receiver.recv().await else {
        panic!("startup apply should be sent");
    };
    response
        .send(WalletBackfillApplyResult::AlreadyCovered { committed_to: 105 })
        .expect("send covered apply result");
    let Some(BackfillEvent::Finish { response, .. }) = receiver.recv().await else {
        panic!("startup finish should be sent");
    };
    response
        .send(WalletBackfillFinishResult::Ready { committed_to: 105 })
        .expect("send ready finish result");
    assert!(send_task.await.expect("send task completed"));
    assert!(receiver.try_recv().is_err());

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_startup_events_retire_token_on_apply_failure() {
    let root_dir = temp_db_root("wallet-startup-events-retire-failure");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cancel = CancellationToken::new();
    let (_live_tx, live_rx) = broadcast::channel(1);
    let (worker_tx, worker_rx) = mpsc::channel(1);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(1);
    let scope = test_scope();
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),
            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: worker_tx,
            public_data_plane: ChainPublicDataPlane::new(
                Arc::clone(&db),
                Arc::new(std::sync::atomic::AtomicU64::new(0)),
            ),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        test_wallet_config(
            &scope,
            Url::parse("http://127.0.0.1:1").expect("quick sync url"),
        ),
        1,
        live_rx,
        worker_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");
    let (sender, mut receiver) = mpsc::channel(4);
    let batch = Arc::new(LogBatch {
        from_block: 101,
        to_block: 105,
        logs: Vec::new(),
        block_timestamps: HashMap::new(),
        to_block_hash: None,
        read_scope: PublicScanReadScope::new(PublicDataPlaneEpoch::new(0)),
    });

    let sender_clone = sender.clone();
    let send_task = tokio::spawn(async move {
        send_wallet_startup_events(
            "test",
            vec![
                WalletScanApply::rows_from_log_batch(101, 105, &batch, PublicScanSource::Rpc)
                    .expect("normalize empty log payload"),
            ],
            Some(105),
            crate::types::WalletSchedulableProgress {
                last_scanned: 0,
                reset_generation: 0,
            },
            &sender_clone,
            &handle,
        )
        .await
    });

    let Some(BackfillEvent::Start {
        target_block,
        token,
        response,
    }) = receiver.recv().await
    else {
        panic!("startup target should be sent");
    };
    response
        .send(WalletBackfillStartResult::Accepted {
            committed_to: 100,
            target_block,
            grant: WalletBackfillGrant::from_token(token, sender.clone()),
        })
        .expect("send target result");

    let Some(BackfillEvent::Apply { response, .. }) = receiver.recv().await else {
        panic!("startup apply should be sent");
    };
    response
        .send(WalletBackfillApplyResult::Rejected {
            committed_to: 100,
            reason: WalletBackfillRejectReason::ApplyFailed,
        })
        .expect("send apply failure");

    assert!(!send_task.await.expect("send task completed"));
    assert!(receiver.try_recv().is_err());

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_startup_events_retire_partial_token_without_done_block() {
    let root_dir = temp_db_root("wallet-startup-events-retire-partial");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cancel = CancellationToken::new();
    let (_live_tx, live_rx) = broadcast::channel(1);
    let (worker_tx, worker_rx) = mpsc::channel(1);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(1);
    let scope = test_scope();
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),
            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: worker_tx,
            public_data_plane: ChainPublicDataPlane::new(
                Arc::clone(&db),
                Arc::new(std::sync::atomic::AtomicU64::new(0)),
            ),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        test_wallet_config(
            &scope,
            Url::parse("http://127.0.0.1:1").expect("quick sync url"),
        ),
        1,
        live_rx,
        worker_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");
    let (sender, mut receiver) = mpsc::channel(4);
    let batch = Arc::new(LogBatch {
        from_block: 101,
        to_block: 105,
        logs: Vec::new(),
        block_timestamps: HashMap::new(),
        to_block_hash: None,
        read_scope: PublicScanReadScope::new(PublicDataPlaneEpoch::new(0)),
    });

    let sender_clone = sender.clone();
    let send_task = tokio::spawn(async move {
        send_wallet_startup_events(
            "test",
            vec![
                WalletScanApply::rows_from_log_batch(101, 105, &batch, PublicScanSource::Rpc)
                    .expect("normalize empty log payload"),
            ],
            None,
            crate::types::WalletSchedulableProgress {
                last_scanned: 0,
                reset_generation: 0,
            },
            &sender_clone,
            &handle,
        )
        .await
    });

    let Some(BackfillEvent::Start {
        target_block,
        token,
        response,
    }) = receiver.recv().await
    else {
        panic!("startup target should be sent");
    };
    response
        .send(WalletBackfillStartResult::Accepted {
            committed_to: 100,
            target_block,
            grant: WalletBackfillGrant::from_token(token, sender.clone()),
        })
        .expect("send target result");

    let Some(BackfillEvent::Apply { response, .. }) = receiver.recv().await else {
        panic!("startup apply should be sent");
    };
    response
        .send(WalletBackfillApplyResult::Committed { committed_to: 105 })
        .expect("send apply success");

    assert!(send_task.await.expect("send task completed"));
    assert!(receiver.try_recv().is_err());

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn short_startup_with_indexed_sources_behind_cursor_delivers_from_rpc_after_cursor() {
    let root_dir = temp_db_root("short-startup-indexed-behind-cursor");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    // Both indexed sources stop at block 103, below the wallet cursor at 105.
    let artifact_source = checkpointed_wallet_artifact_source(&scope, 101, 103, 103);
    let squid = GraphqlServer::spawn(vec![
        r#"{"data":{"squidStatus":{"height":"103"},"transactCommitments":[],"shieldCommitments":[],"nullifiers":[],"legacyEncryptedCommitments":[],"legacyGeneratedCommitments":[]}}"#,
    ]);
    // A head below the target fails the standalone RPC candidate, the Squid
    // tail, and the background warm, while the backfill loop's range fetch
    // (which does not read the head) still succeeds.
    let rpc = JsonRpcServer::spawn_handler(log_range_rpc_handler(
        vec![rpc_nullifiers_log_with_timestamp(
            scope.railgun_contract,
            108,
        )],
        100,
        |_, _, _| None,
    ));
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(
        &scope,
        Arc::clone(&rpcs),
        Some(artifact_source.config.clone()),
    );
    chain.sync.block_range = 10;
    chain.sync.indexed_wallet_block_range = 10;
    chain.finality_depth = 0;
    chain.sync.quick_sync_endpoint = Some(squid.url.clone());
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let (service, backfill_rx) = test_chain_service_with_backfill(
        Arc::clone(&db),
        chain,
        public_data_plane,
        test_proxy_poi_policy(),
    );
    service.safe_head_tx.send_replace(110);
    spawn_backfill_loop(
        Arc::clone(&service),
        backfill_rx,
        rpcs,
        None,
        service.safe_head_tx.subscribe(),
        service.cancel.clone(),
    );

    let mut cfg = test_wallet_config(&scope, squid.url.clone());
    cfg.cache_key = test_cache_key("indexed-behind-cursor");
    cfg.start_block = Some(101);
    cfg.sync_to_block = Some(110);
    db.put_wallet_meta(
        &cfg.cache_key,
        &WalletMeta {
            last_scanned_block: 105,
            updated_at: 1,
            last_scanned_block_hash: None,
        },
    )
    .expect("seed wallet cursor");
    let mut handle = service.register_wallet(cfg).await.expect("register wallet");
    tokio::time::timeout(Duration::from_secs(2), handle.wait_until_ready())
        .await
        .expect("RPC delivery after the cursor completed")
        .expect("wallet readiness succeeded");
    assert_eq!(handle.last_scanned(), Some(110));

    // Head reads: the standalone candidate, the Squid tail, and the warm.
    let mut bodies = Vec::new();
    yield_until("startup requests and failed background warm", || {
        bodies.extend(rpc.drain_request_bodies());
        bodies
            .iter()
            .filter(|body| body["method"] == "eth_blockNumber")
            .count()
            == 3
            && !service.public_data_plane.public_window_warm_running()
    })
    .await;
    assert_eq!(
        get_logs_ranges(&bodies),
        vec![(106, 110)],
        "delivery comes from one RPC range that starts after the cursor"
    );
    let squid_requests = squid.requests.try_iter().collect::<Vec<_>>();
    assert_eq!(squid_requests.len(), 1);
    assert!(
        squid_requests[0].contains("query WalletProbe"),
        "Squid is probed for its height but no rows are requested"
    );
    // Manifest and catalog reads are metadata and may run (the TXID cache
    // loop also reads the manifest once the wallet is ready); chunks are data.
    let artifact_paths = artifact_source.server.requested_paths();
    assert!(artifact_paths.iter().any(|path| path == "/manifest.json"));
    assert!(
        artifact_source.chunk_descriptors.iter().all(|chunk| {
            let chunk_path = format!("/ipfs/{}?format=car&dag-scope=entity", chunk.cid);
            !artifact_paths.contains(&chunk_path)
        }),
        "the artifacts end before the cursor, so no chunk is fetched: {artifact_paths:?}"
    );
    assert_eq!(
        service
            .public_data_plane
            .cached_wallet_scan_suffix(101, 110)
            .await
            .and_then(|applies| applies.first().map(|apply| apply.from_block)),
        Some(106)
    );

    service.unregister_all_wallets().await;
    service.shutdown().await;
    drop(service);
    drop(artifact_source.server);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn short_startup_squid_tail_below_cursor_starts_at_delivery_boundary() {
    let root_dir = temp_db_root("short-startup-squid-tail-below-cursor");
    let events = CapturedEvents::default();
    let _guard = events.capture();
    let hedge_winner = || {
        events
            .events()
            .into_iter()
            .find(|event| {
                event
                    .get("message")
                    .is_some_and(|message| message == "wallet startup hedge complete")
            })
            .and_then(|event| event.get("winner").cloned())
    };
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    // Squid stops at block 103, below the wallet cursor at 105.
    let squid = GraphqlServer::spawn(vec![
        r#"{"data":{"squidStatus":{"height":"103"},"transactCommitments":[],"shieldCommitments":[],"nullifiers":[],"legacyEncryptedCommitments":[],"legacyGeneratedCommitments":[]}}"#,
    ]);
    // The standalone RPC candidate reads the head first, before the Squid
    // probe completes, and fails on a head below the target. The Squid
    // candidate's RPC tail and the background warm see a head that covers it.
    // The winner assertion below fails the test if that order ever changes.
    let serve = log_range_rpc_handler(
        vec![rpc_nullifiers_log_with_timestamp(
            scope.railgun_contract,
            108,
        )],
        110,
        |_, _, _| None,
    );
    let head_reads = AtomicU64::new(0);
    let rpc = JsonRpcServer::spawn_handler(move |request| {
        if request["method"] == "eth_blockNumber" && head_reads.fetch_add(1, Ordering::Relaxed) == 0
        {
            serde_json::json!({ "result": "0x64" })
        } else {
            serve(request)
        }
    });
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    chain.sync.block_range = 10;
    chain.sync.indexed_wallet_block_range = 10;
    chain.finality_depth = 0;
    chain.sync.quick_sync_endpoint = Some(squid.url.clone());
    let public_data_plane = ChainPublicDataPlane::new(Arc::clone(&db), Arc::new(AtomicU64::new(0)));
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
    service.safe_head_tx.send_replace(110);

    let mut cfg = test_wallet_config(&scope, squid.url.clone());
    cfg.cache_key = test_cache_key("squid-tail-below-cursor");
    cfg.start_block = Some(101);
    cfg.sync_to_block = Some(110);
    db.put_wallet_meta(
        &cfg.cache_key,
        &WalletMeta {
            last_scanned_block: 105,
            updated_at: 1,
            last_scanned_block_hash: None,
        },
    )
    .expect("seed wallet cursor");
    let mut handle = service.register_wallet(cfg).await.expect("register wallet");
    tokio::time::timeout(Duration::from_secs(2), handle.wait_until_ready())
        .await
        .expect("Squid RPC tail delivery completed")
        .expect("wallet readiness succeeded");
    assert_eq!(handle.last_scanned(), Some(110));

    // Endpoint-block reads: the Squid tail's and the warm's.
    let mut bodies = Vec::new();
    yield_until("Squid tail delivery and background warm", || {
        bodies.extend(rpc.drain_request_bodies());
        header_blocks(&bodies).len() == 2
            && !service.public_data_plane.public_window_warm_running()
            && hedge_winner().is_some()
    })
    .await;
    assert_eq!(
        hedge_winner().as_deref(),
        Some("indexed"),
        "the Squid candidate delivered through its RPC tail"
    );
    assert_eq!(
        get_logs_ranges(&bodies),
        vec![(106, 110), (101, 105)],
        "the RPC tail starts at the delivery boundary, not after the Squid height; \
         the prefix is fetched by the warm after delivery"
    );

    service.unregister_all_wallets().await;
    service.shutdown().await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn startup_window_warm_stops_on_public_cache_reset_and_shutdown() {
    let root_dir = temp_db_root("startup-window-warm-reset");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let (release_first, first_gate) = std_mpsc::channel();
    let (release_second, second_gate) = std_mpsc::channel();
    let (release_third, third_gate) = std_mpsc::channel();
    let rpc = JsonRpcServer::spawn_handler(gated_get_logs_handler(
        log_range_rpc_handler(Vec::new(), 200, reject_spans_over_25),
        vec![
            ((1, 25), first_gate),
            ((26, 50), second_gate),
            ((101, 125), third_gate),
        ],
    ));
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, rpcs, None);
    chain.sync.block_range = 100;
    chain.finality_depth = 0;
    let public_data_plane = ChainPublicDataPlane::new(Arc::clone(&db), Arc::new(AtomicU64::new(0)));
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
    let window = PublicScanRange::new(1, 100);
    let mut bodies = Vec::new();

    // The first split request completes, then the reset lands before the
    // warm task can issue the next one.
    service.start_public_scan_window_warm(window).await;
    yield_until("first split request", || {
        bodies.extend(rpc.drain_request_bodies());
        get_logs_ranges(&bodies).contains(&(1, 25))
    })
    .await;
    release_first.send(()).expect("release first split request");
    service
        .public_data_plane
        .reset_public_cache()
        .await
        .expect("reset between split requests");
    assert!(!service.public_data_plane.public_window_warm_running());
    bodies.extend(rpc.drain_request_bodies());
    assert_eq!(get_logs_ranges(&bodies), vec![(1, 100), (1, 25)]);

    // A later warm starts, and a reset cancels its in-flight request.
    service.start_public_scan_window_warm(window).await;
    assert!(
        service.public_data_plane.public_window_warm_running(),
        "the slot is free after a reset"
    );
    yield_until("second split request in flight", || {
        bodies.extend(rpc.drain_request_bodies());
        get_logs_ranges(&bodies).contains(&(26, 50))
    })
    .await;
    service
        .public_data_plane
        .reset_public_cache()
        .await
        .expect("reset during an in-flight request");
    assert!(!service.public_data_plane.public_window_warm_running());
    release_second.send(()).expect("release cancelled request");
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    bodies.extend(rpc.drain_request_bodies());
    assert_eq!(
        get_logs_ranges(&bodies),
        vec![(1, 100), (1, 25), (1, 25), (26, 50)],
        "no request follows either reset"
    );
    assert!(
        header_blocks(&bodies).is_empty(),
        "cancelled warms never prove an endpoint block"
    );

    // A held reset permit blocks new starts; after its release a warm runs
    // uninterrupted and proves its range end.
    let permit = service
        .public_data_plane()
        .acquire_public_cache_reset_permit()
        .await;
    service.start_public_scan_window_warm(window).await;
    assert!(
        !service.public_data_plane.public_window_warm_running(),
        "no warm starts while a reset permit is held"
    );
    drop(permit);
    service.start_public_scan_window_warm(window).await;
    yield_until("warm after resets", || {
        !service.public_data_plane.public_window_warm_running()
    })
    .await;
    bodies.extend(rpc.drain_request_bodies());
    assert_eq!(
        get_logs_ranges(&bodies)[4..],
        [(1, 25), (26, 50), (51, 75), (76, 100)]
    );
    assert_eq!(
        header_blocks(&bodies),
        vec![100],
        "the uninterrupted warm reads its endpoint block"
    );
    assert!(
        service
            .public_data_plane
            .cached_wallet_scan_exact(1, 100)
            .await
            .is_some(),
        "an uninterrupted warm records the window as reusable coverage"
    );

    // Chain-service shutdown stops a warm whose request is in flight and
    // closes the slot to later starts.
    let later_window = PublicScanRange::new(101, 200);
    service.start_public_scan_window_warm(later_window).await;
    yield_until("warm request in flight at shutdown", || {
        bodies.extend(rpc.drain_request_bodies());
        get_logs_ranges(&bodies).contains(&(101, 125))
    })
    .await;
    service.shutdown().await;
    assert!(!service.public_data_plane.public_window_warm_running());
    service.start_public_scan_window_warm(later_window).await;
    assert!(
        !service.public_data_plane.public_window_warm_running(),
        "no warm starts after shutdown"
    );
    release_third.send(()).expect("release cancelled request");
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    bodies.extend(rpc.drain_request_bodies());
    assert_eq!(
        get_logs_ranges(&bodies)[8..],
        [(101, 125)],
        "no request follows shutdown"
    );
    assert_eq!(header_blocks(&bodies), vec![100]);

    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

fn test_poi_artifact_source_config() -> PoiArtifactSourceConfig {
    PoiArtifactSourceConfig {
        trusted_publisher_pubkey: FixedBytes::from([0x42; 32]),
        manifest_source: PoiArtifactManifestSource::Url(
            Url::parse("http://127.0.0.1:1/poi-manifest.json")
                .expect("POI manifest URL")
                .into(),
        ),
        gateway_urls: Vec::new(),
        gateway_pool: None,
        max_manifest_age: None,
    }
}

fn test_indexed_poi_policy() -> GlobalPoiPolicy {
    GlobalPoiPolicy::IndexedArtifacts {
        artifact_source: test_poi_artifact_source_config(),
        rpc_url: Url::parse("http://127.0.0.1:1")
            .expect("POI RPC URL")
            .into(),
        wallet_read_fallback: PoiProxyFallback::Disabled,
    }
}

/// Runs the short startup RPC candidate that delivers blocks 106..=110 on a
/// pool of `rpc_urls`, and returns its delivery applies and the pool.
async fn run_wallet_startup_rpc_candidate(
    name: &str,
    rpc_urls: Vec<Url>,
) -> (
    Result<Vec<WalletScanApply>, WalletStartupSyncError>,
    Arc<QueryRpcPool>,
) {
    let root_dir = temp_db_root(name);
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpcs = Arc::new(QueryRpcPool::new(rpc_urls, Duration::from_mins(1)));
    let mut chain = test_chain_config(&scope, Arc::clone(&rpcs), None);
    chain.sync.block_range = 10;
    chain.finality_depth = 0;
    let public_data_plane = ChainPublicDataPlane::new(Arc::clone(&db), Arc::new(AtomicU64::new(0)));
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
    let mut cfg = test_wallet_config(
        &scope,
        Url::parse("http://127.0.0.1:1").expect("unused Squid URL"),
    );
    cfg.start_block = Some(101);

    let result = Arc::clone(&service)
        .wallet_startup_rpc_candidate(
            &cfg,
            WalletShortStartupPlan::new(101, 105, 110, 10).expect("short startup plan"),
            CancellationToken::new(),
        )
        .await
        .map(|candidate| candidate.applies);
    service.shutdown().await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
    (result, rpcs)
}
