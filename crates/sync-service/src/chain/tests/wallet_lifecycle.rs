use super::*;

#[tokio::test]
async fn restored_replay_is_published_before_startup_planner_can_supersede_it() {
    let root_dir = temp_db_root("service-restored-replay-admission");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc_url = Url::parse("http://127.0.0.1:1").expect("rpc url");
    let chain = test_chain_config(
        &scope,
        Arc::new(QueryRpcPool::new(
            vec![rpc_url.clone()],
            Duration::from_secs(1),
        )),
        None,
    );
    let service = test_chain_service_with_backfill(
        Arc::clone(&db),
        chain,
        ChainPublicDataPlane::new(
            Arc::clone(&db),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ),
        test_proxy_poi_policy(),
    );
    let (service, mut backfill_rx) = service;
    let mut cfg = test_wallet_config(&scope, rpc_url);
    cfg.start_block = Some(100);
    cfg.use_indexed_wallet_catch_up = false;
    db.put_wallet_meta(
        &cfg.cache_key,
        &WalletMeta {
            last_scanned_block: 79,
            updated_at: 1,
            last_scanned_block_hash: None,
        },
    )
    .expect("seed post-rewind cursor");
    db.put_wallet_sync_actor_state(&WalletSyncActorStateRecord {
        chain_id: cfg.chain.chain_id,
        wallet_id: cfg.cache_key.to_string(),
        highest_accepted_reset_intent: 7,
        pending_reset: Some(WalletPendingResetRecord {
            intent_id: 7,
            from_block: 80,
            replay_start_block: 80,
            replay_target_block: 99,
            follow_safe_head: false,
        }),
        updated_at: 1,
    })
    .expect("seed restored replay");

    let handle = service
        .register_wallet(cfg.clone())
        .await
        .expect("register wallet");
    let request = tokio::time::timeout(Duration::from_secs(1), backfill_rx.recv())
        .await
        .expect("restored replay Add arrives")
        .expect("backfill channel remains open");
    let BackfillRequest::Add {
        from_block,
        to_block,
        driver,
        cache_key,
        ..
    } = request
    else {
        panic!("restored replay must be the first backfill request");
    };
    assert_eq!((from_block, to_block), (80, 99));
    assert_eq!(driver.token().actor_id(), handle.actor_id());
    assert!(
        service
            .wallet
            .read()
            .await
            .as_ref()
            .is_some_and(|registration| registration.handle.same_actor_as(&handle))
    );
    assert_eq!(handle.readiness(), WalletReadiness::Syncing);

    service.safe_head_tx.send_replace(120);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), backfill_rx.recv())
            .await
            .is_err(),
        "generic startup must wait for restored replay completion"
    );
    assert_eq!(handle.readiness(), WalletReadiness::Syncing);

    driver.retire(&cache_key).await;
    let unregistering = tokio::spawn({
        let service = Arc::clone(&service);
        let handle = handle.clone();
        async move { service.unregister_wallet(&handle).await }
    });
    let remove = tokio::time::timeout(Duration::from_secs(1), backfill_rx.recv())
        .await
        .expect("wallet removal request arrives")
        .expect("backfill channel remains open");
    let BackfillRequest::Remove { response, .. } = remove else {
        panic!("wallet cleanup must request removal");
    };
    response.send(()).expect("acknowledge wallet removal");
    tokio::time::timeout(Duration::from_secs(1), unregistering)
        .await
        .expect("wallet unregister completes")
        .expect("wallet unregister task joins");
    service.cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn zero_head_backfill_loop_retires_and_replaces_target_zero_wallets() {
    let root_dir = temp_db_root("zero-head-backfill-retirement");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc_url = Url::parse("http://127.0.0.1:1").expect("rpc url");
    let chain = test_chain_config(
        &scope,
        Arc::new(QueryRpcPool::new(
            vec![rpc_url.clone()],
            Duration::from_secs(1),
        )),
        None,
    );
    let (service, backfill_rx) = test_chain_service_with_backfill(
        Arc::clone(&db),
        chain,
        ChainPublicDataPlane::new(
            Arc::clone(&db),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ),
        test_proxy_poi_policy(),
    );
    spawn_backfill_loop(
        Arc::clone(&service),
        backfill_rx,
        service.chain.rpcs.clone(),
        None,
        service.safe_head_tx.subscribe(),
        service.cancel.clone(),
    );

    let old = install_test_backfill_actor(&service, &scope, rpc_url.clone(), "zero-head-old").await;
    let (barrier_tx, barrier_rx) = oneshot::channel();
    service
        .backfill_tx
        .send(BackfillRequest::Remove {
            cache_key: old.cache_key.to_string(),
            actor_id: old.actor_id().saturating_add(1),
            response: barrier_tx,
        })
        .await
        .expect("send zero-head parked-state probe");
    tokio::time::timeout(Duration::from_secs(1), barrier_rx)
        .await
        .expect("zero-head loop acknowledges parked-state probe")
        .expect("zero-head probe acknowledgement remains connected");
    tokio::task::yield_now().await;

    tokio::time::timeout(Duration::from_secs(1), service.unregister_wallet(&old))
        .await
        .expect("unregister completes while safe head remains zero");
    assert!(service.wallet.read().await.is_none());

    let middle =
        install_test_backfill_actor(&service, &scope, rpc_url.clone(), "zero-head-middle").await;
    let (middle_barrier_tx, middle_barrier_rx) = oneshot::channel();
    service
        .backfill_tx
        .send(BackfillRequest::Remove {
            cache_key: middle.cache_key.to_string(),
            actor_id: middle.actor_id().saturating_add(1),
            response: middle_barrier_tx,
        })
        .await
        .expect("send second zero-head parked-state probe");
    tokio::time::timeout(Duration::from_secs(1), middle_barrier_rx)
        .await
        .expect("second zero-head probe is acknowledged")
        .expect("second zero-head probe acknowledgement remains connected");

    let mut successor_cfg = test_wallet_config(&scope, rpc_url);
    successor_cfg.cache_key = test_cache_key("zero-head-successor");
    successor_cfg.sync_to_block = Some(0);
    successor_cfg.use_indexed_wallet_catch_up = false;
    let successor = tokio::time::timeout(
        Duration::from_secs(1),
        service.replace_wallet(successor_cfg),
    )
    .await
    .expect("replace completes while safe head remains zero")
    .expect("replace succeeds");
    assert!(
        service
            .wallet_handle(successor.cache_key.as_str())
            .await
            .is_some_and(|handle| handle.same_actor_as(&successor))
    );

    tokio::time::timeout(
        Duration::from_secs(1),
        service.unregister_wallet(&successor),
    )
    .await
    .expect("successor unregister completes");
    service.cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn concurrent_register_wallet_returns_single_actor_handle() {
    let root_dir = temp_db_root("concurrent-register-wallet");
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
    let chain = ChainConfig {
        deployment: broadcaster_core::deployment::RailgunDeployment {
            chain_id: scope.chain_id,
            contract: scope.railgun_contract,
            deployment_block: 0,
            v2_start_block: 0,
            legacy_shield_block: 0,
            relay_adapt_contract: None,
            relay_adapt_7702_contract: Address::ZERO,
            relay_adapt_7702_delegates: &[],
            relay_adapt_history: &[],
        },
        sync: crate::RailgunSyncOptions {
            archive_until_block: 0,
            block_range: 100,
            indexed_wallet_block_range: 100,
            poll_interval: Duration::from_millis(1),
            quick_sync_endpoint: None,
            indexed_artifact_source: None,
            anchor_interval: 1000,
            anchor_retention: 5,
        },
        rpcs: Arc::new(QueryRpcPool::new(
            vec![rpc_url.clone()],
            Duration::from_secs(1),
        )),
        archive_rpc_url: None,
        archive_rpc_http_client: None,
        block_time: Duration::from_secs(12),
        finality_depth: 0,
        http_client: reqwest::Client::new(),
        progress_tx: None,
        poi_submission_routes: None,
    };
    let (head_tx, _head_rx) = watch::channel(0);
    let (safe_head_tx, _safe_head_rx) = watch::channel(0);
    let (forest_last_tx, _forest_last_rx) = watch::channel(0);
    let (live_log_tx, _live_log_rx) = broadcast::channel(8);
    let (backfill_tx, mut backfill_rx) = mpsc::channel(8);
    let backfill_task = tokio::spawn(async move {
        while let Some(request) = backfill_rx.recv().await {
            match request {
                BackfillRequest::Add {
                    driver, cache_key, ..
                } => {
                    driver.retire(&cache_key).await;
                }
                BackfillRequest::Remove { response, .. } => {
                    let _ = response.send(());
                }
            }
        }
    });
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = Arc::new(ChainService {
        chain,
        poi_policy: test_proxy_poi_policy(),
        db: Arc::clone(&db),
        forest: Arc::new(RwLock::new(MerkleForest::new())),
        head_tx,
        safe_head_tx,
        forest_last_tx,
        live_log_tx,
        backfill_tx,
        archive_provider: None,
        wallet: RwLock::new(None),
        wallet_registration_gate: Mutex::new(()),
        cancel: CancellationToken::new(),
        live_log_task: std::sync::Mutex::new(None),
        poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        poi_submitter_task: std::sync::Mutex::new(None),
        anchor_last: std::sync::atomic::AtomicU64::new(0),
        txid_public_cache_started: std::sync::atomic::AtomicBool::new(false),
        txid_public_cache_task: std::sync::Mutex::new(None),
        amount_statistics: crate::amount_statistics::ChainAmountStatistics::default(),
        wallet_actor_next: std::sync::atomic::AtomicU64::new(1),
        wallet_reset_intent_next: std::sync::atomic::AtomicU64::new(1),
        public_data_plane,
    });
    let mut cfg = test_wallet_config(&scope, rpc_url);
    cfg.quick_sync_endpoint = None;
    cfg.sync_to_block = Some(0);
    cfg.use_indexed_wallet_catch_up = false;

    let (first, second) = tokio::join!(
        service.register_wallet(cfg.clone()),
        service.register_wallet(cfg.clone()),
    );
    let first = first.expect("register first wallet");
    let second = second.expect("register second wallet");

    assert_eq!(first.actor_id(), second.actor_id());
    assert_eq!(first.actor_id(), 1);
    assert!(service.wallet.read().await.is_some());
    assert_eq!(
        service
            .wallet_actor_next
            .load(std::sync::atomic::Ordering::Acquire),
        2
    );

    first.publish_readiness_for_test(&WalletReadiness::Ready);
    assert_eq!(first.readiness(), WalletReadiness::Ready);
    let retained_observation = first.subscribe_observation();
    let held_authority = first.hold_actor_authority_for_test().await;
    tokio::time::timeout(Duration::from_secs(1), service.unregister_wallet(&first))
        .await
        .expect("unregister awaits the wallet worker without authority-lock contention");
    assert_eq!(
        retained_observation.borrow().readiness(),
        &WalletReadiness::Shutdown
    );
    assert!(matches!(
        retained_observation.borrow().view(),
        WalletViewState::Inactive {
            reason: WalletInactiveReason::Retired,
            ..
        }
    ));
    drop(held_authority);
    let mut distinct_a = cfg.clone();
    distinct_a.cache_key = test_cache_key("distinct-a");
    let mut distinct_b = cfg.clone();
    distinct_b.cache_key = test_cache_key("distinct-b");
    let (distinct_a, distinct_b) = tokio::join!(
        service.register_wallet(distinct_a),
        service.register_wallet(distinct_b),
    );
    assert_eq!(
        [distinct_a.is_ok(), distinct_b.is_ok()]
            .into_iter()
            .filter(|registered| *registered)
            .count(),
        1
    );
    let distinct_conflicts = usize::from(matches!(
        &distinct_a,
        Err(ChainError::WalletAlreadyRegistered)
    )) + usize::from(matches!(
        &distinct_b,
        Err(ChainError::WalletAlreadyRegistered)
    ));
    assert_eq!(distinct_conflicts, 1);
    let distinct_handle = distinct_a.or(distinct_b).expect("one distinct wallet wins");
    service.unregister_wallet(&distinct_handle).await;
    service.cancel.cancel();
    drop(service);
    backfill_task
        .await
        .expect("backfill acknowledgement task joins");
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn unexpected_terminal_wallet_is_reaped_and_concurrent_retry_replaces_once() {
    let root_dir = temp_db_root("unexpected-terminal-wallet-replacement");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc_url = Url::parse("http://127.0.0.1:1").expect("rpc url");
    let (service, mut backfill_rx) = test_chain_service_with_backfill(
        Arc::clone(&db),
        test_chain_config(
            &scope,
            Arc::new(QueryRpcPool::new(
                vec![rpc_url.clone()],
                Duration::from_secs(1),
            )),
            None,
        ),
        ChainPublicDataPlane::new(
            Arc::clone(&db),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ),
        test_proxy_poi_policy(),
    );
    let mut cfg = test_wallet_config(&scope, rpc_url);
    cfg.sync_to_block = Some(0);
    cfg.use_indexed_wallet_catch_up = false;
    let terminal = service
        .register_wallet(cfg.clone())
        .await
        .expect("register terminal wallet");
    let worker_cancel = service
        .wallet
        .read()
        .await
        .as_ref()
        .expect("terminal wallet registration")
        .cancel
        .clone();

    worker_cancel.cancel();
    tokio::time::timeout(Duration::from_secs(1), async {
        while terminal.readiness() != WalletReadiness::Shutdown {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("unexpected worker termination published shutdown");
    assert!(service.wallet_handle(&cfg.cache_key).await.is_none());

    let mut displaced_cfg = cfg.clone();
    displaced_cfg.cache_key = test_cache_key("terminal-displaced-by-b");
    let registering_cfg = displaced_cfg.clone();
    let registering = tokio::spawn({
        let service = Arc::clone(&service);
        async move { service.register_wallet(registering_cfg).await }
    });
    acknowledge_next_wallet_removal(&mut backfill_rx).await;
    let displaced = registering
        .await
        .expect("wallet B registration task joins")
        .expect("register wallet B after terminal wallet A");
    assert!(
        service
            .wallet_handle(displaced_cfg.cache_key.as_str())
            .await
            .is_some_and(|handle| handle.same_actor_as(&displaced))
    );
    let unregistering = tokio::spawn({
        let service = Arc::clone(&service);
        let displaced = displaced.clone();
        async move { service.unregister_wallet(&displaced).await }
    });
    acknowledge_next_wallet_removal(&mut backfill_rx).await;
    unregistering.await.expect("wallet B unregister task joins");

    let (first, second) = tokio::join!(
        service.register_wallet(cfg.clone()),
        service.register_wallet(cfg.clone()),
    );
    let first = first.expect("register first replacement");
    let second = second.expect("register concurrent replacement");
    assert_ne!(first.actor_id(), terminal.actor_id());
    assert_eq!(first.actor_id(), second.actor_id());
    assert_eq!(
        service
            .wallet_actor_next
            .load(std::sync::atomic::Ordering::Acquire),
        4,
        "concurrent retry must create exactly one fresh actor"
    );

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let wallet = service.wallet.read().await;
            if wallet
                .as_ref()
                .is_some_and(|registration| registration.handle.same_actor_as(&first))
            {
                break;
            }
            drop(wallet);
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("stale terminal reaper preserved the replacement");
    assert!(
        service
            .wallet_handle(&cfg.cache_key)
            .await
            .is_some_and(|handle| handle.same_actor_as(&first))
    );

    let unregistering = tokio::spawn({
        let service = Arc::clone(&service);
        let first = first.clone();
        async move { service.unregister_wallet(&first).await }
    });
    acknowledge_next_wallet_removal(&mut backfill_rx).await;
    unregistering.await.expect("first actor cleanup joins");
    service.cancel.cancel();
    drop(terminal);
    drop(first);
    drop(second);
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn terminal_reaper_cleanup_failure_shuts_down_service_before_successor_install() {
    let root_dir = temp_db_root("terminal-reaper-cleanup-failure");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc_url = Url::parse("http://127.0.0.1:1").expect("rpc url");
    let service = test_chain_service(
        Arc::clone(&db),
        test_chain_config(
            &scope,
            Arc::new(QueryRpcPool::new(
                vec![rpc_url.clone()],
                Duration::from_secs(1),
            )),
            None,
        ),
        ChainPublicDataPlane::new(
            Arc::clone(&db),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ),
    );
    let mut terminal_cfg = test_wallet_config(&scope, rpc_url.clone());
    terminal_cfg.sync_to_block = Some(0);
    terminal_cfg.use_indexed_wallet_catch_up = false;
    let terminal = service
        .register_wallet(terminal_cfg.clone())
        .await
        .expect("register terminal wallet");
    let worker_cancel = service
        .wallet
        .read()
        .await
        .as_ref()
        .expect("terminal registration")
        .cancel
        .clone();
    worker_cancel.cancel();
    tokio::time::timeout(Duration::from_secs(1), async {
        while terminal.readiness() != WalletReadiness::Shutdown {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("terminal worker reaches shutdown");
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if service.wallet.read().await.is_none() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("terminal reaper takes the registration before successor retry");

    let mut successor_cfg = terminal_cfg;
    successor_cfg.cache_key = test_cache_key("reaper-failure-successor");
    let registering = tokio::spawn({
        let service = Arc::clone(&service);
        async move { service.register_wallet(successor_cfg).await }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while !service.cancel.is_cancelled() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("terminal reaper failure shuts down service");
    let result = tokio::time::timeout(Duration::from_secs(1), registering)
        .await
        .expect("successor registration resolves")
        .expect("successor registration task joins");
    assert!(matches!(result, Err(ChainError::Shutdown)));
    assert!(service.wallet.read().await.is_none());
    drop(terminal);
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn replace_wallet_waits_for_old_worker_and_fences_stale_removal() {
    let root_dir = temp_db_root("replace-wallet-ordering");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc_url = Url::parse("http://127.0.0.1:1").expect("rpc url");
    let (service, mut backfill_rx) = test_chain_service_with_backfill(
        Arc::clone(&db),
        test_chain_config(
            &scope,
            Arc::new(QueryRpcPool::new(
                vec![rpc_url.clone()],
                Duration::from_secs(1),
            )),
            None,
        ),
        ChainPublicDataPlane::new(
            Arc::clone(&db),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ),
        test_proxy_poi_policy(),
    );
    let mut old_cfg = test_wallet_config(&scope, rpc_url.clone());
    old_cfg.sync_to_block = Some(0);
    old_cfg.use_indexed_wallet_catch_up = false;
    let old_handle = service
        .register_wallet(old_cfg)
        .await
        .expect("register old wallet");
    old_handle.publish_readiness_for_test(&WalletReadiness::Ready);

    let (worker_finished_tx, worker_finished_rx) = oneshot::channel();
    let (release_worker_tx, release_worker_rx) = oneshot::channel();
    {
        let mut wallet = service.wallet.write().await;
        let registration = wallet.as_mut().expect("old registration");
        let old_worker = std::mem::replace(&mut registration.worker, tokio::spawn(async {}));
        registration.worker = tokio::spawn(async move {
            old_worker.await.expect("old worker completed");
            let _ = worker_finished_tx.send(());
            let _ = release_worker_rx.await;
        });
    }

    let mut successor_cfg = test_wallet_config(&scope, rpc_url);
    successor_cfg.cache_key = test_cache_key("replacement-successor");
    successor_cfg.sync_to_block = Some(0);
    successor_cfg.use_indexed_wallet_catch_up = false;
    let replacing = tokio::spawn({
        let service = Arc::clone(&service);
        async move { service.replace_wallet(successor_cfg).await }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while old_handle.readiness() != WalletReadiness::Shutdown {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("replacement retires old actor");
    tokio::time::timeout(Duration::from_secs(1), worker_finished_rx)
        .await
        .expect("old worker reaches controlled cleanup blocker")
        .expect("controlled cleanup notification is sent");
    let remove_response = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match backfill_rx
                .recv()
                .await
                .expect("backfill loop remains active")
            {
                BackfillRequest::Add {
                    driver, cache_key, ..
                } => {
                    driver.retire(&cache_key).await;
                }
                BackfillRequest::Remove { response, .. } => break response,
            }
        }
    })
    .await
    .expect("replacement sends backfill removal");
    for _ in 0..8 {
        assert!(service.wallet.read().await.is_none());
        assert!(!replacing.is_finished());
        tokio::task::yield_now().await;
    }

    release_worker_tx.send(()).expect("release old worker");
    remove_response
        .send(())
        .expect("acknowledge retired backfill cursor");
    let successor = tokio::time::timeout(Duration::from_secs(1), replacing)
        .await
        .expect("replacement completes after worker cleanup")
        .expect("replacement task joins")
        .expect("replacement succeeds");
    assert!(
        service
            .wallet_handle(successor.cache_key.as_str())
            .await
            .is_some_and(|handle| handle.same_actor_as(&successor))
    );

    service.unregister_wallet(&old_handle).await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert!(
        service
            .wallet_handle(successor.cache_key.as_str())
            .await
            .is_some_and(|handle| handle.same_actor_as(&successor))
    );
    let unregistering = tokio::spawn({
        let service = Arc::clone(&service);
        let successor = successor.clone();
        async move { service.unregister_wallet(&successor).await }
    });
    loop {
        match backfill_rx
            .recv()
            .await
            .expect("backfill loop remains active")
        {
            BackfillRequest::Add {
                driver, cache_key, ..
            } => {
                driver.retire(&cache_key).await;
            }
            BackfillRequest::Remove { response, .. } => {
                response.send(()).expect("acknowledge successor removal");
                break;
            }
        }
    }
    unregistering.await.expect("successor cleanup joins");
    service.cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn replace_wallet_owned_operation_survives_caller_abort() {
    let root_dir = temp_db_root("replace-wallet-backfill-ack");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc_url = Url::parse("http://127.0.0.1:1").expect("rpc url");
    let (service, mut backfill_rx) = test_chain_service_with_backfill(
        Arc::clone(&db),
        test_chain_config(
            &scope,
            Arc::new(QueryRpcPool::new(
                vec![rpc_url.clone()],
                Duration::from_secs(1),
            )),
            None,
        ),
        ChainPublicDataPlane::new(
            Arc::clone(&db),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ),
        test_proxy_poi_policy(),
    );
    let mut old_cfg = test_wallet_config(&scope, rpc_url.clone());
    old_cfg.sync_to_block = Some(0);
    old_cfg.use_indexed_wallet_catch_up = false;
    let old_handle = service
        .register_wallet(old_cfg)
        .await
        .expect("register old wallet");
    old_handle.publish_readiness_for_test(&WalletReadiness::Ready);

    let mut successor_cfg = test_wallet_config(&scope, rpc_url);
    successor_cfg.cache_key = test_cache_key("ack-successor");
    successor_cfg.sync_to_block = Some(0);
    successor_cfg.use_indexed_wallet_catch_up = false;
    let successor_cache_key = successor_cfg.cache_key.clone();
    let replacing = tokio::spawn({
        let service = Arc::clone(&service);
        async move { service.replace_wallet(successor_cfg).await }
    });

    let response = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match backfill_rx
                .recv()
                .await
                .expect("backfill loop remains active")
            {
                BackfillRequest::Add {
                    driver, cache_key, ..
                } => {
                    driver.retire(&cache_key).await;
                }
                BackfillRequest::Remove { response, .. } => break response,
            }
        }
    })
    .await
    .expect("replacement sends backfill removal");
    assert!(
        !replacing.is_finished(),
        "replacement must await removal ack"
    );
    assert!(service.wallet.read().await.is_none());
    replacing.abort();
    response
        .send(())
        .expect("send backfill removal acknowledgement");
    let successor = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let Some(handle) = service.wallet_handle(&successor_cache_key).await {
                break handle;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("owned replacement completes after caller abort");
    assert!(
        service
            .wallet_handle(successor.cache_key.as_str())
            .await
            .is_some_and(|handle| handle.same_actor_as(&successor))
    );
    service.unregister_wallet(&old_handle).await;
    let unregistering = tokio::spawn({
        let service = Arc::clone(&service);
        let successor = successor.clone();
        async move { service.unregister_wallet(&successor).await }
    });
    loop {
        match backfill_rx
            .recv()
            .await
            .expect("backfill loop remains active")
        {
            BackfillRequest::Add {
                driver, cache_key, ..
            } => {
                driver.retire(&cache_key).await;
            }
            BackfillRequest::Remove { response, .. } => {
                response.send(()).expect("acknowledge successor removal");
                break;
            }
        }
    }
    unregistering.await.expect("successor cleanup joins");
    service.cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn replace_wallet_leaves_slot_empty_when_old_worker_cleanup_panics() {
    let root_dir = temp_db_root("replace-wallet-worker-panic");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc_url = Url::parse("http://127.0.0.1:1").expect("rpc url");
    let (service, mut backfill_rx) = test_chain_service_with_backfill(
        Arc::clone(&db),
        test_chain_config(
            &scope,
            Arc::new(QueryRpcPool::new(
                vec![rpc_url.clone()],
                Duration::from_secs(1),
            )),
            None,
        ),
        ChainPublicDataPlane::new(
            Arc::clone(&db),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ),
        test_proxy_poi_policy(),
    );
    let mut old_cfg = test_wallet_config(&scope, rpc_url.clone());
    old_cfg.sync_to_block = Some(0);
    old_cfg.use_indexed_wallet_catch_up = false;
    let old_handle = service
        .register_wallet(old_cfg)
        .await
        .expect("register old wallet");
    old_handle.publish_readiness_for_test(&WalletReadiness::Ready);
    {
        let mut wallet = service.wallet.write().await;
        let registration = wallet.as_mut().expect("old registration");
        let original = std::mem::replace(&mut registration.worker, tokio::spawn(async {}));
        registration.worker = tokio::spawn(async move {
            let _ = original.await;
            panic!("intentional retirement worker panic");
        });
    }

    let mut successor_cfg = test_wallet_config(&scope, rpc_url);
    successor_cfg.cache_key = test_cache_key("panic-successor");
    successor_cfg.sync_to_block = Some(0);
    successor_cfg.use_indexed_wallet_catch_up = false;
    let replacing = tokio::spawn({
        let service = Arc::clone(&service);
        async move { service.replace_wallet(successor_cfg).await }
    });
    let response = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match backfill_rx
                .recv()
                .await
                .expect("backfill loop remains active")
            {
                BackfillRequest::Add {
                    driver, cache_key, ..
                } => {
                    driver.retire(&cache_key).await;
                }
                BackfillRequest::Remove { response, .. } => break response,
            }
        }
    })
    .await
    .expect("replacement sends backfill removal");
    response
        .send(())
        .expect("send backfill removal acknowledgement");
    let error = tokio::time::timeout(Duration::from_secs(1), replacing)
        .await
        .expect("replacement completes after cleanup failure")
        .expect("replacement task joins")
        .expect_err("worker panic must reject replacement");
    assert!(matches!(error, ChainError::WalletWorkerRetirementFailed));
    assert!(service.wallet.read().await.is_none());
    assert!(
        service
            .wallet_handle(old_handle.cache_key.as_str())
            .await
            .is_none()
    );
    service.cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn reset_wallets_serializes_replacement_until_actor_authority_is_released() {
    let root_dir = temp_db_root("reset-wallet-replacement-ordering");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc_url = Url::parse("http://127.0.0.1:1").expect("rpc url");
    let (service, mut backfill_rx) = test_chain_service_with_backfill(
        Arc::clone(&db),
        test_chain_config(
            &scope,
            Arc::new(QueryRpcPool::new(
                vec![rpc_url.clone()],
                Duration::from_secs(1),
            )),
            None,
        ),
        ChainPublicDataPlane::new(
            Arc::clone(&db),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ),
        test_proxy_poi_policy(),
    );
    let mut old_cfg = test_wallet_config(&scope, rpc_url.clone());
    old_cfg.sync_to_block = Some(0);
    old_cfg.use_indexed_wallet_catch_up = false;
    let old_handle = service
        .register_wallet(old_cfg)
        .await
        .expect("register old wallet");
    old_handle.publish_readiness_for_test(&WalletReadiness::Ready);
    let authority = old_handle.hold_actor_authority_for_test().await;
    let resetting = tokio::spawn({
        let service = Arc::clone(&service);
        async move { service.reset_wallets(0, 0).await }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if service.wallet_registration_gate.try_lock().is_err() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("reset owns registration gate");

    let mut successor_cfg = test_wallet_config(&scope, rpc_url);
    successor_cfg.cache_key = test_cache_key("reset-successor");
    successor_cfg.sync_to_block = Some(0);
    successor_cfg.use_indexed_wallet_catch_up = false;
    let replacing = tokio::spawn({
        let service = Arc::clone(&service);
        async move { service.replace_wallet(successor_cfg).await }
    });
    for _ in 0..8 {
        assert!(!resetting.is_finished());
        assert!(!replacing.is_finished());
        assert!(service.wallet.read().await.is_some());
        tokio::task::yield_now().await;
    }
    drop(authority);
    tokio::time::timeout(Duration::from_secs(1), resetting)
        .await
        .expect("reset completes after authority release")
        .expect("reset task joins");

    let response = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match backfill_rx
                .recv()
                .await
                .expect("backfill loop remains active")
            {
                BackfillRequest::Add {
                    driver, cache_key, ..
                } => {
                    driver.retire(&cache_key).await;
                }
                BackfillRequest::Remove { response, .. } => break response,
            }
        }
    })
    .await
    .expect("replacement sends backfill removal");
    response
        .send(())
        .expect("send backfill removal acknowledgement");
    let successor = tokio::time::timeout(Duration::from_secs(1), replacing)
        .await
        .expect("replacement completes after reset")
        .expect("replacement task joins")
        .expect("replacement succeeds");
    assert!(
        service
            .wallet_handle(successor.cache_key.as_str())
            .await
            .is_some_and(|handle| handle.same_actor_as(&successor))
    );
    let unregistering = tokio::spawn({
        let service = Arc::clone(&service);
        let successor = successor.clone();
        async move { service.unregister_wallet(&successor).await }
    });
    loop {
        match backfill_rx
            .recv()
            .await
            .expect("backfill loop remains active")
        {
            BackfillRequest::Add {
                driver, cache_key, ..
            } => {
                driver.retire(&cache_key).await;
            }
            BackfillRequest::Remove { response, .. } => {
                response.send(()).expect("acknowledge successor removal");
                break;
            }
        }
    }
    unregistering.await.expect("successor cleanup joins");
    service.cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_lag_fallback_resets_timing_for_same_key_reincarnation() {
    let root_dir = temp_db_root("wallet-lag-reincarnation");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc_url = Url::parse("http://127.0.0.1:1").expect("rpc url");
    let (service, mut backfill_rx) = test_chain_service_with_backfill(
        Arc::clone(&db),
        test_chain_config(
            &scope,
            Arc::new(QueryRpcPool::new(
                vec![rpc_url.clone()],
                Duration::from_secs(1),
            )),
            None,
        ),
        ChainPublicDataPlane::new(
            Arc::clone(&db),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ),
        test_proxy_poi_policy(),
    );
    let mut cfg = test_wallet_config(&scope, rpc_url);
    cfg.use_indexed_wallet_catch_up = true;
    cfg.sync_to_block = Some(1_000);
    let first = service
        .register_wallet(cfg.clone())
        .await
        .expect("register first actor");
    first.publish_readiness_for_test(&WalletReadiness::Ready);
    let mut state = None;
    let now = std::time::Instant::now();
    let first_state = wallet_lag_fallback_state_for_test(&service, &mut state, 1_000, now)
        .await
        .expect("first lag state");
    assert_eq!(first_state.0, first.actor_id());
    assert!(!first_state.1);
    let first_attempt = wallet_lag_fallback_state_for_test(
        &service,
        &mut state,
        1_000,
        now + Duration::from_secs(20),
    )
    .await
    .expect("first lag attempt state");
    assert_eq!(first_attempt.0, first.actor_id());
    assert!(first_attempt.1);

    let unregistering = tokio::spawn({
        let service = Arc::clone(&service);
        let first = first.clone();
        async move { service.unregister_wallet(&first).await }
    });
    acknowledge_next_wallet_removal(&mut backfill_rx).await;
    unregistering.await.expect("first actor cleanup joins");
    let second = service
        .register_wallet(cfg)
        .await
        .expect("register reincarnated actor");
    second.publish_readiness_for_test(&WalletReadiness::Ready);
    let second_state = wallet_lag_fallback_state_for_test(
        &service,
        &mut state,
        1_000,
        now + Duration::from_secs(21),
    )
    .await
    .expect("reincarnated lag state");
    assert_eq!(second_state.0, second.actor_id());
    assert!(!second_state.1);
    let unregistering = tokio::spawn({
        let service = Arc::clone(&service);
        let second = second.clone();
        async move { service.unregister_wallet(&second).await }
    });
    acknowledge_next_wallet_removal(&mut backfill_rx).await;
    unregistering.await.expect("second actor cleanup joins");
    service.cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn manager_resets_persisted_cache_once_and_every_registered_public_data_plane() {
    let root_dir = temp_db_root("manager-public-cache-reset");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open manager reset db"),
    );
    let rpc_url = Url::parse("http://127.0.0.1:1").expect("rpc url");
    let txid_kind = crate::txid_cache::TXID_CACHE_BLOB_KIND;
    let txid_name = "manager-reset-page.bin";
    let txid_id = "manager-reset-page";
    db.ensure_blob_dir(txid_kind).expect("ensure TXID blob dir");
    fs::write(db.blob_path(txid_kind, txid_name), b"TXID cache").expect("write TXID cache file");
    db.put_blob_meta(
        txid_kind,
        txid_id,
        &BlobMeta {
            format_version: 1,
            relative_path: DbStore::relative_blob_path(txid_kind, txid_name),
            content_hash: Sha256::digest(b"TXID cache").into(),
            source_hash: None,
            source_sequence: None,
            created_at: 1,
            updated_at: 1,
            last_accessed_at: 1,
            last_block: None,
        },
    )
    .expect("write TXID cache metadata");
    assert_eq!(
        db.poi_artifact_cache_generation()
            .expect("initial POI cache generation"),
        0
    );
    let scopes = [
        ChainScope {
            chain_type: ChainType::Evm,
            chain_id: 1,
            railgun_contract: Address::from([0x11; 20]),
        },
        ChainScope {
            chain_type: ChainType::Evm,
            chain_id: 2,
            railgun_contract: Address::from([0x22; 20]),
        },
    ];
    let mut registered = Vec::new();
    let manager = SyncManager::new(Arc::clone(&db), test_proxy_poi_policy())
        .expect("acquire manager ownership");
    for scope in scopes {
        let chain = test_chain_config(
            &scope,
            Arc::new(QueryRpcPool::new(
                vec![rpc_url.clone()],
                Duration::from_secs(1),
            )),
            None,
        );
        let key = ChainKey {
            chain_id: chain.deployment.chain_id,
            contract: chain.deployment.contract,
        };
        let public_data_plane = ChainPublicDataPlane::new(
            Arc::clone(&db),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        );
        let service = test_chain_service(Arc::clone(&db), chain, public_data_plane);
        assert!(service.wallet.read().await.is_none());
        manager.insert_chain_for_test(key, Arc::clone(&service));
        registered.push((key, service));
    }

    let report = manager
        .reset_public_sync_caches()
        .await
        .expect("manager accepts public cache reset");

    assert_eq!(report.chains.len(), 2);
    assert_eq!(
        report
            .chains
            .iter()
            .map(|reset| reset.chain.chain_id)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(report.failed_chain_count(), 0);
    let persisted = report
        .persisted
        .as_ref()
        .expect("persisted manager reset succeeds");
    assert_eq!(persisted.txid_blob_entries_removed, 1);
    assert_eq!(persisted.total_removed_entries(), 1);
    assert_eq!(report.total_removed_entries, 1);
    assert_eq!(
        db.poi_artifact_cache_generation()
            .expect("POI cache generation after manager reset"),
        0,
        "raw public cache reset preserves the serving-corpus generation"
    );
    for (key, service) in &registered {
        let reset = report
            .chains
            .iter()
            .find(|reset| reset.chain == *key)
            .expect("registered chain reset result")
            .result
            .as_ref()
            .expect("registered chain reset succeeds");
        assert_eq!(reset.previous_epoch, PublicDataPlaneEpoch::new(0));
        assert_eq!(reset.new_epoch, PublicDataPlaneEpoch::new(1));
        assert_eq!(
            service.public_data_plane().diagnostics().await.epoch,
            PublicDataPlaneEpoch::new(1),
        );
        assert!(service.wallet.read().await.is_none());
    }

    manager.shutdown().await;
    drop(registered);
    drop(manager);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove manager reset db");
}

#[tokio::test]
async fn manager_public_cache_reset_reports_empty_inventory() {
    let root_dir = temp_db_root("manager-empty-public-cache-reset");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open empty manager reset db"),
    );
    let manager = SyncManager::new(Arc::clone(&db), test_proxy_poi_policy())
        .expect("acquire manager ownership");

    let report = manager
        .reset_public_sync_caches()
        .await
        .expect("manager accepts public cache reset");

    assert!(report.is_empty());
    assert_eq!(report.total_removed_entries, 0);
    assert_eq!(report.failed_chain_count(), 0);
    manager.shutdown().await;
    drop(manager);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove empty manager reset db");
}

#[tokio::test]
async fn session_removal_routes_by_handle_and_rejects_cross_service_actor_collision() {
    let root_a = temp_db_root("session-removal-chain-a");
    let root_b = temp_db_root("session-removal-chain-b");
    let root_reincarnated = temp_db_root("session-removal-chain-a-reincarnated");
    let db_a = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_a.clone(),
        })
        .expect("open chain A db"),
    );
    let db_b = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_b.clone(),
        })
        .expect("open chain B db"),
    );
    let db_reincarnated = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_reincarnated.clone(),
        })
        .expect("open reincarnated chain A db"),
    );
    let scope_a = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xaa; 20]),
    };
    let scope_b = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xbb; 20]),
    };
    let rpc_url = Url::parse("http://127.0.0.1:1").expect("rpc url");
    let chain_a = test_chain_config(
        &scope_a,
        Arc::new(QueryRpcPool::new(
            vec![rpc_url.clone()],
            Duration::from_secs(1),
        )),
        None,
    );
    let chain_b = test_chain_config(
        &scope_b,
        Arc::new(QueryRpcPool::new(
            vec![rpc_url.clone()],
            Duration::from_secs(1),
        )),
        None,
    );
    let chain_a_key = ChainKey {
        chain_id: chain_a.deployment.chain_id,
        contract: chain_a.deployment.contract,
    };
    let chain_b_key = ChainKey {
        chain_id: chain_b.deployment.chain_id,
        contract: chain_b.deployment.contract,
    };
    let service_a = test_chain_service(
        Arc::clone(&db_a),
        chain_a,
        ChainPublicDataPlane::new(
            Arc::clone(&db_a),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ),
    );
    let service_b = test_chain_service(
        Arc::clone(&db_b),
        chain_b,
        ChainPublicDataPlane::new(
            Arc::clone(&db_b),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ),
    );
    let manager = SyncManager::new(Arc::clone(&db_a), test_proxy_poi_policy())
        .expect("acquire manager ownership");
    manager.insert_chain_for_test(chain_a_key, Arc::clone(&service_a));
    manager.insert_chain_for_test(chain_b_key, Arc::clone(&service_b));

    let shared_cache_key = test_cache_key("shared-session");
    let mut cfg_a = test_wallet_config(&scope_a, rpc_url.clone());
    cfg_a.cache_key = shared_cache_key.clone();
    cfg_a.sync_to_block = Some(0);
    cfg_a.use_indexed_wallet_catch_up = false;
    let mut cfg_b = test_wallet_config(&scope_b, rpc_url.clone());
    cfg_b.cache_key = shared_cache_key.clone();
    cfg_b.sync_to_block = Some(0);
    cfg_b.use_indexed_wallet_catch_up = false;

    let handle_a = manager
        .add_wallet(cfg_a.clone())
        .await
        .expect("register chain A");
    let handle_b = manager.add_wallet(cfg_b).await.expect("register chain B");
    assert_eq!(handle_a.actor_id(), 1);
    assert_eq!(handle_b.actor_id(), 1);

    service_b.unregister_wallet(&handle_a).await;
    assert!(service_a.wallet_handle(&shared_cache_key).await.is_some());
    assert!(service_b.wallet_handle(&shared_cache_key).await.is_some());

    manager
        .remove_wallet_session(&handle_a)
        .await
        .expect("remove chain A session by handle");
    assert!(service_a.wallet_handle(&shared_cache_key).await.is_none());
    assert_eq!(
        service_b
            .wallet_handle(&shared_cache_key)
            .await
            .expect("chain B actor remains registered")
            .actor_id(),
        handle_b.actor_id(),
    );

    let replacement_a = manager
        .add_wallet(cfg_a)
        .await
        .expect("register replacement chain A actor");
    assert_ne!(replacement_a.actor_id(), handle_a.actor_id());
    service_a.unregister_wallet(&handle_a).await;
    manager
        .remove_wallet_session(&handle_a)
        .await
        .expect("stale manager removal is a no-op");
    assert_eq!(
        service_a
            .wallet_handle(&shared_cache_key)
            .await
            .expect("replacement chain A actor remains registered")
            .actor_id(),
        replacement_a.actor_id(),
    );

    let reincarnated_chain_a = test_chain_config(
        &scope_a,
        Arc::new(QueryRpcPool::new(
            vec![rpc_url.clone()],
            Duration::from_secs(1),
        )),
        None,
    );
    let reincarnated_service_a = test_chain_service(
        Arc::clone(&db_reincarnated),
        reincarnated_chain_a,
        ChainPublicDataPlane::new(
            Arc::clone(&db_reincarnated),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ),
    );
    let mut reincarnated_cfg_a = test_wallet_config(&scope_a, rpc_url);
    reincarnated_cfg_a.cache_key = shared_cache_key.clone();
    reincarnated_cfg_a.sync_to_block = Some(0);
    reincarnated_cfg_a.use_indexed_wallet_catch_up = false;
    let reincarnated_handle_a = reincarnated_service_a
        .register_wallet(reincarnated_cfg_a)
        .await
        .expect("register reincarnated chain A actor");
    assert_eq!(reincarnated_handle_a.actor_id(), handle_a.actor_id());
    assert_eq!(reincarnated_handle_a.chain_key(), handle_a.chain_key());

    reincarnated_service_a.unregister_wallet(&handle_a).await;
    assert!(
        reincarnated_service_a
            .wallet_handle(&shared_cache_key)
            .await
            .is_some(),
        "a stale handle must not retire an actor from a reincarnated service",
    );
    let current_handle_clone = reincarnated_handle_a.clone();
    reincarnated_service_a
        .unregister_wallet(&current_handle_clone)
        .await;
    assert!(
        reincarnated_service_a
            .wallet_handle(&shared_cache_key)
            .await
            .is_none(),
        "a clone of the current handle must unregister its actor",
    );
    reincarnated_service_a.shutdown().await;

    manager.remove_all_wallets().await;
    manager.shutdown().await;
    drop(handle_a);
    drop(handle_b);
    drop(replacement_a);
    drop(reincarnated_handle_a);
    drop(current_handle_clone);
    drop(service_a);
    drop(service_b);
    drop(reincarnated_service_a);
    drop(manager);
    drop(db_a);
    drop(db_b);
    drop(db_reincarnated);
    fs::remove_dir_all(root_a).expect("remove chain A temp db dir");
    fs::remove_dir_all(root_b).expect("remove chain B temp db dir");
    fs::remove_dir_all(root_reincarnated).expect("remove reincarnated chain A temp db dir");
}

#[tokio::test]
async fn shutdown_terminalizes_readiness_and_awaits_owned_worker_panic() {
    let root_dir = temp_db_root("wallet-shutdown-owned-worker");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc_url = Url::parse("http://127.0.0.1:1").expect("rpc url");
    let (service, mut backfill_rx) = test_chain_service_with_backfill(
        Arc::clone(&db),
        test_chain_config(
            &scope,
            Arc::new(QueryRpcPool::new(
                vec![rpc_url.clone()],
                Duration::from_secs(1),
            )),
            None,
        ),
        ChainPublicDataPlane::new(
            Arc::clone(&db),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ),
        test_proxy_poi_policy(),
    );
    let mut cfg = test_wallet_config(&scope, rpc_url);
    cfg.sync_to_block = Some(0);
    cfg.use_indexed_wallet_catch_up = false;
    let handle = service.register_wallet(cfg).await.expect("register wallet");
    handle.publish_readiness_for_test(&WalletReadiness::Ready);
    assert_eq!(handle.readiness(), WalletReadiness::Ready);
    let mut retained_observation = handle.subscribe_observation();
    let held_authority = handle.hold_actor_authority_for_test().await;

    let (owned_worker_completed_tx, owned_worker_completed_rx) = oneshot::channel();
    let (release_owned_worker_tx, release_owned_worker_rx) = oneshot::channel();
    {
        let mut wallet = service.wallet.write().await;
        let registration = wallet.as_mut().expect("wallet registration");
        let owned_worker = std::mem::replace(&mut registration.worker, tokio::spawn(async {}));
        registration.worker = tokio::spawn(async move {
            owned_worker.await.expect("owned wallet worker completed");
            let _ = owned_worker_completed_tx.send(());
            let _ = release_owned_worker_rx.await;
            panic!("controlled wallet worker panic");
        });
    }

    let shutdown_service = Arc::clone(&service);
    let shutdown = tokio::spawn(async move {
        shutdown_service.shutdown().await;
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while retained_observation.borrow().readiness() != &WalletReadiness::Shutdown {
            retained_observation
                .changed()
                .await
                .expect("retirement keeps readiness sender alive");
        }
    })
    .await
    .expect("shutdown terminalized retained readiness");
    assert!(matches!(
        retained_observation.borrow().view(),
        WalletViewState::Inactive {
            reason: WalletInactiveReason::Shutdown,
            ..
        }
    ));
    tokio::time::timeout(Duration::from_secs(1), owned_worker_completed_rx)
        .await
        .expect("shutdown cancelled and awaited the wallet worker despite authority contention")
        .expect("owned worker reached retirement barrier");
    acknowledge_next_wallet_removal(&mut backfill_rx).await;
    assert!(
        !shutdown.is_finished(),
        "shutdown must await its owned worker"
    );

    release_owned_worker_tx
        .send(())
        .expect("release owned worker panic");
    tokio::time::timeout(Duration::from_secs(1), shutdown)
        .await
        .expect("shutdown completed after owned worker exit")
        .expect("shutdown task completed");
    assert_eq!(handle.readiness(), WalletReadiness::Shutdown);
    drop(held_authority);

    drop(handle);
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

async fn acknowledge_next_wallet_removal(rx: &mut mpsc::Receiver<BackfillRequest>) {
    loop {
        match rx.recv().await.expect("backfill receiver remains active") {
            BackfillRequest::Add {
                driver, cache_key, ..
            } => {
                driver.retire(&cache_key).await;
            }
            BackfillRequest::Remove { response, .. } => {
                response.send(()).expect("acknowledge wallet removal");
                return;
            }
        }
    }
}
