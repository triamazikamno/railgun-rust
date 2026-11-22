use super::*;

#[tokio::test]
async fn indexed_wallet_catch_up_hands_artifact_exhaustion_to_squid_tail() {
    let root_dir = temp_db_root("indexed-wallet-artifact-exhaustion-tail");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xbb; 20]),
    };
    let (artifact_source, manifest_block) =
        checkpointed_wallet_artifact_source_with_blocked_manifest(&scope, 100, 200, 150);
    // The startup race's Squid candidate holds its first page and stalls on
    // its second while the artifact session wins; the tail probe follows.
    let (squid, race_page_block) = GraphqlServer::spawn_owned_with_blocked_response(
        vec![
            squid_wallet_probe(200),
            squid_wallet_page_with_nullifier(120),
            squid_wallet_page_with_nullifier(170),
            squid_wallet_probe(200),
            r#"{"data":{"transactCommitments":[],"shieldCommitments":[],"nullifiers":[]}}"#
                .to_owned(),
        ],
        2,
    );
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
        Duration::from_secs(1),
    ));
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
            // Shorter than the 50-block tail after the artifact checkpoint,
            // so Squid is probed for it.
            block_range: 25,
            indexed_wallet_block_range: 50,
            poll_interval: Duration::from_millis(1),
            quick_sync_endpoint: Some(squid.url.clone()),
            indexed_artifact_source: Some(artifact_source.config),
            anchor_interval: 1000,
            anchor_retention: 5,
        },
        rpcs: Arc::clone(&rpcs),
        archive_rpc_url: None,
        archive_rpc_http_client: None,
        block_time: Duration::from_secs(12),
        finality_depth: 0,
        http_client: reqwest::Client::new(),
        progress_tx: None,
        poi_submission_routes: None,
    };
    let (head_tx, _head_rx) = watch::channel(0);
    let (safe_head_tx, _safe_head_rx) = watch::channel(200);
    let (forest_last_tx, _forest_last_rx) = watch::channel(0);
    let (live_log_tx, live_log_rx) = broadcast::channel(8);
    let (service_backfill_tx, _service_backfill_rx) = mpsc::channel(1);
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = Arc::new(ChainService {
        chain: chain.clone(),
        poi_policy: test_proxy_poi_policy(),
        db: Arc::clone(&db),
        forest: Arc::new(RwLock::new(MerkleForest::new())),
        head_tx,
        safe_head_tx,
        forest_last_tx,
        live_log_tx,
        backfill_tx: service_backfill_tx,
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
        public_data_plane: public_data_plane.clone(),
    });
    let (wallet_backfill_tx, wallet_backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(1);
    let worker_cancel = CancellationToken::new();
    let wallet_cfg = test_wallet_config(&scope, squid.url.clone());
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),
            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: wallet_backfill_tx.clone(),
            public_data_plane,
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_cfg.clone(),
        1,
        live_log_rx,
        wallet_backfill_rx,
        worker_cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");

    let catch_up = service.indexed_wallet_catch_up(
        WalletSyncContext {
            cfg: &wallet_cfg,
            start_block: 0,
            handle: &handle,
            backfill_sender: &wallet_backfill_tx,
        },
        100,
        200,
        &worker_cancel,
        IndexedWalletCatchUpSourceOrder::ArtifactsFirst,
        true,
        crate::types::WalletSchedulableProgress {
            last_scanned: 100,
            reset_generation: 0,
        },
    );
    let release_race_page = async {
        wait_for_std_signal(
            race_page_block.request_started,
            "race Squid page request started",
        )
        .await;
        manifest_block
            .release
            .send(())
            .expect("release artifact manifest");
        yield_until("artifact pages committed", || {
            handle.last_scanned() == Some(150)
        })
        .await;
        race_page_block
            .release
            .send(())
            .expect("release race Squid page");
    };
    let (checkpoint, ()) = tokio::join!(catch_up, release_race_page);

    assert_eq!(checkpoint, 200);
    assert_eq!(handle.last_scanned(), Some(200));
    assert_eq!(
        handle
            .indexed_catch_up_rx
            .borrow()
            .as_ref()
            .map(|status| status.source),
        Some(WalletIndexedCatchUpSource::Squid)
    );
    assert!(
        matches!(
            service
                .public_data_plane
                .cached_public_scan_coverage(PublicScanRange::new(101, 150))
                .await,
            PublicCoverageAnswer::ReplayableEmpty {
                source: PublicScanSource::IndexedArtifacts,
                ..
            }
        ),
        "the held Squid row at block 120 is discarded"
    );
    let requests = squid.requests.try_iter().collect::<Vec<_>>();
    assert_eq!(requests.len(), 5);
    assert!(requests[0].contains("query WalletProbe"));
    assert!(requests[1].contains(r#""fromBlock":"101""#));
    assert!(requests[2].contains(r#""fromBlock":"151""#));
    let probe_request = &requests[3];
    assert!(probe_request.contains("query WalletProbe"));
    let page_request = &requests[4];
    assert!(page_request.contains("query IndexedWalletPage"));
    assert!(page_request.contains(r#""fromBlock":"151""#));
    assert!(page_request.contains(r#""toBlock":"200""#));

    worker_cancel.cancel();
    drop(db);
    drop(artifact_source.server);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn indexed_wallet_artifact_prepare_scope_rejects_epoch_invalidated_before_apply() {
    let root_dir = temp_db_root("indexed-wallet-artifact-stale-prepare-scope");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xbb; 20]),
    };
    let (artifact_source, block) =
        checkpointed_wallet_artifact_source_with_blocked_manifest(&scope, 100, 150, 150);
    let PathServerBlockControl {
        request_started,
        release,
    } = block;
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
        Duration::from_secs(1),
    ));
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
            quick_sync_endpoint: Some(Url::parse("http://127.0.0.1:1").expect("squid url")),
            indexed_artifact_source: Some(artifact_source.config),
            anchor_interval: 1000,
            anchor_retention: 5,
        },
        rpcs: Arc::clone(&rpcs),
        archive_rpc_url: None,
        archive_rpc_http_client: None,
        block_time: Duration::from_secs(12),
        finality_depth: 0,
        http_client: reqwest::Client::new(),
        progress_tx: None,
        poi_submission_routes: None,
    };
    let (head_tx, _head_rx) = watch::channel(0);
    let (safe_head_tx, _safe_head_rx) = watch::channel(150);
    let (forest_last_tx, _forest_last_rx) = watch::channel(0);
    let (live_log_tx, live_log_rx) = broadcast::channel(8);
    let (service_backfill_tx, _service_backfill_rx) = mpsc::channel(1);
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = Arc::new(ChainService {
        chain: chain.clone(),
        poi_policy: test_proxy_poi_policy(),
        db: Arc::clone(&db),
        forest: Arc::new(RwLock::new(MerkleForest::new())),
        head_tx,
        safe_head_tx,
        forest_last_tx,
        live_log_tx,
        backfill_tx: service_backfill_tx,
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
        public_data_plane: public_data_plane.clone(),
    });
    let (wallet_backfill_tx, wallet_backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(1);
    let worker_cancel = CancellationToken::new();
    let (progress_tx, progress_rx) = watch::channel(None);
    let mut wallet_cfg = test_wallet_config(
        &scope,
        Url::parse("http://127.0.0.1:1").expect("quick-sync url"),
    );
    wallet_cfg.progress_tx = Some(progress_tx);
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),
            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: wallet_backfill_tx.clone(),
            public_data_plane: public_data_plane.clone(),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_cfg.clone(),
        1,
        live_log_rx,
        wallet_backfill_rx,
        worker_cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");
    let catch_up_service = Arc::clone(&service);
    let catch_up_cfg = wallet_cfg.clone();
    let catch_up_handle = handle.clone();
    let catch_up_cancel = worker_cancel.clone();
    let catch_up_sender = wallet_backfill_tx.clone();
    let catch_up = tokio::spawn(async move {
        catch_up_service
            .indexed_wallet_catch_up(
                WalletSyncContext {
                    cfg: &catch_up_cfg,
                    start_block: 0,
                    handle: &catch_up_handle,
                    backfill_sender: &catch_up_sender,
                },
                100,
                150,
                &catch_up_cancel,
                IndexedWalletCatchUpSourceOrder::ArtifactsFirst,
                true,
                crate::types::WalletSchedulableProgress {
                    last_scanned: 100,
                    reset_generation: 0,
                },
            )
            .await
    });
    tokio::time::timeout(
        Duration::from_secs(2),
        tokio::task::spawn_blocking(move || {
            request_started
                .recv()
                .expect("artifact manifest fetch started");
        }),
    )
    .await
    .expect("artifact manifest fetch started")
    .expect("manifest wait task completed");
    let preparation = progress_rx
        .borrow()
        .expect("wallet artifact preparation progress");
    assert_eq!(preparation.stage, SyncProgressStage::PreparingUtxoIndex);
    assert_eq!(preparation.unit, SyncProgressUnit::ArtifactPreparation);
    assert_eq!(preparation.source, Some(PublicScanSource::IndexedArtifacts));
    assert_eq!(preparation.percent(), 5);

    public_data_plane
        .invalidate_public_scan_coverage_from(101)
        .await;
    release.send(()).expect("release artifact manifest fetch");
    let checkpoint = catch_up.await.expect("indexed catch-up task");
    let retained_progress = progress_rx
        .borrow()
        .expect("pre-invalidation artifact progress");
    assert_eq!(retained_progress, preparation);

    assert_eq!(checkpoint, 100);
    assert_eq!(handle.last_scanned(), Some(100));
    assert!(matches!(
        public_data_plane
            .cached_public_scan_coverage(PublicScanRange::new(101, 150))
            .await,
        PublicCoverageAnswer::Missing { .. }
    ));
    let diagnostics = public_data_plane.diagnostics().await;
    assert!(diagnostics.events.iter().any(|event| {
        event.kind == PublicDataPlaneDiagnosticKind::CoverageRejected
            && event.source == Some(PublicScanSource::IndexedArtifacts)
            && event.range == Some(PublicScanRange::new(101, 150))
    }));

    worker_cancel.cancel();
    drop(db);
    drop(artifact_source.server);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_retirement_interrupts_active_rpc_backfill_and_reuses_coordinator() {
    let root_dir = temp_db_root("wallet-retirement-active-rpc");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let (rpc, blocked) = JsonRpcServer::spawn_with_blocked_response(vec![serde_json::json!([])], 0);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, Arc::clone(&rpcs), None);
    chain.sync.block_range = 10;
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
    let registered =
        install_test_backfill_actor(&service, &scope, rpc.url.clone(), "retired").await;
    let actor_cancel = service
        .wallet
        .read()
        .await
        .as_ref()
        .expect("registered wallet")
        .cancel
        .clone();
    let (_safe_head_tx, safe_head_rx) = watch::channel(110);
    let loop_cancel = CancellationToken::new();
    spawn_backfill_loop(
        Arc::clone(&service),
        backfill_rx,
        Arc::clone(&rpcs),
        None,
        safe_head_rx,
        loop_cancel.clone(),
    );

    let (wallet_tx, mut wallet_rx) = mpsc::channel(1);
    let (liveness, mut retirement) = oneshot::channel();
    let driver = WalletBackfillGrant::for_actor_accepted_job_with_cancel(
        WalletSyncToken::for_test(1, registered.actor_id(), 0, SYNTHETIC_BACKFILL_JOB_ID),
        wallet_tx,
        liveness,
        actor_cancel,
    )
    .activate();
    service
        .backfill_tx
        .send(BackfillRequest::add(
            registered.cache_key.as_str(),
            100,
            110,
            false,
            100,
            driver,
        ))
        .await
        .expect("queue active backfill");
    wait_for_std_signal(blocked.request_started, "active RPC request started").await;

    let unregistering = tokio::spawn({
        let service = Arc::clone(&service);
        let registered = registered.clone();
        async move { service.unregister_wallet(&registered).await }
    });
    let signal = tokio::time::timeout(Duration::from_secs(1), &mut retirement)
        .await
        .expect("active driver retirement signalled")
        .expect("active driver retirement signal received");
    assert_eq!(
        signal.disposition,
        WalletBackfillOwnerDisposition::BenignRetirement
    );
    signal
        .acknowledgement
        .expect("active retirement acknowledgement")
        .send(())
        .expect("acknowledge active driver retirement");
    tokio::time::timeout(Duration::from_secs(1), unregistering)
        .await
        .expect("wallet retirement completes while RPC is blocked")
        .expect("wallet retirement task joins");

    blocked
        .release
        .send(())
        .expect("release retired RPC request");
    assert!(
        wallet_rx.try_recv().is_err(),
        "retired RPC must not reach actor"
    );

    let mut successor_cfg = test_wallet_config(&scope, rpc.url);
    successor_cfg.cache_key = test_cache_key("retirement-successor");
    successor_cfg.sync_to_block = Some(0);
    successor_cfg.use_indexed_wallet_catch_up = false;
    let successor = service
        .register_wallet(successor_cfg)
        .await
        .expect("successor admission after active RPC retirement");
    assert_ne!(successor.actor_id(), registered.actor_id());
    service.unregister_wallet(&successor).await;
    loop_cancel.cancel();
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn indexed_catch_up_cancellation_is_typed_after_driver_acceptance() {
    let scope = test_scope();
    let probe = r#"{"data":{"squidStatus":{"height":"110"},"transactCommitments":[],"shieldCommitments":[],"nullifiers":[],"legacyEncryptedCommitments":[],"legacyGeneratedCommitments":[]}}"#;
    let (squid, blocked) = GraphqlServer::spawn_owned_with_blocked_response(
        vec![
            probe.to_string(),
            indexed_wallet_nullifier_page(101, U256::ZERO),
        ],
        1,
    );
    let context = IndexedCatchUpTestContext::new(&scope, squid.url.clone(), None, 100, 100).await;
    let service = Arc::clone(&context.service);
    let cfg = context.wallet_cfg.clone();
    let handle = context.handle.clone();
    let cancel = context.cancel.clone();
    let sender = context.wallet_backfill_tx.clone();
    let catch_up = tokio::spawn(async move {
        service
            .indexed_wallet_catch_up_outcome(
                WalletSyncContext {
                    cfg: &cfg,
                    start_block: 0,
                    handle: &handle,
                    backfill_sender: &sender,
                },
                100,
                110,
                &cancel,
                IndexedWalletCatchUpSourceOrder::SquidFirst,
                true,
                crate::types::WalletSchedulableProgress {
                    last_scanned: 100,
                    reset_generation: 0,
                },
            )
            .await
    });
    wait_for_std_signal(blocked.request_started, "indexed page request started").await;
    context.cancel.cancel();
    let outcome = tokio::time::timeout(Duration::from_secs(1), catch_up)
        .await
        .expect("indexed cancellation returns while page is blocked")
        .expect("indexed catch-up task joins");
    assert_eq!(outcome, IndexedWalletCatchUpOutcome::Cancelled(100));
    assert!(
        context
            .handle
            .last_scanned()
            .is_none_or(|last_scanned| last_scanned <= 100)
    );
    tokio::time::timeout(Duration::from_secs(1), async {
        while context.handle.indexed_catch_up_rx.borrow().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancelled indexed status clears");
    blocked
        .release
        .send(())
        .expect("release cancelled indexed page");
    context.cleanup();
}

#[tokio::test]
async fn wallet_snapshot_does_not_fetch_optional_prior_endpoint() {
    let BlockedWalletOptionalMaintenanceFixture {
        root_dir,
        db,
        public_data_plane,
        chain,
        artifact_source,
        optional_block,
        optional_descriptor: _,
    } = blocked_wallet_optional_maintenance_fixture("wallet-optional-nonblocking");
    let PathServerBlockControl {
        request_started,
        release: _,
    } = optional_block;
    let read_scope = public_data_plane.begin_public_scan_read();

    let session = tokio::time::timeout(
        Duration::from_secs(2),
        IndexedWalletArtifactSession::prepare(
            &chain,
            110,
            120,
            read_scope,
            &public_data_plane,
            None,
        ),
    )
    .await
    .expect("required wallet artifact preparation was not blocked by optional retention")
    .expect("prepare wallet artifacts")
    .expect("wallet artifact session");
    let page = match session
        .page_for_block_range(110, 120)
        .expect("required wallet rows are available")
    {
        IndexedWalletArtifactPageOutcome::Page(page) => page,
        IndexedWalletArtifactPageOutcome::Exhausted { .. } => {
            panic!("required wallet artifact page")
        }
    };
    assert_eq!(page.checkpoint_block, 120);

    assert!(
        request_started
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "current snapshot reads must not fetch optional prior-tail chunks"
    );

    public_data_plane.shutdown().await;
    drop(public_data_plane);
    drop(chain);
    drop(artifact_source.server);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn superseded_wallet_descriptor_stays_uncached_after_invalidation() {
    let BlockedWalletOptionalMaintenanceFixture {
        root_dir,
        db,
        public_data_plane,
        chain,
        artifact_source,
        optional_block,
        optional_descriptor,
    } = blocked_wallet_optional_maintenance_fixture("wallet-optional-stale");
    let PathServerBlockControl {
        request_started,
        release: _,
    } = optional_block;
    let read_scope = public_data_plane.begin_public_scan_read();
    IndexedWalletArtifactSession::prepare(&chain, 110, 120, read_scope, &public_data_plane, None)
        .await
        .expect("prepare wallet artifacts")
        .expect("wallet artifact session");
    assert!(
        request_started
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "superseded optional descriptor must not be fetched"
    );

    public_data_plane
        .invalidate_public_scan_coverage_from(110)
        .await;

    assert!(
        public_data_plane
            .cached_wallet_scan_artifact_chunk(&optional_descriptor)
            .is_none(),
        "superseded descriptors must remain uncached"
    );

    public_data_plane.shutdown().await;
    drop(public_data_plane);
    drop(chain);
    drop(artifact_source.server);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_artifact_prepare_reuses_retained_chunks() {
    let root_dir = temp_db_root("wallet-artifact-warm-cache-reuse");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xbb; 20]),
    };
    let (artifact_source, block) = checkpointed_wallet_artifact_source_controlled_with_requests(
        &scope,
        100,
        150,
        150,
        false,
        6,
        Some(125),
        false,
    );
    assert!(block.is_none());
    let retained_descriptor = artifact_source.chunk_descriptors[0].clone();
    let transient_descriptor = artifact_source.chunk_descriptors[1].clone();
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
        Duration::from_secs(1),
    ));
    let chain = test_chain_config(&scope, rpcs, Some(artifact_source.config.clone()));
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );

    IndexedWalletArtifactSession::prepare(
        &chain,
        100,
        150,
        public_data_plane.begin_public_scan_read(),
        &public_data_plane,
        None,
    )
    .await
    .expect("prepare cold wallet artifacts")
    .expect("cold wallet artifact session");
    for _ in 0..100 {
        if public_data_plane
            .cached_wallet_scan_artifact_chunk(&retained_descriptor)
            .is_some()
            && public_data_plane
                .cached_wallet_scan_transient_artifact_chunk(&transient_descriptor)
                .is_some()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        public_data_plane
            .cached_wallet_scan_artifact_chunk(&retained_descriptor)
            .is_some(),
        "stable wallet artifact chunk was not retained"
    );
    assert!(
        public_data_plane
            .cached_wallet_scan_transient_artifact_chunk(&transient_descriptor)
            .is_some(),
        "transient wallet artifact chunk was not retained"
    );
    assert_eq!(artifact_source.server.request_count(), 4);

    IndexedWalletArtifactSession::prepare(
        &chain,
        100,
        150,
        public_data_plane.begin_public_scan_read(),
        &public_data_plane,
        None,
    )
    .await
    .expect("prepare warm wallet artifacts")
    .expect("warm wallet artifact session");
    assert_eq!(
        artifact_source.server.request_count(),
        5,
        "warm preparation should reuse the manifest, stable history and the unchanged transient tail"
    );

    public_data_plane.shutdown().await;
    drop(public_data_plane);
    drop(chain);
    drop(artifact_source.server);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn partial_cached_replay_does_not_publish_regressive_artifact_preparation() {
    let scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xbb; 20]),
    };
    let artifact_source = checkpointed_wallet_artifact_source(&scope, 100, 200, 200);
    let mut context = IndexedCatchUpTestContext::new(
        &scope,
        Url::parse("http://127.0.0.1:1").expect("quick-sync url"),
        Some(artifact_source.config.clone()),
        100,
        100,
    )
    .await;
    context
        .public_data_plane
        .record_public_scan_coverage(PublicScanCoverageWrite {
            range: PublicScanRange::new(101, 150),
            source: PublicScanSource::Rpc,
            row_count: 0,
            read_scope: context.public_data_plane.begin_public_scan_read(),
        })
        .await
        .expect("record cached prefix");
    let (progress_tx, progress_rx) = watch::channel(None);
    context.wallet_cfg.progress_tx = Some(progress_tx);

    let checkpoint = context
        .spawn_catch_up(200, IndexedWalletCatchUpSourceOrder::ArtifactsFirst)
        .await
        .expect("indexed catch-up task");

    assert_eq!(checkpoint, 200);
    assert!(
        progress_rx.borrow().is_none(),
        "artifact preparation must not overwrite progress after cached indexing begins"
    );
    context.cleanup();
    drop(artifact_source.server);
}

#[tokio::test]
async fn verified_stable_chunk_is_retained_when_later_chunk_fails() {
    let root_dir = temp_db_root("wallet-artifact-partial-retention");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xbb; 20]),
    };
    let (artifact_source, block) = checkpointed_wallet_artifact_source_controlled_with_requests(
        &scope,
        100,
        150,
        150,
        false,
        4,
        Some(125),
        true,
    );
    assert!(block.is_none());
    let stable_descriptor = artifact_source.chunk_descriptors[0].clone();
    let failed_tail_descriptor = artifact_source.chunk_descriptors[1].clone();
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
        Duration::from_secs(1),
    ));
    let chain = test_chain_config(&scope, rpcs, Some(artifact_source.config.clone()));
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );

    let preparation = IndexedWalletArtifactSession::prepare(
        &chain,
        100,
        150,
        public_data_plane.begin_public_scan_read(),
        &public_data_plane,
        None,
    )
    .await;
    assert!(
        preparation.is_err(),
        "missing tail chunk must fail preparation"
    );
    for _ in 0..100 {
        if public_data_plane
            .cached_wallet_scan_artifact_chunk(&stable_descriptor)
            .is_some()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        public_data_plane
            .cached_wallet_scan_artifact_chunk(&stable_descriptor)
            .is_some(),
        "verified stable chunk should survive a later fetch failure"
    );
    assert!(
        public_data_plane
            .cached_wallet_scan_artifact_chunk(&failed_tail_descriptor)
            .is_none()
    );

    public_data_plane.shutdown().await;
    drop(public_data_plane);
    drop(chain);
    drop(artifact_source.server);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn indexed_wallet_initial_squid_probe_keeps_pre_probe_read_scope() {
    let scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xbb; 20]),
    };
    let (squid, block) = GraphqlServer::spawn_with_blocked_response(
        vec![
            r#"{"data":{"squidStatus":{"height":"150"},"transactCommitments":[],"shieldCommitments":[],"nullifiers":[],"legacyEncryptedCommitments":[],"legacyGeneratedCommitments":[]}}"#,
            r#"{"data":{"transactCommitments":[],"shieldCommitments":[],"nullifiers":[]}}"#,
        ],
        0,
    );
    let context = IndexedCatchUpTestContext::new(&scope, squid.url.clone(), None, 100, 100).await;
    let catch_up = context.spawn_catch_up(150, IndexedWalletCatchUpSourceOrder::SquidFirst);

    wait_for_std_signal(block.request_started, "initial Squid probe started").await;
    context
        .public_data_plane
        .invalidate_public_scan_coverage_from(101)
        .await;
    block.release.send(()).expect("release initial Squid probe");
    let checkpoint = catch_up.await.expect("indexed catch-up task");

    assert_eq!(checkpoint, 100);
    assert_eq!(context.handle.last_scanned(), Some(100));
    assert!(matches!(
        context
            .public_data_plane
            .cached_public_scan_coverage(PublicScanRange::new(101, 150))
            .await,
        PublicCoverageAnswer::Missing { .. }
    ));
    let diagnostics = context.public_data_plane.diagnostics().await;
    assert!(diagnostics.events.iter().any(|event| {
        event.kind == PublicDataPlaneDiagnosticKind::CoverageRejected
            && event.source == Some(PublicScanSource::Squid)
            && event.range == Some(PublicScanRange::new(101, 150))
    }));

    context.cleanup();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn indexed_wallet_squid_transition_probe_keeps_pre_probe_read_scope() {
    let scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xbb; 20]),
    };
    let artifact_source = checkpointed_wallet_artifact_source(&scope, 100, 200, 150);
    // The startup race's Squid candidate sees Squid behind the wallet, so
    // the blocked response is the transition probe after the artifact pages.
    let (squid, block) = GraphqlServer::spawn_with_blocked_response(
        vec![
            r#"{"data":{"squidStatus":{"height":"100"},"transactCommitments":[],"shieldCommitments":[],"nullifiers":[],"legacyEncryptedCommitments":[],"legacyGeneratedCommitments":[]}}"#,
            r#"{"data":{"squidStatus":{"height":"200"},"transactCommitments":[],"shieldCommitments":[],"nullifiers":[],"legacyEncryptedCommitments":[],"legacyGeneratedCommitments":[]}}"#,
            r#"{"data":{"transactCommitments":[],"shieldCommitments":[],"nullifiers":[]}}"#,
        ],
        1,
    );
    let context = IndexedCatchUpTestContext::new(
        &scope,
        squid.url.clone(),
        Some(artifact_source.config.clone()),
        100,
        100,
    )
    .await;
    // The tail 151..=300 after the artifact checkpoint is longer than one
    // RPC page, so Squid is probed for it.
    let catch_up = context.spawn_catch_up(300, IndexedWalletCatchUpSourceOrder::ArtifactsFirst);

    wait_for_std_signal(block.request_started, "Squid transition probe started").await;
    assert_eq!(context.handle.last_scanned(), Some(150));
    context
        .public_data_plane
        .invalidate_public_scan_coverage_from(151)
        .await;
    block
        .release
        .send(())
        .expect("release Squid transition probe");
    let checkpoint = catch_up.await.expect("indexed catch-up task");

    assert_eq!(checkpoint, 150);
    assert_eq!(context.handle.last_scanned(), Some(150));
    assert!(matches!(
        context
            .public_data_plane
            .cached_public_scan_coverage(PublicScanRange::new(151, 200))
            .await,
        PublicCoverageAnswer::Missing { .. }
    ));
    let diagnostics = context.public_data_plane.diagnostics().await;
    assert!(diagnostics.events.iter().any(|event| {
        event.kind == PublicDataPlaneDiagnosticKind::CoverageRejected
            && event.source == Some(PublicScanSource::Squid)
            && event.range == Some(PublicScanRange::new(151, 200))
    }));

    context.cleanup();
    drop(artifact_source.server);
}

#[tokio::test]
async fn artifact_wallet_catch_up_sends_one_page_tail_to_rpc_without_squid() {
    let root_dir = temp_db_root("artifact-wallet-one-page-tail");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    // Artifacts reach block 150, one 50-block RPC page short of the target.
    let (artifact_source, manifest_block) =
        checkpointed_wallet_artifact_source_with_blocked_manifest(&scope, 100, 200, 150);
    // The startup race's Squid candidate sees Squid behind the wallet. The
    // second response would answer a tail probe.
    let squid = GraphqlServer::spawn_controlled(
        vec![squid_wallet_probe(100), squid_wallet_probe(200)],
        None,
    );
    let rpc = JsonRpcServer::spawn_handler(log_range_rpc_handler(Vec::new(), 200, |_, _, _| None));
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(
        &scope,
        Arc::clone(&rpcs),
        Some(artifact_source.config.clone()),
    );
    chain.sync.block_range = 50;
    chain.sync.indexed_wallet_block_range = 50;
    chain.finality_depth = 0;
    chain.sync.quick_sync_endpoint = Some(squid.url.clone());
    let public_data_plane = ChainPublicDataPlane::new(Arc::clone(&db), Arc::new(AtomicU64::new(0)));
    let (service, backfill_rx) = test_chain_service_with_backfill(
        Arc::clone(&db),
        chain,
        public_data_plane,
        test_proxy_poi_policy(),
    );
    service.safe_head_tx.send_replace(200);
    spawn_backfill_loop(
        Arc::clone(&service),
        backfill_rx,
        rpcs,
        None,
        service.safe_head_tx.subscribe(),
        service.cancel.clone(),
    );

    let mut cfg = test_wallet_config(&scope, squid.url.clone());
    cfg.cache_key = test_cache_key("artifact-one-page-tail");
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
    // Artifacts win the race once the race's Squid probe has been answered.
    let mut squid_requests = Vec::new();
    yield_until("race Squid probe", || {
        squid_requests.extend(squid.requests.try_iter());
        !squid_requests.is_empty()
    })
    .await;
    manifest_block
        .release
        .send(())
        .expect("release artifact manifest");
    tokio::time::timeout(Duration::from_secs(5), handle.wait_until_ready())
        .await
        .expect("RPC backfill delivered the tail")
        .expect("wallet readiness succeeded");

    assert_eq!(handle.last_scanned(), Some(200));
    assert_eq!(
        get_logs_ranges(&rpc.drain_request_bodies()).first(),
        Some(&(151, 200)),
        "RPC backfill reads the tail after the artifact checkpoint"
    );
    // The TXID cache loop may query Squid once the wallet is ready, but it
    // never sends a wallet probe.
    squid_requests.extend(squid.requests.try_iter());
    assert_eq!(
        squid_requests
            .iter()
            .filter(|request| request.contains("query WalletProbe"))
            .count(),
        1,
        "no Squid probe for the one-page tail"
    );

    service.unregister_all_wallets().await;
    service.shutdown().await;
    drop(service);
    drop(artifact_source.server);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test(start_paused = true)]
async fn artifact_wallet_catch_up_stops_waiting_for_hung_squid_tail_probe_at_deadline() {
    let scope = test_scope();
    let (artifact_source, manifest_block) =
        checkpointed_wallet_artifact_source_with_blocked_manifest(&scope, 100, 200, 150);
    // The race's Squid candidate sees Squid behind the wallet, and the tail
    // probe after the artifact checkpoint gets no answer.
    let (squid, tail_probe) = GraphqlServer::spawn_owned_with_blocked_response(
        vec![squid_wallet_probe(100), squid_wallet_probe(300)],
        1,
    );
    let context = IndexedCatchUpTestContext::new(
        &scope,
        squid.url.clone(),
        Some(artifact_source.config.clone()),
        100,
        100,
    )
    .await;
    // The tail 151..=300 is longer than one 100-block RPC page.
    let catch_up = context.spawn_catch_up(300, IndexedWalletCatchUpSourceOrder::ArtifactsFirst);

    // Busy-yielding keeps the paused clock still until the tail probe is held.
    yield_until("race Squid probe", || squid.requests.try_recv().is_ok()).await;
    manifest_block
        .release
        .send(())
        .expect("release artifact manifest");
    yield_until("Squid tail probe", || {
        tail_probe.request_started.try_recv().is_ok()
    })
    .await;
    assert_eq!(context.handle.last_scanned(), Some(150));

    let deadline = super::super::logs::INDEXED_SQUID_STEP_DEADLINE;
    tokio::time::advance(deadline.saturating_sub(Duration::from_millis(1))).await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert!(
        !catch_up.is_finished(),
        "the probe is awaited until the deadline"
    );
    tokio::time::advance(Duration::from_millis(1)).await;
    yield_until("catch-up after the deadline", || catch_up.is_finished()).await;
    assert_eq!(
        catch_up.await.expect("indexed catch-up task"),
        150,
        "RPC backfill resumes from the artifact checkpoint"
    );

    tail_probe
        .release
        .send(())
        .expect("release Squid tail probe");
    context.cleanup();
    drop(artifact_source.server);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn indexed_wallet_squid_session_is_not_restamped_between_pages() {
    let scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xbb; 20]),
    };
    let (squid, block) = GraphqlServer::spawn_with_blocked_response(
        vec![
            r#"{"data":{"squidStatus":{"height":"200"},"transactCommitments":[],"shieldCommitments":[],"nullifiers":[],"legacyEncryptedCommitments":[],"legacyGeneratedCommitments":[]}}"#,
            r#"{"data":{"transactCommitments":[],"shieldCommitments":[],"nullifiers":[]}}"#,
            r#"{"data":{"transactCommitments":[],"shieldCommitments":[],"nullifiers":[]}}"#,
        ],
        2,
    );
    let context = IndexedCatchUpTestContext::new(&scope, squid.url.clone(), None, 100, 50).await;
    let catch_up = context.spawn_catch_up(200, IndexedWalletCatchUpSourceOrder::SquidFirst);

    wait_for_std_signal(block.request_started, "second Squid page request started").await;
    assert_eq!(context.handle.last_scanned(), Some(150));
    context
        .public_data_plane
        .invalidate_public_scan_coverage_from(151)
        .await;
    block.release.send(()).expect("release second Squid page");
    let checkpoint = catch_up.await.expect("indexed catch-up task");

    assert_eq!(checkpoint, 150);
    assert_eq!(context.handle.last_scanned(), Some(150));
    assert!(matches!(
        context
            .public_data_plane
            .cached_public_scan_coverage(PublicScanRange::new(151, 200))
            .await,
        PublicCoverageAnswer::Missing { .. }
    ));
    let diagnostics = context.public_data_plane.diagnostics().await;
    assert!(diagnostics.events.iter().any(|event| {
        event.kind == PublicDataPlaneDiagnosticKind::CoverageRejected
            && event.source == Some(PublicScanSource::Squid)
            && event.range == Some(PublicScanRange::new(151, 200))
    }));

    context.cleanup();
}

#[tokio::test]
async fn squid_wallet_candidate_holds_ordered_pages_within_row_budget() {
    use super::super::service::SquidWalletCandidateOutcome;

    let scope = test_scope();
    let squid = GraphqlServer::spawn_controlled(
        vec![
            squid_wallet_probe(200),
            squid_wallet_page_with_nullifier(120),
            squid_wallet_page_with_nullifier(170),
            squid_wallet_probe(200),
            squid_wallet_page_with_nullifier(120),
            squid_wallet_probe(100),
        ],
        None,
    );
    let context = IndexedCatchUpTestContext::new(&scope, squid.url.clone(), None, 100, 50).await;
    let service = &context.service;
    let cfg = &context.wallet_cfg;

    let SquidWalletCandidateOutcome::Ready(candidate) =
        service.squid_wallet_candidate(cfg, 101, 180, 2).await
    else {
        panic!("the Squid candidate holds every page through its target");
    };
    assert_eq!(candidate.target, 180);
    assert_eq!(candidate.rows, 2);
    let pages = candidate
        .pages
        .iter()
        .map(|(from_block, page)| (*from_block, page.checkpoint_block, page.nullifiers.len()))
        .collect::<Vec<_>>();
    assert_eq!(pages, vec![(101, 150, 1), (151, 180, 1)]);
    assert!(matches!(
        service.squid_wallet_candidate(cfg, 101, 180, 0).await,
        SquidWalletCandidateOutcome::OverBudget {
            target: 180,
            rows: 1
        }
    ));
    assert!(
        matches!(
            service.squid_wallet_candidate(cfg, 101, 180, 2).await,
            SquidWalletCandidateOutcome::NoResult
        ),
        "a Squid source behind the wallet yields no result"
    );

    let requests = squid.requests.try_iter().collect::<Vec<_>>();
    assert_eq!(
        requests.len(),
        6,
        "neither the over-budget nor the behind candidate requests another page"
    );
    assert!(requests[1].contains(r#""fromBlock":"101""#));
    assert!(requests[1].contains(r#""toBlock":"150""#));
    assert!(requests[2].contains(r#""fromBlock":"151""#));
    assert!(requests[2].contains(r#""toBlock":"180""#));
    assert!(requests[3].contains("query WalletProbe"));
    assert!(requests[5].contains("query WalletProbe"));

    context.cleanup();
}

#[tokio::test]
async fn stalled_artifact_manifest_lets_squid_win_wallet_catch_up() {
    let scope = test_scope();
    let (mut artifact_source, manifest_block) =
        checkpointed_wallet_artifact_source_with_blocked_manifest(&scope, 100, 250, 250);
    let gateway_port = artifact_source.server.url.port().expect("gateway port");
    artifact_source.config.manifest_source = IndexedArtifactManifestSource::Url(
        credential_url(gateway_port)
            .join("/manifest.json")
            .expect("manifest url"),
    );
    artifact_source.config.gateway_urls = vec![credential_url(gateway_port)];
    // The first Squid page waits until the manifest request is in flight.
    let (squid, squid_page_block) = GraphqlServer::spawn_owned_with_blocked_response(
        vec![
            squid_wallet_probe(200),
            squid_wallet_page_with_nullifier(120),
            squid_wallet_page_with_nullifier(170),
        ],
        1,
    );
    let squid_port = squid.url.port().expect("Squid port");
    let events = CapturedEvents::default();
    let guard = events.capture();
    let context = IndexedCatchUpTestContext::new(
        &scope,
        credential_url(squid_port),
        Some(artifact_source.config.clone()),
        100,
        50,
    )
    .await;

    let catch_up = context.spawn_catch_up(250, IndexedWalletCatchUpSourceOrder::ArtifactsFirst);
    wait_for_std_signal(
        manifest_block.request_started,
        "artifact manifest request started",
    )
    .await;
    squid_page_block
        .release
        .send(())
        .expect("release first Squid page");
    let checkpoint = catch_up.await.expect("indexed catch-up task");
    manifest_block
        .release
        .send(())
        .expect("release artifact manifest");
    // Give a request from the dropped artifact candidate time to arrive.
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(guard);

    assert_eq!(checkpoint, 200, "Squid commits through its indexed height");
    assert_eq!(context.handle.last_scanned(), Some(200));
    assert!(matches!(
        context
            .public_data_plane
            .cached_public_scan_coverage(PublicScanRange::new(101, 200))
            .await,
        PublicCoverageAnswer::CoveredWithRows {
            range,
            source: PublicScanSource::Squid,
            ..
        } if range == PublicScanRange::new(101, 200)
    ));
    assert!(
        matches!(
            context
                .public_data_plane
                .cached_public_scan_coverage(PublicScanRange::new(201, 250))
                .await,
            PublicCoverageAnswer::Missing { .. }
        ),
        "blocks past the Squid target are left for the RPC tail"
    );
    assert_eq!(
        squid.requests.try_iter().count(),
        3,
        "held pages are committed without being fetched again"
    );
    assert_eq!(
        artifact_source.server.request_count(),
        1,
        "the dropped artifact candidate issues no request after the manifest"
    );

    let started = events.find("wallet catch-up race started");
    for (field, value) in [
        ("from_block", "101"),
        ("safe_head", "250"),
        ("gap_blocks", "150"),
        ("candidates", "indexed_artifacts,squid"),
    ] {
        assert_eq!(
            started.get(field).map(String::as_str),
            Some(value),
            "{field}"
        );
    }
    let candidate_end = |source: &str| {
        events
            .events()
            .into_iter()
            .filter(|event| {
                event
                    .get("message")
                    .is_some_and(|message| message == "wallet catch-up race candidate finished")
                    && event.get("source").is_some_and(|value| value == source)
            })
            .collect::<Vec<_>>()
    };
    let squid_end = candidate_end("squid");
    assert_eq!(squid_end.len(), 1);
    for (field, value) in [("outcome", "ready"), ("target", "200"), ("squid_rows", "2")] {
        assert_eq!(
            squid_end[0].get(field).map(String::as_str),
            Some(value),
            "{field}"
        );
    }
    assert!(squid_end[0].contains_key("elapsed_ms"));
    let artifact_end = candidate_end("indexed_artifacts");
    assert_eq!(artifact_end.len(), 1);
    assert_eq!(
        artifact_end[0].get("outcome").map(String::as_str),
        Some("cancelled")
    );
    let winner = events.find("wallet catch-up race won");
    assert_eq!(winner.get("source").map(String::as_str), Some("squid"));
    assert_eq!(winner.get("target").map(String::as_str), Some("200"));
    assert!(winner.contains_key("elapsed_ms"));
    let endpoints = [squid_port, gateway_port].map(|port| format!("127.0.0.1:{port}"));
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

    context.cleanup();
}

#[tokio::test]
async fn wallet_catch_up_race_without_a_source_falls_back_to_rpc() {
    let scope = test_scope();
    // Artifacts end at block 50, below the wallet's next block, and the
    // Squid probe fails.
    let artifact_source = checkpointed_wallet_artifact_source(&scope, 1, 50, 50);
    let squid = GraphqlServer::spawn(vec![
        r#"{"errors":[{"message":"indexed source unavailable"}]}"#,
    ]);
    let context = IndexedCatchUpTestContext::new(
        &scope,
        squid.url.clone(),
        Some(artifact_source.config.clone()),
        100,
        50,
    )
    .await;

    let checkpoint = context
        .spawn_catch_up(200, IndexedWalletCatchUpSourceOrder::ArtifactsFirst)
        .await
        .expect("indexed catch-up task");

    assert_eq!(checkpoint, 100);
    assert_eq!(context.handle.last_scanned(), Some(100));
    assert!(matches!(
        context
            .public_data_plane
            .cached_public_scan_coverage(PublicScanRange::new(101, 200))
            .await,
        PublicCoverageAnswer::Missing { .. }
    ));
    assert_eq!(
        squid.requests.try_iter().count(),
        1,
        "only the race probe reaches Squid"
    );
    let diagnostics = context.public_data_plane.diagnostics().await;
    assert!(diagnostics.events.iter().any(|event| {
        event.kind == PublicDataPlaneDiagnosticKind::SourceFallback
            && event.source == Some(PublicScanSource::Rpc)
            && event.range == Some(PublicScanRange::new(101, 200))
    }));

    context.cleanup();
    drop(artifact_source.server);
}

#[tokio::test]
async fn indexed_status_guard_drop_retires_claim_and_clears_status() {
    let scope = test_scope();
    let context = IndexedCatchUpTestContext::new(
        &scope,
        Url::parse("http://127.0.0.1:1").expect("quick sync URL"),
        None,
        100,
        10,
    )
    .await;
    let token = context.handle.mint_sync_token(0);
    let driver = match send_wallet_target("test", &context.wallet_backfill_tx, 100, token).await {
        WalletBackfillStartResult::Accepted { grant, .. } => grant.activate(),
        result @ WalletBackfillStartResult::Rejected { .. } => {
            panic!("initial backfill start rejected: {result:?}")
        }
    };
    assert_eq!(
        driver.finish("test", 100).await,
        WalletBackfillFinishResult::Ready { committed_to: 100 }
    );
    let guard = WalletIndexedCatchUpStatusGuard::claim(&context.handle, true)
        .await
        .expect("indexed status guard claim");
    guard.set(WalletIndexedCatchUpSource::Squid, 101, 200);
    tokio::time::timeout(Duration::from_secs(1), async {
        while context.handle.indexed_catch_up_rx.borrow().is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("guard status published");

    drop(guard);

    tokio::time::timeout(Duration::from_secs(1), async {
        while context.handle.indexed_catch_up_rx.borrow().is_some()
            || context.handle.readiness() != WalletReadiness::Ready
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("guard drop cleared status and restored readiness");
    context.cleanup();
}

fn blocked_wallet_optional_maintenance_fixture(
    name: &str,
) -> BlockedWalletOptionalMaintenanceFixture {
    let root_dir = temp_db_root(name);
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = ChainScope {
        chain_type: ChainType::Evm,
        chain_id: 1,
        railgun_contract: Address::from([0xbb; 20]),
    };
    let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
    let optional_bytes = empty_wallet_scan_chunk_bytes(&scope, 100, 109);
    let optional_cid = raw_cid(&optional_bytes);
    let optional_descriptor = wallet_artifact_descriptor(
        scope.clone(),
        100,
        109,
        0,
        optional_cid,
        &optional_bytes,
        DatasetDescriptorMetadata {
            catalog_generation: Some(1),
            checkpoint_block: Some(109),
            ..Default::default()
        },
        CompressionAlgorithm::None,
    );
    let required_bytes = empty_wallet_scan_chunk_bytes(&scope, 110, 120);
    let required_cid = raw_cid(&required_bytes);
    let required_descriptor = wallet_artifact_descriptor(
        scope.clone(),
        110,
        120,
        0,
        required_cid,
        &required_bytes,
        DatasetDescriptorMetadata {
            catalog_generation: Some(1),
            checkpoint_block: Some(120),
            ..Default::default()
        },
        CompressionAlgorithm::None,
    );
    let catalog = IndexedArtifactCatalog {
        format_version: INDEXED_ARTIFACT_CATALOG_FORMAT_VERSION,
        dataset_kind: IndexedDatasetKind::WalletScan,
        scope: scope.clone(),
        chunks: vec![optional_descriptor.clone(), required_descriptor],
    };
    let catalog_bytes = serde_json::to_vec(&catalog).expect("catalog json");
    let catalog_cid = raw_cid(&catalog_bytes);
    let catalog_descriptor = wallet_artifact_descriptor(
        scope.clone(),
        100,
        120,
        0,
        catalog_cid,
        &catalog_bytes,
        DatasetDescriptorMetadata {
            catalog_generation: Some(1),
            checkpoint_block: Some(120),
            ..Default::default()
        },
        CompressionAlgorithm::None,
    );
    let mut manifest = IndexedArtifactManifest::new(
        1_700_000_000_000,
        1,
        PublisherIdentity::ed25519(FixedBytes::from(signing_key.verifying_key().to_bytes())),
        vec![IndexedArtifactChainEntry {
            scope: scope.clone(),
            latest_indexed: vec![LatestIndexedHeight {
                dataset_kind: IndexedDatasetKind::WalletScan,
                block_number: 120,
                block_hash: FixedBytes::from([0x22; 32]),
            }],
            catalogs: vec![catalog_descriptor],
        }],
    );
    manifest.sign_manifest(&signing_key).expect("sign manifest");
    let manifest_bytes = serde_json::to_vec(&manifest).expect("manifest json");
    let optional_path = format!("/ipfs/{optional_cid}?format=car&dag-scope=entity");
    let routes = HashMap::from([
        ("/manifest.json".to_string(), manifest_bytes),
        (
            format!("/ipfs/{catalog_cid}?format=car&dag-scope=entity"),
            car_bytes(catalog_cid, &[(catalog_cid, catalog_bytes)]),
        ),
        (
            optional_path.clone(),
            car_bytes(optional_cid, &[(optional_cid, optional_bytes)]),
        ),
        (
            format!("/ipfs/{required_cid}?format=car&dag-scope=entity"),
            car_bytes(required_cid, &[(required_cid, required_bytes)]),
        ),
    ]);
    let (server, optional_block) = PathServer::spawn_with_blocked_path(routes, 4, optional_path);
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
        amount_statistics_ipns_name: None,
    };
    let artifact_source = TestArtifactSource {
        config,
        server,
        chunk_descriptors: vec![optional_descriptor.clone()],
    };
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![Url::parse("http://127.0.0.1:1").expect("rpc url")],
        Duration::from_secs(1),
    ));
    let chain = test_chain_config(&scope, rpcs, Some(artifact_source.config.clone()));
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    BlockedWalletOptionalMaintenanceFixture {
        root_dir,
        db,
        public_data_plane,
        chain,
        artifact_source,
        optional_block,
        optional_descriptor,
    }
}
