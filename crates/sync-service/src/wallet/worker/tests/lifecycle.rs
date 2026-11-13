use super::*;

#[tokio::test]
async fn cancellation_interrupts_actor_authority_acquisition() {
    let root_dir = temp_db_root("wallet-cancel-authority-wait");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let (live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),

            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: backfill_tx.clone(),
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");
    assert_eq!(
        send_target_token(&backfill_tx, 100, handle.mint_sync_token(0)).await,
        WalletBackfillFinishResult::Ready { committed_to: 100 }
    );
    let mut readiness_rx = handle.subscribe_observation();
    wait_for_readiness(&mut readiness_rx, WalletReadiness::Ready).await;

    let held = Arc::clone(&handle.authority_lock).lock_owned().await;
    live_tx
        .send(logs_payload(101, 101))
        .expect("live receiver remains active");
    wait_for_readiness(&mut readiness_rx, WalletReadiness::Syncing).await;

    cancel.cancel();
    tokio::time::timeout(
        Duration::from_secs(1),
        wait_for_readiness(&mut readiness_rx, WalletReadiness::Shutdown),
    )
    .await
    .expect("worker cancellation bypassed authority contention");
    drop(held);

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn prepared_restored_replay_waits_for_activation_before_backfill_admission() {
    let root_dir = temp_db_root("wallet-reset-prepared-replay-admission");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let mut cfg = wallet_config();
    cfg.start_block = Some(100);
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
    .expect("seed bounded restored replay");

    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_event_tx, backfill_event_rx) = mpsc::channel(8);
    let (backfill_request_tx, mut backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let mut prepared = prepare_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),
            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: backfill_event_tx.clone(),
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        cfg.clone(),
        1,
        live_rx,
        backfill_event_rx,
        cancel.clone(),
        Vec::new(),
        79,
    )
    .await
    .expect("prepare restored wallet worker");

    assert!(backfill_request_rx.try_recv().is_err());
    assert_eq!(
        db.get_wallet_sync_actor_state(cfg.chain.chain_id, &cfg.cache_key)
            .expect("read durable actor state")
            .expect("durable actor state")
            .pending_reset
            .expect("durable replay remains before activation")
            .replay_target_block,
        99
    );

    let worker = prepared.take_worker();
    let handle = prepared.activate().expect("activate prepared worker");
    let request = tokio::time::timeout(Duration::from_secs(1), backfill_request_rx.recv())
        .await
        .expect("restored replay admission arrives after activation")
        .expect("backfill request channel remains open");
    let BackfillRequest::Add {
        from_block,
        to_block,
        driver,
        cache_key,
        ..
    } = request
    else {
        panic!("restored replay must admit an Add request");
    };
    assert_eq!((from_block, to_block), (80, 99));
    assert_eq!(driver.token().actor_id(), handle.actor_id());
    assert_eq!(handle.readiness(), WalletReadiness::Syncing);
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let pending_reset = db
                .get_wallet_sync_actor_state(cfg.chain.chain_id, &cfg.cache_key)
                .expect("read actor state after admission")
                .expect("durable actor state after admission")
                .pending_reset;
            if pending_reset.is_none() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("durable replay retirement follows admission");

    driver.retire(&cache_key).await;
    cancel.cancel();
    worker.await.expect("wallet worker shuts down cleanly");
    drop(backfill_event_tx);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_worker_restores_durable_pending_reset_before_accepting_older_intents() {
    let root_dir = temp_db_root("wallet-reset-restore-pending");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cfg = wallet_config();
    db.put_wallet_sync_actor_state(&WalletSyncActorStateRecord {
        chain_id: cfg.chain.chain_id,
        wallet_id: cfg.cache_key.to_string(),
        highest_accepted_reset_intent: 7,
        pending_reset: Some(WalletPendingResetRecord {
            intent_id: 7,
            from_block: 100,
            replay_start_block: 0,
            replay_target_block: 0,
            follow_safe_head: true,
        }),
        updated_at: 1,
    })
    .expect("seed wallet sync actor state");
    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),

            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: backfill_tx.clone(),
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        cfg.clone(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        vec![test_wallet_utxo(105, 7)],
        120,
    )
    .await
    .expect("spawn wallet worker");

    assert_eq!(handle.authority_reset_generation(), 1);
    assert_eq!(handle.last_scanned(), Some(99));
    assert!(handle.utxos.read().await.is_empty());
    assert_eq!(
        send_reset(&backfill_tx, 7, 90).await,
        WalletBackfillResetResult::Rejected {
            committed_to: 99,
            reason: WalletBackfillRejectReason::StaleResetIntent {
                accepted: 7,
                actual: 7,
            },
        }
    );

    let state = db
        .get_wallet_sync_actor_state(cfg.chain.chain_id, &cfg.cache_key)
        .expect("load wallet sync actor state")
        .expect("wallet sync actor state persisted");
    assert_eq!(state.highest_accepted_reset_intent, 7);
    assert!(state.pending_reset.is_none());

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_worker_restored_pending_reset_waits_for_first_actor_replay_attempt() {
    let root_dir = temp_db_root("wallet-reset-restore-failed-replay");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    let mut cfg = wallet_config();
    cache_store.seed_actor_state(WalletSyncActorStateRecord {
        chain_id: cfg.chain.chain_id,
        wallet_id: cfg.cache_key.to_string(),
        highest_accepted_reset_intent: 7,
        pending_reset: Some(WalletPendingResetRecord {
            intent_id: 7,
            from_block: 100,
            replay_start_block: 0,
            replay_target_block: 0,
            follow_safe_head: true,
        }),
        updated_at: 1,
    });
    cache_store.fail_next_store();
    cfg.cache_store = Some(cache_store.clone());
    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let handle = tokio::time::timeout(
        Duration::from_secs(1),
        spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                http_client: None,
                indexed_artifact_source: None,
                poi_runtime: test_wallet_poi_runtime(),
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx,
                public_data_plane: test_public_data_plane(&db),
                poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
            },
            cfg,
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            vec![test_wallet_utxo(105, 7)],
            120,
        ),
    )
    .await
    .expect("restored pending reset first attempt should complete")
    .expect("spawn wallet worker");

    assert_eq!(
        cache_store.state().store_calls,
        1,
        "worker must not expose the handle before the first rewind attempt"
    );
    assert_eq!(handle.authority_reset_generation(), 1);
    // Public observation is fenced: pre-reset cursor/UTXOs are not current.
    let observation = handle.observation();
    assert!(matches!(
        observation.view(),
        WalletViewState::ResetPending {
            intent_id: 7,
            from_block: 100,
            reset_generation: 1,
        }
    ));
    assert_eq!(observation.readiness(), &WalletReadiness::Syncing);
    assert_eq!(handle.last_scanned(), None);
    assert!(handle.utxos_snapshot().is_none());
    assert!(handle.pending_overlay().is_none());
    assert!(handle.current_snapshot().is_none());
    assert_eq!(handle.last_scanned_raw(), 120);
    assert_eq!(handle.readiness(), WalletReadiness::Syncing);
    assert!(
        cache_store
            .actor_state()
            .expect("restored actor state")
            .pending_reset
            .is_some()
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn incompatible_restored_pending_reset_is_rejected_before_private_state_write() {
    let root_dir = temp_db_root("wallet-reset-incompatible-restored-plan");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    let mut cfg = wallet_config();
    cfg.start_block = Some(100);
    let cache_key = cfg.cache_key.clone();
    let original_meta = WalletMeta {
        last_scanned_block: 120,
        updated_at: 9,
        last_scanned_block_hash: Some([0x91; 32]),
    };
    db.put_wallet_meta(&cache_key, &original_meta)
        .expect("seed wallet cursor");
    cfg.cache_store = Some(cache_store.clone());

    assert!(
        validate_restored_pending_reset(
            &cfg,
            120,
            PendingWalletReset::new(7, 80, 1, WalletResetReplayPlan::new(80, 99, false),),
        )
        .is_ok(),
        "bounded replay through the configured-start boundary must remain valid"
    );

    for (replay_start_block, replay_target_block) in [(100, 150), (80, 98)] {
        cache_store.seed_actor_state(WalletSyncActorStateRecord {
            chain_id: cfg.chain.chain_id,
            wallet_id: cfg.cache_key.to_string(),
            highest_accepted_reset_intent: 7,
            pending_reset: Some(WalletPendingResetRecord {
                intent_id: 7,
                from_block: 80,
                replay_start_block,
                replay_target_block,
                follow_safe_head: false,
            }),
            updated_at: 1,
        });
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();

        let result = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                http_client: None,
                indexed_artifact_source: None,
                poi_runtime: test_wallet_poi_runtime(),
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx,
                public_data_plane: test_public_data_plane(&db),
                poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
            },
            cfg.clone(),
            1,
            live_rx,
            backfill_rx,
            cancel.clone(),
            vec![test_wallet_utxo(105, 7)],
            120,
        )
        .await;

        let Err(ChainError::IncompatiblePendingWalletResetReplay {
            post_rewind_cursor,
            configured_start_block,
            replay_start_block: actual_start,
            replay_target_block: actual_target,
            follow_safe_head,
            required_replay_start_block,
            required_replay_target_block,
        }) = result
        else {
            panic!("incompatible restored replay must be rejected");
        };
        assert_eq!(post_rewind_cursor, 79);
        assert_eq!(configured_start_block, 100);
        assert_eq!(actual_start, replay_start_block);
        assert_eq!(actual_target, replay_target_block);
        assert!(!follow_safe_head);
        assert_eq!(required_replay_start_block, 80);
        assert_eq!(required_replay_target_block, 99);
        assert_eq!(cache_store.state().store_calls, 0);
        assert_eq!(cache_store.state().meta_calls, 0);
        let unchanged_meta = db
            .get_wallet_meta(&cache_key)
            .expect("load unchanged wallet cursor")
            .expect("wallet cursor remains");
        assert_eq!(
            unchanged_meta.last_scanned_block,
            original_meta.last_scanned_block
        );
        assert_eq!(unchanged_meta.updated_at, original_meta.updated_at);
        assert_eq!(
            unchanged_meta.last_scanned_block_hash,
            original_meta.last_scanned_block_hash
        );
        let restored = cache_store
            .actor_state()
            .expect("restored actor state remains");
        let pending = restored
            .pending_reset
            .expect("pending reset remains preserved");
        assert_eq!(pending.replay_start_block, replay_start_block);
        assert_eq!(pending.replay_target_block, replay_target_block);

        cancel.cancel();
    }

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_worker_rejects_bootstrap_when_actor_state_read_fails() {
    let root_dir = temp_db_root("wallet-reset-actor-state-read-fails");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    cache_store.fail_next_actor_state();
    let mut cfg = wallet_config();
    cfg.cache_store = Some(cache_store);
    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let public_data_plane = test_public_data_plane(&db);

    let result = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),

            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: backfill_tx,
            public_data_plane: public_data_plane.clone(),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        cfg,
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        vec![test_wallet_utxo(105, 7)],
        120,
    )
    .await;

    assert!(matches!(
        result,
        Err(ChainError::WalletCache(WalletCacheError::Crypto))
    ));
    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn dropping_prepared_wallet_worker_retires_unregistered_actor() {
    let root_dir = temp_db_root("wallet-prepared-registration-cancelled");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let prepared = prepare_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),

            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: backfill_tx,
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        0,
    )
    .await
    .expect("prepare wallet worker");
    let handle = prepared.handle().clone();
    let retained_observation = handle.subscribe_observation();
    assert_eq!(handle.lifecycle(), WalletActorLifecycle::Prepared);
    assert!(matches!(
        retained_observation.borrow().view(),
        WalletViewState::Current(_)
    ));
    assert_eq!(
        retained_observation.borrow().readiness(),
        &WalletReadiness::Syncing
    );

    drop(prepared);

    assert_eq!(handle.lifecycle(), WalletActorLifecycle::Retired);
    assert!(!handle.is_current_actor());
    assert!(cancel.is_cancelled());
    assert_eq!(
        retained_observation.borrow().view(),
        &WalletViewState::Inactive {
            reason: WalletInactiveReason::Retired,
            reset_generation: 0,
        }
    );
    assert_eq!(
        retained_observation.borrow().readiness(),
        &WalletReadiness::Shutdown
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_worker_publishes_shutdown_readiness_on_cancel() {
    let root_dir = temp_db_root("wallet-shutdown-readiness");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cfg = wallet_config();
    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),

            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: backfill_tx,
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        cfg,
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        0,
    )
    .await
    .expect("spawn wallet worker");
    let mut readiness_rx = handle.subscribe_observation();

    cancel.cancel();

    tokio::time::timeout(Duration::from_secs(1), async {
        while readiness_rx.borrow().readiness() != &WalletReadiness::Shutdown {
            readiness_rx
                .changed()
                .await
                .expect("shutdown readiness should be published before channel closes");
        }
    })
    .await
    .expect("shutdown readiness published");
    let observation = readiness_rx.borrow().clone();
    assert_eq!(observation.readiness(), &WalletReadiness::Shutdown);
    assert_eq!(
        observation.view(),
        &WalletViewState::Inactive {
            reason: WalletInactiveReason::Shutdown,
            reset_generation: 0,
        }
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn inner_wallet_actor_panic_publishes_coherent_terminal_observation() {
    let root_dir = temp_db_root("wallet-inner-panic-observation");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),

            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: backfill_tx.clone(),
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel,
        Vec::new(),
        0,
    )
    .await
    .expect("spawn wallet worker");
    let mut observation_rx = handle.subscribe_observation();

    backfill_tx
        .send(BackfillEvent::PanicForTest)
        .await
        .expect("deliver actor panic trigger");
    tokio::time::timeout(Duration::from_secs(1), async {
        while observation_rx.borrow().readiness() != &WalletReadiness::Shutdown {
            observation_rx
                .changed()
                .await
                .expect("panic fallback publishes before closure");
        }
    })
    .await
    .expect("panic fallback observation");

    let observation = observation_rx.borrow().clone();
    assert_eq!(observation.readiness(), &WalletReadiness::Shutdown);
    assert!(matches!(
        observation.view(),
        WalletViewState::Inactive {
            reason: WalletInactiveReason::Shutdown,
            ..
        }
    ));

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_actor_panic_aborts_tracked_poi_jobs_before_supervisor_completes() {
    let root_dir = temp_db_root("wallet-panic-aborts-tracked-poi-jobs");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let mut prepared = prepare_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),
            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: backfill_tx.clone(),
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel,
        Vec::new(),
        0,
    )
    .await
    .expect("prepare wallet worker");
    let supervisor = prepared.take_worker();
    let _handle = prepared.activate().expect("activate wallet worker");

    let sentinel = Arc::new(());
    let job_sentinel = Arc::downgrade(&sentinel);
    let (started_tx, started_rx) = oneshot::channel();
    backfill_tx
        .send(BackfillEvent::HoldTrackedPoiJobForTest {
            sentinel,
            started: started_tx,
        })
        .await
        .expect("deliver tracked job trigger");
    tokio::time::timeout(Duration::from_secs(1), started_rx)
        .await
        .expect("tracked job starts")
        .expect("tracked job start signal");
    assert!(job_sentinel.upgrade().is_some(), "tracked job is running");

    backfill_tx
        .send(BackfillEvent::PanicForTest)
        .await
        .expect("deliver actor panic trigger");
    tokio::time::timeout(Duration::from_secs(2), supervisor)
        .await
        .expect("supervisor completes after the actor panic")
        .expect("supervisor task");

    assert!(
        job_sentinel.upgrade().is_none(),
        "the supervisor aborts and awaits tracked jobs before it completes"
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_retire_actor_does_not_wait_on_authority_lock() {
    let root_dir = temp_db_root("wallet-retire-without-authority-lock");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),

            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: backfill_tx,
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        0,
    )
    .await
    .expect("spawn wallet worker");

    let lock = Arc::clone(&handle.authority_lock);
    let held = lock.lock_owned().await;
    let retire_handle = handle.clone();
    let retired = tokio::task::spawn_blocking(move || {
        retire_handle.retire_actor();
        retire_handle.lifecycle()
    })
    .await
    .expect("retire task");
    assert_eq!(retired, WalletActorLifecycle::Retired);
    assert!(!handle.is_current_actor());
    drop(held);

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_reset_rejects_retired_actor_without_side_effects() {
    let root_dir = temp_db_root("wallet-reset-retired-actor");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    let mut cfg = wallet_config();
    cfg.cache_store = Some(cache_store.clone());
    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let initial_utxo = test_wallet_utxo(105, 7);
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),

            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: backfill_tx.clone(),
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        cfg,
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        vec![initial_utxo],
        120,
    )
    .await
    .expect("spawn wallet worker");

    assert_eq!(
        send_target(&handle, &backfill_tx, 120, 0).await,
        WalletBackfillFinishResult::Ready { committed_to: 120 }
    );
    let rev_before_reset = *handle.rev_rx.borrow();
    let store_calls_before_reset = cache_store.state().store_calls;
    handle.retire_actor();
    assert_eq!(handle.lifecycle(), WalletActorLifecycle::Retired);

    assert_eq!(
        send_reset(&backfill_tx, 1, 100).await,
        WalletBackfillResetResult::Rejected {
            committed_to: 120,
            reason: WalletBackfillRejectReason::Shutdown,
        }
    );

    assert_eq!(handle.authority_reset_generation(), 0);
    assert_eq!(handle.last_scanned(), None);
    assert_eq!(handle.last_scanned_raw(), 120);
    assert_eq!(
        handle.view_state().inactive_reason(),
        Some(WalletInactiveReason::Retired)
    );
    assert_eq!(handle.readiness(), WalletReadiness::Shutdown);
    assert_eq!(*handle.rev_rx.borrow(), rev_before_reset);
    let snapshot = handle.utxos.read().await;
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].utxo.source.block_number, 105);
    assert_eq!(cache_store.state().store_calls, store_calls_before_reset);

    cancel.cancel();
    drop(snapshot);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
