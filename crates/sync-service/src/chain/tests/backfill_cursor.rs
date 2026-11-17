use super::*;

#[test]
fn wallet_backfill_accepted_progress_resets_persistence_retry() {
    let now = std::time::Instant::now();
    let mut cursor = WalletBackfill::new(
        100,
        120,
        false,
        100,
        None,
        test_backfill_driver(mpsc::channel(1).0, 1, 1),
        now,
    );

    cursor.retry_after_rejected_apply(120);
    cursor.defer_persistence_retry(now, Duration::from_millis(10));

    assert_eq!(cursor.from_block, 100);
    assert_eq!(cursor.last_advanced_at, now);
    assert!(!cursor.is_runnable(now + Duration::from_millis(999)));
    assert!(cursor.is_runnable(now + Duration::from_secs(1)));

    cursor.mark_already_covered(121, now + Duration::from_secs(1));
    assert!(cursor.persistence_retry_at().is_none());
    assert!(cursor.is_runnable(now + Duration::from_secs(1)));
    cursor.defer_persistence_retry(now + Duration::from_secs(1), Duration::from_millis(10));
    assert!(!cursor.is_runnable(now + Duration::from_millis(1_999)));
    assert!(cursor.is_runnable(now + Duration::from_secs(2)));
    cursor.mark_progress(101, now + Duration::from_secs(1));
    assert!(cursor.persistence_retry_at().is_none());
    assert!(cursor.is_runnable(now + Duration::from_secs(1)));
}

#[test]
fn wallet_backfill_retryable_finish_rewinds_cursor_instead_of_removing() {
    let now = std::time::Instant::now();
    let mut cursor = WalletBackfill::new(
        121,
        120,
        false,
        100,
        None,
        test_backfill_driver(mpsc::channel(1).0, 1, 1),
        now,
    );
    let result = WalletBackfillFinishResult::Rejected {
        committed_to: 120,
        reason: WalletBackfillRejectReason::PersistenceFailed,
    };

    assert!(!wallet_finish_result_removes_cursor(&result));
    cursor.retry_after_rejected_finish(result.committed_to());
    cursor.defer_persistence_retry(now, Duration::from_secs(1));

    assert_eq!(cursor.from_block, 100);
    assert!(!cursor.is_runnable(now));
    assert!(cursor.is_runnable(now + Duration::from_secs(1)));
}

#[tokio::test]
async fn ready_tail_persistence_failure_queues_active_driver_for_retry() {
    let result = WalletBackfillFinishResult::Rejected {
        committed_to: 120,
        reason: WalletBackfillRejectReason::PersistenceFailed,
    };
    let token = test_sync_token(1, 1);
    let (event_sender, _event_receiver) = mpsc::channel(1);
    let (liveness, mut disposition) = oneshot::channel();
    let driver =
        WalletBackfillGrant::for_actor_accepted_job(token, event_sender, liveness).activate();

    let request = wallet_finish_retry_request("test".to_string(), 120, false, 100, &result, driver);
    assert!(matches!(
        disposition.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));

    let BackfillRequest::Add {
        from_block,
        to_block,
        progress_start_block,
        driver,
        ..
    } = request
    else {
        panic!("ready-tail finish retry must retain an active driver");
    };
    assert_eq!(from_block, 121);
    assert_eq!(to_block, 120);
    assert_eq!(progress_start_block, 100);
    assert_eq!(driver.token(), token);

    tokio::join!(
        async {
            driver.retire("test").await;
        },
        async {
            let signal = disposition.await.expect("driver retirement disposition");
            assert_eq!(
                signal.disposition,
                WalletBackfillOwnerDisposition::BenignRetirement
            );
            signal
                .acknowledgement
                .expect("explicit retirement requests acknowledgement")
                .send(())
                .expect("driver waits for retirement acknowledgement");
        }
    );
}

#[test]
fn wallet_backfill_terminal_finish_results_remove_cursor() {
    assert!(wallet_finish_result_removes_cursor(
        &WalletBackfillFinishResult::Ready { committed_to: 120 }
    ));
    assert!(wallet_finish_result_removes_cursor(
        &WalletBackfillFinishResult::Rejected {
            committed_to: 120,
            reason: WalletBackfillRejectReason::Shutdown,
        }
    ));
    assert!(wallet_finish_result_removes_cursor(
        &WalletBackfillFinishResult::Rejected {
            committed_to: 120,
            reason: WalletBackfillRejectReason::StaleGeneration {
                expected: 2,
                actual: 1,
            },
        }
    ));
}

#[tokio::test]
async fn active_backfill_drains_reset_replacement_request() {
    let (request_tx, mut request_rx) = mpsc::channel(4);
    let (old_sender, old_receiver) = mpsc::channel(1);
    let (new_sender, _new_receiver) = mpsc::channel(1);
    let mut cursor = Some(WalletBackfillSlot {
        cache_key: "test".to_string(),
        cursor: WalletBackfill::new(
            100,
            1_000,
            true,
            100,
            None,
            test_backfill_driver(old_sender, 0, 1),
            std::time::Instant::now(),
        ),
    });

    request_tx
        .try_send(BackfillRequest::Add {
            cache_key: "test".to_string(),
            from_block: 80,
            to_block: 150,
            follow_safe_head: true,
            progress_start_block: 80,
            acquisition_range: None,
            startup_warm_range: None,
            driver: test_backfill_driver(new_sender, 1, 2),
        })
        .expect("queue reset replacement backfill");

    drain_pending_backfill_requests(&mut request_rx, &mut cursor, Some(("test", 1))).await;

    let cursor = &cursor.expect("cursor retained").cursor;
    assert_eq!(cursor.from_block, 80);
    assert_eq!(cursor.target_block, 150);
    assert!(cursor.follow_safe_head);
    assert_eq!(cursor.progress_start_block, 80);
    assert_eq!(cursor.driver.token().reset_generation(), 1);
    assert!(old_receiver.is_empty());
}

#[tokio::test]
async fn stale_actor_backfill_remove_cannot_remove_replacement_cursor() {
    let (request_tx, mut request_rx) = mpsc::channel(1);
    let (event_tx, _event_rx) = mpsc::channel(1);
    let replacement_token = WalletSyncToken::for_test(1, 2, 0, 1);
    let (remove_response, remove_ack) = oneshot::channel();
    let mut cursor = Some(WalletBackfillSlot {
        cache_key: "test".to_string(),
        cursor: WalletBackfill::new(
            100,
            120,
            false,
            100,
            None,
            WalletBackfillDriver::from_token(replacement_token, event_tx),
            std::time::Instant::now(),
        ),
    });
    request_tx
        .try_send(BackfillRequest::Remove {
            cache_key: "test".to_string(),
            actor_id: 1,
            response: remove_response,
        })
        .expect("queue stale actor removal");

    drain_pending_backfill_requests(&mut request_rx, &mut cursor, None).await;
    remove_ack.await.expect("stale removal acknowledged");

    assert_eq!(
        cursor
            .as_ref()
            .expect("replacement cursor remains")
            .cursor
            .driver
            .token(),
        replacement_token,
    );
}

#[tokio::test]
async fn active_backfill_ignores_stale_replacement_request() {
    let (request_tx, mut request_rx) = mpsc::channel(4);
    let (active_sender, active_receiver) = mpsc::channel(1);
    let (stale_sender, stale_receiver) = mpsc::channel(1);
    let mut cursor = Some(WalletBackfillSlot {
        cache_key: "test".to_string(),
        cursor: WalletBackfill::new(
            100,
            1_000,
            true,
            100,
            None,
            test_backfill_driver(active_sender, 1, 2),
            std::time::Instant::now(),
        ),
    });

    request_tx
        .try_send(BackfillRequest::Add {
            cache_key: "other-wallet".to_string(),
            from_block: 80,
            to_block: 150,
            follow_safe_head: true,
            progress_start_block: 80,
            acquisition_range: None,
            startup_warm_range: None,
            driver: test_backfill_driver(stale_sender, 0, 1),
        })
        .expect("queue stale replacement backfill");

    drain_pending_backfill_requests(&mut request_rx, &mut cursor, Some(("test", 1))).await;

    let cursor = &cursor.expect("active cursor retained").cursor;
    assert_eq!(cursor.from_block, 100);
    assert_eq!(cursor.target_block, 1_000);
    assert_eq!(cursor.driver.token().reset_generation(), 1);
    assert_eq!(cursor.driver.token().job_id(), 2);
    assert!(stale_receiver.is_empty());
    assert!(active_receiver.is_empty());
}

#[tokio::test]
async fn active_backfill_ignores_same_key_stale_token_request() {
    let (request_tx, mut request_rx) = mpsc::channel(2);
    let (active_sender, _active_receiver) = mpsc::channel(1);
    let (stale_sender, _stale_receiver) = mpsc::channel(1);
    let (stale_driver, stale_retirement) =
        test_backfill_driver_with_retirement_signal(stale_sender, 1, 0, 1);
    let mut cursor = Some(WalletBackfillSlot {
        cache_key: "test".to_string(),
        cursor: WalletBackfill::new(
            100,
            1_000,
            true,
            100,
            None,
            test_backfill_driver_for_actor(active_sender, 1, 0, 2),
            std::time::Instant::now(),
        ),
    });
    request_tx
        .try_send(BackfillRequest::Add {
            cache_key: "test".to_string(),
            from_block: 80,
            to_block: 150,
            follow_safe_head: true,
            progress_start_block: 80,
            acquisition_range: None,
            startup_warm_range: None,
            driver: stale_driver,
        })
        .expect("queue same-key stale request");

    let draining = tokio::spawn(async move {
        drain_pending_backfill_requests(&mut request_rx, &mut cursor, Some(("test", 1))).await;
        cursor
    });
    let signal = tokio::time::timeout(Duration::from_secs(1), stale_retirement)
        .await
        .expect("same-key stale driver retirement is signalled")
        .expect("same-key stale driver retirement signal arrives");
    assert_eq!(
        signal.disposition,
        WalletBackfillOwnerDisposition::BenignRetirement
    );
    if let Some(acknowledgement) = signal.acknowledgement {
        acknowledgement
            .send(())
            .expect("acknowledge same-key stale driver retirement");
    }
    let cursor = draining.await.expect("backfill admission task joins");
    let cursor = &cursor.expect("active cursor retained").cursor;
    assert_eq!(cursor.from_block, 100);
    assert_eq!(cursor.target_block, 1_000);
    assert_eq!(cursor.driver.token().job_id(), 2);
}

#[tokio::test]
async fn old_backfill_add_after_remove_cannot_replace_successor() {
    let (request_tx, mut request_rx) = mpsc::channel(4);
    let (old_sender, _old_receiver) = mpsc::channel(1);
    let (stale_sender, _stale_receiver) = mpsc::channel(1);
    let (successor_sender, _successor_receiver) = mpsc::channel(1);
    let (stale_driver, stale_retirement) =
        test_backfill_driver_with_retirement_signal(stale_sender, 1, 1, 2);
    let mut cursor = Some(WalletBackfillSlot {
        cache_key: "test".to_string(),
        cursor: WalletBackfill::new(
            100,
            120,
            false,
            100,
            None,
            test_backfill_driver_for_actor(old_sender, 1, 1, 1),
            std::time::Instant::now(),
        ),
    });
    request_tx
        .try_send(BackfillRequest::Remove {
            cache_key: "test".to_string(),
            actor_id: 1,
            response: oneshot::channel().0,
        })
        .expect("queue old removal");
    request_tx
        .try_send(BackfillRequest::Add {
            cache_key: "test".to_string(),
            from_block: 200,
            to_block: 220,
            follow_safe_head: false,
            progress_start_block: 200,
            acquisition_range: None,
            startup_warm_range: None,
            driver: test_backfill_driver_for_actor(successor_sender, 2, 1, 3),
        })
        .expect("queue successor add");
    request_tx
        .try_send(BackfillRequest::Add {
            cache_key: "test".to_string(),
            from_block: 150,
            to_block: 170,
            follow_safe_head: false,
            progress_start_block: 150,
            acquisition_range: None,
            startup_warm_range: None,
            driver: stale_driver,
        })
        .expect("queue stale old add");

    let draining = tokio::spawn(async move {
        drain_pending_backfill_requests(&mut request_rx, &mut cursor, Some(("test", 2))).await;
        cursor
    });
    let signal = tokio::time::timeout(Duration::from_secs(1), stale_retirement)
        .await
        .expect("stale old driver retirement is signalled")
        .expect("stale old driver retirement signal arrives");
    assert_eq!(
        signal.disposition,
        WalletBackfillOwnerDisposition::BenignRetirement
    );
    if let Some(acknowledgement) = signal.acknowledgement {
        acknowledgement
            .send(())
            .expect("acknowledge stale old driver retirement");
    }
    let cursor = draining.await.expect("backfill admission task joins");

    let cursor = &cursor.expect("successor cursor installed").cursor;
    assert_eq!(cursor.from_block, 200);
    assert_eq!(cursor.target_block, 220);
    assert_eq!(cursor.driver.token().actor_id(), 2);
}

#[test]
fn wallet_tail_fallback_threshold_uses_ten_blocks_or_45_seconds() {
    assert_eq!(
        wallet_tail_fallback_lag_threshold_blocks(Duration::from_secs(12)),
        10
    );
    assert_eq!(
        wallet_tail_fallback_lag_threshold_blocks(Duration::from_millis(250)),
        180
    );
}

#[test]
fn wallet_tail_fallback_requires_lag_stall_and_cooldown() {
    let now = std::time::Instant::now();
    let (sender, _receiver) = mpsc::channel(1);
    let mut cursor = WalletBackfill::new(
        100,
        279,
        true,
        100,
        None,
        test_backfill_driver(sender, 0, 1),
        now.checked_sub(std::time::Duration::from_secs(20))
            .expect("test instant supports 20 second subtraction"),
    );

    assert!(!cursor.should_try_indexed_tail_fallback(
        Duration::from_millis(250),
        25_000,
        now,
        std::time::Duration::from_secs(15),
        std::time::Duration::from_mins(1),
    ));
    cursor.target_block = 280;
    assert!(cursor.should_try_indexed_tail_fallback(
        Duration::from_millis(250),
        25_000,
        now,
        std::time::Duration::from_secs(15),
        std::time::Duration::from_mins(1),
    ));

    cursor.mark_indexed_tail_attempt(now);
    assert!(!cursor.should_try_indexed_tail_fallback(
        Duration::from_millis(250),
        25_000,
        now + std::time::Duration::from_secs(30),
        std::time::Duration::from_secs(15),
        std::time::Duration::from_mins(1),
    ));
    assert!(cursor.should_try_indexed_tail_fallback(
        Duration::from_millis(250),
        25_000,
        now + std::time::Duration::from_mins(1),
        std::time::Duration::from_secs(15),
        std::time::Duration::from_mins(1),
    ));

    cursor.mark_progress(150, now + std::time::Duration::from_mins(1));
    cursor.target_block = 331;
    assert!(!cursor.should_try_indexed_tail_fallback(
        Duration::from_millis(250),
        25_000,
        now + std::time::Duration::from_secs(70),
        std::time::Duration::from_secs(15),
        std::time::Duration::from_mins(1),
    ));
}

#[test]
fn wallet_tail_fallback_retries_while_rpc_backfill_crawls_far_behind() {
    let now = std::time::Instant::now();
    let block_time = Duration::from_millis(250);
    let rpc_crawl_lag_blocks = 50 * 500;
    let min_stall = std::time::Duration::from_secs(15);
    let cooldown = std::time::Duration::from_mins(1);
    let (sender, _receiver) = mpsc::channel(1);
    let mut cursor = WalletBackfill::new(
        100,
        200 + rpc_crawl_lag_blocks,
        true,
        100,
        None,
        test_backfill_driver(sender, 0, 1),
        now,
    );

    // Steady progress keeps the stall rule quiet; the far-behind rule waits
    // for the cooldown since the backfill started.
    let at = now + std::time::Duration::from_secs(59);
    cursor.mark_progress(150, at);
    assert!(!cursor.should_try_indexed_tail_fallback(
        block_time,
        rpc_crawl_lag_blocks,
        at,
        min_stall,
        cooldown,
    ));
    let at = now + std::time::Duration::from_mins(1);
    cursor.mark_progress(199, at);
    assert!(cursor.should_try_indexed_tail_fallback(
        block_time,
        rpc_crawl_lag_blocks,
        at,
        min_stall,
        cooldown,
    ));
    cursor.mark_progress(201, at);
    assert!(!cursor.should_try_indexed_tail_fallback(
        block_time,
        rpc_crawl_lag_blocks,
        at,
        min_stall,
        cooldown,
    ));

    cursor.target_block += rpc_crawl_lag_blocks;
    cursor.mark_indexed_tail_attempt(at);
    let at = now + std::time::Duration::from_secs(119);
    cursor.mark_progress(250, at);
    assert!(!cursor.should_try_indexed_tail_fallback(
        block_time,
        rpc_crawl_lag_blocks,
        at,
        min_stall,
        cooldown,
    ));
    let at = now + std::time::Duration::from_mins(2);
    cursor.mark_progress(300, at);
    assert!(cursor.should_try_indexed_tail_fallback(
        block_time,
        rpc_crawl_lag_blocks,
        at,
        min_stall,
        cooldown,
    ));
}

#[test]
fn ready_wallet_tail_fallback_state_tracks_progress_and_cooldown() {
    let now = std::time::Instant::now();
    let mut state = WalletTailFallbackState::new(
        100,
        now.checked_sub(std::time::Duration::from_secs(20))
            .expect("test instant supports 20 second subtraction"),
    );

    assert!(!state.should_try_indexed_tail_fallback(
        Duration::from_millis(250),
        101,
        280,
        now,
        std::time::Duration::from_secs(15),
        std::time::Duration::from_mins(1),
    ));
    assert!(state.should_try_indexed_tail_fallback(
        Duration::from_millis(250),
        101,
        281,
        now,
        std::time::Duration::from_secs(15),
        std::time::Duration::from_mins(1),
    ));

    state.mark_indexed_tail_attempt(now);
    assert!(!state.should_try_indexed_tail_fallback(
        Duration::from_millis(250),
        101,
        281,
        now + std::time::Duration::from_secs(30),
        std::time::Duration::from_secs(15),
        std::time::Duration::from_mins(1),
    ));

    state.update_last_scanned(130, now + std::time::Duration::from_secs(30));
    assert!(!state.should_try_indexed_tail_fallback(
        Duration::from_millis(250),
        131,
        311,
        now + std::time::Duration::from_secs(40),
        std::time::Duration::from_secs(15),
        std::time::Duration::from_mins(1),
    ));

    assert!(state.should_try_indexed_tail_fallback(
        Duration::from_millis(250),
        131,
        311,
        now + std::time::Duration::from_secs(90),
        std::time::Duration::from_secs(15),
        std::time::Duration::from_mins(1),
    ));
}

#[tokio::test]
async fn backfill_slot_rejects_different_wallet_without_changing_active_target() {
    let root_dir = temp_db_root("backfill-slot-different-wallet");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc = JsonRpcServer::spawn(Vec::new());
    let service = test_chain_service(
        Arc::clone(&db),
        test_chain_config(
            &scope,
            Arc::new(QueryRpcPool::new(
                vec![rpc.url.clone()],
                Duration::from_secs(1),
            )),
            None,
        ),
        ChainPublicDataPlane::new(
            Arc::clone(&db),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ),
    );
    let active = install_test_backfill_actor(&service, &scope, rpc.url.clone(), "wallet-a").await;
    let active_cache_key = active.cache_key.as_str().to_string();
    let active_actor_id = active.actor_id();
    let (active_sender, _active_receiver) = mpsc::channel(1);
    let (other_sender, _other_receiver) = mpsc::channel(1);
    let (other_driver, other_retirement) =
        test_backfill_driver_with_retirement_signal(other_sender, 2, 0, SYNTHETIC_BACKFILL_JOB_ID);
    let mut cursor = Some(WalletBackfillSlot {
        cache_key: active_cache_key.clone(),
        cursor: WalletBackfill::new(
            100,
            199,
            false,
            100,
            None,
            test_backfill_driver_for_actor(
                active_sender,
                active_actor_id,
                0,
                SYNTHETIC_BACKFILL_JOB_ID,
            ),
            std::time::Instant::now(),
        ),
    });
    let (request_tx, mut request_rx) = mpsc::channel(1);
    request_tx
        .send(BackfillRequest::Add {
            cache_key: test_cache_key("wallet-b").as_str().to_string(),
            from_block: 120,
            to_block: 130,
            follow_safe_head: false,
            progress_start_block: 120,
            acquisition_range: None,
            startup_warm_range: None,
            driver: other_driver,
        })
        .await
        .expect("queue different-wallet request");
    assert_test_backfill_actor_current(&service, &active).await;

    let active_cache_key_for_drain = active_cache_key.clone();
    let draining = tokio::spawn(async move {
        drain_pending_backfill_requests(
            &mut request_rx,
            &mut cursor,
            Some((active_cache_key_for_drain.as_str(), active_actor_id)),
        )
        .await;
        cursor
    });
    let signal = tokio::time::timeout(Duration::from_secs(1), other_retirement)
        .await
        .expect("different-wallet driver retirement is signalled")
        .expect("different-wallet driver retirement signal arrives");
    assert_eq!(
        signal.disposition,
        WalletBackfillOwnerDisposition::BenignRetirement
    );
    if let Some(acknowledgement) = signal.acknowledgement {
        acknowledgement
            .send(())
            .expect("acknowledge different-wallet driver retirement");
    }
    let cursor = draining.await.expect("backfill admission task joins");
    let cursor = &cursor.expect("active cursor retained").cursor;
    assert_eq!(cursor.from_block, 100);
    assert_eq!(cursor.target_block, 199);
    assert_eq!(cursor.driver.token().actor_id(), active_actor_id);
    assert_eq!(cursor.driver.token().job_id(), SYNTHETIC_BACKFILL_JOB_ID);

    service.unregister_wallet(&active).await;
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_backfill_loop_rebases_non_contiguous_cursor_to_actor_progress() {
    let root_dir = temp_db_root("wallet-backfill-non-contiguous-rebase");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc = JsonRpcServer::spawn(vec![
        serde_json::json!([]),
        rpc_block(105, 1_700_000_105, 0x11),
        serde_json::json!([]),
        rpc_block(110, 1_700_000_110, 0x22),
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, Arc::clone(&rpcs), None);
    chain.sync.block_range = 100;
    chain.sync.poll_interval = Duration::from_millis(1);
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let (service, backfill_request_rx) = test_chain_service_with_backfill(
        Arc::clone(&db),
        chain,
        public_data_plane,
        test_proxy_poi_policy(),
    );
    let backfill_request_tx = service.backfill_tx.clone();
    let registered = install_test_backfill_actor(&service, &scope, rpc.url.clone(), "test").await;
    let cache_key = registered.cache_key.as_str().to_string();
    let (_safe_head_tx, safe_head_rx) = watch::channel(110);
    let cancel = CancellationToken::new();
    spawn_backfill_loop(
        Arc::clone(&service),
        backfill_request_rx,
        Arc::clone(&rpcs),
        None,
        safe_head_rx,
        cancel.clone(),
    );

    let (wallet_tx, mut wallet_rx) = mpsc::channel(4);
    let actor = tokio::spawn(async move {
        let Some(BackfillEvent::Apply {
            apply, response, ..
        }) = wallet_rx.recv().await
        else {
            panic!("stale wallet backfill apply expected");
        };
        assert_eq!((apply.from_block, apply.to_block), (100, 110));
        response
            .send(WalletBackfillApplyResult::Rejected {
                committed_to: 105,
                reason: WalletBackfillRejectReason::NonContiguous {
                    expected_from: 106,
                    actual_from: 100,
                },
            })
            .expect("reject stale wallet backfill apply");

        let Some(BackfillEvent::Apply {
            apply, response, ..
        }) = wallet_rx.recv().await
        else {
            panic!("rebased wallet backfill apply expected");
        };
        assert_eq!((apply.from_block, apply.to_block), (106, 110));
        response
            .send(WalletBackfillApplyResult::Committed { committed_to: 110 })
            .expect("commit rebased wallet backfill apply");

        let Some(BackfillEvent::Finish {
            target_block,
            response,
            ..
        }) = wallet_rx.recv().await
        else {
            panic!("wallet backfill finish expected");
        };
        assert_eq!(target_block, 110);
        response
            .send(WalletBackfillFinishResult::Ready { committed_to: 110 })
            .expect("finish rebased wallet backfill");
    });

    assert_test_backfill_actor_current(&service, &registered).await;
    backfill_request_tx
        .send(BackfillRequest::add(
            &cache_key,
            100,
            110,
            false,
            100,
            test_backfill_driver_for_actor(
                wallet_tx,
                registered.actor_id(),
                0,
                SYNTHETIC_BACKFILL_JOB_ID,
            ),
        ))
        .await
        .expect("send stale wallet backfill request");

    tokio::time::timeout(Duration::from_secs(2), actor)
        .await
        .expect("rebased wallet backfill completed")
        .expect("actor response task completed");

    service.unregister_wallet(&registered).await;
    cancel.cancel();
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_backfill_loop_delivers_tail_before_warming_startup_gap_once() {
    let root_dir = temp_db_root("wallet-backfill-cached-suffix");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc = JsonRpcServer::spawn(vec![
        serde_json::json!([]),
        rpc_block(110, 1_700_000_110, 0x22),
        serde_json::json!("0x6e"),
        serde_json::json!([rpc_nullifiers_log(scope.railgun_contract, 103)]),
        rpc_block(103, 1_700_000_103, 0x13),
        rpc_block(105, 1_700_000_105, 0x11),
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, Arc::clone(&rpcs), None);
    chain.sync.block_range = 100;
    chain.sync.poll_interval = Duration::from_millis(1);
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    public_data_plane
        .record_recent_public_scan_rows(PublicScanRows {
            range: PublicScanRange::new(106, 110),
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
    for block_number in 200..204 {
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
            .expect("seed newer row page");
    }
    let (service, backfill_request_rx) = test_chain_service_with_backfill(
        Arc::clone(&db),
        chain,
        public_data_plane,
        test_proxy_poi_policy(),
    );
    let backfill_request_tx = service.backfill_tx.clone();
    let registered = install_test_backfill_actor(&service, &scope, rpc.url.clone(), "test").await;
    let cache_key = registered.cache_key.as_str().to_string();
    let (_safe_head_tx, safe_head_rx) = watch::channel(110);
    let cancel = CancellationToken::new();
    spawn_backfill_loop(
        Arc::clone(&service),
        backfill_request_rx,
        Arc::clone(&rpcs),
        None,
        safe_head_rx,
        cancel.clone(),
    );

    let (wallet_tx, mut wallet_rx) = mpsc::channel(4);
    let actor = tokio::spawn(async move {
        let Some(BackfillEvent::Apply {
            apply, response, ..
        }) = wallet_rx.recv().await
        else {
            panic!("delivery apply expected");
        };
        assert_eq!((apply.from_block, apply.to_block), (106, 110));
        assert_eq!(apply.rows.source, PublicScanSource::Rpc);
        response
            .send(WalletBackfillApplyResult::Committed { committed_to: 110 })
            .expect("commit delivery apply");

        let Some(BackfillEvent::Finish {
            target_block,
            response,
            ..
        }) = wallet_rx.recv().await
        else {
            panic!("wallet backfill finish expected");
        };
        assert_eq!(target_block, 110);
        response
            .send(WalletBackfillFinishResult::Ready { committed_to: 110 })
            .expect("finish cached suffix backfill");
    });

    assert_test_backfill_actor_current(&service, &registered).await;
    backfill_request_tx
        .send(
            BackfillRequest::add_with_acquisition(
                &cache_key,
                106,
                110,
                false,
                106,
                (106, 110),
                test_backfill_driver_for_actor(
                    wallet_tx,
                    registered.actor_id(),
                    0,
                    SYNTHETIC_BACKFILL_JOB_ID,
                ),
            )
            .with_startup_warm_range(Some((100, 105))),
        )
        .await
        .expect("send wallet backfill request");
    tokio::time::timeout(Duration::from_secs(2), actor)
        .await
        .expect("cached suffix backfill completed")
        .expect("actor response task completed");

    let mut bodies = Vec::new();
    yield_until("delivery tail and startup gap warm", || {
        bodies.extend(rpc.drain_request_bodies());
        bodies.len() == 6 && !service.public_data_plane.public_window_warm_running()
    })
    .await;
    assert_eq!(
        get_logs_ranges(&bodies),
        vec![(106, 110), (100, 105)],
        "the tail is delivered first and the gap is warmed exactly once"
    );
    assert!(
        service
            .public_data_plane
            .cached_wallet_scan_exact(100, 110)
            .await
            .is_some(),
        "delivery and warming together leave the window replayable"
    );

    service.unregister_wallet(&registered).await;
    cancel.cancel();
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_backfill_loop_reuses_cached_prefix_before_fetching_delivery_tail() {
    let root_dir = temp_db_root("wallet-backfill-cached-prefix");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc = JsonRpcServer::spawn(vec![
        serde_json::json!([]),
        rpc_block(110, 1_700_000_110, 0x22),
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, Arc::clone(&rpcs), None);
    chain.sync.block_range = 100;
    chain.sync.poll_interval = Duration::from_millis(1);
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    public_data_plane
        .record_recent_public_scan_rows(PublicScanRows {
            range: PublicScanRange::new(100, 105),
            source: PublicScanSource::Rpc,
            to_block_hash: Some([0x11; 32]),
            rows: WalletScanInputRows::default(),
            epoch: public_data_plane.current_epoch(),
        })
        .await
        .expect("seed cached acquisition prefix");
    let (service, backfill_request_rx) = test_chain_service_with_backfill(
        Arc::clone(&db),
        chain,
        public_data_plane,
        test_proxy_poi_policy(),
    );
    let backfill_request_tx = service.backfill_tx.clone();
    let registered = install_test_backfill_actor(&service, &scope, rpc.url.clone(), "test").await;
    let cache_key = registered.cache_key.as_str().to_string();
    let (_safe_head_tx, safe_head_rx) = watch::channel(110);
    let cancel = CancellationToken::new();
    spawn_backfill_loop(
        Arc::clone(&service),
        backfill_request_rx,
        Arc::clone(&rpcs),
        None,
        safe_head_rx,
        cancel.clone(),
    );

    let (wallet_tx, mut wallet_rx) = mpsc::channel(4);
    let actor = tokio::spawn(async move {
        let Some(BackfillEvent::Apply {
            apply, response, ..
        }) = wallet_rx.recv().await
        else {
            panic!("delivery tail apply expected");
        };
        assert_eq!((apply.from_block, apply.to_block), (106, 110));
        response
            .send(WalletBackfillApplyResult::Committed { committed_to: 110 })
            .expect("commit delivery tail");

        let Some(BackfillEvent::Finish {
            target_block,
            response,
            ..
        }) = wallet_rx.recv().await
        else {
            panic!("wallet backfill finish expected");
        };
        assert_eq!(target_block, 110);
        response
            .send(WalletBackfillFinishResult::Ready { committed_to: 110 })
            .expect("finish cached-prefix backfill");
    });

    assert_test_backfill_actor_current(&service, &registered).await;
    backfill_request_tx
        .send(BackfillRequest::add_with_acquisition(
            &cache_key,
            106,
            110,
            false,
            106,
            (100, 110),
            test_backfill_driver_for_actor(
                wallet_tx,
                registered.actor_id(),
                0,
                SYNTHETIC_BACKFILL_JOB_ID,
            ),
        ))
        .await
        .expect("send wallet backfill request");
    tokio::time::timeout(Duration::from_secs(2), actor)
        .await
        .expect("cached-prefix backfill completed")
        .expect("actor response task completed");

    let requests = (0..2)
        .map(|_| {
            rpc.requests
                .recv_timeout(Duration::from_secs(1))
                .expect("RPC delivery-tail request")
        })
        .collect::<Vec<_>>();
    let get_logs = requests
        .iter()
        .find(|request| request.contains("eth_getLogs"))
        .expect("eth_getLogs request");
    assert!(get_logs.contains(r#""fromBlock":"0x6a""#));
    assert!(get_logs.contains(r#""toBlock":"0x6e""#));
    assert!(rpc.requests.try_recv().is_err());
    assert!(
        service
            .public_data_plane
            .cached_wallet_scan_exact(100, 110)
            .await
            .is_some(),
        "successful scheduler acquisition must retain the merged warm window"
    );

    service.unregister_wallet(&registered).await;
    cancel.cancel();
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_backfill_loop_reacquires_prefix_invalidated_before_tail_commit() {
    let root_dir = temp_db_root("wallet-backfill-invalidated-prefix");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let (rpc, blocked_tail) = JsonRpcServer::spawn_with_blocked_response(
        vec![
            serde_json::json!([]),
            rpc_block(110, 1_700_000_110, 0x22),
            serde_json::json!([]),
            rpc_block(110, 1_700_000_110, 0x33),
        ],
        0,
    );
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, Arc::clone(&rpcs), None);
    chain.sync.block_range = 100;
    chain.sync.poll_interval = Duration::from_millis(1);
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    public_data_plane
        .record_recent_public_scan_rows(PublicScanRows {
            range: PublicScanRange::new(100, 105),
            source: PublicScanSource::Rpc,
            to_block_hash: Some([0x11; 32]),
            rows: WalletScanInputRows::default(),
            epoch: public_data_plane.current_epoch(),
        })
        .await
        .expect("seed cached acquisition prefix");
    let (service, backfill_request_rx) = test_chain_service_with_backfill(
        Arc::clone(&db),
        chain,
        public_data_plane.clone(),
        test_proxy_poi_policy(),
    );
    let backfill_request_tx = service.backfill_tx.clone();
    let registered = install_test_backfill_actor(&service, &scope, rpc.url.clone(), "test").await;
    let cache_key = registered.cache_key.as_str().to_string();
    let (_safe_head_tx, safe_head_rx) = watch::channel(110);
    let cancel = CancellationToken::new();
    spawn_backfill_loop(
        Arc::clone(&service),
        backfill_request_rx,
        Arc::clone(&rpcs),
        None,
        safe_head_rx,
        cancel.clone(),
    );

    let (wallet_tx, mut wallet_rx) = mpsc::channel(4);
    let actor = tokio::spawn(async move {
        let Some(BackfillEvent::Apply {
            apply, response, ..
        }) = wallet_rx.recv().await
        else {
            panic!("delivery tail apply expected");
        };
        assert_eq!((apply.from_block, apply.to_block), (106, 110));
        response
            .send(WalletBackfillApplyResult::Committed { committed_to: 110 })
            .expect("commit delivery tail");

        let Some(BackfillEvent::Finish {
            target_block,
            response,
            ..
        }) = wallet_rx.recv().await
        else {
            panic!("wallet backfill finish expected after prefix reacquisition");
        };
        assert_eq!(target_block, 110);
        response
            .send(WalletBackfillFinishResult::Ready { committed_to: 110 })
            .expect("finish reacquired-prefix backfill");
    });

    assert_test_backfill_actor_current(&service, &registered).await;
    backfill_request_tx
        .send(BackfillRequest::add_with_acquisition(
            &cache_key,
            106,
            110,
            false,
            106,
            (100, 110),
            test_backfill_driver_for_actor(
                wallet_tx,
                registered.actor_id(),
                0,
                SYNTHETIC_BACKFILL_JOB_ID,
            ),
        ))
        .await
        .expect("send wallet backfill request");
    let PathServerBlockControl {
        request_started,
        release,
    } = blocked_tail;
    tokio::task::spawn_blocking(move || request_started.recv_timeout(Duration::from_secs(1)))
        .await
        .expect("blocked response wait task")
        .expect("tail request started after cached-prefix decision");
    public_data_plane
        .invalidate_public_scan_coverage_from(100)
        .await;
    release.send(()).expect("release tail response");

    tokio::time::timeout(Duration::from_secs(2), actor)
        .await
        .expect("invalidated-prefix backfill completed")
        .expect("actor response task completed");
    let requests = (0..4)
        .map(|_| {
            rpc.requests
                .recv_timeout(Duration::from_secs(1))
                .expect("RPC acquisition request")
        })
        .collect::<Vec<_>>();
    let get_logs = requests
        .iter()
        .filter(|request| request.contains("eth_getLogs"))
        .collect::<Vec<_>>();
    assert_eq!(get_logs.len(), 2);
    assert!(get_logs[0].contains(r#""fromBlock":"0x6a""#));
    assert!(get_logs[0].contains(r#""toBlock":"0x6e""#));
    assert!(get_logs[1].contains(r#""fromBlock":"0x64""#));
    assert!(get_logs[1].contains(r#""toBlock":"0x6e""#));
    assert!(
        public_data_plane
            .cached_wallet_scan_exact(100, 110)
            .await
            .is_some(),
        "prefix invalidation must force full acquisition restoration before finish"
    );

    service.unregister_wallet(&registered).await;
    cancel.cancel();
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_backfill_loop_reacquires_full_window_after_stale_cached_delivery() {
    let root_dir = temp_db_root("wallet-backfill-stale-acquisition");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc = JsonRpcServer::spawn(vec![
        serde_json::json!([]),
        rpc_block(105, 1_700_000_105, 0x11),
        serde_json::json!([]),
        rpc_block(110, 1_700_000_110, 0x22),
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, Arc::clone(&rpcs), None);
    chain.sync.block_range = 100;
    chain.sync.poll_interval = Duration::from_millis(1);
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
        .expect("seed cached delivery suffix");
    let (service, backfill_request_rx) = test_chain_service_with_backfill(
        Arc::clone(&db),
        chain,
        public_data_plane.clone(),
        test_proxy_poi_policy(),
    );
    let backfill_request_tx = service.backfill_tx.clone();
    let registered = install_test_backfill_actor(&service, &scope, rpc.url.clone(), "test").await;
    let cache_key = registered.cache_key.as_str().to_string();
    let (_safe_head_tx, safe_head_rx) = watch::channel(110);
    let cancel = CancellationToken::new();
    spawn_backfill_loop(
        Arc::clone(&service),
        backfill_request_rx,
        Arc::clone(&rpcs),
        None,
        safe_head_rx,
        cancel.clone(),
    );

    let (wallet_tx, mut wallet_rx) = mpsc::channel(4);
    let invalidation_plane = public_data_plane.clone();
    let actor = tokio::spawn(async move {
        let Some(BackfillEvent::Apply {
            apply, response, ..
        }) = wallet_rx.recv().await
        else {
            panic!("initial cached suffix apply expected");
        };
        assert_eq!((apply.from_block, apply.to_block), (106, 110));
        assert_eq!(apply.rows.source, PublicScanSource::CachedCoverage);
        let stale_epoch = apply.read_scope.epoch();
        let current_epoch = invalidation_plane
            .invalidate_public_scan_coverage_from(100)
            .await;
        response
            .send(WalletBackfillApplyResult::Rejected {
                committed_to: 105,
                reason: WalletBackfillRejectReason::StaleDataPlaneEpoch {
                    expected: current_epoch.value,
                    actual: stale_epoch.value,
                },
            })
            .expect("reject invalidated cached suffix");

        let Some(BackfillEvent::Apply {
            apply, response, ..
        }) = wallet_rx.recv().await
        else {
            panic!("reacquired suffix apply expected");
        };
        assert_eq!(
            (apply.from_block, apply.to_block),
            (106, 110),
            "reacquisition must still deliver only the wallet suffix",
        );
        assert_eq!(apply.read_scope.epoch(), current_epoch);
        response
            .send(WalletBackfillApplyResult::Committed { committed_to: 110 })
            .expect("commit reacquired suffix");

        let Some(BackfillEvent::Finish {
            target_block,
            response,
            ..
        }) = wallet_rx.recv().await
        else {
            panic!("wallet backfill finish expected");
        };
        assert_eq!(target_block, 110);
        response
            .send(WalletBackfillFinishResult::Ready { committed_to: 110 })
            .expect("finish reacquired backfill");
    });

    assert_test_backfill_actor_current(&service, &registered).await;
    backfill_request_tx
        .send(BackfillRequest::add_with_acquisition(
            &cache_key,
            106,
            110,
            false,
            106,
            (100, 110),
            test_backfill_driver_for_actor(
                wallet_tx,
                registered.actor_id(),
                0,
                SYNTHETIC_BACKFILL_JOB_ID,
            ),
        ))
        .await
        .expect("send wallet backfill request");
    tokio::time::timeout(Duration::from_secs(2), actor)
        .await
        .expect("reacquired wallet backfill completed")
        .expect("actor response task completed");

    let requests = (0..4)
        .map(|_| {
            rpc.requests
                .recv_timeout(Duration::from_secs(1))
                .expect("RPC acquisition request")
        })
        .collect::<Vec<_>>();
    let get_logs = requests
        .iter()
        .filter(|request| request.contains("eth_getLogs"))
        .collect::<Vec<_>>();
    assert_eq!(get_logs.len(), 2);
    assert!(get_logs[0].contains(r#""fromBlock":"0x64""#));
    assert!(get_logs[0].contains(r#""toBlock":"0x69""#));
    assert!(get_logs[1].contains(r#""fromBlock":"0x64""#));
    assert!(get_logs[1].contains(r#""toBlock":"0x6e""#));
    assert!(
        service
            .public_data_plane
            .cached_wallet_scan_suffix(100, 110)
            .await
            .is_some(),
        "retry must restore the full acquisition window",
    );

    service.unregister_wallet(&registered).await;
    cancel.cancel();
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn retained_acquisition_reconciliation_restores_missing_cache_without_moving_delivery_cursor()
{
    let root_dir = temp_db_root("retained-acquisition-reconciliation");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let rpc = JsonRpcServer::spawn(Vec::new());
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let chain = test_chain_config(&scope, Arc::clone(&rpcs), None);
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let service = test_chain_service(Arc::clone(&db), chain, public_data_plane.clone());
    let (sender, _receiver) = mpsc::channel(1);
    let mut cursor = WalletBackfill::new(
        106,
        110,
        false,
        106,
        Some((100, 105)),
        test_backfill_driver(sender, 0, 1),
        std::time::Instant::now(),
    );
    let apply = WalletScanApply::rows(
        100,
        105,
        WalletScanInputRows::default(),
        public_data_plane.begin_public_scan_read(),
        PublicScanSource::Rpc,
        Some([0x11; 32]),
    );
    public_data_plane
        .commit_completed_wallet_scan_acquisition(PublicScanRange::new(100, 105), &[apply])
        .await
        .expect("commit retained acquisition");
    cursor.finish_retained_acquisition();
    let mut cursor = Some(WalletBackfillSlot {
        cache_key: String::from("test"),
        cursor,
    });

    public_data_plane
        .invalidate_public_scan_coverage_from(100)
        .await;
    assert!(!reconcile_retained_acquisition(&service, &mut cursor).await);

    let active_cursor = &cursor.as_ref().expect("cursor remains active").cursor;
    assert_eq!(active_cursor.acquisition_range(), Some((100, 105)));
    assert_eq!(active_cursor.retained_acquisition_range(), Some((100, 105)));
    assert_eq!(active_cursor.from_block, 106);

    let apply = WalletScanApply::rows(
        100,
        105,
        WalletScanInputRows::default(),
        public_data_plane.begin_public_scan_read(),
        PublicScanSource::Rpc,
        Some([0x22; 32]),
    );
    public_data_plane
        .commit_completed_wallet_scan_acquisition(PublicScanRange::new(100, 105), &[apply])
        .await
        .expect("recommit retained acquisition");
    cursor
        .as_mut()
        .expect("cursor remains active")
        .cursor
        .finish_retained_acquisition();
    public_data_plane
        .invalidate_public_scan_coverage_from(100)
        .await;
    assert!(reconcile_retained_acquisition(&service, &mut cursor).await);
    let cursor = &cursor.as_ref().expect("cursor remains active").cursor;
    assert_eq!(cursor.acquisition_range(), None);
    assert_eq!(cursor.retained_acquisition_range(), None);
    assert_eq!(cursor.from_block, 106);

    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_backfill_loop_abandons_malformed_warm_gap_before_delivering_tail() {
    let root_dir = temp_db_root("wallet-backfill-malformed-warm-gap");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let scope = test_scope();
    let mut malformed_log = rpc_nullifiers_log(scope.railgun_contract, 103);
    malformed_log["data"] = serde_json::json!("0x01");
    let rpc = JsonRpcServer::spawn(vec![
        serde_json::json!([malformed_log]),
        rpc_block(103, 1_700_000_103, 0x13),
        rpc_block(105, 1_700_000_105, 0x11),
        serde_json::json!([]),
        rpc_block(110, 1_700_000_110, 0x22),
    ]);
    let rpcs = Arc::new(QueryRpcPool::new(
        vec![rpc.url.clone()],
        Duration::from_secs(1),
    ));
    let mut chain = test_chain_config(&scope, Arc::clone(&rpcs), None);
    chain.sync.block_range = 100;
    chain.sync.poll_interval = Duration::from_millis(1);
    let public_data_plane = ChainPublicDataPlane::new(
        Arc::clone(&db),
        Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let (service, backfill_request_rx) = test_chain_service_with_backfill(
        Arc::clone(&db),
        chain,
        public_data_plane,
        test_proxy_poi_policy(),
    );
    let backfill_request_tx = service.backfill_tx.clone();
    let registered = install_test_backfill_actor(&service, &scope, rpc.url.clone(), "test").await;
    let cache_key = registered.cache_key.as_str().to_string();
    let (_safe_head_tx, safe_head_rx) = watch::channel(110);
    let cancel = CancellationToken::new();
    spawn_backfill_loop(
        Arc::clone(&service),
        backfill_request_rx,
        Arc::clone(&rpcs),
        None,
        safe_head_rx,
        cancel.clone(),
    );

    let (wallet_tx, mut wallet_rx) = mpsc::channel(4);
    let actor = tokio::spawn(async move {
        let Some(BackfillEvent::Apply {
            apply, response, ..
        }) = wallet_rx.recv().await
        else {
            panic!("delivery apply expected");
        };
        assert_eq!((apply.from_block, apply.to_block), (106, 110));
        response
            .send(WalletBackfillApplyResult::Committed { committed_to: 110 })
            .expect("commit delivery apply");
        let Some(BackfillEvent::Finish {
            target_block,
            response,
            ..
        }) = wallet_rx.recv().await
        else {
            panic!("wallet backfill finish expected");
        };
        assert_eq!(target_block, 110);
        response
            .send(WalletBackfillFinishResult::Ready { committed_to: 110 })
            .expect("finish malformed warm backfill");
    });

    assert_test_backfill_actor_current(&service, &registered).await;
    backfill_request_tx
        .send(BackfillRequest::add_with_acquisition(
            &cache_key,
            106,
            110,
            false,
            106,
            (100, 105),
            test_backfill_driver_for_actor(
                wallet_tx,
                registered.actor_id(),
                0,
                SYNTHETIC_BACKFILL_JOB_ID,
            ),
        ))
        .await
        .expect("send malformed warm backfill request");
    tokio::time::timeout(Duration::from_secs(2), actor)
        .await
        .expect("malformed warm backfill completed")
        .expect("actor response task completed");

    let mut requests: Vec<String> = Vec::new();
    while requests
        .iter()
        .filter(|request| request.contains("eth_getLogs"))
        .count()
        < 2
    {
        requests.push(
            rpc.requests
                .recv_timeout(Duration::from_secs(1))
                .expect("RPC backfill request"),
        );
    }
    let get_logs = requests
        .iter()
        .filter(|request| request.contains("eth_getLogs"))
        .collect::<Vec<_>>();
    assert_eq!(
        get_logs
            .iter()
            .filter(|request| request.contains(r#""fromBlock":"0x64""#))
            .count(),
        1,
        "malformed warm acquisition must be fetched at most once"
    );
    assert!(get_logs.iter().any(|request| {
        request.contains(r#""fromBlock":"0x64""#) && request.contains(r#""toBlock":"0x69""#)
    }));
    assert!(get_logs.iter().any(|request| {
        request.contains(r#""fromBlock":"0x6a""#) && request.contains(r#""toBlock":"0x6e""#)
    }));

    service.unregister_wallet(&registered).await;
    cancel.cancel();
    drop(service);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

fn test_backfill_driver_with_retirement_signal(
    sender: mpsc::Sender<BackfillEvent>,
    actor_id: u64,
    reset_generation: u64,
    job_id: u64,
) -> (
    WalletBackfillDriver,
    oneshot::Receiver<WalletBackfillOwnerSignal>,
) {
    let (liveness, receiver) = oneshot::channel();
    let grant = WalletBackfillGrant::for_actor_accepted_job(
        WalletSyncToken::for_test(1, actor_id, reset_generation, job_id),
        sender,
        liveness,
    );
    (grant.activate(), receiver)
}

async fn assert_test_backfill_actor_current(service: &Arc<ChainService>, handle: &WalletHandle) {
    assert!(
        service
            .wallet
            .read()
            .await
            .as_ref()
            .is_some_and(|registration| registration.handle.same_actor_as(handle)),
        "installed service actor must remain current before synthetic backfill"
    );
}
