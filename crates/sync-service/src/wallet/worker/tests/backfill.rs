use super::*;

fn accepted_test_backfill_owner(
    state: &mut WalletActorState,
    token: WalletSyncToken,
    target_block: u64,
) -> (
    WalletBackfillGrant,
    oneshot::Receiver<WalletBackfillOwnerSignal>,
) {
    assert!(state.test_transition(|mut state| state.accept_target(token, target_block)));
    let (sender, _receiver) = mpsc::channel(1);
    let (liveness, receiver) = oneshot::channel();
    (
        WalletBackfillGrant::for_actor_accepted_job(token, sender, liveness),
        receiver,
    )
}

async fn unacknowledged_test_backfill_disposition(
    token: WalletSyncToken,
    liveness: oneshot::Receiver<WalletBackfillOwnerSignal>,
) -> WalletBackfillOwnerDisposition {
    let (actual_token, signal) = accepted_backfill_owner_dropped(token, liveness).await;
    assert_eq!(actual_token, token);
    assert!(signal.acknowledgement.is_none());
    signal.disposition
}

#[tokio::test]
async fn dropped_start_response_receiver_retires_accepted_owner() {
    let mut state = test_actor_state(100);
    let token = WalletSyncToken::for_test(1, 1, 0, 1);
    let (grant, liveness) = accepted_test_backfill_owner(&mut state, token, 200);
    let (response, result_rx) = oneshot::channel();
    drop(result_rx);

    let result = WalletBackfillStartResult::Accepted {
        committed_to: 100,
        target_block: 200,
        grant,
    };
    drop(
        response
            .send(result)
            .expect_err("start receiver was dropped"),
    );

    assert_eq!(
        unacknowledged_test_backfill_disposition(token, liveness).await,
        WalletBackfillOwnerDisposition::BenignRetirement
    );
    assert!(
        state.test_transition(|mut state| state.apply_backfill_owner_disposition(
            token,
            WalletBackfillOwnerDisposition::BenignRetirement,
        ))
    );
    assert_eq!(state.test_active_job_count(), 0);
}

#[tokio::test]
async fn dropped_delivered_start_result_retires_accepted_owner() {
    let mut state = test_actor_state(100);
    let token = WalletSyncToken::for_test(1, 1, 0, 1);
    let (grant, liveness) = accepted_test_backfill_owner(&mut state, token, 200);
    let (response, result_rx) = oneshot::channel();
    response
        .send(WalletBackfillStartResult::Accepted {
            committed_to: 100,
            target_block: 200,
            grant,
        })
        .expect("deliver accepted start result");

    drop(result_rx.await.expect("receive accepted start result"));

    assert_eq!(
        unacknowledged_test_backfill_disposition(token, liveness).await,
        WalletBackfillOwnerDisposition::BenignRetirement
    );
    assert!(
        state.test_transition(|mut state| state.apply_backfill_owner_disposition(
            token,
            WalletBackfillOwnerDisposition::BenignRetirement,
        ))
    );
    assert_eq!(state.test_active_job_count(), 0);
}

#[tokio::test]
async fn dropping_unactivated_backfill_grant_restores_completed_readiness_without_fault() {
    let mut state = test_actor_state(100);
    let completed = WalletSyncToken::for_test(1, 1, 0, 1);
    assert!(state.test_transition(|mut state| state.accept_target(completed, 100)));
    assert!(state.test_transition(|mut state| state.complete_backfill_job(completed)));
    assert_eq!(state.test_readiness(), WalletReadiness::Ready);

    let newer = WalletSyncToken::for_test(1, 1, 0, 2);
    let (grant, liveness) = accepted_test_backfill_owner(&mut state, newer, 200);
    assert_eq!(state.test_readiness(), WalletReadiness::Syncing);
    drop(grant);

    assert_eq!(
        unacknowledged_test_backfill_disposition(newer, liveness).await,
        WalletBackfillOwnerDisposition::BenignRetirement
    );
    assert!(
        state.test_transition(|mut state| state.apply_backfill_owner_disposition(
            newer,
            WalletBackfillOwnerDisposition::BenignRetirement,
        ))
    );
    assert_eq!(state.completed_target_block(), Some(100));
    assert_eq!(state.test_job_failure_count(), 0);
    assert_eq!(state.test_readiness(), WalletReadiness::Ready);
}

#[tokio::test]
async fn sync_target_lease_bridges_partial_source_and_successor_admission() {
    let mut state = test_actor_state(100);
    let completed = WalletSyncToken::for_test(1, 1, 0, 1);
    assert!(state.test_transition(|mut state| state.accept_target(completed, 100)));
    assert!(state.test_transition(|mut state| state.complete_backfill_job(completed)));
    assert_eq!(state.test_readiness(), WalletReadiness::Ready);

    let target_token = WalletSyncToken::for_test(1, 1, 0, 2);
    assert!(state.test_transition(|mut state| state.accept_sync_target(target_token, 200)));
    let (sender, _receiver) = mpsc::channel(1);
    let (target_liveness, target_dropped) = oneshot::channel();
    let target_lease =
        WalletSyncTargetLease::for_actor_accepted_job(target_token, sender, target_liveness);
    assert_eq!(target_lease.token(), target_token);

    let partial = WalletSyncToken::for_test(1, 1, 0, 3);
    assert!(state.test_transition(|mut state| state.accept_target(partial, 150)));
    state.test_transition(|mut state| state.update_cursor(150));
    assert!(state.test_transition(|mut state| state.retire_job(partial)));
    let indexed = WalletSyncToken::for_test(1, 1, 0, 4);
    assert!(state.test_transition(|mut state| state.accept_indexed_catch_up(indexed)));
    assert!(state.test_transition(|mut state| state.retire_job(indexed)));
    assert_eq!(state.test_readiness(), WalletReadiness::Syncing);

    let successor = WalletSyncToken::for_test(1, 1, 0, 5);
    assert!(state.test_transition(|mut state| state.accept_target(successor, 200)));
    drop(target_lease);
    assert_eq!(
        unacknowledged_test_backfill_disposition(target_token, target_dropped).await,
        WalletBackfillOwnerDisposition::BenignRetirement
    );
    assert!(
        state.test_transition(|mut state| state.apply_backfill_owner_disposition(
            target_token,
            WalletBackfillOwnerDisposition::BenignRetirement,
        ))
    );
    assert_eq!(state.test_readiness(), WalletReadiness::Syncing);

    state.test_transition(|mut state| state.update_cursor(200));
    assert!(state.test_transition(|mut state| state.complete_backfill_job(successor)));
    assert_eq!(state.test_readiness(), WalletReadiness::Ready);
}

#[test]
fn multiple_backfill_targets_recompute_from_job_records() {
    let mut state = test_actor_state(200);
    let first = WalletSyncToken::for_test(1, 1, 0, 1);
    let second = WalletSyncToken::for_test(1, 1, 0, 2);
    assert!(state.test_transition(|mut state| state.accept_target(first, 150)));
    assert!(state.test_transition(|mut state| state.accept_target(second, 200)));

    assert!(state.test_transition(|mut state| state.complete_backfill_job(first)));
    assert_eq!(state.completed_target_block(), Some(150));
    assert_eq!(state.test_readiness(), WalletReadiness::Syncing);
    assert!(state.test_transition(|mut state| state.retire_job(second)));
    assert_eq!(state.test_readiness(), WalletReadiness::Ready);
}

#[tokio::test]
async fn dropped_backfill_request_reports_active_driver_loss() {
    let mut state = test_actor_state(100);
    let completed = WalletSyncToken::for_test(1, 1, 0, 1);
    assert!(state.test_transition(|mut state| state.accept_target(completed, 100)));
    assert!(state.test_transition(|mut state| state.complete_backfill_job(completed)));
    assert_eq!(state.test_readiness(), WalletReadiness::Ready);

    let token = WalletSyncToken::for_test(1, 1, 0, 2);
    let (grant, liveness) = accepted_test_backfill_owner(&mut state, token, 200);
    assert_eq!(state.test_readiness(), WalletReadiness::Syncing);
    drop(BackfillRequest::add(
        "test",
        101,
        200,
        false,
        101,
        grant.activate(),
    ));

    assert_eq!(
        unacknowledged_test_backfill_disposition(token, liveness).await,
        WalletBackfillOwnerDisposition::DriverLost
    );
    assert!(state.test_transition(|mut state| {
        state.apply_backfill_owner_disposition(token, WalletBackfillOwnerDisposition::DriverLost)
    }));
    assert_eq!(state.test_active_job_count(), 0);
    assert_eq!(
        state.test_readiness(),
        WalletReadiness::Failed(WalletReadinessError::BackfillUnavailable)
    );
}

#[tokio::test]
async fn persistence_retry_completion_ignores_subsequent_driver_drop() {
    let mut state = test_actor_state(100);
    let token = WalletSyncToken::for_test(1, 1, 0, 1);
    let (grant, liveness) = accepted_test_backfill_owner(&mut state, token, 100);
    let driver = grant.activate();

    assert!(state.test_transition(|mut state| { state.backfill_completion_persist_failed(token) }));

    assert_eq!(state.test_active_backfill_target_for(token), Some(100));
    assert!(
        state.test_transition(|mut state| { state.durable_backfill_completion_commit_ok(token) })
    );
    assert!(state.test_transition(|mut state| state.complete_backfill_job(token)));
    assert_eq!(state.test_readiness(), WalletReadiness::Ready);
    drop(driver);
    assert_eq!(
        unacknowledged_test_backfill_disposition(token, liveness).await,
        WalletBackfillOwnerDisposition::DriverLost
    );
    assert!(!state.test_transition(|mut state| {
        state.apply_backfill_owner_disposition(token, WalletBackfillOwnerDisposition::DriverLost)
    }));
    assert_eq!(state.test_readiness(), WalletReadiness::Ready);
}

#[tokio::test]
async fn dropped_indexed_owner_clears_exact_job_status_and_readiness() {
    let mut state = test_actor_state(100);
    let completed = WalletSyncToken::for_test(1, 1, 0, 1);
    assert!(state.test_transition(|mut state| state.accept_target(completed, 100)));
    assert!(state.test_transition(|mut state| state.complete_backfill_job(completed)));
    let token = WalletSyncToken::for_test(1, 1, 0, 2);
    assert!(state.test_transition(|mut state| state.accept_indexed_catch_up(token)));
    let status = WalletIndexedCatchUpStatus {
        source: WalletIndexedCatchUpSource::IndexedArtifacts,
        from_block: 101,
        target_block: 200,
    };
    assert!(state.test_transition(|mut state| state.publish_indexed_catch_up(token, status)));
    assert_eq!(state.test_indexed_status(token), Some(&status));
    let (liveness, receiver) = oneshot::channel();
    let lease = WalletIndexedCatchUpLease::for_actor_accepted_job(token, liveness);
    drop(lease);

    assert_eq!(
        accepted_indexed_job_owner_dropped(token, receiver).await,
        token
    );
    assert!(state.test_transition(|mut state| state.retire_job(token)));
    assert_eq!(state.test_readiness(), WalletReadiness::Ready);
}

#[tokio::test]
async fn wallet_dropped_overlapping_backfill_response_preserves_covering_job() {
    let root_dir = temp_db_root("wallet-dropped-backfill-response");
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
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");
    assert_eq!(
        send_target(&handle, &backfill_tx, 100, 0).await,
        WalletBackfillFinishResult::Ready { committed_to: 100 }
    );

    let covering_token = handle.mint_sync_token(0);
    let covering_lease = assert_start_accepted(
        send_start_token(&backfill_tx, 200, covering_token).await,
        covering_token,
        100,
        200,
    );
    let dropped_token = handle.mint_sync_token(0);
    let (response, result_rx) = oneshot::channel();
    drop(result_rx);
    backfill_tx
        .send(BackfillEvent::Start {
            target_block: 150,
            token: dropped_token,
            response,
        })
        .await
        .expect("send target with dropped response receiver");

    let (response, result_rx) = oneshot::channel();
    backfill_tx
        .send(BackfillEvent::Apply {
            apply: indexed_delta_batch(101, 110, empty_delta()),
            token: dropped_token,
            response,
        })
        .await
        .expect("send late apply for dropped handoff");
    assert_eq!(
        result_rx.await.expect("late apply response"),
        WalletBackfillApplyResult::Rejected {
            committed_to: 100,
            reason: WalletBackfillRejectReason::Shutdown,
        }
    );
    assert_eq!(handle.readiness(), WalletReadiness::Syncing);

    assert_eq!(
        covering_lease
            .apply("test", indexed_delta_batch(101, 200, empty_delta()))
            .await,
        WalletBackfillApplyResult::Committed { committed_to: 200 }
    );
    assert_eq!(
        covering_lease.finish("test", 200).await,
        WalletBackfillFinishResult::Ready { committed_to: 200 }
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_live_gap_backfill_queue_full_marks_job_failed() {
    let root_dir = temp_db_root("wallet-live-gap-queue-full");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let (live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, mut backfill_request_rx) = mpsc::channel(1);
    backfill_request_tx
        .try_send(BackfillRequest::Remove {
            cache_key: "blocked".to_string(),
            actor_id: 0,
            response: oneshot::channel().0,
        })
        .expect("fill backfill request queue");
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
        send_target(&handle, &backfill_tx, 100, 0).await,
        WalletBackfillFinishResult::Ready { committed_to: 100 }
    );
    live_tx
        .send(Arc::new(LogBatch {
            from_block: 120,
            to_block: 120,
            logs: Vec::new(),
            block_timestamps: HashMap::new(),
            to_block_hash: None,
            read_scope: test_public_scan_read_scope(),
        }))
        .expect("live receiver");
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if matches!(
                handle.readiness(),
                WalletReadiness::Failed(WalletReadinessError::BackfillUnavailable)
            ) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("backfill unavailable readiness observed");
    assert!(backfill_request_rx.try_recv().is_ok());

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_target_does_not_publish_ready_while_other_backfill_active() {
    let root_dir = temp_db_root("wallet-target-active-job-gate");
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
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");

    let initial_token = handle.mint_sync_token(0);
    assert_eq!(
        send_target_token(&backfill_tx, 100, initial_token).await,
        WalletBackfillFinishResult::Ready { committed_to: 100 }
    );
    let gap_token = handle.mint_sync_token(0);
    let _gap_lease = assert_start_accepted(
        send_start_token(&backfill_tx, 150, gap_token).await,
        gap_token,
        100,
        150,
    );
    let covered_token = handle.mint_sync_token(0);
    let covered_lease = assert_start_accepted(
        send_start_token(&backfill_tx, 100, covered_token).await,
        covered_token,
        100,
        100,
    );
    assert_eq!(
        covered_lease.finish("test", 100).await,
        WalletBackfillFinishResult::Ready { committed_to: 100 }
    );
    assert_eq!(handle.readiness(), WalletReadiness::Syncing);
    assert!(!handle.readiness().is_ready());

    let (response, result_rx) = oneshot::channel();
    backfill_tx
        .send(BackfillEvent::Apply {
            apply: indexed_delta_batch(101, 110, empty_delta()),
            token: covered_token,
            response,
        })
        .await
        .expect("send late covered-token apply");
    assert_eq!(
        result_rx.await.expect("late apply result"),
        WalletBackfillApplyResult::Rejected {
            committed_to: 100,
            reason: WalletBackfillRejectReason::Shutdown,
        }
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_dropped_indexed_claim_response_retires_exact_accepted_job() {
    let root_dir = temp_db_root("wallet-dropped-indexed-claim-response");
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
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");
    assert_eq!(
        send_target(&handle, &backfill_tx, 100, 0).await,
        WalletBackfillFinishResult::Ready { committed_to: 100 }
    );

    let (response, result_rx) = oneshot::channel();
    drop(result_rx);
    handle
        .indexed_catch_up_status_tx
        .send(WalletIndexedCatchUpCommand::Claim { response })
        .expect("send indexed claim with dropped response receiver");

    let lease = tokio::time::timeout(Duration::from_secs(1), handle.try_claim_indexed_catch_up())
        .await
        .expect("second indexed claim completed")
        .expect("dropped first claim must be retired");
    drop(lease);
    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.readiness() != WalletReadiness::Ready {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("indexed claim retirement republished readiness");

    let shutdown_lease = handle
        .try_claim_indexed_catch_up()
        .await
        .expect("indexed claim before shutdown");
    handle.set_indexed_catch_up(
        &shutdown_lease,
        WalletIndexedCatchUpStatus {
            source: WalletIndexedCatchUpSource::Squid,
            from_block: 101,
            target_block: 200,
        },
    );
    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.indexed_catch_up_rx.borrow().is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("indexed status published before shutdown");
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.readiness() != WalletReadiness::Shutdown
            || handle.indexed_catch_up_rx.borrow().is_some()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("shutdown cleared indexed status and active job");
    drop(shutdown_lease);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_handle_rejects_duplicate_indexed_catch_up_claim_until_cleared() {
    let root_dir = temp_db_root("wallet-worker-indexed-catch-up-lease");
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
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");

    assert_eq!(
        send_target(&handle, &backfill_tx, 100, 0).await,
        WalletBackfillFinishResult::Ready { committed_to: 100 }
    );
    assert_eq!(handle.readiness(), WalletReadiness::Ready);

    let first_lease = handle
        .try_claim_indexed_catch_up()
        .await
        .expect("first indexed catch-up claim");
    assert_eq!(handle.readiness(), WalletReadiness::Syncing);
    assert!(handle.try_claim_indexed_catch_up().await.is_none());
    let first_status = WalletIndexedCatchUpStatus {
        source: WalletIndexedCatchUpSource::IndexedArtifacts,
        from_block: 101,
        target_block: 200,
    };
    handle.set_indexed_catch_up(&first_lease, first_status);
    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.indexed_catch_up_rx.borrow().is_none() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("indexed catch-up status published");
    assert_eq!(
        handle.indexed_catch_up_rx.borrow().as_ref(),
        Some(&first_status)
    );
    drop(first_lease);
    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.indexed_catch_up_rx.borrow().is_some() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("indexed catch-up status cleared");
    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.readiness() != WalletReadiness::Ready {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("indexed catch-up readiness restored");
    let second_lease = handle
        .try_claim_indexed_catch_up()
        .await
        .expect("second indexed catch-up claim");
    let second_status = WalletIndexedCatchUpStatus {
        source: WalletIndexedCatchUpSource::Squid,
        from_block: 201,
        target_block: 300,
    };
    handle.set_indexed_catch_up(&second_lease, second_status);
    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.indexed_catch_up_rx.borrow().as_ref() != Some(&second_status) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("second indexed catch-up status published");

    assert!(send_reset(&backfill_tx, 1, 50).await.committed());
    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.indexed_catch_up_rx.borrow().is_some() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("reset cleared indexed catch-up status");
    drop(second_lease);

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_worker_ignores_done_after_non_contiguous_indexed_delta() {
    let root_dir = temp_db_root("wallet-worker-indexed-tail-non-contiguous-done");
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
        cancel.clone(),
        Vec::new(),
        150,
    )
    .await
    .expect("spawn wallet worker");

    assert_eq!(
        send_apply(
            &handle,
            &backfill_tx,
            indexed_delta_batch(101, 200, empty_delta()),
            0
        )
        .await,
        WalletBackfillApplyResult::Rejected {
            committed_to: 150,
            reason: WalletBackfillRejectReason::NonContiguous {
                expected_from: 151,
                actual_from: 101,
            },
        }
    );
    let done_token = handle.mint_sync_token(0);
    let _done_lease = assert_start_accepted(
        send_start_token(&backfill_tx, 200, done_token).await,
        done_token,
        150,
        200,
    );
    assert_eq!(handle.last_scanned(), Some(150));
    assert_eq!(
        send_apply(
            &handle,
            &backfill_tx,
            indexed_delta_batch(151, 151, empty_delta()),
            0
        )
        .await,
        WalletBackfillApplyResult::Committed { committed_to: 151 }
    );

    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.last_scanned() == Some(150) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("marker delta processed");
    assert_eq!(handle.last_scanned(), Some(151));

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_worker_ignores_stale_indexed_tail_events_after_reset() {
    let root_dir = temp_db_root("wallet-worker-indexed-tail-reset");
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
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");

    assert_eq!(
        send_reset(&backfill_tx, 1, 80).await,
        WalletBackfillResetResult::accepted_committed(1, 79)
    );
    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.authority_reset_generation() != 1 || handle.last_scanned() != Some(79) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("reset applied");

    assert_eq!(
        send_apply(
            &handle,
            &backfill_tx,
            indexed_delta_batch(
                101,
                150,
                WalletLogDelta {
                    utxos: vec![test_wallet_utxo(120, 1).utxo],
                    nullifiers: Vec::new(),
                    commitment_observations: Vec::new(),
                    sender_scan_outputs: Vec::new(),
                },
            ),
            0,
        )
        .await,
        WalletBackfillApplyResult::Rejected {
            committed_to: 79,
            reason: WalletBackfillRejectReason::StaleGeneration {
                expected: 1,
                actual: 0,
            },
        }
    );
    assert!(matches!(
        send_target(&handle, &backfill_tx, 150, 0).await,
        WalletBackfillFinishResult::Rejected {
            reason: WalletBackfillRejectReason::StaleGeneration { .. },
            ..
        }
    ));
    assert!(matches!(
        send_apply(&handle, &backfill_tx, logs_apply(101, 150), 0).await,
        WalletBackfillApplyResult::Rejected {
            reason: WalletBackfillRejectReason::StaleGeneration { .. },
            ..
        }
    ));
    assert_eq!(handle.last_scanned(), Some(79));

    assert!(matches!(
        send_apply(
            &handle,
            &backfill_tx,
            indexed_delta_batch(101, 150, empty_delta()),
            1
        )
        .await,
        WalletBackfillApplyResult::Rejected {
            reason: WalletBackfillRejectReason::NonContiguous { .. },
            ..
        }
    ));
    let current_target_token = handle.mint_sync_token(1);
    let current_target_lease = assert_start_accepted(
        send_start_token(&backfill_tx, 150, current_target_token).await,
        current_target_token,
        79,
        150,
    );
    current_target_lease.retire("test").await;
    assert_eq!(
        send_apply(
            &handle,
            &backfill_tx,
            indexed_delta_batch(80, 90, empty_delta()),
            1,
        )
        .await,
        WalletBackfillApplyResult::Committed { committed_to: 90 }
    );
    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.last_scanned() != Some(90) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("current delta applied");

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_worker_requests_backfill_after_live_receiver_lag() {
    let root_dir = temp_db_root("wallet-worker-live-lag-gap");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let (live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, mut backfill_request_rx) = mpsc::channel(8);
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
    for block in 101..=120 {
        live_tx
            .send(Arc::new(LogBatch {
                from_block: block,
                to_block: block,
                logs: Vec::new(),
                block_timestamps: HashMap::new(),
                to_block_hash: None,
                read_scope: test_public_scan_read_scope(),
            }))
            .expect("live receiver");
    }
    tokio::task::yield_now().await;
    assert_eq!(handle.last_scanned(), Some(100));

    assert_eq!(
        send_target(&handle, &backfill_tx, 100, 0).await,
        WalletBackfillFinishResult::Ready { committed_to: 100 }
    );
    let request = tokio::time::timeout(Duration::from_secs(1), backfill_request_rx.recv())
        .await
        .expect("live gap backfill requested")
        .expect("backfill request channel open");
    let BackfillRequest::Add {
        cache_key,
        from_block,
        to_block,
        follow_safe_head,
        driver,
        ..
    } = request
    else {
        panic!("expected add backfill request");
    };
    assert_eq!(cache_key, handle.cache_key.to_string());
    assert_eq!(from_block, 101);
    assert!(to_block > from_block);
    assert!(follow_safe_head);
    assert_eq!(driver.token().reset_generation(), 0);
    assert_eq!(handle.last_scanned(), Some(100));

    assert_eq!(
        driver.apply("test", logs_apply(from_block, to_block)).await,
        WalletBackfillApplyResult::Committed {
            committed_to: to_block
        }
    );
    assert_eq!(
        driver.finish("test", to_block).await,
        WalletBackfillFinishResult::Ready {
            committed_to: to_block
        }
    );
    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.last_scanned() != Some(to_block) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("recovery backfill applied");

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
