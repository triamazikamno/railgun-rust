use super::*;

#[tokio::test]
async fn wallet_pending_overlay_update_runs_through_actor_mailbox() {
    let root_dir = temp_db_root("wallet-pending-overlay-mailbox");
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
    let wallet_utxo = test_wallet_utxo(105, 7);
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
        vec![wallet_utxo.clone()],
        100,
    )
    .await
    .expect("spawn wallet worker");
    let spent_source = source(101, 0xaa);
    let pending_spent = WalletPendingSpent {
        tree: wallet_utxo.utxo.tree,
        position: wallet_utxo.utxo.position,
        stable_identity: None,
        tx_hash: Some(spent_source.tx_hash),
        block_number: Some(spent_source.block_number),
        block_timestamp: Some(spent_source.block_timestamp),
    };

    assert!(
        handle
            .request_pending_overlay_rows(
                pending_overlay_rows_from_delta(
                    101,
                    101,
                    WalletLogDelta {
                        utxos: Vec::new(),
                        nullifiers: vec![SpentNullifier {
                            tree: wallet_utxo.utxo.tree,
                            nullifier: wallet_utxo
                                .utxo
                                .nullifier(wallet_config().scan_keys.nullifying_key),
                            source: spent_source,
                        }],
                        commitment_observations: Vec::new(),
                        sender_scan_outputs: Vec::new(),
                    },
                ),
                0,
                100,
            )
            .await
    );

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let overlay = handle.pending_overlay().expect("current view");
            if overlay.pending_spent == vec![pending_spent.clone()] {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("pending overlay update applied through mailbox");

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_pending_overlay_rejects_older_job_after_newer_overlay() {
    let root_dir = temp_db_root("wallet-pending-overlay-reverse-order");
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
    let wallet_utxo = test_wallet_utxo(105, 7);
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
        vec![wallet_utxo.clone()],
        100,
    )
    .await
    .expect("spawn wallet worker");
    let older_token = handle.mint_sync_token(0);
    let newer_token = handle.mint_sync_token(0);
    let older_source = source(101, 0xaa);
    let newer_source = source(102, 0xbb);
    let older_spent = WalletPendingSpent {
        tree: wallet_utxo.utxo.tree,
        position: wallet_utxo.utxo.position,
        stable_identity: None,
        tx_hash: Some(older_source.tx_hash),
        block_number: Some(older_source.block_number),
        block_timestamp: Some(older_source.block_timestamp),
    };
    let newer_spent = WalletPendingSpent {
        tx_hash: Some(newer_source.tx_hash),
        block_number: Some(newer_source.block_number),
        block_timestamp: Some(newer_source.block_timestamp),
        ..older_spent.clone()
    };
    let nullifier = wallet_utxo
        .utxo
        .nullifier(wallet_config().scan_keys.nullifying_key);

    handle
        .pending_overlay_tx
        .send(WalletPendingOverlayRequest {
            update: WalletPendingOverlayUpdate::PublicRows(pending_overlay_rows_from_delta(
                102,
                102,
                WalletLogDelta {
                    utxos: Vec::new(),
                    nullifiers: vec![SpentNullifier {
                        tree: wallet_utxo.utxo.tree,
                        nullifier,
                        source: newer_source,
                    }],
                    commitment_observations: Vec::new(),
                    sender_scan_outputs: Vec::new(),
                },
            )),
            token: newer_token,
            reset_generation: 0,
            last_scanned: 100,
        })
        .await
        .expect("send newer overlay");

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let overlay = handle.pending_overlay().expect("current view");
            if overlay.pending_spent == vec![newer_spent.clone()] {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("newer pending overlay applied");

    handle
        .pending_overlay_tx
        .send(WalletPendingOverlayRequest {
            update: WalletPendingOverlayUpdate::PublicRows(pending_overlay_rows_from_delta(
                101,
                101,
                WalletLogDelta {
                    utxos: Vec::new(),
                    nullifiers: vec![SpentNullifier {
                        tree: wallet_utxo.utxo.tree,
                        nullifier,
                        source: older_source,
                    }],
                    commitment_observations: Vec::new(),
                    sender_scan_outputs: Vec::new(),
                },
            )),
            token: older_token,
            reset_generation: 0,
            last_scanned: 100,
        })
        .await
        .expect("send older overlay");
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert_eq!(
        handle
            .pending_overlay()
            .expect("current view")
            .pending_spent,
        vec![newer_spent]
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_retired_backfill_job_rejects_late_apply() {
    let root_dir = temp_db_root("wallet-retired-job-late-apply");
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
    let token = handle.mint_sync_token(0);

    let lease = assert_start_accepted(
        send_start_token(&backfill_tx, 150, token).await,
        token,
        100,
        150,
    );
    lease.retire("test").await;

    let (response, result_rx) = oneshot::channel();
    backfill_tx
        .send(BackfillEvent::Apply {
            apply: indexed_delta_batch(
                101,
                110,
                WalletLogDelta {
                    utxos: Vec::new(),
                    nullifiers: Vec::new(),
                    commitment_observations: Vec::new(),
                    sender_scan_outputs: Vec::new(),
                },
            ),
            token,
            response,
        })
        .await
        .expect("send late apply");
    assert_eq!(
        result_rx.await.expect("late apply response"),
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
async fn wallet_reset_rejects_stale_actor_token() {
    let root_dir = temp_db_root("wallet-reset-stale-actor-token");
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

    let (response, result_rx) = oneshot::channel();
    backfill_tx
        .send(BackfillEvent::Reset {
            token: WalletResetToken::for_test(1, 2, 1),
            from_block: 80,
            replay_plan: WalletResetReplayPlan::new(0, 0, true),
            response,
        })
        .await
        .expect("send stale reset");
    assert_eq!(
        result_rx.await.expect("reset response"),
        WalletBackfillResetResult::Rejected {
            committed_to: 100,
            reason: WalletBackfillRejectReason::Shutdown,
        }
    );
    assert_eq!(handle.authority_reset_generation(), 0);
    assert_eq!(handle.last_scanned(), Some(100));

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_generic_persistence_and_late_retired_job_failures_are_noops() {
    let root_dir = temp_db_root("wallet-late-job-failed-retired");
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

    let token = handle.mint_sync_token(0);
    let lease = assert_start_accepted(
        send_start_token(&backfill_tx, 200, token).await,
        token,
        100,
        200,
    );
    let (response, result_rx) = oneshot::channel();
    backfill_tx
        .send(BackfillEvent::JobFailed {
            token,
            reason: WalletReadinessError::PersistenceFailed,
            response,
        })
        .await
        .expect("generic persistence job failure");
    result_rx.await.expect("job failure response");
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert_eq!(handle.readiness(), WalletReadiness::Syncing);

    lease.retire("test").await;
    tokio::time::sleep(Duration::from_millis(25)).await;
    let (response, result_rx) = oneshot::channel();
    backfill_tx
        .send(BackfillEvent::JobFailed {
            token,
            reason: WalletReadinessError::BackfillUnavailable,
            response,
        })
        .await
        .expect("late job failure");
    result_rx.await.expect("job failure response");
    tokio::time::sleep(Duration::from_millis(25)).await;

    assert!(!matches!(handle.readiness(), WalletReadiness::Failed(_)));

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_raw_minted_token_does_not_authorize_apply() {
    let root_dir = temp_db_root("wallet-raw-token-apply-rejected");
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
    let token = handle.mint_sync_token(0);
    let (response, result_rx) = oneshot::channel();
    backfill_tx
        .send(BackfillEvent::Apply {
            apply: indexed_delta_batch(101, 110, empty_delta()),
            token,
            response,
        })
        .await
        .expect("send raw-token apply");

    assert_eq!(
        result_rx.await.expect("raw-token apply response"),
        WalletBackfillApplyResult::Rejected {
            committed_to: 100,
            reason: WalletBackfillRejectReason::Shutdown,
        }
    );
    assert_eq!(handle.last_scanned(), Some(100));

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_never_accepted_job_retired_is_noop() {
    let root_dir = temp_db_root("wallet-never-accepted-retire-noop");
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
    let token = handle.mint_sync_token(0);

    let _lease = assert_start_accepted(
        send_start_token(&backfill_tx, 150, token).await,
        token,
        100,
        150,
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn wallet_actor_retired_job_bookkeeping_is_bounded() {
    let mut actor_state = test_actor_state(0);

    for job_id in 1..=10_000 {
        let token = WalletSyncToken::for_test(1, 1, 0, job_id);
        assert!(actor_state.test_transition(|mut state| state.accept_target(token, 0)));
        assert!(actor_state.test_transition(|mut state| state.retire_job(token)));
    }

    assert_eq!(actor_state.test_active_job_count(), 0);
    assert_eq!(actor_state.test_highest_accepted_backfill_job_id(), 10_000);
    assert!(!actor_state.test_transition(|mut state| {
        state.test_accept_backfill_job_id(WalletSyncToken::for_test(1, 1, 0, 10_000))
    }));
    assert!(actor_state.test_transition(|mut state| {
        state.accept_target(WalletSyncToken::for_test(1, 1, 0, 10_001), 0)
    }));
}

#[tokio::test]
async fn wallet_retired_backfill_job_rejects_late_target() {
    let root_dir = temp_db_root("wallet-retired-job-late-target");
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
    let token = handle.mint_sync_token(0);

    let lease = assert_start_accepted(
        send_start_token(&backfill_tx, 150, token).await,
        token,
        100,
        150,
    );
    lease.retire("test").await;

    assert_eq!(
        send_target_token(&backfill_tx, 150, token).await,
        WalletBackfillFinishResult::Rejected {
            committed_to: 100,
            reason: WalletBackfillRejectReason::Shutdown,
        }
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
