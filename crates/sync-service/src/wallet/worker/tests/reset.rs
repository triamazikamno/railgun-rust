use super::*;

#[tokio::test]
async fn wallet_reset_acceptance_persist_failure_keeps_generation_current() {
    let root_dir = temp_db_root("wallet-reset-acceptance-persist-failure");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    let mut cfg = wallet_config();
    cfg.cache_store = Some(cache_store.clone());
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
        cfg,
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");

    cache_store.fail_next_actor_state_put();
    assert_eq!(
        send_reset(&backfill_tx, 1, 50).await,
        WalletBackfillResetResult::Rejected {
            committed_to: 100,
            reason: WalletBackfillRejectReason::PersistenceFailed,
        }
    );
    assert_eq!(handle.authority_reset_generation(), 0);

    let token = handle.mint_sync_token(handle.authority_reset_generation());
    let lease = assert_start_accepted(
        send_start_token(&backfill_tx, 110, token).await,
        token,
        100,
        110,
    );
    assert_eq!(
        lease
            .apply("test", indexed_delta_batch(101, 110, empty_delta()))
            .await,
        WalletBackfillApplyResult::Committed { committed_to: 110 }
    );
    assert_eq!(
        lease.finish("test", 110).await,
        WalletBackfillFinishResult::Ready { committed_to: 110 }
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
    let request = tokio::time::timeout(Duration::from_secs(1), backfill_request_rx.recv())
        .await
        .expect("live gap backfill requested")
        .expect("backfill request");
    let BackfillRequest::Add {
        from_block,
        to_block,
        driver,
        ..
    } = request
    else {
        panic!("expected live-gap add request");
    };
    assert_eq!(from_block, 111);
    assert_eq!(to_block, 120);
    assert_eq!(driver.token().reset_generation(), 0);

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_reset_replay_is_admitted_when_response_receiver_is_dropped() {
    let root_dir = temp_db_root("wallet-reset-dropped-response");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cfg = wallet_config();
    let (_live_tx, live_rx) = broadcast::channel(8);
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

    let (response, result_rx) = oneshot::channel();
    drop(result_rx);
    backfill_tx
        .send(BackfillEvent::Reset {
            token: test_reset_token(1),
            from_block: 100,
            replay_plan: WalletResetReplayPlan::new(0, 150, false),
            response,
        })
        .await
        .expect("send reset with dropped response receiver");

    let request = tokio::time::timeout(Duration::from_secs(1), backfill_request_rx.recv())
        .await
        .expect("actor-owned reset replay admitted")
        .expect("backfill request channel open");
    let BackfillRequest::Add {
        from_block,
        to_block,
        follow_safe_head,
        driver,
        ..
    } = request
    else {
        panic!("expected reset replay add request");
    };
    assert_eq!(from_block, 100);
    assert_eq!(to_block, 150);
    assert!(!follow_safe_head);
    assert_eq!(driver.token().reset_generation(), 1);

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let state = db
                .get_wallet_sync_actor_state(cfg.chain.chain_id, &cfg.cache_key)
                .expect("load wallet sync actor state")
                .expect("wallet sync actor state");
            if state.pending_reset.is_none() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("durable reset plan retired after actor-owned admission");
    assert!(backfill_request_rx.try_recv().is_err());

    cancel.cancel();
    drop(handle);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_reset_replay_is_readmitted_after_durable_retirement_failure() {
    let root_dir = temp_db_root("wallet-reset-replay-readmission");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    cache_store.fail_next_reset_replay_retirement();
    let mut cfg = wallet_config();
    cfg.cache_store = Some(cache_store);
    let (_live_tx, live_rx) = broadcast::channel(8);
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
        cfg,
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        vec![test_wallet_utxo(105, 7)],
        120,
    )
    .await
    .expect("spawn wallet worker");

    let (response, result_rx) = oneshot::channel();
    backfill_tx
        .send(BackfillEvent::Reset {
            token: test_reset_token(1),
            from_block: 100,
            replay_plan: WalletResetReplayPlan::new(0, 150, false),
            response,
        })
        .await
        .expect("send reset");
    assert_eq!(
        result_rx.await.expect("reset response"),
        WalletBackfillResetResult::accepted_committed(1, 99)
    );
    let first_lease = match tokio::time::timeout(Duration::from_secs(1), backfill_request_rx.recv())
        .await
        .expect("first reset replay admitted")
        .expect("first reset replay request")
    {
        BackfillRequest::Add { driver, .. } => driver,
        BackfillRequest::Remove { .. } => panic!("expected reset replay add request"),
    };
    let first_token = first_lease.token();

    first_lease.retire("test").await;
    let (response, result_rx) = oneshot::channel();
    backfill_tx
        .send(BackfillEvent::Apply {
            apply: indexed_delta_batch(100, 100, empty_delta()),
            token: first_token,
            response,
        })
        .await
        .expect("send event after reset replay retirement");
    assert_eq!(
        result_rx.await.expect("retired replay response"),
        WalletBackfillApplyResult::Rejected {
            committed_to: 99,
            reason: WalletBackfillRejectReason::Shutdown,
        }
    );

    let second_lease =
        match tokio::time::timeout(Duration::from_secs(1), backfill_request_rx.recv())
            .await
            .expect("reset replay readmitted")
            .expect("readmitted reset replay request")
        {
            BackfillRequest::Add { driver, .. } => driver,
            BackfillRequest::Remove { .. } => panic!("expected reset replay add request"),
        };
    let second_token = second_lease.token();
    assert_ne!(second_token, first_token);

    cancel.cancel();
    drop(handle);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_pending_reset_retry_retires_rejected_target_job() {
    let root_dir = temp_db_root("wallet-reset-retry-retires-job");
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
        cfg,
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        vec![test_wallet_utxo(105, 7)],
        120,
    )
    .await
    .expect("spawn wallet worker");

    cache_store.fail_next_store();
    assert_eq!(
        send_reset(&backfill_tx, 1, 100).await,
        WalletBackfillResetResult::accepted_pending(
            1,
            120,
            Some(WalletBackfillRejectReason::PersistenceFailed),
        )
    );
    let token = handle.mint_sync_token(1);
    cache_store.fail_next_store();
    assert!(matches!(
        send_start_token(&backfill_tx, 130, token).await,
        WalletBackfillStartResult::Rejected {
            reason: WalletBackfillRejectReason::PersistenceFailed
                | WalletBackfillRejectReason::Shutdown,
            ..
        }
    ));

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let state = db
                .get_wallet_sync_actor_state(1, handle.cache_key.as_str())
                .expect("load wallet sync actor state");
            if state.is_some_and(|state| state.pending_reset.is_none()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("pending reset retry committed");

    assert_eq!(
        send_target_token(&backfill_tx, 130, token).await,
        WalletBackfillFinishResult::Rejected {
            committed_to: 99,
            reason: WalletBackfillRejectReason::Shutdown,
        }
    );

    let replay_lease = match backfill_request_rx
        .recv()
        .await
        .expect("actor-owned reset replay request")
    {
        BackfillRequest::Add { driver, .. } => driver,
        BackfillRequest::Remove { .. } => panic!("expected reset replay add request"),
    };
    assert_eq!(
        replay_lease
            .apply("test", indexed_delta_batch(100, 130, empty_delta()))
            .await,
        WalletBackfillApplyResult::Committed { committed_to: 130 }
    );
    assert_eq!(
        replay_lease.finish("test", 130).await,
        WalletBackfillFinishResult::Ready { committed_to: 130 }
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_reset_boundary_ahead_of_lagging_cursor_does_not_synthesize_progress() {
    let root_dir = temp_db_root("wallet-reset-boundary-lagging-cursor");
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
        50,
    )
    .await
    .expect("spawn wallet worker");

    assert_eq!(
        send_reset(&backfill_tx, 1, 100).await,
        WalletBackfillResetResult::accepted_committed(1, 50)
    );
    assert_eq!(handle.last_scanned(), Some(50));
    assert_eq!(
        db.get_wallet_meta(&handle.cache_key)
            .expect("load meta")
            .expect("meta persisted")
            .last_scanned_block,
        50
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_reset_covered_positive_replay_target_completes_without_queued_job() {
    let root_dir = temp_db_root("wallet-reset-covered-replay-target");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let (_live_tx, live_rx) = broadcast::channel(8);
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
        120,
    )
    .await
    .expect("spawn wallet worker");

    let (response, result_rx) = oneshot::channel();
    backfill_tx
        .send(BackfillEvent::Reset {
            token: test_reset_token(1),
            from_block: 121,
            replay_plan: WalletResetReplayPlan::new(0, 100, false),
            response,
        })
        .await
        .expect("send covered-target reset");
    assert_eq!(
        result_rx.await.expect("reset response"),
        WalletBackfillResetResult::accepted_committed(1, 120)
    );
    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.readiness() != WalletReadiness::Ready {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("covered replay target becomes ready");

    assert_eq!(handle.last_scanned(), Some(120));
    assert!(backfill_request_rx.try_recv().is_err());

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_newer_reset_merges_pending_reset_boundary() {
    let root_dir = temp_db_root("wallet-reset-newer-merge");
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

    cache_store.fail_next_store();
    assert_eq!(
        send_reset(&backfill_tx, 1, 100).await,
        WalletBackfillResetResult::accepted_pending(
            1,
            120,
            Some(WalletBackfillRejectReason::PersistenceFailed),
        )
    );
    // Accept held, rewind failed: public view is fenced.
    assert_eq!(handle.last_scanned(), None);
    assert_eq!(handle.last_scanned_raw(), 120);
    assert_eq!(
        send_reset(&backfill_tx, 2, 80).await,
        WalletBackfillResetResult::accepted_committed(2, 79)
    );
    assert_eq!(handle.last_scanned(), Some(79));
    assert!(handle.utxos.read().await.is_empty());
    let state = db
        .get_wallet_sync_actor_state(cfg.chain.chain_id, &cfg.cache_key)
        .expect("load sync actor state")
        .expect("sync actor state");
    assert_eq!(state.highest_accepted_reset_intent, 2);
    assert!(state.pending_reset.is_none());
    assert_eq!(
        send_reset(&backfill_tx, 1, 70).await,
        WalletBackfillResetResult::Rejected {
            committed_to: 79,
            reason: WalletBackfillRejectReason::StaleResetIntent {
                accepted: 2,
                actual: 1,
            },
        }
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_reset_commit_clears_stale_pending_overlay() {
    let root_dir = temp_db_root("wallet-reset-clears-pending-overlay");
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
    let expired_wallet_utxo = test_wallet_utxo(106, 8);
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
        vec![wallet_utxo.clone(), expired_wallet_utxo.clone()],
        120,
    )
    .await
    .expect("spawn wallet worker");
    let spent_source = source(121, 0xaa);
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
                    121,
                    121,
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
                120,
            )
            .await
    );
    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.pending_overlay().map(|o| o.pending_spent.clone())
            != Some(vec![pending_spent.clone()])
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("pending overlay applied");
    let now = now_epoch_secs();
    let recent_local =
        WalletPendingSpent::submitted(&wallet_utxo.utxo, Some([0xbb; 32].into()), now);
    let expired_local = WalletPendingSpent::submitted(
        &expired_wallet_utxo.utxo,
        Some([0xcc; 32].into()),
        now.saturating_sub(LOCAL_PENDING_SPENT_TTL.as_secs() + 1),
    );
    {
        let mut overlay = handle.pending_overlay.write().await;
        overlay.local_pending_spent = vec![recent_local.clone(), expired_local];
    }

    assert_eq!(
        send_reset(&backfill_tx, 1, 100).await,
        WalletBackfillResetResult::accepted_committed(1, 99)
    );
    let overlay = handle.pending_overlay().expect("current after rewind");
    assert_eq!(overlay.pending_spent, [] as [WalletPendingSpent; 0]);
    assert!(overlay.new_utxos.is_empty());
    assert_eq!(overlay.local_pending_spent, vec![recent_local]);
    assert!(overlay.local_pending_spent[0].matches_local_utxo(&wallet_utxo));

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_reset_rejects_persistence_failure_without_publishing_rewind() {
    let root_dir = temp_db_root("wallet-reset-persist-failure");
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
    let list_key = default_active_poi_list_keys()[0];
    let external_output = test_wallet_utxo_with_random(110, 17, [0x17; 16]);
    let stale_context = observed_external_pending_output_context(
        &cfg,
        &external_output,
        list_key,
        &source(110, 0xd1),
    );
    let stale_recovery =
        output_poi_recovery_for_pending_context(&stale_context, OutputPoiRecoveryStatus::Submitted);
    let candidate_source = source(110, 0xd3);
    let candidate_note = Note {
        token_hash: U256::from(7),
        value: U256::from(9),
        random: [0x5a; 16],
        npk: U256::from(11),
    };
    let sender_candidate = crate::SenderTransactionCandidate::new(
        cfg.chain.chain_id,
        cfg.cache_key.clone(),
        candidate_source.clone(),
        vec![crate::SenderTransactionCandidateSpend {
            tree: initial_utxo.utxo.tree,
            position: initial_utxo.utxo.position,
            commitment: initial_utxo.utxo.poi.commitment,
        }],
        vec![crate::SenderTransactionCandidateOutput {
            tree: 3,
            position: 18,
            commitment: FixedBytes::from(candidate_note.commitment().to_be_bytes::<32>()),
            note: Some(candidate_note),
        }],
    )
    .expect("sender candidate")
    // Unshield work the rewind removes without completing any validation.
    .with_unshield(Some(crate::SenderTransactionCandidateUnshield {
        railgun_txids: vec![FixedBytes::from([0xd4; 32])],
        outputs_handed_off: false,
    }))
    .expect("sender candidate with unshield work");
    db.put_opaque_wallet_private_row(
        &sender_candidate.namespace(),
        WalletPrivateRecordKind::SenderTransactionCandidate,
        &OpaqueWalletPrivateRow {
            row_id: sender_candidate.row_identity(),
            payload: sender_candidate.encode().expect("encode sender candidate"),
        },
    )
    .expect("seed sender candidate");
    let recovered_output = test_wallet_utxo_with_random(110, 18, [0x18; 16]);
    let mut recovered_context = observed_external_pending_output_context(
        &cfg,
        &recovered_output,
        list_key,
        &candidate_source,
    );
    recovered_context.output_role = PendingOutputPoiRole::RecoveredOutgoing;
    recovered_context.source_operation_id = Some("recovered-sender-output-poi:test".to_string());
    let recovered_recovery = output_poi_recovery_for_pending_context(
        &recovered_context,
        OutputPoiRecoveryStatus::Submitted,
    );
    db.put_pending_output_poi_context(&recovered_context)
        .expect("seed recovered outgoing context");
    db.put_output_poi_recovery(&recovered_recovery)
        .expect("seed recovered outgoing recovery");
    assert_ne!(
        stale_context.output_commitment, initial_utxo.utxo.poi.commitment,
        "external test context must not alias the rewound owned output"
    );
    db.put_pending_output_poi_context(&stale_context)
        .expect("seed external pending context");
    db.put_output_poi_recovery(&stale_recovery)
        .expect("seed external recovery");
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
        vec![initial_utxo],
        120,
    )
    .await
    .expect("spawn wallet worker");
    let workflow_initial = *handle.observation().ppoi_workflow_status();
    assert_eq!(workflow_initial.needs_attention, 2);
    assert_eq!(
        workflow_initial.awaiting_recovery, 2,
        "the candidate's external output and its unshield TXID"
    );
    assert_eq!(workflow_initial.validation_revision, 0);

    assert_eq!(
        send_target(&handle, &backfill_tx, 120, 0).await,
        WalletBackfillFinishResult::Ready { committed_to: 120 }
    );
    let rev_before_reset = *handle.rev_rx.borrow();
    let store_calls_before_reset = cache_store.state().store_calls;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if handle
                .observation()
                .ppoi_workflow_status()
                .awaiting_poi_data
                == 1
                && handle
                    .observation()
                    .ppoi_workflow_status()
                    .retrying_recovery
                    == 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("sender local POI recovery wait state is published");
    let workflow_before_reset = *handle.observation().ppoi_workflow_status();
    cache_store.fail_next_store();

    assert_eq!(
        send_reset(&backfill_tx, 1, 100).await,
        WalletBackfillResetResult::accepted_pending(
            1,
            120,
            Some(WalletBackfillRejectReason::PersistenceFailed),
        )
    );

    assert_eq!(handle.authority_reset_generation(), 1);
    // Accept succeeded, rewind failed: public view is fenced (not pre-reset current).
    let reset_pending_observation = handle.observation();
    assert!(matches!(
        reset_pending_observation.view(),
        WalletViewState::ResetPending {
            intent_id: 1,
            from_block: 100,
            reset_generation: 1,
        }
    ));
    assert_eq!(
        reset_pending_observation.readiness(),
        &WalletReadiness::Syncing
    );
    assert_eq!(handle.last_scanned(), None);
    assert!(handle.utxos_snapshot().is_none());
    assert!(handle.pending_overlay().is_none());
    assert!(handle.current_snapshot().is_none());
    assert_eq!(handle.last_scanned_raw(), 120);
    assert_eq!(handle.readiness(), WalletReadiness::Syncing);
    assert!(!handle.readiness().is_ready());
    assert_eq!(*handle.rev_rx.borrow(), rev_before_reset);
    assert_eq!(
        reset_pending_observation.ppoi_workflow_status(),
        &workflow_before_reset
    );
    let retained_context = db
        .get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &stale_context.output_commitment,
        )
        .expect("load external context after failed rewind")
        .expect("failed rewind retains external context");
    assert_eq!(retained_context.observation, stale_context.observation);
    assert_eq!(
        retained_context.submitted_poi_list_keys,
        stale_context.submitted_poi_list_keys
    );
    assert_eq!(
        retained_context.terminal_error,
        stale_context.terminal_error
    );
    assert!(
        db.get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &stale_context.output_commitment,
        )
        .expect("load recovery after failed rewind")
        .is_some(),
        "failed atomic rewind must retain the matching recovery"
    );
    assert!(
        cache_store
            .get_sender_transaction_candidate(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &sender_candidate.semantic_id(),
            )
            .expect("load candidate after failed rewind")
            .is_some(),
        "failed atomic rewind must retain the sender candidate"
    );
    assert!(
        db.get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &recovered_context.output_commitment,
        )
        .expect("load recovered context after failed rewind")
        .is_some(),
        "failed atomic rewind must retain derived sender context"
    );
    assert!(
        db.get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &recovered_context.output_commitment,
        )
        .expect("load recovered recovery after failed rewind")
        .is_some(),
        "failed atomic rewind must retain derived sender recovery"
    );
    assert_eq!(
        cache_store.state().store_calls,
        store_calls_before_reset + 1
    );
    let state = db
        .get_wallet_sync_actor_state(1, handle.cache_key.as_str())
        .expect("load wallet sync actor state")
        .expect("wallet sync actor state persisted");
    assert_eq!(state.highest_accepted_reset_intent, 1);
    assert_eq!(state.pending_reset.expect("pending reset").from_block, 100);

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if handle.last_scanned() == Some(99) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("actor-owned reset retry commits rewind");
    assert!(handle.utxos.read().await.is_empty());
    let rewound_context = db
        .get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &stale_context.output_commitment,
        )
        .expect("load external context after rewind retry")
        .expect("external proof context is retained");
    assert!(rewound_context.observation.is_none());
    assert_eq!(
        rewound_context.submitted_poi_list_keys,
        [] as [FixedBytes<32>; 0]
    );
    assert!(rewound_context.terminal_error.is_none());
    assert!(
        db.get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &stale_context.output_commitment,
        )
        .expect("load recovery after rewind retry")
        .is_none()
    );
    assert!(
        cache_store
            .get_sender_transaction_candidate(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &sender_candidate.semantic_id(),
            )
            .expect("load candidate after rewind retry")
            .is_none()
    );
    assert!(
        db.get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &recovered_context.output_commitment,
        )
        .expect("load recovered context after rewind retry")
        .is_none()
    );
    assert!(
        db.get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &recovered_context.output_commitment,
        )
        .expect("load recovered recovery after rewind retry")
        .is_none()
    );
    let rewind_observation = handle.observation();
    let WalletViewState::Current(rewound) = rewind_observation.view() else {
        panic!("successful rewind must publish Current");
    };
    assert_eq!(rewound.last_scanned, 99);
    assert_eq!(rewind_observation.readiness(), &WalletReadiness::Syncing);
    assert_eq!(
        rewind_observation.ppoi_workflow_status(),
        &WalletPpoiWorkflowStatus::default()
    );
    assert_ne!(*handle.rev_rx.borrow(), rev_before_reset);
    let state = db
        .get_wallet_sync_actor_state(1, handle.cache_key.as_str())
        .expect("reload wallet sync actor state")
        .expect("wallet sync actor state persisted");
    assert!(state.pending_reset.is_none());

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn reset_current_publication_follows_canonical_apply_and_failure_changes_nothing() {
    let root_dir = temp_db_root("wallet-reset-canonical-publication-order");
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
            backfill_sender: backfill_tx,
            public_data_plane: test_public_data_plane(&db),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        cfg.clone(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        vec![initial_utxo],
        120,
    )
    .await
    .expect("spawn wallet worker");
    assert_eq!(handle.advance_reset_generation().await, Some(1));
    handle.publish_view_for_test(WalletViewState::ResetPending {
        intent_id: 1,
        from_block: 100,
        reset_generation: 1,
    });
    let pending = PendingWalletReset::new(1, 100, 1, WalletResetReplayPlan::new(0, 150, false));
    let (mut actor_state, _unused_observation_rx) = WalletActorState::new(
        1,
        1,
        1,
        120,
        1,
        Some(pending),
        false,
        WalletViewState::ResetPending {
            intent_id: 1,
            from_block: 100,
            reset_generation: 1,
        },
    );
    actor_state.set_observation_publisher_for_test(
        handle
            .observation
            .upgrade()
            .expect("test handle owns observation publisher"),
    );
    let readiness_rx = handle.subscribe_observation();
    let mut last_scanned = 120;
    let mut persist_state = WalletPersistState {
        needs_full_persist: true,
        pending_cache_reset: Some(7),
    };
    let initial_flush_at = Instant::now();
    let mut live_metadata_flush = WalletLiveMetadataFlush::new(120, initial_flush_at);
    let mut observation_rx = handle.subscribe_observation();
    let _ = observation_rx.borrow_and_update();

    cache_store.fail_next_store();
    let failed = WalletResetCommitRequest {
        cache_store: cache_store.as_ref(),
        cfg: &cfg,
        utxos: &handle.utxos,
        worker_handle: &handle,
        pending,
        highest_accepted_reset_intent: 1,
        actor_state: &mut actor_state,
        cancel: &cancel,
        last_scanned: &mut last_scanned,
        persist_state: &mut persist_state,
        live_metadata_flush: &mut live_metadata_flush,
    }
    .commit()
    .await;
    assert_eq!(
        failed.rewind,
        WalletResetRewindOutcome::Deferred {
            committed_to: 120,
            reason: WalletBackfillRejectReason::PersistenceFailed,
        }
    );
    assert_eq!(last_scanned, 120);
    assert_eq!(actor_state.last_scanned(), 120);
    assert!(!actor_state.pending_reset_rewind_committed());
    assert_eq!(handle.last_scanned_raw(), 120);
    assert!(persist_state.needs_full_persist);
    assert_eq!(persist_state.pending_cache_reset, Some(7));
    assert_eq!(live_metadata_flush.last_persisted_block, 120);
    assert_eq!(live_metadata_flush.last_persisted_at, initial_flush_at);
    assert!(matches!(
        observation_rx.borrow().view().clone(),
        WalletViewState::ResetPending { .. }
    ));
    assert!(
        !observation_rx
            .has_changed()
            .expect("observation sender remains active")
    );
    assert_eq!(handle.utxos.read().await.len(), 1);

    let committed = WalletResetCommitRequest {
        cache_store: cache_store.as_ref(),
        cfg: &cfg,
        utxos: &handle.utxos,
        worker_handle: &handle,
        pending,
        highest_accepted_reset_intent: 1,
        actor_state: &mut actor_state,
        cancel: &cancel,
        last_scanned: &mut last_scanned,
        persist_state: &mut persist_state,
        live_metadata_flush: &mut live_metadata_flush,
    }
    .commit()
    .await;
    assert_eq!(
        committed.rewind,
        WalletResetRewindOutcome::Committed { committed_to: 99 }
    );
    assert_eq!(last_scanned, 99);
    assert_eq!(actor_state.last_scanned(), 99);
    assert!(actor_state.pending_reset_rewind_committed());
    assert_eq!(actor_state.test_readiness(), WalletReadiness::Syncing);
    assert_eq!(handle.last_scanned_raw(), 99);
    assert_eq!(handle.readiness(), WalletReadiness::Syncing);
    assert_eq!(readiness_rx.borrow().readiness(), &WalletReadiness::Syncing);
    assert!(!persist_state.needs_full_persist);
    assert_eq!(persist_state.pending_cache_reset, None);
    assert_eq!(live_metadata_flush.last_persisted_block, 99);
    assert!(
        observation_rx
            .has_changed()
            .expect("rewound observation was published")
    );
    let observation = observation_rx.borrow_and_update().clone();
    let WalletViewState::Current(current) = observation.view().clone() else {
        panic!("first post-reset publication must be Current");
    };
    assert_eq!(observation.readiness(), &WalletReadiness::Syncing);
    assert_eq!(current.last_scanned, actor_state.last_scanned());
    assert_eq!(current.last_scanned, last_scanned);
    assert_eq!(current.reset_generation, actor_state.reset_generation());
    assert!(current.utxos.is_empty());

    cancel.cancel();
    drop(handle);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_reset_commit_publishes_retained_ppoi_submissions_with_current_view() {
    let root_dir = temp_db_root("wallet-reset-ppoi-projection");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    let mut cfg = wallet_config();
    cfg.cache_store = Some(cache_store.clone());
    let list_key = default_active_poi_list_keys()[0];
    let preserved_output = test_wallet_utxo_with_random(90, 17, [0xd1; 16]);
    let preserved_context = observed_external_pending_output_context(
        &cfg,
        &preserved_output,
        list_key,
        &source(90, 0xd1),
    );
    let preserved_recovery = output_poi_recovery_for_pending_context(
        &preserved_context,
        OutputPoiRecoveryStatus::Submitted,
    );
    db.put_pending_output_poi_context(&preserved_context)
        .expect("seed retained pending context");
    db.put_output_poi_recovery(&preserved_recovery)
        .expect("seed retained recovery");

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
        cfg.clone(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        vec![test_wallet_utxo(105, 7)],
        120,
    )
    .await
    .expect("prepare wallet worker");
    assert!(prepared.handle().activate_actor());
    let handle = prepared.handle();
    assert_eq!(handle.advance_reset_generation().await, Some(1));

    let expected_submission = WalletPpoiSubmissionStatus {
        output_commitment: preserved_context.output_commitment,
        last_submission_at: preserved_recovery
            .last_submission_at
            .expect("submission time"),
    };
    assert_eq!(
        handle.observation().ppoi_submission_statuses(),
        std::slice::from_ref(&expected_submission)
    );

    let mut observation_rx = handle.subscribe_observation();
    let _ = observation_rx.borrow_and_update();
    handle.publish_view_for_test(WalletViewState::ResetPending {
        intent_id: 1,
        from_block: 100,
        reset_generation: 1,
    });
    assert!(
        observation_rx
            .has_changed()
            .expect("observation sender remains active")
    );
    let reset_pending_observation = observation_rx.borrow_and_update().clone();
    assert!(matches!(
        reset_pending_observation.view(),
        WalletViewState::ResetPending { .. }
    ));
    assert_eq!(
        reset_pending_observation.ppoi_submission_statuses(),
        [] as [WalletPpoiSubmissionStatus; 0]
    );

    let pending = PendingWalletReset::new(1, 100, 1, WalletResetReplayPlan::new(0, 150, false));
    let (mut actor_state, _unused_observation_rx) = WalletActorState::new(
        1,
        1,
        1,
        120,
        1,
        Some(pending),
        false,
        WalletViewState::ResetPending {
            intent_id: 1,
            from_block: 100,
            reset_generation: 1,
        },
    );
    actor_state.set_observation_publisher_for_test(
        handle
            .observation
            .upgrade()
            .expect("test handle owns observation publisher"),
    );
    let mut last_scanned = 120;
    let mut persist_state = WalletPersistState {
        needs_full_persist: true,
        pending_cache_reset: Some(7),
    };
    let initial_flush_at = Instant::now();
    let mut live_metadata_flush = WalletLiveMetadataFlush::new(120, initial_flush_at);

    let committed = WalletResetCommitRequest {
        cache_store: cache_store.as_ref(),
        cfg: &cfg,
        utxos: &handle.utxos,
        worker_handle: handle,
        pending,
        highest_accepted_reset_intent: 1,
        actor_state: &mut actor_state,
        cancel: &cancel,
        last_scanned: &mut last_scanned,
        persist_state: &mut persist_state,
        live_metadata_flush: &mut live_metadata_flush,
    }
    .commit()
    .await;
    assert_eq!(
        committed.rewind,
        WalletResetRewindOutcome::Committed { committed_to: 99 }
    );

    assert!(
        observation_rx
            .has_changed()
            .expect("rewound observation was published")
    );
    let observation = observation_rx.borrow_and_update().clone();
    assert!(matches!(observation.view(), WalletViewState::Current(_)));
    assert_eq!(
        observation.ppoi_submission_statuses(),
        std::slice::from_ref(&expected_submission)
    );

    cancel.cancel();
    drop(prepared);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db root");
}

#[tokio::test]
async fn wallet_reset_commit_discards_pending_contexts_for_rewound_outputs() {
    let root_dir = temp_db_root("wallet-reset-pending-context-cleanup");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    let mut cfg = wallet_config();
    cfg.cache_store = Some(cache_store.clone());
    let initial_utxo = test_wallet_utxo(105, 7);
    let output_commitment = initial_utxo.utxo.poi.commitment;
    db.put_pending_output_poi_context(&pending_output_context_for_wallet_utxo(&cfg, &initial_utxo))
        .expect("seed pending context");
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
        vec![initial_utxo],
        120,
    )
    .await
    .expect("spawn wallet worker");

    assert_eq!(
        send_reset(&backfill_tx, 1, 100).await,
        WalletBackfillResetResult::accepted_committed(1, 99)
    );

    assert_eq!(handle.last_scanned(), Some(99));
    assert!(handle.utxos.read().await.is_empty());
    let state = db
        .get_wallet_sync_actor_state(cfg.chain.chain_id, &cfg.cache_key)
        .expect("load wallet sync actor state")
        .expect("wallet sync actor state persisted");
    assert_eq!(state.highest_accepted_reset_intent, 1);
    assert!(state.pending_reset.is_none());
    assert!(
        db.get_pending_output_poi_context(cfg.chain.chain_id, &cfg.cache_key, &output_commitment)
            .expect("load pending context")
            .is_none()
    );
    assert_eq!(cache_store.state().store_calls, 1);

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_reset_rewinds_external_pending_observation_for_canonical_replay() {
    let root_dir = temp_db_root("wallet-reset-external-pending-observation");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cfg = wallet_config();
    let list_key = default_active_poi_list_keys()[0];
    let external_output = test_wallet_utxo_with_random(110, 17, [0x17; 16]);
    let mut stale_context = observed_external_pending_output_context(
        &cfg,
        &external_output,
        list_key,
        &source(110, 0xd2),
    );
    stale_context.pre_transaction_pois_per_txid_leaf_per_list = current_pending_proof_map(list_key);
    let stale_observation = stale_context
        .observation
        .clone()
        .expect("stale observation");
    let stale_identity = pending_output_poi_submit_identity(&stale_context, &stale_observation)
        .expect("stale external identity");
    let stale_subject = PendingOutputPoiSubject::External {
        output_commitment: stale_context.output_commitment,
        derived_blinded_commitment: stale_identity.derived_blinded_commitment,
    };
    let stale_recovery =
        output_poi_recovery_for_pending_context(&stale_context, OutputPoiRecoveryStatus::Submitted);
    let stale_plan = PendingOutputPoiSubmissionPlan::force_matching(
        vec![list_key],
        expected_recovery_state(Some(&stale_recovery)).expect("recovery fingerprint"),
    );
    db.put_pending_output_poi_context(&stale_context)
        .expect("seed external pending context");
    db.put_output_poi_recovery(&stale_recovery)
        .expect("seed stale external recovery");

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
        Vec::new(),
        120,
    )
    .await
    .expect("spawn wallet worker");

    assert_eq!(
        send_reset(&backfill_tx, 1, 100).await,
        WalletBackfillResetResult::accepted_committed(1, 99)
    );
    assert_eq!(
        handle.observation().ppoi_workflow_status(),
        &WalletPpoiWorkflowStatus::default()
    );
    let rewound = db
        .get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &stale_context.output_commitment,
        )
        .expect("load rewound external context")
        .expect("retain immutable external proof context");
    assert!(rewound.observation.is_none());
    assert_eq!(rewound.submitted_poi_list_keys, [] as [FixedBytes<32>; 0]);
    assert!(rewound.terminal_error.is_none());
    assert_eq!(rewound.railgun_txid, stale_context.railgun_txid);
    assert_eq!(
        rewound.pre_transaction_pois_per_txid_leaf_per_list.len(),
        stale_context
            .pre_transaction_pois_per_txid_leaf_per_list
            .len()
    );
    assert!(
        db.get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &stale_context.output_commitment,
        )
        .expect("load rewound recovery")
        .is_none()
    );

    let authority = WalletPrivateMutationAuthority::new(&handle, 1, &cancel);
    assert_eq!(
        pending_output_poi_submission_plan_current(
            &authority,
            &test_public_data_plane(&db),
            db.as_ref(),
            &cfg,
            &[list_key],
            &stale_context,
            &stale_subject,
            &stale_plan,
        )
        .await
        .expect("stale submission preflight"),
        PendingOutputPoiPreflight::NotCurrent,
        "a submission planned from the rewound observation must be rejected"
    );

    db.put_pending_output_poi_context(&stale_context)
        .expect("reseed legacy stale observation to exercise scan reconciliation");
    db.put_output_poi_recovery(&stale_recovery)
        .expect("reseed legacy stale recovery to exercise scan reconciliation");
    let canonical_source = source(105, 0xe2);
    let canonical_observation = CommitmentObservation {
        tree: 3,
        position: 21,
        commitment: U256::from_be_bytes(stale_context.output_commitment.0),
        source: canonical_source.clone(),
    };
    assert_eq!(
        send_apply(
            &handle,
            &backfill_tx,
            indexed_delta_batch(
                100,
                110,
                WalletLogDelta {
                    utxos: Vec::new(),
                    nullifiers: Vec::new(),
                    commitment_observations: vec![canonical_observation],
                    sender_scan_outputs: Vec::new(),
                },
            ),
            1,
        )
        .await,
        WalletBackfillApplyResult::Committed { committed_to: 110 }
    );

    let canonical = db
        .get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &stale_context.output_commitment,
        )
        .expect("load canonical external context")
        .expect("canonical external context");
    let observed = canonical
        .observation
        .as_ref()
        .expect("canonical observation attached");
    assert_eq!(observed.output_tree, 3);
    assert_eq!(observed.output_position, 21);
    assert_eq!(observed.tx_hash, canonical_source.tx_hash);
    assert_eq!(canonical.submitted_poi_list_keys, [] as [FixedBytes<32>; 0]);
    assert!(canonical.terminal_error.is_none());
    assert_eq!(canonical.missing_list_keys(), vec![list_key]);
    assert_eq!(
        handle.observation().ppoi_workflow_status(),
        &WalletPpoiWorkflowStatus {
            awaiting_submission: 1,
            ..WalletPpoiWorkflowStatus::default()
        }
    );
    assert!(
        db.get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &canonical.output_commitment,
        )
        .expect("load canonical recovery state")
        .is_none()
    );

    let (canonical_subject, owned_output) =
        current_pending_output_poi_subject(&authority, &cfg, &canonical)
            .await
            .expect("canonical external subject is authorized");
    assert!(owned_output.is_none());
    let canonical_plan = PendingOutputPoiSubmissionPlan::force_matching(
        vec![list_key],
        expected_recovery_state(None).expect("absent recovery state"),
    );
    assert_eq!(
        pending_output_poi_submission_plan_current(
            &authority,
            &test_public_data_plane(&db),
            db.as_ref(),
            &cfg,
            &[list_key],
            &canonical,
            &canonical_subject,
            &canonical_plan,
        )
        .await
        .expect("canonical submission preflight"),
        PendingOutputPoiPreflight::Ready
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
