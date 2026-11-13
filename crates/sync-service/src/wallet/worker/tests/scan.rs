use super::*;

fn sender_scan_output(sender: &ViewingKeyData, source: UtxoSource) -> SenderScanOutput {
    let receiver =
        ViewingKeyData::from_spending_public_key([9; 32], [U256::from(13), U256::from(14)]);
    let note = Note::new_change(
        receiver.master_public_key,
        Address::ZERO,
        U256::from(30),
        [0x31; 16],
    );
    let ciphertext: CommitmentCiphertext = NoteCiphertext::try_from_note(
        &note,
        &sender.address_data(),
        &receiver.address_data(),
        &sender.viewing_private_key,
    )
    .expect("encrypt sender output")
    .into();
    SenderScanOutput {
        tree: 3,
        position: 10,
        commitment: note.commitment(),
        ciphertext,
        source,
    }
}

#[test]
fn wallet_scan_progress_retains_configured_baseline_across_pages() {
    const DEPLOYMENT_BLOCK: u64 = 14_737_691;
    const CURRENT_BLOCK: u64 = 25_305_894;
    const TARGET_BLOCK: u64 = 25_537_418;

    let observed_page = wallet_scan_progress_update(
        Some(DEPLOYMENT_BLOCK),
        25_083_449,
        CURRENT_BLOCK,
        TARGET_BLOCK,
        PublicScanSource::Rpc,
    );
    let later_page = wallet_scan_progress_update(
        Some(DEPLOYMENT_BLOCK),
        CURRENT_BLOCK.saturating_add(1),
        25_500_000,
        TARGET_BLOCK,
        PublicScanSource::ArchiveRpc,
    );

    assert_eq!(observed_page.start_block, DEPLOYMENT_BLOCK);
    assert_eq!(observed_page.percent(), 97);
    assert_eq!(observed_page.source, Some(PublicScanSource::Rpc));
    assert_eq!(later_page.start_block, DEPLOYMENT_BLOCK);
    assert!(later_page.percent() >= observed_page.percent());
    assert_eq!(later_page.source, Some(PublicScanSource::ArchiveRpc));

    let fallback = wallet_scan_progress_update(
        None,
        25_083_449,
        CURRENT_BLOCK,
        TARGET_BLOCK,
        PublicScanSource::CachedCoverage,
    );
    assert_eq!(fallback.start_block, 25_083_449);
    assert_eq!(fallback.percent(), 49);
    assert_eq!(fallback.source, Some(PublicScanSource::CachedCoverage));
}

#[tokio::test]
async fn live_scan_publishes_syncing_before_blocked_commit() {
    let root_dir = temp_db_root("wallet-live-readiness-before-commit");
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
    assert_eq!(handle.last_scanned(), Some(100));

    drop(held);
    wait_for_readiness(&mut readiness_rx, WalletReadiness::Ready).await;
    assert_eq!(handle.last_scanned(), Some(101));

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_worker_applies_live_batch_queued_before_done() {
    let root_dir = temp_db_root("wallet-worker-live-before-done");
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
    let public_data_plane = test_public_data_plane(&db);
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),

            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: backfill_tx.clone(),
            public_data_plane: public_data_plane.clone(),
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
    live_tx
        .send(Arc::new(LogBatch {
            from_block: 101,
            to_block: 101,
            logs: Vec::new(),
            block_timestamps: HashMap::new(),
            to_block_hash: None,
            read_scope: test_public_scan_read_scope(),
        }))
        .expect("live receiver");
    tokio::task::yield_now().await;
    assert_eq!(handle.last_scanned(), Some(100));

    let initial_token = handle.mint_sync_token(0);
    assert_eq!(
        send_target_token(&backfill_tx, 100, initial_token).await,
        WalletBackfillFinishResult::Ready { committed_to: 100 }
    );
    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.last_scanned() != Some(101) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("queued live batch applied after done");

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_live_persist_failure_retains_exact_retry_until_cursor_recovers() {
    let root_dir = temp_db_root("wallet-worker-live-persist-failure");
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
    let public_data_plane = test_public_data_plane(&db);
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),

            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: backfill_tx.clone(),
            public_data_plane: public_data_plane.clone(),
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

    let initial_token = handle.mint_sync_token(0);
    assert_eq!(
        send_target_token(&backfill_tx, 100, initial_token).await,
        WalletBackfillFinishResult::Ready { committed_to: 100 }
    );
    cache_store.fail_next_meta();
    live_tx
        .send(Arc::new(LogBatch {
            from_block: 101,
            to_block: 101,
            logs: Vec::new(),
            block_timestamps: HashMap::new(),
            to_block_hash: None,
            read_scope: test_public_scan_read_scope(),
        }))
        .expect("live receiver");

    tokio::time::timeout(Duration::from_secs(1), async {
        while !matches!(
            handle.readiness(),
            WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
        ) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("live persist failure observed");

    assert_eq!(handle.last_scanned(), Some(100));
    assert!(!handle.readiness().is_ready());
    assert_eq!(cache_store.state().meta_calls, 1);

    let retry = tokio::time::timeout(Duration::from_secs(1), backfill_request_rx.recv())
        .await
        .expect("live persistence retry requested")
        .expect("backfill request channel open");
    let BackfillRequest::Add {
        from_block,
        to_block,
        follow_safe_head,
        progress_start_block,
        driver,
        ..
    } = retry
    else {
        panic!("expected live persistence retry request");
    };
    assert_eq!((from_block, to_block), (101, 101));
    assert_eq!(progress_start_block, 101);
    assert!(!follow_safe_head);

    assert_eq!(
        send_target(&handle, &backfill_tx, 100, 0).await,
        WalletBackfillFinishResult::Ready { committed_to: 100 }
    );
    assert_eq!(
        handle.readiness(),
        WalletReadiness::Failed(WalletReadinessError::PersistenceFailed),
        "cursorless completion for unrelated work must not recover failed live progress"
    );

    assert_eq!(
        driver.apply("test", logs_apply(101, 101)).await,
        WalletBackfillApplyResult::Committed { committed_to: 101 }
    );
    assert_eq!(
        driver.finish("test", 101).await,
        WalletBackfillFinishResult::Ready { committed_to: 101 }
    );
    assert_eq!(handle.last_scanned(), Some(101));
    assert_eq!(handle.readiness(), WalletReadiness::Ready);

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_backfill_partial_indexed_tail_leaves_wallet_non_ready() {
    let root_dir = temp_db_root("wallet-partial-indexed-tail-non-ready");
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
    let public_data_plane = test_public_data_plane(&db);
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),

            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_wallet_poi_runtime(),
            forest: Arc::new(RwLock::new(MerkleForest::new())),
            backfill_tx: backfill_request_tx,
            backfill_sender: backfill_tx.clone(),
            public_data_plane: public_data_plane.clone(),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        wallet_config(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        900,
    )
    .await
    .expect("spawn wallet worker");
    assert_eq!(
        send_target(&handle, &backfill_tx, 900, 0).await,
        WalletBackfillFinishResult::Ready { committed_to: 900 }
    );
    assert_eq!(handle.readiness(), WalletReadiness::Ready);
    let tail_token = handle.mint_sync_token(0);
    let tail_lease = assert_start_accepted(
        send_start_token(&backfill_tx, 1000, tail_token).await,
        tail_token,
        900,
        1000,
    );
    assert_eq!(
        tail_lease
            .apply("test", indexed_delta_batch(901, 950, empty_delta()))
            .await,
        WalletBackfillApplyResult::Committed { committed_to: 950 }
    );

    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.last_scanned() != Some(950) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("partial indexed tail applied");
    assert_eq!(handle.readiness(), WalletReadiness::Syncing);
    assert!(!handle.readiness().is_ready());
    assert_eq!(handle.readiness(), WalletReadiness::Syncing);

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_worker_applies_indexed_tail_delta_after_prior_wallet_delta() {
    let root_dir = temp_db_root("wallet-worker-indexed-tail-order");
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
    let wallet_utxo = test_wallet_utxo(105, 7);
    let nullifier = wallet_utxo.utxo.nullifier(U256::ZERO);

    assert_eq!(
        send_apply(
            &handle,
            &backfill_tx,
            indexed_delta_batch(
                101,
                110,
                WalletLogDelta {
                    utxos: vec![wallet_utxo.utxo.clone()],
                    nullifiers: Vec::new(),
                    commitment_observations: Vec::new(),
                    sender_scan_outputs: Vec::new(),
                },
            ),
            0,
        )
        .await,
        WalletBackfillApplyResult::Committed { committed_to: 110 }
    );
    assert_eq!(
        send_apply(
            &handle,
            &backfill_tx,
            indexed_delta_batch(
                111,
                120,
                WalletLogDelta {
                    utxos: Vec::new(),
                    nullifiers: vec![SpentNullifier {
                        tree: wallet_utxo.utxo.tree,
                        nullifier,
                        source: source(120, 0x78),
                    }],
                    commitment_observations: Vec::new(),
                    sender_scan_outputs: Vec::new(),
                },
            ),
            0,
        )
        .await,
        WalletBackfillApplyResult::Committed { committed_to: 120 }
    );

    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.last_scanned() != Some(120) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("indexed deltas applied");

    let snapshot = handle.utxos.read().await;
    assert_eq!(snapshot.len(), 1);
    assert!(snapshot[0].spent.is_some());
    assert_eq!(
        handle.pending_overlay.read().await.local_pending_spent,
        [] as [WalletPendingSpent; 0]
    );

    cancel.cancel();
    drop(snapshot);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_worker_rejects_persistence_failure_without_swapping_state() {
    let root_dir = temp_db_root("wallet-worker-apply-persist-failure");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    cache_store.fail_next_store();
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
    assert_eq!(
        send_apply(
            &handle,
            &backfill_tx,
            indexed_delta_batch(
                101,
                110,
                WalletLogDelta {
                    utxos: vec![test_wallet_utxo(105, 7).utxo],
                    nullifiers: Vec::new(),
                    commitment_observations: Vec::new(),
                    sender_scan_outputs: Vec::new(),
                },
            ),
            0,
        )
        .await,
        WalletBackfillApplyResult::Rejected {
            committed_to: 100,
            reason: WalletBackfillRejectReason::PersistenceFailed,
        }
    );

    assert_eq!(handle.last_scanned(), Some(100));
    assert_eq!(
        handle.readiness(),
        WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
    );
    assert!(!handle.readiness().is_ready());
    assert_eq!(*handle.rev_rx.borrow(), 0);
    assert!(handle.utxos.read().await.is_empty());
    assert_eq!(cache_store.state().store_calls, 1);

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_scan_candidate_persist_failure_keeps_checkpoint_and_pending_context() {
    let root_dir = temp_db_root("wallet-worker-spent-pending-context-persist-failure");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    cache_store.fail_next_store();
    let mut cfg = wallet_config();
    let scan_keys =
        ViewingKeyData::from_spending_public_key([7; 32], [U256::from(11), U256::from(12)]);
    cfg.scan_keys = scan_keys;
    cfg.cache_store = Some(cache_store.clone());
    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let wallet_utxo = test_wallet_utxo(105, 7);
    let output_commitment = wallet_utxo.utxo.poi.commitment;
    db.put_pending_output_poi_context(&pending_output_context_for_wallet_utxo(&cfg, &wallet_utxo))
        .expect("store pending context");
    let nullifier = wallet_utxo.utxo.nullifier(scan_keys.nullifying_key);
    let spent_source = source(110, 0x77);
    db.put_wallet_meta(
        &cfg.cache_key,
        &WalletMeta {
            last_scanned_block: 100,
            updated_at: 1,
            last_scanned_block_hash: Some([0x64; 32]),
        },
    )
    .expect("seed checkpoint");
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
        vec![wallet_utxo.clone()],
        100,
    )
    .await
    .expect("spawn wallet worker");

    assert_eq!(
        send_apply(
            &handle,
            &backfill_tx,
            indexed_delta_batch(
                101,
                110,
                WalletLogDelta {
                    utxos: Vec::new(),
                    nullifiers: vec![SpentNullifier {
                        tree: wallet_utxo.utxo.tree,
                        nullifier,
                        source: spent_source.clone(),
                    }],
                    commitment_observations: Vec::new(),
                    sender_scan_outputs: vec![
                        sender_scan_output(&scan_keys, spent_source.clone(),)
                    ],
                },
            ),
            0,
        )
        .await,
        WalletBackfillApplyResult::Rejected {
            committed_to: 100,
            reason: WalletBackfillRejectReason::PersistenceFailed,
        }
    );

    assert_eq!(handle.last_scanned(), Some(100));
    let snapshot = handle.utxos.read().await;
    assert_eq!(snapshot.len(), 1);
    assert!(snapshot[0].spent.is_none());
    assert_eq!(
        db.get_wallet_meta(&cfg.cache_key)
            .expect("load retained checkpoint")
            .expect("checkpoint present")
            .last_scanned_block,
        100
    );
    assert!(
        cache_store
            .list_sender_transaction_candidates(cfg.chain.chain_id, &cfg.cache_key)
            .expect("list candidates")
            .is_empty()
    );
    assert!(
        db.get_pending_output_poi_context(cfg.chain.chain_id, &cfg.cache_key, &output_commitment)
            .expect("load pending context")
            .is_some()
    );

    cancel.cancel();
    drop(snapshot);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_scan_commit_discards_spent_pending_context_with_progress() {
    let root_dir = temp_db_root("wallet-worker-spent-pending-context-commit");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let mut cfg = wallet_config();
    let scan_keys =
        ViewingKeyData::from_spending_public_key([7; 32], [U256::from(11), U256::from(12)]);
    cfg.scan_keys = scan_keys;
    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let wallet_utxo = test_wallet_utxo(105, 7);
    let output_commitment = wallet_utxo.utxo.poi.commitment;
    db.put_pending_output_poi_context(&pending_output_context_for_wallet_utxo(&cfg, &wallet_utxo))
        .expect("store pending context");
    let nullifier = wallet_utxo.utxo.nullifier(scan_keys.nullifying_key);
    let spent_source = source(110, 0x77);
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
        vec![wallet_utxo.clone()],
        100,
    )
    .await
    .expect("spawn wallet worker");

    assert_eq!(
        handle
            .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), None)
            .await,
        Ok(WalletPendingSpentMarkOutcome::Marked)
    );
    assert_eq!(
        send_apply(
            &handle,
            &backfill_tx,
            indexed_delta_batch(
                101,
                110,
                WalletLogDelta {
                    utxos: Vec::new(),
                    nullifiers: vec![SpentNullifier {
                        tree: wallet_utxo.utxo.tree,
                        nullifier,
                        source: spent_source.clone(),
                    }],
                    commitment_observations: Vec::new(),
                    sender_scan_outputs: vec![
                        sender_scan_output(&scan_keys, spent_source.clone(),)
                    ],
                },
            ),
            0,
        )
        .await,
        WalletBackfillApplyResult::Committed { committed_to: 110 }
    );

    assert_eq!(handle.last_scanned(), Some(110));
    let snapshot = handle.utxos.read().await;
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].spent, Some(spent_source.clone()));
    let persisted = db
        .load_wallet_utxos(&cfg.cache_key)
        .expect("load persisted wallet snapshot");
    assert_eq!(persisted[0].spent, Some(spent_source.clone()));
    let candidates = db
        .list_sender_transaction_candidates(cfg.chain.chain_id, &cfg.cache_key)
        .expect("list persisted candidates");
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].source, spent_source);
    assert!(
        db.get_pending_output_poi_context(cfg.chain.chain_id, &cfg.cache_key, &output_commitment)
            .expect("load pending context")
            .is_none()
    );

    cancel.cancel();
    drop(snapshot);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_scan_commit_does_not_perform_inline_poi_status_refresh() {
    // Architectural invariant: scan commit never awaits POI status I/O.
    // Remote/local status refresh is scheduled via PoiMaintenanceJob instead.
    const DEPLOYMENT_BLOCK: u64 = 14_737_691;
    const PAGE_FROM_BLOCK: u64 = 25_083_449;
    const CURRENT_BLOCK: u64 = 25_305_894;
    const TARGET_BLOCK: u64 = 25_537_418;
    let root_dir = temp_db_root("wallet-scan-commit-no-inline-poi");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    let mut cfg = wallet_config();
    cfg.cache_store = Some(cache_store.clone());
    cfg.start_block = Some(DEPLOYMENT_BLOCK);
    let (progress_tx, progress_rx) = watch::channel(None);
    cfg.progress_tx = Some(progress_tx);
    let wallet_utxo = test_wallet_utxo(CURRENT_BLOCK, 7);
    let (started_tx, _started_rx) = oneshot::channel();
    let (_release, release_rx) = oneshot::channel();
    // If scan commit still awaited status refresh, this would hang forever.
    let _blocking_reader = Arc::new(BlockingPoiStatusReader::new(started_tx, release_rx));
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
        cfg.clone(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        PAGE_FROM_BLOCK.saturating_sub(1),
    )
    .await
    .expect("spawn wallet worker");
    let mut last_scanned = PAGE_FROM_BLOCK.saturating_sub(1);
    let mut persist_state = WalletPersistState::default();
    let mut live_metadata_flush =
        WalletLiveMetadataFlush::new(PAGE_FROM_BLOCK.saturating_sub(1), Instant::now());
    let (mut actor_state, _readiness_rx) =
        test_actor_state_for_handle(&handle, PAGE_FROM_BLOCK.saturating_sub(1));
    let job_token = WalletSyncToken::for_test(1, 1, 0, 1);
    assert!(actor_state.test_transition(|mut state| state.accept_target(job_token, TARGET_BLOCK)));
    let public_data_plane = test_public_data_plane(&db);
    let outcome = tokio::time::timeout(
        Duration::from_secs(2),
        WalletScanCommitRequest {
            cache_store: cache_store.as_ref(),
            cfg: &cfg,
            utxos: &handle.utxos,
            worker_handle: &handle,
            apply: indexed_delta_batch(
                PAGE_FROM_BLOCK,
                CURRENT_BLOCK,
                WalletLogDelta {
                    utxos: vec![wallet_utxo.utxo],
                    nullifiers: Vec::new(),
                    commitment_observations: Vec::new(),
                    sender_scan_outputs: Vec::new(),
                },
            ),
            job_token,
            current_reset_generation: 0,
            event_reset_generation: 0,
            actor_state: &mut actor_state,
            cancel: &cancel,
            last_scanned: &mut last_scanned,
            persist_state: &mut persist_state,
            live_metadata_flush: &mut live_metadata_flush,
            public_data_plane: &public_data_plane,
        }
        .commit(),
    )
    .await
    .expect("scan commit must not block on POI status I/O");

    assert!(matches!(
        outcome.result,
        WalletBackfillApplyResult::Committed { .. }
    ));
    assert!(outcome.changed);
    assert_eq!(handle.last_scanned(), Some(CURRENT_BLOCK));
    let observed_progress = progress_rx.borrow().expect("wallet scan progress");
    assert_eq!(observed_progress.start_block, DEPLOYMENT_BLOCK);
    assert_eq!(observed_progress.current_block, CURRENT_BLOCK);
    assert_eq!(observed_progress.target_block, TARGET_BLOCK);
    assert_eq!(observed_progress.percent(), 97);
    assert_eq!(
        observed_progress.source,
        Some(PublicScanSource::IndexedArtifacts)
    );

    let mut later_apply = indexed_delta_batch(
        CURRENT_BLOCK.saturating_add(1),
        TARGET_BLOCK,
        WalletLogDelta {
            utxos: Vec::new(),
            nullifiers: Vec::new(),
            commitment_observations: Vec::new(),
            sender_scan_outputs: Vec::new(),
        },
    );
    later_apply.rows.source = PublicScanSource::Rpc;
    let later_outcome = WalletScanCommitRequest {
        cache_store: cache_store.as_ref(),
        cfg: &cfg,
        utxos: &handle.utxos,
        worker_handle: &handle,
        apply: later_apply,
        job_token,
        current_reset_generation: 0,
        event_reset_generation: 0,
        actor_state: &mut actor_state,
        cancel: &cancel,
        last_scanned: &mut last_scanned,
        persist_state: &mut persist_state,
        live_metadata_flush: &mut live_metadata_flush,
        public_data_plane: &public_data_plane,
    }
    .commit()
    .await;
    assert!(matches!(
        later_outcome.result,
        WalletBackfillApplyResult::Committed { .. }
    ));
    let completed_progress = progress_rx
        .borrow()
        .expect("completed wallet scan progress");
    assert_eq!(completed_progress.start_block, DEPLOYMENT_BLOCK);
    assert_eq!(completed_progress.current_block, TARGET_BLOCK);
    assert_eq!(completed_progress.percent(), 100);
    assert_eq!(completed_progress.source, Some(PublicScanSource::Rpc));

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn readiness_transitions_recover_only_matching_persistence_failure() {
    let (mut state, readiness_rx) = test_actor_state_with_observation(10);
    let completed = WalletSyncToken::for_test(1, 1, 0, 1);
    state.test_transition(|mut state| {
        assert!(state.accept_target(completed, 10));
        assert!(state.complete_backfill_job(completed));
    });
    assert_eq!(readiness_rx.borrow().readiness(), &WalletReadiness::Ready);

    state.test_transition(|mut state| {
        state.poi_status_persist_failed(0, WalletPoiRefreshSelection::RequiredOrRecoverable);
    });
    assert_eq!(
        readiness_rx.borrow().readiness(),
        &WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
    );

    state.test_transition(|mut state| state.durable_reset_replay_commit_ok(1));
    assert_eq!(
        readiness_rx.borrow().readiness(),
        &WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
    );

    state.test_transition(|mut state| {
        state.durable_poi_status_commit_ok(0, WalletPoiRefreshSelection::RequiredOrRecoverable);
    });
    assert_eq!(readiness_rx.borrow().readiness(), &WalletReadiness::Ready);

    let pending = WalletSyncToken::for_test(1, 1, 0, 2);
    state.test_transition(|mut state| {
        assert!(state.accept_target(pending, 20));
        assert!(state.sync_progress_persist_failed(pending, 11, 20));
    });
    assert_eq!(
        readiness_rx.borrow().readiness(),
        &WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
    );
    state.test_transition(|mut state| {
        assert!(state.durable_sync_progress_commit_ok(pending, 11, 20));
    });
    assert_eq!(state.last_scanned(), 20);
    assert_eq!(readiness_rx.borrow().readiness(), &WalletReadiness::Syncing);

    let failed_job = WalletSyncToken::for_test(1, 1, 0, 3);
    state.test_transition(|mut state| {
        assert!(state.accept_target(failed_job, 30));
        assert!(state.fail_job_backfill_unavailable(failed_job));
    });
    assert_eq!(state.last_scanned(), 20);
    assert_eq!(
        readiness_rx.borrow().readiness(),
        &WalletReadiness::Failed(WalletReadinessError::BackfillUnavailable)
    );

    let replacement = WalletSyncToken::for_test(1, 1, 0, 4);
    state.test_transition(|mut state| {
        assert!(state.accept_target(replacement, 30));
        assert!(state.backfill_dispatch_admitted(replacement));
    });
    assert_eq!(readiness_rx.borrow().readiness(), &WalletReadiness::Syncing);
}

#[tokio::test]
async fn wallet_scan_exact_retry_clears_matching_persistence_failure() {
    let root_dir = temp_db_root("wallet-scan-commit-clears-persistence-failed");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    let mut cfg = wallet_config();
    cfg.cache_store = Some(cache_store.clone());
    let wallet_utxo = test_wallet_utxo(105, 7);
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
        cfg.clone(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        100,
    )
    .await
    .expect("spawn wallet worker");
    let mut last_scanned = 100;
    let mut persist_state = WalletPersistState::default();
    let mut live_metadata_flush = WalletLiveMetadataFlush::new(100, Instant::now());
    let (mut actor_state, mut readiness_rx) = test_actor_state_for_handle(&handle, 100);
    let job_token = WalletSyncToken::for_test(1, 1, 0, 1);
    actor_state.test_transition(|mut state| {
        assert!(state.accept_target(job_token, 110));
        assert!(state.sync_progress_persist_failed(job_token, 101, 110));
    });
    assert_eq!(
        readiness_rx.borrow_and_update().readiness(),
        &WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
    );
    assert_eq!(
        actor_state.test_readiness(),
        WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
    );
    let public_data_plane = test_public_data_plane(&db);
    let outcome = WalletScanCommitRequest {
        cache_store: cache_store.as_ref(),
        cfg: &cfg,
        utxos: &handle.utxos,
        worker_handle: &handle,
        apply: indexed_delta_batch(
            101,
            110,
            WalletLogDelta {
                utxos: vec![wallet_utxo.utxo],
                nullifiers: Vec::new(),
                commitment_observations: Vec::new(),
                sender_scan_outputs: Vec::new(),
            },
        ),
        job_token,
        current_reset_generation: 0,
        event_reset_generation: 0,
        actor_state: &mut actor_state,
        cancel: &cancel,
        last_scanned: &mut last_scanned,
        persist_state: &mut persist_state,
        live_metadata_flush: &mut live_metadata_flush,
        public_data_plane: &public_data_plane,
    }
    .commit()
    .await;

    assert!(matches!(
        outcome.result,
        WalletBackfillApplyResult::Committed { .. }
    ));
    assert_eq!(last_scanned, 110);
    assert_eq!(actor_state.last_scanned(), 110);
    assert!(
        readiness_rx
            .has_changed()
            .expect("observation publisher remains active")
    );
    let recovered_observation = readiness_rx.borrow().clone();
    let WalletViewState::Current(recovered_view) = recovered_observation.view() else {
        panic!("successful scan recovery must publish Current");
    };
    assert_eq!(recovered_view.last_scanned, 110);
    assert_eq!(recovered_view.revision, 1);
    assert_eq!(
        recovered_observation.readiness(),
        &WalletReadiness::Syncing,
        "successful scan must publish recovered readiness, not leave PersistenceFailed"
    );
    assert!(!matches!(
        actor_state.test_readiness(),
        WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
    ));

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_worker_marks_ready_after_queued_indexed_startup_delta() {
    let root_dir = temp_db_root("wallet-worker-indexed-startup-ready");
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
    assert_eq!(
        lease
            .apply("test", indexed_delta_batch(101, 200, empty_delta()))
            .await,
        WalletBackfillApplyResult::Committed { committed_to: 200 }
    );
    assert_eq!(
        lease.finish("test", 200).await,
        WalletBackfillFinishResult::Ready { committed_to: 200 }
    );

    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.last_scanned() != Some(200) || handle.readiness() != WalletReadiness::Ready {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("indexed startup done marked ready");

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_worker_rejects_non_contiguous_log_batch() {
    let root_dir = temp_db_root("wallet-worker-log-gap");
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
        send_apply(&handle, &backfill_tx, logs_apply(105, 110), 0).await,
        WalletBackfillApplyResult::Rejected {
            committed_to: 100,
            reason: WalletBackfillRejectReason::NonContiguous {
                expected_from: 101,
                actual_from: 105,
            },
        }
    );
    assert_eq!(handle.last_scanned(), Some(100));

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_worker_bounds_shared_log_payload_to_apply_range_and_target() {
    let root_dir = temp_db_root("wallet-worker-bounded-shared-log-payload");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let mut cfg = wallet_config();
    cfg.sync_to_block = Some(130);
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
        cfg,
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        Vec::new(),
        119,
    )
    .await
    .expect("spawn wallet worker");

    assert_eq!(
        send_apply(
            &handle,
            &backfill_tx,
            WalletScanApply::rows_from_log_batch(
                120,
                130,
                &logs_payload(100, 199),
                PublicScanSource::Rpc,
            )
            .expect("normalize shared log payload"),
            0,
        )
        .await,
        WalletBackfillApplyResult::Committed { committed_to: 130 }
    );
    assert_eq!(handle.last_scanned(), Some(130));
    assert_eq!(
        send_apply(
            &handle,
            &backfill_tx,
            WalletScanApply::rows_from_log_batch(
                131,
                199,
                &logs_payload(100, 199),
                PublicScanSource::Rpc,
            )
            .expect("normalize shared log payload"),
            0,
        )
        .await,
        WalletBackfillApplyResult::Rejected {
            committed_to: 130,
            reason: WalletBackfillRejectReason::TargetExceeded {
                target_block: 130,
                requested_to: 199,
            },
        }
    );
    assert_eq!(handle.last_scanned(), Some(130));

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
