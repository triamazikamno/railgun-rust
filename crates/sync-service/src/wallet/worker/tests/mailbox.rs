use super::*;

fn pending_output_context_intent_for_wallet_utxo(
    wallet_utxo: &WalletUtxo,
) -> PendingOutputPoiContextIntent {
    PendingOutputPoiContextIntent {
        txid_version: DEFAULT_TXID_VERSION.to_string(),
        output_commitment: wallet_utxo.utxo.poi.commitment,
        output_npk: wallet_utxo.utxo.poi.npk,
        utxo_tree_in: u64::from(wallet_utxo.utxo.tree),
        railgun_txid: U256::from(7),
        pre_transaction_pois_per_txid_leaf_per_list: BTreeMap::new(),
        required_poi_list_keys: Vec::new(),
        output_role: PendingOutputPoiRole::Recipient,
    }
}

async fn assert_private_command_error(
    handle: &WalletHandle,
    wallet_utxo: &WalletUtxo,
    context: PendingOutputPoiContextIntent,
    expected: WalletPrivateRequestError,
) {
    assert_eq!(
        handle
            .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), None)
            .await,
        Err(expected)
    );
    assert_eq!(handle.clear_all_local_pending_spent().await, Err(expected));
    assert_eq!(
        handle
            .create_pending_output_poi_contexts(vec![context])
            .await,
        Err(expected)
    );
}

async fn assert_private_command_state_unchanged(handle: &WalletHandle, revision: u64) {
    assert_eq!(*handle.rev_rx.borrow(), revision);
    assert_eq!(
        handle
            .pending_overlay
            .read()
            .await
            .local_pending_spent
            .len(),
        1
    );
}

async fn spawn_consumer_api_wallet(
    name: &str,
    initial_utxos: Vec<WalletUtxo>,
) -> (
    std::path::PathBuf,
    Arc<DbStore>,
    Arc<FailingCacheStore>,
    WalletHandle,
    CancellationToken,
    mpsc::Sender<BackfillEvent>,
    broadcast::Sender<SharedLogBatch>,
) {
    let root_dir = temp_db_root(name);
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    let mut cfg = wallet_config();
    cfg.cache_store = Some(cache_store.clone());
    cfg.sync_to_block = Some(100);
    cfg.use_indexed_wallet_catch_up = false;
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
        cfg,
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        initial_utxos,
        100,
    )
    .await
    .expect("spawn wallet worker");
    (
        root_dir,
        db,
        cache_store,
        handle,
        cancel,
        backfill_tx,
        live_tx,
    )
}

async fn wait_for_sender_capacity<T>(sender: &mpsc::Sender<T>, expected: usize, label: &str) {
    let reached = tokio::time::timeout(Duration::from_secs(1), async {
        while sender.capacity() != expected {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        reached.is_ok(),
        "{label}: expected sender capacity {expected}, got {}",
        sender.capacity()
    );
}

#[tokio::test]
async fn wallet_private_mailbox_publishes_coherent_local_pending_spends() {
    let wallet_utxo = test_wallet_utxo(105, 7);
    let (root_dir, db, _cache_store, handle, cancel, _backfill_tx, _live_tx) =
        spawn_consumer_api_wallet("wallet-private-local-pending", vec![wallet_utxo.clone()]).await;
    let initial_revision = handle
        .current_snapshot()
        .expect("current wallet view")
        .revision;
    let tx_hash = FixedBytes::from([0x71; 32]);

    assert_eq!(
        handle
            .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), Some(tx_hash))
            .await,
        Ok(WalletPendingSpentMarkOutcome::Marked)
    );
    let marked = handle.current_snapshot().expect("marked wallet view");
    assert_eq!(marked.utxos.len(), 1);
    assert!(marked.revision > initial_revision);
    assert_eq!(marked.pending_overlay.local_pending_spent.len(), 1);
    let initial_block_timestamp = marked.pending_overlay.local_pending_spent[0]
        .block_timestamp
        .expect("submitted lock timestamp");
    assert_eq!(
        marked.pending_overlay.local_pending_spent[0].tx_hash,
        Some(tx_hash)
    );
    assert_eq!(
        handle
            .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), Some(tx_hash))
            .await,
        Ok(WalletPendingSpentMarkOutcome::AlreadyProtected)
    );
    assert_eq!(
        handle
            .current_snapshot()
            .expect("duplicate mark view")
            .revision,
        marked.revision
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        handle
            .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), Some(tx_hash))
            .await,
        Ok(WalletPendingSpentMarkOutcome::Marked),
        "a submitted same-hash lock renews its expiry timestamp"
    );
    let renewed = handle.current_snapshot().expect("renewed mark view");
    assert!(renewed.revision > marked.revision);
    assert!(
        renewed.pending_overlay.local_pending_spent[0]
            .block_timestamp
            .is_some_and(|timestamp| timestamp > initial_block_timestamp),
        "renewal must advance the stored expiry timestamp"
    );

    let missing = test_wallet_utxo(106, 99);
    assert_eq!(
        handle
            .mark_pending_spent_utxos(std::slice::from_ref(&missing.utxo), None)
            .await,
        Ok(WalletPendingSpentMarkOutcome::Marked),
        "the actor retains a latent intent until an identical input replays"
    );
    assert!(
        handle
            .current_snapshot()
            .expect("latent input view")
            .pending_overlay
            .local_pending_spent
            .iter()
            .any(|spent| spent.matches_local_utxo(&missing))
    );
    let mut stale_replacement = wallet_utxo.utxo.clone();
    stale_replacement.note.value = U256::from(999);
    assert_eq!(
        handle
            .mark_pending_spent_utxos(std::slice::from_ref(&stale_replacement), None)
            .await,
        Ok(WalletPendingSpentMarkOutcome::Marked),
        "a distinct latent identity may coexist at the same tree position"
    );
    assert_eq!(
        handle
            .mark_pending_spent_utxos(std::slice::from_ref(&missing.utxo), None)
            .await,
        Ok(WalletPendingSpentMarkOutcome::AlreadyProtected),
        "a duplicate latent intent does not refresh its timestamp"
    );
    assert!(
        handle
            .current_snapshot()
            .expect("replayed input view")
            .pending_overlay
            .local_pending_spent
            .iter()
            .any(|spent| spent.matches_local_utxo(&missing))
    );
    assert_eq!(handle.clear_all_local_pending_spent().await, Ok(true));
    assert_eq!(
        handle
            .current_snapshot()
            .expect("cleared wallet view")
            .pending_overlay
            .local_pending_spent,
        [] as [WalletPendingSpent; 0]
    );
    {
        let mut overlay = handle.pending_overlay.write().await;
        overlay.pending_spent.push(WalletPendingSpent::from_source(
            &wallet_utxo.utxo,
            &source(106, 0x72),
        ));
    }
    assert_eq!(
        handle
            .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), None)
            .await,
        Ok(WalletPendingSpentMarkOutcome::Marked),
        "the local intent remains latent while chain pending state protects the position"
    );
    handle.pending_overlay.write().await.pending_spent.clear();
    handle.utxos.write().await[0].spent = Some(source(107, 0x73));
    assert_eq!(
        handle
            .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), None)
            .await,
        Ok(WalletPendingSpentMarkOutcome::Marked),
        "a confirmed spend retires the local intent for the exact input"
    );
    assert_eq!(
        handle.pending_overlay.read().await.local_pending_spent,
        [] as [WalletPendingSpent; 0]
    );

    handle.retire_actor();
    assert_eq!(
        handle
            .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), None)
            .await,
        Err(WalletPrivateRequestError::Inactive)
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_private_mailbox_clears_mixed_visible_and_latent_spend_intents() {
    let visible = test_wallet_utxo(105, 7);
    let latent = test_wallet_utxo(106, 8);
    let (root_dir, db, _cache_store, handle, cancel, _backfill_tx, _live_tx) =
        spawn_consumer_api_wallet("wallet-private-mixed-pending", vec![visible.clone()]).await;

    assert_eq!(
        handle
            .mark_pending_spent_utxos(&[visible.utxo.clone(), latent.utxo.clone()], None)
            .await,
        Ok(WalletPendingSpentMarkOutcome::Marked)
    );
    let overlay = handle.pending_overlay.read().await.clone();
    assert_eq!(overlay.local_pending_spent.len(), 2);
    assert!(
        overlay
            .local_pending_spent
            .iter()
            .any(|spent| spent.matches_local_utxo(&visible))
    );
    assert!(
        overlay
            .local_pending_spent
            .iter()
            .any(|spent| spent.matches_local_utxo(&latent))
    );

    assert_eq!(handle.clear_all_local_pending_spent().await, Ok(true));
    handle.utxos.write().await.push(latent);
    assert_eq!(
        handle.pending_overlay.read().await.local_pending_spent,
        [] as [WalletPendingSpent; 0]
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test(start_paused = true)]
async fn wallet_private_mailbox_expires_local_spend_intent_without_other_commands() {
    let wallet_utxo = test_wallet_utxo(105, 7);
    let (root_dir, db, _cache_store, handle, cancel, _backfill_tx, _live_tx) =
        spawn_consumer_api_wallet("wallet-private-pending-expiry", vec![wallet_utxo.clone()]).await;
    assert_eq!(
        handle
            .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), None)
            .await,
        Ok(WalletPendingSpentMarkOutcome::Marked)
    );

    tokio::time::advance(LOCAL_PENDING_SPENT_TTL + Duration::from_secs(1)).await;
    for _ in 0..10 {
        if handle
            .pending_overlay
            .read()
            .await
            .local_pending_spent
            .is_empty()
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        handle.pending_overlay.read().await.local_pending_spent,
        [] as [WalletPendingSpent; 0]
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_private_mailbox_orders_mark_before_clear_across_command_kinds() {
    let wallet_utxo = test_wallet_utxo(105, 7);
    let (root_dir, db, _cache_store, handle, cancel, _backfill_tx, _live_tx) =
        spawn_consumer_api_wallet("wallet-private-command-order", vec![wallet_utxo.clone()]).await;
    let snapshot = handle.current_snapshot().expect("current wallet view");
    let revision = snapshot.revision;
    let held = Arc::clone(&handle.authority_lock).lock_owned().await;
    let (mark_reply, mark_result) = oneshot::channel();
    handle
        .private_request_tx
        .send(WalletPrivateRequest::MarkLocalPendingSpent {
            utxos: vec![wallet_utxo.utxo],
            tx_hash: None,
            reply: mark_reply,
        })
        .await
        .expect("queue mark request");
    let (clear_reply, clear_result) = oneshot::channel();
    handle
        .private_request_tx
        .send(WalletPrivateRequest::ClearLocalPendingSpent { reply: clear_reply })
        .await
        .expect("queue clear request");
    wait_for_sender_capacity(&handle.private_request_tx, 7, "ordered private commands").await;

    drop(held);
    assert_eq!(
        mark_result.await.expect("mark result"),
        Ok(WalletPendingSpentMarkOutcome::Marked)
    );
    assert_eq!(clear_result.await.expect("clear result"), Ok(true));
    let final_snapshot = handle.current_snapshot().expect("final wallet view");
    assert_eq!(
        final_snapshot.pending_overlay.local_pending_spent,
        [] as [WalletPendingSpent; 0]
    );
    assert_eq!(final_snapshot.revision, revision.wrapping_add(2));

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn pending_output_context_mailbox_stamps_deduplicates_and_fences_persistence() {
    let wallet_utxo = test_wallet_utxo(105, 7);
    let (root_dir, db, cache_store, handle, cancel, _backfill_tx, _live_tx) =
        spawn_consumer_api_wallet("wallet-private-pending-context", vec![wallet_utxo.clone()])
            .await;
    let cfg = wallet_config();
    let context = pending_output_context_intent_for_wallet_utxo(&wallet_utxo);
    let checkpoint = WalletMeta {
        last_scanned_block: 100,
        updated_at: 77,
        last_scanned_block_hash: Some([0xa5; 32]),
    };
    db.put_wallet_meta(&cfg.cache_key, &checkpoint)
        .expect("seed checkpoint metadata");
    let revision_before = handle
        .current_snapshot()
        .expect("current wallet view")
        .revision;

    assert_eq!(
        handle
            .create_pending_output_poi_contexts(vec![context.clone()])
            .await,
        Ok(1)
    );
    let persisted = db
        .get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &context.output_commitment,
        )
        .expect("read pending context")
        .expect("persisted pending context");
    assert_eq!(persisted.chain_id, cfg.chain.chain_id);
    assert_eq!(persisted.wallet_id, cfg.cache_key.as_str());
    assert!(persisted.created_at > 0);
    assert!(persisted.txid_merkleroot_index.is_none());
    assert!(persisted.source_operation_id.is_none());
    assert!(persisted.observation.is_none());
    assert_eq!(persisted.submitted_poi_list_keys, [] as [FixedBytes<32>; 0]);
    assert!(persisted.terminal_error.is_none());
    let retained_checkpoint = db
        .get_wallet_meta(&cfg.cache_key)
        .expect("read retained checkpoint")
        .expect("checkpoint present");
    assert_eq!(retained_checkpoint.last_scanned_block, 100);
    assert_eq!(retained_checkpoint.updated_at, 77);
    assert_eq!(
        retained_checkpoint.last_scanned_block_hash,
        Some([0xa5; 32])
    );
    assert_eq!(
        handle
            .current_snapshot()
            .expect("wallet view after context persistence")
            .revision,
        revision_before,
        "context persistence must not publish an unrelated wallet-view revision"
    );

    let mut advanced = persisted;
    advanced.observation = Some(PendingOutputPoiObservation {
        output_tree: 3,
        output_position: 4,
        tx_hash: FixedBytes::from([0x79; 32]),
        block_number: 120,
        block_timestamp: 1_700_000_120,
    });
    advanced.submitted_poi_list_keys = vec![FixedBytes::from([0x7a; 32])];
    db.put_pending_output_poi_context(&advanced)
        .expect("advance pending context state");
    assert_eq!(
        handle
            .create_pending_output_poi_contexts(vec![context.clone()])
            .await,
        Ok(0),
        "duplicate creation must not overwrite actor-owned workflow state"
    );
    let retained = db
        .get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &context.output_commitment,
        )
        .expect("read retained pending context")
        .expect("retained pending context");
    assert_eq!(retained.observation, advanced.observation);
    assert_eq!(
        retained.submitted_poi_list_keys,
        advanced.submitted_poi_list_keys
    );

    let mut first = context.clone();
    first.output_commitment = FixedBytes::from([0x81; 32]);
    first.output_npk = FixedBytes::from([0x91; 32]);
    let mut duplicate = first.clone();
    duplicate.output_npk = FixedBytes::from([0x92; 32]);
    assert_eq!(
        handle
            .create_pending_output_poi_contexts(vec![first.clone(), duplicate])
            .await,
        Ok(1),
        "the first matching commitment in one request must win"
    );
    let deduplicated = db
        .get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &first.output_commitment,
        )
        .expect("read deduplicated pending context")
        .expect("deduplicated pending context");
    assert_eq!(deduplicated.output_npk, first.output_npk);
    assert!(deduplicated.observation.is_none());
    assert_eq!(
        deduplicated.submitted_poi_list_keys,
        [] as [FixedBytes<32>; 0]
    );
    assert!(deduplicated.terminal_error.is_none());

    cache_store.fail_next_meta();
    let mut failed = context;
    failed.output_commitment = FixedBytes::from([0x82; 32]);
    assert_eq!(
        handle
            .create_pending_output_poi_contexts(vec![failed.clone()])
            .await,
        Err(WalletPrivateRequestError::PersistenceFailed)
    );
    assert!(
        db.get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &failed.output_commitment,
        )
        .expect("read failed pending context")
        .is_none()
    );
    assert_eq!(
        handle
            .current_snapshot()
            .expect("wallet view after failed persistence")
            .revision,
        revision_before
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn reset_pending_private_commands_prefer_active_then_retired_session_state() {
    let wallet_utxo = test_wallet_utxo(105, 7);
    let (root_dir, db, cache_store, handle, cancel, backfill_tx, _live_tx) =
        spawn_consumer_api_wallet(
            "wallet-private-reset-pending-retired",
            vec![wallet_utxo.clone()],
        )
        .await;
    let cfg = wallet_config();
    let context = pending_output_context_intent_for_wallet_utxo(&wallet_utxo);
    assert_eq!(
        handle
            .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), None)
            .await,
        Ok(WalletPendingSpentMarkOutcome::Marked)
    );
    let revision = *handle.rev_rx.borrow();

    cache_store.fail_next_store();
    assert_eq!(
        send_reset(&backfill_tx, 1, 80).await,
        WalletBackfillResetResult::accepted_pending(
            1,
            100,
            Some(WalletBackfillRejectReason::PersistenceFailed),
        )
    );
    assert!(matches!(
        handle.view_state(),
        WalletViewState::ResetPending { .. }
    ));
    assert_eq!(
        handle
            .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), None)
            .await,
        Ok(WalletPendingSpentMarkOutcome::AlreadyProtected)
    );
    assert_eq!(handle.clear_all_local_pending_spent().await, Ok(true));
    assert_eq!(
        handle
            .create_pending_output_poi_contexts(vec![context.clone()])
            .await,
        Err(WalletPrivateRequestError::ResetPending)
    );
    let revision_after_clear = *handle.rev_rx.borrow();
    assert!(revision_after_clear > revision);
    assert_eq!(
        handle.pending_overlay.read().await.local_pending_spent,
        [] as [WalletPendingSpent; 0]
    );
    assert!(
        db.get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &context.output_commitment,
        )
        .expect("read reset-pending context")
        .is_none()
    );

    handle.retire_actor();
    cancel.cancel();
    assert_eq!(
        handle.view_state().inactive_reason(),
        Some(WalletInactiveReason::Retired)
    );
    assert_private_command_error(
        &handle,
        &wallet_utxo,
        context.clone(),
        WalletPrivateRequestError::Inactive,
    )
    .await;
    assert_eq!(*handle.rev_rx.borrow(), revision_after_clear);
    assert_eq!(
        handle.pending_overlay.read().await.local_pending_spent,
        [] as [WalletPendingSpent; 0]
    );
    assert!(
        db.get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &context.output_commitment,
        )
        .expect("read retired context")
        .is_none()
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn reset_pending_private_commands_prefer_worker_shutdown_state() {
    let wallet_utxo = test_wallet_utxo(105, 7);
    let (root_dir, db, cache_store, handle, cancel, backfill_tx, _live_tx) =
        spawn_consumer_api_wallet(
            "wallet-private-reset-pending-shutdown",
            vec![wallet_utxo.clone()],
        )
        .await;
    let cfg = wallet_config();
    let context = pending_output_context_intent_for_wallet_utxo(&wallet_utxo);
    assert_eq!(
        handle
            .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), None)
            .await,
        Ok(WalletPendingSpentMarkOutcome::Marked)
    );
    let revision = *handle.rev_rx.borrow();

    cache_store.fail_next_store();
    assert!(matches!(
        send_reset(&backfill_tx, 1, 80).await,
        WalletBackfillResetResult::Accepted {
            rewind: WalletResetRewindStatus::Pending { .. },
            ..
        }
    ));
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.view_state().inactive_reason() != Some(WalletInactiveReason::Shutdown) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("worker publishes terminal shutdown view");

    assert_private_command_error(
        &handle,
        &wallet_utxo,
        context.clone(),
        WalletPrivateRequestError::Inactive,
    )
    .await;
    assert_private_command_state_unchanged(&handle, revision).await;
    assert!(
        db.get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &context.output_commitment,
        )
        .expect("read shutdown context")
        .is_none()
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_private_mailbox_rejects_queued_stale_stamps() {
    let wallet_utxo = test_wallet_utxo(105, 7);
    let (root_dir, db, _cache_store, handle, cancel, _backfill_tx, _live_tx) =
        spawn_consumer_api_wallet("wallet-private-stale-queue", vec![wallet_utxo.clone()]).await;
    let cfg = wallet_config();
    let context = pending_output_context_intent_for_wallet_utxo(&wallet_utxo);
    let (context_reply, context_result) = oneshot::channel();
    handle
        .private_request_tx
        .send(WalletPrivateRequest::CreatePendingOutputContexts {
            ticket: WalletPrivateViewTicket::Current {
                reset_generation: 1,
                last_scanned: 100,
            },
            contexts: vec![context.clone()],
            reply: context_reply,
        })
        .await
        .expect("queue stale pending-context request");
    assert_eq!(
        context_result
            .await
            .expect("stale pending-context response"),
        Err(WalletPrivateRequestError::StaleView)
    );
    assert!(
        db.get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &context.output_commitment,
        )
        .expect("read stale pending context")
        .is_none()
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn dequeued_clear_all_rejects_shutdown_without_mutation() {
    let wallet_utxo = test_wallet_utxo(105, 7);
    let (root_dir, db, _cache_store, handle, cancel, _backfill_tx, _live_tx) =
        spawn_consumer_api_wallet("wallet-private-clear-shutdown", vec![wallet_utxo.clone()]).await;
    assert_eq!(
        handle
            .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), None)
            .await,
        Ok(WalletPendingSpentMarkOutcome::Marked)
    );
    let revision_before = handle
        .current_snapshot()
        .expect("marked wallet view")
        .revision;
    let held = Arc::clone(&handle.authority_lock).lock_owned().await;
    let (clear_reply, clear_result) = oneshot::channel();
    handle
        .private_request_tx
        .send(WalletPrivateRequest::ClearLocalPendingSpent { reply: clear_reply })
        .await
        .expect("queue clear-all request");
    wait_for_sender_capacity(&handle.private_request_tx, 8, "dequeued clear-all").await;

    cancel.cancel();
    drop(held);
    assert_eq!(
        clear_result.await.expect("clear-all result"),
        Err(WalletPrivateRequestError::Inactive)
    );
    assert_eq!(
        handle.view_state().inactive_reason(),
        Some(WalletInactiveReason::Shutdown)
    );
    assert_eq!(*handle.rev_rx.borrow(), revision_before);
    assert_eq!(
        handle
            .pending_overlay
            .read()
            .await
            .local_pending_spent
            .len(),
        1
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn dequeued_pending_context_rejects_retirement_without_persistence() {
    let wallet_utxo = test_wallet_utxo(105, 7);
    let (root_dir, db, _cache_store, handle, cancel, _backfill_tx, _live_tx) =
        spawn_consumer_api_wallet(
            "wallet-private-context-retirement",
            vec![wallet_utxo.clone()],
        )
        .await;
    let cfg = wallet_config();
    let context = pending_output_context_intent_for_wallet_utxo(&wallet_utxo);
    let held = Arc::clone(&handle.authority_lock).lock_owned().await;
    let snapshot = handle
        .current_snapshot()
        .expect("current pending-context view");
    let (context_reply, context_result) = oneshot::channel();
    handle
        .private_request_tx
        .send(WalletPrivateRequest::CreatePendingOutputContexts {
            ticket: WalletPrivateViewTicket::Current {
                reset_generation: snapshot.reset_generation,
                last_scanned: snapshot.last_scanned,
            },
            contexts: vec![context],
            reply: context_reply,
        })
        .await
        .expect("queue pending-context request");
    wait_for_sender_capacity(&handle.private_request_tx, 8, "dequeued retirement context").await;

    handle.retire_actor();
    drop(held);
    assert_eq!(
        context_result.await.expect("pending-context result"),
        Err(WalletPrivateRequestError::Inactive)
    );
    assert!(
        db.list_pending_output_poi_contexts(cfg.chain.chain_id, &cfg.cache_key)
            .expect("list pending contexts")
            .is_empty()
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn current_mailbox_requests_queued_behind_reset_are_rejected() {
    let wallet_utxo = test_wallet_utxo(105, 7);
    let (root_dir, db, _cache_store, handle, cancel, backfill_tx, _live_tx) =
        spawn_consumer_api_wallet("wallet-private-queued-reset", vec![wallet_utxo.clone()]).await;
    let cfg = wallet_config();
    let context = pending_output_context_intent_for_wallet_utxo(&wallet_utxo);
    let context_commitment = context.output_commitment;
    let held = Arc::clone(&handle.authority_lock).lock_owned().await;
    let (reset_response, reset_result) = oneshot::channel();
    backfill_tx
        .send(BackfillEvent::Reset {
            token: test_reset_token(1),
            from_block: 80,
            replay_plan: WalletResetReplayPlan::new(0, 0, true),
            response: reset_response,
        })
        .await
        .expect("queue reset");
    wait_for_sender_capacity(&backfill_tx, 8, "dequeued reset").await;

    let mark_handle = handle.clone();
    let mark_utxo = wallet_utxo.utxo.clone();
    let mark = tokio::spawn(async move {
        mark_handle
            .mark_pending_spent_utxos(std::slice::from_ref(&mark_utxo), None)
            .await
    });
    let context_handle = handle.clone();
    let create = tokio::spawn(async move {
        context_handle
            .create_pending_output_poi_contexts(vec![context])
            .await
    });
    wait_for_sender_capacity(&handle.private_request_tx, 6, "queued reset commands").await;

    drop(held);
    assert_eq!(
        reset_result
            .await
            .expect("reset response")
            .reset_generation(),
        Some(1)
    );
    assert!(matches!(
        mark.await.expect("pending-spend task"),
        Ok(WalletPendingSpentMarkOutcome::Marked)
    ));
    assert!(matches!(
        create.await.expect("pending-context task"),
        Err(WalletPrivateRequestError::ResetPending | WalletPrivateRequestError::StaleView)
    ));
    assert!(
        db.get_pending_output_poi_context(cfg.chain.chain_id, &cfg.cache_key, &context_commitment,)
            .expect("read reset-fenced pending context")
            .is_none()
    );

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
