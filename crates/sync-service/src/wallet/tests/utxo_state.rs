use super::*;

#[test]
fn rewind_wallet_utxos_preserves_pre_reorg_outputs() {
    let kept_unspent = test_wallet_utxo(1);
    let mut kept_spent = test_wallet_utxo(2);
    kept_spent.spent = Some(source(4));
    let mut reopened_spend = test_wallet_utxo(3);
    reopened_spend.spent = Some(source(12));
    let dropped_output = test_wallet_utxo(20);
    let dropped_commitment = dropped_output.utxo.poi.commitment;

    let mut wallet_utxos = vec![kept_unspent, kept_spent, reopened_spend, dropped_output];
    let rewind = rewind_wallet_utxos(&mut wallet_utxos, 10);

    assert!(rewind.changed);
    assert_eq!(rewind.removed_output_commitments, vec![dropped_commitment]);
    assert_eq!(wallet_utxos.len(), 3);
    assert!(wallet_utxos.iter().any(|utxo| utxo.utxo.position == 1));
    assert!(wallet_utxos.iter().any(|utxo| {
        utxo.utxo.position == 2
            && utxo
                .spent
                .as_ref()
                .is_some_and(|spent| spent.block_number == 4)
    }));
    assert!(
        wallet_utxos
            .iter()
            .any(|utxo| utxo.utxo.position == 3 && utxo.spent.is_none())
    );
    assert!(!wallet_utxos.iter().any(|utxo| utxo.utxo.position == 20));
}

#[tokio::test]
async fn failed_full_persist_forces_next_no_change_batch_to_store_snapshot() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = RecordingCacheStore::new(Arc::clone(&store));
    cache_store.fail_next_store();
    let snapshot = Vec::new();
    let handle = test_wallet_handle(snapshot.clone());
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let permit = authority.acquire().await.expect("wallet authority");
    let mut persist_state = WalletPersistState::default();

    assert!(
        persist_state
            .persist_progress(
                &cache_store,
                &permit,
                WalletProgressPersist {
                    cache_key: "wallet",
                    snapshot: &snapshot,
                    last_scanned: 10,
                    checkpoint: WalletCheckpointMutation::Set {
                        last_scanned_block: 10,
                        last_scanned_block_hash: None,
                    },
                    changed: true,
                },
            )
            .is_err()
    );
    assert!(persist_state.needs_full_persist);
    assert_eq!(cache_store.state().store_calls, 1);
    assert_eq!(cache_store.state().meta_calls, 0);

    let persisted_full_snapshot = persist_state
        .persist_progress(
            &cache_store,
            &permit,
            WalletProgressPersist {
                cache_key: "wallet",
                snapshot: &snapshot,
                last_scanned: 11,
                checkpoint: WalletCheckpointMutation::Set {
                    last_scanned_block: 11,
                    last_scanned_block_hash: None,
                },
                changed: false,
            },
        )
        .expect("retry full persist");
    assert!(persisted_full_snapshot);
    assert!(!persist_state.needs_full_persist);
    assert_eq!(cache_store.state().store_calls, 2);
    assert_eq!(cache_store.state().meta_calls, 0);

    let persisted_full_snapshot = persist_state
        .persist_progress(
            &cache_store,
            &permit,
            WalletProgressPersist {
                cache_key: "wallet",
                snapshot: &snapshot,
                last_scanned: 12,
                checkpoint: WalletCheckpointMutation::Set {
                    last_scanned_block: 12,
                    last_scanned_block_hash: None,
                },
                changed: false,
            },
        )
        .expect("metadata-only persist");
    assert!(!persisted_full_snapshot);
    assert_eq!(cache_store.state().store_calls, 2);
    assert_eq!(cache_store.state().meta_calls, 1);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn pending_cache_reset_blocks_metadata_only_until_full_snapshot_succeeds() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = RecordingCacheStore::new(Arc::clone(&store));
    cache_store.fail_next_store();
    let snapshot = Vec::new();
    let handle = test_wallet_handle(snapshot.clone());
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let permit = authority.acquire().await.expect("wallet authority");
    let mut persist_state = WalletPersistState {
        needs_full_persist: true,
        pending_cache_reset: Some(9),
    };

    assert!(
        persist_state
            .persist_progress(
                &cache_store,
                &permit,
                WalletProgressPersist {
                    cache_key: "wallet",
                    snapshot: &snapshot,
                    last_scanned: 10,
                    checkpoint: WalletCheckpointMutation::Set {
                        last_scanned_block: 10,
                        last_scanned_block_hash: None,
                    },
                    changed: false,
                },
            )
            .is_err()
    );
    assert_eq!(persist_state.pending_cache_reset, Some(9));
    assert_eq!(cache_store.state().reset_calls, 0);
    assert_eq!(cache_store.state().store_calls, 1);
    assert_eq!(cache_store.state().meta_calls, 0);

    let persisted_full_snapshot = persist_state
        .persist_progress(
            &cache_store,
            &permit,
            WalletProgressPersist {
                cache_key: "wallet",
                snapshot: &snapshot,
                last_scanned: 10,
                checkpoint: WalletCheckpointMutation::Set {
                    last_scanned_block: 10,
                    last_scanned_block_hash: None,
                },
                changed: false,
            },
        )
        .expect("reset then full persist");
    assert!(persisted_full_snapshot);
    assert_eq!(persist_state.pending_cache_reset, None);
    assert!(!persist_state.needs_full_persist);
    assert_eq!(cache_store.state().reset_calls, 0);
    assert_eq!(cache_store.state().store_calls, 2);
    assert_eq!(cache_store.state().meta_calls, 0);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn notify_changed_increments_revision() {
    let handle = test_wallet_handle(Vec::new());

    handle.notify_changed().await;
    assert_eq!(*handle.rev_rx.borrow(), 1);

    handle.notify_changed().await;
    assert_eq!(*handle.rev_rx.borrow(), 2);
}

#[test]
fn readiness_only_observation_change_reuses_current_view_allocation() {
    let handle = test_wallet_handle(vec![test_wallet_utxo(7)]);
    let before = handle.current_snapshot().expect("initial Current view");

    handle.publish_readiness_for_test(&crate::types::WalletReadiness::Ready);

    let observation = handle.observation();
    let WalletViewState::Current(after) = observation.view() else {
        panic!("readiness-only transition must preserve Current view");
    };
    assert!(Arc::ptr_eq(&before, after));
    assert!(Arc::ptr_eq(&before.utxos, &after.utxos));
    assert_eq!(
        observation.readiness(),
        &crate::types::WalletReadiness::Ready
    );
}

#[tokio::test]
async fn schedulable_progress_uses_view_stamped_generation_not_authority() {
    let handle = test_wallet_handle(Vec::new());
    assert_eq!(
        handle.schedulable_progress(),
        Some(WalletSchedulableProgress {
            last_scanned: 0,
            reset_generation: 0,
        })
    );

    // AcceptReset-style window: authority advances before view is republished.
    assert_eq!(handle.advance_reset_generation().await, Some(1));
    assert_eq!(handle.authority_reset_generation(), 1);
    assert_eq!(
        handle.schedulable_progress(),
        Some(WalletSchedulableProgress {
            last_scanned: 0,
            reset_generation: 0,
        }),
        "public scheduling must not pair the current view cursor with authority generation"
    );

    let cancel = CancellationToken::new();
    let progress = handle
        .wait_schedulable_progress(&cancel)
        .await
        .expect("current view is schedulable");
    assert_eq!(
        progress,
        WalletSchedulableProgress {
            last_scanned: 0,
            reset_generation: 0,
        }
    );
}

#[test]
fn schedulable_progress_revalidate_rejects_generation_mismatch() {
    let ticket = WalletSchedulableProgress {
        last_scanned: 100,
        reset_generation: 0,
    };
    let same_gen_advanced = WalletSchedulableProgress {
        last_scanned: 150,
        reset_generation: 0,
    };
    let new_gen = WalletSchedulableProgress {
        last_scanned: 50,
        reset_generation: 1,
    };
    assert_eq!(
        ticket.revalidate(Some(same_gen_advanced)),
        Some(same_gen_advanced)
    );
    assert_eq!(ticket.revalidate(Some(new_gen)), None);
    assert_eq!(ticket.revalidate(None), None);
    assert!(ticket.still_current(Some(same_gen_advanced)));
    assert!(!ticket.still_current(Some(new_gen)));
}

#[tokio::test]
async fn start_backfill_rejects_stale_progress_ticket() {
    let handle = test_wallet_handle(Vec::new());
    let (sender, _rx) = mpsc::channel(1);
    // Advance view generation by republishing Current with new authority gen.
    assert_eq!(handle.advance_reset_generation().await, Some(1));
    handle.notify_changed().await;
    assert_eq!(
        handle.schedulable_progress().map(|p| p.reset_generation),
        Some(1)
    );

    let stale = WalletSchedulableProgress {
        last_scanned: 0,
        reset_generation: 0,
    };
    let result = handle.start_backfill("cache", &sender, stale, 10).await;
    assert!(
        matches!(
            result,
            crate::types::WalletBackfillStartResult::Rejected {
                reason: crate::types::WalletBackfillRejectReason::StaleGeneration { .. },
                ..
            }
        ),
        "stale progress ticket must not mint generation-scoped work: {result:?}"
    );
}

#[tokio::test]
async fn wallet_handle_manual_poi_refresh_sends_forced_recovery_request() {
    let (rev_tx, rev_rx) = watch::channel(0_u64);
    let (reset_generation_tx, reset_generation_rx) = watch::channel(0_u64);
    let (observation, observation_rx) =
        WalletObservationPublisher::new(WalletViewState::Current(WalletCurrentSnapshot::new(
            0,
            0,
            0,
            Arc::<[WalletUtxo]>::from(Vec::new()),
            Arc::new(WalletPendingOverlay::default()),
        )));
    let (pending_overlay_tx, _pending_overlay_rx) = mpsc::channel(1);
    let (private_request_tx, _private_request_rx) = mpsc::channel(1);
    let (poi_refresh_tx, mut poi_refresh_rx) = mpsc::channel::<WalletPoiRefreshRequest>(1);
    let (_poi_refreshing_tx, poi_refreshing_rx) = watch::channel(false);
    let (indexed_catch_up_tx, indexed_catch_up_rx) = watch::channel(None);
    let (indexed_catch_up_status_tx, _indexed_catch_up_status_rx) = mpsc::unbounded_channel();
    let handle = WalletHandle {
        cache_key: test_cache_key("cache-key"),
        chain: ChainKey {
            chain_id: 1,
            contract: Address::ZERO,
        },
        actor_id: 1,
        active_actor_id: Arc::new(AtomicU64::new(1)),
        lifecycle: Arc::new(WalletActorLifecycleCell::new()),
        authority_lock: Arc::new(tokio::sync::Mutex::new(())),
        utxos: Arc::new(RwLock::new(Vec::new())),
        pending_overlay: Arc::new(RwLock::new(WalletPendingOverlay::default())),
        last_scanned: Arc::new(AtomicU64::new(0)),
        reset_generation: Arc::new(AtomicU64::new(0)),
        reset_generation_rx,
        next_sync_job_id: Arc::new(AtomicU64::new(1)),
        observation: Arc::downgrade(&observation),
        observation_rx,
        rev_rx,
        poi_refreshing_rx,
        indexed_catch_up_rx,
        pending_overlay_tx,
        private_request_tx,
        poi_refresh_tx,
        indexed_catch_up_status_tx,
        rev_tx,
        reset_generation_tx,
        indexed_catch_up_tx,
    };

    assert!(handle.refresh_poi_statuses().await);

    let request = poi_refresh_rx.recv().await.expect("refresh request");
    assert!(request.force_output_poi_recovery);
}

#[test]
fn spent_nullifiers_are_scoped_by_tree() {
    let nullifying_key = uint!(42_U256);
    let utxo_tree_one = Utxo::new(
        Note {
            token_hash: uint!(1_U256),
            value: uint!(10_U256),
            random: [0u8; 16],
            npk: uint!(2_U256),
        },
        1,
        7,
        source(1),
        UtxoCommitmentKind::Transact,
    );
    let utxo_tree_two = Utxo::new(
        utxo_tree_one.note.clone(),
        2,
        7,
        source(2),
        UtxoCommitmentKind::Transact,
    );
    let shared_nullifier = utxo_tree_one.nullifier(nullifying_key);
    let spent_source = source(9);
    let nullifier_sources = HashMap::from([((2, shared_nullifier), spent_source.clone())]);

    assert_eq!(
        spent_source_for_utxo(&utxo_tree_one, nullifying_key, &nullifier_sources,),
        None,
    );
    assert_eq!(
        spent_source_for_utxo(&utxo_tree_two, nullifying_key, &nullifier_sources),
        Some(spent_source),
    );
}

#[test]
fn indexed_delta_marks_matching_utxo_spent() {
    let nullifying_key = uint!(42_U256);
    let cfg = wallet_config(nullifying_key);
    let utxo = Utxo::new(
        Note {
            token_hash: uint!(1_U256),
            value: uint!(10_U256),
            random: [0u8; 16],
            npk: uint!(2_U256),
        },
        2,
        7,
        source(1),
        UtxoCommitmentKind::Transact,
    );
    let spent_source = source(9);
    let nullifier = utxo.nullifier(nullifying_key);
    let mut wallet_utxos = vec![WalletUtxo::new(utxo)];
    let delta = WalletLogDelta {
        utxos: Vec::new(),
        nullifiers: vec![SpentNullifier {
            tree: 2,
            nullifier,
            source: spent_source.clone(),
        }],
        commitment_observations: Vec::new(),
        sender_scan_outputs: Vec::new(),
    };

    let changed = apply_wallet_delta_to_vec(&cfg, &mut wallet_utxos, delta);

    assert!(changed);
    assert_eq!(wallet_utxos[0].spent, Some(spent_source));
}

#[test]
fn indexed_delta_reports_spent_output_commitment() {
    let nullifying_key = uint!(42_U256);
    let cfg = wallet_config(nullifying_key);
    let utxo = Utxo::new(
        Note {
            token_hash: uint!(1_U256),
            value: uint!(10_U256),
            random: [0u8; 16],
            npk: uint!(2_U256),
        },
        2,
        7,
        source(1),
        UtxoCommitmentKind::Transact,
    );
    let output_commitment = utxo.poi.commitment;
    let nullifier = utxo.nullifier(nullifying_key);
    let mut wallet_utxos = vec![WalletUtxo::new(utxo)];
    let delta = WalletLogDelta {
        utxos: Vec::new(),
        nullifiers: vec![SpentNullifier {
            tree: 2,
            nullifier,
            source: source(9),
        }],
        commitment_observations: Vec::new(),
        sender_scan_outputs: Vec::new(),
    };

    let outcome = apply_wallet_delta_to_vec_with_outcome(&cfg, &mut wallet_utxos, delta);

    assert!(outcome.changed);
    assert_eq!(outcome.spent_output_commitments, vec![output_commitment]);
}

#[test]
fn pending_overlay_marks_matching_confirmed_utxo_pending_spent() {
    let nullifying_key = uint!(42_U256);
    let cfg = wallet_config(nullifying_key);
    let wallet_utxo = test_wallet_utxo(7);
    let nullifier = wallet_utxo.utxo.nullifier(nullifying_key);
    let spent_source = source(9);
    let delta = WalletLogDelta {
        utxos: Vec::new(),
        nullifiers: vec![SpentNullifier {
            tree: wallet_utxo.utxo.tree,
            nullifier,
            source: spent_source.clone(),
        }],
        commitment_observations: Vec::new(),
        sender_scan_outputs: Vec::new(),
    };

    let overlay = pending_overlay_from_delta(&cfg, &[wallet_utxo], delta);

    assert!(overlay.new_utxos.is_empty());
    assert_eq!(overlay.pending_spent.len(), 1);
    assert_eq!(overlay.pending_spent[0].key(), (2, 7));
    assert_eq!(overlay.pending_spent[0].tx_hash, Some(spent_source.tx_hash));
    assert_eq!(
        overlay.pending_spent[0].block_number,
        Some(spent_source.block_number)
    );
}

#[tokio::test]
async fn local_pending_spent_expires_after_successful_overlay_refresh() {
    let wallet_utxo = test_wallet_utxo(7);
    let handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    let submitted_at = now_epoch_secs().saturating_sub(LOCAL_PENDING_SPENT_TTL.as_secs() + 1);
    {
        let mut overlay = handle.pending_overlay.write().await;
        overlay
            .local_pending_spent
            .push(local_pending_spent_for(&wallet_utxo, submitted_at));
    }

    handle
        .set_chain_pending_overlay(WalletPendingOverlay::default())
        .await;

    assert_eq!(
        handle
            .pending_overlay()
            .expect("current view")
            .local_pending_spent,
        [] as [WalletPendingSpent; 0]
    );
}

#[tokio::test]
async fn local_pending_spent_retains_recent_submissions() {
    let wallet_utxo = test_wallet_utxo(7);
    let handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    let submitted_at = now_epoch_secs();
    {
        let mut overlay = handle.pending_overlay.write().await;
        overlay
            .local_pending_spent
            .push(local_pending_spent_for(&wallet_utxo, submitted_at));
    }

    handle
        .set_chain_pending_overlay(WalletPendingOverlay::default())
        .await;

    assert_eq!(
        handle
            .pending_overlay()
            .expect("current view")
            .local_pending_spent
            .len(),
        1
    );
}

#[tokio::test]
async fn local_pending_spent_updates_existing_submitted_tx_hash() {
    let wallet_utxo = test_wallet_utxo(7);
    let handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    let first_hash = FixedBytes::from([0x11; 32]);
    let replacement_hash = FixedBytes::from([0x22; 32]);

    handle
        .mark_pending_spent_utxos_for_test(
            std::slice::from_ref(&wallet_utxo.utxo),
            Some(first_hash),
        )
        .await;
    handle
        .mark_pending_spent_utxos_for_test(
            std::slice::from_ref(&wallet_utxo.utxo),
            Some(replacement_hash),
        )
        .await;

    let overlay = handle.pending_overlay().expect("current view");
    assert_eq!(overlay.local_pending_spent.len(), 1);
    assert_eq!(
        overlay.local_pending_spent[0].tx_hash,
        Some(replacement_hash)
    );
}

#[tokio::test]
async fn local_pending_spent_remains_latent_while_chain_pending_covers_key() {
    let wallet_utxo = test_wallet_utxo(7);
    let handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    let submitted_at = now_epoch_secs();
    let pending_spent = local_pending_spent_for(&wallet_utxo, submitted_at);
    {
        let mut overlay = handle.pending_overlay.write().await;
        overlay.local_pending_spent.push(pending_spent.clone());
    }

    handle
        .set_chain_pending_overlay(WalletPendingOverlay {
            pending_spent: vec![pending_spent],
            ..WalletPendingOverlay::default()
        })
        .await;

    let overlay = handle.pending_overlay().expect("current view");
    assert_eq!(overlay.local_pending_spent.len(), 1);
    assert_eq!(overlay.pending_spent.len(), 1);
}

#[tokio::test]
async fn local_pending_spent_prunes_when_confirmed_spent_covers_key() {
    let mut wallet_utxo = test_wallet_utxo(7);
    let pending_spent = local_pending_spent_for(&wallet_utxo, now_epoch_secs());
    wallet_utxo.spent = Some(source(9));
    let handle = test_wallet_handle(vec![wallet_utxo]);
    {
        let mut overlay = handle.pending_overlay.write().await;
        overlay.local_pending_spent.push(pending_spent);
    }

    handle
        .set_chain_pending_overlay(WalletPendingOverlay::default())
        .await;

    assert_eq!(
        handle
            .pending_overlay()
            .expect("current view")
            .local_pending_spent,
        [] as [WalletPendingSpent; 0]
    );
}

#[tokio::test]
async fn clear_local_pending_spent_removes_manual_locks() {
    let wallet_utxo = test_wallet_utxo(7);
    let handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    {
        let mut overlay = handle.pending_overlay.write().await;
        overlay
            .local_pending_spent
            .push(local_pending_spent_for(&wallet_utxo, now_epoch_secs()));
    }

    assert!(handle.clear_local_pending_spent_for_test().await);
    assert_eq!(
        handle
            .pending_overlay()
            .expect("current view")
            .local_pending_spent,
        [] as [WalletPendingSpent; 0]
    );
    assert!(!handle.clear_local_pending_spent_for_test().await);
}

#[tokio::test]
async fn terminal_wallet_views_override_retained_reset_pending_state() {
    let wallet_utxo = test_wallet_utxo(7);
    let handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    let revision = *handle.rev_rx.borrow();
    handle.publish_view_for_test(WalletViewState::ResetPending {
        intent_id: 1,
        from_block: 10,
        reset_generation: 1,
    });
    handle.retire_actor();

    assert_eq!(
        handle.view_state(),
        WalletViewState::Inactive {
            reason: WalletInactiveReason::Retired,
            reset_generation: 0,
        }
    );
    assert_eq!(
        handle.observation().readiness(),
        &crate::types::WalletReadiness::Shutdown
    );

    assert_eq!(
        handle
            .mark_pending_spent_utxos(std::slice::from_ref(&wallet_utxo.utxo), None)
            .await,
        Err(WalletPrivateRequestError::Inactive)
    );
    assert_eq!(
        handle.clear_all_local_pending_spent().await,
        Err(WalletPrivateRequestError::Inactive)
    );
    assert_eq!(
        handle
            .create_pending_output_poi_contexts(vec![pending_output_intent(
                FixedBytes::from([0x83; 32]),
                FixedBytes::from([0x84; 32]),
            )])
            .await,
        Err(WalletPrivateRequestError::Inactive)
    );
    assert_eq!(*handle.rev_rx.borrow(), revision);
    assert_eq!(
        handle.pending_overlay.read().await.local_pending_spent,
        [] as [WalletPendingSpent; 0]
    );

    let stopping = test_wallet_handle(vec![wallet_utxo]);
    stopping.publish_view_for_test(WalletViewState::ResetPending {
        intent_id: 2,
        from_block: 20,
        reset_generation: 2,
    });
    let observation = stopping
        .observation
        .upgrade()
        .expect("test observation publisher remains owned");
    stopping.terminalize_panicked_actor(&observation);
    assert_eq!(
        stopping.view_state(),
        WalletViewState::Inactive {
            reason: WalletInactiveReason::Shutdown,
            reset_generation: 0,
        }
    );
    assert_eq!(
        stopping.observation().readiness(),
        &crate::types::WalletReadiness::Shutdown
    );
    assert_eq!(
        stopping.clear_all_local_pending_spent().await,
        Err(WalletPrivateRequestError::Inactive)
    );
}

#[test]
fn spent_output_discards_pending_output_poi_context() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x91; 32]);
    store
        .put_pending_output_poi_context(&pending_output_record(
            chain_id,
            output_commitment,
            FixedBytes::from([0x92; 32]),
        ))
        .expect("store pending context");

    discard_pending_output_poi_contexts_for_spent_outputs(
        &store,
        chain_id,
        test_cache_key("wallet-1").as_str(),
        &[output_commitment],
    )
    .expect("discard spent pending output context");

    assert!(
        store
            .get_pending_output_poi_context(
                chain_id,
                test_cache_key("wallet-1").as_str(),
                &output_commitment,
            )
            .expect("load pending context")
            .is_none()
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn output_poi_recovery_candidates_skip_spent_utxos() {
    let list_key = FixedBytes::from([0x93; 32]);
    let mut spent = test_wallet_utxo(7);
    spent.utxo.poi.statuses.insert(list_key, PoiStatus::Missing);
    spent.spent = Some(source(9));
    let mut unspent = test_wallet_utxo(8);
    unspent
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    let wallet_utxos = vec![spent, unspent];

    let candidates = output_poi_recovery_candidates(&wallet_utxos, &[list_key]);

    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].utxo.position, 8);
}

#[test]
fn indexed_delta_preserves_unmatched_utxo() {
    let nullifying_key = uint!(42_U256);
    let cfg = wallet_config(nullifying_key);
    let utxo = Utxo::new(
        Note {
            token_hash: uint!(1_U256),
            value: uint!(10_U256),
            random: [0u8; 16],
            npk: uint!(2_U256),
        },
        2,
        7,
        source(1),
        UtxoCommitmentKind::Transact,
    );
    let nullifier = utxo.nullifier(nullifying_key);
    let mut wallet_utxos = vec![WalletUtxo::new(utxo)];
    let delta = WalletLogDelta {
        utxos: Vec::new(),
        nullifiers: vec![SpentNullifier {
            tree: 3,
            nullifier,
            source: source(9),
        }],
        commitment_observations: Vec::new(),
        sender_scan_outputs: Vec::new(),
    };

    let changed = apply_wallet_delta_to_vec(&cfg, &mut wallet_utxos, delta);

    assert!(!changed);
    assert!(wallet_utxos[0].spent.is_none());
}

fn local_pending_spent_for(utxo: &WalletUtxo, submitted_at: u64) -> WalletPendingSpent {
    WalletPendingSpent {
        tree: utxo.utxo.tree,
        position: utxo.utxo.position,
        stable_identity: Some(wallet_utxo_stable_identity(utxo)),
        tx_hash: Some(FixedBytes::from([0x77; 32])),
        block_number: None,
        block_timestamp: Some(submitted_at),
    }
}

fn pending_output_intent(
    output_commitment: FixedBytes<32>,
    list_key: FixedBytes<32>,
) -> PendingOutputPoiContextIntent {
    let record = pending_output_record(1, output_commitment, list_key);
    PendingOutputPoiContextIntent {
        txid_version: record.txid_version,
        output_commitment: record.output_commitment,
        output_npk: record.output_npk,
        utxo_tree_in: record.utxo_tree_in,
        railgun_txid: record.railgun_txid,
        pre_transaction_pois_per_txid_leaf_per_list: record
            .pre_transaction_pois_per_txid_leaf_per_list,
        required_poi_list_keys: record.required_poi_list_keys,
        output_role: record.output_role,
    }
}
