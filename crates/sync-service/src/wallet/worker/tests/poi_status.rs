use super::*;

fn test_poi_artifact_source_config() -> PoiArtifactSourceConfig {
    PoiArtifactSourceConfig {
        trusted_publisher_pubkey: FixedBytes::from([0x42; 32]),
        manifest_source: PoiArtifactManifestSource::Url(
            Url::parse("http://127.0.0.1:1/poi-manifest.json")
                .expect("POI manifest URL")
                .into(),
        ),
        gateway_urls: Vec::new(),
        gateway_pool: None,
        max_manifest_age: None,
    }
}

fn test_artifact_poi_runtime() -> WalletPoiRuntime {
    WalletPoiRuntime::from_policy(
        &GlobalPoiPolicy::IndexedArtifacts {
            artifact_source: test_poi_artifact_source_config(),
            rpc_url: Url::parse("http://127.0.0.1:1")
                .expect("POI RPC URL")
                .into(),
            wallet_read_fallback: PoiProxyFallback::Disabled,
        },
        None,
    )
}

fn test_public_data_plane_with_poi_service(db: &Arc<DbStore>) -> ChainPublicDataPlane {
    ChainPublicDataPlane::new(Arc::clone(db), Arc::new(AtomicU64::new(0))).with_poi_cache_service(
        Arc::new(
            crate::poi_cache::PoiCacheService::new(
                Arc::clone(db),
                test_poi_artifact_source_config(),
                None,
            )
            .expect("initialize POI cache generation")
            .with_poi_rpc_url(Url::parse("http://127.0.0.1:1").expect("POI RPC URL")),
        ),
    )
}

struct UnavailablePoiStatusReader;

#[async_trait]
impl PoiStatusReader for UnavailablePoiStatusReader {
    async fn pois_per_list(
        &self,
        _txid_version: &str,
        _chain_type: u8,
        _chain_id: u64,
        _list_keys: &[FixedBytes<32>],
        _blinded_commitment_datas: &[BlindedCommitmentData],
    ) -> Result<BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PoiStatus>>, PoiError> {
        Err(PoiError::MerkleRootsRejected)
    }
}

struct FixedPoiStatusReader(PoiStatus);

#[async_trait]
impl PoiStatusReader for FixedPoiStatusReader {
    async fn pois_per_list(
        &self,
        _txid_version: &str,
        _chain_type: u8,
        _chain_id: u64,
        list_keys: &[FixedBytes<32>],
        blinded_commitment_datas: &[BlindedCommitmentData],
    ) -> Result<BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PoiStatus>>, PoiError> {
        Ok(blinded_commitment_datas
            .iter()
            .map(|data| {
                (
                    data.blinded_commitment,
                    list_keys
                        .iter()
                        .copied()
                        .map(|list_key| (list_key, self.0))
                        .collect(),
                )
            })
            .collect())
    }
}

#[tokio::test]
async fn maintenance_watchdog_converts_timeout_and_panic_to_sanitized_abort_reasons() {
    let timeout =
        run_poi_maintenance_with_watchdog(std::future::pending::<()>(), Duration::from_millis(1))
            .await
            .expect_err("maintenance timeout should abort");
    assert_eq!(timeout, PoiMaintenanceAbortReason::Timeout);
    assert_eq!(timeout.category(), "timeout");

    let panic = run_poi_maintenance_with_watchdog(
        async { panic!("test maintenance panic") },
        Duration::from_secs(1),
    )
    .await
    .expect_err("maintenance panic should abort");
    assert_eq!(panic, PoiMaintenanceAbortReason::Panic);
    assert_eq!(panic.category(), "panic");
}

#[test]
fn tentative_failed_identity_is_released_for_retry() {
    let mut tracker = PendingOutputPoiTentativeAttemptTracker::default();
    let candidate = PendingOutputPoiTentativeCandidate::for_test();
    let key = candidate.attempt_key();
    assert!(tracker.reserve(0, candidate.clone()));
    assert!(!tracker.reserve(0, candidate.clone()));
    tracker.release_retryable(0, std::slice::from_ref(&key));
    assert!(tracker.reserve(0, candidate));
}

#[test]
fn tentative_valid_projection_requires_exact_overlay_identity() {
    let candidate = PendingOutputPoiTentativeCandidate::for_test();
    let list_key = candidate.list_keys()[0];
    let mut tracker = PendingOutputPoiTentativeAttemptTracker::default();
    assert!(tracker.reserve(0, candidate.clone()));
    tracker.accept(0, std::slice::from_ref(&candidate));
    tracker.record_local_statuses(
        0,
        &[PendingOutputPoiTentativeLocalStatus {
            candidate,
            valid_list_keys: vec![list_key],
        }],
    );

    let mut wallet_utxo = test_wallet_utxo(3, 2);
    wallet_utxo.utxo.tree = 1;
    wallet_utxo.utxo.source = UtxoSource {
        tx_hash: FixedBytes::from([0x22; 32]),
        block_number: 3,
        block_timestamp: 4,
    };
    wallet_utxo.utxo.poi.commitment = FixedBytes::from([0x11; 32]);
    wallet_utxo.utxo.poi.statuses.clear();
    let mut overlay = WalletPendingOverlay {
        new_utxos: vec![wallet_utxo],
        ..WalletPendingOverlay::default()
    };
    assert!(tracker.apply_to_overlay(0, &mut overlay, 10));
    assert_eq!(
        overlay.new_utxos[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );

    overlay.new_utxos[0].utxo.position += 1;
    overlay.new_utxos[0].utxo.poi.statuses.clear();
    assert!(!tracker.apply_to_overlay(0, &mut overlay, 11));
    assert!(overlay.new_utxos[0].utxo.poi.statuses.is_empty());
}

#[test]
fn tentative_attempt_pruning_requires_current_exact_observation() {
    let candidate = PendingOutputPoiTentativeCandidate::for_test();
    let key = candidate.attempt_key();
    let mut tracker = PendingOutputPoiTentativeAttemptTracker::default();
    assert!(tracker.reserve(0, candidate.clone()));
    tracker.accept(0, std::slice::from_ref(&candidate));
    tracker.record_local_statuses(
        0,
        &[PendingOutputPoiTentativeLocalStatus {
            candidate: candidate.clone(),
            valid_list_keys: vec![candidate.list_keys()[0]],
        }],
    );
    let mut wallet_utxo = test_wallet_utxo(3, 2);
    wallet_utxo.utxo.tree = 1;
    wallet_utxo.utxo.source = UtxoSource {
        tx_hash: FixedBytes::from([0x22; 32]),
        block_number: 3,
        block_timestamp: 4,
    };
    wallet_utxo.utxo.poi.commitment = FixedBytes::from([0x11; 32]);
    let mut overlay = WalletPendingOverlay {
        new_utxos: vec![wallet_utxo],
        ..WalletPendingOverlay::default()
    };

    tracker.prune_for_observations(0, std::slice::from_ref(candidate.observation()));
    assert!(tracker.attempts.contains_key(&(0, key.clone())));
    assert!(tracker.apply_to_overlay(0, &mut overlay, 10));

    let mut changed_coordinate = candidate.observation().clone();
    changed_coordinate.position += 1;
    tracker.prune_for_observations(0, &[changed_coordinate]);
    assert!(!tracker.attempts.contains_key(&(0, key.clone())));
    assert!(!tracker.valid_lists.contains_key(&(0, key)));
    overlay.new_utxos[0].utxo.poi.statuses.clear();
    assert!(!tracker.apply_to_overlay(0, &mut overlay, 11));

    let mut source_changed_tracker = PendingOutputPoiTentativeAttemptTracker::default();
    assert!(source_changed_tracker.reserve(0, candidate.clone()));
    source_changed_tracker.accept(0, std::slice::from_ref(&candidate));
    source_changed_tracker.record_local_statuses(
        0,
        &[PendingOutputPoiTentativeLocalStatus {
            candidate: candidate.clone(),
            valid_list_keys: vec![candidate.list_keys()[0]],
        }],
    );
    let mut changed_source = candidate.observation().clone();
    changed_source.source.tx_hash = FixedBytes::from([0xaa; 32]);
    source_changed_tracker.prune_for_observations(0, &[changed_source]);
    assert!(source_changed_tracker.attempts.is_empty());
    assert!(source_changed_tracker.valid_lists.is_empty());
}

#[test]
fn tentative_validity_is_monotonic_until_pruned() {
    let candidate = PendingOutputPoiTentativeCandidate::for_test();
    let key = candidate.attempt_key();
    let first_list = candidate.list_keys()[0];
    let second_list = candidate.list_keys()[1];
    let mut tracker = PendingOutputPoiTentativeAttemptTracker::default();
    assert!(tracker.reserve(0, candidate.clone()));
    tracker.accept(0, std::slice::from_ref(&candidate));

    assert_eq!(
        tracker.record_local_statuses(
            0,
            &[PendingOutputPoiTentativeLocalStatus {
                candidate: candidate.clone(),
                valid_list_keys: vec![first_list],
            }],
        ),
        (1, 1)
    );
    assert_eq!(
        tracker.record_local_statuses(
            0,
            &[PendingOutputPoiTentativeLocalStatus {
                candidate: candidate.clone(),
                valid_list_keys: Vec::new(),
            }],
        ),
        (0, 0)
    );
    assert_eq!(
        tracker.record_local_statuses(
            0,
            &[PendingOutputPoiTentativeLocalStatus {
                candidate: candidate.clone(),
                valid_list_keys: vec![second_list],
            }],
        ),
        (1, 1)
    );
    tracker.accept(0, std::slice::from_ref(&candidate));
    assert_eq!(
        tracker.valid_lists[&(0, key)],
        BTreeSet::from([first_list, second_list])
    );
}

#[tokio::test]
async fn committed_corpus_revision_waiter_observes_latest_revision() {
    let (revision_tx, revision_rx) = watch::channel(PoiCorpusRevision::default());
    let mut revision_rx = Some(revision_rx);

    let first = PoiCorpusRevision {
        revision: 1,
        blocked_shields_revision: 0,
    };
    revision_tx.send_replace(first);
    assert_eq!(
        next_poi_corpus_revision(&mut revision_rx).await,
        Some(first)
    );
    let latest = PoiCorpusRevision {
        revision: 3,
        blocked_shields_revision: 2,
    };
    revision_tx.send_replace(latest);
    assert_eq!(
        next_poi_corpus_revision(&mut revision_rx).await,
        Some(latest)
    );
    drop(revision_tx);
    assert_eq!(next_poi_corpus_revision(&mut revision_rx).await, None);
}

#[tokio::test]
async fn wallet_poi_refresh_interval_is_not_restarted_by_other_work() {
    let period = Duration::from_millis(100);
    let mut interval = wallet_poi_refresh_interval_with_period(period);

    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    tokio::time::timeout(Duration::from_millis(70), interval.tick())
        .await
        .expect("persistent refresh interval should retain its original deadline");
}

#[tokio::test]
async fn poi_refresh_projection_does_not_wait_for_authority_lock() {
    let root_dir = temp_db_root("poi-refresh-projection-lock");
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
        100,
    )
    .await
    .expect("spawn wallet worker");
    let (poi_refreshing_tx, poi_refreshing_rx) = watch::channel(false);
    let mut controller = PoiMaintenanceController::new();
    controller
        .request(
            false,
            true,
            Some(WalletActorCredential::current_for(&handle)),
        )
        .expect("start maintenance controller");

    let _authority_guard = handle.authority_lock.lock().await;
    sync_poi_refreshing_from_controller(&controller, &poi_refreshing_tx, &handle, &cancel);
    assert!(*poi_refreshing_rx.borrow());

    let key = WalletActorCredential::current_for(&handle);
    assert!(controller.request(true, true, Some(key)).is_none());
    assert!(controller.on_job_done(PoiRemoteJobKey {
        actor_id: key.actor_id,
        reset_generation: key.reset_generation,
        kind: PoiRemoteJobKind::Maintenance,
    }));
    sync_poi_refreshing_from_controller(&controller, &poi_refreshing_tx, &handle, &cancel);
    assert!(!*poi_refreshing_rx.borrow());
    assert!(controller.try_start(true, Some(key)).is_some());

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn committed_corpus_revision_publishes_syncing_before_blocked_refresh_commit() {
    let root_dir = temp_db_root("wallet-corpus-revision-readiness");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cfg = wallet_config();
    let list_key = default_active_poi_list_keys()[0];
    let mut wallet_utxo = test_wallet_utxo(100, 7);
    let blinded_commitment = wallet_utxo.utxo.poi.blinded_commitment;
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    wallet_utxo.utxo.poi.refreshed_at = Some(now_epoch_secs());

    let public_data_plane = test_public_data_plane_with_poi_service(&db);
    let corpus = public_data_plane
        .ensure_poi_corpus(PublicPoiCorpusKey::wallet_default(cfg.chain.chain_id))
        .await
        .expect("POI corpus");
    let local_caches = corpus.local_caches();
    let mut initial_cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        cfg.chain.chain_id,
        DEFAULT_TXID_VERSION,
        list_key,
    ));
    initial_cache
        .apply_poi_leaves(0, &[U256::from(1)])
        .expect("seed ready POI corpus");
    initial_cache.accept_current_roots();
    local_caches.write().await.insert(list_key, initial_cache);

    let (live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let handle = spawn_wallet_worker(
        WalletWorkerServices {
            db: Arc::clone(&db),
            http_client: None,
            indexed_artifact_source: None,
            poi_runtime: test_artifact_poi_runtime(),
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
        vec![wallet_utxo],
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
    let mut advanced_cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        1,
        DEFAULT_TXID_VERSION,
        list_key,
    ));
    advanced_cache
        .apply_verified_artifact_events(&[SnapshotEvent {
            event_index: 0,
            blinded_commitment: *blinded_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply valid POI event");
    advanced_cache.accept_current_roots();
    let revision_fence = local_caches.revision_write_fence().await;
    local_caches.write().await.insert(list_key, advanced_cache);
    local_caches.publish_committed_revision(true);

    wait_for_readiness(&mut readiness_rx, WalletReadiness::Syncing).await;
    assert_eq!(
        handle
            .current_snapshot()
            .expect("blocked wallet view")
            .utxos[0]
            .utxo
            .poi
            .statuses
            .get(&list_key),
        Some(&PoiStatus::Missing),
        "the old status remains published while durable refresh is blocked"
    );

    drop(revision_fence);
    drop(held);
    wait_for_readiness(&mut readiness_rx, WalletReadiness::Ready).await;
    assert_eq!(
        handle
            .current_snapshot()
            .expect("refreshed wallet view")
            .utxos[0]
            .utxo
            .poi
            .statuses
            .get(&list_key),
        Some(&PoiStatus::Valid)
    );

    cancel.cancel();
    drop(live_tx);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_worker_restores_submitted_external_ppoi_workflow_status() {
    let root_dir = temp_db_root("wallet-ppoi-workflow-restore");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cfg = wallet_config();
    let list_key = default_active_poi_list_keys()[0];
    let output = test_wallet_utxo_with_random(110, 17, [0x31; 16]);
    let mut context =
        observed_external_pending_output_context(&cfg, &output, list_key, &source(110, 0xd0));
    context.terminal_error = None;
    context.pre_transaction_pois_per_txid_leaf_per_list = current_pending_proof_map(list_key);
    let recovery =
        output_poi_recovery_for_pending_context(&context, OutputPoiRecoveryStatus::Submitted);
    db.put_pending_output_poi_context(&context)
        .expect("seed pending context");
    db.put_output_poi_recovery(&recovery)
        .expect("seed recovery");

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
        100,
    )
    .await
    .expect("spawn wallet worker");

    let status = *handle.observation().ppoi_workflow_status();
    assert_eq!(status.awaiting_submission, 0);
    assert_eq!(status.awaiting_validation, 1);
    assert_eq!(status.needs_attention, 0);
    assert_eq!(status.validation_revision, 0);

    cancel.cancel();
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn current_candidate_report_moves_submitted_unshields_and_attention_out_of_recovery() {
    let root_dir = temp_db_root("wallet-candidate-report-refinement");
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let cfg = wallet_config();
    // A spend-only wallet: both outstanding units are handed-off unshields.
    for (position, byte) in [(7, 0xd4), (8, 0xd5)] {
        let spent = test_wallet_utxo(105, position);
        let candidate = crate::SenderTransactionCandidate::new(
            cfg.chain.chain_id,
            cfg.cache_key.clone(),
            source(110, byte),
            vec![crate::SenderTransactionCandidateSpend {
                tree: spent.utxo.tree,
                position: spent.utxo.position,
                commitment: spent.utxo.poi.commitment,
            }],
            Vec::new(),
        )
        .expect("sender candidate")
        .with_unshield(Some(crate::SenderTransactionCandidateUnshield {
            railgun_txids: vec![FixedBytes::from([byte; 32])],
            outputs_handed_off: true,
        }))
        .expect("sender candidate with unshield work");
        db.put_opaque_wallet_private_row(
            &candidate.namespace(),
            WalletPrivateRecordKind::SenderTransactionCandidate,
            &OpaqueWalletPrivateRow {
                row_id: candidate.row_identity(),
                payload: candidate.encode().expect("encode sender candidate"),
            },
        )
        .expect("seed sender candidate");
    }
    let report = SenderCandidateRecoveryReport {
        unshield_awaiting_validation: 1,
        needs_attention: 1,
        ..SenderCandidateRecoveryReport::default()
    };
    let active_list_keys = default_active_poi_list_keys();
    let refined = current_ppoi_workflow_status_for_candidate_report(
        &db,
        &cfg,
        &active_list_keys,
        WalletPpoiWorkflowStatus::default(),
        &report,
    )
    .expect("derive refined status");
    assert_eq!(
        refined,
        WalletPpoiWorkflowStatus {
            awaiting_recovery: 1,
            awaiting_validation: 1,
            recovery_needs_attention: 1,
            ..WalletPpoiWorkflowStatus::default()
        }
    );
    assert_eq!(refined.outstanding_count(), 2);
    // A later pass without durable mutations refines the same base, not the published status.
    assert_eq!(
        current_ppoi_workflow_status_for_candidate_report(
            &db,
            &cfg,
            &active_list_keys,
            refined,
            &report,
        ),
        Some(refined)
    );
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");

    let clamped = ppoi_workflow_status_with_candidate_report(
        WalletPpoiWorkflowStatus {
            awaiting_recovery: 1,
            ..WalletPpoiWorkflowStatus::default()
        },
        &SenderCandidateRecoveryReport {
            unshield_awaiting_validation: 3,
            ..SenderCandidateRecoveryReport::default()
        },
    );
    assert_eq!(
        (clamped.awaiting_recovery, clamped.awaiting_validation),
        (0, 1)
    );
}

#[tokio::test]
async fn maintenance_completion_discards_waiting_details_when_replayed_pending_subject_changes() {
    for replace_subject in [false, true] {
        let root_dir = temp_db_root("wallet-maintenance-subject-publication");
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
        let output = test_wallet_utxo_with_random(110, 17, [0x31; 16]);
        let mut context =
            observed_external_pending_output_context(&cfg, &output, list_key, &source(110, 0xd0));
        context.terminal_error = None;
        context.submitted_poi_list_keys.clear();
        let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../../../core/tests/fixtures/ppoi_3x3_previous.json"
        ))
        .expect("actual previous-key proof");
        let proof: broadcaster_core::transact::PreTxPoi =
            serde_json::from_value(fixture["pre_tx_poi"].clone()).expect("decode old proof");
        context.pre_transaction_pois_per_txid_leaf_per_list = BTreeMap::from([(
            list_key,
            BTreeMap::from([(FixedBytes::from([0x41; 32]), proof)]),
        )]);
        let recovery =
            output_poi_recovery_for_pending_context(&context, OutputPoiRecoveryStatus::Recoverable);
        db.put_pending_output_poi_context(&context)
            .expect("seed pending subject");
        db.put_output_poi_recovery(&recovery)
            .expect("seed replay recovery");
        if replace_subject {
            let mut replacement = context.clone();
            replacement.source_operation_id = Some("replacement-after-replay-snapshot".into());
            *cache_store
                .replay_pending_replacement
                .lock()
                .expect("arm replay race") = Some(replacement);
        }
        let (_live_tx, live_rx) = broadcast::channel(8);
        let (backfill_tx, backfill_rx) = mpsc::channel(8);
        let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        let handle = spawn_wallet_worker(
            WalletWorkerServices {
                db: Arc::clone(&db),
                http_client: None,
                indexed_artifact_source: None,
                poi_runtime: test_artifact_poi_runtime(),
                forest: Arc::new(RwLock::new(MerkleForest::new())),
                backfill_tx: backfill_request_tx,
                backfill_sender: backfill_tx.clone(),
                public_data_plane: test_public_data_plane_with_poi_service(&db),
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
        .expect("spawn worker");
        assert_eq!(
            handle
                .observation()
                .ppoi_workflow_status()
                .awaiting_recovery,
            1
        );
        assert_eq!(
            send_target_token(&backfill_tx, 100, handle.mint_sync_token(0)).await,
            WalletBackfillFinishResult::Ready { committed_to: 100 }
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            while cache_store.recovery_reads.load(Ordering::SeqCst) < 2
                || *handle.poi_refreshing_rx.borrow()
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            // Drain a subsequent actor request so the completion branch has published.
            handle
                .clear_all_local_pending_spent()
                .await
                .expect("actor completion barrier");
        })
        .await
        .expect("maintenance completion");
        let status = *handle.observation().ppoi_workflow_status();
        assert_eq!(status.awaiting_recovery, 1);
        assert_eq!(
            status.awaiting_public_txid_data,
            u64::from(!replace_subject),
            "only the current replay subject may publish its wait detail"
        );
        assert_eq!(status.retrying_recovery, 0);
        assert!(
            cache_store
                .replay_pending_replacement
                .lock()
                .expect("replay race consumed")
                .is_none()
        );
        cancel.cancel();
        drop(handle);
        drop(cache_store);
        drop(db);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }
}

#[tokio::test]
async fn wallet_poi_refresh_rejects_persistence_failure_without_swapping_state() {
    let root_dir = temp_db_root("wallet-poi-refresh-persist-failure");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    cache_store.fail_next_store();
    let mut cfg = wallet_config();
    cfg.chain.chain_id = 42_161;
    cfg.cache_store = Some(cache_store.clone());
    let checkpoint = WalletMeta {
        last_scanned_block: 100,
        updated_at: 88,
        last_scanned_block_hash: Some([0xb6; 32]),
    };
    db.put_wallet_meta(&cfg.cache_key, &checkpoint)
        .expect("seed POI refresh checkpoint");
    let (_live_tx, live_rx) = broadcast::channel(8);
    let (backfill_tx, backfill_rx) = mpsc::channel(8);
    let (backfill_request_tx, _backfill_request_rx) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let public_data_plane = test_public_data_plane(&db);
    let active_poi_list_keys = default_active_poi_list_keys();
    let mut stale_utxo = test_wallet_utxo(105, 7);
    stale_utxo.utxo.poi.statuses.extend(
        active_poi_list_keys
            .iter()
            .copied()
            .map(|list_key| (list_key, PoiStatus::Missing)),
    );
    stale_utxo.utxo.poi.refreshed_at = Some(1);
    let handle = spawn_wallet_worker(
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
        cfg.clone(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        vec![stale_utxo],
        100,
    )
    .await
    .expect("spawn wallet worker");
    let mut persist_state = WalletPersistState::default();
    let (mut actor_state, mut readiness_rx) = test_actor_state_for_handle(&handle, 100);
    let poi_runtime = test_wallet_poi_runtime();
    // Unit test of commit request: job-style reader is fine (not actor path).
    let status_source = poi_runtime
        .status_reader_for_job(&public_data_plane, &cfg, &active_poi_list_keys)
        .await
        .expect("POI status reader");

    let selection = WalletPoiRefreshSelection::RecoverableStale { now: u64::MAX };
    let result = WalletPoiStatusRefreshCommitRequest {
        cache_store: cache_store.as_ref(),
        cfg: &cfg,
        utxos: &handle.utxos,
        worker_handle: &handle,
        last_scanned: 100,
        reset_generation: 0,
        actor_state: &mut actor_state,
        persist_state: &mut persist_state,
        status_reader: status_source.as_reader(),
        active_poi_list_keys: &active_poi_list_keys,
        selection,
        cancel: &cancel,
    }
    .commit()
    .await;

    assert_eq!(result, Err(WalletBackfillRejectReason::PersistenceFailed));
    assert_eq!(
        readiness_rx.borrow().readiness(),
        &WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
    );
    assert_eq!(cache_store.state().last_chain_id, Some(cfg.chain.chain_id));
    let _ = readiness_rx.borrow_and_update();
    assert_eq!(*handle.rev_rx.borrow(), 0);
    let snapshot = handle.utxos.read().await;
    assert!(
        snapshot[0]
            .utxo
            .poi
            .statuses
            .values()
            .all(|status| status == &PoiStatus::Missing)
    );
    assert_eq!(snapshot[0].utxo.poi.refreshed_at, Some(1));
    assert_eq!(cache_store.state().store_calls, 1);
    drop(snapshot);

    assert_eq!(
        WalletPoiStatusRefreshCommitRequest {
            cache_store: cache_store.as_ref(),
            cfg: &cfg,
            utxos: &handle.utxos,
            worker_handle: &handle,
            last_scanned: 100,
            reset_generation: 0,
            actor_state: &mut actor_state,
            persist_state: &mut persist_state,
            status_reader: status_source.as_reader(),
            active_poi_list_keys: &active_poi_list_keys,
            selection,
            cancel: &cancel,
        }
        .commit()
        .await,
        Ok(true)
    );
    assert!(!actor_state.has_persistence_failure());
    assert!(
        readiness_rx
            .has_changed()
            .expect("observation publisher remains active")
    );
    let recovered_observation = readiness_rx.borrow().clone();
    let WalletViewState::Current(recovered_view) = recovered_observation.view() else {
        panic!("successful POI recovery must publish Current");
    };
    assert_eq!(recovered_view.revision, 1);
    assert!(!recovered_view.utxos[0].utxo.poi.statuses.is_empty());
    assert!(
        recovered_view.utxos[0]
            .utxo
            .poi
            .statuses
            .values()
            .any(|status| status != &PoiStatus::Missing)
    );
    assert_eq!(recovered_observation.readiness(), &WalletReadiness::Syncing);
    let retained_checkpoint = db
        .get_wallet_meta(&cfg.cache_key)
        .expect("read retained POI refresh checkpoint")
        .expect("POI refresh checkpoint present");
    assert_eq!(retained_checkpoint.last_scanned_block, 100);
    assert_eq!(retained_checkpoint.updated_at, 88);
    assert_eq!(
        retained_checkpoint.last_scanned_block_hash,
        Some([0xb6; 32])
    );
    let snapshot = handle.utxos.read().await;
    assert!(!snapshot[0].utxo.poi.statuses.is_empty());

    cancel.cancel();
    drop(snapshot);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn same_selection_reader_failure_retains_poi_failure_until_projection_is_obsolete() {
    let root_dir = temp_db_root("wallet-poi-obsolete-failed-selection");
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
    let active_poi_list_keys = default_active_poi_list_keys();
    let mut initial_utxo = test_wallet_utxo(100, 7);
    assert_ne!(
        initial_utxo
            .utxo
            .poi
            .mark_statuses_unknown_for_lists(&active_poi_list_keys),
        0
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
            backfill_sender: backfill_tx,
            public_data_plane: public_data_plane.clone(),
            poi_submitter: ChainPoiSubmitterHandle::detached_for_test(),
        },
        cfg.clone(),
        1,
        live_rx,
        backfill_rx,
        cancel.clone(),
        vec![initial_utxo.clone()],
        100,
    )
    .await
    .expect("spawn wallet worker");
    let mut persist_state = WalletPersistState::default();
    let (mut actor_state, readiness_rx) = test_actor_state_for_handle(&handle, 100);
    let failed_selection = WalletPoiRefreshSelection::RequiredOrRecoverable;
    let unavailable_status_reader = UnavailablePoiStatusReader;
    let valid_status_reader = FixedPoiStatusReader(PoiStatus::Valid);

    assert_eq!(
        WalletPoiStatusRefreshCommitRequest {
            cache_store: cache_store.as_ref(),
            cfg: &cfg,
            utxos: &handle.utxos,
            worker_handle: &handle,
            last_scanned: 100,
            reset_generation: 0,
            actor_state: &mut actor_state,
            persist_state: &mut persist_state,
            status_reader: &valid_status_reader,
            active_poi_list_keys: &active_poi_list_keys,
            selection: failed_selection,
            cancel: &cancel,
        }
        .commit()
        .await,
        Err(WalletBackfillRejectReason::PersistenceFailed)
    );
    assert_eq!(
        readiness_rx.borrow().readiness(),
        &WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
    );

    assert_eq!(
        WalletPoiStatusRefreshCommitRequest {
            cache_store: cache_store.as_ref(),
            cfg: &cfg,
            utxos: &handle.utxos,
            worker_handle: &handle,
            last_scanned: 100,
            reset_generation: 0,
            actor_state: &mut actor_state,
            persist_state: &mut persist_state,
            status_reader: &unavailable_status_reader,
            active_poi_list_keys: &active_poi_list_keys,
            selection: WalletPoiRefreshSelection::Recoverable,
            cancel: &cancel,
        }
        .commit()
        .await,
        Ok(false)
    );
    assert!(actor_state.has_failed_poi_status_refresh(0, failed_selection));

    assert_eq!(
        WalletPoiStatusRefreshCommitRequest {
            cache_store: cache_store.as_ref(),
            cfg: &cfg,
            utxos: &handle.utxos,
            worker_handle: &handle,
            last_scanned: 100,
            reset_generation: 0,
            actor_state: &mut actor_state,
            persist_state: &mut persist_state,
            status_reader: &unavailable_status_reader,
            active_poi_list_keys: &active_poi_list_keys,
            selection: failed_selection,
            cancel: &cancel,
        }
        .commit()
        .await,
        Ok(false)
    );
    assert!(actor_state.has_failed_poi_status_refresh(0, failed_selection));
    assert_eq!(
        readiness_rx.borrow().readiness(),
        &WalletReadiness::Failed(WalletReadinessError::PersistenceFailed)
    );
    assert_eq!(cache_store.state().store_calls, 1);

    let mut last_scanned = 100;
    let mut live_metadata_flush = WalletLiveMetadataFlush::new(100, Instant::now());
    let job_token = WalletSyncToken::for_test(1, 1, 0, 1);
    assert!(actor_state.test_transition(|mut state| state.accept_target(job_token, 101)));
    let spent_source = source(101, 0xaa);
    let outcome = WalletScanCommitRequest {
        cache_store: cache_store.as_ref(),
        cfg: &cfg,
        utxos: &handle.utxos,
        worker_handle: &handle,
        apply: indexed_delta_batch(
            101,
            101,
            WalletLogDelta {
                utxos: Vec::new(),
                nullifiers: vec![SpentNullifier {
                    tree: initial_utxo.utxo.tree,
                    nullifier: initial_utxo.utxo.nullifier(cfg.scan_keys.nullifying_key),
                    source: spent_source,
                }],
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
    assert_eq!(
        outcome.result,
        WalletBackfillApplyResult::Committed { committed_to: 101 }
    );
    assert!(handle.utxos.read().await[0].is_spent());
    let durable_utxos =
        <DbStore as WalletCacheStore>::load_wallet_utxos(db.as_ref(), &cfg.cache_key)
            .expect("load durably spent wallet output");
    assert_eq!(durable_utxos.len(), 1);
    assert!(durable_utxos[0].is_spent());
    assert!(actor_state.has_failed_poi_status_refresh(0, failed_selection));
    assert_eq!(cache_store.state().store_calls, 2);

    assert_eq!(
        WalletPoiStatusRefreshCommitRequest {
            cache_store: cache_store.as_ref(),
            cfg: &cfg,
            utxos: &handle.utxos,
            worker_handle: &handle,
            last_scanned,
            reset_generation: 0,
            actor_state: &mut actor_state,
            persist_state: &mut persist_state,
            status_reader: &valid_status_reader,
            active_poi_list_keys: &active_poi_list_keys,
            selection: failed_selection,
            cancel: &cancel,
        }
        .commit()
        .await,
        Ok(false)
    );
    assert!(!actor_state.has_persistence_failure());
    assert_eq!(cache_store.state().store_calls, 2);

    cancel.cancel();
    drop(handle);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn wallet_poi_refresh_rejects_when_reset_arrives_during_status_fetch() {
    let root_dir = temp_db_root("wallet-poi-refresh-reset-race");
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = Arc::new(FailingCacheStore::new(Arc::clone(&db)));
    let mut cfg = wallet_config();
    cfg.cache_store = Some(cache_store.clone());
    let active_poi_list_keys = default_active_poi_list_keys();
    let initial_utxo = test_wallet_utxo(105, 7);
    let (started_tx, started_rx) = oneshot::channel();
    let (release, release_rx) = oneshot::channel();
    let status_reader = Arc::new(BlockingPoiStatusReader::new(started_tx, release_rx));
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
        vec![initial_utxo],
        100,
    )
    .await
    .expect("spawn wallet worker");
    let (actor_state, readiness_rx) = test_actor_state_for_handle(&handle, 100);
    let commit_cache_store = Arc::clone(&cache_store);
    let commit_cfg = cfg.clone();
    let commit_handle = handle.clone();
    let commit_cancel = cancel.clone();
    let commit_active_poi_list_keys = active_poi_list_keys.clone();
    let commit_status_reader = Arc::clone(&status_reader);
    let commit_task = tokio::spawn(async move {
        let mut persist_state = WalletPersistState::default();
        let mut actor_state = actor_state;
        WalletPoiStatusRefreshCommitRequest {
            cache_store: commit_cache_store.as_ref(),
            cfg: &commit_cfg,
            utxos: &commit_handle.utxos,
            worker_handle: &commit_handle,
            last_scanned: 100,
            reset_generation: 0,
            actor_state: &mut actor_state,
            persist_state: &mut persist_state,
            status_reader: commit_status_reader.as_ref(),
            active_poi_list_keys: &commit_active_poi_list_keys,
            selection: WalletPoiRefreshSelection::RequiredOrRecoverable,
            cancel: &commit_cancel,
        }
        .commit()
        .await
    });
    tokio::time::timeout(Duration::from_secs(2), started_rx)
        .await
        .expect("status request started")
        .expect("status request signal sent");

    assert_eq!(handle.advance_reset_generation().await, Some(1));
    release.send(()).expect("release status reader");
    let result = commit_task.await.expect("commit task");

    assert!(matches!(
        result,
        Err(WalletBackfillRejectReason::StaleGeneration {
            expected: 1,
            actual: 0
        })
    ));
    assert_eq!(readiness_rx.borrow().readiness(), &WalletReadiness::Syncing);
    assert_eq!(*handle.rev_rx.borrow(), 0);
    let snapshot = handle.utxos.read().await;
    assert!(snapshot[0].utxo.poi.statuses.is_empty());
    assert!(snapshot[0].utxo.poi.refreshed_at.is_none());
    assert_eq!(cache_store.state().store_calls, 0);

    cancel.cancel();
    drop(snapshot);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
