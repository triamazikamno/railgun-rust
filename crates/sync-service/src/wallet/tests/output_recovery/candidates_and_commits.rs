use super::*;

#[tokio::test]
async fn candidate_effect_commits_spent_snapshot_and_artifact_bound_atomically() {
    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = RecordingCacheStore::new(Arc::clone(&db));
    let wallet_id = test_cache_key("cache-key");
    let spent_source = source(0x51);
    let mut input = test_wallet_utxo(7);
    input.spent = Some(spent_source.clone());
    let snapshot = vec![input.clone()];
    let candidate = sender_candidate_for_spent_input(wallet_id.clone(), &input, spent_source);
    let handle = test_wallet_handle(snapshot.clone());
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let permit = authority.acquire().await.expect("wallet authority");
    let mut persist_state = WalletPersistState::default();

    let full = persist_state
        .persist_progress_with_private_effects(
            &cache_store,
            &permit,
            WalletProgressPersist {
                cache_key: wallet_id.as_str(),
                snapshot: &snapshot,
                last_scanned: 10,
                checkpoint: WalletCheckpointMutation::Set {
                    last_scanned_block: 10,
                    last_scanned_block_hash: Some([0x10; 32]),
                },
                changed: false,
            },
            WalletProgressPrivateEffects {
                sender_transaction_candidate_updates: std::slice::from_ref(&candidate),
                ..WalletProgressPrivateEffects::default()
            },
        )
        .expect("persist candidate effects");

    assert!(full, "candidate effects require a full durable commit");
    assert_eq!(cache_store.state().store_calls, 1);
    let persisted = <DbStore as WalletCacheStore>::load_wallet_utxos(db.as_ref(), &wallet_id)
        .expect("load persisted snapshot");
    assert_eq!(persisted.len(), 1);
    assert_eq!(persisted[0].spent, input.spent);
    assert_eq!(
        <DbStore as WalletCacheStore>::get_wallet_meta(db.as_ref(), &wallet_id)
            .expect("load artifact_bound")
            .expect("artifact_bound present")
            .last_scanned_block,
        10
    );
    assert!(
        <DbStore as WalletCacheStore>::get_sender_transaction_candidate(
            db.as_ref(),
            1,
            &wallet_id,
            &candidate.semantic_id(),
        )
        .expect("load candidate")
        .is_some()
    );

    let mut replacement_source = candidate.source.clone();
    replacement_source.block_timestamp += 1;
    let mut replacement_input = input;
    replacement_input.spent = Some(replacement_source.clone());
    let replacement_snapshot = vec![replacement_input.clone()];
    let replacement =
        sender_candidate_for_spent_input(wallet_id.clone(), &replacement_input, replacement_source);
    for expected in [&replacement, &replacement] {
        persist_state
            .persist_progress_with_private_effects(
                &cache_store,
                &permit,
                WalletProgressPersist {
                    cache_key: wallet_id.as_str(),
                    snapshot: &replacement_snapshot,
                    last_scanned: 10,
                    checkpoint: WalletCheckpointMutation::Preserve,
                    changed: false,
                },
                WalletProgressPrivateEffects {
                    sender_transaction_candidate_updates: std::slice::from_ref(expected),
                    ..WalletProgressPrivateEffects::default()
                },
            )
            .expect("replace candidate evidence");
    }
    let candidates = <DbStore as WalletCacheStore>::list_sender_transaction_candidates(
        db.as_ref(),
        1,
        &wallet_id,
    )
    .expect("list replaced candidate");
    assert_eq!(candidates.len(), 1);
    assert_eq!(
        candidates[0].encode().expect("encode stored candidate"),
        replacement.encode().expect("encode replacement")
    );

    drop(permit);
    drop(cache_store);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn automatic_recovery_policy_uses_local_proofs_only_and_retains_candidate() {
    let root_dir = temp_db_root();
    let wallet_id = test_cache_key("candidate-maintenance-wallet");
    let spent_source = source(0x53);
    let mut input = test_wallet_utxo(9);
    input.spent = Some(spent_source.clone());
    let candidate = sender_candidate_for_spent_input(wallet_id.clone(), &input, spent_source);
    {
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open seed db");
        db.put_opaque_wallet_private_row(
            &candidate.namespace(),
            WalletPrivateRecordKind::SenderTransactionCandidate,
            &OpaqueWalletPrivateRow {
                row_id: candidate.row_identity(),
                payload: candidate.encode().expect("encode candidate"),
            },
        )
        .expect("persist candidate before restart");
    }

    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("reopen db"),
    );
    let cache_store = RecordingCacheStore::new(Arc::clone(&db));
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = wallet_id.clone();
    let mut handle = test_wallet_handle(vec![input.clone()]);
    handle.cache_key = wallet_id.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let rpc_url = Url::parse("http://127.0.0.1:1").expect("POI RPC URL");
    let poi_runtime = WalletPoiRuntime::from_policy(
        &GlobalPoiPolicy::PoiProxy {
            rpc_url: rpc_url.clone().into(),
        },
        None,
    );
    let poi_client = poi_runtime.public_client().clone();
    let private_poi = WalletPrivatePoiClients::for_submit(
        authority.remote_authority(),
        Arc::new(RecordingPendingOutputPoiSubmitter::default()),
    );
    let public_data_plane = ChainPublicDataPlane::new(Arc::clone(&db), Arc::new(AtomicU64::new(0)));
    let forest = Arc::new(RwLock::new(MerkleForest::new()));
    let active_list_keys = default_active_poi_list_keys();
    let resolver_forest = Arc::new(MerkleForest::new());
    let resolver_wallet_utxos = std::slice::from_ref(&input);
    // Owned-output and sender automatic recovery share this resolver; neither may use remote proofs.
    let proxy_resolver_request = OutputPoiRecoveryRequest {
        authority: &authority,
        db: db.as_ref(),
        cache_store: &cache_store,
        cfg: &cfg,
        public_data_plane: &public_data_plane,
        http_client: None,
        indexed_artifact_source: None,
        forest: Arc::clone(&resolver_forest),
        poi_client: &poi_client,
        private_poi: &private_poi,
        poi_runtime: &poi_runtime,
        active_list_keys: &active_list_keys,
        wallet_utxos: resolver_wallet_utxos,
        force_retry: false,
    };
    assert!(matches!(
        proxy_resolver_request
            .resolve_proof_source(&active_list_keys)
            .await,
        OutputPoiProofSourceResolution::Unavailable
    ));
    let fallback_runtime = test_artifact_poi_runtime_with_fallback(rpc_url);
    let fallback_poi_client = fallback_runtime.public_client().clone();
    let fallback_resolver_request = OutputPoiRecoveryRequest {
        authority: &authority,
        db: db.as_ref(),
        cache_store: &cache_store,
        cfg: &cfg,
        public_data_plane: &public_data_plane,
        http_client: None,
        indexed_artifact_source: None,
        forest: Arc::clone(&resolver_forest),
        poi_client: &fallback_poi_client,
        private_poi: &private_poi,
        poi_runtime: &fallback_runtime,
        active_list_keys: &active_list_keys,
        wallet_utxos: resolver_wallet_utxos,
        force_retry: false,
    };
    assert!(matches!(
        fallback_resolver_request
            .resolve_proof_source(&active_list_keys)
            .await,
        OutputPoiProofSourceResolution::Unavailable
    ));
    // A local resolution records its corpus revision instead of holding the corpus fence, so the
    // corpus writer is never queued behind proof preparation.
    let local_public_data_plane = test_public_data_plane_with_poi_service(&db);
    for list_key in active_list_keys.iter().copied() {
        let mut cache = PoiCache::new(PoiCacheIdentity::new(
            EVM_CHAIN_TYPE,
            cfg.chain.chain_id,
            DEFAULT_TXID_VERSION,
            list_key,
        ));
        cache
            .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
                event_index: 0,
                blinded_commitment: [0x99; 32],
                signature: [0_u8; 64],
                event_type: PoiEventType::Transact,
            }])
            .expect("seed local POI event");
        seed_data_plane_poi_cache(
            &local_public_data_plane,
            cfg.chain.chain_id,
            list_key,
            cache,
        )
        .await;
    }
    let local_runtime = test_artifact_poi_runtime();
    let local_poi_client = local_runtime.public_client().clone();
    let local_resolver_request = OutputPoiRecoveryRequest {
        authority: &authority,
        db: db.as_ref(),
        cache_store: &cache_store,
        cfg: &cfg,
        public_data_plane: &local_public_data_plane,
        http_client: None,
        indexed_artifact_source: None,
        forest: Arc::clone(&resolver_forest),
        poi_client: &local_poi_client,
        private_poi: &private_poi,
        poi_runtime: &local_runtime,
        active_list_keys: &active_list_keys,
        wallet_utxos: resolver_wallet_utxos,
        force_retry: false,
    };
    let local_resolution = local_resolver_request
        .resolve_proof_source(&active_list_keys)
        .await;
    let OutputPoiProofSourceResolution::Local {
        revision, corpus, ..
    } = &local_resolution
    else {
        panic!("a ready local corpus resolves to a local proof source");
    };
    let corpus_caches = corpus.local_caches();
    let write_fence =
        tokio::time::timeout(Duration::from_secs(1), corpus_caches.revision_write_fence())
            .await
            .expect("corpus writer acquires the fence while a local resolution is alive");
    corpus_caches.publish_committed_revision(false);
    drop(write_fence);
    assert_ne!(*corpus.committed_revision_rx().borrow(), *revision);
    drop(local_resolution);
    drop(local_public_data_plane);
    let recovered = (OutputPoiRecoveryRun {
        authority: &authority,
        db: db.as_ref(),
        cache_store: &cache_store,
        cfg: &cfg,
        public_data_plane: &public_data_plane,
        http_client: None,
        indexed_artifact_source: None,
        poi_runtime: &poi_runtime,
        forest: &forest,
        utxos: &handle.utxos,
        client: &poi_client,
        private_poi: &private_poi,
        active_list_keys: &active_list_keys,
        force_retry: false,
        unshield_attempts: &SenderUnshieldAttempts::default(),
    })
    .recover_missing()
    .await;

    assert_eq!(recovered.recovered, 0, "the bounded fixture has no prover");
    assert!(recovered.error.is_none());
    assert_eq!(recovered.candidate_report.awaiting_poi_data, 1);
    assert_eq!(recovered.candidate_report.needs_attention, 0);
    assert_eq!(cache_store.state().candidate_list_calls, 1);
    assert!(
        cache_store
            .get_sender_transaction_candidate(1, &wallet_id, &candidate.semantic_id())
            .expect("reload candidate after maintenance")
            .is_some()
    );

    let fallback = (OutputPoiRecoveryRun {
        authority: &authority,
        db: db.as_ref(),
        cache_store: &cache_store,
        cfg: &cfg,
        public_data_plane: &public_data_plane,
        http_client: None,
        indexed_artifact_source: None,
        poi_runtime: &fallback_runtime,
        forest: &forest,
        utxos: &handle.utxos,
        client: &fallback_poi_client,
        private_poi: &private_poi,
        active_list_keys: &active_list_keys,
        force_retry: false,
        unshield_attempts: &SenderUnshieldAttempts::default(),
    })
    .recover_missing()
    .await;
    assert_eq!(fallback.recovered, 0);
    assert_eq!(fallback.candidate_report.awaiting_poi_data, 1);
    assert_eq!(fallback.candidate_report.needs_attention, 0);
    assert!(
        cache_store
            .get_sender_transaction_candidate(1, &wallet_id, &candidate.semantic_id())
            .expect("reload fallback candidate")
            .is_some()
    );

    cache_store.fail_next_candidate_list();
    let failed = (OutputPoiRecoveryRun {
        authority: &authority,
        db: db.as_ref(),
        cache_store: &cache_store,
        cfg: &cfg,
        public_data_plane: &public_data_plane,
        http_client: None,
        indexed_artifact_source: None,
        poi_runtime: &poi_runtime,
        forest: &forest,
        utxos: &handle.utxos,
        client: &poi_client,
        private_poi: &private_poi,
        active_list_keys: &active_list_keys,
        force_retry: false,
        unshield_attempts: &SenderUnshieldAttempts::default(),
    })
    .recover_missing()
    .await;
    assert_eq!(failed.recovered, 0);
    assert!(matches!(
        failed.error,
        Some(PoiMaintenanceError::SenderCandidateList(_))
    ));
    assert_eq!(cache_store.state().candidate_list_calls, 3);

    drop(public_data_plane);
    drop(cache_store);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn output_poi_recovery_commit_round_trip_does_not_hold_the_corpus_fence() {
    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let list_key = FixedBytes::from([0x61; 32]);
    let spending_public_key = [uint!(4_U256), uint!(5_U256)];
    let mut cfg = wallet_config(U256::ZERO);
    cfg.scan_keys = ViewingKeyData::from_spending_public_key([7_u8; 32], spending_public_key);
    cfg.cache_key = test_cache_key("corpus-fence-cycle");
    cfg.spending_public_key = Some(spending_public_key);
    cfg.poi_recovery_prover = Some(ProverService::new_with_db(&ArtifactSource::default(), &db));

    let mut input = test_wallet_utxo(0);
    let mut output = test_wallet_utxo(8);
    output
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    input.spent = Some(output.utxo.source.clone());
    let mut forest = MerkleForest::new();
    forest
        .insert_leaf(MerkleTreeUpdate {
            tree_number: input.utxo.tree,
            tree_position: input.utxo.position,
            hash: input.utxo.note.commitment(),
        })
        .expect("insert input leaf");
    let merkle_root = forest
        .prove_with_leaf_count(input.utxo.tree, input.utxo.position, 1)
        .expect("input proof")
        .root;
    let graph_response = serde_json::json!({
        "data": {
            "transactions": [{
                "id": "0x00",
                "blockNumber": output.utxo.source.block_number.to_string(),
                "blockTimestamp": output.utxo.source.block_timestamp.to_string(),
                "transactionHash": hex::encode_prefixed(output.utxo.source.tx_hash),
                "merkleRoot": hex::encode_prefixed(FixedBytes::from(merkle_root.to_be_bytes::<32>())),
                "nullifiers": [hex::encode_prefixed(FixedBytes::from(
                    input.utxo.nullifier(cfg.scan_keys.nullifying_key).to_be_bytes::<32>()
                ))],
                "commitments": [hex::encode_prefixed(output.utxo.poi.commitment)],
                "boundParamsHash": "0x33",
                "hasUnshield": false,
                "utxoTreeIn": input.utxo.tree.to_string(),
                "utxoTreeOut": output.utxo.tree.to_string(),
                "utxoBatchStartPositionOut": output.utxo.position.to_string(),
            }]
        }
    })
    .to_string()
    .into_bytes();
    let (graph_endpoint, _graph_requests) = spawn_http_response(graph_response).await;
    cfg.quick_sync_endpoint = Some(graph_endpoint);
    let poi_mock = spawn_poi_rpc_sequence(vec![
        serde_json::json!({
            "validatedTxidIndex": 0,
            "validatedMerkleroot": null,
        }),
        serde_json::json!(true),
    ])
    .await;
    let poi_client = PoiRpcClient::new(poi_mock.url.clone());

    // The input is in the local corpus, so the proof source resolves locally and the preflight
    // passes. Its roots are never validated, so proof generation fails before proving and the
    // job commits a failure record through the actor.
    let public_data_plane = test_public_data_plane_with_poi_service(&db);
    let mut poi_cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        cfg.chain.chain_id,
        DEFAULT_TXID_VERSION,
        list_key,
    ));
    poi_cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: *input.utxo.poi.blinded_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("seed input POI event");
    seed_data_plane_poi_cache(&public_data_plane, cfg.chain.chain_id, list_key, poi_cache).await;
    let corpus_caches = public_data_plane
        .ensure_poi_corpus(PublicPoiCorpusKey::wallet_default(cfg.chain.chain_id))
        .await
        .expect("POI corpus")
        .local_caches();

    let output_commitment = output.utxo.poi.commitment;
    let wallet_utxos = vec![input, output];
    let mut handle = test_wallet_handle(wallet_utxos.clone());
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let (apply_tx, mut apply_rx) = mpsc::channel(1);
    let apply_client = WalletPrivateApplyClient::new(apply_tx);
    let authority =
        WalletPrivateMutationAuthority::new(&handle, 0, &cancel).with_apply_client(&apply_client);
    let private_poi = WalletPrivatePoiClients::for_submit(
        authority.remote_authority(),
        Arc::new(RecordingPendingOutputPoiSubmitter::default()),
    );
    let poi_runtime = test_artifact_poi_runtime();
    let active_list_keys = [list_key];

    // The actor side of the round trip: a corpus writer runs first and must not queue behind a
    // job-held corpus read guard. It publishes a new revision, which a failure record that
    // consumes no local proof commits across.
    let actor_handle = handle.clone();
    let actor_db = Arc::clone(&db);
    let actor_cancel = cancel.clone();
    let actor_cfg = cfg.clone();
    let actor = async move {
        let request = apply_rx
            .recv()
            .await
            .expect("output recovery commit request");
        let write_fence =
            tokio::time::timeout(Duration::from_secs(2), corpus_caches.revision_write_fence())
                .await
                .expect("corpus writer acquires while the job awaits the actor");
        corpus_caches.publish_committed_revision(false);
        drop(write_fence);
        let result = apply_owned_poi_private_delta_on_actor_with_active_lists(
            &actor_handle,
            &actor_cancel,
            request.reset_generation,
            actor_db.as_ref(),
            actor_db.as_ref(),
            &actor_cfg,
            &[list_key],
            request.delta,
        )
        .await;
        request.reply.send(result).expect("send actor result");
    };
    let recovery = recover_missing_output_pois(OutputPoiRecoveryRequest {
        authority: &authority,
        db: db.as_ref(),
        cache_store: db.as_ref(),
        cfg: &cfg,
        public_data_plane: &public_data_plane,
        http_client: None,
        indexed_artifact_source: None,
        forest: Arc::new(forest),
        poi_client: &poi_client,
        private_poi: &private_poi,
        poi_runtime: &poi_runtime,
        active_list_keys: &active_list_keys,
        wallet_utxos: &wallet_utxos,
        force_retry: false,
    });
    let (recovered, ()) = tokio::time::timeout(
        Duration::from_secs(10),
        Box::pin(async { tokio::join!(recovery, actor) }),
    )
    .await
    .expect("output POI recovery finishes without the maintenance watchdog");

    assert_eq!(recovered, 0);
    let record = db
        .get_output_poi_recovery(cfg.chain.chain_id, &cfg.cache_key, &output_commitment)
        .expect("load recovery record")
        .expect("failure record commits after the corpus revision changed");
    assert_eq!(
        record.status,
        OutputPoiRecoveryStatus::ProofGenerationFailed
    );
    assert!(
        record
            .last_error
            .as_deref()
            .is_some_and(|error| error.contains("root validation required")),
        "the job reached proof generation from a local resolution: {record:?}"
    );

    drop(public_data_plane);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn pending_output_and_recovery_reads_route_through_wallet_cache_store() {
    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let chain_id = 1;
    let wallet_id = test_cache_key("wallet-1");
    let output_commitment = FixedBytes::from([0x73; 32]);
    let pending = pending_output_record(chain_id, output_commitment, FixedBytes::from([0x74; 32]));
    db.put_pending_output_poi_context(&pending)
        .expect("seed pending context");
    db.put_output_poi_recovery(&output_poi_recovery_record(
        chain_id,
        wallet_id.as_str(),
        output_commitment,
        OutputPoiRecoveryStatus::Recoverable,
        None,
    ))
    .expect("seed recovery");
    let cache_store = RecordingCacheStore::new(Arc::clone(&db));
    let observation = CommitmentObservation {
        tree: 12,
        position: 34,
        commitment: U256::from_be_bytes(output_commitment.0),
        source: source(8),
    };

    let updates =
        pending_output_poi_observation_updates(&cache_store, chain_id, &wallet_id, &[observation])
            .expect("prepare observation update");
    assert_eq!(updates.len(), 1);
    assert!(
        cache_store
            .get_output_poi_recovery(chain_id, &wallet_id, &output_commitment)
            .expect("load recovery through cache store")
            .is_some()
    );
    assert_eq!(cache_store.state().pending_output_read_calls, 1);
    assert_eq!(cache_store.state().output_recovery_read_calls, 1);

    drop(cache_store);
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn live_metadata_flush_waits_for_interval_or_block_threshold() {
    let now = Instant::now();
    let flush = WalletLiveMetadataFlush::new(100, now);

    assert!(!flush.should_flush(100 + WALLET_METADATA_LIVE_FLUSH_BLOCKS - 1, now));
    assert!(flush.should_flush(100 + WALLET_METADATA_LIVE_FLUSH_BLOCKS, now));
    assert!(flush.should_flush(101, now + WALLET_METADATA_LIVE_FLUSH_INTERVAL));
}

#[test]
fn live_metadata_flush_mark_persisted_resets_thresholds() {
    let now = Instant::now();
    let mut flush = WalletLiveMetadataFlush::new(100, now);

    flush.mark_persisted(125, now + WALLET_METADATA_LIVE_FLUSH_INTERVAL);

    assert!(!flush.should_flush(125, now + WALLET_METADATA_LIVE_FLUSH_INTERVAL));
    assert!(!flush.should_flush(
        125 + WALLET_METADATA_LIVE_FLUSH_BLOCKS - 1,
        now + WALLET_METADATA_LIVE_FLUSH_INTERVAL
    ));
    assert!(flush.should_flush(
        125 + WALLET_METADATA_LIVE_FLUSH_BLOCKS,
        now + WALLET_METADATA_LIVE_FLUSH_INTERVAL
    ));
}
