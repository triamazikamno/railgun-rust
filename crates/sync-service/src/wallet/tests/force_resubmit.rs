use super::*;

#[test]
fn pending_output_poi_context_matches_wallet_output_identity() {
    let cfg = wallet_config(U256::ZERO);
    let list_key = FixedBytes::from([0x49; 32]);
    let wallet_utxo = test_wallet_utxo(38);
    let record = matching_pending_output_record(&cfg, &wallet_utxo, list_key);

    assert_eq!(record.wallet_id, cfg.cache_key.as_str());

    assert!(pending_output_poi_context_matches_wallet_utxo(
        &cfg,
        &wallet_utxo,
        &record
    ));

    let mut wrong_wallet = record.clone();
    wrong_wallet.wallet_id = "other-wallet".to_string();
    assert!(!pending_output_poi_context_matches_wallet_utxo(
        &cfg,
        &wallet_utxo,
        &wrong_wallet
    ));

    let mut wrong_position = record.clone();
    wrong_position
        .observation
        .as_mut()
        .expect("observation")
        .output_position += 1;
    assert!(!pending_output_poi_context_matches_wallet_utxo(
        &cfg,
        &wallet_utxo,
        &wrong_position
    ));

    let mut wrong_npk = record;
    wrong_npk.output_npk = FixedBytes::from([0x88; 32]);
    assert!(!pending_output_poi_context_matches_wallet_utxo(
        &cfg,
        &wallet_utxo,
        &wrong_npk
    ));
}

#[tokio::test]
async fn force_resubmits_matching_pending_output_despite_permanent_recovery_state() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let cfg = wallet_config(U256::ZERO);
    let list_key = FixedBytes::from([0x4a; 32]);
    let mut wallet_utxo = test_wallet_utxo(39);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    store
        .put_output_poi_recovery(&output_poi_recovery_record(
            cfg.chain.chain_id,
            &cfg.cache_key,
            wallet_utxo.utxo.poi.commitment,
            OutputPoiRecoveryStatus::MissingWalletOutputs,
            None,
        ))
        .expect("store recovery state");
    let submitter = RecordingPendingOutputPoiSubmitter::default();

    let submitted = force_resubmit_matching_pending_output_pois(
        &store,
        &cfg,
        &[wallet_utxo.clone()],
        &[list_key],
        &submitter,
    )
    .await;

    assert_eq!(submitted, 1);
    assert_eq!(
        submitter.calls(),
        vec![(
            wallet_utxo.utxo.poi.commitment,
            u64::from(wallet_utxo.utxo.tree),
            wallet_utxo.utxo.position,
        ),]
    );
    let recovery = store
        .get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &wallet_utxo.utxo.poi.commitment,
        )
        .expect("load recovery")
        .expect("recovery present");
    assert_eq!(recovery.status, OutputPoiRecoveryStatus::Submitted);
    assert!(recovery.last_submission_at.is_some());
    assert!(recovery.next_retry_at.is_some());

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn force_resubmitted_recovered_pending_output_uses_pending_retry_delay() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let cfg = wallet_config(U256::ZERO);
    let list_key = FixedBytes::from([0x4c; 32]);
    let mut wallet_utxo = test_wallet_utxo(41);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    pending.wallet_id = cfg.cache_key.to_string();
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let submitter = RecordingPendingOutputPoiSubmitter::default();

    let submitted = force_resubmit_matching_pending_output_pois(
        &store,
        &cfg,
        &[wallet_utxo.clone()],
        &[list_key],
        &submitter,
    )
    .await;

    assert_eq!(submitted, 1);
    assert_eq!(
        submitter.calls(),
        vec![(
            wallet_utxo.utxo.poi.commitment,
            u64::from(wallet_utxo.utxo.tree),
            wallet_utxo.utxo.position,
        ),]
    );
    let recovery = store
        .get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &wallet_utxo.utxo.poi.commitment,
        )
        .expect("load recovery")
        .expect("recovery present");
    let last_submission_at = recovery
        .last_submission_at
        .expect("last submission timestamp");
    assert_eq!(recovery.status, OutputPoiRecoveryStatus::Submitted);
    assert_eq!(recovery.attempt_count, 1);
    assert_eq!(
        recovery.next_retry_at,
        Some(last_submission_at + PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER.as_secs())
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn authorized_force_submits_only_recoverable_subset() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-force-mixed-statuses");
    let list_a = FixedBytes::from([0x4d; 32]);
    let list_b = FixedBytes::from([0x4e; 32]);
    let mut wallet_utxo = test_wallet_utxo(42);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_a, PoiStatus::Missing);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_b, PoiStatus::ShieldBlocked);
    let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, list_a);
    let leaf = FixedBytes::from([0x4f; 32]);
    pending.required_poi_list_keys = vec![list_a, list_b];
    pending.submitted_poi_list_keys = vec![list_a, list_b];
    pending
        .pre_transaction_pois_per_txid_leaf_per_list
        .insert(list_b, BTreeMap::from([(leaf, sample_pre_tx_poi(0x12))]));
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let mut handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let submitter = Arc::new(RecordingPendingOutputPoiSubmitter::default());
    let private_poi =
        WalletPrivatePoiClients::for_submit(authority.remote_authority(), submitter.clone());
    let utxos = Arc::new(RwLock::new(vec![wallet_utxo]));

    let attempted = force_resubmit_matching_pending_output_pois_authorized(
        &authority,
        &test_public_data_plane_with_poi_service(&store),
        store.as_ref(),
        store.as_ref(),
        &cfg,
        &utxos,
        &[list_a, list_b],
        &private_poi,
    )
    .await;

    assert_eq!(attempted, 1);
    assert_eq!(
        submitter.list_key_calls(),
        vec![vec![list_a]],
        "force must exclude the shield-blocked list from transport"
    );
    let persisted = store
        .get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &pending.output_commitment,
        )
        .expect("load pending context")
        .expect("pending context present");
    assert_eq!(persisted.list_keys(), vec![list_a, list_b]);
    assert_eq!(persisted.submitted_poi_list_keys, vec![list_a, list_b]);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test(start_paused = true)]
async fn routed_forced_transact_resubmission_survives_deferral_in_random_order() {
    for seed in 0..32 {
        let (order, store_order) = routed_forced_resubmission_order(seed).await;
        let mut admitted = order.clone();
        admitted.sort_unstable();
        assert_eq!(admitted, [1, 2, 3], "every transaction is admitted once");
        if order != store_order {
            return;
        }
    }
    panic!("every seed admitted the transactions in store order");
}

#[test]
fn routed_submission_order_weights_items_and_keeps_keys_together() {
    let handle = test_wallet_handle(Vec::new());
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let unrouted = WalletPrivatePoiClients::for_status(
        authority.remote_authority(),
        Arc::new(RecordingPoiStatusClient::default()),
    );
    let routed = unrouted.clone().with_submission_routing(
        Some(RecordingRoutes::new().routing(seeded_scheduler(0))),
        DeferredForcedSubmissions::default(),
    );
    assert_eq!(unrouted.submission_order(vec![1, 2, 3], |_| 1), [1, 2, 3]);

    // A candidate with three unshields goes first three times as often as one with one.
    let heavy_first = (0..400)
        .filter(|_| routed.submission_order(vec![1, 3], |&weight| weight)[0] == 3)
        .count();
    assert!((260..=340).contains(&heavy_first), "{heavy_first} of 400");
    let grouped =
        routed.submission_order_by_key(vec![(1, 'a'), (2, 'b'), (1, 'c')], |&(key, _)| key);
    assert!(
        grouped == [(1, 'a'), (1, 'c'), (2, 'b')] || grouped == [(2, 'b'), (1, 'a'), (1, 'c')],
        "{grouped:?}"
    );
}

/// A deferred force-resubmit of a recovered outgoing context is replayed as a
/// force-resubmit of every matching list, without the group evidence its
/// ordinary submission needs, while a deferred forced retry keeps its
/// recovery gate.
#[tokio::test]
async fn routed_deferred_forced_intent_keeps_its_kind() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-routed-forced-kinds");
    let list_a = FixedBytes::from([0x6b; 32]);
    let list_b = FixedBytes::from([0x6c; 32]);
    let active_list_keys = [list_a, list_b];
    // Submitted to one list and missing from the other, with no recovery
    // record or corpus evidence for a recovered outgoing group.
    let mut recovered =
        external_pending_output_record(&cfg, 0xc1, list_a, PendingOutputPoiRole::RecoveredOutgoing);
    recovered.railgun_txid = U256::from(1);
    recovered.txid_merkleroot_index = Some(1);
    recovered.required_poi_list_keys = vec![list_a, list_b];
    recovered.submitted_poi_list_keys = vec![list_a];
    recovered
        .pre_transaction_pois_per_txid_leaf_per_list
        .insert(
            list_b,
            BTreeMap::from([(FixedBytes::from([0x55; 32]), sample_pre_tx_poi(0x11))]),
        );
    store
        .put_pending_output_poi_context(&recovered)
        .expect("store recovered outgoing context");
    let mut retried =
        external_pending_output_record(&cfg, 0xc2, list_a, PendingOutputPoiRole::Recipient);
    retried.railgun_txid = U256::from(2);
    retried.txid_merkleroot_index = Some(2);
    retried.submitted_poi_list_keys = vec![list_a];
    let retried_recovery = |status| {
        let mut recovery = output_poi_recovery_record(
            cfg.chain.chain_id,
            &cfg.cache_key,
            retried.output_commitment,
            status,
            Some(u64::MAX),
        );
        recovery.source_tx_hash = retried.observation.as_ref().expect("observation").tx_hash;
        recovery
    };
    let durable = |output_commitment: &FixedBytes<32>| {
        let record = store
            .get_pending_output_poi_context(cfg.chain.chain_id, &cfg.cache_key, output_commitment)
            .expect("load pending context");
        let recovery = store
            .get_output_poi_recovery(cfg.chain.chain_id, &cfg.cache_key, output_commitment)
            .expect("load recovery");
        format!("{record:?} {recovery:?}")
    };
    let mut handle = test_wallet_handle(Vec::new());
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    // No spacing and one route, so another transaction's admission defers both.
    let scheduler = PoiSubmissionScheduler::new(
        PoiSubmissionSchedulerConfig {
            min_admission_gap: Duration::ZERO,
            max_admission_gap: Duration::ZERO,
            max_open_routes: 1,
        },
        rand::SeedableRng::seed_from_u64(0),
    );
    let PoiSubmissionAdmission::Admitted(other) =
        scheduler.try_reserve(cfg.chain.chain_id, U256::MAX)
    else {
        panic!("an idle scheduler admits");
    };
    let routes = RecordingRoutes::new();
    let shared = Arc::new(RecordingPendingOutputPoiSubmitter::default());
    let private_poi =
        WalletPrivatePoiClients::for_submit(authority.remote_authority(), shared.clone())
            .with_submission_routing(
                Some(routes.routing(Arc::clone(&scheduler))),
                DeferredForcedSubmissions::default(),
            );
    let public_data_plane = test_public_data_plane_with_poi_service(&store);
    let ordinary_pass = |force_submission_retry| {
        process_pending_output_poi_observations_authorized(
            &authority,
            &public_data_plane,
            store.as_ref(),
            store.as_ref(),
            &cfg,
            &active_list_keys,
            Some(&private_poi),
            force_submission_retry,
        )
    };

    let recovered_before = durable(&recovered.output_commitment);
    let attempted = force_resubmit_matching_pending_output_pois_authorized(
        &authority,
        &public_data_plane,
        store.as_ref(),
        store.as_ref(),
        &cfg,
        &Arc::new(RwLock::new(Vec::new())),
        &active_list_keys,
        &private_poi,
    )
    .await;
    assert_eq!(attempted, 0, "the force-resubmit is deferred");
    store
        .put_pending_output_poi_context(&retried)
        .expect("store retried context");
    store
        .put_output_poi_recovery(&retried_recovery(OutputPoiRecoveryStatus::Submitted))
        .expect("store retried recovery");
    let retried_before = durable(&retried.output_commitment);
    assert_eq!(ordinary_pass(true).await, 0, "the forced retry is deferred");
    assert_eq!(
        private_poi.deferred_forced_txids(),
        BTreeMap::from([
            (U256::from(1), DeferredForceKind::ForceMatching),
            (U256::from(2), DeferredForceKind::RetrySubmitted),
        ]),
        "a replayed force-resubmit stays one"
    );
    assert_eq!(durable(&recovered.output_commitment), recovered_before);
    assert_eq!(
        durable(&retried.output_commitment),
        retried_before,
        "a deferral writes nothing"
    );
    assert_eq!(routes.opens(), 0);

    // The retry's recovery becomes permanent before the route frees up.
    store
        .put_output_poi_recovery(&retried_recovery(
            OutputPoiRecoveryStatus::MissingWalletOutputs,
        ))
        .expect("store permanent retried recovery");
    drop(other);
    // An unshield of the same transaction is admitted first and sends nothing.
    let unshield = private_poi
        .reserve_transact_route(cfg.chain.chain_id, U256::from(1), None)
        .await
        .expect("unshield admitted");
    drop(unshield);
    assert_eq!(
        private_poi.deferred_forced_txids().len(),
        2,
        "unshield admission keeps the outputs' forced intent"
    );
    assert_eq!(ordinary_pass(false).await, 1);
    let routed = routes.routes();
    assert_eq!(routed.len(), 2, "only the force-resubmit is sent");
    assert_eq!(routed[0].transact_sends(), [] as [(u64, FixedBytes<32>); 0]);
    let mut sends = routed[1].transact_sends();
    sends.sort_unstable();
    assert_eq!(
        sends,
        vec![(1, list_a), (1, list_b)],
        "every matching list, submitted or not"
    );
    assert_eq!(
        private_poi.deferred_forced_txids(),
        BTreeMap::from([(U256::from(2), DeferredForceKind::RetrySubmitted)]),
        "admission ends the force-resubmit's intent"
    );

    assert_eq!(ordinary_pass(false).await, 0);
    assert_eq!(
        routes.routes().len(),
        2,
        "submitted work is not forced again"
    );
    assert!(
        shared.calls().is_empty(),
        "routed proofs never use the shared client"
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

/// A reset gives the next generation fresh forced deferrals; an obsolete job
/// still running records only into its own.
#[tokio::test]
async fn reset_leaves_obsolete_forced_deferrals_with_the_old_job() {
    let handle = test_wallet_handle(Vec::new());
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let routes = RecordingRoutes::new();
    routes.fail_opens(true);
    let routing = routes.routing(seeded_scheduler(0));
    let job_clients = |forced_deferrals: DeferredForcedSubmissions| {
        WalletPrivatePoiClients::for_status(
            authority.remote_authority(),
            Arc::new(RecordingPoiStatusClient::default()),
        )
        .with_submission_routing(Some(routing.clone()), forced_deferrals)
    };
    let mut controller = PoiMaintenanceController::new();
    let obsolete_job = job_clients(controller.forced_deferrals());

    controller.clear_force_on_reset();
    // The obsolete job's route fails to open only after the reset.
    assert!(
        obsolete_job
            .reserve_transact_route(1, U256::from(1), Some(DeferredForceKind::ForceMatching),)
            .await
            .is_err()
    );
    assert_eq!(obsolete_job.deferred_forced_txids().len(), 1);
    let next_job = job_clients(controller.forced_deferrals());
    assert!(
        next_job.deferred_forced_txids().is_empty(),
        "obsolete forced intent does not cross the reset"
    );

    assert!(
        next_job
            .reserve_transact_route(1, U256::from(2), Some(DeferredForceKind::RetrySubmitted),)
            .await
            .is_err()
    );
    assert_eq!(
        job_clients(controller.forced_deferrals()).deferred_forced_txids(),
        BTreeMap::from([(U256::from(2), DeferredForceKind::RetrySubmitted)]),
        "the new generation keeps its own forced intent"
    );
}

/// A reset interrupts an obsolete job's pending route open, and the job then
/// takes no admission; neither records forced intent.
#[tokio::test(start_paused = true)]
async fn reset_interrupts_route_open_and_bars_obsolete_admission() {
    let handle = test_wallet_handle(Vec::new());
    let cancel = CancellationToken::new();
    let obsolete = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let current = WalletPrivateMutationAuthority::new(&handle, 1, &cancel);
    let routes = RecordingRoutes::new();
    // One route, so a slot the interrupted open kept would block the next one.
    let scheduler = PoiSubmissionScheduler::new(
        PoiSubmissionSchedulerConfig {
            max_open_routes: 1,
            ..PoiSubmissionSchedulerConfig::default()
        },
        rand::SeedableRng::seed_from_u64(0),
    );
    let job_clients = |authority: &WalletPrivateMutationAuthority<'_>| {
        WalletPrivatePoiClients::for_status(
            authority.remote_authority(),
            Arc::new(RecordingPoiStatusClient::default()),
        )
        .with_submission_routing(
            Some(routes.routing(Arc::clone(&scheduler))),
            DeferredForcedSubmissions::default(),
        )
    };
    let obsolete_job = job_clients(&obsolete);
    routes.set_open_gate(false);

    let (interrupted, generation) = tokio::join!(
        tokio::time::timeout(
            Duration::from_secs(1),
            obsolete_job.reserve_transact_route(
                1,
                U256::from(1),
                Some(DeferredForceKind::ForceMatching),
            ),
        ),
        async {
            while routes.opens() == 0 {
                tokio::task::yield_now().await;
            }
            handle.advance_reset_generation().await
        },
    );
    assert_eq!(generation, Some(1));
    let deferred = interrupted
        .expect("the reset interrupts the stalled open")
        .err()
        .expect("no route");
    assert_eq!(deferred.retry_after(), Duration::ZERO);

    routes.set_open_gate(true);
    tokio::time::advance(MAX_ADMISSION_GAP).await;
    assert!(
        obsolete_job
            .reserve_transact_route(1, U256::from(3), Some(DeferredForceKind::ForceMatching))
            .await
            .is_err()
    );
    assert_eq!(routes.opens(), 1, "the obsolete job reaches no provider");
    assert!(
        obsolete_job.deferred_forced_txids().is_empty(),
        "stale work records no forced intent"
    );
    assert!(
        job_clients(&current)
            .reserve_transact_route(1, U256::from(2), None)
            .await
            .is_ok(),
        "the slot is free and no admission gap was consumed"
    );
    assert_eq!(routes.opens(), 2);
}

#[tokio::test]
async fn force_resubmit_preflight_skips_spent_output_before_remote_submit() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-force-spent");
    let list_key = FixedBytes::from([0x51; 32]);
    let mut wallet_utxo = test_wallet_utxo(51);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    pending.output_role = PendingOutputPoiRole::Change;
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    // Discovery snapshot still has the UTXO, but live handle is empty (spent/removed).
    let mut handle = test_wallet_handle(Vec::new());
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let submitter = Arc::new(RecordingPendingOutputPoiSubmitter::default());
    let private_poi =
        WalletPrivatePoiClients::for_submit(authority.remote_authority(), submitter.clone());

    let utxos = Arc::new(tokio::sync::RwLock::new(vec![wallet_utxo]));
    let attempted = force_resubmit_matching_pending_output_pois_authorized(
        &authority,
        &test_public_data_plane_with_poi_service(&store),
        store.as_ref(),
        store.as_ref(),
        &cfg,
        &utxos,
        &[list_key],
        &private_poi,
    )
    .await;

    assert_eq!(attempted, 0);
    assert!(
        submitter.calls().is_empty(),
        "remote submit must not start when live UTXO no longer matches"
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn force_resubmit_preflight_aborts_on_stale_generation() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-force-stale");
    let list_key = FixedBytes::from([0x52; 32]);
    let mut wallet_utxo = test_wallet_utxo(52);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let mut handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    handle.cache_key = cfg.cache_key.clone();
    assert_eq!(handle.advance_reset_generation().await, Some(1));
    handle.notify_changed().await;
    let cancel = CancellationToken::new();
    // Authority still binds generation 0; handle is at 1.
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let submitter = Arc::new(RecordingPendingOutputPoiSubmitter::default());
    let private_poi =
        WalletPrivatePoiClients::for_submit(authority.remote_authority(), submitter.clone());

    let utxos = Arc::new(tokio::sync::RwLock::new(vec![wallet_utxo]));
    let attempted = force_resubmit_matching_pending_output_pois_authorized(
        &authority,
        &test_public_data_plane_with_poi_service(&store),
        store.as_ref(),
        store.as_ref(),
        &cfg,
        &utxos,
        &[list_key],
        &private_poi,
    )
    .await;

    assert_eq!(attempted, 0);
    assert!(
        submitter.calls().is_empty(),
        "remote submit must not start when authority generation is stale"
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn multi_proof_submit_revalidates_between_remote_calls() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-multi-proof");
    let list_a = FixedBytes::from([0x61; 32]);
    let list_b = FixedBytes::from([0x62; 32]);
    let mut wallet_utxo = test_wallet_utxo(61);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_a, PoiStatus::Missing);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_b, PoiStatus::Missing);
    let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, list_a);
    pending.txid_merkleroot_index = Some(105_572);
    pending.required_poi_list_keys = vec![list_a, list_b];
    pending.submitted_poi_list_keys = vec![list_a, list_b];
    let leaf = FixedBytes::from([0x99; 32]);
    pending.pre_transaction_pois_per_txid_leaf_per_list = BTreeMap::from([
        (list_a, BTreeMap::from([(leaf, sample_pre_tx_poi(0x10))])),
        (list_b, BTreeMap::from([(leaf, sample_pre_tx_poi(0x11))])),
    ]);
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let mut handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let submitter = Arc::new(ResetAfterFirstPendingOutputPoiSubmitter::new(
        handle.clone(),
    ));
    let private_poi =
        WalletPrivatePoiClients::for_submit(authority.remote_authority(), submitter.clone());
    let observation = pending.observation.clone().expect("observation");
    let plan = super::super::PendingOutputPoiSubmissionPlan::force_matching(
        vec![list_a, list_b],
        ExpectedRecordState::Absent,
    );
    let subject = PendingOutputPoiSubject::Owned(ExpectedWalletOutput::new(&wallet_utxo));
    let active_lists = [list_a, list_b];

    let attempt = preflight_and_remote_submit_pending_output_poi(
        &PendingOutputPoiSubmissionPreflight {
            authority: &authority,
            public_data_plane: &test_public_data_plane_with_poi_service(&store),
            cache_store: store.as_ref(),
            cfg: &cfg,
            active_list_keys: &active_lists,
            expected: &pending,
            subject: &subject,
            plan: &plan,
        },
        &observation,
        &private_poi,
        &mut None,
    )
    .await
    .expect("submit result");
    assert!(
        matches!(
            attempt,
            super::super::PendingOutputPoiRemoteAttempt::AuthorityStale
                | super::super::PendingOutputPoiRemoteAttempt::NotCurrent
        ),
        "expected generation fence mid multi-proof, got {attempt:?}"
    );
    assert_eq!(
        submitter.calls(),
        1,
        "first submit returns after advancing generation; second must not start"
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn force_resubmit_ignores_nonmatching_pending_output_context() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let cfg = wallet_config(U256::ZERO);
    let list_key = FixedBytes::from([0x4b; 32]);
    let mut wallet_utxo = test_wallet_utxo(40);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    pending.output_npk = FixedBytes::from([0x89; 32]);
    pending.submitted_poi_list_keys = vec![list_key];
    store
        .put_pending_output_poi_context(&pending)
        .expect("store pending context");
    let submitter = RecordingPendingOutputPoiSubmitter::default();

    let submitted = force_resubmit_matching_pending_output_pois(
        &store,
        &cfg,
        &[wallet_utxo],
        &[list_key],
        &submitter,
    )
    .await;

    assert_eq!(submitted, 0);
    assert_eq!(submitter.calls(), [] as [(FixedBytes<32>, u64, u64); 0]);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

/// Forces resubmission of three transactions' transact proofs over seeded
/// routes, then runs ordinary passes a gap apart. Returns the TXID merkleroot
/// index sent over each route in admission order, and the indexes in store order.
async fn routed_forced_resubmission_order(seed: u64) -> (Vec<u64>, Vec<u64>) {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-routed-transact");
    let list_key = FixedBytes::from([0x6a; 32]);
    let mut wallet_utxos = Vec::new();
    for index in 1_u8..=3 {
        let mut wallet_utxo = WalletUtxo::new(Utxo::new(
            Note {
                token_hash: uint!(1_U256),
                // The commitment covers npk, token and value, so vary the value.
                value: U256::from(10 + u64::from(index)),
                random: [index; 16],
                npk: uint!(2_U256),
            },
            2,
            u64::from(index),
            source(index),
            UtxoCommitmentKind::Transact,
        ));
        wallet_utxo
            .utxo
            .poi
            .statuses
            .insert(list_key, PoiStatus::ProofSubmitted);
        let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
        pending.railgun_txid = U256::from(index);
        pending.txid_merkleroot_index = Some(u64::from(index));
        pending.submitted_poi_list_keys = vec![list_key];
        store
            .put_pending_output_poi_context(&pending)
            .expect("store pending context");
        // A permanent state never retried, so only the force-resubmit
        // request's own intent can resubmit it.
        let mut recovery = output_poi_recovery_record(
            cfg.chain.chain_id,
            &cfg.cache_key,
            wallet_utxo.utxo.poi.commitment,
            OutputPoiRecoveryStatus::MissingWalletOutputs,
            Some(u64::MAX),
        );
        recovery.source_tx_hash = wallet_utxo.utxo.source.tx_hash;
        store
            .put_output_poi_recovery(&recovery)
            .expect("store recovery");
        wallet_utxos.push(wallet_utxo);
    }
    let records = || {
        store
            .list_pending_output_poi_contexts(cfg.chain.chain_id, &cfg.cache_key)
            .expect("list pending contexts")
    };
    let durable = |index: u64| {
        let record = records()
            .into_iter()
            .find(|record| record.txid_merkleroot_index == Some(index))
            .expect("pending context");
        let recovery = store
            .get_output_poi_recovery(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &record.output_commitment,
            )
            .expect("load recovery");
        format!("{record:?} {recovery:?}")
    };
    let store_order = records()
        .iter()
        .filter_map(|record| record.txid_merkleroot_index)
        .collect::<Vec<_>>();
    let before = store_order
        .iter()
        .map(|&index| durable(index))
        .collect::<Vec<_>>();
    let mut handle = test_wallet_handle(wallet_utxos.clone());
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let shared = Arc::new(RecordingPendingOutputPoiSubmitter::default());
    let routes = RecordingRoutes::new();
    let private_poi =
        WalletPrivatePoiClients::for_submit(authority.remote_authority(), shared.clone())
            .with_submission_routing(
                Some(routes.routing(seeded_scheduler(seed))),
                DeferredForcedSubmissions::default(),
            );
    let public_data_plane = test_public_data_plane_with_poi_service(&store);
    let admitted = || {
        routes
            .routes()
            .iter()
            .map(|route| match route.transact_sends().as_slice() {
                [(index, sent_list)] if *sent_list == list_key => *index,
                sends => panic!("one transaction's proof per route, got {sends:?}"),
            })
            .collect::<Vec<_>>()
    };

    let attempted = force_resubmit_matching_pending_output_pois_authorized(
        &authority,
        &public_data_plane,
        store.as_ref(),
        store.as_ref(),
        &cfg,
        &Arc::new(RwLock::new(wallet_utxos)),
        &[list_key],
        &private_poi,
    )
    .await;
    assert_eq!(attempted, 1, "spacing defers the other transactions");
    let first = admitted();
    for (index, before) in store_order.iter().zip(&before) {
        if first != [*index] {
            assert_eq!(&durable(*index), before, "a deferral writes nothing");
        }
    }
    // Ordinary passes send the deferred forced work without a new request
    // and long before its retry time, but never force submitted work again.
    for expected in [1, 1, 0] {
        tokio::time::advance(MAX_ADMISSION_GAP).await;
        let submitted = process_pending_output_poi_observations_authorized(
            &authority,
            &public_data_plane,
            store.as_ref(),
            store.as_ref(),
            &cfg,
            &[list_key],
            Some(&private_poi),
            false,
        )
        .await;
        assert_eq!(submitted, expected);
    }
    assert!(
        shared.calls().is_empty(),
        "routed proofs never use the shared client"
    );
    let order = admitted();

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
    (order, store_order)
}
