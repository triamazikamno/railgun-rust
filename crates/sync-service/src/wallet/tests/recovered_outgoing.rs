use super::*;

#[tokio::test]
async fn recovered_outgoing_siblings_submit_once_and_preserve_ordinary_behavior() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let list_key = FixedBytes::from([0xd4; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-recovered-outgoing-group");
    let group = recovered_outgoing_pending_group(&cfg, list_key);
    seed_recovered_outgoing_pending_group(&store, &cfg, &group);
    let ordinary =
        external_pending_output_record(&cfg, 0xd5, list_key, PendingOutputPoiRole::Recipient);
    store
        .put_pending_output_poi_context(&ordinary)
        .expect("store ordinary context");
    let mut handle = test_wallet_handle(Vec::new());
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let submitter = Arc::new(RecordingPendingOutputPoiSubmitter::default());
    let private_poi =
        WalletPrivatePoiClients::for_submit(authority.remote_authority(), submitter.clone());

    let submitted = process_pending_output_poi_observations_authorized(
        &authority,
        &test_public_data_plane_with_poi_service(&store),
        store.as_ref(),
        store.as_ref(),
        &cfg,
        &[list_key],
        Some(&private_poi),
        false,
    )
    .await;

    assert_eq!(submitted, 3);
    assert_eq!(
        submitter.calls().len(),
        2,
        "one grouped and one ordinary RPC"
    );
    for record in group.iter().chain(std::iter::once(&ordinary)) {
        let current = store
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &record.output_commitment,
            )
            .expect("load submitted context")
            .expect("context remains pending validation");
        assert_eq!(current.submitted_poi_list_keys, vec![list_key]);
        assert_eq!(
            store
                .get_output_poi_recovery(
                    cfg.chain.chain_id,
                    &cfg.cache_key,
                    &record.output_commitment,
                )
                .expect("load submitted recovery")
                .expect("recovery present")
                .status,
            OutputPoiRecoveryStatus::Submitted
        );
    }

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn recovered_outgoing_group_uses_only_exact_current_owned_substitute() {
    for case in ["valid", "missing", "spent", "source", "status", "stale"] {
        let root_dir = temp_db_root();
        let store = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let list_key = FixedBytes::from([0xdb; 32]);
        let mut cfg = wallet_config(U256::ZERO);
        cfg.cache_key = test_cache_key(format!("wallet-owned-substitute-{case}"));
        let group = recovered_outgoing_pending_group(&cfg, list_key);
        seed_recovered_outgoing_pending_group(&store, &cfg, &group);
        store
            .delete_pending_output_poi_context(
                cfg.chain.chain_id,
                cfg.cache_key.as_str(),
                &group[1].output_commitment,
            )
            .expect("retire owned pending context");
        store
            .delete_output_poi_recovery(
                cfg.chain.chain_id,
                cfg.cache_key.as_str(),
                &group[1].output_commitment,
            )
            .expect("retire owned recovery");

        let mut owned = owned_substitute_for_recovered_context(&group[1], list_key);
        match case {
            "missing" => owned.utxo.poi.blinded_commitment = FixedBytes::from([0xfe; 32]),
            "spent" => owned.spent = Some(source(0xfe)),
            "source" => owned.utxo.source.block_number += 1,
            "status" => {
                owned.utxo.poi.statuses.insert(list_key, PoiStatus::Missing);
            }
            "valid" | "stale" => {}
            _ => unreachable!(),
        }
        let mut handle = test_wallet_handle(vec![owned]);
        handle.cache_key = cfg.cache_key.clone();
        let cancel = CancellationToken::new();
        let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);

        let calls = if case == "stale" {
            let submitter = Arc::new(InvalidateOwnedSubstituteAfterSubmitter {
                handle: handle.handle.clone(),
                list_key,
                calls: AtomicU64::new(0),
            });
            let private_poi = WalletPrivatePoiClients::for_submit(
                authority.remote_authority(),
                submitter.clone(),
            );
            assert_eq!(
                process_pending_output_poi_observations_authorized(
                    &authority,
                    &test_public_data_plane_with_poi_service(&store),
                    store.as_ref(),
                    store.as_ref(),
                    &cfg,
                    &[list_key],
                    Some(&private_poi),
                    false,
                )
                .await,
                0,
                "case={case}"
            );
            submitter.calls.load(Ordering::Acquire)
        } else {
            let submitter = Arc::new(RecordingPendingOutputPoiSubmitter::default());
            let private_poi = WalletPrivatePoiClients::for_submit(
                authority.remote_authority(),
                submitter.clone(),
            );
            let submitted = process_pending_output_poi_observations_authorized(
                &authority,
                &test_public_data_plane_with_poi_service(&store),
                store.as_ref(),
                store.as_ref(),
                &cfg,
                &[list_key],
                Some(&private_poi),
                false,
            )
            .await;
            assert_eq!(submitted, usize::from(case == "valid"), "case={case}");
            u64::try_from(submitter.calls().len()).expect("bounded calls")
        };

        assert_eq!(
            calls,
            u64::from(matches!(case, "valid" | "stale")),
            "case={case}"
        );
        let external = store
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &group[0].output_commitment,
            )
            .expect("load external context")
            .expect("external context retained");
        assert_eq!(
            external.submitted_poi_list_keys,
            if case == "valid" {
                vec![list_key]
            } else {
                Vec::new()
            },
            "case={case}"
        );
        assert!(
            store
                .get_pending_output_poi_context(
                    cfg.chain.chain_id,
                    &cfg.cache_key,
                    &group[1].output_commitment,
                )
                .expect("load retired owned context")
                .is_none(),
            "case={case}"
        );
        assert!(
            store
                .get_output_poi_recovery(
                    cfg.chain.chain_id,
                    &cfg.cache_key,
                    &group[1].output_commitment,
                )
                .expect("load retired owned recovery")
                .is_none(),
            "case={case}"
        );

        drop(store);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }
}

#[tokio::test]
async fn recovered_outgoing_group_fails_closed_before_rpc() {
    for case in ["missing", "mismatched", "stale-predecessor"] {
        let root_dir = temp_db_root();
        let store = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let list_key = FixedBytes::from([0xd6; 32]);
        let mut cfg = wallet_config(U256::ZERO);
        cfg.cache_key = test_cache_key(format!("wallet-recovered-outgoing-{case}"));
        let mut group = recovered_outgoing_pending_group(&cfg, list_key);
        if case == "mismatched" {
            group[1].railgun_txid = U256::from(8);
        }
        let seeded = if case == "missing" {
            &group[..1]
        } else {
            group.as_slice()
        };
        seed_recovered_outgoing_pending_group(&store, &cfg, seeded);
        if case == "stale-predecessor" {
            let mut recovery = store
                .get_output_poi_recovery(
                    cfg.chain.chain_id,
                    &cfg.cache_key,
                    &group[1].output_commitment,
                )
                .expect("load recovery")
                .expect("recovery present");
            recovery.source_tx_hash = FixedBytes::from([0xff; 32]);
            store
                .put_output_poi_recovery(&recovery)
                .expect("replace recovery predecessor");
        }
        let mut handle = test_wallet_handle(Vec::new());
        handle.cache_key = cfg.cache_key.clone();
        let cancel = CancellationToken::new();
        let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
        let submitter = Arc::new(RecordingPendingOutputPoiSubmitter::default());
        let private_poi =
            WalletPrivatePoiClients::for_submit(authority.remote_authority(), submitter.clone());

        assert_eq!(
            process_pending_output_poi_observations_authorized(
                &authority,
                &test_public_data_plane_with_poi_service(&store),
                store.as_ref(),
                store.as_ref(),
                &cfg,
                &[list_key],
                Some(&private_poi),
                false,
            )
            .await,
            0,
            "case={case}"
        );
        assert!(submitter.calls().is_empty(), "case={case}");

        drop(store);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }
}

#[tokio::test]
async fn recovered_outgoing_group_final_apply_rechecks_every_predecessor() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let list_key = FixedBytes::from([0xda; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-recovered-outgoing-final-fence");
    let group = recovered_outgoing_pending_group(&cfg, list_key);
    seed_recovered_outgoing_pending_group(&store, &cfg, &group);
    let siblings = group
        .iter()
        .map(|context| {
            let observation = context.observation.as_ref().expect("group observation");
            let identity = pending_output_poi_submit_identity(context, observation)
                .expect("group submit identity");
            let recovery = store
                .get_output_poi_recovery(
                    cfg.chain.chain_id,
                    &cfg.cache_key,
                    &context.output_commitment,
                )
                .expect("load recovery")
                .expect("recovery present");
            RecoveredOutgoingSubmissionSibling {
                subject: PendingOutputPoiSubject::External {
                    output_commitment: context.output_commitment,
                    derived_blinded_commitment: identity.derived_blinded_commitment,
                },
                expected_context_fingerprint: pending_output_poi_context_fingerprint(context)
                    .expect("context fingerprint"),
                plan: super::super::pending_output_poi::PendingOutputPoiSubmissionPlan::force_matching(
                    vec![list_key],
                    super::super::expected_recovery_state(Some(&recovery)).expect("recovery fingerprint"),
                ),
            }
        })
        .collect::<Vec<_>>();
    let mut replacement = group[1].clone();
    replacement.source_operation_id = Some("replacement-after-submit".to_string());
    store
        .put_pending_output_poi_context(&replacement)
        .expect("replace one grouped predecessor");
    let mut handle = test_wallet_handle(Vec::new());
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();

    let outcome = apply_owned_poi_private_delta_on_actor(
        &handle,
        &cancel,
        0,
        &store,
        &store,
        &cfg,
        OwnedPoiPrivateDelta::RecoveredOutgoingSubmission(RecoveredOutgoingSubmissionDelta {
            external_valid_substitutes: Vec::new(),
            expected_corpus: None,
            siblings,
            owned_substitutes: Vec::new(),
            active_list_keys: vec![list_key],
            list_keys: vec![list_key],
            merge_submitted_list_keys: true,
            action: OutputPoiRecoveryAction::Submitted {
                retry_after: Duration::from_secs(30),
            },
            now: 12,
        }),
    )
    .await
    .expect("reject stale grouped final apply");

    assert_eq!(outcome, PoiPrivateApplyOutcome::Skipped);
    for context in &group {
        let current = store
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &context.output_commitment,
            )
            .expect("load unchanged group context")
            .expect("group context present");
        assert_eq!(current.submitted_poi_list_keys, [] as [FixedBytes<32>; 0]);
        assert_eq!(
            store
                .get_output_poi_recovery(
                    cfg.chain.chain_id,
                    &cfg.cache_key,
                    &context.output_commitment,
                )
                .expect("load unchanged group recovery")
                .expect("group recovery present")
                .status,
            OutputPoiRecoveryStatus::Recoverable
        );
    }

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn recovered_outgoing_group_read_error_prevents_rpc() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = RecordingCacheStore::new(Arc::clone(&store));
    let list_key = FixedBytes::from([0xd9; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-recovered-outgoing-read-error");
    let group = recovered_outgoing_pending_group(&cfg, list_key);
    seed_recovered_outgoing_pending_group(store.as_ref(), &cfg, &group);
    cache_store.fail_pending_output_list_call(1);
    let mut handle = test_wallet_handle(Vec::new());
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let submitter = Arc::new(RecordingPendingOutputPoiSubmitter::default());
    let private_poi =
        WalletPrivatePoiClients::for_submit(authority.remote_authority(), submitter.clone());

    assert_eq!(
        process_pending_output_poi_observations_authorized(
            &authority,
            &test_public_data_plane_with_poi_service(&store),
            store.as_ref(),
            &cache_store,
            &cfg,
            &[list_key],
            Some(&private_poi),
            false,
        )
        .await,
        0
    );
    assert_eq!(submitter.calls(), [] as [(FixedBytes<32>, u64, u64); 0]);

    drop(cache_store);
    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn recovered_outgoing_group_persistence_failure_has_no_partial_apply() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let cache_store = RecordingCacheStore::new(Arc::clone(&store));
    let list_key = FixedBytes::from([0xd7; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-recovered-outgoing-persist-failure");
    let group = recovered_outgoing_pending_group(&cfg, list_key);
    seed_recovered_outgoing_pending_group(store.as_ref(), &cfg, &group);
    cache_store.fail_next_commit();
    let mut handle = test_wallet_handle(Vec::new());
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let submitter = Arc::new(RecordingPendingOutputPoiSubmitter::default());
    let private_poi =
        WalletPrivatePoiClients::for_submit(authority.remote_authority(), submitter.clone());

    assert_eq!(
        process_pending_output_poi_observations_authorized(
            &authority,
            &test_public_data_plane_with_poi_service(&store),
            store.as_ref(),
            &cache_store,
            &cfg,
            &[list_key],
            Some(&private_poi),
            false,
        )
        .await,
        0
    );
    assert_eq!(submitter.calls().len(), 1);
    for record in &group {
        assert_eq!(
            store
                .get_pending_output_poi_context(
                    cfg.chain.chain_id,
                    &cfg.cache_key,
                    &record.output_commitment,
                )
                .expect("load unchanged context")
                .expect("context present")
                .submitted_poi_list_keys,
            [] as [FixedBytes<32>; 0]
        );
        assert_eq!(
            store
                .get_output_poi_recovery(
                    cfg.chain.chain_id,
                    &cfg.cache_key,
                    &record.output_commitment,
                )
                .expect("load unchanged recovery")
                .expect("recovery present")
                .status,
            OutputPoiRecoveryStatus::Recoverable
        );
    }

    drop(cache_store);
    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn recovered_outgoing_ambiguous_remote_failure_stays_coherently_retryable() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let list_key = FixedBytes::from([0xd8; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-recovered-outgoing-ambiguous");
    let group = recovered_outgoing_pending_group(&cfg, list_key);
    seed_recovered_outgoing_pending_group(&store, &cfg, &group);
    let mut handle = test_wallet_handle(Vec::new());
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let submitter = Arc::new(RecordingPendingOutputPoiSubmitter::default());
    submitter.fail_next();
    let private_poi =
        WalletPrivatePoiClients::for_submit(authority.remote_authority(), submitter.clone());

    assert_eq!(
        process_pending_output_poi_observations_authorized(
            &authority,
            &test_public_data_plane_with_poi_service(&store),
            store.as_ref(),
            store.as_ref(),
            &cfg,
            &[list_key],
            Some(&private_poi),
            false,
        )
        .await,
        0
    );
    assert_eq!(submitter.calls().len(), 1);
    for record in &group {
        let context = store
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &record.output_commitment,
            )
            .expect("load retryable context")
            .expect("context present");
        assert_eq!(context.submitted_poi_list_keys, [] as [FixedBytes<32>; 0]);
        let recovery = store
            .get_output_poi_recovery(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &record.output_commitment,
            )
            .expect("load retryable recovery")
            .expect("recovery present");
        assert_eq!(recovery.status, OutputPoiRecoveryStatus::SubmitFailed);
        assert!(recovery.next_retry_at.is_some());
        assert_eq!(recovery.attempt_count, 1);
    }

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

fn owned_substitute_for_recovered_context(
    context: &PendingOutputPoiContextRecord,
    list_key: FixedBytes<32>,
) -> WalletUtxo {
    let observation = context.observation.as_ref().expect("group observation");
    let mut output = test_wallet_utxo(0xee);
    output.utxo.tree = u32::try_from(observation.output_tree).expect("test tree");
    output.utxo.position = observation.output_position;
    output.utxo.source = UtxoSource {
        tx_hash: observation.tx_hash,
        block_number: observation.block_number,
        block_timestamp: observation.block_timestamp,
    };
    output.utxo.poi.commitment = context.output_commitment;
    output.utxo.poi.npk = context.output_npk;
    output.utxo.poi.blinded_commitment = UtxoPoiMetadata::blinded_commitment_for(
        context.output_commitment,
        context.output_npk,
        output.utxo.tree,
        output.utxo.position,
    );
    output.utxo.poi.statuses = BTreeMap::from([(list_key, PoiStatus::Valid)]);
    output
}
