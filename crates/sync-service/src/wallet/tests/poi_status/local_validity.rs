use super::*;

#[tokio::test]
async fn observed_local_valid_context_suppresses_submission_after_restart() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let list_key = FixedBytes::from([0x41; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-local-valid-restart");
    let wallet_utxo = test_wallet_utxo(41);
    let pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    store
        .put_pending_output_poi_context(&pending)
        .expect("store observed context");
    let mut handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let reader = local_status_reader_for_lists(
        wallet_utxo.utxo.poi.blinded_commitment,
        &[list_key],
        &[list_key],
    );

    let outcome = crate::wallet::pending_output_poi::reconcile_pending_output_poi_local_statuses(
        &authority,
        &reader,
        store.as_ref(),
        &cfg,
        store.as_ref(),
        &[list_key],
    )
    .await;
    assert_eq!(outcome.completed, 1);
    assert_eq!(outcome.pending, 0);

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
        0
    );
    assert_eq!(submitter.calls(), [] as [(FixedBytes<32>, u64, u64); 0]);
    assert!(
        store
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &pending.output_commitment
            )
            .expect("load completed context")
            .is_none()
    );
    assert_eq!(
        store
            .get_output_poi_recovery(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &pending.output_commitment
            )
            .expect("load completed recovery")
            .expect("owned valid recovery")
            .status,
        OutputPoiRecoveryStatus::Valid
    );
    assert_eq!(
        handle.utxos.read().await[0]
            .utxo
            .poi
            .statuses
            .get(&list_key),
        Some(&PoiStatus::Valid)
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn external_local_valid_context_completes_without_submission() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let list_key = FixedBytes::from([0x42; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-external-local-valid");
    let pending =
        external_pending_output_record(&cfg, 0x42, list_key, PendingOutputPoiRole::Recipient);
    let identity = pending_output_poi_submit_identity(
        &pending,
        pending
            .observation
            .as_ref()
            .expect("observed external context"),
    )
    .expect("external submit identity");
    store
        .put_pending_output_poi_context(&pending)
        .expect("store external context");
    let mut handle = test_wallet_handle(Vec::new());
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let reader = local_status_reader_for_lists(
        identity.derived_blinded_commitment,
        &[list_key],
        &[list_key],
    );

    let outcome = crate::wallet::pending_output_poi::reconcile_pending_output_poi_local_statuses(
        &authority,
        &reader,
        store.as_ref(),
        &cfg,
        store.as_ref(),
        &[list_key],
    )
    .await;
    assert_eq!(outcome.completed, 1);
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
        0
    );
    assert_eq!(submitter.calls(), [] as [(FixedBytes<32>, u64, u64); 0]);
    assert!(
        store
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &pending.output_commitment
            )
            .expect("load completed external context")
            .is_none()
    );
    assert!(
        store
            .get_output_poi_recovery(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &pending.output_commitment
            )
            .expect("load external recovery")
            .is_none()
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn partial_local_validity_submits_only_unresolved_list() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let list_a = FixedBytes::from([0x43; 32]);
    let list_b = FixedBytes::from([0x44; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-partial-local-valid");
    let wallet_utxo = test_wallet_utxo(43);
    let mut pending = matching_pending_output_record(&cfg, &wallet_utxo, list_a);
    pending.required_poi_list_keys.push(list_b);
    pending.pre_transaction_pois_per_txid_leaf_per_list.insert(
        list_b,
        BTreeMap::from([(FixedBytes::from([0x77; 32]), sample_pre_tx_poi(0x77))]),
    );
    store
        .put_pending_output_poi_context(&pending)
        .expect("store partial context");
    let mut handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let reader = local_status_reader_for_lists(
        wallet_utxo.utxo.poi.blinded_commitment,
        &[list_a, list_b],
        &[list_a],
    );

    let outcome = crate::wallet::pending_output_poi::reconcile_pending_output_poi_local_statuses(
        &authority,
        &reader,
        store.as_ref(),
        &cfg,
        store.as_ref(),
        &[list_a, list_b],
    )
    .await;
    assert_eq!(outcome.completed, 0);
    assert_eq!(outcome.pending, 1);
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
            &[list_a, list_b],
            Some(&private_poi),
            false,
        )
        .await,
        1
    );
    assert_eq!(submitter.list_key_calls(), vec![vec![list_b]]);
    assert_eq!(
        handle.utxos.read().await[0].utxo.poi.statuses.get(&list_a),
        Some(&PoiStatus::Valid)
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn local_missing_status_keeps_canonical_submission_eligible() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let list_key = FixedBytes::from([0x45; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-local-missing");
    let wallet_utxo = test_wallet_utxo(45);
    let pending = matching_pending_output_record(&cfg, &wallet_utxo, list_key);
    store
        .put_pending_output_poi_context(&pending)
        .expect("store missing context");
    let mut handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let reader =
        local_status_reader_for_lists(wallet_utxo.utxo.poi.blinded_commitment, &[list_key], &[]);
    let outcome = crate::wallet::pending_output_poi::reconcile_pending_output_poi_local_statuses(
        &authority,
        &reader,
        store.as_ref(),
        &cfg,
        store.as_ref(),
        &[list_key],
    )
    .await;
    assert_eq!(outcome.completed, 0);
    assert_eq!(outcome.pending, 0);

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
        1
    );
    assert_eq!(submitter.list_key_calls(), vec![vec![list_key]]);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

fn local_status_reader_for_lists(
    blinded_commitment: FixedBytes<32>,
    list_keys: &[FixedBytes<32>],
    valid_list_keys: &[FixedBytes<32>],
) -> LocalPoiStatusReader {
    let caches = list_keys
        .iter()
        .copied()
        .map(|list_key| {
            let mut cache = PoiCache::new(PoiCacheIdentity::new(
                EVM_CHAIN_TYPE,
                1,
                DEFAULT_TXID_VERSION,
                list_key,
            ));
            if valid_list_keys.contains(&list_key) {
                cache
                    .apply_poi_leaves(0, &[U256::from_be_bytes(blinded_commitment.0)])
                    .expect("apply local POI leaf");
            }
            (list_key, cache)
        })
        .collect();
    LocalPoiStatusReader::new(WalletLocalPoiCaches::new_for_test(caches))
}
