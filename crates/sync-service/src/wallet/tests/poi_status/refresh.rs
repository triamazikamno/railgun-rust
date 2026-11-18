use super::*;

#[tokio::test]
async fn poi_status_refresh_chunks_unspent_utxos() {
    let client = RecordingPoiStatusClient::default();
    let list_keys = vec![FixedBytes::from([0x11; 32]), FixedBytes::from([0x22; 32])];
    let mut wallet_utxos = (0..=WALLET_POI_STATUS_BATCH_SIZE)
        .map(|position| test_wallet_utxo(position as u64))
        .collect::<Vec<_>>();

    let outcome = refresh_wallet_poi_statuses_selected(
        &client,
        1,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(outcome.changed);
    assert!(outcome.complete);
    let calls = client.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].0, list_keys);
    assert_eq!(calls[0].1.len(), WALLET_POI_STATUS_BATCH_SIZE);
    assert_eq!(calls[1].0, list_keys);
    assert_eq!(calls[1].1.len(), 1);
    assert!(wallet_utxos.iter().all(|wallet_utxo| {
        wallet_utxo.utxo.poi.is_valid_for_lists(&list_keys)
            && wallet_utxo.utxo.poi.refreshed_at.is_some()
    }));
}

#[tokio::test]
async fn remote_poi_status_refresh_uses_gateway_and_actor_intent_apply() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let list_key = FixedBytes::from([0x31; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-remote-status");
    let wallet_utxo = test_wallet_utxo(31);
    let mut handle = test_wallet_handle(vec![wallet_utxo.clone()]);
    handle.cache_key = cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let transport = Arc::new(RecordingPoiStatusClient::default());
    let private_poi =
        WalletPrivatePoiClients::for_status(authority.remote_authority(), transport.clone());

    let changed = refresh_wallet_poi_statuses_remote_authorized(
        &authority,
        &private_poi,
        &store,
        &store,
        &cfg,
        &[list_key],
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(changed);
    assert_eq!(transport.calls().len(), 1);
    let snapshot = handle.current_snapshot().expect("current wallet view");
    let refreshed = snapshot
        .utxos
        .iter()
        .find(|utxo| utxo.utxo.poi.commitment == wallet_utxo.utxo.poi.commitment)
        .expect("refreshed UTXO");
    assert_eq!(
        refreshed.utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn delayed_remote_status_intent_does_not_overwrite_newer_local_status() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let list_key = FixedBytes::from([0x32; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key("wallet-status-cas");
    let wallet_utxo = test_wallet_utxo(32);
    let blinded_commitment = wallet_utxo.utxo.poi.blinded_commitment;
    let expected_poi = wallet_utxo.utxo.poi.clone();
    let mut handle = test_wallet_handle(vec![wallet_utxo]);
    handle.cache_key = cfg.cache_key.clone();
    {
        let mut current = handle.utxos.write().await;
        let _ = current[0].utxo.poi.apply_status_refresh(
            &[list_key],
            Some(&BTreeMap::from([(list_key, PoiStatus::Valid)])),
            200,
        );
    }
    let cancel = CancellationToken::new();
    let outcome = apply_owned_poi_private_delta_on_actor(
        &handle,
        &cancel,
        0,
        &store,
        &store,
        &cfg,
        OwnedPoiPrivateDelta::PoiStatusRefresh(PoiStatusRefreshDelta {
            active_list_keys: vec![list_key],
            expected_poi_by_blinded_commitment: BTreeMap::from([(
                blinded_commitment,
                expected_poi,
            )]),
            statuses_by_blinded_commitment: BTreeMap::from([(
                blinded_commitment,
                BTreeMap::from([(list_key, PoiStatus::Missing)]),
            )]),
            refreshed_at: 100,
        }),
    )
    .await
    .expect("apply delayed remote status intent");

    assert_eq!(outcome, PoiPrivateApplyOutcome::Skipped);
    let current = handle.utxos.read().await;
    assert_eq!(
        current[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );
    assert_eq!(current[0].utxo.poi.refreshed_at, Some(200));

    drop(current);
    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn local_poi_status_refresh_reads_cache_without_remote_pois_per_list() {
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut wallet_utxos = vec![test_wallet_utxo(1), test_wallet_utxo(2)];
    let valid_blinded_commitment = wallet_utxos[0].utxo.poi.blinded_commitment;
    let missing_blinded_commitment = wallet_utxos[1].utxo.poi.blinded_commitment;
    let mut cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        1,
        DEFAULT_TXID_VERSION,
        list_key,
    ));
    cache
        .apply_poi_leaves(0, &[U256::from_be_bytes(valid_blinded_commitment.0)])
        .expect("apply local poi leaf");
    let local_caches = WalletLocalPoiCaches::new_for_test(BTreeMap::from([(list_key, cache)]));
    let local_reader = LocalPoiStatusReader::new(local_caches);
    let unused_remote = RecordingPoiStatusClient::default();

    let outcome = refresh_wallet_poi_statuses_selected(
        &local_reader,
        1,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(outcome.changed);
    assert!(outcome.complete);
    assert_eq!(
        unused_remote.calls(),
        [] as [(Vec<FixedBytes<32>>, Vec<BlindedCommitmentData>); 0]
    );
    assert_eq!(
        wallet_utxos[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );
    assert_eq!(
        wallet_utxos[1].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Missing)
    );
    assert_eq!(
        wallet_utxos[0].utxo.poi.blinded_commitment,
        valid_blinded_commitment
    );
    assert_eq!(
        wallet_utxos[1].utxo.poi.blinded_commitment,
        missing_blinded_commitment
    );
}

#[tokio::test]
async fn poi_status_refresh_needed_after_indexed_delta_discovers_utxo() {
    let client = RecordingPoiStatusClient::default();
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let cfg = wallet_config(U256::ZERO);
    let mut wallet_utxos = Vec::new();
    let delta = WalletLogDelta {
        utxos: vec![test_wallet_utxo(1).utxo],
        nullifiers: Vec::new(),
        commitment_observations: Vec::new(),
        sender_scan_outputs: Vec::new(),
    };

    assert!(apply_wallet_delta_to_vec(&cfg, &mut wallet_utxos, delta));
    assert!(wallet_poi_status_refresh_needed(&wallet_utxos, &list_keys));

    let outcome = refresh_wallet_poi_statuses_selected(
        &client,
        cfg.chain.chain_id,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(outcome.changed);
    assert!(outcome.complete);
    assert!(!wallet_poi_status_refresh_needed(&wallet_utxos, &list_keys));
    assert_eq!(client.calls().len(), 1);
    assert_eq!(
        wallet_utxos[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );
    assert!(wallet_utxos[0].utxo.poi.refreshed_at.is_some());
}

#[test]
fn stale_missing_poi_status_is_refresh_needed_after_ttl() {
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut wallet_utxo = test_wallet_utxo(1);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    wallet_utxo.utxo.poi.refreshed_at = Some(100);
    let wallet_utxos = vec![wallet_utxo];

    assert!(!wallet_poi_status_refresh_needed_for_selection(
        &wallet_utxos,
        &list_keys,
        WalletPoiRefreshSelection::RecoverableStale {
            now: 100 + WALLET_POI_RECOVERABLE_REFRESH_AFTER.as_secs() - 1,
        },
    ));
    assert!(wallet_poi_status_refresh_needed_for_selection(
        &wallet_utxos,
        &list_keys,
        WalletPoiRefreshSelection::RecoverableStale {
            now: 100 + WALLET_POI_RECOVERABLE_REFRESH_AFTER.as_secs(),
        },
    ));
}

#[test]
fn stale_transact_missing_without_pending_context_is_timer_retryable() {
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut wallet_utxo = test_wallet_utxo_with_kind(1, UtxoCommitmentKind::Transact);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    wallet_utxo.utxo.poi.refreshed_at = Some(100);
    let wallet_utxos = vec![wallet_utxo];

    assert!(wallet_poi_status_refresh_needed_for_selection(
        &wallet_utxos,
        &list_keys,
        WalletPoiRefreshSelection::RecoverableStale {
            now: 100 + WALLET_POI_RECOVERABLE_REFRESH_AFTER.as_secs(),
        },
    ));
}

#[test]
fn stale_shield_missing_remains_timer_retryable_without_pending_context() {
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut wallet_utxo = test_wallet_utxo_with_kind(1, UtxoCommitmentKind::Shield);
    wallet_utxo
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    wallet_utxo.utxo.poi.refreshed_at = Some(100);
    let wallet_utxos = vec![wallet_utxo];

    assert!(wallet_poi_status_refresh_needed_for_selection(
        &wallet_utxos,
        &list_keys,
        WalletPoiRefreshSelection::RecoverableStale {
            now: 100 + WALLET_POI_RECOVERABLE_REFRESH_AFTER.as_secs(),
        },
    ));
}

#[test]
fn blocked_shield_revision_rechecks_all_owned_shield_statuses() {
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut blocked = test_wallet_utxo_with_kind(1, UtxoCommitmentKind::Shield);
    blocked
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::ShieldBlocked);
    blocked.utxo.poi.refreshed_at = Some(100);
    let mut valid_shield = test_wallet_utxo_with_kind(2, UtxoCommitmentKind::Shield);
    valid_shield
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Valid);
    valid_shield.utxo.poi.refreshed_at = Some(100);
    let mut valid_transact = test_wallet_utxo_with_kind(3, UtxoCommitmentKind::Transact);
    valid_transact
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Valid);
    valid_transact.utxo.poi.refreshed_at = Some(100);
    let selection = WalletPoiRefreshSelection::CorpusRevision {
        blocked_shields_changed: true,
    };

    assert!(selection.matches_wallet_utxo(&blocked, &list_keys));
    assert!(selection.matches_wallet_utxo(&valid_shield, &list_keys));
    assert!(!selection.matches_wallet_utxo(&valid_transact, &list_keys));
    assert!(
        !WalletPoiRefreshSelection::CorpusRevision {
            blocked_shields_changed: false,
        }
        .matches_wallet_utxo(&blocked, &list_keys)
    );
}

#[tokio::test]
async fn forced_recoverable_poi_refresh_batches_missing_utxos() {
    let client = RecordingPoiStatusClient::default();
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut valid = test_wallet_utxo(0);
    valid.utxo.poi.statuses.insert(list_key, PoiStatus::Valid);
    valid.utxo.poi.refreshed_at = Some(100);
    let mut missing_one = test_wallet_utxo(1);
    missing_one
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    missing_one.utxo.poi.refreshed_at = Some(100);
    let mut missing_two = test_wallet_utxo(2);
    missing_two
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    missing_two.utxo.poi.refreshed_at = Some(100);
    let mut wallet_utxos = vec![valid, missing_one, missing_two];

    let outcome = refresh_wallet_poi_statuses_selected(
        &client,
        1,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::Recoverable,
    )
    .await;

    assert!(outcome.changed);
    assert!(outcome.complete);
    let calls = client.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1.len(), 2);
    assert!(
        wallet_utxos
            .iter()
            .all(|wallet_utxo| wallet_utxo.utxo.poi.is_valid_for_lists(&list_keys))
    );
}

#[tokio::test]
async fn required_or_recoverable_poi_refresh_skips_currently_valid_utxos() {
    let client = RecordingPoiStatusClient::default();
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut valid = test_wallet_utxo(0);
    valid.utxo.poi.statuses.insert(list_key, PoiStatus::Valid);
    valid.utxo.poi.refreshed_at = Some(100);
    let mut valid_without_refresh_time = test_wallet_utxo(1);
    valid_without_refresh_time
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Valid);
    let mut missing = test_wallet_utxo(2);
    missing
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Missing);
    missing.utxo.poi.refreshed_at = Some(100);
    let mut wallet_utxos = vec![valid, valid_without_refresh_time, missing];

    let outcome = refresh_wallet_poi_statuses_selected(
        &client,
        1,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(outcome.changed);
    assert!(outcome.complete);
    let calls = client.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1.len(), 2);
    assert_eq!(wallet_utxos[0].utxo.poi.refreshed_at, Some(100));
    assert!(wallet_utxos[1].utxo.poi.refreshed_at.is_some());
    assert_eq!(
        wallet_utxos[2].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );
}

#[tokio::test]
async fn poi_status_refresh_timestamp_only_update_is_changed() {
    let client = RecordingPoiStatusClient::default();
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut valid_without_refresh_time = test_wallet_utxo(1);
    valid_without_refresh_time
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Valid);
    let mut wallet_utxos = vec![valid_without_refresh_time];

    assert!(wallet_poi_status_refresh_needed(&wallet_utxos, &list_keys));
    let outcome = refresh_wallet_poi_statuses_selected(
        &client,
        1,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(outcome.changed);
    assert!(outcome.complete);
    assert!(!wallet_poi_status_refresh_needed(&wallet_utxos, &list_keys));
    assert_eq!(client.calls().len(), 1);
    assert_eq!(
        wallet_utxos[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Valid)
    );
    assert!(wallet_utxos[0].utxo.poi.refreshed_at.is_some());
}

#[tokio::test]
async fn poi_status_refresh_keeps_failed_chunks_unknown() {
    let client = RecordingPoiStatusClient::default();
    client.fail_call(0);
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut wallet_utxos = (0..=WALLET_POI_STATUS_BATCH_SIZE)
        .map(|position| test_wallet_utxo(position as u64))
        .collect::<Vec<_>>();

    let outcome = refresh_wallet_poi_statuses_selected(
        &client,
        1,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(outcome.changed);
    assert!(!outcome.complete);
    assert_eq!(client.calls().len(), 2);
    assert_eq!(
        wallet_utxos[0].utxo.poi.statuses.get(&list_key),
        Some(&PoiStatus::Unknown)
    );
    assert_eq!(wallet_utxos[0].utxo.poi.refreshed_at, None);
    assert_eq!(
        wallet_utxos[WALLET_POI_STATUS_BATCH_SIZE]
            .utxo
            .poi
            .statuses
            .get(&list_key),
        Some(&PoiStatus::Valid)
    );
    assert!(
        wallet_utxos[WALLET_POI_STATUS_BATCH_SIZE]
            .utxo
            .poi
            .refreshed_at
            .is_some()
    );
}

#[tokio::test]
async fn poi_status_refresh_reports_incomplete_when_failed_read_is_unchanged() {
    let client = RecordingPoiStatusClient::default();
    client.fail_call(0);
    let list_key = FixedBytes::from([0x11; 32]);
    let list_keys = vec![list_key];
    let mut wallet_utxos = vec![test_wallet_utxo(1)];
    wallet_utxos[0]
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::Unknown);

    let outcome = refresh_wallet_poi_statuses_selected(
        &client,
        1,
        &list_keys,
        &mut wallet_utxos,
        WalletPoiRefreshSelection::RequiredOrRecoverable,
    )
    .await;

    assert!(!outcome.changed);
    assert!(!outcome.complete);
    assert_eq!(client.calls().len(), 1);
}
