use super::*;

#[tokio::test]
async fn public_broadcaster_partial_unshield_keeps_candidate_after_scan_and_maintenance() {
    let fixture = partial_unshield_fixture(
        "public-broadcaster-partial-unshield",
        UnshieldFixtureShape::OutputsValid,
    )
    .await;
    let unshield_attempts = SenderUnshieldAttempts::default();
    let report = Box::pin(run_partial_unshield_maintenance(
        &fixture,
        &unshield_attempts,
    ))
    .await;

    let stored = fixture
        .stored_candidate()
        .expect("an unresolved unshield must keep its sender candidate");
    assert_eq!(
        stored.unshield,
        Some(SenderTransactionCandidateUnshield {
            railgun_txids: vec![fixture.railgun_txid],
            outputs_handed_off: true,
        }),
        "valid outputs are handed off and only the unshield TXID remains"
    );
    assert_eq!(report.retired_locally_valid, 0);
    assert!(
        report.retrying >= 1,
        "no prover keeps the unshield retrying"
    );
    assert!(
        fixture
            .db
            .list_pending_output_poi_contexts(fixture.cfg.chain.chain_id, &fixture.cfg.cache_key)
            .expect("list pending contexts")
            .is_empty(),
        "already-valid fee and change outputs need no pending context"
    );
    let current_wallet_utxos = fixture.handle.utxos.read().await;
    assert_eq!(current_wallet_utxos.len(), fixture.wallet_utxos.len());
    for (current, expected) in current_wallet_utxos.iter().zip(&fixture.wallet_utxos) {
        assert_eq!(
            wallet_utxo_stable_identity(current),
            wallet_utxo_stable_identity(expected)
        );
        assert_eq!(current.spent, expected.spent);
    }
    drop(current_wallet_utxos);
    assert!(
        fixture
            .handle
            .observation()
            .ppoi_workflow_status()
            .outstanding_count()
            >= 1,
        "the unshield remains outstanding PPOI work"
    );

    unshield_attempts.expire_all();
    let rerun = Box::pin(run_partial_unshield_maintenance(
        &fixture,
        &unshield_attempts,
    ))
    .await;
    assert_eq!(
        fixture
            .stored_candidate()
            .map(|candidate| candidate.unshield),
        Some(stored.unshield),
        "a rerun keeps the handed-off unshield work"
    );
    assert_eq!(rerun.retired_locally_valid, 0);
    assert!(rerun.retrying >= 1);

    let PartialUnshieldFixture { root_dir, db, .. } = fixture;
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn covered_partial_unshield_records_txid_without_handing_off_outputs() {
    let fixture = partial_unshield_fixture(
        "covered-partial-unshield",
        UnshieldFixtureShape::OutputsCovered,
    )
    .await;
    let unshield_attempts = SenderUnshieldAttempts::default();
    let report = Box::pin(run_partial_unshield_maintenance(
        &fixture,
        &unshield_attempts,
    ))
    .await;

    assert_eq!(report.covered_by_pending_contexts, 2);
    assert_eq!(
        fixture
            .stored_candidate()
            .expect("covered candidate is retained")
            .unshield,
        Some(SenderTransactionCandidateUnshield {
            railgun_txids: vec![fixture.railgun_txid],
            outputs_handed_off: false,
        }),
        "covered outputs keep their fallback while the unshield TXID is recorded"
    );

    let PartialUnshieldFixture { root_dir, db, .. } = fixture;
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

/// Owned change needs no sender proof, so a self-broadcast partial unshield retires without a
/// prover once its unshield reads Valid, leaving the change to the wallet's own PPOI work.
#[tokio::test]
async fn self_broadcast_partial_unshield_retires_without_prover() {
    let fixture = partial_unshield_fixture(
        "self-broadcast-partial-unshield",
        UnshieldFixtureShape::SelfBroadcast,
    )
    .await;
    let change = &fixture.wallet_utxos[1];
    let attempts = SenderUnshieldAttempts::default();
    Box::pin(run_partial_unshield_maintenance(&fixture, &attempts)).await;

    assert_eq!(
        fixture
            .stored_candidate()
            .expect("an unresolved unshield keeps the candidate")
            .unshield,
        Some(SenderTransactionCandidateUnshield {
            railgun_txids: vec![fixture.railgun_txid],
            outputs_handed_off: true,
        }),
        "owned change is handed off and only the unshield TXID remains"
    );
    let current_change = fixture
        .handle
        .utxos
        .read()
        .await
        .iter()
        .find(|utxo| wallet_utxo_stable_identity(utxo) == wallet_utxo_stable_identity(change))
        .cloned()
        .expect("change UTXO");
    assert_ne!(
        current_change.utxo.poi.statuses.get(&fixture.list_key),
        Some(&PoiStatus::Valid),
        "handing off does not mark the change Valid"
    );
    assert!(
        fixture
            .db
            .list_pending_output_poi_contexts(fixture.cfg.chain.chain_id, &fixture.cfg.cache_key)
            .expect("list pending contexts")
            .is_empty()
    );
    assert!(
        fixture
            .db
            .get_output_poi_recovery(
                fixture.cfg.chain.chain_id,
                &fixture.cfg.cache_key,
                &change.utxo.poi.commitment,
            )
            .expect("load change recovery")
            .is_none()
    );

    seed_valid_unshield(&fixture).await;
    Box::pin(run_partial_unshield_maintenance(&fixture, &attempts)).await;
    assert!(fixture.stored_candidate().is_none());
    assert_eq!(fixture.published_workflow().outstanding_count(), 0);
    assert_eq!(
        fixture.submitter.calls(),
        [] as [(FixedBytes<32>, u64, u64); 0]
    );

    let PartialUnshieldFixture { root_dir, db, .. } = fixture;
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn handed_off_unshield_submission_is_paced_and_completes_only_when_valid() {
    let fixture = partial_unshield_fixture(
        "handed-off-unshield-submission",
        UnshieldFixtureShape::OutputsValid,
    )
    .await;
    Box::pin(run_partial_unshield_maintenance(
        &fixture,
        &SenderUnshieldAttempts::default(),
    ))
    .await;
    let handed_off = fixture.stored_candidate().expect("handed-off candidate");
    assert!(
        handed_off
            .unshield
            .as_ref()
            .is_some_and(|unshield| unshield.outputs_handed_off)
    );
    let handed_off = handed_off.encode().expect("encode handed-off candidate");
    let unchanged = || {
        fixture
            .stored_candidate()
            .map(|candidate| candidate.encode().expect("encode stored candidate"))
            .as_deref()
            == Some(handed_off.as_slice())
    };
    let calls = || fixture.submitter.calls().len();
    let proofs: PreTransactionPoiMap = BTreeMap::from([(
        fixture.list_key,
        BTreeMap::from([(
            FixedBytes::from([0xd1; 32]),
            current_poi_fixture("ppoi_3x3").pre_tx_poi,
        )]),
    )]);
    let mut previous = external_pending_output_record(
        &fixture.cfg,
        0xd2,
        fixture.list_key,
        PendingOutputPoiRole::RecoveredOutgoing,
    );
    previous
        .pre_transaction_pois_per_txid_leaf_per_list
        .clone_from(&proofs);
    let previous_proofs =
        previous_key_pending_context(&previous).pre_transaction_pois_per_txid_leaf_per_list;
    let cached = |proofs: &PreTransactionPoiMap| {
        BTreeMap::from([(fixture.railgun_txid, (0_u64, proofs.clone()))])
    };
    let cancel = CancellationToken::new();
    let attempts = SenderUnshieldAttempts::default();

    let rejected = Box::pin(process_stored_sender_unshields(
        &fixture,
        &attempts,
        &cancel,
        cached(&previous_proofs),
    ))
    .await;
    assert_eq!(
        calls(),
        0,
        "previous-key proofs are rejected before transport"
    );
    assert_eq!(rejected.unshield_awaiting_validation, 0);

    // 1. A Missing unshield with a proof is submitted once and keeps its candidate unchanged.
    let submitted = Box::pin(process_stored_sender_unshields(
        &fixture,
        &attempts,
        &cancel,
        cached(&proofs),
    ))
    .await;
    assert_eq!(calls(), 1);
    assert_eq!(submitted.unshield_awaiting_validation, 1);
    assert!(unchanged());

    // 2. Before the submitted interval nothing is resent.
    let waiting = Box::pin(process_stored_sender_unshields(
        &fixture,
        &attempts,
        &cancel,
        BTreeMap::new(),
    ))
    .await;
    assert_eq!(calls(), 1);
    assert_eq!(waiting.unshield_awaiting_validation, 1);

    // A retryable transport failure keeps the candidate and is paced.
    attempts.expire_all();
    fixture.submitter.fail_next();
    let failed = Box::pin(process_stored_sender_unshields(
        &fixture,
        &attempts,
        &cancel,
        cached(&proofs),
    ))
    .await;
    assert_eq!(calls(), 2);
    assert_eq!(
        (failed.retrying, failed.unshield_awaiting_validation),
        (1, 0)
    );
    assert!(unchanged());
    let paced = Box::pin(process_stored_sender_unshields(
        &fixture,
        &attempts,
        &cancel,
        cached(&proofs),
    ))
    .await;
    assert_eq!(
        calls(),
        2,
        "the failed submission waits for its retry interval"
    );
    assert_eq!(paced.retrying, 1);

    // 3. After the interval it is resubmitted; the node's duplicate acknowledgement is success.
    attempts.expire_all();
    let resubmitted = Box::pin(process_stored_sender_unshields(
        &fixture,
        &attempts,
        &cancel,
        cached(&proofs),
    ))
    .await;
    assert_eq!(calls(), 3);
    assert_eq!(
        (
            resubmitted.retrying,
            resubmitted.needs_attention,
            resubmitted.unshield_awaiting_validation,
        ),
        (0, 0, 1)
    );

    // 4. A restart forgets in-memory pacing and resubmits.
    let restarted = Box::pin(process_stored_sender_unshields(
        &fixture,
        &SenderUnshieldAttempts::default(),
        &cancel,
        cached(&proofs),
    ))
    .await;
    assert_eq!(calls(), 4);
    assert_eq!(restarted.unshield_awaiting_validation, 1);

    // 5. A stale job authority transmits nothing.
    let stale = CancellationToken::new();
    stale.cancel();
    let stale_report = Box::pin(process_stored_sender_unshields(
        &fixture,
        &SenderUnshieldAttempts::default(),
        &stale,
        cached(&proofs),
    ))
    .await;
    assert_eq!(calls(), 4);
    assert_eq!(stale_report.unshield_awaiting_validation, 0);
    assert!(unchanged());

    // 6. Only a later local Valid read completes the unshield, with no proof and no prover.
    seed_valid_unshield(&fixture).await;
    let revision = fixture.published_workflow().validation_revision;
    let validated = Box::pin(process_stored_sender_unshields(
        &fixture,
        &attempts,
        &cancel,
        BTreeMap::new(),
    ))
    .await;
    assert_eq!(calls(), 4);
    assert_eq!(validated.unshields_validated, 1);
    assert!(fixture.stored_candidate().is_none());
    let workflow = fixture.published_workflow();
    assert_eq!(workflow.validation_revision, revision + 1);
    assert_eq!(workflow.outstanding_count(), 0);

    let PartialUnshieldFixture { root_dir, db, .. } = fixture;
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn routed_unshield_waits_for_admission_then_sends_over_its_own_route() {
    let mut fixture = partial_unshield_fixture(
        "routed-unshield-submission",
        UnshieldFixtureShape::OutputsValid,
    )
    .await;
    Box::pin(run_partial_unshield_maintenance(
        &fixture,
        &SenderUnshieldAttempts::default(),
    ))
    .await;
    // No spacing and one route, so another transaction's admission defers the unshield.
    let scheduler = PoiSubmissionScheduler::new(
        PoiSubmissionSchedulerConfig {
            min_admission_gap: Duration::ZERO,
            max_admission_gap: Duration::ZERO,
            max_open_routes: 1,
        },
        rand::SeedableRng::seed_from_u64(0),
    );
    let routes = RecordingRoutes::new();
    fixture.routing = Some(routes.routing(Arc::clone(&scheduler)));
    let PoiSubmissionAdmission::Admitted(other) =
        scheduler.try_reserve(fixture.cfg.chain.chain_id, U256::MAX)
    else {
        panic!("an idle scheduler admits");
    };
    let proofs: PreTransactionPoiMap = BTreeMap::from([(
        fixture.list_key,
        BTreeMap::from([(
            FixedBytes::from([0xd1; 32]),
            current_poi_fixture("ppoi_3x3").pre_tx_poi,
        )]),
    )]);
    let cached = || BTreeMap::from([(fixture.railgun_txid, (0_u64, proofs.clone()))]);
    let cancel = CancellationToken::new();
    let attempts = SenderUnshieldAttempts::default();

    let deferred = Box::pin(process_stored_sender_unshields(
        &fixture,
        &attempts,
        &cancel,
        cached(),
    ))
    .await;
    assert_eq!(
        (
            deferred.retrying,
            deferred.needs_attention,
            deferred.unshield_awaiting_validation,
        ),
        (1, 0, 0),
        "a deferred unshield stays outstanding without needing attention"
    );
    assert_eq!(routes.opens(), 0, "a deferral opens no route");

    // The freed route admits it on the next pass, with no pacing delay.
    drop(other);
    let submitted = Box::pin(process_stored_sender_unshields(
        &fixture,
        &attempts,
        &cancel,
        cached(),
    ))
    .await;
    assert_eq!(submitted.unshield_awaiting_validation, 1);
    let routed = routes.routes();
    assert_eq!(routed.len(), 1);
    assert_eq!(routed[0].transact_sends(), vec![(0, fixture.list_key)]);
    assert!(
        fixture.submitter.calls().is_empty(),
        "routed proofs never use the shared client"
    );

    seed_valid_unshield(&fixture).await;
    let validated = Box::pin(process_stored_sender_unshields(
        &fixture,
        &attempts,
        &cancel,
        BTreeMap::new(),
    ))
    .await;
    assert_eq!(validated.unshields_validated, 1);
    assert!(fixture.stored_candidate().is_none());
    assert_eq!(routes.routes().len(), 1, "a Valid unshield is not resent");

    let PartialUnshieldFixture { root_dir, db, .. } = fixture;
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn shield_blocked_refund_retires_spend_only_candidate_without_submission() {
    let fixture = partial_unshield_fixture(
        "shield-blocked-refund",
        UnshieldFixtureShape::UnshieldOnly {
            input_blocked: true,
        },
    )
    .await;
    commit_unshield_only_scan(&fixture).await;
    assert!(fixture.stored_candidate().is_some());

    let report = Box::pin(run_partial_unshield_maintenance(
        &fixture,
        &SenderUnshieldAttempts::default(),
    ))
    .await;

    assert!(
        fixture.stored_candidate().is_none(),
        "no PPOI can be built for a blocked input, so the refund leaves no work"
    );
    assert_eq!(
        fixture.submitter.calls(),
        [] as [(FixedBytes<32>, u64, u64); 0]
    );
    assert_eq!(report.unshields_validated, 0);
    let workflow = fixture.published_workflow();
    assert_eq!(workflow.outstanding_count(), 0);
    assert_eq!(workflow.validation_revision, 0);
    assert!(
        fixture
            .db
            .list_pending_output_poi_contexts(fixture.cfg.chain.chain_id, &fixture.cfg.cache_key)
            .expect("list pending contexts")
            .is_empty()
    );

    let PartialUnshieldFixture { root_dir, db, .. } = fixture;
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

/// State left by a Repair-wallet-cache rewind before the spend: the input is unspent, no
/// candidate exists and the public TXID row is cached. Rescanning recovers the unshield.
#[tokio::test]
async fn rescanned_unshield_only_spend_recreates_candidate_and_completes_unshield() {
    let fixture = partial_unshield_fixture(
        "rescanned-unshield-only",
        UnshieldFixtureShape::UnshieldOnly {
            input_blocked: false,
        },
    )
    .await;
    assert!(fixture.stored_candidate().is_none());

    let discovered = commit_unshield_only_scan(&fixture).await;
    let expected = fixture
        .candidate
        .encode()
        .expect("encode spend-only candidate");
    assert_eq!(
        discovered
            .iter()
            .map(|candidate| candidate.encode().expect("encode discovered candidate"))
            .collect::<Vec<_>>(),
        vec![expected.clone()]
    );
    assert_eq!(
        fixture
            .stored_candidate()
            .map(|candidate| candidate.encode().expect("encode stored candidate")),
        Some(expected)
    );

    let attempts = SenderUnshieldAttempts::default();
    let handed_off = Box::pin(run_partial_unshield_maintenance(&fixture, &attempts)).await;
    assert_eq!(
        fixture
            .stored_candidate()
            .and_then(|candidate| candidate.unshield),
        Some(SenderTransactionCandidateUnshield {
            railgun_txids: vec![fixture.railgun_txid],
            outputs_handed_off: true,
        })
    );
    assert!(
        handed_off.retrying >= 1,
        "no prover keeps the unshield retrying"
    );

    seed_valid_unshield(&fixture).await;
    let revision = fixture.published_workflow().validation_revision;
    let completed = Box::pin(run_partial_unshield_maintenance(&fixture, &attempts)).await;
    assert!(fixture.stored_candidate().is_none());
    assert_eq!(completed.unshields_validated, 1);
    assert_eq!(
        fixture.published_workflow().validation_revision,
        revision + 1
    );
    assert_eq!(
        fixture.submitter.calls(),
        [] as [(FixedBytes<32>, u64, u64); 0]
    );

    let PartialUnshieldFixture { root_dir, db, .. } = fixture;
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

/// A public-broadcaster spend paying a broadcaster fee, wallet change and an unshield, or a full
/// unshield for `UnshieldOnly`, or change and an unshield for `SelfBroadcast`. The unshield
/// (keyed by its Railgun TXID) stays Missing.
async fn partial_unshield_fixture(
    name: &str,
    shape: UnshieldFixtureShape,
) -> PartialUnshieldFixture {
    let unshield_only = matches!(shape, UnshieldFixtureShape::UnshieldOnly { .. });
    let self_broadcast = matches!(shape, UnshieldFixtureShape::SelfBroadcast);
    let root_dir = temp_db_root();
    let db = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let list_key = FixedBytes::from([0xc0; 32]);
    let mut cfg = wallet_config(U256::ZERO);
    cfg.cache_key = test_cache_key(name);
    cfg.scan_keys =
        ViewingKeyData::from_spending_public_key([7; 32], [U256::from(11), U256::from(12)]);
    let broadcaster =
        ViewingKeyData::from_spending_public_key([9; 32], [U256::from(13), U256::from(14)]);
    let spend_source = source(0xc1);
    let token = Address::from([0xc2; 20]);
    let input = test_wallet_utxo(7);
    let input_nullifier = input.utxo.nullifier(cfg.scan_keys.nullifying_key);
    let fee_note = Note::new_change(
        broadcaster.master_public_key,
        token,
        U256::from(1),
        [0xc3; 16],
    );
    let change_note = Note::new_change(
        cfg.scan_keys.master_public_key,
        token,
        U256::from(4),
        [0xc4; 16],
    );
    let unshield_note = Note::new_unshield(Address::from([0xc5; 20]), token, U256::from(5));
    let output_tree = 3_u32;
    let fee_position = 4_u64;
    let change_position = if self_broadcast {
        fee_position
    } else {
        fee_position + 1
    };
    let sender_output = |note: &Note, receiver: &ViewingKeyData, position: u64| SenderScanOutput {
        tree: output_tree,
        position,
        commitment: note.commitment(),
        ciphertext: NoteCiphertext::try_from_note(
            note,
            &cfg.scan_keys.address_data(),
            &receiver.address_data(),
            &cfg.scan_keys.viewing_private_key,
            railgun_wallet::NoteOutputType::Transfer,
        )
        .expect("encrypt sender output")
        .into(),
        source: spend_source.clone(),
    };

    let candidate = if unshield_only {
        // The candidate a scan of the spend must produce; `commit_unshield_only_scan` does that.
        SenderTransactionCandidate::new(
            cfg.chain.chain_id,
            cfg.cache_key.clone(),
            spend_source.clone(),
            vec![SenderTransactionCandidateSpend {
                tree: input.utxo.tree,
                position: input.utxo.position,
                commitment: input.utxo.poi.commitment,
            }],
            Vec::new(),
        )
        .expect("spend-only sender candidate")
    } else {
        // Discovery: the scan sees the wallet spend and the sender-encrypted outputs, but the
        // unshield commitment carries no ciphertext.
        let nullifier_sources =
            HashMap::from([((input.utxo.tree, input_nullifier), spend_source.clone())]);
        let mut sender_outputs = vec![sender_output(&change_note, &cfg.scan_keys, change_position)];
        if !self_broadcast {
            sender_outputs.insert(0, sender_output(&fee_note, &broadcaster, fee_position));
        }
        let mut discovered = sender_scan_candidate_inputs(
            std::slice::from_ref(&input),
            cfg.scan_keys.nullifying_key,
            &nullifier_sources,
            sender_outputs,
            &cfg.scan_keys,
        );
        assert_eq!(
            discovered.len(),
            1,
            "the scan discovers one sender candidate"
        );
        let candidate = discovered
            .remove(0)
            .into_record(cfg.chain.chain_id, cfg.cache_key.clone())
            .expect("sender candidate record");
        assert_eq!(candidate.outputs.len(), if self_broadcast { 1 } else { 2 });
        assert!(candidate.outputs.iter().all(|output| output.note.is_some()));
        db.put_opaque_wallet_private_row(
            &candidate.namespace(),
            WalletPrivateRecordKind::SenderTransactionCandidate,
            &OpaqueWalletPrivateRow {
                row_id: candidate.row_identity(),
                payload: candidate.encode().expect("encode sender candidate"),
            },
        )
        .expect("persist sender candidate");
        candidate
    };

    let mut spent_input = input.clone();
    spent_input.spent = Some(spend_source.clone());
    let change = WalletUtxo::new(Utxo::new(
        change_note.clone(),
        output_tree,
        change_position,
        spend_source.clone(),
        UtxoCommitmentKind::Transact,
    ));
    let change_blinded_commitment = change.utxo.poi.blinded_commitment;
    let fee_blinded_commitment = Utxo::new(
        fee_note.clone(),
        output_tree,
        fee_position,
        spend_source.clone(),
        UtxoCommitmentKind::Transact,
    )
    .poi
    .blinded_commitment;
    let mut wallet_utxos = vec![spent_input];
    let mut commitments = Vec::new();
    if !unshield_only {
        wallet_utxos.push(change);
        if !self_broadcast {
            commitments.push(fee_note.commitment());
        }
        commitments.push(change_note.commitment());
    }
    commitments.push(unshield_note.commitment());

    let txid_transaction = IndexedRailgunTransaction {
        id: "public_broadcaster_partial_unshield".to_string(),
        block_number: U64::from(spend_source.block_number),
        block_timestamp: U64::from(spend_source.block_timestamp),
        transaction_hash: spend_source.tx_hash,
        merkle_root: FixedBytes::from([0x22; 32]),
        nullifiers: vec![input_nullifier],
        commitments,
        bound_params_hash: U256::from(2),
        has_unshield: true,
        unshield_token: None,
        unshield_to_address: None,
        unshield_value: None,
        utxo_tree_in: U64::from(input.utxo.tree),
        utxo_tree_out: U64::from(output_tree),
        utxo_batch_start_position_out: U64::from(fee_position),
    };
    let railgun_txid = txid_transaction.railgun_txid();
    seed_single_txid_artifact(db.as_ref(), &cfg, txid_transaction).await;
    let public_data_plane = test_public_data_plane_with_poi_service(&db);
    let (rows, _) = public_data_plane
        .txid_transactions_for_outer_hash_with_authority(
            &DataPlanePublicTxidCacheKey::new(
                ChainScope {
                    chain_type: ChainType::Evm,
                    chain_id: cfg.chain.chain_id,
                    railgun_contract: cfg.chain.contract,
                },
                DEFAULT_TXID_VERSION,
            ),
            spend_source.tx_hash,
        )
        .expect("load artifact-bounded sender row");
    assert_eq!(rows.len(), 1, "maintenance can see the unshield TXID row");

    let mut cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        cfg.chain.chain_id,
        DEFAULT_TXID_VERSION,
        list_key,
    ));
    let valid_blinded_commitments = match shape {
        UnshieldFixtureShape::OutputsValid => {
            vec![fee_blinded_commitment, change_blinded_commitment]
        }
        // Keep the corpus ready without making anything Valid.
        UnshieldFixtureShape::UnshieldOnly { .. } | UnshieldFixtureShape::SelfBroadcast => {
            vec![FixedBytes::from([0xc9; 32])]
        }
        UnshieldFixtureShape::OutputsCovered => {
            let proofs: PreTransactionPoiMap = BTreeMap::from([(
                list_key,
                BTreeMap::from([(
                    FixedBytes::from([0xc6; 32]),
                    current_poi_fixture("ppoi_3x3").pre_tx_poi,
                )]),
            )]);
            for (byte, output) in [(0xc7, &candidate.outputs[0]), (0xc8, &candidate.outputs[1])] {
                let mut pending = external_pending_output_record(
                    &cfg,
                    byte,
                    list_key,
                    PendingOutputPoiRole::RecoveredOutgoing,
                );
                pending.output_commitment = output.commitment;
                pending.output_npk = FixedBytes::from(
                    output
                        .note
                        .as_ref()
                        .expect("sender note")
                        .npk
                        .to_be_bytes::<32>(),
                );
                pending.observation = Some(local_db::PendingOutputPoiObservation {
                    output_tree: u64::from(output.tree),
                    output_position: output.position,
                    tx_hash: spend_source.tx_hash,
                    block_number: spend_source.block_number,
                    block_timestamp: spend_source.block_timestamp,
                });
                pending
                    .pre_transaction_pois_per_txid_leaf_per_list
                    .clone_from(&proofs);
                db.put_pending_output_poi_context(&pending)
                    .expect("store compatible pending context");
            }
            // Keep the corpus ready without making the fee or change Valid.
            vec![FixedBytes::from([0xc9; 32])]
        }
    };
    cache
        .apply_verified_artifact_events(
            &valid_blinded_commitments
                .iter()
                .zip(0_u64..)
                .map(
                    |(blinded_commitment, event_index)| poi::artifacts::SnapshotEvent {
                        event_index,
                        blinded_commitment: blinded_commitment.0,
                        signature: [0_u8; 64],
                        event_type: PoiEventType::Transact,
                    },
                )
                .collect::<Vec<_>>(),
        )
        .expect("seed local PPOI statuses");
    if matches!(
        shape,
        UnshieldFixtureShape::UnshieldOnly {
            input_blocked: true
        }
    ) {
        cache
            .apply_blocked_shields(&[poi::poi::BlockedShield {
                commitment_hash: hex::encode_prefixed(input.utxo.poi.commitment),
                blinded_commitment: hex::encode_prefixed(input.utxo.poi.blinded_commitment),
                block_reason: None,
                signature: hex::encode_prefixed([0_u8; 64]),
            }])
            .expect("seed blocked input shield");
    }
    cache.accept_current_roots();
    seed_data_plane_poi_cache(&public_data_plane, cfg.chain.chain_id, list_key, cache).await;

    let mut handle = test_wallet_handle(if unshield_only {
        vec![input]
    } else {
        wallet_utxos.clone()
    });
    handle.cache_key = cfg.cache_key.clone();
    PartialUnshieldFixture {
        root_dir,
        db,
        cfg,
        list_key,
        candidate,
        railgun_txid: FixedBytes::from(railgun_txid.to_be_bytes::<32>()),
        wallet_utxos,
        handle,
        public_data_plane,
        submitter: Arc::new(RecordingPendingOutputPoiSubmitter::default()),
        routing: None,
    }
}

/// Scan the fixture's unshield-only spend as scan commit does: apply its nullifier-only delta,
/// then persist the spent mark with the discovered sender candidates.
async fn commit_unshield_only_scan(
    fixture: &PartialUnshieldFixture,
) -> Vec<SenderTransactionCandidate> {
    let input = &fixture.wallet_utxos[0].utxo;
    let mut scanned = fixture.handle.utxos.read().await.clone();
    let outcome = apply_wallet_delta_to_vec_with_outcome(
        &fixture.cfg,
        &mut scanned,
        WalletLogDelta {
            utxos: Vec::new(),
            nullifiers: vec![SpentNullifier {
                tree: input.tree,
                nullifier: input.nullifier(fixture.cfg.scan_keys.nullifying_key),
                source: fixture.candidate.source.clone(),
            }],
            commitment_observations: Vec::new(),
            sender_scan_outputs: Vec::new(),
        },
    );
    let changed = outcome.changed;
    let candidates = outcome
        .sender_scan_candidates
        .into_iter()
        .map(|candidate| {
            candidate
                .into_record(fixture.cfg.chain.chain_id, fixture.cfg.cache_key.clone())
                .expect("sender candidate record")
        })
        .collect::<Vec<_>>();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&fixture.handle, 0, &cancel);
    let permit = authority.acquire().await.expect("wallet authority");
    WalletPersistState::default()
        .persist_progress_with_private_effects(
            fixture.db.as_ref(),
            &permit,
            WalletProgressPersist {
                cache_key: fixture.cfg.cache_key.as_str(),
                snapshot: &scanned,
                last_scanned: fixture.candidate.source.block_number,
                checkpoint: WalletCheckpointMutation::Set {
                    last_scanned_block: fixture.candidate.source.block_number,
                    last_scanned_block_hash: None,
                },
                changed,
            },
            WalletProgressPrivateEffects {
                sender_transaction_candidate_updates: &candidates,
                ..WalletProgressPrivateEffects::default()
            },
        )
        .expect("persist scanned spend");
    drop(permit);
    *fixture.handle.utxos.write().await = scanned;
    candidates
}

/// Mark the fixture's unshield TXID Valid in its local PPOI list, as a corpus sync would.
async fn seed_valid_unshield(fixture: &PartialUnshieldFixture) {
    let corpus = fixture
        .public_data_plane
        .ensure_poi_corpus(PublicPoiCorpusKey::wallet_default(
            fixture.cfg.chain.chain_id,
        ))
        .await
        .expect("POI corpus");
    let local_caches = corpus.local_caches();
    let mut caches = local_caches.write().await;
    let cache = caches
        .get_mut(&fixture.list_key)
        .expect("seeded PPOI list cache");
    let event_index = cache.progress().next_event_index;
    cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index,
            blinded_commitment: fixture.railgun_txid.0,
            signature: [0_u8; 64],
            event_type: PoiEventType::Unshield,
        }])
        .expect("seed Valid unshield");
    cache.accept_current_roots();
}

/// Run one maintenance pass with private commits re-entering a test actor loop.
async fn run_partial_unshield_maintenance(
    fixture: &PartialUnshieldFixture,
    unshield_attempts: &SenderUnshieldAttempts,
) -> crate::wallet::SenderCandidateRecoveryReport {
    let cancel = CancellationToken::new();
    let private_poi = WalletPrivatePoiClients::for_test(
        WalletPrivateMutationAuthority::new(&fixture.handle, 0, &cancel).remote_authority(),
        Arc::new(RecordingPoiStatusClient::default()),
        fixture.submitter.clone(),
    )
    .with_submission_routing(
        fixture.routing.clone(),
        DeferredForcedSubmissions::default(),
    );
    let poi_runtime = test_artifact_poi_runtime();
    let forest = Arc::new(RwLock::new(MerkleForest::new()));
    let active_list_keys = [fixture.list_key];
    let (apply_tx, mut apply_rx) = mpsc::channel(1);
    let apply_client = WalletPrivateApplyClient::new(apply_tx);
    let authority = WalletPrivateMutationAuthority::new(&fixture.handle, 0, &cancel)
        .with_apply_client(&apply_client);
    let actor = fixture.apply_private_commits(&mut apply_rx, &cancel);
    let maintenance = (OutputPoiRecoveryRun {
        authority: &authority,
        db: fixture.db.as_ref(),
        cache_store: fixture.db.as_ref(),
        cfg: &fixture.cfg,
        public_data_plane: &fixture.public_data_plane,
        http_client: None,
        indexed_artifact_source: None,
        poi_runtime: &poi_runtime,
        forest: &forest,
        utxos: &fixture.handle.utxos,
        client: poi_runtime.public_client(),
        private_poi: &private_poi,
        active_list_keys: &active_list_keys,
        force_retry: false,
        unshield_attempts,
    })
    .recover_missing();
    // The apply client outlives maintenance, so the actor loop only ends when maintenance does.
    tokio::select! {
        recovered = maintenance => recovered.candidate_report,
        () = actor => unreachable!("the apply channel stays open during maintenance"),
    }
}

/// Run the unshield step for the stored candidate with `cached_proofs`, with private commits
/// re-entering a test actor loop. `cancel` stands for the job authority's lifecycle.
async fn process_stored_sender_unshields(
    fixture: &PartialUnshieldFixture,
    attempts: &SenderUnshieldAttempts,
    cancel: &CancellationToken,
    cached_proofs: BTreeMap<FixedBytes<32>, (u64, PreTransactionPoiMap)>,
) -> crate::wallet::SenderCandidateRecoveryReport {
    let candidate = fixture.stored_candidate().expect("stored sender candidate");
    let private_poi = WalletPrivatePoiClients::for_test(
        WalletPrivateMutationAuthority::new(&fixture.handle, 0, cancel).remote_authority(),
        Arc::new(RecordingPoiStatusClient::default()),
        fixture.submitter.clone(),
    )
    .with_submission_routing(
        fixture.routing.clone(),
        DeferredForcedSubmissions::default(),
    );
    let poi_runtime = test_artifact_poi_runtime();
    let active_list_keys = [fixture.list_key];
    let (apply_tx, mut apply_rx) = mpsc::channel(1);
    let apply_client = WalletPrivateApplyClient::new(apply_tx);
    let authority = WalletPrivateMutationAuthority::new(&fixture.handle, 0, cancel)
        .with_apply_client(&apply_client);
    let request = OutputPoiRecoveryRequest {
        authority: &authority,
        db: fixture.db.as_ref(),
        cache_store: fixture.db.as_ref(),
        cfg: &fixture.cfg,
        public_data_plane: &fixture.public_data_plane,
        http_client: None,
        indexed_artifact_source: None,
        forest: Arc::new(MerkleForest::new()),
        poi_client: poi_runtime.public_client(),
        private_poi: &private_poi,
        poi_runtime: &poi_runtime,
        active_list_keys: &active_list_keys,
        wallet_utxos: &fixture.wallet_utxos,
        force_retry: false,
    };
    let data_key = DataPlanePublicTxidCacheKey::new(
        ChainScope {
            chain_type: ChainType::Evm,
            chain_id: fixture.cfg.chain.chain_id,
            railgun_contract: fixture.cfg.chain.contract,
        },
        DEFAULT_TXID_VERSION,
    );
    let (rows, row_authority) = fixture
        .public_data_plane
        .txid_transactions_for_outer_hash_with_authority(&data_key, candidate.source.tx_hash)
        .expect("load unshield TXID row");
    let public_data_fence = SenderCandidatePublicDataFence::new(
        &fixture.public_data_plane,
        data_key,
        fixture.public_data_plane.current_epoch(),
        rows,
        row_authority,
    );
    let wallet_nullifiers =
        WalletNullifierIndex::new(&fixture.wallet_utxos, &fixture.cfg.scan_keys);
    let work = async {
        let proof_source_resolution = request.resolve_proof_source(&active_list_keys).await;
        let eligible = BTreeSet::from([fixture.railgun_txid]);
        let valid =
            sender_unshield_valid_txids(&request, &proof_source_resolution, &eligible).await;
        let mut report = crate::wallet::SenderCandidateRecoveryReport::default();
        Box::pin(process_sender_candidate_unshields(
            &request,
            &mut report,
            attempts,
            &mut BTreeSet::new(),
            SenderUnshieldInputs {
                candidate,
                eligible,
                valid,
                qualified: &[],
                wallet_nullifiers: &wallet_nullifiers,
                public_data_fence: &public_data_fence,
                proof_source_resolution: &proof_source_resolution,
                cached_proofs,
            },
        ))
        .await;
        report
    };
    let actor = fixture.apply_private_commits(&mut apply_rx, cancel);
    // The apply client outlives the unshield work, so the actor loop only ends when it does.
    tokio::select! {
        report = work => report,
        () = actor => unreachable!("the apply channel stays open during unshield work"),
    }
}
