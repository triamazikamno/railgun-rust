use super::*;

#[tokio::test]
async fn sender_materialization_atomically_installs_standard_records_without_balance_mutation() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let mut cfg = wallet_config(U256::from(42));
    cfg.cache_key = test_cache_key("sender-materialization");
    let list_key = FixedBytes::from([0xa1; 32]);
    let candidate_source = source(0xa2);
    let mut input = test_wallet_utxo(7);
    input.spent = Some(candidate_source.clone());
    let fixture = current_poi_fixture("ppoi_3x3");
    let output_note = fixture_output_note(&fixture, 0);
    let global: u128 = fixture.public_context.output_start_global.to();
    let output = Utxo::new(
        output_note.clone(),
        u32::try_from(global / u128::from(TREE_LEAF_COUNT)).expect("output tree"),
        u64::try_from(global % u128::from(TREE_LEAF_COUNT)).expect("output position"),
        candidate_source.clone(),
        UtxoCommitmentKind::Transact,
    );
    let candidate = SenderTransactionCandidate::new(
        cfg.chain.chain_id,
        cfg.cache_key.clone(),
        candidate_source.clone(),
        vec![SenderTransactionCandidateSpend {
            tree: input.utxo.tree,
            position: input.utxo.position,
            commitment: input.utxo.poi.commitment,
        }],
        vec![SenderTransactionCandidateOutput {
            tree: output.tree,
            position: output.position,
            commitment: output.poi.commitment,
            note: Some(output_note),
        }],
    )
    .expect("candidate");
    store
        .put_opaque_wallet_private_row(
            &candidate.namespace(),
            WalletPrivateRecordKind::SenderTransactionCandidate,
            &OpaqueWalletPrivateRow {
                row_id: candidate.row_identity(),
                payload: candidate.encode().expect("encode candidate"),
            },
        )
        .expect("store candidate");

    let mut pending = external_pending_output_record(
        &cfg,
        0xa4,
        list_key,
        PendingOutputPoiRole::RecoveredOutgoing,
    );
    pending.txid_merkleroot_index = Some(77);
    pending.source_operation_id = Some("test-recovered-sender-inner-7".to_string());
    pending.output_commitment = output.poi.commitment;
    pending.output_npk = output.poi.npk;
    pending.observation = Some(local_db::PendingOutputPoiObservation {
        output_tree: u64::from(output.tree),
        output_position: output.position,
        tx_hash: candidate_source.tx_hash,
        block_number: candidate_source.block_number,
        block_timestamp: candidate_source.block_timestamp,
    });
    let mut recovery = output_poi_recovery_record(
        cfg.chain.chain_id,
        &cfg.cache_key,
        output.poi.commitment,
        OutputPoiRecoveryStatus::Recoverable,
        None,
    );
    recovery.source_tx_hash = candidate_source.tx_hash;

    let (public_data_plane, public_data_fence) = sender_candidate_public_data_fence(
        &store,
        &cfg,
        &candidate,
        &input,
        output.poi.commitment,
        candidate.source.block_timestamp,
    )
    .await;

    let mut handle = test_wallet_handle(vec![input.clone()]);
    handle.cache_key = cfg.cache_key.clone();
    let before = wallet_utxo_stable_identity(&input);
    let cancel = CancellationToken::new();
    let delta = || {
        OwnedPoiPrivateDelta::SenderCandidateMaterialization(SenderCandidateMaterializationDelta {
            expected_candidate: candidate.clone(),
            public_data_fence: public_data_fence.clone(),
            active_list_keys: vec![list_key],
            pending_updates: vec![pending.clone()],
            recovery_updates: vec![recovery.clone()],
            owned_substitutes: Vec::new(),
            proof_outputs: sender_materialization_proof_outputs(std::slice::from_ref(&pending)),
            replacement_group: Vec::new(),
            external_valid_substitutes: Vec::new(),
            expected_corpus: current_poi_corpus_revision(),
            unshield: None,
        })
    };

    assert!(
        apply_owned_poi_private_delta_on_actor(
            &handle,
            &cancel,
            1,
            store.as_ref(),
            store.as_ref(),
            &cfg,
            delta(),
        )
        .await
        .is_err(),
        "reset-generation stale work must not enter private apply"
    );
    let mut retired_handle = test_wallet_handle(vec![input.clone()]);
    retired_handle.cache_key = cfg.cache_key.clone();
    retired_handle.retire_actor();
    assert!(
        apply_owned_poi_private_delta_on_actor(
            &retired_handle,
            &cancel,
            0,
            store.as_ref(),
            store.as_ref(),
            &cfg,
            delta(),
        )
        .await
        .is_err(),
        "replaced actor work must not enter private apply"
    );
    handle.utxos.write().await[0].spent = None;
    assert_eq!(
        apply_owned_poi_private_delta_on_actor(
            &handle,
            &cancel,
            0,
            store.as_ref(),
            store.as_ref(),
            &cfg,
            delta(),
        )
        .await
        .expect("reject changed spent input"),
        PoiPrivateApplyOutcome::Skipped
    );
    handle.utxos.write().await[0].spent = input.spent.clone();

    let mut replacement_source = candidate.source.clone();
    replacement_source.block_timestamp += 1;
    let replacement =
        sender_candidate_for_spent_input(cfg.cache_key.clone(), &input, replacement_source);
    store
        .put_opaque_wallet_private_row(
            &replacement.namespace(),
            WalletPrivateRecordKind::SenderTransactionCandidate,
            &OpaqueWalletPrivateRow {
                row_id: replacement.row_identity(),
                payload: replacement.encode().expect("encode replacement candidate"),
            },
        )
        .expect("replace sender candidate");
    assert_eq!(
        apply_owned_poi_private_delta_on_actor(
            &handle,
            &cancel,
            0,
            store.as_ref(),
            store.as_ref(),
            &cfg,
            delta(),
        )
        .await
        .expect("reject replaced candidate"),
        PoiPrivateApplyOutcome::Skipped
    );
    store
        .put_opaque_wallet_private_row(
            &candidate.namespace(),
            WalletPrivateRecordKind::SenderTransactionCandidate,
            &OpaqueWalletPrivateRow {
                row_id: candidate.row_identity(),
                payload: candidate.encode().expect("restore candidate"),
            },
        )
        .expect("restore sender candidate");

    public_data_plane
        .reset_public_cache()
        .await
        .expect("advance public epoch");
    assert_eq!(
        apply_owned_poi_private_delta_on_actor(
            &handle,
            &cancel,
            0,
            store.as_ref(),
            store.as_ref(),
            &cfg,
            delta(),
        )
        .await
        .expect("reject stale public epoch"),
        PoiPrivateApplyOutcome::Skipped
    );

    let (current_public_data_plane, current_public_data_fence) =
        sender_candidate_public_data_fence(
            &store,
            &cfg,
            &candidate,
            &input,
            output.poi.commitment,
            candidate.source.block_timestamp,
        )
        .await;
    let row_reset_plane =
        ChainPublicDataPlane::new(Arc::clone(&store), Arc::new(AtomicU64::new(0)));
    row_reset_plane
        .reset_public_cache()
        .await
        .expect("replace persisted public rows without changing captured epoch");
    let (_replacement_plane, _) = sender_candidate_public_data_fence(
        &store,
        &cfg,
        &candidate,
        &input,
        output.poi.commitment,
        candidate.source.block_timestamp + 1,
    )
    .await;
    let row_delta = || {
        OwnedPoiPrivateDelta::SenderCandidateMaterialization(SenderCandidateMaterializationDelta {
            expected_candidate: candidate.clone(),
            public_data_fence: current_public_data_fence.clone(),
            active_list_keys: vec![list_key],
            pending_updates: vec![pending.clone()],
            recovery_updates: vec![recovery.clone()],
            owned_substitutes: Vec::new(),
            proof_outputs: sender_materialization_proof_outputs(std::slice::from_ref(&pending)),
            replacement_group: Vec::new(),
            external_valid_substitutes: Vec::new(),
            expected_corpus: current_poi_corpus_revision(),
            unshield: None,
        })
    };
    assert_eq!(current_public_data_plane.current_epoch().value, 0);
    assert_eq!(
        apply_owned_poi_private_delta_on_actor(
            &handle,
            &cancel,
            0,
            store.as_ref(),
            store.as_ref(),
            &cfg,
            row_delta(),
        )
        .await
        .expect("reject replaced public TXID row"),
        PoiPrivateApplyOutcome::Skipped
    );

    let (_final_public_data_plane, final_public_data_fence) = sender_candidate_public_data_fence(
        &store,
        &cfg,
        &candidate,
        &input,
        output.poi.commitment,
        candidate.source.block_timestamp + 1,
    )
    .await;
    let final_delta = |expected_corpus: ExpectedPoiCorpusRevision| {
        OwnedPoiPrivateDelta::SenderCandidateMaterialization(SenderCandidateMaterializationDelta {
            expected_candidate: candidate.clone(),
            public_data_fence: final_public_data_fence.clone(),
            active_list_keys: vec![list_key],
            pending_updates: vec![pending.clone()],
            recovery_updates: vec![recovery.clone()],
            owned_substitutes: Vec::new(),
            proof_outputs: sender_materialization_proof_outputs(std::slice::from_ref(&pending)),
            replacement_group: Vec::new(),
            external_valid_substitutes: Vec::new(),
            expected_corpus,
            unshield: None,
        })
    };
    let corpus_caches = WalletLocalPoiCaches::new();
    let corpus = PublicPoiCorpusHandle::new_for_test(corpus_caches.clone());
    let proof_revision = ExpectedPoiCorpusRevision {
        corpus: corpus.clone(),
        revision: *corpus.committed_revision_rx().borrow(),
    };
    {
        let _write_fence = corpus_caches.revision_write_fence().await;
        corpus_caches.publish_committed_revision(false);
    }
    assert_eq!(
        apply_owned_poi_private_delta_on_actor(
            &handle,
            &cancel,
            0,
            store.as_ref(),
            store.as_ref(),
            &cfg,
            final_delta(proof_revision),
        )
        .await
        .expect("reject proofs from an older corpus revision"),
        PoiPrivateApplyOutcome::SkippedStaleCorpusRevision
    );
    assert!(
        store
            .get_sender_transaction_candidate(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &candidate.semantic_id(),
            )
            .expect("load candidate after stale proof")
            .is_some()
    );
    assert!(
        store
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &output.poi.commitment,
            )
            .expect("load pending sibling after stale proof")
            .is_none()
    );
    assert!(
        store
            .get_output_poi_recovery(cfg.chain.chain_id, &cfg.cache_key, &output.poi.commitment)
            .expect("load recovery sibling after stale proof")
            .is_none()
    );
    {
        let unchanged = handle.utxos.read().await;
        assert_eq!(unchanged.len(), 1);
        assert_eq!(wallet_utxo_stable_identity(&unchanged[0]), before);
        assert_eq!(unchanged[0].spent, input.spent);
    }

    let current_revision = ExpectedPoiCorpusRevision {
        corpus: corpus.clone(),
        revision: *corpus.committed_revision_rx().borrow(),
    };
    let outcome = apply_owned_poi_private_delta_on_actor(
        &handle,
        &cancel,
        0,
        store.as_ref(),
        store.as_ref(),
        &cfg,
        final_delta(current_revision.clone()),
    )
    .await
    .expect("materialize candidate");
    assert_eq!(
        outcome,
        PoiPrivateApplyOutcome::Applied {
            utxo_changed: false
        }
    );
    assert!(
        store
            .get_sender_transaction_candidate(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &candidate.semantic_id(),
            )
            .expect("load consumed candidate")
            .is_none()
    );
    assert!(
        store
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &output.poi.commitment,
            )
            .expect("load pending sibling")
            .is_some()
    );
    assert!(
        store
            .get_output_poi_recovery(cfg.chain.chain_id, &cfg.cache_key, &output.poi.commitment,)
            .expect("load recovery sibling")
            .is_some()
    );
    let after = handle.utxos.read().await;
    assert_eq!(after.len(), 1);
    assert_eq!(wallet_utxo_stable_identity(&after[0]), before);
    assert_eq!(after[0].spent, input.spent);
    drop(after);

    assert_eq!(
        apply_owned_poi_private_delta_on_actor(
            &handle,
            &cancel,
            0,
            store.as_ref(),
            store.as_ref(),
            &cfg,
            final_delta(current_revision),
        )
        .await
        .expect("restart-style retry"),
        PoiPrivateApplyOutcome::Skipped
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn sender_materialization_consumes_exact_covered_and_mixed_candidates_without_overwrite() {
    for covered_count in [1_usize, 2] {
        let root_dir = temp_db_root();
        let store = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let fixture = sender_materialization_test_fixture(
            &store,
            &format!("sender-materialization-covered-{covered_count}"),
            2,
        )
        .await;
        for index in 0..covered_count {
            let mut context = fixture.pending[index].clone();
            context.submitted_poi_list_keys = context.required_poi_list_keys.clone();
            context.terminal_error = Some("preserved progress".to_string());
            let mut recovery = fixture.recoveries[index].clone();
            recovery.status = OutputPoiRecoveryStatus::Submitted;
            recovery.attempt_count = 4;
            recovery.last_error = Some("preserved recovery progress".to_string());
            store
                .put_pending_output_poi_context(&context)
                .expect("seed exact covered context");
            store
                .put_output_poi_recovery(&recovery)
                .expect("seed exact covered recovery");
        }
        let covered_before = (0..covered_count)
            .map(|index| {
                (
                    rmp_serde::to_vec(
                        &store
                            .get_pending_output_poi_context(
                                fixture.cfg.chain.chain_id,
                                &fixture.cfg.cache_key,
                                &fixture.pending[index].output_commitment,
                            )
                            .expect("load covered context")
                            .expect("covered context present"),
                    )
                    .expect("encode covered context"),
                    rmp_serde::to_vec(
                        &store
                            .get_output_poi_recovery(
                                fixture.cfg.chain.chain_id,
                                &fixture.cfg.cache_key,
                                &fixture.pending[index].output_commitment,
                            )
                            .expect("load covered recovery")
                            .expect("covered recovery present"),
                    )
                    .expect("encode covered recovery"),
                )
            })
            .collect::<Vec<_>>();
        let mut handle = test_wallet_handle(vec![fixture.input.clone()]);
        handle.cache_key = fixture.cfg.cache_key.clone();
        let cancel = CancellationToken::new();
        // With unshield work left, the candidate is kept holding exactly the handed-off TXIDs.
        let kept_unshield = (covered_count == 2).then(|| SenderTransactionCandidateUnshield {
            railgun_txids: vec![FixedBytes::from([0x01; 32]), FixedBytes::from([0x02; 32])],
            outputs_handed_off: true,
        });

        assert_eq!(
            apply_owned_poi_private_delta_on_actor(
                &handle,
                &cancel,
                0,
                store.as_ref(),
                store.as_ref(),
                &fixture.cfg,
                OwnedPoiPrivateDelta::SenderCandidateMaterialization(
                    SenderCandidateMaterializationDelta {
                        expected_candidate: fixture.candidate.clone(),
                        public_data_fence: fixture.fence.clone(),
                        active_list_keys: fixture.pending[0].required_poi_list_keys.clone(),
                        pending_updates: fixture.pending.clone(),
                        recovery_updates: fixture.recoveries.clone(),
                        owned_substitutes: Vec::new(),
                        proof_outputs: sender_materialization_proof_outputs(&fixture.pending),
                        replacement_group: Vec::new(),
                        external_valid_substitutes: Vec::new(),
                        expected_corpus: current_poi_corpus_revision(),
                        unshield: kept_unshield.clone(),
                    }
                ),
            )
            .await
            .expect("consume covered candidate"),
            PoiPrivateApplyOutcome::Applied {
                utxo_changed: false
            },
            "covered_count={covered_count}"
        );
        assert_eq!(
            store
                .get_sender_transaction_candidate(
                    fixture.cfg.chain.chain_id,
                    &fixture.cfg.cache_key,
                    &fixture.candidate.semantic_id(),
                )
                .expect("load consumed candidate")
                .map(|candidate| candidate.unshield),
            kept_unshield.map(Some),
            "covered_count={covered_count}"
        );
        assert_eq!(
            apply_owned_poi_private_delta_on_actor(
                &handle,
                &cancel,
                0,
                store.as_ref(),
                store.as_ref(),
                &fixture.cfg,
                OwnedPoiPrivateDelta::SenderCandidateMaterialization(
                    SenderCandidateMaterializationDelta {
                        expected_candidate: fixture.candidate.clone(),
                        public_data_fence: fixture.fence.clone(),
                        active_list_keys: fixture.pending[0].required_poi_list_keys.clone(),
                        pending_updates: fixture.pending.clone(),
                        recovery_updates: fixture.recoveries.clone(),
                        owned_substitutes: Vec::new(),
                        proof_outputs: sender_materialization_proof_outputs(&fixture.pending),
                        replacement_group: Vec::new(),
                        external_valid_substitutes: Vec::new(),
                        expected_corpus: current_poi_corpus_revision(),
                        unshield: None,
                    }
                ),
            )
            .await
            .expect("replay consumed candidate"),
            PoiPrivateApplyOutcome::Skipped
        );
        for (index, before) in covered_before.iter().enumerate() {
            assert_eq!(
                rmp_serde::to_vec(
                    &store
                        .get_pending_output_poi_context(
                            fixture.cfg.chain.chain_id,
                            &fixture.cfg.cache_key,
                            &fixture.pending[index].output_commitment,
                        )
                        .expect("reload covered context")
                        .expect("covered context retained"),
                )
                .expect("encode retained context"),
                before.0
            );
            assert_eq!(
                rmp_serde::to_vec(
                    &store
                        .get_output_poi_recovery(
                            fixture.cfg.chain.chain_id,
                            &fixture.cfg.cache_key,
                            &fixture.pending[index].output_commitment,
                        )
                        .expect("reload covered recovery")
                        .expect("covered recovery retained"),
                )
                .expect("encode retained recovery"),
                before.1
            );
        }
        for index in covered_count..fixture.pending.len() {
            assert!(
                store
                    .get_pending_output_poi_context(
                        fixture.cfg.chain.chain_id,
                        &fixture.cfg.cache_key,
                        &fixture.pending[index].output_commitment,
                    )
                    .expect("load absent materialized context")
                    .is_some()
            );
            assert!(
                store
                    .get_output_poi_recovery(
                        fixture.cfg.chain.chain_id,
                        &fixture.cfg.cache_key,
                        &fixture.pending[index].output_commitment,
                    )
                    .expect("load absent materialized recovery")
                    .is_some()
            );
        }

        drop(store);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }
}

#[tokio::test]
async fn sender_materialization_persists_only_external_output_and_requires_exact_owned_substitute()
{
    for case in ["exact", "missing", "duplicate", "changed", "spent"] {
        let root_dir = temp_db_root();
        let store = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let fixture = sender_materialization_test_fixture(
            &store,
            &format!("sender-materialization-owned-{case}"),
            2,
        )
        .await;
        let owned_candidate_output = &fixture.candidate.outputs[1];
        let mut owned = WalletUtxo::new(Utxo::new(
            owned_candidate_output
                .note
                .clone()
                .expect("owned candidate note"),
            owned_candidate_output.tree,
            owned_candidate_output.position,
            fixture.candidate.source.clone(),
            UtxoCommitmentKind::Transact,
        ));
        let expected_owned = ExpectedWalletOutput::new(&owned);
        match case {
            "changed" => owned.utxo.poi.npk = FixedBytes::from([0xee; 32]),
            "spent" => owned.spent = Some(source(0xef)),
            _ => {}
        }
        let external = fixture.pending[0].clone();
        let proof_outputs = vec![
            pending_output_poi_submit_identity(
                &external,
                external.observation.as_ref().expect("external observation"),
            )
            .expect("external submit identity")
            .derived_blinded_commitment,
            expected_owned.blinded_commitment(),
        ];
        let mut wallet_outputs = vec![fixture.input.clone()];
        if case != "missing" {
            wallet_outputs.push(owned.clone());
        }
        if case == "duplicate" {
            wallet_outputs.push(owned);
        }
        let mut handle = test_wallet_handle(wallet_outputs);
        handle.cache_key = fixture.cfg.cache_key.clone();
        let outcome = apply_owned_poi_private_delta_on_actor(
            &handle,
            &CancellationToken::new(),
            0,
            store.as_ref(),
            store.as_ref(),
            &fixture.cfg,
            OwnedPoiPrivateDelta::SenderCandidateMaterialization(
                SenderCandidateMaterializationDelta {
                    expected_candidate: fixture.candidate.clone(),
                    public_data_fence: fixture.fence,
                    active_list_keys: external.required_poi_list_keys.clone(),
                    pending_updates: vec![external.clone()],
                    recovery_updates: vec![fixture.recoveries[0].clone()],
                    owned_substitutes: vec![expected_owned],
                    proof_outputs,
                    replacement_group: Vec::new(),
                    external_valid_substitutes: Vec::new(),
                    expected_corpus: current_poi_corpus_revision(),
                    unshield: None,
                },
            ),
        )
        .await
        .expect("materialization apply result");

        assert_eq!(
            outcome,
            if case == "exact" {
                PoiPrivateApplyOutcome::Applied {
                    utxo_changed: false,
                }
            } else {
                PoiPrivateApplyOutcome::Skipped
            }
        );
        assert_eq!(
            store
                .get_sender_transaction_candidate(
                    fixture.cfg.chain.chain_id,
                    &fixture.cfg.cache_key,
                    &fixture.candidate.semantic_id(),
                )
                .expect("load candidate")
                .is_some(),
            case != "exact"
        );
        assert_eq!(
            store
                .get_pending_output_poi_context(
                    fixture.cfg.chain.chain_id,
                    &fixture.cfg.cache_key,
                    &fixture.pending[0].output_commitment,
                )
                .expect("load external context")
                .is_some(),
            case == "exact"
        );
        assert!(
            store
                .get_pending_output_poi_context(
                    fixture.cfg.chain.chain_id,
                    &fixture.cfg.cache_key,
                    &fixture.pending[1].output_commitment,
                )
                .expect("load owned context")
                .is_none()
        );

        drop(store);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }
}

#[tokio::test]
async fn public_reset_waits_for_sender_materialization_commit_guard_without_deadlock() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let public_data_plane =
        ChainPublicDataPlane::new(Arc::clone(&store), Arc::new(AtomicU64::new(0)));
    let commit_guard = public_data_plane.acquire_commit_guard().await;
    let reset_plane = public_data_plane.clone();
    let (started_tx, started_rx) = oneshot::channel();
    let reset = tokio::spawn(async move {
        let _ = started_tx.send(());
        reset_plane.reset_public_cache().await
    });
    started_rx.await.expect("reset task started");
    tokio::task::yield_now().await;
    assert!(!reset.is_finished());
    assert_eq!(public_data_plane.current_epoch().value, 0);

    drop(commit_guard);
    let reset = reset
        .await
        .expect("reset task completed")
        .expect("public reset succeeded");
    assert_eq!(reset.previous_epoch.value, 0);
    assert_eq!(reset.new_epoch.value, 1);

    drop(public_data_plane);
    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn sender_materialization_partial_or_conflicting_pair_retains_everything() {
    for case in ["partial", "conflicting"] {
        let root_dir = temp_db_root();
        let store = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root_dir.clone(),
            })
            .expect("open db"),
        );
        let fixture = sender_materialization_test_fixture(
            &store,
            &format!("sender-materialization-{case}"),
            2,
        )
        .await;
        let mut existing = fixture.pending[0].clone();
        if case == "conflicting" {
            existing.railgun_txid += U256::from(1);
        }
        store
            .put_pending_output_poi_context(&existing)
            .expect("seed predecessor context");
        if case == "conflicting" {
            store
                .put_output_poi_recovery(&fixture.recoveries[0])
                .expect("seed conflicting pair recovery");
        }
        let mut handle = test_wallet_handle(vec![fixture.input.clone()]);
        handle.cache_key = fixture.cfg.cache_key.clone();
        let cancel = CancellationToken::new();

        assert_eq!(
            apply_owned_poi_private_delta_on_actor(
                &handle,
                &cancel,
                0,
                store.as_ref(),
                store.as_ref(),
                &fixture.cfg,
                OwnedPoiPrivateDelta::SenderCandidateMaterialization(
                    SenderCandidateMaterializationDelta {
                        expected_candidate: fixture.candidate.clone(),
                        public_data_fence: fixture.fence.clone(),
                        active_list_keys: fixture.pending[0].required_poi_list_keys.clone(),
                        pending_updates: fixture.pending.clone(),
                        recovery_updates: fixture.recoveries.clone(),
                        owned_substitutes: Vec::new(),
                        proof_outputs: sender_materialization_proof_outputs(&fixture.pending),
                        replacement_group: Vec::new(),
                        external_valid_substitutes: Vec::new(),
                        expected_corpus: current_poi_corpus_revision(),
                        unshield: None,
                    }
                ),
            )
            .await
            .expect("reject nonstandard predecessor"),
            PoiPrivateApplyOutcome::Skipped,
            "case={case}"
        );
        assert!(
            store
                .get_sender_transaction_candidate(
                    fixture.cfg.chain.chain_id,
                    &fixture.cfg.cache_key,
                    &fixture.candidate.semantic_id(),
                )
                .expect("load retained candidate")
                .is_some(),
            "case={case}"
        );
        assert!(
            store
                .get_pending_output_poi_context(
                    fixture.cfg.chain.chain_id,
                    &fixture.cfg.cache_key,
                    &fixture.pending[1].output_commitment,
                )
                .expect("load untouched absent context")
                .is_none(),
            "case={case}"
        );
        assert!(
            store
                .get_output_poi_recovery(
                    fixture.cfg.chain.chain_id,
                    &fixture.cfg.cache_key,
                    &fixture.pending[1].output_commitment,
                )
                .expect("load untouched absent recovery")
                .is_none(),
            "case={case}"
        );

        drop(store);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }
}

#[tokio::test]
async fn sender_materialization_persistence_failure_retains_candidate_without_derived_rows() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let fixture =
        sender_materialization_test_fixture(&store, "sender-materialization-failure", 2).await;
    let cache_store = RecordingCacheStore::new(Arc::clone(&store));
    cache_store.fail_next_commit();
    let mut handle = test_wallet_handle(vec![fixture.input.clone()]);
    handle.cache_key = fixture.cfg.cache_key.clone();
    let cancel = CancellationToken::new();

    assert!(
        apply_owned_poi_private_delta_on_actor(
            &handle,
            &cancel,
            0,
            store.as_ref(),
            &cache_store,
            &fixture.cfg,
            OwnedPoiPrivateDelta::SenderCandidateMaterialization(
                SenderCandidateMaterializationDelta {
                    expected_candidate: fixture.candidate.clone(),
                    public_data_fence: fixture.fence,
                    active_list_keys: fixture.pending[0].required_poi_list_keys.clone(),
                    pending_updates: fixture.pending.clone(),
                    recovery_updates: fixture.recoveries,
                    owned_substitutes: Vec::new(),
                    proof_outputs: sender_materialization_proof_outputs(&fixture.pending),
                    replacement_group: Vec::new(),
                    external_valid_substitutes: Vec::new(),
                    expected_corpus: current_poi_corpus_revision(),
                    unshield: None,
                }
            ),
        )
        .await
        .is_err()
    );
    assert!(
        store
            .get_sender_transaction_candidate(
                fixture.cfg.chain.chain_id,
                &fixture.cfg.cache_key,
                &fixture.candidate.semantic_id(),
            )
            .expect("load retained candidate")
            .is_some()
    );
    for context in &fixture.pending {
        assert!(
            store
                .get_pending_output_poi_context(
                    fixture.cfg.chain.chain_id,
                    &fixture.cfg.cache_key,
                    &context.output_commitment,
                )
                .expect("load absent context")
                .is_none()
        );
        assert!(
            store
                .get_output_poi_recovery(
                    fixture.cfg.chain.chain_id,
                    &fixture.cfg.cache_key,
                    &context.output_commitment,
                )
                .expect("load absent recovery")
                .is_none()
        );
    }

    drop(cache_store);
    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn mixed_replay_report_preserves_waiting_subject_after_another_group_is_replaced() {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let fixture = sender_materialization_test_fixture(&store, "mixed-replay-report", 1).await;
    let old = previous_key_pending_context(&fixture.pending[0]);
    store
        .put_pending_output_poi_context(&old)
        .expect("persist obsolete replacement predecessor");
    store
        .put_output_poi_recovery(&fixture.recoveries[0])
        .expect("persist replacement recovery");
    let list_key = fixture.pending[0].required_poi_list_keys[0];
    let mut waiting = recovered_outgoing_pending_group(&fixture.cfg, list_key).remove(0);
    waiting.source_operation_id = Some("mixed-waiting-source".into());
    let old_two: CurrentPoiFixture = serde_json::from_slice(include_bytes!(
        "../../../../core/tests/fixtures/ppoi_3x3_two_outputs_previous.json"
    ))
    .expect("actual previous-key two-output proof");
    for per_leaf in waiting
        .pre_transaction_pois_per_txid_leaf_per_list
        .values_mut()
    {
        for proof in per_leaf.values_mut() {
            *proof = old_two.pre_tx_poi.clone();
        }
    }
    seed_recovered_outgoing_pending_group(
        store.as_ref(),
        &fixture.cfg,
        std::slice::from_ref(&waiting),
    );
    let mut handle = test_wallet_handle(vec![fixture.input.clone()]);
    handle.cache_key = fixture.cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let plane = test_public_data_plane_with_poi_service(&store);
    let runtime = test_artifact_poi_runtime();
    let private_poi = WalletPrivatePoiClients::for_submit(
        authority.remote_authority(),
        Arc::new(RecordingPendingOutputPoiSubmitter::default()),
    );
    let snapshot = [fixture.input.clone()];
    let active_lists = [list_key];
    let replay = super::super::saved_poi_compatibility::reconstruct_incompatible_sender_candidates(
        &OutputPoiRecoveryRequest {
            authority: &authority,
            db: store.as_ref(),
            cache_store: store.as_ref(),
            cfg: &fixture.cfg,
            public_data_plane: &plane,
            http_client: None,
            indexed_artifact_source: None,
            forest: Arc::new(MerkleForest::new()),
            poi_client: runtime.public_client(),
            private_poi: &private_poi,
            poi_runtime: &runtime,
            active_list_keys: &active_lists,
            wallet_utxos: &snapshot,
            force_retry: false,
        },
    )
    .await
    .expect("capture both source groups before replacement");
    assert_eq!(replay.awaiting_public_txid_data, 1);
    let replacement_group = vec![(old.clone(), Some(fixture.recoveries[0].clone()))];
    assert!(matches!(
        apply_owned_poi_private_delta_on_actor(
            &handle,
            &cancel,
            0,
            store.as_ref(),
            store.as_ref(),
            &fixture.cfg,
            OwnedPoiPrivateDelta::SenderCandidateMaterialization(
                SenderCandidateMaterializationDelta {
                    expected_candidate: fixture.candidate.clone(),
                    public_data_fence: fixture.fence.clone(),
                    active_list_keys: active_lists.to_vec(),
                    pending_updates: fixture.pending.clone(),
                    recovery_updates: fixture.recoveries.clone(),
                    owned_substitutes: Vec::new(),
                    proof_outputs: sender_materialization_proof_outputs(&fixture.pending),
                    expected_corpus: current_poi_corpus_revision(),
                    replacement_group,
                    external_valid_substitutes: Vec::new(),
                    unshield: None,
                }
            ),
        )
        .await
        .expect("durably replace only the qualified source group"),
        PoiPrivateApplyOutcome::Applied { .. }
    ));
    let mut materialization = super::super::SenderCandidateRecoveryReport {
        materialized: 1,
        satisfied_pending_contexts: BTreeSet::from([old.output_commitment]),
        ..super::super::SenderCandidateRecoveryReport::default()
    };
    materialization.merge_replay_report(replay);
    assert_eq!(materialization.awaiting_public_txid_data, 1);
    assert!(
        materialization
            .matches_pending_contexts(store.as_ref(), &fixture.cfg)
            .expect("only unresolved source guards its report")
    );
    let candidates = <DbStore as WalletCacheStore>::list_sender_transaction_candidates(
        store.as_ref(),
        fixture.cfg.chain.chain_id,
        &fixture.cfg.cache_key,
    )
    .expect("candidate state after successful replacement");
    assert!(materialization.matches_candidates(&candidates));
    waiting.source_operation_id = Some("waiting-subject-replaced-after-report".into());
    store
        .put_pending_output_poi_context(&waiting)
        .expect("replace unresolved subject");
    assert!(
        !materialization
            .matches_pending_contexts(store.as_ref(), &fixture.cfg)
            .expect("unresolved source still guards publication")
    );
    drop(plane);
    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[tokio::test]
async fn obsolete_external_proof_maintenance_reports_waiting_and_retrying_without_stale_publication()
 {
    let root_dir = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db"),
    );
    let mut group = saved_poi_migration_tests::migration_group(
        "ppoi_3x3_external_previous.json",
        "obsolete-proof-maintenance",
    );
    group.pending[0].submitted_poi_list_keys = vec![group.list_key];
    saved_poi_migration_tests::seed_migration_group(store.as_ref(), &group);
    let mut handle = test_wallet_handle(vec![group.input.clone()]);
    handle.cache_key = group.cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let plane = test_public_data_plane_with_poi_service(&store);
    let runtime = test_artifact_poi_runtime();
    let submitter = Arc::new(RecordingPendingOutputPoiSubmitter::default());
    let private_poi =
        WalletPrivatePoiClients::for_submit(authority.remote_authority(), submitter.clone());
    let forest = Arc::new(RwLock::new(MerkleForest::new()));
    let active_lists = [group.list_key];
    let status = wallet_ppoi_workflow_status_for_test(store.as_ref(), &group.cfg, &active_lists, 0);
    assert_eq!(
        status.awaiting_recovery, 1,
        "submitted obsolete proofs still need replacement"
    );
    assert_eq!(status.awaiting_validation, 0);
    let failed_store = RecordingCacheStore::new(Arc::clone(&store));
    failed_store.fail_next_candidate_list();
    let failed = (OutputPoiRecoveryRun {
        authority: &authority,
        db: store.as_ref(),
        cache_store: &failed_store,
        cfg: &group.cfg,
        public_data_plane: &plane,
        http_client: None,
        indexed_artifact_source: None,
        poi_runtime: &runtime,
        forest: &forest,
        utxos: &handle.utxos,
        client: runtime.public_client(),
        private_poi: &private_poi,
        active_list_keys: &active_lists,
        force_retry: false,
        unshield_attempts: &SenderUnshieldAttempts::default(),
    })
    .recover_missing()
    .await;
    assert!(matches!(
        failed.error,
        Some(PoiMaintenanceError::SenderCandidateReplay(_))
    ));
    assert_eq!(failed.recovered, 0);
    let waiting = (OutputPoiRecoveryRun {
        authority: &authority,
        db: store.as_ref(),
        cache_store: store.as_ref(),
        cfg: &group.cfg,
        public_data_plane: &plane,
        http_client: None,
        indexed_artifact_source: None,
        poi_runtime: &runtime,
        forest: &forest,
        utxos: &handle.utxos,
        client: runtime.public_client(),
        private_poi: &private_poi,
        active_list_keys: &active_lists,
        force_retry: false,
        unshield_attempts: &SenderUnshieldAttempts::default(),
    })
    .recover_missing()
    .await;
    assert!(waiting.error.is_none());
    assert_eq!(waiting.candidate_report.awaiting_public_txid_data, 1);
    assert_eq!(waiting.candidate_report.retrying, 0);
    assert!(
        waiting
            .candidate_report
            .matches_pending_contexts(store.as_ref(), &group.cfg)
            .expect("check waiting subjects")
    );

    saved_poi_migration_tests::seed_migration_source_block(&plane, &group, 43).await;
    let _public_fence = saved_poi_migration_tests::seed_migration_public_rows(
        &plane,
        &group,
        "ppoi_3x3_external_previous.json",
        U256::ZERO,
        false,
    )
    .await;
    let mut cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        group.cfg.chain.chain_id,
        DEFAULT_TXID_VERSION,
        group.list_key,
    ));
    cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: [0x99; 32],
            signature: [0; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("make local corpus ready without marking this output Valid");
    seed_data_plane_poi_cache(&plane, group.cfg.chain.chain_id, group.list_key, cache).await;
    let retrying = (OutputPoiRecoveryRun {
        authority: &authority,
        db: store.as_ref(),
        cache_store: store.as_ref(),
        cfg: &group.cfg,
        public_data_plane: &plane,
        http_client: None,
        indexed_artifact_source: None,
        poi_runtime: &runtime,
        forest: &forest,
        utxos: &handle.utxos,
        client: runtime.public_client(),
        private_poi: &private_poi,
        active_list_keys: &active_lists,
        force_retry: false,
        unshield_attempts: &SenderUnshieldAttempts::default(),
    })
    .recover_missing()
    .await;
    assert!(retrying.error.is_none());
    assert_eq!(
        retrying.recovered, 0,
        "the retained candidate still lacks a prover"
    );
    assert_eq!(retrying.candidate_report.awaiting_public_txid_data, 0);
    assert_eq!(
        retrying.candidate_report.retrying, 1,
        "replay and materialization must count this output once"
    );
    assert_eq!(retrying.candidate_report.needs_attention, 0);
    let candidates = <DbStore as WalletCacheStore>::list_sender_transaction_candidates(
        store.as_ref(),
        group.cfg.chain.chain_id,
        &group.cfg.cache_key,
    )
    .expect("reconstructed candidate");
    assert_eq!(candidates.len(), 1);
    assert!(retrying.candidate_report.matches_candidates(&candidates));
    assert!(
        retrying
            .candidate_report
            .matches_pending_contexts(store.as_ref(), &group.cfg)
            .expect("check retry subjects")
    );
    assert_eq!(
        process_pending_output_poi_observations_authorized(
            &authority,
            &plane,
            store.as_ref(),
            store.as_ref(),
            &group.cfg,
            &active_lists,
            Some(&private_poi),
            true
        )
        .await,
        0
    );
    assert!(
        submitter.calls().is_empty(),
        "waiting and forced retry cannot disclose an old proof"
    );

    let mut replacement = group.pending[0].clone();
    replacement.source_operation_id = Some("new-subject-after-report".to_string());
    store
        .put_pending_output_poi_context(&replacement)
        .expect("replace subject after reporting");
    assert!(
        !waiting
            .candidate_report
            .matches_pending_contexts(store.as_ref(), &group.cfg)
            .expect("reject replaced waiting subject")
    );
    assert!(
        !retrying
            .candidate_report
            .matches_pending_contexts(store.as_ref(), &group.cfg)
            .expect("reject replaced retry subject")
    );
    store
        .delete_pending_output_poi_context(
            group.cfg.chain.chain_id,
            group.cfg.cache_key.as_str(),
            &replacement.output_commitment,
        )
        .expect("retire subject after reporting");
    assert!(
        !retrying
            .candidate_report
            .matches_pending_contexts(store.as_ref(), &group.cfg)
            .expect("reject retired retry subject")
    );
    drop(plane);
    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

fn fixture_output_note(fixture: &CurrentPoiFixture, index: usize) -> Note {
    // Fixture npks and values are public synthetic data; token/random determine their commitments.
    Note {
        token_hash: U256::from_be_slice(Address::from([0x11; 20]).as_slice()),
        value: fixture.public_context.output_values[index],
        random: [2 + u8::try_from(index).expect("bounded fixture index"); 16],
        npk: fixture.public_context.output_npks[index],
    }
}

fn sender_materialization_proof_outputs(
    pending: &[PendingOutputPoiContextRecord],
) -> Vec<FixedBytes<32>> {
    pending
        .iter()
        .map(|context| {
            pending_output_poi_submit_identity(
                context,
                context
                    .observation
                    .as_ref()
                    .expect("materialization observation"),
            )
            .expect("materialization submit identity")
            .derived_blinded_commitment
        })
        .collect()
}

async fn sender_materialization_test_fixture(
    store: &Arc<DbStore>,
    wallet_name: &str,
    output_count: usize,
) -> SenderMaterializationTestFixture {
    let mut cfg = wallet_config(U256::from(42));
    cfg.cache_key = test_cache_key(wallet_name);
    let list_key = FixedBytes::from([0xa1; 32]);
    let candidate_source = source(0xa2);
    let mut input = test_wallet_utxo(7);
    input.spent = Some(candidate_source.clone());
    let fixture = current_poi_fixture(if output_count == 1 {
        "ppoi_3x3"
    } else {
        "ppoi_3x3_two_outputs"
    });
    let global: u128 = fixture.public_context.output_start_global.to();
    let outputs = (0..output_count)
        .map(|index| {
            let note = fixture_output_note(&fixture, index);
            let position = global + u128::try_from(index).expect("bounded output count");
            SenderTransactionCandidateOutput {
                tree: u32::try_from(position / u128::from(TREE_LEAF_COUNT)).expect("output tree"),
                position: u64::try_from(position % u128::from(TREE_LEAF_COUNT))
                    .expect("output position"),
                commitment: FixedBytes::from(note.commitment().to_be_bytes::<32>()),
                note: Some(note),
            }
        })
        .collect();
    let candidate = SenderTransactionCandidate::new(
        cfg.chain.chain_id,
        cfg.cache_key.clone(),
        candidate_source.clone(),
        vec![SenderTransactionCandidateSpend {
            tree: input.utxo.tree,
            position: input.utxo.position,
            commitment: input.utxo.poi.commitment,
        }],
        outputs,
    )
    .expect("candidate");
    store
        .put_opaque_wallet_private_row(
            &candidate.namespace(),
            WalletPrivateRecordKind::SenderTransactionCandidate,
            &OpaqueWalletPrivateRow {
                row_id: candidate.row_identity(),
                payload: candidate.encode().expect("encode candidate"),
            },
        )
        .expect("store candidate");

    let mut pending = Vec::with_capacity(output_count);
    let mut recoveries = Vec::with_capacity(output_count);
    for output in &candidate.outputs {
        let note = output.note.clone().expect("qualified sender output");
        let utxo = Utxo::new(
            note,
            output.tree,
            output.position,
            candidate_source.clone(),
            UtxoCommitmentKind::Transact,
        );
        let mut context = external_pending_output_record(
            &cfg,
            0xa4,
            list_key,
            PendingOutputPoiRole::RecoveredOutgoing,
        );
        context.txid_merkleroot_index = Some(77);
        context.utxo_tree_in = fixture.public_context.input_tree;
        context.railgun_txid = fixture.public_context.railgun_txid;
        context.pre_transaction_pois_per_txid_leaf_per_list = BTreeMap::from([(
            list_key,
            BTreeMap::from([(FixedBytes::from([0xd3; 32]), fixture.pre_tx_poi.clone())]),
        )]);
        context.source_operation_id = Some("test-recovered-sender-inner-7".to_string());
        context.output_commitment = utxo.poi.commitment;
        context.output_npk = utxo.poi.npk;
        context.observation = Some(local_db::PendingOutputPoiObservation {
            output_tree: u64::from(output.tree),
            output_position: output.position,
            tx_hash: candidate_source.tx_hash,
            block_number: candidate_source.block_number,
            block_timestamp: candidate_source.block_timestamp,
        });
        let mut recovery = output_poi_recovery_record(
            cfg.chain.chain_id,
            &cfg.cache_key,
            utxo.poi.commitment,
            OutputPoiRecoveryStatus::Recoverable,
            None,
        );
        recovery.source_tx_hash = candidate_source.tx_hash;
        pending.push(context);
        recoveries.push(recovery);
    }
    let (_, fence) = sender_candidate_public_data_fence(
        store,
        &cfg,
        &candidate,
        &input,
        candidate.outputs[0].commitment,
        candidate.source.block_timestamp,
    )
    .await;
    SenderMaterializationTestFixture {
        cfg,
        candidate,
        input,
        pending,
        recoveries,
        fence,
    }
}
