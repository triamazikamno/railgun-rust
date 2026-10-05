use super::*;
use crate::chain::{PublicScanRange, PublicScanRows};
use crate::types::PublicScanSource;
use crate::wallet::saved_poi_compatibility::{
    reconstruct_incompatible_sender_candidates, saved_pending_context_is_compatible,
    saved_pending_context_matches_public_transaction, saved_poi_is_compatible,
};
use railgun_wallet::scan::{
    IndexedNullifierInput, IndexedTransactCommitmentInput, WalletScanInputRows,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct MigrationProofFixture {
    pre_tx_poi: PreTxPoi,
    public_context: MigrationPublicContext,
}

#[derive(Deserialize)]
struct MigrationPublicContext {
    railgun_txid: U256,
    txid_leaf_hash: FixedBytes<32>,
    input_tree: u32,
    commitments_out: Vec<U256>,
    output_npks: Vec<U256>,
    output_values: Vec<U256>,
    output_start_global: U256,
    nullifiers: Vec<U256>,
    bound_params_hash: U256,
}

fn migration_proof(filename: &str) -> MigrationProofFixture {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../core/tests/fixtures")
        .join(filename);
    serde_json::from_slice(&fs::read(path).expect("retained real PPOI proof"))
        .expect("decode public synthetic fixture")
}

pub(super) struct MigrationGroup {
    pub(super) cfg: WalletConfig,
    pub(super) input: WalletUtxo,
    pub(super) candidate: SenderTransactionCandidate,
    outputs: Vec<Utxo>,
    pub(super) pending: Vec<PendingOutputPoiContextRecord>,
    recoveries: Vec<OutputPoiRecoveryRecord>,
    pub(super) list_key: FixedBytes<32>,
}

pub(super) fn migration_group(filename: &str, name: &str) -> MigrationGroup {
    let fixture = migration_proof(filename);
    let mut cfg = wallet_config(U256::from(42));
    cfg.cache_key = test_cache_key(name);
    cfg.scan_keys =
        ViewingKeyData::from_spending_public_key([7; 32], [U256::from(4), U256::from(5)]);
    let external = filename.contains("_external_");
    if external {
        let keys =
            railgun_wallet::WalletKeys::from_seed(&[42; 64], 0).expect("public synthetic sender");
        cfg.scan_keys = keys.viewing;
        cfg.spending_public_key = Some(keys.spending_public_key);
    }
    let source = source(0x61);
    let mut input = if external {
        WalletUtxo::new(Utxo::new(
            Note::new_change(
                cfg.scan_keys.master_public_key,
                Address::from([0x11; 20]),
                U256::from(100),
                [1; 16],
            ),
            0,
            0,
            super::source(0),
            UtxoCommitmentKind::Transact,
        ))
    } else {
        test_wallet_utxo(0)
    };
    input.spent = Some(source.clone());
    let list_key = FixedBytes::from([0x62; 32]);
    let start = fixture.public_context.output_start_global.to::<u64>();
    let outputs = fixture
        .public_context
        .output_npks
        .iter()
        .enumerate()
        .map(|(index, npk)| {
            let note = Note::new_change(
                railgun_wallet::WalletKeys::from_seed(&[if external { 43 } else { 42 }; 64], 0)
                    .expect("public fixture keys")
                    .viewing
                    .master_public_key,
                Address::from([0x11; 20]),
                fixture.public_context.output_values[index],
                [u8::try_from(index + 2).expect("small fixture output count"); 16],
            );
            assert_eq!(note.npk, *npk);
            assert_eq!(
                note.commitment(),
                fixture.public_context.commitments_out[index]
            );
            let global = start + u64::try_from(index).expect("small fixture output count");
            let output = Utxo::new(
                note,
                u32::try_from(global / TREE_LEAF_COUNT).expect("fixture tree"),
                global % TREE_LEAF_COUNT,
                source.clone(),
                UtxoCommitmentKind::Transact,
            );
            assert_eq!(
                output.poi.blinded_commitment,
                fixture.pre_tx_poi.blinded_commitments_out[index]
            );
            output
        })
        .collect::<Vec<_>>();
    let candidate = SenderTransactionCandidate::new(
        cfg.chain.chain_id,
        cfg.cache_key.clone(),
        source.clone(),
        vec![SenderTransactionCandidateSpend {
            tree: input.utxo.tree,
            position: input.utxo.position,
            commitment: input.utxo.poi.commitment,
        }],
        outputs
            .iter()
            .map(|output| SenderTransactionCandidateOutput {
                tree: output.tree,
                position: output.position,
                commitment: output.poi.commitment,
                note: Some(output.note.clone()),
            })
            .collect(),
    )
    .expect("valid sender candidate");
    let material = BTreeMap::from([(
        list_key,
        BTreeMap::from([(fixture.public_context.txid_leaf_hash, fixture.pre_tx_poi)]),
    )]);
    let pending = outputs
        .iter()
        .map(|output| {
            let mut context = external_pending_output_record(
                &cfg,
                0x63,
                list_key,
                PendingOutputPoiRole::RecoveredOutgoing,
            );
            context.output_commitment = output.poi.commitment;
            context.output_npk = output.poi.npk;
            context.utxo_tree_in = fixture.public_context.input_tree.into();
            context.railgun_txid = fixture.public_context.railgun_txid;
            context.txid_merkleroot_index = Some(0);
            context.source_operation_id = Some("synthetic-migrated-inner-transaction".into());
            context.pre_transaction_pois_per_txid_leaf_per_list = material.clone();
            context.observation = Some(local_db::PendingOutputPoiObservation {
                output_tree: output.tree.into(),
                output_position: output.position,
                tx_hash: source.tx_hash,
                block_number: source.block_number,
                block_timestamp: source.block_timestamp,
            });
            context
        })
        .collect::<Vec<_>>();
    let recoveries = outputs
        .iter()
        .map(|output| {
            let mut recovery = output_poi_recovery_record(
                cfg.chain.chain_id,
                &cfg.cache_key,
                output.poi.commitment,
                OutputPoiRecoveryStatus::Recoverable,
                None,
            );
            recovery.source_tx_hash = source.tx_hash;
            recovery.tx_input = Some(vec![0x12, 0x34]);
            recovery
        })
        .collect();
    MigrationGroup {
        cfg,
        input,
        candidate,
        outputs,
        pending,
        recoveries,
        list_key,
    }
}

pub(super) fn seed_migration_group(store: &DbStore, group: &MigrationGroup) {
    for (context, recovery) in group.pending.iter().zip(&group.recoveries) {
        store
            .put_pending_output_poi_context(context)
            .expect("persist pending proof");
        store
            .put_output_poi_recovery(recovery)
            .expect("persist recovery evidence");
    }
}

fn seed_migration_candidate(store: &DbStore, group: &MigrationGroup) {
    store
        .put_opaque_wallet_private_row(
            &group.candidate.namespace(),
            WalletPrivateRecordKind::SenderTransactionCandidate,
            &OpaqueWalletPrivateRow {
                row_id: group.candidate.row_identity(),
                payload: group.candidate.encode().expect("encode candidate"),
            },
        )
        .expect("persist reconstructed candidate");
}

fn migration_wallet_payloads(utxos: &[WalletUtxo]) -> Vec<Vec<u8>> {
    utxos
        .iter()
        .map(|utxo| {
            railgun_wallet::wallet_cache::serialize_wallet_utxo(utxo)
                .expect("encode complete persisted wallet output")
        })
        .collect()
}

pub(super) async fn seed_migration_public_rows(
    plane: &ChainPublicDataPlane,
    group: &MigrationGroup,
    filename: &str,
    merkle_root: U256,
    extra_inner_transaction: bool,
) -> SenderCandidatePublicDataFence {
    let fixture = migration_proof(filename);
    let mut transaction = serde_json::json!({
        "id": "0x00", "blockNumber": group.candidate.source.block_number.to_string(),
        "blockTimestamp": group.candidate.source.block_timestamp.to_string(),
        "transactionHash": hex::encode_prefixed(group.candidate.source.tx_hash),
        "merkleRoot": hex::encode_prefixed(FixedBytes::from(merkle_root.to_be_bytes::<32>())),
        "nullifiers": fixture.public_context.nullifiers.iter().map(|value| hex::encode_prefixed(FixedBytes::from(value.to_be_bytes::<32>()))).collect::<Vec<_>>(),
        "commitments": fixture.public_context.commitments_out.iter().map(|value| hex::encode_prefixed(FixedBytes::from(value.to_be_bytes::<32>()))).collect::<Vec<_>>(),
        "boundParamsHash": hex::encode_prefixed(FixedBytes::from(fixture.public_context.bound_params_hash.to_be_bytes::<32>())),
        "hasUnshield": false, "utxoTreeIn": fixture.public_context.input_tree.to_string(),
        "utxoTreeOut": group.outputs[0].tree.to_string(),
        "utxoBatchStartPositionOut": group.outputs[0].position.to_string(),
    });
    let mut transactions = vec![transaction.clone()];
    if extra_inner_transaction {
        transaction["id"] = serde_json::json!("0x01");
        transaction["nullifiers"] = serde_json::json!(["0x03", "0x04", "0x05", "0x06"]);
        transaction["commitments"] = serde_json::json!(["0x07"]);
        transaction["utxoBatchStartPositionOut"] =
            serde_json::json!((group.outputs[0].position + 10).to_string());
        transactions.push(transaction);
    }
    let (endpoint, _requests) = spawn_http_response(
        serde_json::json!({ "data": { "transactions": transactions } })
            .to_string()
            .into_bytes(),
    )
    .await;
    let key = DataPlanePublicTxidCacheKey::new(
        ChainScope {
            chain_type: ChainType::Evm,
            chain_id: group.cfg.chain.chain_id,
            railgun_contract: group.cfg.chain.contract,
        },
        DEFAULT_TXID_VERSION,
    );
    plane
        .sync_txid_public_cache(PublicTxidSyncRequest {
            key: key.clone(),
            endpoint: Some(&endpoint),
            http_client: None,
            latest: DataPlanePublicTxidLatestValidated {
                txid_index: u64::from(extra_inner_transaction),
                merkleroot: None,
            },
            indexed_artifact_source: None,
        })
        .await
        .expect("seed exact inner transaction public evidence");
    let rows = plane
        .txid_transactions_for_outer_hash(&key, group.candidate.source.tx_hash)
        .expect("load exact public transaction rows");
    SenderCandidatePublicDataFence::new(
        plane,
        key,
        plane.current_epoch(),
        rows,
        PublicTxidDataAuthority::LatestValidated,
    )
}

pub(super) async fn seed_migration_source_block(
    plane: &ChainPublicDataPlane,
    group: &MigrationGroup,
    recipient_seed: u8,
) {
    let recipient = railgun_wallet::WalletKeys::from_seed(&[recipient_seed; 64], 0)
        .expect("public synthetic recipient");
    let ciphertext = CommitmentCiphertext::from(
        NoteCiphertext::try_from_note(
            &group.outputs[0].note,
            &group.cfg.scan_keys.address_data(),
            &recipient.viewing.address_data(),
            &group.cfg.scan_keys.viewing_private_key,
        )
        .expect("encrypt sender-recoverable external output"),
    );
    let rows = WalletScanInputRows {
        transact_commitments: vec![IndexedTransactCommitmentInput {
            tree_number: group.outputs[0].tree,
            tree_position: group.outputs[0].position,
            hash: group.outputs[0].note.commitment(),
            ciphertext: ciphertext.ciphertext,
            blinded_sender_viewing_key: ciphertext.blindedSenderViewingKey,
            blinded_receiver_viewing_key: ciphertext.blindedReceiverViewingKey,
            annotation_data: ciphertext.annotationData,
            memo: ciphertext.memo,
            source: group.candidate.source.clone(),
        }],
        nullifiers: vec![IndexedNullifierInput {
            tree_number: group.input.utxo.tree,
            nullifier: group
                .input
                .utxo
                .nullifier(group.cfg.scan_keys.nullifying_key),
            source: group.candidate.source.clone(),
        }],
        ..WalletScanInputRows::default()
    };
    plane
        .record_recent_public_scan_rows(PublicScanRows {
            range: PublicScanRange::new(
                group.candidate.source.block_number,
                group.candidate.source.block_number,
            ),
            source: PublicScanSource::Rpc,
            to_block_hash: Some([0x61; 32]),
            rows,
            epoch: plane.current_epoch(),
        })
        .await
        .expect("retain only the source block");
}

#[derive(Default)]
struct MigrationProofTransport {
    proofs: Mutex<Vec<PreTxPoi>>,
    list_keys: Mutex<Vec<FixedBytes<32>>>,
}

async fn seed_migration_partial_list_status(
    plane: &ChainPublicDataPlane,
    group: &MigrationGroup,
    pending_lists: &[FixedBytes<32>],
) {
    for list_key in std::iter::once(group.list_key).chain(pending_lists.iter().copied()) {
        let mut cache = PoiCache::new(PoiCacheIdentity::new(
            EVM_CHAIN_TYPE,
            group.cfg.chain.chain_id,
            DEFAULT_TXID_VERSION,
            list_key,
        ));
        let mut events = vec![poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: group.input.utxo.poi.blinded_commitment.0,
            signature: [0; 64],
            event_type: PoiEventType::Transact,
        }];
        if list_key == group.list_key {
            events.push(poi::artifacts::SnapshotEvent {
                event_index: 1,
                blinded_commitment: group.outputs[0].poi.blinded_commitment.0,
                signature: [0; 64],
                event_type: PoiEventType::Transact,
            });
        }
        cache
            .apply_verified_artifact_events(&events)
            .expect("seed authoritative per-list input and output status");
        cache.accept_current_roots();
        seed_data_plane_poi_cache(plane, group.cfg.chain.chain_id, list_key, cache).await;
    }
}

#[async_trait]
impl PendingOutputPoiSubmitter for MigrationProofTransport {
    async fn submit_single_commitment_proofs(
        &self,
        _: &str,
        _: u8,
        _: u64,
        context: &SingleCommitmentProofContext,
        _: u64,
        _: u64,
    ) -> Result<(), PoiError> {
        for proof in context
            .pre_transaction_pois_per_txid_leaf_per_list
            .values()
            .flat_map(|per_leaf| per_leaf.values())
        {
            assert!(
                saved_poi_is_compatible(proof, None),
                "an obsolete proof reached the transport"
            );
            self.proofs
                .lock()
                .expect("record submitted proofs")
                .push(proof.clone());
        }
        self.list_keys
            .lock()
            .expect("record submitted lists")
            .extend(
                context
                    .pre_transaction_pois_per_txid_leaf_per_list
                    .keys()
                    .copied(),
            );
        Ok(())
    }

    async fn submit_transact_proof(
        &self,
        _: &str,
        _: u8,
        _: u64,
        list_key: &FixedBytes<32>,
        _: u64,
        proof: &PreTxPoi,
    ) -> Result<(), PoiError> {
        assert!(
            saved_poi_is_compatible(proof, None),
            "an obsolete proof reached the transport"
        );
        self.proofs
            .lock()
            .expect("record submitted proof")
            .push(proof.clone());
        self.list_keys
            .lock()
            .expect("record submitted list")
            .push(*list_key);
        Ok(())
    }
}

#[tokio::test]
async fn restored_proofs_select_circuits_from_unshield_and_exact_inner_counts() {
    let fixture = migration_proof("ppoi_13x13_unshield.json");
    assert_eq!(fixture.pre_tx_poi.blinded_commitments_out.len(), 3);
    assert!(saved_poi_is_compatible(&fixture.pre_tx_poi, None));
    assert!(saved_poi_is_compatible(&fixture.pre_tx_poi, Some((1, 4))));
    assert!(!saved_poi_is_compatible(&fixture.pre_tx_poi, Some((1, 3))));
    let root = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root.clone(),
        })
        .expect("open db"),
    );
    let group = migration_group("ppoi_3x3.json", "exact-inner-counts");
    let plane = ChainPublicDataPlane::new(Arc::clone(&store), Arc::new(AtomicU64::new(0)));
    seed_migration_public_rows(&plane, &group, "ppoi_3x3.json", U256::from(1), true).await;
    assert!(
        saved_pending_context_matches_public_transaction(
            &plane,
            &group.cfg,
            &group.pending[0],
            &[group.list_key]
        ),
        "the other inner transaction's four inputs must not select the 13x13 key for this 3x3 proof"
    );
    drop(plane);
    drop(store);
    fs::remove_dir_all(root).expect("remove temp db");
}

#[test]
fn previous_proof_is_ineligible_for_tentative_submission() {
    let root = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root.clone(),
        })
        .expect("open db"),
    );
    let mut group = migration_group("ppoi_3x3_previous.json", "obsolete-proof-transport");
    group.pending[0].output_role = PendingOutputPoiRole::Recipient;
    group.pending[0].txid_merkleroot_index = None;
    group.pending[0].source_operation_id = None;
    let observation = CommitmentObservation {
        tree: group.outputs[0].tree,
        position: group.outputs[0].position,
        commitment: group.outputs[0].note.commitment(),
        source: group.candidate.source.clone(),
    };
    let mut tentative = group.pending[0].clone();
    tentative.observation = None;
    store
        .put_pending_output_poi_context(&tentative)
        .expect("persist tentative previous proof");
    assert!(
        prepare_pending_output_poi_tentative_candidates(
            store.as_ref(),
            &group.cfg,
            &[group.list_key],
            std::slice::from_ref(&observation)
        )
        .expect("prepare tentative old proof")
        .is_empty()
    );

    // A current proof with the same synthetic output is eligible, so rejection is not caused
    // by missing list or output identity prerequisites.
    tentative.pre_transaction_pois_per_txid_leaf_per_list =
        migration_group("ppoi_3x3.json", "control").pending[0]
            .pre_transaction_pois_per_txid_leaf_per_list
            .clone();
    store
        .put_pending_output_poi_context(&tentative)
        .expect("persist current proof control");
    assert_eq!(
        prepare_pending_output_poi_tentative_candidates(
            store.as_ref(),
            &group.cfg,
            &[group.list_key],
            &[observation]
        )
        .expect("prepare compatible control")
        .len(),
        1
    );

    drop(store);
    fs::remove_dir_all(root).expect("remove temp db");
}

#[tokio::test]
async fn source_block_reconstructs_consumed_exact_spend_candidate_and_preserves_durable_wallet_state()
 {
    let root = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root.clone(),
        })
        .expect("open db"),
    );
    let mut group = migration_group("ppoi_3x3_previous.json", "exact-spend-reconstruction");
    group.pending[0].output_role = PendingOutputPoiRole::BroadcasterFee;
    group.recoveries[0].apply_action(
        OutputPoiRecoveryAction::SubmitFailed {
            error: "temporary POI transport failure".into(),
            retry_after: Duration::from_secs(60),
        },
        10,
    );
    seed_migration_group(&store, &group);
    let mut handle = test_wallet_handle(vec![group.input.clone()]);
    handle.cache_key = group.cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let permit = authority.acquire().await.expect("wallet authority");
    let mut persist = WalletPersistState::default();
    persist
        .persist_progress_with_private_effects(
            store.as_ref(),
            &permit,
            WalletProgressPersist {
                cache_key: group.cfg.cache_key.as_str(),
                snapshot: std::slice::from_ref(&group.input),
                last_scanned: 900,
                checkpoint: WalletCheckpointMutation::Set {
                    last_scanned_block: 900,
                    last_scanned_block_hash: Some([0x90; 32]),
                },
                changed: true,
            },
            WalletProgressPrivateEffects::default(),
        )
        .expect("persist spent balance and checkpoint");
    drop(permit);
    let baseline = migration_wallet_payloads(
        &<DbStore as WalletCacheStore>::load_wallet_utxos(store.as_ref(), &group.cfg.cache_key)
            .expect("load baseline wallet history"),
    );
    let meta = <DbStore as WalletCacheStore>::get_wallet_meta(store.as_ref(), &group.cfg.cache_key)
        .expect("load baseline checkpoint");
    let plane = ChainPublicDataPlane::new(Arc::clone(&store), Arc::new(AtomicU64::new(0)));
    let runtime = test_artifact_poi_runtime();
    let submitter = Arc::new(RecordingPendingOutputPoiSubmitter::default());
    let private_poi =
        WalletPrivatePoiClients::for_submit(authority.remote_authority(), submitter.clone());
    let active_lists = [group.list_key];
    let snapshot = [group.input.clone()];
    let request = OutputPoiRecoveryRequest {
        authority: &authority,
        db: store.as_ref(),
        cache_store: store.as_ref(),
        cfg: &group.cfg,
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
    };
    let _ = reconstruct_incompatible_sender_candidates(&request).await;
    assert!(
        <DbStore as WalletCacheStore>::list_sender_transaction_candidates(
            store.as_ref(),
            group.cfg.chain.chain_id,
            &group.cfg.cache_key
        )
        .expect("missing source is retryable")
        .is_empty()
    );

    seed_migration_source_block(&plane, &group, 42).await;
    let _ = reconstruct_incompatible_sender_candidates(&request).await;
    let _ = reconstruct_incompatible_sender_candidates(&request).await;
    let candidates = <DbStore as WalletCacheStore>::list_sender_transaction_candidates(
        store.as_ref(),
        group.cfg.chain.chain_id,
        &group.cfg.cache_key,
    )
    .expect("load reconstructed candidate");
    assert_eq!(candidates.len(), 1, "repeated recovery is idempotent");
    assert_eq!(
        candidates[0].encode().expect("encode actual candidate"),
        group.candidate.encode().expect("encode expected candidate")
    );
    assert!(
        migration_wallet_payloads(&handle.utxos.read().await) == baseline,
        "reconstruction must preserve the complete actor snapshot"
    );
    assert!(submitter.calls().is_empty());
    drop(private_poi);
    drop(plane);
    drop(store);
    let reopened = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root.clone(),
        })
        .expect("restart wallet storage"),
    );
    assert!(
        migration_wallet_payloads(
            &<DbStore as WalletCacheStore>::load_wallet_utxos(
                reopened.as_ref(),
                &group.cfg.cache_key
            )
            .expect("restored spent history")
        ) == baseline,
        "restart must preserve the complete persisted wallet history"
    );
    assert_eq!(
        rmp_serde::to_vec(
            &<DbStore as WalletCacheStore>::get_wallet_meta(
                reopened.as_ref(),
                &group.cfg.cache_key
            )
            .expect("restored checkpoint")
        )
        .expect("encode restored checkpoint"),
        rmp_serde::to_vec(&meta).expect("encode baseline checkpoint")
    );
    assert_eq!(
        <DbStore as WalletCacheStore>::list_sender_transaction_candidates(
            reopened.as_ref(),
            group.cfg.chain.chain_id,
            &group.cfg.cache_key
        )
        .expect("restored candidate")
        .len(),
        1
    );
    assert!(
        reopened
            .get_pending_output_poi_context(
                group.cfg.chain.chain_id,
                &group.cfg.cache_key,
                &group.pending[0].output_commitment
            )
            .expect("restored pending evidence")
            .is_some()
    );
    cancel.cancel();
    let current = migration_group("ppoi_3x3.json", "exact-spend-reconstruction");
    let plane = test_public_data_plane_with_poi_service(&reopened);
    let mut status_cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        current.cfg.chain.chain_id,
        DEFAULT_TXID_VERSION,
        current.list_key,
    ));
    status_cache.accept_current_roots();
    seed_data_plane_poi_cache(
        &plane,
        current.cfg.chain.chain_id,
        current.list_key,
        status_cache,
    )
    .await;
    let corpus = plane
        .ensure_poi_corpus(PublicPoiCorpusKey::wallet_default(
            current.cfg.chain.chain_id,
        ))
        .await
        .expect("restore authoritative pending-output status corpus");
    let revision = *corpus.committed_revision_rx().borrow();
    let fence =
        seed_migration_public_rows(&plane, &current, "ppoi_3x3.json", U256::from(1), false).await;
    let mut restarted = test_wallet_handle(
        <DbStore as WalletCacheStore>::load_wallet_utxos(reopened.as_ref(), &group.cfg.cache_key)
            .expect("restart from durable spent history"),
    );
    restarted.cache_key = current.cfg.cache_key.clone();
    let restart_cancel = CancellationToken::new();
    let outcome = apply_owned_poi_private_delta_on_actor(
        &restarted,
        &restart_cancel,
        0,
        reopened.as_ref(),
        reopened.as_ref(),
        &current.cfg,
        OwnedPoiPrivateDelta::SenderCandidateMaterialization {
            expected_candidate: current.candidate.clone(),
            public_data_fence: fence,
            active_list_keys: vec![current.list_key],
            pending_updates: current.pending.clone(),
            recovery_updates: current.recoveries.clone(),
            owned_substitutes: Vec::new(),
            proof_outputs: current
                .outputs
                .iter()
                .map(|output| output.poi.blinded_commitment)
                .collect(),
            expected_corpus: ExpectedPoiCorpusRevision {
                corpus: corpus.clone(),
                revision,
            },
            replacement_group: vec![(group.pending[0].clone(), Some(group.recoveries[0].clone()))],
            external_valid_substitutes: Vec::new(),
        },
    )
    .await
    .expect("materialize after restart");
    assert_eq!(
        outcome,
        PoiPrivateApplyOutcome::Applied {
            utxo_changed: false
        }
    );
    let restart_authority = WalletPrivateMutationAuthority::new(&restarted, 0, &restart_cancel);
    let transport = Arc::new(MigrationProofTransport::default());
    let private_poi = WalletPrivatePoiClients::for_submit(
        restart_authority.remote_authority(),
        transport.clone(),
    );
    assert_eq!(
        process_pending_output_poi_observations_authorized(
            &restart_authority,
            &plane,
            reopened.as_ref(),
            reopened.as_ref(),
            &current.cfg,
            &[current.list_key],
            Some(&private_poi),
            false
        )
        .await,
        1
    );
    assert_eq!(
        transport
            .proofs
            .lock()
            .expect("read current submissions")
            .len(),
        1
    );
    assert!(
        migration_wallet_payloads(&restarted.utxos.read().await) == baseline,
        "submission must preserve the complete restarted actor snapshot"
    );
    assert_eq!(
        rmp_serde::to_vec(
            &<DbStore as WalletCacheStore>::get_wallet_meta(
                reopened.as_ref(),
                &current.cfg.cache_key
            )
            .expect("checkpoint after submission")
        )
        .expect("encode checkpoint"),
        rmp_serde::to_vec(&meta).expect("encode baseline checkpoint")
    );
    drop(private_poi);
    drop(corpus);
    drop(plane);
    drop(reopened);
    fs::remove_dir_all(root).expect("remove temp db");
}

#[tokio::test]
async fn unresolved_group_replacement_is_atomic_and_rejects_stale_evidence() {
    for stale in ["group", "corpus", "epoch", "lifecycle", "none"] {
        let root = temp_db_root();
        let store = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root.clone(),
            })
            .expect("open db"),
        );
        let current = migration_group("ppoi_3x3_two_outputs.json", "atomic-migration");
        let mut old = migration_group("ppoi_3x3_two_outputs_previous.json", "atomic-migration");
        for recovery in &mut old.recoveries {
            recovery.status = OutputPoiRecoveryStatus::Submitted;
            recovery.last_submission_at = Some(5);
            recovery.next_retry_at = Some(u64::MAX);
            recovery.attempt_count = 2;
        }
        for context in &mut old.pending {
            context.submitted_poi_list_keys.push(old.list_key);
        }
        seed_migration_group(&store, &old);
        seed_migration_candidate(&store, &current);
        let expected = old
            .pending
            .iter()
            .cloned()
            .zip(old.recoveries.iter().cloned().map(Some))
            .collect::<Vec<_>>();
        let (plane, fence) = sender_candidate_public_data_fence(
            &store,
            &current.cfg,
            &current.candidate,
            &current.input,
            current.outputs[0].poi.commitment,
            current.candidate.source.block_timestamp,
        )
        .await;
        let corpus = current_poi_corpus_revision();
        let mut handle = test_wallet_handle(vec![current.input.clone()]);
        handle.cache_key = current.cfg.cache_key.clone();
        let cancel = CancellationToken::new();
        match stale {
            "group" => {
                let mut changed = old.pending[1].clone();
                changed.submitted_poi_list_keys.push(old.list_key);
                store
                    .put_pending_output_poi_context(&changed)
                    .expect("advance one sibling");
            }
            "corpus" => {
                corpus
                    .corpus
                    .local_caches()
                    .publish_committed_revision(false);
            }
            "epoch" => {
                plane
                    .reset_public_cache()
                    .await
                    .expect("advance public epoch");
            }
            "lifecycle" => {
                cancel.cancel();
            }
            _ => {}
        }
        let before = store
            .list_pending_output_poi_contexts(current.cfg.chain.chain_id, &current.cfg.cache_key)
            .expect("snapshot all predecessors");
        let recoveries_before = old
            .pending
            .iter()
            .map(|context| {
                store
                    .get_output_poi_recovery(
                        current.cfg.chain.chain_id,
                        &current.cfg.cache_key,
                        &context.output_commitment,
                    )
                    .expect("snapshot recovery predecessor")
            })
            .collect::<Vec<_>>();
        let outcome = apply_owned_poi_private_delta_on_actor(
            &handle,
            &cancel,
            0,
            store.as_ref(),
            store.as_ref(),
            &current.cfg,
            OwnedPoiPrivateDelta::SenderCandidateMaterialization {
                expected_candidate: current.candidate.clone(),
                public_data_fence: fence,
                active_list_keys: vec![current.list_key],
                pending_updates: current.pending.clone(),
                recovery_updates: current.recoveries.clone(),
                owned_substitutes: Vec::new(),
                proof_outputs: current
                    .outputs
                    .iter()
                    .map(|output| output.poi.blinded_commitment)
                    .collect(),
                expected_corpus: corpus,
                replacement_group: expected,
                external_valid_substitutes: Vec::new(),
            },
        )
        .await;
        if stale == "none" {
            assert!(
                matches!(
                    outcome,
                    Ok(PoiPrivateApplyOutcome::Applied {
                        utxo_changed: false
                    })
                ),
                "{outcome:?}"
            );
            for context in &current.pending {
                let saved = store
                    .get_pending_output_poi_context(
                        current.cfg.chain.chain_id,
                        &current.cfg.cache_key,
                        &context.output_commitment,
                    )
                    .expect("read replacement")
                    .expect("replacement present");
                assert_eq!(
                    rmp_serde::to_vec(&saved).expect("encode saved"),
                    rmp_serde::to_vec(context).expect("encode replacement")
                );
                assert!(saved_pending_context_is_compatible(
                    &saved,
                    &[current.list_key]
                ));
                let recovery = store
                    .get_output_poi_recovery(
                        current.cfg.chain.chain_id,
                        &current.cfg.cache_key,
                        &context.output_commitment,
                    )
                    .expect("read replaced recovery")
                    .expect("replacement recovery present");
                assert_eq!(recovery.status, OutputPoiRecoveryStatus::Recoverable);
                assert!(recovery.last_submission_at.is_none());
                assert!(recovery.next_retry_at.is_none());
                assert_eq!(recovery.attempt_count, 0);
            }
            assert!(
                <DbStore as WalletCacheStore>::list_sender_transaction_candidates(
                    store.as_ref(),
                    current.cfg.chain.chain_id,
                    &current.cfg.cache_key
                )
                .expect("consumed candidate")
                .is_empty()
            );
        } else {
            assert!(
                !matches!(outcome, Ok(PoiPrivateApplyOutcome::Applied { .. })),
                "{stale}: {outcome:?}"
            );
            assert_eq!(
                rmp_serde::to_vec(
                    &store
                        .list_pending_output_poi_contexts(
                            current.cfg.chain.chain_id,
                            &current.cfg.cache_key
                        )
                        .expect("read unchanged group")
                )
                .expect("encode current group"),
                rmp_serde::to_vec(&before).expect("encode predecessors"),
                "{stale}"
            );
            let recoveries_after = old
                .pending
                .iter()
                .map(|context| {
                    store
                        .get_output_poi_recovery(
                            current.cfg.chain.chain_id,
                            &current.cfg.cache_key,
                            &context.output_commitment,
                        )
                        .expect("read unchanged recovery predecessor")
                })
                .collect::<Vec<_>>();
            assert_eq!(
                rmp_serde::to_vec(&recoveries_after).expect("encode unchanged recoveries"),
                rmp_serde::to_vec(&recoveries_before).expect("encode predecessor recoveries"),
                "{stale}"
            );
            assert_eq!(
                <DbStore as WalletCacheStore>::list_sender_transaction_candidates(
                    store.as_ref(),
                    current.cfg.chain.chain_id,
                    &current.cfg.cache_key
                )
                .expect("candidate retained for retry")
                .len(),
                1,
                "{stale}"
            );
        }
        assert_eq!(
            handle.utxos.read().await.len(),
            1,
            "external outputs must not enter balances"
        );
        drop(plane);
        drop(store);
        fs::remove_dir_all(root).expect("remove temp db");
    }
}

#[tokio::test]
async fn external_siblings_keep_only_unresolved_output_and_list_targets() {
    for heterogeneous_lists in [false, true] {
        let root = temp_db_root();
        let store = Arc::new(
            DbStore::open(DbConfig {
                root_dir: root.clone(),
            })
            .expect("open db"),
        );
        let mut current = migration_group("ppoi_3x3_two_outputs.json", "mixed-valid-pending");
        let mut old = migration_group("ppoi_3x3_two_outputs_previous.json", "mixed-valid-pending");
        let second_list = FixedBytes::from([0x64; 32]);
        let lists = if heterogeneous_lists {
            vec![current.list_key, second_list]
        } else {
            vec![current.list_key]
        };
        let pending_count = if heterogeneous_lists { 2 } else { 1 };
        if heterogeneous_lists {
            for group in [&mut old, &mut current] {
                for context in &mut group.pending {
                    context.required_poi_list_keys = lists.clone();
                    let proof = context.pre_transaction_pois_per_txid_leaf_per_list
                        [&group.list_key]
                        .clone();
                    context
                        .pre_transaction_pois_per_txid_leaf_per_list
                        .insert(second_list, proof);
                }
            }
            current.pending[0].required_poi_list_keys = vec![second_list];
            current.pending[1].required_poi_list_keys = vec![current.list_key];
            for context in &mut current.pending {
                context
                    .pre_transaction_pois_per_txid_leaf_per_list
                    .retain(|list_key, _| context.required_poi_list_keys.contains(list_key));
            }
        }
        // With one list the second output was fully retired. With two lists each output
        // remains unresolved on a different list while the whole transaction stays the witness.
        for index in 0..pending_count {
            store
                .put_pending_output_poi_context(&old.pending[index])
                .expect("persist unresolved output");
            store
                .put_output_poi_recovery(&old.recoveries[index])
                .expect("persist unresolved recovery");
        }
        seed_migration_candidate(&store, &current);
        let plane = test_public_data_plane_with_poi_service(&store);
        let fence = seed_migration_public_rows(
            &plane,
            &current,
            "ppoi_3x3_two_outputs.json",
            U256::from(1),
            false,
        )
        .await;
        for list_key in &lists {
            let valid_index = usize::from(!(heterogeneous_lists && *list_key == current.list_key));
            let mut cache = PoiCache::new(PoiCacheIdentity::new(
                EVM_CHAIN_TYPE,
                current.cfg.chain.chain_id,
                DEFAULT_TXID_VERSION,
                *list_key,
            ));
            cache
                .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
                    event_index: 0,
                    blinded_commitment: current.outputs[valid_index].poi.blinded_commitment.0,
                    signature: [0; 64],
                    event_type: PoiEventType::Transact,
                }])
                .expect("retain authoritative accepted sibling status");
            cache.accept_current_roots();
            seed_data_plane_poi_cache(&plane, current.cfg.chain.chain_id, *list_key, cache).await;
        }
        let corpus = plane
            .ensure_poi_corpus(PublicPoiCorpusKey::wallet_default(
                current.cfg.chain.chain_id,
            ))
            .await
            .expect("local status corpus");
        let revision = *corpus.committed_revision_rx().borrow();
        let expected_group = old.pending[..pending_count]
            .iter()
            .cloned()
            .zip(old.recoveries[..pending_count].iter().cloned().map(Some))
            .collect::<Vec<_>>();
        let delta = |pending_updates| OwnedPoiPrivateDelta::SenderCandidateMaterialization {
            expected_candidate: current.candidate.clone(),
            public_data_fence: fence.clone(),
            active_list_keys: lists.clone(),
            pending_updates,
            recovery_updates: current.recoveries[..pending_count].to_vec(),
            owned_substitutes: Vec::new(),
            proof_outputs: current
                .outputs
                .iter()
                .map(|output| output.poi.blinded_commitment)
                .collect(),
            expected_corpus: ExpectedPoiCorpusRevision {
                corpus: corpus.clone(),
                revision,
            },
            replacement_group: expected_group.clone(),
            external_valid_substitutes: if heterogeneous_lists {
                Vec::new()
            } else {
                vec![current.outputs[1].clone()]
            },
        };
        let mut handle = test_wallet_handle(vec![current.input.clone()]);
        handle.cache_key = current.cfg.cache_key.clone();
        let cancel = CancellationToken::new();
        if heterogeneous_lists {
            let mut invalid_targets = current.pending.clone();
            invalid_targets[0].required_poi_list_keys = lists.clone();
            let accepted_list_proof = current.pending[1]
                .pre_transaction_pois_per_txid_leaf_per_list[&current.list_key]
                .clone();
            invalid_targets[0]
                .pre_transaction_pois_per_txid_leaf_per_list
                .insert(current.list_key, accepted_list_proof);
            assert_eq!(
                apply_owned_poi_private_delta_on_actor(
                    &handle,
                    &cancel,
                    0,
                    store.as_ref(),
                    store.as_ref(),
                    &current.cfg,
                    delta(invalid_targets)
                )
                .await
                .expect("reject a target that resurrects an accepted list"),
                PoiPrivateApplyOutcome::Skipped
            );
            let unchanged = store
                .list_pending_output_poi_contexts(
                    current.cfg.chain.chain_id,
                    &current.cfg.cache_key,
                )
                .expect("read rejected replacement");
            for context in &old.pending {
                let restored = unchanged
                    .iter()
                    .find(|saved| saved.output_commitment == context.output_commitment)
                    .expect("old sibling retained");
                assert!(
                    rmp_serde::to_vec(restored).expect("encode retained sibling")
                        == rmp_serde::to_vec(context).expect("encode predecessor"),
                    "an invalid list target must prevent the whole group replacement"
                );
            }
        }
        assert_eq!(
            apply_owned_poi_private_delta_on_actor(
                &handle,
                &cancel,
                0,
                store.as_ref(),
                store.as_ref(),
                &current.cfg,
                delta(current.pending[..pending_count].to_vec())
            )
            .await
            .expect("commit unresolved targets"),
            PoiPrivateApplyOutcome::Applied {
                utxo_changed: false
            }
        );
        let pending = store
            .list_pending_output_poi_contexts(current.cfg.chain.chain_id, &current.cfg.cache_key)
            .expect("list migrated pending work");
        assert_eq!(pending.len(), pending_count);
        for context in &pending {
            let expected = current
                .pending
                .iter()
                .find(|expected| expected.output_commitment == context.output_commitment)
                .expect("known output");
            assert_eq!(
                context.required_poi_list_keys,
                expected.required_poi_list_keys
            );
            assert_eq!(
                context
                    .pre_transaction_pois_per_txid_leaf_per_list
                    .keys()
                    .copied()
                    .collect::<Vec<_>>(),
                context.required_poi_list_keys,
                "replacement must persist only unresolved proof-map entries"
            );
            assert!(saved_pending_context_is_compatible(
                context,
                &context.required_poi_list_keys
            ));
        }
        if !heterogeneous_lists {
            assert!(
                store
                    .get_output_poi_recovery(
                        current.cfg.chain.chain_id,
                        &current.cfg.cache_key,
                        &current.outputs[1].poi.commitment
                    )
                    .expect("accepted sibling remains retired")
                    .is_none()
            );
        }
        let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
        let transport = Arc::new(MigrationProofTransport::default());
        let private_poi =
            WalletPrivatePoiClients::for_submit(authority.remote_authority(), transport.clone());
        assert_eq!(
            process_pending_output_poi_observations_authorized(
                &authority,
                &plane,
                store.as_ref(),
                store.as_ref(),
                &current.cfg,
                &lists,
                Some(&private_poi),
                false
            )
            .await,
            pending_count
        );
        assert_eq!(
            *transport
                .list_keys
                .lock()
                .expect("submitted unresolved list union"),
            lists
        );
        assert_eq!(handle.utxos.read().await.len(), 1);
        assert!(
            <DbStore as WalletCacheStore>::list_sender_transaction_candidates(
                store.as_ref(),
                current.cfg.chain.chain_id,
                &current.cfg.cache_key
            )
            .expect("consume mixed candidate")
            .is_empty()
        );
        drop(private_poi);
        drop(corpus);
        drop(plane);
        drop(store);
        fs::remove_dir_all(root).expect("remove temp db");
    }
}

#[tokio::test]
#[ignore = "requires explicitly provisioned current PPOI artifacts in PPOI_ARTIFACT_CACHE"]
async fn exact_spend_recovery_regenerates_previous_external_proof_and_submits_current_proof() {
    let cache =
        PathBuf::from(std::env::var_os("PPOI_ARTIFACT_CACHE").expect("set PPOI_ARTIFACT_CACHE"));
    let artifacts = ArtifactSource::new(Vec::new(), cache);
    let paths = artifacts.artifact_paths("POI_3x3");
    assert!(
        paths.zkey.is_file() && paths.wasm.is_file(),
        "provision both current 3x3 artifacts"
    );
    let root = temp_db_root();
    let store = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root.clone(),
        })
        .expect("open db"),
    );
    let mut group = migration_group(
        "ppoi_3x3_external_previous.json",
        "real-external-proof-migration",
    );
    group.pending[0].output_role = PendingOutputPoiRole::Recipient;
    group.recoveries[0].apply_action(
        OutputPoiRecoveryAction::SubmitFailed {
            error: "temporary POI transport failure".into(),
            retry_after: Duration::from_secs(60),
        },
        10,
    );
    let pending_list = FixedBytes::from([0x64; 32]);
    let newly_active_list = FixedBytes::from([0x65; 32]);
    let remaining_lists = [pending_list, newly_active_list];
    let lists = [group.list_key, pending_list, newly_active_list];
    group.pending[0].required_poi_list_keys = vec![group.list_key, pending_list];
    let old_material =
        group.pending[0].pre_transaction_pois_per_txid_leaf_per_list[&group.list_key].clone();
    group.pending[0]
        .pre_transaction_pois_per_txid_leaf_per_list
        .insert(pending_list, old_material);
    assert_ne!(
        group.outputs[0].note.npk,
        Note::npk_for(
            group.cfg.scan_keys.master_public_key,
            group.outputs[0].note.random
        ),
        "the exact-spend recipient must be external to the sender"
    );
    assert_eq!(group.input.utxo.note.value, group.outputs[0].note.value);
    assert_eq!(
        group
            .input
            .utxo
            .nullifier(group.cfg.scan_keys.nullifying_key),
        migration_proof("ppoi_3x3_external_previous.json")
            .public_context
            .nullifiers[0]
    );
    group
        .input
        .utxo
        .poi
        .statuses
        .insert(group.list_key, PoiStatus::Valid);
    group
        .input
        .utxo
        .poi
        .statuses
        .insert(pending_list, PoiStatus::Valid);
    group
        .input
        .utxo
        .poi
        .statuses
        .insert(newly_active_list, PoiStatus::Valid);
    group.cfg.poi_recovery_prover = Some(ProverService::with_capacity_db(&artifacts, 1, None));
    seed_migration_group(&store, &group);
    let mut handle = test_wallet_handle(vec![group.input.clone()]);
    handle.cache_key = group.cfg.cache_key.clone();
    let cancel = CancellationToken::new();
    let authority = WalletPrivateMutationAuthority::new(&handle, 0, &cancel);
    let permit = authority.acquire().await.expect("wallet authority");
    WalletPersistState::default()
        .persist_progress_with_private_effects(
            store.as_ref(),
            &permit,
            WalletProgressPersist {
                cache_key: group.cfg.cache_key.as_str(),
                snapshot: std::slice::from_ref(&group.input),
                last_scanned: 900,
                checkpoint: WalletCheckpointMutation::Set {
                    last_scanned_block: 900,
                    last_scanned_block_hash: Some([0x90; 32]),
                },
                changed: true,
            },
            WalletProgressPrivateEffects::default(),
        )
        .expect("persist consumed exact-spend input");
    drop(permit);
    let baseline = migration_wallet_payloads(std::slice::from_ref(&group.input));
    let checkpoint = store
        .get_wallet_meta(&group.cfg.cache_key)
        .expect("baseline checkpoint");
    let plane = test_public_data_plane_with_poi_service(&store);
    let mut forest = MerkleForest::new();
    forest
        .insert_leaf(MerkleTreeUpdate {
            tree_number: group.input.utxo.tree,
            tree_position: group.input.utxo.position,
            hash: group.input.utxo.note.commitment(),
        })
        .expect("seed actual input merkle leaf");
    let merkle_root = forest
        .prove_with_leaf_count(group.input.utxo.tree, group.input.utxo.position, 1)
        .expect("actual input proof")
        .root;
    seed_migration_public_rows(
        &plane,
        &group,
        "ppoi_3x3_external_previous.json",
        merkle_root,
        false,
    )
    .await;
    seed_migration_source_block(&plane, &group, 43).await;
    seed_migration_partial_list_status(&plane, &group, &remaining_lists).await;
    let poi_mock = spawn_poi_rpc_sequence(vec![serde_json::json!(true)]).await;
    let poi_client = PoiRpcClient::new(poi_mock.url);
    let txid_key = DataPlanePublicTxidCacheKey::new(
        ChainScope {
            chain_type: ChainType::Evm,
            chain_id: group.cfg.chain.chain_id,
            railgun_contract: group.cfg.chain.contract,
        },
        DEFAULT_TXID_VERSION,
    );
    let checkpoints = plane
        .txid_public_checkpoint_candidates(&txid_key, 0)
        .await
        .expect("compute public TXID checkpoint awaiting POI acceptance");
    assert_eq!(
        checkpoints.len(),
        1,
        "the seeded transaction needs one authenticated checkpoint"
    );
    for checkpoint in checkpoints {
        assert!(
            poi_client
                .validate_txid_merkleroot(
                    DEFAULT_TXID_VERSION,
                    EVM_CHAIN_TYPE,
                    group.cfg.chain.chain_id,
                    checkpoint.tree,
                    checkpoint.index,
                    &checkpoint.merkleroot
                )
                .await
                .expect("validate computed TXID root through the configured POI client")
        );
        plane
            .commit_txid_public_checkpoint(&txid_key, checkpoint)
            .await
            .expect("persist the accepted TXID checkpoint");
    }
    let runtime = test_artifact_poi_runtime();
    let transport = Arc::new(MigrationProofTransport::default());
    let private_poi =
        WalletPrivatePoiClients::for_submit(authority.remote_authority(), transport.clone());
    assert_eq!(
        process_pending_output_poi_observations_authorized(
            &authority,
            &plane,
            store.as_ref(),
            store.as_ref(),
            &group.cfg,
            &lists,
            Some(&private_poi),
            true
        )
        .await,
        0
    );
    assert!(transport.proofs.lock().expect("no stale sends").is_empty());
    assert!(
        <DbStore as WalletCacheStore>::list_sender_transaction_candidates(
            store.as_ref(),
            group.cfg.chain.chain_id,
            &group.cfg.cache_key
        )
        .expect("sender candidate was already consumed")
        .is_empty()
    );
    let forest = Arc::new(RwLock::new(forest));
    let outcome = (OutputPoiRecoveryRun {
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
        client: &poi_client,
        private_poi: &private_poi,
        active_list_keys: &lists,
        force_retry: false,
    })
    .recover_missing()
    .await;
    assert!(
        outcome.error.is_none(),
        "maintenance must complete without error"
    );
    let report = outcome.candidate_report;
    assert_eq!(
        report.materialized,
        1,
        "the actual prover must replace the obsolete external proof: awaiting_txid={}, awaiting_poi={}, retrying={}, needs_attention={}, covered={}, stale_corpus={}, retired_valid={}",
        report.awaiting_public_txid_data,
        report.awaiting_poi_data,
        report.retrying,
        report.needs_attention,
        report.covered_by_pending_contexts,
        report.stale_revision_skips,
        report.retired_locally_valid
    );
    assert!(
        transport
            .proofs
            .lock()
            .expect("replacement precedes submission")
            .is_empty()
    );
    let pending = store
        .get_pending_output_poi_context(
            group.cfg.chain.chain_id,
            &group.cfg.cache_key,
            &group.outputs[0].poi.commitment,
        )
        .expect("load regenerated pending proof")
        .expect("external output remains pending");
    assert_eq!(
        pending.required_poi_list_keys, remaining_lists,
        "regeneration must retire the already-valid list and include the newly-active missing list"
    );
    assert_eq!(
        pending
            .pre_transaction_pois_per_txid_leaf_per_list
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        remaining_lists,
        "the constructor must retain proof-map entries only for unresolved lists"
    );
    assert!(saved_pending_context_is_compatible(
        &pending,
        &pending.required_poi_list_keys
    ));
    assert_ne!(
        rmp_serde::to_vec(&pending.pre_transaction_pois_per_txid_leaf_per_list)
            .expect("new proof material"),
        rmp_serde::to_vec(&group.pending[0].pre_transaction_pois_per_txid_leaf_per_list)
            .expect("old proof material")
    );
    assert!(
        <DbStore as WalletCacheStore>::list_sender_transaction_candidates(
            store.as_ref(),
            group.cfg.chain.chain_id,
            &group.cfg.cache_key
        )
        .expect("candidate consumed only after durable replacement")
        .is_empty()
    );
    assert_eq!(
        process_pending_output_poi_observations_authorized(
            &authority,
            &plane,
            store.as_ref(),
            store.as_ref(),
            &group.cfg,
            &lists,
            Some(&private_poi),
            false
        )
        .await,
        1
    );
    assert_eq!(
        transport
            .proofs
            .lock()
            .expect("current proofs submitted to remaining lists")
            .len(),
        2
    );
    assert_eq!(
        *transport.list_keys.lock().expect("read submission lists"),
        remaining_lists
    );
    assert_eq!(
        process_pending_output_poi_observations_authorized(
            &authority,
            &plane,
            store.as_ref(),
            store.as_ref(),
            &group.cfg,
            &lists,
            Some(&private_poi),
            true
        )
        .await,
        1,
        "force retry must keep accepted lists retired"
    );
    assert_eq!(
        *transport.list_keys.lock().expect("read force retry lists"),
        remaining_lists.repeat(2)
    );
    assert!(
        migration_wallet_payloads(&handle.utxos.read().await) == baseline,
        "real proof regeneration must preserve the complete actor snapshot"
    );
    assert!(
        migration_wallet_payloads(
            &<DbStore as WalletCacheStore>::load_wallet_utxos(store.as_ref(), &group.cfg.cache_key)
                .expect("durable balance remains spent input only")
        ) == baseline,
        "real proof regeneration must preserve the complete persisted wallet history"
    );
    assert_eq!(
        rmp_serde::to_vec(
            &store
                .get_wallet_meta(&group.cfg.cache_key)
                .expect("checkpoint after real proving")
        )
        .expect("encode checkpoint"),
        rmp_serde::to_vec(&checkpoint).expect("encode baseline checkpoint")
    );
    let recovery = store
        .get_output_poi_recovery(
            group.cfg.chain.chain_id,
            &group.cfg.cache_key,
            &group.outputs[0].poi.commitment,
        )
        .expect("load successful recovery")
        .expect("recovery present");
    assert_eq!(recovery.status, OutputPoiRecoveryStatus::Submitted);
    cancel.cancel();
    drop(private_poi);
    plane.shutdown().await;
    drop(plane);
    drop(store);
    let reopened = Arc::new(
        DbStore::open(DbConfig {
            root_dir: root.clone(),
        })
        .expect("restart after partial-list submission"),
    );
    let plane = test_public_data_plane_with_poi_service(&reopened);
    seed_migration_public_rows(
        &plane,
        &group,
        "ppoi_3x3_external_previous.json",
        merkle_root,
        false,
    )
    .await;
    seed_migration_partial_list_status(&plane, &group, &remaining_lists).await;
    let mut restarted = test_wallet_handle(
        <DbStore as WalletCacheStore>::load_wallet_utxos(reopened.as_ref(), &group.cfg.cache_key)
            .expect("restart exact-spend history"),
    );
    restarted.cache_key = group.cfg.cache_key.clone();
    let restart_cancel = CancellationToken::new();
    let restart_authority = WalletPrivateMutationAuthority::new(&restarted, 0, &restart_cancel);
    let private_poi = WalletPrivatePoiClients::for_submit(
        restart_authority.remote_authority(),
        transport.clone(),
    );
    assert_eq!(
        process_pending_output_poi_observations_authorized(
            &restart_authority,
            &plane,
            reopened.as_ref(),
            reopened.as_ref(),
            &group.cfg,
            &lists,
            Some(&private_poi),
            true
        )
        .await,
        1,
        "restart retry must use the persisted remaining-list target"
    );
    assert_eq!(
        *transport
            .list_keys
            .lock()
            .expect("read restart retry lists"),
        remaining_lists.repeat(3)
    );
    let restored = reopened
        .get_pending_output_poi_context(
            group.cfg.chain.chain_id,
            &group.cfg.cache_key,
            &group.outputs[0].poi.commitment,
        )
        .expect("read restored remaining-list context")
        .expect("pending output remains retryable");
    assert_eq!(restored.required_poi_list_keys, remaining_lists);
    assert!(
        migration_wallet_payloads(&restarted.utxos.read().await) == baseline,
        "restart retry must preserve the complete spent history"
    );
    restart_cancel.cancel();
    drop(private_poi);
    plane.shutdown().await;
    drop(plane);
    drop(reopened);
    fs::remove_dir_all(root).expect("remove temp db");
}
