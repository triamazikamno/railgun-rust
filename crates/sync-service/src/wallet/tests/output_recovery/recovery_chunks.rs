use super::*;

#[tokio::test]
async fn output_poi_recovery_public_row_with_older_input_root_keeps_original_poi_inputs() {
    let spending_public_key = [uint!(4_U256), uint!(5_U256)];
    let scan_keys = ViewingKeyData::from_spending_public_key([7_u8; 32], spending_public_key);
    let mut input = test_wallet_utxo(0);
    let output = test_wallet_utxo(8);
    input.spent = Some(output.utxo.source.clone());
    // The transaction proved against the one-leaf root. Leaves 1-7 arrived before its outputs at
    // position 8, and leaves from 8 on stand in for later growth.
    let mut forest = MerkleForest::new();
    for position in 0..16 {
        forest
            .insert_leaf(MerkleTreeUpdate {
                tree_number: input.utxo.tree,
                tree_position: position,
                hash: if position == input.utxo.position {
                    input.utxo.note.commitment()
                } else {
                    U256::from(position + 12)
                },
            })
            .expect("insert input tree leaf");
    }
    let original_proof = forest
        .prove_with_leaf_count(input.utxo.tree, input.utxo.position, 1)
        .expect("original input proof");
    let forest = Arc::new(forest);
    let bound_params_hash = U256::from(0x33_u64);
    let nullifiers = vec![input.utxo.nullifier(scan_keys.nullifying_key)];
    let original_inputs = vec![InputWitness {
        utxo: input.utxo.clone(),
        merkle_proof: original_proof,
    }];
    let original_outputs = vec![output.utxo.note.clone()];
    let original_chunk = TransactionPlanChunk {
        tree_number: input.utxo.tree,
        merkle_root: original_proof.root,
        inputs: original_inputs.clone(),
        outputs: original_outputs.clone(),
        has_unshield: false,
        public_inputs: PublicInputs::from_parts(
            original_proof.root,
            bound_params_hash,
            nullifiers.clone(),
            &original_outputs,
        ),
        private_inputs: PrivateInputs::from_inputs(
            input.utxo.token_address(),
            &original_inputs,
            &original_outputs,
            &scan_keys,
            &RecoverySpendPublicKey {
                spending_public_key,
            },
        ),
        signature: [U256::ZERO; 3],
    };
    let row = PublicTxidTransaction {
        txid_index: 12,
        transaction: TxidPublicCacheTransaction {
            id: "12".to_string(),
            transaction_hash: output.utxo.source.tx_hash,
            block_number: output.utxo.source.block_number,
            block_timestamp: output.utxo.source.block_timestamp,
            nullifiers,
            commitments: vec![output.utxo.note.commitment()],
            bound_params_hash,
            has_unshield: false,
            unshield_preimage: None,
            utxo_tree_in: u64::from(input.utxo.tree),
            utxo_tree_out: u64::from(output.utxo.tree),
            utxo_batch_start_position_out: output.utxo.position,
        },
    };
    let wallet_utxos = vec![input, output.clone()];
    let wallet_nullifiers = WalletNullifierIndex::new(&wallet_utxos, &scan_keys);

    let recovered = build_output_poi_recovery_chunk_from_public_rows(
        &output,
        &wallet_nullifiers,
        &[row],
        None,
        &[],
        &forest,
        &[],
        spending_public_key,
        &scan_keys,
    )
    .await
    .expect("recover chunk without the transaction root");

    assert_ne!(recovered.chunk.merkle_root, original_chunk.merkle_root);
    let output_start_global = U256::from(recovered.output_start_global);
    let txid_data = PostTransactionPoiData {
        txid_leaf_hash: FixedBytes::from(
            railgun_txid_leaf_hash_with_output_start(
                original_chunk.railgun_txid(),
                u64::from(original_chunk.tree_number),
                output_start_global,
            )
            .to_be_bytes::<32>(),
        ),
        txid_merkleroot: FixedBytes::from([0x77; 32]),
        txid_merkleroot_index: 12,
        txid_merkle_proof_indices: U256::from(12_u64),
        txid_merkle_proof_path_elements: vec![U256::from(9_u64); TREE_DEPTH],
        utxo_batch_global_start_position_out: output_start_global,
    };
    let original_chunk_inputs = original_chunk
        .post_transaction_poi_inputs(&txid_data)
        .expect("original POI chunk inputs");
    let poi_proofs = original_chunk_inputs
        .blinded_commitments_in
        .iter()
        .map(|blinded| PoiMerkleProof {
            leaf: U256::from_be_bytes(blinded.0),
            elements: vec![U256::from(5_u64); TREE_DEPTH],
            indices: U256::ZERO,
            root: U256::from(6_u64),
        })
        .collect::<Vec<_>>();
    let poi_proof_inputs = |chunk: &TransactionPlanChunk| {
        let proof_inputs = chunk
            .post_transaction_poi_inputs(&txid_data)
            .expect("POI chunk inputs")
            .proof_inputs(&poi_proofs)
            .expect("POI proof inputs");
        // PoiProofInputs has no PartialEq; its Debug output lists every circuit input.
        format!("{proof_inputs:?}")
    };
    assert_eq!(
        poi_proof_inputs(&recovered.chunk),
        poi_proof_inputs(&original_chunk)
    );
}

#[tokio::test]
async fn output_poi_recovery_chunk_uses_cached_calldata_only_for_missing_output_notes() {
    let spending_public_key = [uint!(4_U256), uint!(5_U256)];
    let scan_keys = ViewingKeyData::from_spending_public_key([7_u8; 32], spending_public_key);
    let broadcaster_keys =
        ViewingKeyData::from_spending_public_key([8_u8; 32], [uint!(6_U256), uint!(7_U256)]);
    let sender = scan_keys.address_data();
    let broadcaster = broadcaster_keys.address_data();
    let mut input = test_wallet_utxo(0);
    let source = source(44);
    input.spent = Some(source.clone());
    let token = input.utxo.token_address();
    let fee_note = Note::new_change(
        broadcaster.master_public_key,
        token,
        U256::from(2_u8),
        [0x51; 16],
    );
    let change_note = Note::new_change(
        scan_keys.master_public_key,
        token,
        U256::from(3_u8),
        [0x52; 16],
    );
    let output = WalletUtxo::new(Utxo::new(
        change_note.clone(),
        input.utxo.tree,
        9,
        source,
        UtxoCommitmentKind::Transact,
    ));
    let fee_ciphertext = CommitmentCiphertext::from(
        NoteCiphertext::try_from_note(
            &fee_note,
            &sender,
            &broadcaster,
            &scan_keys.viewing_private_key,
            railgun_wallet::NoteOutputType::BroadcasterFee,
        )
        .expect("encrypt fee note"),
    );
    let change_ciphertext = CommitmentCiphertext::from(
        NoteCiphertext::try_from_note(
            &change_note,
            &sender,
            &sender,
            &scan_keys.viewing_private_key,
            railgun_wallet::NoteOutputType::Change,
        )
        .expect("encrypt change note"),
    );
    let unshield_note = Note::new_unshield(Address::from([0x56; 20]), token, U256::from(7_u8));

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
    let forest = Arc::new(forest);
    let transaction = Transaction {
        proof: SnarkProof::default(),
        merkleRoot: FixedBytes::from(merkle_root.to_be_bytes::<32>()),
        nullifiers: vec![FixedBytes::from(
            input
                .utxo
                .nullifier(scan_keys.nullifying_key)
                .to_be_bytes::<32>(),
        )],
        commitments: vec![
            FixedBytes::from(fee_note.commitment().to_be_bytes::<32>()),
            output.utxo.poi.commitment,
            FixedBytes::from(unshield_note.commitment().to_be_bytes::<32>()),
        ],
        boundParams: BoundParams::new_unshield(
            input.utxo.tree,
            EVM_CHAIN_TYPE,
            1,
            vec![fee_ciphertext, change_ciphertext],
            Address::ZERO,
            FixedBytes::ZERO,
        ),
        unshieldPreimage: CommitmentPreimage::new_unshield(&unshield_note, token),
    };
    let calldata = executeCall {
        _transactions: vec![transaction],
        _actionData: RelayAdapt7702ActionData {
            requireSuccess: true,
            minGasLimit: uint!(123_U256),
            calls: vec![Call {
                to: Address::from([0x99; 20]),
                data: Bytes::from(vec![0xab, 0xcd]),
                value: U256::ZERO,
            }],
        },
        _signature: Bytes::from(vec![0x12, 0x34]),
    }
    .abi_encode();
    assert_eq!(&calldata[..4], &[0xc6, 0x1e, 0x6b, 0x9d]);
    let decoded_transactions =
        decode_railgun_transactions(&calldata).expect("decode 7702 recovery calldata");
    let wallet_utxos = vec![input.clone(), output.clone()];
    let wallet_nullifiers = WalletNullifierIndex::new(&wallet_utxos, &scan_keys);

    let decoded = &decoded_transactions[0];
    let public_row = PublicTxidTransaction {
        txid_index: 5,
        transaction: TxidPublicCacheTransaction {
            id: "5".to_string(),
            transaction_hash: output.utxo.source.tx_hash,
            block_number: output.utxo.source.block_number,
            block_timestamp: output.utxo.source.block_timestamp,
            nullifiers: decoded
                .nullifiers
                .iter()
                .map(|nullifier| U256::from_be_bytes(nullifier.0))
                .collect(),
            commitments: decoded
                .commitments
                .iter()
                .map(|commitment| U256::from_be_bytes(commitment.0))
                .collect(),
            bound_params_hash: decoded.boundParams.hash(),
            has_unshield: true,
            unshield_preimage: Some(decoded.unshieldPreimage.abi_encode()),
            utxo_tree_in: u64::from(input.utxo.tree),
            utxo_tree_out: u64::from(output.utxo.tree),
            utxo_batch_start_position_out: 8,
        },
    };
    let chunk = build_output_poi_recovery_chunk_from_public_rows(
        &output,
        &wallet_nullifiers,
        &[public_row],
        None,
        &decoded_transactions,
        &forest,
        &[],
        spending_public_key,
        &scan_keys,
    )
    .await
    .expect("build unshield recovery chunk from calldata");

    assert!(chunk.chunk.has_unshield);
    assert_eq!(chunk.chunk.outputs.len(), 3);
    assert_eq!(chunk.chunk.private_output_count(), Some(2));
    assert_eq!(chunk.chunk.outputs[0].commitment(), fee_note.commitment());
    assert_eq!(chunk.chunk.outputs[0].npk, fee_note.npk);
    assert_eq!(chunk.chunk.outputs[0].value, fee_note.value);
    assert_eq!(
        chunk.chunk.outputs[1].commitment(),
        change_note.commitment()
    );
    assert_eq!(
        chunk.chunk.outputs[2].commitment(),
        unshield_note.commitment()
    );
    assert_eq!(chunk.chunk.private_inputs.npk_out[0], fee_note.npk);
    assert_eq!(chunk.chunk.private_inputs.value_out[0], fee_note.value);
    assert_eq!(
        chunk.output_start_global,
        u128::from(output.utxo.tree) * u128::from(TREE_LEAF_COUNT)
            + u128::from(output.utxo.position)
            - 1
    );
}

#[tokio::test]
async fn output_poi_recovery_chunk_uses_public_row_and_sender_candidate_without_calldata() {
    let spending_public_key = [uint!(4_U256), uint!(5_U256)];
    let scan_keys = ViewingKeyData::from_spending_public_key([7_u8; 32], spending_public_key);
    let mut input = test_wallet_utxo(0);
    let source = source(44);
    input.spent = Some(source.clone());
    let token = input.utxo.token_address();
    let fee_note = Note::new_change(U256::from(99), token, U256::from(2_u8), [0x51; 16]);
    let change_note = Note::new_change(
        scan_keys.master_public_key,
        token,
        U256::from(3_u8),
        [0x52; 16],
    );
    let output = WalletUtxo::new(Utxo::new(
        change_note.clone(),
        input.utxo.tree,
        9,
        source.clone(),
        UtxoCommitmentKind::Transact,
    ));
    let unshield_note = Note::new_unshield(Address::from([0x56; 20]), token, U256::from(7_u8));
    let unshield_preimage = CommitmentPreimage::new_unshield(&unshield_note, token);
    let mut forest = MerkleForest::new();
    forest
        .insert_leaf(MerkleTreeUpdate {
            tree_number: input.utxo.tree,
            tree_position: input.utxo.position,
            hash: input.utxo.note.commitment(),
        })
        .expect("insert input leaf");
    let forest = Arc::new(forest);
    let row = PublicTxidTransaction {
        txid_index: 12,
        transaction: TxidPublicCacheTransaction {
            id: "12".to_string(),
            transaction_hash: source.tx_hash,
            block_number: source.block_number,
            block_timestamp: source.block_timestamp,
            nullifiers: vec![input.utxo.nullifier(scan_keys.nullifying_key)],
            commitments: vec![
                fee_note.commitment(),
                change_note.commitment(),
                unshield_note.commitment(),
            ],
            bound_params_hash: U256::from(88),
            has_unshield: true,
            unshield_preimage: Some(unshield_preimage.abi_encode()),
            utxo_tree_in: u64::from(input.utxo.tree),
            utxo_tree_out: u64::from(input.utxo.tree),
            utxo_batch_start_position_out: 8,
        },
    };
    let sender_candidate = SenderTransactionCandidate::new(
        1,
        test_cache_key("public-row-output-notes"),
        source,
        vec![SenderTransactionCandidateSpend {
            tree: input.utxo.tree,
            position: input.utxo.position,
            commitment: input.utxo.poi.commitment,
        }],
        vec![
            SenderTransactionCandidateOutput {
                tree: output.utxo.tree,
                position: 8,
                commitment: FixedBytes::from(fee_note.commitment().to_be_bytes::<32>()),
                note: Some(fee_note.clone()),
            },
            SenderTransactionCandidateOutput {
                tree: output.utxo.tree,
                position: 9,
                commitment: output.utxo.poi.commitment,
                note: Some(change_note),
            },
        ],
    )
    .expect("sender candidate");
    let wallet_utxos = vec![input, output.clone()];
    let wallet_nullifiers = WalletNullifierIndex::new(&wallet_utxos, &scan_keys);

    let chunk = build_output_poi_recovery_chunk_from_public_rows(
        &output,
        &wallet_nullifiers,
        std::slice::from_ref(&row),
        Some(&sender_candidate),
        &[],
        &forest,
        &[],
        spending_public_key,
        &scan_keys,
    )
    .await
    .expect("build recovery chunk from public row");

    assert_eq!(chunk.target_txid_index, Some(12));
    assert_eq!(chunk.chunk.outputs.len(), 3);
    assert_eq!(chunk.chunk.outputs[0].commitment(), fee_note.commitment());
    assert_eq!(
        chunk.chunk.outputs[2].commitment(),
        unshield_note.commitment()
    );

    let failure = build_output_poi_recovery_chunk_from_public_rows(
        &output,
        &wallet_nullifiers,
        &[],
        Some(&sender_candidate),
        &[],
        &forest,
        &[],
        spending_public_key,
        &scan_keys,
    )
    .await
    .expect_err("missing public row must fail closed");
    assert_eq!(failure.status, OutputPoiRecoveryStatus::NotSelfOriginated);
    assert_eq!(failure.category, "public_row_not_unique_or_missing");

    let mut insufficient_row = row;
    insufficient_row.transaction.unshield_preimage = None;
    let failure = build_output_poi_recovery_chunk_from_public_rows(
        &output,
        &wallet_nullifiers,
        &[insufficient_row],
        Some(&sender_candidate),
        &[],
        &forest,
        &[],
        spending_public_key,
        &scan_keys,
    )
    .await
    .expect_err("missing selected-source unshield preimage must fail closed");
    assert_eq!(failure.status, OutputPoiRecoveryStatus::UnsupportedShape);
    assert!(failure.retry_after.is_none());
    assert_eq!(failure.category, "unshield_preimage_unavailable_or_invalid");
}

#[test]
fn output_poi_recovery_reports_missing_private_output_indexes() {
    let scan_keys =
        ViewingKeyData::from_spending_public_key([7_u8; 32], [uint!(4_U256), uint!(5_U256)]);
    let mut input = test_wallet_utxo(0);
    let output = test_wallet_utxo(8);
    let mut missing_private_output = test_wallet_utxo(9);
    missing_private_output.utxo.source = output.utxo.source.clone();
    missing_private_output.utxo.note.value = U256::from(11_u8);
    missing_private_output.utxo.poi.commitment = FixedBytes::from(
        missing_private_output
            .utxo
            .note
            .commitment()
            .to_be_bytes::<32>(),
    );
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
    let missing_commitment = missing_private_output.utxo.poi.commitment;
    let transaction = Transaction {
        proof: SnarkProof::default(),
        merkleRoot: FixedBytes::from(merkle_root.to_be_bytes::<32>()),
        nullifiers: vec![FixedBytes::from(
            input
                .utxo
                .nullifier(scan_keys.nullifying_key)
                .to_be_bytes::<32>(),
        )],
        commitments: vec![output.utxo.poi.commitment, missing_commitment],
        boundParams: BoundParams::new_transact(
            input.utxo.tree,
            EVM_CHAIN_TYPE,
            1,
            Vec::new(),
            Address::ZERO,
            FixedBytes::ZERO,
        ),
        unshieldPreimage: CommitmentPreimage::empty(),
    };
    let wallet_utxos = vec![input, output.clone()];
    let wallet_nullifiers = WalletNullifierIndex::new(&wallet_utxos, &scan_keys);

    let failure = build_output_poi_recovery_chunk(
        &output,
        &wallet_nullifiers,
        &[transaction],
        &forest,
        &[],
        [uint!(4_U256), uint!(5_U256)],
        &scan_keys,
    )
    .expect_err("missing private output should fail");

    assert_eq!(
        failure.status,
        OutputPoiRecoveryStatus::MissingWalletOutputs
    );
    assert_eq!(failure.category, "missing_wallet_outputs");
    assert!(failure.message.contains("missing_private_outputs=1/2"));
    assert!(failure.message.contains("1:"));
    assert!(failure.message.contains(&hex::encode(missing_commitment)));
}

#[tokio::test]
async fn local_output_poi_proof_preflight_fails_before_expensive_recovery_when_cache_missing() {
    let nullifying_key = uint!(9_U256);
    let cfg = wallet_config(nullifying_key);
    let list_key = FixedBytes::from([0x11; 32]);
    let mut input = test_wallet_utxo(0);
    let output = test_wallet_utxo(8);
    input.spent = Some(output.utxo.source.clone());
    let transaction = recovery_test_transaction(&input, &output, nullifying_key);
    let wallet_utxos = vec![input, output.clone()];
    let wallet_nullifiers = WalletNullifierIndex::new(&wallet_utxos, &cfg.scan_keys);
    let mut cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        cfg.chain.chain_id,
        DEFAULT_TXID_VERSION,
        list_key,
    ));
    cache.accept_current_roots();
    let local_caches = WalletLocalPoiCaches::new_for_test(BTreeMap::from([(list_key, cache)]));
    let source = LocalPoiMerkleProofSource::new(local_caches);

    let failure = preflight_local_output_poi_input_proofs(
        Some(&source),
        &cfg,
        &output,
        &wallet_utxos,
        &wallet_nullifiers,
        &[transaction],
        &[list_key],
    )
    .await
    .expect_err("missing local proof preflight should fail");

    assert_eq!(
        failure.status,
        OutputPoiRecoveryStatus::ProofGenerationFailed
    );
    assert!(failure.message.contains("missing POI cache proof data"));
    assert_eq!(
        failure.retry_after,
        Some(OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER)
    );
}

#[tokio::test]
async fn local_output_poi_proof_preflight_checks_transaction_inputs() {
    let nullifying_key = uint!(9_U256);
    let cfg = wallet_config(nullifying_key);
    let list_key = FixedBytes::from([0x11; 32]);
    let mut input = test_wallet_utxo(0);
    let output = test_wallet_utxo(8);
    input.spent = Some(output.utxo.source.clone());
    let transaction = recovery_test_transaction(&input, &output, nullifying_key);
    let wallet_utxos = vec![input.clone(), output.clone()];
    let wallet_nullifiers = WalletNullifierIndex::new(&wallet_utxos, &cfg.scan_keys);
    let mut cache = PoiCache::new(PoiCacheIdentity::new(
        EVM_CHAIN_TYPE,
        cfg.chain.chain_id,
        DEFAULT_TXID_VERSION,
        list_key,
    ));
    cache
        .apply_verified_artifact_events(&[poi::artifacts::SnapshotEvent {
            event_index: 0,
            blinded_commitment: *input.utxo.poi.blinded_commitment,
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply input POI event");
    let local_caches = WalletLocalPoiCaches::new_for_test(BTreeMap::from([(list_key, cache)]));
    let source = LocalPoiMerkleProofSource::new(local_caches);

    preflight_local_output_poi_input_proofs(
        Some(&source),
        &cfg,
        &output,
        &wallet_utxos,
        &wallet_nullifiers,
        &[transaction],
        &[list_key],
    )
    .await
    .expect("input proof preflight succeeds");
}
