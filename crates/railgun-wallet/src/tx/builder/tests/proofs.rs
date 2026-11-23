use super::*;

#[test]
fn input_witness_cache_uses_sparse_proofs_for_small_forests() {
    let wallet = test_wallet();
    let token = Address::from([0x58; 20]);
    let utxos = vec![
        wallet_test_utxo(&wallet, token, 4, 0, 0),
        wallet_test_utxo(&wallet, token, 6, 0, 1),
    ];
    let forest = forest_for_utxos(&utxos);
    let expected_root = forest.roots()[&0];
    let mut cache = InputWitnessProofCache::new(&forest);

    let proof = cache.prove(0, 0).expect("sparse proof");

    assert_eq!(proof.root, expected_root);
    assert_eq!(cache.stats().proof_count, 1);
    assert_eq!(cache.stats().dense_tree_build_count, 0);
}

fn dummy_merkle_proof(leaf: U256, leaf_index: u64) -> MerkleProof {
    MerkleProof {
        root: U256::ZERO,
        leaf,
        leaf_index,
        path_elements: [U256::ZERO; TREE_DEPTH],
        path_indices: [0u8; TREE_DEPTH],
    }
}

fn sample_chunk(
    seed: u8,
    input_count: usize,
    private_output_count: usize,
    has_unshield: bool,
) -> TransactionPlanChunk {
    let token = Address::from([seed; 20]);
    let inputs = (0..input_count)
        .map(|index| {
            let utxo = test_utxo(
                token,
                u64::try_from(index + 1).unwrap(),
                seed.into(),
                index as u64,
            );
            InputWitness {
                merkle_proof: dummy_merkle_proof(utxo.note.commitment(), index as u64),
                utxo,
            }
        })
        .collect::<Vec<_>>();
    let mut outputs = (0..private_output_count)
        .map(|index| {
            Note::new_change(
                U256::from(1_000_u64 + u64::from(seed) + index as u64),
                token,
                U256::from(10_u64 + index as u64),
                [seed.saturating_add(index as u8); 16],
            )
        })
        .collect::<Vec<_>>();
    if has_unshield {
        outputs.push(Note::new_unshield(
            Address::from([seed.saturating_add(1); 20]),
            token,
            uint!(5_U256),
        ));
    }

    let public_inputs = PublicInputs {
        merkle_root: uint!(7_U256),
        bound_params_hash: U256::from(2_000_u64 + u64::from(seed)),
        nullifiers: (0..input_count)
            .map(|index| U256::from(3_000_u64 + u64::from(seed) + index as u64))
            .collect(),
        commitments_out: outputs.iter().map(Note::commitment).collect(),
    };
    let private_inputs = PrivateInputs {
        token_address: U256::from_be_slice(token.as_slice()),
        random_in: inputs
            .iter()
            .map(|input| U256::from_be_slice(&input.utxo.note.random))
            .collect(),
        value_in: inputs.iter().map(|input| input.utxo.note.value).collect(),
        path_elements: vec![U256::ZERO; input_count * TREE_DEPTH],
        leaves_indices: inputs
            .iter()
            .map(|input| U256::from(input.utxo.position))
            .collect(),
        value_out: outputs.iter().map(|note| note.value).collect(),
        public_key: [uint!(11_U256), uint!(12_U256)],
        npk_out: outputs.iter().map(|note| note.npk).collect(),
        nullifying_key: uint!(13_U256),
    };

    TransactionPlanChunk {
        tree_number: seed.into(),
        merkle_root: uint!(7_U256),
        inputs,
        outputs,
        has_unshield,
        public_inputs,
        private_inputs,
        signature: [uint!(1_U256), uint!(2_U256), uint!(3_U256)],
    }
}

fn sample_poi_merkle_proofs(blinded_commitments: &[FixedBytes<32>]) -> Vec<PoiMerkleProof> {
    blinded_commitments
        .iter()
        .enumerate()
        .map(|(index, blinded_commitment)| PoiMerkleProof {
            leaf: U256::from_be_bytes(blinded_commitment.0),
            elements: (0..TREE_DEPTH)
                .map(|level| U256::from(u64::try_from(index + level + 1).expect("proof level")))
                .collect(),
            indices: U256::from(u64::try_from(index).expect("proof index")),
            root: U256::from(u64::try_from(100 + index).expect("proof root")),
        })
        .collect()
}

fn sample_pre_tx_poi() -> PreTxPoi {
    PreTxPoi {
        snark_proof: SnarkJsProof::zero(),
        txid_merkleroot: FixedBytes::ZERO,
        poi_merkleroots: vec![FixedBytes::ZERO],
        blinded_commitments_out: vec![FixedBytes::ZERO],
        railgun_txid_if_has_unshield: Bytes::copy_from_slice(&[0_u8]),
    }
}

fn sample_post_txid_data(
    chunk: &TransactionPlanChunk,
    utxo_batch_global_start_position_out: U256,
) -> PostTransactionPoiData {
    let railgun_txid = compute_railgun_txid_from_public_inputs(&chunk.public_inputs);
    let txid_leaf_hash = poseidon(vec![
        railgun_txid,
        U256::from(chunk.tree_number),
        utxo_batch_global_start_position_out,
    ]);

    PostTransactionPoiData {
        txid_leaf_hash: FixedBytes::from(txid_leaf_hash.to_be_bytes::<32>()),
        txid_merkleroot: FixedBytes::from([0x77; 32]),
        txid_merkleroot_index: 123,
        txid_merkle_proof_indices: uint!(9_U256),
        txid_merkle_proof_path_elements: vec![uint!(8_U256); TREE_DEPTH],
        utxo_batch_global_start_position_out,
    }
}

#[tokio::test]
async fn pre_transaction_poi_generation_uses_configured_proof_source() {
    let chunk = sample_chunk(11, 1, 1, false);
    let source = FailingLocalPoiProofSource::default();
    let prover = ProverService::with_capacity_db(&ArtifactSource::default(), 1, None);
    let err = generate_pre_transaction_pois(PreTransactionPoiGenerationRequest {
        chunks: &[chunk],
        chain_type: 0,
        chain_id: 1,
        txid_version: Some(DEFAULT_TXID_VERSION),
        required_poi_list_keys: &[FixedBytes::from([0x11; 32])],
        proof_source: &source,
        prover: &prover,
        verify_proof: false,
    })
    .await
    .expect_err("local proof source error should fail generation");

    assert!(matches!(err, PreTransactionPoiError::ProofSource(_)));
    assert_eq!(source.calls(), 1);
}

#[tokio::test]
async fn pre_transaction_poi_generation_batches_merkle_proof_source_by_list() {
    let chunks = [sample_chunk(11, 1, 1, false), sample_chunk(12, 1, 1, false)];
    let source = FailingLocalPoiProofSource::default();
    let prover = ProverService::with_capacity_db(&ArtifactSource::default(), 1, None);
    let err = generate_pre_transaction_pois(PreTransactionPoiGenerationRequest {
        chunks: &chunks,
        chain_type: 0,
        chain_id: 1,
        txid_version: Some(DEFAULT_TXID_VERSION),
        required_poi_list_keys: &[FixedBytes::from([0x11; 32])],
        proof_source: &source,
        prover: &prover,
        verify_proof: false,
    })
    .await
    .expect_err("local proof source error should fail generation");

    assert!(matches!(err, PreTransactionPoiError::ProofSource(_)));
    assert_eq!(source.calls(), 1);
    assert_eq!(source.commitment_counts(), vec![2]);
}

#[tokio::test]
async fn post_transaction_poi_generation_uses_configured_proof_source() {
    let chunk = sample_chunk(12, 1, 1, false);
    let txid_data = sample_post_txid_data(&chunk, uint!(5_U256));
    let source = FailingLocalPoiProofSource::default();
    let prover = ProverService::with_capacity_db(&ArtifactSource::default(), 1, None);
    let err = generate_post_transaction_pois(PostTransactionPoiGenerationRequest {
        chunk: &chunk,
        txid_data: &txid_data,
        chain_type: 0,
        chain_id: 1,
        txid_version: Some(DEFAULT_TXID_VERSION),
        required_poi_list_keys: &[FixedBytes::from([0x11; 32])],
        proof_source: &source,
        prover: &prover,
        verify_proof: false,
    })
    .await
    .expect_err("local proof source error should fail generation");

    assert!(matches!(err, PreTransactionPoiError::ProofSource(_)));
    assert_eq!(source.calls(), 1);
}

#[test]
fn unproven_send_uses_proof_root_from_dirty_forest() {
    let token = Address::from([0xaa; 20]);
    let input = test_utxo(token, 10, 0, 0);
    let mut forest = MerkleForest::new();
    forest
        .insert_leaf(merkletree::tree::MerkleTreeUpdate {
            tree_number: input.tree,
            tree_position: input.position,
            hash: input.note.commitment(),
        })
        .expect("insert leaf");
    assert_eq!(forest.roots().get(&input.tree), Some(&U256::ZERO));

    let sender = sample_address_data(21);
    let recipient = sample_address_data(22).address_data();
    let outputs = build_send_outputs(
        token,
        uint!(4_U256),
        uint!(6_U256),
        &sender.address_data(),
        &recipient,
        None,
        &sender.viewing_private_key,
        NoteOutputType::Transfer,
    )
    .expect("send outputs");
    let builder = TransactionBuilder {
        chain_type: 0,
        chain_id: 1,
        railgun_contract: Address::ZERO,
    };
    let signer = MockSpendSigner {
        signed_msg: Cell::new(None),
    };
    let plan_builder = TransactionPlanBuilder::new(
        &builder,
        &sender,
        &signer,
        &forest,
        vec![input.clone()],
        token,
    )
    .expect("plan builder");

    let plan = plan_builder
        .build_unproven_send(
            &SendRequest {
                token_address: token,
                amount: uint!(4_U256),
                recipient,
                verify_proof: false,
                spend_up_to: false,
                broadcaster_fee: None,
                min_gas_price: 0,
            },
            outputs.outputs,
            outputs.commitment_ciphertext,
            None,
        )
        .expect("unproven send");
    let expected_root = forest
        .prove(input.tree, input.position)
        .expect("proof")
        .root;

    assert_ne!(expected_root, U256::ZERO);
    assert_eq!(plan.merkle_root, expected_root);
    assert_eq!(plan.inputs[0].merkle_proof.root, expected_root);
    assert_eq!(
        plan.transaction.merkleRoot,
        FixedBytes::from(expected_root.to_be_bytes::<32>())
    );
}

#[test]
fn poi_circuit_variant_selects_smallest_supported_variant() {
    assert_eq!(
        poi_circuit_variant(3, 3),
        PoiCircuitVariant {
            max_inputs: 3,
            max_outputs: 3,
        }
    );
    assert_eq!(
        poi_circuit_variant(4, 3),
        PoiCircuitVariant {
            max_inputs: 13,
            max_outputs: 13,
        }
    );
    assert_eq!(
        poi_circuit_variant(3, 4),
        PoiCircuitVariant {
            max_inputs: 13,
            max_outputs: 13,
        }
    );
}

#[test]
fn pre_transaction_poi_inputs_exclude_unshield_output_from_blinded_outputs() {
    let chunk = sample_chunk(31, 2, 2, true);

    let chunk_inputs = chunk.pre_transaction_poi_inputs().expect("chunk inputs");
    let proof_inputs = chunk_inputs
        .proof_inputs(&sample_poi_merkle_proofs(
            &chunk_inputs.blinded_commitments_in,
        ))
        .expect("proof inputs");

    assert_eq!(chunk_inputs.blinded_commitments_in.len(), 2);
    assert_eq!(chunk_inputs.blinded_commitments_out.len(), 2);
    assert_eq!(chunk_inputs.railgun_txid_if_has_unshield.len(), 32);
    assert_eq!(proof_inputs.commitments_out.len(), 3);
    assert_eq!(proof_inputs.npks_out.len(), 2);
    assert_eq!(proof_inputs.values_out.len(), 2);
    assert_ne!(proof_inputs.railgun_txid_if_has_unshield, U256::ZERO);
    assert_eq!(proof_inputs.poi_merkleroots.len(), 2);
    assert_eq!(proof_inputs.poi_in_merkle_proof_path_elements[0].len(), 16);
}

#[test]
fn pre_transaction_poi_map_shape_single_chunk_send() {
    let chunk = sample_chunk(41, 1, 1, false);
    let chunk_inputs = chunk.pre_transaction_poi_inputs().expect("chunk inputs");
    let list_key = FixedBytes::from([0x11; 32]);
    let mut map = BTreeMap::new();

    insert_pre_transaction_poi(
        &mut map,
        list_key,
        chunk_inputs.txid_leaf_hash,
        sample_pre_tx_poi(),
    );

    assert_eq!(map.len(), 1);
    assert!(
        map.get(&list_key)
            .is_some_and(|per_leaf| per_leaf.contains_key(&chunk_inputs.txid_leaf_hash))
    );
    assert_eq!(
        chunk_inputs.railgun_txid_if_has_unshield,
        Bytes::copy_from_slice(&[0_u8])
    );
}

#[test]
fn pre_transaction_poi_map_shape_multi_chunk_unshield() {
    let chunks = [sample_chunk(51, 2, 1, true), sample_chunk(52, 3, 1, true)];
    let list_keys = [FixedBytes::from([0x21; 32]), FixedBytes::from([0x22; 32])];
    let mut map = BTreeMap::new();
    let chunk_inputs = chunks
        .iter()
        .map(TransactionPlanChunk::pre_transaction_poi_inputs)
        .collect::<Result<Vec<_>, _>>()
        .expect("chunk inputs");

    for list_key in list_keys {
        for inputs in &chunk_inputs {
            insert_pre_transaction_poi(
                &mut map,
                list_key,
                inputs.txid_leaf_hash,
                sample_pre_tx_poi(),
            );
        }
    }

    assert_eq!(map.len(), 2);
    for list_key in list_keys {
        let per_leaf = map.get(&list_key).expect("list key");
        assert_eq!(per_leaf.len(), 2);
        for inputs in &chunk_inputs {
            assert!(per_leaf.contains_key(&inputs.txid_leaf_hash));
        }
    }
    assert_ne!(
        chunk_inputs[0].txid_leaf_hash,
        chunk_inputs[1].txid_leaf_hash
    );
}

#[test]
fn post_transaction_poi_inputs_use_included_txid_leaf_and_global_output_positions() {
    let chunk = sample_chunk(61, 2, 2, false);
    let output_start = uint!(65_540_U256);
    let txid_data = sample_post_txid_data(&chunk, output_start);

    let chunk_inputs = chunk
        .post_transaction_poi_inputs(&txid_data)
        .expect("chunk inputs");
    let proof_inputs = chunk_inputs
        .proof_inputs(&sample_poi_merkle_proofs(
            &chunk_inputs.blinded_commitments_in,
        ))
        .expect("proof inputs");

    assert_eq!(chunk_inputs.txid_leaf_hash, txid_data.txid_leaf_hash);
    assert_eq!(chunk_inputs.txid_merkleroot, txid_data.txid_merkleroot);
    assert_eq!(
        proof_inputs.utxo_batch_global_start_position_out,
        output_start
    );
    assert_eq!(
        proof_inputs.railgun_txid_merkle_proof_indices,
        uint!(9_U256)
    );
    assert_eq!(
        proof_inputs.railgun_txid_merkle_proof_path_elements.len(),
        16
    );
    for (index, blinded_commitment) in chunk_inputs.blinded_commitments_out.iter().enumerate() {
        let expected = poseidon(vec![
            chunk.public_inputs.commitments_out[index],
            chunk.private_inputs.npk_out[index],
            output_start + U256::from(index),
        ]);
        assert_eq!(
            *blinded_commitment,
            FixedBytes::from(expected.to_be_bytes::<32>())
        );
    }
}

#[test]
fn post_transaction_poi_zero_value_outputs_use_zero_blinded_commitment() {
    let mut chunk = sample_chunk(63, 1, 2, false);
    chunk.private_inputs.value_out[1] = U256::ZERO;
    let txid_data = sample_post_txid_data(&chunk, uint!(987_654_U256));

    let chunk_inputs = chunk
        .post_transaction_poi_inputs(&txid_data)
        .expect("chunk inputs");

    assert_ne!(chunk.public_inputs.commitments_out[1], U256::ZERO);
    assert_ne!(chunk.private_inputs.npk_out[1], U256::ZERO);
    assert_eq!(chunk_inputs.blinded_commitments_out[1], FixedBytes::ZERO);
    assert_ne!(chunk_inputs.blinded_commitments_out[0], FixedBytes::ZERO);
}

#[test]
fn post_transaction_poi_from_public_signals_uses_canonical_public_outputs() {
    let chunk = sample_chunk(62, 1, 1, false);
    let txid_data = sample_post_txid_data(&chunk, uint!(123_456_U256));
    let chunk_inputs = chunk
        .post_transaction_poi_inputs(&txid_data)
        .expect("chunk inputs");
    let proof_inputs = chunk_inputs
        .proof_inputs(&sample_poi_merkle_proofs(
            &chunk_inputs.blinded_commitments_in,
        ))
        .expect("proof inputs");
    let variant = poi_circuit_variant(
        chunk.public_inputs.nullifiers.len(),
        chunk.public_inputs.commitments_out.len(),
    );
    let mut public_signals = vec![U256::ZERO; variant.max_outputs + 2 + variant.max_inputs];
    public_signals[0] = U256::from_be_bytes(chunk_inputs.blinded_commitments_out[0].0);
    public_signals[variant.max_outputs] = U256::from_be_bytes(txid_data.txid_merkleroot.0);
    public_signals[variant.max_outputs + 1] = U256::ZERO;
    public_signals[variant.max_outputs + 2] = proof_inputs.poi_merkleroots[0];
    public_signals[variant.max_outputs + 3] = MERKLE_ZERO_VALUE;
    public_signals[variant.max_outputs + 4] = MERKLE_ZERO_VALUE;

    let poi = chunk_inputs
        .post_tx_poi_from_public_signals(
            sample_pre_tx_poi().snark_proof,
            &proof_inputs,
            &public_signals,
            variant,
        )
        .expect("post tx poi");

    assert_eq!(poi.txid_merkleroot, txid_data.txid_merkleroot);
    assert_eq!(
        poi.blinded_commitments_out,
        chunk_inputs.blinded_commitments_out
    );
    assert_eq!(poi.poi_merkleroots.len(), 1);
    assert_eq!(
        poi.poi_merkleroots[0],
        FixedBytes::from(proof_inputs.poi_merkleroots[0].to_be_bytes::<32>())
    );
    assert_eq!(
        poi.railgun_txid_if_has_unshield,
        Bytes::copy_from_slice(&[0_u8])
    );

    public_signals[variant.max_outputs + 3] = U256::ZERO;
    let err = chunk_inputs
        .post_tx_poi_from_public_signals(
            sample_pre_tx_poi().snark_proof,
            &proof_inputs,
            &public_signals,
            variant,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        PreTransactionPoiError::PublicSignalMismatch {
            field: "poiMerkleroots",
            ..
        }
    ));
}

#[test]
fn public_inputs_signature_uses_spend_signer_boundary() {
    let public_inputs = PublicInputs {
        merkle_root: uint!(1_U256),
        bound_params_hash: uint!(2_U256),
        nullifiers: vec![uint!(3_U256)],
        commitments_out: vec![uint!(4_U256)],
    };
    let signer = MockSpendSigner {
        signed_msg: Cell::new(None),
    };

    let signature = public_inputs.signature(&signer);

    assert_eq!(signature, [uint!(1_U256), uint!(2_U256), uint!(3_U256)]);
    assert_eq!(
        signer.signed_msg.get(),
        Some(poseidon(public_inputs.signature_message()))
    );
}

#[test]
fn bound_params_min_gas_price_defaults_to_zero_and_accepts_nonzero() {
    let params =
        BoundParams::new_transact(0, 0, 1, Vec::new(), Address::ZERO, UNRELAYED_ADAPT_PARAMS)
            .with_min_gas_price(0)
            .expect("zero min gas price");
    assert_eq!(params.minGasPrice, Uint::<72, 2>::ZERO);

    let params =
        BoundParams::new_transact(0, 0, 1, Vec::new(), Address::ZERO, UNRELAYED_ADAPT_PARAMS)
            .with_min_gas_price(123)
            .expect("nonzero min gas price");
    assert_eq!(params.minGasPrice, Uint::<72, 2>::from(123_u128));
}
