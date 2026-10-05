use std::fs;
use std::path::{Path, PathBuf};

use alloy::primitives::{Address, FixedBytes, U256};
use broadcaster_core::crypto::poseidon::poseidon;
use broadcaster_core::crypto::snark_proof::Prover;
use broadcaster_core::transact::{PreTxPoi, SnarkJsProof};
use broadcaster_core::tree::TREE_DEPTH;
use merkletree::tree::MerkleProof;
use poi::poi::PoiMerkleProof;
use railgun_wallet::artifacts::{ArtifactSource, poi_variant_name};
use railgun_wallet::tx::{InputWitness, PrivateInputs, PublicInputs, TransactionPlanChunk};
use railgun_wallet::{Note, ProverService, Utxo, UtxoCommitmentKind, UtxoSource, WalletKeys};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn zero_sibling_root(leaf: U256) -> U256 {
    (0..TREE_DEPTH).fold(leaf, |node, _| poseidon(vec![node, U256::ZERO]))
}

fn synthetic_chunk(private_output_count: u8, has_unshield: bool) -> TransactionPlanChunk {
    // This fixed seed is public synthetic test data, never a funded wallet.
    let keys = WalletKeys::from_seed(&[42; 64], 0).expect("synthetic wallet keys");
    let token = Address::from([0x11; 20]);
    let input = Utxo::new(
        Note::new_change(
            keys.viewing.master_public_key,
            token,
            U256::from(100),
            [1; 16],
        ),
        0,
        0,
        UtxoSource {
            tx_hash: FixedBytes::ZERO,
            block_number: 0,
            block_timestamp: 0,
        },
        UtxoCommitmentKind::Transact,
    );
    let output_value =
        U256::from(100) / U256::from(u64::from(private_output_count) + u64::from(has_unshield));
    let mut outputs = (2..private_output_count + 2)
        .map(|random| {
            Note::new_change(
                keys.viewing.master_public_key,
                token,
                output_value,
                [random; 16],
            )
        })
        .collect::<Vec<_>>();
    if has_unshield {
        outputs.push(Note::new_unshield(
            Address::from([0x33; 20]),
            token,
            output_value,
        ));
    }
    let input_leaf = input.note.commitment();
    let merkle_root = zero_sibling_root(input_leaf);
    let public_inputs = PublicInputs::from_parts(
        merkle_root,
        U256::from(7),
        vec![input.nullifier(keys.viewing.nullifying_key)],
        &outputs,
    );
    let private_inputs = PrivateInputs {
        token_address: input.note.token_hash,
        random_in: vec![U256::from_be_slice(&input.note.random)],
        value_in: vec![input.note.value],
        path_elements: vec![U256::ZERO; TREE_DEPTH],
        leaves_indices: vec![U256::ZERO],
        value_out: outputs.iter().map(|note| note.value).collect(),
        public_key: keys.spending_public_key,
        npk_out: outputs.iter().map(|note| note.npk).collect(),
        nullifying_key: keys.viewing.nullifying_key,
    };
    TransactionPlanChunk {
        tree_number: 0,
        merkle_root,
        inputs: vec![InputWitness {
            utxo: input,
            merkle_proof: MerkleProof {
                root: merkle_root,
                leaf: input_leaf,
                leaf_index: 0,
                path_elements: [U256::ZERO; TREE_DEPTH],
                path_indices: [0; TREE_DEPTH],
            },
        }],
        outputs,
        has_unshield,
        public_inputs,
        private_inputs,
        signature: [U256::ZERO; 3],
    }
}

fn verify_provisioned_files(source: &ArtifactSource, variant: &str, hashes: &Value) {
    let paths = source.artifact_paths(variant);
    for (kind, path) in [("zkey", paths.zkey), ("wasm", paths.wasm)] {
        let bytes = fs::read(&path).unwrap_or_else(|error| {
            panic!(
                "provision decompressed {variant}/{kind} at {}: {error}",
                path.display()
            )
        });
        let actual = alloy::hex::encode(Sha256::digest(&bytes));
        assert_eq!(
            Some(actual.as_str()),
            hashes[variant][kind].as_str(),
            "provisioned {variant}/{kind} must match embedded artifact metadata",
        );
    }
}

fn snarkjs_proof(proof: &SnarkJsProof) -> Value {
    json!({
        "protocol": "groth16",
        "curve": "bn128",
        "pi_a": [proof.pi_a[0].to_string(), proof.pi_a[1].to_string(), "1".to_string()],
        "pi_b": [
            [proof.pi_b[0][0].to_string(), proof.pi_b[0][1].to_string()],
            [proof.pi_b[1][0].to_string(), proof.pi_b[1][1].to_string()],
            ["1", "0"],
        ],
        "pi_c": [proof.pi_c[0].to_string(), proof.pi_c[1].to_string(), "1".to_string()],
    })
}

fn export_fixture(
    output_dir: &Path,
    filename: &str,
    poi: &PreTxPoi,
    signals: &[U256],
    chunk: &TransactionPlanChunk,
) {
    let base = chunk
        .pre_transaction_poi_inputs()
        .expect("fixture public context");
    let fixture = json!({
        "input_count": 1,
        "output_count": chunk.public_inputs.commitments_out.len(),
        "pre_tx_poi": poi,
        "public_signals": signals,
        "snarkjs_proof": snarkjs_proof(&poi.snark_proof),
        "snarkjs_public_signals": signals.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "public_context": {
            "railgun_txid": chunk.railgun_txid(),
            "txid_leaf_hash": base.txid_leaf_hash,
            "input_tree": chunk.tree_number,
            "input_positions": [0],
            "bound_params_hash": chunk.public_inputs.bound_params_hash,
            "nullifiers": chunk.public_inputs.nullifiers,
            "commitments_out": chunk.public_inputs.commitments_out,
            "output_npks": chunk.private_inputs.npk_out,
            "output_values": chunk.private_inputs.value_out,
            "output_start_global": broadcaster_core::transact::pre_transaction_output_global_position(),
        },
    });
    fs::write(
        output_dir.join(filename),
        serde_json::to_vec_pretty(&fixture).expect("serialize synthetic proof"),
    )
    .expect("write generated synthetic fixture");
}

#[tokio::test]
#[ignore = "requires explicitly provisioned new PPOI artifacts; see core/tests/fixtures/ppoi.md"]
async fn prove_current_ppoi_shapes() {
    let cache =
        PathBuf::from(std::env::var_os("PPOI_ARTIFACT_CACHE").expect("set PPOI_ARTIFACT_CACHE"));
    let output_dir =
        PathBuf::from(std::env::var_os("PPOI_FIXTURE_OUTPUT").expect("set PPOI_FIXTURE_OUTPUT"));
    assert!(cache.is_dir(), "PPOI_ARTIFACT_CACHE must exist");
    fs::create_dir_all(&output_dir).expect("create fixture output directory");
    // Empty gateways prevent network fallback. Preflight both shapes before starting workers.
    let source = ArtifactSource::new(Vec::new(), cache);
    let hashes: Value = serde_json::from_str(include_str!(
        "../resources/metadata/artifact-v2-hashes.json"
    ))
    .expect("embedded artifact hashes");
    for shape in [3, 13] {
        verify_provisioned_files(&source, &poi_variant_name(shape, shape), &hashes);
    }
    let service = ProverService::with_capacity_db(&source, 1, None);
    let verifier = Prover::new().expect("prepare embedded verification keys");
    for (private_output_count, has_unshield, filename) in [
        (1, false, "ppoi_3x3.json"),
        (2, false, "ppoi_3x3_two_outputs.json"),
        (3, true, "ppoi_13x13_unshield.json"),
    ] {
        let chunk = synthetic_chunk(private_output_count, has_unshield);
        let base = chunk
            .pre_transaction_poi_inputs()
            .expect("synthetic PPOI base inputs");
        let leaf = U256::from_be_bytes(base.blinded_commitments_in[0].0);
        let inputs = base
            .proof_inputs(&[PoiMerkleProof {
                leaf,
                elements: vec![U256::ZERO; TREE_DEPTH],
                indices: U256::ZERO,
                root: zero_sibling_root(leaf),
            }])
            .expect("coherent POI membership witness");
        let result = service
            .prove_poi_with_public_signals(&inputs, true)
            .await
            .expect("prove with verified actual artifacts");
        let output_count = chunk.public_inputs.commitments_out.len();
        let variant = railgun_wallet::poi_circuit_variant(1, output_count);
        let poi = base
            .post_tx_poi_from_public_signals(
                result.snark_proof,
                &inputs,
                &result.public_signals,
                variant,
            )
            .expect("application public signals agree with circuit output");
        assert!(
            verifier
                .verify(1, output_count, &poi)
                .expect("verify with embedded key")
        );
        let mut mutated = poi.clone();
        mutated.txid_merkleroot = FixedBytes::from(
            (U256::from_be_bytes(poi.txid_merkleroot.0) + U256::from(1)).to_be_bytes::<32>(),
        );
        assert!(
            !verifier
                .verify(1, output_count, &mutated)
                .expect("verify mutated signal")
        );
        export_fixture(&output_dir, filename, &poi, &result.public_signals, &chunk);
    }
}
