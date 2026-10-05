use alloy::primitives::{FixedBytes, U256};
use broadcaster_core::crypto::snark_proof::Prover;
use broadcaster_core::transact::{MERKLE_ZERO_VALUE, PreTxPoi};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    input_count: usize,
    output_count: usize,
    public_signals: Vec<U256>,
    pre_tx_poi: PreTxPoi,
}

#[test]
fn current_ppoi_proofs_verify_and_bind_public_signals() {
    let verifier = Prover::new().expect("prepare current PPOI verification keys");
    for filename in [
        "ppoi_3x3.json",
        "ppoi_3x3_two_outputs.json",
        "ppoi_13x13_unshield.json",
    ] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(filename);
        let fixture: Fixture =
            serde_json::from_slice(&std::fs::read(path).expect("retained real proof fixture"))
                .expect("decode synthetic PPOI fixture");
        let max_count = if fixture.input_count <= 3 && fixture.output_count <= 3 {
            3
        } else {
            13
        };
        let poi = &fixture.pre_tx_poi;
        let mut signals = poi
            .blinded_commitments_out
            .iter()
            .map(|value| U256::from_be_bytes(value.0))
            .collect::<Vec<_>>();
        signals.resize(max_count, U256::ZERO);
        signals.push(U256::from_be_bytes(poi.txid_merkleroot.0));
        signals.push(U256::from_be_slice(&poi.railgun_txid_if_has_unshield));
        signals.extend(
            poi.poi_merkleroots
                .iter()
                .map(|value| U256::from_be_bytes(value.0)),
        );
        signals.resize(max_count * 2 + 2, MERKLE_ZERO_VALUE);
        assert_eq!(
            signals, fixture.public_signals,
            "{filename}: persisted signals preserve circuit order and padding"
        );
        assert!(
            verifier
                .verify(fixture.input_count, fixture.output_count, poi)
                .expect("verify current fixture"),
            "{filename}"
        );
        let mut mutated = poi.clone();
        mutated.txid_merkleroot = FixedBytes::from(
            (U256::from_be_bytes(poi.txid_merkleroot.0) + U256::from(1)).to_be_bytes::<32>(),
        );
        assert!(
            !verifier
                .verify(fixture.input_count, fixture.output_count, &mutated)
                .expect("verify mutated public signal"),
            "{filename}"
        );
        if fixture.output_count == 4 {
            assert_eq!(poi.blinded_commitments_out.len(), 3);
            assert_ne!(
                U256::from_be_slice(&poi.railgun_txid_if_has_unshield),
                U256::ZERO
            );
            assert!(
                !verifier
                    .verify(fixture.input_count, 3, poi)
                    .expect("wrong shape verification"),
                "unshield must count toward selecting the 13x13 key"
            );
        }
    }
}

#[test]
fn previous_bundle_proof_is_incompatible() {
    let verifier = Prover::new().expect("prepare current PPOI verification keys");
    for json in [
        include_str!("fixtures/ppoi_3x3_previous.json"),
        include_str!("fixtures/ppoi_3x3_two_outputs_previous.json"),
        include_str!("fixtures/ppoi_3x3_external_previous.json"),
    ] {
        let fixture: Fixture =
            serde_json::from_str(json).expect("decode previous-bundle synthetic PPOI fixture");
        assert!(
            !verifier
                .verify(
                    fixture.input_count,
                    fixture.output_count,
                    &fixture.pre_tx_poi
                )
                .expect("verify previous-bundle proof")
        );
    }
}
