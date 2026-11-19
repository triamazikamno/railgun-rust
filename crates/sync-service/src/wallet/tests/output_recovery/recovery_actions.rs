use super::*;

#[test]
fn output_poi_recovery_action_caches_tx_input_without_resetting_state() {
    let mut record = output_poi_recovery_record(
        1,
        "wallet",
        FixedBytes::from([0x44; 32]),
        OutputPoiRecoveryStatus::ProofGenerationFailed,
        Some(20),
    );
    record.attempt_count = 3;
    record.last_error = Some("previous".to_string());

    record.apply_action(
        OutputPoiRecoveryAction::CacheTxInput {
            tx_input: vec![0xde, 0xad],
        },
        10,
    );

    assert_eq!(record.tx_input, Some(vec![0xde, 0xad]));
    assert_eq!(
        record.status,
        OutputPoiRecoveryStatus::ProofGenerationFailed
    );
    assert_eq!(record.updated_at, 10);
    assert_eq!(record.last_detection_at, Some(10));
    assert_eq!(record.next_retry_at, Some(20));
    assert_eq!(record.attempt_count, 3);
    assert_eq!(record.last_error.as_deref(), Some("previous"));
}

#[test]
fn output_poi_recovery_action_records_detected_failure() {
    let mut record = output_poi_recovery_record(
        1,
        "wallet",
        FixedBytes::from([0x44; 32]),
        OutputPoiRecoveryStatus::Recoverable,
        None,
    );

    record.apply_action(
        OutputPoiRecoveryAction::Detected {
            status: OutputPoiRecoveryStatus::DecodeFailed,
            retry_after: Some(Duration::from_secs(30)),
            last_error: Some("decode failed".to_string()),
            increment_attempts: true,
        },
        10,
    );

    assert_eq!(record.status, OutputPoiRecoveryStatus::DecodeFailed);
    assert_eq!(record.updated_at, 10);
    assert_eq!(record.last_detection_at, Some(10));
    assert_eq!(record.next_retry_at, Some(40));
    assert_eq!(record.attempt_count, 1);
    assert_eq!(record.last_error.as_deref(), Some("decode failed"));
}

#[test]
fn output_poi_recovery_action_records_recovered_context() {
    let mut record = output_poi_recovery_record(
        1,
        "wallet",
        FixedBytes::from([0x44; 32]),
        OutputPoiRecoveryStatus::ProofGenerationFailed,
        Some(20),
    );
    record.attempt_count = 2;
    record.last_error = Some("old".to_string());

    record.apply_action(
        OutputPoiRecoveryAction::Detected {
            status: OutputPoiRecoveryStatus::Recoverable,
            retry_after: None,
            last_error: None,
            increment_attempts: false,
        },
        10,
    );

    assert_eq!(record.status, OutputPoiRecoveryStatus::Recoverable);
    assert_eq!(record.updated_at, 10);
    assert_eq!(record.last_detection_at, Some(10));
    assert_eq!(record.next_retry_at, None);
    assert_eq!(record.attempt_count, 2);
    assert_eq!(record.last_error, None);
}

#[test]
fn output_poi_recovery_action_records_submit_success() {
    let mut record = output_poi_recovery_record(
        1,
        "wallet",
        FixedBytes::from([0x44; 32]),
        OutputPoiRecoveryStatus::Recoverable,
        None,
    );
    record.last_error = Some("old".to_string());

    record.apply_action(
        OutputPoiRecoveryAction::Submitted {
            retry_after: Duration::from_mins(1),
        },
        10,
    );

    assert_eq!(record.status, OutputPoiRecoveryStatus::Submitted);
    assert_eq!(record.updated_at, 10);
    assert_eq!(record.last_submission_at, Some(10));
    assert_eq!(record.next_retry_at, Some(70));
    assert_eq!(record.attempt_count, 1);
    assert_eq!(record.last_error, None);
}

#[test]
fn output_poi_recovery_action_records_submit_failure() {
    let mut record = output_poi_recovery_record(
        1,
        "wallet",
        FixedBytes::from([0x44; 32]),
        OutputPoiRecoveryStatus::Recoverable,
        None,
    );

    record.apply_action(
        OutputPoiRecoveryAction::SubmitFailed {
            error: "submit failed".to_string(),
            retry_after: Duration::from_mins(1),
        },
        10,
    );

    assert_eq!(record.status, OutputPoiRecoveryStatus::SubmitFailed);
    assert_eq!(record.updated_at, 10);
    assert_eq!(record.last_submission_at, None);
    assert_eq!(record.next_retry_at, Some(70));
    assert_eq!(record.attempt_count, 1);
    assert_eq!(record.last_error.as_deref(), Some("submit failed"));
}

#[test]
fn output_poi_recovery_action_marks_valid_without_touching_history() {
    let mut record = output_poi_recovery_record(
        1,
        "wallet",
        FixedBytes::from([0x44; 32]),
        OutputPoiRecoveryStatus::Submitted,
        Some(20),
    );
    record.last_detection_at = Some(4);
    record.last_submission_at = Some(5);
    record.attempt_count = 2;
    record.last_error = Some("old".to_string());

    record.apply_action(OutputPoiRecoveryAction::Valid, 10);

    assert_eq!(record.status, OutputPoiRecoveryStatus::Valid);
    assert_eq!(record.updated_at, 10);
    assert_eq!(record.last_detection_at, Some(4));
    assert_eq!(record.last_submission_at, Some(5));
    assert_eq!(record.next_retry_at, None);
    assert_eq!(record.attempt_count, 2);
    assert_eq!(record.last_error, None);
}

#[test]
fn pending_output_submit_identity_derives_status_query_blinded_commitment() {
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x77; 32]);
    let list_key = FixedBytes::from([0x11; 32]);
    let record = pending_output_record(chain_id, output_commitment, list_key);
    let observation = local_db::PendingOutputPoiObservation {
        output_tree: 3,
        output_position: 42,
        tx_hash: source(11).tx_hash,
        block_number: 11,
        block_timestamp: 1_700_000_011,
    };

    let identity =
        pending_output_poi_submit_identity(&record, &observation).expect("submit identity");

    assert_eq!(
        identity.derived_blinded_commitment,
        UtxoPoiMetadata::blinded_commitment_for(
            record.output_commitment,
            record.output_npk,
            observation.output_tree as u32,
            observation.output_position,
        )
    );
}

#[test]
fn pending_output_submit_identity_accepts_included_txid_leaf_for_recovery() {
    let chain_id = 1;
    let output_commitment = FixedBytes::from([0x77; 32]);
    let list_key = FixedBytes::from([0x11; 32]);
    let included_txid_leaf = FixedBytes::from([0x99; 32]);
    let mut record = pending_output_record(chain_id, output_commitment, list_key);
    let dummy_txid_leaf = FixedBytes::from(
        railgun_txid_leaf_hash(record.railgun_txid, record.utxo_tree_in).to_be_bytes::<32>(),
    );
    record.txid_merkleroot_index = Some(105_572);
    record.pre_transaction_pois_per_txid_leaf_per_list = BTreeMap::from([(
        list_key,
        BTreeMap::from([(included_txid_leaf, sample_pre_tx_poi(0x10))]),
    )]);
    let observation = local_db::PendingOutputPoiObservation {
        output_tree: 3,
        output_position: 42,
        tx_hash: source(11).tx_hash,
        block_number: 11,
        block_timestamp: 1_700_000_011,
    };

    pending_output_poi_submit_identity(&record, &observation).expect("submit identity");

    assert_ne!(included_txid_leaf, dummy_txid_leaf);
}

#[test]
fn output_start_global_position_handles_nonzero_output_index_across_tree_boundary() {
    let utxo = Utxo::new(
        Note {
            token_hash: uint!(1_U256),
            value: uint!(10_U256),
            random: [0u8; 16],
            npk: uint!(2_U256),
        },
        3,
        1,
        source(17),
        UtxoCommitmentKind::Transact,
    );

    let start_global = output_start_global_position(&utxo, 2).expect("start global");

    assert_eq!(start_global / u128::from(TREE_LEAF_COUNT), 2);
    assert_eq!(start_global % u128::from(TREE_LEAF_COUNT), 65_535);
    assert_eq!(
        start_global,
        u128::from(utxo.tree) * u128::from(TREE_LEAF_COUNT) + u128::from(utxo.position) - 2
    );
}
