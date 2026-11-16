use super::local_retirement::{
    pending_context_covers_sender_output, sender_candidate_coverage_from_routes,
};
use super::materialization::generate_sender_candidate_post_transaction_pois_with_timeout;
use super::qualification::{
    SenderRowQualification, qualify_sender_candidate, qualify_sender_row_inputs,
};
use super::unshield::sender_unshield_railgun_txid;
use super::*;
use crate::sender_candidate::SenderTransactionCandidateOutput;
use crate::txid_cache::TxidPublicCacheTransaction;
use alloy::primitives::Address;
use broadcaster_core::crypto::railgun::ViewingKeyData;
use broadcaster_core::transact::PreTxPoi;
use local_db::WalletCacheKey;

fn sample_pre_tx_poi() -> PreTxPoi {
    let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../../core/tests/fixtures/ppoi_3x3.json"
    ))
    .expect("proof fixture");
    serde_json::from_value(fixture["pre_tx_poi"].clone()).expect("fixture proof")
}

fn fixture() -> (
    ViewingKeyData,
    SenderTransactionCandidate,
    WalletUtxo,
    PublicTxidTransaction,
) {
    let keys = ViewingKeyData::from_spending_public_key([0x11; 32], [U256::from(2), U256::from(3)]);
    let input_note = Note::new_change(
        keys.master_public_key,
        Address::from([0x22; 20]),
        U256::from(10),
        [0x33; 16],
    );
    let input_source = UtxoSource {
        tx_hash: FixedBytes::from([0x44; 32]),
        block_number: 4,
        block_timestamp: 40,
    };
    let mut input = WalletUtxo {
        utxo: Utxo::new(input_note, 1, 7, input_source, UtxoCommitmentKind::Transact),
        spent: None,
    };
    let source = UtxoSource {
        tx_hash: FixedBytes::from([0x55; 32]),
        block_number: 5,
        block_timestamp: 50,
    };
    input.spent = Some(source.clone());
    let output_note = Note::new_change(
        U256::from(9),
        Address::from([0x22; 20]),
        U256::from(10),
        [0x66; 16],
    );
    let output_commitment = FixedBytes::from(output_note.commitment().to_be_bytes::<32>());
    let candidate = SenderTransactionCandidate::new(
        1,
        WalletCacheKey::from_opaque_bytes(b"sender-qualification").expect("wallet key"),
        source.clone(),
        vec![SenderTransactionCandidateSpend {
            tree: input.utxo.tree,
            position: input.utxo.position,
            commitment: input.utxo.poi.commitment,
        }],
        vec![SenderTransactionCandidateOutput {
            tree: 2,
            position: 3,
            commitment: output_commitment,
            note: Some(output_note),
        }],
    )
    .expect("candidate");
    let row = PublicTxidTransaction {
        txid_index: 8,
        transaction: TxidPublicCacheTransaction {
            id: "8".to_string(),
            transaction_hash: source.tx_hash,
            block_number: source.block_number,
            block_timestamp: source.block_timestamp,
            nullifiers: vec![input.utxo.nullifier(keys.nullifying_key)],
            commitments: vec![U256::from_be_bytes(output_commitment.0)],
            bound_params_hash: U256::from(2),
            has_unshield: false,
            unshield_preimage: None,
            utxo_tree_in: 1,
            utxo_tree_out: 2,
            utxo_batch_start_position_out: 3,
        },
    };
    (keys, candidate, input, row)
}

#[test]
fn exact_foreign_and_mixed_rows_qualify_fail_closed() {
    let (keys, candidate, input, row) = fixture();
    assert_eq!(
        qualify_sender_row_inputs(&candidate, std::slice::from_ref(&input), &keys, &row),
        Ok(SenderRowQualification::WalletAuthored)
    );

    let mut foreign = row.clone();
    foreign.transaction.nullifiers = vec![U256::from(999)];
    assert_eq!(
        qualify_sender_row_inputs(&candidate, std::slice::from_ref(&input), &keys, &foreign),
        Ok(SenderRowQualification::Foreign)
    );

    let mut mixed = row.clone();
    mixed.transaction.nullifiers.push(U256::from(999));
    assert!(
        qualify_sender_row_inputs(&candidate, std::slice::from_ref(&input), &keys, &mixed).is_err()
    );

    let mut duplicate = row;
    duplicate
        .transaction
        .nullifiers
        .push(duplicate.transaction.nullifiers[0]);
    assert!(qualify_sender_row_inputs(&candidate, &[input], &keys, &duplicate).is_err());
}

#[test]
fn complete_mixed_batch_qualifies_every_wallet_authored_chunk_in_order() {
    let (keys, candidate, first_input, first_row) = fixture();
    let source = candidate.source.clone();
    let second_input_note = Note::new_change(
        keys.master_public_key,
        Address::from([0x22; 20]),
        U256::from(11),
        [0x88; 16],
    );
    let mut second_input = WalletUtxo {
        utxo: Utxo::new(
            second_input_note,
            1,
            8,
            UtxoSource {
                tx_hash: FixedBytes::from([0x89; 32]),
                block_number: 4,
                block_timestamp: 40,
            },
            UtxoCommitmentKind::Transact,
        ),
        spent: None,
    };
    second_input.spent = Some(source.clone());
    let second_output_note = Note::new_change(
        U256::from(10),
        Address::from([0x22; 20]),
        U256::from(11),
        [0x99; 16],
    );
    let second_output_commitment =
        FixedBytes::from(second_output_note.commitment().to_be_bytes::<32>());
    let candidate = SenderTransactionCandidate::new(
        candidate.chain_id,
        candidate.wallet_id.clone(),
        source,
        vec![
            SenderTransactionCandidateSpend {
                tree: first_input.utxo.tree,
                position: first_input.utxo.position,
                commitment: first_input.utxo.poi.commitment,
            },
            SenderTransactionCandidateSpend {
                tree: second_input.utxo.tree,
                position: second_input.utxo.position,
                commitment: second_input.utxo.poi.commitment,
            },
        ],
        vec![
            candidate.outputs[0].clone(),
            SenderTransactionCandidateOutput {
                tree: 2,
                position: 4,
                commitment: second_output_commitment,
                note: Some(second_output_note),
            },
        ],
    )
    .expect("complete candidate");
    let mut foreign_row = first_row.clone();
    foreign_row.txid_index = 9;
    foreign_row.transaction.id = "9".to_string();
    foreign_row.transaction.nullifiers = vec![U256::from(999)];
    let mut second_row = first_row.clone();
    second_row.txid_index = 10;
    second_row.transaction.id = "10".to_string();
    second_row.transaction.nullifiers = vec![second_input.utxo.nullifier(keys.nullifying_key)];
    second_row.transaction.commitments = vec![U256::from_be_bytes(second_output_commitment.0)];
    second_row.transaction.utxo_batch_start_position_out = 4;

    let qualified = qualify_sender_candidate(
        &candidate,
        &[first_input.clone(), second_input.clone()],
        &keys,
        vec![first_row.clone(), foreign_row, second_row.clone()],
    )
    .expect("complete rows are valid")
    .expect("all candidate evidence is covered");

    assert_eq!(
        qualified
            .iter()
            .map(|chunk| chunk.txid_index)
            .collect::<Vec<_>>(),
        vec![8, 10]
    );
    assert_eq!(
        qualified
            .iter()
            .flat_map(|chunk| chunk.outputs.iter())
            .map(|output| (output.tree, output.position, output.poi.commitment))
            .collect::<Vec<_>>(),
        candidate
            .outputs
            .iter()
            .map(|output| (output.tree, output.position, output.commitment))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        qualified
            .iter()
            .flat_map(|chunk| chunk.public_row.transaction.nullifiers.iter().copied())
            .collect::<BTreeSet<_>>(),
        [
            first_input.utxo.nullifier(keys.nullifying_key),
            second_input.utxo.nullifier(keys.nullifying_key),
        ]
        .into_iter()
        .collect()
    );
    assert!(!qualified.iter().any(|chunk| chunk.txid_index == 9));

    // Two inner unshields in one outer transaction are each keyed by their own TXID.
    let unshield_rows = [first_row, second_row].map(|mut row| {
        row.transaction.has_unshield = true;
        row.transaction
            .commitments
            .push(U256::from(0x7a_u64 + row.txid_index));
        row
    });
    let wallet_utxos = [first_input, second_input];
    let qualified =
        qualify_sender_candidate(&candidate, &wallet_utxos, &keys, unshield_rows.to_vec())
            .expect("unshield rows are valid")
            .expect("unshield rows cover the candidate");
    let list_key = FixedBytes::from([0x7b; 32]);
    let both = qualified
        .iter()
        .map(sender_unshield_railgun_txid)
        .collect::<BTreeSet<_>>();
    assert_eq!(both.len(), 2);
    assert_eq!(
        eligible_sender_unshield_txids(
            &qualified,
            &WalletNullifierIndex::new(&wallet_utxos, &keys),
            &[list_key],
            &BTreeSet::new(),
        ),
        both
    );
    let mut blocked = wallet_utxos;
    blocked[1]
        .utxo
        .poi
        .statuses
        .insert(list_key, PoiStatus::ShieldBlocked);
    assert_eq!(
        eligible_sender_unshield_txids(
            &qualified,
            &WalletNullifierIndex::new(&blocked, &keys),
            &[list_key],
            &BTreeSet::new(),
        ),
        BTreeSet::from([sender_unshield_railgun_txid(&qualified[0])]),
        "a Shield-blocked input removes only its own row's unshield"
    );
}

#[test]
fn missing_txid_or_output_data_keeps_candidate_unqualified() {
    let (keys, candidate, input, row) = fixture();
    assert!(
        qualify_sender_candidate(&candidate, std::slice::from_ref(&input), &keys, Vec::new())
            .expect("TXID lag is retryable")
            .is_none()
    );

    let mut wrong_output = row.clone();
    wrong_output.transaction.commitments[0] = U256::from(123);
    assert!(
        qualify_sender_candidate(
            &candidate,
            std::slice::from_ref(&input),
            &keys,
            vec![wrong_output]
        )
        .is_err()
    );

    // A full unshield qualifies a spend-only candidate with no private outputs.
    let mut spend_only = candidate.clone();
    spend_only.outputs.clear();
    let mut unshield_only = row.clone();
    unshield_only.transaction.commitments = vec![U256::from(0x7a)];
    unshield_only.transaction.has_unshield = true;
    let qualified = qualify_sender_candidate(
        &spend_only,
        std::slice::from_ref(&input),
        &keys,
        vec![unshield_only.clone()],
    )
    .expect("unshield-only row is well formed")
    .expect("unshield-only row covers the spend-only candidate");
    assert_eq!(qualified.len(), 1);
    assert!(qualified[0].outputs.is_empty());

    let mut no_outputs = unshield_only;
    no_outputs.transaction.commitments.clear();
    no_outputs.transaction.has_unshield = false;
    assert!(
        qualify_sender_candidate(
            &spend_only,
            std::slice::from_ref(&input),
            &keys,
            vec![no_outputs]
        )
        .is_err(),
        "a row with neither private outputs nor an unshield is malformed"
    );

    let mut unknown_note = candidate;
    unknown_note.outputs[0].note = None;
    assert!(
        qualify_sender_candidate(&unknown_note, &[input], &keys, vec![row]).is_err(),
        "a private commitment without its sender note is malformed evidence"
    );
}

#[test]
fn local_retirement_classifier_requires_exact_spends_and_classifies_owned_change() {
    let (keys, candidate, input, _) = fixture();
    let owned_note = Note::new_change(
        keys.master_public_key,
        Address::from([0x22; 20]),
        U256::from(3),
        [0x77; 16],
    );
    let owned_output = SenderTransactionCandidateOutput {
        tree: 2,
        position: 4,
        commitment: FixedBytes::from(owned_note.commitment().to_be_bytes::<32>()),
        note: Some(owned_note.clone()),
    };
    let mixed = SenderTransactionCandidate::new(
        candidate.chain_id,
        candidate.wallet_id.clone(),
        candidate.source.clone(),
        candidate.wallet_spends.clone(),
        vec![candidate.outputs[0].clone(), owned_output.clone()],
    )
    .expect("mixed candidate");
    let owned_utxo = WalletUtxo {
        utxo: Utxo::new(
            owned_note,
            owned_output.tree,
            owned_output.position,
            mixed.source.clone(),
            UtxoCommitmentKind::Transact,
        ),
        spent: None,
    };

    let classification = classify_sender_candidate_for_local_retirement(
        &mixed,
        &[input.clone(), owned_utxo.clone()],
        &keys,
    )
    .expect("exact mixed candidate classification");
    assert_eq!(classification.external_outputs.len(), 1);

    let mut owned_only = mixed.clone();
    owned_only
        .outputs
        .retain(|output| output.commitment == owned_output.commitment);
    let classification = classify_sender_candidate_for_local_retirement(
        &owned_only,
        &[input.clone(), owned_utxo.clone()],
        &keys,
    )
    .expect("an all-owned candidate classifies for local retirement");
    assert_eq!(
        classification.external_outputs,
        [] as [BlindedCommitmentData; 0]
    );
    let mut spend_only = mixed.clone();
    spend_only.outputs.clear();
    assert!(
        classify_sender_candidate_for_local_retirement(
            &spend_only,
            &[input.clone(), owned_utxo],
            &keys,
        )
        .is_none(),
        "a candidate without outputs keeps the no-private-output route"
    );

    let mut extra_spend = input;
    extra_spend.utxo.position += 1;
    extra_spend.spent = Some(mixed.source.clone());
    assert!(
        classify_sender_candidate_for_local_retirement(&mixed, &[extra_spend], &keys,).is_none()
    );
}

#[test]
fn pending_context_coverage_requires_current_observation_and_retained_pois() {
    let (_keys, candidate, _input, _) = fixture();
    let list_key = FixedBytes::from([0x77; 32]);
    let output = &candidate.outputs[0];
    let note = output.note.as_ref().expect("fixture note");
    let mut context = PendingOutputPoiContextRecord {
        chain_id: candidate.chain_id,
        wallet_id: candidate.wallet_id.to_string(),
        txid_version: DEFAULT_TXID_VERSION.to_string(),
        output_commitment: output.commitment,
        output_npk: FixedBytes::from(note.npk.to_be_bytes::<32>()),
        utxo_tree_in: 1,
        railgun_txid: U256::ZERO,
        txid_merkleroot_index: None,
        pre_transaction_pois_per_txid_leaf_per_list: BTreeMap::from([(
            list_key,
            BTreeMap::from([(FixedBytes::from([0x88; 32]), sample_pre_tx_poi())]),
        )]),
        required_poi_list_keys: vec![list_key],
        output_role: PendingOutputPoiRole::Recipient,
        created_at: 1,
        source_operation_id: None,
        observation: Some(PendingOutputPoiObservation {
            output_tree: u64::from(output.tree),
            output_position: output.position,
            tx_hash: candidate.source.tx_hash,
            block_number: candidate.source.block_number,
            block_timestamp: candidate.source.block_timestamp,
        }),
        submitted_poi_list_keys: Vec::new(),
        terminal_error: None,
    };

    assert!(pending_context_covers_sender_output(
        candidate.chain_id,
        candidate.wallet_id.as_str(),
        &candidate,
        output,
        &[list_key],
        &context,
    ));
    let current_material = context.pre_transaction_pois_per_txid_leaf_per_list.clone();
    let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../../core/tests/fixtures/ppoi_3x3_previous.json"
    ))
    .expect("old proof fixture");
    let old_proof: PreTxPoi =
        serde_json::from_value(fixture["pre_tx_poi"].clone()).expect("old fixture proof");
    context.pre_transaction_pois_per_txid_leaf_per_list = BTreeMap::from([(
        list_key,
        BTreeMap::from([(FixedBytes::from([0x88; 32]), old_proof)]),
    )]);
    assert!(!pending_context_covers_sender_output(
        candidate.chain_id,
        candidate.wallet_id.as_str(),
        &candidate,
        output,
        &[list_key],
        &context
    ));
    context.pre_transaction_pois_per_txid_leaf_per_list = current_material;
    context.observation.as_mut().expect("observation").tx_hash = FixedBytes::from([0xaa; 32]);
    assert!(!pending_context_covers_sender_output(
        candidate.chain_id,
        candidate.wallet_id.as_str(),
        &candidate,
        output,
        &[list_key],
        &context,
    ));
    context.observation.as_mut().expect("observation").tx_hash = candidate.source.tx_hash;
    context
        .observation
        .as_mut()
        .expect("observation")
        .block_number += 1;
    assert!(!pending_context_covers_sender_output(
        candidate.chain_id,
        candidate.wallet_id.as_str(),
        &candidate,
        output,
        &[list_key],
        &context,
    ));
    context
        .observation
        .as_mut()
        .expect("observation")
        .block_number = candidate.source.block_number;
    context.output_npk = FixedBytes::from([0x99; 32]);
    assert!(!pending_context_covers_sender_output(
        candidate.chain_id,
        candidate.wallet_id.as_str(),
        &candidate,
        output,
        &[list_key],
        &context,
    ));
    context.output_npk = FixedBytes::from(note.npk.to_be_bytes::<32>());
    context.observation = None;
    assert!(!pending_context_covers_sender_output(
        candidate.chain_id,
        candidate.wallet_id.as_str(),
        &candidate,
        output,
        &[list_key],
        &context,
    ));
    context.observation = Some(PendingOutputPoiObservation {
        output_tree: u64::from(output.tree),
        output_position: output.position,
        tx_hash: candidate.source.tx_hash,
        block_number: candidate.source.block_number,
        block_timestamp: candidate.source.block_timestamp,
    });
    context.pre_transaction_pois_per_txid_leaf_per_list.clear();
    assert!(!pending_context_covers_sender_output(
        candidate.chain_id,
        candidate.wallet_id.as_str(),
        &candidate,
        output,
        &[list_key],
        &context,
    ));
}

#[test]
fn mixed_sender_candidate_coverage_uses_local_and_pending_routes_without_retiring() {
    let (_keys, mut candidate, _input, _) = fixture();
    let second_note = Note::new_change(
        U256::from(9),
        Address::from([0x22; 20]),
        U256::from(11),
        [0x67; 16],
    );
    let second_output = SenderTransactionCandidateOutput {
        tree: 2,
        position: 4,
        commitment: FixedBytes::from(second_note.commitment().to_be_bytes::<32>()),
        note: Some(second_note),
    };
    let third_note = Note::new_change(
        U256::from(9),
        Address::from([0x22; 20]),
        U256::from(12),
        [0x68; 16],
    );
    let third_output = SenderTransactionCandidateOutput {
        tree: 2,
        position: 5,
        commitment: FixedBytes::from(third_note.commitment().to_be_bytes::<32>()),
        note: Some(third_note),
    };
    candidate.outputs.extend([second_output, third_output]);
    candidate
        .outputs
        .sort_by_key(|output| (output.tree, output.position));

    let local = BTreeSet::from([candidate.outputs[0].commitment]);
    // These represent fresh pending contexts accepted by the predicate above.
    let fresh_pending_contexts = BTreeSet::from([
        candidate.outputs[1].commitment,
        candidate.outputs[2].commitment,
    ]);
    let coverage =
        sender_candidate_coverage_from_routes(&candidate, &local, &fresh_pending_contexts)
            .expect("mixed coverage should short-circuit");
    assert_eq!(coverage.local_valid, 1);
    assert_eq!(coverage.pending_contexts, 2);

    let all_local = candidate
        .outputs
        .iter()
        .map(|output| output.commitment)
        .collect();
    assert!(
        sender_candidate_coverage_from_routes(&candidate, &all_local, &BTreeSet::new()).is_none()
    );

    let missing = BTreeSet::from([candidate.outputs[1].commitment]);
    assert!(sender_candidate_coverage_from_routes(&candidate, &local, &missing).is_none());
}

#[tokio::test]
async fn sender_candidate_proof_generation_timeout_is_retryable() {
    let failure = generate_sender_candidate_post_transaction_pois_with_timeout(
        std::future::pending(),
        Duration::from_millis(1),
    )
    .await
    .expect_err("hanging proof generation must time out");
    assert_eq!(failure.category, "proof_generation_timeout");
    assert!(failure.retry_after.is_some());
}
