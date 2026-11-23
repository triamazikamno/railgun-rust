use alloy::hex;
use alloy::primitives::{Address, FixedBytes, U256};
use alloy::sol_types::SolEvent;
use alloy_rpc_types_eth::Log;
use broadcaster_core::contracts::railgun::{CommitmentCiphertext, Transact};
use broadcaster_core::crypto::railgun::ViewingKeyData;
use broadcaster_core::tree::TREE_LEAF_COUNT;
use merkletree::quick::IndexedTransactCommitment;
use railgun_wallet::scan::{
    IndexedTransactCommitmentInput, SenderScanOutput, parse_indexed_wallet_delta,
    parse_wallet_delta_from_logs,
};
use railgun_wallet::{
    Note, NoteCiphertext, NoteOutputType, Utxo, UtxoCommitmentKind, UtxoSource, WalletUtxo,
};

use super::sender_scan_candidate_inputs;

fn source(byte: u8) -> UtxoSource {
    UtxoSource {
        tx_hash: FixedBytes::from([byte; 32]),
        block_number: u64::from(byte),
        block_timestamp: 1_700_000_000 + u64::from(byte),
    }
}

fn sender_output(
    keys: &ViewingKeyData,
    receiver: &ViewingKeyData,
    position: u64,
    value: u64,
    source: UtxoSource,
) -> SenderScanOutput {
    let note = Note::new_change(
        receiver.master_public_key,
        Address::ZERO,
        U256::from(value),
        [value as u8; 16],
    );
    let ciphertext: CommitmentCiphertext = NoteCiphertext::try_from_note(
        &note,
        &keys.address_data(),
        &receiver.address_data(),
        &keys.viewing_private_key,
        NoteOutputType::Transfer,
    )
    .expect("encrypt sender output")
    .into();
    SenderScanOutput {
        tree: 3,
        position,
        commitment: note.commitment(),
        ciphertext,
        source,
    }
}

#[test]
fn sender_selection_emits_one_ordered_candidate_for_exact_wallet_spend() {
    let keys = ViewingKeyData::from_spending_public_key([7; 32], [U256::from(11), U256::from(12)]);
    let receiver =
        ViewingKeyData::from_spending_public_key([9; 32], [U256::from(13), U256::from(14)]);
    let wallet_note = Note::new_change(
        keys.master_public_key,
        Address::ZERO,
        U256::from(50),
        [1; 16],
    );
    let wallet_utxo = WalletUtxo::new(Utxo::new(
        wallet_note,
        2,
        7,
        source(1),
        UtxoCommitmentKind::Transact,
    ));
    let matching_source = source(8);
    let unrelated_source = source(9);
    let nullifier_sources = std::collections::HashMap::from([(
        (2, wallet_utxo.utxo.nullifier(keys.nullifying_key)),
        matching_source.clone(),
    )]);
    let mut unavailable = sender_output(&keys, &receiver, 11, 20, matching_source.clone());
    unavailable.ciphertext.blindedReceiverViewingKey = FixedBytes::ZERO;
    let outputs = vec![
        unavailable,
        sender_output(&keys, &receiver, 10, 30, matching_source.clone()),
        sender_output(&keys, &receiver, 12, 40, unrelated_source),
    ];

    let mut candidates = sender_scan_candidate_inputs(
        std::slice::from_ref(&wallet_utxo),
        keys.nullifying_key,
        &nullifier_sources,
        outputs,
        &keys,
    );

    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].source, matching_source);
    assert_eq!(candidates[0].wallet_spends.len(), 1);
    assert_eq!(candidates[0].wallet_spends[0].key(), (2, 7));
    assert_eq!(
        candidates[0]
            .outputs
            .iter()
            .map(|output| output.position)
            .collect::<Vec<_>>(),
        vec![10, 11]
    );
    assert!(candidates[0].outputs[0].note.is_some());
    assert!(candidates[0].outputs[1].note.is_none());
    let record = candidates
        .remove(0)
        .into_record(
            1,
            local_db::WalletCacheKey::from_opaque_bytes(b"sender-scan-wallet").expect("wallet key"),
        )
        .expect("convert candidate record");
    assert_eq!(record.semantic_id(), matching_source.tx_hash);
    assert_eq!(record.outputs.len(), 2);

    // A full unshield has no sender scan output; its exact wallet spend is still a candidate.
    let mut spend_only = sender_scan_candidate_inputs(
        &[wallet_utxo],
        keys.nullifying_key,
        &nullifier_sources,
        Vec::new(),
        &keys,
    );
    assert_eq!(spend_only.len(), 1);
    let record = spend_only
        .remove(0)
        .into_record(
            1,
            local_db::WalletCacheKey::from_opaque_bytes(b"sender-scan-wallet").expect("wallet key"),
        )
        .expect("spend-only candidate record");
    assert_eq!(record.semantic_id(), matching_source.tx_hash);
    assert_eq!(
        record
            .wallet_spends
            .iter()
            .map(|spend| (spend.tree, spend.position))
            .collect::<Vec<_>>(),
        vec![(2, 7)]
    );
    assert!(record.outputs.is_empty());
}

#[test]
fn rpc_and_indexed_sender_candidates_are_identical() {
    let keys = ViewingKeyData::from_spending_public_key([7; 32], [U256::from(11), U256::from(12)]);
    let receiver =
        ViewingKeyData::from_spending_public_key([9; 32], [U256::from(13), U256::from(14)]);
    let note = Note::new_change(
        receiver.master_public_key,
        Address::ZERO,
        U256::from(30),
        [0x33; 16],
    );
    let ciphertext: CommitmentCiphertext = NoteCiphertext::try_from_note(
        &note,
        &keys.address_data(),
        &receiver.address_data(),
        &keys.viewing_private_key,
        NoteOutputType::Transfer,
    )
    .expect("encrypt sender output")
    .into();
    let tree = 2_u32;
    let position = TREE_LEAF_COUNT + 3;
    let tx_hash = FixedBytes::from([0x44; 32]);
    let block_number = 105_u64;
    let block_timestamp = 1_700_000_105_u64;
    let encoded = Transact {
        treeNumber: U256::from(tree),
        startPosition: U256::from(position),
        hash: vec![FixedBytes::from(note.commitment().to_be_bytes::<32>())],
        ciphertext: vec![ciphertext.clone()],
    }
    .encode_log_data();
    let rpc_log: Log = serde_json::from_value(serde_json::json!({
        "address": format!("{:#x}", Address::from([0xaa; 20])),
        "topics": encoded.topics().iter().map(|topic| format!("{topic:#x}")).collect::<Vec<_>>(),
        "data": format!("0x{}", hex::encode(encoded.data)),
        "blockHash": format!("{:#x}", FixedBytes::<32>::from([0xbb; 32])),
        "blockNumber": format!("0x{block_number:x}"),
        "transactionHash": format!("{tx_hash:#x}"),
        "transactionIndex": "0x0",
        "logIndex": "0x0",
        "removed": false,
    }))
    .expect("deserialize RPC log");
    let rpc_delta = parse_wallet_delta_from_logs(
        &[rpc_log],
        &std::collections::HashMap::from([(block_number, block_timestamp)]),
        &keys,
    )
    .expect("parse RPC delta");

    let iv_tag = ciphertext.ciphertext[0].as_slice();
    let indexed: IndexedTransactCommitment = serde_json::from_value(serde_json::json!({
        "id": "0x01",
        "transactionHash": format!("{tx_hash:#x}"),
        "blockNumber": format!("0x{block_number:x}"),
        "blockTimestamp": format!("0x{block_timestamp:x}"),
        "treeNumber": format!("0x{tree:x}"),
        "treePosition": format!("0x{position:x}"),
        "hash": format!("{:#x}", note.commitment()),
        "ciphertext": {
            "ciphertext": {
                "iv": format!("0x{}", hex::encode(&iv_tag[..16])),
                "tag": format!("0x{}", hex::encode(&iv_tag[16..])),
                "data": ciphertext.ciphertext[1..]
                    .iter()
                    .map(|part| format!("{part:#x}"))
                    .collect::<Vec<_>>(),
            },
            "blindedSenderViewingKey": format!("{:#x}", ciphertext.blindedSenderViewingKey),
            "blindedReceiverViewingKey": format!("{:#x}", ciphertext.blindedReceiverViewingKey),
            "annotationData": format!("0x{}", hex::encode(&ciphertext.annotationData)),
            "memo": format!("0x{}", hex::encode(&ciphertext.memo)),
        },
    }))
    .expect("deserialize normalized indexed row");
    let indexed_delta = parse_indexed_wallet_delta(
        &[IndexedTransactCommitmentInput::from(indexed)],
        &[],
        &[],
        &[],
        &[],
        &keys,
    );

    let rpc_output = &rpc_delta.sender_scan_outputs[0];
    let indexed_output = &indexed_delta.sender_scan_outputs[0];
    assert_eq!((rpc_output.tree, rpc_output.position), (tree + 1, 3));
    assert_eq!(
        (rpc_output.tree, rpc_output.position),
        (indexed_output.tree, indexed_output.position)
    );
    assert_eq!(rpc_output.commitment, indexed_output.commitment);
    assert_eq!(
        (
            rpc_output.source.tx_hash,
            rpc_output.source.block_number,
            rpc_output.source.block_timestamp,
        ),
        (tx_hash, block_number, block_timestamp)
    );
    assert_eq!(rpc_output.source, indexed_output.source);
    assert!(
        rpc_output.ciphertext.ciphertext == indexed_output.ciphertext.ciphertext
            && rpc_output.ciphertext.blindedSenderViewingKey
                == indexed_output.ciphertext.blindedSenderViewingKey
            && rpc_output.ciphertext.blindedReceiverViewingKey
                == indexed_output.ciphertext.blindedReceiverViewingKey
            && rpc_output.ciphertext.annotationData == indexed_output.ciphertext.annotationData
            && rpc_output.ciphertext.memo == indexed_output.ciphertext.memo
    );

    let wallet_note = Note::new_change(
        keys.master_public_key,
        Address::ZERO,
        U256::from(50),
        [1; 16],
    );
    let wallet_utxo = WalletUtxo::new(Utxo::new(
        wallet_note,
        1,
        7,
        source(1),
        UtxoCommitmentKind::Transact,
    ));
    let nullifier_sources = std::collections::HashMap::from([(
        (1, wallet_utxo.utxo.nullifier(keys.nullifying_key)),
        rpc_output.source.clone(),
    )]);
    let record = |outputs| {
        sender_scan_candidate_inputs(
            std::slice::from_ref(&wallet_utxo),
            keys.nullifying_key,
            &nullifier_sources,
            outputs,
            &keys,
        )
        .remove(0)
        .into_record(
            1,
            local_db::WalletCacheKey::from_opaque_bytes(b"source-parity").expect("wallet key"),
        )
        .expect("candidate record")
    };
    let rpc_record = record(rpc_delta.sender_scan_outputs);
    let indexed_record = record(indexed_delta.sender_scan_outputs);
    assert_eq!(rpc_record.source, indexed_record.source);
    assert_eq!(rpc_record.outputs[0].tree, tree + 1);
    assert_eq!(rpc_record.outputs[0].position, 3);
    assert_eq!(
        rpc_record.encode().expect("encode RPC record"),
        indexed_record.encode().expect("encode indexed record")
    );
}

impl super::SenderScanWalletSpend {
    const fn key(&self) -> (u32, u64) {
        (self.tree, self.position)
    }
}
