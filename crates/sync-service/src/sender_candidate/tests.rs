use std::fs;

use local_db::{DbConfig, DbStore, OpaqueWalletPrivateRow, WalletPrivateRecordKind};

use super::*;
use crate::types::WalletCacheStore;

fn candidate(block_number: u64, byte: u8) -> SenderTransactionCandidate {
    let note = Note {
        token_hash: U256::from(1),
        value: U256::from(20),
        random: [byte; 16],
        npk: U256::from(2),
    };
    SenderTransactionCandidate::new(
        1,
        WalletCacheKey::from_opaque_bytes(b"candidate-wallet").expect("wallet key"),
        UtxoSource {
            tx_hash: FixedBytes::from([byte; 32]),
            block_number,
            block_timestamp: 1_700_000_000 + block_number,
        },
        vec![SenderTransactionCandidateSpend {
            tree: 1,
            position: 3,
            commitment: FixedBytes::from([3; 32]),
        }],
        vec![SenderTransactionCandidateOutput {
            tree: 2,
            position: 4,
            commitment: FixedBytes::from(note.commitment().to_be_bytes::<32>()),
            note: Some(note),
        }],
    )
    .expect("valid candidate")
}

#[test]
fn candidate_validation_and_deterministic_roundtrip() {
    let record = candidate(10, 0x11);
    let encoded = record.encode().expect("encode candidate");
    assert_eq!(encoded, record.encode().expect("re-encode candidate"));

    let decoded = SenderTransactionCandidate::decode(&encoded).expect("decode candidate");
    assert_eq!(
        decoded.encode().expect("re-encode decoded candidate"),
        encoded
    );
    assert_eq!(decoded.semantic_id(), record.semantic_id());
    assert_eq!(decoded.namespace(), record.namespace());
    assert_eq!(decoded.wallet_spends, record.wallet_spends);
    assert_eq!(decoded.outputs.len(), 1);
    assert_eq!(
        decoded.outputs[0]
            .note
            .as_ref()
            .expect("sender note")
            .commitment(),
        record.outputs[0]
            .note
            .as_ref()
            .expect("sender note")
            .commitment()
    );

    let unshield = SenderTransactionCandidateUnshield {
        railgun_txids: vec![FixedBytes::from([0x01; 32]), FixedBytes::from([0x02; 32])],
        outputs_handed_off: true,
    };
    let with_unshield = record
        .clone()
        .with_unshield(Some(unshield.clone()))
        .expect("candidate with unshield");
    let encoded_unshield = with_unshield.encode().expect("encode unshield candidate");
    let decoded_unshield =
        SenderTransactionCandidate::decode(&encoded_unshield).expect("decode unshield");
    assert_eq!(decoded_unshield.unshield, Some(unshield));
    assert_eq!(
        decoded_unshield
            .encode()
            .expect("re-encode unshield candidate"),
        encoded_unshield
    );
    assert_ne!(encoded_unshield, encoded);

    let mut spend_only = record.clone();
    spend_only.outputs.clear();
    spend_only
        .validate()
        .expect("candidate without sender note");
    for railgun_txids in [
        Vec::new(),
        vec![FixedBytes::from([0x02; 32]), FixedBytes::from([0x01; 32])],
        vec![FixedBytes::from([0x01; 32]), FixedBytes::from([0x01; 32])],
    ] {
        assert_eq!(
            record
                .clone()
                .with_unshield(Some(SenderTransactionCandidateUnshield {
                    railgun_txids,
                    outputs_handed_off: false,
                }))
                .err(),
            Some(SenderTransactionCandidateError::InvalidUnshield)
        );
    }

    let mut malformed = record.clone();
    malformed.outputs[0].commitment = FixedBytes::ZERO;
    assert_eq!(
        malformed.validate(),
        Err(SenderTransactionCandidateError::NoteCommitmentMismatch)
    );
    let mut malformed = record;
    malformed.wallet_spends.push(malformed.wallet_spends[0]);
    assert_eq!(
        malformed.validate(),
        Err(SenderTransactionCandidateError::InvalidWalletSpends)
    );
}

#[test]
fn rewind_selection_uses_source_block_and_is_ordered() {
    let records = [candidate(20, 0x22), candidate(9, 0x11), candidate(10, 0x33)];
    assert_eq!(
        sender_transaction_candidate_rewind_ids(&records, 10).expect("select rewind rows"),
        vec![FixedBytes::from([0x22; 32]), FixedBytes::from([0x33; 32])]
    );
}

#[test]
fn bare_db_store_candidate_codec_is_namespace_and_kind_separated() {
    let root_dir = std::env::temp_dir().join(format!(
        "railgun-sender-candidate-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ));
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let record = candidate(10, 0x44);
    let namespace = record.namespace();
    let row = OpaqueWalletPrivateRow {
        row_id: record.row_identity(),
        payload: record.encode().expect("encode candidate"),
    };
    store
        .put_opaque_wallet_private_row(
            &namespace,
            WalletPrivateRecordKind::SenderTransactionCandidate,
            &row,
        )
        .expect("put candidate row");

    let loaded = <DbStore as WalletCacheStore>::get_sender_transaction_candidate(
        &store,
        record.chain_id,
        &record.wallet_id,
        &record.semantic_id(),
    )
    .expect("get candidate")
    .expect("candidate present");
    assert_eq!(loaded.semantic_id(), record.semantic_id());
    assert_eq!(
        <DbStore as WalletCacheStore>::list_sender_transaction_candidates(
            &store,
            record.chain_id,
            &record.wallet_id,
        )
        .expect("list candidates")
        .len(),
        1
    );

    let wrong_namespace = WalletPrivateNamespaceId::new(
        record.chain_id,
        WalletCacheKey::from_opaque_bytes(b"wrong-wallet").expect("wallet key"),
    );
    store
        .put_opaque_wallet_private_row(
            &wrong_namespace,
            WalletPrivateRecordKind::SenderTransactionCandidate,
            &row,
        )
        .expect("put wrong-namespace row");
    assert!(
        <DbStore as WalletCacheStore>::get_sender_transaction_candidate(
            &store,
            wrong_namespace.chain_id,
            &wrong_namespace.wallet_id,
            &record.semantic_id(),
        )
        .is_err()
    );

    let wrong_kind = candidate(11, 0x55);
    store
        .put_opaque_wallet_private_row(
            &wrong_kind.namespace(),
            WalletPrivateRecordKind::OutputPoiRecovery,
            &OpaqueWalletPrivateRow {
                row_id: wrong_kind.row_identity(),
                payload: wrong_kind.encode().expect("encode wrong-kind candidate"),
            },
        )
        .expect("put wrong-kind row");
    assert!(
        <DbStore as WalletCacheStore>::get_sender_transaction_candidate(
            &store,
            wrong_kind.chain_id,
            &wrong_kind.wallet_id,
            &wrong_kind.semantic_id(),
        )
        .expect("get kind-separated candidate")
        .is_none()
    );

    store
        .put_opaque_wallet_private_row(
            &namespace,
            WalletPrivateRecordKind::SenderTransactionCandidate,
            &OpaqueWalletPrivateRow {
                row_id: vec![0x66; 32],
                payload: b"malformed".to_vec(),
            },
        )
        .expect("put malformed row");
    assert!(
        <DbStore as WalletCacheStore>::list_sender_transaction_candidates(
            &store,
            record.chain_id,
            &record.wallet_id,
        )
        .is_err()
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
