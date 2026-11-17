use super::{
    BroadcasterRawParamsTransact, BroadcasterTransactRequestType, DEFAULT_TXID_VERSION,
    EncryptedTransactRequest, PreTxPoi, SnarkJsProof, TransactError, compute_railgun_txid,
    parse_transact_calldata, railgun_txid_leaf_hash, try_decrypt_transact_request,
};
use crate::contracts::railgun::{
    BoundParams, CommitmentCiphertext, CommitmentPreimage, RelayAdapt7702,
    RelayAdapt7702ActionData, SnarkProof, TokenData, Transaction, executeCall, transactCall,
};
use crate::crypto::aes_gcm::encrypt_in_place_16b_iv;
use crate::crypto::railgun::{ViewingKeyData, derive_viewing_public_key};
use crate::crypto::shared_key::shared_symmetric_key;
use crate::notes::Note;
use alloy::primitives::{Address, Bytes, FixedBytes, U256};
use alloy::serde::OtherFields;
use alloy::sol_types::SolCall;
use ruint::uint;
use std::collections::BTreeMap;

fn sample_viewing_key_data() -> ViewingKeyData {
    ViewingKeyData::from_spending_public_key([7u8; 32], [uint!(3_U256), uint!(9_U256)])
}

fn sample_ciphertext(
    viewing_key_data: &ViewingKeyData,
    token: Address,
    value: U256,
    random: [u8; 16],
    encoded_mpk: U256,
) -> CommitmentCiphertext {
    let sender_viewing_private_key = [11u8; 32];
    let blinded_sender = derive_viewing_public_key(&sender_viewing_private_key);
    let shared_key = shared_symmetric_key(&viewing_key_data.viewing_private_key, &blinded_sender)
        .expect("shared key");

    let mut plaintext = Vec::with_capacity(96);
    plaintext.extend_from_slice(&encoded_mpk.to_be_bytes::<32>());
    plaintext.extend_from_slice(&U256::from_be_slice(token.as_slice()).to_be_bytes::<32>());
    plaintext.extend_from_slice(&random);
    let value_bytes = value.to_be_bytes::<32>();
    plaintext.extend_from_slice(&value_bytes[16..]);
    let iv_tag = encrypt_in_place_16b_iv(&shared_key, &mut plaintext).expect("encrypt note");

    let mut ciphertext_words = [[0u8; 32]; 4];
    ciphertext_words[0].copy_from_slice(&iv_tag);
    ciphertext_words[1].copy_from_slice(&plaintext[..32]);
    ciphertext_words[2].copy_from_slice(&plaintext[32..64]);
    ciphertext_words[3].copy_from_slice(&plaintext[64..96]);

    CommitmentCiphertext {
        ciphertext: ciphertext_words.map(FixedBytes::from),
        blindedSenderViewingKey: FixedBytes::from(blinded_sender),
        blindedReceiverViewingKey: FixedBytes::ZERO,
        annotationData: Bytes::new(),
        memo: Bytes::new(),
    }
}

fn sample_transaction_and_params_with_encoded_mpk(
    txid_version: Option<&str>,
    encoded_mpk: U256,
) -> (
    Vec<u8>,
    Transaction,
    BroadcasterRawParamsTransact,
    FixedBytes<32>,
    FixedBytes<32>,
) {
    let viewing_key_data = sample_viewing_key_data();
    let fee_token = Address::from([0x22; 20]);
    let fee_value = uint!(42_U256);
    let random = [0x55; 16];
    let npk = Note::npk_for(viewing_key_data.master_public_key, random);
    let fee_commitment = Note {
        token_hash: U256::from_be_slice(fee_token.as_slice()),
        value: fee_value,
        random,
        npk,
    }
    .commitment();
    let transaction = Transaction {
        proof: SnarkProof::default(),
        merkleRoot: FixedBytes::ZERO,
        nullifiers: vec![FixedBytes::from([1u8; 32])],
        commitments: vec![fee_commitment.into()],
        boundParams: BoundParams::new_transact(
            9,
            0,
            1,
            vec![sample_ciphertext(
                &viewing_key_data,
                fee_token,
                fee_value,
                random,
                encoded_mpk,
            )],
            Address::ZERO,
            FixedBytes::ZERO,
        ),
        unshieldPreimage: CommitmentPreimage {
            npk: FixedBytes::ZERO,
            token: TokenData {
                tokenType: 0,
                tokenAddress: Address::ZERO,
                tokenSubID: U256::ZERO,
            },
            value: alloy::primitives::Uint::<120, 2>::ZERO,
        },
    };

    let railgun_txid = compute_railgun_txid(&transaction, txid_version).expect("txid");
    let leaf: FixedBytes<32> = railgun_txid_leaf_hash(railgun_txid, 9).into();
    let required_list_key = FixedBytes::from([0x88; 32]);
    let pre_tx_poi = PreTxPoi {
        snark_proof: SnarkJsProof::zero(),
        txid_merkleroot: FixedBytes::ZERO,
        poi_merkleroots: vec![FixedBytes::ZERO],
        blinded_commitments_out: vec![FixedBytes::from([0x77; 32])],
        railgun_txid_if_has_unshield: Bytes::new(),
    };

    let mut per_leaf = BTreeMap::new();
    per_leaf.insert(leaf, pre_tx_poi);
    let mut per_list = BTreeMap::new();
    per_list.insert(required_list_key, per_leaf);

    let params = BroadcasterRawParamsTransact {
        chain_type: 0,
        chain_id: 1,
        transact_type: None,
        min_gas_price: None,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        authorization: None,
        fees_id: None,
        to: Address::ZERO,
        data: transactCall {
            _transactions: vec![transaction.clone()],
        }
        .abi_encode()
        .into(),
        broadcaster_viewing_key: FixedBytes::ZERO,
        txid_version: txid_version.map(str::to_string),
        pre_transaction_pois_per_txid_leaf_per_list: per_list,
        other: OtherFields::default(),
    };

    (
        transactCall {
            _transactions: vec![transaction.clone()],
        }
        .abi_encode(),
        transaction,
        params,
        fee_commitment.into(),
        FixedBytes::from([0x77; 32]),
    )
}

fn sample_transaction_and_params(
    txid_version: Option<&str>,
) -> (
    Vec<u8>,
    Transaction,
    BroadcasterRawParamsTransact,
    FixedBytes<32>,
    FixedBytes<32>,
) {
    let viewing_key_data = sample_viewing_key_data();
    sample_transaction_and_params_with_encoded_mpk(txid_version, viewing_key_data.master_public_key)
}

#[test]
fn encrypted_envelope_uses_unprefixed_public_key() {
    let broadcaster = sample_viewing_key_data();
    let (_, _, params, _, _) = sample_transaction_and_params(None);
    let encrypted = EncryptedTransactRequest::encrypt_with_seed(
        derive_viewing_public_key(&broadcaster.viewing_private_key),
        &params,
        [8; 32],
    )
    .unwrap();
    let envelope: serde_json::Value =
        serde_json::from_slice(&encrypted.to_transact_payload().unwrap()).unwrap();
    // Noble decodes the outer public key before decrypting the request.
    assert_eq!(
        envelope["params"]["pubkey"],
        alloy::hex::encode(encrypted.pubkey)
    );
    assert_eq!(
        envelope["params"]["encryptedData"],
        serde_json::to_value(&encrypted.encrypted_data).unwrap()
    );
    let pubkey: FixedBytes<32> =
        serde_json::from_value(envelope["params"]["pubkey"].clone()).unwrap();
    let data = serde_json::from_value(envelope["params"]["encryptedData"].clone()).unwrap();
    let decrypted = try_decrypt_transact_request(&broadcaster.viewing_private_key, pubkey.0, &data)
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::to_value(decrypted.params).unwrap(),
        serde_json::to_value(params).unwrap()
    );
}

#[test]
fn parse_transact_extracts_fee_note_context_fields() {
    let viewing_key_data = sample_viewing_key_data();
    let (calldata, _, _, fee_commitment, _) = sample_transaction_and_params(None);
    let parsed = parse_transact_calldata(
        &calldata,
        &viewing_key_data.viewing_private_key,
        viewing_key_data.master_public_key,
        None,
    )
    .expect("parse calldata");

    assert_eq!(parsed.utxo_tree_in, 9);
    assert_eq!(parsed.fee_commitment, fee_commitment);
    assert!(parsed.fee_note_assurance.is_none());
}

#[test]
fn parse_transact_extracts_all_inner_transaction_metadata() {
    let viewing_key_data = sample_viewing_key_data();
    let (_, tx0, _, _, _) = sample_transaction_and_params(None);
    let mut tx1 = tx0.clone();
    tx1.boundParams.treeNumber = 10;
    tx1.nullifiers = vec![FixedBytes::from([2u8; 32]), FixedBytes::from([3u8; 32])];
    tx1.commitments.push(FixedBytes::from([4u8; 32]));
    let calldata = transactCall {
        _transactions: vec![tx0, tx1],
    }
    .abi_encode();

    let parsed = parse_transact_calldata(
        &calldata,
        &viewing_key_data.viewing_private_key,
        viewing_key_data.master_public_key,
        None,
    )
    .expect("parse calldata");

    assert_eq!(parsed.transactions.len(), 2);
    assert_eq!(parsed.transactions[0].utxo_tree_in, 9);
    assert_eq!(parsed.transactions[0].tx_nullifiers_len, 1);
    assert_eq!(parsed.transactions[0].tx_commitments_out_len, 1);
    assert!(!parsed.transactions[0].has_unshield);
    assert_eq!(parsed.transactions[1].utxo_tree_in, 10);
    assert_eq!(parsed.transactions[1].tx_nullifiers_len, 2);
    assert_eq!(parsed.transactions[1].tx_commitments_out_len, 2);
    assert_eq!(parsed.railgun_txid, parsed.transactions[0].railgun_txid);
}

#[test]
fn parse_transact_decodes_relay_adapt_7702_execute_wrapper() {
    let viewing_key_data = sample_viewing_key_data();
    let (_, transaction, _, fee_commitment, _) = sample_transaction_and_params(None);
    let historical = executeCall {
        _transactions: vec![transaction.clone(), transaction],
        _actionData: RelayAdapt7702ActionData {
            requireSuccess: true,
            minGasLimit: uint!(123_U256),
            calls: vec![],
        },
        _signature: Bytes::from(vec![0x12, 0x34]),
    };
    let current = RelayAdapt7702::executeCall {
        _transactions: historical._transactions.clone(),
        _actionData: historical._actionData.clone(),
        _nonce: uint!(9_U256),
        _signature: historical._signature.clone(),
    };
    for calldata in [historical.abi_encode(), current.abi_encode()] {
        let parsed = parse_transact_calldata(
            &calldata,
            &viewing_key_data.viewing_private_key,
            viewing_key_data.master_public_key,
            None,
        )
        .expect("parse current or historical 7702 execute calldata");

        let action_data = parsed.action_data.expect("action data");
        assert_eq!(parsed.fee_commitment, fee_commitment);
        assert_eq!(parsed.transactions.len(), 2);
        assert_eq!(
            parsed.transactions[0].railgun_txid,
            parsed.transactions[1].railgun_txid
        );
        assert!(action_data.requireSuccess);
        assert_eq!(action_data.minGasLimit, uint!(123_U256));
        assert!(action_data.calls.is_empty());
    }
}

#[test]
fn raw_params_deserializes_tx7702_fields() {
    let mut params: BroadcasterRawParamsTransact = serde_json::from_value(serde_json::json!({
        "chainType": 0,
        "chainID": 1,
        "transactType": "TX7702",
        "maxFeePerGas": "134943801",
        "maxPriorityFeePerGas": "10329316",
        "feesID": null,
        "to": "0x56daCb58fD9C6f654047908B573FcCd51652a33C",
        "data": "0x",
        "broadcasterViewingKey": format!("0x00{}", "aB".repeat(31)),
        "txidVersion": null,
        "preTransactionPOIsPerTxidLeafPerList": {},
        "authorization": {
            "address": "0x2df3D82C06339387A4532C685daaF39A218Cf56E",
            "nonce": "0",
            "chainId": "1",
            "signature": {
                "v": 27,
                "r": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "s": "0x2222222222222222222222222222222222222222222222222222222222222222"
            }
        }
    }))
    .expect("deserialize tx7702 params");

    assert_eq!(
        params.transact_type,
        Some(BroadcasterTransactRequestType::Tx7702)
    );
    assert_eq!(params.max_fee_per_gas, Some(uint!(134943801_U256)));
    assert_eq!(params.max_priority_fee_per_gas, Some(uint!(10329316_U256)));
    let list_key = FixedBytes::from(U256::from(0xab));
    let leaf = FixedBytes::from(U256::from(0xcd));
    let poi = PreTxPoi {
        snark_proof: SnarkJsProof::zero(),
        txid_merkleroot: FixedBytes::from(U256::from(0xef)),
        poi_merkleroots: vec![FixedBytes::from(U256::ONE), FixedBytes::repeat_byte(0x12)],
        blinded_commitments_out: vec![FixedBytes::repeat_byte(0x34)],
        railgun_txid_if_has_unshield: Bytes::from(vec![0x56; 32]),
    };
    let canonical_poi = serde_json::to_value(&poi).unwrap();
    params.pre_transaction_pois_per_txid_leaf_per_list =
        BTreeMap::from([(list_key, BTreeMap::from([(leaf, poi)]))]);
    let canonical_pois =
        serde_json::to_value(&params.pre_transaction_pois_per_txid_leaf_per_list).unwrap();
    params
        .other
        .insert("futureField".to_owned(), serde_json::json!({"keep": true}));
    // Node.js compares this field to ByteUtils.hexlify(publicKey), which
    // emits lowercase hex without 0x. Retain both forms on input.
    let serialized = serde_json::to_value(&params).expect("serialize tx7702 params");
    assert_eq!(
        serialized["broadcasterViewingKey"],
        format!("00{}", "ab".repeat(31))
    );
    // The SDK uses exact string keys and compares the dummy Merkle root.
    // Both identifiers retain all 32 bytes, including their leading zeros.
    let wire_poi = &serialized["preTransactionPOIsPerTxidLeafPerList"]
        [format!("{}ab", "00".repeat(31))][format!("{}cd", "00".repeat(31))];
    let mut expected_poi = canonical_poi.clone();
    expected_poi["txidMerkleroot"] = format!("{}ef", "00".repeat(31)).into();
    expected_poi["poiMerkleroots"] =
        serde_json::json!([format!("{}01", "00".repeat(31)), "12".repeat(32)]);
    assert_eq!(wire_poi, &expected_poi);
    assert_eq!(
        canonical_poi["poiMerkleroots"],
        serde_json::json!([
            format!("0x{}01", "00".repeat(31)),
            format!("0x{}", "12".repeat(32))
        ])
    );
    assert_eq!(
        canonical_poi["txidMerkleroot"],
        format!("0x{}ef", "00".repeat(31))
    );
    let mut historical = serialized.clone();
    historical["preTransactionPOIsPerTxidLeafPerList"] = canonical_pois.clone();
    for input in [historical, serialized.clone()] {
        let decoded: BroadcasterRawParamsTransact = serde_json::from_value(input).unwrap();
        assert_eq!(
            serde_json::to_value(&decoded.pre_transaction_pois_per_txid_leaf_per_list).unwrap(),
            canonical_pois
        );
        assert_eq!(decoded.other, params.other);
    }
    let decoded: BroadcasterRawParamsTransact =
        serde_json::from_value(serialized).expect("deserialize unprefixed viewing key");
    assert_eq!(
        decoded.broadcaster_viewing_key,
        params.broadcaster_viewing_key
    );
    let authorization = params.authorization.expect("authorization");
    assert_eq!(authorization.nonce, U256::ZERO);
    assert_eq!(authorization.chain_id, U256::from(1));
    assert!(!authorization.signature.v());
}

#[test]
fn parse_transact_uses_receiver_master_public_key_for_visible_sender_note() {
    let viewing_key_data = sample_viewing_key_data();
    let sender_master_public_key = uint!(0x1234_U256);
    let encoded_mpk = viewing_key_data.master_public_key ^ sender_master_public_key;
    let (calldata, _, _, fee_commitment, _) =
        sample_transaction_and_params_with_encoded_mpk(None, encoded_mpk);

    let parsed = parse_transact_calldata(
        &calldata,
        &viewing_key_data.viewing_private_key,
        viewing_key_data.master_public_key,
        None,
    )
    .expect("parse calldata");

    assert_eq!(parsed.fee_commitment, fee_commitment);
    let expected_npk: FixedBytes<32> =
        Note::npk_for(viewing_key_data.master_public_key, [0x55; 16]).into();
    assert_eq!(parsed.fee_note_npk, expected_npk);
}

#[test]
fn parse_transact_rejects_unsupported_txid_version() {
    let viewing_key_data = sample_viewing_key_data();
    let (calldata, _, _, _, _) = sample_transaction_and_params(None);

    let error = parse_transact_calldata(
        &calldata,
        &viewing_key_data.viewing_private_key,
        viewing_key_data.master_public_key,
        Some("V3_PoseidonMerkle"),
    )
    .expect_err("unsupported txid version should fail");

    assert!(matches!(
        error,
        TransactError::UnsupportedTxidVersion { txid_version }
        if txid_version == "V3_PoseidonMerkle"
    ));
}

#[test]
fn attach_fee_note_assurance_context_rejects_unsupported_txid_version() {
    let viewing_key_data = sample_viewing_key_data();
    let (calldata, _, mut params, _, _) = sample_transaction_and_params(None);
    params.txid_version = Some("V3_PoseidonMerkle".to_string());
    let mut parsed = parse_transact_calldata(
        &calldata,
        &viewing_key_data.viewing_private_key,
        viewing_key_data.master_public_key,
        None,
    )
    .expect("parse calldata");

    let error = parsed
        .attach_fee_note_assurance_context(&params, &[FixedBytes::from([0x88; 32])])
        .expect_err("unsupported txid version should fail");

    assert!(matches!(
        error,
        TransactError::UnsupportedTxidVersion { txid_version }
        if txid_version == "V3_PoseidonMerkle"
    ));
}

#[test]
fn default_txid_version_is_v2_poseidon_merkle() {
    let viewing_key_data = sample_viewing_key_data();
    let (calldata, transaction, _, _, _) = sample_transaction_and_params(None);
    let parsed = parse_transact_calldata(
        &calldata,
        &viewing_key_data.viewing_private_key,
        viewing_key_data.master_public_key,
        None,
    )
    .expect("parse calldata");

    assert_eq!(
        parsed.railgun_txid,
        compute_railgun_txid(&transaction, Some(DEFAULT_TXID_VERSION)).expect("txid")
    );
}
