use super::{
    BlindedCommitmentData, DEFAULT_ACTIVE_POI_LIST_KEY_HEX, DEFAULT_WALLET_POI_RPC_URL,
    POI_RPC_MAX_RESPONSE_BYTES, PoiEventType, PoiMerkleProof, PoiMerkletreeLeavesResponse,
    PoiRpcClient, PoiStatus, PoiSyncedListEvent, SignedBlockedShield, SignedPoiEvent,
    SingleCommitmentProofContext, ValidatedRailgunTxidStatus, decode_json_rpc_ack_response,
    decode_json_rpc_response, default_active_poi_list_key, encode_u256_bare,
    railgun_txid_leaf_hash,
};
use crate::error::{PoiRpcError, PoiRpcTransportPhase};
use alloy::{
    hex,
    primitives::{FixedBytes, U256},
    uint,
};
use broadcaster_core::transact::{FeeNoteAssuranceContext, PreTxPoi, SnarkJsProof};
use reqwest::Url;
use serde_json::to_value;
use std::collections::BTreeMap;
use std::error::Error;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

fn endpoint_with_sentinel(mut url: Url) -> Url {
    url.set_path("/endpoint-sentinel");
    url.set_query(Some("secret=endpoint-sentinel"));
    url.set_fragment(Some("endpoint-sentinel"));
    url
}

fn spawn_rpc_response(status: u16, body: &str, declared_len: Option<usize>) -> Url {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind RPC server");
    let url = Url::parse(&format!(
        "http://{}",
        listener.local_addr().expect("RPC server address")
    ))
    .expect("RPC server URL");
    let response = format!(
        "HTTP/1.1 {status} TEST\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        declared_len.unwrap_or(body.len())
    );
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept RPC request");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buffer).expect("read RPC request");
            if read == 0 {
                return;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        stream
            .write_all(response.as_bytes())
            .expect("write RPC response");
    });
    endpoint_with_sentinel(url)
}

fn spawn_stalled_rpc() -> Url {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stalled RPC server");
    let url = Url::parse(&format!(
        "http://{}",
        listener.local_addr().expect("stalled RPC address")
    ))
    .expect("stalled RPC URL");
    std::thread::spawn(move || {
        let (_stream, _) = listener.accept().expect("accept stalled RPC request");
        std::thread::sleep(Duration::from_secs(1));
    });
    endpoint_with_sentinel(url)
}

fn formatted_error_chain(error: &(dyn Error + 'static)) -> String {
    let mut formatted = String::new();
    let mut current = Some(error);
    while let Some(error) = current {
        std::fmt::Write::write_fmt(&mut formatted, format_args!("{error} {error:?}\n"))
            .expect("write error chain");
        current = error.source();
    }
    formatted
}

fn assert_rpc_error_safe(error: &PoiRpcError, sentinels: &[&str]) {
    let formatted = formatted_error_chain(error);
    for sentinel in sentinels {
        assert!(
            !formatted.contains(sentinel),
            "RPC error leaked {sentinel}: {formatted}"
        );
    }
}

#[tokio::test]
async fn rpc_transport_errors_strip_endpoint_and_remote_body() {
    let send_url =
        endpoint_with_sentinel(Url::parse("http://127.0.0.1:0").expect("unavailable RPC URL"));
    let send_error = PoiRpcClient::new(send_url)
        .send_request::<_, bool>("test_send", ())
        .await
        .expect_err("send error");
    assert_eq!(
        send_error.transport_phase(),
        Some(PoiRpcTransportPhase::Send)
    );
    assert_rpc_error_safe(&send_error, &["endpoint-sentinel"]);

    let status_client = PoiRpcClient::new(spawn_rpc_response(503, "http-body-sentinel", None));
    let status_error = status_client
        .send_request::<_, bool>("test_status", ())
        .await
        .expect_err("status error");
    assert_eq!(
        status_error.status(),
        Some(reqwest::StatusCode::SERVICE_UNAVAILABLE)
    );
    assert_rpc_error_safe(&status_error, &["endpoint-sentinel", "http-body-sentinel"]);

    let decode_client = PoiRpcClient::new(spawn_rpc_response(200, "decode-body-sentinel", None));
    let decode_error = decode_client
        .send_request::<_, bool>("test_decode", ())
        .await
        .expect_err("decode error");
    assert!(matches!(&decode_error, PoiRpcError::JsonDecode(_)));
    assert_rpc_error_safe(
        &decode_error,
        &["endpoint-sentinel", "decode-body-sentinel"],
    );

    let body_client = PoiRpcClient::new(spawn_rpc_response(200, "short", Some(100)));
    let body_error = body_client
        .send_request::<_, bool>("test_body", ())
        .await
        .expect_err("truncated body error");
    assert_eq!(
        body_error.transport_phase(),
        Some(PoiRpcTransportPhase::ResponseBody)
    );
    assert_rpc_error_safe(&body_error, &["endpoint-sentinel"]);

    let large_body = format!(
        "large-body-sentinel{}",
        " ".repeat(POI_RPC_MAX_RESPONSE_BYTES)
    );
    let large_client = PoiRpcClient::new(spawn_rpc_response(200, &large_body, None));
    let large_error = large_client
        .send_request::<_, bool>("test_large", ())
        .await
        .expect_err("oversized body error");
    assert!(matches!(&large_error, PoiRpcError::ResponseTooLarge));
    assert_rpc_error_safe(&large_error, &["endpoint-sentinel", "large-body-sentinel"]);

    let timeout_client =
        PoiRpcClient::new(spawn_stalled_rpc()).with_request_timeout(Duration::from_millis(20));
    let timeout_error = timeout_client
        .send_request::<_, bool>("test_timeout", ())
        .await
        .expect_err("timeout error");
    assert!(timeout_error.is_timeout());
    assert_rpc_error_safe(&timeout_error, &["endpoint-sentinel"]);
}

#[tokio::test]
async fn rpc_response_decodes_with_leading_bom() {
    let client = PoiRpcClient::new(spawn_rpc_response(200, "\u{feff}{\"result\":true}", None));
    let result = client
        .send_request::<_, bool>("test_bom", ())
        .await
        .expect("BOM-prefixed response");
    assert!(result);
}

#[test]
fn rpc_remote_message_data_and_ack_result_are_not_formatted() {
    let error = decode_json_rpc_response::<bool>(
        r#"{"error":{"code":-32000,"message":"message-sentinel","data":{"detail":"data-sentinel"}}}"#,
    )
    .expect_err("JSON-RPC error");
    assert_eq!(error.json_rpc_code(), Some(-32000));
    assert_rpc_error_safe(&error, &["message-sentinel", "data-sentinel"]);

    decode_json_rpc_ack_response(
        "test_ack",
        r#"{"jsonrpc":"2.0","id":2,"result":"ack-sentinel"}"#,
    )
    .expect("ACK result is accepted without formatting its value");
}

fn sample_context() -> FeeNoteAssuranceContext {
    let list_key = FixedBytes::from([0x11; 32]);
    let leaf = FixedBytes::from([0x22; 32]);
    let poi = PreTxPoi {
        snark_proof: SnarkJsProof::zero(),
        txid_merkleroot: FixedBytes::from([0x33; 32]),
        poi_merkleroots: vec![FixedBytes::from([0x44; 32])],
        blinded_commitments_out: vec![FixedBytes::from([0x55; 32])],
        railgun_txid_if_has_unshield: alloy::primitives::Bytes::new(),
    };
    let mut per_leaf = BTreeMap::new();
    per_leaf.insert(leaf, poi);
    let mut per_list = BTreeMap::new();
    per_list.insert(list_key, per_leaf);

    FeeNoteAssuranceContext {
        chain_type: 0,
        txid_version: "V3_PoseidonMerkle".to_string(),
        railgun_txid: uint!(9_U256),
        utxo_tree_in: 7,
        fee_commitment: FixedBytes::from([0x66; 32]),
        fee_note_npk: FixedBytes::from([0x77; 32]),
        pre_transaction_pois_per_txid_leaf_per_list: per_list,
        required_poi_list_keys: vec![list_key],
    }
}

#[test]
fn wallet_poi_defaults_are_available() {
    assert_eq!(DEFAULT_WALLET_POI_RPC_URL, "https://ppoi.fdi.network");
    assert_eq!(
        hex::encode(default_active_poi_list_key()),
        DEFAULT_ACTIVE_POI_LIST_KEY_HEX
    );
}

#[test]
fn poi_status_supports_local_unknown() {
    let json = serde_json::to_string(&PoiStatus::Unknown).expect("serialize unknown status");
    assert_eq!(json, r#""Unknown""#);
    let status: PoiStatus = serde_json::from_str(&json).expect("deserialize unknown status");
    assert_eq!(status, PoiStatus::Unknown);
}

#[test]
fn validate_request_uses_non_default_txid_version() {
    let params = PoiRpcClient::validate_poi_merkleroots_params(
        "V3_PoseidonMerkle",
        0,
        1,
        &FixedBytes::from([0x99; 32]),
        &["abcd".to_string()],
    );
    let json = to_value(params).expect("serialize validate params");

    assert_eq!(json["txidVersion"], "V3_PoseidonMerkle");
    assert_eq!(json["chainType"], "0");
    assert_eq!(json["chainID"], "1");
}

#[test]
fn single_commitment_submit_request_serializes_context() {
    let context = sample_context();
    let single_commitment_context = SingleCommitmentProofContext::from(&context);
    let params = PoiRpcClient::submit_single_commitment_proofs_params(
        &context.txid_version,
        0,
        1,
        &single_commitment_context,
        10,
        12,
    );
    let json = to_value(params).expect("serialize submit params");

    assert_eq!(json["txidVersion"], "V3_PoseidonMerkle");
    assert_eq!(
        json["singleCommitmentProofsData"]["commitment"],
        hex::encode_prefixed(context.fee_commitment)
    );
    assert_eq!(
        json["singleCommitmentProofsData"]["npk"],
        hex::encode_prefixed(context.fee_note_npk)
    );
    assert_eq!(
        json["singleCommitmentProofsData"]["railgunTxid"],
        encode_u256_bare(context.railgun_txid)
    );
    assert_eq!(json["singleCommitmentProofsData"]["utxoTreeOut"], 10);
    assert_eq!(json["singleCommitmentProofsData"]["utxoPositionOut"], 12);
    assert!(
        json["singleCommitmentProofsData"]["pois"]
            .get(hex::encode(context.required_poi_list_keys[0]))
            .is_some()
    );
    assert!(
        json["singleCommitmentProofsData"]["pois"]
            .get(hex::encode_prefixed(context.required_poi_list_keys[0]))
            .is_none()
    );
}

#[test]
fn transact_proof_submit_request_serializes_railway_shape() {
    let context = sample_context();
    let list_key = context.required_poi_list_keys[0];
    let poi = context
        .pre_transaction_pois_per_txid_leaf_per_list
        .get(&list_key)
        .expect("list")
        .values()
        .next()
        .expect("poi");
    let params = PoiRpcClient::submit_transact_proof_params(
        &context.txid_version,
        0,
        1,
        &list_key,
        105_572,
        poi,
    );
    let json = to_value(params).expect("serialize transact proof params");

    assert_eq!(json["txidVersion"], "V3_PoseidonMerkle");
    assert_eq!(json["listKey"], hex::encode(list_key));
    assert!(json.get("singleCommitmentProofsData").is_none());
    assert_eq!(
        json["transactProofData"]["txidMerkleroot"],
        hex::encode(poi.txid_merkleroot)
    );
    assert_eq!(json["transactProofData"]["txidMerklerootIndex"], 105_572);
    assert_eq!(
        json["transactProofData"]["poiMerkleroots"][0],
        hex::encode(poi.poi_merkleroots[0])
    );
    assert_eq!(
        json["transactProofData"]["blindedCommitmentsOut"][0],
        hex::encode_prefixed(poi.blinded_commitments_out[0])
    );
    assert_eq!(
        json["transactProofData"]["railgunTxidIfHasUnshield"],
        "0x00"
    );
}

#[test]
fn validated_txid_response_deserializes() {
    let status: ValidatedRailgunTxidStatus = decode_json_rpc_response(
        r#"{"result":{"validatedTxidIndex":105578,"validatedTxidMerkleroot":"2946581b750a59be1865ea5499ed515957865df1dcecf5db07ea5c7fcf473396"}}"#,
    )
    .expect("decode current validated txid");

    assert_eq!(status.validated_txid_index, Some(105_578));
    assert_eq!(
        status.validated_merkleroot.as_deref(),
        Some("2946581b750a59be1865ea5499ed515957865df1dcecf5db07ea5c7fcf473396")
    );

    let legacy: ValidatedRailgunTxidStatus = decode_json_rpc_response(
        r#"{"result":{"validatedTxidIndex":105578,"validatedMerkleroot":"legacy-root"}}"#,
    )
    .expect("decode legacy validated txid");
    assert_eq!(legacy.validated_txid_index, Some(105_578));
    assert_eq!(legacy.validated_merkleroot.as_deref(), Some("legacy-root"));
}

#[test]
fn single_commitment_submit_request_uses_bare_hex_poi_keys() {
    let context = sample_context();
    let single_commitment_context = SingleCommitmentProofContext::from(&context);
    let params = PoiRpcClient::submit_single_commitment_proofs_params(
        &context.txid_version,
        0,
        1,
        &single_commitment_context,
        10,
        12,
    );
    let json = to_value(params).expect("serialize submit params");
    let list_key = hex::encode(context.required_poi_list_keys[0]);
    let leaf_key = hex::encode(
        context
            .pre_transaction_pois_per_txid_leaf_per_list
            .get(&context.required_poi_list_keys[0])
            .expect("list")
            .keys()
            .next()
            .expect("leaf"),
    );

    assert!(
        json["singleCommitmentProofsData"]["pois"][&list_key]
            .get(&leaf_key)
            .is_some()
    );
    assert!(
        json["singleCommitmentProofsData"]["pois"][&list_key]
            .get(format!("0x{leaf_key}"))
            .is_none()
    );
    assert_eq!(
        json["singleCommitmentProofsData"]["pois"][&list_key][&leaf_key]["txidMerkleroot"],
        hex::encode(FixedBytes::from([0x33; 32]))
    );
    assert_eq!(
        json["singleCommitmentProofsData"]["pois"][&list_key][&leaf_key]["poiMerkleroots"][0],
        hex::encode(FixedBytes::from([0x44; 32]))
    );
    assert_eq!(
        json["singleCommitmentProofsData"]["pois"][&list_key][&leaf_key]["blindedCommitmentsOut"]
            [0],
        hex::encode_prefixed(FixedBytes::from([0x55; 32]))
    );
    assert_eq!(
        json["singleCommitmentProofsData"]["pois"][&list_key][&leaf_key]["railgunTxidIfHasUnshield"],
        "0x00"
    );
    assert_eq!(
        json["singleCommitmentProofsData"]["pois"][&list_key][&leaf_key]["snarkProof"]["pi_a"][0],
        "0"
    );
}

#[test]
fn pois_per_list_query_serializes_blinded_commitment_request() {
    let context = sample_context();
    let blinded_commitment = FixedBytes::from([0x88; 32]);
    let shield_blinded_commitment = FixedBytes::from([0x99; 32]);
    let params = PoiRpcClient::pois_per_list_params(
        &context.txid_version,
        0,
        1,
        &context.required_poi_list_keys,
        &[
            BlindedCommitmentData::transact(blinded_commitment),
            BlindedCommitmentData::shield(shield_blinded_commitment),
        ],
    );
    let json = to_value(params).expect("serialize pois per list params");

    assert_eq!(json["txidVersion"], "V3_PoseidonMerkle");
    assert_eq!(
        json["listKeys"][0],
        hex::encode(context.required_poi_list_keys[0])
    );
    assert_eq!(json["blindedCommitmentDatas"][0]["type"], "Transact");
    assert_eq!(
        json["blindedCommitmentDatas"][0]["blindedCommitment"],
        hex::encode_prefixed(blinded_commitment)
    );
    assert_eq!(json["blindedCommitmentDatas"][1]["type"], "Shield");
    assert_eq!(
        json["blindedCommitmentDatas"][1]["blindedCommitment"],
        hex::encode_prefixed(shield_blinded_commitment)
    );
}

#[test]
fn poi_merkle_proofs_query_serializes_blinded_commitments() {
    let context = sample_context();
    let list_key = context.required_poi_list_keys[0];
    let blinded_commitments = [FixedBytes::from([0x88; 32]), FixedBytes::from([0x99; 32])];
    let params = PoiRpcClient::poi_merkle_proofs_params(
        &context.txid_version,
        0,
        1,
        &list_key,
        &blinded_commitments,
    );
    let json = to_value(params).expect("serialize merkle proof params");

    assert_eq!(json["txidVersion"], "V3_PoseidonMerkle");
    assert_eq!(json["listKey"], hex::encode(list_key));
    assert_eq!(
        json["blindedCommitments"][0],
        hex::encode_prefixed(blinded_commitments[0])
    );
    assert_eq!(
        json["blindedCommitments"][1],
        hex::encode_prefixed(blinded_commitments[1])
    );
}

#[test]
fn poi_merkle_proofs_response_decodes() {
    let proofs: Vec<PoiMerkleProof> = decode_json_rpc_response(
        r#"{"result":[{"leaf":"0x11","elements":["0x22"],"indices":"0x00","root":"0x33"}]}"#,
    )
    .expect("decode merkle proofs");

    assert_eq!(proofs.len(), 1);
    assert_eq!(proofs[0].leaf, U256::from(0x11));
    assert_eq!(proofs[0].elements, vec![U256::from(0x22)]);
    assert_eq!(proofs[0].indices, U256::ZERO);
    assert_eq!(proofs[0].root, U256::from(0x33));

    let encoded = to_value(&proofs[0]).expect("encode merkle proof");
    assert_eq!(
        encoded["leaf"],
        "0x0000000000000000000000000000000000000000000000000000000000000011"
    );
}

#[test]
fn poi_merkletree_leaves_response_decodes_bare_and_prefixed_hex() {
    let prefixed: PoiMerkletreeLeavesResponse = decode_json_rpc_response(
        r#"{"result":["0x1111111111111111111111111111111111111111111111111111111111111111","0x2222222222222222222222222222222222222222222222222222222222222222"]}"#,
    )
    .expect("decode prefixed leaves");
    assert_eq!(
        prefixed.leaves,
        vec![
            U256::from_be_bytes([0x11; 32]),
            U256::from_be_bytes([0x22; 32])
        ]
    );

    let bare: PoiMerkletreeLeavesResponse = decode_json_rpc_response(
        r#"{"result":["3333333333333333333333333333333333333333333333333333333333333333"]}"#,
    )
    .expect("decode bare leaf");
    assert_eq!(bare.leaves, vec![U256::from_be_bytes([0x33; 32])]);

    let encoded = to_value(prefixed).expect("encode leaves");
    assert_eq!(
        encoded[0],
        "0x1111111111111111111111111111111111111111111111111111111111111111"
    );
}

#[test]
fn poi_events_query_serializes_range() {
    let context = sample_context();
    let list_key = context.required_poi_list_keys[0];
    let params = PoiRpcClient::poi_events_params(&context.txid_version, 0, 1, &list_key, 5, 10);
    let json = to_value(params).expect("serialize poi events params");

    assert_eq!(json["txidVersion"], "V3_PoseidonMerkle");
    assert_eq!(json["chainType"], "0");
    assert_eq!(json["chainID"], "1");
    assert_eq!(json["listKey"], hex::encode(list_key));
    assert_eq!(json["startIndex"], 5);
    assert_eq!(json["endIndex"], 10);
}

#[test]
fn poi_merkletree_leaves_query_serializes_range() {
    let context = sample_context();
    let list_key = context.required_poi_list_keys[0];
    let params =
        PoiRpcClient::poi_merkletree_leaves_params(&context.txid_version, 0, 1, &list_key, 5, 10);
    let json = to_value(params).expect("serialize poi leaves params");

    assert_eq!(json["txidVersion"], "V3_PoseidonMerkle");
    assert_eq!(json["listKey"], hex::encode(list_key));
    assert_eq!(json["startIndex"], 5);
    assert_eq!(json["endIndex"], 10);
}

#[test]
fn blocked_shields_query_omits_bloom_filter_when_absent() {
    let context = sample_context();
    let list_key = context.required_poi_list_keys[0];
    let params =
        PoiRpcClient::filtered_blocked_shields_params(&context.txid_version, 0, 1, &list_key, None);
    let json = to_value(params).expect("serialize blocked shields params");

    assert_eq!(json["txidVersion"], "V3_PoseidonMerkle");
    assert_eq!(json["listKey"], hex::encode(list_key));
    assert!(json.get("bloomFilterSerialized").is_none());
}

#[test]
fn blocked_shields_query_serializes_range() {
    let context = sample_context();
    let list_key = context.required_poi_list_keys[0];
    let params =
        PoiRpcClient::blocked_shields_params(&context.txid_version, 0, 1, &list_key, 5, 10);
    let json = to_value(params).expect("serialize blocked shields params");

    assert_eq!(json["txidVersion"], "V3_PoseidonMerkle");
    assert_eq!(json["chainType"], "0");
    assert_eq!(json["chainID"], "1");
    assert_eq!(json["listKey"], hex::encode(list_key));
    assert_eq!(json["startIndex"], 5);
    assert_eq!(json["endIndex"], 10);
}

#[test]
fn bulk_poi_responses_decode() {
    let events: Vec<PoiSyncedListEvent> = decode_json_rpc_response(
        r#"{"result":[{"signedPOIEvent":{"index":7,"blindedCommitment":"0x1111111111111111111111111111111111111111111111111111111111111111","signature":"sig","type":"Shield"},"validatedMerkleroot":"0x22"}]}"#,
    )
    .expect("decode poi events");
    let blocked_shields: Vec<SignedBlockedShield> = decode_json_rpc_response(
        r#"{"result":[{"commitmentHash":"0x33","blindedCommitment":"0x44","blockReason":"blocked","signature":"sig"}]}"#,
    )
    .expect("decode blocked shields");

    assert_eq!(events[0].signed_poi_event.index, 7);
    assert_eq!(events[0].signed_poi_event.event_type, PoiEventType::Shield);
    assert_eq!(
        events[0].signed_poi_event.blinded_commitment,
        FixedBytes::from([0x11; 32])
    );
    let bare_events: Vec<PoiSyncedListEvent> = decode_json_rpc_response(
        r#"{"result":[{"signedPOIEvent":{"index":8,"blindedCommitment":"2222222222222222222222222222222222222222222222222222222222222222","signature":"sig","type":"Transact"},"validatedMerkleroot":"0x33"}]}"#,
    )
    .expect("decode bare poi event commitment");
    assert_eq!(
        bare_events[0].signed_poi_event.blinded_commitment,
        FixedBytes::from([0x22; 32])
    );
    assert_eq!(events[0].validated_merkleroot, "0x22");
    assert_eq!(blocked_shields[0].blinded_commitment, "0x44");
    assert_eq!(blocked_shields[0].block_reason.as_deref(), Some("blocked"));

    let signed = SignedPoiEvent {
        index: 8,
        blinded_commitment: FixedBytes::from([0x55; 32]),
        signature: "sig".to_string(),
        event_type: PoiEventType::Transact,
    };
    let json = to_value(signed).expect("serialize signed poi event");
    assert_eq!(json["type"], "Transact");
    assert_eq!(
        json["blindedCommitment"],
        "0x5555555555555555555555555555555555555555555555555555555555555555"
    );
}

#[test]
fn upstream_event_fixtures_deserialize() {
    let cases = [
        (
            include_str!("../../tests/fixtures/poi_event_shield.json"),
            PoiEventType::Shield,
        ),
        (
            include_str!("../../tests/fixtures/poi_event_transact.json"),
            PoiEventType::Transact,
        ),
        (
            include_str!("../../tests/fixtures/poi_event_unshield.json"),
            PoiEventType::Unshield,
        ),
        (
            include_str!("../../tests/fixtures/poi_event_legacy_transact.json"),
            PoiEventType::LegacyTransact,
        ),
    ];

    for (fixture, event_type) in cases {
        let event: PoiSyncedListEvent =
            serde_json::from_str(fixture).expect("deserialize POI event fixture");
        assert_eq!(event.signed_poi_event.event_type, event_type);
        assert_ne!(event.signed_poi_event.blinded_commitment, FixedBytes::ZERO);
        assert_ne!(event.signed_poi_event.signature, "");
        assert_ne!(event.validated_merkleroot, "");
    }
}

#[test]
fn upstream_blocked_shield_fixture_deserializes() {
    let record: SignedBlockedShield =
        serde_json::from_str(include_str!("../../tests/fixtures/blocked_shield.json"))
            .expect("deserialize blocked-shield fixture");

    assert_eq!(
        record.block_reason.as_deref(),
        Some("fixture blocked shield")
    );
    assert_ne!(record.commitment_hash, "");
    assert_ne!(record.blinded_commitment, "");
    assert_ne!(record.signature, "");
}

#[test]
fn missing_list_status_defaults_to_missing() {
    let blinded_commitment = FixedBytes::from([0x88; 32]);
    let response = BTreeMap::from([(
        hex::encode_prefixed(blinded_commitment),
        BTreeMap::from([("deadbeef".to_string(), PoiStatus::Valid)]),
    )]);
    let list_key = FixedBytes::from([0x11; 32]);
    let per_list = response
        .get(&hex::encode_prefixed(blinded_commitment))
        .cloned()
        .unwrap_or_default();

    let status = per_list
        .get(&hex::encode(list_key))
        .copied()
        .unwrap_or(PoiStatus::Missing);
    assert_eq!(status, PoiStatus::Missing);
}

#[test]
fn txid_leaf_hash_matches_existing_poseidon_path() {
    let leaf = railgun_txid_leaf_hash(uint!(1_U256), 2);
    assert_ne!(leaf, U256::ZERO);
}

#[test]
fn decode_json_rpc_success_response() {
    let result: bool = decode_json_rpc_response(r#"{"result":true}"#).expect("decode result");
    assert!(result);
}

#[test]
fn decode_json_rpc_error_response() {
    let error = decode_json_rpc_response::<bool>(
        r#"{"error":{"code":-32000,"message":"invalid proof","data":{"detail":"bad npk"}}}"#,
    )
    .expect_err("json-rpc error");

    match error {
        PoiRpcError::JsonRpc {
            code,
            message,
            data,
        } => {
            assert_eq!(code, -32000);
            assert_eq!(message, "invalid proof");
            assert_eq!(data.expect("data")["detail"], "bad npk");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn decode_json_rpc_missing_result_is_decode_error() {
    let error = decode_json_rpc_response::<bool>(r"{}").expect_err("missing result error");

    assert!(matches!(error, PoiRpcError::MissingResult));
}

#[test]
fn decode_json_rpc_ack_response_without_result_is_success() {
    decode_json_rpc_ack_response("test_method", r#"{"jsonrpc":"2.0","id":2}"#)
        .expect("ack response should succeed");
}

#[test]
fn decode_json_rpc_ack_response_with_error_fails() {
    let error = decode_json_rpc_ack_response(
        "test_method",
        r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32000,"message":"bad request"}}"#,
    )
    .expect_err("ack error");

    assert!(matches!(error, PoiRpcError::JsonRpc { .. }));
}
