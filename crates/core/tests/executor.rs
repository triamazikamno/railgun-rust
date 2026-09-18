use alloy::primitives::{Address, B256, Bytes, Signature, U256};
use alloy::sol_types::SolCall;
use broadcaster_core::contracts::executor::{
    execute_payload_hash, execute_signing_hash, is_executor_signature, multicall_payload_hash,
    multicall_signing_hash,
};
use broadcaster_core::contracts::railgun::{RelayAdapt7702, executeCall};
use broadcaster_core::transact::{BroadcasterAuthorization, BroadcasterRawParamsTransact};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/executor.json")).expect("public SDK fixture")
}

fn bytes(value: &Value) -> Bytes {
    value
        .as_str()
        .expect("hex string")
        .parse()
        .expect("hex bytes")
}

fn hash(value: &Value) -> B256 {
    value.as_str().expect("hash string").parse().expect("hash")
}

#[test]
fn execute_matches_sdk_and_binds_proved_payload_nonce_chain_and_owner() {
    let fixture = fixture();
    let executor: Address = fixture["executor"].as_str().unwrap().parse().unwrap();
    for vector in fixture["executions"].as_array().unwrap() {
        let encoded = bytes(&vector["calldata"]);
        let call = RelayAdapt7702::executeCall::abi_decode(&encoded).expect("current execute");
        assert_eq!(call.abi_encode(), encoded.as_ref());
        assert_eq!(
            execute_payload_hash(&call._transactions, &call._actionData, call._nonce),
            hash(&vector["payloadHash"])
        );
        let signing_hash = execute_signing_hash(
            &call._transactions,
            &call._actionData,
            call._nonce,
            1,
            executor,
        );
        assert_eq!(signing_hash, hash(&vector["signingHash"]));
        let signature = Signature::try_from(call._signature.as_ref()).expect("owner signature");
        assert!(is_executor_signature(&signature, &signing_hash, executor));

        let mut changed_transaction = call._transactions.clone();
        changed_transaction[0].nullifiers[0] = B256::ZERO;
        let mut changed_action = call._actionData.clone();
        changed_action.calls[0].value += U256::ONE;
        let other = Address::repeat_byte(0xab);
        for changed_hash in [
            execute_signing_hash(
                &changed_transaction,
                &call._actionData,
                call._nonce,
                1,
                executor,
            ),
            execute_signing_hash(
                &call._transactions,
                &changed_action,
                call._nonce,
                1,
                executor,
            ),
            execute_signing_hash(
                &call._transactions,
                &call._actionData,
                call._nonce + U256::ONE,
                1,
                executor,
            ),
            execute_signing_hash(
                &call._transactions,
                &call._actionData,
                call._nonce,
                56,
                executor,
            ),
            execute_signing_hash(
                &call._transactions,
                &call._actionData,
                call._nonce,
                1,
                other,
            ),
        ] {
            assert!(!is_executor_signature(&signature, &changed_hash, executor));
        }
        assert!(!is_executor_signature(&signature, &signing_hash, other));
        assert!(executeCall::abi_decode(&encoded).is_err());
    }
    let historical = bytes(&fixture["historicalCalldata"]);
    let decoded = executeCall::abi_decode(&historical).expect("historical execute");
    assert_eq!(decoded.abi_encode(), historical.as_ref());
    assert!(RelayAdapt7702::executeCall::abi_decode(&historical).is_err());
}

#[test]
fn signed_multicall_matches_reference_and_cannot_authorize_execute_or_changed_recovery() {
    let fixture = fixture();
    let executor: Address = fixture["executor"].as_str().unwrap().parse().unwrap();
    let vector = &fixture["multicall"];
    let encoded = bytes(&vector["calldata"]);
    let call = RelayAdapt7702::multicallCall::abi_decode(&encoded).expect("signed multicall");
    assert_eq!(call.abi_encode(), encoded.as_ref());
    assert_eq!(
        multicall_payload_hash(call._requireSuccess, &call._calls, call._nonce),
        hash(&vector["payloadHash"])
    );
    let signing_hash =
        multicall_signing_hash(call._requireSuccess, &call._calls, call._nonce, 1, executor);
    assert_eq!(signing_hash, hash(&vector["signingHash"]));
    let signature = Signature::try_from(call._signature.as_ref()).expect("owner signature");
    assert!(is_executor_signature(&signature, &signing_hash, executor));
    let execute =
        RelayAdapt7702::executeCall::abi_decode(&bytes(&fixture["executions"][1]["calldata"]))
            .unwrap();
    let mut changed_calls = call._calls.clone();
    changed_calls[0].to = Address::repeat_byte(0xab);
    for changed_hash in [
        multicall_signing_hash(false, &call._calls, call._nonce, 1, executor),
        multicall_signing_hash(true, &changed_calls, call._nonce, 1, executor),
        multicall_signing_hash(true, &call._calls, call._nonce + U256::ONE, 1, executor),
        multicall_signing_hash(true, &call._calls, call._nonce, 56, executor),
        multicall_signing_hash(
            true,
            &call._calls,
            call._nonce,
            1,
            Address::repeat_byte(0xab),
        ),
        execute_signing_hash(
            &execute._transactions,
            &execute._actionData,
            execute._nonce,
            1,
            executor,
        ),
    ] {
        assert!(!is_executor_signature(&signature, &changed_hash, executor));
    }
}

#[test]
fn sdk_and_historical_authorizations_preserve_parity_chain_and_extension_fields() {
    // Frozen released Rust decoder: v is a JSON number, not an RPC hex quantity.
    #[derive(serde::Deserialize)]
    struct ReleasedSignature {
        v: u64,
        r: U256,
        s: U256,
    }

    let fixture = fixture();
    let executor: Address = fixture["executor"].as_str().unwrap().parse().unwrap();
    for vector in fixture["authorizations"].as_array().unwrap() {
        let auth: BroadcasterAuthorization = serde_json::from_value(vector.clone()).unwrap();
        let signed = auth.signed_authorization().unwrap();
        assert_eq!(
            signed
                .signature()
                .unwrap()
                .recover_address_from_prehash(&signed.inner().signature_hash())
                .unwrap(),
            executor
        );
        for v in [0, 1, 27, 28] {
            let mut authorization = vector.clone();
            let signature = authorization["signature"].as_object_mut().unwrap();
            signature.remove("yParity");
            signature.insert("v".into(), v.into());
            signature.insert(
                "signatureExtension".into(),
                serde_json::json!({"accepted": true}),
            );
            authorization["authorizationExtension"] = serde_json::json!(["preserve", 9]);
            let request = serde_json::json!({
                "chainType": 0, "chainID": 1, "transactType": "TX7702",
                "minGasPrice": null, "maxFeePerGas": "1000000000", "maxPriorityFeePerGas": "1",
                "feesID": "fixture", "to": executor, "data": fixture["executions"][1]["calldata"],
                "broadcasterViewingKey": B256::ZERO, "txidVersion": null,
                "authorization": authorization,
                "preTransactionPOIsPerTxidLeafPerList": {},
                "requestExtension": {"preserve": [1, 2]},
            });
            let decoded: BroadcasterRawParamsTransact =
                serde_json::from_value(request.clone()).unwrap();
            let auth = decoded.authorization.as_ref().unwrap();
            assert_eq!(auth.signature.v(), v == 1 || v == 28);
            assert_eq!(
                auth.chain_id.to_string(),
                vector["chainId"].as_str().unwrap()
            );
            let encoded = serde_json::to_value(&decoded).unwrap();
            let outgoing_signature = &encoded["authorization"]["signature"];
            let released: ReleasedSignature = serde_json::from_value(outgoing_signature.clone())
                .expect("outgoing signature must remain readable by released broadcasters");
            assert_eq!(released.v, 27 + u64::from(auth.signature.v()));
            assert_eq!(released.r, auth.signature.r());
            assert_eq!(released.s, auth.signature.s());
            assert_eq!(encoded["requestExtension"], request["requestExtension"]);
            assert_eq!(
                encoded["authorization"]["authorizationExtension"],
                request["authorization"]["authorizationExtension"]
            );
            assert_eq!(
                encoded["authorization"]["signature"]["signatureExtension"],
                request["authorization"]["signature"]["signatureExtension"]
            );
            let roundtrip: BroadcasterRawParamsTransact = serde_json::from_value(encoded).unwrap();
            assert_eq!(
                roundtrip
                    .authorization
                    .unwrap()
                    .signed_authorization()
                    .unwrap(),
                auth.signed_authorization().unwrap()
            );
        }
    }
    // The old wire format accepted a full U256 nonce. Envelope conversion,
    // not a new JSON validator, rejects a nonce that cannot fit Ethereum.
    let mut authorization = fixture["authorizations"][0].clone();
    authorization["nonce"] = U256::MAX.to_string().into();
    let wide: BroadcasterAuthorization = serde_json::from_value(authorization).unwrap();
    assert!(wide.signed_authorization().is_err());
}
