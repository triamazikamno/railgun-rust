use alloy::primitives::{Bytes, U256, keccak256};
use alloy::sol_types::SolCall;
use serde::Deserialize;

use crate::contracts::railgun::{
    RelayAdapt7702ActionData, RelayAdapt7702Current, RelayAdapt7702Legacy, Transaction, executeCall,
};

const CURRENT_ABI: &str =
    include_str!("../../../resources/abi/relay-adapt-7702/RelayAdapt7702.json");
const LEGACY_ABI: &str = include_str!(
    "../../../resources/abi/relay-adapt-7702/RelayAdapt7702_Legacy_PreExecuteNonce.json"
);
const RAILGUN_SELECTOR: [u8; 4] = [0x40, 0x13, 0x07, 0x4d];
const W_BASE_SELECTOR: [u8; 4] = [0x77, 0x32, 0x1c, 0x75];
const ADAPT_IMPLEMENTATION_SELECTOR: [u8; 4] = [0x93, 0xc7, 0x6f, 0x67];
const DOMAIN_SEPARATOR_SELECTOR: [u8; 4] = [0x36, 0x44, 0xe5, 0x15];
const EXECUTE_TYPEHASH_SELECTOR: [u8; 4] = [0x60, 0xd2, 0xf3, 0x3d];
const MULTICALL_TYPEHASH_SELECTOR: [u8; 4] = [0xc3, 0x40, 0x6f, 0xd7];
const NONCE_SELECTOR: [u8; 4] = [0xaf, 0xfe, 0xd0, 0xe0];
const CURRENT_EXECUTE_SELECTOR: [u8; 4] = [0x3e, 0x12, 0xcc, 0x2e];
const LEGACY_EXECUTE_SELECTOR: [u8; 4] = [0xc6, 0x1e, 0x6b, 0x9d];
const CURRENT_PAYLOAD_HASH_SELECTOR: [u8; 4] = [0xa4, 0xef, 0x31, 0xfd];
const LEGACY_PAYLOAD_HASH_SELECTOR: [u8; 4] = [0x85, 0x52, 0x51, 0xa4];

#[derive(Debug, Deserialize)]
struct AbiItem {
    #[serde(rename = "type")]
    item_type: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    inputs: Vec<AbiParam>,
    #[serde(default)]
    outputs: Vec<AbiParam>,
    #[serde(rename = "stateMutability", default)]
    state_mutability: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AbiParam {
    #[serde(default)]
    name: Option<String>,
    #[serde(rename = "type")]
    param_type: String,
    #[serde(default)]
    components: Option<Vec<Self>>,
}

struct ExpectedParam {
    name: &'static str,
    param_type: &'static str,
    components: Vec<Self>,
}

impl ExpectedParam {
    fn new(name: &'static str, param_type: &'static str, components: Vec<Self>) -> Self {
        Self {
            name,
            param_type,
            components,
        }
    }
}

fn expected(
    name: &'static str,
    param_type: &'static str,
    components: Vec<ExpectedParam>,
) -> ExpectedParam {
    ExpectedParam::new(name, param_type, components)
}

fn g1_point(name: &'static str) -> ExpectedParam {
    expected(
        name,
        "tuple",
        vec![
            expected("x", "uint256", vec![]),
            expected("y", "uint256", vec![]),
        ],
    )
}

fn transaction_fields() -> Vec<ExpectedParam> {
    vec![
        expected(
            "proof",
            "tuple",
            vec![
                g1_point("a"),
                expected(
                    "b",
                    "tuple",
                    vec![
                        expected("x", "uint256[2]", vec![]),
                        expected("y", "uint256[2]", vec![]),
                    ],
                ),
                g1_point("c"),
            ],
        ),
        expected("merkleRoot", "bytes32", vec![]),
        expected("nullifiers", "bytes32[]", vec![]),
        expected("commitments", "bytes32[]", vec![]),
        expected(
            "boundParams",
            "tuple",
            vec![
                expected("treeNumber", "uint16", vec![]),
                expected("minGasPrice", "uint72", vec![]),
                expected("unshield", "uint8", vec![]),
                expected("chainID", "uint64", vec![]),
                expected("adaptContract", "address", vec![]),
                expected("adaptParams", "bytes32", vec![]),
                expected(
                    "commitmentCiphertext",
                    "tuple[]",
                    vec![
                        expected("ciphertext", "bytes32[4]", vec![]),
                        expected("blindedSenderViewingKey", "bytes32", vec![]),
                        expected("blindedReceiverViewingKey", "bytes32", vec![]),
                        expected("annotationData", "bytes", vec![]),
                        expected("memo", "bytes", vec![]),
                    ],
                ),
            ],
        ),
        expected(
            "unshieldPreimage",
            "tuple",
            vec![
                expected("npk", "bytes32", vec![]),
                expected(
                    "token",
                    "tuple",
                    vec![
                        expected("tokenType", "uint8", vec![]),
                        expected("tokenAddress", "address", vec![]),
                        expected("tokenSubID", "uint256", vec![]),
                    ],
                ),
                expected("value", "uint120", vec![]),
            ],
        ),
    ]
}

fn call_fields() -> Vec<ExpectedParam> {
    vec![
        expected("to", "address", vec![]),
        expected("data", "bytes", vec![]),
        expected("value", "uint256", vec![]),
    ]
}

fn action_data_fields() -> Vec<ExpectedParam> {
    vec![
        expected("requireSuccess", "bool", vec![]),
        expected("minGasLimit", "uint256", vec![]),
        expected("calls", "tuple[]", call_fields()),
    ]
}

fn parse_abi(source: &str, artifact: &str) -> Vec<AbiItem> {
    serde_json::from_str(source)
        .unwrap_or_else(|error| panic!("{artifact}: parse ABI snapshot: {error}"))
}

fn find_function<'a>(abi: &'a [AbiItem], artifact: &str, name: &str, arity: usize) -> &'a AbiItem {
    let matches: Vec<&AbiItem> = abi
        .iter()
        .filter(|item| {
            item.item_type == "function"
                && item.name.as_deref() == Some(name)
                && item.inputs.len() == arity
        })
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "{artifact}: expected one {name} function with {arity} inputs, found {}",
        matches.len()
    );
    matches[0]
}

fn canonical_type(param: &AbiParam) -> String {
    let Some(components) = &param.components else {
        return param.param_type.clone();
    };
    let suffix = param
        .param_type
        .strip_prefix("tuple")
        .unwrap_or_else(|| panic!("tuple components on non-tuple type {}", param.param_type));
    let component_types = components
        .iter()
        .map(canonical_type)
        .collect::<Vec<_>>()
        .join(",");
    format!("({component_types}){suffix}")
}

fn canonical_signature(function: &AbiItem) -> String {
    let inputs = function
        .inputs
        .iter()
        .map(canonical_type)
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{}({inputs})",
        function.name.as_deref().unwrap_or("<unnamed>")
    )
}

fn expected_type(param: &ExpectedParam) -> String {
    if param.components.is_empty() {
        return param.param_type.to_string();
    }
    let suffix = param
        .param_type
        .strip_prefix("tuple")
        .unwrap_or_else(|| panic!("expected tuple components on {}", param.param_type));
    let component_types = param
        .components
        .iter()
        .map(expected_type)
        .collect::<Vec<_>>()
        .join(",");
    format!("({component_types}){suffix}")
}

fn selector(signature: &str) -> [u8; 4] {
    keccak256(signature.as_bytes())[..4]
        .try_into()
        .expect("keccak selector is four bytes")
}

fn assert_param(actual: &AbiParam, expected: &ExpectedParam, path: &str) {
    assert_eq!(actual.name.as_deref(), Some(expected.name), "{path}.name");
    assert_eq!(actual.param_type, expected.param_type, "{path}.type");
    match (&actual.components, expected.components.is_empty()) {
        (None, true) => {}
        (None, false) => panic!("{path}.components missing"),
        (Some(_), true) => panic!("{path}.components unexpected"),
        (Some(actual_components), false) => {
            assert_eq!(
                actual_components.len(),
                expected.components.len(),
                "{path}.components.len"
            );
            for (index, (actual, expected)) in actual_components
                .iter()
                .zip(&expected.components)
                .enumerate()
            {
                assert_param(actual, expected, &format!("{path}.components[{index}]"));
            }
        }
    }
}

fn assert_same_param(left: &AbiParam, right: &AbiParam, path: &str) {
    assert_eq!(left.name, right.name, "{path}.name");
    assert_eq!(left.param_type, right.param_type, "{path}.type");
    assert_eq!(
        left.components.is_some(),
        right.components.is_some(),
        "{path}.components presence"
    );
    if let (Some(left), Some(right)) = (&left.components, &right.components) {
        assert_eq!(left.len(), right.len(), "{path}.components.len");
        for (index, (left, right)) in left.iter().zip(right).enumerate() {
            assert_same_param(left, right, &format!("{path}.components[{index}]"));
        }
    }
}

fn assert_param_types(function: &AbiItem, expected: &[&str], path: &str, inputs: bool) {
    let params = if inputs {
        &function.inputs
    } else {
        &function.outputs
    };
    assert_eq!(params.len(), expected.len(), "{path}.len");
    for (index, (actual, expected)) in params.iter().zip(expected).enumerate() {
        assert_eq!(canonical_type(actual), *expected, "{path}[{index}]");
    }
}

fn assert_function_surface(
    function: &AbiItem,
    path: &str,
    input_types: &[&str],
    output_types: &[&str],
    state_mutability: &str,
) {
    assert_eq!(function.item_type, "function", "{path}.type");
    assert_eq!(
        function.state_mutability.as_deref(),
        Some(state_mutability),
        "{path}.stateMutability"
    );
    assert_param_types(function, input_types, &format!("{path}.inputs"), true);
    assert_param_types(function, output_types, &format!("{path}.outputs"), false);
}

fn assert_execute_shapes(abi: &[AbiItem], artifact: &str, execute_arity: usize) {
    let execute = find_function(abi, artifact, "execute", execute_arity);
    let transaction = expected("_transactions", "tuple[]", transaction_fields());
    let action_data = expected("_actionData", "tuple", action_data_fields());
    assert_param(
        &execute.inputs[0],
        &transaction,
        &format!("{artifact}.execute.inputs[0]"),
    );
    assert_param(
        &execute.inputs[1],
        &action_data,
        &format!("{artifact}.execute.inputs[1]"),
    );
}

macro_rules! assert_generated_call {
    ($abi:expr, $artifact:expr, $name:literal, $arity:expr, $call:ty, $expected_selector:expr) => {{
        let function = find_function($abi, $artifact, $name, $arity);
        let snapshot_signature = canonical_signature(function);
        assert_eq!(
            <$call as SolCall>::SIGNATURE,
            snapshot_signature,
            "{}.{} generated signature",
            $artifact,
            $name
        );
        assert_eq!(
            <$call as SolCall>::SELECTOR,
            $expected_selector,
            "{}.{} external selector",
            $artifact,
            $name
        );
        assert_eq!(
            <$call as SolCall>::SELECTOR,
            selector(&snapshot_signature),
            "{}.{} snapshot selector",
            $artifact,
            $name
        );
    }};
}

#[test]
fn snapshots_match_canonical_transaction_and_action_shapes() {
    let current = parse_abi(CURRENT_ABI, "current");
    let legacy = parse_abi(LEGACY_ABI, "legacy");

    assert_execute_shapes(&current, "current", 4);
    assert_execute_shapes(&legacy, "legacy", 3);

    let current_execute = find_function(&current, "current", "execute", 4);
    let legacy_execute = find_function(&legacy, "legacy", "execute", 3);
    assert_same_param(
        &current_execute.inputs[0],
        &legacy_execute.inputs[0],
        "current-versus-legacy.execute.transactions",
    );
    assert_same_param(
        &current_execute.inputs[1],
        &legacy_execute.inputs[1],
        "current-versus-legacy.execute.actionData",
    );

    for (artifact, abi, execute_arity, payload_arity) in
        [("current", &current, 4, 3), ("legacy", &legacy, 3, 2)]
    {
        let execute = find_function(abi, artifact, "execute", execute_arity);
        let payload_hash = find_function(abi, artifact, "getExecutePayloadHash", payload_arity);
        assert_same_param(
            &execute.inputs[0],
            &payload_hash.inputs[0],
            &format!("{artifact}.execute-versus-payloadHash.transactions"),
        );
        assert_same_param(
            &execute.inputs[1],
            &payload_hash.inputs[1],
            &format!("{artifact}.execute-versus-payloadHash.actionData"),
        );
    }
}

fn assert_required_surfaces(abi: &[AbiItem], artifact: &str, current: bool) {
    let address_getters = ["railgun", "wBase", "adaptImplementation"];
    for name in address_getters {
        let function = find_function(abi, artifact, name, 0);
        assert_function_surface(
            function,
            &format!("{artifact}.{name}"),
            &[],
            &["address"],
            "view",
        );
    }
    for name in ["DOMAIN_SEPARATOR", "EXECUTE_TYPEHASH", "MULTICALL_TYPEHASH"] {
        let function = find_function(abi, artifact, name, 0);
        assert_function_surface(
            function,
            &format!("{artifact}.{name}"),
            &[],
            &["bytes32"],
            "view",
        );
    }

    let nonce = find_function(abi, artifact, "nonce", 0);
    assert_function_surface(
        nonce,
        &format!("{artifact}.nonce"),
        &[],
        &["uint256"],
        "view",
    );

    let transaction_type =
        expected_type(&expected("_transactions", "tuple[]", transaction_fields()));
    let action_data_type = expected_type(&expected("_actionData", "tuple", action_data_fields()));
    let execute_arity = if current { 4 } else { 3 };
    let execute = find_function(abi, artifact, "execute", execute_arity);
    let execute_inputs = if current {
        vec![
            transaction_type.as_str(),
            action_data_type.as_str(),
            "uint256",
            "bytes",
        ]
    } else {
        vec![
            transaction_type.as_str(),
            action_data_type.as_str(),
            "bytes",
        ]
    };
    assert_function_surface(
        execute,
        &format!("{artifact}.execute"),
        &execute_inputs,
        &[],
        "payable",
    );

    let payload_arity = if current { 3 } else { 2 };
    let payload_hash = find_function(abi, artifact, "getExecutePayloadHash", payload_arity);
    let payload_inputs = if current {
        vec![execute_inputs[0], execute_inputs[1], "uint256"]
    } else {
        vec![execute_inputs[0], execute_inputs[1]]
    };
    assert_function_surface(
        payload_hash,
        &format!("{artifact}.getExecutePayloadHash"),
        &payload_inputs,
        &["bytes32"],
        "pure",
    );
}

#[test]
fn snapshots_match_required_function_surfaces_and_selectors() {
    let current = parse_abi(CURRENT_ABI, "current");
    let legacy = parse_abi(LEGACY_ABI, "legacy");
    assert_required_surfaces(&current, "current", true);
    assert_required_surfaces(&legacy, "legacy", false);

    assert_generated_call!(
        &current,
        "current",
        "railgun",
        0,
        RelayAdapt7702Current::railgunCall,
        RAILGUN_SELECTOR
    );
    assert_generated_call!(
        &current,
        "current",
        "wBase",
        0,
        RelayAdapt7702Current::wBaseCall,
        W_BASE_SELECTOR
    );
    assert_generated_call!(
        &current,
        "current",
        "adaptImplementation",
        0,
        RelayAdapt7702Current::adaptImplementationCall,
        ADAPT_IMPLEMENTATION_SELECTOR
    );
    assert_generated_call!(
        &current,
        "current",
        "DOMAIN_SEPARATOR",
        0,
        RelayAdapt7702Current::DOMAIN_SEPARATORCall,
        DOMAIN_SEPARATOR_SELECTOR
    );
    assert_generated_call!(
        &current,
        "current",
        "EXECUTE_TYPEHASH",
        0,
        RelayAdapt7702Current::EXECUTE_TYPEHASHCall,
        EXECUTE_TYPEHASH_SELECTOR
    );
    assert_generated_call!(
        &current,
        "current",
        "MULTICALL_TYPEHASH",
        0,
        RelayAdapt7702Current::MULTICALL_TYPEHASHCall,
        MULTICALL_TYPEHASH_SELECTOR
    );
    assert_generated_call!(
        &current,
        "current",
        "nonce",
        0,
        RelayAdapt7702Current::nonceCall,
        NONCE_SELECTOR
    );
    assert_generated_call!(
        &current,
        "current",
        "execute",
        4,
        RelayAdapt7702Current::executeCall,
        CURRENT_EXECUTE_SELECTOR
    );
    assert_generated_call!(
        &current,
        "current",
        "getExecutePayloadHash",
        3,
        RelayAdapt7702Current::getExecutePayloadHashCall,
        CURRENT_PAYLOAD_HASH_SELECTOR
    );

    assert_generated_call!(
        &legacy,
        "legacy",
        "railgun",
        0,
        RelayAdapt7702Legacy::railgunCall,
        RAILGUN_SELECTOR
    );
    assert_generated_call!(
        &legacy,
        "legacy",
        "wBase",
        0,
        RelayAdapt7702Legacy::wBaseCall,
        W_BASE_SELECTOR
    );
    assert_generated_call!(
        &legacy,
        "legacy",
        "adaptImplementation",
        0,
        RelayAdapt7702Legacy::adaptImplementationCall,
        ADAPT_IMPLEMENTATION_SELECTOR
    );
    assert_generated_call!(
        &legacy,
        "legacy",
        "DOMAIN_SEPARATOR",
        0,
        RelayAdapt7702Legacy::DOMAIN_SEPARATORCall,
        DOMAIN_SEPARATOR_SELECTOR
    );
    assert_generated_call!(
        &legacy,
        "legacy",
        "EXECUTE_TYPEHASH",
        0,
        RelayAdapt7702Legacy::EXECUTE_TYPEHASHCall,
        EXECUTE_TYPEHASH_SELECTOR
    );
    assert_generated_call!(
        &legacy,
        "legacy",
        "MULTICALL_TYPEHASH",
        0,
        RelayAdapt7702Legacy::MULTICALL_TYPEHASHCall,
        MULTICALL_TYPEHASH_SELECTOR
    );
    assert_generated_call!(
        &legacy,
        "legacy",
        "nonce",
        0,
        RelayAdapt7702Legacy::nonceCall,
        NONCE_SELECTOR
    );
    assert_generated_call!(
        &legacy,
        "legacy",
        "execute",
        3,
        RelayAdapt7702Legacy::executeCall,
        LEGACY_EXECUTE_SELECTOR
    );
    assert_generated_call!(
        &legacy,
        "legacy",
        "getExecutePayloadHash",
        2,
        RelayAdapt7702Legacy::getExecutePayloadHashCall,
        LEGACY_PAYLOAD_HASH_SELECTOR
    );

    let legacy_execute = find_function(&legacy, "legacy", "execute", 3);
    assert_eq!(
        executeCall::SIGNATURE,
        canonical_signature(legacy_execute),
        "top-level executeCall signature"
    );
    assert_eq!(executeCall::SELECTOR, LEGACY_EXECUTE_SELECTOR);
}

#[test]
fn namespaced_execute_calls_use_canonical_struct_types() {
    let current = RelayAdapt7702Current::executeCall {
        _transactions: Vec::<Transaction>::new(),
        _actionData: RelayAdapt7702ActionData {
            requireSuccess: true,
            minGasLimit: U256::ZERO,
            calls: Vec::new(),
        },
        _executeNonce: U256::ZERO,
        _signature: Bytes::new(),
    };
    let RelayAdapt7702Current::executeCall {
        _transactions: current_transactions,
        _actionData: action_data,
        _executeNonce: execute_nonce,
        _signature: signature,
    } = current;
    let _: Vec<Transaction> = current_transactions;
    let _: RelayAdapt7702ActionData = action_data;
    let _: U256 = execute_nonce;
    let _: Bytes = signature;

    let legacy = RelayAdapt7702Legacy::executeCall {
        _transactions: Vec::<Transaction>::new(),
        _actionData: RelayAdapt7702ActionData {
            requireSuccess: true,
            minGasLimit: U256::ZERO,
            calls: Vec::new(),
        },
        _signature: Bytes::new(),
    };
    let RelayAdapt7702Legacy::executeCall {
        _transactions: legacy_transactions,
        _actionData: action_data,
        _signature: signature,
    } = legacy;
    let _: Vec<Transaction> = legacy_transactions;
    let _: RelayAdapt7702ActionData = action_data;
    let _: Bytes = signature;
}
