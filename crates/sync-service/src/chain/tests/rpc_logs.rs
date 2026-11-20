use super::*;

pub(super) fn rpc_nullifiers_log(contract: Address, block_number: u64) -> serde_json::Value {
    rpc_nullifiers_log_with_value(contract, block_number, U256::from(7))
}

pub(super) fn rpc_nullifiers_log_with_value(
    contract: Address,
    block_number: u64,
    nullifier: U256,
) -> serde_json::Value {
    let encoded = Nullifiers {
        treeNumber: U256::from(1),
        nullifier: vec![nullifier],
    }
    .encode_log_data();
    let topics = encoded
        .topics()
        .iter()
        .map(|topic| format!("{topic:#x}"))
        .collect::<Vec<_>>();
    serde_json::json!({
        "address": format!("{contract:#x}"),
        "topics": topics,
        "data": format!("0x{}", hex::encode(encoded.data)),
        "blockHash": format!("{:#x}", FixedBytes::<32>::from([0x11; 32])),
        "blockNumber": format!("{block_number:#x}"),
        "transactionHash": format!("{:#x}", FixedBytes::<32>::from([0x33; 32])),
        "transactionIndex": "0x0",
        "logIndex": "0x0",
        "removed": false,
    })
}

pub(super) fn indexed_wallet_nullifier_page(block_number: u64, nullifier: U256) -> String {
    serde_json::json!({
        "data": {
            "transactCommitments": [],
            "shieldCommitments": [],
            "nullifiers": [{
                "id": format!("0x{}", "33".repeat(64)),
                "transactionHash": format!("0x{}", "aa".repeat(32)),
                "blockNumber": block_number.to_string(),
                "blockTimestamp": block_number.saturating_add(1_700_000_000).to_string(),
                "treeNumber": 1,
                "nullifier": format!("{nullifier:#x}"),
            }],
        }
    })
    .to_string()
}

pub(super) fn rpc_block(block_number: u64, timestamp: u64, hash_byte: u8) -> serde_json::Value {
    let zero_hash = format!("{:#x}", FixedBytes::<32>::ZERO);
    serde_json::json!({
        "hash": format!("{:#x}", FixedBytes::<32>::from([hash_byte; 32])),
        "parentHash": zero_hash,
        "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        "miner": format!("{:#x}", Address::ZERO),
        "stateRoot": zero_hash,
        "transactionsRoot": zero_hash,
        "receiptsRoot": zero_hash,
        "logsBloom": format!("0x{}", "00".repeat(256)),
        "difficulty": "0x0",
        "number": format!("{block_number:#x}"),
        "gasLimit": "0x0",
        "gasUsed": "0x0",
        "timestamp": format!("{timestamp:#x}"),
        "extraData": "0x",
        "mixHash": zero_hash,
        "nonce": "0x0000000000000000",
        "transactions": [],
        "uncles": [],
    })
}

pub(super) fn hex_quantity(value: &serde_json::Value) -> u64 {
    let hex = value.as_str().expect("hex quantity");
    u64::from_str_radix(hex.trim_start_matches("0x"), 16).expect("hex quantity")
}

pub(super) const fn test_block_timestamp(block_number: u64) -> u64 {
    1_700_000_000 + block_number
}

pub(super) fn rpc_nullifiers_log_with_timestamp(
    contract: Address,
    block_number: u64,
) -> serde_json::Value {
    let mut log = rpc_nullifiers_log(contract, block_number);
    log["blockTimestamp"] = serde_json::json!(format!("{:#x}", test_block_timestamp(block_number)));
    log
}

pub(super) fn rpc_error(code: i64, message: &str) -> serde_json::Value {
    serde_json::json!({ "code": code, "message": message })
}

pub(super) fn reject_spans_over_25(
    from_block: u64,
    to_block: u64,
    _log_count: usize,
) -> Option<serde_json::Value> {
    (to_block - from_block + 1 > 25)
        .then(|| rpc_error(-32000, "log query range must not exceed 25 blocks"))
}

/// Serves `eth_getLogs` from `logs` unless `reject` returns an error for the
/// requested range and its log count, plus block-number and header reads.
pub(super) fn log_range_rpc_handler(
    logs: Vec<serde_json::Value>,
    head: u64,
    reject: impl Fn(u64, u64, usize) -> Option<serde_json::Value> + Send + 'static,
) -> impl Fn(&serde_json::Value) -> serde_json::Value + Send + 'static {
    move |request: &serde_json::Value| {
        let params = &request["params"];
        match request["method"].as_str() {
            Some("eth_getLogs") => {
                let from_block = hex_quantity(&params[0]["fromBlock"]);
                let to_block = hex_quantity(&params[0]["toBlock"]);
                let matching = logs
                    .iter()
                    .filter(|log| {
                        (from_block..=to_block).contains(&hex_quantity(&log["blockNumber"]))
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                reject(from_block, to_block, matching.len()).map_or_else(
                    || serde_json::json!({ "result": matching }),
                    |error| serde_json::json!({ "error": error }),
                )
            }
            Some("eth_blockNumber") => serde_json::json!({ "result": format!("{head:#x}") }),
            Some("eth_getBlockByNumber") => {
                let block_number = hex_quantity(&params[0]);
                serde_json::json!({
                    "result": rpc_block(block_number, test_block_timestamp(block_number), 0x11),
                })
            }
            _ => serde_json::json!({ "error": rpc_error(-32601, "method not found") }),
        }
    }
}

/// Serves requests through `serve`, holding each listed `eth_getLogs` range,
/// in order, until its receiver yields.
pub(super) fn gated_get_logs_handler(
    serve: impl Fn(&serde_json::Value) -> serde_json::Value + Send + 'static,
    gates: Vec<((u64, u64), std_mpsc::Receiver<()>)>,
) -> impl Fn(&serde_json::Value) -> serde_json::Value + Send + 'static {
    let gates = std::sync::Mutex::new(std::collections::VecDeque::from(gates));
    move |request: &serde_json::Value| {
        if request["method"] == "eth_getLogs" {
            let range = (
                hex_quantity(&request["params"][0]["fromBlock"]),
                hex_quantity(&request["params"][0]["toBlock"]),
            );
            let gate = {
                let mut gates = gates.lock().expect("gate lock");
                if gates.front().is_some_and(|(gated, _)| *gated == range) {
                    gates.pop_front()
                } else {
                    None
                }
            };
            if let Some((_, release)) = gate {
                let _ = release.recv();
            }
        }
        serve(request)
    }
}

pub(super) fn get_logs_ranges(bodies: &[serde_json::Value]) -> Vec<(u64, u64)> {
    bodies
        .iter()
        .filter(|body| body["method"] == "eth_getLogs")
        .map(|body| {
            (
                hex_quantity(&body["params"][0]["fromBlock"]),
                hex_quantity(&body["params"][0]["toBlock"]),
            )
        })
        .collect()
}

pub(super) fn header_blocks(bodies: &[serde_json::Value]) -> Vec<u64> {
    bodies
        .iter()
        .filter(|body| body["method"] == "eth_getBlockByNumber")
        .map(|body| hex_quantity(&body["params"][0]))
        .collect()
}

pub(super) fn log_fetch_chain(scope: &ChainScope, rpc_url: Url, block_range: u64) -> ChainConfig {
    let rpcs = Arc::new(QueryRpcPool::new(vec![rpc_url], Duration::from_secs(1)));
    let mut chain = test_chain_config(scope, rpcs, None);
    chain.sync.block_range = block_range;
    chain
}

pub(super) fn rpc_event_log(
    contract: Address,
    block_number: u64,
    encoded: &alloy::primitives::LogData,
) -> serde_json::Value {
    let topics = encoded
        .topics()
        .iter()
        .map(|topic| format!("{topic:#x}"))
        .collect::<Vec<_>>();
    serde_json::json!({
        "address": format!("{contract:#x}"),
        "topics": topics,
        "data": format!("0x{}", hex::encode(&encoded.data)),
        "blockHash": format!("{:#x}", FixedBytes::<32>::from([0x11; 32])),
        "blockNumber": format!("{block_number:#x}"),
        "transactionHash": format!("{:#x}", FixedBytes::<32>::from([0x33; 32])),
        "transactionIndex": "0x0",
        "logIndex": "0x0",
        "removed": false,
    })
}
