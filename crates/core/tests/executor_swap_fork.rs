//! Opt-in mainnet-fork check of the guarded swap post-hook against the deployed
//! `RelayAdapt7702` delegate.
//!
//! `ETH_FORK_RPC_URL=<mainnet RPC> cargo test -p broadcaster-core --test executor_swap_fork -- --ignored`
//!
//! Set `ANVIL_BIN` when `anvil` is not on `PATH`.

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use alloy::eips::eip7702::Authorization;
use alloy::network::{EthereumWallet, TransactionBuilder, TransactionBuilder7702};
use alloy::primitives::aliases::U120;
use alloy::primitives::{Address, B256, Bytes, U256, address};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::{TransactionReceipt, TransactionRequest};
use alloy::signers::SignerSync;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::SolCall;
use alloy::transports::http::reqwest::Url;
use broadcaster_core::contracts::executor::{
    guarded_shield_calls, post_hook_signing_hash, signed_post_hook_calldata,
};
use broadcaster_core::contracts::railgun::{
    CommitmentPreimage, RelayAdapt7702, ShieldCiphertext, ShieldRequest, TokenData,
};

const RELAY_ADAPT_7702: Address = address!("0x05ae73c5925d843864ae6f261f3175de2ebcd963");
const WETH: Address = address!("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
// `PUSH1 0x20 PUSH1 0x00 RETURN`: answers every call with 32 zero bytes, so
// ERC-20 `transfer` returns `false` instead of reverting, whatever the balance.
const FALSE_TOKEN_CODE: [u8; 5] = [0x60, 0x20, 0x60, 0x00, 0xf3];
const GAS_LIMIT: u64 = 2_000_000;

sol! {
    interface IWETH {
        function deposit() payable;
        function transfer(address to, uint256 amount) returns (bool);
        function balanceOf(address owner) view returns (uint256);
    }
}

struct Anvil(Child);

impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

// Railgun validates only the preimage: the helper sets the nonzero value, and
// the npk must be in the SNARK field. The ciphertext is not checked on chain.
const fn full_balance_shield(token: Address) -> ShieldRequest {
    ShieldRequest {
        preimage: CommitmentPreimage {
            npk: B256::with_last_byte(1),
            token: TokenData::erc20(token),
            value: U120::ZERO,
        },
        ciphertext: ShieldCiphertext {
            encryptedBundle: [B256::ZERO; 3],
            shieldKey: B256::ZERO,
        },
    }
}

async fn send(provider: &impl Provider, tx: TransactionRequest) -> TransactionReceipt {
    provider
        .send_transaction(tx.with_gas_limit(GAS_LIMIT))
        .await
        .expect("send transaction")
        .get_receipt()
        .await
        .expect("transaction receipt")
}

async fn execution_nonce(provider: &impl Provider, executor: Address) -> U256 {
    let output = provider
        .call(
            TransactionRequest::default()
                .with_to(executor)
                .with_input(RelayAdapt7702::nonceCall {}.abi_encode()),
        )
        .await
        .expect("nonce call");
    RelayAdapt7702::nonceCall::abi_decode_returns(&output).expect("nonce")
}

async fn weth_balance(provider: &impl Provider, owner: Address) -> U256 {
    let output = provider
        .call(
            TransactionRequest::default()
                .with_to(WETH)
                .with_input(IWETH::balanceOfCall { owner }.abi_encode()),
        )
        .await
        .expect("balanceOf call");
    IWETH::balanceOfCall::abi_decode_returns(&output).expect("balance")
}

/// Submit a signed guarded post-hook at the current execution nonce and return
/// whether it succeeded, with the nonce it was signed for.
async fn submit_post_hook(
    provider: &impl Provider,
    executor: &PrivateKeySigner,
    chain_id: u64,
    token: Address,
    amount: U256,
) -> (bool, U256) {
    let executor_address = executor.address();
    let nonce = execution_nonce(provider, executor_address).await;
    let calls =
        guarded_shield_calls(executor_address, token, amount, full_balance_shield(token)).unwrap();
    let signature = executor
        .sign_hash_sync(&post_hook_signing_hash(
            &calls,
            nonce,
            chain_id,
            executor_address,
        ))
        .unwrap();
    let calldata =
        signed_post_hook_calldata(calls, nonce, chain_id, executor_address, &signature).unwrap();
    let receipt = send(
        provider,
        TransactionRequest::default()
            .with_to(executor_address)
            .with_input(calldata),
    )
    .await;
    (receipt.status(), nonce)
}

#[tokio::test]
#[ignore = "needs ETH_FORK_RPC_URL and anvil"]
async fn guarded_post_hook_reverts_without_balance_and_shields_full_balance() {
    let fork_url = std::env::var("ETH_FORK_RPC_URL").expect("ETH_FORK_RPC_URL is not set");
    let port = TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("free port")
        .port();
    let _anvil = Anvil(
        Command::new(std::env::var("ANVIL_BIN").unwrap_or_else(|_| "anvil".to_owned()))
            .args(["--fork-url", fork_url.as_str(), "--hardfork", "prague"])
            .args(["--port", port.to_string().as_str()])
            .stdout(Stdio::null())
            .spawn()
            .expect("spawn anvil"),
    );

    let funder = PrivateKeySigner::random();
    let executor = PrivateKeySigner::random();
    let executor_address = executor.address();
    let url: Url = format!("http://127.0.0.1:{port}").parse().unwrap();
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(funder.clone()))
        .connect_http(url);

    let mut chain_id = None;
    for _ in 0..120 {
        if let Ok(id) = provider.get_chain_id().await {
            chain_id = Some(id);
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let chain_id = chain_id.expect("anvil did not start");

    let _: serde_json::Value = provider
        .raw_request(
            "anvil_setBalance".into(),
            (
                funder.address(),
                U256::from(100_u64) * U256::from(10_u64).pow(U256::from(18)),
            ),
        )
        .await
        .unwrap();

    // Install the delegate at the executor from the funder's type-4 transaction.
    let authorization = Authorization {
        chain_id: U256::from(chain_id),
        address: RELAY_ADAPT_7702,
        nonce: 0,
    };
    let authorization_signature = executor
        .sign_hash_sync(&authorization.signature_hash())
        .unwrap();
    let receipt = send(
        &provider,
        TransactionRequest::default()
            .with_to(executor_address)
            .with_authorization_list(vec![authorization.into_signed(authorization_signature)]),
    )
    .await;
    assert!(receipt.status());
    assert_eq!(
        provider
            .get_code_at(executor_address)
            .await
            .unwrap()
            .to_vec(),
        [&[0xef, 0x01, 0x00][..], RELAY_ADAPT_7702.as_slice()].concat()
    );

    let amount = U256::from(10_u64).pow(U256::from(15));

    // (a) No buy-token balance: the exact self-transfer reverts, rolling back the nonce.
    let (succeeded, nonce) = submit_post_hook(&provider, &executor, chain_id, WETH, amount).await;
    assert!(!succeeded);
    assert_eq!(execution_nonce(&provider, executor_address).await, nonce);

    // (b) A token whose `transfer` returns `false` also reverts under `SafeERC20`.
    let false_token = Address::repeat_byte(0xfa);
    let _: serde_json::Value = provider
        .raw_request(
            "anvil_setCode".into(),
            (false_token, Bytes::from_static(&FALSE_TOKEN_CODE)),
        )
        .await
        .unwrap();
    let (succeeded, _) =
        submit_post_hook(&provider, &executor, chain_id, false_token, amount).await;
    assert!(!succeeded);
    assert_eq!(execution_nonce(&provider, executor_address).await, nonce);

    // (c) With more than the guarded amount, the whole balance is shielded.
    let funded = amount * U256::from(2);
    let receipt = send(
        &provider,
        TransactionRequest::default()
            .with_to(WETH)
            .with_value(funded)
            .with_input(IWETH::depositCall {}.abi_encode()),
    )
    .await;
    assert!(receipt.status());
    let receipt = send(
        &provider,
        TransactionRequest::default().with_to(WETH).with_input(
            IWETH::transferCall {
                to: executor_address,
                amount: funded,
            }
            .abi_encode(),
        ),
    )
    .await;
    assert!(receipt.status());
    assert_eq!(weth_balance(&provider, executor_address).await, funded);

    let (succeeded, _) = submit_post_hook(&provider, &executor, chain_id, WETH, amount).await;
    assert!(succeeded);
    assert_eq!(
        execution_nonce(&provider, executor_address).await,
        nonce + U256::ONE
    );
    assert_eq!(weth_balance(&provider, executor_address).await, U256::ZERO);
}
