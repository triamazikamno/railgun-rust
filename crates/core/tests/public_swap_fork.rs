//! Opt-in fork checks of a bridge deposit paid from a public account: the
//! `SpokePool` deposit an account sends itself, and the cow-shed post-hook that
//! deposits a proxy's whole balance after a `CoW` settlement.
//!
//! ```text
//! ETH_FORK_RPC_URL=<rpc> BNB_FORK_RPC_URL=<rpc> POLYGON_FORK_RPC_URL=<rpc> \
//! ARBITRUM_FORK_RPC_URL=<rpc> \
//!   cargo test -p broadcaster-core --test public_swap_fork -- --ignored --nocapture
//! ```
//!
//! Set `ANVIL_BIN` when `anvil` is not on `PATH`. Each test prints the facts it
//! observed, which is how the numbers in the change's verification record were
//! taken.

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use alloy::eips::BlockNumberOrTag;
use alloy::primitives::aliases::U120;
use alloy::primitives::{Address, B256, Bytes, U256, address, keccak256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::{TransactionReceipt, TransactionRequest};
use alloy::signers::SignerSync;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::{SolCall, SolEvent};
use alloy::transports::http::reqwest::Url;
use broadcaster_core::contracts::across::{
    SpokePool, address_to_bytes32, private_delivery_message, private_deposit_calldata,
};
use broadcaster_core::contracts::cow::{
    AppData, AppDataHook, ORDER_KIND_SELL, Order, TOKEN_BALANCE_ERC20, eip712_order_signature,
    order_digest,
};
use broadcaster_core::contracts::cow_shed::{
    COWShed, COWShedFactory, Call, ExecuteHooks, PROXY_CREATION_CODE, deposit_hook_calls,
    execute_hooks_calldata, execute_hooks_digest, proxy_address, withdrawal_calls,
};
use broadcaster_core::contracts::executor::{
    AcrossPrivateDelivery, guarded_shield_calls, post_hook_signing_hash, signed_post_hook_calldata,
};
use broadcaster_core::contracts::railgun::{
    CommitmentPreimage, RelayAdapt7702, Shield, ShieldCiphertext, ShieldRequest, TokenData,
};
use broadcaster_core::contracts::swap_math::{
    DETERMINISTIC_DEPLOYER, SWAP_MATH_ADDRESS, SWAP_MATH_RUNTIME_CODE_HASH, SwapMath,
    swap_math_deployment_calldata,
};
use broadcaster_core::contracts::weiroll::BalanceDeposit;

const COW_SHED_FACTORY: Address = address!("0x0a654985c5856ab562237286f36d55c0ff637213");
const COW_SHED_IMPLEMENTATION: Address = address!("0xF0D586aB0017fDfE2ACf4AB008B3Ddb2CF50bB09");
const WEIROLL: Address = address!("0x9585c3062Df1C247d5E373Cfca9167F7dC2b5963");
const COW_SHED_FACTORY_CODE_HASH: B256 =
    alloy::primitives::b256!("0x7e9943175529f6c63cfecd52f5c5d12247a6778e53ebbf4ece7d4c0c5b400a69");
const COW_SHED_IMPLEMENTATION_CODE_HASH: B256 =
    alloy::primitives::b256!("0x0dffac9c12c7213477b5b14f4004feb952ffcc74ae3cf14e00d3c2e753d02599");
const WEIROLL_CODE_HASH: B256 =
    alloy::primitives::b256!("0x0f9d0beeff8ae3bd5122b3bbbf9c19efbdc70470eced60bfbac542c2b601f998");

const SETTLEMENT: Address = address!("0x9008D19f58AAbD9eD0D60971565AA8510560ab41");
const VAULT_RELAYER: Address = address!("0xC92E8bdf79f0507f65a392b0ab4667716BFE0110");
const HOOKS_TRAMPOLINE: Address = address!("0x60Bf78233f48eC42eE3F101b9a05eC7878728006");
const SOLVER_AUTHENTICATION: Address = address!("0x2c4c28DDBdAc9C5E7055b4C863b72eA0149D8aFE");

const WETH: Address = address!("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
const USDC: Address = address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
const POLYGON_USDC: Address = address!("0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359");

const SOLVER: Address = Address::repeat_byte(0x50);
const RELAYER: Address = Address::repeat_byte(0x5e);
const CALLER: Address = Address::repeat_byte(0xc1);
const GAS_LIMIT: u64 = 3_000_000;
const SETTLEMENT_GAS: u64 = 12_000_000;

const SELL_AMOUNT: u64 = 10_000_000_000_000_000;
const BUY_AMOUNT: u64 = 15_000_000;
const DESTINATION_MIN: u64 = 14_900_000;
const SURPLUS: u64 = 1_000_000;
/// A generous hook gas limit; the tests print what the hook really used.
const HOOK_GAS_LIMIT: u64 = 1_500_000;

/// One of the four chains the wallet pins an Across `SpokePool` for.
#[derive(Clone, Copy)]
struct Chain {
    rpc_env: &'static str,
    id: u64,
    spoke_pool: Address,
    handler: Address,
    wrapped_native: Address,
    railgun: Address,
    delegate: Address,
}

const ETHEREUM: Chain = Chain {
    rpc_env: "ETH_FORK_RPC_URL",
    id: 1,
    spoke_pool: address!("0x5c7BCd6E7De5423a257D81B442095A1a6ced35C5"),
    handler: address!("0x924a9f036260DdD5808007E1AA95f08eD08aA569"),
    wrapped_native: WETH,
    railgun: address!("0xFA7093CDD9EE6932B4eb2c9e1cde7CE00B1FA4b9"),
    delegate: address!("0x05ae73c5925d843864ae6f261f3175de2ebcd963"),
};
const BNB: Chain = Chain {
    rpc_env: "BNB_FORK_RPC_URL",
    id: 56,
    spoke_pool: address!("0x4e8E101924eDE233C13e2D8622DC8aED2872d505"),
    handler: address!("0xAC537C12fE8f544D712d71ED4376a502EEa944d7"),
    wrapped_native: address!("0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c"),
    railgun: address!("0x590162bf4b50f6576a459b75309ee21d92178a10"),
    delegate: address!("0x48cf4b897f64d81212c1423d78a05e828d0ce19d"),
};
const POLYGON: Chain = Chain {
    rpc_env: "POLYGON_FORK_RPC_URL",
    id: 137,
    spoke_pool: address!("0x9295ee1d8C5b022Be115A2AD3c30C72E34e7F096"),
    handler: address!("0x924a9f036260DdD5808007E1AA95f08eD08aA569"),
    wrapped_native: address!("0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270"),
    railgun: address!("0x19b620929f97b7b990801496c3b361ca5def8c71"),
    delegate: address!("0x48cf4b897f64d81212c1423d78a05e828d0ce19d"),
};
const ARBITRUM: Chain = Chain {
    rpc_env: "ARBITRUM_FORK_RPC_URL",
    id: 42161,
    spoke_pool: address!("0xe35e9842fceaCA96570B734083f4a58e8F7C5f2A"),
    handler: address!("0x924a9f036260DdD5808007E1AA95f08eD08aA569"),
    wrapped_native: address!("0x82aF49447D8a07e3bd95BD0d56f35241523fBab1"),
    railgun: address!("0xFA7093CDD9EE6932B4eb2c9e1cde7CE00B1FA4b9"),
    delegate: address!("0x48cf4b897f64d81212c1423d78a05e828d0ce19d"),
};

sol! {
    interface ForkErc20 {
        function balanceOf(address account) external view returns (uint256);
        function approve(address spender, uint256 amount) external returns (bool);
        function deposit() external payable;
    }

    interface ForkSettlement {
        struct TradeData {
            uint256 sellTokenIndex;
            uint256 buyTokenIndex;
            address receiver;
            uint256 sellAmount;
            uint256 buyAmount;
            uint32 validTo;
            bytes32 appData;
            uint256 feeAmount;
            uint256 flags;
            uint256 executedAmount;
            bytes signature;
        }
        struct InteractionData {
            address target;
            uint256 value;
            bytes callData;
        }
        function settle(address[] tokens, uint256[] clearingPrices, TradeData[] trades, InteractionData[][3] interactions) external;
    }

    interface ForkHooksTrampoline {
        struct Hook {
            address target;
            bytes callData;
            uint256 gasLimit;
        }
        function execute(Hook[] hooks) external;
    }

    interface ForkSolverAuthentication {
        function manager() external view returns (address);
        function addSolver(address solver) external;
    }

    interface ForkSpokePool {
        struct V3RelayData {
            bytes32 depositor;
            bytes32 recipient;
            bytes32 exclusiveRelayer;
            bytes32 inputToken;
            bytes32 outputToken;
            uint256 inputAmount;
            uint256 outputAmount;
            uint256 originChainId;
            uint256 depositId;
            uint32 fillDeadline;
            uint32 exclusivityDeadline;
            bytes message;
        }
        function fillRelay(V3RelayData relayData, uint256 repaymentChainId, bytes32 repaymentAddress) external;
        function wrappedNativeToken() external view returns (address);
    }

    interface ForkShed {
        function trustedExecuteHooks((address,uint256,bytes,bool,bool)[] calls) external;
    }
}

/// A Prague fork of one chain on a free local port, stopped on drop. Every
/// account is impersonated, so transactions are sent with a plain `from`.
struct Fork {
    child: Child,
    provider: DynProvider,
    chain: Chain,
}

impl Drop for Fork {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Fork {
    async fn start(chain: Chain) -> Self {
        let fork_url =
            std::env::var(chain.rpc_env).unwrap_or_else(|_| panic!("{} is not set", chain.rpc_env));
        let port = TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .expect("free port")
            .port();
        let child = Command::new(std::env::var("ANVIL_BIN").unwrap_or_else(|_| "anvil".to_owned()))
            .args(["--fork-url", fork_url.as_str(), "--hardfork", "prague"])
            .args(["--port", port.to_string().as_str(), "--auto-impersonate"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn anvil");
        let url: Url = format!("http://127.0.0.1:{port}").parse().unwrap();
        // Snapshot reverts also rewind account nonces. Read them from the fork for each send.
        let provider = ProviderBuilder::default()
            .with_gas_estimation()
            .with_simple_nonce_management()
            .fetch_chain_id()
            .connect_http(url)
            .erased();
        let fork = Self {
            child,
            provider,
            chain,
        };
        let mut ready = false;
        for _ in 0..240 {
            if fork.provider.get_chain_id().await.ok() == Some(chain.id) {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        assert!(ready, "anvil did not start a fork of chain {}", chain.id);
        fork
    }

    async fn raw(
        &self,
        method: &'static str,
        params: impl serde::Serialize + Clone + std::fmt::Debug + Send + Sync + Unpin,
    ) {
        let _: serde_json::Value = self
            .provider
            .raw_request(method.into(), params)
            .await
            .unwrap_or_else(|error| panic!("{method}: {error}"));
    }

    async fn fund(&self, account: Address) {
        self.raw(
            "anvil_setBalance",
            (account, U256::from(10).pow(U256::from(22))),
        )
        .await;
    }

    async fn deal(&self, token: Address, holder: Address, amount: U256) {
        let balance = self.balance(token, holder).await;
        self.raw("anvil_dealERC20", (holder, token, balance + amount))
            .await;
    }

    async fn balance(&self, token: Address, holder: Address) -> U256 {
        self.call(token, ForkErc20::balanceOfCall { account: holder })
            .await
    }

    async fn code(&self, account: Address) -> Bytes {
        self.provider.get_code_at(account).await.unwrap()
    }

    async fn snapshot(&self) -> U256 {
        self.provider
            .raw_request("evm_snapshot".into(), ())
            .await
            .unwrap()
    }

    async fn revert(&self, snapshot: U256) {
        let reverted: bool = self
            .provider
            .raw_request("evm_revert".into(), (snapshot,))
            .await
            .unwrap();
        assert!(reverted, "the fork returns to its snapshot");
    }

    /// The latest block's timestamp, the fork's clock.
    async fn timestamp(&self) -> u32 {
        let timestamp = self
            .provider
            .get_block_by_number(BlockNumberOrTag::Latest)
            .await
            .unwrap()
            .expect("latest block")
            .header
            .timestamp;
        u32::try_from(timestamp).unwrap()
    }

    async fn call<C: SolCall>(&self, to: Address, call: C) -> C::Return {
        let output = self
            .provider
            .call(
                TransactionRequest::default()
                    .to(to)
                    .input(call.abi_encode().into()),
            )
            .await
            .unwrap();
        C::abi_decode_returns(&output).unwrap()
    }

    /// Why `transaction` would revert on the latest state, or `None` if it would succeed.
    async fn revert_reason(&self, transaction: TransactionRequest) -> Option<String> {
        self.provider
            .call(transaction)
            .await
            .err()
            .map(|error| error.to_string())
    }

    async fn send(&self, transaction: TransactionRequest) -> TransactionReceipt {
        self.provider
            .send_transaction(transaction)
            .await
            .expect("send transaction")
            .get_receipt()
            .await
            .expect("transaction receipt")
    }

    async fn send_from(&self, from: Address, to: Address, input: Vec<u8>) -> TransactionReceipt {
        self.send(
            TransactionRequest::default()
                .from(from)
                .to(to)
                .input(input.into())
                .gas_limit(GAS_LIMIT),
        )
        .await
    }

    /// Gas used by the first call to `to` in `transaction` whose input starts with
    /// `selector`, from anvil's call tracer.
    async fn call_gas(&self, transaction: B256, to: Address, selector: [u8; 4]) -> u64 {
        fn find(frame: &serde_json::Value, to: &str, input: &str) -> Option<u64> {
            let field = |name: &str| frame[name].as_str().map(str::to_lowercase);
            if field("to").as_deref() == Some(to)
                && field("input").is_some_and(|data| data.starts_with(input))
            {
                let used = field("gasUsed")?;
                return u64::from_str_radix(used.trim_start_matches("0x"), 16).ok();
            }
            frame["calls"]
                .as_array()?
                .iter()
                .find_map(|call| find(call, to, input))
        }
        let trace: serde_json::Value = self
            .provider
            .raw_request(
                "debug_traceTransaction".into(),
                (transaction, serde_json::json!({"tracer": "callTracer"})),
            )
            .await
            .expect("call trace");
        find(
            &trace,
            &format!("{to:#x}"),
            &Bytes::copy_from_slice(&selector).to_string(),
        )
        .expect("the traced call")
    }

    fn deposits(&self, receipt: &TransactionReceipt) -> Vec<SpokePool::FundsDeposited> {
        receipt
            .logs()
            .iter()
            .filter(|log| log.address() == self.chain.spoke_pool)
            .filter_map(|log| SpokePool::FundsDeposited::decode_log(&log.inner).ok())
            .map(|log| log.data)
            .collect()
    }

    /// Allow `SOLVER` to settle, through the authenticator's manager.
    async fn allow_solver(&self) {
        let manager = self
            .call(
                SOLVER_AUTHENTICATION,
                ForkSolverAuthentication::managerCall {},
            )
            .await;
        for account in [manager, SOLVER] {
            self.fund(account).await;
        }
        let receipt = self
            .send_from(
                manager,
                SOLVER_AUTHENTICATION,
                ForkSolverAuthentication::addSolverCall { solver: SOLVER }.abi_encode(),
            )
            .await;
        assert!(receipt.status(), "the solver is allowed");
    }

    /// Deploy `SwapMath` through the deterministic deployer, as the release does,
    /// unless the chain already has it. Returns whether it was already there.
    async fn deploy_swap_math(&self) -> bool {
        let deployed = !self.code(SWAP_MATH_ADDRESS).await.is_empty();
        if !deployed {
            self.fund(CALLER).await;
            let receipt = self
                .send_from(
                    CALLER,
                    DETERMINISTIC_DEPLOYER,
                    swap_math_deployment_calldata().to_vec(),
                )
                .await;
            assert!(receipt.status(), "the math contract deploys");
        }
        assert_eq!(
            keccak256(self.code(SWAP_MATH_ADDRESS).await),
            SWAP_MATH_RUNTIME_CODE_HASH
        );
        deployed
    }

    /// Settle one fill-or-kill sell order as `SOLVER`, paying `payout` of the buy
    /// token from the settlement contract's own balance, then run `post_hooks`
    /// through the deployed trampoline as a solver does with app-data hooks.
    async fn settle(
        &self,
        order: &Order,
        signature: [u8; 65],
        post_hooks: &[AppDataHook],
        payout: U256,
    ) -> TransactionReceipt {
        self.deal(order.buyToken, SETTLEMENT, payout).await;
        let post = vec![ForkSettlement::InteractionData {
            target: HOOKS_TRAMPOLINE,
            value: U256::ZERO,
            callData: ForkHooksTrampoline::executeCall {
                hooks: post_hooks
                    .iter()
                    .map(|hook| ForkHooksTrampoline::Hook {
                        target: hook.target,
                        callData: hook.call_data.clone(),
                        gasLimit: U256::from(hook.gas_limit),
                    })
                    .collect(),
            }
            .abi_encode()
            .into(),
        }];
        let settle = ForkSettlement::settleCall {
            tokens: vec![order.sellToken, order.buyToken],
            // The sell amount at these prices buys exactly `payout`.
            clearingPrices: vec![payout, order.sellAmount],
            trades: vec![ForkSettlement::TradeData {
                sellTokenIndex: U256::ZERO,
                buyTokenIndex: U256::ONE,
                receiver: order.receiver,
                sellAmount: order.sellAmount,
                buyAmount: order.buyAmount,
                validTo: order.validTo,
                appData: order.appData,
                feeAmount: order.feeAmount,
                // Sell, fill-or-kill, ERC-20 balances, EIP-712 signature.
                flags: U256::ZERO,
                executedAmount: U256::ZERO,
                signature: signature.into(),
            }],
            interactions: [Vec::new(), Vec::new(), post],
        };
        self.send(
            TransactionRequest::default()
                .from(SOLVER)
                .to(SETTLEMENT)
                .input(settle.abi_encode().into())
                .gas_limit(SETTLEMENT_GAS),
        )
        .await
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

/// A destination stealth account's signed guarded shield of `token`, guarded at
/// `minimum`, for its execution nonce `nonce` on `chain_id`.
fn signed_shield(
    executor: &PrivateKeySigner,
    chain_id: u64,
    token: Address,
    minimum: U256,
    nonce: U256,
) -> Bytes {
    let address = executor.address();
    let calls = guarded_shield_calls(address, token, minimum, full_balance_shield(token)).unwrap();
    let signature = executor
        .sign_hash_sync(&post_hook_signing_hash(&calls, nonce, chain_id, address))
        .unwrap();
    signed_post_hook_calldata(calls, nonce, chain_id, address, &signature).unwrap()
}

/// A hook batch signed by `owner` for its proxy on `chain_id`, as `executeHooks` calldata.
fn signed_batch(
    owner: &PrivateKeySigner,
    chain_id: u64,
    calls: Vec<Call>,
    nonce: B256,
    deadline: u32,
) -> Bytes {
    let proxy = proxy_address(COW_SHED_FACTORY, COW_SHED_IMPLEMENTATION, owner.address());
    let hooks = ExecuteHooks {
        calls,
        nonce,
        deadline: U256::from(deadline),
    };
    let signature = owner
        .sign_hash_sync(&execute_hooks_digest(&hooks, chain_id, proxy))
        .unwrap();
    execute_hooks_calldata(
        hooks,
        owner.address(),
        &signature,
        chain_id,
        COW_SHED_FACTORY,
        COW_SHED_IMPLEMENTATION,
    )
    .unwrap()
}

/// What one swap to Polygon needs: the owner, its proxy, the destination stealth
/// account and the deposit its hook makes. `new` swaps WETH for USDC on Ethereum.
struct Swap {
    owner: PrivateKeySigner,
    proxy: Address,
    deposit: BalanceDeposit,
    origin: Chain,
    sell: Address,
}

impl Swap {
    /// A swap whose deposit is quoted at `quote_timestamp` on the origin fork's clock.
    fn new(
        owner: PrivateKeySigner,
        destination_executor: &PrivateKeySigner,
        destination_nonce: U256,
        quote_timestamp: u32,
        now: u32,
    ) -> Self {
        Self::on(
            ETHEREUM,
            (WETH, USDC),
            owner,
            destination_executor,
            destination_nonce,
            quote_timestamp,
            now,
        )
    }

    /// A swap of `sell` for `buy` on `origin`.
    fn on(
        origin: Chain,
        (sell, buy): (Address, Address),
        owner: PrivateKeySigner,
        destination_executor: &PrivateKeySigner,
        destination_nonce: U256,
        quote_timestamp: u32,
        now: u32,
    ) -> Self {
        let proxy = proxy_address(COW_SHED_FACTORY, COW_SHED_IMPLEMENTATION, owner.address());
        let deposit = BalanceDeposit {
            proxy,
            math: SWAP_MATH_ADDRESS,
            spoke_pool: origin.spoke_pool,
            buy_amount: U256::from(BUY_AMOUNT),
            destination_min: U256::from(DESTINATION_MIN),
            depositor: owner.address(),
            input_token: buy,
            output_token: POLYGON_USDC,
            destination_chain_id: POLYGON.id,
            exclusive_relayer: Address::ZERO,
            quote_timestamp,
            fill_deadline: now + 3600,
            exclusivity_parameter: 0,
            delivery: AcrossPrivateDelivery {
                handler: POLYGON.handler,
                destination_executor: destination_executor.address(),
                shield_multicall: signed_shield(
                    destination_executor,
                    POLYGON.id,
                    POLYGON_USDC,
                    U256::from(DESTINATION_MIN),
                    destination_nonce,
                ),
                fallback: None,
            },
        };
        Self {
            owner,
            proxy,
            deposit,
            origin,
            sell,
        }
    }

    /// The post-hook of an order valid until `valid_to`, with batch nonce `nonce`.
    fn hook(&self, nonce: B256, valid_to: u32) -> AppDataHook {
        AppDataHook {
            call_data: signed_batch(
                &self.owner,
                self.origin.id,
                deposit_hook_calls(WEIROLL, &self.deposit).unwrap(),
                nonce,
                valid_to,
            ),
            gas_limit: HOOK_GAS_LIMIT,
            target: COW_SHED_FACTORY,
        }
    }

    /// The signed order that pays the proxy and carries `hook`, with its app-data size.
    fn order(&self, hook: &AppDataHook, valid_to: u32) -> (Order, [u8; 65], usize) {
        let app_data = AppData::hooks("swap".to_owned(), Vec::new(), vec![hook.clone()])
            .encode()
            .unwrap();
        let order = Order {
            sellToken: self.sell,
            buyToken: self.deposit.input_token,
            receiver: self.proxy,
            sellAmount: U256::from(SELL_AMOUNT),
            buyAmount: U256::from(BUY_AMOUNT),
            validTo: valid_to,
            appData: app_data.hash,
            feeAmount: U256::ZERO,
            kind: ORDER_KIND_SELL.to_owned(),
            partiallyFillable: false,
            sellTokenBalance: TOKEN_BALANCE_ERC20.to_owned(),
            buyTokenBalance: TOKEN_BALANCE_ERC20.to_owned(),
        };
        let signature = eip712_order_signature(
            &self
                .owner
                .sign_hash_sync(&order_digest(&order, self.origin.id, SETTLEMENT))
                .unwrap(),
        );
        (order, signature, app_data.document.len())
    }

    /// Give the owner the sell amount and approve the vault relayer for exactly it.
    async fn fund_owner(&self, fork: &Fork) {
        let owner = self.owner.address();
        fork.fund(owner).await;
        fork.deal(self.sell, owner, U256::from(SELL_AMOUNT)).await;
        let receipt = fork
            .send_from(
                owner,
                self.sell,
                ForkErc20::approveCall {
                    spender: VAULT_RELAYER,
                    amount: U256::from(SELL_AMOUNT),
                }
                .abi_encode(),
            )
            .await;
        assert!(receipt.status(), "the owner approves the vault relayer");
    }

    async fn nonce_used(&self, fork: &Fork, nonce: B256) -> bool {
        fork.call(self.proxy, COWShed::noncesCall { nonce }).await
    }
}

/// An account that pulls tokens can name another account as depositor, with the
/// handler as recipient and a real private-delivery message, and a payable
/// deposit of the wrapped native token takes the amount as value.
async fn deposit_for_another_depositor(chain: Chain, destination: Chain) {
    let fork = Fork::start(chain).await;
    assert_eq!(
        fork.call(chain.spoke_pool, ForkSpokePool::wrappedNativeTokenCall {})
            .await,
        chain.wrapped_native
    );
    let depositor = Address::repeat_byte(0xd2);
    let executor = PrivateKeySigner::random();
    let amount = U256::from(SELL_AMOUNT);
    let output = amount - U256::from(1_000_000_000_000_000_u64);
    let now = fork.timestamp().await;
    let shield = signed_shield(
        &executor,
        destination.id,
        destination.wrapped_native,
        output,
        U256::ZERO,
    );
    let message = private_delivery_message(
        destination.handler,
        destination.wrapped_native,
        executor.address(),
        shield.clone(),
        Some(executor.address()),
    );
    let calldata = private_deposit_calldata(
        SpokePool::depositV3Call {
            depositor,
            recipient: destination.handler,
            inputToken: chain.wrapped_native,
            outputToken: destination.wrapped_native,
            inputAmount: amount,
            outputAmount: output,
            destinationChainId: U256::from(destination.id),
            exclusiveRelayer: Address::ZERO,
            quoteTimestamp: now,
            fillDeadline: now + 3600,
            exclusivityParameter: 0,
            message: Bytes::new(),
        },
        destination.handler,
        executor.address(),
        shield,
        Some(executor.address()),
    )
    .unwrap();

    fork.fund(CALLER).await;
    let check = |deposits: Vec<SpokePool::FundsDeposited>| {
        let [deposit] = deposits.as_slice() else {
            panic!("expected one deposit, got {}", deposits.len());
        };
        assert_eq!(deposit.depositor, address_to_bytes32(depositor));
        assert_eq!(deposit.recipient, address_to_bytes32(destination.handler));
        assert_eq!(deposit.inputToken, address_to_bytes32(chain.wrapped_native));
        assert_eq!(
            deposit.outputToken,
            address_to_bytes32(destination.wrapped_native)
        );
        assert_eq!(
            (deposit.inputAmount, deposit.outputAmount),
            (amount, output)
        );
        assert_eq!(deposit.destinationChainId, U256::from(destination.id));
        assert_eq!(deposit.message, message);
        assert_eq!(
            (deposit.quoteTimestamp, deposit.fillDeadline),
            (now, now + 3600)
        );
        assert_eq!(deposit.exclusivityDeadline, 0);
        deposit.depositId
    };

    // An ERC-20 deposit pulled from the caller, naming the other account.
    for (to, input, value) in [
        (
            chain.wrapped_native,
            ForkErc20::depositCall {}.abi_encode(),
            amount,
        ),
        (
            chain.wrapped_native,
            ForkErc20::approveCall {
                spender: chain.spoke_pool,
                amount,
            }
            .abi_encode(),
            U256::ZERO,
        ),
    ] {
        let receipt = fork
            .send(
                TransactionRequest::default()
                    .from(CALLER)
                    .to(to)
                    .value(value)
                    .input(input.into())
                    .gas_limit(GAS_LIMIT),
            )
            .await;
        assert!(receipt.status());
    }
    let receipt = fork
        .send_from(CALLER, chain.spoke_pool, calldata.to_vec())
        .await;
    assert!(receipt.status(), "chain {}: ERC-20 deposit", chain.id);
    let erc20_gas = receipt.gas_used;
    let erc20_id = check(fork.deposits(&receipt));
    assert_eq!(fork.balance(chain.wrapped_native, CALLER).await, U256::ZERO);
    assert_eq!(
        fork.balance(chain.wrapped_native, depositor).await,
        U256::ZERO
    );

    // The same deposit paid as value: no wrapped balance, no approval.
    let receipt = fork
        .send(
            TransactionRequest::default()
                .from(CALLER)
                .to(chain.spoke_pool)
                .value(amount)
                .input(calldata.clone().into())
                .gas_limit(GAS_LIMIT),
        )
        .await;
    assert!(receipt.status(), "chain {}: native deposit", chain.id);
    let native_id = check(fork.deposits(&receipt));
    println!(
        "chain {}: depositV3 from {CALLER} naming depositor {depositor} accepted, \
         FundsDeposited id {erc20_id} (ERC-20, gas {}) and id {native_id} (native value, gas {}), \
         recipient {} on chain {}, message {} bytes",
        chain.id,
        erc20_gas,
        receipt.gas_used,
        destination.handler,
        destination.id,
        message.len()
    );
}

#[tokio::test]
#[ignore = "needs ETH_FORK_RPC_URL and anvil"]
async fn ethereum_deposit_names_another_depositor_and_takes_native_value() {
    deposit_for_another_depositor(ETHEREUM, ARBITRUM).await;
}

#[tokio::test]
#[ignore = "needs BNB_FORK_RPC_URL and anvil"]
async fn bnb_deposit_names_another_depositor_and_takes_native_value() {
    deposit_for_another_depositor(BNB, ETHEREUM).await;
}

#[tokio::test]
#[ignore = "needs POLYGON_FORK_RPC_URL and anvil"]
async fn polygon_deposit_names_another_depositor_and_takes_native_value() {
    deposit_for_another_depositor(POLYGON, ETHEREUM).await;
}

#[tokio::test]
#[ignore = "needs ARBITRUM_FORK_RPC_URL and anvil"]
async fn arbitrum_deposit_names_another_depositor_and_takes_native_value() {
    deposit_for_another_depositor(ARBITRUM, ETHEREUM).await;
}

/// The same check for any origin chain, named by the environment: a caller that
/// holds `ORIGIN_TOKEN` deposits `ORIGIN_AMOUNT` of it into `ORIGIN_SPOKE_POOL`
/// naming another account as depositor, with Ethereum's handler as recipient and
/// a real private-delivery message. With `ORIGIN_NATIVE=1` the pool's wrapped
/// native token is then deposited as value. This is the check a chain passes
/// before the wallet pins its `SpokePool` as a deposit origin.
#[tokio::test]
#[ignore = "needs ORIGIN_FORK_RPC_URL, ORIGIN_CHAIN_ID, ORIGIN_SPOKE_POOL, ORIGIN_TOKEN, ORIGIN_AMOUNT and anvil"]
async fn origin_deposit_names_another_depositor() {
    let var = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"));
    let token: Address = var("ORIGIN_TOKEN").parse().expect("token address");
    let amount: U256 = var("ORIGIN_AMOUNT").parse().expect("amount");
    let native = std::env::var("ORIGIN_NATIVE").is_ok_and(|native| native == "1");
    let chain = Chain {
        rpc_env: "ORIGIN_FORK_RPC_URL",
        id: var("ORIGIN_CHAIN_ID").parse().expect("chain id"),
        spoke_pool: var("ORIGIN_SPOKE_POOL").parse().expect("pool address"),
        ..ETHEREUM
    };
    let destination = ETHEREUM;
    let fork = Fork::start(chain).await;
    let wrapped_native = fork
        .call(chain.spoke_pool, ForkSpokePool::wrappedNativeTokenCall {})
        .await;
    let depositor = Address::repeat_byte(0xd2);
    let executor = PrivateKeySigner::random();
    let output = amount - amount / U256::from(10);
    let now = fork.timestamp().await;
    let shield = signed_shield(
        &executor,
        destination.id,
        destination.wrapped_native,
        output,
        U256::ZERO,
    );
    let message = private_delivery_message(
        destination.handler,
        destination.wrapped_native,
        executor.address(),
        shield.clone(),
        Some(executor.address()),
    );
    let deposit = |input_token: Address| {
        private_deposit_calldata(
            SpokePool::depositV3Call {
                depositor,
                recipient: destination.handler,
                inputToken: input_token,
                outputToken: destination.wrapped_native,
                inputAmount: amount,
                outputAmount: output,
                destinationChainId: U256::from(destination.id),
                exclusiveRelayer: Address::ZERO,
                quoteTimestamp: now,
                fillDeadline: now + 3600,
                exclusivityParameter: 0,
                message: Bytes::new(),
            },
            destination.handler,
            executor.address(),
            shield.clone(),
            Some(executor.address()),
        )
        .unwrap()
    };
    let check = |deposits: Vec<SpokePool::FundsDeposited>, input_token: Address| {
        let [deposit] = deposits.as_slice() else {
            panic!("expected one deposit, got {}", deposits.len());
        };
        assert_eq!(deposit.depositor, address_to_bytes32(depositor));
        assert_eq!(deposit.recipient, address_to_bytes32(destination.handler));
        assert_eq!(deposit.inputToken, address_to_bytes32(input_token));
        assert_eq!(
            (deposit.inputAmount, deposit.outputAmount),
            (amount, output)
        );
        assert_eq!(deposit.destinationChainId, U256::from(destination.id));
        assert_eq!(deposit.message, message);
        deposit.depositId
    };

    fork.fund(CALLER).await;
    fork.deal(token, CALLER, amount).await;
    let receipt = fork
        .send_from(
            CALLER,
            token,
            ForkErc20::approveCall {
                spender: chain.spoke_pool,
                amount,
            }
            .abi_encode(),
        )
        .await;
    assert!(receipt.status(), "chain {}: approval", chain.id);
    let receipt = fork
        .send_from(CALLER, chain.spoke_pool, deposit(token).to_vec())
        .await;
    assert!(receipt.status(), "chain {}: ERC-20 deposit", chain.id);
    let erc20_gas = receipt.gas_used;
    let erc20_id = check(fork.deposits(&receipt), token);
    assert_eq!(fork.balance(token, CALLER).await, U256::ZERO);

    let native_result = if native {
        let receipt = fork
            .send(
                TransactionRequest::default()
                    .from(CALLER)
                    .to(chain.spoke_pool)
                    .value(amount)
                    .input(deposit(wrapped_native).into())
                    .gas_limit(GAS_LIMIT),
            )
            .await;
        assert!(receipt.status(), "chain {}: native deposit", chain.id);
        let id = check(fork.deposits(&receipt), wrapped_native);
        format!(
            "native value as {wrapped_native} id {id} gas {}",
            receipt.gas_used
        )
    } else {
        "native value not checked".to_owned()
    };
    println!(
        "ORIGIN chain {} pool {}: depositV3 of {token} naming depositor {depositor} accepted, id \
         {erc20_id} gas {erc20_gas}; {native_result}",
        chain.id, chain.spoke_pool
    );
}

/// The order path on any origin chain, named by the environment: an order selling
/// `ORIGIN_SELL_TOKEN` for `ORIGIN_BUY_TOKEN`, paid to the owner's proxy, settles
/// above its buy amount and its hook deposits the proxy's whole balance into
/// `ORIGIN_SPOKE_POOL` at the signed scale; a second order on the deployed proxy
/// settles at exactly its buy amount. This is the check a chain passes before the
/// wallet offers swaps from it. The fill and shield on the destination chain are
/// the same for every origin and are covered by the Ethereum test.
#[tokio::test]
#[ignore = "needs ORIGIN_FORK_RPC_URL, ORIGIN_CHAIN_ID, ORIGIN_SPOKE_POOL, ORIGIN_SELL_TOKEN, ORIGIN_BUY_TOKEN and anvil"]
async fn origin_order_deposits_the_whole_balance() {
    let var = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"));
    let sell: Address = var("ORIGIN_SELL_TOKEN").parse().expect("sell token");
    let buy: Address = var("ORIGIN_BUY_TOKEN").parse().expect("buy token");
    let origin = Chain {
        rpc_env: "ORIGIN_FORK_RPC_URL",
        id: var("ORIGIN_CHAIN_ID").parse().expect("chain id"),
        spoke_pool: var("ORIGIN_SPOKE_POOL").parse().expect("pool address"),
        ..ETHEREUM
    };
    let fork = Fork::start(origin).await;
    for (account, hash) in [
        (COW_SHED_FACTORY, COW_SHED_FACTORY_CODE_HASH),
        (COW_SHED_IMPLEMENTATION, COW_SHED_IMPLEMENTATION_CODE_HASH),
        (WEIROLL, WEIROLL_CODE_HASH),
    ] {
        assert_eq!(keccak256(fork.code(account).await), hash, "{account}");
    }
    fork.allow_solver().await;
    let deployed = fork.deploy_swap_math().await;

    let executor = PrivateKeySigner::random();
    let now = fork.timestamp().await;
    let valid_to = now + 600;
    let swap = Swap::on(
        origin,
        (sell, buy),
        PrivateKeySigner::random(),
        &executor,
        U256::ZERO,
        now,
        now,
    );
    let owner = swap.owner.address();
    assert_eq!(
        fork.call(COW_SHED_FACTORY, COWShedFactory::proxyOfCall { who: owner })
            .await,
        swap.proxy
    );

    // Before any settlement the batch reverts and deploys nothing.
    let nonce = B256::repeat_byte(0x21);
    let hook = swap.hook(nonce, valid_to);
    let receipt = fork
        .send_from(CALLER, COW_SHED_FACTORY, hook.call_data.to_vec())
        .await;
    assert!(!receipt.status(), "the early run reverts");
    assert!(fork.code(swap.proxy).await.is_empty());

    let mut gas = Vec::new();
    for (nonce, payout) in [
        (nonce, U256::from(BUY_AMOUNT + SURPLUS)),
        (B256::repeat_byte(0x22), U256::from(BUY_AMOUNT)),
    ] {
        let hook = swap.hook(nonce, valid_to);
        let (order, signature, _) = swap.order(&hook, valid_to);
        swap.fund_owner(&fork).await;
        let receipt = fork
            .settle(&order, signature, std::slice::from_ref(&hook), payout)
            .await;
        assert!(receipt.status(), "chain {}: settlement", origin.id);
        let deposits = fork.deposits(&receipt);
        let [deposit] = deposits.as_slice() else {
            panic!("expected one deposit, got {}", deposits.len());
        };
        assert_eq!(
            (deposit.inputAmount, deposit.outputAmount),
            (
                payout,
                payout * U256::from(DESTINATION_MIN) / U256::from(BUY_AMOUNT)
            )
        );
        assert_eq!(deposit.depositor, address_to_bytes32(owner));
        assert_eq!(deposit.recipient, address_to_bytes32(POLYGON.handler));
        assert_eq!(deposit.inputToken, address_to_bytes32(buy));
        assert_eq!(fork.balance(buy, swap.proxy).await, U256::ZERO);
        assert!(swap.nonce_used(&fork, nonce).await);
        gas.push(
            fork.call_gas(
                receipt.transaction_hash,
                COW_SHED_FACTORY,
                COWShedFactory::executeHooksCall::SELECTOR,
            )
            .await,
        );
    }
    println!(
        "ORDER chain {} pool {}: sold {sell} for {buy}; hook deposited the whole payout at the \
         signed scale; hook gas {} deploying the proxy and {} on a deployed proxy; SwapMath {}",
        origin.id,
        origin.spoke_pool,
        gas[0],
        gas[1],
        if deployed {
            "is deployed on the forked chain"
        } else {
            "was deployed on the fork by this test"
        }
    );
}

/// The pinned cow-shed and weiroll code, the local proxy derivation, and the
/// math contract's deterministic deployment and arithmetic.
async fn pinned_contracts(chain: Chain) {
    let fork = Fork::start(chain).await;
    for (account, hash) in [
        (COW_SHED_FACTORY, COW_SHED_FACTORY_CODE_HASH),
        (COW_SHED_IMPLEMENTATION, COW_SHED_IMPLEMENTATION_CODE_HASH),
        (WEIROLL, WEIROLL_CODE_HASH),
    ] {
        assert_eq!(keccak256(fork.code(account).await), hash, "{account}");
    }
    assert_eq!(
        fork.call(COW_SHED_FACTORY, COWShedFactory::implementationCall {})
            .await,
        COW_SHED_IMPLEMENTATION
    );
    let creation_code: Bytes = {
        sol! {
            function PROXY_CREATION_CODE() external view returns (bytes);
        }
        fork.call(COW_SHED_FACTORY, PROXY_CREATION_CODECall {})
            .await
    };
    assert_eq!(creation_code.as_ref(), PROXY_CREATION_CODE);
    let owner = PrivateKeySigner::random().address();
    assert_eq!(
        fork.call(COW_SHED_FACTORY, COWShedFactory::proxyOfCall { who: owner })
            .await,
        proxy_address(COW_SHED_FACTORY, COW_SHED_IMPLEMENTATION, owner)
    );

    let deployed = fork.deploy_swap_math().await;
    let scale = |amount: U256, numerator: U256, denominator: U256| {
        TransactionRequest::default().to(SWAP_MATH_ADDRESS).input(
            SwapMath::scaleCall {
                amount,
                numerator,
                denominator,
            }
            .abi_encode()
            .into(),
        )
    };
    let seven = U256::from(7);
    assert_eq!(
        fork.call(
            SWAP_MATH_ADDRESS,
            SwapMath::scaleCall {
                amount: seven,
                numerator: U256::from(3),
                denominator: U256::from(2),
            }
        )
        .await,
        U256::from(10)
    );
    assert!(
        fork.revert_reason(scale(U256::MAX, U256::from(2), U256::ONE))
            .await
            .is_some(),
        "an overflowing product reverts"
    );
    assert!(
        fork.revert_reason(scale(seven, seven, U256::ZERO))
            .await
            .is_some(),
        "a zero denominator reverts"
    );
    println!(
        "chain {}: pinned code hashes match; SwapMath at {SWAP_MATH_ADDRESS} {}",
        chain.id,
        if deployed {
            "is deployed on the forked chain"
        } else {
            "was deployed on the fork by this test"
        }
    );
}

#[tokio::test]
#[ignore = "needs the four fork RPC URLs and anvil"]
async fn pinned_contracts_match_on_every_swap_chain() {
    for chain in [ETHEREUM, BNB, POLYGON, ARBITRUM] {
        pinned_contracts(chain).await;
    }
}

/// An early batch on an empty proxy with and without the guard, then a settled
/// order whose hook fails on a proxy that was never deployed, and the withdrawal
/// through the factory.
#[tokio::test]
#[ignore = "needs ETH_FORK_RPC_URL and anvil"]
async fn early_batches_and_proceeds_stranded_in_an_undeployed_proxy() {
    let fork = Fork::start(ETHEREUM).await;
    fork.allow_solver().await;
    fork.deploy_swap_math().await;
    let now = fork.timestamp().await;
    let valid_to = now + 600;
    let executor = PrivateKeySigner::random();
    let swap = Swap::new(PrivateKeySigner::random(), &executor, U256::ZERO, now, now);
    let owner = swap.owner.address();
    assert!(fork.code(swap.proxy).await.is_empty());

    // Without the guard, an early run on the empty proxy.
    let unguarded_nonce = B256::repeat_byte(0x01);
    let unguarded = signed_batch(
        &swap.owner,
        ETHEREUM.id,
        deposit_hook_calls(WEIROLL, &swap.deposit).unwrap()[1..].to_vec(),
        unguarded_nonce,
        valid_to,
    );
    let snapshot = fork.snapshot().await;
    let receipt = fork
        .send_from(CALLER, COW_SHED_FACTORY, unguarded.to_vec())
        .await;
    if receipt.status() {
        let deposits = fork.deposits(&receipt);
        println!(
            "unguarded early run: succeeded, nonce used: {}, deposits: {:?}",
            swap.nonce_used(&fork, unguarded_nonce).await,
            deposits
                .iter()
                .map(|deposit| (deposit.inputAmount, deposit.outputAmount))
                .collect::<Vec<_>>()
        );
        assert!(swap.nonce_used(&fork, unguarded_nonce).await);
    } else {
        println!("unguarded early run: reverted");
    }
    fork.revert(snapshot).await;

    // With the guard, the same run reverts and deploys nothing.
    let guarded_nonce = B256::repeat_byte(0x02);
    let guarded = swap.hook(guarded_nonce, valid_to);
    let receipt = fork
        .send_from(CALLER, COW_SHED_FACTORY, guarded.call_data.to_vec())
        .await;
    assert!(!receipt.status(), "the guarded early run reverts");
    assert!(fork.code(swap.proxy).await.is_empty());

    // A settled order whose hook fails: its deposit carries a quote timestamp the
    // SpokePool no longer accepts.
    let stale = Swap::new(swap.owner.clone(), &executor, U256::ZERO, now - 7200, now);
    let failing_nonce = B256::repeat_byte(0x03);
    let hook = stale.hook(failing_nonce, valid_to);
    let (order, signature, _) = stale.order(&hook, valid_to);
    stale.fund_owner(&fork).await;
    let payout = U256::from(BUY_AMOUNT);
    let receipt = fork.settle(&order, signature, &[hook], payout).await;
    assert!(receipt.status(), "the settlement survives its failed hook");
    assert!(fork.deposits(&receipt).is_empty());
    assert_eq!(fork.balance(USDC, swap.proxy).await, payout);
    assert_eq!(fork.balance(WETH, owner).await, U256::ZERO);
    assert!(fork.code(swap.proxy).await.is_empty());

    // A call straight to the code-less proxy succeeds and moves nothing.
    let withdrawal = withdrawal_calls(USDC, owner, payout).unwrap();
    let direct = ForkShed::trustedExecuteHooksCall {
        calls: withdrawal
            .iter()
            .map(|call| {
                (
                    call.target,
                    call.value,
                    call.callData.clone(),
                    call.allowFailure,
                    call.isDelegateCall,
                )
            })
            .collect(),
    };
    let receipt = fork.send_from(owner, swap.proxy, direct.abi_encode()).await;
    assert!(receipt.status());
    assert_eq!(fork.balance(USDC, swap.proxy).await, payout);
    assert_eq!(fork.balance(USDC, owner).await, U256::ZERO);

    // The withdrawal batch through the factory deploys the proxy and returns the tokens.
    let withdrawal_nonce = B256::repeat_byte(0x04);
    let batch = signed_batch(
        &swap.owner,
        ETHEREUM.id,
        withdrawal,
        withdrawal_nonce,
        valid_to,
    );
    let receipt = fork
        .send_from(owner, COW_SHED_FACTORY, batch.to_vec())
        .await;
    assert!(receipt.status(), "the withdrawal through the factory");
    assert_eq!(fork.balance(USDC, owner).await, payout);
    assert_eq!(fork.balance(USDC, swap.proxy).await, U256::ZERO);
    assert!(!fork.code(swap.proxy).await.is_empty());
    assert!(swap.nonce_used(&fork, withdrawal_nonce).await);
    for unused in [guarded_nonce, failing_nonce] {
        assert!(!swap.nonce_used(&fork, unused).await);
    }
    println!(
        "guarded early run reverted with its nonce unused; failed hook left {payout} USDC at \
         code-less proxy {}; withdrawal through the factory used {} gas",
        swap.proxy, receipt.gas_used
    );
}

/// A settlement above the buy amount deposits the proxy's whole balance at the
/// signed scale, and the fill on the destination chain shields all of it.
#[tokio::test]
#[ignore = "needs ETH_FORK_RPC_URL, POLYGON_FORK_RPC_URL and anvil"]
async fn settled_order_deposits_the_whole_balance_and_its_fill_is_shielded() {
    let (fork, destination) = tokio::join!(Fork::start(ETHEREUM), Fork::start(POLYGON));
    fork.allow_solver().await;
    fork.deploy_swap_math().await;

    // The destination stealth account, delegated to the accepted `RelayAdapt7702`.
    let executor = PrivateKeySigner::random();
    destination
        .raw(
            "anvil_setCode",
            (
                executor.address(),
                Bytes::from([&[0xef, 0x01, 0x00][..], POLYGON.delegate.as_slice()].concat()),
            ),
        )
        .await;
    let destination_nonce = destination
        .call(executor.address(), RelayAdapt7702::nonceCall {})
        .await;

    let now = fork.timestamp().await;
    let valid_to = now + 600;
    let swap = Swap::new(
        PrivateKeySigner::random(),
        &executor,
        destination_nonce,
        now,
        now,
    );
    let owner = swap.owner.address();
    let message = private_delivery_message(
        POLYGON.handler,
        POLYGON_USDC,
        executor.address(),
        swap.deposit.delivery.shield_multicall.clone(),
        None,
    );

    // First order: the proxy doesn't exist yet, and the settlement pays a surplus.
    let nonce = B256::repeat_byte(0x11);
    let hook = swap.hook(nonce, valid_to);
    let (order, signature, app_data_len) = swap.order(&hook, valid_to);
    swap.fund_owner(&fork).await;
    let payout = U256::from(BUY_AMOUNT + SURPLUS);
    let receipt = fork
        .settle(&order, signature, std::slice::from_ref(&hook), payout)
        .await;
    assert!(receipt.status());
    let deposits = fork.deposits(&receipt);
    let [deposit] = deposits.as_slice() else {
        panic!("expected one deposit, got {}", deposits.len());
    };
    let scaled = payout * U256::from(DESTINATION_MIN) / U256::from(BUY_AMOUNT);
    assert_eq!(
        (deposit.inputAmount, deposit.outputAmount),
        (payout, scaled)
    );
    assert_eq!(deposit.depositor, address_to_bytes32(owner));
    assert_eq!(deposit.recipient, address_to_bytes32(POLYGON.handler));
    assert_eq!(deposit.inputToken, address_to_bytes32(USDC));
    assert_eq!(deposit.outputToken, address_to_bytes32(POLYGON_USDC));
    assert_eq!(deposit.destinationChainId, U256::from(POLYGON.id));
    assert_eq!(deposit.message, message);
    assert_eq!(fork.balance(USDC, swap.proxy).await, U256::ZERO);
    assert!(swap.nonce_used(&fork, nonce).await);
    let deploying_gas = fork
        .call_gas(
            receipt.transaction_hash,
            COW_SHED_FACTORY,
            COWShedFactory::executeHooksCall::SELECTOR,
        )
        .await;

    // Second order on the deployed proxy, settled at exactly its buy amount.
    let second_nonce = B256::repeat_byte(0x12);
    let second_hook = swap.hook(second_nonce, valid_to);
    let (second_order, second_signature, _) = swap.order(&second_hook, valid_to);
    swap.fund_owner(&fork).await;
    let receipt = fork
        .settle(
            &second_order,
            second_signature,
            std::slice::from_ref(&second_hook),
            U256::from(BUY_AMOUNT),
        )
        .await;
    assert!(receipt.status());
    let second = fork.deposits(&receipt);
    let [exact] = second.as_slice() else {
        panic!("expected one deposit, got {}", second.len());
    };
    assert_eq!(
        (exact.inputAmount, exact.outputAmount),
        (U256::from(BUY_AMOUNT), U256::from(DESTINATION_MIN))
    );
    let deployed_gas = fork
        .call_gas(
            receipt.transaction_hash,
            COW_SHED_FACTORY,
            COWShedFactory::executeHooksCall::SELECTOR,
        )
        .await;

    // Replay the first deposit's fill on the destination chain.
    destination.fund(RELAYER).await;
    destination.deal(POLYGON_USDC, RELAYER, scaled).await;
    let receipt = destination
        .send_from(
            RELAYER,
            POLYGON_USDC,
            ForkErc20::approveCall {
                spender: POLYGON.spoke_pool,
                amount: scaled,
            }
            .abi_encode(),
        )
        .await;
    assert!(receipt.status());
    let fill = ForkSpokePool::fillRelayCall {
        relayData: ForkSpokePool::V3RelayData {
            depositor: deposit.depositor,
            recipient: deposit.recipient,
            exclusiveRelayer: deposit.exclusiveRelayer,
            inputToken: deposit.inputToken,
            outputToken: deposit.outputToken,
            inputAmount: deposit.inputAmount,
            outputAmount: deposit.outputAmount,
            originChainId: U256::from(ETHEREUM.id),
            depositId: deposit.depositId,
            fillDeadline: deposit.fillDeadline,
            exclusivityDeadline: deposit.exclusivityDeadline,
            message: deposit.message.clone(),
        },
        repaymentChainId: U256::from(POLYGON.id),
        repaymentAddress: address_to_bytes32(RELAYER),
    };
    let receipt = destination
        .send_from(RELAYER, POLYGON.spoke_pool, fill.abi_encode())
        .await;
    assert!(receipt.status(), "the fill runs the handler's calls");
    let shields = receipt
        .logs()
        .iter()
        .filter(|log| log.address() == POLYGON.railgun)
        .filter_map(|log| Shield::decode_log(&log.inner).ok())
        .map(|log| log.data)
        .collect::<Vec<_>>();
    let [shield] = shields.as_slice() else {
        panic!("expected one shield, got {}", shields.len());
    };
    let [commitment] = shield.commitments.as_slice() else {
        panic!("expected one commitment");
    };
    assert_eq!(commitment.token.tokenAddress, POLYGON_USDC);
    assert_eq!(U256::from(commitment.value) + shield.fees[0], scaled);
    assert_eq!(
        destination.balance(POLYGON_USDC, executor.address()).await,
        U256::ZERO
    );
    assert_eq!(
        destination.balance(POLYGON_USDC, POLYGON.handler).await,
        U256::ZERO
    );
    assert_eq!(
        destination
            .call(executor.address(), RelayAdapt7702::nonceCall {})
            .await,
        destination_nonce + U256::ONE
    );
    println!(
        "settlement paid {payout} for a buy amount of {BUY_AMOUNT}: deposited {} for an output \
         of {} (minimum {DESTINATION_MIN}); fill shielded {} with a fee of {}; hook batch gas \
         {deploying_gas} deploying the proxy and {deployed_gas} on a deployed proxy; hook \
         calldata {} bytes, app data {app_data_len} bytes, fill gas {}",
        deposit.inputAmount,
        deposit.outputAmount,
        commitment.value,
        shield.fees[0],
        hook.call_data.len(),
        receipt.gas_used
    );
}
