//! `CoW` Protocol (`GPv2`) order signing, order UIDs, and hook app data.
//!
//! Settlement, vault relayer, and hook trampoline addresses are chain profile
//! data supplied by callers.

use alloy::primitives::{
    Address, B256, Bytes, FixedBytes, Signature, SignatureError, address, keccak256,
};
use alloy::sol;
use alloy::sol_types::{Eip712Domain, SolStruct, eip712_domain};
use serde::{Deserialize, Serialize};
use thiserror::Error;

sol! {
    /// `GPv2Order.Data` as signed. The field names and types form the `GPv2`
    /// EIP-712 type hash; `kind` and the balance fields are the strings whose
    /// hashes `GPv2Order` stores.
    #[derive(Debug, PartialEq, Eq)]
    struct Order {
        address sellToken;
        address buyToken;
        address receiver;
        uint256 sellAmount;
        uint256 buyAmount;
        uint32 validTo;
        bytes32 appData;
        uint256 feeAmount;
        string kind;
        bool partiallyFillable;
        string sellTokenBalance;
        string buyTokenBalance;
    }

    interface GPv2Settlement {
        function invalidateOrder(bytes orderUid);
    }
}

/// `Order.buyToken` that pays the receiver in the chain's native asset
/// (`GPv2Transfer.BUY_ETH_ADDRESS`). The settlement pays it with a
/// 2,300-gas-stipend `transfer`, and the `Trade` event reports this address as
/// the buy token.
pub const BUY_NATIVE_TOKEN: Address = address!("0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE");

/// `Order.kind` of a sell order.
pub const ORDER_KIND_SELL: &str = "sell";
/// `Order.sellTokenBalance` and `Order.buyTokenBalance` for plain ERC-20 balances.
pub const TOKEN_BALANCE_ERC20: &str = "erc20";

/// Root app-data schema version emitted by [`AppData::encode`].
pub const APP_DATA_VERSION: &str = "1.1.0";
/// Hooks metadata schema version emitted by [`AppData::encode`].
pub const APP_DATA_HOOKS_VERSION: &str = "0.1.0";

#[derive(Debug, Error)]
pub enum CowError {
    #[error("order signature v must be 27 or 28, got {0}")]
    InvalidSignatureV(u8),
    #[error("order signature recovery failed: {0}")]
    Signature(#[from] SignatureError),
    #[error("app data serialization failed: {0}")]
    AppData(#[from] serde_json::Error),
}

/// EIP-712 domain of a `GPv2Settlement` deployment.
#[must_use]
pub const fn settlement_domain(chain_id: u64, settlement: Address) -> Eip712Domain {
    eip712_domain! {
        name: "Gnosis Protocol",
        version: "v2",
        chain_id: chain_id,
        verifying_contract: settlement,
    }
}

/// EIP-712 digest an order owner signs, and the first 32 bytes of its UID.
#[must_use]
pub fn order_digest(order: &Order, chain_id: u64, settlement: Address) -> B256 {
    order.eip712_signing_hash(&settlement_domain(chain_id, settlement))
}

#[must_use]
pub fn order_uid(order: &Order, chain_id: u64, settlement: Address, owner: Address) -> OrderUid {
    OrderUid::new(
        order_digest(order, chain_id, settlement),
        owner,
        order.validTo,
    )
}

/// `GPv2` order UID: `digest (32) || owner (20) || validTo (4, big-endian)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OrderUid(pub FixedBytes<56>);

impl OrderUid {
    #[must_use]
    pub fn new(digest: B256, owner: Address, valid_to: u32) -> Self {
        let mut uid = [0u8; 56];
        uid[..32].copy_from_slice(digest.as_slice());
        uid[32..52].copy_from_slice(owner.as_slice());
        uid[52..].copy_from_slice(&valid_to.to_be_bytes());
        Self(FixedBytes(uid))
    }

    #[must_use]
    pub fn digest(&self) -> B256 {
        B256::from_slice(&self.0[..32])
    }

    #[must_use]
    pub fn owner(&self) -> Address {
        Address::from_slice(&self.0[32..52])
    }

    #[must_use]
    pub const fn valid_to(&self) -> u32 {
        let [.., a, b, c, d] = self.0.0;
        u32::from_be_bytes([a, b, c, d])
    }
}

/// Encode an order signature for the `eip712` signing scheme as `r || s || v`
/// with `v` in {27, 28}, which `GPv2Settlement` passes to `ecrecover` as is.
#[must_use]
pub fn eip712_order_signature(signature: &Signature) -> [u8; 65] {
    signature.as_bytes()
}

/// Recover the signer of an `eip712` scheme order signature over `digest`.
pub fn recover_order_signer(signature: &[u8; 65], digest: &B256) -> Result<Address, CowError> {
    let v = signature[64];
    if !matches!(v, 27 | 28) {
        return Err(CowError::InvalidSignatureV(v));
    }
    Ok(Signature::from_raw_array(signature)?.recover_address_from_prehash(digest)?)
}

/// App-data document carrying only order hooks.
///
/// Fields are declared in key order, so serialization emits sorted keys like
/// the `CoW` SDK's deterministic encoder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppData {
    pub app_code: String,
    pub metadata: AppDataMetadata,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppDataMetadata {
    pub hooks: AppDataHooks,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppDataHooks {
    pub post: Vec<AppDataHook>,
    pub pre: Vec<AppDataHook>,
    pub version: String,
}

/// One hook call made by the `CoW` hooks trampoline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppDataHook {
    pub call_data: Bytes,
    /// Serialized as a decimal string, as `CoW` services parse it.
    #[serde(with = "alloy::serde::displayfromstr")]
    pub gas_limit: u64,
    pub target: Address,
}

/// Serialized app data and the `appData` order field committing to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedAppData {
    pub document: String,
    /// `keccak256` of the exact `document` bytes.
    pub hash: B256,
}

impl AppData {
    #[must_use]
    pub fn hooks(app_code: String, pre: Vec<AppDataHook>, post: Vec<AppDataHook>) -> Self {
        Self {
            app_code,
            metadata: AppDataMetadata {
                hooks: AppDataHooks {
                    post,
                    pre,
                    version: APP_DATA_HOOKS_VERSION.to_owned(),
                },
            },
            version: APP_DATA_VERSION.to_owned(),
        }
    }

    pub fn encode(&self) -> Result<EncodedAppData, CowError> {
        let document = serde_json::to_string(self)?;
        let hash = keccak256(document.as_bytes());
        Ok(EncodedAppData { document, hash })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::hex;
    use alloy::primitives::{U256, b256};
    use alloy::signers::SignerSync;
    use alloy::signers::local::PrivateKeySigner;

    // Order and domain separator from `GPv2Signing.test.ts` in cowprotocol/contracts
    // v1.1.2, as used by cowprotocol/services `compute_order_uid`.
    const TEST_DOMAIN_SEPARATOR: B256 =
        b256!("0x74e0b11bd18120612556bae4578cfd3a254d7e2495f543c569a92ff5794d9b09");
    const TEST_OWNER: Address = address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");

    fn test_order() -> Order {
        Order {
            sellToken: Address::repeat_byte(0x01),
            buyToken: Address::repeat_byte(0x02),
            receiver: Address::repeat_byte(0x03),
            sellAmount: U256::from(42_000_000_000_000_000_000_u128),
            buyAmount: U256::from(13_370_000_000_000_000_000_u128),
            validTo: u32::MAX,
            appData: B256::ZERO,
            feeAmount: U256::from(1_000_000_000_000_000_000_u128),
            kind: ORDER_KIND_SELL.to_owned(),
            partiallyFillable: false,
            sellTokenBalance: TOKEN_BALANCE_ERC20.to_owned(),
            buyTokenBalance: TOKEN_BALANCE_ERC20.to_owned(),
        }
    }

    fn test_digest(order: &Order) -> B256 {
        keccak256(
            [
                &[0x19, 0x01][..],
                TEST_DOMAIN_SEPARATOR.as_slice(),
                order.eip712_hash_struct().as_slice(),
            ]
            .concat(),
        )
    }

    #[test]
    fn order_hash_and_uid_match_gpv2_vector() {
        let order = test_order();
        // `GPv2Order.TYPE_HASH`.
        assert_eq!(
            order.eip712_type_hash(),
            b256!("0xd5a25ba2e97094ad7d83dc28a6572da797d6b3e7fc6663bd93efb789fc17e489")
        );
        let digest = test_digest(&order);
        let uid = OrderUid::new(digest, TEST_OWNER, order.validTo);
        assert_eq!(
            uid.0,
            FixedBytes(hex!(
                "0e45d31fd31b28c26031cdd81b35a8938b2ccca2cc425fcf440fd3bfed1eede9
                 70997970c51812dc3a010c7d01b50e0d17dc79c8
                 ffffffff"
            ))
        );
        assert_eq!(uid.digest(), digest);
        assert_eq!(uid.owner(), TEST_OWNER);
        assert_eq!(uid.valid_to(), u32::MAX);
    }

    #[test]
    fn eip712_order_signatures_recover_owner() {
        let signature = hex!(
            "59c0f5c151071c1320575f6da826a6c276525bbe733234bad1afb2879657d65d
             2afe6812746f4cc97f28f3a5dfdbfc7087511695d23da5e9792cd7ed6c9ddeb7
             1c"
        );
        let digest = test_digest(&test_order());
        assert_eq!(
            recover_order_signer(&signature, &digest).unwrap(),
            TEST_OWNER
        );
        let mut parity_only = signature;
        parity_only[64] -= 27;
        assert!(matches!(
            recover_order_signer(&parity_only, &digest),
            Err(CowError::InvalidSignatureV(1))
        ));

        let signer = PrivateKeySigner::random();
        let settlement = address!("0x9008D19f58AAbD9eD0D60971565AA8510560ab41");
        let digest = order_digest(&test_order(), 1, settlement);
        let signature = eip712_order_signature(&signer.sign_hash_sync(&digest).unwrap());
        assert!(matches!(signature[64], 27 | 28));
        assert_eq!(
            recover_order_signer(&signature, &digest).unwrap(),
            signer.address()
        );
        let uid = order_uid(&test_order(), 1, settlement, signer.address());
        assert_eq!(uid.digest(), digest);
        assert_eq!(uid.owner(), signer.address());
    }

    #[test]
    fn native_buy_order_commits_to_its_receiver() {
        let signer = PrivateKeySigner::random();
        let settlement = address!("0x9008D19f58AAbD9eD0D60971565AA8510560ab41");
        let order = Order {
            buyToken: BUY_NATIVE_TOKEN,
            receiver: Address::repeat_byte(0x04),
            ..test_order()
        };
        assert_ne!(order.receiver, signer.address());
        let digest = order_digest(&order, 1, settlement);
        let signature = eip712_order_signature(&signer.sign_hash_sync(&digest).unwrap());
        assert_eq!(
            recover_order_signer(&signature, &digest).unwrap(),
            signer.address()
        );
        let uid = order_uid(&order, 1, settlement, signer.address());
        assert_eq!(uid.digest(), digest);
        assert_eq!(uid.owner(), signer.address());

        // The UID is the settlement's proof of where the proceeds went.
        let redirected = Order {
            receiver: Address::repeat_byte(0x05),
            ..order.clone()
        };
        assert_ne!(order_digest(&redirected, 1, settlement), digest);
        let erc20_buy = Order {
            buyToken: Address::repeat_byte(0x02),
            ..order
        };
        assert_ne!(order_digest(&erc20_buy, 1, settlement), digest);
    }

    #[test]
    fn mainnet_settlement_domain_matches_deployed_separator() {
        // `domainSeparator()` of the mainnet `GPv2Settlement`.
        assert_eq!(
            settlement_domain(1, address!("0x9008D19f58AAbD9eD0D60971565AA8510560ab41"))
                .separator(),
            b256!("0xc078f884a2676e1345748b1feace7b0abee5d00ecadb6e574dcdd109a63e8943")
        );
    }

    #[test]
    fn hook_app_data_hash_commits_to_emitted_document() {
        let app_data = AppData::hooks(
            "railgun".to_owned(),
            vec![AppDataHook {
                call_data: Bytes::from_static(&[0xab, 0x01]),
                gas_limit: 350_000,
                target: Address::repeat_byte(0x01),
            }],
            vec![AppDataHook {
                call_data: Bytes::new(),
                gas_limit: 21_000,
                target: Address::repeat_byte(0x02),
            }],
        );
        let encoded = app_data.encode().unwrap();
        // `CoW` services parse `gasLimit` from a decimal string and read hooks
        // from `metadata.hooks`.
        assert_eq!(
            encoded.document,
            r#"{"appCode":"railgun","metadata":{"hooks":{"post":[{"callData":"0x","gasLimit":"21000","target":"0x0202020202020202020202020202020202020202"}],"pre":[{"callData":"0xab01","gasLimit":"350000","target":"0x0101010101010101010101010101010101010101"}],"version":"0.1.0"}},"version":"1.1.0"}"#
        );
        assert_eq!(encoded.hash, keccak256(encoded.document.as_bytes()));
        assert_eq!(
            serde_json::from_str::<AppData>(&encoded.document).unwrap(),
            app_data
        );
    }
}
