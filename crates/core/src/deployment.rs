//! Railgun deployment identity and protocol history, independent of network policy.

use alloy::primitives::{Address, address};

use crate::contracts::executor::{ExecutorCapability, ExecutorDelegate};

const ETHEREUM_RELAY_ADAPT_HISTORY: &[Address] = &[
    address!("0x22af4EDBeA3De885dDa8f0a0653E6209e44e5B84"),
    address!("0xc3f2C8F9d5F0705De706b1302B7a039e1e11aC88"),
    address!("0x4025ee6512DBbda97049Bcf5AA5D38C54aF6bE8a"),
    address!("0xAc9f360Ae85469B27aEDdEaFC579Ef2d052aD405"),
];

const BNB_CHAIN_RELAY_ADAPT_HISTORY: &[Address] = &[
    address!("0x20d868C7F1Eb706C46641ADD2f849c5DBf4dB158"),
    address!("0x25f795A8eC8aF7904aa403fF2Cc7205ce683BF52"),
    address!("0x741936fb83DDf324636D3048b3E6bC800B8D9e12"),
    address!("0xF82d00fC51F730F42A00F85E74895a2849ffF2Dd"),
];

const POLYGON_RELAY_ADAPT_HISTORY: &[Address] = &[
    address!("0x30D8AD0339e2CF160620589f2DBa1765126A5fDC"),
    address!("0x969eE9AC1E0B5F5Dd781f63A168C52b73062ff86"),
    address!("0xc7FfA542736321A3dd69246d73987566a5486968"),
    address!("0xF82d00fC51F730F42A00F85E74895a2849ffF2Dd"),
];

const ARBITRUM_RELAY_ADAPT_HISTORY: &[Address] = &[
    address!("0x5aD95C537b002770a39dea342c4bb2b68B1497aA"),
    address!("0xB4F2d77bD12c6b548Ae398244d7FAD4ABCE4D89b"),
];

const SEPOLIA_RELAY_ADAPT_HISTORY: &[Address] =
    &[address!("0x7e3d929EbD5bDC84d02Bd3205c777578f33A214D")];

const SEPOLIA_RELAY_ADAPT_7702_DELEGATES: &[ExecutorDelegate] = &[nonce_bearing_v1(address!(
    "0x05aE73C5925d843864AE6f261f3175dE2ebCd963"
))];

const fn nonce_bearing_v1(address: Address) -> ExecutorDelegate {
    ExecutorDelegate {
        address,
        capability: ExecutorCapability::NonceBearingV1,
    }
}

const ETHEREUM_RELAY_ADAPT_7702_DELEGATES: &[ExecutorDelegate] = &[
    nonce_bearing_v1(address!("0x05aE73C5925d843864AE6f261f3175dE2ebCd963")),
    nonce_bearing_v1(address!("0x1F74b4339990Db761bC0168F20D294A3a141497e")),
];

/// Shared by BNB Chain, Polygon and Arbitrum.
const RELAY_ADAPT_7702_DELEGATES: &[ExecutorDelegate] = &[
    nonce_bearing_v1(address!("0x48cf4b897f64D81212c1423D78a05E828d0cE19d")),
    nonce_bearing_v1(address!("0xa2BFd382c54bb33DF6A13f21acd8770dc1e67D4D")),
];

const BASE_RELAY_ADAPT_7702_DELEGATES: &[ExecutorDelegate] = &[nonce_bearing_v1(address!(
    "0xAcBC3De27E7d9750a7F26b2eCCE9c89C24Cc8691"
))];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RailgunDeployment {
    pub chain_id: u64,
    pub contract: Address,
    pub relay_adapt_contract: Option<Address>,
    /// The primary `RelayAdapt7702` delegate, for new delegations without another choice.
    pub relay_adapt_7702_contract: Address,
    /// Every `RelayAdapt7702` delegate the chain has used, oldest first, the primary last.
    pub relay_adapt_7702_delegates: &'static [ExecutorDelegate],
    /// Every shared `RelayAdapt` contract the chain has used, the current one included.
    pub relay_adapt_history: &'static [Address],
    pub deployment_block: u64,
    pub v2_start_block: u64,
    pub legacy_shield_block: u64,
}

impl RailgunDeployment {
    #[must_use]
    pub const fn for_chain(chain_id: u64) -> Option<Self> {
        match chain_id {
            1 => Some(Self {
                chain_id,
                contract: address!("0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"),
                relay_adapt_contract: Some(address!("0xAc9f360Ae85469B27aEDdEaFC579Ef2d052aD405")),
                relay_adapt_7702_contract: address!("0x1F74b4339990Db761bC0168F20D294A3a141497e"),
                relay_adapt_7702_delegates: ETHEREUM_RELAY_ADAPT_7702_DELEGATES,
                relay_adapt_history: ETHEREUM_RELAY_ADAPT_HISTORY,
                deployment_block: 14_737_691,
                v2_start_block: 16_076_750,
                legacy_shield_block: 16_790_263,
            }),
            56 => Some(Self {
                chain_id,
                contract: address!("0x590162bf4b50f6576a459b75309ee21d92178a10"),
                relay_adapt_contract: Some(address!("0xf82d00fc51f730f42a00f85e74895a2849fff2dd")),
                relay_adapt_7702_contract: address!("0xa2BFd382c54bb33DF6A13f21acd8770dc1e67D4D"),
                relay_adapt_7702_delegates: RELAY_ADAPT_7702_DELEGATES,
                relay_adapt_history: BNB_CHAIN_RELAY_ADAPT_HISTORY,
                deployment_block: 17_633_701,
                v2_start_block: 23_478_204,
                legacy_shield_block: 26_313_947,
            }),
            137 => Some(Self {
                chain_id,
                contract: address!("0x19b620929f97b7b990801496c3b361ca5def8c71"),
                relay_adapt_contract: Some(address!("0xF82d00fC51F730F42A00F85E74895a2849ffF2Dd")),
                relay_adapt_7702_contract: address!("0xa2BFd382c54bb33DF6A13f21acd8770dc1e67D4D"),
                relay_adapt_7702_delegates: RELAY_ADAPT_7702_DELEGATES,
                relay_adapt_history: POLYGON_RELAY_ADAPT_HISTORY,
                deployment_block: 28_083_766,
                v2_start_block: 36_219_104,
                legacy_shield_block: 40_143_539,
            }),
            42161 => Some(Self {
                chain_id,
                contract: address!("0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"),
                relay_adapt_contract: Some(address!("0xB4F2d77bD12c6b548Ae398244d7FAD4ABCE4D89b")),
                relay_adapt_7702_contract: address!("0xa2BFd382c54bb33DF6A13f21acd8770dc1e67D4D"),
                relay_adapt_7702_delegates: RELAY_ADAPT_7702_DELEGATES,
                relay_adapt_history: ARBITRUM_RELAY_ADAPT_HISTORY,
                deployment_block: 56_109_834,
                v2_start_block: 0,
                legacy_shield_block: 68_196_853,
            }),
            8453 => Some(Self {
                chain_id,
                contract: address!("0x0047d1f97674614189e80566575fb615788acf25"),
                relay_adapt_contract: None,
                relay_adapt_7702_contract: address!("0xAcBC3De27E7d9750a7F26b2eCCE9c89C24Cc8691"),
                relay_adapt_7702_delegates: BASE_RELAY_ADAPT_7702_DELEGATES,
                relay_adapt_history: &[],
                deployment_block: 50_224_711,
                v2_start_block: 0,
                legacy_shield_block: 0,
            }),
            11_155_111 => Some(Self {
                chain_id,
                contract: address!("0xecfcf3b4ec647c4ca6d49108b311b7a7c9543fea"),
                relay_adapt_contract: Some(address!("0x7e3d929EbD5bDC84d02Bd3205c777578f33A214D")),
                relay_adapt_7702_contract: address!("0x05aE73C5925d843864AE6f261f3175dE2ebCd963"),
                relay_adapt_7702_delegates: SEPOLIA_RELAY_ADAPT_7702_DELEGATES,
                relay_adapt_history: SEPOLIA_RELAY_ADAPT_HISTORY,
                deployment_block: 5_784_774,
                v2_start_block: 0,
                legacy_shield_block: 0,
            }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_relay_adapt_is_latest_history_entry() {
        for chain_id in [1, 56, 137, 42161, 8453] {
            let deployment = RailgunDeployment::for_chain(chain_id).unwrap();
            assert_eq!(
                deployment.relay_adapt_contract,
                deployment.relay_adapt_history.last().copied()
            );
        }
    }

    #[test]
    fn primary_relay_adapt_7702_is_latest_delegate() {
        for chain_id in [1, 56, 137, 42161, 8453] {
            let deployment = RailgunDeployment::for_chain(chain_id).unwrap();
            assert_eq!(
                Some(deployment.relay_adapt_7702_contract),
                deployment
                    .relay_adapt_7702_delegates
                    .last()
                    .map(|delegate| delegate.address)
            );
        }
    }
}
