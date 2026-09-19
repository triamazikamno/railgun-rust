//! Railgun deployment identity and protocol history, independent of network policy.

use alloy::primitives::{Address, address};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RailgunDeployment {
    pub chain_id: u64,
    pub contract: Address,
    pub relay_adapt_contract: Address,
    pub relay_adapt_7702_contract: Address,
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
                relay_adapt_contract: address!("0xAc9f360Ae85469B27aEDdEaFC579Ef2d052aD405"),
                relay_adapt_7702_contract: address!("0x05ae73c5925d843864ae6f261f3175de2ebcd963"),
                deployment_block: 14_737_691,
                v2_start_block: 16_076_750,
                legacy_shield_block: 16_790_263,
            }),
            56 => Some(Self {
                chain_id,
                contract: address!("0x590162bf4b50f6576a459b75309ee21d92178a10"),
                relay_adapt_contract: address!("0xf82d00fc51f730f42a00f85e74895a2849fff2dd"),
                relay_adapt_7702_contract: address!("0x48cf4b897f64d81212c1423d78a05e828d0ce19d"),
                deployment_block: 17_633_701,
                v2_start_block: 23_478_204,
                legacy_shield_block: 26_313_947,
            }),
            137 => Some(Self {
                chain_id,
                contract: address!("0x19b620929f97b7b990801496c3b361ca5def8c71"),
                relay_adapt_contract: address!("0xF82d00fC51F730F42A00F85E74895a2849ffF2Dd"),
                relay_adapt_7702_contract: address!("0x48cf4b897f64d81212c1423d78a05e828d0ce19d"),
                deployment_block: 28_083_766,
                v2_start_block: 36_219_104,
                legacy_shield_block: 40_143_539,
            }),
            42161 => Some(Self {
                chain_id,
                contract: address!("0xfa7093cdd9ee6932b4eb2c9e1cde7ce00b1fa4b9"),
                relay_adapt_contract: address!("0xB4F2d77bD12c6b548Ae398244d7FAD4ABCE4D89b"),
                relay_adapt_7702_contract: address!("0x48cf4b897f64d81212c1423d78a05e828d0ce19d"),
                deployment_block: 56_109_834,
                v2_start_block: 0,
                legacy_shield_block: 68_196_853,
            }),
            _ => None,
        }
    }
}
