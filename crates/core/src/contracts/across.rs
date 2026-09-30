//! Across V3 `SpokePool` deposits and the events that link a deposit to its fill.
//!
//! `SpokePool` addresses are chain profile data supplied by callers. `depositV3`
//! takes addresses, while `FundsDeposited` and `FilledRelay` carry every address
//! as a `bytes32`; convert with [`address_to_bytes32`] and [`bytes32_to_address`].
//!
//! Pinned against the `SpokePool` implementations deployed on Ethereum, BNB Chain,
//! Polygon, and Arbitrum One, checked on 2026-09-29. Each of them has the
//! `depositV3` selector and both event topics declared here.

use alloy::primitives::{Address, B256};
use alloy::sol;

sol! {
    struct V3RelayExecutionEventInfo {
        bytes32 updatedRecipient;
        bytes32 updatedMessageHash;
        uint256 updatedOutputAmount;
        uint8 fillType;
    }

    interface SpokePool {
        function depositV3(
            address depositor,
            address recipient,
            address inputToken,
            address outputToken,
            uint256 inputAmount,
            uint256 outputAmount,
            uint256 destinationChainId,
            address exclusiveRelayer,
            uint32 quoteTimestamp,
            uint32 fillDeadline,
            uint32 exclusivityParameter,
            bytes message
        ) payable;

        event FundsDeposited(
            bytes32 inputToken,
            bytes32 outputToken,
            uint256 inputAmount,
            uint256 outputAmount,
            uint256 indexed destinationChainId,
            uint256 indexed depositId,
            uint32 quoteTimestamp,
            uint32 fillDeadline,
            uint32 exclusivityDeadline,
            bytes32 indexed depositor,
            bytes32 recipient,
            bytes32 exclusiveRelayer,
            bytes message
        );

        event FilledRelay(
            bytes32 inputToken,
            bytes32 outputToken,
            uint256 inputAmount,
            uint256 outputAmount,
            uint256 repaymentChainId,
            uint256 indexed originChainId,
            uint256 indexed depositId,
            uint32 fillDeadline,
            uint32 exclusivityDeadline,
            bytes32 exclusiveRelayer,
            bytes32 indexed relayer,
            bytes32 depositor,
            bytes32 recipient,
            bytes32 messageHash,
            V3RelayExecutionEventInfo relayExecutionInfo
        );
    }
}

/// An address as the left-padded `bytes32` that Across events carry.
#[must_use]
pub fn address_to_bytes32(address: Address) -> B256 {
    address.into_word()
}

/// The address in a left-padded `bytes32`, or `None` if its upper 12 bytes are
/// not zero.
#[must_use]
pub fn bytes32_to_address(word: B256) -> Option<Address> {
    word[..12]
        .iter()
        .all(|byte| *byte == 0)
        .then(|| Address::from_word(word))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::hex;
    use alloy::primitives::{U256, address, b256};
    use alloy::sol_types::{SolCall, SolEvent};

    const USER: Address = address!("0x99C6a66C3dF9b84ad32907dDCBd90da4EcE12Cc3");
    const ARBITRUM_WETH: Address = address!("0x82aF49447D8a07e3bd95BD0d56f35241523fBab1");
    const MAINNET_WETH: Address = address!("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
    const INPUT_AMOUNT: u64 = 430_853_243_434_415;
    const OUTPUT_AMOUNT: u64 = 378_966_308_170_474;
    const DEPOSIT_ID: u64 = 4_701_902;

    // Arbitrum One `SpokePool` 0xe35e9842fceaCA96570B734083f4a58e8F7C5f2A, tx
    // 0x3116eab797171befdc8e2d808d33e7896a3442c68d85a494f6d230b04be8cb4e.
    fn arbitrum_deposit() -> SpokePool::FundsDeposited {
        SpokePool::FundsDeposited::decode_raw_log(
            [
                b256!("0x32ed1a409ef04c7b0227189c3a103dc5ac10e775a15b785dcc510201f7c25ad3"),
                b256!("0x0000000000000000000000000000000000000000000000000000000000000001"),
                b256!("0x000000000000000000000000000000000000000000000000000000000047bece"),
                b256!("0x00000000000000000000000099c6a66c3df9b84ad32907ddcbd90da4ece12cc3"),
            ],
            &hex!(
                "00000000000000000000000082af49447d8a07e3bd95bd0d56f35241523fbab1
                 000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2
                 000000000000000000000000000000000000000000000000000187dbd68675af
                 000000000000000000000000000000000000000000000000000158aaf82e2aea
                 000000000000000000000000000000000000000000000000000000006abc2ec7
                 000000000000000000000000000000000000000000000000000000006abc5255
                 0000000000000000000000000000000000000000000000000000000000000000
                 00000000000000000000000099c6a66c3df9b84ad32907ddcbd90da4ece12cc3
                 0000000000000000000000000000000000000000000000000000000000000000
                 0000000000000000000000000000000000000000000000000000000000000140
                 0000000000000000000000000000000000000000000000000000000000000000"
            ),
        )
        .unwrap()
    }

    #[test]
    fn bindings_match_deployed_spoke_pool_abi() {
        assert_eq!(SpokePool::depositV3Call::SELECTOR, hex!("7b939232"));
        assert_eq!(
            SpokePool::FundsDeposited::SIGNATURE_HASH,
            b256!("0x32ed1a409ef04c7b0227189c3a103dc5ac10e775a15b785dcc510201f7c25ad3")
        );
        assert_eq!(
            SpokePool::FilledRelay::SIGNATURE_HASH,
            b256!("0x44b559f101f8fbcc8a0ea43fa91a05a729a5ea6e14a7c75aa750374690137208")
        );
    }

    #[test]
    fn decodes_deployed_funds_deposited_log() {
        let deposit = arbitrum_deposit();
        assert_eq!(deposit.destinationChainId, U256::ONE);
        assert_eq!(deposit.depositId, U256::from(DEPOSIT_ID));
        assert_eq!(bytes32_to_address(deposit.depositor), Some(USER));
        assert_eq!(bytes32_to_address(deposit.recipient), Some(USER));
        assert_eq!(bytes32_to_address(deposit.inputToken), Some(ARBITRUM_WETH));
        assert_eq!(bytes32_to_address(deposit.outputToken), Some(MAINNET_WETH));
        assert_eq!(deposit.inputAmount, U256::from(INPUT_AMOUNT));
        assert_eq!(deposit.outputAmount, U256::from(OUTPUT_AMOUNT));
        assert_eq!(deposit.exclusiveRelayer, B256::ZERO);
        assert!(deposit.message.is_empty());
        assert_eq!(address_to_bytes32(USER), deposit.depositor);
        assert_eq!(bytes32_to_address(B256::repeat_byte(0x01)), None);
    }

    #[test]
    fn decodes_deployed_filled_relay_log_matching_its_deposit() {
        // Ethereum `SpokePool` 0x5c7BCd6E7De5423a257D81B442095A1a6ced35C5, block
        // 26085850, tx 0xb1668f6a7151c18a270a0dbb8c69b4d4eea327cc793da1ccefb0ce9eafb7e096.
        let fill = SpokePool::FilledRelay::decode_raw_log(
            [
                b256!("0x44b559f101f8fbcc8a0ea43fa91a05a729a5ea6e14a7c75aa750374690137208"),
                b256!("0x000000000000000000000000000000000000000000000000000000000000a4b1"),
                b256!("0x000000000000000000000000000000000000000000000000000000000047bece"),
                b256!("0x000000000000000000000000394311a6aaa0d8e3411d8b62de4578d41322d1bd"),
            ],
            &hex!(
                "00000000000000000000000082af49447d8a07e3bd95bd0d56f35241523fbab1
                 000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2
                 000000000000000000000000000000000000000000000000000187dbd68675af
                 000000000000000000000000000000000000000000000000000158aaf82e2aea
                 000000000000000000000000000000000000000000000000000000000000a4b1
                 000000000000000000000000000000000000000000000000000000006abc5255
                 0000000000000000000000000000000000000000000000000000000000000000
                 0000000000000000000000000000000000000000000000000000000000000000
                 00000000000000000000000099c6a66c3df9b84ad32907ddcbd90da4ece12cc3
                 00000000000000000000000099c6a66c3df9b84ad32907ddcbd90da4ece12cc3
                 0000000000000000000000000000000000000000000000000000000000000000
                 00000000000000000000000099c6a66c3df9b84ad32907ddcbd90da4ece12cc3
                 0000000000000000000000000000000000000000000000000000000000000000
                 000000000000000000000000000000000000000000000000000158aaf82e2aea
                 0000000000000000000000000000000000000000000000000000000000000000"
            ),
        )
        .unwrap();
        assert_eq!(fill.originChainId, U256::from(42_161));
        assert_eq!(fill.depositId, U256::from(DEPOSIT_ID));
        assert_eq!(
            bytes32_to_address(fill.relayer),
            Some(address!("0x394311A6Aaa0D8E3411D8b62DE4578D41322d1bD"))
        );
        assert_eq!(bytes32_to_address(fill.depositor), Some(USER));
        assert_eq!(bytes32_to_address(fill.recipient), Some(USER));
        assert_eq!(fill.messageHash, B256::ZERO);
        assert_eq!(fill.relayExecutionInfo.updatedRecipient, fill.recipient);
        assert_eq!(
            fill.relayExecutionInfo.updatedOutputAmount,
            fill.outputAmount
        );

        // The fields a wallet matches a fill against its origin deposit by.
        let deposit = arbitrum_deposit();
        assert_eq!(fill.depositId, deposit.depositId);
        assert_eq!(
            (fill.inputToken, fill.outputToken),
            (deposit.inputToken, deposit.outputToken)
        );
        assert_eq!(
            (fill.inputAmount, fill.outputAmount),
            (deposit.inputAmount, deposit.outputAmount)
        );
        assert_eq!(
            (fill.depositor, fill.recipient),
            (deposit.depositor, deposit.recipient)
        );
        assert_eq!(fill.fillDeadline, deposit.fillDeadline);
        assert_eq!(fill.exclusiveRelayer, deposit.exclusiveRelayer);
    }
}
