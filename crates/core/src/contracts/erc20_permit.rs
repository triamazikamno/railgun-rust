//! EIP-2612 `permit`: the token calls and the struct an owner signs.
//!
//! A token's EIP-712 domain is its own. Callers read it from the token and
//! check it against `DOMAIN_SEPARATOR()` before signing.

use alloy::primitives::{Address, Bytes, Signature, U256};
use alloy::sol;
use alloy::sol_types::SolCall;

sol! {
    /// The approval an owner signs. Field names and types form the EIP-712
    /// type hash.
    #[derive(Debug, PartialEq, Eq)]
    struct Permit {
        address owner;
        address spender;
        uint256 value;
        uint256 nonce;
        uint256 deadline;
    }

    interface IERC20Permit {
        function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s);
        function nonces(address owner) view returns (uint256);
        function DOMAIN_SEPARATOR() view returns (bytes32);
        /// EIP-5267.
        function eip712Domain() view returns (bytes1 fields, string name, string version, uint256 chainId, address verifyingContract, bytes32 salt, uint256[] extensions);
        function name() view returns (string);
        /// Not part of EIP-2612. Tokens without it sign under version "1".
        function version() view returns (string);
    }
}

/// `IERC20Permit.permit` calldata for `permit` signed with `signature`.
#[must_use]
pub fn permit_calldata(permit: &Permit, signature: &Signature) -> Bytes {
    IERC20Permit::permitCall {
        owner: permit.owner,
        spender: permit.spender,
        value: permit.value,
        deadline: permit.deadline,
        v: signature.v_byte(),
        r: signature.r().into(),
        s: signature.s().into(),
    }
    .abi_encode()
    .into()
}

/// The owner, spender, value and deadline of `IERC20Permit.permit` calldata.
/// The nonce is not part of the call.
#[must_use]
pub fn decode_permit_calldata(calldata: &[u8]) -> Option<(Address, Address, U256, U256)> {
    let call = IERC20Permit::permitCall::abi_decode(calldata).ok()?;
    Some((call.owner, call.spender, call.value, call.deadline))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::hex;
    use alloy::primitives::{address, b256, keccak256};
    use alloy::sol_types::SolStruct;

    #[test]
    fn permit_matches_eip_2612() {
        let permit = Permit {
            owner: address!("0x1111111111111111111111111111111111111111"),
            spender: address!("0x2222222222222222222222222222222222222222"),
            value: U256::from(1_000_000u64),
            nonce: U256::from(7u64),
            deadline: U256::from(1_800_000_000u64),
        };
        assert_eq!(
            permit.eip712_type_hash(),
            b256!("0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9")
        );
        assert_eq!(
            permit.eip712_type_hash(),
            keccak256(
                "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
            )
        );
        assert_eq!(IERC20Permit::permitCall::SELECTOR, hex!("d505accf"));
        assert_eq!(IERC20Permit::noncesCall::SELECTOR, hex!("7ecebe00"));
        assert_eq!(
            IERC20Permit::DOMAIN_SEPARATORCall::SELECTOR,
            hex!("3644e515")
        );
        assert_eq!(IERC20Permit::eip712DomainCall::SELECTOR, hex!("84b0196e"));

        let r = b256!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let s = b256!("0x0bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let signature = Signature::from_scalars_and_parity(r, s, true);
        let calldata = permit_calldata(&permit, &signature);
        assert_eq!(
            calldata.as_ref(),
            hex!(
                "d505accf"
                "0000000000000000000000001111111111111111111111111111111111111111"
                "0000000000000000000000002222222222222222222222222222222222222222"
                "00000000000000000000000000000000000000000000000000000000000f4240"
                "000000000000000000000000000000000000000000000000000000006b49d200"
                "000000000000000000000000000000000000000000000000000000000000001c"
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                "0bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            )
        );
        assert_eq!(
            decode_permit_calldata(&calldata),
            Some((permit.owner, permit.spender, permit.value, permit.deadline))
        );
    }
}
