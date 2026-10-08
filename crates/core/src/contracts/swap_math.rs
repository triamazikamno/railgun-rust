//! `SwapMath`, a one-function contract that scales an amount by a ratio.
//!
//! It is stateless: no storage, no owner, no payable path, and it never holds
//! or moves funds. Scripts only call it and never delegatecall it.
//!
//! The source is `crates/core/resources/swap-math/src/SwapMath.sol`. The
//! creation code committed here is its `forge build` output under the
//! settings pinned in `crates/core/resources/swap-math/foundry.toml`: solc
//! 0.8.28, optimizer with 200 runs, EVM version paris, no IR pipeline, and no
//! metadata hash. The deterministic deployment proxy deploys it with
//! `CREATE2`, so the address is the same on every chain.

use alloy::hex;
use alloy::primitives::{Address, B256, Bytes, address, b256};
use alloy::sol;

sol! {
    interface SwapMath {
        function scale(uint256 amount, uint256 numerator, uint256 denominator) pure returns (uint256);
    }
}

/// Creation code of `SwapMath`: a 30-byte constructor followed by the runtime code.
pub const SWAP_MATH_CREATION_CODE: &[u8] = &hex!(
    "6080604052348015600f57600080fd5b5060df8061001e6000396000f3fe6080604052348015600f57600080fd5b506004361060285760003560e01c8063ca939f2614602d575b600080fd5b603c60383660046069565b604e565b60405190815260200160405180910390f35b600081605984866094565b6061919060be565b949350505050565b600080600060608486031215607d57600080fd5b505081359360208301359350604090920135919050565b808202811582820484141760b857634e487b7160e01b600052601160045260246000fd5b92915050565b60008260da57634e487b7160e01b600052601260045260246000fd5b50049056"
);

/// `CREATE2` salt of the deployment: `keccak256("railgun.swap-math.v1")`.
pub const SWAP_MATH_SALT: B256 =
    b256!("0xdad30f869f25f65c15c86acda55ca4cb03ea9b9260386f1fb2da845bb420d39a");

/// The deterministic deployment proxy. It deploys `data[32..]` with `CREATE2`
/// under the salt `data[..32]`.
pub const DETERMINISTIC_DEPLOYER: Address = address!("0x4e59b44847b379578588920cA78FbF26c0B4956C");

/// Where [`DETERMINISTIC_DEPLOYER`] puts [`SWAP_MATH_CREATION_CODE`] under
/// [`SWAP_MATH_SALT`].
pub const SWAP_MATH_ADDRESS: Address = address!("0x684efFaC51562fb66664b36fE81Ff165D3C2850E");

/// `keccak256` of the code deployed at [`SWAP_MATH_ADDRESS`].
pub const SWAP_MATH_RUNTIME_CODE_HASH: B256 =
    b256!("0x2672bb2ae120412f6cff0757bc05f9eb29c3d3d220c49223a0739a33908fab0c");

/// Transaction data that makes [`DETERMINISTIC_DEPLOYER`] deploy `SwapMath` at
/// [`SWAP_MATH_ADDRESS`]: the salt followed by the creation code.
#[must_use]
pub fn swap_math_deployment_calldata() -> Bytes {
    [SWAP_MATH_SALT.as_slice(), SWAP_MATH_CREATION_CODE]
        .concat()
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::keccak256;
    use alloy::sol_types::SolCall;

    #[test]
    fn constants_match_the_committed_bytecode() {
        assert_eq!(SWAP_MATH_SALT, keccak256("railgun.swap-math.v1"));
        assert_eq!(
            DETERMINISTIC_DEPLOYER.create2(SWAP_MATH_SALT, keccak256(SWAP_MATH_CREATION_CODE)),
            SWAP_MATH_ADDRESS
        );
        // The constructor returns everything after its 30 bytes.
        let runtime = &SWAP_MATH_CREATION_CODE[SWAP_MATH_CREATION_CODE.len() - 223..];
        assert_eq!(SWAP_MATH_CREATION_CODE.len(), 30 + 223);
        assert_eq!(keccak256(runtime), SWAP_MATH_RUNTIME_CODE_HASH);
        assert_eq!(SwapMath::scaleCall::SELECTOR, hex!("ca939f26"));

        let calldata = swap_math_deployment_calldata();
        assert_eq!(calldata[..32], SWAP_MATH_SALT[..]);
        assert_eq!(calldata[32..], *SWAP_MATH_CREATION_CODE);
    }
}
