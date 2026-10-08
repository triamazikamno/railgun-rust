// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// Scales an amount by a ratio. Stateless: no storage, no owner, no payable
/// path, and it never holds or moves funds.
contract SwapMath {
    /// `amount * numerator / denominator`, rounded down. Reverts when the
    /// product overflows or the denominator is zero.
    function scale(uint256 amount, uint256 numerator, uint256 denominator) external pure returns (uint256) {
        return amount * numerator / denominator;
    }
}
