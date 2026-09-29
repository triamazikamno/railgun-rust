//! Per-chain calibrated gas model for Railgun operations.
//!
//! Each estimate is the gas an operation adds to its enclosing transaction,
//! including its own calldata and excluding the 21,000 intrinsic gas. The
//! calibration measured post-refund `gasUsed`.
//!
//! ```text
//! transact  = transact_call + Σtx [transaction + nullifier·inputs + commitment·outputs
//!                                  + leaf·inserted + unshield·(1 if it unshields)] + tree(L)
//! shield(n) = shield_call + shield_request·n + tree(n)
//! relay(a)  = relay_call + relay_action·a   (the inner transact or shield is added by the caller)
//! executor  = executor_call                  (one RelayAdapt7702 execute)
//!
//! inserted = outputs − 1 if the transaction unshields, else outputs; L = Σ inserted; tree(0) = 0
//! tree(L), UpperBound = tree_update + tree_hash·worst_case_hashes(L)
//! tree(L), Expected   = tree_update + tree_hash·E(L) − tree_write·(16 − W(L))
//! ```
//!
//! # Provenance
//!
//! Mainnet samples of 2026-09-28: Ethereum blocks 26,072,489–26,075,380, BNB
//! 123,513,083–124,505,573, Polygon 94,391,208–94,589,414 and Arbitrum
//! 508,687,391–509,677,298 (net of `gasUsedForL1`). Calldata was decoded into
//! exact transaction shapes and tree start indices and checked against
//! `callTracer` traces. Ethereum anvil-fork runs of the swap hooks at the worst
//! tree positions with cold slots add the hook rows.
//!
//! # Acceptance
//!
//! [`GasEstimateMode::UpperBound`] is at least 1.05× every direct and batch
//! sample on chains 1, 56 and 42161, and at least 1.10× on Polygon.
//! [`GasEstimateMode::Expected`] medians per shape fall between 1.00× and
//! 1.08×, except as listed under known limits.
//!
//! # Polygon
//!
//! Polygon reprices the altbn128 precompiles (`ecPairing` 67,500 + 51,000 per
//! pair, `ecMul` 12,600 and `ecAdd` 540 in traces, against 45,000 + 34,000,
//! 6,000 and 150), and its verifier execution costs more. Its `transact_call` of
//! 211,000 is empirical and unexplained.
//!
//! # Default
//!
//! [`DEFAULT_GAS_MODEL`] is the fieldwise maximum of the two calibrations and
//! covers every chain without one. An unknown chain may reprice the precompiles
//! like Polygon; a bound set too high only costs unused gas, while one set too
//! low reverts.
//!
//! # Tree terms
//!
//! `insertLeaves` hashes once per distinct parent of the current run of nodes at
//! each of the 16 levels. A run of n nodes at a random offset has (n + 1)/2
//! distinct parents on average, so the expected total is
//! 16 + (L − 1)(1 − 2^−16), rounded to E(L) = L + 15. A level that writes the
//! stored subtree node (`filledSubTrees`) costs a cold SSTORE plus a cold read
//! more than one that only reads it. W(L) is the expected number of writing
//! levels: 8 (L = 1), 9 (L = 2), 10 (3..=8), 11 (9..=32) and 12 above that.
//!
//! # Known limits
//!
//! - Two or more leaves can land at unlucky tree positions, where Expected runs
//!   up to ~15% low.
//! - Batches of one circuit cost 50–70k less per extra transaction than
//!   modelled because the verifying key loads cold once. `UpperBound` stays
//!   safe.
//! - `executor_call` is probably high for the hook path.
//! - The first leaf of a fresh tree costs ~46k more than `UpperBound`. Only the
//!   callers' declared-limit margins cover it.
//! - Polygon Expected medians run 1.09–1.14 on shapes with at most one inserted
//!   leaf and on relay calls. The BNB `transact[1/1u]` median is 1.082.

use broadcaster_core::tree::TREE_DEPTH;

use super::TransactionShape;

const DEPTH: u64 = TREE_DEPTH as u64;

/// Which side of the gas distribution an estimate targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GasEstimateMode {
    /// Bounds every calibration sample. Use it for gas that is signed,
    /// submitted, or used as a ceiling or reserve.
    UpperBound,
    /// Tracks typical gas. Use it for fee quotes.
    Expected,
}

/// Gas coefficients of one chain calibration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RailgunGasModel {
    /// Fixed cost of one `transact` call.
    transact_call: u64,
    /// Per transaction: proof verification and per-transaction checks.
    transaction: u64,
    /// Per input nullifier.
    nullifier: u64,
    /// Per output commitment, including an unshield output.
    commitment: u64,
    /// Per commitment inserted into the tree.
    leaf: u64,
    /// Per transaction that unshields.
    unshield: u64,
    /// Fixed cost of one tree insertion.
    tree_update: u64,
    /// Per Poseidon hash of a tree insertion.
    tree_hash: u64,
    /// Saved per tree level that reads the stored subtree node without writing it.
    tree_write: u64,
    /// Fixed cost of one `shield` call.
    shield_call: u64,
    /// Per shield request.
    shield_request: u64,
    /// Fixed cost of one `RelayAdapt` call.
    relay_call: u64,
    /// Per `RelayAdapt` action.
    relay_action: u64,
    /// One EIP-7702 `RelayAdapt7702` execute: signature, nonce and dispatch.
    executor_call: u64,
}

/// Calibration for chains 1, 56 and 42161.
pub const ETHEREUM_GAS_MODEL: RailgunGasModel = RailgunGasModel {
    transact_call: 14_900,
    transaction: 292_900,
    nullifier: 32_000,
    commitment: 12_000,
    leaf: 6_000,
    unshield: 135_500,
    tree_update: 193_800,
    tree_hash: 30_000,
    tree_write: 5_000,
    shield_call: 19_400,
    shield_request: 104_900,
    relay_call: 10_000,
    relay_action: 13_700,
    executor_call: 91_900,
};

/// Calibration for chain 137.
pub const POLYGON_GAS_MODEL: RailgunGasModel = RailgunGasModel {
    transact_call: 211_000,
    transaction: 339_000,
    nullifier: 59_800,
    commitment: 12_000,
    leaf: 6_000,
    unshield: 183_100,
    tree_update: 263_100,
    tree_hash: 30_000,
    tree_write: 5_000,
    shield_call: 75_100,
    shield_request: 110_600,
    relay_call: 10_000,
    relay_action: 0,
    executor_call: 91_900,
};

/// Fieldwise maximum of the calibrations, for every chain without one.
pub const DEFAULT_GAS_MODEL: RailgunGasModel =
    RailgunGasModel::fieldwise_max(&ETHEREUM_GAS_MODEL, &POLYGON_GAS_MODEL);

/// Aggregate transaction counts of one `transact` call.
///
/// Linear terms sum and the tree term depends only on the total inserted
/// leaves, so an aggregate gives the same estimate as per-transaction shapes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransactGasShape {
    /// Transactions in the call.
    pub transactions: usize,
    /// Total nullifiers.
    pub inputs: usize,
    /// Total commitments, including unshield outputs.
    pub outputs: usize,
    /// Transactions that unshield.
    pub unshields: usize,
}

impl TransactGasShape {
    const fn inserted_leaves(self) -> usize {
        self.outputs.saturating_sub(self.unshields)
    }
}

impl From<&[TransactionShape]> for TransactGasShape {
    fn from(transactions: &[TransactionShape]) -> Self {
        transactions
            .iter()
            .fold(Self::default(), |shape, transaction| Self {
                transactions: shape.transactions.saturating_add(1),
                inputs: shape.inputs.saturating_add(transaction.input_count),
                outputs: shape.outputs.saturating_add(transaction.output_count),
                unshields: shape
                    .unshields
                    .saturating_add(usize::from(transaction.has_unshield)),
            })
    }
}

impl RailgunGasModel {
    /// Calibration for `chain_id`; [`DEFAULT_GAS_MODEL`] for every chain
    /// without one.
    #[must_use]
    pub const fn for_chain(chain_id: u64) -> &'static Self {
        match chain_id {
            1 | 56 | 42161 => &ETHEREUM_GAS_MODEL,
            137 => &POLYGON_GAS_MODEL,
            _ => &DEFAULT_GAS_MODEL,
        }
    }

    /// Gas of one `transact` call; zero when `shape` has no transactions.
    #[must_use]
    pub const fn transact(&self, mode: GasEstimateMode, shape: TransactGasShape) -> u64 {
        if shape.transactions == 0 {
            return 0;
        }
        let leaves = shape.inserted_leaves();
        self.transact_call
            .saturating_add(self.transaction.saturating_mul(shape.transactions as u64))
            .saturating_add(self.nullifier.saturating_mul(shape.inputs as u64))
            .saturating_add(self.commitment.saturating_mul(shape.outputs as u64))
            .saturating_add(self.leaf.saturating_mul(leaves as u64))
            .saturating_add(self.unshield.saturating_mul(shape.unshields as u64))
            .saturating_add(self.tree(mode, leaves))
    }

    /// Gas of one `shield` call with `requests` requests; zero without requests.
    #[must_use]
    pub const fn shield(&self, mode: GasEstimateMode, requests: usize) -> u64 {
        if requests == 0 {
            return 0;
        }
        self.shield_call
            .saturating_add(self.shield_request.saturating_mul(requests as u64))
            .saturating_add(self.tree(mode, requests))
    }

    /// Gas of the `RelayAdapt` wrapper around `actions` actions, excluding the
    /// inner `transact` and `shield` calls.
    #[must_use]
    pub const fn relay(&self, actions: usize) -> u64 {
        self.relay_call
            .saturating_add(self.relay_action.saturating_mul(actions as u64))
    }

    /// Gas of one EIP-7702 `RelayAdapt7702` execute, excluding its calls.
    #[must_use]
    pub const fn executor(&self) -> u64 {
        self.executor_call
    }

    const fn tree(&self, mode: GasEstimateMode, leaves: usize) -> u64 {
        if leaves == 0 {
            return 0;
        }
        match mode {
            GasEstimateMode::UpperBound => self.tree_update.saturating_add(
                self.tree_hash
                    .saturating_mul(worst_case_tree_hashes(leaves)),
            ),
            GasEstimateMode::Expected => self
                .tree_update
                .saturating_add(self.tree_hash.saturating_mul(expected_tree_hashes(leaves)))
                .saturating_sub(
                    self.tree_write
                        .saturating_mul(DEPTH.saturating_sub(expected_tree_writes(leaves))),
                ),
        }
    }

    const fn fieldwise_max(a: &Self, b: &Self) -> Self {
        Self {
            transact_call: max(a.transact_call, b.transact_call),
            transaction: max(a.transaction, b.transaction),
            nullifier: max(a.nullifier, b.nullifier),
            commitment: max(a.commitment, b.commitment),
            leaf: max(a.leaf, b.leaf),
            unshield: max(a.unshield, b.unshield),
            tree_update: max(a.tree_update, b.tree_update),
            tree_hash: max(a.tree_hash, b.tree_hash),
            tree_write: max(a.tree_write, b.tree_write),
            shield_call: max(a.shield_call, b.shield_call),
            shield_request: max(a.shield_request, b.shield_request),
            relay_call: max(a.relay_call, b.relay_call),
            relay_action: max(a.relay_action, b.relay_action),
            executor_call: max(a.executor_call, b.executor_call),
        }
    }
}

const fn max(a: u64, b: u64) -> u64 {
    if a > b { a } else { b }
}

/// Most Poseidon hashes one insertion of `leaves` leaves can take: a run of n
/// nodes has at most n/2 + 1 distinct parents.
const fn worst_case_tree_hashes(leaves: usize) -> u64 {
    if leaves == 0 {
        return 0;
    }
    let mut nodes = leaves as u64;
    let mut hashes = 0_u64;
    let mut level = 0;
    while level < TREE_DEPTH {
        nodes = nodes / 2 + 1;
        hashes = hashes.saturating_add(nodes);
        level += 1;
    }
    hashes
}

/// E(L): mean Poseidon hashes of one insertion over uniformly random start
/// indices, rounded.
const fn expected_tree_hashes(leaves: usize) -> u64 {
    if leaves == 0 {
        return 0;
    }
    (leaves as u64).saturating_add(DEPTH - 1)
}

/// W(L): mean tree levels that write the stored subtree node, rounded.
const fn expected_tree_writes(leaves: usize) -> u64 {
    match leaves {
        0 => 0,
        1 => 8,
        2 => 9,
        3..=8 => 10,
        9..=32 => 11,
        _ => 12,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hash count of `Commitments.insertLeaves`, following its loop structure.
    fn simulated_insert_hashes(next_leaf_index: usize, leaves: usize) -> u64 {
        let mut level_insertion_index = next_leaf_index;
        let mut count = leaves;
        let mut hashes = 0;
        for _ in 0..TREE_DEPTH {
            let next_level_start_index = level_insertion_index >> 1;
            let mut next_level_hash_index = 0;
            let mut insertion_element = 0;
            if level_insertion_index % 2 == 1 {
                next_level_hash_index = (level_insertion_index >> 1) - next_level_start_index;
                hashes += 1;
                insertion_element += 1;
                level_insertion_index += 1;
            }
            while insertion_element < count {
                next_level_hash_index = (level_insertion_index >> 1) - next_level_start_index;
                hashes += 1;
                insertion_element += 2;
                level_insertion_index += 2;
            }
            level_insertion_index = next_level_start_index;
            count = next_level_hash_index + 1;
        }
        hashes
    }

    #[test]
    fn tree_hash_counts_match_insert_leaves_over_every_start_index() {
        for leaves in 1..=8 {
            // Inserts that would overflow the tree start a new one at index 0.
            let last_start = (1 << TREE_DEPTH) - leaves;
            let sample_count = last_start as u64 + 1;
            let mut worst = 0_u64;
            let mut sum = 0_u64;
            for start in 0..=last_start {
                let hashes = simulated_insert_hashes(start, leaves);
                worst = worst.max(hashes);
                sum += hashes;
            }
            assert!(
                worst_case_tree_hashes(leaves) >= worst,
                "L = {leaves}: worst case {} < simulated {worst}",
                worst_case_tree_hashes(leaves),
            );
            // |E(L) − mean| ≤ 0.5, in integers.
            let expected_sum = expected_tree_hashes(leaves) * sample_count;
            assert!(
                2 * expected_sum.abs_diff(sum) <= sample_count,
                "L = {leaves}: expected {} vs simulated mean {sum}/{sample_count}",
                expected_tree_hashes(leaves),
            );
        }
    }

    #[derive(Clone, Copy)]
    enum Op {
        /// `(inputs, outputs, unshields)` per transaction; outputs include the
        /// unshield output.
        Transact(&'static [(usize, usize, bool)]),
        Shield(usize),
    }

    fn estimate(chain_id: u64, mode: GasEstimateMode, op: Op) -> u64 {
        let model = RailgunGasModel::for_chain(chain_id);
        match op {
            Op::Transact(transactions) => {
                let shapes: Vec<TransactionShape> = transactions
                    .iter()
                    .map(
                        |&(input_count, output_count, has_unshield)| TransactionShape {
                            input_count,
                            output_count,
                            has_unshield,
                        },
                    )
                    .collect();
                model.transact(mode, TransactGasShape::from(shapes.as_slice()))
            }
            Op::Shield(requests) => model.shield(mode, requests),
        }
    }

    // Rows from the 2026-09-28 calibration report. The report writes
    // `transact[i/o(u)]` for inputs/outputs, where `u` marks a transaction that
    // unshields and its outputs include the unshield output.

    /// Tightest direct and batch samples per chain: `(chain, op, measured max)`.
    const UPPER_BOUND_ROWS: &[(u64, Op, u64)] = &[
        (1, Op::Shield(1), 759_172),
        (1, Op::Transact(&[(1, 1, true)]), 463_511),
        (1, Op::Transact(&[(1, 2, true)]), 1_116_750),
        (1, Op::Transact(&[(2, 2, true)]), 1_143_221),
        (1, Op::Transact(&[(1, 2, true), (1, 1, true)]), 1_530_137),
        (1, Op::Transact(&[(1, 1, false)]), 955_444),
        (1, Op::Transact(&[(1, 1, true), (1, 1, true)]), 801_429),
        (56, Op::Transact(&[(2, 1, false)]), 1_010_522),
        (56, Op::Transact(&[(10, 1, true), (2, 1, true)]), 1_193_046),
        (56, Op::Transact(&[(1, 1, false)]), 960_162),
        (56, Op::Transact(&[(3, 2, true)]), 1_156_709),
        (56, Op::Shield(1), 741_531),
        (56, Op::Transact(&[(1, 1, true)]), 450_501),
        (
            56,
            Op::Transact(&[(10, 1, true), (10, 1, true), (10, 1, true), (8, 1, true)]),
            2_696_239,
        ),
        (137, Op::Transact(&[(1, 1, false)]), 1_244_970),
        (137, Op::Transact(&[(1, 2, true)]), 1_422_141),
        (137, Op::Shield(1), 843_463),
        (137, Op::Transact(&[(1, 1, true)]), 730_909),
        (137, Op::Transact(&[(3, 1, true)]), 839_408),
        (137, Op::Transact(&[(13, 1, false)]), 1_893_525),
        (137, Op::Transact(&[(1, 1, false); 5]), 3_089_358),
        (137, Op::Transact(&[(1, 2, false), (2, 2, true)]), 2_145_863),
        (42161, Op::Transact(&[(1, 1, true)]), 463_189),
        (42161, Op::Shield(1), 747_539),
        (42161, Op::Transact(&[(4, 1, false)]), 1_053_965),
        (42161, Op::Transact(&[(3, 2, true)]), 1_151_605),
        (42161, Op::Transact(&[(1, 1, false)]), 954_815),
        (42161, Op::Transact(&[(2, 2, true)]), 1_116_157),
        (
            42161,
            Op::Transact(&[(1, 2, true), (1, 1, true)]),
            1_508_143,
        ),
        (42161, Op::Transact(&[(13, 1, false); 8]), 6_448_679),
    ];

    /// Representative direct shapes: `(chain, op, measured median)`.
    const EXPECTED_ROWS: &[(u64, Op, u64)] = &[
        (1, Op::Shield(1), 737_753),
        (1, Op::Transact(&[(1, 2, true)]), 1_095_163),
        (1, Op::Transact(&[(1, 2, false)]), 1_042_225),
        (1, Op::Transact(&[(1, 3, true)]), 1_155_832),
        (56, Op::Transact(&[(1, 2, false)]), 1_024_555),
        (56, Op::Transact(&[(2, 2, false)]), 1_054_882),
        (56, Op::Transact(&[(2, 3, true)]), 1_139_371),
        (56, Op::Transact(&[(1, 3, true)]), 1_109_817),
        (137, Op::Shield(1), 824_897),
        (137, Op::Shield(2), 999_188),
        (137, Op::Transact(&[(1, 2, false)]), 1_372_262),
        (137, Op::Transact(&[(1, 2, false), (1, 2, true)]), 1_883_559),
        (42161, Op::Shield(1), 726_650),
        (42161, Op::Transact(&[(1, 2, true)]), 1_073_633),
        (42161, Op::Transact(&[(2, 2, false)]), 1_006_497),
    ];

    #[test]
    fn upper_bound_covers_calibration_samples_with_margin() {
        for &(chain_id, op, measured) in UPPER_BOUND_ROWS {
            let margin_percent = if chain_id == 137 { 110 } else { 105 };
            let gas = estimate(chain_id, GasEstimateMode::UpperBound, op);
            assert!(
                gas * 100 >= measured * margin_percent,
                "chain {chain_id}: upper bound {gas} < {margin_percent}% of {measured}",
            );
        }
    }

    #[test]
    fn expected_tracks_calibration_medians() {
        for &(chain_id, op, median) in EXPECTED_ROWS {
            let gas = estimate(chain_id, GasEstimateMode::Expected, op);
            assert!(
                gas >= median && gas * 100 <= median * 108,
                "chain {chain_id}: expected {gas} outside [1.00, 1.08] × {median}",
            );
        }
    }

    #[test]
    fn empty_operations_add_no_gas() {
        for mode in [GasEstimateMode::UpperBound, GasEstimateMode::Expected] {
            assert_eq!(
                DEFAULT_GAS_MODEL.transact(mode, TransactGasShape::default()),
                0
            );
            assert_eq!(DEFAULT_GAS_MODEL.shield(mode, 0), 0);
        }
    }

    const fn fields(model: &RailgunGasModel) -> [u64; 14] {
        let RailgunGasModel {
            transact_call,
            transaction,
            nullifier,
            commitment,
            leaf,
            unshield,
            tree_update,
            tree_hash,
            tree_write,
            shield_call,
            shield_request,
            relay_call,
            relay_action,
            executor_call,
        } = *model;
        [
            transact_call,
            transaction,
            nullifier,
            commitment,
            leaf,
            unshield,
            tree_update,
            tree_hash,
            tree_write,
            shield_call,
            shield_request,
            relay_call,
            relay_action,
            executor_call,
        ]
    }

    #[test]
    fn chains_map_to_their_calibration_and_default_bounds_both() {
        for chain_id in [1, 56, 42161] {
            assert_eq!(RailgunGasModel::for_chain(chain_id), &ETHEREUM_GAS_MODEL);
        }
        assert_eq!(RailgunGasModel::for_chain(137), &POLYGON_GAS_MODEL);
        for chain_id in [0, 10, 8453, 11_155_111] {
            assert_eq!(RailgunGasModel::for_chain(chain_id), &DEFAULT_GAS_MODEL);
        }

        let default = fields(&DEFAULT_GAS_MODEL);
        for calibration in [fields(&ETHEREUM_GAS_MODEL), fields(&POLYGON_GAS_MODEL)] {
            for (default, calibration) in default.iter().zip(calibration) {
                assert!(*default >= calibration);
            }
        }
    }
}
