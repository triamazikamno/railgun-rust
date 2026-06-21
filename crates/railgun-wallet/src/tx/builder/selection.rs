use std::cmp::Ordering;
use std::collections::BTreeMap;

use alloy::primitives::{Address, U256};
use alloy::uint;
use broadcaster_core::utxo::Utxo;

use super::super::{
    BuildError, MAX_BATCH_TRANSACTIONS, MAX_CIRCUIT_INPUTS, MAX_SIGNATURE_INPUTS,
    UnshieldSelectionInfo,
};

const MAX_ALTERNATE_BATCH_CANDIDATES: usize = 1024;
const MAX_PARTIAL_SELECTION_CANDIDATES_PER_TREE: usize = 32;

#[derive(Debug, Clone)]
pub(super) struct UtxoSelection {
    pub(super) utxos: Vec<Utxo>,
    pub(super) total: U256,
}

impl UtxoSelection {
    fn is_better_for_amount_than(&self, best: &Self, amount: U256) -> bool {
        match self.utxos.len().cmp(&best.utxos.len()) {
            Ordering::Less => return true,
            Ordering::Greater => return false,
            Ordering::Equal => {}
        }

        let candidate_excess = self.total - amount;
        let best_excess = best.total - amount;
        match candidate_excess.cmp(&best_excess) {
            Ordering::Less => true,
            Ordering::Greater => false,
            Ordering::Equal => self.position_key() < best.position_key(),
        }
    }

    fn is_better_max_than(&self, best: &Self) -> bool {
        match self.total.cmp(&best.total) {
            Ordering::Greater => return true,
            Ordering::Less => return false,
            Ordering::Equal => {}
        }

        match self.utxos.len().cmp(&best.utxos.len()) {
            Ordering::Less => true,
            Ordering::Greater => false,
            Ordering::Equal => self.position_key() < best.position_key(),
        }
    }

    fn position_key(&self) -> Vec<(u32, u64)> {
        self.utxos
            .iter()
            .map(|utxo| (utxo.tree, utxo.position))
            .collect()
    }
}

#[derive(Debug, Clone)]
pub(super) struct BatchUtxoSelection {
    pub(super) chunks: Vec<UtxoSelection>,
    pub(super) total: U256,
}

impl BatchUtxoSelection {
    #[must_use]
    pub(super) fn input_count(&self) -> usize {
        self.chunks.iter().map(|chunk| chunk.utxos.len()).sum()
    }
}

#[must_use]
pub fn max_unshield_spendable(utxos: &[Utxo], token_address: Address) -> U256 {
    max_batch_spendable(utxos, token_address, 1, 1)
}

pub fn unshield_selection_info(
    utxos: &[Utxo],
    token_address: Address,
    amount: U256,
    spend_up_to: bool,
) -> Result<UnshieldSelectionInfo, BuildError> {
    let max_spendable = max_batch_spendable(utxos, token_address, 1, 1);
    let selection = select_batched_utxos(utxos, token_address, amount, spend_up_to, 1, 1)?;
    let shape = batch_shape(&selection, amount, U256::ZERO, false, false);
    Ok(UnshieldSelectionInfo {
        total: selection.total,
        input_count: selection.input_count(),
        transaction_count: shape.transaction_count,
        private_output_count: shape.private_output_count,
        public_output_count: shape.public_output_count,
        max_spendable,
    })
}

pub fn unshield_selection_info_with_broadcaster_fee(
    utxos: &[Utxo],
    token_address: Address,
    amount: U256,
    fee_amount: U256,
    spend_up_to: bool,
) -> Result<UnshieldSelectionInfo, BuildError> {
    let target_amount = amount + fee_amount;
    let max_total = max_batch_spendable(utxos, token_address, 2, 1);
    let max_spendable = if max_total > fee_amount {
        max_total - fee_amount
    } else {
        U256::ZERO
    };
    let selection = select_batched_utxos(utxos, token_address, target_amount, spend_up_to, 2, 1)
        .map_err(|error| match error {
            BuildError::InsufficientBalance(_) => BuildError::InsufficientBalance(max_spendable),
            other => other,
        })?;
    let shape = batch_shape(&selection, amount, fee_amount, true, false);
    Ok(UnshieldSelectionInfo {
        total: selection.total,
        input_count: selection.input_count(),
        transaction_count: shape.transaction_count,
        private_output_count: shape.private_output_count,
        public_output_count: shape.public_output_count,
        max_spendable,
    })
}

pub fn unshield_selection_info_with_broadcaster_fee_token(
    utxos: &[Utxo],
    token_address: Address,
    fee_token_address: Address,
    amount: U256,
    fee_amount: U256,
    spend_up_to: bool,
) -> Result<UnshieldSelectionInfo, BuildError> {
    if fee_token_address == token_address {
        return unshield_selection_info_with_broadcaster_fee(
            utxos,
            token_address,
            amount,
            fee_amount,
            spend_up_to,
        );
    }

    different_token_broadcaster_fee_selection_info(
        utxos,
        token_address,
        fee_token_address,
        amount,
        fee_amount,
        spend_up_to,
        false,
    )
}

pub fn unshield_selection_info_with_separate_broadcaster_fee_seed(
    utxos: &[Utxo],
    token_address: Address,
    fee_token_address: Address,
    amount: U256,
    spend_up_to: bool,
) -> Result<UnshieldSelectionInfo, BuildError> {
    separate_broadcaster_fee_seed_selection_info(
        utxos,
        token_address,
        fee_token_address,
        amount,
        spend_up_to,
        false,
    )
}

#[must_use]
pub fn max_send_spendable(utxos: &[Utxo], token_address: Address) -> U256 {
    max_batch_spendable(utxos, token_address, 1, 1)
}

#[must_use]
pub fn max_broadcaster_fee_token_spendable(utxos: &[Utxo], token_address: Address) -> U256 {
    max_unshield_selection_with_output_count(utxos, token_address, 1)
        .map_or(U256::ZERO, |selection| selection.total)
}

pub fn send_selection_info(
    utxos: &[Utxo],
    token_address: Address,
    amount: U256,
    spend_up_to: bool,
) -> Result<UnshieldSelectionInfo, BuildError> {
    let max_spendable = max_batch_spendable(utxos, token_address, 1, 1);
    let selection = select_batched_utxos(utxos, token_address, amount, spend_up_to, 1, 1)?;
    let shape = batch_shape(&selection, amount, U256::ZERO, false, true);
    Ok(UnshieldSelectionInfo {
        total: selection.total,
        input_count: selection.input_count(),
        transaction_count: shape.transaction_count,
        private_output_count: shape.private_output_count,
        public_output_count: shape.public_output_count,
        max_spendable,
    })
}

pub fn send_selection_info_with_broadcaster_fee(
    utxos: &[Utxo],
    token_address: Address,
    amount: U256,
    fee_amount: U256,
    spend_up_to: bool,
) -> Result<UnshieldSelectionInfo, BuildError> {
    let target_amount = amount + fee_amount;
    let max_total = max_batch_spendable(utxos, token_address, 2, 1);
    let max_spendable = if max_total > fee_amount {
        max_total - fee_amount
    } else {
        U256::ZERO
    };
    let selection = select_batched_utxos(utxos, token_address, target_amount, spend_up_to, 2, 1)
        .map_err(|error| match error {
            BuildError::InsufficientBalance(_) => BuildError::InsufficientBalance(max_spendable),
            other => other,
        })?;
    let shape = batch_shape(&selection, amount, fee_amount, true, true);
    Ok(UnshieldSelectionInfo {
        total: selection.total,
        input_count: selection.input_count(),
        transaction_count: shape.transaction_count,
        private_output_count: shape.private_output_count,
        public_output_count: shape.public_output_count,
        max_spendable,
    })
}

pub fn send_selection_info_with_broadcaster_fee_token(
    utxos: &[Utxo],
    token_address: Address,
    fee_token_address: Address,
    amount: U256,
    fee_amount: U256,
    spend_up_to: bool,
) -> Result<UnshieldSelectionInfo, BuildError> {
    if fee_token_address == token_address {
        return send_selection_info_with_broadcaster_fee(
            utxos,
            token_address,
            amount,
            fee_amount,
            spend_up_to,
        );
    }

    different_token_broadcaster_fee_selection_info(
        utxos,
        token_address,
        fee_token_address,
        amount,
        fee_amount,
        spend_up_to,
        true,
    )
}

fn different_token_broadcaster_fee_selection_info(
    utxos: &[Utxo],
    token_address: Address,
    fee_token_address: Address,
    amount: U256,
    fee_amount: U256,
    spend_up_to: bool,
    send: bool,
) -> Result<UnshieldSelectionInfo, BuildError> {
    let fee_selection = select_fee_utxos(utxos, fee_token_address, fee_amount)?;
    let max_spendable =
        max_batch_spendable_with_limit(utxos, token_address, 1, 1, MAX_BATCH_TRANSACTIONS - 1);
    let selection = select_batched_utxos_with_limit(
        utxos,
        token_address,
        amount,
        spend_up_to,
        1,
        1,
        MAX_BATCH_TRANSACTIONS - 1,
    )?;
    let action_shape = batch_shape(&selection, amount, U256::ZERO, false, send);
    let fee_private_outputs = 1 + usize::from(fee_selection.total > fee_amount);

    Ok(UnshieldSelectionInfo {
        total: selection.total,
        input_count: fee_selection.utxos.len() + selection.input_count(),
        transaction_count: 1 + action_shape.transaction_count,
        private_output_count: fee_private_outputs + action_shape.private_output_count,
        public_output_count: action_shape.public_output_count,
        max_spendable,
    })
}

pub fn send_selection_info_with_separate_broadcaster_fee_seed(
    utxos: &[Utxo],
    token_address: Address,
    fee_token_address: Address,
    amount: U256,
    spend_up_to: bool,
) -> Result<UnshieldSelectionInfo, BuildError> {
    separate_broadcaster_fee_seed_selection_info(
        utxos,
        token_address,
        fee_token_address,
        amount,
        spend_up_to,
        true,
    )
}

fn separate_broadcaster_fee_seed_selection_info(
    utxos: &[Utxo],
    token_address: Address,
    fee_token_address: Address,
    amount: U256,
    spend_up_to: bool,
    send: bool,
) -> Result<UnshieldSelectionInfo, BuildError> {
    let fee_max_spendable = max_broadcaster_fee_token_spendable(utxos, fee_token_address);
    if fee_max_spendable.is_zero() {
        return Err(BuildError::InsufficientFeeTokenBalance(U256::ZERO));
    }

    let max_spendable =
        max_batch_spendable_with_limit(utxos, token_address, 1, 1, MAX_BATCH_TRANSACTIONS - 1);
    let selection = select_batched_utxos_with_limit(
        utxos,
        token_address,
        amount,
        spend_up_to,
        1,
        1,
        MAX_BATCH_TRANSACTIONS - 1,
    )?;
    let action_shape = batch_shape(&selection, amount, U256::ZERO, false, send);

    Ok(UnshieldSelectionInfo {
        total: selection.total,
        input_count: 1 + selection.input_count(),
        transaction_count: 1 + action_shape.transaction_count,
        private_output_count: 2 + action_shape.private_output_count,
        public_output_count: action_shape.public_output_count,
        max_spendable,
    })
}

#[derive(Debug, Clone, Copy)]
struct BatchShape {
    transaction_count: usize,
    private_output_count: usize,
    public_output_count: usize,
}

fn batch_shape(
    selection: &BatchUtxoSelection,
    amount: U256,
    fee_amount: U256,
    has_fee_output: bool,
    send: bool,
) -> BatchShape {
    let mut remaining = selection.total.saturating_sub(fee_amount).min(amount);
    let mut private_output_count = 0;
    let mut public_output_count = 0;

    for (index, chunk) in selection.chunks.iter().enumerate() {
        let chunk_fee = if index == 0 { fee_amount } else { U256::ZERO };
        let spendable = chunk.total.saturating_sub(chunk_fee);
        let amount_out = spendable.min(remaining);
        let change = spendable.saturating_sub(amount_out);

        if send {
            private_output_count += 1 + usize::from(index == 0 && has_fee_output);
        } else {
            private_output_count += usize::from(index == 0 && has_fee_output);
            public_output_count += 1;
        }
        private_output_count += usize::from(!change.is_zero());
        remaining = remaining.saturating_sub(amount_out);
    }

    BatchShape {
        transaction_count: selection.chunks.len(),
        private_output_count,
        public_output_count,
    }
}

#[must_use]
fn max_batch_spendable(
    utxos: &[Utxo],
    token_address: Address,
    first_base_output_count: usize,
    continuation_base_output_count: usize,
) -> U256 {
    max_batch_spendable_with_limit(
        utxos,
        token_address,
        first_base_output_count,
        continuation_base_output_count,
        MAX_BATCH_TRANSACTIONS,
    )
}

#[must_use]
fn max_batch_spendable_with_limit(
    utxos: &[Utxo],
    token_address: Address,
    first_base_output_count: usize,
    continuation_base_output_count: usize,
    max_transactions: usize,
) -> U256 {
    max_batch_selection(
        utxos,
        token_address,
        first_base_output_count,
        continuation_base_output_count,
        max_transactions,
    )
    .map_or(U256::ZERO, |selection| selection.total)
}

fn max_batch_selection(
    utxos: &[Utxo],
    token_address: Address,
    first_base_output_count: usize,
    continuation_base_output_count: usize,
    max_transactions: usize,
) -> Option<BatchUtxoSelection> {
    let mut remaining = utxos.to_vec();
    let mut chunks = Vec::new();
    let mut total = U256::ZERO;

    for index in 0..max_transactions {
        let base_output_count = if index == 0 {
            first_base_output_count
        } else {
            continuation_base_output_count
        };
        let Some(selection) =
            max_unshield_selection_with_output_count(&remaining, token_address, base_output_count)
        else {
            break;
        };
        if selection.total.is_zero() {
            break;
        }
        remove_selected_utxos(&mut remaining, &selection.utxos);
        total += selection.total;
        chunks.push(selection);
    }

    if chunks.is_empty() {
        None
    } else {
        Some(BatchUtxoSelection { chunks, total })
    }
}

pub(super) fn select_batched_utxos(
    utxos: &[Utxo],
    token_address: Address,
    amount: U256,
    spend_up_to: bool,
    first_base_output_count: usize,
    continuation_base_output_count: usize,
) -> Result<BatchUtxoSelection, BuildError> {
    select_batched_utxos_with_limit(
        utxos,
        token_address,
        amount,
        spend_up_to,
        first_base_output_count,
        continuation_base_output_count,
        MAX_BATCH_TRANSACTIONS,
    )
}

pub(super) fn select_batched_utxos_with_limit(
    utxos: &[Utxo],
    token_address: Address,
    amount: U256,
    spend_up_to: bool,
    first_base_output_count: usize,
    continuation_base_output_count: usize,
    max_transactions: usize,
) -> Result<BatchUtxoSelection, BuildError> {
    let max_selection = max_batch_selection(
        utxos,
        token_address,
        first_base_output_count,
        continuation_base_output_count,
        max_transactions,
    );
    let max_spendable = max_selection
        .as_ref()
        .map_or(U256::ZERO, |selection| selection.total);

    if amount.is_zero() {
        return Err(BuildError::InsufficientBalance(max_spendable));
    }

    if let Some(selection) =
        best_unshield_selection(utxos, token_address, amount, first_base_output_count)
    {
        let total = selection.total;
        return Ok(BatchUtxoSelection {
            chunks: vec![selection],
            total,
        });
    }

    if let Some(selection) = greedy_batched_selection(
        utxos,
        token_address,
        amount,
        first_base_output_count,
        continuation_base_output_count,
        max_transactions,
    ) {
        return Ok(selection);
    }

    if spend_up_to
        && max_selection
            .as_ref()
            .is_some_and(|selection| !selection.total.is_zero() && selection.total < amount)
    {
        return Ok(max_selection.expect("checked above"));
    }

    Err(BuildError::InsufficientBalance(max_spendable))
}

pub(super) fn select_batched_utxo_candidates_with_limit(
    utxos: &[Utxo],
    token_address: Address,
    amount: U256,
    spend_up_to: bool,
    first_base_output_count: usize,
    continuation_base_output_count: usize,
    max_transactions: usize,
) -> Result<Vec<BatchUtxoSelection>, BuildError> {
    let primary = select_batched_utxos_with_limit(
        utxos,
        token_address,
        amount,
        spend_up_to,
        first_base_output_count,
        continuation_base_output_count,
        max_transactions,
    )?;
    let mut candidates = vec![primary];

    if max_transactions == 0 {
        return Ok(candidates);
    }

    for selection in single_transaction_selection_candidates(
        utxos,
        token_address,
        amount,
        first_base_output_count,
    ) {
        let total = selection.total;
        push_unique_batch_candidate(
            &mut candidates,
            BatchUtxoSelection {
                chunks: vec![selection],
                total,
            },
        );
    }

    for selection in multi_transaction_selection_candidates(
        utxos,
        token_address,
        amount,
        first_base_output_count,
        continuation_base_output_count,
        max_transactions,
    ) {
        push_unique_batch_candidate(&mut candidates, selection);
    }

    Ok(candidates)
}

pub(super) fn select_fee_utxos(
    utxos: &[Utxo],
    fee_token_address: Address,
    fee_amount: U256,
) -> Result<UtxoSelection, BuildError> {
    let max_selection = max_unshield_selection_with_output_count(utxos, fee_token_address, 1);
    let max_spendable = max_selection
        .as_ref()
        .map_or(U256::ZERO, |selection| selection.total);

    if fee_amount.is_zero() {
        return Err(BuildError::InsufficientFeeTokenBalance(max_spendable));
    }

    best_unshield_selection(utxos, fee_token_address, fee_amount, 1)
        .ok_or(BuildError::InsufficientFeeTokenBalance(max_spendable))
}

fn greedy_batched_selection(
    utxos: &[Utxo],
    token_address: Address,
    amount: U256,
    first_base_output_count: usize,
    continuation_base_output_count: usize,
    max_transactions: usize,
) -> Option<BatchUtxoSelection> {
    let mut remaining_utxos = utxos.to_vec();
    let mut remaining_amount = amount;
    let mut chunks = Vec::new();
    let mut total = U256::ZERO;

    for index in 0..max_transactions {
        let base_output_count = if index == 0 {
            first_base_output_count
        } else {
            continuation_base_output_count
        };

        if let Some(selection) = best_unshield_selection(
            &remaining_utxos,
            token_address,
            remaining_amount,
            base_output_count,
        ) {
            total += selection.total;
            chunks.push(selection);
            return Some(BatchUtxoSelection { chunks, total });
        }

        let Some(selection) = max_unshield_selection_with_output_count(
            &remaining_utxos,
            token_address,
            base_output_count,
        ) else {
            break;
        };
        if selection.total.is_zero() {
            return None;
        }
        let selection = if selection.total < remaining_amount {
            selection
        } else {
            best_partial_selection_below_amount(
                &remaining_utxos,
                token_address,
                remaining_amount,
                base_output_count,
            )?
        };

        remaining_amount -= selection.total;
        total += selection.total;
        remove_selected_utxos(&mut remaining_utxos, &selection.utxos);
        chunks.push(selection);
    }

    None
}

pub(super) fn remove_selected_utxos(utxos: &mut Vec<Utxo>, selected: &[Utxo]) {
    utxos.retain(|utxo| {
        !selected
            .iter()
            .any(|selected| selected.tree == utxo.tree && selected.position == utxo.position)
    });
}

#[cfg(test)]
pub(super) fn select_utxos(
    utxos: &[Utxo],
    token_address: Address,
    amount: U256,
    spend_up_to: bool,
    base_output_count: usize,
) -> Result<(Vec<Utxo>, U256), BuildError> {
    let max_selection =
        max_unshield_selection_with_output_count(utxos, token_address, base_output_count);
    let max_spendable = max_selection
        .as_ref()
        .map_or(U256::ZERO, |selection| selection.total);

    if amount.is_zero() {
        return Err(BuildError::InsufficientBalance(max_spendable));
    }

    if let Some(selection) =
        best_unshield_selection(utxos, token_address, amount, base_output_count)
    {
        return Ok((selection.utxos, selection.total));
    }

    if spend_up_to
        && max_selection
            .as_ref()
            .is_some_and(|selection| !selection.total.is_zero() && selection.total < amount)
    {
        let selection = max_selection.expect("checked above");
        return Ok((selection.utxos, selection.total));
    }

    Err(BuildError::InsufficientBalance(max_spendable))
}

fn best_unshield_selection(
    utxos: &[Utxo],
    token_address: Address,
    amount: U256,
    base_output_count: usize,
) -> Option<UtxoSelection> {
    let mut best: Option<UtxoSelection> = None;
    for candidates in token_utxos_by_tree(utxos, token_address).into_values() {
        if let Some(selection) = best_tree_selection(candidates, amount, base_output_count)
            && best
                .as_ref()
                .is_none_or(|best| selection.is_better_for_amount_than(best, amount))
        {
            best = Some(selection);
        }
    }
    best
}

fn single_transaction_selection_candidates(
    utxos: &[Utxo],
    token_address: Address,
    amount: U256,
    base_output_count: usize,
) -> Vec<UtxoSelection> {
    let mut candidates = Vec::new();
    for input_count in 1..=max_inputs_for_base_outputs(base_output_count) {
        candidates.extend(unshield_selection_candidates_for_input_count(
            utxos,
            token_address,
            amount,
            base_output_count,
            input_count,
        ));
        if candidates.len() >= MAX_ALTERNATE_BATCH_CANDIDATES {
            candidates.truncate(MAX_ALTERNATE_BATCH_CANDIDATES);
            break;
        }
    }
    candidates
}

fn multi_transaction_selection_candidates(
    utxos: &[Utxo],
    token_address: Address,
    amount: U256,
    first_base_output_count: usize,
    continuation_base_output_count: usize,
    max_transactions: usize,
) -> Vec<BatchUtxoSelection> {
    if max_transactions < 2 {
        return Vec::new();
    }

    let mut candidates = Vec::new();
    let mut chunks = Vec::new();
    collect_multi_transaction_selection_candidates(
        utxos,
        token_address,
        amount,
        first_base_output_count,
        continuation_base_output_count,
        max_transactions,
        U256::ZERO,
        &mut chunks,
        &mut candidates,
    );
    candidates
}

#[allow(clippy::too_many_arguments)]
fn collect_multi_transaction_selection_candidates(
    utxos: &[Utxo],
    token_address: Address,
    remaining_amount: U256,
    first_base_output_count: usize,
    continuation_base_output_count: usize,
    max_transactions: usize,
    selected_total: U256,
    chunks: &mut Vec<UtxoSelection>,
    candidates: &mut Vec<BatchUtxoSelection>,
) {
    if chunks.len() == max_transactions || candidates.len() >= MAX_ALTERNATE_BATCH_CANDIDATES {
        return;
    }

    let base_output_count = if chunks.is_empty() {
        first_base_output_count
    } else {
        continuation_base_output_count
    };

    for selection in single_transaction_selection_candidates(
        utxos,
        token_address,
        remaining_amount,
        base_output_count,
    ) {
        let mut candidate_chunks = chunks.clone();
        let total = selected_total + selection.total;
        candidate_chunks.push(selection);
        push_unique_batch_candidate(
            candidates,
            BatchUtxoSelection {
                chunks: candidate_chunks,
                total,
            },
        );
        if candidates.len() >= MAX_ALTERNATE_BATCH_CANDIDATES {
            return;
        }
    }

    if chunks.len() + 1 == max_transactions {
        return;
    }

    for selection in partial_transaction_selection_candidates(
        utxos,
        token_address,
        remaining_amount,
        base_output_count,
    ) {
        let mut remaining_utxos = utxos.to_vec();
        remove_selected_utxos(&mut remaining_utxos, &selection.utxos);
        let next_remaining_amount = remaining_amount - selection.total;
        let next_selected_total = selected_total + selection.total;

        chunks.push(selection);
        collect_multi_transaction_selection_candidates(
            &remaining_utxos,
            token_address,
            next_remaining_amount,
            first_base_output_count,
            continuation_base_output_count,
            max_transactions,
            next_selected_total,
            chunks,
            candidates,
        );
        chunks.pop();

        if candidates.len() >= MAX_ALTERNATE_BATCH_CANDIDATES {
            return;
        }
    }
}

fn unshield_selection_candidates_for_input_count(
    utxos: &[Utxo],
    token_address: Address,
    amount: U256,
    base_output_count: usize,
    input_count: usize,
) -> Vec<UtxoSelection> {
    let mut selections = Vec::new();
    for mut candidates in token_utxos_by_tree(utxos, token_address).into_values() {
        sort_search_candidates(&mut candidates);
        let mut search = SelectionSearch::new(&candidates, amount, input_count, base_output_count);
        search.run();
        if let Some(selection) = search.best {
            selections.push(selection);
        }
    }
    selections.sort_by(|a, b| selection_amount_order(a, b, amount));
    selections
}

fn selection_amount_order(a: &UtxoSelection, b: &UtxoSelection, amount: U256) -> Ordering {
    let a_excess = a.total - amount;
    let b_excess = b.total - amount;
    a.utxos
        .len()
        .cmp(&b.utxos.len())
        .then_with(|| a_excess.cmp(&b_excess))
        .then_with(|| a.position_key().cmp(&b.position_key()))
}

fn push_unique_batch_candidate(
    candidates: &mut Vec<BatchUtxoSelection>,
    candidate: BatchUtxoSelection,
) {
    if candidates
        .iter()
        .any(|existing| batch_selection_key(existing) == batch_selection_key(&candidate))
    {
        return;
    }
    candidates.push(candidate);
}

fn batch_selection_key(selection: &BatchUtxoSelection) -> Vec<Vec<(u32, u64)>> {
    selection
        .chunks
        .iter()
        .map(UtxoSelection::position_key)
        .collect()
}

fn partial_transaction_selection_candidates(
    utxos: &[Utxo],
    token_address: Address,
    amount: U256,
    base_output_count: usize,
) -> Vec<UtxoSelection> {
    if amount <= uint!(1_U256) {
        return Vec::new();
    }
    let max_input_count = max_inputs_for_base_outputs(base_output_count);
    if max_input_count == 0 {
        return Vec::new();
    }

    let mut selections = Vec::new();
    for mut candidates in token_utxos_by_tree(utxos, token_address).into_values() {
        sort_search_candidates(&mut candidates);
        let mut search = PartialSelectionSearch::new(
            &candidates,
            amount,
            max_input_count,
            MAX_PARTIAL_SELECTION_CANDIDATES_PER_TREE,
        );
        search.run();
        selections.extend(search.selections);
    }
    selections.sort_by(selection_max_order);
    selections.truncate(MAX_ALTERNATE_BATCH_CANDIDATES);
    selections
}

fn selection_max_order(a: &UtxoSelection, b: &UtxoSelection) -> Ordering {
    b.total
        .cmp(&a.total)
        .then_with(|| a.utxos.len().cmp(&b.utxos.len()))
        .then_with(|| a.position_key().cmp(&b.position_key()))
}

fn best_partial_selection_below_amount(
    utxos: &[Utxo],
    token_address: Address,
    amount: U256,
    base_output_count: usize,
) -> Option<UtxoSelection> {
    partial_transaction_selection_candidates(utxos, token_address, amount, base_output_count)
        .into_iter()
        .next()
}

fn max_unshield_selection_with_output_count(
    utxos: &[Utxo],
    token_address: Address,
    base_output_count: usize,
) -> Option<UtxoSelection> {
    let mut best: Option<UtxoSelection> = None;
    let max_input_count = max_inputs_for_base_outputs(base_output_count);
    if max_input_count == 0 {
        return None;
    }
    for mut candidates in token_utxos_by_tree(utxos, token_address).into_values() {
        sort_search_candidates(&mut candidates);
        candidates.truncate(max_input_count);
        let total = candidates
            .iter()
            .fold(U256::ZERO, |sum, utxo| sum + utxo.note.value);
        if total.is_zero() {
            continue;
        }
        normalize_selection(&mut candidates);
        let selection = UtxoSelection {
            utxos: candidates,
            total,
        };
        if best
            .as_ref()
            .is_none_or(|best| selection.is_better_max_than(best))
        {
            best = Some(selection);
        }
    }
    best
}

const fn max_inputs_for_base_outputs(base_output_count: usize) -> usize {
    let signature_room = MAX_SIGNATURE_INPUTS.saturating_sub(2 + base_output_count);
    if signature_room < MAX_CIRCUIT_INPUTS {
        signature_room
    } else {
        MAX_CIRCUIT_INPUTS
    }
}

fn token_utxos_by_tree(utxos: &[Utxo], token_address: Address) -> BTreeMap<u32, Vec<Utxo>> {
    let token_hash = U256::from_be_slice(token_address.as_slice());
    let mut by_tree: BTreeMap<u32, Vec<Utxo>> = BTreeMap::new();
    for utxo in utxos
        .iter()
        .filter(|utxo| utxo.note.token_hash == token_hash && !utxo.note.value.is_zero())
    {
        by_tree.entry(utxo.tree).or_default().push(utxo.clone());
    }
    by_tree
}

fn best_tree_selection(
    mut candidates: Vec<Utxo>,
    amount: U256,
    base_output_count: usize,
) -> Option<UtxoSelection> {
    sort_search_candidates(&mut candidates);

    for input_count in 1..=max_inputs_for_base_outputs(base_output_count) {
        let mut search = SelectionSearch::new(&candidates, amount, input_count, base_output_count);
        search.run();
        if let Some(selection) = search.best {
            return Some(selection);
        }
    }
    None
}

fn sort_search_candidates(candidates: &mut [Utxo]) {
    candidates.sort_by(|a, b| {
        b.note
            .value
            .cmp(&a.note.value)
            .then_with(|| a.tree.cmp(&b.tree))
            .then_with(|| a.position.cmp(&b.position))
    });
}

fn normalize_selection(utxos: &mut [Utxo]) {
    utxos.sort_by_key(|utxo| (utxo.tree, utxo.position));
}

fn max_possible_from(candidates: &[Utxo], start: usize, remaining: usize) -> U256 {
    candidates[start..]
        .iter()
        .take(remaining)
        .fold(U256::ZERO, |sum, utxo| sum + utxo.note.value)
}

struct PartialSelectionSearch<'a> {
    candidates: &'a [Utxo],
    amount: U256,
    max_input_count: usize,
    selection_limit: usize,
    selected: Vec<usize>,
    best: Option<UtxoSelection>,
    selections: Vec<UtxoSelection>,
}

impl<'a> PartialSelectionSearch<'a> {
    fn new(
        candidates: &'a [Utxo],
        amount: U256,
        max_input_count: usize,
        selection_limit: usize,
    ) -> Self {
        Self {
            candidates,
            amount,
            max_input_count,
            selection_limit,
            selected: Vec::with_capacity(max_input_count),
            best: None,
            selections: Vec::with_capacity(selection_limit),
        }
    }

    fn run(&mut self) {
        self.search(0, U256::ZERO);
    }

    fn search(&mut self, start: usize, total: U256) {
        if self.selected.len() == self.max_input_count || start >= self.candidates.len() {
            return;
        }
        let remaining_slots = self.max_input_count - self.selected.len();
        if let Some(best) = &self.best
            && self.selection_limit <= 1
            && total + max_possible_from(self.candidates, start, remaining_slots) <= best.total
        {
            return;
        }
        if self.selection_limit > 1
            && self.selections.len() >= self.selection_limit
            && self.selections.last().is_some_and(|selection| {
                total + max_possible_from(self.candidates, start, remaining_slots) < selection.total
            })
        {
            return;
        }

        for index in start..self.candidates.len() {
            let next_total = total + self.candidates[index].note.value;
            if next_total >= self.amount {
                continue;
            }
            self.selected.push(index);
            self.record(next_total);
            self.search(index + 1, next_total);
            self.selected.pop();
        }
    }

    fn record(&mut self, total: U256) {
        let mut utxos = self
            .selected
            .iter()
            .map(|index| self.candidates[*index].clone())
            .collect::<Vec<_>>();
        normalize_selection(&mut utxos);
        let selection = UtxoSelection { utxos, total };
        if self
            .best
            .as_ref()
            .is_none_or(|best| selection.is_better_max_than(best))
        {
            self.best = Some(selection.clone());
        }
        push_unique_selection_candidate(&mut self.selections, selection, self.selection_limit);
    }
}

fn push_unique_selection_candidate(
    candidates: &mut Vec<UtxoSelection>,
    candidate: UtxoSelection,
    limit: usize,
) {
    if limit == 0
        || candidates
            .iter()
            .any(|existing| existing.position_key() == candidate.position_key())
    {
        return;
    }
    candidates.push(candidate);
    candidates.sort_by(selection_max_order);
    candidates.truncate(limit);
}

struct SelectionSearch<'a> {
    candidates: &'a [Utxo],
    amount: U256,
    target_count: usize,
    base_output_count: usize,
    selected: Vec<usize>,
    best: Option<UtxoSelection>,
}

impl<'a> SelectionSearch<'a> {
    fn new(
        candidates: &'a [Utxo],
        amount: U256,
        target_count: usize,
        base_output_count: usize,
    ) -> Self {
        Self {
            candidates,
            amount,
            target_count,
            base_output_count,
            selected: Vec::with_capacity(target_count),
            best: None,
        }
    }

    fn run(&mut self) {
        self.search(0, self.target_count, U256::ZERO);
    }

    fn search(&mut self, start: usize, remaining: usize, total: U256) {
        if remaining == 0 {
            self.record_if_valid(total);
            return;
        }
        if self.candidates.len().saturating_sub(start) < remaining {
            return;
        }
        if self.exact_only() && total > self.amount {
            return;
        }
        if !self.exact_only() && self.best.as_ref().is_some_and(|best| total >= best.total) {
            return;
        }
        if total + max_possible_from(self.candidates, start, remaining) < self.amount {
            return;
        }

        let end = self.candidates.len() - remaining;
        for index in start..=end {
            let next_total = total + self.candidates[index].note.value;
            if self.exact_only() && next_total > self.amount {
                continue;
            }
            if !self.exact_only()
                && self
                    .best
                    .as_ref()
                    .is_some_and(|best| next_total >= best.total)
            {
                continue;
            }
            self.selected.push(index);
            self.search(index + 1, remaining - 1, next_total);
            self.selected.pop();
        }
    }

    fn exact_only(&self) -> bool {
        2 + self.target_count + self.base_output_count + 1 > MAX_SIGNATURE_INPUTS
    }

    fn record_if_valid(&mut self, total: U256) {
        if total < self.amount {
            return;
        }
        let output_count = self.base_output_count + usize::from(total > self.amount);
        if 2 + self.target_count + output_count > MAX_SIGNATURE_INPUTS {
            return;
        }

        let mut utxos = self
            .selected
            .iter()
            .map(|index| self.candidates[*index].clone())
            .collect::<Vec<_>>();
        normalize_selection(&mut utxos);
        let selection = UtxoSelection { utxos, total };
        if self
            .best
            .as_ref()
            .is_none_or(|best| selection.is_better_for_amount_than(best, self.amount))
        {
            self.best = Some(selection);
        }
    }
}
