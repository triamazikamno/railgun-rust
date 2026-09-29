//! Pre-proof sizing of a private swap's `CoW` hook app data.
//!
//! The pre-hook is a signed `RelayAdapt7702.execute` that unshields the sell
//! token to the executor; the optional post-hook is a signed
//! `RelayAdapt7702.multicall`.
//! Both are ABI encoded, so their lengths depend only on each transaction's
//! nullifier, commitment, and ciphertext counts and on the calls' data lengths.

use std::cmp::Reverse;

use alloy::primitives::{Address, Bytes, FixedBytes, U256};
use alloy::sol_types::SolCall;
use broadcaster_core::contracts::cow::{AppData, AppDataHook};
use broadcaster_core::contracts::railgun::{
    BoundParams, Call, CommitmentCiphertext, CommitmentPreimage, RelayAdapt7702,
    RelayAdapt7702ActionData, SnarkProof, Transaction,
};
use broadcaster_core::utxo::Utxo;

use super::super::{
    BuildError, CompositeUnshieldLeg, CompositeUnshieldRecipient, MAX_BATCH_TRANSACTIONS,
    MixedPrivateActionPreview, MixedPrivateActionRequest, TransactionBuilder, TransactionShape,
};
use super::selection::{
    max_batch_selection, max_tree_total_below, remove_selected_utxos, token_utxos_by_tree,
};

/// Length of the `r || s || v` owner signature both hooks carry.
const EXECUTOR_SIGNATURE_LEN: usize = 65;

/// Parts of a private swap's app data that do not depend on note selection.
#[derive(Debug, Clone)]
pub struct SwapAppDataTemplate {
    pub app_code: String,
    /// Upper bound on the pre-hook gas limit the order will carry. `gasLimit`
    /// is a decimal string, so a real limit with fewer digits encodes shorter.
    pub pre_hook_gas_limit: u64,
    /// The order's post-hook, or `None` for an order that carries only the
    /// pre-hook.
    pub post_hook: Option<SwapPostHookTemplate>,
}

/// Post-hook part of a [`SwapAppDataTemplate`].
#[derive(Debug, Clone)]
pub struct SwapPostHookTemplate {
    /// `multicall` calls as they will be signed.
    pub calls: Vec<Call>,
    /// Upper bound on the post-hook gas limit, as for
    /// [`SwapAppDataTemplate::pre_hook_gas_limit`].
    pub gas_limit: u64,
}

/// A swap sell amount with the selection its pre-hook plan will use and the
/// app data length estimated for that selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapPreHookSize {
    pub amount: U256,
    pub preview: MixedPrivateActionPreview,
    pub app_data_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwapAmountCheck {
    Fits(SwapPreHookSize),
    /// The entered amount exceeds the balance, the batch limit, or the byte
    /// budget. `largest` is the largest amount found that fits all three and
    /// is strictly below the entered amount.
    TooLarge {
        largest: SwapPreHookSize,
    },
}

/// Length of the app data JSON document for a swap whose pre-hook spends
/// `transactions` and makes `pre_hook_calls` from `executor`.
///
/// Encodes the pre-hook, and the post-hook when the template has one, with
/// zero-filled transactions of the same shapes and 65-byte signatures. Commitment ciphertexts are sized with the empty
/// `annotationData` and `memo` the wallet emits. The result equals the real
/// document length when the real gas limits have as many decimal digits as the
/// template's upper bounds, and exceeds it otherwise.
pub fn estimate_swap_app_data_len(
    template: &SwapAppDataTemplate,
    executor: Address,
    pre_hook_calls: &[Call],
    transactions: &[TransactionShape],
) -> Result<usize, BuildError> {
    let signature = Bytes::from([0_u8; EXECUTOR_SIGNATURE_LEN]);
    let pre_hook = RelayAdapt7702::executeCall {
        _transactions: transactions.iter().map(placeholder_transaction).collect(),
        _actionData: RelayAdapt7702ActionData {
            requireSuccess: true,
            minGasLimit: U256::ZERO,
            calls: pre_hook_calls.to_vec(),
        },
        _nonce: U256::ZERO,
        _signature: signature.clone(),
    }
    .abi_encode();
    let post_hooks = template
        .post_hook
        .iter()
        .map(|post_hook| AppDataHook {
            call_data: RelayAdapt7702::multicallCall {
                _requireSuccess: true,
                _calls: post_hook.calls.clone(),
                _nonce: U256::ZERO,
                _signature: signature.clone(),
            }
            .abi_encode()
            .into(),
            gas_limit: post_hook.gas_limit,
            target: executor,
        })
        .collect();
    let app_data = AppData::hooks(
        template.app_code.clone(),
        vec![AppDataHook {
            call_data: pre_hook.into(),
            gas_limit: template.pre_hook_gas_limit,
            target: executor,
        }],
        post_hooks,
    );
    Ok(app_data.encode()?.document.len())
}

fn placeholder_transaction(shape: &TransactionShape) -> Transaction {
    let ciphertext = CommitmentCiphertext {
        ciphertext: [FixedBytes::ZERO; 4],
        blindedSenderViewingKey: FixedBytes::ZERO,
        blindedReceiverViewingKey: FixedBytes::ZERO,
        annotationData: Bytes::new(),
        memo: Bytes::new(),
    };
    let ciphertext_count = shape
        .output_count
        .saturating_sub(usize::from(shape.has_unshield));
    Transaction {
        proof: SnarkProof::default(),
        merkleRoot: FixedBytes::ZERO,
        nullifiers: vec![FixedBytes::ZERO; shape.input_count],
        commitments: vec![FixedBytes::ZERO; shape.output_count],
        boundParams: BoundParams::new_unshield(
            0,
            0,
            0,
            vec![ciphertext; ciphertext_count],
            Address::ZERO,
            FixedBytes::ZERO,
        ),
        unshieldPreimage: CommitmentPreimage::empty(),
    }
}

impl TransactionBuilder {
    /// Check, without proving, that a swap pre-hook request fits the batch
    /// limit and that its app data fits `byte_budget`.
    ///
    /// `request` must be one executor unshield leg to the executor, carrying
    /// the pre-hook calls. When it does not fit, the result carries the
    /// largest amount that does, found as in [`Self::max_swap_pre_hook`] and
    /// strictly below the entered amount.
    pub fn check_swap_pre_hook(
        &self,
        utxos: &[Utxo],
        request: &MixedPrivateActionRequest,
        template: &SwapAppDataTemplate,
        byte_budget: usize,
    ) -> Result<SwapAmountCheck, BuildError> {
        let (_, leg) = swap_leg(request)?;
        let (over_budget_len, unselectable) =
            match self.size_swap_pre_hook(utxos, request, template, leg.amount) {
                Ok(size) if size.app_data_len <= byte_budget => {
                    return Ok(SwapAmountCheck::Fits(size));
                }
                Ok(size) => (size.app_data_len, None),
                Err(error @ BuildError::InsufficientBalance(_)) if !leg.amount.is_zero() => {
                    (0, Some(error))
                }
                Err(error) => return Err(error),
            };
        let largest = self
            .max_swap_pre_hook_below(
                utxos,
                request,
                template,
                byte_budget,
                Some(leg.amount),
                over_budget_len,
            )
            .map_err(|error| match (error, unselectable) {
                // Nothing below the entered amount was selectable and no
                // candidate exceeded the budget.
                (BuildError::SwapAppDataTooLarge { len: 0, .. }, Some(unselectable)) => {
                    unselectable
                }
                (error, _) => error,
            })?;
        Ok(SwapAmountCheck::TooLarge { largest })
    }

    /// Largest sell amount, found without proving, whose pre-hook plan fits
    /// the batch limit and whose app data fits `byte_budget`.
    ///
    /// Candidates are the maximum spends over 1 to 8 transactions, as in
    /// max-spendable selection. When the next transaction does not fit whole,
    /// it spends the largest notes of one tree, with as many inputs as the
    /// budget allows. Each candidate is sized from the selection the real build
    /// uses for that amount. The amount in `request` is ignored; callers rebuild
    /// amount-dependent calls for the returned amount, which keeps their
    /// encoded lengths.
    pub fn max_swap_pre_hook(
        &self,
        utxos: &[Utxo],
        request: &MixedPrivateActionRequest,
        template: &SwapAppDataTemplate,
        byte_budget: usize,
    ) -> Result<SwapPreHookSize, BuildError> {
        self.max_swap_pre_hook_below(utxos, request, template, byte_budget, None, 0)
    }

    /// [`Self::max_swap_pre_hook`] with an optional exclusive upper bound on
    /// the amount. `over_budget_len` seeds the length reported by
    /// [`BuildError::SwapAppDataTooLarge`] and must exceed `byte_budget`
    /// unless it is 0.
    fn max_swap_pre_hook_below(
        &self,
        utxos: &[Utxo],
        request: &MixedPrivateActionRequest,
        template: &SwapAppDataTemplate,
        byte_budget: usize,
        below: Option<U256>,
        over_budget_len: usize,
    ) -> Result<SwapPreHookSize, BuildError> {
        let (executor, leg) = swap_leg(request)?;
        let mut largest = None;
        let mut smallest_len = over_budget_len;
        for limit in 1..=MAX_BATCH_TRANSACTIONS {
            let Some(selection) = max_batch_selection(utxos, leg.token_address, 1, 1, limit) else {
                return Err(BuildError::InsufficientBalance(U256::ZERO));
            };
            if selection.chunks.len() < limit {
                // No notes remain for another transaction.
                break;
            }
            let size = self.size_swap_pre_hook(utxos, request, template, selection.total)?;
            let fits_budget = size.app_data_len <= byte_budget;
            if fits_budget && below.is_none_or(|below| selection.total < below) {
                largest = Some(size);
                continue;
            }
            if !fits_budget {
                smallest_len = size.app_data_len;
            }

            let (full_chunks, next_chunk) = selection.chunks.split_at(limit - 1);
            let full_total = selection.total - next_chunk[0].total;
            let mut remaining = utxos.to_vec();
            let mut shapes = Vec::with_capacity(limit);
            for chunk in full_chunks {
                remove_selected_utxos(&mut remaining, &chunk.utxos);
                shapes.push(TransactionShape {
                    input_count: chunk.utxos.len(),
                    output_count: 1,
                    has_unshield: true,
                });
            }
            let values_by_tree = token_utxos_by_tree(&remaining, leg.token_address)
                .into_values()
                .map(|tree_utxos| {
                    let mut values = tree_utxos
                        .iter()
                        .map(|utxo| utxo.note.value)
                        .collect::<Vec<_>>();
                    values.sort_unstable_by_key(|value| Reverse(*value));
                    values
                })
                .collect::<Vec<_>>();
            shapes.push(TransactionShape {
                input_count: 0,
                output_count: 1,
                has_unshield: true,
            });
            // A whole transaction rejected only by `below` fits the budget
            // with all of its inputs; otherwise start one input lower.
            let whole_input_count = next_chunk[0].utxos.len();
            let first_input_count = if fits_budget {
                whole_input_count
            } else {
                whole_input_count - 1
            };
            for input_count in (1..=first_input_count).rev() {
                shapes[limit - 1].input_count = input_count;
                let len = estimate_swap_app_data_len(
                    template,
                    executor,
                    &request.executor_calls,
                    &shapes,
                )?;
                if len > byte_budget {
                    smallest_len = len;
                    continue;
                }
                let next_total = match below {
                    None => values_by_tree
                        .iter()
                        .map(|values| {
                            values
                                .iter()
                                .take(input_count)
                                .fold(U256::ZERO, |sum, value| sum + *value)
                        })
                        .max()
                        .unwrap_or_default(),
                    Some(below) => match max_tree_total_below(
                        &remaining,
                        leg.token_address,
                        below.saturating_sub(full_total),
                        input_count,
                    ) {
                        Some(next_total) => next_total,
                        None => continue,
                    },
                };
                let size =
                    self.size_swap_pre_hook(utxos, request, template, full_total + next_total)?;
                if size.app_data_len <= byte_budget {
                    return Ok(size);
                }
                smallest_len = size.app_data_len;
            }
            break;
        }
        largest.ok_or(BuildError::SwapAppDataTooLarge {
            len: smallest_len,
            budget: byte_budget,
        })
    }

    fn size_swap_pre_hook(
        &self,
        utxos: &[Utxo],
        request: &MixedPrivateActionRequest,
        template: &SwapAppDataTemplate,
        amount: U256,
    ) -> Result<SwapPreHookSize, BuildError> {
        let (executor, _) = swap_leg(request)?;
        let mut request = request.clone();
        request.public_unshields[0].amount = amount;
        let preview = self.preview_mixed_private_action_plan(utxos, &request)?;
        let app_data_len = estimate_swap_app_data_len(
            template,
            executor,
            &request.executor_calls,
            &preview.transactions,
        )?;
        Ok(SwapPreHookSize {
            amount,
            preview,
            app_data_len,
        })
    }
}

fn swap_leg(
    request: &MixedPrivateActionRequest,
) -> Result<(Address, CompositeUnshieldLeg), BuildError> {
    let executor = request.executor.ok_or(BuildError::InvalidExecutorContext)?;
    match request.public_unshields.as_slice() {
        [leg]
            if leg.recipient == CompositeUnshieldRecipient::RelayAdapt
                && request.private_sends.is_empty()
                && request.relay_actions.is_none()
                && request.rebuild.is_none() =>
        {
            Ok((executor.executor, *leg))
        }
        _ => Err(BuildError::InvalidSwapRequest),
    }
}
