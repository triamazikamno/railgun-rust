//! Composite unshield plans: several unshield legs in one batch, executed
//! directly against the Railgun contract or through a Relay Adapt contract.

use alloy::primitives::{Bytes, FixedBytes, U256};
use alloy::sol_types::SolCall;

use broadcaster_core::contracts::railgun::{
    ActionData, RelayAdapt7702, RelayAdapt7702ActionData, Transaction, relayCall, transactCall,
};
use broadcaster_core::crypto::railgun::ViewingKeyData;
use broadcaster_core::utxo::Utxo;
use merkletree::tree::MerkleForest;

use crate::keys::{RailgunSpendSigner, WalletKeys};
use crate::prover::ProverService;

use super::super::{
    BroadcasterFeeOutput, BuildError, CompositeAdapter, CompositeExecution, CompositePlanShape,
    CompositePrivateOutputRole, CompositePrivateOutputRoleKind, CompositeUnshieldLeg,
    CompositeUnshieldLegMetadata, CompositeUnshieldPlan, CompositeUnshieldPlannedOutput,
    CompositeUnshieldRequest, MAX_BATCH_TRANSACTIONS, TransactionBuilder, TransactionCall,
    UNRELAYED_ADAPT_PARAMS, UnshieldRequest,
};
use super::outputs::{
    FeeOnlyOutputs, UnshieldOutputs, build_fee_only_outputs, build_unshield_outputs,
};
use super::plan::{
    InputWitnessProofCache, TransactionPlanBuilder, TransactionProver, prove_transaction_plans,
    spend_allocations,
};
use super::rand_array;
use super::selection::{
    BatchUtxoSelection, remove_selected_utxos, select_batched_utxo_candidates_with_limit,
    select_batched_utxos_with_limit, select_fee_utxos,
};

impl TransactionBuilder {
    pub(super) const fn composite_execution(
        &self,
        uses_adapter: bool,
        adapter: Option<CompositeAdapter>,
    ) -> Result<CompositeExecution, BuildError> {
        match (uses_adapter, adapter) {
            (false, None) => Ok(CompositeExecution::Direct(self.railgun_contract)),
            (true, None) => Err(BuildError::MissingCompositeAdapter),
            (true, Some(CompositeAdapter::RelayAdapt(contract))) => {
                Ok(CompositeExecution::RelayAdapt(contract))
            }
            (false, Some(CompositeAdapter::RelayAdapt(_))) => Err(BuildError::UnusedRelayAdapt),
            (true, Some(CompositeAdapter::Executor(context)))
                if self.chain_type == 0 && context.chain_id == self.chain_id =>
            {
                Ok(CompositeExecution::Executor(context))
            }
            (_, Some(CompositeAdapter::Executor(_))) => Err(BuildError::InvalidExecutorContext),
        }
    }

    /// Build a composite unshield plan using token selection from available UTXOs.
    pub async fn build_composite_unshield_plan(
        &self,
        wallet: &WalletKeys,
        forest: &MerkleForest,
        utxos: &[Utxo],
        request: CompositeUnshieldRequest,
        prover: &ProverService,
    ) -> Result<CompositeUnshieldPlan, BuildError> {
        self.build_composite_unshield_plan_with_signer(
            &wallet.viewing,
            wallet,
            forest,
            utxos,
            request,
            prover,
        )
        .await
    }

    /// Build a composite unshield plan using externally scoped viewing data and spend signer.
    pub async fn build_composite_unshield_plan_with_signer(
        &self,
        viewing: &ViewingKeyData,
        signer: &impl RailgunSpendSigner,
        forest: &MerkleForest,
        utxos: &[Utxo],
        request: CompositeUnshieldRequest,
        prover: &ProverService,
    ) -> Result<CompositeUnshieldPlan, BuildError> {
        self.build_composite_unshield_plan_inner(viewing, signer, forest, utxos, request, prover)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn build_composite_unshield_plan_inner<P: TransactionProver>(
        &self,
        viewing: &ViewingKeyData,
        signer: &impl RailgunSpendSigner,
        forest: &MerkleForest,
        utxos: &[Utxo],
        request: CompositeUnshieldRequest,
        prover: &P,
    ) -> Result<CompositeUnshieldPlan, BuildError> {
        if request.legs.is_empty() {
            return Err(BuildError::EmptyCompositeUnshieldRequest);
        }

        let has_relay_adapt_leg = request
            .legs
            .iter()
            .any(|leg| leg.recipient.uses_relay_adapt());
        let relay_call_count = request
            .relay_actions
            .as_ref()
            .map_or(0, |actions| actions.calls.len());
        if has_relay_adapt_leg && relay_call_count == 0 {
            return Err(BuildError::MissingCompositeRelayActions);
        }
        let uses_relay_adapt = has_relay_adapt_leg || relay_call_count > 0;
        let execution = self.composite_execution(uses_relay_adapt, request.adapter)?;
        let mut remaining_utxos = utxos.to_vec();
        let mut input_witness_cache = InputWitnessProofCache::new(forest);
        let receiver = viewing.address_data();
        let mut unproven_plans = Vec::new();
        let mut broadcaster_fee_note = None;
        let mut unshield_outputs = Vec::new();
        let mut private_output_roles = Vec::new();
        let mut leg_metadata = request
            .legs
            .iter()
            .enumerate()
            .map(|(leg_index, leg)| CompositeUnshieldLegMetadata {
                leg_index,
                token_address: leg.token_address,
                requested_amount: leg.amount,
                recipient: leg.recipient,
                role: leg.role,
                transaction_indices: Vec::new(),
            })
            .collect::<Vec<_>>();

        let embedded_fee = request.broadcaster_fee.filter(|fee| {
            request
                .legs
                .iter()
                .any(|leg| leg.token_address == fee.token_address)
        });
        if embedded_fee.is_none()
            && let Some(fee) = request.broadcaster_fee
        {
            let fee_selection = select_fee_utxos(&remaining_utxos, fee.token_address, fee.amount)?;
            remove_selected_utxos(&mut remaining_utxos, &fee_selection.utxos);
            let fee_change = fee_selection.total - fee.amount;
            let fee_plan_builder = TransactionPlanBuilder::new(
                self,
                viewing,
                signer,
                forest,
                fee_selection.utxos,
                fee.token_address,
            )?;
            let FeeOnlyOutputs {
                outputs,
                commitment_ciphertext,
                broadcaster_fee_note: fee_note,
                change_note,
            } = build_fee_only_outputs(fee, fee_change, &receiver, &viewing.viewing_private_key)?;
            private_output_roles.push(CompositePrivateOutputRole {
                chunk_index: 0,
                output_index: 0,
                role: CompositePrivateOutputRoleKind::BroadcasterFee,
                token_address: fee.token_address,
            });
            if change_note.is_some() {
                private_output_roles.push(CompositePrivateOutputRole {
                    chunk_index: 0,
                    output_index: 1,
                    role: CompositePrivateOutputRoleKind::Change,
                    token_address: fee.token_address,
                });
            }
            broadcaster_fee_note = Some(fee_note);
            unproven_plans.push(fee_plan_builder.build_unproven_fee_only(
                fee.token_address,
                request.min_gas_price,
                outputs,
                commitment_ciphertext,
                Some(&mut input_witness_cache),
            )?);
        }

        let (leg_selections, embedded_fee_leg_index) = select_composite_leg_selections(
            &remaining_utxos,
            &request.legs,
            embedded_fee,
            request.spend_up_to,
            unproven_plans.len(),
        )?;
        for leg_index in composite_build_leg_order(request.legs.len(), embedded_fee_leg_index) {
            let leg = request.legs[leg_index];
            let selection = &leg_selections[leg_index];
            let leg_fee = embedded_fee
                .and_then(|fee| (embedded_fee_leg_index == Some(leg_index)).then_some(fee));
            let allocations = spend_allocations(
                selection,
                leg.amount,
                leg_fee.map_or(U256::ZERO, |fee| fee.amount),
                leg_fee,
                request.spend_up_to,
            )?;
            let unshield_to = leg.recipient.unshield_to(execution.account());

            for (chunk, allocation) in selection.chunks.iter().cloned().zip(allocations) {
                let transaction_index = unproven_plans.len();
                let plan_builder = TransactionPlanBuilder::new(
                    self,
                    viewing,
                    signer,
                    forest,
                    chunk.utxos,
                    leg.token_address,
                )?;
                let UnshieldOutputs {
                    outputs,
                    commitment_ciphertext,
                    broadcaster_fee_note: chunk_fee_note,
                    unshield_note,
                    unshield_output_index: output_index,
                    change_note,
                } = build_unshield_outputs(
                    leg.token_address,
                    allocation.amount,
                    unshield_to,
                    allocation.change,
                    &receiver,
                    allocation.fee,
                    &viewing.viewing_private_key,
                )?;
                if let Some(fee) = allocation.fee {
                    private_output_roles.push(CompositePrivateOutputRole {
                        chunk_index: transaction_index,
                        output_index: 0,
                        role: CompositePrivateOutputRoleKind::BroadcasterFee,
                        token_address: fee.token_address,
                    });
                }
                if let Some(note) = chunk_fee_note {
                    broadcaster_fee_note.get_or_insert(note);
                }
                if change_note.is_some() {
                    private_output_roles.push(CompositePrivateOutputRole {
                        chunk_index: transaction_index,
                        output_index: usize::from(allocation.fee.is_some()),
                        role: CompositePrivateOutputRoleKind::Change,
                        token_address: leg.token_address,
                    });
                }

                unshield_outputs.push(CompositeUnshieldPlannedOutput {
                    leg_index,
                    transaction_index,
                    output_index,
                    token_address: leg.token_address,
                    amount: allocation.amount,
                    recipient: leg.recipient,
                    role: leg.role,
                    note: unshield_note.clone(),
                });
                leg_metadata[leg_index]
                    .transaction_indices
                    .push(transaction_index);

                let unshield_request = UnshieldRequest {
                    token_address: leg.token_address,
                    amount: allocation.amount,
                    recipient: unshield_to,
                    verify_proof: request.verify_proof,
                    spend_up_to: request.spend_up_to,
                    broadcaster_fee: allocation.fee,
                    min_gas_price: request.min_gas_price,
                };
                unproven_plans.push(plan_builder.build_unproven_unshield(
                    unshield_request,
                    outputs,
                    commitment_ciphertext,
                    &unshield_note,
                    Some(&mut input_witness_cache),
                )?);
            }
        }

        let action_data = if uses_relay_adapt {
            let actions = request
                .relay_actions
                .clone()
                .ok_or(BuildError::MissingCompositeRelayActions)?;
            let action_data =
                actions.action_data(execution.account(), FixedBytes::<31>::from(rand_array()))?;
            debug_assert!(action_data.requireSuccess);
            let transactions = unproven_plans
                .iter()
                .map(|plan| &plan.transaction)
                .collect::<Vec<_>>();
            let adapt_params = match execution {
                CompositeExecution::Executor(_) => UNRELAYED_ADAPT_PARAMS,
                _ => action_data.adapt_params(&transactions),
            };
            for plan in &mut unproven_plans {
                plan.transaction.boundParams.adaptContract = execution.account();
                plan.transaction.boundParams.adaptParams = adapt_params;
            }
            Some(action_data)
        } else {
            None
        };

        let proven_plans =
            prove_transaction_plans(unproven_plans, signer, prover, request.verify_proof).await?;
        let mut transactions = Vec::with_capacity(proven_plans.len());
        let mut chunks = Vec::with_capacity(proven_plans.len());
        for proven in proven_plans {
            transactions.push(proven.transaction);
            chunks.push(proven.chunk);
        }

        let call = composite_call(execution, transactions, action_data.as_ref())?;
        let inputs = chunks
            .iter()
            .flat_map(|chunk| chunk.inputs.clone())
            .collect::<Vec<_>>();
        let outputs = chunks
            .iter()
            .flat_map(|chunk| chunk.outputs.clone())
            .collect::<Vec<_>>();
        let shape = CompositePlanShape {
            execution,
            transaction_count: chunks.len(),
            input_count: inputs.len(),
            private_output_count: private_output_roles.len(),
            public_output_count: unshield_outputs.len(),
            relay_call_count,
            uses_relay_adapt,
        };

        Ok(CompositeUnshieldPlan {
            call,
            inputs,
            outputs,
            chunks,
            broadcaster_fee_note,
            unshield_outputs,
            leg_metadata,
            private_output_roles,
            action_data,
            shape,
        })
    }
}

pub(super) fn select_composite_leg_selections(
    utxos: &[Utxo],
    legs: &[CompositeUnshieldLeg],
    embedded_fee: Option<BroadcasterFeeOutput>,
    spend_up_to: bool,
    used_transaction_count: usize,
) -> Result<(Vec<BatchUtxoSelection>, Option<usize>), BuildError> {
    let spend_up_to_by_leg = vec![spend_up_to; legs.len()];
    select_composite_leg_selections_with_policy(
        utxos,
        legs,
        embedded_fee,
        &spend_up_to_by_leg,
        used_transaction_count,
    )
}

pub(super) fn select_composite_leg_selections_with_policy(
    utxos: &[Utxo],
    legs: &[CompositeUnshieldLeg],
    embedded_fee: Option<BroadcasterFeeOutput>,
    spend_up_to_by_leg: &[bool],
    used_transaction_count: usize,
) -> Result<(Vec<BatchUtxoSelection>, Option<usize>), BuildError> {
    let mut selections = Vec::with_capacity(legs.len());
    let mut embedded_fee_leg_index = None;
    select_composite_leg_selections_inner(
        utxos,
        legs,
        embedded_fee,
        spend_up_to_by_leg,
        0,
        used_transaction_count,
        &mut selections,
        &mut embedded_fee_leg_index,
    )?;
    Ok((selections, embedded_fee_leg_index))
}

#[allow(clippy::too_many_arguments)]
fn select_composite_leg_selections_inner(
    utxos: &[Utxo],
    legs: &[CompositeUnshieldLeg],
    embedded_fee: Option<BroadcasterFeeOutput>,
    spend_up_to_by_leg: &[bool],
    leg_index: usize,
    used_transaction_count: usize,
    selections: &mut Vec<BatchUtxoSelection>,
    embedded_fee_leg_index: &mut Option<usize>,
) -> Result<(), BuildError> {
    let Some(leg) = legs.get(leg_index).copied() else {
        if embedded_fee.is_some() && embedded_fee_leg_index.is_none() {
            return Err(BuildError::InsufficientBalance(U256::ZERO));
        }
        return Ok(());
    };
    let spend_up_to = spend_up_to_by_leg.get(leg_index).copied().unwrap_or(false);
    let remaining_slots = MAX_BATCH_TRANSACTIONS.saturating_sub(used_transaction_count);
    if remaining_slots == 0 {
        return Err(BuildError::TooManyBatchTransactions {
            requested: used_transaction_count + 1,
            max: MAX_BATCH_TRANSACTIONS,
        });
    }

    let mut last_error = None;
    let fee_options = leg_fee_options(leg, embedded_fee, *embedded_fee_leg_index);
    for leg_fee in fee_options {
        let first_base_output_count = 1 + usize::from(leg_fee.is_some());
        let target_amount = leg.amount + leg_fee.map_or(U256::ZERO, |fee| fee.amount);
        let candidates = match select_batched_utxo_candidates_with_limit(
            utxos,
            leg.token_address,
            target_amount,
            spend_up_to,
            first_base_output_count,
            1,
            remaining_slots,
        ) {
            Ok(candidates) => candidates,
            Err(error) => {
                if remaining_slots < MAX_BATCH_TRANSACTIONS
                    && let Ok(required) = select_batched_utxos_with_limit(
                        utxos,
                        leg.token_address,
                        target_amount,
                        spend_up_to,
                        first_base_output_count,
                        1,
                        MAX_BATCH_TRANSACTIONS,
                    )
                    && required.chunks.len() > remaining_slots
                {
                    retain_preferred_selection_error(
                        &mut last_error,
                        BuildError::TooManyBatchTransactions {
                            requested: used_transaction_count + required.chunks.len(),
                            max: MAX_BATCH_TRANSACTIONS,
                        },
                    );
                    continue;
                }
                retain_preferred_selection_error(&mut last_error, error);
                continue;
            }
        };

        for candidate in candidates {
            let mut remaining_utxos = utxos.to_vec();
            for chunk in &candidate.chunks {
                remove_selected_utxos(&mut remaining_utxos, &chunk.utxos);
            }
            let previous_fee_leg_index = *embedded_fee_leg_index;
            if leg_fee.is_some() {
                *embedded_fee_leg_index = Some(leg_index);
            }
            selections.push(candidate.clone());
            match select_composite_leg_selections_inner(
                &remaining_utxos,
                legs,
                embedded_fee,
                spend_up_to_by_leg,
                leg_index + 1,
                used_transaction_count + candidate.chunks.len(),
                selections,
                embedded_fee_leg_index,
            ) {
                Ok(()) => return Ok(()),
                Err(error) => retain_preferred_selection_error(&mut last_error, error),
            }
            selections.pop();
            *embedded_fee_leg_index = previous_fee_leg_index;
        }
    }

    Err(last_error.unwrap_or(BuildError::InsufficientBalance(U256::ZERO)))
}

fn retain_preferred_selection_error(current: &mut Option<BuildError>, candidate: BuildError) {
    *current = Some(match (current.take(), candidate) {
        (None, candidate) | (_, candidate @ BuildError::TooManyBatchTransactions { .. }) => {
            candidate
        }
        (
            Some(BuildError::InsufficientBalance(current_max)),
            BuildError::InsufficientBalance(candidate_max),
        ) => BuildError::InsufficientBalance(current_max.max(candidate_max)),
        (
            Some(current @ BuildError::TooManyBatchTransactions { .. }),
            BuildError::InsufficientBalance(_),
        ) => current,
        (_, candidate) => candidate,
    });
}

fn leg_fee_options(
    leg: CompositeUnshieldLeg,
    embedded_fee: Option<BroadcasterFeeOutput>,
    embedded_fee_leg_index: Option<usize>,
) -> Vec<Option<BroadcasterFeeOutput>> {
    if let Some(fee) = embedded_fee
        && embedded_fee_leg_index.is_none()
        && leg.token_address == fee.token_address
    {
        return vec![Some(fee), None];
    }
    vec![None]
}

fn composite_build_leg_order(
    leg_count: usize,
    embedded_fee_leg_index: Option<usize>,
) -> Vec<usize> {
    let mut order = Vec::with_capacity(leg_count);
    if let Some(index) = embedded_fee_leg_index.filter(|index| *index < leg_count) {
        order.push(index);
    }
    order.extend((0..leg_count).filter(|index| Some(*index) != embedded_fee_leg_index));
    order
}

pub(super) fn composite_call(
    execution: CompositeExecution,
    transactions: Vec<Transaction>,
    action_data: Option<&ActionData>,
) -> Result<TransactionCall, BuildError> {
    let data = match (execution, action_data) {
        (CompositeExecution::Direct(_), None) => transactCall {
            _transactions: transactions,
        }
        .abi_encode(),
        (CompositeExecution::RelayAdapt(_), Some(actions)) => relayCall {
            _transactions: transactions,
            _actionData: actions.clone(),
        }
        .abi_encode(),
        (CompositeExecution::Executor(context), Some(actions)) if actions.requireSuccess => {
            RelayAdapt7702::executeCall {
                _transactions: transactions,
                _actionData: RelayAdapt7702ActionData {
                    requireSuccess: true,
                    minGasLimit: actions.minGasLimit,
                    calls: actions.calls.clone(),
                },
                _nonce: context.execution_nonce,
                _signature: Bytes::new(),
            }
            .abi_encode()
        }
        _ => return Err(BuildError::InvalidExecutorCall),
    };
    Ok(TransactionCall {
        to: execution.account(),
        data: data.into(),
    })
}
