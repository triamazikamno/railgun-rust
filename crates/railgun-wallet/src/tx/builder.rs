use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use alloy::primitives::{Address, Bytes, FixedBytes, U256};
use alloy::sol_types::SolCall;
use rand::Rng;

use broadcaster_core::contracts::railgun::{
    ActionData, RelayAdapt7702, RelayAdapt7702ActionData, Transaction, relayCall, transactCall,
};
use broadcaster_core::crypto::railgun::ViewingKeyData;
use broadcaster_core::utxo::Utxo;
use merkletree::tree::MerkleForest;

use crate::keys::{RailgunSpendSigner, WalletKeys};
use crate::prover::ProverService;

use super::{
    BroadcasterFeeOutput, BuildError, CompositeAdapter, CompositeExecution, CompositePlanShape,
    CompositePrivateOutputRole, CompositePrivateOutputRoleKind, CompositeUnshieldLeg,
    CompositeUnshieldLegMetadata, CompositeUnshieldPlan, CompositeUnshieldPlannedOutput,
    CompositeUnshieldRequest, MAX_BATCH_TRANSACTIONS, MixedPrivateActionPlan,
    MixedPrivateActionPreview, MixedPrivateActionRequest, MixedPrivateOutputRole,
    MixedPrivateOutputSource, MixedPrivatePlannedOutput, MixedPublicPlannedOutput,
    SelectedInputIdentity, SendPlan, SendRequest, TransactPlan, TransactionBuilder,
    TransactionCall, TransactionShape, UNRELAYED_ADAPT_PARAMS, UnshieldPlan, UnshieldRequest,
};

use outputs::{
    FeeOnlyOutputs, SendOutputs, UnshieldOutputs, build_fee_only_outputs, build_send_outputs,
    build_unshield_outputs,
};
use plan::{
    InputWitnessProofCache, TransactionPlanBuilder, TransactionProver, UnprovenTransactionPlan,
    prove_transaction_plans, spend_allocations,
};
use selection::{
    BatchUtxoSelection, UtxoSelection, remove_selected_utxos,
    select_batched_utxo_candidates_with_limit, select_batched_utxos,
    select_batched_utxos_with_limit, select_fee_utxos,
};

mod outputs;
mod plan;
mod selection;
mod swap;

pub use plan::join_error_to_prover_error;
pub use selection::{
    max_broadcaster_fee_token_spendable, max_send_spendable, max_unshield_spendable,
    send_selection_info, send_selection_info_with_broadcaster_fee,
    send_selection_info_with_broadcaster_fee_token,
    send_selection_info_with_separate_broadcaster_fee_seed, unshield_selection_info,
    unshield_selection_info_with_broadcaster_fee,
    unshield_selection_info_with_broadcaster_fee_token,
    unshield_selection_info_with_separate_broadcaster_fee_seed,
};
pub use swap::{
    SwapAmountCheck, SwapAppDataTemplate, SwapPostHookTemplate, SwapPreHookSize,
    estimate_swap_app_data_len,
};

#[cfg(test)]
use selection::select_utxos;

struct MixedPrivateActionSelectionPlan {
    selections: Vec<BatchUtxoSelection>,
    preview: MixedPrivateActionPreview,
}

impl TransactionBuilder {
    const fn composite_execution(
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

    /// Build an unshield plan using token selection from available UTXOs.
    pub async fn build_unshield_plan(
        &self,
        wallet: &WalletKeys,
        forest: &MerkleForest,
        utxos: &[Utxo],
        request: UnshieldRequest,
        prover: &ProverService,
    ) -> Result<UnshieldPlan, BuildError> {
        self.build_unshield_plan_with_signer(
            &wallet.viewing,
            wallet,
            forest,
            utxos,
            request,
            prover,
        )
        .await
    }

    /// Build an unshield plan using externally scoped viewing data and spend signer.
    pub async fn build_unshield_plan_with_signer(
        &self,
        viewing: &ViewingKeyData,
        signer: &impl RailgunSpendSigner,
        forest: &MerkleForest,
        utxos: &[Utxo],
        request: UnshieldRequest,
        prover: &ProverService,
    ) -> Result<UnshieldPlan, BuildError> {
        if let Some(fee) = request.different_token_broadcaster_fee() {
            let fee_selection = select_fee_utxos(utxos, fee.token_address, fee.amount)?;
            let action_selection = select_batched_utxos_with_limit(
                utxos,
                request.token_address,
                request.amount,
                request.spend_up_to,
                1,
                1,
                MAX_BATCH_TRANSACTIONS - 1,
            )?;
            return self
                .build_unshield_batch_with_separate_fee_token(
                    viewing,
                    signer,
                    forest,
                    fee_selection,
                    action_selection,
                    request,
                    fee,
                    prover,
                )
                .await;
        }

        let selection = select_batched_utxos(
            utxos,
            request.token_address,
            request.target_amount(),
            request.spend_up_to,
            request.base_output_count(),
            1,
        )?;

        self.build_unshield_batch_with_signer(viewing, signer, forest, selection, request, prover)
            .await
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
    async fn build_composite_unshield_plan_inner<P: TransactionProver>(
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

    /// Select a mixed private action and return its proofless input and shape summary.
    pub fn preview_mixed_private_action_plan(
        &self,
        utxos: &[Utxo],
        request: &MixedPrivateActionRequest,
    ) -> Result<MixedPrivateActionPreview, BuildError> {
        Ok(self
            .select_mixed_private_action_plan(utxos, request)?
            .preview)
    }

    fn select_mixed_private_action_plan(
        &self,
        utxos: &[Utxo],
        request: &MixedPrivateActionRequest,
    ) -> Result<MixedPrivateActionSelectionPlan, BuildError> {
        if request.private_sends.is_empty() && request.public_unshields.is_empty() {
            return Err(BuildError::EmptyMixedPrivateActionRequest);
        }
        if !request.executor_calls.is_empty() {
            if !matches!(request.adapter, Some(CompositeAdapter::Executor(_))) {
                return Err(BuildError::InvalidExecutorContext);
            }
            if request.relay_actions.is_some() {
                return Err(BuildError::ConflictingExecutorActions);
            }
        }
        let has_relay_adapt_leg = request
            .public_unshields
            .iter()
            .any(|leg| leg.recipient.uses_relay_adapt());
        let relay_call_count = request.executor_calls.len()
            + request
                .relay_actions
                .as_ref()
                .map_or(0, |actions| actions.calls.len());
        if has_relay_adapt_leg && relay_call_count == 0 {
            return Err(BuildError::MissingCompositeRelayActions);
        }
        // Executor plans always settle through `execute`, even with no calls, so the
        // executor signature also binds fee-only setup plans.
        let uses_relay_adapt = has_relay_adapt_leg
            || relay_call_count > 0
            || matches!(request.adapter, Some(CompositeAdapter::Executor(_)));
        let execution = self.composite_execution(uses_relay_adapt, request.adapter)?;
        let candidate_utxos = request.rebuild.as_ref().map_or_else(
            || Ok(utxos.to_vec()),
            |constraint| resolve_pinned_utxos(utxos, &constraint.selected_inputs),
        )?;
        let selection_legs = request
            .public_unshields
            .iter()
            .copied()
            .chain(
                request
                    .private_sends
                    .iter()
                    .map(|send| CompositeUnshieldLeg {
                        token_address: send.token_address,
                        amount: send.amount,
                        recipient: super::CompositeUnshieldRecipient::Public(Address::ZERO),
                        role: super::CompositeUnshieldLegRole::Other,
                    }),
            )
            .collect::<Vec<_>>();
        let spend_up_to_by_leg = std::iter::repeat_n(false, request.public_unshields.len())
            .chain(std::iter::repeat_n(
                request.spend_up_to,
                request.private_sends.len(),
            ))
            .collect::<Vec<_>>();
        let (selections, _) = select_composite_leg_selections_with_policy(
            &candidate_utxos,
            &selection_legs,
            None,
            &spend_up_to_by_leg,
            0,
        )
        .map_err(|error| match (request.rebuild.is_some(), error) {
            (true, BuildError::InsufficientBalance(max)) => {
                BuildError::PinnedInputsInsufficient(max)
            }
            (_, other) => other,
        })?;

        // Build order: private sends, then public unshields.
        let mut transactions = Vec::new();
        for (send_index, send) in request.private_sends.iter().enumerate() {
            let selection = &selections[request.public_unshields.len() + send_index];
            let allocations = spend_allocations(
                selection,
                send.amount,
                U256::ZERO,
                None,
                request.spend_up_to,
            )?;
            transactions.extend(selection.chunks.iter().zip(allocations).map(
                |(chunk, allocation)| TransactionShape {
                    input_count: chunk.utxos.len(),
                    output_count: 1 + usize::from(!allocation.change.is_zero()),
                    has_unshield: false,
                },
            ));
        }
        for (unshield_index, leg) in request.public_unshields.iter().enumerate() {
            let selection = &selections[unshield_index];
            let allocations = spend_allocations(selection, leg.amount, U256::ZERO, None, false)?;
            transactions.extend(selection.chunks.iter().zip(allocations).map(
                |(chunk, allocation)| TransactionShape {
                    input_count: chunk.utxos.len(),
                    output_count: 1 + usize::from(!allocation.change.is_zero()),
                    has_unshield: true,
                },
            ));
        }
        let public_output_count = transactions
            .iter()
            .filter(|transaction| transaction.has_unshield)
            .count();
        let private_output_count = transactions
            .iter()
            .map(|transaction| transaction.output_count)
            .sum::<usize>()
            - public_output_count;
        let mut selected_inputs = selections
            .iter()
            .flat_map(|selection| selection.chunks.iter())
            .flat_map(|chunk| chunk.utxos.iter())
            .map(SelectedInputIdentity::from_utxo)
            .collect::<Vec<_>>();
        selected_inputs.sort_unstable();
        let shape = CompositePlanShape {
            execution,
            transaction_count: selections
                .iter()
                .map(|selection| selection.chunks.len())
                .sum(),
            input_count: selected_inputs.len(),
            private_output_count,
            public_output_count,
            relay_call_count,
            uses_relay_adapt,
        };
        if let Some(constraint) = request.rebuild.as_ref() {
            let mut expected_inputs = constraint.selected_inputs.clone();
            expected_inputs.sort_unstable();
            if selected_inputs != expected_inputs {
                return Err(BuildError::PinnedInputsChanged {
                    expected: expected_inputs,
                    actual: selected_inputs,
                });
            }
            if shape != constraint.expected_shape {
                return Err(BuildError::CompositePlanShapeChanged {
                    expected: Box::new(constraint.expected_shape),
                    actual: Box::new(shape),
                });
            }
        }
        Ok(MixedPrivateActionSelectionPlan {
            selections,
            preview: MixedPrivateActionPreview {
                selected_inputs,
                shape,
                transactions,
            },
        })
    }

    /// Build a mixed private action containing private sends and public unshield legs.
    pub async fn build_mixed_private_action_plan(
        &self,
        wallet: &WalletKeys,
        forest: &MerkleForest,
        utxos: &[Utxo],
        request: MixedPrivateActionRequest,
        prover: &ProverService,
    ) -> Result<MixedPrivateActionPlan, BuildError> {
        self.build_mixed_private_action_plan_with_signer(
            &wallet.viewing,
            wallet,
            forest,
            utxos,
            request,
            prover,
        )
        .await
    }

    /// Build a mixed private action using externally scoped viewing data and spend signer.
    pub async fn build_mixed_private_action_plan_with_signer(
        &self,
        viewing: &ViewingKeyData,
        signer: &impl RailgunSpendSigner,
        forest: &MerkleForest,
        utxos: &[Utxo],
        request: MixedPrivateActionRequest,
        prover: &ProverService,
    ) -> Result<MixedPrivateActionPlan, BuildError> {
        self.build_mixed_private_action_plan_inner(viewing, signer, forest, utxos, request, prover)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn build_mixed_private_action_plan_inner<P: TransactionProver>(
        &self,
        viewing: &ViewingKeyData,
        signer: &impl RailgunSpendSigner,
        forest: &MerkleForest,
        utxos: &[Utxo],
        request: MixedPrivateActionRequest,
        prover: &P,
    ) -> Result<MixedPrivateActionPlan, BuildError> {
        let MixedPrivateActionSelectionPlan {
            selections,
            preview,
        } = self.select_mixed_private_action_plan(utxos, &request)?;
        let relay_call_count = preview.shape.relay_call_count;
        let uses_relay_adapt = preview.shape.uses_relay_adapt;
        let execution = preview.shape.execution;

        let sender = viewing.address_data();
        let mut input_witness_cache = InputWitnessProofCache::new(forest);
        let mut unproven_plans = Vec::new();
        let mut private_outputs = Vec::new();
        let mut public_outputs = Vec::new();

        for (send_index, send) in request.private_sends.iter().copied().enumerate() {
            let selection = &selections[request.public_unshields.len() + send_index];
            let allocations = spend_allocations(
                selection,
                send.amount,
                U256::ZERO,
                None,
                request.spend_up_to,
            )?;
            let send_request = SendRequest {
                token_address: send.token_address,
                amount: send.amount,
                recipient: send.recipient,
                verify_proof: request.verify_proof,
                spend_up_to: request.spend_up_to,
                broadcaster_fee: None,
                min_gas_price: request.min_gas_price,
            };

            for (chunk, allocation) in selection.chunks.iter().cloned().zip(allocations) {
                let transaction_index = unproven_plans.len();
                let plan_builder = TransactionPlanBuilder::new(
                    self,
                    viewing,
                    signer,
                    forest,
                    chunk.utxos,
                    send.token_address,
                )?;
                let SendOutputs {
                    outputs,
                    commitment_ciphertext,
                    broadcaster_fee_note: _,
                    recipient_note,
                    change_note,
                } = build_send_outputs(
                    send.token_address,
                    allocation.amount,
                    allocation.change,
                    &sender,
                    &send.recipient,
                    None,
                    &viewing.viewing_private_key,
                )?;
                private_outputs.push(MixedPrivatePlannedOutput {
                    source: MixedPrivateOutputSource::Send(send_index),
                    transaction_index,
                    output_index: 0,
                    token_address: send.token_address,
                    amount: allocation.amount,
                    role: MixedPrivateOutputRole::Recipient(send.role),
                    note: recipient_note,
                });
                if let Some(change_note) = change_note {
                    private_outputs.push(MixedPrivatePlannedOutput {
                        source: MixedPrivateOutputSource::Send(send_index),
                        transaction_index,
                        output_index: 1,
                        token_address: send.token_address,
                        amount: allocation.change,
                        role: MixedPrivateOutputRole::Change,
                        note: change_note,
                    });
                }
                unproven_plans.push(plan_builder.build_unproven_send(
                    &send_request,
                    outputs,
                    commitment_ciphertext,
                    Some(&mut input_witness_cache),
                )?);
            }
        }

        for (unshield_index, leg) in request.public_unshields.iter().copied().enumerate() {
            let selection = &selections[unshield_index];
            let allocations = spend_allocations(selection, leg.amount, U256::ZERO, None, false)?;
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
                    broadcaster_fee_note: _,
                    unshield_note,
                    unshield_output_index,
                    change_note,
                } = build_unshield_outputs(
                    leg.token_address,
                    allocation.amount,
                    unshield_to,
                    allocation.change,
                    &sender,
                    None,
                    &viewing.viewing_private_key,
                )?;
                if let Some(change_note) = change_note {
                    private_outputs.push(MixedPrivatePlannedOutput {
                        source: MixedPrivateOutputSource::PublicUnshield(unshield_index),
                        transaction_index,
                        output_index: 0,
                        token_address: leg.token_address,
                        amount: allocation.change,
                        role: MixedPrivateOutputRole::Change,
                        note: change_note,
                    });
                }
                public_outputs.push(MixedPublicPlannedOutput {
                    unshield_index,
                    transaction_index,
                    output_index: unshield_output_index,
                    token_address: leg.token_address,
                    amount: allocation.amount,
                    recipient: leg.recipient,
                    role: leg.role,
                    note: unshield_note.clone(),
                });
                let unshield_request = UnshieldRequest {
                    token_address: leg.token_address,
                    amount: allocation.amount,
                    recipient: unshield_to,
                    verify_proof: request.verify_proof,
                    spend_up_to: request.spend_up_to,
                    broadcaster_fee: None,
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

        let actual_selected_inputs = selected_input_identities_from_unproven(&unproven_plans);
        let actual_shape = CompositePlanShape {
            execution,
            transaction_count: unproven_plans.len(),
            input_count: actual_selected_inputs.len(),
            private_output_count: private_outputs.len(),
            public_output_count: public_outputs.len(),
            relay_call_count,
            uses_relay_adapt,
        };
        debug_assert_eq!(actual_selected_inputs, preview.selected_inputs);
        debug_assert_eq!(actual_shape, preview.shape);
        debug_assert_eq!(
            unproven_plans
                .iter()
                .map(|plan| TransactionShape {
                    input_count: plan.inputs.len(),
                    output_count: plan.outputs.len(),
                    has_unshield: plan.has_unshield,
                })
                .collect::<Vec<_>>(),
            preview.transactions
        );
        let selected_inputs = preview.selected_inputs;
        let shape = preview.shape;

        let action_data = if uses_relay_adapt {
            let action_data = match (request.relay_actions.as_ref(), execution) {
                (Some(relay_actions), _) => relay_actions
                    .action_data(execution.account(), FixedBytes::<31>::from(rand_array()))?,
                (None, CompositeExecution::Executor(_)) => ActionData {
                    random: FixedBytes::<31>::from(rand_array()),
                    requireSuccess: true,
                    minGasLimit: U256::ZERO,
                    calls: request.executor_calls.clone(),
                },
                (None, _) => return Err(BuildError::MissingCompositeRelayActions),
            };
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

        Ok(MixedPrivateActionPlan {
            call,
            inputs,
            outputs,
            chunks,
            private_outputs,
            public_outputs,
            action_data,
            selected_inputs,
            shape,
        })
    }

    /// Build a private send plan using token selection from available UTXOs.
    pub async fn build_send_plan(
        &self,
        wallet: &WalletKeys,
        forest: &MerkleForest,
        utxos: &[Utxo],
        request: SendRequest,
        prover: &ProverService,
    ) -> Result<SendPlan, BuildError> {
        self.build_send_plan_with_signer(&wallet.viewing, wallet, forest, utxos, request, prover)
            .await
    }

    /// Build a private send plan using externally scoped viewing data and spend signer.
    pub async fn build_send_plan_with_signer(
        &self,
        viewing: &ViewingKeyData,
        signer: &impl RailgunSpendSigner,
        forest: &MerkleForest,
        utxos: &[Utxo],
        request: SendRequest,
        prover: &ProverService,
    ) -> Result<SendPlan, BuildError> {
        if let Some(fee) = request.different_token_broadcaster_fee() {
            let fee_selection = select_fee_utxos(utxos, fee.token_address, fee.amount)?;
            let action_selection = select_batched_utxos_with_limit(
                utxos,
                request.token_address,
                request.amount,
                request.spend_up_to,
                1,
                1,
                MAX_BATCH_TRANSACTIONS - 1,
            )?;
            return self
                .build_send_batch_with_separate_fee_token(
                    viewing,
                    signer,
                    forest,
                    fee_selection,
                    action_selection,
                    &request,
                    fee,
                    prover,
                )
                .await;
        }

        let selection = select_batched_utxos(
            utxos,
            request.token_address,
            request.target_amount(),
            request.spend_up_to,
            request.base_output_count(),
            1,
        )?;

        self.build_send_batch_with_signer(viewing, signer, forest, selection, &request, prover)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn build_unshield_batch_with_separate_fee_token(
        &self,
        viewing: &ViewingKeyData,
        signer: &impl RailgunSpendSigner,
        forest: &MerkleForest,
        fee_selection: UtxoSelection,
        action_selection: BatchUtxoSelection,
        request: UnshieldRequest,
        fee: BroadcasterFeeOutput,
        prover: &ProverService,
    ) -> Result<UnshieldPlan, BuildError> {
        let mut input_witness_cache = InputWitnessProofCache::new(forest);
        let receiver = viewing.address_data();
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
            broadcaster_fee_note,
            mut change_note,
        } = build_fee_only_outputs(fee, fee_change, &receiver, &viewing.viewing_private_key)?;
        let fee_unproven_plan = fee_plan_builder.build_unproven_fee_only(
            fee.token_address,
            request.min_gas_price,
            outputs,
            commitment_ciphertext,
            Some(&mut input_witness_cache),
        )?;

        let allocations = spend_allocations(
            &action_selection,
            request.amount,
            U256::ZERO,
            None,
            request.spend_up_to,
        )?;
        let mut unproven_plans = Vec::with_capacity(1 + action_selection.chunks.len());
        unproven_plans.push(fee_unproven_plan);
        let mut unshield_notes = Vec::with_capacity(action_selection.chunks.len());

        for (chunk, allocation) in action_selection.chunks.into_iter().zip(allocations) {
            let plan_builder = TransactionPlanBuilder::new(
                self,
                viewing,
                signer,
                forest,
                chunk.utxos,
                request.token_address,
            )?;
            let UnshieldOutputs {
                outputs,
                commitment_ciphertext,
                broadcaster_fee_note: _,
                unshield_note,
                unshield_output_index: _,
                change_note: chunk_change_note,
            } = build_unshield_outputs(
                request.token_address,
                allocation.amount,
                request.recipient,
                allocation.change,
                &receiver,
                None,
                &viewing.viewing_private_key,
            )?;
            if chunk_change_note.is_some() {
                change_note.clone_from(&chunk_change_note);
            }
            unshield_notes.push(unshield_note);
            unproven_plans.push(plan_builder.build_unproven_unshield(
                request,
                outputs,
                commitment_ciphertext,
                unshield_notes.last().expect("pushed unshield note"),
                Some(&mut input_witness_cache),
            )?);
        }

        let proven_plans =
            prove_transaction_plans(unproven_plans, signer, prover, request.verify_proof).await?;
        let mut transactions = Vec::with_capacity(proven_plans.len());
        let mut chunks = Vec::with_capacity(proven_plans.len());
        for proven in proven_plans {
            transactions.push(proven.transaction);
            chunks.push(proven.chunk);
        }

        let first_chunk = chunks.first().expect("fee selection has one chunk").clone();
        let inputs = chunks
            .iter()
            .flat_map(|chunk| chunk.inputs.clone())
            .collect::<Vec<_>>();
        let outputs = chunks
            .iter()
            .flat_map(|chunk| chunk.outputs.clone())
            .collect::<Vec<_>>();
        let unshield_note = unshield_notes
            .first()
            .expect("action selection has at least one chunk")
            .clone();

        let data = transactCall {
            _transactions: transactions,
        }
        .abi_encode();
        let call = TransactionCall {
            to: self.railgun_contract,
            data: data.into(),
        };

        Ok(UnshieldPlan {
            call,
            tree_number: first_chunk.tree_number,
            merkle_root: first_chunk.merkle_root,
            inputs,
            outputs,
            chunks,
            broadcaster_fee_note: Some(broadcaster_fee_note),
            unshield_note,
            unshield_notes,
            change_note,
            public_inputs: first_chunk.public_inputs,
            private_inputs: first_chunk.private_inputs,
            signature: first_chunk.signature,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn build_send_batch_with_separate_fee_token(
        &self,
        viewing: &ViewingKeyData,
        signer: &impl RailgunSpendSigner,
        forest: &MerkleForest,
        fee_selection: UtxoSelection,
        action_selection: BatchUtxoSelection,
        request: &SendRequest,
        fee: BroadcasterFeeOutput,
        prover: &ProverService,
    ) -> Result<SendPlan, BuildError> {
        let total_started = Instant::now();
        let mut input_witness_cache = InputWitnessProofCache::new(forest);
        let setup_started = Instant::now();
        let sender = viewing.address_data();
        let fee_change = fee_selection.total - fee.amount;
        let setup_elapsed_ms = setup_started.elapsed().as_millis();
        let fee_plan_builder = TransactionPlanBuilder::new(
            self,
            viewing,
            signer,
            forest,
            fee_selection.utxos,
            fee.token_address,
        )?;
        let fee_outputs_started = Instant::now();
        let FeeOnlyOutputs {
            outputs,
            commitment_ciphertext,
            broadcaster_fee_note,
            mut change_note,
        } = build_fee_only_outputs(fee, fee_change, &sender, &viewing.viewing_private_key)?;
        let fee_outputs_elapsed_ms = fee_outputs_started.elapsed().as_millis();
        let fee_unproven_started = Instant::now();
        let fee_unproven_plan = fee_plan_builder.build_unproven_fee_only(
            fee.token_address,
            request.min_gas_price,
            outputs,
            commitment_ciphertext,
            Some(&mut input_witness_cache),
        )?;
        let fee_unproven_elapsed_ms = fee_unproven_started.elapsed().as_millis();

        let allocations_started = Instant::now();
        let allocations = spend_allocations(
            &action_selection,
            request.amount,
            U256::ZERO,
            None,
            request.spend_up_to,
        )?;
        let allocations_elapsed_ms = allocations_started.elapsed().as_millis();
        let mut unproven_plans = Vec::with_capacity(1 + action_selection.chunks.len());
        unproven_plans.push(fee_unproven_plan);
        let mut recipient_notes = Vec::with_capacity(action_selection.chunks.len());
        let mut action_outputs_elapsed_ms = 0_u128;
        let mut action_unproven_elapsed_ms = 0_u128;

        for (chunk, allocation) in action_selection.chunks.into_iter().zip(allocations) {
            let plan_builder = TransactionPlanBuilder::new(
                self,
                viewing,
                signer,
                forest,
                chunk.utxos,
                request.token_address,
            )?;
            let action_outputs_started = Instant::now();
            let SendOutputs {
                outputs,
                commitment_ciphertext,
                broadcaster_fee_note: _,
                recipient_note,
                change_note: chunk_change_note,
            } = build_send_outputs(
                request.token_address,
                allocation.amount,
                allocation.change,
                &sender,
                &request.recipient,
                None,
                &viewing.viewing_private_key,
            )?;
            action_outputs_elapsed_ms += action_outputs_started.elapsed().as_millis();
            if chunk_change_note.is_some() {
                change_note.clone_from(&chunk_change_note);
            }
            recipient_notes.push(recipient_note);
            let action_unproven_started = Instant::now();
            unproven_plans.push(plan_builder.build_unproven_send(
                request,
                outputs,
                commitment_ciphertext,
                Some(&mut input_witness_cache),
            )?);
            action_unproven_elapsed_ms += action_unproven_started.elapsed().as_millis();
        }

        let prove_started = Instant::now();
        let proven_plans =
            prove_transaction_plans(unproven_plans, signer, prover, request.verify_proof).await?;
        let mut transactions = Vec::with_capacity(proven_plans.len());
        let mut chunks = Vec::with_capacity(proven_plans.len());
        for proven in proven_plans {
            transactions.push(proven.transaction);
            chunks.push(proven.chunk);
        }
        let prove_elapsed_ms = prove_started.elapsed().as_millis();

        let first_chunk = chunks.first().expect("fee selection has one chunk").clone();
        let inputs = chunks
            .iter()
            .flat_map(|chunk| chunk.inputs.clone())
            .collect::<Vec<_>>();
        let outputs = chunks
            .iter()
            .flat_map(|chunk| chunk.outputs.clone())
            .collect::<Vec<_>>();
        let recipient_note = recipient_notes
            .first()
            .expect("action selection has at least one chunk")
            .clone();

        let abi_started = Instant::now();
        let data = transactCall {
            _transactions: transactions,
        }
        .abi_encode();
        let abi_elapsed_ms = abi_started.elapsed().as_millis();
        let call = TransactionCall {
            to: self.railgun_contract,
            data: data.into(),
        };
        let witness_stats = input_witness_cache.stats();
        tracing::debug!(
            transaction_count = chunks.len(),
            setup_elapsed_ms,
            fee_outputs_elapsed_ms,
            fee_unproven_elapsed_ms,
            allocations_elapsed_ms,
            action_outputs_elapsed_ms,
            action_unproven_elapsed_ms,
            prove_elapsed_ms,
            abi_elapsed_ms,
            input_witness_proofs = witness_stats.proof_count,
            input_witness_dense_tree_builds = witness_stats.dense_tree_build_count,
            input_witness_dense_tree_build_elapsed_ms = witness_stats.dense_tree_build_elapsed_ms,
            elapsed_ms = total_started.elapsed().as_millis(),
            "built separate-fee send batch"
        );

        Ok(SendPlan {
            call,
            tree_number: first_chunk.tree_number,
            merkle_root: first_chunk.merkle_root,
            inputs,
            outputs,
            chunks,
            broadcaster_fee_note: Some(broadcaster_fee_note),
            recipient_note,
            recipient_notes,
            change_note,
            public_inputs: first_chunk.public_inputs,
            private_inputs: first_chunk.private_inputs,
            signature: first_chunk.signature,
        })
    }

    async fn build_unshield_batch_with_signer(
        &self,
        viewing: &ViewingKeyData,
        signer: &impl RailgunSpendSigner,
        forest: &MerkleForest,
        selection: BatchUtxoSelection,
        request: UnshieldRequest,
        prover: &ProverService,
    ) -> Result<UnshieldPlan, BuildError> {
        let mut input_witness_cache = InputWitnessProofCache::new(forest);
        let allocations = spend_allocations(
            &selection,
            request.amount,
            request.fee_amount(),
            request.same_token_broadcaster_fee(),
            request.spend_up_to,
        )?;
        let receiver = viewing.address_data();

        let mut unproven_plans = Vec::with_capacity(selection.chunks.len());
        let mut broadcaster_fee_note = None;
        let mut unshield_notes = Vec::with_capacity(selection.chunks.len());
        let mut change_note = None;

        for (chunk, allocation) in selection.chunks.into_iter().zip(allocations) {
            let plan_builder = TransactionPlanBuilder::new(
                self,
                viewing,
                signer,
                forest,
                chunk.utxos,
                request.token_address,
            )?;
            let UnshieldOutputs {
                outputs,
                commitment_ciphertext,
                broadcaster_fee_note: chunk_fee_note,
                unshield_note,
                unshield_output_index: _,
                change_note: chunk_change_note,
            } = build_unshield_outputs(
                request.token_address,
                allocation.amount,
                request.recipient,
                allocation.change,
                &receiver,
                allocation.fee,
                &viewing.viewing_private_key,
            )?;
            if broadcaster_fee_note.is_none() {
                broadcaster_fee_note = chunk_fee_note;
            }
            if chunk_change_note.is_some() {
                change_note.clone_from(&chunk_change_note);
            }
            unshield_notes.push(unshield_note);
            unproven_plans.push(plan_builder.build_unproven_unshield(
                request,
                outputs,
                commitment_ciphertext,
                unshield_notes.last().expect("pushed unshield note"),
                Some(&mut input_witness_cache),
            )?);
        }

        let proven_plans =
            prove_transaction_plans(unproven_plans, signer, prover, request.verify_proof).await?;
        let mut transactions = Vec::with_capacity(proven_plans.len());
        let mut chunks = Vec::with_capacity(proven_plans.len());
        for proven in proven_plans {
            transactions.push(proven.transaction);
            chunks.push(proven.chunk);
        }

        let first_chunk = chunks
            .first()
            .expect("selection has at least one chunk")
            .clone();
        let inputs = chunks
            .iter()
            .flat_map(|chunk| chunk.inputs.clone())
            .collect::<Vec<_>>();
        let outputs = chunks
            .iter()
            .flat_map(|chunk| chunk.outputs.clone())
            .collect::<Vec<_>>();
        let unshield_note = unshield_notes
            .first()
            .expect("selection has at least one chunk")
            .clone();

        let data = transactCall {
            _transactions: transactions,
        }
        .abi_encode();
        let call = TransactionCall {
            to: self.railgun_contract,
            data: data.into(),
        };

        Ok(UnshieldPlan {
            call,
            tree_number: first_chunk.tree_number,
            merkle_root: first_chunk.merkle_root,
            inputs,
            outputs,
            chunks,
            broadcaster_fee_note,
            unshield_note,
            unshield_notes,
            change_note,
            public_inputs: first_chunk.public_inputs,
            private_inputs: first_chunk.private_inputs,
            signature: first_chunk.signature,
        })
    }

    async fn build_send_batch_with_signer(
        &self,
        viewing: &ViewingKeyData,
        signer: &impl RailgunSpendSigner,
        forest: &MerkleForest,
        selection: BatchUtxoSelection,
        request: &SendRequest,
        prover: &ProverService,
    ) -> Result<SendPlan, BuildError> {
        let total_started = Instant::now();
        let mut input_witness_cache = InputWitnessProofCache::new(forest);
        let allocations_started = Instant::now();
        let allocations = spend_allocations(
            &selection,
            request.amount,
            request.fee_amount(),
            request.same_token_broadcaster_fee(),
            request.spend_up_to,
        )?;
        let allocations_elapsed_ms = allocations_started.elapsed().as_millis();
        let sender = viewing.address_data();
        let mut unproven_plans = Vec::with_capacity(selection.chunks.len());
        let mut broadcaster_fee_note = None;
        let mut recipient_notes = Vec::with_capacity(selection.chunks.len());
        let mut change_note = None;
        let mut outputs_elapsed_ms = 0_u128;
        let mut unproven_elapsed_ms = 0_u128;

        for (chunk, allocation) in selection.chunks.into_iter().zip(allocations) {
            let plan_builder = TransactionPlanBuilder::new(
                self,
                viewing,
                signer,
                forest,
                chunk.utxos,
                request.token_address,
            )?;
            let outputs_started = Instant::now();
            let SendOutputs {
                outputs,
                commitment_ciphertext,
                broadcaster_fee_note: chunk_fee_note,
                recipient_note,
                change_note: chunk_change_note,
            } = build_send_outputs(
                request.token_address,
                allocation.amount,
                allocation.change,
                &sender,
                &request.recipient,
                allocation.fee,
                &viewing.viewing_private_key,
            )?;
            outputs_elapsed_ms += outputs_started.elapsed().as_millis();
            if broadcaster_fee_note.is_none() {
                broadcaster_fee_note = chunk_fee_note;
            }
            if chunk_change_note.is_some() {
                change_note.clone_from(&chunk_change_note);
            }
            recipient_notes.push(recipient_note);
            let unproven_started = Instant::now();
            unproven_plans.push(plan_builder.build_unproven_send(
                request,
                outputs,
                commitment_ciphertext,
                Some(&mut input_witness_cache),
            )?);
            unproven_elapsed_ms += unproven_started.elapsed().as_millis();
        }

        let prove_started = Instant::now();
        let proven_plans =
            prove_transaction_plans(unproven_plans, signer, prover, request.verify_proof).await?;
        let mut transactions = Vec::with_capacity(proven_plans.len());
        let mut chunks = Vec::with_capacity(proven_plans.len());
        for proven in proven_plans {
            transactions.push(proven.transaction);
            chunks.push(proven.chunk);
        }
        let prove_elapsed_ms = prove_started.elapsed().as_millis();

        let first_chunk = chunks
            .first()
            .expect("selection has at least one chunk")
            .clone();
        let inputs = chunks
            .iter()
            .flat_map(|chunk| chunk.inputs.clone())
            .collect::<Vec<_>>();
        let outputs = chunks
            .iter()
            .flat_map(|chunk| chunk.outputs.clone())
            .collect::<Vec<_>>();
        let recipient_note = recipient_notes
            .first()
            .expect("selection has at least one chunk")
            .clone();

        let abi_started = Instant::now();
        let data = transactCall {
            _transactions: transactions,
        }
        .abi_encode();
        let abi_elapsed_ms = abi_started.elapsed().as_millis();
        let call = TransactionCall {
            to: self.railgun_contract,
            data: data.into(),
        };
        let witness_stats = input_witness_cache.stats();
        tracing::debug!(
            transaction_count = chunks.len(),
            allocations_elapsed_ms,
            outputs_elapsed_ms,
            unproven_elapsed_ms,
            prove_elapsed_ms,
            abi_elapsed_ms,
            input_witness_proofs = witness_stats.proof_count,
            input_witness_dense_tree_builds = witness_stats.dense_tree_build_count,
            input_witness_dense_tree_build_elapsed_ms = witness_stats.dense_tree_build_elapsed_ms,
            elapsed_ms = total_started.elapsed().as_millis(),
            "built send batch"
        );

        Ok(SendPlan {
            call,
            tree_number: first_chunk.tree_number,
            merkle_root: first_chunk.merkle_root,
            inputs,
            outputs,
            chunks,
            broadcaster_fee_note,
            recipient_note,
            recipient_notes,
            change_note,
            public_inputs: first_chunk.public_inputs,
            private_inputs: first_chunk.private_inputs,
            signature: first_chunk.signature,
        })
    }

    /// Build a transact plan for UTXO consolidation.
    pub async fn build_transact_plan(
        &self,
        wallet: &WalletKeys,
        forest: &MerkleForest,
        inputs: &[Utxo],
        token_address: Address,
        prover: &ProverService,
    ) -> Result<TransactPlan, BuildError> {
        let plan_builder = TransactionPlanBuilder::new(
            self,
            &wallet.viewing,
            wallet,
            forest,
            inputs.to_vec(),
            token_address,
        )?;

        plan_builder.build_transact(prover).await
    }
}

fn resolve_pinned_utxos(
    utxos: &[Utxo],
    pinned_inputs: &[SelectedInputIdentity],
) -> Result<Vec<Utxo>, BuildError> {
    let available = utxos
        .iter()
        .map(|utxo| (SelectedInputIdentity::from_utxo(utxo), utxo))
        .collect::<BTreeMap<_, _>>();
    let mut seen = BTreeSet::new();
    let mut pinned = Vec::with_capacity(pinned_inputs.len());
    for identity in pinned_inputs {
        if !seen.insert(*identity) {
            return Err(BuildError::DuplicatePinnedInput {
                tree: identity.tree,
                position: identity.position,
            });
        }
        let utxo = available
            .get(identity)
            .ok_or(BuildError::PinnedInputUnavailable {
                tree: identity.tree,
                position: identity.position,
            })?;
        pinned.push((*utxo).clone());
    }
    Ok(pinned)
}

fn selected_input_identities_from_unproven(
    plans: &[UnprovenTransactionPlan],
) -> Vec<SelectedInputIdentity> {
    let mut identities = plans
        .iter()
        .flat_map(|plan| {
            plan.inputs
                .iter()
                .map(|input| SelectedInputIdentity::from_utxo(&input.utxo))
        })
        .collect::<Vec<_>>();
    identities.sort_unstable();
    identities
}

fn select_composite_leg_selections(
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

fn select_composite_leg_selections_with_policy(
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

fn rand_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::rng().fill_bytes(&mut out);
    out
}

#[cfg(test)]
mod tests;

fn composite_call(
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
