//! Mixed private actions: private sends and public unshield legs in one
//! batch, with optional pinned inputs and a proofless preview.

use std::collections::{BTreeMap, BTreeSet};

use alloy::primitives::{Address, FixedBytes, U256};

use broadcaster_core::contracts::railgun::ActionData;
use broadcaster_core::crypto::railgun::ViewingKeyData;
use broadcaster_core::utxo::Utxo;
use merkletree::tree::MerkleForest;

use crate::keys::{RailgunSpendSigner, WalletKeys};
use crate::prover::ProverService;

use super::super::{
    BuildError, CompositeAdapter, CompositeExecution, CompositePlanShape, CompositeUnshieldLeg,
    CompositeUnshieldLegRole, CompositeUnshieldRecipient, MixedPrivateActionPlan,
    MixedPrivateActionPreview, MixedPrivateActionRequest, MixedPrivateOutputRole,
    MixedPrivateOutputSource, MixedPrivatePlannedOutput, MixedPublicPlannedOutput,
    SelectedInputIdentity, SendRequest, TransactionBuilder, TransactionShape,
    UNRELAYED_ADAPT_PARAMS, UnshieldRequest,
};
use super::composite::{composite_call, select_composite_leg_selections_with_policy};
use super::outputs::{SendOutputs, UnshieldOutputs, build_send_outputs, build_unshield_outputs};
use super::plan::{
    InputWitnessProofCache, TransactionPlanBuilder, TransactionProver, UnprovenTransactionPlan,
    prove_transaction_plans, spend_allocations,
};
use super::rand_array;
use super::selection::BatchUtxoSelection;

struct MixedPrivateActionSelectionPlan {
    selections: Vec<BatchUtxoSelection>,
    preview: MixedPrivateActionPreview,
}

impl TransactionBuilder {
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
                        recipient: CompositeUnshieldRecipient::Public(Address::ZERO),
                        role: CompositeUnshieldLegRole::Other,
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
    pub(super) async fn build_mixed_private_action_plan_inner<P: TransactionProver>(
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
