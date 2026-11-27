//! Composite unshield plans: several unshield legs in one batch, executed
//! directly against the Railgun contract or through an executor.

use alloy::primitives::{Address, FixedBytes, U256};

use broadcaster_core::contracts::railgun::ActionData;
use broadcaster_core::crypto::railgun::{AddressData, ViewingKeyData};
use broadcaster_core::utxo::Utxo;
use merkletree::tree::MerkleForest;

use crate::keys::{RailgunSpendSigner, WalletKeys};
use crate::notes::Note;
use crate::prover::ProverService;

use super::super::{
    BroadcasterFeeOutput, BuildError, CompositeAdapter, CompositeExecution, CompositePlanShape,
    CompositePrivateOutputRole, CompositePrivateOutputRoleKind, CompositeUnshieldLeg,
    CompositeUnshieldLegMetadata, CompositeUnshieldPlan, CompositeUnshieldPlannedOutput,
    CompositeUnshieldRequest, MAX_BATCH_TRANSACTIONS, TransactionBuilder, UnshieldRequest,
};
use super::batch::{BatchPlanner, ProvenBatch};
use super::outputs::{
    FeeOnlyOutputs, UnshieldOutputs, build_fee_only_outputs, build_unshield_outputs,
};
use super::plan::{SpendAllocation, TransactionProver, spend_allocations};
use super::rand_array;
use super::selection::{
    BatchUtxoSelection, UtxoSelection, remove_selected_utxos,
    select_batched_utxo_candidates_with_limit, select_batched_utxos_with_limit, select_fee_utxos,
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
        let routing = self.composite_routing(&request)?;
        let mut remaining_utxos = utxos.to_vec();
        let mut build = CompositeUnshieldBuild::new(
            BatchPlanner::new(self, viewing, signer, forest, routing.execution),
            &request,
        );

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
            build.push_separate_fee(fee, fee_selection)?;
        }

        let (leg_selections, embedded_fee_leg_index) = select_composite_leg_selections(
            &remaining_utxos,
            &request.legs,
            embedded_fee,
            request.spend_up_to,
            build.planner.unproven_plans.len(),
        )?;
        for leg_index in composite_build_leg_order(request.legs.len(), embedded_fee_leg_index) {
            let leg_fee = embedded_fee
                .and_then(|fee| (embedded_fee_leg_index == Some(leg_index)).then_some(fee));
            build.push_leg(leg_index, &leg_selections[leg_index], leg_fee)?;
        }

        let action_data = if routing.uses_relay_adapt {
            let actions = request
                .relay_actions
                .clone()
                .ok_or(BuildError::MissingCompositeRelayActions)?;
            let action_data = actions.action_data(
                routing.execution.account(),
                FixedBytes::<31>::from(rand_array()),
            )?;
            build.planner.bind_adapt_params(&action_data);
            Some(action_data)
        } else {
            None
        };

        build.finish(prover, routing, action_data).await
    }

    fn composite_routing(
        &self,
        request: &CompositeUnshieldRequest,
    ) -> Result<CompositeRouting, BuildError> {
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
        Ok(CompositeRouting {
            execution,
            relay_call_count,
            uses_relay_adapt,
        })
    }
}

/// Where a composite batch settles, and whether it needs relay actions.
#[derive(Clone, Copy)]
pub(super) struct CompositeRouting {
    pub(super) execution: CompositeExecution,
    pub(super) relay_call_count: usize,
    pub(super) uses_relay_adapt: bool,
}

/// A composite unshield plan's outputs and leg metadata, recorded as its
/// transactions are built.
struct CompositeUnshieldBuild<'a, S: RailgunSpendSigner> {
    planner: BatchPlanner<'a, S>,
    request: &'a CompositeUnshieldRequest,
    receiver: AddressData,
    broadcaster_fee_note: Option<Note>,
    unshield_outputs: Vec<CompositeUnshieldPlannedOutput>,
    private_output_roles: Vec<CompositePrivateOutputRole>,
    leg_metadata: Vec<CompositeUnshieldLegMetadata>,
}

impl<'a, S: RailgunSpendSigner> CompositeUnshieldBuild<'a, S> {
    fn new(planner: BatchPlanner<'a, S>, request: &'a CompositeUnshieldRequest) -> Self {
        let receiver = planner.viewing.address_data();
        let leg_metadata = request
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
        Self {
            planner,
            request,
            receiver,
            broadcaster_fee_note: None,
            unshield_outputs: Vec::new(),
            private_output_roles: Vec::new(),
            leg_metadata,
        }
    }

    /// Adds the fee-only transaction for a broadcaster fee in a token no leg spends.
    fn push_separate_fee(
        &mut self,
        fee: BroadcasterFeeOutput,
        fee_selection: UtxoSelection,
    ) -> Result<(), BuildError> {
        let fee_change = fee_selection.total - fee.amount;
        let fee_plan_builder = self
            .planner
            .plan_builder(fee_selection.utxos, fee.token_address)?;
        let FeeOnlyOutputs {
            outputs,
            commitment_ciphertext,
            broadcaster_fee_note: fee_note,
            change_note,
        } = build_fee_only_outputs(
            fee,
            fee_change,
            &self.receiver,
            &self.planner.viewing.viewing_private_key,
        )?;
        self.push_private_output_roles(
            0,
            Some(fee),
            change_note.is_some().then_some(fee.token_address),
        );
        self.broadcaster_fee_note = Some(fee_note);
        self.planner
            .unproven_plans
            .push(fee_plan_builder.build_unproven_fee_only(
                fee.token_address,
                self.request.min_gas_price,
                outputs,
                commitment_ciphertext,
                Some(&mut self.planner.input_witness_cache),
            )?);
        Ok(())
    }

    fn push_leg(
        &mut self,
        leg_index: usize,
        selection: &BatchUtxoSelection,
        leg_fee: Option<BroadcasterFeeOutput>,
    ) -> Result<(), BuildError> {
        let leg = self.request.legs[leg_index];
        let allocations = spend_allocations(
            selection,
            leg.amount,
            leg_fee.map_or(U256::ZERO, |fee| fee.amount),
            leg_fee,
            self.request.spend_up_to,
        )?;
        for (chunk, allocation) in selection.chunks.iter().cloned().zip(allocations) {
            self.push_leg_chunk(leg_index, chunk, allocation)?;
        }
        Ok(())
    }

    fn push_leg_chunk(
        &mut self,
        leg_index: usize,
        chunk: UtxoSelection,
        allocation: SpendAllocation,
    ) -> Result<(), BuildError> {
        let leg = self.request.legs[leg_index];
        let unshield_to = leg.recipient.unshield_to(self.planner.execution.account());
        let transaction_index = self.planner.unproven_plans.len();
        let plan_builder = self.planner.plan_builder(chunk.utxos, leg.token_address)?;
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
            &self.receiver,
            allocation.fee,
            &self.planner.viewing.viewing_private_key,
        )?;
        self.push_private_output_roles(
            transaction_index,
            allocation.fee,
            change_note.is_some().then_some(leg.token_address),
        );
        if let Some(note) = chunk_fee_note {
            self.broadcaster_fee_note.get_or_insert(note);
        }

        self.unshield_outputs.push(CompositeUnshieldPlannedOutput {
            leg_index,
            transaction_index,
            output_index,
            token_address: leg.token_address,
            amount: allocation.amount,
            recipient: leg.recipient,
            role: leg.role,
            note: unshield_note.clone(),
        });
        self.leg_metadata[leg_index]
            .transaction_indices
            .push(transaction_index);

        let unshield_request = UnshieldRequest {
            token_address: leg.token_address,
            amount: allocation.amount,
            recipient: unshield_to,
            verify_proof: self.request.verify_proof,
            spend_up_to: self.request.spend_up_to,
            broadcaster_fee: allocation.fee,
            min_gas_price: self.request.min_gas_price,
        };
        self.planner
            .unproven_plans
            .push(plan_builder.build_unproven_unshield(
                unshield_request,
                outputs,
                commitment_ciphertext,
                &unshield_note,
                Some(&mut self.planner.input_witness_cache),
            )?);
        Ok(())
    }

    /// Proves the batch and assembles the plan from the recorded outputs.
    async fn finish<P: TransactionProver>(
        self,
        prover: &P,
        routing: CompositeRouting,
        action_data: Option<ActionData>,
    ) -> Result<CompositeUnshieldPlan, BuildError> {
        let ProvenBatch {
            call,
            inputs,
            outputs,
            chunks,
        } = self
            .planner
            .prove(prover, self.request.verify_proof, action_data.as_ref())
            .await?;
        let shape = CompositePlanShape {
            execution: routing.execution,
            transaction_count: chunks.len(),
            input_count: inputs.len(),
            private_output_count: self.private_output_roles.len(),
            public_output_count: self.unshield_outputs.len(),
            relay_call_count: routing.relay_call_count,
            uses_relay_adapt: routing.uses_relay_adapt,
        };

        Ok(CompositeUnshieldPlan {
            call,
            inputs,
            outputs,
            chunks,
            broadcaster_fee_note: self.broadcaster_fee_note,
            unshield_outputs: self.unshield_outputs,
            leg_metadata: self.leg_metadata,
            private_output_roles: self.private_output_roles,
            action_data,
            shape,
        })
    }

    /// Records a transaction's broadcaster fee output (first, when present) and
    /// its change output (next, when present).
    fn push_private_output_roles(
        &mut self,
        chunk_index: usize,
        fee: Option<BroadcasterFeeOutput>,
        change_token: Option<Address>,
    ) {
        if let Some(fee) = fee {
            self.private_output_roles.push(CompositePrivateOutputRole {
                chunk_index,
                output_index: 0,
                role: CompositePrivateOutputRoleKind::BroadcasterFee,
                token_address: fee.token_address,
            });
        }
        if let Some(token_address) = change_token {
            self.private_output_roles.push(CompositePrivateOutputRole {
                chunk_index,
                output_index: usize::from(fee.is_some()),
                role: CompositePrivateOutputRoleKind::Change,
                token_address,
            });
        }
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
    let mut search = LegSelectionSearch {
        legs,
        embedded_fee,
        spend_up_to_by_leg,
        selections: Vec::with_capacity(legs.len()),
        embedded_fee_leg_index: None,
    };
    search.search(utxos, 0, used_transaction_count)?;
    Ok((search.selections, search.embedded_fee_leg_index))
}

/// Backtracking search for one batch selection per leg, with the embedded fee
/// carried by the first leg in its token that can fit it.
struct LegSelectionSearch<'a> {
    legs: &'a [CompositeUnshieldLeg],
    embedded_fee: Option<BroadcasterFeeOutput>,
    spend_up_to_by_leg: &'a [bool],
    selections: Vec<BatchUtxoSelection>,
    embedded_fee_leg_index: Option<usize>,
}

impl LegSelectionSearch<'_> {
    fn search(
        &mut self,
        utxos: &[Utxo],
        leg_index: usize,
        used_transaction_count: usize,
    ) -> Result<(), BuildError> {
        let Some(leg) = self.legs.get(leg_index).copied() else {
            return self.require_fee_placed();
        };
        let spend_up_to = self
            .spend_up_to_by_leg
            .get(leg_index)
            .copied()
            .unwrap_or(false);
        let remaining_slots = MAX_BATCH_TRANSACTIONS.saturating_sub(used_transaction_count);
        if remaining_slots == 0 {
            return Err(BuildError::TooManyBatchTransactions {
                requested: used_transaction_count + 1,
                max: MAX_BATCH_TRANSACTIONS,
            });
        }

        let mut last_error = None;
        let fee_options = leg_fee_options(leg, self.embedded_fee, self.embedded_fee_leg_index);
        for leg_fee in fee_options {
            let target = LegTarget {
                token_address: leg.token_address,
                first_base_output_count: 1 + usize::from(leg_fee.is_some()),
                target_amount: leg.amount + leg_fee.map_or(U256::ZERO, |fee| fee.amount),
                spend_up_to,
            };
            let candidates = match target.candidates(utxos, remaining_slots) {
                Ok(candidates) => candidates,
                Err(error) => {
                    let error = target
                        .batch_limit_error(utxos, remaining_slots, used_transaction_count)
                        .unwrap_or(error);
                    retain_preferred_selection_error(&mut last_error, error);
                    continue;
                }
            };

            for candidate in candidates {
                let remaining_utxos = utxos_without_selection(utxos, &candidate);
                let previous_fee_leg_index = self.embedded_fee_leg_index;
                if leg_fee.is_some() {
                    self.embedded_fee_leg_index = Some(leg_index);
                }
                self.selections.push(candidate.clone());
                match self.search(
                    &remaining_utxos,
                    leg_index + 1,
                    used_transaction_count + candidate.chunks.len(),
                ) {
                    Ok(()) => return Ok(()),
                    Err(error) => retain_preferred_selection_error(&mut last_error, error),
                }
                self.selections.pop();
                self.embedded_fee_leg_index = previous_fee_leg_index;
            }
        }

        Err(last_error.unwrap_or(BuildError::InsufficientBalance(U256::ZERO)))
    }

    /// Every leg has a selection; an embedded fee must have found a leg to carry it.
    const fn require_fee_placed(&self) -> Result<(), BuildError> {
        if self.embedded_fee.is_some() && self.embedded_fee_leg_index.is_none() {
            return Err(BuildError::InsufficientBalance(U256::ZERO));
        }
        Ok(())
    }
}

fn utxos_without_selection(utxos: &[Utxo], selection: &BatchUtxoSelection) -> Vec<Utxo> {
    let mut remaining_utxos = utxos.to_vec();
    for chunk in &selection.chunks {
        remove_selected_utxos(&mut remaining_utxos, &chunk.utxos);
    }
    remaining_utxos
}

/// What one leg must select: its amount plus any embedded fee it carries.
struct LegTarget {
    token_address: Address,
    first_base_output_count: usize,
    target_amount: U256,
    spend_up_to: bool,
}

impl LegTarget {
    fn candidates(
        &self,
        utxos: &[Utxo],
        max_transactions: usize,
    ) -> Result<Vec<BatchUtxoSelection>, BuildError> {
        select_batched_utxo_candidates_with_limit(
            utxos,
            self.token_address,
            self.target_amount,
            self.spend_up_to,
            self.first_base_output_count,
            1,
            max_transactions,
        )
    }

    /// When earlier legs used batch slots, reports `TooManyBatchTransactions` if
    /// this leg would fit a full batch but not the slots left.
    fn batch_limit_error(
        &self,
        utxos: &[Utxo],
        remaining_slots: usize,
        used_transaction_count: usize,
    ) -> Option<BuildError> {
        if remaining_slots >= MAX_BATCH_TRANSACTIONS {
            return None;
        }
        let required = select_batched_utxos_with_limit(
            utxos,
            self.token_address,
            self.target_amount,
            self.spend_up_to,
            self.first_base_output_count,
            1,
            MAX_BATCH_TRANSACTIONS,
        )
        .ok()?;
        (required.chunks.len() > remaining_slots).then(|| BuildError::TooManyBatchTransactions {
            requested: used_transaction_count + required.chunks.len(),
            max: MAX_BATCH_TRANSACTIONS,
        })
    }
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
    match embedded_fee
        .filter(|fee| embedded_fee_leg_index.is_none() && leg.token_address == fee.token_address)
    {
        Some(fee) => vec![Some(fee), None],
        None => vec![None],
    }
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
