use std::time::Instant;

use alloy::primitives::{Address, U256};
use alloy::sol_types::SolCall;
use rand::Rng;

use broadcaster_core::contracts::railgun::{Transaction, transactCall};
use broadcaster_core::crypto::railgun::{AddressData, ViewingKeyData};
use broadcaster_core::utxo::Utxo;
use merkletree::tree::MerkleForest;

use crate::keys::{RailgunSpendSigner, WalletKeys};
use crate::notes::Note;
use crate::prover::ProverService;

use super::{
    BroadcasterFeeOutput, BuildError, CompositeExecution, MAX_BATCH_TRANSACTIONS, SendPlan,
    SendRequest, TransactPlan, TransactionBuilder, TransactionCall, TransactionPlanChunk,
    UnshieldPlan, UnshieldRequest,
};

use batch::BatchPlanner;
use outputs::{
    FeeOnlyOutputs, SendOutputs, UnshieldOutputs, build_fee_only_outputs, build_send_outputs,
    build_unshield_outputs,
};
use plan::{
    InputWitnessProofCache, SpendAllocation, TransactionPlanBuilder, TransactionProver,
    prove_transaction_plans, spend_allocations,
};
use selection::{
    BatchUtxoSelection, UtxoSelection, select_batched_utxos, select_batched_utxos_with_limit,
    select_fee_utxos,
};

mod batch;
mod composite;
mod mixed;
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

impl TransactionBuilder {
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
        self.build_unshield_plan_inner(viewing, signer, forest, utxos, request, prover)
            .await
    }

    async fn build_unshield_plan_inner<P: TransactionProver>(
        &self,
        viewing: &ViewingKeyData,
        signer: &impl RailgunSpendSigner,
        forest: &MerkleForest,
        utxos: &[Utxo],
        request: UnshieldRequest,
        prover: &P,
    ) -> Result<UnshieldPlan, BuildError> {
        let separate_fee = SeparateFee::select(utxos, request.different_token_broadcaster_fee())?;
        let selection = select_batched_utxos_with_limit(
            utxos,
            request.token_address,
            request.target_amount(),
            request.spend_up_to,
            request.base_output_count(),
            1,
            SeparateFee::action_transaction_limit(separate_fee.as_ref()),
        )?;
        let mut batch = PaymentBatch::new(
            BatchPlanner::new(
                self,
                viewing,
                signer,
                forest,
                CompositeExecution::Direct(self.railgun_contract),
            ),
            viewing.address_data(),
            selection.chunks.len() + usize::from(separate_fee.is_some()),
            selection.chunks.len(),
        );
        if let Some(separate_fee) = separate_fee {
            batch.push_separate_fee(separate_fee, request.min_gas_price)?;
        }

        let allocations = spend_allocations(
            &selection,
            request.amount,
            request.fee_amount(),
            request.same_token_broadcaster_fee(),
            request.spend_up_to,
        )?;
        for (chunk, allocation) in selection.chunks.into_iter().zip(allocations) {
            batch.push_unshield_chunk(request, chunk, allocation)?;
        }

        let (transactions, chunks) = batch
            .planner
            .prove_and_split(prover, request.verify_proof)
            .await?;
        Ok(batch.into_unshield_plan(self.railgun_contract, transactions, chunks))
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
        self.build_send_plan_inner(viewing, signer, forest, utxos, &request, prover)
            .await
    }

    async fn build_send_plan_inner<P: TransactionProver>(
        &self,
        viewing: &ViewingKeyData,
        signer: &impl RailgunSpendSigner,
        forest: &MerkleForest,
        utxos: &[Utxo],
        request: &SendRequest,
        prover: &P,
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

        self.build_send_batch_with_signer(viewing, signer, forest, selection, request, prover)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn build_send_batch_with_separate_fee_token<P: TransactionProver>(
        &self,
        viewing: &ViewingKeyData,
        signer: &impl RailgunSpendSigner,
        forest: &MerkleForest,
        fee_selection: UtxoSelection,
        action_selection: BatchUtxoSelection,
        request: &SendRequest,
        fee: BroadcasterFeeOutput,
        prover: &P,
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

    async fn build_send_batch_with_signer<P: TransactionProver>(
        &self,
        viewing: &ViewingKeyData,
        signer: &impl RailgunSpendSigner,
        forest: &MerkleForest,
        selection: BatchUtxoSelection,
        request: &SendRequest,
        prover: &P,
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

/// The inputs of the fee-only transaction that pays a broadcaster fee in a
/// token other than the payment's. It runs first in the batch.
struct SeparateFee {
    selection: UtxoSelection,
    fee: BroadcasterFeeOutput,
}

impl SeparateFee {
    fn select(
        utxos: &[Utxo],
        different_token_fee: Option<BroadcasterFeeOutput>,
    ) -> Result<Option<Self>, BuildError> {
        different_token_fee
            .map(|fee| {
                select_fee_utxos(utxos, fee.token_address, fee.amount)
                    .map(|selection| Self { selection, fee })
            })
            .transpose()
    }

    /// The payment's own transactions give up one batch slot to the fee-only one.
    fn action_transaction_limit(separate_fee: Option<&Self>) -> usize {
        MAX_BATCH_TRANSACTIONS - usize::from(separate_fee.is_some())
    }
}

/// A plain send or unshield batch, with the notes its plan reports: the first
/// broadcaster fee note, the last change note and every payment note.
struct PaymentBatch<'a, S: RailgunSpendSigner> {
    planner: BatchPlanner<'a, S>,
    wallet_address: AddressData,
    broadcaster_fee_note: Option<Note>,
    change_note: Option<Note>,
    payment_notes: Vec<Note>,
}

impl<'a, S: RailgunSpendSigner> PaymentBatch<'a, S> {
    fn new(
        mut planner: BatchPlanner<'a, S>,
        wallet_address: AddressData,
        transaction_count: usize,
        payment_count: usize,
    ) -> Self {
        planner.unproven_plans.reserve_exact(transaction_count);
        Self {
            planner,
            wallet_address,
            broadcaster_fee_note: None,
            change_note: None,
            payment_notes: Vec::with_capacity(payment_count),
        }
    }

    /// Adds the fee-only transaction. It must come before the payment chunks.
    fn push_separate_fee(
        &mut self,
        separate_fee: SeparateFee,
        min_gas_price: u128,
    ) -> Result<(), BuildError> {
        let SeparateFee { selection, fee } = separate_fee;
        let fee_change = selection.total - fee.amount;
        let fee_plan_builder = self
            .planner
            .plan_builder(selection.utxos, fee.token_address)?;
        let FeeOnlyOutputs {
            outputs,
            commitment_ciphertext,
            broadcaster_fee_note,
            change_note,
        } = build_fee_only_outputs(
            fee,
            fee_change,
            &self.wallet_address,
            &self.planner.viewing.viewing_private_key,
        )?;
        let fee_unproven_plan = fee_plan_builder.build_unproven_fee_only(
            fee.token_address,
            min_gas_price,
            outputs,
            commitment_ciphertext,
            Some(&mut self.planner.input_witness_cache),
        )?;
        self.planner.unproven_plans.push(fee_unproven_plan);
        self.broadcaster_fee_note = Some(broadcaster_fee_note);
        self.change_note = change_note;
        Ok(())
    }

    fn push_unshield_chunk(
        &mut self,
        request: UnshieldRequest,
        chunk: UtxoSelection,
        allocation: SpendAllocation,
    ) -> Result<(), BuildError> {
        let plan_builder = self
            .planner
            .plan_builder(chunk.utxos, request.token_address)?;
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
            &self.wallet_address,
            allocation.fee,
            &self.planner.viewing.viewing_private_key,
        )?;
        self.record_chunk_notes(chunk_fee_note, chunk_change_note);
        self.payment_notes.push(unshield_note);
        self.planner
            .unproven_plans
            .push(plan_builder.build_unproven_unshield(
                request,
                outputs,
                commitment_ciphertext,
                self.payment_notes.last().expect("pushed unshield note"),
                Some(&mut self.planner.input_witness_cache),
            )?);
        Ok(())
    }

    /// Keeps the first chunk's broadcaster fee note and the last chunk's change note.
    const fn record_chunk_notes(&mut self, fee_note: Option<Note>, change_note: Option<Note>) {
        if self.broadcaster_fee_note.is_none() {
            self.broadcaster_fee_note = fee_note;
        }
        if change_note.is_some() {
            self.change_note = change_note;
        }
    }

    fn into_unshield_plan(
        self,
        railgun_contract: Address,
        transactions: Vec<Transaction>,
        chunks: Vec<TransactionPlanChunk>,
    ) -> UnshieldPlan {
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
        let unshield_note = self
            .payment_notes
            .first()
            .expect("selection has at least one chunk")
            .clone();

        let data = transactCall {
            _transactions: transactions,
        }
        .abi_encode();
        let call = TransactionCall {
            to: railgun_contract,
            data: data.into(),
        };

        UnshieldPlan {
            call,
            tree_number: first_chunk.tree_number,
            merkle_root: first_chunk.merkle_root,
            inputs,
            outputs,
            chunks,
            broadcaster_fee_note: self.broadcaster_fee_note,
            unshield_note,
            unshield_notes: self.payment_notes,
            change_note: self.change_note,
            public_inputs: first_chunk.public_inputs,
            private_inputs: first_chunk.private_inputs,
            signature: first_chunk.signature,
        }
    }
}

fn rand_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::rng().fill_bytes(&mut out);
    out
}

#[cfg(test)]
mod tests;
