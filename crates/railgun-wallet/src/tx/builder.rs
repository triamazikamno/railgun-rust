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
    BroadcasterFeeOutput, BuildError, CompositeExecution, InputWitness, MAX_BATCH_TRANSACTIONS,
    SendPlan, SendRequest, TransactPlan, TransactionBuilder, TransactionCall, TransactionPlanChunk,
    UnshieldPlan, UnshieldRequest,
};

use batch::BatchPlanner;
use outputs::{
    FeeOnlyOutputs, SendOutputs, UnshieldOutputs, build_fee_only_outputs, build_send_outputs,
    build_unshield_outputs,
};
use plan::{
    InputWitnessProofCacheStats, SpendAllocation, TransactionPlanBuilder, TransactionProver,
    spend_allocations,
};
use selection::{
    BatchUtxoSelection, UtxoSelection, select_batched_utxos_with_limit, select_fee_utxos,
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
            let fee_change = separate_fee.change();
            batch.push_separate_fee(separate_fee, fee_change, request.min_gas_price)?;
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
        Ok(batch.into_unshield_plan(transactions, chunks))
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
        let mut timings = SendStageTimings::start(separate_fee.is_some());
        let planner = BatchPlanner::new(
            self,
            viewing,
            signer,
            forest,
            CompositeExecution::Direct(self.railgun_contract),
        );
        let (mut batch, allocations) =
            PaymentBatch::open_send(planner, separate_fee, &selection, request, &mut timings)?;
        for (chunk, allocation) in selection.chunks.into_iter().zip(allocations) {
            let elapsed = batch.push_send_chunk(request, chunk, allocation)?;
            timings.outputs_ms += elapsed.outputs_ms;
            timings.unproven_ms += elapsed.unproven_ms;
        }

        let prove_started = Instant::now();
        let (transactions, chunks) = batch
            .planner
            .prove_and_split(prover, request.verify_proof)
            .await?;
        timings.prove_ms = prove_started.elapsed().as_millis();
        Ok(batch.into_send_plan(transactions, chunks, timings))
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

    fn change(&self) -> U256 {
        self.selection.total - self.fee.amount
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
        fee_change: U256,
        min_gas_price: u128,
    ) -> Result<StageElapsed, BuildError> {
        let SeparateFee { selection, fee } = separate_fee;
        let fee_plan_builder = self
            .planner
            .plan_builder(selection.utxos, fee.token_address)?;
        let outputs_started = Instant::now();
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
        let outputs_ms = outputs_started.elapsed().as_millis();
        let unproven_started = Instant::now();
        let fee_unproven_plan = fee_plan_builder.build_unproven_fee_only(
            fee.token_address,
            min_gas_price,
            outputs,
            commitment_ciphertext,
            Some(&mut self.planner.input_witness_cache),
        )?;
        let unproven_ms = unproven_started.elapsed().as_millis();
        self.planner.unproven_plans.push(fee_unproven_plan);
        self.broadcaster_fee_note = Some(broadcaster_fee_note);
        self.change_note = change_note;
        Ok(StageElapsed {
            outputs_ms,
            unproven_ms,
        })
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

    fn first_payment_note(&self) -> Note {
        self.payment_notes
            .first()
            .expect("selection has at least one chunk")
            .clone()
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
        transactions: Vec<Transaction>,
        chunks: Vec<TransactionPlanChunk>,
    ) -> UnshieldPlan {
        let (first_chunk, inputs, outputs) = first_chunk_and_flattened(&chunks);
        let unshield_note = self.first_payment_note();

        let data = transactCall {
            _transactions: transactions,
        }
        .abi_encode();
        let call = TransactionCall {
            to: self.planner.execution.account(),
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

    /// Starts a send batch and allocates the payment. With a separate fee, the
    /// fee-only transaction comes before the allocations; otherwise the wallet
    /// address is derived after them. Each path's timings follow that order.
    fn open_send(
        planner: BatchPlanner<'a, S>,
        separate_fee: Option<SeparateFee>,
        selection: &BatchUtxoSelection,
        request: &SendRequest,
        timings: &mut SendStageTimings,
    ) -> Result<(Self, Vec<SpendAllocation>), BuildError> {
        let transaction_count = selection.chunks.len() + usize::from(separate_fee.is_some());
        let payment_count = selection.chunks.len();
        let allocate = |timings: &mut SendStageTimings| {
            let allocations_started = Instant::now();
            let allocations = spend_allocations(
                selection,
                request.amount,
                request.fee_amount(),
                request.same_token_broadcaster_fee(),
                request.spend_up_to,
            )?;
            timings.allocations_ms = allocations_started.elapsed().as_millis();
            Ok::<_, BuildError>(allocations)
        };

        let Some(separate_fee) = separate_fee else {
            let allocations = allocate(timings)?;
            let wallet_address = planner.viewing.address_data();
            let batch = Self::new(planner, wallet_address, transaction_count, payment_count);
            return Ok((batch, allocations));
        };
        let setup_started = Instant::now();
        let wallet_address = planner.viewing.address_data();
        let fee_change = separate_fee.change();
        timings.setup_ms = setup_started.elapsed().as_millis();
        let mut batch = Self::new(planner, wallet_address, transaction_count, payment_count);
        let fee_elapsed =
            batch.push_separate_fee(separate_fee, fee_change, request.min_gas_price)?;
        timings.fee_outputs_ms = fee_elapsed.outputs_ms;
        timings.fee_unproven_ms = fee_elapsed.unproven_ms;
        let allocations = allocate(timings)?;
        Ok((batch, allocations))
    }

    fn push_send_chunk(
        &mut self,
        request: &SendRequest,
        chunk: UtxoSelection,
        allocation: SpendAllocation,
    ) -> Result<StageElapsed, BuildError> {
        let plan_builder = self
            .planner
            .plan_builder(chunk.utxos, request.token_address)?;
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
            &self.wallet_address,
            &request.recipient,
            allocation.fee,
            &self.planner.viewing.viewing_private_key,
        )?;
        let outputs_ms = outputs_started.elapsed().as_millis();
        self.record_chunk_notes(chunk_fee_note, chunk_change_note);
        self.payment_notes.push(recipient_note);
        let unproven_started = Instant::now();
        self.planner
            .unproven_plans
            .push(plan_builder.build_unproven_send(
                request,
                outputs,
                commitment_ciphertext,
                Some(&mut self.planner.input_witness_cache),
            )?);
        Ok(StageElapsed {
            outputs_ms,
            unproven_ms: unproven_started.elapsed().as_millis(),
        })
    }

    /// Encodes the batch call, logs the batch's timings while the witness cache
    /// is still alive, then assembles the plan.
    fn into_send_plan(
        self,
        transactions: Vec<Transaction>,
        chunks: Vec<TransactionPlanChunk>,
        mut timings: SendStageTimings,
    ) -> SendPlan {
        let (first_chunk, inputs, outputs) = first_chunk_and_flattened(&chunks);
        let recipient_note = self.first_payment_note();

        let abi_started = Instant::now();
        let data = transactCall {
            _transactions: transactions,
        }
        .abi_encode();
        timings.abi_ms = abi_started.elapsed().as_millis();
        let call = TransactionCall {
            to: self.planner.execution.account(),
            data: data.into(),
        };
        timings.log(chunks.len(), self.planner.input_witness_cache.stats());

        SendPlan {
            call,
            tree_number: first_chunk.tree_number,
            merkle_root: first_chunk.merkle_root,
            inputs,
            outputs,
            chunks,
            broadcaster_fee_note: self.broadcaster_fee_note,
            recipient_note,
            recipient_notes: self.payment_notes,
            change_note: self.change_note,
            public_inputs: first_chunk.public_inputs,
            private_inputs: first_chunk.private_inputs,
            signature: first_chunk.signature,
        }
    }
}

/// A plain plan's first chunk, which supplies its single-transaction fields, and
/// every chunk's inputs and outputs in order.
fn first_chunk_and_flattened(
    chunks: &[TransactionPlanChunk],
) -> (TransactionPlanChunk, Vec<InputWitness>, Vec<Note>) {
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
    (first_chunk, inputs, outputs)
}

/// Time spent building one transaction's outputs and its unproven plan.
struct StageElapsed {
    outputs_ms: u128,
    unproven_ms: u128,
}

/// Elapsed milliseconds of each send batch stage, for the batch's debug event.
struct SendStageTimings {
    started: Instant,
    separate_fee: bool,
    setup_ms: u128,
    fee_outputs_ms: u128,
    fee_unproven_ms: u128,
    allocations_ms: u128,
    outputs_ms: u128,
    unproven_ms: u128,
    prove_ms: u128,
    abi_ms: u128,
}

impl SendStageTimings {
    fn start(separate_fee: bool) -> Self {
        Self {
            started: Instant::now(),
            separate_fee,
            setup_ms: 0,
            fee_outputs_ms: 0,
            fee_unproven_ms: 0,
            allocations_ms: 0,
            outputs_ms: 0,
            unproven_ms: 0,
            prove_ms: 0,
            abi_ms: 0,
        }
    }

    fn log(&self, transaction_count: usize, witness_stats: InputWitnessProofCacheStats) {
        if self.separate_fee {
            tracing::debug!(
                transaction_count,
                setup_elapsed_ms = self.setup_ms,
                fee_outputs_elapsed_ms = self.fee_outputs_ms,
                fee_unproven_elapsed_ms = self.fee_unproven_ms,
                allocations_elapsed_ms = self.allocations_ms,
                action_outputs_elapsed_ms = self.outputs_ms,
                action_unproven_elapsed_ms = self.unproven_ms,
                prove_elapsed_ms = self.prove_ms,
                abi_elapsed_ms = self.abi_ms,
                input_witness_proofs = witness_stats.proof_count,
                input_witness_dense_tree_builds = witness_stats.dense_tree_build_count,
                input_witness_dense_tree_build_elapsed_ms =
                    witness_stats.dense_tree_build_elapsed_ms,
                elapsed_ms = self.started.elapsed().as_millis(),
                "built separate-fee send batch"
            );
        } else {
            tracing::debug!(
                transaction_count,
                allocations_elapsed_ms = self.allocations_ms,
                outputs_elapsed_ms = self.outputs_ms,
                unproven_elapsed_ms = self.unproven_ms,
                prove_elapsed_ms = self.prove_ms,
                abi_elapsed_ms = self.abi_ms,
                input_witness_proofs = witness_stats.proof_count,
                input_witness_dense_tree_builds = witness_stats.dense_tree_build_count,
                input_witness_dense_tree_build_elapsed_ms =
                    witness_stats.dense_tree_build_elapsed_ms,
                elapsed_ms = self.started.elapsed().as_millis(),
                "built send batch"
            );
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
