//! The transactions of one batch: the shared input witness cache, the unproven
//! plans in build order, adapter binding, proving and the batch call.

use alloy::primitives::{Address, Bytes};
use alloy::sol_types::SolCall;

use broadcaster_core::contracts::railgun::{
    ActionData, RelayAdapt7702, RelayAdapt7702ActionData, Transaction, transactCall,
};
use broadcaster_core::crypto::railgun::ViewingKeyData;
use broadcaster_core::utxo::Utxo;
use merkletree::tree::MerkleForest;

use crate::keys::RailgunSpendSigner;
use crate::notes::Note;

use super::super::{
    BuildError, CompositeExecution, InputWitness, TransactionBuilder, TransactionCall,
    TransactionPlanChunk, UNRELAYED_ADAPT_PARAMS,
};
use super::plan::{
    InputWitnessProofCache, TransactionPlanBuilder, TransactionProver, UnprovenTransactionPlan,
    prove_transaction_plans,
};

/// The transactions of one batch in build order, sharing an input witness cache
/// and an execution target.
pub(super) struct BatchPlanner<'a, S: RailgunSpendSigner> {
    builder: &'a TransactionBuilder,
    pub(super) viewing: &'a ViewingKeyData,
    signer: &'a S,
    forest: &'a MerkleForest,
    pub(super) execution: CompositeExecution,
    pub(super) input_witness_cache: InputWitnessProofCache<'a>,
    pub(super) unproven_plans: Vec<UnprovenTransactionPlan>,
}

pub(super) struct ProvenBatch {
    pub(super) call: TransactionCall,
    pub(super) inputs: Vec<InputWitness>,
    pub(super) outputs: Vec<Note>,
    pub(super) chunks: Vec<TransactionPlanChunk>,
}

impl<'a, S: RailgunSpendSigner> BatchPlanner<'a, S> {
    pub(super) fn new(
        builder: &'a TransactionBuilder,
        viewing: &'a ViewingKeyData,
        signer: &'a S,
        forest: &'a MerkleForest,
        execution: CompositeExecution,
    ) -> Self {
        Self {
            builder,
            viewing,
            signer,
            forest,
            execution,
            input_witness_cache: InputWitnessProofCache::new(forest),
            unproven_plans: Vec::new(),
        }
    }

    pub(super) fn plan_builder(
        &self,
        utxos: Vec<Utxo>,
        token_address: Address,
    ) -> Result<TransactionPlanBuilder<'a, S>, BuildError> {
        TransactionPlanBuilder::new(
            self.builder,
            self.viewing,
            self.signer,
            self.forest,
            utxos,
            token_address,
        )
    }

    /// Points every transaction at the executor. The executor signature binds the
    /// action, so adapt params stay unrelayed.
    pub(super) fn bind_adapt_params(&mut self, action_data: &ActionData) {
        debug_assert!(action_data.requireSuccess);
        for plan in &mut self.unproven_plans {
            plan.transaction.boundParams.adaptContract = self.execution.account();
            plan.transaction.boundParams.adaptParams = UNRELAYED_ADAPT_PARAMS;
        }
    }

    /// Proves every planned transaction, returning the transactions and their
    /// chunks in build order. The witness cache stays with the planner.
    pub(super) async fn prove_and_split<P: TransactionProver>(
        &mut self,
        prover: &P,
        verify_proof: bool,
    ) -> Result<(Vec<Transaction>, Vec<TransactionPlanChunk>), BuildError> {
        let proven_plans = prove_transaction_plans(
            std::mem::take(&mut self.unproven_plans),
            self.signer,
            prover,
            verify_proof,
        )
        .await?;
        let mut transactions = Vec::with_capacity(proven_plans.len());
        let mut chunks = Vec::with_capacity(proven_plans.len());
        for proven in proven_plans {
            transactions.push(proven.transaction);
            chunks.push(proven.chunk);
        }
        Ok((transactions, chunks))
    }

    /// Proves every transaction, then encodes the batch call for the execution target.
    pub(super) async fn prove<P: TransactionProver>(
        mut self,
        prover: &P,
        verify_proof: bool,
        action_data: Option<&ActionData>,
    ) -> Result<ProvenBatch, BuildError> {
        let (transactions, chunks) = self.prove_and_split(prover, verify_proof).await?;
        let call = composite_call(self.execution, transactions, action_data)?;
        let inputs = chunks
            .iter()
            .flat_map(|chunk| chunk.inputs.clone())
            .collect::<Vec<_>>();
        let outputs = chunks
            .iter()
            .flat_map(|chunk| chunk.outputs.clone())
            .collect::<Vec<_>>();
        Ok(ProvenBatch {
            call,
            inputs,
            outputs,
            chunks,
        })
    }
}

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
