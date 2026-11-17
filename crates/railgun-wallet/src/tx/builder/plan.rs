//! Transaction plan construction and proving: input witnesses, nullifiers and
//! commitments, the unproven plan of each transaction, and the batch proving
//! pipeline.

use std::collections::BTreeMap;
use std::time::Instant;

use alloy::primitives::{Address, FixedBytes, U256, Uint};
use alloy::sol_types::SolCall;
use async_trait::async_trait;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

use broadcaster_core::contracts::railgun::{
    BoundParams, CommitmentCiphertext, CommitmentPreimage, SnarkProof, Transaction, transactCall,
};
use broadcaster_core::crypto::railgun::ViewingKeyData;
use broadcaster_core::tree::{TREE_LEAF_COUNT, normalize_tree_position};
use broadcaster_core::utxo::Utxo;
use merkletree::tree::{DenseMerkleTree, MerkleForest, MerkleProof};

use crate::keys::RailgunSpendSigner;
use crate::notes::{Note, NoteCiphertext};
use crate::prover::{ProverError, ProverService};

use super::super::{
    BroadcasterFeeOutput, BuildError, InputWitness, MAX_CIRCUIT_INPUTS, MAX_SIGNATURE_INPUTS,
    PrivateInputs, PublicInputs, SendRequest, TransactPlan, TransactionBuilder, TransactionCall,
    TransactionPlanChunk, UNRELAYED_ADAPT_PARAMS, UnshieldRequest,
};
use super::rand_array;
use super::selection::BatchUtxoSelection;

/// Builder for constructing Railgun transaction plans.
pub(super) struct TransactionPlanBuilder<'a, S: RailgunSpendSigner> {
    builder: &'a TransactionBuilder,
    viewing: &'a ViewingKeyData,
    signer: &'a S,
    forest: &'a MerkleForest,
    inputs: Vec<Utxo>,
    token_address: Address,
}

#[derive(Debug, Default, Clone, Copy)]
pub(super) struct InputWitnessProofCacheStats {
    pub(super) proof_count: usize,
    pub(super) dense_tree_build_count: usize,
    pub(super) dense_tree_build_elapsed_ms: u128,
}

pub(super) struct InputWitnessProofCache<'a> {
    forest: &'a MerkleForest,
    dense_trees: BTreeMap<u32, DenseMerkleTree>,
    stats: InputWitnessProofCacheStats,
}

const SPARSE_WITNESS_PROOF_MAX_LEAVES: usize = 64;

impl<'a> InputWitnessProofCache<'a> {
    pub(super) fn new(forest: &'a MerkleForest) -> Self {
        Self {
            forest,
            dense_trees: BTreeMap::new(),
            stats: InputWitnessProofCacheStats::default(),
        }
    }

    pub(super) fn prove(
        &mut self,
        tree_number: u32,
        tree_position: u64,
    ) -> Result<MerkleProof, BuildError> {
        let (normalized_tree, normalized_position) =
            normalize_tree_position(tree_number, tree_position);
        if !self.forest.contains_tree(normalized_tree) {
            return Err(BuildError::MissingProof {
                tree: tree_number,
                position: tree_position,
            });
        }

        if self.forest.leaf_count() <= SPARSE_WITNESS_PROOF_MAX_LEAVES {
            self.stats.proof_count += 1;
            return self
                .forest
                .prove(normalized_tree, normalized_position)
                .ok_or(BuildError::MissingProof {
                    tree: tree_number,
                    position: tree_position,
                });
        }

        if !self.dense_trees.contains_key(&normalized_tree) {
            let build_started = Instant::now();
            let dense_tree =
                DenseMerkleTree::from_forest_prefix(self.forest, normalized_tree, TREE_LEAF_COUNT);
            self.stats.dense_tree_build_elapsed_ms += build_started.elapsed().as_millis();
            self.stats.dense_tree_build_count += 1;
            self.dense_trees.insert(normalized_tree, dense_tree);
        }
        self.stats.proof_count += 1;
        Ok(self
            .dense_trees
            .get(&normalized_tree)
            .expect("dense tree inserted")
            .prove(normalized_position))
    }

    pub(super) const fn stats(&self) -> InputWitnessProofCacheStats {
        self.stats
    }
}

pub(super) struct UnprovenTransactionPlan {
    pub(super) transaction: Transaction,
    tree_number: u32,
    pub(super) merkle_root: U256,
    pub(super) inputs: Vec<InputWitness>,
    pub(super) outputs: Vec<Note>,
    pub(super) has_unshield: bool,
    private_inputs: PrivateInputs,
}

struct PreparedTransactionPlan {
    plan: UnprovenTransactionPlan,
    public_inputs: PublicInputs,
    signature: [U256; 3],
    started: Instant,
    public_inputs_elapsed_ms: u128,
    signature_elapsed_ms: u128,
}

pub(super) struct ProvenTransactionPlan {
    pub(super) transaction: Transaction,
    pub(super) chunk: TransactionPlanChunk,
}

#[async_trait]
pub(super) trait TransactionProver: Clone + Send + Sync + 'static {
    async fn prove_unshield(
        &self,
        public_inputs: &PublicInputs,
        private_inputs: &PrivateInputs,
        signature: &[U256; 3],
        verify_proof: bool,
    ) -> Result<SnarkProof, ProverError>;
}

#[async_trait]
impl TransactionProver for ProverService {
    async fn prove_unshield(
        &self,
        public_inputs: &PublicInputs,
        private_inputs: &PrivateInputs,
        signature: &[U256; 3],
        verify_proof: bool,
    ) -> Result<SnarkProof, ProverError> {
        Self::prove_unshield(self, public_inputs, private_inputs, signature, verify_proof).await
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct SpendAllocation {
    pub(super) amount: U256,
    pub(super) change: U256,
    pub(super) fee: Option<BroadcasterFeeOutput>,
}

impl<'a, S: RailgunSpendSigner> TransactionPlanBuilder<'a, S> {
    /// Create a new builder with validated inputs.
    pub(super) fn new(
        builder: &'a TransactionBuilder,
        viewing: &'a ViewingKeyData,
        signer: &'a S,
        forest: &'a MerkleForest,
        inputs: Vec<Utxo>,
        token_address: Address,
    ) -> Result<Self, BuildError> {
        if inputs.is_empty() {
            return Err(BuildError::InsufficientBalance(U256::ZERO));
        }
        if inputs.len() > MAX_CIRCUIT_INPUTS {
            return Err(BuildError::TooManyInputs);
        }

        let tree_number = inputs[0].tree;
        if inputs.iter().any(|utxo| utxo.tree != tree_number) {
            return Err(BuildError::MixedTrees);
        }

        let token_hash = U256::from_be_slice(token_address.as_slice());
        if inputs.iter().any(|utxo| utxo.note.token_hash != token_hash) {
            return Err(BuildError::TokenMismatch);
        }

        Ok(Self {
            builder,
            viewing,
            signer,
            forest,
            inputs,
            token_address,
        })
    }

    #[must_use]
    fn tree_number(&self) -> u32 {
        self.inputs[0].tree
    }

    /// Get the total value of all inputs.
    #[must_use]
    fn total_value(&self) -> U256 {
        self.inputs
            .iter()
            .fold(U256::ZERO, |sum, utxo| sum + utxo.note.value)
    }

    /// Compute nullifiers for all inputs.
    fn compute_nullifiers(&self) -> Vec<FixedBytes<32>> {
        self.inputs
            .iter()
            .map(|utxo| {
                FixedBytes::from(
                    utxo.nullifier(self.viewing.nullifying_key)
                        .to_be_bytes::<32>(),
                )
            })
            .collect()
    }

    /// Build input witnesses with merkle proofs.
    fn build_input_witnesses(
        &self,
        proof_cache: Option<&mut InputWitnessProofCache<'_>>,
    ) -> Result<Vec<InputWitness>, BuildError> {
        if let Some(proof_cache) = proof_cache {
            return self
                .inputs
                .iter()
                .map(|utxo| {
                    proof_cache
                        .prove(utxo.tree, utxo.position)
                        .map(|proof| InputWitness {
                            utxo: utxo.clone(),
                            merkle_proof: proof,
                        })
                })
                .collect();
        }

        self.inputs
            .par_iter()
            .map(|utxo| {
                self.forest
                    .prove(utxo.tree, utxo.position)
                    .ok_or(BuildError::MissingProof {
                        tree: utxo.tree,
                        position: utxo.position,
                    })
                    .map(|proof| InputWitness {
                        utxo: utxo.clone(),
                        merkle_proof: proof,
                    })
            })
            .collect()
    }

    /// Build witnesses and derive the public root from their proofs.
    fn build_input_witnesses_and_root(
        &self,
        proof_cache: Option<&mut InputWitnessProofCache<'_>>,
    ) -> Result<(Vec<InputWitness>, U256), BuildError> {
        let inputs = self.build_input_witnesses(proof_cache)?;
        let root = inputs
            .first()
            .map(|input| input.merkle_proof.root)
            .ok_or(BuildError::MissingRoot)?;
        Ok((inputs, root))
    }

    /// Validate that the total signature inputs don't exceed the limit.
    const fn validate_signature_limit(&self, num_outputs: usize) -> Result<(), BuildError> {
        let signature_input_len = 2 + self.inputs.len() + num_outputs;
        if signature_input_len > MAX_SIGNATURE_INPUTS {
            return Err(BuildError::SignatureInputLimit {
                inputs: self.inputs.len(),
                outputs: num_outputs,
            });
        }
        Ok(())
    }

    /// Compute output commitments as fixed bytes.
    fn compute_commitments(outputs: &[Note]) -> Vec<FixedBytes<32>> {
        outputs
            .iter()
            .map(|note| FixedBytes::from(note.commitment().to_be_bytes::<32>()))
            .collect()
    }

    pub(super) fn build_unproven_unshield(
        self,
        request: UnshieldRequest,
        outputs: Vec<Note>,
        commitment_ciphertext: Vec<NoteCiphertext>,
        unshield_note: &Note,
        proof_cache: Option<&mut InputWitnessProofCache<'_>>,
    ) -> Result<UnprovenTransactionPlan, BuildError> {
        self.validate_signature_limit(outputs.len())?;

        let tree_number = self.tree_number();
        let (inputs, root) = self.build_input_witnesses_and_root(proof_cache)?;
        let nullifiers = self.compute_nullifiers();
        let commitments = Self::compute_commitments(&outputs);
        let commitment_ciphertext = commitment_ciphertext
            .into_iter()
            .map(CommitmentCiphertext::from)
            .collect();
        let bound_params = BoundParams::new_unshield(
            tree_number,
            self.builder.chain_type,
            self.builder.chain_id,
            commitment_ciphertext,
            Address::ZERO,
            UNRELAYED_ADAPT_PARAMS,
        )
        .with_min_gas_price(request.min_gas_price)?;

        let transaction = Transaction {
            proof: SnarkProof::default(),
            merkleRoot: FixedBytes::from(root.to_be_bytes::<32>()),
            nullifiers,
            commitments,
            boundParams: bound_params,
            unshieldPreimage: CommitmentPreimage::new_unshield(
                unshield_note,
                request.token_address,
            ),
        };
        let private_inputs = PrivateInputs::from_inputs(
            request.token_address,
            &inputs,
            &outputs,
            self.viewing,
            self.signer,
        );

        Ok(UnprovenTransactionPlan {
            transaction,
            tree_number,
            merkle_root: root,
            inputs,
            outputs,
            has_unshield: true,
            private_inputs,
        })
    }

    pub(super) fn build_unproven_send(
        self,
        request: &SendRequest,
        outputs: Vec<Note>,
        commitment_ciphertext: Vec<NoteCiphertext>,
        proof_cache: Option<&mut InputWitnessProofCache<'_>>,
    ) -> Result<UnprovenTransactionPlan, BuildError> {
        self.validate_signature_limit(outputs.len())?;

        let tree_number = self.tree_number();
        let (inputs, root) = self.build_input_witnesses_and_root(proof_cache)?;
        let nullifiers = self.compute_nullifiers();
        let commitments = Self::compute_commitments(&outputs);
        let commitment_ciphertext = commitment_ciphertext
            .into_iter()
            .map(CommitmentCiphertext::from)
            .collect();
        let bound_params = BoundParams::new_transact(
            tree_number,
            self.builder.chain_type,
            self.builder.chain_id,
            commitment_ciphertext,
            Address::ZERO,
            UNRELAYED_ADAPT_PARAMS,
        )
        .with_min_gas_price(request.min_gas_price)?;

        let transaction = Transaction {
            proof: SnarkProof::default(),
            merkleRoot: FixedBytes::from(root.to_be_bytes::<32>()),
            nullifiers,
            commitments,
            boundParams: bound_params,
            unshieldPreimage: CommitmentPreimage::empty(),
        };
        let private_inputs = PrivateInputs::from_inputs(
            request.token_address,
            &inputs,
            &outputs,
            self.viewing,
            self.signer,
        );

        Ok(UnprovenTransactionPlan {
            transaction,
            tree_number,
            merkle_root: root,
            inputs,
            outputs,
            has_unshield: false,
            private_inputs,
        })
    }

    pub(super) fn build_unproven_fee_only(
        self,
        token_address: Address,
        min_gas_price: u128,
        outputs: Vec<Note>,
        commitment_ciphertext: Vec<NoteCiphertext>,
        proof_cache: Option<&mut InputWitnessProofCache<'_>>,
    ) -> Result<UnprovenTransactionPlan, BuildError> {
        self.validate_signature_limit(outputs.len())?;

        let tree_number = self.tree_number();
        let (inputs, root) = self.build_input_witnesses_and_root(proof_cache)?;
        let nullifiers = self.compute_nullifiers();
        let commitments = Self::compute_commitments(&outputs);
        let commitment_ciphertext = commitment_ciphertext
            .into_iter()
            .map(CommitmentCiphertext::from)
            .collect();
        let bound_params = BoundParams::new_transact(
            tree_number,
            self.builder.chain_type,
            self.builder.chain_id,
            commitment_ciphertext,
            Address::ZERO,
            UNRELAYED_ADAPT_PARAMS,
        )
        .with_min_gas_price(min_gas_price)?;

        let transaction = Transaction {
            proof: SnarkProof::default(),
            merkleRoot: FixedBytes::from(root.to_be_bytes::<32>()),
            nullifiers,
            commitments,
            boundParams: bound_params,
            unshieldPreimage: CommitmentPreimage::empty(),
        };
        let private_inputs =
            PrivateInputs::from_inputs(token_address, &inputs, &outputs, self.viewing, self.signer);

        Ok(UnprovenTransactionPlan {
            transaction,
            tree_number,
            merkle_root: root,
            inputs,
            outputs,
            has_unshield: false,
            private_inputs,
        })
    }

    /// Build a transact plan.
    pub(super) async fn build_transact(
        self,
        prover: &ProverService,
    ) -> Result<TransactPlan, BuildError> {
        let total = self.total_value();
        if total.is_zero() {
            return Err(BuildError::InsufficientBalance(total));
        }

        let receiver = self.viewing.address_data();
        let random = rand_array();
        let output = Note::new_change(
            receiver.master_public_key,
            self.token_address,
            total,
            random,
        );

        let ciphertext = NoteCiphertext::try_from_note(
            &output,
            &receiver,
            &receiver,
            &self.viewing.viewing_private_key,
        )?;

        let outputs = vec![output];
        let commitment_ciphertext = vec![CommitmentCiphertext::from(ciphertext)];

        self.validate_signature_limit(outputs.len())?;

        let tree_number = self.tree_number();
        let (inputs, root) = self.build_input_witnesses_and_root(None)?;

        // Build transaction
        let nullifiers = self.compute_nullifiers();
        let commitments = Self::compute_commitments(&outputs);

        let bound_params = BoundParams::new_transact(
            tree_number,
            self.builder.chain_type,
            self.builder.chain_id,
            commitment_ciphertext,
            Address::ZERO,
            UNRELAYED_ADAPT_PARAMS,
        );

        let mut transaction = Transaction {
            proof: SnarkProof::default(),
            merkleRoot: FixedBytes::from(root.to_be_bytes::<32>()),
            nullifiers,
            commitments,
            boundParams: bound_params,
            unshieldPreimage: CommitmentPreimage::empty(),
        };

        // Build inputs from the same proof-derived root used in the transaction.
        let public_inputs = PublicInputs::from_transaction(root, &transaction, &outputs);
        let private_inputs = PrivateInputs::from_inputs(
            self.token_address,
            &inputs,
            &outputs,
            self.viewing,
            self.signer,
        );
        let signature = public_inputs.signature(self.signer);

        let proof = prover
            .prove_unshield(&public_inputs, &private_inputs, &signature, true)
            .await?;
        transaction.proof = proof;

        // Build final call
        let data = transactCall {
            _transactions: vec![transaction],
        }
        .abi_encode();
        let call = TransactionCall {
            to: self.builder.railgun_contract,
            data: data.into(),
        };

        Ok(TransactPlan {
            call,
            tree_number,
            merkle_root: root,
            inputs,
            outputs,
            public_inputs,
            private_inputs,
            signature,
        })
    }
}

pub(super) trait BoundParamsExt {
    fn with_min_gas_price(self, min_gas_price: u128) -> Result<BoundParams, BuildError>;
}

impl BoundParamsExt for BoundParams {
    fn with_min_gas_price(mut self, min_gas_price: u128) -> Result<BoundParams, BuildError> {
        const MAX_UINT72: u128 = (1_u128 << 72) - 1;
        if min_gas_price > MAX_UINT72 {
            return Err(BuildError::MinGasPriceTooLarge(min_gas_price));
        }
        self.minGasPrice = Uint::<72, 2>::from(min_gas_price);
        Ok(self)
    }
}

pub(super) fn spend_allocations(
    selection: &BatchUtxoSelection,
    requested_amount: U256,
    fee_amount: U256,
    broadcaster_fee: Option<BroadcasterFeeOutput>,
    spend_up_to: bool,
) -> Result<Vec<SpendAllocation>, BuildError> {
    if selection.total < fee_amount {
        return Err(BuildError::InsufficientBalance(selection.total));
    }
    let spendable_after_fee = selection.total - fee_amount;
    if !spend_up_to && spendable_after_fee < requested_amount {
        return Err(BuildError::InsufficientBalance(selection.total));
    }
    let amount = if spend_up_to {
        spendable_after_fee.min(requested_amount)
    } else {
        requested_amount
    };
    if amount.is_zero() {
        return Err(BuildError::InsufficientBalance(selection.total));
    }

    let mut remaining = amount;
    let mut allocations = Vec::with_capacity(selection.chunks.len());
    for (index, chunk) in selection.chunks.iter().enumerate() {
        let fee = if index == 0 { broadcaster_fee } else { None };
        let chunk_fee = fee.map_or(U256::ZERO, |fee| fee.amount);
        if chunk.total <= chunk_fee {
            return Err(BuildError::InsufficientBalance(selection.total));
        }
        let spendable = chunk.total - chunk_fee;
        let amount = spendable.min(remaining);
        if amount.is_zero() {
            return Err(BuildError::InsufficientBalance(selection.total));
        }
        let change = spendable - amount;
        remaining -= amount;
        allocations.push(SpendAllocation {
            amount,
            change,
            fee,
        });
    }

    if remaining.is_zero() {
        Ok(allocations)
    } else {
        Err(BuildError::InsufficientBalance(selection.total))
    }
}

fn prepare_transaction_plan(
    plan: UnprovenTransactionPlan,
    signer: &impl RailgunSpendSigner,
) -> PreparedTransactionPlan {
    let started = Instant::now();
    let public_inputs_started = Instant::now();
    let public_inputs =
        PublicInputs::from_transaction(plan.merkle_root, &plan.transaction, &plan.outputs);
    let public_inputs_elapsed_ms = public_inputs_started.elapsed().as_millis();
    let signature_started = Instant::now();
    let signature = public_inputs.signature(signer);
    let signature_elapsed_ms = signature_started.elapsed().as_millis();
    PreparedTransactionPlan {
        plan,
        public_inputs,
        signature,
        started,
        public_inputs_elapsed_ms,
        signature_elapsed_ms,
    }
}

pub(super) async fn prove_transaction_plans<P: TransactionProver>(
    plans: Vec<UnprovenTransactionPlan>,
    signer: &impl RailgunSpendSigner,
    prover: &P,
    verify_proof: bool,
) -> Result<Vec<ProvenTransactionPlan>, BuildError> {
    let plan_count = plans.len();
    if plan_count == 0 {
        return Ok(Vec::new());
    }
    let prepared_plans = plans
        .into_iter()
        .map(|plan| prepare_transaction_plan(plan, signer))
        .collect::<Vec<_>>();

    if plan_count == 1 {
        let proven = prove_prepared_transaction_plan(
            prepared_plans.into_iter().next().expect("one plan"),
            prover,
            verify_proof,
        )
        .await?;
        return Ok(vec![proven]);
    }

    let mut handles = Vec::with_capacity(plan_count);
    for (index, prepared) in prepared_plans.into_iter().enumerate() {
        let prover = prover.clone();
        handles.push(tokio::spawn(async move {
            prove_prepared_transaction_plan(prepared, &prover, verify_proof)
                .await
                .map(|proven| (index, proven))
        }));
    }

    let mut proven_plans = std::iter::repeat_with(|| None)
        .take(plan_count)
        .collect::<Vec<_>>();
    for handle in handles {
        let (index, proven) = handle
            .await
            .map_err(|error| join_error_to_prover_error(&error))??;
        proven_plans[index] = Some(proven);
    }

    Ok(proven_plans
        .into_iter()
        .map(|proven| proven.expect("all plans proved"))
        .collect())
}

async fn prove_prepared_transaction_plan<P: TransactionProver>(
    prepared: PreparedTransactionPlan,
    prover: &P,
    verify_proof: bool,
) -> Result<ProvenTransactionPlan, BuildError> {
    let prove_started = Instant::now();
    let proof = prover
        .prove_unshield(
            &prepared.public_inputs,
            &prepared.plan.private_inputs,
            &prepared.signature,
            verify_proof,
        )
        .await?;
    let prove_elapsed_ms = prove_started.elapsed().as_millis();
    Ok(finalize_prepared_transaction_plan(
        prepared,
        proof,
        prove_elapsed_ms,
    ))
}

fn finalize_prepared_transaction_plan(
    prepared: PreparedTransactionPlan,
    proof: SnarkProof,
    prove_elapsed_ms: u128,
) -> ProvenTransactionPlan {
    let mut plan = prepared.plan;
    let public_inputs = prepared.public_inputs;
    let signature = prepared.signature;
    plan.transaction.proof = proof;
    let chunk = TransactionPlanChunk {
        tree_number: plan.tree_number,
        merkle_root: plan.merkle_root,
        inputs: plan.inputs,
        outputs: plan.outputs,
        has_unshield: plan.has_unshield,
        public_inputs,
        private_inputs: plan.private_inputs,
        signature,
    };
    tracing::debug!(
        tree_number = plan.tree_number,
        input_count = chunk.inputs.len(),
        output_count = chunk.outputs.len(),
        has_unshield = chunk.has_unshield,
        public_inputs_elapsed_ms = prepared.public_inputs_elapsed_ms,
        signature_elapsed_ms = prepared.signature_elapsed_ms,
        prove_elapsed_ms,
        elapsed_ms = prepared.started.elapsed().as_millis(),
        "proved transaction plan"
    );
    ProvenTransactionPlan {
        transaction: plan.transaction,
        chunk,
    }
}

#[must_use]
pub fn join_error_to_prover_error(error: &tokio::task::JoinError) -> ProverError {
    ProverError::WorkerPanic(error.to_string())
}
