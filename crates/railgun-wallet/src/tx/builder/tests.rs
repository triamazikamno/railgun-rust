use std::cell::Cell;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use alloy::primitives::{Address, Bytes, FixedBytes, U256, Uint};
use alloy::signers::{SignerSync, local::PrivateKeySigner};
use alloy::sol_types::SolCall;
use alloy::uint;
use async_trait::async_trait;
use poi::poi::PoiMerkleProof;

use broadcaster_core::contracts::railgun::{
    ActionData, BoundParams, RelayAdapt7702, SnarkProof, TokenTransfer, transactCall,
};
use broadcaster_core::crypto::poseidon::poseidon;
use broadcaster_core::crypto::railgun::ViewingKeyData;
use broadcaster_core::notes::Note;
use broadcaster_core::transact::{
    DEFAULT_TXID_VERSION, MERKLE_ZERO_VALUE, PreTxPoi, SnarkJsProof, parse_transact_calldata,
};
use broadcaster_core::tree::TREE_DEPTH;
use broadcaster_core::utxo::{Utxo, UtxoCommitmentKind, UtxoSource};
use merkletree::tree::{MerkleForest, MerkleProof, MerkleTreeUpdate};

use crate::artifacts::ArtifactSource;
use crate::keys::{RailgunSpendSigner, WalletKeys};
use crate::notes::NoteOutputType;
use crate::prover::{ProverError, ProverService};
use crate::tx::{
    BroadcasterFeeOutput, BuildError, CompositeAdapter, CompositeExecution,
    CompositePrivateOutputRoleKind, CompositeRelayAction, CompositeRelayActionToken,
    CompositeRelayActions, CompositeUnshieldLeg, CompositeUnshieldLegRole,
    CompositeUnshieldRecipient, CompositeUnshieldRequest, ExecutorContext, InputWitness,
    MAX_BATCH_TRANSACTIONS, MAX_CIRCUIT_INPUTS, MixedPrivateActionRebuildConstraint,
    MixedPrivateActionRequest, MixedPrivateOutputRole, MixedPrivateOutputSource, MixedPrivateSend,
    MixedPrivateSendRole, PlannedUnshield, PoiCircuitVariant, PoiMerkleProofSource,
    PostTransactionPoiData, PostTransactionPoiGenerationRequest, PreTransactionPoiError,
    PreTransactionPoiGenerationRequest, PrivateInputs, PublicInputs, SelectedInputIdentity,
    SendPlan, SendRequest, TransactionBuilder, TransactionCall, TransactionPlanChunk,
    UNRELAYED_ADAPT_PARAMS, UnshieldPlan, UnshieldRequest, compute_railgun_txid_from_public_inputs,
    generate_post_transaction_pois, generate_pre_transaction_pois, insert_pre_transaction_poi,
    poi_circuit_variant,
};

use super::composite::select_composite_leg_selections;
use super::outputs::{build_fee_only_outputs, build_send_outputs, build_unshield_outputs};
use super::plan::{
    BoundParamsExt, InputWitnessProofCache, TransactionPlanBuilder, TransactionProver,
};
use super::select_utxos;
use super::{
    max_broadcaster_fee_token_spendable, max_send_spendable, max_unshield_spendable,
    send_selection_info, send_selection_info_with_broadcaster_fee,
    send_selection_info_with_broadcaster_fee_token,
    send_selection_info_with_separate_broadcaster_fee_seed, unshield_selection_info,
    unshield_selection_info_with_broadcaster_fee,
    unshield_selection_info_with_broadcaster_fee_token,
};

struct MockSpendSigner {
    signed_msg: Cell<Option<U256>>,
}

impl RailgunSpendSigner for MockSpendSigner {
    fn spending_public_key(&self) -> [U256; 2] {
        [uint!(11_U256), uint!(12_U256)]
    }

    fn sign_spend_message(&self, msg: U256) -> [U256; 3] {
        self.signed_msg.set(Some(msg));
        [uint!(1_U256), uint!(2_U256), uint!(3_U256)]
    }
}

#[derive(Clone, Copy)]
struct MockTransactionProver;

#[async_trait]
impl TransactionProver for MockTransactionProver {
    async fn prove_unshield(
        &self,
        _public_inputs: &PublicInputs,
        _private_inputs: &PrivateInputs,
        _signature: &[U256; 3],
        _verify_proof: bool,
    ) -> Result<SnarkProof, ProverError> {
        Ok(SnarkProof::default())
    }
}

#[derive(Clone, Default)]
struct RecordingTransactionProver {
    bound_params_hashes: Arc<Mutex<Vec<U256>>>,
}

impl RecordingTransactionProver {
    fn bound_params_hashes(&self) -> Vec<U256> {
        self.bound_params_hashes
            .lock()
            .expect("bound params hashes")
            .clone()
    }
}

#[async_trait]
impl TransactionProver for RecordingTransactionProver {
    async fn prove_unshield(
        &self,
        public_inputs: &PublicInputs,
        _private_inputs: &PrivateInputs,
        _signature: &[U256; 3],
        _verify_proof: bool,
    ) -> Result<SnarkProof, ProverError> {
        self.bound_params_hashes
            .lock()
            .expect("bound params hashes")
            .push(public_inputs.bound_params_hash);
        Ok(SnarkProof::default())
    }
}

#[derive(Default)]
struct FailingLocalPoiProofSource {
    calls: Mutex<usize>,
    commitment_counts: Mutex<Vec<usize>>,
}

impl FailingLocalPoiProofSource {
    fn calls(&self) -> usize {
        *self.calls.lock().expect("calls")
    }

    fn commitment_counts(&self) -> Vec<usize> {
        self.commitment_counts
            .lock()
            .expect("commitment counts")
            .clone()
    }
}

#[async_trait]
impl PoiMerkleProofSource for FailingLocalPoiProofSource {
    async fn poi_merkle_proofs(
        &self,
        _txid_version: &str,
        _chain_type: u8,
        _chain_id: u64,
        _list_key: &FixedBytes<32>,
        blinded_commitments: &[FixedBytes<32>],
    ) -> Result<Vec<PoiMerkleProof>, PreTransactionPoiError> {
        *self.calls.lock().expect("calls") += 1;
        self.commitment_counts
            .lock()
            .expect("commitment counts")
            .push(blinded_commitments.len());
        Err(PreTransactionPoiError::ProofSource(
            "local cache unavailable".to_string(),
        ))
    }
}

fn test_utxo(token: Address, value: u64, tree: u32, position: u64) -> Utxo {
    Utxo::new(
        Note::new_unshield(Address::ZERO, token, U256::from(value)),
        tree,
        position,
        UtxoSource {
            tx_hash: FixedBytes::ZERO,
            block_number: 1,
            block_timestamp: 1,
        },
        UtxoCommitmentKind::Transact,
    )
}

fn wallet_test_utxo(
    wallet: &WalletKeys,
    token: Address,
    value: u64,
    tree: u32,
    position: u64,
) -> Utxo {
    let random = [position as u8; 16];
    let note = Note {
        token_hash: U256::from_be_slice(token.as_slice()),
        value: U256::from(value),
        random,
        npk: Note::npk_for(wallet.viewing.master_public_key, random),
    };
    Utxo::new(
        note,
        tree,
        position,
        UtxoSource {
            tx_hash: FixedBytes::ZERO,
            block_number: 1,
            block_timestamp: 1,
        },
        UtxoCommitmentKind::Transact,
    )
}

fn forest_for_utxos(utxos: &[Utxo]) -> MerkleForest {
    let mut forest = MerkleForest::new();
    for utxo in utxos {
        forest
            .insert_leaf(MerkleTreeUpdate {
                tree_number: utxo.tree,
                tree_position: utxo.position,
                hash: utxo.note.commitment(),
            })
            .expect("insert test utxo");
    }
    forest.compute_roots();
    forest
}

fn test_wallet() -> WalletKeys {
    WalletKeys::from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        0,
    )
    .expect("valid mnemonic")
}

// On `test_transaction_builder`'s chain.
const TEST_EXECUTOR_CONTEXT: ExecutorContext = ExecutorContext {
    chain_id: 1,
    executor: Address::repeat_byte(0x52),
    delegate: Address::repeat_byte(0x53),
    execution_nonce: U256::ZERO,
};

fn test_transaction_builder() -> TransactionBuilder {
    TransactionBuilder {
        chain_type: 0,
        chain_id: 1,
        railgun_contract: Address::from([0x51; 20]),
    }
}

fn sample_address_data(seed: u8) -> ViewingKeyData {
    ViewingKeyData::from_spending_public_key([seed; 32], [U256::from(seed), U256::from(seed + 1)])
}

fn decode_adapter_plan(
    call: &TransactionCall,
    context: ExecutorContext,
) -> RelayAdapt7702::executeCall {
    let decoded = RelayAdapt7702::executeCall::abi_decode(&call.data).expect("executor execute");
    assert_eq!(decoded._nonce, context.execution_nonce);
    assert!(decoded._signature.is_empty());
    decoded
}

mod composite;
mod composite_validation;
mod executor;
mod mixed;
mod plans;
mod proofs;
mod selection;
mod swap;
