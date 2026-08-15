use alloy::primitives::U256;
use railgun_wallet::notes::NoteError;
use railgun_wallet::prover::ProverError;
use railgun_wallet::tx::{BuildError, CompositePlanShape, SelectedInputIdentity};

fn assert_legacy_build_error_shape(error: BuildError) {
    match error {
        BuildError::InsufficientBalance(amount)
        | BuildError::InsufficientFeeTokenBalance(amount)
        | BuildError::PinnedInputsInsufficient(amount) => {
            let _: U256 = amount;
        }
        BuildError::TooManyInputs
        | BuildError::MixedTrees
        | BuildError::TokenMismatch
        | BuildError::MissingRoot
        | BuildError::MissingActionData
        | BuildError::EmptyCompositeUnshieldRequest
        | BuildError::EmptyMixedPrivateActionRequest
        | BuildError::MissingCompositeRelayActions
        | BuildError::InvalidRelayAdaptActionAmount => {}
        BuildError::SignatureInputLimit { inputs, outputs }
        | BuildError::TooManyBatchTransactions {
            requested: inputs,
            max: outputs,
        } => {
            let _: usize = inputs;
            let _: usize = outputs;
        }
        BuildError::DuplicatePinnedInput { tree, position }
        | BuildError::PinnedInputUnavailable { tree, position }
        | BuildError::MissingProof { tree, position } => {
            let _: u32 = tree;
            let _: u64 = position;
        }
        BuildError::PinnedInputsChanged { expected, actual } => {
            let _: Vec<SelectedInputIdentity> = expected;
            let _: Vec<SelectedInputIdentity> = actual;
        }
        BuildError::CompositePlanShapeChanged { expected, actual } => {
            let _: CompositePlanShape = expected;
            let _: CompositePlanShape = actual;
        }
        BuildError::MinGasPriceTooLarge(value) => {
            let _: u128 = value;
        }
        BuildError::Encrypt(error) => {
            let _: NoteError = error;
        }
        BuildError::Prover(error) => {
            let _: ProverError = error;
        }
    }
}

#[test]
fn legacy_build_error_is_an_exhaustive_public_compatibility_contract() {
    assert_legacy_build_error_shape(BuildError::MissingRoot);
}
