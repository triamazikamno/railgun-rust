use alloy::sol_types::Error as AbiError;
use broadcaster_core::crypto::aes_gcm::AesGcmError;
use broadcaster_core::transact::TransactError;

fn assert_legacy_error_shape(error: TransactError) {
    match error {
        TransactError::InvalidEd25519Pubkey
        | TransactError::SharedKey
        | TransactError::Random
        | TransactError::MissingTransactions
        | TransactError::MissingCommitment
        | TransactError::MissingCommitmentCiphertext
        | TransactError::InvalidTokenHash
        | TransactError::MissingPreTransactionPoiForAssurance => {}
        TransactError::AesGcm(error) => {
            let _: AesGcmError = error;
        }
        TransactError::InvalidIvTag { len }
        | TransactError::CalldataTooShort { len }
        | TransactError::PlaintextTooShort { len } => {
            let _: usize = len;
        }
        TransactError::UnknownFunctionCall { selector: value }
        | TransactError::UnsupportedTxidVersion {
            txid_version: value,
        } => {
            let _: String = value;
        }
        TransactError::Json(error) => {
            let _: serde_json::Error = error;
        }
        TransactError::AbiDecode(error) => {
            let _: AbiError = error;
        }
    }
}

#[test]
fn legacy_transact_error_is_an_exhaustive_public_compatibility_contract() {
    assert_legacy_error_shape(TransactError::MissingTransactions);
}
