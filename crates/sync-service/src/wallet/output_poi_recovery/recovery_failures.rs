#[allow(clippy::wildcard_imports)]
use super::*;

impl RecoveryFailure {
    pub(in crate::wallet) fn permanent(
        status: OutputPoiRecoveryStatus,
        message: impl Into<String>,
    ) -> Self {
        Self::permanent_category(status, recovery_failure_category(status), message)
    }

    pub(in crate::wallet) fn permanent_category(
        status: OutputPoiRecoveryStatus,
        category: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            status,
            message: message.into(),
            retry_after: None,
            category,
        }
    }

    pub(in crate::wallet) fn retryable(
        status: OutputPoiRecoveryStatus,
        message: impl Into<String>,
        retry_after: Duration,
    ) -> Self {
        Self::retryable_category(
            status,
            recovery_failure_category(status),
            message,
            retry_after,
        )
    }

    pub(in crate::wallet) fn retryable_category(
        status: OutputPoiRecoveryStatus,
        category: &'static str,
        message: impl Into<String>,
        retry_after: Duration,
    ) -> Self {
        Self {
            status,
            message: message.into(),
            retry_after: Some(retry_after),
            category,
        }
    }

    pub(super) const fn with_category(mut self, category: &'static str) -> Self {
        self.category = category;
        self
    }
}

const fn recovery_failure_category(status: OutputPoiRecoveryStatus) -> &'static str {
    match status {
        OutputPoiRecoveryStatus::MissingWalletOutputs => "missing_wallet_outputs",
        OutputPoiRecoveryStatus::MissingWalletInputs => "missing_wallet_inputs",
        OutputPoiRecoveryStatus::NotSelfOriginated => "not_self_originated",
        OutputPoiRecoveryStatus::MissingMerkleProof => "missing_merkle_proof",
        OutputPoiRecoveryStatus::UnsupportedShape => "unsupported_shape",
        OutputPoiRecoveryStatus::TxFetchFailed => "tx_fetch_failed",
        OutputPoiRecoveryStatus::Recoverable
        | OutputPoiRecoveryStatus::Submitted
        | OutputPoiRecoveryStatus::Valid
        | OutputPoiRecoveryStatus::InputPoiNotValid
        | OutputPoiRecoveryStatus::DecodeFailed
        | OutputPoiRecoveryStatus::ProofGenerationFailed
        | OutputPoiRecoveryStatus::SubmitFailed => "other",
    }
}
