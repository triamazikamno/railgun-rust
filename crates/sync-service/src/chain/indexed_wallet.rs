//! Wallet-scan rows from Squid GraphQL pages and from verified indexed-artifact
//! chunks, plus the startup-sync helpers built on them.

use super::{
    BackfillEvent, CancellationToken, ChainConfig, ChainPublicDataPlane, DEFAULT_PAGE_SIZE, Future,
    IndexedLegacyEncryptedCommitmentInput, IndexedLegacyGeneratedCommitmentInput,
    IndexedNullifierInput, IndexedShieldCommitmentInput, IndexedTransactCommitmentInput,
    IndexedWalletPageKind, Instant, PublicScanReadScope, PublicScanSource, QuickSyncClient,
    SyncError, SyncProgressSender, SyncProgressStage, SyncProgressUpdate, UtxoSource,
    WalletBackfillApplyResult, WalletBackfillDriver, WalletBackfillFinishResult,
    WalletBackfillStartResult, WalletHandle, WalletScanApply, WalletScanInputRows,
    WalletStartupSyncError, artifact_chunk_progress, debug, info, mpsc, send_sync_progress,
};

use crate::indexed_artifacts::IndexedArtifactManifestError;

mod coverage;
mod decode;
mod page;
mod session;
mod startup;
#[cfg(test)]
mod tests;

pub(super) use page::IndexedWalletPage;
#[cfg(test)]
pub(super) use page::complete_stream_checkpoint;
pub(super) use session::{IndexedWalletArtifactPageOutcome, IndexedWalletArtifactSession};
#[cfg(test)]
pub(super) use startup::wallet_startup_hedge_block_count;
pub(super) use startup::{
    artifact_failure_can_fallback_to_squid, send_wallet_startup_events,
    should_hedge_wallet_startup, squid_tail_target_after_artifact, wait_or_cancel,
    wallet_backfill_from_block, wallet_remote_target_before_cached_suffix,
    wallet_reorg_backfill_from_block, wallet_startup_warm_from_block, wallet_sync_target,
};

fn wallet_artifact_error(err: &IndexedArtifactManifestError) -> SyncError {
    wallet_artifact_format(err.to_string())
}

fn wallet_artifact_format(message: impl Into<String>) -> SyncError {
    SyncError::UnexpectedFormat(format!("indexed wallet artifact: {}", message.into()))
}
