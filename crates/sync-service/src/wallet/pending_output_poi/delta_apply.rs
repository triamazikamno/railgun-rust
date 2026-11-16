use crate::types::WalletBackfillRejectReason;

use super::{
    DbStore, ExpectedRecordState, FixedBytes, OutputPoiRecoveryRecord, OwnedPoiPrivateDelta,
    PoiPrivateApplyOutcome, PoiPrivateRows, WalletCacheError, WalletCacheStore,
    WalletCheckpointMutation, WalletConfig, WalletPpoiWorkflowProjection, WalletPrivateCommit,
    WalletPrivateMutationAuthority, WalletPrivateMutationPermit, WalletUtxo, WalletUtxoMutation,
    expected_recovery_matches,
};

mod sender_candidate;
mod submission;
mod validation;

use sender_candidate::{
    apply_sender_candidate_locally_valid, apply_sender_candidate_materialization,
    apply_sender_candidate_reconstruction, apply_sender_candidate_unshield_update,
    apply_sender_candidate_unshield_validated,
};
use submission::{
    apply_output_recovery, apply_pending_submission, apply_recovered_outgoing_submission,
};
use validation::{
    apply_locally_valid_pending_lists, apply_pending_context_terminal, apply_poi_status_refresh,
    apply_verified_valid,
};

/// Outcome of a durable commit that leaves UTXOs unchanged; a rejected apply is an error.
fn durable_apply_outcome(
    result: Result<Result<(), WalletCacheError>, WalletBackfillRejectReason>,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    result.map_or(Err(WalletCacheError::Crypto), |committed| {
        committed.map(|()| PoiPrivateApplyOutcome::Applied {
            utxo_changed: false,
        })
    })
}

/// Outcome of an active apply that may change UTXOs; a rejected apply is skipped.
fn active_apply_outcome(
    result: Result<Result<(), WalletCacheError>, WalletBackfillRejectReason>,
    utxo_changed: bool,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    result.map_or(Ok(PoiPrivateApplyOutcome::Skipped), |committed| {
        committed.map(|()| PoiPrivateApplyOutcome::Applied { utxo_changed })
    })
}

/// Whether `list_keys` is a non-empty subset of the active lists.
fn lists_are_active(active_list_keys: &[FixedBytes<32>], list_keys: &[FixedBytes<32>]) -> bool {
    !list_keys.is_empty()
        && list_keys
            .iter()
            .all(|list_key| active_list_keys.contains(list_key))
}

/// Whether the stored recovery is the expected one and, when present, came from `source_tx_hash`.
fn recovery_matches_source(
    expected: &ExpectedRecordState,
    current: Option<&OutputPoiRecoveryRecord>,
    source_tx_hash: FixedBytes<32>,
) -> bool {
    expected_recovery_matches(expected, current)
        && current.is_none_or(|recovery| recovery.source_tx_hash == source_tx_hash)
}

impl<'a> PoiPrivateRows<'a> {
    const fn add_to<'c>(self, commit: WalletPrivateCommit<'c>) -> WalletPrivateCommit<'c>
    where
        'a: 'c,
    {
        commit
            .with_pending_output_context_updates(self.pending_updates)
            .with_pending_output_context_deletes(self.pending_deletes)
            .with_output_poi_recovery_updates(self.recovery_updates)
            .with_output_poi_recovery_deletes(self.recovery_deletes)
            .with_sender_transaction_candidate_updates(self.candidate_updates)
            .with_sender_transaction_candidate_deletes(self.candidate_deletes)
    }
}

/// Commits `rows` durably with UTXOs preserved, publishes `workflow`, then drops the permit.
fn commit_durable_apply(
    permit: WalletPrivateMutationPermit<'_>,
    cache_store: &dyn WalletCacheStore,
    rows: PoiPrivateRows<'_>,
    workflow: WalletPpoiWorkflowProjection,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    let result = permit.with_durable_apply(|token| {
        cache_store.commit_wallet_private_state(rows.add_to(WalletPrivateCommit::new(
            &token,
            &permit,
            WalletUtxoMutation::Preserve,
            WalletCheckpointMutation::Preserve,
        )))?;
        permit.apply_publish_ppoi_workflow_projection(&token, workflow);
        Ok::<(), WalletCacheError>(())
    });
    drop(permit);
    durable_apply_outcome(result)
}

/// What an active apply commits: private rows, the UTXO snapshot that replaces the wallet's
/// when `utxos_changed`, and the workflow projection to publish.
#[derive(Default)]
struct ActiveApplyCommit<'a> {
    snapshot: Vec<WalletUtxo>,
    utxos_changed: bool,
    rows: PoiPrivateRows<'a>,
    workflow: Option<WalletPpoiWorkflowProjection>,
}

/// Commits `commit` under the UTXO write lock when UTXOs changed, then mirrors and notifies the
/// new UTXOs and publishes the workflow projection.
async fn commit_active_apply(
    permit: WalletPrivateMutationPermit<'_>,
    cache_store: &dyn WalletCacheStore,
    commit: ActiveApplyCommit<'_>,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    let ActiveApplyCommit {
        mut snapshot,
        utxos_changed,
        rows,
        workflow,
    } = commit;
    let mut utxos_locked = if utxos_changed {
        Some(permit.handle_utxos().write().await)
    } else {
        None
    };
    let result = permit.with_active_apply(|token| {
        cache_store.commit_wallet_private_state(rows.add_to(WalletPrivateCommit::new(
            &token,
            &permit,
            if utxos_changed {
                WalletUtxoMutation::Replace(&snapshot)
            } else {
                WalletUtxoMutation::Preserve
            },
            WalletCheckpointMutation::Preserve,
        )))?;
        if let Some(locked) = utxos_locked.as_mut() {
            **locked = std::mem::take(&mut snapshot);
            let overlay = permit
                .pending_overlay()
                .try_read()
                .map(|guard| guard.clone())
                .unwrap_or_default();
            permit.apply_notify_changed(&token, locked, &overlay);
        }
        if let Some(workflow) = workflow {
            permit.apply_publish_ppoi_workflow_projection(&token, workflow);
        }
        Ok::<(), WalletCacheError>(())
    });
    drop(utxos_locked);
    drop(permit);
    active_apply_outcome(result, utxos_changed)
}

/// Wallet state one exclusive apply holds while it folds a delta.
struct PoiApplyTurn<'a> {
    permit: WalletPrivateMutationPermit<'a>,
    snapshot: Vec<WalletUtxo>,
    cache_store: &'a dyn WalletCacheStore,
    cfg: &'a WalletConfig,
    active_list_keys: &'a [FixedBytes<32>],
}

/// Exclusive apply: acquire → fresh snapshot → fold → durable commit → mirrors → drop.
/// Call only from the actor turn (or single-threaded tests without an apply client).
pub(super) async fn apply_poi_private_delta_inline(
    authority: &WalletPrivateMutationAuthority<'_>,
    _db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    delta: OwnedPoiPrivateDelta,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    let permit = authority
        .acquire()
        .await
        .map_err(|_| WalletCacheError::Crypto)?;
    let snapshot = permit
        .wallet_utxos()
        .await
        .map_err(|_| WalletCacheError::Crypto)?;
    if permit.chain_id() != cfg.chain.chain_id || permit.wallet_id() != &cfg.cache_key {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    let turn = PoiApplyTurn {
        permit,
        snapshot,
        cache_store,
        cfg,
        active_list_keys,
    };
    match delta {
        OwnedPoiPrivateDelta::SenderCandidateReconstruction(delta) => {
            apply_sender_candidate_reconstruction(turn, delta).await
        }
        OwnedPoiPrivateDelta::SenderCandidateLocallyValid(delta) => {
            apply_sender_candidate_locally_valid(turn, delta).await
        }
        OwnedPoiPrivateDelta::SenderCandidateMaterialization(delta) => {
            apply_sender_candidate_materialization(turn, delta).await
        }
        OwnedPoiPrivateDelta::SenderCandidateUnshieldUpdate(delta) => {
            apply_sender_candidate_unshield_update(turn, delta).await
        }
        OwnedPoiPrivateDelta::SenderCandidateUnshieldValidated(delta) => {
            apply_sender_candidate_unshield_validated(turn, delta).await
        }
        OwnedPoiPrivateDelta::OutputRecovery(delta) => apply_output_recovery(turn, delta).await,
        OwnedPoiPrivateDelta::PendingSubmission(delta) => apply_pending_submission(turn, delta),
        OwnedPoiPrivateDelta::RecoveredOutgoingSubmission(delta) => {
            apply_recovered_outgoing_submission(turn, delta).await
        }
        OwnedPoiPrivateDelta::PendingContextTerminal(delta) => {
            apply_pending_context_terminal(turn, delta)
        }
        OwnedPoiPrivateDelta::LocallyValidPendingLists(delta) => {
            apply_locally_valid_pending_lists(turn, delta).await
        }
        OwnedPoiPrivateDelta::VerifiedValid(delta) => apply_verified_valid(turn, delta).await,
        OwnedPoiPrivateDelta::PoiStatusRefresh(delta) => {
            apply_poi_status_refresh(turn, delta).await
        }
    }
}
