//! Forced resubmission of matching pending output POI contexts.

use crate::wallet::{
    PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER, PendingContextTerminalDelta,
    PendingOutputPoiPreflight, PendingOutputPoiRemoteAttempt, PendingOutputPoiSubmissionPlan,
    PendingSubmissionDelta, TransactProofRoute, current_pending_output_poi_subject,
    pending_output_poi_context_fingerprint, pending_output_poi_submission_plan_current,
    preflight_and_remote_submit_pending_output_poi,
};
use std::collections::BTreeSet;

use super::{
    Arc, ChainPublicDataPlane, DbStore, FixedBytes, OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
    OutputPoiRecoveryAction, OwnedPoiPrivateDelta, PendingOutputPoiContextRecord, RwLock,
    WalletCacheStore, WalletConfig, WalletPrivateMutationAuthority, WalletPrivatePoiClients,
    WalletUtxo, apply_poi_private_delta, debug, expected_recovery_state, now_epoch_secs, warn,
};

pub(in crate::wallet) async fn force_resubmit_matching_pending_output_pois_authorized(
    authority: &WalletPrivateMutationAuthority<'_>,
    public_data_plane: &ChainPublicDataPlane,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    _utxos: &Arc<RwLock<Vec<WalletUtxo>>>,
    active_list_keys: &[FixedBytes<32>],
    private_poi: &WalletPrivatePoiClients,
) -> usize {
    if authority.revalidate().is_err() {
        debug!(
            chain_id = cfg.chain.chain_id,
            "forced pending output POI resubmission skipped"
        );
        return 0;
    }
    force_resubmit_matching_pending_output_pois_impl(
        authority,
        public_data_plane,
        db,
        cache_store,
        cfg,
        active_list_keys,
        private_poi,
    )
    .await
}

async fn force_resubmit_matching_pending_output_pois_impl(
    authority: &WalletPrivateMutationAuthority<'_>,
    public_data_plane: &ChainPublicDataPlane,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    private_poi: &WalletPrivatePoiClients,
) -> usize {
    if active_list_keys.is_empty() {
        return 0;
    }

    let now = now_epoch_secs();
    let mut attempted_contexts = 0usize;
    let Ok(records) =
        cache_store.list_pending_output_poi_contexts(cfg.chain.chain_id, &cfg.cache_key)
    else {
        warn!(
            chain_id = cfg.chain.chain_id,
            "failed to list pending output POI contexts for resubmission"
        );
        return 0;
    };
    let mut deferred_txids = BTreeSet::new();
    let mut route: Option<TransactProofRoute> = None;
    for record in private_poi.submission_order_by_key(records, |record| record.railgun_txid) {
        if deferred_txids.contains(&record.railgun_txid) {
            continue;
        }
        if route
            .as_ref()
            .is_some_and(|current| current.railgun_txid() != record.railgun_txid)
        {
            route = None;
        }
        // Count only after preflight allowed remote work to start.
        match force_resubmit_pending_output_poi_context(
            authority,
            public_data_plane,
            db,
            cache_store,
            cfg,
            active_list_keys,
            &record,
            private_poi,
            &mut route,
            now,
        )
        .await
        {
            Some(
                PendingOutputPoiRemoteAttempt::Succeeded { .. }
                | PendingOutputPoiRemoteAttempt::Failed { .. },
            ) => attempted_contexts += 1,
            Some(PendingOutputPoiRemoteAttempt::Deferred) => {
                deferred_txids.insert(record.railgun_txid);
            }
            Some(PendingOutputPoiRemoteAttempt::AuthorityStale) => break,
            Some(
                PendingOutputPoiRemoteAttempt::NotCurrent
                | PendingOutputPoiRemoteAttempt::MissingPreTransactionPois,
            )
            | None => {}
        }
    }

    attempted_contexts
}

/// Force-resubmits one pending output context: every recoverable active list
/// on it, with no recovery-retry gate, recording the outcome durably. `None`
/// when nothing is due or the attempt failed before an outcome.
#[allow(clippy::too_many_arguments)]
pub(in crate::wallet) async fn force_resubmit_pending_output_poi_context(
    authority: &WalletPrivateMutationAuthority<'_>,
    public_data_plane: &ChainPublicDataPlane,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    record: &PendingOutputPoiContextRecord,
    private_poi: &WalletPrivatePoiClients,
    route: &mut Option<TransactProofRoute>,
    now: u64,
) -> Option<PendingOutputPoiRemoteAttempt> {
    if record.terminal_error.is_some() {
        return None;
    }
    let output_commitment = record.output_commitment;
    let observation = record.observation.clone()?;
    let (subject, current_output) =
        current_pending_output_poi_subject(authority, cfg, record).await?;
    let Ok(current_recovery) =
        cache_store.get_output_poi_recovery(cfg.chain.chain_id, &cfg.cache_key, &output_commitment)
    else {
        warn!(
            chain_id = cfg.chain.chain_id,
            "failed to load forced pending output POI recovery predecessor"
        );
        return None;
    };
    let expected_recovery = expected_recovery_state(current_recovery.as_ref())?;
    let mut plan =
        PendingOutputPoiSubmissionPlan::force_matching(record.list_keys(), expected_recovery);
    plan.retain_current_recoverable(
        record,
        active_list_keys,
        current_output.as_ref().map(|output| &output.utxo.poi),
    );
    if plan.list_keys().is_empty() {
        return None;
    }
    let expected_context_fingerprint = pending_output_poi_context_fingerprint(record)?;
    debug!(
        chain_id = cfg.chain.chain_id,
        poi_lists = plan.list_keys().len(),
        "force-resubmitting matching pending output POI context"
    );
    let Ok(attempt) = preflight_and_remote_submit_pending_output_poi(
        authority,
        public_data_plane,
        cache_store,
        cfg,
        active_list_keys,
        record,
        &observation,
        &subject,
        &plan,
        private_poi,
        route,
    )
    .await
    else {
        warn!(
            chain_id = cfg.chain.chain_id,
            "forced pending output POI preflight/submit failed"
        );
        return None;
    };
    match &attempt {
        PendingOutputPoiRemoteAttempt::NotCurrent
        | PendingOutputPoiRemoteAttempt::Deferred
        | PendingOutputPoiRemoteAttempt::AuthorityStale => {}
        PendingOutputPoiRemoteAttempt::MissingPreTransactionPois => {
            if apply_poi_private_delta(
                authority,
                db,
                cache_store,
                cfg,
                OwnedPoiPrivateDelta::PendingContextTerminal(PendingContextTerminalDelta {
                    subject: subject.clone(),
                    expected_context_fingerprint,
                    expected_recovery: plan.expected_recovery(),
                    active_list_keys: active_list_keys.to_vec(),
                    target_list_keys: plan.list_keys().to_vec(),
                    error: "missing pre-transaction POI for pending output".to_string(),
                }),
            )
            .await
            .is_err()
            {
                warn!(
                    chain_id = cfg.chain.chain_id,
                    "failed to mark pending output POI context terminal"
                );
            }
        }
        PendingOutputPoiRemoteAttempt::Succeeded {
            submitted_list_keys,
        } => {
            if matches!(
                pending_output_poi_submission_plan_current(
                    authority,
                    public_data_plane,
                    cache_store,
                    cfg,
                    active_list_keys,
                    record,
                    &subject,
                    &plan,
                )
                .await,
                Ok(PendingOutputPoiPreflight::Ready)
            ) && apply_poi_private_delta(
                authority,
                db,
                cache_store,
                cfg,
                OwnedPoiPrivateDelta::PendingSubmission(PendingSubmissionDelta {
                    subject: subject.clone(),
                    expected_context_fingerprint,
                    expected_recovery: plan.expected_recovery(),
                    active_list_keys: active_list_keys.to_vec(),
                    list_keys: submitted_list_keys.clone(),
                    predicate: plan.predicate(),
                    merge_submitted_list_keys: true,
                    action: OutputPoiRecoveryAction::Submitted {
                        retry_after: PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER,
                    },
                    now,
                }),
            )
            .await
            .is_err()
            {
                warn!(
                    chain_id = cfg.chain.chain_id,
                    "failed to persist resubmitted pending output POI state"
                );
            }
        }
        PendingOutputPoiRemoteAttempt::Failed { error, .. } => {
            if matches!(
                pending_output_poi_submission_plan_current(
                    authority,
                    public_data_plane,
                    cache_store,
                    cfg,
                    active_list_keys,
                    record,
                    &subject,
                    &plan,
                )
                .await,
                Ok(PendingOutputPoiPreflight::Ready)
            ) {
                if apply_poi_private_delta(
                    authority,
                    db,
                    cache_store,
                    cfg,
                    OwnedPoiPrivateDelta::PendingSubmission(PendingSubmissionDelta {
                        subject: subject.clone(),
                        expected_context_fingerprint,
                        expected_recovery: plan.expected_recovery(),
                        active_list_keys: active_list_keys.to_vec(),
                        list_keys: plan.list_keys().to_vec(),
                        predicate: plan.predicate(),
                        merge_submitted_list_keys: false,
                        action: OutputPoiRecoveryAction::SubmitFailed {
                            error: error.clone(),
                            retry_after: OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
                        },
                        now,
                    }),
                )
                .await
                .is_err()
                {
                    warn!(
                        chain_id = cfg.chain.chain_id,
                        "failed to persist failed pending output POI resubmission state"
                    );
                }
                warn!(
                    chain_id = cfg.chain.chain_id,
                    "forced pending output POI resubmission failed"
                );
            }
        }
    }
    Some(attempt)
}
