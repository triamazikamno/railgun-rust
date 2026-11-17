//! Forced resubmission of matching pending output POI contexts.

use crate::wallet::{
    PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER, PendingContextTerminalDelta,
    PendingOutputPoiPreflight, PendingOutputPoiRemoteAttempt, PendingOutputPoiSubject,
    PendingOutputPoiSubmissionPlan, PendingOutputPoiSubmissionPreflight, PendingSubmissionDelta,
    TransactProofRoute, WalletCacheError, current_pending_output_poi_subject,
    pending_output_poi_context_fingerprint, preflight_and_remote_submit_pending_output_poi,
};
use std::collections::BTreeSet;

use super::{
    Arc, ChainPublicDataPlane, DbStore, FixedBytes, OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
    OutputPoiRecoveryAction, OwnedPoiPrivateDelta, PendingOutputPoiContextRecord,
    PoiPrivateApplyOutcome, RwLock, WalletCacheStore, WalletConfig, WalletPrivateMutationAuthority,
    WalletPrivatePoiClients, WalletUtxo, apply_poi_private_delta, debug, expected_recovery_state,
    now_epoch_secs, warn,
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
    let forced = ForcedAttempt {
        authority,
        public_data_plane,
        db,
        cache_store,
        cfg,
        active_list_keys,
        record,
        subject,
        plan,
        expected_context_fingerprint,
        now,
    };
    let Ok(attempt) = preflight_and_remote_submit_pending_output_poi(
        &forced.preflight(),
        &observation,
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
    forced.record(&attempt).await;
    Some(attempt)
}

/// A forced resubmission attempt's subject and plan, with the inputs recording its outcome needs.
struct ForcedAttempt<'a> {
    authority: &'a WalletPrivateMutationAuthority<'a>,
    public_data_plane: &'a ChainPublicDataPlane,
    db: &'a DbStore,
    cache_store: &'a dyn WalletCacheStore,
    cfg: &'a WalletConfig,
    active_list_keys: &'a [FixedBytes<32>],
    record: &'a PendingOutputPoiContextRecord,
    subject: PendingOutputPoiSubject,
    plan: PendingOutputPoiSubmissionPlan,
    expected_context_fingerprint: Vec<u8>,
    now: u64,
}

impl ForcedAttempt<'_> {
    /// Records the attempt's outcome: a terminal context, or the submission result while the
    /// plan is still ready.
    async fn record(&self, attempt: &PendingOutputPoiRemoteAttempt) {
        let (list_keys, action, submitted) = match attempt {
            PendingOutputPoiRemoteAttempt::NotCurrent
            | PendingOutputPoiRemoteAttempt::Deferred
            | PendingOutputPoiRemoteAttempt::AuthorityStale => return,
            PendingOutputPoiRemoteAttempt::MissingPreTransactionPois => {
                self.mark_terminal().await;
                return;
            }
            PendingOutputPoiRemoteAttempt::Succeeded {
                submitted_list_keys,
            } => (
                submitted_list_keys.clone(),
                OutputPoiRecoveryAction::Submitted {
                    retry_after: PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER,
                },
                true,
            ),
            PendingOutputPoiRemoteAttempt::Failed { error, .. } => (
                self.plan.list_keys().to_vec(),
                OutputPoiRecoveryAction::SubmitFailed {
                    error: error.clone(),
                    retry_after: OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
                },
                false,
            ),
        };
        if !self.plan_still_ready().await {
            return;
        }
        match self.persist_submission(list_keys, action, submitted).await {
            Ok(_) => {}
            Err(_) if submitted => warn!(
                chain_id = self.cfg.chain.chain_id,
                "failed to persist resubmitted pending output POI state"
            ),
            Err(_) => warn!(
                chain_id = self.cfg.chain.chain_id,
                "failed to persist failed pending output POI resubmission state"
            ),
        }
        if !submitted {
            warn!(
                chain_id = self.cfg.chain.chain_id,
                "forced pending output POI resubmission failed"
            );
        }
    }

    /// Marks the pending context terminal because its pre-transaction POIs are missing.
    async fn mark_terminal(&self) {
        if apply_poi_private_delta(
            self.authority,
            self.db,
            self.cache_store,
            self.cfg,
            OwnedPoiPrivateDelta::PendingContextTerminal(PendingContextTerminalDelta {
                subject: self.subject.clone(),
                expected_context_fingerprint: self.expected_context_fingerprint.clone(),
                expected_recovery: self.plan.expected_recovery(),
                active_list_keys: self.active_list_keys.to_vec(),
                target_list_keys: self.plan.list_keys().to_vec(),
                error: "missing pre-transaction POI for pending output".to_string(),
            }),
        )
        .await
        .is_err()
        {
            warn!(
                chain_id = self.cfg.chain.chain_id,
                "failed to mark pending output POI context terminal"
            );
        }
    }

    /// Whether the submission plan is still ready against current wallet and public state.
    async fn plan_still_ready(&self) -> bool {
        matches!(
            self.preflight().run().await,
            Ok(PendingOutputPoiPreflight::Ready)
        )
    }

    /// The preflight for this attempt's subject and plan.
    const fn preflight(&self) -> PendingOutputPoiSubmissionPreflight<'_> {
        PendingOutputPoiSubmissionPreflight {
            authority: self.authority,
            public_data_plane: self.public_data_plane,
            cache_store: self.cache_store,
            cfg: self.cfg,
            active_list_keys: self.active_list_keys,
            expected: self.record,
            subject: &self.subject,
            plan: &self.plan,
        }
    }

    /// Persists the submission result; submitted list keys are merged only on success.
    async fn persist_submission(
        &self,
        list_keys: Vec<FixedBytes<32>>,
        action: OutputPoiRecoveryAction,
        submitted: bool,
    ) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
        apply_poi_private_delta(
            self.authority,
            self.db,
            self.cache_store,
            self.cfg,
            OwnedPoiPrivateDelta::PendingSubmission(PendingSubmissionDelta {
                subject: self.subject.clone(),
                expected_context_fingerprint: self.expected_context_fingerprint.clone(),
                expected_recovery: self.plan.expected_recovery(),
                active_list_keys: self.active_list_keys.to_vec(),
                list_keys,
                predicate: self.plan.predicate(),
                merge_submitted_list_keys: submitted,
                action,
                now: self.now,
            }),
        )
        .await
    }
}
