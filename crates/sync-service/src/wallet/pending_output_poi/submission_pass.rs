#[allow(clippy::wildcard_imports)]
use super::*;

impl PendingOutputPoiSubmissionPass<'_> {
    pub(super) fn force_retry(&self, record: &PendingOutputPoiContextRecord) -> bool {
        self.force_submission_retry || self.forced_txids.contains_key(&record.railgun_txid)
    }

    pub(super) async fn resubmit_forced(
        &self,
        state: &mut PendingOutputPoiSubmissionPassState,
        record: &PendingOutputPoiContextRecord,
    ) -> ControlFlow<()> {
        match force_resubmit_pending_output_poi_context(
            self.authority,
            self.public_data_plane,
            self.db,
            self.cache_store,
            self.cfg,
            self.active_list_keys,
            record,
            self.private_poi,
            &mut state.route,
            self.now,
        )
        .await
        {
            Some(PendingOutputPoiRemoteAttempt::Succeeded { .. }) => state.submitted_contexts += 1,
            Some(PendingOutputPoiRemoteAttempt::Deferred) => {
                state.deferred_txids.insert(record.railgun_txid);
            }
            Some(PendingOutputPoiRemoteAttempt::AuthorityStale) => return ControlFlow::Break(()),
            Some(
                PendingOutputPoiRemoteAttempt::NotCurrent
                | PendingOutputPoiRemoteAttempt::MissingPreTransactionPois
                | PendingOutputPoiRemoteAttempt::Failed { .. },
            )
            | None => {}
        }
        ControlFlow::Continue(())
    }

    pub(super) async fn submit_record(
        &self,
        state: &mut PendingOutputPoiSubmissionPassState,
        record: &PendingOutputPoiContextRecord,
    ) -> Result<ControlFlow<()>, WalletCacheError> {
        if record.observation.is_none() || record.terminal_error.is_some() {
            return Ok(ControlFlow::Continue(()));
        }
        if record.output_role == PendingOutputPoiRole::RecoveredOutgoing {
            return self.submit_recovered_group(state, record).await;
        }
        self.submit_standard(state, record).await
    }

    async fn submit_standard(
        &self,
        state: &mut PendingOutputPoiSubmissionPassState,
        record: &PendingOutputPoiContextRecord,
    ) -> Result<ControlFlow<()>, WalletCacheError> {
        let Some(observation) = record.observation.as_ref() else {
            return Ok(ControlFlow::Continue(()));
        };
        let recovery = self.cache_store.get_output_poi_recovery(
            self.cfg.chain.chain_id,
            &self.cfg.cache_key,
            &record.output_commitment,
        )?;
        let Some(expected_recovery) = expected_recovery_state(recovery.as_ref()) else {
            return Ok(ControlFlow::Continue(()));
        };
        let Some((subject, plan)) = self
            .due_standard_plan(record, recovery.as_ref(), expected_recovery)
            .await
        else {
            return Ok(ControlFlow::Continue(()));
        };
        let Some(expected_context_fingerprint) = pending_output_poi_context_fingerprint(record)
        else {
            return Ok(ControlFlow::Continue(()));
        };
        let remote_attempt = preflight_and_remote_submit_pending_output_poi(
            &self.preflight(record, &subject, &plan),
            observation,
            self.private_poi,
            &mut state.route,
        )
        .await?;
        StandardAttempt {
            pass: self,
            record,
            subject,
            plan,
            expected_context_fingerprint,
        }
        .record(state, remote_attempt)
        .await
    }

    /// The record's current subject and its due plan: its missing lists or,
    /// when none is recoverable and the recovery allows a retry, its submitted
    /// ones. `None` when nothing is due.
    async fn due_standard_plan(
        &self,
        record: &PendingOutputPoiContextRecord,
        recovery: Option<&OutputPoiRecoveryRecord>,
        expected_recovery: ExpectedRecordState,
    ) -> Option<(PendingOutputPoiSubject, PendingOutputPoiSubmissionPlan)> {
        let force_submission_retry = self.force_retry(record);
        let (subject, current_output) =
            current_pending_output_poi_subject(self.authority, self.cfg, record).await?;
        let poi = current_output.as_ref().map(|output| &output.utxo.poi);
        let mut plan =
            PendingOutputPoiSubmissionPlan::missing(record.missing_list_keys(), expected_recovery);
        plan.retain_current_recoverable(record, self.active_list_keys, poi);
        if plan.list_keys.is_empty()
            && recovery.is_some_and(|recovery| {
                recovery.submission_retry_allowed(self.now, force_submission_retry)
            })
        {
            plan = PendingOutputPoiSubmissionPlan::retry_submitted(
                record.list_keys(),
                plan.expected_recovery.clone(),
                force_submission_retry,
            );
            plan.retain_current_recoverable(record, self.active_list_keys, poi);
        }
        if plan.list_keys.is_empty() {
            return None;
        }
        debug!(target: LOG_TARGET,
            chain_id = self.cfg.chain.chain_id,
            force_submission_retry,
            retry_submitted = matches!(
                plan.predicate,
                PendingOutputPoiSubmissionPredicate::RetrySubmitted
            ),
            "pending output POI submission due"
        );
        Some((subject, plan))
    }
}

impl PendingOutputPoiSubmissionPass<'_> {
    pub(super) async fn pending_output_poi_submission_side_effect_current(
        &self,
        expected: &PendingOutputPoiContextRecord,
        subject: &PendingOutputPoiSubject,
        plan: &PendingOutputPoiSubmissionPlan,
    ) -> Result<bool, WalletCacheError> {
        Ok(matches!(
            self.preflight(expected, subject, plan).run().await?,
            PendingOutputPoiPreflight::Ready
        ))
    }

    /// The preflight for submitting `plan` on `expected` in this pass.
    pub(super) const fn preflight<'p>(
        &'p self,
        expected: &'p PendingOutputPoiContextRecord,
        subject: &'p PendingOutputPoiSubject,
        plan: &'p PendingOutputPoiSubmissionPlan,
    ) -> PendingOutputPoiSubmissionPreflight<'p> {
        PendingOutputPoiSubmissionPreflight {
            authority: self.authority,
            public_data_plane: self.public_data_plane,
            cache_store: self.cache_store,
            cfg: self.cfg,
            active_list_keys: self.active_list_keys,
            expected,
            subject,
            plan,
        }
    }
}
