#[allow(clippy::wildcard_imports)]
use super::*;

impl PendingOutputPoiSubmissionPreflight<'_> {
    /// Whether every preflight stage still passes.
    pub(super) async fn ready(&self) -> Result<bool, WalletCacheError> {
        Ok(matches!(
            self.run().await?,
            PendingOutputPoiPreflight::Ready
        ))
    }

    /// Sole preflight gate before remote pending-output POI disclosure. Runs every
    /// preflight stage in order and returns the first verdict that is not `Ready`.
    pub(in crate::wallet) async fn run(
        &self,
    ) -> Result<PendingOutputPoiPreflight, WalletCacheError> {
        if self.authority.revalidate().is_err() {
            debug!(target: LOG_TARGET,
                chain_id = self.cfg.chain.chain_id,
                "pending output POI submission skipped before plan validation"
            );
            return Ok(PendingOutputPoiPreflight::AuthorityStale);
        }
        if !self.scope_current() {
            return Ok(PendingOutputPoiPreflight::NotCurrent);
        }
        let Some(current) = self.stored_context()? else {
            return Ok(PendingOutputPoiPreflight::NotCurrent);
        };
        if !self.plan_current(&current)? {
            return Ok(PendingOutputPoiPreflight::NotCurrent);
        }
        if let Some(verdict) = self.wallet_subject_verdict(&current).await {
            return Ok(verdict);
        }
        if !self.postflight_unchanged()? {
            return Ok(PendingOutputPoiPreflight::NotCurrent);
        }
        if self.authority.revalidate().is_err() {
            debug!(target: LOG_TARGET,
                chain_id = self.cfg.chain.chain_id,
                "pending output POI submission skipped after plan validation"
            );
            return Ok(PendingOutputPoiPreflight::AuthorityStale);
        }
        Ok(PendingOutputPoiPreflight::Ready)
    }

    /// Whether the authority and the saved context still belong to this chain, wallet and
    /// public transaction.
    fn scope_current(&self) -> bool {
        self.authority.chain_id() == self.cfg.chain.chain_id
            && self.authority.wallet_id() == &self.cfg.cache_key
            && saved_pending_context_matches_public_transaction(
                self.public_data_plane,
                self.cfg,
                self.expected,
                &self.plan.list_keys,
            )
    }

    /// Loads the stored pending context, or `None` when it is gone or no longer matches
    /// `expected`.
    fn stored_context(&self) -> Result<Option<PendingOutputPoiContextRecord>, WalletCacheError> {
        let Some(current) = self.cache_store.get_pending_output_poi_context(
            self.cfg.chain.chain_id,
            &self.cfg.cache_key,
            &self.expected.output_commitment,
        )?
        else {
            return Ok(None);
        };
        if pending_output_poi_context_fingerprint(&current)
            != pending_output_poi_context_fingerprint(self.expected)
        {
            debug!(target: LOG_TARGET,
                chain_id = self.cfg.chain.chain_id,
                "pending output POI submission skipped; context changed"
            );
            return Ok(None);
        }
        Ok(Some(current))
    }

    /// Whether the plan targets at least one list and only active lists.
    fn plan_lists_active(&self) -> bool {
        !self.plan.list_keys.is_empty()
            && self
                .plan
                .list_keys
                .iter()
                .all(|list_key| self.active_list_keys.contains(list_key))
    }

    /// Whether the plan still applies: its lists are active, the stored recovery record matches
    /// the plan and the context observation, and the plan kind's list state still holds.
    fn plan_current(
        &self,
        current: &PendingOutputPoiContextRecord,
    ) -> Result<bool, WalletCacheError> {
        if !self.plan_lists_active() {
            return Ok(false);
        }
        let current_recovery = self.cache_store.get_output_poi_recovery(
            self.cfg.chain.chain_id,
            &self.cfg.cache_key,
            &self.expected.output_commitment,
        )?;
        if !expected_recovery_matches(&self.plan.expected_recovery, current_recovery.as_ref()) {
            debug!(target: LOG_TARGET,
                chain_id = self.cfg.chain.chain_id,
                "pending output POI submission skipped; recovery predecessor changed"
            );
            return Ok(false);
        }
        let Some(current_observation) = current.observation.as_ref() else {
            return Ok(false);
        };
        if current_recovery
            .as_ref()
            .is_some_and(|recovery| recovery.source_tx_hash != current_observation.tx_hash)
        {
            debug!(target: LOG_TARGET,
                chain_id = self.cfg.chain.chain_id,
                "pending output POI submission skipped; recovery source transaction does not match context observation"
            );
            return Ok(false);
        }
        Ok(self.plan_kind_state_current(current, current_recovery.as_ref()))
    }

    /// Whether the context's list state still allows this plan kind's submission.
    fn plan_kind_state_current(
        &self,
        current: &PendingOutputPoiContextRecord,
        current_recovery: Option<&OutputPoiRecoveryRecord>,
    ) -> bool {
        let plan = self.plan;
        match plan.predicate {
            PendingOutputPoiSubmissionPredicate::Missing => {
                let mut current_missing = current.missing_list_keys();
                current_missing.retain(|list_key| self.active_list_keys.contains(list_key));
                if plan
                    .list_keys
                    .iter()
                    .any(|list_key| !current_missing.contains(list_key))
                {
                    debug!(target: LOG_TARGET,
                        chain_id = self.cfg.chain.chain_id,
                        "pending output POI submission skipped; missing-list state changed"
                    );
                    return false;
                }
            }
            PendingOutputPoiSubmissionPredicate::RetrySubmitted => {
                let current_list_keys = current.list_keys();
                if plan.list_keys.iter().any(|list_key| {
                    !current_list_keys.contains(list_key)
                        || !current.submitted_poi_list_keys.contains(list_key)
                }) {
                    debug!(target: LOG_TARGET,
                        chain_id = self.cfg.chain.chain_id,
                        "pending output POI retry skipped; submitted-list state changed"
                    );
                    return false;
                }
                if !current_recovery.is_some_and(|record| {
                    record.submission_retry_allowed(now_epoch_secs(), plan.force_submission_retry)
                }) {
                    debug!(target: LOG_TARGET,
                        chain_id = self.cfg.chain.chain_id,
                        "pending output POI retry skipped; recovery state changed"
                    );
                    return false;
                }
            }
            PendingOutputPoiSubmissionPredicate::ForceMatching => {
                let current_list_keys = current.list_keys();
                if plan
                    .list_keys
                    .iter()
                    .any(|list_key| !current_list_keys.contains(list_key))
                {
                    debug!(target: LOG_TARGET,
                        chain_id = self.cfg.chain.chain_id,
                        "forced pending output POI skipped; list keys no longer on context"
                    );
                    return false;
                }
            }
        }
        true
    }

    /// Checks the subject and its recoverable lists against the wallet snapshot. Returns the
    /// verdict to stop with, or `None` to continue.
    async fn wallet_subject_verdict(
        &self,
        current: &PendingOutputPoiContextRecord,
    ) -> Option<PendingOutputPoiPreflight> {
        let Ok(snapshot) = self.authority.wallet_utxos().await else {
            debug!(target: LOG_TARGET,
                chain_id = self.cfg.chain.chain_id,
                "pending output POI submission skipped before wallet state check"
            );
            return Some(if self.authority.revalidate().is_err() {
                PendingOutputPoiPreflight::AuthorityStale
            } else {
                PendingOutputPoiPreflight::NotCurrent
            });
        };
        let Some(subject_match) =
            pending_output_poi_subject_matches_snapshot(self.cfg, &snapshot, current, self.subject)
        else {
            debug!(target: LOG_TARGET,
                chain_id = self.cfg.chain.chain_id,
                "pending output POI submission skipped; subject no longer matches wallet state"
            );
            return Some(PendingOutputPoiPreflight::NotCurrent);
        };
        let current_recoverable_list_keys = recoverable_pending_submission_list_keys(
            current,
            self.active_list_keys,
            subject_match.poi(),
            self.plan.predicate(),
        );
        if current_recoverable_list_keys != self.plan.list_keys {
            debug!(target: LOG_TARGET,
                chain_id = self.cfg.chain.chain_id,
                planned_poi_lists = self.plan.list_keys.len(),
                current_recoverable_poi_lists = current_recoverable_list_keys.len(),
                "pending output POI submission skipped; recoverable target-list subset changed"
            );
            return Some(PendingOutputPoiPreflight::NotCurrent);
        }
        None
    }

    /// Rereads the context and recovery after the wallet check and confirms neither changed.
    fn postflight_unchanged(&self) -> Result<bool, WalletCacheError> {
        let Some(postflight_context) = self.cache_store.get_pending_output_poi_context(
            self.cfg.chain.chain_id,
            &self.cfg.cache_key,
            &self.expected.output_commitment,
        )?
        else {
            return Ok(false);
        };
        let postflight_recovery = self.cache_store.get_output_poi_recovery(
            self.cfg.chain.chain_id,
            &self.cfg.cache_key,
            &self.expected.output_commitment,
        )?;
        let Some(final_context) = self.cache_store.get_pending_output_poi_context(
            self.cfg.chain.chain_id,
            &self.cfg.cache_key,
            &self.expected.output_commitment,
        )?
        else {
            return Ok(false);
        };
        let expected_fingerprint = pending_output_poi_context_fingerprint(self.expected);
        Ok(
            pending_output_poi_context_fingerprint(&postflight_context) == expected_fingerprint
                && pending_output_poi_context_fingerprint(&final_context) == expected_fingerprint
                && expected_recovery_matches(
                    &self.plan.expected_recovery,
                    postflight_recovery.as_ref(),
                )
                && !postflight_recovery.as_ref().is_some_and(|recovery| {
                    final_context
                        .observation
                        .as_ref()
                        .is_none_or(|observation| recovery.source_tx_hash != observation.tx_hash)
                }),
        )
    }
}

/// Sole production choke point for remote pending-output POI submission:
/// preflight → build context → remote await. Durable apply remains caller's postflight.
pub(in crate::wallet) async fn preflight_and_remote_submit_pending_output_poi(
    preflight: &PendingOutputPoiSubmissionPreflight<'_>,
    observation: &PendingOutputPoiObservation,
    private_poi: &WalletPrivatePoiClients,
    route: &mut Option<TransactProofRoute>,
) -> Result<PendingOutputPoiRemoteAttempt, WalletCacheError> {
    let PendingOutputPoiSubmissionPreflight {
        public_data_plane,
        cfg,
        expected: record,
        plan,
        ..
    } = *preflight;
    if record.observation.as_ref() != Some(observation)
        || !saved_pending_context_matches_public_transaction(
            public_data_plane,
            cfg,
            record,
            &plan.list_keys,
        )
    {
        return Ok(PendingOutputPoiRemoteAttempt::NotCurrent);
    }
    match preflight.run().await? {
        PendingOutputPoiPreflight::Ready => {}
        PendingOutputPoiPreflight::NotCurrent => {
            return Ok(PendingOutputPoiRemoteAttempt::NotCurrent);
        }
        PendingOutputPoiPreflight::AuthorityStale => {
            return Ok(PendingOutputPoiRemoteAttempt::AuthorityStale);
        }
    }

    let pre_transaction_pois = record.retain_poi_lists(&plan.list_keys);
    if pre_transaction_pois.len() != plan.list_keys.len() {
        return Ok(PendingOutputPoiRemoteAttempt::MissingPreTransactionPois);
    }
    if pending_output_poi_submit_identity(record, observation).is_none() {
        warn!(target: LOG_TARGET,
            chain_id = cfg.chain.chain_id,
            "pending output POI context has invalid output tree"
        );
        return Ok(PendingOutputPoiRemoteAttempt::NotCurrent);
    }
    let context = single_commitment_proof_context(record, pre_transaction_pois);
    debug!(target: LOG_TARGET,
        chain_id = cfg.chain.chain_id,
        pre_tx_poi_lists = context.pre_transaction_pois_per_txid_leaf_per_list.len(),
        plan_kind = ?plan.predicate,
        "submitting pending output POI context"
    );
    GatewaySubmission {
        preflight,
        private_poi,
        observation,
    }
    .submit(context, route)
    .await
}

/// The record's single-commitment proof context over its selected
/// pre-transaction POIs.
pub(super) fn single_commitment_proof_context(
    record: &PendingOutputPoiContextRecord,
    pre_transaction_pois: BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PreTxPoi>>,
) -> SingleCommitmentProofContext {
    SingleCommitmentProofContext {
        txid_version: record.txid_version.clone(),
        railgun_txid: record.railgun_txid,
        utxo_tree_in: record.utxo_tree_in,
        commitment: record.output_commitment,
        npk: record.output_npk,
        pre_transaction_pois_per_txid_leaf_per_list: pre_transaction_pois,
    }
}
