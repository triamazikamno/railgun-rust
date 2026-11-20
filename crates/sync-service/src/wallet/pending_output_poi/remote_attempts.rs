#[allow(clippy::wildcard_imports)]
use super::*;

impl StandardAttempt<'_> {
    /// Records the remote attempt's outcome while the plan is still current,
    /// and says whether the pass goes on.
    pub(super) async fn record(
        self,
        state: &mut PendingOutputPoiSubmissionPassState,
        remote_attempt: PendingOutputPoiRemoteAttempt,
    ) -> Result<ControlFlow<()>, WalletCacheError> {
        let (list_keys, action, submitted) = match remote_attempt {
            PendingOutputPoiRemoteAttempt::NotCurrent => return Ok(ControlFlow::Continue(())),
            PendingOutputPoiRemoteAttempt::Deferred => {
                state.deferred_txids.insert(self.record.railgun_txid);
                return Ok(ControlFlow::Continue(()));
            }
            PendingOutputPoiRemoteAttempt::AuthorityStale => return Ok(ControlFlow::Break(())),
            PendingOutputPoiRemoteAttempt::MissingPreTransactionPois => {
                self.mark_terminal().await;
                return Ok(ControlFlow::Continue(()));
            }
            PendingOutputPoiRemoteAttempt::Succeeded {
                submitted_list_keys,
            } => (
                submitted_list_keys,
                OutputPoiRecoveryAction::Submitted {
                    retry_after: PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER,
                },
                true,
            ),
            PendingOutputPoiRemoteAttempt::Failed { error } => (
                self.plan.list_keys.clone(),
                OutputPoiRecoveryAction::SubmitFailed {
                    error,
                    retry_after: OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
                },
                false,
            ),
        };
        if !self
            .pass
            .pending_output_poi_submission_side_effect_current(
                self.record,
                &self.subject,
                &self.plan,
            )
            .await?
        {
            return Ok(ControlFlow::Continue(()));
        }
        let chain_id = self.pass.cfg.chain.chain_id;
        let applied = self.persist_submission(list_keys, action, submitted).await;
        if applied && submitted {
            state.submitted_contexts += 1;
        }
        if !submitted {
            warn!(target: LOG_TARGET,
                chain_id,
                "pending output POI submission failed; keeping context retryable"
            );
        }
        Ok(ControlFlow::Continue(()))
    }

    /// Marks the pending context terminal because its pre-transaction POIs are missing.
    async fn mark_terminal(self) {
        let pass = self.pass;
        if apply_poi_private_delta(
            pass.authority,
            pass.db,
            pass.cache_store,
            pass.cfg,
            OwnedPoiPrivateDelta::PendingContextTerminal(PendingContextTerminalDelta {
                subject: self.subject,
                expected_context_fingerprint: self.expected_context_fingerprint,
                expected_recovery: self.plan.expected_recovery,
                active_list_keys: pass.active_list_keys.to_vec(),
                target_list_keys: self.plan.list_keys,
                error: "missing pre-transaction POI for pending output".to_string(),
            }),
        )
        .await
        .is_err()
        {
            warn!(target: LOG_TARGET,
                chain_id = pass.cfg.chain.chain_id,
                "failed to atomically persist pending output POI terminal state"
            );
        }
    }

    /// Persists the submission result and returns whether it was applied;
    /// submitted list keys are merged only on success.
    async fn persist_submission(
        self,
        list_keys: Vec<FixedBytes<32>>,
        action: OutputPoiRecoveryAction,
        submitted: bool,
    ) -> bool {
        let pass = self.pass;
        let predicate = self.plan.predicate();
        match apply_poi_private_delta(
            pass.authority,
            pass.db,
            pass.cache_store,
            pass.cfg,
            OwnedPoiPrivateDelta::PendingSubmission(PendingSubmissionDelta {
                subject: self.subject,
                expected_context_fingerprint: self.expected_context_fingerprint,
                expected_recovery: self.plan.expected_recovery,
                active_list_keys: pass.active_list_keys.to_vec(),
                list_keys,
                predicate,
                merge_submitted_list_keys: submitted,
                action,
                now: pass.now,
            }),
        )
        .await
        {
            Ok(PoiPrivateApplyOutcome::Applied { .. }) => true,
            Ok(
                PoiPrivateApplyOutcome::Skipped
                | PoiPrivateApplyOutcome::SkippedStaleCorpusRevision,
            ) => false,
            Err(_) if submitted => {
                warn!(target: LOG_TARGET,
                    chain_id = pass.cfg.chain.chain_id,
                    "failed to atomically persist pending output POI submitted state"
                );
                false
            }
            Err(_) => {
                warn!(target: LOG_TARGET,
                    chain_id = pass.cfg.chain.chain_id,
                    "failed to atomically persist pending output POI submit-failure state"
                );
                false
            }
        }
    }
}

/// The pass's route for `record`'s transaction, reserved on its first
/// transact proof and reused by its later records. `None` when deferred.
pub(super) async fn transact_proof_route<'a>(
    private_poi: &WalletPrivatePoiClients,
    route: &'a mut Option<TransactProofRoute>,
    chain_id: u64,
    record: &PendingOutputPoiContextRecord,
    forced: Option<DeferredForceKind>,
) -> Option<&'a TransactProofRoute> {
    if route
        .as_ref()
        .is_none_or(|current| current.railgun_txid() != record.railgun_txid)
    {
        // Drop another transaction's route before reserving this one.
        *route = None;
        *route = Some(
            private_poi
                .reserve_transact_route(chain_id, record.railgun_txid, forced)
                .await
                .ok()?,
        );
        private_poi.end_forced_deferral(record.railgun_txid);
    }
    route.as_ref()
}

impl GatewaySubmission<'_> {
    pub(super) async fn submit(
        &self,
        context: SingleCommitmentProofContext,
        route: &mut Option<TransactProofRoute>,
    ) -> Result<PendingOutputPoiRemoteAttempt, WalletCacheError> {
        if let Some(txid_merkleroot_index) = self.preflight.expected.txid_merkleroot_index {
            self.submit_transact_proofs(&context, txid_merkleroot_index, route)
                .await
        } else {
            self.submit_single_commitment(context).await
        }
    }

    /// Sends each planned list's transact proofs over the transaction's route.
    async fn submit_transact_proofs(
        &self,
        context: &SingleCommitmentProofContext,
        txid_merkleroot_index: u64,
        route: &mut Option<TransactProofRoute>,
    ) -> Result<PendingOutputPoiRemoteAttempt, WalletCacheError> {
        let PendingOutputPoiSubmissionPreflight {
            cfg,
            expected: record,
            plan,
            ..
        } = *self.preflight;
        let chain_id = cfg.chain.chain_id;
        let Some(route) = transact_proof_route(
            self.private_poi,
            route,
            chain_id,
            record,
            plan.deferred_force_kind(),
        )
        .await
        else {
            return Ok(PendingOutputPoiRemoteAttempt::Deferred);
        };
        for list_key in &plan.list_keys {
            let Some(per_leaf) = context
                .pre_transaction_pois_per_txid_leaf_per_list
                .get(list_key)
            else {
                continue;
            };
            for poi in per_leaf.values() {
                let result = self
                    .private_poi
                    .submit_transact_proof(
                        route,
                        || self.preflight.ready(),
                        &record.txid_version,
                        EVM_CHAIN_TYPE,
                        chain_id,
                        list_key,
                        txid_merkleroot_index,
                        poi,
                    )
                    .await;
                if let Err(error) = result {
                    return failed_remote_attempt(error, |failure| failure.to_string());
                }
            }
        }
        Ok(PendingOutputPoiRemoteAttempt::Succeeded {
            submitted_list_keys: plan.list_keys.clone(),
        })
    }

    /// Hands the context's single-commitment proofs off to the chain submitter.
    async fn submit_single_commitment(
        &self,
        context: SingleCommitmentProofContext,
    ) -> Result<PendingOutputPoiRemoteAttempt, WalletCacheError> {
        let PendingOutputPoiSubmissionPreflight {
            cfg,
            expected: record,
            plan,
            ..
        } = *self.preflight;
        let result = self
            .private_poi
            .submit_single_commitment_proofs(
                || self.preflight.ready(),
                plan.submit_intent(),
                &record.txid_version,
                EVM_CHAIN_TYPE,
                cfg.chain.chain_id,
                context,
                self.observation.output_tree,
                self.observation.output_position,
            )
            .await;
        match result {
            Ok(()) => Ok(PendingOutputPoiRemoteAttempt::Succeeded {
                submitted_list_keys: plan.list_keys.clone(),
            }),
            Err(error) => failed_remote_attempt(error, |failure| failure.summary),
        }
    }
}

/// The attempt a failed remote submission ends as, or the preflight's store error.
fn failed_remote_attempt<E>(
    error: WalletPrivateRemoteError<E, WalletCacheError>,
    summary: impl FnOnce(E) -> String,
) -> Result<PendingOutputPoiRemoteAttempt, WalletCacheError> {
    match error {
        WalletPrivateRemoteError::Stale(WalletPrivateRemoteStale::Authority) => {
            Ok(PendingOutputPoiRemoteAttempt::AuthorityStale)
        }
        WalletPrivateRemoteError::Stale(WalletPrivateRemoteStale::Subject) => {
            Ok(PendingOutputPoiRemoteAttempt::NotCurrent)
        }
        WalletPrivateRemoteError::Check(check_error) => Err(check_error),
        WalletPrivateRemoteError::Remote(failure) => Ok(PendingOutputPoiRemoteAttempt::Failed {
            error: summary(failure),
        }),
    }
}
