use super::{
    BTreeMap, BlindedCommitmentData, CancellationToken, ChainPublicDataPlane,
    CommitmentObservation, DbStore, EVM_CHAIN_TYPE, ExpectedPoiListState, ExpectedPoiStatus,
    ExpectedRecordState, ExpectedWalletOutput, FixedBytes, Instant,
    OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER, OutputPoiRecoveryAction, OutputPoiRecoveryRecord,
    OutputPoiRecoveryStatus, OwnedPoiPrivateDelta, PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER,
    PendingOutputPoiContextRecord, PendingOutputPoiObservation,
    PendingOutputPoiSubmissionPredicate, PoiError, PoiPrivateApplyOutcome, PoiStatus,
    PoiStatusReader, PublicPoiCorpusKey, SingleCommitmentProofContext, UtxoPoiMetadata,
    WalletCacheError, WalletCacheKey, WalletCacheStore, WalletCheckpointMutation, WalletConfig,
    WalletHandle, WalletPoiRuntime, WalletPrivateCommit, WalletPrivateMutationAuthority,
    WalletPrivatePoiClients, WalletPrivateRemoteError, WalletPrivateRemoteStale, WalletUtxo,
    WalletUtxoMutation, debug, new_output_poi_recovery_record, now_epoch_secs, warn,
};

#[cfg(test)]
use super::{PendingOutputPoiSubmitter, PoiRpcClient};

#[cfg(test)]
pub(crate) async fn process_pending_output_poi_observations(
    db: &DbStore,
    chain_id: u64,
    wallet_id: &str,
    observations: &[CommitmentObservation],
    submitter: Option<&dyn PendingOutputPoiSubmitter>,
) {
    process_pending_output_poi_observations_inner(
        db,
        chain_id,
        wallet_id,
        observations,
        submitter,
        false,
    )
    .await;
}

pub(super) async fn process_pending_output_poi_observations_authorized(
    authority: &WalletPrivateMutationAuthority<'_>,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    private_poi: Option<&WalletPrivatePoiClients>,
    force_submission_retry: bool,
) -> usize {
    let started = Instant::now();
    let Some(private_poi) = private_poi else {
        return 0;
    };
    // No long-lived permit: remote submit uses authority revalidation; semantic
    // intents acquire a short permit only when the actor folds them into current state.
    if authority.revalidate().is_err() {
        debug!(
            chain_id = cfg.chain.chain_id,
            "pending output POI submission skipped"
        );
        return 0;
    }
    let submitted_contexts = submit_observed_pending_output_pois_inner(
        authority,
        db,
        cache_store,
        cfg,
        active_list_keys,
        private_poi,
        force_submission_retry,
    )
    .await
    .unwrap_or_else(|_| {
        warn!(
            chain_id = cfg.chain.chain_id,
            "failed to submit observed pending output POI contexts"
        );
        0
    });
    if submitted_contexts > 0 {
        debug!(
            chain_id = cfg.chain.chain_id,
            submitted_contexts,
            elapsed_ms = started.elapsed().as_millis(),
            "submitted observed pending output POI contexts"
        );
    }
    submitted_contexts
}

#[cfg(test)]
pub(super) async fn process_pending_output_poi_observations_inner(
    db: &DbStore,
    chain_id: u64,
    wallet_id: &str,
    observations: &[CommitmentObservation],
    submitter: Option<&dyn PendingOutputPoiSubmitter>,
    force_submission_retry: bool,
) {
    let started = Instant::now();
    let record_started = Instant::now();
    let recorded_observations =
        record_pending_output_poi_observations(db, chain_id, wallet_id, observations)
            .unwrap_or_else(|_| {
                warn!(chain_id, "failed to record pending output POI observations");
                0
            });
    let record_elapsed_ms = record_started.elapsed().as_millis();

    let Some(submitter) = submitter else {
        if observations.is_empty() {
            return;
        }
        debug!(
            chain_id,
            observations = observations.len(),
            recorded_observations,
            submitted = false,
            record_elapsed_ms,
            elapsed_ms = started.elapsed().as_millis(),
            "processed pending output POI observations"
        );
        return;
    };
    let submit_started = Instant::now();
    let submitted_contexts = submit_observed_pending_output_pois_unchecked(
        db,
        chain_id,
        wallet_id,
        submitter,
        force_submission_retry,
    )
    .await
    .unwrap_or_else(|_| {
        warn!(
            chain_id,
            "failed to submit observed pending output POI contexts"
        );
        0
    });
    if submitted_contexts > 0 || !observations.is_empty() {
        debug!(
            chain_id,
            observations = observations.len(),
            recorded_observations,
            submitted = true,
            submitted_contexts,
            record_elapsed_ms,
            submit_elapsed_ms = submit_started.elapsed().as_millis(),
            elapsed_ms = started.elapsed().as_millis(),
            "processed pending output POI observations"
        );
    }
}

#[cfg(test)]
pub(super) fn record_pending_output_poi_observations(
    db: &DbStore,
    chain_id: u64,
    wallet_id: &str,
    observations: &[CommitmentObservation],
) -> Result<usize, WalletCacheError> {
    let wallet_id = wallet_id
        .parse::<WalletCacheKey>()
        .map_err(local_db::DbError::from)?;
    let updates = pending_output_poi_observation_updates(db, chain_id, &wallet_id, observations)?;
    let recorded = updates.len();
    for record in updates {
        db.put_pending_output_poi_context(&record)?;
    }
    Ok(recorded)
}

pub(super) fn pending_output_poi_observation_updates(
    cache_store: &dyn WalletCacheStore,
    chain_id: u64,
    wallet_id: &WalletCacheKey,
    observations: &[CommitmentObservation],
) -> Result<Vec<PendingOutputPoiContextRecord>, WalletCacheError> {
    let mut updates = Vec::new();
    for observation in observations {
        let output_commitment = FixedBytes::from(observation.commitment.to_be_bytes::<32>());
        let Some(mut record) =
            cache_store.get_pending_output_poi_context(chain_id, wallet_id, &output_commitment)?
        else {
            continue;
        };
        let observed = PendingOutputPoiObservation {
            output_tree: u64::from(observation.tree),
            output_position: observation.position,
            tx_hash: observation.source.tx_hash,
            block_number: observation.source.block_number,
            block_timestamp: observation.source.block_timestamp,
        };
        if record.observe(observed) {
            updates.push(record);
        }
    }
    Ok(updates)
}

pub(super) async fn submit_observed_pending_output_pois_inner(
    authority: &WalletPrivateMutationAuthority<'_>,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    private_poi: &WalletPrivatePoiClients,
    force_submission_retry: bool,
) -> Result<usize, WalletCacheError> {
    submit_observed_pending_output_pois_impl(
        authority,
        cfg,
        active_list_keys,
        db,
        cache_store,
        cfg.chain.chain_id,
        &cfg.cache_key,
        private_poi,
        force_submission_retry,
    )
    .await
}

/// Preflight result for generation-scoped remote pending-output POI submit.
///
/// Remote disclosure must not start unless [`Self::Ready`]. Authority loss aborts the
/// whole multi-context job; other not-current reasons skip only that candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PendingOutputPoiPreflight {
    Ready,
    NotCurrent,
    AuthorityStale,
}

/// Remote attempt after a successful preflight (durable apply is still postflight-gated).
#[derive(Debug)]
pub(super) enum PendingOutputPoiRemoteAttempt {
    NotCurrent,
    AuthorityStale,
    /// Preflight failed structural build (missing pre-tx POIs); caller may mark terminal.
    MissingPreTransactionPois,
    Succeeded {
        submitted_list_keys: Vec<FixedBytes<32>>,
    },
    Failed {
        error: PoiError,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingOutputPoiSubmissionKind {
    Missing,
    RetrySubmitted,
    /// User/API force-resubmit of matching contexts (no recovery-retry gate).
    ForceMatching,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PendingOutputPoiSubmissionPlan {
    kind: PendingOutputPoiSubmissionKind,
    list_keys: Vec<FixedBytes<32>>,
    expected_recovery: ExpectedRecordState,
    force_submission_retry: bool,
}

impl PendingOutputPoiSubmissionPlan {
    const fn missing(
        list_keys: Vec<FixedBytes<32>>,
        expected_recovery: ExpectedRecordState,
    ) -> Self {
        Self {
            kind: PendingOutputPoiSubmissionKind::Missing,
            list_keys,
            expected_recovery,
            force_submission_retry: false,
        }
    }

    const fn retry_submitted(
        list_keys: Vec<FixedBytes<32>>,
        expected_recovery: ExpectedRecordState,
        force_submission_retry: bool,
    ) -> Self {
        Self {
            kind: PendingOutputPoiSubmissionKind::RetrySubmitted,
            list_keys,
            expected_recovery,
            force_submission_retry,
        }
    }

    /// Force-resubmit plan: active list keys already on the context (submitted or not).
    pub(super) const fn force_matching(
        list_keys: Vec<FixedBytes<32>>,
        expected_recovery: ExpectedRecordState,
    ) -> Self {
        Self {
            kind: PendingOutputPoiSubmissionKind::ForceMatching,
            list_keys,
            expected_recovery,
            force_submission_retry: true,
        }
    }

    pub(super) fn retain_current_recoverable(
        &mut self,
        context: &PendingOutputPoiContextRecord,
        active_list_keys: &[FixedBytes<32>],
        poi: &UtxoPoiMetadata,
    ) {
        self.list_keys = recoverable_pending_submission_list_keys(
            context,
            active_list_keys,
            poi,
            self.predicate(),
        );
    }

    pub(super) fn list_keys(&self) -> &[FixedBytes<32>] {
        &self.list_keys
    }

    pub(super) fn expected_recovery(&self) -> ExpectedRecordState {
        self.expected_recovery.clone()
    }

    pub(super) const fn predicate(&self) -> PendingOutputPoiSubmissionPredicate {
        match self.kind {
            PendingOutputPoiSubmissionKind::Missing => PendingOutputPoiSubmissionPredicate::Missing,
            PendingOutputPoiSubmissionKind::RetrySubmitted => {
                PendingOutputPoiSubmissionPredicate::RetrySubmitted
            }
            PendingOutputPoiSubmissionKind::ForceMatching => {
                PendingOutputPoiSubmissionPredicate::ForceMatching
            }
        }
    }
}

fn recoverable_pending_submission_list_keys(
    context: &PendingOutputPoiContextRecord,
    active_list_keys: &[FixedBytes<32>],
    poi: &UtxoPoiMetadata,
    predicate: PendingOutputPoiSubmissionPredicate,
) -> Vec<FixedBytes<32>> {
    let submitted_list_keys = &context.submitted_poi_list_keys;
    let mut list_keys = match predicate {
        PendingOutputPoiSubmissionPredicate::Missing => context.missing_list_keys(),
        PendingOutputPoiSubmissionPredicate::RetrySubmitted => context
            .list_keys()
            .into_iter()
            .filter(|list_key| submitted_list_keys.contains(list_key))
            .collect(),
        PendingOutputPoiSubmissionPredicate::ForceMatching => context.list_keys(),
    };
    list_keys.retain(|list_key| {
        active_list_keys.contains(list_key)
            && poi
                .statuses
                .get(list_key)
                .is_none_or(|status| status.is_recoverable())
    });
    list_keys
}

async fn submit_observed_pending_output_pois_impl(
    authority: &WalletPrivateMutationAuthority<'_>,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    chain_id: u64,
    _wallet_id: &str,
    private_poi: &WalletPrivatePoiClients,
    force_submission_retry: bool,
) -> Result<usize, WalletCacheError> {
    let records = cache_store.list_pending_output_poi_contexts(chain_id, &cfg.cache_key)?;
    let mut submitted_contexts = 0;
    let now = now_epoch_secs();
    for record in records {
        let Some(observation) = record.observation.clone() else {
            continue;
        };
        if record.terminal_error.is_some() {
            continue;
        }
        let recovery = cache_store.get_output_poi_recovery(
            chain_id,
            &cfg.cache_key,
            &record.output_commitment,
        )?;
        let Some(expected_recovery) = expected_recovery_state(recovery.as_ref()) else {
            continue;
        };
        let Some(current_output) =
            current_wallet_output_for_pending_context(authority, cfg, &record).await
        else {
            continue;
        };
        let mut plan =
            PendingOutputPoiSubmissionPlan::missing(record.missing_list_keys(), expected_recovery);
        plan.retain_current_recoverable(&record, active_list_keys, &current_output.utxo.poi);
        if plan.list_keys.is_empty()
            && let Some(recovery) = recovery.as_ref()
            && recovery.submission_retry_allowed(now, force_submission_retry)
        {
            plan = PendingOutputPoiSubmissionPlan::retry_submitted(
                record.list_keys(),
                plan.expected_recovery.clone(),
                force_submission_retry,
            );
            plan.retain_current_recoverable(&record, active_list_keys, &current_output.utxo.poi);
        }
        if plan.list_keys.is_empty() {
            continue;
        }
        let expected_output = ExpectedWalletOutput::new(&current_output);
        let Some(expected_context_fingerprint) = pending_output_poi_context_fingerprint(&record)
        else {
            continue;
        };
        match preflight_and_remote_submit_pending_output_poi(
            authority,
            cache_store,
            cfg,
            active_list_keys,
            &record,
            &observation,
            &plan,
            private_poi,
        )
        .await?
        {
            PendingOutputPoiRemoteAttempt::NotCurrent => {}
            PendingOutputPoiRemoteAttempt::AuthorityStale => break,
            PendingOutputPoiRemoteAttempt::MissingPreTransactionPois => {
                if apply_poi_private_delta(
                    authority,
                    db,
                    cache_store,
                    cfg,
                    OwnedPoiPrivateDelta::PendingContextTerminal {
                        expected_output,
                        expected_context_fingerprint,
                        active_list_keys: plan.list_keys.clone(),
                        error: "missing pre-transaction POI for pending output".to_string(),
                    },
                )
                .await
                .is_err()
                {
                    warn!(
                        chain_id,
                        "failed to atomically persist pending output POI terminal state"
                    );
                }
            }
            PendingOutputPoiRemoteAttempt::Succeeded {
                submitted_list_keys,
            } => {
                if !pending_output_poi_submission_side_effect_current(
                    authority,
                    cache_store,
                    &record,
                    cfg,
                    active_list_keys,
                    &plan,
                )
                .await?
                {
                    continue;
                }
                match apply_poi_private_delta(
                    authority,
                    db,
                    cache_store,
                    cfg,
                    OwnedPoiPrivateDelta::PendingSubmission {
                        expected_output,
                        expected_context_fingerprint,
                        expected_recovery: plan.expected_recovery.clone(),
                        active_list_keys: active_list_keys.to_vec(),
                        list_keys: submitted_list_keys,
                        predicate: plan.predicate(),
                        merge_submitted_list_keys: true,
                        action: OutputPoiRecoveryAction::Submitted {
                            retry_after: PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER,
                        },
                        now,
                    },
                )
                .await
                {
                    Ok(PoiPrivateApplyOutcome::Applied { .. }) => submitted_contexts += 1,
                    Ok(PoiPrivateApplyOutcome::Skipped) => {}
                    Err(_) => {
                        warn!(
                            chain_id,
                            "failed to atomically persist pending output POI submitted state"
                        );
                    }
                }
            }
            PendingOutputPoiRemoteAttempt::Failed { error: err } => {
                if !pending_output_poi_submission_side_effect_current(
                    authority,
                    cache_store,
                    &record,
                    cfg,
                    active_list_keys,
                    &plan,
                )
                .await?
                {
                    continue;
                }
                if apply_poi_private_delta(
                    authority,
                    db,
                    cache_store,
                    cfg,
                    OwnedPoiPrivateDelta::PendingSubmission {
                        expected_output,
                        expected_context_fingerprint,
                        expected_recovery: plan.expected_recovery.clone(),
                        active_list_keys: active_list_keys.to_vec(),
                        list_keys: plan.list_keys.clone(),
                        predicate: plan.predicate(),
                        merge_submitted_list_keys: false,
                        action: OutputPoiRecoveryAction::SubmitFailed {
                            error: err.to_string(),
                            retry_after: OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
                        },
                        now,
                    },
                )
                .await
                .is_err()
                {
                    warn!(
                        chain_id,
                        "failed to atomically persist pending output POI submit-failure state"
                    );
                }
                warn!(
                    chain_id,
                    "pending output POI submission failed; keeping context retryable"
                );
            }
        }
    }
    Ok(submitted_contexts)
}

#[cfg(test)]
async fn submit_observed_pending_output_pois_unchecked(
    db: &DbStore,
    chain_id: u64,
    wallet_id: &str,
    submitter: &dyn PendingOutputPoiSubmitter,
    force_submission_retry: bool,
) -> Result<usize, local_db::DbError> {
    let records = db.list_pending_output_poi_contexts(chain_id, wallet_id)?;
    let mut submitted_contexts = 0;
    let now = now_epoch_secs();
    for mut record in records {
        let Some(observation) = record.observation.clone() else {
            continue;
        };
        if record.terminal_error.is_some() {
            continue;
        }
        let recovery =
            db.get_output_poi_recovery(chain_id, &record.wallet_id, &record.output_commitment)?;
        let mut missing_list_keys = record.missing_list_keys();
        if missing_list_keys.is_empty()
            && recovery
                .as_ref()
                .is_some_and(|record| record.submission_retry_allowed(now, force_submission_retry))
        {
            missing_list_keys = record.list_keys();
        }
        if missing_list_keys.is_empty() {
            continue;
        }
        let pre_transaction_pois = record.retain_poi_lists(&missing_list_keys);
        if pre_transaction_pois.len() != missing_list_keys.len() {
            record.terminal_error =
                Some("missing pre-transaction POI for pending output".to_string());
            db.put_pending_output_poi_context(&record)?;
            continue;
        }
        let context = SingleCommitmentProofContext {
            txid_version: record.txid_version.clone(),
            railgun_txid: record.railgun_txid,
            utxo_tree_in: record.utxo_tree_in,
            commitment: record.output_commitment,
            npk: record.output_npk,
            pre_transaction_pois_per_txid_leaf_per_list: pre_transaction_pois,
        };
        if pending_output_poi_submit_identity(&record, &observation).is_none() {
            warn!(
                chain_id,
                "pending output POI context has invalid output tree"
            );
            continue;
        }
        let submitted_list_keys = missing_list_keys.clone();
        debug!(
            chain_id,
            poi_lists = submitted_list_keys.len(),
            "submitting unchecked pending output POI context"
        );
        match submit_pending_output_poi_context_unchecked(
            submitter,
            chain_id,
            &record,
            &context,
            &observation,
            &submitted_list_keys,
        )
        .await
        {
            Ok(()) => {
                if !pending_output_poi_context_still_current_unchecked(
                    db, chain_id, wallet_id, &record,
                )? {
                    continue;
                }
                for list_key in &submitted_list_keys {
                    if !record.submitted_poi_list_keys.contains(list_key) {
                        record.submitted_poi_list_keys.push(*list_key);
                    }
                }
                let recovery_update = pending_output_poi_recovery_update(
                    db,
                    chain_id,
                    &record,
                    &observation,
                    now,
                    OutputPoiRecoveryAction::Submitted {
                        retry_after: PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER,
                    },
                )?;
                db.put_pending_output_poi_context(&record)?;
                db.put_output_poi_recovery(&recovery_update)?;
                submitted_contexts += 1;
            }
            Err(err) => {
                if !pending_output_poi_context_still_current_unchecked(
                    db, chain_id, wallet_id, &record,
                )? {
                    continue;
                }
                if let Some(mut recovery) = recovery.clone() {
                    recovery.apply_action(
                        OutputPoiRecoveryAction::SubmitFailed {
                            error: err.to_string(),
                            retry_after: OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
                        },
                        now,
                    );
                    db.put_output_poi_recovery(&recovery)?;
                }
                warn!(
                    chain_id,
                    "pending output POI submission failed; keeping context retryable"
                );
            }
        }
    }
    Ok(submitted_contexts)
}

async fn submit_pending_output_poi_context_via_gateway(
    authority: &WalletPrivateMutationAuthority<'_>,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    plan: &PendingOutputPoiSubmissionPlan,
    private_poi: &WalletPrivatePoiClients,
    chain_id: u64,
    record: &PendingOutputPoiContextRecord,
    context: &SingleCommitmentProofContext,
    observation: &PendingOutputPoiObservation,
    submitted_list_keys: &[FixedBytes<32>],
) -> Result<PendingOutputPoiRemoteAttempt, WalletCacheError> {
    if let Some(txid_merkleroot_index) = record.txid_merkleroot_index {
        for list_key in submitted_list_keys {
            let Some(per_leaf) = context
                .pre_transaction_pois_per_txid_leaf_per_list
                .get(list_key)
            else {
                continue;
            };
            for poi in per_leaf.values() {
                let result = private_poi
                    .submit_transact_proof(
                        || async {
                            Ok(matches!(
                                pending_output_poi_submission_plan_current(
                                    authority,
                                    cache_store,
                                    cfg,
                                    active_list_keys,
                                    record,
                                    plan,
                                )
                                .await?,
                                PendingOutputPoiPreflight::Ready
                            ))
                        },
                        &record.txid_version,
                        EVM_CHAIN_TYPE,
                        chain_id,
                        list_key,
                        txid_merkleroot_index,
                        poi,
                    )
                    .await;
                match result {
                    Ok(()) => {}
                    Err(WalletPrivateRemoteError::Stale(WalletPrivateRemoteStale::Authority)) => {
                        return Ok(PendingOutputPoiRemoteAttempt::AuthorityStale);
                    }
                    Err(WalletPrivateRemoteError::Stale(WalletPrivateRemoteStale::Subject)) => {
                        return Ok(PendingOutputPoiRemoteAttempt::NotCurrent);
                    }
                    Err(WalletPrivateRemoteError::Check(error)) => return Err(error),
                    Err(WalletPrivateRemoteError::Remote(error)) => {
                        return Ok(PendingOutputPoiRemoteAttempt::Failed { error });
                    }
                }
            }
        }
        Ok(PendingOutputPoiRemoteAttempt::Succeeded {
            submitted_list_keys: submitted_list_keys.to_vec(),
        })
    } else {
        let result = private_poi
            .submit_single_commitment_proofs(
                || async {
                    Ok(matches!(
                        pending_output_poi_submission_plan_current(
                            authority,
                            cache_store,
                            cfg,
                            active_list_keys,
                            record,
                            plan,
                        )
                        .await?,
                        PendingOutputPoiPreflight::Ready
                    ))
                },
                &record.txid_version,
                EVM_CHAIN_TYPE,
                chain_id,
                context,
                observation.output_tree,
                observation.output_position,
            )
            .await;
        match result {
            Ok(()) => Ok(PendingOutputPoiRemoteAttempt::Succeeded {
                submitted_list_keys: submitted_list_keys.to_vec(),
            }),
            Err(WalletPrivateRemoteError::Stale(WalletPrivateRemoteStale::Authority)) => {
                Ok(PendingOutputPoiRemoteAttempt::AuthorityStale)
            }
            Err(WalletPrivateRemoteError::Stale(WalletPrivateRemoteStale::Subject)) => {
                Ok(PendingOutputPoiRemoteAttempt::NotCurrent)
            }
            Err(WalletPrivateRemoteError::Check(error)) => Err(error),
            Err(WalletPrivateRemoteError::Remote(error)) => {
                Ok(PendingOutputPoiRemoteAttempt::Failed { error })
            }
        }
    }
}

pub(super) fn new_pending_output_poi_recovery_record(
    chain_id: u64,
    record: &PendingOutputPoiContextRecord,
    observation: &PendingOutputPoiObservation,
    status: OutputPoiRecoveryStatus,
    now: u64,
) -> OutputPoiRecoveryRecord {
    OutputPoiRecoveryRecord {
        chain_id,
        wallet_id: record.wallet_id.clone(),
        output_commitment: record.output_commitment,
        source_tx_hash: observation.tx_hash,
        tx_input: None,
        status,
        created_at: now,
        updated_at: now,
        last_detection_at: None,
        last_submission_at: None,
        next_retry_at: None,
        attempt_count: 0,
        last_error: None,
    }
}

#[cfg(test)]
fn put_pending_output_poi_recovery_record_unchecked(
    db: &DbStore,
    chain_id: u64,
    record: &PendingOutputPoiContextRecord,
    observation: &PendingOutputPoiObservation,
    now: u64,
    action: OutputPoiRecoveryAction,
) -> Result<(), local_db::DbError> {
    let recovery =
        pending_output_poi_recovery_update(db, chain_id, record, observation, now, action)?;
    db.put_output_poi_recovery(&recovery)
}

#[cfg(test)]
pub(super) fn pending_output_poi_recovery_update(
    db: &DbStore,
    chain_id: u64,
    record: &PendingOutputPoiContextRecord,
    observation: &PendingOutputPoiObservation,
    now: u64,
    action: OutputPoiRecoveryAction,
) -> Result<OutputPoiRecoveryRecord, local_db::DbError> {
    let existing =
        db.get_output_poi_recovery(chain_id, &record.wallet_id, &record.output_commitment)?;
    let default_status = match &action {
        OutputPoiRecoveryAction::Detected { status, .. } => *status,
        OutputPoiRecoveryAction::CacheTxInput { .. } | OutputPoiRecoveryAction::ExtendContext => {
            OutputPoiRecoveryStatus::Recoverable
        }
        OutputPoiRecoveryAction::Submitted { .. } => OutputPoiRecoveryStatus::Submitted,
        OutputPoiRecoveryAction::SubmitFailed { .. } => OutputPoiRecoveryStatus::SubmitFailed,
        OutputPoiRecoveryAction::Valid => OutputPoiRecoveryStatus::Valid,
    };
    let mut recovery = existing.unwrap_or_else(|| {
        new_pending_output_poi_recovery_record(chain_id, record, observation, default_status, now)
    });
    recovery.apply_action(action, now);
    Ok(recovery)
}

fn expected_poi_status_matches(
    poi: &UtxoPoiMetadata,
    list_keys: &[FixedBytes<32>],
    expected: ExpectedPoiStatus,
) -> bool {
    match expected {
        ExpectedPoiStatus::Recoverable => poi_statuses_are_recoverable_for_lists(poi, list_keys),
        ExpectedPoiStatus::Valid => poi.is_valid_for_lists(list_keys),
    }
}

fn poi_statuses_are_recoverable_for_lists(
    poi: &UtxoPoiMetadata,
    list_keys: &[FixedBytes<32>],
) -> bool {
    list_keys.iter().all(|list_key| {
        poi.statuses
            .get(list_key)
            .is_none_or(|status| status.is_recoverable())
    })
}

fn expected_pending_context_matches(
    expected: &ExpectedRecordState,
    current: Option<&PendingOutputPoiContextRecord>,
) -> bool {
    match (expected, current) {
        (ExpectedRecordState::Absent, None) => true,
        (ExpectedRecordState::Present(expected), Some(current)) => {
            pending_output_poi_context_fingerprint(current).as_ref() == Some(expected)
        }
        _ => false,
    }
}

fn expected_recovery_matches(
    expected: &ExpectedRecordState,
    current: Option<&OutputPoiRecoveryRecord>,
) -> bool {
    match (expected, current) {
        (ExpectedRecordState::Absent, None) => true,
        (ExpectedRecordState::Present(expected), Some(current)) => {
            output_poi_recovery_fingerprint(current).as_ref() == Some(expected)
        }
        _ => false,
    }
}

fn pending_submission_predicate_matches(
    context: &PendingOutputPoiContextRecord,
    list_keys: &[FixedBytes<32>],
    predicate: PendingOutputPoiSubmissionPredicate,
) -> bool {
    let context_list_keys = context.list_keys();
    match predicate {
        PendingOutputPoiSubmissionPredicate::Missing => {
            let missing = context.missing_list_keys();
            list_keys.iter().all(|list_key| missing.contains(list_key))
        }
        PendingOutputPoiSubmissionPredicate::RetrySubmitted => list_keys.iter().all(|list_key| {
            context_list_keys.contains(list_key)
                && context.submitted_poi_list_keys.contains(list_key)
        }),
        PendingOutputPoiSubmissionPredicate::ForceMatching => list_keys
            .iter()
            .all(|list_key| context_list_keys.contains(list_key)),
    }
}

fn prune_nonrecoverable_unsubmitted_poi_lists(
    context: &mut PendingOutputPoiContextRecord,
    poi: &UtxoPoiMetadata,
    active_list_keys: &[FixedBytes<32>],
) {
    let submitted_poi_list_keys = context.submitted_poi_list_keys.clone();
    let should_retain = |list_key: &FixedBytes<32>| {
        submitted_poi_list_keys.contains(list_key)
            || !active_list_keys.contains(list_key)
            || poi
                .statuses
                .get(list_key)
                .is_none_or(|status| status.is_recoverable())
    };
    context.required_poi_list_keys.retain(&should_retain);
    context
        .pre_transaction_pois_per_txid_leaf_per_list
        .retain(|list_key, _| should_retain(list_key));
}

pub(super) const fn output_poi_recovery_default_status(
    action: &OutputPoiRecoveryAction,
) -> OutputPoiRecoveryStatus {
    match action {
        OutputPoiRecoveryAction::Detected { status, .. } => *status,
        OutputPoiRecoveryAction::CacheTxInput { .. } | OutputPoiRecoveryAction::ExtendContext => {
            OutputPoiRecoveryStatus::Recoverable
        }
        OutputPoiRecoveryAction::Submitted { .. } => OutputPoiRecoveryStatus::Submitted,
        OutputPoiRecoveryAction::SubmitFailed { .. } => OutputPoiRecoveryStatus::SubmitFailed,
        OutputPoiRecoveryAction::Valid => OutputPoiRecoveryStatus::Valid,
    }
}

/// Route private POI durable writes: jobs re-enter the actor; tests/inline use short permit.
///
/// Invariant: only the wallet actor turn mutates private UTXO mirrors. Jobs must attach
/// [`WalletPrivateApplyClient`] via [`WalletPrivateMutationAuthority::with_apply_client`].
pub(super) async fn apply_poi_private_delta(
    authority: &WalletPrivateMutationAuthority<'_>,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    delta: OwnedPoiPrivateDelta,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    if let Some(client) = authority.apply_client() {
        return client.apply(authority.reset_generation(), delta).await;
    }
    apply_poi_private_delta_inline(authority, db, cache_store, cfg, delta).await
}

/// Actor-turn apply of an owned POI delta (sole private writer path).
pub(super) async fn apply_owned_poi_private_delta_on_actor(
    handle: &WalletHandle,
    cancel: &CancellationToken,
    reset_generation: u64,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    delta: OwnedPoiPrivateDelta,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    let authority = WalletPrivateMutationAuthority::new(handle, reset_generation, cancel);
    apply_poi_private_delta_inline(&authority, db, cache_store, cfg, delta).await
}

/// Exclusive apply: acquire → fresh snapshot → fold → durable commit → mirrors → drop.
/// Call only from the actor turn (or single-threaded tests without an apply client).
async fn apply_poi_private_delta_inline(
    authority: &WalletPrivateMutationAuthority<'_>,
    _db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    delta: OwnedPoiPrivateDelta,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    let permit = authority
        .acquire()
        .await
        .map_err(|_| WalletCacheError::Crypto)?;
    let mut snapshot = permit
        .wallet_utxos()
        .await
        .map_err(|_| WalletCacheError::Crypto)?;
    match delta {
        OwnedPoiPrivateDelta::OutputRecovery {
            expected_output,
            active_list_keys,
            required_poi_status,
            pending_update,
            expected_recovery,
            action,
            now,
        } => {
            let Some(wallet_utxo) = snapshot
                .iter()
                .find(|wallet_utxo| expected_output.matches(wallet_utxo))
            else {
                drop(permit);
                return Ok(PoiPrivateApplyOutcome::Skipped);
            };
            if active_list_keys.is_empty()
                || !expected_poi_status_matches(
                    &wallet_utxo.utxo.poi,
                    &active_list_keys,
                    required_poi_status,
                )
            {
                drop(permit);
                return Ok(PoiPrivateApplyOutcome::Skipped);
            }

            let pending_update = if let Some((expected_pending, update)) = *pending_update {
                let current = cache_store.get_pending_output_poi_context(
                    cfg.chain.chain_id,
                    &cfg.cache_key,
                    &expected_output.output_commitment(),
                )?;
                if !expected_pending_context_matches(&expected_pending, current.as_ref())
                    || !pending_output_poi_context_matches_wallet_utxo(cfg, wallet_utxo, &update)
                {
                    drop(permit);
                    return Ok(PoiPrivateApplyOutcome::Skipped);
                }
                Some(update)
            } else {
                None
            };
            let current_recovery = cache_store.get_output_poi_recovery(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &expected_output.output_commitment(),
            )?;
            let valid_recovery_is_stale_for_subset = current_recovery
                .as_ref()
                .is_some_and(|record| record.status == OutputPoiRecoveryStatus::Valid)
                && required_poi_status == ExpectedPoiStatus::Recoverable;
            if !expected_recovery_matches(&expected_recovery, current_recovery.as_ref())
                || current_recovery
                    .as_ref()
                    .is_some_and(|record| record.source_tx_hash != wallet_utxo.utxo.source.tx_hash)
                || (current_recovery
                    .as_ref()
                    .is_some_and(|record| record.status == OutputPoiRecoveryStatus::Valid)
                    && !valid_recovery_is_stale_for_subset
                    && !matches!(&action, OutputPoiRecoveryAction::Valid))
            {
                drop(permit);
                return Ok(PoiPrivateApplyOutcome::Skipped);
            }
            let mut recovery = current_recovery.unwrap_or_else(|| {
                new_output_poi_recovery_record(
                    cfg,
                    wallet_utxo,
                    output_poi_recovery_default_status(&action),
                    now,
                )
            });
            recovery.apply_action(action, now);
            let pending_updates: Vec<_> = pending_update.into_iter().collect();
            let recovery_updates = [recovery];
            let result = permit.with_durable_apply(|token| {
                cache_store.commit_wallet_private_state(
                    WalletPrivateCommit::new(
                        &token,
                        &permit,
                        cfg.chain.chain_id,
                        WalletUtxoMutation::Preserve,
                        WalletCheckpointMutation::Preserve,
                    )
                    .with_pending_output_context_updates(&pending_updates)
                    .with_output_poi_recovery_updates(&recovery_updates),
                )
            });
            drop(permit);
            match result {
                Ok(Ok(())) => Ok(PoiPrivateApplyOutcome::Applied {
                    utxo_changed: false,
                }),
                Ok(Err(err)) => Err(err),
                Err(_) => Err(WalletCacheError::Crypto),
            }
        }
        OwnedPoiPrivateDelta::PendingSubmission {
            expected_output,
            expected_context_fingerprint,
            expected_recovery,
            active_list_keys,
            list_keys,
            predicate,
            merge_submitted_list_keys,
            action,
            now,
        } => {
            let Some(wallet_utxo) = snapshot
                .iter()
                .find(|wallet_utxo| expected_output.matches(wallet_utxo))
            else {
                drop(permit);
                return Ok(PoiPrivateApplyOutcome::Skipped);
            };
            if active_list_keys.is_empty()
                || list_keys.is_empty()
                || list_keys
                    .iter()
                    .any(|list_key| !active_list_keys.contains(list_key))
                || !poi_statuses_are_recoverable_for_lists(&wallet_utxo.utxo.poi, &list_keys)
            {
                drop(permit);
                return Ok(PoiPrivateApplyOutcome::Skipped);
            }
            let Some(mut current_context) = cache_store.get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &expected_output.output_commitment(),
            )?
            else {
                drop(permit);
                return Ok(PoiPrivateApplyOutcome::Skipped);
            };
            if pending_output_poi_context_fingerprint(&current_context).as_ref()
                != Some(&expected_context_fingerprint)
                || current_context.terminal_error.is_some()
                || !pending_submission_predicate_matches(&current_context, &list_keys, predicate)
            {
                drop(permit);
                return Ok(PoiPrivateApplyOutcome::Skipped);
            }
            let current_recovery = cache_store.get_output_poi_recovery(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &expected_output.output_commitment(),
            )?;
            if !expected_recovery_matches(&expected_recovery, current_recovery.as_ref())
                || current_recovery
                    .as_ref()
                    .is_some_and(|record| record.status == OutputPoiRecoveryStatus::Valid)
            {
                drop(permit);
                return Ok(PoiPrivateApplyOutcome::Skipped);
            }
            let Some(observation) = current_context.observation.clone() else {
                drop(permit);
                return Ok(PoiPrivateApplyOutcome::Skipped);
            };
            if current_recovery
                .as_ref()
                .is_some_and(|record| record.source_tx_hash != observation.tx_hash)
            {
                drop(permit);
                return Ok(PoiPrivateApplyOutcome::Skipped);
            }
            if merge_submitted_list_keys {
                for list_key in &list_keys {
                    if !current_context.submitted_poi_list_keys.contains(list_key) {
                        current_context.submitted_poi_list_keys.push(*list_key);
                    }
                }
                prune_nonrecoverable_unsubmitted_poi_lists(
                    &mut current_context,
                    &wallet_utxo.utxo.poi,
                    &active_list_keys,
                );
            }
            let mut recovery = current_recovery.unwrap_or_else(|| {
                new_pending_output_poi_recovery_record(
                    cfg.chain.chain_id,
                    &current_context,
                    &observation,
                    output_poi_recovery_default_status(&action),
                    now,
                )
            });
            recovery.apply_action(action, now);
            let pending_updates: Vec<_> = merge_submitted_list_keys
                .then_some(current_context)
                .into_iter()
                .collect();
            let recovery_updates = [recovery];
            let result = permit.with_durable_apply(|token| {
                cache_store.commit_wallet_private_state(
                    WalletPrivateCommit::new(
                        &token,
                        &permit,
                        cfg.chain.chain_id,
                        WalletUtxoMutation::Preserve,
                        WalletCheckpointMutation::Preserve,
                    )
                    .with_pending_output_context_updates(&pending_updates)
                    .with_output_poi_recovery_updates(&recovery_updates),
                )
            });
            drop(permit);
            match result {
                Ok(Ok(())) => Ok(PoiPrivateApplyOutcome::Applied {
                    utxo_changed: false,
                }),
                Ok(Err(err)) => Err(err),
                Err(_) => Err(WalletCacheError::Crypto),
            }
        }
        OwnedPoiPrivateDelta::PendingContextTerminal {
            expected_output,
            expected_context_fingerprint,
            active_list_keys,
            error,
        } => {
            let Some(wallet_utxo) = snapshot
                .iter()
                .find(|wallet_utxo| expected_output.matches(wallet_utxo))
            else {
                drop(permit);
                return Ok(PoiPrivateApplyOutcome::Skipped);
            };
            if active_list_keys.is_empty()
                || !poi_statuses_are_recoverable_for_lists(&wallet_utxo.utxo.poi, &active_list_keys)
            {
                drop(permit);
                return Ok(PoiPrivateApplyOutcome::Skipped);
            }
            let Some(mut current_context) = cache_store.get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &expected_output.output_commitment(),
            )?
            else {
                drop(permit);
                return Ok(PoiPrivateApplyOutcome::Skipped);
            };
            if pending_output_poi_context_fingerprint(&current_context).as_ref()
                != Some(&expected_context_fingerprint)
            {
                drop(permit);
                return Ok(PoiPrivateApplyOutcome::Skipped);
            }
            current_context.terminal_error = Some(error);
            let pending_updates = [current_context];
            let result = permit.with_durable_apply(|token| {
                cache_store.commit_wallet_private_state(
                    WalletPrivateCommit::new(
                        &token,
                        &permit,
                        cfg.chain.chain_id,
                        WalletUtxoMutation::Preserve,
                        WalletCheckpointMutation::Preserve,
                    )
                    .with_pending_output_context_updates(&pending_updates),
                )
            });
            drop(permit);
            match result {
                Ok(Ok(())) => Ok(PoiPrivateApplyOutcome::Applied {
                    utxo_changed: false,
                }),
                Ok(Err(err)) => Err(err),
                Err(_) => Err(WalletCacheError::Crypto),
            }
        }
        OwnedPoiPrivateDelta::VerifiedValid {
            output_commitment,
            expected_context_fingerprint,
            expected_output,
            expected_poi_list_state,
            active_list_keys,
            valid_list_keys,
            now,
        } => {
            let Some(wallet_utxo) = snapshot
                .iter_mut()
                .find(|wallet_utxo| expected_output.matches(wallet_utxo))
            else {
                drop(permit);
                return Ok(PoiPrivateApplyOutcome::Skipped);
            };
            let Some(current_context) = cache_store.get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &output_commitment,
            )?
            else {
                drop(permit);
                return Ok(PoiPrivateApplyOutcome::Skipped);
            };
            let current_list_keys = current_context.list_keys();
            if active_list_keys.is_empty()
                || valid_list_keys.is_empty()
                || valid_list_keys
                    .iter()
                    .any(|list_key| !active_list_keys.contains(list_key))
                || !expected_poi_list_state
                    .matches_recoverable_or_valid(&wallet_utxo.utxo.poi, &valid_list_keys)
                || pending_output_poi_context_fingerprint(&current_context).as_ref()
                    != Some(&expected_context_fingerprint)
                || !pending_output_poi_context_matches_wallet_utxo(
                    cfg,
                    wallet_utxo,
                    &current_context,
                )
                || valid_list_keys.iter().any(|list_key| {
                    !current_list_keys.contains(list_key)
                        || !current_context.submitted_poi_list_keys.contains(list_key)
                })
            {
                drop(permit);
                return Ok(PoiPrivateApplyOutcome::Skipped);
            }
            let valid_statuses = valid_list_keys
                .iter()
                .copied()
                .map(|list_key| (list_key, PoiStatus::Valid))
                .collect::<BTreeMap<_, _>>();
            let refreshed_at = wallet_utxo
                .utxo
                .poi
                .refreshed_at
                .map_or(now, |current| current.max(now));
            let changed = wallet_utxo.utxo.poi.apply_status_refresh(
                &valid_list_keys,
                Some(&valid_statuses),
                refreshed_at,
            ) > 0;
            let recovery_action = if wallet_utxo
                .utxo
                .poi
                .has_recoverable_status_for_lists(&active_list_keys)
            {
                OutputPoiRecoveryAction::Detected {
                    status: OutputPoiRecoveryStatus::Recoverable,
                    retry_after: None,
                    last_error: None,
                    increment_attempts: false,
                }
            } else {
                OutputPoiRecoveryAction::Valid
            };
            let current_recovery = cache_store.get_output_poi_recovery(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &output_commitment,
            )?;
            let mut recovery = match current_recovery {
                Some(recovery) if recovery.source_tx_hash == wallet_utxo.utxo.source.tx_hash => {
                    recovery
                }
                _ => new_output_poi_recovery_record(
                    cfg,
                    wallet_utxo,
                    output_poi_recovery_default_status(&recovery_action),
                    now,
                ),
            };
            recovery.apply_action(recovery_action, now);
            let recovery_updates_owned = [recovery];
            let pending_deletes_owned = [output_commitment];
            let mut utxos_locked = if changed {
                Some(permit.handle_utxos().write().await)
            } else {
                None
            };
            let result = permit.with_active_apply(|token| {
                cache_store.commit_wallet_private_state(
                    WalletPrivateCommit::new(
                        &token,
                        &permit,
                        cfg.chain.chain_id,
                        if changed {
                            WalletUtxoMutation::Replace(&snapshot)
                        } else {
                            WalletUtxoMutation::Preserve
                        },
                        WalletCheckpointMutation::Preserve,
                    )
                    .with_pending_output_context_deletes(&pending_deletes_owned)
                    .with_output_poi_recovery_updates(&recovery_updates_owned),
                )?;
                if let Some(locked) = utxos_locked.as_mut() {
                    **locked = std::mem::take(&mut snapshot);
                }
                if changed {
                    let overlay = permit
                        .pending_overlay()
                        .try_read()
                        .map(|guard| guard.clone())
                        .unwrap_or_default();
                    let utxos = utxos_locked
                        .as_ref()
                        .map_or(&[] as &[WalletUtxo], |locked| locked.as_slice());
                    permit.apply_notify_changed(&token, utxos, &overlay);
                }
                Ok::<(), WalletCacheError>(())
            });
            drop(utxos_locked);
            drop(permit);
            match result {
                Ok(Ok(())) => Ok(PoiPrivateApplyOutcome::Applied {
                    utxo_changed: changed,
                }),
                Ok(Err(err)) => Err(err),
                Err(_) => Ok(PoiPrivateApplyOutcome::Skipped),
            }
        }
        OwnedPoiPrivateDelta::PoiStatusRefresh {
            active_list_keys,
            expected_poi_by_blinded_commitment,
            statuses_by_blinded_commitment,
            refreshed_at,
        } => {
            let mut changed = false;
            for wallet_utxo in snapshot.iter_mut().filter(|utxo| !utxo.is_spent()) {
                let Some(statuses) =
                    statuses_by_blinded_commitment.get(&wallet_utxo.utxo.poi.blinded_commitment)
                else {
                    continue;
                };
                if expected_poi_by_blinded_commitment.get(&wallet_utxo.utxo.poi.blinded_commitment)
                    != Some(&wallet_utxo.utxo.poi)
                {
                    continue;
                }
                changed |= wallet_utxo.utxo.poi.apply_status_refresh(
                    &active_list_keys,
                    Some(statuses),
                    refreshed_at,
                ) > 0;
            }
            if !changed {
                drop(permit);
                return Ok(PoiPrivateApplyOutcome::Skipped);
            }
            let mut utxos_locked = permit.handle_utxos().write().await;
            let result = permit.with_active_apply(|token| {
                cache_store.commit_wallet_private_state(WalletPrivateCommit::new(
                    &token,
                    &permit,
                    cfg.chain.chain_id,
                    WalletUtxoMutation::Replace(&snapshot),
                    WalletCheckpointMutation::Preserve,
                ))?;
                *utxos_locked = snapshot;
                let overlay = permit
                    .pending_overlay()
                    .try_read()
                    .map(|guard| guard.clone())
                    .unwrap_or_default();
                permit.apply_notify_changed(&token, &utxos_locked, &overlay);
                Ok::<(), WalletCacheError>(())
            });
            drop(utxos_locked);
            drop(permit);
            match result {
                Ok(Ok(())) => Ok(PoiPrivateApplyOutcome::Applied { utxo_changed: true }),
                Ok(Err(err)) => Err(err),
                Err(_) => Ok(PoiPrivateApplyOutcome::Skipped),
            }
        }
    }
}

#[cfg(test)]
fn ensure_pending_output_poi_submission_state_unchecked(
    db: &DbStore,
    chain_id: u64,
    record: &PendingOutputPoiContextRecord,
    observation: &PendingOutputPoiObservation,
    now: u64,
) -> Result<(), local_db::DbError> {
    if db
        .get_output_poi_recovery(chain_id, &record.wallet_id, &record.output_commitment)?
        .is_some()
    {
        return Ok(());
    }
    put_pending_output_poi_recovery_record_unchecked(
        db,
        chain_id,
        record,
        observation,
        now,
        OutputPoiRecoveryAction::Submitted {
            retry_after: PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER,
        },
    )
}

#[cfg(test)]
pub(super) async fn submit_pending_output_poi_context(
    submitter: &dyn PendingOutputPoiSubmitter,
    chain_id: u64,
    record: &PendingOutputPoiContextRecord,
    context: &SingleCommitmentProofContext,
    observation: &PendingOutputPoiObservation,
    submitted_list_keys: &[FixedBytes<32>],
) -> Result<(), PoiError> {
    submit_pending_output_poi_context_unchecked(
        submitter,
        chain_id,
        record,
        context,
        observation,
        submitted_list_keys,
    )
    .await
}

#[cfg(test)]
async fn submit_pending_output_poi_context_unchecked(
    submitter: &dyn PendingOutputPoiSubmitter,
    chain_id: u64,
    record: &PendingOutputPoiContextRecord,
    context: &SingleCommitmentProofContext,
    observation: &PendingOutputPoiObservation,
    submitted_list_keys: &[FixedBytes<32>],
) -> Result<(), PoiError> {
    if let Some(txid_merkleroot_index) = record.txid_merkleroot_index {
        for list_key in submitted_list_keys {
            let Some(per_leaf) = context
                .pre_transaction_pois_per_txid_leaf_per_list
                .get(list_key)
            else {
                continue;
            };
            for poi in per_leaf.values() {
                submitter
                    .submit_transact_proof(
                        &record.txid_version,
                        EVM_CHAIN_TYPE,
                        chain_id,
                        list_key,
                        txid_merkleroot_index,
                        poi,
                    )
                    .await?;
            }
        }
        Ok(())
    } else {
        submitter
            .submit_single_commitment_proofs(
                &record.txid_version,
                EVM_CHAIN_TYPE,
                chain_id,
                context,
                observation.output_tree,
                observation.output_position,
            )
            .await
    }
}

pub(super) struct PendingOutputPoiSubmitIdentity {
    pub(super) derived_blinded_commitment: FixedBytes<32>,
}

pub(super) fn pending_output_poi_submit_identity(
    record: &PendingOutputPoiContextRecord,
    observation: &PendingOutputPoiObservation,
) -> Option<PendingOutputPoiSubmitIdentity> {
    let output_tree = u32::try_from(observation.output_tree).ok()?;
    record.txid_leaf_hash()?;
    Some(PendingOutputPoiSubmitIdentity {
        derived_blinded_commitment: UtxoPoiMetadata::blinded_commitment_for(
            record.output_commitment,
            record.output_npk,
            output_tree,
            observation.output_position,
        ),
    })
}

pub(super) fn pending_output_poi_context_matches_wallet_utxo(
    cfg: &WalletConfig,
    wallet_utxo: &WalletUtxo,
    record: &PendingOutputPoiContextRecord,
) -> bool {
    if record.chain_id != cfg.chain.chain_id
        || record.wallet_id != cfg.cache_key.as_str()
        || record.output_commitment != wallet_utxo.utxo.poi.commitment
    {
        return false;
    }
    let Some(observation) = record.observation.as_ref() else {
        return false;
    };
    if observation.output_tree != u64::from(wallet_utxo.utxo.tree)
        || observation.output_position != wallet_utxo.utxo.position
        || observation.tx_hash != wallet_utxo.utxo.source.tx_hash
    {
        return false;
    }
    pending_output_poi_submit_identity(record, observation).is_some_and(|identity| {
        identity.derived_blinded_commitment == wallet_utxo.utxo.poi.blinded_commitment
    })
}

/// Sole preflight gate before remote pending-output POI disclosure.
pub(super) async fn pending_output_poi_submission_plan_current(
    authority: &WalletPrivateMutationAuthority<'_>,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    expected: &PendingOutputPoiContextRecord,
    plan: &PendingOutputPoiSubmissionPlan,
) -> Result<PendingOutputPoiPreflight, WalletCacheError> {
    if authority.revalidate().is_err() {
        debug!(
            chain_id = cfg.chain.chain_id,
            "pending output POI submission skipped before plan validation"
        );
        return Ok(PendingOutputPoiPreflight::AuthorityStale);
    }
    let Some(current) = cache_store.get_pending_output_poi_context(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &expected.output_commitment,
    )?
    else {
        return Ok(PendingOutputPoiPreflight::NotCurrent);
    };
    if pending_output_poi_context_fingerprint(&current)
        != pending_output_poi_context_fingerprint(expected)
    {
        debug!(
            chain_id = cfg.chain.chain_id,
            "pending output POI submission skipped; context changed"
        );
        return Ok(PendingOutputPoiPreflight::NotCurrent);
    }
    if plan.list_keys.is_empty()
        || plan
            .list_keys
            .iter()
            .any(|list_key| !active_list_keys.contains(list_key))
    {
        return Ok(PendingOutputPoiPreflight::NotCurrent);
    }
    let current_recovery = cache_store.get_output_poi_recovery(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &expected.output_commitment,
    )?;
    if !expected_recovery_matches(&plan.expected_recovery, current_recovery.as_ref()) {
        debug!(
            chain_id = cfg.chain.chain_id,
            "pending output POI submission skipped; recovery predecessor changed"
        );
        return Ok(PendingOutputPoiPreflight::NotCurrent);
    }
    let Some(current_observation) = current.observation.as_ref() else {
        return Ok(PendingOutputPoiPreflight::NotCurrent);
    };
    if current_recovery
        .as_ref()
        .is_some_and(|recovery| recovery.source_tx_hash != current_observation.tx_hash)
    {
        debug!(
            chain_id = cfg.chain.chain_id,
            "pending output POI submission skipped; recovery source transaction does not match context observation"
        );
        return Ok(PendingOutputPoiPreflight::NotCurrent);
    }
    match plan.kind {
        PendingOutputPoiSubmissionKind::Missing => {
            let mut current_missing = current.missing_list_keys();
            current_missing.retain(|list_key| active_list_keys.contains(list_key));
            if plan
                .list_keys
                .iter()
                .any(|list_key| !current_missing.contains(list_key))
            {
                debug!(
                    chain_id = cfg.chain.chain_id,
                    "pending output POI submission skipped; missing-list state changed"
                );
                return Ok(PendingOutputPoiPreflight::NotCurrent);
            }
        }
        PendingOutputPoiSubmissionKind::RetrySubmitted => {
            let current_list_keys = current.list_keys();
            if plan.list_keys.iter().any(|list_key| {
                !current_list_keys.contains(list_key)
                    || !current.submitted_poi_list_keys.contains(list_key)
            }) {
                debug!(
                    chain_id = cfg.chain.chain_id,
                    "pending output POI retry skipped; submitted-list state changed"
                );
                return Ok(PendingOutputPoiPreflight::NotCurrent);
            }
            if !current_recovery.as_ref().is_some_and(|record| {
                record.submission_retry_allowed(now_epoch_secs(), plan.force_submission_retry)
            }) {
                debug!(
                    chain_id = cfg.chain.chain_id,
                    "pending output POI retry skipped; recovery state changed"
                );
                return Ok(PendingOutputPoiPreflight::NotCurrent);
            }
        }
        PendingOutputPoiSubmissionKind::ForceMatching => {
            let current_list_keys = current.list_keys();
            if plan
                .list_keys
                .iter()
                .any(|list_key| !current_list_keys.contains(list_key))
            {
                debug!(
                    chain_id = cfg.chain.chain_id,
                    "forced pending output POI skipped; list keys no longer on context"
                );
                return Ok(PendingOutputPoiPreflight::NotCurrent);
            }
        }
    }
    let Ok(snapshot) = authority.wallet_utxos().await else {
        debug!(
            chain_id = cfg.chain.chain_id,
            "pending output POI submission skipped before wallet state check"
        );
        return Ok(if authority.revalidate().is_err() {
            PendingOutputPoiPreflight::AuthorityStale
        } else {
            PendingOutputPoiPreflight::NotCurrent
        });
    };
    let current_output = snapshot.iter().find(|wallet_utxo| {
        !wallet_utxo.is_spent()
            && pending_output_poi_context_matches_wallet_utxo(cfg, wallet_utxo, expected)
    });
    let Some(current_output) = current_output else {
        debug!(
            chain_id = cfg.chain.chain_id,
            "pending output POI submission skipped; output no longer matches wallet state"
        );
        return Ok(PendingOutputPoiPreflight::NotCurrent);
    };
    let current_recoverable_list_keys = recoverable_pending_submission_list_keys(
        &current,
        active_list_keys,
        &current_output.utxo.poi,
        plan.predicate(),
    );
    if current_recoverable_list_keys != plan.list_keys {
        debug!(
            chain_id = cfg.chain.chain_id,
            planned_poi_lists = plan.list_keys.len(),
            current_recoverable_poi_lists = current_recoverable_list_keys.len(),
            "pending output POI submission skipped; recoverable target-list subset changed"
        );
        return Ok(PendingOutputPoiPreflight::NotCurrent);
    }
    if authority.revalidate().is_err() {
        debug!(
            chain_id = cfg.chain.chain_id,
            "pending output POI submission skipped after plan validation"
        );
        return Ok(PendingOutputPoiPreflight::AuthorityStale);
    }
    Ok(PendingOutputPoiPreflight::Ready)
}

async fn pending_output_poi_submission_side_effect_current(
    authority: &WalletPrivateMutationAuthority<'_>,
    cache_store: &dyn WalletCacheStore,
    expected: &PendingOutputPoiContextRecord,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    plan: &PendingOutputPoiSubmissionPlan,
) -> Result<bool, WalletCacheError> {
    Ok(matches!(
        pending_output_poi_submission_plan_current(
            authority,
            cache_store,
            cfg,
            active_list_keys,
            expected,
            plan,
        )
        .await?,
        PendingOutputPoiPreflight::Ready
    ))
}

/// Sole production choke point for remote pending-output POI submission:
/// preflight → build context → remote await. Durable apply remains caller's postflight.
pub(super) async fn preflight_and_remote_submit_pending_output_poi(
    authority: &WalletPrivateMutationAuthority<'_>,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    record: &PendingOutputPoiContextRecord,
    observation: &PendingOutputPoiObservation,
    plan: &PendingOutputPoiSubmissionPlan,
    private_poi: &WalletPrivatePoiClients,
) -> Result<PendingOutputPoiRemoteAttempt, WalletCacheError> {
    match pending_output_poi_submission_plan_current(
        authority,
        cache_store,
        cfg,
        active_list_keys,
        record,
        plan,
    )
    .await?
    {
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
        warn!(
            chain_id = cfg.chain.chain_id,
            "pending output POI context has invalid output tree"
        );
        return Ok(PendingOutputPoiRemoteAttempt::NotCurrent);
    }
    let context = SingleCommitmentProofContext {
        txid_version: record.txid_version.clone(),
        railgun_txid: record.railgun_txid,
        utxo_tree_in: record.utxo_tree_in,
        commitment: record.output_commitment,
        npk: record.output_npk,
        pre_transaction_pois_per_txid_leaf_per_list: pre_transaction_pois,
    };
    let submitted_list_keys = plan.list_keys.clone();
    debug!(
        chain_id = cfg.chain.chain_id,
        pre_tx_poi_lists = context.pre_transaction_pois_per_txid_leaf_per_list.len(),
        plan_kind = ?plan.kind,
        "submitting pending output POI context"
    );
    submit_pending_output_poi_context_via_gateway(
        authority,
        cache_store,
        cfg,
        active_list_keys,
        plan,
        private_poi,
        cfg.chain.chain_id,
        record,
        &context,
        observation,
        &submitted_list_keys,
    )
    .await
}

pub(super) fn pending_output_poi_context_still_current(
    authority: &WalletPrivateMutationAuthority<'_>,
    cache_store: &dyn WalletCacheStore,
    chain_id: u64,
    wallet_id: &WalletCacheKey,
    expected: &PendingOutputPoiContextRecord,
) -> Result<bool, WalletCacheError> {
    if authority.revalidate().is_err() {
        debug!(chain_id, "pending output POI context side effect rejected");
        return Ok(false);
    }
    let Some(current) = cache_store.get_pending_output_poi_context(
        chain_id,
        wallet_id,
        &expected.output_commitment,
    )?
    else {
        debug!(
            chain_id,
            "pending output POI context side effect skipped; context disappeared"
        );
        return Ok(false);
    };
    Ok(pending_output_poi_context_fingerprint(&current)
        .is_some_and(|current| Some(current) == pending_output_poi_context_fingerprint(expected)))
}

#[cfg(test)]
pub(super) fn pending_output_poi_context_still_current_unchecked(
    db: &DbStore,
    chain_id: u64,
    wallet_id: &str,
    expected: &PendingOutputPoiContextRecord,
) -> Result<bool, local_db::DbError> {
    pending_output_poi_context_still_current_impl(db, chain_id, wallet_id, expected)
}

#[cfg(test)]
fn pending_output_poi_context_still_current_impl(
    db: &DbStore,
    chain_id: u64,
    wallet_id: &str,
    expected: &PendingOutputPoiContextRecord,
) -> Result<bool, local_db::DbError> {
    let Some(current) =
        db.get_pending_output_poi_context(chain_id, wallet_id, &expected.output_commitment)?
    else {
        debug!(
            chain_id,
            "pending output POI context side effect skipped; context disappeared"
        );
        return Ok(false);
    };
    if pending_output_poi_context_fingerprint(&current)
        .is_some_and(|current| Some(current) == pending_output_poi_context_fingerprint(expected))
    {
        return Ok(true);
    }
    debug!(
        chain_id,
        "pending output POI context side effect skipped; context changed"
    );
    Ok(false)
}

pub(super) fn pending_output_poi_context_fingerprint(
    record: &PendingOutputPoiContextRecord,
) -> Option<Vec<u8>> {
    rmp_serde::to_vec(record).ok()
}

fn output_poi_recovery_fingerprint(record: &OutputPoiRecoveryRecord) -> Option<Vec<u8>> {
    rmp_serde::to_vec(record).ok()
}

pub(super) fn expected_pending_context_state(
    record: Option<&PendingOutputPoiContextRecord>,
) -> Option<ExpectedRecordState> {
    match record {
        Some(record) => {
            pending_output_poi_context_fingerprint(record).map(ExpectedRecordState::Present)
        }
        None => Some(ExpectedRecordState::Absent),
    }
}

pub(super) fn expected_recovery_state(
    record: Option<&OutputPoiRecoveryRecord>,
) -> Option<ExpectedRecordState> {
    match record {
        Some(record) => output_poi_recovery_fingerprint(record).map(ExpectedRecordState::Present),
        None => Some(ExpectedRecordState::Absent),
    }
}

#[derive(Default)]
pub(super) struct PendingOutputPoiVerificationOutcome {
    pub(super) completed: usize,
    pub(super) pending: usize,
    pub(super) errors: usize,
}

enum AuthorizedPoiStatusSource<'a> {
    Local(&'a dyn PoiStatusReader),
    Remote(&'a WalletPrivatePoiClients),
}

async fn read_pending_output_poi_statuses(
    source: &AuthorizedPoiStatusSource<'_>,
    authority: &WalletPrivateMutationAuthority<'_>,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    record: &PendingOutputPoiContextRecord,
    list_keys: &[FixedBytes<32>],
    identity: &PendingOutputPoiSubmitIdentity,
) -> Result<Option<BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PoiStatus>>>, String> {
    let request_data = [BlindedCommitmentData::transact(
        identity.derived_blinded_commitment,
    )];
    match source {
        AuthorizedPoiStatusSource::Local(reader) => reader
            .pois_per_list(
                &record.txid_version,
                EVM_CHAIN_TYPE,
                cfg.chain.chain_id,
                list_keys,
                &request_data,
            )
            .await
            .map(Some)
            .map_err(|error| error.to_string()),
        AuthorizedPoiStatusSource::Remote(private_poi) => match private_poi
            .pois_per_list(
                || async {
                    if !pending_output_poi_context_has_current_wallet_utxo(authority, cfg, record)
                        .await
                    {
                        return Ok(false);
                    }
                    pending_output_poi_context_still_current(
                        authority,
                        cache_store,
                        cfg.chain.chain_id,
                        &cfg.cache_key,
                        record,
                    )
                },
                &record.txid_version,
                EVM_CHAIN_TYPE,
                cfg.chain.chain_id,
                list_keys,
                &request_data,
            )
            .await
        {
            Ok(statuses) => Ok(Some(statuses)),
            Err(WalletPrivateRemoteError::Stale(_)) => Ok(None),
            Err(WalletPrivateRemoteError::Check(error)) => Err(error.to_string()),
            Err(WalletPrivateRemoteError::Remote(error)) => Err(error.to_string()),
        },
    }
}

#[cfg(test)]
pub(super) async fn verify_submitted_pending_output_pois_with_config(
    public_data_plane: &ChainPublicDataPlane,
    poi_runtime: &WalletPoiRuntime,
    remote_client: &PoiRpcClient,
    cfg: &WalletConfig,
    db: &DbStore,
    active_list_keys: &[FixedBytes<32>],
) -> PendingOutputPoiVerificationOutcome {
    match poi_runtime {
        WalletPoiRuntime::IndexedArtifacts { .. } => {
            let corpus = public_data_plane
                .ensure_poi_corpus(PublicPoiCorpusKey::wallet_default(cfg.chain.chain_id))
                .await
                .ok();
            if let Some(corpus) = corpus
                && public_data_plane
                    .poi_corpus_ready_for_lists(
                        PublicPoiCorpusKey::wallet_default(cfg.chain.chain_id),
                        active_list_keys,
                    )
                    .await
            {
                let reader = corpus.status_reader();
                verify_submitted_pending_output_pois(
                    &reader,
                    db,
                    cfg.chain.chain_id,
                    &cfg.cache_key,
                    active_list_keys,
                )
                .await
            } else if poi_runtime.wallet_read_fallback_enabled() {
                verify_submitted_pending_output_pois(
                    remote_client,
                    db,
                    cfg.chain.chain_id,
                    &cfg.cache_key,
                    active_list_keys,
                )
                .await
            } else {
                PendingOutputPoiVerificationOutcome::default()
            }
        }
        WalletPoiRuntime::PoiProxy { .. } => {
            verify_submitted_pending_output_pois(
                remote_client,
                db,
                cfg.chain.chain_id,
                &cfg.cache_key,
                active_list_keys,
            )
            .await
        }
    }
}

pub(super) async fn verify_submitted_pending_output_pois_with_config_authorized(
    authority: &WalletPrivateMutationAuthority<'_>,
    public_data_plane: &ChainPublicDataPlane,
    poi_runtime: &WalletPoiRuntime,
    private_poi: &WalletPrivatePoiClients,
    cfg: &WalletConfig,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    active_list_keys: &[FixedBytes<32>],
) -> PendingOutputPoiVerificationOutcome {
    // No long-lived permit across corpus readiness / remote status I/O.
    if authority.revalidate().is_err() {
        debug!(
            chain_id = cfg.chain.chain_id,
            "pending output POI verification skipped"
        );
        return PendingOutputPoiVerificationOutcome::default();
    }
    match poi_runtime {
        WalletPoiRuntime::IndexedArtifacts { .. } => {
            let key = PublicPoiCorpusKey::wallet_default(cfg.chain.chain_id);
            if public_data_plane
                .poi_corpus_ready_for_lists(key.clone(), active_list_keys)
                .await
            {
                let Ok(corpus) = public_data_plane.ensure_poi_corpus(key).await else {
                    warn!(
                        chain_id = cfg.chain.chain_id,
                        "artifact POI corpus unavailable"
                    );
                    return PendingOutputPoiVerificationOutcome::default();
                };
                let reader = corpus.status_reader();
                verify_submitted_pending_output_pois_inner(
                    authority,
                    AuthorizedPoiStatusSource::Local(&reader),
                    db,
                    cfg,
                    cache_store,
                    active_list_keys,
                )
                .await
            } else if poi_runtime.wallet_read_fallback_enabled() {
                verify_submitted_pending_output_pois_inner(
                    authority,
                    AuthorizedPoiStatusSource::Remote(private_poi),
                    db,
                    cfg,
                    cache_store,
                    active_list_keys,
                )
                .await
            } else {
                warn!(
                    chain_id = cfg.chain.chain_id,
                    "artifact POI local cache unavailable; skipping submitted pending output POI verification"
                );
                PendingOutputPoiVerificationOutcome::default()
            }
        }
        WalletPoiRuntime::PoiProxy { .. } => {
            verify_submitted_pending_output_pois_inner(
                authority,
                AuthorizedPoiStatusSource::Remote(private_poi),
                db,
                cfg,
                cache_store,
                active_list_keys,
            )
            .await
        }
    }
}

#[cfg(test)]
pub(super) async fn verify_submitted_pending_output_pois_authorized(
    authority: &WalletPrivateMutationAuthority<'_>,
    status_reader: &dyn PoiStatusReader,
    db: &DbStore,
    chain_id: u64,
    wallet_id: &str,
    active_list_keys: &[FixedBytes<32>],
) -> PendingOutputPoiVerificationOutcome {
    if authority.revalidate().is_err() {
        debug!(chain_id, "pending output POI verification skipped");
        return PendingOutputPoiVerificationOutcome::default();
    }
    verify_submitted_pending_output_pois_check_only(
        authority,
        status_reader,
        db,
        chain_id,
        wallet_id,
        active_list_keys,
    )
    .await
}

#[cfg(test)]
pub(super) async fn verify_submitted_pending_output_pois_authorized_with_projection(
    authority: &WalletPrivateMutationAuthority<'_>,
    status_reader: &dyn PoiStatusReader,
    db: &DbStore,
    cfg: &WalletConfig,
    cache_store: &dyn WalletCacheStore,
    active_list_keys: &[FixedBytes<32>],
) -> PendingOutputPoiVerificationOutcome {
    if authority.revalidate().is_err() {
        debug!(
            chain_id = cfg.chain.chain_id,
            "pending output POI verification skipped"
        );
        return PendingOutputPoiVerificationOutcome::default();
    }
    verify_submitted_pending_output_pois_inner(
        authority,
        AuthorizedPoiStatusSource::Local(status_reader),
        db,
        cfg,
        cache_store,
        active_list_keys,
    )
    .await
}

#[cfg(test)]
pub(super) async fn verify_submitted_pending_output_pois(
    status_reader: &dyn PoiStatusReader,
    db: &DbStore,
    chain_id: u64,
    wallet_id: &str,
    active_list_keys: &[FixedBytes<32>],
) -> PendingOutputPoiVerificationOutcome {
    verify_submitted_pending_output_pois_unchecked(
        status_reader,
        db,
        chain_id,
        wallet_id,
        active_list_keys,
    )
    .await
}

async fn verify_submitted_pending_output_pois_inner(
    authority: &WalletPrivateMutationAuthority<'_>,
    status_source: AuthorizedPoiStatusSource<'_>,
    db: &DbStore,
    cfg: &WalletConfig,
    cache_store: &dyn WalletCacheStore,
    active_list_keys: &[FixedBytes<32>],
) -> PendingOutputPoiVerificationOutcome {
    verify_submitted_pending_output_pois_impl(
        authority,
        &status_source,
        db,
        cfg,
        cache_store,
        active_list_keys,
    )
    .await
}

#[cfg(test)]
async fn verify_submitted_pending_output_pois_unchecked(
    status_reader: &dyn PoiStatusReader,
    db: &DbStore,
    chain_id: u64,
    wallet_id: &str,
    active_list_keys: &[FixedBytes<32>],
) -> PendingOutputPoiVerificationOutcome {
    verify_submitted_pending_output_pois_unchecked_impl(
        status_reader,
        db,
        chain_id,
        wallet_id,
        active_list_keys,
    )
    .await
}

pub(super) async fn pending_output_poi_context_has_current_wallet_utxo(
    authority: &WalletPrivateMutationAuthority<'_>,
    cfg: &WalletConfig,
    record: &PendingOutputPoiContextRecord,
) -> bool {
    current_wallet_output_for_pending_context(authority, cfg, record)
        .await
        .is_some()
}

async fn current_wallet_output_for_pending_context(
    authority: &WalletPrivateMutationAuthority<'_>,
    cfg: &WalletConfig,
    record: &PendingOutputPoiContextRecord,
) -> Option<WalletUtxo> {
    if authority.revalidate().is_err() {
        debug!(
            chain_id = cfg.chain.chain_id,
            "pending output POI verification skipped before status query"
        );
        return None;
    }
    let Ok(snapshot) = authority.wallet_utxos().await else {
        debug!(
            chain_id = cfg.chain.chain_id,
            "pending output POI verification skipped before wallet state check"
        );
        return None;
    };
    let current = snapshot.into_iter().find(|wallet_utxo| {
        !wallet_utxo.is_spent()
            && pending_output_poi_context_matches_wallet_utxo(cfg, wallet_utxo, record)
    });
    let Some(current) = current else {
        debug!(
            chain_id = cfg.chain.chain_id,
            "pending output POI verification skipped; output no longer matches wallet state"
        );
        return None;
    };
    if authority.revalidate().is_err() {
        debug!(
            chain_id = cfg.chain.chain_id,
            "pending output POI verification skipped after wallet state check"
        );
        return None;
    }
    Some(current)
}

async fn commit_verified_pending_output_poi_context(
    authority: &WalletPrivateMutationAuthority<'_>,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    record: &PendingOutputPoiContextRecord,
    expected_output: ExpectedWalletOutput,
    expected_poi_list_state: ExpectedPoiListState,
    active_list_keys: &[FixedBytes<32>],
    valid_list_keys: &[FixedBytes<32>],
    now: u64,
) -> Result<bool, WalletCacheError> {
    let Some(expected_context_fingerprint) = pending_output_poi_context_fingerprint(record) else {
        return Ok(false);
    };

    match apply_poi_private_delta(
        authority,
        db,
        cache_store,
        cfg,
        OwnedPoiPrivateDelta::VerifiedValid {
            output_commitment: record.output_commitment,
            expected_context_fingerprint,
            expected_output,
            expected_poi_list_state,
            active_list_keys: active_list_keys.to_vec(),
            valid_list_keys: valid_list_keys.to_vec(),
            now,
        },
    )
    .await?
    {
        PoiPrivateApplyOutcome::Applied { .. } => Ok(true),
        PoiPrivateApplyOutcome::Skipped => {
            debug!(
                chain_id = cfg.chain.chain_id,
                "verified pending output POI commit skipped"
            );
            Ok(false)
        }
    }
}

async fn verify_submitted_pending_output_pois_impl(
    authority: &WalletPrivateMutationAuthority<'_>,
    status_source: &AuthorizedPoiStatusSource<'_>,
    db: &DbStore,
    cfg: &WalletConfig,
    cache_store: &dyn WalletCacheStore,
    active_list_keys: &[FixedBytes<32>],
) -> PendingOutputPoiVerificationOutcome {
    let chain_id = cfg.chain.chain_id;
    let Ok(records) = cache_store.list_pending_output_poi_contexts(chain_id, &cfg.cache_key) else {
        warn!(chain_id, "failed to list pending output POI contexts");
        return PendingOutputPoiVerificationOutcome {
            errors: 1,
            ..PendingOutputPoiVerificationOutcome::default()
        };
    };
    let now = now_epoch_secs();
    let mut outcome = PendingOutputPoiVerificationOutcome::default();
    for record in records {
        if record.terminal_error.is_some() || record.submitted_poi_list_keys.is_empty() {
            continue;
        }
        let Some(observation) = record.observation.as_ref() else {
            continue;
        };
        let required_list_keys = record
            .list_keys()
            .into_iter()
            .filter(|list_key| active_list_keys.contains(list_key))
            .collect::<Vec<_>>();
        if required_list_keys.is_empty()
            || required_list_keys
                .iter()
                .any(|list_key| !record.submitted_poi_list_keys.contains(list_key))
        {
            continue;
        }
        let Some(identity) = pending_output_poi_submit_identity(&record, observation) else {
            continue;
        };
        let Some(current_output) =
            current_wallet_output_for_pending_context(authority, cfg, &record).await
        else {
            continue;
        };
        let expected_output = ExpectedWalletOutput::new(&current_output);
        let expected_poi_list_state =
            ExpectedPoiListState::new(&current_output.utxo.poi, &required_list_keys);
        let statuses = match read_pending_output_poi_statuses(
            status_source,
            authority,
            cache_store,
            cfg,
            &record,
            &required_list_keys,
            &identity,
        )
        .await
        {
            Ok(Some(mut statuses)) => statuses
                .remove(&identity.derived_blinded_commitment)
                .unwrap_or_default(),
            Ok(None) => continue,
            Err(_) => {
                outcome.errors += 1;
                warn!(
                    chain_id,
                    "failed to verify submitted pending output POI status"
                );
                continue;
            }
        };
        match pending_output_poi_context_still_current(
            authority,
            cache_store,
            chain_id,
            &cfg.cache_key,
            &record,
        ) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(_) => {
                outcome.errors += 1;
                warn!(
                    chain_id,
                    "failed to revalidate submitted pending output POI context"
                );
                continue;
            }
        }
        let all_valid = required_list_keys
            .iter()
            .all(|list_key| statuses.get(list_key) == Some(&PoiStatus::Valid));
        if all_valid {
            match commit_verified_pending_output_poi_context(
                authority,
                db,
                cache_store,
                cfg,
                &record,
                expected_output,
                expected_poi_list_state,
                active_list_keys,
                &required_list_keys,
                now,
            )
            .await
            {
                Ok(true) => {}
                Ok(false) => continue,
                Err(_) => {
                    outcome.errors += 1;
                    warn!(
                        chain_id,
                        "failed to commit verified pending output POI projection"
                    );
                    continue;
                }
            }
            outcome.completed += 1;
            debug!(
                chain_id,
                poi_lists = required_list_keys.len(),
                "verified pending output POI context"
            );
        } else {
            match cache_store.get_output_poi_recovery(
                chain_id,
                &cfg.cache_key,
                &record.output_commitment,
            ) {
                Ok(Some(_)) => {}
                Ok(None) => {
                    let Some(expected_context_fingerprint) =
                        pending_output_poi_context_fingerprint(&record)
                    else {
                        outcome.errors += 1;
                        continue;
                    };
                    if apply_poi_private_delta(
                        authority,
                        db,
                        cache_store,
                        cfg,
                        OwnedPoiPrivateDelta::PendingSubmission {
                            expected_output,
                            expected_context_fingerprint,
                            expected_recovery: ExpectedRecordState::Absent,
                            active_list_keys: active_list_keys.to_vec(),
                            list_keys: required_list_keys.clone(),
                            predicate: PendingOutputPoiSubmissionPredicate::RetrySubmitted,
                            merge_submitted_list_keys: false,
                            action: OutputPoiRecoveryAction::Submitted {
                                retry_after: PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER,
                            },
                            now,
                        },
                    )
                    .await
                    .is_err()
                    {
                        outcome.errors += 1;
                        warn!(
                            chain_id,
                            "failed to commit pending output POI submission state"
                        );
                        continue;
                    }
                }
                Err(_) => {
                    outcome.errors += 1;
                    warn!(
                        chain_id,
                        "failed to load pending output POI submission state"
                    );
                    continue;
                }
            }
            outcome.pending += 1;
        }
    }
    if outcome.completed > 0 || outcome.pending > 0 || outcome.errors > 0 {
        debug!(
            chain_id,
            completed = outcome.completed,
            pending = outcome.pending,
            errors = outcome.errors,
            "verified submitted pending output POI contexts"
        );
    }
    outcome
}

#[cfg(test)]
async fn verify_submitted_pending_output_pois_check_only(
    _authority: &WalletPrivateMutationAuthority<'_>,
    status_reader: &dyn PoiStatusReader,
    db: &DbStore,
    chain_id: u64,
    wallet_id: &str,
    active_list_keys: &[FixedBytes<32>],
) -> PendingOutputPoiVerificationOutcome {
    let mut outcome = PendingOutputPoiVerificationOutcome::default();
    let Ok(records) = db.list_pending_output_poi_contexts(chain_id, wallet_id) else {
        warn!(chain_id, "failed to list pending output POI contexts");
        outcome.errors += 1;
        return outcome;
    };
    for record in records {
        if record.terminal_error.is_some() || record.submitted_poi_list_keys.is_empty() {
            continue;
        }
        let Some(observation) = record.observation.as_ref() else {
            continue;
        };
        let required_list_keys = record
            .list_keys()
            .into_iter()
            .filter(|list_key| active_list_keys.contains(list_key))
            .collect::<Vec<_>>();
        if required_list_keys.is_empty()
            || required_list_keys
                .iter()
                .any(|list_key| !record.submitted_poi_list_keys.contains(list_key))
        {
            continue;
        }
        let Some(identity) = pending_output_poi_submit_identity(&record, observation) else {
            continue;
        };
        let Ok(mut statuses) = status_reader
            .pois_per_list(
                &record.txid_version,
                EVM_CHAIN_TYPE,
                chain_id,
                &required_list_keys,
                &[BlindedCommitmentData::transact(
                    identity.derived_blinded_commitment,
                )],
            )
            .await
        else {
            warn!(
                chain_id,
                "failed to verify submitted pending output POI status"
            );
            outcome.errors += 1;
            continue;
        };
        let statuses = statuses
            .remove(&identity.derived_blinded_commitment)
            .unwrap_or_default();
        match pending_output_poi_context_still_current_unchecked(db, chain_id, wallet_id, &record) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(_) => {
                warn!(
                    chain_id,
                    "failed to revalidate submitted pending output POI context"
                );
                outcome.errors += 1;
                continue;
            }
        }
        if required_list_keys
            .iter()
            .all(|list_key| statuses.get(list_key) == Some(&PoiStatus::Valid))
        {
            outcome.completed += 1;
        } else {
            outcome.pending += 1;
        }
    }
    outcome
}

#[cfg(test)]
async fn verify_submitted_pending_output_pois_unchecked_impl(
    status_reader: &dyn PoiStatusReader,
    db: &DbStore,
    chain_id: u64,
    wallet_id: &str,
    active_list_keys: &[FixedBytes<32>],
) -> PendingOutputPoiVerificationOutcome {
    let Ok(records) = db.list_pending_output_poi_contexts(chain_id, wallet_id) else {
        warn!(chain_id, "failed to list pending output POI contexts");
        return PendingOutputPoiVerificationOutcome {
            errors: 1,
            ..PendingOutputPoiVerificationOutcome::default()
        };
    };
    let now = now_epoch_secs();
    let mut outcome = PendingOutputPoiVerificationOutcome::default();
    for record in records {
        if record.terminal_error.is_some() || record.submitted_poi_list_keys.is_empty() {
            continue;
        }
        let Some(observation) = record.observation.as_ref() else {
            continue;
        };
        let required_list_keys = record
            .list_keys()
            .into_iter()
            .filter(|list_key| active_list_keys.contains(list_key))
            .collect::<Vec<_>>();
        if required_list_keys.is_empty()
            || required_list_keys
                .iter()
                .any(|list_key| !record.submitted_poi_list_keys.contains(list_key))
        {
            continue;
        }
        let Some(identity) = pending_output_poi_submit_identity(&record, observation) else {
            continue;
        };
        let Ok(mut statuses) = status_reader
            .pois_per_list(
                &record.txid_version,
                EVM_CHAIN_TYPE,
                chain_id,
                &required_list_keys,
                &[BlindedCommitmentData::transact(
                    identity.derived_blinded_commitment,
                )],
            )
            .await
        else {
            warn!(
                chain_id,
                "failed to verify submitted pending output POI status"
            );
            outcome.errors += 1;
            continue;
        };
        let statuses = statuses
            .remove(&identity.derived_blinded_commitment)
            .unwrap_or_default();
        match pending_output_poi_context_still_current_unchecked(db, chain_id, wallet_id, &record) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(_) => {
                warn!(
                    chain_id,
                    "failed to revalidate submitted pending output POI context"
                );
                outcome.errors += 1;
                continue;
            }
        }
        let all_valid = required_list_keys
            .iter()
            .all(|list_key| statuses.get(list_key) == Some(&PoiStatus::Valid));
        if all_valid {
            if db
                .delete_pending_output_poi_context(chain_id, wallet_id, &record.output_commitment)
                .is_err()
            {
                warn!(
                    chain_id,
                    "failed to delete verified pending output POI context"
                );
                outcome.errors += 1;
                continue;
            }
            if let Ok(Some(mut recovery)) =
                db.get_output_poi_recovery(chain_id, &record.wallet_id, &record.output_commitment)
            {
                recovery.apply_action(OutputPoiRecoveryAction::Valid, now);
                if db.put_output_poi_recovery(&recovery).is_err() {
                    warn!(chain_id, "failed to mark pending output POI recovery valid");
                }
            }
            outcome.completed += 1;
        } else {
            if ensure_pending_output_poi_submission_state_unchecked(
                db,
                chain_id,
                &record,
                observation,
                now,
            )
            .is_err()
            {
                warn!(
                    chain_id,
                    "failed to persist pending output POI submission state"
                );
                outcome.errors += 1;
            }
            outcome.pending += 1;
        }
    }
    outcome
}
