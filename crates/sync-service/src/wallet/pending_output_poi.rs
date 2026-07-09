use super::*;

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
    // No long-lived permit: remote submit uses authority revalidation; durable
    // commits acquire a short permit only inside commit_pending_output_poi_side_effects.
    if let Err(reason) = authority.revalidate() {
        debug!(
            ?reason,
            chain_id = cfg.chain.chain_id,
            wallet_id = %cfg.cache_key,
            "pending output POI submission skipped"
        );
        return 0;
    }
    let submitted_contexts = match submit_observed_pending_output_pois_inner(
        authority,
        db,
        cache_store,
        cfg,
        active_list_keys,
        private_poi,
        force_submission_retry,
    )
    .await
    {
        Ok(submitted_contexts) => submitted_contexts,
        Err(err) => {
            warn!(
                ?err,
                chain_id = cfg.chain.chain_id,
                wallet_id = %cfg.cache_key,
                "failed to submit observed pending output POI contexts"
            );
            0
        }
    };
    if submitted_contexts > 0 {
        debug!(
            chain_id = cfg.chain.chain_id,
            wallet_id = %cfg.cache_key,
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
        match record_pending_output_poi_observations(db, chain_id, wallet_id, observations) {
            Ok(recorded_observations) => recorded_observations,
            Err(err) => {
                warn!(
                    ?err,
                    chain_id, wallet_id, "failed to record pending output POI observations"
                );
                0
            }
        };
    let record_elapsed_ms = record_started.elapsed().as_millis();

    let Some(submitter) = submitter else {
        if observations.is_empty() {
            return;
        }
        debug!(
            chain_id,
            wallet_id,
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
    let submitted_contexts = match submit_observed_pending_output_pois_unchecked(
        db,
        chain_id,
        wallet_id,
        submitter,
        force_submission_retry,
    )
    .await
    {
        Ok(submitted_contexts) => submitted_contexts,
        Err(err) => {
            warn!(
                ?err,
                chain_id, wallet_id, "failed to submit observed pending output POI contexts"
            );
            0
        }
    };
    if submitted_contexts > 0 || !observations.is_empty() {
        debug!(
            chain_id,
            wallet_id,
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
) -> Result<usize, local_db::DbError> {
    let updates = pending_output_poi_observation_updates(db, chain_id, wallet_id, observations)?;
    let recorded = updates.len();
    for record in updates {
        db.put_pending_output_poi_context(&record)?;
    }
    Ok(recorded)
}

pub(super) fn pending_output_poi_observation_updates(
    db: &DbStore,
    chain_id: u64,
    wallet_id: &str,
    observations: &[CommitmentObservation],
) -> Result<Vec<PendingOutputPoiContextRecord>, local_db::DbError> {
    let mut updates = Vec::new();
    for observation in observations {
        let output_commitment = FixedBytes::from(observation.commitment.to_be_bytes::<32>());
        let Some(mut record) =
            db.get_pending_output_poi_context(chain_id, wallet_id, &output_commitment)?
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
) -> Result<usize, local_db::DbError> {
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
        submitted_list_keys: Vec<FixedBytes<32>>,
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
    recovery_fingerprint: Option<Vec<u8>>,
    force_submission_retry: bool,
}

impl PendingOutputPoiSubmissionPlan {
    fn missing(list_keys: Vec<FixedBytes<32>>) -> Self {
        Self {
            kind: PendingOutputPoiSubmissionKind::Missing,
            list_keys,
            recovery_fingerprint: None,
            force_submission_retry: false,
        }
    }

    fn retry_submitted(
        list_keys: Vec<FixedBytes<32>>,
        recovery: &OutputPoiRecoveryRecord,
        force_submission_retry: bool,
    ) -> Self {
        Self {
            kind: PendingOutputPoiSubmissionKind::RetrySubmitted,
            list_keys,
            recovery_fingerprint: output_poi_recovery_fingerprint(recovery),
            force_submission_retry,
        }
    }

    /// Force-resubmit plan: active list keys already on the context (submitted or not).
    pub(super) fn force_matching(list_keys: Vec<FixedBytes<32>>) -> Self {
        Self {
            kind: PendingOutputPoiSubmissionKind::ForceMatching,
            list_keys,
            recovery_fingerprint: None,
            force_submission_retry: true,
        }
    }

    fn retain_active(&mut self, active_list_keys: &[FixedBytes<32>]) {
        self.list_keys
            .retain(|list_key| active_list_keys.contains(list_key));
    }

    pub(super) fn list_keys(&self) -> &[FixedBytes<32>] {
        &self.list_keys
    }
}

async fn submit_observed_pending_output_pois_impl(
    authority: &WalletPrivateMutationAuthority<'_>,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    chain_id: u64,
    wallet_id: &str,
    private_poi: &WalletPrivatePoiClients,
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
        let mut plan = PendingOutputPoiSubmissionPlan::missing(record.missing_list_keys());
        if plan.list_keys.is_empty()
            && let Some(recovery) = recovery.as_ref()
            && recovery.submission_retry_allowed(now, force_submission_retry)
        {
            plan = PendingOutputPoiSubmissionPlan::retry_submitted(
                record.list_keys(),
                recovery,
                force_submission_retry,
            );
        }
        plan.retain_active(active_list_keys);
        if plan.list_keys.is_empty() {
            continue;
        }
        match preflight_and_remote_submit_pending_output_poi(
            authority,
            db,
            cfg,
            active_list_keys,
            &record,
            &observation,
            &plan,
            private_poi,
        )
        .await?
        {
            PendingOutputPoiRemoteAttempt::NotCurrent => continue,
            PendingOutputPoiRemoteAttempt::AuthorityStale => break,
            PendingOutputPoiRemoteAttempt::MissingPreTransactionPois => {
                record.terminal_error =
                    Some("missing pre-transaction POI for pending output".to_string());
                if let Err(reason) = authority.revalidate() {
                    debug!(
                        ?reason,
                        chain_id,
                        wallet_id = %record.wallet_id,
                        commitment = %hex::encode(record.output_commitment),
                        "pending output POI terminal side effect rejected"
                    );
                    break;
                }
                if let Err(err) = commit_pending_output_poi_side_effects(
                    authority,
                    db,
                    cache_store,
                    cfg,
                    std::slice::from_ref(&record),
                    &[],
                )
                .await
                {
                    warn!(?err, chain_id, wallet_id = %record.wallet_id, commitment = %hex::encode(record.output_commitment), "failed to atomically persist pending output POI terminal state");
                }
            }
            PendingOutputPoiRemoteAttempt::Succeeded {
                submitted_list_keys,
            } => {
                if !pending_output_poi_submission_side_effect_current(
                    authority,
                    db,
                    &record,
                    cfg,
                    active_list_keys,
                    &plan,
                )
                .await?
                {
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
                if let Err(err) = commit_pending_output_poi_side_effects(
                    authority,
                    db,
                    cache_store,
                    cfg,
                    std::slice::from_ref(&record),
                    std::slice::from_ref(&recovery_update),
                )
                .await
                {
                    warn!(?err, chain_id, wallet_id = %record.wallet_id, commitment = %hex::encode(record.output_commitment), "failed to atomically persist pending output POI submitted state");
                    continue;
                }
                submitted_contexts += 1;
            }
            PendingOutputPoiRemoteAttempt::Failed {
                error: err,
                submitted_list_keys: _,
            } => {
                if !pending_output_poi_submission_side_effect_current(
                    authority,
                    db,
                    &record,
                    cfg,
                    active_list_keys,
                    &plan,
                )
                .await?
                {
                    continue;
                }
                if let Some(mut recovery) = recovery.clone() {
                    if let Err(reason) = authority.revalidate() {
                        debug!(
                            ?reason,
                            chain_id,
                            wallet_id = %record.wallet_id,
                            commitment = %hex::encode(record.output_commitment),
                            "pending output POI submit-failure side effect rejected"
                        );
                        break;
                    }
                    recovery.apply_action(
                        OutputPoiRecoveryAction::SubmitFailed {
                            error: err.to_string(),
                            retry_after: OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
                        },
                        now,
                    );
                    if let Err(err) = commit_pending_output_poi_side_effects(
                        authority,
                        db,
                        cache_store,
                        cfg,
                        &[],
                        std::slice::from_ref(&recovery),
                    )
                    .await
                    {
                        warn!(?err, chain_id, wallet_id = %record.wallet_id, commitment = %hex::encode(record.output_commitment), "failed to atomically persist pending output POI submit-failure state");
                    }
                }
                warn!(
                    ?err,
                    chain_id,
                    commitment = %hex::encode(record.output_commitment),
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
        let Some(submit_identity) = pending_output_poi_submit_identity(&record, &observation)
        else {
            warn!(
                chain_id,
                commitment = %hex::encode(record.output_commitment),
                output_tree = observation.output_tree,
                output_position = observation.output_position,
                "pending output POI context has invalid output tree"
            );
            continue;
        };
        let submitted_list_keys = missing_list_keys.clone();
        debug!(
            chain_id,
            wallet_id = %record.wallet_id,
            commitment = %hex::encode(record.output_commitment),
            derived_blinded_commitment = %hex::encode(submit_identity.derived_blinded_commitment),
            source_tx_hash = %hex::encode(observation.tx_hash),
            list_keys = ?submitted_list_keys,
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
                    ?err,
                    chain_id,
                    commitment = %hex::encode(record.output_commitment),
                    "pending output POI submission failed; keeping context retryable"
                );
            }
        }
    }
    Ok(submitted_contexts)
}

/// Remote submit with Protocol A last-moment fence: revalidate before each RPC.
async fn submit_pending_output_poi_context_via_gateway(
    authority: &WalletPrivateMutationAuthority<'_>,
    db: &DbStore,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    plan: &PendingOutputPoiSubmissionPlan,
    private_poi: &WalletPrivatePoiClients,
    chain_id: u64,
    record: &PendingOutputPoiContextRecord,
    context: &SingleCommitmentProofContext,
    observation: &PendingOutputPoiObservation,
    submitted_list_keys: &[FixedBytes<32>],
) -> Result<PendingOutputPoiRemoteAttempt, local_db::DbError> {
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
                                    db,
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
                        return Ok(PendingOutputPoiRemoteAttempt::Failed {
                            submitted_list_keys: submitted_list_keys.to_vec(),
                            error,
                        });
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
                            db,
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
                Ok(PendingOutputPoiRemoteAttempt::Failed {
                    submitted_list_keys: submitted_list_keys.to_vec(),
                    error,
                })
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
        OutputPoiRecoveryAction::CacheTxInput { .. } => OutputPoiRecoveryStatus::Recoverable,
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

/// Pure delta from remote/prepare work. Must not carry a pre-permit wallet snapshot
/// that will later be written back.
pub(super) enum PoiPrivateDelta<'a> {
    /// Pending-context / recovery metadata only (fresh UTXO snapshot under permit).
    Metadata {
        pending_updates: &'a [PendingOutputPoiContextRecord],
        recovery_updates: &'a [OutputPoiRecoveryRecord],
    },
    /// Mark submitted context lists Valid on the matching UTXO under a fresh permit snapshot.
    VerifiedValid {
        record: &'a PendingOutputPoiContextRecord,
        valid_list_keys: &'a [FixedBytes<32>],
        now: u64,
    },
    PoiStatusRefresh {
        active_list_keys: &'a [FixedBytes<32>],
        expected_poi_by_blinded_commitment: &'a BTreeMap<FixedBytes<32>, UtxoPoiMetadata>,
        statuses_by_blinded_commitment:
            &'a BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PoiStatus>>,
        refreshed_at: u64,
    },
}

impl PoiPrivateDelta<'_> {
    fn into_owned(self) -> OwnedPoiPrivateDelta {
        match self {
            Self::Metadata {
                pending_updates,
                recovery_updates,
            } => OwnedPoiPrivateDelta::Metadata {
                pending_updates: pending_updates.to_vec(),
                recovery_updates: recovery_updates.to_vec(),
            },
            Self::VerifiedValid {
                record,
                valid_list_keys,
                now,
            } => OwnedPoiPrivateDelta::VerifiedValid {
                record: record.clone(),
                valid_list_keys: valid_list_keys.to_vec(),
                now,
            },
            Self::PoiStatusRefresh {
                active_list_keys,
                expected_poi_by_blinded_commitment,
                statuses_by_blinded_commitment,
                refreshed_at,
            } => OwnedPoiPrivateDelta::PoiStatusRefresh {
                active_list_keys: active_list_keys.to_vec(),
                expected_poi_by_blinded_commitment: expected_poi_by_blinded_commitment.clone(),
                statuses_by_blinded_commitment: statuses_by_blinded_commitment.clone(),
                refreshed_at,
            },
        }
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
    delta: PoiPrivateDelta<'_>,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    if let Some(client) = authority.apply_client() {
        return client
            .apply(authority.reset_generation(), delta.into_owned())
            .await;
    }
    apply_poi_private_delta_inline(authority, db, cache_store, cfg, delta.into_owned()).await
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
    db: &DbStore,
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
    let last_scanned = permit
        .last_scanned()
        .map_err(|_| WalletCacheError::Crypto)?;

    match delta {
        OwnedPoiPrivateDelta::Metadata {
            pending_updates,
            recovery_updates,
        } => {
            // Protocol B: fold intents against current private state under the apply permit.
            // Never write pre-validated blobs for spent/missing outputs (scan may have deleted them).
            let pending_updates: Vec<_> = pending_updates
                .into_iter()
                .filter(|record| {
                    snapshot.iter().any(|wallet_utxo| {
                        !wallet_utxo.is_spent()
                            && pending_output_poi_context_matches_wallet_utxo(
                                cfg,
                                wallet_utxo,
                                record,
                            )
                    })
                })
                .collect();
            let recovery_updates: Vec<_> = recovery_updates
                .into_iter()
                .filter(|record| {
                    snapshot.iter().any(|wallet_utxo| {
                        !wallet_utxo.is_spent()
                            && wallet_utxo.utxo.poi.commitment == record.output_commitment
                    })
                })
                .collect();
            if pending_updates.is_empty() && recovery_updates.is_empty() {
                drop(permit);
                return Ok(PoiPrivateApplyOutcome::Skipped);
            }
            let result = permit.with_durable_apply(|token| {
                cache_store.commit_wallet_private_state(WalletPrivateCommit::new(
                    &token,
                    &permit,
                    cfg.chain.chain_id,
                    &snapshot,
                    false,
                    last_scanned,
                    None,
                    &pending_updates,
                    &[],
                    &recovery_updates,
                ))
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
            record,
            valid_list_keys,
            now,
        } => {
            let Some(wallet_utxo) = snapshot.iter_mut().find(|wallet_utxo| {
                !wallet_utxo.is_spent()
                    && pending_output_poi_context_matches_wallet_utxo(cfg, wallet_utxo, &record)
            }) else {
                drop(permit);
                return Ok(PoiPrivateApplyOutcome::Skipped);
            };
            let valid_statuses = valid_list_keys
                .iter()
                .copied()
                .map(|list_key| (list_key, PoiStatus::Valid))
                .collect::<BTreeMap<_, _>>();
            let changed = wallet_utxo.utxo.poi.apply_status_refresh(
                &valid_list_keys,
                Some(&valid_statuses),
                now,
            ) > 0;
            let recovery_owned = match db.get_output_poi_recovery(
                cfg.chain.chain_id,
                &record.wallet_id,
                &record.output_commitment,
            )? {
                Some(mut recovery) => {
                    recovery.apply_action(OutputPoiRecoveryAction::Valid, now);
                    Some(recovery)
                }
                None => None,
            };
            let recovery_updates_owned: Vec<OutputPoiRecoveryRecord> =
                recovery_owned.into_iter().collect();
            let pending_deletes_owned = [record.output_commitment];
            let mut utxos_locked = if changed {
                Some(permit.handle_utxos().write().await)
            } else {
                None
            };
            let result = permit.with_active_apply(|token| {
                cache_store.commit_wallet_private_state(WalletPrivateCommit::new(
                    &token,
                    &permit,
                    cfg.chain.chain_id,
                    &snapshot,
                    changed,
                    last_scanned,
                    None,
                    &[],
                    &pending_deletes_owned,
                    &recovery_updates_owned,
                ))?;
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
                        .map(|locked| locked.as_slice())
                        .unwrap_or(&[]);
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
                    &snapshot,
                    true,
                    last_scanned,
                    None,
                    &[],
                    &[],
                    &[],
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

/// Metadata-only private POI side effects (actor re-entry or short permit).
pub(super) async fn commit_pending_output_poi_side_effects(
    authority: &WalletPrivateMutationAuthority<'_>,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    pending_updates: &[PendingOutputPoiContextRecord],
    recovery_updates: &[OutputPoiRecoveryRecord],
) -> Result<(), WalletCacheError> {
    apply_poi_private_delta(
        authority,
        db,
        cache_store,
        cfg,
        PoiPrivateDelta::Metadata {
            pending_updates,
            recovery_updates,
        },
    )
    .await
    .map(|_| ())
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
    pub(super) txid_leaf_hash: FixedBytes<32>,
}

pub(super) fn pending_output_poi_submit_identity(
    record: &PendingOutputPoiContextRecord,
    observation: &PendingOutputPoiObservation,
) -> Option<PendingOutputPoiSubmitIdentity> {
    let output_tree = u32::try_from(observation.output_tree).ok()?;
    let txid_leaf_hash = record.txid_leaf_hash()?;
    Some(PendingOutputPoiSubmitIdentity {
        derived_blinded_commitment: UtxoPoiMetadata::blinded_commitment_for(
            record.output_commitment,
            record.output_npk,
            output_tree,
            observation.output_position,
        ),
        txid_leaf_hash,
    })
}

pub(super) fn pending_output_poi_context_matches_wallet_utxo(
    cfg: &WalletConfig,
    wallet_utxo: &WalletUtxo,
    record: &PendingOutputPoiContextRecord,
) -> bool {
    if record.chain_id != cfg.chain.chain_id
        || record.wallet_id != cfg.cache_key
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
    db: &DbStore,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    expected: &PendingOutputPoiContextRecord,
    plan: &PendingOutputPoiSubmissionPlan,
) -> Result<PendingOutputPoiPreflight, local_db::DbError> {
    if let Err(reason) = authority.revalidate() {
        debug!(
            ?reason,
            chain_id = cfg.chain.chain_id,
            wallet_id = %cfg.cache_key,
            commitment = %hex::encode(expected.output_commitment),
            "pending output POI submission skipped before plan validation"
        );
        return Ok(PendingOutputPoiPreflight::AuthorityStale);
    }
    let Some(current) = db.get_pending_output_poi_context(
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
            wallet_id = %cfg.cache_key,
            commitment = %hex::encode(expected.output_commitment),
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
                    wallet_id = %cfg.cache_key,
                    commitment = %hex::encode(expected.output_commitment),
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
                    wallet_id = %cfg.cache_key,
                    commitment = %hex::encode(expected.output_commitment),
                    "pending output POI retry skipped; submitted-list state changed"
                );
                return Ok(PendingOutputPoiPreflight::NotCurrent);
            }
            let Some(expected_fingerprint) = plan.recovery_fingerprint.as_ref() else {
                return Ok(PendingOutputPoiPreflight::NotCurrent);
            };
            let current_recovery = db.get_output_poi_recovery(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &expected.output_commitment,
            )?;
            let current_fingerprint = current_recovery
                .as_ref()
                .and_then(output_poi_recovery_fingerprint);
            if current_fingerprint.as_ref() != Some(expected_fingerprint)
                || !current_recovery.as_ref().is_some_and(|record| {
                    record.submission_retry_allowed(now_epoch_secs(), plan.force_submission_retry)
                })
            {
                debug!(
                    chain_id = cfg.chain.chain_id,
                    wallet_id = %cfg.cache_key,
                    commitment = %hex::encode(expected.output_commitment),
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
                    wallet_id = %cfg.cache_key,
                    commitment = %hex::encode(expected.output_commitment),
                    "forced pending output POI skipped; list keys no longer on context"
                );
                return Ok(PendingOutputPoiPreflight::NotCurrent);
            }
        }
    }
    let snapshot = match authority.wallet_utxos().await {
        Ok(snapshot) => snapshot,
        Err(reason) => {
            debug!(
                ?reason,
                chain_id = cfg.chain.chain_id,
                wallet_id = %cfg.cache_key,
                commitment = %hex::encode(expected.output_commitment),
                "pending output POI submission skipped before wallet state check"
            );
            return Ok(if authority.revalidate().is_err() {
                PendingOutputPoiPreflight::AuthorityStale
            } else {
                PendingOutputPoiPreflight::NotCurrent
            });
        }
    };
    let matches_current = snapshot.iter().any(|wallet_utxo| {
        !wallet_utxo.is_spent()
            && pending_output_poi_context_matches_wallet_utxo(cfg, wallet_utxo, expected)
    });
    if !matches_current {
        debug!(
            chain_id = cfg.chain.chain_id,
            wallet_id = %cfg.cache_key,
            commitment = %hex::encode(expected.output_commitment),
            "pending output POI submission skipped; output no longer matches wallet state"
        );
        return Ok(PendingOutputPoiPreflight::NotCurrent);
    }
    // Force matching may resubmit even when local status is not "recoverable".
    if plan.kind != PendingOutputPoiSubmissionKind::ForceMatching {
        let still_needs_poi = snapshot.iter().any(|wallet_utxo| {
            !wallet_utxo.is_spent()
                && pending_output_poi_context_matches_wallet_utxo(cfg, wallet_utxo, expected)
                && wallet_utxo
                    .utxo
                    .poi
                    .has_recoverable_status_for_lists(&plan.list_keys)
        });
        if !still_needs_poi {
            debug!(
                chain_id = cfg.chain.chain_id,
                wallet_id = %cfg.cache_key,
                commitment = %hex::encode(expected.output_commitment),
                "pending output POI submission skipped; output no longer needs POI"
            );
            return Ok(PendingOutputPoiPreflight::NotCurrent);
        }
    }
    if let Err(reason) = authority.revalidate() {
        debug!(
            ?reason,
            chain_id = cfg.chain.chain_id,
            wallet_id = %cfg.cache_key,
            commitment = %hex::encode(expected.output_commitment),
            "pending output POI submission skipped after plan validation"
        );
        return Ok(PendingOutputPoiPreflight::AuthorityStale);
    }
    Ok(PendingOutputPoiPreflight::Ready)
}

async fn pending_output_poi_submission_side_effect_current(
    authority: &WalletPrivateMutationAuthority<'_>,
    db: &DbStore,
    expected: &PendingOutputPoiContextRecord,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    plan: &PendingOutputPoiSubmissionPlan,
) -> Result<bool, local_db::DbError> {
    Ok(matches!(
        pending_output_poi_submission_plan_current(
            authority,
            db,
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
    db: &DbStore,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    record: &PendingOutputPoiContextRecord,
    observation: &PendingOutputPoiObservation,
    plan: &PendingOutputPoiSubmissionPlan,
    private_poi: &WalletPrivatePoiClients,
) -> Result<PendingOutputPoiRemoteAttempt, local_db::DbError> {
    match pending_output_poi_submission_plan_current(
        authority,
        db,
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
    let Some(submit_identity) = pending_output_poi_submit_identity(record, observation) else {
        warn!(
            chain_id = cfg.chain.chain_id,
            commitment = %hex::encode(record.output_commitment),
            output_tree = observation.output_tree,
            output_position = observation.output_position,
            "pending output POI context has invalid output tree"
        );
        return Ok(PendingOutputPoiRemoteAttempt::NotCurrent);
    };
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
        wallet_id = %record.wallet_id,
        commitment = %hex::encode(record.output_commitment),
        npk = %hex::encode(record.output_npk),
        output_tree = observation.output_tree,
        output_position = observation.output_position,
        derived_blinded_commitment = %hex::encode(submit_identity.derived_blinded_commitment),
        railgun_txid = %hex::encode(FixedBytes::from(record.railgun_txid.to_be_bytes::<32>())),
        txid_leaf_hash = %hex::encode(submit_identity.txid_leaf_hash),
        utxo_tree_in = record.utxo_tree_in,
        source_tx_hash = %hex::encode(observation.tx_hash),
        list_keys = ?submitted_list_keys,
        pre_tx_poi_lists = context.pre_transaction_pois_per_txid_leaf_per_list.len(),
        plan_kind = ?plan.kind,
        "submitting pending output POI context"
    );
    submit_pending_output_poi_context_via_gateway(
        authority,
        db,
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
    db: &DbStore,
    chain_id: u64,
    wallet_id: &str,
    expected: &PendingOutputPoiContextRecord,
) -> Result<bool, local_db::DbError> {
    if let Err(reason) = authority.revalidate() {
        debug!(
            ?reason,
            chain_id,
            wallet_id,
            commitment = %hex::encode(expected.output_commitment),
            "pending output POI context side effect rejected"
        );
        return Ok(false);
    }
    pending_output_poi_context_still_current_impl(db, chain_id, wallet_id, expected)
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
            wallet_id,
            commitment = %hex::encode(expected.output_commitment),
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
        wallet_id,
        commitment = %hex::encode(expected.output_commitment),
        "pending output POI context side effect skipped; context changed"
    );
    Ok(false)
}

fn pending_output_poi_context_fingerprint(
    record: &PendingOutputPoiContextRecord,
) -> Option<Vec<u8>> {
    rmp_serde::to_vec(record).ok()
}

fn output_poi_recovery_fingerprint(record: &OutputPoiRecoveryRecord) -> Option<Vec<u8>> {
    rmp_serde::to_vec(record).ok()
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

#[derive(Debug)]
enum PendingOutputPoiStatusReadError {
    Remote(PoiError),
    Check(local_db::DbError),
}

async fn read_pending_output_poi_statuses(
    source: &AuthorizedPoiStatusSource<'_>,
    authority: &WalletPrivateMutationAuthority<'_>,
    db: &DbStore,
    cfg: &WalletConfig,
    record: &PendingOutputPoiContextRecord,
    list_keys: &[FixedBytes<32>],
    identity: &PendingOutputPoiSubmitIdentity,
) -> Result<
    Option<BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PoiStatus>>>,
    PendingOutputPoiStatusReadError,
> {
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
            .map_err(PendingOutputPoiStatusReadError::Remote),
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
                        db,
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
            Err(WalletPrivateRemoteError::Check(error)) => {
                Err(PendingOutputPoiStatusReadError::Check(error))
            }
            Err(WalletPrivateRemoteError::Remote(error)) => {
                Err(PendingOutputPoiStatusReadError::Remote(error))
            }
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
                let reader = LocalPoiStatusReader::new(corpus.local_caches());
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
    if let Err(reason) = authority.revalidate() {
        debug!(?reason, cache_key = %cfg.cache_key, "pending output POI verification skipped");
        return PendingOutputPoiVerificationOutcome::default();
    }
    match poi_runtime {
        WalletPoiRuntime::IndexedArtifacts { .. } => {
            let key = PublicPoiCorpusKey::wallet_default(cfg.chain.chain_id);
            if !public_data_plane
                .poi_corpus_ready_for_lists(key.clone(), active_list_keys)
                .await
            {
                if poi_runtime.wallet_read_fallback_enabled() {
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
                        cache_key = %cfg.cache_key,
                        chain_id = cfg.chain.chain_id,
                        "artifact POI local cache unavailable; skipping submitted pending output POI verification"
                    );
                    PendingOutputPoiVerificationOutcome::default()
                }
            } else {
                let corpus = match public_data_plane.ensure_poi_corpus(key).await {
                    Ok(corpus) => corpus,
                    Err(err) => {
                        warn!(?err, cache_key = %cfg.cache_key, "artifact POI corpus unavailable");
                        return PendingOutputPoiVerificationOutcome::default();
                    }
                };
                let reader = LocalPoiStatusReader::new(corpus.local_caches());
                verify_submitted_pending_output_pois_inner(
                    authority,
                    AuthorizedPoiStatusSource::Local(&reader),
                    db,
                    cfg,
                    cache_store,
                    active_list_keys,
                )
                .await
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
    if let Err(reason) = authority.revalidate() {
        debug!(
            ?reason,
            chain_id, wallet_id, "pending output POI verification skipped"
        );
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
    if let Err(reason) = authority.revalidate() {
        debug!(?reason, cache_key = %cfg.cache_key, "pending output POI verification skipped");
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
    if let Err(reason) = authority.revalidate() {
        debug!(
            ?reason,
            chain_id = cfg.chain.chain_id,
            wallet_id = %cfg.cache_key,
            commitment = %hex::encode(record.output_commitment),
            "pending output POI verification skipped before status query"
        );
        return false;
    }
    let snapshot = match authority.wallet_utxos().await {
        Ok(snapshot) => snapshot,
        Err(reason) => {
            debug!(
                ?reason,
                chain_id = cfg.chain.chain_id,
                wallet_id = %cfg.cache_key,
                commitment = %hex::encode(record.output_commitment),
                "pending output POI verification skipped before wallet state check"
            );
            return false;
        }
    };
    let matches_current = snapshot.iter().any(|wallet_utxo| {
        !wallet_utxo.is_spent()
            && pending_output_poi_context_matches_wallet_utxo(cfg, wallet_utxo, record)
    });
    if !matches_current {
        debug!(
            chain_id = cfg.chain.chain_id,
            wallet_id = %cfg.cache_key,
            commitment = %hex::encode(record.output_commitment),
            "pending output POI verification skipped; output no longer matches wallet state"
        );
        return false;
    }
    if let Err(reason) = authority.revalidate() {
        debug!(
            ?reason,
            chain_id = cfg.chain.chain_id,
            wallet_id = %cfg.cache_key,
            commitment = %hex::encode(record.output_commitment),
            "pending output POI verification skipped after wallet state check"
        );
        return false;
    }
    true
}

async fn commit_verified_pending_output_poi_context(
    authority: &WalletPrivateMutationAuthority<'_>,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    record: &PendingOutputPoiContextRecord,
    valid_list_keys: &[FixedBytes<32>],
    now: u64,
) -> Result<bool, WalletCacheError> {
    if !pending_output_poi_context_has_current_wallet_utxo(authority, cfg, record).await {
        return Ok(false);
    }

    // Pure delta only — wallet snapshot + UTXO mutation happen under the short permit.
    match apply_poi_private_delta(
        authority,
        db,
        cache_store,
        cfg,
        PoiPrivateDelta::VerifiedValid {
            record,
            valid_list_keys,
            now,
        },
    )
    .await?
    {
        PoiPrivateApplyOutcome::Applied { .. } => Ok(true),
        PoiPrivateApplyOutcome::Skipped => {
            debug!(
                chain_id = cfg.chain.chain_id,
                wallet_id = %cfg.cache_key,
                commitment = %hex::encode(record.output_commitment),
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
    let wallet_id = cfg.cache_key.as_str();
    let records = match db.list_pending_output_poi_contexts(chain_id, wallet_id) {
        Ok(records) => records,
        Err(err) => {
            warn!(
                ?err,
                chain_id, wallet_id, "failed to list pending output POI contexts"
            );
            return PendingOutputPoiVerificationOutcome {
                errors: 1,
                ..PendingOutputPoiVerificationOutcome::default()
            };
        }
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
        if !pending_output_poi_context_has_current_wallet_utxo(authority, cfg, &record).await {
            continue;
        }
        let statuses = match read_pending_output_poi_statuses(
            status_source,
            authority,
            db,
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
            Err(err) => {
                outcome.errors += 1;
                warn!(
                    ?err,
                    chain_id,
                    wallet_id = %record.wallet_id,
                    commitment = %hex::encode(record.output_commitment),
                    "failed to verify submitted pending output POI status"
                );
                continue;
            }
        };
        match pending_output_poi_context_still_current(authority, db, chain_id, wallet_id, &record)
        {
            Ok(true) => {}
            Ok(false) => continue,
            Err(err) => {
                outcome.errors += 1;
                warn!(
                    ?err,
                    chain_id,
                    wallet_id = %record.wallet_id,
                    commitment = %hex::encode(record.output_commitment),
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
                &required_list_keys,
                now,
            )
            .await
            {
                Ok(true) => {}
                Ok(false) => continue,
                Err(err) => {
                    outcome.errors += 1;
                    warn!(
                        ?err,
                        chain_id,
                        wallet_id = %record.wallet_id,
                        commitment = %hex::encode(record.output_commitment),
                        "failed to commit verified pending output POI projection"
                    );
                    continue;
                }
            }
            outcome.completed += 1;
            debug!(
                chain_id,
                wallet_id = %record.wallet_id,
                output_role = ?record.output_role,
                commitment = %hex::encode(record.output_commitment),
                derived_blinded_commitment = %hex::encode(identity.derived_blinded_commitment),
                list_keys = ?required_list_keys,
                "verified pending output POI context"
            );
        } else {
            if !pending_output_poi_context_has_current_wallet_utxo(authority, cfg, &record).await {
                continue;
            }
            match db.get_output_poi_recovery(chain_id, &record.wallet_id, &record.output_commitment)
            {
                Ok(Some(_)) => {}
                Ok(None) => {
                    let recovery_update = match pending_output_poi_recovery_update(
                        db,
                        chain_id,
                        &record,
                        observation,
                        now,
                        OutputPoiRecoveryAction::Submitted {
                            retry_after: PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER,
                        },
                    ) {
                        Ok(recovery) => recovery,
                        Err(err) => {
                            outcome.errors += 1;
                            warn!(
                                ?err,
                                chain_id,
                                wallet_id = %record.wallet_id,
                                commitment = %hex::encode(record.output_commitment),
                                "failed to prepare pending output POI submission state"
                            );
                            continue;
                        }
                    };
                    if let Err(err) = commit_pending_output_poi_side_effects(
                        authority,
                        db,
                        cache_store,
                        cfg,
                        &[],
                        std::slice::from_ref(&recovery_update),
                    )
                    .await
                    {
                        outcome.errors += 1;
                        warn!(
                            ?err,
                            chain_id,
                            wallet_id = %record.wallet_id,
                            commitment = %hex::encode(record.output_commitment),
                            "failed to commit pending output POI submission state"
                        );
                        continue;
                    }
                }
                Err(err) => {
                    outcome.errors += 1;
                    warn!(
                        ?err,
                        chain_id,
                        wallet_id = %record.wallet_id,
                        commitment = %hex::encode(record.output_commitment),
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
    authority: &WalletPrivateMutationAuthority<'_>,
    status_reader: &dyn PoiStatusReader,
    db: &DbStore,
    chain_id: u64,
    wallet_id: &str,
    active_list_keys: &[FixedBytes<32>],
) -> PendingOutputPoiVerificationOutcome {
    let mut outcome = PendingOutputPoiVerificationOutcome::default();
    let records = match db.list_pending_output_poi_contexts(chain_id, wallet_id) {
        Ok(records) => records,
        Err(err) => {
            warn!(
                ?err,
                chain_id, wallet_id, "failed to list pending output POI contexts"
            );
            outcome.errors += 1;
            return outcome;
        }
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
        let statuses = match status_reader
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
        {
            Ok(mut statuses) => statuses
                .remove(&identity.derived_blinded_commitment)
                .unwrap_or_default(),
            Err(err) => {
                warn!(?err, chain_id, wallet_id = %record.wallet_id, commitment = %hex::encode(record.output_commitment), "failed to verify submitted pending output POI status");
                outcome.errors += 1;
                continue;
            }
        };
        match pending_output_poi_context_still_current(authority, db, chain_id, wallet_id, &record)
        {
            Ok(true) => {}
            Ok(false) => continue,
            Err(err) => {
                warn!(?err, chain_id, wallet_id = %record.wallet_id, commitment = %hex::encode(record.output_commitment), "failed to revalidate submitted pending output POI context");
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
    let records = match db.list_pending_output_poi_contexts(chain_id, wallet_id) {
        Ok(records) => records,
        Err(err) => {
            warn!(
                ?err,
                chain_id, wallet_id, "failed to list pending output POI contexts"
            );
            return PendingOutputPoiVerificationOutcome {
                errors: 1,
                ..PendingOutputPoiVerificationOutcome::default()
            };
        }
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
        let statuses = match status_reader
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
        {
            Ok(mut statuses) => statuses
                .remove(&identity.derived_blinded_commitment)
                .unwrap_or_default(),
            Err(err) => {
                warn!(?err, chain_id, wallet_id = %record.wallet_id, commitment = %hex::encode(record.output_commitment), "failed to verify submitted pending output POI status");
                outcome.errors += 1;
                continue;
            }
        };
        match pending_output_poi_context_still_current_unchecked(db, chain_id, wallet_id, &record) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(err) => {
                warn!(?err, chain_id, wallet_id = %record.wallet_id, commitment = %hex::encode(record.output_commitment), "failed to revalidate submitted pending output POI context");
                outcome.errors += 1;
                continue;
            }
        }
        let all_valid = required_list_keys
            .iter()
            .all(|list_key| statuses.get(list_key) == Some(&PoiStatus::Valid));
        if all_valid {
            if let Err(err) =
                db.delete_pending_output_poi_context(chain_id, wallet_id, &record.output_commitment)
            {
                warn!(?err, chain_id, wallet_id = %record.wallet_id, commitment = %hex::encode(record.output_commitment), "failed to delete verified pending output POI context");
                outcome.errors += 1;
                continue;
            }
            if let Ok(Some(mut recovery)) =
                db.get_output_poi_recovery(chain_id, &record.wallet_id, &record.output_commitment)
            {
                recovery.apply_action(OutputPoiRecoveryAction::Valid, now);
                if let Err(err) = db.put_output_poi_recovery(&recovery) {
                    warn!(?err, chain_id, wallet_id = %record.wallet_id, commitment = %hex::encode(record.output_commitment), "failed to mark pending output POI recovery valid");
                }
            }
            outcome.completed += 1;
        } else {
            if let Err(err) = ensure_pending_output_poi_submission_state_unchecked(
                db,
                chain_id,
                &record,
                observation,
                now,
            ) {
                warn!(?err, chain_id, wallet_id = %record.wallet_id, commitment = %hex::encode(record.output_commitment), "failed to persist pending output POI submission state");
                outcome.errors += 1;
            }
            outcome.pending += 1;
        }
    }
    outcome
}
