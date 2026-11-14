use super::*;
use crate::wallet::{PendingOutputPoiSubmitter, PoiRpcClient};

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

pub(in crate::wallet) fn pending_output_poi_recovery_update(
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

pub(in crate::wallet) async fn submit_pending_output_poi_context(
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

pub(in crate::wallet) fn pending_output_poi_context_still_current_unchecked(
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

pub(in crate::wallet) async fn process_pending_output_poi_observations(
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

pub(in crate::wallet) async fn process_pending_output_poi_observations_inner(
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

fn record_pending_output_poi_observations(
    db: &DbStore,
    chain_id: u64,
    wallet_id: &str,
    observations: &[CommitmentObservation],
) -> Result<usize, WalletCacheError> {
    let wallet_id = wallet_id
        .parse::<WalletCacheKey>()
        .map_err(local_db::DbError::from)?;
    let updates =
        pending_output_poi_observation_state_updates(db, chain_id, &wallet_id, observations)?;
    let recorded = updates.context_updates.len();
    for output_commitment in updates.recovery_deletes {
        db.delete_output_poi_recovery(chain_id, wallet_id.as_str(), &output_commitment)?;
    }
    for record in updates.context_updates {
        db.put_pending_output_poi_context(&record)?;
    }
    Ok(recorded)
}

pub(in crate::wallet) fn pending_output_poi_observation_updates(
    cache_store: &dyn WalletCacheStore,
    chain_id: u64,
    wallet_id: &WalletCacheKey,
    observations: &[CommitmentObservation],
) -> Result<Vec<PendingOutputPoiContextRecord>, WalletCacheError> {
    Ok(pending_output_poi_observation_state_updates(
        cache_store,
        chain_id,
        wallet_id,
        observations,
    )?
    .context_updates)
}

pub(in crate::wallet) async fn verify_submitted_pending_output_pois_with_config(
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

pub(in crate::wallet) async fn verify_submitted_pending_output_pois_authorized_with_projection(
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

pub(in crate::wallet) async fn verify_submitted_pending_output_pois(
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
