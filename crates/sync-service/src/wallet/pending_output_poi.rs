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
    submitter: Option<&dyn PendingOutputPoiSubmitter>,
    force_submission_retry: bool,
) -> usize {
    let started = Instant::now();
    let Some(submitter) = submitter else {
        return 0;
    };
    let permit = match authority.acquire().await {
        Ok(permit) => permit,
        Err(reason) => {
            debug!(
                ?reason,
                chain_id = cfg.chain.chain_id,
                wallet_id = %cfg.cache_key,
                "pending output POI submission skipped"
            );
            return 0;
        }
    };
    let submitted_contexts = match submit_observed_pending_output_pois_inner(
        authority,
        &permit,
        db,
        cache_store,
        cfg,
        active_list_keys,
        submitter,
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
    drop(permit);
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
    permit: &WalletPrivateMutationPermit<'_>,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    submitter: &dyn PendingOutputPoiSubmitter,
    force_submission_retry: bool,
) -> Result<usize, local_db::DbError> {
    submit_observed_pending_output_pois_impl(
        authority,
        permit,
        cfg,
        active_list_keys,
        db,
        cache_store,
        cfg.chain.chain_id,
        &cfg.cache_key,
        submitter,
        force_submission_retry,
    )
    .await
}

async fn submit_observed_pending_output_pois_impl(
    authority: &WalletPrivateMutationAuthority<'_>,
    permit: &WalletPrivateMutationPermit<'_>,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
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
        missing_list_keys.retain(|list_key| active_list_keys.contains(list_key));
        if missing_list_keys.is_empty() {
            continue;
        }
        if !pending_output_poi_submission_plan_current(
            authority,
            db,
            cfg,
            active_list_keys,
            &record,
            &missing_list_keys,
        )
        .await?
        {
            continue;
        }
        let pre_transaction_pois = record.retain_poi_lists(&missing_list_keys);
        if pre_transaction_pois.len() != missing_list_keys.len() {
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
                continue;
            }
            if let Err(err) = commit_pending_output_poi_side_effects(
                permit,
                cache_store,
                cfg,
                std::slice::from_ref(&record),
                &[],
            )
            .await
            {
                warn!(?err, chain_id, wallet_id = %record.wallet_id, commitment = %hex::encode(record.output_commitment), "failed to atomically persist pending output POI terminal state");
                continue;
            }
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
            "submitting pending output POI context"
        );
        let submit_result = submit_pending_output_poi_context_with_cancel(
            authority,
            submitter,
            chain_id,
            &record,
            &context,
            &observation,
            &submitted_list_keys,
        )
        .await;
        match submit_result {
            Ok(()) => {
                if !pending_output_poi_submission_side_effect_current(
                    authority,
                    db,
                    &record,
                    cfg,
                    active_list_keys,
                    &submitted_list_keys,
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
                    permit,
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
            Err(err) => {
                if !pending_output_poi_submission_side_effect_current(
                    authority,
                    db,
                    &record,
                    cfg,
                    active_list_keys,
                    &submitted_list_keys,
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
                        continue;
                    }
                    recovery.apply_action(
                        OutputPoiRecoveryAction::SubmitFailed {
                            error: err.to_string(),
                            retry_after: OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
                        },
                        now,
                    );
                    if let Err(err) = commit_pending_output_poi_side_effects(
                        permit,
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

pub(super) async fn submit_pending_output_poi_context_with_cancel(
    authority: &WalletPrivateMutationAuthority<'_>,
    submitter: &dyn PendingOutputPoiSubmitter,
    chain_id: u64,
    record: &PendingOutputPoiContextRecord,
    context: &SingleCommitmentProofContext,
    observation: &PendingOutputPoiObservation,
    submitted_list_keys: &[FixedBytes<32>],
) -> Result<(), PoiError> {
    let submit = submit_pending_output_poi_context_unchecked(
        submitter,
        chain_id,
        record,
        context,
        observation,
        submitted_list_keys,
    );
    tokio::select! {
        biased;
        () = authority.cancelled() => Err(PoiError::MerkleRootsRejected),
        result = submit => result,
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

pub(super) async fn commit_pending_output_poi_side_effects(
    permit: &WalletPrivateMutationPermit<'_>,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    pending_updates: &[PendingOutputPoiContextRecord],
    recovery_updates: &[OutputPoiRecoveryRecord],
) -> Result<(), WalletCacheError> {
    let snapshot = permit
        .wallet_utxos()
        .await
        .map_err(|_| WalletCacheError::Crypto)?;
    let last_scanned = permit
        .last_scanned()
        .map_err(|_| WalletCacheError::Crypto)?;
    permit.revalidate().map_err(|_| WalletCacheError::Crypto)?;
    cache_store.commit_wallet_private_state(WalletPrivateCommit::new(
        permit,
        cfg.chain.chain_id,
        &snapshot,
        false,
        last_scanned,
        None,
        pending_updates,
        &[],
        recovery_updates,
    ))
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

pub(super) async fn pending_output_poi_submission_plan_current(
    authority: &WalletPrivateMutationAuthority<'_>,
    db: &DbStore,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    expected: &PendingOutputPoiContextRecord,
    submitted_list_keys: &[FixedBytes<32>],
) -> Result<bool, local_db::DbError> {
    if let Err(reason) = authority.revalidate() {
        debug!(
            ?reason,
            chain_id = cfg.chain.chain_id,
            wallet_id = %cfg.cache_key,
            commitment = %hex::encode(expected.output_commitment),
            "pending output POI submission skipped before plan validation"
        );
        return Ok(false);
    }
    let Some(current) = db.get_pending_output_poi_context(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &expected.output_commitment,
    )?
    else {
        return Ok(false);
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
        return Ok(false);
    }
    let mut current_missing = current.missing_list_keys();
    current_missing.retain(|list_key| active_list_keys.contains(list_key));
    if submitted_list_keys.is_empty()
        || submitted_list_keys
            .iter()
            .any(|list_key| !current_missing.contains(list_key))
    {
        debug!(
            chain_id = cfg.chain.chain_id,
            wallet_id = %cfg.cache_key,
            commitment = %hex::encode(expected.output_commitment),
            "pending output POI submission skipped; missing-list state changed"
        );
        return Ok(false);
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
            return Ok(false);
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
        return Ok(false);
    }
    if let Err(reason) = authority.revalidate() {
        debug!(
            ?reason,
            chain_id = cfg.chain.chain_id,
            wallet_id = %cfg.cache_key,
            commitment = %hex::encode(expected.output_commitment),
            "pending output POI submission skipped after plan validation"
        );
        return Ok(false);
    }
    Ok(true)
}

async fn pending_output_poi_submission_side_effect_current(
    authority: &WalletPrivateMutationAuthority<'_>,
    db: &DbStore,
    expected: &PendingOutputPoiContextRecord,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    submitted_list_keys: &[FixedBytes<32>],
) -> Result<bool, local_db::DbError> {
    pending_output_poi_submission_plan_current(
        authority,
        db,
        cfg,
        active_list_keys,
        expected,
        submitted_list_keys,
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

#[derive(Default)]
pub(super) struct PendingOutputPoiVerificationOutcome {
    pub(super) completed: usize,
    pub(super) pending: usize,
    pub(super) errors: usize,
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
    remote_client: &PoiRpcClient,
    cfg: &WalletConfig,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    active_list_keys: &[FixedBytes<32>],
) -> PendingOutputPoiVerificationOutcome {
    let permit = match authority.acquire().await {
        Ok(permit) => permit,
        Err(reason) => {
            debug!(?reason, cache_key = %cfg.cache_key, "pending output POI verification skipped");
            return PendingOutputPoiVerificationOutcome::default();
        }
    };
    let outcome = match poi_runtime {
        WalletPoiRuntime::IndexedArtifacts { .. } => {
            let key = PublicPoiCorpusKey::wallet_default(cfg.chain.chain_id);
            if !public_data_plane
                .poi_corpus_ready_for_lists(key.clone(), active_list_keys)
                .await
            {
                if poi_runtime.wallet_read_fallback_enabled() {
                    verify_submitted_pending_output_pois_inner(
                        authority,
                        &permit,
                        remote_client,
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
                    &permit,
                    &reader,
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
                &permit,
                remote_client,
                db,
                cfg,
                cache_store,
                active_list_keys,
            )
            .await
        }
    };
    drop(permit);
    outcome
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
    let permit = match authority.acquire().await {
        Ok(permit) => permit,
        Err(reason) => {
            debug!(
                ?reason,
                chain_id, wallet_id, "pending output POI verification skipped"
            );
            return PendingOutputPoiVerificationOutcome::default();
        }
    };
    let outcome = verify_submitted_pending_output_pois_check_only(
        authority,
        status_reader,
        db,
        chain_id,
        wallet_id,
        active_list_keys,
    )
    .await;
    drop(permit);
    outcome
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
    let permit = match authority.acquire().await {
        Ok(permit) => permit,
        Err(reason) => {
            debug!(?reason, cache_key = %cfg.cache_key, "pending output POI verification skipped");
            return PendingOutputPoiVerificationOutcome::default();
        }
    };
    let outcome = verify_submitted_pending_output_pois_inner(
        authority,
        &permit,
        status_reader,
        db,
        cfg,
        cache_store,
        active_list_keys,
    )
    .await;
    drop(permit);
    outcome
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
    permit: &WalletPrivateMutationPermit<'_>,
    status_reader: &dyn PoiStatusReader,
    db: &DbStore,
    cfg: &WalletConfig,
    cache_store: &dyn WalletCacheStore,
    active_list_keys: &[FixedBytes<32>],
) -> PendingOutputPoiVerificationOutcome {
    verify_submitted_pending_output_pois_impl(
        authority,
        permit,
        status_reader,
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
    permit: &WalletPrivateMutationPermit<'_>,
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

    let mut candidate = match authority.wallet_utxos().await {
        Ok(snapshot) => snapshot,
        Err(reason) => {
            debug!(
                ?reason,
                chain_id = cfg.chain.chain_id,
                wallet_id = %cfg.cache_key,
                commitment = %hex::encode(record.output_commitment),
                "verified pending output POI commit skipped before wallet state snapshot"
            );
            return Ok(false);
        }
    };
    let Some(wallet_utxo) = candidate.iter_mut().find(|wallet_utxo| {
        !wallet_utxo.is_spent()
            && pending_output_poi_context_matches_wallet_utxo(cfg, wallet_utxo, record)
    }) else {
        debug!(
            chain_id = cfg.chain.chain_id,
            wallet_id = %cfg.cache_key,
            commitment = %hex::encode(record.output_commitment),
            "verified pending output POI commit skipped; output disappeared"
        );
        return Ok(false);
    };
    let valid_statuses = valid_list_keys
        .iter()
        .copied()
        .map(|list_key| (list_key, PoiStatus::Valid))
        .collect::<BTreeMap<_, _>>();
    let changed =
        wallet_utxo
            .utxo
            .poi
            .apply_status_refresh(valid_list_keys, Some(&valid_statuses), now)
            > 0;

    let recovery_updates = match db.get_output_poi_recovery(
        cfg.chain.chain_id,
        &record.wallet_id,
        &record.output_commitment,
    )? {
        Some(mut recovery) => {
            recovery.apply_action(OutputPoiRecoveryAction::Valid, now);
            vec![recovery]
        }
        None => Vec::new(),
    };
    let pending_context_deletes = [record.output_commitment];
    if let Err(reason) = authority.revalidate() {
        debug!(
            ?reason,
            chain_id = cfg.chain.chain_id,
            wallet_id = %cfg.cache_key,
            commitment = %hex::encode(record.output_commitment),
            "verified pending output POI commit rejected"
        );
        return Ok(false);
    }
    cache_store.commit_wallet_private_state(WalletPrivateCommit::new(
        permit,
        cfg.chain.chain_id,
        &candidate,
        changed,
        permit
            .last_scanned()
            .map_err(|_| WalletCacheError::Crypto)?,
        None,
        &[],
        &pending_context_deletes,
        &recovery_updates,
    ))?;
    if let Err(reason) = authority.revalidate() {
        debug!(
            ?reason,
            chain_id = cfg.chain.chain_id,
            wallet_id = %cfg.cache_key,
            commitment = %hex::encode(record.output_commitment),
            "verified pending output POI runtime swap skipped after commit"
        );
        return Ok(false);
    }
    if changed {
        if let Err(reason) = permit.replace_wallet_utxos(candidate).await {
            debug!(
                ?reason,
                chain_id = cfg.chain.chain_id,
                wallet_id = %cfg.cache_key,
                commitment = %hex::encode(record.output_commitment),
                "verified pending output POI runtime swap rejected"
            );
            return Ok(false);
        }
    }
    if let Err(reason) = authority.revalidate() {
        debug!(
            ?reason,
            chain_id = cfg.chain.chain_id,
            wallet_id = %cfg.cache_key,
            commitment = %hex::encode(record.output_commitment),
            "verified pending output POI revision publication rejected"
        );
        return Ok(false);
    }
    permit
        .notify_if_changed(changed)
        .map_err(|_| WalletCacheError::Crypto)?;
    Ok(true)
}

async fn verify_submitted_pending_output_pois_impl(
    authority: &WalletPrivateMutationAuthority<'_>,
    permit: &WalletPrivateMutationPermit<'_>,
    status_reader: &dyn PoiStatusReader,
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
                permit,
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
                        permit,
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
