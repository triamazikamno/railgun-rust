#[allow(clippy::wildcard_imports)]
use super::*;

pub(in crate::wallet) async fn process_pending_output_poi_observations_authorized(
    authority: &WalletPrivateMutationAuthority<'_>,
    public_data_plane: &ChainPublicDataPlane,
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
        debug!(target: LOG_TARGET,
            chain_id = cfg.chain.chain_id,
            "pending output POI submission skipped"
        );
        return 0;
    }
    let submitted_contexts = submit_observed_pending_output_pois_inner(
        authority,
        public_data_plane,
        db,
        cache_store,
        cfg,
        active_list_keys,
        private_poi,
        force_submission_retry,
    )
    .await
    .unwrap_or_else(|_| {
        warn!(target: LOG_TARGET,
            chain_id = cfg.chain.chain_id,
            "failed to submit observed pending output POI contexts"
        );
        0
    });
    if submitted_contexts > 0 {
        debug!(target: LOG_TARGET,
            chain_id = cfg.chain.chain_id,
            submitted_contexts,
            elapsed_ms = started.elapsed().as_millis(),
            "submitted observed pending output POI contexts"
        );
    }
    submitted_contexts
}

pub(in crate::wallet) fn pending_output_poi_observation_state_updates(
    cache_store: &dyn WalletCacheStore,
    chain_id: u64,
    wallet_id: &WalletCacheKey,
    observations: &[CommitmentObservation],
) -> Result<PendingOutputPoiStateUpdates, WalletCacheError> {
    let mut updates = PendingOutputPoiStateUpdates::default();
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
        let observation_changed = record.observe(observed.clone());
        let recovery_mismatch = if observation_changed {
            false
        } else {
            cache_store
                .get_output_poi_recovery(chain_id, wallet_id, &output_commitment)?
                .is_some_and(|recovery| recovery.source_tx_hash != observed.tx_hash)
        };
        if observation_changed || recovery_mismatch {
            // An observation identifies the post-transaction recovery subject. Any state
            // derived from a different (or previously cleared) observation must be retired
            // in the same durable scan commit before this subject becomes submit-ready.
            record.submitted_poi_list_keys.clear();
            record.terminal_error = None;
            updates.context_updates.push(record);
            updates.recovery_deletes.push(output_commitment);
        }
    }
    Ok(updates)
}

pub(crate) fn is_missing_railgun_txid_error(error: &PoiError) -> bool {
    let PoiError::RpcRequest {
        source: PoiRpcError::JsonRpc { message, .. },
    } = error
    else {
        return false;
    };
    let normalized = message
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|character| character.to_ascii_lowercase())
        .collect::<String>();
    normalized.contains("couldnotfindrailguntxid")
}

/// Send-ready copy of a newly created context for the chain PPOI submitter,
/// holding the proofs of its required lists that are currently active. `None`
/// when the context submits by transact proof or lacks one of those proofs,
/// the same rule the missing-list preflight applies.
pub(in crate::wallet) fn pending_output_poi_handoff_context(
    record: &PendingOutputPoiContextRecord,
    active_list_keys: &[FixedBytes<32>],
) -> Option<SingleCommitmentProofContext> {
    if record.txid_merkleroot_index.is_some()
        || record.output_role == PendingOutputPoiRole::RecoveredOutgoing
    {
        return None;
    }
    let mut list_keys = record.list_keys();
    list_keys.retain(|list_key| active_list_keys.contains(list_key));
    if list_keys.is_empty() {
        return None;
    }
    let pre_transaction_pois = record.retain_poi_lists(&list_keys);
    if pre_transaction_pois.len() != list_keys.len()
        || !saved_pending_context_is_compatible(record, &list_keys)
    {
        return None;
    }
    Some(single_commitment_proof_context(
        record,
        pre_transaction_pois,
    ))
}

pub(in crate::wallet) fn pending_output_poi_rewind_state_updates(
    cache_store: &dyn WalletCacheStore,
    chain_id: u64,
    wallet_id: &WalletCacheKey,
    rewind_from_block: u64,
    wallet_utxos_before_rewind: &[WalletUtxo],
) -> Result<PendingOutputPoiStateUpdates, WalletCacheError> {
    let mut updates = PendingOutputPoiStateUpdates::default();
    for mut record in cache_store.list_pending_output_poi_contexts(chain_id, wallet_id)? {
        let rewound_external_observation = record.observation.as_ref().is_some_and(|observation| {
            observation.block_number >= rewind_from_block
                && matches!(
                    record.output_role,
                    PendingOutputPoiRole::Recipient
                        | PendingOutputPoiRole::BroadcasterFee
                        | PendingOutputPoiRole::RecoveredOutgoing
                )
                && (record.output_role == PendingOutputPoiRole::RecoveredOutgoing
                    || !wallet_utxos_before_rewind.iter().any(|wallet_utxo| {
                        wallet_utxo.utxo.poi.commitment == record.output_commitment
                    }))
        });
        if !rewound_external_observation {
            continue;
        }

        updates.recovery_deletes.push(record.output_commitment);
        if record.output_role == PendingOutputPoiRole::RecoveredOutgoing {
            // Sender-recovery records are wholly derived from this observation. Unlike recipient
            // intents, they have no pre-observation context to retain for canonical replay.
            updates.context_deletes.push(record.output_commitment);
        } else {
            record.observation = None;
            record.submitted_poi_list_keys.clear();
            record.terminal_error = None;
            updates.context_updates.push(record);
        }
    }
    Ok(updates)
}

pub(in crate::wallet) async fn submit_observed_pending_output_pois_inner(
    authority: &WalletPrivateMutationAuthority<'_>,
    public_data_plane: &ChainPublicDataPlane,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    private_poi: &WalletPrivatePoiClients,
    force_submission_retry: bool,
) -> Result<usize, WalletCacheError> {
    let chain_id = cfg.chain.chain_id;
    let records = cache_store.list_pending_output_poi_contexts(chain_id, &cfg.cache_key)?;
    let now = now_epoch_secs();
    debug!(target: LOG_TARGET,
        chain_id,
        records = records.len(),
        force_submission_retry,
        "pending output POI retry-submitted scan started"
    );
    let forced_txids = private_poi.deferred_forced_txids();
    let pass = PendingOutputPoiSubmissionPass {
        authority,
        public_data_plane,
        db,
        cache_store,
        cfg,
        active_list_keys,
        private_poi,
        records: &records,
        forced_txids: &forced_txids,
        force_submission_retry,
        now,
    };
    let mut state = PendingOutputPoiSubmissionPassState::default();
    let order = private_poi.submission_order_by_key(records.iter().collect::<Vec<_>>(), |record| {
        record.railgun_txid
    });
    for record in order {
        if state.deferred_txids.contains(&record.railgun_txid) {
            continue;
        }
        if state
            .route
            .as_ref()
            .is_some_and(|current| current.railgun_txid() != record.railgun_txid)
        {
            state.route = None;
        }
        // A forced submission deferred by an earlier pass is still forced the same way.
        let step =
            if forced_txids.get(&record.railgun_txid) == Some(&DeferredForceKind::ForceMatching) {
                pass.resubmit_forced(&mut state, record).await
            } else {
                pass.submit_record(&mut state, record).await?
            };
        if step.is_break() {
            break;
        }
    }
    Ok(state.submitted_contexts)
}
