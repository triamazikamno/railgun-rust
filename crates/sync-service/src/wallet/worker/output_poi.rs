#[allow(clippy::wildcard_imports)]
use super::*;

/// Persists the new contexts, then hands their send-ready copies to the chain
/// PPOI submitter and waits for it to record them, so the chain holds them
/// before the caller broadcasts.
pub(super) async fn commit_pending_output_contexts(
    handle: &WalletHandle,
    cancel: &CancellationToken,
    _db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    reset_generation: u64,
    active_poi_list_keys: &[FixedBytes<32>],
    poi_submitter: &ChainPoiSubmitterHandle,
    contexts: &[PendingOutputPoiContextIntent],
) -> Result<usize, WalletPrivateRequestError> {
    let authority = WalletPrivateMutationAuthority::new(handle, reset_generation, cancel);
    let permit = authority
        .acquire()
        .await
        .map_err(|reason| wallet_private_request_error(&reason))?;
    let created_at = now_epoch_secs();
    let mut seen_commitments = HashSet::with_capacity(contexts.len());
    let mut new_records = Vec::with_capacity(contexts.len());
    for context in contexts {
        if !seen_commitments.insert(context.output_commitment) {
            continue;
        }
        let record =
            context
                .clone()
                .into_record(cfg.chain.chain_id, cfg.cache_key.to_string(), created_at);
        match cache_store.get_pending_output_poi_context(
            record.chain_id,
            &cfg.cache_key,
            &record.output_commitment,
        ) {
            Ok(Some(_)) => {}
            Ok(None) => new_records.push(record),
            Err(_) => return Err(WalletPrivateRequestError::PersistenceFailed),
        }
    }
    if new_records.is_empty() {
        return Ok(0);
    }
    match permit.with_durable_apply(|token| {
        cache_store.commit_wallet_private_state(
            WalletPrivateCommit::new(
                &token,
                &permit,
                WalletUtxoMutation::Preserve,
                WalletCheckpointMutation::Preserve,
            )
            .with_pending_output_context_updates(&new_records),
        )?;
        Ok::<(), WalletCacheError>(())
    }) {
        Ok(Ok(())) => {}
        Ok(Err(_)) => return Err(WalletPrivateRequestError::PersistenceFailed),
        Err(reason) => return Err(wallet_private_request_error(&reason)),
    }
    let handoff = new_records
        .iter()
        .filter_map(|record| pending_output_poi_handoff_context(record, active_poi_list_keys))
        .collect::<Vec<_>>();
    if handoff.is_empty() {
        return Ok(new_records.len());
    }
    let handoff_count = handoff.len();
    if permit.revalidate().is_err() {
        debug!(
            chain_id = cfg.chain.chain_id,
            contexts = handoff_count,
            "pending output POI handoff skipped; wallet actor inactive"
        );
    } else if poi_submitter.prepare(handoff).await.is_err() {
        debug!(
            chain_id = cfg.chain.chain_id,
            contexts = handoff_count,
            "pending output POI handoff skipped; chain PPOI submitter stopped"
        );
    }
    Ok(new_records.len())
}

pub(super) fn spawn_pending_output_poi_tentative_job(
    poi_jobs: &WalletPoiJobTracker,
    handle: &WalletHandle,
    cancel: &CancellationToken,
    done_tx: &mpsc::Sender<WalletRemoteDone>,
    cache_store: &Arc<dyn WalletCacheStore>,
    cfg: &WalletConfig,
    poi_runtime: &WalletPoiRuntime,
    poi_submitter: &ChainPoiSubmitterHandle,
    active_list_keys: &[FixedBytes<32>],
    candidates: Vec<PendingOutputPoiTentativeCandidate>,
) {
    let handle = handle.clone();
    let cancel = cancel.clone();
    let credential = WalletActorCredential::current_for(&handle);
    let done_tx = done_tx.clone();
    let cache_store = Arc::clone(cache_store);
    let cfg = cfg.clone();
    let poi_client = poi_runtime.public_client().clone();
    let poi_submitter = poi_submitter.clone();
    let active_list_keys = active_list_keys.to_vec();
    poi_jobs.spawn(async move {
        let authority =
            WalletPrivateMutationAuthority::new(&handle, credential.reset_generation, &cancel);
        let private_poi = WalletPrivatePoiClients::new(
            authority.remote_authority(),
            poi_client,
            Arc::new(poi_submitter),
        );
        let result = submit_pending_output_poi_tentative_candidates(
            &authority,
            cache_store.as_ref(),
            &cfg,
            &active_list_keys,
            &candidates,
            &private_poi,
        )
        .await;
        let _ = done_tx
            .send(WalletRemoteDone::PendingOutputPoiTentative {
                credential,
                retryable: result.retryable,
                accepted_candidates: result.accepted_candidates,
                accepted: result.accepted,
                missing_txid: result.missing_txid,
                remote_failure: result.remote_failure,
                context_stale: result.context_stale,
                authority_stale: result.authority_stale,
            })
            .await;
    });
}

#[derive(Default)]
pub(super) struct PendingOutputPoiTentativeAttemptTracker {
    pub(super) attempts:
        BTreeMap<(u64, PendingOutputPoiTentativeAttemptKey), PendingOutputPoiTentativeCandidate>,
    pub(super) valid_lists:
        BTreeMap<(u64, PendingOutputPoiTentativeAttemptKey), BTreeSet<FixedBytes<32>>>,
}

impl PendingOutputPoiTentativeAttemptTracker {
    pub(super) fn reserve(
        &mut self,
        reset_generation: u64,
        candidate: PendingOutputPoiTentativeCandidate,
    ) -> bool {
        let key = candidate.attempt_key();
        self.attempts
            .insert((reset_generation, key), candidate)
            .is_none()
    }

    pub(super) fn accept(
        &mut self,
        reset_generation: u64,
        candidates: &[PendingOutputPoiTentativeCandidate],
    ) {
        for candidate in candidates {
            let key = candidate.attempt_key();
            self.attempts
                .insert((reset_generation, key.clone()), candidate.clone());
        }
    }

    pub(super) fn release_retryable(
        &mut self,
        reset_generation: u64,
        keys: &[PendingOutputPoiTentativeAttemptKey],
    ) {
        for key in keys {
            self.attempts.remove(&(reset_generation, key.clone()));
            self.valid_lists.remove(&(reset_generation, key.clone()));
        }
    }

    pub(super) fn clear_generation(&mut self, reset_generation: u64) {
        self.attempts
            .retain(|(generation, _), _| *generation == reset_generation);
        self.valid_lists
            .retain(|(generation, _), _| *generation == reset_generation);
    }

    pub(super) fn clear(&mut self) {
        self.attempts.clear();
        self.valid_lists.clear();
    }

    fn candidates(&self, reset_generation: u64) -> Vec<PendingOutputPoiTentativeCandidate> {
        self.attempts
            .iter()
            .filter(|((generation, _), _)| *generation == reset_generation)
            .map(|(_, candidate)| candidate.clone())
            .collect()
    }

    pub(super) fn record_local_statuses(
        &mut self,
        reset_generation: u64,
        statuses: &[PendingOutputPoiTentativeLocalStatus],
    ) -> (usize, usize) {
        let mut newly_valid_outputs = 0;
        let mut newly_valid_lists = 0;
        for status in statuses {
            let key = status.candidate.attempt_key();
            if self
                .attempts
                .get(&(reset_generation, key.clone()))
                .is_some_and(|candidate| candidate.attempt_key() == key)
            {
                let valid_lists = self.valid_lists.entry((reset_generation, key)).or_default();
                let before = valid_lists.len();
                valid_lists.extend(status.valid_list_keys.iter().copied());
                let added = valid_lists.len().saturating_sub(before);
                if added > 0 {
                    newly_valid_outputs += 1;
                    newly_valid_lists += added;
                }
            }
        }
        (newly_valid_outputs, newly_valid_lists)
    }

    pub(super) fn prune_for_observations(
        &mut self,
        reset_generation: u64,
        observations: &[super::super::CommitmentObservation],
    ) {
        let stale = self
            .attempts
            .iter()
            .filter(|((generation, _), candidate)| {
                *generation == reset_generation
                    && !observations.iter().any(|observation| {
                        candidate.output_commitment()
                            == FixedBytes::from(observation.commitment.to_be_bytes::<32>())
                            && candidate.observation().tree == observation.tree
                            && candidate.observation().position == observation.position
                            && candidate.observation().source == observation.source
                    })
            })
            .map(|((_, key), _)| key.clone())
            .collect::<Vec<_>>();
        self.release_retryable(reset_generation, &stale);
    }

    pub(super) fn apply_to_overlay(
        &self,
        reset_generation: u64,
        overlay: &mut WalletPendingOverlay,
        refreshed_at: u64,
    ) -> bool {
        let mut changed = false;
        for ((generation, key), candidate) in &self.attempts {
            if *generation != reset_generation {
                continue;
            }
            let Some(valid_lists) = self.valid_lists.get(&(*generation, key.clone())) else {
                continue;
            };
            let Some(wallet_utxo) = overlay.new_utxos.iter_mut().find(|wallet_utxo| {
                let observation = candidate.observation();
                candidate.output_commitment() == wallet_utxo.utxo.poi.commitment
                    && observation.tree == wallet_utxo.utxo.tree
                    && observation.position == wallet_utxo.utxo.position
                    && observation.source == wallet_utxo.utxo.source
            }) else {
                continue;
            };
            let statuses = valid_lists
                .iter()
                .copied()
                .map(|list_key| (list_key, super::super::PoiStatus::Valid))
                .collect::<BTreeMap<_, _>>();
            changed |= wallet_utxo.utxo.poi.apply_status_refresh(
                candidate.list_keys(),
                Some(&statuses),
                refreshed_at,
            ) > 0;
        }
        changed
    }
}

pub(super) async fn refresh_tentative_pending_output_poi_statuses(
    handle: &WalletHandle,
    cancel: &CancellationToken,
    corpus: Option<&PublicPoiCorpusHandle>,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    reset_generation: u64,
    tracker: &mut PendingOutputPoiTentativeAttemptTracker,
) {
    tracker.clear_generation(reset_generation);
    let candidates = tracker.candidates(reset_generation);
    let statuses = read_pending_output_poi_tentative_local_statuses(
        corpus,
        cfg,
        active_list_keys,
        &candidates,
    )
    .await;
    let (newly_valid_outputs, newly_valid_lists) =
        tracker.record_local_statuses(reset_generation, &statuses);
    if newly_valid_lists > 0 {
        info!(
            valid_outputs = newly_valid_outputs,
            valid_lists = newly_valid_lists,
            pending_outputs = candidates.len().saturating_sub(newly_valid_outputs),
            "tentative POI visible in local corpus"
        );
    }
    if candidates.is_empty() {
        return;
    }
    let authority = WalletPrivateMutationAuthority::new(handle, reset_generation, cancel);
    let Ok(permit) = authority.acquire().await else {
        return;
    };
    let mut overlay = permit.pending_overlay().read().await.clone();
    let changed = tracker.apply_to_overlay(reset_generation, &mut overlay, now_epoch_secs());
    if changed && permit.replace_chain_pending_overlay(overlay).await.is_ok() {
        let _ = permit.notify_if_changed(true).await;
    }
}
