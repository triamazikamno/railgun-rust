#[allow(clippy::wildcard_imports)]
use super::*;

pub(in crate::wallet) async fn recover_missing_output_pois(
    request: OutputPoiRecoveryRequest<'_>,
) -> usize {
    let Some(spending_public_key) = request.cfg.spending_public_key else {
        return 0;
    };
    let Some(prover) = request.cfg.poi_recovery_prover.as_ref() else {
        return 0;
    };
    if request.active_list_keys.is_empty() {
        return 0;
    }

    let started = Instant::now();
    let now = now_epoch_secs();
    let mut recovered = 0usize;
    let mut stale_revision_skips = 0usize;
    let candidates = output_poi_recovery_candidates(request.wallet_utxos, request.active_list_keys);
    let scan = RecoveryScan {
        request: &request,
        wallet_nullifiers: WalletNullifierIndex::new(request.wallet_utxos, &request.cfg.scan_keys),
        spending_public_key,
        prover,
        now,
    };
    debug!(target: LOG_TARGET,
        chain_id = request.cfg.chain.chain_id,
        candidates = candidates.len(),
        force_retry = request.force_retry,
        "output POI recovery scan started"
    );

    for candidate in candidates {
        match scan.recover_candidate(candidate).await {
            CandidateOutcome::Recovered => recovered += 1,
            CandidateOutcome::StaleCorpusRevision => stale_revision_skips += 1,
            CandidateOutcome::Skipped => {}
        }
    }

    if recovered > 0 {
        submit_recovered_output_pois(&request, recovered, started).await;
    }

    debug!(target: LOG_TARGET,
        chain_id = request.cfg.chain.chain_id,
        recovered,
        stale_revision_skips,
        elapsed_ms = started.elapsed().as_millis(),
        "output POI recovery scan complete"
    );

    recovered
}

impl RecoveryScan<'_> {
    /// Runs one candidate through admission, reconstruction, proof generation and persistence.
    async fn recover_candidate(&self, candidate: &WalletUtxo) -> CandidateOutcome {
        let Some(recovery) = self.admit(candidate) else {
            return CandidateOutcome::Skipped;
        };
        let Some(reconstruction) = recovery.reconstruct().await else {
            return CandidateOutcome::Skipped;
        };
        recovery.prove_and_persist(reconstruction).await
    }

    /// Applies the pending-context and retry gates, returning `None` when the candidate is skipped.
    fn admit<'s>(&'s self, candidate: &'s WalletUtxo) -> Option<CandidateRecovery<'s>> {
        let started = Instant::now();
        let request = self.request;
        let recoverable_list_keys =
            recoverable_output_poi_list_keys(&candidate.utxo.poi, request.active_list_keys);
        if recoverable_list_keys.is_empty() {
            return None;
        }
        let Ok(existing_pending_context) = request.cache_store.get_pending_output_poi_context(
            request.cfg.chain.chain_id,
            &request.cfg.cache_key,
            &candidate.utxo.poi.commitment,
        ) else {
            warn!(target: LOG_TARGET,
                chain_id = request.cfg.chain.chain_id,
                "failed to load pending output POI recovery predecessor"
            );
            return None;
        };
        let expected_pending_context =
            expected_pending_context_state(existing_pending_context.as_ref())?;
        let (list_keys, pending_context_extension) = match existing_pending_context.as_ref() {
            Some(existing) => {
                self.pending_context_admission(candidate, existing, recoverable_list_keys)?
            }
            None => (recoverable_list_keys, None),
        };
        if !self.recovery_record_allows_retry(
            candidate,
            &list_keys,
            pending_context_extension.is_some(),
        ) {
            return None;
        }
        Some(CandidateRecovery {
            scan: self,
            candidate,
            started,
            list_keys,
            expected_pending_context,
            pending_context_extension,
        })
    }

    /// Applies a saved pending context to the candidate's list keys, or returns `None` to skip it.
    fn pending_context_admission(
        &self,
        candidate: &WalletUtxo,
        existing: &PendingOutputPoiContextRecord,
        list_keys: Vec<FixedBytes<32>>,
    ) -> Option<(Vec<FixedBytes<32>>, Option<PendingOutputPoiContextRecord>)> {
        let request = self.request;
        if !pending_output_poi_context_matches_wallet_utxo(request.cfg, candidate, existing) {
            if !request.force_retry {
                return None;
            }
            log_forced_output_poi_recovery_regeneration(request.cfg, candidate, existing);
            return Some((list_keys, None));
        }
        match matching_pending_output_poi_context_disposition(
            existing,
            &list_keys,
            request.force_retry,
        ) {
            MatchingPendingOutputPoiContextDisposition::Skip => {
                debug!(target: LOG_TARGET,
                    chain_id = request.cfg.chain.chain_id,
                    "output POI recovery skipped; matching pending context does not require recovery"
                );
                None
            }
            MatchingPendingOutputPoiContextDisposition::Extend(new_list_keys) => {
                Some((new_list_keys, Some(existing.clone())))
            }
            MatchingPendingOutputPoiContextDisposition::Regenerate => {
                log_forced_output_poi_recovery_regeneration(request.cfg, candidate, existing);
                Some((list_keys, None))
            }
        }
    }

    /// Checks the candidate's cached recovery record: its source transaction and retry state.
    fn recovery_record_allows_retry(
        &self,
        candidate: &WalletUtxo,
        list_keys: &[FixedBytes<32>],
        extends_context: bool,
    ) -> bool {
        let request = self.request;
        let Ok(existing_recovery) = request.cache_store.get_output_poi_recovery(
            request.cfg.chain.chain_id,
            &request.cfg.cache_key,
            &candidate.utxo.poi.commitment,
        ) else {
            warn!(target: LOG_TARGET,
                chain_id = request.cfg.chain.chain_id,
                "failed to load output POI recovery cache"
            );
            return false;
        };
        let Some(record) = existing_recovery.as_ref() else {
            return true;
        };
        if record.source_tx_hash != candidate.utxo.source.tx_hash {
            debug!(target: LOG_TARGET,
                chain_id = request.cfg.chain.chain_id,
                "output POI recovery skipped; cached recovery source transaction is stale"
            );
            return false;
        }
        let extends_submitted_context =
            extends_context && record.status == OutputPoiRecoveryStatus::Submitted;
        if !output_poi_recovery_retry_allowed_for_lists(
            record,
            self.now,
            request.force_retry,
            list_keys,
        ) && !extends_submitted_context
        {
            debug!(target: LOG_TARGET,
                chain_id = request.cfg.chain.chain_id,
                status = ?record.status,
                force_retry = request.force_retry,
                "output POI recovery skipped; cached recovery state is not retryable"
            );
            return false;
        }
        true
    }
}

/// Submits the pending output POI contexts that a recovery scan reconstructed.
async fn submit_recovered_output_pois(
    request: &OutputPoiRecoveryRequest<'_>,
    recovered: usize,
    started: Instant,
) {
    match submit_observed_pending_output_pois_inner(
        request.authority,
        request.public_data_plane,
        request.db,
        request.cache_store,
        request.cfg,
        request.active_list_keys,
        request.private_poi,
        false,
    )
    .await
    {
        Ok(submitted_contexts) => {
            debug!(target: LOG_TARGET,
                chain_id = request.cfg.chain.chain_id,
                recovered,
                submitted_contexts,
                elapsed_ms = started.elapsed().as_millis(),
                "recovered missing output POI contexts"
            );
        }
        Err(_) => {
            warn!(target: LOG_TARGET,
                chain_id = request.cfg.chain.chain_id,
                recovered, "failed to submit recovered output POI contexts"
            );
        }
    }
}
