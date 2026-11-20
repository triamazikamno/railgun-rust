#[allow(clippy::wildcard_imports)]
use super::*;

impl CandidateRecovery<'_> {
    /// Rechecks that the candidate still matches wallet state for its POI lists.
    async fn still_current(&self) -> bool {
        self.scan
            .request
            .candidate_still_current(self.candidate, &self.list_keys)
            .await
    }

    /// Records a recovery failure for the candidate's POI lists.
    async fn record_failure(&self, failure: RecoveryFailure) {
        let request = self.scan.request;
        record_output_poi_recovery_failure(
            request.authority,
            request.db,
            request.cache_store,
            request.cfg,
            self.candidate,
            request.active_list_keys,
            &self.list_keys,
            failure,
            self.scan.now,
        )
        .await;
    }

    /// Records a recovery failure if the candidate is still current.
    async fn record_failure_if_current(&self, failure: RecoveryFailure) {
        if self.still_current().await {
            self.record_failure(failure).await;
        }
    }

    /// Rebuilds the candidate's transaction chunk and recovers its TXID data.
    pub(super) async fn reconstruct(&self) -> Option<Reconstruction> {
        let scan = self.scan;
        let request = scan.request;
        let build_chunk_started = Instant::now();
        let recovery_chunk = match build_output_poi_recovery_chunk_from_public_cache(
            PublicTxidRecoveryBuildRequest {
                request,
                candidate: self.candidate,
                source_tx_hash: self.candidate.utxo.source.tx_hash,
                output_commitment: self.candidate.utxo.poi.commitment,
                wallet_nullifiers: &scan.wallet_nullifiers,
                required_poi_list_keys: &self.list_keys,
                spending_public_key: scan.spending_public_key,
                candidate_started: self.started,
            },
        )
        .await
        {
            Ok(recovery_chunk) => recovery_chunk,
            Err(failure) => {
                warn!(target: LOG_TARGET,
                    chain_id = request.cfg.chain.chain_id,
                    status = ?failure.status,
                    retryable = failure.retry_after.is_some(),
                    failure_category = failure.category,
                    "output POI recovery reconstruction failed"
                );
                self.record_failure_if_current(failure).await;
                return None;
            }
        };
        let build_chunk_elapsed_ms = build_chunk_started.elapsed().as_millis();
        debug!(target: LOG_TARGET,
            chain_id = request.cfg.chain.chain_id,
            inputs = recovery_chunk.chunk.inputs.len(),
            outputs = recovery_chunk.chunk.outputs.len(),
            build_chunk_elapsed_ms,
            candidate_elapsed_ms = self.started.elapsed().as_millis(),
            "output POI recovery chunk built"
        );

        let txid_data_started = Instant::now();
        let txid_data =
            match recovered_output_txid_data_from_public_cache(PublicCacheTxidRecoveryRequest {
                public_data_plane: request.public_data_plane,
                cfg: request.cfg,
                poi_client: request.poi_client,
                http_client: request.http_client,
                indexed_artifact_source: request.indexed_artifact_source,
                recovery_chunk: &recovery_chunk,
                started: Instant::now(),
            })
            .await
            {
                Ok(txid_data) => txid_data,
                Err(failure) => {
                    self.record_failure_if_current(failure).await;
                    return None;
                }
            };
        let txid_data_elapsed_ms = txid_data_started.elapsed().as_millis();
        debug!(target: LOG_TARGET,
            chain_id = request.cfg.chain.chain_id,
            txid_data_elapsed_ms,
            candidate_elapsed_ms = self.started.elapsed().as_millis(),
            "output POI recovery TXID data recovered"
        );
        Some(Reconstruction {
            chunk: recovery_chunk,
            txid_data,
        })
    }

    /// Generates the candidate's output POIs and persists them as its pending context.
    pub(super) async fn prove_and_persist(
        self,
        reconstruction: Reconstruction,
    ) -> CandidateOutcome {
        if !self.still_current().await {
            return CandidateOutcome::Skipped;
        }

        let request = self.scan.request;
        let proof_source_resolution = request.resolve_proof_source(&self.list_keys).await;
        if !self.still_current().await {
            return CandidateOutcome::Skipped;
        }
        let proof_source: &dyn PoiMerkleProofSource = match &proof_source_resolution {
            OutputPoiProofSourceResolution::Local { source, .. } => source,
            OutputPoiProofSourceResolution::Unavailable => {
                if self.still_current().await {
                    log_local_poi_cache_unavailable(
                        request.cfg,
                        "output_poi_recovery_proof_generation",
                    );
                    self.record_failure(RecoveryFailure::retryable(
                        OutputPoiRecoveryStatus::ProofGenerationFailed,
                        "local POI proof source unavailable",
                        OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
                    ))
                    .await;
                }
                return CandidateOutcome::Skipped;
            }
        };
        let proof_generation_started = Instant::now();
        let generated = generate_post_transaction_pois(PostTransactionPoiGenerationRequest {
            chunk: &reconstruction.chunk.chunk,
            txid_data: &reconstruction.txid_data.poi_data,
            chain_type: EVM_CHAIN_TYPE,
            chain_id: request.cfg.chain.chain_id,
            txid_version: Some(DEFAULT_TXID_VERSION),
            required_poi_list_keys: &self.list_keys,
            proof_source,
            prover: self.scan.prover,
            verify_proof: OUTPUT_POI_RECOVERY_VERIFY_PROOF,
        })
        .await;
        match generated {
            Ok(pre_transaction_pois) => {
                self.persist_context(
                    &reconstruction,
                    pre_transaction_pois,
                    &proof_source_resolution,
                    proof_generation_started,
                )
                .await
            }
            Err(err) => {
                self.record_proof_failure(&err, proof_generation_started)
                    .await;
                CandidateOutcome::Skipped
            }
        }
    }

    /// Records a proof-generation failure if the candidate is still current.
    async fn record_proof_failure(
        &self,
        err: &PreTransactionPoiError,
        proof_generation_started: Instant,
    ) {
        if !self.still_current().await {
            return;
        }
        let request = self.scan.request;
        let proof_generation_elapsed_ms = proof_generation_started.elapsed().as_millis();
        warn!(target: LOG_TARGET,
            chain_id = request.cfg.chain.chain_id,
            proof_generation_elapsed_ms,
            candidate_elapsed_ms = self.started.elapsed().as_millis(),
            "output POI recovery proof generation failed"
        );
        let retry_after = output_poi_recovery_proof_retry_after(err);
        self.record_failure(RecoveryFailure::retryable(
            OutputPoiRecoveryStatus::ProofGenerationFailed,
            err.to_string(),
            retry_after,
        ))
        .await;
        log_candidate_elapsed(request.cfg, self.started);
    }

    /// Persists the generated POIs as the candidate's pending context.
    async fn persist_context(
        self,
        reconstruction: &Reconstruction,
        pre_transaction_pois: PreTransactionPoiMap,
        proof_source_resolution: &OutputPoiProofSourceResolution,
        proof_generation_started: Instant,
    ) -> CandidateOutcome {
        if !self.still_current().await {
            return CandidateOutcome::Skipped;
        }
        let scan = self.scan;
        let request = scan.request;
        let candidate = self.candidate;
        let proof_generation_elapsed_ms = proof_generation_started.elapsed().as_millis();
        let record = if let Some(existing) = self.pending_context_extension.as_ref() {
            extend_pending_output_poi_context(existing, &self.list_keys, pre_transaction_pois)
        } else {
            pending_output_poi_context_from_recovery(
                request.cfg,
                candidate,
                &reconstruction.chunk,
                reconstruction.txid_data.poi_data.txid_merkleroot_index,
                pre_transaction_pois,
                &self.list_keys,
                scan.now,
            )
        };
        let Ok(current_recovery) = request.cache_store.get_output_poi_recovery(
            request.cfg.chain.chain_id,
            &request.cfg.cache_key,
            &candidate.utxo.poi.commitment,
        ) else {
            warn!(target: LOG_TARGET,
                chain_id = request.cfg.chain.chain_id,
                "failed to load recovered output POI predecessor"
            );
            return CandidateOutcome::Skipped;
        };
        let Some(expected_recovery) = expected_recovery_state(current_recovery.as_ref()) else {
            return CandidateOutcome::Skipped;
        };
        let action = self.recovery_action(current_recovery.as_ref());
        match apply_poi_private_delta(
            request.authority,
            request.db,
            request.cache_store,
            request.cfg,
            OwnedPoiPrivateDelta::OutputRecovery(OutputRecoveryDelta {
                expected_output: ExpectedWalletOutput::new(candidate),
                active_list_keys: request.active_list_keys.to_vec(),
                target_list_keys: self.list_keys.clone(),
                required_poi_status: ExpectedPoiStatus::Recoverable,
                pending_update: Box::new(Some((self.expected_pending_context, record))),
                expected_recovery,
                action,
                now: scan.now,
                expected_corpus: proof_source_resolution.expected_corpus_revision(),
                replay_fence: reconstruction.chunk.replay_fence.clone(),
            }),
        )
        .await
        {
            Ok(PoiPrivateApplyOutcome::Applied { .. }) => {}
            Ok(PoiPrivateApplyOutcome::SkippedStaleCorpusRevision) => {
                return CandidateOutcome::StaleCorpusRevision;
            }
            Ok(PoiPrivateApplyOutcome::Skipped) => return CandidateOutcome::Skipped,
            Err(_) => {
                warn!(target: LOG_TARGET,
                    chain_id = request.cfg.chain.chain_id,
                    "failed to persist recovered output POI context"
                );
                return CandidateOutcome::Skipped;
            }
        }
        debug!(target: LOG_TARGET,
            chain_id = request.cfg.chain.chain_id,
            inputs = reconstruction.chunk.chunk.inputs.len(),
            outputs = reconstruction.chunk.chunk.outputs.len(),
            proof_generation_elapsed_ms,
            candidate_elapsed_ms = self.started.elapsed().as_millis(),
            "reconstructed output POI context"
        );
        log_candidate_elapsed(request.cfg, self.started);
        CandidateOutcome::Recovered
    }

    /// Extends the saved context unless the current recovery is `Valid`, otherwise re-detects it.
    fn recovery_action(
        &self,
        current_recovery: Option<&OutputPoiRecoveryRecord>,
    ) -> OutputPoiRecoveryAction {
        let reset_valid_recovery =
            current_recovery.is_some_and(|record| record.status == OutputPoiRecoveryStatus::Valid);
        if self.pending_context_extension.is_some() && !reset_valid_recovery {
            OutputPoiRecoveryAction::ExtendContext
        } else {
            OutputPoiRecoveryAction::Detected {
                status: OutputPoiRecoveryStatus::Recoverable,
                retry_after: None,
                last_error: None,
                increment_attempts: false,
            }
        }
    }
}

/// Logs how long one recovery candidate took, as a warning when it was slow.
fn log_candidate_elapsed(cfg: &WalletConfig, started: Instant) {
    let candidate_elapsed = started.elapsed();
    if candidate_elapsed >= OUTPUT_POI_RECOVERY_SLOW_STEP_AFTER {
        warn!(target: LOG_TARGET,
            chain_id = cfg.chain.chain_id,
            elapsed_ms = candidate_elapsed.as_millis(),
            "slow output POI recovery candidate"
        );
    } else {
        debug!(target: LOG_TARGET,
            chain_id = cfg.chain.chain_id,
            elapsed_ms = candidate_elapsed.as_millis(),
            "output POI recovery candidate complete"
        );
    }
}
