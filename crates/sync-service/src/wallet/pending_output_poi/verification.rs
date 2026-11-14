use super::{
    BTreeMap, BlindedCommitmentData, ChainPublicDataPlane, DbStore, EVM_CHAIN_TYPE,
    ExpectedPoiListState, ExpectedRecordState, FixedBytes, LocallyValidPendingListsDelta,
    OutputPoiRecoveryAction, OwnedPoiPrivateDelta, PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER,
    PendingOutputPoiContextRecord, PendingOutputPoiSubject, PendingOutputPoiSubmissionPredicate,
    PendingOutputPoiSubmitIdentity, PendingOutputPoiValidationEvidence, PendingSubmissionDelta,
    PoiPrivateApplyOutcome, PoiStatus, PoiStatusReader, PublicPoiCorpusKey, VerifiedValidDelta,
    WalletCacheError, WalletCacheStore, WalletConfig, WalletPoiRuntime,
    WalletPrivateMutationAuthority, WalletPrivatePoiClients, WalletPrivateRemoteError,
    apply_poi_private_delta, current_pending_output_poi_subject, debug, expected_recovery_matches,
    expected_recovery_state, info, now_epoch_secs, pending_output_poi_context_fingerprint,
    pending_output_poi_subject_matches_snapshot, pending_output_poi_submit_identity, warn,
};

#[derive(Default)]
pub(in crate::wallet) struct PendingOutputPoiVerificationOutcome {
    pub(in crate::wallet) completed: usize,
    pub(in crate::wallet) pending: usize,
    pub(in crate::wallet) errors: usize,
}

pub(super) enum AuthorizedPoiStatusSource<'a> {
    Local(&'a dyn PoiStatusReader),
    Remote(&'a WalletPrivatePoiClients),
}

async fn read_pending_output_poi_statuses(
    source: &AuthorizedPoiStatusSource<'_>,
    authority: &WalletPrivateMutationAuthority<'_>,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    record: &PendingOutputPoiContextRecord,
    subject: &PendingOutputPoiSubject,
    expected_recovery: &ExpectedRecordState,
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
                    pending_output_poi_subject_still_current(
                        authority,
                        cache_store,
                        cfg,
                        record,
                        subject,
                        expected_recovery,
                    )
                    .await
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

pub(in crate::wallet) async fn reconcile_pending_output_poi_local_statuses(
    authority: &WalletPrivateMutationAuthority<'_>,
    reader: &dyn PoiStatusReader,
    db: &DbStore,
    cfg: &WalletConfig,
    cache_store: &dyn WalletCacheStore,
    active_list_keys: &[FixedBytes<32>],
) -> PendingOutputPoiVerificationOutcome {
    let Ok(records) =
        cache_store.list_pending_output_poi_contexts(cfg.chain.chain_id, &cfg.cache_key)
    else {
        return PendingOutputPoiVerificationOutcome {
            errors: 1,
            ..PendingOutputPoiVerificationOutcome::default()
        };
    };
    let mut outcome = PendingOutputPoiVerificationOutcome::default();
    let now = now_epoch_secs();
    let source = AuthorizedPoiStatusSource::Local(reader);
    let mut suppressed_contexts = 0usize;
    let mut suppressed_list_keys = 0usize;
    for record in records {
        if record.terminal_error.is_some() {
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
        if required_list_keys.is_empty() {
            continue;
        }
        let Some(identity) = pending_output_poi_submit_identity(&record, observation) else {
            continue;
        };
        let Some((subject, _)) = current_pending_output_poi_subject(authority, cfg, &record).await
        else {
            continue;
        };
        let Ok(recovery) = cache_store.get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &record.output_commitment,
        ) else {
            outcome.errors += 1;
            continue;
        };
        let Some(expected_recovery) = expected_recovery_state(recovery.as_ref()) else {
            outcome.errors += 1;
            continue;
        };
        let statuses = match read_pending_output_poi_statuses(
            &source,
            authority,
            cache_store,
            cfg,
            &record,
            &subject,
            &expected_recovery,
            &required_list_keys,
            &identity,
        )
        .await
        {
            Ok(Some(mut statuses)) => statuses
                .remove(&identity.derived_blinded_commitment)
                .unwrap_or_default(),
            Ok(None) | Err(_) => continue,
        };
        let valid_list_keys = required_list_keys
            .iter()
            .copied()
            .filter(|list_key| statuses.get(list_key) == Some(&PoiStatus::Valid))
            .collect::<Vec<_>>();
        if valid_list_keys.is_empty() {
            continue;
        }
        let Some(expected_context_fingerprint) = pending_output_poi_context_fingerprint(&record)
        else {
            outcome.errors += 1;
            continue;
        };
        let applied = apply_poi_private_delta(
            authority,
            db,
            cache_store,
            cfg,
            OwnedPoiPrivateDelta::LocallyValidPendingLists(LocallyValidPendingListsDelta {
                subject,
                expected_context_fingerprint,
                expected_recovery,
                active_list_keys: active_list_keys.to_vec(),
                valid_list_keys: valid_list_keys.clone(),
                now,
            }),
        )
        .await;
        match applied {
            Ok(PoiPrivateApplyOutcome::Applied { .. }) => {
                suppressed_contexts += 1;
                suppressed_list_keys += valid_list_keys.len();
                if valid_list_keys.len() == required_list_keys.len() {
                    outcome.completed += 1;
                } else {
                    outcome.pending += 1;
                }
            }
            Ok(
                PoiPrivateApplyOutcome::Skipped
                | PoiPrivateApplyOutcome::SkippedStaleCorpusRevision,
            ) => {}
            Err(_) => outcome.errors += 1,
        }
    }
    if suppressed_contexts > 0 {
        info!(
            contexts = suppressed_contexts,
            list_keys = suppressed_list_keys,
            "canonical pending output POI submission suppressed for locally valid lists"
        );
    }
    outcome
}

pub(in crate::wallet) async fn verify_submitted_pending_output_pois_with_config_authorized(
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
                let local_reconciled = reconcile_pending_output_poi_local_statuses(
                    authority,
                    &reader,
                    db,
                    cfg,
                    cache_store,
                    active_list_keys,
                )
                .await;
                let mut remaining = verify_submitted_pending_output_pois_inner(
                    authority,
                    AuthorizedPoiStatusSource::Local(&reader),
                    db,
                    cfg,
                    cache_store,
                    active_list_keys,
                )
                .await;
                remaining.completed += local_reconciled.completed;
                remaining.pending += local_reconciled.pending;
                remaining.errors += local_reconciled.errors;
                remaining
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

pub(super) async fn verify_submitted_pending_output_pois_inner(
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

async fn pending_output_poi_subject_still_current(
    authority: &WalletPrivateMutationAuthority<'_>,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    record: &PendingOutputPoiContextRecord,
    subject: &PendingOutputPoiSubject,
    expected_recovery: &ExpectedRecordState,
) -> Result<bool, WalletCacheError> {
    if authority.revalidate().is_err() {
        return Ok(false);
    }
    let Some(current) = cache_store.get_pending_output_poi_context(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &record.output_commitment,
    )?
    else {
        return Ok(false);
    };
    if pending_output_poi_context_fingerprint(&current)
        != pending_output_poi_context_fingerprint(record)
    {
        return Ok(false);
    }
    let snapshot = authority
        .wallet_utxos()
        .await
        .map_err(|_| WalletCacheError::Crypto)?;
    let Some(postflight_context) = cache_store.get_pending_output_poi_context(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &record.output_commitment,
    )?
    else {
        return Ok(false);
    };
    if authority.revalidate().is_err()
        || pending_output_poi_context_fingerprint(&postflight_context)
            != pending_output_poi_context_fingerprint(record)
        || pending_output_poi_subject_matches_snapshot(cfg, &snapshot, &postflight_context, subject)
            .is_none()
    {
        return Ok(false);
    }
    let current_recovery = cache_store.get_output_poi_recovery(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &record.output_commitment,
    )?;
    let Some(final_context) = cache_store.get_pending_output_poi_context(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &record.output_commitment,
    )?
    else {
        return Ok(false);
    };
    Ok(authority.revalidate().is_ok()
        && pending_output_poi_context_fingerprint(&final_context)
            == pending_output_poi_context_fingerprint(record)
        && pending_output_poi_subject_matches_snapshot(cfg, &snapshot, &final_context, subject)
            .is_some()
        && expected_recovery_matches(expected_recovery, current_recovery.as_ref())
        && current_recovery.as_ref().is_none_or(|recovery| {
            final_context
                .observation
                .as_ref()
                .is_some_and(|observation| recovery.source_tx_hash == observation.tx_hash)
        }))
}

async fn commit_verified_pending_output_poi_context(
    authority: &WalletPrivateMutationAuthority<'_>,
    db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    record: &PendingOutputPoiContextRecord,
    subject: PendingOutputPoiSubject,
    evidence: PendingOutputPoiValidationEvidence,
    expected_recovery: ExpectedRecordState,
    expected_poi_list_state: Option<ExpectedPoiListState>,
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
        OwnedPoiPrivateDelta::VerifiedValid(VerifiedValidDelta {
            subject,
            evidence,
            expected_context_fingerprint,
            expected_recovery,
            expected_poi_list_state,
            active_list_keys: active_list_keys.to_vec(),
            valid_list_keys: valid_list_keys.to_vec(),
            now,
        }),
    )
    .await?
    {
        PoiPrivateApplyOutcome::Applied { .. } => Ok(true),
        PoiPrivateApplyOutcome::Skipped | PoiPrivateApplyOutcome::SkippedStaleCorpusRevision => {
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
        if record.terminal_error.is_some() {
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
        if required_list_keys.is_empty() {
            continue;
        }
        let Some((subject, current_output)) =
            current_pending_output_poi_subject(authority, cfg, &record).await
        else {
            continue;
        };
        let all_lists_submitted = required_list_keys
            .iter()
            .all(|list_key| record.submitted_poi_list_keys.contains(list_key));
        let evidence = if all_lists_submitted {
            PendingOutputPoiValidationEvidence::SubmittedStatus
        } else if current_output
            .as_ref()
            .is_some_and(|output| output.utxo.poi.is_valid_for_lists(&required_list_keys))
        {
            PendingOutputPoiValidationEvidence::OwnedStatusRefresh
        } else {
            continue;
        };
        let expected_poi_list_state = current_output
            .as_ref()
            .map(|output| ExpectedPoiListState::new(&output.utxo.poi, &required_list_keys));
        let Ok(recovery) = cache_store.get_output_poi_recovery(
            chain_id,
            &cfg.cache_key,
            &record.output_commitment,
        ) else {
            outcome.errors += 1;
            continue;
        };
        if recovery
            .as_ref()
            .is_some_and(|recovery| recovery.source_tx_hash != observation.tx_hash)
        {
            continue;
        }
        let Some(expected_recovery) = expected_recovery_state(recovery.as_ref()) else {
            outcome.errors += 1;
            continue;
        };
        match pending_output_poi_subject_still_current(
            authority,
            cache_store,
            cfg,
            &record,
            &subject,
            &expected_recovery,
        )
        .await
        {
            Ok(true) => {}
            Ok(false) => continue,
            Err(_) => {
                outcome.errors += 1;
                continue;
            }
        }
        let all_valid = match evidence {
            PendingOutputPoiValidationEvidence::OwnedStatusRefresh => true,
            PendingOutputPoiValidationEvidence::SubmittedStatus => {
                let Some(identity) = pending_output_poi_submit_identity(&record, observation)
                else {
                    continue;
                };
                let statuses = match read_pending_output_poi_statuses(
                    status_source,
                    authority,
                    cache_store,
                    cfg,
                    &record,
                    &subject,
                    &expected_recovery,
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
                match pending_output_poi_subject_still_current(
                    authority,
                    cache_store,
                    cfg,
                    &record,
                    &subject,
                    &expected_recovery,
                )
                .await
                {
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
                required_list_keys
                    .iter()
                    .all(|list_key| statuses.get(list_key) == Some(&PoiStatus::Valid))
            }
        };
        if all_valid {
            match commit_verified_pending_output_poi_context(
                authority,
                db,
                cache_store,
                cfg,
                &record,
                subject.clone(),
                evidence,
                expected_recovery.clone(),
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
                "reconciled valid pending output POI context"
            );
        } else {
            if recovery.is_none() {
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
                    OwnedPoiPrivateDelta::PendingSubmission(PendingSubmissionDelta {
                        subject,
                        expected_context_fingerprint,
                        expected_recovery,
                        active_list_keys: active_list_keys.to_vec(),
                        list_keys: required_list_keys.clone(),
                        predicate: PendingOutputPoiSubmissionPredicate::RetrySubmitted,
                        merge_submitted_list_keys: false,
                        action: OutputPoiRecoveryAction::Submitted {
                            retry_after: PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER,
                        },
                        now,
                    }),
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
            outcome.pending += 1;
        }
    }
    if outcome.completed > 0 || outcome.pending > 0 || outcome.errors > 0 {
        debug!(
            chain_id,
            completed = outcome.completed,
            pending = outcome.pending,
            errors = outcome.errors,
            "reconciled pending output POI contexts"
        );
    }
    outcome
}
