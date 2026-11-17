use std::collections::BTreeSet;
use std::ops::ControlFlow;

use super::{
    BTreeMap, ChainPublicDataPlane, EVM_CHAIN_TYPE, ExpectedPoiCorpusRevision,
    ExpectedWalletOutput, FixedBytes, OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
    OutputPoiRecoveryAction, OwnedPoiPrivateDelta, PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER,
    PendingOutputPoiContextRecord, PendingOutputPoiPreflight, PendingOutputPoiRemoteAttempt,
    PendingOutputPoiRole, PendingOutputPoiSubject, PendingOutputPoiSubmissionPass,
    PendingOutputPoiSubmissionPassState, PendingOutputPoiSubmissionPlan,
    PendingOutputPoiSubmissionPredicate, PoiPrivateApplyOutcome, PublicPoiCorpusKey,
    RecoveredOutgoingSubmissionDelta, RecoveredOutgoingSubmissionSibling, TransactProofRoute,
    WalletCacheError, WalletConfig, WalletPrivateRemoteError, WalletPrivateRemoteStale, WalletUtxo,
    apply_poi_private_delta, current_pending_output_poi_subject, debug, expected_recovery_matches,
    expected_recovery_state, hold_expected_poi_corpus_revision,
    pending_output_poi_context_fingerprint, pending_output_poi_submit_identity,
    recoverable_pending_submission_list_keys, saved_pending_context_matches_public_transaction,
    transact_proof_route, warn,
};

struct RecoveredOutgoingSubmissionMember {
    record: PendingOutputPoiContextRecord,
    subject: PendingOutputPoiSubject,
    plan: PendingOutputPoiSubmissionPlan,
    expected_context_fingerprint: Vec<u8>,
}

struct RecoveredOutgoingSubmissionGroup {
    members: Vec<RecoveredOutgoingSubmissionMember>,
    owned_substitutes: Vec<ExpectedWalletOutput>,
    external_valid_substitutes: Vec<FixedBytes<32>>,
    expected_corpus: Option<ExpectedPoiCorpusRevision>,
    proofs: Vec<(FixedBytes<32>, broadcaster_core::transact::PreTxPoi)>,
}

pub(super) struct RecoveredOutgoingGroupEvidence<'a> {
    proofs: Vec<(FixedBytes<32>, broadcaster_core::transact::PreTxPoi)>,
    pub(super) owned_outputs: Vec<&'a WalletUtxo>,
    pub(super) external_valid_substitutes: Vec<FixedBytes<32>>,
}

pub(super) fn recovered_outgoing_group_records<'a>(
    records: &'a [PendingOutputPoiContextRecord],
    seed: &PendingOutputPoiContextRecord,
) -> Option<Vec<&'a PendingOutputPoiContextRecord>> {
    if seed.output_role != PendingOutputPoiRole::RecoveredOutgoing
        || seed.source_operation_id.is_none()
    {
        return None;
    }
    let records = records
        .iter()
        .filter(|record| {
            record.output_role == PendingOutputPoiRole::RecoveredOutgoing
                && record.chain_id == seed.chain_id
                && record.wallet_id == seed.wallet_id
                && record.source_operation_id == seed.source_operation_id
        })
        .collect::<Vec<_>>();
    (!records.is_empty()).then_some(records)
}

pub(super) fn recovered_outgoing_group_evidence<'a>(
    records: &[&PendingOutputPoiContextRecord],
    wallet_utxos: &'a [WalletUtxo],
    list_keys: &[FixedBytes<32>],
    external_valid: &BTreeMap<FixedBytes<32>, BTreeSet<FixedBytes<32>>>,
) -> Option<RecoveredOutgoingGroupEvidence<'a>> {
    let leader = *records.first()?;
    let leader_observation = leader.observation.as_ref()?;
    let transaction_material = rmp_serde::to_vec(&(
        &leader.txid_version,
        leader.utxo_tree_in,
        leader.railgun_txid,
        leader.txid_merkleroot_index,
        &leader.source_operation_id,
    ))
    .ok()?;
    if leader.txid_merkleroot_index.is_none()
        || leader.required_poi_list_keys.is_empty()
        || list_keys.is_empty()
        || records.iter().any(|record| {
            record.observation.as_ref().is_none_or(|observation| {
                observation.tx_hash != leader_observation.tx_hash
                    || observation.block_number != leader_observation.block_number
                    || observation.block_timestamp != leader_observation.block_timestamp
            }) || rmp_serde::to_vec(&(
                &record.txid_version,
                record.utxo_tree_in,
                record.railgun_txid,
                record.txid_merkleroot_index,
                &record.source_operation_id,
            ))
            .ok()
            .as_ref()
                != Some(&transaction_material)
        })
    {
        return None;
    }

    let mut external_outputs = BTreeSet::new();
    let mut immutable_outputs = BTreeSet::new();
    let mut retained_proofs = BTreeMap::new();
    for record in records {
        for (list_key, per_leaf) in &record.pre_transaction_pois_per_txid_leaf_per_list {
            let encoded = rmp_serde::to_vec(per_leaf).ok()?;
            if retained_proofs
                .insert(*list_key, encoded.clone())
                .is_some_and(|previous| previous != encoded)
            {
                return None;
            }
        }
        let observation = record.observation.as_ref()?;
        let identity = pending_output_poi_submit_identity(record, observation)?;
        if !external_outputs.insert(identity.derived_blinded_commitment)
            || !immutable_outputs.insert((
                observation.output_tree,
                observation.output_position,
                record.output_commitment,
                record.output_npk,
            ))
        {
            return None;
        }
    }

    let mut proofs = Vec::with_capacity(list_keys.len());
    let mut proof_outputs = None;
    for list_key in list_keys {
        let mut retained = records.iter().filter_map(|record| {
            record
                .pre_transaction_pois_per_txid_leaf_per_list
                .get(list_key)
        });
        let per_leaf = retained.next()?;
        let encoded = rmp_serde::to_vec(per_leaf).ok()?;
        if retained.any(|other| rmp_serde::to_vec(other).ok().as_ref() != Some(&encoded)) {
            return None;
        }
        let mut values = per_leaf.values();
        let poi = values.next()?.clone();
        if values.next().is_some()
            || poi
                .blinded_commitments_out
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len()
                != poi.blinded_commitments_out.len()
        {
            return None;
        }
        let outputs = poi
            .blinded_commitments_out
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if proof_outputs
            .as_ref()
            .is_some_and(|expected| expected != &outputs)
        {
            return None;
        }
        proof_outputs = Some(outputs);
        proofs.push((*list_key, poi));
    }
    let proof_outputs = proof_outputs?;
    if !external_outputs.is_subset(&proof_outputs) {
        return None;
    }
    let mut owned_outputs = Vec::new();
    let mut external_valid_substitutes = BTreeSet::new();
    for list_key in list_keys {
        let unresolved = records
            .iter()
            .filter(|record| record.list_keys().contains(list_key))
            .filter_map(|record| {
                record
                    .observation
                    .as_ref()
                    .and_then(|observation| pending_output_poi_submit_identity(record, observation))
            })
            .map(|identity| identity.derived_blinded_commitment)
            .collect::<BTreeSet<_>>();
        for blinded_commitment in proof_outputs.difference(&unresolved) {
            let mut matches = wallet_utxos.iter().filter(|output| {
                !output.is_spent()
                    && output.utxo.poi.blinded_commitment == *blinded_commitment
                    && output.utxo.source.tx_hash == leader_observation.tx_hash
                    && output.utxo.source.block_number == leader_observation.block_number
                    && output.utxo.poi.is_valid_for_lists(&[*list_key])
            });
            let Some(output) = matches.next() else {
                if external_valid
                    .get(list_key)
                    .is_some_and(|valid| valid.contains(blinded_commitment))
                {
                    external_valid_substitutes.insert(*blinded_commitment);
                    continue;
                }
                return None;
            };
            if matches.next().is_some() {
                return None;
            }
            if !owned_outputs.iter().any(|existing: &&WalletUtxo| {
                existing.utxo.poi.blinded_commitment == *blinded_commitment
            }) {
                owned_outputs.push(output);
            }
        }
    }
    Some(RecoveredOutgoingGroupEvidence {
        proofs,
        owned_outputs,
        external_valid_substitutes: external_valid_substitutes.into_iter().collect(),
    })
}

pub(super) fn recovered_outgoing_owned_substitutes_match(
    expected: &[ExpectedWalletOutput],
    current: &[&WalletUtxo],
) -> bool {
    expected.len() == current.len()
        && expected.iter().all(|expected| {
            current
                .iter()
                .filter(|output| expected.matches(output))
                .count()
                == 1
        })
        && current.iter().all(|output| {
            expected
                .iter()
                .filter(|expected| expected.matches(output))
                .count()
                == 1
        })
}

async fn recovered_outgoing_external_valid_evidence(
    public_data_plane: &ChainPublicDataPlane,
    cfg: &WalletConfig,
    seed: &PendingOutputPoiContextRecord,
    list_keys: &[FixedBytes<32>],
) -> (
    BTreeMap<FixedBytes<32>, BTreeSet<FixedBytes<32>>>,
    Option<ExpectedPoiCorpusRevision>,
) {
    let Ok(corpus) = public_data_plane
        .ensure_poi_corpus(PublicPoiCorpusKey::wallet_default(cfg.chain.chain_id))
        .await
    else {
        return (BTreeMap::new(), None);
    };
    let _fence = corpus.revision_read_fence().await;
    let outputs = seed
        .pre_transaction_pois_per_txid_leaf_per_list
        .values()
        .flat_map(|per_leaf| per_leaf.values())
        .flat_map(|poi| poi.blinded_commitments_out.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let revision = *corpus.committed_revision_rx().borrow();
    let Some(valid) = super::saved_poi_compatibility::corpus_valid_outputs_by_list(
        &corpus,
        cfg.chain.chain_id,
        list_keys,
        &outputs,
    )
    .await
    else {
        return (BTreeMap::new(), None);
    };
    (valid, Some(ExpectedPoiCorpusRevision { corpus, revision }))
}

impl PendingOutputPoiSubmissionPass<'_> {
    pub(super) async fn submit_recovered_group(
        &self,
        state: &mut PendingOutputPoiSubmissionPassState,
        record: &PendingOutputPoiContextRecord,
    ) -> Result<ControlFlow<()>, WalletCacheError> {
        let force_submission_retry = self.force_retry(record);
        let chain_id = self.cfg.chain.chain_id;
        let Some(group) = self
            .prepare_recovered_outgoing_submission_group(record, force_submission_retry)
            .await?
        else {
            return Ok(ControlFlow::Continue(()));
        };
        let remote_attempt = self
            .submit_recovered_outgoing_submission_group(&group, &mut state.route)
            .await?;
        debug!(
            chain_id,
            force_submission_retry,
            retry_submitted = group.members.iter().any(|member| {
                matches!(
                    member.plan.predicate,
                    PendingOutputPoiSubmissionPredicate::RetrySubmitted
                )
            }),
            "pending output POI retry-submitted group due"
        );
        let (submitted_list_keys, merge_submitted_list_keys, action, submitted) =
            match remote_attempt {
                PendingOutputPoiRemoteAttempt::AuthorityStale => return Ok(ControlFlow::Break(())),
                PendingOutputPoiRemoteAttempt::NotCurrent
                | PendingOutputPoiRemoteAttempt::MissingPreTransactionPois => {
                    return Ok(ControlFlow::Continue(()));
                }
                PendingOutputPoiRemoteAttempt::Deferred => {
                    state.deferred_txids.insert(record.railgun_txid);
                    return Ok(ControlFlow::Continue(()));
                }
                PendingOutputPoiRemoteAttempt::Succeeded {
                    submitted_list_keys,
                } => (
                    submitted_list_keys,
                    true,
                    OutputPoiRecoveryAction::Submitted {
                        retry_after: PENDING_OUTPUT_POI_SUBMITTED_RETRY_AFTER,
                    },
                    true,
                ),
                PendingOutputPoiRemoteAttempt::Failed { error } => (
                    group.proofs.iter().map(|(list_key, _)| *list_key).collect(),
                    false,
                    OutputPoiRecoveryAction::SubmitFailed {
                        error,
                        retry_after: OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
                    },
                    false,
                ),
            };
        if !matches!(
            self.recovered_outgoing_submission_group_current(&group)
                .await?,
            PendingOutputPoiPreflight::Ready
        ) {
            return Ok(ControlFlow::Continue(()));
        }
        let siblings = group
            .members
            .iter()
            .map(|member| RecoveredOutgoingSubmissionSibling {
                subject: member.subject.clone(),
                expected_context_fingerprint: member.expected_context_fingerprint.clone(),
                plan: member.plan.clone(),
            })
            .collect::<Vec<_>>();
        let sibling_count = siblings.len();
        match apply_poi_private_delta(
            self.authority,
            self.db,
            self.cache_store,
            self.cfg,
            OwnedPoiPrivateDelta::RecoveredOutgoingSubmission(RecoveredOutgoingSubmissionDelta {
                siblings,
                owned_substitutes: group.owned_substitutes.clone(),
                external_valid_substitutes: group.external_valid_substitutes.clone(),
                expected_corpus: group.expected_corpus.clone(),
                active_list_keys: self.active_list_keys.to_vec(),
                list_keys: submitted_list_keys,
                merge_submitted_list_keys,
                action,
                now: self.now,
            }),
        )
        .await
        {
            Ok(PoiPrivateApplyOutcome::Applied { .. }) => {
                if submitted {
                    state.submitted_contexts += sibling_count;
                }
            }
            Ok(
                PoiPrivateApplyOutcome::Skipped
                | PoiPrivateApplyOutcome::SkippedStaleCorpusRevision,
            ) => {}
            Err(_) => warn!(
                chain_id,
                "failed to atomically persist recovered outgoing POI submission state"
            ),
        }
        Ok(ControlFlow::Continue(()))
    }

    async fn prepare_recovered_outgoing_submission_group(
        &self,
        seed: &PendingOutputPoiContextRecord,
        force_submission_retry: bool,
    ) -> Result<Option<RecoveredOutgoingSubmissionGroup>, WalletCacheError> {
        let Self {
            authority,
            public_data_plane,
            cache_store,
            cfg,
            active_list_keys,
            records,
            now,
            ..
        } = *self;
        let Some(group_records) = recovered_outgoing_group_records(records, seed) else {
            return Ok(None);
        };
        let Some(canonical) = group_records
            .iter()
            .min_by_key(|record| record.output_commitment)
        else {
            return Ok(None);
        };
        if canonical.output_commitment != seed.output_commitment {
            return Ok(None);
        }
        let snapshot = authority
            .wallet_utxos()
            .await
            .map_err(|_| WalletCacheError::Crypto)?;
        let (external_valid, expected_corpus) = recovered_outgoing_external_valid_evidence(
            public_data_plane,
            cfg,
            seed,
            active_list_keys,
        )
        .await;
        let mut members = Vec::with_capacity(group_records.len());
        for record in &group_records {
            if record.observation.is_none() {
                return Ok(None);
            }
            if record.terminal_error.is_some() {
                return Ok(None);
            }
            let Some(identity) = record
                .observation
                .as_ref()
                .and_then(|observation| pending_output_poi_submit_identity(record, observation))
            else {
                return Ok(None);
            };
            if record.required_poi_list_keys
                != super::saved_poi_compatibility::unresolved_output_lists(
                    active_list_keys,
                    identity.derived_blinded_commitment,
                    &external_valid,
                )
            {
                return Ok(None);
            }
            let Some(recovery) = cache_store.get_output_poi_recovery(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &record.output_commitment,
            )?
            else {
                return Ok(None);
            };
            let Some(expected_recovery) = expected_recovery_state(Some(&recovery)) else {
                return Ok(None);
            };
            let Some((subject, current_output)) =
                current_pending_output_poi_subject(authority, cfg, record).await
            else {
                return Ok(None);
            };
            if !matches!(&subject, PendingOutputPoiSubject::External { .. })
                || current_output.is_some()
            {
                return Ok(None);
            }
            let mut plan = PendingOutputPoiSubmissionPlan::missing(
                record.missing_list_keys(),
                expected_recovery,
            );
            plan.retain_current_recoverable(
                record,
                active_list_keys,
                current_output.as_ref().map(|output| &output.utxo.poi),
            );
            if plan.list_keys.is_empty()
                && recovery.submission_retry_allowed(now, force_submission_retry)
            {
                plan = PendingOutputPoiSubmissionPlan::retry_submitted(
                    record.list_keys(),
                    plan.expected_recovery.clone(),
                    force_submission_retry,
                );
                plan.retain_current_recoverable(
                    record,
                    active_list_keys,
                    current_output.as_ref().map(|output| &output.utxo.poi),
                );
            }
            let Some(expected_context_fingerprint) = pending_output_poi_context_fingerprint(record)
            else {
                return Ok(None);
            };
            members.push(RecoveredOutgoingSubmissionMember {
                record: (*record).clone(),
                subject,
                plan,
                expected_context_fingerprint,
            });
        }
        let list_keys = members
            .iter()
            .flat_map(|member| member.plan.list_keys().iter().copied())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if list_keys.is_empty()
            || expected_corpus.is_none()
            || members.iter().any(|member| {
                !saved_pending_context_matches_public_transaction(
                    public_data_plane,
                    cfg,
                    &member.record,
                    &member.record.list_keys(),
                )
            })
        {
            return Ok(None);
        }
        let Some(evidence) = recovered_outgoing_group_evidence(
            &group_records,
            &snapshot,
            &list_keys,
            &external_valid,
        ) else {
            return Ok(None);
        };
        Ok(Some(RecoveredOutgoingSubmissionGroup {
            members,
            owned_substitutes: evidence
                .owned_outputs
                .into_iter()
                .map(ExpectedWalletOutput::new)
                .collect(),
            expected_corpus,
            external_valid_substitutes: evidence.external_valid_substitutes,
            proofs: evidence.proofs,
        }))
    }

    async fn recovered_outgoing_submission_group_current(
        &self,
        group: &RecoveredOutgoingSubmissionGroup,
    ) -> Result<PendingOutputPoiPreflight, WalletCacheError> {
        let Self {
            authority,
            cache_store,
            cfg,
            active_list_keys,
            ..
        } = *self;
        if authority.revalidate().is_err() {
            return Ok(PendingOutputPoiPreflight::AuthorityStale);
        }
        let Some(seed) = group.members.first() else {
            return Ok(PendingOutputPoiPreflight::NotCurrent);
        };
        let current_records =
            cache_store.list_pending_output_poi_contexts(cfg.chain.chain_id, &cfg.cache_key)?;
        let Some(current_group) = recovered_outgoing_group_records(&current_records, &seed.record)
        else {
            return Ok(PendingOutputPoiPreflight::NotCurrent);
        };
        let expected_fingerprints = group
            .members
            .iter()
            .map(|member| member.expected_context_fingerprint.clone())
            .collect::<BTreeSet<_>>();
        let current_fingerprints = current_group
            .iter()
            .filter_map(|record| pending_output_poi_context_fingerprint(record))
            .collect::<BTreeSet<_>>();
        let snapshot = authority
            .wallet_utxos()
            .await
            .map_err(|_| WalletCacheError::Crypto)?;
        let list_keys = group
            .proofs
            .iter()
            .map(|(list_key, _)| *list_key)
            .collect::<Vec<_>>();
        let external_valid = if let Some(expected) = &group.expected_corpus {
            let outputs = group
                .proofs
                .iter()
                .flat_map(|(_, poi)| poi.blinded_commitments_out.iter().copied())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let Some(valid) = super::saved_poi_compatibility::corpus_valid_outputs_by_list(
                &expected.corpus,
                cfg.chain.chain_id,
                active_list_keys,
                &outputs,
            )
            .await
            else {
                return Ok(PendingOutputPoiPreflight::NotCurrent);
            };
            valid
        } else {
            BTreeMap::new()
        };
        let current_evidence = recovered_outgoing_group_evidence(
            &current_group,
            &snapshot,
            &list_keys,
            &external_valid,
        );
        if current_group.len() != group.members.len()
            || current_fingerprints.len() != current_group.len()
            || current_fingerprints != expected_fingerprints
            || current_evidence.as_ref().is_none_or(|evidence| {
                !recovered_outgoing_owned_substitutes_match(
                    &group.owned_substitutes,
                    &evidence.owned_outputs,
                )
            })
        {
            return Ok(PendingOutputPoiPreflight::NotCurrent);
        }
        for member in &group.members {
            let Some(identity) = member.record.observation.as_ref().and_then(|observation| {
                pending_output_poi_submit_identity(&member.record, observation)
            }) else {
                return Ok(PendingOutputPoiPreflight::NotCurrent);
            };
            if member.record.required_poi_list_keys
                != super::saved_poi_compatibility::unresolved_output_lists(
                    active_list_keys,
                    identity.derived_blinded_commitment,
                    &external_valid,
                )
            {
                return Ok(PendingOutputPoiPreflight::NotCurrent);
            }
            if member.plan.list_keys.is_empty() {
                let recovery = cache_store.get_output_poi_recovery(
                    cfg.chain.chain_id,
                    &cfg.cache_key,
                    &member.record.output_commitment,
                )?;
                if !expected_recovery_matches(&member.plan.expected_recovery, recovery.as_ref())
                    || !recoverable_pending_submission_list_keys(
                        &member.record,
                        active_list_keys,
                        None,
                        member.plan.predicate(),
                    )
                    .is_empty()
                {
                    return Ok(PendingOutputPoiPreflight::NotCurrent);
                }
                continue;
            }
            match self
                .preflight(&member.record, &member.subject, &member.plan)
                .run()
                .await?
            {
                PendingOutputPoiPreflight::Ready => {}
                not_ready => return Ok(not_ready),
            }
        }
        // Acquire the corpus fence only after the wallet actor awaits above. A corpus writer
        // may need that actor, so holding its read guard across an actor request can deadlock.
        let Ok(_corpus_fence) =
            hold_expected_poi_corpus_revision(group.expected_corpus.as_ref()).await
        else {
            return Ok(PendingOutputPoiPreflight::NotCurrent);
        };
        let final_records =
            cache_store.list_pending_output_poi_contexts(cfg.chain.chain_id, &cfg.cache_key)?;
        let Some(final_group) = recovered_outgoing_group_records(&final_records, &seed.record)
        else {
            return Ok(PendingOutputPoiPreflight::NotCurrent);
        };
        let final_fingerprints = final_group
            .iter()
            .filter_map(|record| pending_output_poi_context_fingerprint(record))
            .collect::<BTreeSet<_>>();
        if authority.revalidate().is_err()
            || final_group.len() != group.members.len()
            || final_fingerprints != expected_fingerprints
        {
            return Ok(PendingOutputPoiPreflight::NotCurrent);
        }
        for member in &group.members {
            let recovery = cache_store.get_output_poi_recovery(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &member.record.output_commitment,
            )?;
            if !expected_recovery_matches(&member.plan.expected_recovery, recovery.as_ref()) {
                return Ok(PendingOutputPoiPreflight::NotCurrent);
            }
        }
        Ok(PendingOutputPoiPreflight::Ready)
    }

    async fn submit_recovered_outgoing_submission_group(
        &self,
        group: &RecoveredOutgoingSubmissionGroup,
        route: &mut Option<TransactProofRoute>,
    ) -> Result<PendingOutputPoiRemoteAttempt, WalletCacheError> {
        let Self {
            cfg, private_poi, ..
        } = *self;
        let Some(leader) = group.members.first() else {
            return Ok(PendingOutputPoiRemoteAttempt::NotCurrent);
        };
        let Some(txid_merkleroot_index) = leader.record.txid_merkleroot_index else {
            return Ok(PendingOutputPoiRemoteAttempt::NotCurrent);
        };
        let forced = group
            .members
            .iter()
            .filter_map(|member| member.plan.deferred_force_kind())
            .max();
        let Some(route) = transact_proof_route(
            private_poi,
            route,
            cfg.chain.chain_id,
            &leader.record,
            forced,
        )
        .await
        else {
            return Ok(PendingOutputPoiRemoteAttempt::Deferred);
        };
        for (list_key, poi) in &group.proofs {
            let result = private_poi
                .submit_transact_proof(
                    route,
                    || async {
                        Ok(matches!(
                            self.recovered_outgoing_submission_group_current(group)
                                .await?,
                            PendingOutputPoiPreflight::Ready
                        ))
                    },
                    &leader.record.txid_version,
                    EVM_CHAIN_TYPE,
                    cfg.chain.chain_id,
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
                        error: error.to_string(),
                    });
                }
            }
        }
        Ok(PendingOutputPoiRemoteAttempt::Succeeded {
            submitted_list_keys: group.proofs.iter().map(|(list_key, _)| *list_key).collect(),
        })
    }
}
