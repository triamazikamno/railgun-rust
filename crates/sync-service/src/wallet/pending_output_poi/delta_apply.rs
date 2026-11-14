use std::collections::BTreeSet;

use crate::SenderTransactionCandidate;
use crate::SenderTransactionCandidateUnshield;
use crate::types::WalletBackfillRejectReason;

use super::{
    BTreeMap, BlindedCommitmentData, DbStore, ExpectedPoiStatus, FixedBytes,
    LocallyValidPendingListsDelta, OutputPoiRecoveryAction, OutputPoiRecoveryStatus,
    OutputRecoveryDelta, OwnedPoiPrivateDelta, PendingContextTerminalDelta, PendingOutputPoiRole,
    PendingOutputPoiSubject, PendingOutputPoiSubjectMatch, PendingOutputPoiSubmissionKind,
    PendingOutputPoiValidationEvidence, PendingSubmissionDelta, PoiPrivateApplyOutcome, PoiStatus,
    PoiStatusRefreshDelta, RecoveredOutgoingSubmissionDelta, SenderCandidateLocallyValidDelta,
    SenderCandidateMaterializationDelta, SenderCandidateReconstructionDelta,
    SenderCandidateUnshieldUpdateDelta, SenderCandidateUnshieldValidatedDelta, VerifiedValidDelta,
    WalletCacheError, WalletCacheStore, WalletCheckpointMutation, WalletConfig,
    WalletPrivateCommit, WalletPrivateMutationAuthority, WalletPrivateMutationPermit, WalletUtxo,
    WalletUtxoMutation, expected_pending_context_matches, expected_pending_context_state,
    expected_poi_status_matches, expected_recovery_matches, expected_recovery_state,
    hold_expected_poi_corpus_revision, new_output_poi_recovery_record,
    new_pending_output_poi_recovery_record, output_poi_recovery_default_status,
    pending_output_poi_context_fingerprint, pending_output_poi_context_matches_wallet_utxo,
    pending_output_poi_subject_matches_snapshot, pending_output_poi_submit_identity,
    pending_submission_predicate_matches, poi_statuses_are_recoverable_for_lists,
    prune_nonrecoverable_unsubmitted_poi_lists, recoverable_pending_submission_list_keys,
    recovered_outgoing_group_evidence, recovered_outgoing_group_records,
    recovered_outgoing_owned_substitutes_match, saved_pending_context_is_compatible,
    sender_materialization_pending_matches, sender_materialization_recovery_matches,
    wallet_ppoi_workflow_status_after_mutations, wallet_ppoi_workflow_status_after_validation,
};

/// Whether the stored sender candidate still equals `expected`; a missing record does not.
fn stored_sender_candidate_matches(
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    expected: &SenderTransactionCandidate,
) -> Result<bool, WalletCacheError> {
    Ok(cache_store
        .get_sender_transaction_candidate(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &expected.semantic_id(),
        )?
        .is_some_and(|current| {
            super::sender_candidate_recovery::candidates_match(expected, &current)
        }))
}

/// The candidate kept for handed-off unshield work, or `None` without unshield work. Work whose
/// outputs are not handed off, or that the candidate rejects, is an error.
fn handed_off_sender_candidate(
    expected_candidate: &SenderTransactionCandidate,
    unshield: Option<SenderTransactionCandidateUnshield>,
) -> Result<Option<SenderTransactionCandidate>, ()> {
    match unshield {
        Some(unshield) if unshield.outputs_handed_off => expected_candidate
            .clone()
            .with_unshield(Some(unshield))
            .map(Some)
            .map_err(|_| ()),
        Some(_) => Err(()),
        None => Ok(None),
    }
}

/// Candidate-only commit that writes `replacement`, or deletes the expected candidate without
/// one. The caller holds every fence the commit needs; the permit drops after it.
fn commit_sender_candidate_replacement(
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    validation_revision: u64,
    permit: WalletPrivateMutationPermit<'_>,
    expected_candidate_id: FixedBytes<32>,
    replacement: Option<SenderTransactionCandidate>,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    let (candidate_updates, candidate_deletes) = match replacement {
        Some(replacement) => (vec![replacement], Vec::new()),
        None => (Vec::new(), vec![expected_candidate_id]),
    };
    let workflow_status = wallet_ppoi_workflow_status_after_mutations(
        cache_store,
        cfg,
        active_list_keys,
        validation_revision,
        &[],
        &[],
        &[],
        &[],
        &candidate_updates,
        &candidate_deletes,
    )?;
    let result = permit.with_durable_apply(|token| {
        cache_store.commit_wallet_private_state(
            WalletPrivateCommit::new(
                &token,
                &permit,
                WalletUtxoMutation::Preserve,
                WalletCheckpointMutation::Preserve,
            )
            .with_sender_transaction_candidate_updates(&candidate_updates)
            .with_sender_transaction_candidate_deletes(&candidate_deletes),
        )?;
        permit.apply_publish_ppoi_workflow_projection(&token, workflow_status);
        Ok::<(), WalletCacheError>(())
    });
    drop(permit);
    durable_apply_outcome(result)
}

/// Outcome of a durable commit that leaves UTXOs unchanged; a rejected apply is an error.
fn durable_apply_outcome(
    result: Result<Result<(), WalletCacheError>, WalletBackfillRejectReason>,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    result.map_or(Err(WalletCacheError::Crypto), |committed| {
        committed.map(|()| PoiPrivateApplyOutcome::Applied {
            utxo_changed: false,
        })
    })
}

/// Outcome of an active apply that may change UTXOs; a rejected apply is skipped.
fn active_apply_outcome(
    result: Result<Result<(), WalletCacheError>, WalletBackfillRejectReason>,
    utxo_changed: bool,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    result.map_or(Ok(PoiPrivateApplyOutcome::Skipped), |committed| {
        committed.map(|()| PoiPrivateApplyOutcome::Applied { utxo_changed })
    })
}

/// Wallet state one exclusive apply holds while it folds a delta.
struct PoiApplyTurn<'a> {
    permit: WalletPrivateMutationPermit<'a>,
    snapshot: Vec<WalletUtxo>,
    cache_store: &'a dyn WalletCacheStore,
    cfg: &'a WalletConfig,
    active_list_keys: &'a [FixedBytes<32>],
}

/// Exclusive apply: acquire → fresh snapshot → fold → durable commit → mirrors → drop.
/// Call only from the actor turn (or single-threaded tests without an apply client).
pub(super) async fn apply_poi_private_delta_inline(
    authority: &WalletPrivateMutationAuthority<'_>,
    _db: &DbStore,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    delta: OwnedPoiPrivateDelta,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    let permit = authority
        .acquire()
        .await
        .map_err(|_| WalletCacheError::Crypto)?;
    let snapshot = permit
        .wallet_utxos()
        .await
        .map_err(|_| WalletCacheError::Crypto)?;
    if permit.chain_id() != cfg.chain.chain_id || permit.wallet_id() != &cfg.cache_key {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    let turn = PoiApplyTurn {
        permit,
        snapshot,
        cache_store,
        cfg,
        active_list_keys,
    };
    match delta {
        OwnedPoiPrivateDelta::SenderCandidateReconstruction(delta) => {
            apply_sender_candidate_reconstruction(turn, delta).await
        }
        OwnedPoiPrivateDelta::SenderCandidateLocallyValid(delta) => {
            apply_sender_candidate_locally_valid(turn, delta).await
        }
        OwnedPoiPrivateDelta::SenderCandidateMaterialization(delta) => {
            apply_sender_candidate_materialization(turn, delta).await
        }
        OwnedPoiPrivateDelta::SenderCandidateUnshieldUpdate(delta) => {
            apply_sender_candidate_unshield_update(turn, delta).await
        }
        OwnedPoiPrivateDelta::SenderCandidateUnshieldValidated(delta) => {
            apply_sender_candidate_unshield_validated(turn, delta).await
        }
        OwnedPoiPrivateDelta::OutputRecovery(delta) => apply_output_recovery(turn, delta).await,
        OwnedPoiPrivateDelta::PendingSubmission(delta) => apply_pending_submission(turn, delta),
        OwnedPoiPrivateDelta::RecoveredOutgoingSubmission(delta) => {
            apply_recovered_outgoing_submission(turn, delta).await
        }
        OwnedPoiPrivateDelta::PendingContextTerminal(delta) => {
            apply_pending_context_terminal(turn, delta)
        }
        OwnedPoiPrivateDelta::LocallyValidPendingLists(delta) => {
            apply_locally_valid_pending_lists(turn, delta).await
        }
        OwnedPoiPrivateDelta::VerifiedValid(delta) => apply_verified_valid(turn, delta).await,
        OwnedPoiPrivateDelta::PoiStatusRefresh(delta) => {
            apply_poi_status_refresh(turn, delta).await
        }
    }
}

async fn apply_sender_candidate_reconstruction(
    turn: PoiApplyTurn<'_>,
    delta: SenderCandidateReconstructionDelta,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    let PoiApplyTurn {
        permit,
        snapshot,
        cache_store,
        cfg,
        active_list_keys,
    } = turn;
    let SenderCandidateReconstructionDelta {
        candidate,
        replay_fence,
        expected_group,
    } = delta;
    let _public_commit_guard = replay_fence.public_data_plane.acquire_commit_guard().await;
    if candidate.validate().is_err()
        || candidate.chain_id != cfg.chain.chain_id
        || candidate.wallet_id != cfg.cache_key
        || replay_fence.public_data_plane.current_epoch() != replay_fence.epoch
        || expected_group.is_empty()
        || !super::sender_candidate_recovery::sender_candidate_matches_wallet_snapshot(
            &candidate, &snapshot,
        )
        || !super::saved_poi_compatibility::saved_sender_group_is_current(
            cache_store,
            cfg,
            &candidate.source,
            &expected_group,
        )?
        || expected_group.iter().any(|(record, _)| {
            record.observation.as_ref().is_none_or(|observation| {
                !candidate.outputs.iter().any(|output| {
                    u64::from(output.tree) == observation.output_tree
                        && output.position == observation.output_position
                        && output.commitment == record.output_commitment
                        && output.note.as_ref().is_some_and(|note| {
                            FixedBytes::from(note.npk.to_be_bytes::<32>()) == record.output_npk
                        })
                })
            })
        })
    {
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    if let Some(current) = cache_store.get_sender_transaction_candidate(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &candidate.semantic_id(),
    )? {
        return Ok(
            if super::sender_candidate_recovery::candidates_match(&candidate, &current) {
                PoiPrivateApplyOutcome::Applied {
                    utxo_changed: false,
                }
            } else {
                PoiPrivateApplyOutcome::Skipped
            },
        );
    }
    commit_sender_candidate_replacement(
        cache_store,
        cfg,
        active_list_keys,
        permit.ppoi_workflow_status().validation_revision,
        permit,
        candidate.semantic_id(),
        Some(candidate),
    )
}

async fn apply_sender_candidate_locally_valid(
    turn: PoiApplyTurn<'_>,
    delta: SenderCandidateLocallyValidDelta,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    let PoiApplyTurn {
        permit,
        snapshot,
        cache_store,
        cfg,
        active_list_keys,
    } = turn;
    let SenderCandidateLocallyValidDelta {
        expected_candidate,
        corpus,
        public_data_fence,
        unshield,
    } = delta;
    let Ok(replacement) = handed_off_sender_candidate(&expected_candidate, unshield) else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    if active_list_keys.is_empty()
        || expected_candidate.chain_id != cfg.chain.chain_id
        || expected_candidate.wallet_id != cfg.cache_key
        || super::sender_candidate_recovery::classify_sender_candidate_for_local_retirement(
            &expected_candidate,
            &snapshot,
            &cfg.scan_keys,
        )
        .is_none()
        || !stored_sender_candidate_matches(cache_store, cfg, &expected_candidate)?
    {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }

    // Lock order: wallet permit, public commit guard, then the corpus revision fence,
    // held through the final local read and candidate-only commit.
    let _public_commit_guard = public_data_fence.acquire_commit_guard().await;
    if !public_data_fence.is_current(expected_candidate.source.tx_hash) {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    let _revision_fence = corpus.revision_read_fence().await;
    let classification =
        super::sender_candidate_recovery::classify_sender_candidate_for_local_retirement(
            &expected_candidate,
            &snapshot,
            &cfg.scan_keys,
        );
    let Some(classification) = classification else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    let valid = super::saved_poi_compatibility::corpus_valid_blinded_commitments(
        &corpus,
        cfg.chain.chain_id,
        active_list_keys,
        &classification.external_outputs,
    )
    .await
    .map_err(|_| WalletCacheError::Crypto)?;
    if !classification
        .external_outputs
        .iter()
        .all(|data| valid.contains(&data.blinded_commitment))
    {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    commit_sender_candidate_replacement(
        cache_store,
        cfg,
        active_list_keys,
        permit.ppoi_workflow_status().validation_revision,
        permit,
        expected_candidate.semantic_id(),
        replacement,
    )
}

async fn apply_sender_candidate_materialization(
    turn: PoiApplyTurn<'_>,
    delta: SenderCandidateMaterializationDelta,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    let PoiApplyTurn {
        permit,
        snapshot,
        cache_store,
        cfg,
        ..
    } = turn;
    let SenderCandidateMaterializationDelta {
        expected_candidate,
        public_data_fence,
        active_list_keys,
        pending_updates,
        recovery_updates,
        owned_substitutes,
        proof_outputs,
        expected_corpus,
        replacement_group,
        external_valid_substitutes,
        unshield,
    } = delta;
    // A kept candidate retains only its handed-off unshield work.
    let Ok(replacement) = handed_off_sender_candidate(&expected_candidate, unshield) else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    let external_blinded = external_valid_substitutes
        .iter()
        .map(|output| output.poi.blinded_commitment)
        .collect::<Vec<_>>();
    let external_valid = if external_blinded.is_empty() {
        BTreeSet::new()
    } else {
        let Some(valid) = super::saved_poi_compatibility::corpus_valid_outputs(
            &expected_corpus.corpus,
            cfg.chain.chain_id,
            &active_list_keys,
            &external_blinded,
        )
        .await
        else {
            return Ok(PoiPrivateApplyOutcome::Skipped);
        };
        valid
    };
    if external_valid.len() != external_blinded.len() {
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    // This is the final public authority acquisition. Private actor and network work
    // completed before it; reset cannot cross the local validation/commit below.
    let _public_commit_guard = public_data_fence.acquire_commit_guard().await;
    // The corpus fence comes last and is held through the commit, so the proofs were
    // built from the corpus revision that is current when the candidate is consumed.
    let _revision_fence = match hold_expected_poi_corpus_revision(Some(&expected_corpus)).await {
        Ok(revision_fence) => revision_fence,
        Err(stale) => {
            drop(permit);
            return Ok(stale);
        }
    };
    let candidate_blinded = expected_candidate
        .outputs
        .iter()
        .filter_map(|output| {
            output.note.as_ref().map(|note| {
                super::Utxo::new(
                    note.clone(),
                    output.tree,
                    output.position,
                    expected_candidate.source.clone(),
                    super::UtxoCommitmentKind::Transact,
                )
                .poi
                .blinded_commitment
            })
        })
        .collect::<Vec<_>>();
    let Some(valid_by_list) = super::saved_poi_compatibility::corpus_valid_outputs_by_list(
        &expected_corpus.corpus,
        cfg.chain.chain_id,
        &active_list_keys,
        &candidate_blinded,
    )
    .await
    else {
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    if active_list_keys.is_empty()
        || pending_updates.len() != recovery_updates.len()
        || (pending_updates.is_empty()
            && owned_substitutes.is_empty()
            && external_valid_substitutes.is_empty())
        || !super::sender_candidate_recovery::sender_candidate_matches_wallet_snapshot(
            &expected_candidate,
            &snapshot,
        )
        || !public_data_fence.is_current(expected_candidate.source.tx_hash)
        || !stored_sender_candidate_matches(cache_store, cfg, &expected_candidate)?
    {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    if !replacement_group.is_empty()
        && !super::saved_poi_compatibility::saved_sender_group_is_current(
            cache_store,
            cfg,
            &expected_candidate.source,
            &replacement_group,
        )?
    {
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    let qualified_outputs = expected_candidate
        .outputs
        .iter()
        .filter(|output| output.note.is_some())
        .map(|output| (output.tree, output.position, output.commitment))
        .collect::<BTreeSet<_>>();
    let mut output_commitments = BTreeSet::new();
    let mut blinded_commitments = BTreeSet::new();
    let mut absent_pending_updates = Vec::new();
    let mut absent_recovery_updates = Vec::new();
    for (pending, recovery) in pending_updates.iter().zip(&recovery_updates) {
        let Some(observation) = pending.observation.as_ref() else {
            drop(permit);
            return Ok(PoiPrivateApplyOutcome::Skipped);
        };
        let Ok(output_tree) = u32::try_from(observation.output_tree) else {
            drop(permit);
            return Ok(PoiPrivateApplyOutcome::Skipped);
        };
        if pending.chain_id != cfg.chain.chain_id
            || pending.wallet_id != cfg.cache_key.as_str()
            || pending.output_role != PendingOutputPoiRole::RecoveredOutgoing
            || pending.source_operation_id.is_none()
            || pending.txid_merkleroot_index.is_none()
            || pending.required_poi_list_keys.is_empty()
            || observation.tx_hash != expected_candidate.source.tx_hash
            || observation.block_number != expected_candidate.source.block_number
            || observation.block_timestamp != expected_candidate.source.block_timestamp
            || recovery.chain_id != cfg.chain.chain_id
            || recovery.wallet_id != cfg.cache_key.as_str()
            || recovery.output_commitment != pending.output_commitment
            || recovery.source_tx_hash != expected_candidate.source.tx_hash
            || !qualified_outputs.contains(&(
                output_tree,
                observation.output_position,
                pending.output_commitment,
            ))
            || !output_commitments.insert((
                output_tree,
                observation.output_position,
                pending.output_commitment,
            ))
        {
            drop(permit);
            return Ok(PoiPrivateApplyOutcome::Skipped);
        }
        let Some(identity) = pending_output_poi_submit_identity(pending, observation) else {
            drop(permit);
            return Ok(PoiPrivateApplyOutcome::Skipped);
        };
        if pending.required_poi_list_keys
            != super::saved_poi_compatibility::unresolved_output_lists(
                &active_list_keys,
                identity.derived_blinded_commitment,
                &valid_by_list,
            )
        {
            return Ok(PoiPrivateApplyOutcome::Skipped);
        }
        if !blinded_commitments.insert(identity.derived_blinded_commitment) {
            drop(permit);
            return Ok(PoiPrivateApplyOutcome::Skipped);
        }
        if snapshot.iter().any(|output| {
            !output.is_spent()
                && output.utxo.tree == output_tree
                && output.utxo.position == observation.output_position
                && output.utxo.source == expected_candidate.source
                && output.utxo.poi.commitment == pending.output_commitment
        }) {
            drop(permit);
            return Ok(PoiPrivateApplyOutcome::Skipped);
        }
        let current_pending = cache_store.get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &pending.output_commitment,
        )?;
        let current_recovery = cache_store.get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &pending.output_commitment,
        )?;
        match (current_pending, current_recovery) {
            (None, None) => {
                absent_pending_updates.push(pending.clone());
                absent_recovery_updates.push(recovery.clone());
            }
            (Some(current_pending), current_recovery)
                if replacement_group
                    .iter()
                    .any(|(expected, expected_recovery)| {
                        expected.output_commitment == pending.output_commitment
                            && expected_pending_context_state(Some(expected))
                                == expected_pending_context_state(Some(&current_pending))
                            && expected_recovery_state(expected_recovery.as_ref())
                                == expected_recovery_state(current_recovery.as_ref())
                    }) =>
            {
                absent_pending_updates.push(pending.clone());
                absent_recovery_updates.push(recovery.clone());
            }
            (Some(current_pending), Some(current_recovery))
                if sender_materialization_pending_matches(&current_pending, pending)
                    && sender_materialization_recovery_matches(&current_recovery, recovery) => {}
            _ => {
                drop(permit);
                return Ok(PoiPrivateApplyOutcome::Skipped);
            }
        }
    }
    for expected in &owned_substitutes {
        let mut matches = snapshot.iter().filter(|output| expected.matches(output));
        let Some(current) = matches.next() else {
            drop(permit);
            return Ok(PoiPrivateApplyOutcome::Skipped);
        };
        if matches.next().is_some()
            || current.utxo.source != expected_candidate.source
            || !output_commitments.insert(expected.candidate_identity())
            || !blinded_commitments.insert(current.utxo.poi.blinded_commitment)
        {
            drop(permit);
            return Ok(PoiPrivateApplyOutcome::Skipped);
        }
    }
    for output in &external_valid_substitutes {
        let exact = expected_candidate
            .outputs
            .iter()
            .filter(|candidate_output| {
                candidate_output.tree == output.tree
                    && candidate_output.position == output.position
                    && candidate_output.commitment == output.poi.commitment
                    && candidate_output
                        .note
                        .as_ref()
                        .is_some_and(|note| note.commitment() == output.note.commitment())
            })
            .count();
        if exact != 1
            || output.source != expected_candidate.source
            || !external_valid.contains(&output.poi.blinded_commitment)
            || !output_commitments.insert((output.tree, output.position, output.poi.commitment))
            || !blinded_commitments.insert(output.poi.blinded_commitment)
            || cache_store
                .get_pending_output_poi_context(
                    cfg.chain.chain_id,
                    &cfg.cache_key,
                    &output.poi.commitment,
                )?
                .is_some()
        {
            return Ok(PoiPrivateApplyOutcome::Skipped);
        }
    }
    if pending_updates.iter().any(|pending| {
        !saved_pending_context_is_compatible(pending, &pending.required_poi_list_keys)
    }) {
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    let mut proof_groups = BTreeMap::new();
    for pending in &pending_updates {
        let key = (pending.railgun_txid, pending.utxo_tree_in);
        let material =
            rmp_serde::to_vec(&(pending.txid_merkleroot_index, &pending.source_operation_id))?;
        if proof_groups
            .insert((key, None), material.clone())
            .is_some_and(|old| old != material)
        {
            return Ok(PoiPrivateApplyOutcome::Skipped);
        }
        for (list_key, per_leaf) in &pending.pre_transaction_pois_per_txid_leaf_per_list {
            let encoded = rmp_serde::to_vec(per_leaf)?;
            if proof_groups
                .insert((key, Some(*list_key)), encoded.clone())
                .is_some_and(|old| old != encoded)
            {
                return Ok(PoiPrivateApplyOutcome::Skipped);
            }
        }
    }
    if output_commitments != qualified_outputs {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    let proof_outputs = proof_outputs.into_iter().collect::<BTreeSet<_>>();
    if proof_outputs.len() != blinded_commitments.len()
        || proof_outputs != blinded_commitments
        || !public_data_fence.is_current(expected_candidate.source.tx_hash)
    {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    let (candidate_updates, candidate_deletes) = match replacement {
        Some(replacement) => (vec![replacement], Vec::new()),
        None => (Vec::new(), vec![expected_candidate.semantic_id()]),
    };
    let workflow_status = wallet_ppoi_workflow_status_after_mutations(
        cache_store,
        cfg,
        &active_list_keys,
        permit.ppoi_workflow_status().validation_revision,
        &absent_pending_updates,
        &[],
        &absent_recovery_updates,
        &[],
        &candidate_updates,
        &candidate_deletes,
    )?;
    let result = permit.with_durable_apply(|token| {
        cache_store.commit_wallet_private_state(
            WalletPrivateCommit::new(
                &token,
                &permit,
                WalletUtxoMutation::Preserve,
                WalletCheckpointMutation::Preserve,
            )
            .with_pending_output_context_updates(&absent_pending_updates)
            .with_output_poi_recovery_updates(&absent_recovery_updates)
            .with_sender_transaction_candidate_updates(&candidate_updates)
            .with_sender_transaction_candidate_deletes(&candidate_deletes),
        )?;
        permit.apply_publish_ppoi_workflow_projection(&token, workflow_status);
        Ok::<(), WalletCacheError>(())
    });
    drop(permit);
    durable_apply_outcome(result)
}

async fn apply_sender_candidate_unshield_update(
    turn: PoiApplyTurn<'_>,
    delta: SenderCandidateUnshieldUpdateDelta,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    let PoiApplyTurn {
        permit,
        snapshot,
        cache_store,
        cfg,
        active_list_keys,
    } = turn;
    let SenderCandidateUnshieldUpdateDelta {
        expected_candidate,
        public_data_fence,
        replacement,
    } = delta;
    if expected_candidate.chain_id != cfg.chain.chain_id
        || expected_candidate.wallet_id != cfg.cache_key
        || !super::sender_candidate_recovery::sender_candidate_matches_wallet_snapshot(
            &expected_candidate,
            &snapshot,
        )
    {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    // Only `unshield` may differ; every other field must equal the expected candidate.
    if replacement.as_ref().is_some_and(|replacement| {
        !expected_candidate
            .clone()
            .with_unshield(replacement.unshield.clone())
            .is_ok_and(|expected| {
                super::sender_candidate_recovery::candidates_match(&expected, replacement)
            })
    }) {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    let _public_commit_guard = public_data_fence.acquire_commit_guard().await;
    if !public_data_fence.is_current(expected_candidate.source.tx_hash)
        || !stored_sender_candidate_matches(cache_store, cfg, &expected_candidate)?
    {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    commit_sender_candidate_replacement(
        cache_store,
        cfg,
        active_list_keys,
        permit.ppoi_workflow_status().validation_revision,
        permit,
        expected_candidate.semantic_id(),
        replacement,
    )
}

async fn apply_sender_candidate_unshield_validated(
    turn: PoiApplyTurn<'_>,
    delta: SenderCandidateUnshieldValidatedDelta,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    let PoiApplyTurn {
        permit,
        cache_store,
        cfg,
        active_list_keys,
        ..
    } = turn;
    let SenderCandidateUnshieldValidatedDelta {
        expected_candidate,
        validated_txids,
        corpus,
    } = delta;
    let validated = validated_txids.iter().copied().collect::<BTreeSet<_>>();
    let Some(unshield) = expected_candidate.unshield.as_ref() else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    if active_list_keys.is_empty()
        || expected_candidate.chain_id != cfg.chain.chain_id
        || expected_candidate.wallet_id != cfg.cache_key
        || validated.is_empty()
        || validated.len() != validated_txids.len()
        || !validated
            .iter()
            .all(|txid| unshield.railgun_txids.contains(txid))
    {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    if !stored_sender_candidate_matches(cache_store, cfg, &expected_candidate)? {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    // Hold the corpus revision fence through the fresh status read and the commit.
    let _revision_fence = corpus.revision_read_fence().await;
    let datas = validated
        .iter()
        .map(|txid| BlindedCommitmentData::unshield(*txid))
        .collect::<Vec<_>>();
    let valid = super::saved_poi_compatibility::corpus_valid_blinded_commitments(
        &corpus,
        cfg.chain.chain_id,
        active_list_keys,
        &datas,
    )
    .await
    .map_err(|_| WalletCacheError::Crypto)?;
    if !validated.is_subset(&valid) {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    let Ok(replacement) =
        super::sender_candidate_recovery::sender_candidate_after_unshield_validation(
            &expected_candidate,
            unshield,
            &validated,
        )
    else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    commit_sender_candidate_replacement(
        cache_store,
        cfg,
        active_list_keys,
        permit
            .ppoi_workflow_status()
            .validation_revision
            .saturating_add(u64::try_from(validated.len()).unwrap_or(u64::MAX)),
        permit,
        expected_candidate.semantic_id(),
        replacement,
    )
}

async fn apply_output_recovery(
    turn: PoiApplyTurn<'_>,
    delta: OutputRecoveryDelta,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    let PoiApplyTurn {
        permit,
        snapshot,
        cache_store,
        cfg,
        ..
    } = turn;
    let OutputRecoveryDelta {
        expected_output,
        active_list_keys,
        target_list_keys,
        required_poi_status,
        pending_update,
        expected_recovery,
        action,
        now,
        expected_corpus,
        replay_fence,
    } = delta;
    // Match sender reconstruction lock ordering: public data, then corpus, then commit.
    let _public_commit_guard = match replay_fence.as_ref() {
        Some(fence) => Some(fence.public_data_plane.acquire_commit_guard().await),
        None => None,
    };
    if replay_fence
        .as_ref()
        .is_some_and(|fence| fence.public_data_plane.current_epoch() != fence.epoch)
    {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    // Held through the commit when this record consumes a local proof.
    let _revision_fence = match hold_expected_poi_corpus_revision(expected_corpus.as_ref()).await {
        Ok(revision_fence) => revision_fence,
        Err(stale) => {
            drop(permit);
            return Ok(stale);
        }
    };
    let Some(wallet_utxo) = snapshot
        .iter()
        .find(|wallet_utxo| expected_output.matches(wallet_utxo))
    else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    if active_list_keys.is_empty()
        || target_list_keys.is_empty()
        || target_list_keys
            .iter()
            .any(|list_key| !active_list_keys.contains(list_key))
        || !expected_poi_status_matches(
            &wallet_utxo.utxo.poi,
            &target_list_keys,
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
    let workflow_status = wallet_ppoi_workflow_status_after_mutations(
        cache_store,
        cfg,
        &active_list_keys,
        permit.ppoi_workflow_status().validation_revision,
        &pending_updates,
        &[],
        &recovery_updates,
        &[],
        &[],
        &[],
    )?;
    let result = permit.with_durable_apply(|token| {
        cache_store.commit_wallet_private_state(
            WalletPrivateCommit::new(
                &token,
                &permit,
                WalletUtxoMutation::Preserve,
                WalletCheckpointMutation::Preserve,
            )
            .with_pending_output_context_updates(&pending_updates)
            .with_output_poi_recovery_updates(&recovery_updates),
        )?;
        permit.apply_publish_ppoi_workflow_projection(&token, workflow_status);
        Ok::<(), WalletCacheError>(())
    });
    drop(permit);
    durable_apply_outcome(result)
}

fn apply_pending_submission(
    turn: PoiApplyTurn<'_>,
    delta: PendingSubmissionDelta,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    let PoiApplyTurn {
        permit,
        snapshot,
        cache_store,
        cfg,
        ..
    } = turn;
    let PendingSubmissionDelta {
        subject,
        expected_context_fingerprint,
        expected_recovery,
        active_list_keys,
        list_keys,
        predicate,
        merge_submitted_list_keys,
        action,
        now,
    } = delta;
    if active_list_keys.is_empty()
        || list_keys.is_empty()
        || list_keys
            .iter()
            .any(|list_key| !active_list_keys.contains(list_key))
    {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    let Some(mut current_context) = cache_store.get_pending_output_poi_context(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &subject.output_commitment(),
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
    let Some(subject_match) =
        pending_output_poi_subject_matches_snapshot(cfg, &snapshot, &current_context, &subject)
    else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    if subject_match
        .poi()
        .is_some_and(|poi| !poi_statuses_are_recoverable_for_lists(poi, &list_keys))
    {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    let current_recovery = cache_store.get_output_poi_recovery(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &subject.output_commitment(),
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
        if let Some(poi) = subject_match.poi() {
            prune_nonrecoverable_unsubmitted_poi_lists(
                &mut current_context,
                poi,
                &active_list_keys,
            );
        }
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
    let workflow_status = wallet_ppoi_workflow_status_after_mutations(
        cache_store,
        cfg,
        &active_list_keys,
        permit.ppoi_workflow_status().validation_revision,
        &pending_updates,
        &[],
        &recovery_updates,
        &[],
        &[],
        &[],
    )?;
    let result = permit.with_durable_apply(|token| {
        cache_store.commit_wallet_private_state(
            WalletPrivateCommit::new(
                &token,
                &permit,
                WalletUtxoMutation::Preserve,
                WalletCheckpointMutation::Preserve,
            )
            .with_pending_output_context_updates(&pending_updates)
            .with_output_poi_recovery_updates(&recovery_updates),
        )?;
        permit.apply_publish_ppoi_workflow_projection(&token, workflow_status);
        Ok::<(), WalletCacheError>(())
    });
    drop(permit);
    durable_apply_outcome(result)
}

async fn apply_recovered_outgoing_submission(
    turn: PoiApplyTurn<'_>,
    delta: RecoveredOutgoingSubmissionDelta,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    let PoiApplyTurn {
        permit,
        snapshot,
        cache_store,
        cfg,
        ..
    } = turn;
    let RecoveredOutgoingSubmissionDelta {
        siblings,
        owned_substitutes,
        external_valid_substitutes,
        expected_corpus,
        active_list_keys,
        list_keys,
        merge_submitted_list_keys,
        action,
        now,
    } = delta;
    if siblings.is_empty()
        || active_list_keys.is_empty()
        || list_keys.is_empty()
        || list_keys
            .iter()
            .any(|list_key| !active_list_keys.contains(list_key))
    {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    let _corpus_fence = match hold_expected_poi_corpus_revision(expected_corpus.as_ref()).await {
        Ok(fence) => fence,
        Err(stale) => return Ok(stale),
    };
    let planned_union = siblings
        .iter()
        .flat_map(|sibling| sibling.plan.list_keys().iter().copied())
        .collect::<BTreeSet<_>>();
    if list_keys.iter().copied().collect::<BTreeSet<_>>() != planned_union {
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    let mut current_contexts = Vec::with_capacity(siblings.len());
    let mut current_recoveries = Vec::with_capacity(siblings.len());
    let mut output_commitments = BTreeSet::new();
    for sibling in &siblings {
        if !matches!(&sibling.subject, PendingOutputPoiSubject::External { .. }) {
            drop(permit);
            return Ok(PoiPrivateApplyOutcome::Skipped);
        }
        let output_commitment = sibling.subject.output_commitment();
        if !output_commitments.insert(output_commitment) {
            drop(permit);
            return Ok(PoiPrivateApplyOutcome::Skipped);
        }
        let Some(current_context) = cache_store.get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &output_commitment,
        )?
        else {
            drop(permit);
            return Ok(PoiPrivateApplyOutcome::Skipped);
        };
        if current_context.output_role != PendingOutputPoiRole::RecoveredOutgoing
            || pending_output_poi_context_fingerprint(&current_context).as_ref()
                != Some(&sibling.expected_context_fingerprint)
            || current_context.terminal_error.is_some()
            || !pending_submission_predicate_matches(
                &current_context,
                sibling.plan.list_keys(),
                sibling.plan.predicate(),
            )
            || recoverable_pending_submission_list_keys(
                &current_context,
                &active_list_keys,
                None,
                sibling.plan.predicate(),
            ) != sibling.plan.list_keys
            || !saved_pending_context_is_compatible(&current_context, &current_context.list_keys())
            || pending_output_poi_subject_matches_snapshot(
                cfg,
                &snapshot,
                &current_context,
                &sibling.subject,
            )
            .is_none()
        {
            drop(permit);
            return Ok(PoiPrivateApplyOutcome::Skipped);
        }
        let Some(current_recovery) = cache_store.get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &output_commitment,
        )?
        else {
            drop(permit);
            return Ok(PoiPrivateApplyOutcome::Skipped);
        };
        let Some(observation) = current_context.observation.as_ref() else {
            drop(permit);
            return Ok(PoiPrivateApplyOutcome::Skipped);
        };
        if !expected_recovery_matches(&sibling.plan.expected_recovery, Some(&current_recovery))
            || current_recovery.status == OutputPoiRecoveryStatus::Valid
            || current_recovery.source_tx_hash != observation.tx_hash
            || (sibling.plan.kind == PendingOutputPoiSubmissionKind::RetrySubmitted
                && !current_recovery
                    .submission_retry_allowed(now, sibling.plan.force_submission_retry))
        {
            drop(permit);
            return Ok(PoiPrivateApplyOutcome::Skipped);
        }
        current_contexts.push(current_context);
        current_recoveries.push(current_recovery);
    }
    let Some(seed) = current_contexts.first() else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    let all_contexts =
        cache_store.list_pending_output_poi_contexts(cfg.chain.chain_id, &cfg.cache_key)?;
    let Some(current_group) = recovered_outgoing_group_records(&all_contexts, seed) else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    let external_valid = if let Some(expected) = &expected_corpus {
        let outputs = current_group
            .iter()
            .flat_map(|context| context.pre_transaction_pois_per_txid_leaf_per_list.values())
            .flat_map(|per_leaf| per_leaf.values())
            .flat_map(|poi| poi.blinded_commitments_out.iter().copied())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let Some(valid) = super::saved_poi_compatibility::corpus_valid_outputs_by_list(
            &expected.corpus,
            cfg.chain.chain_id,
            &active_list_keys,
            &outputs,
        )
        .await
        else {
            return Ok(PoiPrivateApplyOutcome::Skipped);
        };
        valid
    } else {
        BTreeMap::new()
    };
    if current_group.iter().any(|context| {
        context
            .observation
            .as_ref()
            .and_then(|observation| pending_output_poi_submit_identity(context, observation))
            .is_none_or(|identity| {
                context.required_poi_list_keys
                    != super::saved_poi_compatibility::unresolved_output_lists(
                        &active_list_keys,
                        identity.derived_blinded_commitment,
                        &external_valid,
                    )
            })
    }) {
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    let current_evidence =
        recovered_outgoing_group_evidence(&current_group, &snapshot, &list_keys, &external_valid);
    if current_group.len() != current_contexts.len()
        || current_evidence.as_ref().is_none_or(|evidence| {
            !recovered_outgoing_owned_substitutes_match(&owned_substitutes, &evidence.owned_outputs)
                || evidence
                    .external_valid_substitutes
                    .iter()
                    .copied()
                    .collect::<BTreeSet<_>>()
                    != external_valid_substitutes
                        .iter()
                        .copied()
                        .collect::<BTreeSet<_>>()
        })
    {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }

    let mut pending_updates = Vec::with_capacity(current_contexts.len());
    let mut recovery_updates = Vec::with_capacity(current_contexts.len());
    for ((mut context, mut recovery), sibling) in current_contexts
        .into_iter()
        .zip(current_recoveries)
        .zip(&siblings)
    {
        let member_lists = list_keys
            .iter()
            .filter(|list_key| sibling.plan.list_keys.contains(list_key))
            .collect::<Vec<_>>();
        if member_lists.is_empty() {
            continue;
        }
        if merge_submitted_list_keys {
            for list_key in member_lists {
                if !context.submitted_poi_list_keys.contains(list_key) {
                    context.submitted_poi_list_keys.push(*list_key);
                }
            }
        }
        recovery.apply_action(action.clone(), now);
        if merge_submitted_list_keys {
            pending_updates.push(context);
        }
        recovery_updates.push(recovery);
    }
    let workflow_status = wallet_ppoi_workflow_status_after_mutations(
        cache_store,
        cfg,
        &active_list_keys,
        permit.ppoi_workflow_status().validation_revision,
        &pending_updates,
        &[],
        &recovery_updates,
        &[],
        &[],
        &[],
    )?;
    let result = permit.with_durable_apply(|token| {
        cache_store.commit_wallet_private_state(
            WalletPrivateCommit::new(
                &token,
                &permit,
                WalletUtxoMutation::Preserve,
                WalletCheckpointMutation::Preserve,
            )
            .with_pending_output_context_updates(&pending_updates)
            .with_output_poi_recovery_updates(&recovery_updates),
        )?;
        permit.apply_publish_ppoi_workflow_projection(&token, workflow_status);
        Ok::<(), WalletCacheError>(())
    });
    drop(permit);
    durable_apply_outcome(result)
}

fn apply_pending_context_terminal(
    turn: PoiApplyTurn<'_>,
    delta: PendingContextTerminalDelta,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    let PoiApplyTurn {
        permit,
        snapshot,
        cache_store,
        cfg,
        ..
    } = turn;
    let PendingContextTerminalDelta {
        subject,
        expected_context_fingerprint,
        expected_recovery,
        active_list_keys,
        target_list_keys,
        error,
    } = delta;
    if active_list_keys.is_empty()
        || target_list_keys.is_empty()
        || target_list_keys
            .iter()
            .any(|list_key| !active_list_keys.contains(list_key))
    {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    let Some(mut current_context) = cache_store.get_pending_output_poi_context(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &subject.output_commitment(),
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
    let Some(subject_match) =
        pending_output_poi_subject_matches_snapshot(cfg, &snapshot, &current_context, &subject)
    else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    if subject_match
        .poi()
        .is_some_and(|poi| !poi_statuses_are_recoverable_for_lists(poi, &target_list_keys))
    {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    let Some(observation) = current_context.observation.as_ref() else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    let current_recovery = cache_store.get_output_poi_recovery(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &subject.output_commitment(),
    )?;
    if !expected_recovery_matches(&expected_recovery, current_recovery.as_ref())
        || current_recovery
            .as_ref()
            .is_some_and(|recovery| recovery.source_tx_hash != observation.tx_hash)
    {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    current_context.terminal_error = Some(error);
    let pending_updates = [current_context];
    let workflow_status = wallet_ppoi_workflow_status_after_mutations(
        cache_store,
        cfg,
        &active_list_keys,
        permit.ppoi_workflow_status().validation_revision,
        &pending_updates,
        &[],
        &[],
        &[],
        &[],
        &[],
    )?;
    let result = permit.with_durable_apply(|token| {
        cache_store.commit_wallet_private_state(
            WalletPrivateCommit::new(
                &token,
                &permit,
                WalletUtxoMutation::Preserve,
                WalletCheckpointMutation::Preserve,
            )
            .with_pending_output_context_updates(&pending_updates),
        )?;
        permit.apply_publish_ppoi_workflow_projection(&token, workflow_status);
        Ok::<(), WalletCacheError>(())
    });
    drop(permit);
    durable_apply_outcome(result)
}

async fn apply_locally_valid_pending_lists(
    turn: PoiApplyTurn<'_>,
    delta: LocallyValidPendingListsDelta,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    let PoiApplyTurn {
        permit,
        mut snapshot,
        cache_store,
        cfg,
        ..
    } = turn;
    let LocallyValidPendingListsDelta {
        subject,
        expected_context_fingerprint,
        expected_recovery,
        active_list_keys,
        valid_list_keys,
        now,
    } = delta;
    let output_commitment = subject.output_commitment();
    if active_list_keys.is_empty()
        || valid_list_keys.is_empty()
        || valid_list_keys
            .iter()
            .any(|list_key| !active_list_keys.contains(list_key))
    {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    let Some(mut current_context) = cache_store.get_pending_output_poi_context(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &output_commitment,
    )?
    else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    if pending_output_poi_context_fingerprint(&current_context).as_ref()
        != Some(&expected_context_fingerprint)
        || valid_list_keys
            .iter()
            .any(|list_key| !current_context.list_keys().contains(list_key))
    {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    let Some(subject_match) =
        pending_output_poi_subject_matches_snapshot(cfg, &snapshot, &current_context, &subject)
    else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    let Some(observation) = current_context.observation.as_ref() else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    let current_recovery = cache_store.get_output_poi_recovery(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &output_commitment,
    )?;
    if !expected_recovery_matches(&expected_recovery, current_recovery.as_ref())
        || current_recovery
            .as_ref()
            .is_some_and(|recovery| recovery.source_tx_hash != observation.tx_hash)
    {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }

    let mut changed = false;
    let mut recovery_updates = Vec::new();
    let mut recovery_deletes = Vec::new();
    if matches!(&subject_match, PendingOutputPoiSubjectMatch::Owned(_)) {
        let PendingOutputPoiSubject::Owned(expected_output) = &subject else {
            drop(permit);
            return Ok(PoiPrivateApplyOutcome::Skipped);
        };
        let Some(wallet_utxo) = snapshot
            .iter_mut()
            .find(|wallet_utxo| expected_output.matches(wallet_utxo))
        else {
            drop(permit);
            return Ok(PoiPrivateApplyOutcome::Skipped);
        };
        let valid_statuses = valid_list_keys
            .iter()
            .copied()
            .map(|list_key| (list_key, PoiStatus::Valid))
            .collect::<BTreeMap<_, _>>();
        changed = wallet_utxo.utxo.poi.apply_status_refresh(
            &valid_list_keys,
            Some(&valid_statuses),
            wallet_utxo
                .utxo
                .poi
                .refreshed_at
                .map_or(now, |refreshed_at| refreshed_at.max(now)),
        ) > 0;
    }

    current_context
        .required_poi_list_keys
        .retain(|list_key| !valid_list_keys.contains(list_key));
    current_context
        .pre_transaction_pois_per_txid_leaf_per_list
        .retain(|list_key, _| !valid_list_keys.contains(list_key));
    current_context
        .submitted_poi_list_keys
        .retain(|list_key| !valid_list_keys.contains(list_key));
    let remaining_active_lists = current_context
        .list_keys()
        .into_iter()
        .filter(|list_key| active_list_keys.contains(list_key))
        .collect::<Vec<_>>();
    let complete = remaining_active_lists.is_empty();
    let pending_updates = if complete {
        Vec::new()
    } else {
        vec![current_context]
    };
    let pending_deletes: Vec<FixedBytes<32>> =
        complete.then_some(output_commitment).into_iter().collect();
    if complete {
        if let Some(wallet_output) = match &subject_match {
            PendingOutputPoiSubjectMatch::Owned(output) => Some(output),
            PendingOutputPoiSubjectMatch::External => None,
        } {
            let mut recovery = current_recovery.unwrap_or_else(|| {
                new_output_poi_recovery_record(
                    cfg,
                    wallet_output,
                    OutputPoiRecoveryStatus::Valid,
                    now,
                )
            });
            recovery.apply_action(OutputPoiRecoveryAction::Valid, now);
            recovery_updates.push(recovery);
        } else {
            recovery_deletes.push(output_commitment);
        }
    } else if current_recovery
        .as_ref()
        .is_some_and(|recovery| recovery.status == OutputPoiRecoveryStatus::Valid)
    {
        let mut recovery = current_recovery
            .clone()
            .expect("Valid recovery status was checked above");
        recovery.apply_action(
            OutputPoiRecoveryAction::Detected {
                status: OutputPoiRecoveryStatus::Recoverable,
                retry_after: None,
                last_error: None,
                increment_attempts: false,
            },
            now,
        );
        recovery_updates.push(recovery);
    }
    let workflow_status = wallet_ppoi_workflow_status_after_mutations(
        cache_store,
        cfg,
        &active_list_keys,
        permit.ppoi_workflow_status().validation_revision,
        &pending_updates,
        &pending_deletes,
        &recovery_updates,
        &recovery_deletes,
        &[],
        &[],
    )?;
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
                if changed {
                    WalletUtxoMutation::Replace(&snapshot)
                } else {
                    WalletUtxoMutation::Preserve
                },
                WalletCheckpointMutation::Preserve,
            )
            .with_pending_output_context_updates(&pending_updates)
            .with_pending_output_context_deletes(&pending_deletes)
            .with_output_poi_recovery_updates(&recovery_updates)
            .with_output_poi_recovery_deletes(&recovery_deletes),
        )?;
        if let Some(locked) = utxos_locked.as_mut() {
            locked.clone_from(&snapshot);
            let overlay = permit
                .pending_overlay()
                .try_read()
                .map(|guard| guard.clone())
                .unwrap_or_default();
            permit.apply_notify_changed(&token, locked, &overlay);
        }
        permit.apply_publish_ppoi_workflow_projection(&token, workflow_status);
        Ok::<(), WalletCacheError>(())
    });
    drop(utxos_locked);
    drop(permit);
    active_apply_outcome(result, changed)
}

async fn apply_verified_valid(
    turn: PoiApplyTurn<'_>,
    delta: VerifiedValidDelta,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    let PoiApplyTurn {
        permit,
        mut snapshot,
        cache_store,
        cfg,
        ..
    } = turn;
    let VerifiedValidDelta {
        subject,
        evidence,
        expected_context_fingerprint,
        expected_recovery,
        expected_poi_list_state,
        active_list_keys,
        valid_list_keys,
        now,
    } = delta;
    let output_commitment = subject.output_commitment();
    let Some(current_context) = cache_store.get_pending_output_poi_context(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &output_commitment,
    )?
    else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    let Some(subject_match) =
        pending_output_poi_subject_matches_snapshot(cfg, &snapshot, &current_context, &subject)
    else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    let current_list_keys = current_context.list_keys();
    let submitted_lists_match = valid_list_keys
        .iter()
        .all(|list_key| current_context.submitted_poi_list_keys.contains(list_key));
    let evidence_matches = match evidence {
        PendingOutputPoiValidationEvidence::SubmittedStatus => submitted_lists_match,
        PendingOutputPoiValidationEvidence::OwnedStatusRefresh => {
            matches!(
                &subject_match,
                PendingOutputPoiSubjectMatch::Owned(output)
                    if expected_poi_list_state.as_ref().is_some_and(|expected| {
                        expected.matches_valid(&output.utxo.poi, &valid_list_keys)
                    })
            )
        }
    };
    if active_list_keys.is_empty()
        || valid_list_keys.is_empty()
        || valid_list_keys
            .iter()
            .any(|list_key| !active_list_keys.contains(list_key))
        || pending_output_poi_context_fingerprint(&current_context).as_ref()
            != Some(&expected_context_fingerprint)
        || valid_list_keys
            .iter()
            .any(|list_key| !current_list_keys.contains(list_key))
        || !evidence_matches
    {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }
    let Some(observation) = current_context.observation.as_ref() else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    let current_recovery = cache_store.get_output_poi_recovery(
        cfg.chain.chain_id,
        &cfg.cache_key,
        &output_commitment,
    )?;
    if !expected_recovery_matches(&expected_recovery, current_recovery.as_ref())
        || current_recovery
            .as_ref()
            .is_some_and(|recovery| recovery.source_tx_hash != observation.tx_hash)
    {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    }

    if matches!(subject_match, PendingOutputPoiSubjectMatch::External) {
        if expected_poi_list_state.is_some() {
            drop(permit);
            return Ok(PoiPrivateApplyOutcome::Skipped);
        }
        let workflow_candidate = wallet_ppoi_workflow_status_after_validation(
            &permit,
            cache_store,
            cfg,
            &active_list_keys,
            output_commitment,
        )?;
        let pending_deletes = [output_commitment];
        let recovery_deletes = [output_commitment];
        let result = permit.with_durable_apply(|token| {
            cache_store.commit_wallet_private_state(
                WalletPrivateCommit::new(
                    &token,
                    &permit,
                    WalletUtxoMutation::Preserve,
                    WalletCheckpointMutation::Preserve,
                )
                .with_pending_output_context_deletes(&pending_deletes)
                .with_output_poi_recovery_deletes(&recovery_deletes),
            )?;
            permit.apply_publish_ppoi_workflow_projection(&token, workflow_candidate);
            Ok::<(), WalletCacheError>(())
        });
        drop(permit);
        return durable_apply_outcome(result);
    }

    let PendingOutputPoiSubject::Owned(expected_output) = subject else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    let Some(wallet_utxo) = snapshot
        .iter_mut()
        .find(|wallet_utxo| expected_output.matches(wallet_utxo))
    else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    let Some(expected_poi_list_state) = expected_poi_list_state else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    let poi_state_matches = match evidence {
        PendingOutputPoiValidationEvidence::SubmittedStatus => expected_poi_list_state
            .matches_recoverable_or_valid(&wallet_utxo.utxo.poi, &valid_list_keys),
        PendingOutputPoiValidationEvidence::OwnedStatusRefresh => {
            expected_poi_list_state.matches_valid(&wallet_utxo.utxo.poi, &valid_list_keys)
        }
    };
    if !poi_state_matches {
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
    let mut recovery = current_recovery.unwrap_or_else(|| {
        new_output_poi_recovery_record(
            cfg,
            wallet_utxo,
            output_poi_recovery_default_status(&recovery_action),
            now,
        )
    });
    recovery.apply_action(recovery_action, now);
    let workflow_candidate = wallet_ppoi_workflow_status_after_validation(
        &permit,
        cache_store,
        cfg,
        &active_list_keys,
        output_commitment,
    )?;
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
        permit.apply_publish_ppoi_workflow_projection(&token, workflow_candidate);
        Ok::<(), WalletCacheError>(())
    });
    drop(utxos_locked);
    drop(permit);
    active_apply_outcome(result, changed)
}

async fn apply_poi_status_refresh(
    turn: PoiApplyTurn<'_>,
    delta: PoiStatusRefreshDelta,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    let PoiApplyTurn {
        permit,
        mut snapshot,
        cache_store,
        ..
    } = turn;
    let PoiStatusRefreshDelta {
        active_list_keys,
        expected_poi_by_blinded_commitment,
        statuses_by_blinded_commitment,
        refreshed_at,
    } = delta;
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
    active_apply_outcome(result, true)
}
