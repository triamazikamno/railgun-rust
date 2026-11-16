//! Applying sender candidate deltas: reconstruction, local retirement, materialization and
//! unshield work.

use std::collections::BTreeSet;

use crate::wallet::pending_output_poi::{
    BTreeMap, BlindedCommitmentData, ExpectedWalletOutput, FixedBytes, OutputPoiRecoveryRecord,
    PendingOutputPoiContextRecord, PendingOutputPoiObservation, PendingOutputPoiRole,
    PoiPrivateApplyOutcome, PoiPrivateRows, SenderCandidateLocallyValidDelta,
    SenderCandidateMaterializationDelta, SenderCandidateReconstructionDelta,
    SenderCandidateUnshieldUpdateDelta, SenderCandidateUnshieldValidatedDelta, Utxo,
    UtxoCommitmentKind, WalletCacheError, WalletCacheStore, WalletConfig,
    WalletPrivateMutationPermit, WalletUtxo, expected_pending_context_state,
    expected_recovery_state, hold_expected_poi_corpus_revision, pending_output_poi_submit_identity,
    saved_pending_context_is_compatible, saved_poi_compatibility, sender_candidate_recovery,
    sender_materialization_pending_matches, sender_materialization_recovery_matches,
    wallet_ppoi_workflow_status_after_mutations,
};
use crate::{SenderTransactionCandidate, SenderTransactionCandidateUnshield};

use super::{PoiApplyTurn, commit_durable_apply};

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
        .is_some_and(|current| sender_candidate_recovery::candidates_match(expected, &current)))
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
    let rows = PoiPrivateRows {
        candidate_updates: &candidate_updates,
        candidate_deletes: &candidate_deletes,
        ..PoiPrivateRows::default()
    };
    let workflow_status = wallet_ppoi_workflow_status_after_mutations(
        cache_store,
        cfg,
        active_list_keys,
        validation_revision,
        rows,
    )?;
    commit_durable_apply(permit, cache_store, rows, workflow_status)
}

pub(super) async fn apply_sender_candidate_reconstruction(
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
        || !sender_candidate_recovery::sender_candidate_matches_wallet_snapshot(
            &candidate, &snapshot,
        )
        || !saved_poi_compatibility::saved_sender_group_is_current(
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
            if sender_candidate_recovery::candidates_match(&candidate, &current) {
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

pub(super) async fn apply_sender_candidate_locally_valid(
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
        || sender_candidate_recovery::classify_sender_candidate_for_local_retirement(
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
    let classification = sender_candidate_recovery::classify_sender_candidate_for_local_retirement(
        &expected_candidate,
        &snapshot,
        &cfg.scan_keys,
    );
    let Some(classification) = classification else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    let valid = saved_poi_compatibility::corpus_valid_blinded_commitments(
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

fn candidate_blinded_commitments(candidate: &SenderTransactionCandidate) -> Vec<FixedBytes<32>> {
    candidate
        .outputs
        .iter()
        .filter_map(|output| {
            output.note.as_ref().map(|note| {
                Utxo::new(
                    note.clone(),
                    output.tree,
                    output.position,
                    candidate.source.clone(),
                    UtxoCommitmentKind::Transact,
                )
                .poi
                .blinded_commitment
            })
        })
        .collect::<Vec<_>>()
}

/// Rows and output identities a sender materialization covers so far.
#[derive(Default)]
struct SenderMaterializationRows {
    output_commitments: BTreeSet<(u32, u64, FixedBytes<32>)>,
    blinded_commitments: BTreeSet<FixedBytes<32>>,
    absent_pending_updates: Vec<PendingOutputPoiContextRecord>,
    absent_recovery_updates: Vec<OutputPoiRecoveryRecord>,
}

impl SenderMaterializationRows {
    /// Records an output's identity, then its blinded commitment; `false` when either is already
    /// recorded.
    fn insert_output(
        &mut self,
        output_commitment: (u32, u64, FixedBytes<32>),
        blinded_commitment: FixedBytes<32>,
    ) -> bool {
        self.output_commitments.insert(output_commitment)
            && self.blinded_commitments.insert(blinded_commitment)
    }
}

/// Wallet state and corpus results a sender materialization's rows are checked against.
struct SenderMaterializationCheck<'a> {
    cache_store: &'a dyn WalletCacheStore,
    cfg: &'a WalletConfig,
    snapshot: &'a [WalletUtxo],
    candidate: &'a SenderTransactionCandidate,
    active_list_keys: &'a [FixedBytes<32>],
    valid_by_list: &'a BTreeMap<FixedBytes<32>, BTreeSet<FixedBytes<32>>>,
    qualified_outputs: &'a BTreeSet<(u32, u64, FixedBytes<32>)>,
    replacement_group: &'a [(
        PendingOutputPoiContextRecord,
        Option<OutputPoiRecoveryRecord>,
    )],
    external_valid: &'a BTreeSet<FixedBytes<32>>,
}

/// Each `record_*` method checks rows and records them; `false` means skip the materialization.
impl SenderMaterializationCheck<'_> {
    /// Records the pending rows, then the owned substitutes.
    fn record_candidate_rows(
        &self,
        rows: &mut SenderMaterializationRows,
        delta: &SenderCandidateMaterializationDelta,
    ) -> Result<bool, WalletCacheError> {
        for (pending, recovery) in delta.pending_updates.iter().zip(&delta.recovery_updates) {
            if !self.record_pending_row(rows, pending, recovery)? {
                return Ok(false);
            }
        }
        Ok(delta
            .owned_substitutes
            .iter()
            .all(|expected| self.record_owned_substitute(rows, expected)))
    }

    /// Records the external substitutes, then checks that every pending row's saved context fits
    /// its lists and that rows sharing a proof group carry the same proof inputs.
    fn record_external_rows_and_check_pending_proofs(
        &self,
        rows: &mut SenderMaterializationRows,
        delta: &SenderCandidateMaterializationDelta,
    ) -> Result<bool, WalletCacheError> {
        for output in &delta.external_valid_substitutes {
            if !self.record_external_substitute(rows, output)? {
                return Ok(false);
            }
        }
        Ok(delta.pending_updates.iter().all(|pending| {
            saved_pending_context_is_compatible(pending, &pending.required_poi_list_keys)
        }) && proof_groups_are_consistent(&delta.pending_updates)?)
    }

    fn record_pending_row(
        &self,
        rows: &mut SenderMaterializationRows,
        pending: &PendingOutputPoiContextRecord,
        recovery: &OutputPoiRecoveryRecord,
    ) -> Result<bool, WalletCacheError> {
        let Some(observation) = pending.observation.as_ref() else {
            return Ok(false);
        };
        let Ok(output_tree) = u32::try_from(observation.output_tree) else {
            return Ok(false);
        };
        let output_key = (
            output_tree,
            observation.output_position,
            pending.output_commitment,
        );
        if !self.pending_row_matches_candidate(pending, recovery, observation)
            || !self.qualified_outputs.contains(&output_key)
        {
            return Ok(false);
        }
        if !rows.output_commitments.insert(output_key)
            || !self.record_pending_identity(rows, pending, observation)
        {
            return Ok(false);
        }
        if self.snapshot_holds_output(output_key) {
            return Ok(false);
        }
        self.record_stored_pending_row(rows, pending, recovery)
    }

    /// Records the blinded commitment of `pending`'s submit identity, whose required lists must be
    /// the active lists it is not yet Valid on.
    fn record_pending_identity(
        &self,
        rows: &mut SenderMaterializationRows,
        pending: &PendingOutputPoiContextRecord,
        observation: &PendingOutputPoiObservation,
    ) -> bool {
        let Some(identity) = pending_output_poi_submit_identity(pending, observation) else {
            return false;
        };
        pending.required_poi_list_keys
            == saved_poi_compatibility::unresolved_output_lists(
                self.active_list_keys,
                identity.derived_blinded_commitment,
                self.valid_by_list,
            )
            && rows
                .blinded_commitments
                .insert(identity.derived_blinded_commitment)
    }

    /// Whether the snapshot already holds an unspent copy of the output at `output_key`.
    fn snapshot_holds_output(&self, output_key: (u32, u64, FixedBytes<32>)) -> bool {
        let (output_tree, output_position, output_commitment) = output_key;
        self.snapshot.iter().any(|output| {
            !output.is_spent()
                && (
                    output.utxo.tree,
                    output.utxo.position,
                    &output.utxo.source,
                    output.utxo.poi.commitment,
                ) == (
                    output_tree,
                    output_position,
                    &self.candidate.source,
                    output_commitment,
                )
        })
    }

    fn pending_row_matches_candidate(
        &self,
        pending: &PendingOutputPoiContextRecord,
        recovery: &OutputPoiRecoveryRecord,
        observation: &PendingOutputPoiObservation,
    ) -> bool {
        let source = &self.candidate.source;
        (pending.chain_id, pending.wallet_id.as_str())
            == (self.cfg.chain.chain_id, self.cfg.cache_key.as_str())
            && pending.output_role == PendingOutputPoiRole::RecoveredOutgoing
            && pending.source_operation_id.is_some()
            && pending.txid_merkleroot_index.is_some()
            && !pending.required_poi_list_keys.is_empty()
            && (
                observation.tx_hash,
                observation.block_number,
                observation.block_timestamp,
            ) == (source.tx_hash, source.block_number, source.block_timestamp)
            && (
                recovery.chain_id,
                recovery.wallet_id.as_str(),
                recovery.output_commitment,
                recovery.source_tx_hash,
            ) == (
                self.cfg.chain.chain_id,
                self.cfg.cache_key.as_str(),
                pending.output_commitment,
                source.tx_hash,
            )
    }

    fn record_stored_pending_row(
        &self,
        rows: &mut SenderMaterializationRows,
        pending: &PendingOutputPoiContextRecord,
        recovery: &OutputPoiRecoveryRecord,
    ) -> Result<bool, WalletCacheError> {
        let current_pending = self.cache_store.get_pending_output_poi_context(
            self.cfg.chain.chain_id,
            &self.cfg.cache_key,
            &pending.output_commitment,
        )?;
        let current_recovery = self.cache_store.get_output_poi_recovery(
            self.cfg.chain.chain_id,
            &self.cfg.cache_key,
            &pending.output_commitment,
        )?;
        match (current_pending, current_recovery) {
            (None, None) => {
                rows.absent_pending_updates.push(pending.clone());
                rows.absent_recovery_updates.push(recovery.clone());
            }
            (Some(current_pending), current_recovery)
                if self
                    .replacement_group
                    .iter()
                    .any(|(expected, expected_recovery)| {
                        expected.output_commitment == pending.output_commitment
                            && expected_pending_context_state(Some(expected))
                                == expected_pending_context_state(Some(&current_pending))
                            && expected_recovery_state(expected_recovery.as_ref())
                                == expected_recovery_state(current_recovery.as_ref())
                    }) =>
            {
                rows.absent_pending_updates.push(pending.clone());
                rows.absent_recovery_updates.push(recovery.clone());
            }
            (Some(current_pending), Some(current_recovery))
                if sender_materialization_pending_matches(&current_pending, pending)
                    && sender_materialization_recovery_matches(&current_recovery, recovery) => {}
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn record_owned_substitute(
        &self,
        rows: &mut SenderMaterializationRows,
        expected: &ExpectedWalletOutput,
    ) -> bool {
        let mut matches = self
            .snapshot
            .iter()
            .filter(|output| expected.matches(output));
        let Some(current) = matches.next() else {
            return false;
        };
        if matches.next().is_some() || current.utxo.source != self.candidate.source {
            return false;
        }
        rows.insert_output(
            expected.candidate_identity(),
            current.utxo.poi.blinded_commitment,
        )
    }

    fn record_external_substitute(
        &self,
        rows: &mut SenderMaterializationRows,
        output: &Utxo,
    ) -> Result<bool, WalletCacheError> {
        let exact = self
            .candidate
            .outputs
            .iter()
            .filter(|candidate_output| {
                (
                    candidate_output.tree,
                    candidate_output.position,
                    candidate_output.commitment,
                ) == (output.tree, output.position, output.poi.commitment)
                    && candidate_output
                        .note
                        .as_ref()
                        .is_some_and(|note| note.commitment() == output.note.commitment())
            })
            .count();
        if exact != 1 || output.source != self.candidate.source {
            return Ok(false);
        }
        if !self.external_valid.contains(&output.poi.blinded_commitment)
            || !rows.insert_output(
                (output.tree, output.position, output.poi.commitment),
                output.poi.blinded_commitment,
            )
        {
            return Ok(false);
        }
        Ok(self
            .cache_store
            .get_pending_output_poi_context(
                self.cfg.chain.chain_id,
                &self.cfg.cache_key,
                &output.poi.commitment,
            )?
            .is_none())
    }
}

/// Whether rows sharing a railgun txid and input tree carry the same proof inputs.
fn proof_groups_are_consistent(
    pending_updates: &[PendingOutputPoiContextRecord],
) -> Result<bool, WalletCacheError> {
    let mut proof_groups = BTreeMap::new();
    for pending in pending_updates {
        let key = (pending.railgun_txid, pending.utxo_tree_in);
        let material =
            rmp_serde::to_vec(&(pending.txid_merkleroot_index, &pending.source_operation_id))?;
        if proof_groups
            .insert((key, None), material.clone())
            .is_some_and(|old| old != material)
        {
            return Ok(false);
        }
        for (list_key, per_leaf) in &pending.pre_transaction_pois_per_txid_leaf_per_list {
            let encoded = rmp_serde::to_vec(per_leaf)?;
            if proof_groups
                .insert((key, Some(*list_key)), encoded.clone())
                .is_some_and(|old| old != encoded)
            {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

pub(super) async fn apply_sender_candidate_materialization(
    turn: PoiApplyTurn<'_>,
    mut delta: SenderCandidateMaterializationDelta,
) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
    let PoiApplyTurn {
        permit,
        snapshot,
        cache_store,
        cfg,
        ..
    } = turn;
    // A kept candidate retains only its handed-off unshield work.
    let Ok(replacement) =
        handed_off_sender_candidate(&delta.expected_candidate, delta.unshield.take())
    else {
        drop(permit);
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    let materialization = SenderMaterialization {
        cache_store,
        cfg,
        snapshot,
        delta,
    };
    let Some(external_valid) = materialization.valid_external_substitutes().await else {
        return Ok(PoiPrivateApplyOutcome::Skipped);
    };
    materialization
        .validate_and_commit(permit, replacement, &external_valid)
        .await
}

/// A sender materialization delta and the wallet state it is checked against.
struct SenderMaterialization<'a> {
    cache_store: &'a dyn WalletCacheStore,
    cfg: &'a WalletConfig,
    snapshot: Vec<WalletUtxo>,
    delta: SenderCandidateMaterializationDelta,
}

impl SenderMaterialization<'_> {
    /// Blinded commitments of the external substitutes, which must all be Valid on every active
    /// list; `None` when the corpus read fails or one is not Valid.
    async fn valid_external_substitutes(&self) -> Option<BTreeSet<FixedBytes<32>>> {
        let external_blinded = self
            .delta
            .external_valid_substitutes
            .iter()
            .map(|output| output.poi.blinded_commitment)
            .collect::<Vec<_>>();
        let external_valid = if external_blinded.is_empty() {
            BTreeSet::new()
        } else {
            saved_poi_compatibility::corpus_valid_outputs(
                &self.delta.expected_corpus.corpus,
                self.cfg.chain.chain_id,
                &self.delta.active_list_keys,
                &external_blinded,
            )
            .await?
        };
        (external_valid.len() == external_blinded.len()).then_some(external_valid)
    }

    /// Validates the delta under the public commit guard and the corpus revision fence, then
    /// commits it. Each skip keeps its permit release order relative to the guards.
    async fn validate_and_commit(
        &self,
        permit: WalletPrivateMutationPermit<'_>,
        replacement: Option<SenderTransactionCandidate>,
        external_valid: &BTreeSet<FixedBytes<32>>,
    ) -> Result<PoiPrivateApplyOutcome, WalletCacheError> {
        let delta = &self.delta;
        // This is the final public authority acquisition. Private actor and network work
        // completed before it; reset cannot cross the local validation/commit below.
        let _public_commit_guard = delta.public_data_fence.acquire_commit_guard().await;
        // The corpus fence comes last and is held through the commit, so the proofs were
        // built from the corpus revision that is current when the candidate is consumed.
        let _revision_fence =
            match hold_expected_poi_corpus_revision(Some(&delta.expected_corpus)).await {
                Ok(revision_fence) => revision_fence,
                Err(stale) => {
                    drop(permit);
                    return Ok(stale);
                }
            };
        let Some(valid_by_list) = self.valid_by_list().await else {
            return Ok(PoiPrivateApplyOutcome::Skipped);
        };
        if !self.is_current()? {
            drop(permit);
            return Ok(PoiPrivateApplyOutcome::Skipped);
        }
        if !self.replacement_group_is_current()? {
            return Ok(PoiPrivateApplyOutcome::Skipped);
        }
        let qualified_outputs = self.qualified_outputs();
        let check = self.check(&valid_by_list, &qualified_outputs, external_valid);
        let mut rows = SenderMaterializationRows::default();
        if !check.record_candidate_rows(&mut rows, delta)? {
            drop(permit);
            return Ok(PoiPrivateApplyOutcome::Skipped);
        }
        if !check.record_external_rows_and_check_pending_proofs(&mut rows, delta)? {
            return Ok(PoiPrivateApplyOutcome::Skipped);
        }
        if !self.rows_are_complete(&rows, &qualified_outputs) {
            drop(permit);
            return Ok(PoiPrivateApplyOutcome::Skipped);
        }
        let (candidate_updates, candidate_deletes) = self.candidate_rows(replacement);
        let private_rows = PoiPrivateRows {
            pending_updates: &rows.absent_pending_updates,
            recovery_updates: &rows.absent_recovery_updates,
            candidate_updates: &candidate_updates,
            candidate_deletes: &candidate_deletes,
            ..PoiPrivateRows::default()
        };
        let workflow_status = wallet_ppoi_workflow_status_after_mutations(
            self.cache_store,
            self.cfg,
            &delta.active_list_keys,
            permit.ppoi_workflow_status().validation_revision,
            private_rows,
        )?;
        commit_durable_apply(permit, self.cache_store, private_rows, workflow_status)
    }

    /// The candidate's outputs by active list on which they are Valid; `None` when the corpus
    /// read fails.
    async fn valid_by_list(&self) -> Option<BTreeMap<FixedBytes<32>, BTreeSet<FixedBytes<32>>>> {
        let candidate_blinded = candidate_blinded_commitments(&self.delta.expected_candidate);
        saved_poi_compatibility::corpus_valid_outputs_by_list(
            &self.delta.expected_corpus.corpus,
            self.cfg.chain.chain_id,
            &self.delta.active_list_keys,
            &candidate_blinded,
        )
        .await
    }

    /// Whether the delta carries rows to materialize and its candidate is still the stored one,
    /// matching the snapshot under a current public data fence.
    fn is_current(&self) -> Result<bool, WalletCacheError> {
        let delta = &self.delta;
        if delta.active_list_keys.is_empty()
            || delta.pending_updates.len() != delta.recovery_updates.len()
        {
            return Ok(false);
        }
        let nothing_to_materialize = delta.pending_updates.is_empty()
            && delta.owned_substitutes.is_empty()
            && delta.external_valid_substitutes.is_empty();
        Ok(!nothing_to_materialize
            && sender_candidate_recovery::sender_candidate_matches_wallet_snapshot(
                &delta.expected_candidate,
                &self.snapshot,
            )
            && delta
                .public_data_fence
                .is_current(delta.expected_candidate.source.tx_hash)
            && stored_sender_candidate_matches(
                self.cache_store,
                self.cfg,
                &delta.expected_candidate,
            )?)
    }

    /// Whether the pending contexts the materialization replaces are still the stored ones.
    fn replacement_group_is_current(&self) -> Result<bool, WalletCacheError> {
        Ok(self.delta.replacement_group.is_empty()
            || saved_poi_compatibility::saved_sender_group_is_current(
                self.cache_store,
                self.cfg,
                &self.delta.expected_candidate.source,
                &self.delta.replacement_group,
            )?)
    }

    /// The candidate rows to commit: the kept replacement, or the expected candidate's deletion.
    fn candidate_rows(
        &self,
        replacement: Option<SenderTransactionCandidate>,
    ) -> (Vec<SenderTransactionCandidate>, Vec<FixedBytes<32>>) {
        match replacement {
            Some(replacement) => (vec![replacement], Vec::new()),
            None => (
                Vec::new(),
                vec![self.delta.expected_candidate.semantic_id()],
            ),
        }
    }

    /// Identities of the candidate outputs that carry a note; the rows must cover exactly these.
    fn qualified_outputs(&self) -> BTreeSet<(u32, u64, FixedBytes<32>)> {
        self.delta
            .expected_candidate
            .outputs
            .iter()
            .filter(|output| output.note.is_some())
            .map(|output| (output.tree, output.position, output.commitment))
            .collect()
    }

    fn check<'c>(
        &'c self,
        valid_by_list: &'c BTreeMap<FixedBytes<32>, BTreeSet<FixedBytes<32>>>,
        qualified_outputs: &'c BTreeSet<(u32, u64, FixedBytes<32>)>,
        external_valid: &'c BTreeSet<FixedBytes<32>>,
    ) -> SenderMaterializationCheck<'c> {
        SenderMaterializationCheck {
            cache_store: self.cache_store,
            cfg: self.cfg,
            snapshot: &self.snapshot,
            candidate: &self.delta.expected_candidate,
            active_list_keys: &self.delta.active_list_keys,
            valid_by_list,
            qualified_outputs,
            replacement_group: &self.delta.replacement_group,
            external_valid,
        }
    }

    /// Whether the rows cover every qualified output and exactly the proved outputs, under a
    /// still current public data fence.
    fn rows_are_complete(
        &self,
        rows: &SenderMaterializationRows,
        qualified_outputs: &BTreeSet<(u32, u64, FixedBytes<32>)>,
    ) -> bool {
        if rows.output_commitments != *qualified_outputs {
            return false;
        }
        let proof_outputs = self
            .delta
            .proof_outputs
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        proof_outputs.len() == rows.blinded_commitments.len()
            && proof_outputs == rows.blinded_commitments
            && self
                .delta
                .public_data_fence
                .is_current(self.delta.expected_candidate.source.tx_hash)
    }
}

pub(super) async fn apply_sender_candidate_unshield_update(
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
        || !sender_candidate_recovery::sender_candidate_matches_wallet_snapshot(
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
                sender_candidate_recovery::candidates_match(&expected, replacement)
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

pub(super) async fn apply_sender_candidate_unshield_validated(
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
    let valid = saved_poi_compatibility::corpus_valid_blinded_commitments(
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
    let Ok(replacement) = sender_candidate_recovery::sender_candidate_after_unshield_validation(
        &expected_candidate,
        unshield,
        &validated,
    ) else {
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
