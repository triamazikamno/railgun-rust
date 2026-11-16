//! Whether a sender candidate's outputs are already Valid or covered by pending contexts.

use std::collections::BTreeSet;

use crate::wallet::saved_poi_compatibility::{
    corpus_valid_blinded_commitments, saved_pending_context_is_compatible,
};
use crate::wallet::{
    BlindedCommitmentData, DEFAULT_TXID_VERSION, EVM_CHAIN_TYPE, FixedBytes, Note,
    OutputPoiRecoveryRequest, PendingOutputPoiContextRecord, PoiStatus, PoiStatusReader,
    PublicPoiCorpusHandle, PublicPoiCorpusKey, SenderTransactionCandidate,
    SenderTransactionCandidateSpend, Utxo, UtxoCommitmentKind, UtxoPoiMetadata, WalletUtxo,
};

use super::sender_candidate_still_current;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SenderCandidateLocalClassification {
    pub(crate) external_outputs: Vec<BlindedCommitmentData>,
}

/// Classify a candidate without consulting public or remote state.
///
/// This is deliberately shared by the preflight and actor paths.  The actor repeats it from
/// its fresh wallet snapshot before allowing the candidate-only durable deletion.
///
/// Every output must be either exactly one wallet UTXO owned by the scan key or an external
/// output. An all-owned candidate classifies with no external outputs, which settles only its
/// private outputs, not its unshields. A candidate without outputs is `None`: it takes the
/// no-private-output unshield route instead.
pub(crate) fn classify_sender_candidate_for_local_retirement(
    candidate: &SenderTransactionCandidate,
    wallet_utxos: &[WalletUtxo],
    scan_keys: &railgun_wallet::scan::WalletScanKeys,
) -> Option<SenderCandidateLocalClassification> {
    candidate.validate().ok()?;
    if candidate.outputs.is_empty() {
        return None;
    }
    if !sender_candidate_wallet_spends_match(candidate, wallet_utxos) {
        return None;
    }

    let mut external_outputs = Vec::new();
    let mut external_blinded_commitments = BTreeSet::new();
    for output in &candidate.outputs {
        let owned_by_scan_key = output.note.as_ref().is_some_and(|note| {
            note.npk == Note::npk_for(scan_keys.master_public_key, note.random)
        });
        let exact_wallet_matches = wallet_utxos
            .iter()
            .filter(|wallet_utxo| {
                wallet_utxo_matches_sender_output(candidate, scan_keys, output, wallet_utxo)
            })
            .count();

        if exact_wallet_matches > 1 {
            return None;
        }
        if owned_by_scan_key {
            if exact_wallet_matches != 1 {
                return None;
            }
            continue;
        }
        let note = output.note.as_ref()?;
        let recomputed = Utxo::new(
            note.clone(),
            output.tree,
            output.position,
            candidate.source.clone(),
            UtxoCommitmentKind::Transact,
        );
        if !external_blinded_commitments.insert(recomputed.poi.blinded_commitment) {
            return None;
        }
        external_outputs.push(BlindedCommitmentData::transact(
            recomputed.poi.blinded_commitment,
        ));
    }
    Some(SenderCandidateLocalClassification { external_outputs })
}

/// Whether the wallet UTXOs spent by the candidate's source are exactly its wallet spends, with
/// no duplicate on either side.
fn sender_candidate_wallet_spends_match(
    candidate: &SenderTransactionCandidate,
    wallet_utxos: &[WalletUtxo],
) -> bool {
    let expected_spends = candidate
        .wallet_spends
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if expected_spends.len() != candidate.wallet_spends.len() {
        return false;
    }
    let actual_spend_entries = wallet_utxos
        .iter()
        .filter(|wallet_utxo| wallet_utxo.spent.as_ref() == Some(&candidate.source))
        .map(|wallet_utxo| SenderTransactionCandidateSpend {
            tree: wallet_utxo.utxo.tree,
            position: wallet_utxo.utxo.position,
            commitment: wallet_utxo.utxo.poi.commitment,
        })
        .collect::<Vec<_>>();
    let actual_spends = actual_spend_entries
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    actual_spends.len() == actual_spend_entries.len() && actual_spends == expected_spends
}

/// Whether `wallet_utxo` is the wallet's copy of `output`: the same source, location and POI
/// identity, with an NPK of the scan key. Without a candidate note, the wallet note's commitment
/// must also match.
fn wallet_utxo_matches_sender_output(
    candidate: &SenderTransactionCandidate,
    scan_keys: &railgun_wallet::scan::WalletScanKeys,
    output: &crate::SenderTransactionCandidateOutput,
    wallet_utxo: &WalletUtxo,
) -> bool {
    if (
        &wallet_utxo.utxo.source,
        wallet_utxo.utxo.tree,
        wallet_utxo.utxo.position,
    ) != (&candidate.source, output.tree, output.position)
    {
        return false;
    }
    let Some(note) = output.note.as_ref() else {
        return wallet_utxo.utxo.poi.commitment == output.commitment
            && wallet_utxo.utxo.poi.commitment_kind == UtxoCommitmentKind::Transact
            && wallet_utxo.utxo.poi.npk
                == FixedBytes::from(
                    Note::npk_for(scan_keys.master_public_key, wallet_utxo.utxo.note.random)
                        .to_be_bytes::<32>(),
                )
            && sender_candidate_poi_identity_matches(
                &wallet_utxo.utxo.poi,
                &Utxo::new(
                    wallet_utxo.utxo.note.clone(),
                    output.tree,
                    output.position,
                    candidate.source.clone(),
                    UtxoCommitmentKind::Transact,
                )
                .poi,
            );
    };
    let recomputed = Utxo::new(
        note.clone(),
        output.tree,
        output.position,
        candidate.source.clone(),
        UtxoCommitmentKind::Transact,
    );
    sender_candidate_poi_identity_matches(&wallet_utxo.utxo.poi, &recomputed.poi)
        && wallet_utxo.utxo.note.npk == Note::npk_for(scan_keys.master_public_key, note.random)
}

fn sender_candidate_poi_identity_matches(
    actual: &UtxoPoiMetadata,
    expected: &UtxoPoiMetadata,
) -> bool {
    actual.commitment_kind == expected.commitment_kind
        && actual.commitment == expected.commitment
        && actual.npk == expected.npk
        && actual.blinded_commitment == expected.blinded_commitment
}

pub(super) async fn locally_valid_sender_candidate(
    request: &OutputPoiRecoveryRequest<'_>,
    candidate: &SenderTransactionCandidate,
) -> Option<PublicPoiCorpusHandle> {
    if !request.poi_runtime.is_indexed_artifacts() || request.active_list_keys.is_empty() {
        return None;
    }
    let classification = classify_sender_candidate_for_local_retirement(
        candidate,
        request.wallet_utxos,
        &request.cfg.scan_keys,
    )?;
    let key = PublicPoiCorpusKey::wallet_default(request.cfg.chain.chain_id);
    if !request
        .public_data_plane
        .poi_corpus_ready_for_lists(key.clone(), request.active_list_keys)
        .await
    {
        return None;
    }
    let corpus = request
        .public_data_plane
        .ensure_poi_corpus(key)
        .await
        .ok()?;
    let _revision_fence = corpus.revision_read_fence().await;
    let statuses = corpus
        .status_reader()
        .pois_per_list(
            DEFAULT_TXID_VERSION,
            EVM_CHAIN_TYPE,
            request.cfg.chain.chain_id,
            request.active_list_keys,
            &classification.external_outputs,
        )
        .await
        .ok()?;
    let all_valid = classification.external_outputs.iter().all(|data| {
        statuses
            .get(&data.blinded_commitment)
            .is_some_and(|per_list| {
                request
                    .active_list_keys
                    .iter()
                    .all(|list_key| per_list.get(list_key) == Some(&PoiStatus::Valid))
            })
    });
    all_valid.then_some(corpus)
}

async fn locally_valid_sender_candidate_outputs(
    request: &OutputPoiRecoveryRequest<'_>,
    candidate: &SenderTransactionCandidate,
) -> BTreeSet<FixedBytes<32>> {
    if !request.poi_runtime.is_indexed_artifacts() || request.active_list_keys.is_empty() {
        return BTreeSet::new();
    }
    if !request
        .public_data_plane
        .poi_corpus_ready_for_lists(
            PublicPoiCorpusKey::wallet_default(request.cfg.chain.chain_id),
            request.active_list_keys,
        )
        .await
    {
        return BTreeSet::new();
    }
    let Some(output_data) = candidate
        .outputs
        .iter()
        .map(|output| {
            let note = output.note.as_ref()?;
            let utxo = Utxo::new(
                note.clone(),
                output.tree,
                output.position,
                candidate.source.clone(),
                UtxoCommitmentKind::Transact,
            );
            (utxo.poi.commitment == output.commitment)
                .then_some(BlindedCommitmentData::transact(utxo.poi.blinded_commitment))
        })
        .collect::<Option<Vec<_>>>()
    else {
        return BTreeSet::new();
    };
    let Ok(corpus) = request
        .public_data_plane
        .ensure_poi_corpus(PublicPoiCorpusKey::wallet_default(
            request.cfg.chain.chain_id,
        ))
        .await
    else {
        return BTreeSet::new();
    };
    let _revision_fence = corpus.revision_read_fence().await;
    corpus_valid_blinded_commitments(
        &corpus,
        request.cfg.chain.chain_id,
        request.active_list_keys,
        &output_data,
    )
    .await
    .unwrap_or_default()
}

/// Whether `context` covers the candidate's `output`: compatible with the active lists, not
/// terminal, for the candidate's chain and wallet, observed at the output in the candidate's
/// source transaction, and holding a proof on every active list.
pub(super) fn pending_context_covers_sender_output(
    candidate: &SenderTransactionCandidate,
    output: &crate::SenderTransactionCandidateOutput,
    active_list_keys: &[FixedBytes<32>],
    context: &PendingOutputPoiContextRecord,
) -> bool {
    if !saved_pending_context_is_compatible(context, active_list_keys)
        || context.terminal_error.is_some()
    {
        return false;
    }
    if (
        context.chain_id,
        context.wallet_id.as_str(),
        context.output_commitment,
    ) != (
        candidate.chain_id,
        candidate.wallet_id.as_str(),
        output.commitment,
    ) {
        return false;
    }
    let Some(note) = output.note.as_ref() else {
        return false;
    };
    if context.output_npk != FixedBytes::from(note.npk.to_be_bytes::<32>()) {
        return false;
    }
    let Some(observation) = context.observation.as_ref() else {
        return false;
    };
    (
        observation.output_tree,
        observation.output_position,
        observation.tx_hash,
        observation.block_number,
        observation.block_timestamp,
    ) == (
        u64::from(output.tree),
        output.position,
        candidate.source.tx_hash,
        candidate.source.block_number,
        candidate.source.block_timestamp,
    ) && pending_context_has_list_proofs(context, active_list_keys)
}

/// Whether `context` names every active list and holds a proof for each.
fn pending_context_has_list_proofs(
    context: &PendingOutputPoiContextRecord,
    active_list_keys: &[FixedBytes<32>],
) -> bool {
    active_list_keys.iter().all(|list_key| {
        context.list_keys().contains(list_key)
            && context
                .pre_transaction_pois_per_txid_leaf_per_list
                .get(list_key)
                .is_some_and(|pois| !pois.is_empty())
    })
}

#[derive(Debug, Default, Clone, Copy)]
pub(super) struct SenderCandidateCoverage {
    pub(super) local_valid: u64,
    pub(super) pending_contexts: u64,
}

pub(super) fn sender_candidate_coverage_from_routes(
    candidate: &SenderTransactionCandidate,
    local_valid_commitments: &BTreeSet<FixedBytes<32>>,
    pending_context_commitments: &BTreeSet<FixedBytes<32>>,
) -> Option<SenderCandidateCoverage> {
    let mut coverage = SenderCandidateCoverage::default();
    for output in &candidate.outputs {
        if local_valid_commitments.contains(&output.commitment) {
            coverage.local_valid = coverage.local_valid.saturating_add(1);
        } else if pending_context_commitments.contains(&output.commitment) {
            coverage.pending_contexts = coverage.pending_contexts.saturating_add(1);
        } else {
            return None;
        }
    }
    (coverage.pending_contexts > 0).then_some(coverage)
}

pub(super) async fn sender_candidate_coverage(
    request: &OutputPoiRecoveryRequest<'_>,
    candidate: &SenderTransactionCandidate,
) -> Option<SenderCandidateCoverage> {
    if candidate.validate().is_err()
        || classify_sender_candidate_for_local_retirement(
            candidate,
            request.wallet_utxos,
            &request.cfg.scan_keys,
        )
        .is_none()
    {
        return None;
    }
    if !sender_candidate_still_current(
        request.authority,
        request.cache_store,
        request.cfg,
        candidate,
    )
    .await
    {
        return None;
    }
    let local_valid = locally_valid_sender_candidate_outputs(request, candidate).await;
    let mut local_valid_commitments = BTreeSet::new();
    let mut pending_context_commitments = BTreeSet::new();
    for output in &candidate.outputs {
        let blinded_commitment = output.note.as_ref().and_then(|note| {
            let utxo = Utxo::new(
                note.clone(),
                output.tree,
                output.position,
                candidate.source.clone(),
                UtxoCommitmentKind::Transact,
            );
            (utxo.poi.commitment == output.commitment).then_some(utxo.poi.blinded_commitment)
        });
        if blinded_commitment.is_some_and(|blinded| local_valid.contains(&blinded)) {
            local_valid_commitments.insert(output.commitment);
            continue;
        }
        let pending = request
            .cache_store
            .get_pending_output_poi_context(
                request.cfg.chain.chain_id,
                &request.cfg.cache_key,
                &output.commitment,
            )
            .ok()
            .flatten()
            .is_some_and(|context| {
                pending_context_covers_sender_output(
                    candidate,
                    output,
                    request.active_list_keys,
                    &context,
                )
            });
        if pending {
            pending_context_commitments.insert(output.commitment);
        }
    }
    sender_candidate_coverage_from_routes(
        candidate,
        &local_valid_commitments,
        &pending_context_commitments,
    )
}
