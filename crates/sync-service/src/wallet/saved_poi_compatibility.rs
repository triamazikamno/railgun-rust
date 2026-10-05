use std::collections::BTreeSet;
use std::sync::OnceLock;

use broadcaster_core::crypto::snark_proof::Prover;
use broadcaster_core::transact::PreTxPoi;

use super::{ChainPublicDataPlane, PoiStatusReader, PublicTxidCacheKey, WalletConfig};
use super::{FixedBytes, PendingOutputPoiContextRecord, PreTransactionPoiMap};
use crate::indexed_artifacts::{ChainScope, ChainType};

#[derive(Clone)]
pub(crate) struct SenderCandidateReplayFence {
    pub(super) public_data_plane: ChainPublicDataPlane,
    pub(super) epoch: crate::types::PublicDataPlaneEpoch,
}

impl std::fmt::Debug for SenderCandidateReplayFence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SenderCandidateReplayFence")
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

pub(super) fn saved_sender_group_is_current(
    cache_store: &dyn super::WalletCacheStore,
    cfg: &WalletConfig,
    source: &super::UtxoSource,
    expected: &[(
        PendingOutputPoiContextRecord,
        Option<super::OutputPoiRecoveryRecord>,
    )],
) -> Result<bool, super::WalletCacheError> {
    let current =
        cache_store.list_pending_output_poi_contexts(cfg.chain.chain_id, &cfg.cache_key)?;
    let fingerprints = |records: Vec<&PendingOutputPoiContextRecord>| -> Option<BTreeSet<Vec<u8>>> {
        records
            .into_iter()
            .map(|record| rmp_serde::to_vec(record).ok())
            .collect()
    };
    let current = fingerprints(
        current
            .iter()
            .filter(|record| {
                record.observation.as_ref().is_some_and(|observation| {
                    observation.tx_hash == source.tx_hash
                        && observation.block_number == source.block_number
                        && observation.block_timestamp == source.block_timestamp
                })
            })
            .collect(),
    );
    if current.is_none()
        || current != fingerprints(expected.iter().map(|(record, _)| record).collect())
    {
        return Ok(false);
    }
    for (record, recovery) in expected {
        let current = cache_store.get_output_poi_recovery(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &record.output_commitment,
        )?;
        if super::expected_recovery_state(current.as_ref())
            != super::expected_recovery_state(recovery.as_ref())
        {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(super) async fn corpus_valid_outputs(
    corpus: &super::PublicPoiCorpusHandle,
    chain_id: u64,
    list_keys: &[FixedBytes<32>],
    outputs: &[FixedBytes<32>],
) -> Option<BTreeSet<FixedBytes<32>>> {
    if list_keys.is_empty() {
        return None;
    }
    let data = outputs
        .iter()
        .copied()
        .map(super::BlindedCommitmentData::transact)
        .collect::<Vec<_>>();
    let statuses = corpus
        .status_reader()
        .pois_per_list(
            super::DEFAULT_TXID_VERSION,
            super::EVM_CHAIN_TYPE,
            chain_id,
            list_keys,
            &data,
        )
        .await
        .ok()?;
    Some(
        outputs
            .iter()
            .copied()
            .filter(|output| {
                statuses.get(output).is_some_and(|per_list| {
                    list_keys
                        .iter()
                        .all(|list_key| per_list.get(list_key) == Some(&super::PoiStatus::Valid))
                })
            })
            .collect(),
    )
}

pub(super) async fn corpus_valid_outputs_by_list(
    corpus: &super::PublicPoiCorpusHandle,
    chain_id: u64,
    list_keys: &[FixedBytes<32>],
    outputs: &[FixedBytes<32>],
) -> Option<std::collections::BTreeMap<FixedBytes<32>, BTreeSet<FixedBytes<32>>>> {
    let data = outputs
        .iter()
        .copied()
        .map(super::BlindedCommitmentData::transact)
        .collect::<Vec<_>>();
    let statuses = corpus
        .status_reader()
        .pois_per_list(
            super::DEFAULT_TXID_VERSION,
            super::EVM_CHAIN_TYPE,
            chain_id,
            list_keys,
            &data,
        )
        .await
        .ok()?;
    Some(
        list_keys
            .iter()
            .copied()
            .map(|list_key| {
                (
                    list_key,
                    outputs
                        .iter()
                        .copied()
                        .filter(|output| {
                            statuses
                                .get(output)
                                .and_then(|per_list| per_list.get(&list_key))
                                == Some(&super::PoiStatus::Valid)
                        })
                        .collect(),
                )
            })
            .collect(),
    )
}

pub(super) fn unresolved_output_lists(
    active_lists: &[FixedBytes<32>],
    blinded_commitment: FixedBytes<32>,
    valid_by_list: &std::collections::BTreeMap<FixedBytes<32>, BTreeSet<FixedBytes<32>>>,
) -> Vec<FixedBytes<32>> {
    active_lists
        .iter()
        .copied()
        .filter(|list_key| {
            !valid_by_list
                .get(list_key)
                .is_some_and(|valid| valid.contains(&blinded_commitment))
        })
        .collect()
}

pub(super) async fn reconstruct_incompatible_sender_candidates(
    request: &super::output_poi_recovery::OutputPoiRecoveryRequest<'_>,
) -> Result<super::SenderCandidateRecoveryReport, super::WalletCacheError> {
    let records = request
        .cache_store
        .list_pending_output_poi_contexts(request.cfg.chain.chain_id, &request.cfg.cache_key)?;
    let mut sources = BTreeSet::new();
    let mut unresolved_outputs = BTreeSet::new();
    for record in &records {
        let retained_active = record
            .list_keys()
            .into_iter()
            .filter(|list_key| request.active_list_keys.contains(list_key))
            .collect::<Vec<_>>();
        if matches!(
            record.output_role,
            super::PendingOutputPoiRole::Recipient
                | super::PendingOutputPoiRole::BroadcasterFee
                | super::PendingOutputPoiRole::RecoveredOutgoing
        ) && !retained_active.is_empty()
            && record.terminal_error.is_none()
            && !saved_pending_context_is_compatible(record, &retained_active)
            && let Some(observation) = &record.observation
        {
            let recovery = request.cache_store.get_output_poi_recovery(
                request.cfg.chain.chain_id,
                &request.cfg.cache_key,
                &record.output_commitment,
            )?;
            if recovery.as_ref().is_some_and(|recovery| {
                recovery.source_tx_hash != observation.tx_hash
                    || !matches!(
                        recovery.status,
                        super::OutputPoiRecoveryStatus::Recoverable
                            | super::OutputPoiRecoveryStatus::Submitted
                            | super::OutputPoiRecoveryStatus::SubmitFailed
                    )
            }) {
                continue;
            }
            sources.insert((
                observation.block_number,
                observation.tx_hash,
                observation.block_timestamp,
            ));
            unresolved_outputs.insert(record.output_commitment);
        }
    }
    if sources.is_empty() {
        return Ok(super::SenderCandidateRecoveryReport::default());
    }
    let existing = request
        .cache_store
        .list_sender_transaction_candidates(request.cfg.chain.chain_id, &request.cfg.cache_key)?;
    let mut report = super::SenderCandidateRecoveryReport {
        expected_candidates: existing
            .iter()
            .map(|candidate| {
                candidate
                    .encode()
                    .map(|encoded| (candidate.semantic_id(), encoded))
                    .map_err(|_| super::WalletCacheError::Crypto)
            })
            .collect::<Result<_, _>>()?,
        ..super::SenderCandidateRecoveryReport::default()
    };
    for (block_number, tx_hash, block_timestamp) in sources {
        if request.authority.revalidate().is_err() {
            break;
        }
        let expected_group = records
            .iter()
            .filter(|record| {
                record.observation.as_ref().is_some_and(|observation| {
                    observation.tx_hash == tx_hash
                        && observation.block_number == block_number
                        && observation.block_timestamp == block_timestamp
                })
            })
            .map(|record| {
                request
                    .cache_store
                    .get_output_poi_recovery(
                        request.cfg.chain.chain_id,
                        &request.cfg.cache_key,
                        &record.output_commitment,
                    )
                    .map(|recovery| (record.clone(), recovery))
            })
            .collect::<Result<Vec<_>, _>>()?;
        for (record, _) in &expected_group {
            report.expected_pending_contexts.insert(
                record.output_commitment,
                super::pending_output_poi_context_fingerprint(record)
                    .ok_or(super::WalletCacheError::Crypto)?,
            );
        }
        let output_count = u64::try_from(
            expected_group
                .iter()
                .filter(|(record, _)| unresolved_outputs.contains(&record.output_commitment))
                .count(),
        )
        .unwrap_or(u64::MAX);
        // A durable candidate already supplies the replay evidence; the existing materializer
        // owns its qualification/failure reporting. Do not count that group a second time.
        if existing.iter().any(|candidate| {
            candidate.source.tx_hash == tx_hash
                && candidate.source.block_number == block_number
                && candidate.source.block_timestamp == block_timestamp
        }) {
            continue;
        }
        let rows = match request
            .public_data_plane
            .saved_poi_source_block_rows(block_number)
            .await
        {
            Ok(crate::chain::PublicScanRowsAnswer::Rows(rows)) => rows,
            Ok(_) => {
                report.awaiting_public_txid_data = report
                    .awaiting_public_txid_data
                    .saturating_add(output_count);
                continue;
            }
            Err(_) => {
                report.retrying = report.retrying.saturating_add(output_count);
                continue;
            }
        };
        if rows.range.from_block > block_number
            || rows.range.to_block < block_number
            || rows.epoch != request.public_data_plane.current_epoch()
        {
            report.retrying = report.retrying.saturating_add(output_count);
            continue;
        }
        let delta = super::WalletLogDelta::from_rows(&rows.rows, &request.cfg.scan_keys);
        let nullifiers = delta
            .nullifiers
            .into_iter()
            .map(|spent| ((spent.tree, spent.nullifier), spent.source))
            .collect();
        let candidates = super::delta::sender_scan_candidate_inputs(
            request.wallet_utxos,
            request.cfg.scan_keys.nullifying_key,
            &nullifiers,
            delta.sender_scan_outputs,
            &request.cfg.scan_keys,
        );
        let mut candidates = candidates.into_iter().filter(|candidate| {
            candidate.source.tx_hash == tx_hash
                && candidate.source.block_number == block_number
                && candidate.source.block_timestamp == block_timestamp
        });
        let Some(candidate) = candidates.next() else {
            report.needs_attention = report.needs_attention.saturating_add(output_count);
            continue;
        };
        if candidates.next().is_some() {
            report.needs_attention = report.needs_attention.saturating_add(output_count);
            continue;
        }
        let Ok(candidate) =
            candidate.into_record(request.cfg.chain.chain_id, request.cfg.cache_key.clone())
        else {
            report.needs_attention = report.needs_attention.saturating_add(output_count);
            continue;
        };
        let encoded = candidate
            .encode()
            .map_err(|_| super::WalletCacheError::Crypto)?;
        let candidate_id = candidate.semantic_id();
        let outcome = super::apply_poi_private_delta(
            request.authority,
            request.db,
            request.cache_store,
            request.cfg,
            super::OwnedPoiPrivateDelta::SenderCandidateReconstruction {
                candidate,
                replay_fence: SenderCandidateReplayFence {
                    public_data_plane: request.public_data_plane.clone(),
                    epoch: rows.epoch,
                },
                expected_group,
            },
        )
        .await?;
        match outcome {
            super::PoiPrivateApplyOutcome::Applied { .. } => {
                report.expected_candidates.insert(candidate_id, encoded);
            }
            super::PoiPrivateApplyOutcome::Skipped
            | super::PoiPrivateApplyOutcome::SkippedStaleCorpusRevision => {
                if request.public_data_plane.current_epoch() == rows.epoch {
                    report.needs_attention = report.needs_attention.saturating_add(output_count);
                } else {
                    report.retrying = report.retrying.saturating_add(output_count);
                }
            }
        }
    }
    Ok(report)
}

/// Saved proof records have no circuit version. Verify their actual public signals against
/// the embedded current keys before reusing them. This cache contains only prepared keys.
fn current_verifier() -> Option<&'static Prover> {
    static VERIFIER: OnceLock<Option<Prover>> = OnceLock::new();
    VERIFIER.get_or_init(|| Prover::new().ok()).as_ref()
}

pub(super) fn saved_poi_is_compatible(
    poi: &PreTxPoi,
    exact_transaction_counts: Option<(usize, usize)>,
) -> bool {
    // These are the unpadded fields saved by our prover. Unshield is an additional output
    // even though it is absent from blinded_commitments_out.
    let counts = exact_transaction_counts.unwrap_or_else(|| {
        (
            poi.poi_merkleroots.len(),
            poi.blinded_commitments_out.len()
                + usize::from(
                    poi.railgun_txid_if_has_unshield
                        .iter()
                        .any(|byte| *byte != 0),
                ),
        )
    });
    counts.0 <= 13
        && counts.1 <= 13
        && poi.railgun_txid_if_has_unshield.len() <= 32
        && current_verifier()
            .is_some_and(|verifier| verifier.verify(counts.0, counts.1, poi).unwrap_or(false))
}

pub(super) fn saved_poi_map_is_compatible(
    proofs: &PreTransactionPoiMap,
    list_keys: &[FixedBytes<32>],
) -> bool {
    let mut checked = BTreeSet::new();
    !list_keys.is_empty()
        && list_keys.iter().all(|list_key| {
            proofs.get(list_key).is_some_and(|per_leaf| {
                !per_leaf.is_empty()
                    && per_leaf.values().all(|poi| {
                        let Ok(fingerprint) = rmp_serde::to_vec(poi) else {
                            return false;
                        };
                        !checked.insert(fingerprint) || saved_poi_is_compatible(poi, None)
                    })
            })
        })
}

pub(super) fn saved_pending_context_is_compatible(
    context: &PendingOutputPoiContextRecord,
    list_keys: &[FixedBytes<32>],
) -> bool {
    saved_poi_map_is_compatible(
        &context.pre_transaction_pois_per_txid_leaf_per_list,
        list_keys,
    )
}

pub(super) fn saved_pending_context_matches_public_transaction(
    public_data_plane: &ChainPublicDataPlane,
    cfg: &WalletConfig,
    context: &PendingOutputPoiContextRecord,
    list_keys: &[FixedBytes<32>],
) -> bool {
    let Some(observation) = context.observation.as_ref() else {
        return saved_pending_context_is_compatible(context, list_keys);
    };
    let cache_key = PublicTxidCacheKey::new(
        ChainScope {
            chain_type: ChainType::Evm,
            chain_id: cfg.chain.chain_id,
            railgun_contract: cfg.chain.contract,
        },
        &context.txid_version,
    );
    let Ok((rows, _)) = public_data_plane
        .txid_transactions_for_outer_hash_with_authority(&cache_key, observation.tx_hash)
    else {
        return saved_pending_context_is_compatible(context, list_keys);
    };
    let output_global = u128::from(observation.output_tree)
        * u128::from(broadcaster_core::tree::TREE_LEAF_COUNT)
        + u128::from(observation.output_position);
    let mut matching = rows.iter().filter(|row| {
        let transaction = &row.transaction;
        (transaction.transaction_hash, transaction.block_number)
            == (observation.tx_hash, observation.block_number)
            && transaction.utxo_tree_in == context.utxo_tree_in
            && broadcaster_core::transact::compute_railgun_txid_parts(
                &transaction.nullifiers,
                &transaction.commitments,
                transaction.bound_params_hash,
            ) == context.railgun_txid
            && output_global
                .checked_sub(transaction.output_start_global())
                .is_some_and(|offset| {
                    usize::try_from(offset)
                        .ok()
                        .and_then(|offset| transaction.commitments.get(offset))
                        .is_some_and(|commitment| {
                            FixedBytes::from(commitment.to_be_bytes::<32>())
                                == context.output_commitment
                        })
                })
    });
    let Some(row) = matching.next() else {
        return rows.is_empty() && saved_pending_context_is_compatible(context, list_keys);
    };
    matching.next().is_none()
        && !list_keys.is_empty()
        && list_keys.iter().all(|list_key| {
            context
                .pre_transaction_pois_per_txid_leaf_per_list
                .get(list_key)
                .is_some_and(|per_leaf| {
                    !per_leaf.is_empty()
                        && per_leaf.iter().all(|(leaf, poi)| {
                            let mut matching_rows = rows.iter().filter(|candidate| {
                                let transaction = &candidate.transaction;
                                let txid = broadcaster_core::transact::compute_railgun_txid_parts(
                                    &transaction.nullifiers,
                                    &transaction.commitments,
                                    transaction.bound_params_hash,
                                );
                                *leaf
                                    == FixedBytes::from(
                                        broadcaster_core::transact::railgun_txid_leaf_hash(
                                            txid,
                                            transaction.utxo_tree_in,
                                        )
                                        .to_be_bytes::<32>(),
                                    )
                                    || *leaf
                                        == FixedBytes::from(
                                            super::railgun_txid_leaf_hash_with_output_start(
                                                txid,
                                                transaction.utxo_tree_in,
                                                super::U256::from(
                                                    transaction.output_start_global(),
                                                ),
                                            )
                                            .to_be_bytes::<32>(),
                                        )
                            });
                            if let Some(exact) = matching_rows.next() {
                                matching_rows.next().is_none()
                                    && saved_poi_is_compatible(
                                        poi,
                                        Some((
                                            exact.transaction.nullifiers.len(),
                                            exact.transaction.commitments.len(),
                                        )),
                                    )
                            } else {
                                // The source context identifies this inner transaction even for locally
                                // retained maps whose leaf keys predate public observation.
                                saved_poi_is_compatible(
                                    poi,
                                    Some((
                                        row.transaction.nullifiers.len(),
                                        row.transaction.commitments.len(),
                                    )),
                                )
                            }
                        })
                })
        })
}
