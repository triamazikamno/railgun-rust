use crate::chain::PendingOutputPoiSubmitIntent;

use super::{
    BlindedCommitmentData, CommitmentObservation, EVM_CHAIN_TYPE, FixedBytes,
    PendingOutputPoiContextRecord, PendingOutputPoiObservation, PendingOutputPoiRole, PoiStatus,
    PoiStatusReader, PublicPoiCorpusHandle, SingleCommitmentProofContext, WalletCacheError,
    WalletCacheStore, WalletConfig, WalletPrivateMutationAuthority, WalletPrivatePoiClients,
    WalletPrivateRemoteError, WalletPrivateRemoteStale, pending_output_poi_context_fingerprint,
    pending_output_poi_submit_identity, saved_pending_context_is_compatible,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct PendingOutputPoiTentativeAttemptKey {
    output_commitment: FixedBytes<32>,
    output_tree: u64,
    output_position: u64,
    tx_hash: FixedBytes<32>,
    list_keys: Vec<FixedBytes<32>>,
}

#[derive(Debug, Clone)]
pub(crate) struct PendingOutputPoiTentativeCandidate {
    output_commitment: FixedBytes<32>,
    observation: CommitmentObservation,
    list_keys: Vec<FixedBytes<32>>,
    derived_blinded_commitment: FixedBytes<32>,
    txid_version: String,
    expected_context_fingerprint: Vec<u8>,
}

impl PendingOutputPoiTentativeCandidate {
    pub(in crate::wallet) fn attempt_key(&self) -> PendingOutputPoiTentativeAttemptKey {
        PendingOutputPoiTentativeAttemptKey {
            output_commitment: self.output_commitment,
            output_tree: u64::from(self.observation.tree),
            output_position: self.observation.position,
            tx_hash: self.observation.source.tx_hash,
            list_keys: self.list_keys.clone(),
        }
    }

    pub(in crate::wallet) const fn output_commitment(&self) -> FixedBytes<32> {
        self.output_commitment
    }

    pub(in crate::wallet) const fn observation(&self) -> &CommitmentObservation {
        &self.observation
    }

    pub(in crate::wallet) fn list_keys(&self) -> &[FixedBytes<32>] {
        &self.list_keys
    }
}

#[cfg(test)]
impl PendingOutputPoiTentativeCandidate {
    pub(in crate::wallet) fn for_test() -> Self {
        Self {
            output_commitment: FixedBytes::from([0x11; 32]),
            observation: CommitmentObservation {
                tree: 1,
                position: 2,
                commitment: alloy::primitives::U256::from_be_bytes([0x11; 32]),
                source: railgun_wallet::UtxoSource {
                    tx_hash: FixedBytes::from([0x22; 32]),
                    block_number: 3,
                    block_timestamp: 4,
                },
            },
            list_keys: vec![FixedBytes::from([0x33; 32]), FixedBytes::from([0x34; 32])],
            derived_blinded_commitment: FixedBytes::ZERO,
            txid_version: super::super::DEFAULT_TXID_VERSION.to_string(),
            expected_context_fingerprint: vec![0x44],
        }
    }
}

#[derive(Debug, Default)]
pub(in crate::wallet) struct PendingOutputPoiTentativeSubmissionResult {
    pub(in crate::wallet) succeeded: Vec<PendingOutputPoiTentativeAttemptKey>,
    pub(in crate::wallet) accepted_candidates: Vec<PendingOutputPoiTentativeCandidate>,
    pub(in crate::wallet) retryable: Vec<PendingOutputPoiTentativeAttemptKey>,
    pub(in crate::wallet) accepted: usize,
    pub(in crate::wallet) missing_txid: usize,
    pub(in crate::wallet) remote_failure: usize,
    pub(in crate::wallet) context_stale: usize,
    pub(in crate::wallet) authority_stale: bool,
}

#[derive(Debug, Clone)]
pub(in crate::wallet) struct PendingOutputPoiTentativeLocalStatus {
    pub(in crate::wallet) candidate: PendingOutputPoiTentativeCandidate,
    pub(in crate::wallet) valid_list_keys: Vec<FixedBytes<32>>,
}

pub(in crate::wallet) async fn read_pending_output_poi_tentative_local_statuses(
    corpus: Option<&PublicPoiCorpusHandle>,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    candidates: &[PendingOutputPoiTentativeCandidate],
) -> Vec<PendingOutputPoiTentativeLocalStatus> {
    if corpus.is_none() || candidates.is_empty() || active_list_keys.is_empty() {
        return Vec::new();
    }
    let reader = corpus.expect("checked local POI corpus").status_reader();
    let mut visible = Vec::new();
    for candidate in candidates {
        let request = [BlindedCommitmentData::transact(
            candidate.derived_blinded_commitment,
        )];
        let Ok(statuses) = reader
            .pois_per_list(
                &candidate.txid_version,
                EVM_CHAIN_TYPE,
                cfg.chain.chain_id,
                &candidate.list_keys,
                &request,
            )
            .await
        else {
            continue;
        };
        let valid_list_keys = statuses
            .get(&candidate.derived_blinded_commitment)
            .into_iter()
            .flat_map(|statuses| {
                candidate.list_keys.iter().filter_map(|list_key| {
                    (statuses.get(list_key) == Some(&PoiStatus::Valid)).then_some(*list_key)
                })
            })
            .collect::<Vec<_>>();
        visible.push(PendingOutputPoiTentativeLocalStatus {
            candidate: candidate.clone(),
            valid_list_keys,
        });
    }
    visible
}

fn tentative_pending_output_poi_list_keys(
    record: &PendingOutputPoiContextRecord,
    active_list_keys: &[FixedBytes<32>],
) -> Vec<FixedBytes<32>> {
    record
        .list_keys()
        .into_iter()
        .filter(|list_key| {
            active_list_keys.contains(list_key)
                && record
                    .pre_transaction_pois_per_txid_leaf_per_list
                    .contains_key(list_key)
        })
        .collect()
}

fn tentative_pending_output_poi_context_matches(
    record: &PendingOutputPoiContextRecord,
    expected_context_fingerprint: &[u8],
    list_keys: &[FixedBytes<32>],
    active_list_keys: &[FixedBytes<32>],
) -> bool {
    pending_output_poi_context_fingerprint(record).as_deref() == Some(expected_context_fingerprint)
        && record.observation.is_none()
        && record.txid_merkleroot_index.is_none()
        && tentative_pending_output_poi_list_keys(record, active_list_keys) == list_keys
}

pub(in crate::wallet) fn prepare_pending_output_poi_tentative_candidates(
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    observations: &[CommitmentObservation],
) -> Result<Vec<PendingOutputPoiTentativeCandidate>, WalletCacheError> {
    let mut candidates = Vec::<PendingOutputPoiTentativeCandidate>::new();
    for observation in observations {
        let output_commitment = FixedBytes::from(observation.commitment.to_be_bytes::<32>());
        let Some(record) = cache_store.get_pending_output_poi_context(
            cfg.chain.chain_id,
            &cfg.cache_key,
            &output_commitment,
        )?
        else {
            continue;
        };
        if record.output_role == PendingOutputPoiRole::RecoveredOutgoing
            || record.txid_merkleroot_index.is_some()
            || record.observation.is_some()
        {
            continue;
        }
        let list_keys = tentative_pending_output_poi_list_keys(&record, active_list_keys);
        if list_keys.is_empty() || !saved_pending_context_is_compatible(&record, &list_keys) {
            continue;
        }
        let Some(expected_context_fingerprint) = pending_output_poi_context_fingerprint(&record)
        else {
            continue;
        };
        let Some(identity) = pending_output_poi_submit_identity(
            &record,
            &PendingOutputPoiObservation {
                output_tree: u64::from(observation.tree),
                output_position: observation.position,
                tx_hash: observation.source.tx_hash,
                block_number: observation.source.block_number,
                block_timestamp: observation.source.block_timestamp,
            },
        ) else {
            continue;
        };
        let candidate = PendingOutputPoiTentativeCandidate {
            output_commitment,
            observation: observation.clone(),
            list_keys,
            derived_blinded_commitment: identity.derived_blinded_commitment,
            txid_version: record.txid_version.clone(),
            expected_context_fingerprint,
        };
        if !candidates
            .iter()
            .any(|existing| existing.attempt_key() == candidate.attempt_key())
        {
            candidates.push(candidate);
        }
    }
    Ok(candidates)
}

pub(in crate::wallet) async fn submit_pending_output_poi_tentative_candidates(
    authority: &WalletPrivateMutationAuthority<'_>,
    cache_store: &dyn WalletCacheStore,
    cfg: &WalletConfig,
    active_list_keys: &[FixedBytes<32>],
    candidates: &[PendingOutputPoiTentativeCandidate],
    private_poi: &WalletPrivatePoiClients,
) -> PendingOutputPoiTentativeSubmissionResult {
    let mut result = PendingOutputPoiTentativeSubmissionResult::default();
    for (candidate_index, candidate) in candidates.iter().enumerate() {
        let key = candidate.attempt_key();
        if authority.revalidate().is_err() {
            result.authority_stale = true;
            result.retryable.extend(
                candidates[candidate_index..]
                    .iter()
                    .map(PendingOutputPoiTentativeCandidate::attempt_key),
            );
            break;
        }
        let Ok(Some(record)) = cache_store
            .get_pending_output_poi_context(
                cfg.chain.chain_id,
                &cfg.cache_key,
                &candidate.output_commitment,
            )
            .map(|record| {
                record.filter(|record| {
                    tentative_pending_output_poi_context_matches(
                        record,
                        &candidate.expected_context_fingerprint,
                        &candidate.list_keys,
                        active_list_keys,
                    )
                })
            })
        else {
            result.retryable.push(key);
            result.context_stale += 1;
            continue;
        };
        let context = SingleCommitmentProofContext {
            txid_version: record.txid_version.clone(),
            railgun_txid: record.railgun_txid,
            utxo_tree_in: record.utxo_tree_in,
            commitment: record.output_commitment,
            npk: record.output_npk,
            pre_transaction_pois_per_txid_leaf_per_list: record
                .retain_poi_lists(&candidate.list_keys),
        };
        let attempt = private_poi
            .submit_single_commitment_proofs(
                || async {
                    if authority.revalidate().is_err() {
                        return Ok::<bool, WalletCacheError>(false);
                    }
                    let current = cache_store.get_pending_output_poi_context(
                        cfg.chain.chain_id,
                        &cfg.cache_key,
                        &candidate.output_commitment,
                    )?;
                    Ok(current.is_some_and(|current| {
                        tentative_pending_output_poi_context_matches(
                            &current,
                            &candidate.expected_context_fingerprint,
                            &candidate.list_keys,
                            active_list_keys,
                        )
                    }))
                },
                PendingOutputPoiSubmitIntent::Tentative,
                &record.txid_version,
                EVM_CHAIN_TYPE,
                cfg.chain.chain_id,
                context,
                u64::from(candidate.observation.tree),
                candidate.observation.position,
            )
            .await;
        match attempt {
            Ok(()) => {
                result.succeeded.push(key);
                result.accepted_candidates.push(candidate.clone());
                result.accepted += 1;
            }
            Err(WalletPrivateRemoteError::Stale(WalletPrivateRemoteStale::Authority)) => {
                result.authority_stale = true;
                result.retryable.extend(
                    candidates[candidate_index..]
                        .iter()
                        .map(PendingOutputPoiTentativeCandidate::attempt_key),
                );
                break;
            }
            Err(
                WalletPrivateRemoteError::Stale(WalletPrivateRemoteStale::Subject)
                | WalletPrivateRemoteError::Check(_),
            ) => {
                result.retryable.push(key);
                result.context_stale += 1;
            }
            Err(WalletPrivateRemoteError::Remote(failure)) => {
                result.retryable.push(key);
                if failure.missing_txid {
                    result.missing_txid += 1;
                } else {
                    result.remote_failure += 1;
                }
            }
        }
    }
    result
}
