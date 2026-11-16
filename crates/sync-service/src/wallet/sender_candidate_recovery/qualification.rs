//! Qualifying a sender candidate against its public TXID rows and the wallet's UTXOs.

use std::collections::BTreeSet;

use crate::types::PublicDataPlaneEpoch;
use crate::wallet::output_poi_recovery::{
    PublicCacheTxidRefreshRequest, refresh_public_txid_cache,
};
use crate::wallet::{
    FixedBytes, OutputPoiRecoveryRequest, PublicTxidCacheKey, PublicTxidTransaction,
    SenderTransactionCandidate, SenderTransactionCandidateSpend, TREE_LEAF_COUNT,
    TxidPublicCacheError, Utxo, UtxoCommitmentKind, WalletUtxo, debug, warn,
};

use super::{
    QualifiedSenderTransaction, SenderCandidatePublicDataFence, SenderCandidateRecoveryReport,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SenderRowQualification {
    Foreign,
    WalletAuthored,
}

async fn refresh_sender_candidate_public_txid_cache(
    request: &OutputPoiRecoveryRequest<'_>,
    cache_key: &PublicTxidCacheKey,
    refreshed: &mut Option<bool>,
) -> bool {
    if let Some(refreshed) = *refreshed {
        refreshed
    } else {
        let result = refresh_public_txid_cache(PublicCacheTxidRefreshRequest {
            public_data_plane: request.public_data_plane,
            cfg: request.cfg,
            poi_client: request.poi_client,
            http_client: request.http_client,
            indexed_artifact_source: request.indexed_artifact_source,
            cache_key: cache_key.clone(),
        })
        .await
        .is_ok();
        *refreshed = Some(result);
        result
    }
}

pub(super) struct QualifiedSenderCandidate {
    pub(super) qualified: Vec<QualifiedSenderTransaction>,
    pub(super) public_data_fence: SenderCandidatePublicDataFence,
    pub(super) data_epoch: PublicDataPlaneEpoch,
}

/// Why public rows do not yet qualify a candidate; each maps to one report category.
#[derive(Debug, Clone, Copy)]
pub(super) enum SenderCandidateQualificationPending {
    AwaitingPublicTxidData,
    Retrying,
    NeedsAttention,
}

impl SenderCandidateQualificationPending {
    pub(super) const fn record(self, report: &mut SenderCandidateRecoveryReport, count: u64) {
        let counter = match self {
            Self::AwaitingPublicTxidData => &mut report.awaiting_public_txid_data,
            Self::Retrying => &mut report.retrying,
            Self::NeedsAttention => &mut report.needs_attention,
        };
        *counter = counter.saturating_add(count);
    }
}

pub(super) async fn qualify_sender_candidate_from_public_rows(
    request: &OutputPoiRecoveryRequest<'_>,
    candidate: &SenderTransactionCandidate,
    cache_key: &PublicTxidCacheKey,
    refreshed: &mut Option<bool>,
) -> Result<QualifiedSenderCandidate, SenderCandidateQualificationPending> {
    let mut data_epoch = request.public_data_plane.current_epoch();
    let mut rows = request
        .public_data_plane
        .txid_transactions_for_outer_hash_with_authority(cache_key, candidate.source.tx_hash);
    if matches!(&rows, Ok((rows, _)) if rows.is_empty())
        || matches!(&rows, Err(TxidPublicCacheError::CacheNotReady { .. }))
    {
        if !refresh_sender_candidate_public_txid_cache(request, cache_key, refreshed).await {
            return Err(SenderCandidateQualificationPending::Retrying);
        }
        data_epoch = request.public_data_plane.current_epoch();
        rows = request
            .public_data_plane
            .txid_transactions_for_outer_hash_with_authority(cache_key, candidate.source.tx_hash);
    }
    let (mut rows, mut authority) = match rows {
        Ok((rows, _authority)) if rows.is_empty() => {
            return Err(SenderCandidateQualificationPending::AwaitingPublicTxidData);
        }
        Ok((rows, authority)) => (rows, authority),
        Err(TxidPublicCacheError::CacheNotReady { .. }) => {
            return Err(SenderCandidateQualificationPending::AwaitingPublicTxidData);
        }
        Err(_) => return Err(SenderCandidateQualificationPending::Retrying),
    };
    let mut qualification = qualify_sender_candidate(
        candidate,
        request.wallet_utxos,
        &request.cfg.scan_keys,
        rows.clone(),
    );
    if matches!(qualification, Ok(None)) && refreshed.is_none() {
        if !refresh_sender_candidate_public_txid_cache(request, cache_key, refreshed).await {
            return Err(SenderCandidateQualificationPending::Retrying);
        }
        data_epoch = request.public_data_plane.current_epoch();
        (rows, authority) = match request
            .public_data_plane
            .txid_transactions_for_outer_hash_with_authority(cache_key, candidate.source.tx_hash)
        {
            Ok((rows, authority)) if !rows.is_empty() => (rows, authority),
            Ok(_) | Err(TxidPublicCacheError::CacheNotReady { .. }) => {
                return Err(SenderCandidateQualificationPending::AwaitingPublicTxidData);
            }
            Err(_) => return Err(SenderCandidateQualificationPending::Retrying),
        };
        qualification = qualify_sender_candidate(
            candidate,
            request.wallet_utxos,
            &request.cfg.scan_keys,
            rows.clone(),
        );
    }
    let qualified = match qualification {
        Ok(Some(qualified)) => qualified,
        Ok(None) => {
            debug!(
                chain_id = request.cfg.chain.chain_id,
                category = "public_rows_do_not_cover_candidate",
                "sender candidate recovery qualification incomplete"
            );
            return Err(SenderCandidateQualificationPending::AwaitingPublicTxidData);
        }
        Err(()) => {
            warn!(
                chain_id = request.cfg.chain.chain_id,
                category = "candidate_shape_or_wallet_association_mismatch",
                "sender candidate recovery qualification failed"
            );
            return Err(SenderCandidateQualificationPending::NeedsAttention);
        }
    };
    Ok(QualifiedSenderCandidate {
        qualified,
        public_data_fence: SenderCandidatePublicDataFence::new(
            request.public_data_plane,
            cache_key.clone(),
            data_epoch,
            rows,
            authority,
        ),
        data_epoch,
    })
}

pub(super) fn qualify_sender_candidate(
    candidate: &SenderTransactionCandidate,
    wallet_utxos: &[WalletUtxo],
    scan_keys: &railgun_wallet::scan::WalletScanKeys,
    rows: Vec<PublicTxidTransaction>,
) -> Result<Option<Vec<QualifiedSenderTransaction>>, ()> {
    if candidate.validate().is_err() || rows.is_empty() {
        return Ok(None);
    }
    let mut qualified = Vec::new();
    let mut consumed_outputs = BTreeSet::new();
    let mut consumed_spends = BTreeSet::new();
    let mut qualified_nullifiers = BTreeSet::new();
    for row in rows {
        match qualify_sender_row_inputs(candidate, wallet_utxos, scan_keys, &row)? {
            SenderRowQualification::Foreign => continue,
            SenderRowQualification::WalletAuthored => {}
        }
        let transaction = &row.transaction;
        if transaction.transaction_hash != candidate.source.tx_hash
            || transaction.block_number != candidate.source.block_number
            || transaction.utxo_tree_in > u64::from(u32::MAX)
        {
            return Err(());
        }
        for nullifier in &transaction.nullifiers {
            if !qualified_nullifiers.insert(*nullifier) {
                return Err(());
            }
            let input = wallet_utxos
                .iter()
                .find(|wallet_utxo| {
                    u64::from(wallet_utxo.utxo.tree) == transaction.utxo_tree_in
                        && wallet_utxo.utxo.nullifier(scan_keys.nullifying_key) == *nullifier
                })
                .ok_or(())?;
            consumed_spends.insert(SenderTransactionCandidateSpend {
                tree: input.utxo.tree,
                position: input.utxo.position,
                commitment: input.utxo.poi.commitment,
            });
        }
        let private_output_count = transaction
            .commitments
            .len()
            .checked_sub(usize::from(transaction.has_unshield))
            .ok_or(())?;
        // A row with no private outputs qualifies only for its unshield.
        if private_output_count == 0 && !transaction.has_unshield {
            return Err(());
        }
        let output_start_global = transaction.output_start_global();
        let mut outputs = Vec::with_capacity(private_output_count);
        let mut output_notes = Vec::with_capacity(private_output_count);
        for (offset, commitment) in transaction
            .commitments
            .iter()
            .take(private_output_count)
            .enumerate()
        {
            let global = output_start_global
                .checked_add(u128::try_from(offset).map_err(|_| ())?)
                .ok_or(())?;
            let tree = u32::try_from(global / u128::from(TREE_LEAF_COUNT)).map_err(|_| ())?;
            let position = u64::try_from(global % u128::from(TREE_LEAF_COUNT)).map_err(|_| ())?;
            let commitment = FixedBytes::from(commitment.to_be_bytes::<32>());
            let output = candidate
                .outputs
                .iter()
                .find(|output| {
                    output.tree == tree
                        && output.position == position
                        && output.commitment == commitment
                })
                .ok_or(())?;
            let note = output.note.clone().ok_or(())?;
            if !consumed_outputs.insert((tree, position, commitment)) {
                return Err(());
            }
            outputs.push(Utxo::new(
                note.clone(),
                tree,
                position,
                candidate.source.clone(),
                UtxoCommitmentKind::Transact,
            ));
            output_notes.push(note);
        }
        qualified.push(QualifiedSenderTransaction {
            txid_index: row.txid_index,
            public_row: row,
            output_start_global,
            outputs,
            output_notes,
        });
    }
    if qualified.is_empty()
        || consumed_spends.len() != candidate.wallet_spends.len()
        || candidate
            .wallet_spends
            .iter()
            .any(|spend| !consumed_spends.contains(spend))
        || candidate.outputs.iter().any(|output| {
            output.note.is_some()
                && !consumed_outputs.contains(&(output.tree, output.position, output.commitment))
        })
    {
        return Ok(None);
    }
    Ok(Some(qualified))
}

pub(super) fn qualify_sender_row_inputs(
    candidate: &SenderTransactionCandidate,
    wallet_utxos: &[WalletUtxo],
    scan_keys: &railgun_wallet::scan::WalletScanKeys,
    row: &PublicTxidTransaction,
) -> Result<SenderRowQualification, ()> {
    let input_tree = u32::try_from(row.transaction.utxo_tree_in).map_err(|_| ())?;
    let mut nullifiers = BTreeSet::new();
    let mut resolved = 0;
    for nullifier in &row.transaction.nullifiers {
        if !nullifiers.insert(*nullifier) {
            return Err(());
        }
        let matches = wallet_utxos
            .iter()
            .filter(|wallet_utxo| {
                wallet_utxo.utxo.tree == input_tree
                    && wallet_utxo.utxo.nullifier(scan_keys.nullifying_key) == *nullifier
            })
            .collect::<Vec<_>>();
        if matches.is_empty() {
            continue;
        }
        if matches.len() != 1 {
            return Err(());
        }
        let wallet_utxo = matches[0];
        if wallet_utxo.spent.as_ref() != Some(&candidate.source)
            || !candidate
                .wallet_spends
                .contains(&SenderTransactionCandidateSpend {
                    tree: wallet_utxo.utxo.tree,
                    position: wallet_utxo.utxo.position,
                    commitment: wallet_utxo.utxo.poi.commitment,
                })
        {
            return Err(());
        }
        resolved += 1;
    }
    if resolved == 0 {
        Ok(SenderRowQualification::Foreign)
    } else if resolved == row.transaction.nullifiers.len() && resolved > 0 {
        Ok(SenderRowQualification::WalletAuthored)
    } else {
        Err(())
    }
}
