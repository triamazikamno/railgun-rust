//! Qualifying a sender candidate against its public TXID rows and the wallet's UTXOs.

use std::collections::BTreeSet;

use crate::txid_cache::TxidPublicCacheTransaction;
use crate::types::PublicDataPlaneEpoch;
use crate::wallet::output_poi_recovery::{
    PublicCacheTxidRefreshRequest, refresh_public_txid_cache,
};
use crate::wallet::{
    FixedBytes, Note, OutputPoiRecoveryRequest, PublicTxidCacheKey, PublicTxidTransaction,
    SenderTransactionCandidate, SenderTransactionCandidateSpend, TREE_LEAF_COUNT,
    TxidPublicCacheError, U256, Utxo, UtxoCommitmentKind, WalletUtxo, debug, warn,
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
    let mut qualifier = SenderCandidateQualifier {
        candidate,
        wallet_utxos,
        scan_keys,
        qualified: Vec::new(),
        consumed_outputs: BTreeSet::new(),
        consumed_spends: BTreeSet::new(),
        qualified_nullifiers: BTreeSet::new(),
    };
    for row in rows {
        qualifier.add_row(row)?;
    }
    Ok(qualifier.finish())
}

/// The rows of one candidate qualified so far, and the wallet spends and candidate outputs they
/// consumed.
struct SenderCandidateQualifier<'q> {
    candidate: &'q SenderTransactionCandidate,
    wallet_utxos: &'q [WalletUtxo],
    scan_keys: &'q railgun_wallet::scan::WalletScanKeys,
    qualified: Vec<QualifiedSenderTransaction>,
    consumed_outputs: BTreeSet<(u32, u64, FixedBytes<32>)>,
    consumed_spends: BTreeSet<SenderTransactionCandidateSpend>,
    qualified_nullifiers: BTreeSet<U256>,
}

impl SenderCandidateQualifier<'_> {
    /// Qualify one public row. A row without wallet inputs is skipped; a row that does not match
    /// the candidate is an error.
    fn add_row(&mut self, row: PublicTxidTransaction) -> Result<(), ()> {
        match qualify_sender_row_inputs(self.candidate, self.wallet_utxos, self.scan_keys, &row)? {
            SenderRowQualification::Foreign => return Ok(()),
            SenderRowQualification::WalletAuthored => {}
        }
        let transaction = &row.transaction;
        if (transaction.transaction_hash, transaction.block_number)
            != (
                self.candidate.source.tx_hash,
                self.candidate.source.block_number,
            )
            || transaction.utxo_tree_in > u64::from(u32::MAX)
        {
            return Err(());
        }
        self.consume_inputs(transaction)?;
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
        let (outputs, output_notes) =
            self.consume_outputs(transaction, output_start_global, private_output_count)?;
        self.qualified.push(QualifiedSenderTransaction {
            txid_index: row.txid_index,
            public_row: row,
            output_start_global,
            outputs,
            output_notes,
        });
        Ok(())
    }

    /// Record the wallet spends of `transaction`. Each nullifier must be new to the candidate and
    /// belong to a wallet UTXO.
    fn consume_inputs(&mut self, transaction: &TxidPublicCacheTransaction) -> Result<(), ()> {
        for nullifier in &transaction.nullifiers {
            if !self.qualified_nullifiers.insert(*nullifier) {
                return Err(());
            }
            let input = self
                .wallet_utxos
                .iter()
                .find(|wallet_utxo| {
                    u64::from(wallet_utxo.utxo.tree) == transaction.utxo_tree_in
                        && wallet_utxo.utxo.nullifier(self.scan_keys.nullifying_key) == *nullifier
                })
                .ok_or(())?;
            self.consumed_spends
                .insert(SenderTransactionCandidateSpend {
                    tree: input.utxo.tree,
                    position: input.utxo.position,
                    commitment: input.utxo.poi.commitment,
                });
        }
        Ok(())
    }

    /// The UTXOs and notes of the first `private_output_count` commitments of `transaction`. Each
    /// must be a candidate output with a note, consumed at most once per candidate.
    fn consume_outputs(
        &mut self,
        transaction: &TxidPublicCacheTransaction,
        output_start_global: u128,
        private_output_count: usize,
    ) -> Result<(Vec<Utxo>, Vec<Note>), ()> {
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
            let output = self
                .candidate
                .outputs
                .iter()
                .find(|output| {
                    (output.tree, output.position, output.commitment)
                        == (tree, position, commitment)
                })
                .ok_or(())?;
            let note = output.note.clone().ok_or(())?;
            if !self.consumed_outputs.insert((tree, position, commitment)) {
                return Err(());
            }
            outputs.push(Utxo::new(
                note.clone(),
                tree,
                position,
                self.candidate.source.clone(),
                UtxoCommitmentKind::Transact,
            ));
            output_notes.push(note);
        }
        Ok((outputs, output_notes))
    }

    /// The qualified rows, or `None` when they do not cover every wallet spend and every output
    /// with a note.
    fn finish(self) -> Option<Vec<QualifiedSenderTransaction>> {
        let Self {
            candidate,
            qualified,
            consumed_outputs,
            consumed_spends,
            ..
        } = self;
        if qualified.is_empty() || consumed_spends.len() != candidate.wallet_spends.len() {
            return None;
        }
        if candidate
            .wallet_spends
            .iter()
            .any(|spend| !consumed_spends.contains(spend))
        {
            return None;
        }
        let uncovered_output = candidate.outputs.iter().any(|output| {
            output.note.is_some()
                && !consumed_outputs.contains(&(output.tree, output.position, output.commitment))
        });
        (!uncovered_output).then_some(qualified)
    }
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
