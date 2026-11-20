#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) fn output_poi_statuses_are_recoverable_for_lists(
    poi: &UtxoPoiMetadata,
    list_keys: &[FixedBytes<32>],
) -> bool {
    list_keys.iter().all(|list_key| {
        poi.statuses
            .get(list_key)
            .is_none_or(|status| status.is_recoverable())
    })
}

pub(in crate::wallet) fn poi_shield_blocked_on_any_list(
    poi: &UtxoPoiMetadata,
    active_list_keys: &[FixedBytes<32>],
) -> bool {
    active_list_keys
        .iter()
        .any(|list_key| poi.statuses.get(list_key) == Some(&PoiStatus::ShieldBlocked))
}

pub(in crate::wallet) fn recoverable_output_poi_list_keys(
    poi: &UtxoPoiMetadata,
    active_list_keys: &[FixedBytes<32>],
) -> Vec<FixedBytes<32>> {
    active_list_keys
        .iter()
        .copied()
        .filter(|list_key| {
            poi.statuses
                .get(list_key)
                .is_none_or(|status| status.is_recoverable())
        })
        .collect()
}

pub(in crate::wallet) fn matching_pending_output_poi_context_disposition(
    context: &PendingOutputPoiContextRecord,
    recoverable_list_keys: &[FixedBytes<32>],
    force_retry: bool,
) -> MatchingPendingOutputPoiContextDisposition {
    if !saved_pending_context_is_compatible(context, &context.list_keys()) {
        return MatchingPendingOutputPoiContextDisposition::Regenerate;
    }
    if context.terminal_error.is_some() {
        return if force_retry {
            MatchingPendingOutputPoiContextDisposition::Regenerate
        } else {
            MatchingPendingOutputPoiContextDisposition::Skip
        };
    }
    let new_list_keys = newly_recoverable_output_poi_list_keys(context, recoverable_list_keys);
    if new_list_keys.is_empty() {
        MatchingPendingOutputPoiContextDisposition::Skip
    } else {
        MatchingPendingOutputPoiContextDisposition::Extend(new_list_keys)
    }
}

pub(in crate::wallet) fn output_poi_recovery_retry_allowed_for_lists(
    record: &OutputPoiRecoveryRecord,
    now: u64,
    force_retry: bool,
    recoverable_list_keys: &[FixedBytes<32>],
) -> bool {
    !recoverable_list_keys.is_empty()
        && (record.status == OutputPoiRecoveryStatus::Valid
            || record.retry_allowed(now, force_retry))
}

pub(super) fn output_poi_recovery_source_matches_candidate(
    record: Option<&OutputPoiRecoveryRecord>,
    candidate: &WalletUtxo,
) -> bool {
    record.is_none_or(|record| record.source_tx_hash == candidate.utxo.source.tx_hash)
}

impl<'a> WalletNullifierIndex<'a> {
    pub(in crate::wallet) fn new(
        wallet_utxos: &'a [WalletUtxo],
        scan_keys: &railgun_wallet::scan::WalletScanKeys,
    ) -> Self {
        let mut by_tree_nullifier = HashMap::with_capacity(wallet_utxos.len());
        for (index, wallet_utxo) in wallet_utxos.iter().enumerate() {
            if wallet_utxo.spent.is_some() {
                by_tree_nullifier.insert(
                    (
                        wallet_utxo.utxo.tree,
                        wallet_utxo.utxo.nullifier(scan_keys.nullifying_key),
                    ),
                    index,
                );
            }
        }
        Self {
            wallet_utxos,
            by_tree_nullifier,
        }
    }

    pub(in crate::wallet) fn input_for(
        &self,
        input_tree: u32,
        nullifier: U256,
        source_tx_hash: FixedBytes<32>,
    ) -> Option<&'a WalletUtxo> {
        let index = self.by_tree_nullifier.get(&(input_tree, nullifier))?;
        let wallet_utxo = self.wallet_utxos.get(*index)?;
        wallet_utxo
            .spent
            .as_ref()
            .is_some_and(|spent| spent.tx_hash == source_tx_hash)
            .then_some(wallet_utxo)
    }
}

pub(in crate::wallet) const fn output_poi_recovery_proof_retry_after(
    err: &PreTransactionPoiError,
) -> Duration {
    match err {
        PreTransactionPoiError::Prover(
            ProverError::WorkerPanic(_) | ProverError::WorkerDropped | ProverError::QueueClosed,
        ) => OUTPUT_POI_RECOVERY_PROOF_FAILURE_RETRY_AFTER,
        _ => OUTPUT_POI_RECOVERY_TRANSIENT_RETRY_AFTER,
    }
}

pub(in crate::wallet) fn output_poi_recovery_candidates<'a>(
    wallet_utxos: &'a [WalletUtxo],
    active_list_keys: &[FixedBytes<32>],
) -> Vec<&'a WalletUtxo> {
    wallet_utxos
        .iter()
        .filter(|wallet_utxo| {
            !wallet_utxo.is_spent()
                && wallet_utxo.utxo.poi.commitment_kind == UtxoCommitmentKind::Transact
                && wallet_utxo
                    .utxo
                    .poi
                    .has_recoverable_status_for_lists(active_list_keys)
        })
        .collect()
}
