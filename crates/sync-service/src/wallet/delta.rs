use super::{
    BTreeMap, FixedBytes, HashMap, HashSet, Note, SenderScanOutput, U256, Utxo, UtxoSource,
    WalletConfig, WalletLogDelta, WalletPendingOverlay, WalletPendingSpent, WalletUtxo,
    decrypt_sender_note,
};

pub(crate) fn pending_overlay_from_delta(
    cfg: &WalletConfig,
    wallet_utxos: &[WalletUtxo],
    delta: WalletLogDelta,
) -> WalletPendingOverlay {
    let WalletLogDelta {
        utxos: delta_utxos,
        nullifiers,
        ..
    } = delta;
    let nullifier_sources: HashMap<_, _> = nullifiers
        .into_iter()
        .map(|spent| ((spent.tree, spent.nullifier), spent.source))
        .collect();

    let mut pending_spent = wallet_utxos
        .iter()
        .filter(|entry| !entry.is_spent())
        .filter_map(|entry| {
            spent_source_for_utxo(
                &entry.utxo,
                cfg.scan_keys.nullifying_key,
                &nullifier_sources,
            )
            .map(|source| WalletPendingSpent::from_source(&entry.utxo, &source))
        })
        .collect::<Vec<_>>();
    pending_spent.sort_by_key(WalletPendingSpent::key);

    let mut existing: HashSet<_> = wallet_utxos
        .iter()
        .map(|wallet_utxo| (wallet_utxo.utxo.tree, wallet_utxo.utxo.position))
        .collect();
    let mut new_utxos = Vec::new();
    for utxo in delta_utxos {
        if existing.insert((utxo.tree, utxo.position)) {
            let spent =
                spent_source_for_utxo(&utxo, cfg.scan_keys.nullifying_key, &nullifier_sources);
            new_utxos.push(WalletUtxo { utxo, spent });
        }
    }
    new_utxos.sort_by_key(|wallet_utxo| (wallet_utxo.utxo.tree, wallet_utxo.utxo.position));

    WalletPendingOverlay {
        new_utxos,
        pending_spent,
        local_pending_spent: Vec::new(),
    }
}

pub(super) fn apply_wallet_delta_to_vec_with_outcome(
    cfg: &WalletConfig,
    wallet_utxos: &mut Vec<WalletUtxo>,
    delta: WalletLogDelta,
) -> WalletDeltaApplyOutcome {
    let WalletLogDelta {
        utxos: new_utxos,
        nullifiers,
        sender_scan_outputs,
        ..
    } = delta;
    let nullifier_sources: HashMap<_, _> = nullifiers
        .into_iter()
        .map(|spent| ((spent.tree, spent.nullifier), spent.source))
        .collect();
    let mut changed = false;
    let mut spent_output_commitments = Vec::new();
    if !nullifier_sources.is_empty() {
        for wallet_utxo in wallet_utxos.iter_mut().filter(|entry| !entry.is_spent()) {
            if let Some(source) = spent_source_for_utxo(
                &wallet_utxo.utxo,
                cfg.scan_keys.nullifying_key,
                &nullifier_sources,
            ) {
                wallet_utxo.spent = Some(source);
                spent_output_commitments.push(wallet_utxo.utxo.poi.commitment);
                changed = true;
            }
        }
    }

    let mut existing: HashSet<_> = wallet_utxos
        .iter()
        .map(|wallet_utxo| (wallet_utxo.utxo.tree, wallet_utxo.utxo.position))
        .collect();
    for utxo in new_utxos {
        if existing.insert((utxo.tree, utxo.position)) {
            let spent =
                spent_source_for_utxo(&utxo, cfg.scan_keys.nullifying_key, &nullifier_sources);
            if spent.is_some() {
                spent_output_commitments.push(utxo.poi.commitment);
            }
            wallet_utxos.push(WalletUtxo { utxo, spent });
            changed = true;
        }
    }

    let before_dedupe = wallet_utxos.len();
    super::worker::dedupe_wallet_utxos(wallet_utxos);
    let sender_scan_candidates = sender_scan_candidate_inputs(
        wallet_utxos,
        cfg.scan_keys.nullifying_key,
        &nullifier_sources,
        sender_scan_outputs,
        &cfg.scan_keys,
    );
    WalletDeltaApplyOutcome {
        changed: changed || wallet_utxos.len() != before_dedupe,
        spent_output_commitments,
        sender_scan_candidates,
    }
}

pub(crate) fn rewind_wallet_utxos(
    wallet_utxos: &mut Vec<WalletUtxo>,
    from_block: u64,
) -> WalletRewindOutcome {
    let before_len = wallet_utxos.len();
    let mut removed_output_commitments = Vec::new();
    wallet_utxos.retain(|wallet_utxo| {
        if wallet_utxo.utxo.source.block_number < from_block {
            true
        } else {
            removed_output_commitments.push(wallet_utxo.utxo.poi.commitment);
            false
        }
    });
    let mut changed = wallet_utxos.len() != before_len;

    for wallet_utxo in wallet_utxos {
        if wallet_utxo
            .spent
            .as_ref()
            .is_some_and(|spent| spent.block_number >= from_block)
        {
            wallet_utxo.spent = None;
            changed = true;
        }
    }

    WalletRewindOutcome {
        changed,
        removed_output_commitments,
    }
}

#[derive(Debug, Default)]
pub(crate) struct WalletRewindOutcome {
    pub(crate) changed: bool,
    pub(crate) removed_output_commitments: Vec<FixedBytes<32>>,
}

#[derive(Default)]
pub(super) struct WalletDeltaApplyOutcome {
    pub(super) changed: bool,
    pub(super) spent_output_commitments: Vec<FixedBytes<32>>,
    pub(super) sender_scan_candidates: Vec<SenderScanCandidateInput>,
}

pub(super) struct SenderScanCandidateInput {
    pub(super) source: UtxoSource,
    pub(super) wallet_spends: Vec<SenderScanWalletSpend>,
    pub(super) outputs: Vec<SenderScanCandidateOutput>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SenderScanWalletSpend {
    pub(super) tree: u32,
    pub(super) position: u64,
    pub(super) commitment: FixedBytes<32>,
}

pub(super) struct SenderScanCandidateOutput {
    pub(super) tree: u32,
    pub(super) position: u64,
    pub(super) commitment: FixedBytes<32>,
    pub(super) note: Option<Note>,
}

impl SenderScanCandidateInput {
    pub(super) fn into_record(
        self,
        chain_id: u64,
        wallet_id: local_db::WalletCacheKey,
    ) -> Result<crate::SenderTransactionCandidate, crate::SenderTransactionCandidateError> {
        crate::SenderTransactionCandidate::new(
            chain_id,
            wallet_id,
            self.source,
            self.wallet_spends
                .into_iter()
                .map(|spend| crate::SenderTransactionCandidateSpend {
                    tree: spend.tree,
                    position: spend.position,
                    commitment: spend.commitment,
                })
                .collect(),
            self.outputs
                .into_iter()
                .map(|output| crate::SenderTransactionCandidateOutput {
                    tree: output.tree,
                    position: output.position,
                    commitment: output.commitment,
                    note: output.note,
                })
                .collect(),
        )
    }
}

pub(super) fn sender_scan_candidate_inputs(
    wallet_utxos: &[WalletUtxo],
    nullifying_key: U256,
    nullifier_sources: &HashMap<(u32, U256), UtxoSource>,
    sender_scan_outputs: Vec<SenderScanOutput>,
    scan_keys: &railgun_wallet::scan::WalletScanKeys,
) -> Vec<SenderScanCandidateInput> {
    let mut spends_by_tx =
        BTreeMap::<FixedBytes<32>, (UtxoSource, Vec<SenderScanWalletSpend>)>::new();
    for wallet_utxo in wallet_utxos {
        let key = (
            wallet_utxo.utxo.tree,
            wallet_utxo.utxo.nullifier(nullifying_key),
        );
        let Some(source) = nullifier_sources.get(&key) else {
            continue;
        };
        spends_by_tx
            .entry(source.tx_hash)
            .or_insert_with(|| (source.clone(), Vec::new()))
            .1
            .push(SenderScanWalletSpend {
                tree: wallet_utxo.utxo.tree,
                position: wallet_utxo.utxo.position,
                commitment: wallet_utxo.utxo.poi.commitment,
            });
    }
    for (_, spends) in spends_by_tx.values_mut() {
        spends.sort_by_key(|spend| (spend.tree, spend.position, spend.commitment));
        spends.dedup();
    }

    let mut outputs_by_tx = BTreeMap::<FixedBytes<32>, Vec<SenderScanOutput>>::new();
    for output in sender_scan_outputs {
        if spends_by_tx.contains_key(&output.source.tx_hash) {
            outputs_by_tx
                .entry(output.source.tx_hash)
                .or_default()
                .push(output);
        }
    }

    spends_by_tx
        .into_iter()
        .map(|(tx_hash, (source, wallet_spends))| {
            let mut outputs = outputs_by_tx.remove(&tx_hash).unwrap_or_default();
            outputs.sort_by_key(|output| (output.tree, output.position, output.commitment));
            let outputs = outputs
                .into_iter()
                .map(|output| SenderScanCandidateOutput {
                    tree: output.tree,
                    position: output.position,
                    commitment: FixedBytes::from(output.commitment.to_be_bytes::<32>()),
                    note: decrypt_sender_note(&output.ciphertext, output.commitment, scan_keys),
                })
                .collect::<Vec<_>>();
            SenderScanCandidateInput {
                source,
                wallet_spends,
                outputs,
            }
        })
        .collect()
}

pub(super) fn spent_source_for_utxo(
    utxo: &Utxo,
    nullifying_key: U256,
    nullifier_sources: &HashMap<(u32, U256), UtxoSource>,
) -> Option<UtxoSource> {
    nullifier_sources
        .get(&(utxo.tree, utxo.nullifier(nullifying_key)))
        .cloned()
}

pub(super) fn chain_pending_overlay_matches(
    current: &WalletPendingOverlay,
    next: &WalletPendingOverlay,
) -> bool {
    current.pending_spent == next.pending_spent
        && wallet_utxo_keys_match(&current.new_utxos, &next.new_utxos)
}

pub(super) fn wallet_utxo_keys_match(left: &[WalletUtxo], right: &[WalletUtxo]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            left.utxo.tree == right.utxo.tree
                && left.utxo.position == right.utxo.position
                && left.utxo.poi.commitment == right.utxo.poi.commitment
                && left.spent.as_ref().map(|source| source.tx_hash)
                    == right.spent.as_ref().map(|source| source.tx_hash)
                && left.spent.as_ref().map(|source| source.block_number)
                    == right.spent.as_ref().map(|source| source.block_number)
        })
}

#[cfg(test)]
mod sender_scan_tests;

#[cfg(test)]
pub(in crate::wallet) mod test_support;
