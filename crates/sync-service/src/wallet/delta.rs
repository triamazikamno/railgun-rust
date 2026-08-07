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

    outputs_by_tx
        .into_iter()
        .filter_map(|(tx_hash, mut outputs)| {
            let (source, wallet_spends) = spends_by_tx.remove(&tx_hash)?;
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
            if !outputs.iter().any(|output| output.note.is_some()) {
                return None;
            }
            Some(SenderScanCandidateInput {
                source,
                wallet_spends,
                outputs,
            })
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
mod sender_scan_tests {
    use alloy::hex;
    use alloy::primitives::{Address, FixedBytes, U256};
    use alloy::sol_types::SolEvent;
    use alloy_rpc_types_eth::Log;
    use broadcaster_core::contracts::railgun::{CommitmentCiphertext, Transact};
    use broadcaster_core::crypto::railgun::ViewingKeyData;
    use broadcaster_core::tree::TREE_LEAF_COUNT;
    use merkletree::quick::IndexedTransactCommitment;
    use railgun_wallet::scan::{
        IndexedTransactCommitmentInput, SenderScanOutput, parse_indexed_wallet_delta,
        parse_wallet_delta_from_logs,
    };
    use railgun_wallet::{Note, NoteCiphertext, Utxo, UtxoCommitmentKind, UtxoSource, WalletUtxo};

    use super::sender_scan_candidate_inputs;

    fn source(byte: u8) -> UtxoSource {
        UtxoSource {
            tx_hash: FixedBytes::from([byte; 32]),
            block_number: u64::from(byte),
            block_timestamp: 1_700_000_000 + u64::from(byte),
        }
    }

    fn sender_output(
        keys: &ViewingKeyData,
        receiver: &ViewingKeyData,
        position: u64,
        value: u64,
        source: UtxoSource,
    ) -> SenderScanOutput {
        let note = Note::new_change(
            receiver.master_public_key,
            Address::ZERO,
            U256::from(value),
            [value as u8; 16],
        );
        let ciphertext: CommitmentCiphertext = NoteCiphertext::try_from_note(
            &note,
            &keys.address_data(),
            &receiver.address_data(),
            &keys.viewing_private_key,
        )
        .expect("encrypt sender output")
        .into();
        SenderScanOutput {
            tree: 3,
            position,
            commitment: note.commitment(),
            ciphertext,
            source,
        }
    }

    #[test]
    fn sender_selection_emits_one_ordered_candidate_for_exact_wallet_spend() {
        let keys =
            ViewingKeyData::from_spending_public_key([7; 32], [U256::from(11), U256::from(12)]);
        let receiver =
            ViewingKeyData::from_spending_public_key([9; 32], [U256::from(13), U256::from(14)]);
        let wallet_note = Note::new_change(
            keys.master_public_key,
            Address::ZERO,
            U256::from(50),
            [1; 16],
        );
        let wallet_utxo = WalletUtxo::new(Utxo::new(
            wallet_note,
            2,
            7,
            source(1),
            UtxoCommitmentKind::Transact,
        ));
        let matching_source = source(8);
        let unrelated_source = source(9);
        let nullifier_sources = std::collections::HashMap::from([(
            (2, wallet_utxo.utxo.nullifier(keys.nullifying_key)),
            matching_source.clone(),
        )]);
        let mut unavailable = sender_output(&keys, &receiver, 11, 20, matching_source.clone());
        unavailable.ciphertext.blindedReceiverViewingKey = FixedBytes::ZERO;
        let outputs = vec![
            unavailable,
            sender_output(&keys, &receiver, 10, 30, matching_source.clone()),
            sender_output(&keys, &receiver, 12, 40, unrelated_source),
        ];

        let mut candidates = sender_scan_candidate_inputs(
            &[wallet_utxo],
            keys.nullifying_key,
            &nullifier_sources,
            outputs,
            &keys,
        );

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].source, matching_source);
        assert_eq!(candidates[0].wallet_spends.len(), 1);
        assert_eq!(candidates[0].wallet_spends[0].key(), (2, 7));
        assert_eq!(
            candidates[0]
                .outputs
                .iter()
                .map(|output| output.position)
                .collect::<Vec<_>>(),
            vec![10, 11]
        );
        assert!(candidates[0].outputs[0].note.is_some());
        assert!(candidates[0].outputs[1].note.is_none());
        let record = candidates
            .remove(0)
            .into_record(
                1,
                local_db::WalletCacheKey::from_opaque_bytes(b"sender-scan-wallet")
                    .expect("wallet key"),
            )
            .expect("convert candidate record");
        assert_eq!(record.semantic_id(), matching_source.tx_hash);
        assert_eq!(record.outputs.len(), 2);
    }

    #[test]
    fn rpc_and_indexed_sender_candidates_are_identical() {
        let keys =
            ViewingKeyData::from_spending_public_key([7; 32], [U256::from(11), U256::from(12)]);
        let receiver =
            ViewingKeyData::from_spending_public_key([9; 32], [U256::from(13), U256::from(14)]);
        let note = Note::new_change(
            receiver.master_public_key,
            Address::ZERO,
            U256::from(30),
            [0x33; 16],
        );
        let ciphertext: CommitmentCiphertext = NoteCiphertext::try_from_note(
            &note,
            &keys.address_data(),
            &receiver.address_data(),
            &keys.viewing_private_key,
        )
        .expect("encrypt sender output")
        .into();
        let tree = 2_u32;
        let position = TREE_LEAF_COUNT + 3;
        let tx_hash = FixedBytes::from([0x44; 32]);
        let block_number = 105_u64;
        let block_timestamp = 1_700_000_105_u64;
        let encoded = Transact {
            treeNumber: U256::from(tree),
            startPosition: U256::from(position),
            hash: vec![FixedBytes::from(note.commitment().to_be_bytes::<32>())],
            ciphertext: vec![ciphertext.clone()],
        }
        .encode_log_data();
        let rpc_log: Log = serde_json::from_value(serde_json::json!({
            "address": format!("{:#x}", Address::from([0xaa; 20])),
            "topics": encoded.topics().iter().map(|topic| format!("{topic:#x}")).collect::<Vec<_>>(),
            "data": format!("0x{}", hex::encode(encoded.data)),
            "blockHash": format!("{:#x}", FixedBytes::<32>::from([0xbb; 32])),
            "blockNumber": format!("0x{block_number:x}"),
            "transactionHash": format!("{tx_hash:#x}"),
            "transactionIndex": "0x0",
            "logIndex": "0x0",
            "removed": false,
        }))
        .expect("deserialize RPC log");
        let rpc_delta = parse_wallet_delta_from_logs(
            &[rpc_log],
            &std::collections::HashMap::from([(block_number, block_timestamp)]),
            &keys,
        )
        .expect("parse RPC delta");

        let iv_tag = ciphertext.ciphertext[0].as_slice();
        let indexed: IndexedTransactCommitment = serde_json::from_value(serde_json::json!({
            "id": "0x01",
            "transactionHash": format!("{tx_hash:#x}"),
            "blockNumber": format!("0x{block_number:x}"),
            "blockTimestamp": format!("0x{block_timestamp:x}"),
            "treeNumber": format!("0x{tree:x}"),
            "treePosition": format!("0x{position:x}"),
            "hash": format!("{:#x}", note.commitment()),
            "ciphertext": {
                "ciphertext": {
                    "iv": format!("0x{}", hex::encode(&iv_tag[..16])),
                    "tag": format!("0x{}", hex::encode(&iv_tag[16..])),
                    "data": ciphertext.ciphertext[1..]
                        .iter()
                        .map(|part| format!("{part:#x}"))
                        .collect::<Vec<_>>(),
                },
                "blindedSenderViewingKey": format!("{:#x}", ciphertext.blindedSenderViewingKey),
                "blindedReceiverViewingKey": format!("{:#x}", ciphertext.blindedReceiverViewingKey),
                "annotationData": format!("0x{}", hex::encode(&ciphertext.annotationData)),
                "memo": format!("0x{}", hex::encode(&ciphertext.memo)),
            },
        }))
        .expect("deserialize normalized indexed row");
        let indexed_delta = parse_indexed_wallet_delta(
            &[IndexedTransactCommitmentInput::from(indexed)],
            &[],
            &[],
            &[],
            &[],
            &keys,
        );

        let rpc_output = &rpc_delta.sender_scan_outputs[0];
        let indexed_output = &indexed_delta.sender_scan_outputs[0];
        assert_eq!((rpc_output.tree, rpc_output.position), (tree + 1, 3));
        assert_eq!(
            (rpc_output.tree, rpc_output.position),
            (indexed_output.tree, indexed_output.position)
        );
        assert_eq!(rpc_output.commitment, indexed_output.commitment);
        assert_eq!(
            (
                rpc_output.source.tx_hash,
                rpc_output.source.block_number,
                rpc_output.source.block_timestamp,
            ),
            (tx_hash, block_number, block_timestamp)
        );
        assert_eq!(rpc_output.source, indexed_output.source);
        assert!(
            rpc_output.ciphertext.ciphertext == indexed_output.ciphertext.ciphertext
                && rpc_output.ciphertext.blindedSenderViewingKey
                    == indexed_output.ciphertext.blindedSenderViewingKey
                && rpc_output.ciphertext.blindedReceiverViewingKey
                    == indexed_output.ciphertext.blindedReceiverViewingKey
                && rpc_output.ciphertext.annotationData == indexed_output.ciphertext.annotationData
                && rpc_output.ciphertext.memo == indexed_output.ciphertext.memo
        );

        let wallet_note = Note::new_change(
            keys.master_public_key,
            Address::ZERO,
            U256::from(50),
            [1; 16],
        );
        let wallet_utxo = WalletUtxo::new(Utxo::new(
            wallet_note,
            1,
            7,
            source(1),
            UtxoCommitmentKind::Transact,
        ));
        let nullifier_sources = std::collections::HashMap::from([(
            (1, wallet_utxo.utxo.nullifier(keys.nullifying_key)),
            rpc_output.source.clone(),
        )]);
        let record = |outputs| {
            sender_scan_candidate_inputs(
                std::slice::from_ref(&wallet_utxo),
                keys.nullifying_key,
                &nullifier_sources,
                outputs,
                &keys,
            )
            .remove(0)
            .into_record(
                1,
                local_db::WalletCacheKey::from_opaque_bytes(b"source-parity").expect("wallet key"),
            )
            .expect("candidate record")
        };
        let rpc_record = record(rpc_delta.sender_scan_outputs);
        let indexed_record = record(indexed_delta.sender_scan_outputs);
        assert_eq!(rpc_record.source, indexed_record.source);
        assert_eq!(rpc_record.outputs[0].tree, tree + 1);
        assert_eq!(rpc_record.outputs[0].position, 3);
        assert_eq!(
            rpc_record.encode().expect("encode RPC record"),
            indexed_record.encode().expect("encode indexed record")
        );
    }

    impl super::SenderScanWalletSpend {
        const fn key(&self) -> (u32, u64) {
            (self.tree, self.position)
        }
    }
}

#[cfg(test)]
pub(in crate::wallet) mod test_support {
    use super::*;
    use crate::wallet::DbStore;

    pub(in crate::wallet) fn apply_wallet_delta_to_vec(
        cfg: &WalletConfig,
        wallet_utxos: &mut Vec<WalletUtxo>,
        delta: WalletLogDelta,
    ) -> bool {
        apply_wallet_delta_to_vec_with_outcome(cfg, wallet_utxos, delta).changed
    }

    pub(in crate::wallet) fn discard_pending_output_poi_contexts_for_spent_outputs(
        db: &DbStore,
        chain_id: u64,
        wallet_id: &str,
        spent_output_commitments: &[FixedBytes<32>],
    ) -> Result<usize, local_db::DbError> {
        let mut discarded = 0;
        for output_commitment in spent_output_commitments {
            db.delete_pending_output_poi_context(chain_id, wallet_id, output_commitment)?;
            discarded += 1;
        }
        Ok(discarded)
    }
}
