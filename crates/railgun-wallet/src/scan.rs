use std::collections::HashMap;

use alloy::primitives::{Bytes, FixedBytes, U256};
use alloy::sol_types::{Error as SolError, SolEvent};
use alloy_rpc_types_eth::Log;
use thiserror::Error;

use broadcaster_core::contracts::railgun::{
    CommitmentBatch, CommitmentCiphertext, CommitmentPreimage, GeneratedCommitmentBatch,
    LegacyCommitmentPreimage, Nullified, Nullifiers, RailgunLegacyShieldEvents, Shield,
    ShieldCiphertext, Transact,
};
use broadcaster_core::crypto::railgun::ViewingKeyData;
use broadcaster_core::crypto::shared_key::{shared_symmetric_key, shared_symmetric_key_legacy};
use broadcaster_core::notes::{Note, decrypt_legacy_random, decrypt_shield_random};
use broadcaster_core::tree::normalize_tree_position;
use broadcaster_core::utxo::{Utxo, UtxoCommitmentKind, UtxoSource};
use merkletree::quick::{
    IndexedLegacyEncryptedCommitment as QuickIndexedLegacyEncryptedCommitment,
    IndexedLegacyGeneratedCommitment as QuickIndexedLegacyGeneratedCommitment,
    IndexedNullifier as QuickIndexedNullifier,
    IndexedShieldCommitment as QuickIndexedShieldCommitment,
    IndexedTransactCommitment as QuickIndexedTransactCommitment,
};

#[derive(Debug, Error)]
pub enum WalletScanError {
    #[error("decode log: {0}")]
    Decode(#[from] SolError),
    #[error("log missing required metadata: {0}")]
    MissingLogMetadata(&'static str),
}

pub type WalletScanKeys = ViewingKeyData;

#[derive(Debug, Clone)]
pub struct WalletLogDelta {
    pub utxos: Vec<Utxo>,
    pub nullifiers: Vec<SpentNullifier>,
    pub commitment_observations: Vec<CommitmentObservation>,
    pub sender_scan_outputs: Vec<SenderScanOutput>,
}

impl WalletLogDelta {
    #[must_use]
    pub fn from_rows(rows: &WalletScanInputRows, keys: &WalletScanKeys) -> Self {
        Self::from_indexed_inputs(
            &rows.transact_commitments,
            &rows.shield_commitments,
            &rows.legacy_encrypted_commitments,
            &rows.legacy_generated_commitments,
            &rows.nullifiers,
            &rows.commitment_observations,
            keys,
        )
    }

    fn from_indexed_inputs(
        transact_commitments: &[IndexedTransactCommitmentInput],
        shield_commitments: &[IndexedShieldCommitmentInput],
        legacy_encrypted_commitments: &[IndexedLegacyEncryptedCommitmentInput],
        legacy_generated_commitments: &[IndexedLegacyGeneratedCommitmentInput],
        indexed_nullifiers: &[IndexedNullifierInput],
        extra_commitment_observations: &[CommitmentObservation],
        keys: &WalletScanKeys,
    ) -> Self {
        let mut utxos = Vec::new();
        let mut nullifiers = HashMap::new();
        let mut commitment_observations = extra_commitment_observations.to_vec();
        let mut sender_scan_outputs = Vec::with_capacity(transact_commitments.len());

        for commitment in transact_commitments {
            sender_scan_outputs.push(commitment.sender_scan_output());
            commitment_observations.push(commitment_observation(
                commitment.tree_number,
                commitment.tree_position,
                commitment.hash,
                commitment.source.clone(),
            ));
            if let Some(utxo) = commitment.scan(keys) {
                utxos.push(utxo);
            }
        }

        for commitment in shield_commitments {
            commitment_observations.push(commitment_observation(
                commitment.tree_number,
                commitment.tree_position,
                commitment.preimage.hash(),
                commitment.source.clone(),
            ));
            if let Some(utxo) = scan_shield_commitment(
                commitment.tree_number,
                commitment.tree_position,
                &commitment.preimage,
                &commitment.shield_ciphertext,
                commitment.source.clone(),
                keys,
            ) {
                utxos.push(utxo);
            }
        }

        for commitment in legacy_encrypted_commitments {
            commitment_observations.push(commitment_observation(
                commitment.tree_number,
                commitment.tree_position,
                commitment.hash,
                commitment.source.clone(),
            ));
            if let Some(utxo) = commitment.scan(keys) {
                utxos.push(utxo);
            }
        }

        for commitment in legacy_generated_commitments {
            commitment_observations.push(commitment_observation(
                commitment.tree_number,
                commitment.tree_position,
                commitment.preimage.hash(),
                commitment.source.clone(),
            ));
            if let Some(utxo) = commitment.scan(keys) {
                utxos.push(utxo);
            }
        }

        for nullifier in indexed_nullifiers {
            nullifiers
                .entry((nullifier.tree_number, nullifier.nullifier))
                .or_insert_with(|| nullifier.source.clone());
        }

        Self {
            utxos,
            nullifiers: nullifiers
                .into_iter()
                .map(|((tree, nullifier), source)| SpentNullifier {
                    tree,
                    nullifier,
                    source,
                })
                .collect(),
            commitment_observations,
            sender_scan_outputs,
        }
    }
}

#[derive(Clone, Default)]
pub struct WalletScanInputRows {
    pub transact_commitments: Vec<IndexedTransactCommitmentInput>,
    pub shield_commitments: Vec<IndexedShieldCommitmentInput>,
    pub legacy_encrypted_commitments: Vec<IndexedLegacyEncryptedCommitmentInput>,
    pub legacy_generated_commitments: Vec<IndexedLegacyGeneratedCommitmentInput>,
    pub nullifiers: Vec<IndexedNullifierInput>,
    pub commitment_observations: Vec<CommitmentObservation>,
}

impl std::fmt::Debug for WalletScanInputRows {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletScanInputRows")
            .field("transact_commitments", &self.transact_commitments.len())
            .field("shield_commitments", &self.shield_commitments.len())
            .field(
                "legacy_encrypted_commitments",
                &self.legacy_encrypted_commitments.len(),
            )
            .field(
                "legacy_generated_commitments",
                &self.legacy_generated_commitments.len(),
            )
            .field("nullifiers", &self.nullifiers.len())
            .field(
                "commitment_observations",
                &self.commitment_observations.len(),
            )
            .finish()
    }
}

impl WalletScanInputRows {
    #[must_use]
    pub const fn row_count(&self) -> usize {
        self.transact_commitments
            .len()
            .saturating_add(self.shield_commitments.len())
            .saturating_add(self.legacy_encrypted_commitments.len())
            .saturating_add(self.legacy_generated_commitments.len())
            .saturating_add(self.nullifiers.len())
            .saturating_add(self.commitment_observations.len())
    }

    pub fn retain_block_range(&mut self, from_block: u64, to_block: u64) {
        let contains = |block_number| block_number >= from_block && block_number <= to_block;
        self.transact_commitments
            .retain(|row| contains(row.source.block_number));
        self.shield_commitments
            .retain(|row| contains(row.source.block_number));
        self.legacy_encrypted_commitments
            .retain(|row| contains(row.source.block_number));
        self.legacy_generated_commitments
            .retain(|row| contains(row.source.block_number));
        self.nullifiers
            .retain(|row| contains(row.source.block_number));
        self.commitment_observations
            .retain(|row| contains(row.source.block_number));
    }

    pub fn from_logs(
        logs: &[Log],
        block_timestamps: &HashMap<u64, u64>,
    ) -> Result<Self, WalletScanError> {
        let mut rows = Self::default();

        for raw_log in logs {
            let topic0 = raw_log.inner.topics().first().copied().unwrap_or_default();
            if topic0 == Transact::SIGNATURE_HASH {
                let event = Transact::decode_log(&raw_log.inner)?.data;

                let tree_number: u32 = event.treeNumber.to();
                let start_pos: u64 = event.startPosition.to();
                let commitment_hashes = &event.hash;
                let source = source_from_log(raw_log, block_timestamps)?;
                for (index, ciphertext) in event.ciphertext.iter().enumerate() {
                    let position = start_pos + index as u64;
                    if let Some(expected_hash) = commitment_hashes
                        .get(index)
                        .map(|hash| U256::from_be_bytes(hash.0))
                    {
                        rows.transact_commitments
                            .push(IndexedTransactCommitmentInput {
                                tree_number,
                                tree_position: position,
                                hash: expected_hash,
                                ciphertext: ciphertext.ciphertext,
                                blinded_sender_viewing_key: ciphertext.blindedSenderViewingKey,
                                blinded_receiver_viewing_key: ciphertext.blindedReceiverViewingKey,
                                annotation_data: ciphertext.annotationData.clone(),
                                memo: ciphertext.memo.clone(),
                                source: source.clone(),
                            });
                    }
                }
            } else if topic0 == Shield::SIGNATURE_HASH {
                let event = Shield::decode_log(&raw_log.inner)?.data;

                let tree_number: u32 = event.treeNumber.to();
                let start_pos: u64 = event.startPosition.to();
                let source = source_from_log(raw_log, block_timestamps)?;
                rows.push_shield_event_rows(
                    tree_number,
                    start_pos,
                    &event.commitments,
                    &event.shieldCiphertext,
                    &source,
                );
            } else if topic0 == RailgunLegacyShieldEvents::Shield::SIGNATURE_HASH {
                let event = RailgunLegacyShieldEvents::Shield::decode_log(&raw_log.inner)?.data;

                let tree_number: u32 = event.treeNumber.to();
                let start_pos: u64 = event.startPosition.to();
                let source = source_from_log(raw_log, block_timestamps)?;
                rows.push_shield_event_rows(
                    tree_number,
                    start_pos,
                    &event.commitments,
                    &event.shieldCiphertext,
                    &source,
                );
            } else if topic0 == Nullifiers::SIGNATURE_HASH {
                let event = Nullifiers::decode_log(&raw_log.inner)?.data;
                let tree_number: u32 = event.treeNumber.to();
                let source = source_from_log(raw_log, block_timestamps)?;
                for nullifier in event.nullifier {
                    rows.nullifiers.push(IndexedNullifierInput {
                        tree_number,
                        nullifier,
                        source: source.clone(),
                    });
                }
            } else if topic0 == Nullified::SIGNATURE_HASH {
                let event = Nullified::decode_log(&raw_log.inner)?.data;
                let tree_number: u32 = event.treeNumber.into();
                let source = source_from_log(raw_log, block_timestamps)?;
                for nullifier in event.nullifier {
                    rows.nullifiers.push(IndexedNullifierInput {
                        tree_number,
                        nullifier: U256::from_be_bytes(nullifier.0),
                        source: source.clone(),
                    });
                }
            } else if topic0 == CommitmentBatch::SIGNATURE_HASH {
                let event = CommitmentBatch::decode_log(&raw_log.inner)?.data;

                let tree_number: u32 = event.treeNumber.to();
                let start_pos: u64 = event.startPosition.to();
                let source = source_from_log(raw_log, block_timestamps)?;
                for (index, ciphertext) in event.ciphertext.iter().enumerate() {
                    let Some(expected_hash) = event.hash.get(index).copied() else {
                        continue;
                    };
                    let position = start_pos + index as u64;
                    rows.legacy_encrypted_commitments
                        .push(IndexedLegacyEncryptedCommitmentInput {
                            tree_number,
                            tree_position: position,
                            hash: expected_hash,
                            ciphertext: ciphertext
                                .ciphertext
                                .map(|value| FixedBytes::from(value.to_be_bytes::<32>())),
                            ephemeral_keys: ciphertext
                                .ephemeralKeys
                                .map(|value| FixedBytes::from(value.to_be_bytes::<32>())),
                            memo: ciphertext
                                .memo
                                .iter()
                                .copied()
                                .map(|value| FixedBytes::from(value.to_be_bytes::<32>()))
                                .collect(),
                            source: source.clone(),
                        });
                }
            } else if topic0 == GeneratedCommitmentBatch::SIGNATURE_HASH {
                let event = GeneratedCommitmentBatch::decode_log(&raw_log.inner)?.data;

                let tree_number: u32 = event.treeNumber.to();
                let start_pos: u64 = event.startPosition.to();
                let source = source_from_log(raw_log, block_timestamps)?;
                for (index, preimage) in event.commitments.iter().enumerate() {
                    let Some(encrypted_random) = event.encryptedRandom.get(index) else {
                        continue;
                    };
                    let position = start_pos + index as u64;
                    rows.legacy_generated_commitments
                        .push(IndexedLegacyGeneratedCommitmentInput {
                            tree_number,
                            tree_position: position,
                            preimage: preimage.clone(),
                            encrypted_random: encrypted_random_from_u256(*encrypted_random),
                            source: source.clone(),
                        });
                }
            }
        }

        Ok(rows)
    }

    fn push_shield_event_rows(
        &mut self,
        tree_number: u32,
        start_pos: u64,
        commitments: &[CommitmentPreimage],
        shield_ciphertext: &[ShieldCiphertext],
        source: &UtxoSource,
    ) {
        for (index, preimage) in commitments.iter().enumerate() {
            let position = start_pos + index as u64;
            if let Some(ciphertext) = shield_ciphertext.get(index) {
                self.shield_commitments.push(IndexedShieldCommitmentInput {
                    tree_number,
                    tree_position: position,
                    preimage: preimage.clone(),
                    shield_ciphertext: ciphertext.clone(),
                    source: source.clone(),
                });
            } else {
                self.commitment_observations.push(commitment_observation(
                    tree_number,
                    position,
                    preimage.hash(),
                    source.clone(),
                ));
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct CommitmentObservation {
    pub tree: u32,
    pub position: u64,
    pub commitment: U256,
    pub source: UtxoSource,
}

#[derive(Debug, Clone)]
pub struct SpentNullifier {
    pub tree: u32,
    pub nullifier: U256,
    pub source: UtxoSource,
}

/// Complete output slot retained until the sync boundary can determine whether its outer
/// transaction spends a wallet input.
#[derive(Clone)]
pub struct SenderScanOutput {
    pub tree: u32,
    pub position: u64,
    pub commitment: U256,
    pub ciphertext: CommitmentCiphertext,
    pub source: UtxoSource,
}

impl std::fmt::Debug for SenderScanOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SenderScanOutput")
            .field("tree", &self.tree)
            .field("position", &self.position)
            .field("commitment", &self.commitment)
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct IndexedTransactCommitmentInput {
    pub tree_number: u32,
    pub tree_position: u64,
    pub hash: U256,
    pub ciphertext: [FixedBytes<32>; 4],
    pub blinded_sender_viewing_key: FixedBytes<32>,
    pub blinded_receiver_viewing_key: FixedBytes<32>,
    pub annotation_data: Bytes,
    pub memo: Bytes,
    pub source: UtxoSource,
}

impl From<QuickIndexedTransactCommitment> for IndexedTransactCommitmentInput {
    fn from(value: QuickIndexedTransactCommitment) -> Self {
        Self {
            tree_number: value.tree_number.to(),
            tree_position: value.tree_position.to(),
            hash: value.hash,
            ciphertext: value.ciphertext.ciphertext,
            blinded_sender_viewing_key: value.ciphertext.blinded_sender_viewing_key,
            blinded_receiver_viewing_key: value.ciphertext.blinded_receiver_viewing_key,
            annotation_data: value.ciphertext.annotation_data,
            memo: value.ciphertext.memo,
            source: indexed_source(
                value.transaction_hash,
                value.block_number,
                value.block_timestamp,
            ),
        }
    }
}

impl IndexedTransactCommitmentInput {
    fn sender_scan_output(&self) -> SenderScanOutput {
        let (tree, position) = normalize_tree_position(self.tree_number, self.tree_position);
        SenderScanOutput {
            tree,
            position,
            commitment: self.hash,
            ciphertext: CommitmentCiphertext {
                ciphertext: self.ciphertext,
                blindedSenderViewingKey: self.blinded_sender_viewing_key,
                blindedReceiverViewingKey: self.blinded_receiver_viewing_key,
                annotationData: self.annotation_data.clone(),
                memo: self.memo.clone(),
            },
            source: self.source.clone(),
        }
    }

    fn scan(&self, keys: &WalletScanKeys) -> Option<Utxo> {
        let (tree, position) = normalize_tree_position(self.tree_number, self.tree_position);
        let shared_key = shared_symmetric_key(
            &keys.viewing_private_key,
            &self.blinded_sender_viewing_key.0,
        )
        .ok()?;
        let note = Note::decrypt_v2(
            &self.ciphertext,
            self.memo.as_ref(),
            &shared_key,
            keys.master_public_key,
        )
        .ok()?;
        if note.commitment() != self.hash {
            return None;
        }
        Some(Utxo::new(
            note,
            tree,
            position,
            self.source.clone(),
            UtxoCommitmentKind::Transact,
        ))
    }
}

#[derive(Clone)]
pub struct IndexedShieldCommitmentInput {
    pub tree_number: u32,
    pub tree_position: u64,
    pub preimage: CommitmentPreimage,
    pub shield_ciphertext: ShieldCiphertext,
    pub source: UtxoSource,
}

impl From<QuickIndexedShieldCommitment> for IndexedShieldCommitmentInput {
    fn from(value: QuickIndexedShieldCommitment) -> Self {
        Self {
            tree_number: value.tree_number.to(),
            tree_position: value.tree_position.to(),
            preimage: value.preimage.into(),
            shield_ciphertext: ShieldCiphertext {
                encryptedBundle: value.encrypted_bundle,
                shieldKey: value.shield_key,
            },
            source: indexed_source(
                value.transaction_hash,
                value.block_number,
                value.block_timestamp,
            ),
        }
    }
}

#[derive(Clone)]
pub struct IndexedNullifierInput {
    pub tree_number: u32,
    pub nullifier: U256,
    pub source: UtxoSource,
}

impl From<QuickIndexedNullifier> for IndexedNullifierInput {
    fn from(value: QuickIndexedNullifier) -> Self {
        Self {
            tree_number: value.tree_number.to(),
            nullifier: value.nullifier,
            source: indexed_source(
                value.transaction_hash,
                value.block_number,
                value.block_timestamp,
            ),
        }
    }
}

#[derive(Clone)]
pub struct IndexedLegacyEncryptedCommitmentInput {
    pub tree_number: u32,
    pub tree_position: u64,
    pub hash: U256,
    pub ciphertext: [FixedBytes<32>; 4],
    pub ephemeral_keys: [FixedBytes<32>; 2],
    pub memo: Vec<FixedBytes<32>>,
    pub source: UtxoSource,
}

impl From<QuickIndexedLegacyEncryptedCommitment> for IndexedLegacyEncryptedCommitmentInput {
    fn from(value: QuickIndexedLegacyEncryptedCommitment) -> Self {
        Self {
            tree_number: value.tree_number.to(),
            tree_position: value.tree_position.to(),
            hash: value.hash,
            ciphertext: value.ciphertext.ciphertext,
            ephemeral_keys: value.ciphertext.ephemeral_keys,
            memo: value.ciphertext.memo,
            source: indexed_source(
                value.transaction_hash,
                value.block_number,
                value.block_timestamp,
            ),
        }
    }
}

impl IndexedLegacyEncryptedCommitmentInput {
    fn scan(&self, keys: &WalletScanKeys) -> Option<Utxo> {
        let memo = self
            .memo
            .iter()
            .skip(2)
            .flat_map(|chunk| chunk.0)
            .collect::<Vec<_>>();
        let shared_key =
            shared_symmetric_key_legacy(&keys.viewing_private_key, &self.ephemeral_keys[0].0)
                .ok()?;
        let (tree, position) = normalize_tree_position(self.tree_number, self.tree_position);
        let note =
            Note::decrypt_v2(&self.ciphertext, &memo, &shared_key, keys.master_public_key).ok()?;
        if note.commitment() != self.hash {
            return None;
        }
        Some(Utxo::new(
            note,
            tree,
            position,
            self.source.clone(),
            UtxoCommitmentKind::Transact,
        ))
    }
}

#[derive(Clone)]
pub struct IndexedLegacyGeneratedCommitmentInput {
    pub tree_number: u32,
    pub tree_position: u64,
    pub preimage: LegacyCommitmentPreimage,
    pub encrypted_random: (FixedBytes<32>, FixedBytes<16>),
    pub source: UtxoSource,
}

impl From<QuickIndexedLegacyGeneratedCommitment> for IndexedLegacyGeneratedCommitmentInput {
    fn from(value: QuickIndexedLegacyGeneratedCommitment) -> Self {
        Self {
            tree_number: value.tree_number.to(),
            tree_position: value.tree_position.to(),
            preimage: value.preimage.into(),
            encrypted_random: value.encrypted_random,
            source: indexed_source(
                value.transaction_hash,
                value.block_number,
                value.block_timestamp,
            ),
        }
    }
}

impl IndexedLegacyGeneratedCommitmentInput {
    fn scan(&self, keys: &WalletScanKeys) -> Option<Utxo> {
        let random = decrypt_legacy_random(
            self.encrypted_random.0,
            self.encrypted_random.1,
            &keys.viewing_private_key,
        )
        .ok()?;
        let npk = Note::npk_for(keys.master_public_key, random);
        if npk != self.preimage.npk {
            return None;
        }
        let (tree, position) = normalize_tree_position(self.tree_number, self.tree_position);
        let note = Note {
            token_hash: self.preimage.token.id(),
            value: U256::from(self.preimage.value.to::<u128>()),
            random,
            npk: self.preimage.npk,
        };
        Some(Utxo::new(
            note,
            tree,
            position,
            self.source.clone(),
            UtxoCommitmentKind::Shield,
        ))
    }
}

fn indexed_source(
    tx_hash: FixedBytes<32>,
    block_number: U256,
    block_timestamp: U256,
) -> UtxoSource {
    UtxoSource {
        tx_hash,
        block_number: block_number.to(),
        block_timestamp: block_timestamp.to(),
    }
}

pub fn parse_wallet_delta_from_logs(
    logs: &[Log],
    block_timestamps: &HashMap<u64, u64>,
    keys: &WalletScanKeys,
) -> Result<WalletLogDelta, WalletScanError> {
    let rows = WalletScanInputRows::from_logs(logs, block_timestamps)?;
    Ok(WalletLogDelta::from_rows(&rows, keys))
}

pub fn parse_indexed_wallet_delta(
    transact_commitments: &[IndexedTransactCommitmentInput],
    shield_commitments: &[IndexedShieldCommitmentInput],
    legacy_encrypted_commitments: &[IndexedLegacyEncryptedCommitmentInput],
    legacy_generated_commitments: &[IndexedLegacyGeneratedCommitmentInput],
    indexed_nullifiers: &[IndexedNullifierInput],
    keys: &WalletScanKeys,
) -> WalletLogDelta {
    WalletLogDelta::from_indexed_inputs(
        transact_commitments,
        shield_commitments,
        legacy_encrypted_commitments,
        legacy_generated_commitments,
        indexed_nullifiers,
        &[],
        keys,
    )
}

const fn commitment_observation(
    tree_number: u32,
    tree_position: u64,
    commitment: U256,
    source: UtxoSource,
) -> CommitmentObservation {
    let (tree, position) = normalize_tree_position(tree_number, tree_position);
    CommitmentObservation {
        tree,
        position,
        commitment,
        source,
    }
}

fn encrypted_random_from_u256(value: [U256; 2]) -> (FixedBytes<32>, FixedBytes<16>) {
    let data = value[1].to_be_bytes::<32>();
    let mut data16 = [0u8; 16];
    data16.copy_from_slice(&data[16..]);
    (
        FixedBytes::from(value[0].to_be_bytes::<32>()),
        FixedBytes::from(data16),
    )
}

fn scan_shield_commitment(
    tree_number: u32,
    tree_position: u64,
    preimage: &CommitmentPreimage,
    ciphertext: &ShieldCiphertext,
    source: UtxoSource,
    keys: &WalletScanKeys,
) -> Option<Utxo> {
    let (tree, position) = normalize_tree_position(tree_number, tree_position);
    let shared_key =
        shared_symmetric_key(&keys.viewing_private_key, &ciphertext.shieldKey.0).ok()?;
    let random = decrypt_shield_random(&ciphertext.encryptedBundle, &shared_key).ok()?;
    Some(Utxo::new(
        preimage.note_with_random(random),
        tree,
        position,
        source,
        UtxoCommitmentKind::Shield,
    ))
}

fn source_from_log(
    log: &Log,
    block_timestamps: &HashMap<u64, u64>,
) -> Result<UtxoSource, WalletScanError> {
    let block_number = log
        .block_number
        .ok_or(WalletScanError::MissingLogMetadata("block_number"))?;
    let block_timestamp = block_timestamps
        .get(&block_number)
        .copied()
        .ok_or(WalletScanError::MissingLogMetadata("block_timestamp"))?;

    Ok(UtxoSource {
        tx_hash: log
            .transaction_hash
            .ok_or(WalletScanError::MissingLogMetadata("transaction_hash"))?,
        block_number,
        block_timestamp,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use alloy::hex;
    use alloy::primitives::{Address, Bytes, FixedBytes, U256};
    use alloy::sol_types::SolEvent;
    use alloy_rpc_types_eth::Log;
    use broadcaster_core::contracts::railgun::{CommitmentCiphertext, Transact};

    use super::WalletScanInputRows;

    #[test]
    fn rpc_transact_log_preserves_complete_ciphertext() {
        let ciphertext = CommitmentCiphertext {
            ciphertext: std::array::from_fn(|index| FixedBytes::from([index as u8 + 1; 32])),
            blindedSenderViewingKey: FixedBytes::from([0x11; 32]),
            blindedReceiverViewingKey: FixedBytes::from([0x22; 32]),
            annotationData: Bytes::from(vec![0x33, 0x34]),
            memo: Bytes::from(vec![0x44, 0x45]),
        };
        let encoded = Transact {
            treeNumber: U256::from(7),
            startPosition: U256::from(9),
            hash: vec![FixedBytes::from([0x55; 32])],
            ciphertext: vec![ciphertext.clone()],
        }
        .encode_log_data();
        let topics = encoded
            .topics()
            .iter()
            .map(|topic| format!("{topic:#x}"))
            .collect::<Vec<_>>();
        let log: Log = serde_json::from_value(serde_json::json!({
            "address": format!("{:#x}", Address::from([0xaa; 20])),
            "topics": topics,
            "data": format!("0x{}", hex::encode(encoded.data)),
            "blockHash": format!("{:#x}", FixedBytes::<32>::from([0xbb; 32])),
            "blockNumber": "0x69",
            "transactionHash": format!("{:#x}", FixedBytes::<32>::from([0xcc; 32])),
            "transactionIndex": "0x0",
            "logIndex": "0x0",
            "removed": false,
        }))
        .expect("deserialize transact log");
        let rows = WalletScanInputRows::from_logs(&[log], &HashMap::from([(105, 1_700_000_105)]))
            .expect("normalize transact log");
        let row = &rows.transact_commitments[0];

        assert_eq!(row.tree_number, 7);
        assert_eq!(row.tree_position, 9);
        assert_eq!(row.hash, U256::from_be_bytes([0x55; 32]));
        assert_eq!(row.ciphertext, ciphertext.ciphertext);
        assert_eq!(
            row.blinded_sender_viewing_key,
            ciphertext.blindedSenderViewingKey
        );
        assert_eq!(
            row.blinded_receiver_viewing_key,
            ciphertext.blindedReceiverViewingKey
        );
        assert_eq!(row.annotation_data, ciphertext.annotationData);
        assert_eq!(row.memo, ciphertext.memo);
        assert_eq!(row.source.tx_hash, FixedBytes::from([0xcc; 32]));
        assert_eq!(row.source.block_number, 105);
        assert_eq!(row.source.block_timestamp, 1_700_000_105);
    }
}
