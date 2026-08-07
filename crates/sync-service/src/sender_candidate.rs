use std::collections::BTreeSet;
use std::io::Cursor;

use alloy::primitives::{FixedBytes, U256};
use broadcaster_core::notes::Note;
use broadcaster_core::utxo::UtxoSource;
use local_db::{WalletCacheKey, WalletPrivateNamespaceId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const SENDER_TRANSACTION_CANDIDATE_FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SenderTransactionCandidateSpend {
    pub tree: u32,
    pub position: u64,
    pub commitment: FixedBytes<32>,
}

#[derive(Debug, Clone)]
pub struct SenderTransactionCandidateOutput {
    pub tree: u32,
    pub position: u64,
    pub commitment: FixedBytes<32>,
    pub note: Option<Note>,
}

#[derive(Debug, Clone)]
pub struct SenderTransactionCandidate {
    pub format_version: u32,
    pub chain_id: u64,
    pub wallet_id: WalletCacheKey,
    pub source: UtxoSource,
    pub wallet_spends: Vec<SenderTransactionCandidateSpend>,
    pub outputs: Vec<SenderTransactionCandidateOutput>,
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum SenderTransactionCandidateError {
    #[error("unsupported sender transaction candidate format version")]
    UnsupportedFormatVersion,
    #[error("sender transaction candidate wallet spends must be nonempty, unique, and sorted")]
    InvalidWalletSpends,
    #[error(
        "sender transaction candidate outputs must have unique sorted positions and commitments"
    )]
    InvalidOutputs,
    #[error("sender transaction candidate note does not match its output commitment")]
    NoteCommitmentMismatch,
    #[error("sender transaction candidate must contain at least one valid sender note")]
    MissingSenderNote,
    #[error("invalid sender transaction candidate encoding")]
    InvalidEncoding,
}

impl SenderTransactionCandidate {
    pub fn new(
        chain_id: u64,
        wallet_id: WalletCacheKey,
        source: UtxoSource,
        wallet_spends: Vec<SenderTransactionCandidateSpend>,
        outputs: Vec<SenderTransactionCandidateOutput>,
    ) -> Result<Self, SenderTransactionCandidateError> {
        let record = Self {
            format_version: SENDER_TRANSACTION_CANDIDATE_FORMAT_VERSION,
            chain_id,
            wallet_id,
            source,
            wallet_spends,
            outputs,
        };
        record.validate()?;
        Ok(record)
    }

    #[must_use]
    pub const fn semantic_id(&self) -> FixedBytes<32> {
        self.source.tx_hash
    }

    #[must_use]
    pub fn row_identity(&self) -> Vec<u8> {
        self.semantic_id().to_vec()
    }

    #[must_use]
    pub fn namespace(&self) -> WalletPrivateNamespaceId {
        WalletPrivateNamespaceId::new(self.chain_id, self.wallet_id.clone())
    }

    pub fn validate(&self) -> Result<(), SenderTransactionCandidateError> {
        if self.format_version != SENDER_TRANSACTION_CANDIDATE_FORMAT_VERSION {
            return Err(SenderTransactionCandidateError::UnsupportedFormatVersion);
        }
        if self.wallet_spends.is_empty()
            || !self.wallet_spends.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(SenderTransactionCandidateError::InvalidWalletSpends);
        }

        let mut positions = BTreeSet::new();
        let mut commitments = BTreeSet::new();
        let mut has_sender_note = false;
        for (index, output) in self.outputs.iter().enumerate() {
            if index > 0 && output_key(&self.outputs[index - 1]) >= output_key(output) {
                return Err(SenderTransactionCandidateError::InvalidOutputs);
            }
            if !positions.insert((output.tree, output.position))
                || !commitments.insert(output.commitment)
            {
                return Err(SenderTransactionCandidateError::InvalidOutputs);
            }
            if let Some(note) = &output.note {
                let note_commitment = FixedBytes::from(note.commitment().to_be_bytes::<32>());
                if note_commitment != output.commitment {
                    return Err(SenderTransactionCandidateError::NoteCommitmentMismatch);
                }
                has_sender_note = true;
            }
        }
        if !has_sender_note {
            return Err(SenderTransactionCandidateError::MissingSenderNote);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, SenderTransactionCandidateError> {
        self.validate()?;
        rmp_serde::to_vec_named(&CandidateWire::from(self))
            .map_err(|_| SenderTransactionCandidateError::InvalidEncoding)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, SenderTransactionCandidateError> {
        let mut deserializer = rmp_serde::Deserializer::new(Cursor::new(payload));
        let wire = CandidateWire::deserialize(&mut deserializer)
            .map_err(|_| SenderTransactionCandidateError::InvalidEncoding)?;
        if deserializer.get_ref().position() != u64::try_from(payload.len()).unwrap_or(u64::MAX) {
            return Err(SenderTransactionCandidateError::InvalidEncoding);
        }
        let record = Self::try_from(wire)?;
        record.validate()?;
        Ok(record)
    }
}

pub fn sender_transaction_candidate_rewind_ids(
    records: &[SenderTransactionCandidate],
    from_block: u64,
) -> Result<Vec<FixedBytes<32>>, SenderTransactionCandidateError> {
    let mut ids = Vec::new();
    for record in records {
        record.validate()?;
        if record.source.block_number >= from_block {
            ids.push(record.semantic_id());
        }
    }
    ids.sort_unstable();
    ids.dedup();
    Ok(ids)
}

const fn output_key(output: &SenderTransactionCandidateOutput) -> (u32, u64, FixedBytes<32>) {
    (output.tree, output.position, output.commitment)
}

#[derive(Serialize, Deserialize)]
struct CandidateWire {
    format_version: u32,
    chain_id: u64,
    wallet_id: WalletCacheKey,
    source: SourceWire,
    wallet_spends: Vec<SpendWire>,
    outputs: Vec<OutputWire>,
}

#[derive(Serialize, Deserialize)]
struct SourceWire {
    tx_hash: [u8; 32],
    block_number: u64,
    block_timestamp: u64,
}

#[derive(Serialize, Deserialize)]
struct SpendWire {
    tree: u32,
    position: u64,
    commitment: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct OutputWire {
    tree: u32,
    position: u64,
    commitment: [u8; 32],
    note: Option<NoteWire>,
}

#[derive(Serialize, Deserialize)]
struct NoteWire {
    token_hash: [u8; 32],
    value: [u8; 32],
    random: [u8; 16],
    npk: [u8; 32],
}

impl From<&SenderTransactionCandidate> for CandidateWire {
    fn from(record: &SenderTransactionCandidate) -> Self {
        Self {
            format_version: record.format_version,
            chain_id: record.chain_id,
            wallet_id: record.wallet_id.clone(),
            source: SourceWire {
                tx_hash: record.source.tx_hash.0,
                block_number: record.source.block_number,
                block_timestamp: record.source.block_timestamp,
            },
            wallet_spends: record
                .wallet_spends
                .iter()
                .map(|spend| SpendWire {
                    tree: spend.tree,
                    position: spend.position,
                    commitment: spend.commitment.0,
                })
                .collect(),
            outputs: record
                .outputs
                .iter()
                .map(|output| OutputWire {
                    tree: output.tree,
                    position: output.position,
                    commitment: output.commitment.0,
                    note: output.note.as_ref().map(|note| NoteWire {
                        token_hash: note.token_hash.to_be_bytes(),
                        value: note.value.to_be_bytes(),
                        random: note.random,
                        npk: note.npk.to_be_bytes(),
                    }),
                })
                .collect(),
        }
    }
}

impl TryFrom<CandidateWire> for SenderTransactionCandidate {
    type Error = SenderTransactionCandidateError;

    fn try_from(wire: CandidateWire) -> Result<Self, Self::Error> {
        Ok(Self {
            format_version: wire.format_version,
            chain_id: wire.chain_id,
            wallet_id: wire.wallet_id,
            source: UtxoSource {
                tx_hash: FixedBytes::from(wire.source.tx_hash),
                block_number: wire.source.block_number,
                block_timestamp: wire.source.block_timestamp,
            },
            wallet_spends: wire
                .wallet_spends
                .into_iter()
                .map(|spend| SenderTransactionCandidateSpend {
                    tree: spend.tree,
                    position: spend.position,
                    commitment: FixedBytes::from(spend.commitment),
                })
                .collect(),
            outputs: wire
                .outputs
                .into_iter()
                .map(|output| SenderTransactionCandidateOutput {
                    tree: output.tree,
                    position: output.position,
                    commitment: FixedBytes::from(output.commitment),
                    note: output.note.map(|note| Note {
                        token_hash: U256::from_be_bytes(note.token_hash),
                        value: U256::from_be_bytes(note.value),
                        random: note.random,
                        npk: U256::from_be_bytes(note.npk),
                    }),
                })
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use local_db::{DbConfig, DbStore, OpaqueWalletPrivateRow, WalletPrivateRecordKind};

    use super::*;
    use crate::types::WalletCacheStore;

    fn candidate(block_number: u64, byte: u8) -> SenderTransactionCandidate {
        let note = Note {
            token_hash: U256::from(1),
            value: U256::from(20),
            random: [byte; 16],
            npk: U256::from(2),
        };
        SenderTransactionCandidate::new(
            1,
            WalletCacheKey::from_opaque_bytes(b"candidate-wallet").expect("wallet key"),
            UtxoSource {
                tx_hash: FixedBytes::from([byte; 32]),
                block_number,
                block_timestamp: 1_700_000_000 + block_number,
            },
            vec![SenderTransactionCandidateSpend {
                tree: 1,
                position: 3,
                commitment: FixedBytes::from([3; 32]),
            }],
            vec![SenderTransactionCandidateOutput {
                tree: 2,
                position: 4,
                commitment: FixedBytes::from(note.commitment().to_be_bytes::<32>()),
                note: Some(note),
            }],
        )
        .expect("valid candidate")
    }

    #[test]
    fn candidate_validation_and_deterministic_roundtrip() {
        let record = candidate(10, 0x11);
        let encoded = record.encode().expect("encode candidate");
        assert_eq!(encoded, record.encode().expect("re-encode candidate"));

        let decoded = SenderTransactionCandidate::decode(&encoded).expect("decode candidate");
        assert_eq!(
            decoded.encode().expect("re-encode decoded candidate"),
            encoded
        );
        assert_eq!(decoded.semantic_id(), record.semantic_id());
        assert_eq!(decoded.namespace(), record.namespace());
        assert_eq!(decoded.wallet_spends, record.wallet_spends);
        assert_eq!(decoded.outputs.len(), 1);
        assert_eq!(
            decoded.outputs[0]
                .note
                .as_ref()
                .expect("sender note")
                .commitment(),
            record.outputs[0]
                .note
                .as_ref()
                .expect("sender note")
                .commitment()
        );

        let mut malformed = record.clone();
        malformed.outputs[0].commitment = FixedBytes::ZERO;
        assert_eq!(
            malformed.validate(),
            Err(SenderTransactionCandidateError::NoteCommitmentMismatch)
        );
        let mut malformed = record;
        malformed.wallet_spends.push(malformed.wallet_spends[0]);
        assert_eq!(
            malformed.validate(),
            Err(SenderTransactionCandidateError::InvalidWalletSpends)
        );
    }

    #[test]
    fn rewind_selection_uses_source_block_and_is_ordered() {
        let records = [candidate(20, 0x22), candidate(9, 0x11), candidate(10, 0x33)];
        assert_eq!(
            sender_transaction_candidate_rewind_ids(&records, 10).expect("select rewind rows"),
            vec![FixedBytes::from([0x22; 32]), FixedBytes::from([0x33; 32])]
        );
    }

    #[test]
    fn bare_db_store_candidate_codec_is_namespace_and_kind_separated() {
        let root_dir = std::env::temp_dir().join(format!(
            "railgun-sender-candidate-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        let store = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open db");
        let record = candidate(10, 0x44);
        let namespace = record.namespace();
        let row = OpaqueWalletPrivateRow {
            row_id: record.row_identity(),
            payload: record.encode().expect("encode candidate"),
        };
        store
            .put_opaque_wallet_private_row(
                &namespace,
                WalletPrivateRecordKind::SenderTransactionCandidate,
                &row,
            )
            .expect("put candidate row");

        let loaded = <DbStore as WalletCacheStore>::get_sender_transaction_candidate(
            &store,
            record.chain_id,
            &record.wallet_id,
            &record.semantic_id(),
        )
        .expect("get candidate")
        .expect("candidate present");
        assert_eq!(loaded.semantic_id(), record.semantic_id());
        assert_eq!(
            <DbStore as WalletCacheStore>::list_sender_transaction_candidates(
                &store,
                record.chain_id,
                &record.wallet_id,
            )
            .expect("list candidates")
            .len(),
            1
        );

        let wrong_namespace = WalletPrivateNamespaceId::new(
            record.chain_id,
            WalletCacheKey::from_opaque_bytes(b"wrong-wallet").expect("wallet key"),
        );
        store
            .put_opaque_wallet_private_row(
                &wrong_namespace,
                WalletPrivateRecordKind::SenderTransactionCandidate,
                &row,
            )
            .expect("put wrong-namespace row");
        assert!(
            <DbStore as WalletCacheStore>::get_sender_transaction_candidate(
                &store,
                wrong_namespace.chain_id,
                &wrong_namespace.wallet_id,
                &record.semantic_id(),
            )
            .is_err()
        );

        let wrong_kind = candidate(11, 0x55);
        store
            .put_opaque_wallet_private_row(
                &wrong_kind.namespace(),
                WalletPrivateRecordKind::OutputPoiRecovery,
                &OpaqueWalletPrivateRow {
                    row_id: wrong_kind.row_identity(),
                    payload: wrong_kind.encode().expect("encode wrong-kind candidate"),
                },
            )
            .expect("put wrong-kind row");
        assert!(
            <DbStore as WalletCacheStore>::get_sender_transaction_candidate(
                &store,
                wrong_kind.chain_id,
                &wrong_kind.wallet_id,
                &wrong_kind.semantic_id(),
            )
            .expect("get kind-separated candidate")
            .is_none()
        );

        store
            .put_opaque_wallet_private_row(
                &namespace,
                WalletPrivateRecordKind::SenderTransactionCandidate,
                &OpaqueWalletPrivateRow {
                    row_id: vec![0x66; 32],
                    payload: b"malformed".to_vec(),
                },
            )
            .expect("put malformed row");
        assert!(
            <DbStore as WalletCacheStore>::list_sender_transaction_candidates(
                &store,
                record.chain_id,
                &record.wallet_id,
            )
            .is_err()
        );

        drop(store);
        fs::remove_dir_all(root_dir).expect("remove temp db dir");
    }
}
