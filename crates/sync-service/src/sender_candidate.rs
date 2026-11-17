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
    pub unshield: Option<SenderTransactionCandidateUnshield>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderTransactionCandidateUnshield {
    /// Railgun TXIDs of unresolved eligible inner unshields, strictly ascending, nonempty.
    pub railgun_txids: Vec<FixedBytes<32>>,
    /// Private outputs were handed to pending-output maintenance (or none exist); only
    /// unshield work remains and output materialization is skipped.
    pub outputs_handed_off: bool,
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
    #[error("sender transaction candidate unshield TXIDs must be nonempty, unique, and sorted")]
    InvalidUnshield,
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
            unshield: None,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn with_unshield(
        mut self,
        unshield: Option<SenderTransactionCandidateUnshield>,
    ) -> Result<Self, SenderTransactionCandidateError> {
        self.unshield = unshield;
        self.validate()?;
        Ok(self)
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
            }
        }
        if let Some(unshield) = &self.unshield
            && (unshield.railgun_txids.is_empty()
                || !unshield
                    .railgun_txids
                    .windows(2)
                    .all(|pair| pair[0] < pair[1]))
        {
            return Err(SenderTransactionCandidateError::InvalidUnshield);
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
    unshield: Option<UnshieldWire>,
}

#[derive(Serialize, Deserialize)]
struct UnshieldWire {
    railgun_txids: Vec<[u8; 32]>,
    outputs_handed_off: bool,
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
            unshield: record.unshield.as_ref().map(|unshield| UnshieldWire {
                railgun_txids: unshield.railgun_txids.iter().map(|txid| txid.0).collect(),
                outputs_handed_off: unshield.outputs_handed_off,
            }),
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
            unshield: wire
                .unshield
                .map(|unshield| SenderTransactionCandidateUnshield {
                    railgun_txids: unshield
                        .railgun_txids
                        .into_iter()
                        .map(FixedBytes::from)
                        .collect(),
                    outputs_handed_off: unshield.outputs_handed_off,
                }),
        })
    }
}

#[cfg(test)]
mod tests;
