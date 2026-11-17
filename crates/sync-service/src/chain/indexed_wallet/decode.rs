//! The binary wallet-scan chunk decoder.

use super::coverage::WalletScanChunkBounds;
use super::page::IndexedWalletPage;
use super::{
    IndexedLegacyEncryptedCommitmentInput, IndexedLegacyGeneratedCommitmentInput,
    IndexedNullifierInput, IndexedShieldCommitmentInput, IndexedTransactCommitmentInput, SyncError,
    UtxoSource, wallet_artifact_error, wallet_artifact_format,
};

use crate::indexed_artifacts::{
    ChainType, IndexedArtifactManifestError, IndexedArtifactRangeKind, IndexedDatasetKind,
    VerifiedIndexedArtifactChunk, decode_indexed_artifact_chunk,
};
use alloy::primitives::{FixedBytes as AlloyFixedBytes, U256};
use alloy::sol_types::SolValue;
use broadcaster_core::contracts::railgun::{
    CommitmentCiphertext, CommitmentPreimage, LegacyCommitmentCiphertext, LegacyCommitmentPreimage,
    ShieldCiphertext,
};

pub(super) const WALLET_TRANSACT_SECTION_ID: u16 = 1;
pub(super) const WALLET_SHIELD_SECTION_ID: u16 = 2;
pub(super) const WALLET_NULLIFIER_SECTION_ID: u16 = 3;
pub(super) const WALLET_LEGACY_ENCRYPTED_SECTION_ID: u16 = 4;
pub(super) const WALLET_LEGACY_GENERATED_SECTION_ID: u16 = 5;

#[derive(Clone, Copy)]
struct WalletScanRowBounds {
    from_block: u64,
    to_block: u64,
}

impl WalletScanRowBounds {
    const fn contains(self, source: &UtxoSource) -> bool {
        source.block_number >= self.from_block && source.block_number <= self.to_block
    }
}

impl IndexedWalletPage {
    pub(super) fn from_chunk_for_block_range(
        chunk: &VerifiedIndexedArtifactChunk,
        from_block: u64,
        to_block: u64,
    ) -> Result<Self, SyncError> {
        Self::decode_from_chunk(
            chunk,
            Some(WalletScanRowBounds {
                from_block,
                to_block,
            }),
        )
    }

    fn decode_from_chunk(
        chunk: &VerifiedIndexedArtifactChunk,
        bounds: Option<WalletScanRowBounds>,
    ) -> Result<Self, SyncError> {
        let envelope =
            decode_indexed_artifact_chunk(chunk).map_err(|err| wallet_artifact_error(&err))?;
        if envelope.header.dataset_kind != IndexedDatasetKind::WalletScan {
            return Err(wallet_artifact_format(
                "chunk is not a wallet_scan artifact",
            ));
        }
        if envelope.header.scope.chain_type != ChainType::Evm {
            return Err(wallet_artifact_format("chunk is not an EVM chain artifact"));
        }
        if envelope.header.range.kind != IndexedArtifactRangeKind::Block {
            return Err(wallet_artifact_format(
                "wallet_scan range is not block scoped",
            ));
        }

        let chunk_bounds = WalletScanChunkBounds::try_from(&chunk.descriptor)?;
        let checkpoint_block = chunk_bounds.checkpoint_block();
        let mut page = Self {
            transact_commitments: Vec::new(),
            shield_commitments: Vec::new(),
            legacy_encrypted_commitments: Vec::new(),
            legacy_generated_commitments: Vec::new(),
            nullifiers: Vec::new(),
            checkpoint_block,
            transact_rows: 0,
            shield_rows: 0,
            legacy_encrypted_rows: 0,
            legacy_generated_rows: 0,
            nullifier_rows: 0,
        };

        let mut row_count = 0_usize;
        for section in &envelope.header.sections {
            let payload = envelope
                .section_payload(section.section_id)
                .map_err(IndexedArtifactManifestError::from)
                .map_err(|err| wallet_artifact_error(&err))?;
            let mut cursor = WalletScanArtifactCursor::new(payload);
            match section.section_id {
                WALLET_TRANSACT_SECTION_ID => {
                    let (rows, decoded_rows) = cursor.read_transact_rows(chunk_bounds, bounds)?;
                    page.transact_rows = rows.len();
                    page.transact_commitments = rows;
                    row_count = row_count.saturating_add(decoded_rows);
                }
                WALLET_SHIELD_SECTION_ID => {
                    let (rows, decoded_rows) = cursor.read_shield_rows(chunk_bounds, bounds)?;
                    page.shield_rows = rows.len();
                    page.shield_commitments = rows;
                    row_count = row_count.saturating_add(decoded_rows);
                }
                WALLET_NULLIFIER_SECTION_ID => {
                    let (rows, decoded_rows) = cursor.read_nullifier_rows(chunk_bounds, bounds)?;
                    page.nullifier_rows = rows.len();
                    page.nullifiers = rows;
                    row_count = row_count.saturating_add(decoded_rows);
                }
                WALLET_LEGACY_ENCRYPTED_SECTION_ID => {
                    let (rows, decoded_rows) =
                        cursor.read_legacy_encrypted_rows(chunk_bounds, bounds)?;
                    page.legacy_encrypted_rows = rows.len();
                    page.legacy_encrypted_commitments = rows;
                    row_count = row_count.saturating_add(decoded_rows);
                }
                WALLET_LEGACY_GENERATED_SECTION_ID => {
                    let (rows, decoded_rows) =
                        cursor.read_legacy_generated_rows(chunk_bounds, bounds)?;
                    page.legacy_generated_rows = rows.len();
                    page.legacy_generated_commitments = rows;
                    row_count = row_count.saturating_add(decoded_rows);
                }
                other => {
                    return Err(wallet_artifact_format(format!(
                        "unknown wallet_scan section id {other}"
                    )));
                }
            }
            cursor.expect_eof("wallet_scan section")?;
        }

        if row_count as u64 != envelope.header.row_count {
            return Err(wallet_artifact_format(format!(
                "wallet_scan row count mismatch: expected {}, got {row_count}",
                envelope.header.row_count
            )));
        }
        Ok(page)
    }
}

impl TryFrom<&VerifiedIndexedArtifactChunk> for IndexedWalletPage {
    type Error = SyncError;

    fn try_from(chunk: &VerifiedIndexedArtifactChunk) -> Result<Self, Self::Error> {
        Self::decode_from_chunk(chunk, None)
    }
}

struct WalletScanArtifactCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> WalletScanArtifactCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read_transact_rows(
        &mut self,
        chunk_bounds: WalletScanChunkBounds,
        bounds: Option<WalletScanRowBounds>,
    ) -> Result<(Vec<IndexedTransactCommitmentInput>, usize), SyncError> {
        let count = self.read_count("transact count")?;
        let mut rows = Vec::new();
        for _ in 0..count {
            let source = self.read_source()?;
            let tree_number = self.read_u32("transact tree_number")?;
            let tree_position = self.read_u64("transact tree_position")?;
            let hash = U256::from_be_bytes(self.read_fixed_32("transact hash")?);
            let ciphertext =
                CommitmentCiphertext::abi_decode(&self.read_bytes("transact ciphertext")?)
                    .map_err(|err| {
                        wallet_artifact_format(format!("decode transact ciphertext: {err}"))
                    })?;
            chunk_bounds.validate_source(&source)?;
            if bounds.is_none_or(|bounds| bounds.contains(&source)) {
                rows.push(IndexedTransactCommitmentInput {
                    tree_number,
                    tree_position,
                    hash,
                    ciphertext: ciphertext.ciphertext,
                    blinded_sender_viewing_key: ciphertext.blindedSenderViewingKey,
                    blinded_receiver_viewing_key: ciphertext.blindedReceiverViewingKey,
                    annotation_data: ciphertext.annotationData,
                    memo: ciphertext.memo,
                    source,
                });
            }
        }
        Ok((rows, count))
    }

    fn read_shield_rows(
        &mut self,
        chunk_bounds: WalletScanChunkBounds,
        bounds: Option<WalletScanRowBounds>,
    ) -> Result<(Vec<IndexedShieldCommitmentInput>, usize), SyncError> {
        let count = self.read_count("shield count")?;
        let mut rows = Vec::new();
        for _ in 0..count {
            let source = self.read_source()?;
            let tree_number = self.read_u32("shield tree_number")?;
            let tree_position = self.read_u64("shield tree_position")?;
            let _hash = self.read_fixed_32("shield hash")?;
            let preimage = CommitmentPreimage::abi_decode(&self.read_bytes("shield preimage")?)
                .map_err(|err| wallet_artifact_format(format!("decode shield preimage: {err}")))?;
            let shield_ciphertext = ShieldCiphertext::abi_decode(
                &self.read_bytes("shield ciphertext")?,
            )
            .map_err(|err| wallet_artifact_format(format!("decode shield ciphertext: {err}")))?;
            chunk_bounds.validate_source(&source)?;
            if bounds.is_none_or(|bounds| bounds.contains(&source)) {
                rows.push(IndexedShieldCommitmentInput {
                    tree_number,
                    tree_position,
                    preimage,
                    shield_ciphertext,
                    source,
                });
            }
        }
        Ok((rows, count))
    }

    fn read_nullifier_rows(
        &mut self,
        chunk_bounds: WalletScanChunkBounds,
        bounds: Option<WalletScanRowBounds>,
    ) -> Result<(Vec<IndexedNullifierInput>, usize), SyncError> {
        let count = self.read_count("nullifier count")?;
        let mut rows = Vec::new();
        for _ in 0..count {
            let source = self.read_source()?;
            let tree_number = self.read_u32("nullifier tree_number")?;
            let nullifier = U256::from_be_bytes(self.read_fixed_32("nullifier")?);
            chunk_bounds.validate_source(&source)?;
            if bounds.is_none_or(|bounds| bounds.contains(&source)) {
                rows.push(IndexedNullifierInput {
                    tree_number,
                    nullifier,
                    source,
                });
            }
        }
        Ok((rows, count))
    }

    fn read_legacy_encrypted_rows(
        &mut self,
        chunk_bounds: WalletScanChunkBounds,
        bounds: Option<WalletScanRowBounds>,
    ) -> Result<(Vec<IndexedLegacyEncryptedCommitmentInput>, usize), SyncError> {
        let count = self.read_count("legacy encrypted count")?;
        let mut rows = Vec::new();
        for _ in 0..count {
            let source = self.read_source()?;
            let tree_number = self.read_u32("legacy encrypted tree_number")?;
            let tree_position = self.read_u64("legacy encrypted tree_position")?;
            let hash = U256::from_be_bytes(self.read_fixed_32("legacy encrypted hash")?);
            let ciphertext = LegacyCommitmentCiphertext::abi_decode(
                &self.read_bytes("legacy encrypted ciphertext")?,
            )
            .map_err(|err| {
                wallet_artifact_format(format!("decode legacy encrypted ciphertext: {err}"))
            })?;
            chunk_bounds.validate_source(&source)?;
            if bounds.is_none_or(|bounds| bounds.contains(&source)) {
                rows.push(IndexedLegacyEncryptedCommitmentInput {
                    tree_number,
                    tree_position,
                    hash,
                    ciphertext: ciphertext
                        .ciphertext
                        .map(|value| AlloyFixedBytes::from(value.to_be_bytes::<32>())),
                    ephemeral_keys: ciphertext
                        .ephemeralKeys
                        .map(|value| AlloyFixedBytes::from(value.to_be_bytes::<32>())),
                    memo: ciphertext
                        .memo
                        .into_iter()
                        .map(|value| AlloyFixedBytes::from(value.to_be_bytes::<32>()))
                        .collect(),
                    source,
                });
            }
        }
        Ok((rows, count))
    }

    fn read_legacy_generated_rows(
        &mut self,
        chunk_bounds: WalletScanChunkBounds,
        bounds: Option<WalletScanRowBounds>,
    ) -> Result<(Vec<IndexedLegacyGeneratedCommitmentInput>, usize), SyncError> {
        let count = self.read_count("legacy generated count")?;
        let mut rows = Vec::new();
        for _ in 0..count {
            let source = self.read_source()?;
            let tree_number = self.read_u32("legacy generated tree_number")?;
            let tree_position = self.read_u64("legacy generated tree_position")?;
            let _hash = self.read_fixed_32("legacy generated hash")?;
            let preimage = LegacyCommitmentPreimage::abi_decode(
                &self.read_bytes("legacy generated preimage")?,
            )
            .map_err(|err| {
                wallet_artifact_format(format!("decode legacy generated preimage: {err}"))
            })?;
            let encrypted_random = self.read_fixed_64("legacy generated encrypted_random")?;
            let encrypted_random_iv_tag: [u8; 32] = encrypted_random[..32]
                .try_into()
                .expect("encrypted random iv/tag slice length");
            let encrypted_random_data: [u8; 16] = encrypted_random[48..64]
                .try_into()
                .expect("encrypted random data slice length");
            chunk_bounds.validate_source(&source)?;
            if bounds.is_none_or(|bounds| bounds.contains(&source)) {
                rows.push(IndexedLegacyGeneratedCommitmentInput {
                    tree_number,
                    tree_position,
                    preimage,
                    encrypted_random: (
                        AlloyFixedBytes::from(encrypted_random_iv_tag),
                        AlloyFixedBytes::from(encrypted_random_data),
                    ),
                    source,
                });
            }
        }
        Ok((rows, count))
    }

    fn read_source(&mut self) -> Result<UtxoSource, SyncError> {
        let block_number = self.read_u64("source block_number")?;
        let block_timestamp = self.read_u64("source block_timestamp")?;
        let transaction_hash =
            AlloyFixedBytes::from(self.read_fixed_32("source transaction_hash")?);
        Ok(UtxoSource {
            tx_hash: transaction_hash,
            block_number,
            block_timestamp,
        })
    }

    fn read_count(&mut self, field: &'static str) -> Result<usize, SyncError> {
        usize::try_from(self.read_u64(field)?)
            .map_err(|_| wallet_artifact_format(format!("{field} overflows usize")))
    }

    fn read_u32(&mut self, field: &'static str) -> Result<u32, SyncError> {
        let bytes = self.read_exact(4, field)?;
        Ok(u32::from_le_bytes(
            bytes.try_into().expect("u32 read length"),
        ))
    }

    fn read_u64(&mut self, field: &'static str) -> Result<u64, SyncError> {
        let bytes = self.read_exact(8, field)?;
        Ok(u64::from_le_bytes(
            bytes.try_into().expect("u64 read length"),
        ))
    }

    fn read_bytes(&mut self, field: &'static str) -> Result<Vec<u8>, SyncError> {
        let length = usize::try_from(self.read_u32(field)?)
            .map_err(|_| wallet_artifact_format(format!("{field} length overflows usize")))?;
        Ok(self.read_exact(length, field)?.to_vec())
    }

    fn read_fixed_32(&mut self, field: &'static str) -> Result<[u8; 32], SyncError> {
        self.read_exact(32, field)?
            .try_into()
            .map_err(|_| wallet_artifact_format(format!("invalid fixed bytes in {field}")))
    }

    fn read_fixed_64(&mut self, field: &'static str) -> Result<[u8; 64], SyncError> {
        self.read_exact(64, field)?
            .try_into()
            .map_err(|_| wallet_artifact_format(format!("invalid fixed bytes in {field}")))
    }

    fn read_exact(&mut self, length: usize, field: &'static str) -> Result<&'a [u8], SyncError> {
        let end = self.position.checked_add(length).ok_or_else(|| {
            wallet_artifact_format(format!("wallet_scan artifact overflow in {field}"))
        })?;
        let value = self.bytes.get(self.position..end).ok_or_else(|| {
            wallet_artifact_format(format!("wallet_scan artifact ended while reading {field}"))
        })?;
        self.position = end;
        Ok(value)
    }

    fn expect_eof(&self, field: &'static str) -> Result<(), SyncError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(wallet_artifact_format(format!(
                "{field} has {} trailing bytes",
                self.bytes.len().saturating_sub(self.position)
            )))
        }
    }
}
