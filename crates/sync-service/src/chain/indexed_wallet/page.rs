//! Wallet-scan rows for one block range, and the Squid GraphQL page fetch.

use super::coverage::source_in_range;
use super::{
    DEFAULT_PAGE_SIZE, IndexedLegacyEncryptedCommitmentInput,
    IndexedLegacyGeneratedCommitmentInput, IndexedNullifierInput, IndexedShieldCommitmentInput,
    IndexedTransactCommitmentInput, IndexedWalletPageKind, QuickSyncClient, SyncError,
    WalletScanInputRows,
};

pub(in crate::chain) struct IndexedWalletPage {
    pub(in crate::chain) transact_commitments: Vec<IndexedTransactCommitmentInput>,
    pub(in crate::chain) shield_commitments: Vec<IndexedShieldCommitmentInput>,
    pub(in crate::chain) legacy_encrypted_commitments: Vec<IndexedLegacyEncryptedCommitmentInput>,
    pub(in crate::chain) legacy_generated_commitments: Vec<IndexedLegacyGeneratedCommitmentInput>,
    pub(in crate::chain) nullifiers: Vec<IndexedNullifierInput>,
    pub(in crate::chain) checkpoint_block: u64,
    pub(in crate::chain) transact_rows: usize,
    pub(in crate::chain) shield_rows: usize,
    pub(in crate::chain) legacy_encrypted_rows: usize,
    pub(in crate::chain) legacy_generated_rows: usize,
    pub(in crate::chain) nullifier_rows: usize,
}

impl IndexedWalletPage {
    pub(in crate::chain) const fn row_count(&self) -> usize {
        self.transact_commitments.len()
            + self.shield_commitments.len()
            + self.legacy_encrypted_commitments.len()
            + self.legacy_generated_commitments.len()
            + self.nullifiers.len()
    }

    pub(in crate::chain) fn into_scan_rows(self) -> WalletScanInputRows {
        WalletScanInputRows {
            transact_commitments: self.transact_commitments,
            shield_commitments: self.shield_commitments,
            legacy_encrypted_commitments: self.legacy_encrypted_commitments,
            legacy_generated_commitments: self.legacy_generated_commitments,
            nullifiers: self.nullifiers,
            commitment_observations: Vec::new(),
        }
    }

    async fn fetch_modern(
        client: &QuickSyncClient,
        from_block: u64,
        to_block: u64,
    ) -> Result<Self, SyncError> {
        let page = client
            .fetch_indexed_wallet_page(from_block, to_block, DEFAULT_PAGE_SIZE)
            .await?;
        let transact = page.transact_commitments;
        let shields = page.shield_commitments;
        let nullifiers = page.nullifiers;
        let page_size = DEFAULT_PAGE_SIZE.get();
        let transact_checkpoint = complete_stream_checkpoint(
            transact.len(),
            page_size,
            to_block,
            transact.iter().map(|item| item.block_number.to()),
        );
        let shield_checkpoint = complete_stream_checkpoint(
            shields.len(),
            page_size,
            to_block,
            shields.iter().map(|item| item.block_number.to()),
        );
        let nullifier_checkpoint = complete_stream_checkpoint(
            nullifiers.len(),
            page_size,
            to_block,
            nullifiers.iter().map(|item| item.block_number.to()),
        );
        let checkpoint_block = transact_checkpoint
            .min(shield_checkpoint)
            .min(nullifier_checkpoint);
        if checkpoint_block < from_block {
            return Err(SyncError::UnexpectedFormat(format!(
                "indexed wallet page is incomplete at block {from_block}; reduce page range or increase page size"
            )));
        }

        let transact_rows = transact.len();
        let shield_rows = shields.len();
        let nullifier_rows = nullifiers.len();
        let transact_commitments = transact
            .into_iter()
            .filter(|item| item.block_number.to::<u64>() <= checkpoint_block)
            .map(Into::into)
            .collect();
        let shield_commitments = shields
            .into_iter()
            .filter(|item| item.block_number.to::<u64>() <= checkpoint_block)
            .map(Into::into)
            .collect();
        let nullifiers = nullifiers
            .into_iter()
            .filter(|item| item.block_number.to::<u64>() <= checkpoint_block)
            .map(Into::into)
            .collect();

        Ok(Self {
            transact_commitments,
            shield_commitments,
            legacy_encrypted_commitments: Vec::new(),
            legacy_generated_commitments: Vec::new(),
            nullifiers,
            checkpoint_block,
            transact_rows,
            shield_rows,
            legacy_encrypted_rows: 0,
            legacy_generated_rows: 0,
            nullifier_rows,
        })
    }

    async fn fetch_legacy(
        client: &QuickSyncClient,
        from_block: u64,
        to_block: u64,
    ) -> Result<Self, SyncError> {
        let page = client
            .fetch_indexed_legacy_wallet_page(from_block, to_block, DEFAULT_PAGE_SIZE)
            .await?;
        let legacy_encrypted = page.legacy_encrypted_commitments;
        let legacy_generated = page.legacy_generated_commitments;
        let nullifiers = page.nullifiers;
        let page_size = DEFAULT_PAGE_SIZE.get();
        let encrypted_checkpoint = complete_stream_checkpoint(
            legacy_encrypted.len(),
            page_size,
            to_block,
            legacy_encrypted.iter().map(|item| item.block_number.to()),
        );
        let generated_checkpoint = complete_stream_checkpoint(
            legacy_generated.len(),
            page_size,
            to_block,
            legacy_generated.iter().map(|item| item.block_number.to()),
        );
        let nullifier_checkpoint = complete_stream_checkpoint(
            nullifiers.len(),
            page_size,
            to_block,
            nullifiers.iter().map(|item| item.block_number.to()),
        );
        let checkpoint_block = encrypted_checkpoint
            .min(generated_checkpoint)
            .min(nullifier_checkpoint);
        if checkpoint_block < from_block {
            return Err(SyncError::UnexpectedFormat(format!(
                "indexed legacy wallet page is incomplete at block {from_block}; reduce page range or increase page size"
            )));
        }

        let legacy_encrypted_rows = legacy_encrypted.len();
        let legacy_generated_rows = legacy_generated.len();
        let nullifier_rows = nullifiers.len();
        let legacy_encrypted_commitments = legacy_encrypted
            .into_iter()
            .filter(|item| item.block_number.to::<u64>() <= checkpoint_block)
            .map(Into::into)
            .collect();
        let legacy_generated_commitments = legacy_generated
            .into_iter()
            .filter(|item| item.block_number.to::<u64>() <= checkpoint_block)
            .map(Into::into)
            .collect();
        let nullifiers = nullifiers
            .into_iter()
            .filter(|item| item.block_number.to::<u64>() <= checkpoint_block)
            .map(Into::into)
            .collect();

        Ok(Self {
            transact_commitments: Vec::new(),
            shield_commitments: Vec::new(),
            legacy_encrypted_commitments,
            legacy_generated_commitments,
            nullifiers,
            checkpoint_block,
            transact_rows: 0,
            shield_rows: 0,
            legacy_encrypted_rows,
            legacy_generated_rows,
            nullifier_rows,
        })
    }

    pub(in crate::chain) async fn fetch(
        client: &QuickSyncClient,
        page_kind: IndexedWalletPageKind,
        from_block: u64,
        to_block: u64,
    ) -> Result<Self, SyncError> {
        match page_kind {
            IndexedWalletPageKind::Legacy => Self::fetch_legacy(client, from_block, to_block).await,
            IndexedWalletPageKind::Modern => Self::fetch_modern(client, from_block, to_block).await,
        }
    }

    pub(super) const fn empty(checkpoint_block: u64) -> Self {
        Self {
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
        }
    }

    pub(super) fn extend_filtered_from(&mut self, source: &Self, from_block: u64, to_block: u64) {
        self.transact_commitments.extend(
            source
                .transact_commitments
                .iter()
                .filter(|row| source_in_range(&row.source, from_block, to_block))
                .cloned(),
        );
        self.shield_commitments.extend(
            source
                .shield_commitments
                .iter()
                .filter(|row| source_in_range(&row.source, from_block, to_block))
                .cloned(),
        );
        self.legacy_encrypted_commitments.extend(
            source
                .legacy_encrypted_commitments
                .iter()
                .filter(|row| source_in_range(&row.source, from_block, to_block))
                .cloned(),
        );
        self.legacy_generated_commitments.extend(
            source
                .legacy_generated_commitments
                .iter()
                .filter(|row| source_in_range(&row.source, from_block, to_block))
                .cloned(),
        );
        self.nullifiers.extend(
            source
                .nullifiers
                .iter()
                .filter(|row| source_in_range(&row.source, from_block, to_block))
                .cloned(),
        );
    }

    pub(super) const fn refresh_row_counts(&mut self) {
        self.transact_rows = self.transact_commitments.len();
        self.shield_rows = self.shield_commitments.len();
        self.legacy_encrypted_rows = self.legacy_encrypted_commitments.len();
        self.legacy_generated_rows = self.legacy_generated_commitments.len();
        self.nullifier_rows = self.nullifiers.len();
    }
}

pub(in crate::chain) fn complete_stream_checkpoint<I>(
    row_count: usize,
    page_size: usize,
    target_block: u64,
    block_numbers: I,
) -> u64
where
    I: Iterator<Item = u64>,
{
    if row_count < page_size {
        return target_block;
    }
    block_numbers
        .max()
        .unwrap_or(target_block)
        .saturating_sub(1)
}
