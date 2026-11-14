use std::collections::HashMap;
use std::sync::Arc;

use alloy_rpc_types_eth::Log;
use railgun_wallet::scan::{WalletScanError, WalletScanInputRows};

use super::{PublicScanSource, WalletIndexedCatchUpSource};

#[derive(Debug, Clone)]
pub struct LogBatch {
    pub from_block: u64,
    pub to_block: u64,
    pub logs: Vec<Log>,
    pub block_timestamps: HashMap<u64, u64>,
    pub to_block_hash: Option<[u8; 32]>,
    pub read_scope: PublicScanReadScope,
}

pub type SharedLogBatch = Arc<LogBatch>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicDataPlaneEpoch {
    pub value: u64,
}

impl PublicDataPlaneEpoch {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self { value }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicScanReadScope {
    epoch: PublicDataPlaneEpoch,
}

impl PublicScanReadScope {
    #[must_use]
    pub(crate) const fn new(epoch: PublicDataPlaneEpoch) -> Self {
        Self { epoch }
    }

    #[must_use]
    pub const fn epoch(self) -> PublicDataPlaneEpoch {
        self.epoch
    }
}

#[derive(Debug, Clone)]
pub(crate) enum WalletScanRowsPayload {
    Rows(Box<WalletScanInputRows>),
    EmptyCoverage,
    #[cfg(test)]
    IndexedDeltaForTest {
        delta: Box<railgun_wallet::scan::WalletLogDelta>,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct WalletScanRows {
    pub(crate) from_block: u64,
    pub(crate) to_block: u64,
    pub(crate) source: PublicScanSource,
    pub(crate) to_block_hash: Option<[u8; 32]>,
    pub(crate) payload: WalletScanRowsPayload,
}

impl WalletScanRows {
    #[must_use]
    pub(crate) const fn new(
        from_block: u64,
        to_block: u64,
        source: PublicScanSource,
        to_block_hash: Option<[u8; 32]>,
        payload: WalletScanRowsPayload,
    ) -> Self {
        Self {
            from_block,
            to_block,
            source,
            to_block_hash,
            payload,
        }
    }

    #[must_use]
    pub(crate) const fn covers(&self, from_block: u64, to_block: u64) -> bool {
        self.from_block == from_block
            && self.to_block == to_block
            && match &self.payload {
                WalletScanRowsPayload::Rows(_) | WalletScanRowsPayload::EmptyCoverage => true,
                #[cfg(test)]
                WalletScanRowsPayload::IndexedDeltaForTest { .. } => true,
            }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct WalletScanApply {
    pub(crate) from_block: u64,
    pub(crate) to_block: u64,
    pub(crate) rows: WalletScanRows,
    pub(crate) read_scope: PublicScanReadScope,
}

impl WalletScanApply {
    #[must_use]
    pub(crate) const fn new(
        from_block: u64,
        to_block: u64,
        rows: WalletScanRows,
        read_scope: PublicScanReadScope,
    ) -> Self {
        Self {
            from_block,
            to_block,
            rows,
            read_scope,
        }
    }

    #[must_use]
    pub(crate) fn rows(
        from_block: u64,
        to_block: u64,
        rows: WalletScanInputRows,
        read_scope: PublicScanReadScope,
        source: PublicScanSource,
        to_block_hash: Option<[u8; 32]>,
    ) -> Self {
        Self::new(
            from_block,
            to_block,
            WalletScanRows::new(
                from_block,
                to_block,
                source,
                to_block_hash,
                WalletScanRowsPayload::Rows(Box::new(rows)),
            ),
            read_scope,
        )
    }

    pub(crate) fn rows_from_log_batch(
        from_block: u64,
        to_block: u64,
        batch: &SharedLogBatch,
        source: PublicScanSource,
    ) -> Result<Self, WalletScanError> {
        let read_scope = batch.read_scope;
        let filtered_logs: Vec<_> = batch
            .logs
            .iter()
            .filter(|log| {
                log.block_number
                    .is_some_and(|block| block >= from_block && block <= to_block)
            })
            .cloned()
            .collect();
        let rows = WalletScanInputRows::from_logs(&filtered_logs, &batch.block_timestamps)?;
        let to_block_hash = if batch.to_block == to_block {
            batch.to_block_hash
        } else {
            None
        };
        Ok(Self::rows(
            from_block,
            to_block,
            rows,
            read_scope,
            source,
            to_block_hash,
        ))
    }

    #[must_use]
    pub(crate) fn indexed_rows(
        from_block: u64,
        to_block: u64,
        rows: WalletScanInputRows,
        read_scope: PublicScanReadScope,
        source: WalletIndexedCatchUpSource,
    ) -> Self {
        Self::rows(from_block, to_block, rows, read_scope, source.into(), None)
    }

    #[must_use]
    pub(crate) const fn empty_coverage(
        from_block: u64,
        to_block: u64,
        read_scope: PublicScanReadScope,
        source: PublicScanSource,
        to_block_hash: Option<[u8; 32]>,
    ) -> Self {
        Self::new(
            from_block,
            to_block,
            WalletScanRows::new(
                from_block,
                to_block,
                source,
                to_block_hash,
                WalletScanRowsPayload::EmptyCoverage,
            ),
            read_scope,
        )
    }
}

#[cfg(test)]
impl WalletScanApply {
    #[must_use]
    pub(crate) fn indexed_delta_for_test(
        from_block: u64,
        to_block: u64,
        delta: railgun_wallet::scan::WalletLogDelta,
        read_scope: PublicScanReadScope,
        source: WalletIndexedCatchUpSource,
    ) -> Self {
        Self::new(
            from_block,
            to_block,
            WalletScanRows::new(
                from_block,
                to_block,
                source.into(),
                None,
                WalletScanRowsPayload::IndexedDeltaForTest {
                    delta: Box::new(delta),
                },
            ),
            read_scope,
        )
    }
}
