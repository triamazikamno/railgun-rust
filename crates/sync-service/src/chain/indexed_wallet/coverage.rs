//! Wallet-scan artifact coverage and checkpoint-block arithmetic.

use super::{SyncError, UtxoSource, wallet_artifact_format};

use crate::indexed_artifacts::{IndexedArtifactDescriptor, IndexedArtifactStreamCoverage};

#[derive(Default)]
pub(super) struct WalletScanArtifactCoverage {
    pub(super) ranges: Vec<WalletScanCoverageRange>,
}

impl WalletScanArtifactCoverage {
    pub(super) fn from_coverage(
        coverage_ranges: &[IndexedArtifactStreamCoverage],
    ) -> Result<Self, SyncError> {
        let mut coverage = Self::default();
        for range in coverage_ranges {
            coverage.add_range(range)?;
        }
        Ok(coverage)
    }

    fn add_range(&mut self, coverage: &IndexedArtifactStreamCoverage) -> Result<(), SyncError> {
        self.ranges
            .push(WalletScanCoverageRange::try_from(coverage)?);
        self.ranges.sort_by_key(|range| (range.start, range.end));
        Ok(())
    }

    pub(super) fn checkpoint_for_range(
        &self,
        from_block: u64,
        target_block: u64,
    ) -> Result<WalletScanCoverageStatus, SyncError> {
        let mut next_start = from_block;
        let mut checkpoint = None;
        for range in &self.ranges {
            if range.end < next_start {
                continue;
            }
            if range.start > next_start {
                break;
            }
            let range_end = range.end.min(target_block);
            if range.checkpoint_block < next_start {
                return Ok(WalletScanCoverageStatus::Exhausted {
                    checkpoint_block: checkpoint.map_or(range.checkpoint_block, |current: u64| {
                        current.max(range.checkpoint_block)
                    }),
                });
            }
            let range_checkpoint = range.checkpoint_block.min(range_end);
            checkpoint = Some(checkpoint.map_or(range_checkpoint, |current: u64| {
                current.max(range_checkpoint)
            }));
            if range_checkpoint < range_end {
                return Ok(WalletScanCoverageStatus::Available {
                    checkpoint_block: range_checkpoint,
                });
            }
            if range_end >= target_block {
                return Ok(WalletScanCoverageStatus::Available {
                    checkpoint_block: target_block,
                });
            }
            next_start = range_end.saturating_add(1);
        }

        checkpoint.map_or_else(
            || {
                Err(wallet_artifact_format(format!(
                    "wallet_scan artifact coverage does not include requested block {from_block}"
                )))
            },
            |checkpoint_block| Ok(WalletScanCoverageStatus::Available { checkpoint_block }),
        )
    }
}

pub(super) fn wallet_scan_artifact_target_block(
    coverage: &WalletScanArtifactCoverage,
    chunk_descriptors: &[IndexedArtifactDescriptor],
    from_block: u64,
    requested_target_block: u64,
) -> Result<Option<u64>, SyncError> {
    let mut target_block =
        match coverage.checkpoint_for_range(from_block, requested_target_block)? {
            WalletScanCoverageStatus::Available { checkpoint_block }
            | WalletScanCoverageStatus::Exhausted { checkpoint_block } => checkpoint_block,
        };
    if target_block < from_block {
        return Ok(None);
    }

    for descriptor in chunk_descriptors {
        if !descriptor.range.intersects(from_block, target_block) {
            continue;
        }
        let bounds = WalletScanChunkBounds::try_from(descriptor)?;
        if bounds.checkpoint_block < bounds.range_end {
            target_block = target_block.min(bounds.checkpoint_block);
        }
    }

    Ok((target_block >= from_block).then_some(target_block))
}

#[derive(Clone, Copy)]
pub(super) enum WalletScanCoverageStatus {
    Available { checkpoint_block: u64 },
    Exhausted { checkpoint_block: u64 },
}

#[derive(Clone, Copy)]
pub(super) struct WalletScanCoverageRange {
    pub(super) start: u64,
    pub(super) end: u64,
    pub(super) checkpoint_block: u64,
}

impl TryFrom<&IndexedArtifactStreamCoverage> for WalletScanCoverageRange {
    type Error = SyncError;

    fn try_from(coverage: &IndexedArtifactStreamCoverage) -> Result<Self, Self::Error> {
        let checkpoint_block = wallet_scan_coverage_checkpoint_block(coverage)?;
        Ok(Self {
            start: coverage.range.start,
            end: coverage.range.end,
            checkpoint_block,
        })
    }
}

#[derive(Clone, Copy)]
pub(super) struct WalletScanChunkBounds {
    range_start: u64,
    range_end: u64,
    checkpoint_block: u64,
}

impl TryFrom<&IndexedArtifactDescriptor> for WalletScanChunkBounds {
    type Error = SyncError;

    fn try_from(descriptor: &IndexedArtifactDescriptor) -> Result<Self, Self::Error> {
        let checkpoint_block = wallet_scan_descriptor_checkpoint_block(descriptor, "chunk")?;
        Ok(Self {
            range_start: descriptor.range.start,
            range_end: descriptor.range.end,
            checkpoint_block,
        })
    }
}

impl WalletScanChunkBounds {
    pub(super) const fn checkpoint_block(self) -> u64 {
        self.checkpoint_block
    }

    pub(super) fn validate_source(self, source: &UtxoSource) -> Result<(), SyncError> {
        if !source_in_range(source, self.range_start, self.range_end) {
            return Err(wallet_artifact_format(format!(
                "wallet_scan row source block {} is outside chunk block range {}-{}",
                source.block_number, self.range_start, self.range_end
            )));
        }
        if source.block_number > self.checkpoint_block {
            return Err(wallet_artifact_format(format!(
                "wallet_scan row source block {} exceeds checkpoint block {}",
                source.block_number, self.checkpoint_block
            )));
        }
        Ok(())
    }
}

fn wallet_scan_descriptor_checkpoint_block(
    descriptor: &IndexedArtifactDescriptor,
    descriptor_kind: &str,
) -> Result<u64, SyncError> {
    let checkpoint_block = descriptor
        .metadata
        .checkpoint_block
        .unwrap_or(descriptor.range.end);
    if checkpoint_block > descriptor.range.end {
        return Err(wallet_artifact_format(format!(
            "wallet_scan {descriptor_kind} checkpoint block {checkpoint_block} exceeds range end {}",
            descriptor.range.end
        )));
    }
    if checkpoint_block < descriptor.range.start {
        return Err(wallet_artifact_format(format!(
            "wallet_scan {descriptor_kind} checkpoint block {checkpoint_block} is before range start {}",
            descriptor.range.start
        )));
    }
    Ok(checkpoint_block)
}

fn wallet_scan_coverage_checkpoint_block(
    coverage: &IndexedArtifactStreamCoverage,
) -> Result<u64, SyncError> {
    let checkpoint_block = coverage.checkpoint_block.unwrap_or(coverage.range.end);
    if checkpoint_block > coverage.range.end {
        return Err(wallet_artifact_format(format!(
            "wallet_scan coverage checkpoint block {checkpoint_block} exceeds range end {}",
            coverage.range.end
        )));
    }
    if checkpoint_block < coverage.range.start {
        return Err(wallet_artifact_format(format!(
            "wallet_scan coverage checkpoint block {checkpoint_block} is before range start {}",
            coverage.range.start
        )));
    }
    Ok(checkpoint_block)
}

pub(super) const fn source_in_range(source: &UtxoSource, from_block: u64, to_block: u64) -> bool {
    source.block_number >= from_block && source.block_number <= to_block
}

#[cfg(test)]
impl WalletScanArtifactCoverage {
    pub(super) fn add_descriptor(
        &mut self,
        descriptor: &IndexedArtifactDescriptor,
    ) -> Result<(), SyncError> {
        self.add_range(&IndexedArtifactStreamCoverage::from(descriptor))
    }
}
