use tokio::sync::watch;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncProgressStage {
    SynchronizingCommitments,
    PreparingUtxoIndex,
    IndexingUtxos,
}

impl SyncProgressStage {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SynchronizingCommitments => "Synchronizing commitments",
            Self::PreparingUtxoIndex => "Preparing UTXO index",
            Self::IndexingUtxos => "Indexing UTXOs",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncProgressUnit {
    Block,
    ArtifactPreparation,
    ArtifactChunk { completed: u64, total: u64 },
    ArtifactApplied,
    CommitmentTail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncProgressUpdate {
    pub stage: SyncProgressStage,
    pub unit: SyncProgressUnit,
    pub source: Option<PublicScanSource>,
    pub start_block: u64,
    pub current_block: u64,
    pub target_block: u64,
}

impl SyncProgressUpdate {
    #[must_use]
    pub const fn new(
        stage: SyncProgressStage,
        start_block: u64,
        current_block: u64,
        target_block: u64,
    ) -> Self {
        Self::with_unit(
            stage,
            SyncProgressUnit::Block,
            start_block,
            current_block,
            target_block,
        )
    }

    #[must_use]
    pub const fn artifact_preparation(
        stage: SyncProgressStage,
        current_progress: u64,
        target_progress: u64,
    ) -> Self {
        Self::with_unit(
            stage,
            SyncProgressUnit::ArtifactPreparation,
            0,
            current_progress,
            target_progress,
        )
    }

    #[must_use]
    pub const fn artifact_chunk(
        stage: SyncProgressStage,
        current_progress: u64,
        target_progress: u64,
        completed_chunks: u64,
        total_chunks: u64,
    ) -> Self {
        Self::with_unit(
            stage,
            SyncProgressUnit::ArtifactChunk {
                completed: completed_chunks,
                total: total_chunks,
            },
            0,
            current_progress,
            target_progress,
        )
    }

    #[must_use]
    pub const fn artifact_applied(stage: SyncProgressStage) -> Self {
        Self::with_unit(stage, SyncProgressUnit::ArtifactApplied, 0, 100, 100)
    }

    #[must_use]
    pub const fn commitment_tail(start_block: u64, current_block: u64, target_block: u64) -> Self {
        Self::with_unit(
            SyncProgressStage::SynchronizingCommitments,
            SyncProgressUnit::CommitmentTail,
            start_block,
            current_block,
            target_block,
        )
    }

    #[must_use]
    pub const fn with_unit(
        stage: SyncProgressStage,
        unit: SyncProgressUnit,
        start_block: u64,
        current_block: u64,
        target_block: u64,
    ) -> Self {
        Self {
            stage,
            unit,
            source: None,
            start_block,
            current_block,
            target_block,
        }
    }

    #[must_use]
    pub const fn with_source(mut self, source: PublicScanSource) -> Self {
        self.source = Some(source);
        self
    }

    #[must_use]
    pub const fn percent(self) -> u8 {
        if self.target_block <= self.start_block {
            return 100;
        }
        let current_block = if self.current_block < self.start_block {
            self.start_block
        } else if self.current_block > self.target_block {
            self.target_block
        } else {
            self.current_block
        };
        let completed = current_block - self.start_block;
        let total = self.target_block - self.start_block;
        ((completed.saturating_mul(100)) / total) as u8
    }
}

pub type SyncProgressSender = watch::Sender<Option<SyncProgressUpdate>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletIndexedCatchUpSource {
    Squid,
    IndexedArtifacts,
}

impl WalletIndexedCatchUpSource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Squid => "squid",
            Self::IndexedArtifacts => "indexed_artifacts",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicScanSource {
    CachedCoverage,
    IndexedArtifacts,
    Squid,
    Rpc,
    ArchiveRpc,
}

impl PublicScanSource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CachedCoverage => "cached_coverage",
            Self::IndexedArtifacts => "indexed_artifacts",
            Self::Squid => "squid",
            Self::Rpc => "rpc",
            Self::ArchiveRpc => "archive_rpc",
        }
    }
}

impl From<WalletIndexedCatchUpSource> for PublicScanSource {
    fn from(source: WalletIndexedCatchUpSource) -> Self {
        match source {
            WalletIndexedCatchUpSource::Squid => Self::Squid,
            WalletIndexedCatchUpSource::IndexedArtifacts => Self::IndexedArtifacts,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletIndexedCatchUpStatus {
    pub source: WalletIndexedCatchUpSource,
    pub from_block: u64,
    pub target_block: u64,
}
