//! Amount statistics for a chain session: the indexer's signed manifest resolved through the
//! indexed artifact source's gateways, the verified snapshot kept in the public cache, and an
//! hourly refresh. Nothing here reads wallet state, and a failure only waits for the next
//! refresh.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use local_db::{DbError, DbStore};
use railgun_indexed_artifacts::AmountStatisticsError;
pub use railgun_indexed_artifacts::{
    AmountStatisticsCoveredBlock, AmountStatisticsSnapshot, RepeatedShieldAmount,
    RepeatedUnshieldAmount, ShieldValueBucketCount, TokenAmountStatistics, TreeShieldAmountCount,
    TreeShieldValueBuckets, amount_value_bucket,
};
use thiserror::Error;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::indexed_artifacts::{ChainScope, CompressionAlgorithm, IndexedArtifactManifestError};
use crate::runtime_admission::DbRuntimeLease;
use crate::trustless_artifacts::TrustlessArtifactError;
use crate::types::{ChainConfig, IndexedArtifactSourceConfig};

mod client;
mod store;

use client::{AmountStatisticsClient, FetchedAmountStatistics, decode_snapshot};
#[cfg(test)]
pub(crate) use store::AMOUNT_STATISTICS_TABLE;
pub(crate) use store::clear_amount_statistics;
use store::{
    AmountStatisticsSourceIdentity, StoredAmountStatistics, load_amount_statistics,
    replace_amount_statistics,
};

/// How often a chain session fetches amount statistics after the fetch at its start.
pub const AMOUNT_STATISTICS_REFRESH_INTERVAL: Duration = Duration::from_hours(1);
/// A held snapshot whose covered block is older than this is out of date.
pub const AMOUNT_STATISTICS_MAX_AGE: Duration = Duration::from_hours(6);

/// Whether a chain's amount statistics can be used, or why not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AmountStatisticsStatus {
    /// The chain has no indexed artifact source, or the source has no amount-statistics IPNS
    /// name.
    NotConfigured,
    /// A source is configured and no snapshot has been accepted yet.
    NotYetAvailable,
    /// The held snapshot's covered block is more than [`AMOUNT_STATISTICS_MAX_AGE`] old, or its
    /// timestamp is that far ahead of the local clock.
    OutOfDate,
    Available(Arc<AmountStatisticsSnapshot>),
}

#[derive(Debug, Error)]
pub(crate) enum AmountStatisticsRefreshError {
    #[error("amount statistics trustless retrieval failed: {message}")]
    Trustless { message: String },
    #[error(transparent)]
    Statistics(#[from] AmountStatisticsError),
    #[error(transparent)]
    Manifest(#[from] IndexedArtifactManifestError),
    #[error("amount statistics manifest has no entry for chain scope {scope}")]
    MissingChainScope { scope: String },
    #[error("unsupported amount statistics snapshot compression {0:?}")]
    UnsupportedCompression(CompressionAlgorithm),
    #[error("amount statistics snapshot byte size mismatch: expected {expected}, got {actual}")]
    SnapshotByteSizeMismatch { expected: u64, actual: u64 },
    #[error("amount statistics snapshot sha256 mismatch: expected {expected}, got {actual}")]
    SnapshotHashMismatch { expected: String, actual: String },
    #[error("amount statistics snapshot scope mismatch: expected {expected}, got {actual}")]
    SnapshotScopeMismatch { expected: String, actual: String },
    #[error(
        "amount statistics snapshot covers block {actual}, but its manifest entry names block {expected}"
    )]
    CoveredBlockMismatch { expected: u64, actual: u64 },
    #[error("amount statistics manifest has no valid candidate")]
    NoValidManifest,
    #[error("a newer amount statistics snapshot is already stored")]
    StoredSequenceIsNewer,
    #[error("amount statistics cache access failed")]
    Store(#[from] DbError),
    #[error("amount statistics cache record could not be encoded")]
    Encode(#[from] rmp_serde::encode::Error),
}

impl From<TrustlessArtifactError> for AmountStatisticsRefreshError {
    fn from(source: TrustlessArtifactError) -> Self {
        Self::Trustless {
            message: source.to_string(),
        }
    }
}

/// A chain's amount-statistics source. It follows the chain's indexed artifact source: the
/// same publisher key, gateways, gateway pool and manifest age limit.
#[derive(Debug, Clone)]
pub(crate) struct AmountStatisticsSource {
    pub(crate) ipns_name: String,
    pub(crate) artifacts: IndexedArtifactSourceConfig,
    pub(crate) scope: ChainScope,
}

impl AmountStatisticsSource {
    pub(crate) fn for_chain(chain: &ChainConfig) -> Option<Self> {
        let artifacts = chain.sync.indexed_artifact_source.as_ref()?;
        Some(Self {
            ipns_name: artifacts.amount_statistics_ipns_name.clone()?,
            artifacts: artifacts.clone(),
            scope: chain.indexed_artifact_scope(),
        })
    }

    fn identity(&self) -> AmountStatisticsSourceIdentity {
        AmountStatisticsSourceIdentity {
            ipns_name: self.ipns_name.clone(),
            publisher_key: self.artifacts.trusted_publisher_pubkey,
        }
    }
}

/// A chain session's amount-statistics source, its last accepted snapshot and its refresh
/// loop.
#[derive(Default)]
pub(crate) struct ChainAmountStatistics {
    source: Option<AmountStatisticsSource>,
    held: watch::Sender<Option<Arc<AmountStatisticsSnapshot>>>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl ChainAmountStatistics {
    pub(crate) fn for_chain(chain: &ChainConfig) -> Self {
        Self::new(AmountStatisticsSource::for_chain(chain))
    }

    pub(crate) fn new(source: Option<AmountStatisticsSource>) -> Self {
        Self {
            source,
            ..Self::default()
        }
    }

    /// Spawns the refresh loop, which loads the stored snapshot, fetches at once and then
    /// every [`AMOUNT_STATISTICS_REFRESH_INTERVAL`] until `cancel`. Spawns nothing when no
    /// source is configured.
    pub(crate) fn spawn_refresh(
        &self,
        db: Arc<DbStore>,
        http_client: reqwest::Client,
        cancel: CancellationToken,
        runtime_lease: Option<DbRuntimeLease>,
    ) {
        let Some(source) = self.source.clone() else {
            return;
        };
        let refresh = AmountStatisticsRefresh {
            client: AmountStatisticsClient::new(source, http_client),
            db,
            published: self.held.clone(),
            held: None,
            _runtime_lease: runtime_lease,
        };
        *self.task.lock().unwrap_or_else(PoisonError::into_inner) =
            Some(tokio::spawn(refresh.run(cancel)));
    }

    /// The refresh loop's task, which chain shutdown joins.
    pub(crate) const fn task(&self) -> &Mutex<Option<JoinHandle<()>>> {
        &self.task
    }

    pub(crate) fn status(&self, now: SystemTime) -> AmountStatisticsStatus {
        if self.source.is_none() {
            return AmountStatisticsStatus::NotConfigured;
        }
        let Some(snapshot) = self.held.borrow().clone() else {
            return AmountStatisticsStatus::NotYetAvailable;
        };
        if covered_block_is_current(snapshot.covered_block.timestamp, now) {
            AmountStatisticsStatus::Available(snapshot)
        } else {
            AmountStatisticsStatus::OutOfDate
        }
    }
}

/// Whether a covered block's timestamp is within [`AMOUNT_STATISTICS_MAX_AGE`] of `now`, in
/// either direction. A timestamp further ahead of the local clock is a publisher error, not a
/// fresh snapshot, so it never keeps the snapshot available.
fn covered_block_is_current(timestamp_secs: u64, now: SystemTime) -> bool {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(timestamp_secs))
        .is_some_and(|covered_at| match now.duration_since(covered_at) {
            Ok(age) => age <= AMOUNT_STATISTICS_MAX_AGE,
            Err(ahead) => ahead.duration() <= AMOUNT_STATISTICS_MAX_AGE,
        })
}

struct AmountStatisticsRefresh {
    client: AmountStatisticsClient,
    db: Arc<DbStore>,
    published: watch::Sender<Option<Arc<AmountStatisticsSnapshot>>>,
    /// The stored record behind the published snapshot.
    held: Option<StoredAmountStatistics>,
    /// Keeps runtime admission held while the loop can still write; dropped when `run` returns.
    _runtime_lease: Option<DbRuntimeLease>,
}

impl AmountStatisticsRefresh {
    async fn run(mut self, cancel: CancellationToken) {
        self.load_stored();
        let mut interval = tokio::time::interval(AMOUNT_STATISTICS_REFRESH_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = cancel.cancelled() => return,
                _ = interval.tick() => {}
            }
            let result = tokio::select! {
                () = cancel.cancelled() => return,
                result = self.refresh() => result,
            };
            if let Err(error) = result {
                warn!(
                    ?error,
                    chain_id = self.client.source().scope.chain_id,
                    "amount statistics refresh failed; retrying at the next interval"
                );
            }
        }
    }

    /// Publishes the snapshot stored by an earlier session, so it is available before the
    /// first fetch completes.
    fn load_stored(&mut self) {
        let source = self.client.source();
        let chain_id = source.scope.chain_id;
        let record = match load_amount_statistics(&self.db, &source.scope, &source.identity()) {
            Ok(Some(record)) => record,
            Ok(None) => return,
            Err(error) => {
                warn!(
                    ?error,
                    chain_id, "stored amount statistics could not be read"
                );
                return;
            }
        };
        match decode_snapshot(&record.snapshot, &source.scope) {
            Ok(snapshot) => self.hold(record, Arc::new(snapshot)),
            Err(error) => warn!(?error, chain_id, "stored amount statistics are unusable"),
        }
    }

    async fn refresh(&mut self) -> Result<(), AmountStatisticsRefreshError> {
        let fetched = self
            .client
            .fetch(self.held.as_ref(), SystemTime::now())
            .await?;
        match fetched {
            FetchedAmountStatistics::Held { sequence } => self.advance_held_sequence(sequence),
            FetchedAmountStatistics::New { record, snapshot } => {
                if !replace_amount_statistics(&self.db, &self.client.source().scope, &record)? {
                    return Err(AmountStatisticsRefreshError::StoredSequenceIsNewer);
                }
                self.hold(record, snapshot);
                Ok(())
            }
        }
    }

    /// Stores a newer manifest sequence that names the held snapshot, so the rollback floor
    /// survives a restart.
    fn advance_held_sequence(&mut self, sequence: u64) -> Result<(), AmountStatisticsRefreshError> {
        let Some(held) = self.held.as_mut().filter(|held| held.sequence < sequence) else {
            return Ok(());
        };
        // Persist first: a failed write must not raise the floor only in memory.
        let advanced = StoredAmountStatistics {
            sequence,
            ..held.clone()
        };
        replace_amount_statistics(&self.db, &self.client.source().scope, &advanced)?;
        *held = advanced;
        Ok(())
    }

    fn hold(&mut self, record: StoredAmountStatistics, snapshot: Arc<AmountStatisticsSnapshot>) {
        self.held = Some(record);
        self.published.send_replace(Some(snapshot));
    }
}

#[cfg(test)]
mod tests;
