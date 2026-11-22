use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use alloy::primitives::FixedBytes;
use ed25519_dalek::SigningKey;
use local_db::DbConfig;
use railgun_indexed_artifacts::{
    AMOUNT_STATISTICS_MANIFEST_FORMAT_VERSION, AMOUNT_STATISTICS_MAX_COMPRESSED_BYTES,
    AMOUNT_STATISTICS_SNAPSHOT_ENCODING_VERSION, AmountStatisticsChainEntry,
    AmountStatisticsManifest, AmountStatisticsManifestEnvelope, AmountStatisticsSnapshotDescriptor,
    PublisherIdentity, encode_amount_statistics_snapshot,
};
use sha2::{Digest, Sha256};

use super::*;
use crate::indexed_artifacts::format_scope;
use crate::indexed_artifacts::tests::{
    ManifestGateway, car_bytes, config, ipns_name, ipns_record, raw_cid, scope, test_ipns_keypair,
    yield_until,
};
use crate::runtime_admission::DbRuntimeOwnerKind;

const COVERED_AT_SECS: u64 = 1_700_000_000;

static TEMP_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

#[test]
fn covered_block_far_ahead_of_the_clock_is_not_current() {
    let now = UNIX_EPOCH + Duration::from_secs(COVERED_AT_SECS);
    let max_age_secs = AMOUNT_STATISTICS_MAX_AGE.as_secs();
    assert!(covered_block_is_current(COVERED_AT_SECS + 5, now));
    assert!(covered_block_is_current(
        COVERED_AT_SECS + max_age_secs,
        now
    ));
    assert!(!covered_block_is_current(
        COVERED_AT_SECS + max_age_secs + 1,
        now
    ));
    // A timestamp in milliseconds, and one that overflows `SystemTime`.
    assert!(!covered_block_is_current(COVERED_AT_SECS * 1000, now));
    assert!(!covered_block_is_current(u64::MAX, now));
}

#[tokio::test]
async fn manifest_from_an_untrusted_key_is_rejected() {
    let snapshot = snapshot_for(scope());
    let bytes = encoded(&snapshot);
    let untrusted = SigningKey::from_bytes(&[8; 32]);
    let gateway = StatisticsGateway::spawn(
        envelope_bytes(&untrusted, 1, entry_for(&snapshot, &bytes)),
        bytes,
    );

    let error = gateway.fetch().await.expect_err("untrusted manifest");

    assert!(matches!(
        error,
        AmountStatisticsRefreshError::Statistics(
            AmountStatisticsError::PublisherKeyMismatch { .. }
        )
    ));
    assert_eq!(gateway.snapshot_requests(), 0);
}

#[tokio::test]
async fn snapshot_bytes_must_match_the_descriptor() {
    let snapshot = snapshot_for(scope());
    let bytes = encoded(&snapshot);
    let mut entry = entry_for(&snapshot, &bytes);
    entry.snapshot.sha256 = FixedBytes::from([0x22; 32]);
    let gateway = StatisticsGateway::spawn(envelope_bytes(&signing_key(), 1, entry), bytes);

    let error = gateway.fetch().await.expect_err("mismatched snapshot");

    assert!(matches!(
        error,
        AmountStatisticsRefreshError::SnapshotHashMismatch { .. }
    ));
    assert_eq!(gateway.snapshot_requests(), 1);
}

#[tokio::test]
async fn entries_and_snapshots_for_another_chain_are_rejected() {
    let other_snapshot = snapshot_for(ChainScope {
        chain_id: 137,
        ..scope()
    });
    let other_bytes = encoded(&other_snapshot);

    let other_entry_only = StatisticsGateway::spawn(
        envelope_bytes(&signing_key(), 1, entry_for(&other_snapshot, &other_bytes)),
        other_bytes.clone(),
    );
    let error = other_entry_only
        .fetch()
        .await
        .expect_err("no entry for this chain");
    assert!(matches!(
        error,
        AmountStatisticsRefreshError::MissingChainScope { .. }
    ));
    assert_eq!(other_entry_only.snapshot_requests(), 0);

    let mut entry = entry_for(&other_snapshot, &other_bytes);
    entry.scope = scope();
    let other_snapshot_scope =
        StatisticsGateway::spawn(envelope_bytes(&signing_key(), 1, entry), other_bytes);
    let error = other_snapshot_scope
        .fetch()
        .await
        .expect_err("snapshot for another chain");
    assert!(matches!(
        error,
        AmountStatisticsRefreshError::SnapshotScopeMismatch { .. }
    ));
}

#[tokio::test]
async fn oversized_snapshot_is_not_fetched() {
    let (error, gateway) = fetch_with_descriptor(|descriptor| {
        descriptor.byte_size = AMOUNT_STATISTICS_MAX_COMPRESSED_BYTES + 1;
    })
    .await;

    assert!(matches!(
        error,
        AmountStatisticsRefreshError::Statistics(AmountStatisticsError::CompressedTooLarge { .. })
    ));
    assert_eq!(gateway.snapshot_requests(), 0);
}

#[tokio::test]
async fn unsupported_snapshot_encoding_is_not_fetched() {
    let (error, gateway) = fetch_with_descriptor(|descriptor| {
        descriptor.encoding_version = AMOUNT_STATISTICS_SNAPSHOT_ENCODING_VERSION + 1;
    })
    .await;

    assert!(matches!(
        error,
        AmountStatisticsRefreshError::Statistics(
            AmountStatisticsError::UnsupportedEncodingVersion(_)
        )
    ));
    assert_eq!(gateway.snapshot_requests(), 0);
}

#[tokio::test]
async fn stored_snapshot_is_available_after_restart_before_a_fetch_completes() {
    let snapshot = snapshot_for(scope());
    let bytes = encoded(&snapshot);
    let stalled = ManifestGateway::spawn(HashMap::new(), usize::MAX);
    let source = source_for(&stalled);
    let root_dir = temp_db_root();
    let earlier_session = open_db(&root_dir);
    assert!(
        replace_amount_statistics(
            &earlier_session,
            &scope(),
            &stored(&source.identity(), 3, &bytes),
        )
        .expect("store snapshot")
    );
    drop(earlier_session);

    let db = Arc::new(open_db(&root_dir));
    let statistics = ChainAmountStatistics::new(Some(source));
    let cancel = CancellationToken::new();
    statistics.spawn_refresh(
        Arc::clone(&db),
        reqwest::Client::new(),
        cancel.clone(),
        None,
    );
    // The refresh loads the stored snapshot before it sends its first request.
    stalled.wait_for_requests(1).await;

    assert_eq!(
        statistics.status(fresh_until()),
        AmountStatisticsStatus::Available(Arc::new(snapshot))
    );
    let row = db
        .read_app_tables(|tables| tables.get(AMOUNT_STATISTICS_TABLE, &format_scope(&scope())))
        .expect("read stored row")
        .expect("stored row");
    // Only the record's keys matter here, so the values are skipped.
    #[allow(clippy::zero_sized_map_values)]
    let fields: Vec<String> =
        rmp_serde::from_slice::<BTreeMap<String, serde::de::IgnoredAny>>(&row)
            .expect("stored record map")
            .into_keys()
            .collect();
    assert_eq!(fields, ["cid", "sequence", "sha256", "snapshot", "source"]);

    stop_refresh(&statistics, &cancel).await;
    drop(db);
    std::fs::remove_dir_all(root_dir).expect("remove temp db");
}

#[tokio::test]
async fn refresh_keeps_runtime_admission_until_it_stops() {
    let stalled = ManifestGateway::spawn(HashMap::new(), usize::MAX);
    let root_dir = temp_db_root();
    let db = Arc::new(open_db(&root_dir));
    let statistics = ChainAmountStatistics::new(Some(source_for(&stalled)));
    let cancel = CancellationToken::new();
    let lease = DbRuntimeLease::acquire(&db, DbRuntimeOwnerKind::SyncManager)
        .expect("acquire runtime lease");
    // The refresh task holds the only clone of the lease.
    statistics.spawn_refresh(
        Arc::clone(&db),
        reqwest::Client::new(),
        cancel.clone(),
        Some(lease),
    );
    stalled.wait_for_requests(1).await;

    let Err(error) = DbRuntimeLease::acquire(&db, DbRuntimeOwnerKind::OfflinePoiReset) else {
        panic!("a running refresh keeps runtime admission held");
    };
    assert_eq!(error.active, DbRuntimeOwnerKind::SyncManager);

    stop_refresh(&statistics, &cancel).await;
    // `statistics` is still alive, so the stopped task released the lease.
    let replacement = DbRuntimeLease::acquire(&db, DbRuntimeOwnerKind::OfflinePoiReset)
        .expect("admission is free once the refresh stops");

    drop(replacement);
    drop(statistics);
    drop(db);
    std::fs::remove_dir_all(root_dir).expect("remove temp db");
}

#[test]
fn stored_record_is_not_replaced_by_a_lower_sequence() {
    let root_dir = temp_db_root();
    let db = open_db(&root_dir);
    let identity = identity([7; 32]);

    assert!(
        replace_amount_statistics(&db, &scope(), &stored(&identity, 5, b"newer"))
            .expect("store newer")
    );
    assert!(
        !replace_amount_statistics(&db, &scope(), &stored(&identity, 4, b"older"))
            .expect("refuse older")
    );

    let kept = load_amount_statistics(&db, &scope(), &identity)
        .expect("load")
        .expect("newer record kept");
    assert_eq!(kept.sequence, 5);
    assert_eq!(kept.snapshot.to_vec(), b"newer");
    drop(db);
    std::fs::remove_dir_all(root_dir).expect("remove temp db");
}

#[test]
fn records_from_another_source_are_discarded() {
    let root_dir = temp_db_root();
    let db = open_db(&root_dir);
    let previous = identity([7; 32]);
    let rotated = identity([8; 32]);
    replace_amount_statistics(&db, &scope(), &stored(&previous, 9, b"previous"))
        .expect("store previous source");

    assert!(
        load_amount_statistics(&db, &scope(), &rotated)
            .expect("load")
            .is_none()
    );
    assert!(
        load_amount_statistics(&db, &scope(), &previous)
            .expect("load")
            .is_none(),
        "the discarded record does not come back"
    );
    assert!(
        replace_amount_statistics(&db, &scope(), &stored(&rotated, 1, b"rotated"))
            .expect("store new source"),
        "the previous source's sequence is no floor for the new one"
    );
    drop(db);
    std::fs::remove_dir_all(root_dir).expect("remove temp db");
}

#[tokio::test(start_paused = true)]
async fn refresh_fetches_at_start_then_hourly_without_downloading_the_held_snapshot_again() {
    let snapshot = snapshot_for(scope());
    let bytes = encoded(&snapshot);
    let gateway = StatisticsGateway::spawn(
        envelope_bytes(&signing_key(), 1, entry_for(&snapshot, &bytes)),
        bytes,
    );
    let root_dir = temp_db_root();
    let db = Arc::new(open_db(&root_dir));
    let statistics = ChainAmountStatistics::new(Some(gateway.source.clone()));
    assert_eq!(
        ChainAmountStatistics::default().status(fresh_until()),
        AmountStatisticsStatus::NotConfigured
    );
    assert_eq!(
        statistics.status(fresh_until()),
        AmountStatisticsStatus::NotYetAvailable
    );
    let cancel = CancellationToken::new();
    statistics.spawn_refresh(
        Arc::clone(&db),
        reqwest::Client::new(),
        cancel.clone(),
        None,
    );

    yield_until("the first refresh accepts the snapshot", || {
        statistics.status(fresh_until()) != AmountStatisticsStatus::NotYetAvailable
    })
    .await;
    assert_eq!(
        statistics.status(fresh_until()),
        AmountStatisticsStatus::Available(Arc::new(snapshot))
    );
    assert_eq!(
        statistics.status(fresh_until() + Duration::from_secs(1)),
        AmountStatisticsStatus::OutOfDate
    );
    assert_eq!(gateway.server.request_count(), 3);

    tokio::time::advance(AMOUNT_STATISTICS_REFRESH_INTERVAL.saturating_sub(Duration::from_secs(1)))
        .await;
    yield_many().await;
    assert_eq!(
        gateway.server.request_count(),
        3,
        "no refresh before the hour"
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    yield_until("the first hourly refresh resolves the manifest", || {
        gateway.server.request_count() == 5
    })
    .await;
    yield_many().await;
    // The tick schedule does not depend on when a refresh ends, and refreshes run one at a
    // time, so the next manifest request also means this refresh has finished.
    tokio::time::advance(AMOUNT_STATISTICS_REFRESH_INTERVAL).await;
    yield_until("the second hourly refresh resolves the manifest", || {
        gateway.server.request_count() == 7
    })
    .await;

    let (ipns, manifest) = (gateway.ipns_path.as_str(), gateway.manifest_path.as_str());
    let snapshot = gateway.snapshot_path.as_str();
    assert_eq!(
        gateway.server.request_paths(),
        [ipns, manifest, snapshot, ipns, manifest, ipns, manifest],
        "an hourly refresh does not download the held snapshot again"
    );
    stop_refresh(&statistics, &cancel).await;
    drop(db);
    std::fs::remove_dir_all(root_dir).expect("remove temp db");
}

/// Serves one manifest through IPNS, and the snapshot bytes, from a recording gateway.
struct StatisticsGateway {
    server: ManifestGateway,
    source: AmountStatisticsSource,
    ipns_path: String,
    manifest_path: String,
    snapshot_path: String,
}

impl StatisticsGateway {
    fn spawn(envelope: Vec<u8>, snapshot: Vec<u8>) -> Self {
        let keypair = test_ipns_keypair();
        let manifest_cid = raw_cid(&envelope);
        let snapshot_cid = raw_cid(&snapshot);
        let ipns_path = format!("/ipns/{}?format=ipns-record", ipns_name(&keypair));
        let manifest_path = format!("/ipfs/{manifest_cid}?format=raw");
        let snapshot_path = format!("/ipfs/{snapshot_cid}?format=car&dag-scope=entity");
        let server = ManifestGateway::spawn(
            HashMap::from([
                (
                    ipns_path.clone(),
                    ipns_record(&keypair, format!("/ipfs/{manifest_cid}"), 1),
                ),
                (manifest_path.clone(), envelope),
                (
                    snapshot_path.clone(),
                    car_bytes(snapshot_cid, &[(snapshot_cid, snapshot)]),
                ),
            ]),
            0,
        );
        Self {
            source: source_for(&server),
            server,
            ipns_path,
            manifest_path,
            snapshot_path,
        }
    }

    async fn fetch(&self) -> Result<FetchedAmountStatistics, AmountStatisticsRefreshError> {
        AmountStatisticsClient::new(self.source.clone(), reqwest::Client::new())
            .fetch(None, SystemTime::now())
            .await
    }

    fn snapshot_requests(&self) -> usize {
        self.server
            .request_paths()
            .iter()
            .filter(|path| **path == self.snapshot_path)
            .count()
    }
}

/// Cancels the refresh loop and waits for it to stop.
async fn stop_refresh(statistics: &ChainAmountStatistics, cancel: &CancellationToken) {
    cancel.cancel();
    let task = statistics.task().lock().expect("refresh task lock").take();
    task.expect("refresh spawned")
        .await
        .expect("refresh stops on cancel");
}

/// Lets in-flight work run without letting paused time advance.
async fn yield_many() {
    for _ in 0..1_000 {
        tokio::task::yield_now().await;
    }
}

/// Fetches through a manifest whose descriptor `edit` changed, which must fail.
async fn fetch_with_descriptor(
    edit: impl FnOnce(&mut AmountStatisticsSnapshotDescriptor),
) -> (AmountStatisticsRefreshError, StatisticsGateway) {
    let snapshot = snapshot_for(scope());
    let bytes = encoded(&snapshot);
    let mut entry = entry_for(&snapshot, &bytes);
    edit(&mut entry.snapshot);
    let gateway = StatisticsGateway::spawn(envelope_bytes(&signing_key(), 1, entry), bytes);
    let error = gateway.fetch().await.expect_err("descriptor rejected");
    (error, gateway)
}

fn source_for(gateway: &ManifestGateway) -> AmountStatisticsSource {
    let mut artifacts = config(signing_key().verifying_key().to_bytes(), None);
    artifacts.gateway_urls = vec![gateway.url.clone()];
    AmountStatisticsSource {
        ipns_name: ipns_name(&test_ipns_keypair()),
        artifacts,
        scope: scope(),
    }
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn snapshot_for(scope: ChainScope) -> AmountStatisticsSnapshot {
    AmountStatisticsSnapshot {
        encoding_version: AMOUNT_STATISTICS_SNAPSHOT_ENCODING_VERSION,
        scope,
        covered_block: AmountStatisticsCoveredBlock {
            number: 100,
            hash: FixedBytes::from([0x11; 32]),
            timestamp: COVERED_AT_SECS,
        },
        tokens: Vec::new(),
    }
}

/// The last instant at which [`snapshot_for`] is not out of date.
fn fresh_until() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(COVERED_AT_SECS) + AMOUNT_STATISTICS_MAX_AGE
}

fn encoded(snapshot: &AmountStatisticsSnapshot) -> Vec<u8> {
    encode_amount_statistics_snapshot(snapshot)
        .expect("encode snapshot")
        .bytes
}

/// A chain entry for `snapshot` whose descriptor matches `bytes`.
fn entry_for(snapshot: &AmountStatisticsSnapshot, bytes: &[u8]) -> AmountStatisticsChainEntry {
    AmountStatisticsChainEntry {
        scope: snapshot.scope.clone(),
        covered_block: snapshot.covered_block.clone(),
        snapshot: AmountStatisticsSnapshotDescriptor {
            cid: raw_cid(bytes).to_string(),
            sha256: FixedBytes::from_slice(&Sha256::digest(bytes)),
            byte_size: bytes.len() as u64,
            encoding_version: AMOUNT_STATISTICS_SNAPSHOT_ENCODING_VERSION,
            compression: CompressionAlgorithm::Zstd,
        },
    }
}

fn envelope_bytes(
    signing_key: &SigningKey,
    sequence: u64,
    entry: AmountStatisticsChainEntry,
) -> Vec<u8> {
    let manifest = AmountStatisticsManifest {
        format_version: AMOUNT_STATISTICS_MANIFEST_FORMAT_VERSION,
        issued_at_ms: COVERED_AT_SECS * 1000,
        sequence,
        publisher: PublisherIdentity::ed25519(FixedBytes::ZERO),
        chains: vec![entry],
    };
    let envelope =
        AmountStatisticsManifestEnvelope::sign(&manifest, signing_key).expect("sign manifest");
    serde_json::to_vec(&envelope).expect("envelope JSON")
}

fn identity(publisher_key: [u8; 32]) -> AmountStatisticsSourceIdentity {
    AmountStatisticsSourceIdentity {
        ipns_name: ipns_name(&test_ipns_keypair()),
        publisher_key: FixedBytes::from(publisher_key),
    }
}

fn stored(
    identity: &AmountStatisticsSourceIdentity,
    sequence: u64,
    snapshot: &[u8],
) -> StoredAmountStatistics {
    StoredAmountStatistics {
        source: identity.clone(),
        sequence,
        cid: raw_cid(snapshot).to_string(),
        sha256: FixedBytes::from_slice(&Sha256::digest(snapshot)),
        snapshot: snapshot.to_vec().into(),
    }
}

fn open_db(root_dir: &Path) -> DbStore {
    DbStore::open(DbConfig {
        root_dir: root_dir.to_path_buf(),
    })
    .expect("open db")
}

fn temp_db_root() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let counter = TEMP_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "sync-service-amount-statistics-{}-{unique}-{counter}",
        std::process::id()
    ))
}
