use super::test_support::{
    load_persisted_cache, observe_manifest, persist_public_rpc_cache,
    poi_v4_manifest_envelope_signing_message,
};
use super::*;
use std::fs;
use std::path::PathBuf;

use ed25519_dalek::{Signer, SigningKey};
use local_db::DbConfig;
use merkletree::tree::{MerkleForest, MerkleTreeUpdate};
use poi::artifacts::v4::{
    ArtifactEncoding, BLOCKED_SHIELDS_ARTIFACT_MAX_BYTES, BlockedShieldsDescriptor,
    CheckpointCatalogDescriptor, Compression, FORMAT_VERSION,
};
use poi::artifacts::{ManifestEntry as LegacyManifestEntry, SnapshotEvent};
use poi::cache::{
    POI_CACHE_SNAPSHOT_VERSION, PoiCachePosition, PoiCacheRootValidation, PoiCacheSyncProgress,
};
use poi::poi::{BlockedShield, PoiEventType, PoiStatus};

#[derive(serde::Serialize)]
struct TestPoiCacheSnapshot {
    version: u32,
    identity: PoiCacheIdentity,
    progress: PoiCacheSyncProgress,
    forest: MerkleForest,
    status_by_blinded_commitment: BTreeMap<FixedBytes<32>, PoiStatus>,
    position_by_blinded_commitment: BTreeMap<FixedBytes<32>, PoiCachePosition>,
    blocked_shields_by_blinded_commitment: BTreeMap<FixedBytes<32>, BlockedShield>,
}

#[test]
fn v4_manifest_watermark_is_durable_before_entry_or_candidate_work() {
    let root_dir = temp_db_root("v4-watermark-before-entry");
    fs::create_dir_all(&root_dir).expect("create temp DB root");
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open temp DB");
    let signing_key = SigningKey::from_bytes(&[0x91; 32]);
    let publisher = FixedBytes::from(signing_key.verifying_key().to_bytes());
    let mut manifest = Manifest::new(1_700_000_000_000, 9, publisher, Vec::new());
    manifest.sign_manifest(&signing_key).expect("sign manifest");

    let observed = observe_manifest(&db, publisher, manifest, None, SystemTime::now())
        .expect("observe authenticated manifest");
    let missing_scope = Scope::new(FixedBytes::from([0x92; 32]), 0, 1, "V2_PoseidonMerkle");
    assert!(matches!(
        observed.entry(&missing_scope),
        Err(PoiArtifactError::MissingManifestEntry { .. })
    ));
    assert_eq!(
        db.get_poi_publisher_manifest_watermark(&publisher)
            .expect("read publisher watermark")
            .expect("watermark persisted")
            .accepted_sequence,
        9
    );

    let mut older = Manifest::new(1_700_000_000_001, 8, publisher, Vec::new());
    older
        .sign_manifest(&signing_key)
        .expect("sign older manifest");
    assert!(matches!(
        observe_manifest(&db, publisher, older, None, SystemTime::now()),
        Err(PoiArtifactError::ManifestSequenceRollback {
            previous: 9,
            received: 8,
        })
    ));

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp DB root");
}

#[test]
fn v4_equal_sequence_equivocation_is_rejected_after_reopen() {
    let root_dir = temp_db_root("v4-equal-sequence-equivocation");
    fs::create_dir_all(&root_dir).expect("create temp DB root");
    let signing_key = SigningKey::from_bytes(&[0x93; 32]);
    let publisher = FixedBytes::from(signing_key.verifying_key().to_bytes());
    let mut first = Manifest::new(1_700_000_000_000, 11, publisher, Vec::new());
    first
        .sign_manifest(&signing_key)
        .expect("sign first manifest");
    {
        let db = DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        })
        .expect("open temp DB");
        observe_manifest(&db, publisher, first.clone(), None, SystemTime::now())
            .expect("observe first publication");
        observe_manifest(&db, publisher, first, None, SystemTime::now())
            .expect("same publication is idempotent");
    }
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("reopen temp DB");
    let mut equivocation = Manifest::new(1_700_000_000_001, 11, publisher, Vec::new());
    equivocation
        .sign_manifest(&signing_key)
        .expect("sign equivocation");
    assert!(matches!(
        observe_manifest(&db, publisher, equivocation, None, SystemTime::now()),
        Err(PoiArtifactError::ManifestSequenceEquivocation { sequence: 11 })
    ));

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp DB root");
}

#[test]
fn oversized_v4_blocked_descriptor_advances_watermark_before_graph_rejection() {
    let root_dir = temp_db_root("v4-oversized-blocked-descriptor");
    fs::create_dir_all(&root_dir).expect("create temp DB root");
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open temp DB");
    let signing_key = SigningKey::from_bytes(&[0x94; 32]);
    let publisher = FixedBytes::from(signing_key.verifying_key().to_bytes());
    let scope = Scope::new(FixedBytes::from([0x95; 32]), 0, 1, "V2_PoseidonMerkle");
    let entry = ManifestEntry {
        scope: scope.clone(),
        event_count: 0,
        current_tip_index: None,
        current_root: None,
        checkpoint_catalog: CheckpointCatalogDescriptor {
            artifact: ArtifactDescriptor {
                cid: "bafy-catalog".to_string(),
                sha256: FixedBytes::from([0x96; 32]),
                byte_size: 1,
            },
            format_version: FORMAT_VERSION,
            scope: scope.clone(),
            range: None,
            row_count: 0,
            chunk_count: 0,
            encoding: ArtifactEncoding::CanonicalJson,
            compression: Compression::Identity,
            checkpoint_root: None,
        },
        current_tail: None,
        retained_bridges: Vec::new(),
        blocked_shields: BlockedShieldsDescriptor {
            artifact: ArtifactDescriptor {
                cid: "bafy-blocked".to_string(),
                sha256: FixedBytes::from([0x97; 32]),
                byte_size: BLOCKED_SHIELDS_ARTIFACT_MAX_BYTES + 1,
            },
            format_version: FORMAT_VERSION,
            scope,
            row_count: 0,
            encoding: ArtifactEncoding::CanonicalJson,
            compression: Compression::Identity,
        },
    };
    let mut manifest = Manifest::new(1_700_000_000_000, 12, publisher, vec![entry]);
    manifest.publisher_signature = Some(FixedBytes::from(
        signing_key
            .sign(&poi_v4_manifest_envelope_signing_message(&manifest))
            .to_bytes(),
    ));

    assert!(matches!(
        observe_manifest(&db, publisher, manifest, None, SystemTime::now()),
        Err(PoiArtifactError::Format(
            ArtifactFormatError::BlockedShieldsArtifactByteLimitExceeded { .. }
        ))
    ));
    assert_eq!(
        db.get_poi_publisher_manifest_watermark(&publisher)
            .expect("read publisher watermark")
            .expect("oversized graph watermark persisted")
            .accepted_sequence,
        12
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp DB root");
}

#[test]
fn v4_manifest_freshness_applies_to_each_higher_sequence() {
    let root_dir = temp_db_root("v4-sequence-freshness");
    fs::create_dir_all(&root_dir).expect("create temp DB root");
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open temp DB");
    let signing_key = SigningKey::from_bytes(&[0x98; 32]);
    let publisher = FixedBytes::from(signing_key.verifying_key().to_bytes());
    let max_age = Duration::from_secs(1);
    let first_now = UNIX_EPOCH + Duration::from_secs(10);

    let stale_first = signed_empty_v4_manifest(&signing_key, 7_000, 9);
    assert!(matches!(
        observe_manifest(&db, publisher, stale_first, Some(max_age), first_now,),
        Err(PoiArtifactError::ManifestStale { .. })
    ));
    assert!(
        db.get_poi_publisher_manifest_watermark(&publisher)
            .expect("read absent stale-first watermark")
            .is_none()
    );

    let sequence_ten = signed_empty_v4_manifest(&signing_key, 9_500, 10);
    observe_manifest(
        &db,
        publisher,
        sequence_ten.clone(),
        Some(max_age),
        first_now,
    )
    .expect("fresh initial publication");
    let retained_ten = db
        .get_poi_publisher_manifest_watermark(&publisher)
        .expect("read sequence ten watermark")
        .expect("sequence ten watermark");

    let later = UNIX_EPOCH + Duration::from_secs(12);
    observe_manifest(&db, publisher, sequence_ten.clone(), Some(max_age), later)
        .expect("aged exact replay remains accepted");
    assert_eq!(
        db.get_poi_publisher_manifest_watermark(&publisher)
            .expect("read replay watermark")
            .expect("replay watermark"),
        retained_ten
    );

    let equal_equivocation = signed_empty_v4_manifest(&signing_key, 7_001, 10);
    assert!(matches!(
        observe_manifest(&db, publisher, equal_equivocation, Some(max_age), later,),
        Err(PoiArtifactError::ManifestSequenceEquivocation { sequence: 10 })
    ));

    let stale_higher = signed_empty_v4_manifest(&signing_key, 7_002, 11);
    assert!(matches!(
        observe_manifest(&db, publisher, stale_higher, Some(max_age), later,),
        Err(PoiArtifactError::ManifestStale { .. })
    ));
    assert_eq!(
        db.get_poi_publisher_manifest_watermark(&publisher)
            .expect("read watermark after stale higher sequence")
            .expect("retained sequence ten"),
        retained_ten
    );

    let fresh_higher = signed_empty_v4_manifest(&signing_key, 11_500, 11);
    observe_manifest(&db, publisher, fresh_higher, Some(max_age), later)
        .expect("fresh higher sequence advances");
    let retained_eleven = db
        .get_poi_publisher_manifest_watermark(&publisher)
        .expect("read sequence eleven watermark")
        .expect("sequence eleven watermark");
    assert_eq!(retained_eleven.accepted_sequence, 11);

    let future_higher = signed_empty_v4_manifest(&signing_key, 13_000, 12);
    assert!(matches!(
        observe_manifest(&db, publisher, future_higher, Some(max_age), later,),
        Err(PoiArtifactError::ManifestIssuedInFuture)
    ));
    assert_eq!(
        db.get_poi_publisher_manifest_watermark(&publisher)
            .expect("read watermark after future higher sequence")
            .expect("retained sequence eleven"),
        retained_eleven
    );

    assert!(matches!(
        observe_manifest(&db, publisher, sequence_ten, Some(max_age), later,),
        Err(PoiArtifactError::ManifestSequenceRollback {
            previous: 11,
            received: 10,
        })
    ));

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp DB root");
}

#[test]
fn hashless_equal_sequence_requires_freshness_before_v4_binding() {
    let root_dir = temp_db_root("v4-hashless-floor-freshness");
    fs::create_dir_all(&root_dir).expect("create temp DB root");
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open temp DB");
    let signing_key = SigningKey::from_bytes(&[0x9a; 32]);
    let publisher = FixedBytes::from(signing_key.verifying_key().to_bytes());
    db.advance_poi_publisher_manifest_watermark(publisher, 10)
        .expect("seed hashless migrated floor");
    let max_age = Duration::from_secs(1);
    let now = UNIX_EPOCH + Duration::from_secs(10);

    let stale = signed_empty_v4_manifest(&signing_key, 7_000, 10);
    assert!(matches!(
        observe_manifest(&db, publisher, stale, Some(max_age), now),
        Err(PoiArtifactError::ManifestStale { .. })
    ));
    assert_eq!(
        db.get_poi_publisher_manifest_watermark(&publisher)
            .expect("read floor after stale observation")
            .expect("hashless floor")
            .accepted_manifest_hash,
        None
    );

    let future = signed_empty_v4_manifest(&signing_key, 11_000, 10);
    assert!(matches!(
        observe_manifest(&db, publisher, future, Some(max_age), now),
        Err(PoiArtifactError::ManifestIssuedInFuture)
    ));
    assert_eq!(
        db.get_poi_publisher_manifest_watermark(&publisher)
            .expect("read floor after future observation")
            .expect("hashless floor")
            .accepted_manifest_hash,
        None
    );

    let fresh = signed_empty_v4_manifest(&signing_key, 9_500, 10);
    let expected_hash = fresh
        .publication_id_envelope()
        .expect("fresh publication identity")
        .manifest_body_hash;
    observe_manifest(&db, publisher, fresh, Some(max_age), now)
        .expect("fresh equal sequence binds migrated floor");
    assert_eq!(
        db.get_poi_publisher_manifest_watermark(&publisher)
            .expect("read bound floor")
            .expect("bound floor")
            .accepted_manifest_hash,
        Some(expected_hash)
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp DB root");
}

#[test]
fn v4_future_time_is_rejected_without_max_age_before_watermark_binding() {
    let root_dir = temp_db_root("v4-future-without-max-age");
    fs::create_dir_all(&root_dir).expect("create temp DB root");
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open temp DB");
    let signing_key = SigningKey::from_bytes(&[0x9b; 32]);
    let publisher = FixedBytes::from(signing_key.verifying_key().to_bytes());
    let now = UNIX_EPOCH + Duration::from_secs(10);

    let future = signed_empty_v4_manifest(&signing_key, 11_000, 1);
    assert!(matches!(
        observe_manifest(&db, publisher, future, None, now),
        Err(PoiArtifactError::ManifestIssuedInFuture)
    ));
    assert!(
        db.get_poi_publisher_manifest_watermark(&publisher)
            .expect("read absent future watermark")
            .is_none()
    );

    let old = signed_empty_v4_manifest(&signing_key, 1_000, 1);
    observe_manifest(&db, publisher, old, None, now)
        .expect("old manifest is accepted when max age is disabled");

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp DB root");
}

#[test]
fn hashless_equal_sequence_future_without_max_age_does_not_bind_hash() {
    let root_dir = temp_db_root("v4-hashless-future-without-max-age");
    fs::create_dir_all(&root_dir).expect("create temp DB root");
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open temp DB");
    let signing_key = SigningKey::from_bytes(&[0x9c; 32]);
    let publisher = FixedBytes::from(signing_key.verifying_key().to_bytes());
    db.advance_poi_publisher_manifest_watermark(publisher, 10)
        .expect("seed hashless floor");
    let now = UNIX_EPOCH + Duration::from_secs(10);

    let future = signed_empty_v4_manifest(&signing_key, 11_000, 10);
    assert!(matches!(
        observe_manifest(&db, publisher, future, None, now),
        Err(PoiArtifactError::ManifestIssuedInFuture)
    ));
    assert_eq!(
        db.get_poi_publisher_manifest_watermark(&publisher)
            .expect("read future-rejected floor")
            .expect("hashless floor")
            .accepted_manifest_hash,
        None
    );

    let nonfuture = signed_empty_v4_manifest(&signing_key, 9_000, 10);
    let expected_hash = nonfuture
        .publication_id_envelope()
        .expect("nonfuture publication identity")
        .manifest_body_hash;
    observe_manifest(&db, publisher, nonfuture, None, now)
        .expect("nonfuture equal sequence binds hashless floor");
    assert_eq!(
        db.get_poi_publisher_manifest_watermark(&publisher)
            .expect("read bound floor")
            .expect("bound floor")
            .accepted_manifest_hash,
        Some(expected_hash)
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp DB root");
}

fn signed_empty_v4_manifest(
    signing_key: &SigningKey,
    issued_at_ms: u64,
    sequence: u64,
) -> Manifest {
    let publisher = FixedBytes::from(signing_key.verifying_key().to_bytes());
    let mut manifest = Manifest::new(issued_at_ms, sequence, publisher, Vec::new());
    manifest
        .sign_manifest(signing_key)
        .expect("sign empty manifest");
    manifest
}

#[test]
fn legacy_materialized_corpus_is_only_a_v4_start_for_exact_identity() {
    let identity = test_identity();
    let cache = test_cache(&identity, &[0x31]);
    let root = test_cache_root(&cache);
    let entry = test_entry(&identity, 0, root.0);
    let publisher = FixedBytes::from([0x61; 32]);
    let persisted = || {
        let mut persisted =
            persisted_cache(&identity, test_cache(&identity, &[0x31]), 0, root, &entry);
        persisted.record.validation = PoiCorpusValidationRecord::PublisherAttested {
            publisher_pubkey: publisher,
            manifest_sequence: 4,
            manifest_root: root,
            artifact_tip_index: 0,
        };
        persisted
    };
    let scope = Scope::new(
        identity.list_key,
        identity.chain_type,
        identity.chain_id,
        identity.txid_version.clone(),
    );

    let starting = persisted()
        .into_starting_state(&scope, publisher)
        .expect("exact legacy corpus is reusable");
    assert_eq!(starting.cache.progress().next_event_index, 1);
    assert_eq!(starting.cache.root_at_global_index(0), Some(root));
    assert_eq!(starting.cache.identity(), &identity);

    let mut wrong_txid = scope.clone();
    wrong_txid.txid_version.push_str("-other");
    assert!(
        persisted()
            .into_starting_state(&wrong_txid, publisher)
            .is_none()
    );
    let mut wrong_list = scope.clone();
    wrong_list.list_key = FixedBytes::from([0xff; 32]);
    assert!(
        persisted()
            .into_starting_state(&wrong_list, publisher)
            .is_none()
    );
    assert!(
        persisted()
            .into_starting_state(&scope, FixedBytes::from([0x62; 32]))
            .is_none()
    );
}

#[test]
fn public_rpc_cache_persistence_does_not_own_publisher_watermark() {
    let root_dir = temp_db_root("rpc-cache-sequence-watermark");
    fs::create_dir_all(&root_dir).expect("create temp DB root");
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open temp DB");
    let identity = test_identity();
    let mut cache = PoiCache::new(identity.clone());
    cache
        .apply_verified_artifact_events(&[SnapshotEvent {
            event_index: 0,
            blinded_commitment: [0x41_u8; 32],
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply test event");
    cache.accept_current_roots();
    let generation = db
        .poi_artifact_cache_generation()
        .expect("cache generation");
    let publisher_pubkey = FixedBytes::from([0x40; 32]);
    db.advance_poi_publisher_manifest_watermark(publisher_pubkey, 7)
        .expect("seed publisher watermark");

    let returned = match PoiCorpusStore::new(&db, generation, publisher_pubkey)
        .commit_public_rpc(
            cache,
            0,
            ExpectedPoiCorpusBase::NoValidCorpus,
            None,
            None,
            &PoiCacheJournalDelta {
                version: poi::cache::POI_CACHE_JOURNAL_DELTA_VERSION,
                identity: identity.clone(),
                event_start_cursor: 0,
                event_end_cursor: 1,
                leaf_start_cursor: 0,
                leaf_end_cursor: 1,
                events: vec![poi::cache::PoiCacheJournalEvent {
                    event_index: 0,
                    blinded_commitment: FixedBytes::from([0x41; 32]),
                }],
                leaves: vec![FixedBytes::from([0x41; 32])],
            },
            Some(Vec::new()),
        )
        .expect("persist public RPC cache")
    {
        PublicRpcPersistResult::Applied(persisted) => *persisted,
        _ => panic!("expected applied public RPC cache"),
    };
    let returned_payload = returned
        .cache
        .to_bytes()
        .expect("serialize returned public RPC cache");
    assert_eq!(returned.record.cache_payload, [] as [u8; 0]);
    let bundle = match db
        .inspect_poi_corpus_journal(
            identity.chain_type,
            identity.chain_id,
            &identity.txid_version,
            &identity.list_key,
        )
        .expect("inspect public RPC journal")
    {
        StoredRecord::Valid(bundle) => bundle,
        other => panic!("unexpected public RPC journal: {other:?}"),
    };
    assert_eq!(returned_payload, bundle.base.cache_payload);
    let decoded = PoiCache::from_bytes(&bundle.base.cache_payload, returned.cache.identity())
        .expect("decode returned public RPC base payload");
    assert_eq!(
        decoded.to_bytes().expect("re-encode public RPC payload"),
        bundle.base.cache_payload
    );
    let persisted = load_persisted_cache_for_publisher(&db, &identity, publisher_pubkey)
        .expect("load public RPC cache")
        .expect("public RPC cache record");

    assert_eq!(persisted.record, returned.record);
    assert_eq!(persisted.record.source, PoiCacheRecordSource::PublicRpc);
    assert_eq!(persisted.record.legacy_observed_manifest_sequence, 0);
    assert_eq!(
        publisher_manifest_watermark(&db, publisher_pubkey)
            .expect("load publisher watermark")
            .map(|record| record.accepted_sequence),
        Some(7)
    );
    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp DB root");
}

#[test]
fn public_rpc_suffix_appends_journal_without_rewriting_base_and_replays_on_restart() {
    let root_dir = temp_db_root("rpc-journal-append-replay");
    fs::create_dir_all(&root_dir).expect("create temp DB root");
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open temp DB");
    let identity = test_identity();
    let generation = db
        .poi_artifact_cache_generation()
        .expect("cache generation");
    let base_cache = test_cache(&identity, &[0x51]);
    assert_eq!(
        persist_public_rpc_cache(
            &db,
            &base_cache,
            generation,
            0,
            ExpectedPoiCorpusBase::NoValidCorpus,
        )
        .expect("persist journal base"),
        CorpusCommitOutcome::Applied
    );
    let initial_bundle = match db
        .inspect_poi_corpus_journal(
            identity.chain_type,
            identity.chain_id,
            &identity.txid_version,
            &identity.list_key,
        )
        .expect("inspect initial journal")
    {
        StoredRecord::Valid(bundle) => bundle,
        other => panic!("unexpected initial journal: {other:?}"),
    };
    let initial_base_payload = initial_bundle.base.cache_payload;
    assert_eq!(
        initial_bundle.deltas,
        [] as [PoiCorpusJournalDeltaRecord; 0]
    );

    let expected_base = load_persisted_cache(&db, &identity)
        .expect("load journal base")
        .expect("journal base")
        .expected_base();
    let candidate = test_cache(&identity, &[0x51, 0x52]);
    assert_eq!(
        persist_public_rpc_cache(&db, &candidate, generation, 1, expected_base)
            .expect("append public RPC journal suffix"),
        CorpusCommitOutcome::Applied
    );
    let bundle = match db
        .inspect_poi_corpus_journal(
            identity.chain_type,
            identity.chain_id,
            &identity.txid_version,
            &identity.list_key,
        )
        .expect("inspect appended journal")
    {
        StoredRecord::Valid(bundle) => bundle,
        other => panic!("unexpected appended journal: {other:?}"),
    };
    assert_eq!(bundle.base.cache_payload, initial_base_payload);
    assert_eq!(bundle.deltas.len(), 1);
    assert!(bundle.deltas[0].payload.len() < bundle.base.cache_payload.len());
    drop(db);
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("reopen temp DB");
    let replayed = load_persisted_cache(&db, &identity)
        .expect("replay appended journal")
        .expect("replayed journal");
    assert_eq!(
        replayed.cache.to_bytes().expect("encode replayed cache"),
        candidate.to_bytes().expect("encode direct candidate")
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp DB root");
}

#[test]
fn blocked_only_public_rpc_revision_replays_without_event_delta() {
    let root_dir = temp_db_root("rpc-journal-blocked-only");
    fs::create_dir_all(&root_dir).expect("create temp DB root");
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open temp DB");
    let identity = test_identity();
    let generation = db
        .poi_artifact_cache_generation()
        .expect("cache generation");
    let base_cache = test_cache(&identity, &[0x53]);
    persist_public_rpc_cache(
        &db,
        &base_cache,
        generation,
        0,
        ExpectedPoiCorpusBase::NoValidCorpus,
    )
    .expect("persist blocked-only base");
    let persisted = load_persisted_cache(&db, &identity)
        .expect("load blocked-only base")
        .expect("blocked-only base");
    let expected_base = persisted.expected_base();
    let starting_record = persisted.metadata_only();
    let starting_head = persisted.journal_head.clone();
    let mut candidate = persisted.cache;
    let blocked = vec![BlockedShield {
        commitment_hash: hex::encode_prefixed([0x54; 32]),
        blinded_commitment: hex::encode_prefixed([0x55; 32]),
        block_reason: Some("test blocked replacement".to_string()),
        signature: hex::encode_prefixed([0x56; 64]),
    }];
    candidate
        .replace_blocked_shields(&blocked)
        .expect("apply blocked-only candidate");
    let delta = PoiCacheJournalDelta {
        version: poi::cache::POI_CACHE_JOURNAL_DELTA_VERSION,
        identity: identity.clone(),
        event_start_cursor: 1,
        event_end_cursor: 1,
        leaf_start_cursor: 1,
        leaf_end_cursor: 1,
        events: Vec::new(),
        leaves: Vec::new(),
    };
    assert!(matches!(
        persist_public_rpc_cache_with_publisher(
            &db,
            candidate.clone(),
            generation,
            1,
            None,
            expected_base,
            Some(&starting_record),
            starting_head.as_ref(),
            &delta,
            Some(blocked),
        )
        .expect("persist blocked-only journal revision"),
        PublicRpcPersistResult::Applied(_)
    ));
    let bundle = match db
        .inspect_poi_corpus_journal(
            identity.chain_type,
            identity.chain_id,
            &identity.txid_version,
            &identity.list_key,
        )
        .expect("inspect blocked-only journal")
    {
        StoredRecord::Valid(bundle) => bundle,
        other => panic!("unexpected blocked-only journal: {other:?}"),
    };
    assert_eq!(bundle.deltas, [] as [PoiCorpusJournalDeltaRecord; 0]);
    assert!(bundle.blocked.is_some());
    drop(db);
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("reopen temp DB");
    let replayed = load_persisted_cache(&db, &identity)
        .expect("replay blocked-only journal")
        .expect("blocked-only journal");
    assert!(replayed.cache.blocked_shields_match(&candidate));

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp DB root");
}

#[test]
fn public_rpc_append_requires_metadata_from_exact_starting_head() {
    let root_dir = temp_db_root("rpc-journal-exact-starting-head");
    fs::create_dir_all(&root_dir).expect("create temp DB root");
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open temp DB");
    let identity = test_identity();
    let generation = db
        .poi_artifact_cache_generation()
        .expect("cache generation");
    let base_cache = test_cache(&identity, &[0x5b]);
    persist_public_rpc_cache(
        &db,
        &base_cache,
        generation,
        0,
        ExpectedPoiCorpusBase::NoValidCorpus,
    )
    .expect("persist exact-head base");
    let persisted = load_persisted_cache(&db, &identity)
        .expect("load exact-head base")
        .expect("exact-head base");
    let expected_base = persisted.expected_base();
    let starting_record = persisted.metadata_only();
    let original_head = persisted.journal_head.expect("exact starting head");
    let mut mismatched_head = original_head.clone();
    mismatched_head.corpus.validation = PoiCorpusValidationRecord::Legacy;
    let candidate = test_cache(&identity, &[0x5b, 0x5c]);
    let delta = PoiCacheJournalDelta {
        version: poi::cache::POI_CACHE_JOURNAL_DELTA_VERSION,
        identity: identity.clone(),
        event_start_cursor: 1,
        event_end_cursor: 2,
        leaf_start_cursor: 1,
        leaf_end_cursor: 2,
        events: vec![poi::cache::PoiCacheJournalEvent {
            event_index: 1,
            blinded_commitment: FixedBytes::from([0x5c; 32]),
        }],
        leaves: vec![FixedBytes::from([0x5c; 32])],
    };

    let Err(error) = persist_public_rpc_cache_with_publisher(
        &db,
        candidate,
        generation,
        1,
        None,
        expected_base,
        Some(&starting_record),
        Some(&mismatched_head),
        &delta,
        None,
    ) else {
        panic!("metadata detached from exact starting head was accepted");
    };
    assert!(matches!(
        error,
        PoiArtifactError::PersistedArtifactMetadata {
            reason: "journal public RPC starting metadata does not match its exact head"
        }
    ));
    match db
        .inspect_poi_corpus_journal_head(
            identity.chain_type,
            identity.chain_id,
            &identity.txid_version,
            &identity.list_key,
        )
        .expect("inspect unchanged exact head")
    {
        StoredRecord::Valid(head) => assert_eq!(head, original_head),
        other => panic!("unexpected journal after rejected starting head: {other:?}"),
    }

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp DB root");
}

#[test]
fn public_rpc_blocked_snapshot_enforces_exact_durable_byte_limit() {
    let root_dir = temp_db_root("rpc-journal-blocked-byte-limit");
    fs::create_dir_all(&root_dir).expect("create temp DB root");
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open temp DB");
    let identity = test_identity();
    let generation = db
        .poi_artifact_cache_generation()
        .expect("cache generation");
    let base_cache = test_cache(&identity, &[0x57]);
    persist_public_rpc_cache(
        &db,
        &base_cache,
        generation,
        0,
        ExpectedPoiCorpusBase::NoValidCorpus,
    )
    .expect("persist blocked byte-limit base");
    let persisted = load_persisted_cache(&db, &identity)
        .expect("load blocked byte-limit base")
        .expect("blocked byte-limit base");
    let expected_base = persisted.expected_base();
    let starting_record = persisted.metadata_only();
    let starting_head = persisted.journal_head.clone();
    let payload_limit = usize::try_from(POI_CORPUS_JOURNAL_MAX_BLOCKED_PAYLOAD_BYTES)
        .expect("blocked payload limit fits usize");
    let blocked_at_limit = blocked_shields_with_payload_size(payload_limit);
    let mut candidate_at_limit = persisted.cache;
    candidate_at_limit
        .replace_blocked_shields(&blocked_at_limit)
        .expect("apply blocked snapshot at limit");
    let empty_delta = PoiCacheJournalDelta {
        version: poi::cache::POI_CACHE_JOURNAL_DELTA_VERSION,
        identity: identity.clone(),
        event_start_cursor: 1,
        event_end_cursor: 1,
        leaf_start_cursor: 1,
        leaf_end_cursor: 1,
        events: Vec::new(),
        leaves: Vec::new(),
    };
    assert!(matches!(
        persist_public_rpc_cache_with_publisher(
            &db,
            candidate_at_limit,
            generation,
            1,
            None,
            expected_base,
            Some(&starting_record),
            starting_head.as_ref(),
            &empty_delta,
            Some(blocked_at_limit.clone()),
        )
        .expect("persist blocked snapshot at exact byte limit"),
        PublicRpcPersistResult::Applied(_)
    ));
    let before_rejection = match db
        .inspect_poi_corpus_journal(
            identity.chain_type,
            identity.chain_id,
            &identity.txid_version,
            &identity.list_key,
        )
        .expect("inspect journal before oversized blocked snapshot")
    {
        StoredRecord::Valid(bundle) => bundle,
        other => panic!("unexpected journal before oversized snapshot: {other:?}"),
    };
    assert_eq!(
        before_rejection
            .blocked
            .as_ref()
            .map(|blocked| blocked.payload.len()),
        Some(payload_limit)
    );

    let persisted = load_persisted_cache(&db, &identity)
        .expect("load exact-limit blocked snapshot")
        .expect("exact-limit blocked snapshot");
    let expected_base = persisted.expected_base();
    let starting_record = persisted.metadata_only();
    let starting_head = persisted.journal_head.clone();
    let mut blocked_over_limit = blocked_at_limit;
    blocked_over_limit[0]
        .block_reason
        .as_mut()
        .expect("test blocked reason")
        .push('x');
    let mut candidate_over_limit = persisted.cache;
    candidate_over_limit
        .replace_blocked_shields(&blocked_over_limit)
        .expect("apply oversized blocked snapshot candidate");
    let Err(error) = persist_public_rpc_cache_with_publisher(
        &db,
        candidate_over_limit,
        generation,
        1,
        None,
        expected_base,
        Some(&starting_record),
        starting_head.as_ref(),
        &empty_delta,
        Some(blocked_over_limit),
    ) else {
        panic!("blocked snapshot above durable byte limit was accepted");
    };
    assert!(matches!(
        error,
        PoiArtifactError::Persistence { reason }
            if reason.contains("4194305 bytes") && reason.contains("maximum is 4194304")
    ));
    let after_rejection = match db
        .inspect_poi_corpus_journal(
            identity.chain_type,
            identity.chain_id,
            &identity.txid_version,
            &identity.list_key,
        )
        .expect("inspect journal after oversized blocked snapshot")
    {
        StoredRecord::Valid(bundle) => bundle,
        other => panic!("unexpected journal after oversized snapshot: {other:?}"),
    };
    assert_eq!(after_rejection, before_rejection);

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp DB root");
}

fn blocked_shields_with_payload_size(target_bytes: usize) -> Vec<BlockedShield> {
    let mut blocked = vec![BlockedShield {
        commitment_hash: hex::encode_prefixed([0x58; 32]),
        blinded_commitment: hex::encode_prefixed([0x59; 32]),
        block_reason: Some("x".repeat(65_536)),
        signature: hex::encode_prefixed([0x5a; 64]),
    }];
    let initial_bytes = rmp_serde::to_vec_named(&blocked)
        .expect("encode initial blocked snapshot")
        .len();
    assert!(initial_bytes <= target_bytes);
    blocked[0]
        .block_reason
        .as_mut()
        .expect("test blocked reason")
        .push_str(&"x".repeat(target_bytes - initial_bytes));
    assert_eq!(
        rmp_serde::to_vec_named(&blocked)
            .expect("encode sized blocked snapshot")
            .len(),
        target_bytes
    );
    blocked
}

#[test]
fn journal_compaction_rebases_current_cache_and_retires_deltas() {
    let root_dir = temp_db_root("rpc-journal-compaction");
    fs::create_dir_all(&root_dir).expect("create temp DB root");
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open temp DB");
    let identity = test_identity();
    let generation = db
        .poi_artifact_cache_generation()
        .expect("cache generation");
    let publisher = FixedBytes::from([0x58; 32]);
    let base = test_cache(&identity, &[0x57]);
    persist_public_rpc_cache(
        &db,
        &base,
        generation,
        0,
        ExpectedPoiCorpusBase::NoValidCorpus,
    )
    .expect("persist compaction base");
    let expected = load_persisted_cache(&db, &identity)
        .expect("load compaction base")
        .expect("compaction base")
        .expected_base();
    let candidate = test_cache(&identity, &[0x57, 0x58]);
    persist_public_rpc_cache(&db, &candidate, generation, 1, expected)
        .expect("append before compaction");
    let expected = load_persisted_cache(&db, &identity)
        .expect("load journal before compaction")
        .expect("journal before compaction")
        .expected_base();

    let compacted = match PoiCorpusStore::new(&db, generation, publisher)
        .compact(&identity, expected)
        .expect("compact journal")
    {
        PoiCorpusCompactionResult::Applied(persisted) => persisted,
        PoiCorpusCompactionResult::Stale => panic!("compaction unexpectedly became stale"),
    };
    let bundle = match db
        .inspect_poi_corpus_journal(
            identity.chain_type,
            identity.chain_id,
            &identity.txid_version,
            &identity.list_key,
        )
        .expect("inspect compacted journal")
    {
        StoredRecord::Valid(bundle) => bundle,
        other => panic!("unexpected compacted journal: {other:?}"),
    };
    let head = bundle.head.expect("compacted journal head");
    assert_eq!(compacted.journal_head.as_ref(), Some(&head));
    assert_eq!(head.base_revision, head.revision);
    assert_eq!(head.delta_count, 0);
    assert_eq!(bundle.deltas, [] as [PoiCorpusJournalDeltaRecord; 0]);
    assert_eq!(
        PoiCache::from_bytes(&bundle.base.cache_payload, &identity)
            .expect("decode compacted base")
            .to_bytes()
            .expect("encode compacted base"),
        candidate.to_bytes().expect("encode compaction candidate")
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp DB root");
}

#[test]
fn rpc_only_corpus_cannot_recover_publisher_watermark() {
    let root_dir = temp_db_root("rpc-cache-no-publisher-watermark");
    fs::create_dir_all(&root_dir).expect("create temp DB root");
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open temp DB");
    let identity = test_identity();
    let cache = test_cache(&identity, &[0x42]);
    let generation = db
        .poi_artifact_cache_generation()
        .expect("cache generation");
    persist_public_rpc_cache(
        &db,
        &cache,
        generation,
        0,
        ExpectedPoiCorpusBase::NoValidCorpus,
    )
    .expect("persist RPC-only corpus");
    let mut record = db
        .get_poi_artifact_cache(
            identity.chain_type,
            identity.chain_id,
            &identity.txid_version,
            &identity.list_key,
        )
        .expect("load RPC-only corpus")
        .expect("RPC-only corpus");
    record.legacy_observed_manifest_sequence = 99;
    db.put_poi_artifact_cache(&record)
        .expect("persist legacy observational sequence");

    assert_eq!(
        publisher_manifest_watermark(&db, FixedBytes::from([0x41; 32]))
            .expect("derive publisher watermark"),
        None
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp DB root");
}

#[test]
fn malformed_persisted_tip_is_rejected_and_does_not_block_valid_replacement() {
    let root_dir = temp_db_root("malformed-persisted-tip");
    fs::create_dir_all(&root_dir).expect("create temp DB root");
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open temp DB");
    let identity = test_identity();
    let cache = test_cache(&identity, &[0x31]);
    let root = test_cache_root(&cache);
    let entry = test_entry(&identity, 0, root.0);
    let mut malformed = persisted_cache(&identity, cache.clone(), 0, root, &entry).record;
    malformed.current_tip_index = 50;
    db.put_poi_artifact_cache(&malformed)
        .expect("persist malformed corpus");

    assert!(matches!(
        load_persisted_cache(&db, &identity),
        Err(PoiArtifactError::PersistedTipMismatch {
            metadata: 50,
            payload: 0,
        })
    ));

    let generation = db
        .poi_artifact_cache_generation()
        .expect("cache generation");
    let expected_base = observed_corrupt_expected_base(&db, &identity);
    assert_eq!(
        persist_public_rpc_cache(&db, &cache, generation, 0, expected_base,)
            .expect("replace malformed corpus"),
        CorpusCommitOutcome::Applied
    );
    let recovered = load_persisted_cache(&db, &identity)
        .expect("load replacement corpus")
        .expect("replacement corpus");
    assert_eq!(recovered.record.current_tip_index, 0);
    assert_eq!(recovered.record.current_tip_root, root);

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp DB root");
}

#[test]
fn exact_installed_head_anchor_can_advance_past_corrupt_historical_rows() {
    let root_dir = temp_db_root("installed-head-anchor");
    fs::create_dir_all(&root_dir).expect("create temp DB root");
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open temp DB");
    let identity = test_identity();
    let cache = test_cache(&identity, &[0x35]);
    let generation = db
        .poi_artifact_cache_generation()
        .expect("cache generation");
    persist_public_rpc_cache(
        &db,
        &cache,
        generation,
        0,
        ExpectedPoiCorpusBase::NoValidCorpus,
    )
    .expect("persist initial corpus");
    let installed = load_persisted_cache(&db, &identity)
        .expect("load installed corpus")
        .expect("installed corpus");
    let installed_head = installed.journal_head.clone().expect("installed head");

    let mut corrupt_base = db
        .get_poi_artifact_cache(
            identity.chain_type,
            identity.chain_id,
            &identity.txid_version,
            &identity.list_key,
        )
        .expect("load persisted base")
        .expect("persisted base");
    corrupt_base.cache_payload = vec![0xc1];
    db.put_poi_artifact_cache(&corrupt_base)
        .expect("corrupt historical base row");
    assert!(load_persisted_cache(&db, &identity).is_err());
    let installed_expected_base = installed.expected_base();
    let strict_fallback_cache = installed.cache.clone();

    let (anchored, expected_base) = load_persisted_cache_candidate_for_publisher(
        &db,
        &identity,
        FixedBytes::from([0x41; 32]),
        Some(installed.cache),
        Some(&installed_head),
    )
    .expect("select exactly anchored runtime corpus");
    let anchored = anchored.expect("anchored runtime corpus");
    assert_eq!(anchored.journal_head, Some(installed_head.clone()));
    assert_eq!(expected_base, installed_expected_base);

    let mut replacement = anchored.metadata_only();
    replacement.cache_payload = anchored.cache.to_bytes().expect("encode replacement base");
    let replaced = match db
        .rebase_poi_corpus_journal_if_current(
            replacement,
            anchored.cache.progress().next_event_index,
            anchored.cache.progress().next_leaf_index,
            PoiCorpusJournalCommitCondition {
                expected_generation: generation,
                expected_publisher: None,
                expected_manifest_hash: None,
                expected_state: expected_base.into_db_state(),
            },
        )
        .expect("advance anchored corpus")
    {
        PoiCorpusJournalCommitOutcome::Applied(commit) => commit,
        outcome => panic!("unexpected anchored rebase outcome: {outcome:?}"),
    };
    assert_eq!(replaced.head.revision, installed_head.revision + 1);

    let (strict_winner, _) = load_persisted_cache_candidate_for_publisher(
        &db,
        &identity,
        FixedBytes::from([0x41; 32]),
        Some(strict_fallback_cache),
        Some(&installed_head),
    )
    .expect("fall back to strict current winner after anchor mismatch");
    assert_eq!(
        strict_winner
            .expect("strict current winner")
            .journal_head
            .expect("strict current head")
            .revision,
        replaced.head.revision
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp DB root");
}

#[test]
fn persisted_root_and_validation_provenance_must_match_payload() {
    let root_dir = temp_db_root("malformed-persisted-root");
    fs::create_dir_all(&root_dir).expect("create temp DB root");
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open temp DB");
    let identity = test_identity();
    let cache = test_cache(&identity, &[0x32]);
    let root = test_cache_root(&cache);
    let entry = test_entry(&identity, 0, root.0);
    let mut malformed = persisted_cache(&identity, cache.clone(), 0, root, &entry).record;
    malformed.current_tip_root = FixedBytes::from([0xff; 32]);
    db.put_poi_artifact_cache(&malformed)
        .expect("persist mismatched root");
    assert!(matches!(
        load_persisted_cache(&db, &identity),
        Err(PoiArtifactError::PersistedRootMismatch { tip_index: 0 })
    ));

    let generation = db
        .poi_artifact_cache_generation()
        .expect("cache generation");
    let expected_base = observed_corrupt_expected_base(&db, &identity);
    persist_public_rpc_cache(&db, &cache, generation, 0, expected_base)
        .expect("replace root-mismatched corpus");
    let persisted = load_persisted_cache(&db, &identity)
        .expect("load public corpus")
        .expect("public corpus");
    let expected_state = persisted.expected_base().into_db_state();
    let mut malformed = persisted.record;
    malformed.cache_payload = persisted.cache.to_bytes().expect("encode public corpus");
    malformed.validation = PoiCorpusValidationRecord::ListSignedRanges {
        list_key: FixedBytes::from([0xee; 32]),
        from_index: 0,
    };
    assert!(matches!(
        db.rebase_poi_corpus_journal_if_current(
            malformed,
            1,
            1,
            PoiCorpusJournalCommitCondition {
                expected_generation: generation,
                expected_publisher: None,
                expected_manifest_hash: None,
                expected_state,
            },
        )
        .expect("persist mismatched provenance"),
        PoiCorpusJournalCommitOutcome::Applied(_)
    ));
    assert!(matches!(
        load_persisted_cache(&db, &identity),
        Err(PoiArtifactError::PersistedValidationProvenance { .. })
    ));

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp DB root");
}

#[test]
fn materialized_corpus_rejects_validated_roots_that_do_not_match_forest() {
    let identity = test_identity();
    let mut forest = MerkleForest::new();
    forest
        .insert_leaf(MerkleTreeUpdate {
            tree_number: 0,
            tree_position: 0,
            hash: alloy::primitives::U256::from_be_bytes([0x33; 32]),
        })
        .expect("insert test leaf");
    let forged_root = FixedBytes::from([0xff; 32]);
    let payload = rmp_serde::to_vec_named(&TestPoiCacheSnapshot {
        version: POI_CACHE_SNAPSHOT_VERSION,
        identity: identity.clone(),
        progress: PoiCacheSyncProgress {
            next_event_index: 1,
            next_leaf_index: 1,
            blocked_shields_synced: false,
            root_validation: PoiCacheRootValidation::Validated {
                roots: BTreeMap::from([(0, forged_root)]),
            },
        },
        forest,
        status_by_blinded_commitment: BTreeMap::new(),
        position_by_blinded_commitment: BTreeMap::new(),
        blocked_shields_by_blinded_commitment: BTreeMap::new(),
    })
    .expect("encode malformed test cache");
    let cache = PoiCache::from_bytes(&payload, &identity).expect("decode malformed test cache");
    let actual_root = *cache
        .current_roots_readonly()
        .get(&0)
        .expect("actual test root");
    assert_ne!(actual_root, forged_root);

    let entry = test_entry(&identity, 0, actual_root.0);
    let mut record = persisted_cache(&identity, cache.clone(), 0, actual_root, &entry).record;
    record.current_tip_root = forged_root;

    assert!(matches!(
        validate_materialized_corpus_payload(&record, &cache),
        Err(PoiArtifactError::PersistedRootsNotValidated)
    ));
}

#[test]
fn persisted_record_identity_must_match_payload_identity() {
    let identity = test_identity();
    let cache = test_cache(&identity, &[0x3a]);
    let root = test_cache_root(&cache);
    let entry = test_entry(&identity, 0, root.0);
    let mut record = persisted_cache(&identity, cache, 0, root, &entry).record;
    record.chain_id = 137;

    assert!(matches!(
        validate_persisted_record(&record, &identity, None),
        Err(PoiArtifactError::PersistedIdentityMismatch)
    ));
}

#[tokio::test]
async fn stale_generation_rpc_health_cannot_overwrite_current_health() {
    let root_dir = temp_db_root("generation-fenced-rpc-health");
    fs::create_dir_all(&root_dir).expect("create temp DB root");
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open temp DB");
    let identity = test_identity();
    let reset = clear_poi_artifact_cache_for_reset(&db).expect("advance generation");
    db.put_poi_corpus_rpc_health(&PoiCorpusRpcHealthRecord {
        chain_type: identity.chain_type,
        chain_id: identity.chain_id,
        txid_version: identity.txid_version.clone(),
        list_key: identity.list_key,
        cache_generation: reset.generation,
        last_successful_rpc_sync_at_ms: Some(777),
        updated_at: 0,
    })
    .expect("persist current-generation health");

    assert!(matches!(
        record_poi_rpc_success(&db, &identity, 0),
        Err(PoiArtifactError::StalePublicCacheGeneration {
            expected: 1,
            actual: 0,
        })
    ));
    let retained = db
        .get_poi_corpus_rpc_health(
            identity.chain_type,
            identity.chain_id,
            &identity.txid_version,
            &identity.list_key,
        )
        .expect("load retained health")
        .expect("retained health");
    assert_eq!(retained.cache_generation, reset.generation);
    assert_eq!(retained.last_successful_rpc_sync_at_ms, Some(777));

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp DB root");
}

#[test]
fn expected_absent_public_rpc_candidate_loses_first_writer_race() {
    let root_dir = temp_db_root("rpc-expected-absent-first-writer");
    fs::create_dir_all(&root_dir).expect("create temp DB root");
    let db = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open temp DB");
    let identity = test_identity();
    let first = test_cache(&identity, &[0x61]);
    let stale = test_cache(&identity, &[0x62]);
    let generation = db
        .poi_artifact_cache_generation()
        .expect("cache generation");

    assert_eq!(
        persist_public_rpc_cache(
            &db,
            &first,
            generation,
            0,
            ExpectedPoiCorpusBase::NoValidCorpus,
        )
        .expect("persist first writer"),
        CorpusCommitOutcome::Applied
    );
    assert_eq!(
        persist_public_rpc_cache(
            &db,
            &stale,
            generation,
            0,
            ExpectedPoiCorpusBase::NoValidCorpus,
        )
        .expect("reject stale first-run candidate"),
        CorpusCommitOutcome::Stale
    );

    let retained = load_persisted_cache(&db, &identity)
        .expect("load retained corpus")
        .expect("first writer remains durable");
    assert_eq!(
        retained.cache.to_bytes().expect("encode retained corpus"),
        first.to_bytes().expect("encode first corpus")
    );

    drop(db);
    fs::remove_dir_all(root_dir).expect("remove temp DB root");
}

fn test_identity() -> PoiCacheIdentity {
    PoiCacheIdentity::new(0, 1, "V2_PoseidonMerkle", FixedBytes::from([0x11; 32]))
}

fn temp_db_root(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    std::env::temp_dir().join(format!("sync-service-poi-artifacts-{name}-{unique}"))
}

fn test_entry(
    identity: &PoiCacheIdentity,
    current_tip_index: u64,
    current_tip_merkleroot: [u8; 32],
) -> LegacyManifestEntry {
    LegacyManifestEntry {
        list_key: identity.list_key,
        chain_id: identity.chain_id,
        base: descriptor("base"),
        deltas: vec![descriptor("delta")],
        retained_deltas: Vec::new(),
        blocked_shields: descriptor("blocked"),
        current_tip_index,
        current_tip_merkleroot: FixedBytes::from(current_tip_merkleroot),
    }
}

fn descriptor(cid: &str) -> ArtifactDescriptor {
    ArtifactDescriptor {
        cid: cid.to_string(),
        sha256: FixedBytes::ZERO,
        byte_size: 0,
    }
}

fn test_cache(identity: &PoiCacheIdentity, commitment_bytes: &[u8]) -> PoiCache {
    let events = commitment_bytes
        .iter()
        .enumerate()
        .map(|(index, byte)| SnapshotEvent {
            event_index: index as u64,
            blinded_commitment: [*byte; 32],
            signature: [0_u8; 64],
            event_type: PoiEventType::Transact,
        })
        .collect::<Vec<_>>();
    let mut cache = PoiCache::new(identity.clone());
    cache
        .apply_verified_artifact_events(&events)
        .expect("apply test artifact events");
    cache.accept_current_roots();
    cache
}

fn test_cache_root(cache: &PoiCache) -> FixedBytes<32> {
    *cache
        .clone()
        .current_roots()
        .get(&0)
        .expect("test cache root")
}

fn observed_corrupt_expected_base(
    db: &DbStore,
    identity: &PoiCacheIdentity,
) -> ExpectedPoiCorpusBase {
    match inspect_persisted_cache_with_publisher(db, identity, None)
        .expect("inspect corrupt persisted corpus")
    {
        PersistedPoiCorpusInspection::Corrupt {
            replacement_token, ..
        } => ExpectedPoiCorpusBase::Corrupt { replacement_token },
        _ => panic!("expected corrupt persisted corpus"),
    }
}

fn persisted_cache(
    identity: &PoiCacheIdentity,
    cache: PoiCache,
    current_tip_index: u64,
    current_tip_root: FixedBytes<32>,
    entry: &LegacyManifestEntry,
) -> PersistedPoiArtifactCache {
    PersistedPoiArtifactCache {
        record: PoiArtifactCacheRecord {
            chain_type: identity.chain_type,
            chain_id: identity.chain_id,
            txid_version: identity.txid_version.clone(),
            list_key: identity.list_key,
            cache_generation: 0,
            source: PoiCacheRecordSource::IndexedArtifacts,
            validation: PoiCorpusValidationRecord::Legacy,
            legacy_observed_manifest_sequence: 4,
            base_descriptor: descriptor_record(&descriptor("old-base")),
            applied_delta_descriptors: Vec::new(),
            blocked_shields_descriptor: descriptor_record(&entry.blocked_shields),
            artifact_tip_index: Some(current_tip_index),
            artifact_tip_root: Some(current_tip_root),
            current_tip_index,
            current_tip_root,
            cache_payload: cache.to_bytes().expect("cache bytes"),
            legacy_last_successful_rpc_sync_at_ms: None,
            updated_at: 0,
        },
        cache,
        cache_generation: 0,
        journal_head: None,
        compaction_recommended: false,
    }
}
