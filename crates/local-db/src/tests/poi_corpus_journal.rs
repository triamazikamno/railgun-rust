use super::*;

#[test]
fn legacy_poi_artifact_cache_record_defaults_to_indexed_artifact_source() {
    #[derive(serde::Serialize)]
    struct LegacyPoiArtifactCacheRecord {
        chain_type: u8,
        chain_id: u64,
        txid_version: String,
        list_key: FixedBytes<32>,
        last_accepted_manifest_sequence: u64,
        base_descriptor: PoiArtifactDescriptorRecord,
        applied_delta_descriptors: Vec<PoiArtifactDescriptorRecord>,
        blocked_shields_descriptor: PoiArtifactDescriptorRecord,
        current_tip_index: u64,
        current_tip_root: FixedBytes<32>,
        cache_payload: Vec<u8>,
        last_successful_rpc_sync_at_ms: Option<u64>,
        updated_at: u64,
    }

    let current = sample_poi_artifact_cache_record(1, FixedBytes::from([0x71; 32]));
    let encoded = encode(&LegacyPoiArtifactCacheRecord {
        chain_type: current.chain_type,
        chain_id: current.chain_id,
        txid_version: current.txid_version,
        list_key: current.list_key,
        last_accepted_manifest_sequence: current.legacy_observed_manifest_sequence,
        base_descriptor: current.base_descriptor,
        applied_delta_descriptors: current.applied_delta_descriptors,
        blocked_shields_descriptor: current.blocked_shields_descriptor,
        current_tip_index: current.current_tip_index,
        current_tip_root: current.current_tip_root,
        cache_payload: current.cache_payload,
        last_successful_rpc_sync_at_ms: Some(42),
        updated_at: current.updated_at,
    })
    .expect("encode legacy POI cache record");
    let decoded: PoiArtifactCacheRecord = decode(&encoded).expect("decode legacy POI cache record");

    assert_eq!(decoded.source, PoiCacheRecordSource::IndexedArtifacts);
    assert_eq!(decoded.validation, PoiCorpusValidationRecord::Legacy);
    assert_eq!(decoded.cache_generation, 0);
    assert_eq!(decoded.legacy_observed_manifest_sequence, 7);
    assert_eq!(decoded.artifact_tip_index, None);
    assert_eq!(decoded.artifact_tip_root, None);
    assert_eq!(decoded.legacy_last_successful_rpc_sync_at_ms, Some(42));
}

#[test]
fn poi_artifact_cache_payload_encoding_is_bidirectionally_compatible() {
    #[derive(serde::Deserialize)]
    struct PlainPayloadRecord {
        cache_payload: Vec<u8>,
    }

    let record = sample_poi_artifact_cache_record(1, FixedBytes::from([0x72; 32]));
    let encoded = encode(&record).expect("encode byte-specialized POI cache record");
    let decoded: PlainPayloadRecord =
        decode(&encoded).expect("decode byte-specialized payload through plain Vec");

    assert_eq!(decoded.cache_payload, record.cache_payload);
}

#[test]
fn poi_corpus_journal_adopts_legacy_base_and_appends_atomically() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let base = sample_poi_artifact_cache_record(1, FixedBytes::from([0x73; 32]));
    store
        .put_poi_artifact_cache(&base)
        .expect("store implicit journal base");
    drop(store);
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("reopen db with implicit journal base");
    let persisted_base = store
        .get_poi_artifact_cache(
            base.chain_type,
            base.chain_id,
            &base.txid_version,
            &base.list_key,
        )
        .expect("load implicit journal base")
        .expect("implicit journal base");
    let end_root = FixedBytes::from([0x74; 32]);
    let head = sample_journal_head(&persisted_base, 101, 101, end_root);
    let delta = sample_journal_delta(
        &persisted_base,
        100,
        101,
        persisted_base.current_tip_root,
        end_root,
    );

    let applied = match store
        .append_poi_corpus_journal_if_current(
            head,
            Some(delta),
            None,
            implicit_journal_condition(&persisted_base),
        )
        .expect("append journal delta")
    {
        PoiCorpusJournalCommitOutcome::Applied(applied) => applied,
        outcome => panic!("unexpected journal append outcome: {outcome:?}"),
    };

    assert_eq!(applied.head.revision, 1);
    assert_eq!(applied.head.base_revision, 0);
    assert_eq!(applied.head.delta_count, 1);
    assert_eq!(applied.head.delta_payload_bytes, 3);
    assert_eq!(applied.delta.as_ref().map(|delta| delta.revision), Some(1));
    assert!(applied.base.is_none());
    let bundle = match store
        .inspect_poi_corpus_journal(
            base.chain_type,
            base.chain_id,
            &base.txid_version,
            &base.list_key,
        )
        .expect("inspect explicit journal")
    {
        StoredRecord::Valid(bundle) => bundle,
        other => panic!("unexpected stored journal: {other:?}"),
    };
    assert_eq!(bundle.base.cache_payload, base.cache_payload);
    assert_eq!(bundle.head, Some(applied.head.clone()));
    assert_eq!(bundle.deltas, applied.delta.into_iter().collect::<Vec<_>>());
    assert!(bundle.blocked.is_none());

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn poi_corpus_journal_blocked_only_revision_does_not_add_delta() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let base = sample_poi_artifact_cache_record(1, FixedBytes::from([0x75; 32]));
    store
        .put_poi_artifact_cache(&base)
        .expect("store implicit journal base");
    let persisted_base = store
        .get_poi_artifact_cache(
            base.chain_type,
            base.chain_id,
            &base.txid_version,
            &base.list_key,
        )
        .expect("load implicit journal base")
        .expect("implicit journal base");
    let first = match store
        .append_poi_corpus_journal_if_current(
            sample_journal_head(&persisted_base, 100, 100, persisted_base.current_tip_root),
            None,
            Some(PoiCorpusBlockedSnapshotRecord {
                format_version: 0,
                chain_type: base.chain_type,
                chain_id: base.chain_id,
                txid_version: base.txid_version.clone(),
                list_key: base.list_key,
                cache_generation: 0,
                revision: 0,
                payload_hash: FixedBytes::ZERO,
                payload: vec![0x91, 0x92],
                updated_at: 0,
            }),
            implicit_journal_condition(&persisted_base),
        )
        .expect("commit blocked-only revision")
    {
        PoiCorpusJournalCommitOutcome::Applied(applied) => applied,
        outcome => panic!("unexpected blocked-only outcome: {outcome:?}"),
    };

    assert_eq!(first.head.revision, 1);
    assert_eq!(first.head.delta_count, 0);
    assert_eq!(first.head.delta_payload_bytes, 0);
    assert!(first.delta.is_none());
    assert_eq!(first.head.blocked_revision, Some(1));
    assert_eq!(
        first.blocked.as_ref().map(|blocked| blocked.revision),
        Some(1)
    );
    let bundle = match store
        .inspect_poi_corpus_journal(
            base.chain_type,
            base.chain_id,
            &base.txid_version,
            &base.list_key,
        )
        .expect("inspect blocked-only journal")
    {
        StoredRecord::Valid(bundle) => bundle,
        other => panic!("unexpected stored journal: {other:?}"),
    };
    assert_eq!(bundle.deltas, [] as [PoiCorpusJournalDeltaRecord; 0]);
    assert_eq!(bundle.blocked, first.blocked);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn stale_poi_corpus_journal_append_leaves_no_partial_delta() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let base = sample_poi_artifact_cache_record(1, FixedBytes::from([0x76; 32]));
    store
        .put_poi_artifact_cache(&base)
        .expect("store implicit journal base");
    let persisted_base = store
        .get_poi_artifact_cache(
            base.chain_type,
            base.chain_id,
            &base.txid_version,
            &base.list_key,
        )
        .expect("load implicit journal base")
        .expect("implicit journal base");
    let condition = implicit_journal_condition(&persisted_base);
    let first_root = FixedBytes::from([0x77; 32]);
    let first = store
        .append_poi_corpus_journal_if_current(
            sample_journal_head(&persisted_base, 101, 101, first_root),
            Some(sample_journal_delta(
                &persisted_base,
                100,
                101,
                persisted_base.current_tip_root,
                first_root,
            )),
            None,
            condition,
        )
        .expect("commit first journal winner");
    assert!(matches!(first, PoiCorpusJournalCommitOutcome::Applied(_)));

    let stale_root = FixedBytes::from([0x78; 32]);
    assert_eq!(
        store
            .append_poi_corpus_journal_if_current(
                sample_journal_head(&persisted_base, 101, 101, stale_root),
                Some(sample_journal_delta(
                    &persisted_base,
                    100,
                    101,
                    persisted_base.current_tip_root,
                    stale_root,
                )),
                None,
                condition,
            )
            .expect("reject stale journal append"),
        PoiCorpusJournalCommitOutcome::CorpusConflict
    );
    let bundle = match store
        .inspect_poi_corpus_journal(
            base.chain_type,
            base.chain_id,
            &base.txid_version,
            &base.list_key,
        )
        .expect("inspect winning journal")
    {
        StoredRecord::Valid(bundle) => bundle,
        other => panic!("unexpected stored journal: {other:?}"),
    };
    assert_eq!(bundle.deltas.len(), 1);
    assert_eq!(bundle.head.expect("journal head").revision, 1);

    let winning_bundle = match store
        .inspect_poi_corpus_journal(
            base.chain_type,
            base.chain_id,
            &base.txid_version,
            &base.list_key,
        )
        .expect("inspect winning journal before stale rebase")
    {
        StoredRecord::Valid(bundle) => bundle,
        other => panic!("unexpected stored journal: {other:?}"),
    };
    let mut stale_rebase = persisted_base;
    stale_rebase.current_tip_index = 100;
    stale_rebase.current_tip_root = first_root;
    stale_rebase.cache_payload = vec![9, 8, 7, 6];
    assert_eq!(
        store
            .rebase_poi_corpus_journal_if_current(stale_rebase, 101, 101, condition)
            .expect("reject stale journal rebase"),
        PoiCorpusJournalCommitOutcome::CorpusConflict
    );
    let after_stale_rebase = match store
        .inspect_poi_corpus_journal(
            base.chain_type,
            base.chain_id,
            &base.txid_version,
            &base.list_key,
        )
        .expect("inspect journal after stale rebase")
    {
        StoredRecord::Valid(bundle) => bundle,
        other => panic!("unexpected stored journal: {other:?}"),
    };
    assert_eq!(after_stale_rebase, winning_bundle);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn poi_corpus_journal_rebase_retires_deltas_and_reset_clears_all_state() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let base = sample_poi_artifact_cache_record(1, FixedBytes::from([0x79; 32]));
    store
        .put_poi_artifact_cache(&base)
        .expect("store implicit journal base");
    let persisted_base = store
        .get_poi_artifact_cache(
            base.chain_type,
            base.chain_id,
            &base.txid_version,
            &base.list_key,
        )
        .expect("load implicit journal base")
        .expect("implicit journal base");
    let append_root = FixedBytes::from([0x7a; 32]);
    let appended = match store
        .append_poi_corpus_journal_if_current(
            sample_journal_head(&persisted_base, 101, 101, append_root),
            Some(sample_journal_delta(
                &persisted_base,
                100,
                101,
                persisted_base.current_tip_root,
                append_root,
            )),
            None,
            implicit_journal_condition(&persisted_base),
        )
        .expect("append before rebase")
    {
        PoiCorpusJournalCommitOutcome::Applied(applied) => applied,
        outcome => panic!("unexpected append outcome: {outcome:?}"),
    };
    let mut replacement = persisted_base;
    replacement.current_tip_index = 100;
    replacement.current_tip_root = append_root;
    replacement.cache_payload = vec![9, 8, 7, 6];
    let rebased = match store
        .rebase_poi_corpus_journal_if_current(
            replacement.clone(),
            101,
            101,
            explicit_journal_condition(&appended.head),
        )
        .expect("rebase journal")
    {
        PoiCorpusJournalCommitOutcome::Applied(applied) => applied,
        outcome => panic!("unexpected rebase outcome: {outcome:?}"),
    };
    assert_eq!(rebased.head.revision, 2);
    assert_eq!(rebased.head.base_revision, 2);
    assert_eq!(rebased.head.delta_count, 0);
    assert_eq!(rebased.retired_delta_count, 1);
    let bundle = match store
        .inspect_poi_corpus_journal(
            base.chain_type,
            base.chain_id,
            &base.txid_version,
            &base.list_key,
        )
        .expect("inspect rebased journal")
    {
        StoredRecord::Valid(bundle) => bundle,
        other => panic!("unexpected rebased journal: {other:?}"),
    };
    assert_eq!(bundle.base.cache_payload, replacement.cache_payload);
    assert_eq!(bundle.deltas, [] as [PoiCorpusJournalDeltaRecord; 0]);
    assert!(bundle.blocked.is_none());

    let (removed, generation) = store
        .clear_poi_artifact_cache_with_generation()
        .expect("clear rebased journal");
    assert_eq!(removed, 1);
    assert_eq!(generation, 1);
    assert!(matches!(
        store
            .inspect_poi_corpus_journal(
                base.chain_type,
                base.chain_id,
                &base.txid_version,
                &base.list_key,
            )
            .expect("inspect cleared journal"),
        StoredRecord::Missing
    ));

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn poi_corpus_journal_rejects_generation_race_and_corrupt_or_unbounded_head() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let base = sample_poi_artifact_cache_record(1, FixedBytes::from([0x7b; 32]));
    store
        .put_poi_artifact_cache(&base)
        .expect("store implicit journal base");
    let persisted_base = store
        .get_poi_artifact_cache(
            base.chain_type,
            base.chain_id,
            &base.txid_version,
            &base.list_key,
        )
        .expect("load implicit journal base")
        .expect("implicit journal base");
    let condition = implicit_journal_condition(&persisted_base);
    store
        .clear_poi_artifact_cache_with_generation()
        .expect("advance generation");
    assert_eq!(
        store
            .append_poi_corpus_journal_if_current(
                sample_journal_head(&persisted_base, 100, 100, persisted_base.current_tip_root,),
                None,
                None,
                condition,
            )
            .expect("reject old-generation append"),
        PoiCorpusJournalCommitOutcome::GenerationConflict { actual: 1 }
    );

    let mut corrupt =
        sample_journal_head(&persisted_base, 100, 100, persisted_base.current_tip_root);
    corrupt.format_version = POI_CORPUS_JOURNAL_FORMAT_VERSION;
    corrupt.base_payload_hash = keccak256(&persisted_base.cache_payload);
    corrupt.delta_payload_bytes = POI_CORPUS_JOURNAL_MAX_PAYLOAD_BYTES.saturating_add(1);
    put_raw_poi_artifact_record(
        &store,
        &persisted_base.key(),
        &encode(&persisted_base).expect("encode restored base"),
    );
    insert_raw_poi_journal_row(
        &store,
        &corrupt.key(),
        &encode(&corrupt).expect("encode corrupt journal head"),
    );
    assert!(matches!(
        store
            .inspect_poi_corpus_journal(
                base.chain_type,
                base.chain_id,
                &base.txid_version,
                &base.list_key,
            )
            .expect("inspect corrupt journal"),
        StoredRecord::Corrupt { .. }
    ));

    corrupt.delta_payload_bytes = 0;
    corrupt.delta_count = crate::POI_CORPUS_JOURNAL_MAX_DELTA_COUNT.saturating_add(1);
    insert_raw_poi_journal_row(
        &store,
        &corrupt.key(),
        &encode(&corrupt).expect("encode count-unbounded journal head"),
    );
    assert!(matches!(
        store
            .inspect_poi_corpus_journal(
                base.chain_type,
                base.chain_id,
                &base.txid_version,
                &base.list_key,
            )
            .expect("inspect count-unbounded journal"),
        StoredRecord::Corrupt { .. }
    ));

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
