use super::*;

#[test]
fn poi_corpus_journal_inspection_rejects_discontinuous_or_corrupt_rows() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let base = sample_poi_artifact_cache_record(1, FixedBytes::from([0x7c; 32]));
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
    let end_root = FixedBytes::from([0x7d; 32]);
    let applied = match store
        .append_poi_corpus_journal_if_current(
            sample_journal_head(&persisted_base, 101, 101, end_root),
            Some(sample_journal_delta(
                &persisted_base,
                100,
                101,
                persisted_base.current_tip_root,
                end_root,
            )),
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
        .expect("append valid journal revision")
    {
        PoiCorpusJournalCommitOutcome::Applied(applied) => applied,
        outcome => panic!("unexpected journal append outcome: {outcome:?}"),
    };
    let head = applied.head;
    let delta = applied.delta.expect("stored delta");
    let blocked = applied.blocked.expect("stored blocked snapshot");
    let assert_corrupt = || {
        assert!(matches!(
            store
                .inspect_poi_corpus_journal(
                    base.chain_type,
                    base.chain_id,
                    &base.txid_version,
                    &base.list_key,
                )
                .expect("inspect corrupted journal"),
            StoredRecord::Corrupt { .. }
        ));
    };

    let mut malformed_delta = delta.clone();
    malformed_delta.cache_generation = 1;
    insert_raw_poi_journal_row(
        &store,
        &delta.key(),
        &encode(&malformed_delta).expect("encode wrong-generation delta"),
    );
    assert_corrupt();

    malformed_delta = delta.clone();
    malformed_delta.base_revision = malformed_delta.base_revision.saturating_add(1);
    insert_raw_poi_journal_row(
        &store,
        &delta.key(),
        &encode(&malformed_delta).expect("encode wrong-base delta"),
    );
    assert_corrupt();

    malformed_delta = delta.clone();
    malformed_delta.list_key = FixedBytes::from([0x7f; 32]);
    insert_raw_poi_journal_row(
        &store,
        &delta.key(),
        &encode(&malformed_delta).expect("encode wrong-identity delta"),
    );
    assert_corrupt();

    malformed_delta = delta.clone();
    malformed_delta.start_tip_root = FixedBytes::from([0x7e; 32]);
    insert_raw_poi_journal_row(
        &store,
        &delta.key(),
        &encode(&malformed_delta).expect("encode root-discontinuous delta"),
    );
    assert_corrupt();

    remove_raw_poi_journal_row(&store, &delta.key());
    assert_corrupt();
    insert_raw_poi_journal_row(
        &store,
        &delta.key(),
        &encode(&delta).expect("restore valid delta"),
    );

    let mut malformed_blocked = blocked.clone();
    malformed_blocked.payload_hash = FixedBytes::ZERO;
    insert_raw_poi_journal_row(
        &store,
        &blocked.key(),
        &encode(&malformed_blocked).expect("encode corrupt blocked snapshot"),
    );
    assert_corrupt();

    remove_raw_poi_journal_row(&store, &blocked.key());
    assert_corrupt();
    insert_raw_poi_journal_row(
        &store,
        &blocked.key(),
        &encode(&blocked).expect("restore valid blocked snapshot"),
    );

    let duplicate_key = format!("{}-duplicate", delta.key());
    insert_raw_poi_journal_row(
        &store,
        &duplicate_key,
        &encode(&delta).expect("encode duplicate logical delta"),
    );
    assert_corrupt();
    remove_raw_poi_journal_row(&store, &duplicate_key);

    let mut malformed_head = head.clone();
    malformed_head.base_payload_hash = FixedBytes::from([0x80; 32]);
    insert_raw_poi_journal_row(
        &store,
        &head.key(),
        &encode(&malformed_head).expect("encode wrong-base journal head"),
    );
    assert_corrupt();

    insert_raw_poi_journal_row(&store, &head.key(), &[0xc1]);
    assert_corrupt();

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn poi_corpus_journal_inspection_rejects_trailing_messagepack_values_and_suffixes() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let base = sample_poi_artifact_cache_record(1, FixedBytes::from([0x83; 32]));
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
    let end_root = FixedBytes::from([0x84; 32]);
    let applied = match store
        .append_poi_corpus_journal_if_current(
            sample_journal_head(&persisted_base, 101, 101, end_root),
            Some(sample_journal_delta(
                &persisted_base,
                100,
                101,
                persisted_base.current_tip_root,
                end_root,
            )),
            Some(PoiCorpusBlockedSnapshotRecord {
                format_version: 0,
                chain_type: base.chain_type,
                chain_id: base.chain_id,
                txid_version: base.txid_version.clone(),
                list_key: base.list_key,
                cache_generation: 0,
                revision: 0,
                payload_hash: FixedBytes::ZERO,
                payload: vec![0x90],
                updated_at: 0,
            }),
            implicit_journal_condition(&persisted_base),
        )
        .expect("append valid journal revision")
    {
        PoiCorpusJournalCommitOutcome::Applied(applied) => applied,
        outcome => panic!("unexpected journal append outcome: {outcome:?}"),
    };
    let head = applied.head;
    let delta = applied.delta.expect("stored delta");
    let blocked = applied.blocked.expect("stored blocked snapshot");
    let trailing_suffixes = [[0xc0_u8].as_slice(), [0xc1_u8].as_slice()];
    let with_suffix = |mut bytes: Vec<u8>, suffix: &[u8]| {
        bytes.extend_from_slice(suffix);
        bytes
    };

    for suffix in trailing_suffixes {
        insert_raw_poi_journal_row(
            &store,
            &head.key(),
            &with_suffix(encode(&head).expect("encode head"), suffix),
        );
        assert!(matches!(
            store
                .inspect_poi_corpus_journal_head(
                    base.chain_type,
                    base.chain_id,
                    &base.txid_version,
                    &base.list_key,
                )
                .expect("inspect head with trailing bytes"),
            StoredRecord::Corrupt { .. }
        ));
        assert!(matches!(
            store
                .inspect_poi_corpus_journal_detailed(
                    base.chain_type,
                    base.chain_id,
                    &base.txid_version,
                    &base.list_key,
                )
                .expect("inspect journal with trailing head bytes"),
            PoiCorpusJournalInspection::Corrupt { .. }
        ));
        insert_raw_poi_journal_row(&store, &head.key(), &encode(&head).expect("restore head"));

        insert_raw_poi_journal_row(
            &store,
            &delta.key(),
            &with_suffix(encode(&delta).expect("encode delta"), suffix),
        );
        assert!(matches!(
            store
                .inspect_poi_corpus_journal_detailed(
                    base.chain_type,
                    base.chain_id,
                    &base.txid_version,
                    &base.list_key,
                )
                .expect("inspect journal with trailing delta bytes"),
            PoiCorpusJournalInspection::Corrupt { .. }
        ));
        insert_raw_poi_journal_row(
            &store,
            &delta.key(),
            &encode(&delta).expect("restore delta"),
        );

        insert_raw_poi_journal_row(
            &store,
            &blocked.key(),
            &with_suffix(encode(&blocked).expect("encode blocked snapshot"), suffix),
        );
        assert!(matches!(
            store
                .inspect_poi_corpus_journal_detailed(
                    base.chain_type,
                    base.chain_id,
                    &base.txid_version,
                    &base.list_key,
                )
                .expect("inspect journal with trailing blocked bytes"),
            PoiCorpusJournalInspection::Corrupt { .. }
        ));
        insert_raw_poi_journal_row(
            &store,
            &blocked.key(),
            &encode(&blocked).expect("restore blocked snapshot"),
        );
    }
    assert!(matches!(
        store
            .inspect_poi_corpus_journal_detailed(
                base.chain_type,
                base.chain_id,
                &base.txid_version,
                &base.list_key,
            )
            .expect("inspect restored journal"),
        PoiCorpusJournalInspection::Valid { .. }
    ));

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn corrupt_poi_corpus_replacement_requires_the_exact_observed_bytes() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let base = sample_poi_artifact_cache_record(1, FixedBytes::from([0x81; 32]));
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
    let end_root = FixedBytes::from([0x82; 32]);
    let applied = match store
        .append_poi_corpus_journal_if_current(
            sample_journal_head(&persisted_base, 101, 101, end_root),
            Some(sample_journal_delta(
                &persisted_base,
                100,
                101,
                persisted_base.current_tip_root,
                end_root,
            )),
            None,
            implicit_journal_condition(&persisted_base),
        )
        .expect("append journal delta")
    {
        PoiCorpusJournalCommitOutcome::Applied(applied) => applied,
        outcome => panic!("unexpected journal append outcome: {outcome:?}"),
    };
    let delta_key = applied.delta.as_ref().expect("stored delta").key();
    insert_raw_poi_journal_row(&store, &delta_key, &[0xc1]);
    let first_token = match store
        .inspect_poi_corpus_journal_detailed(
            base.chain_type,
            base.chain_id,
            &base.txid_version,
            &base.list_key,
        )
        .expect("inspect first corruption")
    {
        PoiCorpusJournalInspection::Corrupt {
            replacement_token, ..
        } => replacement_token,
        other => panic!("unexpected first corruption inspection: {other:?}"),
    };

    insert_raw_poi_journal_row(&store, &delta_key, &[0xc2]);
    let mut replacement = persisted_base;
    replacement.current_tip_index = 100;
    replacement.current_tip_root = end_root;
    replacement.cache_payload = vec![9, 8, 7, 6];
    let replacement_generation = replacement.cache_generation;
    let condition = |replacement_token| PoiCorpusJournalCommitCondition {
        expected_generation: replacement_generation,
        expected_publisher: None,
        expected_manifest_hash: None,
        expected_state: ExpectedPoiCorpusJournalState::Corrupt { replacement_token },
    };
    assert_eq!(
        store
            .rebase_poi_corpus_journal_if_current(
                replacement.clone(),
                101,
                101,
                condition(first_token),
            )
            .expect("reject stale corrupt replacement token"),
        PoiCorpusJournalCommitOutcome::CorpusConflict
    );
    let current_token = match store
        .inspect_poi_corpus_journal_detailed(
            base.chain_type,
            base.chain_id,
            &base.txid_version,
            &base.list_key,
        )
        .expect("inspect current corruption")
    {
        PoiCorpusJournalInspection::Corrupt {
            replacement_token, ..
        } => replacement_token,
        other => panic!("unexpected current corruption inspection: {other:?}"),
    };
    assert_ne!(current_token, first_token);
    let rebased = match store
        .rebase_poi_corpus_journal_if_current(replacement, 101, 101, condition(current_token))
        .expect("replace exactly observed corruption")
    {
        PoiCorpusJournalCommitOutcome::Applied(commit) => commit,
        outcome => panic!("unexpected corrupt replacement outcome: {outcome:?}"),
    };
    assert_eq!(rebased.head.revision, 2);
    assert_eq!(rebased.retired_delta_count, 1);
    assert!(matches!(
        store
            .inspect_poi_corpus_journal(
                base.chain_type,
                base.chain_id,
                &base.txid_version,
                &base.list_key,
            )
            .expect("inspect replacement"),
        StoredRecord::Valid(_)
    ));

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn blocked_snapshot_only_justifies_revision_holes_through_its_revision() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let base = sample_poi_artifact_cache_record(1, FixedBytes::from([0x83; 32]));
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
    let end_root = FixedBytes::from([0x84; 32]);
    let mut delta = sample_journal_delta(
        &persisted_base,
        100,
        101,
        persisted_base.current_tip_root,
        end_root,
    );
    delta.format_version = POI_CORPUS_JOURNAL_FORMAT_VERSION;
    delta.revision = 3;
    delta.previous_revision = 2;
    delta.base_revision = 0;
    let blocked_payload = vec![0x91, 0x92];
    let blocked = PoiCorpusBlockedSnapshotRecord {
        format_version: POI_CORPUS_JOURNAL_FORMAT_VERSION,
        chain_type: base.chain_type,
        chain_id: base.chain_id,
        txid_version: base.txid_version.clone(),
        list_key: base.list_key,
        cache_generation: 0,
        revision: 2,
        payload_hash: keccak256(&blocked_payload),
        payload: blocked_payload,
        updated_at: 0,
    };
    let mut head = sample_journal_head(&persisted_base, 101, 101, end_root);
    head.revision = 3;
    head.base_revision = 0;
    head.base_payload_hash = keccak256(&persisted_base.cache_payload);
    head.delta_count = 1;
    head.delta_payload_bytes = delta.payload.len() as u64;
    head.blocked_revision = Some(2);
    head.blocked_payload_hash = Some(blocked.payload_hash);
    insert_raw_poi_journal_row(
        &store,
        &delta.key(),
        &encode(&delta).expect("encode revision-three delta"),
    );
    insert_raw_poi_journal_row(
        &store,
        &blocked.key(),
        &encode(&blocked).expect("encode revision-two blocked snapshot"),
    );
    insert_raw_poi_journal_row(
        &store,
        &head.key(),
        &encode(&head).expect("encode revision-three head"),
    );
    assert!(matches!(
        store
            .inspect_poi_corpus_journal(
                base.chain_type,
                base.chain_id,
                &base.txid_version,
                &base.list_key,
            )
            .expect("inspect blocked-covered revision hole"),
        StoredRecord::Valid(_)
    ));

    delta.previous_revision = 1;
    insert_raw_poi_journal_row(
        &store,
        &delta.key(),
        &encode(&delta).expect("encode skipped predecessor delta"),
    );
    assert!(matches!(
        store
            .inspect_poi_corpus_journal(
                base.chain_type,
                base.chain_id,
                &base.txid_version,
                &base.list_key,
            )
            .expect("inspect skipped predecessor"),
        StoredRecord::Corrupt { .. }
    ));

    delta.previous_revision = 2;
    insert_raw_poi_journal_row(
        &store,
        &delta.key(),
        &encode(&delta).expect("restore immediate predecessor"),
    );
    remove_raw_poi_journal_row(&store, &blocked.key());
    head.blocked_revision = None;
    head.blocked_payload_hash = None;
    insert_raw_poi_journal_row(
        &store,
        &head.key(),
        &encode(&head).expect("encode head without blocked coverage"),
    );
    assert!(matches!(
        store
            .inspect_poi_corpus_journal(
                base.chain_type,
                base.chain_id,
                &base.txid_version,
                &base.list_key,
            )
            .expect("inspect uncovered revision hole"),
        StoredRecord::Corrupt { .. }
    ));

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}
