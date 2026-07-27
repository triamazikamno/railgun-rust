use super::*;

pub(crate) fn poi_v4_manifest_envelope_signing_message(manifest: &Manifest) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct ManifestBody {
        format_version: u16,
        issued_at_ms: u64,
        sequence: u64,
        publisher_pubkey: FixedBytes<32>,
        entries: Vec<ManifestEntry>,
    }

    let mut entries = manifest.entries.clone();
    entries.sort_by(|left, right| left.scope.cmp(&right.scope));
    let body = serde_json::to_vec(&ManifestBody {
        format_version: manifest.format_version,
        issued_at_ms: manifest.issued_at_ms,
        sequence: manifest.sequence,
        publisher_pubkey: manifest.publisher_pubkey,
        entries,
    })
    .expect("test manifest body is JSON serializable");
    let mut message =
        Vec::with_capacity(poi::artifacts::v4::MANIFEST_SIGNATURE_DOMAIN.len() + body.len());
    message.extend_from_slice(poi::artifacts::v4::MANIFEST_SIGNATURE_DOMAIN);
    message.extend_from_slice(&body);
    message
}

pub(crate) fn observe_manifest(
    db: &DbStore,
    trusted_publisher_pubkey: FixedBytes<32>,
    manifest: Manifest,
    max_age: Option<Duration>,
    now: SystemTime,
) -> Result<ObservedManifest, PoiArtifactError> {
    observe_manifest_with_clock(db, trusted_publisher_pubkey, manifest, max_age, &|| now)
}

pub(crate) fn load_persisted_cache(
    db: &DbStore,
    identity: &PoiCacheIdentity,
) -> Result<Option<PersistedPoiArtifactCache>, PoiArtifactError> {
    load_persisted_cache_with_publisher(db, identity, None)
}

pub(crate) fn persist_public_rpc_cache(
    db: &DbStore,
    cache: &PoiCache,
    cache_generation: u64,
    range_start_index: u64,
    expected_base: ExpectedPoiCorpusBase,
) -> Result<CorpusCommitOutcome, PoiArtifactError> {
    let identity = cache.identity();
    let starting = if matches!(
        expected_base,
        ExpectedPoiCorpusBase::NoValidCorpus | ExpectedPoiCorpusBase::Corrupt { .. }
    ) {
        None
    } else {
        load_persisted_cache(db, identity)?
    };
    let starting_record = starting
        .as_ref()
        .map(PersistedPoiArtifactCache::metadata_only);
    let starting_head = starting.and_then(|persisted| persisted.journal_head);
    let event_end_cursor = cache.progress().next_event_index;
    let mut events = Vec::new();
    let mut leaves = Vec::new();
    for event_index in range_start_index..event_end_cursor {
        let blinded_commitment = cache.commitment_at_global_index(event_index).ok_or(
            PoiArtifactError::PersistedArtifactMetadata {
                reason: "test cache has no commitment for journal delta",
            },
        )?;
        events.push(poi::cache::PoiCacheJournalEvent {
            event_index,
            blinded_commitment,
        });
        leaves.push(blinded_commitment);
    }
    let delta = PoiCacheJournalDelta {
        version: poi::cache::POI_CACHE_JOURNAL_DELTA_VERSION,
        identity: identity.clone(),
        event_start_cursor: range_start_index,
        event_end_cursor,
        leaf_start_cursor: range_start_index,
        leaf_end_cursor: cache.progress().next_leaf_index,
        events,
        leaves,
    };
    match persist_public_rpc_cache_with_publisher(
        db,
        cache.clone(),
        cache_generation,
        range_start_index,
        None,
        expected_base,
        starting_record.as_ref(),
        starting_head.as_ref(),
        &delta,
        None,
    )? {
        PublicRpcPersistResult::Applied(_) => Ok(CorpusCommitOutcome::Applied),
        PublicRpcPersistResult::Stale => Ok(CorpusCommitOutcome::Stale),
        PublicRpcPersistResult::CompactionRequired(_) => {
            Err(PoiArtifactError::JournalHardLimitExceeded)
        }
    }
}
