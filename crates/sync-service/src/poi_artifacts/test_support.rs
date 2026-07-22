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
    persist_public_rpc_cache_with_publisher(
        db,
        cache,
        cache_generation,
        range_start_index,
        None,
        expected_base,
    )
}
