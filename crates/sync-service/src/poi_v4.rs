//! Typed public data-plane persistence boundary for the fixed POI v4 protocol.
//!
//! The module name is the explicit version boundary, so runtime types within it use concise names.
//! Network discovery, retrieval, planning, and replay remain private ingestion concerns. This
//! module exposes only authority-bearing graph, cache, candidate, and persistence tokens used by
//! [`crate::PublicDataPlaneHandle::poi_artifact_persistence`].
//!
//! Raw retention requires [`SemanticVerifiedChunk`], and corpus commit requires
//! [`VerifiedCorpusCandidate`]. Neither capability has a public constructor from bytes,
//! booleans, or an arbitrary `poi::cache::PoiCache`.

pub use crate::chain::PoiArtifactPersistenceHandle as PersistenceHandle;
pub use crate::poi_artifacts::{
    CandidateError, CorpusCandidate, CorpusCommitOutcome, CurrentChunk, FetchedArtifact,
    ObservedManifest, RawChunkRetainOutcome, SemanticVerifiedChunk, TransportVerifiedChunk,
    VerifiedBlockedShields, VerifiedCatalog, VerifiedCorpusCandidate,
};
