use ed25519_dalek::{Signer, SigningKey};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use serde_json::{Value, json};

use super::*;
use crate::artifacts::verify::{canonical_blocked_shield_message, canonical_poi_event_message};
use crate::poi::{PoiEventType, SignedPoiEvent};

struct MockJsonRpc {
    url: reqwest::Url,
    requests: Receiver<String>,
}

fn identity() -> PoiCacheIdentity {
    PoiCacheIdentity::new(
        0,
        1,
        "V2_PoseidonMerkle",
        FixedBytes::from(signing_key().verifying_key().to_bytes()),
    )
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x11; 32])
}

fn temp_cache_path() -> PathBuf {
    let dir = std::env::temp_dir().join("railgun-broadcaster-tests");
    fs::create_dir_all(&dir).expect("create temp cache dir");
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    dir.join(format!("poi-cache-{pid}-{nanos}.msgpack"))
}

fn event(index: u64, blinded_commitment: FixedBytes<32>) -> PoiSyncedListEvent {
    let mut signed_poi_event = SignedPoiEvent {
        index,
        blinded_commitment,
        signature: String::new(),
        event_type: PoiEventType::Shield,
    };
    signed_poi_event.signature = hex::encode(
        signing_key()
            .sign(&canonical_poi_event_message(&signed_poi_event))
            .to_bytes(),
    );
    PoiSyncedListEvent {
        signed_poi_event,
        validated_merkleroot: hex::encode(FixedBytes::from([0x44; 32])),
    }
}

fn blocked(blinded_commitment: FixedBytes<32>) -> BlockedShield {
    let mut blocked = BlockedShield {
        commitment_hash: hex::encode_prefixed(FixedBytes::from([0x99; 32])),
        blinded_commitment: hex::encode_prefixed(blinded_commitment),
        block_reason: Some("blocked".to_string()),
        signature: String::new(),
    };
    blocked.signature = hex::encode(
        signing_key()
            .sign(&canonical_blocked_shield_message(&blocked))
            .to_bytes(),
    );
    blocked
}

fn spawn_json_rpc(responses: Vec<String>) -> MockJsonRpc {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
    let url = reqwest::Url::parse(&format!("http://{}", listener.local_addr().unwrap()))
        .expect("mock url");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for response in responses {
            let (mut stream, _) = listener.accept().expect("accept request");
            let body = read_http_body(&mut stream);
            tx.send(body).expect("send request body");
            let reply = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                response.len(),
                response
            );
            stream.write_all(reply.as_bytes()).expect("write response");
        }
    });
    MockJsonRpc { url, requests: rx }
}

fn read_http_body(stream: &mut std::net::TcpStream) -> String {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk).expect("read request");
        assert!(read > 0, "connection closed before request body");
        buffer.extend_from_slice(&chunk[..read]);
        if let Some((body_start, content_length)) = request_body_bounds(&buffer)
            && buffer.len() >= body_start + content_length
        {
            return String::from_utf8_lossy(&buffer[body_start..body_start + content_length])
                .to_string();
        }
    }
}

fn request_body_bounds(buffer: &[u8]) -> Option<(usize, usize)> {
    let header_end = buffer.windows(4).position(|window| window == b"\r\n\r\n")?;
    let body_start = header_end + 4;
    let headers = String::from_utf8_lossy(&buffer[..header_end]);
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    Some((body_start, content_length))
}

fn json_rpc_result(result: &Value) -> String {
    json!({ "jsonrpc": "2.0", "id": 1, "result": result }).to_string()
}

fn request_json(mock: &MockJsonRpc) -> Value {
    let body = mock
        .requests
        .recv_timeout(Duration::from_secs(2))
        .expect("receive request");
    serde_json::from_str(&body).expect("request json")
}

#[test]
fn cache_snapshot_roundtrip_preserves_indexes_and_progress() {
    let path = temp_cache_path();
    let mut cache = PoiCache::new(identity());
    let valid_commitment = FixedBytes::from([0x22; 32]);
    let blocked_commitment = FixedBytes::from([0x33; 32]);
    let leaves = vec![U256::from_be_bytes(valid_commitment.0)];

    cache
        .apply_poi_events(&[event(0, valid_commitment)])
        .unwrap();
    cache.apply_poi_leaves(0, &leaves).unwrap();
    cache
        .apply_blocked_shields(&[blocked(blocked_commitment)])
        .unwrap();
    cache.write(&path).unwrap();

    let loaded = PoiCache::load(&path, &identity()).unwrap().unwrap();

    assert_eq!(loaded.progress().next_event_index, 1);
    assert_eq!(loaded.progress().next_leaf_index, 1);
    assert_eq!(loaded.leaf_count(), 1);
    assert_eq!(loaded.status(&valid_commitment), PoiStatus::Valid);
    assert_eq!(loaded.status(&blocked_commitment), PoiStatus::ShieldBlocked);
    assert_eq!(loaded.position(&valid_commitment).unwrap().global_index, 0);

    fs::remove_file(path).unwrap();
}

#[test]
fn cache_snapshot_requires_exact_messagepack_input_and_accepts_legacy_sequence_encoding() {
    let cache = PoiCache::new(identity());
    let named = cache.to_bytes().expect("encode named cache snapshot");
    let legacy_sequence =
        rmp_serde::to_vec(&cache.snapshot).expect("encode legacy sequence cache snapshot");

    PoiCache::from_bytes(&named, &identity()).expect("decode named cache snapshot");
    PoiCache::from_bytes(&legacy_sequence, &identity())
        .expect("decode legacy sequence cache snapshot");
    for suffix in [&[0xc0_u8][..], &[0xc1_u8][..]] {
        let mut tainted = named.clone();
        tainted.extend_from_slice(suffix);
        assert!(PoiCache::from_bytes(&tainted, &identity()).is_err());
    }
}

#[test]
fn cache_derives_roots_at_historical_global_indexes() {
    let mut prefix = PoiCache::new(identity());
    prefix
        .apply_verified_artifact_events(&[SnapshotEvent {
            event_index: 0,
            blinded_commitment: [0x21; 32],
            signature: [0; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply prefix event");
    let prefix_root = prefix.current_roots().remove(&0).expect("prefix root");

    let mut extended = prefix;
    extended
        .apply_verified_artifact_events(&[SnapshotEvent {
            event_index: 1,
            blinded_commitment: [0x22; 32],
            signature: [0; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("apply extension event");
    let current_root = extended.current_roots().remove(&0).expect("extended root");

    assert_eq!(extended.root_at_global_index(0), Some(prefix_root));
    assert_eq!(extended.root_at_global_index(1), Some(current_root));
    assert_eq!(extended.root_at_global_index(TREE_LEAF_COUNT), None);
}

#[test]
fn replacing_blocked_shields_removes_omitted_blocked_only_statuses() {
    let mut cache = PoiCache::new(identity());
    let removed = FixedBytes::from([0x22; 32]);
    let retained = FixedBytes::from([0x33; 32]);
    cache
        .apply_blocked_shields(&[blocked(removed), blocked(retained)])
        .expect("apply blocked shields");

    cache
        .replace_blocked_shields(&[blocked(retained)])
        .expect("replace blocked shields");

    assert_eq!(cache.status(&removed), PoiStatus::Missing);
    assert_eq!(cache.status(&retained), PoiStatus::ShieldBlocked);
}

#[test]
fn proof_generation_fails_closed_until_roots_are_validated() {
    let mut cache = PoiCache::new(identity());
    let blinded_commitment = FixedBytes::from([0x22; 32]);
    let leaves = vec![U256::from_be_bytes(blinded_commitment.0)];
    cache.apply_poi_leaves(0, &leaves).unwrap();

    let missing_validation = cache
        .poi_merkle_proofs(&[blinded_commitment])
        .expect_err("root validation should be required");
    assert!(matches!(
        missing_validation,
        PoiCacheError::RootValidationRequired
    ));

    let roots = cache.current_roots();
    cache.snapshot.progress.root_validation = PoiCacheRootValidation::Validated { roots };
    let proofs = cache.poi_merkle_proofs(&[blinded_commitment]).unwrap();
    assert_eq!(proofs.len(), 1);
    assert_eq!(proofs[0].leaf, U256::from_be_bytes(blinded_commitment.0));
    assert_eq!(proofs[0].elements.len(), broadcaster_core::tree::TREE_DEPTH);
    assert_eq!(proofs[0].indices, U256::ZERO);

    let roots = cache.current_roots();
    cache.snapshot.progress.root_validation = PoiCacheRootValidation::Invalid { roots };
    let invalid_roots = cache
        .poi_merkle_proofs(&[blinded_commitment])
        .expect_err("rejected roots should fail closed");
    assert!(matches!(invalid_roots, PoiCacheError::InvalidRoots));
}

#[test]
fn poi_leaf_error_after_possible_insertion_invalidates_validated_roots() {
    let mut cache = PoiCache::new(identity());
    cache
        .apply_poi_leaves(0, &[U256::from(1)])
        .expect("seed POI leaf");
    cache.accept_current_roots();
    assert!(cache.validated_roots().is_some());

    let error = cache
        .apply_poi_leaves(u64::MAX, &[U256::from(2)])
        .expect_err("overflowing POI leaf must fail");

    assert!(matches!(error, PoiCacheError::RangeOverflow));
    assert!(cache.validated_roots().is_none());
}

#[test]
fn artifact_event_error_after_possible_insertion_invalidates_validated_roots() {
    let mut cache = PoiCache::new(identity());
    cache
        .apply_verified_artifact_events(&[SnapshotEvent {
            event_index: 0,
            blinded_commitment: [0x21; 32],
            signature: [0; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect("seed artifact event");
    cache.accept_current_roots();
    assert!(cache.validated_roots().is_some());

    let error = cache
        .apply_verified_artifact_events(&[SnapshotEvent {
            event_index: u64::MAX,
            blinded_commitment: [0x22; 32],
            signature: [0; 64],
            event_type: PoiEventType::Transact,
        }])
        .expect_err("overflowing artifact event must fail");

    assert!(matches!(error, PoiCacheError::RangeOverflow));
    assert!(cache.validated_roots().is_none());
}

#[test]
fn local_proofs_match_merkle_forest_for_representative_leaves() {
    let mut cache = PoiCache::new(identity());
    let commitments = [
        FixedBytes::from([0x22; 32]),
        FixedBytes::from([0x33; 32]),
        FixedBytes::from([0x44; 32]),
        FixedBytes::from([0x55; 32]),
    ];
    let leaves = commitments
        .iter()
        .copied()
        .map(|commitment| U256::from_be_bytes(commitment.0))
        .collect::<Vec<_>>();
    cache.apply_poi_leaves(0, &leaves).unwrap();
    let roots = cache.current_roots();
    cache.snapshot.progress.root_validation = PoiCacheRootValidation::Validated { roots };

    let mut expected_forest = MerkleForest::new();
    for (index, commitment) in commitments.iter().enumerate() {
        expected_forest
            .insert_leaf(MerkleTreeUpdate {
                tree_number: 0,
                tree_position: index as u64,
                hash: U256::from_be_bytes(commitment.0),
            })
            .expect("insert expected leaf");
    }
    let expected = [
        commitments[0],
        commitments[1],
        commitments[2],
        commitments[3],
    ]
    .iter()
    .map(|commitment| {
        let position = cache.position(commitment).expect("position");
        let proof = expected_forest
            .prove(position.tree_number, position.tree_position)
            .expect("expected proof");
        poi_merkle_proof_from_cache(&proof)
    })
    .collect::<Vec<_>>();

    let actual = cache
        .poi_merkle_proofs(&[
            commitments[0],
            commitments[1],
            commitments[2],
            commitments[3],
        ])
        .unwrap();

    assert_eq!(actual, expected);
}

#[test]
fn missing_local_proof_data_fails_closed() {
    let mut cache = PoiCache::new(identity());
    let present = FixedBytes::from([0x22; 32]);
    let missing = FixedBytes::from([0x33; 32]);
    cache
        .apply_poi_leaves(0, &[U256::from_be_bytes(present.0)])
        .unwrap();
    let roots = cache.current_roots();
    cache.snapshot.progress.root_validation = PoiCacheRootValidation::Validated { roots };

    let err = cache
        .poi_merkle_proofs(&[missing])
        .expect_err("missing proof data should fail closed");

    assert!(matches!(
        err,
        PoiCacheError::MissingCommitment {
            blinded_commitment
        } if blinded_commitment == missing
    ));
}

#[tokio::test]
async fn sync_uses_paginated_bulk_methods_without_wallet_scoped_reads() {
    let commitment_0 = FixedBytes::from([0x22; 32]);
    let commitment_1 = FixedBytes::from([0x33; 32]);
    let mock = spawn_json_rpc(vec![
        json_rpc_result(&json!([event(0, commitment_0), event(1, commitment_1)])),
        json_rpc_result(&json!([])),
        json_rpc_result(&json!([
            hex::encode_prefixed(commitment_0),
            hex::encode_prefixed(commitment_1),
        ])),
        json_rpc_result(&json!([])),
    ]);
    let client = PoiRpcClient::new(mock.url.clone());
    let mut cache = PoiCache::new(identity());

    let outcome = cache.sync_with_page_sizes(&client, 2, 2).await.unwrap();

    assert_eq!(outcome.events, 2);
    assert_eq!(outcome.leaves, 2);
    assert_eq!(outcome.blocked_shields, 0);
    assert!(outcome.changed);
    assert_eq!(cache.status(&commitment_0), PoiStatus::Valid);
    assert_eq!(cache.status(&commitment_1), PoiStatus::Valid);

    let requests = [
        request_json(&mock),
        request_json(&mock),
        request_json(&mock),
        request_json(&mock),
    ];
    let methods = requests
        .iter()
        .map(|request| request["method"].as_str().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(
        methods,
        vec![
            "ppoi_poi_events",
            "ppoi_poi_events",
            "ppoi_poi_merkletree_leaves",
            "ppoi_blocked_shields",
        ]
    );
    assert!(!methods.contains(&"ppoi_pois_per_list"));
    assert!(!methods.contains(&"ppoi_merkle_proofs"));
    assert_eq!(requests[0]["params"]["startIndex"], 0);
    assert_eq!(requests[0]["params"]["endIndex"], 1);
    assert_eq!(requests[1]["params"]["startIndex"], 2);
    assert_eq!(requests[1]["params"]["endIndex"], 3);
    assert_eq!(requests[2]["params"]["startIndex"], 0);
    assert_eq!(requests[2]["params"]["endIndex"], 2);
    assert!(requests[3]["params"].get("bloomFilterSerialized").is_none());
    assert_eq!(requests[3]["params"]["startIndex"], 0);
    assert_eq!(requests[3]["params"]["endIndex"], 500);
}

#[tokio::test]
async fn scoped_event_sync_skips_blocked_shield_snapshot() {
    let commitment = FixedBytes::from([0x42; 32]);
    let mock = spawn_json_rpc(vec![
        json_rpc_result(&json!([event(0, commitment)])),
        json_rpc_result(&json!([hex::encode_prefixed(commitment)])),
    ]);
    let (cache, result) = PoiCache::new(identity())
        .sync_events_bounded_with_journal(&PoiRpcClient::new(mock.url.clone()), 2, 2, 4)
        .await
        .expect("event-only sync");

    assert_eq!(result.outcome.events, 1);
    assert!(result.blocked_shields.is_none());
    assert_eq!(cache.progress().next_event_index, 1);
    assert_eq!(
        [request_json(&mock), request_json(&mock)]
            .iter()
            .map(|request| request["method"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["ppoi_poi_events", "ppoi_poi_merkletree_leaves"]
    );
}

#[tokio::test]
async fn scoped_blocked_shield_sync_skips_events_and_leaves() {
    let mock = spawn_json_rpc(vec![json_rpc_result(&json!([]))]);
    let (cache, result) = PoiCache::new(identity())
        .sync_blocked_shields_with_journal(&PoiRpcClient::new(mock.url.clone()))
        .await
        .expect("blocked-shield-only sync");

    assert!(result.delta.is_empty());
    assert!(result.blocked_shields.is_some());
    assert!(cache.progress().blocked_shields_synced);
    let request = request_json(&mock);
    assert_eq!(request["method"], "ppoi_blocked_shields");
    assert!(mock.requests.try_recv().is_err());
}

#[tokio::test]
async fn sync_collects_complete_paginated_blocked_shield_snapshot() {
    let valid_commitment = FixedBytes::from([0x22; 32]);
    let blocked_shields = (1_u64..=501)
        .map(|index| blocked(FixedBytes::from(U256::from(index).to_be_bytes::<32>())))
        .collect::<Vec<_>>();
    let target = FixedBytes::from(U256::from(501).to_be_bytes::<32>());
    let mock = spawn_json_rpc(vec![
        json_rpc_result(&json!([event(0, valid_commitment)])),
        json_rpc_result(&json!([hex::encode_prefixed(valid_commitment)])),
        json_rpc_result(&json!(&blocked_shields[..500])),
        json_rpc_result(&json!(&blocked_shields[500..])),
    ]);
    let mut cache = PoiCache::new(identity());

    let outcome = cache
        .sync_with_page_sizes(&PoiRpcClient::new(mock.url.clone()), 2, 2)
        .await
        .expect("sync paginated blocked Shield snapshot");

    assert_eq!(outcome.blocked_shields, 501);
    assert_eq!(cache.status(&valid_commitment), PoiStatus::Valid);
    assert_eq!(cache.status(&target), PoiStatus::ShieldBlocked);

    let requests = [
        request_json(&mock),
        request_json(&mock),
        request_json(&mock),
        request_json(&mock),
    ];
    assert_eq!(requests[2]["method"], "ppoi_blocked_shields");
    assert_eq!(requests[2]["params"]["startIndex"], 0);
    assert_eq!(requests[2]["params"]["endIndex"], 500);
    assert_eq!(requests[3]["method"], "ppoi_blocked_shields");
    assert_eq!(requests[3]["params"]["startIndex"], 500);
    assert_eq!(requests[3]["params"]["endIndex"], 1000);
}

#[tokio::test]
async fn captured_journal_delta_replays_to_the_public_rpc_candidate() {
    let commitment_0 = FixedBytes::from([0x24; 32]);
    let commitment_1 = FixedBytes::from([0x35; 32]);
    let mock = spawn_json_rpc(vec![
        json_rpc_result(&json!([event(0, commitment_0), event(1, commitment_1)])),
        json_rpc_result(&json!([])),
        json_rpc_result(&json!([
            hex::encode_prefixed(commitment_0),
            hex::encode_prefixed(commitment_1),
        ])),
        json_rpc_result(&json!([])),
    ]);
    let base = PoiCache::new(identity());

    let (mut candidate, result) = base
        .clone()
        .sync_bounded_with_journal(&PoiRpcClient::new(mock.url), 2, 2, usize::MAX)
        .await
        .expect("sync candidate with journal capture");
    let encoded = result.delta.to_bytes().expect("encode journal delta");
    let decoded = PoiCacheJournalDelta::from_bytes(&encoded).expect("decode journal delta");
    assert_eq!(decoded, result.delta);
    assert_eq!(
        PoiCacheJournalDelta::from_bytes_bounded(&encoded, 2, 2)
            .expect("decode bounded journal delta"),
        result.delta
    );
    assert!(PoiCacheJournalDelta::from_bytes_bounded(&encoded, 1, 2).is_err());
    assert!(PoiCacheJournalDelta::from_bytes_bounded(&encoded, 2, 1).is_err());
    for suffix in [&[0xc0_u8][..], &[0xc1_u8][..]] {
        let mut tainted = encoded.clone();
        tainted.extend_from_slice(suffix);
        assert!(PoiCacheJournalDelta::from_bytes(&tainted).is_err());
        assert!(PoiCacheJournalDelta::from_bytes_bounded(&tainted, 2, 2).is_err());
    }
    assert_eq!(decoded.events.len(), 2);
    assert_eq!(decoded.leaves.len(), 2);
    assert_eq!(result.blocked_shields, Some(Vec::new()));

    let mut replayed = base;
    replayed
        .apply_journal_delta(&decoded)
        .expect("replay captured delta");
    replayed
        .replace_blocked_shields(
            result
                .blocked_shields
                .as_deref()
                .expect("captured blocked snapshot"),
        )
        .expect("replay blocked snapshot");
    replayed.accept_current_roots();
    candidate.accept_current_roots();

    assert_eq!(
        replayed.to_bytes().expect("serialize replayed cache"),
        candidate.to_bytes().expect("serialize direct candidate")
    );
    assert_eq!(replayed.status(&commitment_0), PoiStatus::Valid);
    assert_eq!(
        replayed
            .position(&commitment_1)
            .expect("replayed commitment position")
            .global_index,
        1
    );
}

#[test]
fn incremental_journal_replay_matches_each_committed_root_with_zero_leaf() {
    let identity = identity();
    let base = PoiCache::new(identity.clone());
    let mut direct = base.clone();
    let mut replay = base.into_journal_replay();

    for event_index in 0..4 {
        let commitment = if event_index == 1 {
            FixedBytes::ZERO
        } else {
            FixedBytes::from([0x60 + event_index as u8; 32])
        };
        let delta = PoiCacheJournalDelta {
            version: POI_CACHE_JOURNAL_DELTA_VERSION,
            identity: identity.clone(),
            event_start_cursor: event_index,
            event_end_cursor: event_index + 1,
            leaf_start_cursor: event_index,
            leaf_end_cursor: event_index + 1,
            events: vec![PoiCacheJournalEvent {
                event_index,
                blinded_commitment: commitment,
            }],
            leaves: vec![commitment],
        };
        direct
            .apply_journal_delta(&delta)
            .expect("apply direct journal delta");
        let expected_root = direct
            .current_roots()
            .get(&0)
            .copied()
            .expect("direct replay root");
        assert_eq!(
            replay
                .apply_delta(&delta)
                .expect("apply incremental journal delta"),
            expected_root
        );
    }

    direct.accept_current_roots();
    let replayed = replay.finish();
    assert_eq!(
        replayed.to_bytes().expect("serialize incremental replay"),
        direct.to_bytes().expect("serialize direct replay")
    );
}

#[test]
fn journal_delta_rejects_cursor_and_leaf_conflicts_before_mutation() {
    let commitment = FixedBytes::from([0x46; 32]);
    let base = PoiCache::new(identity());
    let delta = PoiCacheJournalDelta {
        version: POI_CACHE_JOURNAL_DELTA_VERSION,
        identity: identity(),
        event_start_cursor: 0,
        event_end_cursor: 1,
        leaf_start_cursor: 0,
        leaf_end_cursor: 1,
        events: vec![PoiCacheJournalEvent {
            event_index: 0,
            blinded_commitment: commitment,
        }],
        leaves: vec![FixedBytes::from([0x47; 32])],
    };
    let mut mismatched_leaf = base.clone();
    assert!(matches!(
        mismatched_leaf.apply_journal_delta(&delta),
        Err(PoiCacheError::EventLeafMismatch { index: 0 })
    ));
    assert_eq!(mismatched_leaf.progress().next_event_index, 0);
    assert_eq!(mismatched_leaf.progress().next_leaf_index, 0);

    let mut wrong_cursor = base;
    let mut delta = delta;
    delta.leaves[0] = commitment;
    delta.event_start_cursor = 1;
    assert!(matches!(
        wrong_cursor.apply_journal_delta(&delta),
        Err(PoiCacheError::JournalDeltaCursorMismatch { .. })
    ));
    assert_eq!(wrong_cursor.progress().next_event_index, 0);
    assert_eq!(wrong_cursor.progress().next_leaf_index, 0);
}

#[tokio::test]
async fn empty_public_range_sync_reports_no_corpus_change() {
    let mock = spawn_json_rpc(vec![
        json_rpc_result(&json!([])),
        json_rpc_result(&json!([])),
    ]);
    let client = PoiRpcClient::new(mock.url);
    let mut cache = PoiCache::new(identity());

    let outcome = cache.sync_with_page_sizes(&client, 2, 2).await.unwrap();

    assert!(!outcome.changed);
    assert_eq!(outcome.events, 0);
    assert_eq!(outcome.leaves, 0);
    assert_eq!(outcome.blocked_shields, 0);
}

#[tokio::test]
async fn public_range_sync_rejects_mismatched_cursors_before_requesting() {
    let commitment = FixedBytes::from([0x65; 32]);
    let mock = spawn_json_rpc(vec![]);
    let mut cache = PoiCache::new(identity());
    cache.apply_poi_events(&[event(0, commitment)]).unwrap();

    let error = cache
        .sync_with_page_sizes(&PoiRpcClient::new(mock.url), 2, 2)
        .await
        .expect_err("mismatched cursors must fail");

    assert!(matches!(
        error,
        PoiCacheError::SyncCursorMismatch {
            next_event_index: 1,
            next_leaf_index: 0
        }
    ));
    assert_eq!(cache.progress().next_leaf_index, 0);
}

#[tokio::test]
async fn public_range_sync_rejects_invalid_event_signature() {
    let commitment = FixedBytes::from([0x66; 32]);
    let mut invalid = event(0, commitment);
    invalid.signed_poi_event.event_type = PoiEventType::Transact;
    invalid.signed_poi_event.signature = "00".repeat(64);
    let mock = spawn_json_rpc(vec![json_rpc_result(&json!([invalid]))]);
    let mut cache = PoiCache::new(identity());

    let error = cache
        .sync_with_page_sizes(&PoiRpcClient::new(mock.url), 2, 2)
        .await
        .expect_err("invalid list signature must fail");

    assert!(matches!(error, PoiCacheError::Verify(_)));
}

#[tokio::test]
async fn public_range_sync_rejects_non_contiguous_event_index() {
    let mock = spawn_json_rpc(vec![json_rpc_result(&json!([event(
        1,
        FixedBytes::from([0x67; 32])
    )]))]);
    let mut cache = PoiCache::new(identity());

    let error = cache
        .sync_with_page_sizes(&PoiRpcClient::new(mock.url), 2, 2)
        .await
        .expect_err("non-contiguous range must fail");

    assert!(matches!(
        error,
        PoiCacheError::NonContiguousEvent {
            expected: 0,
            actual: 1
        }
    ));
}

#[tokio::test]
async fn public_range_sync_rejects_event_response_larger_than_requested_page() {
    let mock = spawn_json_rpc(vec![json_rpc_result(&json!([
        event(0, FixedBytes::from([0x67; 32])),
        event(1, FixedBytes::from([0x68; 32])),
    ]))]);
    let mut cache = PoiCache::new(identity());

    let error = cache
        .sync_with_page_sizes(&PoiRpcClient::new(mock.url), 1, 2)
        .await
        .expect_err("oversized event page must fail");

    assert!(matches!(
        error,
        PoiCacheError::EventPageTooLarge {
            start_index: 0,
            end_index: 0,
            requested: 1,
            actual: 2
        }
    ));
    assert_eq!(cache.progress().next_event_index, 0);
    assert_eq!(cache.progress().next_leaf_index, 0);
}

#[tokio::test]
async fn public_range_sync_rejects_event_leaf_mismatch() {
    let event_commitment = FixedBytes::from([0x68; 32]);
    let leaf_commitment = FixedBytes::from([0x69; 32]);
    let mock = spawn_json_rpc(vec![
        json_rpc_result(&json!([event(0, event_commitment)])),
        json_rpc_result(&json!([hex::encode_prefixed(leaf_commitment)])),
    ]);
    let mut cache = PoiCache::new(identity());

    let error = cache
        .sync_with_page_sizes(&PoiRpcClient::new(mock.url), 2, 2)
        .await
        .expect_err("event/leaf mismatch must fail");

    assert!(matches!(
        error,
        PoiCacheError::EventLeafMismatch { index: 0 }
    ));
    assert_eq!(cache.progress().next_event_index, 0);
    assert_eq!(cache.progress().next_leaf_index, 0);
    assert_eq!(cache.leaf_count(), 0);
}

#[tokio::test]
async fn public_range_sync_rejects_short_leaf_response_without_advancing_leaf_state() {
    let commitment = FixedBytes::from([0x6a; 32]);
    let mock = spawn_json_rpc(vec![
        json_rpc_result(&json!([event(0, commitment)])),
        json_rpc_result(&json!([])),
    ]);
    let mut cache = PoiCache::new(identity());

    let error = cache
        .sync_with_page_sizes(&PoiRpcClient::new(mock.url), 2, 2)
        .await
        .expect_err("short leaf page must fail");

    assert!(matches!(
        error,
        PoiCacheError::LeafPageSizeMismatch {
            start_index: 0,
            end_index: 1,
            expected: 1,
            actual: 0
        }
    ));
    assert_eq!(cache.progress().next_event_index, 0);
    assert_eq!(cache.progress().next_leaf_index, 0);
    assert_eq!(cache.leaf_count(), 0);
}

#[tokio::test]
async fn public_range_sync_rejects_extra_leaf_response_without_advancing_leaf_state() {
    let commitment = FixedBytes::from([0x6b; 32]);
    let extra = FixedBytes::from([0x6c; 32]);
    let mock = spawn_json_rpc(vec![
        json_rpc_result(&json!([event(0, commitment)])),
        json_rpc_result(&json!([
            hex::encode_prefixed(commitment),
            hex::encode_prefixed(extra),
        ])),
    ]);
    let mut cache = PoiCache::new(identity());

    let error = cache
        .sync_with_page_sizes(&PoiRpcClient::new(mock.url), 2, 2)
        .await
        .expect_err("extra leaf page must fail");

    assert!(matches!(
        error,
        PoiCacheError::LeafPageSizeMismatch {
            start_index: 0,
            end_index: 1,
            expected: 1,
            actual: 2
        }
    ));
    assert_eq!(cache.progress().next_event_index, 0);
    assert_eq!(cache.progress().next_leaf_index, 0);
    assert_eq!(cache.leaf_count(), 0);
}

#[tokio::test]
async fn public_range_sync_rejects_invalid_blocked_shield_signature() {
    let commitment = FixedBytes::from([0x70; 32]);
    let mut invalid_blocked = blocked(FixedBytes::from([0x71; 32]));
    invalid_blocked.signature = "00".repeat(64);
    let mock = spawn_json_rpc(vec![
        json_rpc_result(&json!([event(0, commitment)])),
        json_rpc_result(&json!([hex::encode_prefixed(commitment)])),
        json_rpc_result(&json!([invalid_blocked])),
    ]);
    let mut cache = PoiCache::new(identity());

    let error = cache
        .sync_with_page_sizes(&PoiRpcClient::new(mock.url), 2, 2)
        .await
        .expect_err("invalid blocked-shield signature must fail");

    assert!(matches!(error, PoiCacheError::Verify(_)));
}

#[tokio::test]
async fn bounded_public_range_sync_reports_large_backlog() {
    let commitment = FixedBytes::from([0x72; 32]);
    let mock = spawn_json_rpc(vec![
        json_rpc_result(&json!([event(0, commitment)])),
        json_rpc_result(&json!([hex::encode_prefixed(commitment)])),
        json_rpc_result(&json!([])),
    ]);
    let mut cache = PoiCache::new(identity());

    let outcome = cache
        .sync_bounded(&PoiRpcClient::new(mock.url), 1, 1, 1)
        .await
        .expect("bounded public range sync");

    assert!(outcome.event_page_budget_exhausted);
    assert_eq!(outcome.events, 1);
    assert_eq!(outcome.leaves, 1);
}

#[tokio::test]
async fn public_range_request_timeout_bounds_stalled_endpoint() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stalled POI RPC");
    let url = reqwest::Url::parse(&format!(
        "http://{}",
        listener.local_addr().expect("stalled RPC address")
    ))
    .expect("stalled RPC URL");
    std::thread::spawn(move || {
        let (_stream, _) = listener.accept().expect("accept stalled request");
        std::thread::sleep(Duration::from_secs(1));
    });
    let client = PoiRpcClient::new(url).with_request_timeout(Duration::from_millis(50));
    let mut cache = PoiCache::new(identity());

    let error = cache
        .sync(&client)
        .await
        .expect_err("stalled RPC times out");

    assert!(matches!(
        error,
        PoiCacheError::Rpc(PoiRpcError::Post { source, .. }) if source.is_timeout()
    ));
}
