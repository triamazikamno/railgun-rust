use std::fs;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use alloy::hex;
use alloy::primitives::FixedBytes;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;

use super::{
    ARTIFACT_CIDS_FILE, ARTIFACTS_HASHES_EMBED, ARTIFACTS_HASHES_FILE, ARTIFACTS_LIST_EMBED,
    ARTIFACTS_LIST_FILE, ArtifactError, ArtifactHashes, ArtifactPaths, ArtifactSource,
    materialize_artifacts, poi_variant_name,
};

#[test]
fn poi_variant_name_matches_expected_shape() {
    assert_eq!(poi_variant_name(3, 3), "POI_3x3");
    assert_eq!(poi_variant_name(13, 13), "POI_13x13");
}

#[test]
fn embedded_artifact_list_includes_deployed_high_input_variants() {
    let variants = ArtifactSource::default()
        .list_variants()
        .expect("embedded variants should parse");

    for variant in ["11x02", "11x03", "12x02"] {
        assert!(
            variants.iter().any(|candidate| candidate == variant),
            "missing deployed verifier variant {variant}"
        );
    }
}

#[test]
fn embedded_cid_table_includes_known_variant() {
    let cids = ArtifactSource::default()
        .load_cids()
        .expect("embedded CIDs should parse");
    let variant = cids.get("01x01").expect("known variant");
    assert_eq!(variant.zkey.br_bytes, 3_447_484);
    assert_eq!(variant.wasm.br_bytes, 895_378);
}

#[tokio::test]
async fn missing_cid_variant_fails_before_network() {
    let dir = std::env::temp_dir().join(format!(
        "railgun-missing-artifact-cid-{}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("create metadata dir");
    fs::write(dir.join(ARTIFACTS_LIST_FILE), ARTIFACTS_LIST_EMBED).expect("write list");
    fs::write(dir.join(ARTIFACTS_HASHES_FILE), ARTIFACTS_HASHES_EMBED).expect("write hashes");
    fs::write(dir.join(ARTIFACT_CIDS_FILE), b"{}").expect("write CIDs");
    let source = ArtifactSource::default()
        .with_gateways(Vec::new())
        .with_metadata_dir(dir.clone())
        .expect("metadata override");
    let error = source
        .download_variant("01x01", true)
        .await
        .expect_err("missing CID should fail");
    assert!(matches!(error, ArtifactError::MissingCid { ref variant } if variant == "01x01"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn metadata_directory_override_reads_cid_table() {
    let dir = std::env::temp_dir().join(format!("railgun-artifact-cids-{}", std::process::id()));
    fs::create_dir_all(&dir).expect("create metadata dir");
    fs::write(dir.join(ARTIFACTS_LIST_FILE), b"[]").expect("write list");
    fs::write(dir.join(ARTIFACTS_HASHES_FILE), b"{}").expect("write hashes");
    fs::write(
        dir.join(ARTIFACT_CIDS_FILE),
        br#"{"custom":{"zkey":{"cid":"Qmfoo","br_bytes":1},"wasm":{"cid":"Qmbar","br_bytes":2}}}"#,
    )
    .expect("write CIDs");
    let source = ArtifactSource::default()
        .with_metadata_dir(dir.clone())
        .expect("metadata override");
    assert_eq!(
        source
            .load_cids()
            .expect("override CIDs")
            .get("custom")
            .expect("custom variant")
            .zkey
            .cid,
        "Qmfoo"
    );
    let _ = fs::remove_dir_all(dir);
}

#[tokio::test]
async fn poi_bundle_upgrade_fetches_new_artifacts_and_never_falls_back() {
    let dir =
        std::env::temp_dir().join(format!("railgun-poi-bundle-upgrade-{}", std::process::id()));
    fs::create_dir_all(&dir).expect("create test directory");
    let cache = dir.join("cache");
    let legacy = cache.join("artifacts-v2.1/poi-nov-2-23");
    for variant in ["POI_3x3", "POI_13x13"] {
        fs::create_dir_all(legacy.join(variant)).expect("create old variant");
        fs::write(legacy.join(variant).join("zkey"), b"old zkey").expect("old zkey");
        fs::write(legacy.join(variant).join("wasm"), b"old wasm").expect("old wasm");
    }
    fs::create_dir_all(cache.join("01x01")).expect("create ordinary variant");
    fs::write(cache.join("01x01/zkey"), b"ordinary zkey").expect("ordinary zkey");
    fs::write(cache.join("01x01/wasm"), b"ordinary wasm").expect("ordinary wasm");

    let zkey = b"new zkey";
    let wasm = b"new wasm";
    let zkey_br = brotli_compress(zkey);
    let wasm_br = brotli_compress(wasm);
    let (zkey_cid, zkey_car) = single_block_car(&zkey_br);
    let (wasm_cid, wasm_car) = single_block_car(&wasm_br);
    let cid_entry = serde_json::json!({
        "zkey": {"cid": zkey_cid, "br_bytes": zkey_br.len()},
        "wasm": {"cid": wasm_cid, "br_bytes": wasm_br.len()}
    });
    let hash_entry = serde_json::json!({
        "zkey": hex::encode(Sha256::digest(zkey)),
        "wasm": hex::encode(Sha256::digest(wasm))
    });
    fs::write(dir.join(ARTIFACTS_LIST_FILE), ARTIFACTS_LIST_EMBED).expect("write list");
    fs::write(
        dir.join(ARTIFACT_CIDS_FILE),
        serde_json::to_vec(&serde_json::json!({
            "POI_3x3": cid_entry, "POI_13x13": cid_entry
        }))
        .expect("serialize CIDs"),
    )
    .expect("write CIDs");
    fs::write(
        dir.join(ARTIFACTS_HASHES_FILE),
        serde_json::to_vec(&serde_json::json!({
            "POI_3x3": hash_entry, "POI_13x13": hash_entry
        }))
        .expect("serialize hashes"),
    )
    .expect("write hashes");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind server");
    let gateway = Url::parse(&format!(
        "http://{}",
        listener.local_addr().expect("server address")
    ))
    .expect("gateway URL");
    let requests = Arc::new(AtomicUsize::new(0));
    let server_requests = requests.clone();
    let server = tokio::spawn(async move {
        for body in [Some(zkey_car), Some(wasm_car), None] {
            let (mut socket, _) = listener.accept().await.expect("accept request");
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(socket.read_u8().await.expect("read request"));
            }
            assert!(String::from_utf8_lossy(&request).contains("format=car"));
            server_requests.fetch_add(1, Ordering::SeqCst);
            let status = if body.is_some() {
                "200 OK"
            } else {
                "503 Service Unavailable"
            };
            let body = body.unwrap_or_default();
            let header = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/vnd.ipld.car\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            socket
                .write_all(header.as_bytes())
                .await
                .expect("write header");
            socket.write_all(&body).await.expect("write CAR");
        }
    });
    let source = ArtifactSource::new(vec![gateway], cache.clone())
        .with_client(
            reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(5))
                .build()
                .expect("client"),
        )
        .with_metadata_dir(dir.clone())
        .expect("metadata override");
    let paths = source
        .ensure_poi_artifacts(3, 3)
        .await
        .expect("fetch new bundle");
    assert_eq!(
        paths.zkey,
        cache.join("artifacts-v2.1/QmZ2MyM6TKxffkv6stuo2hFwmUfs3q4xgMYN164Sje8new/POI_3x3/zkey")
    );
    assert_eq!(fs::read(&paths.zkey).expect("new zkey"), zkey);
    assert_eq!(fs::read(&paths.wasm).expect("new wasm"), wasm);
    source
        .ensure_poi_artifacts(3, 3)
        .await
        .expect("reuse selected bundle");
    source
        .ensure_artifacts(1, 1)
        .await
        .expect("reuse ordinary variant");
    assert_eq!(requests.load(Ordering::SeqCst), 2);

    let error = source
        .ensure_poi_artifacts(13, 13)
        .await
        .expect_err("new bundle unavailable");
    assert!(matches!(error, ArtifactError::Trustless(_)));
    server.await.expect("server completed");
    assert_eq!(requests.load(Ordering::SeqCst), 3);
    let unavailable = source.artifact_paths("POI_13x13");
    assert!(!unavailable.zkey.exists());
    assert!(!unavailable.wasm.exists());
    for variant in ["POI_3x3", "POI_13x13"] {
        assert_eq!(
            fs::read(legacy.join(variant).join("zkey")).expect("old zkey retained"),
            b"old zkey"
        );
        assert_eq!(
            fs::read(legacy.join(variant).join("wasm")).expect("old wasm retained"),
            b"old wasm"
        );
    }
    assert_eq!(
        fs::read(cache.join("01x01/zkey")).expect("ordinary zkey retained"),
        b"ordinary zkey"
    );
    assert_eq!(
        fs::read(cache.join("01x01/wasm")).expect("ordinary wasm retained"),
        b"ordinary wasm"
    );
    fs::remove_dir_all(dir).expect("remove test directory");
}

fn single_block_car(bytes: &[u8]) -> (String, Vec<u8>) {
    // CIDv1, raw codec, SHA-256. The small fixture uses single-byte CAR lengths.
    let mut cid = vec![0x01, 0x55, 0x12, 0x20];
    cid.extend_from_slice(&Sha256::digest(bytes));
    let mut header = b"\xa2\x65roots\x81\xd8\x2a\x58\x25\0".to_vec();
    header.extend_from_slice(&cid);
    header.extend_from_slice(b"\x67version\x01");
    let block_len = cid.len() + bytes.len();
    assert!(block_len < 128);
    let mut car = vec![u8::try_from(header.len()).expect("small CAR header")];
    car.extend_from_slice(&header);
    car.push(u8::try_from(block_len).expect("small CAR block"));
    car.extend_from_slice(&cid);
    car.extend_from_slice(bytes);
    (format!("f{}", hex::encode(cid)), car)
}

#[tokio::test]
async fn unsupported_poi_variant_is_rejected_before_download() {
    let source = ArtifactSource::default();

    let error = source
        .ensure_poi_artifacts(4, 4)
        .await
        .expect_err("unsupported poi variant should fail");

    assert!(error.to_string().contains("POI_4x4"));
}

fn brotli_compress(data: &[u8]) -> Vec<u8> {
    let mut compressed = Vec::new();
    {
        let mut writer = brotli::CompressorWriter::new(&mut compressed, 4096, 5, 22);
        writer.write_all(data).expect("compress test data");
    }
    compressed
}

#[test]
fn materialization_validates_both_artifacts_before_writes() {
    let dir = std::env::temp_dir().join(format!(
        "railgun-artifact-materialization-{}",
        std::process::id()
    ));
    let paths = ArtifactPaths {
        zkey: dir.join("nested/zkey"),
        wasm: dir.join("nested/wasm"),
    };
    let zkey = b"valid zkey";
    let wasm = b"valid wasm";
    let zkey_hash: [u8; 32] = Sha256::digest(zkey).into();
    let wasm_hash: [u8; 32] = Sha256::digest(wasm).into();
    let expected = ArtifactHashes {
        zkey: FixedBytes::from(zkey_hash),
        wasm: FixedBytes::from(wasm_hash),
        dat: None,
    };
    materialize_artifacts(
        &brotli_compress(zkey),
        &brotli_compress(wasm),
        &expected,
        paths.clone(),
        false,
    )
    .expect("valid artifacts should materialize");
    assert_eq!(fs::read(&paths.zkey).expect("zkey output"), zkey);
    assert_eq!(fs::read(&paths.wasm).expect("wasm output"), wasm);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn materialization_hash_mismatch_leaves_both_outputs_absent() {
    let dir = std::env::temp_dir().join(format!(
        "railgun-artifact-materialization-mismatch-{}",
        std::process::id()
    ));
    let paths = ArtifactPaths {
        zkey: dir.join("nested/zkey"),
        wasm: dir.join("nested/wasm"),
    };
    let zkey_hash: [u8; 32] = Sha256::digest(b"valid zkey").into();
    let wasm_hash: [u8; 32] = Sha256::digest(b"wrong wasm").into();
    let expected = ArtifactHashes {
        zkey: FixedBytes::from(zkey_hash),
        wasm: FixedBytes::from(wasm_hash),
        dat: None,
    };
    let error = materialize_artifacts(
        &brotli_compress(b"valid zkey"),
        &brotli_compress(b"valid wasm"),
        &expected,
        paths.clone(),
        false,
    )
    .expect_err("wasm mismatch should fail");
    assert!(matches!(error, ArtifactError::HashMismatch { ref label, .. } if label == "wasm"));
    assert!(!paths.zkey.exists());
    assert!(!paths.wasm.exists());
    assert!(!dir.exists());
}
