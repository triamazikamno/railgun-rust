use super::*;

#[test]
fn wallet_cache_keys_are_canonical_delimiter_free_and_preserve_opaque_ids() {
    let opaque = "11".repeat(16);
    let parsed: WalletCacheKey = opaque.parse().expect("parse alpha wallet cache key");
    assert_eq!(parsed.as_str(), opaque);
    assert!(!parsed.as_str().contains('|'));
    assert!("wallet|1|contract".parse::<WalletCacheKey>().is_err());
    assert!("AA".parse::<WalletCacheKey>().is_err());
    assert!(WalletCacheKey::from_opaque_bytes(&[]).is_err());

    let first = WalletCacheKey::new("wallet", 1, Address::from([0x22; 20]));
    let second = WalletCacheKey::new("wallet|1", 1, Address::from([0x22; 20]));
    assert_ne!(first, second);
    assert!(!first.as_str().contains('|'));
    let encoded = rmp_serde::to_vec_named(&first).expect("serialize wallet cache key");
    assert_eq!(
        rmp_serde::from_slice::<WalletCacheKey>(&encoded).expect("deserialize wallet cache key"),
        first
    );
}

#[test]
fn database_directory_lock_rejects_second_store_for_same_root() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open first db");

    assert!(matches!(
        DbStore::open(DbConfig {
            root_dir: root_dir.clone(),
        }),
        Err(DbError::DatabaseInUse { path })
            if path == root_dir.join("railgun").join("db.lock")
    ));

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn database_directory_lock_releases_after_store_drop() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open first db");
    drop(store);

    let reopened = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("reopen db after lock release");
    drop(reopened);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn database_opens_and_reopens_with_explicit_cache_size() {
    let root_dir = temp_db_root();
    let store = DbStore::open_with_cache_size_bytes(
        DbConfig {
            root_dir: root_dir.clone(),
        },
        64 * 1024,
    )
    .expect("open db with explicit cache size");
    drop(store);

    let reopened = DbStore::open_with_cache_size_bytes(
        DbConfig {
            root_dir: root_dir.clone(),
        },
        64 * 1024,
    )
    .expect("reopen db with explicit cache size");
    drop(reopened);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn database_directory_locks_are_scoped_by_root() {
    let first_root = temp_db_root();
    let second_root = temp_db_root();
    let first = DbStore::open(DbConfig {
        root_dir: first_root.clone(),
    })
    .expect("open first root");
    let second = DbStore::open(DbConfig {
        root_dir: second_root.clone(),
    })
    .expect("open second root");

    drop((first, second));
    fs::remove_dir_all(first_root).expect("remove first temp db dir");
    fs::remove_dir_all(second_root).expect("remove second temp db dir");
}

#[test]
fn canonical_blob_meta_identity_requires_direct_child_components() {
    let identity =
        CanonicalBlobMetaIdentity::from_leaf("poi_v4_artifact_chunks", "poi-v4-artifact-0123.bin")
            .expect("generate direct-child identity");
    assert_eq!(
        identity.relative_path(),
        "blobs/poi_v4_artifact_chunks/poi-v4-artifact-0123.bin"
    );

    for (kind, leaf) in [
        ("", "leaf.bin"),
        (".", "leaf.bin"),
        ("..", "leaf.bin"),
        ("nested/kind", "leaf.bin"),
        (r"nested\kind", "leaf.bin"),
        ("kind:stream", "leaf.bin"),
        ("kind\0suffix", "leaf.bin"),
        ("kind", ""),
        ("kind", "."),
        ("kind", ".."),
        ("kind", "nested/leaf.bin"),
        ("kind", r"nested\leaf.bin"),
        ("kind", "leaf:stream"),
        ("kind", "leaf\0suffix"),
    ] {
        assert!(matches!(
            CanonicalBlobMetaIdentity::from_leaf(kind, leaf),
            Err(DbError::InvalidBlobRelativePath { .. })
        ));
    }
}

#[test]
fn checked_blob_open_handles_regular_missing_and_directory_entries() {
    use std::io::Read;

    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let kind = "blob-file-operations";
    let kind_dir = store.ensure_blob_dir(kind).expect("create kind");
    let identity = CanonicalBlobMetaIdentity::from_leaf(kind, "leaf.bin").expect("identity");

    assert!(
        store
            .open_blob_meta_file(&identity)
            .expect("missing open")
            .is_none()
    );
    fs::write(kind_dir.join("leaf.bin"), b"regular bytes").expect("write regular leaf");
    let mut file = store
        .open_blob_meta_file(&identity)
        .expect("open regular leaf")
        .expect("regular leaf exists");
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).expect("read regular leaf");
    assert_eq!(bytes, b"regular bytes");
    drop(file);
    fs::remove_file(kind_dir.join("leaf.bin")).expect("remove regular leaf");
    fs::create_dir(kind_dir.join("leaf.bin")).expect("create directory leaf");
    assert!(matches!(
        store.open_blob_meta_file(&identity),
        Err(DbError::UnsafeBlobEntry { .. })
    ));
    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[cfg(unix)]
#[test]
fn checked_blob_open_rejects_static_symlink_parent_and_leaf() {
    use std::os::unix::fs::symlink;

    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let external_dir = root_dir.join("external");
    fs::create_dir_all(&external_dir).expect("create external dir");
    fs::write(external_dir.join("leaf.bin"), b"sentinel").expect("write sentinel");

    let parent_kind = "symlink-parent";
    symlink(&external_dir, store.blob_dir().join(parent_kind)).expect("create parent symlink");
    let parent_identity =
        CanonicalBlobMetaIdentity::from_leaf(parent_kind, "leaf.bin").expect("parent identity");
    assert!(matches!(
        store.open_blob_meta_file(&parent_identity),
        Err(DbError::UnsafeBlobEntry { .. })
    ));
    let leaf_kind = "symlink-leaf";
    let kind_dir = store.ensure_blob_dir(leaf_kind).expect("create real kind");
    let leaf_path = kind_dir.join("leaf.bin");
    symlink(external_dir.join("leaf.bin"), &leaf_path).expect("create leaf symlink");
    let leaf_identity =
        CanonicalBlobMetaIdentity::from_leaf(leaf_kind, "leaf.bin").expect("leaf identity");
    assert!(matches!(
        store.open_blob_meta_file(&leaf_identity),
        Err(DbError::UnsafeBlobEntry { .. })
    ));
    assert_eq!(
        fs::read(external_dir.join("leaf.bin")).expect("read sentinel"),
        b"sentinel"
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[cfg(windows)]
#[test]
fn checked_blob_open_rejects_static_reparse_parent_and_leaf() {
    use std::os::windows::fs::{symlink_dir, symlink_file};

    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let external_dir = root_dir.join("external");
    fs::create_dir_all(&external_dir).expect("create external dir");
    let external_file = external_dir.join("leaf.bin");
    fs::write(&external_file, b"sentinel").expect("write sentinel");

    let parent_kind = "reparse-parent";
    if let Err(error) = symlink_dir(&external_dir, store.blob_dir().join(parent_kind)) {
        if error.kind() == std::io::ErrorKind::PermissionDenied
            || error.raw_os_error() == Some(1314)
        {
            drop(store);
            fs::remove_dir_all(root_dir).expect("remove skipped test root");
            return;
        }
        panic!("create parent reparse fixture: {error}");
    }
    let parent_identity =
        CanonicalBlobMetaIdentity::from_leaf(parent_kind, "leaf.bin").expect("parent identity");
    assert!(matches!(
        store.open_blob_meta_file(&parent_identity),
        Err(DbError::UnsafeBlobEntry { .. })
    ));

    let leaf_kind = "reparse-leaf";
    let kind_dir = store.ensure_blob_dir(leaf_kind).expect("create real kind");
    let leaf_path = kind_dir.join("leaf.bin");
    symlink_file(&external_file, &leaf_path).expect("create leaf reparse fixture");
    let leaf_identity =
        CanonicalBlobMetaIdentity::from_leaf(leaf_kind, "leaf.bin").expect("leaf identity");
    assert!(matches!(
        store.open_blob_meta_file(&leaf_identity),
        Err(DbError::UnsafeBlobEntry { .. })
    ));
    assert_eq!(fs::read(external_file).expect("read sentinel"), b"sentinel");

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn failed_create_new_does_not_remove_preexisting_temp_entry() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let kind = "atomic-preexisting-temp";
    let kind_dir = store.ensure_blob_dir(kind).expect("create kind directory");
    let temp_name = ".preexisting-temp";
    let temp_path = kind_dir.join(temp_name);
    fs::write(&temp_path, b"preexisting").expect("write preexisting temp entry");

    assert!(
        store
            .replace_blob_file_atomic_with_test_temp_name(
                kind,
                "final.bin",
                b"new bytes",
                temp_name,
            )
            .is_err()
    );
    assert_eq!(
        fs::read(&temp_path).expect("read preexisting temp entry"),
        b"preexisting"
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn atomic_blob_replace_allows_missing_and_existing_regular_file() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let kind = "atomic-regular";
    let path = store
        .ensure_blob_dir(kind)
        .expect("create kind")
        .join("final.bin");

    store
        .replace_blob_file_atomic(kind, "final.bin", b"created")
        .expect("create missing file");
    assert_eq!(fs::read(&path).expect("read created file"), b"created");

    fs::write(&path, b"old").expect("write old file");

    store
        .replace_blob_file_atomic(kind, "final.bin", b"new")
        .expect("replace regular file");
    assert_eq!(fs::read(path).expect("read new file"), b"new");

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn atomic_blob_replace_cleans_temp_after_unsafe_destination_rejection() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let kind = "atomic-directory-final";
    let kind_dir = store.ensure_blob_dir(kind).expect("create kind");
    fs::create_dir(kind_dir.join("final.bin")).expect("create final directory");

    assert!(matches!(
        store.replace_blob_file_atomic(kind, "final.bin", b"new"),
        Err(DbError::UnsafeBlobEntry { .. })
    ));
    assert_no_atomic_temps(&kind_dir);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[cfg(unix)]
#[test]
fn atomic_blob_replace_rejects_final_symlink_without_touching_target() {
    use std::os::unix::fs::symlink;

    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let kind = "atomic-final-symlink";
    let kind_dir = store.ensure_blob_dir(kind).expect("create kind");
    let external_target = root_dir.join("external-atomic-target.bin");
    fs::write(&external_target, b"sentinel").expect("write external target");
    symlink(&external_target, kind_dir.join("final.bin")).expect("create final symlink");

    assert!(matches!(
        store.replace_blob_file_atomic(kind, "final.bin", b"new"),
        Err(DbError::UnsafeBlobEntry { .. })
    ));
    assert_eq!(
        fs::read(external_target).expect("read external target"),
        b"sentinel"
    );
    assert_no_atomic_temps(&kind_dir);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[cfg(windows)]
#[test]
fn atomic_blob_replace_rejects_final_reparse_without_touching_target() {
    use std::os::windows::fs::symlink_file;

    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let kind = "atomic-final-reparse";
    let kind_dir = store.ensure_blob_dir(kind).expect("create kind");
    let external_target = root_dir.join("external-atomic-target.bin");
    fs::write(&external_target, b"sentinel").expect("write external target");
    if let Err(error) = symlink_file(&external_target, kind_dir.join("final.bin")) {
        if error.kind() == std::io::ErrorKind::PermissionDenied
            || error.raw_os_error() == Some(1314)
        {
            drop(store);
            fs::remove_dir_all(root_dir).expect("remove skipped test root");
            return;
        }
        panic!("create final reparse fixture: {error}");
    }

    assert!(matches!(
        store.replace_blob_file_atomic(kind, "final.bin", b"new"),
        Err(DbError::UnsafeBlobEntry { .. })
    ));
    assert_eq!(
        fs::read(external_target).expect("read external target"),
        b"sentinel"
    );
    assert_no_atomic_temps(&kind_dir);

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[cfg(unix)]
#[test]
fn blob_kind_purge_unlinks_root_symlink_without_following_target() {
    use std::os::unix::fs::symlink;

    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let kind = "purge-root-symlink";
    let external = root_dir.join("external-purge-root");
    fs::create_dir_all(&external).expect("create external tree");
    fs::write(external.join("sentinel"), b"sentinel").expect("write sentinel");
    symlink(&external, store.blob_dir().join(kind)).expect("symlink kind root");

    store.purge_blob_kind(kind).expect("purge root symlink");
    assert_eq!(
        fs::read(external.join("sentinel")).expect("read sentinel"),
        b"sentinel"
    );
    assert!(store.blob_dir().join(kind).is_dir());
    assert!(
        !fs::symlink_metadata(store.blob_dir().join(kind))
            .expect("read replacement kind")
            .file_type()
            .is_symlink()
    );
    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[cfg(windows)]
#[test]
fn windows_blob_kind_purge_replaces_root_reparse_without_following_target() {
    use std::os::windows::fs::symlink_dir;

    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let kind = "purge-root-reparse";
    let external = root_dir.join("external-purge-root");
    fs::create_dir_all(&external).expect("create external tree");
    fs::write(external.join("sentinel"), b"sentinel").expect("write sentinel");
    if let Err(error) = symlink_dir(&external, store.blob_dir().join(kind)) {
        if error.kind() == std::io::ErrorKind::PermissionDenied
            || error.raw_os_error() == Some(1314)
        {
            drop(store);
            fs::remove_dir_all(root_dir).expect("remove skipped test root");
            return;
        }
        panic!("create root reparse fixture: {error}");
    }

    store.purge_blob_kind(kind).expect("purge root reparse");
    assert_eq!(
        fs::read(external.join("sentinel")).expect("read external sentinel"),
        b"sentinel"
    );
    let recreated = store.blob_dir().join(kind);
    assert!(recreated.is_dir());
    assert!(
        !fs::symlink_metadata(recreated)
            .expect("read recreated kind")
            .file_type()
            .is_symlink()
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

#[test]
fn blob_kind_purge_removes_nested_regular_tree_and_recreates_kind() {
    let root_dir = temp_db_root();
    let store = DbStore::open(DbConfig {
        root_dir: root_dir.clone(),
    })
    .expect("open db");
    let kind = "purge-nested-regular";
    let kind_dir = store.ensure_blob_dir(kind).expect("create kind");
    fs::create_dir_all(kind_dir.join("one/two/three")).expect("create nested tree");
    fs::write(kind_dir.join("root.bin"), b"root").expect("write root file");
    fs::write(kind_dir.join("one/two/three/leaf.bin"), b"leaf").expect("write leaf file");

    store.purge_blob_kind(kind).expect("purge regular tree");
    let recreated = store.blob_dir().join(kind);
    assert!(recreated.is_dir());
    assert!(
        fs::read_dir(recreated)
            .expect("read recreated kind")
            .next()
            .is_none()
    );

    drop(store);
    fs::remove_dir_all(root_dir).expect("remove temp db dir");
}

fn assert_no_atomic_temps(kind_dir: &std::path::Path) {
    assert!(
        fs::read_dir(kind_dir)
            .expect("read kind directory")
            .filter_map(Result::ok)
            .all(|entry| !entry
                .file_name()
                .to_string_lossy()
                .starts_with(".railgun-blob-"))
    );
}
