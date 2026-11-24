//! Crash-safe file replacement shared by the artifact and prover caches.

use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::path::Path;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};

/// Keeps temp file names distinct when several provers and the eager cache build write in one
/// process.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A random token per process, so temp names never repeat across runs (unlike pids, which
/// sandboxes often reuse).
static PROCESS_TOKEN: LazyLock<u64> = LazyLock::new(rand::random);

/// Replaces `path` through a synced temp file in the same directory and a rename, so a reader
/// that only checks whether a file exists never sees a partial one.
pub(crate) fn write_atomic<E: From<std::io::Error>>(
    path: &Path,
    write: impl FnOnce(&mut File) -> Result<(), E>,
) -> Result<(), E> {
    remove_abandoned_temps(path);
    let (prefix, own_token) = temp_name_parts(path.file_name().unwrap_or_default());
    let nonce = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp_path = path.with_file_name(format!("{prefix}{own_token}{nonce}.tmp"));
    // `create_new` refuses any existing entry, symlinks included.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)?;
    let result = write(&mut file).and_then(|()| file.sync_all().map_err(E::from));
    drop(file);
    let result = result.and_then(|()| fs::rename(&temp_path, path).map_err(E::from));
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

/// Temp names for `file_name` are `{prefix}{token}-{nonce}.tmp`. Returns the prefix and this
/// process's `{token}-`.
fn temp_name_parts(file_name: &OsStr) -> (String, String) {
    let prefix = format!(".{}.", file_name.to_string_lossy());
    let own_token = format!("{:016x}-", *PROCESS_TOKEN);
    (prefix, own_token)
}

/// Only one process opens a profile at a time (the database lock), so temp files for `path`
/// from any other process are abandoned and removed. Removing a symlink never follows it.
fn remove_abandoned_temps(path: &Path) {
    let (Some(parent), Some(file_name)) = (path.parent(), path.file_name()) else {
        return;
    };
    let Ok(entries) = fs::read_dir(parent) else {
        return;
    };
    let (prefix, own_token) = temp_name_parts(file_name);
    for entry in entries.flatten() {
        let name = entry.file_name();
        let abandoned = name
            .to_string_lossy()
            .strip_prefix(prefix.as_str())
            .and_then(|rest| rest.strip_suffix(".tmp"))
            .is_some_and(|token_and_nonce| !token_and_nonce.starts_with(own_token.as_str()));
        if abandoned {
            let _ = fs::remove_file(entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn abandoned_temps_are_removed_without_following_symlinks() {
        use std::fs;
        use std::io::Write;

        use super::{PROCESS_TOKEN, write_atomic};

        let dir = std::env::temp_dir().join(format!("railgun-atomic-file-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create test dir");
        let victim = dir.join("victim");
        fs::write(&victim, b"keep").expect("write victim");
        let target = dir.join("out");
        let stale_file = dir.join(format!(".out.{:016x}-7.tmp", PROCESS_TOKEN.wrapping_add(1)));
        fs::write(&stale_file, b"partial").expect("write stale temp");
        let stale_link = dir.join(format!(".out.{:016x}-3.tmp", PROCESS_TOKEN.wrapping_add(2)));
        std::os::unix::fs::symlink(&victim, &stale_link).expect("plant stale temp symlink");
        let unrelated = dir.join(".other.0000000000000001-0.tmp");
        fs::write(&unrelated, b"other").expect("write unrelated temp");

        let result = write_atomic(&target, |file| file.write_all(b"new"));
        let victim_bytes = fs::read(&victim).ok();
        let target_bytes = fs::read(&target).ok();
        let stale_file_left = fs::symlink_metadata(&stale_file).is_ok();
        let stale_link_left = fs::symlink_metadata(&stale_link).is_ok();
        let unrelated_left = fs::symlink_metadata(&unrelated).is_ok();
        let out_temps_left: Vec<String> = fs::read_dir(&dir)
            .expect("list test dir")
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(".out."))
            .collect();
        let _ = fs::remove_dir_all(&dir);

        result.expect("atomic write");
        assert_eq!(victim_bytes.as_deref(), Some(&b"keep"[..]));
        assert_eq!(target_bytes.as_deref(), Some(&b"new"[..]));
        assert!(!stale_file_left, "stale temp file should be removed");
        assert!(!stale_link_left, "stale temp symlink should be removed");
        assert!(unrelated_left, "another target's temp should survive");
        assert!(out_temps_left.is_empty(), "temps left: {out_temps_left:?}");
    }
}
