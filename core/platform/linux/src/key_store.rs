//! Linux mechanism for the DB-MAC signing-key [`KeyStore`].
//!
//! The neutral `KeyStore` PORT, `generate_signing_key` (portable OS CSPRNG) and
//! the off-platform `InMemKeyStore` test double live in `nrr-platform-api`,
//! shared with Windows. This module implements the port's MECHANISM for Linux.
//!
//! ## Protection model — filesystem permissions, not encryption
//!
//! Windows binds the key at rest with per-user DPAPI
//! (`WindowsDpapiKeyStore`): even reading the blob file yields nothing without
//! the `LocalSystem` DPAPI context. Linux has no built-in equivalent for a
//! headless system daemon, so this MVP protects the key the way system daemons
//! conventionally protect their secrets (cf. `/etc/ssl/private/`): a **`0600`
//! file inside a `0700` directory**, owned by the account the service runs as
//! (root or a dedicated service user). The key is therefore stored **in
//! plaintext at rest** — the access control is the directory/file mode, not
//! encryption. True at-rest encryption (libsecret / a TPM-sealed
//! key) is a later hardening, declared here so no reviewer assumes parity with
//! DPAPI.
//!
//! Threat model fit: the DB-MAC key defends tamper-detection of the `revisions`
//! table against a NON-root local actor. An attacker who already has root can
//! replace the database and the service outright, so binding the key more
//! tightly than "root-only" buys nothing here — the same reasoning that makes a
//! root-owned `0600` file the standard for daemon secrets.
//!
//! ## Testability
//!
//! [`FileKeyStore::at`] stores at an explicit path (a tempdir) without
//! hardening the parent directory; [`FileKeyStore::default_system`] uses the
//! canonical `/var/lib/netrulerouter/` location and additionally `chmod 0700`s
//! the directory. The file itself is always written `0600`. The module is
//! `#[cfg(unix)]` (it sets Unix mode bits), so its tests run on WSL2 / any Unix
//! host; the consumer selects it under `#[cfg(target_os = "linux")]`.

#![cfg(unix)]

use std::io::{ErrorKind, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use nrr_platform_api::error::PlatformError;

// Re-export the neutral coordinator so `nrr_platform_linux::key_store::*`
// mirrors `nrr_platform_windows::key_store::*`.
pub use nrr_platform_api::key_store::{
    generate_signing_key, InMemKeyStore, KeyStore, SIGNING_KEY_BYTE_LEN,
};

/// File name for the persisted key. Stable across versions.
const KEY_FILE_NAME: &str = "db-mac-key.bin";

/// Canonical production directory — root-owned service state, the Linux analog
/// of the Windows `systemprofile` tree.
const DEFAULT_STATE_DIR: &str = "/var/lib/netrulerouter";

/// Owner-only directory mode (`rwx------`).
const DIR_MODE: u32 = 0o700;

/// Owner-only file mode (`rw-------`).
const FILE_MODE: u32 = 0o600;

/// Production [`KeyStore`] backed by a `0600` file in a `0700` directory.
pub struct FileKeyStore {
    path: PathBuf,
    /// When `true`, [`Self::save`] `chmod 0700`s the parent directory. Only set
    /// by [`Self::default_system`]; [`Self::at`] leaves an arbitrary (possibly
    /// shared temp) parent untouched and relies on the `0600` file mode alone.
    harden_dir: bool,
}

impl FileKeyStore {
    /// Store the key at an explicit path **without** hardening the parent
    /// directory. Mainly for tests using a tempdir; production uses
    /// [`Self::default_system`].
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            harden_dir: false,
        }
    }

    /// The canonical production location `/var/lib/netrulerouter/db-mac-key.bin`,
    /// hardening the directory to `0700` on save.
    pub fn default_system() -> Self {
        Self {
            path: Path::new(DEFAULT_STATE_DIR).join(KEY_FILE_NAME),
            harden_dir: true,
        }
    }

    /// The resolved key-file path (exposed for diagnostics / tests).
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl KeyStore for FileKeyStore {
    fn load(&self) -> Result<Option<Vec<u8>>, PlatformError> {
        match std::fs::read(&self.path) {
            // A zero-length file is indistinguishable from a fresh install —
            // treat as absent so the bootstrap regenerates (mirrors Windows).
            Ok(bytes) if bytes.is_empty() => Ok(None),
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(classify("key_store::load::read", &self.path, e)),
        }
    }

    fn save(&self, key: &[u8]) -> Result<(), PlatformError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| classify("key_store::save::mkdir", parent, e))?;
            if self.harden_dir {
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(DIR_MODE))
                    .map_err(|e| classify("key_store::save::chmod_dir", parent, e))?;
            }
        }
        // Write to a sibling temp file (created `0600`) then rename, so a crash
        // mid-write never leaves a truncated blob that reads as "present but
        // corrupt", and the key is never briefly world-readable.
        let tmp = self.path.with_extension("bin.tmp");
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(FILE_MODE)
                .open(&tmp)
                .map_err(|e| classify("key_store::save::open_tmp", &tmp, e))?;
            f.write_all(key)
                .map_err(|e| classify("key_store::save::write_tmp", &tmp, e))?;
        }
        // `OpenOptions::mode` only applies when creating; enforce `0600` in case
        // a stale temp pre-existed with looser perms.
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(FILE_MODE))
            .map_err(|e| classify("key_store::save::chmod_tmp", &tmp, e))?;
        std::fs::rename(&tmp, &self.path)
            .map_err(|e| classify("key_store::save::rename", &self.path, e))?;
        Ok(())
    }

    fn delete(&self) -> Result<(), PlatformError> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(classify("key_store::delete", &self.path, e)),
        }
    }
}

/// Maps a filesystem error onto the neutral [`PlatformError`]: permission
/// failures become [`PlatformError::AccessDenied`]; everything else is a
/// (possibly retryable) [`PlatformError::Transient`].
fn classify(operation: &'static str, path: &Path, e: std::io::Error) -> PlatformError {
    if e.kind() == ErrorKind::PermissionDenied {
        PlatformError::AccessDenied { operation }
    } else {
        PlatformError::Transient {
            operation,
            detail: format!("{operation} {}: {e}", path.display()),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Unique temp dir with best-effort recursive cleanup on drop.
    struct TempDir(PathBuf);
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn temp_dir() -> TempDir {
        static N: AtomicU32 = AtomicU32::new(0);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "nrr-keystore-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        TempDir(p)
    }

    fn store_in(dir: &TempDir) -> FileKeyStore {
        FileKeyStore::at(dir.0.join("sub").join(KEY_FILE_NAME))
    }

    #[test]
    fn round_trips_save_load() {
        let dir = temp_dir();
        let store = store_in(&dir);
        assert_eq!(store.load().expect("load empty"), None);

        let key = generate_signing_key().expect("key");
        store.save(&key).expect("save");
        assert!(store.path().exists(), "key file must exist after save");

        let loaded = store.load().expect("load").expect("present");
        assert_eq!(loaded, key, "round-trip must recover the key");
    }

    #[test]
    fn saved_key_file_is_owner_only_0600() {
        let dir = temp_dir();
        let store = store_in(&dir);
        store.save(&[0xABu8; SIGNING_KEY_BYTE_LEN]).expect("save");
        let mode = std::fs::metadata(store.path())
            .expect("stat")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, FILE_MODE, "key file must be rw------- (0600)");
    }

    #[test]
    fn key_is_plaintext_at_rest_protected_by_perms_not_encryption() {
        // Honest documentation of the Linux MVP posture: unlike DPAPI, the file
        // content equals the key. Protection is the 0600 mode above, not
        // encryption. If a future slice adds at-rest encryption, this assertion
        // flips and the security note in the module doc must be updated.
        let dir = temp_dir();
        let store = store_in(&dir);
        let key = generate_signing_key().expect("key");
        store.save(&key).expect("save");
        assert_eq!(std::fs::read(store.path()).expect("read"), key);
    }

    #[test]
    fn zero_length_file_reads_as_absent() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir.0).expect("mkdir");
        let path = dir.0.join(KEY_FILE_NAME);
        std::fs::write(&path, b"").expect("touch empty");
        let store = FileKeyStore::at(&path);
        assert_eq!(store.load().expect("load"), None);
    }

    #[test]
    fn save_overwrites_existing_key() {
        let dir = temp_dir();
        let store = store_in(&dir);
        store.save(&[1u8; 8]).expect("save 1");
        store.save(&[2u8; 16]).expect("save 2");
        assert_eq!(store.load().expect("load").expect("present"), vec![2u8; 16]);
    }

    #[test]
    fn delete_is_idempotent() {
        let dir = temp_dir();
        let store = store_in(&dir);
        store.save(&[9u8; 4]).expect("save");
        store.delete().expect("delete");
        assert_eq!(store.load().expect("load"), None);
        store.delete().expect("delete again is ok");
    }

    #[test]
    fn default_system_targets_root_owned_state_dir() {
        let store = FileKeyStore::default_system();
        assert_eq!(
            store.path(),
            Path::new("/var/lib/netrulerouter/db-mac-key.bin")
        );
    }
}
