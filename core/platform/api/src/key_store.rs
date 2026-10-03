//! DB-MAC signing key persistence — the neutral port (policy/mechanism seam).
//!
//! An HMAC-SHA256 over every `revisions` row is keyed by an opaque byte vector
//! that the storage layer treats as a black box. This module holds the neutral
//! [`KeyStore`] trait — "load / save / delete an opaque key" — plus
//! [`generate_signing_key`] (OS CSPRNG via `getrandom`, portable) and
//! [`InMemKeyStore`], the in-memory test double used on every OS.
//!
//! The real mechanism lives in the per-OS backend and `impl`s this trait:
//! Windows per-user DPAPI + a SYSTEM-only DACL
//! (`nrr_platform_windows::key_store::WindowsDpapiKeyStore`), Linux a root-only
//! file beside the state database (`nrr_platform_linux::key_store::FileKeyStore`).
//! macOS gets its own later.

use crate::error::PlatformError;

/// Length of a freshly generated signing key. Matches
/// `nrr_storage::revision_hmac::RECOMMENDED_KEY_BYTE_LEN` (one SHA-256 block).
/// Re-declared here so the platform crate does not depend on storage internals
/// just for a constant.
pub const SIGNING_KEY_BYTE_LEN: usize = 32;

/// Opaque persistent store for the DB-MAC signing key.
///
/// Implementations must be safe to share across the service's worker
/// threads (the bootstrap loads once, but a future key-rotation path
/// may call `save` from another context).
pub trait KeyStore: Send + Sync {
    /// Returns the stored key, or `None` when no key has been saved
    /// yet (fresh install / key file deleted). Decryption failures are
    /// surfaced as `Err`, distinct from "absent".
    fn load(&self) -> Result<Option<Vec<u8>>, PlatformError>;

    /// Persists `key`, encrypting it at rest. Overwrites any existing
    /// key. Creates the containing directory if needed.
    fn save(&self, key: &[u8]) -> Result<(), PlatformError>;

    /// Removes the stored key. Succeeds (no-op) when nothing is stored.
    fn delete(&self) -> Result<(), PlatformError>;

    /// Persists the re-sign-pending marker beside the key, under the same
    /// protection. Opaque bytes: the caller binds them to the key, so a marker
    /// planted or replayed from an earlier incident does not match.
    fn save_resign_marker(&self, marker: &[u8]) -> Result<(), PlatformError>;

    /// The stored marker, `None` when absent or unreadable as a marker.
    /// `Err` only for an I/O fault reaching it.
    fn load_resign_marker(&self) -> Result<Option<Vec<u8>>, PlatformError>;

    /// Removes the marker. Succeeds (no-op) when nothing is stored.
    fn delete_resign_marker(&self) -> Result<(), PlatformError>;
}

/// Generate a fresh signing key from the OS CSPRNG.
///
/// Centralised here so the service-runtime bootstrap never hand-rolls
/// randomness — it asks the platform layer for a key and hands it
/// straight to [`KeyStore::save`].
pub fn generate_signing_key() -> Result<Vec<u8>, PlatformError> {
    let mut buf = vec![0u8; SIGNING_KEY_BYTE_LEN];
    getrandom::fill(&mut buf).map_err(|e| PlatformError::Transient {
        operation: "generate_signing_key",
        detail: format!("OS CSPRNG failed: {e}"),
    })?;
    Ok(buf)
}

// ── InMemKeyStore ───────────────────────────────────────────────────────────

/// In-memory [`KeyStore`] for tests. Holds the
/// key in plaintext behind a mutex — never use in production.
#[derive(Default)]
pub struct InMemKeyStore {
    inner: std::sync::Mutex<Option<Vec<u8>>>,
    resign_marker: std::sync::Mutex<Option<Vec<u8>>>,
}

impl InMemKeyStore {
    /// Empty store — `load` returns `None` until the first `save`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-seeded store, simulating a service that has already
    /// generated and persisted a key on a previous run.
    pub fn with_key(key: Vec<u8>) -> Self {
        Self {
            inner: std::sync::Mutex::new(Some(key)),
            ..Self::default()
        }
    }
}

fn lock_slot(
    slot: &std::sync::Mutex<Option<Vec<u8>>>,
) -> Result<std::sync::MutexGuard<'_, Option<Vec<u8>>>, PlatformError> {
    slot.lock().map_err(|_| PlatformError::StateCorrupted {
        detail: "InMemKeyStore mutex poisoned".into(),
    })
}

impl KeyStore for InMemKeyStore {
    fn load(&self) -> Result<Option<Vec<u8>>, PlatformError> {
        Ok(lock_slot(&self.inner)?.clone())
    }

    fn save(&self, key: &[u8]) -> Result<(), PlatformError> {
        *lock_slot(&self.inner)? = Some(key.to_vec());
        Ok(())
    }

    fn delete(&self) -> Result<(), PlatformError> {
        *lock_slot(&self.inner)? = None;
        Ok(())
    }

    fn save_resign_marker(&self, marker: &[u8]) -> Result<(), PlatformError> {
        *lock_slot(&self.resign_marker)? = Some(marker.to_vec());
        Ok(())
    }

    fn load_resign_marker(&self) -> Result<Option<Vec<u8>>, PlatformError> {
        Ok(lock_slot(&self.resign_marker)?.clone())
    }

    fn delete_resign_marker(&self) -> Result<(), PlatformError> {
        *lock_slot(&self.resign_marker)? = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_signing_key_is_correct_length_and_nonzero() {
        let k = generate_signing_key().expect("CSPRNG");
        assert_eq!(k.len(), SIGNING_KEY_BYTE_LEN);
        // Vanishingly unlikely to be all zeroes — guards against a
        // stubbed RNG silently returning a constant.
        assert!(k.iter().any(|&b| b != 0));
    }

    #[test]
    fn generate_signing_key_differs_each_call() {
        let a = generate_signing_key().expect("CSPRNG");
        let b = generate_signing_key().expect("CSPRNG");
        assert_ne!(a, b, "two CSPRNG draws must differ");
    }

    #[test]
    fn in_mem_round_trips_save_load() {
        let store = InMemKeyStore::new();
        assert_eq!(store.load().expect("load"), None);
        let key = vec![0xABu8; SIGNING_KEY_BYTE_LEN];
        store.save(&key).expect("save");
        assert_eq!(store.load().expect("load"), Some(key));
    }

    #[test]
    fn in_mem_delete_clears() {
        let store = InMemKeyStore::with_key(vec![1, 2, 3]);
        assert!(store.load().expect("load").is_some());
        store.delete().expect("delete");
        assert_eq!(store.load().expect("load"), None);
        // Delete is idempotent.
        store.delete().expect("delete again");
    }

    #[test]
    fn in_mem_resign_marker_is_independent_of_the_key() {
        let store = InMemKeyStore::with_key(vec![7; SIGNING_KEY_BYTE_LEN]);
        assert_eq!(store.load_resign_marker().expect("load"), None);
        store.save_resign_marker(&[1, 2]).expect("save marker");
        assert_eq!(store.load_resign_marker().expect("load"), Some(vec![1, 2]));
        store.delete().expect("delete key");
        assert_eq!(store.load_resign_marker().expect("load"), Some(vec![1, 2]));
        store.delete_resign_marker().expect("delete marker");
        store.delete_resign_marker().expect("delete marker again");
        assert_eq!(store.load_resign_marker().expect("load"), None);
    }

    #[test]
    fn in_mem_save_overwrites() {
        let store = InMemKeyStore::new();
        store.save(&[1, 1, 1]).expect("save 1");
        store.save(&[2, 2, 2, 2]).expect("save 2");
        assert_eq!(store.load().expect("load"), Some(vec![2, 2, 2, 2]));
    }
}
