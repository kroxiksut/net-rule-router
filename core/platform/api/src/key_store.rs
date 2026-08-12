//! DB-MAC signing key persistence — the neutral port (policy/mechanism seam).
//!
//! An HMAC-SHA256 over every `revisions` row is keyed by an opaque byte vector
//! that the storage layer treats as a black box. This module holds the neutral
//! [`KeyStore`] trait — "load / save / delete an opaque key" — plus
//! [`generate_signing_key`] (OS CSPRNG via `getrandom`, portable) and
//! [`InMemKeyStore`], the in-memory test double used on every OS.
//!
//! The real mechanism (Windows per-user DPAPI + a SYSTEM-only DACL) lives in the
//! per-OS backend (`nrr_platform_windows::key_store::WindowsDpapiKeyStore`) and
//! `impl`s this trait. Linux/macOS get their own impls later (e.g. `libsecret` /
//! Keychain).

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

/// In-memory [`KeyStore`] for tests and non-Windows builds. Holds the
/// key in plaintext behind a mutex — never use in production.
#[derive(Default)]
pub struct InMemKeyStore {
    inner: std::sync::Mutex<Option<Vec<u8>>>,
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
        }
    }
}

impl KeyStore for InMemKeyStore {
    fn load(&self) -> Result<Option<Vec<u8>>, PlatformError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| PlatformError::StateCorrupted {
                detail: "InMemKeyStore mutex poisoned".into(),
            })?
            .clone())
    }

    fn save(&self, key: &[u8]) -> Result<(), PlatformError> {
        *self
            .inner
            .lock()
            .map_err(|_| PlatformError::StateCorrupted {
                detail: "InMemKeyStore mutex poisoned".into(),
            })? = Some(key.to_vec());
        Ok(())
    }

    fn delete(&self) -> Result<(), PlatformError> {
        *self
            .inner
            .lock()
            .map_err(|_| PlatformError::StateCorrupted {
                detail: "InMemKeyStore mutex poisoned".into(),
            })? = None;
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
    fn in_mem_save_overwrites() {
        let store = InMemKeyStore::new();
        store.save(&[1, 1, 1]).expect("save 1");
        store.save(&[2, 2, 2, 2]).expect("save 2");
        assert_eq!(store.load().expect("load"), Some(vec![2, 2, 2, 2]));
    }
}
