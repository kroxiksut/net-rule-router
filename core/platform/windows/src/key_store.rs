//! DPAPI-protected storage for the
//! `nrr_service_state.db` row-MAC signing key.
//!
//! ## What this protects
//!
//! Every `revisions` row carries an HMAC-SHA256, keyed by an
//! opaque byte vector that the storage layer treats as a black box.
//! This module owns the lifecycle of that key on Windows: it is
//! generated once at first service start, encrypted at rest with
//! per-user DPAPI, and handed back to the service-runtime bootstrap
//! to thread into the `ActivationCoordinator`.
//!
//! ## Threat model — why per-user DPAPI, not LOCAL_MACHINE
//!
//! The service runs as `LocalSystem`. We call [`CryptProtectData`]
//! **without** `CRYPTPROTECT_LOCAL_MACHINE`, so the ciphertext is bound
//! to the `LocalSystem` account's master key, not the machine. An
//! ordinary local administrator process cannot decrypt the blob — it
//! would have to impersonate `LocalSystem` (e.g. `psexec -s`), which
//! raises the bar and leaves traces. With `CRYPTPROTECT_LOCAL_MACHINE`,
//! any admin process on the box could decrypt the key, forge a valid
//! `row_hmac`, and tamper undetectably — defeating the whole feature.
//!
//! The on-disk blob additionally gets a SYSTEM-only DACL as
//! defence-in-depth; failure to set it is logged but non-fatal because
//! the parent `systemprofile` tree is already admin/SYSTEM-only and the
//! DPAPI binding is the real protection.

// The neutral `KeyStore` PORT + `generate_signing_key` + the
// off-platform `InMemKeyStore` test double live in `nrr-platform-api`;
// re-export so `nrr_platform_windows::key_store::*` paths keep resolving
// unchanged. The Windows MECHANISM (`WindowsDpapiKeyStore`, DPAPI/Win32 FFI)
// stays here.
pub use nrr_platform_api::key_store::{
    generate_signing_key, InMemKeyStore, KeyStore, SIGNING_KEY_BYTE_LEN,
};

// ── WindowsDpapiKeyStore ─────────────────────────────────────────────────────

#[cfg(windows)]
pub use windows_impl::WindowsDpapiKeyStore;

#[cfg(windows)]
mod windows_impl {
    #![allow(unsafe_code)]

    use std::path::{Path, PathBuf};

    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows::Win32::Security::Authorization::SDDL_REVISION_1;
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB,
    };
    use windows::Win32::Security::{
        SetFileSecurityW, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    };

    use crate::error::PlatformError;

    use super::KeyStore;

    /// File name for the persisted key blob.
    const KEY_FILE_NAME: &str = "db-mac-key.bin";

    /// SDDL granting only `LocalSystem` (`SY`) full file access (`FA`)
    /// on a protected DACL (`P` — block inheritance from the parent).
    /// Administrators are intentionally absent: per the threat model an
    /// admin must impersonate `LocalSystem` to touch the key at all.
    const KEY_FILE_SDDL: &str = "D:P(A;;FA;;;SY)";

    const OP_PROTECT: &str = "CryptProtectData";
    const OP_UNPROTECT: &str = "CryptUnprotectData";

    /// Production [`KeyStore`] backed by per-user DPAPI + a SYSTEM-only
    /// DACL on the blob file.
    pub struct WindowsDpapiKeyStore {
        path: PathBuf,
        /// When `true`, [`Self::save`] locks the blob down to
        /// `LocalSystem:F`. Only set for the production
        /// [`Self::default_systemprofile`] constructor — a SYSTEM-only
        /// DACL would lock out any non-SYSTEM caller (e.g. a test
        /// running as the developer account), so [`Self::at`] leaves it
        /// off and relies on the parent-directory ACL.
        harden_acl: bool,
    }

    impl WindowsDpapiKeyStore {
        /// Store the key at an explicit path **without** applying the
        /// SYSTEM-only DACL. Mainly for tests that want a temp
        /// directory; production uses [`Self::default_systemprofile`].
        pub fn at(path: impl Into<PathBuf>) -> Self {
            Self {
                path: path.into(),
                harden_acl: false,
            }
        }

        /// The canonical production location:
        /// `%SystemRoot%\System32\config\systemprofile\AppData\Local\
        /// NetRuleRouter\db-mac-key.bin` — inside the `LocalSystem`
        /// profile, matching the account whose DPAPI master key
        /// encrypts the blob. Applies the SYSTEM-only DACL on save.
        pub fn default_systemprofile() -> Self {
            let system_root =
                std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
            let path = Path::new(&system_root)
                .join("System32")
                .join("config")
                .join("systemprofile")
                .join("AppData")
                .join("Local")
                .join("NetRuleRouter")
                .join(KEY_FILE_NAME);
            Self {
                path,
                harden_acl: true,
            }
        }

        /// The resolved blob path (exposed for diagnostics / tests).
        pub fn path(&self) -> &Path {
            &self.path
        }

        /// Best-effort: lock the blob file down to `LocalSystem:F`.
        /// Logged-and-swallowed on failure — the DPAPI binding is the
        /// real protection and the parent tree is already restrictive.
        /// No-op unless [`Self::harden_acl`] is set (production only).
        fn tighten_acl(&self) {
            if !self.harden_acl {
                return;
            }
            let mut sddl_w: Vec<u16> = KEY_FILE_SDDL.encode_utf16().chain([0]).collect();
            let mut psd = PSECURITY_DESCRIPTOR::default();

            // SAFETY: `sddl_w` is a valid NUL-terminated UTF-16 buffer
            // borrowed for the call; `psd` is an output slot Win32
            // fills with a LocalAlloc'd descriptor on success (which we
            // free below). On failure psd stays default and nothing is
            // allocated.
            let convert = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    PCWSTR(sddl_w.as_mut_ptr()),
                    SDDL_REVISION_1,
                    &mut psd,
                    None,
                )
            };
            if let Err(e) = convert {
                tracing::warn!(
                    target: "nrr::keystore",
                    error = %e,
                    "failed to build SYSTEM-only descriptor; relying on parent ACL",
                );
                return;
            }

            let mut path_w: Vec<u16> = self.path.as_os_str().encode_wide().chain([0]).collect();
            // SAFETY: `path_w` is a valid NUL-terminated wide path;
            // `psd` is the descriptor we just built and still own.
            let set = unsafe {
                SetFileSecurityW(PCWSTR(path_w.as_mut_ptr()), DACL_SECURITY_INFORMATION, psd)
            };
            if let Err(e) = set.ok() {
                tracing::warn!(
                    target: "nrr::keystore",
                    error = %e,
                    path = %self.path.display(),
                    "failed to apply SYSTEM-only DACL; relying on parent ACL",
                );
            }

            // SAFETY: `psd.0` is the LocalAlloc'd buffer returned by the
            // conversion API; LocalFree is its documented deallocator.
            let _ = unsafe { LocalFree(HLOCAL(psd.0)) };
        }
    }

    impl KeyStore for WindowsDpapiKeyStore {
        fn load(&self) -> Result<Option<Vec<u8>>, PlatformError> {
            let ciphertext = match std::fs::read(&self.path) {
                Ok(bytes) => bytes,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => {
                    return Err(PlatformError::Transient {
                        operation: "key_store::load::read",
                        detail: format!("read {}: {e}", self.path.display()),
                    })
                }
            };
            if ciphertext.is_empty() {
                // A zero-length file is indistinguishable from a fresh
                // install for our purposes — treat as absent so the
                // bootstrap regenerates rather than erroring out.
                return Ok(None);
            }
            match dpapi_unprotect(&ciphertext) {
                Ok(plaintext) => Ok(Some(plaintext)),
                Err(e) => {
                    // The blob exists but can't be decrypted under the
                    // current DPAPI context — e.g. it was written under a
                    // different account/profile (common after dev runs)
                    // or the LocalSystem master key path is unavailable
                    // (`0x80070003`). The DB-MAC key is rebuildable, so
                    // report it as ABSENT rather than propagating the
                    // error: the tamper bootstrap then regenerates it,
                    // re-saves under the current context (self-healing on
                    // the next boot), and raises a `KeyReset` alert if
                    // there is existing data — instead of hard-failing the
                    // whole integrity scan and running the coordinator
                    // unsigned.
                    tracing::warn!(
                        target: "nrr::keystore",
                        error = %e,
                        path = %self.path.display(),
                        "DB-MAC key blob is undecryptable under the current \
                         DPAPI context; treating as absent so it is regenerated",
                    );
                    Ok(None)
                }
            }
        }

        fn save(&self, key: &[u8]) -> Result<(), PlatformError> {
            if let Some(parent) = self.path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| PlatformError::Transient {
                    operation: "key_store::save::mkdir",
                    detail: format!("create_dir_all {}: {e}", parent.display()),
                })?;
            }
            let ciphertext = dpapi_protect(key)?;
            // Write to a sibling temp file then rename, so a crash mid
            // write never leaves a truncated blob that would read as
            // "key present but corrupt".
            let tmp = self.path.with_extension("bin.tmp");
            std::fs::write(&tmp, &ciphertext).map_err(|e| PlatformError::Transient {
                operation: "key_store::save::write_tmp",
                detail: format!("write {}: {e}", tmp.display()),
            })?;
            std::fs::rename(&tmp, &self.path).map_err(|e| PlatformError::Transient {
                operation: "key_store::save::rename",
                detail: format!("rename {} -> {}: {e}", tmp.display(), self.path.display()),
            })?;
            self.tighten_acl();
            Ok(())
        }

        fn delete(&self) -> Result<(), PlatformError> {
            match std::fs::remove_file(&self.path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(PlatformError::Transient {
                    operation: "key_store::delete",
                    detail: format!("remove {}: {e}", self.path.display()),
                }),
            }
        }
    }

    /// Encrypt `plain` with per-user DPAPI (no machine flag).
    fn dpapi_protect(plain: &[u8]) -> Result<Vec<u8>, PlatformError> {
        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: plain.len() as u32,
            pbData: plain.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB::default();
        // SAFETY: `in_blob` borrows `plain` for the duration of the
        // call only (no flag means the call is synchronous). `out_blob`
        // is an output slot Win32 fills with a LocalAlloc'd buffer we
        // copy out of and free immediately afterwards.
        unsafe {
            CryptProtectData(&in_blob, PCWSTR::null(), None, None, None, 0, &mut out_blob)
                .map_err(|e| win32_err(OP_PROTECT, &e))?;
        }
        Ok(copy_and_free_blob(&out_blob))
    }

    /// Decrypt a blob previously produced by [`dpapi_protect`].
    fn dpapi_unprotect(cipher: &[u8]) -> Result<Vec<u8>, PlatformError> {
        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: cipher.len() as u32,
            pbData: cipher.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB::default();
        // SAFETY: same contract as `dpapi_protect`. A wrong account /
        // corrupted blob surfaces as an `Err` from CryptUnprotectData,
        // never UB.
        unsafe {
            CryptUnprotectData(&in_blob, None, None, None, None, 0, &mut out_blob)
                .map_err(|e| win32_err(OP_UNPROTECT, &e))?;
        }
        Ok(copy_and_free_blob(&out_blob))
    }

    /// Copy a Win32 output `CRYPT_INTEGER_BLOB` into an owned `Vec` and
    /// release the LocalAlloc'd buffer.
    fn copy_and_free_blob(blob: &CRYPT_INTEGER_BLOB) -> Vec<u8> {
        if blob.pbData.is_null() || blob.cbData == 0 {
            return Vec::new();
        }
        // SAFETY: on success Win32 guarantees `pbData` points at
        // `cbData` valid bytes in a LocalAlloc'd region. We read them
        // once into an owned Vec, then hand the region to LocalFree.
        let owned =
            unsafe { std::slice::from_raw_parts(blob.pbData, blob.cbData as usize).to_vec() };
        let _ = unsafe { LocalFree(HLOCAL(blob.pbData as *mut core::ffi::c_void)) };
        owned
    }

    fn win32_err(operation: &'static str, e: &windows::core::Error) -> PlatformError {
        PlatformError::Win32 {
            operation,
            code: e.code().0 as u32,
            message: e.message(),
        }
    }

    use std::os::windows::ffi::OsStrExt;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn dpapi_store_round_trips_in_tempdir() {
        // DPAPI is available to any logged-in test account; this
        // exercises the real protect/unprotect + file I/O path without
        // needing LocalSystem (the ciphertext binds to whoever runs the
        // test, which is fine for a round-trip check).
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sub").join("db-mac-key.bin");
        let store = WindowsDpapiKeyStore::at(&path);
        assert_eq!(store.load().expect("load empty"), None);

        let key = generate_signing_key().expect("key");
        store.save(&key).expect("save");
        assert!(path.exists(), "blob file must exist after save");
        // Ciphertext on disk must not equal the plaintext key.
        let on_disk = std::fs::read(&path).expect("read blob");
        assert_ne!(on_disk, key, "key must be encrypted at rest");

        let loaded = store.load().expect("load").expect("present");
        assert_eq!(loaded, key, "DPAPI round-trip must recover the key");

        store.delete().expect("delete");
        assert_eq!(store.load().expect("load after delete"), None);
    }
}
