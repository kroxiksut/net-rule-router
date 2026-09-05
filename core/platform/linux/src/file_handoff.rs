//! Linux implementation of [`FileHandoffPort`]: ownership plus a traversable
//! parent.
//!
//! The daemon's state directory is `0700` root, so an ordinary user cannot open
//! a diagnostics archive built for them. Opening it by full path needs execute
//! (traverse) on every ancestor — Linux has no equivalent of Windows'
//! "bypass traverse checking" — so the archive directory is raised to `0711`:
//! traversable, still unlistable, which keeps one user from discovering another
//! user's exports even though both live there. The file itself is then chowned
//! to the caller and left `0600`, so only they can read it.
//!
//! Only the ARCHIVE directory is touched; `/var/lib/<product>` and its
//! databases stay `0700`.

#![cfg(target_os = "linux")]
// Localized: the single `chown` FFI call is the only `unsafe` here. There is no
// stable `std` API for changing a file's owner.
#![allow(unsafe_code)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use nrr_platform_api::file_handoff::FileHandoffPort;

use nrr_platform_api::error::PlatformError;

/// Directory mode that lets a user open a known file inside without being able
/// to list what else is there.
const TRAVERSABLE_DIR_MODE: u32 = 0o711;
/// File mode for a handed-off file: its new owner, and nobody else.
const OWNER_ONLY_FILE_MODE: u32 = 0o600;

/// Hands a service-produced file to the caller by making them its owner.
#[derive(Debug, Default, Clone, Copy)]
pub struct ChownFileHandoff;

impl FileHandoffPort for ChownFileHandoff {
    fn grant_read(&self, path: &Path, principal: &str) -> Result<(), PlatformError> {
        let uid = uid_from_principal(principal).ok_or(PlatformError::NotSupported {
            reason: "file handoff needs a unix:uid:<n> principal",
        })?;
        // Traverse on the parent, or the owner still cannot open the path.
        if let Some(parent) = path.parent() {
            std::fs::set_permissions(
                parent,
                std::fs::Permissions::from_mode(TRAVERSABLE_DIR_MODE),
            )
            .map_err(|e| PlatformError::Transient {
                operation: "file_handoff.parent_mode",
                detail: e.to_string(),
            })?;
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(OWNER_ONLY_FILE_MODE))
            .map_err(|e| PlatformError::Transient {
                operation: "file_handoff.file_mode",
                detail: e.to_string(),
            })?;
        chown_to(path, uid)
    }
}

/// The uid inside a stored principal (`unix:uid:<n>`), or `None` for anything
/// else — including a Windows SID that reached a Linux build.
fn uid_from_principal(principal: &str) -> Option<u32> {
    principal.trim().strip_prefix("unix:uid:")?.parse().ok()
}

/// `chown(path, uid, -1)` — the group is left alone.
fn chown_to(path: &Path, uid: u32) -> Result<(), PlatformError> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| PlatformError::NotSupported {
            reason: "file handoff path contains a NUL byte",
        })?;
    // SAFETY: `c_path` is a NUL-terminated string that outlives the call, and
    // `chown` only reads it. `-1` for gid is the documented "leave unchanged".
    let rc = unsafe { libc::chown(c_path.as_ptr(), uid, u32::MAX) };
    if rc == 0 {
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    Err(PlatformError::Errno {
        operation: "file_handoff.chown",
        code: err.raw_os_error().unwrap_or(0),
        message: err.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stored_principal_yields_its_uid() {
        assert_eq!(uid_from_principal("unix:uid:1000"), Some(1000));
        assert_eq!(uid_from_principal(" unix:uid:0 "), Some(0));
    }

    /// A principal this mechanism cannot act on must be refused, not guessed
    /// at: chowning to the wrong uid hands the archive to the wrong person.
    #[test]
    fn anything_that_is_not_a_unix_principal_is_refused() {
        assert_eq!(uid_from_principal("S-1-5-21-7"), None);
        assert_eq!(uid_from_principal(""), None);
        assert_eq!(uid_from_principal("unix:uid:"), None);
        assert_eq!(uid_from_principal("unix:uid:abc"), None);

        let err = ChownFileHandoff
            .grant_read(Path::new("/tmp/nrr-nonexistent.zip"), "S-1-5-21-7")
            .expect_err("must refuse");
        assert!(matches!(err, PlatformError::NotSupported { .. }));
    }

    /// The owner must end up able to open the file, and the directory must stay
    /// unlistable — the reason it is `0711` and not `0755`.
    #[test]
    fn a_handoff_leaves_the_file_owner_only_and_the_parent_traversable() {
        let base = std::env::temp_dir().join(format!(
            "nrr-file-handoff-{}-{}",
            std::process::id(),
            unsafe { libc::getpid() }
        ));
        let archives = base.join("archives");
        std::fs::create_dir_all(&archives).expect("mkdir");
        std::fs::set_permissions(&archives, std::fs::Permissions::from_mode(0o700))
            .expect("tighten");
        let file = archives.join("export.zip");
        std::fs::write(&file, b"zip").expect("write");

        // chown to our own uid always succeeds, root or not.
        let me = unsafe { libc::getuid() };
        ChownFileHandoff
            .grant_read(&file, &format!("unix:uid:{me}"))
            .expect("handoff");

        let dir_mode = std::fs::metadata(&archives)
            .expect("stat dir")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, TRAVERSABLE_DIR_MODE, "parent must be traversable");
        let file_mode = std::fs::metadata(&file)
            .expect("stat file")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, OWNER_ONLY_FILE_MODE, "file is the owner's alone");

        let _ = std::fs::remove_dir_all(&base);
    }
}
