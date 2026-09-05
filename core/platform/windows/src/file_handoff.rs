//! Windows implementation of [`FileHandoffPort`]: one DACL entry on one file.
//!
//! The service's data directory grants `SYSTEM` and `Administrators` and
//! nothing else, so an ordinary user cannot open a diagnostics archive the
//! service just built for them. Granting the directory to `Users` would hand
//! every account every other account's export — the opposite of what the
//! per-principal read scoping is for. So the grant goes on the FILE.
//!
//! Opening `…\archives\x.zip` by full path needs traverse on the ancestors,
//! which Windows gives everyone through the `Bypass traverse checking`
//! privilege (`SeChangeNotifyPrivilege`, held by `Everyone` by default). The
//! directory therefore stays unlistable while the one file is readable by the
//! one principal.
//!
//! `icacls.exe` rather than the DACL API for the same reason the installer uses
//! it: the command line is human-auditable in a log, and this runs once per
//! export, not on any hot path.

#![cfg(target_os = "windows")]

use std::path::Path;
use std::process::Command;

use nrr_platform_api::file_handoff::FileHandoffPort;

use crate::error::PlatformError;

/// Grants a caller read access to a single service-produced file.
#[derive(Debug, Default, Clone, Copy)]
pub struct IcaclsFileHandoff;

impl FileHandoffPort for IcaclsFileHandoff {
    fn grant_read(&self, path: &Path, principal: &str) -> Result<(), PlatformError> {
        let sid = principal.trim();
        // The stored principal on Windows IS the SID string. Anything else —
        // an empty caller, a `unix:uid:` from a test fixture — is not something
        // this mechanism can grant to, and inventing an interpretation of it is
        // how a grant ends up on the wrong account.
        if !is_windows_sid(sid) {
            return Err(PlatformError::NotSupported {
                reason: "file handoff needs a Windows SID as the principal",
            });
        }
        let path_str = path.to_str().ok_or(PlatformError::NotSupported {
            reason: "file handoff needs a UTF-8 path",
        })?;
        // `*<SID>` is icacls' explicit "this is a SID, not a name" form, so a
        // machine with an unresolvable or renamed account still gets the right
        // entry. `(R)` is read: no write, no delete, no ACL change.
        let grant = format!("*{sid}:(R)");
        run_icacls(&[path_str, "/grant", &grant])
    }
}

/// Whether `value` looks like a Windows SID string (`S-1-…`).
fn is_windows_sid(value: &str) -> bool {
    let mut parts = value.split('-');
    if parts.next() != Some("S") {
        return false;
    }
    let mut count = 0;
    for part in parts {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        count += 1;
    }
    count >= 2
}

fn run_icacls(args: &[&str]) -> Result<(), PlatformError> {
    // `%SystemRoot%` rather than the bare name: this runs as LocalSystem, and
    // the process search path includes the current directory.
    let icacls = match std::env::var_os("SystemRoot") {
        Some(root) => std::path::PathBuf::from(root)
            .join("System32")
            .join("icacls.exe"),
        None => std::path::PathBuf::from("icacls.exe"),
    };
    let output =
        Command::new(icacls)
            .args(args)
            .output()
            .map_err(|e| PlatformError::Transient {
                operation: "file_handoff.icacls.spawn",
                detail: e.to_string(),
            })?;
    if output.status.success() {
        return Ok(());
    }
    Err(PlatformError::Transient {
        operation: "file_handoff.icacls",
        detail: format!(
            "icacls failed (exit={:?}): {} {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim(),
            String::from_utf8_lossy(&output.stdout).trim()
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The grant is addressed by SID. A caller string that is not one must be
    /// refused rather than passed to `icacls`, which would either fail
    /// obscurely or — worse — resolve it as an account name.
    #[test]
    fn only_a_sid_is_accepted_as_the_principal() {
        assert!(is_windows_sid(
            "S-1-5-21-1004336348-1177238915-682003330-512"
        ));
        assert!(is_windows_sid("S-1-5-18"));
        assert!(!is_windows_sid("unix:uid:1000"));
        assert!(!is_windows_sid(""));
        assert!(!is_windows_sid("S"));
        assert!(!is_windows_sid("S-1"));
        assert!(!is_windows_sid("Administrators"));
        assert!(!is_windows_sid("S-1-5-x"));
    }

    /// A non-SID principal is refused before any process is spawned: the file
    /// stays unreadable, which is the safe direction.
    #[test]
    fn a_non_sid_principal_is_refused_without_running_anything() {
        let port = IcaclsFileHandoff;
        let err = port
            .grant_read(Path::new("C:/nonexistent/x.zip"), "unix:uid:1000")
            .expect_err("must refuse");
        assert!(matches!(err, PlatformError::NotSupported { .. }));
    }
}
