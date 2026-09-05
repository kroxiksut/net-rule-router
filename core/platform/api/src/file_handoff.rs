//! Handing a file the service produced to the user who asked for it.
//!
//! ## Why a port and not a `chmod`
//!
//! The service writes into its own data tree, which is closed to ordinary
//! users on purpose: it holds every principal's rules, their route bindings
//! and the audit trail. It must not write into a user-writable directory
//! instead — a `SYSTEM` / `root` process following a path an unprivileged
//! account controls is how symlink planting turns into privilege escalation.
//!
//! So the file stays where the service put it and the caller is granted read
//! on THAT FILE, nothing else. The two OSes spell it completely differently —
//! a DACL entry for a SID on Windows, ownership plus a traversable parent on
//! Unix — which is exactly what a port is for.
//!
//! ## What the caller may do with it
//!
//! Read and copy it out. The grant is per-file, so it cannot be widened into
//! "may list the service's data directory": another principal's export sitting
//! in the same directory stays unreadable, and that is the whole point — the
//! archive carries the diagnostics of the person who asked for it.

use std::path::Path;

use crate::error::PlatformError;

/// Grants one principal read access to one file the service produced.
pub trait FileHandoffPort: Send + Sync {
    /// Let `principal` (a stored principal string — a Windows SID, a
    /// `unix:uid:<n>`) read `path`.
    ///
    /// Implementations must not widen access to the containing directory
    /// beyond what is needed to open this file by full path, and must not
    /// grant write.
    fn grant_read(&self, path: &Path, principal: &str) -> Result<(), PlatformError>;
}

/// The port when there is nothing to do — a build with no OS backend, and the
/// preview/test wiring. Reports success: the caller's next step is copying the
/// file, which will fail on its own terms if the grant was actually needed.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopFileHandoff;

impl FileHandoffPort for NoopFileHandoff {
    fn grant_read(&self, _path: &Path, _principal: &str) -> Result<(), PlatformError> {
        Ok(())
    }
}

/// Records what it was asked to grant, for tests that assert the wiring.
#[derive(Debug, Default)]
pub struct MockFileHandoff {
    pub grants: std::sync::Mutex<Vec<(std::path::PathBuf, String)>>,
}

impl FileHandoffPort for MockFileHandoff {
    fn grant_read(&self, path: &Path, principal: &str) -> Result<(), PlatformError> {
        if let Ok(mut grants) = self.grants.lock() {
            grants.push((path.to_path_buf(), principal.to_string()));
        }
        Ok(())
    }
}
