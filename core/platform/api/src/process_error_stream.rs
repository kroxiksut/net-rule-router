//! Neutral "where does this process's error output go" port.
//!
//! A process writes unstructured diagnostics from everywhere: `eprintln!` in
//! its own modules, a library's warning line, a panic message. All of it leaves
//! through one stream, and by default that stream is whatever the PARENT
//! process handed down. For a program started by another program that default
//! is actively misleading: the child's diagnostics land in the parent's log
//! file, the child's own log stays empty, and whoever reads the empty file
//! concludes the child produced nothing.
//!
//! The decision — which file, and when — is the caller's and is the same on
//! every OS. Only the mechanism differs: Windows keeps a per-process table of
//! standard handles, Unix keeps a file-descriptor table. Hence this seam.
//!
//! Redirection is process-wide and permanent: it applies to everything written
//! after the call by any crate in the process, and there is deliberately no
//! "restore" — a diagnostics stream that moves back and forth is worse than one
//! that never moved.

use std::path::Path;

use crate::error::PlatformError;

/// Point this process's error stream somewhere the caller chooses.
pub trait ProcessErrorStreamPort {
    /// Is the error stream a terminal a human is currently reading? Callers use
    /// it to leave a developer's console alone and only claim streams that
    /// belong to somebody else's plumbing.
    fn error_stream_is_interactive(&self) -> bool;

    /// Send everything this process writes to its error stream from now on to
    /// `path`. The file is created when missing and appended to otherwise, so
    /// several processes can share one file without truncating each other.
    ///
    /// Returns [`PlatformError::NotSupported`] on hosts with no mechanism for
    /// it; callers treat that as "diagnostics keep going wherever they went
    /// before", never as a reason to fail startup.
    fn redirect_to_file(&self, path: &Path) -> Result<(), PlatformError>;
}
