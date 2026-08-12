//! Unix mechanism behind
//! [`nrr_platform_api::process_error_stream::ProcessErrorStreamPort`].
//!
//! The Unix analog of the Windows standard-handle table is the file-descriptor
//! table: descriptor 2 is the error stream, a child inherits its parent's, and
//! `dup2` replaces it in place. Because the replacement happens at the
//! descriptor level, everything written afterwards follows it — `eprintln!` from
//! any crate, a library's warning, the panic message — with no logging facade in
//! the middle.
//!
//! The mechanism is POSIX, not Linux-specific, so a future macOS backend reuses
//! this module rather than copying it.

#![allow(unsafe_code)]

use std::path::Path;

use nrr_platform_api::error::PlatformError;
use nrr_platform_api::process_error_stream::ProcessErrorStreamPort;

/// Production implementation over the process's file-descriptor table.
pub struct UnixProcessErrorStream;

impl ProcessErrorStreamPort for UnixProcessErrorStream {
    #[cfg(target_os = "linux")]
    fn error_stream_is_interactive(&self) -> bool {
        // SAFETY: `isatty` reads the descriptor table and takes no pointer.
        unsafe { libc::isatty(libc::STDERR_FILENO) == 1 }
    }

    #[cfg(not(target_os = "linux"))]
    fn error_stream_is_interactive(&self) -> bool {
        false
    }

    #[cfg(target_os = "linux")]
    fn redirect_to_file(&self, path: &Path) -> Result<(), PlatformError> {
        use std::fs::OpenOptions;
        use std::os::fd::AsRawFd;

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| PlatformError::Transient {
                operation: "open error-stream file",
                detail: format!("{}: {e}", path.display()),
            })?;

        // SAFETY: `file` is open for the duration of the call and `libc::STDERR_FILENO`
        // is a descriptor number, not a pointer. `dup2` closes the old descriptor 2
        // and makes 2 refer to the same open file description as `file`.
        let rc = unsafe { libc::dup2(file.as_raw_fd(), libc::STDERR_FILENO) };
        if rc < 0 {
            let errno = std::io::Error::last_os_error();
            return Err(PlatformError::Transient {
                operation: "dup2 onto the error stream",
                detail: format!("{errno}"),
            });
        }
        // Descriptor 2 now has its own reference to the open file, so dropping
        // `file` here closes only the extra descriptor, not the destination.
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn redirect_to_file(&self, _path: &Path) -> Result<(), PlatformError> {
        Err(PlatformError::NotSupported {
            reason: "process error-stream redirection has no implementation on this host",
        })
    }
}
