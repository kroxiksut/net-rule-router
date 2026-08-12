//! Keep each launcher's diagnostics in its OWN log file.
//!
//! ## The problem this exists for
//!
//! The tray launcher is started by the main window's Qt host, and a process
//! started by another process inherits its parent's error stream. That stream is
//! the pipe the MAIN launcher reads and writes into `launcher-main.log`, so
//! every line the tray's own libraries printed — the IPC client's push
//! accounting, most of all — was filed under the main window, while
//! `launcher-tray.log` held only the lines this crate writes to the file
//! directly. Twice in a row a tray problem was diagnosed against that
//! deceptively empty file.
//!
//! The launcher's own [`crate::launcher::diag_log`] cannot fix it: it can only
//! redirect the lines IT writes, and the lines that mattered came from other
//! crates.
//!
//! ## What is done instead
//!
//! The whole process's error stream is pointed at this surface's log file, once,
//! at startup. From then on every `eprintln!` in the process — this crate's, the
//! IPC client's, the elevation broker's — plus any panic message lands in the
//! log of the surface that produced it, and the parent's log stops collecting
//! another process's output.
//!
//! The mechanism is per-OS and lives behind
//! `nrr_platform_api::process_error_stream::ProcessErrorStreamPort`; this module
//! only chooses the implementation for the host and remembers whether it took.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use nrr_platform_api::process_error_stream::ProcessErrorStreamPort;

/// Set once the process's error stream is known to reach the surface log file.
/// Read by [`crate::launcher::diag_log`], which stops echoing to that stream: it
/// already writes the same line to the same file, with a timestamp.
static CAPTURED: AtomicBool = AtomicBool::new(false);

/// Point this process's error stream at `path`. Best-effort: a host with no
/// implementation, or a file that cannot be opened, leaves the stream where it
/// was and the launcher starts normally.
///
/// A console is left alone. There the stream belongs to the developer who
/// started the process and is watching it; everywhere else it belongs to
/// whatever plumbing happened to be inherited, which is precisely the case this
/// exists to end.
pub fn capture_process_error_stream(path: &Path) {
    let Some(port) = error_stream_port() else {
        return;
    };
    if port.error_stream_is_interactive() {
        return;
    }
    match port.redirect_to_file(path) {
        Ok(()) => {
            CAPTURED.store(true, Ordering::Release);
        }
        Err(error) => {
            eprintln!(
                "nrr-launcher: could not point diagnostics at {}: {error}",
                path.display()
            );
        }
    }
}

/// Whether this process's error stream reaches the surface log file.
pub fn error_stream_is_captured() -> bool {
    CAPTURED.load(Ordering::Acquire)
}

fn error_stream_port() -> Option<Box<dyn ProcessErrorStreamPort>> {
    #[cfg(windows)]
    {
        Some(Box::new(
            nrr_platform_windows::process_error_stream::WindowsProcessErrorStream,
        ))
    }
    #[cfg(unix)]
    {
        Some(Box::new(
            nrr_platform_linux::process_error_stream::UnixProcessErrorStream,
        ))
    }
    #[cfg(not(any(windows, unix)))]
    {
        None
    }
}
