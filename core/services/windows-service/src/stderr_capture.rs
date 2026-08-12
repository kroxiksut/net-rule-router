//! Redirects the service process's stderr into a file.
//!
//! Under SCM there is no console: panics and anything written before the
//! tracing subscriber exists go to a closed handle and vanish. Diagnosing a
//! service that dies during startup then depends on output nobody kept. This
//! points the process-wide stderr handle at a file in the log directory before
//! that can happen.
//!
//! Deliberately not routed through `tracing`: the point is to catch what
//! happens when tracing is not up, or is itself what failed.

// SAFETY: `SetStdHandle` is the only supported way to redirect a process's
// standard error and it takes a raw handle. The unsafe block is confined to
// that single call.
#![allow(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

/// One previous run is kept alongside the current one, so a crash-restart
/// loop cannot erase the evidence of the first crash.
const FILE_NAME: &str = "nrr_service_stderr.log";
const PREVIOUS_FILE_NAME: &str = "nrr_service_stderr.1.log";

/// Point stderr at `<logs_dir>/nrr_service_stderr.log`, rotating the previous
/// run's file aside. Returns the active path on success.
///
/// Failure is silent by design: losing stderr capture must never keep the
/// service from starting.
pub fn redirect_stderr_to_logs(logs_dir: &Path) -> Option<PathBuf> {
    let (file, path) = open_capture_file(logs_dir)?;
    install(file).then_some(path)
}

/// Rotate and open the capture file without touching process state, so the
/// file handling can be tested without redirecting the test runner's stderr.
fn open_capture_file(logs_dir: &Path) -> Option<(File, PathBuf)> {
    std::fs::create_dir_all(logs_dir).ok()?;
    let current = logs_dir.join(FILE_NAME);
    if current.exists() {
        let _ = std::fs::rename(&current, logs_dir.join(PREVIOUS_FILE_NAME));
    }
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&current)
        .ok()?;
    Some((file, current))
}

#[cfg(windows)]
fn install(file: File) -> bool {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Console::{SetStdHandle, STD_ERROR_HANDLE};

    let handle = HANDLE(file.as_raw_handle());
    // SAFETY: `handle` belongs to a File we own; it must outlive every write
    // std performs through STD_ERROR_HANDLE, which is why the File is leaked
    // on success rather than dropped.
    let installed = unsafe { SetStdHandle(STD_ERROR_HANDLE, handle) }.is_ok();
    if installed {
        // std re-reads STD_ERROR_HANDLE on every write, so the handle stays
        // open for the life of the process.
        std::mem::forget(file);
    }
    installed
}

#[cfg(not(windows))]
fn install(_file: File) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_file_lands_in_a_created_directory() {
        let temp = tempfile::tempdir().expect("temp dir");
        let logs = temp.path().join("logs");

        let (_file, path) = open_capture_file(&logs).expect("capture file opened");

        assert!(logs.exists());
        assert_eq!(path.file_name().and_then(|n| n.to_str()), Some(FILE_NAME));
    }

    #[test]
    fn previous_run_is_kept_aside() {
        let temp = tempfile::tempdir().expect("temp dir");
        let logs = temp.path().to_path_buf();
        std::fs::write(logs.join(FILE_NAME), b"older run").expect("seed file");

        let (_file, _path) = open_capture_file(&logs).expect("capture file opened");

        let previous = std::fs::read(logs.join(PREVIOUS_FILE_NAME)).expect("previous kept");
        assert_eq!(previous, b"older run");
    }
}
