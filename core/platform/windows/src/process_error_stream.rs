//! Windows mechanism behind
//! [`nrr_platform_api::process_error_stream::ProcessErrorStreamPort`].
//!
//! Windows gives every process a small table of standard handles, and a child
//! started by another process inherits its parent's entries. Replacing the
//! error entry with a file handle is therefore enough to move ALL later output —
//! the Rust standard library re-reads the table on every write, so `eprintln!`
//! from any crate and the panic hook follow the new destination without anyone
//! having to route through a logging facade.

#![cfg(target_os = "windows")]
#![allow(unsafe_code)]

use std::fs::OpenOptions;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use nrr_platform_api::error::PlatformError;
use nrr_platform_api::process_error_stream::ProcessErrorStreamPort;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Console::{
    GetConsoleMode, GetStdHandle, SetStdHandle, CONSOLE_MODE, STD_ERROR_HANDLE,
};

/// Production implementation over the process's standard-handle table.
pub struct WindowsProcessErrorStream;

impl ProcessErrorStreamPort for WindowsProcessErrorStream {
    fn error_stream_is_interactive(&self) -> bool {
        // `GetConsoleMode` succeeds for console handles and fails for every
        // other kind — a pipe, a file, or the invalid handle a double-clicked
        // GUI program starts with.
        // SAFETY: both calls only read this process's own handle table;
        // `mode` is a stack `u32` the callee writes through a valid pointer.
        unsafe {
            let Ok(handle) = GetStdHandle(STD_ERROR_HANDLE) else {
                return false;
            };
            let mut mode = CONSOLE_MODE::default();
            GetConsoleMode(handle, &mut mode).is_ok()
        }
    }

    fn redirect_to_file(&self, path: &Path) -> Result<(), PlatformError> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| PlatformError::Transient {
                operation: "open error-stream file",
                detail: format!("{}: {e}", path.display()),
            })?;
        let handle = HANDLE(file.as_raw_handle());

        // SAFETY: `handle` is a live file handle owned by this process for as
        // long as the process runs (see the leak below). `SetStdHandle` only
        // stores it in this process's own handle table — it neither duplicates
        // nor closes anything.
        let result = unsafe { SetStdHandle(STD_ERROR_HANDLE, handle) };
        result.map_err(|e| PlatformError::Win32 {
            operation: "SetStdHandle(STD_ERROR_HANDLE)",
            code: e.code().0 as u32,
            message: e.message(),
        })?;

        // The handle table borrows the handle without owning it: dropping the
        // `File` here would close it and leave every later write pointing at a
        // closed handle. The destination is meant to live as long as the
        // process, so the file is deliberately never closed.
        std::mem::forget(file);
        Ok(())
    }
}
