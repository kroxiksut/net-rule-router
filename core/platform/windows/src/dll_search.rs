//! Where this process looks for a DLL named without a path.
//!
//! By default Windows also searches the current directory and every `PATH`
//! entry, both chosen by whoever starts the process, so a planted DLL runs
//! inside ours — and in the service, as the system account. Every executable
//! calls [`restrict_dll_search`] first in `main`, before anything can load one.

#![cfg(target_os = "windows")]
#![allow(unsafe_code)]

use windows::core::w;
use windows::Win32::System::LibraryLoader::{
    SetDefaultDllDirectories, SetDllDirectoryW, LOAD_LIBRARY_SEARCH_APPLICATION_DIR,
    LOAD_LIBRARY_SEARCH_SYSTEM32,
};

use crate::error::PlatformError;

/// Narrows the search to System32 and the executable's own directory.
///
/// Not `LOAD_LIBRARY_SEARCH_DEFAULT_DIRS`: that also admits directories added
/// with `AddDllDirectory`, which none of our processes needs, so it would only
/// widen the set for whatever library calls it later.
pub fn restrict_dll_search() -> Result<(), PlatformError> {
    // SAFETY: takes plain flags and changes only this process's loader settings.
    unsafe {
        SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_APPLICATION_DIR)
    }
    .map_err(|e| win32_error("SetDefaultDllDirectories", &e))?;
    // A load that asks for the classic search order (`LOAD_WITH_ALTERED_SEARCH_PATH`)
    // bypasses the list above; the empty string drops the current directory there.
    // SAFETY: a static NUL-terminated string; process-local loader setting.
    unsafe { SetDllDirectoryW(w!("")) }.map_err(|e| win32_error("SetDllDirectoryW", &e))
}

fn win32_error(operation: &'static str, e: &windows::core::Error) -> PlatformError {
    PlatformError::Win32 {
        operation,
        code: e.code().0 as u32,
        message: e.message(),
    }
}
