//! Running processes: their ids and image paths.

#![allow(unsafe_code)]

use std::path::PathBuf;

use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, FALSE, HANDLE};
use windows::Win32::System::ProcessStatus::EnumProcesses;
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// The longest path Win32 can name, in UTF-16 units with the terminator.
const MAX_PATH_UNITS: usize = 32_768;
/// Past `MAX_PATH` with room to spare, so an ordinary path takes one call.
const FIRST_TRY_UNITS: usize = 512;

/// Every running process id; empty on failure.
pub fn enum_process_ids() -> Vec<u32> {
    let mut pids = vec![0u32; 1024];
    loop {
        let cap_bytes = u32::try_from(std::mem::size_of_val(pids.as_slice())).unwrap_or(u32::MAX);
        let mut needed: u32 = 0;
        // SAFETY: `pids` is a valid `cap_bytes`-sized buffer; `needed` is a
        // fresh out-param receiving the bytes written.
        let ok = unsafe { EnumProcesses(pids.as_mut_ptr(), cap_bytes, &mut needed) };
        if ok.is_err() {
            return Vec::new();
        }
        let returned = (needed as usize) / std::mem::size_of::<u32>();
        // A full buffer may have dropped ids: grow and ask again.
        if returned < pids.len() || pids.len() >= 65_536 {
            pids.truncate(returned.min(pids.len()));
            return pids;
        }
        pids.resize(pids.len() * 2, 0);
    }
}

/// The image path of `pid`. `None` for pid 0, a process that has exited, or
/// one query-only rights cannot open.
pub fn process_image_path(pid: u32) -> Option<PathBuf> {
    if pid == 0 {
        return None;
    }
    // SAFETY: query-only rights on a pid; the handle is closed below.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid) }.ok()?;
    if handle.is_invalid() {
        return None;
    }
    let path = image_path_of(handle);
    // SAFETY: opened above and not used after this call.
    unsafe {
        let _ = CloseHandle(handle);
    }
    path.ok().filter(|path| !path.is_empty()).map(PathBuf::from)
}

/// The Win32 image path of an open process, however long: a long-path
/// install must not make its process invisible.
pub fn image_path_of(process: HANDLE) -> windows::core::Result<String> {
    image_path_growing_from(process, FIRST_TRY_UNITS)
}

fn image_path_growing_from(process: HANDLE, first_try: usize) -> windows::core::Result<String> {
    let mut units = first_try.clamp(1, MAX_PATH_UNITS);
    loop {
        let mut buf = vec![0u16; units];
        let mut size = u32::try_from(units).unwrap_or(u32::MAX);
        // SAFETY: `buf` holds `size` units; the call writes at most that many
        // and sets `size` to the count written, without the terminator.
        let queried = unsafe {
            QueryFullProcessImageNameW(
                process,
                PROCESS_NAME_WIN32,
                PWSTR(buf.as_mut_ptr()),
                &mut size,
            )
        };
        match queried {
            Ok(()) => {
                buf.truncate((size as usize).min(units));
                return Ok(String::from_utf16_lossy(&buf));
            }
            Err(e)
                if e.code() == ERROR_INSUFFICIENT_BUFFER.to_hresult() && units < MAX_PATH_UNITS =>
            {
                units = (units * 4).min(MAX_PATH_UNITS);
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::System::Threading::GetCurrentProcess;

    fn same_file(a: &std::path::Path, b: &std::path::Path) -> bool {
        std::fs::canonicalize(a).ok() == std::fs::canonicalize(b).ok()
    }

    #[test]
    fn this_process_is_found_by_its_pid() {
        let path = process_image_path(std::process::id()).expect("own image");
        assert!(
            same_file(&path, &std::env::current_exe().expect("exe")),
            "{path:?}"
        );
        assert!(enum_process_ids().contains(&std::process::id()));
    }

    /// A buffer far too small grows until the whole path fits.
    #[test]
    fn a_path_longer_than_the_first_buffer_is_read_whole() {
        // SAFETY: the pseudo-handle of this process needs no closing.
        let own = unsafe { GetCurrentProcess() };
        let path = image_path_growing_from(own, 4).expect("grown");
        let exe = std::env::current_exe().expect("exe");
        assert!(same_file(std::path::Path::new(&path), &exe), "{path}");
    }

    #[test]
    fn pid_zero_has_no_image() {
        assert_eq!(process_image_path(0), None);
    }
}
