//! Directories Windows itself names, asked of Windows rather than of the
//! environment.
//!
//! `%SystemRoot%` and `%ProgramData%` are environment strings, and an elevated
//! process a user starts inherits that user's environment. Taken from there, a
//! planted variable hands an installer or the UAC relay someone else's
//! `icacls.exe` or `powershell.exe`, or points a SYSTEM-owned data tree at a
//! directory the user controls.
#![allow(unsafe_code)]

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows::Win32::UI::Shell::{
    FOLDERID_LocalAppData, FOLDERID_ProgramData, SHGetKnownFolderPath, KNOWN_FOLDER_FLAG,
};

/// Where every supported Windows keeps it; used only if the API itself fails,
/// and still an administrators-only directory rather than a search by name.
const SYSTEM_DIRECTORY_FALLBACK: &str = r"C:\Windows\System32";

/// `System32`, from `GetSystemDirectoryW`.
#[must_use]
pub fn system_directory() -> PathBuf {
    let mut buf = [0u16; 512];
    // SAFETY: the buffer is valid for its whole length, and the call writes at
    // most that many UTF-16 units, returning how many it wrote.
    let len = unsafe { GetSystemDirectoryW(Some(&mut buf)) } as usize;
    if len == 0 || len >= buf.len() {
        return PathBuf::from(SYSTEM_DIRECTORY_FALLBACK);
    }
    PathBuf::from(OsString::from_wide(&buf[..len]))
}

/// A tool shipped in `System32`, by absolute path.
#[must_use]
pub fn system32_exe(file_name: &str) -> PathBuf {
    system_directory().join(file_name)
}

/// The system Windows PowerShell.
#[must_use]
pub fn system_powershell() -> PathBuf {
    system_directory()
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe")
}

/// `%ProgramData%` as the shell registers it, or `None` when it cannot say.
#[must_use]
pub fn program_data_directory() -> Option<PathBuf> {
    known_folder(&FOLDERID_ProgramData)
}

/// `%LOCALAPPDATA%` as the shell registers it, or `None` when it cannot say.
#[must_use]
pub fn local_app_data_directory() -> Option<PathBuf> {
    known_folder(&FOLDERID_LocalAppData)
}

fn known_folder(id: &windows::core::GUID) -> Option<PathBuf> {
    // SAFETY: a documented known-folder query with no token; the returned
    // buffer is read once and released with `CoTaskMemFree`, as the API requires.
    unsafe {
        let raw = SHGetKnownFolderPath(id, KNOWN_FOLDER_FLAG(0), None).ok()?;
        let path = raw.to_string().ok().map(PathBuf::from);
        CoTaskMemFree(Some(raw.0 as *const core::ffi::c_void));
        path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_directory_is_the_one_holding_the_system_tools() {
        let dir = system_directory();
        assert!(dir.is_absolute(), "{}", dir.display());
        assert!(system32_exe("icacls.exe").is_file(), "{}", dir.display());
        assert!(system_powershell().is_file());
    }

    #[test]
    fn program_data_is_an_existing_absolute_directory() {
        let dir = program_data_directory().expect("known folder");
        assert!(dir.is_absolute() && dir.is_dir(), "{}", dir.display());
    }

    #[test]
    fn local_app_data_is_an_existing_absolute_directory() {
        let dir = local_app_data_directory().expect("known folder");
        assert!(dir.is_absolute() && dir.is_dir(), "{}", dir.display());
    }
}
