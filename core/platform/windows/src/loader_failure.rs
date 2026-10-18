//! A child whose DLLs are missing fails with an exit code instead of the
//! system's "DLL not found" box, and the parent says what happened in its own
//! words.

#![cfg(target_os = "windows")]
#![allow(unsafe_code)]

use windows::core::PCWSTR;
use windows::Win32::Foundation::HWND;
use windows::Win32::System::Diagnostics::Debug::{
    GetErrorMode, SetErrorMode, SEM_FAILCRITICALERRORS, THREAD_ERROR_MODE,
};
use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK, MB_SETFOREGROUND};

/// Keeps `SEM_FAILCRITICALERRORS` on this process until dropped, so a child
/// created meanwhile inherits it; the previous mode comes back on drop.
///
/// The process mode is the only carrier: `CreateProcess` gives the child either
/// the parent's process mode or, with `CREATE_DEFAULT_ERROR_MODE`, the system
/// default, and a thread error mode is not inherited at all.
#[must_use = "the mode is restored when this guard drops"]
pub struct LoaderErrorBoxesSuppressed {
    previous: u32,
}

impl LoaderErrorBoxesSuppressed {
    pub fn engage() -> Self {
        // SAFETY: both calls only read and write this process's error-mode word.
        let previous = unsafe {
            let previous = GetErrorMode();
            let _ = SetErrorMode(THREAD_ERROR_MODE(previous | SEM_FAILCRITICALERRORS.0));
            previous
        };
        Self { previous }
    }
}

impl Drop for LoaderErrorBoxesSuppressed {
    fn drop(&mut self) {
        // SAFETY: as in `engage`.
        unsafe {
            let _ = SetErrorMode(THREAD_ERROR_MODE(self.previous));
        }
    }
}

/// A modal error box with no owner window. Blocks until the user closes it.
pub fn show_error_box(title: &str, body: &str) {
    let title = wide_z(title);
    let body = wide_z(body);
    // SAFETY: both buffers are NUL-terminated, contain no interior NUL and
    // outlive the call; a null owner window is allowed.
    unsafe {
        let _ = MessageBoxW(
            HWND::default(),
            PCWSTR(body.as_ptr()),
            PCWSTR(title.as_ptr()),
            MB_OK | MB_ICONERROR | MB_SETFOREGROUND,
        );
    }
}

/// UTF-16 with one terminating NUL; an interior NUL would cut the text short.
fn wide_z(text: &str) -> Vec<u16> {
    text.encode_utf16()
        .filter(|unit| *unit != 0)
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_text_has_exactly_one_terminator() {
        assert_eq!(wide_z("a\0b"), [u16::from(b'a'), u16::from(b'b'), 0]);
        assert_eq!(wide_z(""), [0]);
    }

    #[test]
    fn the_guard_restores_the_previous_mode() {
        // SAFETY: reads this process's error-mode word.
        let before = unsafe { GetErrorMode() };
        {
            let _guard = LoaderErrorBoxesSuppressed::engage();
            // SAFETY: as above.
            let during = unsafe { GetErrorMode() };
            assert_ne!(during & SEM_FAILCRITICALERRORS.0, 0);
        }
        // SAFETY: as above.
        assert_eq!(unsafe { GetErrorMode() }, before);
    }
}
