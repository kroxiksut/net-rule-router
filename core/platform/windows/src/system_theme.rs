//! Windows implementation of [`SystemThemePort`].

use nrr_platform_api::system_theme::{SystemAppearance, SystemThemePort};

/// Reads the per-user Personalize key directly.
///
/// The previous probe spawned PowerShell to read the same value — on the cold
/// start path, before the window exists, for one DWORD.
pub struct WindowsSystemTheme;

impl SystemThemePort for WindowsSystemTheme {
    fn detect(&self) -> Option<SystemAppearance> {
        #[cfg(target_os = "windows")]
        {
            const PERSONALIZE: &str =
                r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";
            // 0 = apps use the dark theme, 1 = light. Absent on older builds,
            // which is a legitimate "cannot tell".
            match reg_dword(PERSONALIZE, "AppsUseLightTheme")? {
                0 => Some(SystemAppearance::Dark),
                _ => Some(SystemAppearance::Light),
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            None
        }
    }
}

/// Read a `REG_DWORD` from `HKEY_CURRENT_USER`. `None` on any failure.
#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
fn reg_dword(subkey: &str, value: &str) -> Option<u32> {
    use std::ffi::c_void;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_DWORD};

    let subkey_w: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
    let value_w: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    let mut data: u32 = 0;
    let mut size: u32 = std::mem::size_of::<u32>() as u32;
    // SAFETY: NUL-terminated wide pointers, and a destination whose declared
    // size matches the u32 actually passed.
    let rc = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            PCWSTR(subkey_w.as_ptr()),
            PCWSTR(value_w.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some(std::ptr::addr_of_mut!(data) as *mut c_void),
            Some(&mut size),
        )
    };
    (rc == ERROR_SUCCESS).then_some(data)
}

// Windows-only: the one test here probes the live registry, so off Windows the
// module would be empty and its import unused (`-D warnings` in CI). Same shape
// as `app_path_resolver`'s tests in this crate.
#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;

    #[test]
    fn the_probe_answers_or_admits_it_cannot() {
        // Whatever this machine is set to, the answer must be a real one or a
        // stated absence — never a guess dressed as an observation.
        let answer = WindowsSystemTheme.detect();
        assert!(matches!(
            answer,
            None | Some(SystemAppearance::Light) | Some(SystemAppearance::Dark)
        ));
    }
}
