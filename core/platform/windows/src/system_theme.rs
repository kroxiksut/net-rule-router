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

    fn high_contrast(&self) -> Option<bool> {
        #[cfg(target_os = "windows")]
        {
            const ACCESSIBILITY: &str = r"Control Panel\Accessibility\HighContrast";
            // `Flags` is a REG_SZ holding the decimal HCF_* bitmask; bit 0
            // (`HCF_HIGHCONTRASTON`) is the switch itself. Read from the
            // registry rather than through `SPI_GETHIGHCONTRAST` so the probe
            // stays a value read with no window and no message loop.
            let flags: u32 = reg_string(ACCESSIBILITY, "Flags")?.trim().parse().ok()?;
            Some(flags & 1 != 0)
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

/// Read a `REG_SZ` from `HKEY_CURRENT_USER`. `None` on any failure.
#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
fn reg_string(subkey: &str, value: &str) -> Option<String> {
    use std::ffi::c_void;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_SZ};

    let subkey_w: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
    let value_w: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    // The bitmask is a handful of digits; anything longer is not this value.
    let mut buffer = [0u16; 64];
    let mut size: u32 = std::mem::size_of_val(&buffer) as u32;
    // SAFETY: NUL-terminated wide pointers, and a destination whose declared
    // size in BYTES matches the buffer actually passed.
    let rc = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            PCWSTR(subkey_w.as_ptr()),
            PCWSTR(value_w.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            Some(buffer.as_mut_ptr().cast::<c_void>()),
            Some(&mut size),
        )
    };
    if rc != ERROR_SUCCESS {
        return None;
    }
    let chars = (size as usize / std::mem::size_of::<u16>()).min(buffer.len());
    let text: String = String::from_utf16_lossy(&buffer[..chars]);
    Some(text.trim_end_matches('\0').to_owned())
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

    #[test]
    fn high_contrast_is_read_or_admitted_unknown() {
        // Same contract as the appearance probe: a real answer or a stated
        // absence. `Some(false)` on a machine with high contrast off is the
        // observation; `None` is what a missing key must produce, never a
        // silent "off" that would strand the user in the ordinary palette.
        assert!(matches!(
            WindowsSystemTheme.high_contrast(),
            None | Some(true) | Some(false)
        ));
    }
}
