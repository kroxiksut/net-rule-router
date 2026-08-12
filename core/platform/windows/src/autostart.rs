//! `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
//! autostart helper for `NetRuleRouterTray.exe`.
//!
//! ## Why HKCU and not HKLM
//!
//! Per-user, no admin required. The tray runs as the interactive user
//! and applies routing per-SID, so there is no
//! security benefit to a system-wide autostart entry — only complexity
//! around running tray as the right user. HKCU is the platform default
//! for "launch at login" on Windows.
//!
//! ## Why the tray, not the GUI
//!
//! The tray is the routing agent. GUI is a management console — it should NOT be auto-launched. Users
//! who want the GUI on startup can pin it to the Windows startup folder
//! themselves.
//!
//! ## Default after install
//!
//! Disabled. We never write the registry value at install time — the
//! GUI toggle in Settings → General → "Launch at Windows startup" is
//! the only way to opt in.
//!
//! ## Detection of external overrides
//!
//! Tools and other installers sometimes write to the same `Run` key.
//! [`AutostartHelper::get_state`] returns
//! [`AutostartCurrentState::OverriddenExternally`] when the value
//! exists but does not point at our binary. The GUI surfaces this so
//! the user can decide whether to overwrite.
//!
//! ## Testability
//!
//! Production wraps the Win32 Registry API behind
//! [`AutostartRegistryPort`]. Tests use [`MockAutostartRegistry`] which
//! is a simple `Mutex<Option<String>>` — same pattern as the existing
//! `WindowsApiPort` / `MockWindowsApi` split.

// The neutral autostart coordinator (state/error types, the
// `AutostartRegistryPort` trait, the generic `AutostartHelper` coordinator,
// and the `MockAutostartRegistry` test double) lives in `nrr-platform-api`;
// re-export so `nrr_platform_windows::autostart::*` paths keep resolving
// unchanged. The Windows registry MECHANISM below implements the port via
// the real `HKEY_CURRENT_USER` hive.
pub use nrr_platform_api::autostart::{
    AutostartCurrentState, AutostartError, AutostartHelper, AutostartRegistryPort,
    MockAutostartRegistry,
};

/// Registry "value name" we own. Stable across versions — changing it
/// would orphan existing autostart entries on user upgrades.
pub const AUTOSTART_VALUE_NAME: &str = "NetRuleRouter";

/// Registry key path. `HKEY_CURRENT_USER\` prefix is implicit (the
/// production impl opens HKCU in `RegOpenKeyExW`).
pub const AUTOSTART_SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

// ── Production impl (Win32) ───────────────────────────────────────────────────

#[cfg(target_os = "windows")]
mod production {
    #![allow(unsafe_code)]

    use super::{AutostartError, AutostartRegistryPort, AUTOSTART_SUBKEY, AUTOSTART_VALUE_NAME};

    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, WIN32_ERROR};
    use windows::Win32::System::Registry::{
        RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
        HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_SZ, REG_VALUE_TYPE,
    };

    /// Production `AutostartRegistryPort` — talks to the real
    /// `HKEY_CURRENT_USER` registry hive.
    pub struct ProductionAutostartRegistry;

    impl ProductionAutostartRegistry {
        pub const fn new() -> Self {
            Self
        }

        fn open(&self, access: u32) -> Result<HKEY, AutostartError> {
            let subkey: Vec<u16> = AUTOSTART_SUBKEY
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let mut hkey = HKEY::default();
            // SAFETY: `subkey` is null-terminated UTF-16 and lives for
            // the duration of the call. `hkey` is a freshly-initialised
            // out-pointer. `HKEY_CURRENT_USER` is a Win32 pseudo-handle.
            let rc = unsafe {
                RegOpenKeyExW(
                    HKEY_CURRENT_USER,
                    PCWSTR(subkey.as_ptr()),
                    0,
                    windows::Win32::System::Registry::REG_SAM_FLAGS(access),
                    &mut hkey,
                )
            };
            if rc == ERROR_SUCCESS {
                Ok(hkey)
            } else {
                Err(AutostartError::RegistryAccess {
                    code: rc.0,
                    // (cast: rc is WIN32_ERROR, rc.0 is u32)
                    message: format!("RegOpenKeyExW({AUTOSTART_SUBKEY:?}) failed"),
                })
            }
        }

        fn close(hkey: HKEY) {
            // SAFETY: `hkey` was obtained via `RegOpenKeyExW`. Closing
            // a valid key handle is safe. We ignore the return code — a
            // close failure is non-actionable from this layer.
            unsafe {
                let _ = RegCloseKey(hkey);
            }
        }
    }

    impl Default for ProductionAutostartRegistry {
        fn default() -> Self {
            Self::new()
        }
    }

    impl AutostartRegistryPort for ProductionAutostartRegistry {
        fn read_value(&self) -> Result<Option<String>, AutostartError> {
            let hkey = match self.open(KEY_QUERY_VALUE.0) {
                Ok(h) => h,
                Err(AutostartError::RegistryAccess { code, .. })
                    if WIN32_ERROR(code) == ERROR_FILE_NOT_FOUND =>
                {
                    return Ok(None);
                }
                Err(e) => return Err(e),
            };
            let value_name: Vec<u16> = AUTOSTART_VALUE_NAME
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let mut size: u32 = 0;
            let mut value_type = REG_VALUE_TYPE::default();
            // First call: probe size.
            // SAFETY: pointers refer to local stack values that outlive
            // the call.
            let rc = unsafe {
                RegQueryValueExW(
                    hkey,
                    PCWSTR(value_name.as_ptr()),
                    None,
                    Some(&mut value_type),
                    None,
                    Some(&mut size),
                )
            };
            if WIN32_ERROR(rc.0 as u32) == ERROR_FILE_NOT_FOUND {
                Self::close(hkey);
                return Ok(None);
            }
            if rc != ERROR_SUCCESS {
                Self::close(hkey);
                return Err(AutostartError::RegistryAccess {
                    code: rc.0,
                    // (cast: rc is WIN32_ERROR, rc.0 is u32)
                    message: format!("RegQueryValueExW probe for {AUTOSTART_VALUE_NAME:?} failed"),
                });
            }
            // Buffer for UTF-16 string + trailing NUL.
            let mut buf: Vec<u16> = vec![0u16; (size as usize) / 2 + 1];
            let mut read_size = (buf.len() * 2) as u32;
            // SAFETY: same pointer rules; buf is now sized to fit the
            // value.
            let rc = unsafe {
                RegQueryValueExW(
                    hkey,
                    PCWSTR(value_name.as_ptr()),
                    None,
                    Some(&mut value_type),
                    Some(buf.as_mut_ptr().cast()),
                    Some(&mut read_size),
                )
            };
            Self::close(hkey);
            if rc != ERROR_SUCCESS {
                return Err(AutostartError::RegistryAccess {
                    code: rc.0,
                    // (cast: rc is WIN32_ERROR, rc.0 is u32)
                    message: format!("RegQueryValueExW read for {AUTOSTART_VALUE_NAME:?} failed"),
                });
            }
            let chars = (read_size as usize) / 2;
            let end = chars.min(buf.len()).saturating_sub(1); // strip NUL
            let s = String::from_utf16_lossy(&buf[..end]);
            Ok(Some(s))
        }

        fn write_value(&self, value: &str) -> Result<(), AutostartError> {
            let hkey = self.open(KEY_SET_VALUE.0)?;
            let value_name: Vec<u16> = AUTOSTART_VALUE_NAME
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let utf16: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
            let bytes_len = (utf16.len() * 2) as u32;
            // SAFETY: utf16 lives for the duration of the call; size
            // reflects its byte length including the NUL terminator.
            let rc = unsafe {
                RegSetValueExW(
                    hkey,
                    PCWSTR(value_name.as_ptr()),
                    0,
                    REG_SZ,
                    Some(std::slice::from_raw_parts(
                        utf16.as_ptr().cast::<u8>(),
                        bytes_len as usize,
                    )),
                )
            };
            Self::close(hkey);
            if rc == ERROR_SUCCESS {
                Ok(())
            } else {
                Err(AutostartError::RegistryAccess {
                    code: rc.0,
                    // (cast: rc is WIN32_ERROR, rc.0 is u32)
                    message: format!("RegSetValueExW({AUTOSTART_VALUE_NAME:?}) failed"),
                })
            }
        }

        fn delete_value(&self) -> Result<(), AutostartError> {
            let hkey = match self.open(KEY_SET_VALUE.0) {
                Ok(h) => h,
                Err(AutostartError::RegistryAccess { code, .. })
                    if WIN32_ERROR(code) == ERROR_FILE_NOT_FOUND =>
                {
                    return Ok(());
                }
                Err(e) => return Err(e),
            };
            let value_name: Vec<u16> = AUTOSTART_VALUE_NAME
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            // SAFETY: name is null-terminated UTF-16 and outlives the call.
            let rc = unsafe { RegDeleteValueW(hkey, PCWSTR(value_name.as_ptr())) };
            Self::close(hkey);
            if rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND {
                Ok(())
            } else {
                Err(AutostartError::RegistryAccess {
                    code: rc.0,
                    // (cast: rc is WIN32_ERROR, rc.0 is u32)
                    message: format!("RegDeleteValueW({AUTOSTART_VALUE_NAME:?}) failed"),
                })
            }
        }
    }
}

#[cfg(target_os = "windows")]
pub use production::ProductionAutostartRegistry;
