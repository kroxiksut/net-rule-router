//! Read-only registry access, the installed-program list, and the path values
//! programs leave there.

#![allow(unsafe_code)]

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{ERROR_MORE_DATA, ERROR_SUCCESS};
use windows::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_CURRENT_USER,
    HKEY_LOCAL_MACHINE, KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE, REG_SAM_FLAGS,
};

/// Key names are at most 255 characters.
const MAX_KEY_NAME_UNITS: usize = 256;
/// Bounds a pathological hive.
const MAX_SUBKEYS: u32 = 20_000;

/// An open key, closed when dropped.
struct Key(HKEY);

impl Key {
    fn open(hive: HKEY, subkey: &str, access: REG_SAM_FLAGS) -> Option<Self> {
        let wide: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
        let mut hkey = HKEY::default();
        // SAFETY: `wide` is NUL-terminated UTF-16 outliving the call; `hkey` is
        // a fresh out-param; the hive is a predefined handle.
        let rc = unsafe { RegOpenKeyExW(hive, PCWSTR(wide.as_ptr()), 0, access, &mut hkey) };
        (rc == ERROR_SUCCESS).then_some(Self(hkey))
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful `RegOpenKeyExW` and is
        // closed once, here.
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

/// Whether `hive\subkey` exists and can be opened for reading.
pub fn key_exists(hive: HKEY, subkey: &str) -> bool {
    Key::open(hive, subkey, KEY_QUERY_VALUE).is_some()
}

/// A string value of `hive\subkey`; `value_name` `None` reads the default
/// value. Taken as written, `%VAR%` tokens included.
pub fn read_string(hive: HKEY, subkey: &str, value_name: Option<&str>) -> Option<String> {
    let key = Key::open(hive, subkey, KEY_QUERY_VALUE)?;
    let name: Option<Vec<u16>> =
        value_name.map(|n| n.encode_utf16().chain(std::iter::once(0)).collect());
    let name_ptr = name.as_ref().map_or(PCWSTR::null(), |n| PCWSTR(n.as_ptr()));
    let mut size: u32 = 0;
    // SAFETY: `name_ptr` is null (the default value) or NUL-terminated UTF-16
    // outliving the call; this probe asks only for the byte length.
    let rc = unsafe { RegQueryValueExW(key.0, name_ptr, None, None, None, Some(&mut size)) };
    if rc != ERROR_SUCCESS {
        return None;
    }
    let mut buf: Vec<u16> = vec![0u16; (size as usize) / 2 + 1];
    let mut read = u32::try_from(buf.len() * 2).unwrap_or(u32::MAX);
    // SAFETY: `buf` is sized from the probe and `read` carries its byte
    // length, so the call cannot write past it.
    let rc = unsafe {
        RegQueryValueExW(
            key.0,
            name_ptr,
            None,
            None,
            Some(buf.as_mut_ptr().cast()),
            Some(&mut read),
        )
    };
    if rc != ERROR_SUCCESS {
        return None;
    }
    let units = ((read as usize) / 2).min(buf.len());
    Some(
        String::from_utf16_lossy(&buf[..units])
            .trim_end_matches('\0')
            .to_string(),
    )
}

/// The immediate subkey names of `hive\subkey`; empty when it cannot be
/// opened. A name too long to read is skipped, not the rest.
pub fn enum_subkeys(hive: HKEY, subkey: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Some(key) = Key::open(hive, subkey, KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE) else {
        return out;
    };
    for index in 0..MAX_SUBKEYS {
        let mut buf = [0u16; MAX_KEY_NAME_UNITS];
        let mut len = MAX_KEY_NAME_UNITS as u32;
        // SAFETY: `buf` is owned by this frame and `len` carries its length in
        // characters, so the call cannot write past it.
        let rc = unsafe {
            RegEnumKeyExW(
                key.0,
                index,
                PWSTR(buf.as_mut_ptr()),
                &mut len,
                None,
                PWSTR::null(),
                None,
                None,
            )
        };
        if rc == ERROR_SUCCESS {
            out.push(String::from_utf16_lossy(
                &buf[..(len as usize).min(buf.len())],
            ));
        } else if rc != ERROR_MORE_DATA {
            break;
        }
    }
    out
}

/// The `Uninstall` roots that list installed programs: the native view, the
/// 32-bit `WOW6432Node` view, and the per-user hive.
const UNINSTALL_ROOTS: &[(HKEY, &str)] = &[
    (
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    ),
    (
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ),
    (
        HKEY_CURRENT_USER,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    ),
];

/// One program an `Uninstall` key lists. Values are read on demand, so a
/// caller that rejects the name pays for nothing else.
pub struct InstalledProgram {
    hive: HKEY,
    key: String,
}

impl InstalledProgram {
    /// `DisplayName`, trimmed; `None` when missing or blank.
    pub fn display_name(&self) -> Option<String> {
        read_string(self.hive, &self.key, Some("DisplayName"))
            .map(|name| name.trim().to_string())
            .filter(|name| !name.is_empty())
    }

    /// Best-effort exe path: the `DisplayIcon` executable, else the
    /// `InstallLocation` directory as a hint for the file picker.
    pub fn exe_path(&self) -> Option<String> {
        read_string(self.hive, &self.key, Some("DisplayIcon"))
            .and_then(|raw| exe_from_display_icon(&raw))
            .or_else(|| {
                read_string(self.hive, &self.key, Some("InstallLocation"))
                    .map(|loc| unquote(&loc).to_string())
                    .filter(|s| !s.trim().is_empty())
            })
    }
}

/// Every installed-program entry under the `Uninstall` roots; a root that
/// cannot be opened contributes nothing.
pub fn installed_programs() -> impl Iterator<Item = InstalledProgram> {
    UNINSTALL_ROOTS.iter().flat_map(|&(hive, root)| {
        enum_subkeys(hive, root)
            .into_iter()
            .map(move |sub| InstalledProgram {
                hive,
                key: format!(r"{root}\{sub}"),
            })
    })
}

/// Strip one pair of surrounding double quotes, if present.
pub fn unquote(raw: &str) -> &str {
    let trimmed = raw.trim();
    trimmed
        .strip_prefix('"')
        .and_then(|r| r.strip_suffix('"'))
        .unwrap_or(trimmed)
}

/// The executable a `DisplayIcon` value names: a trailing `,<index>` icon
/// selector and surrounding quotes stripped, kept only if it is an `.exe`.
pub fn exe_from_display_icon(raw: &str) -> Option<String> {
    let unquoted = unquote(raw);
    let candidate = match unquoted.rsplit_once(',') {
        Some((path, idx)) if idx.chars().all(|c| c.is_ascii_digit() || c == '-') => path,
        _ => unquoted,
    };
    let candidate = candidate.trim();
    candidate
        .to_ascii_lowercase()
        .ends_with(".exe")
        .then(|| candidate.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;

    const CURRENT_VERSION: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

    #[test]
    fn exe_from_display_icon_strips_index_and_quotes() {
        assert_eq!(
            exe_from_display_icon(r#""C:\Apps\client.exe,0""#).as_deref(),
            Some(r"C:\Apps\client.exe")
        );
        assert_eq!(
            exe_from_display_icon(r"C:\Apps\client.exe").as_deref(),
            Some(r"C:\Apps\client.exe")
        );
        assert_eq!(
            exe_from_display_icon(r"C:\Apps\app.exe,-1").as_deref(),
            Some(r"C:\Apps\app.exe")
        );
        assert_eq!(exe_from_display_icon(r"C:\Apps\icon.ico"), None);
        assert_eq!(exe_from_display_icon(""), None);
    }

    #[test]
    fn unquote_strips_a_single_surrounding_pair() {
        assert_eq!(unquote(r#""C:\a\b.exe""#), r"C:\a\b.exe");
        assert_eq!(unquote(r"C:\a\b.exe"), r"C:\a\b.exe");
        assert_eq!(unquote(r#""C:\a\b.exe"#), r#""C:\a\b.exe"#);
    }

    /// Keys every Windows install carries, so the reads are exercised for real.
    #[test]
    fn reads_what_every_windows_install_has() {
        assert!(key_exists(HKEY_LOCAL_MACHINE, CURRENT_VERSION));
        let product = read_string(HKEY_LOCAL_MACHINE, CURRENT_VERSION, Some("ProductName"))
            .expect("product name");
        assert!(product.contains("Windows"), "{product}");
        assert!(!product.ends_with('\0'));
        assert!(enum_subkeys(HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft").contains(&"Windows".into()));
        assert!(!key_exists(HKEY_LOCAL_MACHINE, r"SOFTWARE\nrr-no-such-key"));
        assert!(enum_subkeys(HKEY_LOCAL_MACHINE, r"SOFTWARE\nrr-no-such-key").is_empty());
    }
}
