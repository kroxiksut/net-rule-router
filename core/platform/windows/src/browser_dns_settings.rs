//! Read-only browser settings hints for the authenticated user's fixed locations.

use nrr_platform_api::browser_dns_settings::BrowserDnsSettingsPort;
use nrr_shared::browser_dns_settings::BrowserDnsSettingsDto;

pub struct WindowsBrowserDnsSettings;

impl BrowserDnsSettingsPort for WindowsBrowserDnsSettings {
    fn inspect(&self, principal: &str) -> Vec<BrowserDnsSettingsDto> {
        #[cfg(windows)]
        {
            inspect_windows(principal)
        }
        #[cfg(not(windows))]
        {
            nrr_platform_api::browser_dns_settings::NoopBrowserDnsSettings.inspect(principal)
        }
    }
}

#[cfg(windows)]
fn inspect_windows(principal: &str) -> Vec<BrowserDnsSettingsDto> {
    use nrr_shared::browser_dns_settings::{
        read_chromium_dns_mode, BrowserDnsBrowser, BrowserDnsSource, MAX_BROWSER_DNS_SETTINGS_BYTES,
    };
    let mut observations = Vec::with_capacity(3);
    let valid = principal.starts_with("S-1-")
        && principal.len() <= 184
        && principal
            .bytes()
            .skip(2)
            .all(|b| b.is_ascii_digit() || b == b'-');
    let root = valid
        .then(|| policy_probe::profile_root(principal))
        .flatten();
    for (browser, location, policy) in [
        (
            BrowserDnsBrowser::Chrome,
            r"Google\Chrome\User Data\Local State",
            r"SOFTWARE\Policies\Google\Chrome",
        ),
        (
            BrowserDnsBrowser::Edge,
            r"Microsoft\Edge\User Data\Local State",
            r"SOFTWARE\Policies\Microsoft\Edge",
        ),
    ] {
        let mut observation = BrowserDnsSettingsDto::unavailable(browser);
        if valid {
            observation.policy = policy_probe::inspect(principal, policy);
        }
        if let Some(root) = root.as_ref() {
            let path = root.join("AppData").join("Local").join(location);
            if let Ok(file) = crate::win32_browser_history::open_verified(
                root,
                &path,
                principal,
                MAX_BROWSER_DNS_SETTINGS_BYTES,
            ) {
                if let Some(mode) = read_chromium_dns_mode(file) {
                    observation.configured_mode = mode;
                    observation.source = BrowserDnsSource::LocalState;
                }
            }
        }
        observations.push(observation);
    }
    observations.push(BrowserDnsSettingsDto::unsupported(
        BrowserDnsBrowser::Firefox,
    ));
    observations
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use nrr_shared::browser_dns_settings::{BrowserDnsMode, BrowserDnsSource};

    #[test]
    fn invalid_principals_cannot_fall_back_to_the_services_browser_profile() {
        for principal in ["", "__baseline__", r"S-1-5-21-1\another-user", "unix:uid:0"] {
            let observations = WindowsBrowserDnsSettings.inspect(principal);
            assert_eq!(observations.len(), 3);
            assert!(observations
                .iter()
                .all(|observation| observation.configured_mode == BrowserDnsMode::Unknown));
            assert!(observations[..2]
                .iter()
                .all(|observation| observation.source == BrowserDnsSource::Unavailable));
        }
    }
}

#[cfg(windows)]
mod policy_probe {
    // Registry FFI stays here; profile paths have a fixed read bound.
    #![allow(unsafe_code)]

    use nrr_shared::browser_dns_settings::BrowserDnsPolicy;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, HKEY_USERS,
        KEY_QUERY_VALUE, KEY_WOW64_32KEY, KEY_WOW64_64KEY, REG_EXPAND_SZ, REG_SZ, REG_VALUE_TYPE,
    };

    struct Key(HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: this owns a successfully opened key and closes it once.
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }

    pub(super) fn profile_root(principal: &str) -> Option<std::path::PathBuf> {
        let path = format!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{principal}");
        let path: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
        let mut handle = HKEY::default();
        // SAFETY: the validated SID produces a bounded NUL-terminated key path.
        let result = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(path.as_ptr()),
                0,
                KEY_QUERY_VALUE | KEY_WOW64_64KEY,
                &mut handle,
            )
        };
        if result != ERROR_SUCCESS {
            return None;
        }
        let key = Key(handle);
        let name: Vec<u16> = "ProfileImagePath".encode_utf16().chain(Some(0)).collect();
        let mut buffer = [0_u16; 32_768];
        let mut length = 65_536;
        let mut kind = REG_VALUE_TYPE::default();
        // SAFETY: the fixed buffer is exactly `length` bytes; all pointers outlive the call.
        let result = unsafe {
            RegQueryValueExW(
                key.0,
                PCWSTR(name.as_ptr()),
                None,
                Some(&mut kind),
                Some(buffer.as_mut_ptr().cast()),
                Some(&mut length),
            )
        };
        if result != ERROR_SUCCESS
            || ![REG_SZ, REG_EXPAND_SZ].contains(&kind)
            || !(2..=65_536).contains(&length)
            || !length.is_multiple_of(2)
        {
            return None;
        }
        let units = buffer[..length as usize / 2].strip_suffix(&[0])?;
        if units.contains(&0) {
            return None;
        }
        let path = String::from_utf16(units).ok()?;
        if path.is_empty() || path.contains('%') {
            return None;
        }
        let path = std::path::PathBuf::from(path);
        path.is_absolute().then_some(path)
    }

    pub(super) fn inspect(principal: &str, policy: &str) -> BrowserDnsPolicy {
        let user_policy = format!(r"{principal}\{policy}");
        for (hive, path) in [
            (HKEY_LOCAL_MACHINE, policy),
            (HKEY_USERS, user_policy.as_str()),
        ] {
            let path: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
            for view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
                let mut handle = HKEY::default();
                // SAFETY: bounded NUL-terminated path and a fresh out-parameter.
                let result = unsafe {
                    RegOpenKeyExW(
                        hive,
                        PCWSTR(path.as_ptr()),
                        0,
                        KEY_QUERY_VALUE | view,
                        &mut handle,
                    )
                };
                if result != ERROR_SUCCESS {
                    continue;
                }
                let key = Key(handle);
                for name in ["DnsOverHttpsMode", "DnsOverHttpsTemplates"] {
                    let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
                    let mut length = 0;
                    // SAFETY: names outlive the call; null data requests only the size.
                    let result = unsafe {
                        RegQueryValueExW(
                            key.0,
                            PCWSTR(name.as_ptr()),
                            None,
                            None,
                            None,
                            Some(&mut length),
                        )
                    };
                    if result == ERROR_SUCCESS {
                        return BrowserDnsPolicy::Detected;
                    }
                }
            }
        }
        // Cloud policy and running-process overrides cannot be excluded from disk.
        BrowserDnsPolicy::Unknown
    }
}
