//! Browser configuration observations never establish the browser's effective DNS path.

use serde::{Deserialize, Serialize};
use std::io::Read;

pub const MAX_BROWSER_DNS_SETTINGS_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BrowserDnsBrowser {
    Chrome,
    Edge,
    Firefox,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BrowserDnsMode {
    Off,
    Automatic,
    Secure,
    #[default]
    Unknown,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BrowserDnsPolicy {
    Detected,
    #[default]
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BrowserDnsSource {
    LocalState,
    Unavailable,
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BrowserDnsSettingsDto {
    pub browser: BrowserDnsBrowser,
    pub configured_mode: BrowserDnsMode,
    pub policy: BrowserDnsPolicy,
    pub source: BrowserDnsSource,
    pub automatic_change_available: bool,
}

impl BrowserDnsSettingsDto {
    pub fn unavailable(browser: BrowserDnsBrowser) -> Self {
        Self {
            browser,
            configured_mode: BrowserDnsMode::Unknown,
            policy: BrowserDnsPolicy::Unknown,
            source: BrowserDnsSource::Unavailable,
            automatic_change_available: false,
        }
    }

    pub fn unsupported(browser: BrowserDnsBrowser) -> Self {
        Self {
            source: BrowserDnsSource::Unsupported,
            ..Self::unavailable(browser)
        }
    }
}

/// Read the explicit Local State preference only; defaults and policy overrides remain unknown.
pub fn read_chromium_dns_mode(reader: impl Read) -> Option<BrowserDnsMode> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_BROWSER_DNS_SETTINGS_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    parse_chromium_dns_mode(&bytes)
}

fn parse_chromium_dns_mode(bytes: &[u8]) -> Option<BrowserDnsMode> {
    if bytes.len() as u64 > MAX_BROWSER_DNS_SETTINGS_BYTES || !bounded_json_depth(bytes) {
        return None;
    }
    #[derive(Deserialize)]
    struct LocalState {
        dns_over_https: Option<DnsSettings>,
    }
    #[derive(Deserialize)]
    struct DnsSettings {
        mode: Option<String>,
    }
    let settings: LocalState = serde_json::from_slice(bytes).ok()?;
    Some(
        match settings.dns_over_https.and_then(|dns| dns.mode).as_deref() {
            Some("off") => BrowserDnsMode::Off,
            Some("automatic") => BrowserDnsMode::Automatic,
            Some("secure") => BrowserDnsMode::Secure,
            _ => BrowserDnsMode::Unknown,
        },
    )
}

fn bounded_json_depth(bytes: &[u8]) -> bool {
    let mut depth = 0_u8;
    let mut quoted = false;
    let mut escaped = false;
    for &byte in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    if depth == 64 {
                        return false;
                    }
                    depth += 1;
                }
                b'}' | b']' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    true
}

#[cfg(feature = "fuzzing")]
pub fn fuzz_chromium_dns_mode(bytes: &[u8]) {
    let _ = parse_chromium_dns_mode(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_or_unrecognized_preference_never_proves_dns_disabled() {
        for input in [
            br#"{}"#.as_slice(),
            br#"{"dns_over_https":{"mode":"future-mode"}}"#,
        ] {
            assert_eq!(read_chromium_dns_mode(input), Some(BrowserDnsMode::Unknown));
        }
        assert_eq!(
            read_chromium_dns_mode(br#"{"dns_over_https":{"mode":"secure"}}"#.as_slice()),
            Some(BrowserDnsMode::Secure)
        );
        assert_eq!(
            read_chromium_dns_mode(br#"{"dns_over_https":{"mode":"off"}}"#.as_slice()),
            Some(BrowserDnsMode::Off)
        );
    }

    #[test]
    fn duplicate_settings_and_truncated_or_deep_json_are_unknown() {
        for input in [
            br#"{"dns_over_https":{"mode":"off","mode":"secure"}}"#.as_slice(),
            br#"{"dns_over_https":{"mode":"off"},"dns_over_https":{"mode":"secure"}}"#,
            br#"{"dns_over_https":{"mode":"off"}"#,
        ] {
            assert_eq!(read_chromium_dns_mode(input), None);
        }
        let deep = format!("{{\"ignored\":{}0{}}}", "[".repeat(256), "]".repeat(256));
        assert_eq!(read_chromium_dns_mode(deep.as_bytes()), None);
        assert_eq!(read_chromium_dns_mode([0xff, 0xfe].as_slice()), None);
    }

    #[test]
    fn a_growing_file_and_a_failing_reader_do_not_report_success() {
        let oversized = std::io::repeat(b' ').take(MAX_BROWSER_DNS_SETTINGS_BYTES + 1);
        assert_eq!(read_chromium_dns_mode(oversized), None);
        struct Failing;
        impl Read for Failing {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
            }
        }
        assert_eq!(read_chromium_dns_mode(Failing), None);
    }
}
