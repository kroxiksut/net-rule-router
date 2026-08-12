//! Redaction helpers and `Redacted<T>` wrapper.
//!
//! # Redaction markers
//!
//! When a field is hidden, a stable marker string replaces it so the user
//! understands the data was intentionally withheld:
//!
//! | Marker                        | Used for                              |
//! |-------------------------------|---------------------------------------|
//! | `<redacted>`                  | Generic — field exists but is hidden  |
//! | `<masked-ipv4>`               | IPv4 address hidden in default mode   |
//! | `<masked-path>`               | Full process path hidden              |
//! | `<diagnostic-mode-required>`  | Field needs explicit diagnostic mode  |
//! | `<private-ipv4>`              | RFC-1918 / loopback address           |
//! | `<public-ipv4>`               | Public IPv4, hidden in default mode   |
//!
//! # Golden rule: `PrivacyClass::SecretNeverLog`
//!
//! Any value tagged `SecretNeverLog` must **never** appear in any output.
//! Use [`SecretNeverLog`] (defined in `secret.rs`) for values that must be
//! denied at the type level.

use std::net::Ipv4Addr;

use crate::privacy::mode::RedactionMode;

// ── Redaction markers ─────────────────────────────────────────────────────────

pub const MARKER_REDACTED: &str = "<redacted>";
pub const MARKER_MASKED_IPV4: &str = "<masked-ipv4>";
pub const MARKER_MASKED_PATH: &str = "<masked-path>";
pub const MARKER_DIAGNOSTIC_REQUIRED: &str = "<diagnostic-mode-required>";
pub const MARKER_PRIVATE_IPV4: &str = "<private-ipv4>";
pub const MARKER_PUBLIC_IPV4: &str = "<public-ipv4>";

// ── Redacted<T> ───────────────────────────────────────────────────────────────

/// A value that may be hidden based on the active redaction mode.
///
/// At `Default` mode sensitive fields are `Hidden(marker)`; at `Diagnostics`+
/// the actual `Value(v)` is provided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Redacted<T> {
    /// The value is available at the current redaction level.
    Value(T),
    /// The value is intentionally hidden; the marker explains why.
    Hidden(String),
}

impl<T> Redacted<T> {
    /// Returns `true` if the value is hidden.
    #[must_use]
    pub fn is_hidden(&self) -> bool {
        matches!(self, Self::Hidden(_))
    }

    /// Returns the marker string if hidden, `None` if the value is available.
    #[must_use]
    pub fn marker(&self) -> Option<&str> {
        match self {
            Self::Hidden(m) => Some(m.as_str()),
            Self::Value(_) => None,
        }
    }

    /// Converts to `Option<T>`, returning `None` for hidden values.
    pub fn into_option(self) -> Option<T> {
        match self {
            Self::Value(v) => Some(v),
            Self::Hidden(_) => None,
        }
    }
}

impl<T: std::fmt::Display> Redacted<T> {
    /// Returns the value as a display string, or the redaction marker.
    #[must_use]
    pub fn display_or_marker(&self) -> String {
        match self {
            Self::Value(v) => v.to_string(),
            Self::Hidden(m) => m.clone(),
        }
    }
}

// ── Hostname redaction ────────────────────────────────────────────────────────

/// Redacts a hostname according to `mode`.
///
/// | Mode          | Output                          |
/// |---------------|---------------------------------|
/// | `Default`     | eTLD+1 (e.g., `"example.com"`) |
/// | `Diagnostics` | Full hostname                  |
/// | `DeveloperLocal` | Full hostname               |
///
/// If the hostname cannot be parsed, returns `<redacted>` in Default mode.
#[must_use]
pub fn redact_hostname(hostname: &str, mode: RedactionMode) -> Redacted<String> {
    if mode.shows_full_hostname() {
        return Redacted::Value(hostname.to_string());
    }
    // Default: extract eTLD+1 (simplistic: last two labels).
    let etld1 = extract_etld1(hostname);
    match etld1 {
        Some(s) => Redacted::Value(s),
        None => Redacted::Hidden(MARKER_REDACTED.to_string()),
    }
}

/// Extracts a simplified eTLD+1 (last two dot-separated labels).
///
/// For example: `"updates.example.com"` → `"example.com"`.
/// IP addresses (all-numeric labels) return `None`.
fn extract_etld1(hostname: &str) -> Option<String> {
    let hostname = hostname.trim_end_matches('.');
    if hostname.is_empty() {
        return None;
    }
    // Reject bare IPs.
    if hostname.parse::<Ipv4Addr>().is_ok() {
        return None;
    }
    let labels: Vec<&str> = hostname.split('.').collect();
    if labels.len() < 2 {
        // Single-label hostname (e.g., "localhost") — show as-is.
        return Some(hostname.to_string());
    }
    let n = labels.len();
    Some(format!("{}.{}", labels[n - 2], labels[n - 1]))
}

// ── IP redaction ──────────────────────────────────────────────────────────────

/// Redacts an IPv4 address according to `mode`.
///
/// | Mode          | Output                                      |
/// |---------------|---------------------------------------------|
/// | `Default`     | `<private-ipv4>` or `<public-ipv4>`         |
/// | `Diagnostics` | Full dotted-decimal `"1.2.3.4"`             |
/// | `DeveloperLocal` | Full dotted-decimal                     |
#[must_use]
pub fn redact_ipv4(ip: Ipv4Addr, mode: RedactionMode) -> Redacted<String> {
    if mode.shows_ip() {
        return Redacted::Value(ip.to_string());
    }
    let marker = if is_private_ipv4(ip) {
        MARKER_PRIVATE_IPV4
    } else {
        MARKER_PUBLIC_IPV4
    };
    Redacted::Hidden(marker.to_string())
}

/// Redacts an IPv4 address given as a dotted-decimal string.
/// Returns `Redacted::Hidden(<redacted>)` if the string is not a valid IPv4.
#[must_use]
pub fn redact_ipv4_str(ip_str: &str, mode: RedactionMode) -> Redacted<String> {
    match ip_str.parse::<Ipv4Addr>() {
        Ok(ip) => redact_ipv4(ip, mode),
        Err(_) => Redacted::Hidden(MARKER_REDACTED.to_string()),
    }
}

fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    // RFC-1918: 10.x.x.x, 172.16-31.x.x, 192.168.x.x  |  Loopback: 127.x.x.x
    o[0] == 10
        || o[0] == 127
        || (o[0] == 172 && o[1] >= 16 && o[1] <= 31)
        || (o[0] == 192 && o[1] == 168)
}

// ── Process path redaction ────────────────────────────────────────────────────

/// Redacts a process path according to `mode`.
///
/// | Mode             | Output                                              |
/// |------------------|-----------------------------------------------------|
/// | `Default`        | Filename only (e.g., `"chrome.exe"`)                |
/// | `Diagnostics`    | Path with username/home segments masked             |
/// | `DeveloperLocal` | Full path                                           |
#[must_use]
pub fn redact_process_path(path: &str, mode: RedactionMode) -> Redacted<String> {
    if mode.shows_full_path() {
        return Redacted::Value(path.to_string());
    }
    if mode.shows_ip() {
        // Diagnostics: mask sensitive path segments.
        return Redacted::Value(mask_path_username(path));
    }
    // Default: filename only.
    let filename = extract_filename(path);
    match filename {
        Some(f) => Redacted::Value(f),
        None => Redacted::Hidden(MARKER_MASKED_PATH.to_string()),
    }
}

/// Extracts the filename (last path component) from a Windows or Unix path.
fn extract_filename(path: &str) -> Option<String> {
    // Try Windows-style separator first, then Unix.
    let name = path.rsplit(['\\', '/']).next().unwrap_or(path);
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Replaces the username/home directory segment in a path with `<masked-user>`.
///
/// Handles common Windows patterns:
/// - `C:\Users\username\...` → `C:\Users\<masked-user>\...`
/// - `C:\Documents and Settings\username\...` → `C:\Documents and Settings\<masked-user>\...`
fn mask_path_username(path: &str) -> String {
    // Case-insensitive match for Windows Users dir.
    let lower = path.to_ascii_lowercase();
    for prefix in &[r"c:\users\", r"c:\documents and settings\"] {
        if let Some(rest) = lower.strip_prefix(prefix) {
            // Find the next separator to locate the username segment end.
            let sep_pos = rest.find(['\\', '/']);
            let prefix_len = prefix.len();
            return match sep_pos {
                Some(pos) => format!(
                    "{}<masked-user>{}",
                    &path[..prefix_len],
                    &path[prefix_len + pos..]
                ),
                None => format!("{}<masked-user>", &path[..prefix_len]),
            };
        }
    }
    path.to_string()
}

// ── Adapter name redaction ────────────────────────────────────────────────────

/// Redacts an adapter name/system id according to `mode`.
///
/// | Mode          | Output                                    |
/// |---------------|-------------------------------------------|
/// | `Default`     | User label (if provided) or shortened id  |
/// | `Diagnostics` | Full technical adapter identifier         |
#[must_use]
pub fn redact_adapter_id(
    technical_id: &str,
    user_label: Option<&str>,
    mode: RedactionMode,
) -> Redacted<String> {
    if mode.shows_full_hostname() {
        return Redacted::Value(technical_id.to_string());
    }
    // Default: show user label or first 8 chars of technical id.
    match user_label {
        Some(label) if !label.is_empty() => Redacted::Value(label.to_string()),
        _ => {
            let shortened = if technical_id.len() > 8 {
                format!("{}...", &technical_id[..8])
            } else {
                technical_id.to_string()
            };
            Redacted::Value(shortened)
        }
    }
}

// ── Resolver/source metadata redaction ───────────────────────────────────────

/// Redacts resolver/source detail according to `mode`.
///
/// | Mode          | Output              |
/// |---------------|---------------------|
/// | `Default`     | Category label only |
/// | `Diagnostics` | Source detail       |
#[must_use]
pub fn redact_resolver_source(
    category: &str,
    detail: Option<&str>,
    mode: RedactionMode,
) -> Redacted<String> {
    if mode.shows_full_hostname() {
        match detail {
            Some(d) => Redacted::Value(d.to_string()),
            None => Redacted::Value(category.to_string()),
        }
    } else {
        Redacted::Value(category.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Redacted<T> ──────────────────────────────────────────────────────────

    #[test]
    fn redacted_value_not_hidden() {
        let r: Redacted<String> = Redacted::Value("hello".into());
        assert!(!r.is_hidden());
        assert!(r.marker().is_none());
    }

    #[test]
    fn redacted_hidden_has_marker() {
        let r: Redacted<String> = Redacted::Hidden(MARKER_REDACTED.into());
        assert!(r.is_hidden());
        assert_eq!(r.marker(), Some(MARKER_REDACTED));
    }

    #[test]
    fn redacted_display_or_marker() {
        let value: Redacted<u32> = Redacted::Value(42);
        assert_eq!(value.display_or_marker(), "42");
        let hidden: Redacted<u32> = Redacted::Hidden(MARKER_REDACTED.into());
        assert_eq!(hidden.display_or_marker(), MARKER_REDACTED);
    }

    // ── Hostname redaction ────────────────────────────────────────────────────

    #[test]
    fn hostname_default_shows_etld1() {
        let r = redact_hostname("updates.example.com", RedactionMode::Default);
        assert_eq!(r, Redacted::Value("example.com".into()));
    }

    #[test]
    fn hostname_default_single_label() {
        let r = redact_hostname("localhost", RedactionMode::Default);
        assert_eq!(r, Redacted::Value("localhost".into()));
    }

    #[test]
    fn hostname_diagnostics_shows_full() {
        let r = redact_hostname("updates.example.com", RedactionMode::Diagnostics);
        assert_eq!(r, Redacted::Value("updates.example.com".into()));
    }

    #[test]
    fn hostname_default_rejects_raw_ip() {
        let r = redact_hostname("192.168.1.1", RedactionMode::Default);
        assert!(r.is_hidden());
    }

    #[test]
    fn hostname_trailing_dot_stripped() {
        let r = redact_hostname("updates.example.com.", RedactionMode::Default);
        assert_eq!(r, Redacted::Value("example.com".into()));
    }

    // ── IP redaction ──────────────────────────────────────────────────────────

    #[test]
    fn ip_default_private_returns_marker() {
        let r = redact_ipv4("192.168.1.100".parse().unwrap(), RedactionMode::Default);
        assert_eq!(r, Redacted::Hidden(MARKER_PRIVATE_IPV4.into()));
    }

    #[test]
    fn ip_default_public_returns_marker() {
        let r = redact_ipv4("8.8.8.8".parse().unwrap(), RedactionMode::Default);
        assert_eq!(r, Redacted::Hidden(MARKER_PUBLIC_IPV4.into()));
    }

    #[test]
    fn ip_diagnostics_shows_full() {
        let r = redact_ipv4("8.8.8.8".parse().unwrap(), RedactionMode::Diagnostics);
        assert_eq!(r, Redacted::Value("8.8.8.8".into()));
    }

    #[test]
    fn ip_str_invalid_returns_redacted() {
        let r = redact_ipv4_str("not-an-ip", RedactionMode::Default);
        assert!(r.is_hidden());
    }

    #[test]
    fn private_ipv4_detection() {
        assert!(is_private_ipv4("10.0.0.1".parse().unwrap()));
        assert!(is_private_ipv4("172.16.0.1".parse().unwrap()));
        assert!(is_private_ipv4("192.168.0.1".parse().unwrap()));
        assert!(is_private_ipv4("127.0.0.1".parse().unwrap()));
        assert!(!is_private_ipv4("8.8.8.8".parse().unwrap()));
        assert!(!is_private_ipv4("1.1.1.1".parse().unwrap()));
    }

    // ── Process path redaction ────────────────────────────────────────────────

    #[test]
    fn process_path_default_shows_filename() {
        let r = redact_process_path(r"C:\Users\john\AppData\chrome.exe", RedactionMode::Default);
        assert_eq!(r, Redacted::Value("chrome.exe".into()));
    }

    #[test]
    fn process_path_diagnostics_masks_username() {
        let r = redact_process_path(
            r"C:\Users\john\AppData\chrome.exe",
            RedactionMode::Diagnostics,
        );
        let s = r.into_option().unwrap();
        assert!(s.contains("<masked-user>"), "username must be masked: {s}");
        assert!(s.contains("chrome.exe"), "filename must be present: {s}");
        assert!(!s.contains("john"), "actual username must not appear: {s}");
    }

    #[test]
    fn process_path_developer_local_shows_full() {
        let path = r"C:\Users\john\AppData\chrome.exe";
        let r = redact_process_path(path, RedactionMode::DeveloperLocal);
        assert_eq!(r, Redacted::Value(path.into()));
    }

    #[test]
    fn process_path_unix_default() {
        let r = redact_process_path("/usr/bin/firefox", RedactionMode::Default);
        assert_eq!(r, Redacted::Value("firefox".into()));
    }

    // ── Adapter id redaction ──────────────────────────────────────────────────

    #[test]
    fn adapter_default_shows_user_label() {
        let r = redact_adapter_id("{GUID-abc}", Some("Wi-Fi"), RedactionMode::Default);
        assert_eq!(r, Redacted::Value("Wi-Fi".into()));
    }

    #[test]
    fn adapter_default_shortens_technical_id_when_no_label() {
        let r = redact_adapter_id("{GUID-abc-very-long}", None, RedactionMode::Default);
        let s = r.into_option().unwrap();
        assert!(s.ends_with("..."), "long id must be shortened: {s}");
    }

    #[test]
    fn adapter_diagnostics_shows_technical_id() {
        let r = redact_adapter_id("{GUID-abc}", Some("Wi-Fi"), RedactionMode::Diagnostics);
        assert_eq!(r, Redacted::Value("{GUID-abc}".into()));
    }

    // ── Resolver source redaction ─────────────────────────────────────────────

    #[test]
    fn resolver_default_shows_category() {
        let r = redact_resolver_source("dns", Some("8.8.8.8:53"), RedactionMode::Default);
        assert_eq!(r, Redacted::Value("dns".into()));
    }

    #[test]
    fn resolver_diagnostics_shows_detail() {
        let r = redact_resolver_source("dns", Some("8.8.8.8:53"), RedactionMode::Diagnostics);
        assert_eq!(r, Redacted::Value("8.8.8.8:53".into()));
    }

    // ── Golden test: same data → same output regardless of path ──────────────

    #[test]
    fn golden_hostname_redaction_consistent() {
        let hostname = "secure.bank.example.com";
        let default_result = redact_hostname(hostname, RedactionMode::Default);
        let diag_result = redact_hostname(hostname, RedactionMode::Diagnostics);

        // Default should show eTLD+1 consistently
        assert_eq!(default_result, Redacted::Value("example.com".into()));
        // Diagnostics should show full consistently
        assert_eq!(diag_result, Redacted::Value(hostname.into()));

        // Same input always produces same output (determinism)
        let r1 = redact_hostname(hostname, RedactionMode::Default);
        let r2 = redact_hostname(hostname, RedactionMode::Default);
        assert_eq!(r1, r2);
    }

    #[test]
    fn golden_ip_redaction_consistent() {
        let ip: Ipv4Addr = "192.168.1.100".parse().unwrap();
        let r1 = redact_ipv4(ip, RedactionMode::Default);
        let r2 = redact_ipv4(ip, RedactionMode::Default);
        assert_eq!(r1, r2, "redaction must be deterministic");

        // Default hides, Diagnostics reveals — consistently
        assert!(redact_ipv4(ip, RedactionMode::Default).is_hidden());
        assert!(!redact_ipv4(ip, RedactionMode::Diagnostics).is_hidden());
    }

    #[test]
    fn markers_are_stable_strings() {
        assert_eq!(MARKER_REDACTED, "<redacted>");
        assert_eq!(MARKER_MASKED_IPV4, "<masked-ipv4>");
        assert_eq!(MARKER_MASKED_PATH, "<masked-path>");
        assert_eq!(MARKER_DIAGNOSTIC_REQUIRED, "<diagnostic-mode-required>");
        assert_eq!(MARKER_PRIVATE_IPV4, "<private-ipv4>");
        assert_eq!(MARKER_PUBLIC_IPV4, "<public-ipv4>");
    }
}
