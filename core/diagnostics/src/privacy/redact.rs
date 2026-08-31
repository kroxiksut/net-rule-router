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
    // Reject bare IPs — v6 as well as v4. A v6 literal has no dots, so it used
    // to fall through to the single-label branch below and be returned WHOLE by
    // the very function meant to shorten it. A bracketed literal (`[::1]`) is
    // the URL spelling of the same thing.
    let unbracketed = hostname
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(hostname);
    if unbracketed.parse::<std::net::IpAddr>().is_ok() {
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

/// Masks user-name segments in every path-like token of a free-text blob.
///
/// Captured stderr is the one section that is copied verbatim — a panic
/// message carries `C:\Users\<name>\...` and the archive's own manifest
/// promises no credential-like content. Filename-only reduction would gut a
/// backtrace, so the username is masked and the rest of the path survives.
/// `DeveloperLocal` keeps the text byte-for-byte.
#[must_use]
pub fn mask_user_paths_in_text(text: &str, mode: RedactionMode) -> String {
    if mode.shows_full_path() {
        return text.to_string();
    }
    let is_boundary =
        |c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ',' | ';' | '(' | ')');
    let mut out = String::with_capacity(text.len());
    let mut token = String::new();
    let flush = |token: &mut String, out: &mut String| {
        if token.contains('\\') || token.contains('/') {
            out.push_str(&mask_path_username(token));
        } else {
            out.push_str(token);
        }
        token.clear();
    };
    for c in text.chars() {
        if is_boundary(c) {
            flush(&mut token, &mut out);
            out.push(c);
        } else {
            token.push(c);
        }
    }
    flush(&mut token, &mut out);
    out
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
/// Matched by the home-directory MARKER segment, not by a whole prefix on one
/// drive: the two hard-coded `C:` prefixes let `D:\Users\john`, `/home/john` and
/// `\\server\home\john` through with the name intact — into the archive that gets
/// sent to support, on the platform this product is going cross to.
fn mask_path_username(path: &str) -> String {
    /// Segments after which the NEXT segment is a user name.
    const HOME_MARKERS: &[&str] = &["users", "documents and settings", "home"];
    let is_sep = |c: char| c == '\\' || c == '/';
    // Walk the segments, keeping byte offsets so the original spelling (drive
    // letter, separator flavour, case) survives verbatim around the mask.
    let mut start = 0usize;
    let mut previous: Option<&str> = None;
    let mut out = String::with_capacity(path.len());
    let mut last_copied = 0usize;
    let is_marker = |seg: &str| HOME_MARKERS.contains(&seg.to_ascii_lowercase().as_str());
    for (idx, ch) in path.char_indices() {
        if !is_sep(ch) {
            continue;
        }
        let segment = &path[start..idx];
        if previous.is_some_and(is_marker) && !segment.is_empty() {
            out.push_str(&path[last_copied..start]);
            out.push_str("<masked-user>");
            last_copied = idx;
            previous = None;
        } else if !segment.is_empty() {
            previous = Some(segment);
        }
        start = idx + ch.len_utf8();
    }
    // The path may END with the user segment (no trailing separator).
    let tail = &path[start..];
    if previous.is_some_and(is_marker) && !tail.is_empty() {
        out.push_str(&path[last_copied..start]);
        out.push_str("<masked-user>");
        return out;
    }
    out.push_str(&path[last_copied..]);
    out
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
            // By CHARACTERS, not bytes: an adapter name where a multi-byte
            // character straddles the eighth byte (`以太网 2`, a Cyrillic
            // connection name) panicked here — in a crate that denies
            // `unwrap`, on the path that builds a support archive.
            let shortened = if technical_id.chars().count() > 8 {
                let head: String = technical_id.chars().take(8).collect();
                format!("{head}...")
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

    /// The archive goes to support. A home directory on any drive, on any
    /// platform, or on a share must lose the user name — two hard-coded `C:`
    /// prefixes did not.
    #[test]
    fn a_home_directory_loses_the_user_name_wherever_it_lives() {
        let cases = [
            (r"C:\Users\john\AppData", r"C:\Users\<masked-user>\AppData"),
            (
                r"D:\Users\john\rules.txt",
                r"D:\Users\<masked-user>\rules.txt",
            ),
            (
                r"C:\Documents and Settings\john\x",
                r"C:\Documents and Settings\<masked-user>\x",
            ),
            ("/home/john/.config/nrr", "/home/<masked-user>/.config/nrr"),
            ("/Users/john/Library", "/Users/<masked-user>/Library"),
            (
                r"\\server\home\john\share",
                r"\\server\home\<masked-user>\share",
            ),
            // No trailing separator: the user segment is the last one.
            ("/home/john", "/home/<masked-user>"),
            // Nothing that looks like a home directory is left alone.
            (
                r"C:\Program Files\NetRuleRouter",
                r"C:\Program Files\NetRuleRouter",
            ),
        ];
        for (input, want) in cases {
            assert_eq!(mask_path_username(input), want, "input: {input}");
        }
    }

    /// A v6 literal has no dots, so the eTLD+1 shortener used to hand it back
    /// whole — through the very path that exists to shorten it.
    #[test]
    fn an_ipv6_literal_is_not_mistaken_for_a_single_label_hostname() {
        assert_eq!(extract_etld1("2001:db8::1"), None);
        assert_eq!(extract_etld1("[2001:db8::1]"), None);
        assert_eq!(extract_etld1("::1"), None);
        // A real single-label hostname still passes.
        assert_eq!(extract_etld1("localhost"), Some("localhost".to_string()));
    }
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
