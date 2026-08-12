//! Strict semantic validation of a rule's `match_value` for one rule type.
//!
//! This module is the single source of truth for "is this match value
//! semantically valid as a {zone, domain, exact-ip, application} rule?"
//! It is consumed by:
//!
//! - the rules-file parser pipeline (the service layer wires this on the import
//!   path so a row with a malformed IPv4 ends up flagged as
//!   [`RuleValueValidation::Error`] rather than silently coerced);
//! - the GUI preview snapshot (`apps/desktop/gui/src/ui_surface.rs`), which
//!   tags every row with a `validationStatus` for the QML red-state badge.
//!
//! The validator is **pure**: no I/O, no DNS lookups, no allocations beyond
//! the small `String` keys/args returned in the message. It encodes the
//! same rules already enforced by the QML Add-Rule dialog
//! (`apps/desktop/qml/Main.qml::isMatchValueValid`) so user input that
//! passed the dialog never produces an `Error` here, and a row imported
//! from a hand-edited file gets the same diagnosis as if the user had
//! typed it.
//!
//! # Diagnostic shape
//!
//! Each non-`Valid` outcome carries a localisation key (e.g.
//! `"rules.validation.match-value-invalid.exact-ip"`) plus an optional
//! arguments map (e.g. `{"octet": "300", "position": "1"}`). The GUI
//! resolves the key against the active locale and substitutes args.
//! Domain code never produces user-facing strings.

use std::collections::BTreeMap;

/// Result of validating a single rule's `match_value`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleValueValidation {
    /// Value is well-formed and acceptable for this rule type.
    Valid,
    /// Value is acceptable but flags a soft concern the user should see
    /// (e.g. routing `127.0.0.1` through a non-default route is unusual).
    Warning {
        message_key: String,
        args: BTreeMap<String, String>,
    },
    /// Value is rejected. The corresponding rule must be treated as
    /// inactive until corrected.
    Error {
        message_key: String,
        args: BTreeMap<String, String>,
    },
}

impl RuleValueValidation {
    /// Convenience constructor for a keyless warning.
    pub fn warning(message_key: impl Into<String>) -> Self {
        Self::Warning {
            message_key: message_key.into(),
            args: BTreeMap::new(),
        }
    }

    /// Convenience constructor for a keyless error.
    pub fn error(message_key: impl Into<String>) -> Self {
        Self::Error {
            message_key: message_key.into(),
            args: BTreeMap::new(),
        }
    }

    /// One of the three slugs the GUI uses for `validationStatus`.
    pub const fn status_slug(&self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Warning { .. } => "warning",
            Self::Error { .. } => "error",
        }
    }

    /// Localisation key for the diagnostic, or empty when `Valid`.
    pub fn message_key(&self) -> &str {
        match self {
            Self::Valid => "",
            Self::Warning { message_key, .. } | Self::Error { message_key, .. } => message_key,
        }
    }

    /// Substitution parameters for the localised message (e.g. `{octet}`,
    /// `{position}`). Empty for `Valid`.
    pub fn args(&self) -> &BTreeMap<String, String> {
        static EMPTY: std::sync::OnceLock<BTreeMap<String, String>> = std::sync::OnceLock::new();
        match self {
            Self::Valid => EMPTY.get_or_init(BTreeMap::new),
            Self::Warning { args, .. } | Self::Error { args, .. } => args,
        }
    }

    pub fn is_error(&self) -> bool {
        matches!(self, Self::Error { .. })
    }

    pub fn is_warning(&self) -> bool {
        matches!(self, Self::Warning { .. })
    }
}

/// Validate a rule's match value for the given rule-type slug.
///
/// `rule_type_slug` is one of `"zone" | "domain" | "exact-ip" |
/// "application"`. Unknown slugs return [`RuleValueValidation::Error`]
/// with key `rules.validation.unknown-rule-type` so callers don't silently
/// drop misconfigured snapshots.
pub fn validate_rule_value(rule_type_slug: &str, match_value: &str) -> RuleValueValidation {
    let trimmed = match_value.trim();
    if trimmed.is_empty() {
        return RuleValueValidation::error("rules.validation.match-value-empty");
    }
    match rule_type_slug {
        "zone" => validate_zone(trimmed),
        "domain" => validate_domain(trimmed),
        "exact-ip" => validate_exact_ip(trimmed),
        "application" => validate_application(trimmed),
        _ => {
            let mut args = BTreeMap::new();
            args.insert("slug".to_string(), rule_type_slug.to_string());
            RuleValueValidation::Error {
                message_key: "rules.validation.unknown-rule-type".to_string(),
                args,
            }
        }
    }
}

// ── exact-ip ──────────────────────────────────────────────────────────────────

fn validate_exact_ip(value: &str) -> RuleValueValidation {
    // Reject anything that is not exactly four dot-separated decimal octets.
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 4 {
        return RuleValueValidation::error("rules.validation.match-value-invalid.exact-ip");
    }
    let mut octets = [0u16; 4];
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() || part.len() > 3 {
            return RuleValueValidation::error("rules.validation.match-value-invalid.exact-ip");
        }
        if !part.bytes().all(|b| b.is_ascii_digit()) {
            return RuleValueValidation::error("rules.validation.match-value-invalid.exact-ip");
        }
        // Disallow leading zeros (except a single "0") to avoid the
        // octal-vs-decimal trap on tools that interpret "010" as 8.
        if part.len() > 1 && part.starts_with('0') {
            return RuleValueValidation::error("rules.validation.match-value-invalid.exact-ip");
        }
        let n: u16 = part.parse().unwrap_or(u16::MAX);
        if n > 255 {
            let mut args = BTreeMap::new();
            args.insert("octet".to_string(), (*part).to_string());
            args.insert("position".to_string(), (i + 1).to_string());
            return RuleValueValidation::Error {
                message_key: "rules.validation.match-value-invalid.exact-ip-octet-out-of-range"
                    .to_string(),
                args,
            };
        }
        octets[i] = n;
    }
    // First octet of zero (0.x.x.x) is the "this network" range — never a
    // sensible routing target.
    if octets[0] == 0 {
        return RuleValueValidation::error(
            "rules.validation.match-value-invalid.exact-ip-first-octet-zero",
        );
    }
    // 255.255.255.255 — limited broadcast. Routing it doesn't make sense.
    if octets == [255, 255, 255, 255] {
        return RuleValueValidation::error(
            "rules.validation.match-value-invalid.exact-ip-broadcast",
        );
    }
    // Soft warnings for ranges that are technically valid but unusual to
    // see in a routing rule.
    if octets[0] == 127 {
        return RuleValueValidation::warning(
            "rules.validation.match-value-warning.exact-ip-loopback",
        );
    }
    if octets[0] >= 224 && octets[0] <= 239 {
        return RuleValueValidation::warning(
            "rules.validation.match-value-warning.exact-ip-multicast",
        );
    }
    RuleValueValidation::Valid
}

// ── domain ────────────────────────────────────────────────────────────────────

fn validate_domain(value: &str) -> RuleValueValidation {
    // Optional `*.` glob prefix for suffix matches; everything after must
    // be a valid FQDN.
    let stripped = value.strip_prefix("*.").unwrap_or(value);
    if value.starts_with("*.") && stripped.is_empty() {
        return RuleValueValidation::error("rules.validation.match-value-invalid.domain");
    }
    // Total length cap from RFC 1035 (253 octets when the trailing dot is
    // omitted).
    if stripped.len() > 253 {
        return RuleValueValidation::error("rules.validation.match-value-invalid.domain-too-long");
    }
    // No interior glob beyond the leading `*.` prefix.
    if stripped.contains('*') {
        return RuleValueValidation::error(
            "rules.validation.match-value-invalid.domain-glob-position",
        );
    }
    if is_valid_hostname(stripped) {
        RuleValueValidation::Valid
    } else {
        RuleValueValidation::error("rules.validation.match-value-invalid.domain")
    }
}

// ── zone ──────────────────────────────────────────────────────────────────────

fn validate_zone(value: &str) -> RuleValueValidation {
    // The GUI dialog forbids dots in zone values to keep the canonical
    // form "ru" rather than "*.ru" or compound zones. Both bare label and
    // `*.label` are accepted by the parser per docs/en/rules-file-format.md Match value syntax, but the GUI
    // dialog stores only the bare label form.
    let normalized = value.strip_prefix("*.").unwrap_or(value);
    if normalized.is_empty() {
        return RuleValueValidation::error("rules.validation.match-value-invalid.zone");
    }
    if !is_valid_hostname(normalized) {
        return RuleValueValidation::error("rules.validation.match-value-invalid.zone");
    }
    // Compound zones like `corp.internal` are accepted by the parser but
    // not by the dialog. Treat them as a warning so the GUI shows the
    // user what's going on without rejecting the row.
    if normalized.contains('.') {
        return RuleValueValidation::warning("rules.validation.match-value-warning.zone-compound");
    }
    RuleValueValidation::Valid
}

/// Validate a hostname (one or more dot-separated DNS labels), IDNA-aware.
///
/// ASCII names take the strict per-label LDH path, preserving the exact
/// diagnostics for hyphen/length/empty-label mistakes. Names containing any
/// non-ASCII codepoint are validated as an IDN via UTS-46
/// ([`idna::domain_to_ascii`]): success means every label is a legitimate
/// internationalized label — the crate enforces the combining-mark, bidi and
/// confusable rules that a per-`char` test cannot. The value is kept in its
/// Unicode form; the codegen/cache layer punycode-encodes at the boundary
/// (see `crate::validation::normalize_domain_label`).
///
/// A naive per-`char` `is_alphanumeric` check would reject
/// Tamil/Devanagari/Arabic labels: their vowel signs and virama are combining
/// marks (Unicode categories Mn/Mc), not alphanumerics.
fn is_valid_hostname(host: &str) -> bool {
    if host.is_ascii() {
        host.split('.').all(is_valid_ascii_dns_label)
    } else {
        idna::domain_to_ascii(host).is_ok()
    }
}

/// Validate a single **ASCII** DNS label: 1..=63 chars, letter-digit-hyphen
/// (plus underscore, widely tolerated for internal corp zones), not starting
/// or ending with a hyphen, not empty (which also catches consecutive dots).
/// Non-ASCII labels are handled by IDNA in [`is_valid_hostname`].
fn is_valid_ascii_dns_label(label: &str) -> bool {
    if label.is_empty() || label.len() > 63 {
        return false;
    }
    if label.starts_with('-') || label.ends_with('-') {
        return false;
    }
    label
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

// ── application ───────────────────────────────────────────────────────────────

fn validate_application(value: &str) -> RuleValueValidation {
    // Accept any non-empty filename or glob that does not contain
    // Windows-illegal characters or ASCII control codes. The actual
    // platform-specific match (windows .exe, linux process name, macos
    // bundle id) happens at decision time, not at validation.
    if value.len() > 260 {
        return RuleValueValidation::error("rules.validation.match-value-invalid.application");
    }
    for c in value.chars() {
        if matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?') {
            return RuleValueValidation::error("rules.validation.match-value-invalid.application");
        }
        if (c as u32) < 0x20 {
            return RuleValueValidation::error("rules.validation.match-value-invalid.application");
        }
    }
    RuleValueValidation::Valid
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(rule_type: &str, value: &str) {
        let r = validate_rule_value(rule_type, value);
        assert_eq!(
            r,
            RuleValueValidation::Valid,
            "expected Valid for {rule_type}/{value:?}, got {r:?}"
        );
    }

    fn err(rule_type: &str, value: &str, key_suffix: &str) {
        let r = validate_rule_value(rule_type, value);
        match &r {
            RuleValueValidation::Error { message_key, .. } => {
                assert!(
                    message_key.contains(key_suffix),
                    "expected error key to contain {key_suffix:?}, got {message_key:?}"
                );
            }
            other => panic!("expected Error for {rule_type}/{value:?}, got {other:?}"),
        }
    }

    fn warn(rule_type: &str, value: &str, key_suffix: &str) {
        let r = validate_rule_value(rule_type, value);
        match &r {
            RuleValueValidation::Warning { message_key, .. } => {
                assert!(
                    message_key.contains(key_suffix),
                    "expected warning key to contain {key_suffix:?}, got {message_key:?}"
                );
            }
            other => panic!("expected Warning for {rule_type}/{value:?}, got {other:?}"),
        }
    }

    // ── exact-ip ──

    #[test]
    fn ipv4_valid_addresses() {
        ok("exact-ip", "1.2.3.4");
        ok("exact-ip", "192.168.1.1");
        ok("exact-ip", "203.0.113.7");
        ok("exact-ip", "8.8.8.8");
        ok("exact-ip", "100.64.0.1");
    }

    #[test]
    fn ipv4_first_octet_zero_rejected() {
        err("exact-ip", "0.0.0.0", "first-octet-zero");
        err("exact-ip", "0.1.2.3", "first-octet-zero");
    }

    #[test]
    fn ipv4_octet_above_255_rejected() {
        err("exact-ip", "300.1.1.1", "octet-out-of-range");
        err("exact-ip", "1.999.1.1", "octet-out-of-range");
        err("exact-ip", "1.1.1.256", "octet-out-of-range");
    }

    #[test]
    fn ipv4_broadcast_rejected() {
        err("exact-ip", "255.255.255.255", "broadcast");
    }

    #[test]
    fn ipv4_wrong_octet_count_rejected() {
        err("exact-ip", "1.2.3", "exact-ip");
        err("exact-ip", "1.2.3.4.5", "exact-ip");
        err("exact-ip", "1234", "exact-ip");
    }

    #[test]
    fn ipv4_empty_or_whitespace_octets_rejected() {
        err("exact-ip", "1..2.3", "exact-ip");
        err("exact-ip", "1.2.3.", "exact-ip");
        err("exact-ip", ".1.2.3", "exact-ip");
    }

    #[test]
    fn ipv4_leading_zero_rejected() {
        // 010.1.1.1 is ambiguous (octal vs decimal) — disallow.
        err("exact-ip", "010.1.1.1", "exact-ip");
        err("exact-ip", "1.001.1.1", "exact-ip");
    }

    #[test]
    fn ipv4_loopback_warns() {
        warn("exact-ip", "127.0.0.1", "loopback");
        warn("exact-ip", "127.255.255.254", "loopback");
    }

    #[test]
    fn ipv4_multicast_warns() {
        warn("exact-ip", "224.0.0.1", "multicast");
        warn("exact-ip", "239.255.255.250", "multicast");
    }

    #[test]
    fn ipv4_non_digit_rejected() {
        err("exact-ip", "abc.def.ghi.jkl", "exact-ip");
        err("exact-ip", "1.2.3.x", "exact-ip");
    }

    // ── domain ──

    #[test]
    fn domain_valid_addresses() {
        ok("domain", "example.com");
        ok("domain", "www.example.com");
        ok("domain", "foo.bar.baz.example.com");
        ok("domain", "*.example.com");
        ok("domain", "a-b.c");
        ok("domain", "xn--p1ai");
        // IDN passes through validation; the parser/cache layer handles
        // punycode conversion when needed.
        ok("domain", "пример.рф");
    }

    #[test]
    fn domain_too_long_rejected() {
        // Single label > 63 chars — fails the per-label check, returns
        // the generic `domain` error key.
        let label = "a".repeat(64);
        err("domain", &label, "domain");
        // > 253 chars total, but every label is short enough to pass the
        // per-label check — should hit the dedicated `domain-too-long`
        // error path. 40 × "abcdef." (7 chars each) + "com" = 283 chars.
        let very_long = "abcdef.".repeat(40) + "com";
        assert!(very_long.len() > 253);
        err("domain", &very_long, "domain-too-long");
    }

    #[test]
    fn domain_with_interior_glob_rejected() {
        err("domain", "foo.*.bar", "domain-glob-position");
        err("domain", "*example.com", "domain-glob-position");
    }

    #[test]
    fn domain_label_starting_or_ending_with_hyphen_rejected() {
        err("domain", "-example.com", "domain");
        err("domain", "example-.com", "domain");
        err("domain", "ex.-foo.com", "domain");
    }

    #[test]
    fn domain_consecutive_dots_rejected() {
        err("domain", "example..com", "domain");
        err("domain", ".example.com", "domain");
        err("domain", "example.com.", "domain");
    }

    #[test]
    fn domain_bare_glob_prefix_rejected() {
        err("domain", "*.", "domain");
    }

    // ── zone ──

    #[test]
    fn zone_single_label_valid() {
        ok("zone", "ru");
        ok("zone", "com");
        ok("zone", "corp-internal");
        ok("zone", "xn--p1ai");
        ok("zone", "рф");
    }

    #[test]
    fn zone_with_glob_prefix_valid() {
        ok("zone", "*.ru");
    }

    #[test]
    fn zone_compound_warns() {
        warn("zone", "corp.internal", "zone-compound");
    }

    #[test]
    fn zone_invalid_label_rejected() {
        err("zone", "-ru", "zone");
        err("zone", "ru-", "zone");
        err("zone", "", "match-value-empty");
        err("zone", "*.", "zone");
    }

    // ── IDN (internationalized domain names) ──

    #[test]
    fn idn_non_latin_scripts_accepted_as_zone_and_domain() {
        // Combining-mark scripts the old per-`char` `is_alphanumeric` check
        // wrongly rejected: Tamil/Devanagari vowel signs and the virama are
        // Mn/Mc (marks), not alphanumeric. UTS-46 ToASCII is the authority now.
        for v in ["இந்தியா", "भारत", "中国", "مصر", "日本"] {
            ok("zone", v);
            ok("domain", v);
        }
        // Mixed IDN label + ASCII TLD, and the glob form.
        ok("domain", "भारत.com");
        ok("domain", "*.இந்தியா");
        ok("zone", "*.中国");
    }

    #[test]
    fn idn_structural_errors_still_rejected() {
        // The structural guards still apply with non-ASCII content. (UTS-46
        // `domain_to_ascii` is deliberately lenient on the label *content* —
        // it maps away ignorable codepoints rather than erroring — and it does
        // NOT do confusable/mixed-script detection; that is out of scope for a
        // routing-rule validator. The goal here is to stop wrongly rejecting
        // valid IDN, while keeping the length/glob/empty structural checks.)
        let long = "ந".repeat(200); // 600 bytes > 253 — caught before IDNA
        assert!(long.len() > 253);
        err("domain", &long, "domain-too-long");
        // Interior glob is still rejected even with non-ASCII labels present.
        err("domain", "ந.*.ந", "domain-glob-position");
    }

    // ── application ──

    #[test]
    fn application_valid_values() {
        ok("application", "browser.exe");
        ok("application", "*vpn*.exe");
        ok("application", "script.ps1");
        ok("application", "deploy.sh");
        ok("application", "Some App.app");
        // Cyrillic process name.
        ok("application", "браузер.exe");
    }

    #[test]
    fn application_with_path_separators_rejected() {
        err("application", "C:\\Program Files\\app.exe", "application");
        err("application", "/usr/bin/app", "application");
    }

    #[test]
    fn application_with_control_chars_rejected() {
        err("application", "app\x01.exe", "application");
        err("application", "app\n.exe", "application");
    }

    // ── general ──

    #[test]
    fn unknown_rule_type_rejected() {
        let r = validate_rule_value("nonsense", "anything");
        match r {
            RuleValueValidation::Error { message_key, args } => {
                assert_eq!(message_key, "rules.validation.unknown-rule-type");
                assert_eq!(args.get("slug").map(String::as_str), Some("nonsense"));
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn empty_value_rejected_uniformly() {
        for rule_type in ["zone", "domain", "exact-ip", "application"] {
            err(rule_type, "", "match-value-empty");
            err(rule_type, "   ", "match-value-empty");
        }
    }

    #[test]
    fn status_slug_round_trips() {
        assert_eq!(RuleValueValidation::Valid.status_slug(), "valid");
        assert_eq!(RuleValueValidation::warning("k").status_slug(), "warning");
        assert_eq!(RuleValueValidation::error("k").status_slug(), "error");
    }
}
