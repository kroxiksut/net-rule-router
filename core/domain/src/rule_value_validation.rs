//! The per-row verdict on a rule's `match_value` for one rule type — the
//! badge the rules table shows and the gate of the Add/Edit rule dialog.
//!
//! Consumers: the service's rule rows (`RuleRowEntry::validation_status`) and
//! its acceptance of a revision, the launcher's preset-import rows and its
//! `local.rule-value-verdict` answer to the dialog, and the GUI preview snapshot.
//!
//! Every value is judged by the rule pipeline itself (`validation`'s
//! `canonical_host_name`, `canonical_ip_address`, `canonical_app_pattern`), so
//! what shows as valid is exactly what the service keeps as a live rule, and
//! the service refuses a new revision by the same verdict
//! ([`rules_with_refused_values`]). The validator is pure: no I/O, no DNS.
//!
//! # Diagnostic shape
//!
//! Each non-`Valid` outcome carries a localisation key (e.g.
//! `"rules.validation.match-value-invalid.exact-ip"`) plus an optional
//! arguments map (e.g. `{"octet": "300", "position": "1"}`). The GUI
//! resolves the key against the active locale and substitutes args.
//! Domain code never produces user-facing strings.

use std::collections::{BTreeMap, HashSet};

use nrr_shared::rules_json::{AddressMatchDto, AppPatternDto, CanonicalRulesJsonV1, RuleDto};

use crate::address_class::AddressClass;
use crate::ip_network_policy::IpValueKind;
use crate::rules_file::HostPlatform;
use crate::rules_json_codec::wire_app_pattern;
use crate::validation::{
    canonical_app_pattern, canonical_host_name, canonical_ip_address, canonical_ip_range,
    canonical_subnet, HostNameKind, ValidationError, ValidationWarning,
};
use crate::RuleId;

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
/// `rule_type_slug` is one of `"zone" | "domain" | "exact-ip" | "subnet" |
/// "ip-range" | "application"`. Unknown slugs return [`RuleValueValidation::Error`]
/// with key `rules.validation.unknown-rule-type` so callers don't silently
/// drop misconfigured snapshots.
pub fn validate_rule_value(rule_type_slug: &str, match_value: &str) -> RuleValueValidation {
    let trimmed = match_value.trim();
    if trimmed.is_empty() {
        return RuleValueValidation::error("rules.validation.match-value-empty");
    }
    match rule_type_slug {
        "zone" => validate_host_name(HostNameKind::Zone, trimmed),
        "domain" => validate_host_name(HostNameKind::Domain, trimmed),
        "exact-ip" => validate_exact_ip(trimmed),
        "subnet" => validate_network(trimmed, |value, warnings| {
            canonical_subnet(value, &RuleId(String::new()), warnings).map(drop)
        }),
        "ip-range" => validate_network(trimmed, |value, warnings| {
            canonical_ip_range(value, &RuleId(String::new()), warnings).map(drop)
        }),
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

/// The pipeline's verdict on an address, warnings included: the address class
/// is judged there, once.
fn validate_exact_ip(value: &str) -> RuleValueValidation {
    let mut warnings = Vec::new();
    match canonical_ip_address(value, &RuleId(String::new()), &mut warnings) {
        Ok(_) => {}
        Err(ValidationError::IpAddressNotADestination { class, .. }) => {
            return RuleValueValidation::error(match class {
                AddressClass::Broadcast => {
                    "rules.validation.match-value-invalid.exact-ip-broadcast"
                }
                _ => "rules.validation.match-value-invalid.exact-ip-this-host",
            });
        }
        Err(ValidationError::WrongAddressSection { belongs_in, .. }) => {
            return wrong_kind(belongs_in)
        }
        Err(_) => return exact_ip_refusal(value),
    }
    let class = warnings.iter().find_map(|w| match w {
        ValidationWarning::UnusualIpDestination { class, .. } => Some(*class),
        _ => None,
    });
    match class {
        Some(AddressClass::Loopback) => {
            RuleValueValidation::warning("rules.validation.match-value-warning.exact-ip-loopback")
        }
        Some(AddressClass::Multicast) => {
            RuleValueValidation::warning("rules.validation.match-value-warning.exact-ip-multicast")
        }
        Some(AddressClass::LinkLocal) => {
            RuleValueValidation::warning("rules.validation.match-value-warning.exact-ip-link-local")
        }
        Some(_) | None => RuleValueValidation::Valid,
    }
}

/// The most specific existing wording for a refused address: a dotted quad
/// with an octet past 255 names that octet.
fn exact_ip_refusal(value: &str) -> RuleValueValidation {
    let parts: Vec<&str> = value.split('.').collect();
    let dotted_digits = parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    if dotted_digits {
        if let Some((i, part)) = parts
            .iter()
            .enumerate()
            .find(|(_, p)| p.parse::<u32>().map_or(true, |n| n > 255))
        {
            let mut args = BTreeMap::new();
            args.insert("octet".to_string(), (*part).to_string());
            args.insert("position".to_string(), (i + 1).to_string());
            return RuleValueValidation::Error {
                message_key: "rules.validation.match-value-invalid.exact-ip-octet-out-of-range"
                    .to_string(),
                args,
            };
        }
    }
    RuleValueValidation::error("rules.validation.match-value-invalid.exact-ip")
}

/// The value is another kind of address: name the type it belongs to.
fn wrong_kind(belongs_in: IpValueKind) -> RuleValueValidation {
    RuleValueValidation::error(match belongs_in {
        IpValueKind::Address => "rules.validation.match-value-invalid.is-exact-ip",
        IpValueKind::Subnet => "rules.validation.match-value-invalid.is-subnet",
        IpValueKind::Range => "rules.validation.match-value-invalid.is-ip-range",
    })
}

// ── subnet / ip-range ─────────────────────────────────────────────────────────

/// The pipeline's verdict on a network or a range, warnings included.
fn validate_network(
    value: &str,
    canonical: impl FnOnce(&str, &mut Vec<ValidationWarning>) -> Result<(), ValidationError>,
) -> RuleValueValidation {
    let mut warnings = Vec::new();
    match canonical(value, &mut warnings) {
        Ok(()) => {}
        Err(ValidationError::WrongAddressSection { belongs_in, .. }) => {
            return wrong_kind(belongs_in)
        }
        Err(ValidationError::InvalidSubnet { .. }) => {
            return RuleValueValidation::error("rules.validation.match-value-invalid.subnet")
        }
        Err(ValidationError::NetworkTooWide { widest_prefix, .. }) => {
            return RuleValueValidation::Error {
                message_key: "rules.validation.match-value-invalid.network-too-wide".to_string(),
                args: prefix_arg(widest_prefix),
            }
        }
        Err(ValidationError::NetworkCoversReserved { .. }) => {
            return RuleValueValidation::error(
                "rules.validation.match-value-invalid.network-reserved",
            )
        }
        Err(_) => {
            return RuleValueValidation::error("rules.validation.match-value-invalid.ip-range")
        }
    }
    let wide = warnings.iter().find_map(|w| match w {
        ValidationWarning::WideNetwork {
            public,
            widest_prefix,
            ..
        } => Some((*public, *widest_prefix)),
        _ => None,
    });
    if let Some((public, widest_prefix)) = wide {
        return RuleValueValidation::Warning {
            message_key: if public {
                "rules.validation.match-value-warning.network-wide-public"
            } else {
                "rules.validation.match-value-warning.network-wide"
            }
            .to_string(),
            args: prefix_arg(widest_prefix),
        };
    }
    for warning in &warnings {
        match warning {
            ValidationWarning::SubnetHostBitsCleared { normalized, .. } => {
                let mut args = BTreeMap::new();
                args.insert("network".to_string(), normalized.clone());
                return RuleValueValidation::Warning {
                    message_key: "rules.validation.match-value-warning.subnet-host-bits"
                        .to_string(),
                    args,
                };
            }
            ValidationWarning::UnusualIpDestination { .. } => {
                return RuleValueValidation::warning(
                    "rules.validation.match-value-warning.exact-ip-link-local",
                )
            }
            _ => {}
        }
    }
    RuleValueValidation::Valid
}

fn prefix_arg(prefix: u8) -> BTreeMap<String, String> {
    BTreeMap::from([("prefix".to_string(), prefix.to_string())])
}

// ── zone / domain ─────────────────────────────────────────────────────────────

/// A zone or domain gets the rule pipeline's own verdict, so what shows as
/// valid is exactly what the service keeps as a live rule.
fn validate_host_name(kind: HostNameKind, value: &str) -> RuleValueValidation {
    // A domain value carries its suffix form the way the rules file does.
    let body = match kind {
        HostNameKind::Domain => value.strip_prefix("*.").unwrap_or(value),
        HostNameKind::Zone => value,
    };
    match canonical_host_name(kind, body, &RuleId(String::new()), &mut Vec::new()) {
        Ok(_) => RuleValueValidation::Valid,
        Err(refusal) => RuleValueValidation::error(refusal_message_key(kind, body, &refusal)),
    }
}

/// The most specific existing wording for a refusal; the verdict itself is
/// the pipeline's.
fn refusal_message_key(kind: HostNameKind, body: &str, refusal: &ValidationError) -> &'static str {
    if kind == HostNameKind::Zone {
        return "rules.validation.match-value-invalid.zone";
    }
    if body.contains('*') {
        return "rules.validation.match-value-invalid.domain-glob-position";
    }
    // The refused ASCII form when there is one; IDNA may give up on a long
    // name before producing it.
    let too_long = match refusal {
        ValidationError::DomainInvalidValue { value, .. } => value.len() > MAX_HOSTNAME_OCTETS,
        _ => body.len() > MAX_HOSTNAME_OCTETS,
    };
    if too_long {
        "rules.validation.match-value-invalid.domain-too-long"
    } else {
        "rules.validation.match-value-invalid.domain"
    }
}

/// RFC 1035 limits, on the ASCII form the wire carries: the whole name without
/// its trailing dot, and one label. Every check of a host name reads these.
pub(crate) const MAX_HOSTNAME_OCTETS: usize = 253;
pub(crate) const MAX_LABEL_OCTETS: usize = 63;

/// One or more dot-separated DNS labels, IDNA-aware: ASCII names take the
/// per-label LDH check, anything else must pass UTS-46 ([`idna::domain_to_ascii`]),
/// since combining-mark scripts (Tamil, Devanagari) fail a per-`char` test.
/// Length of the whole name is the caller's check.
pub(crate) fn is_valid_hostname(host: &str) -> bool {
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
    if label.is_empty() || label.len() > MAX_LABEL_OCTETS {
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

/// The pipeline's verdict on an application value, written as a pattern when
/// it carries a `*` — the way the rules file reads it.
fn validate_application(value: &str) -> RuleValueValidation {
    match canonical_app_pattern(
        value,
        value.contains('*'),
        HostPlatform::compiled().executable_naming(),
        &RuleId(String::new()),
        &mut Vec::new(),
    ) {
        Ok(_) => RuleValueValidation::Valid,
        Err(_) => RuleValueValidation::error("rules.validation.match-value-invalid.application"),
    }
}

// ── a revision's rules ────────────────────────────────────────────────────────

/// Every value a wire rule carries, as `(rule type, value)` the way the rules
/// table shows it: the address first, then the application.
pub fn wire_rule_values(rule: &RuleDto) -> impl Iterator<Item = (&'static str, String)> + '_ {
    let address = rule.address_match.as_ref().map(|m| match m {
        AddressMatchDto::ExactFqdn { value } => ("domain", value.clone()),
        AddressMatchDto::SuffixDomain { suffix } => ("domain", format!("*.{suffix}")),
        AddressMatchDto::Zone { name } => ("zone", name.clone()),
        AddressMatchDto::ExactIpv4 { address } | AddressMatchDto::ExactIpv6 { address } => {
            ("exact-ip", address.clone())
        }
        AddressMatchDto::Subnet { network } => ("subnet", network.clone()),
        AddressMatchDto::IpRange { first, last } => ("ip-range", format!("{first}-{last}")),
        // Kept for a newer build, never judged by this one.
        AddressMatchDto::Unrecognized(_) => ("", String::new()),
    });
    let address = address.filter(|(kind, _)| !kind.is_empty());
    let app = rule.app_match.as_ref().map(|m| match &m.pattern {
        AppPatternDto::Exact { value } | AppPatternDto::Glob { value } => {
            ("application", value.clone())
        }
    });
    address.into_iter().chain(app)
}

/// A rule the per-row verdict refuses, with the value as the rules table
/// shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefusedRuleValue {
    pub rule_id: String,
    pub value: String,
}

/// The rules in `book` whose value the per-row verdict refuses, in book order.
/// A value `carried` (the book in force) already holds is spared: a stored book
/// written before the check must stay editable, and refusing it would also stop
/// every automatic edit of that book. A rule refused outright is never spared:
/// reading the book in force drops it ([`drop_rules_refused_outright`]).
pub fn rules_with_refused_values(
    book: &CanonicalRulesJsonV1,
    carried: Option<&CanonicalRulesJsonV1>,
) -> Vec<RefusedRuleValue> {
    let held: HashSet<(&'static str, String)> = carried
        .into_iter()
        .flat_map(|c| c.primary.iter().chain(&c.secondary))
        .filter(|rule| refused_outright(rule).is_none())
        .flat_map(wire_rule_values)
        .collect();
    book.primary
        .iter()
        .chain(&book.secondary)
        .filter_map(|rule| {
            wire_rule_values(rule)
                .find(|entry| {
                    validate_rule_value(entry.0, &entry.1).is_error() && !held.contains(entry)
                })
                .map(|(_, value)| RefusedRuleValue {
                    rule_id: rule.id.clone(),
                    value,
                })
        })
        .collect()
}

/// Removes from a stored `book` every rule no book may hold and returns them,
/// in book order: an address that is never a destination ("this host", the
/// limited broadcast), or an application value the pipeline refuses (too long,
/// a control character, the bare `*`). Such a rule is refused anew everywhere;
/// one already stored is gone once read, and the rest of the book loads.
pub fn drop_rules_refused_outright(book: &mut CanonicalRulesJsonV1) -> Vec<RefusedRuleValue> {
    let mut dropped = Vec::new();
    for rules in [&mut book.primary, &mut book.secondary] {
        rules.retain(|rule| match refused_outright(rule) {
            None => true,
            Some(value) => {
                dropped.push(RefusedRuleValue {
                    rule_id: rule.id.clone(),
                    value,
                });
                false
            }
        });
    }
    dropped
}

/// The value that puts `rule` beyond any book, as the rules table shows it.
fn refused_outright(rule: &RuleDto) -> Option<String> {
    let no_rule = RuleId(String::new());
    match &rule.address_match {
        Some(AddressMatchDto::ExactIpv4 { address } | AddressMatchDto::ExactIpv6 { address }) => {
            if matches!(
                canonical_ip_address(address, &no_rule, &mut Vec::new()),
                Err(ValidationError::IpAddressNotADestination { .. })
            ) {
                return Some(address.clone());
            }
        }
        Some(AddressMatchDto::Subnet { network }) => {
            if matches!(
                canonical_subnet(network, &no_rule, &mut Vec::new()),
                Err(ValidationError::NetworkCoversReserved { .. })
            ) {
                return Some(network.clone());
            }
        }
        Some(AddressMatchDto::IpRange { first, last }) => {
            let value = format!("{first}-{last}");
            if matches!(
                canonical_ip_range(&value, &no_rule, &mut Vec::new()),
                Err(ValidationError::NetworkCoversReserved { .. })
            ) {
                return Some(value);
            }
        }
        _ => {}
    }
    let app = rule.app_match.as_ref()?;
    // The refusal does not depend on the platform's spelling of names.
    wire_app_pattern(
        &app.pattern,
        HostPlatform::compiled().executable_naming(),
        &no_rule,
    )
    .is_err()
    .then(|| match &app.pattern {
        AppPatternDto::Exact { value } | AppPatternDto::Glob { value } => value.clone(),
    })
}

// ── network domain ────────────────────────────────────────────────────────────

/// The domain a user names for completing short names, in the form it is
/// stored and queried: lower case, no surrounding dots. `None` when `raw` is
/// not a usable domain. ASCII only — it goes into a DNS question as typed.
pub fn normalize_network_domain(raw: &str) -> Option<String> {
    let domain = raw.trim().trim_matches('.').to_ascii_lowercase();
    (!domain.is_empty()
        && domain.is_ascii()
        && domain.len() <= MAX_HOSTNAME_OCTETS
        && is_valid_hostname(&domain))
    .then_some(domain)
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_network_domain_is_stored_in_one_form() {
        assert_eq!(
            normalize_network_domain(" .Corp.Example. ").as_deref(),
            Some("corp.example")
        );
        assert_eq!(normalize_network_domain("corp").as_deref(), Some("corp"));
        for bad in [
            "",
            "..",
            "corp..example",
            "-corp.example",
            "corp example",
            "пример.рф",
        ] {
            assert_eq!(normalize_network_domain(bad), None, "{bad:?}");
        }
    }

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
        ok("exact-ip", "198.51.100.4");
        ok("exact-ip", "192.168.1.1");
        ok("exact-ip", "203.0.113.7");
        ok("exact-ip", "198.51.100.8");
        ok("exact-ip", "100.64.0.1");
    }

    #[test]
    fn an_address_that_is_never_a_destination_is_refused() {
        for ip in [
            "0.0.0.0",
            "0.1.2.3",
            "0.255.255.255",
            "::",
            "::ffff:0.0.0.0",
        ] {
            err("exact-ip", ip, "exact-ip-this-host");
        }
        err("exact-ip", "255.255.255.255", "exact-ip-broadcast");
        ok("exact-ip", "::ffff:192.0.2.1");
        ok("exact-ip", "1.0.0.1");
        warn("exact-ip", "::ffff:127.0.0.1", "loopback");
    }

    #[test]
    fn a_link_local_address_warns() {
        warn("exact-ip", "169.254.1.1", "link-local");
        warn("exact-ip", "fe80::1", "link-local");
    }

    #[test]
    fn ipv4_octet_above_255_rejected() {
        err("exact-ip", "300.1.1.1", "octet-out-of-range");
        err("exact-ip", "1.999.1.1", "octet-out-of-range");
        err("exact-ip", "1.1.1.256", "octet-out-of-range");
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
    fn an_ipv6_literal_is_an_exact_ip() {
        ok("exact-ip", "2001:db8::7");
        warn("exact-ip", "::1", "loopback");
        warn("exact-ip", "ff02::1", "multicast");
    }

    #[test]
    fn a_subnet_a_range_or_a_name_is_not_an_address() {
        err(
            "exact-ip",
            "192.168.1.0/24",
            "match-value-invalid.is-subnet",
        );
        err(
            "exact-ip",
            "10.0.0.1-10.0.0.9",
            "match-value-invalid.is-ip-range",
        );
        for value in ["abc.def", "fe80::1%3"] {
            err("exact-ip", value, "match-value-invalid.exact-ip");
        }
    }

    #[test]
    fn a_subnet_is_judged_by_its_width_and_class() {
        ok("subnet", "10.0.0.0/16");
        ok("subnet", "2001:db8::/48");
        err("subnet", "10.0.0.0/7", "network-too-wide");
        err("subnet", "127.0.0.0/16", "network-reserved");
        err("subnet", "224.0.0.0/8", "network-reserved");
        err("subnet", "10.0.0.0/33", "match-value-invalid.subnet");
        err("subnet", "192.0.2.1", "match-value-invalid.is-exact-ip");
        err(
            "subnet",
            "10.0.0.1-10.0.0.9",
            "match-value-invalid.is-ip-range",
        );
        warn("subnet", "10.0.0.0/8", "network-wide");
        warn("subnet", "8.0.0.0/12", "network-wide-public");
        warn("subnet", "10.0.2.7/24", "subnet-host-bits");
        warn("subnet", "169.254.1.0/24", "link-local");
    }

    #[test]
    fn a_range_is_judged_by_its_blocks() {
        ok("ip-range", "10.0.0.5-10.0.0.40");
        ok("ip-range", "2001:db8::1 - 2001:db8::ff");
        err(
            "ip-range",
            "10.0.0.9-10.0.0.1",
            "match-value-invalid.ip-range",
        );
        err("ip-range", "10.0.0.0-11.0.0.0", "network-too-wide");
        err("ip-range", "126.255.255.0-127.0.0.1", "network-reserved");
        err("ip-range", "10.0.0.0/24", "match-value-invalid.is-subnet");
        warn("ip-range", "10.0.0.0-10.3.255.255", "network-wide");
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
    }

    #[test]
    fn a_trailing_dot_is_the_fully_qualified_spelling() {
        ok("domain", "example.com.");
        ok("domain", "*.example.com.");
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
    fn every_spelling_of_a_zone_the_pipeline_folds_is_valid() {
        for zone in ["corp.internal", ".ru", "ru.", "*.ru", ".рф", "RU"] {
            ok("zone", zone);
        }
    }

    #[test]
    fn a_zone_the_pipeline_refuses_is_an_error() {
        err("zone", "123", "zone");
        err("zone", ".", "zone");
        err("zone", "..ru", "zone");
        err("zone", &("abcdef.".repeat(40) + "com"), "zone");
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
        // UTS-46 is lenient on label content and does no confusable
        // detection; the length and glob checks still apply to an IDN.
        // 600 bytes as typed, but one label: refused for the label, whose
        // punycode stays under 253 octets.
        let long_label = "ந".repeat(200);
        assert!(long_label.len() > 253);
        err("domain", &long_label, "match-value-invalid.domain");
        // Short as typed, longer than 253 octets once punycoded.
        let long_punycode = ["中"; 40].join(".");
        assert!(long_punycode.len() <= 253);
        err("domain", &long_punycode, "domain-too-long");
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

    /// The pipeline keeps the file name of a path, so the row does too.
    #[test]
    fn an_application_path_is_valid() {
        ok("application", "C:\\Program Files\\app.exe");
        ok("application", "/usr/bin/app");
    }

    #[test]
    fn an_application_the_pipeline_refuses_is_an_error() {
        err("application", "*", "application");
        err("application", &"a".repeat(261), "application");
        ok("application", &"a".repeat(260));
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
