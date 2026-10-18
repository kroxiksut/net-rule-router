//! What kind of rule a value is, read from its spelling alone.
//!
//! A section of a rules file is a type: a value whose spelling places it in
//! another section is a line error that names that section, and nothing is
//! ever re-filed on its own. The service's validation, the Add dialog's verdict
//! and both clients read this one definition; `rules.js` keeps a twin held to
//! it by `core/client-logic/tests/vectors/rule_value_class.json`.
//!
//! Only what the spelling settles is decided. One word (`telegram`, `ru`) may
//! be a zone or a program, so the section it is written in decides it. The
//! reading is a single pass over the text with no recursion, so any input
//! costs time linear in its length and nothing here can panic.

use crate::app_identity::ExecutableNaming;
use crate::preset_parser::ParsedRuleType;

/// Longest rule value, in bytes: a host name (253) or a program name fits;
/// a longer one is refused before anything reads it. An application path has
/// its own bound, [`crate::app_path::MAX_PATH_VALUE_BYTES`].
pub const MAX_RULE_VALUE_BYTES: usize = 260;

/// The kind of rule a value's spelling names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleValueClass {
    /// One address, well-formed or not: `192.0.2.7`, `300.1.1.1`, `2001:db8::7`.
    Address,
    /// `address/prefix`, the prefix in range or not.
    Subnet,
    /// `first-last`, both ends addresses.
    Range,
    /// `*.ru` or `.ru`.
    Zone,
    /// A host name of two labels or more: `example.com`.
    Host,
    /// `*.example.com`.
    HostWithSubdomains,
    /// `example.*` or `*.example.*`.
    SiteInEveryZone,
    /// `chrome.exe`, a path, or a wildcard pattern without a dot (`nord*`).
    Application,
    /// One word: a zone or a program.
    Ambiguous,
    /// Nothing the spelling settles.
    Unrecognized,
}

impl RuleValueClass {
    /// The slug the vectors and the JS twin use.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Address => "address",
            Self::Subnet => "subnet",
            Self::Range => "range",
            Self::Zone => "zone",
            Self::Host => "host",
            Self::HostWithSubdomains => "host-with-subdomains",
            Self::SiteInEveryZone => "site-in-every-zone",
            Self::Application => "application",
            Self::Ambiguous => "ambiguous",
            Self::Unrecognized => "unrecognized",
        }
    }

    /// The rule type a value of this class is written as; `None` when the
    /// spelling does not say.
    #[must_use]
    pub const fn rule_type(self) -> Option<ParsedRuleType> {
        match self {
            Self::Address => Some(ParsedRuleType::ExactIp),
            Self::Subnet => Some(ParsedRuleType::Subnet),
            Self::Range => Some(ParsedRuleType::IpRange),
            Self::Zone => Some(ParsedRuleType::Zone),
            Self::Host | Self::HostWithSubdomains | Self::SiteInEveryZone => {
                Some(ParsedRuleType::Domain)
            }
            Self::Application => Some(ParsedRuleType::Application),
            Self::Ambiguous | Self::Unrecognized => None,
        }
    }
}

/// The kind of rule `value` is, by its spelling.
#[must_use]
pub fn classify_rule_value(value: &str) -> RuleValueClass {
    let v = value.trim();
    if v.is_empty() {
        return RuleValueClass::Unrecognized;
    }
    if is_address_shaped(v) {
        return RuleValueClass::Address;
    }
    // A prefix after an address is a network, never the last part of a path.
    if let Some((head, tail)) = v.split_once('/') {
        let tail = tail.trim();
        if is_address_shaped(head.trim())
            && !tail.is_empty()
            && tail.bytes().all(|b| b.is_ascii_digit())
        {
            return RuleValueClass::Subnet;
        }
    }
    if let Some((first, last)) = v.split_once('-') {
        if is_address_shaped(first.trim()) && is_address_shaped(last.trim()) {
            return RuleValueClass::Range;
        }
    }
    if names_a_program(v) {
        return RuleValueClass::Application;
    }
    if v.contains('*') {
        return pattern_class(v);
    }
    name_class(v)
}

/// The rule type `value` belongs to when a `section` rule cannot hold it;
/// `None` when it can, or when its spelling does not say. `naming` is how the
/// platform whose application section is meant spells a program.
#[must_use]
pub fn misplaced_rule_value(
    section: ParsedRuleType,
    value: &str,
    naming: ExecutableNaming,
) -> Option<ParsedRuleType> {
    let class = classify_rule_value(value);
    if section_holds(section, class, naming) {
        None
    } else {
        class.rule_type()
    }
}

/// Whether a `section` rule can hold a value of `class`.
///
/// Zones hold compound names (`corp.internal`) and Domains hold a suffix rule
/// over one label (`*.ru` there is a domain rule of its own priority). On Linux
/// and macOS a program is called whatever its file is, dots included
/// (`org.example.app`, `deploy.sh`, `com.example.*`), so only an address, a
/// network or a subdomain pattern is out of place in their sections.
fn section_holds(section: ParsedRuleType, class: RuleValueClass, naming: ExecutableNaming) -> bool {
    use RuleValueClass as C;
    match section {
        ParsedRuleType::ExactIp | ParsedRuleType::Subnet | ParsedRuleType::IpRange => {
            class.rule_type().is_none_or(|kind| kind == section)
        }
        ParsedRuleType::Zone => !matches!(
            class,
            C::Address | C::Subnet | C::Range | C::SiteInEveryZone | C::Application
        ),
        ParsedRuleType::Domain => {
            !matches!(class, C::Address | C::Subnet | C::Range | C::Application)
        }
        ParsedRuleType::Application => match naming {
            ExecutableNaming::WindowsExe => !matches!(
                class,
                C::Address
                    | C::Subnet
                    | C::Range
                    | C::Zone
                    | C::Host
                    | C::HostWithSubdomains
                    | C::SiteInEveryZone
            ),
            ExecutableNaming::AsNamed => !matches!(
                class,
                C::Address | C::Subnet | C::Range | C::HostWithSubdomains
            ),
        },
    }
}

/// A rule-type slug of the rules table, `None` for anything else.
#[must_use]
pub fn rule_type_from_slug(slug: &str) -> Option<ParsedRuleType> {
    match slug {
        "zone" => Some(ParsedRuleType::Zone),
        "domain" => Some(ParsedRuleType::Domain),
        "exact-ip" => Some(ParsedRuleType::ExactIp),
        "subnet" => Some(ParsedRuleType::Subnet),
        "ip-range" => Some(ParsedRuleType::IpRange),
        "application" => Some(ParsedRuleType::Application),
        _ => None,
    }
}

/// The start of every "this value is a rule of another type" message key.
pub const MISPLACED_KEY_PREFIX: &str = "rules.validation.match-value-invalid.is-";

/// The message key that says a value is a `belongs_in` rule.
#[must_use]
pub const fn misplaced_message_key(belongs_in: ParsedRuleType) -> &'static str {
    match belongs_in {
        ParsedRuleType::Zone => "rules.validation.match-value-invalid.is-zone",
        ParsedRuleType::Domain => "rules.validation.match-value-invalid.is-domain",
        ParsedRuleType::ExactIp => "rules.validation.match-value-invalid.is-exact-ip",
        ParsedRuleType::Subnet => "rules.validation.match-value-invalid.is-subnet",
        ParsedRuleType::IpRange => "rules.validation.match-value-invalid.is-ip-range",
        ParsedRuleType::Application => "rules.validation.match-value-invalid.is-application",
    }
}

/// The rule type a verdict's message key says the value belongs to — what a
/// "Move to section" offer moves it to. `None` for every other key.
#[must_use]
pub fn misplaced_target_of_message_key(message_key: &str) -> Option<ParsedRuleType> {
    rule_type_from_slug(message_key.strip_prefix(MISPLACED_KEY_PREFIX)?)
}

/// An address by its characters, well-formed or not: digits and dots with a
/// dot, or hex digits, colons and dots with two colons (a zone index after
/// `%` allowed). No top-level domain is all digits, and no name has colons.
fn is_address_shaped(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    // A digit is required: a bare `.` or `..` is a broken name, not an address.
    if s.contains('.')
        && s.bytes().any(|b| b.is_ascii_digit())
        && s.bytes().all(|b| b.is_ascii_digit() || b == b'.')
    {
        return true;
    }
    let head = s.split('%').next().unwrap_or(s);
    !head.is_empty()
        && head.bytes().filter(|&b| b == b':').count() >= 2
        && head
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
}

/// A program by its spelling: the `.exe` suffix or a path.
///
/// `.exe` is the one suffix taken as a program: it is how Windows spells one
/// and no top-level domain uses it. `.app` (macOS bundles), `.sh` and `.py` are
/// real top-level domains, so `example.app` stays a host name.
fn names_a_program(v: &str) -> bool {
    let bytes = v.as_bytes();
    let exe = bytes.len() >= 4
        && bytes
            .get(bytes.len() - 4..)
            .is_some_and(|tail| tail.eq_ignore_ascii_case(b".exe"));
    let drive = matches!(bytes, [letter, b':', b'/' | b'\\', ..] if letter.is_ascii_alphabetic());
    exe || drive
        || v.contains('\\')
        || v.starts_with('/')
        || v.starts_with("./")
        || v.starts_with("../")
        || v.starts_with("~/")
}

/// A value with a `*` in it: a domain or zone pattern by its dots, a program
/// pattern when it has none.
fn pattern_class(v: &str) -> RuleValueClass {
    if v.chars().all(|c| c == '*') {
        return RuleValueClass::Unrecognized;
    }
    if let Some(rest) = v.strip_prefix("*.") {
        if let Some(base) = rest.strip_suffix(".*") {
            return match host_labels(base) {
                Some(_) => RuleValueClass::SiteInEveryZone,
                None => RuleValueClass::Unrecognized,
            };
        }
        return match host_labels(rest) {
            Some((1, last)) if tld_shaped(last) => RuleValueClass::Zone,
            Some((_, last)) if tld_shaped(last) => RuleValueClass::HostWithSubdomains,
            _ => RuleValueClass::Unrecognized,
        };
    }
    if let Some(base) = v.strip_suffix(".*") {
        return match host_labels(base) {
            Some(_) => RuleValueClass::SiteInEveryZone,
            None => RuleValueClass::Unrecognized,
        };
    }
    if v.contains('.') {
        RuleValueClass::Unrecognized
    } else {
        RuleValueClass::Application
    }
}

/// A value with no `*`, no path and no address shape.
fn name_class(v: &str) -> RuleValueClass {
    if let Some(rest) = v.strip_prefix('.') {
        return match host_labels(rest) {
            Some((1, last)) if tld_shaped(last) && !rest.ends_with('.') => RuleValueClass::Zone,
            _ => RuleValueClass::Unrecognized,
        };
    }
    let Some((count, last)) = host_labels(v) else {
        return RuleValueClass::Unrecognized;
    };
    if count == 1 {
        return RuleValueClass::Ambiguous;
    }
    // `1.2.3.x`: a dotted quad with a typo in it, not a host.
    let quad_typo = count == 4
        && v.split('.')
            .take(3)
            .all(|l| l.bytes().all(|b| b.is_ascii_digit()));
    if quad_typo {
        return RuleValueClass::Address;
    }
    if tld_shaped(last) {
        RuleValueClass::Host
    } else {
        RuleValueClass::Unrecognized
    }
}

/// The label count and the last label of a host name, one trailing dot
/// allowed; `None` when a label is empty, edged with `-`, or holds a character
/// no name carries.
fn host_labels(v: &str) -> Option<(usize, &str)> {
    let v = v.strip_suffix('.').unwrap_or(v);
    if v.is_empty() {
        return None;
    }
    let mut count = 0usize;
    let mut last = "";
    for label in v.split('.') {
        if label.is_empty()
            || label.starts_with('-')
            || label.ends_with('-')
            || !label.chars().all(is_name_char)
        {
            return None;
        }
        count += 1;
        last = label;
    }
    Some((count, last))
}

/// The last label of a host: letters only (any script), or an ACE label.
/// `ps1`, `11` and `c0m` are no top-level domain.
fn tld_shaped(label: &str) -> bool {
    label
        .get(..4)
        .is_some_and(|p| p.eq_ignore_ascii_case("xn--"))
        || label
            .chars()
            .all(|c| c.is_ascii_alphabetic() || !c.is_ascii())
}

/// A character a host-name label may carry: ASCII letters, digits, `-`, `_`,
/// or any other character but the invisible and space ones. The list is
/// explicit so the JS twin, which reads UTF-16 units, agrees character for
/// character.
fn is_name_char(c: char) -> bool {
    if c.is_ascii() {
        return c.is_ascii_alphanumeric() || c == '-' || c == '_';
    }
    !matches!(
        u32::from(c),
        0x80..=0xA0 | 0x1680 | 0x2000..=0x200F | 0x2028..=0x202F | 0x205F..=0x206F | 0x3000 | 0xFEFF
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use RuleValueClass as C;

    #[test]
    fn every_class_is_read_from_its_spelling() {
        for (value, class) in [
            ("192.0.2.7", C::Address),
            ("300.1.1.1", C::Address),
            ("1.2.3.x", C::Address),
            ("2001:db8::7", C::Address),
            ("fe80::1%3", C::Address),
            ("10.0.0.0/24", C::Subnet),
            ("10.0.0.0/33", C::Subnet),
            ("2001:db8:: / 48", C::Subnet),
            ("192.0.2.10-192.0.2.40", C::Range),
            ("192.0.2.10 - 192.0.2.40", C::Range),
            ("*.ru", C::Zone),
            (".ru", C::Zone),
            ("example.com", C::Host),
            ("example.com.", C::Host),
            ("пример.рф", C::Host),
            ("*.example.com", C::HostWithSubdomains),
            ("example.*", C::SiteInEveryZone),
            ("*.example.*", C::SiteInEveryZone),
            ("chrome.exe", C::Application),
            ("Chrome.EXE", C::Application),
            ("*vpn*.exe", C::Application),
            ("nord*", C::Application),
            ("C:\\Program Files\\app", C::Application),
            ("C:/Apps/tool", C::Application),
            ("/usr/bin/app", C::Application),
            ("telegram", C::Ambiguous),
            ("corp-internal", C::Ambiguous),
            ("ru", C::Ambiguous),
            ("script.ps1", C::Unrecognized),
            ("python3.11", C::Unrecognized),
            ("Some App.app", C::Unrecognized),
            ("foo.*.bar", C::Unrecognized),
            ("*", C::Unrecognized),
            ("", C::Unrecognized),
            ("example.com/page", C::Unrecognized),
        ] {
            assert_eq!(classify_rule_value(value), class, "{value:?}");
        }
    }

    #[test]
    fn a_value_out_of_its_section_names_the_one_it_belongs_in() {
        let win = ExecutableNaming::WindowsExe;
        let unix = ExecutableNaming::AsNamed;
        use ParsedRuleType as T;
        let t = T::Application;
        for (section, value, naming, belongs_in) in [
            (T::Domain, "chrome.exe", win, Some(t)),
            (T::Zone, "chrome.exe", win, Some(t)),
            (t, "192.0.2.7", win, Some(T::ExactIp)),
            (t, "example.com", win, Some(T::Domain)),
            (t, "10.0.0.0/24", win, Some(T::Subnet)),
            (t, "10.0.0.0/24", unix, Some(T::Subnet)),
            (t, "*.example.com", unix, Some(T::Domain)),
            (t, "org.example.app", unix, None),
            (t, "*.ru", win, Some(T::Zone)),
            (t, "*.sh", unix, None),
            (t, "telegram", win, None),
            (T::ExactIp, "example.com", win, Some(T::Domain)),
            (T::Subnet, "example.com", win, Some(T::Domain)),
            (T::Domain, "192.0.2.7", win, Some(T::ExactIp)),
            (T::Zone, "192.0.2.7", win, Some(T::ExactIp)),
            (T::Zone, "example.*", win, Some(T::Domain)),
            (T::Zone, "corp.internal", win, None),
            (T::Domain, "*.ru", win, None),
            (T::Domain, "10.0.0.0/24", win, Some(T::Subnet)),
            (T::ExactIp, "10.0.0.0/33", win, Some(T::Subnet)),
            (T::Subnet, "10.0.0.0/33", win, None),
            (T::ExactIp, "telegram", win, None),
        ] {
            assert_eq!(
                misplaced_rule_value(section, value, naming),
                belongs_in,
                "{section:?} {value:?} {naming:?}"
            );
        }
    }

    #[test]
    fn a_misplaced_key_names_its_type_and_nothing_else_does() {
        for t in [
            ParsedRuleType::Zone,
            ParsedRuleType::Domain,
            ParsedRuleType::ExactIp,
            ParsedRuleType::Subnet,
            ParsedRuleType::IpRange,
            ParsedRuleType::Application,
        ] {
            assert_eq!(
                misplaced_target_of_message_key(misplaced_message_key(t)),
                Some(t)
            );
            assert_eq!(rule_type_from_slug(t.slug()), Some(t));
        }
        assert_eq!(
            misplaced_target_of_message_key("rules.validation.match-value-invalid.domain"),
            None
        );
    }
}
