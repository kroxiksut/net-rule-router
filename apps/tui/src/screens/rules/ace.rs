//! The ACE boundary for host names (the GUI's `HostAceCodec`): rules cross the
//! wire in ACE form and are read and typed in Unicode. Both directions are
//! total — a value that does not convert comes back trimmed, never lost.

/// A host split at its wildcard ends, which are not labels and stay outside
/// the conversion in both directions.
fn split_wildcards(host: &str) -> (&str, &str, &str) {
    let (prefix, name) = match host.strip_prefix("*.") {
        Some(rest) => ("*.", rest),
        None => ("", host),
    };
    match name.strip_suffix(".*") {
        Some(rest) => (prefix, rest, ".*"),
        None => (prefix, name, ""),
    }
}

/// Unicode host to ACE; ASCII passes through.
pub fn encode(host: &str) -> String {
    let trimmed = host.trim();
    if trimmed.is_ascii() {
        return trimmed.to_owned();
    }
    let (prefix, name, suffix) = split_wildcards(trimmed);
    match idna::domain_to_ascii(name) {
        Ok(ace) if !ace.is_empty() => format!("{prefix}{ace}{suffix}"),
        _ => trimmed.to_owned(),
    }
}

/// ACE host to Unicode, for display; a value with no `xn--` label is kept.
pub fn decode(host: &str) -> String {
    let trimmed = host.trim();
    if !trimmed.to_ascii_lowercase().contains("xn--") {
        return trimmed.to_owned();
    }
    let (prefix, name, suffix) = split_wildcards(trimmed);
    let (unicode, result) = idna::domain_to_unicode(name);
    if result.is_err() || unicode.is_empty() {
        trimmed.to_owned()
    } else {
        format!("{prefix}{unicode}{suffix}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_directions_round_trip_and_keep_what_does_not_convert() {
        assert_eq!(encode("пример.рф"), "xn--e1afmkfd.xn--p1ai");
        assert_eq!(encode("*.пример.рф"), "*.xn--e1afmkfd.xn--p1ai");
        assert_eq!(encode(" example.com "), "example.com");
        assert_eq!(decode("xn--e1afmkfd.xn--p1ai"), "пример.рф");
        assert_eq!(decode("example.com"), "example.com");
    }

    /// Published punycode pairs, not output the codec made itself.
    #[test]
    fn real_punycode_pairs_in_both_directions() {
        let pairs = [
            ("bücher.example", "xn--bcher-kva.example"),
            ("яндекс.рф", "xn--d1acpjx3f.xn--p1ai"),
            ("日本語.jp", "xn--wgv71a119e.jp"),
            // Top-level names Qt's whitelist leaves in ACE; the codec here
            // converts every label, so the rule shown is the rule typed.
            ("сайт.москва", "xn--80aswg.xn--80adxhks"),
            ("сайт.рус", "xn--80aswg.xn--p1acf"),
        ];
        for (unicode, ace) in pairs {
            assert_eq!(encode(unicode), ace, "{unicode}");
            assert_eq!(decode(ace), unicode, "{ace}");
        }
    }

    #[test]
    fn a_wildcard_stays_outside_the_conversion_at_either_end() {
        assert_eq!(encode("*.яндекс.рф"), "*.xn--d1acpjx3f.xn--p1ai");
        assert_eq!(encode("яндекс.*"), "xn--d1acpjx3f.*");
        assert_eq!(decode("*.xn--d1acpjx3f.xn--p1ai"), "*.яндекс.рф");
    }

    #[test]
    fn upper_case_unicode_folds_to_the_lower_case_ace() {
        assert_eq!(encode("ПРИМЕР.РФ"), "xn--e1afmkfd.xn--p1ai");
    }
}
