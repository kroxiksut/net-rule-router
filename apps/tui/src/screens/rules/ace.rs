//! The ACE boundary for host names (the GUI's `HostAceCodec`): rules cross the
//! wire in ACE form and are read and typed in Unicode. Both directions are
//! total — a value that does not convert comes back trimmed, never lost.

/// Unicode host to ACE; ASCII passes through.
pub fn encode(host: &str) -> String {
    let trimmed = host.trim();
    if trimmed.is_ascii() {
        return trimmed.to_owned();
    }
    // A suffix wildcard is not a label, so it stays outside the conversion.
    let (prefix, name) = match trimmed.strip_prefix("*.") {
        Some(rest) => ("*.", rest),
        None => ("", trimmed),
    };
    match idna::domain_to_ascii(name) {
        Ok(ace) if !ace.is_empty() => format!("{prefix}{ace}"),
        _ => trimmed.to_owned(),
    }
}

/// ACE host to Unicode, for display; a value with no `xn--` label is kept.
pub fn decode(host: &str) -> String {
    let trimmed = host.trim();
    if !trimmed.to_ascii_lowercase().contains("xn--") {
        return trimmed.to_owned();
    }
    let (unicode, result) = idna::domain_to_unicode(trimmed);
    if result.is_err() || unicode.is_empty() {
        trimmed.to_owned()
    } else {
        unicode
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
}
