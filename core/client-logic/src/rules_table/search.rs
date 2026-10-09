//! The rules table's search box: a pasted URL cleaned to its host
//! (`normalizeHostInput`), and the row filter (`passesFilter` of the rules
//! section, which has no JS twin to run against).

use super::{RuleRow, RuleType};
use crate::js;

/// `[:/@?#]` — characters only a URL, not a host, carries.
fn has_url_punctuation(s: &str) -> bool {
    s.contains([':', '/', '@', '?', '#'])
}

/// ECMAScript `LineTerminator`, which `.` does not match.
fn is_line_terminator(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}')
}

/// The length of a leading `scheme://` whose scheme matches `first` then
/// `rest*`, or `None`.
fn scheme_len(s: &str, rest: impl Fn(char) -> bool) -> Option<usize> {
    let mut chars = s.char_indices();
    let (_, first) = chars.next()?;
    if !first.is_ascii_alphabetic() {
        return None;
    }
    for (i, c) in chars {
        if c == ':' {
            return s[i..].starts_with("://").then_some(i + 3);
        }
        if !rest(c) {
            return None;
        }
    }
    None
}

/// A host typed or pasted as a URL, cut down to the host
/// (`normalizeHostInput`). Only host types are touched, and only a value that
/// carries URL punctuation; such a value comes back lower-cased, and a broad
/// domain loses a leading `www.`.
pub fn normalize_host_input(rule_type: &RuleType, raw: &str) -> String {
    let broad = matches!(rule_type, RuleType::Domain | RuleType::SuffixDomain);
    if !rule_type.is_hostlike() || !has_url_punctuation(raw) {
        return raw.to_owned();
    }
    let mut s = raw;
    // `^[A-Za-z][A-Za-z0-9\u0080-￿-]*://`
    if let Some(n) = scheme_len(s, |c| {
        c.is_ascii_alphanumeric() || c == '-' || !c.is_ascii()
    }) {
        s = &s[n..];
    }
    // `^[^@\/]*@`
    if let Some(at) = s.find(['@', '/']).filter(|&i| s[i..].starts_with('@')) {
        s = &s[at + 1..];
    }
    // `[\/?#].*$`: the first such character whose tail holds no line break.
    if let Some(cut) = s.char_indices().find_map(|(i, c)| {
        (matches!(c, '/' | '?' | '#') && !s[i + c.len_utf8()..].contains(is_line_terminator))
            .then_some(i)
    }) {
        s = &s[..cut];
    }
    // `:\d+$`
    let digits = s.len() - s.trim_end_matches(|c: char| c.is_ascii_digit()).len();
    if digits > 0 && s[..s.len() - digits].ends_with(':') {
        s = &s[..s.len() - digits - 1];
    }
    let lower = s.to_lowercase();
    match lower.strip_prefix("www.") {
        Some(rest) if broad => rest.to_owned(),
        _ => lower,
    }
}

/// What the search box keeps when `text` arrives: a URL with a scheme is
/// cleaned to its host; anything else stays as typed, because the host
/// cleaner reads a subnet's `/` and an IPv6 address's `:` as URL parts.
pub fn search_box_text(text: &str) -> String {
    let scheme = scheme_len(text, |c| {
        c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-')
    });
    if scheme.is_some() {
        normalize_host_input(&RuleType::Domain, text)
    } else {
        text.to_owned()
    }
}

/// Whether `row` passes the search `query` (`passesFilter`). `ace_lower` is the
/// row's lower-case ACE value, so `xn--p1ai` finds `рф` and back. The needle is
/// both the host-cleaned query and the query as typed.
pub fn row_matches_search(row: &RuleRow, ace_lower: &str, query: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    let typed = js::trim(query).to_lowercase();
    let mut needle = normalize_host_input(&RuleType::Domain, &typed);
    // Bare punctuation (`/`) cleans to nothing, which would match every row.
    if needle.is_empty() {
        needle.clone_from(&typed);
    }
    let hay = format!("{} {} {}", row.match_value, ace_lower, row.comment).to_lowercase();
    hay.contains(&needle) || hay.contains(&typed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(raw: &str) -> String {
        normalize_host_input(&RuleType::Domain, raw)
    }

    #[test]
    fn a_url_comes_down_to_its_host() {
        assert_eq!(
            domain("https://user:pw@WWW.Example.COM:8443/path?q=1#top"),
            "example.com"
        );
        assert_eq!(domain("example.com/page"), "example.com");
        assert_eq!(domain("http://пример.рф/"), "пример.рф");
    }

    #[test]
    fn exact_names_keep_www_and_other_types_are_untouched() {
        assert_eq!(
            normalize_host_input(&RuleType::ExactFqdn, "https://www.example.com/"),
            "www.example.com"
        );
        assert_eq!(
            normalize_host_input(&RuleType::Subnet, "192.0.2.0/24"),
            "192.0.2.0/24"
        );
        assert_eq!(
            domain("Example.COM"),
            "Example.COM",
            "no URL punctuation, as typed"
        );
    }

    #[test]
    fn a_path_cut_stops_at_a_line_break_as_js_dot_does() {
        assert_eq!(domain("a.example/x\ny"), "a.example/x\ny".to_lowercase());
        assert_eq!(domain("a.example/x\ny/z"), "a.example/x\ny");
    }

    #[test]
    fn only_a_trailing_port_is_dropped() {
        assert_eq!(domain("host:1:23"), "host:1");
        assert_eq!(domain("host:"), "host:");
    }

    #[test]
    fn the_search_box_cleans_only_a_url_with_a_scheme() {
        assert_eq!(search_box_text("https://www.example.com/a"), "example.com");
        assert_eq!(search_box_text("2001:db8::/32"), "2001:db8::/32");
        assert_eq!(search_box_text("example.com/a"), "example.com/a");
    }

    #[test]
    fn search_finds_the_value_the_ace_form_and_the_comment() {
        let row = RuleRow {
            id: "R-0001".into(),
            enabled: true,
            rule_type: RuleType::Domain,
            match_value: "пример.рф".into(),
            target_route: super::super::TargetRoute::Secondary,
            verify: false,
            comment: "Work Site".into(),
            origin: None,
        };
        assert!(row_matches_search(
            &row,
            "xn--e1afmkfd.xn--p1ai",
            "XN--P1AI"
        ));
        assert!(row_matches_search(&row, "", "work"));
        assert!(row_matches_search(&row, "", "https://пример.рф/page"));
        assert!(!row_matches_search(&row, "", "other"));
        assert!(row_matches_search(&row, "", ""));
    }
}
