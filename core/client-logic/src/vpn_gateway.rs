//! The rule that lets a VPN reach its gateway over the chosen route
//! (`vpnGatewayRuleDraft` in `rules.js`): an exact address, or the host when a
//! name is chosen or typed, commented with the program it is for.

use crate::js;
use crate::rules_table::{normalize_host_input, RuleType};
use crate::Route;

/// `{program}` in the comment template.
pub const PROGRAM_PLACEHOLDER: &str = "{program}";

/// One rule ready for the table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayRuleDraft {
    /// [`RuleType::ExactIp`], or [`RuleType::Domain`] for one host (no `*.`).
    pub rule_type: RuleType,
    pub value: String,
    pub route: Route,
    pub comment: String,
}

/// The file name of a program typed or picked with its path.
pub fn program_file_name(raw: &str) -> &str {
    js::trim(js::trim(raw).rsplit(['\\', '/']).next().unwrap_or_default())
}

fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 3
                && p.bytes().all(|b| b.is_ascii_digit())
                && p.parse::<u16>().is_ok_and(|n| n <= 255)
        })
}

fn is_hex_group(g: &str) -> bool {
    !g.is_empty() && g.len() <= 4 && g.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Groups of one side of an IPv6 text, the last one possibly a dotted IPv4
/// (worth two). `None` when a group is malformed or empty.
fn ipv6_groups(side: &str, may_end_in_ipv4: bool) -> Option<usize> {
    if side.is_empty() {
        return Some(0);
    }
    let groups: Vec<&str> = side.split(':').collect();
    let last = groups.len() - 1;
    let mut count = 0;
    for (i, g) in groups.iter().enumerate() {
        if i == last && may_end_in_ipv4 && g.contains('.') {
            if !is_ipv4(g) {
                return None;
            }
            count += 2;
        } else if is_hex_group(g) {
            count += 1;
        } else {
            return None;
        }
    }
    Some(count)
}

fn is_ipv6(s: &str) -> bool {
    if !s.contains(':') {
        return false;
    }
    match s.split_once("::") {
        Some((left, right)) => {
            if right.contains("::") {
                return false;
            }
            match (ipv6_groups(left, false), ipv6_groups(right, true)) {
                (Some(l), Some(r)) => l + r <= 7,
                _ => false,
            }
        }
        None => ipv6_groups(s, true) == Some(8),
    }
}

/// An address literal, brackets allowed, lower-cased.
fn ip_literal(s: &str) -> Option<String> {
    let bare = s
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(s);
    (is_ipv4(bare) || is_ipv6(bare)).then(|| bare.to_lowercase())
}

/// A name of two labels or more: ASCII letters, digits, `-` and `_`, or any
/// non-ASCII character but a space; no label empty or edged with `-`, and the
/// last not all digits, which is a mistyped address. The rules validator
/// judges the rest.
fn is_host_name(s: &str) -> bool {
    let labels: Vec<&str> = s.split('.').collect();
    labels.len() >= 2
        && !labels
            .last()
            .is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit()))
        && labels.iter().all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| {
                    if c.is_ascii() {
                        c.is_ascii_alphanumeric() || c == '-' || c == '_'
                    } else {
                        !js::is_whitespace(c)
                    }
                })
        })
}

/// The rule for `input` — a chosen address or name, or what the user typed —
/// over `route`, commented by filling `{program}` in `comment_template`.
/// `None` when the input is neither an address nor a host name, or no program
/// is named.
pub fn gateway_rule_draft(
    input: &str,
    program: &str,
    route: Route,
    comment_template: &str,
) -> Option<GatewayRuleDraft> {
    let program = program_file_name(program);
    let text = js::trim(input);
    if program.is_empty() || text.is_empty() {
        return None;
    }
    let draft = |rule_type: RuleType, value: String| GatewayRuleDraft {
        rule_type,
        value,
        route,
        comment: comment_template.replace(PROGRAM_PLACEHOLDER, program),
    };
    if let Some(ip) = ip_literal(text) {
        return Some(draft(RuleType::ExactIp, ip));
    }
    let host = normalize_host_input(&RuleType::ExactFqdn, text);
    let host = js::trim(&host);
    if let Some(ip) = ip_literal(host) {
        return Some(draft(RuleType::ExactIp, ip));
    }
    let host = host.strip_suffix('.').unwrap_or(host).to_lowercase();
    is_host_name(&host).then(|| draft(RuleType::Domain, host))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_families_and_their_edges() {
        for ok in [
            "192.0.2.1",
            "2001:db8::1",
            "::",
            "::ffff:192.0.2.1",
            "1:2:3:4:5:6:7:8",
        ] {
            assert!(ip_literal(ok).is_some(), "{ok}");
        }
        for bad in [
            "192.0.2",
            "256.0.0.1",
            "1:2:3:4:5:6:7:8:9",
            "1::2::3",
            "12345::1",
            ":1::",
        ] {
            assert!(ip_literal(bad).is_none(), "{bad}");
        }
    }
}
