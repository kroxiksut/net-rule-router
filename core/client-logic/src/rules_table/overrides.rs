//! Which rules the service applies despite the protection of system programs
//! (`ruleOverrideKey`, `overrideRemaining` in `rules.js`): a table row and a
//! confirmation the snapshot lists are matched through one key, and the mark
//! says how much of the term is left.

use nrr_shared::app_identity::app_match_key;
use nrr_shared::preset_parser::without_rule_flags;

const MINUTE_MS: i64 = 60_000;
const HOUR_MS: i64 = 60 * MINUTE_MS;
const DAY_MS: i64 = 24 * HOUR_MS;

/// The key a confirmation and its rule share: the route and the value as the
/// service compares it — flags off, a name by its match key, a path folded
/// over all of Unicode where `os` ignores case, as the service spells its
/// canonical value. `""` for anything no confirmation can be about.
#[must_use]
pub fn rule_override_key(rule_type: &str, value: &str, route: &str, os: &str) -> String {
    if rule_type != "application" || !matches!(route, "secondary" | "block") {
        return String::new();
    }
    let bare = without_rule_flags(value.trim());
    let bare = bare.trim();
    if bare.is_empty() {
        return String::new();
    }
    let windows = os != "linux" && os != "macos";
    let is_path = bare.contains('/') || (windows && bare.contains('\\'));
    let spelled = if !is_path {
        app_match_key(bare)
    } else if windows {
        bare.replace('/', "\\").to_lowercase()
    } else if os == "macos" {
        bare.to_lowercase()
    } else {
        bare.to_owned()
    };
    format!("{route}|{spelled}")
}

/// How much of a confirmation's term is left at `now_ms`: `until-revoked`
/// with no deadline, `ended` past it, else `minutes` under an hour, `hours`
/// under two days and `days` beyond, each rounded up.
#[must_use]
pub fn override_remaining(until_ms: Option<i64>, now_ms: i64) -> (&'static str, i64) {
    let Some(until) = until_ms else {
        return ("until-revoked", 0);
    };
    let left = until.saturating_sub(now_ms);
    let up = |unit: i64| left.saturating_add(unit - 1) / unit;
    if left <= 0 {
        ("ended", 0)
    } else if left < HOUR_MS {
        ("minutes", up(MINUTE_MS))
    } else if left < 2 * DAY_MS {
        ("hours", up(HOUR_MS))
    } else {
        ("days", up(DAY_MS))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_row_and_its_confirmation_share_a_key() {
        assert_eq!(
            rule_override_key("application", r"C:\InetPub\* +override", "block", "windows"),
            rule_override_key("application", r"c:\inetpub\*", "block", "windows")
        );
        assert_eq!(
            rule_override_key("application", "svchost +override", "secondary", "windows"),
            rule_override_key("application", "svchost.exe", "secondary", "windows")
        );
        assert_eq!(
            rule_override_key(
                "application",
                r"C:\Program Files\Мой Софт\* +override",
                "secondary",
                "windows"
            ),
            rule_override_key(
                "application",
                r"c:\program files\мой софт\*",
                "secondary",
                "windows"
            )
        );
        assert_eq!(
            rule_override_key("application", "Программа.EXE +override", "block", "windows"),
            rule_override_key("application", "программа", "block", "windows")
        );
        assert_ne!(
            rule_override_key("application", "/var/WWW/*", "block", "linux"),
            rule_override_key("application", "/var/www/*", "block", "linux")
        );
        assert_ne!(
            rule_override_key("application", "/var/www/*", "block", "linux"),
            rule_override_key("application", "/var/www/*", "secondary", "linux")
        );
        assert_eq!(
            rule_override_key("domain", "example.com", "block", "linux"),
            ""
        );
        assert_eq!(
            rule_override_key("application", "/var/www/*", "primary", "linux"),
            ""
        );
    }

    #[test]
    fn the_term_left_is_rounded_up_in_the_largest_fitting_unit() {
        let now = 1_000_000;
        assert_eq!(override_remaining(None, now), ("until-revoked", 0));
        assert_eq!(override_remaining(Some(now), now), ("ended", 0));
        assert_eq!(override_remaining(Some(now + 1), now), ("minutes", 1));
        assert_eq!(override_remaining(Some(now + HOUR_MS), now), ("hours", 1));
        assert_eq!(override_remaining(Some(now + DAY_MS), now), ("hours", 24));
        assert_eq!(override_remaining(Some(now + 7 * DAY_MS), now), ("days", 7));
    }
}
