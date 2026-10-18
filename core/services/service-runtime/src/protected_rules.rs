//! The machine's protected programs and folders, as every rules read of the
//! service judges them: a stored rule that denies one or sends it over the
//! additional route is kept in the book and out of enforcement, and the
//! Overlaps screen says so.
//!
//! Installed once by the production service from the platform port. Without
//! it the per-OS static lists apply, which is what tests and tools get.

use std::sync::OnceLock;

use nrr_domain::canonical::CanonicalRuleBook;
use nrr_domain::protected_places::{
    withhold_app_paths, withhold_protected, ProtectedPlaces, ProtectedRule,
};
use nrr_domain::rules_file::HostPlatform;
use nrr_platform_api::enforcement::EnforcementCapabilities;

static MACHINE: OnceLock<ProtectedPlaces> = OnceLock::new();

/// Sets the machine's places. Only the first call counts: what a running
/// service judged its rules by must not move under it.
pub fn install(places: ProtectedPlaces) {
    let _ = MACHINE.set(places);
}

/// The machine's places, or this platform's static lists when none were
/// installed.
#[must_use]
pub fn places() -> &'static ProtectedPlaces {
    static DEFAULTS: OnceLock<ProtectedPlaces> = OnceLock::new();
    MACHINE.get().unwrap_or_else(|| {
        DEFAULTS.get_or_init(|| ProtectedPlaces::defaults(HostPlatform::compiled()))
    })
}

/// `book` as enforcement may see it, and the rules kept out of it: the
/// protected ones, and rules by program path where the platform cannot carry
/// them out yet.
#[must_use]
pub fn withhold(book: CanonicalRuleBook) -> (CanonicalRuleBook, Vec<ProtectedRule>) {
    withhold_on(book, EnforcementCapabilities::current().app_path_rules)
}

fn withhold_on(
    book: CanonicalRuleBook,
    app_path_rules: bool,
) -> (CanonicalRuleBook, Vec<ProtectedRule>) {
    let (book, mut withheld) = withhold_protected(book, places());
    if app_path_rules {
        return (book, withheld);
    }
    let (book, paths) = withhold_app_paths(book);
    withheld.extend(paths);
    (book, withheld)
}

/// One line per change of what is withheld for `principal`: the rules decode
/// on every source change, and the same set would repeat each time.
pub fn report_withheld(principal: &str, withheld: &[ProtectedRule]) {
    if withheld.is_empty() {
        return;
    }
    let rules: Vec<String> = withheld
        .iter()
        .map(|rule| format!("{} ({})", rule.value, rule.reason))
        .collect();
    tracing::warn!(
        target: "nrr::rules-provider",
        msg_key = "protected-rules-not-applied",
        sid = %principal,
        count = withheld.len(),
        rules = %rules.join(", "),
        "rules not applied: they deny a system program or folder, send one over the additional route, or name a program by a path this system cannot apply yet",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_domain::canonical::{
        CanonicalAppMatch, CanonicalAppPattern, CanonicalRule, CanonicalRuleSet, RuleAction,
    };

    #[test]
    fn a_deny_of_a_critical_process_is_withheld_and_named() {
        let critical = match HostPlatform::compiled() {
            HostPlatform::Windows => "svchost.exe",
            HostPlatform::Linux => "networkmanager",
            HostPlatform::MacOS => "configd",
        };
        let rule = CanonicalRule {
            id: nrr_domain::RuleId("r-1".into()),
            enabled: true,
            address_match: None,
            app_match: Some(CanonicalAppMatch {
                pattern: CanonicalAppPattern::Exact(critical.into()),
                include_child_processes: false,
            }),
            comment: String::new(),
            action: RuleAction::Block,
            origin: None,
        };
        let book = CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![rule]),
            secondary: CanonicalRuleSet::default(),
        };
        let (kept, withheld) = withhold(book);
        assert!(kept.primary.is_empty());
        assert_eq!(withheld.len(), 1);
        assert_eq!(withheld[0].value, critical);
    }

    /// A rule by program path is withheld and named until the platform says
    /// it carries such rules out; then it reaches enforcement untouched.
    #[test]
    fn a_path_rule_waits_for_the_capability() {
        let path = if cfg!(windows) {
            r"C:\Apps\Tool\*"
        } else {
            "/opt/tool/*"
        };
        let content = nrr_domain::rules_json_codec::decode(
            nrr_shared::rules_json::from_canonical_string(
                &serde_json::json!({
                    "schema-version": 5,
                    "primary": [{
                        "id": "r-1", "enabled": true,
                        "app-match": {
                            "pattern": { "kind": "path", "value": path },
                            "include-child-processes": false,
                        },
                    }],
                    "secondary": [],
                })
                .to_string(),
            )
            .expect("wire"),
            HostPlatform::compiled(),
        )
        .expect("decode");
        let (kept, withheld) = withhold_on(content.rule_book.clone(), false);
        assert!(kept.primary.is_empty());
        assert_eq!(
            withheld.iter().map(|r| r.reason).collect::<Vec<_>>(),
            [nrr_domain::protected_places::ProtectionReason::AppPathUnsupported]
        );
        let (kept, withheld) = withhold_on(content.rule_book, true);
        assert_eq!(kept.primary.len(), 1);
        assert!(withheld.is_empty());
        assert!(!EnforcementCapabilities::current().app_path_rules);
    }
}
