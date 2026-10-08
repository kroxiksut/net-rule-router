/// One format, one reading of it. The service side used to accept a header
/// with leading whitespace while the GUI side did not, so a file with
/// `  --- IP` imported as two different rule sets depending on who read it.
#[test]
fn both_parsers_agree_on_where_a_section_starts() {
    let text = "--- Domains
example.com
  --- IP
203.0.113.1
";
    let outcome = parse_rules_file(text);
    // The indented line is NOT a header, so the address after it stays in
    // Domains and no IP section is opened.
    assert!(
        outcome.parsed.entries_for(RulesFileSection::Ip).is_empty(),
        "an indented header must not open a section"
    );
    let shared = nrr_shared::preset_parser::parse_canonical_rules(text);
    assert!(
        shared
            .rules
            .iter()
            .all(|r| r.rule_type != nrr_shared::preset_parser::ParsedRuleType::ExactIp),
        "the GUI parser must reach the same conclusion"
    );
}

/// An indented disabled rule is still a disabled rule. The GUI parser kept
/// leading whitespace, so `  # example.com` was not recognised as one and
/// the rule vanished from the list the service was still keeping.
#[test]
fn both_parsers_keep_an_indented_disabled_rule() {
    let text = "--- Domains
  # example.com
keep.example
";
    let outcome = parse_rules_file(text);
    let entries = outcome.parsed.entries_for(RulesFileSection::Domains);
    assert_eq!(entries.len(), 2, "the disabled rule is kept: {entries:?}");
    assert!(entries.iter().any(|e| !e.enabled));

    let shared = nrr_shared::preset_parser::parse_canonical_rules(text);
    assert_eq!(shared.rules.len(), 2, "the GUI parser must keep it too");
    assert!(shared.rules.iter().any(|r| !r.enabled));
}

/// A file saved by a Windows editor starts with a BOM. The service strips
/// it; the GUI parser did not, so its first section header was invisible
/// and every rule under it read as prose.
#[test]
fn a_leading_bom_does_not_hide_the_first_section() {
    let text = "\u{feff}--- Domains
example.com
";
    let outcome = parse_rules_file(text);
    assert_eq!(
        outcome.parsed.entries_for(RulesFileSection::Domains).len(),
        1
    );
    let shared = nrr_shared::preset_parser::parse_canonical_rules(text);
    assert_eq!(shared.rules.len(), 1, "the GUI parser must see it too");
}

/// `?` (try the primary route first) is read the same way by both parsers:
/// on host-name lines only, enabled or not, and a line also carrying
/// `+block` is no rule for either of them.
#[test]
fn both_parsers_agree_on_the_verify_prefix() {
    let text = "--- Domains
?accounts.example.com
?*.mail.example
# ?off.example.com
plain.example.com
? spaced.example.com
?both.example.com +block
--- Auto
?learned.example.com  # auto:user-confirmed anchor:learned.example.com added:2026-01-01
--- IP
?192.0.2.10
";
    let outcome = parse_rules_file(text);
    let mut service: Vec<(String, bool, bool)> = outcome
        .parsed
        .sections
        .iter()
        .flat_map(|s| &s.entries)
        .map(|e| (e.match_value.clone(), e.enabled, e.verify_primary))
        .collect();
    let mut gui: Vec<(String, bool, bool)> = nrr_shared::preset_parser::parse_canonical_rules(text)
        .rules
        .into_iter()
        .map(|r| (r.match_value, r.enabled, r.verify_primary))
        .collect();
    service.sort();
    gui.sort();
    assert_eq!(service, gui);
    // Positive control: the prefix was actually read somewhere.
    assert!(service.contains(&("accounts.example.com".to_string(), true, true)));
    assert!(service.contains(&("?192.0.2.10".to_string(), true, false)));
    assert!(!service.iter().any(|(v, ..)| v.contains("both.example.com")));
}
use super::*;

use crate::canonical::{CanonicalAddressMatch, CanonicalRule, CanonicalRuleSet};
use crate::RuleId;
use std::net::{IpAddr, Ipv4Addr};

// ── Fixtures shared by more than one theme ───────────────────────────────

const SAMPLE_FILE: &str = "\
# NetRuleRouter rules file — version 1

--- Zones
corp-internal  # corporate zone

--- Domains
updates.example.org  # vendor updates
corp.example.net
# old.example.com

--- IP
203.0.113.7

--- Windows
browser.exe   # browser traffic
# powershell.exe

--- Linux

--- MacOS
";
fn rule_with_address(
    id: &str,
    enabled: bool,
    addr: CanonicalAddressMatch,
    comment: &str,
) -> CanonicalRule {
    CanonicalRule {
        id: RuleId(id.to_string()),
        enabled,
        address_match: Some(addr),
        app_match: None,
        comment: comment.to_string(),
        action: crate::canonical::RuleAction::Route,
        origin: None,
    }
}

mod auto_section;
mod canonical;
mod conversion;
mod model;
mod parsing;
mod verify_primary;
mod writing;
