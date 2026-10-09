use super::*;

// ── `?` — check where it works ───────────────────────────────────────────

use crate::canonical::{CanonicalAddressMatch, CanonicalRule, CanonicalRuleSet, RuleAction};
use crate::preset_canonicalize::{canonicalize_preset_rules, PresetRulesCanonicalizeOutcome};
use crate::validation::{validate_and_canonicalize, ValidationWarning};
use crate::{
    ActiveConfiguration, AdapterIdentity, BindingSource, RouteBehaviorMode, RouteBinding, RuleBook,
};
use nrr_shared::RouteRole;
use std::net::{IpAddr, Ipv4Addr};

fn domains(text: &str) -> Vec<RulesFileEntry> {
    parse_rules_file(text)
        .parsed
        .entries_for(RulesFileSection::Domains)
        .to_vec()
}

fn binding(role: RouteRole, id: &str) -> Option<RouteBinding> {
    Some(RouteBinding {
        role,
        adapter: AdapterIdentity {
            stable_id: id.to_string(),
            display_name: id.to_string(),
        },
        source: BindingSource::UserAssigned,
    })
}

/// Both files through conversion and validation, as the service reads a book.
fn validate_book(primary: &str, secondary: &str) -> crate::validation::ValidationOutcome {
    let set = |text: &str| {
        rules_file_to_route_rule_set(&parse_rules_file(text).parsed, HostPlatform::Windows, false)
    };
    let config = ActiveConfiguration {
        primary: binding(RouteRole::Primary, "eth0"),
        secondary: binding(RouteRole::Secondary, "tun0"),
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        rule_book: RuleBook {
            primary: set(primary),
            secondary: set(secondary),
        },
    };
    validate_and_canonicalize(&config, HostPlatform::Windows)
}

#[test]
fn the_prefix_is_read_on_exact_suffix_and_disabled_domain_lines() {
    let entries = domains(
        "--- Domains\n?accounts.example.com  # sign-in\n?*.mail.example\n# ?off.example.com\nplain.example.com\n",
    );
    let read: Vec<_> = entries
        .iter()
        .map(|e| (e.match_value.as_str(), e.enabled, e.verify_primary))
        .collect();
    assert_eq!(
        read,
        [
            ("accounts.example.com", true, true),
            ("*.mail.example", true, true),
            ("off.example.com", false, true),
            ("plain.example.com", true, false),
        ]
    );
    assert_eq!(entries[0].inline_comment.as_deref(), Some("sign-in"));
}

#[test]
fn the_prefix_round_trips_through_write_and_parse() {
    let text =
        "--- Domains\n?accounts.example.com  # sign-in\n?*.mail.example\n# ?off.example.com\n";
    let parsed = parse_rules_file(text).parsed;
    let written = write_rules_file(&parsed, &[], None);
    assert_eq!(written, text, "the writer puts `?` right before the value");
    assert_eq!(parse_rules_file(&written).parsed, parsed);
}

#[test]
fn a_detached_or_doubled_question_mark_stays_in_the_value() {
    // Positive control: the attached form is the prefix.
    assert_eq!(
        domains(
            "--- Domains
?a.example
"
        )[0]
        .match_value,
        "a.example"
    );
    // Anything else leaves a `?` in the value, for validation to refuse.
    for line in ["? a.example", "??a.example"] {
        let entries = domains(&format!(
            "--- Domains
{line}
"
        ));
        assert!(
            entries.iter().any(|e| e.match_value.starts_with('?')),
            "{line:?}: {entries:?}"
        );
    }
}

#[test]
fn verify_and_block_on_one_line_refuse_the_line() {
    let outcome = parse_rules_file(
        "--- Domains\n?both.example.com +block\n# ?off.example.com +block\nkept.example.com\n",
    );
    let entries = outcome.parsed.entries_for(RulesFileSection::Domains);
    assert_eq!(
        entries.len(),
        1,
        "only the plain line is a rule: {entries:?}"
    );
    assert_eq!(entries[0].match_value, "kept.example.com");
    assert_eq!(
        outcome.warnings,
        vec![
            ParseWarning::VerifyPrimaryWithBlock {
                match_value: "both.example.com".to_string(),
            },
            ParseWarning::VerifyPrimaryWithBlock {
                match_value: "off.example.com".to_string(),
            },
        ]
    );
}

#[test]
fn the_prefix_is_read_on_exact_ip_lines() {
    let outcome =
        parse_rules_file("--- IP\n?192.0.2.10  # one host\n# ?2001:db8::7\n198.51.100.1\n");
    let read: Vec<_> = outcome
        .parsed
        .entries_for(RulesFileSection::Ip)
        .iter()
        .map(|e| (e.match_value.as_str(), e.enabled, e.verify_primary))
        .collect();
    assert_eq!(
        read,
        [
            ("192.0.2.10", true, true),
            ("2001:db8::7", false, true),
            ("198.51.100.1", true, false),
        ]
    );
}

#[test]
fn outside_the_domain_and_ip_sections_the_prefix_is_a_bad_value() {
    for (section, value) in [("Zones", "?example"), ("CIDR", "?192.0.2.0/24")] {
        let text = format!("--- {section}\n{value}\n");
        let outcome = parse_rules_file(&text);
        assert!(
            outcome
                .parsed
                .sections
                .iter()
                .flat_map(|s| &s.entries)
                .all(|e| !e.verify_primary && e.match_value == value),
            "{section}: the value keeps its `?`"
        );
        let canonical =
            canonicalize_preset_rules(&outcome, RouteRole::Secondary, HostPlatform::Windows, false);
        assert!(
            matches!(canonical, PresetRulesCanonicalizeOutcome::Rejected { .. }),
            "{section}: {canonical:?}"
        );
    }
}

#[test]
fn in_either_file_the_prefix_becomes_the_verify_action() {
    let primary = "--- Domains\n?accounts.example.com\n?*.mail.example\n--- IP\n?192.0.2.10\n";
    let secondary = "--- Domains\n?login.example.net\n?*.post.example.net\n--- IP\n?192.0.2.20\n";
    let outcome = validate_book(primary, secondary);
    let profile = outcome.profile().expect("accepted");
    for set in [&profile.rule_book.primary, &profile.rule_book.secondary] {
        let actions: Vec<_> = set.rules().iter().map(|r| r.action).collect();
        assert_eq!(actions, [RuleAction::Verify; 3]);
    }
    assert!(
        !outcome
            .warnings()
            .iter()
            .any(|w| matches!(w, ValidationWarning::VerifyIgnored { .. })),
        "{:?}",
        outcome.warnings()
    );
}

#[test]
fn on_an_application_rule_the_prefix_is_a_plain_route_with_a_warning() {
    let app_rule = |id: &str, name: &str| crate::Rule {
        id: crate::RuleId(id.to_string()),
        enabled: true,
        address_match: None,
        app_match: Some(crate::AppMatch {
            pattern: crate::AppMatchPattern::Exact(name.to_string()),
            include_child_processes: false,
            windows_service_name: None,
        }),
        comment: String::new(),
        action: RuleAction::Verify,
        origin: None,
    };
    let config = ActiveConfiguration {
        primary: binding(RouteRole::Primary, "eth0"),
        secondary: binding(RouteRole::Secondary, "tun0"),
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        rule_book: RuleBook {
            primary: crate::RouteRuleSet {
                rules: vec![app_rule("r-app-1", "foo.exe")],
            },
            secondary: crate::RouteRuleSet {
                rules: vec![app_rule("r-app-2", "bar.exe")],
            },
        },
    };
    let outcome = validate_and_canonicalize(&config, HostPlatform::Windows);
    let profile = outcome.profile().expect("accepted");
    assert_eq!(
        profile.rule_book.primary.rules()[0].action,
        RuleAction::Route
    );
    assert_eq!(
        profile.rule_book.secondary.rules()[0].action,
        RuleAction::Route
    );
    assert!(outcome.warnings().iter().any(|w| matches!(
        w,
        ValidationWarning::VerifyIgnored {
            role: RouteRole::Primary,
            ..
        }
    )));
}

#[test]
fn within_one_set_the_checked_and_plain_copies_are_one_rule() {
    let outcome = validate_book(
        "",
        "--- Domains\n?accounts.example.com\naccounts.example.com\n",
    );
    let profile = outcome.profile().expect("accepted");
    assert_eq!(profile.rule_book.secondary.rules().len(), 1);
    assert!(outcome
        .warnings()
        .iter()
        .any(|w| matches!(w, ValidationWarning::DuplicateRuleInSameSet { .. })));
}

#[test]
fn within_one_set_the_plain_copy_wins_whichever_line_comes_first() {
    for text in [
        "--- Domains\n?accounts.example.com\naccounts.example.com\n",
        "--- Domains\naccounts.example.com\n?accounts.example.com\n",
    ] {
        let outcome = validate_book("", text);
        let profile = outcome.profile().expect("accepted");
        let rules = profile.rule_book.secondary.rules();
        assert_eq!(rules.len(), 1, "{text}");
        assert_eq!(rules[0].action, RuleAction::Route, "{text}");
        let kept = outcome.warnings().iter().find_map(|w| match w {
            ValidationWarning::DuplicateRuleInSameSet { kept_rule_id, .. } => Some(kept_rule_id),
            _ => None,
        });
        assert_eq!(kept, Some(&rules[0].id), "the warning names the kept rule");
    }
}

#[test]
fn across_sets_plain_primary_and_checked_secondary_are_two_instructions() {
    let outcome = validate_book(
        "--- Domains\naccounts.example.com\n",
        "--- Domains\n?accounts.example.com\n",
    );
    let profile = outcome.profile().expect("accepted");
    assert_eq!(profile.rule_book.primary.rules().len(), 1);
    assert_eq!(profile.rule_book.secondary.rules().len(), 1);
    assert!(!outcome
        .warnings()
        .iter()
        .any(|w| matches!(w, ValidationWarning::DuplicateRuleAcrossSets { .. })));

    // Positive control: the same plain rule in both sets IS reported.
    let twice = validate_book(
        "--- Domains\naccounts.example.com\n",
        "--- Domains\naccounts.example.com\n",
    );
    assert!(twice
        .warnings()
        .iter()
        .any(|w| matches!(w, ValidationWarning::DuplicateRuleAcrossSets { .. })));
}

#[test]
fn a_canonical_verify_rule_is_written_back_with_its_prefix() {
    let verify = |id, addr| CanonicalRule {
        action: RuleAction::Verify,
        ..rule_with_address(id, true, addr, "")
    };
    let set = CanonicalRuleSet::from_rules(vec![
        verify(
            "r-1",
            CanonicalAddressMatch::SuffixDomain("mail.example".to_string()),
        ),
        verify(
            "r-2",
            CanonicalAddressMatch::ExactIp(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
        ),
    ]);
    let parsed = canonical_rule_set_to_rules_file_parsed(&set, RulesFileSection::Windows);
    let text = write_rules_file(&parsed, &[], None);
    assert!(text.contains("\n?*.mail.example\n"), "got:\n{text}");
    assert!(text.contains("\n?192.0.2.10\n"), "got:\n{text}");
}
