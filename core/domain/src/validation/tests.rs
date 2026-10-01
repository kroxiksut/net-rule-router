use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nrr_shared::{BindingSource, RouteBehaviorMode, RouteRole};

use crate::{
    ActiveConfiguration, AdapterIdentity, AddressMatch, AppMatch, AppMatchPattern, RouteBinding,
    RouteRuleSet, Rule, RuleBook, RuleId,
};

// ── Test helpers ──────────────────────────────────────────────────────────

fn binding(role: RouteRole, stable_id: &str) -> RouteBinding {
    RouteBinding {
        role,
        adapter: AdapterIdentity {
            stable_id: stable_id.to_string(),
            display_name: stable_id.to_string(),
        },
        source: BindingSource::UserAssigned,
    }
}

fn primary() -> RouteBinding {
    binding(RouteRole::Primary, "eth0")
}

fn secondary() -> RouteBinding {
    binding(RouteRole::Secondary, "vpn0")
}

fn config_with_rules(
    primary: Option<RouteBinding>,
    secondary: Option<RouteBinding>,
    mode: RouteBehaviorMode,
    primary_rules: Vec<Rule>,
    secondary_rules: Vec<Rule>,
) -> ActiveConfiguration {
    ActiveConfiguration {
        primary,
        secondary,
        behavior_mode: mode,
        rule_book: RuleBook {
            primary: RouteRuleSet {
                rules: primary_rules,
            },
            secondary: RouteRuleSet {
                rules: secondary_rules,
            },
        },
    }
}

fn minimal_config() -> ActiveConfiguration {
    config_with_rules(
        Some(primary()),
        Some(secondary()),
        RouteBehaviorMode::PreferPrimary,
        vec![],
        vec![],
    )
}

fn domain_rule(id: &str, label: &str) -> Rule {
    Rule {
        id: RuleId(id.to_string()),
        enabled: true,
        address_match: Some(AddressMatch::ExactFqdn(label.to_string())),
        app_match: None,
        comment: String::new(),
        action: crate::canonical::RuleAction::Route,
        origin: None,
    }
}

fn ip_rule(id: &str, addr: IpAddr) -> Rule {
    Rule {
        id: RuleId(id.to_string()),
        enabled: true,
        address_match: Some(AddressMatch::ExactIp(addr.to_string())),
        app_match: None,
        comment: String::new(),
        action: crate::canonical::RuleAction::Route,
        origin: None,
    }
}

fn app_rule(id: &str, process: &str) -> Rule {
    Rule {
        id: RuleId(id.to_string()),
        enabled: true,
        address_match: None,
        app_match: Some(AppMatch {
            pattern: AppMatchPattern::Exact(process.to_string()),
            include_child_processes: false,
            windows_service_name: None,
        }),
        comment: String::new(),
        action: crate::canonical::RuleAction::Route,
        origin: None,
    }
}

// ── Binding validation ────────────────────────────────────────────────────

#[test]
fn missing_primary_is_rejected() {
    let config = config_with_rules(
        None,
        Some(secondary()),
        RouteBehaviorMode::PreferPrimary,
        vec![],
        vec![],
    );
    let outcome = validate_and_canonicalize(&config, HostPlatform::Windows);
    assert!(!outcome.is_accepted());
    assert!(outcome
        .errors()
        .contains(&ValidationError::MissingPrimaryBinding));
}

#[test]
fn role_conflict_is_rejected() {
    let config = config_with_rules(
        Some(binding(RouteRole::Primary, "eth0")),
        Some(binding(RouteRole::Secondary, "eth0")), // same adapter
        RouteBehaviorMode::PreferPrimary,
        vec![],
        vec![],
    );
    let outcome = validate_and_canonicalize(&config, HostPlatform::Windows);
    assert!(!outcome.is_accepted());
    assert!(outcome
        .errors()
        .iter()
        .any(|e| matches!(e, ValidationError::SameAdapterBoundToBothRoles { .. })));
}

#[test]
fn valid_config_no_rules_is_accepted_clean() {
    let outcome = validate_and_canonicalize(&minimal_config(), HostPlatform::Windows);
    assert!(outcome.is_clean());
    let profile = outcome.profile().expect("profile must be present");
    assert!(profile.rule_book.primary.is_empty());
    assert!(profile.rule_book.secondary.is_empty());
}

// ── Missing secondary with StrictFailClosed ───────────────────────────────

#[test]
fn missing_secondary_with_strict_fail_closed_is_warning() {
    let config = config_with_rules(
        Some(primary()),
        None,
        RouteBehaviorMode::StrictSecondaryFailClosed,
        vec![],
        vec![],
    );
    let outcome = validate_and_canonicalize(&config, HostPlatform::Windows);
    assert!(outcome.is_accepted()); // not rejected
    assert!(outcome
        .warnings()
        .contains(&ValidationWarning::MissingSecondaryWithFailClosed));
}

#[test]
fn missing_secondary_with_prefer_primary_is_clean() {
    let config = config_with_rules(
        Some(primary()),
        None,
        RouteBehaviorMode::PreferPrimary,
        vec![],
        vec![],
    );
    let outcome = validate_and_canonicalize(&config, HostPlatform::Windows);
    assert!(outcome.is_clean());
}

// ── Domain normalization ──────────────────────────────────────────────────

#[test]
fn domain_label_uppercased_is_lowercased() {
    let mut warnings = Vec::new();
    let result = normalize_domain_label("Site.EXAMPLE", &RuleId("r-1".to_string()), &mut warnings);
    assert_eq!(result, Ok("site.example".to_string()));
    assert!(warnings.is_empty());
}

#[test]
fn domain_label_trailing_dot_removed_with_warning() {
    let mut warnings = Vec::new();
    let result = normalize_domain_label("example.com.", &RuleId("r-1".to_string()), &mut warnings);
    assert_eq!(result, Ok("example.com".to_string()));
    assert!(warnings
        .iter()
        .any(|w| matches!(w, ValidationWarning::DomainTrailingDotRemoved { .. })));
}

#[test]
fn domain_label_empty_is_blocked() {
    let mut warnings = Vec::new();
    let result = normalize_domain_label("", &RuleId("r-1".to_string()), &mut warnings);
    assert!(matches!(
        result,
        Err(ValidationError::DomainEmptyValue { .. })
    ));
}

#[test]
fn domain_label_only_trailing_dot_is_blocked() {
    let mut warnings = Vec::new();
    let result = normalize_domain_label(".", &RuleId("r-1".to_string()), &mut warnings);
    assert!(matches!(
        result,
        Err(ValidationError::DomainEmptyValue { .. })
    ));
}

#[test]
fn domain_label_idn_unicode_normalized_to_punycode() {
    let mut warnings = Vec::new();
    // образец.рф is a valid Russian IDN domain
    let result = normalize_domain_label("образец.рф", &RuleId("r-1".to_string()), &mut warnings);
    let normalized = result.expect("IDN domain must normalize successfully");
    assert!(normalized.is_ascii(), "normalized domain must be ASCII");
    assert!(normalized.starts_with("xn--"), "must be punycode");
    assert!(warnings
        .iter()
        .any(|w| matches!(w, ValidationWarning::DomainNormalizedToAscii { .. })));
}

#[test]
fn domain_label_ascii_no_idn_warning() {
    let mut warnings = Vec::new();
    let result = normalize_domain_label("example.com", &RuleId("r-1".to_string()), &mut warnings);
    assert_eq!(result, Ok("example.com".to_string()));
    assert!(!warnings
        .iter()
        .any(|w| matches!(w, ValidationWarning::DomainNormalizedToAscii { .. })));
}

// ── Zone normalization ────────────────────────────────────────────────────

fn zone_rule(id: &str, name: &str) -> Rule {
    Rule {
        id: RuleId(id.to_string()),
        enabled: true,
        address_match: Some(AddressMatch::Zone(name.to_string())),
        app_match: None,
        comment: String::new(),
        action: crate::canonical::RuleAction::Route,
        origin: None,
    }
}

/// Validates a config with a single primary zone rule and returns the
/// canonical zone value.
fn canonical_zone(raw: &str) -> String {
    let config = config_with_rules(
        Some(primary()),
        Some(secondary()),
        RouteBehaviorMode::PreferPrimary,
        vec![zone_rule("r-1", raw)],
        vec![],
    );
    let outcome = validate_and_canonicalize(&config, HostPlatform::Windows);
    let profile = outcome.profile().expect("profile must be present");
    match &profile.rule_book.primary.rules()[0].address_match {
        Some(CanonicalAddressMatch::Zone(name)) => name.clone(),
        other => panic!("expected a zone match, got {other:?}"),
    }
}

#[test]
fn zone_unicode_normalized_to_punycode() {
    // The GUI (QUrl::toAce) stores "рф" as "xn--p1ai"; the service-side
    // canonical form must converge on the same spelling or the rule diff
    // reports a spurious removed+added pair.
    assert_eq!(canonical_zone("рф"), "xn--p1ai");
    assert_eq!(canonical_zone("РФ"), "xn--p1ai");
    assert_eq!(canonical_zone("ru"), "ru");
}

#[test]
fn zone_wildcard_prefix_stripped_before_punycode() {
    assert_eq!(canonical_zone("*.рф"), "xn--p1ai");
    assert_eq!(canonical_zone("*.ru"), "ru");
}

#[test]
fn zone_written_with_a_leading_dot_canonicalizes_to_the_matchable_form() {
    // `.ru` is how a user writes a TLD. It used to be canonicalized
    // verbatim, and `match_zone` looks for `.{zone}` — so the stored rule
    // searched hostnames for `..ru` and never fired: accepted, applied,
    // inert. The canonical form now drops the dot, which is also what the
    // wire comparison key and the GUI validator already assumed.
    assert_eq!(canonical_zone(".ru"), "ru");
    assert_eq!(canonical_zone(".рф"), "xn--p1ai");
    assert_eq!(canonical_zone("corp.ru"), "corp.ru");
    assert_eq!(canonical_zone("пример.рф"), "xn--e1afmkfd.xn--p1ai");
}

/// The property the test above exists for: a zone the user wrote with a
/// dot must actually match hostnames in it. Canonical form and matcher are
/// checked together, because "accepted" and "enforced" drifting apart is
/// exactly the defect.
#[test]
fn a_dotted_zone_matches_hosts_in_it_after_canonicalization() {
    let zone = canonical_zone(".ru");
    assert!(crate::decision_matching::match_zone("example.ru", &zone));
    assert!(crate::decision_matching::match_zone(
        "translate.example.ru",
        &zone
    ));
    assert!(!crate::decision_matching::match_zone("example.com", &zone));
    // The apex itself is not a member — unchanged contract.
    assert!(!crate::decision_matching::match_zone("ru", &zone));
}

#[test]
fn zone_unicode_and_punycode_forms_produce_empty_diff() {
    // "рф" (as a rules file keeps it) and "xn--p1ai" (as the GUI saves
    // it) are the same zone after canonicalization: diffing the two
    // profiles must yield no rule changes.
    let profile_of = |raw: &str| {
        let config = config_with_rules(
            Some(primary()),
            Some(secondary()),
            RouteBehaviorMode::PreferPrimary,
            vec![zone_rule("r-1", raw)],
            vec![],
        );
        validate_and_canonicalize(&config, HostPlatform::Windows)
            .profile()
            .expect("profile must be present")
            .clone()
    };
    let unicode = profile_of("рф");
    let punycode = profile_of("xn--p1ai");
    let diff = crate::review::compute_diff(Some(&unicode), &punycode);
    assert!(
        diff.rule_changes.is_empty(),
        "unicode and punycode spellings of one zone must not diff, got {:?}",
        diff.rule_changes
    );
    assert!(diff.is_empty());
}

// ── IP normalization ──────────────────────────────────────────────────────

#[test]
fn ipv4_accepted_as_is() {
    let mut warnings = Vec::new();
    let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let result = canonical_ip_address("10.0.0.1", &RuleId("r-1".to_string()), &mut warnings);
    assert_eq!(result, Ok(addr));
    assert!(warnings.is_empty());
}

#[test]
fn ipv6_accepted_as_is() {
    let mut warnings = Vec::new();
    let addr = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
    let result = canonical_ip_address("2001:db8::1", &RuleId("r-1".to_string()), &mut warnings);
    assert_eq!(result, Ok(addr));
    assert!(warnings.is_empty());
}

#[test]
fn ipv4_mapped_ipv6_normalized_to_ipv4() {
    let mut warnings = Vec::new();
    let result = canonical_ip_address(
        "::ffff:192.0.2.1",
        &RuleId("r-1".to_string()),
        &mut warnings,
    );
    assert_eq!(result, Ok(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
    assert!(warnings
        .iter()
        .any(|w| matches!(w, ValidationWarning::Ipv4MappedIpv6Normalized { .. })));
}

// ── Application normalization ─────────────────────────────────────────────

#[test]
fn process_name_exact_uppercased_lowercased() {
    let app = AppMatch {
        pattern: AppMatchPattern::Exact("Chrome.EXE".to_string()),
        include_child_processes: false,
        windows_service_name: None,
    };
    let mut warnings = Vec::new();
    let result = normalize_app_match(
        &app,
        ExecutableNaming::WindowsExe,
        &RuleId("r-1".to_string()),
        &mut warnings,
    )
    .expect("Exact pattern must normalize successfully");
    assert_eq!(result.pattern.as_str(), "chrome.exe");
    assert!(warnings.is_empty()); // uppercase → lowercase is silent, .exe already present
}

#[test]
fn process_name_exact_missing_exe_gets_appended_with_warning() {
    let app = AppMatch {
        pattern: AppMatchPattern::Exact("chrome".to_string()),
        include_child_processes: false,
        windows_service_name: None,
    };
    let mut warnings = Vec::new();
    let result = normalize_app_match(
        &app,
        ExecutableNaming::WindowsExe,
        &RuleId("r-1".to_string()),
        &mut warnings,
    )
    .expect("Exact pattern must normalize successfully");
    assert_eq!(result.pattern.as_str(), "chrome.exe");
    assert!(warnings
        .iter()
        .any(|w| matches!(w, ValidationWarning::ProcessNameMissingExeSuffix { .. })));
}

/// `.exe` is how Windows names a program. A Linux or macOS rule that gained it
/// warned about a "fix" the user could not undo and stored a name no file has.
#[test]
fn unix_rules_keep_their_names_and_raise_no_suffix_warning() {
    for platform in [HostPlatform::Linux, HostPlatform::MacOS] {
        let config = config_with_rules(
            Some(primary()),
            None,
            RouteBehaviorMode::PreferPrimary,
            vec![
                app_rule("r-1", "messenger-desktop"),
                app_rule("r-2", "org.example.messenger"),
                Rule {
                    app_match: Some(AppMatch {
                        pattern: AppMatchPattern::Glob("Codex*".to_string()),
                        include_child_processes: false,
                        windows_service_name: None,
                    }),
                    ..app_rule("r-3", "")
                },
            ],
            vec![],
        );
        let outcome = validate_and_canonicalize(&config, platform);
        let names: Vec<&str> = outcome
            .profile()
            .expect("accepted")
            .rule_book
            .primary
            .rules()
            .iter()
            .filter_map(|r| r.app_match.as_ref().map(|a| a.pattern.as_str()))
            .collect();
        assert_eq!(
            names.len(),
            3,
            "{platform:?}: every rule survives: {names:?}"
        );
        for expected in ["messenger-desktop", "org.example.messenger", "codex*"] {
            assert!(names.contains(&expected), "{platform:?}: {names:?}");
        }
        assert!(
            !outcome
                .warnings()
                .iter()
                .any(|w| matches!(w, ValidationWarning::ProcessNameMissingExeSuffix { .. })),
            "{platform:?}: {:?}",
            outcome.warnings()
        );
    }
}

#[test]
fn a_unix_path_is_still_reduced_to_its_file_name() {
    let app = AppMatch {
        pattern: AppMatchPattern::Exact("/usr/bin/Chat-Desktop".to_string()),
        include_child_processes: false,
        windows_service_name: None,
    };
    let mut warnings = Vec::new();
    let result = normalize_app_match(
        &app,
        ExecutableNaming::AsNamed,
        &RuleId("r-1".to_string()),
        &mut warnings,
    )
    .expect("Exact pattern must normalize successfully");
    assert_eq!(result.pattern.as_str(), "chat-desktop");
    assert!(warnings
        .iter()
        .all(|w| matches!(w, ValidationWarning::ProcessNameContainedPath { .. })));
}

#[test]
fn process_name_exact_windows_path_stripped_with_warning() {
    let app = AppMatch {
        pattern: AppMatchPattern::Exact(r"C:\Program Files\chrome.exe".to_string()),
        include_child_processes: false,
        windows_service_name: None,
    };
    let mut warnings = Vec::new();
    let result = normalize_app_match(
        &app,
        ExecutableNaming::WindowsExe,
        &RuleId("r-1".to_string()),
        &mut warnings,
    )
    .expect("Exact pattern must normalize successfully");
    assert_eq!(result.pattern.as_str(), "chrome.exe");
    assert!(warnings
        .iter()
        .any(|w| matches!(w, ValidationWarning::ProcessNameContainedPath { .. })));
}

#[test]
fn process_name_exact_double_slash_path_stripped() {
    let app = AppMatch {
        pattern: AppMatchPattern::Exact("//C//Program Files//chrome.exe".to_string()),
        include_child_processes: false,
        windows_service_name: None,
    };
    let mut warnings = Vec::new();
    let result = normalize_app_match(
        &app,
        ExecutableNaming::WindowsExe,
        &RuleId("r-1".to_string()),
        &mut warnings,
    )
    .expect("Exact pattern must normalize successfully");
    assert_eq!(result.pattern.as_str(), "chrome.exe");
    assert!(warnings
        .iter()
        .any(|w| matches!(w, ValidationWarning::ProcessNameContainedPath { .. })));
}

#[test]
fn process_name_exact_forward_slash_path_stripped() {
    let app = AppMatch {
        pattern: AppMatchPattern::Exact("C:/Program Files/firefox.exe".to_string()),
        include_child_processes: false,
        windows_service_name: None,
    };
    let mut warnings = Vec::new();
    let result = normalize_app_match(
        &app,
        ExecutableNaming::WindowsExe,
        &RuleId("r-1".to_string()),
        &mut warnings,
    )
    .expect("Exact pattern must normalize successfully");
    assert_eq!(result.pattern.as_str(), "firefox.exe");
}

#[test]
fn process_name_glob_is_lowercased() {
    let app = AppMatch {
        pattern: AppMatchPattern::Glob("*VPN*.EXE".to_string()),
        include_child_processes: false,
        windows_service_name: None,
    };
    let mut warnings = Vec::new();
    let result = normalize_app_match(
        &app,
        ExecutableNaming::WindowsExe,
        &RuleId("r-1".to_string()),
        &mut warnings,
    )
    .expect("Glob pattern must normalize successfully");
    assert_eq!(result.pattern.as_str(), "*vpn*.exe");
    assert!(warnings.is_empty());
}

#[test]
fn process_name_glob_bare_star_is_rejected() {
    let app = AppMatch {
        pattern: AppMatchPattern::Glob("*".to_string()),
        include_child_processes: false,
        windows_service_name: None,
    };
    let mut warnings = Vec::new();
    let result = normalize_app_match(
        &app,
        ExecutableNaming::WindowsExe,
        &RuleId("r-1".to_string()),
        &mut warnings,
    );
    assert!(matches!(
        result,
        Err(ValidationError::AppGlobTooWide { .. })
    ));
}

/// The matcher drops the directory and `.exe` before comparing, so these
/// name every process just as a bare `*` does.
#[test]
fn process_name_glob_that_reduces_to_a_bare_star_is_rejected() {
    for pattern in [
        r"C:\Games\*",
        "/opt/*",
        "*.exe",
        "*.EXE",
        "**",
        r"C:\Games\**.exe",
    ] {
        for naming in [ExecutableNaming::WindowsExe, ExecutableNaming::AsNamed] {
            let result = canonical_app_pattern(
                pattern,
                true,
                naming,
                &RuleId("r-1".to_string()),
                &mut Vec::new(),
            );
            assert!(
                matches!(result, Err(ValidationError::AppGlobTooWide { .. })),
                "{pattern}: {result:?}"
            );
        }
    }
    // Something left after the reduction still narrows the match.
    for pattern in [r"C:\Games\*game*.exe", "/opt/*torrent", r"C:\*\steam.exe"] {
        assert!(
            canonical_app_pattern(
                pattern,
                true,
                ExecutableNaming::WindowsExe,
                &RuleId("r-1".to_string()),
                &mut Vec::new(),
            )
            .is_ok(),
            "{pattern}"
        );
    }
}

#[test]
fn process_name_glob_accepted_no_exe_appended() {
    let app = AppMatch {
        pattern: AppMatchPattern::Glob("nord*".to_string()),
        include_child_processes: false,
        windows_service_name: None,
    };
    let mut warnings = Vec::new();
    let result = normalize_app_match(
        &app,
        ExecutableNaming::WindowsExe,
        &RuleId("r-1".to_string()),
        &mut warnings,
    )
    .expect("Glob pattern must normalize successfully");
    assert_eq!(result.pattern.as_str(), "nord*");
    assert!(warnings.is_empty()); // no .exe appended for globs
}

// ── Rule-level validation ─────────────────────────────────────────────────

#[test]
fn rule_with_empty_match_is_rejected() {
    let rule = Rule {
        id: RuleId("r-empty".to_string()),
        enabled: true,
        address_match: None,
        app_match: None,
        comment: String::new(),
        action: crate::canonical::RuleAction::Route,
        origin: None,
    };
    let config = config_with_rules(
        Some(primary()),
        Some(secondary()),
        RouteBehaviorMode::PreferPrimary,
        vec![rule],
        vec![],
    );
    let outcome = validate_and_canonicalize(&config, HostPlatform::Windows);
    assert!(!outcome.is_accepted());
    assert!(outcome
        .errors()
        .iter()
        .any(|e| matches!(e, ValidationError::RuleEmptyMatch { .. })));
}

#[test]
fn ipv6_rule_is_accepted() {
    let rule = ip_rule(
        "r-v6",
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
    );
    let config = config_with_rules(
        Some(primary()),
        Some(secondary()),
        RouteBehaviorMode::PreferPrimary,
        vec![rule],
        vec![],
    );
    let outcome = validate_and_canonicalize(&config, HostPlatform::Windows);
    assert!(outcome.is_accepted(), "{:?}", outcome.errors());
}

// ── Deduplication ─────────────────────────────────────────────────────────

#[test]
fn duplicate_within_set_deduplicated_with_warning() {
    let config = config_with_rules(
        Some(primary()),
        Some(secondary()),
        RouteBehaviorMode::PreferPrimary,
        vec![
            domain_rule("r-1", "example.com"),
            domain_rule("r-2", "example.com"), // duplicate
        ],
        vec![],
    );
    let outcome = validate_and_canonicalize(&config, HostPlatform::Windows);
    assert!(outcome.is_accepted());
    let profile = outcome.profile().expect("profile must be present");
    assert_eq!(profile.rule_book.primary.len(), 1);
    assert!(outcome
        .warnings()
        .iter()
        .any(|w| matches!(w, ValidationWarning::DuplicateRuleInSameSet { .. })));
}

/// Two rules over the same destination that say OPPOSITE things are not
/// duplicates. Folding them dropped one instruction and reported it as a
/// removed duplicate, so a `+block` next to a plain route silently lost the
/// block (or the route, depending on which came first).
#[test]
fn a_rule_and_its_opposite_over_the_same_destination_both_survive() {
    let blocked = Rule {
        action: crate::canonical::RuleAction::Block,
        ..domain_rule("r-block", "example.com")
    };
    let config = config_with_rules(
        Some(primary()),
        Some(secondary()),
        RouteBehaviorMode::PreferPrimary,
        vec![domain_rule("r-route", "example.com"), blocked],
        vec![],
    );
    let outcome = validate_and_canonicalize(&config, HostPlatform::Windows);
    assert!(outcome.is_accepted());
    let profile = outcome.profile().expect("profile must be present");
    assert_eq!(profile.rule_book.primary.len(), 2);
    assert!(!outcome
        .warnings()
        .iter()
        .any(|w| matches!(w, ValidationWarning::DuplicateRuleInSameSet { .. })));
}

/// A disabled copy is not a duplicate of the enabled one either — keeping
/// the first-seen row meant a commented-out line above an active one left
/// the DISABLED copy in the set.
#[test]
fn a_disabled_copy_does_not_swallow_the_enabled_rule() {
    let disabled = Rule {
        enabled: false,
        ..domain_rule("r-off", "example.com")
    };
    let config = config_with_rules(
        Some(primary()),
        Some(secondary()),
        RouteBehaviorMode::PreferPrimary,
        vec![disabled, domain_rule("r-on", "example.com")],
        vec![],
    );
    let outcome = validate_and_canonicalize(&config, HostPlatform::Windows);
    let profile = outcome.profile().expect("profile must be present");
    assert!(profile
        .rule_book
        .primary
        .rules()
        .iter()
        .any(|r| r.enabled && r.id.0 == "r-on"));
}

#[test]
fn duplicate_across_sets_produces_warning_not_error() {
    let config = config_with_rules(
        Some(primary()),
        Some(secondary()),
        RouteBehaviorMode::PreferPrimary,
        vec![domain_rule("r-pri", "example.com")],
        vec![domain_rule("r-sec", "example.com")],
    );
    let outcome = validate_and_canonicalize(&config, HostPlatform::Windows);
    assert!(outcome.is_accepted()); // not rejected
                                    // Both rules are kept — cross-set duplicate is a warning for the GUI
    let profile = outcome.profile().expect("profile must be present");
    assert_eq!(profile.rule_book.primary.len(), 1);
    assert_eq!(profile.rule_book.secondary.len(), 1);
    assert!(outcome
        .warnings()
        .iter()
        .any(|w| matches!(w, ValidationWarning::DuplicateRuleAcrossSets { .. })));
}

// ── Canonical profile contents ────────────────────────────────────────────

#[test]
fn canonical_profile_has_correct_binding_and_mode() {
    let config = config_with_rules(
        Some(primary()),
        Some(secondary()),
        RouteBehaviorMode::StrictSecondaryFailClosed,
        vec![],
        vec![],
    );
    let outcome = validate_and_canonicalize(&config, HostPlatform::Windows);
    let profile = outcome.profile().expect("profile must be present");
    assert_eq!(profile.primary.adapter.stable_id, "eth0");
    assert_eq!(
        profile
            .secondary
            .as_ref()
            .map(|b| b.adapter.stable_id.as_str()),
        Some("vpn0")
    );
    assert_eq!(
        profile.behavior_mode,
        RouteBehaviorMode::StrictSecondaryFailClosed
    );
}

#[test]
fn canonical_profile_rules_are_in_canonical_order() {
    // Insert rules in non-canonical order: app, ip, domain.
    let config = config_with_rules(
        Some(primary()),
        None,
        RouteBehaviorMode::PreferPrimary,
        vec![
            app_rule("r-app", "firefox"),
            ip_rule("r-ip", IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            domain_rule("r-dom", "example.com"),
        ],
        vec![],
    );
    let outcome = validate_and_canonicalize(&config, HostPlatform::Windows);
    let profile = outcome.profile().expect("profile must be present");
    let types: Vec<&str> = profile
        .rule_book
        .primary
        .rules()
        .iter()
        .map(|r| match &r.address_match {
            Some(CanonicalAddressMatch::Zone(_)) => "zone",
            Some(CanonicalAddressMatch::ExactFqdn(_) | CanonicalAddressMatch::SuffixDomain(_)) => {
                "domain"
            }
            Some(CanonicalAddressMatch::ExactIp(_)) => "ip",
            None => "app",
        })
        .collect();
    assert_eq!(types, ["domain", "ip", "app"]);
}

#[test]
fn equivalent_configs_different_rule_order_produce_equal_profiles() {
    let rules_a = vec![
        domain_rule("r-1", "example.com"),
        ip_rule("r-2", IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8))),
    ];
    let rules_b = vec![
        ip_rule("r-2", IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8))),
        domain_rule("r-1", "example.com"),
    ];

    let profile_a = validate_and_canonicalize(
        &config_with_rules(
            Some(primary()),
            None,
            RouteBehaviorMode::PreferPrimary,
            rules_a,
            vec![],
        ),
        HostPlatform::Windows,
    )
    .profile()
    .cloned()
    .expect("profile a");

    let profile_b = validate_and_canonicalize(
        &config_with_rules(
            Some(primary()),
            None,
            RouteBehaviorMode::PreferPrimary,
            rules_b,
            vec![],
        ),
        HostPlatform::Windows,
    )
    .profile()
    .cloned()
    .expect("profile b");

    assert_eq!(profile_a.rule_book, profile_b.rule_book);
}

#[test]
fn domain_case_variants_produce_equal_canonical_rules() {
    let config_upper = config_with_rules(
        Some(primary()),
        None,
        RouteBehaviorMode::PreferPrimary,
        vec![domain_rule("r-1", "EXAMPLE.COM")],
        vec![],
    );
    let config_lower = config_with_rules(
        Some(primary()),
        None,
        RouteBehaviorMode::PreferPrimary,
        vec![domain_rule("r-1", "example.com")],
        vec![],
    );

    let book_upper = validate_and_canonicalize(&config_upper, HostPlatform::Windows)
        .profile()
        .cloned()
        .expect("upper profile")
        .rule_book;
    let book_lower = validate_and_canonicalize(&config_lower, HostPlatform::Windows)
        .profile()
        .cloned()
        .expect("lower profile")
        .rule_book;

    assert_eq!(book_upper, book_lower);
}

#[test]
fn comment_is_trimmed_in_canonical_rule() {
    let mut rule = domain_rule("r-1", "example.com");
    rule.comment = "  my comment  ".to_string();

    let config = config_with_rules(
        Some(primary()),
        None,
        RouteBehaviorMode::PreferPrimary,
        vec![rule],
        vec![],
    );
    let outcome = validate_and_canonicalize(&config, HostPlatform::Windows);
    let profile = outcome.profile().expect("profile");
    let canonical_rule = &profile.rule_book.primary.rules()[0];
    assert_eq!(canonical_rule.comment, "my comment");
}

#[test]
fn multiple_errors_all_collected() {
    // Two rules with empty match conditions — both errors must be reported.
    let r1 = Rule {
        id: RuleId("r-1".to_string()),
        enabled: true,
        address_match: None,
        app_match: None,
        comment: String::new(),
        action: crate::canonical::RuleAction::Route,
        origin: None,
    };
    let r2 = Rule {
        id: RuleId("r-2".to_string()),
        enabled: true,
        address_match: None,
        app_match: None,
        comment: String::new(),
        action: crate::canonical::RuleAction::Route,
        origin: None,
    };
    let config = config_with_rules(
        Some(primary()),
        None,
        RouteBehaviorMode::PreferPrimary,
        vec![r1, r2],
        vec![],
    );
    let outcome = validate_and_canonicalize(&config, HostPlatform::Windows);
    assert!(!outcome.is_accepted());
    assert_eq!(
        outcome
            .errors()
            .iter()
            .filter(|e| matches!(e, ValidationError::RuleEmptyMatch { .. }))
            .count(),
        2
    );
}

#[test]
fn a_rule_enabled_in_both_sets_is_reported_once_with_what_it_matches() {
    let book = CanonicalRuleBook {
        primary: CanonicalRuleSet::from_rules(vec![
            rule_with("R-0001", "example.com", true),
            rule_with("R-0002", "only-primary.com", true),
        ]),
        secondary: CanonicalRuleSet::from_rules(vec![rule_with("R-0003", "example.com", true)]),
    };

    let found = enabled_duplicates_across_sets(&book);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].primary_rule_id.as_str(), "R-0001");
    assert_eq!(found[0].secondary_rule_id.as_str(), "R-0003");
    assert_eq!(found[0].match_summary, "example.com");
}

#[test]
fn a_copy_the_user_already_disabled_is_not_asked_about_again() {
    // Disabling one copy is the resolution offered for this exact pair, so
    // reporting the pair afterwards would re-open a settled question.
    let book = CanonicalRuleBook {
        primary: CanonicalRuleSet::from_rules(vec![rule_with("R-0001", "example.com", true)]),
        secondary: CanonicalRuleSet::from_rules(vec![rule_with("R-0003", "example.com", false)]),
    };
    assert!(enabled_duplicates_across_sets(&book).is_empty());
}

/// One enabled/disabled domain rule. The route comes from the set the rule
/// is placed in, so it is not part of the rule itself.
fn rule_with(id: &str, host: &str, enabled: bool) -> CanonicalRule {
    CanonicalRule {
        id: RuleId(id.to_string()),
        enabled,
        address_match: Some(CanonicalAddressMatch::ExactFqdn(host.to_string())),
        app_match: None,
        comment: String::new(),
        action: crate::canonical::RuleAction::Route,
        origin: None,
    }
}

// ── Rule cap ──────────────────────────────────────────────────────────────

fn many_domain_rules(n: usize, prefix: &str) -> Vec<Rule> {
    (0..n)
        .map(|i| domain_rule(&format!("{prefix}-{i}"), &format!("{prefix}{i}.test")))
        .collect()
}

#[test]
fn a_book_at_the_rule_cap_is_accepted_and_one_past_it_is_refused() {
    let cap = nrr_shared::rules_json::FREE_MAX_RULES;
    let with = |n: usize| {
        // Split across both routes: the cap is on the book, not a route.
        let config = config_with_rules(
            Some(primary()),
            Some(secondary()),
            RouteBehaviorMode::PreferPrimary,
            many_domain_rules(n / 2, "p"),
            many_domain_rules(n - n / 2, "s"),
        );
        validate_and_canonicalize(&config, HostPlatform::Windows)
    };
    assert!(with(cap).is_accepted());
    match with(cap + 1) {
        ValidationOutcome::Rejected { errors, .. } => assert_eq!(
            errors,
            vec![ValidationError::TooManyRules {
                count: cap + 1,
                limit: cap
            }]
        ),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn app_authored_rules_spend_their_own_allowance_not_the_users() {
    let cap = nrr_shared::rules_json::FREE_MAX_RULES;
    let auto_cap = crate::auto_rule_budget::MAX_AUTO_RULES;
    let auto = |n: usize| {
        many_domain_rules(n, "a")
            .into_iter()
            .map(|rule| Rule {
                origin: Some(crate::RuleOrigin::auto(
                    crate::AutoRuleReason::SiteCompanion,
                    "site.example",
                    "2026-01-01",
                )),
                ..rule
            })
            .collect::<Vec<_>>()
    };
    let with = |n_auto: usize| {
        let config = config_with_rules(
            Some(primary()),
            Some(secondary()),
            RouteBehaviorMode::PreferPrimary,
            many_domain_rules(cap, "u"),
            auto(n_auto),
        );
        validate_and_canonicalize(&config, HostPlatform::Windows)
    };
    assert!(with(auto_cap).is_accepted());
    // A file on its own does not know the book it lands in, so the app's
    // budget is the service write's to hold; a pre-budget export reads back.
    assert!(with(auto_cap + 500).is_accepted());
}

/// The app's allowance is its own ceiling, not headroom left over by the
/// user: a book with few rules of the user's still cannot carry more
/// app-authored ones than their budget.
#[test]
fn app_authored_rules_are_capped_even_when_the_user_has_few() {
    let auto_cap = crate::auto_rule_budget::MAX_AUTO_RULES;
    let flags = |user: usize, auto: usize| {
        std::iter::repeat_n(true, user).chain(std::iter::repeat_n(false, auto))
    };
    assert_eq!(rule_cap_excess(flags(10, auto_cap), Some(auto_cap)), None);
    assert_eq!(
        rule_cap_excess(flags(10, auto_cap + 1), Some(auto_cap)),
        Some(RuleCapExcess::Auto {
            count: auto_cap + 1,
            limit: auto_cap
        })
    );
    assert_eq!(
        rule_cap_excess(flags(10, auto_cap + 1), None),
        None,
        "no book to hold the app's rules against"
    );
    let cap = nrr_shared::rules_json::FREE_MAX_RULES;
    for auto_limit in [Some(auto_cap), None] {
        assert_eq!(
            rule_cap_excess(flags(cap + 1, auto_cap + 1), auto_limit),
            Some(RuleCapExcess::User {
                count: cap + 1,
                limit: cap
            }),
            "the user's own cap is absolute and its overrun the one to report",
        );
    }
}

/// A book saved before the budget stays editable at its size, and cannot grow.
#[test]
fn the_app_allowance_is_the_budget_or_what_the_book_already_holds() {
    use crate::auto_rule_budget::{auto_rule_allowance, MAX_AUTO_RULES};
    assert_eq!(auto_rule_allowance(0), MAX_AUTO_RULES);
    assert_eq!(auto_rule_allowance(1_999), MAX_AUTO_RULES);
    assert_eq!(auto_rule_allowance(2_500), 2_500);
    let auto = |n: usize| std::iter::repeat_n(false, n);
    assert_eq!(
        rule_cap_excess(auto(2_500), Some(auto_rule_allowance(2_500))),
        None
    );
    assert_eq!(
        rule_cap_excess(auto(2_400), Some(auto_rule_allowance(2_500))),
        None
    );
    assert_eq!(
        rule_cap_excess(auto(2_501), Some(auto_rule_allowance(2_500))),
        Some(RuleCapExcess::Auto {
            count: 2_501,
            limit: 2_500
        })
    );
    assert_eq!(
        rule_cap_excess(auto(2_001), Some(auto_rule_allowance(1_999))),
        Some(RuleCapExcess::Auto {
            count: 2_001,
            limit: MAX_AUTO_RULES
        })
    );
}
