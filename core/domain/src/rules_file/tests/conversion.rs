use super::*;

// ── rules_file_to_route_rule_set ─────────────────────────────────────────

#[test]
fn converter_produces_rules_for_active_sections() {
    let outcome = parse_rules_file(SAMPLE_FILE);
    let rule_set = rules_file_to_route_rule_set(&outcome.parsed, HostPlatform::Windows, false);
    // Zones: 1, Domains: 3 (2 enabled + 1 disabled), IP: 1, Windows: 2
    assert_eq!(rule_set.rules.len(), 7);
}

#[test]
fn converter_excludes_linux_section_on_windows() {
    let input = "--- Linux\ncurl\n--- Windows\nbrowser.exe\n";
    let outcome = parse_rules_file(input);
    let rule_set = rules_file_to_route_rule_set(&outcome.parsed, HostPlatform::Windows, false);
    assert_eq!(rule_set.rules.len(), 1);
    assert_eq!(rule_set.rules[0].comment, "");
}

#[test]
fn converter_preserves_enabled_flag() {
    let outcome = parse_rules_file(SAMPLE_FILE);
    let rule_set = rules_file_to_route_rule_set(&outcome.parsed, HostPlatform::Windows, false);
    let disabled: Vec<_> = rule_set.rules.iter().filter(|r| !r.enabled).collect();
    // old.example.com + powershell.exe = 2 disabled
    assert_eq!(disabled.len(), 2);
}

#[test]
fn converter_sets_include_child_processes_from_param() {
    let input = "--- Windows\nbrowser.exe\n";
    let outcome = parse_rules_file(input);
    let with_icp = rules_file_to_route_rule_set(&outcome.parsed, HostPlatform::Windows, true);
    let without_icp = rules_file_to_route_rule_set(&outcome.parsed, HostPlatform::Windows, false);
    assert!(with_icp.rules[0]
        .app_match
        .as_ref()
        .is_some_and(|a| a.include_child_processes));
    assert!(!without_icp.rules[0]
        .app_match
        .as_ref()
        .is_none_or(|a| a.include_child_processes));
}

#[test]
fn converter_inline_comment_becomes_rule_comment() {
    let outcome = parse_rules_file(SAMPLE_FILE);
    let rule_set = rules_file_to_route_rule_set(&outcome.parsed, HostPlatform::Windows, false);
    let browser = rule_set
        .rules
        .iter()
        .find(|r| {
            r.app_match
                .as_ref()
                .is_some_and(|a| a.pattern.as_str() == "browser.exe")
        })
        .expect("browser.exe rule not found");
    assert_eq!(browser.comment, "browser traffic");
}

#[test]
fn converter_rule_ids_have_r_prefix() {
    let outcome = parse_rules_file(SAMPLE_FILE);
    let rule_set = rules_file_to_route_rule_set(&outcome.parsed, HostPlatform::Windows, false);
    for rule in &rule_set.rules {
        assert!(
            rule.id.as_str().starts_with("r-"),
            "rule ID '{}' does not start with 'r-'",
            rule.id
        );
    }
}

// ── Pipeline integration (parse → validate) ──────────────────────────────

#[test]
fn full_pipeline_parse_then_validate() {
    use crate::{
        validation::validate_and_canonicalize, ActiveConfiguration, AdapterIdentity, BindingSource,
        RouteBehaviorMode, RouteBinding, RuleBook,
    };
    use nrr_shared::RouteRole;

    let primary_input = "--- Domains\ncorp.example.net\n--- IP\n203.0.113.7\n";
    let secondary_input = "--- Windows\nbrowser.exe  # browser\n";

    let primary_parsed = parse_rules_file(primary_input);
    let secondary_parsed = parse_rules_file(secondary_input);

    let primary_set =
        rules_file_to_route_rule_set(&primary_parsed.parsed, HostPlatform::Windows, false);
    let secondary_set =
        rules_file_to_route_rule_set(&secondary_parsed.parsed, HostPlatform::Windows, false);

    let config = ActiveConfiguration {
        primary: Some(RouteBinding {
            role: RouteRole::Primary,
            adapter: AdapterIdentity {
                stable_id: "eth0".to_string(),
                display_name: "Ethernet".to_string(),
            },
            source: BindingSource::UserAssigned,
        }),
        secondary: Some(RouteBinding {
            role: RouteRole::Secondary,
            adapter: AdapterIdentity {
                stable_id: "vpn0".to_string(),
                display_name: "VPN".to_string(),
            },
            source: BindingSource::UserAssigned,
        }),
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        rule_book: RuleBook {
            primary: primary_set,
            secondary: secondary_set,
        },
    };

    let outcome = validate_and_canonicalize(&config);
    assert!(
        outcome.is_accepted(),
        "pipeline rejected with warnings: {:?}",
        outcome
    );
}

/// The GUI writes its own preset files, so it declares the format version
/// itself. A file it saves can carry version-4 constructs (`--- Auto`,
/// `+block`) — a header claiming an older version tells the next reader
/// they are not there.
#[test]
fn the_gui_writes_the_current_preset_format_version() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../apps/desktop/qml/lib/rules.js");
    let source =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

    const DECL: &str = "var CANONICAL_PRESET_FORMAT_VERSION = ";
    let declared: u32 = source
        .lines()
        .find_map(|line| line.trim().strip_prefix(DECL))
        .unwrap_or_else(|| panic!("`{DECL}` is gone from rules.js"))
        .trim()
        .parse()
        .expect("the declared version is a number");
    assert_eq!(
        declared, CURRENT_PRESET_FORMAT_VERSION,
        "rules.js declares preset format version {declared}, this build writes \
             {CURRENT_PRESET_FORMAT_VERSION}"
    );

    // The header the GUI emits must also be the one the parser reads back.
    let header =
        format!("# NetRuleRouter preset \u{2014} version {declared}\n--- Domains\nexample.com\n");
    assert_eq!(
        parse_rules_file(&header).file_format_version,
        Some(CURRENT_PRESET_FORMAT_VERSION)
    );
}

/// Verified against the presets this repository ships: 32 of them declare
/// their version with an ASCII hyphen and 4 with an em-dash. Rejecting the
/// hyphen meant `file_format_version` was `None` on nearly every real file.
#[test]
fn a_version_header_is_read_with_any_dash_a_keyboard_produces() {
    for dash in ["\u{2014}", "\u{2013}", "-"] {
        let preset = format!("# NetRuleRouter preset {dash} version 4\n--- Domains\nexample.com\n");
        assert_eq!(
            parse_rules_file(&preset).file_format_version,
            Some(4),
            "preset header with {dash:?}"
        );

        let rules =
            format!("# NetRuleRouter rules file {dash} version 4\n--- Domains\nexample.com\n");
        assert_eq!(
            parse_rules_file(&rules).file_format_version,
            Some(4),
            "rules-file header with {dash:?}"
        );
    }

    // Positive control: a dash outside the accepted set, and a line that is
    // not the header at all, are still not a version declaration.
    assert_eq!(
        parse_rules_file("# NetRuleRouter preset ~ version 4\n").file_format_version,
        None
    );
    assert_eq!(
        parse_rules_file("# something else \u{2014} version 4\n").file_format_version,
        None
    );
}
