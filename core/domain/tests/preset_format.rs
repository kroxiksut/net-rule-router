//! Preset format and Free/Pro compatibility.
//!
//! These tests verify the design decisions documented in docs/en/rules-file-format.md
//! Forward compatibility and Preset Files sections, and in CLAUDE.md under "Free vs Pro Configuration Model":
//!
//! - A preset is two independent txt files (one per route), same syntax as
//!   working rules files.
//! - Metadata header comments (`name`, `description`, `author`,
//!   `preset_version`) are optional and captured in `PresetMetadata`.
//! - Pro-only sections (`CIDR`, `Ports`, …) are parsed and preserved but
//!   **not** applied. They are reported via `ParseWarning::UnknownSection`.
//! - Round-trip guarantee: Free → Pro → Free without data loss. Pro-only
//!   entries survive unmodified in `unknown_sections`.
//! - A file with only Free-edition sections is always valid for Pro without
//!   transformation.
//! - An absent route file (the optional second file) is represented by an
//!   empty string — always valid.

use nrr_domain::rules_file::{
    parse_rules_file, HostPlatform, ParseWarning, RulesFileSection, CURRENT_PRESET_FORMAT_VERSION,
};

// ── preset file two-file independence ────────────────────────────────────────

#[test]
fn absent_route_file_is_valid_empty_outcome() {
    // An absent file is modelled as an empty string. Parsing must succeed with
    // no sections and no warnings — absence of one route file is not an error.
    let outcome = parse_rules_file("");
    assert!(outcome.parsed.sections.is_empty());
    assert!(outcome.unknown_sections.is_empty());
    assert!(outcome.warnings.is_empty());
    assert!(outcome.preset_metadata.is_none());
}

#[test]
fn preset_file_with_only_primary_route_is_valid() {
    // Simulates the user sharing only a primary-route file without a secondary.
    let primary = "# NetRuleRouter preset \u{2014} version 1\n\
                   --- Domains\nexample.com\n";
    let outcome = parse_rules_file(primary);
    assert!(outcome.preset_metadata.is_some());
    let domains = outcome.parsed.entries_for(RulesFileSection::Domains);
    assert_eq!(domains.len(), 1);
    // No secondary file needed — parsing the primary alone is self-contained.
}

// ── preset metadata ───────────────────────────────────────────────────────────

#[test]
fn all_metadata_keys_captured_from_preset_header() {
    let input = "\
# NetRuleRouter preset \u{2014} version 1
# name: Corporate VPN Rules
# description: Routes corporate traffic via VPN
# author: Jane Doe
# preset_version: 2

--- Domains
corp.example.com
";
    let outcome = parse_rules_file(input);
    let meta = outcome
        .preset_metadata
        .as_ref()
        .expect("preset_metadata must be Some when preset header is present");
    assert_eq!(meta.name.as_deref(), Some("Corporate VPN Rules"));
    assert_eq!(
        meta.description.as_deref(),
        Some("Routes corporate traffic via VPN")
    );
    assert_eq!(meta.author.as_deref(), Some("Jane Doe"));
    assert_eq!(meta.preset_version.as_deref(), Some("2"));
}

#[test]
fn metadata_keys_are_optional_any_subset_is_valid() {
    // Only `name` present — the other fields must be None without error.
    let input = "# name: Minimal preset\n--- Domains\nexample.com\n";
    let outcome = parse_rules_file(input);
    let meta = outcome
        .preset_metadata
        .as_ref()
        .expect("metadata should be Some");
    assert_eq!(meta.name.as_deref(), Some("Minimal preset"));
    assert!(meta.description.is_none());
    assert!(meta.author.is_none());
    assert!(meta.preset_version.is_none());
}

#[test]
fn no_metadata_at_all_gives_none_preset_metadata() {
    // A plain rules file with no preamble metadata is not a "preset file"
    // and should produce None for preset_metadata.
    let input = "--- Domains\nexample.com\n";
    let outcome = parse_rules_file(input);
    assert!(outcome.preset_metadata.is_none());
}

#[test]
fn preset_file_without_any_metadata_keys_but_with_preset_header() {
    // The preset header alone (no key-value lines) makes preset_metadata Some
    // but with all fields None (is_empty() == true).
    let input = "# NetRuleRouter preset \u{2014} version 1\n--- Domains\nexample.com\n";
    let outcome = parse_rules_file(input);
    let meta = outcome
        .preset_metadata
        .as_ref()
        .expect("preset header must set preset_metadata");
    assert!(meta.is_empty());
}

// ── forward-compatibility: Pro-only sections ──────────────────────────────────

#[test]
fn pro_only_sections_produce_unknown_section_warnings() {
    // CIDR and Ports are Pro-edition sections. The Free parser must flag them
    // via `ParseWarning::UnknownSection` — they are not errors.
    let input = "--- Domains\nexample.com\n--- CIDR\n10.0.0.0/8\n--- Ports\n443\n";
    let outcome = parse_rules_file(input);

    let unknown_names: Vec<&str> = outcome
        .unknown_sections
        .iter()
        .map(|s| s.name.as_str())
        .collect();
    assert!(
        unknown_names.contains(&"CIDR"),
        "CIDR must be in unknown_sections"
    );
    assert!(
        unknown_names.contains(&"Ports"),
        "Ports must be in unknown_sections"
    );

    let warning_names: Vec<&str> = outcome
        .warnings
        .iter()
        .filter_map(|w| {
            if let ParseWarning::UnknownSection { name, .. } = w {
                Some(name.as_str())
            } else {
                None
            }
        })
        .collect();
    assert!(warning_names.contains(&"CIDR"));
    assert!(warning_names.contains(&"Ports"));
}

#[test]
fn pro_only_sections_not_in_parsed_active_sections() {
    // Pro sections must NOT appear in `parsed.sections` — they are never
    // applied to routing policy in the Free edition.
    let input = "--- Domains\nexample.com\n--- CIDR\n10.0.0.0/8\n";
    let outcome = parse_rules_file(input);

    let known_names: Vec<&str> = outcome
        .parsed
        .sections
        .iter()
        .map(|s| s.section.name())
        .collect();
    assert!(
        !known_names.contains(&"CIDR"),
        "CIDR must not appear in parsed.sections"
    );
}

#[test]
fn pro_only_section_entries_preserved_with_correct_count() {
    let input = "--- CIDR\n10.0.0.0/8\n192.168.0.0/16\n--- Ports\n443\n";
    let outcome = parse_rules_file(input);

    let cidr = outcome
        .unknown_sections
        .iter()
        .find(|s| s.name == "CIDR")
        .unwrap();
    assert_eq!(cidr.entries.len(), 2);
    assert_eq!(cidr.entries[0].match_value, "10.0.0.0/8");
    assert_eq!(cidr.entries[1].match_value, "192.168.0.0/16");

    let ports = outcome
        .unknown_sections
        .iter()
        .find(|s| s.name == "Ports")
        .unwrap();
    assert_eq!(ports.entries.len(), 1);
    assert_eq!(ports.entries[0].match_value, "443");

    // Warnings carry correct entry counts.
    assert!(matches!(
        outcome
            .warnings
            .iter()
            .find(|w| matches!(w, ParseWarning::UnknownSection { name, .. } if name == "CIDR")),
        Some(ParseWarning::UnknownSection { entry_count: 2, .. })
    ));
}

// ── round-trip guarantee (Free → Pro → Free) ──────────────────────────────────

#[test]
fn round_trip_free_to_pro_no_data_loss() {
    // After a Free-edition parse, all data must be accessible:
    //   - Free sections in `parsed`
    //   - Pro-only sections in `unknown_sections`
    // Both together represent the full file content — no entry is silently dropped.
    let input = "\
--- Zones\ncorp-internal\n\
--- Domains\nexample.com\n\
--- CIDR\n10.0.0.0/8\n\
--- Ports\n443\n";

    let outcome = parse_rules_file(input);

    // Free sections intact.
    assert_eq!(outcome.parsed.entries_for(RulesFileSection::Zones).len(), 1);
    assert_eq!(
        outcome.parsed.entries_for(RulesFileSection::Domains).len(),
        1
    );

    // Pro sections preserved.
    assert_eq!(outcome.unknown_sections.len(), 2);
    let cidr = outcome
        .unknown_sections
        .iter()
        .find(|s| s.name == "CIDR")
        .unwrap();
    let ports = outcome
        .unknown_sections
        .iter()
        .find(|s| s.name == "Ports")
        .unwrap();
    assert_eq!(cidr.entries[0].match_value, "10.0.0.0/8");
    assert_eq!(ports.entries[0].match_value, "443");
}

#[test]
fn pro_sections_inline_comments_preserved_in_round_trip() {
    let input = "--- CIDR\n10.0.0.0/8  # internal range\n";
    let outcome = parse_rules_file(input);
    let cidr = outcome
        .unknown_sections
        .iter()
        .find(|s| s.name == "CIDR")
        .unwrap();
    assert_eq!(
        cidr.entries[0].inline_comment.as_deref(),
        Some("internal range")
    );
}

#[test]
fn pro_sections_disabled_entries_preserved_in_round_trip() {
    let input = "--- CIDR\n# 10.0.0.0/8\n";
    let outcome = parse_rules_file(input);
    let cidr = outcome
        .unknown_sections
        .iter()
        .find(|s| s.name == "CIDR")
        .unwrap();
    assert_eq!(cidr.entries.len(), 1);
    assert!(!cidr.entries[0].enabled);
    assert_eq!(cidr.entries[0].match_value, "10.0.0.0/8");
}

// ── free-only file is always valid for Pro ────────────────────────────────────

#[test]
fn free_only_file_has_no_unknown_sections_and_no_warnings() {
    // A file that contains only Free-edition sections must produce no warnings
    // and no unknown sections — it is always valid input for both editions.
    let input = "\
# NetRuleRouter preset \u{2014} version 1
--- Zones\ncorp-internal\n\
--- Domains\nexample.com\n\
--- IP\n203.0.113.7\n\
--- Windows\nbrowser.exe\n\
--- Linux\n\
--- MacOS\n";

    let outcome = parse_rules_file(input);
    assert!(
        outcome.unknown_sections.is_empty(),
        "free-only preset must have no unknown sections"
    );
    assert!(
        outcome.warnings.is_empty(),
        "free-only preset must produce no warnings"
    );
}

// ── fixture round-trip ────────────────────────────────────────────────────────

#[test]
fn fixture_preset_with_pro_sections_parses_correctly() {
    let content = include_str!("fixtures/preset_with_pro_sections.txt");
    let outcome = parse_rules_file(content);

    // Preset header present.
    assert!(outcome.preset_metadata.is_some());
    assert_eq!(
        outcome.file_format_version,
        Some(CURRENT_PRESET_FORMAT_VERSION)
    );

    // Free sections parsed.
    assert!(!outcome
        .parsed
        .entries_for(RulesFileSection::Zones)
        .is_empty());
    assert!(!outcome
        .parsed
        .entries_for(RulesFileSection::Domains)
        .is_empty());

    // Pro sections preserved but not applied.
    assert!(!outcome.unknown_sections.is_empty());
    assert!(outcome.unknown_sections.iter().any(|s| s.name == "CIDR"));
    assert!(outcome.unknown_sections.iter().any(|s| s.name == "Ports"));

    // Warnings for Pro sections (no format-version warning — version is current).
    assert!(outcome
        .warnings
        .iter()
        .all(|w| matches!(w, ParseWarning::UnknownSection { .. })));

    // Metadata captured.
    let meta = outcome.preset_metadata.as_ref().unwrap();
    assert!(meta.name.is_some());
    assert!(meta.description.is_some());
}

#[test]
fn fixture_preset_pro_sections_not_routed_on_windows() {
    use nrr_domain::rules_file::rules_file_to_route_rule_set;

    let content = include_str!("fixtures/preset_with_pro_sections.txt");
    let outcome = parse_rules_file(content);

    // Only Free sections contribute to routing.
    let rule_set = rules_file_to_route_rule_set(&outcome.parsed, HostPlatform::Windows, false);

    // Pro CIDR/Ports entries must not appear in the rule set.
    for rule in &rule_set.rules {
        let v = rule
            .address_match
            .as_ref()
            .map(|a| format!("{a:?}"))
            .unwrap_or_default();
        assert!(
            !v.contains("10.0.0.0/8") && !v.contains("443"),
            "Pro-only entry must not appear in routing rule set, found: {v}"
        );
    }
}
