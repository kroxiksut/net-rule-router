use super::*;

// ── write_rules_file ──────────────────────────────────────────────────────

/// The raw body must come back out as a section the parser recognises as
/// unknown — emitting bytes is only preservation if the result still reads
/// as a section on the next import.
#[test]
fn a_carried_passthrough_section_parses_back_as_an_unknown_section() {
    let parsed = parse_rules_file(
        "--- Domains
example.com
",
    )
    .parsed;
    let carried = [PassthroughSection {
        name: "CIDR".to_string(),
        body: "10.0.0.0/8
"
        .to_string(),
    }];

    let text = write_rules_file_with_passthrough(&parsed, &[], &carried, None);
    let outcome = parse_rules_file(&text);
    let names: Vec<&str> = outcome
        .unknown_sections
        .iter()
        .map(|s| s.name.as_str())
        .collect();
    assert_eq!(
        names,
        vec!["CIDR"],
        "written text:
{text}"
    );
    assert_eq!(
        outcome.unknown_sections[0].entries[0].match_value, "10.0.0.0/8",
        "written text:
{text}"
    );
}

#[test]
fn write_empty_parsed_returns_empty_string() {
    // With no sections in input and no metadata, output is empty —
    // the writer emits only what's structurally present (round-trip
    // symmetry with the parser).
    let parsed = RulesFileParsed::default();
    let text = write_rules_file(&parsed, &[], None);
    assert!(text.is_empty(), "got {text:?}");
}

#[test]
fn write_preserves_empty_section_when_present_in_input() {
    // docs/en/rules-file-format.md Sections — a section header with no entries is preserved on
    // export. The writer relies on the section being explicit in input.
    let parsed = RulesFileParsed {
        sections: vec![
            SectionContent {
                section: RulesFileSection::Zones,
                entries: vec![],
            },
            SectionContent {
                section: RulesFileSection::Domains,
                entries: vec![RulesFileEntry::enabled("example.com")],
            },
        ],
    };
    let text = write_rules_file(&parsed, &[], None);
    assert!(text.contains("--- Zones\n"), "got:\n{text}");
    assert!(text.contains("--- Domains\nexample.com\n"), "got:\n{text}");
}

#[test]
fn write_single_active_entry_in_domains() {
    let parsed = RulesFileParsed {
        sections: vec![SectionContent {
            section: RulesFileSection::Domains,
            entries: vec![RulesFileEntry::enabled("example.com")],
        }],
    };
    let text = write_rules_file(&parsed, &[], None);
    assert!(text.contains("--- Domains\nexample.com\n"), "got:\n{text}");
}

#[test]
fn write_entry_with_inline_comment_uses_two_spaces() {
    let parsed = RulesFileParsed {
        sections: vec![SectionContent {
            section: RulesFileSection::Domains,
            entries: vec![RulesFileEntry::enabled_with_comment(
                "example.com",
                "vendor updates",
            )],
        }],
    };
    let text = write_rules_file(&parsed, &[], None);
    assert!(
        text.contains("example.com  # vendor updates\n"),
        "got:\n{text}"
    );
}

#[test]
fn write_disabled_entry_prefixed_with_hash() {
    let parsed = RulesFileParsed {
        sections: vec![SectionContent {
            section: RulesFileSection::Domains,
            entries: vec![RulesFileEntry::disabled("example.com")],
        }],
    };
    let text = write_rules_file(&parsed, &[], None);
    assert!(text.contains("# example.com\n"), "got:\n{text}");
    // Must not be misinterpreted as an active rule.
    assert!(!text.contains("\nexample.com\n"), "got:\n{text}");
}

#[test]
fn write_disabled_entry_with_inline_comment() {
    let parsed = RulesFileParsed {
        sections: vec![SectionContent {
            section: RulesFileSection::Domains,
            entries: vec![RulesFileEntry {
                match_value: "example.com".to_string(),
                inline_comment: Some("was active".to_string()),
                enabled: false,
                blocked: false,
                origin: None,
            }],
        }],
    };
    let text = write_rules_file(&parsed, &[], None);
    assert!(
        text.contains("# example.com  # was active\n"),
        "got:\n{text}"
    );
}

#[test]
fn write_then_parse_round_trips_active_rules() {
    let input = "\
--- Zones
ru

--- Domains
example.com
*.corp.example.net  # all subdomains

--- IP
203.0.113.7

--- Windows
chrome.exe

--- Linux

--- MacOS
";
    let parsed_first = parse_rules_file(input).parsed;
    let written = write_rules_file(&parsed_first, &[], None);
    let parsed_again = parse_rules_file(&written).parsed;
    assert_eq!(
            parsed_first, parsed_again,
            "round-trip diverged:\nfirst={parsed_first:#?}\nagain={parsed_again:#?}\nwritten=\n{written}"
        );
}

#[test]
fn write_then_parse_round_trips_disabled_rules() {
    let input = "\
--- Domains
example.com
# old.example.com  # decommissioned
";
    let parsed_first = parse_rules_file(input).parsed;
    let written = write_rules_file(&parsed_first, &[], None);
    let parsed_again = parse_rules_file(&written).parsed;
    assert_eq!(parsed_first, parsed_again);
}

#[test]
fn write_then_parse_round_trips_unicode_comments() {
    let input = "\
--- Domains
example.com  # отечественный поставщик обновлений
";
    let parsed_first = parse_rules_file(input).parsed;
    let written = write_rules_file(&parsed_first, &[], None);
    let parsed_again = parse_rules_file(&written).parsed;
    assert_eq!(parsed_first, parsed_again);
}

#[test]
fn write_preserves_unknown_sections_in_supplied_order() {
    let parsed = RulesFileParsed::default();
    let unknown = vec![
        UnknownSection {
            name: "CIDR".to_string(),
            entries: vec![RulesFileEntry::enabled("10.0.0.0/8")],
        },
        UnknownSection {
            name: "Ports".to_string(),
            entries: vec![
                RulesFileEntry::enabled("443"),
                RulesFileEntry::disabled("8080"),
            ],
        },
    ];
    let text = write_rules_file(&parsed, &unknown, None);
    assert!(text.contains("--- CIDR\n10.0.0.0/8\n"), "got:\n{text}");
    assert!(text.contains("--- Ports\n443\n# 8080\n"), "got:\n{text}");
    // CIDR must appear before Ports.
    let cidr_at = text.find("--- CIDR").unwrap();
    let ports_at = text.find("--- Ports").unwrap();
    assert!(cidr_at < ports_at, "supplied order not preserved");
}

#[test]
fn write_round_trips_unknown_sections() {
    let input = "\
--- Domains
example.com

--- CIDR
10.0.0.0/8
192.168.1.0/24  # office subnet

--- Ports
443
";
    let outcome = parse_rules_file(input);
    let written = write_rules_file(&outcome.parsed, &outcome.unknown_sections, None);
    let again = parse_rules_file(&written);
    assert_eq!(outcome.parsed, again.parsed);
    assert_eq!(outcome.unknown_sections, again.unknown_sections);
}

#[test]
fn write_includes_preset_metadata_when_supplied() {
    let parsed = RulesFileParsed::default();
    let meta = PresetMetadata {
        name: Some("Corporate VPN".to_string()),
        description: Some("Routes traffic via VPN".to_string()),
        author: Some("Jane Doe".to_string()),
        preset_version: Some("1".to_string()),
    };
    let text = write_rules_file(&parsed, &[], Some(&meta));
    assert!(
        text.starts_with("# NetRuleRouter preset \u{2014} version 4\n"),
        "got:\n{text}"
    );
    assert!(text.contains("# name: Corporate VPN\n"));
    assert!(text.contains("# description: Routes traffic via VPN\n"));
    assert!(text.contains("# author: Jane Doe\n"));
    assert!(text.contains("# preset_version: 1\n"));
}

#[test]
fn write_omits_metadata_keys_with_none_values() {
    let parsed = RulesFileParsed::default();
    let meta = PresetMetadata {
        name: Some("Solo".to_string()),
        description: None,
        author: None,
        preset_version: None,
    };
    let text = write_rules_file(&parsed, &[], Some(&meta));
    assert!(text.contains("# name: Solo\n"));
    assert!(!text.contains("# description:"));
    assert!(!text.contains("# author:"));
    assert!(!text.contains("# preset_version:"));
}

#[test]
fn write_round_trips_preset_metadata() {
    let input = "\
# NetRuleRouter preset \u{2014} version 1
# name: Corporate VPN
# description: Routes corporate traffic
# author: Jane Doe
# preset_version: 1

--- Domains
example.com
";
    let outcome = parse_rules_file(input);
    let written = write_rules_file(
        &outcome.parsed,
        &outcome.unknown_sections,
        outcome.preset_metadata.as_ref(),
    );
    let again = parse_rules_file(&written);
    assert_eq!(outcome.preset_metadata, again.preset_metadata);
    assert_eq!(outcome.parsed, again.parsed);
}

#[test]
fn write_emits_present_sections_in_canonical_order_regardless_of_input() {
    // Input deliberately reverse-ordered. Writer must restore canonical
    // order (Zones < MacOS). Absent sections are not emitted.
    let parsed = RulesFileParsed {
        sections: vec![
            SectionContent {
                section: RulesFileSection::MacOS,
                entries: vec![RulesFileEntry::enabled("Safari")],
            },
            SectionContent {
                section: RulesFileSection::Zones,
                entries: vec![RulesFileEntry::enabled("ru")],
            },
        ],
    };
    let text = write_rules_file(&parsed, &[], None);
    let zones_at = text.find("--- Zones").expect("Zones missing");
    let macos_at = text.find("--- MacOS").expect("MacOS missing");
    assert!(zones_at < macos_at, "Zones must precede MacOS:\n{text}");
    // Absent sections must NOT appear.
    for absent in &[
        RulesFileSection::Domains,
        RulesFileSection::Ip,
        RulesFileSection::Windows,
        RulesFileSection::Linux,
    ] {
        let header = format!("--- {}", absent.name());
        assert!(
            !text.contains(&header),
            "absent section {header:?} unexpectedly emitted:\n{text}"
        );
    }
}

#[test]
fn write_round_trips_input_with_empty_section_header() {
    // docs/en/rules-file-format.md Sections — `--- Domains\n\n--- IP\n203.0.113.7\n` should
    // round-trip preserving the empty Domains section header.
    let input = "\
--- Domains

--- IP
203.0.113.7
";
    let parsed_first = parse_rules_file(input).parsed;
    let written = write_rules_file(&parsed_first, &[], None);
    let parsed_again = parse_rules_file(&written).parsed;
    assert_eq!(parsed_first, parsed_again);
    // Domains header survived even though it has no entries.
    assert!(written.contains("--- Domains\n"), "got:\n{written}");
}
