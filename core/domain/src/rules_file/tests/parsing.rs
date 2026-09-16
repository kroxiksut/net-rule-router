use super::*;

// ── parse_rules_file ─────────────────────────────────────────────────────

#[test]
fn parse_active_rules_are_enabled() {
    let outcome = parse_rules_file(SAMPLE_FILE);
    let domains = outcome.parsed.entries_for(RulesFileSection::Domains);
    let enabled: Vec<_> = domains.iter().filter(|e| e.enabled).collect();
    assert_eq!(enabled.len(), 2);
    assert!(enabled
        .iter()
        .any(|e| e.match_value == "updates.example.org"));
    assert!(enabled.iter().any(|e| e.match_value == "corp.example.net"));
}

#[test]
fn parse_disabled_rule_via_comment_prefix() {
    let outcome = parse_rules_file(SAMPLE_FILE);
    let domains = outcome.parsed.entries_for(RulesFileSection::Domains);
    let disabled: Vec<_> = domains.iter().filter(|e| !e.enabled).collect();
    assert_eq!(disabled.len(), 1);
    assert_eq!(disabled[0].match_value, "old.example.com");
}

#[test]
fn parse_block_flag_sets_blocked_and_strips_token() {
    let input = "--- Domains\nads.example.com +block  # tracker\n# off.example.com +block\n";
    let outcome = parse_rules_file(input);
    let domains = outcome.parsed.entries_for(RulesFileSection::Domains);
    let active = domains
        .iter()
        .find(|e| e.match_value == "ads.example.com")
        .expect("active blocked rule");
    assert!(active.enabled);
    assert!(active.blocked);
    assert_eq!(active.inline_comment.as_deref(), Some("tracker"));
    let disabled = domains
        .iter()
        .find(|e| e.match_value == "off.example.com")
        .expect("disabled blocked rule");
    assert!(!disabled.enabled);
    assert!(disabled.blocked);
}

/// `+children` is documented in the rules-file format and nothing in the
/// matcher can act on it yet. Left in the match value it did worse than
/// nothing: the application normaliser turned `codex.exe +children` into
/// the pattern `codex.exe +children.exe`, which matches no process, so a
/// user following the shipped documentation got a rule covering nothing at
/// all. Consumed, the rule covers the named process.
#[test]
fn the_children_flag_is_consumed_instead_of_corrupting_the_value() {
    let input = "--- Windows\ncodex.exe +children  # AI assistant\n";
    let parsed = parse_rules_file(input).parsed;
    let entry = parsed
        .entries_for(RulesFileSection::Windows)
        .iter()
        .find(|e| e.match_value == "codex.exe")
        .expect("the process name survives on its own");
    assert!(!entry.blocked);
    assert_eq!(entry.inline_comment.as_deref(), Some("AI assistant"));

    // Both documented flags on one line, in either order.
    for line in ["codex.exe +children +block", "codex.exe +block +children"] {
        let parsed = parse_rules_file(&format!("--- Windows\n{line}\n")).parsed;
        let entry = parsed
            .entries_for(RulesFileSection::Windows)
            .iter()
            .find(|e| e.match_value == "codex.exe")
            .unwrap_or_else(|| panic!("value survives for {line:?}"));
        assert!(entry.blocked, "{line:?} keeps its block flag");
    }

    // Negative control: a trailing token that is NOT a documented flag
    // still reaches the value, so the semantic validator can complain
    // about it instead of the parser swallowing a typo.
    let parsed = parse_rules_file("--- Windows\ncodex.exe +childern\n").parsed;
    assert!(parsed
        .entries_for(RulesFileSection::Windows)
        .iter()
        .any(|e| e.match_value.contains("+childern")));
}

#[test]
fn block_flag_round_trips_through_write_and_parse() {
    let input = "--- Domains\nads.example.com +block  # tracker\n";
    let parsed = parse_rules_file(input).parsed;
    let written = write_rules_file(&parsed, &[], None);
    assert!(
        written.contains("ads.example.com +block"),
        "writer must emit the +block flag, got:\n{written}"
    );
    let reparsed = parse_rules_file(&written).parsed;
    let e = reparsed
        .entries_for(RulesFileSection::Domains)
        .iter()
        .find(|e| e.match_value == "ads.example.com")
        .expect("round-trip entry")
        .clone();
    assert!(e.blocked);
    assert_eq!(e.inline_comment.as_deref(), Some("tracker"));
}

#[test]
fn block_flag_maps_to_domain_rule_block_action() {
    let input = "--- Domains\nads.example.com +block\nrouted.example.com\n";
    let parsed = parse_rules_file(input).parsed;
    let set = rules_file_to_route_rule_set(&parsed, HostPlatform::Windows, false);
    let blocked = set
            .rules
            .iter()
            .find(|r| {
                matches!(&r.address_match, Some(crate::AddressMatch::ExactFqdn(v)) if v == "ads.example.com")
            })
            .expect("blocked rule");
    assert_eq!(blocked.action, crate::RuleAction::Block);
    let routed = set
            .rules
            .iter()
            .find(|r| {
                matches!(&r.address_match, Some(crate::AddressMatch::ExactFqdn(v)) if v == "routed.example.com")
            })
            .expect("routed rule");
    assert_eq!(routed.action, crate::RuleAction::Route);
}

#[test]
fn parse_inline_comment_extracted() {
    let outcome = parse_rules_file(SAMPLE_FILE);
    let domains = outcome.parsed.entries_for(RulesFileSection::Domains);
    let with_comment = domains
        .iter()
        .find(|e| e.match_value == "updates.example.org")
        .expect("entry not found");
    assert_eq!(
        with_comment.inline_comment.as_deref(),
        Some("vendor updates")
    );
}

#[test]
fn parse_entry_without_inline_comment() {
    let outcome = parse_rules_file(SAMPLE_FILE);
    let domains = outcome.parsed.entries_for(RulesFileSection::Domains);
    let no_comment = domains
        .iter()
        .find(|e| e.match_value == "corp.example.net")
        .expect("entry not found");
    assert!(no_comment.inline_comment.is_none());
}

#[test]
fn parse_zone_entry() {
    let outcome = parse_rules_file(SAMPLE_FILE);
    let zones = outcome.parsed.entries_for(RulesFileSection::Zones);
    assert_eq!(zones.len(), 1);
    assert_eq!(zones[0].match_value, "corp-internal");
    assert!(zones[0].enabled);
    assert_eq!(zones[0].inline_comment.as_deref(), Some("corporate zone"));
}

#[test]
fn parse_ip_entry() {
    let outcome = parse_rules_file(SAMPLE_FILE);
    let ip = outcome.parsed.entries_for(RulesFileSection::Ip);
    assert_eq!(ip.len(), 1);
    assert_eq!(ip[0].match_value, "203.0.113.7");
    assert!(ip[0].enabled);
}

#[test]
fn parse_windows_disabled_entry() {
    let outcome = parse_rules_file(SAMPLE_FILE);
    let win = outcome.parsed.entries_for(RulesFileSection::Windows);
    assert_eq!(win.len(), 2);
    let enabled: Vec<_> = win.iter().filter(|e| e.enabled).collect();
    let disabled: Vec<_> = win.iter().filter(|e| !e.enabled).collect();
    assert_eq!(enabled.len(), 1);
    assert_eq!(disabled.len(), 1);
    assert_eq!(enabled[0].match_value, "browser.exe");
    assert_eq!(disabled[0].match_value, "powershell.exe");
}

/// The toggle in the GUI writes `# <value>` and the file is rewritten from
/// the parsed model, so a value dropped here is a rule deleted for good.
///
/// Written against the HOST's own application section: whether a commented
/// line with a space is a disabled rule or prose is decided per rule kind,
/// and only the running platform's section counts as one. Hardcoding
/// `--- Windows` made this fail under Linux for a reason that has nothing to
/// do with what it asserts — the same trap
/// `compiled_platform_matches_the_build_target` documents.
#[test]
fn a_disabled_program_name_with_a_space_survives_the_round_trip() {
    let section = match HostPlatform::compiled() {
        HostPlatform::Windows => RulesFileSection::Windows,
        HostPlatform::Linux => RulesFileSection::Linux,
        HostPlatform::MacOS => RulesFileSection::MacOS,
    };
    let file = format!("--- {}\n# Adobe Reader.exe\nbrowser.exe\n", section.name());
    let outcome = parse_rules_file(&file);
    let apps = outcome.parsed.entries_for(section);
    assert_eq!(apps.len(), 2, "{apps:?}");
    assert_eq!(apps[0].match_value, "Adobe Reader.exe");
    assert!(!apps[0].enabled);
}

#[test]
fn prose_in_a_section_is_still_a_comment() {
    let file = "--- Windows
# a note about the browser below
browser.exe
";
    let outcome = parse_rules_file(file);
    let win = outcome.parsed.entries_for(RulesFileSection::Windows);
    assert_eq!(win.len(), 1, "{win:?}");
    assert_eq!(win[0].match_value, "browser.exe");
}

#[test]
fn a_multi_word_comment_in_a_domain_section_is_never_a_rule() {
    let file = "--- Domains
# see example.com for details
example.org
";
    let outcome = parse_rules_file(file);
    let dom = outcome.parsed.entries_for(RulesFileSection::Domains);
    assert_eq!(dom.len(), 1, "{dom:?}");
    assert_eq!(dom[0].match_value, "example.org");
}

#[test]
fn parse_empty_sections_preserved() {
    let outcome = parse_rules_file(SAMPLE_FILE);
    // Linux and MacOS sections appear in file but have no entries.
    assert!(outcome
        .parsed
        .entries_for(RulesFileSection::Linux)
        .is_empty());
    assert!(outcome
        .parsed
        .entries_for(RulesFileSection::MacOS)
        .is_empty());
    // But the sections themselves are present in the parsed output.
    assert!(outcome
        .parsed
        .sections
        .iter()
        .any(|s| s.section == RulesFileSection::Linux));
    assert!(outcome
        .parsed
        .sections
        .iter()
        .any(|s| s.section == RulesFileSection::MacOS));
}

#[test]
fn parse_free_comment_lines_ignored() {
    let input = "--- Domains\n# this is a note about routing\nexample.com\n";
    let outcome = parse_rules_file(input);
    let domains = outcome.parsed.entries_for(RulesFileSection::Domains);
    // Only the active rule; the prose comment is ignored.
    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].match_value, "example.com");
}

#[test]
fn parse_preamble_lines_before_first_section_ignored() {
    let input = "# preamble line\nexample.com\n--- Domains\ncorp.net\n";
    let outcome = parse_rules_file(input);
    let domains = outcome.parsed.entries_for(RulesFileSection::Domains);
    // "example.com" before the first section header is ignored.
    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0].match_value, "corp.net");
}

#[test]
fn parse_unknown_section_produces_warning() {
    let input = "--- CIDR\n10.0.0.0/8\n";
    let outcome = parse_rules_file(input);
    assert_eq!(outcome.warnings.len(), 1);
    assert!(matches!(
        &outcome.warnings[0],
        ParseWarning::UnknownSection { name, .. } if name == "CIDR"
    ));
    assert_eq!(outcome.unknown_sections.len(), 1);
    assert_eq!(outcome.unknown_sections[0].name, "CIDR");
    assert_eq!(outcome.unknown_sections[0].entries.len(), 1);
}

#[test]
fn parse_unknown_section_entry_count_in_warning() {
    let input = "--- Ports\n443\n80\n8080\n";
    let outcome = parse_rules_file(input);
    assert!(matches!(
        &outcome.warnings[0],
        ParseWarning::UnknownSection { name, entry_count: 3 } if name == "Ports"
    ));
}

/// The parser is reachable over IPC with a client-supplied 1 MiB payload,
/// so its cost has to be linear in the input. Section bookkeeping used to
/// scan the accumulated list per header — 20k headers took ~750 ms, and the
/// import limit allows five times as many. A wall-clock guard is coarse on
/// purpose: it fails on a return to quadratic (tens of seconds) and cannot
/// flake on a slow machine at these margins.
#[test]
fn a_file_of_many_distinct_headers_parses_in_linear_time() {
    const HEADERS: usize = 20_000;
    let mut input = String::with_capacity(HEADERS * 16);
    for i in 0..HEADERS {
        input.push_str(&format!("--- Section{i}\nvalue{i}.example\n"));
    }
    let started = std::time::Instant::now();
    let outcome = parse_rules_file(&input);
    let elapsed = started.elapsed();
    assert_eq!(outcome.unknown_sections.len(), HEADERS);
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "parsing {HEADERS} headers took {elapsed:?} — the per-header lookup is scanning again",
    );
}

#[test]
fn parse_multiple_unknown_sections_all_preserved() {
    let input = "--- CIDR\n10.0.0.0/8\n--- Ports\n443\n";
    let outcome = parse_rules_file(input);
    assert_eq!(outcome.unknown_sections.len(), 2);
    assert_eq!(outcome.unknown_sections[0].name, "CIDR");
    assert_eq!(outcome.unknown_sections[1].name, "Ports");
}

#[test]
fn parse_unknown_sections_round_trip_free_edition() {
    // A file with known + unknown sections: known sections parsed,
    // unknown sections preserved with entries intact.
    let input = "--- Domains\nexample.com\n--- CIDR\n10.0.0.0/8\n";
    let outcome = parse_rules_file(input);
    let domains = outcome.parsed.entries_for(RulesFileSection::Domains);
    assert_eq!(domains.len(), 1);
    assert_eq!(outcome.unknown_sections.len(), 1);
    assert_eq!(
        outcome.unknown_sections[0].entries[0].match_value,
        "10.0.0.0/8"
    );
    // No data loss: all entries are accessible.
}

// ── preset metadata ──────────────────────────────────────────────────────

#[test]
fn parse_preset_header_sets_preset_metadata() {
    let input = "# NetRuleRouter preset \u{2014} version 1\n--- Domains\nexample.com\n";
    let outcome = parse_rules_file(input);
    assert!(outcome.preset_metadata.is_some());
    assert_eq!(outcome.file_format_version, Some(1));
}

#[test]
fn parse_rules_file_header_does_not_set_preset_metadata() {
    let input = "# NetRuleRouter rules file \u{2014} version 1\n--- Domains\nexample.com\n";
    let outcome = parse_rules_file(input);
    assert!(outcome.preset_metadata.is_none());
    assert_eq!(outcome.file_format_version, Some(1));
}

#[test]
fn parse_preset_metadata_keys_extracted() {
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
        .expect("preset_metadata should be Some");
    assert_eq!(meta.name.as_deref(), Some("Corporate VPN Rules"));
    assert_eq!(
        meta.description.as_deref(),
        Some("Routes corporate traffic via VPN")
    );
    assert_eq!(meta.author.as_deref(), Some("Jane Doe"));
    assert_eq!(meta.preset_version.as_deref(), Some("2"));
}

#[test]
fn parse_metadata_keys_without_preset_header_still_captured() {
    let input = "# name: My Rules\n--- Domains\nexample.com\n";
    let outcome = parse_rules_file(input);
    let meta = outcome
        .preset_metadata
        .as_ref()
        .expect("metadata should be Some");
    assert_eq!(meta.name.as_deref(), Some("My Rules"));
}

#[test]
fn parse_no_metadata_gives_none_preset_metadata() {
    let outcome = parse_rules_file(SAMPLE_FILE);
    assert!(outcome.preset_metadata.is_none());
}

#[test]
fn parse_metadata_keys_inside_section_ignored() {
    // Metadata key-value comments inside a section are treated as free
    // comments, not captured as preset metadata.
    let input = "--- Domains\n# name: should be ignored\nexample.com\n";
    let outcome = parse_rules_file(input);
    assert!(outcome.preset_metadata.is_none());
}

#[test]
fn parse_preset_unknown_version_produces_warning() {
    let input = "# NetRuleRouter preset \u{2014} version 99\n--- Domains\nexample.com\n";
    let outcome = parse_rules_file(input);
    assert_eq!(outcome.file_format_version, Some(99));
    assert!(outcome.preset_metadata.is_some());
    assert!(matches!(
        &outcome.warnings[0],
        ParseWarning::UnknownFormatVersion {
            found: 99,
            supported: 4
        }
    ));
}

#[test]
fn preset_metadata_is_empty_when_all_none() {
    let meta = PresetMetadata::default();
    assert!(meta.is_empty());
}

#[test]
fn preset_metadata_not_empty_when_name_set() {
    let meta = PresetMetadata {
        name: Some("Test".to_string()),
        ..Default::default()
    };
    assert!(!meta.is_empty());
}

#[test]
fn parse_empty_input() {
    let outcome = parse_rules_file("");
    assert!(outcome.parsed.sections.is_empty());
    assert!(outcome.warnings.is_empty());
}

#[test]
fn parse_duplicate_section_header_merges_entries() {
    let input = "--- Domains\nexample.com\n--- Domains\ncorp.net\n";
    let outcome = parse_rules_file(input);
    let domains = outcome.parsed.entries_for(RulesFileSection::Domains);
    assert_eq!(domains.len(), 2);
}

#[test]
fn parse_no_warnings_for_valid_file() {
    let outcome = parse_rules_file(SAMPLE_FILE);
    assert!(outcome.warnings.is_empty());
}

// ── version header ───────────────────────────────────────────────────────

#[test]
fn parse_version_header_from_sample_file() {
    let outcome = parse_rules_file(SAMPLE_FILE);
    assert_eq!(outcome.file_format_version, Some(1));
    assert!(
        outcome.warnings.is_empty(),
        "a version-1 file is fully understood by a version-4 build"
    );
}

#[test]
fn parse_version_absent_gives_none() {
    let input = "--- Domains\nexample.com\n";
    let outcome = parse_rules_file(input);
    assert_eq!(outcome.file_format_version, None);
    assert!(outcome.warnings.is_empty());
}

#[test]
fn parse_known_version_produces_no_warning() {
    let input = "# NetRuleRouter rules file \u{2014} version 1\n--- Domains\nexample.com\n";
    let outcome = parse_rules_file(input);
    assert_eq!(outcome.file_format_version, Some(1));
    assert!(outcome.warnings.is_empty());
}

#[test]
fn parse_unknown_version_produces_warning() {
    let input = "# NetRuleRouter rules file \u{2014} version 99\n--- Domains\nexample.com\n";
    let outcome = parse_rules_file(input);
    assert_eq!(outcome.file_format_version, Some(99));
    assert_eq!(outcome.warnings.len(), 1);
    assert!(matches!(
        &outcome.warnings[0],
        ParseWarning::UnknownFormatVersion {
            found: 99,
            supported: 4
        }
    ));
}

#[test]
fn parse_fixture_file_is_valid() {
    let content = include_str!("../../../tests/fixtures/rules_primary_sample.txt");
    let outcome = parse_rules_file(content);
    // Fixture has a known version header — no format-version warning.
    assert!(
        outcome.warnings.is_empty(),
        "fixture produced unexpected warnings: {:?}",
        outcome.warnings
    );
    assert_eq!(outcome.file_format_version, Some(1));
    // At least one enabled domain entry.
    let domains = outcome.parsed.entries_for(RulesFileSection::Domains);
    assert!(
        domains.iter().any(|e| e.enabled),
        "fixture must have at least one enabled domain rule"
    );
}

#[test]
fn parse_version_header_only_matched_in_preamble() {
    // A version-like comment inside a section must NOT be treated as the header.
    let input = "--- Domains\n# NetRuleRouter rules file \u{2014} version 1\nexample.com\n";
    let outcome = parse_rules_file(input);
    // The comment line is inside a section — it is a free comment, ignored as a rule.
    // file_format_version stays None because the header was not in the preamble.
    assert_eq!(outcome.file_format_version, None);
}
