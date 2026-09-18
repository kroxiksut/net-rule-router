use super::*;

/// The application section THIS build classifies as rules, and two it does
/// not. The roles are host-relative and these tests spelled them out
/// (`Windows` = rules, `Linux`/`MacOS` = passthrough), which held only on a
/// Windows runner: on a Linux one `--- Linux` becomes the rule section and
/// every passthrough assertion here inverts.
const NATIVE_APP: &str = if cfg!(target_os = "windows") {
    "Windows"
} else if cfg!(target_os = "linux") {
    "Linux"
} else {
    "MacOS"
};
const FOREIGN_A: &str = if cfg!(target_os = "windows") {
    "Linux"
} else {
    "Windows"
};
const FOREIGN_B: &str = if cfg!(target_os = "macos") {
    "Linux"
} else {
    "MacOS"
};

fn rule(
    id: u32,
    enabled: bool,
    ty: ParsedRuleType,
    section: &str,
    value: &str,
    comment: &str,
    line: usize,
) -> ParsedRule {
    ParsedRule {
        id_hint: id,
        enabled,
        rule_type: ty,
        section_name: section.to_string(),
        match_value: value.to_string(),
        comment: comment.to_string(),
        blocked: false,
        line_number: line,
        origin: None,
    }
}

#[test]
fn empty_input_yields_default_result() {
    let result = parse_canonical_rules("");
    assert_eq!(result, PresetParseResult::default());
}

#[test]
fn no_sections_drops_prelude() {
    // Lines before the first `--- ` header are file-level prelude.
    let result = parse_canonical_rules("# header line one\n# header line two\n");
    assert!(result.rules.is_empty());
    assert!(result.passthrough.is_empty());
}

/// Mirrors `nrr_domain::rules_file`: both parsers of this format must keep
/// the same lines, or saving from the GUI deletes what the service applies.
#[test]
fn a_disabled_program_name_with_a_space_is_a_rule_not_prose() {
    let result = parse_canonical_rules(&format!(
        "--- {NATIVE_APP}
# Adobe Reader.exe
browser.exe
"
    ));
    assert_eq!(result.rules.len(), 2, "{:?}", result.rules);
    assert_eq!(result.rules[0].match_value, "Adobe Reader.exe");
    assert!(!result.rules[0].enabled);
}

#[test]
fn a_multi_word_note_stays_a_comment() {
    let result = parse_canonical_rules(
        "--- Domains
# see example.com for details
example.org
",
    );
    assert_eq!(result.rules.len(), 1, "{:?}", result.rules);
    assert_eq!(result.rules[0].match_value, "example.org");
}

#[test]
fn single_known_section_with_one_rule() {
    let result = parse_canonical_rules("--- Zones\nru\n");
    assert_eq!(result.rules.len(), 1);
    let r = &result.rules[0];
    assert_eq!(r.rule_type, ParsedRuleType::Zone);
    assert_eq!(r.match_value, "ru");
    assert!(r.enabled);
}

#[test]
fn inline_comment_split_at_first_hash() {
    let result = parse_canonical_rules("--- Domains\nab.test  # Russian social\n");
    assert_eq!(result.rules.len(), 1);
    let r = &result.rules[0];
    assert_eq!(r.match_value, "ab.test");
    assert_eq!(r.comment, "Russian social");
}

#[test]
fn disabled_rule_single_token() {
    let result = parse_canonical_rules("--- Domains\n# disabled.example.com\n");
    assert_eq!(result.rules.len(), 1);
    let r = &result.rules[0];
    assert!(!r.enabled);
    assert_eq!(r.match_value, "disabled.example.com");
}

#[test]
fn disabled_rule_with_inline_comment() {
    // First # is the disable prefix; second is the inline-comment
    // separator. Value is `ab.test`, comment is `temporarily off`.
    let result = parse_canonical_rules("--- Domains\n# ab.test  # temporarily off\n");
    assert_eq!(result.rules.len(), 1);
    let r = &result.rules[0];
    assert!(!r.enabled);
    assert_eq!(r.match_value, "ab.test");
    assert_eq!(r.comment, "temporarily off");
}

#[test]
fn multi_word_comment_is_dropped_not_disabled_rule() {
    // "# this is a note" is a free comment — NOT a disabled rule.
    let result = parse_canonical_rules("--- Domains\n# this is a note\n");
    assert!(result.rules.is_empty());
}

#[test]
fn block_flag_marks_rule_blocked_and_strips_token() {
    let result = parse_canonical_rules("--- Domains\nads.example.com +block\n");
    assert_eq!(result.rules.len(), 1);
    let r = &result.rules[0];
    assert!(r.enabled);
    assert!(r.blocked);
    assert_eq!(r.match_value, "ads.example.com");
}

#[test]
fn block_flag_with_inline_comment() {
    let result = parse_canonical_rules("--- Domains\nads.example.com +block  # tracker\n");
    assert_eq!(result.rules.len(), 1);
    let r = &result.rules[0];
    assert!(r.blocked);
    assert_eq!(r.match_value, "ads.example.com");
    assert_eq!(r.comment, "tracker");
}

#[test]
fn disabled_block_rule_is_not_mistaken_for_free_comment() {
    // `# value +block` must parse as a disabled blocked rule, not prose.
    let result = parse_canonical_rules("--- Domains\n# ads.example.com +block\n");
    assert_eq!(result.rules.len(), 1);
    let r = &result.rules[0];
    assert!(!r.enabled);
    assert!(r.blocked);
    assert_eq!(r.match_value, "ads.example.com");
}

#[test]
fn no_block_flag_leaves_rule_unblocked() {
    let result = parse_canonical_rules("--- Domains\nexample.com\n");
    assert_eq!(result.rules.len(), 1);
    assert!(!result.rules[0].blocked);
}

#[test]
fn double_hash_is_always_free_comment() {
    let result = parse_canonical_rules("--- Domains\n## metadata: vendor-list\n");
    assert!(result.rules.is_empty());
}

#[test]
fn lone_hash_is_dropped() {
    let result = parse_canonical_rules("--- Domains\n#\n");
    assert!(result.rules.is_empty());
}

#[test]
fn blank_lines_between_rules_ignored() {
    let result = parse_canonical_rules("--- Domains\nab.test\n\n\nvideo.example\n");
    assert_eq!(result.rules.len(), 2);
    assert_eq!(result.rules[0].match_value, "ab.test");
    assert_eq!(result.rules[1].match_value, "video.example");
}

#[test]
fn crlf_line_endings_supported() {
    let result = parse_canonical_rules("--- Zones\r\nru\r\n");
    assert_eq!(result.rules.len(), 1);
    assert_eq!(result.rules[0].match_value, "ru");
}

#[test]
fn mixed_line_endings_supported() {
    let result = parse_canonical_rules("--- Zones\r\nru\n--- Domains\r\nab.test\n");
    assert_eq!(result.rules.len(), 2);
}

#[test]
fn case_insensitive_section_headers_accepted() {
    // QML parser was lenient on case — preserve that behaviour
    // so older hand-edited files keep importing the same way.
    let result = parse_canonical_rules("--- zones\nru\n");
    assert_eq!(result.rules.len(), 1);
    assert_eq!(result.rules[0].rule_type, ParsedRuleType::Zone);
}

#[test]
fn unknown_section_goes_to_passthrough() {
    let input = format!("--- {FOREIGN_A}\n# (reserved)\nfirefox\nchromium\n");
    let result = parse_canonical_rules(&input);
    assert!(result.rules.is_empty());
    assert_eq!(result.passthrough.len(), 1);
    let block = &result.passthrough[0];
    assert_eq!(block.section_name, FOREIGN_A);
    // Everything carried: the `# (reserved)` header plus firefox and
    // chromium → 3. The count answers "how much is preserved", and the
    // header is preserved too; the preview below still shows only the
    // substance.
    assert_eq!(block.content_lines, 3);
    assert_eq!(
        block.preview,
        vec!["firefox".to_string(), "chromium".to_string()]
    );
    // Body trailing-newline normalised.
    assert_eq!(block.raw_text, "# (reserved)\nfirefox\nchromium\n");
}

#[test]
fn passthrough_preserves_blank_lines_and_comments_in_raw() {
    let input = format!("--- {FOREIGN_A}\n\nfirefox\n# vendor note\nchromium\n");
    let result = parse_canonical_rules(&input);
    assert_eq!(result.passthrough.len(), 1);
    let block = &result.passthrough[0];
    assert_eq!(block.raw_text, "\nfirefox\n# vendor note\nchromium\n");
    // Preview only contains non-blank, non-comment.
    assert_eq!(
        block.preview,
        vec!["firefox".to_string(), "chromium".to_string()]
    );
}

#[test]
fn passthrough_preview_caps_at_five_lines() {
    let mut input = format!("--- {FOREIGN_A}\n");
    for i in 0..10 {
        input.push_str(&format!("app{i}\n"));
    }
    let result = parse_canonical_rules(&input);
    let block = &result.passthrough[0];
    assert_eq!(block.content_lines, 10);
    assert_eq!(block.preview.len(), PASSTHROUGH_PREVIEW_LINES);
    assert_eq!(block.preview[0], "app0");
    assert_eq!(block.preview[4], "app4");
}

#[test]
fn empty_unknown_section_produces_block_with_empty_body() {
    let result = parse_canonical_rules(&format!("--- {FOREIGN_A}\n--- {FOREIGN_B}\nSafari\n"));
    // Two passthrough blocks — the first empty, the second one line.
    assert_eq!(result.passthrough.len(), 2);
    assert_eq!(result.passthrough[0].section_name, FOREIGN_A);
    assert_eq!(result.passthrough[0].raw_text, "");
    assert_eq!(result.passthrough[0].content_lines, 0);
    assert!(result.passthrough[0].preview.is_empty());
    assert_eq!(result.passthrough[1].section_name, FOREIGN_B);
    assert_eq!(result.passthrough[1].content_lines, 1);
}

#[test]
fn duplicate_unknown_section_creates_two_passthrough_blocks() {
    let input = format!("--- {FOREIGN_A}\nfirefox\n--- {FOREIGN_A}\nchromium\n");
    let result = parse_canonical_rules(&input);
    assert_eq!(result.passthrough.len(), 2);
    assert_eq!(result.passthrough[0].raw_text, "firefox\n");
    assert_eq!(result.passthrough[1].raw_text, "chromium\n");
    // The duplicate diagnostic fires.
    assert_eq!(result.duplicate_sections.len(), 1);
    assert_eq!(result.duplicate_sections[0].section_name, FOREIGN_A);
    assert_eq!(result.duplicate_sections[0].occurrences, 2);
    assert!(!result.duplicate_sections[0].is_known_section);
}

#[test]
fn duplicate_known_section_merges_rules_and_flags_diagnostic() {
    let input = "--- Domains\nab.test\n--- Domains\nya.ru\n";
    let result = parse_canonical_rules(input);
    // Rules from both blocks are present in encounter order.
    assert_eq!(result.rules.len(), 2);
    assert_eq!(result.rules[0].match_value, "ab.test");
    assert_eq!(result.rules[1].match_value, "ya.ru");
    // Diagnostic fires with `is_known_section = true`.
    assert_eq!(result.duplicate_sections.len(), 1);
    let dup = &result.duplicate_sections[0];
    assert_eq!(dup.section_name, "Domains");
    assert_eq!(dup.occurrences, 2);
    assert!(dup.is_known_section);
}

#[test]
fn multiple_distinct_duplicates_in_order() {
    let input =
        format!("--- {FOREIGN_A}\na\n--- {FOREIGN_B}\nb\n--- {FOREIGN_A}\nc\n--- {FOREIGN_B}\nd\n");
    let result = parse_canonical_rules(&input);
    assert_eq!(result.duplicate_sections.len(), 2);
    // Order preserved by first encounter.
    assert_eq!(result.duplicate_sections[0].section_name, FOREIGN_A);
    assert_eq!(result.duplicate_sections[1].section_name, FOREIGN_B);
}

#[test]
fn id_hint_increments_sequentially() {
    let input = "--- Zones\nru\n--- Domains\nab.test\nya.ru\n";
    let result = parse_canonical_rules(input);
    assert_eq!(result.rules.len(), 3);
    assert_eq!(result.rules[0].id_hint, 1);
    assert_eq!(result.rules[1].id_hint, 2);
    assert_eq!(result.rules[2].id_hint, 3);
}

#[test]
fn line_numbers_are_one_based_and_track_file_position() {
    let input = "# prelude\n--- Domains\n\nab.test\n# disabled.example.com\n";
    let result = parse_canonical_rules(input);
    assert_eq!(result.rules.len(), 2);
    // ab.test is on line 4 (1-based), counting the blank line.
    assert_eq!(result.rules[0].line_number, 4);
    assert_eq!(result.rules[1].line_number, 5);
}

#[test]
fn cyrillic_match_value_preserved_verbatim() {
    let input = "--- Zones\nрф          # Российская Федерация\n";
    let result = parse_canonical_rules(input);
    assert_eq!(result.rules.len(), 1);
    assert_eq!(result.rules[0].match_value, "рф");
    assert_eq!(result.rules[0].comment, "Российская Федерация");
}

#[test]
fn ace_punycode_match_value_preserved_verbatim() {
    // The parser does NOT do Punycode↔Unicode conversion; that's
    // a UI-layer concern (see `_unicodeDecodeHost` in Main.qml).
    let input = "--- Zones\nxn--p1ai\n";
    let result = parse_canonical_rules(input);
    assert_eq!(result.rules[0].match_value, "xn--p1ai");
}

#[test]
fn windows_section_treated_as_application() {
    let input = format!("--- {NATIVE_APP}\nbrowser.exe\n*vpn*.exe\n");
    let result = parse_canonical_rules(&input);
    assert_eq!(result.rules.len(), 2);
    for r in &result.rules {
        assert_eq!(r.rule_type, ParsedRuleType::Application);
    }
}

#[test]
fn ip_section_treated_as_exact_ip() {
    let input = "--- IP\n203.0.113.7\n";
    let result = parse_canonical_rules(input);
    assert_eq!(result.rules[0].rule_type, ParsedRuleType::ExactIp);
}

#[test]
fn extended_section_cidr_goes_to_passthrough() {
    // unsupported sections (CIDR, Ports) are not yet supported by
    // this engine — they survive as passthrough so a round-trip does
    // not lose them.
    let result = parse_canonical_rules("--- Cidr\n10.0.0.0/8\n");
    assert!(result.rules.is_empty());
    assert_eq!(result.passthrough[0].section_name, "Cidr");
    assert_eq!(result.passthrough[0].raw_text, "10.0.0.0/8\n");
}

#[test]
fn section_header_with_extra_spaces_normalised() {
    // `---  Zones  ` (extra spaces) — the prefix matcher requires
    // exactly `--- ` (three hyphens + one space), so this line is
    // NOT a header. It falls through to the prelude bucket.
    let result = parse_canonical_rules("---  Zones  \nru\n");
    assert!(result.rules.is_empty());
    assert!(result.passthrough.is_empty());
}

#[test]
fn rule_type_slug_matches_qml_mapping() {
    assert_eq!(ParsedRuleType::Zone.slug(), "zone");
    assert_eq!(ParsedRuleType::Domain.slug(), "domain");
    assert_eq!(ParsedRuleType::ExactIp.slug(), "exact-ip");
    assert_eq!(ParsedRuleType::Application.slug(), "application");
}

#[test]
fn classify_section_strict_case_sensitive() {
    assert_eq!(classify_section("Zones"), Some(ParsedRuleType::Zone));
    assert_eq!(classify_section("zones"), None);
    assert_eq!(classify_section("ZONES"), None);
    // A literal on purpose: unlike the lenient classifier, the strict one
    // is host-independent — its known set is fixed, so `Linux` is unknown
    // to it on every OS.
    assert_eq!(classify_section("Linux"), None);
}

#[test]
fn classify_section_lenient_case_insensitive() {
    assert_eq!(
        classify_section_lenient_pub("Zones"),
        Some(ParsedRuleType::Zone)
    );
    assert_eq!(
        classify_section_lenient_pub("zones"),
        Some(ParsedRuleType::Zone)
    );
    assert_eq!(
        classify_section_lenient_pub("ZONES"),
        Some(ParsedRuleType::Zone)
    );
    // A section belonging to another OS classifies as nothing here — which
    // one that is depends on the host, so it is named rather than spelled.
    assert_eq!(classify_section_lenient_pub(FOREIGN_A), None);
}

#[test]
fn ten_thousand_rules_perf() {
    // Sanity: parser must finish a 10k-rule preset in well under a
    // second. Hard cap of 500 ms is intentionally generous so the
    // test stays stable on slow CI runners.
    let mut input = String::from("--- Domains\n");
    for i in 0..10_000 {
        input.push_str(&format!("host{i}.example.com  # comment {i}\n"));
    }
    let start = std::time::Instant::now();
    let result = parse_canonical_rules(&input);
    let elapsed = start.elapsed();
    assert_eq!(result.rules.len(), 10_000);
    assert!(
        elapsed.as_millis() < 500,
        "10k rules took {} ms (should be <500)",
        elapsed.as_millis()
    );
}

#[test]
fn complete_realistic_preset_matches_qml_behaviour() {
    // A realistic RU preset shape — verifies the parser behaves
    // identically to the QML reference for a representative file.
    let input = format!(
        "# NetRuleRouter preset - version 1\n# name: Test\n# preset_version: 1\n\n--- Zones\nru          # Россия (.ru)\nрф          # Россия (.рф, Punycode xn--p1ai)\n\n--- Domains\nab.test\n*.ab.test\n# *.deprecated.com  # turned off last week\n\n--- IP\n# Intentionally left empty\n\n--- {NATIVE_APP}\nmessenger.exe\n# notepad.exe\n\n--- {FOREIGN_A}\n# (reserved - not applied on this host)\nfirefox\n\n--- {FOREIGN_B}\n# (reserved - not applied on this host)\nSafari\n"
    );

    let result = parse_canonical_rules(&input);

    // 2 zones + 2 domains + 1 disabled domain + 1 enabled app +
    // 1 disabled app = 7 rules.
    assert_eq!(result.rules.len(), 7);

    // Spot-check
    assert_eq!(result.rules[0].match_value, "ru");
    assert!(result.rules[0].enabled);
    assert_eq!(result.rules[1].match_value, "рф");
    assert_eq!(result.rules[2].match_value, "ab.test");
    assert!(result.rules[5].enabled); // messenger.exe
    assert!(!result.rules[6].enabled); // # notepad.exe

    // Passthrough: the two foreign-OS sections preserved.
    assert_eq!(result.passthrough.len(), 2);
    assert_eq!(result.passthrough[0].section_name, FOREIGN_A);
    assert_eq!(result.passthrough[1].section_name, FOREIGN_B);
    // Two carried lines each: the `# (reserved …)` header and the entry.
    // The count says how much is preserved, and the header is preserved
    // too — the preview below is what shows the substance.
    assert_eq!(result.passthrough[0].content_lines, 2);
    assert_eq!(result.passthrough[1].content_lines, 2);
    assert_eq!(result.passthrough[0].preview, vec!["firefox".to_string()]);
    assert_eq!(result.passthrough[1].preview, vec!["Safari".to_string()]);

    // No duplicates in a well-formed file.
    assert!(result.duplicate_sections.is_empty());

    // ── Verify exact rule layout ──
    let expected_section_for_idx = [
        "Zones", "Zones", "Domains", "Domains", "Domains", NATIVE_APP, NATIVE_APP,
    ];
    for (i, r) in result.rules.iter().enumerate() {
        assert_eq!(r.section_name, expected_section_for_idx[i], "rule {i}");
    }
}

#[test]
fn rule_with_only_whitespace_value_skipped() {
    let result = parse_canonical_rules("--- Domains\n   \n");
    assert!(result.rules.is_empty());
}

#[test]
fn hash_with_just_prefix_skipped() {
    // "# " alone (with trailing newline) → empty body → skipped.
    let result = parse_canonical_rules("--- Domains\n# \n");
    assert!(result.rules.is_empty());
}

#[test]
fn trailing_carriage_returns_stripped() {
    // Single \r at end of value should not become part of match_value.
    let result = parse_canonical_rules("--- Domains\nab.test\r\n");
    assert_eq!(result.rules[0].match_value, "ab.test");
}

#[test]
fn passthrough_block_for_section_with_only_blank_lines() {
    let result = parse_canonical_rules(&format!("--- {FOREIGN_A}\n\n\n\n"));
    assert_eq!(result.passthrough.len(), 1);
    let block = &result.passthrough[0];
    assert_eq!(block.content_lines, 0);
    // raw_text is normalised: all blanks collapsed at the end.
    assert_eq!(block.raw_text, "");
}

#[test]
fn rejecting_section_with_empty_name_after_dashes() {
    // `---   ` with no section name is not a valid header.
    let result = parse_canonical_rules("---   \nfoo\n");
    // Should not have started a section; everything is prelude.
    assert!(result.rules.is_empty());
    assert!(result.passthrough.is_empty());
}

#[test]
fn serde_roundtrip_through_json() {
    // Wire-protocol smoke: result types serialise to JSON cleanly
    // (this is what the launcher RPC handler emits).
    let result = parse_canonical_rules("--- Zones\nru\n--- Linux\nfirefox\n");
    let json = serde_json::to_string(&result).expect("serialise");
    let parsed: PresetParseResult = serde_json::from_str(&json).expect("deserialise");
    assert_eq!(result, parsed);
}

#[test]
fn parsed_rule_keeps_section_name_case() {
    // Even though we accept lowercased section headers, the
    // parsed rule's `section_name` field preserves the original
    // case from the file. Useful for diagnostics and exports.
    let result = parse_canonical_rules("--- domains\nab.test\n");
    assert_eq!(result.rules[0].section_name, "domains");
}

#[test]
fn duplicate_known_section_with_passthrough_after_does_not_confuse() {
    // The foreign section is unknown, Domains is known. Two of each.
    let input = format!(
        "--- Domains\nab.test\n--- {FOREIGN_A}\nfirefox\n--- Domains\nya.ru\n--- {FOREIGN_A}\nchromium\n"
    );
    let result = parse_canonical_rules(&input);
    assert_eq!(result.rules.len(), 2);
    assert_eq!(result.passthrough.len(), 2);
    assert_eq!(result.duplicate_sections.len(), 2);
}

#[test]
fn invalid_section_marker_treated_as_normal_line_inside_section() {
    // A line that looks like a section header but is malformed
    // (e.g. `----- Zones` with four dashes) is not a header, and
    // inside a known section it would be parsed as a rule value.
    // Inside an unknown section it accumulates as passthrough text.
    let result = parse_canonical_rules(&format!("--- {FOREIGN_A}\n----- not a header\nfoo\n"));
    assert!(result.rules.is_empty());
    let block = &result.passthrough[0];
    assert_eq!(block.section_name, FOREIGN_A);
    assert_eq!(block.raw_text, "----- not a header\nfoo\n");
}

#[test]
fn unicode_section_name_treated_as_unknown_and_passthrough() {
    // A user could in theory create `--- Зоны` — non-canonical.
    // It's not a recognised section, so it goes into passthrough.
    let result = parse_canonical_rules("--- Зоны\nru\n");
    assert!(result.rules.is_empty());
    assert_eq!(result.passthrough[0].section_name, "Зоны");
    assert_eq!(result.passthrough[0].content_lines, 1);
}

#[test]
fn fixture_minimal_three_known_sections() {
    let result =
        parse_canonical_rules("--- Zones\nru\n--- Domains\nab.test\n--- IP\n203.0.113.7\n");
    assert_eq!(result.rules.len(), 3);
    assert_eq!(result.rules[0].rule_type, ParsedRuleType::Zone);
    assert_eq!(result.rules[1].rule_type, ParsedRuleType::Domain);
    assert_eq!(result.rules[2].rule_type, ParsedRuleType::ExactIp);
}

#[test]
fn fixture_application_with_glob_pattern() {
    let result = parse_canonical_rules(&format!(
        "--- {NATIVE_APP}\n*chrome*.exe  # any chrome variant\n"
    ));
    assert_eq!(result.rules[0].match_value, "*chrome*.exe");
    assert_eq!(result.rules[0].comment, "any chrome variant");
}

#[test]
fn fixture_helper_rule_constructor_used_in_assertions() {
    let result = parse_canonical_rules("--- Zones\nru\n");
    assert_eq!(
        result.rules[0],
        rule(1, true, ParsedRuleType::Zone, "Zones", "ru", "", 2)
    );
}

// ── `--- Auto` section ───────────────────────────────────────────────────

#[test]
fn auto_section_classifies_as_rules_not_passthrough() {
    // Lockstep with `nrr_domain::rules_file`: if this fell to passthrough
    // the GUI would show opaque text where the service sees rules.
    assert_eq!(classify_section("Auto"), Some(ParsedRuleType::Domain));
    assert_eq!(
        classify_section_lenient_pub("auto"),
        Some(ParsedRuleType::Domain)
    );
}

#[test]
fn auto_rule_provenance_is_lifted_out_of_the_comment() {
    let result = parse_canonical_rules(
        "--- Auto\nrr3.example-cdn.net  # auto:site-companion anchor:example.com added:2026-07-31 video CDN\n",
    );
    assert!(result.passthrough.is_empty(), "must not be passthrough");
    assert_eq!(result.rules.len(), 1);
    let parsed = &result.rules[0];
    assert_eq!(parsed.match_value, "rr3.example-cdn.net");
    assert_eq!(parsed.section_name, "Auto");
    assert_eq!(parsed.rule_type, ParsedRuleType::Domain);
    // The label is the free text; the machinery is typed.
    assert_eq!(parsed.comment, "video CDN");
    assert_eq!(
        parsed.origin,
        Some(crate::auto_rule::RuleOrigin::auto(
            crate::auto_rule::AutoRuleReason::SiteCompanion,
            "example.com",
            "2026-07-31"
        ))
    );
}

#[test]
fn auto_rule_without_provenance_keeps_its_comment_and_stays_a_rule() {
    let result = parse_canonical_rules("--- Auto\nh.example.net  # hand-added by me\n");
    assert_eq!(result.rules.len(), 1);
    assert_eq!(result.rules[0].comment, "hand-added by me");
    assert_eq!(result.rules[0].origin, None);
}

#[test]
fn disabled_auto_rule_keeps_its_provenance() {
    let result = parse_canonical_rules(
        "--- Auto\n# stale.example.net  # auto:user-confirmed anchor:example.com added:2026-01-05\n",
    );
    assert_eq!(result.rules.len(), 1);
    assert!(!result.rules[0].enabled);
    assert_eq!(
        result.rules[0]
            .origin
            .as_ref()
            .map(|o| o.reason().as_slug()),
        Some("user-confirmed")
    );
}

#[test]
fn user_authored_rules_carry_no_origin_and_no_extra_wire_field() {
    let result = parse_canonical_rules("--- Domains\nexample.com  # vendor\n");
    assert_eq!(result.rules[0].origin, None);
    let json = serde_json::to_string(&result.rules[0]).expect("serialize");
    assert!(!json.contains("origin"), "got {json}");
}
