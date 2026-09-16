use super::*;

// ── `--- Auto` section ───────────────────────────────────────────────────

use nrr_shared::auto_rule::AutoRuleReason;

/// The canonical shape of an app-authored line, kept verbatim so a change
/// to the syntax has to be made deliberately here first.
const AUTO_SAMPLE_LINE: &str =
    "rr3.example-cdn.net  # auto:site-companion anchor:example.com added:2026-07-31";

fn auto_origin(reason: AutoRuleReason) -> RuleOrigin {
    RuleOrigin::auto(reason, "example.com", "2026-07-31")
}

#[test]
fn auto_section_header_parses_case_insensitively() {
    for header in ["--- Auto", "--- auto", "--- AUTO"] {
        assert_eq!(
            RulesFileSection::parse_header(header),
            Some(RulesFileSection::Auto),
            "header {header:?} must classify as the app-authored section"
        );
    }
}

#[test]
fn auto_entry_lifts_provenance_out_of_the_inline_comment() {
    let outcome = parse_rules_file(&format!("--- Auto\n{AUTO_SAMPLE_LINE}\n"));
    assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
    let entries = outcome.parsed.entries_for(RulesFileSection::Auto);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].match_value, "rr3.example-cdn.net");
    assert!(entries[0].enabled);
    assert_eq!(
        entries[0].origin,
        Some(auto_origin(AutoRuleReason::SiteCompanion))
    );
    // The tokens are consumed, not duplicated into the label.
    assert_eq!(entries[0].inline_comment, None);
}

#[test]
fn auto_entry_keeps_trailing_free_text_as_the_label() {
    let input =
            "--- Auto\nvideo.example.net  # auto:site-companion anchor:example.com added:2026-07-31 video CDN\n";
    let entries = parse_rules_file(input)
        .parsed
        .entries_for(RulesFileSection::Auto)
        .to_vec();
    assert_eq!(entries[0].inline_comment.as_deref(), Some("video CDN"));
    assert_eq!(
        entries[0].origin,
        Some(auto_origin(AutoRuleReason::SiteCompanion))
    );
}

#[test]
fn auto_entry_accepts_every_known_reason_slug() {
    for reason in AutoRuleReason::KNOWN {
        let input = format!(
            "--- Auto\nh.example.net  # auto:{} anchor:example.com added:2026-07-31\n",
            reason.as_slug()
        );
        let entries = parse_rules_file(&input)
            .parsed
            .entries_for(RulesFileSection::Auto)
            .to_vec();
        assert_eq!(entries[0].origin, Some(auto_origin(reason)));
    }
}

#[test]
fn auto_entry_with_unknown_reason_slug_is_preserved_not_rejected() {
    let input =
        "--- Auto\nh.example.net  # auto:from-the-future anchor:example.com added:2030-01-01\n";
    let outcome = parse_rules_file(input);
    assert!(outcome.warnings.is_empty());
    let entries = outcome.parsed.entries_for(RulesFileSection::Auto);
    assert_eq!(
        entries[0].origin.as_ref().map(RuleOrigin::reason),
        Some(&AutoRuleReason::Other("from-the-future".to_string()))
    );
    // …and it survives a write/parse round-trip unchanged.
    let written = write_rules_file(&outcome.parsed, &[], None);
    assert!(written.contains("auto:from-the-future"), "got:\n{written}");
    assert_eq!(parse_rules_file(&written).parsed, outcome.parsed);
}

#[test]
fn auto_line_without_provenance_is_kept_as_an_ordinary_rule_plus_warning() {
    let input = "--- Auto\nh.example.net  # hand-added by me\nbare.example.net\n";
    let outcome = parse_rules_file(input);
    let entries = outcome.parsed.entries_for(RulesFileSection::Auto);
    // Never dropped, never an error.
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].origin, None);
    assert_eq!(
        entries[0].inline_comment.as_deref(),
        Some("hand-added by me")
    );
    assert_eq!(entries[1].origin, None);
    assert_eq!(
        outcome.warnings,
        vec![
            ParseWarning::AutoRuleMissingProvenance {
                match_value: "h.example.net".to_string()
            },
            ParseWarning::AutoRuleMissingProvenance {
                match_value: "bare.example.net".to_string()
            },
        ]
    );
}

#[test]
fn auto_line_with_partial_provenance_warns_but_keeps_the_origin() {
    let input = "--- Auto\nh.example.net  # auto:site-companion added:2026-07-31\n";
    let outcome = parse_rules_file(input);
    let entries = outcome.parsed.entries_for(RulesFileSection::Auto);
    assert_eq!(entries[0].origin.as_ref().map(RuleOrigin::anchor), Some(""));
    assert_eq!(
        outcome.warnings,
        vec![ParseWarning::AutoRuleIncompleteProvenance {
            match_value: "h.example.net".to_string(),
            reason_slug: "site-companion".to_string(),
        }]
    );
}

#[test]
fn provenance_tokens_are_not_parsed_outside_the_auto_section() {
    // A user's own comment that happens to start with `auto:` stays a
    // comment — provenance is read in the app-authored section only.
    let input = "--- Domains\nh.example.net  # auto:site-companion anchor:x added:2026-07-31\n";
    let outcome = parse_rules_file(input);
    let entries = outcome.parsed.entries_for(RulesFileSection::Domains);
    assert_eq!(entries[0].origin, None);
    assert_eq!(
        entries[0].inline_comment.as_deref(),
        Some("auto:site-companion anchor:x added:2026-07-31")
    );
    assert!(outcome.warnings.is_empty());
}

#[test]
fn auto_entries_round_trip_through_write_and_parse() {
    let input = "\
--- Auto
rr3.example-cdn.net  # auto:site-companion anchor:example.com added:2026-07-31
*.assets.example.net  # auto:site-companion anchor:example.com added:2026-07-31 all asset hosts
# stale.example.net  # auto:user-confirmed anchor:example.com added:2026-01-05
tracker.example.net +block  # auto:user-confirmed anchor:example.com added:2026-02-02
";
    let first = parse_rules_file(input).parsed;
    let written = write_rules_file(&first, &[], None);
    assert_eq!(
        written, input,
        "canonical form must be byte-stable for already-canonical input"
    );
    assert_eq!(parse_rules_file(&written).parsed, first);
}

#[test]
fn writer_emits_the_documented_line_shape() {
    let parsed = RulesFileParsed {
        sections: vec![SectionContent {
            section: RulesFileSection::Auto,
            entries: vec![RulesFileEntry::auto(
                "rr3.example-cdn.net",
                auto_origin(AutoRuleReason::SiteCompanion),
            )],
        }],
    };
    let text = write_rules_file(&parsed, &[], None);
    assert_eq!(text, format!("--- Auto\n{AUTO_SAMPLE_LINE}\n"));
}

#[test]
fn auto_section_sorts_after_every_user_section_on_write() {
    let parsed = RulesFileParsed {
        sections: vec![
            SectionContent {
                section: RulesFileSection::Auto,
                entries: vec![RulesFileEntry::auto(
                    "cdn.example.net",
                    auto_origin(AutoRuleReason::SiteCompanion),
                )],
            },
            SectionContent {
                section: RulesFileSection::Domains,
                entries: vec![RulesFileEntry::enabled("example.com")],
            },
        ],
    };
    let text = write_rules_file(&parsed, &[], None);
    let domains_at = text.find("--- Domains").expect("Domains missing");
    let auto_at = text.find("--- Auto").expect("Auto missing");
    assert!(domains_at < auto_at, "Auto must come last:\n{text}");
}

// ── Auto ⇄ rule-model converters ─────────────────────────────────────────

#[test]
fn auto_section_converts_to_domain_style_rules_carrying_their_origin() {
    let input = "\
--- Auto
rr3.example-cdn.net  # auto:site-companion anchor:example.com added:2026-07-31
*.assets.example.net  # auto:vpn-client-bootstrap anchor:vpn.example.net added:2026-07-31
";
    let parsed = parse_rules_file(input).parsed;
    let set = rules_file_to_route_rule_set(&parsed, HostPlatform::Windows, false);
    assert_eq!(set.rules.len(), 2);
    assert_eq!(
        set.rules[0].address_match,
        Some(crate::AddressMatch::ExactFqdn(
            "rr3.example-cdn.net".to_string()
        ))
    );
    assert_eq!(
        set.rules[0].origin,
        Some(auto_origin(AutoRuleReason::SiteCompanion))
    );
    // `*.x` follows the Domains grammar: suffix domain, prefix stripped.
    assert_eq!(
        set.rules[1].address_match,
        Some(crate::AddressMatch::SuffixDomain(
            "assets.example.net".to_string()
        ))
    );
    assert_eq!(
        set.rules[1].origin.as_ref().map(RuleOrigin::reason),
        Some(&AutoRuleReason::VpnClientBootstrap)
    );
}

#[test]
fn canonical_rule_with_origin_lands_in_auto_and_leaves_domains_untouched() {
    let mut app_authored = rule_with_address(
        "r-1",
        true,
        CanonicalAddressMatch::ExactFqdn("rr3.example-cdn.net".to_string()),
        "",
    );
    app_authored.origin = Some(auto_origin(AutoRuleReason::SiteCompanion));
    let user_authored = rule_with_address(
        "r-2",
        true,
        CanonicalAddressMatch::ExactFqdn("example.com".to_string()),
        "",
    );
    let set = CanonicalRuleSet::from_rules(vec![app_authored, user_authored]);

    let parsed = canonical_rule_set_to_rules_file_parsed(&set, RulesFileSection::Windows);
    assert_eq!(parsed.entries_for(RulesFileSection::Domains).len(), 1);
    assert_eq!(
        parsed.entries_for(RulesFileSection::Domains)[0].match_value,
        "example.com"
    );
    let auto = parsed.entries_for(RulesFileSection::Auto);
    assert_eq!(auto.len(), 1);
    assert_eq!(auto[0].match_value, "rr3.example-cdn.net");
    assert_eq!(
        auto[0].origin,
        Some(auto_origin(AutoRuleReason::SiteCompanion))
    );
}

#[test]
fn app_authored_rule_survives_canonical_to_file_to_rule_set() {
    let mut app_authored = rule_with_address(
        "r-1",
        true,
        CanonicalAddressMatch::SuffixDomain("assets.example.net".to_string()),
        "all asset hosts",
    );
    app_authored.origin = Some(auto_origin(AutoRuleReason::UserConfirmed));
    let set = CanonicalRuleSet::from_rules(vec![app_authored]);

    let text = write_rules_file(
        &canonical_rule_set_to_rules_file_parsed(&set, RulesFileSection::Windows),
        &[],
        None,
    );
    let back = rules_file_to_route_rule_set(
        &parse_rules_file(&text).parsed,
        HostPlatform::Windows,
        false,
    );
    assert_eq!(back.rules.len(), 1);
    assert_eq!(
        back.rules[0].address_match,
        Some(crate::AddressMatch::SuffixDomain(
            "assets.example.net".to_string()
        ))
    );
    assert_eq!(
        back.rules[0].origin,
        Some(auto_origin(AutoRuleReason::UserConfirmed))
    );
    assert_eq!(back.rules[0].comment, "all asset hosts");
}

#[test]
fn non_domain_address_kinds_keep_their_section_even_with_an_origin() {
    // The Auto section carries domain-style values only — an IP written
    // there would be re-read as a hostname, so it stays in `--- IP`.
    let mut ip_rule = rule_with_address(
        "r-1",
        true,
        CanonicalAddressMatch::ExactIp(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
        "",
    );
    ip_rule.origin = Some(auto_origin(AutoRuleReason::SiteCompanion));
    let set = CanonicalRuleSet::from_rules(vec![ip_rule]);
    let parsed = canonical_rule_set_to_rules_file_parsed(&set, RulesFileSection::Windows);
    assert_eq!(parsed.sections.len(), 1);
    assert_eq!(parsed.sections[0].section, RulesFileSection::Ip);
    // No provenance is written where it could not be read back.
    assert_eq!(parsed.sections[0].entries[0].origin, None);
    let text = write_rules_file(&parsed, &[], None);
    assert_eq!(parse_rules_file(&text).parsed, parsed);
}

#[test]
fn user_authored_rules_are_unaffected_by_the_origin_field() {
    let outcome = parse_rules_file(SAMPLE_FILE);
    let set = rules_file_to_route_rule_set(&outcome.parsed, HostPlatform::Windows, false);
    assert!(
        set.rules.iter().all(|r| r.origin.is_none()),
        "no section other than Auto may produce an origin"
    );
    let written = write_rules_file(&outcome.parsed, &[], None);
    assert!(!written.contains("auto:"), "got:\n{written}");
}
