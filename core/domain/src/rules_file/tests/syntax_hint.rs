// ── the `#:` syntax hint ──────────────────────────────────────────────────
//
// The client writer opens a file with a few `#:` lines explaining the syntax.
// Their examples are rule-shaped on purpose; none may ever become a rule, a
// metadata value or a second copy of the hint.

use super::*;

/// The head of a file as the client writer emits it.
const HEADED: &str = concat!(
    "# NetRuleRouter preset \u{2014} version 9\n",
    r"# name: NetRuleRouter Export - Primary Route
# description: Exported from the NetRuleRouter app on 2026-01-02T03:04:05.000Z
# preset_version: 1

#: --- Name         section header: rule type below     --- Domains
#: value            rule: goes over this file's route   example.com
#: !value           deny: through no connection at all  !ads.example.net
#: ?value           this route while the site opens     ?mail.example.com
#: # value          rule kept but turned off            # example.com
#: value  # note    rule with your note                 example.com  # updates
#: value +children  the app and the programs it starts  codex.exe +children
#: name: not the preset name

--- Domains
live.example.com  # updates
# off.example.com
# my notes

--- Windows
client.exe
"
);

#[test]
fn the_hint_is_skipped_and_the_header_still_read() {
    let outcome = parse_rules_file(HEADED);
    assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
    assert_eq!(outcome.file_format_version, Some(9));
    let meta = outcome.preset_metadata.expect("preset header");
    assert_eq!(
        meta.name.as_deref(),
        Some("NetRuleRouter Export - Primary Route")
    );
    let domains: Vec<_> = outcome
        .parsed
        .entries_for(RulesFileSection::Domains)
        .iter()
        .map(|e| {
            (
                e.match_value.as_str(),
                e.enabled,
                e.inline_comment.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        domains,
        [
            ("live.example.com", true, Some("updates")),
            ("off.example.com", false, None),
        ]
    );
    let apps = outcome.parsed.entries_for(RulesFileSection::Windows);
    assert_eq!(apps.len(), 1);
    assert_eq!(apps[0].match_value, "client.exe");
}

/// Inside a section `#:example.com` would otherwise read as a disabled rule
/// and `#: Adobe Reader.exe` as a disabled program.
#[test]
fn a_hint_example_inside_a_section_is_not_a_rule() {
    let text = "--- Domains
#:example.com
#: # example.com
#: !ads.example.net
--- IP
#:192.0.2.7
--- Windows
#: Adobe Reader.exe
--- Ports
#:443
";
    let outcome = parse_rules_file(text);
    for section in [
        RulesFileSection::Domains,
        RulesFileSection::Ip,
        RulesFileSection::Windows,
    ] {
        assert!(
            outcome.parsed.entries_for(section).is_empty(),
            "{section:?}: {:?}",
            outcome.parsed.entries_for(section)
        );
    }
    assert_eq!(outcome.unknown_sections.len(), 1);
    assert!(outcome.unknown_sections[0].entries.is_empty());
    let shared = nrr_shared::preset_parser::parse_canonical_rules(text);
    assert!(shared.rules.is_empty(), "{:?}", shared.rules);
}

/// Reading a hinted file and writing it back gives no hint lines (this
/// writer emits none), and reading that again gives the same rules: nothing
/// of the hint survives to be doubled by the next write.
#[test]
fn the_hint_never_accumulates_through_a_round_trip() {
    let first = parse_rules_file(HEADED);
    let written = write_rules_file(&first.parsed, &first.unknown_sections, None);
    let is_hint = nrr_shared::preset_parser::is_syntax_hint_line;
    assert!(!written.lines().any(is_hint), "{written}");
    let head: Vec<&str> = HEADED
        .lines()
        .take_while(|line| !line.starts_with("--- "))
        .collect();
    let rehinted = format!("{}\n{written}", head.join("\n"));
    let again = parse_rules_file(&rehinted);
    assert_eq!(again.parsed, first.parsed);
}

/// A user's own `#` lines read as they always did: a disabled rule stays one,
/// a note beside a rule stays its note, prose stays prose.
#[test]
fn the_users_own_comments_are_read_as_before() {
    let outcome = parse_rules_file(
        "# my file, my notes\n--- Domains\n# example.com  # parked\n# see the wiki\nexample.net  # work\n",
    );
    let read: Vec<_> = outcome
        .parsed
        .entries_for(RulesFileSection::Domains)
        .iter()
        .map(|e| {
            (
                e.match_value.as_str(),
                e.enabled,
                e.inline_comment.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        read,
        [
            ("example.com", false, Some("parked")),
            ("example.net", true, Some("work")),
        ]
    );
}
