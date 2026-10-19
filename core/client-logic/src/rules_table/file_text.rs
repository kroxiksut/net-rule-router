//! THE rules-file writer (`buildCanonicalRulesText`): one text per route,
//! grouped into the sections of `docs/en/rules-file-format.md`, built from the
//! rows in front of the user — never from a service round-trip, which is what
//! makes saving work with the service stopped.

use std::collections::BTreeMap;

use nrr_shared::preset_parser::SYNTAX_HINT_PREFIX;

use super::{RuleRow, RuleType, TargetRoute};
use crate::{js, Route};

/// The preset format version this build writes. Mirrors
/// `nrr_domain::rules_file::CURRENT_RULES_FILE_FORMAT_VERSION` through the
/// GUI's `CANONICAL_PRESET_FORMAT_VERSION`, which a GUI test pins to it.
pub const PRESET_FORMAT_VERSION: u32 = 11;

/// Room between a rule and its inline comment.
const COMMENT_GAP: &str = "          # ";

/// The syntax hint a written file opens with: locale key and English text per
/// line, in file order. The caller translates them (the GUI's twin is
/// `RULES_FILE_HINT_KEYS` in `rules.js`) and hands the lines in through
/// [`RulesFileOptions::syntax_hint`].
pub const RULES_FILE_HINT_KEYS: [(&str, &str); 10] = [
    (
        "rules.file-hint.section",
        r"--- Name         section header: rule type below     --- Domains",
    ),
    (
        "rules.file-hint.value",
        r"value            rule: goes over this file's route   example.com",
    ),
    (
        "rules.file-hint.subdomains",
        r"*.value          the site and all its subdomains     *.example.com",
    ),
    (
        "rules.file-hint.any-zone",
        r"value.*          the site in every zone              example.*",
    ),
    (
        "rules.file-hint.deny",
        r"!value           deny: through no connection at all  !ads.example.net",
    ),
    (
        "rules.file-hint.verify",
        r"?value           this route while the site opens     ?mail.example.com",
    ),
    (
        "rules.file-hint.disabled",
        r"# value          rule kept but turned off            # example.com",
    ),
    (
        "rules.file-hint.note",
        r"value  # note    rule with your note                 example.com  # updates",
    ),
    (
        "rules.file-hint.children",
        r"value +children  the app and the programs it starts  codex.exe +children",
    ),
    (
        "rules.file-hint.comment",
        r"# text           comment, not a rule                 # my notes",
    ),
];

/// Bounds on the hint, whose text comes from locale files a user can drop
/// in. A line is measured in UTF-16 units, as its JS twin's `length`.
const HINT_MAX_LINES: usize = 16;
const HINT_MAX_LINE: usize = 200;

/// How a rules file is written.
#[derive(Clone, Copy, Debug)]
pub struct RulesFileOptions<'a> {
    /// `false` strips user comments; app provenance is written regardless,
    /// or the next import reads the rule as one the user typed.
    pub include_comments: bool,
    /// The export moment for the `# description:` line, ISO 8601. The
    /// caller owns the clock.
    pub exported_at: &'a str,
    /// Sections captured at the previous import that this build does not
    /// apply (another OS's applications, say), name to raw text. They ride
    /// through untouched, by name order.
    pub passthrough: &'a BTreeMap<String, String>,
    /// The `PlatformProfile::os` the file is written on: application rules
    /// go under that OS's section, the only one its parser applies.
    pub os: &'a str,
    /// The hint lines, already translated (see [`RULES_FILE_HINT_KEYS`]);
    /// empty writes no hint.
    pub syntax_hint: &'a [String],
}

/// The application section of `os` (`RulesFileSection::host_app` in the
/// domain writer). The profile names no other OS.
fn app_section_header(os: &str) -> &'static str {
    match os {
        "linux" => "Linux",
        "macos" => "MacOS",
        _ => "Windows",
    }
}

/// The sections in the order the Rust writer emits them
/// (`nrr_domain::rules_file::RulesFileSection::ALL`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Section {
    Zones,
    Domains,
    Ip,
    Cidr,
    Ranges,
    Apps,
    Auto,
}

impl Section {
    const ALL: [Self; 7] = [
        Self::Zones,
        Self::Domains,
        Self::Ip,
        Self::Cidr,
        Self::Ranges,
        Self::Apps,
        Self::Auto,
    ];

    fn header(self, os: &str) -> &'static str {
        match self {
            Self::Zones => "Zones",
            Self::Domains => "Domains",
            Self::Ip => "IP",
            Self::Cidr => "CIDR",
            Self::Ranges => "Ranges",
            Self::Apps => app_section_header(os),
            Self::Auto => "Auto",
        }
    }

    /// `None` for a type the file has no section for — the row is skipped,
    /// as the parser skips it on the way in.
    fn of(rule_type: &RuleType) -> Option<Self> {
        match rule_type {
            RuleType::Zone => Some(Self::Zones),
            RuleType::Domain | RuleType::SuffixDomain | RuleType::ExactFqdn => Some(Self::Domains),
            RuleType::ExactIp | RuleType::ExactIpv4 | RuleType::ExactIpv6 => Some(Self::Ip),
            RuleType::Subnet => Some(Self::Cidr),
            RuleType::IpRange => Some(Self::Ranges),
            RuleType::Application => Some(Self::Apps),
            RuleType::Other(_) => None,
        }
    }
}

/// A control character inside one field would start a line the parser reads
/// as a rule or a section of its own (`neutralize_field` in the Rust writer).
/// Tab stays.
fn one_line(value: &str) -> String {
    value
        .chars()
        .map(|c| match c {
            '\u{0}'..='\u{8}' | '\u{a}'..='\u{1f}' | '\u{7f}'..='\u{9f}' => ' ',
            other => other,
        })
        .collect()
}

/// The hint as written (`rulesFileHintBlock`): each line behind the marker
/// both parsers skip, one line each, blank and overlong ones left out.
fn syntax_hint_block(texts: &[String]) -> Vec<String> {
    texts
        .iter()
        .filter_map(|text| {
            let text = one_line(text);
            let text = js::trim(&text);
            let fits = !text.is_empty() && text.encode_utf16().count() <= HINT_MAX_LINE;
            fits.then(|| format!("{SYNTAX_HINT_PREFIX} {text}"))
        })
        .take(HINT_MAX_LINES)
        .collect()
}

/// The text of the rules file for `route` (`buildCanonicalRulesText`).
///
/// Host values are written in Unicode form, as stored. A block row rides in
/// the secondary file marked by a `!` before the value; a `?` row is marked by
/// a `?` there in its own file; a disabled row is written commented out. An
/// app-authored domain rule moves to `--- Auto` with the provenance tokens the
/// parser reads it back from; an app-authored program rule carries them in its
/// own section.
pub fn build_rules_file_text(
    rows: &[RuleRow],
    route: Route,
    options: &RulesFileOptions<'_>,
) -> String {
    let mut sections: [Vec<String>; Section::ALL.len()] = Default::default();
    for row in rows
        .iter()
        .filter(|row| row.target_route.bucket() == Some(route))
    {
        let Some(mut section) = Section::of(&row.rule_type) else {
            continue;
        };
        // A domain rule carries provenance in `--- Auto`, a program rule in
        // its own section; any other kind goes without (`--- Auto` parses as
        // domains, and losing the badge beats corrupting the rule).
        let origin = row
            .auto_origin()
            .filter(|_| matches!(section, Section::Domains | Section::Apps));
        if origin.is_some() && section == Section::Domains {
            section = Section::Auto;
        }
        let value = one_line(&row.match_value);
        let value = js::trim(&value);
        if value.is_empty() {
            continue;
        }

        let mut line = String::new();
        if !row.enabled {
            line.push_str("# ");
        }
        // A block row is never `is_verify`, so the two marks never meet.
        if row.target_route == TargetRoute::Block {
            line.push('!');
        } else if row.is_verify() {
            line.push('?');
        }
        line.push_str(value);

        let comment = if options.include_comments {
            one_line(&row.comment)
        } else {
            String::new()
        };
        let comment = js::trim(&comment);
        if let Some(origin) = origin {
            line.push_str(COMMENT_GAP);
            line.push_str("auto:");
            line.push_str(&one_line(&origin.reason));
            for (token, raw) in [(" anchor:", &origin.anchor), (" added:", &origin.added)] {
                let text = one_line(raw);
                let text = js::trim(&text);
                if !text.is_empty() {
                    line.push_str(token);
                    line.push_str(text);
                }
            }
            if !comment.is_empty() {
                line.push(' ');
                line.push_str(comment);
            }
        } else if !comment.is_empty() {
            line.push_str(COMMENT_GAP);
            line.push_str(comment);
        }
        sections[section as usize].push(line);
    }

    let name_label = match route {
        Route::Primary => "Primary Route",
        Route::Secondary => "Secondary Route",
    };
    // A header claiming an older version tells the reader the newer sections
    // are not there.
    let mut lines = vec![
        format!("# NetRuleRouter preset \u{2014} version {PRESET_FORMAT_VERSION}"),
        format!("# name: NetRuleRouter Export - {name_label}"),
        format!(
            "# description: Exported from the NetRuleRouter app on {}",
            options.exported_at
        ),
        "# preset_version: 1".to_owned(),
        String::new(),
    ];
    let hint = syntax_hint_block(options.syntax_hint);
    if !hint.is_empty() {
        lines.extend(hint);
        lines.push(String::new());
    }
    for (section, bucket) in Section::ALL.iter().zip(sections) {
        lines.push(format!("--- {}", section.header(options.os)));
        lines.extend(bucket);
        lines.push(String::new());
    }
    for (name, raw_text) in options.passthrough {
        lines.push(format!("--- {name}"));
        // Stored text ends in exactly one newline when non-empty; the split
        // leaves an empty last entry that is not a line.
        if !raw_text.is_empty() {
            let raw = raw_text.strip_suffix('\n').unwrap_or(raw_text.as_str());
            lines.extend(raw.split('\n').map(str::to_owned));
        }
        lines.push(String::new());
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_on(os: &str) -> String {
        let row = RuleRow {
            id: String::new(),
            enabled: true,
            rule_type: RuleType::Application,
            match_value: "client".to_owned(),
            target_route: TargetRoute::Secondary,
            verify: false,
            comment: String::new(),
            origin: None,
        };
        let options = RulesFileOptions {
            include_comments: true,
            exported_at: "2026-01-01T00:00:00Z",
            passthrough: &BTreeMap::new(),
            os,
            syntax_hint: &[],
        };
        build_rules_file_text(&[row], Route::Secondary, &options)
    }

    /// A block is written `!value` and reads back as a block; the retired
    /// suffix is never written.
    #[test]
    fn a_block_row_round_trips_through_the_parser() {
        let row = |rule_type, value: &str, enabled| RuleRow {
            id: String::new(),
            enabled,
            rule_type,
            match_value: value.to_owned(),
            target_route: TargetRoute::Block,
            verify: true,
            comment: String::new(),
            origin: None,
        };
        let rows = [
            row(RuleType::Domain, "ads.example", true),
            row(RuleType::ExactIp, "192.0.2.7", false),
        ];
        let options = RulesFileOptions {
            include_comments: true,
            exported_at: "2026-01-01T00:00:00Z",
            passthrough: &BTreeMap::new(),
            os: "windows",
            syntax_hint: &[],
        };
        let text = build_rules_file_text(&rows, Route::Secondary, &options);
        assert!(text.contains("\n!ads.example\n"), "{text}");
        assert!(text.contains("\n# !192.0.2.7\n"), "{text}");
        assert!(!text.contains("+block"), "{text}");
        let parsed = nrr_shared::preset_parser::parse_canonical_rules(&text);
        let read: Vec<_> = parsed
            .rules
            .iter()
            .map(|r| {
                (
                    r.match_value.as_str(),
                    r.enabled,
                    r.blocked,
                    r.verify_primary,
                )
            })
            .collect();
        assert_eq!(
            read,
            [
                ("ads.example", true, true, false),
                ("192.0.2.7", false, true, false),
            ]
        );
    }

    /// Write, read, write: one hint, the same text. The parser skips the hint,
    /// so nothing of it comes back as a rule to be written twice, while the
    /// user's own note on a rule stays.
    #[test]
    fn the_hint_is_written_once_and_never_read_back() {
        let hint: Vec<String> = RULES_FILE_HINT_KEYS
            .iter()
            .map(|(_, en)| (*en).to_owned())
            .collect();
        let row = |rule_type, value: &str, enabled, comment: &str| RuleRow {
            id: String::new(),
            enabled,
            rule_type,
            match_value: value.to_owned(),
            target_route: TargetRoute::Primary,
            verify: false,
            comment: comment.to_owned(),
            origin: None,
        };
        let rows = [
            row(RuleType::Domain, "example.com", true, "updates"),
            row(RuleType::Domain, "off.example.com", false, ""),
            row(RuleType::ExactIp, "192.0.2.7", true, ""),
        ];
        let options = RulesFileOptions {
            include_comments: true,
            exported_at: "2026-01-01T00:00:00Z",
            passthrough: &BTreeMap::new(),
            os: "windows",
            syntax_hint: &hint,
        };
        let first = build_rules_file_text(&rows, Route::Primary, &options);
        let is_hint = nrr_shared::preset_parser::is_syntax_hint_line;
        assert_eq!(first.lines().filter(|l| is_hint(l)).count(), hint.len());
        assert!(
            first.contains("# preset_version: 1\n\n#: --- Name"),
            "{first}"
        );

        let parsed = nrr_shared::preset_parser::parse_canonical_rules(&first);
        let back: Vec<RuleRow> = parsed
            .rules
            .iter()
            .map(|rule| RuleRow {
                comment: rule.comment.clone(),
                ..crate::rules_table::drift_row_from_parsed_rule(rule, Route::Primary)
            })
            .collect();
        assert_eq!(back, rows);
        assert_eq!(
            build_rules_file_text(&back, Route::Primary, &options),
            first
        );
    }

    #[test]
    fn hint_lines_are_one_line_each_and_bounded() {
        let mut texts = vec![
            "a\nb".to_owned(),
            "   ".to_owned(),
            "x".repeat(HINT_MAX_LINE + 1),
            "\u{1F600}".repeat(HINT_MAX_LINE / 2),
        ];
        texts.extend((0..HINT_MAX_LINES).map(|n| format!("line {n}")));
        let block = syntax_hint_block(&texts);
        assert_eq!(block.len(), HINT_MAX_LINES);
        assert_eq!(block[0], "#: a b");
        assert_eq!(
            block[1],
            format!("#: {}", "\u{1F600}".repeat(HINT_MAX_LINE / 2))
        );
        assert_eq!(block[2], "#: line 0");
    }

    #[test]
    fn application_rules_go_under_the_section_of_the_os_written_on() {
        for (os, header) in [
            ("windows", "--- Windows"),
            ("linux", "--- Linux"),
            ("macos", "--- MacOS"),
        ] {
            let text = text_on(os);
            assert!(
                text.contains(&format!("{header}\nclient\n")),
                "{os}: {text}"
            );
            let app_headers = ["--- Windows", "--- Linux", "--- MacOS"];
            assert_eq!(
                app_headers.iter().filter(|h| text.contains(*h)).count(),
                1,
                "{os}: {text}"
            );
        }
    }
}
