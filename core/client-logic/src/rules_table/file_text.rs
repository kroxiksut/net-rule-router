//! THE rules-file writer (`buildCanonicalRulesText`): one text per route,
//! grouped into the sections of `docs/en/rules-file-format.md`, built from the
//! rows in front of the user — never from a service round-trip, which is what
//! makes saving work with the service stopped.

use std::collections::BTreeMap;

use super::{RuleRow, RuleType, TargetRoute};
use crate::{js, Route};

/// The preset format version this build writes. Mirrors
/// `nrr_domain::rules_file::CURRENT_RULES_FILE_FORMAT_VERSION` through the
/// GUI's `CANONICAL_PRESET_FORMAT_VERSION`, which a GUI test pins to it.
pub const PRESET_FORMAT_VERSION: u32 = 6;

/// Room between a rule and its inline comment.
const COMMENT_GAP: &str = "          # ";

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

/// The text of the rules file for `route` (`buildCanonicalRulesText`).
///
/// Host values are written in Unicode form, as stored. A block or verify row
/// rides in the secondary file, marked by `+block` or a `?` before the value;
/// a disabled row is written commented out. An app-authored domain rule moves
/// to `--- Auto` with the provenance tokens the parser reads it back from.
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
        // Only the domain section can carry provenance: `--- Auto` parses as
        // domains, and losing the badge beats corrupting the rule.
        let origin = row.auto_origin().filter(|_| section == Section::Domains);
        if origin.is_some() {
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
        if row.target_route == TargetRoute::Verify {
            line.push('?');
        }
        line.push_str(value);
        if row.target_route == TargetRoute::Block {
            line.push_str(" +block");
        }

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
            comment: String::new(),
            origin: None,
        };
        let options = RulesFileOptions {
            include_comments: true,
            exported_at: "2026-01-01T00:00:00Z",
            passthrough: &BTreeMap::new(),
            os,
        };
        build_rules_file_text(&[row], Route::Secondary, &options)
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
