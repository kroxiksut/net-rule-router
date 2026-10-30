// Sections a build reads but does not apply, carried from the rules file a
// write replaces into the text that replaces it: they live only in that file.

use std::borrow::Cow;
use std::collections::BTreeMap;

use super::{classify_section_lenient, parse_canonical_rules, parse_section_header};

/// One section's text added under its name: a name already held keeps its
/// text and gets this one after it, so a section written twice loses nothing
/// of its first copy.
pub fn add_passthrough_block(sections: &mut BTreeMap<String, String>, name: &str, raw: &str) {
    if name.is_empty() {
        return;
    }
    let text = sections.entry(name.to_owned()).or_default();
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(raw);
}

/// The sections of `text` this build does not apply, merged per name.
pub fn passthrough_sections(text: &str) -> BTreeMap<String, String> {
    let mut sections = BTreeMap::new();
    for block in parse_canonical_rules(text).passthrough {
        add_passthrough_block(&mut sections, &block.section_name, &block.raw_text);
    }
    sections
}

/// `text` with the sections this build does not apply replaced by
/// `sections`, appended the way the rules-file writer appends them: after the
/// rest, by name, each followed by a blank line.
pub fn with_passthrough_sections(text: &str, sections: &BTreeMap<String, String>) -> String {
    // The parser reads past a BOM; a header behind one must not stay here.
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut lines: Vec<Cow<'_, str>> = Vec::new();
    let mut skipping = false;
    for line in text.split('\n') {
        if let Some(name) = parse_section_header(line.strip_suffix('\r').unwrap_or(line)) {
            skipping = classify_section_lenient(name).is_none();
        }
        if !skipping {
            lines.push(Cow::Borrowed(line));
        }
    }
    // One blank line before the carried sections however the text ended, so
    // the same rules always come out as the same text.
    while lines.last().is_some_and(|line| line.trim().is_empty()) {
        lines.pop();
    }
    if !lines.is_empty() {
        lines.push(Cow::Borrowed(""));
    }
    for (name, raw) in sections {
        lines.push(Cow::Owned(format!("--- {name}")));
        if !raw.is_empty() {
            let raw = raw.strip_suffix('\n').unwrap_or(raw);
            lines.extend(raw.split('\n').map(Cow::Borrowed));
        }
        lines.push(Cow::Borrowed(""));
    }
    lines.join("\n")
}

/// What routes in a rules file: past the leading blank and `#` lines (the
/// header carries the time of writing), trailing blank lines dropped, line
/// ends trimmed. The window's `canonicalRulesBody`.
pub fn canonical_rules_body(text: &str) -> String {
    let lines: Vec<&str> = text.lines().map(str::trim_end).collect();
    let start = lines
        .iter()
        .position(|line| !line.is_empty() && !line.starts_with('#'))
        .unwrap_or(lines.len());
    let end = lines
        .iter()
        .rposition(|line| !line.is_empty())
        .map_or(start, |last| (last + 1).max(start));
    lines[start..end].join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file saved by a Windows editor opens with a BOM: carried back into
    /// its own text, each section it holds comes out once, not twice.
    #[test]
    fn a_section_carried_into_a_text_that_opens_with_a_bom_is_kept_once() {
        let text = "\u{feff}--- Geo\nsome line\n\n--- Domains\na.example\n";
        let sections = passthrough_sections(text);
        let carried = with_passthrough_sections(text, &sections);
        assert_eq!(passthrough_sections(&carried), sections, "{carried:?}");
    }
}
