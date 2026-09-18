// Writing a rules file back out, preserving unsupported sections.

use super::parse::BLOCK_FLAG;
use super::*;

/// Serialises a [`RulesFileParsed`] (and optional unsupported sections) back to
/// canonical rules-file text.
///
/// This is the inverse of [`parse_rules_file`]: feeding the output back through
/// the parser produces a structurally equivalent [`ParseOutcome`].
///
/// # Format
///
/// - If `metadata` is `Some`, a `# NetRuleRouter preset — version 1` header is
///   written followed by `# key: value` lines for each populated metadata
///   field, then a blank line.
/// - All known sections appear in canonical order
///   (Zones → Domains → IP → Windows → Linux → MacOS → Auto), **including
///   empty sections** (docs/en/rules-file-format.md Sections — empty sections must not be stripped).
/// - Unknown sections from `unknown` are written after the known ones, in the
///   order supplied. This preserves unsupported sections through a Free
///   round-trip.
/// - Active rule line: `value` (no inline comment) or `value  # comment`
///   (two spaces before `#`, matching docs/en/rules-file-format.md Complete example examples).
/// - Disabled rule line: `# value` or `# value  # comment`.
/// - Sections are separated by a blank line for readability.
///
/// # Round-trip guarantee
///
/// For any `parsed: &RulesFileParsed`:
///
/// ```text
/// let text = write_rules_file(&parsed, &[], None);
/// let again = parse_rules_file(&text).parsed;
/// assert_eq!(again, *parsed);
/// ```
///
/// unsupported section preservation requires the caller to thread the original
/// `unknown_sections` through (the canonical revision store does not retain
/// them today). A caller holding them as raw text instead of parsed entries —
/// an exporter reading that store — uses
/// [`write_rules_file_with_passthrough`].
pub fn write_rules_file(
    parsed: &RulesFileParsed,
    unknown: &[UnknownSection],
    metadata: Option<&PresetMetadata>,
) -> String {
    write_rules_file_with_passthrough(parsed, unknown, &[], metadata)
}

/// [`write_rules_file`] plus sections carried as raw text.
///
/// An exporter reading the canonical revision store has no `unknown_sections`
/// to thread through — the store does not retain them — so without this the
/// foreign-OS and unsupported blocks a user imported are dropped on the way
/// back out, against the preservation guarantee on [`UnknownSection`]. The
/// caller that captured them at import time supplies them here.
pub fn write_rules_file_with_passthrough(
    parsed: &RulesFileParsed,
    unknown: &[UnknownSection],
    passthrough: &[PassthroughSection],
    metadata: Option<&PresetMetadata>,
) -> String {
    let mut out = String::new();

    // Preamble: preset header + metadata, when supplied.
    if let Some(meta) = metadata {
        out.push_str("# NetRuleRouter preset \u{2014} version ");
        out.push_str(&CURRENT_PRESET_FORMAT_VERSION.to_string());
        out.push('\n');
        if let Some(name) = &meta.name {
            out.push_str("# name: ");
            out.push_str(name);
            out.push('\n');
        }
        if let Some(description) = &meta.description {
            out.push_str("# description: ");
            out.push_str(description);
            out.push('\n');
        }
        if let Some(author) = &meta.author {
            out.push_str("# author: ");
            out.push_str(author);
            out.push('\n');
        }
        if let Some(preset_version) = &meta.preset_version {
            out.push_str("# preset_version: ");
            out.push_str(preset_version);
            out.push('\n');
        }
        out.push('\n');
    }

    // Emit only sections present in `parsed.sections`, but in canonical
    // order (Zones → Auto). A section that exists with zero entries is
    // preserved as `--- Name\n` per docs/en/rules-file-format.md Sections
    let by_section: std::collections::HashMap<RulesFileSection, &[RulesFileEntry]> = parsed
        .sections
        .iter()
        .map(|s| (s.section, s.entries.as_slice()))
        .collect();

    let mut first_section = true;
    for section in &RulesFileSection::ALL {
        let Some(entries) = by_section.get(section) else {
            continue;
        };
        if !first_section {
            out.push('\n');
        }
        first_section = false;
        out.push_str("--- ");
        out.push_str(section.name());
        out.push('\n');
        for entry in *entries {
            write_entry_line(&mut out, entry, section.is_app_authored());
        }
    }

    // Append unknown (unsupported) sections in supplied order.
    for unknown_section in unknown {
        if !first_section {
            out.push('\n');
        }
        first_section = false;
        out.push_str("--- ");
        out.push_str(&unknown_section.name);
        out.push('\n');
        for entry in &unknown_section.entries {
            write_entry_line(&mut out, entry, false);
        }
    }

    // Raw-text sections last, in supplied order. The body is emitted verbatim:
    // the point of carrying bytes instead of entries is that nothing here is
    // re-rendered.
    for section in passthrough {
        if !first_section {
            out.push('\n');
        }
        first_section = false;
        out.push_str("--- ");
        out.push_str(&section.name);
        out.push('\n');
        out.push_str(&section.body);
        if !section.body.is_empty() && !section.body.ends_with('\n') {
            out.push('\n');
        }
    }

    out
}

/// Writes a single rule line in canonical format.
///
/// - Active rule: `value` or `value  # comment`.
/// - Disabled rule: `# value` or `# value  # comment`.
///
/// The two-space separator before the inline `#` mirrors the canonical form
/// shown in docs/en/rules-file-format.md Complete example examples.
///
/// `emit_origin` is set for the app-authored section only. Its provenance
/// tokens are rendered from the entry's typed fields and precede the free-text
/// note, so a hand-edited file is normalised to canonical token order:
/// `value  # auto:<slug> anchor:<host> added:<date> <note>`.
fn write_entry_line(out: &mut String, entry: &RulesFileEntry, emit_origin: bool) {
    if !entry.enabled {
        out.push_str("# ");
    }
    out.push_str(&entry.match_value);
    if entry.blocked {
        out.push(' ');
        out.push_str(BLOCK_FLAG);
    }
    let provenance = if emit_origin {
        entry
            .origin
            .as_ref()
            .map(|origin| origin.to_provenance_comment())
    } else {
        None
    };
    if provenance.is_some() || entry.inline_comment.is_some() {
        out.push_str("  # ");
        if let Some(tokens) = &provenance {
            out.push_str(tokens);
            if entry.inline_comment.is_some() {
                out.push(' ');
            }
        }
        if let Some(comment) = &entry.inline_comment {
            out.push_str(comment);
        }
    }
    out.push('\n');
}

// ── DB cache policy invariant ─────────────────────────────────────────────────
