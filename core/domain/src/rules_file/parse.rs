// Reading a rules file: headers, entries, inline comments and flags.

use super::*;

/// Parses a rules file from its raw text content.
///
/// The parser is lenient by design: unknown sections are preserved with a
/// warning, unrecognized lines are treated as free comments, and the function
/// never returns an error. Semantic validation of individual rule values is
/// done later in the pipeline by [`crate::validation::validate_and_canonicalize`].
///
/// # Algorithm
///
/// Lines are classified in order:
/// 1. Empty or whitespace-only, or a `#:` syntax-hint line → ignored.
/// 2. `--- SectionName` → section header; starts a new section context.
/// 3. `# value` → disabled rule if the part after `#` is a single word;
///    otherwise a free comment (ignored).
/// 4. Any other non-empty line → active rule, optionally with an inline comment
///    after `#`.
///
/// Lines before the first section header are treated as free comments.
/// Tries to extract the format version from a preamble line of the form
/// `# NetRuleRouter rules file — version N`.
fn parse_version_header(line: &str) -> Option<u32> {
    parse_dashed_header(line, "# NetRuleRouter rules file ", " version ")
}

/// Every dash a person or an editor can produce where the format documents an
/// em-dash.
///
/// Only the em-dash is WRITTEN, and the docs keep saying so. Accepting only it
/// on READ was a separate decision, and the wrong one: an ASCII hyphen is what
/// a keyboard gives you, what an editor's autocorrect leaves behind, and what
/// most of the presets in this repository actually contain — so their version
/// header went unrecognised, `is_preset_file` stayed false, and the "this file
/// is from a newer version" branch could never fire on the files it was
/// written for.
const HEADER_DASHES: [&str; 3] = ["\u{2014}", "\u{2013}", "-"];

/// `{prefix}{dash}{infix}{number}`, for any accepted spelling of the dash.
fn parse_dashed_header(line: &str, prefix: &str, infix: &str) -> Option<u32> {
    let rest = line.trim().strip_prefix(prefix)?;
    for dash in HEADER_DASHES {
        if let Some(number) = rest.strip_prefix(dash).and_then(|t| t.strip_prefix(infix)) {
            return number.trim().parse::<u32>().ok();
        }
    }
    None
}

/// Parses a preset format header: `# NetRuleRouter preset — version N`.
///
/// Returns the declared format version or `None` if the line does not match.
fn parse_preset_header(line: &str) -> Option<u32> {
    parse_dashed_header(line, "# NetRuleRouter preset ", " version ")
}

/// Parses a metadata key-value comment from the file preamble.
///
/// Matches `# key: value` where `key` is a non-empty ASCII word token
/// (letters, digits, underscores) and `value` is the trimmed remainder.
/// Returns `(key, value)` or `None` if the line does not match.
fn parse_metadata_kv(line: &str) -> Option<(&str, &str)> {
    let rest = line.strip_prefix('#')?.trim_start();
    let colon = rest.find(':')?;
    let key = rest[..colon].trim();
    if key.is_empty()
        || key.contains(char::is_whitespace)
        || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    let value = rest[colon + 1..].trim();
    Some((key, value))
}

pub fn parse_rules_file(input: &str) -> ParseOutcome {
    // A file saved by a Windows editor starts with a BOM. One caller
    // (`preset_validation`) stripped it before handing the text over and the
    // others did not, so the same file parsed differently depending on the
    // route in. Stripped here, once, for every caller and both parsers.
    let input = input.strip_prefix('\u{feff}').unwrap_or(input);
    let mut known: Vec<SectionContent> = Vec::new();
    let mut unknown: Vec<UnknownSection> = Vec::new();
    // Name → position in `unknown`, so a file full of distinct headers costs
    // linear time rather than quadratic.
    let mut unknown_index: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut warnings: Vec<ParseWarning> = Vec::new();
    let mut file_format_version: Option<u32> = None;
    let mut is_preset_file = false;
    let mut preset_meta: Option<PresetMetadata> = None;

    // Which slot is "current": either an index into `known` or `unknown`.
    enum Slot {
        Known(usize),
        Unknown(usize),
    }
    let mut current: Option<Slot> = None;

    for line in input.lines() {
        let trimmed = line.trim();

        if trimmed.is_empty() || nrr_shared::preset_parser::is_syntax_hint_line(trimmed) {
            continue;
        }

        // Section header? Checked first so `--- SectionName` lines are never
        // consumed by the preamble block below.
        //
        // Recognised by the SHARED header parser, not by a second reading of
        // the same spec: this side used to accept a header with leading
        // whitespace (`  --- IP`) while the GUI's parser did not, so the
        // service opened a section the GUI kept feeding to the previous one —
        // and every address after it landed under the wrong heading. The strict
        // reading is the one the format documents.
        if let Some(name) = nrr_shared::preset_parser::parse_section_header(line) {
            match RulesFileSection::from_name(name) {
                Some(section) => {
                    // Merge into existing slot for this section (handles duplicate headers).
                    let idx = known
                        .iter()
                        .position(|s| s.section == section)
                        .unwrap_or_else(|| {
                            known.push(SectionContent {
                                section,
                                entries: Vec::new(),
                            });
                            known.len() - 1
                        });
                    current = Some(Slot::Known(idx));
                }
                None => {
                    // Indexed, not scanned: the section name comes from the
                    // file, so a linear lookup per header is quadratic in a
                    // value the caller controls — and this parser is reachable
                    // over IPC with a 1 MiB payload (~116k headers, tens of
                    // seconds of CPU). The known-section lookup below stays a
                    // scan: its length is the enum's, not the file's.
                    let idx = *unknown_index.entry(name.to_string()).or_insert_with(|| {
                        unknown.push(UnknownSection {
                            name: name.to_string(),
                            entries: Vec::new(),
                        });
                        unknown.len() - 1
                    });
                    // Emit warning on first encounter only.
                    if unknown[idx].entries.is_empty() {
                        warnings.push(ParseWarning::UnknownSection {
                            name: name.to_string(),
                            entry_count: 0, // updated after parsing entries
                        });
                    }
                    current = Some(Slot::Unknown(idx));
                }
            }
            continue;
        }

        // Preamble lines (before any section header has been encountered).
        if current.is_none() {
            // Format version header — matched once, two accepted forms.
            if file_format_version.is_none() {
                if let Some(v) = parse_version_header(trimmed) {
                    file_format_version = Some(v);
                    if v > CURRENT_RULES_FILE_FORMAT_VERSION {
                        warnings.push(ParseWarning::UnknownFormatVersion {
                            found: v,
                            supported: CURRENT_RULES_FILE_FORMAT_VERSION,
                        });
                    }
                    continue;
                }
                if let Some(v) = parse_preset_header(trimmed) {
                    file_format_version = Some(v);
                    is_preset_file = true;
                    if v > CURRENT_RULES_FILE_FORMAT_VERSION {
                        warnings.push(ParseWarning::UnknownFormatVersion {
                            found: v,
                            supported: CURRENT_RULES_FILE_FORMAT_VERSION,
                        });
                    }
                    continue;
                }
            }
            // Metadata key-value comment (# key: value).
            if let Some((key, value)) = parse_metadata_kv(trimmed) {
                let meta = preset_meta.get_or_insert_with(PresetMetadata::default);
                match key {
                    "name" => meta.name = Some(value.to_string()),
                    "description" => meta.description = Some(value.to_string()),
                    "author" => meta.author = Some(value.to_string()),
                    "preset_version" => meta.preset_version = Some(value.to_string()),
                    _ => {}
                }
            }
            // Remaining preamble lines (free comments) are ignored.
            continue;
        }

        // Rule entry (current section is active).
        let slot = match &current {
            Some(s) => s,
            None => continue,
        };
        let verify_values =
            matches!(slot, Slot::Known(idx) if known[*idx].section.takes_verify_prefix());

        let (mut entry, markers) = if let Some(rest) = trimmed.strip_prefix('#') {
            // Possibly a disabled rule — `nrr_shared` owns the one predicate
            // that tells a disabled rule from a prose comment.
            let rest = rest.trim_start();
            if rest.is_empty() || rest.starts_with('#') {
                // Pure comment line — ignore.
                continue;
            }
            let (value, comment) = split_inline_comment(rest);
            let value = extract_rule_flags(value.trim());
            let (value, markers) = take_rule_markers(&value, verify_values);
            // By the section, not by whether this host applies it: a disabled
            // spaced path in another OS's section is still a rule to keep.
            let rule_type = match &current {
                Some(Slot::Known(idx)) => Some(known[*idx].section.rule_type()),
                _ => None,
            };
            let is_rule = match rule_type {
                Some(kind) => nrr_shared::preset_parser::is_disabled_rule_value(kind, &value),
                None => !value.contains(char::is_whitespace),
            };
            if value.is_empty() || !is_rule {
                // Prose comment like "# this is a note about example.com" — ignore.
                continue;
            }
            (
                RulesFileEntry {
                    match_value: value,
                    inline_comment: comment,
                    enabled: false,
                    blocked: markers.deny,
                    verify_primary: markers.verify,
                    origin: None,
                },
                markers,
            )
        } else {
            let (value, comment) = split_inline_comment(trimmed);
            let value = extract_rule_flags(value.trim());
            if value.is_empty() {
                continue;
            }
            let (value, markers) = take_rule_markers(&value, verify_values);
            if value.is_empty() {
                continue;
            }
            (
                RulesFileEntry {
                    match_value: value,
                    inline_comment: comment,
                    enabled: true,
                    blocked: markers.deny,
                    verify_primary: markers.verify,
                    origin: None,
                },
                markers,
            )
        };

        // "Check where it works" and "drop it" contradict each other: the
        // line keeps both marks in its value, which validation refuses.
        if markers.contradictory {
            warnings.push(ParseWarning::VerifyPrimaryWithBlock {
                match_value: entry.match_value.clone(),
            });
        }

        match slot {
            Slot::Known(idx) => {
                // Never in the user's own address sections, so a comment there
                // starting with `auto:` is never swallowed. An application line
                // without the tokens is simply the user's.
                let section = known[*idx].section;
                if section.is_app_authored() {
                    take_provenance(&mut entry, &mut warnings);
                } else if section.carries_provenance() {
                    take_provenance_if_any(&mut entry);
                }
                known[*idx].entries.push(entry)
            }
            Slot::Unknown(idx) => unknown[*idx].entries.push(entry),
        }
    }

    // Update entry_count in UnknownSection warnings now that parsing is done —
    // through the same index, so this pass is linear too.
    for w in &mut warnings {
        if let ParseWarning::UnknownSection { name, entry_count } = w {
            if let Some(idx) = unknown_index.get(name) {
                *entry_count = unknown[*idx].entries.len();
            }
        }
    }

    let preset_metadata = if is_preset_file {
        Some(preset_meta.unwrap_or_default())
    } else {
        preset_meta
    };

    ParseOutcome {
        parsed: RulesFileParsed { sections: known },
        unknown_sections: unknown,
        warnings,
        file_format_version,
        preset_metadata,
    }
}

/// Moves the structured provenance prefix of an `--- Auto` entry's inline
/// comment into `entry.origin`, leaving only the free-text note behind.
///
/// A line whose comment carries no recognisable `auto:` token keeps that
/// comment verbatim and stays an ordinary rule of the file's route — a
/// hand-edited file must never lose a rule — and the condition is reported as
/// a warning instead of an error.
fn take_provenance(entry: &mut RulesFileEntry, warnings: &mut Vec<ParseWarning>) {
    let parsed = entry
        .inline_comment
        .as_deref()
        .and_then(parse_provenance_comment);
    match parsed {
        Some(provenance) => {
            if !provenance.complete {
                warnings.push(ParseWarning::AutoRuleIncompleteProvenance {
                    match_value: entry.match_value.clone(),
                    reason_slug: provenance.origin.reason().as_slug().to_string(),
                });
            }
            entry.inline_comment = provenance.note;
            entry.origin = Some(provenance.origin);
        }
        None => warnings.push(ParseWarning::AutoRuleMissingProvenance {
            match_value: entry.match_value.clone(),
        }),
    }
}

/// [`take_provenance`] for a section where a line without the tokens is
/// ordinary: nothing to report.
fn take_provenance_if_any(entry: &mut RulesFileEntry) {
    if let Some(provenance) = entry
        .inline_comment
        .as_deref()
        .and_then(parse_provenance_comment)
    {
        entry.inline_comment = provenance.note;
        entry.origin = Some(provenance.origin);
    }
}

/// Splits a rule line at the first `#`, returning `(value, inline_comment)`.
///
/// Both parts are trimmed. `inline_comment` is `None` when there is no `#`.
fn split_inline_comment(s: &str) -> (String, Option<String>) {
    match s.find('#') {
        None => (s.to_string(), None),
        Some(pos) => {
            let value = s[..pos].trim().to_string();
            let comment = s[pos + 1..].trim().to_string();
            let comment = if comment.is_empty() {
                None
            } else {
                Some(comment)
            };
            (value, comment)
        }
    }
}

/// The value with its words rejoined and `+children` taken off, by the one
/// reading the GUI's parser shares. Nothing acts on the flag yet, but left in,
/// `codex.exe +children` normalised to the pattern `codex.exe +children.exe`
/// and covered no process at all.
pub(crate) fn extract_rule_flags(value: &str) -> String {
    nrr_shared::preset_parser::split_children_flag(value).0
}

/// Lifts the `!` prefix off `value` in any section, and the `?` prefix in a
/// host-name or exact-IP one; a mark anywhere else stays part of the value,
/// which validation then refuses. One reading with the GUI parser.
fn take_rule_markers(
    value: &str,
    verify_values: bool,
) -> (String, nrr_shared::preset_parser::RuleMarkers) {
    let (rest, markers) = nrr_shared::preset_parser::split_rule_markers(value, verify_values);
    (rest.to_string(), markers)
}

// ── File-to-RuleSet conversion ────────────────────────────────────────────────
