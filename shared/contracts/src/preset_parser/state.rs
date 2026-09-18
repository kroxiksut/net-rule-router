// Parser state while walking a preset body.

use super::*;

pub(super) struct ParserState {
    rules: Vec<ParsedRule>,
    passthrough: Vec<PassthroughBlock>,
    /// Map of section name → encounter count, used to compute the
    /// `duplicate_sections` field at the end. The order of insertion
    /// is preserved by walking `section_order` so the duplicate list
    /// matches file order (important for deterministic UI rendering).
    section_counts: std::collections::HashMap<String, u32>,
    /// Encounter order as `(case-insensitive key, name as first written)`.
    /// The key groups `--- Domains` with `--- domains`; the name is what the
    /// user sees reported back.
    section_order: Vec<(String, String)>,
    /// Monotonic id assigned to the next rule we emit.
    next_id_hint: u32,
    /// Current section, if any. `None` means we're in the file-level
    /// prelude before the first `--- ` header.
    current: CurrentSection,
}

/// What kind of section is currently being parsed.
pub(super) enum CurrentSection {
    None,
    Known {
        rule_type: ParsedRuleType,
        section_name: String,
    },
    Unknown {
        section_name: String,
        accumulated: String,
    },
}

impl ParserState {
    pub(super) fn new() -> Self {
        Self {
            rules: Vec::new(),
            passthrough: Vec::new(),
            section_counts: std::collections::HashMap::new(),
            section_order: Vec::new(),
            next_id_hint: 1,
            current: CurrentSection::None,
        }
    }

    pub(super) fn start_section(&mut self, section_name: &str) {
        // Close the previous section (flushes any pending passthrough).
        self.close_current();

        // Keyed case-INSENSITIVELY, matching `classify_section_lenient`: with a
        // raw-name key `--- Domains` and `--- domains` counted as two different
        // sections, so the merge-policy dialog never came up for a file that has
        // the same section twice in different case.
        let key = section_name.to_ascii_lowercase();
        let count = self.section_counts.entry(key.clone()).or_insert(0);
        if *count == 0 {
            self.section_order.push((key, section_name.to_string()));
        }
        *count += 1;

        // The NAME carried forward is the one the file used — it is what the
        // GUI shows and what a passthrough block writes back out. Only the
        // duplicate bookkeeping above is case-insensitive.
        self.current = match classify_section_lenient(section_name) {
            Some(rule_type) => CurrentSection::Known {
                rule_type,
                section_name: section_name.to_string(),
            },
            None => CurrentSection::Unknown {
                section_name: section_name.to_string(),
                accumulated: String::new(),
            },
        };
    }

    pub(super) fn consume_line(&mut self, line: &str, line_number: usize) {
        match &mut self.current {
            CurrentSection::None => {
                // File-level prelude before any section header — drop.
            }
            CurrentSection::Known {
                rule_type,
                section_name,
            } => {
                if let Some(rule) = parse_rule_line(
                    line,
                    *rule_type,
                    section_name,
                    self.next_id_hint,
                    line_number,
                ) {
                    self.rules.push(rule);
                    self.next_id_hint += 1;
                }
            }
            CurrentSection::Unknown { accumulated, .. } => {
                accumulated.push_str(line);
                accumulated.push('\n');
            }
        }
    }

    pub(super) fn close_current(&mut self) {
        let taken = std::mem::replace(&mut self.current, CurrentSection::None);
        if let CurrentSection::Unknown {
            section_name,
            accumulated,
        } = taken
        {
            let (content_lines, preview) = summarize_passthrough(&accumulated);
            let raw_text = normalise_trailing_newline(accumulated);
            self.passthrough.push(PassthroughBlock {
                section_name,
                raw_text,
                content_lines,
                preview,
            });
        }
    }

    pub(super) fn finish(mut self) -> PresetParseResult {
        // Flush any in-flight passthrough.
        self.close_current();

        // Compute duplicate-sections in file-encounter order.
        let mut duplicate_sections = Vec::new();
        for (key, display_name) in self.section_order {
            if let Some(&count) = self.section_counts.get(&key) {
                if count >= 2 {
                    let is_known = classify_section_lenient(&key).is_some();
                    duplicate_sections.push(DuplicateGroup {
                        section_name: display_name,
                        occurrences: count,
                        is_known_section: is_known,
                    });
                }
            }
        }

        PresetParseResult {
            rules: self.rules,
            passthrough: self.passthrough,
            duplicate_sections,
        }
    }
}
