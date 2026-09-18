// Walking the file: section headers and what each section means.

use super::*;

/// Parse a canonical txt preset body.
///
/// The function is total — never panics, never returns an error —
/// because every line either maps to a rule, a passthrough block, a
/// duplicate-section note, or is silently dropped. Surfaceable issues
/// (validation errors, semantic conflicts) live downstream of this
/// parser; the goal here is to faithfully decompose the file into the
/// structural categories above.
///
/// Line endings are accepted in any combination of `\r\n` and `\n`.
/// Trailing carriage returns inside lines are stripped before parsing.
pub fn parse_canonical_rules(text: &str) -> PresetParseResult {
    let mut state = ParserState::new();
    // A file saved by a Windows editor starts with a BOM, and the service side
    // strips it before parsing. Without the same strip here the first line —
    // usually `--- Domains` — was not recognised as a header, so the GUI showed
    // as prose exactly the rules the service imported.
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    for (idx, raw_line) in text.split('\n').enumerate() {
        let line_number = idx + 1;
        // Strip the trailing \r on CRLF lines without allocating
        // when the input is already LF-only.
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if let Some(section_name) = parse_section_header(line) {
            state.start_section(section_name);
            continue;
        }
        state.consume_line(line, line_number);
    }
    state.finish()
}

/// Detect `--- SectionName` headers per docs/en/rules-file-format.md Syntax. Returns the
/// section name trimmed of surrounding whitespace. Returns `None` for
/// any line that doesn't start with exactly `--- ` (three hyphens,
/// one space).
pub fn parse_section_header(line: &str) -> Option<&str> {
    let stripped = line.strip_prefix("--- ")?;
    // docs/en/rules-file-format.md Syntax: "exactly three hyphens, one space, then the
    // section name". Extra whitespace between the mandatory space and
    // the section name is invalid input — treat as a non-header so the
    // line falls through to the current section's content.
    if stripped.starts_with(char::is_whitespace) {
        return None;
    }
    // Trailing whitespace is explicitly allowed by the spec.
    let name = stripped.trim_end();
    if name.is_empty() {
        return None;
    }
    Some(name)
}

/// Map a section name (case-sensitive) to the rule type the GUI
/// represents in `rulesModel`. Returns `None` for sections that go
/// into passthrough (foreign-OS sections on Windows hosts, extended sections,
/// custom user-named sections).
///
/// We deliberately match by exact case rather than lowercasing — the
/// canonical format declares section names case-sensitive in §1.2, and
/// matching case-insensitively would silently accept malformed input
/// like `--- domains`. The QML reciprocal `_sectionToRuleTypeSlug` did
/// lowercase, which we keep as a backwards-compat helper below.
pub fn classify_section(name: &str) -> Option<ParsedRuleType> {
    match name {
        "Zones" => Some(ParsedRuleType::Zone),
        "Domains" => Some(ParsedRuleType::Domain),
        "IP" => Some(ParsedRuleType::ExactIp),
        "Windows" => Some(ParsedRuleType::Application),
        // App-authored rules share the domain value grammar; authorship is
        // carried by `ParsedRule::origin`, not by the rule type. Classifying
        // them as rules (rather than letting them fall to passthrough) is what
        // keeps the GUI parser in lockstep with `nrr_domain::rules_file` —
        // otherwise a file would import as rules server-side and as opaque
        // text in the GUI.
        crate::auto_rule::AUTO_SECTION_NAME => Some(ParsedRuleType::Domain),
        _ => None,
    }
}

/// Permissive variant of [`classify_section`] with case-insensitive
/// matching. Useful for preset files that may have been hand-edited with
/// non-canonical case (`--- zones`, `--- DOMAINS`). The parser uses this
/// internally so existing user files keep importing the same way; new
/// exports always emit canonical case.
pub fn classify_section_lenient(name: &str) -> Option<ParsedRuleType> {
    let lowered = name.to_ascii_lowercase();
    match lowered.as_str() {
        "zones" => Some(ParsedRuleType::Zone),
        "domains" => Some(ParsedRuleType::Domain),
        "ip" => Some(ParsedRuleType::ExactIp),
        "auto" => Some(ParsedRuleType::Domain),
        // The application section of the OS we are RUNNING ON is a rule
        // section; the others are passthrough. `nrr_domain::rules_file` already
        // decides it this way (`is_active_on`), and disagreeing meant a Linux
        // host enforced `--- Linux` while the GUI displayed it as inert text.
        "windows" if cfg!(target_os = "windows") => Some(ParsedRuleType::Application),
        "linux" if cfg!(target_os = "linux") => Some(ParsedRuleType::Application),
        "macos" if cfg!(target_os = "macos") => Some(ParsedRuleType::Application),
        _ => None,
    }
}

/// `true` when a section name denotes the app-authored section, whose entries
/// carry a structured provenance comment. Case-insensitive, matching
/// [`classify_section_lenient`].
pub(super) fn is_auto_section(name: &str) -> bool {
    name.eq_ignore_ascii_case(crate::auto_rule::AUTO_SECTION_NAME)
}

/// Test helper hook for the lenient classifier — exposed only when the
/// crate is built with `cfg(test)` so consumers don't grow a dependency
/// on the case-insensitive matching.
#[cfg(test)]
pub(super) fn classify_section_lenient_pub(name: &str) -> Option<ParsedRuleType> {
    classify_section_lenient(name)
}

// ── Internal parser state machine ─────────────────────────────────────
