// One rule line: what it means, and the flags it carries.

use super::*;

/// Parse one rule line. Returns `None` when the line is blank, a free
/// comment, or otherwise rejected by the docs/en/rules-file-format.md rules. Mirrors the
/// QML implementation exactly so that the parser change is invisible
/// at the rule level (passthrough is the only new behaviour).
/// Is a `#`-prefixed line inside a rule section a DISABLED RULE, or prose?
///
/// A value without whitespace is always a rule value. Whitespace is the whole
/// ambiguity: `# this is a note about example.com` is prose, while
/// `# Adobe Reader.exe` is a real rule — program names carry spaces. Calling
/// the second one prose loses the rule outright, because the GUI rewrites the
/// file from its parsed model, so a space is allowed where a program name is
/// expected and still looks like a file name.
///
/// One predicate for both parsers of this format, so the two cannot disagree
/// about which lines survive a round-trip.
pub fn is_disabled_rule_value(rule_type: ParsedRuleType, value: &str) -> bool {
    if looks_like_a_rule_value(value) {
        return true;
    }
    rule_type == ParsedRuleType::Application && has_file_extension(value)
}

/// The half of [`is_disabled_rule_value`] that needs no rule type: a value with
/// no whitespace in it is a rule value, whatever section it came from.
///
/// Split out for the sections whose type we do not know — a passthrough block
/// has no rule type by definition, and its commented-out lines still have to be
/// told apart from prose.
#[must_use]
pub fn looks_like_a_rule_value(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty() && !value.contains(char::is_whitespace)
}

pub(super) fn has_file_extension(value: &str) -> bool {
    value.rsplit_once('.').is_some_and(|(stem, ext)| {
        !stem.trim().is_empty()
            && (1..=8).contains(&ext.chars().count())
            && ext.chars().all(|c| c.is_ascii_alphanumeric())
    })
}

pub(super) fn parse_rule_line(
    raw: &str,
    rule_type: ParsedRuleType,
    section_name: &str,
    id_hint: u32,
    line_number: usize,
) -> Option<ParsedRule> {
    // Both ends. Trailing-only was the QML behaviour, and it disagreed with the
    // service parser on `  # example.com`: there a disabled rule with an indent
    // is preserved as a disabled rule, here the leading spaces kept the line
    // from being recognised as one at all — the GUI dropped a rule the service
    // was keeping.
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    // "## something" is always a free comment (file-level documentation).
    if raw.starts_with("##") {
        return None;
    }

    // Detect disabled-rule prefix vs free comment.
    let (body, started_with_hash) = if let Some(rest) = raw.strip_prefix("# ") {
        (rest, true)
    } else if let Some(rest) = raw.strip_prefix('#') {
        // "#value" or "#" — empty hash is dropped.
        if rest.is_empty() {
            return None;
        }
        (rest, true)
    } else {
        (raw, false)
    };

    // Split inline comment at the first `#` past the value body.
    let (match_value, comment) = match body.find('#') {
        Some(hash_idx) => {
            let (val, rest) = body.split_at(hash_idx);
            (val, &rest[1..])
        }
        None => (body, ""),
    };

    let match_value = match_value.trim();
    let comment = comment.trim();

    // Strip the `+block` flag (docs/en/rules-file-format.md Blocking destinations) BEFORE the single-token
    // check below, so a disabled blocked rule (`# ads.example.com +block`) is
    // not misread as multi-word free text. Kept in lockstep with the domain
    // parser in `nrr_domain::rules_file::extract_rule_flags`.
    let (match_value, blocked) = extract_block_flag(match_value);

    if match_value.is_empty() {
        return None;
    }

    let enabled = if started_with_hash {
        if !is_disabled_rule_value(rule_type, &match_value) {
            return None; // prose comment
        }
        false
    } else {
        true
    };

    // In the app-authored section the leading `auto:` / `anchor:` / `added:`
    // tokens are provenance, not label text — lift them into typed fields so
    // the GUI shows the note, not the machinery. A line without the tokens
    // keeps its comment verbatim and stays an ordinary rule (the domain parser
    // additionally raises a warning; this one has no warning channel).
    let (comment, origin) = if is_auto_section(section_name) {
        match crate::auto_rule::parse_provenance_comment(comment) {
            Some(provenance) => (provenance.note.unwrap_or_default(), Some(provenance.origin)),
            None => (comment.to_string(), None),
        }
    } else {
        (comment.to_string(), None)
    };

    Some(ParsedRule {
        id_hint,
        enabled,
        rule_type,
        section_name: section_name.to_string(),
        match_value,
        comment,
        blocked,
        origin,
        line_number,
    })
}

/// Per-rule `+block` flag token (docs/en/rules-file-format.md Blocking destinations). Placed after the match
/// value and before any inline `#`; mirrors the `+children` convention.
pub(super) const BLOCK_FLAG: &str = "+block";

/// Splits a match value into its head (the actual match value) and the parsed
/// `+block` flag. The first whitespace-separated token is always the match
/// value; a subsequent `+block` token is consumed and reported as
/// `blocked = true`. Non-flag trailing tokens are preserved so the caller can
/// still diagnose accidental whitespace. Mirrors
/// `nrr_domain::rules_file::extract_rule_flags` exactly (strict-vs-lenient
/// lockstep: both parsers must agree, or the GUI would block while the service
/// routes).
pub(super) fn extract_block_flag(value: &str) -> (String, bool) {
    let mut blocked = false;
    let mut kept: Vec<&str> = Vec::new();
    for (idx, token) in value.split_whitespace().enumerate() {
        if idx > 0 && token == BLOCK_FLAG {
            blocked = true;
        } else {
            kept.push(token);
        }
    }
    (kept.join(" "), blocked)
}

/// Count the non-blank lines of `body` — everything carried — and return the
/// first [`PASSTHROUGH_PREVIEW_LINES`] non-comment lines as the preview.
///
/// The count and the preview answer different questions on purpose. The count
/// says how much is being preserved, so it includes commented lines: a section
/// of nothing but disabled rules (`# example.com`) is not empty, and saying "0
/// lines" about text on its way to the sidecar was the defect. The preview is a
/// sample of the section's substance, so it still leads with the lines that
/// carry a value.
pub(super) fn summarize_passthrough(body: &str) -> (usize, Vec<String>) {
    let mut content_lines = 0usize;
    let mut preview = Vec::new();
    for raw in body.split('\n') {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        content_lines += 1;
        if !line.starts_with('#') && preview.len() < PASSTHROUGH_PREVIEW_LINES {
            preview.push(line.to_string());
        }
    }
    (content_lines, preview)
}

/// Ensure passthrough body has exactly one trailing newline when
/// non-empty, and no trailing newline when empty. Stable for diff
/// tests: a section with no content emits `--- Name\n` only, and a
/// section with content emits `--- Name\n<content>\n`.
pub(super) fn normalise_trailing_newline(mut s: String) -> String {
    while s.ends_with('\n') {
        s.pop();
    }
    if !s.is_empty() {
        s.push('\n');
    }
    s
}

// ── Tests ─────────────────────────────────────────────────────────────
