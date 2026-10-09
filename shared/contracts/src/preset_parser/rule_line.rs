// One rule line: what it means, and the flags it carries.

use super::*;

/// Is a `#`-prefixed line inside a rule section a DISABLED RULE, or prose?
///
/// Prose is ruled out first: a value with whitespace is a comment, with one
/// exception — `# Adobe Reader.exe` is a real rule, because program names carry
/// spaces, and calling it prose loses the rule outright when the GUI rewrites
/// the file from its parsed model. The exception is a program IMAGE name, not
/// any file name: `# see readme.txt` or `# note v1.2` reads as a file name too,
/// and taking it for a rule writes the note back out as a rule line.
///
/// The network forms are the other exception: an enabled line may space out
/// `10.0.0.5 - 10.0.0.40` or `10.0.0.0 / 8`, and unticking it must not turn
/// the rule into prose.
///
/// One predicate for both parsers of this format, so the two cannot disagree
/// about which lines survive a round-trip.
pub fn is_disabled_rule_value(rule_type: ParsedRuleType, value: &str) -> bool {
    if looks_like_a_rule_value(value) {
        return true;
    }
    let value = value.trim();
    match rule_type {
        ParsedRuleType::Application => names_a_program_image(value),
        ParsedRuleType::Subnet => crate::ip_block::IpBlock::parse(value).is_some(),
        // Both bounds addresses, any family: the validator settles the rest,
        // as it does for the enabled line.
        ParsedRuleType::IpRange => value.split_once('-').is_some_and(|(first, last)| {
            first.trim().parse::<std::net::IpAddr>().is_ok()
                && last.trim().parse::<std::net::IpAddr>().is_ok()
        }),
        ParsedRuleType::Zone | ParsedRuleType::Domain | ParsedRuleType::ExactIp => false,
    }
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

/// A character one field of this line-oriented format cannot carry: a line
/// break ends the field, and whatever follows is read as a rule or a section of
/// its own. The other controls are invisible in an editor and mean nothing in a
/// host, a program name or a note. Tab is ordinary whitespace here.
#[must_use]
pub fn is_forbidden_field_char(c: char) -> bool {
    c.is_control() && c != '\t'
}

/// The first character of `field` the format cannot carry, if any.
#[must_use]
pub fn first_forbidden_field_char(field: &str) -> Option<char> {
    field.chars().find(|&c| is_forbidden_field_char(c))
}

/// `field` with every character it cannot carry replaced by a space — for a
/// writer, so a value that bypassed validation still cannot start a line.
#[must_use]
pub fn neutralize_field(field: &str) -> std::borrow::Cow<'_, str> {
    if first_forbidden_field_char(field).is_none() {
        return std::borrow::Cow::Borrowed(field);
    }
    std::borrow::Cow::Owned(
        field
            .chars()
            .map(|c| if is_forbidden_field_char(c) { ' ' } else { c })
            .collect(),
    )
}

/// Extensions a running program's image carries, lowercase. What an
/// application rule matches is a process, so a spaced value ending in anything
/// else — a document, a version number — is a note about one.
const PROGRAM_IMAGE_EXTENSIONS: &[&str] = &["exe", "com", "app", "appimage"];

fn names_a_program_image(value: &str) -> bool {
    value.rsplit_once('.').is_some_and(|(stem, ext)| {
        !stem.trim().is_empty()
            && PROGRAM_IMAGE_EXTENSIONS
                .iter()
                .any(|known| ext.eq_ignore_ascii_case(known))
    })
}

/// Parse one rule line. Returns `None` when the line is blank, a free
/// comment, or otherwise rejected by the docs/en/rules-file-format.md rules.
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
    // `?` is read where values are host names or single addresses; elsewhere
    // it stays part of the value for validation to judge. Same reading as
    // `nrr_domain::rules_file`.
    let reads_verify = matches!(rule_type, ParsedRuleType::Domain | ParsedRuleType::ExactIp);
    let (match_value, verify_primary) = if reads_verify {
        let (rest, verify) = split_verify_primary(&match_value);
        if verify {
            (rest.to_string(), true)
        } else {
            (match_value, false)
        }
    } else {
        (match_value, false)
    };

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

    // "Check where it works" and "drop it" contradict each other; the line is
    // refused rather than one of them guessed.
    if verify_primary && blocked {
        return None;
    }

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
        verify_primary,
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

/// Prefix that marks a domain or exact-IP rule "check where it works"
/// (docs/en/rules-file-format.md Check where it works). It sits right before
/// the value, after a `# ` disable prefix: `# ?example.com`.
pub const VERIFY_PRIMARY_PREFIX: char = '?';

/// Splits the `?` prefix off a value: `?example.com` reads as
/// `("example.com", true)`. A bare `?` or `? example.com` is not the prefix and
/// stays in the value, for validation to refuse. One reading for both parsers.
#[must_use]
pub fn split_verify_primary(value: &str) -> (&str, bool) {
    match value.strip_prefix(VERIFY_PRIMARY_PREFIX) {
        Some(rest) if rest.starts_with(|c: char| !c.is_whitespace()) => (rest, true),
        _ => (value, false),
    }
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
