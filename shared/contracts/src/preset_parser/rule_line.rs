// One rule line: what it means, and the flags it carries.

use super::*;

/// Is a `#`-prefixed line inside a rule section a DISABLED RULE, or prose?
///
/// Prose is ruled out first: a value with whitespace is a comment, with one
/// exception — `# Adobe Reader.exe` is a real rule, because program names carry
/// spaces, and calling it prose loses the rule outright when the GUI rewrites
/// the file from its parsed model. The exception is a program IMAGE name, not
/// any file name: `# see readme.txt` or `# note v1.2` reads as a file name too,
/// and taking it for a rule writes the note back out as a rule line. A path
/// rule is the other application exception (see `names_a_place`).
///
/// The network forms are the other exception: an enabled line may space out
/// `10.0.0.5 - 10.0.0.40` or `10.0.0.0 / 8`, and unticking it must not turn
/// the rule into prose.
///
/// One predicate for both parsers of this format, so the two cannot disagree
/// about which lines survive a round-trip.
pub fn is_disabled_rule_value(rule_type: ParsedRuleType, value: &str) -> bool {
    // A deny in the retired spelling stays a rule, so validation can say how
    // it is written now instead of the line vanishing as prose.
    let head;
    let value = if carries_retired_block_flag(value) {
        head = without_retired_block_flag(value);
        head.as_str()
    } else {
        value
    };
    if looks_like_a_rule_value(value) {
        return true;
    }
    let value = value.trim();
    match rule_type {
        ParsedRuleType::Application => names_a_program_image(value) || names_a_place(value),
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

/// A spaced path rule: one starting at a drive or a share (a note seldom
/// does), or at `/` and ending as a folder does (`/`, `/*`). Folder names
/// carry spaces (`Program Files`), and calling such a line prose loses the
/// rule when the file is written back.
fn names_a_place(value: &str) -> bool {
    let bytes = value.as_bytes();
    let drive = matches!(bytes, [letter, b':', b'\\' | b'/', ..] if letter.is_ascii_alphabetic());
    let share = value.starts_with("\\\\");
    let unix_folder = value.starts_with('/') && (value.ends_with('/') || value.ends_with("/*"));
    drive || share || unix_folder
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

    // Words rejoined and the flag taken off before the disabled-rule check,
    // which would read `exe +children` as a file extension and drop the rule.
    let (match_value, children) = split_children_flag(match_value);
    let comment = comment.trim();

    // `?` is read where values are host names or single addresses; elsewhere
    // it stays part of the value for validation to judge. Same reading as
    // `nrr_domain::rules_file`.
    let reads_verify = matches!(rule_type, ParsedRuleType::Domain | ParsedRuleType::ExactIp);
    let (match_value, markers) = split_rule_markers(&match_value, reads_verify);
    let match_value = match_value.to_string();

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

    // In the app-authored section, and on a program line (an app-authored
    // program rule keeps its section), the leading `auto:` / `anchor:` /
    // `added:` tokens are provenance, not label text. A line without them
    // keeps its comment verbatim and stays an ordinary rule.
    let (comment, origin) =
        if is_auto_section(section_name) || rule_type == ParsedRuleType::Application {
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
        blocked: markers.deny,
        verify_primary: markers.verify,
        children,
        origin,
        line_number,
    })
}

/// Per-rule child-process flag (docs/en/rules-file-format.md Child process
/// tracking): a word after the value, before any inline `#`. Both parsers take
/// it off in every section through [`split_children_flag`]; nothing acts on it
/// yet, the matcher has no process tree to follow.
pub const CHILDREN_FLAG: &str = "+children";

/// `value` with its words rejoined by one space and every [`CHILDREN_FLAG`]
/// after the first word taken off, and whether there was one. Any other later
/// word, the retired `+block` among them, stays for validation to judge.
#[must_use]
pub fn split_children_flag(value: &str) -> (String, bool) {
    let mut out = String::with_capacity(value.len());
    let mut children = false;
    for (idx, token) in value.split_whitespace().enumerate() {
        if idx > 0 && token == CHILDREN_FLAG {
            children = true;
            continue;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(token);
    }
    (out, children)
}

/// The value a rules table keeps for a parsed rule: `value`, with ` +children`
/// after a program's name when its line carried the flag, so a file written
/// back from the table keeps it. Elsewhere the flag means nothing and is gone,
/// as the service reads it.
#[must_use]
pub fn stored_rule_value(rule_type: ParsedRuleType, value: &str, children: bool) -> String {
    if children && rule_type == ParsedRuleType::Application {
        format!("{value} {CHILDREN_FLAG}")
    } else {
        value.to_owned()
    }
}

/// A table's value without the flag [`stored_rule_value`] keeps on it: what
/// the service matches, as the file reader hands it over.
#[must_use]
pub fn without_children_flag(value: &str) -> std::borrow::Cow<'_, str> {
    let (bare, children) = split_children_flag(value);
    if children {
        std::borrow::Cow::Owned(bare)
    } else {
        std::borrow::Cow::Borrowed(value)
    }
}

/// Starts every line of the syntax hint a writer puts at the top of a file.
/// Never localized. Both parsers skip such a line wherever it stands, so an
/// example in the hint is never a rule and the next write never doubles it.
/// After `#` comes `:`, which no rule value starts with.
pub const SYNTAX_HINT_PREFIX: &str = "#:";

/// Whether `line` belongs to the syntax hint ([`SYNTAX_HINT_PREFIX`]).
#[must_use]
pub fn is_syntax_hint_line(line: &str) -> bool {
    line.trim_start().starts_with(SYNTAX_HINT_PREFIX)
}

/// Prefix that denies a rule's traffic (docs/en/rules-file-format.md Blocking
/// destinations), in any section of either file. It sits right before the
/// value, after a `# ` disable prefix: `# !example.com`.
pub const DENY_PREFIX: char = '!';

/// Splits the `!` prefix off a value: `!example.com` reads as
/// `("example.com", true)`. A bare `!` or `! example.com` is not the prefix and
/// stays in the value, for validation to refuse.
#[must_use]
pub fn split_deny(value: &str) -> (&str, bool) {
    match value.strip_prefix(DENY_PREFIX) {
        Some(rest) if rest.starts_with(|c: char| !c.is_whitespace()) => (rest, true),
        _ => (value, false),
    }
}

/// The marks read before a rule value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RuleMarkers {
    /// `!`: the matching traffic is dropped.
    pub deny: bool,
    /// `?`: check where it works.
    pub verify: bool,
    /// Both were written (`!?x`, `?!x`). A check never applies to a deny, so
    /// neither is taken and the value keeps both for validation to refuse.
    pub contradictory: bool,
}

/// The `!` and `?` marks of `value`, read the one way both parsers share;
/// `reads_verify` is set where `?` means "check where it works".
#[must_use]
pub fn split_rule_markers(value: &str, reads_verify: bool) -> (&str, RuleMarkers) {
    let (rest, deny) = split_deny(value);
    let (rest, verify) = if reads_verify {
        split_verify_primary(rest)
    } else {
        (rest, false)
    };
    if verify && (deny || rest.starts_with(DENY_PREFIX)) {
        let markers = RuleMarkers {
            contradictory: true,
            ..RuleMarkers::default()
        };
        return (value, markers);
    }
    let markers = RuleMarkers {
        deny,
        verify,
        contradictory: false,
    };
    (rest, markers)
}

/// The suffix a deny was written with before the `!` prefix. It is never read
/// as a deny, nor dropped: an unknown token silently skipped would turn the
/// deny into a route, so it stays in the value and validation refuses the line
/// with a hint at the new spelling.
pub const RETIRED_BLOCK_FLAG: &str = "+block";

/// Whether `value` carries [`RETIRED_BLOCK_FLAG`] after its first word.
#[must_use]
pub fn carries_retired_block_flag(value: &str) -> bool {
    value
        .split_whitespace()
        .skip(1)
        .any(|token| token == RETIRED_BLOCK_FLAG)
}

/// `value` without its [`RETIRED_BLOCK_FLAG`] tokens, words rejoined by one
/// space.
#[must_use]
pub fn without_retired_block_flag(value: &str) -> String {
    value
        .split_whitespace()
        .enumerate()
        .filter(|(idx, token)| *idx == 0 || *token != RETIRED_BLOCK_FLAG)
        .map(|(_, token)| token)
        .collect::<Vec<_>>()
        .join(" ")
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
