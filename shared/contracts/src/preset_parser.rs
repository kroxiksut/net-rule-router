//! Canonical txt preset parser.
//!
//! Replaces the JavaScript `_parseCanonicalRulesText` that used to live in
//! `Main.qml`. The Rust implementation is the source of truth for the
//! canonical txt format (docs/en/rules-file-format.md Rules File Format) and is reachable from QML via the
//! `preset.parse` local RPC opcode, and directly from the service side
//! without going through the GUI process.
//!
//! ## Format summary (see docs/en/rules-file-format.md Rules File Format for the full spec)
//!
//! * Sections are introduced by lines starting with `--- ` (exactly
//!   three hyphens, one space, then the section name). The name is
//!   case-sensitive.
//! * Known section names: `Zones`, `Domains`, `IP`, `Windows`, `Auto`, plus
//!   foreign-OS `Linux` / `MacOS` (preserved as passthrough on Windows
//!   hosts — see [`is_known_section`]).
//! * `--- Auto` holds rules the application authored on the user's behalf.
//!   Values follow the `Domains` grammar; each line's provenance is lifted out
//!   of the inline comment into [`ParsedRule::origin`] (docs/en/rules-file-format.md App-authored rules).
//! * Inside a known section, each non-blank, non-comment line is an
//!   active rule. A line starting with `# ` (or `#`, no space) is a
//!   disabled rule when its body is a single token (matches the
//!   round-trip semantics in the QML parser).
//! * Multi-word `# free text` is a documentation comment — skipped
//!   and not round-tripped through `rules`.
//! * A `+block` flag token after the match value (before any inline `#`)
//!   marks the rule as a hard block: matching traffic is dropped and the
//!   containing file (primary/secondary) is irrelevant for enforcement.
//!   See docs/en/rules-file-format.md Blocking destinations. Mirrors the documented `+children` convention.
//! * The first unescaped `#` past the value content starts an inline
//!   comment that becomes the rule's `comment` field.
//! * Lines preceding any `--- ` header are file-level prelude and are
//!   silently dropped (header preservation is out of scope for v1).
//!
//! ## Output shape
//!
//! [`PresetParseResult`] separates three concerns the GUI / service
//! cares about distinctly:
//!
//! 1. **`rules`** — what the routing engine actually consumes.
//! 2. **`passthrough`** — raw text of unknown sections. The sidecar
//!    DB stores these so an Export-to-file round-trip is byte-identical
//!    even for sections this build doesn't understand.
//! 3. **`duplicate_sections`** — names of sections that appeared more
//!    than once. The UI uses this to prompt the user for a merge
//!    policy in [`PresetImportReviewDialog`].
//!
//! Caller assigns final rule ids (`R-NNNN`) — the parser only emits
//! 1-based `id_hint` values so the GUI can offset them against
//! existing rules (`nextFreeRuleId`).

use serde::{Deserialize, Serialize};

/// Maximum number of `preview` lines returned per [`PassthroughBlock`].
/// Five is enough for the user to recognise the content type in the
/// import-review dialog without flooding the modal.
pub const PASSTHROUGH_PREVIEW_LINES: usize = 5;

/// Outcome of [`parse_canonical_rules`].
///
/// Every field is independently usable by callers — for example, the
/// import-summary banner needs only `rules` and `passthrough`, while
/// the review dialog needs `duplicate_sections` and the preview info
/// inside each `PassthroughBlock`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PresetParseResult {
    /// Rules extracted from known sections, in file order. The
    /// caller is responsible for assigning final `R-NNNN` ids and
    /// pinning each rule to a route.
    pub rules: Vec<ParsedRule>,
    /// Raw text of unknown sections, in encounter order. When the
    /// same section name appears twice it generates two
    /// `PassthroughBlock` entries; consult `duplicate_sections` to
    /// detect this without scanning the vector.
    pub passthrough: Vec<PassthroughBlock>,
    /// Names of sections (known or unknown) that appeared more than
    /// once. Used by the UI to prompt for a merge/last-wins/ignore
    /// policy before committing the import. Empty when the file is
    /// well-formed.
    pub duplicate_sections: Vec<DuplicateGroup>,
}

/// One rule extracted from a known section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ParsedRule {
    /// 1-based monotonic counter the parser emits for each rule it
    /// produces. Callers can map it to `R-NNNN` via
    /// `format!("R-{:04}", id_hint)`.
    pub id_hint: u32,
    /// Whether the line carried a `#` disable prefix.
    pub enabled: bool,
    /// Coarse rule type (corresponds to the matched section).
    pub rule_type: ParsedRuleType,
    /// Original case-sensitive name of the section the rule came
    /// from. Useful when callers want to preserve the section
    /// header verbatim (e.g. a file with `--- Domains` vs
    /// `--- domains` — though we accept only the canonical case).
    pub section_name: String,
    /// Match value — trimmed, with the disable prefix and inline
    /// comment already stripped. The caller is responsible for any
    /// Punycode↔Unicode boundary conversion (see
    /// `Main.qml::_unicodeDecodeHost`).
    pub match_value: String,
    /// Inline comment text after the first `#` in the value line;
    /// trimmed; empty when no inline comment was present.
    pub comment: String,
    /// Whether the line carried the per-rule `+block` flag (docs/en/rules-file-format.md Blocking destinations):
    /// matching traffic is dropped (hard WFP block) and the containing file
    /// (primary/secondary) is irrelevant for enforcement. `#[serde(default)]`
    /// so the field is optional across the `preset.parse` RPC wire.
    #[serde(default)]
    pub blocked: bool,
    /// Provenance of an app-authored rule — `Some` only for entries in the
    /// `--- Auto` section (docs/en/rules-file-format.md App-authored rules). The structured tokens are
    /// removed from `comment`, which keeps only the free text that followed
    /// them. `None` for every user-authored rule, and then absent from the
    /// RPC payload entirely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<crate::auto_rule::RuleOrigin>,
    /// 1-based line number in the source file. Useful for diagnostics
    /// when the caller wants to surface "rule R-0042 came from
    /// line 123".
    pub line_number: usize,
}

/// Coarse rule type derived from the section header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ParsedRuleType {
    Zone,
    Domain,
    ExactIp,
    Application,
}

impl ParsedRuleType {
    /// Canonical slug used by the QML rulesModel / wire format.
    /// Mirrors `_sectionToRuleTypeSlug` in `Main.qml`.
    pub fn slug(self) -> &'static str {
        match self {
            ParsedRuleType::Zone => "zone",
            ParsedRuleType::Domain => "domain",
            ParsedRuleType::ExactIp => "exact-ip",
            ParsedRuleType::Application => "application",
        }
    }
}

/// One block of raw text from an unknown section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PassthroughBlock {
    /// Original case-sensitive section name (e.g. `"Linux"`,
    /// `"MacOS"`, `"Cidr"`).
    pub section_name: String,
    /// Verbatim content of the section, between its header and the
    /// next section header (or end of file). Newlines preserved.
    /// Trailing newline normalised — exactly one trailing `\n` when
    /// the content is non-empty, zero when empty.
    pub raw_text: String,
    /// Count of non-blank, non-comment lines in `raw_text`. Surfaced
    /// for the review dialog ("Linux (5 lines)") so the GUI doesn't
    /// have to re-parse the raw text.
    pub content_lines: usize,
    /// First [`PASSTHROUGH_PREVIEW_LINES`] non-blank, non-comment
    /// lines from `raw_text` for the review-dialog preview area.
    /// Always a subset of `raw_text`; never references it by index.
    pub preview: Vec<String>,
}

/// Diagnostic for a section name that appeared more than once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DuplicateGroup {
    /// Section name (original case).
    pub section_name: String,
    /// Number of times the section appeared in the file. Always ≥ 2.
    pub occurrences: u32,
    /// Whether this section name is one the parser knows how to
    /// classify into rules. Affects the UI prompt — duplicates inside
    /// `Domains` mean two batches of rules to merge; duplicates inside
    /// `Linux` mean two passthrough segments to reconcile.
    pub is_known_section: bool,
}

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
fn parse_section_header(line: &str) -> Option<&str> {
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
/// into passthrough (foreign-OS sections on Windows hosts, future Pro
/// sections, custom user-named sections).
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
fn classify_section_lenient(name: &str) -> Option<ParsedRuleType> {
    let lowered = name.to_ascii_lowercase();
    match lowered.as_str() {
        "zones" => Some(ParsedRuleType::Zone),
        "domains" => Some(ParsedRuleType::Domain),
        "ip" => Some(ParsedRuleType::ExactIp),
        "windows" => Some(ParsedRuleType::Application),
        "auto" => Some(ParsedRuleType::Domain),
        _ => None,
    }
}

/// `true` when a section name denotes the app-authored section, whose entries
/// carry a structured provenance comment. Case-insensitive, matching
/// [`classify_section_lenient`].
fn is_auto_section(name: &str) -> bool {
    name.eq_ignore_ascii_case(crate::auto_rule::AUTO_SECTION_NAME)
}

/// Test helper hook for the lenient classifier — exposed only when the
/// crate is built with `cfg(test)` so consumers don't grow a dependency
/// on the case-insensitive matching.
#[cfg(test)]
fn classify_section_lenient_pub(name: &str) -> Option<ParsedRuleType> {
    classify_section_lenient(name)
}

// ── Internal parser state machine ─────────────────────────────────────

struct ParserState {
    rules: Vec<ParsedRule>,
    passthrough: Vec<PassthroughBlock>,
    /// Map of section name → encounter count, used to compute the
    /// `duplicate_sections` field at the end. The order of insertion
    /// is preserved by walking `section_order` so the duplicate list
    /// matches file order (important for deterministic UI rendering).
    section_counts: std::collections::HashMap<String, u32>,
    section_order: Vec<String>,
    /// Monotonic id assigned to the next rule we emit.
    next_id_hint: u32,
    /// Current section, if any. `None` means we're in the file-level
    /// prelude before the first `--- ` header.
    current: CurrentSection,
}

/// What kind of section is currently being parsed.
enum CurrentSection {
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
    fn new() -> Self {
        Self {
            rules: Vec::new(),
            passthrough: Vec::new(),
            section_counts: std::collections::HashMap::new(),
            section_order: Vec::new(),
            next_id_hint: 1,
            current: CurrentSection::None,
        }
    }

    fn start_section(&mut self, section_name: &str) {
        // Close the previous section (flushes any pending passthrough).
        self.close_current();

        // Record the encounter so duplicate detection sees it.
        let key = section_name.to_string();
        let count = self.section_counts.entry(key.clone()).or_insert(0);
        if *count == 0 {
            self.section_order.push(key.clone());
        }
        *count += 1;

        self.current = match classify_section_lenient(section_name) {
            Some(rule_type) => CurrentSection::Known {
                rule_type,
                section_name: key,
            },
            None => CurrentSection::Unknown {
                section_name: key,
                accumulated: String::new(),
            },
        };
    }

    fn consume_line(&mut self, line: &str, line_number: usize) {
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

    fn close_current(&mut self) {
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

    fn finish(mut self) -> PresetParseResult {
        // Flush any in-flight passthrough.
        self.close_current();

        // Compute duplicate-sections in file-encounter order.
        let mut duplicate_sections = Vec::new();
        for name in self.section_order {
            if let Some(&count) = self.section_counts.get(&name) {
                if count >= 2 {
                    let is_known = classify_section_lenient(&name).is_some();
                    duplicate_sections.push(DuplicateGroup {
                        section_name: name,
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

/// Parse one rule line. Returns `None` when the line is blank, a free
/// comment, or otherwise rejected by the docs/en/rules-file-format.md rules. Mirrors the
/// QML implementation exactly so that the parser change is invisible
/// at the rule level (passthrough is the only new behaviour).
fn parse_rule_line(
    raw: &str,
    rule_type: ParsedRuleType,
    section_name: &str,
    id_hint: u32,
    line_number: usize,
) -> Option<ParsedRule> {
    // Strip trailing whitespace per QML behaviour.
    let raw = raw.trim_end();
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

    // A line that started with `#` is a disabled rule only when the
    // candidate value is a single token. Multi-word "# free text" is
    // a documentation comment.
    let enabled = if started_with_hash {
        if match_value.contains(char::is_whitespace) {
            return None;
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
const BLOCK_FLAG: &str = "+block";

/// Splits a match value into its head (the actual match value) and the parsed
/// `+block` flag. The first whitespace-separated token is always the match
/// value; a subsequent `+block` token is consumed and reported as
/// `blocked = true`. Non-flag trailing tokens are preserved so the caller can
/// still diagnose accidental whitespace. Mirrors
/// `nrr_domain::rules_file::extract_rule_flags` exactly (strict-vs-lenient
/// lockstep: both parsers must agree, or the GUI would block while the service
/// routes).
fn extract_block_flag(value: &str) -> (String, bool) {
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

/// Count non-blank, non-comment lines in `body` and return the first
/// [`PASSTHROUGH_PREVIEW_LINES`] of them. Used to populate the
/// review-dialog preview area without parsing the section through the
/// rule machinery (which we can't — by definition it's not a known
/// section).
fn summarize_passthrough(body: &str) -> (usize, Vec<String>) {
    let mut content_lines = 0usize;
    let mut preview = Vec::new();
    for raw in body.split('\n') {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        content_lines += 1;
        if preview.len() < PASSTHROUGH_PREVIEW_LINES {
            preview.push(line.to_string());
        }
    }
    (content_lines, preview)
}

/// Ensure passthrough body has exactly one trailing newline when
/// non-empty, and no trailing newline when empty. Stable for diff
/// tests: a section with no content emits `--- Name\n` only, and a
/// section with content emits `--- Name\n<content>\n`.
fn normalise_trailing_newline(mut s: String) -> String {
    while s.ends_with('\n') {
        s.pop();
    }
    if !s.is_empty() {
        s.push('\n');
    }
    s
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(
        id: u32,
        enabled: bool,
        ty: ParsedRuleType,
        section: &str,
        value: &str,
        comment: &str,
        line: usize,
    ) -> ParsedRule {
        ParsedRule {
            id_hint: id,
            enabled,
            rule_type: ty,
            section_name: section.to_string(),
            match_value: value.to_string(),
            comment: comment.to_string(),
            blocked: false,
            line_number: line,
            origin: None,
        }
    }

    #[test]
    fn empty_input_yields_default_result() {
        let result = parse_canonical_rules("");
        assert_eq!(result, PresetParseResult::default());
    }

    #[test]
    fn no_sections_drops_prelude() {
        // Lines before the first `--- ` header are file-level prelude.
        let result = parse_canonical_rules("# header line one\n# header line two\n");
        assert!(result.rules.is_empty());
        assert!(result.passthrough.is_empty());
    }

    #[test]
    fn single_known_section_with_one_rule() {
        let result = parse_canonical_rules("--- Zones\nru\n");
        assert_eq!(result.rules.len(), 1);
        let r = &result.rules[0];
        assert_eq!(r.rule_type, ParsedRuleType::Zone);
        assert_eq!(r.match_value, "ru");
        assert!(r.enabled);
    }

    #[test]
    fn inline_comment_split_at_first_hash() {
        let result = parse_canonical_rules("--- Domains\nvk.com  # Russian social\n");
        assert_eq!(result.rules.len(), 1);
        let r = &result.rules[0];
        assert_eq!(r.match_value, "vk.com");
        assert_eq!(r.comment, "Russian social");
    }

    #[test]
    fn disabled_rule_single_token() {
        let result = parse_canonical_rules("--- Domains\n# disabled.example.com\n");
        assert_eq!(result.rules.len(), 1);
        let r = &result.rules[0];
        assert!(!r.enabled);
        assert_eq!(r.match_value, "disabled.example.com");
    }

    #[test]
    fn disabled_rule_with_inline_comment() {
        // First # is the disable prefix; second is the inline-comment
        // separator. Value is `vk.com`, comment is `temporarily off`.
        let result = parse_canonical_rules("--- Domains\n# vk.com  # temporarily off\n");
        assert_eq!(result.rules.len(), 1);
        let r = &result.rules[0];
        assert!(!r.enabled);
        assert_eq!(r.match_value, "vk.com");
        assert_eq!(r.comment, "temporarily off");
    }

    #[test]
    fn multi_word_comment_is_dropped_not_disabled_rule() {
        // "# this is a note" is a free comment — NOT a disabled rule.
        let result = parse_canonical_rules("--- Domains\n# this is a note\n");
        assert!(result.rules.is_empty());
    }

    #[test]
    fn block_flag_marks_rule_blocked_and_strips_token() {
        let result = parse_canonical_rules("--- Domains\nads.example.com +block\n");
        assert_eq!(result.rules.len(), 1);
        let r = &result.rules[0];
        assert!(r.enabled);
        assert!(r.blocked);
        assert_eq!(r.match_value, "ads.example.com");
    }

    #[test]
    fn block_flag_with_inline_comment() {
        let result = parse_canonical_rules("--- Domains\nads.example.com +block  # tracker\n");
        assert_eq!(result.rules.len(), 1);
        let r = &result.rules[0];
        assert!(r.blocked);
        assert_eq!(r.match_value, "ads.example.com");
        assert_eq!(r.comment, "tracker");
    }

    #[test]
    fn disabled_block_rule_is_not_mistaken_for_free_comment() {
        // `# value +block` must parse as a disabled blocked rule, not prose.
        let result = parse_canonical_rules("--- Domains\n# ads.example.com +block\n");
        assert_eq!(result.rules.len(), 1);
        let r = &result.rules[0];
        assert!(!r.enabled);
        assert!(r.blocked);
        assert_eq!(r.match_value, "ads.example.com");
    }

    #[test]
    fn no_block_flag_leaves_rule_unblocked() {
        let result = parse_canonical_rules("--- Domains\nexample.com\n");
        assert_eq!(result.rules.len(), 1);
        assert!(!result.rules[0].blocked);
    }

    #[test]
    fn double_hash_is_always_free_comment() {
        let result = parse_canonical_rules("--- Domains\n## metadata: vendor-list\n");
        assert!(result.rules.is_empty());
    }

    #[test]
    fn lone_hash_is_dropped() {
        let result = parse_canonical_rules("--- Domains\n#\n");
        assert!(result.rules.is_empty());
    }

    #[test]
    fn blank_lines_between_rules_ignored() {
        let result = parse_canonical_rules("--- Domains\nvk.com\n\n\nyoutube.com\n");
        assert_eq!(result.rules.len(), 2);
        assert_eq!(result.rules[0].match_value, "vk.com");
        assert_eq!(result.rules[1].match_value, "youtube.com");
    }

    #[test]
    fn crlf_line_endings_supported() {
        let result = parse_canonical_rules("--- Zones\r\nru\r\n");
        assert_eq!(result.rules.len(), 1);
        assert_eq!(result.rules[0].match_value, "ru");
    }

    #[test]
    fn mixed_line_endings_supported() {
        let result = parse_canonical_rules("--- Zones\r\nru\n--- Domains\r\nvk.com\n");
        assert_eq!(result.rules.len(), 2);
    }

    #[test]
    fn case_insensitive_section_headers_accepted() {
        // QML parser was lenient on case — preserve that behaviour
        // so older hand-edited files keep importing the same way.
        let result = parse_canonical_rules("--- zones\nru\n");
        assert_eq!(result.rules.len(), 1);
        assert_eq!(result.rules[0].rule_type, ParsedRuleType::Zone);
    }

    #[test]
    fn unknown_section_goes_to_passthrough() {
        let input = "--- Linux\n# (reserved)\nfirefox\nchromium\n";
        let result = parse_canonical_rules(input);
        assert!(result.rules.is_empty());
        assert_eq!(result.passthrough.len(), 1);
        let block = &result.passthrough[0];
        assert_eq!(block.section_name, "Linux");
        // Content (non-blank, non-comment): firefox, chromium → 2 lines.
        assert_eq!(block.content_lines, 2);
        assert_eq!(
            block.preview,
            vec!["firefox".to_string(), "chromium".to_string()]
        );
        // Body trailing-newline normalised.
        assert_eq!(block.raw_text, "# (reserved)\nfirefox\nchromium\n");
    }

    #[test]
    fn passthrough_preserves_blank_lines_and_comments_in_raw() {
        let input = "--- Linux\n\nfirefox\n# vendor note\nchromium\n";
        let result = parse_canonical_rules(input);
        assert_eq!(result.passthrough.len(), 1);
        let block = &result.passthrough[0];
        assert_eq!(block.raw_text, "\nfirefox\n# vendor note\nchromium\n");
        // Preview only contains non-blank, non-comment.
        assert_eq!(
            block.preview,
            vec!["firefox".to_string(), "chromium".to_string()]
        );
    }

    #[test]
    fn passthrough_preview_caps_at_five_lines() {
        let mut input = String::from("--- Linux\n");
        for i in 0..10 {
            input.push_str(&format!("app{i}\n"));
        }
        let result = parse_canonical_rules(&input);
        let block = &result.passthrough[0];
        assert_eq!(block.content_lines, 10);
        assert_eq!(block.preview.len(), PASSTHROUGH_PREVIEW_LINES);
        assert_eq!(block.preview[0], "app0");
        assert_eq!(block.preview[4], "app4");
    }

    #[test]
    fn empty_unknown_section_produces_block_with_empty_body() {
        let result = parse_canonical_rules("--- Linux\n--- MacOS\nSafari\n");
        // Two passthrough blocks — Linux (empty) and MacOS (one line).
        assert_eq!(result.passthrough.len(), 2);
        assert_eq!(result.passthrough[0].section_name, "Linux");
        assert_eq!(result.passthrough[0].raw_text, "");
        assert_eq!(result.passthrough[0].content_lines, 0);
        assert!(result.passthrough[0].preview.is_empty());
        assert_eq!(result.passthrough[1].section_name, "MacOS");
        assert_eq!(result.passthrough[1].content_lines, 1);
    }

    #[test]
    fn duplicate_unknown_section_creates_two_passthrough_blocks() {
        let input = "--- Linux\nfirefox\n--- Linux\nchromium\n";
        let result = parse_canonical_rules(input);
        assert_eq!(result.passthrough.len(), 2);
        assert_eq!(result.passthrough[0].raw_text, "firefox\n");
        assert_eq!(result.passthrough[1].raw_text, "chromium\n");
        // The duplicate diagnostic fires.
        assert_eq!(result.duplicate_sections.len(), 1);
        assert_eq!(result.duplicate_sections[0].section_name, "Linux");
        assert_eq!(result.duplicate_sections[0].occurrences, 2);
        assert!(!result.duplicate_sections[0].is_known_section);
    }

    #[test]
    fn duplicate_known_section_merges_rules_and_flags_diagnostic() {
        let input = "--- Domains\nvk.com\n--- Domains\nya.ru\n";
        let result = parse_canonical_rules(input);
        // Rules from both blocks are present in encounter order.
        assert_eq!(result.rules.len(), 2);
        assert_eq!(result.rules[0].match_value, "vk.com");
        assert_eq!(result.rules[1].match_value, "ya.ru");
        // Diagnostic fires with `is_known_section = true`.
        assert_eq!(result.duplicate_sections.len(), 1);
        let dup = &result.duplicate_sections[0];
        assert_eq!(dup.section_name, "Domains");
        assert_eq!(dup.occurrences, 2);
        assert!(dup.is_known_section);
    }

    #[test]
    fn multiple_distinct_duplicates_in_order() {
        let input = "--- Linux\na\n--- MacOS\nb\n--- Linux\nc\n--- MacOS\nd\n";
        let result = parse_canonical_rules(input);
        assert_eq!(result.duplicate_sections.len(), 2);
        // Order preserved by first-encounter (Linux before MacOS).
        assert_eq!(result.duplicate_sections[0].section_name, "Linux");
        assert_eq!(result.duplicate_sections[1].section_name, "MacOS");
    }

    #[test]
    fn id_hint_increments_sequentially() {
        let input = "--- Zones\nru\n--- Domains\nvk.com\nya.ru\n";
        let result = parse_canonical_rules(input);
        assert_eq!(result.rules.len(), 3);
        assert_eq!(result.rules[0].id_hint, 1);
        assert_eq!(result.rules[1].id_hint, 2);
        assert_eq!(result.rules[2].id_hint, 3);
    }

    #[test]
    fn line_numbers_are_one_based_and_track_file_position() {
        let input = "# prelude\n--- Domains\n\nvk.com\n# disabled.example.com\n";
        let result = parse_canonical_rules(input);
        assert_eq!(result.rules.len(), 2);
        // vk.com is on line 4 (1-based), counting the blank line.
        assert_eq!(result.rules[0].line_number, 4);
        assert_eq!(result.rules[1].line_number, 5);
    }

    #[test]
    fn cyrillic_match_value_preserved_verbatim() {
        let input = "--- Zones\nрф          # Российская Федерация\n";
        let result = parse_canonical_rules(input);
        assert_eq!(result.rules.len(), 1);
        assert_eq!(result.rules[0].match_value, "рф");
        assert_eq!(result.rules[0].comment, "Российская Федерация");
    }

    #[test]
    fn ace_punycode_match_value_preserved_verbatim() {
        // The parser does NOT do Punycode↔Unicode conversion; that's
        // a UI-layer concern (see `_unicodeDecodeHost` in Main.qml).
        let input = "--- Zones\nxn--p1ai\n";
        let result = parse_canonical_rules(input);
        assert_eq!(result.rules[0].match_value, "xn--p1ai");
    }

    #[test]
    fn windows_section_treated_as_application() {
        let input = "--- Windows\nbrowser.exe\n*vpn*.exe\n";
        let result = parse_canonical_rules(input);
        assert_eq!(result.rules.len(), 2);
        for r in &result.rules {
            assert_eq!(r.rule_type, ParsedRuleType::Application);
        }
    }

    #[test]
    fn ip_section_treated_as_exact_ip() {
        let input = "--- IP\n203.0.113.7\n";
        let result = parse_canonical_rules(input);
        assert_eq!(result.rules[0].rule_type, ParsedRuleType::ExactIp);
    }

    #[test]
    fn pro_section_cidr_goes_to_passthrough() {
        // Pro-tier sections (CIDR, Ports) are not yet supported by
        // the Free engine — they survive as passthrough so a Pro→Free
        // round-trip doesn't lose them.
        let result = parse_canonical_rules("--- Cidr\n10.0.0.0/8\n");
        assert!(result.rules.is_empty());
        assert_eq!(result.passthrough[0].section_name, "Cidr");
        assert_eq!(result.passthrough[0].raw_text, "10.0.0.0/8\n");
    }

    #[test]
    fn section_header_with_extra_spaces_normalised() {
        // `---  Zones  ` (extra spaces) — the prefix matcher requires
        // exactly `--- ` (three hyphens + one space), so this line is
        // NOT a header. It falls through to the prelude bucket.
        let result = parse_canonical_rules("---  Zones  \nru\n");
        assert!(result.rules.is_empty());
        assert!(result.passthrough.is_empty());
    }

    #[test]
    fn rule_type_slug_matches_qml_mapping() {
        assert_eq!(ParsedRuleType::Zone.slug(), "zone");
        assert_eq!(ParsedRuleType::Domain.slug(), "domain");
        assert_eq!(ParsedRuleType::ExactIp.slug(), "exact-ip");
        assert_eq!(ParsedRuleType::Application.slug(), "application");
    }

    #[test]
    fn classify_section_strict_case_sensitive() {
        assert_eq!(classify_section("Zones"), Some(ParsedRuleType::Zone));
        assert_eq!(classify_section("zones"), None);
        assert_eq!(classify_section("ZONES"), None);
        assert_eq!(classify_section("Linux"), None);
    }

    #[test]
    fn classify_section_lenient_case_insensitive() {
        assert_eq!(
            classify_section_lenient_pub("Zones"),
            Some(ParsedRuleType::Zone)
        );
        assert_eq!(
            classify_section_lenient_pub("zones"),
            Some(ParsedRuleType::Zone)
        );
        assert_eq!(
            classify_section_lenient_pub("ZONES"),
            Some(ParsedRuleType::Zone)
        );
        assert_eq!(classify_section_lenient_pub("Linux"), None);
    }

    #[test]
    fn ten_thousand_rules_perf() {
        // Sanity: parser must finish a 10k-rule preset in well under a
        // second. Hard cap of 500 ms is intentionally generous so the
        // test stays stable on slow CI runners.
        let mut input = String::from("--- Domains\n");
        for i in 0..10_000 {
            input.push_str(&format!("host{i}.example.com  # comment {i}\n"));
        }
        let start = std::time::Instant::now();
        let result = parse_canonical_rules(&input);
        let elapsed = start.elapsed();
        assert_eq!(result.rules.len(), 10_000);
        assert!(
            elapsed.as_millis() < 500,
            "10k rules took {} ms (should be <500)",
            elapsed.as_millis()
        );
    }

    #[test]
    fn complete_realistic_preset_matches_qml_behaviour() {
        // A realistic RU preset shape — verifies the parser behaves
        // identically to the QML reference for a representative file.
        let input = "# NetRuleRouter preset - version 1\n# name: Test\n# preset_version: 1\n\n--- Zones\nru          # Россия (.ru)\nрф          # Россия (.рф, Punycode xn--p1ai)\n\n--- Domains\nvk.com\n*.vk.com\n# *.deprecated.com  # turned off last week\n\n--- IP\n# Intentionally left empty\n\n--- Windows\ntelegram.exe\n# notepad.exe\n\n--- Linux\n# (reserved - not applied on Windows)\nfirefox\n\n--- MacOS\n# (reserved - not applied on Windows)\nSafari\n";

        let result = parse_canonical_rules(input);

        // 2 zones + 2 domains + 1 disabled domain + 1 enabled app +
        // 1 disabled app = 7 rules.
        assert_eq!(result.rules.len(), 7);

        // Spot-check
        assert_eq!(result.rules[0].match_value, "ru");
        assert!(result.rules[0].enabled);
        assert_eq!(result.rules[1].match_value, "рф");
        assert_eq!(result.rules[2].match_value, "vk.com");
        assert!(result.rules[5].enabled); // telegram.exe
        assert!(!result.rules[6].enabled); // # notepad.exe

        // Passthrough: Linux and MacOS sections preserved.
        assert_eq!(result.passthrough.len(), 2);
        assert_eq!(result.passthrough[0].section_name, "Linux");
        assert_eq!(result.passthrough[1].section_name, "MacOS");
        // Linux has 1 content line (firefox), MacOS has 1 (Safari).
        assert_eq!(result.passthrough[0].content_lines, 1);
        assert_eq!(result.passthrough[1].content_lines, 1);

        // No duplicates in a well-formed file.
        assert!(result.duplicate_sections.is_empty());

        // ── Verify exact rule layout ──
        let expected_section_for_idx = [
            "Zones", "Zones", "Domains", "Domains", "Domains", "Windows", "Windows",
        ];
        for (i, r) in result.rules.iter().enumerate() {
            assert_eq!(r.section_name, expected_section_for_idx[i], "rule {i}");
        }
    }

    #[test]
    fn rule_with_only_whitespace_value_skipped() {
        let result = parse_canonical_rules("--- Domains\n   \n");
        assert!(result.rules.is_empty());
    }

    #[test]
    fn hash_with_just_prefix_skipped() {
        // "# " alone (with trailing newline) → empty body → skipped.
        let result = parse_canonical_rules("--- Domains\n# \n");
        assert!(result.rules.is_empty());
    }

    #[test]
    fn trailing_carriage_returns_stripped() {
        // Single \r at end of value should not become part of match_value.
        let result = parse_canonical_rules("--- Domains\nvk.com\r\n");
        assert_eq!(result.rules[0].match_value, "vk.com");
    }

    #[test]
    fn passthrough_block_for_section_with_only_blank_lines() {
        let result = parse_canonical_rules("--- Linux\n\n\n\n");
        assert_eq!(result.passthrough.len(), 1);
        let block = &result.passthrough[0];
        assert_eq!(block.content_lines, 0);
        // raw_text is normalised: all blanks collapsed at the end.
        assert_eq!(block.raw_text, "");
    }

    #[test]
    fn rejecting_section_with_empty_name_after_dashes() {
        // `---   ` with no section name is not a valid header.
        let result = parse_canonical_rules("---   \nfoo\n");
        // Should not have started a section; everything is prelude.
        assert!(result.rules.is_empty());
        assert!(result.passthrough.is_empty());
    }

    #[test]
    fn serde_roundtrip_through_json() {
        // Wire-protocol smoke: result types serialise to JSON cleanly
        // (this is what the launcher RPC handler emits).
        let result = parse_canonical_rules("--- Zones\nru\n--- Linux\nfirefox\n");
        let json = serde_json::to_string(&result).expect("serialise");
        let parsed: PresetParseResult = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(result, parsed);
    }

    #[test]
    fn parsed_rule_keeps_section_name_case() {
        // Even though we accept lowercased section headers, the
        // parsed rule's `section_name` field preserves the original
        // case from the file. Useful for diagnostics and exports.
        let result = parse_canonical_rules("--- domains\nvk.com\n");
        assert_eq!(result.rules[0].section_name, "domains");
    }

    #[test]
    fn duplicate_known_section_with_passthrough_after_does_not_confuse() {
        // Linux is unknown, Domains is known. Two of each.
        let input =
            "--- Domains\nvk.com\n--- Linux\nfirefox\n--- Domains\nya.ru\n--- Linux\nchromium\n";
        let result = parse_canonical_rules(input);
        assert_eq!(result.rules.len(), 2);
        assert_eq!(result.passthrough.len(), 2);
        assert_eq!(result.duplicate_sections.len(), 2);
    }

    #[test]
    fn invalid_section_marker_treated_as_normal_line_inside_section() {
        // A line that looks like a section header but is malformed
        // (e.g. `----- Zones` with four dashes) is not a header, and
        // inside a known section it would be parsed as a rule value.
        // Inside an unknown section it accumulates as passthrough text.
        let result = parse_canonical_rules("--- Linux\n----- not a header\nfoo\n");
        assert!(result.rules.is_empty());
        let block = &result.passthrough[0];
        assert_eq!(block.section_name, "Linux");
        assert_eq!(block.raw_text, "----- not a header\nfoo\n");
    }

    #[test]
    fn unicode_section_name_treated_as_unknown_and_passthrough() {
        // A user could in theory create `--- Зоны` — non-canonical.
        // It's not a recognised section, so it goes into passthrough.
        let result = parse_canonical_rules("--- Зоны\nru\n");
        assert!(result.rules.is_empty());
        assert_eq!(result.passthrough[0].section_name, "Зоны");
        assert_eq!(result.passthrough[0].content_lines, 1);
    }

    #[test]
    fn fixture_minimal_three_known_sections() {
        let result =
            parse_canonical_rules("--- Zones\nru\n--- Domains\nvk.com\n--- IP\n203.0.113.7\n");
        assert_eq!(result.rules.len(), 3);
        assert_eq!(result.rules[0].rule_type, ParsedRuleType::Zone);
        assert_eq!(result.rules[1].rule_type, ParsedRuleType::Domain);
        assert_eq!(result.rules[2].rule_type, ParsedRuleType::ExactIp);
    }

    #[test]
    fn fixture_application_with_glob_pattern() {
        let result = parse_canonical_rules("--- Windows\n*chrome*.exe  # any chrome variant\n");
        assert_eq!(result.rules[0].match_value, "*chrome*.exe");
        assert_eq!(result.rules[0].comment, "any chrome variant");
    }

    #[test]
    fn fixture_helper_rule_constructor_used_in_assertions() {
        let result = parse_canonical_rules("--- Zones\nru\n");
        assert_eq!(
            result.rules[0],
            rule(1, true, ParsedRuleType::Zone, "Zones", "ru", "", 2)
        );
    }

    // ── `--- Auto` section ───────────────────────────────────────────────────

    #[test]
    fn auto_section_classifies_as_rules_not_passthrough() {
        // Lockstep with `nrr_domain::rules_file`: if this fell to passthrough
        // the GUI would show opaque text where the service sees rules.
        assert_eq!(classify_section("Auto"), Some(ParsedRuleType::Domain));
        assert_eq!(
            classify_section_lenient_pub("auto"),
            Some(ParsedRuleType::Domain)
        );
    }

    #[test]
    fn auto_rule_provenance_is_lifted_out_of_the_comment() {
        let result = parse_canonical_rules(
            "--- Auto\nrr3.example-cdn.net  # auto:site-companion anchor:example.com added:2026-07-31 video CDN\n",
        );
        assert!(result.passthrough.is_empty(), "must not be passthrough");
        assert_eq!(result.rules.len(), 1);
        let parsed = &result.rules[0];
        assert_eq!(parsed.match_value, "rr3.example-cdn.net");
        assert_eq!(parsed.section_name, "Auto");
        assert_eq!(parsed.rule_type, ParsedRuleType::Domain);
        // The label is the free text; the machinery is typed.
        assert_eq!(parsed.comment, "video CDN");
        assert_eq!(
            parsed.origin,
            Some(crate::auto_rule::RuleOrigin::auto(
                crate::auto_rule::AutoRuleReason::SiteCompanion,
                "example.com",
                "2026-07-31"
            ))
        );
    }

    #[test]
    fn auto_rule_without_provenance_keeps_its_comment_and_stays_a_rule() {
        let result = parse_canonical_rules("--- Auto\nh.example.net  # hand-added by me\n");
        assert_eq!(result.rules.len(), 1);
        assert_eq!(result.rules[0].comment, "hand-added by me");
        assert_eq!(result.rules[0].origin, None);
    }

    #[test]
    fn disabled_auto_rule_keeps_its_provenance() {
        let result = parse_canonical_rules(
            "--- Auto\n# stale.example.net  # auto:user-confirmed anchor:example.com added:2026-01-05\n",
        );
        assert_eq!(result.rules.len(), 1);
        assert!(!result.rules[0].enabled);
        assert_eq!(
            result.rules[0]
                .origin
                .as_ref()
                .map(|o| o.reason().as_slug()),
            Some("user-confirmed")
        );
    }

    #[test]
    fn user_authored_rules_carry_no_origin_and_no_extra_wire_field() {
        let result = parse_canonical_rules("--- Domains\nexample.com  # vendor\n");
        assert_eq!(result.rules[0].origin, None);
        let json = serde_json::to_string(&result.rules[0]).expect("serialize");
        assert!(!json.contains("origin"), "got {json}");
    }
}
