//! Preset file validation pipeline.
//!
//! This module implements the parse-level validation pipeline for rules txt
//! files used as preset imports. It accepts raw bytes so it can perform the
//! encoding check itself — the caller does not need to decode the file first.
//!
//! # Pipeline stages
//!
//! ```text
//! raw bytes
//!   → 1. size check                           FileTooLarge      → Rejected
//!   → 2. UTF-8 encoding check                 EncodingError     → Rejected
//!   → 3. parse_rules_file()  (structural)     —
//!   → 4. match value length check             MatchValueTooLong → Rejected
//!   → 5. total rule count check               TooManyRules      → Rejected
//!   → 6. collect parse warnings               →  AcceptedWithWarnings
//!   → PresetFileValidationOutcome             →  Accepted
//! ```
//!
//! Semantic validation (IDNA normalisation, IP format, unsupported-feature rejection
//! on known sections) occurs in a later pipeline stage when the preset is
//! incorporated into an `ActiveConfiguration` and passed to
//! [`crate::validation::validate_and_canonicalize`]. This module focuses on
//! structural safety — ensuring the file is parseable, within resource limits,
//! and that unsupported content is flagged rather than silently discarded.
//!
//! # Outcome model
//!
//! | Outcome                | Meaning                                           |
//! |------------------------|---------------------------------------------------|
//! | `Accepted`             | No issues; import candidate build may proceed.    |
//! | `AcceptedWithWarnings` | Non-blocking issues (unsupported sections, future format  |
//! |                        | version); import may proceed, GUI shows warnings. |
//! | `Rejected`             | Hard error; import candidate build must not start.|
//!
//! **Warnings allow continuation; rejections do not.** A file with only
//! extended sections and no applicable rules is still `Accepted` — the user
//! chose to import it and the GUI shows the badges.

use core::fmt;

use crate::{
    import::IMPORT_FILE_SIZE_LIMIT_BYTES,
    rules_file::{parse_rules_file, ParseOutcome, ParseWarning},
};

// ── Resource limits ───────────────────────────────────────────────────────────

/// Maximum byte length of a single match value string.
///
/// - DNS names: RFC 1035 §2.3.4 caps the total FQDN at 253 octets.
/// - Windows process names: NTFS max filename 255 chars.
/// - We use 260 as a safe upper bound that covers all current match value types.
///
/// Values exceeding this limit are rejected at the parse stage. This prevents
/// pathological inputs (e.g. a 1 MiB "domain name") from entering later
/// validation stages.
pub const MAX_MATCH_VALUE_LEN: usize = 260;

/// Maximum character count of a single inline comment (the label after `#`
/// on an active rule line).
///
/// docs/en/rules-file-format.md Syntax specifies 200 characters. Counted as Unicode scalar
/// values (`chars().count()`), not bytes — so multibyte alphabets get the
/// same effective limit as ASCII. The parser trims leading/trailing
/// whitespace before storing the comment, so padding doesn't count.
///
/// The GUI's Add/Edit Rule dialog truncates input at this limit; the
/// parser rejects files exceeding it. Both surfaces agree on the boundary.
pub const MAX_INLINE_COMMENT_CHARS: usize = 200;

// ── Outcome types ─────────────────────────────────────────────────────────────

/// The result of running [`validate_preset_bytes`].
///
/// The variant names map directly to the three localization-layer outcomes
/// (`accepted`, `accepted-with-warnings`, `rejected`) defined in the import UX
/// contract.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PresetFileValidationOutcome {
    /// The file passed all checks. No warnings.
    ///
    /// The caller may proceed to `rules_file_to_route_rule_set` →
    /// `validate_and_canonicalize` → candidate revision.
    Accepted { parse_outcome: ParseOutcome },

    /// The file passed all checks but has non-blocking issues.
    ///
    /// The caller may proceed to import candidate build. The GUI must surface
    /// `warnings` to the user before (or during) the review dialog.
    AcceptedWithWarnings {
        parse_outcome: ParseOutcome,
        warnings: Vec<PresetImportWarning>,
    },

    /// A hard error prevents import candidate build from starting.
    ///
    /// The active revision is unchanged. The caller must surface a user-visible
    /// error. Retrying with the same file will produce the same result unless
    /// the file is corrected first.
    Rejected(PresetImportRejectedReason),
}

impl PresetFileValidationOutcome {
    /// Returns `true` when the file may proceed to import candidate build.
    ///
    /// Both `Accepted` and `AcceptedWithWarnings` return `true`.
    pub fn is_accepted(&self) -> bool {
        !matches!(self, Self::Rejected(_))
    }

    /// Returns `true` when the outcome is `AcceptedWithWarnings`.
    pub fn has_warnings(&self) -> bool {
        matches!(self, Self::AcceptedWithWarnings { .. })
    }

    /// Returns the `ParseOutcome` when the file was accepted (with or without warnings).
    pub fn parse_outcome(&self) -> Option<&ParseOutcome> {
        match self {
            Self::Accepted { parse_outcome } => Some(parse_outcome),
            Self::AcceptedWithWarnings { parse_outcome, .. } => Some(parse_outcome),
            Self::Rejected(_) => None,
        }
    }

    /// Returns the non-blocking warnings when present.
    pub fn warnings(&self) -> &[PresetImportWarning] {
        match self {
            Self::AcceptedWithWarnings { warnings, .. } => warnings.as_slice(),
            _ => &[],
        }
    }
}

// ── Rejected reasons ──────────────────────────────────────────────────────────

/// Why a preset file was rejected.
///
/// All variants are deterministic: retrying with the same file bytes
/// produces the same rejection.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PresetImportRejectedReason {
    /// The file exceeds [`IMPORT_FILE_SIZE_LIMIT_BYTES`].
    ///
    /// The file must be reduced in size before import is attempted.
    FileTooLarge { size_bytes: u64, limit_bytes: u64 },

    /// The file bytes are not valid UTF-8.
    ///
    /// NetRuleRouter rules files must be UTF-8 (or ASCII, which is a subset).
    /// Other encodings (UTF-16, Latin-1, etc.) must be re-saved as UTF-8 first.
    EncodingError,

    /// More of the user's own entries than the Free cap
    /// ([`nrr_shared::rules_json::FREE_MAX_RULES`]: one file carries the whole
    /// allowance), or more app-authored ones than their budget. Disabled and
    /// unknown-section entries count too.
    TooManyRules { count: u32, limit: u32 },

    /// A match value string exceeds [`MAX_MATCH_VALUE_LEN`] bytes.
    ///
    /// `section` is the raw section name (e.g. `"Domains"`, `"Geo"`).
    /// `value` is truncated to 64 bytes for display safety.
    MatchValueTooLong {
        section: String,
        value: String,
        len: usize,
        limit: usize,
    },

    /// An inline comment on a rule line exceeds [`MAX_INLINE_COMMENT_CHARS`]
    /// characters (Unicode scalar values, not bytes).
    ///
    /// `section` is the raw section name (e.g. `"Domains"`, `"Geo"`).
    /// `comment_preview` is truncated to 64 bytes for display safety.
    /// `chars` is the actual character count of the (whitespace-trimmed)
    /// comment, which exceeds `limit`.
    InlineCommentTooLong {
        section: String,
        comment_preview: String,
        chars: usize,
        limit: usize,
    },

    /// A match value, inline comment, metadata value or section name carries
    /// a control character (see
    /// [`nrr_shared::preset_parser::is_forbidden_field_char`]). Kept out
    /// because the file is written back out: a line break there becomes a
    /// rule of its own.
    ///
    /// `section` is the raw section name, empty for the preamble metadata.
    /// `field` is `match-value`, `inline-comment`, `metadata` or
    /// `section-name`.
    ControlCharacter {
        section: String,
        field: &'static str,
    },
}

impl fmt::Display for PresetImportRejectedReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileTooLarge {
                size_bytes,
                limit_bytes,
            } => write!(
                f,
                "file is too large ({size_bytes} bytes, limit is {limit_bytes} bytes)"
            ),
            Self::EncodingError => write!(
                f,
                "file is not valid UTF-8 — re-save as UTF-8 before importing"
            ),
            Self::TooManyRules { count, limit } => write!(
                f,
                "file contains {count} rule entries, which exceeds the limit of {limit}"
            ),
            Self::MatchValueTooLong {
                section,
                value,
                len,
                limit,
            } => write!(
                f,
                "match value in section '{section}' is {len} bytes, \
                 which exceeds the limit of {limit} bytes: '{value}'"
            ),
            Self::InlineCommentTooLong {
                section,
                comment_preview,
                chars,
                limit,
            } => write!(
                f,
                "inline comment in section '{section}' is {chars} characters, \
                 which exceeds the limit of {limit} characters: '{comment_preview}'"
            ),
            Self::ControlCharacter { section, field } => write!(
                f,
                "{field} in section '{section}' contains a line break or other \
                 control character"
            ),
        }
    }
}

// ── Non-blocking warnings ─────────────────────────────────────────────────────

/// A non-blocking warning produced during preset file validation.
///
/// Warnings do **not** prevent import candidate build from proceeding. The
/// GUI must surface them so the user can make an informed decision.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PresetImportWarning {
    /// A section with an unrecognised name was found (e.g. `--- Geo`,
    /// `--- Ports`). Its entries are preserved but will not be applied to
    /// routing policy. The GUI displays them with a "not applied" badge.
    UnknownSection { name: String, entry_count: usize },

    /// The file's version header declares a format version newer than this
    /// build supports. Known sections are parsed; unrecognised sections are
    /// preserved. The user should be informed that some rules may be ignored.
    FormatVersionMismatch { found: u32, supported: u32 },
}

impl fmt::Display for PresetImportWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownSection { name, entry_count } => write!(
                f,
                "section '{name}' contains {entry_count} rule(s) this build does not \
                 support and will not apply"
            ),
            Self::FormatVersionMismatch { found, supported } => write!(
                f,
                "file format version {found} is newer than this build supports (v{supported}); \
                 some rules may be ignored"
            ),
        }
    }
}

// ── Pipeline ──────────────────────────────────────────────────────────────────

/// Runs the preset file validation pipeline on raw bytes.
///
/// This is the entry point for stage 1–5 of the preset import pipeline (see
/// module-level docs). The caller reads the file bytes; this function handles
/// everything from the size check through parse-level validation.
///
/// Semantic validation (IDNA, IP format, unsupported-feature rejection on known
/// sections) is not performed here — it requires a full `ActiveConfiguration`
/// and happens via [`crate::validation::validate_and_canonicalize`].
///
/// # Encoding
///
/// The function decodes `bytes` as UTF-8. A file that is not valid UTF-8 is
/// rejected with [`PresetImportRejectedReason::EncodingError`]. A UTF-8 BOM
/// at the start of the file is stripped before parsing.
pub fn validate_preset_bytes(bytes: &[u8]) -> PresetFileValidationOutcome {
    // Stage 1: size check.
    if bytes.len() as u64 > IMPORT_FILE_SIZE_LIMIT_BYTES {
        return PresetFileValidationOutcome::Rejected(PresetImportRejectedReason::FileTooLarge {
            size_bytes: bytes.len() as u64,
            limit_bytes: IMPORT_FILE_SIZE_LIMIT_BYTES,
        });
    }

    // Stage 2: UTF-8 encoding check. Strip UTF-8 BOM if present.
    let text = match std::str::from_utf8(bytes) {
        Ok(s) => s.strip_prefix('\u{FEFF}').unwrap_or(s),
        Err(_) => {
            return PresetFileValidationOutcome::Rejected(
                PresetImportRejectedReason::EncodingError,
            );
        }
    };

    // Stage 3: structural parse.
    let parse_outcome = parse_rules_file(text);

    // Stage 4: match value length check — applies to known and unknown sections.
    for section in &parse_outcome.parsed.sections {
        for entry in &section.entries {
            if entry.match_value.len() > MAX_MATCH_VALUE_LEN {
                return PresetFileValidationOutcome::Rejected(
                    PresetImportRejectedReason::MatchValueTooLong {
                        section: section.section.name().to_string(),
                        value: truncate_for_display(&entry.match_value),
                        len: entry.match_value.len(),
                        limit: MAX_MATCH_VALUE_LEN,
                    },
                );
            }
        }
    }
    for unknown in &parse_outcome.unknown_sections {
        for entry in &unknown.entries {
            if entry.match_value.len() > MAX_MATCH_VALUE_LEN {
                return PresetFileValidationOutcome::Rejected(
                    PresetImportRejectedReason::MatchValueTooLong {
                        section: unknown.name.clone(),
                        value: truncate_for_display(&entry.match_value),
                        len: entry.match_value.len(),
                        limit: MAX_MATCH_VALUE_LEN,
                    },
                );
            }
        }
    }

    // Stage 4b: inline comment length check — chars (Unicode scalar values),
    // not bytes. Applies to known and unknown sections. docs/en/rules-file-format.md Syntax
    for section in &parse_outcome.parsed.sections {
        for entry in &section.entries {
            if let Some(comment) = &entry.inline_comment {
                let chars = comment.chars().count();
                if chars > MAX_INLINE_COMMENT_CHARS {
                    return PresetFileValidationOutcome::Rejected(
                        PresetImportRejectedReason::InlineCommentTooLong {
                            section: section.section.name().to_string(),
                            comment_preview: truncate_for_display(comment),
                            chars,
                            limit: MAX_INLINE_COMMENT_CHARS,
                        },
                    );
                }
            }
        }
    }
    for unknown in &parse_outcome.unknown_sections {
        for entry in &unknown.entries {
            if let Some(comment) = &entry.inline_comment {
                let chars = comment.chars().count();
                if chars > MAX_INLINE_COMMENT_CHARS {
                    return PresetFileValidationOutcome::Rejected(
                        PresetImportRejectedReason::InlineCommentTooLong {
                            section: unknown.name.clone(),
                            comment_preview: truncate_for_display(comment),
                            chars,
                            limit: MAX_INLINE_COMMENT_CHARS,
                        },
                    );
                }
            }
        }
    }

    // Stage 4c: control characters in any single-line field.
    if let Some(reason) = first_control_character(&parse_outcome) {
        return PresetFileValidationOutcome::Rejected(reason);
    }

    // Stage 5: the user's own rules (known + unknown, enabled + disabled)
    // against their cap — the same count the service caps a revision by, so an
    // exported book re-imports. App-authored ones are held to the book the
    // file lands in, which only the service's write knows.
    let entries = parse_outcome
        .parsed
        .sections
        .iter()
        .flat_map(|s| s.entries.iter())
        .chain(
            parse_outcome
                .unknown_sections
                .iter()
                .flat_map(|s| s.entries.iter()),
        );
    if let Some(excess) =
        crate::validation::rule_cap_excess(entries.map(|e| e.origin.is_none()), None)
    {
        let (count, limit) = excess.count_and_limit();
        return PresetFileValidationOutcome::Rejected(PresetImportRejectedReason::TooManyRules {
            count: u32::try_from(count).unwrap_or(u32::MAX),
            limit: u32::try_from(limit).unwrap_or(u32::MAX),
        });
    }

    // Stage 6: collect non-blocking parse warnings.
    let warnings: Vec<PresetImportWarning> = parse_outcome
        .warnings
        .iter()
        .filter_map(|w| match w {
            ParseWarning::UnknownSection { name, entry_count } => {
                Some(PresetImportWarning::UnknownSection {
                    name: name.clone(),
                    entry_count: *entry_count,
                })
            }
            ParseWarning::UnknownFormatVersion { found, supported } => {
                Some(PresetImportWarning::FormatVersionMismatch {
                    found: *found,
                    supported: *supported,
                })
            }
            // Provenance defects in the app-authored section are not an import
            // concern: the rule itself is imported intact either way, and the
            // import-review dialog reports what the user must *decide* about
            // (unsupported sections, format version). Callers that want to surface them
            // read `ParseOutcome::warnings` directly.
            ParseWarning::AutoRuleMissingProvenance { .. }
            | ParseWarning::AutoRuleIncompleteProvenance { .. } => None,
        })
        .collect();

    if warnings.is_empty() {
        PresetFileValidationOutcome::Accepted { parse_outcome }
    } else {
        PresetFileValidationOutcome::AcceptedWithWarnings {
            parse_outcome,
            warnings,
        }
    }
}

/// The first field of a parsed file holding a character the format cannot
/// carry. Lines are already split, so this is the rest of the controls: a lone
/// carriage return, NUL, escape and the like.
fn first_control_character(outcome: &ParseOutcome) -> Option<PresetImportRejectedReason> {
    use nrr_shared::preset_parser::first_forbidden_field_char;
    let bad = |s: &str| first_forbidden_field_char(s).is_some();
    let reject = |section: &str, field| {
        Some(PresetImportRejectedReason::ControlCharacter {
            section: section.to_string(),
            field,
        })
    };
    let entry_field = |entry: &crate::rules_file::RulesFileEntry| {
        if bad(&entry.match_value) {
            Some("match-value")
        } else if entry.inline_comment.as_deref().is_some_and(bad) {
            Some("inline-comment")
        } else {
            None
        }
    };

    if let Some(meta) = &outcome.preset_metadata {
        let fields = [
            &meta.name,
            &meta.description,
            &meta.author,
            &meta.preset_version,
        ];
        if fields.into_iter().flatten().any(|v| bad(v)) {
            return reject("", "metadata");
        }
    }
    for section in &outcome.parsed.sections {
        if let Some(field) = section.entries.iter().find_map(entry_field) {
            return reject(section.section.name(), field);
        }
    }
    for unknown in &outcome.unknown_sections {
        if bad(&unknown.name) {
            let shown = nrr_shared::preset_parser::neutralize_field(&unknown.name);
            return reject(&shown, "section-name");
        }
        if let Some(field) = unknown.entries.iter().find_map(entry_field) {
            return reject(&unknown.name, field);
        }
    }
    None
}

/// Truncates a match value string to 64 bytes for safe inclusion in
/// error messages. Appends `"…"` when truncation occurs.
fn truncate_for_display(s: &str) -> String {
    const DISPLAY_LIMIT: usize = 64;
    if s.len() <= DISPLAY_LIMIT {
        s.to_string()
    } else {
        // Find a char boundary at or before DISPLAY_LIMIT.
        let mut boundary = DISPLAY_LIMIT;
        while !s.is_char_boundary(boundary) {
            boundary -= 1;
        }
        format!("{}…", &s[..boundary])
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_shared::rules_json::FREE_MAX_RULES;

    // ── Accepted ─────────────────────────────────────────────────────────────

    #[test]
    fn empty_file_is_accepted_no_warnings() {
        let outcome = validate_preset_bytes(b"");
        assert!(outcome.is_accepted());
        assert!(!outcome.has_warnings());
    }

    #[test]
    fn valid_free_only_preset_is_accepted() {
        let input = b"# NetRuleRouter preset \xe2\x80\x94 version 1\n\
                      --- Domains\nexample.com\n--- IP\n203.0.113.7\n";
        let outcome = validate_preset_bytes(input);
        assert!(outcome.is_accepted());
        assert!(!outcome.has_warnings());
        assert!(outcome.parse_outcome().is_some());
    }

    #[test]
    fn utf8_bom_stripped_before_parsing() {
        // UTF-8 BOM is EF BB BF. Parser must not treat it as part of a rule.
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(b"--- Domains\nexample.com\n");
        let outcome = validate_preset_bytes(&bytes);
        assert!(outcome.is_accepted());
        let po = outcome.parse_outcome().unwrap();
        let domains = po
            .parsed
            .entries_for(crate::rules_file::RulesFileSection::Domains);
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0].match_value, "example.com");
    }

    /// CRLF files and tabs are ordinary; a control character inside a field
    /// is not, wherever it sits.
    #[test]
    fn a_control_character_in_any_field_is_rejected() {
        assert!(validate_preset_bytes(b"--- Domains\r\nexample.com\t# a\tnote\r\n").is_accepted());

        let cases: [(&[u8], &str, &str); 5] = [
            (
                b"--- Domains\nexample.com  # note\r--- IP\n",
                "Domains",
                "inline-comment",
            ),
            (b"--- Domains\nexa\x00mple.com\n", "Domains", "match-value"),
            (
                b"# name: evil\x1bname\n--- Domains\nexample.com\n",
                "",
                "metadata",
            ),
            (b"--- Geo\n10.0.0.0/8  # x\x0by\n", "Geo", "inline-comment"),
            (b"--- CI\x07DR\n10.0.0.0/8\n", "CI DR", "section-name"),
        ];
        for (input, section, field) in cases {
            assert_eq!(
                validate_preset_bytes(input),
                PresetFileValidationOutcome::Rejected(
                    PresetImportRejectedReason::ControlCharacter {
                        section: section.to_string(),
                        field,
                    }
                ),
                "{:?}",
                String::from_utf8_lossy(input)
            );
        }
    }

    // ── AcceptedWithWarnings ──────────────────────────────────────────────────

    #[test]
    fn unsupported_section_produces_accepted_with_warning() {
        let input = b"--- Domains\nexample.com\n--- Geo\n10.0.0.0/8\n";
        let outcome = validate_preset_bytes(input);
        assert!(outcome.is_accepted());
        assert!(outcome.has_warnings());
        let warnings = outcome.warnings();
        assert_eq!(warnings.len(), 1);
        assert!(matches!(
            &warnings[0],
            PresetImportWarning::UnknownSection { name, entry_count: 1 } if name == "Geo"
        ));
    }

    #[test]
    fn multiple_extended_sections_produce_one_warning_each() {
        let input = b"--- Domains\nexample.com\n--- Geo\n10.0.0.0/8\n--- Ports\n443\n";
        let outcome = validate_preset_bytes(input);
        assert!(outcome.has_warnings());
        assert_eq!(outcome.warnings().len(), 2);
    }

    #[test]
    fn future_format_version_produces_version_mismatch_warning() {
        let input = b"# NetRuleRouter preset \xe2\x80\x94 version 99\n\
                      --- Domains\nexample.com\n";
        let outcome = validate_preset_bytes(input);
        assert!(outcome.is_accepted());
        assert!(outcome.has_warnings());
        assert!(matches!(
            &outcome.warnings()[0],
            PresetImportWarning::FormatVersionMismatch { found: 99, .. }
        ));
    }

    #[test]
    fn extended_section_and_version_mismatch_both_reported() {
        let input = b"# NetRuleRouter preset \xe2\x80\x94 version 99\n\
                      --- Domains\nexample.com\n--- Geo\n10.0.0.0/8\n";
        let outcome = validate_preset_bytes(input);
        assert!(outcome.has_warnings());
        assert_eq!(outcome.warnings().len(), 2);
    }

    #[test]
    fn parse_outcome_available_when_accepted_with_warnings() {
        let input = b"--- Geo\n10.0.0.0/8\n";
        let outcome = validate_preset_bytes(input);
        assert!(outcome.has_warnings());
        assert!(outcome.parse_outcome().is_some());
    }

    // ── Rejected: FileTooLarge ────────────────────────────────────────────────

    #[test]
    fn file_exceeding_size_limit_is_rejected() {
        // Build a byte slice just over the limit without actually allocating 1 MiB+.
        // We test the limit check using a synthetic oversized value via the constant.
        let over_limit = IMPORT_FILE_SIZE_LIMIT_BYTES + 1;
        // Use a vec of spaces to avoid slow allocation; just test the constant path.
        let big = vec![b' '; over_limit as usize];
        let outcome = validate_preset_bytes(&big);
        assert!(matches!(
            outcome,
            PresetFileValidationOutcome::Rejected(PresetImportRejectedReason::FileTooLarge {
                size_bytes,
                limit_bytes,
            }) if size_bytes == over_limit && limit_bytes == IMPORT_FILE_SIZE_LIMIT_BYTES
        ));
    }

    #[test]
    fn file_exactly_at_size_limit_is_not_rejected_for_size() {
        // A file at exactly the limit must pass the size check.
        // Content will be mostly whitespace so parse succeeds with no entries.
        let at_limit = vec![b'\n'; IMPORT_FILE_SIZE_LIMIT_BYTES as usize];
        let outcome = validate_preset_bytes(&at_limit);
        assert!(!matches!(
            outcome,
            PresetFileValidationOutcome::Rejected(PresetImportRejectedReason::FileTooLarge { .. })
        ));
    }

    // ── Rejected: EncodingError ───────────────────────────────────────────────

    #[test]
    fn non_utf8_bytes_are_rejected_as_encoding_error() {
        // 0xFF is not valid UTF-8.
        let input = b"--- Domains\n\xFF\xFE invalid\n";
        let outcome = validate_preset_bytes(input);
        assert!(matches!(
            outcome,
            PresetFileValidationOutcome::Rejected(PresetImportRejectedReason::EncodingError)
        ));
    }

    #[test]
    fn latin1_encoded_file_is_rejected() {
        // Latin-1 'ä' (0xE4) is not valid UTF-8.
        let input = b"--- Domains\nexample-\xe4.com\n";
        let outcome = validate_preset_bytes(input);
        assert!(matches!(
            outcome,
            PresetFileValidationOutcome::Rejected(PresetImportRejectedReason::EncodingError)
        ));
    }

    #[test]
    fn utf16_le_bom_is_rejected_as_encoding_error() {
        // UTF-16 LE BOM is FF FE — invalid as UTF-8.
        let input = b"\xFF\xFE--- Domains\x00\n\x00";
        let outcome = validate_preset_bytes(input);
        assert!(matches!(
            outcome,
            PresetFileValidationOutcome::Rejected(PresetImportRejectedReason::EncodingError)
        ));
    }

    // ── Rejected: TooManyRules ────────────────────────────────────────────────

    #[test]
    fn file_within_rule_count_limit_is_accepted() {
        // One rule — well within the limit.
        let input = b"--- Domains\nexample.com\n";
        let outcome = validate_preset_bytes(input);
        assert!(outcome.is_accepted());
    }

    #[test]
    fn file_exceeding_rule_count_is_rejected() {
        let mut content = String::from("--- Domains\n");
        for i in 0..=FREE_MAX_RULES {
            content.push_str(&format!("host{i}.example.com\n"));
        }
        let outcome = validate_preset_bytes(content.as_bytes());
        assert!(matches!(
            outcome,
            PresetFileValidationOutcome::Rejected(PresetImportRejectedReason::TooManyRules {
                limit,
                ..
            }) if limit as usize == FREE_MAX_RULES
        ));
    }

    #[test]
    fn rule_count_includes_disabled_entries() {
        // Disabled entries count toward the limit.
        let mut content = String::from("--- Domains\n");
        for i in 0..=FREE_MAX_RULES {
            content.push_str(&format!("# host{i}.example.com\n"));
        }
        let outcome = validate_preset_bytes(content.as_bytes());
        assert!(matches!(
            outcome,
            PresetFileValidationOutcome::Rejected(PresetImportRejectedReason::TooManyRules { .. })
        ));
    }

    #[test]
    fn rule_count_includes_unknown_extended_section_entries() {
        // Entries in unknown sections count toward the total rule limit.
        let mut content = String::from("--- Geo\n");
        for i in 0..=FREE_MAX_RULES {
            content.push_str(&format!("10.0.{}.0/24\n", i % 256));
        }
        let outcome = validate_preset_bytes(content.as_bytes());
        assert!(matches!(
            outcome,
            PresetFileValidationOutcome::Rejected(PresetImportRejectedReason::TooManyRules { .. })
        ));
    }

    fn book_file(user: usize, auto: usize) -> String {
        let mut content = String::from("--- Domains\n");
        for i in 0..user {
            content.push_str(&format!("host{i}.example.com\n"));
        }
        content.push_str("--- Auto\n");
        for i in 0..auto {
            content.push_str(&format!(
                "cdn{i}.example.net  # auto:site-companion anchor:example.com added:2026-07-31\n"
            ));
        }
        content
    }

    /// An export of a legitimate book — the user's allowance nearly spent,
    /// plus the app's companions — must import back.
    #[test]
    fn app_authored_entries_do_not_spend_the_users_file_allowance() {
        let outcome = validate_preset_bytes(book_file(9_000, 1_500).as_bytes());
        assert!(outcome.is_accepted(), "{outcome:?}");
        let full = validate_preset_bytes(
            book_file(FREE_MAX_RULES, crate::auto_rule_budget::MAX_AUTO_RULES).as_bytes(),
        );
        assert!(full.is_accepted(), "{full:?}");
    }

    /// An export of a book saved before the app's budget must read back: the
    /// budget is held against the book the file lands in, by the service.
    #[test]
    fn app_authored_entries_past_their_budget_are_left_to_the_service() {
        let auto_cap = crate::auto_rule_budget::MAX_AUTO_RULES;
        let outcome = validate_preset_bytes(book_file(10, auto_cap + 500).as_bytes());
        assert!(outcome.is_accepted(), "{outcome:?}");
        let over_users = validate_preset_bytes(book_file(FREE_MAX_RULES + 1, 10).as_bytes());
        assert!(matches!(
            over_users,
            PresetFileValidationOutcome::Rejected(PresetImportRejectedReason::TooManyRules {
                count,
                limit,
            }) if count as usize == FREE_MAX_RULES + 1 && limit as usize == FREE_MAX_RULES
        ));
    }

    // ── Rejected: MatchValueTooLong ───────────────────────────────────────────

    #[test]
    fn match_value_at_limit_is_accepted() {
        let value = "a".repeat(MAX_MATCH_VALUE_LEN);
        let input = format!("--- Domains\n{value}\n");
        let outcome = validate_preset_bytes(input.as_bytes());
        // A 260-char "domain" will fail semantic validation later but is accepted
        // at the parse level.
        assert!(outcome.is_accepted());
    }

    #[test]
    fn match_value_exceeding_limit_is_rejected() {
        let value = "a".repeat(MAX_MATCH_VALUE_LEN + 1);
        let input = format!("--- Domains\n{value}\n");
        let outcome = validate_preset_bytes(input.as_bytes());
        assert!(matches!(
            outcome,
            PresetFileValidationOutcome::Rejected(PresetImportRejectedReason::MatchValueTooLong {
                len,
                limit,
                ..
            }) if len == MAX_MATCH_VALUE_LEN + 1 && limit == MAX_MATCH_VALUE_LEN
        ));
    }

    #[test]
    fn match_value_too_long_in_unknown_section_is_rejected() {
        let value = "x".repeat(MAX_MATCH_VALUE_LEN + 1);
        let input = format!("--- Geo\n{value}\n");
        let outcome = validate_preset_bytes(input.as_bytes());
        assert!(matches!(
            outcome,
            PresetFileValidationOutcome::Rejected(PresetImportRejectedReason::MatchValueTooLong {
                ref section, ..
            }) if section == "Geo"
        ));
    }

    // ── Rejected: InlineCommentTooLong ────────────────────────────────────────

    #[test]
    fn inline_comment_at_limit_is_accepted() {
        let comment = "a".repeat(MAX_INLINE_COMMENT_CHARS);
        let input = format!("--- Domains\nexample.com  # {comment}\n");
        let outcome = validate_preset_bytes(input.as_bytes());
        assert!(
            outcome.is_accepted(),
            "comment of exactly {MAX_INLINE_COMMENT_CHARS} chars must be accepted, got {outcome:?}"
        );
    }

    #[test]
    fn inline_comment_one_char_over_limit_is_rejected() {
        let comment = "a".repeat(MAX_INLINE_COMMENT_CHARS + 1);
        let input = format!("--- Domains\nexample.com  # {comment}\n");
        let outcome = validate_preset_bytes(input.as_bytes());
        assert!(
            matches!(
                outcome,
                PresetFileValidationOutcome::Rejected(
                    PresetImportRejectedReason::InlineCommentTooLong { chars, limit, .. }
                ) if chars == MAX_INLINE_COMMENT_CHARS + 1 && limit == MAX_INLINE_COMMENT_CHARS
            ),
            "got {outcome:?}"
        );
    }

    #[test]
    fn inline_comment_length_counts_unicode_chars_not_bytes() {
        // Cyrillic "я" is 2 bytes in UTF-8, 1 char. 200 of them = 400 bytes,
        // 200 chars — within limit.
        let comment = "я".repeat(MAX_INLINE_COMMENT_CHARS);
        assert_eq!(comment.len(), MAX_INLINE_COMMENT_CHARS * 2);
        assert_eq!(comment.chars().count(), MAX_INLINE_COMMENT_CHARS);
        let input = format!("--- Domains\nexample.com  # {comment}\n");
        let outcome = validate_preset_bytes(input.as_bytes());
        assert!(
            outcome.is_accepted(),
            "200 multibyte chars (400 bytes) must be accepted, got {outcome:?}"
        );
    }

    #[test]
    fn inline_comment_unicode_over_limit_is_rejected() {
        // 201 Cyrillic chars — over the limit when counted by chars.
        let comment = "я".repeat(MAX_INLINE_COMMENT_CHARS + 1);
        let input = format!("--- Domains\nexample.com  # {comment}\n");
        let outcome = validate_preset_bytes(input.as_bytes());
        assert!(
            matches!(
                outcome,
                PresetFileValidationOutcome::Rejected(
                    PresetImportRejectedReason::InlineCommentTooLong { chars, .. }
                ) if chars == MAX_INLINE_COMMENT_CHARS + 1
            ),
            "got {outcome:?}"
        );
    }

    #[test]
    fn inline_comment_whitespace_is_trimmed_before_counting() {
        // The parser trims leading/trailing whitespace from the comment, so
        // surrounding spaces do not contribute to the length count.
        let core = "x".repeat(MAX_INLINE_COMMENT_CHARS);
        let input = format!("--- Domains\nexample.com  #     {core}     \n");
        let outcome = validate_preset_bytes(input.as_bytes());
        assert!(
            outcome.is_accepted(),
            "padded {MAX_INLINE_COMMENT_CHARS}-char comment must be accepted after trim, got {outcome:?}"
        );
    }

    #[test]
    fn empty_inline_comment_is_accepted() {
        // `value  #` with nothing after — parser stores no comment.
        let input = "--- Domains\nexample.com  #\n";
        let outcome = validate_preset_bytes(input.as_bytes());
        assert!(outcome.is_accepted(), "got {outcome:?}");
    }

    #[test]
    fn no_inline_comment_is_accepted() {
        let input = "--- Domains\nexample.com\n";
        let outcome = validate_preset_bytes(input.as_bytes());
        assert!(outcome.is_accepted(), "got {outcome:?}");
    }

    #[test]
    fn inline_comment_too_long_in_unknown_section_is_rejected() {
        let comment = "a".repeat(MAX_INLINE_COMMENT_CHARS + 1);
        let input = format!("--- Geo\n10.0.0.0/8  # {comment}\n");
        let outcome = validate_preset_bytes(input.as_bytes());
        assert!(
            matches!(
                outcome,
                PresetFileValidationOutcome::Rejected(
                    PresetImportRejectedReason::InlineCommentTooLong { ref section, .. }
                ) if section == "Geo"
            ),
            "got {outcome:?}"
        );
    }

    #[test]
    fn inline_comment_too_long_on_disabled_rule_is_rejected() {
        // Disabled rules (`# value  # label`) also carry inline comments and
        // must be subject to the same limit.
        let comment = "a".repeat(MAX_INLINE_COMMENT_CHARS + 1);
        let input = format!("--- Domains\n# example.com  # {comment}\n");
        let outcome = validate_preset_bytes(input.as_bytes());
        assert!(
            matches!(
                outcome,
                PresetFileValidationOutcome::Rejected(
                    PresetImportRejectedReason::InlineCommentTooLong { .. }
                )
            ),
            "got {outcome:?}"
        );
    }

    // ── Display ───────────────────────────────────────────────────────────────

    #[test]
    fn rejected_reason_display_is_nonempty() {
        let reasons = [
            PresetImportRejectedReason::FileTooLarge {
                size_bytes: 2_000_000,
                limit_bytes: 1_048_576,
            },
            PresetImportRejectedReason::EncodingError,
            PresetImportRejectedReason::TooManyRules {
                count: 2001,
                limit: 2000,
            },
            PresetImportRejectedReason::MatchValueTooLong {
                section: "Domains".to_string(),
                value: "a".repeat(64),
                len: 300,
                limit: 260,
            },
            PresetImportRejectedReason::InlineCommentTooLong {
                section: "Domains".to_string(),
                comment_preview: "label ".repeat(10),
                chars: 250,
                limit: MAX_INLINE_COMMENT_CHARS,
            },
        ];
        for r in &reasons {
            assert!(
                !r.to_string().is_empty(),
                "display must not be empty for {r:?}"
            );
        }
    }

    #[test]
    fn warning_display_is_nonempty() {
        let warnings = [
            PresetImportWarning::UnknownSection {
                name: "Geo".to_string(),
                entry_count: 3,
            },
            PresetImportWarning::FormatVersionMismatch {
                found: 5,
                supported: 1,
            },
        ];
        for w in &warnings {
            assert!(
                !w.to_string().is_empty(),
                "display must not be empty for {w:?}"
            );
        }
    }

    // ── Constants ─────────────────────────────────────────────────────────────

    #[test]
    fn max_match_value_len_is_two_sixty() {
        assert_eq!(MAX_MATCH_VALUE_LEN, 260);
    }

    #[test]
    fn max_inline_comment_chars_is_two_hundred() {
        assert_eq!(MAX_INLINE_COMMENT_CHARS, 200);
    }
}
