//! Integration tests for preset file validation pipeline.
//!
//! Test matrix:
//!   - malformed file (binary noise, truncated UTF-8)
//!   - oversized file
//!   - unknown Pro sections (CIDR, Ports)
//!   - invalid match values (semantic errors deferred, length errors here)
//!   - duplicate rules (parse-level: accepted, semantic layer deduplicates)
//!   - empty file
//!   - encoding errors (Latin-1, UTF-16 LE/BE, truncated multi-byte)
//!   - pipeline stops at first hard error (encoding before count)

use nrr_domain::{
    import::IMPORT_FILE_SIZE_LIMIT_BYTES,
    preset_validation::{
        validate_preset_bytes, PresetFileValidationOutcome, PresetImportRejectedReason,
        PresetImportWarning, MAX_MATCH_VALUE_LEN, MAX_RULES_PER_FILE,
    },
    rules_file::RulesFileSection,
};

// ── Empty file ────────────────────────────────────────────────────────────────

#[test]
fn empty_file_is_accepted() {
    let outcome = validate_preset_bytes(b"");
    assert!(outcome.is_accepted());
    assert!(!outcome.has_warnings());
}

#[test]
fn whitespace_only_file_is_accepted() {
    let outcome = validate_preset_bytes(b"   \n\n\t\n");
    assert!(outcome.is_accepted());
}

// ── Malformed / binary input ──────────────────────────────────────────────────

#[test]
fn binary_noise_is_rejected_as_encoding_error() {
    let input: Vec<u8> = (0u8..=255u8).collect();
    let outcome = validate_preset_bytes(&input);
    assert!(matches!(
        outcome,
        PresetFileValidationOutcome::Rejected(PresetImportRejectedReason::EncodingError)
    ));
}

#[test]
fn truncated_multibyte_sequence_is_rejected() {
    // U+00E9 in UTF-8 is 0xC3 0xA9; drop the second byte → invalid sequence.
    let input = b"--- Domains\nexampl\xC3\n";
    let outcome = validate_preset_bytes(input);
    assert!(matches!(
        outcome,
        PresetFileValidationOutcome::Rejected(PresetImportRejectedReason::EncodingError)
    ));
}

#[test]
fn overlong_utf8_sequence_is_rejected() {
    // 0xF8 starts a 4-byte sequence but is not valid UTF-8 in Rust's strict decoder.
    let input = b"--- Domains\n\xF8\x80\x80\x80\x80\n";
    let outcome = validate_preset_bytes(input);
    assert!(matches!(
        outcome,
        PresetFileValidationOutcome::Rejected(PresetImportRejectedReason::EncodingError)
    ));
}

// ── Oversized file ────────────────────────────────────────────────────────────

#[test]
fn file_one_byte_over_limit_is_rejected_as_too_large() {
    let size = IMPORT_FILE_SIZE_LIMIT_BYTES as usize + 1;
    let bytes = vec![b'\n'; size];
    let outcome = validate_preset_bytes(&bytes);
    assert!(matches!(
        outcome,
        PresetFileValidationOutcome::Rejected(PresetImportRejectedReason::FileTooLarge { .. })
    ));
}

#[test]
fn file_exactly_at_limit_passes_size_check() {
    let bytes = vec![b'\n'; IMPORT_FILE_SIZE_LIMIT_BYTES as usize];
    let outcome = validate_preset_bytes(&bytes);
    assert!(!matches!(
        outcome,
        PresetFileValidationOutcome::Rejected(PresetImportRejectedReason::FileTooLarge { .. })
    ));
}

#[test]
fn size_check_happens_before_encoding_check() {
    // A file that is both too large and non-UTF-8 must be rejected for size.
    let mut bytes = vec![0xFF_u8; IMPORT_FILE_SIZE_LIMIT_BYTES as usize + 1];
    bytes[0] = b'-';
    let outcome = validate_preset_bytes(&bytes);
    assert!(matches!(
        outcome,
        PresetFileValidationOutcome::Rejected(PresetImportRejectedReason::FileTooLarge { .. })
    ));
}

// ── Unknown Pro sections ──────────────────────────────────────────────────────

#[test]
fn cidr_section_is_accepted_with_warning_not_rejected() {
    let input = b"--- Domains\nexample.com\n--- CIDR\n10.0.0.0/8\n";
    let outcome = validate_preset_bytes(input);
    assert!(
        outcome.is_accepted(),
        "CIDR section must not reject the file"
    );
    assert!(outcome.has_warnings());
}

#[test]
fn ports_section_is_accepted_with_warning() {
    let input = b"--- Ports\n443\n80\n";
    let outcome = validate_preset_bytes(input);
    assert!(outcome.is_accepted());
    let w = outcome.warnings();
    assert_eq!(w.len(), 1);
    assert!(
        matches!(&w[0], PresetImportWarning::UnknownProSection { name, entry_count: 2 } if name == "Ports")
    );
}

#[test]
fn unknown_section_entries_included_in_parse_outcome() {
    let input = b"--- CIDR\n10.0.0.0/8\n192.168.0.0/16\n";
    let outcome = validate_preset_bytes(input);
    let po = outcome.parse_outcome().unwrap();
    assert_eq!(po.unknown_sections.len(), 1);
    assert_eq!(po.unknown_sections[0].entries.len(), 2);
}

#[test]
fn file_with_only_pro_sections_is_accepted_with_warning() {
    let input = b"--- CIDR\n10.0.0.0/8\n";
    let outcome = validate_preset_bytes(input);
    assert!(outcome.is_accepted());
    assert!(outcome.has_warnings());
}

// ── Invalid / long match values ───────────────────────────────────────────────

#[test]
fn match_value_exactly_at_limit_is_accepted() {
    let v = "a".repeat(MAX_MATCH_VALUE_LEN);
    let input = format!("--- Domains\n{v}\n");
    // Semantically invalid as a domain name but length is within limits.
    let outcome = validate_preset_bytes(input.as_bytes());
    assert!(outcome.is_accepted());
}

#[test]
fn match_value_one_byte_over_limit_is_rejected() {
    let v = "a".repeat(MAX_MATCH_VALUE_LEN + 1);
    let input = format!("--- Domains\n{v}\n");
    let outcome = validate_preset_bytes(input.as_bytes());
    assert!(matches!(
        outcome,
        PresetFileValidationOutcome::Rejected(PresetImportRejectedReason::MatchValueTooLong {
            len, limit, ..
        }) if len == MAX_MATCH_VALUE_LEN + 1 && limit == MAX_MATCH_VALUE_LEN
    ));
}

#[test]
fn too_long_value_in_pro_section_is_rejected() {
    let v = "x".repeat(MAX_MATCH_VALUE_LEN + 1);
    let input = format!("--- CIDR\n{v}\n");
    let outcome = validate_preset_bytes(input.as_bytes());
    assert!(matches!(
        outcome,
        PresetFileValidationOutcome::Rejected(PresetImportRejectedReason::MatchValueTooLong {
            ref section, ..
        }) if section == "CIDR"
    ));
}

#[test]
fn disabled_entry_with_long_value_is_also_rejected() {
    let v = "a".repeat(MAX_MATCH_VALUE_LEN + 1);
    let input = format!("--- Domains\n# {v}\n");
    let outcome = validate_preset_bytes(input.as_bytes());
    assert!(matches!(
        outcome,
        PresetFileValidationOutcome::Rejected(PresetImportRejectedReason::MatchValueTooLong { .. })
    ));
}

// ── Duplicate rules ───────────────────────────────────────────────────────────

#[test]
fn duplicate_rules_are_accepted_at_parse_level() {
    // Duplicate detection is a semantic concern handled by
    // validate_and_canonicalize. The preset validation pipeline accepts
    // files with duplicates and passes them through.
    let input = b"--- Domains\nexample.com\nexample.com\n";
    let outcome = validate_preset_bytes(input);
    assert!(outcome.is_accepted());
    let po = outcome.parse_outcome().unwrap();
    let domains = po.parsed.entries_for(RulesFileSection::Domains);
    assert_eq!(domains.len(), 2); // both preserved
}

// ── Rule count limits ─────────────────────────────────────────────────────────

#[test]
fn exactly_at_rule_count_limit_is_accepted() {
    let mut content = String::from("--- Domains\n");
    for i in 0..MAX_RULES_PER_FILE as usize {
        content.push_str(&format!("h{i}.example.com\n"));
    }
    let outcome = validate_preset_bytes(content.as_bytes());
    assert!(outcome.is_accepted());
}

#[test]
fn one_over_rule_count_limit_is_rejected() {
    let mut content = String::from("--- Domains\n");
    for i in 0..=(MAX_RULES_PER_FILE as usize) {
        content.push_str(&format!("h{i}.example.com\n"));
    }
    let outcome = validate_preset_bytes(content.as_bytes());
    assert!(matches!(
        outcome,
        PresetFileValidationOutcome::Rejected(PresetImportRejectedReason::TooManyRules {
            count, limit
        }) if count == MAX_RULES_PER_FILE + 1 && limit == MAX_RULES_PER_FILE
    ));
}

#[test]
fn rule_count_spans_both_free_and_pro_sections() {
    // Split rules between a Free section and a Pro section.
    // Combined they exceed the limit.
    let half = MAX_RULES_PER_FILE as usize / 2;
    let mut content = String::from("--- Domains\n");
    for i in 0..half {
        content.push_str(&format!("h{i}.example.com\n"));
    }
    content.push_str("--- CIDR\n");
    for i in 0..=(half + 1) {
        content.push_str(&format!("10.{}.0.0/24\n", i % 256));
    }
    let outcome = validate_preset_bytes(content.as_bytes());
    assert!(matches!(
        outcome,
        PresetFileValidationOutcome::Rejected(PresetImportRejectedReason::TooManyRules { .. })
    ));
}

// ── Pipeline order ────────────────────────────────────────────────────────────

#[test]
fn encoding_check_happens_before_rule_count() {
    // File with invalid UTF-8 that would also be over the rule count limit
    // if it were valid — must be rejected for encoding, not count.
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(b"--- Domains\n");
    for _ in 0..=(MAX_RULES_PER_FILE as usize) {
        bytes.extend_from_slice(b"example.com\n");
    }
    bytes.push(0xFF); // poison byte
    let outcome = validate_preset_bytes(&bytes);
    assert!(matches!(
        outcome,
        PresetFileValidationOutcome::Rejected(PresetImportRejectedReason::EncodingError)
    ));
}

#[test]
fn length_check_happens_before_count_check() {
    // A file where a single entry is too long AND there are too many entries.
    // Should reject for length, not count.
    let long_val = "a".repeat(MAX_MATCH_VALUE_LEN + 1);
    let mut content = String::from("--- Domains\n");
    content.push_str(&format!("{long_val}\n"));
    for i in 0..=(MAX_RULES_PER_FILE as usize) {
        content.push_str(&format!("h{i}.example.com\n"));
    }
    let outcome = validate_preset_bytes(content.as_bytes());
    assert!(matches!(
        outcome,
        PresetFileValidationOutcome::Rejected(PresetImportRejectedReason::MatchValueTooLong { .. })
    ));
}

// ── Fixture ───────────────────────────────────────────────────────────────────

#[test]
fn example_preset_primary_passes_validation() {
    let bytes = include_bytes!("../../../presets/examples/rules_primary.txt");
    let outcome = validate_preset_bytes(bytes);
    assert!(
        outcome.is_accepted(),
        "example primary preset must be accepted: {outcome:?}"
    );
}

#[test]
fn example_preset_secondary_passes_validation() {
    let bytes = include_bytes!("../../../presets/examples/rules_secondary.txt");
    let outcome = validate_preset_bytes(bytes);
    assert!(outcome.is_accepted());
}

#[test]
fn fixture_preset_with_pro_sections_accepted_with_warnings() {
    let bytes = include_bytes!("fixtures/preset_with_pro_sections.txt");
    let outcome = validate_preset_bytes(bytes);
    assert!(outcome.is_accepted(), "file must be accepted");
    assert!(outcome.has_warnings(), "Pro sections must produce warnings");
    let pro_warnings: Vec<_> = outcome
        .warnings()
        .iter()
        .filter(|w| matches!(w, PresetImportWarning::UnknownProSection { .. }))
        .collect();
    assert!(!pro_warnings.is_empty());
}
