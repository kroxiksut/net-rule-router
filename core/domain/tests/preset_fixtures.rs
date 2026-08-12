//! Preset fixtures and CI test matrix.
//!
//! Verifies that:
//!   1. Canonical example files in `presets/examples/` parse and validate correctly.
//!   2. Community example-pack files pass validation.
//!   3. Negative fixture files produce the expected outcomes.
//!   4. Pro-only sections round-trip without data loss.
//!
//! All fixture content is embedded at compile time via `include_bytes!` / `include_str!`
//! so the tests require no file-system access at runtime.

use nrr_domain::{
    preset_canonicalize::{canonicalize_preset_rules, PresetRulesCanonicalizeOutcome},
    preset_validation::{validate_preset_bytes, PresetFileValidationOutcome, PresetImportWarning},
    rules_file::HostPlatform,
    validation::{ValidationError, ValidationWarning},
};
use nrr_shared::RouteRole;

// ── Canonical example files ───────────────────────────────────────────────────

static EXAMPLES_PRIMARY: &[u8] = include_bytes!("../../../presets/examples/rules_primary.txt");
static EXAMPLES_SECONDARY: &[u8] = include_bytes!("../../../presets/examples/rules_secondary.txt");

#[test]
fn canonical_example_primary_passes_validation() {
    let outcome = validate_preset_bytes(EXAMPLES_PRIMARY);
    assert!(
        outcome.is_accepted(),
        "presets/examples/rules_primary.txt must pass validation: {outcome:?}"
    );
}

#[test]
fn canonical_example_secondary_passes_validation() {
    let outcome = validate_preset_bytes(EXAMPLES_SECONDARY);
    assert!(
        outcome.is_accepted(),
        "presets/examples/rules_secondary.txt must pass validation: {outcome:?}"
    );
}

#[test]
fn canonical_example_primary_canonicalizes_for_windows() {
    let outcome = validate_preset_bytes(EXAMPLES_PRIMARY);
    let parse_outcome = accepted_parse_outcome(outcome);
    let canon = canonicalize_preset_rules(
        &parse_outcome,
        RouteRole::Primary,
        HostPlatform::Windows,
        false,
    );
    assert!(
        canon.is_accepted(),
        "presets/examples/rules_primary.txt must canonicalize: {canon:?}"
    );
}

#[test]
fn canonical_example_secondary_canonicalizes_for_windows() {
    let outcome = validate_preset_bytes(EXAMPLES_SECONDARY);
    let parse_outcome = accepted_parse_outcome(outcome);
    let canon = canonicalize_preset_rules(
        &parse_outcome,
        RouteRole::Secondary,
        HostPlatform::Windows,
        false,
    );
    assert!(
        canon.is_accepted(),
        "presets/examples/rules_secondary.txt must canonicalize: {canon:?}"
    );
}

// ── Negative fixtures ─────────────────────────────────────────────────────────

static NEG_DISABLED_ONLY: &[u8] = include_bytes!("fixtures/negative/disabled_rules_only.txt");
static NEG_BARE_GLOB: &[u8] = include_bytes!("fixtures/negative/invalid_bare_glob.txt");
static NEG_IPV6: &[u8] = include_bytes!("fixtures/negative/invalid_ipv6.txt");
static NEG_DUPLICATES: &[u8] = include_bytes!("fixtures/negative/duplicate_domains.txt");

/// A file whose every rule is disabled is still valid. Disabled rules are
/// **retained** in the canonical set (with `enabled == false`) so the revision
/// / GUI can show and toggle them; none participate in routing.
#[test]
fn disabled_rules_only_is_accepted_with_no_active_rules() {
    let outcome = validate_preset_bytes(NEG_DISABLED_ONLY);
    assert!(
        outcome.is_accepted(),
        "disabled-only preset must pass validation"
    );

    let parse_outcome = accepted_parse_outcome(outcome);
    let canon = canonicalize_preset_rules(
        &parse_outcome,
        RouteRole::Primary,
        HostPlatform::Windows,
        false,
    );
    let rule_set = canon.rule_set().expect("disabled-only must canonicalize");
    assert!(
        rule_set.rules().iter().all(|r| !r.enabled),
        "no rule may be enabled in a disabled-only preset: {rule_set:?}"
    );
}

/// A bare `*` glob in the Windows section is a blocking semantic error.
#[test]
fn bare_glob_in_windows_section_is_rejected_at_canonicalize() {
    let outcome = validate_preset_bytes(NEG_BARE_GLOB);
    // Validation layer accepts it (no byte-level problem).
    assert!(
        outcome.is_accepted(),
        "bare-glob file must pass byte-level validation"
    );

    let parse_outcome = accepted_parse_outcome(outcome);
    let canon = canonicalize_preset_rules(
        &parse_outcome,
        RouteRole::Primary,
        HostPlatform::Windows,
        false,
    );
    assert!(
        !canon.is_accepted(),
        "bare `*` glob must be rejected at canonicalization"
    );

    if let PresetRulesCanonicalizeOutcome::Rejected { errors } = &canon {
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::AppGlobTooWide { .. })),
            "expected AppGlobTooWide error, got: {errors:?}"
        );
    }
}

/// An IPv6 address in the IP section is rejected (Free edition only supports IPv4).
#[test]
fn ipv6_address_in_ip_section_is_rejected_at_canonicalize() {
    let outcome = validate_preset_bytes(NEG_IPV6);
    assert!(
        outcome.is_accepted(),
        "IPv6 file must pass byte-level validation"
    );

    let parse_outcome = accepted_parse_outcome(outcome);
    let canon = canonicalize_preset_rules(
        &parse_outcome,
        RouteRole::Primary,
        HostPlatform::Windows,
        false,
    );
    assert!(
        !canon.is_accepted(),
        "IPv6 address must be rejected at canonicalization"
    );

    if let PresetRulesCanonicalizeOutcome::Rejected { errors } = &canon {
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::Ipv6NotSupportedInFree { .. })),
            "expected Ipv6NotSupportedInFree error, got: {errors:?}"
        );
    }
}

/// Duplicate domains produce an `AcceptedWithWarnings` outcome; second copy is dropped.
#[test]
fn duplicate_domains_accepted_with_warnings_and_second_copy_dropped() {
    let outcome = validate_preset_bytes(NEG_DUPLICATES);
    assert!(outcome.is_accepted());

    let parse_outcome = accepted_parse_outcome(outcome);
    let canon = canonicalize_preset_rules(
        &parse_outcome,
        RouteRole::Primary,
        HostPlatform::Windows,
        false,
    );
    assert!(canon.is_accepted(), "duplicates must not be a hard error");

    let warnings = canon.warnings();
    assert!(
        warnings
            .iter()
            .any(|w| matches!(w, ValidationWarning::DuplicateRuleInSameSet { .. })),
        "expected DuplicateRuleInSameSet warning, got: {warnings:?}"
    );

    // Unique domain count: example.com (×2 deduplicated) + *.cdn.example.com (×2 deduplicated) = 2
    let rule_set = canon
        .rule_set()
        .expect("duplicates must produce a rule set");
    assert_eq!(rule_set.len(), 2, "duplicates deduped to 2 unique rules");
}

// ── Pro sections round-trip ───────────────────────────────────────────────────

static PRO_SECTIONS: &[u8] = include_bytes!("fixtures/preset_with_pro_sections.txt");

/// Pro-only sections (CIDR, Ports) are not included in the canonical rule set
/// but their entries are preserved in `ParseOutcome::unknown_sections`.
#[test]
fn pro_sections_not_in_canonical_rule_set() {
    let outcome = validate_preset_bytes(PRO_SECTIONS);
    let (parse_outcome, warnings) = match outcome {
        PresetFileValidationOutcome::Accepted { parse_outcome } => (parse_outcome, vec![]),
        PresetFileValidationOutcome::AcceptedWithWarnings {
            parse_outcome,
            warnings,
        } => (parse_outcome, warnings),
        PresetFileValidationOutcome::Rejected(reason) => {
            panic!("Pro sections fixture must pass validation: {reason:?}")
        }
        _ => unreachable!("non-exhaustive: unknown PresetFileValidationOutcome variant"),
    };

    // Pro sections produce an UnknownProSection warning.
    assert!(
        warnings
            .iter()
            .any(|w| matches!(w, PresetImportWarning::UnknownProSection { .. })),
        "expected UnknownProSection warning for CIDR/Ports sections"
    );

    // The canonical rule set contains only Free-edition rules.
    let canon = canonicalize_preset_rules(
        &parse_outcome,
        RouteRole::Secondary,
        HostPlatform::Windows,
        false,
    );
    let rule_set = canon.rule_set().expect("Pro fixture must canonicalize");

    // Free-edition rules from the fixture: Zones(1) + Domains(2) + IP(1) + Windows(1) = 5
    assert_eq!(
        rule_set.len(),
        5,
        "only 5 Free-edition rules must appear in canonical set; got {}",
        rule_set.len()
    );

    // Pro-only entries are preserved in unknown_sections (round-trip guarantee).
    assert!(
        !parse_outcome.unknown_sections.is_empty(),
        "Pro sections must be preserved in unknown_sections"
    );
    let cidr = parse_outcome
        .unknown_sections
        .iter()
        .find(|s| s.name == "CIDR");
    assert!(cidr.is_some(), "CIDR section must be preserved");
    assert_eq!(
        cidr.expect("checked above").entries.len(),
        2,
        "CIDR must have 2 entries"
    );

    let ports = parse_outcome
        .unknown_sections
        .iter()
        .find(|s| s.name == "Ports");
    assert!(ports.is_some(), "Ports section must be preserved");
    assert_eq!(
        ports.expect("checked above").entries.len(),
        2,
        "Ports must have 2 entries"
    );
}

/// A file with only Free-edition sections is valid for Pro without transformation.
#[test]
fn free_edition_file_is_valid_for_pro_without_change() {
    let free_only = b"\
--- Zones\ncorp-internal\n\
--- Domains\nexample.com\n\
--- IP\n203.0.113.7\n\
--- Windows\noutlook.exe\n";

    let outcome = validate_preset_bytes(free_only);
    assert!(outcome.is_accepted());
    let parse_outcome = accepted_parse_outcome(outcome);
    assert!(
        parse_outcome.unknown_sections.is_empty(),
        "Free-only file must have no unknown sections"
    );
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn accepted_parse_outcome(
    outcome: PresetFileValidationOutcome,
) -> nrr_domain::rules_file::ParseOutcome {
    match outcome {
        PresetFileValidationOutcome::Accepted { parse_outcome }
        | PresetFileValidationOutcome::AcceptedWithWarnings { parse_outcome, .. } => parse_outcome,
        PresetFileValidationOutcome::Rejected(reason) => {
            panic!("expected accepted outcome, got rejected: {reason:?}")
        }
        _ => unreachable!("non-exhaustive: unknown PresetFileValidationOutcome variant"),
    }
}
