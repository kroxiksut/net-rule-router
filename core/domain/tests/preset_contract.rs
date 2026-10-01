//! Import/export contract integration tests.
//!
//! Exercises the domain stages of the preset import pipeline with in-memory
//! bytes: `validate_preset_bytes` → `canonicalize_preset_rules`. Also verifies
//! the contract constants and shapes.

// Integration test file: `expect()` on parse/setup helpers asserts invariants,
// and the contract tests deliberately assert on default-value constants.
#![allow(clippy::expect_used, clippy::assertions_on_constants)]

use nrr_domain::{
    preset_canonicalize::canonicalize_preset_rules,
    preset_contract::{
        PresetExportMetadata, PresetExportSpec, PresetImportSpec,
        IMPORT_BOTH_FILES_TOGETHER_DEFAULT,
    },
    preset_validation::{validate_preset_bytes, PresetFileValidationOutcome},
    rules_file::HostPlatform,
    RouteRole,
};

// ── Contract constant ─────────────────────────────────────────────────────────

#[test]
fn import_both_files_default_is_false() {
    assert!(!IMPORT_BOTH_FILES_TOGETHER_DEFAULT);
}

// ── Contract shapes ───────────────────────────────────────────────────────────

#[test]
fn preset_import_spec_fields_accessible() {
    let spec = PresetImportSpec {
        route: RouteRole::Primary,
        source_path: "C:/rules_primary.txt".to_string(),
        platform: HostPlatform::Windows,
        include_child_processes: false,
    };
    assert_eq!(spec.route, RouteRole::Primary);
    assert_eq!(spec.source_path, "C:/rules_primary.txt");
    assert_eq!(spec.platform, HostPlatform::Windows);
    assert!(!spec.include_child_processes);
}

#[test]
fn preset_export_spec_fields_accessible() {
    let spec = PresetExportSpec {
        route: RouteRole::Secondary,
        dest_path: "C:/export/rules_secondary.txt".to_string(),
        include_metadata: true,
    };
    assert_eq!(spec.route, RouteRole::Secondary);
    assert_eq!(spec.dest_path, "C:/export/rules_secondary.txt");
    assert!(spec.include_metadata);
}

#[test]
fn preset_export_metadata_default_is_all_none() {
    let meta = PresetExportMetadata::default();
    assert!(meta.name.is_none());
    assert!(meta.description.is_none());
    assert!(meta.author.is_none());
    assert!(meta.preset_version.is_none());
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn parse_and_validate(bytes: &[u8]) -> nrr_domain::rules_file::ParseOutcome {
    match validate_preset_bytes(bytes) {
        PresetFileValidationOutcome::Accepted { parse_outcome }
        | PresetFileValidationOutcome::AcceptedWithWarnings { parse_outcome, .. } => parse_outcome,
        PresetFileValidationOutcome::Rejected(reason) => {
            panic!("validate_preset_bytes rejected: {reason:?}")
        }
        _ => unreachable!("non-exhaustive: unknown PresetFileValidationOutcome variant"),
    }
}

fn canonicalize(
    bytes: &[u8],
    route: RouteRole,
    icp: bool,
) -> nrr_domain::canonical::CanonicalRuleSet {
    let parse_outcome = parse_and_validate(bytes);
    canonicalize_preset_rules(&parse_outcome, route, HostPlatform::Windows, icp)
        .rule_set()
        .expect("canonicalize_preset_rules must succeed")
        .clone()
}

// ── Domain stages ────────────────────────────────────────────────────────────

#[test]
fn preset_bytes_canonicalize_for_the_primary_route() {
    let bytes = b"--- Domains\nexample.com\n*.cdn.example.com\n--- IP\n203.0.113.7\n";

    let rule_set = canonicalize(bytes, RouteRole::Primary, false);
    assert_eq!(rule_set.len(), 3, "expected 3 canonical rules");
}

#[test]
fn preset_bytes_canonicalize_for_the_secondary_route() {
    let bytes = b"--- Domains\nvpn.corp.example.com\n*.internal.example.com\n";
    let rule_set = canonicalize(bytes, RouteRole::Secondary, false);
    assert_eq!(rule_set.len(), 2);
}

#[test]
fn empty_preset_canonicalizes_to_zero_rules() {
    assert!(canonicalize(b"", RouteRole::Primary, false).is_empty());
}

// ── include_child_processes propagation through pipeline ─────────────────────

#[test]
fn include_child_processes_propagated_through_full_pipeline() {
    let bytes = b"--- Windows\nbrowser.exe\n";

    let set_with = canonicalize(bytes, RouteRole::Primary, true);
    let set_without = canonicalize(bytes, RouteRole::Primary, false);

    let icp_flag = |set: &nrr_domain::canonical::CanonicalRuleSet| {
        set.rules()
            .first()
            .and_then(|r| r.app_match.as_ref())
            .map(|a| a.include_child_processes)
    };

    assert_eq!(icp_flag(&set_with), Some(true));
    assert_eq!(icp_flag(&set_without), Some(false));
}
