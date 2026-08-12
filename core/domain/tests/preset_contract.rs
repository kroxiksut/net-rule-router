//! Import/export contract integration tests.
//!
//! Exercises the full preset import pipeline end-to-end with in-memory bytes:
//!
//!   bytes
//!     → validate_preset_bytes        (stage 2)
//!     → canonicalize_preset_rules    (stage 3)
//!     → build CanonicalProfile       (stage 4+5 — mock; real merge is service-side)
//!     → ImportRequest                (stage 6)
//!     → process_import               (stage 7)
//!     → ImportResult::PendingReview  (confirmed)
//!
//! Also verifies contract constants and the `UiPreferences::import_both_files_together`
//! field introduced in this block.

// Integration test file: `expect()` on parse/setup helpers asserts invariants,
// and the contract tests deliberately assert on default-value constants.
#![allow(clippy::expect_used, clippy::assertions_on_constants)]

use nrr_domain::{
    canonical::{CanonicalProfile, CanonicalRuleBook},
    import::{process_import, ImportRequest, ImportResult, ImportTrigger},
    preset_canonicalize::canonicalize_preset_rules,
    preset_contract::{
        PresetExportMetadata, PresetExportSpec, PresetImportSpec,
        IMPORT_BOTH_FILES_TOGETHER_DEFAULT,
    },
    preset_validation::{validate_preset_bytes, PresetFileValidationOutcome},
    revision::{ContentHash, RevisionActor, RevisionId, RevisionSeq, UnixTimestamp},
    rules_file::HostPlatform,
    AdapterIdentity, BindingSource, RouteBehaviorMode, RouteBinding, RouteRole,
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

fn stub_profile(
    route: RouteRole,
    rule_set: nrr_domain::canonical::CanonicalRuleSet,
) -> CanonicalProfile {
    let (primary_rules, secondary_rules) = match route {
        RouteRole::Primary => (rule_set, Default::default()),
        RouteRole::Secondary => (Default::default(), rule_set),
    };
    CanonicalProfile {
        primary: RouteBinding {
            role: RouteRole::Primary,
            adapter: AdapterIdentity {
                stable_id: "preset-stub-primary-00000000".to_string(),
                display_name: String::new(),
            },
            source: BindingSource::UserAssigned,
        },
        secondary: None,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        rule_book: CanonicalRuleBook {
            primary: primary_rules,
            secondary: secondary_rules,
        },
    }
}

fn make_request(
    id_suffix: &str,
    source: &str,
    content_hash_byte: u8,
    profile: CanonicalProfile,
) -> ImportRequest {
    ImportRequest {
        revision_id: RevisionId::from_prefixed_string(format!("rev-preset-{id_suffix}"))
            .expect("valid revision id"),
        seq: RevisionSeq::FIRST,
        source_path: source.to_string(),
        file_hash: ContentHash::from_bytes([0xaa; 32]),
        // Test fixture: synthetic content_hash. Production path computes
        // real SHA-256 in `nrr_service_runtime::production_preset_exporter`
        // and via the bridge's `sha256Hex` Q_INVOKABLE on the GUI side.
        content_hash: ContentHash::from_bytes([content_hash_byte; 32]),
        acquired_at: UnixTimestamp::from_secs(1_700_000_000),
        trigger: ImportTrigger::NewFile,
        actor: RevisionActor::LocalUser,
        content: profile,
        displaces_pending_id: None,
    }
}

// ── Full pipeline — primary route ─────────────────────────────────────────────

#[test]
fn pipeline_bytes_to_pending_review_primary_route() {
    let bytes = b"\
--- Domains\n\
example.com\n\
*.cdn.example.com\n\
--- IP\n\
203.0.113.7\n";

    let rule_set = canonicalize(bytes, RouteRole::Primary, false);
    assert_eq!(rule_set.len(), 3, "expected 3 canonical rules");

    let profile = stub_profile(RouteRole::Primary, rule_set);
    let request = make_request("primary-001", "C:/rules_primary.txt", 0xbb, profile);
    let result = process_import(request, None, None);

    let pending = match result {
        ImportResult::PendingReview(pending) => pending,
        other => panic!("expected PendingReview, got: {other:?}"),
    };

    assert_eq!(
        pending.candidate.content.rule_book.primary.len(),
        3,
        "PendingRevision must carry all 3 canonicalized rules"
    );
    assert!(
        pending.candidate.content.secondary.is_none(),
        "secondary route binding must be absent for a single-route import"
    );
}

// ── Full pipeline — secondary route ──────────────────────────────────────────

#[test]
fn pipeline_bytes_to_pending_review_secondary_route() {
    let bytes = b"--- Domains\nvpn.corp.example.com\n*.internal.example.com\n";
    let rule_set = canonicalize(bytes, RouteRole::Secondary, false);
    assert_eq!(rule_set.len(), 2);

    // Stage 4+5 (mock): merge secondary rules into a profile with a real primary binding.
    let profile = CanonicalProfile {
        primary: RouteBinding {
            role: RouteRole::Primary,
            adapter: AdapterIdentity {
                stable_id: "win-adapter:ethernet".to_string(),
                display_name: "Ethernet".to_string(),
            },
            source: BindingSource::UserAssigned,
        },
        secondary: Some(RouteBinding {
            role: RouteRole::Secondary,
            adapter: AdapterIdentity {
                stable_id: "win-adapter:vpn".to_string(),
                display_name: "VPN".to_string(),
            },
            source: BindingSource::UserAssigned,
        }),
        behavior_mode: RouteBehaviorMode::StrictSecondaryFailClosed,
        rule_book: CanonicalRuleBook {
            primary: Default::default(),
            secondary: rule_set,
        },
    };

    let request = make_request("secondary-001", "C:/rules_secondary.txt", 0xdd, profile);
    let result = process_import(request, None, None);
    let pending = result.pending_revision().expect("expected PendingReview");

    assert_eq!(pending.candidate.content.rule_book.secondary.len(), 2);
    assert!(pending.candidate.content.secondary.is_some());
}

// ── No-change detection ───────────────────────────────────────────────────────

#[test]
fn pipeline_returns_no_change_when_content_hash_matches_active() {
    let rule_set = canonicalize(b"--- Domains\nexample.com\n", RouteRole::Primary, false);
    let profile = stub_profile(RouteRole::Primary, rule_set);

    let active_hash = ContentHash::from_bytes([0xee; 32]);
    let request = ImportRequest {
        revision_id: RevisionId::from_prefixed_string("rev-preset-nochange-001".to_string())
            .expect("valid revision id"),
        seq: RevisionSeq::FIRST,
        source_path: "C:/rules_primary.txt".to_string(),
        file_hash: ContentHash::from_bytes([0xff; 32]),
        content_hash: active_hash.clone(),
        acquired_at: UnixTimestamp::from_secs(1_700_000_000),
        trigger: ImportTrigger::CurrentFile,
        actor: RevisionActor::LocalUser,
        content: profile,
        displaces_pending_id: None,
    };

    let result = process_import(request, Some(&active_hash), None);
    assert!(
        result.is_no_change(),
        "identical content hash must produce NoChange"
    );
}

// ── Empty preset ──────────────────────────────────────────────────────────────

#[test]
fn empty_preset_produces_pending_review_with_zero_rules() {
    let rule_set = canonicalize(b"", RouteRole::Primary, false);
    assert!(rule_set.is_empty());

    let profile = stub_profile(RouteRole::Primary, rule_set);
    let request = make_request("empty-001", "C:/rules_primary.txt", 0x11, profile);
    let result = process_import(request, None, None);
    let pending = result
        .pending_revision()
        .expect("empty preset must still produce PendingReview");
    assert_eq!(pending.candidate.content.rule_book.primary.len(), 0);
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
